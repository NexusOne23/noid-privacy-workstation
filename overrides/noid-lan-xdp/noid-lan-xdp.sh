#!/bin/bash
# NoID Privacy physical-link XDP/TC controller. Configuration swaps use fresh pinned
# maps and overwrite each XDP link atomically; active flow maps are reused so a
# topology refresh does not break established WAN traffic.
set -euo pipefail
umask 077
LC_ALL=C
export LC_ALL

OBJECT=${NOID_LAN_XDP_OBJECT:-/usr/lib/noid-privacy/noid-lan-xdp.bpf.o}
OBJECT_SHA256=9f244286de91021ed53fab3f1bf03cdfc248aa9e0090061a91beafe39f96849a
BPF_ROOT=${NOID_LAN_XDP_BPF_ROOT:-/sys/fs/bpf/noid-lan-xdp}
STATE_FILE=${NOID_LAN_XDP_STATE_FILE:-/run/noid-privacy/lan-xdp.state}
LOCK_FILE=${NOID_LAN_XDP_LOCK_FILE:-/run/noid-privacy/lan-xdp.lock}
# Sidecar, deliberately NOT a state-file key: the state grammar is closed and
# audited, and a schema bump would fail-closed on every already-running host.
# A missing, stale or unreadable sidecar only ever costs a full rebuild.
POLICY_DIGEST_FILE=${NOID_LAN_XDP_POLICY_DIGEST_FILE:-/run/noid-privacy/lan-xdp.policy-digest}
SYS_CLASS_NET=${NOID_SYS_CLASS_NET:-/sys/class/net}
ARP_STATE=${NOID_ARP_STATE_FILE:-/var/lib/noid-privacy/arp-hardening.state}
EXPECTED_ARP_STATE_UID=0
EXPECTED_ARP_STATE_GID=0
EXPECTED_DIGEST_UID=0
EXPECTED_DIGEST_GID=0
STATE_SCHEMA=2
MAP_SCHEMA=4
PENDING_GENERATION=''
STATE_GENERATION=''
STATE_OBJECT_SHA256=''
STATE_REUSE_MAPS=0
GATEWAY_IFACE=''
GATEWAY_IP=''
GATEWAY_MAC=''
declare -a STATE_ENTRIES=()

cleanup() {
    local rc=$?
    trap - EXIT
    [ -z "$PENDING_GENERATION" ] || rm -rf "$PENDING_GENERATION"
    exit "$rc"
}
trap cleanup EXIT

die() { echo "noid-lan-xdp: ERROR: $*" >&2; exit 1; }
valid_iface() { [[ $1 =~ ^[a-zA-Z0-9_.-]{1,15}$ ]]; }
valid_mac() { [[ $1 =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]]; }
# True when the gateway IPv4 lies inside a directly-connected subnet of $iface.
# Binds the pinned gateway MAC to every on-link physical interface (multi-homed
# WAN return) without ever accepting it on an unrelated subnet.
iface_onlink_ipv4() {
    local iface=$1 gw=$2 cidrs
    [ -n "$gw" ] || return 1
    cidrs=$(ip -o -4 addr show dev "$iface" scope global 2>/dev/null \
        | awk '{print $4}')
    [ -n "$cidrs" ] || return 1
    # shellcheck disable=SC2086 # intentional word-split of the CIDR list.
    python3 - "$gw" $cidrs <<'ONLINK_PY'
import ipaddress, sys
try:
    gw = ipaddress.ip_address(sys.argv[1])
except ValueError:
    sys.exit(1)
for cidr in sys.argv[2:]:
    try:
        if gw in ipaddress.ip_interface(cidr).network:
            sys.exit(0)
    except ValueError:
        continue
sys.exit(1)
ONLINK_PY
}
mac_hex() { printf '%s' "$1" | tr ':' ' '; }
u32_hex() {
    python3 -c 'import sys; n=int(sys.argv[1]); print(" ".join(f"{b:02x}" for b in n.to_bytes(4,sys.byteorder)))' "$1"
}
ipv4_hex() {
    python3 -c 'import ipaddress,sys; print(" ".join(f"{b:02x}" for b in ipaddress.IPv4Address(sys.argv[1]).packed))' "$1"
}
peer_policy_hex() {
    python3 -c '
import sys
direction = {"outbound": 1, "inbound": 2, "both": 3}[sys.argv[1]]
protocol = {"none": 0, "tcp": 6, "udp": 17}[sys.argv[2]]
start, end = int(sys.argv[3]), int(sys.argv[4])
value = bytes((direction, protocol))
value += start.to_bytes(2, sys.byteorder)
value += end.to_bytes(2, sys.byteorder)
value += bytes(2)
print(" ".join(f"{byte:02x}" for byte in value))
' "$1" "$2" "$3" "$4"
}

read_ifindex() {
    local iface=$1 value
    value=$(cat "$SYS_CLASS_NET/$iface/ifindex" 2>/dev/null) \
        || die "cannot read interface index for $iface"
    [[ $value =~ ^[1-9][0-9]*$ ]] || die "invalid interface index for $iface"
    printf '%s\n' "$value"
}
require_ethernet_link() {
    local iface=$1 link_type
    link_type=$(cat "$SYS_CLASS_NET/$iface/type" 2>/dev/null) \
        || die "cannot read link-layer type for $iface"
    [ "$link_type" = 1 ] \
        || die "unsupported non-Ethernet link-layer type $link_type on $iface"
}
require_root() {
    [ "$(id -u)" -eq 0 ] || die "must run as root"
}

load_gateway_identity() {
    local line key value canonical metadata parent count=0
    local seen_enabled=0 seen_iface=0 seen_ip=0 seen_mac=0 seen_learned=0
    GATEWAY_IFACE=''
    GATEWAY_IP=''
    GATEWAY_MAC=''
    parent=${ARP_STATE%/*}
    [ -d "$parent" ] && [ ! -L "$parent" ] \
        || die "gateway identity parent is not a non-symlink directory"
    metadata=$(stat -Lc '%u:%g:%a' -- "$parent") \
        || die "cannot inspect gateway identity parent"
    [ "$metadata" = \
      "$EXPECTED_ARP_STATE_UID:$EXPECTED_ARP_STATE_GID:755" ] \
        || die "gateway identity parent has unsafe metadata"
    [ -f "$ARP_STATE" ] && [ ! -L "$ARP_STATE" ] \
        || die "gateway identity is not a regular non-symlink file"
    metadata=$(stat -Lc '%u:%g:%a:%h' -- "$ARP_STATE") \
        || die "cannot inspect gateway identity metadata"
    [ "$metadata" = \
      "$EXPECTED_ARP_STATE_UID:$EXPECTED_ARP_STATE_GID:644:1" ] \
        || die "gateway identity has unsafe metadata"
    while IFS= read -r line || [ -n "$line" ]; do
        [[ "$line" == *=* ]] || die "malformed gateway identity line"
        key=${line%%=*}
        value=${line#*=}
        [ -n "$value" ] || die "empty gateway identity value"
        case "$key" in
            ENABLED)
                [ "$seen_enabled" -eq 0 ] || die "duplicate gateway ENABLED"
                seen_enabled=1
                case "$value" in 0|1) ;;
                    *) die "invalid gateway ENABLED value" ;;
                esac
                ;;
            WAN_IFACE)
                [ "$seen_iface" -eq 0 ] || die "duplicate gateway WAN_IFACE"
                seen_iface=1
                valid_iface "$value" || die "invalid gateway interface"
                GATEWAY_IFACE=$value
                ;;
            GATEWAY_IP)
                [ "$seen_ip" -eq 0 ] || die "duplicate gateway IPv4"
                seen_ip=1
                canonical=$(python3 -c \
                    'import ipaddress,sys; print(ipaddress.IPv4Address(sys.argv[1]))' \
                    "$value" 2>/dev/null) || die "invalid gateway IPv4"
                [ "$canonical" = "$value" ] || die "non-canonical gateway IPv4"
                GATEWAY_IP=$value
                ;;
            GATEWAY_MAC)
                [ "$seen_mac" -eq 0 ] || die "duplicate gateway MAC"
                seen_mac=1
                valid_mac "$value" || die "invalid gateway MAC"
                GATEWAY_MAC=$value
                ;;
            LEARNED_AT)
                [ "$seen_learned" -eq 0 ] || die "duplicate gateway timestamp"
                seen_learned=1
                [[ "$value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] \
                    || die "invalid gateway timestamp"
                ;;
            *) die "unknown gateway identity key" ;;
        esac
        count=$((count + 1))
    done < "$ARP_STATE"
    [ "$count" -eq 5 ] \
        && [ "$seen_enabled$seen_iface$seen_ip$seen_mac$seen_learned" = 11111 ] \
        || die "gateway identity is incomplete"
}

load_state() {
    local line key value state_schema='' map_schema='' state_object=''
    local generation='' canonical_root canonical_generation iface mode metadata
    local schema_count=0 map_count=0 object_count=0 generation_count=0
    declare -a entries=()
    declare -A seen_ifaces=()

    STATE_GENERATION=''
    STATE_OBJECT_SHA256=''
    STATE_REUSE_MAPS=0
    STATE_ENTRIES=()
    [ -r "$STATE_FILE" ] || return 1
    [ -f "$STATE_FILE" ] && [ ! -L "$STATE_FILE" ] \
        || die "state is not a regular non-symlink file"
    metadata=$(stat -c '%u:%a' -- "$STATE_FILE" 2>/dev/null) \
        || die "cannot inspect state ownership and mode"
    [ "$metadata" = 0:600 ] \
        || die "state must be root-owned with mode 0600"
    while IFS= read -r line || [ -n "$line" ]; do
        [[ $line == *=* ]] || die "malformed state line"
        key=${line%%=*}
        value=${line#*=}
        [ -n "$value" ] || die "empty state value"
        case "$key" in
            STATE_SCHEMA)
                schema_count=$((schema_count + 1)); state_schema=$value ;;
            MAP_SCHEMA)
                map_count=$((map_count + 1)); map_schema=$value ;;
            OBJECT_SHA256)
                object_count=$((object_count + 1)); state_object=$value ;;
            GEN)
                generation_count=$((generation_count + 1)); generation=$value ;;
            IFACE)
                iface=${value%%:*}; mode=${value#*:}
                if [ "$iface" = "$value" ] || ! valid_iface "$iface"; then
                    die "invalid state interface"
                fi
                case "$mode" in xdpdrv|xdpgeneric) ;; *) die "invalid state XDP mode" ;; esac
                [[ -z ${seen_ifaces[$iface]+x} ]] || die "duplicate state interface"
                seen_ifaces[$iface]=1
                entries+=("$iface:$mode")
                ;;
            *) die "unknown state key" ;;
        esac
    done < "$STATE_FILE"
    [ "$generation_count" -eq 1 ] || die "state must contain exactly one generation"
    [ "${#entries[@]}" -gt 0 ] || die "state contains no interface attachments"

    # A legacy state written by the immediately preceding controller has only
    # GEN/IFACE rows. It may be detached/rolled back after full path validation,
    # but its maps are never reused. Any partially versioned mixture is invalid.
    if [ "$schema_count" -eq 0 ] && [ "$map_count" -eq 0 ] \
            && [ "$object_count" -eq 0 ]; then
        STATE_REUSE_MAPS=0
    else
        [ "$schema_count" -eq 1 ] && [ "$state_schema" = "$STATE_SCHEMA" ] \
            || die "unsupported state schema"
        [ "$map_count" -eq 1 ] || die "state must contain exactly one map schema"
        [ "$object_count" -eq 1 ] \
            && [[ $state_object =~ ^[0-9a-f]{64}$ ]] \
            || die "invalid state object digest"
        case "$map_schema" in
            "$MAP_SCHEMA") STATE_REUSE_MAPS=1 ;;
            2|3)
                # One-way migration from either preceding map set. Validate
                # its attachment for rollback, but reuse none of its maps:
                # map-v4 replaces the broad peer byte with a direction and
                # protocol/port selector value.
                STATE_REUSE_MAPS=0
                ;;
            *) die "unsupported map schema" ;;
        esac
        STATE_OBJECT_SHA256=$state_object
    fi

    [ -d "$BPF_ROOT" ] && [ ! -L "$BPF_ROOT" ] \
        || die "BPF root is not a non-symlink directory"
    [ -d "$generation" ] && [ ! -L "$generation" ] \
        || die "state generation is not a non-symlink directory"
    canonical_root=$(readlink -e -- "$BPF_ROOT") \
        || die "cannot canonicalize BPF root"
    canonical_generation=$(readlink -e -- "$generation") \
        || die "cannot canonicalize state generation"
    [ "${canonical_generation%/*}" = "$canonical_root" ] \
        || die "state generation is outside the BPF root"
    [[ ${canonical_generation##*/} =~ ^generation_([0-9]+_[0-9]+|[A-Za-z0-9]{8})$ ]] \
        || die "invalid state generation name"

    STATE_GENERATION=$canonical_generation
    STATE_ENTRIES=("${entries[@]}")
}

map_mac_update() {
    local map=$1 iface=$2 mac=$3 ifindex
    ifindex=$(read_ifindex "$iface")
    # shellcheck disable=SC2046 # bpftool requires one argv per hex byte.
    bpftool map update pinned "$map" key hex $(u32_hex "$ifindex") \
        $(mac_hex "$mac") 00 00 value hex 01
}

map_peer_update() {
    local map=$1 iface=$2 ip=$3 mac=$4 direction=$5 protocol=$6
    local port_start=$7 port_end=$8 ifindex
    ifindex=$(read_ifindex "$iface")
    # shellcheck disable=SC2046 # bpftool requires one argv per hex byte.
    bpftool map update pinned "$map" key hex $(u32_hex "$ifindex") \
        $(ipv4_hex "$ip") $(mac_hex "$mac") 00 00 value hex \
        $(peer_policy_hex "$direction" "$protocol" "$port_start" "$port_end")
}

map_is_compatible() {
    local map=$1 map_type=$2 key_size=$3 value_size=$4 max_entries=$5
    bpftool -j map show pinned "$map" 2>/dev/null \
        | python3 -c '
import json, sys

expected_type, key_size, value_size, max_entries = sys.argv[1:]
document = json.load(sys.stdin)
if isinstance(document, list):
    if len(document) != 1:
        raise SystemExit(1)
    document = document[0]
expected = {
    "type": expected_type,
    "bytes_key": int(key_size),
    "bytes_value": int(value_size),
    "max_entries": int(max_entries),
    "flags": 0,
}
if not isinstance(document, dict) or any(document.get(k) != v for k, v in expected.items()):
    raise SystemExit(1)
' "$map_type" "$key_size" "$value_size" "$max_entries"
}

# Identify both pinned programs of one generation. Prints "<xdp_id> <tc_id>";
# any deviation exits non-zero and prints nothing, so every caller fails closed.
#
# Each program is resolved through its own pin path. The earlier form took one
# `bpftool --bpffs prog show` snapshot and searched it for the pin path, which
# needs BPF_PROG_GET_NEXT_ID — a call the kernel gates on CAP_SYS_ADMIN, not on
# CAP_BPF. Every unit that drives this controller deliberately carries only
# CAP_NET_ADMIN, CAP_BPF and CAP_PERFMON, so the enumeration returned EPERM
# there and identifying an already-existing generation could never succeed:
# fail-soft callers absorbed that as one DEGRADED line per boot, while the
# fail-closed revoke path in module 05 turned it into a NetworkManager-stop
# loop that left the machine without a login and without a rescue shell.
#
# The binding is not weakened. Resolving the pin path through the kernel is at
# least as tight as searching a system-wide list for a self-reported path, and
# a wrong program behind the expected path still fails the id/type/name/tag
# checks below.
#
# Cost: two bpftool executions per call instead of one, measured on this image
# at ~190 ms each against ~210 ms for the snapshot. Correctness outranks that
# difference, and the same measurement shows `--bpffs` was never the expensive
# part — bpftool's fixed startup is.
generation_program_identities() {
    local generation=$1 xdp_row tc_row
    xdp_row=$(bpftool -j prog show \
        pinned "$generation/progs/noid_lan_xdp" 2>/dev/null) || return 1
    tc_row=$(bpftool -j prog show \
        pinned "$generation/progs/noid_lan_egress" 2>/dev/null) || return 1
    python3 -c '
import json, re, sys


def identify(document, program_name, program_type):
    try:
        row = json.loads(document)
    except ValueError:
        raise SystemExit(1)
    if not isinstance(row, dict):
        raise SystemExit(1)
    program_id = row.get("id")
    tag = row.get("tag")
    if (row.get("type") != program_type or row.get("name") != program_name
            or not isinstance(program_id, int) or program_id <= 0
            or not isinstance(tag, str) or not re.fullmatch(r"[0-9a-f]{16}", tag)):
        raise SystemExit(1)
    return program_id


print(identify(sys.argv[1], "noid_lan_xdp", "xdp"),
      identify(sys.argv[2], "noid_lan_egress", "sched_cls"))
' "$xdp_row" "$tc_row"
}

attach_generation() {
    local generation=$1 iface=$2 mode
    if bpftool net attach xdpdrv pinned \
        "$generation/progs/noid_lan_xdp" dev "$iface" overwrite 2>/dev/null; then
        mode=xdpdrv
    elif bpftool net attach xdpgeneric pinned \
        "$generation/progs/noid_lan_xdp" dev "$iface" overwrite; then
        mode=xdpgeneric
    else
        return 1
    fi
    if ! tc qdisc replace dev "$iface" clsact \
       || ! tc filter replace dev "$iface" egress pref 10 handle 1 \
            bpf direct-action pinned \
            "$generation/progs/noid_lan_egress"; then
        # The XDP overwrite has already changed this interface. Report that
        # partial attachment to the caller and keep its fail-closed XDP program
        # live until the transaction restores the old XDP/TC pair (or detaches
        # this first-generation attempt). Detaching here would make the outer
        # rollback unaware that this interface also needs restoration.
        printf '%s:%s\n' "$iface" "$mode"
        return 1
    fi
    printf '%s:%s\n' "$iface" "$mode"
}

restore_old_generation() {
    local old_generation=$1 entry iface mode phase=old failed=0
    declare -A old_modes=()
    shift
    for entry in "$@"; do
        if [ "$entry" = -- ]; then
            phase=attached
            continue
        fi
        iface=${entry%%:*}
        mode=${entry#*:}
        valid_iface "$iface" || { failed=1; continue; }
        if [ "$phase" = old ]; then
            old_modes[$iface]=$mode
            continue
        fi
        if [[ -n ${old_modes[$iface]+x} ]]; then
            mode=${old_modes[$iface]}
            bpftool net attach "$mode" pinned \
                "$old_generation/progs/noid_lan_xdp" dev "$iface" overwrite \
                >/dev/null 2>&1 || failed=1
            tc qdisc replace dev "$iface" clsact >/dev/null 2>&1 \
                || failed=1
            tc filter replace dev "$iface" egress pref 10 handle 1 \
                bpf direct-action pinned \
                "$old_generation/progs/noid_lan_egress" >/dev/null 2>&1 \
                || failed=1
        else
            bpftool net detach "$mode" dev "$iface" >/dev/null 2>&1 || true
            tc filter delete dev "$iface" egress pref 10 >/dev/null 2>&1 || true
        fi
    done
    [ "$failed" -eq 0 ]
}

# Read the sidecar digest that describes the currently committed generation.
# Every rejection path returns non-zero, which only ever selects a full
# rebuild. The recorded generation must equal the one the authoritative state
# file names, so a sidecar left over from an older generation is never trusted.
read_policy_digest() {
    local expected_generation=$1 line key value metadata
    local generation='' digest='' generation_count=0 digest_count=0
    [ -f "$POLICY_DIGEST_FILE" ] && [ ! -L "$POLICY_DIGEST_FILE" ] || return 1
    metadata=$(stat -c '%u:%g:%a:%h' -- "$POLICY_DIGEST_FILE" 2>/dev/null) \
        || return 1
    [ "$metadata" = "$EXPECTED_DIGEST_UID:$EXPECTED_DIGEST_GID:600:1" ] || return 1
    while IFS= read -r line || [ -n "$line" ]; do
        [[ $line == *=* ]] || return 1
        key=${line%%=*}
        value=${line#*=}
        [ -n "$value" ] || return 1
        case "$key" in
            GEN) generation_count=$((generation_count + 1)); generation=$value ;;
            DIGEST) digest_count=$((digest_count + 1)); digest=$value ;;
            *) return 1 ;;
        esac
    done < "$POLICY_DIGEST_FILE"
    [ "$generation_count" -eq 1 ] && [ "$digest_count" -eq 1 ] || return 1
    [[ $digest =~ ^[0-9a-f]{64}$ ]] || return 1
    [ "$generation" = "$expected_generation" ] || return 1
    printf '%s\n' "$digest"
}

# Publish the sidecar only after the authoritative state file has committed.
# A failure here is not fatal: it merely forfeits the next fast path.
write_policy_digest() {
    local generation=$1 digest=$2 dir tmp
    dir=${POLICY_DIGEST_FILE%/*}
    install -d -m 0755 "$dir" || return 1
    tmp=$(mktemp "$dir/.lan-xdp-policy-digest.XXXXXX") || return 1
    if ! { printf 'GEN=%s\n' "$generation"
           printf 'DIGEST=%s\n' "$digest"; } > "$tmp" \
       || ! chmod 0600 "$tmp" \
       || ! chown "$EXPECTED_DIGEST_UID:$EXPECTED_DIGEST_GID" "$tmp" \
       || ! mv -fT "$tmp" "$POLICY_DIGEST_FILE"; then
        rm -f -- "$tmp"
        return 1
    fi
}

sync_policy() {
    local global_allow=$1
    shift
    local -a ifaces=() peers=() old_entries=() attached=() reuse=()
    local arg iface pair ip mac direction protocol port_start port_end
    local fresh_flow_peer=''
    local old_generation='' generation state_dir tmp
    local canonical_root
    local expected gwif gateway_state_present=0
    local desired_digest=''
    local -a fields=()
    declare -A seen_ifaces=() seen_peers=()

    case "$global_allow" in 0|1) ;; *) die "sync requires global mode 0 or 1" ;; esac
    while [ "$#" -gt 0 ]; do
        arg=$1
        shift
        case "$arg" in
            --iface)
                [ "$#" -gt 0 ] || die "--iface requires a value"
                iface=$1; shift
                valid_iface "$iface" || die "unsafe interface name"
                [ -d "$SYS_CLASS_NET/$iface/device" ] || die "not a physical interface: $iface"
                require_ethernet_link "$iface"
                if [[ -z ${seen_ifaces[$iface]+x} ]]; then
                    ifaces+=("$iface"); seen_ifaces[$iface]=1
                fi
                ;;
            --peer)
                [ "$#" -gt 0 ] \
                    || die "--peer requires IFACE,IPv4,MAC,DIRECTION,PROTOCOL,PORT_START,PORT_END"
                pair=$1; shift
                IFS=, read -r -a fields <<< "$pair"
                [ "${#fields[@]}" -eq 7 ] || die "invalid peer policy field count"
                iface=${fields[0]}; ip=${fields[1]}; mac=${fields[2],,}
                direction=${fields[3]}; protocol=${fields[4]}
                port_start=${fields[5]}; port_end=${fields[6]}
                valid_iface "$iface" || die "unsafe peer interface name"
                [[ -n ${seen_ifaces[$iface]+x} ]] \
                    || die "peer interface is not in the physical interface set"
                ip=$(python3 -c 'import ipaddress,sys; print(ipaddress.IPv4Address(sys.argv[1]))' "$ip") \
                    || die "invalid peer IPv4"
                valid_mac "$mac" || die "invalid peer MAC"
                case "$direction" in outbound|inbound|both) ;;
                    *) die "invalid peer direction" ;;
                esac
                case "$direction:$protocol:$port_start:$port_end" in
                    outbound:none:0:0) ;;
                    inbound:tcp:*:*|inbound:udp:*:*|both:tcp:*:*|both:udp:*:*)
                        [[ $port_start =~ ^[1-9][0-9]{0,4}$ ]] \
                            && [[ $port_end =~ ^[1-9][0-9]{0,4}$ ]] \
                            && [ "$port_start" -le "$port_end" ] \
                            && [ "$port_end" -le 65535 ] \
                            || die "invalid peer port selector"
                        ;;
                    *) die "peer direction and selector disagree" ;;
                esac
                [[ -z ${seen_peers[$ip]+x} ]] \
                    || die "duplicate peer IPv4 policy"
                peers+=("$iface,$ip,$mac,$direction,$protocol,$port_start,$port_end")
                seen_peers[$ip]=1
                ;;
            --fresh-flow-map-for-peer)
                [ "$#" -gt 0 ] && [ -z "$fresh_flow_peer" ] \
                    || die "--fresh-flow-map-for-peer requires one unique IPv4"
                fresh_flow_peer=$(python3 -c \
                    'import ipaddress,sys; print(ipaddress.IPv4Address(sys.argv[1]))' \
                    "$1" 2>/dev/null) || die "invalid flow-reset IPv4"
                [ "$fresh_flow_peer" = "$1" ] \
                    || die "non-canonical flow-reset IPv4"
                shift
                ;;
            *) die "unknown sync argument: $arg" ;;
        esac
    done
    [ "${#ifaces[@]}" -gt 0 ] || die "sync requires at least one physical interface"

    # Validate optional M04 identity before creating a BPF generation or
    # touching an attachment. A present malformed object is never equivalent
    # to "identity not learned yet".
    if [ -e "$ARP_STATE" ] || [ -L "$ARP_STATE" ]; then
        load_gateway_identity
        gateway_state_present=1
    fi

    [ -r "$OBJECT" ] || die "BPF object missing or unreadable: $OBJECT"
    expected=$(sha256sum "$OBJECT" 2>/dev/null | awk '{print $1}') \
        || die "cannot hash BPF object: $OBJECT"
    [ "$expected" = "$OBJECT_SHA256" ] || die "BPF object hash mismatch"
    mountpoint -q /sys/fs/bpf || die "bpffs is not mounted"
    [ ! -L "$BPF_ROOT" ] || die "BPF root must not be a symlink"
    install -d -m 0700 "$BPF_ROOT"
    canonical_root=$(readlink -e -- "$BPF_ROOT") \
        || die "cannot canonicalize BPF root"
    if [ -e "$STATE_FILE" ] || [ -L "$STATE_FILE" ]; then
        load_state || die "cannot load existing XDP state"
        old_generation=$STATE_GENERATION
        old_entries=("${STATE_ENTRIES[@]}")
        generation_program_identities "$old_generation" >/dev/null \
            || die "existing state has no valid pinned XDP and TC programs"
    fi

    # Canonical digest of EVERY input that decides the enforced boundary. An
    # omission here would let a real policy change be skipped, so this list is
    # the security-critical half of the fast path below:
    #   - schema/object identity: a controller or BPF object change must rebuild
    #   - global_allow: the LAN widening switch itself
    #   - gateway identity: seeded into noid_xdp_gateway_macs
    #   - per interface name, ifindex AND local MAC: both are map key/value
    #     material, and MAC randomization changes the MAC on reconnect
    #   - the complete peer policy tuples
    # Sorted so that pure enumeration order can never look like a change.
    desired_digest=$( {
        printf 'NOID-LAN-XDP-POLICY-V1\n'
        printf 'state_schema=%s\nmap_schema=%s\nobject=%s\n' \
            "$STATE_SCHEMA" "$MAP_SCHEMA" "$OBJECT_SHA256"
        printf 'global_allow=%s\n' "$global_allow"
        printf 'gateway=%s|%s|%s|%s\n' "$gateway_state_present" \
            "$GATEWAY_IFACE" "$GATEWAY_IP" "$GATEWAY_MAC"
        for iface in "${ifaces[@]}"; do
            printf 'iface=%s|%s|%s\n' "$iface" \
                "$(cat "$SYS_CLASS_NET/$iface/ifindex")" \
                "$(tr 'A-F' 'a-f' < "$SYS_CLASS_NET/$iface/address")"
        done | LC_ALL=C sort
        if [ "${#peers[@]}" -gt 0 ]; then
            printf 'peer=%s\n' "${peers[@]}" | LC_ALL=C sort
        fi
    } | sha256sum) || die "cannot compute the policy digest"
    desired_digest=${desired_digest%% *}
    [[ $desired_digest =~ ^[0-9a-f]{64}$ ]] || die "invalid policy digest"

    # Fast path. NetworkManager serializes dispatcher scripts and an awaited
    # pre-up blocks the activation it reports to applications, so one queued
    # link event burst previously rebuilt an identical BPF generation once per
    # event and starved every unrelated profile activation for seconds. Skip
    # the rebuild only when the complete input set is byte-identical AND the
    # live attachment still binds the pinned program identities on every
    # recorded interface. `status` is the existing, audited postcondition and is
    # reused verbatim in a subshell rather than reimplemented; its `die` paths
    # end that subshell only. Any doubt whatsoever falls through to the full
    # transaction, so the unconditional self-healing property is preserved.
    if [ -n "$old_generation" ] \
       && [ -z "$fresh_flow_peer" ] \
       && [ "$STATE_REUSE_MAPS" -eq 1 ] \
       && [ "$STATE_OBJECT_SHA256" = "$OBJECT_SHA256" ] \
       && [ "$(read_policy_digest "$old_generation" || true)" = "$desired_digest" ] \
       && ( status ) >/dev/null 2>&1; then
        return 0
    fi
    # Past this point the committed generation is about to be replaced. Retire
    # the sidecar first so an interrupted transaction can never leave a digest
    # that authorizes skipping a rebuild the machine did not actually perform.
    # Removal failure is not fatal: the sidecar is bound to the generation
    # named by the state file, and that generation is about to be replaced,
    # so a leftover can never authorize a skip afterwards.
    rm -f -- "$POLICY_DIGEST_FILE" 2>/dev/null || true

    # bpffs rejects dots in object/directory names on current Fedora kernels.
    # Let mktemp atomically reserve a fresh name: a PID/RANDOM collision must
    # never make cleanup remove a pre-existing active generation.
    generation=$(mktemp -d "$canonical_root/generation_XXXXXXXX") \
        || die "cannot create a fresh BPF generation"
    PENDING_GENERATION=$generation
    mkdir -m 0700 "$generation/progs" "$generation/maps"
    if [ -n "$old_generation" ] && [ "$STATE_REUSE_MAPS" -eq 1 ]; then
        map_is_compatible "$old_generation/maps/noid_xdp_flows_v4" \
            lru_hash 20 8 65536 || die "incompatible reusable flow map"
        map_is_compatible "$old_generation/maps/noid_xdp_dhcp_v4" \
            lru_hash 16 8 256 || die "incompatible reusable DHCP map"
        map_is_compatible "$old_generation/maps/noid_xdp_stats" \
            percpu_array 4 8 9 || die "incompatible reusable stats map"
        # A peer policy transition must never share its reply-correlation map
        # with the still-attached old TC program: that program can insert a new
        # tuple concurrently after any userspace scan/delete has completed.
        # Give the pending generation a fresh flow map instead. The old map and
        # attachments remain untouched for rollback until every new attachment
        # and the authoritative state file commit.
        if [ -z "$fresh_flow_peer" ]; then
            reuse+=(map name noid_xdp_flows_v4 pinned \
                "$old_generation/maps/noid_xdp_flows_v4")
        fi
        reuse+=(map name noid_xdp_dhcp_v4 pinned \
            "$old_generation/maps/noid_xdp_dhcp_v4")
        reuse+=(map name noid_xdp_stats pinned \
            "$old_generation/maps/noid_xdp_stats")
    fi
    if ! bpftool prog loadall "$OBJECT" "$generation/progs" \
        "${reuse[@]}" pinmaps "$generation/maps"; then
        rm -rf "$generation"
        die "kernel rejected BPF object"
    fi
    if [ -n "$fresh_flow_peer" ]; then
        printf 'FLOW_RESET peer_ip=%s scope=all\n' "$fresh_flow_peer"
    fi

    for iface in "${ifaces[@]}"; do
        mac=$(tr 'A-F' 'a-f' < "$SYS_CLASS_NET/$iface/address") || {
            rm -rf "$generation"
            die "cannot read local MAC for $iface"
        }
        valid_mac "$mac" || { rm -rf "$generation"; die "invalid local MAC"; }
        map_mac_update "$generation/maps/noid_xdp_local_macs" "$iface" "$mac"
    done
    if [ "$gateway_state_present" -eq 1 ]; then
        # Seed the validated gateway MAC for EVERY physical interface whose
        # directly-connected IPv4 subnet contains the gateway IP, not only the
        # recorded WAN_IFACE. ENABLED=0 disables only M04's kernel neighbour
        # pin; retaining this identity is deliberate so the M03 default-drop
        # return gate cannot open during that explicit opt-out.
        for gwif in "${ifaces[@]}"; do
            if [ "$gwif" = "$GATEWAY_IFACE" ] \
               || iface_onlink_ipv4 "$gwif" "$GATEWAY_IP"; then
                map_mac_update \
                    "$generation/maps/noid_xdp_gateway_macs" \
                    "$gwif" "$GATEWAY_MAC"
            fi
        done
    fi
    for pair in "${peers[@]}"; do
        IFS=, read -r iface ip mac direction protocol port_start port_end <<< "$pair"
        map_peer_update "$generation/maps/noid_xdp_peer4" \
            "$iface" "$ip" "$mac" "$direction" "$protocol" \
            "$port_start" "$port_end"
    done
    bpftool map update pinned "$generation/maps/noid_xdp_global_allow" \
        key hex 00 00 00 00 value hex "0$global_allow"

    for iface in "${ifaces[@]}"; do
        entry=''
        if ! entry=$(attach_generation "$generation" "$iface"); then
            [ -z "$entry" ] || attached+=("$entry")
            restore_old_generation "$old_generation" "${old_entries[@]}" \
                -- "${attached[@]}" \
                || echo "noid-lan-xdp: CRITICAL: rollback was incomplete" >&2
            rm -rf "$generation"
            die "cannot attach XDP/TC to $iface"
        fi
        attached+=("$entry")
    done

    state_dir=${STATE_FILE%/*}
    if ! install -d -m 0755 "$state_dir" \
       || ! tmp=$(mktemp "$state_dir/.lan-xdp-state.XXXXXX") \
       || ! {
            printf 'STATE_SCHEMA=%s\n' "$STATE_SCHEMA"
            printf 'MAP_SCHEMA=%s\n' "$MAP_SCHEMA"
            printf 'OBJECT_SHA256=%s\n' "$OBJECT_SHA256"
            printf 'GEN=%s\n' "$generation"
            for entry in "${attached[@]}"; do printf 'IFACE=%s\n' "$entry"; done
          } > "$tmp" \
       || ! chmod 0600 "$tmp" \
       || ! mv -fT "$tmp" "$STATE_FILE"; then
        rm -f "${tmp:-}"
        restore_old_generation "$old_generation" "${old_entries[@]}" \
            -- "${attached[@]}" \
            || echo "noid-lan-xdp: CRITICAL: rollback was incomplete" >&2
        die "cannot publish XDP generation state"
    fi
    PENDING_GENERATION=''

    # Sidecar last: the state file stays the single authority, and a failure to
    # publish the digest only forfeits the next fast path. It is never fatal and
    # never precedes the commit it describes.
    write_policy_digest "$generation" "$desired_digest" \
        || logger -t noid-lan-xdp \
            "policy digest not published; the next refresh rebuilds in full" \
            || true

    # Detach disappeared physical interfaces only after every desired link and
    # the authoritative state file have committed. Entries are root-produced.
    for entry in "${old_entries[@]}"; do
        iface=${entry%%:*}; mode=${entry#*:}
        valid_iface "$iface" || continue
        [[ -z ${seen_ifaces[$iface]+x} ]] || continue
        bpftool net detach "$mode" dev "$iface" >/dev/null 2>&1 || true
        tc filter delete dev "$iface" egress pref 10 >/dev/null 2>&1 || true
    done
    if [ -n "$old_generation" ] && [ "$old_generation" != "$generation" ]; then
        rm -rf "$old_generation"
    fi
}

status() {
    local generation entry iface mode expected_mode expected_ifindex expected
    local xdp_program_id tc_program_id
    [ -r "$OBJECT" ] || die "BPF object missing or unreadable: $OBJECT"
    expected=$(sha256sum "$OBJECT" 2>/dev/null | awk '{print $1}') \
        || die "cannot hash BPF object: $OBJECT"
    [ "$expected" = "$OBJECT_SHA256" ] || die "BPF object hash mismatch"
    load_state || die "not loaded"
    [ "$STATE_REUSE_MAPS" -eq 1 ] || die "state requires a map-schema migration sync"
    [ "$STATE_OBJECT_SHA256" = "$OBJECT_SHA256" ] \
        || die "state object digest does not match the selected object"
    generation=$STATE_GENERATION
    [ -r "$generation/progs/noid_lan_xdp" ] || die "missing pinned XDP program"
    [ -r "$generation/progs/noid_lan_egress" ] || die "missing pinned TC program"
    read -r xdp_program_id tc_program_id \
        < <(generation_program_identities "$generation") \
        || die "cannot identify the pinned XDP and TC programs"
    # The helper prints nothing on any rejection, so an empty or malformed read
    # must not reach the per-interface comparison as a wildcard.
    [[ $xdp_program_id =~ ^[1-9][0-9]*$ && $tc_program_id =~ ^[1-9][0-9]*$ ]] \
        || die "cannot identify the pinned XDP and TC programs"
    if [ -t 1 ] && declare -F fmt_section >/dev/null; then
        fmt_section "Live attachment identity"
    fi
    for entry in "${STATE_ENTRIES[@]}"; do
        iface=${entry%%:*}
        mode=${entry#*:}
        [ -d "$SYS_CLASS_NET/$iface/device" ] \
            || die "state interface is no longer physical"
        require_ethernet_link "$iface"
        # Keep inspection in the caller's already-authorized service domain.
        # Executing ip/tc transitions to Fedora's ifconfig_t; asking either
        # tool to expand a program loaded by NetworkManager's dispatcher then
        # requests cross-domain bpf:prog_run and emits a denied AVC. bpftool's
        # device-scoped JSON binds the same kernel attachments without that
        # transition. Its unrelated netfilter enumeration can be EPERM in the
        # capability-limited service and is deliberately ignored; the xdp/tc
        # arrays remain complete and were verified on the target sandbox.
        #
        # The pinned lookups above bind type, name and program ID. This
        # query additionally binds that ID to the exact interface, XDP mode
        # and clsact egress hook. The TC program is a side-effect-only flow
        # tracker and returns TC_ACT_OK on every exit, so its live hook/program
        # identity is the load-bearing postcondition; the attach path still
        # owns the stable pref/handle/direct-action configuration.
        case "$mode" in
            xdpdrv) expected_mode=driver ;;
            xdpgeneric) expected_mode=generic ;;
            *) die "invalid XDP mode in state" ;;
        esac
        expected_ifindex=$(read_ifindex "$iface")
        bpftool -j net show dev "$iface" 2>/dev/null \
            | python3 -c '
import json, sys
document = json.load(sys.stdin)
if (not isinstance(document, list) or len(document) != 1
        or not isinstance(document[0], dict)):
    raise SystemExit(1)
document = document[0]
iface, ifindex, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3]
xdp_id, tc_id = int(sys.argv[4]), int(sys.argv[5])
xdp = document.get("xdp")
tc = document.get("tc")
if not isinstance(xdp, list) or not isinstance(tc, list):
    raise SystemExit(1)
xdp_matches = [row for row in xdp if isinstance(row, dict)
               and row.get("devname") == iface
               and row.get("ifindex") == ifindex
               and row.get("mode") == mode
               and row.get("id") == xdp_id]
tc_matches = [row for row in tc if isinstance(row, dict)
              and row.get("devname") == iface
              and row.get("ifindex") == ifindex
              and row.get("kind") == "clsact/egress"
              and row.get("id") == tc_id]
if len(xdp_matches) != 1 or len(tc_matches) != 1:
    raise SystemExit(1)
' "$iface" "$expected_ifindex" "$expected_mode" \
                "$xdp_program_id" "$tc_program_id" \
            || die "live XDP/TC attachment identity mismatch on $iface"
        echo "ACTIVE interface=$iface mode=$mode"
    done
    echo "ACTIVE boundary=verified"
}

require_root
if [ "${NOID_LAN_XDP_LOCK_HELD:-0}" != 1 ]; then
    [[ "$LOCK_FILE" == /* && "$LOCK_FILE" != */ ]] \
        || die "lock path must be an absolute file path"
    install -d -m 0755 "${LOCK_FILE%/*}"
    exec flock --close --exclusive "$LOCK_FILE" env NOID_LAN_XDP_LOCK_HELD=1 \
        /bin/bash "$0" "$@"
fi
unset NOID_LAN_XDP_LOCK_HELD

# Human invocations receive the same TTY-only presentation as the other public
# NoID Privacy CLIs. Load it only after the lock-owning re-exec, otherwise both
# process images render the banner. Service, dispatcher and command-substitution
# callers retain the byte-stable machine output because stdout is redirected.
# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — LAN XDP Boundary" \
    NOID_FMT_AUTO_SUBTITLE="Live XDP and TC attachment identity" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

case "${1:-}" in
    sync) shift; [ "$#" -gt 0 ] || die "sync requires mode"; sync_policy "$@" ;;
    status) [ "$#" -eq 1 ] || die "status takes no arguments"; status ;;
    *) die "usage: $0 {sync 0|1 [--iface IFACE] [--peer IFACE,IPv4,MAC,DIRECTION,PROTOCOL,PORT_START,PORT_END] [--fresh-flow-map-for-peer IPv4]|status}" ;;
esac
