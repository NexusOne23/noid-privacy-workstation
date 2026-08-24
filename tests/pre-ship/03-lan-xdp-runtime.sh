#!/bin/bash
# Installed-candidate physical-link BPF release gate.
#
# Exercises the exact installed object in disposable network namespaces. It
# never attaches to a host physical interface. The test proves verifier load,
# forced generic-XDP pre-AF_PACKET drop, TC attachment, an allowed peer on one
# interface, and rejection of the same IP/MAC identity on a second interface.
set -euo pipefail

TEST_NAME=03-lan-xdp-runtime
OBJECT=${NOID_LAN_XDP_OBJECT:-/usr/lib/noid-privacy/noid-lan-xdp.bpf.o}
CONTROLLER=${NOID_LAN_XDP_CONTROLLER:-/usr/local/sbin/noid-lan-xdp}
REQUIRE_NATIVE=${NOID_REQUIRE_NATIVE_XDP:-0}
FIXTURES=$(cd "$(dirname "$0")" && pwd)/03-lan-xdp-packet-fixtures.py

if [ "$(id -u)" -ne 0 ]; then
    if sudo -n true >/dev/null 2>&1; then
        exec sudo -n env NOID_REQUIRE_NATIVE_XDP="$REQUIRE_NATIVE" \
            NOID_LAN_XDP_OBJECT="$OBJECT" \
            NOID_LAN_XDP_CONTROLLER="$CONTROLLER" "$0"
    fi
    echo "FAIL  $TEST_NAME: run as root or establish sudo credentials first" >&2
    exit 2
fi

for command in bpftool ip tc tcpdump timeout python3 awk sysctl nsenter \
               readlink unshare mountpoint ping grep sed; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "FAIL  $TEST_NAME: missing command: $command" >&2
        exit 2
    }
done
[ -r "$OBJECT" ] || { echo "FAIL  $TEST_NAME: missing installed BPF object" >&2; exit 2; }
[ -r "$FIXTURES" ] || { echo "FAIL  $TEST_NAME: missing packet fixtures" >&2; exit 2; }
mountpoint -q /sys/fs/bpf || { echo "FAIL  $TEST_NAME: bpffs is not mounted" >&2; exit 2; }
case "$REQUIRE_NATIVE" in 0|1) ;; *) echo "FAIL  $TEST_NAME: NOID_REQUIRE_NATIVE_XDP must be 0 or 1" >&2; exit 2 ;; esac

suffix=$$
va="nxa$suffix"; vb="nxb$suffix"; vc="nxc$suffix"; vd="nxd$suffix"
pin="/sys/fs/bpf/noid_xdp_preship_$suffix"
capture_dir=$(mktemp -d /var/tmp/noid-lan-xdp-capture.XXXXXX)
declare -a namespace_pids=()
declare -A namespace_ids=()
namespace_pid=
host_namespace=$(readlink /proc/self/ns/net) || {
    echo "FAIL  $TEST_NAME: cannot identify the host network namespace" >&2
    exit 1
}

cleanup() {
    local rc=$?
    trap - EXIT HUP INT TERM
    set +e
    ip link del "$va" >/dev/null 2>&1
    ip link del "$vc" >/dev/null 2>&1
    for namespace_pid in "${namespace_pids[@]}"; do
        kill "$namespace_pid" >/dev/null 2>&1
        wait "$namespace_pid" 2>/dev/null
    done
    find "$pin" -type f -delete >/dev/null 2>&1
    rmdir "$pin/progs" "$pin/maps" "$pin" >/dev/null 2>&1
    find "$capture_dir" -depth -delete >/dev/null 2>&1
    exit "$rc"
}
trap cleanup EXIT HUP INT TERM

spawn_namespace() {
    local observed=
    unshare --net /usr/bin/sleep 300 >/dev/null 2>&1 &
    namespace_pid=$!
    namespace_pids+=("$namespace_pid")
    for _ in {1..50}; do
        if observed=$(readlink "/proc/$namespace_pid/ns/net" 2>/dev/null) \
                && [ "$observed" != "$host_namespace" ]; then
            break
        fi
        kill -0 "$namespace_pid" 2>/dev/null || {
            echo "FAIL  $TEST_NAME: process-bound network namespace exited during setup" >&2
            exit 1
        }
        sleep 0.02
    done
    [ -n "$observed" ] && [ "$observed" != "$host_namespace" ] || {
        echo "FAIL  $TEST_NAME: process-bound network namespace did not become observable" >&2
        exit 1
    }
    [[ -z ${namespace_ids[$observed]+present} ]] || {
        echo "FAIL  $TEST_NAME: unshare reused a network namespace identity" >&2
        exit 1
    }
    namespace_ids["$observed"]=1
}

in_namespace() {
    local target_pid=$1
    shift
    nsenter --target "$target_pid" --net -- "$@"
}

start_tcpdump_capture() {
    local target_pid=$1 capture_timeout=$2 interface=$3 stderr_file=$4
    local capture_rc
    shift 4

    : > "$stderr_file" || return 1
    LC_ALL=C in_namespace "$target_pid" timeout "$capture_timeout" \
        tcpdump -lnni "$interface" -c 1 "$@" \
        >/dev/null 2>"$stderr_file" &
    capture_pid=$!
    for _ in {1..100}; do
        if grep -Fq "listening on $interface," "$stderr_file"; then
            return 0
        fi
        if ! kill -0 "$capture_pid" 2>/dev/null; then
            if wait "$capture_pid"; then capture_rc=0; else capture_rc=$?; fi
            echo "FAIL  $TEST_NAME: tcpdump exited before readiness (rc=$capture_rc)" >&2
            sed 's/^/  tcpdump: /' "$stderr_file" >&2
            return 1
        fi
        sleep 0.02
    done
    echo "FAIL  $TEST_NAME: tcpdump readiness was not observable on $interface" >&2
    kill "$capture_pid" 2>/dev/null || true
    wait "$capture_pid" 2>/dev/null || true
    sed 's/^/  tcpdump: /' "$stderr_file" >&2
    return 1
}

spawn_namespace; pid_a=$namespace_pid
spawn_namespace; pid_b=$namespace_pid
spawn_namespace; pid_c=$namespace_pid
spawn_namespace; pid_d=$namespace_pid
for target_pid in "$pid_a" "$pid_b" "$pid_c" "$pid_d"; do
    in_namespace "$target_pid" ip link set lo up
    in_namespace "$target_pid" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
    in_namespace "$target_pid" sysctl -qw net.ipv6.conf.default.disable_ipv6=1
done
ip link add "$va" type veth peer name "$vb"
ip link add "$vc" type veth peer name "$vd"
ip link set "$va" netns "$pid_a"; ip link set "$vb" netns "$pid_b"
ip link set "$vc" netns "$pid_c"; ip link set "$vd" netns "$pid_d"

in_namespace "$pid_a" ip link set "$va" address 02:00:00:00:00:01
in_namespace "$pid_c" ip link set "$vc" address 02:00:00:00:00:01
in_namespace "$pid_b" ip link set "$vb" address 02:00:00:00:00:02
in_namespace "$pid_d" ip link set "$vd" address 02:00:00:00:00:03
in_namespace "$pid_a" ip addr add 192.0.2.1/24 dev "$va"
in_namespace "$pid_b" ip addr add 192.0.2.2/24 dev "$vb"
in_namespace "$pid_c" ip addr add 192.0.2.1/24 dev "$vc"
in_namespace "$pid_d" ip addr add 192.0.2.2/24 dev "$vd"
for spec in "$pid_a:$va" "$pid_b:$vb" "$pid_c:$vc" "$pid_d:$vd"; do
    in_namespace "${spec%%:*}" ip link set "${spec#*:}" up
done

# Static neighbours keep ARP bootstrap out of this exact peer-key test.
in_namespace "$pid_a" ip neigh replace 192.0.2.2 lladdr 02:00:00:00:00:02 dev "$va" nud permanent
in_namespace "$pid_b" ip neigh replace 192.0.2.1 lladdr 02:00:00:00:00:01 dev "$vb" nud permanent
in_namespace "$pid_c" ip neigh replace 192.0.2.2 lladdr 02:00:00:00:00:03 dev "$vc" nud permanent
in_namespace "$pid_d" ip neigh replace 192.0.2.1 lladdr 02:00:00:00:00:01 dev "$vd" nud permanent

mkdir -p "$pin/progs" "$pin/maps"
bpftool prog loadall "$OBJECT" "$pin/progs" pinmaps "$pin/maps"
xdp_id=$(bpftool prog show pinned "$pin/progs/noid_lan_xdp" | awk -F: 'NR==1 {print $1}')
xdp_tc_id=$(bpftool prog show pinned "$pin/progs/noid_lan_egress" | awk -F: 'NR==1 {print $1}')
[[ $xdp_id =~ ^[0-9]+$ && $xdp_tc_id =~ ^[0-9]+$ ]] || {
    echo "FAIL  $TEST_NAME: cannot identify loaded programs" >&2
    exit 1
}

native=unavailable
if in_namespace "$pid_b" bpftool net attach xdpdrv id "$xdp_id" dev "$vb" 2>/dev/null; then
    native=verified
    in_namespace "$pid_b" bpftool net detach xdpdrv dev "$vb"
elif [ "$REQUIRE_NATIVE" -eq 1 ]; then
    echo "FAIL  $TEST_NAME: native XDP was required but rejected" >&2
    exit 1
fi
in_namespace "$pid_b" bpftool net attach xdpgeneric id "$xdp_id" dev "$vb"
in_namespace "$pid_d" bpftool net attach xdpgeneric id "$xdp_id" dev "$vd"
in_namespace "$pid_b" tc qdisc replace dev "$vb" clsact
# Enter only the process-bound network namespace. The host mount namespace and
# the already loaded bpffs pins remain visible, so TC attaches the shared-map
# program instead of loading a second object.
in_namespace "$pid_b" tc filter replace dev "$vb" egress \
    pref 10 handle 1 bpf direct-action \
    object-pinned "$pin/progs/noid_lan_egress"
in_namespace "$pid_b" tc filter show dev "$vb" egress pref 10 \
    | grep -q 'noid_lan_egress'

ifindex_b=$(in_namespace "$pid_b" ip -o link show "$vb" | awk -F: '{gsub(/ /,"",$1); print $1}')
mapfile -t peer_key < <(python3 - "$ifindex_b" <<'PY'
import ipaddress
import sys

key = (
    int(sys.argv[1]).to_bytes(4, sys.byteorder)
    + ipaddress.IPv4Address("192.0.2.1").packed
    + bytes.fromhex("020000000001")
    + b"\0\0"
)
for byte in key:
    print(f"{byte:02x}")
PY
)
bpftool map update pinned "$pin/maps/noid_xdp_peer4" \
    key hex "${peer_key[@]}" value hex 01 00 00 00 00 00 00 00
mapfile -t local_mac_key < <(python3 - "$ifindex_b" <<'PY'
import sys

key = int(sys.argv[1]).to_bytes(4, sys.byteorder) + bytes.fromhex("020000000002") + b"\0\0"
for byte in key:
    print(f"{byte:02x}")
PY
)
bpftool map update pinned "$pin/maps/noid_xdp_local_macs" \
    key hex "${local_mac_key[@]}" value hex 01

stat_count() {
    local reason=$1
    local key
    printf -v key '%02x' "$reason"
    bpftool -j map lookup pinned "$pin/maps/noid_xdp_stats" \
        key hex "$key" 00 00 00 \
        | python3 -c 'import json,sys; print(sum(row["value"] for row in json.load(sys.stdin)["formatted"]["values"]))'
}

# All namespace addresses above were assigned directly, without a DHCP client.
# Even a structurally valid reply with the exact local MAC and transaction ID
# must therefore drop before AF_PACKET while no request-created map entry
# exists. The later positive fixture installs that exact entry and proves this
# is transaction correlation, not an unconditional DHCP drop.
default_before=$(stat_count 8)
dhcp_before=$(stat_count 3)
set +e
start_tcpdump_capture "$pid_b" 4 "$vb" \
    "$capture_dir/unsolicited-dhcp-tcpdump.stderr" \
    'udp src port 67 and udp dst port 68' || exit 1
unsolicited_dhcp_capture_pid=$capture_pid
in_namespace "$pid_a" python3 "$FIXTURES" --interface "$va" --suite dhcp-reply \
    >/dev/null 2>&1
unsolicited_dhcp_send_rc=$?
wait "$unsolicited_dhcp_capture_pid"
unsolicited_dhcp_capture_rc=$?
set -e
[ "$unsolicited_dhcp_send_rc" -eq 0 ] || {
    echo "FAIL  $TEST_NAME: unsolicited DHCP reply sender failed" >&2
    exit 1
}
[ "$unsolicited_dhcp_capture_rc" -eq 124 ] || {
    echo "FAIL  $TEST_NAME: static-address namespace received DHCP without a tracked request" >&2
    exit 1
}
[ $(( $(stat_count 8) - default_before )) -eq 1 ] || {
    echo "FAIL  $TEST_NAME: unsolicited DHCP reply did not take the default-drop path" >&2
    exit 1
}
[ $(( $(stat_count 3) - dhcp_before )) -eq 0 ] || {
    echo "FAIL  $TEST_NAME: unsolicited DHCP reply took the DHCP pass path" >&2
    exit 1
}

# Open the exact DHCP transaction and related-flow fixtures. Values use the
# kernel's monotonic clock and host-endian map ABI, matching the controller.
mapfile -t live_expiry < <(python3 <<'PY'
import sys
import time

value = time.clock_gettime_ns(time.CLOCK_MONOTONIC) + 60_000_000_000
for byte in value.to_bytes(8, sys.byteorder):
    print(f"{byte:02x}")
PY
)
mapfile -t dhcp_key < <(python3 - "$ifindex_b" <<'PY'
import sys

key = (
    int(sys.argv[1]).to_bytes(4, sys.byteorder)
    + (0x12345678).to_bytes(4, "big")
    + bytes.fromhex("020000000002") + b"\0\0"
)
for byte in key:
    print(f"{byte:02x}")
PY
)
bpftool map update pinned "$pin/maps/noid_xdp_dhcp_v4" \
    key hex "${dhcp_key[@]}" value hex "${live_expiry[@]}"
mapfile -t gateway_key < <(python3 - "$ifindex_b" <<'PY'
import sys

key = int(sys.argv[1]).to_bytes(4, sys.byteorder) + bytes.fromhex("020000000001") + b"\0\0"
for byte in key:
    print(f"{byte:02x}")
PY
)
bpftool map update pinned "$pin/maps/noid_xdp_gateway_macs" \
    key hex "${gateway_key[@]}" value hex 01
mapfile -t related_flow_key < <(python3 - "$ifindex_b" <<'PY'
import ipaddress
import sys

key = (
    int(sys.argv[1]).to_bytes(4, sys.byteorder)
    + ipaddress.IPv4Address("198.51.100.1").packed
    + ipaddress.IPv4Address("192.0.2.2").packed
    + (443).to_bytes(2, "big")
    + (50000).to_bytes(2, "big")
    + bytes([6, 0, 0, 0])
)
for byte in key:
    print(f"{byte:02x}")
PY
)
bpftool map update pinned "$pin/maps/noid_xdp_flows_v4" \
    key hex "${related_flow_key[@]}" value hex "${live_expiry[@]}"

# Thirty-three live malformed or explicitly unsupported L2/L3/L4/MAC/checksum
# fixtures, including both PPPoE EtherTypes, must take the ordinary drop path.
# All three fragment forms must take the dedicated fragment drop path. An
# AF_PACKET observer on the receiving veth must see none of them.
default_before=$(stat_count 8)
fragment_before=$(stat_count 7)
set +e
start_tcpdump_capture "$pid_b" 4 "$vb" "$capture_dir/invalid-tcpdump.stderr" \
    'ether src 02:00:00:00:00:01 or ether src 02:00:00:00:00:03' || exit 1
fixture_capture_pid=$capture_pid
in_namespace "$pid_a" python3 "$FIXTURES" --interface "$va" --suite invalid \
    >/dev/null 2>&1
fixture_send_rc=$?
wait "$fixture_capture_pid"
fixture_capture_rc=$?
set -e
[ "$fixture_send_rc" -eq 0 ] || {
    echo "FAIL  $TEST_NAME: raw malformed-fixture sender failed" >&2
    exit 1
}
[ "$fixture_capture_rc" -eq 124 ] || {
    echo "FAIL  $TEST_NAME: AF_PACKET observed a malformed fixture after XDP" >&2
    exit 1
}
default_after=$(stat_count 8)
fragment_after=$(stat_count 7)
[ $((default_after - default_before)) -eq 33 ] || {
    echo "FAIL  $TEST_NAME: malformed default-drop delta was $((default_after - default_before)), expected 33" >&2
    exit 1
}
[ $((fragment_after - fragment_before)) -eq 3 ] || {
    echo "FAIL  $TEST_NAME: fragment-drop delta was $((fragment_after - fragment_before)), expected 3" >&2
    exit 1
}

set_peer_policy() {
    local policy=$1
    local -a value=()
    case "$policy" in
        outbound)
            value=(01 00 00 00 00 00 00 00) ;;
        inbound-tcp-443)
            value=(02 06 bb 01 bb 01 00 00) ;;
        inbound-udp-5300-5301)
            value=(02 11 b4 14 b5 14 00 00) ;;
        both-udp-5300-5301)
            value=(03 11 b4 14 b5 14 00 00) ;;
        *) echo "FAIL  $TEST_NAME: unknown peer policy fixture: $policy" >&2; exit 1 ;;
    esac
    bpftool map update pinned "$pin/maps/noid_xdp_peer4" \
        key hex "${peer_key[@]}" value hex "${value[@]}"
}

send_peer_suite() {
    in_namespace "$pid_a" python3 "$FIXTURES" --interface "$va" \
        --suite "$1" >/dev/null
}

# Outbound-only admits no unsolicited peer protocol, but the exact reverse
# TCP, UDP and ICMP tuples observed first at local TC egress remain reachable.
set_peer_policy outbound
default_before=$(stat_count 8)
peer_before=$(stat_count 1)
send_peer_suite peer-unsolicited-alt1
[ $(( $(stat_count 8) - default_before )) -eq 6 ] || {
    echo "FAIL  $TEST_NAME: outbound-only did not drop all 6 unsolicited peer probes" >&2
    exit 1
}
[ $(( $(stat_count 1) - peer_before )) -eq 0 ] || {
    echo "FAIL  $TEST_NAME: outbound-only used an unsolicited peer pass" >&2
    exit 1
}
in_namespace "$pid_b" python3 "$FIXTURES" --interface "$vb" \
    --suite peer-flow-open >/dev/null
flow_before=$(stat_count 5)
send_peer_suite peer-flow-replies
[ $(( $(stat_count 5) - flow_before )) -eq 3 ] || {
    echo "FAIL  $TEST_NAME: outbound-only did not admit all 3 correlated replies" >&2
    exit 1
}

# Inbound TCP accepts exactly dport 443. Live reverse-flow state cannot widen
# an inbound-only policy because the outbound direction bit is absent.
set_peer_policy inbound-tcp-443
default_before=$(stat_count 8)
peer_before=$(stat_count 1)
send_peer_suite peer-unsolicited-alt2
[ $(( $(stat_count 1) - peer_before )) -eq 1 ] || {
    echo "FAIL  $TEST_NAME: inbound TCP did not admit exactly port 443" >&2
    exit 1
}
[ $(( $(stat_count 8) - default_before )) -eq 5 ] || {
    echo "FAIL  $TEST_NAME: inbound TCP did not reject 5 wrong selector/protocol probes" >&2
    exit 1
}
default_before=$(stat_count 8)
flow_before=$(stat_count 5)
peer_before=$(stat_count 1)
send_peer_suite peer-flow-replies
[ $(( $(stat_count 1) - peer_before )) -eq 1 ] \
    && [ $(( $(stat_count 5) - flow_before )) -eq 0 ] \
    && [ $(( $(stat_count 8) - default_before )) -eq 2 ] || {
    echo "FAIL  $TEST_NAME: inbound TCP was widened by stale UDP/ICMP flow state" >&2
    exit 1
}

# Inbound UDP range accepts both endpoints, but adjacent UDP, TCP and ICMP are
# rejected. Even live flow state remains unusable without the outbound bit.
set_peer_policy inbound-udp-5300-5301
default_before=$(stat_count 8)
peer_before=$(stat_count 1)
send_peer_suite peer-unsolicited-alt3
[ $(( $(stat_count 1) - peer_before )) -eq 2 ] || {
    echo "FAIL  $TEST_NAME: inbound UDP did not admit both exact range endpoints" >&2
    exit 1
}
[ $(( $(stat_count 8) - default_before )) -eq 4 ] || {
    echo "FAIL  $TEST_NAME: inbound UDP did not reject adjacent/protocol/ICMP probes" >&2
    exit 1
}
default_before=$(stat_count 8)
flow_before=$(stat_count 5)
send_peer_suite peer-flow-replies
[ $(( $(stat_count 5) - flow_before )) -eq 0 ] \
    && [ $(( $(stat_count 8) - default_before )) -eq 3 ] || {
    echo "FAIL  $TEST_NAME: inbound UDP was widened by live reverse-flow state" >&2
    exit 1
}

# Both is the exact union: the same UDP range plus all three correlated reply
# protocols, while wrong unsolicited selectors still drop.
set_peer_policy both-udp-5300-5301
default_before=$(stat_count 8)
peer_before=$(stat_count 1)
send_peer_suite peer-unsolicited
peer_delta=$(( $(stat_count 1) - peer_before ))
default_delta=$(( $(stat_count 8) - default_before ))
[ "$peer_delta" -eq 2 ] && [ "$default_delta" -eq 4 ] || {
    echo "FAIL  $TEST_NAME: both-direction unsolicited selector is not exact (peer=$peer_delta drop=$default_delta)" >&2
    exit 1
}
flow_before=$(stat_count 5)
send_peer_suite peer-flow-replies
[ $(( $(stat_count 5) - flow_before )) -eq 3 ] || {
    echo "FAIL  $TEST_NAME: both-direction did not include all correlated replies" >&2
    exit 1
}

# Positive raw fixtures prove the same parser admits fully consistent frames
# in each exceptional branch instead of achieving safety by dropping all.
eapol_before=$(stat_count 2)
dhcp_before=$(stat_count 3)
arp_before=$(stat_count 4)
icmp_error_before=$(stat_count 6)
in_namespace "$pid_a" python3 "$FIXTURES" --interface "$va" --suite valid >/dev/null
[ $(( $(stat_count 2) - eapol_before )) -eq 1 ] || {
    echo "FAIL  $TEST_NAME: valid bounded EAPOL fixture did not pass" >&2
    exit 1
}
[ $(( $(stat_count 3) - dhcp_before )) -eq 1 ] || {
    echo "FAIL  $TEST_NAME: valid checksum-bearing DHCP fixture did not pass" >&2
    exit 1
}
[ $(( $(stat_count 4) - arp_before )) -eq 4 ] || {
    echo "FAIL  $TEST_NAME: valid ARP reply/request/Probe/Announcement fixtures did not pass" >&2
    exit 1
}
[ $(( $(stat_count 6) - icmp_error_before )) -eq 1 ] || {
    echo "FAIL  $TEST_NAME: valid related ICMP error did not pass its inner-header/flow checks" >&2
    exit 1
}

# NetworkManager changes from the permanent MAC to its stable cloned MAC before
# DHCP. Prove that the exact shared TC program records the newly emitted local
# source MAC and DHCP transaction before XDP evaluates the server reply.
rotated_mac=02:00:00:00:00:10
in_namespace "$pid_b" ip link set "$vb" down
in_namespace "$pid_b" ip link set "$vb" address "$rotated_mac"
in_namespace "$pid_b" ip link set "$vb" up
mapfile -t rotated_mac_key < <(python3 - "$ifindex_b" <<'PY'
import sys

key = int(sys.argv[1]).to_bytes(4, sys.byteorder) + bytes.fromhex("020000000010") + b"\0\0"
for byte in key:
    print(f"{byte:02x}")
PY
)
if bpftool map lookup pinned "$pin/maps/noid_xdp_local_macs" \
        key hex "${rotated_mac_key[@]}" >/dev/null 2>&1; then
    echo "FAIL  $TEST_NAME: rotated MAC precondition was already present" >&2
    exit 1
fi
in_namespace "$pid_b" python3 "$FIXTURES" --interface "$vb" \
    --suite dhcp-request-rotated >/dev/null
bpftool map lookup pinned "$pin/maps/noid_xdp_local_macs" \
    key hex "${rotated_mac_key[@]}" >/dev/null || {
    echo "FAIL  $TEST_NAME: TC egress did not register the rotated local MAC" >&2
    exit 1
}
mapfile -t rotated_dhcp_key < <(python3 - "$ifindex_b" <<'PY'
import sys

key = (
    int(sys.argv[1]).to_bytes(4, sys.byteorder)
    + (0x87654321).to_bytes(4, "big")
    + bytes.fromhex("020000000010") + b"\0\0"
)
for byte in key:
    print(f"{byte:02x}")
PY
)
bpftool map lookup pinned "$pin/maps/noid_xdp_dhcp_v4" \
    key hex "${rotated_dhcp_key[@]}" >/dev/null || {
    echo "FAIL  $TEST_NAME: TC egress did not register the rotated DHCP tuple" >&2
    exit 1
}
dhcp_rotated_before=$(stat_count 3)
set +e
start_tcpdump_capture "$pid_b" 4 "$vb" "$capture_dir/rotated-tcpdump.stderr" \
    'udp src port 67 and udp dst port 68' || exit 1
rotated_capture_pid=$capture_pid
in_namespace "$pid_a" python3 "$FIXTURES" --interface "$va" \
    --suite dhcp-reply-rotated >/dev/null 2>&1
rotated_send_rc=$?
wait "$rotated_capture_pid"
rotated_capture_rc=$?
set -e
[ "$rotated_send_rc" -eq 0 ] || {
    echo "FAIL  $TEST_NAME: rotated DHCP reply sender failed" >&2
    exit 1
}
[ "$rotated_capture_rc" -eq 0 ] || {
    echo "FAIL  $TEST_NAME: XDP dropped the exact rotated-MAC DHCP reply" >&2
    exit 1
}
[ $(( $(stat_count 3) - dhcp_rotated_before )) -eq 1 ] || {
    echo "FAIL  $TEST_NAME: rotated-MAC DHCP reply did not take the DHCP pass path" >&2
    exit 1
}

# First prove the second veth pair and its static neighbour setup can carry the
# same ping when XDP is absent. Then reattach XDP: the same source IP and MAC on
# the second interface must increment the default-drop counter before an
# ordinary packet socket can observe it.
in_namespace "$pid_d" bpftool net detach xdpgeneric dev "$vd"
in_namespace "$pid_c" ping -c 1 -W 1 192.0.2.2 >/dev/null 2>&1 || {
    echo "FAIL  $TEST_NAME: multi-NIC positive-control ping failed without XDP" >&2
    exit 1
}
in_namespace "$pid_d" bpftool net attach xdpgeneric id "$xdp_id" dev "$vd"
cross_default_before=$(stat_count 8)
set +e
start_tcpdump_capture "$pid_d" 3 "$vd" "$capture_dir/cross-tcpdump.stderr" icmp || exit 1
cross_capture_pid=$capture_pid
in_namespace "$pid_c" ping -c 1 -W 1 192.0.2.2 >/dev/null 2>&1
cross_ping_rc=$?
wait "$cross_capture_pid"
cross_capture_rc=$?
set -e
[ "$cross_ping_rc" -eq 1 ] || {
    echo "FAIL  $TEST_NAME: cross-interface ping returned unexpected status $cross_ping_rc" >&2
    exit 1
}
[ $(( $(stat_count 8) - cross_default_before )) -ge 1 ] || {
    echo "FAIL  $TEST_NAME: cross-interface probe did not reach the XDP default-drop path" >&2
    exit 1
}
[ "$cross_capture_rc" -eq 124 ] || {
    echo "FAIL  $TEST_NAME: AF_PACKET observed the cross-interface frame" >&2
    exit 1
}

# On an installed system the production controller must independently verify
# its real links/hash. This isolated gate does not replace that status check.
if [ -x "$CONTROLLER" ] && [ -r /run/noid-privacy/lan-xdp.state ]; then
    "$CONTROLLER" status >/dev/null
fi

echo "PASS  $TEST_NAME: verifier+generic+TC+36 invalid/unsupported+direction matrix+static-address unsolicited DHCP drop+7 baseline valid+stable-MAC rotation+multi-NIC binding; native=$native"
