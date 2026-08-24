#!/bin/bash
# Closed state grammar, path confinement, exact attachment identity and
# multi-interface rollback tests for the LAN-XDP controller.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

ROOT=$(find_project_root)
CONTROLLER_SOURCE="$ROOT/overrides/noid-lan-xdp/noid-lan-xdp.sh"
PAYLOAD="$ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.o.b64"
EXPECTED_HASH=9f244286de91021ed53fab3f1bf03cdfc248aa9e0090061a91beafe39f96849a
# NoID Privacy deliberately mounts /tmp noexec. Ignore an ambient TMPDIR that
# may point there; executable fixture doubles always live below /var/tmp.
TMPDIR=$(mktemp -d /var/tmp/noid-test-03b.XXXXXX)
cleanup() { find "$TMPDIR" -depth -delete; }
trap cleanup EXIT
MOCKBIN="$TMPDIR/bin"
BPF_ROOT="$TMPDIR/bpf-root"
GENERATION="$BPF_ROOT/generation_100_1"
STATE="$TMPDIR/state"
SYS_NET="$TMPDIR/sys-class-net"
OBJECT="$TMPDIR/object.o"
MOCK_LOG="$TMPDIR/mock.log"
ARP_STATE_DIR="$TMPDIR/arp-state-root"
ARP_STATE="$ARP_STATE_DIR/arp-hardening.state"
CONTROLLER="$TMPDIR/noid-lan-xdp.sh"

test_start "03b-lan-xdp-controller-state"
fixture_uid=$(id -u)
fixture_gid=$(id -g)
sed \
    -e "s/^EXPECTED_ARP_STATE_UID=0$/EXPECTED_ARP_STATE_UID=$fixture_uid/" \
    -e "s/^EXPECTED_ARP_STATE_GID=0$/EXPECTED_ARP_STATE_GID=$fixture_gid/" \
    "$CONTROLLER_SOURCE" > "$CONTROLLER"
chmod 0755 "$CONTROLLER"
mkdir -p "$MOCKBIN" "$GENERATION/progs" "$GENERATION/maps" \
    "$SYS_NET/eth0/device" "$SYS_NET/eth1/device" "$ARP_STATE_DIR"
chmod 0755 "$ARP_STATE_DIR"
printf '%s\n' 11 > "$SYS_NET/eth0/ifindex"
printf '%s\n' 12 > "$SYS_NET/eth1/ifindex"
printf '%s\n' 1 > "$SYS_NET/eth0/type"
printf '%s\n' 1 > "$SYS_NET/eth1/type"
printf '%s\n' 02:00:00:00:00:10 > "$SYS_NET/eth0/address"
printf '%s\n' 02:00:00:00:00:11 > "$SYS_NET/eth1/address"
touch "$GENERATION/progs/noid_lan_xdp" "$GENERATION/progs/noid_lan_egress"
base64 -d "$PAYLOAD" > "$OBJECT"
assert_eq "$EXPECTED_HASH" "$(sha256sum "$OBJECT" | awk '{print $1}')" \
    "state fixtures use the exact pinned BPF object"

cat > "$MOCKBIN/id" <<'MOCK'
#!/bin/bash
if [ "${1:-}" = -u ]; then echo 0; else exec /usr/bin/id "$@"; fi
MOCK
cat > "$MOCKBIN/mountpoint" <<'MOCK'
#!/bin/bash
exit 0
MOCK
cat > "$MOCKBIN/stat" <<'MOCK'
#!/bin/bash
if [ "${1:-}" = -c ] && [ "${2:-}" = %u:%a ] \
        && [ "${3:-}" = -- ] && [ "${4:-}" = "$MOCK_STATE_FILE" ]; then
    printf '%s\n' "${MOCK_STATE_META:-0:600}"
else
    exec /usr/bin/stat "$@"
fi
MOCK
cat > "$MOCKBIN/ip" <<'MOCK'
#!/bin/bash
printf 'ip %s\n' "$*" >> "$MOCK_LOG"
MOCK
cat > "$MOCKBIN/tc" <<'MOCK'
#!/bin/bash
printf 'tc %s\n' "$*" >> "$MOCK_LOG"
if [ "${1:-}" = filter ] && [ "${2:-}" = replace ] \
        && [ "${3:-}" = dev ] \
        && [ "${4:-}" = "${MOCK_TC_FAIL_IFACE:-}" ] \
        && [ ! -e "${MOCK_TC_FAIL_MARKER:-/nonexistent}" ]; then
    : > "$MOCK_TC_FAIL_MARKER"
    exit 1
fi
MOCK
cat > "$MOCKBIN/bpftool" <<'MOCK'
#!/bin/bash
printf 'bpftool %s\n' "$*" >> "$MOCK_LOG"
if [ "${1:-}" = -j ] && [ "${2:-}" = net ]; then
    iface=${5:-eth0}
    netdev=${MOCK_NET_DEV:-$iface}
    printf '[{"xdp":[{"devname":"%s","ifindex":11,"mode":"%s","id":%s}],' \
        "$netdev" "${MOCK_XDP_MODE:-generic}" "${MOCK_XDP_ID:-101}"
    printf '"tc":[{"devname":"%s","ifindex":11,"kind":"%s","name":"noid_lan_egress:[*fsobj]","id":%s}],' \
        "$netdev" "${MOCK_TC_KIND:-clsact/egress}" "${MOCK_TC_ID:-202}"
    printf '"flow_dissector":[],"netfilter":[{"error":"Operation not permitted"}]}]\n'
    exit 0
fi
case " $* " in
    *" prog show "*)
        case " $* " in
            *" pinned "*) : ;;
            *)
                # Regression guard for the boot-wedge defect. Enumerating BPF
                # programs needs BPF_PROG_GET_NEXT_ID, which the kernel gates
                # on CAP_SYS_ADMIN -- a capability none of the units driving
                # this controller carry. Under the shipped bounding set the
                # real tool answers exactly like this, identifying an existing
                # generation becomes impossible, and module 05's fail-closed
                # revoke path turns that into a NetworkManager-stop loop that
                # leaves the machine without a login. Refuse it here so any
                # reintroduction fails in the suite instead of on a user's disk.
                printf '[{"error":"can not get next program: Operation not permitted"}]\n'
                exit 255 ;;
        esac ;;
esac
if [ "${1:-}" = -j ] && [ "${2:-}" = prog ] && [ "${3:-}" = show ] \
   && [ "${4:-}" = pinned ]; then
    # One lookup per pin path, exactly as the controller now asks for it. The
    # kernel resolves the path, so a state pointing at a missing generation
    # fails the way `bpf obj get` fails on the real tool -- rejected by the
    # controller, not by the mock. The identities stay literal here while the
    # `net` branch above honours MOCK_XDP_ID/MOCK_TC_ID, so a test can still
    # drive the live attachment away from the pinned program identity.
    pin=${5:?mock: no pin path}
    if [ ! -e "$pin" ]; then
        printf '{"error":"bpf obj get (%s): No such file or directory"}\n' "$pin"
        exit 255
    fi
    case "$pin" in
        */progs/noid_lan_xdp)
            printf '{"id":%s,"type":"xdp","name":"noid_lan_xdp","tag":"1111111111111111"}\n' \
                "101" ;;
        */progs/noid_lan_egress)
            printf '{"id":%s,"type":"sched_cls","name":"%s","tag":"2222222222222222"}\n' \
                "202" "${MOCK_PINNED_TC_NAME:-noid_lan_egress}" ;;
        *) exit 1 ;;
    esac
    exit 0
fi
if [ "${1:-}" = -j ] && [ "${2:-}" = map ]; then
    case "${*: -1}" in
        */noid_xdp_flows_v4)
            printf '{"type":"lru_hash","flags":0,"bytes_key":20,"bytes_value":8,"max_entries":%s}\n' \
                "${MOCK_FLOW_MAX:-65536}" ;;
        */noid_xdp_dhcp_v4)
            printf '{"type":"lru_hash","flags":0,"bytes_key":16,"bytes_value":8,"max_entries":256}\n' ;;
        */noid_xdp_stats)
            printf '{"type":"percpu_array","flags":0,"bytes_key":4,"bytes_value":8,"max_entries":9}\n' ;;
        *) exit 1 ;;
    esac
    exit 0
fi
if [ "${1:-}" = prog ] && [ "${2:-}" = loadall ]; then
    # The pinmaps argument is not at a fixed position: every reused map adds
    # 'map name <m> pinned <p>' ahead of it. Guessing $6 silently created a
    # directory called 'name' in the caller's working directory.
    progdir=$4
    mapdir=''
    prev=''
    for arg in "$@"; do
        [ "$prev" = pinmaps ] && mapdir=$arg
        prev=$arg
    done
    [ -n "$mapdir" ] || { echo "mock: no pinmaps argument" >&2; exit 1; }
    mkdir -p "$progdir" "$mapdir"
    touch "$progdir/noid_lan_xdp" "$progdir/noid_lan_egress"
    exit 0
fi
if [ "${1:-}" = net ] && [ "${2:-}" = attach ]; then
    args=("$@")
    for ((i=0; i<${#args[@]}; i++)); do
        if [ "${args[$i]}" = dev ] && [ "${args[$((i+1))]}" = "${MOCK_FAIL_IFACE:-}" ]; then
            exit 1
        fi
    done
fi
exit 0
MOCK
chmod 0755 "$MOCKBIN"/*
fixture_identity=$(env PATH="$MOCKBIN:/usr/bin:/bin" /bin/bash -c 'command -v id; id -u')
assert_eq "$MOCKBIN/id
0" "$fixture_identity" \
    "controller fixture executes with the root identity stub"

write_state() {
    printf '%s\n' "$@" > "$STATE"
    chmod 0600 "$STATE"
}

run_controller_with_env() {
    env PATH="$MOCKBIN:/usr/bin:/bin" MOCK_LOG="$MOCK_LOG" \
        MOCK_STATE_FILE="$STATE" \
        NOID_LAN_XDP_OBJECT="$OBJECT" NOID_LAN_XDP_BPF_ROOT="$BPF_ROOT" \
        NOID_LAN_XDP_STATE_FILE="$STATE" NOID_SYS_CLASS_NET="$SYS_NET" \
        NOID_LAN_XDP_POLICY_DIGEST_FILE="$TMPDIR/policy-digest" \
        NOID_ARP_STATE_FILE="${NOID_TEST_ARP_STATE:-$TMPDIR/no-arp-state}" \
        NOID_LAN_XDP_LOCK_HELD=1 "$@" /bin/bash "$CONTROLLER" status
}
run_controller() {
    run_controller_with_env NOID_CONTROLLER_FIXTURE=1
}

valid_state() {
    write_state \
        STATE_SCHEMA=2 MAP_SCHEMA=4 OBJECT_SHA256="$EXPECTED_HASH" \
        GEN="$GENERATION" IFACE=eth0:xdpgeneric
}

valid_state
if status_output=$(run_controller 2>&1); then
    _pass "closed state/map-v4 and exact bpftool XDP/TC identities pass"
else
    _fail "closed state/map-v4 and exact bpftool XDP/TC identities pass"
    printf '    diagnostic: %s\n' "$status_output"
fi

# Current mktemp-generation names and the immediately preceding PID/RANDOM
# names both remain readable across the one-way controller migration.
CURRENT_GENERATION="$BPF_ROOT/generation_Ab12Cd34"
mkdir -p "$CURRENT_GENERATION/progs" "$CURRENT_GENERATION/maps"
touch "$CURRENT_GENERATION/progs/noid_lan_xdp" \
    "$CURRENT_GENERATION/progs/noid_lan_egress"
write_state STATE_SCHEMA=2 MAP_SCHEMA=4 OBJECT_SHA256="$EXPECTED_HASH" \
    GEN="$CURRENT_GENERATION" IFACE=eth0:xdpgeneric
assert_cmd_success "atomically generated current state name is accepted" \
    run_controller
valid_state

LOCK_FILE="$TMPDIR/run/noid-privacy/lan-xdp.lock"
assert_cmd_success "controller status succeeds under its real parent-held lock" \
    env PATH="$MOCKBIN:/usr/bin:/bin" MOCK_LOG="$MOCK_LOG" \
        MOCK_STATE_FILE="$STATE" \
        NOID_LAN_XDP_OBJECT="$OBJECT" NOID_LAN_XDP_BPF_ROOT="$BPF_ROOT" \
        NOID_LAN_XDP_STATE_FILE="$STATE" NOID_SYS_CLASS_NET="$SYS_NET" \
        NOID_LAN_XDP_POLICY_DIGEST_FILE="$TMPDIR/policy-digest" \
        NOID_ARP_STATE_FILE="$TMPDIR/no-arp-state" \
        NOID_LAN_XDP_LOCK_FILE="$LOCK_FILE" \
        /bin/bash "$CONTROLLER" status
assert_eq 600 "$(stat -c '%a' "$LOCK_FILE")" \
    "controller lock is root-private"

printf '%s\n' 65534 > "$SYS_NET/eth0/type"
assert_cmd_failure "non-Ethernet state cannot report an active boundary" \
    run_controller
printf '%s\n' 1 > "$SYS_NET/eth0/type"

write_state STATE_SCHEMA=2 MAP_SCHEMA=3 OBJECT_SHA256="$EXPECTED_HASH" \
    GEN="$GENERATION" IFACE=eth0:xdpgeneric
assert_cmd_failure "preceding ARP-admission map schema cannot report current status" \
    run_controller

write_state STATE_SCHEMA=2 MAP_SCHEMA=4 OBJECT_SHA256="$EXPECTED_HASH" GEN="$GENERATION"
assert_cmd_failure "empty interface state cannot report an active boundary" run_controller

write_state STATE_SCHEMA=2 MAP_SCHEMA=4 OBJECT_SHA256="$EXPECTED_HASH" \
    GEN="$GENERATION" IFACE=eth0:xdpgeneric IFACE=eth0:xdpgeneric
assert_cmd_failure "duplicate state interface is rejected" run_controller

write_state STATE_SCHEMA=2 MAP_SCHEMA=4 OBJECT_SHA256="$EXPECTED_HASH" \
    GEN="$GENERATION" IFACE=eth0:xdpgeneric UNKNOWN=value
assert_cmd_failure "unknown state key is rejected" run_controller

write_state STATE_SCHEMA=2 GEN="$GENERATION" IFACE=eth0:xdpgeneric
assert_cmd_failure "partially versioned state is rejected" run_controller

write_state STATE_SCHEMA=2 MAP_SCHEMA=4 OBJECT_SHA256="$EXPECTED_HASH" \
    GEN="$GENERATION" IFACE=eth0:badmode
assert_cmd_failure "unknown recorded XDP mode is rejected" run_controller

OUTSIDE="$TMPDIR/outside/generation_200_1"
mkdir -p "$OUTSIDE"
write_state STATE_SCHEMA=2 MAP_SCHEMA=4 OBJECT_SHA256="$EXPECTED_HASH" \
    GEN="$OUTSIDE" IFACE=eth0:xdpgeneric
assert_cmd_failure "cross-root generation path is rejected" run_controller

LINK_TARGET="$BPF_ROOT/generation_300_1"
ln -s "$GENERATION" "$LINK_TARGET"
write_state STATE_SCHEMA=2 MAP_SCHEMA=4 OBJECT_SHA256="$EXPECTED_HASH" \
    GEN="$LINK_TARGET" IFACE=eth0:xdpgeneric
assert_cmd_failure "symlink generation path is rejected" run_controller

INVALID_NAME="$BPF_ROOT/generation_bad-name"
mkdir -p "$INVALID_NAME/progs" "$INVALID_NAME/maps"
touch "$INVALID_NAME/progs/noid_lan_xdp" \
    "$INVALID_NAME/progs/noid_lan_egress"
write_state STATE_SCHEMA=2 MAP_SCHEMA=4 OBJECT_SHA256="$EXPECTED_HASH" \
    GEN="$INVALID_NAME" IFACE=eth0:xdpgeneric
assert_cmd_failure "unowned generation-name grammar is rejected" run_controller

valid_state
assert_cmd_failure "TC program ID mismatch is rejected" \
    run_controller_with_env MOCK_TC_ID=999
assert_cmd_failure "pinned TC program name mismatch is rejected" \
    run_controller_with_env MOCK_PINNED_TC_NAME=foreign_program
assert_cmd_failure "TC program on the wrong hook is rejected" \
    run_controller_with_env MOCK_TC_KIND=clsact/ingress
assert_cmd_failure "attachment on the wrong interface is rejected" \
    run_controller_with_env MOCK_NET_DEV=eth1
assert_cmd_failure "recorded generic XDP mode mismatch is rejected" \
    run_controller_with_env MOCK_XDP_MODE=driver
assert_cmd_failure "XDP numeric identity mismatch is rejected" \
    run_controller_with_env MOCK_XDP_ID=999
assert_cmd_failure "non-root state ownership is rejected" \
    run_controller_with_env MOCK_STATE_META=1000:600
assert_cmd_failure "group-readable state mode is rejected" \
    run_controller_with_env MOCK_STATE_META=0:640

# A current schema authorizes map reuse only when the exact key/value/capacity
# contract matches. A mismatch fails before program loading or link changes.
valid_state
cp "$STATE" "$TMPDIR/state.before"
: > "$MOCK_LOG"
assert_cmd_failure "map capacity drift aborts before state reuse" \
    env PATH="$MOCKBIN:/usr/bin:/bin" MOCK_LOG="$MOCK_LOG" \
        MOCK_STATE_FILE="$STATE" MOCK_FLOW_MAX=1 \
        NOID_LAN_XDP_OBJECT="$OBJECT" NOID_LAN_XDP_BPF_ROOT="$BPF_ROOT" \
        NOID_LAN_XDP_STATE_FILE="$STATE" NOID_SYS_CLASS_NET="$SYS_NET" \
        NOID_LAN_XDP_POLICY_DIGEST_FILE="$TMPDIR/policy-digest" \
        NOID_ARP_STATE_FILE="$TMPDIR/no-arp-state" \
        NOID_LAN_XDP_LOCK_HELD=1 /bin/bash "$CONTROLLER" \
        sync 0 --iface eth0
assert_cmd_success "map-schema rejection preserves authoritative state bytes" \
    cmp -s "$STATE" "$TMPDIR/state.before"
assert_not_grep 'bpftool prog loadall' "$MOCK_LOG" \
    "map-schema rejection occurs before loading or attaching a new generation"

# A peer-policy generation must use a fresh flow map rather than trying to
# scan/delete a map that is still writable by the attached old TC program.
# DHCP state and counters remain reusable. This fixture proves both the
# no-shared-flow-map boundary and rollback without requiring BPF privilege.
FLOW_BPF_ROOT="$TMPDIR/flow-bpf-root"
FLOW_GENERATION="$FLOW_BPF_ROOT/generation_400_1"
FLOW_STATE="$TMPDIR/flow-state"
mkdir -p "$FLOW_GENERATION/progs" "$FLOW_GENERATION/maps"
touch "$FLOW_GENERATION/progs/noid_lan_xdp" \
    "$FLOW_GENERATION/progs/noid_lan_egress"
printf '%s\n' \
    STATE_SCHEMA=2 MAP_SCHEMA=4 OBJECT_SHA256="$EXPECTED_HASH" \
    GEN="$FLOW_GENERATION" IFACE=eth0:xdpgeneric > "$FLOW_STATE"
chmod 0600 "$FLOW_STATE"
: > "$MOCK_LOG"
assert_cmd_success "peer flow invalidation commits one fresh-map generation" \
    env PATH="$MOCKBIN:/usr/bin:/bin" MOCK_LOG="$MOCK_LOG" \
        MOCK_STATE_FILE="$FLOW_STATE" \
        NOID_LAN_XDP_OBJECT="$OBJECT" NOID_LAN_XDP_BPF_ROOT="$FLOW_BPF_ROOT" \
        NOID_LAN_XDP_STATE_FILE="$FLOW_STATE" NOID_SYS_CLASS_NET="$SYS_NET" \
        NOID_ARP_STATE_FILE="$TMPDIR/no-arp-state" \
        NOID_LAN_XDP_LOCK_HELD=1 /bin/bash "$CONTROLLER" \
        sync 0 --iface eth0 --fresh-flow-map-for-peer 198.19.7.20
assert_not_grep \
    "map name noid_xdp_flows_v4 pinned $FLOW_GENERATION/maps/noid_xdp_flows_v4" \
    "$MOCK_LOG" \
    "peer transition never shares the old reply-correlation map"
assert_grep_fixed \
    "map name noid_xdp_dhcp_v4 pinned $FLOW_GENERATION/maps/noid_xdp_dhcp_v4" \
    "$MOCK_LOG" "peer transition retains unrelated live DHCP correlation"
assert_grep_fixed \
    "map name noid_xdp_stats pinned $FLOW_GENERATION/maps/noid_xdp_stats" \
    "$MOCK_LOG" "peer transition retains cumulative XDP counters"

FLOW_CURRENT_GENERATION=$(sed -n 's/^GEN=//p' "$FLOW_STATE")
FLOW_CURRENT_MODE=$(sed -n 's/^IFACE=eth0://p' "$FLOW_STATE")
cp "$FLOW_STATE" "$TMPDIR/state.before-flow-attach-failure"
: > "$MOCK_LOG"
flow_tc_fail_marker="$TMPDIR/flow-tc-failed-once"
assert_cmd_failure "fresh-flow generation attach failure rolls back" \
    env PATH="$MOCKBIN:/usr/bin:/bin" MOCK_LOG="$MOCK_LOG" \
        MOCK_TC_FAIL_IFACE=eth0 MOCK_TC_FAIL_MARKER="$flow_tc_fail_marker" \
        MOCK_STATE_FILE="$FLOW_STATE" \
        NOID_LAN_XDP_OBJECT="$OBJECT" NOID_LAN_XDP_BPF_ROOT="$FLOW_BPF_ROOT" \
        NOID_LAN_XDP_STATE_FILE="$FLOW_STATE" NOID_SYS_CLASS_NET="$SYS_NET" \
        NOID_ARP_STATE_FILE="$TMPDIR/no-arp-state" \
        NOID_LAN_XDP_LOCK_HELD=1 /bin/bash "$CONTROLLER" \
        sync 0 --iface eth0 --fresh-flow-map-for-peer 198.19.7.20
assert_cmd_success "failed fresh-flow attachment preserves committed state" \
    cmp -s "$FLOW_STATE" "$TMPDIR/state.before-flow-attach-failure"
assert_grep_fixed \
    "bpftool net attach $FLOW_CURRENT_MODE pinned $FLOW_CURRENT_GENERATION/progs/noid_lan_xdp dev eth0 overwrite" \
    "$MOCK_LOG" "fresh-flow failure restores the old attached generation"
assert_cmd_failure "non-canonical peer flow invalidation is rejected" \
    env PATH="$MOCKBIN:/usr/bin:/bin" MOCK_LOG="$MOCK_LOG" \
        MOCK_STATE_FILE="$FLOW_STATE" \
        NOID_LAN_XDP_OBJECT="$OBJECT" NOID_LAN_XDP_BPF_ROOT="$FLOW_BPF_ROOT" \
        NOID_LAN_XDP_STATE_FILE="$FLOW_STATE" NOID_SYS_CLASS_NET="$SYS_NET" \
        NOID_ARP_STATE_FILE="$TMPDIR/no-arp-state" \
        NOID_LAN_XDP_LOCK_HELD=1 /bin/bash "$CONTROLLER" \
        sync 0 --iface eth0 --fresh-flow-map-for-peer 198.019.7.20
assert_cmd_failure "duplicate peer flow invalidation is rejected" \
    env PATH="$MOCKBIN:/usr/bin:/bin" MOCK_LOG="$MOCK_LOG" \
        MOCK_STATE_FILE="$FLOW_STATE" \
        NOID_LAN_XDP_OBJECT="$OBJECT" NOID_LAN_XDP_BPF_ROOT="$FLOW_BPF_ROOT" \
        NOID_LAN_XDP_STATE_FILE="$FLOW_STATE" NOID_SYS_CLASS_NET="$SYS_NET" \
        NOID_ARP_STATE_FILE="$TMPDIR/no-arp-state" \
        NOID_LAN_XDP_LOCK_HELD=1 /bin/bash "$CONTROLLER" \
        sync 0 --iface eth0 --fresh-flow-map-for-peer 198.19.7.20 \
        --fresh-flow-map-for-peer 198.19.7.21

# A legacy state is path-validated but cannot claim current-object status. It
# remains usable only as the old rollback/detach source during one sync.
write_state GEN="$GENERATION" IFACE=eth0:xdpgeneric IFACE=eth1:xdpgeneric
assert_cmd_failure "legacy state cannot report current active status" run_controller

# Force the second desired interface's two attach modes to fail. The first
# interface must be restored from the validated old generation, while the
# authoritative old state remains byte-identical and the pending generation is
# removed.
cp "$STATE" "$TMPDIR/state.before"
: > "$MOCK_LOG"
generation_count_before=$(find "$BPF_ROOT" -mindepth 1 -maxdepth 1 \
    -type d -name 'generation_*' | wc -l)
assert_cmd_failure "second-interface attach failure rolls back the first" \
    env PATH="$MOCKBIN:/usr/bin:/bin" MOCK_LOG="$MOCK_LOG" MOCK_FAIL_IFACE=eth1 \
        MOCK_STATE_FILE="$STATE" \
        NOID_LAN_XDP_OBJECT="$OBJECT" NOID_LAN_XDP_BPF_ROOT="$BPF_ROOT" \
        NOID_LAN_XDP_STATE_FILE="$STATE" NOID_SYS_CLASS_NET="$SYS_NET" \
        NOID_LAN_XDP_POLICY_DIGEST_FILE="$TMPDIR/policy-digest" \
        NOID_ARP_STATE_FILE="$TMPDIR/no-arp-state" \
        NOID_LAN_XDP_LOCK_HELD=1 /bin/bash "$CONTROLLER" \
        sync 0 --iface eth0 --iface eth1
assert_cmd_success "failed multi-interface transaction preserves old state bytes" \
    cmp -s "$STATE" "$TMPDIR/state.before"
assert_grep_fixed "bpftool net attach xdpgeneric pinned $GENERATION/progs/noid_lan_xdp dev eth0 overwrite" \
    "$MOCK_LOG" "rollback restores the old generation in its recorded generic mode"
new_generation_count=$(find "$BPF_ROOT" -mindepth 1 -maxdepth 1 -type d -name 'generation_*' | wc -l)
assert_eq "$generation_count_before" "$new_generation_count" \
    "failed transaction removes only its pending generation"

# A later TC failure is different from an XDP attach refusal: XDP overwrite has
# already replaced the old ingress program on that interface. The controller
# must include that partially attached interface in rollback and must not first
# create an unprotected detach window.
cp "$STATE" "$TMPDIR/state.before"
: > "$MOCK_LOG"
tc_fail_marker="$TMPDIR/tc-failed-once"
assert_cmd_failure "TC failure restores the overwritten interface too" \
    env PATH="$MOCKBIN:/usr/bin:/bin" MOCK_LOG="$MOCK_LOG" \
        MOCK_TC_FAIL_IFACE=eth1 MOCK_TC_FAIL_MARKER="$tc_fail_marker" \
        MOCK_STATE_FILE="$STATE" \
        NOID_LAN_XDP_OBJECT="$OBJECT" NOID_LAN_XDP_BPF_ROOT="$BPF_ROOT" \
        NOID_LAN_XDP_STATE_FILE="$STATE" NOID_SYS_CLASS_NET="$SYS_NET" \
        NOID_LAN_XDP_POLICY_DIGEST_FILE="$TMPDIR/policy-digest" \
        NOID_ARP_STATE_FILE="$TMPDIR/no-arp-state" \
        NOID_LAN_XDP_LOCK_HELD=1 /bin/bash "$CONTROLLER" \
        sync 0 --iface eth0 --iface eth1
assert_cmd_success "TC-failed transaction preserves old state bytes" \
    cmp -s "$STATE" "$TMPDIR/state.before"
assert_grep_fixed \
    "bpftool net attach xdpgeneric pinned $GENERATION/progs/noid_lan_xdp dev eth1 overwrite" \
    "$MOCK_LOG" \
    "rollback restores old XDP on the interface whose new TC attach failed"
assert_grep_fixed \
    "tc filter replace dev eth1 egress pref 10 handle 1 bpf direct-action pinned $GENERATION/progs/noid_lan_egress" \
    "$MOCK_LOG" \
    "rollback restores old TC on the interface whose new TC attach failed"
assert_not_grep 'bpftool net detach xdpgeneric dev eth1' "$MOCK_LOG" \
    "TC failure never opens an XDP-detached window before rollback"

# M04's identity is a closed, root-metadata-bound input. ENABLED=0 means only
# that the kernel neighbour pin is opted out; the fail-closed XDP gateway
# return identity must remain seeded on the recorded physical interface.
GATEWAY_BPF_ROOT="$TMPDIR/gateway-bpf-root"
GATEWAY_STATE="$TMPDIR/gateway-xdp.state"
mkdir -p "$GATEWAY_BPF_ROOT"
cat > "$ARP_STATE" <<'ARP_STATE_EOF'
ENABLED=0
WAN_IFACE=eth0
GATEWAY_IP=192.0.2.1
GATEWAY_MAC=02:00:00:00:00:03
LEARNED_AT=2026-07-27T00:00:00Z
ARP_STATE_EOF
chmod 0644 "$ARP_STATE"
: > "$MOCK_LOG"
assert_cmd_success "disabled kernel pin retains the validated XDP gateway identity" \
    env PATH="$MOCKBIN:/usr/bin:/bin" MOCK_LOG="$MOCK_LOG" \
        MOCK_STATE_FILE="$GATEWAY_STATE" \
        NOID_LAN_XDP_OBJECT="$OBJECT" NOID_LAN_XDP_BPF_ROOT="$GATEWAY_BPF_ROOT" \
        NOID_LAN_XDP_STATE_FILE="$GATEWAY_STATE" NOID_SYS_CLASS_NET="$SYS_NET" \
        NOID_ARP_STATE_FILE="$ARP_STATE" NOID_LAN_XDP_LOCK_HELD=1 \
        /bin/bash "$CONTROLLER" sync 0 --iface eth0
assert_grep_extended \
    'noid_xdp_gateway_macs key hex 0b 00 00 00 02 00 00 00 00 03 00 00 value hex 01$' \
    "$MOCK_LOG" "ENABLED=0 still seeds the exact per-ifindex gateway MAC"

printf 'UNKNOWN=value\n' >> "$ARP_STATE"
: > "$MOCK_LOG"
assert_cmd_failure "present malformed gateway identity fails closed" \
    env PATH="$MOCKBIN:/usr/bin:/bin" MOCK_LOG="$MOCK_LOG" \
        MOCK_STATE_FILE="$GATEWAY_STATE" \
        NOID_LAN_XDP_OBJECT="$OBJECT" NOID_LAN_XDP_BPF_ROOT="$GATEWAY_BPF_ROOT" \
        NOID_LAN_XDP_STATE_FILE="$GATEWAY_STATE" NOID_SYS_CLASS_NET="$SYS_NET" \
        NOID_ARP_STATE_FILE="$ARP_STATE" NOID_LAN_XDP_LOCK_HELD=1 \
        /bin/bash "$CONTROLLER" sync 0 --iface eth0
assert_not_grep 'bpftool prog loadall' "$MOCK_LOG" \
    "malformed gateway identity is rejected before BPF generation mutation"
sed -i '/^UNKNOWN=/d' "$ARP_STATE"
chmod 0600 "$ARP_STATE"
assert_cmd_failure "wrong gateway identity mode fails closed" \
    env PATH="$MOCKBIN:/usr/bin:/bin" MOCK_LOG="$MOCK_LOG" \
        MOCK_STATE_FILE="$GATEWAY_STATE" \
        NOID_LAN_XDP_OBJECT="$OBJECT" NOID_LAN_XDP_BPF_ROOT="$GATEWAY_BPF_ROOT" \
        NOID_LAN_XDP_STATE_FILE="$GATEWAY_STATE" NOID_SYS_CLASS_NET="$SYS_NET" \
        NOID_ARP_STATE_FILE="$ARP_STATE" NOID_LAN_XDP_LOCK_HELD=1 \
        /bin/bash "$CONTROLLER" sync 0 --iface eth0
chmod 0644 "$ARP_STATE"
chmod 0777 "$ARP_STATE_DIR"
assert_cmd_failure "writable gateway identity parent fails closed" \
    env PATH="$MOCKBIN:/usr/bin:/bin" MOCK_LOG="$MOCK_LOG" \
        MOCK_STATE_FILE="$GATEWAY_STATE" \
        NOID_LAN_XDP_OBJECT="$OBJECT" NOID_LAN_XDP_BPF_ROOT="$GATEWAY_BPF_ROOT" \
        NOID_LAN_XDP_STATE_FILE="$GATEWAY_STATE" NOID_SYS_CLASS_NET="$SYS_NET" \
        NOID_ARP_STATE_FILE="$ARP_STATE" NOID_LAN_XDP_LOCK_HELD=1 \
        /bin/bash "$CONTROLLER" sync 0 --iface eth0
chmod 0755 "$ARP_STATE_DIR"

# A successful generation receives one closed eight-byte value per exact peer.
# Values are host-endian u16 port bounds, matching the BPF map ABI.
SYNC_BPF_ROOT="$TMPDIR/sync-bpf-root"
SYNC_STATE="$TMPDIR/sync-state"
mkdir -p "$SYNC_BPF_ROOT"
mkdir -p "$SYNC_BPF_ROOT/generation_AAAAAAAA"
printf '%s\n' sentinel > "$SYNC_BPF_ROOT/generation_AAAAAAAA/owner"
: > "$MOCK_LOG"
assert_cmd_success "three direction policies publish one XDP generation" \
    env PATH="$MOCKBIN:/usr/bin:/bin" MOCK_LOG="$MOCK_LOG" \
        MOCK_STATE_FILE="$SYNC_STATE" \
        NOID_LAN_XDP_OBJECT="$OBJECT" NOID_LAN_XDP_BPF_ROOT="$SYNC_BPF_ROOT" \
        NOID_LAN_XDP_STATE_FILE="$SYNC_STATE" NOID_SYS_CLASS_NET="$SYS_NET" \
        NOID_ARP_STATE_FILE="$TMPDIR/no-arp-state" \
        NOID_LAN_XDP_LOCK_HELD=1 /bin/bash "$CONTROLLER" sync 0 \
        --iface eth0 \
        --peer eth0,198.19.7.20,02:00:00:00:00:01,outbound,none,0,0 \
        --peer eth0,198.19.7.21,02:00:00:00:00:02,inbound,tcp,443,443 \
        --peer eth0,198.19.7.22,02:00:00:00:00:03,both,udp,5300,5301
assert_grep_extended \
    'noid_xdp_peer4 key hex 0b 00 00 00 c6 13 07 14 02 00 00 00 00 01 00 00 value hex 01 00 00 00 00 00 00 00$' \
    "$MOCK_LOG" "outbound-only map value has direction bit 1 and no selector"
assert_grep_extended \
    'noid_xdp_peer4 key hex 0b 00 00 00 c6 13 07 15 02 00 00 00 00 02 00 00 value hex 02 06 bb 01 bb 01 00 00$' \
    "$MOCK_LOG" "inbound TCP map value has direction bit 2 and exact port 443"
assert_grep_extended \
    'noid_xdp_peer4 key hex 0b 00 00 00 c6 13 07 16 02 00 00 00 00 03 00 00 value hex 03 11 b4 14 b5 14 00 00$' \
    "$MOCK_LOG" "both UDP map value has direction bits 3 and exact 5300-5301 range"
assert_grep_fixed 'MAP_SCHEMA=4' "$SYNC_STATE" \
    "committed peer-policy generation records map schema 4"
sync_generation=$(awk -F= '$1=="GEN" {print $2}' "$SYNC_STATE")
assert_grep_extended '/generation_[A-Za-z0-9]{8}$' "$SYNC_STATE" \
    "new state records the atomically reserved generation grammar"
if [ "$sync_generation" != "$SYNC_BPF_ROOT/generation_AAAAAAAA" ] \
        && [ "$(cat "$SYNC_BPF_ROOT/generation_AAAAAAAA/owner")" = sentinel ]; then
    _pass "fresh generation allocation preserves a pre-existing valid-name directory"
else
    _fail "fresh generation allocation preserves a pre-existing valid-name directory"
fi

cp "$SYNC_STATE" "$TMPDIR/sync-state.before"
invalid_peer() {
    env PATH="$MOCKBIN:/usr/bin:/bin" MOCK_LOG="$MOCK_LOG" \
        MOCK_STATE_FILE="$SYNC_STATE" \
        NOID_LAN_XDP_OBJECT="$OBJECT" NOID_LAN_XDP_BPF_ROOT="$SYNC_BPF_ROOT" \
        NOID_LAN_XDP_STATE_FILE="$SYNC_STATE" NOID_SYS_CLASS_NET="$SYS_NET" \
        NOID_ARP_STATE_FILE="$TMPDIR/no-arp-state" \
        NOID_LAN_XDP_LOCK_HELD=1 /bin/bash "$CONTROLLER" sync 0 \
        --iface eth0 "$@"
}
assert_cmd_failure "old three-field peer grammar is rejected" \
    invalid_peer --peer eth0,198.19.7.20,02:00:00:00:00:01
assert_cmd_failure "outbound peer cannot carry an inbound protocol" \
    invalid_peer --peer eth0,198.19.7.20,02:00:00:00:00:01,outbound,tcp,0,0
assert_cmd_failure "inbound peer cannot omit a transport selector" \
    invalid_peer --peer eth0,198.19.7.20,02:00:00:00:00:01,inbound,none,0,0
assert_cmd_failure "inbound port zero is rejected" \
    invalid_peer --peer eth0,198.19.7.20,02:00:00:00:00:01,inbound,tcp,0,443
assert_cmd_failure "reversed inbound port range is rejected" \
    invalid_peer --peer eth0,198.19.7.20,02:00:00:00:00:01,inbound,udp,5301,5300
assert_cmd_failure "inbound port above 65535 is rejected" \
    invalid_peer --peer eth0,198.19.7.20,02:00:00:00:00:01,inbound,tcp,443,65536
assert_cmd_failure "duplicate IPv4 policy with another MAC is rejected" \
    invalid_peer \
        --peer eth0,198.19.7.20,02:00:00:00:00:01,outbound,none,0,0 \
        --peer eth0,198.19.7.20,02:00:00:00:00:10,inbound,tcp,443,443
assert_cmd_success "all rejected peer grammars preserve committed state bytes" \
    cmp -s "$SYNC_STATE" "$TMPDIR/sync-state.before"

test_finish
