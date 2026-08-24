#!/bin/bash
# Fast-path contract for the LAN-XDP controller.
#
# A queued NetworkManager/udev burst re-runs the whole topology transaction once
# per event. Rebuilding an identical BPF generation each time starved unrelated
# NetworkManager profile activations behind the serialized, activation-blocking
# pre-up dispatcher chain. The controller therefore skips the rebuild when the
# complete enforced input set is byte-identical AND the live attachment still
# binds the pinned program identities.
#
# Every check below exists because skipping wrongly would leave stale
# enforcement. Each mutation is asserted twice: it must force a full rebuild,
# and the fast path must converge again afterwards.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

ROOT=$(find_project_root)
CONTROLLER_SOURCE="$ROOT/overrides/noid-lan-xdp/noid-lan-xdp.sh"
PAYLOAD="$ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.o.b64"
EXPECTED_HASH=9f244286de91021ed53fab3f1bf03cdfc248aa9e0090061a91beafe39f96849a
# /tmp is noexec on this image; executable fixture doubles live below /var/tmp.
TMPDIR=$(mktemp -d /var/tmp/noid-test-03c.XXXXXX)
cleanup() { find "$TMPDIR" -depth -delete; }
trap cleanup EXIT
MOCKBIN="$TMPDIR/bin"
BPF_ROOT="$TMPDIR/bpf-root"
STATE="$TMPDIR/state"
DIGEST="$TMPDIR/policy-digest"
SYS_NET="$TMPDIR/sys-class-net"
OBJECT="$TMPDIR/object.o"
MOCK_LOG="$TMPDIR/mock.log"
CONTROLLER="$TMPDIR/noid-lan-xdp.sh"

test_start "03d-lan-xdp-policy-digest"
fixture_uid=$(id -u)
fixture_gid=$(id -g)
# The digest sidecar is root-private in production. Rebind that identity to the
# fixture user, exactly as the sibling state test rebinds the ARP-state owner.
sed \
    -e "s/^EXPECTED_DIGEST_UID=0$/EXPECTED_DIGEST_UID=$fixture_uid/" \
    -e "s/^EXPECTED_DIGEST_GID=0$/EXPECTED_DIGEST_GID=$fixture_gid/" \
    "$CONTROLLER_SOURCE" > "$CONTROLLER"
chmod 0755 "$CONTROLLER"
assert_grep_fixed "EXPECTED_DIGEST_UID=$fixture_uid" "$CONTROLLER" \
    "fixture rebinds the digest owner contract"

mkdir -p "$MOCKBIN" "$BPF_ROOT" "$SYS_NET/eth0/device" "$SYS_NET/eth1/device"
printf '%s\n' 11 > "$SYS_NET/eth0/ifindex"
printf '%s\n' 12 > "$SYS_NET/eth1/ifindex"
printf '%s\n' 1 > "$SYS_NET/eth0/type"
printf '%s\n' 1 > "$SYS_NET/eth1/type"
printf '%s\n' 02:00:00:00:00:10 > "$SYS_NET/eth0/address"
printf '%s\n' 02:00:00:00:00:11 > "$SYS_NET/eth1/address"
base64 -d "$PAYLOAD" > "$OBJECT"
assert_eq "$EXPECTED_HASH" "$(sha256sum "$OBJECT" | awk '{print $1}')" \
    "fast-path fixtures use the exact pinned BPF object"

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
    printf '%s\n' 0:600
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
MOCK
# Reports the real per-device ifindex so a multi-interface attachment can be
# verified honestly instead of pinning one hard-coded index.
cat > "$MOCKBIN/bpftool" <<'MOCK'
#!/bin/bash
printf 'bpftool %s\n' "$*" >> "$MOCK_LOG"
if [ "${1:-}" = -j ] && [ "${2:-}" = net ]; then
    iface=${5:-eth0}
    ifindex=$(cat "$MOCK_SYS_NET/$iface/ifindex")
    printf '[{"xdp":[{"devname":"%s","ifindex":%s,"mode":"%s","id":%s}],' \
        "$iface" "$ifindex" "${MOCK_XDP_MODE:-driver}" \
        "${MOCK_LIVE_XDP_ID:-${MOCK_XDP_ID:-101}}"
    printf '"tc":[{"devname":"%s","ifindex":%s,"kind":"clsact/egress","id":%s}],' \
        "$iface" "$ifindex" "${MOCK_LIVE_TC_ID:-${MOCK_TC_ID:-202}}"
    printf '"flow_dissector":[],"netfilter":[]}]\n'
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
    # controller, not by the mock. MOCK_XDP_ID/MOCK_TC_ID stay the pinned
    # identities here while MOCK_LIVE_* drive the attachment above, so a test
    # can still separate the two.
    pin=${5:?mock: no pin path}
    if [ ! -e "$pin" ]; then
        printf '{"error":"bpf obj get (%s): No such file or directory"}\n' "$pin"
        exit 255
    fi
    case "$pin" in
        */progs/noid_lan_xdp)
            printf '{"id":%s,"type":"xdp","name":"noid_lan_xdp","tag":"1111111111111111"}\n' \
                "${MOCK_XDP_ID:-101}" ;;
        */progs/noid_lan_egress)
            printf '{"id":%s,"type":"sched_cls","name":"%s","tag":"2222222222222222"}\n' \
                "${MOCK_TC_ID:-202}" "${MOCK_PINNED_TC_NAME:-noid_lan_egress}" ;;
        *) exit 1 ;;
    esac
    exit 0
fi
if [ "${1:-}" = -j ] && [ "${2:-}" = map ]; then
    case "${*: -1}" in
        */noid_xdp_flows_v4)
            printf '{"type":"lru_hash","flags":0,"bytes_key":20,"bytes_value":8,"max_entries":65536}\n' ;;
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
    for map in noid_xdp_flows_v4 noid_xdp_dhcp_v4 noid_xdp_stats \
               noid_xdp_local_macs noid_xdp_gateway_macs noid_xdp_peer4 \
               noid_xdp_global_allow; do
        touch "$mapdir/$map"
    done
    exit 0
fi
exit 0
MOCK
chmod 0755 "$MOCKBIN"/*

EXTRA_ENV=()
sync_run() {
    : > "$MOCK_LOG"
    env PATH="$MOCKBIN:/usr/bin:/bin" MOCK_LOG="$MOCK_LOG" \
        MOCK_STATE_FILE="$STATE" MOCK_SYS_NET="$SYS_NET" \
        NOID_LAN_XDP_OBJECT="$OBJECT" NOID_LAN_XDP_BPF_ROOT="$BPF_ROOT" \
        NOID_LAN_XDP_STATE_FILE="$STATE" NOID_SYS_CLASS_NET="$SYS_NET" \
        NOID_LAN_XDP_POLICY_DIGEST_FILE="$DIGEST" \
        NOID_ARP_STATE_FILE="$TMPDIR/no-arp-state" \
        NOID_LAN_XDP_LOCK_HELD=1 "${EXTRA_ENV[@]}" \
        /bin/bash "$CONTROLLER" sync "$@"
}

generations() { find "$BPF_ROOT" -maxdepth 1 -name 'generation_*' | wc -l; }

# Runs one sync and asserts whether a new BPF generation was built.
expect_rebuild() {
    local label=$1; shift
    if sync_run "$@"; then
        assert_grep 'bpftool prog loadall' "$MOCK_LOG" "$label"
    else
        _fail "$label"
        printf '    diagnostic: sync exited non-zero\n'
    fi
}
expect_fastpath() {
    local label=$1; shift
    if sync_run "$@"; then
        assert_not_grep 'bpftool prog loadall' "$MOCK_LOG" "$label"
    else
        _fail "$label"
        printf '    diagnostic: sync exited non-zero\n'
    fi
}

# --- baseline -------------------------------------------------------------
expect_rebuild "first sync builds a generation" 0 --iface eth0
assert_file_exists "$DIGEST" "committed sync publishes the digest sidecar"
assert_grep_fixed "GEN=$(awk -F= '/^GEN=/{print $2}' "$STATE")" "$DIGEST" \
    "sidecar names exactly the committed generation"
baseline_generations=$(generations)

expect_fastpath "identical rerun skips the rebuild" 0 --iface eth0
assert_eq "$baseline_generations" "$(generations)" \
    "skipped rerun creates no additional BPF generation"

# --- each enforced input must defeat the fast path -------------------------
expect_rebuild "global LAN allow change rebuilds" 1 --iface eth0
expect_fastpath "fast path reconverges after allow change" 1 --iface eth0
expect_rebuild "global LAN allow revert rebuilds" 0 --iface eth0
expect_fastpath "fast path reconverges after allow revert" 0 --iface eth0

PEER='eth0,192.0.2.10,02:00:00:00:00:22,outbound,none,0,0'
expect_rebuild "added peer policy rebuilds" 0 --iface eth0 --peer "$PEER"
expect_fastpath "fast path reconverges with the peer" 0 --iface eth0 --peer "$PEER"
expect_rebuild "removed peer policy rebuilds" 0 --iface eth0
expect_fastpath "fast path reconverges without the peer" 0 --iface eth0

# The local MAC is map material and NoID Privacy enables MAC randomization, so a
# reconnect can change it while nothing else does.
printf '%s\n' 02:00:00:00:00:33 > "$SYS_NET/eth0/address"
expect_rebuild "changed local MAC rebuilds" 0 --iface eth0
expect_fastpath "fast path reconverges after the MAC change" 0 --iface eth0

# Map keys are built from the ifindex; a re-created netdev may reuse the name.
printf '%s\n' 21 > "$SYS_NET/eth0/ifindex"
expect_rebuild "changed ifindex rebuilds" 0 --iface eth0
expect_fastpath "fast path reconverges after the ifindex change" 0 --iface eth0

expect_rebuild "added physical interface rebuilds" 0 --iface eth0 --iface eth1
expect_fastpath "fast path reconverges with both interfaces" 0 --iface eth0 --iface eth1
expect_rebuild "removed physical interface rebuilds" 0 --iface eth0
expect_fastpath "fast path reconverges after removal" 0 --iface eth0

# --- sidecar integrity ----------------------------------------------------
rm -f "$DIGEST"
expect_rebuild "missing sidecar rebuilds" 0 --iface eth0
expect_fastpath "fast path reconverges after republication" 0 --iface eth0

sed -i 's/^DIGEST=.*/DIGEST=0000000000000000000000000000000000000000000000000000000000000000/' \
    "$DIGEST"
expect_rebuild "tampered sidecar digest rebuilds" 0 --iface eth0
expect_fastpath "fast path reconverges after the tamper" 0 --iface eth0

sed -i "s|^GEN=.*|GEN=$BPF_ROOT/generation_deadbeef|" "$DIGEST"
expect_rebuild "sidecar naming a foreign generation rebuilds" 0 --iface eth0
expect_fastpath "fast path reconverges after the foreign generation" 0 --iface eth0

printf 'DIGEST=%s\n' "$(awk -F= '/^DIGEST=/{print $2}' "$DIGEST")" > "$DIGEST"
chmod 0600 "$DIGEST"
expect_rebuild "sidecar without a generation row rebuilds" 0 --iface eth0
expect_fastpath "fast path reconverges after the truncated sidecar" 0 --iface eth0

chmod 0644 "$DIGEST"
expect_rebuild "world-readable sidecar rebuilds" 0 --iface eth0
expect_fastpath "fast path reconverges after the mode repair" 0 --iface eth0

# --- explicit flow reset and self-healing ---------------------------------
expect_rebuild "explicit peer flow reset always rebuilds" \
    0 --iface eth0 --peer "$PEER" --fresh-flow-map-for-peer 192.0.2.10
expect_rebuild "flow reset never leaves a fast path behind" \
    0 --iface eth0 --peer "$PEER" --fresh-flow-map-for-peer 192.0.2.10
expect_rebuild "return to the plain policy rebuilds" 0 --iface eth0
expect_fastpath "fast path reconverges after the flow reset" 0 --iface eth0

# A detached or replaced live program must never be skipped: this is the
# self-healing property the unconditional rebuild used to provide for free.
# The pinned program keeps its identity while the live attachment reports a
# different one, i.e. something replaced or re-attached the program underneath.
EXTRA_ENV=(MOCK_LIVE_XDP_ID=999)
expect_rebuild "live XDP attachment drift rebuilds" 0 --iface eth0
EXTRA_ENV=()
expect_fastpath "fast path reconverges after the XDP drift" 0 --iface eth0

EXTRA_ENV=(MOCK_LIVE_TC_ID=888)
expect_rebuild "live TC attachment drift rebuilds" 0 --iface eth0
EXTRA_ENV=()
expect_fastpath "fast path reconverges after the TC drift" 0 --iface eth0

# --- the skipped path must not disturb committed state --------------------
cp "$STATE" "$TMPDIR/state.before"
cp "$DIGEST" "$TMPDIR/digest.before"
expect_fastpath "final identical rerun still skips" 0 --iface eth0
assert_cmd_success "skipped sync leaves the authoritative state byte-identical" \
    cmp -s "$STATE" "$TMPDIR/state.before"
assert_cmd_success "skipped sync leaves the sidecar byte-identical" \
    cmp -s "$DIGEST" "$TMPDIR/digest.before"

test_finish
