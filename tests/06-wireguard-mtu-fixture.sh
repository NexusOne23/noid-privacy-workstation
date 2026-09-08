#!/bin/bash
# 06-wireguard-mtu-fixture -- live-only WireGuard MTU reconciliation semantics
set -euo pipefail
. "$(dirname "$0")/lib.sh"

ROOT="$(find_project_root)"
SOURCE="$ROOT/scripts/noid-wireguard-mtu-reconcile.sh"
TMP="$(mktemp -d /var/tmp/noid-wg-mtu-test.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
BIN="$TMP/bin"
STATE="$TMP/state"
SYS="$TMP/sys/class/net"
HELPER="$TMP/noid-wireguard-mtu-reconcile"
CALLS="$TMP/ip.calls"
ROUTE_CALLS="$TMP/route.calls"
LOGGER_CALLS="$TMP/logger.calls"
LOCK="$TMP/noid-wireguard-mtu.lock"

test_start "06-wireguard-mtu-fixture"
assert_file_exists "$SOURCE"
mkdir -p "$BIN" "$STATE" "$SYS"
cp "$SOURCE" "$HELPER"
chmod 0700 "$HELPER"

cat > "$BIN/wg" <<'WG_EOF'
#!/bin/bash
set -eu
state=${NOID_FIXTURE_STATE:?}
case "$*" in
    'show interfaces')
        if [ -e "$state/interfaces.once" ]; then
            rm "$state/interfaces.once"
            cat "$state/interfaces"
        else
            cat "$state/interfaces"
            exit "$(cat "$state/interfaces.rc")"
        fi
        ;;
    show\ *\ endpoints)
        iface=$2
        cat "$state/$iface.endpoints"
        ;;
    show\ *\ fwmark)
        iface=$2
        cat "$state/$iface.fwmark"
        exit "$(cat "$state/fwmark.rc")"
        ;;
    show\ *\ allowed-ips)
        iface=$2
        cat "$state/$iface.allowed"
        ;;
    *) exit 64 ;;
esac
WG_EOF

cat > "$BIN/ip" <<'IP_EOF'
#!/bin/bash
set -eu
state=${NOID_FIXTURE_STATE:?}
sys=${NOID_FIXTURE_SYS:?}
calls=${NOID_FIXTURE_CALLS:?}
case "${1:-}" in
    route)
        [ "${2:-}" = get ] || exit 64
        printf '%s\n' "$*" >> "${NOID_FIXTURE_ROUTE_CALLS:?}"
        case "${3:-}" in
            203.0.113.1) printf '%s\n' '203.0.113.1 via 192.0.2.1 dev outer0 src 192.0.2.2' ;;
            203.0.113.2) printf '%s\n' '203.0.113.2 via 192.0.2.1 dev outer1 src 192.0.2.2' ;;
            203.0.113.3) printf '%s\n' '203.0.113.3 via 192.0.2.1 dev outer0 src 192.0.2.2 mtu 1400' ;;
            203.0.113.254) exit 1 ;;
            2001:db8::1) printf '%s\n' '2001:db8::1 via fe80::1 dev outer0 src 2001:db8::2' ;;
            *) exit 1 ;;
        esac
        ;;
    -6)
        [ "${2:-}" = addr ] && [ "${3:-}" = show ] \
            && [ "${4:-}" = dev ] || exit 64
        cat "$state/${5}.ipv6"
        ;;
    link)
        [ "${2:-}" = set ] && [ "${3:-}" = dev ] \
            && [ "${5:-}" = mtu ] || exit 64
        printf '%s\n' "$*" >> "$calls"
        printf '%s\n' "$6" > "$sys/$4/mtu"
        ;;
    *) exit 64 ;;
esac
IP_EOF

cat > "$BIN/flock" <<'FLOCK_EOF'
#!/bin/bash
exit 0
FLOCK_EOF

cat > "$BIN/logger" <<'LOGGER_EOF'
#!/bin/bash
printf '%s\n' "$*" >> "${NOID_FIXTURE_LOGGER_CALLS:?}"
LOGGER_EOF
chmod 0700 "$BIN/wg" "$BIN/ip" "$BIN/flock" "$BIN/logger"

fixture_uid=$(id -u)
fixture_gid=$(id -g)
sed -i \
    -e "s|^IP=.*|IP=$BIN/ip|" \
    -e "s|^WG=.*|WG=$BIN/wg|" \
    -e "s|^FLOCK=.*|FLOCK=$BIN/flock|" \
    -e "s|^LOGGER=.*|LOGGER=$BIN/logger|" \
    -e "s|^LOCK=.*|LOCK=$LOCK|" \
    -e "s|^SYS_CLASS_NET=.*|SYS_CLASS_NET=$SYS|" \
    -e 's/^\[ "$EUID" -eq 0 \] || {$/[ "$EUID" -eq "$EUID" ] || {/' \
    -e "s/'0:0:600:1'/'$fixture_uid:$fixture_gid:600:1'/" \
    "$HELPER"
assert_cmd_success "fixture helper syntax" bash -n "$HELPER"
assert_grep_fixed '[ "$EUID" -eq 0 ]' "$SOURCE" \
    "production helper remains root-only"
assert_grep_fixed 'set -f' "$SOURCE" \
    "production helper disables pathname expansion before interface enumeration"
assert_not_grep_extended 'nmcli|connection (modify|up|down)' "$SOURCE" \
    "production helper has no profile-mutation surface"

reset_fixture() {
    local current=${1:-1420} outer0=${2:-1456} outer1=${3:-1500}
    rm -rf "$SYS"
    mkdir -p "$SYS/wg0" "$SYS/outer0" "$SYS/outer1"
    printf '%s\n' "$current" > "$SYS/wg0/mtu"
    printf '%s\n' "$outer0" > "$SYS/outer0/mtu"
    printf '%s\n' "$outer1" > "$SYS/outer1/mtu"
    printf '%s\n' wg0 > "$STATE/interfaces"
    printf '%s\n' 'fixture-key 203.0.113.1:51820' > "$STATE/wg0.endpoints"
    printf '%s\n' 0x1234 > "$STATE/wg0.fwmark"
    printf '%s\n' 'fixture-key 0.0.0.0/0' > "$STATE/wg0.allowed"
    : > "$STATE/wg0.ipv6"
    printf '0\n' > "$STATE/interfaces.rc"
    printf '0\n' > "$STATE/fwmark.rc"
    rm -f "$STATE/interfaces.once"
    : > "$CALLS"
    : > "$ROUTE_CALLS"
    : > "$LOGGER_CALLS"
    : > "$LOCK"
    chmod 0600 "$LOCK"
}

run_helper() {
    env NOID_FIXTURE_STATE="$STATE" NOID_FIXTURE_SYS="$SYS" \
        NOID_FIXTURE_CALLS="$CALLS" NOID_FIXTURE_ROUTE_CALLS="$ROUTE_CALLS" \
        NOID_FIXTURE_LOGGER_CALLS="$LOGGER_CALLS" \
        "$HELPER" "$@"
}

run_helper_from() {
    local workdir=$1
    shift
    (cd "$workdir" && run_helper "$@")
}

reset_fixture 1420 1456
assert_cmd_success "1456-byte outer link lowers an unsafe tunnel" \
    run_helper wg0
assert_eq 1392 "$(<"$SYS/wg0/mtu")" \
    "IPv4 overhead and 16-byte WireGuard padding produce 1392"
assert_grep_fixed 'link set dev wg0 mtu 1392' "$CALLS" \
    "only the live kernel interface receives the computed correction"

reset_fixture 1300 1456
assert_cmd_success "already safer live MTU is accepted" run_helper wg0
assert_eq 1300 "$(<"$SYS/wg0/mtu")" \
    "reconciliation never raises a deliberately smaller MTU"
assert_eq '' "$(<"$CALLS")" "safe live MTU causes no link mutation"

reset_fixture 1420 1456
printf '%s\n' \
    'fixture-key-a 203.0.113.2:51820' \
    'fixture-key-b 203.0.113.1:51820' > "$STATE/wg0.endpoints"
assert_cmd_success "multiple peers use the strictest evaluated route" \
    run_helper wg0
assert_eq 1392 "$(<"$SYS/wg0/mtu")" \
    "larger second route cannot hide the 1456-byte outer ceiling"

reset_fixture 1420 1500
printf '%s\n' 'fixture-key 203.0.113.3:51820' > "$STATE/wg0.endpoints"
assert_cmd_success "route-scoped MTU overrides a larger link MTU" \
    run_helper wg0
assert_eq 1328 "$(<"$SYS/wg0/mtu")" \
    "route MTU 1400 is reduced by overhead and WireGuard padding"

reset_fixture 1420 1456
printf '%s\n' 'fixture-key [2001:db8::1]:51820' > "$STATE/wg0.endpoints"
assert_cmd_success "IPv6 outer endpoint uses its larger header" run_helper wg0
assert_eq 1376 "$(<"$SYS/wg0/mtu")" \
    "IPv6 outer overhead produces the stricter 1376-byte ceiling"

reset_fixture 1420 1456
printf '%s\n' \
    'fixture-key-a 203.0.113.1:51820' \
    'fixture-key-b (none)' > "$STATE/wg0.endpoints"
assert_cmd_failure "one unresolved peer keeps the entire verdict open" \
    run_helper wg0
assert_eq 1420 "$(<"$SYS/wg0/mtu")" \
    "partial peer evidence cannot authorize a live MTU change"
assert_eq '' "$(<"$CALLS")" "unresolved peers cause no link mutation"

reset_fixture 1420 1320
printf '%s\n' 'fixture-key ::/0' > "$STATE/wg0.allowed"
assert_cmd_failure "sub-1280 correction is refused for configured IPv6" \
    run_helper wg0
assert_eq 1420 "$(<"$SYS/wg0/mtu")" \
    "IPv6 minimum is preserved instead of applying an unsafe correction"

reset_fixture 1420 1320
assert_cmd_success "proven IPv4-only tunnel may use a sub-1280 ceiling" \
    run_helper wg0
assert_eq 1248 "$(<"$SYS/wg0/mtu")" \
    "IPv4-only low-MTU path remains usable without a false IPv6 block"

reset_fixture 1420 1456
assert_cmd_success "--all reconciles every enumerated WireGuard interface" \
    run_helper --all
assert_eq 1392 "$(<"$SYS/wg0/mtu")" \
    "--all follows the same lower-only calculation"

reset_fixture 1420 1456
glob_workdir="$TMP/glob-workdir"
mkdir -p "$glob_workdir"
: > "$glob_workdir/wg0"
printf '%s\n' 'wg*' > "$STATE/interfaces"
assert_cmd_failure "wildcard interface output cannot expand through the working directory" \
    run_helper_from "$glob_workdir" --all
assert_eq 1420 "$(<"$SYS/wg0/mtu")" \
    "unsupported wildcard names authorize no MTU mutation"
assert_eq '' "$(<"$CALLS")" \
    "pathname matches cannot be mistaken for WireGuard interfaces"

# Query failures must stay distinct from a proven non-WireGuard interface or
# the native explicit "off" fwmark. All routes and mutations remain private.
for mark in off 0xffffffff; do
    reset_fixture
    printf '%s\n' "$mark" > "$STATE/wg0.fwmark"
    assert_cmd_success "native fwmark $mark is accepted" run_helper wg0
    assert_eq 1392 "$(<"$SYS/wg0/mtu")" "valid fwmark keeps the lower-only correction"
    if [ "$mark" = off ]; then
        expected_route='route get 203.0.113.1'
    else
        expected_route="route get 203.0.113.1 mark $mark"
    fi
    assert_eq "$expected_route" "$(<"$ROUTE_CALLS")" "route query uses the proven fwmark state"
done

reset_fixture
assert_cmd_success "proven non-WireGuard link is skipped" run_helper outer0
assert_eq '' "$(<"$ROUTE_CALLS")" "non-WireGuard link requires no endpoint route"
assert_eq '' "$(<"$CALLS")" "non-WireGuard link is unchanged"

for inventory_case in empty partial repeated; do
    reset_fixture
    printf '7\n' > "$STATE/interfaces.rc"
    target=wg0
    case "$inventory_case" in
        empty) : > "$STATE/interfaces" ;;
        repeated) : > "$STATE/interfaces.once"; target=--all ;;
    esac
    assert_cmd_failure "failed $inventory_case interface inventory is reported" run_helper "$target"
    assert_eq 1420 "$(<"$SYS/wg0/mtu")" "failed interface inventory preserves live MTU"
    assert_eq '' "$(<"$ROUTE_CALLS")" "failed inventory cannot authorize route selection"
    assert_eq '' "$(<"$CALLS")" "failed inventory cannot authorize link mutation"
done

for query_case in empty-error partial-error empty none overflow decimal multiline; do
    reset_fixture
    case "$query_case" in
        empty-error) : > "$STATE/wg0.fwmark"; printf '7\n' > "$STATE/fwmark.rc" ;;
        partial-error) printf '7\n' > "$STATE/fwmark.rc" ;;
        empty) : > "$STATE/wg0.fwmark" ;;
        none) printf 'none\n' > "$STATE/wg0.fwmark" ;;
        overflow) printf '0x100000000\n' > "$STATE/wg0.fwmark" ;;
        decimal) printf '4660\n' > "$STATE/wg0.fwmark" ;;
        multiline) printf '0x1234\noff\n' > "$STATE/wg0.fwmark" ;;
    esac
    assert_cmd_failure "failed or invalid fwmark $query_case is reported" run_helper wg0
    assert_eq 1420 "$(<"$SYS/wg0/mtu")" "unknown fwmark preserves live MTU"
    assert_eq '' "$(<"$ROUTE_CALLS")" "unknown fwmark never falls back to an unmarked route"
    assert_eq '' "$(<"$CALLS")" "unknown fwmark cannot authorize link mutation"
done

reset_fixture 1420 1456
rm -f "$LOCK"
ln -s "$STATE/interfaces" "$LOCK"
assert_cmd_failure "symlinked lock is rejected" run_helper wg0
assert_eq 1420 "$(<"$SYS/wg0/mtu")" \
    "untrusted lock metadata authorizes no MTU mutation"

test_finish
