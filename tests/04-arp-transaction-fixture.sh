#!/bin/bash
# Behavioural regression fixture for M04's serialized ARP transition.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/04-arp-hardening.ks"
# The hardened image mounts /tmp noexec. Behaviour fixtures contain executable
# mock commands, so keep the private directory on the repository's executable
# filesystem and remove it unconditionally on exit.
FIXTURE="$(mktemp -d "$PROJECT_ROOT/.test-04-arp.XXXXXX")"
trap 'rm -rf "$FIXTURE"' EXIT

ROOT="$FIXTURE/root"
MOCK_BIN="$FIXTURE/bin"
LOG_DIR="$FIXTURE/log"
mkdir -p "$ROOT/templates" \
    "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d" \
    "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d" \
    "$ROOT/var/lib/noid-privacy" "$ROOT/run/noid-privacy" \
    "$ROOT/sys/class/net/eth0/device" \
    "$ROOT/sys/class/net/eth1/device" "$MOCK_BIN" "$LOG_DIR"

export NOID_TEST_NEIGHBORS="$FIXTURE/neighbors"
export NOID_TEST_IP_LOG="$LOG_DIR/ip.log"
export NOID_TEST_TOPOLOGY_LOG="$LOG_DIR/topology.log"
export NOID_TEST_NMCLI_LOG="$LOG_DIR/nmcli.log"
export NOID_TEST_ARPING_LOG="$LOG_DIR/arping.log"
export NOID_TEST_ARPING_COUNT="$LOG_DIR/arping.count"
export NOID_TEST_READINESS_LOG="$LOG_DIR/readiness.log"
export NOID_TEST_SYS_CLASS_NET="$ROOT/sys/class/net"
export NOID_SYS_CLASS_NET="$NOID_TEST_SYS_CLASS_NET"
export NOID_TEST_NEW_MAC="02:00:00:00:00:22"
export NOID_TEST_TOPOLOGY_MODE=success

extract_heredoc "$KS_FILE" NM_TEMPLATE_EOF "$ROOT/templates/90-arp-hardening.template"
extract_heredoc "$KS_FILE" ARP_TOOL_EOF "$FIXTURE/tool.original"
extract_heredoc "$KS_FILE" ARP_STATE_GUARD_EOF "$FIXTURE/state-guard.original"
chmod 0644 "$ROOT/templates/90-arp-hardening.template"

# Redirect only the extracted fixture copy. Production retains fixed root-owned
# paths and ownership enforcement; the behaviour test runs without host writes.
fixture_uid=$(id -u)
fixture_gid=$(id -g)
chmod 0755 "$ROOT/run/noid-privacy"
sed \
    -e "s|^TEMPLATE_DIR=.*|TEMPLATE_DIR=\"$ROOT/templates\"|" \
    -e "s|^NM_DISPATCHER=.*|NM_DISPATCHER=\"$ROOT/etc/NetworkManager/dispatcher.d/90-arp-hardening\"|" \
    -e "s|^NM_DISPATCHER_PREUP=.*|NM_DISPATCHER_PREUP=\"$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening\"|" \
    -e "s|^NM_DISPATCHER_NOWAIT=.*|NM_DISPATCHER_NOWAIT=\"$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening\"|" \
    -e "s|^STATE_DIR=.*|STATE_DIR=\"$ROOT/var/lib/noid-privacy\"|" \
    -e "s|^STATE_GUARD=.*|STATE_GUARD=\"$MOCK_BIN/state-guard\"|" \
    -e "s|^NETWORK_READINESS=.*|NETWORK_READINESS=\"$MOCK_BIN/network-readiness\"|" \
    -e "s|^EXPECTED_OWNER=0$|EXPECTED_OWNER=$fixture_uid|" \
    -e "s|^EXPECTED_GROUP=0$|EXPECTED_GROUP=$fixture_gid|" \
    -e "s|/usr/local/sbin/noid-lan-topology-refresh.sh|$MOCK_BIN/topology|g" \
    -e 's/ -o root -g root//g' \
    "$FIXTURE/tool.original" > "$FIXTURE/tool.sh"
chmod 0755 "$FIXTURE/tool.sh"

sed \
    -e "s|^STATE=.*|STATE=$ROOT/var/lib/noid-privacy/arp-hardening.state|" \
    -e "s|^STATE_DIR=.*|STATE_DIR=$ROOT/var/lib/noid-privacy|" \
    -e "s|^DISABLED=.*|DISABLED=$ROOT/var/lib/noid-privacy/arp-hardening.disabled|" \
    -e "s|^DISPATCHER_DIR=.*|DISPATCHER_DIR=$ROOT/etc/NetworkManager/dispatcher.d|" \
    -e "s|^PREUP_DIR=.*|PREUP_DIR=$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d|" \
    -e "s|^NOWAIT_DIR=.*|NOWAIT_DIR=$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d|" \
    -e "s|^DISPATCHER=.*|DISPATCHER=$ROOT/etc/NetworkManager/dispatcher.d/90-arp-hardening|" \
    -e "s|^PREUP=.*|PREUP=$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening|" \
    -e "s|^NOWAIT=.*|NOWAIT=$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening|" \
    -e "s|^TEMPLATE=.*|TEMPLATE=$ROOT/templates/90-arp-hardening.template|" \
    -e "s|0:0:|$fixture_uid:$fixture_gid:|g" \
    "$FIXTURE/state-guard.original" > "$FIXTURE/state-guard.sh"
chmod 0755 "$FIXTURE/state-guard.sh"
chmod 0755 "$ROOT/etc/NetworkManager/dispatcher.d" \
    "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d" \
    "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d"

cat > "$MOCK_BIN/id" <<'MOCK_EOF'
#!/bin/bash
[ "${1:-}" = -u ] && { echo 0; exit 0; }
exec /usr/bin/id "$@"
MOCK_EOF

cat > "$MOCK_BIN/ip" <<'MOCK_EOF'
#!/bin/bash
set -euo pipefail
printf '%q ' "$@" >> "$NOID_TEST_IP_LOG"; printf '\n' >> "$NOID_TEST_IP_LOG"
args=("$@")
if [ "${args[0]:-}" = -4 ] && [ "${args[1]:-}" = route ] \
   && [ "${args[2]:-}" = show ] && [ "${args[3]:-}" = default ] \
   && [ "${args[4]:-}" = dev ] && [ "${args[5]:-}" = eth0 ]; then
    printf 'default via 192.0.2.1 dev eth0 proto dhcp metric 100\n'
    exit 0
fi
index=0
[ "${args[0]:-}" != -4 ] || index=1
[ "${args[$index]:-}" = neigh ] || exit 1
index=$((index + 1))
action=${args[$index]:-}
index=$((index + 1))
case "$action" in
    show)
        [ "${args[$index]:-}" != to ] || index=$((index + 1))
        ip=${args[$index]:-}; index=$((index + 1))
        [ "${args[$index]:-}" = dev ] || exit 1
        iface=${args[$((index + 1))]:-}
        # Maintained iproute2 omits `dev IFACE` from an already device-scoped
        # neighbour query. Keep the backing fixture device-qualified while
        # reproducing that real command output.
        awk -v ip="$ip" -v iface="$iface" '
            $1==ip && $3==iface { print $1, "lladdr", $5, $6 }
        ' "$NOID_TEST_NEIGHBORS"
        ;;
    del)
        ip=${args[$index]:-}; index=$((index + 1))
        [ "${args[$index]:-}" = dev ] || exit 1
        iface=${args[$((index + 1))]:-}
        awk -v ip="$ip" -v iface="$iface" '!($1==ip && $3==iface)' \
            "$NOID_TEST_NEIGHBORS" > "$NOID_TEST_NEIGHBORS.new"
        mv "$NOID_TEST_NEIGHBORS.new" "$NOID_TEST_NEIGHBORS"
        ;;
    replace)
        ip=${args[$index]:-}; index=$((index + 1))
        [ "${args[$index]:-}" = lladdr ] || exit 1
        mac=${args[$((index + 1))]:-}; index=$((index + 2))
        [ "${args[$index]:-}" = dev ] || exit 1
        iface=${args[$((index + 1))]:-}; index=$((index + 2))
        [ "${args[$index]:-}" = nud ] || exit 1
        state=${args[$((index + 1))]:-}
        [ "${NOID_TEST_IP_FAIL_REPLACE_IFACE:-}" != "$iface" ] || exit 95
        awk -v ip="$ip" -v iface="$iface" '!($1==ip && $3==iface)' \
            "$NOID_TEST_NEIGHBORS" > "$NOID_TEST_NEIGHBORS.new"
        printf '%s dev %s lladdr %s %s\n' "$ip" "$iface" "$mac" "${state^^}" \
            >> "$NOID_TEST_NEIGHBORS.new"
        mv "$NOID_TEST_NEIGHBORS.new" "$NOID_TEST_NEIGHBORS"
        ;;
    *) exit 1 ;;
esac
MOCK_EOF

cat > "$MOCK_BIN/arping" <<'MOCK_EOF'
#!/bin/bash
set -euo pipefail
iface=""; gateway=""
while [ $# -gt 0 ]; do
    case "$1" in
        -I) iface=$2; shift 2 ;;
        -c3|-w5) shift ;;
        *) gateway=$1; shift ;;
    esac
done
[ -n "$iface" ] && [ -n "$gateway" ]
count=0
[ ! -s "$NOID_TEST_ARPING_COUNT" ] || read -r count < "$NOID_TEST_ARPING_COUNT"
count=$((count + 1))
printf '%s\n' "$count" > "$NOID_TEST_ARPING_COUNT"
mac=$NOID_TEST_NEW_MAC
if [ "${NOID_TEST_ARPING_MODE:-stable}" = alternate ] \
        && [ $((count % 2)) -eq 0 ]; then
    mac=02:00:00:00:00:33
fi
printf 'call=%s iface=%s gateway=%s mac=%s\n' \
    "$count" "$iface" "$gateway" "$mac" >> "$NOID_TEST_ARPING_LOG"
if [ "${NOID_TEST_ARPING_POPULATE:-0}" = 1 ]; then
    awk -v ip="$gateway" -v iface="$iface" '!($1==ip && $3==iface)' \
        "$NOID_TEST_NEIGHBORS" > "$NOID_TEST_NEIGHBORS.new"
    printf '%s dev %s lladdr %s REACHABLE\n' "$gateway" "$iface" \
        "$mac" >> "$NOID_TEST_NEIGHBORS.new"
    mv "$NOID_TEST_NEIGHBORS.new" "$NOID_TEST_NEIGHBORS"
fi
printf 'Unicast reply from %s [%s]  1.000ms\n' "$gateway" "$mac"
MOCK_EOF

cat > "$MOCK_BIN/sleep" <<'MOCK_EOF'
#!/bin/bash
printf 'sleep %s\n' "$*" >> "$NOID_TEST_ARPING_LOG"
exit 0
MOCK_EOF

cat > "$MOCK_BIN/logger" <<'MOCK_EOF'
#!/bin/bash
exit 0
MOCK_EOF
cat > "$MOCK_BIN/topology" <<'MOCK_EOF'
#!/bin/bash
printf '%s\n' "${NOID_TEST_TOPOLOGY_MODE:-success}" >> "$NOID_TEST_TOPOLOGY_LOG"
case "${NOID_TEST_TOPOLOGY_MODE:-success}" in
    success) exit 0 ;;
    fail) exit 91 ;;
    signal) kill -TERM "$PPID"; exit 0 ;;
    repin)
        ip neigh replace 192.0.2.1 lladdr 02:00:00:00:00:11 \
            dev eth0 nud permanent
        exit 0
        ;;
    *) exit 92 ;;
esac
MOCK_EOF
cat > "$MOCK_BIN/state-guard" <<'MOCK_EOF'
#!/bin/bash
count_file=${NOID_TEST_GUARD_COUNT_FILE:?}
count=0
[ ! -s "$count_file" ] || read -r count < "$count_file"
count=$((count + 1))
printf '%s\n' "$count" > "$count_file"
case "${NOID_TEST_GUARD_MODE:-success}" in
    success) exit 0 ;;
    fail) exit 1 ;;
    fail-third) [ "$count" -lt 3 ] ;;
    *) exit 2 ;;
esac
MOCK_EOF
# The exit code is the whole point now: 2 means two bounded observations
# disagree about who owns the gateway address, anything else means the control
# simply has not established itself. Only the former may reach the link.
cat > "$MOCK_BIN/arp-tool-fail" <<'MOCK_EOF'
#!/bin/bash
exit "${NOID_TEST_ARP_TOOL_RC:-73}"
MOCK_EOF
cat > "$MOCK_BIN/arp-tool-success" <<'MOCK_EOF'
#!/bin/bash
printf 'iface=%s gateway=%s argv=%s\n' \
    "${NOID_ARP_IFACE:-}" "${NOID_ARP_GATEWAY_IP:-}" "$*" \
    >> "$NOID_TEST_ARP_TOOL_LOG"
exit 0
MOCK_EOF
cat > "$MOCK_BIN/nmcli" <<'MOCK_EOF'
#!/bin/bash
printf '%s\n' "$*" >> "$NOID_TEST_NMCLI_LOG"
exit 0
MOCK_EOF
cat > "$MOCK_BIN/network-readiness" <<'MOCK_EOF'
#!/bin/bash
[ "$#" -eq 1 ] || exit 2
case "$1" in
    offline|ready) printf '%s\n' "$1" >> "$NOID_TEST_READINESS_LOG" ;;
    *) exit 2 ;;
esac
MOCK_EOF
chmod 0755 "$MOCK_BIN"/*

export PATH="$MOCK_BIN:/usr/bin:/usr/sbin"
export NOID_TEST_ARP_TOOL_LOG="$LOG_DIR/arp-tool.log"
export NOID_TEST_GUARD_COUNT_FILE="$LOG_DIR/state-guard.count"

reset_old_state() {
    mkdir -p "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d" \
        "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d" \
        "$ROOT/var/lib/noid-privacy"
    chmod 0755 "$ROOT/var/lib/noid-privacy"
    printf '%s\n' \
        '192.0.2.1 dev eth0 lladdr 02:00:00:00:00:11 PERMANENT' \
        '192.0.2.1 dev eth1 lladdr 02:00:00:00:01:11 PERMANENT' \
        > "$NOID_TEST_NEIGHBORS"
    rm -f "$ROOT/etc/NetworkManager/dispatcher.d/90-arp-hardening" \
        "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening" \
        "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening"
    ln -s prior-no-wait-target \
        "$ROOT/etc/NetworkManager/dispatcher.d/90-arp-hardening"
    printf 'exact-prior-preup\n' \
        > "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening"
    printf 'exact-prior-nowait\n' \
        > "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening"
    chmod 0700 \
        "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening" \
        "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening"
    cat > "$ROOT/var/lib/noid-privacy/arp-hardening.state" <<'STATE_EOF'
ENABLED=1
WAN_IFACE=eth0
GATEWAY_IP=192.0.2.1
GATEWAY_MAC=02:00:00:00:00:11
LEARNED_AT=2026-07-13T00:00:00Z
STATE_EOF
    chmod 0644 "$ROOT/var/lib/noid-privacy/arp-hardening.state"
    rm -f "$ROOT/var/lib/noid-privacy/arp-hardening.disabled"
    : > "$NOID_TEST_IP_LOG"
    : > "$NOID_TEST_TOPOLOGY_LOG"
    : > "$NOID_TEST_NMCLI_LOG"
    : > "$NOID_TEST_ARP_TOOL_LOG"
    : > "$NOID_TEST_ARPING_LOG"
    : > "$NOID_TEST_ARPING_COUNT"
    : > "$NOID_TEST_READINESS_LOG"
    : > "$NOID_TEST_GUARD_COUNT_FILE"
    unset NOID_TEST_IP_FAIL_REPLACE_IFACE || true
    unset NOID_TEST_ARPING_MODE NOID_TEST_ARPING_POPULATE || true
    export NOID_TEST_GUARD_MODE=success
    export NOID_TEST_TOPOLOGY_MODE=success
}

test_start "04-arp-transaction-fixture"

# One successful standard-ARP refresh proves stale-pin removal, exact-device
# observation, atomic publication and preservation of a duplicate gateway on
# another physical interface.
reset_old_state
if NOID_ARP_IFACE=eth0 NOID_ARP_GATEWAY_IP=192.0.2.1 \
        "$FIXTURE/tool.sh" --silent refresh >/dev/null 2>"$LOG_DIR/refresh.stderr"; then
    _pass "standard-ARP refresh commits through bounded kernel ARP observation"
else
    _fail "standard-ARP refresh commits through bounded kernel ARP observation"
    sed 's/^/    diagnostic: /' "$LOG_DIR/refresh.stderr" >&2
fi
assert_grep_fixed \
    '192.0.2.1 dev eth0 lladdr 02:00:00:00:00:22 PERMANENT' \
    "$NOID_TEST_NEIGHBORS" "freshly observed gateway becomes the exact permanent pin"
assert_grep_fixed \
    '192.0.2.1 dev eth1 lladdr 02:00:00:00:01:11 PERMANENT' \
    "$NOID_TEST_NEIGHBORS" "same gateway address on another interface is untouched"
assert_grep_fixed 'neigh del 192.0.2.1 dev eth0' "$NOID_TEST_IP_LOG" \
    "stale permanent target is deleted before bounded observation"
assert_eq "2" "$(cat "$NOID_TEST_ARPING_COUNT")" \
    "empty cache succeeds through two independent raw observations"
assert_grep_fixed 'sleep 1' "$NOID_TEST_ARPING_LOG" \
    "empty-cache raw observations include a time-separation step"
assert_not_grep 'neigh del 192\.0\.2\.1 dev eth1' "$NOID_TEST_IP_LOG" \
    "target deletion is device-scoped"
assert_grep_fixed 'success' "$NOID_TEST_TOPOLOGY_LOG" \
    "gateway refresh revalidates the authoritative M03/M05 topology"
assert_grep_fixed 'offline' "$NOID_TEST_READINESS_LOG" \
    "gateway refresh retires readiness before observation"
assert_grep_fixed 'ready' "$NOID_TEST_READINESS_LOG" \
    "gateway refresh publishes readiness only after the boundary postcheck"
assert_eq "no-wait.d/90-arp-hardening" \
    "$(readlink "$ROOT/etc/NetworkManager/dispatcher.d/90-arp-hardening")" \
    "normal dispatcher entry points to the committed no-wait copy"
assert_cmd_success "generated awaited/no-wait copies are identical" \
    cmp -s \
        "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening" \
        "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening"
assert_eq "0" \
    "$(find "$ROOT/var/lib/noid-privacy" -maxdepth 1 -name '.arp-transaction.*' | wc -l)" \
    "successful commit leaves no transaction directory"

if "$FIXTURE/tool.sh" --silent disable >/dev/null 2>&1; then
    _pass "transactional disable commits"
else
    _fail "transactional disable commits"
fi
assert_not_grep '192\.0\.2\.1 dev eth0' "$NOID_TEST_NEIGHBORS" \
    "disable removes the managed permanent gateway pin"
if [ -f "$ROOT/var/lib/noid-privacy/arp-hardening.disabled" ] \
   && grep -qx 'ENABLED=0' "$ROOT/var/lib/noid-privacy/arp-hardening.state" \
   && [ ! -e "$ROOT/etc/NetworkManager/dispatcher.d/90-arp-hardening" ] \
   && [ ! -e "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening" ] \
   && [ ! -e "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening" ]; then
    _pass "disable removes the pin/dispatcher but retains fail-closed identity"
else
    _fail "disable lost its opt-out/identity contract"
fi
assert_eq 600 "$(stat -c '%a' "$ROOT/var/lib/noid-privacy/arp-hardening.disabled")" \
    "disabled marker is private"
assert_grep_fixed 'GATEWAY_MAC=02:00:00:00:00:22' \
    "$ROOT/var/lib/noid-privacy/arp-hardening.state" \
    "disabled state retains the last validated XDP gateway identity"
assert_eq 644 "$(stat -c '%a' "$ROOT/var/lib/noid-privacy/arp-hardening.state")" \
    "retained GUI-readable identity keeps its exact mode"

# An independent kernel neighbour is retained and must match one raw
# observation. A disagreement fails before any new permanent pin is published.
reset_old_state
sed -i \
    's/192.0.2.1 dev eth0 lladdr 02:00:00:00:00:11 PERMANENT/192.0.2.1 dev eth0 lladdr 02:00:00:00:00:22 REACHABLE/' \
    "$NOID_TEST_NEIGHBORS"
assert_cmd_success "matching kernel/raw gateway evidence succeeds" \
    env NOID_ARP_IFACE=eth0 NOID_ARP_GATEWAY_IP=192.0.2.1 \
        "$FIXTURE/tool.sh" --silent refresh
assert_eq "1" "$(cat "$NOID_TEST_ARPING_COUNT")" \
    "independent kernel match needs only one bounded raw observation"

reset_old_state
sed -i \
    's/192.0.2.1 dev eth0 lladdr 02:00:00:00:00:11 PERMANENT/192.0.2.1 dev eth0 lladdr 02:00:00:00:00:33 REACHABLE/' \
    "$NOID_TEST_NEIGHBORS"
assert_cmd_failure "kernel/raw gateway disagreement fails closed" \
    env NOID_ARP_IFACE=eth0 NOID_ARP_GATEWAY_IP=192.0.2.1 \
        "$FIXTURE/tool.sh" --silent refresh
assert_not_grep 'neigh replace 192.0.2.1 lladdr 02:00:00:00:00:22' \
    "$NOID_TEST_IP_LOG" \
    "kernel/raw disagreement never publishes the newly observed pin"

reset_old_state
export NOID_TEST_ARPING_MODE=alternate
assert_cmd_failure "two different empty-cache raw observations fail closed" \
    env NOID_ARP_IFACE=eth0 NOID_ARP_GATEWAY_IP=192.0.2.1 \
        "$FIXTURE/tool.sh" --silent refresh
assert_grep_fixed \
    '192.0.2.1 dev eth0 lladdr 02:00:00:00:00:11 PERMANENT' \
    "$NOID_TEST_NEIGHBORS" \
    "disagreeing raw observations roll back the prior permanent pin"
unset NOID_TEST_ARPING_MODE

# Interrupt after all candidate files have been published. Every byte, symlink
# and previous permanent neighbour must be restored by the EXIT trap.
reset_old_state
mkdir -p "$FIXTURE/prior"
cp -a "$ROOT/etc/NetworkManager/dispatcher.d/90-arp-hardening" "$FIXTURE/prior/dispatcher"
cp -a "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening" \
    "$FIXTURE/prior/preup"
cp -a "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening" \
    "$FIXTURE/prior/nowait"
cp -a "$ROOT/var/lib/noid-privacy/arp-hardening.state" "$FIXTURE/prior/state"
export NOID_TEST_TOPOLOGY_MODE=signal
if NOID_ARP_IFACE=eth0 NOID_ARP_GATEWAY_IP=192.0.2.1 \
        "$FIXTURE/tool.sh" --silent refresh >/dev/null 2>&1; then
    interrupt_rc=0
else
    interrupt_rc=$?
fi
assert_eq "143" "$interrupt_rc" "TERM during post-publication validation is visible"
assert_eq "$(readlink "$FIXTURE/prior/dispatcher")" \
    "$(readlink "$ROOT/etc/NetworkManager/dispatcher.d/90-arp-hardening")" \
    "interruption restores prior dispatcher link"
assert_cmd_success "interruption restores prior awaited bytes" \
    cmp -s "$FIXTURE/prior/preup" \
        "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening"
assert_cmd_success "interruption restores prior no-wait bytes" \
    cmp -s "$FIXTURE/prior/nowait" \
        "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening"
assert_cmd_success "interruption restores prior state bytes" \
    cmp -s "$FIXTURE/prior/state" "$ROOT/var/lib/noid-privacy/arp-hardening.state"
assert_eq "prior-no-wait-target" \
    "$(readlink "$ROOT/etc/NetworkManager/dispatcher.d/90-arp-hardening")" \
    "interruption restores the exact prior root symlink target"
assert_grep_fixed \
    '192.0.2.1 dev eth0 lladdr 02:00:00:00:00:11 PERMANENT' \
    "$NOID_TEST_NEIGHBORS" "interruption restores the previous permanent neighbour"
assert_eq "0" \
    "$(find "$ROOT/var/lib/noid-privacy" -maxdepth 1 -name '.arp-transaction.*' | wc -l)" \
    "rollback removes its private transaction directory"

# Every NetworkManager entry point must propagate refresh failure. The already
# active up/dhcp4-change events additionally disconnect their exact interface.
extract_heredoc "$KS_FILE" NM_TEMPLATE_EOF "$FIXTURE/dispatcher.template"
sed \
    -e 's/@@WAN_IFACE@@/eth0/g' \
    -e 's/@@GATEWAY_IP@@/192.0.2.1/g' \
    -e 's/@@GATEWAY_MAC@@/02:00:00:00:00:11/g' \
    -e 's|/sys/class/net|${NOID_TEST_SYS_CLASS_NET}|g' \
    -e "s|ARP_TOOL=\"/usr/local/sbin/noid-arp-hardening.sh\"|ARP_TOOL=\"$MOCK_BIN/arp-tool-fail\"|" \
    -e "s|STATE_GUARD=\"/usr/local/sbin/noid-arp-state-guard.sh\"|STATE_GUARD=\"$MOCK_BIN/state-guard\"|" \
    -e "s|NETWORK_READINESS=\"/usr/local/libexec/noid-network-readiness\"|NETWORK_READINESS=\"$MOCK_BIN/network-readiness\"|" \
    -e "s|/var/lib/noid-privacy|$ROOT/var/lib/noid-privacy|g" \
    -e "s|/run/noid-privacy|$ROOT/run/noid-privacy|g" \
    -e "s|0:0:|$fixture_uid:$fixture_gid:|g" \
    -e "s|/usr/bin/nmcli|$MOCK_BIN/nmcli|g" \
    "$FIXTURE/dispatcher.template" > "$FIXTURE/dispatcher.sh"
chmod 0755 "$FIXTURE/dispatcher.sh"
if IP4_GATEWAY=192.0.2.2 "$FIXTURE/dispatcher.sh" eth0 pre-up >/dev/null 2>&1; then
    _fail "awaited pre-up propagates transactional refresh failure"
else
    _pass "awaited pre-up propagates transactional refresh failure"
fi
assert_eq "" "$(cat "$NOID_TEST_NMCLI_LOG")" \
    "pre-up failure blocks activation without disconnecting an inactive device"
# A transient failure must still fail the event -- and must leave the link
# alone. This is the ordinary case: DHCP not settled, no arping reply yet, a
# helper that could not run. Disconnecting here stranded the owner on hardware
# that was merely slow, which is exactly what the compatibility document
# promises cannot happen.
: > "$NOID_TEST_NMCLI_LOG"
if NOID_TEST_ARP_TOOL_RC=73 IP4_GATEWAY=192.0.2.2 \
        "$FIXTURE/dispatcher.sh" eth0 dhcp4-change >/dev/null 2>&1; then
    _fail "dhcp4-change propagates transactional refresh failure"
else
    _pass "dhcp4-change propagates transactional refresh failure"
fi
assert_eq "" "$(cat "$NOID_TEST_NMCLI_LOG")" \
    "a transient DHCP-transition failure never disconnects the link"
if NOID_TEST_ARP_TOOL_RC=73 IP4_GATEWAY=192.0.2.2 \
        "$FIXTURE/dispatcher.sh" eth0 up >/dev/null 2>&1; then
    _fail "up propagates transactional refresh failure"
else
    _pass "up propagates transactional refresh failure"
fi
assert_eq "" "$(cat "$NOID_TEST_NMCLI_LOG")" \
    "a transient up-transition failure never disconnects the link"

# A contested gateway identity is the one failure that leaves a boundary open
# this layer cannot close, so it still takes the affected interface down.
: > "$NOID_TEST_NMCLI_LOG"
if NOID_TEST_ARP_TOOL_RC=2 IP4_GATEWAY=192.0.2.2 \
        "$FIXTURE/dispatcher.sh" eth0 dhcp4-change >/dev/null 2>&1; then
    _fail "dhcp4-change propagates a contested gateway identity"
else
    _pass "dhcp4-change propagates a contested gateway identity"
fi
assert_grep_fixed 'device disconnect eth0' "$NOID_TEST_NMCLI_LOG" \
    "a contested DHCP transition disconnects only its exact interface"
: > "$NOID_TEST_NMCLI_LOG"
if NOID_TEST_ARP_TOOL_RC=2 IP4_GATEWAY=192.0.2.2 \
        "$FIXTURE/dispatcher.sh" eth0 up >/dev/null 2>&1; then
    _fail "up propagates a contested gateway identity"
else
    _pass "up propagates a contested gateway identity"
fi
assert_grep_fixed 'device disconnect eth0' "$NOID_TEST_NMCLI_LOG" \
    "a contested up transition disconnects only its exact interface"
# pre-up never touches the link even when contested: the device is not active.
: > "$NOID_TEST_NMCLI_LOG"
NOID_TEST_ARP_TOOL_RC=2 IP4_GATEWAY=192.0.2.2 \
    "$FIXTURE/dispatcher.sh" eth0 pre-up >/dev/null 2>&1 || true
assert_eq "" "$(cat "$NOID_TEST_NMCLI_LOG")" \
    "a contested pre-up still never disconnects an inactive device"

# Same-interface pre-up restores only the already validated identity. Any
# active-event revalidation failure, including a same-IP interface roam, fails
# closed instead of retaining a potentially stale destination MAC.
: > "$NOID_TEST_NMCLI_LOG"
if IP4_GATEWAY=192.0.2.1 "$FIXTURE/dispatcher.sh" eth0 pre-up >/dev/null 2>&1; then
    _pass "same-interface pre-up restores the previously validated pin"
else
    _fail "same-interface pre-up restores the previously validated pin"
fi
assert_eq "" "$(cat "$NOID_TEST_NMCLI_LOG")" \
    "pre-up restore never disconnects an inactive interface"
assert_grep_fixed \
    '192.0.2.1 dev eth0 lladdr 02:00:00:00:00:11 PERMANENT' \
    "$NOID_TEST_NEIGHBORS" \
    "pre-up restore retains the exact permanent identity"

: > "$NOID_TEST_NMCLI_LOG"
if NOID_TEST_ARP_TOOL_RC=73 IP4_GATEWAY=192.0.2.1 \
        "$FIXTURE/dispatcher.sh" eth1 up >/dev/null 2>&1; then
    _fail "same-gateway roam rejects failed identity revalidation"
else
    _pass "same-gateway roam rejects failed identity revalidation"
fi
assert_eq "" "$(cat "$NOID_TEST_NMCLI_LOG")" \
    "a transient roam revalidation failure never disconnects the link"
: > "$NOID_TEST_NMCLI_LOG"
if NOID_TEST_ARP_TOOL_RC=2 IP4_GATEWAY=192.0.2.1 \
        "$FIXTURE/dispatcher.sh" eth1 up >/dev/null 2>&1; then
    _fail "same-gateway roam rejects a contested identity"
else
    _pass "same-gateway roam rejects a contested identity"
fi
assert_grep_fixed 'device disconnect eth1' "$NOID_TEST_NMCLI_LOG" \
    "a contested same-gateway revalidation disconnects the exact event interface"

extract_heredoc "$KS_FILE" ARP_INITIAL_DISPATCHER_EOF "$FIXTURE/bootstrap-pre-up.sh"
sed \
    -e 's|/sys/class/net|${NOID_TEST_SYS_CLASS_NET}|g' \
    -e "s|ARP_TOOL=/usr/local/sbin/noid-arp-hardening.sh|ARP_TOOL=$MOCK_BIN/arp-tool-fail|g" \
    -e "s|STATE_GUARD=/usr/local/sbin/noid-arp-state-guard.sh|STATE_GUARD=$MOCK_BIN/state-guard|g" \
    -e "s|NETWORK_READINESS=/usr/local/libexec/noid-network-readiness|NETWORK_READINESS=$MOCK_BIN/network-readiness|g" \
    -e "s|/usr/bin/nmcli|$MOCK_BIN/nmcli|g" \
    "$FIXTURE/bootstrap-pre-up.sh" > "$FIXTURE/bootstrap-pre-up.fixture.sh"
chmod 0755 "$FIXTURE/bootstrap-pre-up.fixture.sh"
rm -f "$ROOT/var/lib/noid-privacy/arp-hardening.state"
sed -i "s|/var/lib/noid-privacy|$ROOT/var/lib/noid-privacy|g" \
    "$FIXTURE/bootstrap-pre-up.fixture.sh"
if IP4_GATEWAY=192.0.2.1 "$FIXTURE/bootstrap-pre-up.fixture.sh" eth0 pre-up \
        >/dev/null 2>&1; then
    _fail "initial awaited pre-up propagates learner failure"
else
    _pass "initial awaited pre-up propagates learner failure"
fi

# The reproduced VM failure had no IP4_GATEWAY at pre-up. That must defer
# without a learner call, then the ordinary up event must derive the exact
# device route and invoke learning. A failed post-DHCP call disconnects.
sed \
    -e "s|ARP_TOOL=$MOCK_BIN/arp-tool-fail|ARP_TOOL=$MOCK_BIN/arp-tool-success|g" \
    "$FIXTURE/bootstrap-pre-up.fixture.sh" > "$FIXTURE/bootstrap-retry.fixture.sh"
chmod 0755 "$FIXTURE/bootstrap-retry.fixture.sh"
: > "$NOID_TEST_ARP_TOOL_LOG"
if "$FIXTURE/bootstrap-retry.fixture.sh" eth0 pre-up >/dev/null 2>&1; then
    _pass "gateway-less pre-up preserves bootstrap state for retry"
else
    _fail "gateway-less pre-up preserves bootstrap state for retry"
fi
assert_eq "" "$(cat "$NOID_TEST_ARP_TOOL_LOG")" \
    "gateway-less pre-up does not trust a stale route"
assert_cmd_success "up retries bootstrap learning from exact-device route" \
    "$FIXTURE/bootstrap-retry.fixture.sh" eth0 up
assert_grep_fixed 'iface=eth0 gateway=192.0.2.1 argv=--silent learn' \
    "$NOID_TEST_ARP_TOOL_LOG" "post-DHCP retry passes exact interface and gateway"

for no_gateway_event in pre-up up dhcp4-change; do
    : > "$NOID_TEST_ARP_TOOL_LOG"
    : > "$NOID_TEST_NMCLI_LOG"
    assert_cmd_success \
        "initial $no_gateway_event accepts NetworkManager no-gateway sentinel" \
        env IP4_GATEWAY=0.0.0.0 "$FIXTURE/bootstrap-retry.fixture.sh" \
            eth0 "$no_gateway_event"
    assert_eq "" "$(cat "$NOID_TEST_ARP_TOOL_LOG")" \
        "initial $no_gateway_event never probes 0.0.0.0"
    assert_eq "" "$(cat "$NOID_TEST_NMCLI_LOG")" \
        "initial $no_gateway_event never disconnects a gateway-less LAN"
done

for no_gateway_event in pre-up up dhcp4-change; do
    : > "$NOID_TEST_ARP_TOOL_LOG"
    : > "$NOID_TEST_NMCLI_LOG"
    : > "$NOID_TEST_READINESS_LOG"
    assert_cmd_success \
        "generated $no_gateway_event accepts NetworkManager no-gateway sentinel" \
        env IP4_GATEWAY=0.0.0.0 "$FIXTURE/dispatcher.sh" \
            eth1 "$no_gateway_event"
    assert_eq "" "$(cat "$NOID_TEST_ARP_TOOL_LOG")" \
        "generated $no_gateway_event never invokes gateway refresh for 0.0.0.0"
    assert_eq "" "$(cat "$NOID_TEST_NMCLI_LOG")" \
        "generated $no_gateway_event never disconnects a gateway-less LAN"
    assert_eq "" "$(cat "$NOID_TEST_READINESS_LOG")" \
        "generated $no_gateway_event on an unpinned link preserves the pinned WAN's readiness"

    : > "$NOID_TEST_READINESS_LOG"
    assert_cmd_success \
        "generated pinned-interface $no_gateway_event handles the no-gateway sentinel" \
        env IP4_GATEWAY=0.0.0.0 "$FIXTURE/dispatcher.sh" \
            eth0 "$no_gateway_event"
    assert_eq "offline" "$(cat "$NOID_TEST_READINESS_LOG")" \
        "generated pinned-interface $no_gateway_event retires readiness fail-closed"
done

# Fail-closed distinctions around the gatewayless exception are load-bearing.
# Corrupt state must still retire readiness before rejecting the event, and a
# real gateway candidate must retire it before any transactional refresh.
: > "$NOID_TEST_READINESS_LOG"
export NOID_TEST_GUARD_MODE=fail
assert_cmd_failure "generated gatewayless event fails closed on invalid state" \
    env IP4_GATEWAY=0.0.0.0 "$FIXTURE/dispatcher.sh" eth1 up
assert_eq "offline" "$(cat "$NOID_TEST_READINESS_LOG")" \
    "state-guard failure retires readiness even without an event gateway"
export NOID_TEST_GUARD_MODE=success

: > "$NOID_TEST_READINESS_LOG"
assert_cmd_failure "generated gateway transition propagates refresh failure" \
    env NOID_TEST_ARP_TOOL_RC=73 IP4_GATEWAY=192.0.2.2 \
        "$FIXTURE/dispatcher.sh" eth1 up
assert_eq "offline" "$(cat "$NOID_TEST_READINESS_LOG")" \
    "an actual gateway transition retires readiness before refresh"

# Discriminating control: reintroduce the old unconditional retirement before
# gateway detection and prove the gatewayless assertion detects it.
cp "$FIXTURE/dispatcher.sh" "$FIXTURE/dispatcher-unconditional-offline.sh"
python3 - "$FIXTURE/dispatcher-unconditional-offline.sh" <<'MUTATE_UP_EOF'
import sys

path = sys.argv[1]
source = open(path, encoding="utf-8").read()
anchor = '''    pre-up|up|dhcp4-change)
        [[ "$IFACE" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || exit 1
        [ -d "${NOID_TEST_SYS_CLASS_NET}/$IFACE/device" ] || exit 0
'''
if source.count(anchor) != 1:
    raise SystemExit("gatewayless mutation anchor missing or ambiguous")
source = source.replace(
    anchor,
    anchor + '        "$NETWORK_READINESS" offline\n',
    1,
)
open(path, "w", encoding="utf-8").write(source)
MUTATE_UP_EOF
chmod 0755 "$FIXTURE/dispatcher-unconditional-offline.sh"
: > "$NOID_TEST_READINESS_LOG"
assert_cmd_success "control: old gatewayless event still exits successfully" \
    env IP4_GATEWAY=0.0.0.0 \
        "$FIXTURE/dispatcher-unconditional-offline.sh" eth1 up
assert_eq "offline" "$(cat "$NOID_TEST_READINESS_LOG")" \
    "control: unconditional gatewayless readiness retirement is detectable"

: > "$NOID_TEST_NMCLI_LOG"
if NOID_TEST_ARP_TOOL_RC=73 "$FIXTURE/bootstrap-pre-up.fixture.sh" eth0 up \
        >/dev/null 2>&1; then
    _fail "failed post-DHCP bootstrap is visible"
else
    _pass "failed post-DHCP bootstrap is visible"
fi
assert_eq "" "$(cat "$NOID_TEST_NMCLI_LOG")" \
    "a transient post-DHCP bootstrap failure never disconnects the link"
: > "$NOID_TEST_NMCLI_LOG"
if NOID_TEST_ARP_TOOL_RC=2 "$FIXTURE/bootstrap-pre-up.fixture.sh" eth0 up \
        >/dev/null 2>&1; then
    _fail "contested post-DHCP bootstrap is visible"
else
    _pass "contested post-DHCP bootstrap is visible"
fi
assert_grep_fixed 'device disconnect eth0' "$NOID_TEST_NMCLI_LOG" \
    "a contested post-DHCP bootstrap disconnects the exact interface"

# A durable M05 peer policy for the gateway can legitimately restore the same
# kernel entry during topology refresh. M04 must roll its opt-out back rather
# than claim that the permanent pin disappeared.
reset_old_state
export NOID_TEST_TOPOLOGY_MODE=repin
if "$FIXTURE/tool.sh" --silent disable >/dev/null 2>&1; then
    _fail "conflicting M05 gateway-peer pin prevents a false M04 disable"
else
    _pass "conflicting M05 gateway-peer pin prevents a false M04 disable"
fi
assert_grep_fixed 'ENABLED=1' \
    "$ROOT/var/lib/noid-privacy/arp-hardening.state" \
    "failed pin opt-out restores the active M04 state"
assert_cmd_success "failed pin opt-out removes its transient marker" \
    test ! -e "$ROOT/var/lib/noid-privacy/arp-hardening.disabled"
assert_grep_fixed \
    '192.0.2.1 dev eth0 lladdr 02:00:00:00:00:11 PERMANENT' \
    "$NOID_TEST_NEIGHBORS" "failed pin opt-out restores the exact old neighbour"

# Unsafe state and lock objects must fail before ARP observation mutates the
# current neighbour. Neither refresh nor disable has a corruption-bypass mode.
reset_old_state
assert_eq 600 \
    "$(stat -c '%a' "$ROOT/var/lib/noid-privacy/.arp-hardening.lock")" \
    "serialized transition lock remains private"
printf 'UNKNOWN=value\n' >> "$ROOT/var/lib/noid-privacy/arp-hardening.state"
if NOID_ARP_IFACE=eth0 NOID_ARP_GATEWAY_IP=192.0.2.1 \
        "$FIXTURE/tool.sh" --silent refresh >/dev/null 2>&1; then
    _fail "closed parser rejects an unknown state key"
else
    _pass "closed parser rejects an unknown state key"
fi
assert_grep_fixed \
    '192.0.2.1 dev eth0 lladdr 02:00:00:00:00:11 PERMANENT' \
    "$NOID_TEST_NEIGHBORS" "invalid state is rejected before gateway mutation"

reset_old_state
rm -f "$ROOT/var/lib/noid-privacy/.arp-hardening.lock"
printf 'do-not-touch\n' > "$FIXTURE/foreign-lock-target"
ln -s "$FIXTURE/foreign-lock-target" \
    "$ROOT/var/lib/noid-privacy/.arp-hardening.lock"
if NOID_ARP_IFACE=eth0 NOID_ARP_GATEWAY_IP=192.0.2.1 \
        "$FIXTURE/tool.sh" --silent refresh >/dev/null 2>&1; then
    _fail "transaction rejects a symlink lock"
else
    _pass "transaction rejects a symlink lock"
fi
assert_eq 'do-not-touch' "$(cat "$FIXTURE/foreign-lock-target")" \
    "symlink lock target is never opened or truncated"
rm -f "$ROOT/var/lib/noid-privacy/.arp-hardening.lock"

reset_old_state
export NOID_TEST_GUARD_MODE=fail
if NOID_ARP_IFACE=eth0 NOID_ARP_GATEWAY_IP=192.0.2.1 \
        "$FIXTURE/tool.sh" --silent refresh >/dev/null 2>&1; then
    _fail "pre-transaction state-guard failure is propagated"
else
    _pass "pre-transaction state-guard failure is propagated"
fi
assert_grep_fixed \
    '192.0.2.1 dev eth0 lladdr 02:00:00:00:00:11 PERMANENT' \
    "$NOID_TEST_NEIGHBORS" "state-guard failure precedes gateway mutation"
export NOID_TEST_GUARD_MODE=success

# A complete candidate must pass the guard after all managed files are
# published. Inject failure only at that third invocation and prove that the
# already-installed pin and every prior file are rolled back before topology.
reset_old_state
cp -a "$ROOT/etc/NetworkManager/dispatcher.d/90-arp-hardening" \
    "$FIXTURE/prior/post-guard-dispatcher"
cp -a "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening" \
    "$FIXTURE/prior/post-guard-preup"
cp -a "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening" \
    "$FIXTURE/prior/post-guard-nowait"
cp -a "$ROOT/var/lib/noid-privacy/arp-hardening.state" \
    "$FIXTURE/prior/post-guard-state"
export NOID_TEST_GUARD_MODE=fail-third
if NOID_ARP_IFACE=eth0 NOID_ARP_GATEWAY_IP=192.0.2.1 \
        "$FIXTURE/tool.sh" --silent refresh >/dev/null 2>&1; then
    _fail "post-publication guard failure aborts the transaction"
else
    _pass "post-publication guard failure aborts the transaction"
fi
assert_eq "$(readlink "$FIXTURE/prior/post-guard-dispatcher")" \
    "$(readlink "$ROOT/etc/NetworkManager/dispatcher.d/90-arp-hardening")" \
    "post-publication failure restores prior dispatcher link"
assert_cmd_success "post-publication failure restores prior awaited copy" \
    cmp -s "$FIXTURE/prior/post-guard-preup" \
        "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening"
assert_cmd_success "post-publication failure restores prior no-wait copy" \
    cmp -s "$FIXTURE/prior/post-guard-nowait" \
        "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening"
assert_cmd_success "post-publication failure restores prior state" \
    cmp -s "$FIXTURE/prior/post-guard-state" \
        "$ROOT/var/lib/noid-privacy/arp-hardening.state"
assert_grep_fixed \
    '192.0.2.1 dev eth0 lladdr 02:00:00:00:00:11 PERMANENT' \
    "$NOID_TEST_NEIGHBORS" \
    "post-publication failure restores the exact prior neighbour"
assert_eq "" "$(cat "$NOID_TEST_TOPOLOGY_LOG")" \
    "invalid published contract never reaches topology mutation"
export NOID_TEST_GUARD_MODE=success

# Exercise the actual extracted boot guard against its complete enabled,
# disabled, malformed-marker and unsafe-metadata state machine.
rm -f "$ROOT/var/lib/noid-privacy/arp-hardening.state" \
    "$ROOT/var/lib/noid-privacy/arp-hardening.disabled" \
    "$ROOT/etc/NetworkManager/dispatcher.d/90-arp-hardening" \
    "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening" \
    "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening"
assert_cmd_success "empty pre-learning state is internally consistent" \
    "$FIXTURE/state-guard.sh"
ln -s "$FIXTURE/missing-marker-target" \
    "$ROOT/var/lib/noid-privacy/arp-hardening.disabled"
assert_cmd_failure "dangling disabled marker fails closed" \
    "$FIXTURE/state-guard.sh"
rm -f "$ROOT/var/lib/noid-privacy/arp-hardening.disabled"

cat > "$ROOT/var/lib/noid-privacy/arp-hardening.state" <<'STATE_EOF'
ENABLED=1
WAN_IFACE=eth0
GATEWAY_IP=192.0.2.1
GATEWAY_MAC=02:00:00:00:00:11
LEARNED_AT=2026-07-27T00:00:00Z
STATE_EOF
chmod 0644 "$ROOT/var/lib/noid-privacy/arp-hardening.state"
assert_cmd_failure "enabled state without generated dispatcher fails closed" \
    "$FIXTURE/state-guard.sh"
sed -e 's|@@WAN_IFACE@@|eth0|g' \
    -e 's|@@GATEWAY_IP@@|192.0.2.1|g' \
    -e 's|@@GATEWAY_MAC@@|02:00:00:00:00:11|g' \
    "$ROOT/templates/90-arp-hardening.template" \
    > "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening"
cp "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening" \
    "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening"
chmod 0700 \
    "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening" \
    "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening"
ln -s no-wait.d/90-arp-hardening \
    "$ROOT/etc/NetworkManager/dispatcher.d/90-arp-hardening"
assert_cmd_success "complete enabled identity contract is accepted" \
    "$FIXTURE/state-guard.sh"
printf '\n# mismatched but syntactically valid transaction generation\n' \
    >> "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening"
assert_cmd_failure "awaited/no-wait generation mismatch fails closed" \
    "$FIXTURE/state-guard.sh"
sed -i '$d' "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening"
sed -i '$d' "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening"
assert_cmd_success "exact state-derived dispatcher is accepted again" \
    "$FIXTURE/state-guard.sh"
chmod 0666 "$ROOT/var/lib/noid-privacy/arp-hardening.state"
assert_cmd_failure "world-writable identity state fails closed" \
    "$FIXTURE/state-guard.sh"
chmod 0644 "$ROOT/var/lib/noid-privacy/arp-hardening.state"

sed -i 's/^ENABLED=1$/ENABLED=0/' \
    "$ROOT/var/lib/noid-privacy/arp-hardening.state"
rm -f "$ROOT/etc/NetworkManager/dispatcher.d/90-arp-hardening" \
    "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening" \
    "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening"
install -m 0600 /dev/null \
    "$ROOT/var/lib/noid-privacy/arp-hardening.disabled"
assert_cmd_success "disabled pin state retains a validated identity" \
    "$FIXTURE/state-guard.sh"
printf 'unexpected\n' > "$ROOT/var/lib/noid-privacy/arp-hardening.disabled"
chmod 0600 "$ROOT/var/lib/noid-privacy/arp-hardening.disabled"
assert_cmd_failure "non-empty opt-out marker fails closed" \
    "$FIXTURE/state-guard.sh"
chmod 0777 "$ROOT/var/lib/noid-privacy"
assert_cmd_failure "writable gateway-state parent fails closed" \
    "$FIXTURE/state-guard.sh"
chmod 0755 "$ROOT/var/lib/noid-privacy"

# ---------------------------------------------------------------------------
# A link going down must retire the global readiness marker only when that link
# owns the pinned identity. The marker is single and global, so retiring it for
# an unrelated NIC strands the still-active pinned link: readiness is
# republished only by a later up/dhcp4-change on some physical link, which
# stops NTS synchronisation and M06's WAN-strict endpoint resolution until the
# next DHCP renewal. Both dispatchers are driven for real here -- the generated
# one, which carries WAN_IFACE substituted at generation time, and the static
# initial-learn one, which reads it from the state file.
# ---------------------------------------------------------------------------
DOWN_ROOT="$FIXTURE/down"
mkdir -p "$DOWN_ROOT/var/lib/noid-privacy" "$DOWN_ROOT/run" \
    "$DOWN_ROOT/sys/class/net/eth0/device" \
    "$DOWN_ROOT/sys/class/net/eth1/device"
printf '%s\n' 'ENABLED=1' 'WAN_IFACE=eth0' 'GATEWAY_IP=192.0.2.1' \
    'GATEWAY_MAC=02:00:00:00:00:01' 'LEARNED_AT=2026-08-01T00:00:00Z' \
    > "$DOWN_ROOT/var/lib/noid-privacy/arp-hardening.state"

extract_heredoc "$KS_FILE" ARP_INITIAL_DISPATCHER_EOF \
    "$FIXTURE/initial-dispatcher.original" \
    || _fail "initial dispatcher extraction for the down-event fixture"

build_down_dispatchers() {
    # $1 = source .ks (allows a mutated copy), rebuilds both runnable fixtures
    local src="$1"
    extract_heredoc "$src" NM_TEMPLATE_EOF "$FIXTURE/gen.template"
    sed \
        -e "s|@@GATEWAY_IP@@|192.0.2.1|g" \
        -e "s|@@GATEWAY_MAC@@|02:00:00:00:00:01|g" \
        -e "s|@@WAN_IFACE@@|eth0|g" \
        -e "s|^NETWORK_READINESS=.*|NETWORK_READINESS=\"$MOCK_BIN/network-readiness\"|" \
        -e "s|^STATE_GUARD=.*|STATE_GUARD=\"$MOCK_BIN/state-guard\"|" \
        -e "s|^DISABLED=.*|DISABLED=\"$DOWN_ROOT/var/lib/noid-privacy/arp-hardening.disabled\"|" \
        -e "s|^ACTIVATION_MARKER_PREFIX=.*|ACTIVATION_MARKER_PREFIX=\"$DOWN_ROOT/run/arp-activation-ready\"|" \
        -e "s|/sys/class/net|$DOWN_ROOT/sys/class/net|g" \
        "$FIXTURE/gen.template" > "$FIXTURE/gen-dispatcher.sh"
    extract_heredoc "$src" ARP_INITIAL_DISPATCHER_EOF "$FIXTURE/init.template"
    sed \
        -e "s|^NETWORK_READINESS=.*|NETWORK_READINESS=$MOCK_BIN/network-readiness|" \
        -e "s|^STATE_GUARD=.*|STATE_GUARD=$MOCK_BIN/state-guard|" \
        -e "s|^STATE=.*|STATE=$DOWN_ROOT/var/lib/noid-privacy/arp-hardening.state|" \
        -e "s|^DISABLED=.*|DISABLED=$DOWN_ROOT/var/lib/noid-privacy/arp-hardening.disabled|" \
        "$FIXTURE/init.template" > "$FIXTURE/init-dispatcher.sh"
    chmod 0755 "$FIXTURE/gen-dispatcher.sh" "$FIXTURE/init-dispatcher.sh"
}

# Echoes how many times readiness was retired for one down event. The static
# dispatcher takes (iface, event); the generated one takes (IFACE, ACTION).
down_retirements() {
    # $1 = fixture script, $2 = interface, $3 = event
    : > "$NOID_TEST_READINESS_LOG"
    NOID_SYS_CLASS_NET="$DOWN_ROOT/sys/class/net" \
        "$1" "$2" "$3" >/dev/null 2>&1 || true
    grep -cFx offline "$NOID_TEST_READINESS_LOG" || true
}

build_down_dispatchers "$KS_FILE"
for down_event in pre-down down; do
    assert_eq 0 \
        "$(down_retirements "$FIXTURE/init-dispatcher.sh" eth1 "$down_event")" \
        "initial-learn dispatcher keeps readiness on '$down_event' of an unpinned link"
    assert_eq 1 \
        "$(down_retirements "$FIXTURE/init-dispatcher.sh" eth0 "$down_event")" \
        "initial-learn dispatcher retires readiness on '$down_event' of the pinned link"
    assert_eq 0 \
        "$(down_retirements "$FIXTURE/gen-dispatcher.sh" eth1 "$down_event")" \
        "generated dispatcher keeps readiness on '$down_event' of an unpinned link"
    assert_eq 1 \
        "$(down_retirements "$FIXTURE/gen-dispatcher.sh" eth0 "$down_event")" \
        "generated dispatcher retires readiness on '$down_event' of the pinned link"
done

# Fail-closed default: with no usable pinned identity there is no link to
# protect, so the initial-learn dispatcher must still retire.
mv "$DOWN_ROOT/var/lib/noid-privacy/arp-hardening.state" "$FIXTURE/state.saved"
assert_eq 1 "$(down_retirements "$FIXTURE/init-dispatcher.sh" eth1 down)" \
    "initial-learn dispatcher retires readiness while no identity is pinned"
printf '%s\n' 'ENABLED=1' 'WAN_IFACE=../../etc/passwd' \
    > "$DOWN_ROOT/var/lib/noid-privacy/arp-hardening.state"
assert_eq 1 "$(down_retirements "$FIXTURE/init-dispatcher.sh" eth1 down)" \
    "initial-learn dispatcher retires readiness on an implausible pinned name"
mv -f "$FIXTURE/state.saved" \
    "$DOWN_ROOT/var/lib/noid-privacy/arp-hardening.state"

# Discriminating control: restore the unconditional retirement both dispatchers
# used to carry and prove these assertions actually fail. Without this the
# checks above would also pass against the defect they exist to catch.
MUTATED_KS="$FIXTURE/mutated-04.ks"
python3 - "$KS_FILE" "$MUTATED_KS" <<'MUTATE_EOF'
import re, sys
src = open(sys.argv[1], encoding='utf-8').read()
# Static dispatcher: drop the pinned-identity lookup entirely.
static = re.search(
    r'\n        pinned_iface=""\n.*?\n        if \[ -z "\$pinned_iface" \].*?\n'
    r'            "\$NETWORK_READINESS" offline\n        fi\n',
    src, re.S)
# Generated dispatcher: drop the WAN_IFACE comparison.
generated = re.search(
    r'\n        if \[ "\$IFACE" = "\$WAN_IFACE" \]; then\n'
    r'            "\$NETWORK_READINESS" offline\n        fi\n',
    src, re.S)
if not static or not generated:
    sys.exit('mutation anchors not found -- the fixture no longer matches the source')
src = src.replace(static.group(0), '\n        "$NETWORK_READINESS" offline\n')
src = src.replace(generated.group(0), '\n        "$NETWORK_READINESS" offline\n')
open(sys.argv[2], 'w', encoding='utf-8').write(src)
MUTATE_EOF
build_down_dispatchers "$MUTATED_KS"
assert_eq 1 "$(down_retirements "$FIXTURE/init-dispatcher.sh" eth1 down)" \
    "control: unconditional initial-learn retirement is detectable"
assert_eq 1 "$(down_retirements "$FIXTURE/gen-dispatcher.sh" eth1 down)" \
    "control: unconditional generated retirement is detectable"
build_down_dispatchers "$KS_FILE"

# A recorded USB/dock interface may disappear before an operator asks for
# status. The report must remain complete and diagnostic instead of errexit
# aborting at the device-scoped neighbour query.
reset_old_state
rmdir "$ROOT/sys/class/net/eth0/device" "$ROOT/sys/class/net/eth0"
status_rc=0
"$FIXTURE/tool.sh" --silent status >"$LOG_DIR/status.out" \
    2>"$LOG_DIR/status.err" || status_rc=$?
assert_eq "1" "$status_rc" "status reports a vanished recorded interface"
assert_grep_fixed 'kernel pin:   unavailable [interface not present]' \
    "$LOG_DIR/status.out" "status names the missing interface"
assert_grep_fixed 'NM dispatch:  installed + state-guard validated' \
    "$LOG_DIR/status.out" "status completes after the missing-interface diagnosis"
mkdir -p "$ROOT/sys/class/net/eth0/device"

test_finish
