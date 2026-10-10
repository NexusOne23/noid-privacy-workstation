#!/bin/bash
# Behavioural regression fixture for M04's serialized ARP transition.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/04-arp-hardening.ks"
# The hardened image mounts /tmp noexec. Behaviour fixtures contain executable
# mock commands, so keep the private directory in an exec-capable scratch
# parent and remove it unconditionally on exit.
FIXTURE="$(make_exec_tmpdir 04-arp-transaction)"
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
export NOID_TEST_SYSTEMCTL_LOG="$LOG_DIR/systemctl.log"
export NOID_TEST_ARPING_LOG="$LOG_DIR/arping.log"
export NOID_TEST_ARPING_COUNT="$LOG_DIR/arping.count"
export NOID_TEST_READINESS_LOG="$LOG_DIR/readiness.log"
export NOID_TEST_SYSTEMCTL_LOG="$LOG_DIR/systemctl.log"
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
    [ -n "${NOID_TEST_NO_DEFAULT_ROUTE:-}" ] || \
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
        case "${NOID_TEST_IP_SHOW_MODE:-normal}" in
            fail) exit 95 ;;
            post-topology) [ ! -s "$NOID_TEST_TOPOLOGY_LOG" ] || exit 95 ;;
        esac
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
# Unit manager that cannot queue the hand-off: the generated dispatcher must
# then revalidate in-process exactly as before. No fixture may reach the real
# systemctl.
cat > "$MOCK_BIN/systemctl-unavailable" <<'MOCK_EOF'
#!/bin/bash
printf '%s\n' "$*" >> "$NOID_TEST_SYSTEMCTL_LOG"
exit 1
MOCK_EOF
cat > "$MOCK_BIN/network-readiness" <<'MOCK_EOF'
#!/bin/bash
[ "$#" -eq 1 ] || exit 2
case "$1" in
    offline|ready) printf '%s\n' "$1" >> "$NOID_TEST_READINESS_LOG" ;;
    *) exit 2 ;;
esac
MOCK_EOF
cat > "$MOCK_BIN/systemctl" <<'MOCK_EOF'
#!/bin/bash
printf '%s\n' "$*" >> "$NOID_TEST_SYSTEMCTL_LOG"
exit 0
MOCK_EOF
cat > "$MOCK_BIN/arp-tool-record" <<'MOCK_EOF'
#!/bin/bash
printf 'call %s\n' "$*" >> "$NOID_TEST_ARP_TOOL_LOG"
exit "${NOID_TEST_ARP_TOOL_RC:-0}"
MOCK_EOF
# Record every fsync target together with whether a rollback journal still
# existed at that moment, then perform the real sync.
cat > "$MOCK_BIN/sync" <<'MOCK_EOF'
#!/bin/bash
if [ -n "${NOID_TEST_SYNC_LOG:-}" ]; then
    journal=absent
    for candidate in "$NOID_TEST_SYNC_STATE_DIR"/.arp-transaction.*/journal; do
        [ ! -e "$candidate" ] || journal=present
    done
    for argument in "$@"; do
        [ "$argument" = -- ] || \
            printf '%s journal=%s\n' "$argument" "$journal" >> "$NOID_TEST_SYNC_LOG"
    done
fi
exec /usr/bin/sync "$@"
MOCK_EOF
cat > "$MOCK_BIN/find" <<'MOCK_EOF'
#!/bin/bash
[ "${NOID_TEST_FIND_FAILURE:-}" != empty ] || exit 74
/usr/bin/find "$@" || exit "$?"
[ "${NOID_TEST_FIND_FAILURE:-}" != partial ] || exit 74
MOCK_EOF
chmod 0755 "$MOCK_BIN"/*

export PATH="$MOCK_BIN:/usr/bin:/usr/sbin"
export NOID_TEST_SYNC_STATE_DIR="$ROOT/var/lib/noid-privacy"
# Every restored regular file must be fsynced while its journal still exists.
assert_restored_files_synced() {
    local description=$1 path
    for path in \
        "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening" \
        "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening" \
        "$ROOT/var/lib/noid-privacy/arp-hardening.state" \
        "$ROOT/var/lib/noid-privacy/arp-hardening.disabled"; do
        [ -f "$path" ] && [ ! -L "$path" ] || continue
        assert_grep_fixed "$path journal=present" "$NOID_TEST_SYNC_LOG" \
            "$description: ${path#"$ROOT"/} is fsynced before its journal is retired"
    done
}
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
    : > "$NOID_TEST_SYSTEMCTL_LOG"
    : > "$NOID_TEST_GUARD_COUNT_FILE"
    unset NOID_TEST_IP_FAIL_REPLACE_IFACE || true
    unset NOID_TEST_IP_SHOW_MODE || true
    unset NOID_TEST_ARPING_MODE NOID_TEST_ARPING_POPULATE || true
    export NOID_TEST_GUARD_MODE=success
    export NOID_TEST_TOPOLOGY_MODE=success
}

test_start "04-arp-transaction-fixture"

# Invalid arguments must stop before any readiness or neighbour transition.
arp_usage_rejected() {
    local rc=0
    reset_old_state
    "$FIXTURE/tool.sh" "$@" >"$LOG_DIR/argv.out" \
        2>"$LOG_DIR/argv.err" || rc=$?
    [ "$rc" -eq 2 ] && [ ! -s "$NOID_TEST_READINESS_LOG" ] \
        && [ ! -s "$NOID_TEST_IP_LOG" ] \
        && [ ! -s "$NOID_TEST_GUARD_COUNT_FILE" ]
}
for command in learn status disable refresh help; do
    assert_cmd_success "$command rejects an extra empty argument before acting" \
        arp_usage_rejected "$command" ''
    assert_cmd_success "--silent $command rejects combined help before acting" \
        arp_usage_rejected --silent "$command" --help
done
assert_cmd_success "explicit empty command is rejected before acting" \
    arp_usage_rejected ''
assert_cmd_success "unknown command is rejected before acting" \
    arp_usage_rejected --unknown
assert_cmd_success "no arguments still display help" "$FIXTURE/tool.sh"
assert_cmd_success "explicit help remains available" "$FIXTURE/tool.sh" --help

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

# A converged refresh keeps the generated dispatcher inodes: the post-DHCP
# reconciliation runs routinely and Fedora's AIDE rules flag replacements.
arp_dispatcher_inodes() {
    stat -c '%i' \
        "$ROOT/etc/NetworkManager/dispatcher.d/90-arp-hardening" \
        "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening" \
        "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening" \
        | tr '\n' ' '
}
arp_inodes_before=$(arp_dispatcher_inodes)
if NOID_ARP_IFACE=eth0 NOID_ARP_GATEWAY_IP=192.0.2.1 \
        "$FIXTURE/tool.sh" --silent refresh >/dev/null 2>&1; then
    assert_eq "$arp_inodes_before" "$(arp_dispatcher_inodes)" \
        "converged refresh keeps the generated dispatcher inodes"
else
    _fail "converged refresh keeps the generated dispatcher inodes"
fi
printf '# drift\n' >> "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening"
if NOID_ARP_IFACE=eth0 NOID_ARP_GATEWAY_IP=192.0.2.1 \
        "$FIXTURE/tool.sh" --silent refresh >/dev/null 2>&1 \
   && cmp -s "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening" \
        "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening"; then
    _pass "a differing awaited dispatcher copy is republished once the (mocked) state guard accepts the transaction"
else
    _fail "a differing awaited dispatcher copy is republished once the (mocked) state guard accepts the transaction"
fi
unset -f arp_dispatcher_inodes
unset arp_inodes_before

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

# An explicit disable is durable: refresh must refuse instead of silently
# enabling the pin again. `learn` remains the deliberate way back.
disabled_state_sha=$(sha256sum "$ROOT/var/lib/noid-privacy/arp-hardening.state")
: > "$NOID_TEST_ARPING_COUNT"
refresh_disabled_rc=0
NOID_ARP_IFACE=eth0 NOID_ARP_GATEWAY_IP=192.0.2.1 \
    "$FIXTURE/tool.sh" --silent refresh >/dev/null \
    2>"$LOG_DIR/refresh-disabled.err" || refresh_disabled_rc=$?
assert_eq 1 "$refresh_disabled_rc" "refresh refuses a durably disabled pin"
assert_grep_fixed 'refresh does not re-enable it' "$LOG_DIR/refresh-disabled.err" \
    "refused refresh names the deliberate re-enable path"
assert_eq "$disabled_state_sha" \
    "$(sha256sum "$ROOT/var/lib/noid-privacy/arp-hardening.state")" \
    "refused refresh leaves the disabled identity state unchanged"
assert_cmd_success "refused refresh keeps the opt-out marker" \
    test -f "$ROOT/var/lib/noid-privacy/arp-hardening.disabled"
assert_eq "" "$(cat "$NOID_TEST_ARPING_COUNT")" \
    "refused refresh performs no gateway observation"

# Failure to read neighbours is not proof that a disabled pin is absent.
assert_cmd_success "disabled status accepts a successful empty neighbour query" \
    "$FIXTURE/tool.sh" --silent status
assert_cmd_failure "disabled status preserves a failed neighbour query" \
    env NOID_TEST_IP_SHOW_MODE=fail "$FIXTURE/tool.sh" --silent status

reset_old_state
assert_cmd_failure "disable rolls back when its final neighbour query fails" \
    env NOID_TEST_IP_SHOW_MODE=post-topology "$FIXTURE/tool.sh" --silent disable
assert_grep_fixed 'ENABLED=1' \
    "$ROOT/var/lib/noid-privacy/arp-hardening.state" \
    "failed final query restores enabled state"
assert_grep_fixed '192.0.2.1 dev eth0 lladdr 02:00:00:00:00:11 PERMANENT' \
    "$NOID_TEST_NEIGHBORS" "failed final query restores the prior pin"
assert_not_grep '^ready$' "$NOID_TEST_READINESS_LOG" \
    "failed final query cannot publish readiness"

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
export NOID_TEST_SYNC_LOG="$LOG_DIR/sync-rollback.log"
: > "$NOID_TEST_SYNC_LOG"
if NOID_ARP_IFACE=eth0 NOID_ARP_GATEWAY_IP=192.0.2.1 \
        "$FIXTURE/tool.sh" --silent refresh >/dev/null 2>&1; then
    interrupt_rc=0
else
    interrupt_rc=$?
fi
unset NOID_TEST_SYNC_LOG
assert_eq "143" "$interrupt_rc" "TERM during post-publication validation is visible"
NOID_TEST_SYNC_LOG="$LOG_DIR/sync-rollback.log" \
    assert_restored_files_synced "EXIT-trap rollback"
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
# active up/dhcp4-change events additionally disconnect their exact interface
# only when the gateway identity is contested (tool exit code 2).
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
    -e "s|/usr/bin/systemctl|$MOCK_BIN/systemctl-unavailable|g" \
    "$FIXTURE/dispatcher.template" > "$FIXTURE/dispatcher.sh"
chmod 0755 "$FIXTURE/dispatcher.sh"
assert_not_grep_fixed '/usr/bin/systemctl' "$FIXTURE/dispatcher.sh" \
    "dispatcher fixture cannot reach the real unit manager"
: > "$NOID_TEST_SYSTEMCTL_LOG"
if IP4_GATEWAY=192.0.2.2 "$FIXTURE/dispatcher.sh" eth0 pre-up >/dev/null 2>&1; then
    _fail "awaited pre-up propagates transactional refresh failure"
else
    _pass "awaited pre-up propagates transactional refresh failure"
fi
assert_eq "" "$(cat "$NOID_TEST_NMCLI_LOG")" \
    "pre-up failure fails the event without disconnecting the device"
# A transient failure must still fail the event -- and must leave the link
# alone. This is the ordinary case: DHCP not settled, no arping reply yet, a
# helper that could not run. Disconnecting here would strand the owner on
# hardware that is merely slow, which the compatibility document promises
# cannot happen.
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

# A failed `up` must not turn every later DHCP renewal of the same activation
# into a deferred no-op: `up` marks the activation before its own refresh, so
# the renewal performs the complete transaction. DHCP actions queued before
# that `up` (after pre-up cleared the marker) are still coalesced and must not
# retire readiness.
sed \
    -e "s|ARP_TOOL=\"$MOCK_BIN/arp-tool-fail\"|ARP_TOOL=\"$MOCK_BIN/arp-tool-record\"|" \
    -e 's|chown root:root "\$staged"|:|' \
    "$FIXTURE/dispatcher.sh" > "$FIXTURE/dispatcher-activation.sh"
chmod 0755 "$FIXTURE/dispatcher-activation.sh"
activation_uuid=11111111-2222-4333-8444-555555555555
: > "$NOID_TEST_ARP_TOOL_LOG"
assert_cmd_failure "a transient up refresh failure is reported" \
    env CONNECTION_UUID="$activation_uuid" NOID_TEST_ARP_TOOL_RC=73 \
        IP4_GATEWAY=192.0.2.1 "$FIXTURE/dispatcher-activation.sh" eth0 up
assert_cmd_success "a DHCP renewal after a failed up revalidates the gateway" \
    env CONNECTION_UUID="$activation_uuid" NOID_TEST_ARP_TOOL_RC=0 \
        IP4_GATEWAY=192.0.2.1 "$FIXTURE/dispatcher-activation.sh" eth0 dhcp4-change
assert_eq 2 "$(grep -c '^call ' "$NOID_TEST_ARP_TOOL_LOG")" \
    "the renewal ran a complete transaction instead of being deferred"
assert_cmd_success "pre-up restores the pin and clears the activation marker" \
    env CONNECTION_UUID="$activation_uuid" IP4_GATEWAY=192.0.2.1 \
        "$FIXTURE/dispatcher-activation.sh" eth0 pre-up
: > "$NOID_TEST_ARP_TOOL_LOG"
: > "$NOID_TEST_READINESS_LOG"
assert_cmd_success "a DHCP action queued before up is coalesced" \
    env CONNECTION_UUID="$activation_uuid" IP4_GATEWAY=192.0.2.1 \
        "$FIXTURE/dispatcher-activation.sh" eth0 dhcp4-change
assert_eq "" "$(cat "$NOID_TEST_ARP_TOOL_LOG")" \
    "a coalesced early DHCP action runs no transaction"
assert_eq "" "$(cat "$NOID_TEST_READINESS_LOG")" \
    "a coalesced early DHCP action does not retire readiness"
assert_cmd_success "post-activation events first tried the per-event unit" \
    grep -Eq -- '^--no-ask-password start --no-block noid-arp-revalidate@[0-9]{1,20}-[0-9]{1,10}\.service$' \
    "$NOID_TEST_SYSTEMCTL_LOG"
assert_eq "0" "$(grep -cvE '^--no-ask-password start --no-block noid-arp-revalidate@[0-9]{1,20}-[0-9]{1,10}\.service$' "$NOID_TEST_SYSTEMCTL_LOG")" \
    "the dispatcher issues no other unit-manager command"
assert_eq "0" "$(find "$ROOT/run/noid-privacy/arp-revalidate" -type f 2>/dev/null | wc -l)" \
    "an unavailable hand-off leaves no request behind"

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
# device route and invoke learning. A failed post-DHCP call fails the event;
# only a contested identity disconnects.
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
chmod 0755 "$DOWN_ROOT/run"
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
        -e "s|^STATE=.*|STATE=\"$DOWN_ROOT/var/lib/noid-privacy/arp-hardening.state\"|" \
        -e "s|^DISABLED=.*|DISABLED=\"$DOWN_ROOT/var/lib/noid-privacy/arp-hardening.disabled\"|" \
        -e "s|/run/noid-privacy|$DOWN_ROOT/run|g" \
        -e "s|0:0:|$fixture_uid:$fixture_gid:|g" \
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
# Generated dispatcher: drop the comparison with the current validated pin.
generated = re.search(
    r'\n        \[ "\$IFACE" = "\$current_pinned_iface" \] \|\| exit 0\n',
    src, re.S)
if not static or not generated:
    sys.exit('mutation anchors not found -- the fixture no longer matches the source')
src = src.replace(static.group(0), '\n        "$NETWORK_READINESS" offline\n')
src = src.replace(generated.group(0), '\n')
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

# During failover the old hardware can be gone permanently. A failure on the
# remaining link must still restore the exact files without trying to recreate
# a neighbour on the nonexistent link or stopping all of NetworkManager.
cp "$ROOT/var/lib/noid-privacy/arp-hardening.state" "$FIXTURE/prior-missing-state"
: > "$NOID_TEST_NEIGHBORS"
export NOID_TEST_IP_FAIL_REPLACE_IFACE=eth0
export NOID_TEST_TOPOLOGY_MODE=fail
failover_rc=0
NOID_ARP_IFACE=eth1 NOID_ARP_GATEWAY_IP=192.0.2.1 \
    "$FIXTURE/tool.sh" --silent refresh >"$LOG_DIR/failover.out" \
    2>"$LOG_DIR/failover.err" || failover_rc=$?
assert_eq 1 "$failover_rc" "failed remaining-link topology is reported"
assert_cmd_success "failed failover restores exact prior state bytes" \
    cmp -s "$FIXTURE/prior-missing-state" "$ROOT/var/lib/noid-privacy/arp-hardening.state"
assert_eq "" "$(cat "$NOID_TEST_SYSTEMCTL_LOG")" \
    "vanished old interface does not stop NetworkManager during rollback"
assert_eq "" "$(find "$ROOT/var/lib/noid-privacy" -maxdepth 1 -name '.arp-transaction.*' -print)" \
    "rollback with vanished old interface retires its completed journal"
unset NOID_TEST_IP_FAIL_REPLACE_IFACE
export NOID_TEST_TOPOLOGY_MODE=success
mkdir -p "$ROOT/sys/class/net/eth0/device"

# Positive control for the safety boundary: a present link whose old pin
# cannot actually be restored must retain the journal and stop activation.
reset_old_state
: > "$NOID_TEST_NEIGHBORS"
export NOID_TEST_IP_FAIL_REPLACE_IFACE=eth0
export NOID_TEST_TOPOLOGY_MODE=fail
present_rc=0
NOID_ARP_IFACE=eth1 NOID_ARP_GATEWAY_IP=192.0.2.1 \
    "$FIXTURE/tool.sh" --silent refresh >"$LOG_DIR/failover-present.out" \
    2>"$LOG_DIR/failover-present.err" || present_rc=$?
assert_eq 1 "$present_rc" "present-link rollback failure remains an error"
assert_grep_fixed '--no-block stop NetworkManager.service' "$NOID_TEST_SYSTEMCTL_LOG" \
    "present-link pin restoration failure retains the fail-closed stop"
assert_eq 1 "$(find "$ROOT/var/lib/noid-privacy" -maxdepth 1 -name '.arp-transaction.*' | wc -l)" \
    "present-link rollback failure retains one recovery journal"
unset NOID_TEST_IP_FAIL_REPLACE_IFACE
export NOID_TEST_TOPOLOGY_MODE=success
assert_cmd_success "native recovery completes the retained control journal" \
    "$FIXTURE/tool.sh" --silent recover

# Two real processes race the production first-lock creation boundary.
cat > "$FIXTURE/lock-race.py" <<'ARP_LOCK_RACE_EOF'
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

source = Path(sys.argv[1]).read_text()
body = source.split('acquire_transaction_lock() {\n', 1)[1].split('\n}\n', 1)[0]
# Synchronize the two callers after both observed an absent lock. All native
# creation/open/flock/metadata operations remain the production source bytes.
head, creation = body.split('    lock_path=', 1)
creation = creation.replace('\n    else\n', '\n    else\n        creation_barrier\n', 1)
body = head + '    lock_path=' + creation
with tempfile.TemporaryDirectory(prefix='arp-lock-race-', dir=sys.argv[2]) as directory:
    root = Path(directory)
    state = root/'state'
    state.mkdir(mode=0o755)
    state.chmod(0o755)
    script = root/'actor.sh'
    script.write_text('''#!/bin/bash
set -euo pipefail
umask 077
STATE_DIR=$1
FIXTURE=$2
ROLE=$3
EXPECTED_OWNER=$(id -u)
EXPECTED_GROUP=$(id -g)
TX_LOCK_FD=""
err() { printf '%s\\n' "$*" >&2; }
creation_barrier() {
    : > "$FIXTURE/creation.$ROLE"
    while [ ! -e "$FIXTURE/permit.$ROLE" ]; do /usr/bin/sleep 0.01; done
}
acquire_transaction_lock() {
''' + body + '''
}
acquire_transaction_lock
: > "$FIXTURE/entered.$ROLE"
while [ ! -e "$FIXTURE/release.$ROLE" ]; do /usr/bin/sleep 0.01; done
''')
    processes = []
    def wait_file(name):
        deadline = time.monotonic() + 3
        actor = processes[0 if name.endswith('.one') else 1]
        while not (root/name).exists():
            if time.monotonic() > deadline or actor.poll() is not None:
                for p in processes:
                    if p.poll() is not None:
                        sys.stderr.write(p.stderr.read().decode())
                raise RuntimeError('actor did not reach '+name)
            time.sleep(.01)
    try:
        for role in ('one', 'two'):
            processes.append(subprocess.Popen(['bash', str(script), str(state), str(root), role],
                                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE))
            wait_file('creation.'+role)
        (root/'permit.one').touch()
        wait_file('entered.one')
        inode = (state/'.arp-hardening.lock').stat().st_ino
        (root/'permit.two').touch()
        time.sleep(.25)
        result = {'overlap': (root/'entered.two').exists(),
                  'same_inode': (state/'.arp-hardening.lock').stat().st_ino == inode}
        (root/'release.one').touch()
        wait_file('entered.two')
        (root/'release.two').touch()
        result['exit'] = [p.wait(timeout=3) for p in processes]
        result['stderr_empty'] = all(not p.stderr.read() for p in processes)
        print(json.dumps(result))
        assert result == {'overlap': False, 'same_inode': True,
                          'exit': [0, 0], 'stderr_empty': True}, result
    finally:
        for p in processes:
            if p.poll() is None:
                p.terminate()
            p.wait(timeout=3)
            p.stderr.close()
ARP_LOCK_RACE_EOF
assert_cmd_success "concurrent first-time ARP transactions share one lock inode" \
    env PATH=/usr/bin:/usr/sbin python3 "$FIXTURE/lock-race.py" "$KS_FILE" "$FIXTURE"


# ---------------------------------------------------------------------------
# Crash recovery. A transaction killed with SIGKILL runs no EXIT trap; its
# fsynced journal must let `recover` (run by the state-guard unit before
# NetworkManager) restore the exact prior file set. The real boot guard proves
# both the inconsistent intermediate state and the repaired result.
# ---------------------------------------------------------------------------
seed_consistent_state() {
    reset_old_state
    rm -f "$ROOT/etc/NetworkManager/dispatcher.d/90-arp-hardening" \
        "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening" \
        "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening"
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
}
seed_empty_state() {
    reset_old_state
    rm -f "$ROOT/etc/NetworkManager/dispatcher.d/90-arp-hardening" \
        "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening" \
        "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening" \
        "$ROOT/var/lib/noid-privacy/arp-hardening.state"
    : > "$NOID_TEST_NEIGHBORS"
}
managed_snapshot() {
    local path
    for path in \
        "$ROOT/etc/NetworkManager/dispatcher.d/90-arp-hardening" \
        "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening" \
        "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening" \
        "$ROOT/var/lib/noid-privacy/arp-hardening.state" \
        "$ROOT/var/lib/noid-privacy/arp-hardening.disabled"; do
        if [ -L "$path" ]; then
            printf 'link %s %s\n' "$path" "$(readlink "$path")"
        elif [ -e "$path" ]; then
            printf 'file %s %s %s\n' "$path" "$(stat -c %a "$path")" \
                "$(sha256sum < "$path" | cut -d' ' -f1)"
        else
            printf 'absent %s\n' "$path"
        fi
    done
}
transaction_dirs() {
    find "$ROOT/var/lib/noid-privacy" -maxdepth 1 -name '.arp-transaction.*' | wc -l
}
# Build a copy that SIGKILLs itself right after one exact publication step.
killer_after() {
    local anchor=$1 output=$2
    python3 - "$FIXTURE/tool.sh" "$output" "$anchor" <<'KILLER_EOF'
import sys
source = open(sys.argv[1], encoding="utf-8").read()
anchor = sys.argv[3] + "\n"
if source.count(anchor) != 1:
    raise SystemExit("kill anchor missing or ambiguous: " + sys.argv[3])
source = source.replace(anchor, anchor + '    kill -KILL "$$"\n', 1)
open(sys.argv[2], "w", encoding="utf-8").write(source)
KILLER_EOF
    chmod 0755 "$output"
}
killer_after '    atomic_publish "$TX_DIR/90-arp-hardening" "$NM_DISPATCHER_PREUP" 0700' \
    "$FIXTURE/tool-kill-after-preup.sh"
killer_after '    atomic_publish "$TX_DIR/90-arp-hardening" "$NM_DISPATCHER_NOWAIT" 0700' \
    "$FIXTURE/tool-kill-after-nowait.sh"
killer_after '    atomic_publish "$TX_DIR/disabled" "$DISABLED_FILE" 0600' \
    "$FIXTURE/tool-kill-after-marker.sh"
killer_after '        ip neigh del "$TX_OLD_GATEWAY_IP" dev "$TX_OLD_IFACE"' \
    "$FIXTURE/tool-kill-after-unpin.sh"

crash_case() {
    # $1 = description, $2 = killer copy, remaining = tool arguments
    local description=$1 killer=$2 before killed_rc=0
    shift 2
    before=$(managed_snapshot)
    NOID_ARP_IFACE=eth0 NOID_ARP_GATEWAY_IP=192.0.2.1 \
        "$killer" "$@" >/dev/null 2>&1 || killed_rc=$?
    assert_eq 137 "$killed_rc" "$description: transaction was killed mid-publication"
    assert_cmd_failure "$description: interrupted file set fails the boot guard" \
        "$FIXTURE/state-guard.sh"
    assert_eq 1 "$(transaction_dirs)" "$description: fsynced journal survives the kill"
    export NOID_TEST_SYNC_LOG="$LOG_DIR/sync-recover.log"
    : > "$NOID_TEST_SYNC_LOG"
    assert_cmd_success "$description: recover rolls the journal back" \
        "$FIXTURE/tool.sh" --silent recover
    assert_restored_files_synced "$description: recover"
    unset NOID_TEST_SYNC_LOG
    assert_eq "$before" "$(managed_snapshot)" \
        "$description: recovery restores the exact prior file set"
    assert_eq 0 "$(transaction_dirs)" "$description: recovery retires the journal"
    assert_cmd_success "$description: recovered file set passes the boot guard" \
        "$FIXTURE/state-guard.sh"
}

seed_empty_state
crash_case "first learn" "$FIXTURE/tool-kill-after-preup.sh" --silent learn
seed_consistent_state
assert_cmd_success "seeded consistent identity passes the boot guard" \
    "$FIXTURE/state-guard.sh"
crash_case "refresh" "$FIXTURE/tool-kill-after-nowait.sh" --silent refresh
seed_consistent_state
crash_case "disable" "$FIXTURE/tool-kill-after-marker.sh" --silent disable

# The journal covers files only. A refresh killed after re-pinning and a
# disable killed after unpinning both leave the kernel pin changed; recover
# restores the recorded pin from the restored state while its gateway is the
# current default route, exactly like the EXIT-trap rollback.
recorded_pin='192.0.2.1 dev eth0 lladdr 02:00:00:00:00:11 PERMANENT'
for pin_case in refresh:tool-kill-after-nowait.sh disable:tool-kill-after-unpin.sh; do
    pin_command=${pin_case%%:*}
    seed_consistent_state
    NOID_ARP_IFACE=eth0 NOID_ARP_GATEWAY_IP=192.0.2.1 \
        "$FIXTURE/${pin_case#*:}" --silent "$pin_command" >/dev/null 2>&1 || true
    assert_eq 1 "$(transaction_dirs)" "killed $pin_command leaves its journal"
    assert_not_grep "$recorded_pin" "$NOID_TEST_NEIGHBORS" \
        "killed $pin_command left the recorded kernel pin changed"
    assert_cmd_success "recover after a killed $pin_command succeeds" \
        "$FIXTURE/tool.sh" --silent recover
    assert_grep_fixed "$recorded_pin" "$NOID_TEST_NEIGHBORS" \
        "recover restores the recorded permanent pin after a killed $pin_command"
    assert_eq 1 "$(grep -c '^192.0.2.1 dev eth0 ' "$NOID_TEST_NEIGHBORS" || true)" \
        "recover leaves exactly one gateway neighbour after a killed $pin_command"
    assert_cmd_success "recovered $pin_command state passes the boot guard" \
        "$FIXTURE/state-guard.sh"
done
# Without that default route -- the boot path before NetworkManager -- recover
# restores the files only and leaves pinning to the link's activation.
seed_consistent_state
NOID_ARP_IFACE=eth0 NOID_ARP_GATEWAY_IP=192.0.2.1 \
    "$FIXTURE/tool-kill-after-unpin.sh" --silent disable >/dev/null 2>&1 || true
assert_cmd_success "recover without the recorded default route succeeds" \
    env NOID_TEST_NO_DEFAULT_ROUTE=1 "$FIXTURE/tool.sh" --silent recover
assert_not_grep "$recorded_pin" "$NOID_TEST_NEIGHBORS" \
    "recover pins nothing while the recorded gateway is not the default route"
assert_eq 0 "$(transaction_dirs)" "recover without the default route still retires the journal"

# An unreadable inventory is not an empty inventory, including a producer that
# emits a valid transaction path before failing. Neither case may restore or
# retire any journal from that incomplete listing.
for inventory_failure in empty partial; do
    seed_consistent_state
    NOID_ARP_IFACE=eth0 NOID_ARP_GATEWAY_IP=192.0.2.1 \
        "$FIXTURE/tool-kill-after-unpin.sh" --silent disable >/dev/null 2>&1 || true
    before=$(managed_snapshot)
    assert_cmd_status 1 "recover rejects $inventory_failure journal inventory failure" \
        env NOID_TEST_FIND_FAILURE="$inventory_failure" \
            "$FIXTURE/tool.sh" --silent recover
    assert_eq "$before" "$(managed_snapshot)" \
        "failed $inventory_failure inventory leaves managed files unchanged"
    assert_eq 1 "$(transaction_dirs)" \
        "failed $inventory_failure inventory preserves the recovery journal"
    assert_cmd_success "recovery succeeds after $inventory_failure inventory read recovers" \
        "$FIXTURE/tool.sh" --silent recover
    assert_grep_fixed "$recorded_pin" "$NOID_TEST_NEIGHBORS" \
        "successful $inventory_failure inventory retry restores the kernel pin"
done

# A transient kernel error must leave the recovery journal available. Otherwise
# the second invocation skips restoration and reports success with no pin.
seed_consistent_state
NOID_ARP_IFACE=eth0 NOID_ARP_GATEWAY_IP=192.0.2.1 \
    "$FIXTURE/tool-kill-after-unpin.sh" --silent disable >/dev/null 2>&1 || true
assert_cmd_status 1 "recover reports a failed kernel-pin restore" \
    env NOID_TEST_IP_FAIL_REPLACE_IFACE=eth0 "$FIXTURE/tool.sh" --silent recover
assert_eq 1 "$(transaction_dirs)" "failed kernel restore preserves its recovery journal"
assert_not_grep_fixed "$recorded_pin" "$NOID_TEST_NEIGHBORS" \
    "fault injection actually prevented the kernel-pin restore"
assert_cmd_success "recovery can retry a transient kernel-pin failure" \
    "$FIXTURE/tool.sh" --silent recover
assert_grep_fixed "$recorded_pin" "$NOID_TEST_NEIGHBORS" \
    "successful recovery retry restores the kernel pin"
assert_eq 0 "$(transaction_dirs)" "successful kernel restore retires its journal"

# The next ordinary transaction also rolls a leftover journal back first.
seed_consistent_state
NOID_ARP_IFACE=eth0 NOID_ARP_GATEWAY_IP=192.0.2.1 \
    "$FIXTURE/tool-kill-after-nowait.sh" --silent refresh >/dev/null 2>&1 || true
assert_cmd_success "refresh after an interrupted refresh recovers and commits" \
    env NOID_ARP_IFACE=eth0 NOID_ARP_GATEWAY_IP=192.0.2.1 \
        "$FIXTURE/tool.sh" --silent refresh
assert_eq 0 "$(transaction_dirs)" "follow-up transaction leaves no journal"
assert_cmd_success "follow-up transaction publishes a consistent identity" \
    "$FIXTURE/state-guard.sh"

# A transaction directory without a journal changed nothing and is discarded.
seed_consistent_state
before=$(managed_snapshot)
mkdir -m 0700 "$ROOT/var/lib/noid-privacy/.arp-transaction.nojournal"
printf 'stale backup\n' > "$ROOT/var/lib/noid-privacy/.arp-transaction.nojournal/path.3"
assert_cmd_success "recover discards a journal-less transaction directory" \
    "$FIXTURE/tool.sh" --silent recover
assert_eq "$before" "$(managed_snapshot)" \
    "journal-less directory restores nothing"
assert_eq 0 "$(transaction_dirs)" "journal-less directory is removed"

# A journal naming any path outside the closed managed set is rejected and
# restores nothing.
seed_consistent_state
before=$(managed_snapshot)
foreign_tx="$ROOT/var/lib/noid-privacy/.arp-transaction.foreign"
mkdir -m 0700 "$foreign_tx"
printf 'do-not-touch\n' > "$FIXTURE/foreign-restore-target"
printf 'replacement\n' > "$foreign_tx/path.0"
{
    printf '%s\n' NOID_ARP_TX_JOURNAL_V1
    printf '0\tPRESENT\t%s\n' "$FIXTURE/foreign-restore-target"
    printf '%s\tABSENT\t%s\n' 1 "$ROOT/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening" \
        2 "$ROOT/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening" \
        3 "$ROOT/var/lib/noid-privacy/arp-hardening.state" \
        4 "$ROOT/var/lib/noid-privacy/arp-hardening.disabled"
    printf '%s\n' COMPLETE
} > "$foreign_tx/journal"
assert_cmd_failure "recover rejects a journal with a foreign path" \
    "$FIXTURE/tool.sh" --silent recover
assert_eq 'do-not-touch' "$(cat "$FIXTURE/foreign-restore-target")" \
    "foreign journal path is never written"
assert_eq "$before" "$(managed_snapshot)" "rejected journal changes no managed file"
rm -rf "$foreign_tx"

# `reset` is the confirmed recovery for a state no journal can repair.
seed_consistent_state
rm -f "$ROOT/var/lib/noid-privacy/arp-hardening.state"
assert_cmd_failure "damaged identity fails the boot guard" "$FIXTURE/state-guard.sh"
before=$(managed_snapshot)
assert_cmd_failure "reset without the exact confirmation refuses" \
    bash -c 'printf "%s\n" yes | "$1" --silent reset' _ "$FIXTURE/tool.sh"
assert_eq "$before" "$(managed_snapshot)" "unconfirmed reset changes nothing"
assert_cmd_success "confirmed reset forgets the damaged identity" \
    bash -c 'printf "%s\n" RESET | "$1" --silent reset' _ "$FIXTURE/tool.sh"
assert_cmd_success "reset returns to the empty first-learn lifecycle" \
    "$FIXTURE/state-guard.sh"
seed_consistent_state
install -m 0600 /dev/null "$ROOT/var/lib/noid-privacy/arp-hardening.disabled"
assert_cmd_success "confirmed reset also clears a consistent identity and opt-out" \
    bash -c 'printf "%s\n" RESET | "$1" --silent reset' _ "$FIXTURE/tool.sh"
assert_not_grep '192\.0\.2\.1 dev eth0 ' "$NOID_TEST_NEIGHBORS" \
    "reset removes the exact recorded permanent pin"
assert_grep_fixed '192.0.2.1 dev eth1 lladdr 02:00:00:00:01:11 PERMANENT' \
    "$NOID_TEST_NEIGHBORS" "reset leaves an unrelated interface's neighbour alone"
assert_cmd_success "reset removes the opt-out marker" \
    test ! -e "$ROOT/var/lib/noid-privacy/arp-hardening.disabled"
assert_cmd_success "reset leaves the empty lifecycle valid" "$FIXTURE/state-guard.sh"

test_finish
