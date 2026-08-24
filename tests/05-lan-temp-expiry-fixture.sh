#!/bin/bash
# Behavioural regression fixture for M05's durable temporary-LAN expiry state.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/05-lan-isolation.ks"
FIXTURE="$(mktemp -d "$PROJECT_ROOT/.test-05-expiry.XXXXXX")"
trap 'rm -rf "$FIXTURE"' EXIT

extract_heredoc "$KS_FILE" LAN_ALLOW_EOF "$FIXTURE/noid-lan-allow"
awk '/^# === ACTION DISPATCH ===/ {exit} {print}' \
    "$FIXTURE/noid-lan-allow" > "$FIXTURE/functions.sh"

export NOID_LAN_EXCEPTION_STATE_DIR="$FIXTURE/exception-state"
export NOID_LAN_PEER_STATE_DIR="$FIXTURE/peer-state"
mkdir -p "$FIXTURE/locks"
chmod 0755 "$FIXTURE/locks"
export NOID_LAN_EXCEPTION_LOCK="$FIXTURE/locks/exception.lock"
export NOID_LAN_EXCEPTION_SCHEDULE_FILE="$FIXTURE/locks/lan-expiry-schedule"
NOID_LAN_STATE_UID=$(id -u)
NOID_LAN_STATE_GID=$(id -g)
export NOID_LAN_STATE_UID NOID_LAN_STATE_GID
printf '%s\n' '#!/bin/bash' 'exit 0' > "$FIXTURE/topology-refresh"
chmod 0755 "$FIXTURE/topology-refresh"
export NOID_LAN_TOPOLOGY_REFRESH="$FIXTURE/topology-refresh"
export NOID_LAN_XDP_CONTROLLER=/bin/true
export NOID_LAN_XDP_HEALTH_FILE="$FIXTURE/xdp-health"
export NOID_TEST_RULES="$FIXTURE/rules"
export NOID_TEST_SYSTEMCTL_LOG="$FIXTURE/systemctl.log"
export NOID_TEST_FIREWALL_MODE=normal
printf '%s\n' 'STATE=ACTIVE' > "$NOID_LAN_XDP_HEALTH_FILE"
: > "$NOID_TEST_RULES"
: > "$NOID_TEST_SYSTEMCTL_LOG"

# shellcheck disable=SC2317,SC2329 # production helper calls this exported double.
function firewall-cmd() {
    local arg rule
    case "$*" in
        '--permanent --policy=block-lan-out --list-rich-rules'|\
        '--policy=block-lan-out --list-rich-rules')
            cat "$NOID_TEST_RULES"
            ;;
        '--permanent --zone=drop --list-rich-rules'|\
        '--zone=drop --list-rich-rules')
            return 0
            ;;
        *'--remove-rich-rule='*)
            [ "$NOID_TEST_FIREWALL_MODE" != fail-remove ] || return 71
            for arg in "$@"; do
                case "$arg" in --remove-rich-rule=*) rule=${arg#--remove-rich-rule=} ;; esac
            done
            grep -vxF -- "$rule" "$NOID_TEST_RULES" > "$NOID_TEST_RULES.new" || true
            mv "$NOID_TEST_RULES.new" "$NOID_TEST_RULES"
            ;;
        '--reload') return 0 ;;
        *) return 1 ;;
    esac
}

# No runtime nft element exists after the mocked firewalld revoke.
# shellcheck disable=SC2317,SC2329
nft() { return 1; }
# shellcheck disable=SC2317,SC2329
ip() { return 1; }
# State is owned by the unprivileged fixture account; production requires UID 0.
# shellcheck disable=SC2317,SC2329
chown() { return 0; }
# shellcheck disable=SC2317,SC2329
systemctl() {
    printf '%s\n' "$*" >> "$NOID_TEST_SYSTEMCTL_LOG"
    return 0
}
export -f firewall-cmd nft ip chown systemctl

# shellcheck disable=SC1090
. "$FIXTURE/functions.sh"

IP=198.19.7.20
FAMILY=ipv4
BOOT_A=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
BOOT_B=bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb

add_rule() {
    printf '%s\n' \
        'rule priority="-100" family="ipv4" destination address="198.19.7.20" accept' \
        > "$NOID_TEST_RULES"
}

reset_fixture() {
    rm -rf "$NOID_LAN_EXCEPTION_STATE_DIR" "$NOID_LAN_PEER_STATE_DIR"
    rm -f "$NOID_LAN_EXCEPTION_SCHEDULE_FILE"
    : > "$NOID_TEST_RULES"
    : > "$NOID_TEST_SYSTEMCTL_LOG"
    export NOID_TEST_FIREWALL_MODE=normal
}

create_temp() {
    local epoch="$1" boot_id="$2" boottime="$3" duration="$4"
    export NOID_TEST_NOW_EPOCH="$epoch"
    export NOID_TEST_BOOT_ID="$boot_id"
    export NOID_TEST_BOOTTIME="$boottime"
    write_exception_state "$IP" "$FAMILY" temporary "$duration" \
        outbound none 0 0
    add_rule
}

test_start "05-lan-temp-expiry-fixture"

# State-directory substitution is rejected before any durable record can
# escape the closed root-owned path.
reset_fixture
mkdir -p "$FIXTURE/state-escape"
ln -s "$FIXTURE/state-escape" "$NOID_LAN_EXCEPTION_STATE_DIR"
assert_cmd_failure "symlinked exception-state directory is rejected" \
    write_exception_state "$IP" "$FAMILY" temporary 60 outbound none 0 0
assert_eq 0 "$(find "$FIXTURE/state-escape" -mindepth 1 | wc -l)" \
    "rejected state-directory symlink publishes nothing to its target"

# The active XDP contract has no IPv6/NDP peer return-flow admission. Reject
# before peer learning, metadata publication or any firewalld mutation.
reset_fixture
global_state() { printf '%s\n' BLOCKED; }
if (add_ip_exception fd00::1 permanent 0) > "$FIXTURE/ipv6.out" 2>&1; then
    _fail "IPv6 add is rejected before mutation"
else
    _pass "IPv6 add is rejected before mutation"
fi
assert_grep_fixed 'IPv6 per-IP LAN exceptions are unsupported' \
    "$FIXTURE/ipv6.out" "IPv6 rejection names the missing XDP/NDP contract"
assert_eq "" "$(cat "$NOID_TEST_RULES")" "IPv6 rejection adds no firewall rule"
if [ ! -d "$NOID_LAN_EXCEPTION_STATE_DIR" ] \
   || [ "$(find "$NOID_LAN_EXCEPTION_STATE_DIR" -name '*.state' | wc -l)" -eq 0 ]; then
    _pass "IPv6 rejection publishes no exception metadata"
else
    _fail "IPv6 rejection published exception metadata"
fi

# Same boot: retain strictly before both deadlines, revoke exactly at either.
reset_fixture
create_temp 1000 "$BOOT_A" 100 60
export NOID_TEST_NOW_EPOCH=1059 NOID_TEST_BOOTTIME=159
assert_cmd_success "same-boot grant survives strictly before its deadline" \
    reconcile_expired_exceptions
assert_grep_fixed 'destination address="198.19.7.20"' "$NOID_TEST_RULES" \
    "pre-expiry rule remains"
assert_grep_fixed 'start noid-lan-expiry-reconcile.timer' \
    "$NOID_TEST_SYSTEMCTL_LOG" "valid temporary grant activates its deadline timer"
assert_grep_fixed 'EPOCH=1060' "$NOID_LAN_EXCEPTION_SCHEDULE_FILE" \
    "runtime schedule carries the absolute wall-clock deadline"
assert_grep_fixed 'MONOTONIC_DELAY_SEC=1' "$NOID_LAN_EXCEPTION_SCHEDULE_FILE" \
    "runtime schedule carries the same-boot monotonic deadline"
: > "$NOID_TEST_SYSTEMCTL_LOG"
export NOID_TEST_NOW_EPOCH=1060 NOID_TEST_BOOTTIME=160
assert_cmd_success "same-boot grant is reconciled at its deadline" \
    reconcile_expired_exceptions
assert_eq "" "$(cat "$NOID_TEST_RULES")" "deadline removes the durable rule"
assert_grep_fixed 'stop noid-lan-expiry-reconcile.timer' \
    "$NOID_TEST_SYSTEMCTL_LOG" "last expiry stops deadline reconciliation"
if [ ! -e "$NOID_LAN_EXCEPTION_SCHEDULE_FILE" ]; then
    _pass "last expiry removes generated deadline state"
else
    _fail "last expiry left generated deadline state"
fi
if [ ! -e "$(exception_state_file "$IP")" ]; then
    _pass "deadline removes the durable metadata"
else
    _fail "deadline left durable metadata"
fi

# Reboot does not erase the deadline: before remains, after revokes.
reset_fixture
create_temp 2000 "$BOOT_A" 300 120
export NOID_TEST_BOOT_ID="$BOOT_B" NOID_TEST_NOW_EPOCH=2050 NOID_TEST_BOOTTIME=5
assert_cmd_success "reboot-before-expiry retains the bounded exception" \
    reconcile_expired_exceptions
assert_grep_fixed 'destination address="198.19.7.20"' "$NOID_TEST_RULES" \
    "reboot cannot relabel the temporary rule as permanent"
export NOID_TEST_NOW_EPOCH=2120 NOID_TEST_BOOTTIME=75
assert_cmd_success "reboot-at-expiry revokes before continued use" \
    reconcile_expired_exceptions
assert_eq "" "$(cat "$NOID_TEST_RULES")" "post-reboot expiry removes the rule"

# Wall clock movement never extends a grant.
reset_fixture
create_temp 3000 "$BOOT_A" 400 60
export NOID_TEST_NOW_EPOCH=2999 NOID_TEST_BOOTTIME=401
assert_cmd_success "clock rollback is treated as fail-closed expiry" \
    reconcile_expired_exceptions
assert_eq "" "$(cat "$NOID_TEST_RULES")" "clock rollback removes the rule"
reset_fixture
create_temp 4000 "$BOOT_A" 500 60
export NOID_TEST_NOW_EPOCH=9999 NOID_TEST_BOOTTIME=501
assert_cmd_success "clock forward expires immediately" reconcile_expired_exceptions
assert_eq "" "$(cat "$NOID_TEST_RULES")" "clock forward removes the rule"

# Missing, malformed or permission-weakened state is never read as permanent.
reset_fixture
add_rule
export NOID_TEST_NOW_EPOCH=5000 NOID_TEST_BOOT_ID="$BOOT_A" NOID_TEST_BOOTTIME=600
assert_cmd_success "missing metadata revokes the managed rule" reconcile_expired_exceptions
assert_eq "" "$(cat "$NOID_TEST_RULES")" "missing metadata leaves no exception"
reset_fixture
create_temp 6000 "$BOOT_A" 700 60
chmod 0666 "$(exception_state_file "$IP")"
export NOID_TEST_NOW_EPOCH=6001 NOID_TEST_BOOTTIME=701
assert_cmd_success "permission-weakened metadata revokes the rule" \
    reconcile_expired_exceptions
assert_eq "" "$(cat "$NOID_TEST_RULES")" "weak metadata cannot authorize access"
reset_fixture
create_temp 7000 "$BOOT_A" 800 60
printf '%s\n' 'UNKNOWN=1' >> "$(exception_state_file "$IP")"
export NOID_TEST_NOW_EPOCH=7001 NOID_TEST_BOOTTIME=801
assert_cmd_success "unknown state records revoke the rule" reconcile_expired_exceptions
assert_eq "" "$(cat "$NOID_TEST_RULES")" "open-ended metadata is rejected"
reset_fixture
create_temp 7100 "$BOOT_A" 810 60
sed -i 's/^EXPIRES_EPOCH=7160$/EXPIRES_EPOCH=07160/' "$(exception_state_file "$IP")"
export NOID_TEST_NOW_EPOCH=7101 NOID_TEST_BOOTTIME=811
assert_cmd_success "non-canonical numeric state revokes the rule" \
    reconcile_expired_exceptions
assert_eq "" "$(cat "$NOID_TEST_RULES")" "octal/ambiguous deadline text is rejected"

# Rescheduling atomically replaces one record and moves the absolute deadline.
reset_fixture
export NOID_TEST_NOW_EPOCH=8000 NOID_TEST_BOOT_ID="$BOOT_A" NOID_TEST_BOOTTIME=900
write_exception_state "$IP" "$FAMILY" temporary 60 outbound none 0 0
export NOID_TEST_NOW_EPOCH=8020 NOID_TEST_BOOTTIME=920
write_exception_state "$IP" "$FAMILY" temporary 120 outbound none 0 0
load_exception_state "$IP"
assert_eq 8140 "$EX_STATE_EXPIRES" "duplicate scheduling replaces the deadline"
assert_eq 1 "$(find "$NOID_LAN_EXCEPTION_STATE_DIR" -maxdepth 1 -name '*.state' | wc -l)" \
    "duplicate scheduling leaves one canonical record"

# A failed revoke is visible and stops NetworkManager fail-closed.
reset_fixture
create_temp 9000 "$BOOT_A" 1000 60
export NOID_TEST_NOW_EPOCH=9060 NOID_TEST_BOOTTIME=1060
export NOID_TEST_FIREWALL_MODE=fail-remove
if reconcile_expired_exceptions >/dev/null 2>&1; then
    _fail "failed expiry revoke is reported"
else
    _pass "failed expiry revoke is reported"
fi
assert_grep_fixed '--no-block stop NetworkManager.service' "$NOID_TEST_SYSTEMCTL_LOG" \
    "failed revoke stops networking fail-closed"
assert_grep_fixed 'destination address="198.19.7.20"' "$NOID_TEST_RULES" \
    "failed revoke is not falsely reported as absent"

test_finish
