#!/bin/bash
# Behavioural contract for direction-aware per-peer LAN exceptions.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/05-lan-isolation.ks"
FIXTURE=$(mktemp -d "${TMPDIR:-/var/tmp}/noid-test-05-direction.XXXXXX")
cleanup() { find "$FIXTURE" -depth -delete; }
trap cleanup EXIT

extract_heredoc "$KS_FILE" LAN_ALLOW_EOF "$FIXTURE/noid-lan-allow"
awk '/^# === ACTION DISPATCH ===/ {exit} {print}' \
    "$FIXTURE/noid-lan-allow" > "$FIXTURE/functions.sh"
NOID_LAN_STATE_UID=$(id -u)
NOID_LAN_STATE_GID=$(id -g)
export NOID_LAN_STATE_UID NOID_LAN_STATE_GID
# shellcheck disable=SC1090
. "$FIXTURE/functions.sh"

test_start "05-lan-direction-fixture"

if python3 -I -c 'from firewall.core.rich import Rich_Rule' \
        >"$FIXTURE/python3-firewall.out" 2>"$FIXTURE/python3-firewall.err"; then
    _pass "python3-firewall rich-rule parser is available"
else
    _fail "prerequisite missing: python3-firewall (firewall.core.rich)"
    test_finish
    exit 1
fi

# Exercise the production action parser without reaching privileged mutation.
PARSED="$FIXTURE/parsed"
add_ip_exception() {
    printf 'permanent\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$@" > "$PARSED"
}
add_temp_ip_exception() {
    printf 'temporary\t%s\t%s\t%s\t%s\t%s\t%s\n' "$@" > "$PARSED"
}

parse_success() {
    local description="$1" expected="$2"; shift 2
    : > "$PARSED"
    if action_add "$@" >"$FIXTURE/parser.out" 2>&1; then
        assert_eq "$expected" "$(cat "$PARSED")" "$description"
    else
        _fail "$description"
    fi
}
parse_failure() {
    local description="$1"; shift
    : > "$PARSED"
    if (action_add "$@") >"$FIXTURE/parser.out" 2>&1; then
        _fail "$description"
    else
        _pass "$description"
    fi
    assert_eq "" "$(cat "$PARSED")" "$description mutates no backend"
}

parse_success "outbound parser emits no unsolicited-ingress selector" \
    $'permanent\t198.19.7.20\tpermanent\t0\toutbound\tnone\t0\t0' \
    198.19.7.20 --direction outbound
parse_success "inbound parser emits exact TCP port" \
    $'permanent\t198.19.7.21\tpermanent\t0\tinbound\ttcp\t443\t443' \
    198.19.7.21 --direction inbound --protocol tcp --ports 443
parse_success "both parser emits exact UDP range and deadline" \
    $'temporary\t198.19.7.22\t30\tboth\tudp\t5300\t5301' \
    198.19.7.22 --direction both --protocol udp --ports 5300-5301 --temp 30

parse_failure "missing direction is rejected" 198.19.7.20
parse_failure "unknown direction is rejected" 198.19.7.20 --direction sideways
parse_failure "outbound protocol widening is rejected" \
    198.19.7.20 --direction outbound --protocol tcp
parse_failure "outbound port widening is rejected" \
    198.19.7.20 --direction outbound --ports 443
parse_failure "inbound missing protocol is rejected" \
    198.19.7.20 --direction inbound --ports 443
parse_failure "inbound missing ports is rejected" \
    198.19.7.20 --direction inbound --protocol tcp
parse_failure "port zero is rejected" \
    198.19.7.20 --direction inbound --protocol tcp --ports 0
parse_failure "port 65536 is rejected" \
    198.19.7.20 --direction inbound --protocol tcp --ports 65536
parse_failure "reversed range is rejected" \
    198.19.7.20 --direction inbound --protocol udp --ports 5301-5300
parse_failure "multi-dash range is rejected" \
    198.19.7.20 --direction inbound --protocol udp --ports 1-2-3
parse_failure "duplicate selector is rejected" \
    198.19.7.20 --direction inbound --protocol tcp --protocol udp --ports 443

# Restore the production functions replaced by the parser capture doubles.
# shellcheck disable=SC1090
. "$FIXTURE/functions.sh"

export NOID_LAN_EXCEPTION_STATE_DIR="$FIXTURE/exception-state"
export NOID_LAN_PEER_STATE_DIR="$FIXTURE/peer-state"
export LAN_EXCEPTION_STATE_DIR="$NOID_LAN_EXCEPTION_STATE_DIR"
export LAN_PEER_STATE_DIR="$NOID_LAN_PEER_STATE_DIR"
export LAN_STATE_UID="$NOID_LAN_STATE_UID"
export LAN_STATE_GID="$NOID_LAN_STATE_GID"
export NOID_TEST_NOW_EPOCH=1000
export NOID_TEST_BOOT_ID=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
export NOID_TEST_BOOTTIME=100
export POLICY_RULES_PERM="$FIXTURE/policy.perm"
export POLICY_RULES_RUN="$FIXTURE/policy.run"
export ZONE_RULES_PERM="$FIXTURE/zone.perm"
export ZONE_RULES_RUN="$FIXTURE/zone.run"
export EVENT_LOG="$FIXTURE/events"
: > "$POLICY_RULES_PERM"
: > "$POLICY_RULES_RUN"
: > "$ZONE_RULES_PERM"
: > "$ZONE_RULES_RUN"
: > "$EVENT_LOG"

chown() { return 0; }
nft() { return 1; }
# Invoked indirectly by functions loaded from the extracted production helper.
# shellcheck disable=SC2317,SC2329
ip() { return 1; }
systemctl() {
    printf 'systemctl %s\n' "$*" >> "$EVENT_LOG"
    return 0
}

firewall-cmd() {
    local scope=runtime target='' operation='' rule='' arg file
    for arg in "$@"; do
        case "$arg" in
            --permanent) scope=permanent ;;
            --policy=*) target=policy ;;
            --zone=*) target=zone ;;
            --list-rich-rules) operation=list ;;
            --add-rich-rule=*) operation=add; rule=${arg#--add-rich-rule=} ;;
            --remove-rich-rule=*) operation=remove; rule=${arg#--remove-rich-rule=} ;;
            --reload) operation=reload ;;
            *) return 1 ;;
        esac
    done
    case "$target:$scope" in
        policy:permanent) file=$POLICY_RULES_PERM ;;
        policy:runtime) file=$POLICY_RULES_RUN ;;
        zone:permanent) file=$ZONE_RULES_PERM ;;
        zone:runtime) file=$ZONE_RULES_RUN ;;
        :runtime|:permanent) file='' ;;
        *) return 1 ;;
    esac
    case "$operation" in
        list)
            if [ "$target" = policy ] \
               && [ "${FAIL_POLICY_LIST:-0}" = 1 ]; then
                return 1
            fi
            if [ "$target" = zone ] \
               && [ "${FAIL_ZONE_LIST:-0}" = 1 ]; then
                return 1
            fi
            cat "$file"
            ;;
        add)
            printf 'firewall add %s %s %s\n' "$scope" "$target" "$rule" >> "$EVENT_LOG"
            grep -Fxq -- "$rule" "$file" || printf '%s\n' "$rule" >> "$file"
            ;;
        remove)
            printf 'firewall remove %s %s %s\n' "$scope" "$target" "$rule" >> "$EVENT_LOG"
            grep -vxF -- "$rule" "$file" > "$file.new" || true
            mv "$file.new" "$file"
            ;;
        reload)
            printf 'firewall reload\n' >> "$EVENT_LOG"
            cp "$POLICY_RULES_PERM" "$POLICY_RULES_RUN"
            cp "$ZONE_RULES_PERM" "$ZONE_RULES_RUN"
            ;;
        *) return 1 ;;
    esac
}
export -f chown nft ip systemctl
export -f -- firewall-cmd

reset_rules() {
    : > "$POLICY_RULES_PERM"
    : > "$POLICY_RULES_RUN"
    : > "$ZONE_RULES_PERM"
    : > "$ZONE_RULES_RUN"
}

# A failed firewalld query is unknown state, never evidence that a permit is
# absent. Exercise policy and zone failures independently.
FAIL_POLICY_LIST=1
assert_cmd_failure "policy query failure cannot prove exception absence" \
    verify_ip_exception_absent 198.19.7.99 ipv4
EX_STATE_DIRECTION=outbound
assert_cmd_failure "policy query failure cannot report rule cleanup success" \
    remove_loaded_firewall_rules 198.19.7.99
assert_cmd_failure "orphan check reports a policy query failure" \
    revert_ip_exception 198.19.7.99 no-sync
unset FAIL_POLICY_LIST

FAIL_ZONE_LIST=1
assert_cmd_failure "zone query failure cannot prove inbound-rule absence" \
    verify_ip_exception_absent 198.19.7.99 ipv4
unset FAIL_ZONE_LIST

# A peer exception may deliberately target the default gateway. Revoking that
# peer policy must restore M04's independent permanent gateway pin rather than
# deleting it. Non-gateway cleanup is identity-scoped and must not delete a
# neighbour that no longer matches the peer state.
ARP_HARDENING_STATE="$FIXTURE/arp-hardening.state"
NEIGHBOUR_STATE="$FIXTURE/neighbour.state"
NEIGHBOUR_LOG="$FIXTURE/neighbour.log"
: > "$NEIGHBOUR_LOG"
# Invoked indirectly by remove_ipv4_peer_state from the extracted helper.
# shellcheck disable=SC2317,SC2329
ip() {
    printf '%s\n' "$*" >> "$NEIGHBOUR_LOG"
    case "$1:$2" in
        -4:neigh)
            cat "$NEIGHBOUR_STATE"
            ;;
        neigh:replace)
            local ip_addr=$3 mac="" iface="" index
            for ((index=4; index<=$#; index++)); do
                case "${!index}" in
                    lladdr)
                        index=$((index + 1)); mac=${!index}
                        ;;
                    dev)
                        index=$((index + 1)); iface=${!index}
                        ;;
                esac
            done
            printf '%s dev %s lladdr %s PERMANENT\n' \
                "$ip_addr" "$iface" "$mac" > "$NEIGHBOUR_STATE"
            ;;
        neigh:del)
            : > "$NEIGHBOUR_STATE"
            ;;
        *) return 1 ;;
    esac
}
export -f ip

cat > "$ARP_HARDENING_STATE" <<'EOF'
ENABLED=1
WAN_IFACE=test0
GATEWAY_IP=198.19.7.1
GATEWAY_MAC=02:00:00:00:00:01
LEARNED_AT=2026-07-26T00:00:00Z
EOF
chmod 0644 "$ARP_HARDENING_STATE"
write_ipv4_peer_state 198.19.7.1 test0 02:00:00:00:00:01 outbound none 0 0
printf '%s\n' \
    '198.19.7.1 dev test0 lladdr 02:00:00:00:00:01 STALE' > "$NEIGHBOUR_STATE"
assert_cmd_success "gateway-peer revoke restores the independent M04 pin" \
    remove_ipv4_peer_state 198.19.7.1
assert_grep_fixed \
    'neigh replace 198.19.7.1 lladdr 02:00:00:00:00:01 dev test0 nud permanent' \
    "$NEIGHBOUR_LOG" "gateway-peer cleanup performs an exact permanent replacement"
assert_grep_fixed \
    '198.19.7.1 dev test0 lladdr 02:00:00:00:00:01 PERMANENT' \
    "$NEIGHBOUR_STATE" "gateway-peer cleanup verifies the restored permanent identity"
assert_cmd_success "gateway-peer state is removed after pin restoration" \
    test ! -e "$(peer_state_file 198.19.7.1)"

# M04's explicit kernel-pin opt-out retains the gateway identity for M03 XDP,
# but M05 must not recreate the opted-out permanent neighbour when removing a
# peer policy for that same address.
sed -i 's/^ENABLED=1$/ENABLED=0/' "$ARP_HARDENING_STATE"
: > "$NEIGHBOUR_LOG"
write_ipv4_peer_state 198.19.7.1 test0 02:00:00:00:00:01 outbound none 0 0
printf '%s\n' \
    '198.19.7.1 dev test0 lladdr 02:00:00:00:00:01 PERMANENT' > "$NEIGHBOUR_STATE"
assert_cmd_success "disabled M04 pin is not recreated during gateway-peer revoke" \
    remove_ipv4_peer_state 198.19.7.1
assert_not_grep 'neigh replace 198\.19\.7\.1' "$NEIGHBOUR_LOG" \
    "retained XDP identity does not override the explicit kernel-pin opt-out"
assert_grep_fixed 'neigh del 198.19.7.1 dev test0' "$NEIGHBOUR_LOG" \
    "gateway peer pin is deleted when M04 records ENABLED=0"
sed -i 's/^ENABLED=0$/ENABLED=1/' "$ARP_HARDENING_STATE"

: > "$NEIGHBOUR_LOG"
write_ipv4_peer_state 198.19.7.2 test0 02:00:00:00:00:02 outbound none 0 0
printf '%s\n' \
    '198.19.7.2 dev test0 lladdr 02:00:00:00:00:02 PERMANENT' > "$NEIGHBOUR_STATE"
assert_cmd_success "ordinary peer revoke removes its exact managed pin" \
    remove_ipv4_peer_state 198.19.7.2
assert_grep_fixed 'neigh del 198.19.7.2 dev test0' "$NEIGHBOUR_LOG" \
    "ordinary peer cleanup deletes its exact permanent neighbour"

: > "$NEIGHBOUR_LOG"
write_ipv4_peer_state 198.19.7.3 test0 02:00:00:00:00:03 outbound none 0 0
printf '%s\n' \
    '198.19.7.3 dev test0 lladdr 02:00:00:00:00:22 PERMANENT' > "$NEIGHBOUR_STATE"
assert_cmd_success "changed peer identity is left to the kernel after policy revoke" \
    remove_ipv4_peer_state 198.19.7.3
assert_not_grep 'neigh del 198.19.7.3' "$NEIGHBOUR_LOG" \
    "peer cleanup never deletes a neighbour with a different identity"
assert_grep_fixed \
    '198.19.7.3 dev test0 lladdr 02:00:00:00:00:22 PERMANENT' \
    "$NEIGHBOUR_STATE" "changed neighbour identity remains untouched"

# If M04 evidence exists but is malformed, M05 cannot safely decide whether
# the peer is the protected gateway. The LAN permit is already closed by the
# caller, so retain both the kernel identity and the valid peer record for a
# fail-closed retry instead of erasing evidence and reporting false success.
printf '%s\n' 'malformed=true' > "$ARP_HARDENING_STATE"
write_ipv4_peer_state 198.19.7.4 test0 02:00:00:00:00:10 outbound none 0 0
printf '%s\n' \
    '198.19.7.4 dev test0 lladdr 02:00:00:00:00:10 PERMANENT' > "$NEIGHBOUR_STATE"
assert_cmd_failure "invalid M04 state makes peer cleanup fail closed" \
    remove_ipv4_peer_state 198.19.7.4
assert_cmd_success "failed cleanup retains the valid peer evidence" \
    test -e "$(peer_state_file 198.19.7.4)"
assert_grep_fixed \
    '198.19.7.4 dev test0 lladdr 02:00:00:00:00:10 PERMANENT' \
    "$NEIGHBOUR_STATE" "failed cleanup preserves the uncertain kernel neighbour"
rm -f -- "$(peer_state_file 198.19.7.4)"

cat > "$ARP_HARDENING_STATE" <<'EOF'
ENABLED=1
WAN_IFACE=test0
GATEWAY_IP=198.19.7.1
GATEWAY_MAC=02:00:00:00:00:01
LEARNED_AT=2026-07-26T00:00:00Z
EOF
chmod 0644 "$ARP_HARDENING_STATE"
write_ipv4_peer_state 198.19.7.5 test0 02:00:00:00:00:11 outbound none 0 0
printf '%s\n' \
    '198.19.7.5 dev test0 lladdr 02:00:00:00:00:11 PERMANENT' \
    '198.19.7.5 dev test0 lladdr 02:00:00:00:00:22 PERMANENT' \
    > "$NEIGHBOUR_STATE"
assert_cmd_failure "ambiguous kernel neighbour records fail cleanup closed" \
    remove_ipv4_peer_state 198.19.7.5
assert_cmd_success "ambiguous cleanup retains its peer evidence" \
    test -e "$(peer_state_file 198.19.7.5)"
assert_not_grep 'neigh del 198\.19\.7\.5' "$NEIGHBOUR_LOG" \
    "ambiguous cleanup deletes no kernel identity"
rm -f -- "$(peer_state_file 198.19.7.5)"

# Invoked indirectly by state/export helpers sourced from the production CLI.
# shellcheck disable=SC2317,SC2329
ip() { return 1; }
export -f ip

# State/export schemas preserve every selector without interpretation drift.
write_exception_state 198.19.7.20 ipv4 permanent 0 outbound none 0 0
write_ipv4_peer_state 198.19.7.20 test0 02:00:00:00:00:01 outbound none 0 0
write_exception_state 198.19.7.21 ipv4 permanent 0 inbound tcp 443 443
write_ipv4_peer_state 198.19.7.21 test0 02:00:00:00:00:02 inbound tcp 443 443
write_exception_state 198.19.7.22 ipv4 temporary 1800 both udp 5300 5301
write_ipv4_peer_state 198.19.7.22 test0 02:00:00:00:00:03 both udp 5300 5301

machine_output=$(list_machine)
printf '%s\n' "$machine_output" > "$FIXTURE/machine-output"
assert_grep_fixed 'NOID-LAN-EXCEPTIONS-V2' \
    "$FIXTURE/machine-output" "machine list pins the v2 direction schema"
assert_grep_fixed $'198.19.7.20\toutbound\tnone\t0\t0\tpermanent\t0\t0' \
    "$FIXTURE/machine-output" "machine list preserves outbound-only"
assert_grep_fixed $'198.19.7.21\tinbound\ttcp\t443\t443\tpermanent\t0\t0' \
    "$FIXTURE/machine-output" "machine list preserves inbound TCP"
assert_grep_fixed $'198.19.7.22\tboth\tudp\t5300\t5301\ttemporary\t1800\t2800' \
    "$FIXTURE/machine-output" "machine list preserves both UDP range"

# A reader can race a root mutation between enumeration and record loading.
# Neither the human renderer nor the machine protocol may reuse globals from a
# preceding row, and a failed machine snapshot must publish no valid-looking
# V2 header or partial rows.
assert_cmd_success "human list renders fixed invalid-metadata placeholders" \
    bash -c '
        set -euo pipefail
        . "$1"
        list_per_ip_raw() { printf "%s\n" 198.19.7.99; }
        load_exception_state() { return 1; }
        output=$(show_per_ip_exceptions)
        [[ $output == *"unavailable — invalid metadata"* ]]
    ' _ "$FIXTURE/functions.sh"
if (
    # These fixture overrides are consumed indirectly by the sourced
    # list_machine implementation in this subshell.
    # shellcheck disable=SC2317,SC2329
    list_per_ip_raw() { printf '%s\n' 198.19.7.99; }
    # shellcheck disable=SC2317,SC2329
    load_exception_state() { return 1; }
    list_machine
) > "$FIXTURE/failed-machine-output" 2> "$FIXTURE/failed-machine-error"; then
    _fail "failed machine enumeration is rejected"
else
    _pass "failed machine enumeration is rejected"
fi
assert_eq "" "$(cat "$FIXTURE/failed-machine-output")" \
    "failed machine enumeration publishes no V2 header or partial row"

policy_output=$(export_policy)
printf '%s\n' "$policy_output" > "$FIXTURE/policy-output"
assert_grep_fixed $'test0\t198.19.7.20\t02:00:00:00:00:01\toutbound\tnone\t0\t0' \
    "$FIXTURE/policy-output" "policy export is exact for outbound"
assert_grep_fixed $'test0\t198.19.7.21\t02:00:00:00:00:02\tinbound\ttcp\t443\t443' \
    "$FIXTURE/policy-output" "policy export is exact for inbound"
assert_grep_fixed $'test0\t198.19.7.22\t02:00:00:00:00:03\tboth\tudp\t5300\t5301' \
    "$FIXTURE/policy-output" "policy export is exact for both"
excluded_output=$(export_policy 198.19.7.21)
printf '%s\n' "$excluded_output" > "$FIXTURE/excluded-output"
assert_not_grep '198.19.7.21' "$FIXTURE/excluded-output" \
    "XDP-first edit export excludes exactly the target peer"

write_ipv4_peer_state 198.19.7.21 test0 02:00:00:00:00:02 inbound udp 443 443
assert_cmd_failure "exception/peer selector disagreement closes policy export" export_policy
write_ipv4_peer_state 198.19.7.21 test0 02:00:00:00:00:02 inbound tcp 443 443

assert_cmd_success "native firewalld parser accepts all generated rule forms" \
    python3 -I - "$(outbound_rule_text 198.19.7.20)" \
        "$(inbound_rule_text 198.19.7.21 tcp 443 443)" \
        "$(inbound_rule_text 198.19.7.22 udp 5300 5301)" <<'PY'
from firewall.core.rich import Rich_Rule
import sys

for rule in sys.argv[1:]:
    assert str(Rich_Rule(rule_str=rule)) == rule
PY

# Firewalld publication is the exact union requested by direction.
for spec in \
    '198.19.7.20 outbound none 0 0' \
    '198.19.7.21 inbound tcp 443 443' \
    '198.19.7.22 both udp 5300 5301'; do
    read -r ip_addr direction _protocol _port_start _port_end <<< "$spec"
    reset_rules
    load_exception_state "$ip_addr"
    assert_cmd_success "publish exact $direction firewalld contract" \
        add_loaded_firewall_rules "$ip_addr"
    assert_cmd_success "verify exact $direction firewalld contract" \
        firewall_contract_exists "$ip_addr" permanent
    case "$direction" in
        outbound)
            assert_eq 1 "$(wc -l < "$POLICY_RULES_PERM")" \
                "outbound publishes one destination rule"
            assert_eq 0 "$(wc -l < "$ZONE_RULES_PERM")" \
                "outbound publishes no unsolicited-ingress rule"
            ;;
        inbound)
            assert_eq 0 "$(wc -l < "$POLICY_RULES_PERM")" \
                "inbound publishes no guest-originated destination rule"
            assert_grep_fixed 'source address="198.19.7.21" port port="443" protocol="tcp" accept' \
                "$ZONE_RULES_PERM" "inbound publishes its exact TCP port"
            ;;
        both)
            assert_eq 1 "$(wc -l < "$POLICY_RULES_PERM")" \
                "both publishes the outbound destination rule"
            assert_grep_fixed 'source address="198.19.7.22" port port="5300-5301" protocol="udp" accept' \
                "$ZONE_RULES_PERM" "both publishes its exact UDP range"
            ;;
    esac
    assert_cmd_success "remove exact $direction firewalld contract" \
        remove_loaded_firewall_rules "$ip_addr"
    assert_cmd_success "reload after exact $direction removal" firewall-cmd --reload
    assert_eq 0 "$(wc -l < "$POLICY_RULES_RUN")" \
        "$direction removal leaves no outbound runtime permit"
    assert_eq 0 "$(wc -l < "$ZONE_RULES_RUN")" \
        "$direction removal leaves no inbound runtime permit"
done

# Full production add/edit/revoke ordering with deterministic boundary doubles.
find "$NOID_LAN_EXCEPTION_STATE_DIR" -mindepth 1 -delete
find "$NOID_LAN_PEER_STATE_DIR" -mindepth 1 -delete
reset_rules
: > "$EVENT_LOG"
ip() {
    case "$1:$2" in
        -4:neigh)
            cat "$NEIGHBOUR_STATE"
            ;;
        neigh:del)
            : > "$NEIGHBOUR_STATE"
            ;;
        *) return 1 ;;
    esac
}
export -f ip
global_state() { printf '%s\n' BLOCKED; }
sync_expiry_timer() { return 0; }
refresh_topology_guard() {
    printf 'topology %s\n' "$*" >> "$EVENT_LOG"
    [ "${FAIL_TOPOLOGY_ONCE:-0}" != 1 ] || {
        FAIL_TOPOLOGY_ONCE=0
        return 1
    }
}
learn_ipv4_peer() {
    printf 'learn %s\n' "$*" >> "$EVENT_LOG"
    [ "${FAIL_LEARN_ONCE:-0}" != 1 ] || {
        FAIL_LEARN_ONCE=0
        return 1
    }
    write_ipv4_peer_state "$1" test0 02:00:00:00:00:11 "$2" "$3" "$4" "$5"
    printf '%s dev test0 lladdr %s PERMANENT\n' \
        "$1" 02:00:00:00:00:11 > "$NEIGHBOUR_STATE"
}
verify_ip_exception_runtime() {
    load_exception_state "$1" \
        && firewall_contract_exists "$1" permanent \
        && firewall_contract_exists "$1" runtime
}

assert_cmd_success "production add commits outbound-only" \
    add_ip_exception 198.19.7.30 permanent 0 outbound none 0 0
assert_cmd_success "production outbound add publishes exact runtime contract" \
    verify_ip_exception_runtime 198.19.7.30 ipv4
assert_grep_fixed \
    'topology --invalidate-peer-flows 198.19.7.30 --require-xdp' \
    "$EVENT_LOG" "new peer activation invalidates stale reverse tuples"

: > "$EVENT_LOG"
assert_cmd_success "production edit replaces outbound with inbound" \
    add_ip_exception 198.19.7.30 permanent 0 inbound tcp 8443 8443
assert_cmd_success "edit quiesces XDP before removing the old firewalld permit" \
    awk '
        /^topology --exclude-peer 198.19.7.30 --invalidate-peer-flows 198.19.7.30 --require-xdp$/ { q=NR }
        /^firewall remove permanent policy / { r=NR }
        END { exit !(q > 0 && r > q) }
    ' "$EVENT_LOG"
assert_cmd_success "edit resets reply correlation before its replacement permit" \
    awk '
        /^topology --invalidate-peer-flows 198.19.7.30 --require-xdp$/ { f=NR }
        /^firewall add permanent zone / { a=NR }
        END { exit !(f > 0 && a > f) }
    ' "$EVENT_LOG"
load_exception_state 198.19.7.30
assert_eq inbound "$EX_STATE_DIRECTION" "edit commits only the new direction"
assert_eq tcp "$EX_STATE_PROTOCOL" "edit commits only the new protocol"
assert_eq 8443 "$EX_STATE_PORT_START" "edit commits only the new port"

: > "$EVENT_LOG"
assert_cmd_success "production revoke removes inbound exception" \
    revert_ip_exception 198.19.7.30 no-sync
assert_cmd_success "revoke quiesces XDP before removing firewalld" \
    awk '
        /^topology --exclude-peer 198.19.7.30 --invalidate-peer-flows 198.19.7.30 --require-xdp$/ { q=NR }
        /^firewall remove permanent zone / { r=NR }
        END { exit !(q > 0 && r > q) }
    ' "$EVENT_LOG"
assert_cmd_success "revoke removes durable selector state" \
    test ! -e "$(exception_state_file 198.19.7.30)"
assert_eq 0 "$(wc -l < "$POLICY_RULES_RUN")" \
    "revoke leaves no outbound permit"
assert_eq 0 "$(wc -l < "$ZONE_RULES_RUN")" \
    "revoke leaves no inbound permit"

# New IPv6 grants are intentionally unsupported, but pre-v2 outbound permits
# had no selector record. Reconciliation must still enumerate and revoke the
# exact legacy rule without invoking the IPv4 peer-identity path.
legacy_ipv6_rule=$(outbound_rule_text 2001:db8::30)
firewall-cmd --permanent --policy="$POLICY" \
    --add-rich-rule="$legacy_ipv6_rule"
firewall-cmd --reload
assert_grep_fixed '2001:db8::30' <(list_managed_firewall_ips) \
    "legacy IPv6 rule remains visible to fail-closed reconciliation"
assert_cmd_success "legacy IPv6 rule is revoked by reconciliation" \
    reconcile_expired_exceptions
assert_eq 0 "$(wc -l < "$POLICY_RULES_RUN")" \
    "legacy IPv6 reconciliation leaves no outbound permit"

legacy_ipv6_rule=$(outbound_rule_text 2001:db8::31)
firewall-cmd --permanent --policy="$POLICY" \
    --add-rich-rule="$legacy_ipv6_rule"
firewall-cmd --reload
assert_cmd_success "direct legacy IPv6 revoke bypasses IPv4 peer cleanup" \
    revert_ip_exception 2001:db8::31 no-sync
assert_eq 0 "$(wc -l < "$POLICY_RULES_RUN")" \
    "direct legacy IPv6 revoke leaves no outbound permit"

: > "$EVENT_LOG"
FAIL_TOPOLOGY_ONCE=1
if add_ip_exception 198.19.7.31 permanent 0 both udp 6000 6001 \
        >"$FIXTURE/topology-fail.out" 2>&1; then
    _fail "failed topology publication rolls a new both-direction grant back"
else
    _pass "failed topology publication rolls a new both-direction grant back"
fi
assert_cmd_success "topology failure removes exception state" \
    test ! -e "$(exception_state_file 198.19.7.31)"
assert_eq 0 "$(wc -l < "$POLICY_RULES_RUN")" \
    "topology failure leaves no outbound permit"
assert_eq 0 "$(wc -l < "$ZONE_RULES_RUN")" \
    "topology failure leaves no inbound permit"
assert_cmd_success "rollback quiesces XDP before its firewalld cleanup" \
    awk '
        /^topology --exclude-peer 198.19.7.31 --invalidate-peer-flows 198.19.7.31 --require-xdp$/ { q=NR }
        /^firewall reload$/ && reload == 0 { reload=NR }
        END { exit !(q > 0 && reload > q) }
    ' "$EVENT_LOG"

FAIL_LEARN_ONCE=1
if add_ip_exception 198.19.7.32 permanent 0 inbound tcp 9443 9443 \
        >"$FIXTURE/learn-fail.out" 2>&1; then
    _fail "failed peer learning rolls all partial state back"
else
    _pass "failed peer learning rolls all partial state back"
fi
assert_cmd_success "peer-learning failure leaves no exception state" \
    test ! -e "$(exception_state_file 198.19.7.32)"

write_exception_state() { return 1; }
if add_ip_exception 198.19.7.33 permanent 0 outbound none 0 0 \
        >"$FIXTURE/state-fail.out" 2>&1; then
    _fail "failed selector-state publication rolls learned peer back"
else
    _pass "failed selector-state publication rolls learned peer back"
fi
assert_cmd_success "state-publication failure leaves no peer binding" \
    test ! -e "$(peer_state_file 198.19.7.33)"
assert_eq 0 "$(wc -l < "$POLICY_RULES_RUN")" \
    "state-publication failure leaves no outbound permit"
assert_eq 0 "$(wc -l < "$ZONE_RULES_RUN")" \
    "state-publication failure leaves no inbound permit"

test_finish
