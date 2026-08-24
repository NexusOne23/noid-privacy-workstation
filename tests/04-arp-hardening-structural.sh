#!/bin/bash
# M04 structural contract: native ACD, closed identity state, exact pin and
# fail-closed XDP/topology hand-off without a non-enforcing nft shadow table.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/04-arp-hardening.ks"
ACD_GATE="$PROJECT_ROOT/tests/pre-ship/04-ipv4-acd-runtime.sh"
TMPDIR="$(mktemp -d "$PROJECT_ROOT/.test-arp.XXXXXXXX")"
trap 'rm -rf "$TMPDIR"' EXIT

test_start "04-arp-hardening-structural"

assert_file_exists "$KS_FILE"
assert_cmd_success "M04 is valid Bash/Kickstart shell syntax" bash -n "$KS_FILE"
assert_grep_fixed '# Architecture (6 components):' "$KS_FILE" \
    "M04 header inventories every durable architecture component"
assert_grep_fixed 'M11 chrony online/offline transition owner' "$KS_FILE" \
    "M04 header records the chrony readiness coupling"
assert_grep_fixed 'endpoint resolver also consumes the readiness marker M04 publishes' \
    "$KS_FILE" "M04 cross-reference includes both readiness consumers"
assert_grep_extended '^iputils$' "$KS_FILE" \
    "M04 explicitly owns bounded ARP observation runtime"
assert_grep_extended '^python3$' "$KS_FILE" \
    "M04 explicitly owns closed IPv4/state validation runtime"
assert_grep_extended '^diffutils$' "$KS_FILE" \
    "M04 explicitly owns dispatcher/state byte-parity runtime"
assert_grep_fixed 'install -d -m 0755 -o root -g root /var/lib/noid-privacy' \
    "$KS_FILE" "fresh installs create the state root before the boot guard"
assert_file_exists "$ACD_GATE"
assert_file_executable "$ACD_GATE"
assert_cmd_success "IPv4 ACD runtime gate is valid Bash" bash -n "$ACD_GATE"
assert_grep_fixed 'live|fresh-install|reboot' "$ACD_GATE" \
    "runtime proof covers all three lifecycle passes"
assert_grep_fixed 'unshare --net /usr/bin/sleep 60 &' "$ACD_GATE" \
    "packet proof owns a bounded process namespace"
assert_grep_fixed 'nsenter --target "$namespace_pid" --net' "$ACD_GATE" \
    "packet proof enters only its process-bound namespace"
assert_not_grep 'ip netns' "$ACD_GATE" \
    "runtime proof avoids SELinux-denied named-netns bind mounts"
assert_grep_fixed '"$XDP_CONTROLLER" status >/dev/null' "$ACD_GATE" \
    "every lifecycle proof verifies the active XDP/TC identity"

extract_heredoc "$KS_FILE" ARP_STATE_GUARD_EOF "$TMPDIR/state-guard.sh" \
    || _fail "state guard extraction"
extract_heredoc "$KS_FILE" NETWORK_READINESS_EOF "$TMPDIR/network-readiness.sh" \
    || _fail "network readiness helper extraction"
extract_heredoc "$KS_FILE" ARP_STATE_GUARD_SERVICE_EOF "$TMPDIR/state-guard.service" \
    || _fail "state guard unit extraction"
extract_heredoc "$KS_FILE" ARP_NM_REQUIRE_EOF "$TMPDIR/nm-require.conf" \
    || _fail "NetworkManager dependency extraction"
extract_heredoc "$KS_FILE" ARP_INITIAL_DISPATCHER_EOF "$TMPDIR/initial-dispatcher.sh" \
    || _fail "initial dispatcher extraction"
extract_heredoc "$KS_FILE" NM_TEMPLATE_EOF "$TMPDIR/dispatcher.sh" \
    || _fail "generated dispatcher extraction"
extract_heredoc "$KS_FILE" ARP_TOOL_EOF "$TMPDIR/tool.sh" \
    || _fail "ARP tool extraction"
extract_heredoc "$KS_FILE" SVC_EOF "$TMPDIR/firstboot.service" \
    || _fail "firstboot unit extraction"

for script in "$TMPDIR/state-guard.sh" "$TMPDIR/network-readiness.sh" \
              "$TMPDIR/initial-dispatcher.sh" "$TMPDIR/dispatcher.sh" \
              "$TMPDIR/tool.sh"; do
    assert_cmd_success "valid Bash: ${script##*/}" bash -n "$script"
done
if help_output=$(bash "$TMPDIR/tool.sh" help 2>"$TMPDIR/help.stderr") \
   && [ ! -s "$TMPDIR/help.stderr" ]; then
    _pass "literal help renders without command substitution"
else
    _fail "literal help emits an error"
fi
if grep -Fq 'run `refresh` explicitly.' <<<"$help_output"; then
    _pass "help preserves the literal refresh command"
else
    _fail "help lost the literal refresh command"
fi

# Reproduce the Live-boot window where a hardware NIC exists before DHCP has
# published its default route. The service's deferred mode must reach its
# explicit no-gateway branch instead of errexit terminating on the assignment.
mkdir -p "$TMPDIR/defer-bin" "$TMPDIR/defer-sys/mock0/device"
cat > "$TMPDIR/defer-bin/id" <<'DEFER_ID_EOF'
#!/bin/sh
[ "$1" = -u ] && printf '0\n'
DEFER_ID_EOF
cat > "$TMPDIR/defer-bin/ip" <<'DEFER_IP_EOF'
#!/bin/sh
exit 0
DEFER_IP_EOF
cat > "$TMPDIR/defer-state-guard" <<'DEFER_GUARD_EOF'
#!/bin/sh
exit 0
DEFER_GUARD_EOF
cat > "$TMPDIR/defer-network-readiness" <<'DEFER_READINESS_EOF'
#!/bin/sh
[ "$#" -eq 1 ] && [ "$1" = offline ]
DEFER_READINESS_EOF
chmod 0755 "$TMPDIR/defer-bin/id" "$TMPDIR/defer-bin/ip" \
    "$TMPDIR/defer-state-guard" "$TMPDIR/defer-network-readiness"
cp "$TMPDIR/tool.sh" "$TMPDIR/defer-tool.sh"
sed -i \
    -e "s#^STATE_GUARD=.*#STATE_GUARD=\"$TMPDIR/defer-state-guard\"#" \
    -e "s#^NETWORK_READINESS=.*#NETWORK_READINESS=\"$TMPDIR/defer-network-readiness\"#" \
    "$TMPDIR/defer-tool.sh"
if defer_output=$(env PATH="$TMPDIR/defer-bin:/usr/sbin:/usr/bin" \
        NOID_SYS_CLASS_NET="$TMPDIR/defer-sys" NOID_ARP_IFACE=mock0 \
        NOID_ARP_DEFER_MISSING_NETWORK=1 \
        bash "$TMPDIR/defer-tool.sh" learn 2>"$TMPDIR/defer.stderr") \
   && [ ! -s "$TMPDIR/defer.stderr" ]; then
    _pass "pre-DHCP hardware NIC defers cleanly without a failed unit"
else
    _fail "pre-DHCP hardware NIC did not use the clean deferred lifecycle"
fi
if grep -Fq \
        'no default IPv4 gateway on mock0; deferred with native ARP/ACD and fail-closed topology active' \
        <<<"$defer_output"; then
    _pass "pre-DHCP deferral reports the exact retained enforcement boundary"
else
    _fail "pre-DHCP deferral did not report its retained enforcement boundary"
fi

# The pre-network validator is the sole early M04 gate.
assert_grep_fixed 'Before=NetworkManager.service network-pre.target' \
    "$TMPDIR/state-guard.service" \
    "state validation precedes NetworkManager and network-pre"
assert_grep_fixed 'CapabilityBoundingSet=' "$TMPDIR/state-guard.service" \
    "read-only state validator has an empty capability bounding set"
assert_grep_fixed 'Requires=noid-arp-state-guard.service' "$TMPDIR/nm-require.conf" \
    "NetworkManager requires the closed state contract"
assert_grep_fixed 'After=noid-arp-state-guard.service' "$TMPDIR/nm-require.conf" \
    "NetworkManager starts only after validation"
assert_grep_fixed 'systemctl enable noid-arp-state-guard.service noid-arp-hardening-firstboot.service' \
    "$KS_FILE" "state guard and firstboot learner are durably enabled"
assert_grep_fixed \
    'rm -f /etc/systemd/system/NetworkManager.service.d/21-noid-arp-bootstrap.conf' \
    "$KS_FILE" "live migration removes the retired NetworkManager requirement"
assert_grep_fixed \
    'systemctl disable --now noid-arp-bootstrap.service >/dev/null 2>&1 || true' \
    "$KS_FILE" "retired runtime guard is stopped only on a reloaded manager"
assert_grep_fixed \
    'systemctl disable noid-arp-bootstrap.service >/dev/null 2>&1 || true' \
    "$KS_FILE" "offline migration disables boot activation without a live stop"
assert_cmd_success "live migration forgets the Requires edge before stopping its guard" \
    python3 - "$KS_FILE" <<'PY'
import sys

text = open(sys.argv[1], encoding="utf-8").read()
drop = text.index(
    "rm -f /etc/systemd/system/NetworkManager.service.d/"
    "21-noid-arp-bootstrap.conf"
)
reload = text.index("if systemctl daemon-reload", drop)
stop = text.index(
    "systemctl disable --now noid-arp-bootstrap.service", reload
)
assert drop < reload < stop
PY

# Root-owned state/marker/dispatcher metadata and schema are exact.
assert_grep_fixed "stat -Lc '%u:%g:%a:%h'" "$TMPDIR/state-guard.sh" \
    "state guard binds ownership, mode, link count and file type"
assert_grep_fixed '0:0:$mode:1' "$TMPDIR/state-guard.sh" \
    "state guard accepts only root-owned single-link regular files"
assert_grep_fixed '[ "$metadata" = 0:0:755 ]' "$TMPDIR/state-guard.sh" \
    "state guard binds every root-owned non-writable contract directory"
assert_grep_fixed 'require_directory "$DISPATCHER_DIR"' \
    "$TMPDIR/state-guard.sh" \
    "state guard binds NetworkManager's dispatcher parent"
assert_grep_fixed 'require_directory "$PREUP_DIR"' \
    "$TMPDIR/state-guard.sh" \
    "state guard binds NetworkManager's awaited dispatcher parent"
assert_grep_fixed 'require_directory "$NOWAIT_DIR"' \
    "$TMPDIR/state-guard.sh" \
    "state guard binds NetworkManager's no-wait dispatcher parent"
assert_grep_fixed 'state["ENABLED"] not in {"0", "1"}' "$TMPDIR/state-guard.sh" \
    "closed schema distinguishes active pin from explicit pin opt-out"
assert_grep_fixed 'r"[A-Za-z0-9_.-]{1,15}"' "$TMPDIR/state-guard.sh" \
    "state schema enforces the Linux interface-name limit"
assert_grep_fixed 'gateway = ipaddress.IPv4Address(state["GATEWAY_IP"])' \
    "$TMPDIR/state-guard.sh" \
    "gateway IPv4 must be canonical"
assert_grep_fixed 'gateway.is_unspecified' "$TMPDIR/state-guard.sh" \
    "unspecified 0.0.0.0 can never become durable gateway identity"
assert_grep_fixed 'enabled state conflicts with disabled marker' "$TMPDIR/state-guard.sh"
assert_grep_fixed 'disabled identity state lacks its explicit marker' "$TMPDIR/state-guard.sh"
assert_grep_fixed 'generated dispatcher exists without gateway state' "$TMPDIR/state-guard.sh"
assert_grep_fixed 'bash -n "$PREUP"' "$TMPDIR/state-guard.sh" \
    "active awaited dispatcher is syntax checked at boot"
assert_grep_fixed 'bash -n "$NOWAIT"' "$TMPDIR/state-guard.sh" \
    "active no-wait dispatcher is syntax checked at boot"
assert_grep_fixed '"$TEMPLATE" | cmp -s - "$PREUP"' \
    "$TMPDIR/state-guard.sh" \
    "awaited dispatcher bytes derive from the validated gateway identity"
assert_grep_fixed 'cmp -s -- "$PREUP" "$NOWAIT"' \
    "$TMPDIR/state-guard.sh" \
    "awaited and no-wait dispatcher bytes must match"
assert_grep_fixed 'no-wait.d/90-arp-hardening' "$TMPDIR/state-guard.sh" \
    "normal dispatcher symlink is bound to NetworkManager's no-wait path"

# Initial and generated dispatchers are awaited, hardware/provider neutral and
# fail closed after DHCP without suppressing standard ARP/ACD.
assert_grep_fixed '/etc/NetworkManager/dispatcher.d/25-noid-arp-initial-learn' \
    "$KS_FILE" "one canonical initial learner is installed"
assert_grep_fixed 'ln -sfnT ../25-noid-arp-initial-learn' "$KS_FILE" \
    "initial learner has an exact awaited pre-up symlink"
assert_grep_fixed 'pre-up|up|dhcp4-change' "$TMPDIR/initial-dispatcher.sh"
assert_grep_fixed '[ -d "$SYS_CLASS_NET/$iface/device" ]' \
    "$TMPDIR/initial-dispatcher.sh" \
    "initial learner uses hardware backing rather than provider names"
assert_not_grep_extended 'proton|mullvad|pvpn|wg\*|tun\*' "$TMPDIR/tool.sh" \
    "physical-interface detection is VPN-provider agnostic"
# A failed pin is not an attack. Only a contested gateway identity -- two
# bounded observations disagreeing about who owns the address -- leaves a
# boundary open that this layer cannot close, and only that reaches the link.
assert_grep_fixed 'gateway identity is contested on $iface; disconnecting' \
    "$TMPDIR/initial-dispatcher.sh" \
    "a contested gateway identity still takes the affected interface down"
for route_consumer in "$TMPDIR/initial-dispatcher.sh" \
                      "$TMPDIR/dispatcher.sh" "$TMPDIR/tool.sh"; do
    assert_grep_fixed 'if ($i=="via") {print $(i+1); exit}' \
        "$route_consumer" \
        "route parser ${route_consumer##*/} finds the named via field"
    assert_not_grep_extended 'awk.*\{print[[:space:]]+\$3' \
        "$route_consumer" \
        "route parser ${route_consumer##*/} has no positional gateway assumption"
done
assert_not_grep '^[[:space:]]*arping[[:space:]]' "$TMPDIR/dispatcher.sh" \
    "dispatcher delegates every raw observation to the transactional tool"
assert_grep_fixed 'gateway identity revalidated and boundary postchecked' \
    "$TMPDIR/dispatcher.sh" \
    "active link events revalidate same-IP gateway identity"
assert_grep_fixed 'NOID_ARP_ACTIVATION_READY_V1' \
    "$TMPDIR/dispatcher.sh" \
    "activation coalescing uses one versioned runtime marker"
assert_grep_fixed \
    '[[ "$EVENT_UUID" =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ ]]' \
    "$TMPDIR/dispatcher.sh" \
    "activation generation is bound to a canonical NetworkManager UUID"
assert_grep_fixed \
    'if [ "$ACTION" = dhcp4-change ] && valid_event_uuid' \
    "$TMPDIR/dispatcher.sh" \
    "pre-up DHCP queue entries use the exact activation-generation gate"
assert_grep_fixed \
    'gateway revalidation deferred until activation up event' \
    "$TMPDIR/dispatcher.sh" \
    "early DHCP work remains explicitly deferred and fail-closed"
assert_grep_fixed \
    'if [ "$ACTION" = up ] && valid_event_uuid' \
    "$TMPDIR/dispatcher.sh" \
    "the final activation event owns generation publication"
refresh_line=$(grep -nF '        trigger_refresh "revalidate interface=$IFACE"' \
    "$TMPDIR/dispatcher.sh" \
    | head -1 | cut -d: -f1 || true)
generation_line=$(grep -nF '&& ! publish_activation_marker; then' \
    "$TMPDIR/dispatcher.sh" | head -1 | cut -d: -f1 || true)
if [ -n "$refresh_line" ] && [ -n "$generation_line" ] \
   && [ "$refresh_line" -lt "$generation_line" ]; then
    _pass "activation generation is published only after full gateway refresh"
else
    _fail "activation generation must follow full gateway refresh"
fi
unset refresh_line generation_line
assert_grep_fixed "grep -Fq 'pre-up|up|dhcp4-change)'" "$KS_FILE" \
    "compose verifies the installed awaited event set as fixed text"
assert_grep_fixed 'grep -Fq '\''"$NETWORK_READINESS" offline'\''' "$KS_FILE" \
    "compose verifies readiness retirement in installed dispatcher bytes"
assert_grep_fixed \
    'grep -Fq '\''NOID_ARP_IFACE="$IFACE" NOID_ARP_GATEWAY_IP="$CURRENT_GW"'\''' \
    "$KS_FILE" \
    "compose verifies exact-interface transactional refresh in installed bytes"
assert_grep_fixed \
    "grep -Fq 'gateway identity revalidated and boundary postchecked'" \
    "$KS_FILE" \
    "compose verification is anchored to a current executable postcondition"
assert_not_grep 'same-IP MAC changes require explicit re-learn' "$KS_FILE" \
    "compose has no retired prose-only trust-boundary probe"
assert_grep_fixed 'pin_recorded_identity_on_event_iface' \
    "$TMPDIR/dispatcher.sh" \
    "pre-up restores the validated pin on the exact event interface"
assert_grep_fixed '[ "$observed" = "$GATEWAY_MAC" ]' \
    "$TMPDIR/dispatcher.sh" \
    "pre-up restore postchecks the exact permanent neighbour identity"
assert_grep_fixed 'if ! pin_recorded_identity_on_event_iface; then' \
    "$TMPDIR/dispatcher.sh" \
    "ordinary pre-up restoration uses the same exact pin postcondition"
assert_not_grep 'roam re-learn deferred' "$TMPDIR/dispatcher.sh" \
    "stale gateway identity is never retained as a roam fallback"
assert_grep_fixed 'if [ "$gateway" = 0.0.0.0 ]; then' \
    "$TMPDIR/initial-dispatcher.sh" \
    "NetworkManager no-gateway sentinel is treated as absent"
assert_grep_fixed '[ "$IP4_GATEWAY" = 0.0.0.0 ] || printf' \
    "$TMPDIR/dispatcher.sh" \
    "generated dispatcher ignores the no-gateway sentinel"
for event_consumer in "$TMPDIR/initial-dispatcher.sh" \
                      "$TMPDIR/dispatcher.sh"; do
    assert_grep_fixed '"$NETWORK_READINESS" offline' "$event_consumer" \
        "link transitions retire readiness in ${event_consumer##*/}"
done

# Transactional tool: native observation, exact permanent pin, private lock,
# atomic files and retained fail-closed identity on explicit disable.
assert_grep_fixed 'arping -c3 -w5 -I "$iface" "$gateway_ip"' "$TMPDIR/tool.sh"
assert_grep_fixed 'ip -4 neigh show to "$gateway_ip" dev "$iface"' "$TMPDIR/tool.sh" \
    "gateway observation is exact-device scoped"
assert_grep_fixed '[ "$neighbor_count" -le 1 ]' \
    "$TMPDIR/tool.sh" "gateway observation rejects ambiguous kernel records"
assert_grep_fixed '[ "$first_macs" = "$second_macs" ]' \
    "$TMPDIR/tool.sh" \
    "empty kernel cache requires two matching bounded raw observations"
assert_grep_fixed 'sleep 1' "$TMPDIR/tool.sh" \
    "empty-cache observations are time-separated"
assert_grep_fixed 'ip neigh replace "$gateway_ip" lladdr "$gateway_mac" dev "$iface" nud permanent' \
    "$TMPDIR/tool.sh" "trust becomes one exact permanent neighbour pin"
assert_grep_fixed 'flock -x "$TX_LOCK_FD"' "$TMPDIR/tool.sh" \
    "all mutations share one serialization lock"
assert_grep_fixed '$EXPECTED_OWNER:$EXPECTED_GROUP:600:1' \
    "$TMPDIR/tool.sh" "transaction lock is private, owned and single-linked"
assert_grep_fixed 'trap cleanup_transaction EXIT' "$TMPDIR/tool.sh" \
    "ordinary failures use transactional rollback"
assert_grep_fixed "trap 'exit 143' TERM" "$TMPDIR/tool.sh" \
    "TERM reaches the same rollback"
assert_grep_fixed 'atomic_publish "$TX_DIR/90-arp-hardening" "$NM_DISPATCHER_PREUP" 0700' \
    "$TMPDIR/tool.sh" "awaited dispatcher copy is atomically published"
assert_grep_fixed 'atomic_publish "$TX_DIR/90-arp-hardening" "$NM_DISPATCHER_NOWAIT" 0700' \
    "$TMPDIR/tool.sh" "ordinary dispatcher copy is atomically published no-wait"
assert_grep_fixed 'atomic_symlink_publish no-wait.d/90-arp-hardening "$NM_DISPATCHER"' \
    "$TMPDIR/tool.sh" "normal dispatcher entry is atomically linked no-wait"
assert_grep_fixed 'bash -n "$TX_DIR/90-arp-hardening"' "$TMPDIR/tool.sh" \
    "generated dispatcher is parsed before publication"
assert_grep_fixed 'published gateway identity contract failed validation' \
    "$TMPDIR/tool.sh" \
    "learn validates the complete published multi-file contract"
assert_grep_fixed 'published kernel-pin opt-out contract failed validation' \
    "$TMPDIR/tool.sh" \
    "disable validates the complete published multi-file contract"
assert_not_grep_extended '^[[:space:]]*\.[[:space:]]+"?\$STATE_FILE' \
    "$TMPDIR/tool.sh" "root state is parsed as data, never sourced"
assert_grep_fixed 'ENABLED=0' "$TMPDIR/tool.sh" \
    "explicit disable retains the validated gateway identity"
assert_grep_fixed 'M03 XDP gateway identity retained' "$TMPDIR/tool.sh" \
    "pin opt-out cannot silently open LAN isolation"
assert_grep_fixed '/usr/local/sbin/noid-lan-topology-refresh.sh' "$TMPDIR/tool.sh" \
    "every identity transition revalidates the real enforcement path"
assert_grep_fixed 'topology refresh changed or removed the validated permanent gateway pin' \
    "$TMPDIR/tool.sh" "learn has an exact post-topology pin postcondition"
assert_grep_fixed 'an approved M05 peer policy restored the gateway pin' \
    "$TMPDIR/tool.sh" "disable cannot overclaim an opt-out when M05 owns the same pin"
assert_grep_fixed '"$NETWORK_READINESS" offline' "$TMPDIR/tool.sh" \
    "transaction retires readiness before gateway observation"
assert_grep_fixed '"$NETWORK_READINESS" ready' "$TMPDIR/tool.sh" \
    "transaction publishes readiness only after boundary validation"
assert_grep_fixed 'NOID_GATEWAY_XDP_READY_V1' "$TMPDIR/network-readiness.sh" \
    "readiness marker has an exact versioned content contract"
assert_grep_fixed "stat -Lc '%s' \"\$XDP_HEALTH\"" \
    "$TMPDIR/network-readiness.sh" \
    "readiness binds the complete XDP health-file byte count"
assert_grep_fixed "'STATE=ACTIVE:DETAIL=verified'" "$TMPDIR/network-readiness.sh" \
    "readiness accepts the fully verified XDP health contract"

{
    printf '%s\n' '#!/bin/bash' 'set -euo pipefail' 'XDP_HEALTH=$1'
    awk '
        /^runtime_boundary_verified\(\)/ { copy=1 }
        /^boundary_verified\(\)/ { exit }
        copy { print }
    ' "$TMPDIR/network-readiness.sh"
    printf '%s\n' 'runtime_boundary_verified'
} > "$TMPDIR/runtime-boundary-fixture.sh"
sed -i "s/0:0:644:1/$(id -u):$(id -g):644:1/" \
    "$TMPDIR/runtime-boundary-fixture.sh"
chmod 0755 "$TMPDIR/runtime-boundary-fixture.sh"
printf '%s\n' 'STATE=ACTIVE' 'DETAIL=verified' > "$TMPDIR/xdp-health"
chmod 0644 "$TMPDIR/xdp-health"
assert_cmd_success "readiness accepts the exact two-line XDP health file" \
    "$TMPDIR/runtime-boundary-fixture.sh" "$TMPDIR/xdp-health"
printf '%s' 'TRAILING' >> "$TMPDIR/xdp-health"
assert_cmd_failure "readiness rejects trailing bytes without a final newline" \
    "$TMPDIR/runtime-boundary-fixture.sh" "$TMPDIR/xdp-health"
# M03 owns the XDP/TC boundary and fails its topology transaction whenever the
# current LAN state requires XDP. Once that owner has returned success, M04 may
# accept any value in M03's closed vocabulary: refusing one cannot repair XDP
# and only withholds the shared marker. That marker brings M11's NTS sources
# online and lets M06 resolve a configured VPN endpoint before WAN-strict
# reconciliation. The latter still requires the validated ARP state and OS
# resolver; XDP is not part of its DNS trust chain. Reporting remains loud, and
# tests/00-degradation-contract.py holds this accepted set equal to M03's.
for degraded_detail in no-ethernet-link unsupported-link-type \
        physical-ipv6-unsupported controller-missing sync-or-postcheck-failed; do
    assert_grep_fixed "'STATE=DEGRADED:DETAIL=${degraded_detail}'" \
        "$TMPDIR/network-readiness.sh" \
        "readiness accepts M03's documented degradation: $degraded_detail"
done
# An unknown reason must still fail closed: accepting the closed vocabulary is
# not the same as accepting anything that says DEGRADED.
assert_not_grep "STATE=DEGRADED:DETAIL=\*" "$TMPDIR/network-readiness.sh" \
    "readiness never wildcards the degraded vocabulary"
assert_grep_fixed 'CHRONY_OFFLINE_UNIT=noid-chrony-network-offline.service' \
    "$TMPDIR/network-readiness.sh" \
    "readiness names the dedicated SELinux-compatible offline one-shot"
assert_grep_fixed 'systemctl start "$CHRONY_OFFLINE_UNIT"' \
    "$TMPDIR/network-readiness.sh" \
    "caller domains synchronously delegate NTS offline transition to PID 1"
assert_grep_fixed 'offline-consumer)' "$TMPDIR/network-readiness.sh" \
    "dedicated offline service has one closed helper action"
assert_not_grep '/usr/bin/chronyc -u root offline' \
    "$TMPDIR/network-readiness.sh" \
    "NoNewPrivileges and NetworkManager callers never invoke chronyc directly"
assert_grep_fixed \
    'CHRONY_TRANSITION_LOCK=/run/chrony/noid-network-readiness.lock' \
    "$TMPDIR/network-readiness.sh" \
    "chrony transitions share one private native runtime lock"
assert_grep_fixed 'umask 077' "$TMPDIR/network-readiness.sh" \
    "chrony transition lock is created private by default"
assert_grep_fixed '/usr/bin/flock --exclusive 9' \
    "$TMPDIR/network-readiness.sh" \
    "chrony transition lock is blocking and exclusive"
assert_eq "2" \
    "$(grep -c '^[[:space:]]*lock_chrony_transition$' \
        "$TMPDIR/network-readiness.sh")" \
    "both online and offline consumers serialize their chronyc transaction"
# errexit exempts every command of an AND-OR list except the last one, so an
# assertion written as a bare `[ -f x ] && [ ! -L x ]` statement falls straight
# through when the first test is false. Proven here rather than asserted, so a
# future reader sees the semantics and not just the rule:
assert_cmd_success "errexit lets a bare AND-OR assertion fall through" \
    bash -c 'set -euo pipefail; [ -f /nonexistent ] && [ ! -L /nonexistent ]; exit 0'
assert_cmd_failure "the same tests as separate statements abort" \
    bash -c 'set -euo pipefail; [ -f /nonexistent ]; [ ! -L /nonexistent ]; exit 0'
# Both guards therefore stay one statement per line. For the transition lock a
# fall-through would let `exec 9>` create whatever a dangling symlink points at.
assert_grep_extended '^\s+\[ -f "\$CHRONY_TRANSITION_LOCK" \]\s*$' \
    "$TMPDIR/network-readiness.sh" \
    "transition lock regular-file guard terminates on its own"
assert_grep_extended '^\s+\[ ! -L "\$CHRONY_TRANSITION_LOCK" \]\s*$' \
    "$TMPDIR/network-readiness.sh" \
    "transition lock symlink guard terminates on its own"
assert_grep_extended \
    '^\s+\[ -f "/etc/systemd/system/\$CHRONY_ONLINE_UNIT" \]\s*$' \
    "$TMPDIR/network-readiness.sh" \
    "online unit-file existence guard terminates on its own"
assert_grep_extended \
    '^\s+\[ ! -L "/etc/systemd/system/\$CHRONY_ONLINE_UNIT" \]\s*$' \
    "$TMPDIR/network-readiness.sh" \
    "online unit-file symlink guard terminates on its own"
assert_grep_fixed 'valid_ready || exit 0' "$TMPDIR/network-readiness.sh" \
    "a queued online job can cancel cleanly after readiness retirement"
assert_grep_fixed '/usr/bin/chronyc -u chrony online' \
    "$TMPDIR/network-readiness.sh" \
    "unprivileged consumer explicitly brings offline NTS sources online"
assert_grep_fixed '/usr/bin/chronyc -u chrony offline' \
    "$TMPDIR/network-readiness.sh" \
    "consumer closes a link-race by returning NTS sources offline"
assert_grep_fixed 'consumer-precheck)' "$TMPDIR/network-readiness.sh" \
    "root-only state guard has one closed preflight action"
assert_grep_fixed 'runtime_boundary_verified' "$TMPDIR/network-readiness.sh" \
    "unprivileged consumer rechecks the public XDP runtime boundary"
assert_grep_fixed 'CHRONY_MIN_ONLINE=3' "$TMPDIR/network-readiness.sh" \
    "chrony readiness matches M11 minsources"
assert_grep_fixed 'CHRONY_ONLINE_ATTEMPTS=600' \
    "$TMPDIR/network-readiness.sh" \
    "asynchronous chrony source resolution has a two-minute bound"
assert_grep_fixed 'while [ "$attempt" -lt "$CHRONY_ONLINE_ATTEMPTS" ]; do' \
    "$TMPDIR/network-readiness.sh" \
    "chrony resolver polling consumes the explicit bounded budget"
assert_grep_fixed 'if [ "$online" -ge "$CHRONY_MIN_ONLINE" ]; then' \
    "$TMPDIR/network-readiness.sh" \
    "one resolved source cannot satisfy a three-source selection policy"
assert_grep_fixed 'waiting for chrony resolver readiness:' \
    "$TMPDIR/network-readiness.sh" \
    "slow resolver progress is aggregate and journal-visible"
assert_grep_fixed 'chrony resolver readiness timed out:' \
    "$TMPDIR/network-readiness.sh" \
    "bounded exhaustion records the final aggregate cause"
assert_grep_fixed '/usr/bin/sleep 0.2' "$TMPDIR/network-readiness.sh" \
    "chrony readiness polling has a fixed short interval"
assert_grep_fixed 'attempt=$((attempt + 1))' \
    "$TMPDIR/network-readiness.sh" \
    "chrony readiness polling cannot become unbounded"

# Exercise the extracted consumer against the exact activity vocabulary.  The
# first sequence reproduces a resolver that has two usable addresses before it
# reaches the configured three-source selection floor.  The second proves that
# bounded exhaustion returns every source offline and records why.
chrony_fixture="$TMPDIR/chrony-readiness-fixture"
chrony_bin="$chrony_fixture/bin"
chrony_run="$chrony_fixture/run"
chrony_log="$chrony_fixture/commands.log"
chrony_logger="$chrony_fixture/logger.log"
chrony_sequence="$chrony_fixture/activity.sequence"
chrony_count="$chrony_fixture/activity.count"
fixture_uid=$(id -u)
fixture_gid=$(id -g)
mkdir -p "$chrony_bin" "$chrony_run/noid-privacy" "$chrony_run/chrony"
chmod 0755 "$chrony_run/noid-privacy"
chmod 0750 "$chrony_run/chrony"
printf '%s\n' NOID_GATEWAY_XDP_READY_V1 \
    > "$chrony_run/noid-privacy/gateway-xdp.ready"
printf '%s\n' STATE=ACTIVE DETAIL=verified \
    > "$chrony_run/noid-privacy/lan-xdp-health"
chmod 0644 "$chrony_run/noid-privacy/gateway-xdp.ready" \
    "$chrony_run/noid-privacy/lan-xdp-health"

cat > "$chrony_bin/state-guard" <<'CHRONY_GUARD_EOF'
#!/bin/sh
exit 0
CHRONY_GUARD_EOF
cat > "$chrony_bin/id" <<CHRONY_ID_EOF
#!/bin/sh
case "\${1:-}:\${2:-}" in
    -u:chrony) printf '%s\\n' '$fixture_uid' ;;
    -g:chrony) printf '%s\\n' '$fixture_gid' ;;
    *) exec /usr/bin/id "\$@" ;;
esac
CHRONY_ID_EOF
cat > "$chrony_bin/systemctl" <<'CHRONY_SYSTEMCTL_EOF'
#!/bin/sh
case "$*" in
    'is-active --quiet chronyd-restricted.service') exit 0 ;;
    *) exit 1 ;;
esac
CHRONY_SYSTEMCTL_EOF
cat > "$chrony_bin/chronyc" <<'CHRONY_CHRONYC_EOF'
#!/bin/bash
set -euo pipefail
printf '%s\n' "${*: -1}" >> "$NOID_CHRONY_COMMAND_LOG"
case "${*: -1}" in
    online|offline) exit 0 ;;
    activity)
        count=0
        [ ! -s "$NOID_CHRONY_COUNT" ] || read -r count < "$NOID_CHRONY_COUNT"
        count=$((count + 1))
        printf '%s\n' "$count" > "$NOID_CHRONY_COUNT"
        row=$(/usr/bin/sed -n "${count}p" "$NOID_CHRONY_SEQUENCE")
        [ -n "$row" ] || row=$(/usr/bin/tail -n 1 "$NOID_CHRONY_SEQUENCE")
        read -r online burst unknown <<<"$row"
        printf '%s\n' \
            '200 OK' \
            "$online sources online" \
            '0 sources offline' \
            "$burst sources doing burst (return to online)" \
            '0 sources doing burst (return to offline)' \
            "$unknown sources with unknown address"
        ;;
    *) exit 64 ;;
esac
CHRONY_CHRONYC_EOF
cat > "$chrony_bin/logger" <<'CHRONY_LOGGER_EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$NOID_CHRONY_LOGGER_LOG"
CHRONY_LOGGER_EOF
cat > "$chrony_bin/sleep" <<'CHRONY_SLEEP_EOF'
#!/bin/sh
exit 0
CHRONY_SLEEP_EOF
cat > "$chrony_bin/flock" <<'CHRONY_FLOCK_EOF'
#!/bin/sh
exit 0
CHRONY_FLOCK_EOF
chmod 0755 "$chrony_bin"/*

cp "$TMPDIR/network-readiness.sh" "$chrony_fixture/consumer"
sed -i \
    -e "s|^READY_DIR=.*|READY_DIR=$chrony_run/noid-privacy|" \
    -e "s|^XDP_HEALTH=.*|XDP_HEALTH=$chrony_run/noid-privacy/lan-xdp-health|" \
    -e "s|^STATE_GUARD=.*|STATE_GUARD=$chrony_bin/state-guard|" \
    -e 's|^CHRONY_ONLINE_ATTEMPTS=.*|CHRONY_ONLINE_ATTEMPTS=6|' \
    -e 's|^CHRONY_ACTIVITY_LOG_EVERY=.*|CHRONY_ACTIVITY_LOG_EVERY=1|' \
    -e "s|/run/chrony|$chrony_run/chrony|g" \
    -e "s|^CHRONY_TRANSITION_LOCK=.*|CHRONY_TRANSITION_LOCK=$chrony_run/chrony/noid-network-readiness.lock|" \
    -e "s|/usr/bin/chronyc|$chrony_bin/chronyc|g" \
    -e "s|/usr/bin/logger|$chrony_bin/logger|g" \
    -e "s|/usr/bin/sleep|$chrony_bin/sleep|g" \
    -e "s|/usr/bin/flock|$chrony_bin/flock|g" \
    -e "s|0:0:755|$fixture_uid:$fixture_gid:755|g" \
    -e "s|0:0:644:1|$fixture_uid:$fixture_gid:644:1|g" \
    "$chrony_fixture/consumer"
assert_cmd_success "chrony resolver fixture helper remains valid Bash" \
    bash -n "$chrony_fixture/consumer"

run_chrony_fixture() {
    env PATH="$chrony_bin:/usr/sbin:/usr/bin" \
        NOID_CHRONY_COMMAND_LOG="$chrony_log" \
        NOID_CHRONY_LOGGER_LOG="$chrony_logger" \
        NOID_CHRONY_SEQUENCE="$chrony_sequence" \
        NOID_CHRONY_COUNT="$chrony_count" \
        bash "$chrony_fixture/consumer" online-consumer
}

printf '%s\n' '0 0 6' '2 1 3' '3 1 2' > "$chrony_sequence"
: > "$chrony_log"
: > "$chrony_logger"
: > "$chrony_count"
assert_cmd_success "chrony readiness waits through a two-source DNS state" \
    run_chrony_fixture
assert_eq 3 "$(grep -c '^activity$' "$chrony_log")" \
    "consumer accepts only the first three-source activity sample"
assert_not_grep_extended '^offline$' "$chrony_log" \
    "successful resolver convergence does not return sources offline"
assert_grep_fixed \
    'chrony resolver readiness reached: online=3 burst=1 unknown=2 activity_ok=1' \
    "$chrony_logger" \
    "success evidence records aggregate resolved/unknown state"

printf '%s\n' '2 0 4' > "$chrony_sequence"
: > "$chrony_log"
: > "$chrony_logger"
: > "$chrony_count"
assert_cmd_failure "sub-minsources resolver state exhausts the bounded budget" \
    run_chrony_fixture
assert_eq 6 "$(grep -c '^activity$' "$chrony_log")" \
    "consumer performs exactly its configured number of attempts"
assert_grep_extended '^offline$' "$chrony_log" \
    "bounded resolver failure returns all sources offline"
assert_grep_fixed \
    'chrony resolver readiness timed out: online=2 burst=0 unknown=4 activity_ok=1 required=3 elapsed_s=1' \
    "$chrony_logger" \
    "timeout evidence reports the final aggregate cause"

assert_grep_fixed 'systemctl is-active --quiet "$WAN_SCAN_PATH"' \
    "$TMPDIR/network-readiness.sh" \
    "WAN hostname reconciliation is queued only when WAN strict is active"
assert_grep_fixed 'ExecStart=/usr/local/sbin/noid-arp-hardening.sh --silent learn' \
    "$TMPDIR/firstboot.service" \
    "firstboot keeps interactive gateway identity out of the journal"
state_guard_line=$(grep -nF 'if ! "$STATE_GUARD"; then' \
    "$TMPDIR/initial-dispatcher.sh" | head -1 | cut -d: -f1 || true)
state_skip_line=$(grep -nF 'if [ -e "$STATE" ]; then' \
    "$TMPDIR/initial-dispatcher.sh" | head -1 | cut -d: -f1 || true)
offline_line=$(grep -nF '"$NETWORK_READINESS" offline' \
    "$TMPDIR/initial-dispatcher.sh" | tail -1 | cut -d: -f1 || true)
if [ -n "$state_guard_line" ] && [ -n "$state_skip_line" ] \
   && [ -n "$offline_line" ] \
   && [ "$state_guard_line" -lt "$state_skip_line" ] \
   && [ "$state_skip_line" -lt "$offline_line" ]; then
    _pass "initial learner validates and retires readiness only for an empty identity lifecycle"
else
    _fail "initial learner must leave established transitions to the generated dispatcher"
fi
unset state_guard_line state_skip_line offline_line
# cmd_disable keeps the state file at ENABLED=0 but deletes both generated
# dispatchers, so from the next boot on nothing else recreates
# gateway-xdp.ready. chrony's sources are declared offline and only
# noid-chrony-network-online.service brings them up, gated on that file, so
# without this republication the clock free-runs silently after a documented
# `noid-arp-hardening.sh disable`.
assert_grep_fixed '"$NETWORK_READINESS" ready || exit 1' \
    "$TMPDIR/initial-dispatcher.sh" \
    "initial learner republishes readiness for the durably disabled state"
disabled_ready_line=$(grep -nF '"$NETWORK_READINESS" ready || exit 1' \
    "$TMPDIR/initial-dispatcher.sh" | head -1 | cut -d: -f1 || true)
disabled_guard_line=$(grep -nF 'if [ -e "$DISABLED" ]; then' \
    "$TMPDIR/initial-dispatcher.sh" | head -1 | cut -d: -f1 || true)
if [ -n "$disabled_ready_line" ] && [ -n "$disabled_guard_line" ] \
   && [ "$disabled_guard_line" -lt "$disabled_ready_line" ]; then
    _pass "readiness republication is reached only through the opt-out marker"
else
    _fail "readiness republication must stay behind the durable opt-out marker"
fi
unset disabled_ready_line disabled_guard_line

# No retired table, fake firewalld reload hook or daemon reload remains inside
# any runtime script. The paths occur in the KS only in explicit removal and
# absence-verification lists.
for runtime in "$TMPDIR/state-guard.sh" "$TMPDIR/initial-dispatcher.sh" \
               "$TMPDIR/dispatcher.sh" "$TMPDIR/tool.sh"; do
    assert_not_grep_extended '(^|[[:space:]])nft([[:space:]]|$)|arp_hardening|ExecStartPost|systemctl daemon-reload' \
        "$runtime" "runtime ${runtime##*/} has no shadow nft/firewalld machinery"
done
assert_grep_fixed 'retired non-enforcing artifact remains' "$KS_FILE" \
    "compose verification requires every retired artifact to be absent"
assert_grep_fixed 'if /usr/local/sbin/noid-arp-state-guard.sh; then' \
    "$KS_FILE" "compose executes the complete empty-state lifecycle guard"

# Firstboot is one-shot/offline-quiescent and has only the writes and
# capabilities needed for arping, neighbour updates and M03 BPF refresh.
assert_grep_fixed 'Requires=noid-arp-state-guard.service' "$TMPDIR/firstboot.service"
assert_grep_fixed 'Environment=NOID_ARP_DEFER_MISSING_NETWORK=1' "$TMPDIR/firstboot.service"
assert_grep_fixed 'gateway_ip=$(detect_gateway_ip "$iface" || true)' \
    "$TMPDIR/tool.sh" \
    "missing pre-DHCP gateway reaches the explicit deferred lifecycle"
assert_grep_fixed 'Restart=no' "$TMPDIR/firstboot.service"
assert_not_grep_extended 'NetworkManager-wait-online\.service|Restart=on-failure' \
    "$TMPDIR/firstboot.service" "offline boot creates no wait/restart loop"
assert_grep_fixed 'ReadWritePaths=/etc/NetworkManager/dispatcher.d /var/lib/noid-privacy /run -/sys/fs/bpf' \
    "$TMPDIR/firstboot.service" "firstboot write surface is minimal"
assert_grep_fixed 'CapabilityBoundingSet=CAP_CHOWN CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_PERFMON' \
    "$TMPDIR/firstboot.service"
assert_grep_fixed 'RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK AF_PACKET' \
    "$TMPDIR/firstboot.service"
assert_not_grep '/etc/nftables|/etc/systemd/system' "$TMPDIR/firstboot.service" \
    "firstboot no longer writes nft or unit configuration"


# --- NoID Privacy journal must not accumulate a per-network location history ---
# Scripted learn runs are silent, and the generated dispatcher logs only the
# interface reason code. The exact current identity belongs in the state file
# and interactive output, not in a timestamped NoID Privacy journal history.
assert_grep_fixed 'logger -t noid-arp "ENABLED (gateway pinned on $iface)"' "$KS_FILE" \
    "learn confirmation names the interface, not the peer identity"
assert_not_grep 'logger .*gateway_mac' "$KS_FILE" \
    "no journal line carries the gateway MAC"
assert_grep_fixed 'trigger_refresh "revalidate interface=$IFACE"' \
    "$TMPDIR/dispatcher.sh" \
    "dispatcher journal reason carries only its interface"
assert_not_grep_extended \
    'revalidate .*GATEWAY_IP|revalidate .*CURRENT_GW' \
    "$TMPDIR/dispatcher.sh" \
    "dispatcher journal reason carries no gateway IP"
assert_grep_fixed 'dev "$WAN_IFACE" 2>/dev/null || true)' \
    "$TMPDIR/tool.sh" \
    "a vanished interface cannot abort status before its diagnosis"
assert_grep_fixed 'unavailable [interface not present]' "$TMPDIR/tool.sh" \
    "status names a vanished recorded interface explicitly"

# The retired Mode B toggle has no runtime owner. Keep its absence as a real
# repository test instead of a compose-time grep that could only warn and whose
# pattern did not occur in the generated tool even before the check ran.
assert_not_grep_extended 'mode[[:space:]]+B|noid-privacy-mode' \
    "$TMPDIR/tool.sh" "ARP tool contains no retired Mode B control surface"


# --- a layer may only tear down what its own failure left open --------------
# Collapsing every detection failure into one exit code made a DHCP race
# indistinguishable from an attack, so an ordinary transient ran
# `nmcli device disconnect` on the owner's link. Exit code 2 now means two
# bounded observations disagree about who owns the gateway address -- the one
# case where the boundary really is open -- and only that reaches the link.
assert_grep_fixed 'return 2' "$KS_FILE" \
    "gateway detection reports a contested identity distinctly"
assert_grep_fixed 'err "conflicting MAC observations for $gateway_ip on $iface"' \
    "$KS_FILE" "a contested identity is named rather than folded into a generic failure"
assert_grep_fixed '[ "$learn_rc" -eq 2 ] && [ "$event" != pre-up ]' "$KS_FILE" \
    "the initial-learn dispatcher disconnects only on a contested identity"
assert_grep_fixed 'severity="${2:-transient}"' "$KS_FILE" \
    "the generated dispatcher defaults to leaving the link alone"
assert_grep_fixed '[ "$severity" = contested ] && [ "$ACTION" != pre-up ]' "$KS_FILE" \
    "the generated dispatcher disconnects only on a contested identity"
assert_grep_fixed 'return "$rc"' "$KS_FILE" \
    "the refresh helper propagates the contested code instead of swallowing it"
# A transient failure must never reach the link, in either dispatcher.
assert_not_grep 'disconnecting unpinned interface' "$KS_FILE" \
    "no dispatcher disconnects a link merely because a pin is absent"
assert_not_grep 'disconnecting affected interface' "$KS_FILE" \
    "no dispatcher disconnects a link on an unclassified failure"

# The readiness gate must not out-strict the layer that owns the boundary.
for detail in no-ethernet-link unsupported-link-type physical-ipv6-unsupported \
              controller-missing sync-or-postcheck-failed; do
    assert_grep_fixed "'STATE=DEGRADED:DETAIL=$detail'" "$KS_FILE" \
        "readiness accepts M03's documented degraded reason: $detail"
done
assert_grep_fixed 'could not hold NTS sources offline via $CHRONY_OFFLINE_UNIT' \
    "$KS_FILE" "a failed time-sync transition is loud instead of fatal"

test_finish
