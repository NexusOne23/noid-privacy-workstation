#!/usr/bin/env bash
# M07 locked policy fixture: exact publication, failure visibility, logger
# independence, hostile metadata, concurrency and interruption rollback.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/07-ipv6-privacy.ks"
test_start "07-ipv6-policy-transaction-fixture"

TMPDIR="$(mktemp -d /var/tmp/noid-test-07-policy.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT
extract_heredoc "$KS_FILE" SCRIPT_EOF "$TMPDIR/helper.sh" || \
    _fail "M07 helper extraction"
extract_heredoc "$KS_FILE" REFRESH_EOF "$TMPDIR/dispatcher.sh" || \
    _fail "M07 dispatcher extraction"
chmod 0755 "$TMPDIR/helper.sh" "$TMPDIR/dispatcher.sh"

mkdir -p "$TMPDIR/bin" "$TMPDIR/sys-class/eth0/device" \
    "$TMPDIR/sys-class/wlan0/device" "$TMPDIR/sys-class/eth1/device" \
    "$TMPDIR/sys-class/wg-uplink/device" "$TMPDIR/sys-class/bravo0/device" \
    "$TMPDIR/sys-class/wan.0/device" \
    "$TMPDIR/sys-class/virtual0" "$TMPDIR/proc/eth0" \
    "$TMPDIR/proc/wlan0" "$TMPDIR/proc/wg-uplink" \
    "$TMPDIR/proc/bravo0" "$TMPDIR/proc/wan.0" \
    "$TMPDIR/proc/virtual0" "$TMPDIR/policy" \
    "$TMPDIR/run" "$TMPDIR/lock" "$TMPDIR/empty-sys"
chmod 0755 "$TMPDIR/policy" "$TMPDIR/run" "$TMPDIR/lock"
printf '0\n' > "$TMPDIR/proc/eth0/disable_ipv6"
printf '0\n' > "$TMPDIR/proc/wlan0/disable_ipv6"
printf '0\n' > "$TMPDIR/proc/wg-uplink/disable_ipv6"
printf '0\n' > "$TMPDIR/proc/bravo0/disable_ipv6"
printf '0\n' > "$TMPDIR/proc/wan.0/disable_ipv6"
printf '0\n' > "$TMPDIR/proc/virtual0/disable_ipv6"
: > "$TMPDIR/cmdline"
: > "$TMPDIR/sysctl.log"
: > "$TMPDIR/logger.log"

cat > "$TMPDIR/bin/sysctl-mock" <<'SYSCTL_MOCK'
#!/bin/bash
set -euo pipefail
[ "${1:-}" = -w ] && [ "$#" -eq 2 ] || exit 2
key=$2
case "$key" in
    net/ipv6/conf/*/disable_ipv6=1)
        iface=${key#net/ipv6/conf/}
        iface=${iface%/disable_ipv6=1}
        ;;
    *) exit 2 ;;
esac
printf 'START %s\n' "$iface" >> "$NOID_SYSCTL_LOG"
if [ -n "${NOID_SYSCTL_MARKER:-}" ]; then : > "$NOID_SYSCTL_MARKER"; fi
if [ -n "${NOID_SYSCTL_DELAY:-}" ]; then sleep "$NOID_SYSCTL_DELAY"; fi
[ "${NOID_SYSCTL_FAIL:-0}" != 1 ] || exit 1
target="$NOID_PROC_IPV6_ROOT/$iface/disable_ipv6"
[ -f "$target" ] || exit 1
printf '1\n' > "$target"
printf 'END %s\n' "$iface" >> "$NOID_SYSCTL_LOG"
SYSCTL_MOCK

cat > "$TMPDIR/bin/ip-mock" <<'IP_MOCK'
#!/bin/bash
printf 'default via 192.0.2.1 dev eth0 proto dhcp\n'
IP_MOCK

cat > "$TMPDIR/bin/logger" <<'LOGGER_MOCK'
#!/bin/bash
if [ ! -t 0 ]; then cat >/dev/null; fi
printf 'FAIL=%s\n' "${NOID_LOGGER_FAIL:-0}" >> "$NOID_LOGGER_LOG"
[ "${NOID_LOGGER_FAIL:-0}" != 1 ]
LOGGER_MOCK
chmod 0755 "$TMPDIR/bin/sysctl-mock" "$TMPDIR/bin/ip-mock" "$TMPDIR/bin/logger"

base_env=(
    PATH="$TMPDIR/bin:$PATH"
    NOID_WAN_IPV6_TEST_MODE=1
    NOID_WAN_IPV6_SYSCTL_FILE="$TMPDIR/policy/99-wan-ipv6-off.conf"
    NOID_WAN_IPV6_STATUS_FILE="$TMPDIR/run/wan-ipv6-status"
    NOID_WAN_IPV6_LOCK_FILE="$TMPDIR/lock/wan-ipv6.lock"
    NOID_SYS_CLASS_NET="$TMPDIR/sys-class"
    NOID_PROC_IPV6_ROOT="$TMPDIR/proc"
    NOID_SYSCTL_BIN="bash $TMPDIR/bin/sysctl-mock"
    NOID_IP_BIN="bash $TMPDIR/bin/ip-mock"
    NOID_SYSCTL_LOG="$TMPDIR/sysctl.log"
    NOID_LOGGER_LOG="$TMPDIR/logger.log"
    NOID_TEST_LOGGER_BACKEND="$TMPDIR/bin/logger"
)

if env "${base_env[@]}" bash "$TMPDIR/helper.sh" --interface eth0 \
        >"$TMPDIR/initial.out" 2>"$TMPDIR/initial.err"; then
    _pass "explicit physical interface commits exact policy"
else
    sed 's/^/    helper: /' "$TMPDIR/initial.err" >&2
    _fail "explicit physical interface commits exact policy"
fi
assert_grep_fixed '# NOID_WAN_IPV6_POLICY_V1 IFACE=eth0' \
    "$TMPDIR/policy/99-wan-ipv6-off.conf" \
    "durable policy records the exact interface identity"
assert_grep_fixed '-net/ipv6/conf/eth0/disable_ipv6 = 1' \
    "$TMPDIR/policy/99-wan-ipv6-off.conf" \
    "durable policy has one exact sysctl assignment"
assert_eq 640 "$(stat -c %a "$TMPDIR/policy/99-wan-ipv6-off.conf")" \
    "durable policy metadata is exact"
assert_eq 1 "$(cat "$TMPDIR/proc/eth0/disable_ipv6")" \
    "live kernel fixture is verified before commit"
assert_eq $'NOID_WAN_IPV6_STATUS_V1\nMODE=ENFORCED\nIFACE=eth0' \
    "$(cat "$TMPDIR/run/wan-ipv6-status")" \
    "runtime status is a closed committed contract"

# A host upgraded from the preceding M07 format can retain a lossless dot-form
# assignment for an interface without dots. Accept it once and migrate the
# canonical file; dotted names were never safely representable in that form.
sed -i 's|^-net/ipv6/conf/eth0/disable_ipv6 = 1$|-net.ipv6.conf.eth0.disable_ipv6 = 1|' \
    "$TMPDIR/policy/99-wan-ipv6-off.conf"
assert_cmd_success "legacy lossless sysctl policy migrates on refresh" \
    env "${base_env[@]}" bash "$TMPDIR/helper.sh" --interface eth0
assert_grep_fixed '-net/ipv6/conf/eth0/disable_ipv6 = 1' \
    "$TMPDIR/policy/99-wan-ipv6-off.conf" \
    "legacy policy is republished in canonical slash form"
assert_not_grep '^-net\.ipv6\.conf\.' \
    "$TMPDIR/policy/99-wan-ipv6-off.conf" \
    "successful migration retires the legacy dot-form assignment"
status_before=$(sha256sum "$TMPDIR/run/wan-ipv6-status" | awk '{print $1}')
if env "${base_env[@]}" bash "$TMPDIR/helper.sh" --unknown \
        >/dev/null 2>&1; then
    _fail "unknown helper argument is rejected before transaction ownership"
else
    _pass "unknown helper argument is rejected before transaction ownership"
fi
assert_eq "$status_before" \
    "$(sha256sum "$TMPDIR/run/wan-ipv6-status" | awk '{print $1}')" \
    "invalid invocation cannot overwrite authoritative runtime status"

# Interface names are administrator-controlled. Hardware backing, not a
# VPN/bridge-looking prefix, is the physical-device authority.
assert_cmd_success "hardware-backed wg-prefixed NIC cannot bypass enforcement" \
    env "${base_env[@]}" bash "$TMPDIR/helper.sh" --interface wg-uplink
assert_grep_fixed '# NOID_WAN_IPV6_POLICY_V1 IFACE=wg-uplink' \
    "$TMPDIR/policy/99-wan-ipv6-off.conf" \
    "renamed physical NIC owns the durable policy"
assert_eq 1 "$(cat "$TMPDIR/proc/wg-uplink/disable_ipv6")" \
    "renamed physical NIC receives the live hard constraint"
assert_cmd_success "hardware-backed br-prefixed NIC cannot bypass enforcement" \
    env "${base_env[@]}" bash "$TMPDIR/helper.sh" --interface bravo0
assert_eq 1 "$(cat "$TMPDIR/proc/bravo0/disable_ipv6")" \
    "ordinary br prefix cannot override sysfs topology"
assert_cmd_success "dotted physical NIC uses a lossless slash-form sysctl path" \
    env "${base_env[@]}" bash "$TMPDIR/helper.sh" --interface wan.0
assert_grep_fixed '-net/ipv6/conf/wan.0/disable_ipv6 = 1' \
    "$TMPDIR/policy/99-wan-ipv6-off.conf" \
    "durable policy preserves a dotted physical-interface identity"
assert_eq 1 "$(cat "$TMPDIR/proc/wan.0/disable_ipv6")" \
    "dotted physical NIC receives the live hard constraint"
if env "${base_env[@]}" bash "$TMPDIR/helper.sh" --interface virtual0 \
        >/dev/null 2>&1; then
    _fail "non-hardware interface is rejected regardless of an available proc node"
else
    _pass "non-hardware interface is rejected regardless of an available proc node"
fi
assert_eq 0 "$(cat "$TMPDIR/proc/virtual0/disable_ipv6")" \
    "rejected virtual interface is not mutated"
assert_cmd_success "fixture restores the initial physical policy" \
    env "${base_env[@]}" bash "$TMPDIR/helper.sh" --interface eth0

policy_before=$(sha256sum "$TMPDIR/policy/99-wan-ipv6-off.conf" | awk '{print $1}')
if env "${base_env[@]}" bash "$TMPDIR/helper.sh" --interface '../bad' \
        >/dev/null 2>&1; then
    _fail "invalid interface is rejected before policy mutation"
else
    _pass "invalid interface is rejected before policy mutation"
fi
assert_eq "$policy_before" \
    "$(sha256sum "$TMPDIR/policy/99-wan-ipv6-off.conf" | awk '{print $1}')" \
    "invalid interface preserves durable policy bytes"

if env "${base_env[@]}" bash "$TMPDIR/helper.sh" --interface eth1 \
        >/dev/null 2>&1; then
    _fail "missing proc sysctl node is fail-visible"
else
    _pass "missing proc sysctl node is fail-visible"
fi
assert_eq "$policy_before" \
    "$(sha256sum "$TMPDIR/policy/99-wan-ipv6-off.conf" | awk '{print $1}')" \
    "missing proc node cannot publish staged policy"
assert_grep_fixed 'MODE=ERROR' "$TMPDIR/run/wan-ipv6-status" \
    "failed enforcement publishes machine-readable ERROR"

assert_cmd_success "logger failure cannot undo committed enforcement" \
    env "${base_env[@]}" NOID_LOGGER_FAIL=1 \
        bash "$TMPDIR/helper.sh" --interface eth0
assert_grep_fixed 'FAIL=1' "$TMPDIR/logger.log" \
    "logger failure fixture reaches the selected failing backend"
assert_grep_fixed 'MODE=ENFORCED' "$TMPDIR/run/wan-ipv6-status" \
    "logger failure leaves the enforcement status truthful"

# Hold the first transaction inside the mocked sysctl write. The second helper
# must not enter its sysctl stage until flock handoff.
: > "$TMPDIR/sysctl.log"
rm -f "$TMPDIR/sysctl.started"
env "${base_env[@]}" NOID_SYSCTL_DELAY=1 \
    NOID_SYSCTL_MARKER="$TMPDIR/sysctl.started" \
    bash "$TMPDIR/helper.sh" --interface eth0 >"$TMPDIR/first.out" 2>"$TMPDIR/first.err" &
first_pid=$!
for _ in $(seq 1 100); do
    [ -e "$TMPDIR/sysctl.started" ] && break
    sleep 0.01
done
if [ -e "$TMPDIR/sysctl.started" ]; then
    _pass "concurrency fixture observes the first locked sysctl stage"
else
    _fail "concurrency fixture observes the first locked sysctl stage"
fi
env "${base_env[@]}" bash "$TMPDIR/helper.sh" --interface wlan0 \
    >"$TMPDIR/second.out" 2>"$TMPDIR/second.err" &
second_pid=$!
sleep 0.1
assert_eq 1 "$(grep -c '^START ' "$TMPDIR/sysctl.log")" \
    "second event cannot enter sysctl while first holds the lock"
if wait "$first_pid" && wait "$second_pid"; then
    _pass "both serialized hotplug events complete"
else
    sed 's/^/    first: /' "$TMPDIR/first.err" >&2
    sed 's/^/    second: /' "$TMPDIR/second.err" >&2
    _fail "both serialized hotplug events complete"
fi
assert_eq $'START eth0\nEND eth0\nSTART wlan0\nEND wlan0' \
    "$(cat "$TMPDIR/sysctl.log")" \
    "concurrent events have one complete deterministic lock order"
assert_grep_fixed '# NOID_WAN_IPV6_POLICY_V1 IFACE=wlan0' \
    "$TMPDIR/policy/99-wan-ipv6-off.conf" \
    "later locked hotplug event owns final durable policy"

policy_before=$(sha256sum "$TMPDIR/policy/99-wan-ipv6-off.conf" | awk '{print $1}')
printf '0\n' > "$TMPDIR/proc/eth0/disable_ipv6"
if env "${base_env[@]}" NOID_TEST_FAIL_STAGE=after-live \
        bash "$TMPDIR/helper.sh" --interface eth0 >/dev/null 2>&1; then
    _fail "post-live pre-publication failure is rejected"
else
    _pass "post-live pre-publication failure is rejected"
fi
assert_eq 1 "$(cat "$TMPDIR/proc/eth0/disable_ipv6")" \
    "failpoint occurs only after the live hard constraint is effective"
assert_eq "$policy_before" \
    "$(sha256sum "$TMPDIR/policy/99-wan-ipv6-off.conf" | awk '{print $1}')" \
    "failure after live apply preserves prior durable policy"
assert_grep_fixed 'MODE=ERROR' "$TMPDIR/run/wan-ipv6-status" \
    "failure after live apply is not hidden by old status"

if env "${base_env[@]}" NOID_TEST_FAIL_STAGE=after-policy-rename \
        bash "$TMPDIR/helper.sh" --interface eth0 >/dev/null 2>&1; then
    _fail "post-rename pre-status failure is rejected"
else
    _pass "post-rename pre-status failure is rejected"
fi
assert_grep_fixed '# NOID_WAN_IPV6_POLICY_V1 IFACE=eth0' \
    "$TMPDIR/policy/99-wan-ipv6-off.conf" \
    "post-rename failure retains the already committed safe policy"
assert_grep_fixed 'MODE=ERROR' "$TMPDIR/run/wan-ipv6-status" \
    "post-rename failure replaces stale success with ERROR"
assert_cmd_success "normal rerun repairs post-rename status" \
    env "${base_env[@]}" bash "$TMPDIR/helper.sh" --interface wlan0

chmod 0666 "$TMPDIR/policy/99-wan-ipv6-off.conf"
weakened_before=$(sha256sum "$TMPDIR/policy/99-wan-ipv6-off.conf" | awk '{print $1}')
if env "${base_env[@]}" bash "$TMPDIR/helper.sh" --interface eth0 \
        >/dev/null 2>&1; then
    _fail "weakened existing policy metadata is rejected"
else
    _pass "weakened existing policy metadata is rejected"
fi
assert_eq "$weakened_before" \
    "$(sha256sum "$TMPDIR/policy/99-wan-ipv6-off.conf" | awk '{print $1}')" \
    "metadata rejection preserves policy bytes"
chmod 0640 "$TMPDIR/policy/99-wan-ipv6-off.conf"

# A second active sysctl in the helper-owned file would execute at boot and
# could undo another hard constraint. It must be rejected without normalization
# or byte replacement so the unexpected evidence remains reviewable.
printf '%s\n' 'net.ipv6.conf.all.disable_ipv6 = 0' \
    >> "$TMPDIR/policy/99-wan-ipv6-off.conf"
printf '0\n' > "$TMPDIR/proc/eth0/disable_ipv6"
unexpected_before=$(sha256sum "$TMPDIR/policy/99-wan-ipv6-off.conf" | awk '{print $1}')
if env "${base_env[@]}" bash "$TMPDIR/helper.sh" --interface eth0 \
        >/dev/null 2>&1; then
    _fail "unexpected active sysctl in existing policy is rejected"
else
    _pass "unexpected active sysctl in existing policy is rejected"
fi
assert_eq "$unexpected_before" \
    "$(sha256sum "$TMPDIR/policy/99-wan-ipv6-off.conf" | awk '{print $1}')" \
    "active-directive rejection preserves forensic policy bytes"
assert_eq 1 "$(cat "$TMPDIR/proc/eth0/disable_ipv6")" \
    "malformed durable evidence cannot suppress the live hard constraint"
sed -i '$d' "$TMPDIR/policy/99-wan-ipv6-off.conf"

# Kill a process group while the mocked sysctl call is sleeping. No staged
# file may replace the last committed wlan0 policy.
interruption_before=$(sha256sum "$TMPDIR/policy/99-wan-ipv6-off.conf" | awk '{print $1}')
rm -f "$TMPDIR/interrupt.started"
setsid env "${base_env[@]}" NOID_SYSCTL_DELAY=10 \
    NOID_SYSCTL_MARKER="$TMPDIR/interrupt.started" \
    bash "$TMPDIR/helper.sh" --interface eth0 \
    >"$TMPDIR/interrupt.out" 2>"$TMPDIR/interrupt.err" &
interrupt_pid=$!
for _ in $(seq 1 100); do
    [ -e "$TMPDIR/interrupt.started" ] && break
    sleep 0.01
done
kill -TERM -- "-$interrupt_pid" 2>/dev/null || true
if wait "$interrupt_pid" 2>/dev/null; then
    _fail "interrupted transaction returns failure"
else
    _pass "interrupted transaction returns failure"
fi
assert_eq "$interruption_before" \
    "$(sha256sum "$TMPDIR/policy/99-wan-ipv6-off.conf" | awk '{print $1}')" \
    "interruption preserves prior durable policy bytes"
assert_eq 0 "$(find "$TMPDIR/policy" -maxdepth 1 -name '.99-wan-ipv6-off.*' | wc -l)" \
    "interruption removes every staged policy file"
assert_grep_fixed 'MODE=ERROR' "$TMPDIR/run/wan-ipv6-status" \
    "interruption publishes an explicit error postcondition"

# Dispatcher success/failure follows the helper, even when logger itself fails.
dispatcher_env=(
    "${base_env[@]}"
    NOID_WAN_IPV6_HELPER="bash $TMPDIR/helper.sh"
    NOID_CMDLINE_FILE="$TMPDIR/cmdline"
    NOID_WAN_IPV6_REFRESH_TMPDIR="$TMPDIR/run"
    NOID_LOGGER_FAIL=1
)
if env "${dispatcher_env[@]}" bash "$TMPDIR/dispatcher.sh" eth0 \
        >/dev/null 2>&1; then
    _fail "dispatcher rejects a one-argument invocation"
else
    _pass "dispatcher rejects a one-argument invocation"
fi
if env "${dispatcher_env[@]}" bash "$TMPDIR/dispatcher.sh" eth0 pre-up extra \
        >/dev/null 2>&1; then
    _fail "dispatcher rejects a three-argument invocation"
else
    _pass "dispatcher rejects a three-argument invocation"
fi

# The live-medium guard recognizes the exact kernel-command-line key, either
# bare or valued, without accepting a key substring or another value.
printf '0\n' > "$TMPDIR/proc/eth0/disable_ipv6"
printf 'quiet rd.live.image test\n' > "$TMPDIR/cmdline"
assert_cmd_success "bare live-image key skips installed-runtime enforcement" \
    env "${dispatcher_env[@]}" bash "$TMPDIR/dispatcher.sh" eth0 pre-up
assert_eq 0 "$(cat "$TMPDIR/proc/eth0/disable_ipv6")" \
    "bare live-image guard does not invoke the helper"
printf 'quiet rd.live.image=1 test\n' > "$TMPDIR/cmdline"
assert_cmd_success "valued live-image key skips installed-runtime enforcement" \
    env "${dispatcher_env[@]}" bash "$TMPDIR/dispatcher.sh" eth0 pre-up
assert_eq 0 "$(cat "$TMPDIR/proc/eth0/disable_ipv6")" \
    "valued live-image guard does not invoke the helper"
printf 'rd.live.imagefoo foo=rd.live.image\n' > "$TMPDIR/cmdline"
assert_cmd_success "live-image substrings cannot bypass enforcement" \
    env "${dispatcher_env[@]}" bash "$TMPDIR/dispatcher.sh" eth0 pre-up
assert_eq 1 "$(cat "$TMPDIR/proc/eth0/disable_ipv6")" \
    "substring-only command line still receives the live hard constraint"
: > "$TMPDIR/cmdline"

assert_cmd_success "logger failure cannot hide successful pre-up enforcement" \
    env "${dispatcher_env[@]}" bash "$TMPDIR/dispatcher.sh" eth0 pre-up
if env "${dispatcher_env[@]}" NOID_SYSCTL_FAIL=1 \
        bash "$TMPDIR/dispatcher.sh" eth0 pre-up >/dev/null 2>&1; then
    _fail "dispatcher propagates helper failure despite logger failure"
else
    _pass "dispatcher propagates helper failure despite logger failure"
fi

# Interrupt the full dispatcher process group while its helper is active.
# Both scripts must terminate nonzero and the dispatcher's private capture file
# must be removed by its EXIT trap.
rm -f "$TMPDIR/dispatcher-interrupt.started"
setsid env "${dispatcher_env[@]}" NOID_SYSCTL_DELAY=10 \
    NOID_SYSCTL_MARKER="$TMPDIR/dispatcher-interrupt.started" \
    bash "$TMPDIR/dispatcher.sh" eth0 pre-up \
    >"$TMPDIR/dispatcher-interrupt.out" \
    2>"$TMPDIR/dispatcher-interrupt.err" &
dispatcher_interrupt_pid=$!
for _ in $(seq 1 100); do
    [ -e "$TMPDIR/dispatcher-interrupt.started" ] && break
    sleep 0.01
done
if [ -e "$TMPDIR/dispatcher-interrupt.started" ]; then
    _pass "dispatcher interruption reaches the active helper stage"
else
    _fail "dispatcher interruption reaches the active helper stage"
fi
kill -TERM -- "-$dispatcher_interrupt_pid" 2>/dev/null || true
if wait "$dispatcher_interrupt_pid" 2>/dev/null; then
    _fail "interrupted dispatcher returns failure"
else
    _pass "interrupted dispatcher returns failure"
fi
assert_eq 0 \
    "$(find "$TMPDIR/run" -maxdepth 1 -name 'noid-wan-ipv6-refresh.*' | wc -l)" \
    "interrupted dispatcher removes its private output file"

policy_before=$(sha256sum "$TMPDIR/policy/99-wan-ipv6-off.conf" | awk '{print $1}')
empty_lock="$TMPDIR/lock/deferred.lock"
assert_cmd_success "no-NIC firstboot publishes bounded deferred state" \
    env "${base_env[@]}" NOID_SYS_CLASS_NET="$TMPDIR/empty-sys" \
        NOID_WAN_IPV6_LOCK_FILE="$empty_lock" \
        bash "$TMPDIR/helper.sh" --defer-missing-network
assert_grep_fixed 'MODE=DEFERRED' "$TMPDIR/run/wan-ipv6-status" \
    "deferred firstboot state is machine-readable"
assert_eq "$policy_before" \
    "$(sha256sum "$TMPDIR/policy/99-wan-ipv6-off.conf" | awk '{print $1}')" \
    "deferred no-NIC run preserves prior durable policy"

rm -f "$TMPDIR/lock/hostile.lock"
ln -s "$TMPDIR/lock/target" "$TMPDIR/lock/hostile.lock"
if env "${base_env[@]}" NOID_WAN_IPV6_LOCK_FILE="$TMPDIR/lock/hostile.lock" \
        bash "$TMPDIR/helper.sh" --interface eth0 >/dev/null 2>&1; then
    _fail "symlink transaction lock is rejected"
else
    _pass "symlink transaction lock is rejected"
fi

test_finish
