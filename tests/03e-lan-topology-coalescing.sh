#!/bin/bash
# Behavioural regression fixture for M03's topology-refresh event coalescing.
#
# The coalescing decision is an optimisation that is allowed to skip enforcement
# work, so it must never be able to skip work the machine did not actually do.
# Both of its stamps therefore read the boot-monotonic clock. CLOCK_REALTIME is
# unusable: chrony runs `makestep 1.0 3` and steps the wall clock during exactly
# the early-boot window in which NetworkManager emits most topology events, and
# a backward step would let a scan that ran BEFORE an event outrank it.
#
# This fixture drives the shipped decision block itself, not a reimplementation.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/03-firewalld.ks"
FIXTURE="$(mktemp -d "$PROJECT_ROOT/.test-03e-coalescing.XXXXXX")"
trap 'rm -rf "$FIXTURE"' EXIT

test_start "03e-lan-topology-coalescing"

extract_heredoc "$KS_FILE" LAN_TOPOLOGY_REFRESH_EOF "$FIXTURE/topology-refresh.sh"
HELPER="$FIXTURE/topology-refresh.sh"

# --------------------------------------------------------------------------
# Structural: the wall clock must not reappear anywhere in this helper.
# --------------------------------------------------------------------------
assert_not_grep_extended 'date[[:space:]]+\+%s' "$HELPER" \
    "topology refresh never stamps coalescing state from the wall clock"
assert_grep_fixed 'read -r up _rest < /proc/uptime' "$HELPER" \
    "monotonic stamp source is /proc/uptime"
assert_grep_fixed 'SCAN_STARTED_AT=$(boot_monotonic_cs || true)' "$HELPER" \
    "scan-start stamp uses the boot-monotonic helper"
assert_grep_fixed \
    'export NOID_LAN_TOPOLOGY_QUEUED_AT="${NOID_LAN_TOPOLOGY_QUEUED_AT:-$(boot_monotonic_cs || true)}"' \
    "$HELPER" "event-arrival stamp uses the boot-monotonic helper"
assert_grep_fixed 'SCAN_STAMP_TAG=MONOTONIC_CS' "$HELPER" \
    "stamp format tag is defined next to the stamp path"
assert_grep_fixed '"$SCAN_STAMP_TAG" "$SCAN_STARTED_AT"' "$HELPER" \
    "published stamp carries its explicit format tag"

# --------------------------------------------------------------------------
# Extract the two shipped fragments under test.
# --------------------------------------------------------------------------
awk '/^boot_monotonic_cs\(\) \{/,/^\}/' "$HELPER" > "$FIXTURE/clock.sh"
assert_cmd_success "extracted boot_monotonic_cs parses" \
    bash -n "$FIXTURE/clock.sh"

awk '/^SCAN_STAMP="/{f=1} f{print} f && /^fi$/{exit}' "$HELPER" \
    > "$FIXTURE/decision.sh"
assert_cmd_success "extracted coalescing decision parses" \
    bash -n "$FIXTURE/decision.sh"
assert_grep_fixed 'exit 0' "$FIXTURE/decision.sh" \
    "extracted decision still contains the coalescing exit"

# --------------------------------------------------------------------------
# Harness. Exit 0 = coalesced (event discarded), exit 9 = full run proceeds.
# --------------------------------------------------------------------------
cat > "$FIXTURE/decide" <<'DECIDE_EOF'
#!/bin/bash
set -euo pipefail
FIXTURE=$(dirname "$0")
# shellcheck disable=SC1091 # fragments are extracted at fixture build time.
. "$FIXTURE/clock.sh"
logger() { :; }
LOG_TAG=test-03e
EXCLUDE_PEER=${EXCLUDE_PEER:-}
INVALIDATE_FLOW_PEER=${INVALIDATE_FLOW_PEER:-}
REQUIRE_XDP=${REQUIRE_XDP:-0}
STATE_UID=${STATE_UID:?}
STATE_GID=${STATE_GID:?}
# shellcheck disable=SC1091 # fragments are extracted at fixture build time.
. "$FIXTURE/decision.sh"
exit 9
DECIDE_EOF
chmod 0755 "$FIXTURE/decide"

STATE_UID=$(id -u)
STATE_GID=$(id -g)
export STATE_UID STATE_GID
STAMP="$FIXTURE/lan-topology-refresh.scan"
export NOID_LAN_TOPOLOGY_SCAN_STAMP="$STAMP"

write_stamp() {
    printf '%s\n' "$1" > "$STAMP"
    chmod 0600 "$STAMP"
}

# decide <expected-rc> <label>
decide() {
    local expect=$1 label=$2 rc=0
    "$FIXTURE/decide" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq "$expect" ]; then
        _pass "$label"
    else
        _fail "$label (expected rc $expect, got $rc)"
    fi
}

NOW=$(bash -c ". '$FIXTURE/clock.sh'; boot_monotonic_cs")
if [[ $NOW =~ ^[0-9]+$ ]]; then
    _pass "boot_monotonic_cs returns bare centiseconds ($NOW)"
else
    _fail "boot_monotonic_cs returns bare centiseconds (got '$NOW')"
fi

# --------------------------------------------------------------------------
# The clock must not be reachable through the wall clock at all. Comparing two
# separately-taken samples for equality would be flaky by construction — they
# straddle centisecond boundaries — so the independence claim is asserted
# structurally, and the stubbed run only has to stay a plausible uptime.
# --------------------------------------------------------------------------
assert_not_grep_extended '(^|[^[:alnum:]_])date([^[:alnum:]_]|$)' \
    "$FIXTURE/clock.sh" "boot_monotonic_cs never invokes date(1)"
STUBBED=$(bash -c "date() { echo 1; }; . '$FIXTURE/clock.sh'; boot_monotonic_cs")
if [[ $STUBBED =~ ^[0-9]+$ ]] && [ "$STUBBED" -ge "$NOW" ] \
        && [ $((STUBBED - NOW)) -lt 6000 ]; then
    _pass "boot_monotonic_cs still reports uptime with date(1) stubbed out"
else
    _fail "boot_monotonic_cs was perturbed by a stubbed date(1) (got '$STUBBED', uptime was '$NOW')"
fi

MONO_A=$(bash -c ". '$FIXTURE/clock.sh'; boot_monotonic_cs")
sleep 1
MONO_B=$(bash -c ". '$FIXTURE/clock.sh'; boot_monotonic_cs")
assert_cmd_success \
    "boot_monotonic_cs advances monotonically across a real interval" \
    test "$MONO_B" -gt "$MONO_A"

# --------------------------------------------------------------------------
# Case 1 — the regression itself. A scan that started BEFORE the event must
# never coalesce it away, whatever the wall clock did in between.
# --------------------------------------------------------------------------
export NOID_LAN_TOPOLOGY_QUEUED_AT=$((NOW + 500))
write_stamp "MONOTONIC_CS=$NOW"
decide 9 "an earlier scan never coalesces a later event away"

# --------------------------------------------------------------------------
# Case 2 — a genuinely later scan still coalesces. The optimisation must
# survive the fix, otherwise a link burst re-serialises full transactions.
# --------------------------------------------------------------------------
export NOID_LAN_TOPOLOGY_QUEUED_AT=$NOW
write_stamp "MONOTONIC_CS=$((NOW + 500))"
decide 0 "a later scan still coalesces a queued generic event"

# --------------------------------------------------------------------------
# Case 3 — the upgrade trap. A stamp left by the pre-monotonic helper holds
# CLOCK_REALTIME nanoseconds, a number no boot-monotonic value can ever reach.
# Untagged, it would coalesce away every refresh until the next reboot.
# --------------------------------------------------------------------------
export NOID_LAN_TOPOLOGY_QUEUED_AT=$NOW
write_stamp "1785627659999011365"
decide 9 "a stale pre-monotonic realtime stamp cannot coalesce anything"

write_stamp "MONOTONIC_CS=1785627659999011365
MONOTONIC_CS=$((NOW + 500))"
decide 9 "a multi-line stamp is rejected instead of partially parsed"

write_stamp "REALTIME_NS=$((NOW + 500))"
decide 9 "a foreign format tag is rejected"

write_stamp "MONOTONIC_CS=$((NOW + 500))x"
decide 9 "a malformed tagged value is rejected"

write_stamp ""
decide 9 "an empty stamp is rejected"

# --------------------------------------------------------------------------
# Case 4 — the stamp stays an integrity-checked, root-private object.
# --------------------------------------------------------------------------
write_stamp "MONOTONIC_CS=$((NOW + 500))"
chmod 0644 "$STAMP"
decide 9 "a world-readable stamp is not trusted"
chmod 0600 "$STAMP"

rm -f "$STAMP"
ln -s /dev/null "$STAMP"
decide 9 "a symlinked stamp is not trusted"
rm -f "$STAMP"

decide 9 "a missing stamp falls through to a full run"

# --------------------------------------------------------------------------
# Case 5 — targeted invocations carry intent a generic rescan cannot
# reproduce and must never be coalesced, however new the stamp is.
# --------------------------------------------------------------------------
write_stamp "MONOTONIC_CS=$((NOW + 500))"
EXCLUDE_PEER=192.168.50.7 decide 9 "--exclude-peer is never coalesced"
INVALIDATE_FLOW_PEER=192.168.50.7 decide 9 "--invalidate-peer-flows is never coalesced"
REQUIRE_XDP=1 decide 9 "--require-xdp is never coalesced"

# --------------------------------------------------------------------------
# Case 6 — an unusable arrival stamp must fail open, never skip.
# --------------------------------------------------------------------------
export NOID_LAN_TOPOLOGY_QUEUED_AT=""
decide 9 "an empty arrival stamp falls through to a full run"
export NOID_LAN_TOPOLOGY_QUEUED_AT="not-a-number"
decide 9 "a non-numeric arrival stamp falls through to a full run"

test_finish
