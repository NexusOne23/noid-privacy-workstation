#!/bin/bash
# Behavioural regression fixture for M05's reviewed print-stack opt-in.
#
# The point of noid-toggle-printing is that enabling printing must NOT re-open
# the discovery surface M05 Step 4 closed. cups-browsed, avahi and wsdd are the
# actual privacy cost; the CUPS units alone are not. A regression here would be
# silent on an installed system — printing would simply work, and so would mDNS
# announcement of this host. So the units the toggle touches are asserted by
# driving the shipped script against a recording systemctl, not by reading it.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/05-lan-isolation.ks"
# The hardened image mounts /tmp noexec and this fixture ships executable
# mocks, so keep the scratch tree on the repository filesystem.
FIXTURE="$(mktemp -d "$PROJECT_ROOT/.test-05-printing.XXXXXX")"
trap 'rm -rf "$FIXTURE"' EXIT

MOCK_BIN="$FIXTURE/bin"
mkdir -p "$MOCK_BIN"
MASKED_FILE="$FIXTURE/masked"
ACTIVE_FILE="$FIXTURE/active"
CALL_LOG="$FIXTURE/systemctl.log"

# Recording systemctl. Unit existence, mask state and active state are files so
# the script's own probes drive real branching instead of a fixed answer.
cat > "$MOCK_BIN/systemctl" <<'MOCK_SYSTEMCTL_EOF'
#!/bin/bash
# Deliberately not `set -e`: the real systemctl reports state through exit
# codes and the script under test branches on them.
masked=$NOID_TEST_MASKED_FILE
active=$NOID_TEST_ACTIVE_FILE
log=$NOID_TEST_CALL_LOG
printf '%s\n' "$*" >> "$log"

verb=$1
shift
# Strip the option words the script passes so the unit list is clean.
units=()
for arg in "$@"; do
    case "$arg" in
        --now|--quiet|--no-block) ;;
        *) units+=("$arg") ;;
    esac
done

is_masked() { grep -qxF "$1" "$masked" 2>/dev/null; }

case "$verb" in
    is-enabled)
        if is_masked "${units[0]}"; then echo masked; exit 1; fi
        if grep -qxF "enabled:${units[0]}" "$active" 2>/dev/null; then
            echo enabled; exit 0
        fi
        echo disabled
        exit 1
        ;;
    is-active)
        grep -qxF "active:${units[0]}" "$active" 2>/dev/null
        exit $?
        ;;
    cat)
        # Every unit this fixture cares about exists except the ones named as
        # absent, which mirrors cups-browsed/wsdd being excluded from %packages.
        case "${units[0]}" in
            "$NOID_TEST_ABSENT_UNIT") exit 1 ;;
            *) exit 0 ;;
        esac
        ;;
    unmask)
        for u in "${units[@]}"; do
            grep -vxF "$u" "$masked" > "$masked.tmp" 2>/dev/null || true
            mv -f "$masked.tmp" "$masked"
        done
        exit 0
        ;;
    mask)
        for u in "${units[@]}"; do
            is_masked "$u" || printf '%s\n' "$u" >> "$masked"
        done
        exit 0
        ;;
    enable)
        [ "${NOID_TEST_ENABLE_FAILS:-0}" -eq 0 ] || exit 1
        for u in "${units[@]}"; do
            printf 'enabled:%s\nactive:%s\n' "$u" "$u" >> "$active"
        done
        exit 0
        ;;
    disable|stop)
        for u in "${units[@]}"; do
            grep -vxF "enabled:$u" "$active" 2>/dev/null \
                | grep -vxF "active:$u" > "$active.tmp" || true
            mv -f "$active.tmp" "$active"
        done
        exit 0
        ;;
    *) exit 0 ;;
esac
MOCK_SYSTEMCTL_EOF

# `id -u` must report root so require_root passes without the test needing it.
cat > "$MOCK_BIN/id" <<'MOCK_ID_EOF'
#!/bin/bash
[ "${1:-}" = -u ] && { echo 0; exit 0; }
exec /usr/bin/id "$@"
MOCK_ID_EOF

# Fail loudly if the toggle ever reaches for the firewall: an outbound LAN
# exception is the owner's separate, explicit decision.
for forbidden in nft firewall-cmd noid-lan-allow; do
    cat > "$MOCK_BIN/$forbidden" <<'MOCK_FORBIDDEN_EOF'
#!/bin/bash
printf 'FORBIDDEN %s %s\n' "$(basename "$0")" "$*" \
    >> "$NOID_TEST_CALL_LOG"
exit 0
MOCK_FORBIDDEN_EOF
done
chmod 0755 "$MOCK_BIN"/*

export NOID_TEST_MASKED_FILE="$MASKED_FILE"
export NOID_TEST_ACTIVE_FILE="$ACTIVE_FILE"
export NOID_TEST_CALL_LOG="$CALL_LOG"
export NOID_TEST_ABSENT_UNIT=wsdd2.service

CUPS_UNITS=(cups.path cups.service cups.socket)
DISCOVERY_UNITS=(cups-browsed.service avahi-daemon.service
                 avahi-daemon.socket wsdd.service wsdd2.service)

build_toggle() {
    # $1 = source .ks (allows a mutated copy)
    #
    # The shipped script pins its own PATH, which is exactly right in
    # production and exactly why the mocks cannot be injected through the
    # environment. Redirect only the extracted fixture copy — the same
    # convention the M04 and M05 fixtures use — so the production bytes keep
    # their fixed search path and the test still drives the real logic.
    extract_heredoc "$1" NOID_TOGGLE_PRINTING_EOF "$FIXTURE/toggle.original"
    sed -e "s|^PATH=/usr/sbin:/usr/bin:/sbin:/bin$|PATH=$MOCK_BIN:/usr/sbin:/usr/bin:/sbin:/bin|" \
        "$FIXTURE/toggle.original" > "$FIXTURE/noid-toggle-printing"
    if ! grep -qxF "PATH=$MOCK_BIN:/usr/sbin:/usr/bin:/sbin:/bin" \
            "$FIXTURE/noid-toggle-printing"; then
        _fail "fixture PATH redirect did not apply — the mocks would be bypassed"
    fi
    chmod 0755 "$FIXTURE/noid-toggle-printing"
}

reset_default_state() {
    # NoID Privacy default: every CUPS unit and every discovery unit masked,
    # nothing active.
    printf '%s\n' "${CUPS_UNITS[@]}" "${DISCOVERY_UNITS[@]}" > "$MASKED_FILE"
    : > "$ACTIVE_FILE"
    : > "$CALL_LOG"
}

run_toggle() {
    # $1 = verb; echoes nothing, exit status is the script's
    PATH="$MOCK_BIN:$PATH" "$FIXTURE/noid-toggle-printing" "$1" \
        > "$FIXTURE/out" 2>&1
}

masked_count() {
    # $1 = unit; 1 when masked, 0 when not
    grep -cxF "$1" "$MASKED_FILE" 2>/dev/null || true
}

test_start "05-printing-toggle-fixture"

build_toggle "$KS_FILE"
assert_cmd_success "shipped printing toggle parses" \
    bash -n "$FIXTURE/noid-toggle-printing"

# --- enable ---------------------------------------------------------------
reset_default_state
assert_cmd_success "'on' succeeds from the masked default" run_toggle on
for unit in "${CUPS_UNITS[@]}"; do
    assert_eq 0 "$(masked_count "$unit")" \
        "'on' unmasks $unit"
done
for unit in "${DISCOVERY_UNITS[@]}"; do
    assert_eq 1 "$(masked_count "$unit")" \
        "'on' leaves the discovery daemon $unit masked"
done
assert_grep_fixed 'enable --now cups.socket cups.path' "$CALL_LOG" \
    "'on' activates only the socket and path entry points"
assert_not_grep_extended '^enable .*cups\.service' "$CALL_LOG" \
    "'on' never enables cups.service outright — it stays activated on demand"
assert_not_grep 'FORBIDDEN' "$CALL_LOG" \
    "'on' touches no firewall command"
assert_grep_fixed 'noid-lan-allow --add' "$FIXTURE/out" \
    "'on' names the separate outbound LAN exception a network printer needs"

# --- status while enabled --------------------------------------------------
: > "$CALL_LOG"
assert_cmd_success "'status' succeeds while enabled" run_toggle status
assert_grep_fixed '-> ENABLED' "$FIXTURE/out" \
    "'status' reports the enabled stack"

# --- disable ---------------------------------------------------------------
: > "$CALL_LOG"
assert_cmd_success "'off' succeeds from the enabled state" run_toggle off
for unit in "${CUPS_UNITS[@]}"; do
    assert_eq 1 "$(masked_count "$unit")" \
        "'off' re-masks $unit"
done
assert_not_grep 'FORBIDDEN' "$CALL_LOG" \
    "'off' touches no firewall command"
: > "$CALL_LOG"
assert_cmd_success "'status' succeeds while disabled" run_toggle status
assert_grep_fixed '-> DISABLED' "$FIXTURE/out" \
    "'status' reports the masked default"

# --- rollback on a failed activation ---------------------------------------
# Unmasking succeeds but the activation does not. Leaving the units unmasked
# would publish a half-open state that neither the switch nor `status` calls
# enabled, so the failure path must restore the default it started from.
reset_default_state
NOID_TEST_ENABLE_FAILS=1 run_toggle on && enable_rc=0 || enable_rc=$?
assert_eq 1 "$enable_rc" "a failed activation exits non-zero"
for unit in "${CUPS_UNITS[@]}"; do
    assert_eq 1 "$(masked_count "$unit")" \
        "a failed activation restores the mask on $unit"
done

# --- unexpected discovery drift is reported, never silently re-masked ------
reset_default_state
grep -vxF avahi-daemon.service "$MASKED_FILE" > "$MASKED_FILE.tmp"
mv -f "$MASKED_FILE.tmp" "$MASKED_FILE"
assert_cmd_success "'on' still succeeds with a pre-existing discovery drift" \
    run_toggle on
assert_grep_fixed 'avahi-daemon.service is no longer masked' "$FIXTURE/out" \
    "'on' reports an unmasked discovery daemon it did not cause"
assert_eq 0 "$(masked_count avahi-daemon.service)" \
    "'on' does not silently re-mask a unit someone else changed"

# --- discriminating control ------------------------------------------------
# Fold the discovery daemons into the unit list the toggle unmasks. Without
# this control the assertions above would also pass against a toggle that
# re-opens mDNS/WSD announcement together with printing.
MUTATED_KS="$FIXTURE/mutated-05.ks"
python3 - "$KS_FILE" "$MUTATED_KS" <<'MUTATE_EOF'
import sys
src = open(sys.argv[1], encoding='utf-8').read()
anchor = 'CUPS_UNITS="cups.path cups.service cups.socket"'
if src.count(anchor) != 1:
    sys.exit('mutation anchor not found -- the fixture no longer matches '
             'the source')
src = src.replace(
    anchor,
    'CUPS_UNITS="cups.path cups.service cups.socket cups-browsed.service '
    'avahi-daemon.service"')
open(sys.argv[2], 'w', encoding='utf-8').write(src)
MUTATE_EOF
build_toggle "$MUTATED_KS"
reset_default_state
run_toggle on || true
assert_eq 0 "$(masked_count cups-browsed.service)" \
    "control: a toggle that unmasks discovery daemons is detectable"
build_toggle "$KS_FILE"

test_finish
