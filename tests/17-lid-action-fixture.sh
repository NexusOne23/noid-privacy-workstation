#!/usr/bin/env bash
# Behavioral fixture for the native M17 lid-action transaction.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
SOURCE=${1:-$PROJECT_ROOT/scripts/noid-toggle-lid-action.sh}
FIXTURE=$(mktemp -d /var/tmp/noid-lid-fixture.XXXXXX)
trap 'rm -rf -- "$FIXTURE"' EXIT

test_start "17-lid-action-fixture"
assert_file_executable "$SOURCE" "canonical lid-action helper is executable"
assert_cmd_success "canonical lid-action helper parses" bash -n "$SOURCE"

mkdir -p "$FIXTURE/bin" "$FIXTURE/sys/class/input/event0/device/capabilities" \
    "$FIXTURE/etc/systemd/logind.conf.d"
chmod 0755 "$FIXTURE/etc/systemd/logind.conf.d"
printf '%s\n' 0 >"$FIXTURE/sys/class/input/event0/device/capabilities/sw"
printf '%s\n' "Power Button" >"$FIXTURE/sys/class/input/event0/device/name"

cat >"$FIXTURE/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $* == "reload systemd-logind.service" ]]
if [[ -e ${NOID_LID_TEST_ROOT:?}/fail-reload-once ]]; then
    rm -f -- "$NOID_LID_TEST_ROOT/fail-reload-once"
    exit 1
fi
rm -f -- "$NOID_LID_TEST_ROOT/effective-override"
EOF
cat >"$FIXTURE/bin/busctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
root=${NOID_LID_TEST_ROOT:?}
policy=$root/etc/systemd/logind.conf.d/99-noid-user-lid-action.conf
base=$root/etc/systemd/logind.conf.d/99-noid-nvidia-lid.conf
if [[ $1 == call && ${5:-} == CanSuspend ]]; then
    printf 's "yes"\n'
    exit 0
fi
[[ $1 == get-property ]]
property=${5:?}
normal=suspend
external=
docked=ignore
source=$base
[[ -f $policy ]] && source=$policy
if [[ -f $source ]]; then
    value=$(sed -n 's/^HandleLidSwitch=//p' "$source" | tail -n1)
    external_value=$(sed -n 's/^HandleLidSwitchExternalPower=//p' "$source" | tail -n1)
    [[ -n $value ]] && normal=$value
    [[ -n $external_value ]] && external=$external_value
fi
if [[ -f $root/effective-override ]]; then
    normal=$(sed -n '1p' "$root/effective-override")
    external=$(sed -n '2p' "$root/effective-override")
fi
case "$property" in
    HandleLidSwitch) value=$normal ;;
    HandleLidSwitchExternalPower) value=$external ;;
    HandleLidSwitchDocked) value=$docked ;;
    *) exit 1 ;;
esac
printf 's "%s"\n' "$value"
EOF
cat >"$FIXTURE/bin/systemd-inhibit" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$FIXTURE/bin/restorecon" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod 0755 "$FIXTURE"/bin/*

run_tool() {
    env NOID_LID_TEST_ROOT="$FIXTURE" "$SOURCE" "$@"
}

desktop_output=$(run_tool status)
assert_grep_fixed 'Hardware: ABSENT (desktop or no kernel SW_LID device)' \
    <(printf '%s\n' "$desktop_output") \
    "desktop status reports the absent kernel lid capability"
assert_cmd_failure "desktop refuses a lid mutation" run_tool lock
if [[ ! -e $FIXTURE/etc/systemd/logind.conf.d/99-noid-user-lid-action.conf ]]; then
    _pass "desktop refusal publishes no policy"
else
    _fail "desktop refusal publishes no policy"
fi

mkdir -p "$FIXTURE/sys/class/input/event1/device/capabilities"
printf '%s\n' '0 1' >"$FIXTURE/sys/class/input/event1/device/capabilities/sw"
printf '%s\n' "Convertible Lid Switch" >"$FIXTURE/sys/class/input/event1/device/name"

assert_cmd_success "multiword SW_LID bitmap is detected" \
    bash -c 'env NOID_LID_TEST_ROOT="$1" "$2" status | grep -qF \
        "Hardware: PRESENT (kernel SW_LID)"' _ "$FIXTURE" "$SOURCE"
assert_cmd_success "confirmed suspend transaction succeeds" \
    bash -c 'printf "y\n" | env NOID_LID_TEST_ROOT="$1" "$2" suspend \
        >/dev/null' _ "$FIXTURE" "$SOURCE"
POLICY="$FIXTURE/etc/systemd/logind.conf.d/99-noid-user-lid-action.conf"
assert_grep_fixed 'HandleLidSwitch=suspend' "$POLICY"
assert_grep_fixed 'HandleLidSwitchExternalPower=suspend' "$POLICY"

assert_cmd_success "lock transaction succeeds" run_tool lock
assert_grep_fixed 'HandleLidSwitch=lock' "$POLICY"
assert_grep_fixed 'HandleLidSwitchExternalPower=lock' "$POLICY"

printf '%s\n' suspend suspend >"$FIXTURE/effective-override"
assert_cmd_success "same-value request reloads stale effective state" run_tool lock
if [[ ! -e $FIXTURE/effective-override ]]; then
    _pass "same-value request reached the native reload path"
else
    _fail "same-value request reached the native reload path"
fi

touch "$FIXTURE/fail-reload-once"
assert_cmd_failure "failed reload rejects the requested change" \
    bash -c 'printf "y\n" | env NOID_LID_TEST_ROOT="$1" "$2" suspend \
        >/dev/null' _ "$FIXTURE" "$SOURCE"
assert_grep_fixed 'HandleLidSwitch=lock' "$POLICY" \
    "failed reload restores the prior action"
assert_grep_fixed 'HandleLidSwitchExternalPower=lock' "$POLICY" \
    "failed reload restores the prior external-power action"

cat >"$FIXTURE/etc/systemd/logind.conf.d/99-noid-nvidia-lid.conf" <<'EOF'
[Login]
HandleLidSwitch=lock
HandleLidSwitchExternalPower=lock
EOF
assert_cmd_success "reset removes only the explicit user policy" run_tool reset
if [[ ! -e $POLICY ]]; then
    _pass "reset removes the explicit policy"
else
    _fail "reset removes the explicit policy"
fi
assert_file_exists \
    "$FIXTURE/etc/systemd/logind.conf.d/99-noid-nvidia-lid.conf" \
    "reset preserves the lower NVIDIA compatibility policy"

cat >"$POLICY" <<'EOF'
[Login]
HandleLidSwitch=poweroff
EOF
before=$(sha256sum "$POLICY" | awk '{print $1}')
assert_cmd_failure "independently modified policy is refused" run_tool lock
assert_eq "$before" "$(sha256sum "$POLICY" | awk '{print $1}')" \
    "refusal preserves independently modified bytes"

test_finish
