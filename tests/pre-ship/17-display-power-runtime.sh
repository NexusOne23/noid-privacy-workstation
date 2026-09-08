#!/bin/bash
# Candidate-only GNOME/logind display-power ownership gate.
# Run as the normal GNOME user in live, fresh-install and reboot passes.

set -euo pipefail

TEST_NAME=17-display-power-runtime
PASS_ID="${1:-}"
case "$PASS_ID" in
    live|fresh-install|reboot) ;;
    *)
        echo "Usage: bash $0 {live|fresh-install|reboot}" >&2
        exit 2
        ;;
esac

fail() {
    echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2
    exit 1
}

[[ $EUID -ne 0 ]] || fail "run inside the normal GNOME session, not as root"
grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
[[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]] || fail "session D-Bus address is missing"
[[ "${XDG_CURRENT_DESKTOP:-}" == *GNOME* ]] || fail "active desktop is not GNOME"

for cmd in awk busctl gsettings grep noid-toggle-lid-action pgrep sed \
        systemd-detect-virt systemd-inhibit; do
    command -v "$cmd" >/dev/null 2>&1 || fail "required command missing: $cmd"
done
systemd-detect-virt --quiet || fail "three-pass display/power gate expects the audit VM"

expect_setting() {
    local schema=$1 key=$2 expected=$3 actual
    actual="$(gsettings get "$schema" "$key")" || fail "cannot read $schema $key"
    [[ "$actual" == "$expected" ]] || \
        fail "$schema $key is $actual, expected $expected"
    [[ "$(gsettings writable "$schema" "$key")" == true ]] || \
        fail "$schema $key is unexpectedly locked"
}

has_active_assignment() {
    local pattern=$1 config_file rc
    shift
    for config_file in "$@"; do
        [[ -e $config_file || -L $config_file ]] || continue
        if grep -Eqs "$pattern" "$config_file"; then
            return 0
        else
            rc=$?
        fi
        [[ $rc -eq 1 ]] || fail "cannot inspect system configuration: $config_file"
    done
    return 1
}

# The Live session deliberately carries different blank/lock values. liveuser
# has no password and the image ships authselect `without-nullok`, so a lock
# screen there could never be unlocked; M17's livesys hook therefore writes a
# Live-only site.d keyfile that disables both. The installed passes must keep
# the hardened defaults.
if [[ "$PASS_ID" == live ]]; then
    expect_setting org.gnome.desktop.session idle-delay 'uint32 0'
    expect_setting org.gnome.desktop.screensaver lock-enabled 'false'
else
    expect_setting org.gnome.desktop.session idle-delay 'uint32 300'
    expect_setting org.gnome.desktop.screensaver lock-enabled 'true'
fi
expect_setting org.gnome.desktop.screensaver lock-delay 'uint32 0'
expect_setting org.gnome.settings-daemon.plugins.power idle-dim 'false'
expect_setting org.gnome.settings-daemon.plugins.power idle-brightness '30'
expect_setting org.gnome.settings-daemon.plugins.power sleep-inactive-ac-timeout '900'
expect_setting org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type "'nothing'"
expect_setting org.gnome.settings-daemon.plugins.power sleep-inactive-battery-timeout '900'
expect_setting org.gnome.settings-daemon.plugins.power sleep-inactive-battery-type "'nothing'"

if has_active_assignment \
        '^[[:space:]]*(IdleAction(Sec)?|Handle(Power|Suspend|Hibernate|Lid)[A-Za-z]*)=' \
        /etc/systemd/logind.conf /etc/systemd/logind.conf.d/*.conf; then
    fail "compose image installs a competing logind idle/key/lid override"
fi
if has_active_assignment \
        '^[[:space:]]*(AllowSuspend|AllowHibernation|AllowSuspendThenHibernate|AllowHybridSleep|SuspendState|MemorySleepMode|HibernateMode|HibernateDelaySec|HibernateOnACPower)=' \
        /etc/systemd/sleep.conf /etc/systemd/sleep.conf.d/*.conf; then
    fail "compose image installs a systemd sleep-state override"
fi
if grep -Eq '(^|[[:space:]])(acpi_backlight|mem_sleep_default)=' /proc/cmdline; then
    fail "retired global backlight/suspend kernel override is active"
fi
[[ ! -e /etc/systemd/logind.conf.d/99-noid-user-lid-action.conf ]] || \
    fail "fresh candidate unexpectedly carries a prior explicit lid choice"
[[ -f /usr/local/bin/noid-toggle-lid-action \
    && ! -L /usr/local/bin/noid-toggle-lid-action \
    && -x /usr/local/bin/noid-toggle-lid-action ]] || \
    fail "native lid-action helper is missing, symlinked or not executable"
[[ "$(stat -Lc '%U:%G:%a:%h' /usr/local/bin/noid-toggle-lid-action \
        2>/dev/null || true)" == root:root:755:1 ]] || \
    fail "native lid-action helper metadata is not root:root:0755:1"

manager_property() {
    local property=$1
    busctl get-property org.freedesktop.login1 /org/freedesktop/login1 \
        org.freedesktop.login1.Manager "$property"
}

upower_property() {
    local property=$1
    busctl get-property org.freedesktop.UPower /org/freedesktop/UPower \
        org.freedesktop.UPower "$property"
}

[[ "$(manager_property IdleAction)" == 's "ignore"' ]] || \
    fail "logind IdleAction is not the systemd 259 vendor value"
[[ "$(manager_property HandlePowerKey)" == 's "poweroff"' ]] || \
    fail "logind power-key action differs from the reviewed vendor value"
[[ "$(manager_property HandleSuspendKey)" == 's "suspend"' ]] || \
    fail "logind suspend-key action differs from the reviewed vendor value"
[[ "$(manager_property HandleHibernateKey)" == 's "hibernate"' ]] || \
    fail "logind hibernate-key action differs from the reviewed vendor value"
[[ "$(manager_property HandleLidSwitch)" == 's "suspend"' ]] || \
    fail "logind lid action differs from the reviewed base-image vendor value"
[[ "$(manager_property HandleLidSwitchExternalPower)" == 's ""' ]] || \
    fail "logind external-power lid action is not the reviewed unset vendor value"
[[ "$(manager_property HandleLidSwitchDocked)" == 's "ignore"' ]] || \
    fail "logind docked lid action differs from the reviewed vendor value"
[[ "$(manager_property InhibitorsMax)" == 't 8192' ]] || \
    fail "logind did not retain the reviewed 8192 inhibitor capacity"

can_sleep() {
    local method=$1
    busctl call org.freedesktop.login1 /org/freedesktop/login1 \
        org.freedesktop.login1.Manager "$method" | sed -n 's/^s "\([^"]*\)"$/\1/p'
}

case "$(can_sleep CanSuspend)" in
    yes|challenge) ;;
    *) fail "suspend is unavailable to the active local session" ;;
esac
[[ "$(can_sleep CanHibernate)" == na ]] || \
    fail "zram-only candidate unexpectedly advertises hibernation"
[[ "$(can_sleep CanHybridSleep)" == na ]] || \
    fail "zram-only candidate unexpectedly advertises hybrid sleep"
[[ "$(can_sleep CanSuspendThenHibernate)" == na ]] || \
    fail "zram-only candidate unexpectedly advertises suspend-then-hibernate"

swap_count=0
while read -r swap_name _rest; do
    [[ "$swap_name" == Filename ]] && continue
    [[ "$swap_name" == /dev/zram* ]] || fail "unexpected disk-backed swap: $swap_name"
    swap_count=$((swap_count + 1))
done < /proc/swaps
[[ "$swap_count" -ge 1 ]] || fail "no active zram swap found"

pgrep -x gnome-shell >/dev/null || fail "gnome-shell is not running"
pgrep -f 'gsd-power' >/dev/null || fail "GNOME power plugin is not running"
inhibitors="$(systemd-inhibit --list --no-legend 2>/dev/null)"
grep -q 'handle-power-key:handle-suspend-key:handle-hibernate-key' \
    <<<"$inhibitors" || fail "GNOME hardware-key inhibitor is missing"

# GNOME 50 takes handle-lid-switch only while the active-session/external-
# monitor topology requires it, then releases it after a safety timer. Its
# steady-state presence is therefore not a valid health invariant. UPower's
# documented capability property must still expose an unambiguous hardware
# state, while the logind policy and running gsd-power process are checked above.
case "$(upower_property LidIsPresent)" in
    'b true'|'b false') ;;
    *) fail "UPower LidIsPresent is unavailable or not boolean" ;;
esac

# The general helper's hardware truth comes from the kernel SW_LID bitmap, not
# UPower, DMI or a battery heuristic. Its read-only status must agree with that
# source on both a laptop/convertible and a desktop VM.
kernel_lid=0
shopt -s nullglob
for sw_path in /sys/class/input/event*/device/capabilities/sw; do
    [[ -r $sw_path ]] || continue
    sw_bitmap=$(<"$sw_path") || continue
    sw_bitmap=${sw_bitmap//$'\n'/ }
    sw_word=${sw_bitmap##* }
    [[ $sw_word =~ ^[[:xdigit:]]+$ ]] || continue
    if (( (0x$sw_word & 1) == 1 )); then
        kernel_lid=1
        break
    fi
done
shopt -u nullglob
lid_status=$(noid-toggle-lid-action status) || \
    fail "native lid-action status failed"
grep -qF 'Explicit choice: none (lower NoID Privacy/Fedora policy)' \
    <<<"$lid_status" || fail "fresh candidate lid status reports an explicit choice"
if [[ $kernel_lid -eq 1 ]]; then
    grep -qF 'Hardware: PRESENT (kernel SW_LID)' <<<"$lid_status" || \
        fail "helper missed the kernel SW_LID capability"
else
    grep -qF 'Hardware: ABSENT (desktop or no kernel SW_LID device)' \
        <<<"$lid_status" || fail "helper misclassified a desktop without SW_LID"
fi

if [[ "$PASS_ID" == live ]]; then
    blank_lock_state="blank/lock are disabled for the passwordless Live session"
else
    blank_lock_state="blank/lock remain active"
fi
echo "PASS  $TEST_NAME [$PASS_ID]: GNOME keeps agent power defaults user-adjustable while $blank_lock_state; native lid status agrees with kernel SW_LID; logind and hibernation boundaries are explicit"
