#!/usr/bin/env bash
# Candidate gate for Live power/logout truth and USBGuard notifier ownership.
# `fresh-install initial`, a real graphical logout/login, then
# `fresh-install second-login` proves two distinct sessions in the same boot.
set -euo pipefail
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin

TEST_NAME=17-session-lifecycle-runtime
PASS_ID=${1:-}
LIFECYCLE=${2:-}
case "$PASS_ID:$LIFECYCLE" in
    live:initial|fresh-install:initial|fresh-install:second-login|\
    reboot:initial|reboot:second-login) ;;
    *) echo "Usage: bash $0 {live|fresh-install|reboot} {initial|second-login}" >&2; exit 2 ;;
esac

fail() { echo "FAIL  $TEST_NAME [$PASS_ID/$LIFECYCLE]: $*" >&2; exit 1; }
[[ $EUID -ne 0 ]] || fail "run as the normal GNOME user, not root"

for required_command in \
    awk busctl chmod find grep gsettings loginctl matchpathcon mkdir readlink \
    rm rmdir stat sync systemctl; do
    command -v "$required_command" >/dev/null 2>&1 || \
        fail "required command missing: $required_command"
done

grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
[[ ${XDG_CURRENT_DESKTOP:-} == *GNOME* ]] || fail "active desktop is not GNOME"
[[ -n ${DBUS_SESSION_BUS_ADDRESS:-} ]] || fail "session D-Bus address is missing"

# NOID_USER_SESSION_SELECTOR_BEGIN
session_id=$(loginctl show-user "$UID" -p Display --value 2>/dev/null) || \
    fail "could not identify logind's primary graphical session"
[[ -n $session_id && $session_id != *$'\n'* ]] || \
    fail "logind did not publish one primary graphical session"
session_uid=$(loginctl show-session "$session_id" -p User --value 2>/dev/null) || \
    fail "could not inspect primary session UID: $session_id"
session_class=$(loginctl show-session "$session_id" -p Class --value 2>/dev/null) || \
    fail "could not inspect primary session class: $session_id"
session_type=$(loginctl show-session "$session_id" -p Type --value 2>/dev/null) || \
    fail "could not inspect primary session type: $session_id"
session_remote=$(loginctl show-session "$session_id" -p Remote --value 2>/dev/null) || \
    fail "could not inspect primary session locality: $session_id"
session_active=$(loginctl show-session "$session_id" -p Active --value 2>/dev/null) || \
    fail "could not inspect primary session activity: $session_id"
session_state=$(loginctl show-session "$session_id" -p State --value 2>/dev/null) || \
    fail "could not inspect primary session state: $session_id"
[[ $session_uid == "$UID" ]] || fail "primary graphical session belongs to another UID"
[[ $session_class == user ]] || fail "primary graphical session is not class=user"
[[ $session_type =~ ^(wayland|x11)$ ]] || fail "primary session is not graphical"
[[ $session_remote == no ]] || fail "primary graphical session is remote"
[[ $session_active == yes && $session_state == active ]] || \
    fail "primary graphical session is not active"
# NOID_USER_SESSION_SELECTOR_END

unit=usbguard-notifier.service
vendor_unit=/usr/lib/systemd/user/$unit
dropin=/etc/systemd/user/usbguard-notifier.service.d/10-noid-wait.conf
wants=/usr/lib/systemd/user/graphical-session.target.wants/$unit
gate=/usr/libexec/noid-eligible-user
[[ -f $gate && ! -L $gate && -x $gate \
   && $(stat -c '%U:%G:%a:%h' "$gate") == root:root:755:1 ]] || \
    fail "persistent-user/logind gate metadata invalid"
[[ -f $vendor_unit && ! -L $vendor_unit \
   && $(stat -c '%U:%G:%a:%h' "$vendor_unit") == root:root:644:1 ]] || \
    fail "vendor notifier unit metadata invalid"
[[ -f $dropin && ! -L $dropin \
   && $(stat -c '%U:%G:%a:%h' "$dropin") == root:root:644:1 ]] || \
    fail "notifier drop-in metadata invalid"
for root_file in "$gate" "$vendor_unit" "$dropin"; do
    matchpathcon -V "$root_file" >/dev/null 2>&1 || \
        fail "SELinux context invalid: $root_file"
done
[[ -L $wants && $(readlink "$wants") == "$vendor_unit" ]] || \
    fail "static graphical-session wants link invalid"
[[ $(systemctl --user show "$unit" -p FragmentPath --value) == "$vendor_unit" ]] || \
    fail "loaded notifier unit fragment differs"
loaded_dropins=$(systemctl --user show "$unit" -p DropInPaths --value) || \
    fail "could not inspect loaded notifier drop-ins"
[[ " $loaded_dropins " == *" $dropin "* ]] || \
    fail "NoID Privacy notifier drop-in is not loaded"
grep -qxF 'ConditionUser=!@system' "$dropin" || fail "system-user exclusion missing"
grep -qxF 'PartOf=graphical-session.target' "$dropin" || fail "PartOf edge missing"
grep -qxF 'After=graphical-session.target' "$dropin" || fail "After edge missing"
grep -qxF 'ExecCondition=/usr/libexec/noid-eligible-user graphical' "$dropin" || \
    fail "persistent-account/local-logind condition missing"
grep -qxF 'ExecCondition=/usr/bin/systemctl --user --quiet is-active graphical-session.target' \
    "$dropin" || fail "active graphical-session condition missing"
grep -qxF 'ExecStart=/usr/bin/usbguard-notifier --wait' "$dropin" || \
    fail "native wait mode missing"
systemctl --user --quiet is-active graphical-session.target || \
    fail "graphical-session.target is not active"
"$gate" account || fail "normal VM user did not pass the persistent-account gate"
"$gate" graphical || fail "current normal VM login did not pass the exact logind gate"
systemctl --user --quiet is-active "$unit" || fail "notifier is not active"
[[ $(systemctl --user show "$unit" -p ConditionResult --value) == yes ]] || \
    fail "notifier condition did not pass"
[[ $(systemctl --user show "$unit" -p Result --value) == success ]] || \
    fail "notifier result is not success"
control_group=$(systemctl --user show "$unit" -p ControlGroup --value)
[[ $control_group == /*usbguard-notifier.service ]] || \
    fail "notifier control group is missing or malformed"
main_pid=$(systemctl --user show "$unit" -p MainPID --value)
[[ $main_pid =~ ^[1-9][0-9]*$ && -r /proc/$main_pid/cmdline ]] || \
    fail "notifier MainPID is not live"
[[ $(<"/proc/$main_pid/cgroup") == "0::$control_group" ]] || \
    fail "notifier MainPID is outside the unit control group"
notifier_uid=$(awk '
    $1 == "Uid:" && NF == 5 { print $2; found++ }
    END { exit found != 1 }
' "/proc/$main_pid/status") || fail "cannot read one notifier real UID"
[[ $notifier_uid == "$UID" ]] || fail "notifier process belongs to another UID"
mapfile -d '' -t notifier_argv < "/proc/$main_pid/cmdline"
[[ ${#notifier_argv[@]} -eq 2 \
   && ${notifier_argv[0]} == /usr/bin/usbguard-notifier \
   && ${notifier_argv[1]} == --wait ]] || fail "notifier argv differs"
[[ $(systemctl --user show "$unit" -p MainPID --value) == "$main_pid" ]] || \
    fail "notifier MainPID changed during identity inspection"

[[ $(gsettings get org.gnome.desktop.lockdown disable-log-out) == false ]] || \
    fail "GNOME logout lockdown hides the Restart/Power Off submenu"
if [[ $PASS_ID == live ]]; then
    gdm_config=/etc/gdm/custom.conf
    [[ -f $gdm_config && ! -L $gdm_config \
       && $(stat -c '%U:%G:%a:%h' "$gdm_config") == root:root:644:1 ]] || \
        fail "Live GDM configuration metadata invalid"
    matchpathcon -V "$gdm_config" >/dev/null 2>&1 || \
        fail "Live GDM configuration SELinux context invalid"
    gdm_daemon_value() {
        local key=$1
        awk -v wanted="$key" '
            /^[[:space:]]*[#;]/ { next }
            /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
                section=$0
                gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", section)
                next
            }
            section == "daemon" {
                line=$0
                sub(/^[[:space:]]*/, "", line)
                if (index(line, wanted "=") == 1) {
                    count++
                    value=substr(line, length(wanted) + 2)
                    sub(/[[:space:]]*$/, "", value)
                }
            }
            END {
                if (count != 1) exit 1
                print value
            }
        ' "$gdm_config"
    }
    for live_login_contract in \
        'AutomaticLoginEnable=true' \
        'AutomaticLogin=liveuser' \
        'TimedLoginEnable=true' \
        'TimedLogin=liveuser' \
        'TimedLoginDelay=1'; do
        key=${live_login_contract%%=*}
        expected=${live_login_contract#*=}
        actual=$(gdm_daemon_value "$key") || \
            fail "Live GDM [daemon] key is missing or ambiguous: $key"
        [[ $actual == "$expected" ]] || \
            fail "Live GDM [daemon] value differs: $key=$actual"
    done
    [[ $(busctl call org.freedesktop.login1 /org/freedesktop/login1 \
        org.freedesktop.login1.Manager CanPowerOff) == 's "yes"' ]] || \
        fail "logind does not authorize Live Power Off"
    [[ $(busctl call org.freedesktop.login1 /org/freedesktop/login1 \
        org.freedesktop.login1.Manager CanReboot) == 's "yes"' ]] || \
        fail "logind does not authorize Live Restart"
fi

boot_id=$(< /proc/sys/kernel/random/boot_id)
[[ $boot_id =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || \
    fail "kernel boot identity is malformed"
if [[ $LIFECYCLE == initial && $PASS_ID != live ]]; then
    umask 077
    marker_root=/var/tmp/noid-pre-ship-session-$UID
    marker_dir=$marker_root/$PASS_ID
    marker=$marker_dir/context
    [[ -d /var/tmp && ! -L /var/tmp \
       && $(stat -c '%U:%G:%a' /var/tmp) == root:root:1777 \
       && $(readlink -e /var/tmp) == /var/tmp ]] || \
        fail "shared persistent-state parent is unsafe"
    if [[ ! -e $marker_root && ! -L $marker_root ]]; then
        mkdir -- "$marker_root" || fail "cannot create private session-marker root"
    fi
    [[ -d $marker_root && ! -L $marker_root \
       && $(readlink -e "$marker_root") == "$marker_root" \
       && $(stat -c '%u:%a' "$marker_root") == "$UID:700" ]] || \
        fail "private session-marker root is unsafe"
    [[ ! -e $marker_dir && ! -L $marker_dir ]] || \
        fail "initial-session marker already exists"
    mkdir -- "$marker_dir" || fail "cannot create private session-marker directory"
    [[ -d $marker_dir && ! -L $marker_dir \
       && $(readlink -e "$marker_dir") == "$marker_dir" \
       && $(stat -c '%u:%a' "$marker_dir") == "$UID:700" ]] || \
        fail "private session-marker directory metadata invalid"
    printf 'boot=%s\nsession=%s\n' "$boot_id" "$session_id" > "$marker"
    chmod 0600 "$marker"
    [[ -f $marker && ! -L $marker \
       && $(stat -c '%u:%a:%h' "$marker") == "$UID:600:1" ]] || \
        fail "session-marker context metadata invalid"
    sync -- "$marker" "$marker_dir"
elif [[ $LIFECYCLE == second-login ]]; then
    marker_root=/var/tmp/noid-pre-ship-session-$UID
    marker_dir=$marker_root/$PASS_ID
    marker=$marker_dir/context
    [[ -d /var/tmp && ! -L /var/tmp \
       && $(stat -c '%U:%G:%a' /var/tmp) == root:root:1777 \
       && $(readlink -e /var/tmp) == /var/tmp ]] || \
        fail "shared persistent-state parent is unsafe"
    for private_marker_dir in "$marker_root" "$marker_dir"; do
        [[ -d $private_marker_dir && ! -L $private_marker_dir \
           && $(readlink -e "$private_marker_dir") == "$private_marker_dir" \
           && $(stat -c '%u:%a' "$private_marker_dir") == "$UID:700" ]] || \
            fail "private session-marker directory is unsafe: $private_marker_dir"
    done
    [[ -f $marker && ! -L $marker \
       && $(stat -c '%u:%a:%h' "$marker") == "$UID:600:1" ]] || \
        fail "initial-session marker context missing or unsafe"
    mapfile -t marker_context < "$marker"
    [[ ${#marker_context[@]} -eq 2 \
       && ${marker_context[0]} == boot=* \
       && ${marker_context[1]} == session=* ]] || \
        fail "initial-session marker context schema invalid"
    old_boot=${marker_context[0]#boot=}
    old_session=${marker_context[1]#session=}
    [[ $old_boot == "$boot_id" ]] || fail "second login is not in the same boot"
    [[ -n $old_session && $old_session != "$session_id" ]] || \
        fail "second-login gate did not observe a new session identity"
    [[ -z $(find -P "$marker_dir" -mindepth 1 -maxdepth 1 \
        ! -name context -print -quit) ]] || \
        fail "private session-marker directory contains an unexpected entry"
    rm -f -- "$marker"
    rmdir -- "$marker_dir" || fail "cannot remove exact session-marker directory"
    if [[ -z $(find -P "$marker_root" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
        rmdir -- "$marker_root" || fail "cannot remove empty session-marker root"
    fi
fi

echo "PASS  $TEST_NAME [$PASS_ID/$LIFECYCLE]: Live power/logout truth and eligible graphical notifier lifecycle exact"
