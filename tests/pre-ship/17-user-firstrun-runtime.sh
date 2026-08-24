#!/usr/bin/env bash
# Candidate-only real-user first-login transaction gate for Module 17.
# Run as the normal GNOME user after the first graphical login of each
# installed pass. It proves the per-user first-login transaction ran and
# completed on THIS boot's GNOME/systemd stack, and probes the session-class
# environment dependency the unit's start condition relies on — so a GNOME
# or systemd package change that stops exporting the session class into the
# user manager surfaces here instead of silently skipping the transaction.
# The GNOME Initial Setup pseudo-user negative is covered by
# tests/17-user-firstrun-fixture.sh and the structural condition pins.
set -euo pipefail
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin

TEST_NAME=17-user-firstrun-runtime
PASS_ID=${1:-}
case "$PASS_ID" in
    fresh-install|reboot) ;;
    *)
        echo "Usage: bash $0 {fresh-install|reboot}" >&2
        exit 2
        ;;
esac

fail() { echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2; exit 1; }
[[ $EUID -ne 0 ]] || fail "run as the normal GNOME user, not root"

for required_command in awk dconf find gio grep matchpathcon readlink stat \
        systemctl xdg-user-dir; do
    command -v "$required_command" >/dev/null 2>&1 || \
        fail "required command missing: $required_command"
done

grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
[[ ${XDG_CURRENT_DESKTOP:-} == *GNOME* ]] || fail "active desktop is not GNOME"
[[ -n ${DBUS_SESSION_BUS_ADDRESS:-} ]] || fail "session D-Bus address is missing"

unit=/usr/lib/systemd/user/noid-user-firstrun.service
wants=/usr/lib/systemd/user/graphical-session.target.wants/noid-user-firstrun.service
helper=/usr/local/libexec/noid-user-firstrun
update_timer=/etc/systemd/user/noid-update-reminder.timer
notifier=/usr/lib/systemd/user/usbguard-notifier.service
notifier_wants=/usr/lib/systemd/user/graphical-session.target.wants/usbguard-notifier.service
[[ -f $unit && ! -L $unit \
   && $(stat -c '%U:%G:%a:%h' "$unit") == root:root:644:1 ]] || \
    fail "first-login unit metadata invalid"
[[ -L $wants && $(stat -c '%U:%G:%h' "$wants") == root:root:1 \
   && $(readlink "$wants") == "$unit" ]] || \
    fail "graphical-session wants link invalid"
[[ -x $helper && ! -L $helper \
   && $(stat -c '%U:%G:%a:%h' "$helper") == root:root:755:1 ]] || \
    fail "first-login helper metadata invalid"
[[ -f $update_timer && ! -L $update_timer \
   && $(stat -c '%U:%G:%a:%h' "$update_timer") == root:root:644:1 ]] || \
    fail "update-reminder timer metadata invalid"
[[ -f $notifier && ! -L $notifier \
   && $(stat -c '%U:%G:%a:%h' "$notifier") == root:root:644:1 ]] || \
    fail "static notifier unit metadata invalid"
[[ -L $notifier_wants \
   && $(stat -c '%U:%G:%h' "$notifier_wants") == root:root:1 \
   && $(readlink "$notifier_wants") == "$notifier" ]] || \
    fail "static notifier wants link invalid"
for root_file in "$unit" "$helper" "$update_timer" "$notifier"; do
    matchpathcon -V "$root_file" >/dev/null 2>&1 || \
        fail "SELinux context invalid: $root_file"
done
[[ $(systemctl --user show noid-user-firstrun.service \
        -p FragmentPath --value) == "$unit" ]] || \
    fail "loaded first-login unit fragment differs"
[[ $(systemctl --user show noid-update-reminder.timer \
        -p FragmentPath --value) == "$update_timer" ]] || \
    fail "loaded update-reminder timer fragment differs"
[[ $(systemctl --user show usbguard-notifier.service \
        -p FragmentPath --value) == "$notifier" ]] || \
    fail "loaded notifier unit fragment differs"
grep -qxF 'ConditionEnvironment=XDG_SESSION_CLASS=user' "$unit" || \
    fail "unit lacks the real-user session-class condition"

# Probe the environment dependency directly: the condition can only ever
# pass if GNOME exported the session class into this user manager.
manager_environment=$(systemctl --user show-environment 2>/dev/null) || \
    fail "cannot inspect the user-manager environment"
manager_class=$(awk -F= '
    $1 == "XDG_SESSION_CLASS" {
        count++
        value=substr($0, length($1) + 2)
    }
    END {
        if (count != 1) exit 1
        print value
    }
' <<<"$manager_environment") || \
    fail "user manager environment lacks one unambiguous XDG_SESSION_CLASS"
[[ $manager_class == user ]] || \
    fail "user manager XDG_SESSION_CLASS is not user ($manager_class)"

# Then the outcome on this stack: condition passed, unit succeeded.
condition=$(systemctl --user show noid-user-firstrun.service -p ConditionResult --value)
[[ $condition == yes ]] || \
    fail "first-login unit start condition did not pass (ConditionResult=$condition)"
result=$(systemctl --user show noid-user-firstrun.service -p Result --value)
[[ $result == success ]] || fail "first-login unit result is not success ($result)"
active_state=$(systemctl --user show noid-user-firstrun.service -p ActiveState --value)
sub_state=$(systemctl --user show noid-user-firstrun.service -p SubState --value)
[[ $active_state == inactive && $sub_state == dead ]] || \
    fail "completed oneshot state differs ($active_state/$sub_state)"
main_start=$(systemctl --user show noid-user-firstrun.service \
    -p ExecMainStartTimestampMonotonic --value)
main_exit=$(systemctl --user show noid-user-firstrun.service \
    -p ExecMainExitTimestampMonotonic --value)
main_code=$(systemctl --user show noid-user-firstrun.service -p ExecMainCode --value)
main_status=$(systemctl --user show noid-user-firstrun.service -p ExecMainStatus --value)
invocation_id=$(systemctl --user show noid-user-firstrun.service -p InvocationID --value)
[[ $main_start =~ ^[1-9][0-9]*$ \
   && $main_exit =~ ^[1-9][0-9]*$ \
   && $main_exit -ge $main_start \
   && $main_code == 1 \
   && $main_status == 0 \
   && $invocation_id =~ ^[0-9a-f]{32}$ ]] || \
    fail "first-login unit lacks a successful invocation in this boot"
systemctl --user is-enabled --quiet noid-update-reminder.timer || \
    fail "update-reminder timer is not enabled"
systemctl --user is-active --quiet noid-update-reminder.timer || \
    fail "update-reminder timer is not active"
systemctl --user is-active --quiet usbguard-notifier.service || \
    fail "static notifier is not active in the graphical session"
notifier_result=$(systemctl --user show usbguard-notifier.service -p Result --value)
[[ $notifier_result == success ]] || \
    fail "static notifier unit result is not success ($notifier_result)"

# Finally the durable transaction evidence: every task marker, exact schema.
[[ ${HOME:-} == /* ]] || fail "HOME must be absolute"
config_home=${XDG_CONFIG_HOME:-$HOME/.config}
[[ $config_home == /* && $config_home != / ]] || \
    fail "configuration home must be an absolute non-root path"
state_dir=$config_home/noid-user-firstrun
[[ -d $state_dir && ! -L $state_dir ]] || fail "first-login state directory missing"
[[ $(stat -c '%u:%a' "$state_dir") == "$EUID:700" ]] || \
    fail "first-login state directory metadata differs"
for task in region nautilus_download_sort libvirt_qemu_core noid_update_reminder \
        usbguard_notifier complete; do
    marker="$state_dir/$task-v2.done"
    expected=$(printf 'version=2\nstatus=complete\ntask=%s' "$task")
    expected_size=$((${#expected} + 1))
    [[ -f $marker && ! -L $marker \
       && $(stat -c '%u:%a:%h:%s' "$marker") == \
            "$EUID:600:1:$expected_size" ]] || \
        fail "task marker metadata differs: $task"
    [[ $(<"$marker") == "$expected" ]] || \
        fail "task marker content differs: $task"
done
unexpected_state=$(find -P "$state_dir" -mindepth 1 -maxdepth 1 \
    ! -name region-v2.done \
    ! -name nautilus_download_sort-v2.done \
    ! -name libvirt_qemu_core-v2.done \
    ! -name noid_update_reminder-v2.done \
    ! -name usbguard_notifier-v2.done \
    ! -name complete-v2.done \
    -print -quit)
[[ -z $unexpected_state ]] || fail "first-login state contains an unexpected entry"
legacy_sentinel="$HOME/.config/noid-user-firstrun.done"
[[ ! -e $legacy_sentinel && ! -L $legacy_sentinel ]] || \
    fail "retired v1 sentinel still present"

# The session driver has no fallback to /etc/libvirt/qemu.conf. Prove the
# per-user functional compatibility file that allowed the task marker to land.
libvirt_dir=$config_home/libvirt
libvirt_conf=$libvirt_dir/qemu.conf
[[ -d $libvirt_dir && ! -L $libvirt_dir \
   && $(stat -c '%u:%a' "$libvirt_dir") == "$EUID:700" ]] || \
    fail "session libvirt directory metadata differs"
[[ -f $libvirt_conf && ! -L $libvirt_conf \
   && $(stat -c '%u:%a:%h' "$libvirt_conf") == "$EUID:600:1" ]] || \
    fail "session libvirt qemu.conf metadata differs"
[[ $(grep -Ec '^[[:space:]]*max_core[[:space:]]*=' "$libvirt_conf") -eq 1 \
   && $(grep -Ec \
        '^[[:space:]]*max_core[[:space:]]*=[[:space:]]*0[[:space:]]*(#.*)?$' \
        "$libvirt_conf") -eq 1 ]] || \
    fail "session max_core is not unique and zero"
[[ $(grep -Ec '^[[:space:]]*dump_guest_core[[:space:]]*=' \
        "$libvirt_conf") -eq 1 \
   && $(grep -Ec \
        '^[[:space:]]*dump_guest_core[[:space:]]*=[[:space:]]*0[[:space:]]*(#.*)?$' \
        "$libvirt_conf") -eq 1 ]] || \
    fail "session dump_guest_core is not unique and zero"

# Prove both layers of the unlocked Nautilus default contract. dconf's
# default-only reads are unaffected by any user value Nautilus migration may
# already have written. Downloads is then checked through the same native GIO
# metadata attributes consumed by Nautilus 50.
[[ $(DCONF_PROFILE=user dconf read -d \
        /org/gtk/settings/file-chooser/show-hidden) == true ]] || \
    fail "GTK3 hidden-file migration default is not true"
[[ $(DCONF_PROFILE=user dconf read -d \
        /org/gtk/gtk4/settings/file-chooser/show-hidden) == true ]] || \
    fail "GTK4 hidden-file runtime default is not true"
[[ $(DCONF_PROFILE=user dconf read -d \
        /org/gnome/nautilus/preferences/default-sort-order) == "'name'" ]] || \
    fail "generic Nautilus default sort is not name"
[[ $(DCONF_PROFILE=user dconf read -d \
        /org/gnome/nautilus/preferences/default-sort-in-reverse-order) == false ]] || \
    fail "generic Nautilus default sort is not ascending"
download_dir=$(xdg-user-dir DOWNLOAD) || fail "cannot resolve XDG Downloads"
[[ $download_dir == /* && $download_dir != / && -d $download_dir ]] || \
    fail "XDG Downloads is not one existing absolute non-root directory"
download_sort=$(gio info \
    --attributes=metadata::nautilus-icon-view-sort-by,metadata::nautilus-icon-view-sort-reversed \
    "$download_dir") || fail "cannot read Downloads Nautilus metadata"
grep -qxF '  metadata::nautilus-icon-view-sort-by: name' \
    <<<"$download_sort" || fail "Downloads is not sorted by name"
grep -qxF '  metadata::nautilus-icon-view-sort-reversed: false' \
    <<<"$download_sort" || fail "Downloads name sorting is not ascending"

echo "PASS  $TEST_NAME [$PASS_ID]: real-user first-login transaction complete; session-class dependency intact"
