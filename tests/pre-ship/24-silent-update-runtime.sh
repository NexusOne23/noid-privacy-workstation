#!/usr/bin/env bash
# Candidate-only proof that background update surfaces stay silent while the
# deliberate Update All and GNOME Software launch paths remain intact.
set -euo pipefail
ulimit -c 0

TEST_NAME=24-silent-update-runtime
PASS_ID=${1:-}
case "$PASS_ID" in
    live|fresh-install|reboot) ;;
    *) echo "Usage: bash $0 {live|fresh-install|reboot}" >&2; exit 2 ;;
esac

fail() { echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] || fail "run as the normal GNOME user, not root"
grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
[[ ${XDG_CURRENT_DESKTOP:-} == *GNOME* ]] || fail "active desktop is not GNOME"
[[ -n ${DBUS_SESSION_BUS_ADDRESS:-} ]] || fail "session D-Bus address is missing"

for command_name in awk bash busctl cmp desktop-file-edit desktop-file-install \
        desktop-file-validate env find gdbus grep matchpathcon mktemp pgrep python3 \
        readlink rm rpm sed sha256sum sleep sort stat sudo systemctl tail timeout \
        tr visudo; do
    command -v "$command_name" >/dev/null 2>&1 || \
        fail "required command missing: $command_name"
done
rpm -q gnome-software fwupd desktop-file-utils dnf5daemon-server >/dev/null || \
    fail "reviewed GNOME Software/fwupd runtime packages are incomplete"

tmp=$(mktemp -d "${XDG_RUNTIME_DIR:-/var/tmp}/noid-silent-update.XXXXXXXX")
software_started=0
cleanup() {
    if [[ $software_started -eq 1 && -x ${quit_helper:-} ]]; then
        "$quit_helper" >/dev/null 2>&1 || true
    fi
    rm -rf -- "$tmp"
}
trap cleanup EXIT HUP INT TERM

verify_rpm_file() {
    local path=$1 package=$2 expected_config=${3:-0}
    local record dump_path expected_size expected_mtime
    local expected_sha expected_mode expected_owner expected_group dump_config
    local dump_doc dump_rdev dump_caps dump_extra
    [[ -f $path && ! -L $path ]] || fail "RPM payload is missing or unsafe: $path"
    [[ $(rpm -qf --qf '%{NAME}\n' "$path" 2>/dev/null || true) == "$package" ]] || \
        fail "RPM owner differs for $path"
    record=$(rpm -q --dump "$package" 2>/dev/null | \
        awk -v wanted="$path" '$1 == wanted {print; found=1} END {exit !found}') || \
        fail "RPM dump record missing for $path"
    read -r dump_path expected_size expected_mtime expected_sha expected_mode \
        expected_owner expected_group dump_config dump_doc dump_rdev dump_caps \
        dump_extra <<< "$record"
    [[ $dump_path == "$path" && $expected_mode == 0100644 \
       && ${dump_config:-}:${dump_doc:-}:${dump_rdev:-}:${dump_caps:-} == \
          "$expected_config:0:0:X" \
       && -z ${dump_extra:-} ]] || fail "RPM dump record malformed for $path"
    [[ $(stat -c '%s:%Y:%U:%G:%a:%h' "$path" 2>/dev/null || true) == \
       "$expected_size:$expected_mtime:$expected_owner:$expected_group:644:1" ]] || \
        fail "RPM metadata differs for $path"
    [[ $(sha256sum "$path" | awk '{print $1}') == "$expected_sha" ]] || \
        fail "RPM bytes differ for $path"
}

verify_safe_root_dir() {
    local path=$1 metadata uid gid mode
    [[ -d $path && ! -L $path ]] || return 1
    metadata=$(stat -Lc '%u:%g:%a' -- "$path" 2>/dev/null) || return 1
    IFS=: read -r uid gid mode <<< "$metadata"
    [[ $uid:$gid == 0:0 ]] || return 1
    (( (8#$mode & 8#022) == 0 ))
}

verify_owned_file() {
    local path=$1 mode=$2
    [[ -f $path && ! -L $path ]] && \
        [[ $(stat -Lc '%U:%G:%a:%h' -- "$path" 2>/dev/null || true) == \
           "root:root:$mode:1" ]]
}

require_masked_inactive() {
    local unit=$1 state
    state=$(systemctl is-enabled "$unit" 2>/dev/null || true)
    [[ $state == masked ]] || fail "$unit is not masked (state=$state)"
    ! systemctl --quiet is-active "$unit" || fail "$unit is active"
}

software_name_owned() {
    gdbus call --session \
        --dest org.freedesktop.DBus \
        --object-path /org/freedesktop/DBus \
        --method org.freedesktop.DBus.ListNames 2>/dev/null | \
        grep -q "'org.gnome.Software'"
}

admin_service=/usr/local/share/dbus-1/services/org.gnome.Software.service
vendor_service=/usr/share/dbus-1/services/org.gnome.Software.service
dbus_policy=/etc/dbus-1/session.d/20-noid-blocked-services.conf
dbus_block_unit=/etc/systemd/user/noid-blocked-session-service.service
admin_desktop=/usr/local/share/applications/org.gnome.Software.desktop
vendor_desktop=/usr/share/applications/org.gnome.Software.desktop
sync_helper=/usr/local/sbin/noid-gnome-software-launcher-sync
sync_action=/etc/dnf/libdnf5-plugins/actions.d/noid-gnome-software-launcher.actions
quit_helper=/usr/local/bin/noid-gnome-software-quit
rpm_helper=/usr/local/bin/noid-gnome-software-rpm
backend_stop=/usr/local/sbin/noid-gnome-software-backend-stop
quit_sudoers=/etc/sudoers.d/48-noid-gnome-software-quit
software_wrapper=/usr/local/bin/gnome-software

[[ ! -e $admin_service && ! -L $admin_service ]] || \
    fail "redundant GNOME Software D-Bus admin override remains"
[[ -L $dbus_block_unit && $(readlink "$dbus_block_unit") == /dev/null ]] || \
    fail "common D-Bus denial unit is not globally masked"
[[ $(stat -c '%U:%G:%a' "$dbus_policy" 2>/dev/null || true) == root:root:644 ]] || \
    fail "reference-bus send-deny policy metadata differs"
grep -qxF '  <policy context="mandatory">' "$dbus_policy" || \
    fail "reference-bus mandatory policy is missing"
tracker_names=(
    org.freedesktop.Tracker3.Miner.Files
    org.freedesktop.Tracker3.Miner.Files.Control
    org.freedesktop.Tracker3.Writeback
    org.freedesktop.portal.Tracker
)
policy_names=(
    org.gnome.OnlineAccounts
    org.gnome.Identity
    "${tracker_names[@]}"
)
for service_name in "${policy_names[@]}"; do
    grep -qxF "    <deny send_destination=\"$service_name\"/>" "$dbus_policy" || \
        fail "reference-bus denial missing for $service_name"
done
for service_name in "${tracker_names[@]}"; do
    tracker_admin="/usr/local/share/dbus-1/services/$service_name.service"
    [[ ! -e $tracker_admin && ! -L $tracker_admin ]] || \
        fail "delayed Tracker admin override remains: $tracker_admin"
done
verify_rpm_file "$vendor_service" gnome-software
verify_rpm_file "$vendor_desktop" gnome-software
grep -qxF 'SystemdService=gnome-software.service' "$vendor_service" || \
    fail "Fedora GNOME Software descriptor lost its native masked-unit route"

[[ -L /etc/systemd/user/gnome-software.service \
   && $(readlink /etc/systemd/user/gnome-software.service) == /dev/null ]] || \
    fail "GNOME Software user service is not globally masked"
[[ $(stat -c '%U:%G:%a' "$sync_helper" 2>/dev/null || true) == root:root:755 ]] || \
    fail "GNOME Software launcher synchronizer metadata differs"
[[ -f $quit_helper && ! -L $quit_helper \
   && $(stat -c '%U:%G:%a' "$quit_helper" 2>/dev/null || true) == root:root:755 ]] || \
    fail "GNOME Software complete-quit helper metadata differs"
[[ -f $rpm_helper && ! -L $rpm_helper \
   && $(stat -c '%U:%G:%a' "$rpm_helper" 2>/dev/null || true) == root:root:755 ]] || \
    fail "GNOME Software Fedora-RPM helper metadata differs"
[[ -f $software_wrapper && ! -L $software_wrapper \
   && $(stat -c '%U:%G:%a' "$software_wrapper" 2>/dev/null || true) == root:root:755 ]] || \
    fail "GNOME Software explicit wrapper metadata differs"
bash -n "$software_wrapper" || fail "GNOME Software explicit wrapper does not parse"
software_plugins=flatpak,icons,hardcoded-blocklist,malcontent,modalias,os-release,provenance,provenance-license,generic-updates
grep -qxF "NOID_SOFTWARE_PLUGINS=$software_plugins" "$software_wrapper" || \
    fail "GNOME Software explicit Flatpak-store scope differs"
# shellcheck disable=SC2016 # exact installed-wrapper source contract
grep -qxF '    export GNOME_SOFTWARE_PLUGINS_ALLOWLIST="$NOID_SOFTWARE_PLUGINS"' \
    "$software_wrapper" || fail "GNOME Software wrapper does not export its reviewed scope"
! grep -Eq 'systemctl|--gapplication-service|--autostart' "$software_wrapper" || \
    fail "GNOME Software wrapper can manage or background-start its service"
bash -n "$quit_helper" || fail "GNOME Software complete-quit helper does not parse"
grep -qxF '/usr/bin/sudo -n /usr/local/sbin/noid-gnome-software-backend-stop' \
    "$quit_helper" || fail "complete-quit privilege route is not noninteractive and exact"
bash -n "$rpm_helper" || fail "GNOME Software Fedora-RPM helper does not parse"
rpm_plugins=flatpak,appstream,dnf5,icons,hardcoded-blocklist,malcontent,modalias,os-release,provenance,provenance-license,generic-updates
grep -qxF "RPM_PLUGINS=$rpm_plugins" "$rpm_helper" || \
    fail "GNOME Software Fedora-RPM one-shot scope differs"
# shellcheck disable=SC2016 # exact installed-helper source contract
grep -qxF 'exec "$SOFTWARE"' "$rpm_helper" || \
    fail "GNOME Software Fedora-RPM helper bypasses the reviewed wrapper"
! grep -qF 'fwupd' "$rpm_helper" || \
    fail "GNOME Software Fedora-RPM helper can enable the firmware plugin"
[[ -f $backend_stop && ! -L $backend_stop \
   && $(stat -c '%U:%G:%a' "$backend_stop" 2>/dev/null || true) == root:root:755 ]] || \
    fail "GNOME Software backend-stop helper metadata differs"
bash -n "$backend_stop" || fail "GNOME Software backend-stop helper does not parse"
grep -qF "expected_tree=\$'/\\n/org\\n/org/rpm\\n/org/rpm/dnf\\n/org/rpm/dnf/v0'" \
    "$backend_stop" || fail "backend-stop helper lacks the closed idle object tree"
# shellcheck disable=SC2016 # exact installed-helper source contract
grep -qxF 'deadline=$((SECONDS + 90))' "$backend_stop" || \
    fail "backend-stop helper lacks the bounded DNF Session teardown wait"
grep -qxF '    /usr/bin/sleep 0.25' "$backend_stop" || \
    fail "backend-stop helper does not poll DNF Session teardown conservatively"
# shellcheck disable=SC2016 # exact root-helper source contract
grep -qxF '/usr/bin/systemctl stop "$unit"' "$backend_stop" || \
    fail "backend-stop helper does not target its closed unit variable"
if ! sudo -n /usr/bin/test -f "$quit_sudoers" \
   || sudo -n /usr/bin/test -L "$quit_sudoers" \
   || [[ $(sudo -n stat -c '%U:%G:%a' "$quit_sudoers" 2>/dev/null || true) != \
         root:root:440 ]]; then
    fail "GNOME Software complete-quit sudoers metadata differs"
fi
[[ $(sudo -n grep -cEv '^[[:space:]]*(#|$)' "$quit_sudoers" || true) -eq 1 ]] || \
    fail "complete-quit sudoers active-command count differs"
sudo -n grep -qxF \
    '%wheel ALL=(root) NOPASSWD: /usr/local/sbin/noid-gnome-software-backend-stop ""' \
    "$quit_sudoers" || fail "complete-quit sudoers command is not argumentless and exact"
sudo -n visudo -cf "$quit_sudoers" >/dev/null || \
    fail "complete-quit sudoers contract does not parse"
[[ $(stat -c '%U:%G:%a' "$sync_action" 2>/dev/null || true) == root:root:644 ]] || \
    fail "GNOME Software package action metadata differs"
grep -qxF \
    'post_transaction:gnome-software:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-gnome-software-launcher-sync\ >/dev/null' \
    "$sync_action" || fail "GNOME Software package action differs"

vendor_actions_count=$(awk '
    $0 == "[Desktop Entry]" { in_entry=1; next }
    /^\[/ { in_entry=0 }
    in_entry && /^Actions=/ { count++ }
    END { print count + 0 }
' "$vendor_desktop")
[[ $vendor_actions_count -le 1 ]] || fail "vendor launcher has duplicate Actions keys"
vendor_actions=$(awk '
    $0 == "[Desktop Entry]" { in_entry=1; next }
    /^\[/ { in_entry=0 }
    in_entry && /^Actions=/ { print substr($0, 9) }
' "$vendor_desktop")
vendor_actions=${vendor_actions%;}
for noid_action in NoIDFedoraRPM NoIDQuit; do
    [[ ";$vendor_actions;" != *";$noid_action;"* ]] || \
        fail "vendor launcher already owns the $noid_action action"
    ! grep -qxF "[Desktop Action $noid_action]" "$vendor_desktop" || \
        fail "vendor launcher already owns the $noid_action action group"
done
if [[ -n $vendor_actions ]]; then
    admin_actions="$vendor_actions;NoIDFedoraRPM;NoIDQuit;"
else
    admin_actions='NoIDFedoraRPM;NoIDQuit;'
fi
expected_desktop="$tmp/org.gnome.Software.desktop"
desktop-file-install --dir="$tmp" --mode=0644 \
    --set-key=DBusActivatable --set-value=false "$vendor_desktop" || \
    fail "cannot independently copy the expected admin launcher"
printf '\n[Desktop Action NoIDFedoraRPM]\nName=Open GNOME Software with Fedora RPMs\nName[de]=GNOME Software mit Fedora-RPMs öffnen\nExec=/usr/local/bin/noid-gnome-software-rpm\n\n[Desktop Action NoIDQuit]\nName=Quit completely\nName[de]=Vollständig beenden\nExec=/usr/local/bin/noid-gnome-software-quit\n' \
    >> "$expected_desktop" || fail "cannot independently add the NoID Privacy action groups"
desktop-file-edit --set-key=Actions --set-value="$admin_actions" \
    "$expected_desktop" || fail "cannot independently reference complete-quit"
[[ $(stat -c '%U:%G:%a' "$admin_desktop" 2>/dev/null || true) == root:root:644 ]] || \
    fail "GNOME Software admin launcher metadata differs"
matchpathcon -V "$admin_desktop" >/dev/null 2>&1 || \
    fail "GNOME Software admin launcher SELinux context differs"
desktop-file-validate "$admin_desktop" || fail "GNOME Software admin launcher is invalid"
cmp -s "$expected_desktop" "$admin_desktop" || \
    fail "GNOME Software admin launcher differs from its exact native transform"
grep -qxF 'DBusActivatable=false' "$admin_desktop" || \
    fail "explicit launcher still requests D-Bus activation"
grep -qxF 'Exec=gnome-software %U' "$admin_desktop" || \
    fail "explicit launcher lost Fedora's execution path"
grep -qxF "Actions=$admin_actions" "$admin_desktop" || \
    fail "explicit launcher action list differs"
[[ $(grep -c '^\[Desktop Action NoIDQuit\]$' "$admin_desktop") -eq 1 ]] || \
    fail "explicit launcher complete-quit action count differs"
[[ $(grep -c '^\[Desktop Action NoIDFedoraRPM\]$' "$admin_desktop") -eq 1 ]] || \
    fail "explicit launcher Fedora-RPM action count differs"
grep -qxF 'Exec=/usr/local/bin/noid-gnome-software-rpm' "$admin_desktop" || \
    fail "explicit launcher lost GNOME Software's Fedora-RPM path"
grep -qxF 'Exec=/usr/local/bin/noid-gnome-software-quit' "$admin_desktop" || \
    fail "explicit launcher lost GNOME Software's complete-quit path"

python3 - <<'PY' || fail "GIO does not resolve the explicit admin launcher"
import gi

gi.require_version("GioUnix", "2.0")
from gi.repository import GioUnix

info = GioUnix.DesktopAppInfo.new("org.gnome.Software.desktop")
if info is None:
    raise SystemExit("desktop entry not resolved")
if info.get_filename() != "/usr/local/share/applications/org.gnome.Software.desktop":
    raise SystemExit(f"wrong XDG winner: {info.get_filename()!r}")
if info.get_boolean("DBusActivatable"):
    raise SystemExit("GIO still selects D-Bus activation")
if info.get_string("Exec") != "gnome-software %U":
    raise SystemExit(f"wrong direct Exec: {info.get_string('Exec')!r}")
actions = info.list_actions()
if actions != ["NoIDFedoraRPM", "NoIDQuit"]:
    raise SystemExit(f"NoID Privacy action list differs: {actions!r}")
for action in actions:
    if not info.get_action_name(action):
        raise SystemExit(f"desktop action has no localized name: {action}")
PY

fwupd_conf=/etc/fwupd/fwupd.conf
stable_remote=/etc/fwupd/remotes.d/lvfs.conf
testing_remote=/etc/fwupd/remotes.d/lvfs-testing.conf
embargo_remote=/etc/fwupd/remotes.d/lvfs-embargo.conf
vendor_remote=/etc/fwupd/remotes.d/vendor-directory.conf
state_dropin=/etc/systemd/system/fwupd.service.d/97-noid-state-privacy.conf
keep_warm=/etc/systemd/system/fwupd.service.d/99-noid-keep-warm.conf
boot_link=/etc/systemd/system/multi-user.target.wants/fwupd.service
FWUPD_MIN_VERSION=2.1.7
fwupd_version=$(rpm -q --qf '%{VERSION}' fwupd 2>/dev/null) || \
    fail "cannot read installed fwupd version"
FWUPD_VERSION_CANDIDATE=$fwupd_version \
FWUPD_MIN_VERSION_CANDIDATE=$FWUPD_MIN_VERSION rpm --eval \
    '%{lua:if rpm.vercmp(os.getenv("FWUPD_VERSION_CANDIDATE"), os.getenv("FWUPD_MIN_VERSION_CANDIDATE")) < 0 then error("below minimum") end}' \
    >/dev/null 2>&1 || \
    fail "fwupd $fwupd_version is below required $FWUPD_MIN_VERSION"
for config_dir in /etc/fwupd /etc/fwupd/remotes.d; do
    verify_safe_root_dir "$config_dir" || \
        fail "fwupd configuration directory is unsafe: $config_dir"
done
for mutable_dir in /var/lib/fwupd /var/lib/fwupd/remotes.d; do
    if [[ -e $mutable_dir || -L $mutable_dir ]]; then
        verify_safe_root_dir "$mutable_dir" || \
            fail "fwupd mutable directory is unsafe: $mutable_dir"
    fi
done
verify_owned_file "$state_dropin" 644 || \
    fail "fwupd state privacy drop-in metadata differs"
[[ $(grep -cxF '[Service]' "$state_dropin") -eq 1 ]] || \
    fail "fwupd state privacy drop-in section differs"
[[ $(grep -cxF 'StateDirectoryMode=0700' "$state_dropin") -eq 1 ]] || \
    fail "fwupd state privacy mode assignment differs"
[[ $(stat -Lc '%u:%g:%a' -- /var/lib/fwupd 2>/dev/null || true) == 0:0:700 ]] || \
    fail "fwupd firmware and HSI history is not root-only"
[[ $(systemctl show fwupd.service -p StateDirectory --value) == fwupd ]] || \
    fail "fwupd vendor StateDirectory contract differs"
[[ $(systemctl show fwupd.service -p StateDirectoryMode --value) == 0700 ]] || \
    fail "effective fwupd state directory mode is not root-only"
verify_owned_file "$fwupd_conf" 640 || \
    fail "fwupd.conf metadata differs"
# This privacy configuration is intentionally not readable by the desktop
# user. The gate stays in that user's GNOME/D-Bus context but uses an already
# authenticated, noninteractive sudo ticket for this bounded read only.
sudo -n /usr/bin/test -r "$fwupd_conf" || \
    fail "privileged fwupd.conf read unavailable; run sudo -v immediately before this gate"
for line in P2pPolicy=nothing 'DisabledPlugins=redfish;android_boot' OnlyTrusted=true \
        UpdateMotd=false ShowDevicePrivate=false IdleTimeout=300 \
        IdleInhibitStartupThreshold=0; do
    fwupd_line_count=
    if fwupd_line_count=$(sudo -n /usr/bin/grep -cxF -- "$line" "$fwupd_conf" \
            2>"$tmp/fwupd-conf-grep.err"); then
        :
    else
        fwupd_grep_rc=$?
        [[ $fwupd_grep_rc -eq 1 ]] || \
            fail "privileged fwupd.conf read failed for $line"
    fi
    [[ ${fwupd_line_count:-0} -eq 1 ]] || \
        fail "fwupd.conf exact assignment missing or duplicated: $line"
done
for remote_contract in \
        "$stable_remote:true" "$testing_remote:false" "$embargo_remote:false"; do
    remote_path=${remote_contract%:*}
    remote_enabled=${remote_contract##*:}
    verify_owned_file "$remote_path" 644 || \
        fail "owned network remote metadata differs: $remote_path"
    grep -qxF '[fwupd Remote]' "$remote_path" || \
        fail "owned network remote section differs: $remote_path"
    for line in "Enabled=$remote_enabled" AutomaticReports=false \
            AutomaticSecurityReports=false; do
        [[ $(grep -cxF "$line" "$remote_path") -eq 1 ]] || \
            fail "owned remote assignment missing or duplicated: $remote_path: $line"
    done
    ! grep -Eq '^[[:space:]]*ReportURI[[:space:]]*=' "$remote_path" || \
        fail "owned network remote has a reporting endpoint: $remote_path"
done
verify_rpm_file "$vendor_remote" fwupd 1
grep -qxF '[fwupd Remote]' "$vendor_remote" || \
    fail "vendor-directory remote section differs"
grep -qxF 'Enabled=true' "$vendor_remote" || \
    fail "vendor-directory is not enabled"
grep -qxF 'MetadataURI=file:///usr/share/fwupd/remotes.d/vendor/firmware' \
    "$vendor_remote" || fail "vendor-directory is not the packaged local source"
! grep -Eq '^[[:space:]]*ReportURI[[:space:]]*=' "$vendor_remote" || \
    fail "vendor-directory unexpectedly has a reporting endpoint"
expected_remote_files=$(
    printf '%s\n' lvfs-embargo.conf lvfs-testing.conf lvfs.conf \
        vendor-directory.conf |
        LC_ALL=C sort
)
actual_remote_files=$(
    find -P /etc/fwupd/remotes.d -mindepth 1 -maxdepth 1 \
        -name '*.conf' -printf '%f\n' |
        LC_ALL=C sort
)
[[ $actual_remote_files == "$expected_remote_files" ]] || \
    fail "effective fwupd remote source-file inventory differs"
if [[ -d /var/lib/fwupd/remotes.d ]] && \
   [[ -n $(find -P /var/lib/fwupd/remotes.d -mindepth 1 -maxdepth 1 \
        -name '*.conf' -print -quit) ]]; then
    fail "unexpected mutable fwupd remote definition"
fi
[[ ! -e $keep_warm && ! -L $keep_warm ]] || \
    fail "retired fwupd keep-warm drop-in remains"
[[ ! -e $boot_link && ! -L $boot_link ]] || \
    fail "fwupd.service remains linked into the boot target"
[[ $(systemctl is-enabled fwupd.service 2>/dev/null || true) == static ]] || \
    fail "fwupd.service is not the upstream static D-Bus service"

for unit in fwupd-refresh.timer fwupd-refresh.service passim.service \
        packagekit.service; do
    require_masked_inactive "$unit"
done
if rpm -q PackageKit >/dev/null 2>&1; then
    fail "retired PackageKit daemon package is installed"
fi

if [[ $PASS_ID == live ]]; then
    grep -Eq '(^|[[:space:]])rd\.live\.image(=([^[:space:]]*)?)?([[:space:]]|$)' \
        /proc/cmdline || fail "live pass lacks the initramfs Live-media marker"
else
    if grep -Eq '(^|[[:space:]])rd\.live\.image(=([^[:space:]]*)?)?([[:space:]]|$)' \
            /proc/cmdline; then
        fail "installed pass still carries the Live-media marker"
    fi
fi
! systemctl --quiet is-active fwupd.service || \
    fail "fwupd runs before an explicit firmware command"

command -v noid-status >/dev/null 2>&1 || fail "noid-status is unavailable"
noid-status --json >"$tmp/noid-status.json" 2>"$tmp/noid-status.err" || \
    fail "noid-status JSON probe failed"
python3 -m json.tool "$tmp/noid-status.json" >/dev/null || \
    fail "noid-status JSON probe is malformed"
! systemctl --quiet is-active fwupd.service || \
    fail "noid-status woke the boot-dormant fwupd service"

update_helper=/usr/local/bin/noid-update-all.sh
[[ $(stat -c '%U:%G:%a' "$update_helper" 2>/dev/null || true) == root:root:755 ]] || \
    fail "Update All orchestrator metadata differs"
# These are exact literal source contracts, not expressions for this shell.
# shellcheck disable=SC2016
for line in \
    'LC_ALL=C fwupdmgr refresh --force 2>&1' \
    'fw_updates=$(LC_ALL=C fwupdmgr get-updates 2>&1) || fw_rc=$?' \
    '_emit_marker "PROMPT fwupd Install firmware updates"' \
    'LC_ALL=C fwupdmgr update --no-reboot-check 2>&1 | sed' \
    'LC_ALL=C fwupdmgr check-reboot-needed --json' \
    'fw_refresh_rc=${PIPESTATUS[0]}' \
    'fw_update_rc=${PIPESTATUS[0]}' \
    'sudo LC_ALL=C fwupdmgr quit' \
    'settle_fwupd_daemon'; do
    grep -qF "$line" "$update_helper" || \
        fail "Update All firmware contract missing: $line"
done
for forbidden in \
    'sudo LC_ALL=C fwupdmgr refresh --force' \
    'sudo fwupdmgr update'; do
    ! grep -qF "$forbidden" "$update_helper" || \
        fail "Update All runs a network-facing fwupd client as root: $forbidden"
done

! pgrep -u "$UID" -x gnome-software >/dev/null || \
    fail "GNOME Software already runs; close it and start this gate from a clean session"
! software_name_owned || fail "org.gnome.Software is already owned on the session bus"
! systemctl --quiet is-active dnf5daemon-server.service || \
    fail "dnf5daemon-server already runs; start this gate before manual update/app use"

fwupd_before=$(systemctl show fwupd.service -p ActiveState -p MainPID \
    -p NRestarts -p ActiveEnterTimestampMonotonic)

# A one-second ceiling keeps the native static-mask path deterministic and
# rejects a regression to a slow helper/timeout path. Every request must fail,
# but a timeout is itself a regression rather than a successful denial.
for service_name in org.gnome.Software org.gnome.OnlineAccounts org.gnome.Identity \
        "${tracker_names[@]}"; do
    set +e
    timeout 1 gdbus call --session \
        --dest "$service_name" \
        --object-path / \
        --method org.freedesktop.DBus.Peer.Ping \
        >"$tmp/dbus-$service_name.out" 2>"$tmp/dbus-$service_name.err"
    dbus_rc=$?
    set -e
    [[ $dbus_rc -ne 0 ]] || \
        fail "suppressed D-Bus service unexpectedly answered: $service_name"
    [[ $dbus_rc -ne 124 && $dbus_rc -ne 137 ]] || \
        fail "suppressed D-Bus service denial exceeded one second: $service_name"
done

if timeout 10 gdbus call --session \
        --dest org.gnome.Software \
        --object-path /org/gnome/Software \
        --method org.freedesktop.Application.Activate '{}' \
        >"$tmp/dbus-probe.out" 2>"$tmp/dbus-probe.err"; then
    fail "unsolicited GNOME Software D-Bus activation unexpectedly succeeded"
fi
sleep 1

! pgrep -u "$UID" -x gnome-software >/dev/null || \
    fail "D-Bus probe spawned GNOME Software"
! software_name_owned || fail "D-Bus probe left org.gnome.Software owned"
! systemctl --quiet is-active dnf5daemon-server.service || \
    fail "D-Bus probe activated the DNF daemon"
fwupd_after=$(systemctl show fwupd.service -p ActiveState -p MainPID \
    -p NRestarts -p ActiveEnterTimestampMonotonic)
[[ $fwupd_after == "$fwupd_before" ]] || \
    fail "D-Bus probe changed the fwupd process/restart state"
for unit in fwupd-refresh.timer fwupd-refresh.service passim.service; do
    ! systemctl --quiet is-active "$unit" || \
        fail "D-Bus probe activated $unit"
done

# The explicit launcher must start only the reviewed Flatpak plugin scope. It
# must not wake native-package or firmware backends, and the supported complete
# quit path must leave no application ownership behind.
"$software_wrapper" --verbose >"$tmp/software.out" 2>"$tmp/software.err" &
software_pid=$!
software_started=1
software_deadline=$((SECONDS + 15))
until software_name_owned; do
    kill -0 "$software_pid" 2>/dev/null || \
        fail "explicit GNOME Software launch exited before owning its D-Bus name"
    (( SECONDS < software_deadline )) || \
        fail "explicit GNOME Software launch did not become ready"
    sleep 0.1
done
sleep 1
! systemctl --quiet is-active dnf5daemon-server.service || \
    fail "explicit Flatpak-store launch activated the DNF daemon"
! systemctl --quiet is-active fwupd.service || \
    fail "explicit Flatpak-store launch activated fwupd"
"$quit_helper" || fail "explicit GNOME Software complete-quit failed"
software_started=0
wait "$software_pid" || fail "explicit GNOME Software process exited unsuccessfully"
! software_name_owned || fail "explicit complete-quit left org.gnome.Software owned"
enabled_plugins=$(sed -n 's/.*enabled plugins: //p' \
    "$tmp/software.out" "$tmp/software.err" | tail -n 1 | tr -d ' ')
disabled_plugins=$(sed -n 's/.*disabled plugins: //p' \
    "$tmp/software.out" "$tmp/software.err" | tail -n 1 | tr -d ' ')
[[ -n $enabled_plugins && -n $disabled_plugins ]] || \
    fail "GNOME Software verbose plugin evidence is incomplete"
case ",$enabled_plugins," in
    *,appstream,*|*,dnf5,*|*,fwupd,*) fail "non-Flatpak backend was enabled: $enabled_plugins" ;;
esac
for disabled_plugin in appstream dnf5 fwupd; do
    case ",$disabled_plugins," in
        *",$disabled_plugin,"*) ;;
        *) fail "expected disabled GNOME Software backend is missing: $disabled_plugin" ;;
    esac
done

# The named Fedora-RPM action is per-process only. It adds exactly appstream
# and dnf5 to the reviewed default, never fwupd, and complete-quit must release
# both the application and its sessionless DNF daemon.
env -u GNOME_SOFTWARE_PLUGINS_ALLOWLIST \
    -u GNOME_SOFTWARE_PLUGINS_BLOCKLIST \
    "$rpm_helper" >"$tmp/software-rpm.out" 2>"$tmp/software-rpm.err" &
software_pid=$!
software_started=1
software_deadline=$((SECONDS + 15))
until software_name_owned; do
    kill -0 "$software_pid" 2>/dev/null || \
        fail "Fedora-RPM one-shot exited before owning its D-Bus name"
    (( SECONDS < software_deadline )) || \
        fail "Fedora-RPM one-shot did not become ready"
    sleep 0.1
done
process_plugins=$(tr '\0' '\n' < "/proc/$software_pid/environ" | \
    sed -n 's/^GNOME_SOFTWARE_PLUGINS_ALLOWLIST=//p')
[[ $process_plugins == "$rpm_plugins" ]] || \
    fail "Fedora-RPM process plugin scope differs: $process_plugins"
dnf_deadline=$((SECONDS + 15))
until systemctl --quiet is-active dnf5daemon-server.service; do
    kill -0 "$software_pid" 2>/dev/null || \
        fail "Fedora-RPM process exited before DNF5 activation"
    (( SECONDS < dnf_deadline )) || \
        fail "Fedora-RPM one-shot did not activate DNF5"
    sleep 0.1
done
# Do not quit at the first service-activation edge: prove the complete-quit
# path survives the real catalog-loading window where GNOME Software owns a
# dynamic DNF Session and then releases it only during graceful shutdown.
dnf_session_deadline=$((SECONDS + 15))
expected_dnf_tree=$'/\n/org\n/org/rpm\n/org/rpm/dnf\n/org/rpm/dnf/v0'
while :; do
    if ! current_dnf_tree=$(busctl --system tree org.rpm.dnf.v0 \
            --list --no-pager 2>/dev/null); then
        fail "Fedora-RPM one-shot DNF Session tree is unreadable"
    fi
    [[ $current_dnf_tree == "$expected_dnf_tree" ]] || break
    kill -0 "$software_pid" 2>/dev/null || \
        fail "Fedora-RPM process exited before opening its DNF Session"
    (( SECONDS < dnf_session_deadline )) || \
        fail "Fedora-RPM one-shot did not expose its dynamic DNF Session"
    sleep 0.1
done
! systemctl --quiet is-active fwupd.service || \
    fail "Fedora-RPM one-shot activated fwupd"
"$quit_helper" || fail "Fedora-RPM complete-quit failed"
software_started=0
wait "$software_pid" || fail "Fedora-RPM process exited unsuccessfully"
! software_name_owned || fail "Fedora-RPM complete-quit left the bus name owned"
! systemctl --quiet is-active dnf5daemon-server.service || \
    fail "Fedora-RPM complete-quit left DNF5 active"
! systemctl --quiet is-active fwupd.service || \
    fail "Fedora-RPM complete-quit changed fwupd state"

# Prove the opt-in wrote no state: the very next ordinary start returns to the
# exact Flatpak-only process scope and wakes neither native backend.
"$software_wrapper" >"$tmp/software-after-rpm.out" \
    2>"$tmp/software-after-rpm.err" &
software_pid=$!
software_started=1
software_deadline=$((SECONDS + 15))
until software_name_owned; do
    kill -0 "$software_pid" 2>/dev/null || \
        fail "post-RPM default launch exited before owning its D-Bus name"
    (( SECONDS < software_deadline )) || \
        fail "post-RPM default launch did not become ready"
    sleep 0.1
done
process_plugins=$(tr '\0' '\n' < "/proc/$software_pid/environ" | \
    sed -n 's/^GNOME_SOFTWARE_PLUGINS_ALLOWLIST=//p')
[[ $process_plugins == "$software_plugins" ]] || \
    fail "Fedora-RPM opt-in persisted into the next launch: $process_plugins"
! systemctl --quiet is-active dnf5daemon-server.service || \
    fail "post-RPM default launch activated DNF5"
! systemctl --quiet is-active fwupd.service || \
    fail "post-RPM default launch activated fwupd"
"$quit_helper" || fail "post-RPM default complete-quit failed"
software_started=0
wait "$software_pid" || fail "post-RPM default process exited unsuccessfully"

# Live media deliberately cannot activate fwupd: M08 supplies a native unit
# condition because the overlay has no refreshed LVFS cache and must not fetch
# one before installation. Prove that condition directly without waiting for a
# D-Bus client timeout. Installed passes retain native on-demand activation,
# followed by fwupd's documented update-aware quit request. Never signal or
# kill the firmware daemon.
if [[ $PASS_ID == live ]]; then
    live_skip=/etc/systemd/system/fwupd.service.d/98-noid-live-skip.conf
    [[ -f $live_skip && ! -L $live_skip \
       && $(stat -c '%U:%G:%a' "$live_skip" 2>/dev/null || true) == \
          root:root:644 ]] || fail "Live fwupd skip drop-in metadata differs"
    grep -qxF 'ConditionKernelCommandLine=!rd.live.image' "$live_skip" || \
        fail "Live fwupd skip condition differs"
    sudo -n systemctl start --no-block fwupd.service || \
        fail "could not evaluate the Live fwupd unit condition"
    fwupd_live_deadline=$((SECONDS + 10))
    while [[ -n $(systemctl show fwupd.service -p Job --value) ]]; do
        (( SECONDS < fwupd_live_deadline )) || \
            fail "Live fwupd condition job did not settle"
        sleep 0.1
    done
    ! systemctl --quiet is-active fwupd.service || \
        fail "fwupd activated despite the Live-media condition"
    [[ $(systemctl show fwupd.service -p ConditionResult --value) == no ]] || \
        fail "Live fwupd unit did not record its condition skip"
    fwupd_contract='is condition-skipped on Live media'
else
    # shellcheck disable=SC2024 # command is privileged; evidence file stays user-owned
    sudo -n LC_ALL=C fwupdmgr --version --no-unreported-check \
        >"$tmp/fwupd-version.out" 2>"$tmp/fwupd-version.err" || \
        fail "local fwupd D-Bus activation probe failed"
    if systemctl --quiet is-active fwupd.service; then
        # shellcheck disable=SC2024 # command is privileged; evidence file stays user-owned
        sudo -n LC_ALL=C fwupdmgr quit --no-unreported-check \
            >"$tmp/fwupd-quit.out" 2>"$tmp/fwupd-quit.err" || \
            fail "native fwupd quit request failed"
    fi
    fwupd_deadline=$((SECONDS + 30))
    while systemctl --quiet is-active fwupd.service; do
        (( SECONDS < fwupd_deadline )) || \
            fail "fwupd remained active after its native safe quit request"
        sleep 0.25
    done
    fwupd_contract='activates on demand and settles through its update-aware quit path'
fi

[[ $(stat -Lc '%u:%g:%a' -- /var/lib/fwupd 2>/dev/null || true) == 0:0:700 ]] || \
    fail "fwupd state directory mode changed across daemon activation"

echo "PASS  $TEST_NAME [$PASS_ID]: unsolicited activation is closed; ordinary GNOME Software is Flatpak-only; the Fedora-RPM one-shot is exact and non-persistent; fwupd stays boot-dormant, $fwupd_contract"
