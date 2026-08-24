#!/bin/bash
# 17-gnome-hardening-structural — M17 regression test
#
# Covers: dconf privacy profile + locks, immediate D-Bus service denials,
# user unit masks via /etc/systemd/user symlinks.
# Would catch: missing dconf profile, wrong dir, GOA mask removed.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/17-gnome-hardening.ks"
POWER_RUNTIME="$PROJECT_ROOT/tests/pre-ship/17-display-power-runtime.sh"
FIRSTRUN_FIXTURE="$PROJECT_ROOT/tests/17-user-firstrun-fixture.sh"
MIC_CONF_SOURCE="$PROJECT_ROOT/scripts/noid-microphone-privacy.conf"
MIC_LUA_SOURCE="$PROJECT_ROOT/scripts/noid-microphone-privacy.lua"
MIC_TOGGLE_SOURCE="$PROJECT_ROOT/scripts/noid-toggle-microphone.sh"
MIC_REGEN="$PROJECT_ROOT/scripts/regen-microphone-policy-embed.sh"
CLEANUP_SOURCE="$PROJECT_ROOT/scripts/noid-gnome-privacy-cleanup.py"
CLEANUP_REGEN="$PROJECT_ROOT/scripts/regen-gnome-privacy-cleanup-embed.sh"
CLEANUP_FIXTURE="$PROJECT_ROOT/tests/17-privacy-cleanup-fixture.sh"
CLEANUP_RUNTIME="$PROJECT_ROOT/tests/pre-ship/17-privacy-cleanup-runtime.sh"
WAYLAND_RUNTIME="$PROJECT_ROOT/tests/pre-ship/17-wayland-default-runtime.sh"
JIT_RUNTIME="$PROJECT_ROOT/tests/pre-ship/17-jit-runtime.sh"
FIRSTRUN_RUNTIME="$PROJECT_ROOT/tests/pre-ship/17-user-firstrun-runtime.sh"
SESSION_RUNTIME="$PROJECT_ROOT/tests/pre-ship/17-session-lifecycle-runtime.sh"
LIVEINST_LIFECYCLE_SOURCE="$PROJECT_ROOT/scripts/noid-liveinst-webui-lifecycle.py"
LIVEINST_LIFECYCLE_REGEN="$PROJECT_ROOT/scripts/regen-liveinst-webui-lifecycle-embed.sh"
LIVEINST_LIFECYCLE_FIXTURE="$PROJECT_ROOT/tests/17-liveinst-webui-lifecycle-fixture.py"
LIVEINST_LIFECYCLE_RUNTIME="$PROJECT_ROOT/tests/pre-ship/17-liveinst-webui-runtime.sh"
LIVEINST_SIZE_SOURCE="$PROJECT_ROOT/overrides/anaconda/live-os-initialization.py"
LIVEINST_SIZE_REGEN="$PROJECT_ROOT/scripts/regen-liveinst-required-space-embed.sh"
LIVEINST_SIZE_FIXTURE="$PROJECT_ROOT/tests/17-liveinst-required-space-fixture.py"
GS_LAUNCHER_SOURCE="$PROJECT_ROOT/scripts/noid-gnome-software-launcher-sync.sh"
GS_LAUNCHER_REGEN="$PROJECT_ROOT/scripts/regen-gnome-software-launcher-embed.sh"
GS_QUIT_SOURCE="$PROJECT_ROOT/scripts/noid-gnome-software-quit.sh"
GS_QUIT_REGEN="$PROJECT_ROOT/scripts/regen-gnome-software-quit-embed.sh"
GS_RPM_SOURCE="$PROJECT_ROOT/scripts/noid-gnome-software-rpm.sh"
GS_RPM_REGEN="$PROJECT_ROOT/scripts/regen-gnome-software-rpm-embed.sh"
GS_BACKEND_SOURCE="$PROJECT_ROOT/scripts/noid-gnome-software-backend-stop.sh"
GS_BACKEND_REGEN="$PROJECT_ROOT/scripts/regen-gnome-software-backend-stop-embed.sh"
LID_ACTION_SOURCE="$PROJECT_ROOT/scripts/noid-toggle-lid-action.sh"
LID_ACTION_REGEN="$PROJECT_ROOT/scripts/regen-lid-action-embed.sh"
LID_ACTION_FIXTURE="$PROJECT_ROOT/tests/17-lid-action-fixture.sh"
SILENT_UPDATE_RUNTIME="$PROJECT_ROOT/tests/pre-ship/24-silent-update-runtime.sh"

test_start "17-gnome-hardening-structural"

extract_nth_heredoc() {
    local source=$1 marker=$2 ordinal=$3 destination=$4
    awk -v marker="$marker" -v wanted="$ordinal" '
        index($0, "<<\047" marker "\047") {
            seen++
            if (seen == wanted) {
                capture = 1
                started = 1
                next
            }
        }
        capture && $0 == marker {
            closed = 1
            exit
        }
        capture { print }
        END { if (!started || !closed) exit 1 }
    ' "$source" > "$destination"
}

instrument_shell_effect_boundary() {
    local helper=$1 anchor=$2 candidate
    candidate="${helper}.instrumented"
    awk -v anchor="$anchor" '
        !inserted && $0 == anchor {
            print "printf \047NOID_EFFECT_REACHED\\n\047"
            print "exit 97"
            inserted = 1
        }
        { print }
        END { if (!inserted) exit 1 }
    ' "$helper" > "$candidate" || return 1
    mv -f -- "$candidate" "$helper"
    chmod 0755 "$helper"
}

instrument_python_effect_boundary() {
    local helper=$1 candidate
    candidate="${helper}.instrumented"
    awk '
        !inserted && $0 == "        if not _is_live_boot():" {
            print "        print(\"NOID_EFFECT_REACHED\")"
            print "        return 97"
            inserted = 1
        }
        { print }
        END { if (!inserted) exit 1 }
    ' "$helper" > "$candidate" || return 1
    mv -f -- "$candidate" "$helper"
    chmod 0755 "$helper"
}

exercise_noarg_gate() {
    local label=$1 helper=$2 diagnostic=$3 case_label rc stdout
    shift 3
    local stderr_file="${helper}.stderr"

    run_hostile_case() {
        case_label=$1
        shift
        rc=0
        stdout=$("$helper" "$@" 2>"$stderr_file") || rc=$?
        assert_eq 2 "$rc" "$label rejects $case_label before its effect boundary"
        assert_eq "" "$stdout" "$label keeps stdout empty for $case_label"
        assert_eq "$diagnostic" "$(cat "$stderr_file")" \
            "$label emits one constant diagnostic for $case_label"
    }

    run_hostile_case "an unknown argument" --unknown
    run_hostile_case "an empty argument" ""
    run_hostile_case "surplus arguments" alpha beta
    run_hostile_case "a newline argument" $'line\nbreak'
    run_hostile_case "an escape-sequence argument" $'\033[31mred'

    rc=0
    stdout=$("$helper" 2>"$stderr_file") || rc=$?
    assert_eq 97 "$rc" "$label preserves its exact no-argument contract"
    assert_eq NOID_EFFECT_REACHED "$stdout" \
        "$label reaches the instrumented effect only without arguments"
    assert_eq "" "$(cat "$stderr_file")" \
        "$label keeps the valid instrumented path diagnostic-free"
}

# GNOME Software must not be D-Bus activatable in the silent-machine default.
# Fedora's vendor descriptor routes to the masked user unit without a
# duplicate admin service; the separate admin desktop entry makes deliberate
# app-grid launch follow Fedora's Exec path.
assert_not_grep 'cat > "$DBUS_ADMIN_DIR/org.gnome.Software.service"' "$KS_FILE" \
    "GNOME Software has no redundant D-Bus service override"
assert_grep_fixed 'rm -f -- "$GNOME_SOFTWARE_ADMIN_SERVICE"' "$KS_FILE" \
    "M17 retires the obsolete duplicate Software service descriptor"
assert_grep_fixed "grep -qxF 'SystemdService=gnome-software.service'" "$KS_FILE" \
    "M17 requires Fedora's native masked-unit activation route"
assert_grep_fixed 'DBUS_ADMIN_BLOCKED_NAMES=(' "$KS_FILE" \
    "one closed array owns the explicit-launch-split admin routes"
assert_grep_fixed 'TRACKER_DBUS_NAMES=(' "$KS_FILE" \
    "one closed array owns the native Tracker activation routes"
assert_grep_fixed 'DBUS_POLICY_BLOCKED_NAMES=(' "$KS_FILE" \
    "one closed array owns the reference-bus send denials"
assert_grep_fixed 'Installed ${#DBUS_ADMIN_BLOCKED_NAMES[@]} static-mask admin routes' \
    "$KS_FILE" "M17 derives its admin deployment count from the closed array"
assert_grep_fixed 'retired ${#TRACKER_DBUS_NAMES[@]} delayed Tracker overrides' \
    "$KS_FILE" "M17 derives its Tracker cleanup count from the closed array"
assert_grep_fixed 'Masked: ${#MASK_UNITS[@]} user units verified against /dev/null in Step 7.3' \
    "$KS_FILE" "M17 derives its masked-unit summary from the closed array"
assert_not_grep 'masked_ok' "$KS_FILE" \
    "M17 does not present the mask-deployment loop as an independent postcondition"
MASK_UNITS_BLOCK=$(mktemp /var/tmp/noid-m17-mask-units.XXXXXXXX)
trap 'rm -f -- "$MASK_UNITS_BLOCK"' EXIT
sed -n '/^MASK_UNITS=($/,/^)/p' "$KS_FILE" > "$MASK_UNITS_BLOCK"
assert_eq 12 \
    "$(awk '!/^[[:space:]]*#/ && !/^[[:space:]]*$/ && !/^MASK_UNITS=\($/ && !/^\)$/ { count++ } END { print count + 0 }' "$MASK_UNITS_BLOCK")" \
    "M17 declares the exact reviewed user-unit mask cardinality"
for mask_unit in \
    evolution-alarm-notify.service \
    evolution-user-prompter.service \
    localsearch-3.service \
    localsearch-control-3.service \
    localsearch-writeback-3.service \
    tinysparql-xdg-portal-3.service \
    '"$DBUS_BLOCK_SYSTEMD_SERVICE"' \
    org.gnome.SettingsDaemon.Sharing.service \
    org.gnome.SettingsDaemon.Smartcard.service \
    org.gnome.SettingsDaemon.UsbProtection.service \
    org.gnome.SettingsDaemon.UsbProtection.target \
    gvfs-goa-volume-monitor.service; do
    assert_grep_fixed "$mask_unit" \
        "$MASK_UNITS_BLOCK" "M17 mask set contains $mask_unit"
done
assert_not_grep 'Installed 7 D-Bus\|OK: 7 exact\|D-Bus: 7 native' "$KS_FILE" \
    "M17 carries no independent hard-coded D-Bus deployment count"
assert_not_grep_extended 'cat > "$DBUS_VENDOR_DIR/|cat > /usr/share/dbus-1/services' "$KS_FILE" \
    "M17 never writes an RPM-owned D-Bus descriptor"
assert_grep_fixed 'retired RPM rewrite artifact present' \
    "$PROJECT_ROOT/kickstart/snippets/99-finalize.ks" \
    "finalizer rejects the obsolete post-transaction mutator"
GIS_SESSION_STOP=
GS_DBUS=$(mktemp /var/tmp/noid-m17-dbus.XXXXXXXX)
GNOME_PRIVACY_HELPER="$GS_DBUS.privacy-contract"
POWER_TMP=
FLOW_TMP=
MIC_TMP=
NOARG_TMP=
cleanup() {
    local temp_dir
    rm -f -- "$GIS_SESSION_STOP" "$GS_DBUS" "$GS_DBUS.launcher" "$GS_DBUS.quit" \
        "$GS_DBUS.rpm" "$GS_DBUS.backend" "$GS_DBUS.power" "$GS_DBUS.mime" \
        "$GS_DBUS.lid" "$GS_DBUS.goa" "$GS_DBUS.agent-power-verify" \
        "$GS_DBUS.privacy" "$GS_DBUS.privacy-locks" \
        "$GNOME_PRIVACY_HELPER" "$GNOME_PRIVACY_HELPER.rpm" \
        "$GNOME_PRIVACY_HELPER.out" "$MASK_UNITS_BLOCK"
    for temp_dir in "$POWER_TMP" "$FLOW_TMP" "$MIC_TMP" "$NOARG_TMP"; do
        [[ -z $temp_dir ]] || rm -rf -- "$temp_dir"
    done
}
trap cleanup EXIT

GIS_SESSION_STOP=$(mktemp /var/tmp/noid-m17-gis-stop.XXXXXXXX)
extract_heredoc "$KS_FILE" GIS_SESSION_STOP_EOF "$GIS_SESSION_STOP" || \
    _fail "GNOME Initial Setup clean-stop drop-in extraction"
assert_eq $'# NoID Privacy — clean retirement of GNOME Initial Setup\'s kiosk session\n[Service]\nKillSignal=SIGHUP\nTimeoutStopSec=5s' \
    "$(cat "$GIS_SESSION_STOP")" \
    "GNOME Initial Setup receives one exact instance-only clean-stop contract"
assert_grep_fixed \
    'GIS_SESSION_STOP_UNIT=gnome-session-manager@gnome-initial-setup.service' \
    "$KS_FILE" "clean-stop unit follows GNOME's literal Initial Setup instance name"
assert_grep_fixed \
    'GIS_SESSION_STOP_DIR=/etc/systemd/user/gnome-session-manager@gnome-initial-setup.service.d' \
    "$KS_FILE" "clean-stop override is scoped only to the literal Initial Setup instance"
assert_grep_fixed \
    'chmod 0755 "$GIS_SESSION_STOP_DIR"' \
    "$KS_FILE" "global user-unit drop-in directory remains traversable"
assert_grep_fixed \
    'matchpathcon -V "$GIS_SESSION_STOP_DIR"' \
    "$KS_FILE" "global user-unit drop-in directory has a canonical SELinux label"
assert_grep_fixed \
    'GIS_VERIFY_RUNTIME=$(mktemp -d /run/noid-m17-systemd-verify.XXXXXXXX)' \
    "$KS_FILE" "user-unit verification receives a private runtime directory"
assert_grep_fixed \
    'XDG_RUNTIME_DIR="$GIS_VERIFY_RUNTIME" systemd-analyze --user' \
    "$KS_FILE" "GNOME Initial Setup is verified by the native user-manager parser"
assert_grep_fixed \
    '--recursive-errors=no --generators=no verify "$GIS_SESSION_STOP_UNIT"' \
    "$KS_FILE" "only the exact instance is fatal and generators stay out of the parallel compose"
assert_grep_fixed \
    '>"$GIS_VERIFY_RUNTIME/verify.log" 2>&1 || gis_verify_rc=$?' \
    "$KS_FILE" "native verification loads the literal Initial Setup instance"
assert_grep_fixed \
    'sed -n '\''1,80p'\'' "$GIS_VERIFY_RUNTIME/verify.log" >&2' \
    "$KS_FILE" "a failed native parser retains bounded compose diagnostics"
assert_grep_fixed \
    'find "$GIS_VERIFY_RUNTIME" -depth -delete' \
    "$KS_FILE" "private parser runtime is retired without following symlinks"
assert_not_grep_extended \
    '^[[:space:]]*systemd-analyze[[:space:]]+verify' \
    "$KS_FILE" "user-unit verification cannot fall back to the system manager"
assert_not_grep_extended \
    '(/etc/systemd/user/gnome-session-manager@\.service\.d|/etc/systemd/user/service\.d).*KillSignal' \
    "$KS_FILE" "normal GNOME sessions receive no kill-signal override"

assert_grep_fixed 'noid-blocked-session-service.service' "$KS_FILE" \
    "common GOA/Identity D-Bus denial unit is declared"
assert_grep_fixed 'ln -sf /dev/null "$SYSTEMD_USER_DIR/$unit"' "$KS_FILE" \
    "declared denial unit is published as a global mask"
GS_LAUNCHER="$GS_DBUS.launcher"
extract_heredoc "$KS_FILE" NOID_GS_LAUNCHER_SYNC_EOF "$GS_LAUNCHER"
assert_cmd_success "GNOME Software launcher source/embed parity" \
    cmp -s "$GS_LAUNCHER_SOURCE" "$GS_LAUNCHER"
assert_cmd_success "GNOME Software launcher helper parses" bash -n "$GS_LAUNCHER"
assert_file_executable "$GS_LAUNCHER_REGEN" \
    "GNOME Software launcher embed generator is executable"
assert_cmd_success "GNOME Software launcher embed generator check passes" \
    "$GS_LAUNCHER_REGEN" --check
GS_QUIT="$GS_DBUS.quit"
extract_heredoc "$KS_FILE" NOID_GS_QUIT_EOF "$GS_QUIT"
assert_cmd_success "GNOME Software complete-quit source/embed parity" \
    cmp -s "$GS_QUIT_SOURCE" "$GS_QUIT"
assert_cmd_success "GNOME Software complete-quit helper parses" bash -n "$GS_QUIT"
assert_file_executable "$GS_QUIT_REGEN" \
    "GNOME Software complete-quit embed generator is executable"
assert_cmd_success "GNOME Software complete-quit generator check passes" \
    "$GS_QUIT_REGEN" --check
assert_grep_fixed '/usr/bin/gnome-software --quit' "$GS_QUIT" \
    "complete-quit helper uses upstream's graceful application shutdown"
assert_grep_fixed '/usr/bin/sudo -n /usr/local/sbin/noid-gnome-software-backend-stop' \
    "$GS_QUIT" "complete-quit helper never opens an authentication dialog"
GS_RPM="$GS_DBUS.rpm"
extract_heredoc "$KS_FILE" NOID_GS_RPM_EOF "$GS_RPM"
assert_cmd_success "GNOME Software Fedora-RPM source/embed parity" \
    cmp -s "$GS_RPM_SOURCE" "$GS_RPM"
assert_cmd_success "GNOME Software Fedora-RPM helper parses" bash -n "$GS_RPM"
assert_file_executable "$GS_RPM_REGEN" \
    "GNOME Software Fedora-RPM embed generator is executable"
assert_cmd_success "GNOME Software Fedora-RPM generator check passes" \
    "$GS_RPM_REGEN" --check
assert_grep_fixed \
    'RPM_PLUGINS=flatpak,appstream,dnf5,icons,hardcoded-blocklist,malcontent,modalias,os-release,provenance,provenance-license,generic-updates' \
    "$GS_RPM" "Fedora-RPM one-shot adds only appstream and dnf5"
assert_grep_fixed 'org.freedesktop.DBus.NameHasOwner org.gnome.Software' \
    "$GS_RPM" "Fedora-RPM one-shot refuses an already-owned application"
assert_grep_fixed 'GNOME_SOFTWARE_PLUGINS_ALLOWLIST+x' "$GS_RPM" \
    "Fedora-RPM one-shot respects an administrator allowlist"
assert_grep_fixed 'GNOME_SOFTWARE_PLUGINS_BLOCKLIST+x' "$GS_RPM" \
    "Fedora-RPM one-shot respects an administrator blocklist"
assert_grep_fixed 'exec "$SOFTWARE"' "$GS_RPM" \
    "Fedora-RPM one-shot returns through the reviewed NoID Privacy wrapper"
assert_not_grep 'fwupd' "$GS_RPM" \
    "Fedora-RPM one-shot cannot enable the firmware plugin"
GS_BACKEND="$GS_DBUS.backend"
extract_heredoc "$KS_FILE" NOID_GS_BACKEND_STOP_EOF "$GS_BACKEND"
assert_cmd_success "GNOME Software backend-stop source/embed parity" \
    cmp -s "$GS_BACKEND_SOURCE" "$GS_BACKEND"
assert_cmd_success "GNOME Software backend-stop helper parses" bash -n "$GS_BACKEND"
assert_file_executable "$GS_BACKEND_REGEN" \
    "GNOME Software backend-stop embed generator is executable"
assert_cmd_success "GNOME Software backend-stop generator check passes" \
    "$GS_BACKEND_REGEN" --check
assert_grep_fixed "expected_tree=\$'/\\n/org\\n/org/rpm\\n/org/rpm/dnf\\n/org/rpm/dnf/v0'" \
    "$GS_BACKEND" "backend stop requires the exact sessionless DNF object tree"
assert_grep_fixed 'deadline=$((SECONDS + 90))' "$GS_BACKEND" \
    "backend stop bounds graceful DNF Session teardown"
assert_grep_fixed '[[ $actual_tree != "$expected_tree" ]] || break' "$GS_BACKEND" \
    "backend stop waits only while a dynamic DNF Session exists"
assert_grep_fixed '/usr/bin/sleep 0.25' "$GS_BACKEND" \
    "backend stop observes DNF Session teardown without a busy loop"
assert_grep_fixed 'DNF5 still has an active session' "$GS_BACKEND" \
    "backend stop remains fail-closed after its bounded wait"
assert_grep_fixed '/usr/bin/systemctl stop "$unit"' "$GS_BACKEND" \
    "backend stop targets only its closed DNF service variable"
LID_ACTION="$GS_DBUS.lid"
extract_heredoc "$KS_FILE" NOID_LID_ACTION_EOF "$LID_ACTION"
assert_cmd_success "lid-action source/embed parity" \
    cmp -s "$LID_ACTION_SOURCE" "$LID_ACTION"
assert_cmd_success "lid-action helper parses" bash -n "$LID_ACTION"
assert_file_executable "$LID_ACTION_REGEN" \
    "lid-action embed generator is executable"
assert_cmd_success "lid-action embed generator check passes" \
    "$LID_ACTION_REGEN" --check
assert_file_executable "$LID_ACTION_FIXTURE" \
    "lid-action behavioral fixture is executable"
assert_cmd_success "lid-action desktop/SW_LID/rollback fixture passes" \
    "$LID_ACTION_FIXTURE" "$LID_ACTION_SOURCE"
assert_grep_fixed 'INPUT_ROOT=/sys/class/input' "$LID_ACTION" \
    "lid hardware detection uses the kernel input subsystem"
assert_grep_fixed 'device/capabilities/sw' "$LID_ACTION" \
    "lid hardware detection reads the SW_LID capability bitmap"
assert_not_grep_extended 'chassis_type|/sys/class/power_supply|BAT\\*' \
    "$LID_ACTION" "lid hardware is never inferred from DMI or batteries"
assert_grep_fixed \
    'POLICY_FILE=$POLICY_DIR/99-noid-user-lid-action.conf' "$LID_ACTION" \
    "explicit lid choice has one independent higher-priority drop-in"
assert_grep_fixed '"HandleLidSwitch=$action"' "$LID_ACTION" \
    "explicit choice covers the normal lid-close path"
assert_grep_fixed '"HandleLidSwitchExternalPower=$action"' "$LID_ACTION" \
    "explicit choice covers the external-power lid-close path"
assert_not_grep_extended 'HandleLidSwitchDocked=.*action' "$LID_ACTION" \
    "explicit choice never mutates docked/clamshell ownership"
assert_grep_fixed 'manager_value HandleLidSwitchDocked' "$LID_ACTION" \
    "status still reports effective docked/clamshell behavior"
assert_grep_fixed '"$SYSTEMCTL" reload systemd-logind.service' "$LID_ACTION" \
    "changes use logind's native reload path"
assert_grep_fixed \
    '[[ $(stat -Lc '\''%U:%G:%a'\'' "$POLICY_DIR" 2>/dev/null || true)' \
    "$LID_ACTION" "directory trust is independent of filesystem link-count semantics"
assert_not_grep_extended \
    'stat -Lc '\''%U:%G:%a:%h'\'' .*POLICY_DIR' "$LID_ACTION" \
    "directory trust does not require a Btrfs-specific link count"
assert_not_grep_extended 'action == "\$prior"' "$LID_ACTION" \
    "same-value requests still reload and verify effective logind state"
assert_grep_fixed 'prior policy restored' "$LID_ACTION" \
    "failed apply paths explicitly report transactional restoration"
assert_grep_fixed \
    '/usr/bin/sudo -n /usr/local/bin/noid-toggle-lid-action' "$LID_ACTION" \
    "NoID Privacy Tools invocation can never open a password prompt"
for lid_action in suspend lock reset; do
    assert_grep_fixed \
        "%wheel ALL=(root) NOPASSWD: /usr/local/bin/noid-toggle-lid-action --apply-root $lid_action" \
        "$KS_FILE" "sudoers grants only the exact internal $lid_action transaction"
done
assert_grep_fixed 'LID_ACTION_SUDOERS="/etc/sudoers.d/49-noid-lid-action"' \
    "$KS_FILE" "lid privilege bridge has one fixed administrator path"
assert_grep_fixed 'visudo -cf "$LID_ACTION_SUDOERS"' "$KS_FILE" \
    "lid privilege bridge is parser-validated before and after publication"
assert_grep_fixed "grep -cEv '^[[:space:]]*(#|$)'" "$KS_FILE" \
    "lid sudoers gate counts active commands instead of comments"
assert_not_grep_extended 'wc -l.*LID_ACTION_SUDOERS' "$KS_FILE" \
    "lid sudoers gate has no fragile physical-line contract"
assert_not_grep_extended \
    'noid-toggle-lid-action.*NOPASSWD:[[:space:]]+ALL|NOPASSWD:[[:space:]]+ALL.*noid-toggle-lid-action' \
    "$KS_FILE" "lid privilege bridge never grants an argument wildcard"
assert_grep_fixed \
    '%wheel ALL=(root) NOPASSWD: /usr/local/sbin/noid-gnome-software-backend-stop ""' \
    "$KS_FILE" "complete-quit sudoers allows exactly the argumentless root helper"
assert_grep_fixed "grep -cEv '^[[:space:]]*(#|$)'" "$KS_FILE" \
    "complete-quit sudoers gate counts active commands instead of comments"
assert_not_grep_extended 'wc -l.*GNOME_SOFTWARE_QUIT_SUDOERS' "$KS_FILE" \
    "complete-quit sudoers gate has no fragile physical-line contract"
assert_grep_fixed 'export LC_ALL=C' "$GS_LAUNCHER" \
    "launcher generator parses vendor metadata in one closed locale"
assert_grep_fixed 'export PATH=/usr/sbin:/usr/bin' "$GS_LAUNCHER" \
    "launcher generator resolves administrative tools from a closed path"
assert_grep_fixed '[[ $EUID -eq 0 ]] || fail "must run as root"' "$GS_LAUNCHER" \
    "launcher generator rejects an unprivileged caller before mutation"
assert_grep_fixed 'rpm -q --dump "$EXPECTED_PACKAGE"' "$GS_LAUNCHER" \
    "launcher generator authenticates the current Fedora RPM payload"
assert_grep_fixed '--set-key=DBusActivatable' "$GS_LAUNCHER" \
    "launcher generator forces the explicit direct-execution path"
assert_grep_fixed '--set-value=false' "$GS_LAUNCHER"
assert_grep_fixed \
    "admin_actions=\"\$vendor_actions;NoIDFedoraRPM;NoIDQuit;\"" \
    "$GS_LAUNCHER" \
    "launcher generator preserves any future vendor action list"
assert_grep_fixed '--set-key=Actions' "$GS_LAUNCHER" \
    "launcher generator publishes the standard desktop-action reference"
assert_grep_fixed 'Exec=/usr/local/bin/noid-gnome-software-quit' "$GS_LAUNCHER" \
    "launcher generator uses the graceful idle-release path"
assert_grep_fixed 'Exec=/usr/local/bin/noid-gnome-software-rpm' "$GS_LAUNCHER" \
    "launcher generator exposes the Fedora-RPM one-shot"
assert_grep_fixed 'Name[de]=GNOME Software mit Fedora-RPMs öffnen' \
    "$GS_LAUNCHER" "Fedora-RPM desktop action has the reviewed German label"
assert_grep_fixed 'mv -fT -- "$candidate" "$ADMIN_FILE"' "$GS_LAUNCHER" \
    "launcher generator publishes atomically"
assert_grep_fixed 'matchpathcon -V "$ADMIN_FILE"' "$GS_LAUNCHER" \
    "launcher generator makes the SELinux label a hard postcondition"
assert_grep_fixed 'post_transaction:gnome-software:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-gnome-software-launcher-sync\ >/dev/null' \
    "$KS_FILE" "gnome-software updates regenerate only the admin launcher"
assert_grep_fixed 'DETAIL: $1' "$KS_FILE" \
    "compose verifier names the exact failing GNOME Software postcondition"
assert_grep_fixed 'admin desktop differs from vendor-derived candidate' \
    "$KS_FILE" "compose verifier diagnoses the final launcher byte comparison"
assert_not_grep_extended 'cat > "$DBUS_VENDOR_DIR/|cat > /usr/share/dbus-1/services|sed -i.*org\.gnome\.Software\.service' \
    "$KS_FILE" "no package transaction or compose step mutates the vendor D-Bus payload"
assert_not_grep_extended 'noid-dbus-suppress-reassert <<|post_transaction:.*noid-dbus-suppress' \
    "$KS_FILE" "retired vendor-payload reassert machinery stays absent"
assert_file_executable "$SILENT_UPDATE_RUNTIME" \
    "three-pass GNOME Software Silent Machine gate is executable"
assert_cmd_success "GNOME Software Silent Machine gate parses" \
    bash -n "$SILENT_UPDATE_RUNTIME"
assert_grep_fixed 'GioUnix.DesktopAppInfo.new("org.gnome.Software.desktop")' \
    "$SILENT_UPDATE_RUNTIME" "candidate gate proves the effective XDG launcher winner"
assert_grep_fixed 'actions != ["NoIDFedoraRPM", "NoIDQuit"]' \
    "$SILENT_UPDATE_RUNTIME" \
    "candidate gate resolves both NoID Privacy desktop actions through GIO"
assert_grep_fixed 'org.freedesktop.Application.Activate' "$SILENT_UPDATE_RUNTIME" \
    "candidate gate performs a real negative bus activation"
assert_grep_fixed '[[ ! -e $admin_service && ! -L $admin_service ]]' \
    "$SILENT_UPDATE_RUNTIME" "candidate gate rejects the duplicate Software service"
assert_grep_fixed "SystemdService=gnome-software.service" \
    "$SILENT_UPDATE_RUNTIME" "candidate gate requires Fedora's native Software route"
assert_grep_fixed 'policy then returned `AccessDenied`' "$KS_FILE" \
    "installed guidance records why GOA/Identity admin routes remain"
assert_grep_fixed 'those two diagnostics are the known cost' "$KS_FILE" \
    "installed guidance labels the bounded broker diagnostic honestly"

assert_file_exists "$KS_FILE"
assert_not_grep 'dconf update.*[|][|][[:space:]]*true' "$KS_FILE" \
    "dconf compilation failures are not swallowed"
assert_grep_fixed 'if ! dconf update; then' "$KS_FILE" \
    "dconf diagnostics flow through the Module 17 kickstart log"
assert_not_grep '/tmp/dconf-update.log' "$KS_FILE" \
    "dconf compilation leaves no fixed-path build artifact in the target root"
assert_grep_fixed 'distro missing or empty after successful dconf update' "$KS_FILE" \
    "compiled distro database has a non-empty postcondition"
assert_grep_fixed 'Required pinned Just-Perfection payload unavailable — aborting build' \
    "$KS_FILE" "missing pinned extension aborts instead of shipping a broken configured default"
assert_grep_fixed 'FAIL: required Just-Perfection extension metadata missing' \
    "$KS_FILE" "M17 verifies the required extension after extraction"
assert_grep_fixed 'JP_SIZE="230176"' "$KS_FILE" \
    "Just-Perfection transport size is pinned to the reviewed payload"
assert_grep_fixed \
    'JP_SHA256="4aef633af6345755d8982f14821d1c276b539faa10c2eddc596a27359ebe3281"' \
    "$KS_FILE" "Just-Perfection digest is pinned to the reviewed payload"
assert_grep_fixed 'JP_ENTRY_COUNT="74"' "$KS_FILE" \
    "Just-Perfection archive entry count is pinned"
assert_grep_fixed 'JP_EXPANDED_SIZE="864052"' "$KS_FILE" \
    "Just-Perfection expanded-byte budget is pinned"
assert_grep_fixed "--proto '=https' --tlsv1.2 --max-redirs 0" "$KS_FILE" \
    "extension seed fetch has an explicit HTTPS/TLS floor"
assert_grep_fixed "--max-redirs 0 --connect-timeout 15" "$KS_FILE" \
    "extension fetch cannot leave the reviewed EGO origin through redirects"
assert_grep_fixed '--max-filesize "$JP_SIZE"' "$KS_FILE" \
    "extension fetch has the reviewed transport-size ceiling"
assert_grep_fixed 'download_sha256=$(sha256sum "$JP_TMPZIP"' "$KS_FILE" \
    "downloaded Just-Perfection bytes are hashed before extraction"
assert_grep_fixed 'if [ "$download_sha256" != "$JP_SHA256" ]; then' "$KS_FILE" \
    "downloaded Just-Perfection hash is compared with the pinned digest"
assert_grep_fixed \
    '&& [ "$(sha256sum "$JP_CACHE_ZIP" | awk '\''{print $1}'\'')" = "$JP_SHA256" ]; then' \
    "$KS_FILE" "existing Just-Perfection cache bytes are digest-verified"
assert_grep_fixed \
    '|| [ "$(sha256sum "$JP_CACHE_ZIP" | awk '\''{print $1}'\'')" != "$JP_SHA256" ]' \
    "$KS_FILE" "newly published Just-Perfection cache bytes are digest-verified"
assert_grep_fixed 'if bundle.testzip() is not None:' "$KS_FILE" \
    "extension archive CRC is checked before extraction"
assert_grep_fixed 'if metadata.get("uuid") != expected_uuid:' "$KS_FILE" \
    "extension metadata UUID is closed to the reviewed identity"
assert_grep_fixed 'if str(metadata.get("version", "")) != expected_version:' \
    "$KS_FILE" "extension metadata version is closed to v36"
assert_grep_fixed '"50" not in {str(value) for value in shells}' "$KS_FILE" \
    "extension metadata must explicitly support GNOME 50"
assert_grep_fixed 'glib-compile-schemas --strict "$JP_CANDIDATE/schemas"' \
    "$KS_FILE" "extension candidate schemas compile strictly before publication"
assert_grep_fixed 'RENAME_EXCHANGE' "$KS_FILE" \
    "extension reruns exchange complete sibling trees atomically"
assert_grep_fixed 'mv -fT -- "$JP_CACHE_CANDIDATE" "$JP_CACHE_ZIP"' \
    "$KS_FILE" "reviewed extension cache publication is atomic"
assert_grep_fixed 'published Just-Perfection cache postcondition differs' \
    "$KS_FILE" "extension cache bytes, metadata and label have a hard postcondition"
assert_grep_fixed 'matchpathcon -V "$JP_EXT_DIR/metadata.json"' "$KS_FILE" \
    "published extension metadata has a verified SELinux label"
assert_not_grep '/tmp/just-perfection-v[$][{]JP_VERSION[}][.]zip' "$KS_FILE" \
    "extension archive no longer uses a predictable shared temporary path"
assert_not_grep_extended '^[[:space:]]*rm -rf "?[$]JP_EXT_DIR"?' "$KS_FILE" \
    "working extension is never deleted before its replacement is complete"
assert_grep_fixed 'mkdir -p /usr/share/doc/noid-privacy' "$KS_FILE" \
    "M17 owns its installed-document directory precondition"
assert_cmd_success "bash -n $KS_FILE" bash -n "$KS_FILE"

# Profile + db + locks in distro.d (Module 08 shared profile)
assert_grep_fixed "/etc/dconf/profile/user" "$KS_FILE"
assert_grep_fixed "/etc/dconf/db/distro.d/10-noid-gnome-privacy" "$KS_FILE"
assert_grep_fixed "/etc/dconf/db/distro.d/locks/10-noid-gnome-privacy" "$KS_FILE"
assert_grep_fixed "/etc/dconf/db/distro.d/12-noid-agent-workflow-power" "$KS_FILE" \
    "agent workflow power policy uses a dedicated system-default keyfile"
POWER_DCONF="$GS_DBUS.power"
extract_heredoc "$KS_FILE" DCONF_AGENT_POWER_EOF "$POWER_DCONF"
assert_grep_extended '^\[org/gnome/settings-daemon/plugins/power\]$' \
    "$POWER_DCONF" "agent workflow keyfile has the exact GNOME power schema"
assert_grep_extended '^idle-dim=false$' "$POWER_DCONF" \
    "extracted agent workflow keyfile disables early idle dimming"
assert_grep_extended "^sleep-inactive-ac-type='nothing'$" "$POWER_DCONF" \
    "extracted agent workflow keyfile disables AC idle suspend"
assert_grep_extended "^sleep-inactive-battery-type='nothing'$" "$POWER_DCONF" \
    "extracted agent workflow keyfile disables battery idle suspend"
assert_not_grep_extended '^(sleep-inactive-(ac|battery)-timeout|idle-delay)=' \
    "$POWER_DCONF" "agent workflow keyfile does not own blank/suspend delays"
assert_grep_fixed 'agent_power_key_count=$(grep -cE' "$KS_FILE" \
    "M17 verifies the agent workflow key identity at install time"
assert_grep_fixed 'agent_power_assignment_count=$(grep -cE' "$KS_FILE" \
    "M17 rejects surplus assignments in the agent workflow keyfile"
AGENT_POWER_VERIFY="$GS_DBUS.agent-power-verify"
sed -n '/# 7.1b: Agent workflow power defaults/,/# 7.1c:/p' \
    "$KS_FILE" > "$AGENT_POWER_VERIFY"
assert_grep_fixed "root:root:644:1" "$AGENT_POWER_VERIFY" \
    "M17 verifies exact agent workflow keyfile ownership and metadata"
assert_grep_fixed "user-adjustable agent workflow power defaults invalid" "$KS_FILE" \
    "M17 fails the module when the agent power contract drifts"

# The security-critical values and their lock set are asserted on the actual
# extracted payloads, not merely on their heredoc marker names.
PRIVACY_DCONF="$GS_DBUS.privacy"
PRIVACY_LOCKS="$GS_DBUS.privacy-locks"
extract_heredoc "$KS_FILE" DCONF_PRIVACY_EOF "$PRIVACY_DCONF"
extract_heredoc "$KS_FILE" DCONF_LOCKS_EOF "$PRIVACY_LOCKS"
for privacy_assignment in \
    autorun-never=true \
    disable-all=true \
    show-in-lock-screen=false \
    allow-extension-installation=false \
    disable-user-extensions=false \
    donation-reminder-enabled=false; do
    assert_grep_extended "^${privacy_assignment}$" "$PRIVACY_DCONF" \
        "GNOME privacy payload contains $privacy_assignment"
done
assert_eq 2 "$(grep -Fxc 'enable=false' "$PRIVACY_DCONF")" \
    "GNOME privacy payload disables both remote-desktop protocols"
assert_eq 8 "$(grep -c '^/' "$PRIVACY_LOCKS")" \
    "GNOME privacy lock payload has the exact reviewed cardinality"
assert_grep_fixed 'expected_sections=17' "$KS_FILE" \
    "compose independently gates the reviewed dconf section count"
assert_grep_extended '^\[org/gtk/settings/file-chooser\]$' \
    "$PRIVACY_DCONF" "Nautilus GTK3 migration source is configured"
assert_grep_extended '^\[org/gtk/gtk4/settings/file-chooser\]$' \
    "$PRIVACY_DCONF" "Nautilus GTK4 visibility schema is configured"
assert_eq 2 "$(grep -Fxc 'show-hidden=true' "$PRIVACY_DCONF")" \
    "both Nautilus migration and runtime visibility defaults are true"
assert_not_grep_extended '^show-hidden-files=' "$PRIVACY_DCONF" \
    "deprecated ignored Nautilus visibility key is absent"
assert_grep_extended '^\[org/gnome/nautilus/preferences\]$' \
    "$PRIVACY_DCONF" "Nautilus defaults use the maintained preferences schema"
assert_grep_extended "^default-sort-order='name'$" "$PRIVACY_DCONF" \
    "fresh accounts sort Nautilus views by name"
assert_grep_extended '^default-sort-in-reverse-order=false$' \
    "$PRIVACY_DCONF" "fresh accounts use ascending A-Z ordering"
for unlocked_file_manager_key in \
    /org/gtk/settings/file-chooser/show-hidden \
    /org/gtk/gtk4/settings/file-chooser/show-hidden \
    /org/gnome/nautilus/preferences/default-sort-order \
    /org/gnome/nautilus/preferences/default-sort-in-reverse-order; do
    assert_not_grep_extended "^${unlocked_file_manager_key}$" "$PRIVACY_LOCKS" \
        "file-manager preference stays user-overridable: $unlocked_file_manager_key"
done
assert_grep_fixed 'expected_locks=8' "$KS_FILE" \
    "compose independently gates the reviewed security-lock count"
for locked_key in \
    /org/gnome/desktop/media-handling/autorun-never \
    /org/gnome/desktop/thumbnailers/disable-all \
    /org/gnome/desktop/remote-desktop/rdp/enable \
    /org/gnome/desktop/remote-desktop/vnc/enable \
    /org/gnome/desktop/notifications/show-in-lock-screen \
    /org/gnome/shell/allow-extension-installation \
    /org/gnome/shell/disable-user-extensions \
    /org/gnome/settings-daemon/plugins/housekeeping/donation-reminder-enabled; do
    assert_grep_extended "^${locked_key}$" "$PRIVACY_LOCKS" \
        "GNOME privacy lock set contains $locked_key"
done
assert_grep_fixed 'idle-delay=uint32 300' "$KS_FILE" \
    "GNOME owns the user-adjustable five-minute graphical idle default"
assert_grep_fixed 'idle-dim=false' "$KS_FILE" \
    "agent workflow default avoids an early idle brightness transition"
assert_grep_fixed "sleep-inactive-ac-type='nothing'" "$KS_FILE" \
    "agent workflow default keeps AC jobs running while idle"
assert_grep_fixed "sleep-inactive-battery-type='nothing'" "$KS_FILE" \
    "agent workflow default keeps battery jobs running while idle"
assert_grep_fixed 'lock-delay=uint32 0' "$KS_FILE" \
    "GNOME lock delay default is explicit"
assert_not_grep '^[[:space:]]*idle-activation-enabled=' "$KS_FILE" \
    "deprecated ignored screensaver activation key is not written"
assert_not_grep_extended '^[[:space:]]*sleep-inactive-(ac|battery)-timeout=' \
    "$KS_FILE" "agent workflow policy does not replace GNOME's visible delays"
assert_not_grep_extended 'locks/.*(idle-dim|sleep-inactive)' "$KS_FILE" \
    "agent workflow power defaults remain user-overridable"
assert_grep_fixed 'lock-delay=0` is not a literal zero-second lock' "$KS_FILE" \
    "installed doc states GNOME's minimum idle-fade boundary"
assert_grep_fixed 'no persistent disk-backed swap' "$KS_FILE" \
    "installed doc states the default hibernation boundary"
assert_file_executable "$POWER_RUNTIME" \
    "three-pass GNOME display/power runtime gate is executable"
assert_cmd_success "display/power runtime gate parses" bash -n "$POWER_RUNTIME"
for pass_id in live fresh-install reboot; do
    assert_grep_fixed "$pass_id" "$POWER_RUNTIME" \
        "display/power gate recognizes $pass_id pass"
done
assert_grep_fixed 'CanSuspendThenHibernate' "$POWER_RUNTIME" \
    "runtime gate verifies the persistent-resume boundary"
assert_grep_fixed 'handle-power-key:handle-suspend-key:handle-hibernate-key' \
    "$POWER_RUNTIME" "runtime gate observes GNOME hardware-key ownership"
assert_grep_fixed 'upower_property LidIsPresent' "$POWER_RUNTIME" \
    "runtime gate obtains the lid capability from UPower"
assert_grep_fixed 'has_active_assignment()' "$POWER_RUNTIME" \
    "runtime gate distinguishes absent overrides from unreadable configuration"
assert_grep_fixed '[[ $rc -eq 1 ]] || fail' "$POWER_RUNTIME" \
    "runtime gate cannot report grep/configuration errors as policy absence"
POWER_TMP=$(mktemp -d /var/tmp/noid-m17-power.XXXXXXXX)
sed -n '/^has_active_assignment() {$/,/^}$/p' "$POWER_RUNTIME" \
    > "$POWER_TMP/has-active-assignment.sh"
printf '%s\n' '[Login]' 'RemoveIPC=yes' \
    > "$POWER_TMP/power-config-no-override.conf"
printf '%s\n' '[Login]' 'HandleLidSwitch=lock' \
    > "$POWER_TMP/power-config-override.conf"
ln -s "$POWER_TMP/power-config-missing.conf" \
    "$POWER_TMP/power-config-dangling.conf"
set +e
bash -c '
        fail() { exit 77; }
        . "$1"
        has_active_assignment "^[[:space:]]*HandleLidSwitch=" "$2"
    ' _ "$POWER_TMP/has-active-assignment.sh" \
        "$POWER_TMP/power-config-no-override.conf" >/dev/null 2>&1
power_no_override_rc=$?
set -e
assert_eq 1 "$power_no_override_rc" \
    "power parser reports policy absence distinctly from configuration errors"
assert_cmd_success "power parser detects an active override" \
    bash -c '
        fail() { exit 77; }
        . "$1"
        has_active_assignment "^[[:space:]]*HandleLidSwitch=" "$2"
    ' _ "$POWER_TMP/has-active-assignment.sh" \
        "$POWER_TMP/power-config-override.conf"
set +e
bash -c '
    fail() { exit 77; }
    . "$1"
    has_active_assignment "^[[:space:]]*HandleLidSwitch=" "$2"
' _ "$POWER_TMP/has-active-assignment.sh" \
    "$POWER_TMP/power-config-dangling.conf" >/dev/null 2>&1
power_config_error_rc=$?
set -e
assert_eq 77 "$power_config_error_rc" \
    "power parser fails distinctly when a configuration path is unreadable"
assert_grep_fixed "'b true'|'b false'" "$POWER_RUNTIME" \
    "runtime gate accepts only an unambiguous UPower lid capability"
assert_grep_fixed '/sys/class/input/event*/device/capabilities/sw' "$POWER_RUNTIME" \
    "runtime gate independently derives the real kernel SW_LID state"
assert_grep_fixed 'lid_status=$(noid-toggle-lid-action status)' "$POWER_RUNTIME" \
    "runtime gate executes the installed helper's read-only status"
assert_grep_fixed 'Hardware: PRESENT (kernel SW_LID)' "$POWER_RUNTIME" \
    "runtime gate verifies laptop/convertible classification"
assert_grep_fixed 'Hardware: ABSENT (desktop or no kernel SW_LID device)' \
    "$POWER_RUNTIME" "runtime gate verifies desktop classification"
assert_not_grep "grep -q 'handle-lid-switch'" "$POWER_RUNTIME" \
    "runtime gate does not mistake GNOME's transient lid inhibitor for steady state"

# Comments and installed guidance must describe the exact GNOME 50 contracts;
# these assertions prevent previously disproved release claims from returning.
assert_grep_fixed 'blanks the monitors immediately' "$KS_FILE" \
    "screen lifecycle documents the immediate post-fade blank"
assert_grep_fixed '30-second active-shield idle watch is a recovery path' \
    "$KS_FILE" "screen lifecycle does not invent another 30-second delay"
assert_not_grep 'powers monitors off 30 seconds after' "$KS_FILE" \
    "retired post-shield delay claim is absent"
assert_grep_fixed 'retains scale-monitor-framebuffer and xwayland-native-scaling as' \
    "$KS_FILE" "Mutter legacy schema nicks are distinguished from runtime support"
assert_grep_fixed 'runtime parser no longer recognizes or' "$KS_FILE" \
    "Mutter policy follows the GNOME 50 parser"
assert_grep_fixed 'experimental-features=@as []' "$KS_FILE" \
    "Mutter experimental features are explicitly disabled"
assert_not_grep "experimental-features=['autoclose-xwayland']" "$KS_FILE" \
    "autoclose-xwayland is not selected"
assert_not_grep 'removed scale-monitor-framebuffer' "$KS_FILE" \
    "Mutter schema is not falsely described"
assert_grep_fixed 'allowing a reminder once per 365 days' "$KS_FILE" \
    "donation reminder cadence matches GNOME Settings Daemon 50.1"
assert_not_grep 'bi-annual' "$KS_FILE" \
    "misleading donation cadence is absent"
assert_grep_fixed "audio stack's amplified maximum" "$KS_FILE" \
    "volume amplification ceiling is correctly stack-dependent"
assert_grep_fixed 'may clip' "$KS_FILE" \
    "software amplification trade-off is explicit"
assert_not_grep_extended 'up to 150%|turning RED' "$KS_FILE" \
    "unsupported volume UI specifics are absent"
assert_grep_fixed 'Click, Hum, String or Swing' "$KS_FILE" \
    "GNOME 50 alert choices use the current names"
assert_grep_fixed 'creates the per-user __custom theme' "$KS_FILE" \
    "custom sound theme is correctly scoped to a user choice"
assert_not_grep_extended 'Bark/Drip/Glass/Sonar|leaves theme-name='\''__custom'\''' \
    "$KS_FILE" "retired sound-theme claims are absent"

# Session-bus admin overrides follow the standard XDG service precedence;
# package-owned /usr/share descriptors stay exact. Only the separate admin
# desktop copy has a package-scoped synchronization hook.
assert_grep_fixed 'DBUS_ADMIN_DIR="/usr/local/share/dbus-1/services"' "$KS_FILE"
assert_grep_fixed 'DBUS_VENDOR_DIR="/usr/share/dbus-1/services"' "$KS_FILE"
assert_grep_fixed 'DBUS_BLOCK_POLICY="$DBUS_POLICY_DIR/20-noid-blocked-services.conf"' \
    "$KS_FILE" "M17 owns one reference-bus policy file"
assert_grep_fixed 'org.gnome.OnlineAccounts.service' "$KS_FILE"
assert_grep_fixed 'org.gnome.Identity.service' "$KS_FILE"
assert_grep_fixed 'Exec=/bin/false' "$KS_FILE"
assert_grep_fixed '<policy context="mandatory">' "$KS_FILE" \
    "reference bus applies the send denials without caller exceptions"
GOA_CONF="$GS_DBUS.goa"
extract_heredoc "$KS_FILE" GOA_CONF_EOF "$GOA_CONF"
assert_eq 1 "$(grep -Fxc '[providers]' "$GOA_CONF")" \
    "GOA configuration has one provider policy group"
assert_eq 1 "$(grep -Ec '^(enable|disable)=' "$GOA_CONF")" \
    "GOA configuration has one unambiguous provider selector"
assert_grep_fixed 'enable=__noid_none__' "$GOA_CONF" \
    "GOA uses a deliberately unmatched empty-subset allowlist"
assert_not_grep_extended '^disable=all$' "$GOA_CONF" \
    "GOA does not use the disproved ordinary-name disable value"
assert_grep_fixed 'GOA 3.58.1 does not treat disable=all specially' "$KS_FILE" \
    "GOA deny-all rationale records the exact upstream behavior"
assert_grep_fixed "grep -qxF 'enable=__noid_none__' /etc/goa.conf" "$KS_FILE" \
    "M17 verifies the provider allowlist after publication"
assert_grep_fixed "stat -c '%U:%G:%a' /etc/goa.conf" "$KS_FILE" \
    "M17 verifies GOA administrator-file ownership and mode"
assert_grep_fixed 'rm -f -- "$DBUS_ADMIN_DIR/${service_name}.service"' "$KS_FILE" \
    "legacy delayed Tracker overrides are retired exactly"
assert_grep_fixed 'matchpathcon -V "$DBUS_BLOCK_POLICY"' "$KS_FILE" \
    "M17 verifies the session-bus policy SELinux label"
assert_grep_fixed 'rpm -q --dump "$vendor_package"' "$KS_FILE" \
    "M17 binds every vendor descriptor to its RPM digest record"
assert_grep_fixed '${#DBUS_ADMIN_BLOCKED_NAMES[@]} static-mask admin routes; ${#TRACKER_DBUS_NAMES[@]} immediate native Tracker routes; ${#DBUS_VENDOR_SPECS[@]} RPM vendor descriptors byte-pristine' \
    "$KS_FILE" "M17 verifies every D-Bus route rather than a subset"
assert_grep_fixed 'if [ "$m17_dbus_fail" -eq 0 ]; then' "$KS_FILE" \
    "M17 emits its complete-set OK line only after a clean aggregate result"
assert_grep_fixed 'one or more D-Bus denial/vendor integrity contracts failed' \
    "$KS_FILE" "M17 exposes aggregate D-Bus integrity failure"
assert_not_grep 'verified in an installed F44 desktop session' "$KS_FILE" \
    "source does not pre-claim the pending candidate manual-launch result"
assert_not_grep_extended 'post_transaction:gnome-software:.*(org\.gnome\.Software\.service|noid-dbus-suppress)' \
    "$KS_FILE" "gnome-software package action cannot rewrite D-Bus vendor payloads"

# The root/DNF privacy-contract helper must resolve every non-absolute tool
# from a closed path and observe failure of the RPM payload enumeration itself.
extract_heredoc "$KS_FILE" NOID_GNOME_PRIVACY_CONTRACT_EOF \
    "$GNOME_PRIVACY_HELPER" || _fail "GNOME privacy-contract helper extraction"
assert_grep_fixed 'PATH=/usr/sbin:/usr/bin' "$GNOME_PRIVACY_HELPER" \
    "GNOME privacy-contract helper uses a closed administrative path"
assert_grep_fixed 'shell_payload_list=$(/usr/bin/rpm -ql gnome-shell) ||' \
    "$GNOME_PRIVACY_HELPER" \
    "GNOME privacy-contract helper captures the RPM enumeration status"
assert_grep_fixed 'done <<< "$shell_payload_list"' "$GNOME_PRIVACY_HELPER" \
    "GNOME privacy-contract helper parses only the checked RPM listing"
assert_not_grep 'done < <(/usr/bin/rpm -ql gnome-shell)' \
    "$GNOME_PRIVACY_HELPER" \
    "GNOME privacy-contract helper has no unchecked process substitution"
sed -i "s#/usr/bin/rpm#$GNOME_PRIVACY_HELPER.rpm#g" "$GNOME_PRIVACY_HELPER"
assert_grep_fixed "$GNOME_PRIVACY_HELPER.rpm -ql gnome-shell" \
    "$GNOME_PRIVACY_HELPER" "privacy-contract RPM fixture rewrite applied"
cat > "$GNOME_PRIVACY_HELPER.rpm" <<'GNOME_PRIVACY_RPM_FIXTURE_EOF'
#!/bin/bash
case "$*" in
    '-q gnome-shell') exit 0 ;;
    '-ql gnome-shell') exit 42 ;;
    *) exit 1 ;;
esac
GNOME_PRIVACY_RPM_FIXTURE_EOF
chmod 0755 "$GNOME_PRIVACY_HELPER" "$GNOME_PRIVACY_HELPER.rpm"
if "$GNOME_PRIVACY_HELPER" >"$GNOME_PRIVACY_HELPER.out" 2>&1; then
    _fail "failed GNOME Shell RPM enumeration is fail-visible"
else
    _pass "failed GNOME Shell RPM enumeration is fail-visible"
fi
assert_grep_fixed 'cannot enumerate gnome-shell payload' \
    "$GNOME_PRIVACY_HELPER.out" \
    "RPM database failure retains its specific diagnostic"
assert_grep_fixed 'M26 excludes gnome-tour in the image package transaction' \
    "$KS_FILE" "M17 documents gnome-tour as a defense-in-depth reinstall guard"
assert_not_grep_extended \
    'gnome-tour.*(NOT removed|do NOT remove)|manual launch.*apps grid' \
    "$KS_FILE" "M17 carries no retired claim that gnome-tour ships"
assert_grep_fixed '-gnome-tour' "$PROJECT_ROOT/kickstart/snippets/26-package-set.ks" \
    "M26 remains the owner of gnome-tour package exclusion"
assert_not_grep 'unzip: M17' \
    "$PROJECT_ROOT/kickstart/snippets/26-package-set.ks" \
    "M26 does not attribute its retained unzip dependency to M17"
assert_grep_fixed 'if /usr/local/sbin/noid-restore-gnome-flow; then' \
    "$KS_FILE" "compose preserves GNOME-flow helper diagnostics in the module log"
assert_not_grep 'noid-restore-gnome-flow >/dev/null 2>&1' "$KS_FILE" \
    "compose does not discard GNOME-flow helper failure details"

# Routine gnome-initial-setup, geoclue2 and evolution-data-server updates
# replace three package-owned flow files. Exercise the exact embedded
# single-writer against a stock-payload stomp, including multi-file recovery
# and idempotence; structural action greps alone cannot prove this behavior.
FLOW_TMP=$(mktemp -d /var/tmp/noid-m17-flow.XXXXXXXX)
FLOW_HELPER="$FLOW_TMP/noid-restore-gnome-flow"
FLOW_ROOT="$FLOW_TMP/root"
FLOW_MOCKBIN="$FLOW_TMP/mockbin"
extract_heredoc "$KS_FILE" GNOME_FLOW_EOF "$FLOW_HELPER" || \
    _fail "GNOME flow helper extraction"
sed -i \
    -e "s|/usr/share/gnome-initial-setup|$FLOW_ROOT/usr/share/gnome-initial-setup|g" \
    -e "s|/etc/xdg/autostart|$FLOW_ROOT/etc/xdg/autostart|g" \
    -e "s|PATH=/usr/sbin:/usr/bin|PATH=$FLOW_MOCKBIN:/usr/sbin:/usr/bin|" \
    -e "s|root:root:755|$(id -un):$(id -gn):755|g" \
    -e "s|root:root:644:1|$(id -un):$(id -gn):644:1|g" \
    "$FLOW_HELPER"
chmod 0755 "$FLOW_HELPER"
assert_cmd_success "GNOME flow helper parses" bash -n "$FLOW_HELPER"
assert_cmd_failure "GNOME flow helper rejects an unprivileged caller" \
    "$FLOW_HELPER"
mkdir -p "$FLOW_MOCKBIN" "$FLOW_ROOT/usr/share/gnome-initial-setup" \
    "$FLOW_ROOT/etc/xdg/autostart"
chmod 0755 "$FLOW_ROOT/usr/share/gnome-initial-setup" \
    "$FLOW_ROOT/etc/xdg/autostart"
cat > "$FLOW_MOCKBIN/id" <<'FLOW_ID_EOF'
#!/bin/bash
if [ "${1:-}" = -u ]; then printf '0\n'; else exec /usr/bin/id "$@"; fi
FLOW_ID_EOF
for mock_cmd in chown logger matchpathcon restorecon; do
    cat > "$FLOW_MOCKBIN/$mock_cmd" <<'FLOW_NOOP_EOF'
#!/bin/bash
exit 0
FLOW_NOOP_EOF
done
chmod 0755 "$FLOW_MOCKBIN"/*
printf '%s\n' '[pages]' 'skip=' \
    > "$FLOW_ROOT/usr/share/gnome-initial-setup/vendor.conf"
for flow_file in \
    org.gnome.Tour.desktop \
    localsearch-3.desktop \
    org.gnome.Evolution-alarm-notify.desktop \
    geoclue-demo-agent.desktop
do
    printf '%s\n' '[Desktop Entry]' 'Hidden=false' \
        > "$FLOW_ROOT/etc/xdg/autostart/$flow_file"
done
assert_cmd_success "GNOME flow helper repairs a complete package stomp" \
    env PATH="$FLOW_MOCKBIN:$PATH" "$FLOW_HELPER"
assert_grep_fixed 'skip=privacy;goa;software;parental-controls' \
    "$FLOW_ROOT/usr/share/gnome-initial-setup/vendor.conf" \
    "gnome-initial-setup page policy is restored"
for flow_file in \
    org.gnome.Tour.desktop \
    localsearch-3.desktop \
    org.gnome.Evolution-alarm-notify.desktop \
    geoclue-demo-agent.desktop
do
    assert_grep_fixed 'Hidden=true' \
        "$FLOW_ROOT/etc/xdg/autostart/$flow_file" \
        "$flow_file is hidden after package recovery"
    assert_eq 644 "$(stat -c %a "$FLOW_ROOT/etc/xdg/autostart/$flow_file")" \
        "$flow_file has the public desktop-entry mode"
done
flow_hash_before=$(find "$FLOW_ROOT" -type f -print0 | sort -z | \
    xargs -0 sha256sum | sha256sum | awk '{print $1}')
assert_cmd_success "GNOME flow recovery is idempotent" \
    env PATH="$FLOW_MOCKBIN:$PATH" "$FLOW_HELPER"
flow_hash_after=$(find "$FLOW_ROOT" -type f -print0 | sort -z | \
    xargs -0 sha256sum | sha256sum | awk '{print $1}')
assert_eq "$flow_hash_before" "$flow_hash_after" \
    "second GNOME flow recovery preserves every managed byte"
assert_grep_fixed 'mv -fT -- "$flow_tmp" "$dst"' "$FLOW_HELPER" \
    "GNOME flow helper atomically replaces, rather than follows, a target"
assert_grep_fixed 'matchpathcon -V "$dst"' "$FLOW_HELPER" \
    "GNOME flow helper makes the published SELinux label a hard postcondition"
assert_grep_fixed 'matchpathcon -V "$flow_dir"' "$FLOW_HELPER" \
    "GNOME flow helper verifies both managed directory labels"
rm -f "$FLOW_ROOT/etc/xdg/autostart/geoclue-demo-agent.desktop"
mkdir "$FLOW_ROOT/etc/xdg/autostart/geoclue-demo-agent.desktop"
assert_cmd_failure "GNOME flow helper rejects a managed directory target" \
    "$FLOW_HELPER"
assert_cmd_success "GNOME flow helper preserves the rejected directory target" \
    test -d "$FLOW_ROOT/etc/xdg/autostart/geoclue-demo-agent.desktop"
rmdir "$FLOW_ROOT/etc/xdg/autostart/geoclue-demo-agent.desktop"
for flow_pkg in gnome-initial-setup geoclue2 evolution-data-server; do
    assert_grep_fixed \
        "post_transaction:${flow_pkg}:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-restore-gnome-flow\\ >/dev/null" \
        "$KS_FILE" "$flow_pkg has a host-scoped fail-visible inbound recovery action"
done

# Persistent microphone policy is native WirePlumber configuration, not a
# best-effort login one-shot. All embedded bytes have canonical repo sources.
MIC_TMP=$(mktemp -d /var/tmp/noid-m17-structural.XXXXXXXX)
extract_heredoc "$KS_FILE" NOID_MIC_WP_CONF_EOF "$MIC_TMP/policy.conf" || \
    _fail "microphone WirePlumber config extraction"
extract_heredoc "$KS_FILE" NOID_MIC_WP_LUA_EOF "$MIC_TMP/policy.lua" || \
    _fail "microphone WirePlumber Lua extraction"
extract_heredoc "$KS_FILE" NOID_MIC_TOGGLE_EOF "$MIC_TMP/toggle" || \
    _fail "microphone toggle extraction"
assert_cmd_success "microphone config source/embed parity" \
    cmp -s "$MIC_CONF_SOURCE" "$MIC_TMP/policy.conf"
assert_cmd_success "microphone Lua source/embed parity" \
    cmp -s "$MIC_LUA_SOURCE" "$MIC_TMP/policy.lua"
assert_cmd_success "microphone toggle source/embed parity" \
    cmp -s "$MIC_TOGGLE_SOURCE" "$MIC_TMP/toggle"
if command -v spa-json-dump >/dev/null 2>&1; then
    assert_cmd_success "microphone WirePlumber config parses" \
        spa-json-dump "$MIC_TMP/policy.conf"
else
    _pass "WirePlumber SPA parser unavailable; Fedora runtime fixture owns parse gate"
fi
assert_cmd_success "microphone toggle parses" bash -n "$MIC_TMP/toggle"
assert_file_executable "$MIC_REGEN" "microphone embed generator is executable"
assert_cmd_success "microphone embed generator check passes" "$MIC_REGEN" --check
assert_grep_fixed 'noid.microphone.privacy = required' "$MIC_TMP/policy.conf" \
    "microphone component is a required main-profile feature"
assert_grep_fixed 'api.mixer' "$MIC_TMP/policy.conf" \
    "microphone component requires WirePlumber's native mixer API"
assert_grep_fixed 'default = true' "$MIC_TMP/policy.conf" \
    "microphone policy defaults fail-closed"
assert_grep_fixed 'ENFORCEMENT_INTERVAL_MSEC = 1000' "$MIC_TMP/policy.lua" \
    "event-driven microphone enforcement retains a bounded fallback"
assert_grep_fixed 'Plugin.find ("mixer-api")' "$MIC_TMP/policy.lua" \
    "microphone policy reads effective device-route mute state"
assert_grep_fixed 'mixer:connect ("changed"' "$MIC_TMP/policy.lua" \
    "microphone policy reacts to hardware and panel route changes"
assert_grep_fixed 'mixer:call ("set-volume"' "$MIC_TMP/policy.lua" \
    "microphone policy writes through WirePlumber's native route owner"
assert_grep_fixed 'grep -qxF "$WP_KEY=$value" "$state_file"' "$MIC_TMP/toggle" \
    "microphone toggle verifies persistent state-file durability"
assert_grep_fixed '($saved_value == true || $saved_value == default)' \
    "$MIC_TMP/toggle" "microphone status accepts the enforced safe schema default"
assert_grep_fixed 'microphone enable failed and fail-closed restoration was incomplete' \
    "$MIC_TMP/toggle" "microphone toggle exposes a failed safety rollback"
assert_not_grep 'force_disabled [|][|] true' "$MIC_TMP/toggle" \
    "microphone toggle never hides fail-closed rollback failure"
assert_not_grep_extended 'wpctl status.*awk|for _ in .*seq 1 30|set-mute.*[|][|] true' \
    "$KS_FILE" "retired best-effort one-shot implementation is absent"
assert_grep_fixed 'rm -f /usr/local/libexec/noid-mic-privacy-enforce' "$KS_FILE" \
    "M17 retires the old one-shot helper"

# First-login state is closed, per-task and retryable. The enabled update
# timer and static notifier intentionally have different activation contracts.
FIRSTRUN_TMP="$MIC_TMP/firstrun"
extract_heredoc "$KS_FILE" FIRSTRUN_SCRIPT_EOF "$FIRSTRUN_TMP" || \
    _fail "first-login helper extraction"
assert_grep_fixed 'UPDATE_UNIT=noid-update-reminder.timer' "$FIRSTRUN_TMP" \
    "first-login pins the preset-managed update timer"
assert_grep_fixed 'NOTIFIER_UNIT=usbguard-notifier.service' "$FIRSTRUN_TMP" \
    "first-login pins the static notifier unit"
assert_grep_fixed 'NOTIFIER_WANTS=/usr/lib/systemd/user/graphical-session.target.wants/usbguard-notifier.service' \
    "$FIRSTRUN_TMP" "first-login pins the notifier wants link"
assert_grep_fixed 'NOTIFIER_TARGET=/usr/lib/systemd/user/usbguard-notifier.service' \
    "$FIRSTRUN_TMP" "first-login pins the notifier link target"
assert_grep_fixed 'NAUTILUS_SORT_BY_ATTRIBUTE=metadata::nautilus-icon-view-sort-by' \
    "$FIRSTRUN_TMP" "first-login uses Nautilus' native folder sort metadata"
assert_grep_fixed 'NAUTILUS_SORT_REVERSED_ATTRIBUTE=metadata::nautilus-icon-view-sort-reversed' \
    "$FIRSTRUN_TMP" "first-login uses Nautilus' native sort-direction metadata"
assert_grep_fixed 'raw=$(xdg-user-dir DOWNLOAD' "$FIRSTRUN_TMP" \
    "first-login resolves the configured XDG Downloads folder"
assert_grep_fixed 'gio set -t string "$DOWNLOAD_DIR"' "$FIRSTRUN_TMP" \
    "first-login writes Downloads sorting through native GIO metadata"
assert_grep_fixed 'Every other pre-existing' "$FIRSTRUN_TMP" \
    "first-login preserves pre-existing user sort state"
assert_grep_fixed 'region nautilus_download_sort libvirt_qemu_core noid_update_reminder usbguard_notifier' \
    "$FIRSTRUN_TMP" "Downloads and libvirt initialization are required transactional tasks"
assert_grep_fixed 'LIBVIRT_CONFIG_DIR="${CONFIG_HOME}/libvirt"' \
    "$FIRSTRUN_TMP" "session libvirt configuration follows XDG_CONFIG_HOME"
assert_grep_fixed 'LIBVIRT_QEMU_CONF="${LIBVIRT_CONFIG_DIR}/qemu.conf"' \
    "$FIRSTRUN_TMP" "session libvirt configuration pins qemu.conf"
assert_grep_fixed 'existing max_core setting is user-owned and not zero' \
    "$FIRSTRUN_TMP" "first-login refuses a conflicting user max_core"
assert_grep_fixed 'existing dump_guest_core setting is user-owned and not zero' \
    "$FIRSTRUN_TMP" "first-login refuses conflicting guest-memory policy"
assert_grep_fixed 'contains duplicate active core settings' "$FIRSTRUN_TMP" \
    "first-login rejects ambiguous libvirt core configuration"
assert_grep_fixed 'exceeds the 1 MiB safety bound' "$FIRSTRUN_TMP" \
    "first-login bounds existing configuration input"
assert_grep_fixed 'mv -T --update=none-fail -- "$tmp" "$LIBVIRT_QEMU_CONF"' \
    "$FIRSTRUN_TMP" "first-login cannot replace a concurrently created file"
assert_grep_fixed '"$fingerprint_after" == "$fingerprint_before"' \
    "$FIRSTRUN_TMP" "first-login detects a concurrent existing-file change"
assert_grep_fixed "printf 'max_core = 0\\n'" "$FIRSTRUN_TMP" \
    "session libvirt max_core zero is explicit"
assert_grep_fixed "printf 'dump_guest_core = 0\\n'" "$FIRSTRUN_TMP" \
    "session libvirt guest-memory default is explicit"
assert_grep_fixed 'systemctl --user preset "$UPDATE_UNIT"' "$FIRSTRUN_TMP" \
    "first-login applies only the update timer preset"
assert_grep_fixed 'systemctl --user is-enabled --quiet "$UPDATE_UNIT"' "$FIRSTRUN_TMP" \
    "first-login proves update enablement before task commit"
assert_grep_fixed '[[ -L "$NOTIFIER_WANTS" ]]' "$FIRSTRUN_TMP" \
    "first-login rejects a non-symlink notifier wants entry"
assert_grep_fixed 'readlink -- "$NOTIFIER_WANTS"' "$FIRSTRUN_TMP" \
    "first-login proves the exact absolute static target"
assert_grep_fixed 'systemctl --user start "$NOTIFIER_UNIT"' "$FIRSTRUN_TMP" \
    "first-login starts the static notifier in the active session"
assert_grep_fixed 'systemctl --user is-active --quiet "$NOTIFIER_UNIT"' "$FIRSTRUN_TMP" \
    "first-login proves static notifier activity before task commit"
assert_not_grep 'preset "$NOTIFIER_UNIT"' "$FIRSTRUN_TMP" \
    "first-login never presets the deliberately static notifier"
assert_not_grep 'is-enabled --quiet "$NOTIFIER_UNIT"' "$FIRSTRUN_TMP" \
    "static notifier completion never depends on is-enabled"
assert_grep_fixed 'marker_valid complete || mark_done complete || exit 1' "$KS_FILE" \
    "completion is a no-write fast path once its derived state is exact"
assert_grep_fixed 'sync -- "$tmp"' "$FIRSTRUN_TMP" \
    "first-login task bytes are fsynced before atomic publication"
assert_grep_fixed 'sync -- "$STATE_DIR"' "$FIRSTRUN_TMP" \
    "first-login marker renames are fsynced through their directory"
assert_grep_fixed 'cannot durably invalidate stale complete marker' "$FIRSTRUN_TMP" \
    "derived completion is durably withdrawn before an incomplete-task retry"
assert_grep_fixed "'%u:%a:%h:%s'" "$FIRSTRUN_TMP" \
    "first-login markers require exact owner, mode, link count and byte count"
assert_grep_fixed 'flock -x "$state_lock_fd"' "$KS_FILE" \
    "manual and unit invocations serialize state cleanup/commit"
assert_grep_fixed 'Restart=on-failure' "$KS_FILE" \
    "transient first-login failure is retried"
assert_grep_fixed 'PartOf=graphical-session.target' "$KS_FILE" \
    "logout cancels an in-flight or queued first-login retry"
assert_grep_fixed 'ConditionEnvironment=XDG_SESSION_CLASS=user' "$KS_FILE" \
    "user unit rejects GNOME Initial Setup pseudo-user sessions"
assert_grep_fixed 'ExecCondition=/usr/bin/systemctl --user --quiet is-active graphical-session.target' \
    "$KS_FILE" "a delayed retry cannot run outside the graphical session"
assert_grep_fixed 'if [ "${XDG_SESSION_CLASS:-}" != user ]; then' "$KS_FILE" \
    "helper exits before home writes outside a real user session"
assert_not_grep_extended 'systemctl --user preset-all|Mark done regardless|ConditionPathExists=!%h/.config/noid-user-firstrun.done' \
    "$KS_FILE" "false-success/open-ended v1 first-login contract is absent"
assert_file_executable "$FIRSTRUN_FIXTURE" \
    "transactional first-login behavioral fixture is executable"

# Every service/DNF/environment-generator entry point in this module has one
# exact internal no-argument contract. Instrument the first effect of pristine
# extracted copies so hostile argv cannot pass merely because a later mock or
# live precondition happens to stop execution. This includes newline/terminal
# control bytes and the two independently installed systemd generators.
NOARG_TMP=$(mktemp -d /var/tmp/noid-m17-noarg.XXXXXXXX)
extract_heredoc "$KS_FILE" FIRSTRUN_SCRIPT_EOF "$NOARG_TMP/firstrun" || \
    _fail "first-login invocation fixture extraction"
extract_nth_heredoc "$KS_FILE" XDG_GEN_EOF 1 "$NOARG_TMP/xdg-system" || \
    _fail "system environment-generator invocation fixture extraction"
extract_nth_heredoc "$KS_FILE" XDG_GEN_EOF 2 "$NOARG_TMP/xdg-user" || \
    _fail "user environment-generator invocation fixture extraction"
extract_heredoc "$KS_FILE" NOID_GNOME_PRIVACY_CONTRACT_EOF \
    "$NOARG_TMP/privacy-contract" || \
    _fail "GNOME privacy-contract invocation fixture extraction"
extract_heredoc "$KS_FILE" GNOME_FLOW_EOF "$NOARG_TMP/gnome-flow" || \
    _fail "GNOME flow invocation fixture extraction"
cp -- "$LIVEINST_LIFECYCLE_SOURCE" "$NOARG_TMP/liveinst-lifecycle"

instrument_shell_effect_boundary "$NOARG_TMP/firstrun" 'export LC_ALL=C' || \
    _fail "first-login effect-boundary instrumentation"
instrument_shell_effect_boundary "$NOARG_TMP/xdg-system" \
    'xdg="${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"' || \
    _fail "system environment-generator effect-boundary instrumentation"
instrument_shell_effect_boundary "$NOARG_TMP/xdg-user" \
    'xdg="${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"' || \
    _fail "user environment-generator effect-boundary instrumentation"
instrument_shell_effect_boundary "$NOARG_TMP/privacy-contract" 'fail() {' || \
    _fail "GNOME privacy-contract effect-boundary instrumentation"
instrument_shell_effect_boundary "$NOARG_TMP/gnome-flow" \
    'LOG_TAG="noid-restore-gnome-flow"' || \
    _fail "GNOME flow effect-boundary instrumentation"
instrument_python_effect_boundary "$NOARG_TMP/liveinst-lifecycle" || \
    _fail "Live-installer lifecycle effect-boundary instrumentation"

for noarg_shell in firstrun xdg-system xdg-user privacy-contract gnome-flow; do
    assert_cmd_success "$noarg_shell invocation fixture parses" \
        bash -n "$NOARG_TMP/$noarg_shell"
done
assert_cmd_success "Live-installer invocation fixture compiles" python3 -c \
    'import pathlib,sys; p=pathlib.Path(sys.argv[1]); compile(p.read_bytes(), str(p), "exec")' \
    "$NOARG_TMP/liveinst-lifecycle"

exercise_noarg_gate "first-login helper" "$NOARG_TMP/firstrun" \
    'noid-user-firstrun: ERROR: this internal helper accepts no arguments'
exercise_noarg_gate "system XDG generator" "$NOARG_TMP/xdg-system" \
    'noid-xdg-cleanup: ERROR: this internal helper accepts no arguments'
exercise_noarg_gate "user XDG generator" "$NOARG_TMP/xdg-user" \
    'noid-xdg-cleanup: ERROR: this internal helper accepts no arguments'
exercise_noarg_gate "GNOME privacy-contract helper" \
    "$NOARG_TMP/privacy-contract" \
    'noid-verify-gnome-privacy-contract: ERROR: this internal helper accepts no arguments'
exercise_noarg_gate "GNOME flow helper" "$NOARG_TMP/gnome-flow" \
    'noid-restore-gnome-flow: ERROR: this internal helper accepts no arguments'
exercise_noarg_gate "Live-installer lifecycle helper" \
    "$NOARG_TMP/liveinst-lifecycle" \
    'noid-liveinst-webui-lifecycle: ERROR: this internal helper accepts no arguments'

# User unit masks via /etc/systemd/user
assert_grep_fixed "/etc/systemd/user" "$KS_FILE"
assert_grep_fixed 'org.gnome.SettingsDaemon.UsbProtection.service' "$KS_FILE" \
    "GNOME USB-protection service is masked system-wide"
assert_grep_fixed 'org.gnome.SettingsDaemon.UsbProtection.target' "$KS_FILE" \
    "GNOME USB-protection target cannot reactivate the service"
assert_grep_fixed 'false was effective in' "$KS_FILE" \
    "Dconf false is not misrepresented as the USB security boundary"
# dconf update is invoked (required for binary db compile)
assert_grep_fixed "dconf update" "$KS_FILE"

# NOT masking at-spi (accessibility must keep working on generic image)
assert_not_grep 'ln -sf /dev/null /etc/systemd/user/at-spi-dbus-bus' "$KS_FILE"

# Step 7c: Live-mode GDM auto-login + graphical.target default
# Fills livesys-script gaps for GNOME flavor — see M17 Step 7c comments.
assert_grep_fixed 'AutomaticLogin only under its own runtime conditions' \
    "$KS_FILE" "stock Live GDM behavior is described as conditional"
assert_grep_fixed 'it does not provide TimedLogin after an intentional' "$KS_FILE" \
    "M17 distinguishes its TimedLogin addition from Fedora's stock hook"
assert_grep_fixed 'M41 noid-anaconda-cleanup safety net removes liveuser' \
    "$KS_FILE" "installed-system cleanup ownership names the actual NoID Privacy helper"
assert_not_grep 'livesys-gnome writes no GDM AutomaticLogin' "$KS_FILE" \
    "false stock livesys claim is absent"
assert_not_grep_extended '(^|[^-])anaconda-cleanup reverts|Anaconda-cleanup reverts' \
    "$KS_FILE" "ambiguous upstream cleanup ownership is absent"
assert_grep_fixed 'Fedora removed the GNOME X11 session in Fedora 43' "$KS_FILE" \
    "Wayland rationale follows Fedora's actual release change"
assert_not_grep 'gnome-session-xsession' "$KS_FILE" \
    "Wayland rationale does not rely on a stale package-group claim"
assert_grep_fixed '/var/lib/livesys/livesys-session-extra' "$KS_FILE"
assert_grep_fixed 'LIVESYS_EXTRA_EOF' "$KS_FILE"
assert_grep_fixed 'passwd -d liveuser' "$KS_FILE"
assert_not_grep 'passwd -d liveuser.*[|][|][[:space:]]*true' "$KS_FILE" \
    "liveuser unlock failure is reported"
assert_not_grep 'passwd -d root.*[|][|][[:space:]]*true' "$KS_FILE" \
    "live root unlock failure is reported"
assert_grep_fixed 'AutomaticLogin=liveuser' "$KS_FILE"
assert_grep_fixed 'TimedLoginEnable=true' "$KS_FILE" \
    "Live GDM enables native recovery after an intentional logout"
assert_grep_fixed 'TimedLogin=liveuser' "$KS_FILE"
assert_grep_fixed 'TimedLoginDelay=1' "$KS_FILE"
assert_grep_fixed 'systemctl set-default graphical.target' "$KS_FILE"
extract_heredoc "$KS_FILE" LIVESYS_EXTRA_EOF "$MIC_TMP/livesys-session-extra" || \
    _fail "Live session hook extraction"
assert_cmd_success "Live session hook parses" sh -n "$MIC_TMP/livesys-session-extra"
extract_heredoc "$MIC_TMP/livesys-session-extra" NOID_LIVEUSER_SUDOERS_EOF \
    "$MIC_TMP/liveuser.sudoers" || _fail "Live sudoers extraction"
assert_eq 2 "$(grep -cEv '^[[:space:]]*(#|$)' "$MIC_TMP/liveuser.sudoers")" \
    "Live sudoers contains exactly two active records"
assert_eq 1 \
    "$(grep -Fxc 'Defaults:liveuser verifypw=any' "$MIC_TMP/liveuser.sudoers")" \
    "Live sudo validation needs one current-host NOPASSWD entry"
assert_eq 1 \
    "$(grep -Fxc 'liveuser ALL=(ALL) NOPASSWD: ALL' "$MIC_TMP/liveuser.sudoers")" \
    "Live command authorization remains one exact NOPASSWD rule"
assert_cmd_success "Live sudoers passes the native parser" \
    visudo -cf "$MIC_TMP/liveuser.sudoers"
assert_grep_fixed 'mv -fT -- "$live_sudoers_tmp" "$live_sudoers"' \
    "$MIC_TMP/livesys-session-extra" \
    "validated Live sudoers policy is atomically published"
assert_grep_fixed "/usr/sbin/visudo -cf" "$MIC_TMP/livesys-session-extra" \
    "Live hook validates both staged and published sudoers bytes"
assert_grep_fixed 'install -d -m 0700 -o "$noid_live_uid" -g "$noid_live_gid"' \
    "$MIC_TMP/livesys-session-extra" \
    "Live user receives private UID/GID-bound config directories"
assert_grep_fixed '/home/liveuser/.config/containers/storage.conf' \
    "$MIC_TMP/livesys-session-extra" \
    "Live-only storage selection is scoped to the ephemeral user home"
assert_grep_fixed 'driver = "vfs"' "$MIC_TMP/livesys-session-extra" \
    "rootless Podman avoids unsupported overlay-on-Live-overlay nesting"
assert_grep_fixed 'chmod 0600 "$noid_live_storage_tmp"' \
    "$MIC_TMP/livesys-session-extra" \
    "Live Podman storage candidate is user-private before publication"
assert_grep_fixed 'mv -fT -- "$noid_live_storage_tmp" "$noid_live_storage"' \
    "$MIC_TMP/livesys-session-extra" \
    "Live Podman storage selection is atomically published"
assert_not_grep '/etc/containers/storage\.conf' "$MIC_TMP/livesys-session-extra" \
    "installed users retain Podman's maintained storage-driver selection"
assert_not_grep 'fuse-overlayfs' "$MIC_TMP/livesys-session-extra" \
    "Live repair adds no package or external overlay helper"
assert_grep_fixed 'noid_live_seed_template()' "$MIC_TMP/livesys-session-extra" \
    "Live hook owns one closed template-seeding path"
assert_grep_fixed '0:0:644' "$MIC_TMP/livesys-session-extra" \
    "Live Agent templates require exact Root-owned source metadata"
assert_grep_fixed 'cmp -s -- "$noid_live_source" "$noid_live_destination"' \
    "$MIC_TMP/livesys-session-extra" \
    "Live Agent config floor has a byte-exact postcondition"
assert_grep_fixed 'mv -fT -- "$noid_live_tmp" "$noid_live_destination"' \
    "$MIC_TMP/livesys-session-extra" \
    "Live Agent template publication never chmods through a user path"
assert_grep_fixed 'preserving different persistent Live template' \
    "$MIC_TMP/livesys-session-extra" \
    "Live hook explicitly preserves divergent persistent user configuration"
assert_grep_fixed 'continuing essential Live setup' \
    "$MIC_TMP/livesys-session-extra" \
    "user-home failure cannot abort the sourced livesys parent"
assert_grep_fixed '/etc/skel/.config/VSCodium/User/settings.json' \
    "$MIC_TMP/livesys-session-extra" \
    "Live VSCodium floor comes from M08's reviewed skel template"
assert_grep_fixed '/home/liveuser/.config/VSCodium/User/settings.json' \
    "$MIC_TMP/livesys-session-extra" \
    "Live VSCodium floor reaches the already-created Live account"
assert_grep_fixed '/etc/skel/.claude/settings.json' \
    "$MIC_TMP/livesys-session-extra" \
    "Live Claude floor comes from M08's reviewed skel template"
assert_grep_fixed '/home/liveuser/.claude/settings.json' \
    "$MIC_TMP/livesys-session-extra" \
    "Live Claude floor reaches the already-created Live account"
assert_not_grep_extended '\.vsix|open-vsx|anthropic/claude|openai/codex' \
    "$MIC_TMP/livesys-session-extra" \
    "Live config repair carries no vendor Agent code or fetch path"
assert_grep_fixed 'TimedLoginEnable=true' "$MIC_TMP/livesys-session-extra" \
    "extracted Live hook uses GDM timed re-login"
assert_grep_fixed 'TimedLogin=liveuser' "$MIC_TMP/livesys-session-extra"
assert_grep_fixed 'TimedLoginDelay=1' "$MIC_TMP/livesys-session-extra"
assert_not_grep 'disable-log-out=true' "$MIC_TMP/livesys-session-extra" \
    "extracted Live hook never enables the power-submenu lockdown"
assert_not_grep '/org/gnome/desktop/lockdown/disable-log-out' \
    "$MIC_TMP/livesys-session-extra" \
    "extracted Live hook never locks the power-submenu setting"
assert_grep_fixed 'Fedora livesys-main deliberately disables' \
    "$MIC_TMP/livesys-session-extra" \
    "Live hook identifies the native deferred systemd-cache owner"
assert_eq 1 "$(grep -cFx 'if ! systemctl daemon-reload; then' \
    "$MIC_TMP/livesys-session-extra")" \
    "Live hook completes Fedora's deferred daemon reload exactly once"

# Fedora's RPM-owned liveinst/WebUI payload stays untouched. A Live-only path
# unit consumes Fedora's own PID record, while a pidfd binds the exact process
# instance and systemd owns teardown of the known service cgroup.
extract_heredoc "$KS_FILE" NOID_LIVEINST_WEBUI_LIFECYCLE_EOF \
    "$MIC_TMP/noid-liveinst-webui-lifecycle.py" || \
    _fail "Live-installer lifecycle helper extraction"
extract_heredoc "$KS_FILE" NOID_LIVEINST_WEBUI_SERVICE_EOF \
    "$MIC_TMP/noid-liveinst-webui-lifecycle.service.raw" || \
    _fail "Live-installer lifecycle service extraction"
extract_heredoc "$KS_FILE" NOID_LIVEINST_WEBUI_PATH_EOF \
    "$MIC_TMP/noid-liveinst-webui-lifecycle.path" || \
    _fail "Live-installer lifecycle path extraction"
assert_cmd_success "Live-installer lifecycle source/embed parity" \
    cmp -s "$LIVEINST_LIFECYCLE_SOURCE" \
        "$MIC_TMP/noid-liveinst-webui-lifecycle.py"
assert_cmd_success "Live-installer lifecycle helper compiles" python3 -c \
    'import pathlib,sys; p=pathlib.Path(sys.argv[1]); compile(p.read_bytes(), str(p), "exec")' \
    "$LIVEINST_LIFECYCLE_SOURCE"
assert_file_executable "$LIVEINST_LIFECYCLE_REGEN" \
    "Live-installer lifecycle embed generator is executable"
assert_cmd_success "Live-installer lifecycle embed generator check passes" \
    "$LIVEINST_LIFECYCLE_REGEN" --check
assert_file_executable "$LIVEINST_LIFECYCLE_FIXTURE" \
    "Live-installer lifecycle behavioral fixture is executable"
assert_grep_fixed 'sys.dont_write_bytecode = True' \
    "$LIVEINST_LIFECYCLE_FIXTURE" \
    "lifecycle fixture cannot leave bytecode in the public source tree"
assert_cmd_success "Live-installer lifecycle behavioral fixture passes" \
    python3 "$LIVEINST_LIFECYCLE_FIXTURE" "$LIVEINST_LIFECYCLE_SOURCE"
assert_file_executable "$LIVEINST_LIFECYCLE_RUNTIME" \
    "candidate Live-installer lifecycle gate is executable"
assert_cmd_success "candidate Live-installer lifecycle gate parses" \
    bash -n "$LIVEINST_LIFECYCLE_RUNTIME"
for lifecycle_phase in live:baseline live:active live:closed live:error-exit \
        fresh-install:absent reboot:absent; do
    assert_grep_fixed "$lifecycle_phase" "$LIVEINST_LIFECYCLE_RUNTIME" \
        "Live-installer runtime gate recognizes $lifecycle_phase"
done
assert_grep_fixed 'signal.pidfd_send_signal(pidfd, signal.SIGTERM)' \
    "$LIVEINST_LIFECYCLE_RUNTIME" \
    "error-exit gate signals the identity-validated process descriptor"
assert_not_grep 'kill -TERM "$WEBUI_PID"' "$LIVEINST_LIFECYCLE_RUNTIME" \
    "error-exit gate never falls back to a reusable numeric PID"
assert_grep_fixed 'proc_cgroup == "$control_group"' \
    "$LIVEINST_LIFECYCLE_RUNTIME" \
    "active gate binds every TCP/80 listener to the WebUI service cgroup"
assert_grep_fixed '127.0.0.1:80' "$LIVEINST_LIFECYCLE_RUNTIME" \
    "active gate proves the listener remains loopback-only"
extract_heredoc "$LIVEINST_LIFECYCLE_RUNTIME" NOID_LIVEINST_PIDFD_SIGNAL_EOF \
    "$MIC_TMP/noid-liveinst-runtime-pidfd-signal.py" || \
    _fail "Live-installer runtime pidfd signal extraction"
assert_cmd_success "Live-installer runtime pidfd signal helper compiles" python3 -c \
    'import pathlib,sys; p=pathlib.Path(sys.argv[1]); compile(p.read_bytes(), str(p), "exec")' \
    "$MIC_TMP/noid-liveinst-runtime-pidfd-signal.py"
assert_grep_fixed 'for package in anaconda-live anaconda-webui; do' \
    "$LIVEINST_LIFECYCLE_RUNTIME" \
    "installed lifecycle pass requires the installer-only packages removed"
assert_grep_fixed 'installer-only RPM payload remains: $payload' \
    "$LIVEINST_LIFECYCLE_RUNTIME" \
    "installed lifecycle pass rejects a retained installer payload"
assert_grep_fixed '-p LoadState --value) == not-found' \
    "$LIVEINST_LIFECYCLE_RUNTIME" \
    "installed lifecycle pass proves Fedora's WebUI unit is no longer loadable"
assert_grep_fixed 'PathChanged=/run/anaconda/webui_script.pid' \
    "$MIC_TMP/noid-liveinst-webui-lifecycle.path" \
    "systemd observes Fedora's close-after-write lifecycle record"
assert_grep_fixed 'ConditionKernelCommandLine=rd.live.image' \
    "$MIC_TMP/noid-liveinst-webui-lifecycle.path" \
    "path activation is impossible on an installed root"
assert_grep_fixed 'ConditionKernelCommandLine=rd.live.image' \
    "$MIC_TMP/noid-liveinst-webui-lifecycle.service.raw" \
    "lifecycle helper has an independent Live-root condition"
assert_grep_fixed 'TimeoutStartSec=infinity' \
    "$MIC_TMP/noid-liveinst-webui-lifecycle.service.raw" \
    "companion may wait for an intentionally long installer session"
assert_grep_fixed 'KillMode=control-group' \
    "$MIC_TMP/noid-liveinst-webui-lifecycle.service.raw" \
    "companion teardown itself remains cgroup-scoped"
assert_grep_fixed 'pidfd_open(pid, 0)' "$LIVEINST_LIFECYCLE_SOURCE" \
    "WebUI identity is bound without a PID-reuse race"
assert_grep_fixed 'os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK' \
    "$LIVEINST_LIFECYCLE_SOURCE" \
    "WebUI PID-file inspection cannot block on a non-regular lifecycle record"
assert_grep_fixed 'arguments[1:] != expected_tail' "$LIVEINST_LIFECYCLE_SOURCE" \
    "only Fedora's exact webui-desktop -t live argv is admitted"
assert_grep_fixed '[SYSTEMCTL, "stop", SERVICE]' "$LIVEINST_LIFECYCLE_SOURCE" \
    "helper stops only the exact auxiliary systemd unit"
assert_grep_fixed 'properties != expected' "$LIVEINST_LIFECYCLE_SOURCE" \
    "inactive/dead/MainPID-zero is an exact postcondition"
assert_not_grep_extended 'pkill|killall|os\.kill\(|pidfd_send_signal' \
    "$LIVEINST_LIFECYCLE_SOURCE" \
    "lifecycle helper never signals an arbitrary process or process name"
assert_not_grep_extended 'sed -i.*(/usr/bin/liveinst|webui-desktop)|cat > /usr/bin/liveinst|cat > /usr/libexec/anaconda/webui-desktop' \
    "$KS_FILE" "M17 leaves Fedora's signed Live-installer payload pristine"

# The normal Live desktop path uses Fedora liveinst's supported local
# updates-image interface. Its one derivative consumes only a strict,
# compose-time Lorax manifest and retains Fedora's full scan as the fallback.
extract_heredoc "$KS_FILE" NOID_LIVEINST_REQUIRED_SPACE_EOF \
    "$MIC_TMP/live-os-initialization.py" || \
    _fail "Live required-space derivative extraction"
assert_cmd_success "Live required-space source/embed parity" \
    cmp -s "$LIVEINST_SIZE_SOURCE" "$MIC_TMP/live-os-initialization.py"
assert_cmd_success "Live required-space derivative compiles" python3 -B -c \
    'import pathlib,sys; p=pathlib.Path(sys.argv[1]); compile(p.read_bytes(), str(p), "exec")' \
    "$LIVEINST_SIZE_SOURCE"
assert_eq 73fc1d452704547ef1c1759ebd925234e5a4d9c2e856486f33989242807148b0 \
    "$(sha256sum "$LIVEINST_SIZE_SOURCE" | awk '{print $1}')" \
    "M17 pins the exact generated derivative bytes"
liveinst_size_sha256=$(sha256sum "$LIVEINST_SIZE_SOURCE" | awk '{print $1}')
assert_grep_fixed "LIVEINST_UPDATE_SOURCE_SHA256=\"$liveinst_size_sha256\"" \
    "$KS_FILE" "M17 runtime pin matches the canonical derivative bytes"
assert_file_executable "$LIVEINST_SIZE_REGEN" \
    "Live required-space embed generator is executable"
assert_cmd_success "Live required-space embed generator check passes" \
    "$LIVEINST_SIZE_REGEN" --check
assert_file_executable "$LIVEINST_SIZE_FIXTURE" \
    "Live required-space behavioral fixture is executable"
assert_grep_fixed 'sys.dont_write_bytecode = True' "$LIVEINST_SIZE_FIXTURE" \
    "Live required-space fixture never writes into the repository source tree"
assert_cmd_success "Live required-space behavioral fixture passes" \
    python3 -B "$LIVEINST_SIZE_FIXTURE" "$LIVEINST_SIZE_SOURCE"
assert_grep_fixed \
    'SUPPORTED_ANACONDA_BASE_SHA256 = (' \
    "$LIVEINST_SIZE_SOURCE" "overlay binds the reviewed upstream source"
assert_grep_fixed \
    'b"0dbcdeccf8d9ee0a1e36700b32adf3d0ef9eef7b9ea310386c60996439c946b6"' \
    "$LIVEINST_SIZE_SOURCE" "overlay carries the exact Anaconda base hash"
assert_grep_fixed 'precalculated_space = self._read_precalculated_required_space()' \
    "$LIVEINST_SIZE_SOURCE" "strict manifest is consulted before the scan"
assert_grep_fixed 'os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,' \
    "$LIVEINST_SIZE_SOURCE" \
    "manifest inspection cannot block on a non-regular image entry"
assert_grep_fixed 'result = execWithCapture("du", du_cmd_args)' \
    "$LIVEINST_SIZE_SOURCE" "Fedora's original du fallback remains intact"
assert_grep_fixed 'anaconda-core-44.30-2.fc44.x86_64' "$KS_FILE" \
    "updates overlay is gated to the reviewed Anaconda core NEVRA"
assert_grep_fixed 'anaconda-live-44.30-2.fc44.noarch' "$KS_FILE" \
    "updates overlay is gated to the reviewed liveinst NEVRA"
assert_grep_fixed \
    '99fa227f7ec0e2ae79dcf648fafa316b79c384d173c886385cb9879c890eef59' \
    "$KS_FILE" "M17 proves the RPM-owned liveinst bytes before and after wiring"
assert_grep_fixed \
    'cpio --null --quiet --format=newc --reproducible --owner=0:0 -o' \
    "$KS_FILE" "Live updates image has deterministic newc metadata"
assert_grep_fixed 'unsafe Live-installer updates parent:' "$KS_FILE" \
    "M17 refuses a symlinked, foreign-owned or writable /boot path"
assert_grep_fixed 'unsafe pre-existing Live-installer updates directory' \
    "$KS_FILE" "M17 never follows an existing updates-directory symlink"
assert_grep_fixed 'gzip -n -9 > "$liveinst_update_candidate"' "$KS_FILE" \
    "Live updates image has deterministic gzip metadata"
assert_grep_fixed 'matchpathcon -V "$LIVEINST_UPDATE_IMAGE"' "$KS_FILE" \
    "published Live updates image has a verified SELinux label"
assert_grep_fixed 'sync -- "$LIVEINST_UPDATE_IMAGE" "$LIVEINST_UPDATE_DIR"' \
    "$KS_FILE" "Live updates publication durably syncs bytes and directory entry"
assert_grep_fixed \
    'noid_liveinst_expected="Exec=liveinst --updates=file://$noid_liveinst_updates"' \
    "$KS_FILE" "ephemeral Live launcher uses Fedora's native local updates path"
assert_grep_fixed 'LIVEINST_UMASK_WRAPPER=/usr/local/bin/liveinst' \
    "$KS_FILE" "Live PATH receives one explicit public-system-metadata wrapper"
assert_grep_fixed 'PATH=/usr/local/bin:/usr/bin command -v liveinst' "$KS_FILE" \
    "compose proves the stock launcher resolves through the explicit Live PATH"
assert_grep_fixed 'hash -r' \
    <(sed -n '/LIVEINST_UMASK_WRAPPER=/,/Live-installer public-umask wrapper postcondition/p' \
        "$KS_FILE") \
    "Live wrapper publication invalidates any earlier shell command cache"
assert_grep_fixed 'exec /usr/bin/liveinst "$@"' "$KS_FILE" \
    "Live wrapper delegates argument-exactly to Fedora's RPM-owned executable"
assert_grep_fixed \
    'liveinst_resolved=$(command -v liveinst 2>/dev/null || true)' \
    "$LIVEINST_LIFECYCLE_RUNTIME" \
    "runtime resolves the effective launcher without assuming one PATH spelling"
assert_grep_fixed \
    '&& $liveinst_resolved -ef $liveinst_umask_wrapper ]]' \
    "$LIVEINST_LIFECYCLE_RUNTIME" \
    "runtime accepts Fedora's merged local-sbin alias only for the same wrapper inode"
assert_grep_fixed 'assert_anaconda_public_umask' "$LIVEINST_LIFECYCLE_RUNTIME" \
    "active Live gate proves the real Anaconda backend inherited umask 0022"
assert_grep_fixed "grep -qE '^Umask:[[:space:]]+0022\$'" \
    "$LIVEINST_LIFECYCLE_RUNTIME" \
    "runtime reads the kernel-reported backend umask instead of inferring it"
extract_heredoc "$KS_FILE" NOID_LIVEINST_UMASK_EOF \
    "$MIC_TMP/liveinst-umask-wrapper" || \
    _fail "Live-installer public-umask wrapper extraction"
sed "s#/usr/bin/liveinst#$MIC_TMP/liveinst-umask-target#" \
    "$MIC_TMP/liveinst-umask-wrapper" \
    > "$MIC_TMP/liveinst-umask-wrapper.fixture"
cat > "$MIC_TMP/liveinst-umask-target" <<'NOID_LIVEINST_UMASK_TARGET_EOF'
#!/usr/bin/bash
printf '%s|%s\n' "$(umask)" "$*"
NOID_LIVEINST_UMASK_TARGET_EOF
chmod 0755 \
    "$MIC_TMP/liveinst-umask-wrapper.fixture" \
    "$MIC_TMP/liveinst-umask-target"
assert_cmd_success "Live-installer public-umask wrapper parses" \
    bash -n "$MIC_TMP/liveinst-umask-wrapper"
liveinst_umask_result=$(umask 027; \
    "$MIC_TMP/liveinst-umask-wrapper.fixture" --updates=file:///fixture direct)
assert_eq '0022|--updates=file:///fixture direct' "$liveinst_umask_result" \
    "Live wrapper narrows only its child to public umask and preserves argv"
assert_grep_fixed 'launcher wiring deferred to Live overlay' "$KS_FILE" \
    "compose keeps Fedora's RPM-owned desktop launcher pristine"
assert_grep_fixed \
    'noid_liveinst_updates=/boot/loader/noid-privacy/liveinst-updates.img' \
    "$MIC_TMP/livesys-session-extra" \
    "post-livesys hook owns the ephemeral updates-image wiring"
assert_grep_fixed \
    'optional installer --updates wiring unavailable; continuing essential Live convergence' \
    "$MIC_TMP/livesys-session-extra" \
    "optional installer acceleration cannot abort essential Live convergence"
assert_grep_fixed \
    'mv -fT -- "$noid_liveinst_tmp" "$noid_liveinst_desktop"' \
    "$MIC_TMP/livesys-session-extra" \
    "ephemeral installer launcher is atomically published"
assert_grep_fixed 'mktemp --suffix=.desktop' \
    "$MIC_TMP/livesys-session-extra" \
    "staged launcher retains the suffix required by the native validator"
assert_not_grep_extended \
    'sed -i.*[$]LIVEINST_VENDOR_DESKTOP|sed -i.*liveinst[.]desktop' \
    "$KS_FILE" "compose never edits the RPM-owned Live installer launcher"
assert_not_grep_extended \
    'sed -i.*initialization\.py|cat > /usr/lib64/python3\.14/site-packages/pyanaconda' \
    "$KS_FILE" "M17 never rewrites the package-owned Anaconda module in SquashFS"
assert_not_grep_extended \
    'KSPP_KERNEL_ARGS=.*inst\.updates|--extra-boot-args.*inst\.updates' \
    "$PROJECT_ROOT/scripts/build-iso.sh" \
    "Live-only overlay is not consumed by the transient build installer"
sed 's#ExecStart=/usr/local/libexec/noid-liveinst-webui-lifecycle#ExecStart=/bin/true#' \
    "$MIC_TMP/noid-liveinst-webui-lifecycle.service.raw" \
    > "$MIC_TMP/noid-liveinst-webui-lifecycle.service"
if command -v systemd-analyze >/dev/null 2>&1; then
    assert_cmd_success "Live-installer lifecycle systemd units validate" \
        systemd-analyze verify \
            "$MIC_TMP/noid-liveinst-webui-lifecycle.service" \
            "$MIC_TMP/noid-liveinst-webui-lifecycle.path"
else
    _pass "systemd-analyze unavailable; candidate runtime owns lifecycle-unit validation"
fi

# Exercise the exact extracted hook in a private /var/tmp filesystem view.
# Identity/account commands are deterministic local mocks; every productive
# path is rewritten below the fixture root, so no host account/config changes.
LIVE_FIXTURE="$MIC_TMP/live-agent-floor"
LIVE_FAKEBIN="$LIVE_FIXTURE/fakebin"
LIVE_HOME="$LIVE_FIXTURE/home/liveuser"
mkdir -p \
    "$LIVE_FAKEBIN" \
    "$LIVE_HOME" \
    "$LIVE_FIXTURE/etc/skel/.config/VSCodium/User" \
    "$LIVE_FIXTURE/etc/skel/.claude" \
    "$LIVE_FIXTURE/etc/sudoers.d" \
    "$LIVE_FIXTURE/usr/share/applications" \
    "$LIVE_FIXTURE/boot/loader/noid-privacy"
printf '%s\n' \
    '[Desktop Entry]' \
    'Type=Application' \
    'Name=Install to Hard Drive' \
    'Exec=liveinst' \
    > "$LIVE_FIXTURE/usr/share/applications/anaconda.desktop"
printf '%s\n' 'fixture updates image' | gzip -n \
    > "$LIVE_FIXTURE/boot/loader/noid-privacy/liveinst-updates.img"
chmod 0644 \
    "$LIVE_FIXTURE/usr/share/applications/anaconda.desktop" \
    "$LIVE_FIXTURE/boot/loader/noid-privacy/liveinst-updates.img"
extract_heredoc "$PROJECT_ROOT/kickstart/snippets/08-service-minimization.ks" \
    CODIUM_SETTINGS_EOF \
    "$LIVE_FIXTURE/etc/skel/.config/VSCodium/User/settings.json" || \
    _fail "extract canonical VSCodium Live fixture"
extract_heredoc "$PROJECT_ROOT/kickstart/snippets/08-service-minimization.ks" \
    CLAUDE_SETTINGS_EOF \
    "$LIVE_FIXTURE/etc/skel/.claude/settings.json" || \
    _fail "extract canonical Claude Live fixture"
chmod 0644 \
    "$LIVE_FIXTURE/etc/skel/.config/VSCodium/User/settings.json" \
    "$LIVE_FIXTURE/etc/skel/.claude/settings.json"

cat > "$LIVE_FAKEBIN/id" <<'NOID_LIVE_ID_FIXTURE_EOF'
#!/bin/sh
case "$*" in
    liveuser) exit 0 ;;
    '-u liveuser') exec /usr/bin/id -u ;;
    '-g liveuser') exec /usr/bin/id -g ;;
    *) exec /usr/bin/id "$@" ;;
esac
NOID_LIVE_ID_FIXTURE_EOF
for noid_mock in chown dconf logger passwd restorecon usermod; do
    cat > "$LIVE_FAKEBIN/$noid_mock" <<'NOID_LIVE_ACCOUNT_FIXTURE_EOF'
#!/bin/sh
exit 0
NOID_LIVE_ACCOUNT_FIXTURE_EOF
done
LIVE_SYSTEMCTL_CALLS="$LIVE_FIXTURE/systemctl.calls"
: > "$LIVE_SYSTEMCTL_CALLS"
cat > "$LIVE_FAKEBIN/systemctl" <<'NOID_LIVE_SYSTEMCTL_FIXTURE_EOF'
#!/bin/sh
printf '%s\n' "$*" >> "${NOID_TEST_LIVE_SYSTEMCTL_CALLS:?}"
exit 0
NOID_LIVE_SYSTEMCTL_FIXTURE_EOF
chmod 0755 \
    "$LIVE_FAKEBIN/id" \
    "$LIVE_FAKEBIN/chown" \
    "$LIVE_FAKEBIN/logger" \
    "$LIVE_FAKEBIN/restorecon" \
    "$LIVE_FAKEBIN/passwd" \
    "$LIVE_FAKEBIN/usermod" \
    "$LIVE_FAKEBIN/dconf" \
    "$LIVE_FAKEBIN/systemctl"

sed \
    -e "s#/home/liveuser#$LIVE_HOME#g" \
    -e "s#/etc/skel#$LIVE_FIXTURE/etc/skel#g" \
    -e "s#\"0:0:644\"#\"$(id -u):$(id -g):644\"#g" \
    -e "s#\"0:0:440:1\"#\"$(id -u):$(id -g):440:1\"#g" \
    -e "s#root:root:644:1#$(id -un):$(id -gn):644:1#g" \
    -e "s#/etc/sudoers.d#$LIVE_FIXTURE/etc/sudoers.d#g" \
    -e "s#/etc/gdm#$LIVE_FIXTURE/etc/gdm#g" \
    -e "s#/etc/dconf/db/site.d#$LIVE_FIXTURE/etc/dconf/db/site.d#g" \
    -e "s#/usr/share/applications#$LIVE_FIXTURE/usr/share/applications#g" \
    -e "s#/boot/loader/noid-privacy/liveinst-updates.img#$LIVE_FIXTURE/boot/loader/noid-privacy/liveinst-updates.img#g" \
    "$MIC_TMP/livesys-session-extra" > "$MIC_TMP/livesys-session-extra.fixture"
chmod 0755 "$MIC_TMP/livesys-session-extra.fixture"

run_live_agent_floor_fixture() {
    env PATH="$LIVE_FAKEBIN:/usr/bin:/bin" \
        NOID_TEST_LIVE_SYSTEMCTL_CALLS="$LIVE_SYSTEMCTL_CALLS" \
        sh "$MIC_TMP/livesys-session-extra.fixture"
}

assert_cmd_success "Live Agent floor behavioral happy path" \
    run_live_agent_floor_fixture
assert_eq 1 "$(grep -cFx 'daemon-reload' "$LIVE_SYSTEMCTL_CALLS")" \
    "Live hook executes one native daemon reload on its happy path"
assert_eq 1 \
    "$(grep -Fxc \
        "Exec=liveinst --updates=file://$LIVE_FIXTURE/boot/loader/noid-privacy/liveinst-updates.img" \
        "$LIVE_FIXTURE/usr/share/applications/anaconda.desktop")" \
    "Live hook publishes the exact local updates-image launcher"
assert_cmd_success "Live fixture installer launcher validates" \
    desktop-file-validate \
        "$LIVE_FIXTURE/usr/share/applications/anaconda.desktop"
assert_cmd_success "Live VSCodium fixture is byte-exact" cmp -s \
    "$LIVE_FIXTURE/etc/skel/.config/VSCodium/User/settings.json" \
    "$LIVE_HOME/.config/VSCodium/User/settings.json"
assert_cmd_success "Live Claude fixture is byte-exact" cmp -s \
    "$LIVE_FIXTURE/etc/skel/.claude/settings.json" \
    "$LIVE_HOME/.claude/settings.json"
assert_eq "$(id -u):$(id -g):644" \
    "$(stat -c '%u:%g:%a' "$LIVE_HOME/.config/VSCodium/User/settings.json")" \
    "Live VSCodium fixture ownership/mode postcondition"
assert_eq "$(id -u):$(id -g):644" \
    "$(stat -c '%u:%g:%a' "$LIVE_HOME/.claude/settings.json")" \
    "Live Claude fixture ownership/mode postcondition"
assert_cmd_success "Live Agent floor behavioral idempotence" \
    run_live_agent_floor_fixture
printf '\nfixture divergence\n' >> \
    "$LIVE_HOME/.config/VSCodium/User/settings.json"
divergent_sha=$(sha256sum "$LIVE_HOME/.config/VSCodium/User/settings.json")
assert_cmd_success "Live Agent floor preserves a divergent persistent target" \
    run_live_agent_floor_fixture
assert_eq "$divergent_sha" \
    "$(sha256sum "$LIVE_HOME/.config/VSCodium/User/settings.json")" \
    "divergent persistent VSCodium bytes remain user-owned"
assert_grep_fixed 'liveuser ALL=(ALL) NOPASSWD: ALL' \
    "$LIVE_FIXTURE/etc/sudoers.d/liveuser-nopasswd" \
    "persistent-home divergence cannot suppress Live sudoers"
assert_grep_fixed 'Defaults:liveuser verifypw=any' \
    "$LIVE_FIXTURE/etc/sudoers.d/liveuser-nopasswd" \
    "persistent-home divergence cannot restore passworded Live sudo validation"
assert_eq 2 \
    "$(grep -cEv '^[[:space:]]*(#|$)' \
        "$LIVE_FIXTURE/etc/sudoers.d/liveuser-nopasswd")" \
    "Live sudoers fixture retains the closed two-record schema"
assert_eq "$(id -u):$(id -g):440:1" \
    "$(stat -c '%u:%g:%a:%h' \
        "$LIVE_FIXTURE/etc/sudoers.d/liveuser-nopasswd")" \
    "Live sudoers fixture has exact ownership, mode and link count"
assert_cmd_success "published Live sudoers fixture passes the native parser" \
    visudo -cf "$LIVE_FIXTURE/etc/sudoers.d/liveuser-nopasswd"
assert_grep_fixed 'AutomaticLogin=liveuser' \
    "$LIVE_FIXTURE/etc/gdm/custom.conf" \
    "persistent-home divergence cannot suppress GDM autologin"
assert_grep_fixed 'TimedLoginEnable=true' \
    "$LIVE_FIXTURE/etc/gdm/custom.conf" \
    "persistent-home divergence cannot suppress GDM logout recovery"
assert_grep_fixed 'TimedLogin=liveuser' \
    "$LIVE_FIXTURE/etc/gdm/custom.conf"
assert_grep_fixed 'TimedLoginDelay=1' \
    "$LIVE_FIXTURE/etc/gdm/custom.conf"
assert_grep_fixed '[org/gnome/shell]' \
    "$LIVE_FIXTURE/etc/dconf/db/site.d/10-noid-live-favorites" \
    "Live fixture publishes only the installer favorite group"
assert_grep_fixed 'anaconda.desktop' \
    "$LIVE_FIXTURE/etc/dconf/db/site.d/10-noid-live-favorites" \
    "Live fixture keeps Fedora's installer in the dock"
assert_not_grep 'disable-log-out' \
    "$LIVE_FIXTURE/etc/dconf/db/site.d/10-noid-live-favorites" \
    "Live fixture does not hide Restart or Power Off"
assert_cmd_failure "retired Live logout lock is absent" test -e \
    "$LIVE_FIXTURE/etc/dconf/db/site.d/locks/10-noid-live-session"
# liveuser has no password and the image ships authselect `without-nullok`, so
# a Live lock screen could never be unlocked. The Live-only keyfile must
# therefore disable both the lock and the idle blank, and must stay
# user-writable (not under site.d/locks).
assert_grep_fixed 'lock-enabled=false' \
    "$LIVE_FIXTURE/etc/dconf/db/site.d/10-noid-live-screensaver" \
    "Live fixture disables the unopenable screen lock"
assert_grep_fixed 'idle-delay=uint32 0' \
    "$LIVE_FIXTURE/etc/dconf/db/site.d/10-noid-live-screensaver" \
    "Live fixture disables the idle blank that precedes the lock"
assert_cmd_failure "Live screensaver keyfile is not locked against the user" \
    test -e "$LIVE_FIXTURE/etc/dconf/db/site.d/locks/10-noid-live-screensaver"

# Fedora's optional launcher rename may be absent even though the remaining
# Live convergence is still mandatory. Prove that this degraded path writes
# GDM/screen-lock policy, reaches daemon-reload and exercises the favourites
# cleanup branch instead of exiting the sourced parent.
rm -f -- \
    "$LIVE_FIXTURE/usr/share/applications/anaconda.desktop" \
    "$LIVE_FIXTURE/etc/gdm/custom.conf" \
    "$LIVE_FIXTURE/etc/dconf/db/site.d/10-noid-live-favorites" \
    "$LIVE_FIXTURE/etc/dconf/db/site.d/10-noid-live-screensaver"
: > "$LIVE_SYSTEMCTL_CALLS"
assert_cmd_success "missing optional Live launcher preserves essential convergence" \
    run_live_agent_floor_fixture
assert_grep_fixed 'AutomaticLogin=liveuser' \
    "$LIVE_FIXTURE/etc/gdm/custom.conf" \
    "missing installer launcher cannot suppress GDM auto-login convergence"
assert_grep_fixed 'TimedLogin=liveuser' \
    "$LIVE_FIXTURE/etc/gdm/custom.conf" \
    "missing installer launcher cannot suppress GDM logout recovery"
assert_grep_fixed 'lock-enabled=false' \
    "$LIVE_FIXTURE/etc/dconf/db/site.d/10-noid-live-screensaver" \
    "missing installer launcher cannot restore the unlockable Live screen lock"
assert_cmd_failure "missing installer launcher removes the optional favourite" \
    test -e "$LIVE_FIXTURE/etc/dconf/db/site.d/10-noid-live-favorites"
assert_eq 1 "$(grep -cFx 'daemon-reload' "$LIVE_SYSTEMCTL_CALLS")" \
    "missing installer launcher still reaches the deferred daemon reload"

printf '%s\n' 'outside target remains untouched' > "$LIVE_FIXTURE/outside-target"
rm -f "$LIVE_HOME/.config/VSCodium/User/settings.json"
ln -s "$LIVE_FIXTURE/outside-target" \
    "$LIVE_HOME/.config/VSCodium/User/settings.json"
outside_sha=$(sha256sum "$LIVE_FIXTURE/outside-target")
assert_cmd_success "unsafe persistent target is isolated from livesys parent" \
    run_live_agent_floor_fixture
assert_eq "$outside_sha" "$(sha256sum "$LIVE_FIXTURE/outside-target")" \
    "Live hook never follows a persistent user symlink"
assert_cmd_success "unsafe target remains a symlink" test -L \
    "$LIVE_HOME/.config/VSCodium/User/settings.json"

# Fedora-stock Mutter: GNOME closed MR !5023 after the alternative fix
# a4a851d4 landed in the official 50.3 tag. Keep every retired local-RPM
# integration point absent and exercise provenance in the installed candidate.
MUTTER_RUNTIME="$PROJECT_ROOT/tests/pre-ship/17-mutter-fedora-runtime.sh"
MUTTER_LOGOUT_RUNTIME="$PROJECT_ROOT/tests/pre-ship/17-gnome-shell-logout-runtime.sh"
GREETER_RETIREMENT_RUNTIME="$PROJECT_ROOT/tests/pre-ship/17-greeter-retirement-runtime.sh"
assert_file_executable "$MUTTER_RUNTIME" \
    "Fedora-Mutter installed-candidate gate is executable"
assert_cmd_success "Fedora-Mutter runtime gate parses" bash -n "$MUTTER_RUNTIME"
assert_grep_fixed 'candidate os-release resolves outside candidate root' \
    "$MUTTER_RUNTIME" \
    "offline Mutter gate refuses an os-release symlink escaping its target root"
assert_grep_fixed 'Key ID dbfcf71c6d9f90a6' "$MUTTER_RUNTIME" \
    "Mutter provenance is bound to the Fedora 44 package-signing key"
mutter_escape_root="$MIC_TMP/mutter-escape-root"
mkdir -p "$mutter_escape_root/etc"
ln -s /etc/os-release "$mutter_escape_root/etc/os-release"
mutter_escape_result=$("$MUTTER_RUNTIME" "$mutter_escape_root" 2>&1 || true)
assert_eq \
    "FAIL  17-mutter-fedora-runtime: candidate os-release resolves outside candidate root" \
    "$mutter_escape_result" \
    "offline Mutter gate behaviorally rejects an absolute os-release escape"
assert_file_executable "$MUTTER_LOGOUT_RUNTIME" \
    "GNOME Shell logout/re-login runtime gate is executable"
assert_cmd_success "GNOME Shell logout/re-login runtime gate parses" \
    bash -n "$MUTTER_LOGOUT_RUNTIME"
assert_grep_fixed 'fresh-install:1:prepare|fresh-install:1:verify|fresh-install:2:prepare|fresh-install:2:verify|reboot:1:prepare|reboot:1:verify' \
    "$MUTTER_LOGOUT_RUNTIME" \
    "Shell transition gate permits exactly the three required cycles"
assert_grep_fixed 'ausearch -m ANOM_ABEND --start boot --raw' \
    "$MUTTER_LOGOUT_RUNTIME" \
    "Shell transition gate brackets immutable-audit native crashes"
assert_grep_fixed 'journalctl -b --after-cursor="$cursor" -o json --no-pager' \
    "$MUTTER_LOGOUT_RUNTIME" \
    "Shell transition gate brackets the exact journal interval"
assert_grep_fixed 'incorrect pop' "$MUTTER_LOGOUT_RUNTIME" \
    "Shell transition gate rejects the observed JavaScript precursor"
assert_grep_fixed '[[ $(shell_property Result) == success ]]' \
    "$MUTTER_LOGOUT_RUNTIME" \
    "Shell transition gate requires a successful replacement user unit"
assert_grep_fixed 'loginctl show-session "$session_id" -p LockedHint --value' \
    "$MUTTER_LOGOUT_RUNTIME" \
    "Shell transition gate refuses to bracket a locked session as normal UI logout"
assert_grep_fixed "GNOME's Log Out entry" "$MUTTER_LOGOUT_RUNTIME" \
    "Shell transition gate names the user-visible logout path"
# GNOME 50 does not render that entry on a single-account installation unless
# always-show-log-out is set, so demanding the dialog alone made this gate
# unreachable on a normal candidate. gnome-session-quit calls the identical
# org.gnome.SessionManager.Logout path; loginctl and delayed automation stay
# excluded because they skip the session-manager teardown under test.
assert_grep_fixed 'gnome-session-quit --logout --no-prompt' \
    "$MUTTER_LOGOUT_RUNTIME" \
    "Shell transition gate names the equivalent path for a hidden Log Out entry"
assert_grep_fixed 'state_dir=/run/noid-privacy' "$MUTTER_LOGOUT_RUNTIME" \
    "Shell transition marker stays out of shared writable /var/tmp"
assert_grep_fixed 'root:root:755' "$MUTTER_LOGOUT_RUNTIME" \
    "Shell transition gate authenticates the root-owned runtime parent"
assert_grep_fixed "0:0:600:1" "$MUTTER_LOGOUT_RUNTIME" \
    "Shell transition marker has exact root-only single-link metadata"
assert_not_grep '/var/tmp/noid-f284-shell-' "$MUTTER_LOGOUT_RUNTIME" \
    "Shell transition gate has no predictable shared-directory marker"
assert_file_executable "$GREETER_RETIREMENT_RUNTIME" \
    "pre-user Shell retirement gate is executable"
assert_cmd_success "pre-user Shell retirement gate parses" \
    bash -n "$GREETER_RETIREMENT_RUNTIME"
assert_grep_fixed 'live|fresh-install) BOOTS=(0)' \
    "$GREETER_RETIREMENT_RUNTIME" \
    "pre-user Shell retirement gate audits active Live and fresh-install lifecycles"
assert_grep_fixed 'reboot) BOOTS=(-1 0)' \
    "$GREETER_RETIREMENT_RUNTIME" \
    "pre-user Shell retirement gate binds both sides of the normal reboot"
assert_grep_fixed 'SYSLOG_IDENTIFIER=systemd' \
    "$GREETER_RETIREMENT_RUNTIME" \
    "pre-user Shell gate follows systemd user managers across transient UIDs"
assert_grep_fixed \
    "--grep='org\\.gnome\\.Shell@(gdm|initial-setup)\\.service'" \
    "$GREETER_RETIREMENT_RUNTIME" \
    "manager query remains scoped to both exact Fedora pre-user Shell units"
assert_grep_fixed 'org.gnome.Shell@initial-setup.service' \
    "$GREETER_RETIREMENT_RUNTIME" \
    "fresh-install gate recognizes Fedora's exact Initial Setup Shell unit"
assert_grep_fixed \
    'pass_id == "reboot" and boot_label == "previous"' \
    "$GREETER_RETIREMENT_RUNTIME" \
    "Initial Setup is allowed only on the first installed lifecycle"
assert_grep_fixed 'unexpected_units = observed_units - allowed_units' \
    "$GREETER_RETIREMENT_RUNTIME" \
    "later boots reject a returned Initial Setup Shell"
assert_grep_fixed "grep -qw 'rd.live.image' /proc/cmdline" \
    "$GREETER_RETIREMENT_RUNTIME" \
    "Live retirement gate authenticates the Live boot identity"
assert_grep_fixed "grep -qxF 'AutomaticLogin=liveuser' /etc/gdm/custom.conf" \
    "$GREETER_RETIREMENT_RUNTIME" \
    "Live retirement gate binds the exact automatic-login target"
assert_grep_fixed \
    "'_SYSTEMD_USER_UNIT=org.gnome.Shell@user.service'" \
    "$GREETER_RETIREMENT_RUNTIME" \
    "Live retirement gate retains the exact active automatic-login Shell"
assert_grep_fixed 'pass_id != "live" or boot_label != "current"' \
    "$GREETER_RETIREMENT_RUNTIME" \
    "only the current Live automatic-login boot may omit a pre-user Shell"
assert_grep_fixed 'Live automatic login correctly bypassed the pre-user' \
    "$GREETER_RETIREMENT_RUNTIME" \
    "Live retirement result distinguishes native bypass from missing evidence"
assert_not_grep '_UID="$gdm_uid" SYSLOG_IDENTIFIER=systemd' \
    "$GREETER_RETIREMENT_RUNTIME" \
    "pre-user Shell gate does not bind transient users to the static account UID"
assert_grep_fixed 'greeter_uids = {' "$GREETER_RETIREMENT_RUNTIME" \
    "pre-user Shell gate derives observed transient UIDs"
assert_grep_fixed 'greeter_pids = {' "$GREETER_RETIREMENT_RUNTIME" \
    "pre-user Shell gate derives observed PIDs for crash correlation"
for greeter_failure in 'status=11/segv' "failed with result 'core-dump'" \
        'code=dumped' 'segfault at' 'sig=11' 'anom_abend'; do
    assert_grep_fixed "$greeter_failure" "$GREETER_RETIREMENT_RUNTIME" \
        "pre-user Shell gate rejects native-crash evidence: $greeter_failure"
done
assert_grep_fixed 'and str(row.get("MESSAGE", "")) == "Shutting down GNOME Shell"' \
    "$GREETER_RETIREMENT_RUNTIME" \
    "pre-user Shell gate requires Shell's native shutdown path"
assert_grep_fixed \
    'f"Stopped {unit} - GNOME Shell"' \
    "$GREETER_RETIREMENT_RUNTIME" \
    "pre-user Shell gate requires every observed unit to complete its stop"
for retired_path in \
    "$PROJECT_ROOT/overrides/mutter-mr5023" \
    "$PROJECT_ROOT/scripts/build-mutter-patched.sh" \
    "$PROJECT_ROOT/scripts/audit-mutter-build-log.py" \
    "$PROJECT_ROOT/scripts/noid-mutter-rpm-transaction.sh" \
    "$PROJECT_ROOT/scripts/regen-mutter-rpm-transaction-embed.sh" \
    "$PROJECT_ROOT/tests/00-mutter-build-audit.sh" \
    "$PROJECT_ROOT/tests/17-mutter-transaction-fixture.sh" \
    "$PROJECT_ROOT/tests/pre-ship/17-mutter-mr5023-installed.sh"; do
    assert_cmd_failure "retired Mutter override absent: ${retired_path#"$PROJECT_ROOT"/}" \
        test -e "$retired_path"
done
assert_not_grep_extended 'mutter-mr5023|MR !5023 backport|MUTTER_SIGNING|stage_mutter_backport|build-mutter-patched' \
    "$KS_FILE" "M17 contains no retired Mutter override machinery"
assert_not_grep_extended 'mutter-mr5023|MR !5023 backport|NOID_MUTTER|MUTTER_SIGNING|stage_mutter_backport|build-mutter-patched' \
    "$PROJECT_ROOT/scripts/build-iso.sh" \
    "ISO builder contains no retired Mutter override machinery"

# Step 6c: ordered GNOME-shutdown cleanup, with exact canonical helper bytes.
GNOME_PRIVACY_CONTRACT="$MIC_TMP/gnome-privacy-contract"
extract_heredoc "$KS_FILE" NOID_GNOME_PRIVACY_CONTRACT_EOF \
    "$GNOME_PRIVACY_CONTRACT" || _fail "GNOME privacy contract extraction"
assert_cmd_success "GNOME privacy contract helper parses" \
    bash -n "$GNOME_PRIVACY_CONTRACT"
assert_grep_fixed '*/usr/lib64/gnome-shell/libshell-*.so)' \
    "$GNOME_PRIVACY_CONTRACT" \
    "privacy contract discovers the RPM-owned Shell ABI payload"
assert_grep_fixed 'for state_name in application_state session-active-history.json' \
    "$GNOME_PRIVACY_CONTRACT" \
    "privacy contract owns both current upstream private-state names"
assert_grep_fixed '/usr/bin/rpm -q --dump gnome-shell' \
    "$GNOME_PRIVACY_CONTRACT" \
    "privacy contract authenticates the Shell payload against its RPM record"
assert_grep_fixed 'GNOME Shell payload digest differs from its RPM record' \
    "$GNOME_PRIVACY_CONTRACT" \
    "privacy contract makes installed payload drift fatal"
assert_grep_fixed \
    'post_transaction:gnome-shell:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-verify-gnome-privacy-contract\ >/dev/null' \
    "$KS_FILE" \
    "gnome-shell updates fail visibly if the cleanup schema drifts"

CONTRACT_ROOT="$MIC_TMP/contract-root"
CONTRACT_PAYLOAD="$CONTRACT_ROOT/usr/lib64/gnome-shell/libshell-18.so"
CONTRACT_RPM="$MIC_TMP/rpm-fixture"
CONTRACT_FIXTURE="$MIC_TMP/gnome-privacy-contract.fixture"
mkdir -p "$(dirname "$CONTRACT_PAYLOAD")"
cat > "$CONTRACT_RPM" <<'GNOME_PRIVACY_RPM_FIXTURE_EOF'
#!/bin/bash
case "${1:-}" in
    -ql)
        printf '%s\n' ${GNOME_PRIVACY_FIXTURE_PAYLOADS:?}
        ;;
    -qf)
        printf 'gnome-shell\n'
        ;;
    -q)
        case "${2:-}" in
            --qf)
                printf '50.3-1.fc44\n'
                ;;
            --dump)
                fixture_payload=${GNOME_PRIVACY_FIXTURE_PAYLOADS%% *}
                fixture_size=$(stat -c %s "$fixture_payload")
                fixture_mtime=$(stat -c %Y "$fixture_payload")
                fixture_owner=$(stat -c %U "$fixture_payload")
                fixture_group=$(stat -c %G "$fixture_payload")
                fixture_sha=$(sha256sum "$fixture_payload" | awk '{print $1}')
                if [[ ${GNOME_PRIVACY_FIXTURE_BAD_DIGEST:-0} == 1 ]]; then
                    fixture_sha=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
                fi
                printf '%s %s %s %s 0100755 %s %s 0 0 0 X\n' \
                    "$fixture_payload" "$fixture_size" "$fixture_mtime" "$fixture_sha" \
                    "$fixture_owner" "$fixture_group"
                ;;
            *)
                printf 'gnome-shell-50.3-1.fc44.x86_64\n'
                ;;
        esac
        ;;
    *)
        exit 64
        ;;
esac
GNOME_PRIVACY_RPM_FIXTURE_EOF
chmod 0755 "$CONTRACT_RPM"
sed "s#/usr/bin/rpm#$CONTRACT_RPM#g" \
    "$GNOME_PRIVACY_CONTRACT" > "$CONTRACT_FIXTURE"
chmod 0755 "$CONTRACT_FIXTURE"
printf '%s\n' application_state session-active-history.json \
    > "$CONTRACT_PAYLOAD"
chmod 0755 "$CONTRACT_PAYLOAD"
assert_cmd_success "current GNOME private-state contract is accepted" \
    env GNOME_PRIVACY_FIXTURE_PAYLOADS="$CONTRACT_PAYLOAD" \
    "$CONTRACT_FIXTURE"
assert_cmd_failure "modified Shell payload cannot authenticate as signed state evidence" \
    env GNOME_PRIVACY_FIXTURE_PAYLOADS="$CONTRACT_PAYLOAD" \
        GNOME_PRIVACY_FIXTURE_BAD_DIGEST=1 "$CONTRACT_FIXTURE"
printf '%s\n' application_state > "$CONTRACT_PAYLOAD"
assert_cmd_failure "renamed session history cannot degrade silently" \
    env GNOME_PRIVACY_FIXTURE_PAYLOADS="$CONTRACT_PAYLOAD" \
    "$CONTRACT_FIXTURE"
printf '%s\n' application_state session-active-history.json \
    > "$CONTRACT_PAYLOAD"
CONTRACT_PAYLOAD_SECOND="$CONTRACT_ROOT/usr/lib64/gnome-shell/libshell-19.so"
cp -a "$CONTRACT_PAYLOAD" "$CONTRACT_PAYLOAD_SECOND"
ambiguous_payload_rc=0
ambiguous_payload_output=$(env \
    GNOME_PRIVACY_FIXTURE_PAYLOADS="$CONTRACT_PAYLOAD $CONTRACT_PAYLOAD_SECOND" \
    "$CONTRACT_FIXTURE" 2>&1) || ambiguous_payload_rc=$?
assert_eq 1 "$ambiguous_payload_rc" \
    "ambiguous Shell ABI payload topology is refused"
assert_grep_fixed 'expected exactly one RPM-owned libshell payload; found 2' \
    <(printf '%s\n' "$ambiguous_payload_output") \
    "ambiguity fixture reaches the exact payload-count gate"

extract_heredoc "$KS_FILE" NOID_GNOME_CLEANUP_EOF "$MIC_TMP/cleanup.py" || \
    _fail "GNOME privacy-cleanup helper extraction"
extract_heredoc "$KS_FILE" CLEANUP_SVC_EOF "$MIC_TMP/cleanup.service" || \
    _fail "GNOME privacy-cleanup unit extraction"
sed 's#ExecStart=/usr/local/libexec/noid-gnome-privacy-cleanup#ExecStart=/bin/true#' \
    "$MIC_TMP/cleanup.service" > "$MIC_TMP/cleanup.verify.service"
assert_cmd_success "GNOME cleanup source/embed parity" \
    cmp -s "$CLEANUP_SOURCE" "$MIC_TMP/cleanup.py"
assert_cmd_success "GNOME cleanup helper compiles" python3 -c \
    'import pathlib,sys; p=pathlib.Path(sys.argv[1]); compile(p.read_bytes(), str(p), "exec")' \
    "$MIC_TMP/cleanup.py"
if command -v systemd-analyze >/dev/null 2>&1; then
    assert_cmd_success "GNOME cleanup unit validates" \
        systemd-analyze verify "$MIC_TMP/cleanup.verify.service"
else
    _pass "systemd-analyze unavailable; candidate runtime owns unit validation"
fi
assert_file_executable "$CLEANUP_REGEN" "GNOME cleanup embed generator is executable"
assert_cmd_success "GNOME cleanup embed generator check passes" "$CLEANUP_REGEN" --check
assert_file_executable "$CLEANUP_FIXTURE" "GNOME cleanup behavioral fixture is executable"
assert_file_executable "$CLEANUP_RUNTIME" "three-pass GNOME logout cleanup gate is executable"
assert_cmd_success "GNOME logout cleanup gate parses" bash -n "$CLEANUP_RUNTIME"
assert_file_executable "$FIRSTRUN_RUNTIME" "real-user first-login runtime gate is executable"
assert_cmd_success "first-login runtime gate parses" bash -n "$FIRSTRUN_RUNTIME"
for lifecycle in fresh-install reboot; do
    assert_grep_fixed "$lifecycle" "$FIRSTRUN_RUNTIME" \
        "first-login gate recognizes the $lifecycle pass"
done
assert_grep_fixed 'XDG_SESSION_CLASS=user' "$FIRSTRUN_RUNTIME" \
    "first-login gate probes the user-manager session-class dependency"
assert_not_grep 'show-environment.*[|].*grep.*[|][|][[:space:]]*true' \
    "$FIRSTRUN_RUNTIME" \
    "first-login gate cannot hide a failed manager-environment query"
assert_grep_fixed '-p ConditionResult --value' "$FIRSTRUN_RUNTIME" \
    "first-login gate proves the start condition passed on the live stack"
assert_grep_fixed 'ExecMainStartTimestampMonotonic' "$FIRSTRUN_RUNTIME" \
    "first-login gate binds the successful invocation to the current boot"
assert_grep_fixed 'is-enabled --quiet noid-update-reminder.timer' \
    "$FIRSTRUN_RUNTIME" \
    "first-login gate re-proves the update timer enablement postcondition"
assert_grep_fixed 'is-active --quiet noid-update-reminder.timer' \
    "$FIRSTRUN_RUNTIME" \
    "first-login gate re-proves the update timer activity postcondition"
assert_grep_fixed 'matchpathcon -V "$root_file"' "$FIRSTRUN_RUNTIME" \
    "first-login gate verifies every root-owned payload SELinux boundary"
assert_grep_fixed 'notifier_wants=/usr/lib/systemd/user/graphical-session.target.wants/usbguard-notifier.service' \
    "$FIRSTRUN_RUNTIME" "first-login runtime pins the static notifier link"
assert_grep_fixed '$(readlink "$notifier_wants") == "$notifier"' \
    "$FIRSTRUN_RUNTIME" "first-login runtime requires the exact absolute notifier target"
assert_grep_fixed 'systemctl --user is-active --quiet usbguard-notifier.service' \
    "$FIRSTRUN_RUNTIME" "first-login runtime proves the static notifier active"
assert_grep_fixed 'notifier_result == success' "$FIRSTRUN_RUNTIME" \
    "first-login runtime proves a successful notifier result"
assert_grep_fixed "printf 'version=2\\nstatus=complete\\ntask=%s'" "$FIRSTRUN_RUNTIME" \
    "first-login gate pins the exact v2 marker schema"
assert_grep_fixed '"$EUID:600:1:$expected_size"' "$FIRSTRUN_RUNTIME" \
    "first-login gate authenticates exact marker metadata and byte count"
assert_grep_fixed 'unexpected_state=$(find -P "$state_dir"' "$FIRSTRUN_RUNTIME" \
    "first-login gate rejects surplus transaction state"
assert_grep_fixed 'noid-user-firstrun.done' "$FIRSTRUN_RUNTIME" \
    "first-login gate rejects a lingering v1 sentinel"
assert_grep_fixed 'nautilus_download_sort-v2.done' "$FIRSTRUN_RUNTIME" \
    "first-login runtime expects the Downloads-sort task marker"
assert_grep_fixed 'libvirt_qemu_core-v2.done' "$FIRSTRUN_RUNTIME" \
    "first-login runtime expects the libvirt task marker"
assert_grep_fixed 'max_core is not unique and zero' "$FIRSTRUN_RUNTIME" \
    "first-login runtime proves the session max_core postcondition"
assert_grep_fixed 'dump_guest_core is not unique and zero' "$FIRSTRUN_RUNTIME" \
    "first-login runtime proves the documented guest-memory default"
assert_grep_fixed 'metadata::nautilus-icon-view-sort-by: name' \
    "$FIRSTRUN_RUNTIME" "first-login runtime proves Downloads name sorting"
assert_grep_fixed 'metadata::nautilus-icon-view-sort-reversed: false' \
    "$FIRSTRUN_RUNTIME" "first-login runtime proves Downloads ascending sorting"
assert_file_executable "$SESSION_RUNTIME" \
    "Live/logout/notifier lifecycle runtime gate is executable"
assert_cmd_success "session lifecycle runtime gate parses" bash -n "$SESSION_RUNTIME"
for lifecycle_pair in live:initial fresh-install:initial \
        fresh-install:second-login reboot:initial reboot:second-login; do
    assert_grep_fixed "$lifecycle_pair" "$SESSION_RUNTIME" \
        "session lifecycle gate recognizes $lifecycle_pair"
done
assert_grep_fixed 'TimedLoginEnable=true' "$SESSION_RUNTIME" \
    "runtime gate checks the native Live logout recovery"
assert_grep_fixed 'CanPowerOff' "$SESSION_RUNTIME" \
    "runtime gate checks the effective Live power capability"
assert_grep_fixed 'usbguard-notifier --wait' "$SESSION_RUNTIME" \
    "runtime gate binds the actual long-running notifier argv"
assert_grep_fixed '0::$control_group' "$SESSION_RUNTIME" \
    "runtime gate binds the notifier PID to the effective unit control group"
assert_grep_fixed 'notifier_uid == "$UID"' "$SESSION_RUNTIME" \
    "runtime gate binds the notifier PID to the invoking user"
assert_grep_fixed 'root:root:644:1' "$SESSION_RUNTIME" \
    "runtime gate authenticates exact root-owned single-link unit metadata"
assert_grep_fixed 'matchpathcon -V "$root_file"' "$SESSION_RUNTIME" \
    "runtime gate verifies every root-owned unit/helper SELinux boundary"
assert_grep_fixed 'gdm_daemon_value' "$SESSION_RUNTIME" \
    "Live GDM values are parsed from the exact daemon section"
GDM_RUNTIME_PARSER="$MIC_TMP/session-gdm-parser.sh"
awk '
    /^    gdm_daemon_value\(\) \{$/ { capture=1 }
    capture {
        raw=$0
        sub(/^    /, "")
        print
        if (raw == "    }") exit
    }
' "$SESSION_RUNTIME" > "$GDM_RUNTIME_PARSER"
run_gdm_runtime_parser_fixture() {
    bash -s -- "$GDM_RUNTIME_PARSER" "$MIC_TMP/session-gdm-parser.conf" <<'GDM_RUNTIME_PARSER_EOF'
set -euo pipefail
parser=$1
gdm_config=$2
. "$parser"
printf '%s\n' \
    '[security]' \
    'AutomaticLoginEnable=false' \
    '[daemon]' \
    'AutomaticLoginEnable=true' > "$gdm_config"
[[ $(gdm_daemon_value AutomaticLoginEnable) == true ]]
printf '%s\n' \
    '[daemon]' \
    'TimedLoginEnable=true' \
    'TimedLoginEnable=false' > "$gdm_config"
if gdm_daemon_value TimedLoginEnable >/dev/null; then
    exit 1
fi
GDM_RUNTIME_PARSER_EOF
}
assert_cmd_success \
    "Live GDM parser scopes values to daemon and rejects ambiguity" \
    run_gdm_runtime_parser_fixture
assert_grep_fixed 'old_session != "$session_id"' "$SESSION_RUNTIME" \
    "second-login proof requires a distinct session identity"
assert_grep_fixed 'marker_root=/var/tmp/noid-pre-ship-session-$UID' "$SESSION_RUNTIME" \
    "session evidence is nested below one private user-owned marker root"
assert_grep_fixed 'mkdir -- "$marker_dir"' "$SESSION_RUNTIME" \
    "initial-session evidence gains an atomic private directory"
assert_not_grep 'marker=/var/tmp/noid-pre-ship-session-${UID}-${PASS_ID}' \
    "$SESSION_RUNTIME" \
    "session gate never opens the retired predictable shared-directory file"
assert_grep_fixed 'loginctl show-user "$UID" -p Display --value' "$SESSION_RUNTIME" \
    "session selection uses logind's authoritative primary graphical display"
assert_grep_fixed '[[ $session_uid == "$UID" ]]' "$SESSION_RUNTIME" \
    "primary display must belong to the invoking normal user"
assert_grep_fixed '[[ $session_type =~ ^(wayland|x11)$ ]]' "$SESSION_RUNTIME" \
    "primary display must be an actual graphical session"
assert_grep_fixed '[[ $session_remote == no ]]' "$SESSION_RUNTIME" \
    "primary display must be local"
assert_grep_fixed '[[ $session_active == yes && $session_state == active ]]' \
    "$SESSION_RUNTIME" "primary display must be foreground-active"

SESSION_SELECTOR_FIXTURE="$MIC_TMP/session-selector.sh"
awk '
    /^# NOID_USER_SESSION_SELECTOR_BEGIN$/ { capture = 1; next }
    /^# NOID_USER_SESSION_SELECTOR_END$/ { capture = 0 }
    capture { print }
' "$SESSION_RUNTIME" > "$SESSION_SELECTOR_FIXTURE"
assert_file_min_size "$SESSION_SELECTOR_FIXTURE" 1 \
    "session selector fixture extracted from the runtime gate"

run_session_selector_fixture() {
    bash -s -- "$SESSION_SELECTOR_FIXTURE" <<'NOID_SESSION_SELECTOR_FIXTURE_EOF'
selector=$1
fail() { printf 'unexpected selector failure: %s\n' "$*" >&2; exit 1; }
loginctl() {
    if [[ $1 == show-user && $2 == "$UID" && $3 == -p \
          && $4 == Display && $5 == --value ]]; then
        printf 'graphical\n'
        return 0
    fi
    if [[ $1 == show-session && $2 == graphical && $3 == -p \
          && $5 == --value ]]; then
        case $4 in
            User) printf '%s\n' "$UID" ;;
            Class) printf 'user\n' ;;
            Type) printf 'wayland\n' ;;
            Remote) printf 'no\n' ;;
            Active) printf 'yes\n' ;;
            State) printf 'active\n' ;;
            *) return 98 ;;
        esac
        return 0
    fi
    return 97
}
. "$selector"
[[ $session_id == graphical ]]
NOID_SESSION_SELECTOR_FIXTURE_EOF
}

run_session_selector_failure_fixture() {
    bash -s -- "$SESSION_SELECTOR_FIXTURE" <<'NOID_SESSION_SELECTOR_FAILURE_EOF'
selector=$1
fail() { printf 'expected selector failure: %s\n' "$*" >&2; exit 1; }
loginctl() {
    if [[ $1 == show-user && $2 == "$UID" && $3 == -p \
          && $4 == Display && $5 == --value ]]; then
        printf 'serial\n'
        return 0
    fi
    if [[ $1 == show-session && $2 == serial && $3 == -p \
          && $5 == --value ]]; then
        case $4 in
            User) printf '%s\n' "$UID" ;;
            Class) printf 'user\n' ;;
            Type) printf 'tty\n' ;;
            Remote) printf 'no\n' ;;
            Active) printf 'yes\n' ;;
            State) printf 'active\n' ;;
            *) return 98 ;;
        esac
        return 0
    fi
    return 97
}
. "$selector"
NOID_SESSION_SELECTOR_FAILURE_EOF
}

assert_cmd_success \
    "session selector accepts logind's exact primary graphical display" \
    run_session_selector_fixture
assert_cmd_failure \
    "session selector rejects a non-graphical primary session" \
    run_session_selector_failure_fixture
CLEANUP_SESSION_SELECTOR_FIXTURE="$MIC_TMP/cleanup-session-selector.sh"
awk '
    /^# NOID_USER_SESSION_SELECTOR_BEGIN$/ { capture = 1; next }
    /^# NOID_USER_SESSION_SELECTOR_END$/ { capture = 0 }
    capture { print }
' "$CLEANUP_RUNTIME" > "$CLEANUP_SESSION_SELECTOR_FIXTURE"
assert_cmd_success \
    "logout cleanup and lifecycle gates share one graphical-session selector" \
    cmp -s "$SESSION_SELECTOR_FIXTURE" "$CLEANUP_SESSION_SELECTOR_FIXTURE"
for lifecycle in live fresh-install reboot; do
    assert_grep_fixed "$lifecycle:prepare" "$CLEANUP_RUNTIME" \
        "GNOME cleanup gate recognizes $lifecycle prepare"
    assert_grep_fixed "$lifecycle:verify" "$CLEANUP_RUNTIME" \
        "GNOME cleanup gate recognizes $lifecycle verify"
done
assert_grep_fixed 'firefox-legacy-profiles.preexisting' "$CLEANUP_RUNTIME" \
    "logout gate records whether it created the behaviorally significant legacy profile root"
assert_grep_fixed 'remove_test_created_empty_parent' "$CLEANUP_RUNTIME" \
    "logout gate restores only test-created empty Mozilla parents"
assert_grep_fixed '--after-cursor="$cursor"' "$CLEANUP_RUNTIME" \
    "logout gate binds success evidence to its exact pre-logout journal cursor"
assert_grep_fixed 'prepared_boot == "$current_boot"' "$CLEANUP_RUNTIME" \
    "logout gate rejects a reboot between prepare and verify"
assert_grep_fixed 'prepared_session != "$session_id"' "$CLEANUP_RUNTIME" \
    "logout gate requires a distinct graphical session identity"
assert_not_grep 'prepared-epoch' "$CLEANUP_RUNTIME" \
    "logout gate carries no second-granularity timestamp marker"
assert_not_grep '--since "@' "$CLEANUP_RUNTIME" \
    "logout gate carries no second-granularity stale-success query"
assert_grep_fixed 'remove_exact_profile_canary' "$CLEANUP_RUNTIME" \
    "logout gate removes only the exact validated Mozilla canary entries"
assert_not_grep 'rm -rf -- "$ff_dir" "$tb_dir"' "$CLEANUP_RUNTIME" \
    "logout gate never recursively deletes a profile-canary directory"
assert_not_grep_extended \
    'rm -rf -- .*("\$HOME/\.mozilla"|"\$ff_legacy_(root|profiles)"|"\$tb_root")' \
    "$CLEANUP_RUNTIME" \
    "logout gate never recursively removes a Mozilla parent"

run_cleanup_parent_restore_fixture() {
    bash -s -- "$CLEANUP_RUNTIME" <<'CLEANUP_PARENT_FIXTURE_EOF'
set -euo pipefail
runtime=$1
root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT
fail() { printf 'fixture failure: %s\n' "$*" >&2; exit 1; }
. <(
    awk '
        /^remove_test_created_empty_parent\(\) \{/ { capture=1 }
        capture { print }
        capture && /^}$/ { exit }
    ' "$runtime"
)

mkdir -p "$root/new/.mozilla/firefox" "$root/new/state"
remove_test_created_empty_parent \
    "$root/new/.mozilla/firefox" "$root/new/state/firefox.preexisting" \
    "new Firefox profile root"
remove_test_created_empty_parent \
    "$root/new/.mozilla" "$root/new/state/mozilla.preexisting" \
    "new Mozilla root"
[[ ! -e $root/new/.mozilla ]]

mkdir -p "$root/existing/.mozilla/firefox" "$root/existing/state"
printf '%s\n' preexisting > "$root/existing/state/firefox.preexisting"
remove_test_created_empty_parent \
    "$root/existing/.mozilla/firefox" \
    "$root/existing/state/firefox.preexisting" \
    "existing Firefox profile root"
[[ -d $root/existing/.mozilla/firefox ]]

mkdir -p "$root/nonempty/.mozilla/firefox" "$root/nonempty/state"
printf '%s\n' keep > "$root/nonempty/.mozilla/firefox/keep"
remove_test_created_empty_parent \
    "$root/nonempty/.mozilla/firefox" \
    "$root/nonempty/state/firefox.preexisting" \
    "non-empty Firefox profile root"
[[ -f $root/nonempty/.mozilla/firefox/keep ]]

mkdir -p "$root/symlink/target" "$root/symlink/state"
ln -s "$root/symlink/target" "$root/symlink/firefox"
if (
    remove_test_created_empty_parent \
        "$root/symlink/firefox" "$root/symlink/state/firefox.preexisting" \
        "symlinked Firefox profile root"
); then
    exit 1
fi
CLEANUP_PARENT_FIXTURE_EOF
}

assert_cmd_success \
    "logout gate restores absence, preserves prior/non-empty parents and rejects symlinks" \
    run_cleanup_parent_restore_fixture
assert_grep_fixed 'RESOLVE_NO_XDEV' "$MIC_TMP/cleanup.py" \
    "cleanup rejects mount-boundary traversal"
assert_grep_fixed 'RESOLVE_NO_SYMLINKS' "$MIC_TMP/cleanup.py" \
    "cleanup rejects symlinked path components"
assert_grep_fixed '_preflight_tree(tree_fd, label)' "$MIC_TMP/cleanup.py" \
    "cleanup preflights the complete tree before mutation"
assert_grep_fixed 'os.rename(' "$MIC_TMP/cleanup.py" \
    "cleanup detaches the exact thumbnail inode before recursion"
assert_grep_fixed 'entry.name.startswith(QUARANTINE_PREFIX)' "$MIC_TMP/cleanup.py" \
    "cleanup resumes an interrupted exact quarantine"
assert_grep_fixed 'DefaultDependencies=no' "$MIC_TMP/cleanup.service" \
    "cleanup participates in GNOME's shutdown transaction"
assert_grep_fixed 'Slice=-.slice' "$MIC_TMP/cleanup.service" \
    "shutdown helper remains runnable while session slices stop"
assert_grep_fixed 'Before=gnome-session-shutdown.target gnome-session-restart-dbus.service' \
    "$MIC_TMP/cleanup.service" "cleanup completes before target and D-Bus restart"
assert_grep_fixed 'ExecStart=/usr/local/libexec/noid-gnome-privacy-cleanup' \
    "$MIC_TMP/cleanup.service" "cleanup is an explicit shutdown action"
assert_grep_fixed 'WantedBy=gnome-session-shutdown.target' "$MIC_TMP/cleanup.service" \
    "cleanup is activated by GNOME's real shutdown target"
assert_grep_fixed '/etc/systemd/user/gnome-session-shutdown.target.wants' "$KS_FILE" \
    "cleanup has the exact global shutdown-target link"
assert_not_grep_extended '^ExecStop=|PartOf=graphical-session.target' \
    "$MIC_TMP/cleanup.service" "cleanup has no racing graphical-target stop hook"
assert_not_grep_extended '\.thunderbird|\.parentlock|\.mozilla/firefox|\.config/mozilla/firefox' \
    "$MIC_TMP/cleanup.py" "cleanup never touches Mozilla profile locks"
assert_not_grep_extended 'rm -rf.*thumbnails|ExecStop=.*thumbnails' "$KS_FILE" \
    "unsafe wildcard thumbnail deletion is absent"

# JIT disablement remains an evidence-bounded, application-overridable default.
assert_grep_fixed 'JavaScriptCoreUseJIT=0' "$KS_FILE" \
    "WebKitGTK JIT-disable default remains selected"
assert_grep_fixed 'GJS_DISABLE_JIT=1' "$KS_FILE" \
    "GJS JIT-disable default remains selected"
assert_grep_fixed "root:root:644:1" "$JIT_RUNTIME" \
    "JIT runtime gate authenticates exact single-link policy metadata"
assert_grep_fixed 'matchpathcon -V "$jit_env"' "$JIT_RUNTIME" \
    "JIT runtime gate verifies the environment-file SELinux boundary"
assert_grep_fixed \
    'JavaScriptCoreUseJIT=0\nGJS_DISABLE_JIT=1' "$JIT_RUNTIME" \
    "JIT runtime gate permits exactly the two active assignments"
assert_grep_fixed '[ "$jit_active" != $'\''JavaScriptCoreUseJIT=0\nGJS_DISABLE_JIT=1'\'' ]' \
    "$KS_FILE" "M17 compose verification rejects every surplus JIT assignment"
assert_grep_fixed 'does not make either engine memory-safe' "$KS_FILE" \
    "JIT disablement is not misrepresented as memory safety"
assert_grep_fixed 'application- and workload-specific' "$KS_FILE" \
    "JIT cost is scoped to the actual application and workload"
assert_grep_fixed 'release gate proves effective tier state, not a universal latency number' \
    "$KS_FILE" "runtime validation is not misrepresented as a benchmark"
assert_grep_fixed 'env -u GJS_DISABLE_JIT gjs-application' "$KS_FILE" \
    "GJS per-launch recovery is documented"
assert_grep_fixed 'env JavaScriptCoreUseJIT=1 webkit-application' "$KS_FILE" \
    "WebKitGTK per-launch recovery is documented"
assert_not_grep_extended \
    'JIT-spray attack surface|slower interpreted JS in UI workloads — acceptable|generated-code (path|surface|primitive)|1\.68|1\.94|1843|38x|Five-run' \
    "$KS_FILE" "retired unbounded or unrepeatable JIT claims are absent"
assert_file_executable "$JIT_RUNTIME" "three-pass JIT behavior gate is executable"
assert_cmd_success "JIT runtime gate parses" bash -n "$JIT_RUNTIME"
for lifecycle in live fresh-install reboot; do
    assert_grep_fixed "$lifecycle)" "$JIT_RUNTIME" \
        "JIT runtime gate recognizes $lifecycle"
done
assert_grep_fixed "GJS_DEBUG_TOPICS='JS CTX'" "$JIT_RUNTIME" \
    "JIT gate observes GJS's maintained runtime diagnostic"
assert_grep_fixed 'JSC_dumpOptions=3' "$JIT_RUNTIME" \
    "JIT gate observes JavaScriptCore's effective tier state"

# Strict Wayland selection remains an honest, application-overridable default.
assert_grep_fixed 'GDK_BACKEND=wayland' "$KS_FILE" \
    "GTK strict native-Wayland default remains selected"
assert_grep_fixed 'QT_QPA_PLATFORM=wayland' "$KS_FILE" \
    "Qt strict native-Wayland default remains selected"
assert_grep_fixed 'compatibility default, not a security boundary' "$KS_FILE" \
    "Wayland environment selection is not misrepresented as enforcement"
assert_grep_fixed 'Qt:  env QT_QPA_PLATFORM=xcb application' "$KS_FILE" \
    "Qt xcb recovery is documented"
assert_grep_fixed 'application -platform xcb' "$KS_FILE" \
    "Qt command-line precedence recovery is documented"
assert_grep_fixed 'GTK: env GDK_BACKEND=x11 application' "$KS_FILE" \
    "GTK X11 recovery is documented"
assert_grep_fixed 'Xwayland remains' "$KS_FILE" \
    "Xwayland compatibility boundary is explicit"
assert_grep_fixed "gsettings get org.gnome.mutter experimental-features" \
    "$WAYLAND_RUNTIME" \
    "runtime gate checks the effective empty Mutter feature set"
assert_grep_fixed 'NameHasOwner org.gnome.Shell' "$WAYLAND_RUNTIME" \
    "runtime gate proves GNOME survives the real X11 client lifecycle"
assert_grep_fixed 'gtk_x11_again=' "$WAYLAND_RUNTIME" \
    "runtime gate reopens a second real X11 client after the first teardown"
assert_eq 2 "$(grep -cF 'GDK_BACKEND=x11 /usr/bin/python3 -c "$gtk_probe"' \
    "$WAYLAND_RUNTIME")" \
    "runtime gate executes exactly two successive GTK X11 client lifecycles"
assert_grep_fixed 'gtk_after_x11=' "$WAYLAND_RUNTIME" \
    "runtime gate reopens native Wayland after the X11 client exits"
assert_not_grep_extended 'Wayland enforcement|env-injection downgrade|downgrade-to-XWayland|XWayland CVE' \
    "$KS_FILE" "retired Wayland security-boundary hype is absent"
assert_file_executable "$WAYLAND_RUNTIME" "three-pass Wayland default gate is executable"
assert_cmd_success "Wayland default runtime gate parses" bash -n "$WAYLAND_RUNTIME"
for lifecycle in live fresh-install reboot; do
    assert_grep_fixed "$lifecycle)" "$WAYLAND_RUNTIME" \
        "Wayland runtime gate recognizes $lifecycle"
done
assert_grep_fixed '[[ $QT_QPA_PLATFORM == wayland ]]' "$WAYLAND_RUNTIME" \
    "runtime gate requires one exact Qt platform selector"
assert_grep_fixed 'policy=/etc/environment.d/45-noid-wayland.conf' \
    "$WAYLAND_RUNTIME" \
    "runtime gate authenticates the root-owned Wayland policy source"
assert_grep_fixed 'root:root:644:1' "$WAYLAND_RUNTIME" \
    "runtime gate requires exact single-link policy metadata"
assert_grep_fixed 'matchpathcon -V "$root_file"' "$WAYLAND_RUNTIME" \
    "runtime gate verifies policy and executable SELinux boundaries"
assert_grep_fixed 'manager_setting=$(manager_value "$environment_name")' \
    "$WAYLAND_RUNTIME" \
    "runtime gate binds caller selectors and endpoints to the user manager"
assert_grep_fixed '"unix:path=$XDG_RUNTIME_DIR/bus"' "$WAYLAND_RUNTIME" \
    "runtime gate binds the user bus to the private session runtime root"
assert_grep_fixed 'package_release == *.fc44' "$WAYLAND_RUNTIME" \
    "runtime gate binds all four named probe packages to Fedora 44"
assert_grep_fixed 'key id $fedora_key' "$WAYLAND_RUNTIME" \
    "runtime gate authenticates probe packages with Fedora's release key"
assert_grep_fixed 'rpm -V qt5-qtwayland keepassxc python3-gobject gtk4' \
    "$WAYLAND_RUNTIME" \
    "runtime gate rejects drift in every graphical probe package"
assert_grep_fixed 'stat -c '\''%u:%h'\'' "$wayland_socket"' "$WAYLAND_RUNTIME" \
    "runtime gate authenticates the active user-owned Wayland socket"
assert_grep_fixed '"$UID:600:1"' "$WAYLAND_RUNTIME" \
    "runtime gate authenticates the exact Xwayland authority file"
assert_grep_fixed 'QT_FORCE_STDERR_LOGGING=1 WAYLAND_DEBUG=client' \
    "$WAYLAND_RUNTIME" "runtime gate observes a real Qt Wayland handshake"
assert_grep_fixed ' -> wl_display#[0-9]+[.]get_registry' "$WAYLAND_RUNTIME" \
    "runtime gate proves KeePassXC reached the native Wayland protocol"
assert_not_grep_extended 'WAYLAND_DISPLAY=[^[:space:]]+[[:space:]]+keepassxc' \
    "$WAYLAND_RUNTIME" \
    "Wayland gate never creates an immutable-audit Qt crash as negative evidence"

# The system-administrator MIME tier must resolve plain and empty text files to
# Fedora's lightweight native editor without mutating package-owned metadata.
MIME_DEFAULTS="$GS_DBUS.mime"
extract_heredoc "$KS_FILE" MIMEAPPS_EOF "$MIME_DEFAULTS"
assert_eq $'[Default Applications]\napplication/x-zerosize=org.gnome.TextEditor.desktop;\ntext/plain=org.gnome.TextEditor.desktop;' \
    "$(cat "$MIME_DEFAULTS")" \
    "plain and empty text files have one exact native-editor default"
assert_grep_fixed 'MIME_DEFAULTS=/etc/xdg/mimeapps.list' "$KS_FILE" \
    "M17 verifies the XDG administrator MIME tier"
assert_grep_fixed 'TEXT_EDITOR_DESKTOP=/usr/share/applications/org.gnome.TextEditor.desktop' \
    "$KS_FILE" "M17 binds the default to Fedora's installed desktop entry"
assert_grep_fixed 'desktop-file-validate "$TEXT_EDITOR_DESKTOP"' "$KS_FILE" \
    "M17 validates the target desktop payload"
assert_grep_fixed "grep -qE '^MimeType=([^;]+;)*text/plain;'" "$KS_FILE" \
    "M17 verifies the native editor advertises text/plain"
assert_grep_fixed "grep -qE '^MimeType=([^;]+;)*application/x-zerosize;'" "$KS_FILE" \
    "M17 verifies the native editor advertises empty files"
assert_not_grep_extended 'text/plain=codium\.desktop|application/x-zerosize=codium\.desktop' \
    "$KS_FILE" "VSCodium is never made the plain-text system default"

test_finish
