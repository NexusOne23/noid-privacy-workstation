#!/bin/bash
# 24-fwupd-structural — M24 regression test
#
# Covers: lvfs remote configs, exact no-report/P2P posture, on-demand installed
# daemon, background refresh/P2P masks and the three-pass Silent Machine gate.
# Would catch: background activation, persistent firmware-daemon regression,
# manual Update All path loss, reintroduction of motd writes or missing privacy
# controls.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/24-firmware-fwupd.ks"
SILENT_RUNTIME="$PROJECT_ROOT/tests/pre-ship/24-silent-update-runtime.sh"
TEST_TMPDIR=$(mktemp -d)
trap 'rm -rf "$TEST_TMPDIR"' EXIT

test_start "24-fwupd-structural"

assert_file_exists "$KS_FILE"
assert_cmd_success "bash -n $KS_FILE" bash -n "$KS_FILE"
FWUPD_DOC="$TEST_TMPDIR/24-firmware-updates.md"
if extract_heredoc "$KS_FILE" DOC_EOF "$FWUPD_DOC"; then
    _pass "deployed fwupd documentation payload extracts"
else
    _fail "deployed fwupd documentation payload extracts"
fi
FWUPD_CONF="$TEST_TMPDIR/fwupd.conf"
if extract_heredoc "$KS_FILE" FWUPDCONF_EOF "$FWUPD_CONF"; then
    _pass "deployed fwupd daemon configuration extracts"
else
    _fail "deployed fwupd daemon configuration extracts"
fi
FWUPD_STATE_DROPIN="$TEST_TMPDIR/97-noid-state-privacy.conf"
if extract_heredoc "$KS_FILE" FWUPD_STATE_EOF "$FWUPD_STATE_DROPIN"; then
    _pass "deployed fwupd state privacy drop-in extracts"
else
    _fail "deployed fwupd state privacy drop-in extracts"
fi
assert_eq \
    $'# NoID Privacy — keep local firmware and HSI history root-only\n[Service]\nStateDirectoryMode=0700' \
    "$(<"$FWUPD_STATE_DROPIN")" \
    "fwupd state privacy drop-in is the exact minimal native override"
assert_not_grep_fixed 'StateDirectoryMode=0755' "$FWUPD_STATE_DROPIN" \
    "deployed override cannot reopen local firmware history"
FWUPD_STABLE="$TEST_TMPDIR/lvfs.conf"
if extract_heredoc "$KS_FILE" LVFS_EOF "$FWUPD_STABLE"; then
    _pass "deployed LVFS stable remote configuration extracts"
else
    _fail "deployed LVFS stable remote configuration extracts"
fi
FWUPD_TESTING="$TEST_TMPDIR/lvfs-testing.conf"
if extract_heredoc "$KS_FILE" LVFSTEST_EOF "$FWUPD_TESTING"; then
    _pass "deployed LVFS testing remote configuration extracts"
else
    _fail "deployed LVFS testing remote configuration extracts"
fi
FWUPD_EMBARGO="$TEST_TMPDIR/lvfs-embargo.conf"
if extract_heredoc "$KS_FILE" LVFSEMBARGO_EOF "$FWUPD_EMBARGO"; then
    _pass "deployed LVFS embargo remote configuration extracts"
else
    _fail "deployed LVFS embargo remote configuration extracts"
fi

# Three network remotes (stable, testing, embargo) + local vendor directory
# ownership statement + main fwupd.conf.
assert_grep_fixed "/etc/fwupd/remotes.d/lvfs.conf" "$KS_FILE"
assert_grep_fixed "/etc/fwupd/remotes.d/lvfs-testing.conf" "$KS_FILE"
assert_grep_fixed "/etc/fwupd/remotes.d/lvfs-embargo.conf" "$KS_FILE"
assert_grep_fixed 'local file:/// source' "$KS_FILE" \
    "vendor-directory is consciously retained as a local-only remote"
assert_grep_fixed "/etc/fwupd/fwupd.conf" "$KS_FILE"

# Heredoc markers
assert_grep_fixed 'LVFS_EOF' "$KS_FILE"
assert_grep_fixed 'LVFSTEST_EOF' "$KS_FILE"
assert_grep_fixed 'LVFSEMBARGO_EOF' "$KS_FILE"
assert_grep_fixed 'FWUPDCONF_EOF' "$KS_FILE"

# Hardening posture: UpdateMotd off (AIDE-noise mitigation)
assert_grep_extended 'UpdateMotd\s*=\s*false' "$KS_FILE"

# Hardening posture: P2P publishing disabled; passim is separately masked so
# no local cache service can be activated or contacted.
assert_grep_fixed 'P2pPolicy=nothing' "$KS_FILE"
for remote_config in "$FWUPD_STABLE" "$FWUPD_TESTING" "$FWUPD_EMBARGO"; do
    assert_grep_extended '^AutomaticReports=false$' "$remote_config" \
        "owned remote disables automatic firmware reports"
    assert_grep_extended '^AutomaticSecurityReports=false$' "$remote_config" \
        "owned remote disables automatic HSI reports"
    assert_not_grep_extended '^[[:space:]]*ReportURI[[:space:]]*=' \
        "$remote_config" "owned remote has no active reporting endpoint"
done
assert_grep_extended '^Enabled=true$' "$FWUPD_STABLE" \
    "stable firmware remote remains enabled"
assert_grep_extended '^Enabled=false$' "$FWUPD_TESTING" \
    "testing firmware remote remains disabled"
assert_grep_extended '^ShowDevicePrivate=false$' "$FWUPD_CONF" \
    "deployed daemon configuration suppresses private device metadata"
assert_not_grep_extended '^ShowDevicePrivate=true$' "$FWUPD_CONF" \
    "deployed daemon configuration cannot expose private device metadata"
assert_grep_fixed 'DisabledPlugins=redfish;android_boot' "$FWUPD_CONF" \
    "desktop image disables exactly the inapplicable server and Android Boot plugins"
assert_not_grep 'DisabledPlugins=redfish,android_boot' "$FWUPD_CONF" \
    "fwupd plugin list does not use an invalid comma delimiter"
assert_grep_fixed 'it is unrelated to Android Studio, ADB and the' "$FWUPD_DOC" \
    "Android Boot firmware scope is separated from development and emulation"
assert_grep_fixed 'Enabled=false' "$FWUPD_EMBARGO" \
    "embargo remote remains explicitly disabled"
assert_grep_fixed 'AutomaticReports=false' "$FWUPD_EMBARGO" \
    "embargo remote cannot automatically report firmware results"
assert_grep_fixed 'AutomaticSecurityReports=false' "$FWUPD_EMBARGO" \
    "embargo remote cannot automatically report HSI data"
assert_not_grep_extended '^[[:space:]]*ReportURI=' "$FWUPD_EMBARGO" \
    "embargo remote has no reporting endpoint"
assert_grep_fixed 'lvfs-embargo.conf: exact metadata + disabled reporting' \
    "$KS_FILE" "compose verifies the embargo remote privacy boundary"
for remote_name in lvfs lvfs-testing lvfs-embargo vendor-directory; do
    assert_grep_fixed "/var/lib/fwupd/remotes.d/${remote_name}.conf" \
        "$KS_FILE" "compose removes stale mutable $remote_name override"
done
assert_not_grep 'mkdir -p /etc/fwupd/remotes.d' "$KS_FILE" \
    "compose never follows a redirected fwupd directory before validation"
assert_grep_fixed 'verify_safe_root_dir()' "$KS_FILE" \
    "compose has one root-owned non-writable directory-boundary verifier"
assert_grep_fixed \
    'for config_dir in /etc/fwupd /etc/fwupd/remotes.d; do' \
    "$KS_FILE" "compose rejects redirected configuration directories"
assert_grep_fixed \
    'for mutable_dir in /var/lib/fwupd /var/lib/fwupd/remotes.d; do' \
    "$KS_FILE" "compose rejects redirected mutable directories"
assert_grep_fixed 'unexpected mutable remote definition:' "$KS_FILE" \
    "compose fails if any higher-priority mutable remote survives"
assert_grep_fixed 'effective remote source-file inventory differs' "$KS_FILE" \
    "compose fails closed on an unexpected /etc remote"
assert_grep_fixed 'install -d -m 0700 -o root -g root -- /var/lib/fwupd' \
    "$KS_FILE" "compose restores the packaged root-only fwupd state boundary"
assert_grep_fixed \
    '/etc/systemd/system/fwupd.service.d/97-noid-state-privacy.conf' \
    "$KS_FILE" "M24 owns the native fwupd state-mode drop-in"
assert_grep_fixed 'StateDirectoryMode=0700' "$KS_FILE" \
    "systemd cannot relax firmware and HSI history to its 0755 default"
assert_not_grep_fixed \
    'systemctl show fwupd.service -p StateDirectoryMode --value' \
    "$KS_FILE" "offline compose never queries a target service manager"
assert_grep_fixed 'fwupd firmware/HSI state remains root-only 0700' \
    "$KS_FILE" "compose records the effective state privacy postcondition"
assert_grep_fixed 'systemctl daemon-reload' "$KS_FILE" \
    "compose reloads unit definitions after payload changes"
assert_grep_fixed 'EXPECTED_REMOTE_FILES=' "$KS_FILE" \
    "compose defines the complete four-remote source inventory"
assert_grep_fixed 'FWUPD_MIN_VERSION=2.1.7' "$KS_FILE" \
    "compose requires the first fwupd release with complete OnlyTrusted enforcement"
assert_grep_fixed \
    'rpm.vercmp(os.getenv("FWUPD_VERSION_CANDIDATE"), os.getenv("FWUPD_MIN_VERSION_CANDIDATE"))' \
    "$KS_FILE" "compose compares the installed fwupd version with RPM semantics"
assert_grep_fixed 'below required ${FWUPD_MIN_VERSION}' "$KS_FILE" \
    "compose refuses an older fwupd instead of overstating trust"
assert_not_grep 'updates-testing' "$FWUPD_DOC" \
    "deployed guidance never routes users to Fedora updates-testing"
assert_grep_fixed 'fwupd-efi' "$KS_FILE" \
    "M24 explicitly installs the Recommends-only capsule package"
assert_grep_fixed 'FWUPD_EFI_PAYLOAD=/usr/libexec/fwupd/efi/fwupdx64.efi.signed' \
    "$KS_FILE" "compose names the load-bearing UEFI capsule payload"
assert_grep_fixed "rpm -qf --qf '%{NAME}' \"\$FWUPD_EFI_PAYLOAD\"" \
    "$KS_FILE" "compose verifies capsule payload package ownership"
assert_grep_fixed 'fwupd-efi package + exact owned UEFI capsule payload present' \
    "$KS_FILE" "compose records the complete capsule postcondition"
assert_grep_fixed 'Historical fwupd#8254' "$KS_FILE" \
    "passim rationale marks the superseded upstream bug as historical"
assert_grep_fixed 'upstream PR #8286 fixed that on 2025-01-08' "$KS_FILE" \
    "passim rationale records the primary-source fix date"
assert_not_grep 'Known bug: fwupd connects to passim' "$KS_FILE" \
    "fixed passim activation bug is not described as current"
assert_not_grep 'Already the fwupd default' "$KS_FILE" \
    "fwupd private-device-data default is not inverted"
assert_not_grep 'M13: AIDE (UpdateMotd rationale)' "$KS_FILE" \
    "UpdateMotd rationale has no stale cross-module pointer"
assert_grep_fixed 'restorecon failed for fwupd configuration/documentation' "$KS_FILE" \
    "SELinux relabel failure is visible and fatal"
assert_grep_fixed 'FWUPD_RELABEL_PATHS=(' "$KS_FILE" \
    "M24 has an exact relabel allowlist"
assert_grep_fixed 'restorecon -F "${FWUPD_RELABEL_PATHS[@]}"' "$KS_FILE" \
    "M24 relabels only its owned payloads"
assert_not_grep 'restorecon -R' "$KS_FILE" \
    "M24 does not recursively relabel cross-module directories"
assert_grep_fixed 'verify_owned_regular()' "$KS_FILE" \
    "compose has one exact file-metadata verifier"
assert_grep_fixed 'verify_rpm_regular()' "$KS_FILE" \
    "compose can prove a retained vendor file is RPM-pristine"
assert_grep_fixed 'dump_rdev dump_symlink dump_extra' "$KS_FILE" \
    "RPM dump column 11 is named for its symlink-target semantics"
assert_not_grep 'dump_caps' "$KS_FILE" \
    "RPM dump parsing does not pretend to verify file capabilities"
assert_grep_fixed 'not a file-capability field' "$KS_FILE" \
    "RPM dump field boundary is documented for future callers"
assert_grep_fixed 'verify_rpm_regular "$VENDOR_REMOTE" fwupd 644' "$KS_FILE" \
    "compose proves vendor-directory bytes and metadata against the Fedora RPM"
assert_grep_fixed \
    'MetadataURI=file:///usr/share/fwupd/remotes.d/vendor/firmware' \
    "$KS_FILE" "compose pins vendor-directory to the packaged local metadata source"
for exact_file_mode in \
    '/etc/fwupd/remotes.d/lvfs.conf 644' \
    '/etc/fwupd/remotes.d/lvfs-testing.conf 644' \
    '/etc/fwupd/remotes.d/lvfs-embargo.conf 644' \
    '/etc/fwupd/fwupd.conf 640' \
    '/usr/share/doc/noid-privacy/24-firmware-updates.md 644' \
    '"$FWUPD_EFI_PAYLOAD" 600'; do
    assert_grep_fixed "verify_owned_regular $exact_file_mode" "$KS_FILE" \
        "compose verifies exact metadata for $exact_file_mode"
done

# Deployed guidance must describe the minimum-supported 2.1.7 behavior without claiming
# anonymity, scheduled updates, or an unattainable/outdated HSI model.
assert_grep_fixed 'disables automatic report uploads' "$FWUPD_DOC" \
    "privacy claim is scoped to the controls M24 actually sets"
assert_grep_fixed '`fwupdmgr report-devices`' "$FWUPD_DOC" \
    "explicit upload capability remains honestly disclosed"
assert_grep_fixed 'ordinary HTTPS request metadata' "$FWUPD_DOC" \
    "CDN request metadata is not mislabeled as zero data disclosure"
assert_not_grep 'disables all fwupd telemetry' "$FWUPD_DOC" \
    "documentation has no absolute telemetry claim"
assert_not_grep 'no data is sent back' "$FWUPD_DOC" \
    "documentation has no false zero-egress claim"
assert_not_grep 'Telemetry**: NONE' "$FWUPD_DOC" \
    "network table does not overstate reporting controls"
assert_grep_fixed 'user-started NoID Privacy Update workflow' "$FWUPD_DOC" \
    "firmware checks are described as user-initiated"
assert_not_grep 'weekly update script' "$FWUPD_DOC" \
    "silent-machine documentation does not invent a scheduled updater"
assert_not_grep '`update-all.sh`' "$FWUPD_DOC" \
    "documentation does not use the stale updater name"
assert_grep_fixed 'explicit fwupd client action' "$FWUPD_DOC" \
    "manual network scope includes every deliberate fwupd frontend"
assert_grep_fixed '| HSI:5 | Secure Proven:' "$FWUPD_DOC" \
    "current HSI:5 semantics are documented"
assert_grep_fixed 'HSI:5 cannot currently' "$FWUPD_DOC" \
    "unattainable current HSI:5 status is explicit"
assert_grep_fixed 'separate HSI-3' "$FWUPD_DOC" \
    "fwupd UEFI MemoryProtection/NxCompat split is accurate"
assert_grep_fixed 'minimum-supported 2.1.7 release also adds MTD' "$FWUPD_DOC" \
    "current fwupd HSI additions are documented"
assert_not_grep 'fwupd#10534' "$FWUPD_DOC" \
    "unrelated numeric device ID is not cited as an HSI issue"
assert_not_grep 'No security features detected' "$FWUPD_DOC" \
    "outdated HSI:0 definition is absent"
assert_grep_fixed 'env http_proxy="$proxy_url" https_proxy="$proxy_url"' \
    "$FWUPD_DOC" "proxy guidance scopes libcurl variables to the transfer"
assert_not_grep_extended 'sudo([[:space:]]+env)?[[:space:]].*fwupdmgr[[:space:]]+(refresh|update)' \
    "$FWUPD_DOC" "network-facing fwupdmgr clients stay unprivileged"
assert_grep_fixed 'PolicyKit authorizes the' "$FWUPD_DOC" \
    "manual guidance preserves fine-grained daemon authorization"
assert_not_grep 'DefaultEnvironment=' "$FWUPD_DOC" \
    "proxy guidance does not mutate every system service environment"
assert_not_grep 'systemctl daemon-reexec' "$FWUPD_DOC" \
    "proxy guidance does not re-exec PID 1"
assert_grep_fixed 'curl --fail --show-error --silent --head --max-time 20' \
    "$FWUPD_DOC" "connectivity probe preserves failure and has a timeout"
assert_grep_fixed \
    'findmnt --mountpoint /boot/efi --output SOURCE,FSTYPE,OPTIONS --noheadings' \
    "$FWUPD_DOC" "ESP troubleshooting uses an exact mountpoint query"
assert_grep_fixed 'fwupdmgr --show-all get-devices' "$FWUPD_DOC" \
    "device troubleshooting uses the current visible fwupdmgr option"
assert_not_grep '--show-all-devices' "$FWUPD_DOC" \
    "device troubleshooting does not teach the hidden compatibility alias"

# M24 documents routing; M06 owns filtering and runtime mode. An active VPN is
# not proof of a default route, and only armed strict modes block direct WAN.
assert_grep_fixed "fwupd receives no special VPN" "$FWUPD_DOC" \
    "fwupd documentation does not claim a module-owned VPN route"
assert_grep_fixed "installs the default route, LVFS HTTPS normally follows that route" "$FWUPD_DOC" \
    "fwupd documentation conditions tunnel use on routing"
assert_grep_fixed "split-tunnel or excluded route can differ" "$FWUPD_DOC" \
    "fwupd documentation discloses split-routing limits"
assert_grep_fixed 'reports `STRICT` or `STRICT_EMPTY`' "$FWUPD_DOC" \
    "fwupd fail-closed claim is bound to armed M06 modes"
assert_grep_fixed '`GRACE_BOOTSTRAP`, `GRACE_PAUSED`, and `DISABLED`' "$FWUPD_DOC" \
    "fwupd documentation discloses direct-WAN modes"
assert_not_grep 'all fwupd HTTPS traffic' "$FWUPD_DOC" \
    "unconditional fwupd VPN-routing claim is absent"
assert_not_grep 'With a VPN active.*all fwupd' "$FWUPD_DOC" \
    "active-VPN wording cannot imply universal tunnel routing"
assert_not_grep 'killswitch keeps.*fail-closed' "$FWUPD_DOC" \
    "fail-closed wording cannot omit the M06 runtime mode"

# Exact Silent Machine split: no scheduled LVFS/P2P work and no boot-started
# daemon, while the deliberate CLI retains native D-Bus on-demand activation.
for masked_unit in passim.service fwupd-refresh.timer fwupd-refresh.service; do
    assert_grep_fixed "systemctl mask $masked_unit" "$KS_FILE" \
        "M24 masks $masked_unit exactly"
    assert_not_grep_extended "systemctl mask $masked_unit.*[|][|][[:space:]]*true" \
        "$KS_FILE" "M24 does not swallow the $masked_unit mask failure"
done
assert_grep_fixed 'passim.service proactively masked' "$KS_FILE" \
    "compose evidence names the package-independent proactive mask"
assert_grep_fixed 'proactive passim.service mask missing or incorrect' "$KS_FILE" \
    "missing proactive passim mask fails the compose"
assert_not_grep 'passim not installed (no mask needed)' "$KS_FILE" \
    "unreachable passim package-absence acceptance is retired"
assert_not_grep 'rpm -q passim' "$KS_FILE" \
    "passim mask verification does not branch on package presence"
assert_grep_fixed 'IdleTimeout=300' "$FWUPD_CONF" \
    "fwupd uses the maintained five-minute idle default"
assert_grep_fixed 'IdleInhibitStartupThreshold=0' "$FWUPD_CONF" \
    "slow startup alone cannot create an unlimited daemon lifetime"
assert_not_grep_extended '^IdleTimeout=0$' "$FWUPD_CONF" \
    "retired never-exit daemon policy is absent"
assert_not_grep 'KEEPWARM_EOF' "$KS_FILE" \
    "retired keep-warm payload is absent"
assert_not_grep 'WantedBy=multi-user.target' "$KS_FILE" \
    "M24 never extends the vendor service into a boot target"
assert_not_grep 'systemctl enable fwupd.service' "$KS_FILE" \
    "M24 never enables the firmware daemon at boot"
assert_grep_fixed 'systemctl disable fwupd.service' "$KS_FILE" \
    "M24 natively removes legacy boot enablement"
assert_grep_fixed \
    'rm -f -- /etc/systemd/system/fwupd.service.d/99-noid-keep-warm.conf' \
    "$KS_FILE" "M24 retires the exact legacy policy artifact"
assert_grep_fixed 'systemctl is-enabled fwupd.service' "$KS_FILE" \
    "compose verifies the upstream static service state"
assert_grep_fixed 'fwupd itself defers that request while an update is in' \
    "$FWUPD_DOC" "documentation preserves safe in-progress update handling"
assert_grep_fixed 'fwupdmgr refresh' "$FWUPD_DOC" \
    "manual refresh remains documented despite service masks"
assert_grep_fixed 'fwupdmgr update' "$FWUPD_DOC" \
    "confirmed manual firmware installation remains documented"
assert_grep_fixed 'fwupdmgr quit' "$FWUPD_DOC" \
    "safe explicit daemon settlement remains documented"

assert_file_executable "$SILENT_RUNTIME" \
    "three-pass Silent Machine/update runtime gate is executable"
assert_cmd_success "Silent Machine/update runtime gate parses" \
    bash -n "$SILENT_RUNTIME"
assert_grep_fixed 'live|fresh-install|reboot) ;;' "$SILENT_RUNTIME" \
    "Silent Machine/update gate recognizes the exact three pass identities"
assert_grep_fixed 'org.freedesktop.Application.Activate' "$SILENT_RUNTIME" \
    "runtime gate performs the actual negative GNOME Software activation probe"
assert_grep_fixed 'fwupd_before=' "$SILENT_RUNTIME" \
    "runtime gate brackets fwupd process identity"
assert_grep_fixed 'noid-status woke the boot-dormant fwupd service' \
    "$SILENT_RUNTIME" \
    "runtime gate proves the general status diagnostic cannot activate fwupd"
assert_grep_fixed 'dnf5daemon-server.service' "$SILENT_RUNTIME" \
    "runtime gate rejects a DNF-daemon side effect"
assert_grep_fixed 'LC_ALL=C fwupdmgr refresh --force' "$SILENT_RUNTIME" \
    "runtime gate retains Update All's unprivileged manual firmware refresh"
assert_grep_fixed 'LC_ALL=C fwupdmgr update --no-reboot-check' "$SILENT_RUNTIME" \
    "runtime gate retains confirmed PolicyKit firmware installation"
assert_grep_fixed 'LC_ALL=C fwupdmgr check-reboot-needed --json' "$SILENT_RUNTIME" \
    "runtime gate retains the dedicated noninteractive firmware reboot query"
assert_grep_fixed 'sudo -n LC_ALL=C fwupdmgr quit' "$SILENT_RUNTIME" \
    "runtime gate requires noninteractive safe daemon settlement"
assert_grep_fixed 'FWUPD_MIN_VERSION=2.1.7' "$SILENT_RUNTIME" \
    "runtime gate rechecks the complete-trust fwupd floor"
assert_grep_fixed 'verify_rpm_file "$vendor_remote" fwupd 1' "$SILENT_RUNTIME" \
    "runtime gate proves vendor-directory remains Fedora RPM-pristine"
assert_grep_fixed 'verify_safe_root_dir "$config_dir"' "$SILENT_RUNTIME" \
    "runtime gate rechecks the root-owned fwupd directory boundary"
assert_grep_fixed 'StateDirectoryMode --value' "$SILENT_RUNTIME" \
    "runtime gate checks the effective fwupd state-directory mode"
assert_grep_fixed 'fwupd state directory mode changed across daemon activation' \
    "$SILENT_RUNTIME" \
    "runtime gate detects systemd reopening local firmware history"
assert_grep_fixed 'verify_owned_file "$remote_path" 644' "$SILENT_RUNTIME" \
    "runtime gate rejects linked or misowned network-remote files"
assert_grep_fixed 'unexpected mutable fwupd remote definition' "$SILENT_RUNTIME" \
    "runtime gate rejects every mutable remote definition"
assert_grep_fixed 'if [[ $PASS_ID == live ]]; then' "$SILENT_RUNTIME" \
    "runtime gate separates the intentionally unavailable Live daemon"
assert_grep_fixed \
    '/etc/systemd/system/fwupd.service.d/98-noid-live-skip.conf' \
    "$SILENT_RUNTIME" "Live runtime checks the exact native fwupd condition drop-in"
assert_grep_fixed 'systemctl start --no-block fwupd.service' "$SILENT_RUNTIME" \
    "Live condition probe cannot inherit an activation-client wait"
assert_grep_fixed \
    '[[ $(systemctl show fwupd.service -p ConditionResult --value) == no ]]' \
    "$SILENT_RUNTIME" "Live runtime proves the daemon was condition-skipped"
assert_grep_fixed 'IdleInhibitStartupThreshold=0' "$SILENT_RUNTIME" \
    "runtime gate pins the bounded slow-start policy"
assert_grep_fixed 'DisabledPlugins=redfish;android_boot' "$SILENT_RUNTIME" \
    "runtime gate pins the closed fwupd plugin list"
assert_not_grep 'kill.*fwupd' "$SILENT_RUNTIME" \
    "runtime gate never permits signal-based firmware-daemon termination"
assert_grep_fixed 'sudo -n /usr/bin/test -r "$fwupd_conf"' "$SILENT_RUNTIME" \
    "normal-user gate requires a pre-authenticated bounded privileged read"
assert_grep_fixed 'sudo -n /usr/bin/grep -cxF -- "$line" "$fwupd_conf"' \
    "$SILENT_RUNTIME" \
    "root-only fwupd configuration is never read directly as the desktop user"
assert_not_grep_extended '^.*\$\(grep -cxF "\$line" "\$fwupd_conf"\)' \
    "$SILENT_RUNTIME" \
    "direct unreadable fwupd.conf probe is retired"

# File permissions
assert_grep_extended 'chmod 644 /etc/fwupd/' "$KS_FILE"

test_finish
