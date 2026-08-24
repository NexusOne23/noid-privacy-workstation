#!/bin/bash
# 99-finalize-structural — regression test for the final %post gate
#
# Covers: exact health-stamp cross-check for the 14 failure-atomic adopters plus
# explicit M99 artifact/postcondition checks, size gates for docs, the
# user-owned AIDE trust boundary,
# final build timestamp, EXPECTED_STAMPS list, forensic-retention
# cross-checks (NUMBER_LIMIT + 10 exclusions + snapper-
# prune), Status-line presence, M42 cross-mod refs.
# Would catch: regression removing cross-check, missing Module stamp,
# EXPECTED_STAMPS list drift, silent-deployment-failure gap.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/99-finalize.ks"
M09_KS_FILE="$PROJECT_ROOT/kickstart/snippets/09-ssh.ks"
M10_KS_FILE="$PROJECT_ROOT/kickstart/snippets/10-pam-login.ks"
M12_KS_FILE="$PROJECT_ROOT/kickstart/snippets/12-selinux-auditd.ks"
M17_KS_FILE="$PROJECT_ROOT/kickstart/snippets/17-gnome-hardening.ks"
M32_KS_FILE="$PROJECT_ROOT/kickstart/snippets/32-branding.ks"
M40_KS_FILE="$PROJECT_ROOT/kickstart/snippets/40-audit-bundle.ks"
TEST_TMPDIR=$(mktemp -d)
trap 'rm -rf "$TEST_TMPDIR"' EXIT

test_start "99-finalize-structural"

assert_file_exists "$KS_FILE"
assert_file_exists "$M09_KS_FILE"
assert_file_exists "$M12_KS_FILE"
assert_file_exists "$M32_KS_FILE"
assert_file_exists "$M40_KS_FILE"
assert_cmd_success "bash -n $KS_FILE" bash -n "$KS_FILE"
assert_eq 2 "$(grep -cFx 'PATH=/usr/sbin:/usr/bin:/sbin:/bin' "$KS_FILE")" \
    "M99 and its installed ACL helper each close command lookup"
assert_eq 2 "$(grep -cFx 'export PATH' "$KS_FILE")" \
    "both privileged execution boundaries export only the closed path"
assert_grep_fixed "grep -q '^WakeOnLan=off$' /etc/systemd/network/10-noid-no-wol.link" \
    "$KS_FILE" "finalizer cross-checks the actual M27 Wake-on-LAN disable control"
assert_grep_fixed "grep -q '^\\[EnergyEfficientEthernet\\]$' /etc/systemd/network/10-noid-no-wol.link" \
    "$KS_FILE" "finalizer rejects a returned global EEE override"
assert_grep_fixed '[ -e /etc/systemd/network/10-noid-no-eee.link ]' \
    "$KS_FILE" "finalizer rejects the retired EEE policy artifact"
assert_grep_fixed 'NetworkManager WoL ownership boundary missing' "$KS_FILE" \
    "finalizer distinguishes NM ownership from device disablement"
assert_grep_fixed "grep -qFx 'ethernet.wake-on-lan=32768'" "$KS_FILE" \
    "finalizer requires NM.conf's numeric wake-on-lan ignore flag"
assert_not_grep "grep -q.*ethernet.wake-on-lan=ignore" "$KS_FILE" \
    "finalizer cannot accept nmcli's wake-on-lan nick in NM.conf"
assert_grep_fixed "grep -cFx 'ipv6.addr-gen-mode=1'" "$KS_FILE" \
    "finalizer requires NM.conf's numeric stable-privacy enum"
assert_not_grep "grep -c.*ipv6.addr-gen-mode=stable-privacy" "$KS_FILE" \
    "finalizer cannot accept nmcli's addr-gen-mode nick in NM.conf"
M17_GNOME_DOC="$TEST_TMPDIR/17-gnome-hardening.md"
if extract_heredoc "$M17_KS_FILE" GNOME_DOC_EOF "$M17_GNOME_DOC"; then
    _pass "M17 deployed GNOME documentation payload extracts"
else
    _fail "M17 deployed GNOME documentation payload extracts"
fi
M17_FIRSTRUN="$TEST_TMPDIR/noid-user-firstrun"
if extract_heredoc "$M17_KS_FILE" FIRSTRUN_SCRIPT_EOF "$M17_FIRSTRUN"; then
    _pass "M17 deployed first-login helper extracts"
else
    _fail "M17 deployed first-login helper extracts"
fi
assert_grep_fixed 'System dconf locks remain' "$KS_FILE" "finalizer package rationale keeps dconf locks authoritative"
assert_grep_fixed "rpm -qa --qf '%{NAME}-%{EVR}.%{ARCH}\\n' 2>/dev/null | LC_ALL=C sort > \"\$PACKAGE_MANIFEST\"" \
    "$KS_FILE" "finalizer records a deterministic image package manifest"
assert_grep_fixed 'package manifest suspiciously small' "$KS_FILE" \
    "package manifest emptiness is a build failure, not a silent gap"
assert_grep_fixed 'install -d -m 0700 -o root -g root /var/log/aide' \
    "$KS_FILE" "finalizer creates the Fedora AIDE log directory as 0700"
assert_grep_fixed 'Module 13 AIDE local-session notification contract invalid' \
    "$KS_FILE" "finalizer gates the hardened AIDE notifier"
assert_grep_fixed "stat -c '%U:%G:%a' /var/log/aide" "$KS_FILE" \
    "finalizer verifies filesystem-neutral AIDE log-directory metadata"
assert_grep_fixed 'root:root:700 ]; then' "$KS_FILE" \
    "finalizer requires the exact AIDE log-directory owner and mode"
assert_grep_fixed '[ ! -d /var/log/aide ] || [ -L /var/log/aide ]' "$KS_FILE" \
    "finalizer retains exact directory and symlink checks"
assert_not_grep "stat -Lc '%U:%G:%a:%h' /var/log/aide" "$KS_FILE" \
    "finalizer does not require a filesystem-specific directory link count"
assert_grep_fixed 'never a trust or suppression input' "$KS_FILE" \
    "package manifest is declared a transparency record only"
assert_not_grep_extended 'gnome-tweaks lets user undo dconf|undo dconf hardening' "$KS_FILE" "finalizer contains no false Tweaks lock-bypass rationale"
assert_grep_fixed 'obsolete Location flag exists; gsettings must remain authoritative' \
    "$KS_FILE" "finalizer rejects the stale Location flag contract"
assert_not_grep 'reference zenity' "$KS_FILE" \
    "welcome contract no longer describes the retired zenity UI"
assert_grep_fixed 'import GTK4/libadwaita' "$KS_FILE" \
    "welcome contract names the active toolkit"
assert_not_grep 'branding assets best-effort' "$KS_FILE" \
    "finalizer does not describe mandatory branding assets as best-effort"
assert_grep_fixed 'mandatory Plymouth/avatar assets are checked separately below' \
    "$KS_FILE" "branding comment points to the actual hard gates"
assert_not_grep 'date(1) calls below' "$KS_FILE" \
    "release-metadata comment contains no retired date invocation"
assert_grep_fixed "derive from M32's NOID_BUILD_TIMESTAMP field" "$KS_FILE" \
    "release-metadata comment names the reproducible timestamp source"
# Every section is a named, dated release. The exact ordered heading inventory
# below rejects any extra pending or pseudo-version bucket.
actual_release_headings=$(grep '^## \[' "$PROJECT_ROOT/CHANGELOG.md")
expected_release_headings=$(printf '%s\n' \
    '## [v1.7] - 2026-08-23' \
    '## [v1.6] - 2026-08-14' \
    '## [v1.5] - 2026-08-08' \
    '## [v1.4] - 2026-07-26' \
    '## [v1.3] - 2026-06-22' \
    '## [v1.2] - 2026-06-14' \
    '## [v1.1] - 2026-06-08' \
    '## [v1.0] - 2026-06-04')
assert_eq "$expected_release_headings" "$actual_release_headings" \
    "changelog contains exactly eight named and dated releases, newest first"
# The version the image stamps must be the newest section, or the shipped
# /etc/noid-build-info would claim a release the changelog never describes.
branding_version=$(grep -m1 '^NOID_VERSION="' \
    "$PROJECT_ROOT/kickstart/snippets/32-branding.ks" | cut -d'"' -f2)
assert_eq "## [$branding_version] - 2026-08-23" \
    "$(printf '%s\n' "$actual_release_headings" | head -1)" \
    "changelog's newest release is the version M32 stamps into the image"
assert_cmd_success "changelog has no entries before its first release section" \
    awk '
        /^## / { found=1; exit }
        /^- / { exit 1 }
        END { if (!found) exit 1 }
    ' "$PROJECT_ROOT/CHANGELOG.md"
assert_grep_fixed 'shared NoID Privacy state directory must be 0755 root:root' "$KS_FILE" \
    "finalizer enforces the cross-module state-directory metadata contract"
assert_grep_fixed '/usr/local/sbin/noid-lan-topology-boot-refresh.sh' \
    "$KS_FILE" "finalizer requires M03's boot-critical topology helper"
assert_grep_fixed '# Existing-user agent-policy adapters are also owned by Module 08.' \
    "$KS_FILE" "agent-policy adapter checks live in the Module 08 section"
for agent_policy_failure in \
    'Module 08 existing-user agent-policy adapter helper invalid' \
    'Module 08 existing-user agent-policy adapter unit invalid' \
    'Module 08 existing-user agent-policy adapter global enablement invalid' \
    'Module 08 existing-user agent-policy one-shot validation boundary invalid'; do
    assert_grep_fixed "$agent_policy_failure" "$KS_FILE" \
        "agent-policy failure names its owner: $agent_policy_failure"
done
assert_grep_fixed '[ ! -d "$NOID_STATE_DIR" ] || [ -L "$NOID_STATE_DIR" ]' \
    "$KS_FILE" "finalizer rejects a missing, non-directory or symlinked state root"
assert_not_grep 'chmod 0755 "$NOID_STATE_DIR"' "$KS_FILE" \
    "finalizer detects state-root drift instead of normalizing it"
assert_not_grep 'verification of every module' "$PROJECT_ROOT/CHANGELOG.md" \
    "changelog does not claim universal artifact verification"
assert_grep_fixed 'for pkg in codium ffmpeg-free python3-libdnf5' "$KS_FILE" \
    "finalizer requires the native DNF5 cache-path binding"
assert_grep_fixed '/usr/libexec/noid-vscodium-repo-key-seed' "$KS_FILE" \
    "finalizer requires the VSCodium per-user metadata-key helper"
assert_grep_fixed '/usr/lib/systemd/user/noid-vscodium-repo-key-seed.service' "$KS_FILE" \
    "finalizer requires the VSCodium per-user metadata-key unit"
assert_grep_fixed '/etc/dnf/libdnf5-plugins/actions.d/noid-vscodium-repo-key.actions' "$KS_FILE" \
    "finalizer requires the host DNF cache-reconciliation action"
assert_grep_fixed 'repos_configured:::enabled=host-only raise_error=1:/usr/libexec/noid-vscodium-repo-key-seed --cache-root ${conf.cachedir}' \
    "$KS_FILE" "finalizer pins the shell-free VSCodium pre-load action"
assert_grep_fixed 'create_repos_from_system_configuration()' "$KS_FILE" \
    "finalizer binds native offline DNF5 cache-path derivation"
assert_grep_fixed '*/dnf5daemon-server)' "$KS_FILE" \
    "finalizer requires GNOME Software's native DNF daemon cache contract"
assert_grep_fixed 'RestrictAddressFamilies=AF_UNIX' "$KS_FILE" \
    "finalizer retains the VSCodium key seed network boundary"
assert_grep_fixed "grep -qE '^(PrivateNetwork|IPAddressDeny)='" "$KS_FILE" \
    "finalizer rejects unenforceable user-manager network claims"
assert_grep_fixed '/usr/libexec/noid-codium-launch' "$KS_FILE" \
    "finalizer requires the VSCodium native default-GPU launcher"
assert_grep_fixed '/usr/local/sbin/noid-codium-launcher-sync' "$KS_FILE" \
    "finalizer requires the RPM-authenticated desktop publisher"
assert_grep_fixed \
    'post_transaction:codium:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-codium-launcher-sync\ >/dev/null' \
    "$KS_FILE" "finalizer binds codium updates to desktop-overlay convergence"
assert_grep_fixed \
    'exec "$SWITCHEROOCTL" launch --gpu=0 "$VENDOR_EXECUTABLE" "$@"' \
    "$KS_FILE" "finalizer pins the platform-default switcheroo path"
assert_grep_fixed 'rpm -Vf "$codium_vendor_desktop"' "$KS_FILE" \
    "finalizer proves VSCodium vendor desktop bytes stay RPM-pristine"
assert_grep_fixed \
    'Module 08 VSCodium default-GPU launcher contract invalid' "$KS_FILE" \
    "finalizer makes incomplete VSCodium routing fatal"
assert_not_grep 'Each module carries a `verify_fail` counter and a health-stamp' \
    "$PROJECT_ROOT/CHANGELOG.md" \
    "changelog does not claim universal verification counters/stamps"
assert_grep_fixed \
    "grep -qF 'return polkit.Result.AUTH_ADMIN;' /etc/polkit-1/rules.d/60-noid-toggle-privacy-services.rules" \
    "$KS_FILE" "finalizer requires uncached exact-program pkexec authorization"
assert_grep_fixed \
    "grep -qF 'return polkit.Result.AUTH_ADMIN_KEEP;' /etc/polkit-1/rules.d/60-noid-toggle-privacy-services.rules" \
    "$KS_FILE" "finalizer rejects retained generic-pkexec authorization"
assert_grep_fixed 'Made AIDE evidence fully user-owned.' \
    "$PROJECT_ROOT/CHANGELOG.md" \
    "release highlights name the current AIDE trust boundary"
if grep -RInE --include='*.ks' \
        '^[[:space:]]*(install[[:space:]]+[^#]*-m[[:space:]]*0?700|chmod[[:space:]]+0?700)[^#]*/var/lib/noid-privacy([[:space:]]|$)' \
        "$PROJECT_ROOT/kickstart/snippets" >/dev/null 2>&1; then
    _fail "no module narrows the shared NoID Privacy state root to 0700"
else
    _pass "no module narrows the shared NoID Privacy state root to 0700"
fi

# Canonical locale manifest: package selection in master.ks and the deployed
# finalizer's package/data gate must be exact generated views of one reviewed
# 13-entry source.
LANGPACK_MANIFEST="$PROJECT_ROOT/manifests/required-glibc-langpacks.tsv"
assert_file_exists "$LANGPACK_MANIFEST" "canonical glibc langpack manifest exists"
langpack_count=$(wc -l < "$LANGPACK_MANIFEST")
assert_eq 13 "$langpack_count" "canonical langpack manifest has the promised 13 entries"
assert_cmd_success "canonical langpack manifest has unique closed fields" \
    awk -F'|' '
        NF != 2 || $1 !~ /^glibc-langpack-[A-Za-z_]+$/ || $2 !~ /^[A-Za-z_]+[.]utf8$/ || seen_pkg[$1]++ || seen_locale[$2]++ { bad=1 }
        END { exit bad }
    ' "$LANGPACK_MANIFEST"

cut -d'|' -f1 "$LANGPACK_MANIFEST" > "$TEST_TMPDIR/langpack-packages.expected"
sed -n \
    '/^# BEGIN GENERATED REQUIRED_GLIBC_LANGPACKS /,/^# END GENERATED REQUIRED_GLIBC_LANGPACKS$/p' \
    "$PROJECT_ROOT/kickstart/master.ks" \
    | sed '1d;$d' > "$TEST_TMPDIR/langpack-packages.master"
assert_cmd_success "master package selection matches canonical langpack manifest" \
    cmp -s "$TEST_TMPDIR/langpack-packages.expected" \
        "$TEST_TMPDIR/langpack-packages.master"
extract_heredoc "$KS_FILE" "REQUIRED_GLIBC_LANGPACKS_EOF" \
    "$TEST_TMPDIR/langpack-finalizer.tsv" \
    || _fail "finalizer langpack manifest extraction"
assert_cmd_success "finalizer package/data gate matches canonical langpack manifest" \
    cmp -s "$LANGPACK_MANIFEST" "$TEST_TMPDIR/langpack-finalizer.tsv"
assert_grep_fixed 'required locale package missing: $langpack_pkg' "$KS_FILE" \
    "every missing named langpack is fatal"
assert_grep_fixed 'required locale data missing: $locale_name' "$KS_FILE" \
    "every missing named locale payload is fatal"
assert_not_grep 'LANGPACK_COUNT.*-lt 5' "$KS_FILE" \
    "five-package partial threshold is gone"
assert_not_grep 'LANGPACK_COUNT.*-lt 13' "$KS_FILE" \
    "thirteen-package aggregate threshold is gone"
AIDE_SECURE_MANIFEST="$PROJECT_ROOT/manifests/aide-secure-paths.tsv"
assert_file_exists "$AIDE_SECURE_MANIFEST" "canonical AIDE SECURE manifest exists"
extract_heredoc "$KS_FILE" "AIDE_SECURE_PATHS_EOF" \
    "$TEST_TMPDIR/aide-secure-finalizer.tsv" || \
    _fail "finalizer AIDE SECURE manifest extraction"
assert_cmd_success "finalizer AIDE coverage gate matches canonical manifest" \
    cmp -s "$AIDE_SECURE_MANIFEST" "$TEST_TMPDIR/aide-secure-finalizer.tsv"
assert_grep_fixed \
    '/usr/local/bin/noid-gnome-software-rpm|f|/usr/local/bin/noid-gnome-software-rpm' \
    "$AIDE_SECURE_MANIFEST" "Fedora-RPM one-shot is in the canonical AIDE boundary"
assert_grep_fixed '--path-check="$aide_file_type:$aide_probe_path"' "$KS_FILE" \
    "finalizer evaluates effective AIDE rule-tree coverage"
assert_grep_fixed 'canonical AIDE coverage weak or shadowed' "$KS_FILE" \
    "weak or negative-shadowed canonical coverage is fatal"
assert_grep_fixed 'deployed AIDE coverage manifest differs from the finalize view' \
    "$KS_FILE" "finalizer binds the deployed coverage manifest byte-for-byte"
assert_grep_fixed 'Module 13 wrapper lacks the runtime coverage re-probe' \
    "$KS_FILE" "finalizer requires the daily wrapper runtime coverage probe"
assert_grep_fixed '/etc/ssh/sshd_config.d:root:root:700' "$KS_FILE" \
    "finalizer pins Fedora-compatible SSH server-directory metadata"
assert_grep_fixed '/etc/ssh/sshd_config.d/01-noid-hardening.conf:root:root:600' \
    "$KS_FILE" "finalizer pins the dormant SSH server policy metadata"
assert_grep_fixed 'Module 14 USBGuard daemon config metadata is not root:root 0600 nlink=1' \
    "$KS_FILE" "finalizer pins USBGuard's daemon-start metadata contract"
assert_grep_fixed "'AuthenticationMethods publickey'" "$KS_FILE" \
    "finalizer requires the explicit public-key-only server invariant"
assert_grep_fixed "'AllowStreamLocalForwarding no'" "$KS_FILE" \
    "finalizer requires the complete no-forwarding server invariant"
assert_grep_fixed 'client-only image contains sshd or a private host-key path' \
    "$KS_FILE" "finalizer rejects every inbound-server secret/listener artifact"
assert_grep_fixed '[ ! -x /usr/libexec/noid-mark-hostonly-boot-success ]' \
    "$KS_FILE" "finalizer requires the M21 first-login boot-success helper"
assert_grep_fixed \
    "/usr/libexec/noid-mark-hostonly-boot-success 2>/dev/null)\" != root:root:755" \
    "$KS_FILE" \
    "finalizer pins the M21 boot-success helper metadata"
assert_grep_fixed \
    '[ ! -f /usr/lib/systemd/user/noid-hostonly-boot-success.service ]' \
    "$KS_FILE" "finalizer requires the M21 boot-success user unit"
assert_grep_fixed \
    '[ ! -f /usr/lib/systemd/user/noid-hostonly-boot-success.path ]' \
    "$KS_FILE" "finalizer requires the race-free M21 request watcher"
assert_grep_fixed \
    'noid-user-firstrun.service.wants/noid-hostonly-boot-success.service' \
    "$KS_FILE" "finalizer requires the static first-login boot-success link"
assert_grep_fixed \
    'noid-user-firstrun.service.wants/noid-hostonly-boot-success.path' \
    "$KS_FILE" "finalizer requires the static first-login request watcher link"
assert_grep_fixed \
    'multi-user.target.wants/noid-dracut-hostonly-firstboot.timer' \
    "$KS_FILE" "finalizer requires nonblocking native M21 timer activation"
assert_grep_fixed \
    'multi-user.target.wants/noid-dracut-hostonly-firstboot.service' \
    "$KS_FILE" "finalizer rejects legacy M21 critical-path activation"
assert_grep_fixed 'grub2-set-bootflag menu_show_once' "$KS_FILE" \
    "finalizer rejects the forced M21 GRUB menu"
assert_grep_fixed '"$BOOTFLAG" boot_success' "$KS_FILE" \
    "finalizer binds the single Fedora boot-success operation"
assert_grep_fixed 'Requires=noid-user-firstrun.service' "$KS_FILE" \
    "finalizer binds boot success to transactional first-login work"
assert_grep_fixed 'Four-app first-party suite' "$KS_FILE" \
    "finalizer owns one cross-app release gate"
assert_grep_fixed '/usr/lib/noid-privacy/noid_ui.py' "$KS_FILE" \
    "finalizer verifies the shared application contract"
assert_grep_fixed 'def accessible(widget, label, description=' "$KS_FILE" \
    "finalizer requires explicit accessible labels/descriptions"
assert_grep_fixed 'Gtk.AccessibleProperty.DESCRIPTION' "$KS_FILE" \
    "finalizer binds shared accessible descriptions"
assert_grep_fixed 'Gtk.AccessibleRelation.LABELLED_BY' "$KS_FILE" \
    "finalizer binds native visible-label relations"
assert_grep_fixed 'Gtk.AccessibleRelation.DESCRIBED_BY' "$KS_FILE" \
    "finalizer binds native row-description relations"
assert_grep_fixed 'Gtk.AccessibleList.new_from_list' "$KS_FILE" \
    "finalizer binds the Fedora 44 PyGObject relation transport"
assert_grep_fixed 'def _prepare_row_text_labels(row)' "$KS_FILE" \
    "finalizer binds dynamic Adw private-label promotion"
assert_grep_fixed "not child.has_css_class('noid-emoji')" "$KS_FILE" \
    "finalizer keeps decorative emoji out of accessible row names"
assert_grep_fixed "not child.has_css_class('noid-step-num')" "$KS_FILE" \
    "finalizer keeps decorative Update ordinals out of accessible row names"
assert_grep_fixed 'def bind_view_switcher_accessibility' "$KS_FILE" \
    "finalizer binds responsive page-tab names"
assert_grep_fixed "grep -qF 'noid_ui.accessible(' /usr/local/bin/noid-update" \
    "$KS_FILE" "finalizer requires Update-local accessible controls"
assert_grep_fixed "grep -qF 'noid_ui.accessible_row(' /usr/local/bin/noid-network" \
    "$KS_FILE" "finalizer requires Network-local accessible rows"
assert_grep_fixed "grep -qxF 'RestrictAddressFamilies=AF_UNIX'" "$KS_FILE" \
    "finalizer retains the enforceable adapter network boundary"
assert_grep_fixed "grep -q '^IPAddressDeny='" "$KS_FILE" \
    "finalizer rejects the adapter's unenforceable user IP firewall claim"
assert_not_grep 'python3 -m py_compile /usr/' "$KS_FILE" \
    "final verification creates no untracked system bytecode cache"
for app in noid-welcome.sh noid-update noid-network noid-tools; do
    assert_grep_fixed "/usr/local/bin/$app" "$KS_FILE" \
        "finalizer verifies first-party app: $app"
done
for icon in noid-privacy-setup noid-privacy-update noid-privacy-network \
            noid-privacy-tools; do
    assert_grep_fixed "$icon" "$KS_FILE" \
        "finalizer binds first-party desktop icon: $icon"
done
assert_grep_fixed 'app_icon_payload' "$KS_FILE" \
    "finalizer resolves every declared first-party icon to installed bytes"
assert_grep_fixed 'first-party desktop icon has no regular payload' "$KS_FILE" \
    "a missing or symlink-only first-party icon is fatal"
for phase in 1 2 3 4 5 6 7 8 9 10; do
    assert_grep_fixed "log \"Phase $phase:" "$KS_FILE" \
        "finalizer publishes coherent phase $phase progress"
done
assert_not_grep 'log "Step [^"]*/[0-9]' "$KS_FILE" \
    "finalizer exposes no contradictory step denominator"
assert_not_grep 'checks_total is a dynamic' "$KS_FILE" \
    "M99 header names its actual sole error accumulator"
assert_grep_fixed 'M40 evidence owns the requested auditor pin; this gate makes no' \
    "$KS_FILE" "M99 keeps the requested auditor pin without a release-state claim"
assert_not_grep 'Exact upstream 3\.7\.1' "$KS_FILE" \
    "M99 does not claim an external publication state"
assert_grep_fixed 'FAIL: M10 native permission policy missing or failed' "$KS_FILE" \
    "final native permission reconciliation has an explicit fatal path"
assert_grep_fixed 'systemd-tmpfiles --create "$M10_PERMISSION_POLICY"' "$KS_FILE" \
    "finalizer uses the declarative Fedora permission mechanism"
assert_grep_fixed 'obsolete periodic permission mutator present' "$KS_FILE" \
    "finalizer rejects every retired weekly chmod artifact"
assert_grep_fixed 'Module 08 native iSCSI dispatcher precedence contract invalid' \
    "$KS_FILE" "finalizer requires the native iSCSI dispatcher admin override"
assert_grep_fixed '[ -e /etc/tmpfiles.d/noid-disable-iscsi-dispatcher.conf ]' \
    "$KS_FILE" "finalizer rejects the obsolete RPM mode-repair artifact"
assert_grep_fixed '/etc/systemd/system/basic.target.wants/noid-mount-hardening.service' \
    "$KS_FILE" "final gate checks mount hardening in its declared early-boot target"
assert_not_grep 'multi-user.target.wants/noid-mount-hardening.service' "$KS_FILE" \
    "final gate has no stale mount-hardening target check"
assert_grep_fixed 'FAIL: Module 18 flatpak binary missing' "$KS_FILE" \
    "missing Flatpak cannot skip the M18 final gate"
assert_grep_fixed 'Flatpak version below 1.18.1 security baseline' "$KS_FILE" \
    "finalizer rechecks the Flatpak security floor"
assert_grep_fixed 'xdg-desktop-portal version below 1.22.1 security baseline' "$KS_FILE" \
    "finalizer rechecks the portal security floor"
assert_grep_fixed \
    "if ! portal_version=\$(rpm -q --queryformat '%{VERSION}'" \
    "$KS_FILE" "missing xdg-desktop-portal fails the version gate closed"
assert_grep_fixed 'bubblewrap missing, non-executable or setuid' "$KS_FILE" \
    "finalizer rejects deprecated setuid bubblewrap"
assert_grep_fixed 'noid-flatpak-remote-policy verify-default' "$KS_FILE" \
    "finalizer re-runs exact config/key/cached-catalog verification"
assert_grep_fixed 'Fedora Flatpak auto-add unit is not natively masked' "$KS_FILE" \
    "finalizer requires the native systemd mask"
assert_grep_fixed 'forged Fedora Flatpak initialization sentinel present' "$KS_FILE" \
    "finalizer rejects the old private-sentinel workaround"
assert_grep_fixed 'helper missing/not regular executable: $helper' "$KS_FILE" \
    "all action helpers have an unconditional existence/type/exec gate"
assert_grep_fixed \
    'if [ ! -f "$helper" ] || [ -L "$helper" ] || [ ! -x "$helper" ]; then' \
    "$KS_FILE" "the shared action-helper gate rejects symlink substitution"
assert_grep_fixed '/usr/local/bin/noid-complete-setup.sh' "$KS_FILE" \
    "Silent-Machine opt-in setup helper is final-gated"
assert_grep_fixed '| LC_ALL=C sort -V | tail -1)"' "$M32_KS_FILE" \
    "M32 records the deterministic newest installed image kernel"
assert_grep_fixed \
    'KERNEL_VER=$(sed -nE '\''s/^NOID_KERNEL="([^"]+)"$/\1/p'\'' "$BUILD_INFO")' \
    "$KS_FILE" "M99 consumes M32's canonical installed-image kernel provenance"
assert_grep_fixed 'KERNEL="${KERNEL_VER}"' "$KS_FILE" \
    "release metadata writer uses the validated kernel value verbatim"
assert_grep_fixed 'kernel=${KERNEL_VER}' "$KS_FILE" \
    "machine metadata writer uses the validated kernel value verbatim"
assert_not_grep 'KERNEL_VER:-unknown' "$KS_FILE" \
    "release metadata writers and validators cannot disagree on empty provenance"
assert_not_grep 'kernel-core 2>/dev/null | head -1' "$KS_FILE" \
    "M99 never relies on unspecified RPM query ordering"
assert_grep_fixed "stat -Lc '%u:%g:%a:%h' -- \"\$BUILD_INFO\"" "$KS_FILE" \
    "M99 accepts only the exact root-owned canonical provenance file"
assert_grep_fixed \
    'canonical build provenance is missing, duplicated or malformed' "$KS_FILE" \
    "missing, duplicate or malformed canonical provenance is fatal"
assert_grep_fixed 'RELEASE_EXPECTED=(' "$KS_FILE" \
    "M99 defines the closed release-metadata schema"
assert_grep_fixed 'VERSION_EXPECTED=(' "$KS_FILE" \
    "M99 defines the closed machine-readable version schema"
assert_grep_fixed \
    '"/etc/noid-privacy-release:${#RELEASE_EXPECTED[@]}"' "$KS_FILE" \
    "release metadata must contain exactly the closed schema line count"
assert_grep_fixed \
    '"$NOID_STATE_DIR/version:${#VERSION_EXPECTED[@]}"' "$KS_FILE" \
    "machine metadata must contain exactly the closed schema line count"
assert_grep_fixed "stat -Lc '%u:%g:%a:%h' -- \"\$metadata_path\"" "$KS_FILE" \
    "both metadata files require exact ownership, mode and link count"
assert_grep_fixed 'matchpathcon -V "$metadata_path"' "$KS_FILE" \
    "both metadata files require their policy-defined SELinux labels"
assert_grep_fixed 'grep -cFx -- "$expected_line" /etc/noid-privacy-release' \
    "$KS_FILE" "every release-metadata line is present exactly once"
assert_grep_fixed \
    'grep -cFx -- "$expected_line" "$NOID_STATE_DIR/version"' "$KS_FILE" \
    "every machine-metadata line is present exactly once"
assert_not_grep 'build-version metadata files missing or empty' "$KS_FILE" \
    "non-empty-only release metadata validation is retired"
assert_not_grep '\[ ! -f "\$f" \] && \[ ! -x "\$f" \]' "$KS_FILE" \
    "generic artifact lists cannot accept an executable directory"
assert_grep_fixed '/usr/local/bin/noid-dns-diagnose' "$KS_FILE" \
    "M11b manual diagnostic is final-gated"
assert_grep_fixed 'Module 11b diagnostic CLI type, metadata, label or parser contract invalid' \
    "$KS_FILE" "M11b final gate binds executable integrity and SELinux state"
assert_grep_fixed 'Module 11b local evidence contract missing' "$KS_FILE" \
    "M11b final gate requires resolver, server, rule, route and journal evidence"
assert_grep_fixed 'Module 11b diagnostic CLI contains an automatic query/recovery action' \
    "$KS_FILE" "M11b final gate rejects mutation or a fixed probe"
assert_grep_fixed 'Module 11b diagnostic document type, metadata, label or privacy warning invalid' \
    "$KS_FILE" "M11b final gate binds documentation and disclosure"
assert_grep_fixed 'resolvectl --no-ask-password --no-pager show-server-state' "$KS_FILE" \
    "M11b final gate requires learned server-state evidence"
assert_grep_fixed 'if [ "$EUID" -ne 0 ]; then' "$KS_FILE" \
    "M11b final gate prevents an unprivileged monitor-endpoint timeout"
assert_grep_fixed 'sudo noid-dns-diagnose evidence' "$KS_FILE" \
    "M11b final gate retains the explicit complete-evidence invocation"
assert_grep_fixed 'ip -4 route show table all' "$KS_FILE" \
    "M11b final gate requires all-table IPv4 routing evidence"
assert_grep_fixed 'ip -6 route show table all' "$KS_FILE" \
    "M11b final gate requires all-table IPv6 routing evidence"
assert_grep_fixed 'journalctl --system -u systemd-resolved.service' "$KS_FILE" \
    "M11b final gate explicitly scopes the system journal"
assert_grep_fixed 'obsolete automatic artifact present' "$KS_FILE" \
    "M11b timer/recovery artifacts are rejected"
assert_grep_fixed '/usr/share/doc/noid-privacy/11b-dns-health-monitoring.md' \
    "$KS_FILE" "M11b final gate rejects the obsolete monitoring guide"
assert_not_grep 'noid-dns-health.timer not in timers.target.wants' "$KS_FILE" \
    "M11b background timer is no longer required"
assert_grep_fixed '/etc/audit/plugins.d/noid-notify.conf' "$KS_FILE" \
    "finalizer requires the auditd notification plugin descriptor"
assert_grep_fixed 'auparse.AuParser(auparse.AUSOURCE_FEED, None)' "$KS_FILE" \
    "finalizer requires maintained complete-event assembly"
assert_grep_fixed 'row.get("uid") != uid' "$KS_FILE" \
    "finalizer preserves event-AUID/session binding"
for event_notify_meta in \
    "/usr/local/libexec/noid-audit-event-notify 2>/dev/null || true)\" !=" \
    "/etc/systemd/system/noid-audit-event-notify.service 2>/dev/null || true)\" !=" \
    "/etc/systemd/system/noid-audit-event-notify.path 2>/dev/null || true)\" !="; do
    assert_grep_fixed "$event_notify_meta" "$KS_FILE" \
        "finalizer pins event-notify metadata: $event_notify_meta"
done
assert_grep_fixed \
    '! matchpathcon -V /usr/local/libexec/noid-audit-event-notify' \
    "$KS_FILE" "finalizer verifies event-notify SELinux labels"
assert_grep_fixed \
    'systemctl is-enabled noid-audit-event-notify.path' "$KS_FILE" \
    "finalizer requires the event-notify watcher to remain enabled"
assert_grep_fixed 'complete-event/local-session notification contract invalid' \
    "$KS_FILE" "audit popup integration has one fatal final-gate path"
assert_grep_fixed 'libnotify python3-audit zenity curl' "$KS_FILE" \
    "final package gate includes the explicit auparse binding"
assert_grep_fixed '/usr/local/libexec/noid-auditd-live-thresholds' "$KS_FILE" \
    "finalizer requires the Live-only auditd watermark selector"
assert_grep_fixed "grep -qxF 'ExecStartPre=-/usr/local/libexec/noid-auditd-live-thresholds'" \
    "$KS_FILE" "finalizer pins the failure-tolerant selector ExecStartPre (writer/checker parity)"
assert_not_grep 'ExecStartPre=/usr/local/libexec/noid-auditd-live-thresholds' \
    "$KS_FILE" "no stale dash-less selector ExecStartPre pin remains in the finalizer"
assert_grep_fixed 'rd.live.image|rd.live.image=*) live_image=1' "$KS_FILE" \
    "finalizer binds the explicit Live kernel-token gate"
assert_grep_fixed 'print "space_left = 15%"' "$KS_FILE" \
    "finalizer binds the Live low watermark"
assert_grep_fixed 'print "admin_space_left = 10%"' "$KS_FILE" \
    "finalizer binds the Live emergency watermark"
assert_grep_fixed 'PartOf=graphical-session.target' "$KS_FILE" \
    "finalizer requires logout-bound first-login retries"
assert_grep_fixed 'ConditionEnvironment=XDG_SESSION_CLASS=user' "$KS_FILE" \
    "finalizer rejects GNOME Initial Setup pseudo-user execution"
assert_grep_fixed 'ExecCondition=/usr/bin/systemctl --user --quiet is-active graphical-session.target' \
    "$KS_FILE" "finalizer rejects retries outside a graphical session"
assert_grep_fixed 'if [ "${XDG_SESSION_CLASS:-}" != user ]; then' "$KS_FILE" \
    "finalizer requires the helper's pre-home real-user gate"
assert_grep_fixed 'm14_notifier_wants=/usr/lib/systemd/user/graphical-session.target.wants/usbguard-notifier.service' \
    "$KS_FILE" "finalizer owns the notifier's actual graphical target link"
assert_grep_fixed 'm14_catchup_wants=/usr/lib/systemd/user/graphical-session.target.wants/noid-usbguard-login-catchup.service' \
    "$KS_FILE" "finalizer owns the pre-login USB block catch-up target link"
assert_grep_fixed 'Module 14 USBGuard graphical notification contract invalid' \
    "$KS_FILE" "finalizer binds live-event and pre-login USB notification paths"
assert_grep_fixed '--action=review="Open USBGuard Devices"' "$KS_FILE" \
    "finalizer binds the catch-up action to the named USBGuard manager"
assert_grep_fixed '/usr/bin/systemd-run --user --collect --wait --quiet' "$KS_FILE" \
    "finalizer requires the direct transient-terminal launch path"
assert_grep_fixed '--expand-environment=no' "$KS_FILE" \
    "finalizer preserves the terminal shell command through systemd-run"
assert_grep_fixed '/usr/bin/sudo -- /usr/local/bin/noid-usbguard-devices' "$KS_FILE" \
    "finalizer requires the interactive USBGuard manager command"
assert_grep_fixed "grep -q '^IPAddressDeny=' \"\$m14_catchup_unit\"" "$KS_FILE" \
    "finalizer rejects the catch-up unit's unenforceable user IP firewall claim"
assert_grep_fixed "grep -Eq 'usbguard[[:space:]]+(allow-device|append-rule)'" \
    "$KS_FILE" "finalizer prevents the login catch-up from authorizing devices"
assert_grep_fixed 'Module 14 least-privilege named IPC contract invalid' \
    "$KS_FILE" "finalizer rejects broad or incomplete USBGuard IPC authorization"
assert_grep_fixed "grep -qF \"'Parameters=list,listen'\"" \
    "$KS_FILE" "finalizer requires the normal-user read-only parameter profile"
assert_grep_fixed '/usr/bin/gpasswd -d "$username" usbguard' \
    "$KS_FILE" "finalizer requires legacy broad group-grant cleanup"
assert_grep_fixed '/usr/local/bin/noid-usbguard-devices' "$KS_FILE" \
    "finalizer requires the unified USBGuard manager artifact"
assert_grep_fixed 'Module 14 unified USBGuard manager contract invalid' \
    "$KS_FILE" "finalizer makes USBGuard manager drift fatal"
assert_grep_fixed "ast.parse(pathlib.Path(\"/usr/local/bin/noid-usbguard-devices\").read_text())" \
    "$KS_FILE" "finalizer syntax-checks the manager without creating bytecode"
assert_grep_fixed 'runtime-only rules are loaded; refusing a save' "$KS_FILE" \
    "finalizer retains the runtime-policy persistence guard"
assert_grep_fixed 'ordered_parity = [rule.body for rule in rules] == durable_bodies' \
    "$KS_FILE" "finalizer retains exact daemon/file policy-order parity"
assert_grep_fixed 'run_usbguard("list-rules", "-d")' "$KS_FILE" \
    "finalizer binds the manager to USBGuard's supported device mapping"
assert_grep_fixed "grep -qF 'run_usbguard(\"list-devices\", match_query)'" \
    "$KS_FILE" "finalizer rejects the unsupported positional device query"
assert_grep_fixed "grep -qF 'os.execv(ALLOW_HELPER'" "$KS_FILE" \
    "finalizer binds the manager to the reviewed admission backend"
assert_grep_fixed 'fmt_section("Blocked USB devices")' "$KS_FILE" \
    "finalizer requires explicit blocked-device inventory"
assert_grep_fixed 'def rule_display_name(' "$KS_FILE" \
    "finalizer requires useful connected and portable-rule names"
assert_grep_fixed 'public CLI shared presentation contract invalid' "$KS_FILE" \
    "finalizer makes shared public CLI presentation drift fatal"
for cli_title in \
    'NoID Privacy — Network Gate' \
    'NoID Privacy — AIDE Check' \
    'NoID Privacy — LAN XDP Boundary'; do
    assert_grep_fixed "$cli_title" "$KS_FILE" \
        "finalizer pins public CLI title: $cli_title"
done
assert_grep_fixed "grep -qxF 'PartOf=graphical-session.target' \"\$m14_notifier_dropin\"" \
    "$KS_FILE" "finalizer pins notifier stop ownership"
assert_grep_fixed "grep -qF 'ConditionEnvironment=XDG_SESSION_CLASS=user' \"\$m14_notifier_dropin\"" \
    "$KS_FILE" "finalizer rejects the retired environment race"
assert_grep_fixed 'TimedLoginEnable=true' "$KS_FILE" \
    "finalizer requires native Live logout recovery"
assert_grep_fixed 'TimedLogin=liveuser' "$KS_FILE"
assert_grep_fixed 'TimedLoginDelay=1' "$KS_FILE"
assert_grep_fixed "grep -qF 'disable-log-out=true'" "$KS_FILE" \
    "finalizer rejects the GNOME power-submenu lockdown"
assert_grep_fixed "grep -qF '/org/gnome/desktop/lockdown/disable-log-out'" \
    "$KS_FILE" "finalizer rejects a persistent lock on that setting"
assert_grep_fixed 'Live power/logout lifecycle contract invalid' "$KS_FILE" \
    "finalizer makes Live power lifecycle drift fatal"
assert_grep_fixed 'optional /etc/chrony.d audit target invalid' "$KS_FILE" \
    "finalizer requires the directory whose missing state blocked all audit rules"
assert_grep_fixed 'STATUS_LIFECYCLE=build-time-placeholder' "$KS_FILE" \
    "finalizer requires an explicit staged platform lifecycle"

# The live payload cannot carry POSIX ACL xattrs in the current SquashFS
# toolchain. Require one canonical two-path manifest, an exact embedded copy,
# rollback-capable helper and an early unit before persistent journal use.
ACL_MANIFEST="$PROJECT_ROOT/manifests/live-payload-acls.tsv"
ACL_PARITY_GATE="$PROJECT_ROOT/tests/pre-ship/30-live-payload-acl-parity.sh"
assert_file_exists "$ACL_MANIFEST" "canonical live-payload ACL manifest exists"
assert_eq 2 "$(wc -l < "$ACL_MANIFEST")" \
    "ACL manifest contains exactly the two observed nontrivial paths"
assert_cmd_success "ACL manifest has a closed unique six-field schema" \
    awk -F'|' '
        NF != 6 || $1 !~ /^\/var\/(lib\/tpm2-tss\/system\/keystore|log\/journal)$/ ||
        $2 !~ /^[0-7]{4}$/ || $3 !~ /^[a-z_][a-z0-9_-]*$/ ||
        $4 !~ /^[a-z_][a-z0-9_-]*$/ || seen[$1]++ { bad=1 }
        END { exit bad }
    ' "$ACL_MANIFEST"
extract_heredoc "$KS_FILE" "LIVE_PAYLOAD_ACLS_EOF" \
    "$TEST_TMPDIR/live-payload-acls.tsv" || _fail "M99 ACL manifest extraction"
assert_cmd_success "deployed ACL manifest matches the canonical source" \
    cmp -s "$ACL_MANIFEST" "$TEST_TMPDIR/live-payload-acls.tsv"
extract_heredoc "$KS_FILE" "ACL_RESTORE_EOF" \
    "$TEST_TMPDIR/noid-restore-live-payload-acls" || _fail "ACL helper extraction"
chmod +x "$TEST_TMPDIR/noid-restore-live-payload-acls"
assert_eq '#!/usr/bin/bash' "$(head -n1 "$TEST_TMPDIR/noid-restore-live-payload-acls")" \
    "ACL helper uses an absolute trusted interpreter"
assert_cmd_success "ACL restore helper parses" \
    bash -n "$TEST_TMPDIR/noid-restore-live-payload-acls"
assert_cmd_success "ACL restore helper passes ShellCheck" \
    shellcheck "$TEST_TMPDIR/noid-restore-live-payload-acls"
assert_grep_fixed 'PATH=/usr/sbin:/usr/bin:/sbin:/bin' \
    "$TEST_TMPDIR/noid-restore-live-payload-acls" \
    "ACL helper ignores an inherited command-search path"
assert_grep_fixed 'if [ "$#" -ne 0 ]; then' \
    "$TEST_TMPDIR/noid-restore-live-payload-acls" \
    "ACL helper requires its exact argumentless service contract"
acl_arg_gate_line=$(grep -nF 'if [ "$#" -ne 0 ]; then' \
    "$TEST_TMPDIR/noid-restore-live-payload-acls" | cut -d: -f1)
acl_root_line=$(grep -nF 'ROOT="${NOID_ACL_ROOT:-/}"' \
    "$TEST_TMPDIR/noid-restore-live-payload-acls" | cut -d: -f1)
if [ "$acl_arg_gate_line" -lt "$acl_root_line" ]; then
    _pass "ACL helper rejects arguments before reading redirectable state"
else
    _fail "ACL helper rejects arguments before reading redirectable state"
fi
ACL_USAGE='Usage: noid-restore-live-payload-acls'
acl_reject_args() {
    local label=$1 rc
    shift
    if /usr/bin/bash "$TEST_TMPDIR/noid-restore-live-payload-acls" "$@" \
        >"$TEST_TMPDIR/acl-args.stdout" \
        2>"$TEST_TMPDIR/acl-args.stderr"; then
        rc=0
    else
        rc=$?
    fi
    assert_eq 2 "$rc" "ACL helper rejects hostile arguments: $label"
    assert_eq '' "$(cat "$TEST_TMPDIR/acl-args.stdout")" \
        "ACL helper emits no stdout for hostile arguments: $label"
    assert_eq "$ACL_USAGE" "$(cat "$TEST_TMPDIR/acl-args.stderr")" \
        "ACL helper emits one constant diagnostic for hostile arguments: $label"
}
acl_reject_args unknown --unknown
acl_reject_args empty ''
acl_reject_args surplus expected extra
acl_reject_args newline $'unexpected\nsecond-line'
acl_reject_args escape $'unexpected\033[31mred'
assert_grep_fixed 'setfacl -P --restore="$backup"' \
    "$TEST_TMPDIR/noid-restore-live-payload-acls" \
    "ACL helper rolls every staged path back on failure"
assert_grep_fixed 'actual=$(getfacl -cp -- "$full_path"' \
    "$TEST_TMPDIR/noid-restore-live-payload-acls" \
    "ACL helper verifies complete canonical ACL output"
assert_grep_fixed 'stage_parent="${NOID_ACL_STAGE_PARENT:-${ROOT%/}/run}"' \
    "$TEST_TMPDIR/noid-restore-live-payload-acls" \
    "ACL helper accepts only the unit-owned rollback parent override"
assert_grep_fixed '/run|/run/noid-live-payload-acls)' \
    "$TEST_TMPDIR/noid-restore-live-payload-acls" \
    "installed ACL rollback staging has a closed path contract"
assert_grep_fixed 'find "$stage" -xdev -mindepth 1 -delete || cleanup_failed=1' \
    "$TEST_TMPDIR/noid-restore-live-payload-acls" \
    "ACL helper removes scratch only within its task-owned filesystem boundary"
assert_grep_fixed 'rmdir -- "$stage" || cleanup_failed=1' \
    "$TEST_TMPDIR/noid-restore-live-payload-acls" \
    "ACL helper removes its exact task-owned directory last"
assert_grep_fixed '[ "$rc" -ne 0 ] || rc=1' \
    "$TEST_TMPDIR/noid-restore-live-payload-acls" \
    "ACL helper propagates scratch cleanup failure"
assert_not_grep 'rm -rf -- "$stage"' \
    "$TEST_TMPDIR/noid-restore-live-payload-acls" \
    "ACL helper has no recursive removal outside the bounded find walk"
for signal_contract in \
    "trap 'exit 129' HUP" \
    "trap 'exit 130' INT" \
    "trap 'exit 143' TERM"; do
    assert_grep_fixed "$signal_contract" \
        "$TEST_TMPDIR/noid-restore-live-payload-acls" \
        "ACL helper preserves conventional signal status: $signal_contract"
done
extract_heredoc "$KS_FILE" "ACL_UNIT_EOF" \
    "$TEST_TMPDIR/noid-live-payload-acl-restore.service" || _fail "ACL unit extraction"
assert_grep_fixed 'Before=systemd-journal-flush.service systemd-tmpfiles-setup.service sysinit.target' \
    "$TEST_TMPDIR/noid-live-payload-acl-restore.service" \
    "ACL restore precedes the first persistent journal flush"
assert_not_grep_extended '^PrivateTmp=(yes|true|1|on|y|t)$' \
    "$TEST_TMPDIR/noid-live-payload-acl-restore.service" \
    "ACL early unit cannot gain the implicit tmpfiles After= cycle"
assert_grep_fixed \
    "grep -qxE 'PrivateTmp=(yes|true|1|on|y|t)'" "$KS_FILE" \
    "finalizer rejects every true PrivateTmp spelling on the early ACL unit"
assert_grep_fixed 'Environment=NOID_ACL_STAGE_PARENT=/run/noid-live-payload-acls' \
    "$TEST_TMPDIR/noid-live-payload-acl-restore.service" \
    "ACL early unit selects its private rollback parent"
assert_grep_fixed 'RuntimeDirectory=noid-live-payload-acls' \
    "$TEST_TMPDIR/noid-live-payload-acl-restore.service" \
    "systemd creates the rollback parent without tmpfiles"
assert_grep_fixed 'RuntimeDirectoryMode=0700' \
    "$TEST_TMPDIR/noid-live-payload-acl-restore.service" \
    "ACL rollback parent is root-private"
assert_grep_fixed 'ReadWritePaths=/run/noid-live-payload-acls /var/log/journal -/var/lib/tpm2-tss/system/keystore' \
    "$TEST_TMPDIR/noid-live-payload-acl-restore.service" \
    "strict unit exposes only its scratch parent and the two target paths"
assert_grep_fixed 'CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_FSETID' \
    "$TEST_TMPDIR/noid-live-payload-acl-restore.service" \
    "ACL repair retains only the capabilities needed to restore owner, ACL and setgid mode"
assert_grep_fixed 'live-payload ACL restore scratch/ordering sandbox is unsafe' \
    "$KS_FILE" "final gate rejects the early-boot cycle and scratch drift"
sed 's#ExecStart=/usr/libexec/noid-restore-live-payload-acls#ExecStart=/bin/true#' \
    "$TEST_TMPDIR/noid-live-payload-acl-restore.service" \
    > "$TEST_TMPDIR/noid-live-payload-acl-restore.verify.service"
assert_cmd_success "ACL early-boot unit validates" \
    systemd-analyze verify "$TEST_TMPDIR/noid-live-payload-acl-restore.verify.service"
assert_grep_extended '^acl$' "$PROJECT_ROOT/kickstart/master.ks" \
    "ACL command package is an explicit compose dependency"
assert_file_executable "$ACL_PARITY_GATE" \
    "raw-SquashFS-installed ACL parity gate is executable"
assert_cmd_success "ACL parity gate parses" bash -n "$ACL_PARITY_GATE"

# Rootless exact-apply and rollback fixtures exercise the extracted installed
# helper without touching host ACLs.
ACL_FIXTURE="$TEST_TMPDIR/acl-root"
mkdir -p "$ACL_FIXTURE/run" \
    "$ACL_FIXTURE/var/lib/tpm2-tss/system/keystore" \
    "$ACL_FIXTURE/var/log/journal"
fixture_user=$(id -un)
fixture_group=$(id -gn)
awk -F'|' -v OFS='|' -v owner="$fixture_user" -v group="$fixture_group" \
    '{$3=owner; $4=group; print}' "$ACL_MANIFEST" \
    > "$TEST_TMPDIR/acl-fixture.tsv"
chmod 0700 "$ACL_FIXTURE/var/lib/tpm2-tss/system/keystore" \
    "$ACL_FIXTURE/var/log/journal"
setfacl -b -k "$ACL_FIXTURE/var/lib/tpm2-tss/system/keystore" \
    "$ACL_FIXTURE/var/log/journal"
assert_cmd_success "ACL helper establishes the exact fixture contract" \
    env PATH=/noid-hostile-path NOID_ACL_TEST_MODE=1 NOID_ACL_ROOT="$ACL_FIXTURE" \
        NOID_ACL_MANIFEST="$TEST_TMPDIR/acl-fixture.tsv" \
        /usr/bin/bash "$TEST_TMPDIR/noid-restore-live-payload-acls"
assert_cmd_success "successful ACL transaction removes rollback scratch" \
    bash -c \
        '! find "$1" -mindepth 1 -maxdepth 1 -name "noid-live-payload-acls.*" -print -quit | grep -q .' \
        _ "$ACL_FIXTURE/run"
while IFS='|' read -r path mode owner group access_acl default_acl; do
    fixture_path="$ACL_FIXTURE$path"
    assert_eq "$mode:$owner:$group" \
        "$(stat -c '%a:%U:%G' "$fixture_path")" \
        "fixture owner/mode exact for $path"
    expected_acl="$access_acl,$default_acl"
    actual_acl=$(getfacl -cp "$fixture_path" | sed '/^$/d' | paste -sd, -)
    assert_eq "$expected_acl" "$actual_acl" "fixture ACL exact for $path"
done < "$TEST_TMPDIR/acl-fixture.tsv"

chmod 0700 "$ACL_FIXTURE/var/lib/tpm2-tss/system/keystore" \
    "$ACL_FIXTURE/var/log/journal"
setfacl -b -k "$ACL_FIXTURE/var/lib/tpm2-tss/system/keystore" \
    "$ACL_FIXTURE/var/log/journal"
getfacl -p "$ACL_FIXTURE/var/lib/tpm2-tss/system/keystore" \
    > "$TEST_TMPDIR/keystore.before"
getfacl -p "$ACL_FIXTURE/var/log/journal" > "$TEST_TMPDIR/journal.before"
awk -F'|' -v OFS='|' -v bad='noid_missing_acl_group_fixture' \
    'NR == 2 {$4=bad} {print}' "$TEST_TMPDIR/acl-fixture.tsv" \
    > "$TEST_TMPDIR/acl-rollback.tsv"
assert_cmd_failure "ACL helper rejects an unresolvable second owner/group" \
    env NOID_ACL_TEST_MODE=1 NOID_ACL_ROOT="$ACL_FIXTURE" \
        NOID_ACL_MANIFEST="$TEST_TMPDIR/acl-rollback.tsv" \
        bash "$TEST_TMPDIR/noid-restore-live-payload-acls"
getfacl -p "$ACL_FIXTURE/var/lib/tpm2-tss/system/keystore" \
    > "$TEST_TMPDIR/keystore.after"
getfacl -p "$ACL_FIXTURE/var/log/journal" > "$TEST_TMPDIR/journal.after"
assert_cmd_success "failed transaction restores the first path byte-exactly" \
    cmp -s "$TEST_TMPDIR/keystore.before" "$TEST_TMPDIR/keystore.after"
assert_cmd_success "failed transaction restores the second path byte-exactly" \
    cmp -s "$TEST_TMPDIR/journal.before" "$TEST_TMPDIR/journal.after"
assert_cmd_success "failed ACL transaction removes rollback scratch" \
    bash -c \
        '! find "$1" -mindepth 1 -maxdepth 1 -name "noid-live-payload-acls.*" -print -quit | grep -q .' \
        _ "$ACL_FIXTURE/run"
ACL_FIND_FAIL_BIN="$TEST_TMPDIR/acl-find-fail-bin"
mkdir -p "$ACL_FIND_FAIL_BIN"
ln -s /usr/bin/false "$ACL_FIND_FAIL_BIN/find"
ACL_FIND_FAIL_HELPER="$TEST_TMPDIR/noid-restore-live-payload-acls-find-fail"
sed "s#^PATH=/usr/sbin:/usr/bin:/sbin:/bin\$#PATH=$ACL_FIND_FAIL_BIN:/usr/sbin:/usr/bin:/sbin:/bin#" \
    "$TEST_TMPDIR/noid-restore-live-payload-acls" > "$ACL_FIND_FAIL_HELPER"
chmod +x "$ACL_FIND_FAIL_HELPER"
assert_cmd_failure "ACL helper surfaces an injected scratch cleanup failure" \
    env NOID_ACL_TEST_MODE=1 NOID_ACL_ROOT="$ACL_FIXTURE" \
        NOID_ACL_MANIFEST="$TEST_TMPDIR/acl-fixture.tsv" \
        /usr/bin/bash "$ACL_FIND_FAIL_HELPER"
assert_cmd_success "injected cleanup failure leaves recoverable private evidence" \
    bash -c \
        'find "$1" -mindepth 1 -maxdepth 1 -name "noid-live-payload-acls.*" -print -quit | grep -q .' \
        _ "$ACL_FIXTURE/run"

# A bare module token in M99 can live in a comment or history note and is not
# evidence of an executable gate. Do not restore the former M01-M42 token loop;
# the exact adopter manifest below and the explicit per-contract assertions in
# this suite are the only claimed coverage.

# Finalize must preserve the user-owned AIDE trust boundary.
assert_not_grep_extended \
    '(^|[[:space:]])(/usr/(s)?bin/)?aide[[:space:]]+(-i|--init|-u|--update)([[:space:]]|$)' \
    "$KS_FILE" \
    "compose finalizer never creates an active AIDE baseline"
assert_not_grep 'mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz' \
    "$KS_FILE" "compose finalizer never commits a candidate database"
assert_grep_fixed 'compose produced forbidden AIDE trust state' "$KS_FILE" \
    "final gate rejects active or candidate AIDE databases"
assert_grep_fixed 'AIDE baseline: uninitialized; explicit user review required' "$KS_FILE" \
    "final log states the trust boundary"
assert_not_grep 'noid-privacy-linux.sh --refresh-noid-rpm-policy' "$KS_FILE" \
    "finalizer never asks the auditor to create expected state"
assert_not_grep 'chmod 0700 "$secure_dir"' "$KS_FILE" \
    "finalizer detects RPM metadata drift instead of normalizing it"
assert_not_grep 'ln -s ../default/grub' "$KS_FILE" \
    "finalizer detects a missing compatibility symlink instead of creating it"
assert_grep_fixed 'bundled auditor integration exact; default is non-remediating/offline' \
    "$KS_FILE" "finalizer reports the exact M40 payload/default wrapper boundary"
assert_grep_fixed 'audit_actual_sha=$(sha256sum "$audit_payload"' "$KS_FILE" \
    "finalizer re-verifies the installed auditor bytes"
assert_grep_fixed 'audit_actual_size=$(stat -c %s "$audit_payload"' "$KS_FILE" \
    "finalizer re-verifies the installed auditor byte count"
assert_grep_fixed 'readlink -e -- "$audit_payload"' "$KS_FILE" \
    "finalizer binds the canonical bundled-auditor path"
assert_grep_fixed "stat -Lc '%u:%g:%a:%h' \"\$audit_payload\"" "$KS_FILE" \
    "finalizer binds bundled-auditor ownership, mode and link count"
assert_grep_fixed 'matchpathcon -V "$audit_payload"' "$KS_FILE" \
    "finalizer binds the bundled-auditor SELinux label"
assert_grep_fixed 'matchpathcon -V "$audit_wrapper"' "$KS_FILE" \
    "finalizer binds the audit-wrapper SELinux label"
assert_grep_fixed "stat -Lc '%u:%g:%a:%h' \"\$audit_version_marker\"" "$KS_FILE" \
    "finalizer binds version-marker ownership, mode and link count"
assert_grep_fixed 'matchpathcon -V "$audit_version_marker"' "$KS_FILE" \
    "finalizer binds the version-marker SELinux label"
assert_grep_fixed 'audit_actual_wrapper_sha=$(sha256sum "$audit_wrapper"' "$KS_FILE" \
    "finalizer binds the exact audit-wrapper bytes"
assert_grep_fixed 'sha256sum "$audit_version_marker"' "$KS_FILE" \
    "finalizer binds the exact version-marker bytes"
assert_grep_fixed "stat -Lc '%u:%g:%a:%h' \"\$audit_stamp\"" "$KS_FILE" \
    "finalizer binds health-stamp ownership, mode and link count"
assert_grep_fixed 'matchpathcon -V "$audit_stamp"' "$KS_FILE" \
    "finalizer binds the health-stamp SELinux label"
M40_WRAPPER="$TEST_TMPDIR/99-m40-noid-audit"
extract_heredoc "$M40_KS_FILE" WRAPPER_EOF "$M40_WRAPPER" \
    || _fail "M40 deployed audit wrapper extracts"
for audit_wrapper_contract in \
    '    exec "$SUDO" -- "$ENV_BIN" "${root_environment[@]}" "$BASH_BIN" "$SCRIPT" "$@"' \
    '    AUDIT_ARGS=(--ai)' \
    'run_root_audit --offline "${AUDIT_ARGS[@]}"' \
    '    [ "$AIDE_LIVE" -eq 0 ] || root_environment+=(NOID_AIDE_LIVE=1)' \
    '        init) root_environment+=(NOID_RPM_BASELINE_INIT=1) ;;' \
    '        update) root_environment+=(NOID_RPM_BASELINE_UPDATE=1) ;;'; do
    assert_grep_fixed "$audit_wrapper_contract" "$M40_WRAPPER" \
        "M40 wrapper supplies final-gated execution contract: $audit_wrapper_contract"
    assert_grep_fixed "$audit_wrapper_contract" "$KS_FILE" \
        "M99 replays current M40 execution contract: $audit_wrapper_contract"
done
assert_grep_fixed "stat -Lc '%u:%g:%a:%h' \"\$audit_wrapper\"" "$KS_FILE" \
    "finalizer rejects linked, misowned or writable audit wrappers"
assert_grep_fixed '/usr/bin/bash -n "$audit_wrapper"' "$KS_FILE" \
    "finalizer rejects an invalid audit-wrapper program"
assert_not_grep 'exec sudo bash "$SCRIPT" --offline' "$KS_FILE" \
    "finalizer has no stale pre-helper M40 execution assertion"
assert_not_grep "grep -qE 'refresh-noid-rpm-policy|NOID_RPM_BASELINE_" "$KS_FILE" \
    "finalizer does not reject reviewed upstream opt-in RPM evidence workflows"
assert_grep_fixed 'forbidden self-generated RPM trust state present' "$KS_FILE"

# dconf binary database existence check — ensures M17+M08 compile step ran
assert_grep_fixed '/etc/dconf/db/distro' "$KS_FILE"

# Module 04 final gate binds the authoritative state guard and rejects every
# retired hookless shadow-table/reload artifact.
assert_grep_fixed '/usr/local/sbin/noid-arp-state-guard.sh' "$KS_FILE" \
    "finalizer requires M04's closed state validator"
assert_grep_fixed '/usr/share/noid-privacy/arp-hardening/90-arp-hardening.template' \
    "$KS_FILE" "finalizer requires the generated-dispatcher source"
assert_grep_fixed 'systemctl is-enabled noid-arp-state-guard.service' "$KS_FILE" \
    "finalizer requires the pre-network state guard to be enabled"
assert_grep_fixed \
    'ACTIVATION_MARKER_CONTENT="NOID_ARP_ACTIVATION_READY_V1"' "$KS_FILE" \
    "finalizer binds M04's exact versioned activation-generation assignment"
assert_grep_fixed \
    'gateway revalidation deferred until activation up event' \
    "$KS_FILE" "finalizer requires native event-generation coalescing"
assert_grep_fixed '&& ! publish_activation_marker; then' "$KS_FILE" \
    "finalizer requires post-refresh generation publication"
assert_grep_fixed \
    '/etc/systemd/system/NetworkManager.service.d/21-noid-arp-state-guard.conf' \
    "$KS_FILE" "finalizer binds NetworkManager to M04 state validation"
assert_grep_fixed 'retired non-enforcing artifact remains' "$KS_FILE" \
    "finalizer rejects M04's retired nft/firewalld shadow machinery"

# Module 05 uses maintained dconf policy and rejects package-owned GVfs drift.
assert_grep_fixed '/etc/dconf/db/distro.d/04-noid-lan-discovery' "$KS_FILE"
assert_grep_fixed '/etc/dconf/db/distro.d/locks/04-noid-lan-discovery' "$KS_FILE"
assert_grep_fixed 'rpm -V gvfs' "$KS_FILE"
assert_grep_fixed \
    'ARP_HARDENING_STATE="${NOID_ARP_HARDENING_STATE:-/var/lib/noid-privacy/arp-hardening.state}"' \
    "$KS_FILE" "final gate requires the LAN peer cleanup gateway-state boundary"
assert_grep_fixed \
    'ip neigh replace "$ip" lladdr "$PROTECTED_GATEWAY_MAC"' \
    "$KS_FILE" "final gate requires permanent gateway-pin restoration on peer revoke"
assert_grep_fixed \
    '[ "$PROTECTED_GATEWAY_ENABLED" = 1 ]' \
    "$KS_FILE" "final gate preserves M04's explicit kernel-pin opt-out"
assert_grep_fixed \
    '[ -x "$ARP_STATE_GUARD" ] && "$ARP_STATE_GUARD" || return 1' \
    "$KS_FILE" "final gate requires complete M04 lifecycle validation in M05"
assert_grep_fixed \
    'valid_global_allow_marker()' "$KS_FILE" \
    "final gate requires a closed global-widening marker"
assert_grep_fixed \
    'read_global_runtime_state()' "$KS_FILE" \
    "final gate requires validated unprivileged global-state reads"
assert_grep_fixed \
    'exec 8<>"$LAN_EXCEPTION_LOCK"' "$KS_FILE" \
    "final gate requires the non-truncating M05 transaction lock"
assert_grep_fixed \
    'raw ARP and kernel neighbour identity disagree' "$KS_FILE" \
    "final gate requires independent peer-identity observations"
assert_grep_fixed \
    'f /run/noid-privacy/lan-exceptions.lock 0600 root root -' "$KS_FILE" \
    "final gate requires the root-private M05 lock tmpfiles contract"
assert_grep_fixed \
    'f /run/noid-privacy/usbguard-add-user.lock 0600 root root -' "$KS_FILE" \
    "final gate requires the USBGuard reconciliation lock"
assert_grep_fixed \
    'z /run/noid-privacy/usbguard-add-user.lock 0600 root root -' "$KS_FILE" \
    "final gate requires the USBGuard lock SELinux relabel contract"
assert_grep_fixed \
    'f /run/noid-privacy/displaylink.lock 0600 root root -' "$KS_FILE" \
    "final gate requires the DisplayLink transaction lock"
assert_grep_fixed \
    'z /run/noid-privacy/displaylink.lock 0600 root root -' "$KS_FILE" \
    "final gate requires the DisplayLink lock SELinux relabel contract"
assert_grep_fixed \
    'Module 05 LAN state/peer identity contract is incomplete' \
    "$KS_FILE" "final gate names the complete M05 trust-boundary failure"
assert_grep_fixed \
    'Module 05 LAN expiry deadline generator is missing or invalid' \
    "$KS_FILE" "final gate requires the native dual-clock expiry generator"
assert_grep_fixed \
    '[ -L /usr/local/bin/noid-lan-allow ]' "$KS_FILE" \
    "final gate rejects a symlinked privileged LAN helper"
assert_not_grep 'noid-gvfs-silence.conf\|/usr/share/gvfs/mounts' "$KS_FILE" \
    "final gate does not require a package-file rewrite mechanism"
assert_grep_fixed '/usr/local/libexec/noid-wan-strict-endpoints' "$KS_FILE" \
    "final gate requires the libnm WAN endpoint authority"
assert_grep_fixed 'noid-wan-strict-endpoint-expiry.timer' "$KS_FILE" \
    "final gate requires bounded authenticated endpoint expiry"
assert_grep_fixed \
    'f /run/lock/noid-wan-strict.lock 0600 root root -' "$KS_FILE" \
    "final gate requires the root-private M06 controller lock"
assert_grep_fixed \
    'd /run/noid-privacy/wan-strict-active 0700 root root -' "$KS_FILE" \
    "final gate requires root-private volatile tunnel evidence"
assert_grep_fixed \
    'ReadWritePaths=/var/lib/noid-privacy /run/noid-privacy /run/lock/noid-wan-strict.lock' \
    "$KS_FILE" "final gate narrows M06 service writes to owned state"
assert_grep_fixed 'def nft_json(*arguments: str) -> list[object]:' "$KS_FILE" \
    "final gate requires machine-readable nft runtime evidence"
assert_grep_fixed 'raise fail("WAN strict is explicitly disabled")' "$KS_FILE" \
    "final gate requires the locked post-opt-out dispatcher barrier"
assert_grep_fixed 'opt-out leaves background lifecycle units enabled' "$KS_FILE" \
    "final gate rejects noisy M06 opt-out background work"
assert_grep_fixed 'AUTORESUME_SERVICE=noid-wan-strict-autoresume.service' \
    "$KS_FILE" "final gate requires transient auto-resume drain on opt-out"
assert_grep_fixed 'vpn_candidates_v4' "$KS_FILE" \
    "final gate requires separate bounded hostname candidates"
assert_grep_fixed 'obsolete universal WireGuard keepalive mutator present' "$KS_FILE" \
    "final gate rejects unobservable keepalive-intent overrides"
assert_grep_fixed 'obsolete Proton kill-switch profile mutator present' "$KS_FILE" \
    "final gate rejects provider-profile lifecycle interference"
assert_grep_fixed 'provider-compatible, user-overridable DNS contract invalid' \
    "$KS_FILE" "final gate requires Firefox and Thunderbird to honor system/VPN DNS"
assert_grep_fixed 'defaultPref("network.trr.mode", 5);' "$KS_FILE" \
    "final gate pins the user-overridable Mozilla DNS default"
assert_grep_fixed 'defaultPref("doh-rollout.home-region", "global");' "$KS_FILE" \
    "final gate keeps Mozilla provider choosers usable without country lookup"
assert_grep_fixed 'user_pref\("network\.trr\.' "$KS_FILE" \
    "final gate rejects profile-level Secure DNS preference resets"
assert_grep_fixed 'WAN lifecycle is not one atomic locked controller' "$KS_FILE" \
    "final gate rejects split table/control transactions"
assert_grep_fixed '"pause", "resume", "disable", "enable", "publish-status"' \
    "$KS_FILE" "final gate requires locked feature enable and disable actions"
assert_grep_fixed 'WAN threat/onboarding boundary is overstated or incomplete' \
    "$KS_FILE" "final gate rejects WAN malware/always-active hype"
assert_grep_fixed 'no automatic wall-clock expiry' "$KS_FILE" \
    "final gate requires the explicit bootstrap-grace expiry decision"
assert_grep_fixed 'Module 07 sysctl or gai.conf policy is incomplete/invalid' \
    "$KS_FILE" "final gate rejects invalid M07 sysctl or address-order policy"
assert_grep_fixed '700:/etc/NetworkManager/dispatcher.d/55-wan-ipv6-refresh' \
    "$KS_FILE" "final gate requires the root-private M07 dispatcher"
assert_grep_fixed '640:/etc/sysctl.d/98-privacy-network.conf' \
    "$KS_FILE" "final gate requires the reset-safe M07 sysctl filename"
assert_grep_fixed '[ -e /etc/sysctl.d/99-privacy-network.conf ]' \
    "$KS_FILE" "final gate rejects the retired ordering-defective filename"
assert_not_grep 'noid-ipv4-redirect-converge\|PathChanged=/run/libvirt/network' \
    "$KS_FILE" "final gate carries no redundant runtime convergence machinery"
assert_grep_fixed 'Module 07 artifact missing or unsafe' \
    "$KS_FILE" "final gate rejects M07 ownership, mode, link or type drift"
assert_grep_fixed 'scopev4 ::ffff:0.0.0.0/96       14' \
    "$KS_FILE" "final gate requires a valid IPv4-mapped default scope"
assert_grep_fixed "scopev4[[:space:]]+::/96[[:space:]]+14" \
    "$KS_FILE" "final gate rejects the silently ignored legacy scope line"
assert_grep_fixed 'Module 07 publishes a partial or overstated physical IPv6 mode' \
    "$KS_FILE" "final gate rejects the retired broken IPv6 reactivation recipe"
assert_grep_fixed 'Module 07 IPv6-off transition is not one locked pre-activation policy' \
    "$KS_FILE" "final gate requires the transactional IPv6-off pre-up contract"
assert_grep_fixed 'Module 07 runtime lock or firstboot sandbox is over-broad' \
    "$KS_FILE" "final gate requires the exact lock and least-privilege M07 unit"
assert_grep_fixed 'existing sysctl policy contains unexpected active directives' \
    "$KS_FILE" "final gate requires rejection of injected active M07 sysctls"
assert_grep_fixed 'Module 09 FIDO Ed25519 signature/certificate parity missing' \
    "$KS_FILE" "final gate requires client/server FIDO algorithm parity"
assert_grep_fixed 'Module 09 FIDO physical-presence policy missing' \
    "$KS_FILE" "final gate requires server-side FIDO touch enforcement"
assert_grep_fixed "'Compression no'" "$KS_FILE" \
    "final gate requires the mechanism-based compression policy"
assert_grep_fixed 'Module 09 changed RPM-owned /etc/ssh/moduli despite closed non-DH-GEX policy' \
    "$KS_FILE" "final gate rejects dead SSH package-file drift"
assert_grep_fixed 'rpm -Vf /etc/ssh/moduli' "$KS_FILE" \
    "final gate uses the RPM database as the moduli byte-integrity oracle"
assert_grep_fixed 'moduli_owner" != openssh' "$KS_FILE" \
    "final gate binds moduli to its exact owning package"
assert_grep_fixed \
    "grep -qE '(^|[[:space:]])/etc/ssh/moduli\$'" "$KS_FILE" \
    "final gate filters RPM verification drift to the exact moduli path"
assert_grep_fixed 'Module 09 lockout-safe opt-in transaction missing' \
    "$KS_FILE" "final gate requires every prepare/test/commit/rollback primitive"
assert_grep_fixed 'Module 09 opt-in guide weakens bootstrap auth or unmasks the extra socket' \
    "$KS_FILE" "final gate rejects unsafe SSH bootstrap shortcuts"
assert_grep_fixed 'Module 09 mechanism-accurate SSH client guidance missing' \
    "$KS_FILE" "final gate requires the complete SSH client trust boundary"
assert_grep_fixed 'Module 09 SSH client guide overclaims DNS, visual proof or secure deletion' \
    "$KS_FILE" "final gate rejects retired SSH privacy/erasure claims"
assert_grep_fixed 'Module 10 password length/composition/root policy invalid' \
    "$KS_FILE" "final gate requires the exact no-composition password policy"
assert_grep_fixed 'Module 10 native YESCRYPT cost 8 is not exact and unique' \
    "$KS_FILE" "final gate requires the measured native login.defs cost"
assert_not_grep 'obsolete unbenchmarked YESCRYPT cost pin remains' \
    "$KS_FILE" "final gate does not reject M10's supported native cost"
assert_grep_fixed \
    "M10_AUTHSELECT_EXPECTED='local with-silent-lastlog without-nullok with-faillock with-pwhistory with-pamaccess'" \
    "$KS_FILE" "final gate requires the exact five-feature Fedora profile"
assert_grep_fixed 'authselect current -r' "$KS_FILE" \
    "final gate uses authselect's machine-readable state"
assert_grep_fixed 'authselect check >/dev/null' "$KS_FILE" \
    "final gate validates authselect-owned checksums"
assert_grep_fixed 'Module 10 exact five-feature authselect state or private evidence invalid' \
    "$KS_FILE" "final gate binds profile, checksums and private evidence"
assert_grep_fixed 'Module 10 vendor yescrypt or self-contained PAM path invalid' \
    "$KS_FILE" "final gate requires yescrypt and rejects the oddjobd session path"
assert_grep_fixed "grep -qF 'pam_oddjob_mkhomedir.so'" \
    "$KS_FILE" "final gate rejects the disabled home-helper module"
assert_grep_fixed '/etc/security/pwhistory.conf' "$KS_FILE" \
    "final gate requires the explicit password-history policy"
assert_grep_fixed '/etc/security/opasswd' "$KS_FILE" \
    "final gate requires the password-history backing store"
assert_grep_fixed 'Module 10 password-history policy or backing-store metadata invalid' \
    "$KS_FILE" "final gate verifies history semantics and root-only state"
assert_grep_fixed 'Module 10 pam_access policy or metadata invalid' \
    "$KS_FILE" "final gate verifies the fail-closed login policy"
assert_grep_fixed 'Module 10 sudo PAM non-login session contract invalid' \
    "$KS_FILE" "final gate verifies sudo's supported non-login PAM session"
assert_grep_fixed \
    "m10_sudo_pam_line='session    optional     pam_env.so conffile=/etc/security/pam_env-sudo.conf readenv=0 user_readenv=0'" \
    "$KS_FILE" "final gate disables both mutable PAM environment sources"
assert_grep_fixed 'include_nr > env_nr' "$KS_FILE" \
    "final gate requires the service-local environment before system-auth"
assert_grep_fixed \
    "rpm -qf --qf '%{NAME}' \"\$m10_sudo_pam\"" \
    "$KS_FILE" "final gate binds the modified PAM service to Fedora's sudo RPM"
assert_grep_fixed 'Module 10 GnuPG skel policy or metadata invalid' \
    "$KS_FILE" "final gate verifies new-user GnuPG defaults"
assert_grep_fixed "Module 10 overrides systemd's maintained inhibitor capacity" \
    "$KS_FILE" "final gate rejects the retired 16-inhibitor cap"
assert_grep_fixed 'image overrides GNOME/vendor idle, key or lid ownership' \
    "$KS_FILE" "final gate rejects competing compose-time desktop power overrides"
assert_grep_fixed 'Module 10 login.defs privacy/local-account policy is not exact and unique' \
    "$KS_FILE" "final gate requires exact privacy and native home defaults"
for login_contract in \
    'LOG_OK_LOGINS no' \
    'LOG_UNKFAIL_ENAB no' \
    'FAIL_DELAY 4' \
    'UMASK 022' \
    'HOME_MODE 0700' \
    'CREATE_HOME yes' \
    'ENCRYPT_METHOD YESCRYPT' \
    'PASS_MAX_DAYS 99999'; do
    assert_grep_fixed "$login_contract" "$KS_FILE" \
        "final gate carries login.defs contract: $login_contract"
done
assert_grep_fixed 'Module 10 defensive sudo !fqdn state missing' \
    "$KS_FILE" "final gate retains explicit noncanonical sudo host matching"
assert_grep_fixed 'Module 10 command-scoped DNF umask missing' \
    "$KS_FILE" "final gate requires public DNF system state after sudo transactions"
assert_grep_fixed 'Module 10 interactive-only umask guard invalid' \
    "$KS_FILE" "final gate rejects a global login-shell umask mutation"
assert_grep_fixed 'Module 10 locked/atomic Bash history contract invalid' \
    "$KS_FILE" "final gate requires serialized atomic prompt compaction"
assert_grep_fixed '/usr/local/libexec/noid-bash-history-compact|root:root:755' \
    "$KS_FILE" "final gate enforces Bash history compactor ownership and mode"
assert_grep_fixed '/etc/profile.d/98-noid-bash-history.sh|root:root:644' \
    "$KS_FILE" "final gate enforces Bash history profile ownership and mode"
assert_grep_fixed "grep -qE 'unset[[:space:]]+PROMPT_COMMAND|PROMPT_COMMAND=\"history -a'" \
    "$KS_FILE" "final gate rejects destructive prompt-hook handling"
M10_HISTORY_COMPACTOR="$TEST_TMPDIR/noid-bash-history-compact"
extract_heredoc "$M10_KS_FILE" HIST_COMPACT_EOF "$M10_HISTORY_COMPACTOR" \
    || _fail "M10 Bash-history compactor extraction"
chmod +x "$M10_HISTORY_COMPACTOR"
assert_cmd_success "deployed M10 Bash-history compactor parses" \
    bash -n "$M10_HISTORY_COMPACTOR"
for dedup_contract in \
    'declare -a retained_reversed=()' \
    'for ((history_offset=1;' \
    'builtin fc -ln -- "-${history_offset}" "-${history_offset}"' \
    'if [[ "$history_value" == "$retained_value" ]]; then' \
    '(( duplicate == 1 )) || retained_reversed+=("$history_value")' \
    'builtin history -s -- "${retained_reversed[history_index]}"' \
    'builtin history -w "$1"'; do
    assert_grep_fixed "'$dedup_contract'" "$KS_FILE" \
        "M99 final gate requires the deployed dedup contract: $dedup_contract"
    assert_grep_fixed "$dedup_contract" "$M10_HISTORY_COMPACTOR" \
        "deployed M10 compactor supplies the final-gated contract: $dedup_contract"
done
M99_M10_FC_PREFIX="$TEST_TMPDIR/m99-m10-fc-prefix"
if extract_heredoc "$KS_FILE" M10_FC_PREFIX_EOF "$M99_M10_FC_PREFIX"; then
    _pass "M99 exact fc-prefix literal extracts"
else
    _fail "M99 exact fc-prefix literal extracts"
fi
assert_grep_fixed 'grep -qF "$M10_FC_PREFIX_LITERAL"' \
    "$KS_FILE" "M99 final gate uses its byte-exact fc-prefix literal"
assert_grep_fixed "[[ \"\${history_value:0:2}\" == \$'\\''\\t '\\'' ]] || exit 2" \
    "$M10_HISTORY_COMPACTOR" \
    "deployed compactor validates fc framing before exposing event data"
assert_cmd_success "M99 fc-prefix literal matches the exact deployed compactor bytes" \
    grep -qFf "$M99_M10_FC_PREFIX" "$M10_HISTORY_COMPACTOR"
assert_grep_fixed "grep -qF 'builtin history -p \"!\${history_index}\"'" \
    "$KS_FILE" "M99 rejects the option-reparsing history expansion path"
if grep -qF 'builtin history -p "!${history_index}"' "$M10_HISTORY_COMPACTOR"; then
    _fail "deployed compactor contains no option-reparsing history expansion path"
else
    _pass "deployed compactor contains no option-reparsing history expansion path"
fi
assert_not_grep 'builtin history -d "1-\$excess"' "$KS_FILE" \
    "final gate has no stale pre-dedup Bash-event deletion contract"
assert_not_grep 'builtin history -d "1-\$excess"' "$M10_HISTORY_COMPACTOR" \
    "deployed compactor has no stale pre-dedup deletion path"
assert_grep_fixed "'unset HISTFILE HISTSIZE HISTFILESIZE HISTTIMEFORMAT'" \
    "$KS_FILE" "final gate blocks inherited physical-line retruncation"
assert_grep_fixed "printf '#0\\\\n' > \\\"\\\$parse_tmp\\\"" \
    "$KS_FILE" "final gate requires detected mixed timestamp framing canonicalization"
assert_grep_fixed 'grep -qF '\''[[ "$history_line" =~ ^#[0-9]+$ ]]'\''' \
    "$KS_FILE" "final gate requires numeric timestamp-record detection"
assert_grep_fixed "'if (( timestamp_framing == 1 )); then'" \
    "$KS_FILE" "final gate requires conditional timestamp framing"
assert_grep_fixed "'\"\$history_dir/.\${history_base}.noid-parse.\"*'" \
    "$KS_FILE" "final gate requires exact SIGKILL-leftover cleanup"
assert_grep_fixed "'rm -f -- \"\$parse_tmp\"'" "$KS_FILE" \
    "final gate requires successful full-history-copy cleanup"
assert_grep_fixed '/usr/share/anaconda/noid-target-kernel-cmdline.ks' \
    "$KS_FILE" "M99 requires the inspectable target-karg suffix"
assert_grep_fixed 'interactive_timezone_count=$(grep -Ec' "$KS_FILE" \
    "M99 counts every active interactive-installer timezone directive"
assert_grep_fixed "interactive_utc_count=\$(grep -cEx 'timezone UTC --utc'" \
    "$KS_FILE" "M99 requires the one exact neutral installer timezone"
assert_grep_fixed 'Module 01 interactive installer timezone is not exactly neutral UTC' \
    "$KS_FILE" "M99 blocks a non-neutral or ambiguous installer timezone"
assert_grep_fixed '/usr/libexec/noid-rebind-firstboot-rootflags' \
    "$KS_FILE" "M99 requires the bounded M01 rootflags handoff"
assert_grep_fixed 'Module 01 obsolete detached target-karg script remains' \
    "$KS_FILE" "M99 rejects the retired inert Anaconda post-scripts artifact"
assert_grep_fixed 'Module 01 Fedora tuned/BLS transport boundary invalid' \
    "$KS_FILE" "M99 binds semantic kernel args to native Fedora BLS transport"
assert_grep_fixed 'expected_bls_options="$merged \$tuned_params"' \
    "$KS_FILE" "M99 requires exact target-install tuned macro placement"
assert_grep_fixed 'bls_options="$merged \$tuned_params"' \
    "$KS_FILE" "M99 requires exact firstboot tuned macro placement"
assert_grep_fixed 'Module 10 permission contract invalid' "$KS_FILE" \
    "final gate binds every stripped/native mode to its RPM owner"
assert_grep_fixed 'Module 11 local-VT authenticated time-recovery boundary invalid' \
    "$KS_FILE" "final gate requires the manual authenticated clock-seed boundary"
assert_grep_fixed '/usr/share/doc/noid-privacy/11-nts-sources.tsv' "$KS_FILE" \
    "final gate requires the dated NTS operator manifest"
assert_grep_fixed 'NR == 7 && review_date != "" && bad == 0' "$KS_FILE" \
    "final gate requires six closed rows plus one manifest-owned review date"
assert_grep_fixed '$6 != review_date' "$KS_FILE" \
    "final gate rejects mixed NTS operator review dates"
assert_grep_fixed 'Module 11 dated NTS operator manifest/config contract invalid' \
    "$KS_FILE" "final gate binds chrony.conf to the dated operator manifest"
assert_grep_fixed "grep -qE '^server ntppool[34]\\.time\\.nl '" "$KS_FILE" \
    "final gate rejects SIDN pre-production sources"
assert_grep_fixed \
    "print \"server \" \$1 \" iburst nts ipv4 maxpoll 11 offline\"" "$KS_FILE" \
    "final gate generates the exact expected chrony lines from the manifest"
assert_grep_fixed '/usr/local/sbin/noid-time-recovery' "$KS_FILE" \
    "final gate requires the M11 recovery helper"
assert_grep_fixed '/usr/share/doc/noid-privacy/11-time-recovery.md' "$KS_FILE" \
    "final gate requires the M11 recovery guide"
assert_grep_fixed "grep -qE '^[[:space:]]*nocerttimecheck" "$KS_FILE" \
    "final gate rejects an NTS certificate-time bypass"
assert_grep_fixed 'Module 11 native restricted chronyd service/provider contract invalid' \
    "$KS_FILE" "final gate requires the Fedora restricted NTS client"
assert_grep_fixed 'rpm_payload_file_pristine chrony "$m11_restricted_unit"' "$KS_FILE" \
    "final gate requires byte identity for the vendor restricted unit"
assert_grep_fixed 'rpm_payload_file_pristine chrony /etc/sysconfig/chronyd' "$KS_FILE" \
    "final gate requires byte identity for the vendor -F 2 options"
assert_grep_fixed "'%{FILEDIGESTALGO}'" "$KS_FILE" \
    "final gate requires SHA-256 RPM payload records"
assert_grep_fixed "'[%{FILENAMES}\\t%{FILEDIGESTS}\\n]'" "$KS_FILE" \
    "final gate selects the exact RPM-owned file digest"
for chronyd_contract in \
    'SELinuxContext=system_u:system_r:chronyd_restricted_t:s0' \
    'User=chrony' \
    'CapabilityBoundingSet=CAP_SYS_TIME' \
    'DevicePolicy=closed' \
    'MemoryDenyWriteExecute=yes' \
    'NoNewPrivileges=yes' \
    'PrivateDevices=yes' \
    'ProtectProc=invisible' \
    'ProtectSystem=strict' \
    'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX'; do
    assert_grep_fixed "$chronyd_contract" "$KS_FILE" \
        "final gate pins restricted chronyd property: $chronyd_contract"
done
assert_grep_fixed "grep -cFx 'chronyd-restricted.service'" "$KS_FILE" \
    "timedated provider has one exact active service line"
assert_grep_fixed 'systemctl is-enabled chronyd-restricted.service' "$KS_FILE" \
    "restricted client must be enabled"
assert_grep_fixed \
    'systemctl is-enabled noid-chrony-network-online.service' "$KS_FILE" \
    "readiness consumer must be enabled"
assert_grep_fixed \
    'ConditionPathExists=/run/noid-privacy/gateway-xdp.ready' "$KS_FILE" \
    "final gate binds NTS activation to the M04 readiness marker"
assert_grep_fixed \
    'ExecStart=/usr/local/libexec/noid-network-readiness online-consumer' \
    "$KS_FILE" "final gate requires boundary revalidation before NTS activation"
assert_grep_fixed "grep -qxF 'Restart=on-failure'" "$KS_FILE" \
    "final gate requires automatic recovery after bounded resolver failure"
assert_grep_fixed "grep -qxF 'RestartSec=30s'" "$KS_FILE" \
    "final gate pins the initial NTS recovery delay"
assert_grep_fixed "grep -qxF 'RestartSteps=4'" "$KS_FILE" \
    "final gate pins native exponential NTS recovery backoff"
assert_grep_fixed "grep -qxF 'RestartMaxDelaySec=15min'" "$KS_FILE" \
    "final gate bounds prolonged NTS recovery cadence"
assert_grep_fixed \
    'ExecStart=/usr/local/libexec/noid-network-readiness offline-consumer' \
    "$KS_FILE" "final gate requires a dedicated SELinux-compatible offline transition"
assert_grep_fixed \
    'm11_offline_readiness_unit=/etc/systemd/system/noid-chrony-network-offline.service' \
    "$KS_FILE" "final gate verifies the static NTS offline one-shot"
assert_grep_fixed \
    'CHRONY_TRANSITION_LOCK=/run/chrony/noid-network-readiness.lock' \
    "$KS_FILE" "final gate requires serialized online/offline chrony transitions"
assert_grep_fixed 'WantedBy=chronyd-restricted.service' "$KS_FILE" \
    "final gate reconsumes readiness after a native daemon restart"
assert_grep_fixed \
    '[ -e /etc/systemd/system/noid-chrony-network-online.path ]' "$KS_FILE" \
    "final gate rejects the retired readiness path prototype"
assert_grep_fixed 'systemctl is-enabled chronyd.service' "$KS_FILE" \
    "ordinary client must remain disabled"
assert_grep_fixed 'm11_preset_file=/etc/systemd/system-preset/05-noid-chrony.preset' \
    "$KS_FILE" "final gate requires the native target-transaction preset"
assert_grep_fixed '/usr/bin/systemctl start chronyd-restricted.service' "$KS_FILE" \
    "recovery helper must restore the restricted client"
assert_grep_fixed 'Module 12 selected SELinux module/update-reconcile contract invalid' \
    "$KS_FILE" "final gate requires the exact selected custom policy and update boundary"
assert_grep_fixed 'm12_reconcile=/usr/local/sbin/noid-selinux-policy-reconcile' \
    "$KS_FILE" "final gate requires the policy-update reconcile helper"
assert_grep_fixed 'm12_action=/etc/dnf/libdnf5-plugins/actions.d/noid-selinux-policy.actions' \
    "$KS_FILE" "final gate requires the targeted-policy package action"
assert_grep_fixed \
    'post_transaction:selinux-policy-targeted:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-selinux-policy-reconcile\ >/dev/null' \
    "$KS_FILE" "final gate pins the fail-closed policy-update action"
assert_grep_fixed 'Module 12 audit ABI/time-adjustment coverage contract invalid' \
    "$KS_FILE" "final gate requires exact dual-ABI audit coverage"
assert_grep_fixed "-ne 132 ]" "$KS_FILE" \
    "final gate requires the canonical 132-rule payload"
assert_grep_fixed 'Module 12 measured retention/degradation action contract invalid' \
    "$KS_FILE" "final gate requires the measured audit storage policy"
M09_SSH_CLIENT="$TEST_TMPDIR/99-m09-ssh-client.conf"
extract_heredoc "$M09_KS_FILE" SSH_EOF "$M09_SSH_CLIENT" \
    || _fail "M09 SSH client payload extraction"
assert_cmd_success "M99 exact SSH host-certificate preference matches M09 payload" \
    grep -qxF \
    '    HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512' \
    "$M09_SSH_CLIENT"
assert_grep_fixed \
    "'    HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512'" \
    "$KS_FILE" "M99 checks the exact indented M09 client directive"
M12_AUDIT_NOTIFY="$TEST_TMPDIR/99-m12-audit-storage-notify"
extract_heredoc "$M12_KS_FILE" AUDIT_STORAGE_NOTIFY_EOF "$M12_AUDIT_NOTIFY" \
    || _fail "M12 audit-storage notifier extraction"
assert_cmd_success "M99 option-safe notification timeout matches M12 payload" \
    grep -qF -- \
    '--reset-env /usr/bin/timeout --signal=TERM --kill-after=1s 5s' \
    "$M12_AUDIT_NOTIFY"
assert_grep_fixed "|| ! grep -qF -- \\" "$KS_FILE" \
    "M99 terminates grep options before the M12 setpriv fragment"
assert_grep_fixed 'sed '\''s/arch=b64/arch=ABI/'\''' "$KS_FILE" \
    "final gate compares normalized b64 rules"
assert_grep_fixed 'sed '\''s/arch=b32/arch=ABI/'\''' "$KS_FILE" \
    "final gate compares normalized b32 rules"
assert_grep_fixed 'clock_adjtime -k time_change' "$KS_FILE" \
    "final gate requires modern daemon-inclusive time evidence"
assert_grep_fixed "'-F path=/etc/aide.conf -F perm=wa -F obj_type=etc_t -k aide_integrity'" \
    "$KS_FILE" "final gate requires exact AIDE configuration audit coverage"
assert_grep_fixed "'-F dir=/var/lib/aide -F perm=wa -k aide_integrity'" \
    "$KS_FILE" "final gate requires exact AIDE database-directory coverage"
assert_grep_fixed 'Module 12 /var/lib/aide audit target invalid' \
    "$KS_FILE" "final gate requires a real root-only AIDE audit target"
assert_grep_fixed 'grep -qF '\''"aide_integrity",'\''' \
    "$KS_FILE" "final gate requires AIDE changes in the critical notification set"
assert_grep_fixed 'space_left_action = EXEC /usr/local/sbin/noid-audit-space-alert' \
    "$KS_FILE" "final gate requires a persistent low-space alert action"
assert_grep_fixed 'admin_space_left_action = EXEC /usr/local/sbin/noid-audit-space-critical' \
    "$KS_FILE" "final gate requires the visible critical-suspend action"
assert_grep_fixed 'disk_full_action = ROTATE' "$KS_FILE" \
    "final gate requires survivable bounded-ring rotation on a full device"
assert_grep_fixed "grep -qE '^[[:space:]]*(if ! )?auditctl --signal resume'" \
    "$KS_FILE" "final gate rejects a critical helper that executes a resume"
assert_grep_fixed 'PathModified=/run/noid-privacy/audit-storage-degraded' \
    "$KS_FILE" "final gate binds the storage-marker session notifier"
assert_grep_fixed 'semanage boolean -E' "$KS_FILE" \
    "final gate reads native persistent SELinux boolean overrides"
assert_grep_fixed 'grep -xcF "boolean -m -0 $m12_boolean"' "$KS_FILE" \
    "final gate requires each execution restriction exactly once"
assert_grep_fixed "stat -c '%U:%G:%a:%h' /usr/local/libexec/noid-audit-storage-notify" \
    "$KS_FILE" "final gate rejects linked or misowned storage notifiers"
assert_grep_fixed 'matchpathcon -V /usr/local/libexec/noid-audit-storage-notify' \
    "$KS_FILE" "final gate validates storage-notifier SELinux labels"
assert_grep_fixed 'CapabilityBoundingSet=CAP_SETGID CAP_SETUID' \
    "$KS_FILE" "final gate pins notifier privilege-drop capabilities"
assert_grep_fixed 'TimeoutStartSec=30s' \
    "$KS_FILE" "final gate requires a bounded notifier oneshot"
assert_grep_fixed 'InaccessiblePaths=/home /root' \
    "$KS_FILE" "final gate hides home data without hiding /run/user"
assert_grep_fixed 'ProtectHome=read-only' \
    "$KS_FILE" "final gate leaves session buses visible but immutable"
assert_grep_fixed 'RestrictAddressFamilies=AF_UNIX' \
    "$KS_FILE" "final gate keeps storage notification local-only"
assert_grep_fixed "grep -qF -- '--property=LockedHint'" \
    "$KS_FILE" "final gate requires locked-session suppression"
assert_grep_fixed "grep -qF 'loginctl list-users'" \
    "$KS_FILE" "final gate rejects generic logged-in-user targeting"
assert_grep_fixed 'os.O_RDONLY | os.O_DIRECTORY' "$KS_FILE" \
    "final gate requires crash-durable plugin state replacement"
assert_grep_fixed 'notification-worker-{type(error).__name__}' "$KS_FILE" \
    "final gate requires unexpected worker failures to stay visible"
assert_grep_fixed 'initial-health-write-failed' "$KS_FILE" \
    "final gate requires startup health failure to degrade visibly"
assert_grep_fixed 'final-health-write-failed' "$KS_FILE" \
    "final gate requires final health failure to degrade visibly"
assert_grep_fixed 'module noid-selinux-fixes 1.9;' "$KS_FILE" \
    "final gate pins the current module version"
assert_grep_fixed "grep -qxF 'allow init_t auditd_etc_t:dir mounton;'" "$KS_FILE" \
    "final gate requires the audit controller sandbox mount-point edge"
assert_grep_fixed "grep -qxF 'allow passwd_t hugetlbfs_t:file { read write map };'" "$KS_FILE" \
    "final gate requires the Yescrypt password-creation HugeTLB edge"
assert_grep_fixed "grep -qxF 'allow chkpwd_t hugetlbfs_t:file { read write map };'" "$KS_FILE" \
    "final gate requires the Yescrypt password-check HugeTLB edge"
assert_grep_fixed "grep -qxF 'allow updpwd_t hugetlbfs_t:file { read write map };'" "$KS_FILE" \
    "final gate requires the Yescrypt password-history HugeTLB edge"
assert_grep_fixed '/usr/libexec/selinux/hll/pp "$m12_pp"' "$KS_FILE" \
    "final gate derives the vendor CIL checksum from the retained package"
assert_grep_fixed 'semodule -lfull -m' "$KS_FILE" \
    "final gate inspects every module-store priority"
assert_grep_fixed 'grep -qE '\''unconfined_t|user_tmp_t|execmod'\''' "$KS_FILE" \
    "final gate rejects the broad user-domain execmod rule"
assert_grep_fixed 'Fedora liveinst RPM payload is not pristine' "$KS_FILE" \
    "final gate rejects a modified Live-installer payload"
assert_grep_fixed 'rpm_payload_file_pristine anaconda-live /usr/bin/liveinst' "$KS_FILE" \
    "final gate scopes liveinst identity to its exact RPM file record"
assert_not_grep 'rpm -Vf /usr/bin/liveinst' "$KS_FILE" \
    "final gate ignores intentional branding drift in package siblings"
assert_grep_fixed 'native permission policy/action metadata or trigger count invalid' \
    "$KS_FILE" "final gate requires exact native artifacts and five triggers"
assert_grep_fixed 'exact dnf5 permission trigger missing' "$KS_FILE" \
    "final gate verifies every transaction trigger byte-exactly"
assert_grep_fixed 'enabled=host-only raise_error=1:/usr/bin/sh -c /usr/bin/systemd-tmpfiles' \
    "$KS_FILE" "permission reconciliation cannot escape an installroot transaction"
assert_grep_fixed 'NVIDIA installer lacks host-scoped action' "$KS_FILE" \
    "final gate requires both opt-in NVIDIA actions to remain host-scoped"
assert_grep_fixed 'Module 32 host-scoped identity/branding action contract invalid' \
    "$KS_FILE" "final gate requires exact host-scoped identity and branding actions"
assert_grep_fixed \
    'post_transaction:fedora-release*:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-restore-identity\ >/dev/null' \
    "$KS_FILE" "final gate pins host-only identity recovery"
assert_grep_fixed \
    'post_transaction:generic-logos*:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-restore-branding\ >/dev/null' \
    "$KS_FILE" "final gate pins host-only generic-logos recovery"
for native_spec in \
    '/usr/bin/chage|4755|shadow-utils' \
    '/usr/bin/pam_timestamp_check|4755|pam' \
    '/usr/bin/userhelper|4711|usermode' \
    '/usr/libexec/libgtop_server2|4755|libgtop2'; do
    assert_grep_fixed "$native_spec" "$KS_FILE" \
        "final gate retains load-bearing Fedora SUID: ${native_spec%%|*}"
done
assert_grep_fixed 'root-only policy directory invalid' "$KS_FILE" \
    "final gate verifies effective cron/sudoers directory modes"
assert_grep_fixed 'dbus_admin_dir=/usr/local/share/dbus-1/services' "$KS_FILE" \
    "final gate checks the standard D-Bus admin directory"
assert_grep_fixed 'dbus_policy=/etc/dbus-1/session.d/20-noid-blocked-services.conf' \
    "$KS_FILE" "final gate binds the reference-bus fallback policy"
assert_grep_fixed 'dbus_block_unit=/etc/systemd/user/noid-blocked-session-service.service' \
    "$KS_FILE" "final gate binds the immediate static activation mask"
assert_grep_fixed 'gnome_software_admin_service="$dbus_admin_dir/org.gnome.Software.service"' \
    "$KS_FILE" "final gate rejects the redundant Software service override"
assert_grep_fixed "grep -qxF 'SystemdService=gnome-software.service'" \
    "$KS_FILE" "final gate requires Fedora's native Software activation route"
assert_grep_fixed 'immediate D-Bus denial/vendor-integrity contract invalid' \
    "$KS_FILE" "final gate binds admin, native Tracker and vendor descriptors"
assert_grep_fixed 'matchpathcon -V "$dbus_policy"' "$KS_FILE" \
    "final gate verifies the session-bus policy SELinux label"
assert_grep_fixed 'rpm -q --dump "$vendor_package"' "$KS_FILE" \
    "final gate verifies vendor bytes against RPM records"
assert_grep_fixed 'm17_gs_vendor_desktop=/usr/share/applications/org.gnome.Software.desktop' \
    "$KS_FILE" "final gate binds Fedora's GNOME Software launcher"
assert_grep_fixed 'm17_gs_admin_desktop=/usr/local/share/applications/org.gnome.Software.desktop' \
    "$KS_FILE" "final gate binds the explicit-launch admin override"
assert_grep_fixed 'post_transaction:gnome-software:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-gnome-software-launcher-sync\ >/dev/null' \
    "$KS_FILE" "final gate pins the package-scoped launcher resync"
assert_grep_fixed '--set-key=DBusActivatable --set-value=false' "$KS_FILE" \
    "final gate independently preserves direct launcher execution"
assert_grep_fixed '--set-key=Actions' "$KS_FILE" \
    "final gate independently references both NoID Privacy actions"
assert_grep_fixed 'm17_gs_rpm=/usr/local/bin/noid-gnome-software-rpm' \
    "$KS_FILE" "final gate owns the Fedora-RPM one-shot helper"
assert_grep_fixed 'Exec=/usr/local/bin/noid-gnome-software-rpm' "$KS_FILE" \
    "final gate requires the Fedora-RPM desktop action"
assert_grep_fixed 'NoIDFedoraRPM;NoIDQuit;' "$KS_FILE" \
    "final gate pins the one-shot-before-quit action order"
assert_grep_fixed 'Exec=/usr/local/bin/noid-gnome-software-quit' "$KS_FILE" \
    "final gate requires GNOME Software's graceful idle-release path"
assert_grep_fixed 'm17_gs_backend_stop=/usr/local/sbin/noid-gnome-software-backend-stop' \
    "$KS_FILE" "final gate owns the privileged idle-backend helper"
assert_grep_fixed 'grep -qF "expected_tree=\$' "$KS_FILE" \
    "final gate matches the backend helper's named idle-tree assignment"
assert_grep_fixed '/\\n/org\\n/org/rpm\\n/org/rpm/dnf\\n/org/rpm/dnf/v0' \
    "$KS_FILE" "final gate requires the exact sessionless DNF object tree"
assert_grep_fixed \
    '%wheel ALL=(root) NOPASSWD: /usr/local/sbin/noid-gnome-software-backend-stop ""' \
    "$KS_FILE" "final gate requires the argumentless sudoers command"
assert_grep_fixed "grep -cEv '^[[:space:]]*(#|$)'" "$KS_FILE" \
    "final gate counts active sudoers commands independently of comments"
assert_not_grep_extended 'wc -l.*m17_gs_sudoers' "$KS_FILE" \
    "final gate has no fragile physical-line contract for complete quit"
assert_grep_fixed 'matchpathcon -V "$m17_gs_admin_desktop"' "$KS_FILE" \
    "final gate verifies the admin launcher SELinux label"
assert_grep_fixed 'GNOME Software Flatpak/RPM/complete-quit split invalid' \
    "$KS_FILE" "final gate makes the complete Software split fatal"
assert_grep_fixed 'retired RPM rewrite artifact present' "$KS_FILE" \
    "final gate rejects the obsolete upgrade-time mutator"
assert_grep_fixed 'Module 17 transactional per-task first-login contract invalid' \
    "$KS_FILE" "final gate requires the retryable first-login state machine"
assert_grep_fixed "grep -qF 'preset-all' \"\$m17_firstrun\"" "$KS_FILE" \
    "final gate rejects the open-ended user preset operation"
for retired_firstrun_contract in \
    'PRESET_UNITS=(' \
    'systemctl --user preset "$unit"' \
    'systemctl --user start "$unit"' \
    'systemctl --user is-enabled --quiet "$unit"' \
    'systemctl --user is-active --quiet "$unit"'; do
    if grep -qF "$retired_firstrun_contract" "$KS_FILE"; then
        _fail "M99 rejects retired shared-unit first-login contract: $retired_firstrun_contract"
    else
        _pass "M99 rejects retired shared-unit first-login contract: $retired_firstrun_contract"
    fi
done
for current_firstrun_contract in \
    'UPDATE_UNIT=noid-update-reminder.timer' \
    'NOTIFIER_UNIT=usbguard-notifier.service' \
    'NOTIFIER_WANTS=/usr/lib/systemd/user/graphical-session.target.wants/usbguard-notifier.service' \
    'NOTIFIER_TARGET=/usr/lib/systemd/user/usbguard-notifier.service' \
    'systemctl --user preset "$UPDATE_UNIT"' \
    'systemctl --user start "$UPDATE_UNIT"' \
    'systemctl --user is-enabled --quiet "$UPDATE_UNIT"' \
    'systemctl --user is-active --quiet "$UPDATE_UNIT"' \
    '[[ -L "$NOTIFIER_WANTS" ]]' \
    'readlink -- "$NOTIFIER_WANTS"' \
    'systemctl --user start "$NOTIFIER_UNIT"' \
    'systemctl --user is-active --quiet "$NOTIFIER_UNIT"'; do
    assert_grep_fixed "$current_firstrun_contract" "$M17_FIRSTRUN" \
        "deployed M17 helper supplies current first-login contract: $current_firstrun_contract"
    assert_grep_fixed "$current_firstrun_contract" "$KS_FILE" \
        "M99 final-gates current first-login contract: $current_firstrun_contract"
done
for forbidden_notifier_operation in \
    'preset "$NOTIFIER_UNIT"' \
    'is-enabled --quiet "$NOTIFIER_UNIT"'; do
    if grep -qF "$forbidden_notifier_operation" "$M17_FIRSTRUN"; then
        _fail "deployed M17 helper rejects notifier operation: $forbidden_notifier_operation"
    else
        _pass "deployed M17 helper rejects notifier operation: $forbidden_notifier_operation"
    fi
    assert_grep_fixed "grep -qF '$forbidden_notifier_operation' \"\$m17_firstrun\"" \
        "$KS_FILE" "M99 rejects notifier operation: $forbidden_notifier_operation"
done
assert_grep_fixed 'm17_firstrun_notifier=/usr/lib/systemd/user/usbguard-notifier.service' \
    "$KS_FILE" "M99 pins the static notifier target"
assert_grep_fixed 'm17_firstrun_notifier_wants=/usr/lib/systemd/user/graphical-session.target.wants/usbguard-notifier.service' \
    "$KS_FILE" "M99 pins the static notifier wants link"
assert_grep_fixed "stat -c '%U:%G' \"\$m17_firstrun_notifier_wants\"" \
    "$KS_FILE" "M99 requires root ownership of the static notifier link"
assert_grep_fixed '"$m17_firstrun_notifier" ]; then' "$KS_FILE" \
    "M99 requires the exact static notifier link target"
assert_grep_fixed 'mark_done complete' "$KS_FILE" \
    "final gate requires derived atomic completion"
assert_grep_fixed 'persistent WirePlumber microphone policy invalid' "$KS_FILE" \
    "final gate validates the native microphone policy owner"
assert_grep_fixed 'ENFORCEMENT_INTERVAL_MSEC = 1000' "$KS_FILE" \
    "final gate requires event-driven microphone enforcement with bounded fallback"
assert_grep_fixed 'Plugin.find ("mixer-api")' "$KS_FILE" \
    "final gate requires effective microphone route-state reads"
assert_grep_fixed 'mixer:connect ("changed"' "$KS_FILE" \
    "final gate requires native hardware-route change enforcement"
assert_grep_fixed 'mixer:call ("set-volume"' "$KS_FILE" \
    "final gate requires native WirePlumber route writes"
assert_grep_fixed 'retired one-shot microphone enforcer present' "$KS_FILE" \
    "final gate rejects every obsolete microphone one-shot artifact"
assert_grep_fixed 'GNOME privacy producer/cleanup contract invalid' "$KS_FILE" \
    "final gate binds producer schema and ordered cleanup"
assert_grep_fixed 'm17_privacy_contract=/usr/local/sbin/noid-verify-gnome-privacy-contract' \
    "$KS_FILE" "final gate requires the GNOME private-state schema verifier"
assert_grep_fixed \
    'post_transaction:gnome-shell:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-verify-gnome-privacy-contract\ >/dev/null' \
    "$KS_FILE" "final gate pins the host-scoped gnome-shell schema action"
assert_grep_fixed 'RESOLVE_NO_XDEV' "$KS_FILE" \
    "final gate requires the kernel mount-boundary resolver"
assert_grep_fixed 'Before=gnome-session-shutdown.target gnome-session-restart-dbus.service' \
    "$KS_FILE" "final gate requires the GNOME shutdown ordering edge"
assert_grep_fixed 'm17_cleanup_old_wants' "$KS_FILE" \
    "final gate rejects the racing graphical-target activation link"
assert_grep_fixed 'evidence-bounded application-overridable JIT defaults invalid' \
    "$KS_FILE" "final gate validates the measured reversible JIT defaults"
assert_grep_fixed 'It does not make either engine memory-safe' "$M17_GNOME_DOC" \
    "final gate preserves the documented JIT residual boundary"
assert_grep_fixed 'env -u GJS_DISABLE_JIT gjs-application' "$M17_GNOME_DOC" \
    "final gate preserves the exact GJS opt-out"
assert_grep_fixed 'env JavaScriptCoreUseJIT=1 webkit-application' "$M17_GNOME_DOC" \
    "final gate preserves the exact WebKitGTK opt-out"
assert_grep_fixed 'strict application-overridable Wayland defaults invalid' "$KS_FILE" \
    "final gate validates the honest strict GTK/Qt Wayland defaults"
assert_grep_fixed 'they are not an enforcement or anti-downgrade boundary' "$M17_GNOME_DOC" \
    "final gate preserves the documented Wayland trust boundary"
assert_grep_fixed 'env GDK_BACKEND=x11 gtk-application' "$M17_GNOME_DOC" \
    "final gate preserves the documented GTK Xwayland recovery"
assert_grep_fixed 'env QT_QPA_PLATFORM=xcb qt-application' "$M17_GNOME_DOC" \
    "final gate preserves the documented Qt environment recovery"
assert_grep_fixed 'qt-application -platform xcb' "$M17_GNOME_DOC" \
    "final gate preserves the Qt command-line recovery override"
for recovery_literal in \
    'they are not an enforcement or anti-downgrade boundary' \
    'env GDK_BACKEND=x11 gtk-application' \
    'env QT_QPA_PLATFORM=xcb qt-application' \
    'qt-application -platform xcb'; do
    assert_grep_fixed "$recovery_literal" "$M17_GNOME_DOC" \
        "M99 recovery literal exists in the deployed M17 documentation payload"
done
assert_grep_fixed 'qt5-qtwayland btop' "$KS_FILE" \
    "final package gate requires the Qt5 Wayland runtime beside KeePassXC"
assert_grep_fixed '/usr/lib64/qt5/plugins/platforms/libqwayland-generic.so' \
    "$KS_FILE" "final gate binds the Qt5 Wayland plugin to its Fedora RPM"

# M16's image seed, canonical managed-list source and active compose-time copy
# form one executable contract. Runtime removal of the active copy remains the
# documented system-wide opt-out; the finalizer runs only during image compose.
assert_grep_fixed 'm16_ubo_xpi="/usr/lib64/mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/uBlock0@raymondhill.net.xpi"' \
    "$KS_FILE" "M99 binds the exact system uBO seed"
assert_grep_fixed 'm16_ubo_policy_source=/usr/share/noid-firefox/uBlock0@raymondhill.net.json' \
    "$KS_FILE" "M99 requires the canonical uBO policy source"
assert_grep_fixed 'm16_ubo_policy_active=/usr/lib64/mozilla/managed-storage/uBlock0@raymondhill.net.json' \
    "$KS_FILE" "M99 requires the active compose-time uBO policy"
assert_grep_fixed 'm16_ubo_policy_validator=/usr/local/lib/noid-privacy/validate-ubo-policy.py' \
    "$KS_FILE" "M99 requires the uBO policy validator"
assert_grep_fixed "stat -Lc '%u:%g:%a:%h' \"\$m16_ubo_xpi\"" \
    "$KS_FILE" "M99 pins uBO seed ownership, mode and link count"
assert_grep_fixed "stat -Lc '%s' \"\$m16_ubo_xpi\"" \
    "$KS_FILE" "M99 pins the current uBO seed byte count"
assert_grep_fixed 'bccc51a773150af4af6e1fd62c7bfdeb7238b79ff2381b998fa9f2e38f64786a' \
    "$KS_FILE" "M99 pins the current official uBO seed digest"
assert_grep_fixed 'cmp -s -- "$m16_ubo_policy_source" "$m16_ubo_policy_active"' \
    "$KS_FILE" "M99 requires canonical/active managed-list parity at compose time"
assert_grep_fixed '"$m16_ubo_policy_validator" "$m16_ubo_xpi"' \
    "$KS_FILE" "M99 executes policy/XPI compatibility validation"
assert_grep_fixed 'mandatory in the composed image but may be removed later' \
    "$KS_FILE" "M99 distinguishes the image seed from the supported runtime opt-out"
assert_grep_fixed 'Module 16 uBO seed/policy/validator contract invalid' \
    "$KS_FILE" "M99 exposes one fatal complete uBO contract"

# M34's current icon contract uses Fedora's packaged Firefox artwork. The
# final gate must reject both a missing package icon and stale custom aliases;
# the old inverse requirement aborted the first exact v1.4 compose.
assert_grep_fixed "grep -qxF 'Icon=firefox'" "$KS_FILE" \
    "M99 requires the exact packaged Firefox icon name"
assert_grep_fixed 'Module 34 packaged Firefox icon lookup has no payload' \
    "$KS_FILE" "M99 requires a resolvable Fedora Firefox icon"
assert_grep_fixed '/usr/share/icons/hicolor/symbolic/apps/firefox*-symbolic.svg' \
    "$KS_FILE" "M99 tolerates renamed package-owned symbolic Firefox variants"
assert_grep_fixed 'rpm -qf --qf '\''%{NAME}'\'' -- "$m34_firefox_icon"' \
    "$KS_FILE" "M99 binds the resolved icon to the Firefox RPM"
assert_grep_fixed 'm34_legacy_icons=(/usr/share/icons/hicolor/*/apps/firefox-playground.png)' \
    "$KS_FILE" "M99 enumerates every legacy custom icon alias"
assert_grep_fixed 'Module 34 legacy custom icon alias remains' "$KS_FILE" \
    "M99 rejects upgrade-only custom icon residue"
assert_not_grep 'Module 34 no firefox-playground icon generated' "$KS_FILE" \
    "M99 no longer requires the retired custom icon"

# Health stamp directory
assert_grep_fixed \
    'for stamp_file in /var/lib/noid-privacy/stamp-*.ok; do' "$KS_FILE" \
    "health gate scans the canonical stamp directory"

# ----------------------------------------------------------------------------
# Exact health-stamp filename/content binding (14 adopters)
# ----------------------------------------------------------------------------
assert_grep_fixed 'EXPECTED_STAMPS=(' "$KS_FILE"
for stamp_spec in \
    16:firefox \
    28:local-ai-docs 29:user-docs 30:user-docs-tier-b \
    31:user-docs-tier-c 32:branding 33:operational-hygiene \
    34:firefox-playground 35:thunderbird 36:noid-network-app \
    37:noid-tools-app \
    40:audit-bundle 41:anaconda-cleanup 42:forensic-retention; do
    assert_grep_fixed "\"${stamp_spec}\"" "$KS_FILE"
done
assert_grep_fixed 'stamp filename/content binding invalid' "$KS_FILE" \
    "health gate binds filename to module/name/status"
assert_grep_fixed 'unexpected health stamp outside canonical set' "$KS_FILE" \
    "health gate rejects stale/unknown stamps"
assert_grep_fixed 'if [ "$stamp_meta" != "0:0:644" ]; then' "$KS_FILE" \
    "health gate verifies root-owned non-writable metadata"

# ----------------------------------------------------------------------------
# M20 NUMBER_LIMIT increased from 5 to 50
# ----------------------------------------------------------------------------
# Was a ship-blocker: an earlier M99 asserted NUMBER_LIMIT="5" but M20 set
# 50, would have aborted installation with "FAIL: snapper root config
# NUMBER_LIMIT!=5". Sanity guard: the old "5" assertion must NOT survive.
assert_grep_fixed 'NUMBER_LIMIT="50"' "$KS_FILE"
assert_not_grep 'snapper.*NUMBER_LIMIT.*!=5\b' "$KS_FILE"
for snapper_config_entry in \
    'QGROUP=""' \
    'SPACE_LIMIT="0.5"' \
    'FREE_LIMIT="0.2"'; do
    assert_grep_fixed "'$snapper_config_entry'" "$KS_FILE" \
        "M99 requires M20's exact Snapper config: $snapper_config_entry"
done
assert_grep_fixed 'Module 20 Snapper quota-hint config drifted' "$KS_FILE" \
    "M99 rejects writer/finalizer drift without requiring invalid empty values"
assert_not_grep 'retains inert quota-dependent space-limit claims' "$KS_FILE" \
    "M99 no longer rejects Snapper's valid inactive numeric defaults"

# ----------------------------------------------------------------------------
# M42-managed aide.conf exclusions cross-check
# ----------------------------------------------------------------------------
# M13 source-port deploys exclusions to /etc/aide.conf for M42-managed
# retention paths. M99 added a build-time verify that all 10 are present
# after install. Without this, M13 deployment failure would silently degrade
# to alarm-fatigue runtime state (= masks real intrusions). Same ship-blocker
# class as (the verify-additions for M13 wrapper artifacts).
# Keep these shell words single-quoted so `$` and backslashes stay literal.
for excl_anchor in \
    '!/var/log/aide(/.*)?$' \
    '!/var/log/anaconda(/.*)?$' \
    '!/var/log/ks-[^/]*\.log$' \
    '!/var/log/ks-10-authselect\.err$' \
    '!/var/log/noid-anaconda-kernel-cmdline\.log$' \
    '!/var/log/noid-firstboot-setup\.log$' \
    '!/var/log/noid-crypto-policy\.err$' \
    '!/var/log/libvirt(/.*)?$' \
    '!/var/log/swtpm/libvirt/qemu(/.*)?$' \
    '!/var/log/tuned(/.*)?$'; do
    assert_grep_fixed "$excl_anchor" "$KS_FILE"
done

# 1 fail-block must emit the canonical FAIL log message + increment
# the fail counter (= verify-counter pattern). Sanity that the verify-
# block isn't accidentally turned into a no-op via missing fail=$((fail + 1)).
assert_grep_fixed 'Module 13 retention exclusion missing' "$KS_FILE"

# ----------------------------------------------------------------------------
# noid-snapper-prune service+timer cross-check
# ----------------------------------------------------------------------------
# M20 ships noid-snapper-prune.{sh,service,timer} for time-based snapshot
# cleanup. M99 verifies presence + the script invokes the configured snapper
# binary with `delete --sync` and the selected snapshot number.
assert_grep_fixed '/usr/local/sbin/noid-snapper-prune.sh' "$KS_FILE"
assert_grep_fixed '/etc/systemd/system/noid-snapper-prune.service' "$KS_FILE"
assert_grep_fixed '/etc/systemd/system/noid-snapper-prune.timer' "$KS_FILE"
assert_grep_fixed 'grep -qF '\''"$SNAPPER" -c root delete --sync "$num"'\''' "$KS_FILE" \
    "M99 verifies the variable-based M20 snapper invocation exactly"

snapper_script="$TEST_TMPDIR/noid-snapper-prune.sh"
extract_heredoc "$PROJECT_ROOT/kickstart/snippets/20-snapper.ks" \
    "SNAPPER_PRUNE_EOF" "$snapper_script" || _fail "M20 prune extraction"
assert_grep_fixed '"$SNAPPER" -c root delete --sync "$num"' "$snapper_script" \
    "deployed M20 prune contract matches the M99 final gate"
assert_grep_fixed 'Active/default roots remain protected and visible' "$KS_FILE" \
    "M99 retention claim names the non-deletable active/default boundary"
assert_grep_fixed 'RequiresMountsFor=/.snapshots' "$KS_FILE" \
    "M99 requires retention state outside the rollback root"
assert_grep_fixed 'fixed read-only Snapper sudo boundary drifted' "$KS_FILE" \
    "M99 pins the exact two-command sudoers boundary"
assert_grep_fixed 'recovery guide bypasses the checked rollback wrapper' "$KS_FILE" \
    "M99 rejects direct raw rollback guidance"
assert_grep_fixed 'Module 20 rollback bypasses the shared boot-mutation contract' \
    "$KS_FILE" "M99 requires M20 root selection to join the boot transaction"
assert_grep_fixed 'gsk_toggle=/usr/local/bin/noid-toggle-gsk-gl' "$KS_FILE" \
    "M99 requires the standalone GTK renderer toggle"
assert_grep_fixed 'gsk_matcher=/usr/libexec/noid-gsk-hybrid-match' "$KS_FILE" \
    "M99 requires the exact NVIDIA-offload topology matcher"
assert_grep_fixed 'gsk_wrapper=/usr/local/bin/gnome-control-center' "$KS_FILE" \
    "M99 requires the app-scoped GNOME Settings wrapper"
assert_grep_fixed 'gsk_software_wrapper=/usr/local/bin/gnome-software' "$KS_FILE" \
    "M99 requires the explicit-launch GNOME Software wrapper"
assert_grep_fixed 'gsk_session_helper=/usr/libexec/noid-gsk-session-environment' \
    "$KS_FILE" "M99 requires the post-Shell GTK activation helper"
assert_grep_fixed 'gsk_session_unit=/usr/lib/systemd/user/noid-gsk-session-environment.service' \
    "$KS_FILE" "M99 requires the distribution GTK user unit"
assert_grep_fixed 'gsk_session_enable=/etc/systemd/user/gnome-session.target.wants/noid-gsk-session-environment.service' \
    "$KS_FILE" "M99 requires the exact global GNOME-session enablement"
assert_grep_fixed 'Module 19 GTK session user unit network boundary is invalid' \
    "$KS_FILE" "M99 rejects unenforceable user-manager network isolation"
assert_grep_fixed 'GNOME Software wrapper can manage/background-start the service' \
    "$KS_FILE" "M99 rejects a renderer wrapper that weakens silent-machine policy"
assert_grep_fixed 'GNOME Software explicit Flatpak-store scope is invalid' \
    "$KS_FILE" "M99 requires the reviewed fast explicit store scope"
assert_grep_fixed \
    'NOID_SOFTWARE_PLUGINS=flatpak,icons,hardcoded-blocklist,malcontent,modalias,os-release,provenance,provenance-license,generic-updates' \
    "$KS_FILE" "M99 pins the complete explicit store plugin inventory"
assert_grep_fixed \
    '"$runtime_parent/noid-m19-systemd-verify.XXXXXX"' \
    "$KS_FILE" "M99 creates a private runtime for offline user-unit verification"
assert_grep_fixed 'XDG_RUNTIME_DIR="$runtime_dir"' "$KS_FILE" \
    "M99 verifies user units through its private compose runtime"
assert_grep_fixed 'find "$runtime_dir" -xdev -mindepth 1 -delete' \
    "$KS_FILE" "M99 cleans only the private verifier runtime mount boundary"
assert_not_grep 'XDG_RUNTIME_DIR="/run/user/' "$KS_FILE" \
    "M99 never assumes that root owns a logind login runtime"
assert_grep_fixed 'gsk_launcher_sync=/usr/libexec/noid-gsk-settings-launcher-sync' \
    "$KS_FILE" "M99 requires the XDG launcher sync helper"
assert_grep_fixed 'gsk_launcher=/usr/local/share/applications/org.gnome.Settings.desktop' \
    "$KS_FILE" "M99 requires the precedence-safe XDG launcher"
assert_grep_fixed \
    'post_transaction:gnome-control-center:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/libexec/noid-gsk-settings-launcher-sync\ >/dev/null' \
    "$KS_FILE" "M99 pins the host-only launcher self-healing action"
assert_grep_fixed 'retired GTK renderer vendor generator exists' "$KS_FILE" \
    "M99 rejects the retired session-wide renderer generator"
assert_grep_fixed 'obsolete duplicate GNOME Settings D-Bus shadow exists' "$KS_FILE" \
    "M99 rejects noisy duplicate D-Bus activation"
assert_grep_fixed 'GTK renderer static override was activated during compose' "$KS_FILE" \
    "M99 rejects a compose-host static renderer decision"
assert_grep_fixed 'GTK renderer mode override was activated during compose' "$KS_FILE" \
    "M99 rejects a compose-host app policy decision"
assert_grep_fixed 'legacy GTK generator override exists during compose' "$KS_FILE" \
    "M99 rejects a stale generator override"
assert_grep_fixed 'GSK_RENDERER=ngl' "$KS_FILE" \
    "M99 rejects the deprecated renderer alias"

# ----------------------------------------------------------------------------
# M27 vendor-owned performance boundary
# ----------------------------------------------------------------------------
assert_grep_fixed 'Module 27 retired I/O scheduler override still exists' \
    "$KS_FILE" "M99 rejects the retired per-device scheduler bet"
assert_grep_fixed 'Module 27 retired Intel HWP override still exists' \
    "$KS_FILE" "M99 rejects the retired global HWP boost bet"
assert_grep_fixed 'Module 27 retired zram override still exists' \
    "$KS_FILE" "M99 rejects retired zram compression/priority policy"
assert_grep_fixed '/usr/lib/udev/rules.d/60-block-scheduler.rules' \
    "$KS_FILE" "M99 requires Fedora's scheduler policy"
assert_grep_fixed '/usr/lib/systemd/zram-generator.conf' \
    "$KS_FILE" "M99 requires Fedora's zram policy"
assert_grep_fixed 'zram-generator-defaults policy missing or wrong owner' \
    "$KS_FILE" "M99 binds the zram policy to its Fedora RPM owner"
assert_grep_fixed 'UDISKS_MOUNT_OPTIONS_DEFAULTS}="noexec"' \
    "$KS_FILE" "M99 final-gates the USB/SD noexec policy"
for m27_ntfs_scope in \
    'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_FS_TYPE}=="ntfs", SUBSYSTEMS=="usb", ENV{UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS}="ntfs3,ntfs"' \
    'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_FS_TYPE}=="ntfs", ENV{ID_DRIVE_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS}="ntfs3,ntfs"' \
    'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_FS_TYPE}=="ntfs", ENV{ID_DRIVE_MEDIA_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS}="ntfs3,ntfs"'; do
    assert_grep_fixed "$m27_ntfs_scope" "$KS_FILE" \
        "M99 final-gates external NTFS driver priority for every media scope"
done
assert_grep_fixed '99-noid-usb-sync-mount.rules' \
    "$KS_FILE" "M99 rejects the retired blanket-sync rule"
assert_grep_fixed '99-noid-usb-write-through.rules' \
    "$KS_FILE" "M99 rejects the retired cache-view mutator"
assert_grep_fixed 'ENV{ID_DRIVE_FLASH_SD}=="1"' \
    "$KS_FILE" "M99 final-gates recognized SD-reader media"
assert_grep_fixed 'ENV{ID_DRIVE_MEDIA_FLASH_SD}=="1"' \
    "$KS_FILE" "M99 final-gates native SD/SD-combo media"
assert_grep_fixed "grep -q 'ID_DRIVE_FLASH_MMC'" \
    "$KS_FILE" "M99 rejects accidental internal MMC/eMMC classification"
assert_grep_fixed 'for unit in thermald.service tuned.service tuned-ppd.service; do' \
    "$KS_FILE" "M99 requires every M27 power-profile service enablement contract"
assert_grep_fixed 'if rpm -q unrar >/dev/null 2>&1; then' \
    "$KS_FILE" "M99 retains the real M26 archive-package absence gate"
assert_grep_fixed 'if rpm -q pipewire-config-raop >/dev/null 2>&1; then' \
    "$KS_FILE" "M99 enforces the M26 Silent-Machine RAOP package boundary"
assert_grep_fixed 'PipeWire RAOP discovery config present' \
    "$KS_FILE" "M99 reports the exact forbidden discovery surface"
assert_not_grep 'for tpkg in unrar p7zip-plugins' "$KS_FILE" \
    "M99 cannot count the nonexistent p7zip-plugins package as green evidence"

# ----------------------------------------------------------------------------
# M21 shared boot-mutation lifecycle
# ----------------------------------------------------------------------------
assert_grep_fixed '/usr/libexec/noid-boot-mutation-guard' "$KS_FILE" \
    "M99 requires the canonical stable-basis guard"
assert_grep_fixed '/usr/libexec/noid-dracut-regenerate-all' "$KS_FILE" \
    "M99 requires the atomic later-rebuild helper"
assert_grep_fixed '! /usr/libexec/noid-verify-target-karg-payload >/dev/null' \
    "$KS_FILE" "M99 repeats the lifecycle-correct M01 target-karg payload proof"
assert_grep_fixed \
    "/usr/libexec/noid-verify-target-karg-payload 2>/dev/null)\" != root:root:755" \
    "$KS_FILE" \
    "M99 binds the verifier itself to root ownership and executable mode"
assert_grep_fixed 'target-install module.sig_enforce=1 payload invalid' "$KS_FILE" \
    "M99 makes an invalid target signature-enforcement payload fatal"
assert_not_grep 'Module 21/M01 module.sig_enforce=1 missing:' "$KS_FILE" \
    "M99 does not misclassify the build-topology Live BLS as an installed target"
assert_grep_fixed 'f /run/lock/noid-boot-mutation.lock 0660 root wheel -' "$KS_FILE" \
    "M99 requires the shared lock tmpfiles contract"
assert_grep_fixed 'Defaults!/usr/libexec/noid-dracut-regenerate-all closefrom_override' \
    "$KS_FILE" "M99 requires the scoped inherited-descriptor sudoers contract"
assert_grep_fixed 'ReadWritePaths=/boot /var/lib/noid-privacy /run/lock/noid-identity-bls-refresh.lock /run/lock/noid-boot-mutation.lock' \
    "$KS_FILE" "M99 requires M32 sandbox access to the shared boot lock"
assert_grep_fixed "grep -qxF 'ProtectKernelModules=yes'" "$KS_FILE" \
    "M99 rejects a sandbox that hides M21 target-module evidence"
assert_grep_fixed "grep -qxF 'ProtectKernelModules=no'" "$KS_FILE" \
    "M99 requires readable target-module evidence"
assert_grep_fixed "grep -qxF 'CapabilityBoundingSet=~CAP_SYS_MODULE'" "$KS_FILE" \
    "M99 preserves the module-management capability denial"
assert_grep_fixed "grep -qxF 'SystemCallFilter=~@module'" "$KS_FILE" \
    "M99 preserves the module-management syscall denial"
assert_grep_fixed "grep -qxF 'SystemCallErrorNumber=EPERM'" "$KS_FILE" \
    "M99 binds the fail-closed module syscall result"
assert_grep_fixed 'candidate for $kernel lacks root-path driver' "$KS_FILE" \
    "M99 requires root-controller validation on later rebuilds"
assert_grep_fixed 'enrolled NVIDIA identity verification failed for $kernel' "$KS_FILE" \
    "M99 requires enrolled NVIDIA identity on normal later rebuilds"
assert_grep_fixed 'complete) basis=hostonly' "$KS_FILE" \
    "M99 requires confirmed host-only terminal handling"
assert_grep_fixed 'recovered-generic) basis=generic' "$KS_FILE" \
    "M99 requires restored-Generic terminal handling"
assert_grep_fixed 'validate_snapper_record "$SNAPPER_PENDING" pending' "$KS_FILE" \
    "M99 requires persistent Snapper interruption evidence in the boot guard"
assert_grep_fixed 'a Snapper rollback root is selected; reboot before changing /boot' \
    "$KS_FILE" "M99 blocks boot writers until the selected root is active"
assert_grep_fixed 'mv -fT -- "$candidate" "$final"' "$KS_FILE" \
    "M99 requires atomic later initramfs publication"
assert_grep_fixed 'Module 25 process/lock-bound update-window validator missing or incomplete' \
    "$KS_FILE" "M99 rejects existence-only/stale update suppression authority"
assert_grep_fixed 'Module 24 bounded on-demand daemon policy missing' \
    "$KS_FILE" "M99 requires the maintained fwupd idle lifecycle"
assert_grep_fixed "grep -qxF 'DisabledPlugins=redfish;android_boot'" "$KS_FILE" \
    "M99 pins the closed fwupd plugin list and its native delimiter"
assert_grep_fixed 'Module 24 fwupd is not purely static/on-demand' \
    "$KS_FILE" "M99 rejects firmware-daemon boot persistence"
assert_grep_fixed 'Module 25 native fwupd settlement contract invalid' \
    "$KS_FILE" "M99 requires fwupd's update-aware quit path"
assert_grep_fixed 'sudo LC_ALL=C fwupdmgr quit' "$KS_FILE" \
    "M99 pins the normal-sudo native firmware-daemon settlement command"
assert_grep_fixed 'Module 25 extension update transaction/identity contract invalid' \
    "$KS_FILE" "M99 final-gates transactional GNOME and agent-safe editor updates"
for extension_update_contract in \
    '/usr/local/lib/noid-privacy/validate-webextension.py' \
    '/usr/local/lib/noid-privacy/validate-ubo-policy.py' \
    '/usr/local/lib/noid-privacy/verify-firefox-xpi-signature' \
    'MARKETPLACE_XPI_RELEASE_PY' \
    'UBO_POLICY_VALIDATOR=/usr/local/lib/noid-privacy/validate-ubo-policy.py' \
    'UBO_POLICY_SOURCE=/usr/share/noid-firefox/uBlock0@raymondhill.net.json' \
    'ubo_candidate_action()' \
    '"$UBO_POLICY_VALIDATOR" "$LATEST_XPI_PATH"' \
    '"$UBO_POLICY_VALIDATOR" "$ubo_target"' \
    'FIREFOX_XPI_SIGNATURE_VERIFIER=' \
    'https://addons.mozilla.org/api/v5/addons/search/' \
    'https://services.addons.thunderbird.net/api/v4/addons/search/' \
    'fetch_latest_xpi ubo' \
    'fetch_latest_xpi dkim' \
    'update_marketplace_extensions firefox amo' \
    'update_marketplace_extensions thunderbird atn' \
    'BROWSER_EXTENSION_INVENTORY_PY' \
    'TB_DKIM_CURRENT_VALID=0' \
    'EGO update check unavailable; installed extension left unchanged' \
    'Open-VSX REST channel unavailable for' \
    'extension-updates.log' \
    'extension-checks' \
    'record_extension_check() {' \
    'record_extension_check firefox-ubo' \
    'record_extension_check thunderbird-dkim' \
    'record_extension_check "${product}-marketplace"' \
    'JP_SEED_VERSION=' \
    'grep -qF -- "--data-urlencode \"uuid=\${ego_uuid}\""' \
    'EGO_VALIDATE_PY' \
    'RENAME_EXCHANGE' \
    'managed agent extensions present; using per-extension native updates' \
    'no additional VSCodium extensions require Open-VSX reconciliation' \
    'VSX_VERSION_PY' \
    'installed ${ext_ver} is newer than registry ${latest}; no downgrade' \
    'installed_exact=$(codium --list-extensions --show-versions'; do
    assert_grep_fixed "$extension_update_contract" "$KS_FILE" \
        "M99 binds deployed M25 extension contract: $extension_update_contract"
done
assert_grep_fixed "grep -qF 'https://api.github.com/repos/gorhill/uBlock/releases/latest'" \
    "$KS_FILE" "M99 rejects the rate-limited uBO GitHub REST resolver"
assert_grep_fixed "grep -qF 'https://api.github.com/repos/lieser/dkim_verifier/releases/latest'" \
    "$KS_FILE" "M99 rejects the rate-limited DKIM GitHub REST resolver"
assert_grep_fixed "grep -qF 'UBO_MANAGED_POLICY='" "$KS_FILE" \
    "M99 rejects updater coupling to the optional active managed-list copy"
assert_grep_fixed "grep -qF '[ \"\$ext_path\" = \"\$JP_PATH\" ] && continue'" \
    "$KS_FILE" "M99 rejects exclusion of managed Just-Perfection from EGO updates"
assert_grep_fixed 'Module 35 Thunderbird background update suppression missing' \
    "$KS_FILE" "M99 requires every Thunderbird background update path to stay disabled"
assert_grep_fixed 'Module 16 Firefox background update suppression missing' \
    "$KS_FILE" "M99 requires every Firefox background update path to stay disabled"
for current_update_pref in \
    'defaultPref("app.update.auto", false);' \
    'defaultPref("app.update.silent", false);' \
    'defaultPref("extensions.update.enabled", false);' \
    'defaultPref("extensions.update.autoUpdateDefault", false);' \
    'defaultPref("extensions.systemAddon.update.enabled", false);'; do
    assert_grep_fixed "$current_update_pref" "$KS_FILE" \
        "M99 uses a current Firefox/Thunderbird updater contract: $current_update_pref"
done
for retired_update_pref in \
    'defaultPref("app.update.enabled", false);' \
    'defaultPref("app.update.background.scheduling.enabled", false);'; do
    assert_cmd_success \
        "M99 does not resurrect a retired Mozilla updater key: $retired_update_pref" \
        bash -c '! grep -qF -- "$1" "$2"' _ "$retired_update_pref" "$KS_FILE"
done
assert_grep_fixed "grep -qF 'sudo unzip' /usr/local/bin/noid-update-all.sh" \
    "$KS_FILE" "M99 rejects root overlay extraction of marketplace archives"
assert_grep_fixed 'Module 32 runtime BLS writer bypasses the shared guarded publication contract' \
    "$KS_FILE" "M99 requires M32 to share the boot-mutation contract"
assert_grep_fixed 'Module 32 initial durable identity BLS request is missing or malformed' \
    "$KS_FILE" "M99 requires the first-install BLS convergence request"
assert_grep_fixed 'multi-user.target.wants/noid-identity-bls-refresh.path' \
    "$KS_FILE" "M99 requires durable handoff-race retry enablement"

# ----------------------------------------------------------------------------
# M13 wrapper + explicit baseline review
# ----------------------------------------------------------------------------
# aide-check wrapper + drop-in
assert_grep_fixed '/usr/local/sbin/noid-aide-check.sh' "$KS_FILE"
assert_grep_fixed '/etc/systemd/system/aide-check.service.d/30-noid-wrapper.conf' "$KS_FILE"
assert_grep_fixed '/usr/local/sbin/noid-aide-baseline-review' "$KS_FILE"
assert_grep_fixed 'obsolete automatic AIDE trust-replacement artifact present' "$KS_FILE"
assert_not_grep 'noid-aide-firstboot-rebaseline.timer not enabled' "$KS_FILE"

# ----------------------------------------------------------------------------
# noid-toggle-aide outer-wrapper CLI in the M13 file-existence loop
# ----------------------------------------------------------------------------
# noid-toggle-aide (= Welcome dialog API) was added to the M13 verify-list
# in M99. Was previously missing (only inner noid-toggle-aide-popup
# was checked).
assert_grep_fixed '/usr/local/bin/noid-toggle-aide' "$KS_FILE"

# M15 platform state is consumed by noid-status, not the GTK Welcome UI.
# Cross-extract the deployed STATUS_EOF so this test cannot pass from stale
# prose in M99 while the actual consumer drifts.
status_script="$TEST_TMPDIR/noid-status"
extract_heredoc "$PROJECT_ROOT/kickstart/snippets/13-aide-welcome.ks" \
    "STATUS_EOF" "$status_script" || _fail "M13 status extraction"
assert_grep_fixed 'local file="${1:-/var/lib/noid-privacy/mei-status.txt}"' \
    "$status_script" "noid-status reads the M15 platform-state schema"
assert_grep_fixed 'PLATFORM_STATUS=$(read_platform_status)' "$status_script" \
    "noid-status publishes parsed M15 platform state"
assert_grep_fixed 'local file="${1:-/var/lib/noid-privacy/mei-status.txt}"' \
    "$KS_FILE" "M99 replays the deployed parameterized platform-state path"
assert_grep_fixed 'Module 13 noid-status missing Module 15 platform-status consumer' \
    "$KS_FILE" "M99 final-gates the current M13/M15 consumer contract"
assert_not_grep 'noid-welcome\.sh missing MEI_STATUS_FILE' "$KS_FILE" \
    "M99 has no stale Welcome-era MEI consumer assertion"

# ----------------------------------------------------------------------------
# M99 status-line sanity
# ----------------------------------------------------------------------------
# Lock-history was consolidated to a single Status line (history lives in
# git). Regression-guard: the Status line must be present near the top.
assert_grep_extended '^# Status: LOCKED' "$KS_FILE"
assert_not_grep_extended \
    'rc[.][0-9]+|Module [0-9]+ v[0-9]+|Lesson #[0-9]+' "$KS_FILE" \
    "M99 contains no obsolete release-candidate, module-version or lesson-number annotations"

# ----------------------------------------------------------------------------
# M99 cross-reference producers
# ----------------------------------------------------------------------------
# M99's own header names this failure class: a finalize check hardcoded against
# OLD module state, discovered only when a build aborts. It happened twice more
# after that warning was written -- M04 replaced its initial-learner early exit
# with a superset that also republishes readiness, and M04's readiness helper
# wrapped a bare `systemctl start` in a failure-checked branch. Both were
# improvements; neither moved the pin, the suite stayed green, and the compose
# failed in Phase 5. Nothing bound M99's literals to the modules that produce
# them, so bind them here: every fixed string M99 requires to be PRESENT must
# be produced somewhere in the tree.
if python3 - "$KS_FILE" "$PROJECT_ROOT" <<'PY'
from pathlib import Path
import re
import sys

finalize = Path(sys.argv[1])
root = Path(sys.argv[2])
lines = finalize.read_text(encoding="utf-8").splitlines()

# One reviewed exception: this pin sits in an `A && ! B && C || { fail }`
# chain, where the negation means the literal must be ABSENT. Every other
# `! grep` in M99 is the `if ! grep ...; then FAIL` form and is a requirement.
ABSENT_IN_AND_CHAIN = (
    'ConditionPathExists=!%h/.local/state/noid-privacy/'
    'agent-policy-adapters.done'
)

statements, buffer, start = [], "", None
for number, line in enumerate(lines, 1):
    if start is None:
        start = number
    if line.rstrip().endswith("\\"):
        buffer += line.rstrip()[:-1] + " "
        continue
    statements.append((start, buffer + line))
    buffer, start = "", None
if buffer:
    statements.append((start or len(lines), buffer))

# M99 produces a few of the artifacts it also verifies, so its own heredoc
# bodies count as producers -- but its verification code does not.
corpus = []
marker = None
for line in lines:
    if marker is not None:
        if line.strip() == marker:
            marker = None
        else:
            corpus.append(line)
        continue
    opened = re.search(r"<<-?\s*'([A-Za-z_][A-Za-z0-9_]*)'", line)
    if opened:
        marker = opened.group(1)
corpus = ["\n".join(corpus)]
for path in sorted(root.glob("kickstart/snippets/*.ks")):
    if path.name != finalize.name:
        corpus.append(path.read_text(encoding="utf-8"))
for path in sorted(root.glob("scripts/*")):
    if path.is_file():
        try:
            corpus.append(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, OSError):
            pass

grep_re = re.compile(
    r"grep\s+-(?P<flags>[a-zA-Z]*)\s+'(?P<literal>(?:[^']|'\\'')*)'")
required, orphaned, exception_seen = 0, [], False
for number, statement in statements:
    for match in grep_re.finditer(statement):
        flags = match.group("flags")
        if "F" not in flags or "E" in flags:
            continue
        literal = match.group("literal").replace("'\\''", "'")
        if not literal.strip():
            continue
        if not statement[:match.start()].rstrip().endswith("!"):
            continue
        if literal == ABSENT_IN_AND_CHAIN:
            exception_seen = True
            continue
        required += 1
        if not any(literal in body for body in corpus):
            orphaned.append((number, literal))

if not exception_seen:
    print("the reviewed absent-literal exception no longer exists in M99; "
          "drop it from this gate", file=sys.stderr)
    raise SystemExit(1)
if required < 300:
    print(f"only {required} M99 requirement pins parsed; the extractor "
          "stopped matching M99's shape", file=sys.stderr)
    raise SystemExit(1)
if orphaned:
    for number, literal in orphaned:
        print(f"99-finalize.ks:{number} requires a literal no module "
              f"produces: {literal!r}", file=sys.stderr)
    raise SystemExit(1)
PY
then
    _pass "every M99 required literal is produced by some module"
else
    _fail "M99 pins a literal against retired module state"
fi

test_finish
