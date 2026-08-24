#!/bin/bash
# 13-welcome-script — verify noid-welcome.sh structural invariants
#
# The welcome UI was rewritten from Zenity/Bash to GTK4 +
# libadwaita Python, then absorbed the setup-wizard
# functionality (hardware privacy mic/cam toggles) into the welcome dialog
# and removed the standalone setup-wizard. This test covers the
# resulting behavior.
#
# Welcome script is installed by Module 13 (M13). Current GTK4 group order:
#   1. Critical — Do These First       8. Printing
#   2. VPN — Install Before Updates    9. Gaming Mode
#   3. System Updates                 10. App Autostart
#   4. Hardware Privacy               11. Security Notifications
#   5. Devices                        12. Companion Apps
#   6. AI Development Tools           13. Reference
#   7. Media & Graphics               14. Project & Ecosystem
#                                      + Conditional finish/restart action

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/13-aide-welcome.ks"
A11Y_RUNTIME="$PROJECT_ROOT/tests/pre-ship/13-first-party-app-accessibility-runtime.sh"
TEST_STRATEGY="$PROJECT_ROOT/docs/test-strategy.md"

test_start "13-welcome-script"

assert_file_exists "$KS_FILE"
assert_file_exists "$TEST_STRATEGY"
assert_grep_fixed 'Failed sending audit message:added=...' "$TEST_STRATEGY" \
    "test strategy distinguishes AIDE fixture audit noise from the daily service"
assert_grep_fixed 'Do not run the suite as root merely to' "$TEST_STRATEGY" \
    "AIDE fixture guidance does not broaden test authority to root"
assert_grep_fixed '    /etc/codex' "$KS_FILE" \
    "Codex system defaults are in the authoritative AIDE manifest"
for tracked_control in \
    '    /etc/NetworkManager/dispatcher.d' \
    '    /etc/nftables' \
    '    /etc/systemd/system.control' \
    '    /etc/usbguard'; do
    assert_grep_fixed "$tracked_control" "$KS_FILE" \
        "mutable security control is SECURE-tracked: ${tracked_control#    }"
done
assert_grep_fixed "printf '%s SECURE" "$KS_FILE" \
    "authoritative AIDE manifest emits every SECURE rule"
for forbidden_control_exclude in \
    '!/etc/nftables/arp-hardening\.nft$' \
    '!/etc/NetworkManager/dispatcher\.d/90-arp-hardening$' \
    '!/etc/systemd/system/firewalld\.service\.d/arp-hardening-firewalld-reload\.conf$' \
    '!/etc/sysctl\.d/99-wan-ipv6-off\.conf$' \
    '!/etc/usbguard/rules\.conf$' \
    '!/etc/usbguard/IPCAccessControl\.d(/.*)?$' \
    '!/etc/systemd/system\.control(/.*)?$' \
    '!/usr/share/plymouth/themes/bgrt/bgrt\.plymouth$'; do
    if grep -qxF "$forbidden_control_exclude" "$KS_FILE"; then
        _fail "integrity-relevant path is directly excluded: $forbidden_control_exclude"
    else
        _pass "integrity-relevant path has no direct AIDE exclusion: $forbidden_control_exclude"
    fi
done
assert_grep_fixed 'mv -fT -- "$aide_candidate" /etc/aide.conf' "$KS_FILE" \
    "legacy AIDE exclusion cleanup replaces config atomically"
assert_grep_fixed 'AIDE SECURE rules reconciled from canonical manifest' \
    "$KS_FILE" "an existing AIDE block receives later canonical SECURE paths"
assert_grep_fixed 'grep -qxF "$secure_path SECURE" "$aide_candidate"' \
    "$KS_FILE" "SECURE reconciliation tests the atomic candidate"
assert_grep_fixed '!/var/lib/libvirt/images(/.*)?$' "$KS_FILE" \
    "AIDE excludes only the default mutable VM image store"
assert_grep_fixed '!/var/lib/libvirt/qemu(/.*)?$' "$KS_FILE" \
    "AIDE excludes generated QEMU runtime state"
assert_eq 1 "$(grep -cF "'!/boot/System\.map-[^/]*$'" "$KS_FILE")" \
    "former /boot System.map exclusion exists only in legacy cleanup policy"
assert_eq 1 "$(grep -cF "'!/usr/lib/modules/[^/]+/System\.map$'" "$KS_FILE")" \
    "former module-tree System.map exclusion exists only in legacy cleanup policy"
assert_not_grep '!/usr/lib/modules(/.*)?$' "$KS_FILE" \
    "AIDE retains every module-tree sibling in scope"
for retention_exclude in \
    '!/var/log/ks-10-authselect\.err$' \
    '!/var/log/noid-anaconda-kernel-cmdline\.log$' \
    '!/var/log/noid-firstboot-setup\.log$' \
    '!/var/log/noid-crypto-policy\.err$' \
    '!/var/log/swtpm/libvirt/qemu(/.*)?$'; do
    assert_grep_fixed "$retention_exclude" "$KS_FILE" \
        "AIDE excludes only an M42-managed retention path: $retention_exclude"
done
if grep -qxF '!/var/log/noid-[^/]*' "$KS_FILE"; then
    _fail "AIDE does not hide arbitrary NoID Privacy logs"
else
    _pass "AIDE does not hide arbitrary NoID Privacy logs"
fi
if grep -qxF '!/var/lib/libvirt(/.*)?$' "$KS_FILE"; then
    _fail "AIDE does not hide the entire libvirt state hierarchy"
else
    _pass "AIDE does not hide the entire libvirt state hierarchy"
fi

TMPDIR="$(mktemp -d)"
PROTON_STUB_ROOT=
trap 'rm -rf "$TMPDIR" "${PROTON_STUB_ROOT:-}"' EXIT

SECURE_RECONCILE="$TMPDIR/aide-secure-reconcile.sh"
sed -n \
    '/^# BEGIN M13_SECURE_RECONCILE$/,/^# END M13_SECURE_RECONCILE$/p' \
    "$KS_FILE" | sed '1d;$d' > "$SECURE_RECONCILE"
assert_cmd_success "AIDE SECURE reconciliation block parses" \
    bash -n "$SECURE_RECONCILE"
aide_candidate="$TMPDIR/aide-reconcile.conf"
printf '%s\n' \
    'SECURE = p+u+g+sha256+sha512' \
    '/etc/modprobe.d/ SECURE' > "$aide_candidate"
# The extracted production block consumes this fixture array dynamically.
# shellcheck disable=SC2034
SECURE_PATHS=(/etc/modprobe.d/ "=/etc/security/pam_env-sudo.conf")
secure_rules_reconciled=-1
# shellcheck source=/dev/null
. "$SECURE_RECONCILE"
assert_eq 1 "$secure_rules_reconciled" \
    "older AIDE block gains exactly its missing canonical rule"
assert_eq 1 \
    "$(grep -cFx '=/etc/security/pam_env-sudo.conf SECURE' "$aide_candidate")" \
    "reconciliation publishes the exact sudo policy rule once"
# shellcheck source=/dev/null
. "$SECURE_RECONCILE"
assert_eq 0 "$secure_rules_reconciled" \
    "AIDE SECURE reconciliation is idempotent"
assert_eq 1 \
    "$(grep -cFx '=/etc/security/pam_env-sudo.conf SECURE' "$aide_candidate")" \
    "idempotent rerun does not duplicate the sudo policy rule"

# The SECURE rule must be derived from Fedora's NORMAL, never spelled out by
# hand. A hand-written list shipped for months and silently dropped l, i,
# ftype, selinux, e2fsattrs and sha3_256, so on every SECURE path the
# advertised upgrade was a net attribute REDUCTION against the Fedora rule
# those paths would otherwise have used.
assert_grep_fixed 'SECURE = NORMAL+sha256+b' "$KS_FILE" \
    "SECURE derives from Fedora NORMAL instead of a hand-written attribute list"
assert_not_grep_extended '^SECURE = [a-z]' "$KS_FILE" \
    "no literal attribute list remains on the shipped SECURE definition"
assert_grep_fixed 'SECURE drops NORMAL attribute(s)' "$KS_FILE" \
    "compose verification proves the superset invariant against the aide binary"
# /etc/aide.conf is appended to rather than created from a heredoc, so
# 00-gate-literal-contract.py cannot resolve this gate's literal against the
# shipped bytes and honestly reports it as unresolvable. Tie the two together
# here instead: the step-10.0 gate must grep the exact line the append-block
# writes, or a one-sided edit ships a check that can never succeed.
shipped_secure_line=$(grep -m1 '^SECURE = ' "$KS_FILE" || true)
assert_grep_fixed "grep -qxF '$shipped_secure_line'" "$KS_FILE" \
    "compose gate greps the exact SECURE line the append-block ships"

# Behavioural proof with the real aide binary. The fixture pins Fedora's own
# NORMAL definition (aide.conf:120, `NORMAL = R+sha512-m-c`); the property
# under test is the derivation, which holds for any NORMAL. Module 13's
# step-10.0a check re-proves it against the installed aide.conf at compose
# time, so a Fedora-side change to NORMAL cannot slip through unnoticed.
if command -v aide >/dev/null 2>&1; then
    aide_root="$TMPDIR/c018"
    mkdir -p "$aide_root/n" "$aide_root/s"
    printf 'good\n' > "$aide_root/good.unit"
    printf 'evil\n' > "$aide_root/evil.unit"
    shipped_secure=$(grep -m1 '^SECURE = ' "$KS_FILE" || true)
    assert_grep_fixed 'NORMAL' <(printf '%s\n' "$shipped_secure") \
        "shipped SECURE line was extracted for the live aide check"

    write_aide_conf() {
        # $1 = target config, $2 = SECURE definition line under test
        printf '%s\n' \
            "database_in=file:$aide_root/db.in" \
            "database_out=file:$aide_root/db.out" \
            'NORMAL = R+sha512-m-c' \
            "$2" \
            "$aide_root/n NORMAL" \
            "$aide_root/s SECURE" > "$1"
    }
    aide_attrs() {
        # $1 = config, $2 = path-check argument. `aide --path-check` prints the
        # matched rule as '<path> <restriction> <attributes>'; take the last
        # field of the first single-quoted group. The path need not exist.
        aide --config="$1" --path-check="$2" 2>/dev/null \
            | sed -n "s/^[^']*'\([^']*\)'.*/\1/p" | head -1 | awk '{print $NF}'
    }

    write_aide_conf "$aide_root/shipped.conf" "$shipped_secure"
    normal_attrs=$(aide_attrs "$aide_root/shipped.conf" "d:$aide_root/n")
    secure_attrs=$(aide_attrs "$aide_root/shipped.conf" "d:$aide_root/s")
    assert_grep_extended '.' <(printf '%s\n' "$normal_attrs") \
        "aide resolved the NORMAL attribute set"
    dropped=""
    for attr in $(printf '%s\n' "$normal_attrs" | tr '+' ' '); do
        case "+${secure_attrs}+" in
            *"+${attr}+"*) ;;
            *) dropped="${dropped} ${attr}" ;;
        esac
    done
    assert_eq "" "$dropped" \
        "shipped SECURE resolves to a superset of NORMAL (SECURE=$secure_attrs)"
    for added in sha256 b; do
        assert_cmd_success "SECURE still adds $added on top of NORMAL" \
            grep -qF "+${added}+" <<<"+${secure_attrs}+"
    done

    # The concrete attack the dropped `l` allowed: symlinks carry no hashsum,
    # so repointing a unit symlink at an equal-length attacker unit changes no
    # mode, uid, gid, size, nlink or xattr. Only `l` reports it.
    run_retarget_probe() {
        # $1 = SECURE definition line; echoes the number of changed entries
        rm -rf "$aide_root/n" "$aide_root/s" "$aide_root/db.in" "$aide_root/db.out"
        mkdir -p "$aide_root/n" "$aide_root/s"
        ln -s ../good.unit "$aide_root/n/link"
        ln -s ../good.unit "$aide_root/s/link"
        write_aide_conf "$aide_root/probe.conf" "$1"
        aide --config="$aide_root/probe.conf" --init >/dev/null 2>&1 || true
        mv -f "$aide_root/db.out" "$aide_root/db.in"
        ln -sfn ../evil.unit "$aide_root/n/link"
        ln -sfn ../evil.unit "$aide_root/s/link"
        aide --config="$aide_root/probe.conf" --check > "$aide_root/report.txt" 2>&1 || true
        sed -n 's/^[[:space:]]*Changed entries:[[:space:]]*//p' "$aide_root/report.txt" | head -1
    }
    assert_eq 2 "$(run_retarget_probe "$shipped_secure")" \
        "real aide reports the symlink retarget on both the NORMAL and the SECURE path"
    # Control: the previously shipped hand-written list must NOT detect it.
    # This is what makes the assertion above discriminating rather than
    # decorative — reverting the definition turns the 2 back into a 1.
    assert_eq 1 \
        "$(run_retarget_probe 'SECURE = p+u+g+s+n+b+acl+xattrs+sha256+sha512')" \
        "the withdrawn hand-written SECURE list provably misses the retarget"
    unset -f write_aide_conf aide_attrs run_retarget_probe
fi

AIDE_SECURE_MANIFEST="$PROJECT_ROOT/manifests/aide-secure-paths.tsv"
assert_file_exists "$AIDE_SECURE_MANIFEST" "canonical AIDE SECURE manifest exists"
assert_eq 73 "$(wc -l < "$AIDE_SECURE_MANIFEST")" \
    "canonical AIDE SECURE manifest has 73 contracts"
assert_grep_fixed '/etc/dbus-1/session.d|f|/etc/dbus-1/session.d/.noid-aide-coverage-probe' \
    "$AIDE_SECURE_MANIFEST" "session-bus denial policy is AIDE-covered"
assert_grep_fixed '/etc/ssh/sshd_config.d|f|/etc/ssh/sshd_config.d/.noid-aide-coverage-probe' \
    "$AIDE_SECURE_MANIFEST" "dormant SSH server policy is AIDE-covered"
assert_grep_fixed '=/etc/security/pam_env-sudo.conf|f|/etc/security/pam_env-sudo.conf' \
    "$AIDE_SECURE_MANIFEST" "sudo session-class policy is AIDE-covered"
assert_grep_fixed '/etc/sudoers.d/48-noid-gnome-software-quit|f|/etc/sudoers.d/48-noid-gnome-software-quit' \
    "$AIDE_SECURE_MANIFEST" "complete-quit sudoers boundary is AIDE-covered"
assert_grep_fixed '/etc/sudoers.d/90-noid-boot-mutation-fd|f|/etc/sudoers.d/90-noid-boot-mutation-fd' \
    "$AIDE_SECURE_MANIFEST" "boot-lock descriptor policy is AIDE-covered"
assert_grep_fixed '=/etc/sudoers.d/91-noid-aide-status|f|/etc/sudoers.d/91-noid-aide-status' \
    "$AIDE_SECURE_MANIFEST" "AIDE state sudo boundary is AIDE-covered"
assert_grep_fixed '=/usr/libexec/noid-aide-status|f|/usr/libexec/noid-aide-status' \
    "$AIDE_SECURE_MANIFEST" "AIDE state helper is AIDE-covered"
assert_grep_fixed '=/usr/lib/tmpfiles.d/noid-aide-lock.conf|f|/usr/lib/tmpfiles.d/noid-aide-lock.conf' \
    "$AIDE_SECURE_MANIFEST" "AIDE mutex definition is AIDE-covered"
assert_grep_fixed '/etc/systemd/system/|f|/etc/systemd/system/.noid-aide-coverage-probe' \
    "$AIDE_SECURE_MANIFEST" "system unit tree rule cannot swallow system.control"
assert_grep_fixed '/etc/systemd/system.control|f|/etc/systemd/system.control/.noid-aide-coverage-probe' \
    "$AIDE_SECURE_MANIFEST" "persistent systemd control state keeps its own contract"
assert_grep_fixed '/etc/environment.d|f|/etc/environment.d/.noid-aide-coverage-probe' \
    "$AIDE_SECURE_MANIFEST" "JIT/backend environment policy is AIDE-covered"
assert_grep_fixed '/usr/libexec/noid-gsk-hybrid-match|f|/usr/libexec/noid-gsk-hybrid-match' \
    "$AIDE_SECURE_MANIFEST" "GTK hybrid topology matcher is AIDE-covered"
assert_grep_fixed '/usr/libexec/noid-gsk-session-environment|f|/usr/libexec/noid-gsk-session-environment' \
    "$AIDE_SECURE_MANIFEST" "post-Shell GTK activation helper is AIDE-covered"
assert_grep_fixed '/usr/lib/systemd/user/noid-gsk-session-environment.service|f|/usr/lib/systemd/user/noid-gsk-session-environment.service' \
    "$AIDE_SECURE_MANIFEST" "post-Shell GTK user unit is AIDE-covered"
assert_grep_fixed '/usr/local/bin/gnome-software|f|/usr/local/bin/gnome-software' \
    "$AIDE_SECURE_MANIFEST" "explicit GNOME Software renderer wrapper is AIDE-covered"
assert_grep_fixed '/etc/systemd/user|f|/etc/systemd/user/.noid-aide-coverage-probe' \
    "$AIDE_SECURE_MANIFEST" "global user-unit enablements are AIDE-covered"
assert_grep_fixed '/usr/libexec/noid-vscodium-repo-key-seed|f|/usr/libexec/noid-vscodium-repo-key-seed' \
    "$AIDE_SECURE_MANIFEST" "VSCodium metadata trust reconciler is AIDE-covered"
assert_grep_fixed '/usr/libexec/noid-codium-launch|f|/usr/libexec/noid-codium-launch' \
    "$AIDE_SECURE_MANIFEST" "VSCodium default-GPU launcher is AIDE-covered"
assert_grep_fixed '/usr/local/sbin/noid-codium-launcher-sync|f|/usr/local/sbin/noid-codium-launcher-sync' \
    "$AIDE_SECURE_MANIFEST" "VSCodium desktop publisher is AIDE-covered"
assert_grep_fixed '/usr/lib/systemd/user-environment-generators/55-noid-gsk-renderer|f|/usr/lib/systemd/user-environment-generators/55-noid-gsk-renderer' \
    "$AIDE_SECURE_MANIFEST" "GTK topology environment generator is AIDE-covered"
assert_grep_fixed '/etc/dnf/libdnf5-plugins/actions.d|f|/etc/dnf/libdnf5-plugins/actions.d/.noid-aide-coverage-probe' \
    "$AIDE_SECURE_MANIFEST" "package reconciliation actions are AIDE-covered"
assert_grep_fixed '/usr/local/sbin/noid-gnome-software-launcher-sync|f|/usr/local/sbin/noid-gnome-software-launcher-sync' \
    "$AIDE_SECURE_MANIFEST" "GNOME Software launcher synchronizer is AIDE-covered"
assert_grep_fixed '/usr/local/sbin/noid-gnome-software-backend-stop|f|/usr/local/sbin/noid-gnome-software-backend-stop' \
    "$AIDE_SECURE_MANIFEST" "GNOME Software idle-backend helper is AIDE-covered"
assert_grep_fixed '/usr/local/bin/noid-gnome-software-quit|f|/usr/local/bin/noid-gnome-software-quit' \
    "$AIDE_SECURE_MANIFEST" "GNOME Software complete-quit helper is AIDE-covered"
assert_grep_fixed '/usr/local/bin/noid-gnome-software-rpm|f|/usr/local/bin/noid-gnome-software-rpm' \
    "$AIDE_SECURE_MANIFEST" "GNOME Software Fedora-RPM helper is AIDE-covered"
assert_grep_fixed '/usr/local/bin/noid-host-identity|f|/usr/local/bin/noid-host-identity' \
    "$AIDE_SECURE_MANIFEST" "pre-login host-identity helper is AIDE-covered"
assert_grep_fixed '/usr/local/sbin/noid-verify-gnome-privacy-contract|f|/usr/local/sbin/noid-verify-gnome-privacy-contract' \
    "$AIDE_SECURE_MANIFEST" "GNOME private-state schema verifier is AIDE-covered"
assert_grep_fixed '/usr/local/sbin/noid-wireguard-mtu-reconcile|f|/usr/local/sbin/noid-wireguard-mtu-reconcile' \
    "$AIDE_SECURE_MANIFEST" "WireGuard MTU event worker is AIDE-covered"
assert_grep_fixed '/usr/local/share/applications|f|/usr/local/share/applications/.noid-aide-coverage-probe' \
    "$AIDE_SECURE_MANIFEST" "admin launcher overlays are AIDE-covered"
assert_cmd_success "canonical AIDE SECURE manifest has unique closed fields" \
    awk -F'|' '
        NF != 3 || $1 !~ /^=?\// || $2 !~ /^[fd]$/ || $3 !~ /^\// || seen[$1]++ { bad=1 }
        END { exit bad }
    ' "$AIDE_SECURE_MANIFEST"
cut -d'|' -f1 "$AIDE_SECURE_MANIFEST" > "$TMPDIR/aide-paths.expected"
awk '
    /^SECURE_PATHS=\($/ { copy=1; next }
    copy && /^\)$/ { exit }
    copy { sub(/^[[:space:]]+/, ""); if ($0 != "") print }
' "$KS_FILE" > "$TMPDIR/aide-paths.m13"
assert_cmd_success "M13 SECURE_PATHS matches the canonical manifest" \
    cmp -s "$TMPDIR/aide-paths.expected" "$TMPDIR/aide-paths.m13"
AIDE_COVERAGE_TSV="$TMPDIR/aide-secure-paths.deployed.tsv"
extract_heredoc "$KS_FILE" "AIDE_COVERAGE_TSV_EOF" "$AIDE_COVERAGE_TSV" || \
    _fail "AIDE_COVERAGE_TSV_EOF extraction"
assert_cmd_success "M13 deployed coverage manifest matches the canonical manifest" \
    cmp -s "$AIDE_SECURE_MANIFEST" "$AIDE_COVERAGE_TSV"
assert_grep_fixed '/usr/libexec/noid-platform-policy-sha256' \
    "$TMPDIR/aide-paths.m13" \
    "platform-policy status helper has exact content tracking"
assert_grep_fixed '/usr/libexec/noid-boot-mutation-guard' \
    "$TMPDIR/aide-paths.m13" \
    "boot-mutation stable-basis guard has exact content tracking"
assert_grep_fixed '/usr/libexec/noid-dracut-regenerate-all' \
    "$TMPDIR/aide-paths.m13" \
    "atomic later-initramfs writer has exact content tracking"
assert_grep_fixed '/usr/libexec/noid-mark-hostonly-boot-success' \
    "$TMPDIR/aide-paths.m13" \
    "first-login boot-success helper has exact content tracking"
assert_grep_fixed '/usr/lib/systemd/user/noid-hostonly-boot-success.service' \
    "$TMPDIR/aide-paths.m13" \
    "first-login boot-success unit has exact content tracking"
assert_grep_fixed '/usr/lib/systemd/user/noid-hostonly-boot-success.path' \
    "$TMPDIR/aide-paths.m13" \
    "first-login request watcher has exact content tracking"
assert_grep_fixed '/usr/libexec/noid-update-window-active' \
    "$TMPDIR/aide-paths.m13" \
    "update-suppression authority has exact content tracking"
assert_grep_fixed '/usr/local/sbin/noid-restore-identity' \
    "$TMPDIR/aide-paths.m13" \
    "runtime identity/BLS queue owner has exact content tracking"
assert_grep_fixed '/usr/local/bin/noid-toggle-gsk-gl' \
    "$TMPDIR/aide-paths.m13" \
    "GTK renderer policy writer has exact content tracking"
assert_grep_fixed '/usr/local/share/dbus-1/services' \
    "$TMPDIR/aide-paths.m13" \
    "native D-Bus activation denials have exact content tracking"
assert_grep_fixed '/etc/wireplumber/wireplumber.conf.d' \
    "$TMPDIR/aide-paths.m13" \
    "WirePlumber microphone policy config has exact content tracking"
assert_grep_fixed '/usr/local/share/wireplumber/scripts' \
    "$TMPDIR/aide-paths.m13" \
    "WirePlumber microphone policy code has exact content tracking"
assert_grep_fixed '/usr/local/bin/noid-toggle-microphone' \
    "$TMPDIR/aide-paths.m13" \
    "microphone policy control helper has exact content tracking"
assert_grep_fixed '/usr/local/libexec/noid-gnome-privacy-cleanup' \
    "$TMPDIR/aide-paths.m13" \
    "GNOME shutdown privacy cleanup has exact content tracking"
assert_grep_fixed '/usr/local/sbin/noid-verify-gnome-privacy-contract' \
    "$TMPDIR/aide-paths.m13" \
    "GNOME private-state schema verifier has exact content tracking"

# Reproduce Fedora 44's earlier rules that share the same AIDE tree nodes.
# AIDE resolves the deepest node first and then the first rule inside it, so a
# later SECURE line with the same node is silently shadowed by NORMAL. Test the
# complete canonical manifest against those real conflicts, not an isolated
# candidate-only fixture.
AIDE_EFFECTIVE_FIXTURE="$TMPDIR/aide-effective-fedora.conf"
cat > "$AIDE_EFFECTIVE_FIXTURE" <<'AIDE_EFFECTIVE_BASE_EOF'
NORMAL = p+u+g+s+sha512
SECURE = p+u+g+s+sha256+sha512
/etc/modprobe.d NORMAL
/etc/dracut.conf.d NORMAL
/etc/firewalld NORMAL
/etc/sysctl.d NORMAL
/etc/chrony.conf$ NORMAL
/etc/audit NORMAL
/etc/usbguard NORMAL
/etc/tmpfiles.d NORMAL
AIDE_EFFECTIVE_BASE_EOF
while IFS='|' read -r aide_rule_path _ _; do
    printf '%s SECURE\n' "$aide_rule_path" >> "$AIDE_EFFECTIVE_FIXTURE"
done < "$AIDE_SECURE_MANIFEST"
while IFS='|' read -r aide_rule_path aide_file_type aide_probe_path; do
    if aide_match=$(LC_ALL=C aide --config="$AIDE_EFFECTIVE_FIXTURE" \
            --path-check="$aide_file_type:$aide_probe_path" 2>&1) && \
       grep -qF sha256 <<<"$aide_match" && grep -qF sha512 <<<"$aide_match"; then
        _pass "effective Fedora AIDE precedence: $aide_rule_path"
    else
        _fail "effective Fedora AIDE precedence: $aide_rule_path"
    fi
done < "$AIDE_SECURE_MANIFEST"

SCRIPT="$TMPDIR/noid-welcome.sh"
extract_heredoc "$KS_FILE" "NOID_WELCOME_PY_EOF" "$SCRIPT" || _fail "NOID_WELCOME_PY_EOF extraction"
UI_COMMON="$TMPDIR/noid_ui.py"
extract_heredoc "$KS_FILE" "NOID_UI_PY_EOF" "$UI_COMMON" || \
    _fail "NOID_UI_PY_EOF extraction"
AUTOSTART_DESKTOP="$TMPDIR/noid-welcome-autostart.desktop"
extract_heredoc "$KS_FILE" "DESKTOP_EOF" "$AUTOSTART_DESKTOP" || \
    _fail "DESKTOP_EOF extraction"
APP_DESKTOP="$TMPDIR/noid-welcome.desktop"
extract_heredoc "$KS_FILE" "APPDESKTOP_EOF" "$APP_DESKTOP" || \
    _fail "APPDESKTOP_EOF extraction"
CLAUDE_INSTALLER="$TMPDIR/noid-claude-install"
extract_heredoc "$KS_FILE" "CLAUDE_INSTALL_EOF" "$CLAUDE_INSTALLER" || \
    _fail "CLAUDE_INSTALL_EOF extraction"
CODEX_INSTALLER="$TMPDIR/noid-codex-install"
extract_heredoc "$KS_FILE" "CODEX_INSTALL_EOF" "$CODEX_INSTALLER" || \
    _fail "CODEX_INSTALL_EOF extraction"
AIDE_CHECK_WRAPPER="$TMPDIR/noid-aide-check.sh"
extract_heredoc "$KS_FILE" "AIDE_CHECK_WRAPPER_EOF" "$AIDE_CHECK_WRAPPER" || \
    _fail "AIDE_CHECK_WRAPPER_EOF extraction"
AIDE_REVIEW="$TMPDIR/noid-aide-baseline-review"
extract_heredoc "$KS_FILE" "AIDE_BASELINE_REVIEW_EOF" "$AIDE_REVIEW" || \
    _fail "AIDE_BASELINE_REVIEW_EOF extraction"
AIDE_SERVICE="$TMPDIR/aide-check.service"
extract_heredoc "$KS_FILE" "SERVICE_EOF" "$AIDE_SERVICE" || \
    _fail "AIDE service extraction"
AIDE_BOOT_PRIORITY="$TMPDIR/aide-boot-priority.conf"
extract_heredoc "$KS_FILE" "BOOTPRIO_EOF" "$AIDE_BOOT_PRIORITY" || \
    _fail "AIDE resource drop-in extraction"
AIDE_TIMER="$TMPDIR/aide-check.timer"
extract_heredoc "$KS_FILE" "TIMER_EOF" "$AIDE_TIMER" || \
    _fail "AIDE timer extraction"
AIDE_NOTIFY_DOC="$TMPDIR/notifications.md"
extract_heredoc "$KS_FILE" "NOTIFY_DOC_EOF" "$AIDE_NOTIFY_DOC" || \
    _fail "AIDE notification documentation extraction"
AIDE_NOTIFIER="$TMPDIR/aide-notify.sh"
extract_heredoc "$KS_FILE" "NOTIFY_SH_EOF" "$AIDE_NOTIFIER" || \
    _fail "AIDE notifier extraction"
AIDE_POPUP_TOGGLE="$TMPDIR/noid-toggle-aide-popup"
extract_heredoc "$KS_FILE" "TOGGLE_POPUP_EOF" "$AIDE_POPUP_TOGGLE" || \
    _fail "AIDE popup toggle extraction"
AIDE_COMBINED_TOGGLE="$TMPDIR/noid-toggle-aide"
extract_heredoc "$KS_FILE" "TOGGLE_AIDE_EOF" "$AIDE_COMBINED_TOGGLE" || \
    _fail "AIDE combined toggle extraction"
assert_file_min_size "$SCRIPT" 4096 "welcome script >4KB (non-trivial scope)"
assert_not_grep 'M13 is the FIRST module writing /usr/share/doc/noid-privacy' \
    "$KS_FILE" "M13 documentation does not claim false first ownership"
assert_grep_fixed 'ProtectHome=tmpfs' "$AIDE_SERVICE" \
    "scheduled AIDE checks hide user home trees by default"
assert_grep_fixed 'BindReadOnlyPaths=/root' "$AIDE_SERVICE" \
    "scheduled AIDE checks retain Fedora's required root-tree coverage"
assert_not_grep 'ProtectHome=read-only' "$AIDE_SERVICE" \
    "scheduled AIDE checks do not retain unnecessary home read access"
assert_grep_fixed 'Shared bash helper sourced by Module 34' "$KS_FILE" \
    "Fedora Welcome wait-helper ownership names its only consumer"
assert_not_grep 'Shared bash helper sourced by Module 16' "$KS_FILE" \
    "Fedora Welcome helper docs do not invent an M16 consumer"
assert_grep_fixed 'System dconf locks remain effective in either' "$KS_FILE" "Welcome comments follow GNOME's real system-lock precedence"
assert_grep_fixed 'GNOME Settings has no app-autostart control on the shipped image' "$SCRIPT" "Welcome describes only the shipped Settings surface"
assert_not_grep_extended 'undo dconf hardening locks|expose dconf-lock UI|GNOME 50 has no native autostart UI' "$KS_FILE" "Welcome contains no lock-bypass or invented universal-GUI claim"
assert_not_grep_extended '[0-9]+ verified apps' "$KS_FILE" \
    "Welcome states no drifting Flathub catalog count"
assert_grep_fixed 'enforces 15+ characters there.' "$SCRIPT" \
    "Welcome states the current account-password minimum"
assert_grep_fixed 'without a character-class' "$SCRIPT" \
    "Welcome does not imply a composition requirement"
assert_not_grep_extended 'minlen=14|enforces 14\+ characters' "$SCRIPT" \
    "Welcome has no stale 14-character policy"

# --- Python parse check -----------------------------------------------------
if python3 -m py_compile "$SCRIPT" 2>/dev/null; then
    _pass "welcome script: python3 -m py_compile clean"
else
    _fail "welcome script: python3 -m py_compile errors"
fi
assert_cmd_success "shared UI module: python3 -m py_compile clean" \
    env PYTHONPYCACHEPREFIX="$TMPDIR/pycache" python3 -m py_compile "$UI_COMMON"
assert_grep_fixed 'DEFAULT_WIDTH = 960' "$UI_COMMON" \
    "shared app windows use the reviewed wide-screen default width"
assert_grep_fixed 'DEFAULT_HEIGHT = 800' "$UI_COMMON" \
    "shared app windows use the reviewed wide-screen default height"
assert_grep_fixed 'class NoIDApplication(Adw.Application)' "$UI_COMMON" \
    "shared module owns the one-instance application base"
assert_grep_fixed 'flags=Gio.ApplicationFlags.DEFAULT_FLAGS' "$UI_COMMON" \
    "all first-party apps use one-instance Gio semantics"
assert_grep_fixed 'def sectioned_app_bars(window, title, subtitle, icon_name, stack)' \
    "$UI_COMMON" "shared module owns persistent identity plus adaptive navigation"
assert_grep_fixed 'header = app_header(title, subtitle, icon_name)' "$UI_COMMON" \
    "sectioned apps use the same persistent identity as the other three apps"
assert_grep_fixed 'switcher = Adw.ViewSwitcher()' "$UI_COMMON" \
    "wide navigation uses the maintained native view switcher"
assert_grep_fixed 'section_bar = Adw.HeaderBar()' "$UI_COMMON" \
    "wide section navigation has a dedicated native row below identity"
assert_grep_fixed 'section_bar.set_title_widget(switcher)' "$UI_COMMON" \
    "section tabs are centered on their own row"
assert_grep_fixed 'section_bar.set_show_start_title_buttons(False)' "$UI_COMMON" \
    "section row does not duplicate window controls"
assert_grep_fixed 'section_bar.set_show_end_title_buttons(False)' "$UI_COMMON" \
    "section row does not duplicate window controls at either edge"
assert_grep_fixed "Adw.BreakpointCondition.parse('max-width: 760sp')" "$UI_COMMON" \
    "narrow navigation uses a native libadwaita breakpoint"
assert_grep_fixed "breakpoint.add_setter(section_bar, 'visible', False)" "$UI_COMMON" \
    "breakpoint removes the dedicated wide section row when constrained"
assert_grep_fixed "breakpoint.add_setter(switcher_bar, 'reveal', True)" "$UI_COMMON" \
    "breakpoint reveals the native bottom navigation when narrow"
assert_not_grep 'Adw.ViewSwitcherTitle.new' "$UI_COMMON" \
    "shared UI does not use the libadwaita 1.4-deprecated title switcher"
assert_grep_fixed 'Gtk.AccessibleProperty.LABEL' "$UI_COMMON" \
    "shared controls have explicit accessible labels"
assert_grep_fixed 'Gtk.AccessibleProperty.DESCRIPTION' "$UI_COMMON" \
    "semantic shared controls have explicit accessible descriptions"
assert_grep_fixed 'Gtk.AccessibleRelation.LABELLED_BY' "$UI_COMMON" \
    "visible control text remains the native accessible label source"
assert_grep_fixed 'Gtk.AccessibleRelation.DESCRIBED_BY' "$UI_COMMON" \
    "row subtitles are exported through the native description relation"
assert_grep_fixed 'Gtk.AccessibleList.new_from_list' "$UI_COMMON" \
    "PyGObject uses GTK's maintained boxed reference-list API"
assert_grep_fixed 'def accessible_row(row, description=None)' "$UI_COMMON" \
    "row and internal activatable widgets share one dynamic name contract"
assert_grep_fixed 'def _prepare_row_text_labels(row)' "$UI_COMMON" \
    "dynamic Adw rows promote their private text labels before first use"
assert_grep_fixed "not child.has_css_class('noid-emoji')" "$UI_COMMON" \
    "decorative emoji remain excluded from accessible row names"
assert_grep_fixed "not child.has_css_class('noid-step-num')" "$UI_COMMON" \
    "decorative Update ordinals remain excluded from accessible row names"
assert_grep_fixed "row.connect('notify::title'" "$UI_COMMON" \
    "dynamic row titles refresh their AT-SPI name"
assert_grep_fixed "row.connect('notify::subtitle'" "$UI_COMMON" \
    "dynamic row subtitles refresh their AT-SPI description"
assert_grep_fixed "row.connect('map'" "$UI_COMMON" \
    "composite rows rebind relations after GTK realizes private labels"
assert_grep_fixed 'def bind_view_switcher_accessibility' "$UI_COMMON" \
    "adaptive page tabs receive explicit names after realization"
assert_grep_fixed "action = Gtk.Button.new_from_icon_name('go-next-symbolic')" \
    "$UI_COMMON" "shared action rows expose a native button action"
assert_grep_fixed 'accessible(action, title, subtitle)' "$UI_COMMON" \
    "shared action-row button has an explicit accessible name and description"
assert_grep_fixed 'row.set_activatable_widget(action)' "$UI_COMMON" \
    "whole-row activation forwards to the published native button"
assert_not_grep "row.connect('activated', callback)" "$UI_COMMON" \
    "shared rows do not keep an AT-SPI-invisible signal-only action"
assert_file_executable "$A11Y_RUNTIME" \
    "three-pass first-party AT-SPI runtime gate is executable"
assert_cmd_success "first-party AT-SPI runtime gate parses" bash -n "$A11Y_RUNTIME"
for lifecycle in live fresh-install reboot; do
    assert_grep_fixed "$lifecycle" "$A11Y_RUNTIME" \
        "AT-SPI gate recognizes $lifecycle"
done
for app_title in 'NoID Privacy Setup' 'NoID Privacy Network' \
        'NoID Privacy Update' 'NoID Privacy Tools'; do
    assert_grep_fixed "$app_title" "$A11Y_RUNTIME" \
        "AT-SPI gate launches and inspects $app_title"
done
assert_grep_fixed "'forbidden': {'Faster App Install via Terminal'}" \
    "$A11Y_RUNTIME" \
    "AT-SPI gate rejects the retired Setup Flatpak detour at runtime"
assert_grep_fixed "'WAN Privacy', 'LAN Exceptions', 'DNS Privacy'," \
    "$A11Y_RUNTIME" "AT-SPI gate clicks every Network section, including DNS Privacy"
assert_grep_fixed "'Audit tunnel MTU'" "$A11Y_RUNTIME" \
    "AT-SPI gate requires the read-only WireGuard MTU audit action"
assert_grep_fixed 'Setup, Network, Update and Tools expose named/described controls' \
    "$A11Y_RUNTIME" "AT-SPI success evidence names the complete inspected app set"
assert_grep_fixed "'Start Update'" "$A11Y_RUNTIME" \
    "AT-SPI gate observes Update without invoking its mutation"
assert_grep_fixed 'node.get_process_id() == process_id' "$A11Y_RUNTIME" \
    "AT-SPI gate binds each inspected frame to the launched process"
assert_grep_fixed 'returncode = proc.poll()' "$A11Y_RUNTIME" \
    "AT-SPI gate rejects a launcher that exits before exposing its window"
assert_grep_fixed 'pre-existing window must be closed before this gate' \
    "$A11Y_RUNTIME" "AT-SPI gate cannot pass against a stale existing frame"
assert_grep_fixed 'os.killpg(process_group, signal.SIGTERM)' "$A11Y_RUNTIME" \
    "AT-SPI gate terminates its complete test-owned process group"
assert_grep_fixed 'os.killpg(process_group, signal.SIGKILL)' "$A11Y_RUNTIME" \
    "AT-SPI gate has a bounded whole-group kill fallback"
assert_grep_fixed 'test-owned process group survived cleanup' "$A11Y_RUNTIME" \
    "AT-SPI gate refuses to pass with an orphaned helper"
assert_grep_fixed '=/usr/lib/noid-privacy/noid_ui.py' "$AIDE_SECURE_MANIFEST" \
    "shared UI contract has exact AIDE content coverage"
assert_not_grep 'python3 -m py_compile /usr/lib/noid-privacy/noid_ui.py' \
    "$KS_FILE" "production verification creates no untracked bytecode cache"

# --- Python shebang + GTK4 + libadwaita imports -----------------------------
assert_grep_fixed '#!/usr/bin/python3'                    "$SCRIPT" "Python3 shebang"
assert_grep_fixed "gi.require_version('Gtk', '4.0')"      "$SCRIPT" "GTK 4.0 import"
assert_grep_fixed "gi.require_version('Adw', '1')"        "$SCRIPT" "libadwaita import"
assert_grep_fixed 'from gi.repository import Gtk, Adw, Gio, GLib' "$SCRIPT" "Gtk + Adw + Gio + GLib"
assert_grep_fixed 'import noid_ui' "$SCRIPT" "Setup imports the shared UI contract"
assert_grep_fixed 'noid_ui.accessible_row(row)' "$SCRIPT" \
    "Setup explicitly labels icon-prefixed app rows"
assert_grep_fixed 'Remove this local XDG autostart entry' "$SCRIPT" \
    "Setup trash controls describe their exact local-file consequence"
assert_grep_fixed "AUTOSTART_DIR = Path(GLib.get_user_config_dir()) / 'autostart'" \
    "$SCRIPT" "Setup honors the XDG user configuration directory"
assert_not_grep "Path.home() / '.config' / 'autostart'" "$SCRIPT" \
    "Setup does not hardcode the default XDG configuration directory"
assert_grep_fixed '_parse_desktop_file(f, include_masked=True)' "$SCRIPT" \
    "current autostart view includes disabled local masks"
assert_grep_fixed "'hidden': hidden" "$SCRIPT" \
    "parsed autostart entries retain their Hidden state"
assert_grep_fixed "'no_display': no_display" "$SCRIPT" \
    "parsed autostart entries retain their NoDisplay state"
assert_grep_fixed 'Disabled local mask — removing it may restore an ' "$SCRIPT" \
    "Setup explains the consequence of removing an inherited-app mask"
if python3 - "$SCRIPT" "$TMPDIR" <<'PY'
import ast
from pathlib import Path
import sys

tree = ast.parse(Path(sys.argv[1]).read_text(encoding='utf-8'))
fn = next(node for node in tree.body
          if isinstance(node, ast.FunctionDef)
          and node.name == '_parse_desktop_file')
module = ast.Module(body=[fn], type_ignores=[])
ast.fix_missing_locations(module)
namespace = {'Path': Path, '_warn': lambda *_args: None}
exec(compile(module, '<autostart-parser-fixture>', 'exec'), namespace)
parse = namespace['_parse_desktop_file']
fixture_dir = Path(sys.argv[2])
hidden = fixture_dir / 'masked.desktop'
hidden.write_text('[Desktop Entry]\nHidden=true\n', encoding='utf-8')
assert parse(hidden) is None
hidden_info = parse(hidden, include_masked=True)
assert hidden_info['hidden'] is True
assert hidden_info['name'] == 'masked'
assert hidden_info['exec'] == ''
no_display = fixture_dir / 'menu-hidden.desktop'
no_display.write_text(
    '[Desktop Entry]\nName=Background App\nExec=/usr/bin/true\n'
    'NoDisplay=true\n', encoding='utf-8')
assert parse(no_display) is None
no_display_info = parse(no_display, include_masked=True)
assert no_display_info['no_display'] is True
assert no_display_info['name'] == 'Background App'
PY
then
    _pass "autostart parser exposes Hidden and NoDisplay local entries"
else
    _fail "autostart parser masked-entry fixtures"
fi
assert_grep_fixed "super().__init__(APP_ID, 'noid-privacy-setup')" "$SCRIPT" \
    "Setup uses its exact suite icon and one-instance base"
assert_grep_fixed "'NoID Privacy Setup', 'Guided system setup'" "$SCRIPT" \
    "Setup uses the common identity header"
assert_grep_fixed 'self.toast_overlay = Adw.ToastOverlay()' "$SCRIPT" \
    "Setup provides in-app failure feedback"
assert_not_grep 'Gio.ApplicationFlags.NON_UNIQUE' "$SCRIPT" \
    "Setup cannot open racing duplicate windows"

# --- App ID + state path constants ------------------------------------------
assert_grep_fixed "APP_ID = 'com.noidprivacy.Welcome'"    "$SCRIPT" "App ID constant"
assert_grep_fixed 'GLib.get_user_state_dir()'             "$SCRIPT" "uses XDG state dir (XDG_STATE_HOME)"
assert_grep_fixed "'noid-privacy'"                        "$SCRIPT" "state subdir noid-privacy"
assert_grep_fixed "'welcome-shown'"                       "$SCRIPT" "state file welcome-shown"

# --- CLI flags --------------------------------------------------------------
assert_grep_fixed "'--again' in sys.argv"                 "$SCRIPT" "supports --again flag"
assert_grep_fixed "'--autostart' in sys.argv"             "$SCRIPT" "supports --autostart flag (race fix)"
assert_grep_fixed "'--help' in sys.argv"                  "$SCRIPT" "supports --help flag"

# --- Idempotency state ------------------------------------------------------
assert_grep_fixed 'STATE_FILE.exists()'                   "$SCRIPT" "STATE_FILE check (one-shot guard)"
assert_grep_fixed 'STATE_FILE.touch()'                    "$SCRIPT" "STATE_FILE.touch() after present"
assert_grep_fixed 'FIRSTBOOT_REBOOT_MARKER'               "$SCRIPT" "firstboot reboot marker constant"
assert_grep_fixed 'def firstboot_reboot_pending'          "$SCRIPT" "firstboot completion-state reader"
assert_grep_fixed "['sudo', '-n', '/usr/libexec/noid-snapper-status']" \
    "$SCRIPT" "Welcome reuses the fixed-schema Snapper boot-state boundary"
assert_grep_fixed "'Required — Finish Installation'"      "$SCRIPT" "required firstboot completion title"
assert_grep_fixed "'The security kernel arguments are already active." \
    "$SCRIPT" "pending completion copy does not underclaim first-boot hardening"
assert_grep_fixed "'Restart and Finish Installation'"     "$SCRIPT" "explicit completion action"
assert_not_grep 'installation is not fully hardened\|kernel already running cannot adopt' \
    "$SCRIPT" "obsolete false security warning is absent"
assert_grep_fixed 'if not is_live_mode():'                 "$SCRIPT" "Live UI omits restart group"
assert_grep_fixed "token == 'rd.live.image'"              "$SCRIPT" "Live detection uses an exact token"
assert_grep_fixed "token.startswith('rd.live.image=')"    "$SCRIPT" "Live detection accepts valued token"
assert_grep_fixed 'Provider-agnostic walkthrough (WireGuard, ' "$SCRIPT" \
    "VPN walkthrough row names no preferred provider"
assert_grep_fixed "'OpenVPN profiles)'" "$SCRIPT" \
    "VPN walkthrough row names the exact supported protocol paths"
assert_not_grep "'OpenVPN, others)'" "$SCRIPT" \
    "VPN walkthrough does not imply untested protocol support"
assert_grep_fixed "'Install Proton VPN'" "$SCRIPT" \
    "direct Proton VPN install row present"
assert_grep_fixed "'Install Mullvad VPN'" "$SCRIPT" \
    "direct Mullvad VPN install row present"
assert_grep_fixed "run_in_terminal('/usr/local/bin/noid-protonvpn-install')" "$SCRIPT" \
    "Proton row spawns the pinned installer helper"
assert_grep_fixed "run_in_terminal('/usr/local/bin/noid-mullvad-install')" "$SCRIPT" \
    "Mullvad row spawns the pinned installer helper"
assert_grep_fixed "'Pre-VPN DNS compatibility'" "$SCRIPT" \
    "VPN group exposes the bootstrap DNS compatibility switch"
assert_grep_fixed "'Off keeps strict authenticated DoT on the physical uplink." "$SCRIPT" \
    "Setup scopes strict pre-VPN DoT to the physical uplink"
assert_grep_fixed "'inside the tunnel is a separate per-link setting.'" "$SCRIPT" \
    "Setup separates bootstrap DNS from in-tunnel DNS"
assert_grep_fixed "lines[0] != 'NOID-DNS-MODE-V2'" "$SCRIPT" \
    "Setup consumes the exact current DNS backend schema"
assert_grep_fixed "_privileged_argv([DNS_MODE_CLI, mode])" "$SCRIPT" \
    "Setup routes DNS changes through the exact pinned backend"
assert_grep_fixed "'Enable pre-VPN DNS compatibility?'" "$SCRIPT" \
    "Setup confirms the DNS/53 downgrade before enabling compatibility"
assert_grep_fixed "separately inherits NoID Privacy" "$SCRIPT" \
    "Setup attributes an unset tunnel transport to NoID Privacy"
assert_grep_fixed "best-effort opportunistic default" "$SCRIPT" \
    "Setup discloses the independent unset-tunnel default"
assert_grep_fixed "until Strict is selected again." "$SCRIPT" \
    "Setup warns that opportunistic mode outlives VPN activation"
assert_not_grep 'VPN DNS itself.*provider-owned' "$SCRIPT" \
    "Setup does not misattribute inherited tunnel transport to the provider"
assert_grep_fixed "_start_vpn_dns_mode(switch, 'strict')" "$SCRIPT" \
    "switch-off restores strict global and physical DNS policy"
assert_grep_fixed "_start_vpn_dns_mode(switch, 'opportunistic')" "$SCRIPT" \
    "confirmed switch-on selects the shared compatibility policy"
assert_not_grep 'VP8/9 video codecs' "$SCRIPT" \
    "codec row does not re-claim base-image codecs"
assert_not_grep 'after the second reboot'                 "$SCRIPT" "stale blanket second-reboot claim removed"

# Restart is never dispatched directly from the action-row callback. The
# native dialog defaults/closes to Cancel and only its exact confirm response
# reaches systemctl. AST structure prevents comments/strings from satisfying
# this UX contract.
if python3 - "$SCRIPT" <<'PY'
import ast
import sys

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
outer = next(node for node in tree.body
             if isinstance(node, ast.FunctionDef) and node.name == 'act_reboot')
nested = next(node for node in outer.body
              if isinstance(node, ast.FunctionDef) and node.name == 'on_response')
direct_spawns = [node for statement in outer.body
                 for node in ast.walk(statement)
                 if not isinstance(statement, ast.FunctionDef)
                 and isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name)
                 and node.func.id == 'spawn_app']
if direct_spawns:
    raise SystemExit('direct reboot spawn bypasses confirmation')
outer_calls = [node for node in ast.walk(outer) if isinstance(node, ast.Call)]
if not any(isinstance(node.func, ast.Attribute)
           and node.func.attr == 'set_default_response'
           and len(node.args) == 1
           and isinstance(node.args[0], ast.Constant)
           and node.args[0].value == 'cancel' for node in outer_calls):
    raise SystemExit('restart dialog lacks cancel default')
if not any(isinstance(node.func, ast.Attribute)
           and node.func.attr == 'set_close_response'
           and len(node.args) == 1
           and isinstance(node.args[0], ast.Constant)
           and node.args[0].value == 'cancel' for node in outer_calls):
    raise SystemExit('restart dialog lacks cancel close response')
if not any(isinstance(node.func, ast.Attribute)
           and node.func.attr == 'set_response_appearance'
           and len(node.args) == 2
           and isinstance(node.args[0], ast.Constant)
           and node.args[0].value == 'restart'
           and isinstance(node.args[1], ast.Attribute)
           and node.args[1].attr == 'DESTRUCTIVE' for node in outer_calls):
    raise SystemExit('restart confirmation is not marked destructive')
if not any(isinstance(node.func, ast.Attribute)
           and node.func.attr == 'present'
           and len(node.args) == 1
           and isinstance(node.args[0], ast.Call)
           and isinstance(node.args[0].func, ast.Attribute)
           and node.args[0].func.attr == 'get_root' for node in outer_calls):
    raise SystemExit('restart dialog is not parented to the application window')
guards = [node for node in nested.body if isinstance(node, ast.If)]
if len(guards) != 1 or not isinstance(guards[0].test, ast.Compare):
    raise SystemExit('restart response lacks one explicit guard')
comparison = guards[0].test
if (len(comparison.ops) != 1 or not isinstance(comparison.ops[0], ast.Eq)
        or len(comparison.comparators) != 1
        or not isinstance(comparison.comparators[0], ast.Constant)
        or comparison.comparators[0].value != 'restart'):
    raise SystemExit('restart response guard is not exact')
spawns = [node for node in ast.walk(guards[0])
          if isinstance(node, ast.Call)
          and isinstance(node.func, ast.Name)
          and node.func.id == 'spawn_app']
if len(spawns) != 1:
    raise SystemExit('confirmed restart dispatch cardinality differs')

welcome = next(node for node in tree.body
               if isinstance(node, ast.ClassDef)
               and node.name == 'WelcomeWindow')
initializer = next(node for node in welcome.body
                   if isinstance(node, ast.FunctionDef)
                   and node.name == '__init__')
live_guards = []
for node in ast.walk(initializer):
    if not isinstance(node, ast.If) or not isinstance(node.test, ast.UnaryOp):
        continue
    operand = node.test.operand
    if (isinstance(node.test.op, ast.Not)
            and isinstance(operand, ast.Call)
            and isinstance(operand.func, ast.Name)
            and operand.func.id == 'is_live_mode'):
        live_guards.append(node)
if len(live_guards) != 4:
    raise SystemExit('installed-only guard cardinality differs')
def guard_strings(guard):
    return {node.value for node in ast.walk(guard)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)}
restart_guards = [guard for guard in live_guards
                  if 'Required — Finish Installation' in guard_strings(guard)]
if len(restart_guards) != 1:
    raise SystemExit('required restart group escaped the installed-only guard')
if not any(isinstance(node, ast.Call)
           and isinstance(node.func, ast.Attribute)
           and node.func.attr == 'add'
           and len(node.args) == 1
           and isinstance(node.args[0], ast.Name)
           and node.args[0].id == 'final'
           for node in ast.walk(restart_guards[0])):
    raise SystemExit('installed-only guard does not own final-group publication')
codec_guards = [guard for guard in live_guards
                if 'Install Multimedia Codecs + GPU HW-Decode'
                in guard_strings(guard)]
if len(codec_guards) != 1:
    raise SystemExit('codec install row escaped the installed-only guard')
vpn_guards = [guard for guard in live_guards
              if 'Install Proton VPN' in guard_strings(guard)
              and 'Install Mullvad VPN' in guard_strings(guard)]
if len(vpn_guards) != 1:
    raise SystemExit('VPN install rows escaped the installed-only guard')
gaming_guards = [guard for guard in live_guards
                 if 'Gaming Mode (Steam / Proton)' in guard_strings(guard)]
if len(gaming_guards) != 1:
    raise SystemExit('Gaming Mode escaped the installed-only guard')
PY
then
    _pass "restart action is cancel-default and exact-confirm-only"
else
    _fail "restart action confirmation contract invalid"
fi

# --- Hardware/system detection functions ------------------------------------
for fn in \
    'def has_luks' \
    'def has_nvidia' \
    'def has_nvidia_proprietary' \
    'def read_status'; do
    assert_grep_fixed "$fn" "$SCRIPT" "detect fn: $fn"
done

# System-level USBGuard/MEI state belongs to noid-status; the Welcome UI has no
# dead constants whose only purpose is satisfying self-referential greps.
assert_not_grep 'MEI_STATUS_FILE' "$SCRIPT" "Welcome has no dead MEI audit anchor"
assert_not_grep 'USBGUARD_STATUS_FILE' "$SCRIPT" "Welcome has no dead USBGuard audit anchor"

# --- Action handlers (wizard-merge: act_wizard removed, mic/cam +
# updates added directly into Welcome) -----------------------------------------
for fn in \
    'def act_luks_backup' \
    'def act_vpn_setup' \
    'def on_vpn_dns_compatibility_toggle' \
    'def act_codecs' \
    'def act_firefox_drm' \
    'def act_nvidia_install' \
    'def act_install_claude_code' \
    'def act_install_codex' \
    'def on_aide_toggle' \
    'def on_audit_toggle' \
    'def act_doc_getting_started' \
    'def act_doc_hardware'; do
    assert_grep_fixed "$fn" "$SCRIPT" "action handler: $fn"
done

# --- Terminal close-prompt contract: run_in_terminal() owns exactly ONE
# hold for every terminal-backed action row. NOID_WELCOME_SPAWN=1 skips the
# companion scripts' standalone prompt; the trailing exit 0 keeps Ptyxis
# from stacking its process-failed hold on top (it keeps the window open on
# any non-zero exit — the historical "double ENTER" on the LUKS backup).
assert_grep_fixed 'def run_in_terminal' "$SCRIPT" \
    "unified terminal wrapper helper exists"
assert_grep_fixed "'NOID_WELCOME_SPAWN=1 ' + command_path" "$SCRIPT" \
    "wrapper marks welcome-spawned terminals for companion scripts"
assert_grep_fixed "read -r -p \"Press ENTER to close...\" || :; exit 0" "$SCRIPT" \
    "wrapper holds once and exits 0 (no terminal-level second hold)"
assert_not_grep 'read -r -p "Press ENTER to close..."; }' "$SCRIPT" \
    "no conditional-block hold remains (returned rc=1 on success)"
for wrapped in \
    "run_in_terminal('/usr/local/bin/noid-luks-backup.sh')" \
    "run_in_terminal('/usr/local/bin/noid-complete-setup.sh')" \
    "run_in_terminal('/usr/local/bin/noid-firefox-drm enable')" \
    "run_in_terminal('/usr/local/bin/noid-nvidia-install.sh')" \
    "run_in_terminal('/usr/local/bin/noid-claude-install')" \
    "run_in_terminal('/usr/local/bin/noid-codex-install')" \
    "run_in_terminal('/usr/local/bin/noid-protonvpn-install')" \
    "run_in_terminal('/usr/local/bin/noid-mullvad-install')"; do
    assert_grep_fixed "$wrapped" "$SCRIPT" "wrapped terminal action: $wrapped"
done
assert_grep_fixed 'def act_open_tools_app' "$SCRIPT" \
    "Tools app cross-link handler exists"
assert_grep_fixed "spawn_app(['/usr/local/bin/noid-tools'])" "$SCRIPT" \
    "Tools cross-link launches the Module 37 app"
assert_grep_fixed "'Open NoID Privacy Tools'" "$SCRIPT" \
    "Setup surfaces the Tools launcher row"
assert_grep_fixed 'def act_open_software_with_rpms' "$SCRIPT" \
    "Setup owns the GNOME Software Fedora-RPM action"
assert_grep_fixed "spawn_app(['/usr/local/bin/noid-gnome-software-rpm'])" \
    "$SCRIPT" "Setup launches the exact one-shot helper"
assert_grep_fixed "software_sources.set_title('GNOME Software Sources')" \
    "$SCRIPT" "Setup gives the one-shot its own accurately named group"
assert_grep_fixed 'noid_ui.icon_action_row(' "$SCRIPT" \
    "Setup uses a native themed icon action row"
assert_grep_fixed "'org.gnome.Software', 'Open GNOME Software with Fedora RPMs'" \
    "$SCRIPT" "Setup uses GNOME Software's own theme icon and full name"
assert_grep_fixed 'def add_icon_prefix(row, icon_name):' "$UI_COMMON" \
    "shared UI supports native themed row icons"
assert_grep_fixed 'def icon_action_row(icon_name, title, subtitle, callback):' \
    "$UI_COMMON" "shared UI owns the accessible native-icon action pattern"
for retired_flatpak_detour in \
    'def act_flatpak_tip' \
    'Faster App Install via Terminal' \
    'Skip Software Center for verified Flatpaks' \
    'If Software search stalls' \
    'NoID Privacy Flatpak CLI' \
    'flatpak install flathub-verified APP_ID'; do
    assert_not_grep "$retired_flatpak_detour" "$SCRIPT" \
        "retired Setup Flatpak detour stays absent: $retired_flatpak_detour"
done
assert_grep_fixed "'Enable Firefox DRM / Widevine'" "$SCRIPT" \
    "Setup surfaces the Firefox DRM opt-in beside media options"
assert_grep_fixed "'Required for Prime Video, Netflix and similar '" "$SCRIPT" \
    "Firefox DRM row names the affected streaming services"
assert_grep_fixed "'download after a separate opt-in for each Firefox '" "$SCRIPT" \
    "Firefox DRM row discloses independent profile-local consent"
assert_not_grep "'download for the default Firefox profile'" "$SCRIPT" \
    "Firefox DRM row does not promise an implicit default-profile change"
assert_not_grep 'exit "\$gaming_rc"' "$SCRIPT" \
    "gaming terminal exits 0 (result file carries the real rc)"

# --- Emoji prefix uniqueness: every row/switch glyph in the Setup dialog is
# distinct so rows stay visually scannable (historic dups: globe x3, gamepad,
# shield, refresh-arrows).
if python3 - "$SCRIPT" <<'PY'
import re
import sys
import collections
src = open(sys.argv[1], encoding='utf-8').read()
emojis = re.findall(r"_row\(\s*'([^']+)',", src)
emojis += re.findall(r"add_emoji_prefix\([A-Za-z_.]+,\s*'([^']+)'\)", src)
if len(emojis) < 20:
    raise SystemExit('emoji census implausibly small: %d' % len(emojis))
dups = {glyph: n for glyph, n in collections.Counter(emojis).items() if n > 1}
if dups:
    raise SystemExit('duplicate emoji prefixes: %r' % dups)
PY
then
    _pass "Setup dialog emoji prefixes are unique"
else
    _fail "Setup dialog has duplicate emoji prefixes"
fi

# --- wizard-merge: hardware privacy switches in Welcome dialog -------
# Camera remains a direct gsetting. Microphone uses M17's two-layer
# transactional helper and fail-closed policy/status read.
for hw_marker in \
    "'Hardware Privacy'" \
    "'Disable Microphone'" \
    "'Disable Camera'" \
    "'org.gnome.desktop.privacy'" \
    "'disable-microphone'" \
    "'disable-camera'"; do
    assert_grep_fixed "$hw_marker" "$SCRIPT" "wizard-merged hw-privacy: $hw_marker"
done
assert_grep_fixed "['/usr/local/bin/noid-toggle-microphone', command]" "$SCRIPT" \
    "Welcome microphone switch uses the transactional policy helper"

# --- USB device policy + printing opt-in ----------------------------
# Both are capability opt-ins, so ON means AVAILABLE — the inverse of the
# Hardware Privacy switches directly above them. The two follow-up rows are
# load-bearing, not decoration: on this image enabling CUPS alone prints
# nothing, because a USB printer still needs a USBGuard decision and a network
# printer still needs an outbound LAN exception past block-lan-out.
for setup_marker in \
    "'Devices'" \
    "'Manage USB Devices'" \
    "/usr/local/bin/noid-usbguard-devices" \
    "'Printing'" \
    "'Enable Printing (CUPS)'" \
    "/usr/local/sbin/noid-toggle-printing" \
    "'USB Printer — Manage the Device'" \
    "'Network Printer — Allow its Address'"; do
    assert_grep_fixed "$setup_marker" "$SCRIPT" \
        "Setup surfaces device/printing policy: $setup_marker"
done
assert_grep_fixed "_privileged_toggle_async('printing', not switch.get_active())" \
    "$SCRIPT" "the printing switch drives the reviewed CLI, never systemctl directly"
# The switch has no flag file — its truth is the unit state the CLI writes, and
# one unit must not be trusted to represent the set: an enabled socket beside a
# hand-masked service still prints nothing.
assert_grep_fixed "is_unit_enabled('cups.socket')" "$SCRIPT" \
    "the printing switch reads the activation unit the CLI enables"
assert_grep_fixed "not _is_unit_masked('cups.service')" "$SCRIPT" \
    "the printing switch also rejects a hand-masked service"
# The network-printer step is only actionable on LAN Exceptions, so the row
# lands there instead of telling the user to go looking for the right tab.
assert_grep_fixed "['/usr/local/bin/noid-network', '--section', 'lan']" \
    "$SCRIPT" "the network-printer row deep-links into LAN Exceptions"
assert_grep_fixed 'act_open_network_lan' "$SCRIPT" \
    "the deep-link handler is wired, not just defined"

# --- reviewed page order --------------------------------------------
# The sequence is an argument, not a list: secure what cannot be recovered,
# get the network right before downloading anything, decide what the hardware
# may do, then what software exists, then what starts by itself, then what
# reports trouble, and only then where to read on. Two dependencies are real
# rather than aesthetic -- updates must follow the VPN group that tells the
# user to bring the tunnel up first, and the autostart picker can only offer
# applications the install groups above have already put on disk. A new group
# appended in the wrong place breaks that reading without breaking anything
# else, so pin the order here.
m13_page_order() {
    python3 - "$SCRIPT" <<'PAGE_ORDER_EOF'
import ast, re, sys

source = open(sys.argv[1], encoding='utf-8').read()
titles = {}
for node in ast.walk(ast.parse(source)):
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == 'set_title'
            and isinstance(node.func.value, ast.Name)
            and node.args and isinstance(node.args[0], ast.Constant)):
        titles[node.func.value.id] = node.args[0].value
order = [titles.get(v, v)
         for v in re.findall(r'^ {8,12}page\.add\((\w+)\)$', source, re.M)
         if v != 'final']
expected = [
    'Critical — Do These First',
    'VPN — Install Before Updates &amp; Apps',
    'System Updates',
    'GNOME Software Sources',
    'Hardware Privacy',
    'Devices',
    'AI Development Tools',
    'Media &amp; Graphics',
    'Printing',
    'Gaming Mode (Steam / Proton)',
    'App Autostart',
    'Security Notifications',
    'Companion Apps',
    'Reference',
    'Project &amp; Ecosystem',
]
if order != expected:
    raise SystemExit('Setup page order drifted:\n  is  %r\n  want %r'
                     % (order, expected))
PAGE_ORDER_EOF
}
assert_cmd_success "Setup page groups appear in the reviewed order" \
    m13_page_order

# --- laptop lid -----------------------------------------------------
# Three states, so the widget must be a ComboRow: a switch would have to
# misrepresent one of lock / suspend / no-pinned-choice. The helper refuses to
# run as root and escalates itself through its own closed sudoers bridge, so
# routing it through _privileged_argv would make every change fail. The lid row
# lives in the merged Devices group; its own title is what pins it here.
for lid_marker in \
    "'Laptop Lid Action'" \
    "Adw.ComboRow()" \
    "'Lock the screen', 'Suspend', 'System default'" \
    "LID_ACTION_CHOICES = ('lock', 'suspend', 'reset')"; do
    assert_grep_fixed "$lid_marker" "$SCRIPT" \
        "Setup surfaces the lid choice: $lid_marker"
done
assert_grep_fixed 'spawn_app([LID_ACTION_CLI, LID_ACTION_CHOICES[index]])' \
    "$SCRIPT" "the lid change runs as the desktop user, never through sudo/pkexec"
assert_not_grep '_privileged_argv(\[LID_ACTION_CLI' "$SCRIPT" \
    "the lid helper is never wrapped in a privilege escalation it rejects"
assert_grep_fixed "lid_row.set_subtitle('No lid switch detected on this system')" \
    "$SCRIPT" "a machine without a lid switch shows the reason instead of a dead control"
assert_grep_fixed "combo.set_sensitive(choice is not None)" "$SCRIPT" \
    "an independently changed policy file locks the row instead of inventing a state"

# Every other subtitle in this dialog is written for a reader. Pasting the
# helper's `lid=… external-power=… docked=…` line in verbatim made this the one
# row that spoke in key=value, so it is rendered as prose — and the renderer
# must refuse to guess: an unmapped handler value or a changed field set has to
# fall back to the raw line rather than invent a sentence.
m13_lid_prose() {
    python3 - "$SCRIPT" <<'LID_PROSE_EOF'
import ast, sys

source = open(sys.argv[1], encoding='utf-8').read()
wanted = {}
for node in ast.parse(source).body:
    if (isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == 'LID_EFFECT_PHRASES'):
        wanted['map'] = node
    if (isinstance(node, ast.FunctionDef)
            and node.name == '_lid_effective_prose'):
        wanted['func'] = node
if set(wanted) != {'map', 'func'}:
    raise SystemExit('LID_EFFECT_PHRASES or _lid_effective_prose is missing')

namespace = {}
exec(compile(ast.Module(body=[wanted['map'], wanted['func']], type_ignores=[]),
             '<m13>', 'exec'), namespace)
render = namespace['_lid_effective_prose']

cases = [
    ('lid=lock external-power=lock docked=ignore',
     'locks the screen on battery and on external power; '
     'does nothing while docked'),
    ('lid=lock external-power=suspend docked=lock',
     'locks the screen on battery, suspends on external power; '
     'locks the screen while docked'),
    # Fail-safe: an unmapped logind handler and a changed field set must both
    # come back unchanged.
    ('lid=kexec external-power=lock docked=ignore',
     'lid=kexec external-power=lock docked=ignore'),
    ('lid=lock docked=ignore', 'lid=lock docked=ignore'),
    ('', ''),
]
for effective, expected in cases:
    got = render(effective)
    if got != expected:
        raise SystemExit('prose for %r was %r, expected %r'
                         % (effective, got, expected))
LID_PROSE_EOF
}
assert_cmd_success "the lid subtitle reads as prose and never guesses a value" \
    m13_lid_prose
# Count the call sites rather than pattern-matching one spelling of the
# statement: both subtitle writers are line-wrapped, so a single-line grep for
# the withdrawn form matches nothing and proves nothing.
assert_eq 2 "$(grep -cF '+ _lid_effective_prose(' "$SCRIPT")" \
    "both lid subtitle writers route through the prose renderer"
assert_grep_fixed 'def _wireplumber_mic_policy_disabled' "$SCRIPT" \
    "Welcome reads the persistent WirePlumber microphone setting"
assert_grep_fixed '(wp_policy_off is not False)' "$SCRIPT" \
    "unknown WirePlumber microphone state is displayed fail-closed"
assert_grep_fixed 'WP_MIC_SETTING_RE.fullmatch' "$SCRIPT" \
    "Welcome rejects malformed wpctl setting output"
assert_grep_fixed 'GLib.timeout_add_seconds(8, _resync_mic, switch)' "$SCRIPT" \
    "Welcome resync covers the helper's bounded durable transaction"
assert_grep_fixed 'def _privileged_action_async(argv)' "$SCRIPT" \
    "AIDE and audit actions retain a process handle"
assert_grep_fixed 'def _resync_switch_when_done' "$SCRIPT" \
    "AIDE and audit switches resync on helper completion"
assert_grep_fixed 'attempts[0] < 120' "$SCRIPT" \
    "privileged-action polling has a bounded UI deadline"
assert_not_grep_extended 'timeout_add_seconds\(5, _resync_(aide|audit)' "$SCRIPT" \
    "AIDE and audit switches do not race a fixed five-second polkit delay"
assert_grep_fixed "'disable-microphone', False" "$SCRIPT" \
    "failed microphone gsettings reads do not falsely claim protection"
assert_grep_fixed "'disable-camera', False" "$SCRIPT" \
    "failed camera gsettings reads do not falsely claim protection"
assert_grep_fixed "'org.gnome.system.location', 'enabled', True" "$SCRIPT" \
    "failed location reads do not invert the conservative UI fallback"
assert_grep_fixed 'Path(path).lstat()' "$SCRIPT" \
    "privacy flag reads distinguish absence from filesystem errors"
assert_grep_fixed 'except FileNotFoundError:' "$SCRIPT" \
    "privacy flag absence has an explicit reachable branch"
if python3 - "$SCRIPT" <<'PY'
import ast
import sys

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
fn = next(node for node in tree.body
          if isinstance(node, ast.FunctionDef)
          and node.name == '_flag_file_present')
gaming_fn = next(node for node in tree.body
                 if isinstance(node, ast.FunctionDef)
                 and node.name == '_gaming_enabled')
module = ast.Module(body=[fn, gaming_fn], type_ignores=[])
ast.fix_missing_locations(module)
state = {'result': 'present'}
class FakePath:
    def __init__(self, _path): pass
    def lstat(self):
        if state['result'] == 'absent':
            raise FileNotFoundError
        if state['result'] == 'error':
            raise PermissionError
namespace = {
    'Path': FakePath,
    'GAMING_FLAG': '/gaming-fixture',
    '_warn': lambda *_args: None,
}
exec(compile(module, '<flag-state-fixture>', 'exec'), namespace)
present = namespace['_flag_file_present']
gaming_enabled = namespace['_gaming_enabled']
assert present('/fixture') is True
assert gaming_enabled() is True
state['result'] = 'absent'
assert present('/fixture') is False
assert gaming_enabled() is False
state['result'] = 'error'
assert present('/fixture') is True
assert gaming_enabled() is True
PY
then
    _pass "privacy and gaming flag readers distinguish absence from conservative errors"
else
    _fail "privacy flag state fixtures"
fi
if python3 - "$SCRIPT" <<'PY'
import ast
import sys

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
fn = next(node for node in tree.body
          if isinstance(node, ast.FunctionDef)
          and node.name == '_gsetting_is_true')
module = ast.Module(body=[fn], type_ignores=[])
ast.fix_missing_locations(module)
class FailedSubprocess:
    @staticmethod
    def check_output(*_args, **_kwargs):
        raise OSError('fixture')
namespace = {
    'subprocess': FailedSubprocess,
    'PROCESS_ERRORS': (OSError,),
    '_warn': lambda *_args: None,
}
exec(compile(module, '<gsetting-fallback-fixture>', 'exec'), namespace)
read_bool = namespace['_gsetting_is_true']
assert read_bool('schema', 'key', False) is False
assert read_bool('schema', 'key', True) is True
PY
then
    _pass "gsettings failure preserves the caller-specific UI fallback polarity"
else
    _fail "gsettings fallback polarity fixtures"
fi
assert_not_grep 'def _pipewire_set_mic_mute' "$SCRIPT" \
    "Welcome has no competing direct microphone policy writer"
assert_grep_fixed 'noid-toggle-microphone status' "$KS_FILE" \
    "installed hardware-privacy documentation uses the coordinated mic CLI"
assert_not_grep 'gsettings set org.gnome.desktop.privacy disable-microphone false' \
    "$KS_FILE" "installed docs do not bypass the persistent microphone layer"
assert_not_grep 'LOC_FLAG' "$SCRIPT" \
    "Welcome has no obsolete Location flag constant"
assert_not_grep 'location-disabled.flag' "$SCRIPT" \
    "Welcome has no obsolete Location flag state"
assert_grep_fixed "'org.gnome.system.location', 'enabled'" "$SCRIPT" \
    "Welcome reads the authoritative Location gsetting"
assert_not_grep 'AIDE database update' "$KS_FILE" \
    "Welcome docs do not claim agent-owned AIDE database updates"
assert_not_grep 'AIDE rebuild' "$KS_FILE" \
    "Welcome UI does not claim agent-owned AIDE rebaselining"
assert_grep_fixed 'one-shot GNOME-initial-setup sentinel wait' "$AUTOSTART_DESKTOP" \
    "autostart desktop comment matches the executable sentinel wait"

# --- Helper-script paths referenced in action handlers ----------------------
assert_grep_fixed '/usr/local/bin/noid-luks-backup.sh'           "$SCRIPT" "luks-backup path"
assert_grep_fixed '/usr/local/bin/noid-complete-setup.sh'        "$SCRIPT" "complete-setup path"
assert_grep_fixed '/usr/local/bin/noid-firefox-drm enable'       "$SCRIPT" "Firefox DRM opt-in path"
assert_grep_fixed '/usr/local/bin/noid-nvidia-install.sh'        "$SCRIPT" "nvidia-install path"
assert_grep_fixed '/usr/local/bin/noid-claude-install'           "$SCRIPT" "claude-install path"
assert_grep_fixed '/usr/local/bin/noid-codex-install'            "$SCRIPT" "codex-install path"
assert_cmd_success "Claude installer: bash -n clean" bash -n "$CLAUDE_INSTALLER"
assert_grep_extended '^CLAUDE_VERSION="[0-9]+\.[0-9]+\.[0-9]+"$' "$CLAUDE_INSTALLER" \
    "Claude installer pins native release version"
assert_grep_fixed 'CLAUDE_VERSION="2.1.241"' "$CLAUDE_INSTALLER" \
    "Claude native seed matches the reviewed vendor release"
assert_grep_fixed 'CLAUDE_SHA256="0771bd866cff82b76581fc0499f6529e1a36845078f144f8c81dccb3bc7037b8"' \
    "$CLAUDE_INSTALLER" \
    "Claude 2.1.241 native seed is bound to the reviewed vendor bytes"
assert_grep_fixed 'CLAUDE_SIZE="342636848"' "$CLAUDE_INSTALLER" \
    "Claude 2.1.241 native seed is bound to the reviewed byte count"
assert_grep_extended '^CLAUDE_SHA256="[0-9a-f]{64}"$' "$CLAUDE_INSTALLER" \
    "Claude installer pins native release SHA256"
assert_grep_extended '^CLAUDE_SIZE="[0-9]+"$' "$CLAUDE_INSTALLER" \
    "Claude installer pins native release byte count"
assert_grep_fixed 'actual_sha=$(sha256sum "$DOWNLOAD"' "$CLAUDE_INSTALLER" \
    "Claude installer verifies downloaded SHA256"
assert_grep_fixed '[ "$actual_sha" = "$CLAUDE_SHA256" ]' "$CLAUDE_INSTALLER" \
    "Claude installer fails closed on changed native binary"
assert_grep_fixed "--proto '=https' --proto-redir '=https' --tlsv1.2" \
    "$CLAUDE_INSTALLER" "Claude installer keeps redirects on HTTPS"
assert_grep_fixed '--max-redirs 3' "$CLAUDE_INSTALLER" \
    "Claude installer bounds redirect traversal"
assert_not_grep 'npm install' "$CLAUDE_INSTALLER" \
    "Claude installer never invokes npm install"
assert_grep_fixed 'DOWNLOAD=$(mktemp /var/tmp/noid-claude.' "$CLAUDE_INSTALLER" \
    "Claude installer keeps its large native payload off RAM-backed /tmp"
assert_grep_fixed 'VSIX=$(mktemp /var/tmp/noid-claude-ext.' "$CLAUDE_INSTALLER" \
    "Claude installer keeps extension payloads off RAM-backed /tmp"
assert_not_grep_extended 'mktemp[[:space:]]+/tmp/noid-claude' "$CLAUDE_INSTALLER" \
    "Claude installer has no large payload scratch under RAM-backed /tmp"
assert_not_grep 'bash "$INSTALLER"' "$CLAUDE_INSTALLER" \
    "Claude installer never executes a downloaded installer"
HELP_ONLY_PATH="$TMPDIR/help-only-bin"
mkdir -p "$HELP_ONLY_PATH"
ln -s /usr/bin/cat "$HELP_ONLY_PATH/cat"
assert_cmd_success "Claude installer --help is side-effect-free and noninteractive" \
    env PATH="$HELP_ONLY_PATH" /bin/bash "$CLAUDE_INSTALLER" --help
assert_cmd_success "Claude installer -h is side-effect-free and noninteractive" \
    env PATH="$HELP_ONLY_PATH" /bin/bash "$CLAUDE_INSTALLER" -h
assert_grep_extended '^EXT_VERSION="[0-9]+\.[0-9]+\.[0-9]+"$' "$CLAUDE_INSTALLER" \
    "Claude installer pins its VSCodium extension version"
assert_grep_fixed 'EXT_VERSION="2.1.241"' "$CLAUDE_INSTALLER" \
    "Claude VSCodium seed matches the reviewed fixed client release"
assert_grep_fixed 'EXT_SHA256="1af9fd16fe55873073685a6e562afa54f142d237b4500ca1dcb02b63c3328e90"' \
    "$CLAUDE_INSTALLER" \
    "Claude 2.1.241 VSIX seed is bound to the reviewed Open VSX bytes"
assert_grep_fixed 'EXT_SIZE="107201776"' "$CLAUDE_INSTALLER" \
    "Claude 2.1.241 VSIX seed is bound to the reviewed byte count"
assert_grep_fixed 'Install the pinned Claude Code VSCodium extension? [y/N]' \
    "$CLAUDE_INSTALLER" "Claude extension sits behind its own prompt"
assert_grep_fixed 'codium --install-extension "$1" --force' "$CLAUDE_INSTALLER" \
    "Claude installer installs only the verified local VSIX"
assert_not_grep 'Close VSCodium before changing its extensions' \
    "$CLAUDE_INSTALLER" \
    "Claude extension updates use Codium's supported live CLI path"
assert_grep_fixed 'reload or restart it to activate the installed extension bytes' \
    "$CLAUDE_INSTALLER" \
    "Claude extension update names the live-editor activation boundary"
assert_grep_fixed 'claude update' "$CLAUDE_INSTALLER" \
    "Claude update mode uses Anthropic's native updater"
assert_grep_fixed 'Next (CLI): claude auth login' "$CLAUDE_INSTALLER" \
    "Claude CLI opt-in names the current authentication command"
assert_grep_fixed 'open the Claude Code panel and use its first-use sign-in screen' \
    "$CLAUDE_INSTALLER" \
    "extension-only opt-in has a working first-run authentication path"
assert_not_grep 'Next: claude login' "$CLAUDE_INSTALLER" \
    "obsolete ambiguous Claude login instruction is absent"
assert_grep_fixed 'exit 3' "$CLAUDE_INSTALLER" \
    "Claude helper reports the never-opted-in state distinctly"

assert_cmd_success "Codex installer: bash -n clean" bash -n "$CODEX_INSTALLER"
assert_grep_fixed "--proto '=https' --proto-redir '=https' --tlsv1.2" \
    "$CODEX_INSTALLER" "Codex installer keeps redirects on HTTPS"
assert_grep_fixed '--max-redirs 3' "$CODEX_INSTALLER" \
    "Codex installer bounds redirect traversal"
assert_grep_fixed 'ARCHIVE=$(mktemp /var/tmp/noid-codex.' "$CODEX_INSTALLER" \
    "Codex installer keeps its large native payload off RAM-backed /tmp"
assert_grep_fixed 'VSIX=$(mktemp /var/tmp/noid-codex-ext.' "$CODEX_INSTALLER" \
    "Codex installer keeps extension payloads off RAM-backed /tmp"
assert_not_grep_extended 'mktemp[[:space:]]+/tmp/noid-codex' "$CODEX_INSTALLER" \
    "Codex installer has no large payload scratch under RAM-backed /tmp"
assert_grep_extended '^CODEX_VERSION="[0-9]+\.[0-9]+\.[0-9]+"$' "$CODEX_INSTALLER" \
    "Codex installer pins standalone version"
assert_grep_fixed 'CODEX_VERSION="0.149.1"' "$CODEX_INSTALLER" \
    "Codex standalone seed matches the reviewed stable release"
assert_grep_fixed 'CODEX_SHA256="1e8531ae5f6dea3c6e11e53e74cc5ac81bf1ba597f9b296fb112d6ea30fdaf5d"' \
    "$CODEX_INSTALLER" \
    "Codex 0.149.1 standalone seed matches the official release digest"
assert_grep_fixed 'CODEX_SIZE="122578702"' "$CODEX_INSTALLER" \
    "Codex 0.149.1 standalone seed is bound to the reviewed byte count"
assert_grep_extended '^CODEX_SHA256="[0-9a-f]{64}"$' "$CODEX_INSTALLER" \
    "Codex installer pins standalone SHA256"
assert_grep_fixed 'EXT_VERSION="26.5818.61809"' "$CODEX_INSTALLER" \
    "Codex VSCodium seed matches the reviewed Open VSX release"
assert_grep_fixed 'EXT_SHA256="8ac93a0682eda97ff79d0ef6e4b7d8344615f8dc1ebd816b7863f5a0629ea33e"' \
    "$CODEX_INSTALLER" \
    "Codex VSCodium seed matches the Open VSX published digest"
assert_grep_fixed 'EXT_SIZE="228819497"' "$CODEX_INSTALLER" \
    "Codex VSCodium seed is bound to the reviewed byte count"
assert_grep_extended '^EXT_SHA256="[0-9a-f]{64}"$' "$CODEX_INSTALLER" \
    "Codex installer pins VSCodium VSIX SHA256"
assert_grep_fixed 'codex-package-x86_64-unknown-linux-musl.tar.gz' "$CODEX_INSTALLER" \
    "Codex installer uses native standalone package"
assert_grep_fixed 'Unsafe archive path:' "$CODEX_INSTALLER" \
    "Codex installer rejects archive path traversal"
assert_grep_fixed 'Archive contains a link or special file.' "$CODEX_INSTALLER" \
    "Codex installer rejects archive links and special files"
assert_grep_fixed 'PRE-RELEASE' "$CODEX_INSTALLER" \
    "Codex installer discloses Open VSX pre-release boundary"
assert_grep_fixed 'contains OpenAI product telemetry' "$CODEX_INSTALLER" \
    "Codex installer discloses extension telemetry boundary"
assert_grep_fixed 'NR>2 && substr($1,1,1)=="l"' "$CODEX_INSTALLER" \
    "VSIX symlink validation includes the first archive member"
assert_not_grep 'NR>3 && substr' "$CODEX_INSTALLER" \
    "off-by-one VSIX member boundary is absent"
assert_grep_fixed 'codium --install-extension "$1" --pre-release --force' "$CODEX_INSTALLER" \
    "Codex installer installs only verified local VSIX"
assert_not_grep 'Close VSCodium before changing its extensions' \
    "$CODEX_INSTALLER" \
    "Codex extension updates use Codium's supported live CLI path"
assert_grep_fixed 'reload or restart it to activate the installed extension bytes' \
    "$CODEX_INSTALLER" \
    "Codex extension update names the live-editor activation boundary"
assert_not_grep 'npm install' "$CODEX_INSTALLER" \
    "Codex installer never invokes npm install"
assert_cmd_success "Codex installer --help is side-effect-free and noninteractive" \
    env PATH="$HELP_ONLY_PATH" /bin/bash "$CODEX_INSTALLER" --help
assert_cmd_success "Codex installer -h is side-effect-free and noninteractive" \
    env PATH="$HELP_ONLY_PATH" /bin/bash "$CODEX_INSTALLER" -h
assert_not_grep 'api.github.com/repos/openai/codex/releases/latest' \
    "$CODEX_INSTALLER" \
    "Codex update resolution does not consume GitHub's shared unauthenticated quota"
assert_grep_fixed 'CODEX_LATEST_URL="https://github.com/openai/codex/releases/latest"' \
    "$CODEX_INSTALLER" \
    "Codex update uses GitHub's official latest-release redirect"
assert_grep_fixed "--proto-redir '=https'" "$CODEX_INSTALLER" \
    "Codex latest-release redirects remain HTTPS-only"
assert_grep_fixed "prefix=https://github.com/openai/codex/releases/tag/rust-v" \
    "$CODEX_INSTALLER" \
    "Codex resolver binds the final redirect to the official repository and tag family"
CODEX_RELEASE_RESOLVER="$TMPDIR/codex-release-resolver.sh"
sed -n '/^resolve_latest_codex_version()/,/^}$/p' "$CODEX_INSTALLER" \
    > "$CODEX_RELEASE_RESOLVER"
assert_cmd_success "Codex latest-release redirect resolver parses" \
    bash -n "$CODEX_RELEASE_RESOLVER"
assert_cmd_success "Codex resolver accepts one exact stable official tag" \
    env FAKE_EFFECTIVE=https://github.com/openai/codex/releases/tag/rust-v0.145.0 \
        bash -c '
            . "$1"
            CODEX_LATEST_URL=https://github.com/openai/codex/releases/latest
            curl() { printf "%s" "$FAKE_EFFECTIVE"; }
            [ "$(resolve_latest_codex_version)" = 0.145.0 ]
        ' _ "$CODEX_RELEASE_RESOLVER"
for rejected_codex_release in \
    https://github.com/attacker/codex/releases/tag/rust-v0.145.0 \
    https://github.com/openai/codex/releases/tag/rust-v0.145.0-alpha.1 \
    https://github.com/openai/codex/releases/tag/rust-v0.145.0?redirected=1 \
    https://github.com/openai/codex/releases/tag/v0.145.0; do
    assert_cmd_failure "Codex resolver rejects non-contract redirect: $rejected_codex_release" \
        env FAKE_EFFECTIVE="$rejected_codex_release" bash -c '
            . "$1"
            CODEX_LATEST_URL=https://github.com/openai/codex/releases/latest
            curl() { printf "%s" "$FAKE_EFFECTIVE"; }
            resolve_latest_codex_version
        ' _ "$CODEX_RELEASE_RESOLVER"
done
assert_grep_fixed "grep -qF 'api.github.com/repos/openai/codex/releases/latest'" \
    "$KS_FILE" "Module 13 rejects the rate-limited Codex API resolver"
assert_grep_fixed "grep -qF 'https://github.com/openai/codex/releases/latest'" \
    "$KS_FILE" "Module 13 requires the quota-free official release redirect"

# --- Shared installer presentation library ----------------------------------
FMT_LIB="$TMPDIR/agent-install-format.sh"
extract_heredoc "$KS_FILE" "FMT_EOF" "$FMT_LIB" || _fail "FMT_EOF extraction"
assert_cmd_success "format library: bash -n clean" bash -n "$FMT_LIB"
assert_grep_fixed 'if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]' "$FMT_LIB" \
    "colour only on an interactive TTY and honours NO_COLOR"
for fn in fmt_banner fmt_step fmt_section fmt_kv fmt_kv_warn fmt_ok fmt_info \
        fmt_warn fmt_err fmt_note fmt_done fmt_tty_banner; do
    assert_grep_fixed "$fn()" "$FMT_LIB" "format library defines $fn"
done
for title in \
    'NoID Privacy — AIDE Popup' \
    'NoID Privacy — AIDE' \
    'NoID Privacy — AIDE Baseline'; do
    assert_grep_fixed "NOID_FMT_AUTO_TITLE=\"$title\"" "$KS_FILE" \
        "M13 user CLI joins the shared terminal design: $title"
done
# Both AI installers source the shared library with a safe fallback.
for inst in "$CLAUDE_INSTALLER" "$CODEX_INSTALLER"; do
    assert_grep_fixed '. "$FMT_LIB"' "$inst" \
        "$(basename "$inst") sources the shared presentation library"
    assert_grep_fixed 'fmt_banner(){ echo' "$inst" \
        "$(basename "$inst") has a plain fallback when the library is absent"
done
assert_not_grep 'echo "\[CLI 1/3\]' "$CLAUDE_INSTALLER" \
    "Claude installer no longer prints bare bracketed step lines"
assert_not_grep 'echo "\[CLI 1/3\]' "$CODEX_INSTALLER" \
    "Codex installer no longer prints bare bracketed step lines"

# --- Opt-in VPN installers (Proton + Mullvad) -------------------------------
# Both wired from the setup app's VPN group; each verifies the vendor signing
# key fingerprint BEFORE import and installs only from the official repo.
PROTON_INSTALLER="$TMPDIR/noid-protonvpn-install"
extract_heredoc "$KS_FILE" "PROTONVPN_INSTALL_EOF" "$PROTON_INSTALLER" || \
    _fail "PROTONVPN_INSTALL_EOF extraction"
assert_cmd_success "Proton installer: bash -n clean" bash -n "$PROTON_INSTALLER"
assert_cmd_success "Proton installer --help is side-effect-free" \
    env PATH=/nonexistent /bin/bash "$PROTON_INSTALLER" --help
assert_grep_fixed 'FPR_EXPECTED="6929133BDE1CE1CFA9EDB286D84176F6844830D4"' \
    "$PROTON_INSTALLER" "Proton installer pins the published signing fingerprint"
assert_grep_fixed "--proto '=https' --proto-redir '=https' --tlsv1.2" \
    "$PROTON_INSTALLER" "Proton key fetch keeps redirects on HTTPS"
assert_grep_fixed '--max-redirs 3' "$PROTON_INSTALLER" \
    "Proton key fetch bounds redirect traversal"
assert_grep_fixed '[ "${#PRIMARY_FPRS[@]}" -eq 1 ]' "$PROTON_INSTALLER" \
    "Proton installer requires exactly one primary key before import"
assert_grep_fixed '[ "${PRIMARY_FPRS[0]}" = "$FPR_EXPECTED" ]' "$PROTON_INSTALLER" \
    "Proton installer aborts on a primary fingerprint mismatch before import"
assert_grep_fixed 'rpmkeys --list "$FPR_EXPECTED"' "$PROTON_INSTALLER" \
    "Proton installer queries the RPM keyring by full pinned fingerprint"
assert_not_grep 'grep -qi proton' "$PROTON_INSTALLER" \
    "Proton installer never substitutes a mutable key description for identity"
assert_grep_fixed 'rpmkeys --import "$KEY_LOCAL"' "$PROTON_INSTALLER" \
    "Proton installer imports only the verified local key"
assert_grep_fixed 'cmp -s -- "$TMPKEY" "$KEY_LOCAL"' "$PROTON_INSTALLER" \
    "Proton installer verifies the deployed key bytes"
assert_grep_fixed 'matchpathcon -V "$KEY_LOCAL"' "$PROTON_INSTALLER" \
    "Proton installer verifies the deployed key label"
assert_grep_fixed 'gpgkey = file://$KEY_LOCAL' "$PROTON_INSTALLER" \
    "Proton repository uses only the verified local key bytes"
assert_grep_fixed 'baseurl = https://repo.protonvpn.com/fedora-\$releasever-stable' \
    "$PROTON_INSTALLER" \
    "Proton installer uses the canonical vendor baseurl"
assert_grep_fixed 'proton-vpn-gnome-desktop' "$PROTON_INSTALLER" \
    "Proton installer installs the official GUI package"
assert_grep_fixed \
    'PROTON_CORE_PKGS=(proton-vpn-gnome-desktop proton-vpn-gtk-app proton-vpn-daemon)' \
    "$PROTON_INSTALLER" "Proton recovery requires every essential package"
assert_grep_fixed 'dnf_status=("${PIPESTATUS[@]}")' "$PROTON_INSTALLER" \
    "Proton installer preserves DNF and transcript pipeline results"
assert_grep_fixed 'is_known_proton_posttrans_failure "$DNF_TRANSCRIPT"' \
    "$PROTON_INSTALLER" "Proton recovery is bound to the known posttrans signature"
assert_grep_fixed 'exec 9<"$0"' "$PROTON_INSTALLER" \
    "Proton installer locks the exact invoked source instead of host-installed state"
assert_grep_fixed 'sudo rpm -q -- "$installed_pkg"' "$PROTON_INSTALLER" \
    "Proton recovery verifies installed package state through the root RPM view"
assert_grep_fixed 'sudo systemctl restart "$DAEMON_UNIT"' "$PROTON_INSTALLER" \
    "Proton recovery retries only its installed daemon"
assert_grep_fixed 'dnf install failed with an unrecognized error' "$PROTON_INSTALLER" \
    "unknown DNF failures remain fatal"
assert_not_grep 'sudo dnf -y --refresh install "$PKG" || fail' "$PROTON_INSTALLER" \
    "Proton installer no longer mistakes every posttrans result for no installation"
assert_not_grep 'curl .*| *bash' "$PROTON_INSTALLER" \
    "Proton installer never pipes a remote script to a shell"

# Exercise the narrow, locale-tolerant transaction signature independently.
PROTON_CLASSIFIER="$TMPDIR/proton-posttrans-classifier.sh"
sed -n '/^is_known_proton_posttrans_failure() {$/,/^}$/p' \
    "$PROTON_INSTALLER" > "$PROTON_CLASSIFIER"
assert_cmd_success "Proton posttrans classifier: bash -n clean" \
    bash -n "$PROTON_CLASSIFIER"
# shellcheck disable=SC1090
. "$PROTON_CLASSIFIER"
printf '%s\n' \
    'WARNING: %posttrans(proton-vpn-daemon-0.13.7-1.fc44.noarch) Scriptlet failed, exit status 1' \
    > "$TMPDIR/proton-posttrans-en.log"
printf '%s\n' \
    'WARNUNG: %posttrans(proton-vpn-daemon-0.13.7-1.fc44.noarch) Scriptlet fehlgeschlagen, Beenden-Status 1' \
    > "$TMPDIR/proton-posttrans-de.log"
printf '%s\n' \
    'ERROR: package proton-vpn-gnome-desktop could not be downloaded' \
    > "$TMPDIR/proton-dnf-unrelated.log"
printf '%s\n' \
    'WARNING: %posttrans(unrelated-daemon-1.0-1.fc44) Scriptlet failed, exit status 1' \
    > "$TMPDIR/other-posttrans.log"
assert_cmd_success "English Proton daemon posttrans failure is recognized" \
    is_known_proton_posttrans_failure "$TMPDIR/proton-posttrans-en.log"
assert_cmd_success "German Proton daemon posttrans failure is recognized" \
    is_known_proton_posttrans_failure "$TMPDIR/proton-posttrans-de.log"
assert_cmd_failure "unrelated Proton DNF error is not recoverable" \
    is_known_proton_posttrans_failure "$TMPDIR/proton-dnf-unrelated.log"
assert_cmd_failure "another package's posttrans error is not recoverable" \
    is_known_proton_posttrans_failure "$TMPDIR/other-posttrans.log"

# Run the complete install branch with command fakes. The fixture consumes the
# repo heredoc and prompt but cannot touch RPM, systemd, /etc or the network.
PROTON_STUB_ROOT="$(mktemp -d /var/tmp/noid-proton-fixture.XXXXXX)"
PROTON_STUB_DIR="$PROTON_STUB_ROOT/bin"
PROTON_SERVICE_STATE="$PROTON_STUB_ROOT/proton-service-active"
PROTON_KEY_STATE="$PROTON_STUB_ROOT/proton-key-imported"
mkdir -p "$PROTON_STUB_DIR"
cat > "$PROTON_STUB_DIR/rpm" <<'PROTON_STUB_RPM_EOF'
#!/bin/bash
if [ "${1:-}" = "-E" ]; then
    echo 44
elif [ "${1:-}" = "-q" ] && [ "${2:-}" = "gpg-pubkey" ]; then
    echo "trusted Proton signing key"
elif [ "${1:-}" = "-q" ]; then
    for arg in "$@"; do
        [ "$arg" != "${STUB_RPM_MISSING:-}" ] || exit 1
    done
else
    exit 0
fi
PROTON_STUB_RPM_EOF
cat > "$PROTON_STUB_DIR/gpg" <<'PROTON_STUB_GPG_EOF'
#!/bin/bash
echo 'pub:-:255:1:0000000000000000:0:0::::::'
echo 'fpr:::::::::6929133BDE1CE1CFA9EDB286D84176F6844830D4:'
PROTON_STUB_GPG_EOF
cat > "$PROTON_STUB_DIR/rpmkeys" <<'PROTON_STUB_RPMKEYS_EOF'
#!/bin/bash
case "${1:-}" in
    --list)
        [ -e "$PROTON_KEY_STATE" ] || exit 1
        echo '6929133bde1ce1cfa9edb286d84176f6844830d4 Proton Technologies AG (Fedora 44) <opensource@proton.me> public key'
        ;;
    --import)
        /usr/bin/touch "$PROTON_KEY_STATE"
        ;;
    *)
        exit 99
        ;;
esac
PROTON_STUB_RPMKEYS_EOF
cat > "$PROTON_STUB_DIR/curl" <<'PROTON_STUB_CURL_EOF'
#!/bin/bash
output=
while [ "$#" -gt 0 ]; do
    if [ "$1" = "-o" ]; then output=$2; shift 2; else shift; fi
done
[ -n "$output" ] || exit 2
: > "$output"
PROTON_STUB_CURL_EOF
cat > "$PROTON_STUB_DIR/sudo" <<'PROTON_STUB_SUDO_EOF'
#!/bin/bash
command_name=${1:-}
[ "$#" -eq 0 ] || shift
case "$command_name" in
    tee)
        /usr/bin/tee /dev/null
        ;;
    chmod|chown|restorecon|matchpathcon|cmp)
        exit 0
        ;;
    stat)
        echo '0:0:644:1'
        ;;
    install)
        exit 0
        ;;
    rpmkeys)
        exec "$PROTON_STUB_DIR/rpmkeys" "$@"
        ;;
    dnf)
        case "${STUB_DNF_MODE:-clean}" in
            clean) exit 0 ;;
            known)
                echo 'WARNING: %posttrans(proton-vpn-daemon-0.13.7-1.fc44.noarch) Scriptlet failed, exit status 1'
                exit 1
                ;;
            unknown)
                echo 'ERROR: repository metadata download failed'
                exit 1
                ;;
            *) exit 98 ;;
        esac
        ;;
    rpm)
        exec "$PROTON_STUB_DIR/rpm" "$@"
        ;;
    systemctl)
        action=${1:-}
        case "$action" in
            is-active)
                [ -e "$PROTON_SERVICE_STATE" ]
                ;;
            restart)
                [ "${STUB_SERVICE_FAIL:-0}" -eq 0 ] || exit 1
                /usr/bin/touch "$PROTON_SERVICE_STATE"
                ;;
            *) exit 97 ;;
        esac
        ;;
    *) exit 96 ;;
esac
PROTON_STUB_SUDO_EOF
for inert_command in dnf systemctl; do
    cat > "$PROTON_STUB_DIR/$inert_command" <<'PROTON_STUB_INERT_EOF'
#!/bin/bash
exit 95
PROTON_STUB_INERT_EOF
done
chmod 0755 "$PROTON_STUB_DIR"/*
assert_eq "$PROTON_STUB_DIR/sudo" \
    "$(PATH="$PROTON_STUB_DIR:/usr/bin:/bin" command -v sudo)" \
    "Proton fixture resolves its isolated sudo fake first"
assert_file_executable "$PROTON_STUB_DIR/dnf" \
    "Proton fixture direct DNF tripwire is executable"
assert_eq "$PROTON_STUB_DIR/dnf" \
    "$(PATH="$PROTON_STUB_DIR:/usr/bin:/bin" command -v dnf)" \
    "Proton fixture resolves its isolated DNF tripwire first"
assert_cmd_failure "Proton fixture direct DNF fake is a fail-closed tripwire" \
    "$PROTON_STUB_DIR/dnf"

run_proton_fixture() {
    local mode=$1 missing_pkg=${2:-} service_fail=${3:-0} output=$4
    rm -f "$PROTON_SERVICE_STATE"
    rm -f "$PROTON_KEY_STATE"
    printf 'y\n' |
        env PATH="$PROTON_STUB_DIR:/usr/bin:/bin" \
            PROTON_STUB_DIR="$PROTON_STUB_DIR" \
            PROTON_SERVICE_STATE="$PROTON_SERVICE_STATE" \
            PROTON_KEY_STATE="$PROTON_KEY_STATE" \
            STUB_DNF_MODE="$mode" \
            STUB_RPM_MISSING="$missing_pkg" \
            STUB_SERVICE_FAIL="$service_fail" \
            bash "$PROTON_INSTALLER" > "$output" 2>&1
}

assert_cmd_success "known Proton posttrans failure recovers end-to-end" \
    run_proton_fixture known "" 0 "$TMPDIR/proton-known.out"
assert_grep_fixed \
    'packages verified and Proton daemon recovered after the known %posttrans failure' \
    "$TMPDIR/proton-known.out" "known recovery reports verified success"
assert_file_exists "$PROTON_SERVICE_STATE" \
    "known recovery starts the exact Proton daemon"
assert_file_exists "$PROTON_KEY_STATE" \
    "missing exact Proton key is imported before repository use"

assert_cmd_failure "unknown DNF failure remains fatal end-to-end" \
    run_proton_fixture unknown "" 0 "$TMPDIR/proton-unknown.out"
assert_grep_fixed 'dnf install failed with an unrecognized error' \
    "$TMPDIR/proton-unknown.out" "unknown DNF failure is reported honestly"
if [ -e "$PROTON_SERVICE_STATE" ]; then
    _fail "unknown DNF failure does not attempt service recovery"
else
    _pass "unknown DNF failure does not attempt service recovery"
fi

assert_cmd_failure "known posttrans cannot hide a missing essential package" \
    run_proton_fixture known proton-vpn-daemon 0 "$TMPDIR/proton-missing.out"
assert_grep_fixed 'proton-vpn-daemon is not installed' \
    "$TMPDIR/proton-missing.out" "missing package fails the recovered transaction"

assert_cmd_failure "known posttrans cannot hide a daemon restart failure" \
    run_proton_fixture known "" 1 "$TMPDIR/proton-service-fail.out"
assert_grep_fixed 'could not be started' "$TMPDIR/proton-service-fail.out" \
    "daemon restart failure remains fatal"

MULLVAD_INSTALLER="$TMPDIR/noid-mullvad-install"
extract_heredoc "$KS_FILE" "MULLVAD_INSTALL_EOF" "$MULLVAD_INSTALLER" || \
    _fail "MULLVAD_INSTALL_EOF extraction"
assert_cmd_success "Mullvad installer: bash -n clean" bash -n "$MULLVAD_INSTALLER"
assert_cmd_success "Mullvad installer --help is side-effect-free" \
    env PATH=/nonexistent /bin/bash "$MULLVAD_INSTALLER" --help
assert_grep_fixed 'FPR_EXPECTED="A1198702FC3E0A09A9AE5B75D5A1D4F266DE8DDF"' \
    "$MULLVAD_INSTALLER" "Mullvad installer pins the published code-signing fingerprint"
assert_grep_fixed "--proto '=https' --proto-redir '=https' --tlsv1.2" \
    "$MULLVAD_INSTALLER" "Mullvad key fetch keeps redirects on HTTPS"
assert_grep_fixed '--max-redirs 3' "$MULLVAD_INSTALLER" \
    "Mullvad key fetch bounds redirect traversal"
assert_grep_fixed '[ "${#PRIMARY_FPRS[@]}" -eq 1 ]' "$MULLVAD_INSTALLER" \
    "Mullvad installer requires exactly one primary key before import"
assert_grep_fixed '[ "${PRIMARY_FPRS[0]}" = "$FPR_EXPECTED" ]' "$MULLVAD_INSTALLER" \
    "Mullvad installer requires the pinned primary fingerprint before import"
assert_grep_fixed 'gpgkey=file://$KEY_LOCAL' "$MULLVAD_INSTALLER" \
    "Mullvad repository reuses only the verified local keyring"
assert_grep_fixed 'rpmkeys --import "$KEY_LOCAL"' "$MULLVAD_INSTALLER" \
    "Mullvad installer imports only the verified local keyring"
assert_grep_fixed 'cmp -s -- "$TMPKEY" "$KEY_LOCAL"' "$MULLVAD_INSTALLER" \
    "Mullvad installer verifies the deployed keyring bytes"
assert_grep_fixed 'matchpathcon -V "$REPO_FILE"' "$MULLVAD_INSTALLER" \
    "Mullvad installer verifies the repository SELinux label"
assert_grep_fixed 'repository.mullvad.net/rpm/stable' "$MULLVAD_INSTALLER" \
    "Mullvad installer uses the canonical vendor baseurl"
assert_grep_fixed 'mullvad-vpn' "$MULLVAD_INSTALLER" \
    "Mullvad installer installs the official app package"
assert_grep_fixed 'sudo /usr/bin/env LC_ALL=C /usr/bin/rpm' \
    "$MULLVAD_INSTALLER" \
    "Mullvad package-state queries use the privileged RPM database path"
assert_not_grep_fixed 'rpm -q "$PKG"' "$MULLVAD_INSTALLER" \
    "Mullvad never mistakes an unprivileged RPM database error for absence"
assert_not_grep 'curl .*| *bash' "$MULLVAD_INSTALLER" \
    "Mullvad installer never pipes a remote script to a shell"

# --- AIDE wrappers fail closed ----------------------------------------------
assert_cmd_success "AIDE notifier: bash -n clean" bash -n "$AIDE_NOTIFIER"
for local_session_contract in \
    'list-sessions --json=short' \
    '/usr/bin/timeout --signal=TERM --kill-after=1s 3s' \
    '--property=LockedHint' \
    'show-seat "$seat"' \
    '[ "$uid" -le 4294967294 ]' \
    'notified_uids["$uid"]=1' \
    '"_SYSTEMD_INVOCATION_ID=${INVOCATION_ID}"' \
    '/usr/bin/stat -c '\''%F:%u'\'' "$dbus_sock"' \
    '/usr/bin/setpriv' \
    '--reset-env'; do
    assert_grep_fixed "$local_session_contract" "$AIDE_NOTIFIER" \
        "AIDE notifier enforces local-session contract: $local_session_contract"
done
assert_not_grep '/run/systemd/users/' "$AIDE_NOTIFIER" \
    "AIDE notifier does not treat a lingering user manager as an active session"
assert_not_grep 'sudo -u' "$AIDE_NOTIFIER" \
    "AIDE notifier drops privileges without PAM or a password-capable sudo path"
assert_grep_fixed 'install -d -m 0700 -o root -g root /var/log/aide' \
    "$KS_FILE" "M13 creates the AIDE log directory at exact mode 0700"
assert_grep_fixed 'root:root:700 ]; then' "$KS_FILE" \
    "M13 verifies the exact AIDE log-directory metadata"
assert_grep_fixed "stat -c '%U:%G:%a' /var/log/aide" "$KS_FILE" \
    "M13 verifies filesystem-neutral AIDE log-directory metadata"
assert_grep_fixed '[ ! -d /var/log/aide ] || [ -L /var/log/aide ]' "$KS_FILE" \
    "M13 retains exact directory and symlink checks"
assert_not_grep "stat -Lc '%U:%G:%a:%h' /var/log/aide" "$KS_FILE" \
    "M13 does not require a filesystem-specific directory link count"
assert_cmd_success "AIDE check wrapper: bash -n clean" bash -n "$AIDE_CHECK_WRAPPER"
assert_grep_fixed 'NOID_FMT_AUTO_TITLE="NoID Privacy — AIDE Check"' \
    "$AIDE_CHECK_WRAPPER" "interactive AIDE checks use the shared CLI frame"
assert_grep_fixed 'AIDE_INTERACTIVE_FORMAT=0' "$AIDE_CHECK_WRAPPER" \
    "service and redirected AIDE runs keep their machine output unchanged"
assert_grep_fixed 'fmt_step 2 2 "Run check and write timestamped evidence"' \
    "$AIDE_CHECK_WRAPPER" "interactive AIDE progress covers the final scan"
# aide-check.service.d/exitcode.conf declares SuccessExitStatus=1..7 so AIDE's
# difference bitmask is not a unit failure. A wrapper guard that exits inside
# that range would therefore be recorded as a successful check that never ran,
# and aide-notify.sh would render it as "Integrity changes detected". Guards
# and unexpected aborts must both land in the documented >=14 error range.
assert_eq 0 "$(grep -cE 'exit [1-7]( |;|$)' "$AIDE_CHECK_WRAPPER")" \
    "no wrapper guard exits inside AIDE's success-mapped bitmask"
assert_eq 14 "$(grep -c 'exit 14' "$AIDE_CHECK_WRAPPER")" \
    "every wrapper guard uses the documented >=14 error range"
assert_grep_fixed 'trap noid_aide_abort ERR' "$AIDE_CHECK_WRAPPER" \
    "an unexpected set -e abort is remapped out of the bitmask too"
assert_grep_fixed '[ "$rc" -ge 14 ] || rc=14' "$AIDE_CHECK_WRAPPER" \
    "the abort handler raises any sub-14 status into the error range"
assert_grep_fixed 'SuccessExitStatus=1 2 3 4 5 6 7' "$KS_FILE" \
    "the bitmask mapping this namespace avoids is still the shipped one"
# -E keeps the exit-14 remapping below effective inside function bodies too:
# without errtrace an abort there would exit with the failing command's own
# status, usually 1, which SuccessExitStatus turns back into unit SUCCESS.
assert_grep_fixed 'set -Eeuo pipefail' "$AIDE_CHECK_WRAPPER" \
    "AIDE daily wrapper rejects prerequisite failures under errtrace"
assert_not_grep 'mkdir -p /var/log/aide 2>/dev/null || true' "$AIDE_CHECK_WRAPPER" \
    "AIDE daily wrapper does not swallow log-directory failures"
assert_grep_fixed 'COVERAGE_MANIFEST=/usr/lib/noid-privacy/aide-secure-paths.tsv' \
    "$AIDE_CHECK_WRAPPER" "AIDE daily wrapper reads the deployed coverage manifest"
assert_grep_fixed '--path-check="$file_type:$probe_path"' "$AIDE_CHECK_WRAPPER" \
    "AIDE daily wrapper re-resolves every canonical coverage contract"
assert_grep_fixed 'canonical AIDE coverage weak or shadowed' "$AIDE_CHECK_WRAPPER" \
    "weak or shadowed runtime coverage fails the daily unit"
assert_grep_fixed 'coverage manifest contract count is $contracts, expected 73' \
    "$AIDE_CHECK_WRAPPER" "an incomplete coverage manifest fails closed"
assert_grep_fixed 'exec 9<>"$LOCK_FILE"' "$AIDE_CHECK_WRAPPER" \
    "coverage probes and the check share one AIDE mutex"
assert_grep_fixed 'require_selinux_type "$LOCK_FILE" var_lock_t' \
    "$AIDE_CHECK_WRAPPER" "daily checks bind the shared mutex to var_lock_t"
assert_grep_fixed 'matchpathcon -V "$labeled_path"' "$AIDE_CHECK_WRAPPER" \
    "daily checks reject drifted labels on trusted AIDE inputs"
assert_eq 2 "$(grep -c '/usr/sbin/aide --workers=1' "$AIDE_CHECK_WRAPPER")" \
    "both daily coverage and full-check calls pin one AIDE worker"
assert_grep_fixed 'ExecStart=/usr/sbin/aide --workers=1 --check' \
    "$AIDE_SERVICE" "fallback daily service path also pins one AIDE worker"
assert_grep_fixed 'AIDE num_workers=1 is the single active config assignment' \
    "$KS_FILE" "compose verification rejects worker-count drift"
assert_cmd_success "AIDE baseline review: bash -n clean" bash -n "$AIDE_REVIEW"
assert_grep_fixed 'The active database will not be changed.' "$AIDE_REVIEW" \
    "candidate preparation cannot claim trust acceptance"
assert_grep_fixed 'require_stable_boot_state' "$AIDE_REVIEW" \
    "AIDE trust workflow checks the M21 lifecycle boundary"
assert_grep_fixed 'basis_record=$(/usr/libexec/noid-boot-mutation-guard)' "$AIDE_REVIEW" \
    "AIDE reuses the canonical M21 stable-basis predicate"
assert_grep_fixed 'basis=hostonly|basis=generic' "$AIDE_REVIEW" \
    "AIDE accepts only confirmed host-only or fully restored Generic"
assert_not_grep 'phase=//p' "$AIDE_REVIEW" \
    "AIDE has no divergent phase-only lifecycle parser"
assert_grep_fixed 'candidate_sha256=' "$AIDE_REVIEW" \
    "candidate identity is recorded"
assert_grep_fixed 'verify_bound_candidate' "$AIDE_REVIEW" \
    "commit binds the supplied hash and complete review inputs"
assert_grep_fixed 'verify_discard_identity' "$AIDE_REVIEW" \
    "partial or stale candidates retain an exact safe discard path"
for review_binding in source_active_sha256 aide_config_sha256 \
        coverage_manifest_sha256 boot_basis kernel_release report_sha256; do
    assert_grep_fixed "$review_binding=" "$AIDE_REVIEW" \
        "candidate records review binding: $review_binding"
done
assert_grep_fixed 'ACCEPT AIDE BASELINE $hash' "$AIDE_REVIEW" \
    "commit requires exact interactive acceptance"
assert_grep_fixed '[ -r /dev/tty ] && [ -w /dev/tty ]' "$AIDE_REVIEW" \
    "trust commit requires an interactive TTY"
assert_grep_fixed 'mv -fT -- "$CANDIDATE" "$ACTIVE"' "$AIDE_REVIEW" \
    "reviewed commit is an atomic same-filesystem rename"
assert_grep_fixed 'rollback_commit' "$AIDE_REVIEW" \
    "failed baseline activation restores the prior database and candidate"
assert_grep_fixed 'accepted_pending="${accepted_record}.pending"' "$AIDE_REVIEW" \
    "acceptance evidence is staged before it receives its committed name"
assert_not_grep 'systemctl enable --now aide-check.timer' "$AIDE_REVIEW" \
    "baseline acceptance does not silently enable scheduling"
assert_not_grep 'cat > /etc/systemd/system/noid-aide-firstboot-rebaseline' "$KS_FILE" \
    "no first-boot baseline service or timer is installed"
assert_grep_fixed 'ConditionKernelCommandLine=!rd.live.image' "$AIDE_SERVICE" \
    "daily AIDE scan is disabled on transient live media"
assert_grep_fixed 'ConditionPathExists=/var/lib/aide/aide.db.gz' \
    "$AIDE_SERVICE" \
    "daily scan cannot run without an active reviewed baseline"
assert_not_grep 'ExecStartPre=/bin/sleep 600' "$AIDE_BOOT_PRIORITY" \
    "normal scheduled AIDE checks have no ten-minute boot delay"
assert_grep_fixed 'MemoryMax=4G' "$AIDE_BOOT_PRIORITY" \
    "daily AIDE scan has a hard memory ceiling"
assert_not_grep '^Wants=aide-check.service$' "$AIDE_TIMER" \
    "enabling the timer does not start the scan service at every boot"
assert_grep_fixed 'systemctl daemon-reload' "$KS_FILE" \
    "AIDE unit deployment reloads systemd"
assert_grep_fixed 'ESP = p+u+g+s+sha256+sha512' "$KS_FILE" \
    "AIDE defines VFAT-safe ESP content attributes"
assert_grep_fixed '/boot/efi ESP' "$KS_FILE" \
    "AIDE tracks the EFI System Partition"
assert_not_grep '^!/boot/efi' "$KS_FILE" \
    "AIDE does not exclude the EFI System Partition"
assert_not_grep '^=/boot/efi E' "$KS_FILE" \
    "AIDE does not replace ESP tracking with an empty-attribute rule"
assert_not_grep 'systemctl disable --now "$TIMER" 2>/dev/null || true' "$KS_FILE" \
    "AIDE toggle does not hide timer-disable failure"
assert_grep_fixed 'systemctl is-active --quiet "$TIMER"' "$KS_FILE" \
    "AIDE toggle verifies that the timer stopped"
assert_grep_fixed 'Run the user-owned review workflow first' "$KS_FILE" \
    "AIDE toggle refuses to enable without a baseline"
assert_grep_fixed 'The image does not' "$AIDE_NOTIFY_DOC" \
    "AIDE documentation introduces the inactive-by-default boundary"
assert_grep_fixed 'create a baseline or enable the timer automatically' \
    "$AIDE_NOTIFY_DOC" "AIDE documentation states both explicit user decisions"
assert_grep_fixed 'This helper does not change the timer.' "$AIDE_POPUP_TOGGLE" \
    "popup-only helper does not imply an active timer"
assert_grep_fixed 'flock -n 9' "$AIDE_POPUP_TOGGLE" \
    "popup transactions are serialized"
assert_grep_fixed 'matchpathcon -V "$DROPIN_DIR"' "$AIDE_POPUP_TOGGLE" \
    "popup deployment rejects a drifted parent-directory label"
assert_grep_fixed 'timeout --signal=TERM --kill-after=2s 30s gzip -t' \
    "$AIDE_POPUP_TOGGLE" "popup enablement requires a bounded readable baseline"
assert_not_grep 'still runs daily' "$AIDE_POPUP_TOGGLE" \
    "popup-only helper has no unconditional daily-scan claim"
assert_not_grep 'sudo cp /usr/share/doc/noid-privacy/aide-notify-dropin.conf' \
    "$AIDE_NOTIFY_DOC" "notification docs use the transactional popup helper"
assert_grep_fixed 'Enable the timer without popups: sudo systemctl enable --now aide-check.timer' \
    "$AIDE_COMBINED_TOGGLE" "combined toggle gives an accurate silent-check path"
assert_not_grep 'Re-enable silent daily checks after baseline review: sudo noid-toggle-aide on' \
    "$AIDE_COMBINED_TOGGLE" "combined toggle does not call timer-plus-popup silent"
assert_grep_fixed 'UNINITIALIZED (review and accept a baseline before enabling checks)' \
    "$AIDE_COMBINED_TOGGLE" "status distinguishes fresh state from user opt-out"
assert_grep_fixed 'Unsafe or drifted popup state; refusing combined mutation.' \
    "$AIDE_COMBINED_TOGGLE" "combined toggle never snapshots drift as disabled"
assert_grep_fixed 'original AIDE timer/popup state could not be restored completely' \
    "$AIDE_COMBINED_TOGGLE" "combined rollback failures remain visible"
assert_grep_fixed 'command=(sudo -n /usr/libexec/noid-aide-status)' \
    "$AIDE_COMBINED_TOGGLE" \
    "unprivileged combined status uses the fixed passwordless state boundary"
assert_not_grep 'rmdir "$DROPIN_DIR"' "$AIDE_POPUP_TOGGLE" \
    "popup disable has no impossible drop-in-directory cleanup"
assert_grep_fixed \
    '[[ "${META_VALUES[source_active_sha256]}" =~ ^[a-f0-9]{64}$ ]]' \
    "$AIDE_REVIEW" "update candidates require an exact active-database digest"
assert_not_grep 'update:[a-f0-9]*' "$AIDE_REVIEW" \
    "candidate binding cannot accept update:absent through a shell glob"
assert_not_grep 'dconf-lock on /org/gnome/system/location/enabled' "$KS_FILE" \
    "M13 comments match the deliberately unlocked M17 location key"
for current_aide_doc in \
    "$PROJECT_ROOT/README.md" \
    "$PROJECT_ROOT/docs/comparison.md" \
    "$PROJECT_ROOT/docs/threat-model.md"; do
    assert_file_exists "$current_aide_doc"
    assert_not_grep_extended 'daily AIDE detection|pre-snapshots and daily AIDE checks|AIDE daily scans detect tampering' \
        "$current_aide_doc" \
        "$(basename "$current_aide_doc") has no unconditional daily-AIDE claim"
done
assert_not_grep 'systemctl enable noid-aide-firstboot-rebaseline.timer' "$KS_FILE" \
    "no automatic AIDE trust timer is enabled"

# --- Gaming Mode opt-in — own group, NOT inside Hardware Privacy ------------
# Steam/Proton relaxation toggle wired to M08 noid-toggle-gaming. Own
# PreferencesGroup (after Media & Graphics) so a hardening RELAXATION is never mistaken
# for a privacy-protection toggle. Confirm dialogs via Adw.AlertDialog.
for gaming_marker in \
    "'Gaming Mode (Steam / Proton)'" \
    'def on_gaming_toggle' \
    'def _gaming_enable_confirm' \
    'def _gaming_disable_confirm' \
    'def _gaming_enabled' \
    'def _gaming_steam_installed' \
    'def _gaming_ia32_live' \
    'def _sync_gaming_completion_row' \
    'def _start_gaming_enable_terminal' \
    'GAMING_FLAG' \
    'GAMING_COMPLETION_ROWS' \
    'Adw.AlertDialog.new' \
    '/usr/local/sbin/noid-toggle-gaming'; do
    assert_grep_fixed "$gaming_marker" "$SCRIPT" "gaming-mode: $gaming_marker"
done
assert_grep_fixed 'GLib.timeout_add(500, _poll_gaming_enable_result' "$SCRIPT" \
    "Gaming Mode enable observes completion without a short timeout"
assert_grep_fixed 'if spawn_terminal(shell_cmd):' "$SCRIPT" \
    "Gaming Mode distinguishes terminal launch success"
assert_grep_fixed '_set_gaming_switch_truth(switch, _gaming_enabled())' "$SCRIPT" \
    "Gaming Mode resynchronizes to the committed flag"
assert_not_grep 'switch reflects final truth on the next dialog' "$SCRIPT" \
    "Gaming Mode UI does not postpone truth until reopen"
assert_grep_fixed 'attempts[0] < 7200' "$SCRIPT" \
    "Gaming Mode completion polling has a one-hour attempt cap"
assert_grep_fixed 'Gaming Mode timed out; showing the committed system state.' \
    "$SCRIPT" "Gaming Mode timeout restores a truthful usable switch"
assert_grep_fixed 'switch, result_path, completion_row, [0])' "$SCRIPT" \
    "Gaming Mode completion polling carries row and bounded state"
assert_grep_fixed "'Complete Steam installation'" "$SCRIPT" \
    "Gaming Mode exposes the explicit post-reboot package stage"
assert_grep_fixed "'Restart first so 32-bit package scriptlets can execute'" \
    "$SCRIPT" \
    "Gaming Mode blocks the package row until live IA32 is proven"
assert_grep_fixed "'32-bit execution is active · opens the reviewed DNF transaction'" \
    "$SCRIPT" \
    "Gaming Mode enables the completion row only for the live-ready state"
assert_grep_fixed '_sync_gaming_completion_row(completion_row)' "$SCRIPT" \
    "Gaming Mode refreshes the completion row after the visible helper exits"
assert_grep_fixed '_poll_gaming_disable_result' "$SCRIPT" \
    "Gaming Mode disabling also refreshes the separate package-stage row"
assert_not_grep 'def _gaming_result_state' "$SCRIPT" \
    "Gaming Mode has no unreachable pending-state helper"

# --- wizard removal verification -------------------------------------
# noid-setup-wizard binary path must NOT be exec'd / referenced as a path
# anywhere in the welcome script. Historical context comments mentioning
# "deprecated noid-setup-wizard" by name (explaining WHY logic was merged
# here) are intentionally kept as code-archaeology breadcrumbs.
assert_not_grep "/usr/local/bin/noid-setup-wizard" "$SCRIPT" \
    "no exec path /usr/local/bin/noid-setup-wizard (wizard-merge complete)"
assert_not_grep "act_wizard" "$SCRIPT" \
    "act_wizard NOT defined (wizard-merge complete)"

# --- Privilege routing for system toggles (AIDE / audit-notify) ------------
# See tests/05: a bare policy-permission answer selected sudo for backends
# that have no sudoers rule, and `sudo -n` then failed with "a password is
# required" instead of using the provisioned polkit route.
assert_grep_fixed "'-n', '-l', '-l', '--'" "$SCRIPT" \
    "Setup asks for the matching sudoers entry, not just permission"
assert_grep_fixed "'!authenticate' in listing" "$SCRIPT" \
    "Setup requires an explicit passwordless tag before choosing sudo"
assert_grep_fixed "listing.count('Matched:') == 1" "$SCRIPT" \
    "Setup accepts exactly one matching sudoers record"
assert_grep_fixed "LC_ALL='C.UTF-8'" "$SCRIPT" \
    "Setup reads the translated sudo listing under a pinned locale"
assert_grep_fixed "return ['/usr/bin/pkexec'] + argv" "$SCRIPT" \
    "installed system toggles retain exact-program polkit fallback"
assert_grep_fixed "return ['/usr/bin/sudo', '-n', '--'] + argv" "$SCRIPT" \
    "authorized Setup route uses noninteractive sudo"
assert_grep_fixed "pwd.getpwuid(os.getuid()).pw_name == 'liveuser'" "$SCRIPT" \
    "passwordless route is restricted to the exact Live account"
assert_grep_fixed "Path('/run/initramfs/livedev').exists()" "$SCRIPT" \
    "passwordless route requires the initramfs Live-media marker"
assert_not_grep "def _toggle_unit" "$SCRIPT" \
    "Setup carries no unused generic privileged systemctl route"
assert_grep_fixed "'aide-check.timer'"                    "$SCRIPT" "aide-check.timer enable target"
assert_grep_fixed "'audit-notify.service'"                "$SCRIPT" "audit-notify.service enable target"

assert_cmd_success "Welcome privilege selection is closed over Live, sudo, and polkit paths" \
    python3 - "$SCRIPT" <<'PY'
import ast
import sys

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
wanted = {'_noninteractive_sudo_authorizes', '_privileged_argv'}
functions = [node for node in tree.body
             if isinstance(node, ast.FunctionDef) and node.name in wanted]
assert {node.name for node in functions} == wanted
module = ast.Module(body=functions, type_ignores=[])
ast.fix_missing_locations(module)

class FakeSubprocess:
    DEVNULL = object()
    PIPE = object()

    class TimeoutExpired(Exception):
        pass

    returncode = 1
    stdout = ''
    calls = []

    @classmethod
    def run(cls, argv, **kwargs):
        cls.calls.append((argv, kwargs))
        return type('Result', (), {'returncode': cls.returncode,
                                   'stdout': cls.stdout})()

namespace = {
    '_is_passwordless_live_session': lambda: False,
    '_warn': lambda *_args: None,
    'subprocess': FakeSubprocess,
    'os': type('FakeOS', (), {'environ': {}})(),
}
exec(compile(module, '<noid-welcome-privilege>', 'exec'), namespace)
backend = ['/usr/local/sbin/noid-toggle-aide', 'popup-on']
assert namespace['_privileged_argv'](backend) == ['/usr/bin/pkexec'] + backend
assert FakeSubprocess.calls[-1][0] == \
       ['/usr/bin/sudo', '-n', '-l', '-l', '--'] + backend
assert FakeSubprocess.calls[-1][1]['timeout'] == 3
assert FakeSubprocess.calls[-1][1]['check'] is False
assert FakeSubprocess.calls[-1][1]['env']['LC_ALL'] == 'C.UTF-8'

# A PASSWD-tagged %wheel match is "permitted by policy" but not passwordless;
# selecting sudo there made every toggle fail with "a password is required".
FakeSubprocess.returncode = 0
FakeSubprocess.stdout = (
    'Sudoers entry: /etc/sudoers.d/10-wheel\n'
    '    Options: setenv\n'
    '    Matched: /usr/local/sbin/noid-toggle-aide popup-on\n')
assert namespace['_privileged_argv'](backend) == ['/usr/bin/pkexec'] + backend

FakeSubprocess.stdout = (
    'Sudoers entry: /etc/sudoers.d/90-owner\n'
    '    Options: !authenticate\n'
    '    Matched: /usr/local/sbin/noid-toggle-aide popup-on\n')
assert namespace['_privileged_argv'](backend) == \
       ['/usr/bin/sudo', '-n', '--'] + backend

FakeSubprocess.stdout = (
    'Sudoers entry: /etc/sudoers.d/90-owner\n'
    '    Options: !authenticate\n'
    '    Matched: /usr/local/sbin/noid-toggle-aide popup-on\n'
    'Sudoers entry: /etc/sudoers.d/99-override\n'
    '    Options: authenticate\n'
    '    Matched: /usr/local/sbin/noid-toggle-aide popup-on\n')
assert namespace['_privileged_argv'](backend) == ['/usr/bin/pkexec'] + backend

call_count = len(FakeSubprocess.calls)
namespace['_is_passwordless_live_session'] = lambda: True
assert namespace['_privileged_argv'](backend) == \
       ['/usr/bin/sudo', '-n', '--'] + backend
assert len(FakeSubprocess.calls) == call_count
assert backend == ['/usr/local/sbin/noid-toggle-aide', 'popup-on']
PY

assert_cmd_success "Welcome passwordless route requires exact Live identity and marker" \
    python3 - "$SCRIPT" <<'PY'
import ast
import sys
from types import SimpleNamespace

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
fn = next(node for node in tree.body
          if isinstance(node, ast.FunctionDef)
          and node.name == '_is_passwordless_live_session')
module = ast.Module(body=[fn], type_ignores=[])
ast.fix_missing_locations(module)
state = {'live': True, 'user': 'liveuser', 'marker': True}
class FakePwd:
    @staticmethod
    def getpwuid(_uid):
        return SimpleNamespace(pw_name=state['user'])
class FakePath:
    def __init__(self, _path): pass
    def exists(self): return state['marker']
namespace = {
    'is_live_mode': lambda: state['live'],
    'pwd': FakePwd,
    'os': SimpleNamespace(getuid=lambda: 1000),
    'Path': FakePath,
    '_warn': lambda *_args: None,
}
exec(compile(module, '<noid-welcome-live-detect>', 'exec'), namespace)
detect = namespace['_is_passwordless_live_session']
assert detect() is True
state['user'] = 'alice'
assert detect() is False
state['user'] = 'liveuser'
state['live'] = False
assert detect() is False
state['live'] = True
state['marker'] = False
assert detect() is False
PY

# --- Installed autostart ordering -------------------------------------------
assert_grep_fixed "'gnome-initial-setup-done'" "$SCRIPT" \
    "installed autostart waits for GNOME initial setup"
assert_not_grep 'def wait_for_fedora_welcome_closure' "$SCRIPT" \
    "Setup has no unreachable live Fedora Welcome polling helper"
assert_not_grep 'def anaconda_install_running' "$SCRIPT" \
    "Setup has no unreachable live Anaconda process probe"

# --- GNOME dock icon name ------------------------------
assert_grep_fixed "super().__init__(APP_ID, 'noid-privacy-setup')" \
    "$SCRIPT" "Setup icon name set for dock + alt-tab"

# --- Process helpers --------------------------------------------------------
assert_grep_fixed 'def spawn_terminal'                    "$SCRIPT" "terminal-spawn helper function"
assert_grep_fixed "'ptyxis'"                              "$SCRIPT" "ptyxis primary (F44 GNOME 50 default)"
assert_grep_fixed "'gnome-terminal'"                      "$SCRIPT" "gnome-terminal legacy fallback"
assert_grep_fixed 'def spawn_app'                         "$SCRIPT" "spawn_app non-blocking helper"
assert_grep_fixed 'def open_doc'                          "$SCRIPT" "open_doc xdg-open helper"

# --- Doc references ---------------------------------------------------------
assert_grep_fixed '/usr/share/doc/noid-privacy'           "$SCRIPT" "DOC_DIR constant"
assert_grep_fixed '01-getting-started.md'                 "$SCRIPT" "launches 01-getting-started.md"
assert_grep_fixed '06-vpn-setup.md'                       "$SCRIPT" "links to VPN setup guide"
assert_grep_fixed 'def act_open_doc_folder'               "$SCRIPT" "documentation-folder action exists"
assert_grep_fixed "spawn_app(['xdg-open', str(p)])"       "$SCRIPT" "documentation folder uses the native desktop opener"
assert_grep_fixed "'All Documentation'"                   "$SCRIPT" "Reference group exposes every installed guide"
assert_grep_fixed 'act_open_doc_folder'                   "$SCRIPT" "documentation-folder row is wired to its action"

# --- Project & Ecosystem group (website / siblings / donation) --
# The distro's only interactive website/donation/cross-platform surface —
# static one-shot group, no timer/popup/nag (companion: M32 STEP 7c doc).
# Regression guard so these pointers are never silently lost again.
for eco_marker in \
    'def act_open_website' \
    'def act_open_github' \
    'def act_open_donate' \
    "'Project &amp; Ecosystem'" \
    'https://noid-privacy.com/' \
    'https://github.com/NexusOne23' \
    'https://buymeacoffee.com/noidprivacy'; do
    assert_grep_fixed "$eco_marker" "$SCRIPT" "ecosystem group: $eco_marker"
done

# --- autostart .desktop entry (--autostart is required) -------
assert_grep_fixed '/etc/xdg/autostart/noid-welcome.desktop'        "$KS_FILE" "autostart .desktop installed"
assert_grep_fixed 'Exec=/usr/local/bin/noid-welcome.sh --autostart' \
    "$AUTOSTART_DESKTOP" "autostart Exec uses GTK's maintained renderer"
assert_not_grep 'GSK_RENDERER=' "$AUTOSTART_DESKTOP" \
    "autostart launcher does not pin a renderer"
assert_not_grep_extended '^AutostartCondition=' "$AUTOSTART_DESKTOP" \
    "Setup autostart is not silently dropped when GNOME's condition helper is absent"
assert_grep_fixed "initial_setup_done = Path(config_home) / 'gnome-initial-setup-done'" \
    "$SCRIPT" "Setup orders itself after GNOME's real completion sentinel"
assert_grep_fixed 'deadline = time.monotonic() + 1800' "$SCRIPT" \
    "GNOME initial-setup ordering is bounded and retryable"
assert_eq 2 "$(grep -cF 'row.set_use_markup(False)' "$SCRIPT")" \
    "third-party desktop names and comments are rendered as literal text"
assert_grep_fixed 'StartupWMClass=com.noidprivacy.Welcome'         "$KS_FILE" ".desktop WMClass = APP_ID"

# --- app-grid launcher (re-launch via --again) --------------------
assert_grep_fixed '/usr/share/applications/noid-welcome.desktop'    "$KS_FILE" "app-grid launcher present"
assert_grep_fixed 'Exec=/usr/local/bin/noid-welcome.sh --again' \
    "$APP_DESKTOP" "app-grid Exec uses GTK's maintained renderer"
assert_not_grep 'GSK_RENDERER=' "$APP_DESKTOP" \
    "app-grid launcher does not pin a renderer"
assert_grep_fixed 'GenericName=System Setup' "$KS_FILE" \
    "Setup desktop identity includes the suite-wide generic name"
assert_grep_fixed 'Icon=noid-privacy-setup' "$KS_FILE" \
    "Setup desktop and running-window icon agree"
assert_not_grep '^Icon=noid-privacy-welcome$' "$KS_FILE" \
    "autostart and app-grid launchers cannot diverge on Setup identity"
for identity in \
    'Name=NoID Privacy Setup' \
    'GenericName=System Setup' \
    'Icon=noid-privacy-setup' \
    'StartupWMClass=com.noidprivacy.Welcome' \
    'StartupNotify=true'; do
    assert_grep_fixed "$identity" "$AUTOSTART_DESKTOP" \
        "Setup autostart identity: $identity"
    assert_grep_fixed "$identity" "$APP_DESKTOP" \
        "Setup app-grid identity: $identity"
done

# --- pure hardware-event live watches (F4 mic / rfkill BT) ---
assert_grep_fixed 'def _fd_add_watch'                 "$SCRIPT" "fd-watch helper (GLibUnix.fd_add_full + fallback)"
assert_grep_fixed 'def _watch_pipewire'               "$SCRIPT" "pw-mon watch (F4 mic-mute + GNOME audio panel)"
assert_grep_fixed 'def _watch_rfkill'                 "$SCRIPT" "/dev/rfkill watch (GNOME BT toggle + hardware key)"
assert_grep_fixed 'self._mic_pwmon = _watch_pipewire' "$SCRIPT" "mic pw-mon watch wired in __init__"
assert_grep_fixed 'self._bt_rfkill = _watch_rfkill'   "$SCRIPT" "bt rfkill watch wired in __init__"
assert_grep_fixed 'GLib.IOCondition.ERR | GLib.IOCondition.NVAL' "$SCRIPT" \
    "fd watches subscribe to terminal error conditions"
assert_grep_fixed '_retire_pipewire_monitor(proc)' "$SCRIPT" \
    "terminal pw-mon watches close and reap their process"
assert_grep_fixed 'def retire_pipewire_monitor(self)' "$SCRIPT" \
    "Setup owns an idempotent pw-mon shutdown path"
assert_grep_fixed 'win.connect('\''close-request'\'', self._on_window_close_request)' \
    "$SCRIPT" "native window close retires Setup background monitoring"
assert_grep_fixed 'def do_shutdown(self)' "$SCRIPT" \
    "application-driven Setup shutdown also retires background monitoring"
assert_grep_fixed 'Adw.Application.do_shutdown(self)' "$SCRIPT" \
    "Setup chains through the complete Gtk/libadwaita shutdown hierarchy"
assert_not_grep 'Gio.Application.do_shutdown(self)' "$SCRIPT" \
    "Setup does not skip GtkApplication shutdown"
assert_grep_fixed "exact_user_processes('pw-mon')" "$A11Y_RUNTIME" \
    "real four-app gate inventories Setup's out-of-group pw-mon helper"
assert_grep_fixed "invoke(frame, ('close',))" "$A11Y_RUNTIME" \
    "real four-app gate exercises each native window close path"
assert_grep_fixed 'Setup left pw-mon running after native close' "$A11Y_RUNTIME" \
    "real four-app gate rejects an escaped Setup PipeWire monitor"
assert_grep_fixed 'review the current DNF transaction and watch progress' \
    "$SCRIPT" "Gaming confirmation delegates moving package size to DNF"
assert_not_grep_extended '~1 GB|~184 packages' "$KS_FILE" \
    "M13 UI and comments carry no stale Steam transaction size"

# Execute the pure fd-read state machine without importing GTK/GI. This covers
# data, coalesced EAGAIN, EOF, HUP, IN|HUP and a hard read error.
if python3 - "$SCRIPT" <<'PY'
import ast
import sys

source = open(sys.argv[1], encoding='utf-8').read()
tree = ast.parse(source)
fn = next(node for node in tree.body
          if isinstance(node, ast.FunctionDef)
          and node.name == '_classify_fd_event')
module = ast.Module(body=[fn], type_ignores=[])
ast.fix_missing_locations(module)
namespace = {}
exec(compile(module, '<fd-event-fixture>', 'exec'), namespace)
classify = namespace['_classify_fd_event']

IN = 1
HUP = 2
ERR = 4
NVAL = 8
TERMINAL = HUP | ERR | NVAL

assert classify(IN, IN, TERMINAL, lambda: b'event') == (True, True, None)

def eagain():
    raise BlockingIOError()
assert classify(IN, IN, TERMINAL, eagain) == (True, False, None)

assert classify(IN, IN, TERMINAL, lambda: b'') == (False, False, None)

def must_not_read():
    raise AssertionError('pure HUP must not call read')
assert classify(HUP, IN, TERMINAL, must_not_read) == (False, False, None)
assert classify(IN | HUP, IN, TERMINAL, lambda: b'last') == \
       (False, True, None)

def hard_error():
    raise OSError('fixture failure')
keep, seen, error = classify(IN, IN, TERMINAL, hard_error)
assert (keep, seen) == (False, False)
assert isinstance(error, OSError)
PY
then
    _pass "fd callback fixtures cover data, EAGAIN, EOF, HUP and hard errors"
else
    _fail "fd callback state-machine fixtures"
fi

test_finish
