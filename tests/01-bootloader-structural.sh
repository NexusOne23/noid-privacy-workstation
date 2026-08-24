#!/bin/bash
# 01-bootloader-structural — M01 regression test
#
# Covers: cmdline KSPP hardening flags, CPU/GPU hardware conditionals,
# vendor-owned backlight/sleep selection, dnf.conf and GRUB handling.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/01-bootloader.ks"
REVERT_DOC="$PROJECT_ROOT/docs/revert-uninstall.md"
GAMING_DOC="$PROJECT_ROOT/docs/gaming.md"
KARG_MANIFEST="$PROJECT_ROOT/manifests/kernel-cmdline.tsv"
KARG_CONTRACT="$PROJECT_ROOT/tests/01-karg-contract.py"
RUNTIME_GATE="$PROJECT_ROOT/tests/pre-ship/01-kernel-cmdline-runtime.sh"
TIMEZONE_RUNTIME_GATE="$PROJECT_ROOT/tests/pre-ship/01-timezone-runtime.sh"
GRUB_PTY_FIXTURE="$PROJECT_ROOT/tests/01-grub-prompt-fixture.py"
# The hardened host mounts /tmp noexec. This fixture must exercise the helper's
# real `-x`/direct-exec check for Fedora's 01_users, so keep it on the executable
# repository filesystem and remove it unconditionally.
TEST_TMPDIR=$(mktemp -d "$PROJECT_ROOT/.test-01-bootloader.XXXXXX")
trap 'rm -rf "$TEST_TMPDIR"' EXIT

test_start "01-bootloader-structural"

assert_file_exists "$KS_FILE"
assert_file_exists "$REVERT_DOC"
assert_file_exists "$GAMING_DOC"
assert_cmd_success "bash -n $KS_FILE" bash -n "$KS_FILE"

# One canonical closed manifest drives exact parsing of the five load-bearing
# surfaces: primary/interactive bootloader append, target NOID_BASE_ARGS,
# hardware conditionals and the inherited-argument filter. The verifier also
# mutates the primary line in memory to prove that a comment-only token and a
# duplicate/conflicting value both fail.
assert_file_exists "$KARG_MANIFEST" "canonical kernel-cmdline manifest exists"
assert_file_executable "$KARG_CONTRACT" "kernel-cmdline contract verifier is executable"
assert_cmd_success "all M01 kernel-argument surfaces match the closed manifest" \
    python3 "$KARG_CONTRACT" source "$KS_FILE" "$KARG_MANIFEST"
assert_grep_fixed '#     rd.luks.options=<UUID>=tries=0,discard' "$KS_FILE" \
    "M01 header records the complete LUKS option including discard pass-through"
assert_grep_fixed "systemd-escape: Input 'luks-…' is not an absolute" \
    "$PROJECT_ROOT/docs/known-failures.md" \
    "known failures records Fedora dracut's cosmetic LUKS mapper escape warning"
assert_grep_fixed '70crypt/module-setup.sh' "$PROJECT_ROOT/docs/known-failures.md" \
    "LUKS mapper warning classification cites the installed upstream producer"
assert_grep_fixed 'systemd-cryptsetup@luks\x2d….service' \
    "$PROJECT_ROOT/docs/known-failures.md" \
    "LUKS mapper warning guidance requires a positive unlock postcondition"
assert_grep_fixed '### One-boot pstore capture for an early hang' \
    "$PROJECT_ROOT/docs/known-failures.md" \
    "known failures documents the bounded early-boot evidence path"
assert_grep_fixed 'efi_pstore.pstore_disable=N printk.always_kmsg_dump=Y' \
    "$PROJECT_ROOT/docs/known-failures.md" \
    "pstore diagnostic uses the current kernel one-boot controls"
assert_grep_fixed 'make the same temporary GRUB edit on' \
    "$PROJECT_ROOT/docs/known-failures.md" \
    "pstore retrieval re-enables the backend on the recovery boot"
assert_grep_fixed 'Removing a file from `/sys/fs/pstore` erases' \
    "$PROJECT_ROOT/docs/known-failures.md" \
    "pstore guidance protects the evidence boundary"
assert_not_grep 'grubby.*efi_pstore.pstore_disable=N' \
    "$PROJECT_ROOT/docs/known-failures.md" \
    "one-boot diagnostics never prescribe a persistent cmdline mutation"
assert_grep_fixed 'On an affected CPU this deliberately leaves' "$KS_FILE" \
    "M01 names the residual cross-thread risk of retaining SMT"
assert_grep_fixed 'performance impact is workload- and' "$KS_FILE" \
    "M01 does not claim a universal SMT performance percentage"
assert_not_grep_extended '30[[:space:]]*[-–—…][[:space:]]*50.*multithread' \
    "$KS_FILE" "obsolete universal SMT performance range cannot return"
assert_grep_fixed 'workload- and CPU-topology-dependent (M01)' "$GAMING_DOC" \
    "gaming guide uses the same bounded SMT performance statement"
assert_not_grep_extended '30[[:space:]]*[-–—…][[:space:]]*50.*multithread' \
    "$GAMING_DOC" "gaming guide cannot restore the universal SMT range"
assert_not_grep_extended '~1 GB|~184 packages|official Steam Flatpak' \
    "$GAMING_DOC" "gaming guide carries no stale transaction size or publisher claim"
assert_grep_fixed 'DNF displays the current package set, download size and disk change' \
    "$GAMING_DOC" "gaming guide delegates moving transaction facts to DNF"
assert_not_grep 'spectre_v2_user' "$KARG_MANIFEST" \
    "redundant user-space Spectre-v2 default is absent from the closed manifest"
assert_not_grep 'spectre_v2_user=auto' "$KS_FILE" \
    "spectre_v2=on is not paired with an overridden active user-space token"
assert_grep_fixed 'base|loglevel=4' "$KARG_MANIFEST" \
    "console threshold retains KERN_ERR and more-severe early diagnostics"
assert_grep_fixed 'base|quiet' "$KARG_MANIFEST" \
    "systemd status output is reduced to failures on the boot console"
assert_eq 4 "$(grep -cF 'rhgb quiet ' "$KS_FILE")" \
    "both bootloader appends and both canonical arg sets carry rhgb quiet"
assert_not_grep_extended '(--append=|NOID_BASE_ARGS=)"rhgb [^q]' "$KS_FILE" \
    "no canonical kernel-command-line definition lost the quiet companion"
assert_eq 2 "$(grep -cF 'spectre_v2_user=*' "$KS_FILE")" \
    "target and firstboot canonicalizers retire the former override"
assert_grep_fixed 'Pykickstart records the historical' "$KS_FILE" \
    "M01 documents the real omitted-location parser default"
assert_not_grep 'no --location=mbr' "$KS_FILE" \
    "bootloader-location omission is never misrepresented as a BIOS defense"
assert_grep_fixed 'crypto-policies-scripts' "$KS_FILE" \
    "crypto-policy switching tool is explicit with weak dependencies disabled"

# Lorax owns `rhgb` and `quiet` per menu entry: every entry carries one quiet,
# normal/basic additionally carry one rhgb, while media-check deliberately omits
# rhgb. scripts/build-iso.sh therefore keeps both out of --extra-boot-args.
# Mirror that exact split here and exercise the parser used against the final ISO.
primary_args=$(sed -n \
    's/^bootloader --timeout=3 --append="\([^"]*\)"$/\1/p' "$KS_FILE" | head -1)
live_args=plymouth.use-simpledrm=1
for arg in $primary_args; do
    case "$arg" in
        rhgb|quiet) continue ;;
    esac
    live_args="$live_args $arg"
done
LIVE_CONFIG_FIXTURE="$TEST_TMPDIR/live-grub.cfg"
cat > "$LIVE_CONFIG_FIXTURE" <<EOF_LIVE_CONFIG
set default="0"
set timeout=3
menuentry normal {
  linux /images/pxeboot/vmlinuz root=live:LABEL=FIXTURE $live_args rd.live.image quiet rhgb
}
menuentry media-check {
  linux /images/pxeboot/vmlinuz root=live:LABEL=FIXTURE $live_args rd.live.image rd.live.check quiet
}
menuentry basic {
  linux /images/pxeboot/vmlinuz root=live:LABEL=FIXTURE $live_args rd.live.image nomodeset quiet rhgb
}
EOF_LIVE_CONFIG
assert_cmd_success "final Live config accepts exact Lorax rhgb ownership" \
    python3 "$KARG_CONTRACT" live-config \
        "$LIVE_CONFIG_FIXTURE" "$KARG_MANIFEST" "$KS_FILE"
cp "$LIVE_CONFIG_FIXTURE" "$LIVE_CONFIG_FIXTURE.bad"
sed -i '0,/root=live:LABEL=FIXTURE /s//root=live:LABEL=FIXTURE rhgb /' \
    "$LIVE_CONFIG_FIXTURE.bad"
assert_cmd_failure "normal Live entry rejects duplicate rhgb" \
    python3 "$KARG_CONTRACT" live-config \
        "$LIVE_CONFIG_FIXTURE.bad" "$KARG_MANIFEST" "$KS_FILE"
cp "$LIVE_CONFIG_FIXTURE" "$LIVE_CONFIG_FIXTURE.bad"
sed -i '/rd\.live\.check/s/ quiet$/ quiet rhgb/' "$LIVE_CONFIG_FIXTURE.bad"
assert_cmd_failure "media-check entry rejects an injected rhgb" \
    python3 "$KARG_CONTRACT" live-config \
        "$LIVE_CONFIG_FIXTURE.bad" "$KARG_MANIFEST" "$KS_FILE"
cp "$LIVE_CONFIG_FIXTURE" "$LIVE_CONFIG_FIXTURE.bad"
sed -i '0,/root=live:LABEL=FIXTURE /s//root=live:LABEL=FIXTURE quiet /' \
    "$LIVE_CONFIG_FIXTURE.bad"
assert_cmd_failure "normal Live entry rejects duplicate quiet" \
    python3 "$KARG_CONTRACT" live-config \
        "$LIVE_CONFIG_FIXTURE.bad" "$KARG_MANIFEST" "$KS_FILE"
cp "$LIVE_CONFIG_FIXTURE" "$LIVE_CONFIG_FIXTURE.bad"
sed -i 's/ rd\.live\.image quiet rhgb$/ rd.live.image rhgb/' "$LIVE_CONFIG_FIXTURE.bad"
assert_cmd_failure "normal Live entry rejects a missing vendor quiet" \
    python3 "$KARG_CONTRACT" live-config \
        "$LIVE_CONFIG_FIXTURE.bad" "$KARG_MANIFEST" "$KS_FILE"
cp "$LIVE_CONFIG_FIXTURE" "$LIVE_CONFIG_FIXTURE.bad"
sed -i '0,/ module\.sig_enforce=1/s///' "$LIVE_CONFIG_FIXTURE.bad"
assert_cmd_failure "final Live entry rejects a missing managed security token" \
    python3 "$KARG_CONTRACT" live-config \
        "$LIVE_CONFIG_FIXTURE.bad" "$KARG_MANIFEST" "$KS_FILE"
cp "$LIVE_CONFIG_FIXTURE" "$LIVE_CONFIG_FIXTURE.bad"
sed -i 's/^set default="0"$/set default="1"/' "$LIVE_CONFIG_FIXTURE.bad"
assert_cmd_failure "final Live config rejects media-check as the default" \
    python3 "$KARG_CONTRACT" live-config \
        "$LIVE_CONFIG_FIXTURE.bad" "$KARG_MANIFEST" "$KS_FILE"
cp "$LIVE_CONFIG_FIXTURE" "$LIVE_CONFIG_FIXTURE.bad"
sed -i 's/^set timeout=3$/set timeout=60/' "$LIVE_CONFIG_FIXTURE.bad"
assert_cmd_failure "final Live config rejects the legacy 60-second countdown" \
    python3 "$KARG_CONTRACT" live-config \
        "$LIVE_CONFIG_FIXTURE.bad" "$KARG_MANIFEST" "$KS_FILE"

LIVE_CMDLINE_FIXTURE="$TEST_TMPDIR/live-cmdline"
sed -n '0,/^[[:space:]]*linux /s/^[[:space:]]*linux [^[:space:]]*[[:space:]]*//p' \
    "$LIVE_CONFIG_FIXTURE" > "$LIVE_CMDLINE_FIXTURE"
assert_cmd_success "runtime live mode consumes its explicit cmdline input" \
    python3 "$KARG_CONTRACT" live "$LIVE_CMDLINE_FIXTURE" \
        "$KARG_MANIFEST" "$KS_FILE"
printf ' slab_debug=FZPU\n' >> "$LIVE_CMDLINE_FIXTURE"
assert_cmd_failure "runtime contract rejects the forbidden slab_debug family" \
    python3 "$KARG_CONTRACT" live "$LIVE_CMDLINE_FIXTURE" \
        "$KARG_MANIFEST" "$KS_FILE"

assert_not_grep 'kptr_restrict' "$KARG_MANIFEST" \
    "sysctl-only kptr_restrict cannot be counted as a kernel argument"
assert_not_grep '^base|slab_debug=' "$KARG_MANIFEST" \
    "production kernel contract does not enable global SLUB diagnostics"
assert_grep_fixed 'base|kfence.deferrable=1' "$KARG_MANIFEST" \
    "sampled KFENCE does not wake an otherwise idle CPU"
assert_file_executable "$RUNTIME_GATE" \
    "three-pass installed BLS/kernel-cmdline gate is executable"
assert_grep_fixed 'case "$PASS_ID" in live|fresh-install|reboot)' "$RUNTIME_GATE" \
    "runtime gate has the exact closed lifecycle-pass set"
assert_grep_fixed '01-karg-contract.py' "$RUNTIME_GATE" \
    "runtime gate uses the same canonical parser as the source contract"
assert_grep_fixed '"$MANIFEST" "$SOURCE"' "$RUNTIME_GATE" \
    "live runtime order is derived from the reviewed primary source surface"
assert_grep_fixed 'noid-firstboot-cmdline.service -p Result' "$RUNTIME_GATE" \
    "installed passes require a successful firstboot cmdline result"
assert_grep_fixed 'elif bls != kernel + [TUNED_BLS_ARG]:' "$KARG_CONTRACT" \
    "runtime parser requires one exact normal-BLS tuned transport macro"
assert_grep_fixed 'if bls != kernel + [TUNED_BLS_ARG, FALLBACK_ARG]:' \
    "$KARG_CONTRACT" \
    "runtime parser permits only the tuned macro then pending recovery marker"
assert_grep_fixed 'require_runtime_managed("/proc/cmdline"' "$KARG_CONTRACT" \
    "runtime parser checks the effective installed boot arguments"
assert_grep_fixed 'M21 lifecycle state ownership/mode differs' "$KARG_CONTRACT" \
    "runtime parser authenticates the private M21 lifecycle state"
assert_grep_fixed 'M21 lifecycle root class differs' "$KARG_CONTRACT" \
    "runtime parser closes the M21 root-class vocabulary"
assert_grep_fixed 'M21 lifecycle target kernel is malformed' "$KARG_CONTRACT" \
    "runtime parser validates the M21 kernel identity"
assert_grep_fixed 'M21 lifecycle prepared boot ID is malformed' "$KARG_CONTRACT" \
    "runtime parser validates the M21 boot identity"
assert_grep_fixed 'BLS entry directory is non-directory/symlinked' \
    "$KARG_CONTRACT" "runtime parser rejects an unsafe BLS directory"
assert_grep_fixed 'BLS entry is non-regular/symlinked' "$KARG_CONTRACT" \
    "runtime parser rejects symlinked BLS entries"
assert_grep_fixed 'BLS entry ownership/mode differs' "$KARG_CONTRACT" \
    "runtime parser authenticates BLS entry metadata"

# Exercise the actual deployed compose-time payload verifier. No BLS fixture is
# created: that intentionally reproduces the lifecycle boundary exposed by the
# canonical Live-image compose. The verifier must accept the two exact target
# writers, then reject an active omission, comment-only false green, conflicting
# value, removed atomic publication marker and a symlinked payload.
KARG_PAYLOAD_VERIFIER="$TEST_TMPDIR/noid-verify-target-karg-payload"
INTERACTIVE_FIXTURE="$TEST_TMPDIR/interactive-defaults.ks"
TARGET_POST_FIXTURE="$TEST_TMPDIR/90-noid-kernel-cmdline.ks"
TARGET_POST_BODY="$TEST_TMPDIR/90-noid-kernel-cmdline.body"
CANONICALIZER_FIXTURE="$TEST_TMPDIR/noid-canonicalize-kernel-cmdline"
FIRSTBOOT_FIXTURE="$TEST_TMPDIR/noid-firstboot-cmdline"
ROOTFLAGS_REBIND_FIXTURE="$TEST_TMPDIR/noid-rebind-firstboot-rootflags"
CMDLINE_TRANSITION_FIXTURE="$TEST_TMPDIR/noid-firstboot-cmdline-transition"
extract_heredoc "$KS_FILE" "KARG_PAYLOAD_VERIFY_EOF" \
    "$KARG_PAYLOAD_VERIFIER" || _fail "KARG_PAYLOAD_VERIFY_EOF extraction"
assert_grep_fixed 'Read-only compose-time verifier' "$KARG_PAYLOAD_VERIFIER" \
    "payload verifier names its real lifecycle"
assert_grep_fixed 'target %post removes this verifier' "$KARG_PAYLOAD_VERIFIER" \
    "deployed verifier names its exact target-cleanup boundary"
assert_not_grep 'compose/runtime verifier' "$KARG_PAYLOAD_VERIFIER" \
    "payload verifier no longer advertises an impossible runtime contract"
extract_heredoc "$KS_FILE" "INTERACTIVE_DEFAULTS_EOF" \
    "$INTERACTIVE_FIXTURE" || _fail "INTERACTIVE_DEFAULTS_EOF extraction"
assert_eq 1 "$(grep -cE '^[[:space:]]*timezone[[:space:]]' "$INTERACTIVE_FIXTURE")" \
    "interactive installer has exactly one active timezone directive"
assert_grep_fixed 'timezone UTC --utc' "$INTERACTIVE_FIXTURE" \
    "interactive installer stays neutral UTC until conscious user choice"
assert_not_grep 'America/New_York' "$INTERACTIVE_FIXTURE" \
    "Anaconda's internal US fallback cannot become the installer default"
assert_file_executable "$TIMEZONE_RUNTIME_GATE" \
    "timezone lifecycle has an executable three-stage candidate gate"
assert_grep_fixed 'fresh-install|reboot)' \
    "$TIMEZONE_RUNTIME_GATE" \
    "timezone runtime gate covers both installed selection passes"
assert_grep_fixed 'EXPECTED_TIMEZONE=$2' "$TIMEZONE_RUNTIME_GATE" \
    "installed timezone passes consume the consciously selected IANA name"
assert_grep_fixed 'expected timezone contains a traversal component' \
    "$TIMEZONE_RUNTIME_GATE" \
    "selected timezone validation rejects path traversal"
assert_grep_fixed 'readlink /etc/localtime' "$TIMEZONE_RUNTIME_GATE" \
    "timezone runtime gate authenticates the exact lifecycle symlink target"
assert_grep_fixed 'timedatectl show -p Timezone --value' "$TIMEZONE_RUNTIME_GATE" \
    "timezone runtime gate verifies systemd's effective timezone"
assert_grep_fixed 'NR == 3 { print; found=1 }' "$TIMEZONE_RUNTIME_GATE" \
    "timezone runtime gate verifies the hardware-clock UTC contract"
extract_heredoc "$KS_FILE" "NOID_KARGS_EOF" \
    "$TARGET_POST_BODY" || _fail "NOID_KARGS_EOF extraction"
assert_grep_fixed 'remove_installer_only_payload()' "$TARGET_POST_BODY" \
    "target post owns explicit installer-payload cleanup"
assert_grep_fixed '/usr/share/anaconda/noid-target-kernel-cmdline.ks root:root:644' \
    "$TARGET_POST_BODY" "target post removes its regular audited fragment"
assert_grep_fixed '/usr/libexec/noid-verify-target-karg-payload root:root:755' \
    "$TARGET_POST_BODY" "target post removes the compose-only verifier"
assert_grep_fixed 'installer-only payload survived removal' "$TARGET_POST_BODY" \
    "target cleanup verifies the absence postcondition"
assert_grep_fixed 'publish_target_bls_options()' "$TARGET_POST_BODY" \
    "target post owns the bounded atomic BLS publisher"
assert_grep_fixed 'Anaconda has already installed the kernel' "$TARGET_POST_BODY" \
    "target post documents why an initramfs rebuild is redundant"
assert_not_grep_extended '^[[:space:]]*(kernel-install|dracut)([[:space:]]|$)' \
    "$TARGET_POST_BODY" \
    "target cmdline publication cannot invoke the kernel or initramfs plugin stack"
assert_grep_fixed 'restorecon -F "$temporary"' "$TARGET_POST_BODY" \
    "atomic target BLS replacement receives its destination SELinux type"
assert_grep_fixed 'matchpathcon -V "$entry"' "$TARGET_POST_BODY" \
    "published target BLS entry verifies its final SELinux label"

BLS_PUBLISHER_FIXTURE="$TEST_TMPDIR/publish-target-bls-options.sh"
awk '
    /^publish_target_bls_options\(\)/ { copy=1 }
    copy { print }
    copy && /^}/ { exit }
' "$TARGET_POST_BODY" > "$BLS_PUBLISHER_FIXTURE"
assert_cmd_success "target BLS publisher parses" \
    bash -n "$BLS_PUBLISHER_FIXTURE"

BLS_FIXTURE_DIR="$TEST_TMPDIR/bls/loader/entries"
BLS_FAKE_BIN="$TEST_TMPDIR/bls-fake-bin"
mkdir -p "$BLS_FIXTURE_DIR" "$BLS_FAKE_BIN"
cat > "$BLS_FAKE_BIN/noid-true" <<'EOF_BLS_TRUE'
#!/bin/sh
exit 0
EOF_BLS_TRUE
chmod 0755 "$BLS_FAKE_BIN/noid-true"
ln -s noid-true "$BLS_FAKE_BIN/chown"
ln -s noid-true "$BLS_FAKE_BIN/restorecon"
ln -s noid-true "$BLS_FAKE_BIN/matchpathcon"
printf '%s\n' \
    'title NoID Privacy kernel one' \
    'version 1.0.0' \
    'linux /vmlinuz-1.0.0' \
    'options root=UUID=old-one ro quiet $tuned_params' \
    > "$BLS_FIXTURE_DIR/one.conf"
printf '%s\n' \
    'title NoID Privacy kernel two' \
    'version 2.0.0' \
    'linux /vmlinuz-2.0.0' \
    'options root=UUID=old-two ro quiet $tuned_params' \
    > "$BLS_FIXTURE_DIR/two.conf"
bls_expected='root=UUID=target ro module.sig_enforce=1 $tuned_params'
assert_cmd_success "target BLS publisher updates the complete valid set" \
    env PATH="$BLS_FAKE_BIN:$PATH" bash -c \
    'log() { :; }; . "$1"; publish_target_bls_options "$2" "$3"' _ \
    "$BLS_PUBLISHER_FIXTURE" "$BLS_FIXTURE_DIR" "$bls_expected"
assert_eq "$bls_expected" \
    "$(sed -n 's/^options //p' "$BLS_FIXTURE_DIR/one.conf")" \
    "first target BLS entry receives the exact options value"
assert_eq "$bls_expected" \
    "$(sed -n 's/^options //p' "$BLS_FIXTURE_DIR/two.conf")" \
    "second target BLS entry receives the exact options value"
assert_grep_fixed 'title NoID Privacy kernel one' "$BLS_FIXTURE_DIR/one.conf" \
    "target publisher preserves unrelated BLS fields"
bls_hashes=$(sha256sum "$BLS_FIXTURE_DIR"/*.conf)
assert_cmd_success "target BLS publication is idempotent" \
    env PATH="$BLS_FAKE_BIN:$PATH" bash -c \
    'log() { :; }; . "$1"; publish_target_bls_options "$2" "$3"' _ \
    "$BLS_PUBLISHER_FIXTURE" "$BLS_FIXTURE_DIR" "$bls_expected"
assert_eq "$bls_hashes" "$(sha256sum "$BLS_FIXTURE_DIR"/*.conf)" \
    "idempotent target publication preserves exact BLS bytes"

printf '%s\n' \
    'title malformed later entry' \
    'options root=UUID=first ro' \
    'options root=UUID=second ro' \
    > "$BLS_FIXTURE_DIR/z-malformed.conf"
bls_hashes=$(sha256sum "$BLS_FIXTURE_DIR/one.conf" \
    "$BLS_FIXTURE_DIR/two.conf")
assert_cmd_failure "target publisher rejects duplicate options before mutation" \
    env PATH="$BLS_FAKE_BIN:$PATH" bash -c \
    'log() { :; }; . "$1"; publish_target_bls_options "$2" "$3"' _ \
    "$BLS_PUBLISHER_FIXTURE" "$BLS_FIXTURE_DIR" "$bls_expected"
assert_eq "$bls_hashes" \
    "$(sha256sum "$BLS_FIXTURE_DIR/one.conf" "$BLS_FIXTURE_DIR/two.conf")" \
    "malformed later entry leaves the prior valid set untouched"
rm "$BLS_FIXTURE_DIR/z-malformed.conf"

mv "$BLS_FIXTURE_DIR/two.conf" "$BLS_FIXTURE_DIR/two.conf.real"
ln -s two.conf.real "$BLS_FIXTURE_DIR/two.conf"
assert_cmd_failure "target publisher rejects symlinked BLS entries" \
    env PATH="$BLS_FAKE_BIN:$PATH" bash -c \
    'log() { :; }; . "$1"; publish_target_bls_options "$2" "$3"' _ \
    "$BLS_PUBLISHER_FIXTURE" "$BLS_FIXTURE_DIR" "$bls_expected"
rm "$BLS_FIXTURE_DIR/two.conf"
mv "$BLS_FIXTURE_DIR/two.conf.real" "$BLS_FIXTURE_DIR/two.conf"
mkdir "$TEST_TMPDIR/empty-bls"
assert_cmd_failure "target publisher rejects an empty BLS directory" \
    env PATH="$BLS_FAKE_BIN:$PATH" bash -c \
    'log() { :; }; . "$1"; publish_target_bls_options "$2" "$3"' _ \
    "$BLS_PUBLISHER_FIXTURE" "$TEST_TMPDIR/empty-bls" "$bls_expected"
if compgen -G "$BLS_FIXTURE_DIR/.noid-bls.*" >/dev/null; then
    _fail "target BLS fixture left a temporary publication file"
else
    _pass "target BLS publisher leaves no temporary files"
fi

TARGET_CLEANUP_HELPER="$TEST_TMPDIR/remove-installer-only-payload.sh"
awk '
    /^remove_installer_only_payload\(\)/ { copy=1 }
    copy { print }
    copy && /^}/ { exit }
' "$TARGET_POST_BODY" > "$TARGET_CLEANUP_HELPER"
assert_cmd_success "target installer-payload cleanup helper parses" \
    bash -n "$TARGET_CLEANUP_HELPER"
TARGET_CLEANUP_FILE="$TEST_TMPDIR/installer-only-payload"
printf '%s\n' 'compose-only fixture' > "$TARGET_CLEANUP_FILE"
chmod 0644 "$TARGET_CLEANUP_FILE"
cleanup_metadata="$(id -un):$(id -gn):644"
assert_cmd_success "target cleanup removes an exact regular payload" \
    bash -c '. "$1"; remove_installer_only_payload "$2" "$3"' _ \
    "$TARGET_CLEANUP_HELPER" "$TARGET_CLEANUP_FILE" "$cleanup_metadata"
assert_cmd_success "target cleanup establishes the absence postcondition" \
    test ! -e "$TARGET_CLEANUP_FILE"
printf '%s\n' 'wrong mode fixture' > "$TARGET_CLEANUP_FILE"
chmod 0600 "$TARGET_CLEANUP_FILE"
assert_cmd_failure "target cleanup rejects unexpected payload metadata" \
    bash -c 'log() { :; }; . "$1"; remove_installer_only_payload "$2" "$3"' _ \
    "$TARGET_CLEANUP_HELPER" "$TARGET_CLEANUP_FILE" "$cleanup_metadata"
rm "$TARGET_CLEANUP_FILE"
printf '%s\n' 'symlink target fixture' > "$TARGET_CLEANUP_FILE.real"
ln -s "$(basename "$TARGET_CLEANUP_FILE.real")" "$TARGET_CLEANUP_FILE"
assert_cmd_failure "target cleanup rejects a symlinked payload" \
    bash -c 'log() { :; }; . "$1"; remove_installer_only_payload "$2" "$3"' _ \
    "$TARGET_CLEANUP_HELPER" "$TARGET_CLEANUP_FILE" "$cleanup_metadata"
rm "$TARGET_CLEANUP_FILE"
mv "$TARGET_CLEANUP_FILE.real" "$TARGET_CLEANUP_FILE"
{
    printf '%s\n' '%post --erroronfail --interpreter=/bin/bash --log=/var/log/noid-anaconda-kernel-cmdline.log'
    cat "$TARGET_POST_BODY"
    printf '%s\n' '%end'
} > "$TARGET_POST_FIXTURE"
cat "$TARGET_POST_FIXTURE" >> "$INTERACTIVE_FIXTURE"
extract_heredoc "$KS_FILE" "CMDLINE_CANONICALIZER_EOF" \
    "$CANONICALIZER_FIXTURE" || _fail "CMDLINE_CANONICALIZER_EOF extraction"
extract_heredoc "$KS_FILE" "CMDLINE_EOF" \
    "$FIRSTBOOT_FIXTURE" || _fail "CMDLINE_EOF extraction"
extract_heredoc "$KS_FILE" "ROOTFLAGS_REBIND_EOF" \
    "$ROOTFLAGS_REBIND_FIXTURE" || _fail "ROOTFLAGS_REBIND_EOF extraction"
extract_heredoc "$KS_FILE" "CMDLINE_TRANSITION_EOF" \
    "$CMDLINE_TRANSITION_FIXTURE" || _fail "CMDLINE_TRANSITION_EOF extraction"
fixture_identity="$(id -un):$(id -gn):644"
sed \
    -e "s|^INTERACTIVE=.*|INTERACTIVE=$INTERACTIVE_FIXTURE|" \
    -e "s|^TARGET_POST=.*|TARGET_POST=$TARGET_POST_FIXTURE|" \
    -e "s|^EXPECTED_METADATA=.*|EXPECTED_METADATA=$fixture_identity|" \
    "$KARG_PAYLOAD_VERIFIER" > "$KARG_PAYLOAD_VERIFIER.tmp"
mv -fT "$KARG_PAYLOAD_VERIFIER.tmp" "$KARG_PAYLOAD_VERIFIER"
chmod 0755 "$KARG_PAYLOAD_VERIFIER"
chmod 0644 "$INTERACTIVE_FIXTURE" "$TARGET_POST_FIXTURE"
chmod 0755 "$CANONICALIZER_FIXTURE"
chmod 0755 "$FIRSTBOOT_FIXTURE"
chmod 0755 "$ROOTFLAGS_REBIND_FIXTURE"
chmod 0755 "$CMDLINE_TRANSITION_FIXTURE"
if command -v ksvalidator >/dev/null 2>&1; then
    assert_cmd_success "combined interactive target kickstart validates as Fedora 44" \
        ksvalidator --version F44 "$INTERACTIVE_FIXTURE"
fi
assert_cmd_success "target-karg payload proof passes without a build-topology BLS" \
    "$KARG_PAYLOAD_VERIFIER"

cp "$INTERACTIVE_FIXTURE" "$INTERACTIVE_FIXTURE.good"
sed -i 's/ module\.sig_enforce=1//' "$INTERACTIVE_FIXTURE"
printf '%s\n' '# module.sig_enforce=1 comment-only false-green fixture' \
    >> "$INTERACTIVE_FIXTURE"
assert_cmd_failure "comment-only module signature token cannot satisfy payload proof" \
    "$KARG_PAYLOAD_VERIFIER"
mv -fT "$INTERACTIVE_FIXTURE.good" "$INTERACTIVE_FIXTURE"

cp "$TARGET_POST_FIXTURE" "$TARGET_POST_FIXTURE.good"
sed -i 's/module\.sig_enforce=1/module.sig_enforce=0/g' "$TARGET_POST_FIXTURE"
assert_cmd_failure "conflicting target-post module signature value fails closed" \
    "$KARG_PAYLOAD_VERIFIER"
mv -fT "$TARGET_POST_FIXTURE.good" "$TARGET_POST_FIXTURE"

cp "$TARGET_POST_FIXTURE" "$TARGET_POST_FIXTURE.good"
sed -i 's|^\([[:space:]]*publish_target_bls_options /boot/loader/entries "\$expected_bls_options"\)$|# \1|' \
    "$TARGET_POST_FIXTURE"
assert_cmd_failure "comment-only atomic BLS publication marker fails closed" \
    "$KARG_PAYLOAD_VERIFIER"
mv -fT "$TARGET_POST_FIXTURE.good" "$TARGET_POST_FIXTURE"

mv "$TARGET_POST_FIXTURE" "$TARGET_POST_FIXTURE.real"
ln -s "$(basename "$TARGET_POST_FIXTURE.real")" "$TARGET_POST_FIXTURE"
assert_cmd_failure "symlinked target-post payload fails closed" \
    "$KARG_PAYLOAD_VERIFIER"
rm "$TARGET_POST_FIXTURE"
mv "$TARGET_POST_FIXTURE.real" "$TARGET_POST_FIXTURE"

# --- the canonicalizer may not make a one-boot argument permanent -----------
# It merges durable sources AND the running /proc/cmdline, then publishes the
# result to /etc/kernel/cmdline, every BLS entry and GRUB_CMDLINE_LINUX. An
# argument typed once at the GRUB `e` prompt therefore used to become durable:
# a troubleshooting `nomodeset` survives the driver install it was typed for
# (noid-nvidia-install.sh and noid-update-all.sh both invoke --publish), and
# `enforcing=0` becomes a permanent silent SELinux downgrade that the M01
# firstboot service then seals as the trusted baseline. Drive the real helper
# rather than asserting the source shape.
CANON_ROOT="$TEST_TMPDIR/canon-root"
mkdir -p "$CANON_ROOT/etc/kernel" "$CANON_ROOT/etc/default" \
         "$CANON_ROOT/boot/loader/entries" "$CANON_ROOT/proc"
printf 'root=UUID=11111111-2222-3333-4444-555555555555 ro noid.durable=yes\n' \
    > "$CANON_ROOT/etc/kernel/cmdline"
printf 'GRUB_CMDLINE_LINUX="noid.durable=yes"\n' > "$CANON_ROOT/etc/default/grub"
printf 'options root=UUID=11111111-2222-3333-4444-555555555555 ro noid.durable=yes\n' \
    > "$CANON_ROOT/boot/loader/entries/test.conf"
printf 'UUID=11111111-2222-3333-4444-555555555555 / btrfs subvol=root 0 0\n' \
    > "$CANON_ROOT/etc/fstab"
printf 'flags\t\t: fpu\nvendor_id\t: GenuineIntel\n' > "$CANON_ROOT/proc/cpuinfo"
# The running boot carries the durable set PLUS two operator-typed arguments.
printf 'root=UUID=11111111-2222-3333-4444-555555555555 ro noid.durable=yes enforcing=0 nomodeset\n' \
    > "$CANON_ROOT/proc/cmdline"
canon_stderr="$TEST_TMPDIR/canon.err"
if env NOID_TEST_MODE=1 NOID_TEST_ROOT="$CANON_ROOT" \
       NOID_TEST_CMDLINE_FILE="$CANON_ROOT/proc/cmdline" \
       NOID_TEST_CPUINFO_FILE="$CANON_ROOT/proc/cpuinfo" \
       NOID_TEST_LSPCI_BIN="$CANON_ROOT/nonexistent-lspci" \
       bash "$CANONICALIZER_FIXTURE" --publish >/dev/null 2>"$canon_stderr"; then
    canon_published=$(cat "$CANON_ROOT/etc/kernel/cmdline")
    printf '%s' "$canon_published" | grep -qw 'noid.durable=yes' \
        && _pass "canonicalizer keeps an argument a durable source carries" \
        || _fail "canonicalizer dropped a durable argument"
    printf '%s' "$canon_published" | grep -qw 'enforcing=0' \
        && _fail "one-boot enforcing=0 was made a permanent SELinux downgrade" \
        || _pass "one-boot enforcing=0 is not made durable"
    printf '%s' "$canon_published" | grep -qw 'nomodeset' \
        && _fail "one-boot nomodeset was made permanent" \
        || _pass "one-boot nomodeset is not made durable"
    grep -q 'active-only kernel argument' "$canon_stderr" \
        && _pass "canonicalizer names the active-only arguments it refused" \
        || _fail "active-only arguments were dropped without a diagnostic"
    grep -qw 'enforcing=0' "$CANON_ROOT/boot/loader/entries/test.conf" \
        && _fail "one-boot enforcing=0 reached the BLS entries" \
        || _pass "one-boot argument does not reach the BLS entries"
    grep -qw 'enforcing=0' "$CANON_ROOT/etc/default/grub" \
        && _fail "one-boot enforcing=0 reached GRUB_CMDLINE_LINUX" \
        || _pass "one-boot argument does not reach GRUB_CMDLINE_LINUX"
else
    _fail "canonicalizer failed against its own test root"
    sed 's/^/      /' "$canon_stderr" >&2
fi
# Counter-check: the same token IS preserved when a durable source carries it,
# so the guard discriminates provenance rather than blanket-stripping a name.
printf 'root=UUID=11111111-2222-3333-4444-555555555555 ro noid.durable=yes enforcing=0\n' \
    > "$CANON_ROOT/etc/kernel/cmdline"
printf 'options root=UUID=11111111-2222-3333-4444-555555555555 ro noid.durable=yes enforcing=0\n' \
    > "$CANON_ROOT/boot/loader/entries/test.conf"
if env NOID_TEST_MODE=1 NOID_TEST_ROOT="$CANON_ROOT" \
       NOID_TEST_CMDLINE_FILE="$CANON_ROOT/proc/cmdline" \
       NOID_TEST_CPUINFO_FILE="$CANON_ROOT/proc/cpuinfo" \
       NOID_TEST_LSPCI_BIN="$CANON_ROOT/nonexistent-lspci" \
       bash "$CANONICALIZER_FIXTURE" --publish >/dev/null 2>&1; then
    grep -qw 'enforcing=0' "$CANON_ROOT/etc/kernel/cmdline" \
        && _pass "a durably configured argument is still preserved" \
        || _fail "canonicalizer stripped an argument its durable source carries"
else
    _fail "canonicalizer failed on the durable counter-check"
fi
unset canon_published canon_stderr

assert_grep_fixed 'KERN_ERR/CRIT/ALERT/EMERG diagnostics' "$KS_FILE" \
    "halt-only early recovery retains actionable console errors"
assert_cmd_success "firstboot canonicalizer parses" bash -n "$CANONICALIZER_FIXTURE"
assert_cmd_success "firstboot lifecycle helper parses" bash -n "$FIRSTBOOT_FIXTURE"
assert_cmd_success "rootflags evidence handoff parses" bash -n "$ROOTFLAGS_REBIND_FIXTURE"
assert_cmd_success "post-install cmdline transition helper parses" \
    bash -n "$CMDLINE_TRANSITION_FIXTURE"
if command -v shellcheck >/dev/null 2>&1; then
    assert_cmd_success "firstboot canonicalizer passes ShellCheck" \
        shellcheck "$CANONICALIZER_FIXTURE"
    assert_cmd_success "firstboot lifecycle helper passes ShellCheck" \
        shellcheck "$FIRSTBOOT_FIXTURE"
    assert_cmd_success "rootflags evidence handoff passes ShellCheck" \
        shellcheck "$ROOTFLAGS_REBIND_FIXTURE"
    assert_cmd_success "post-install cmdline transition helper passes ShellCheck" \
        shellcheck "$CMDLINE_TRANSITION_FIXTURE"
fi
assert_grep_fixed '/usr/libexec/noid-canonicalize-kernel-cmdline --publish' \
    "$KS_FILE" "firstboot closes every durable cmdline surface before sealing"
assert_grep_fixed 'NOID_FIRSTBOOT_CMDLINE_REBOOT_REQUIRED_V2' "$KS_FILE" \
    "firstboot records active, desired and boot identity at the reboot boundary"
assert_not_grep 'systemctl.*reboot\|SYSTEMCTL_BIN.*reboot' "$FIRSTBOOT_FIXTURE" \
    "firstboot never forces a surprise pre-GDM reboot"
assert_not_grep 'exit 75' "$FIRSTBOOT_FIXTURE" \
    "pending firstboot activation is a successful prepared state"
assert_grep_fixed 'one user-controlled reboot is required before sealing' "$KS_FILE" \
    "firstboot publishes the pending activation state"
assert_grep_fixed 'active cmdline still differs after the requested reboot' \
    "$KS_FILE" "a persistent mismatch fails instead of reboot-looping"
assert_grep_fixed 'if [ "$active_pending" -eq 1 ]; then' "$KS_FILE" \
    "active/durable success seal remains withheld while reboot is pending"
assert_grep_fixed 'NOID_FIRSTBOOT_CMDLINE_V2' "$KS_FILE" \
    "success state binds the canonical active and durable hashes"
assert_grep_fixed 'target post-script is not the exact interactive kickstart tail' \
    "$KARG_PAYLOAD_VERIFIER" \
    "payload proof binds the target script to Anaconda's parsed kickstart"
assert_not_grep '/usr/share/anaconda/post-scripts/90-noid-kernel-cmdline.ks' \
    "$KARG_PAYLOAD_VERIFIER" \
    "payload verifier never trusts the inert detached post-scripts path"
assert_grep_fixed '/usr/libexec/noid-rebind-firstboot-rootflags --recover' \
    "$FIRSTBOOT_FIXTURE" \
    "firstboot invokes the bounded rootflags power-loss recovery"
assert_grep_fixed 'recovered one interrupted boot-policy publication' \
    "$ROOTFLAGS_REBIND_FIXTURE" \
    "M01 handoff has one bounded power-loss recovery rearm"
assert_grep_fixed 'noid.initramfs=generic-fallback)' "$FIRSTBOOT_FIXTURE" \
    "firstboot evidence normalizes the one transient M21 recovery marker"
assert_grep_fixed 'noid.initramfs=generic-fallback)' "$ROOTFLAGS_REBIND_FIXTURE" \
    "rootflags evidence handoff normalizes the one transient M21 recovery marker"
assert_grep_fixed 'repeats the Generic recovery marker' "$FIRSTBOOT_FIXTURE" \
    "firstboot rejects duplicate M21 recovery markers"
assert_grep_fixed 'repeats the Generic recovery marker' "$ROOTFLAGS_REBIND_FIXTURE" \
    "rootflags evidence handoff rejects duplicate M21 recovery markers"
assert_grep_fixed 'one exact firstboot command-line evidence object is required' \
    "$CMDLINE_TRANSITION_FIXTURE" \
    "post-install cmdline writers require one exclusive validated evidence object"
assert_grep_fixed "stat -c '%U:%G:%a' \"\$STATE_FILE\"" "$KS_FILE" \
    "firstboot validates exact success-evidence ownership and mode"
assert_not_grep 'ConditionPathExists=!/var/lib/noid-privacy/.firstboot-cmdline-done' \
    "$KS_FILE" "invalid firstboot evidence cannot bypass helper validation"
assert_grep_fixed "stat -c '%U:%G:%a' \"\$SENTINEL\"" "$RUNTIME_GATE" \
    "runtime gate binds exact firstboot evidence ownership and mode"
assert_grep_fixed '--remove-args="intel_iommu=on amd_iommu=on"' "$KS_FILE" \
    "firstboot fallback reconciles inherited CPU-vendor arguments"
assert_grep_fixed 'leaving service retryable' "$KS_FILE" \
    "failed grubby updates cannot commit the one-shot sentinel"
assert_grep_fixed 'Fedora repo config(s) remain unrestricted; leaving service retryable' \
    "$FIRSTBOOT_FIXTURE" \
    "firstboot cannot seal state with a degraded mirror-transport contract"
assert_grep_fixed 'durable kernel cmdline missing required argument' "$KS_FILE" \
    "firstboot sentinel follows a durable next-boot postcondition"
assert_grep_fixed 'Reconcile that second persistence' "$KS_FILE" \
    "firstboot reconciles legacy GRUB persistence too"
assert_grep_fixed 'durable kernel cmdline retains wrong-vendor argument' "$KS_FILE" \
    "firstboot rejects wrong-vendor kernel persistence before sentinel"
assert_grep_fixed '/etc/default/grub retains wrong-vendor argument' "$KS_FILE" \
    "firstboot rejects wrong-vendor GRUB persistence before sentinel"
assert_grep_fixed 'target LUKS unlock-retry arg: $LUKS_KARG' \
    "$TARGET_POST_FIXTURE" \
    "Anaconda target writer publishes LUKS retry policy before first boot"
assert_grep_fixed 'rd\.luks\.uuid=luks-' "$TARGET_POST_FIXTURE" \
    "target LUKS UUID is derived from target BLS state"
assert_grep_fixed 'pending firstboot delta exceeds the reviewed root-selector/framebuffer transition' \
    "$KARG_CONTRACT" \
    "runtime pending state permits no security-argument delta"
assert_grep_fixed 'active first-boot security arguments' "$KARG_CONTRACT" \
    "runtime gate proves every base and CPU security argument active"
assert_grep_fixed 'root-LUKS selector lacks one exact active policy' \
    "$KARG_CONTRACT" \
    "runtime gate proves the LUKS retry policy active"
assert_grep_fixed 'noid-status --json' "$RUNTIME_GATE" \
    "runtime gate binds the user-visible reboot state"
assert_grep_fixed "required_safe_re='^REQUIRED \\+ SAFE" "$RUNTIME_GATE" \
    "runtime gate accepts only the canonical two-axis required-safe status"
assert_not_grep 'REQUIRED (activate prepared boot-policy change)' \
    "$RUNTIME_GATE" \
    "runtime gate rejects the retired single-axis reboot wording"
assert_eq 3 "$(grep -cF 'restorecon -F /etc/default/grub' "$KS_FILE")" \
    "compose, target-install and late firstboot writers restore the GRUB label"
assert_eq 3 "$(grep -cF 'matchpathcon -V /etc/default/grub' "$KS_FILE")" \
    "every literal GRUB-label convergence is verified"
assert_grep_fixed 'restorecon -F "$path"' "$CANONICALIZER_FIXTURE" \
    "real-root atomic cmdline publication restores destination labels"
assert_grep_fixed 'matchpathcon -V "$path" >&2' "$CANONICALIZER_FIXTURE" \
    "real-root label diagnostics cannot contaminate canonical stdout"
assert_grep_fixed 'if [ -z "$ROOT" ]; then' "$CANONICALIZER_FIXTURE" \
    "SELinux relabeling is excluded from isolated alternate-root fixtures"

# Anaconda/grubby-style scrambled input must converge to one byte-identical
# source across /etc/kernel/cmdline and every normal BLS entry. The second run
# must make no byte change.
CMDLINE_ROOT="$TEST_TMPDIR/cmdline-root"
mkdir -p "$CMDLINE_ROOT/etc/default" "$CMDLINE_ROOT/etc/kernel" \
    "$CMDLINE_ROOT/boot/loader/entries" "$CMDLINE_ROOT/proc" \
    "$CMDLINE_ROOT/etc" "$CMDLINE_ROOT/var/lib/noid-privacy"
chmod 0755 "$CMDLINE_ROOT/var/lib/noid-privacy"
printf '%s\n' 'vendor_id : GenuineIntel' > "$CMDLINE_ROOT/proc/cpuinfo"
mkdir -p "$CMDLINE_ROOT/test-bin"
cat > "$CMDLINE_ROOT/test-bin/lspci-none" <<'EOF_LSPCI_NONE'
#!/bin/sh
printf '%s\n' '00:00.0 Host bridge: fixture'
EOF_LSPCI_NONE
chmod 0755 "$CMDLINE_ROOT/test-bin/lspci-none"
base_args=$(sed -n 's/^NOID_BASE_ARGS="\([^"]*\)"$/\1/p' \
    "$CANONICALIZER_FIXTURE")
intel_args='intel_iommu=on tsx=off l1tf=full l1d_flush=on kvm-intel.vmentry_l1d_flush=always'
read -r -a managed_tokens <<< "$base_args $intel_args"
scrambled_managed=$(printf '%s\n' "${managed_tokens[@]}" | tac | paste -sd' ' -)
luks_uuid=11111111-2222-4333-8444-555555555555
scrambled="root=UUID=root-fixture ro quiet $scrambled_managed amd_iommu=on acpi_backlight=native spectre_v2_user=auto rd.luks.uuid=luks-$luks_uuid \$tuned_params"
printf '%s\n' "$scrambled" > "$CMDLINE_ROOT/etc/kernel/cmdline"
printf 'GRUB_CMDLINE_LINUX="%s"\nGRUB_DISABLE_OS_PROBER=true\n' \
    "${scrambled#root=UUID=root-fixture ro }" > "$CMDLINE_ROOT/etc/default/grub"
printf '%s\n' 'title NoID Privacy fixture' 'linux /vmlinuz-fixture' \
    "options $scrambled" > "$CMDLINE_ROOT/boot/loader/entries/fixture.conf"
printf '%s\n' "BOOT_IMAGE=/vmlinuz-fixture $scrambled" \
    > "$CMDLINE_ROOT/proc/cmdline"
printf '%s\n' 'UUID=root-fixture / btrfs subvol=root 0 0' \
    > "$CMDLINE_ROOT/etc/fstab"

assert_cmd_success "scrambled Anaconda cmdline converges" \
    env NOID_TEST_MODE=1 NOID_TEST_ROOT="$CMDLINE_ROOT" \
        NOID_TEST_CMDLINE_FILE="$CMDLINE_ROOT/proc/cmdline" \
        NOID_TEST_CPUINFO_FILE="$CMDLINE_ROOT/proc/cpuinfo" \
        NOID_TEST_LSPCI_BIN="$CMDLINE_ROOT/test-bin/lspci-none" \
        "$CANONICALIZER_FIXTURE" --publish
canonical=$(cat "$CMDLINE_ROOT/etc/kernel/cmdline")
canonical_managed=""
for arg in $canonical; do
    case "$arg" in
        rhgb|quiet|slab_nomerge|efi=disable_early_pci_dma|erst_disable|plymouth.use-simpledrm=*|init_on_alloc=*|init_on_free=*|pti=*|vsyscall=*|vdso32=*|debugfs=*|page_alloc.shuffle=*|randomize_kstack_offset=*|spec_store_bypass_disable=*|module.sig_enforce=*|iommu.strict=*|iommu.passthrough=*|lockdown=*|slab_debug=*|slub_debug=*|mitigations=*|proc_mem.force_override=*|hash_pointers=*|hardened_usercopy=*|kfence.sample_interval=*|kfence.deferrable=*|ia32_emulation=*|bdev_allow_write_mounted=*|rd.emergency=*|rd.shell=*|loglevel=*|systemd.ssh_auto=*|random.trust_cpu=*|random.trust_bootloader=*|intel_iommu=*|amd_iommu=*|tsx=*|l1tf=*|l1d_flush=*|kvm-intel.vmentry_l1d_flush=*|acpi_backlight=*|mem_sleep_default=*|audit=*|audit_backlog_limit=*|zswap.enabled=*|kvm.nx_huge_pages=*|mmio_stale_data=*|retbleed=*|gather_data_sampling=*|reg_file_data_sampling=*|indirect_target_selection=*|vmscape=*|efi_pstore.pstore_disable=*|spectre_v2=*|spectre_v2_user=*|spectre_bhi=*|mds=*|tsx_async_abort=*|srbds=*|spec_rstack_overflow=*|tsa=*)
            canonical_managed="${canonical_managed:+$canonical_managed }$arg" ;;
    esac
done
assert_eq "$base_args $intel_args" "$canonical_managed" \
    "scrambled managed tokens converge to exact manifest order"
assert_eq "$canonical" \
    "$(sed -n 's/^options //p' "$CMDLINE_ROOT/boot/loader/entries/fixture.conf" | sed 's/ \$tuned_params$//')" \
    "normal BLS semantic options equal the canonical kernel source"
assert_eq "$canonical \$tuned_params" \
    "$(sed -n 's/^options //p' "$CMDLINE_ROOT/boot/loader/entries/fixture.conf")" \
    "normal BLS adds exactly one trailing Fedora tuned transport macro"
assert_not_grep '[$]tuned_params' "$CMDLINE_ROOT/etc/kernel/cmdline" \
    "Fedora tuned transport macro never enters semantic kernel cmdline"
assert_not_grep '[$]tuned_params' "$CMDLINE_ROOT/etc/default/grub" \
    "Fedora tuned transport macro never enters GRUB semantic args"
assert_grep_fixed "rd.luks.options=${luks_uuid}=tries=0,discard" \
    "$CMDLINE_ROOT/etc/kernel/cmdline" \
    "canonical merger retains the per-root unlimited-retry LUKS policy"
assert_not_grep 'amd_iommu=on\|acpi_backlight=\|spectre_v2_user=' \
    "$CMDLINE_ROOT/etc/kernel/cmdline" \
    "wrong-vendor and retired managed families cannot survive convergence"
cmdline_hashes=$(sha256sum "$CMDLINE_ROOT/etc/kernel/cmdline" \
    "$CMDLINE_ROOT/etc/default/grub" \
    "$CMDLINE_ROOT/boot/loader/entries/fixture.conf")
assert_cmd_success "canonical cmdline second run is idempotent" \
    env NOID_TEST_MODE=1 NOID_TEST_ROOT="$CMDLINE_ROOT" \
        NOID_TEST_CMDLINE_FILE="$CMDLINE_ROOT/proc/cmdline" \
        NOID_TEST_CPUINFO_FILE="$CMDLINE_ROOT/proc/cpuinfo" \
        NOID_TEST_LSPCI_BIN="$CMDLINE_ROOT/test-bin/lspci-none" \
        "$CANONICALIZER_FIXTURE" --publish
assert_eq "$cmdline_hashes" \
    "$(sha256sum "$CMDLINE_ROOT/etc/kernel/cmdline" \
        "$CMDLINE_ROOT/etc/default/grub" \
        "$CMDLINE_ROOT/boot/loader/entries/fixture.conf")" \
    "canonical cmdline second run preserves every published byte"

# The exact Gaming receipt is the sole authority for the two compatibility
# values. Reject unsafe receipt metadata before mutation, publish the reviewed
# on-profile in canonical order, and converge byte-for-byte back to the
# hardened profile when the receipt is removed.
gaming_flag="$CMDLINE_ROOT/var/lib/noid-privacy/gaming-mode.enabled"
printf x > "$gaming_flag"
chmod 0644 "$gaming_flag"
assert_cmd_failure "canonicalizer rejects a non-empty Gaming receipt" \
    env NOID_TEST_MODE=1 NOID_TEST_ROOT="$CMDLINE_ROOT" \
        NOID_TEST_CMDLINE_FILE="$CMDLINE_ROOT/proc/cmdline" \
        NOID_TEST_CPUINFO_FILE="$CMDLINE_ROOT/proc/cpuinfo" \
        NOID_TEST_LSPCI_BIN="$CMDLINE_ROOT/test-bin/lspci-none" \
        "$CANONICALIZER_FIXTURE" --publish
assert_eq "$cmdline_hashes" \
    "$(sha256sum "$CMDLINE_ROOT/etc/kernel/cmdline" \
        "$CMDLINE_ROOT/etc/default/grub" \
        "$CMDLINE_ROOT/boot/loader/entries/fixture.conf")" \
    "unsafe Gaming receipt cannot mutate boot bytes"
: > "$gaming_flag"
assert_cmd_success "exact Gaming receipt selects the compatibility profile" \
    env NOID_TEST_MODE=1 NOID_TEST_ROOT="$CMDLINE_ROOT" \
        NOID_TEST_CMDLINE_FILE="$CMDLINE_ROOT/proc/cmdline" \
        NOID_TEST_CPUINFO_FILE="$CMDLINE_ROOT/proc/cpuinfo" \
        NOID_TEST_LSPCI_BIN="$CMDLINE_ROOT/test-bin/lspci-none" \
        "$CANONICALIZER_FIXTURE" --publish
assert_grep_fixed 'vdso32=1' "$CMDLINE_ROOT/etc/kernel/cmdline" \
    "Gaming receipt publishes vDSO32 compatibility"
assert_grep_fixed 'ia32_emulation=1' "$CMDLINE_ROOT/etc/kernel/cmdline" \
    "Gaming receipt publishes IA32 compatibility"
assert_not_grep 'vdso32=0\|ia32_emulation=0' \
    "$CMDLINE_ROOT/etc/kernel/cmdline" \
    "Gaming profile retains no contradictory hardened value"
rm -f -- "$gaming_flag"
assert_cmd_success "removed Gaming receipt restores the hardened profile" \
    env NOID_TEST_MODE=1 NOID_TEST_ROOT="$CMDLINE_ROOT" \
        NOID_TEST_CMDLINE_FILE="$CMDLINE_ROOT/proc/cmdline" \
        NOID_TEST_CPUINFO_FILE="$CMDLINE_ROOT/proc/cpuinfo" \
        NOID_TEST_LSPCI_BIN="$CMDLINE_ROOT/test-bin/lspci-none" \
        "$CANONICALIZER_FIXTURE" --publish
assert_eq "$canonical" "$(cat "$CMDLINE_ROOT/etc/kernel/cmdline")" \
    "Gaming receipt removal restores exact canonical hardened bytes"
assert_eq "$cmdline_hashes" \
    "$(sha256sum "$CMDLINE_ROOT/etc/kernel/cmdline" \
        "$CMDLINE_ROOT/etc/default/grub" \
        "$CMDLINE_ROOT/boot/loader/entries/fixture.conf")" \
    "Gaming profile round trip restores every boot byte"

# Reproduce the installed-host behavior of SELinux userspace: a successful
# `matchpathcon -V` emits one "verified" line per path. The firstboot caller
# captures canonicalizer stdout as a security-evidence value, so those
# diagnostics must remain observable on stderr without entering that value.
NOISY_CANONICALIZER="$TEST_TMPDIR/noid-canonicalize-kernel-cmdline-noisy"
SELINUX_NOISE_BIN="$TEST_TMPDIR/selinux-noise-bin"
SELINUX_NOISE_LOG="$TEST_TMPDIR/selinux-noise.stderr"
mkdir -p "$SELINUX_NOISE_BIN"
sed 's/if \[ -z "\$ROOT" \]; then/if true; then/g' \
    "$CANONICALIZER_FIXTURE" > "$NOISY_CANONICALIZER"
cat > "$SELINUX_NOISE_BIN/restorecon" <<'EOF_RESTORECON_NOISE'
#!/bin/sh
exit 0
EOF_RESTORECON_NOISE
cat > "$SELINUX_NOISE_BIN/matchpathcon" <<'EOF_MATCHPATHCON_NOISE'
#!/bin/sh
[ "$#" -eq 2 ] && [ "$1" = -V ] || exit 2
printf '%s verified.\n' "$2"
EOF_MATCHPATHCON_NOISE
chmod 0755 "$NOISY_CANONICALIZER" "$SELINUX_NOISE_BIN"/*
if noisy_stdout=$(env PATH="$SELINUX_NOISE_BIN:$PATH" \
        NOID_TEST_MODE=1 NOID_TEST_ROOT="$CMDLINE_ROOT" \
        NOID_TEST_CMDLINE_FILE="$CMDLINE_ROOT/proc/cmdline" \
        NOID_TEST_CPUINFO_FILE="$CMDLINE_ROOT/proc/cpuinfo" \
        NOID_TEST_LSPCI_BIN="$CMDLINE_ROOT/test-bin/lspci-none" \
        "$NOISY_CANONICALIZER" --publish 2>"$SELINUX_NOISE_LOG"); then
    _pass "canonicalizer accepts verbose successful SELinux verification"
else
    _fail "canonicalizer rejected verbose successful SELinux verification"
fi
assert_eq "$(cat "$CMDLINE_ROOT/etc/kernel/cmdline")" "$noisy_stdout" \
    "canonicalizer stdout contains exactly the canonical kernel line"
assert_eq 2 "$(grep -cF ' verified.' "$SELINUX_NOISE_LOG")" \
    "both SELinux label diagnostics remain visible on stderr"

# Exercise the opposite CPU-vendor branch deterministically. This proves the
# closed publication logic, not real AMD IOMMU hardware behavior; candidate
# evidence must state that runtime remains limited to the VM host's vendor.
printf '%s\n' 'vendor_id : AuthenticAMD' > "$CMDLINE_ROOT/proc/cpuinfo"
assert_cmd_success "AMD fixture converges from Intel target state" \
    env NOID_TEST_MODE=1 NOID_TEST_ROOT="$CMDLINE_ROOT" \
        NOID_TEST_CMDLINE_FILE="$CMDLINE_ROOT/proc/cmdline" \
        NOID_TEST_CPUINFO_FILE="$CMDLINE_ROOT/proc/cpuinfo" \
        NOID_TEST_LSPCI_BIN="$CMDLINE_ROOT/test-bin/lspci-none" \
        "$CANONICALIZER_FIXTURE" --publish
amd_canonical=$(cat "$CMDLINE_ROOT/etc/kernel/cmdline")
amd_managed=""
for arg in $amd_canonical; do
    case "$arg" in
        rhgb|quiet|slab_nomerge|efi=disable_early_pci_dma|erst_disable|plymouth.use-simpledrm=*|init_on_alloc=*|init_on_free=*|pti=*|vsyscall=*|vdso32=*|debugfs=*|page_alloc.shuffle=*|randomize_kstack_offset=*|spec_store_bypass_disable=*|module.sig_enforce=*|iommu.strict=*|iommu.passthrough=*|lockdown=*|slab_debug=*|slub_debug=*|mitigations=*|proc_mem.force_override=*|hash_pointers=*|hardened_usercopy=*|kfence.sample_interval=*|kfence.deferrable=*|ia32_emulation=*|bdev_allow_write_mounted=*|rd.emergency=*|rd.shell=*|loglevel=*|systemd.ssh_auto=*|random.trust_cpu=*|random.trust_bootloader=*|intel_iommu=*|amd_iommu=*|tsx=*|l1tf=*|l1d_flush=*|kvm-intel.vmentry_l1d_flush=*|acpi_backlight=*|mem_sleep_default=*|audit=*|audit_backlog_limit=*|zswap.enabled=*|kvm.nx_huge_pages=*|mmio_stale_data=*|retbleed=*|gather_data_sampling=*|reg_file_data_sampling=*|indirect_target_selection=*|vmscape=*|efi_pstore.pstore_disable=*|spectre_v2=*|spectre_v2_user=*|spectre_bhi=*|mds=*|tsx_async_abort=*|srbds=*|spec_rstack_overflow=*|tsa=*)
            amd_managed="${amd_managed:+$amd_managed }$arg" ;;
    esac
done
assert_eq "$base_args amd_iommu=on" "$amd_managed" \
    "AMD fixture publishes the exact base plus AMD contract"
assert_not_grep 'intel_iommu=on\|tsx=off\|l1tf=full\|l1d_flush=on\|kvm-intel.vmentry_l1d_flush=always' \
    "$CMDLINE_ROOT/etc/kernel/cmdline" \
    "AMD fixture removes every Intel-only argument"
assert_grep_fixed "rd.luks.options=${luks_uuid}=tries=0,discard" \
    "$CMDLINE_ROOT/etc/kernel/cmdline" \
    "AMD fixture retains the active LUKS policy"

# Reproduce the boot immediately after an interrupted M20 recovery: durable
# sources and fstab already use the Btrfs default, while the running kernel
# still carries the obsolete selector from this boot. The canonicalizer must
# not import that active-only topology token back into future-boot bytes.
selector_free=$(printf '%s\n' "$amd_canonical" | tr ' ' '\n' \
    | grep -vE '^rootflags=subvol=/?root$' | paste -sd' ' -)
printf '%s\n' "$selector_free" > "$CMDLINE_ROOT/etc/kernel/cmdline"
printf '%s\n' 'title NoID Privacy fixture' 'linux /vmlinuz-fixture' \
    "options $selector_free \$tuned_params" > "$CMDLINE_ROOT/boot/loader/entries/fixture.conf"
printf '%s\n' "BOOT_IMAGE=/vmlinuz-fixture $amd_canonical" \
    > "$CMDLINE_ROOT/proc/cmdline"
printf '%s\n' 'UUID=root-fixture / btrfs rw,compress=zstd:1 0 0' \
    > "$CMDLINE_ROOT/etc/fstab"
assert_cmd_success "canonicalizer preserves recovered selector-free durable topology" \
    env NOID_TEST_MODE=1 NOID_TEST_ROOT="$CMDLINE_ROOT" \
        NOID_TEST_CMDLINE_FILE="$CMDLINE_ROOT/proc/cmdline" \
        NOID_TEST_CPUINFO_FILE="$CMDLINE_ROOT/proc/cpuinfo" \
        NOID_TEST_LSPCI_BIN="$CMDLINE_ROOT/test-bin/lspci-none" \
        "$CANONICALIZER_FIXTURE" --publish
assert_eq "$selector_free" "$(cat "$CMDLINE_ROOT/etc/kernel/cmdline")" \
    "active-only root selector is not reintroduced into durable bytes"
assert_not_grep_extended 'rootflags=subvol=/?root' \
    "$CMDLINE_ROOT/boot/loader/entries/fixture.conf" \
    "normal BLS remains selector-free after recovery convergence"

# Reproduce Fedora 44's kernel-install/grub2-mkconfig regression after the
# system is already on the default-subvolume model: a stale durable selector
# must be removed from every future-boot source, while an unrelated root mount
# flag remains intact.
stale_durable=${amd_canonical/rootflags=subvol=root/rootflags=subvol=root,noatime}
printf '%s\n' "$stale_durable" > "$CMDLINE_ROOT/etc/kernel/cmdline"
printf '%s\n' 'title NoID Privacy fixture' 'linux /vmlinuz-fixture' \
    "options $stale_durable \$tuned_params" \
    > "$CMDLINE_ROOT/boot/loader/entries/fixture.conf"
printf '%s\n' "BOOT_IMAGE=/vmlinuz-fixture $stale_durable" \
    > "$CMDLINE_ROOT/proc/cmdline"
assert_cmd_success "stale durable root selector converges from selector-free fstab" \
    env NOID_TEST_MODE=1 NOID_TEST_ROOT="$CMDLINE_ROOT" \
        NOID_TEST_CMDLINE_FILE="$CMDLINE_ROOT/proc/cmdline" \
        NOID_TEST_CPUINFO_FILE="$CMDLINE_ROOT/proc/cpuinfo" \
        NOID_TEST_LSPCI_BIN="$CMDLINE_ROOT/test-bin/lspci-none" \
        "$CANONICALIZER_FIXTURE" --publish
assert_not_grep_extended 'rootflags=[^[:space:]]*(subvol|subvolid)=' \
    "$CMDLINE_ROOT/etc/kernel/cmdline" \
    "stale durable Btrfs root selector cannot survive fstab authority"
assert_grep_fixed 'rootflags=noatime' "$CMDLINE_ROOT/etc/kernel/cmdline" \
    "non-topology root flags survive selector reconciliation"
assert_eq "$(cat "$CMDLINE_ROOT/etc/kernel/cmdline") \$tuned_params" \
    "$(sed -n 's/^options //p' "$CMDLINE_ROOT/boot/loader/entries/fixture.conf")" \
    "stale-selector repair preserves exact kernel/BLS parity"

# A healthy post-install NVIDIA transaction opens the exact success seal before
# RPM scriptlets mutate BLS state. Upgrades from the affected legacy workflow
# recover only the observed NVIDIA blacklist plus obsolete root-selector delta.
TRANSITION_ROOT="$TEST_TMPDIR/transition-root"
mkdir -p "$TRANSITION_ROOT/etc/kernel" "$TRANSITION_ROOT/etc" \
    "$TRANSITION_ROOT/var/lib/noid-privacy" \
    "$TRANSITION_ROOT/.snapshots/.noid-state" \
    "$TRANSITION_ROOT/proc/sys/kernel/random"
transition_owner="$(id -un):$(id -gn)"
transition_boot_id=12345678-1234-4234-8234-123456789abc
printf '%s\n' "$transition_boot_id" \
    > "$TRANSITION_ROOT/proc/sys/kernel/random/boot_id"
transition_base='root=UUID=root-fixture ro quiet module.sig_enforce=1 plymouth.use-simpledrm=1'
transition_active='root=UUID=root-fixture ro rootflags=subvol=root quiet module.sig_enforce=1 plymouth.use-simpledrm=1'
transition_durable='root=UUID=root-fixture ro rd.driver.blacklist=nouveau,nova_core modprobe.blacklist=nouveau,nova_core quiet module.sig_enforce=1 plymouth.use-simpledrm=1'
transition_hash=$(printf '%s\n' "$transition_base" | sha256sum | awk '{print $1}')
write_transition_success() {
    printf 'NOID_FIRSTBOOT_CMDLINE_V2\ndesired_sha256=%s\nactive_sha256=%s\n' \
        "$transition_hash" "$transition_hash" \
        > "$TRANSITION_ROOT/var/lib/noid-privacy/.firstboot-cmdline-done"
    chmod 0644 "$TRANSITION_ROOT/var/lib/noid-privacy/.firstboot-cmdline-done"
}
printf '%s\n' 'UUID=root-fixture / btrfs rw,compress=zstd:1 0 0' \
    > "$TRANSITION_ROOT/etc/fstab"
printf '%s\n' 'MODEL=default-subvolume-v1' 'SNAPSHOTS_FSROOT=/snapshots' \
    'LIBVIRT_FSROOT=/libvirt' \
    > "$TRANSITION_ROOT/.snapshots/.noid-state/boot-model.ready"
chmod 0600 "$TRANSITION_ROOT/.snapshots/.noid-state/boot-model.ready"
printf '%s\n' "$transition_durable" > "$TRANSITION_ROOT/etc/kernel/cmdline"
printf 'BOOT_IMAGE=/vmlinuz-fixture %s\n' "$transition_active" \
    > "$TRANSITION_ROOT/proc-cmdline"
write_transition_success
transition_env=(
    NOID_TEST_MODE=1
    NOID_TEST_ROOT="$TRANSITION_ROOT"
    NOID_TEST_CMDLINE_FILE="$TRANSITION_ROOT/proc-cmdline"
    NOID_TEST_OWNER="$transition_owner"
    NOID_TEST_NVIDIA_PRESENT=1
)
assert_cmd_success "legacy NVIDIA/root-selector evidence recovers exactly" \
    env "${transition_env[@]}" "$CMDLINE_TRANSITION_FIXTURE" \
        --recover-legacy-nvidia-transition
assert_cmd_success "legacy recovery removes only the stale success seal" \
    test ! -e "$TRANSITION_ROOT/var/lib/noid-privacy/.firstboot-cmdline-done"

printf '%s\n' "$transition_base" > "$TRANSITION_ROOT/etc/kernel/cmdline"
printf 'BOOT_IMAGE=/vmlinuz-fixture %s\n' "$transition_base" \
    > "$TRANSITION_ROOT/proc-cmdline"
write_transition_success
assert_cmd_success "healthy NVIDIA install opens exact M01 evidence" \
    env "${transition_env[@]}" "$CMDLINE_TRANSITION_FIXTURE" \
        --invalidate-nvidia-install
assert_cmd_success "healthy invalidation commits the absent-seal state" \
    test ! -e "$TRANSITION_ROOT/var/lib/noid-privacy/.firstboot-cmdline-done"

write_transition_success
assert_cmd_success "reviewed hardening migration opens exact M01 evidence" \
    env "${transition_env[@]}" "$CMDLINE_TRANSITION_FIXTURE" \
        --invalidate-hardening-profile
assert_cmd_success "hardening invalidation commits the absent-seal state" \
    test ! -e "$TRANSITION_ROOT/var/lib/noid-privacy/.firstboot-cmdline-done"

# A user may reverse a reviewed hardening choice before reboot. The exact
# same-boot pending record may be replaced only by that hardening operation;
# unrelated NVIDIA transitions retain the stricter success-seal precondition.
transition_pending_durable="$transition_base ia32_emulation=1 vdso32=1"
transition_pending_active_hash=$(printf '%s\n' "$transition_base" \
    | sha256sum | awk '{print $1}')
transition_pending_durable_hash=$(printf '%s\n' "$transition_pending_durable" \
    | sha256sum | awk '{print $1}')
write_transition_pending() {
    local prepared_boot_id=${1:-$transition_boot_id}
    printf '%s\n' NOID_FIRSTBOOT_CMDLINE_REBOOT_REQUIRED_V2 \
        "active_sha256=$transition_pending_active_hash" \
        "desired_sha256=$transition_pending_durable_hash" \
        "prepared_boot_id=$prepared_boot_id" \
        'recovery_attempt=0' \
        > "$TRANSITION_ROOT/var/lib/noid-privacy/.firstboot-cmdline-reboot-required"
    chmod 0600 "$TRANSITION_ROOT/var/lib/noid-privacy/.firstboot-cmdline-reboot-required"
}
printf '%s\n' "$transition_pending_durable" \
    > "$TRANSITION_ROOT/etc/kernel/cmdline"
printf 'BOOT_IMAGE=/vmlinuz-fixture %s\n' "$transition_base" \
    > "$TRANSITION_ROOT/proc-cmdline"
write_transition_pending
assert_cmd_success "hardening profile can replace exact same-boot pending evidence" \
    env "${transition_env[@]}" "$CMDLINE_TRANSITION_FIXTURE" \
        --invalidate-hardening-profile
assert_cmd_success "pending hardening invalidation commits the absent-evidence state" \
    test ! -e "$TRANSITION_ROOT/var/lib/noid-privacy/.firstboot-cmdline-reboot-required"

write_transition_pending
assert_cmd_failure "NVIDIA transition cannot consume hardening pending evidence" \
    env "${transition_env[@]}" "$CMDLINE_TRANSITION_FIXTURE" \
        --invalidate-nvidia-install
assert_cmd_success "rejected NVIDIA invalidation preserves pending evidence" \
    test -f "$TRANSITION_ROOT/var/lib/noid-privacy/.firstboot-cmdline-reboot-required"
rm -f "$TRANSITION_ROOT/var/lib/noid-privacy/.firstboot-cmdline-reboot-required"

write_transition_pending 99999999-1234-4234-8234-123456789abc
assert_cmd_failure "hardening profile cannot consume another boot's pending evidence" \
    env "${transition_env[@]}" "$CMDLINE_TRANSITION_FIXTURE" \
        --invalidate-hardening-profile
assert_cmd_success "rejected cross-boot replacement preserves pending evidence" \
    test -f "$TRANSITION_ROOT/var/lib/noid-privacy/.firstboot-cmdline-reboot-required"
rm -f "$TRANSITION_ROOT/var/lib/noid-privacy/.firstboot-cmdline-reboot-required"

write_transition_pending
printf '%s\n' "$transition_pending_durable unreviewed.transition=1" \
    > "$TRANSITION_ROOT/etc/kernel/cmdline"
assert_cmd_failure "hardening profile cannot consume drifted pending evidence" \
    env "${transition_env[@]}" "$CMDLINE_TRANSITION_FIXTURE" \
        --invalidate-hardening-profile
assert_cmd_success "rejected drifted replacement preserves pending evidence" \
    test -f "$TRANSITION_ROOT/var/lib/noid-privacy/.firstboot-cmdline-reboot-required"
rm -f "$TRANSITION_ROOT/var/lib/noid-privacy/.firstboot-cmdline-reboot-required"

printf '%s\n' "$transition_base unreviewed.transition=1" \
    > "$TRANSITION_ROOT/etc/kernel/cmdline"
write_transition_success
assert_cmd_failure "unreviewed cmdline drift cannot be invalidated as NVIDIA" \
    env "${transition_env[@]}" "$CMDLINE_TRANSITION_FIXTURE" \
        --invalidate-nvidia-install
assert_cmd_success "rejected invalidation preserves the prior success evidence" \
    test -f "$TRANSITION_ROOT/var/lib/noid-privacy/.firstboot-cmdline-done"

# Prove the ordered M01 -> M20 handoff against the deployed helper. A valid
# M01 seal over the active Anaconda root selector becomes a V2 reboot record
# bound to the exact selector-free bytes before grubby publishes them.
REBIND_ROOT="$TEST_TMPDIR/rebind-root"
mkdir -p "$REBIND_ROOT/etc/kernel" "$REBIND_ROOT/var/lib/noid-privacy" \
    "$REBIND_ROOT/proc/sys/kernel/random"
rebind_boot_id=11111111-2222-4333-8444-555555555555
rebind_recovery_boot_id=66666666-7777-4888-8999-aaaaaaaaaaaa
rebind_pre='root=UUID=root-fixture ro rootflags=subvol=root rhgb module.sig_enforce=1 intel_iommu=on'
rebind_post='root=UUID=root-fixture ro rhgb module.sig_enforce=1 intel_iommu=on'
printf '%s\n' "$rebind_pre" > "$REBIND_ROOT/etc/kernel/cmdline"
printf 'UUID=root-fixture / btrfs rw,compress=zstd:1 0 0\n' \
    > "$REBIND_ROOT/etc/fstab"
printf 'BOOT_IMAGE=/vmlinuz-fixture %s\n' "$rebind_pre" \
    > "$REBIND_ROOT/proc/cmdline"
printf '%s\n' "$rebind_boot_id" \
    > "$REBIND_ROOT/proc/sys/kernel/random/boot_id"
rebind_pre_hash=$(printf '%s\n' "$rebind_pre" | sha256sum | awk '{print $1}')
rebind_post_hash=$(printf '%s\n' "$rebind_post" | sha256sum | awk '{print $1}')
printf 'NOID_FIRSTBOOT_CMDLINE_V2\ndesired_sha256=%s\nactive_sha256=%s\n' \
    "$rebind_pre_hash" "$rebind_pre_hash" \
    > "$REBIND_ROOT/var/lib/noid-privacy/.firstboot-cmdline-done"
chmod 0644 "$REBIND_ROOT/var/lib/noid-privacy/.firstboot-cmdline-done"
mkdir -p "$REBIND_ROOT/test-bin"
cat > "$REBIND_ROOT/test-bin/grubby" <<'REBIND_GRUBBY_EOF'
#!/bin/bash
set -euo pipefail
[[ $# -eq 2 && $1 == --update-kernel=ALL \
    && $2 == '--remove-args=rootflags=subvol=root rootflags=subvol=/root' ]]
input=${NOID_TEST_ROOT:?}/etc/kernel/cmdline
result=
for arg in $(cat "$input"); do
    case "$arg" in rootflags=subvol=root|rootflags=subvol=/root) continue ;; esac
    result="${result:+$result }$arg"
done
printf '%s\n' "$result" > "$input"
REBIND_GRUBBY_EOF
chmod 0755 "$REBIND_ROOT/test-bin/grubby"
rebind_owner="$(id -un):$(id -gn)"
rebind_env=(
    NOID_TEST_MODE=1
    NOID_TEST_ROOT="$REBIND_ROOT"
    NOID_TEST_CMDLINE_FILE="$REBIND_ROOT/proc/cmdline"
    NOID_TEST_BOOT_ID_FILE="$REBIND_ROOT/proc/sys/kernel/random/boot_id"
    NOID_TEST_OWNER="$rebind_owner"
    NOID_TEST_GRUBBY_BIN="$REBIND_ROOT/test-bin/grubby"
)
assert_cmd_success "M20 handoff prepares exact selector-free reboot evidence" \
    env "${rebind_env[@]}" "$ROOTFLAGS_REBIND_FIXTURE" --prepare
assert_cmd_success "M20 handoff removes the now-stale success seal" \
    test ! -e "$REBIND_ROOT/var/lib/noid-privacy/.firstboot-cmdline-done"
assert_eq \
    "NOID_FIRSTBOOT_CMDLINE_REBOOT_REQUIRED_V2
active_sha256=$rebind_pre_hash
desired_sha256=$rebind_post_hash
prepared_boot_id=$rebind_boot_id
recovery_attempt=0" \
    "$(cat "$REBIND_ROOT/var/lib/noid-privacy/.firstboot-cmdline-reboot-required")" \
    "M20 handoff binds active, desired and current boot identity"

# Simulate power loss after the marker is durable but before grubby writes.
# A different boot still has the exact old active/durable selector. Recovery
# must publish only the pre-authorized selector-free bytes and consume its one
# attempt before ordinary M20 idempotency/verification continues.
printf '%s\n' "$rebind_recovery_boot_id" \
    > "$REBIND_ROOT/proc/sys/kernel/random/boot_id"
assert_cmd_success "M01 handoff recovers marker-before-grubby interruption" \
    env "${rebind_env[@]}" "$ROOTFLAGS_REBIND_FIXTURE" --recover
assert_eq "$rebind_post" "$(cat "$REBIND_ROOT/etc/kernel/cmdline")" \
    "power-loss recovery publishes only the planned selector-free bytes"
assert_eq \
    "NOID_FIRSTBOOT_CMDLINE_REBOOT_REQUIRED_V2
active_sha256=$rebind_pre_hash
desired_sha256=$rebind_post_hash
prepared_boot_id=$rebind_recovery_boot_id
recovery_attempt=1" \
    "$(cat "$REBIND_ROOT/var/lib/noid-privacy/.firstboot-cmdline-reboot-required")" \
    "power-loss recovery rebinds active bytes and the new boot exactly once"
assert_cmd_success "M20 handoff accepts its recovered active-selector delta" \
    env "${rebind_env[@]}" "$ROOTFLAGS_REBIND_FIXTURE" --prepare
assert_cmd_success "M20 handoff verifies the published selector-free bytes" \
    env "${rebind_env[@]}" "$ROOTFLAGS_REBIND_FIXTURE" --verify

# Any pre-M20 delta beyond the explicitly non-security NVIDIA framebuffer
# token must fail before evidence is rebound.
printf '%s\n' "$rebind_pre" > "$REBIND_ROOT/etc/kernel/cmdline"
printf 'BOOT_IMAGE=/vmlinuz-fixture %s\n' \
    "${rebind_pre/module.sig_enforce=1/}" > "$REBIND_ROOT/proc/cmdline"
rm -f "$REBIND_ROOT/var/lib/noid-privacy/.firstboot-cmdline-reboot-required"
missing_security_active=$(sed 's/  */ /g;s/ $//' "$REBIND_ROOT/proc/cmdline")
missing_security_active=${missing_security_active#BOOT_IMAGE=/vmlinuz-fixture }
missing_security_hash=$(printf '%s\n' "$missing_security_active" | sha256sum | awk '{print $1}')
printf 'NOID_FIRSTBOOT_CMDLINE_REBOOT_REQUIRED_V2\nactive_sha256=%s\ndesired_sha256=%s\nprepared_boot_id=%s\nrecovery_attempt=0\n' \
    "$missing_security_hash" "$rebind_pre_hash" "$rebind_boot_id" \
    > "$REBIND_ROOT/var/lib/noid-privacy/.firstboot-cmdline-reboot-required"
chmod 0600 "$REBIND_ROOT/var/lib/noid-privacy/.firstboot-cmdline-reboot-required"
assert_cmd_failure "M20 handoff rejects a pending security argument" \
    env "${rebind_env[@]}" "$ROOTFLAGS_REBIND_FIXTURE" --prepare

# Portable chassis class is not sufficient evidence for either override.
assert_not_grep 'CHASSIS_EXTRA=' "$KS_FILE" \
    "M01 has no portable-chassis argument assignment"
assert_not_grep_extended 'grubby .*--args=.*(acpi_backlight|mem_sleep_default)' "$KS_FILE" \
    "M01 never adds the retired hardware workarounds"
assert_grep_fixed 'acpi_backlight=*|mem_sleep_default=*' "$KS_FILE" \
    "retired argument families remain in inherited-state cleanup"
assert_grep_fixed 'retains retired argument family' "$KS_FILE" \
    "firstboot rejects durable retired hardware overrides"

# HTTPS-only metalink filter (STEP 2b)
# Ensures both the Fedora metadata endpoint and selected mirrors use HTTPS.
assert_grep_fixed '&protocol=https' "$KS_FILE"
assert_grep_fixed 'STEP 2b: Authenticated mirror transport' "$KS_FILE" \
    "metalink HTTPS filter step marker is present"
assert_eq 2 "$(grep -cF 'url !~ /^https:\/\//' "$KS_FILE")" \
    "compose and firstboot reject non-HTTPS metalink endpoints"
assert_eq 2 "$(grep -cF 'if [ "$repos_inspected" -eq 0 ]; then' "$KS_FILE")" \
    "compose and firstboot reject an empty Fedora repository set"

METALINK_HELPER="$TEST_TMPDIR/metalink-compose-helper.sh"
METALINK_FIRSTBOOT_HELPER="$TEST_TMPDIR/metalink-firstboot-helper.sh"
METALINK_REPO="$TEST_TMPDIR/fedora-fixture.repo"
for pair in 1 2; do
    output=$METALINK_HELPER
    [ "$pair" -eq 1 ] || output=$METALINK_FIRSTBOOT_HELPER
    awk -v wanted="$pair" '
    /^repo_has_unrestricted_metalink\(\)/ {
        seen++
        if (seen == wanted) copy=1
    }
    copy { print }
    copy && /^restrict_repo_metalinks\(\)/ { in_restrict=1 }
    copy && in_restrict && /^}/ { exit }
' "$KS_FILE" > "$output"
done
assert_cmd_success "compose metalink helper fixture parses" bash -n "$METALINK_HELPER"
assert_cmd_success "firstboot metalink helper fixture parses" \
    bash -n "$METALINK_FIRSTBOOT_HELPER"
assert_cmd_success "compose and firstboot metalink helpers are byte-identical" \
    cmp -s "$METALINK_HELPER" "$METALINK_FIRSTBOOT_HELPER"
printf '%s\n' \
    '[fedora]' \
    'metalink=https://mirrors.example/metalink?repo=fedora' \
    '[updates]' \
    '  metalink = https://mirrors.example/metalink?repo=updates  # vendor spacing' \
    '[openh264]' \
    'metalink=https://mirrors.example/metalink?repo=openh264&protocol=https' \
    > "$METALINK_REPO"
assert_cmd_success "all supported metalink lines are converged" \
    bash -c '. "$1"; restrict_repo_metalinks "$2"' _ \
    "$METALINK_HELPER" "$METALINK_REPO"
assert_eq "3" "$(grep -cF '&protocol=https' "$METALINK_REPO")" \
    "missing protocol filters are added without duplicating an existing one"
assert_grep_fixed '  metalink = https://mirrors.example/metalink?repo=updates&protocol=https  # vendor spacing' \
    "$METALINK_REPO" "spacing and an inline comment survive convergence"
metalink_hash=$(sha256sum "$METALINK_REPO" | awk '{print $1}')
assert_cmd_success "metalink convergence is idempotent" \
    bash -c '. "$1"; restrict_repo_metalinks "$2"' _ \
    "$METALINK_HELPER" "$METALINK_REPO"
assert_eq "$metalink_hash" "$(sha256sum "$METALINK_REPO" | awk '{print $1}')" \
    "second metalink convergence leaves bytes unchanged"
printf '%s\n' '[fedora]' 'metalink = ${unsupported_vendor_expression}' \
    > "$METALINK_REPO"
assert_cmd_failure "unsupported metalink syntax fails visibly" \
    bash -c '. "$1"; restrict_repo_metalinks "$2"' _ \
    "$METALINK_HELPER" "$METALINK_REPO"
printf '%s\n' \
    '[fedora]' \
    'metalink=http://mirrors.example/metalink?repo=fedora&protocol=https' \
    > "$METALINK_REPO"
assert_cmd_failure "HTTP metadata endpoint fails despite HTTPS mirror filter" \
    bash -c '. "$1"; restrict_repo_metalinks "$2"' _ \
    "$METALINK_HELPER" "$METALINK_REPO"
mv "$METALINK_REPO" "$METALINK_REPO.real"
ln -s "$(basename "$METALINK_REPO.real")" "$METALINK_REPO"
assert_cmd_failure "symlinked Fedora repository config fails closed" \
    bash -c '. "$1"; restrict_repo_metalinks "$2"' _ \
    "$METALINK_HELPER" "$METALINK_REPO"
rm "$METALINK_REPO"
mv "$METALINK_REPO.real" "$METALINK_REPO"

# dnf.conf hardening
assert_grep_fixed "/etc/dnf/dnf.conf" "$KS_FILE"
assert_grep_fixed 'installonly_limit=3' "$KS_FILE"
assert_grep_fixed 'install_weak_deps=False' "$KS_FILE"
assert_grep_extended 'countme=False|countme=false|countme=0' "$KS_FILE"
assert_grep_fixed 'update-crypto-policies --check' "$KS_FILE" \
    "crypto-policy publication has a generated-state postcondition"
assert_grep_fixed 'FAIL: DEFAULT policy postcondition differs' "$KS_FILE" \
    "crypto-policy drift is fatal rather than advisory"
assert_grep_fixed 'UMask=0077' "$KS_FILE" \
    "firstboot service creates intermediate evidence with a restrictive umask"
assert_grep_fixed '/var/lib/noid-privacy/.firstboot-cmdline-reboot-required; do' \
    "$KS_FILE" "compose cleanup covers both success and pending reboot evidence"
assert_not_grep 'firstboot-cmdline-done 2>/dev/null || true' "$KS_FILE" \
    "compose state cleanup no longer swallows deletion failure"

# os-prober disabled
assert_grep_extended 'GRUB_DISABLE_OS_PROBER\s*=\s*true' "$KS_FILE"

# grub2-mkconfig target is the correct path (NOT EFI chainload-stub)
assert_grep_fixed '/boot/grub2/grub.cfg' "$KS_FILE"
assert_not_grep 'grub2-mkconfig -o /boot/efi/EFI/fedora/grub.cfg' "$KS_FILE"

# Regression guards for real-hardware install-path findings:
#   grub2-mkconfig in compose %post body breaks Anaconda's
#           gen_grub_cfgstub on real-hardware end-user install (BLS-default
#           on F34+; Anaconda owns target bootloader after %post)
#   grubby --update-kernel=ALL in compose %post freezes build-VM
#           /etc/kernel/cmdline state into squashfs (build-VM UUID + missing
#           29 KSPP base flags); end-user install propagates broken state
#           via kernel-install add. Both must be deferred to either runtime
#           CLI helpers (heredoc-embedded) or anaconda post-scripts (target
#           sysroot context).
# Strip heredocs from the .ks file, then grep for direct calls in the
# outer %post body. Heredoc-embedded calls remain allowed.
STRIPPED=$(awk '
    !in_heredoc && /<<-?[[:space:]]*'\''[A-Z_]+'\''/ {
        match($0, /<<-?[[:space:]]*'\''([A-Z_]+)'\''/, a)
        delim = a[1]
        in_heredoc = 1
        next
    }
    in_heredoc && $0 ~ "^"delim"$" { in_heredoc = 0; next }
    !in_heredoc { print }
' "$KS_FILE")

if [ -z "$STRIPPED" ]; then
    _fail "heredoc stripper produced an empty outer M01 body"
else
    _pass "heredoc stripper retains a non-empty outer M01 body"
fi
if echo "$STRIPPED" | grep -qE '^[[:space:]]*grub2-mkconfig[[:space:]]'; then
    _fail "grub2-mkconfig is called directly in the outer M01 %post body"
else
    _pass "outer M01 %post body contains no direct grub2-mkconfig call"
fi

if echo "$STRIPPED" | grep -qE '^[[:space:]]*grubby[[:space:]]+--update-kernel=ALL'; then
    _fail "grubby is called directly in the outer M01 %post body"
else
    _pass "outer M01 %post body contains no direct grubby mutation"
fi

# STEP 5b: GRUB password infrastructure (opt-in). Parse the actual deployed
# helper/doc and exercise the prompt/hash/atomic-publication behavior in a
# disposable tree with a pseudo-terminal.
GRUB_HELPER="$TEST_TMPDIR/noid-grub-password"
GRUB_DOC="$TEST_TMPDIR/01-grub-password.md"
extract_heredoc "$KS_FILE" "GRUBPW_EOF" "$GRUB_HELPER" || \
    _fail "GRUBPW_EOF extraction"
extract_heredoc "$KS_FILE" "GRUBDOC_EOF" "$GRUB_DOC" || \
    _fail "GRUBDOC_EOF extraction"
chmod 0755 "$GRUB_HELPER"
assert_cmd_success "GRUB password helper parses" bash -n "$GRUB_HELPER"
if command -v shellcheck >/dev/null 2>&1; then
    assert_cmd_success "GRUB password helper passes ShellCheck" \
        shellcheck -e SC2016 "$GRUB_HELPER"
fi
assert_grep_fixed "printf 'Enter new GRUB password: ' >/dev/tty" "$GRUB_HELPER" \
    "helper owns a visible first TTY prompt"
assert_grep_fixed "printf '\\nReenter new GRUB password: ' >/dev/tty" "$GRUB_HELPER" \
    "helper owns a visible confirmation prompt"
assert_not_grep_extended 'HASH_OUTPUT=\$\(grub2-mkpasswd-pbkdf2' "$GRUB_HELPER" \
    "tool-owned stdout prompts are not hidden in direct command substitution"
assert_grep_fixed 'mv -fT -- "$TMP_CFG" "$USER_CFG"' "$GRUB_HELPER" \
    "user.cfg publication is an atomic same-directory replacement"
assert_grep_fixed 'BOOT_LOCK=/run/lock/noid-boot-mutation.lock' "$GRUB_HELPER" \
    "GRUB credential writes join the shared boot lock"
assert_grep_fixed 'BOOT_GUARD=/usr/libexec/noid-boot-mutation-guard' "$GRUB_HELPER" \
    "GRUB credential writes require the M21 terminal-state guard"
assert_grep_fixed 'flock -w 300 9' "$GRUB_HELPER" \
    "GRUB credential mutation has a bounded lock wait"
assert_grep_fixed 'boot_basis=$($BOOT_GUARD)' "$GRUB_HELPER" \
    "GRUB helper evaluates the guarded hostonly/Generic basis"
assert_grep_fixed 'TMP_GRUB=$(mktemp "${GRUB_CFG}.tmp.XXXXXX")' "$GRUB_HELPER" \
    "grub.cfg is staged beside its final path"
assert_grep_fixed 'mv -fT -- "$TMP_GRUB" "$GRUB_CFG"' "$GRUB_HELPER" \
    "validated grub.cfg publication is atomic"
assert_grep_fixed "grep -cFx 'grub_arg --unrestricted'" "$GRUB_HELPER" \
    "helper verifies normal Fedora BLS selection remains unrestricted"
assert_grep_fixed 'sudo noid-grub-password --remove' "$GRUB_DOC" \
    "documented removal stays inside the guarded helper"
assert_not_grep_extended 'sudo rm /boot/grub2/user.cfg|sudo grub2-mkconfig' "$GRUB_DOC" \
    "GRUB password guide publishes no raw /boot mutation bypass"
assert_not_grep_extended '^[[:space:]]*sudo[[:space:]]+(grub2-mkconfig|grubby|dracut|kernel-install)' \
    "$REVERT_DOC" "aggregate revert guide contains no naked boot writer"
assert_grep_fixed 'No generic blanket command-line revert is shipped.' \
    "$REVERT_DOC" "aggregate revert guide states the real ownership boundary"
assert_grep_fixed 'can bypass the' "$REVERT_DOC" \
    "aggregate revert guide explains why raw regeneration is unsafe"
assert_not_grep_extended 'module\.sig_enforce=1.*evil-maid|evil-maid.*module\.sig_enforce=1' \
    "$GRUB_DOC" "module signature enforcement is not represented as /boot authentication"
assert_grep_fixed 'It does not authenticate `grub.cfg` or' "$GRUB_DOC" \
    "guide states the module-signing boundary"
assert_grep_fixed 'Enrolling a MOK adds a trusted signing key' "$GRUB_DOC" \
    "guide states that MOK enrollment expands the trust set"
assert_file_executable "$GRUB_PTY_FIXTURE" "GRUB prompt PTY fixture is executable"
assert_grep_fixed 'TERMINATE_GRACE_SECONDS = 2' "$GRUB_PTY_FIXTURE" \
    "GRUB prompt PTY fixture bounds its SIGTERM grace period"
assert_grep_fixed 'os.kill(pid, signal.SIGKILL)' "$GRUB_PTY_FIXTURE" \
    "GRUB prompt PTY fixture force-terminates an unresponsive child"

GRUB_FIXTURE="$TEST_TMPDIR/grub-fixture"
FAKE_BIN="$TEST_TMPDIR/fake-bin"
mkdir -p "$GRUB_FIXTURE/boot/grub2" "$GRUB_FIXTURE/boot/loader/entries" \
    "$GRUB_FIXTURE/etc/grub.d" "$GRUB_FIXTURE/run/lock" \
    "$GRUB_FIXTURE/usr/libexec" "$FAKE_BIN"
touch "$GRUB_FIXTURE/run/lock/noid-boot-mutation.lock"
cat > "$GRUB_FIXTURE/usr/libexec/noid-boot-mutation-guard" <<'EOF_BOOT_GUARD_FIXTURE'
#!/bin/sh
printf '%s\n' 'basis=hostonly'
EOF_BOOT_GUARD_FIXTURE
cat > "$GRUB_FIXTURE/etc/grub.d/01_users" <<'EOF_USERS_FIXTURE'
#!/bin/sh
printf '%s\n' 'set superusers="root"' \
    'password_pbkdf2 root ${GRUB2_PASSWORD}'
EOF_USERS_FIXTURE
cat > "$GRUB_FIXTURE/boot/loader/entries/candidate.conf" <<'EOF_BLS_FIXTURE'
title NoID Privacy fixture
options root=UUID=fixture ro
grub_users $grub_users
grub_arg --unrestricted
EOF_BLS_FIXTURE
cat > "$FAKE_BIN/grub2-mkpasswd-pbkdf2" <<'EOF_MKPASS_FIXTURE'
#!/bin/bash
IFS= read -r first
IFS= read -r second
[ -n "$first" ] && [ "$first" = "$second" ] || exit 9
printf '%s\n' 'Enter password: ' 'Reenter password: ' \
    'PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.AAAA.BBBB'
EOF_MKPASS_FIXTURE
cat > "$FAKE_BIN/grub2-mkconfig" <<'EOF_MKCONFIG_FIXTURE'
#!/bin/bash
[ "$1" = -o ] && [ "$#" -eq 2 ] || exit 8
printf '%s\n' 'set superusers="root"' \
    'password_pbkdf2 root ${GRUB2_PASSWORD}' > "$2"
EOF_MKCONFIG_FIXTURE
cat > "$FAKE_BIN/chown" <<'EOF_CHOWN_FIXTURE'
#!/bin/sh
exit 0
EOF_CHOWN_FIXTURE
cat > "$FAKE_BIN/restorecon" <<'EOF_RESTORECON_FIXTURE'
#!/bin/sh
exit 0
EOF_RESTORECON_FIXTURE
chmod 0755 "$GRUB_FIXTURE/etc/grub.d/01_users" \
    "$GRUB_FIXTURE/usr/libexec/noid-boot-mutation-guard" "$FAKE_BIN"/*

GRUB_HELPER_FIXTURE="$TEST_TMPDIR/noid-grub-password-fixture"
sed \
    -e 's/^if \[ "$(id -u)" != "0" \]; then$/if false; then/' \
    -e "s|^USER_CFG=.*|USER_CFG=$GRUB_FIXTURE/boot/grub2/user.cfg|" \
    -e "s|^GRUB_CFG=.*|GRUB_CFG=$GRUB_FIXTURE/boot/grub2/grub.cfg|" \
    -e "s|^USERS_SCRIPT=.*|USERS_SCRIPT=$GRUB_FIXTURE/etc/grub.d/01_users|" \
    -e "s|^BLS_DIR=.*|BLS_DIR=$GRUB_FIXTURE/boot/loader/entries|" \
    -e "s|^BOOT_LOCK=.*|BOOT_LOCK=$GRUB_FIXTURE/run/lock/noid-boot-mutation.lock|" \
    -e "s|^BOOT_GUARD=.*|BOOT_GUARD=$GRUB_FIXTURE/usr/libexec/noid-boot-mutation-guard|" \
    -e "s|sync -- /boot/grub2|sync -- $GRUB_FIXTURE/boot/grub2|g" \
    "$GRUB_HELPER" > "$GRUB_HELPER_FIXTURE"
chmod 0755 "$GRUB_HELPER_FIXTURE"

if prompt_output=$(env PATH="$FAKE_BIN:$PATH" \
        python3 "$GRUB_PTY_FIXTURE" "$GRUB_HELPER_FIXTURE" fixture-secret 2>&1); then
    _pass "pseudo-TTY prompt/hash fixture succeeds"
else
    _fail "pseudo-TTY prompt/hash fixture failed"
fi
assert_grep_fixed 'Enter new GRUB password:' <(printf '%s\n' "$prompt_output") \
    "first password prompt is observable"
assert_grep_fixed 'Reenter new GRUB password:' <(printf '%s\n' "$prompt_output") \
    "confirmation prompt is observable"
assert_grep_fixed 'GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.AAAA.BBBB' \
    "$GRUB_FIXTURE/boot/grub2/user.cfg" "only the exact parsed hash is published"
assert_eq 600 "$(stat -c %a "$GRUB_FIXTURE/boot/grub2/user.cfg")" \
    "published user.cfg mode is 600"
if compgen -G "$GRUB_FIXTURE/boot/grub2/user.cfg.tmp.*" >/dev/null; then
    _fail "successful publication left a temporary user.cfg"
else
    _pass "successful publication leaves no temporary user.cfg"
fi

printf '%s\n' 'ORIGINAL-CREDENTIAL' > "$GRUB_FIXTURE/boot/grub2/user.cfg"
original_credential_sha=$(sha256sum "$GRUB_FIXTURE/boot/grub2/user.cfg")
cat > "$FAKE_BIN/grub2-mkconfig" <<'EOF_MKCONFIG_FAIL_FIXTURE'
#!/bin/sh
exit 7
EOF_MKCONFIG_FAIL_FIXTURE
chmod 0755 "$FAKE_BIN/grub2-mkconfig"
if env PATH="$FAKE_BIN:$PATH" python3 "$GRUB_PTY_FIXTURE" \
        "$GRUB_HELPER_FIXTURE" replacement >/dev/null 2>&1; then
    _fail "helper accepted a failed grub2-mkconfig"
else
    _pass "failed grub2-mkconfig aborts publication"
fi
assert_eq "$original_credential_sha" \
    "$(sha256sum "$GRUB_FIXTURE/boot/grub2/user.cfg")" \
    "failed pre-publication validation preserves the prior credential bytes"

cat > "$GRUB_FIXTURE/usr/libexec/noid-boot-mutation-guard" <<'EOF_BOOT_GUARD_FAIL_FIXTURE'
#!/bin/sh
exit 1
EOF_BOOT_GUARD_FAIL_FIXTURE
original_credential_sha=$(sha256sum "$GRUB_FIXTURE/boot/grub2/user.cfg")
if env PATH="$FAKE_BIN:$PATH" bash "$GRUB_HELPER_FIXTURE" --remove \
        >/dev/null 2>&1; then
    _fail "GRUB removal bypassed a nonterminal M21 state"
else
    _pass "nonterminal M21 state blocks GRUB credential removal"
fi
assert_eq "$original_credential_sha" \
    "$(sha256sum "$GRUB_FIXTURE/boot/grub2/user.cfg")" \
    "guard rejection preserves the prior credential bytes"

cat > "$GRUB_FIXTURE/usr/libexec/noid-boot-mutation-guard" <<'EOF_BOOT_GUARD_RESTORE_FIXTURE'
#!/bin/sh
printf '%s\n' 'basis=generic'
EOF_BOOT_GUARD_RESTORE_FIXTURE
assert_cmd_success "guarded --remove path succeeds on a terminal Generic basis" \
    env PATH="$FAKE_BIN:$PATH" bash "$GRUB_HELPER_FIXTURE" --remove
if [ -e "$GRUB_FIXTURE/boot/grub2/user.cfg" ]; then
    _fail "guarded --remove left the credential file present"
else
    _pass "guarded --remove deletes only the credential file"
fi

# STEP 9 must retain both kernel-core System.map path shapes but make them
# root-only. Generated kmod RPMs use either file to select target-specific
# depmod; deleting both silently indexes the running kernel instead.
SYSMAP_HOOK="$TEST_TMPDIR/noid-protect-system-map"
SYSMAP_ROOT="$TEST_TMPDIR/system-map-root"
extract_heredoc "$KS_FILE" "SYSMAP_HOOK_EOF" "$SYSMAP_HOOK" || \
    _fail "SYSMAP_HOOK_EOF extraction"
assert_cmd_success "System.map hook parses" bash -n "$SYSMAP_HOOK"
assert_grep_fixed '"/boot/System.map-${KERNEL_VERSION}"' "$SYSMAP_HOOK" \
    "kernel hook owns the /boot symbol table"
assert_grep_fixed '"/usr/lib/modules/${KERNEL_VERSION}/System.map"' \
    "$SYSMAP_HOOK" "kernel hook owns the module-tree symbol table"
assert_grep_fixed 'install_time_system_maps=(/boot/System.map-* /usr/lib/modules/*/System.map)' \
    "$KS_FILE" "compose protection covers both install-time path shapes"
assert_not_grep 'rm -f -- /boot/System.map-' "$KS_FILE" \
    "compose never deletes package-native symbol tables"
assert_grep_fixed 'chmod 0600 -- "$system_map"' "$SYSMAP_HOOK" \
    "kernel hook makes each package-native symbol table root-only"

mkdir -p "$SYSMAP_ROOT/boot" \
    "$SYSMAP_ROOT/usr/lib/modules/7.1.5-200.fc44.x86_64"
printf 'boot symbols\n' > \
    "$SYSMAP_ROOT/boot/System.map-7.1.5-200.fc44.x86_64"
printf 'module symbols\n' > \
    "$SYSMAP_ROOT/usr/lib/modules/7.1.5-200.fc44.x86_64/System.map"
chmod 0644 \
    "$SYSMAP_ROOT/boot/System.map-7.1.5-200.fc44.x86_64" \
    "$SYSMAP_ROOT/usr/lib/modules/7.1.5-200.fc44.x86_64/System.map"
SYSMAP_FIXTURE="$TEST_TMPDIR/noid-protect-system-map-fixture"
sed \
    -e "s|/boot/System.map-|$SYSMAP_ROOT/boot/System.map-|g" \
    -e "s|/usr/lib/modules/|$SYSMAP_ROOT/usr/lib/modules/|g" \
    "$SYSMAP_HOOK" > "$SYSMAP_FIXTURE"
chmod 0755 "$SYSMAP_FIXTURE"
SYSMAP_BIN="$TEST_TMPDIR/system-map-bin"
mkdir -p "$SYSMAP_BIN"
cat > "$SYSMAP_BIN/chown" <<'EOF_SYSMAP_CHOWN'
#!/bin/sh
exit 0
EOF_SYSMAP_CHOWN
chmod 0755 "$SYSMAP_BIN/chown"
assert_cmd_success "kernel add protects both symbol-table copies" \
    env PATH="$SYSMAP_BIN:/usr/bin" \
        "$SYSMAP_FIXTURE" add 7.1.5-200.fc44.x86_64
for protected_map in \
    "$SYSMAP_ROOT/boot/System.map-7.1.5-200.fc44.x86_64" \
    "$SYSMAP_ROOT/usr/lib/modules/7.1.5-200.fc44.x86_64/System.map"; do
    assert_file_exists "$protected_map" \
        "kernel add retains package-native symbol table"
    assert_eq 600 "$(stat -c '%a' "$protected_map")" \
        "kernel add makes symbol table root-only"
done
printf 'escape sentinel\n' > "$SYSMAP_ROOT/escape"
assert_cmd_failure "kernel hook rejects a path-traversal version" \
    env PATH="$SYSMAP_BIN:/usr/bin" \
        "$SYSMAP_FIXTURE" add '../../escape'
assert_file_exists "$SYSMAP_ROOT/escape" \
    "invalid version cannot escape the kernel path boundary"

test_finish
