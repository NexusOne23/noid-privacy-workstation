#!/bin/bash
# 32-plymouth-theme — M32 Plymouth bgrt theme regression test
#
# Covers: M26 plymouth-plugin-label package add,
# M32 %post Plymouth theme install + activation, M21 sole transactional
# target-kernel Dracut ownership + candidate content validation, theme files
# present in branding/plymouth/ payload, M32's compose/runtime BLS ownership
# split, durable guarded identity-title queue, and 99-finalize checks.
# Would catch: plymouth-plugin-label missing from M26, plymouthd.conf not
# set to our theme, a competing M32 Dracut writer, or incomplete payload.

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
M26_FILE="$PROJECT_ROOT/kickstart/snippets/26-package-set.ks"
M32_FILE="$PROJECT_ROOT/kickstart/snippets/32-branding.ks"
M21_FILE="$PROJECT_ROOT/kickstart/snippets/21-kernel-module-blacklist.ks"
FINALIZE_FILE="$PROJECT_ROOT/kickstart/snippets/99-finalize.ks"
M25_FILE="$PROJECT_ROOT/kickstart/snippets/25-update-process.ks"
PLYMOUTH_DIR="$PROJECT_ROOT/branding/plymouth"

test_start "32-plymouth-theme"

assert_file_exists "$M26_FILE"
assert_file_exists "$M32_FILE"
assert_file_exists "$M21_FILE"
assert_file_exists "$FINALIZE_FILE"
assert_file_exists "$M25_FILE"

TMPDIR="$(mktemp -d)"
# /tmp is noexec on the hardened development host. The runtime helper now
# executes its validated guard directly, so keep that one behavioral fixture
# on the executable repository filesystem and remove it on every exit.
EXEC_FIXTURE_DIR="$(mktemp -d "$PROJECT_ROOT/.test-m32-fixture.XXXXXX")"
trap 'rm -rf "$TMPDIR" "$EXEC_FIXTURE_DIR"' EXIT
current_user=$(id -un)
current_group=$(id -gn)

# --- Payload files in branding/plymouth/ ------------------------------------
# Switched from a locally maintained script theme to Fedora's
# stock bgrt/two-step path. Custom .plymouth + .script files are absent
# from the payload; only the two managed watermark inputs remain (commit
# 70f863b). Only logo.png + logo-watermark-192.png remain — used by bgrt
# spinner watermark. See the stable spinner/watermark.png install in M32 STEP 4
# and the plymouth-set-default-theme bgrt assertions below.
assert_file_exists "$PLYMOUTH_DIR/logo.png"
assert_file_exists "$PLYMOUTH_DIR/logo-watermark-192.png"

# --- M26 package: plymouth-plugin-label (two-step text renderer) -------------
assert_grep_extended '^plymouth-plugin-label$' "$M26_FILE" \
    "M26: plymouth-plugin-label included (two-step LUKS-prompt text)"

# --- M32 bash syntax --------------------------------------------------------
assert_cmd_success "bash -n $M32_FILE" bash -n "$M32_FILE"
assert_grep_fixed 'STEP 8   Anaconda welcome dialog + installer icon rebrand (8a-8g)' \
    "$M32_FILE" "M32 ownership index includes runtime branding recovery"
assert_grep_fixed 'prior Module 32 health stamp is absent' "$M32_FILE" \
    "M32 retires historical branding success before payload mutation"
assert_grep_fixed 'verify_m32_health_content()' "$M32_FILE" \
    "M32 validates staged and final stamp content with one exact schema"
assert_grep_fixed 'STAMP_PUBLICATION_ACTIVE=1' "$M32_FILE" \
    "published M32 evidence remains removable through every final gate"
assert_grep_fixed '/usr/sbin/matchpathcon -V "$STAMP_SOURCE"' "$M32_FILE" \
    "M32 verifies the staged source SELinux context"
assert_grep_fixed '/usr/sbin/matchpathcon -V "$STAMP"' "$M32_FILE" \
    "M32 verifies the final stamp SELinux context"
assert_not_grep_fixed 'if [ -n "$BRANDING_SHASUMS" ]; then' "$M32_FILE" \
    "M32 mandatory manifest verification has no opt-in guard"
assert_not_grep_fixed 'if [ -z "$BRANDING_PAYLOAD" ]; then' "$M32_FILE" \
    "M32 mandatory transport has no vestigial fallback selector"

manifest_verified_line=$(grep -nF \
    'log "  [verify] exact manifest set + SHA-256 verified' \
    "$M32_FILE" | head -1 | cut -d: -f1 || true)
payload_accepted_line=$(grep -nF \
    'BRANDING_PAYLOAD="$BRANDING_FETCH_DIR"' \
    "$M32_FILE" | head -1 | cut -d: -f1 || true)
if [ -n "$manifest_verified_line" ] && [ -n "$payload_accepted_line" ] \
   && [ "$manifest_verified_line" -lt "$payload_accepted_line" ]; then
    _pass "M32 accepts the branding payload only after exact SHA-256 verification"
else
    _fail "M32 can accept the branding payload before exact SHA-256 verification"
fi

m32_invalidate_line=$(grep -nF \
    '# M32_HEALTH_INVALIDATION_BEGIN' "$M32_FILE" | cut -d: -f1 || true)
m32_first_payload_line=$(grep -nF \
    'publish_root_file /usr/lib/os-release 0644' \
    "$M32_FILE" | head -1 | cut -d: -f1 || true)
m32_guard_line=$(grep -nF \
    'if [ "$ver_fail" -gt 0 ]; then' \
    "$M32_FILE" | head -1 | cut -d: -f1 || true)
m32_publish_line=$(grep -nF \
    '# M32_HEALTH_PUBLICATION_BEGIN' "$M32_FILE" | cut -d: -f1 || true)
m32_complete_line=$(grep -nF \
    'log "=== Module 32 complete ==="' "$M32_FILE" | cut -d: -f1 || true)
if [ -n "$m32_invalidate_line" ] && [ -n "$m32_first_payload_line" ] \
   && [ -n "$m32_guard_line" ] && [ -n "$m32_publish_line" ] \
   && [ -n "$m32_complete_line" ] \
   && [ "$m32_invalidate_line" -lt "$m32_first_payload_line" ] \
   && [ "$m32_guard_line" -lt "$m32_publish_line" ] \
   && [ "$m32_publish_line" -lt "$m32_complete_line" ]; then
    _pass "M32 retires old health and publishes only after verification"
else
    _fail "M32 health-stamp ordering is not failure-atomic"
fi

# Run the exact M32 health-boundary blocks with an adapted copy of its actual
# root publisher. Only absolute roots, ownership expectations and SELinux
# command paths are changed for the rootless fixture.
m32_stamp_root="$EXEC_FIXTURE_DIR/health-stamp"
m32_stamp_state="$m32_stamp_root/state"
m32_stamp_bin="$m32_stamp_root/bin"
m32_stamp_invalidate="$m32_stamp_root/invalidate.sh"
m32_stamp_publish="$m32_stamp_root/publish.sh"
m32_stamp_uid=$(id -u)
m32_stamp_gid=$(id -g)
mkdir -p "$m32_stamp_bin"

cat > "$m32_stamp_bin/restorecon" <<'M32_STAMP_RESTORECON_EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${!#}"
case "${FAKE_RESTORECON_FAIL:-}" in
    all) exit 1 ;;
    final)
        case "$target" in
            */stamp-32-branding.ok) exit 1 ;;
        esac
        ;;
esac
exit 0
M32_STAMP_RESTORECON_EOF
cat > "$m32_stamp_bin/matchpathcon" <<'M32_STAMP_MATCHPATHCON_EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${!#}"
case "${FAKE_MATCHPATHCON_MODE:-}" in
    final-fail)
        case "$target" in
            */stamp-32-branding.ok) exit 1 ;;
        esac
        ;;
    final-term)
        case "$target" in
            */stamp-32-branding.ok)
                kill -TERM "$PPID"
                ;;
        esac
        ;;
esac
exit 0
M32_STAMP_MATCHPATHCON_EOF
cat > "$m32_stamp_bin/mv" <<'M32_STAMP_MV_EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${FAKE_MV_FAIL:-0}" -eq 1 ]; then
    exit 1
fi
exec /usr/bin/mv "$@"
M32_STAMP_MV_EOF
chmod 0700 "$m32_stamp_bin/restorecon" \
    "$m32_stamp_bin/matchpathcon" "$m32_stamp_bin/mv"

{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'log() { :; }' "STAMP_DIR=$m32_stamp_state" \
        'STAMP="$STAMP_DIR/stamp-32-branding.ok"'
    sed -n \
        '/^# M32_HEALTH_INVALIDATION_BEGIN$/,/^# M32_HEALTH_INVALIDATION_END$/p' \
        "$M32_FILE" |
        sed -e "s|/var/lib/noid-privacy|$m32_stamp_state|g" \
            -e "s|-o root -g root|-o $m32_stamp_uid -g $m32_stamp_gid|" \
            -e "s|0:0:755|$m32_stamp_uid:$m32_stamp_gid:755|" \
            -e "s|/usr/sbin/restorecon|$m32_stamp_bin/restorecon|g" \
            -e "s|/usr/sbin/matchpathcon|$m32_stamp_bin/matchpathcon|g"
} > "$m32_stamp_invalidate"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'log() { :; }' "STAMP_DIR=$m32_stamp_state" \
        'STAMP="$STAMP_DIR/stamp-32-branding.ok"' \
        'ver_ok=57' 'ver_fail=0'
    awk '
        /^publish_root_file\(\) \($/ { capture = 1 }
        capture { print }
        capture && /^\)$/ { exit }
    ' "$M32_FILE" |
        sed -e "s|/usr/sbin/restorecon|$m32_stamp_bin/restorecon|g" \
            -e "s|/usr/sbin/matchpathcon|$m32_stamp_bin/matchpathcon|g" \
            -e "s|chown root:root|chown $m32_stamp_uid:$m32_stamp_gid|g" \
            -e "s|0:0|$m32_stamp_uid:$m32_stamp_gid|g"
    sed -n \
        '/^# M32_HEALTH_PUBLICATION_BEGIN$/,/^# M32_HEALTH_PUBLICATION_END$/p' \
        "$M32_FILE" |
        sed -e "s|chown root:root|chown $m32_stamp_uid:$m32_stamp_gid|g" \
            -e "s|0:0:755|$m32_stamp_uid:$m32_stamp_gid:755|" \
            -e "s|0:0:644:1|$m32_stamp_uid:$m32_stamp_gid:644:1|" \
            -e "s|/usr/sbin/restorecon|$m32_stamp_bin/restorecon|g" \
            -e "s|/usr/sbin/matchpathcon|$m32_stamp_bin/matchpathcon|g"
} > "$m32_stamp_publish"
chmod 0700 "$m32_stamp_invalidate" "$m32_stamp_publish"

mkdir -m 0755 "$m32_stamp_state"
printf '%s\n' 'module=32' 'name=branding' 'status=ok' \
    > "$m32_stamp_state/stamp-32-branding.ok"
assert_cmd_success "M32 rerun invalidates its prior build-success stamp" \
    env PATH="$m32_stamp_bin:$PATH" "$m32_stamp_invalidate"
if [ ! -e "$m32_stamp_state/stamp-32-branding.ok" ]; then
    _pass "M32 old success evidence is absent before branding publication"
else
    _fail "M32 old success evidence is absent before branding publication"
fi

chmod 0777 "$m32_stamp_state"
printf '%s\n' 'must-survive' > "$m32_stamp_state/stamp-32-branding.ok"
assert_cmd_failure "M32 rejects shared state-directory metadata drift" \
    env PATH="$m32_stamp_bin:$PATH" "$m32_stamp_invalidate"
assert_eq "$m32_stamp_uid:$m32_stamp_gid:777" \
    "$(stat -c '%u:%g:%a' "$m32_stamp_state")" \
    "M32 does not normalize drifted shared-directory metadata"
assert_grep_fixed 'must-survive' \
    "$m32_stamp_state/stamp-32-branding.ok" \
    "M32 does not traverse a drifted shared state boundary"
rm "$m32_stamp_state/stamp-32-branding.ok"
chmod 0755 "$m32_stamp_state"

assert_cmd_failure "M32 rejects a staged-source label failure" \
    env PATH="$m32_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=all \
        "$m32_stamp_publish"
if [ ! -e "$m32_stamp_state/stamp-32-branding.ok" ] \
   && [ -z "$(find "$m32_stamp_state" -maxdepth 1 \
        -name '.stamp-32-branding.ok.*' -print -quit)" ]; then
    _pass "M32 source-label failure leaves no plausible health evidence"
else
    _fail "M32 source-label failure leaves no plausible health evidence"
fi

assert_cmd_failure "M32 retires a stamp after final-label failure" \
    env PATH="$m32_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=final \
        "$m32_stamp_publish"
if [ ! -e "$m32_stamp_state/stamp-32-branding.ok" ]; then
    _pass "M32 final-label failure removes the published success stamp"
else
    _fail "M32 final-label failure removes the published success stamp"
fi

assert_cmd_failure "M32 rejects a final SELinux verification failure" \
    env PATH="$m32_stamp_bin:$PATH" FAKE_MATCHPATHCON_MODE=final-fail \
        "$m32_stamp_publish"
if [ ! -e "$m32_stamp_state/stamp-32-branding.ok" ]; then
    _pass "M32 failed final SELinux verification retires the success stamp"
else
    _fail "M32 failed final SELinux verification retires the success stamp"
fi

assert_cmd_failure "M32 TERM after rename retires unconfirmed health evidence" \
    env PATH="$m32_stamp_bin:$PATH" FAKE_MATCHPATHCON_MODE=final-term \
        "$m32_stamp_publish"
if [ ! -e "$m32_stamp_state/stamp-32-branding.ok" ] \
   && [ -z "$(find "$m32_stamp_state" -maxdepth 1 \
        -name '.stamp-32-branding.ok.*' -print -quit)" ]; then
    _pass "M32 TERM cleanup leaves no plausible health evidence"
else
    _fail "M32 TERM cleanup leaves no plausible health evidence"
fi

assert_cmd_failure "M32 rejects an atomic health-stamp rename failure" \
    env PATH="$m32_stamp_bin:$PATH" FAKE_MV_FAIL=1 "$m32_stamp_publish"
if [ ! -e "$m32_stamp_state/stamp-32-branding.ok" ] \
   && [ -z "$(find "$m32_stamp_state" -maxdepth 1 \
        -name '.stamp-32-branding.ok.*' -print -quit)" ]; then
    _pass "M32 rename failure leaves no stamp or staged source"
else
    _fail "M32 rename failure leaves no stamp or staged source"
fi

if m32_stamp_output=$(env PATH="$m32_stamp_bin:$PATH" \
        "$m32_stamp_publish" 2>&1); then
    _pass "M32 publishes exact health evidence after all gates"
else
    _fail "M32 exact health publication failed: $m32_stamp_output"
fi
assert_grep_fixed 'module=32' "$m32_stamp_state/stamp-32-branding.ok"
assert_grep_fixed 'name=branding' "$m32_stamp_state/stamp-32-branding.ok"
assert_grep_fixed 'checks_passed=57' \
    "$m32_stamp_state/stamp-32-branding.ok"
assert_grep_fixed 'checks_total=57' \
    "$m32_stamp_state/stamp-32-branding.ok"
assert_eq 10 "$(wc -l < "$m32_stamp_state/stamp-32-branding.ok")" \
    "M32 published health stamp has the exact ten-line schema"

# Fedora 42+ intentionally unifies the local administrator command paths with
# /usr/local/sbin -> bin. Exercise that exact package-owned parent link while
# retaining fail-closed behavior for every other parent symlink.
m32_parent_root="$EXEC_FIXTURE_DIR/publication-parent"
m32_parent_script="$m32_parent_root/publish.sh"
mkdir -p "$m32_parent_root/usr/local/bin"
ln -s bin "$m32_parent_root/usr/local/sbin"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'log() { :; }'
    awk '
        /^publish_root_file\(\) \($/ { capture = 1 }
        capture { print }
        capture && /^\)$/ { exit }
    ' "$M32_FILE" |
        sed -e "s|/usr/sbin/restorecon|$m32_stamp_bin/restorecon|g" \
            -e "s|/usr/sbin/matchpathcon|$m32_stamp_bin/matchpathcon|g" \
            -e "s|chown root:root|chown $m32_stamp_uid:$m32_stamp_gid|g" \
            -e "s|0:0|$m32_stamp_uid:$m32_stamp_gid|g" \
            -e "s|/usr/local/sbin|$m32_parent_root/usr/local/sbin|g" \
            -e "s|/usr/local/bin|$m32_parent_root/usr/local/bin|g"
    printf '%s\n' \
        'printf "unified-sbin-parent\n" | publish_root_file "$1" 0644'
} >"$m32_parent_script"
chmod 0700 "$m32_parent_script"

assert_cmd_success "M32 accepts Fedora's exact unified local-sbin parent" \
    "$m32_parent_script" \
        "$m32_parent_root/usr/local/sbin/noid-publisher-fixture"
assert_grep_fixed 'unified-sbin-parent' \
    "$m32_parent_root/usr/local/bin/noid-publisher-fixture" \
    "M32 stages unified-sbin publications in the canonical directory"
assert_cmd_success "M32 unified-sbin path and canonical path share one file" \
    test "$m32_parent_root/usr/local/sbin/noid-publisher-fixture" -ef \
        "$m32_parent_root/usr/local/bin/noid-publisher-fixture"

rm -f "$m32_parent_root/usr/local/sbin"
mkdir "$m32_parent_root/usr/local/unexpected"
printf '%s\n' 'must-survive' \
    >"$m32_parent_root/usr/local/unexpected/noid-publisher-fixture"
ln -s unexpected "$m32_parent_root/usr/local/sbin"
assert_cmd_failure "M32 rejects an unexpected publication-parent symlink" \
    "$m32_parent_script" \
        "$m32_parent_root/usr/local/sbin/noid-publisher-fixture"
assert_grep_fixed 'must-survive' \
    "$m32_parent_root/usr/local/unexpected/noid-publisher-fixture" \
    "rejected parent symlink leaves its target untouched"

# --- M32: plymouth-set-default-theme called at build-time ------------------
# Uses Fedora's maintained bgrt theme (two-step + label plugin
# path) instead of carrying a local script-theme. The NoID Privacy mark is a
# separately managed watermark.
assert_grep_fixed 'plymouth-set-default-theme bgrt' "$M32_FILE" \
    "M32: plymouth-set-default-theme bgrt at build time"

# --- M32: plymouthd.conf written ---------------------------------------------
assert_grep_fixed '/etc/plymouth/plymouthd.conf' "$M32_FILE" \
    "M32: writes /etc/plymouth/plymouthd.conf"
assert_grep_fixed 'Theme=bgrt' "$M32_FILE" \
    "M32: plymouthd.conf Theme=bgrt"
assert_grep_fixed 'system-logo-white.png' "$M32_FILE" \
    "M32: NoID Privacy logo deployed as /usr/share/pixmaps/system-logo-white.png (GDM/Anaconda/About-dialog)"
# The path that bgrt actually reads:
assert_grep_fixed '/usr/share/plymouth/themes/spinner/watermark.png' "$M32_FILE" \
    "M32: NoID Privacy logo deployed as /usr/share/plymouth/themes/spinner/watermark.png (Plymouth two-step actually reads this)"
extract_heredoc "$M32_FILE" "PLYMOUTHD_EOF" "$TMPDIR/plymouthd.conf" \
    || _fail "M32 plymouthd.conf extraction"
assert_not_grep '^UseSimpledrmNoLuks=' "$TMPDIR/plymouthd.conf" \
    "M32: no local no-LUKS renderer-policy override"
assert_not_grep 'WatermarkVerticalAlignment=\\\.96' "$M32_FILE" \
    "M32 never keys convergence to one Fedora default value"
assert_not_grep 'VerticalAlignment=\\\.7' "$M32_FILE" \
    "M32 spinner convergence is independent of upstream default values"
assert_grep_fixed "-e 's|^WatermarkVerticalAlignment=.*$|WatermarkVerticalAlignment=.73|'" \
    "$M32_FILE" "M32 compose/runtime paths converge the guarded watermark key"
assert_grep_fixed 'publish_root_file "$BGRT_PLY" 0644' \
    "$M32_FILE" "M32 compose path publishes bgrt atomically"
assert_grep_fixed 'STEP 4: bgrt.plymouth key shape drifted; refusing ambiguous layout rewrite' \
    "$M32_FILE" "M32 compose path fails loud on ambiguous key shape"

# --- Package-update branding recovery --------------------------------------
assert_grep_fixed \
    'post_transaction:fedora-release*:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-restore-identity\ >/dev/null' \
    "$M32_FILE" "M32 identity action is host-scoped"
extract_heredoc "$M32_FILE" "RESTORE_BRAND_EOF" \
    "$TMPDIR/noid-restore-branding" || _fail "M32 branding helper extraction"
assert_cmd_success "M32 branding recovery helper parses" \
    bash -n "$TMPDIR/noid-restore-branding"
assert_cmd_failure "M32 branding helper rejects an unknown argument" \
    bash "$TMPDIR/noid-restore-branding" --unexpected
assert_cmd_failure "M32 branding helper rejects surplus arguments" \
    bash "$TMPDIR/noid-restore-branding" alpha beta
assert_cmd_success "M32 branding recovery helper passes ShellCheck" \
    shellcheck -S warning "$TMPDIR/noid-restore-branding"
assert_grep_fixed 'local src=$1 dst=$2 cache_class=${3:-plain}' \
    "$TMPDIR/noid-restore-branding" \
    "branding copy separates cache invalidation from command status"
assert_not_grep 'copy_if_differs .*||' "$TMPDIR/noid-restore-branding" \
    "branding copy calls never run in an errexit-suppressing OR list"
for package in 'generic-logos*' plymouth-theme-spinner; do
    assert_grep_fixed \
        "post_transaction:${package}:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-restore-branding\\ >/dev/null" \
        "$M32_FILE" "M32 branding action covers ${package}"
done

brand_root="$TMPDIR/branding-root"
mkdir -p \
    "$brand_root/proc" \
    "$brand_root/usr/share/noid-privacy/branding" \
    "$brand_root/usr/share/icons/hicolor"/{16x16,24x24,32x32,48x48,64x64,96x96,128x128,256x256,512x512}/apps \
    "$brand_root/usr/share/icons/hicolor/scalable/apps" \
    "$brand_root/usr/share/icons/oxygen/48x48/apps" \
    "$brand_root/usr/share/pixmaps" \
    "$brand_root/usr/share/anaconda/pixmaps" \
    "$brand_root/usr/share/plymouth/themes"/{bgrt,spinner}
printf 'fixture cmdline\n' > "$brand_root/proc/cmdline"
printf 'system-logo\n' > "$brand_root/usr/share/noid-privacy/branding/system-logo-white.png"
printf 'watermark\n' > "$brand_root/usr/share/noid-privacy/branding/watermark.png"
for size in 16 24 32 48 64 96 128 256 512; do
    printf 'noid-%s\n' "$size" \
        > "$brand_root/usr/share/icons/hicolor/${size}x${size}/apps/noid-privacy-logo.png"
done
find "$brand_root/usr/share/noid-privacy/branding" \
    "$brand_root/usr/share/icons/hicolor" -type f -exec chmod 0644 {} +
for target in \
    "$brand_root/usr/share/pixmaps/system-logo-white.png" \
    "$brand_root/usr/share/pixmaps/fedora-logo.png" \
    "$brand_root/usr/share/pixmaps/fedora-logo-small.png" \
    "$brand_root/usr/share/icons/hicolor/48x48/apps/anaconda.png" \
    "$brand_root/usr/share/icons/oxygen/48x48/apps/anaconda.png" \
    "$brand_root/usr/share/anaconda/pixmaps/sidebar-logo.png" \
    "$brand_root/usr/share/anaconda/pixmaps/anaconda_header.png" \
    "$brand_root/usr/share/plymouth/themes/spinner/watermark.png"; do
    printf 'vendor-stock\n' > "$target"
done
for svg in fedora-logo-icon.svg fedora-logo-sprite.svg anaconda.svg; do
    printf 'vendor-svg\n' \
        > "$brand_root/usr/share/icons/hicolor/scalable/apps/$svg"
done
printf 'vendor-svg\n' > "$brand_root/usr/share/pixmaps/fedora-logo-sprite.svg"
cat > "$brand_root/usr/share/plymouth/themes/bgrt/bgrt.plymouth" <<'BGRT_FIXTURE_EOF'
[boot-up]
UseFirmwareBackground=true
WatermarkVerticalAlignment=.91
VerticalAlignment=.66
[shutdown]
UseFirmwareBackground=true
[reboot]
UseFirmwareBackground=true
BGRT_FIXTURE_EOF
chmod 0644 "$brand_root/usr/share/plymouth/themes/bgrt/bgrt.plymouth"

symlink_victim="$brand_root/system-logo-victim"
printf 'symlink-victim-must-not-change\n' >"$symlink_victim"
chmod 0644 "$symlink_victim"
rm -f "$brand_root/usr/share/pixmaps/system-logo-white.png"
ln -s "$symlink_victim" \
    "$brand_root/usr/share/pixmaps/system-logo-white.png"
hardlink_victim="$brand_root/fedora-logo-hardlink-victim"
printf 'hardlink-victim-must-not-change\n' >"$hardlink_victim"
chmod 0644 "$hardlink_victim"
rm -f "$brand_root/usr/share/pixmaps/fedora-logo.png"
ln "$hardlink_victim" "$brand_root/usr/share/pixmaps/fedora-logo.png"

brand_fixture="$EXEC_FIXTURE_DIR/noid-restore-branding.fixture"
mkdir -p "$TMPDIR/test-bin"
ln -s /bin/true "$TMPDIR/test-bin/logger"
sed \
    -e '/^\[ "$(id -u)" -eq 0 \] || fail "must run as root"$/c\: # fixture: root guard' \
    -e "s|/proc/cmdline|$brand_root/proc/cmdline|g" \
    -e "s|/usr/share/noid-privacy/branding|$brand_root/usr/share/noid-privacy/branding|g" \
    -e "s|/usr/share/icons/hicolor|$brand_root/usr/share/icons/hicolor|g" \
    -e "s|/usr/share/icons/oxygen|$brand_root/usr/share/icons/oxygen|g" \
    -e "s|/usr/share/pixmaps|$brand_root/usr/share/pixmaps|g" \
    -e "s|/usr/share/anaconda|$brand_root/usr/share/anaconda|g" \
    -e "s|/usr/share/plymouth|$brand_root/usr/share/plymouth|g" \
    -e "s#EXPECTED_OWNER=root:root#EXPECTED_OWNER=$current_user:$current_group#" \
    -e 's#RESTORECON=/usr/sbin/restorecon#RESTORECON=/bin/true#' \
    -e 's#MATCHPATHCON=/usr/sbin/matchpathcon#MATCHPATHCON=/bin/true#' \
    -e 's#CHCON=/usr/bin/chcon#CHCON=/bin/true#' \
    -e 's|if \[ "$icons_changed" -eq 1 \] && command -v gtk-update-icon-cache|if false \&\& command -v gtk-update-icon-cache|' \
    "$TMPDIR/noid-restore-branding" > "$brand_fixture"
chmod 0755 "$brand_fixture"

# A copy failure must remain a failure, not the old overloaded "changed"
# return code. Run against an isolated clone because the broken historical
# path continued into later branding mutations after swallowing this error.
failure_root="$TMPDIR/branding-failure-root"
cp -a "$brand_root" "$failure_root"
failure_fixture="$EXEC_FIXTURE_DIR/noid-restore-branding-failure.fixture"
sed "s|$brand_root|$failure_root|g" "$brand_fixture" >"$failure_fixture"
chmod 0755 "$failure_fixture"
mkdir -p "$EXEC_FIXTURE_DIR/fail-bin"
cat >"$EXEC_FIXTURE_DIR/fail-bin/install" <<'BRANDING_INSTALL_FAIL_EOF'
#!/bin/bash
printf 'invoked\n' >>"${NOID_BRANDING_INSTALL_LOG:?}"
exit 70
BRANDING_INSTALL_FAIL_EOF
chmod 0755 "$EXEC_FIXTURE_DIR/fail-bin/install"
assert_cmd_failure "branding helper exposes atomic copy failure" \
    env NOID_BRANDING_INSTALL_LOG="$TMPDIR/branding-install-failure.log" \
        PATH="$EXEC_FIXTURE_DIR/fail-bin:$TMPDIR/test-bin:$PATH" \
        "$failure_fixture"
assert_file_exists "$TMPDIR/branding-install-failure.log" \
    "branding failure fixture reaches the injected install command"
assert_grep_fixed 'vendor-stock' \
    "$failure_root/usr/share/pixmaps/fedora-logo-small.png" \
    "failed branding copy preserves the prior destination"

assert_cmd_success "branding helper restores a package-stomp fixture" \
    env PATH="$TMPDIR/test-bin:$PATH" "$brand_fixture"
assert_cmd_success "system logo restored from cache" cmp -s \
    "$brand_root/usr/share/noid-privacy/branding/system-logo-white.png" \
    "$brand_root/usr/share/pixmaps/system-logo-white.png"
assert_grep_fixed 'symlink-victim-must-not-change' "$symlink_victim" \
    "branding publication never follows an existing destination symlink"
assert_cmd_failure "symlink destination is replaced by a regular file" \
    test -L "$brand_root/usr/share/pixmaps/system-logo-white.png"
assert_eq 1 "$(stat -c %h \
    "$brand_root/usr/share/pixmaps/system-logo-white.png")" \
    "symlink destination is replaced by a standalone regular file"
assert_grep_fixed 'hardlink-victim-must-not-change' "$hardlink_victim" \
    "branding publication never overwrites a destination hardlink peer"
assert_eq 1 "$(stat -Lc %h "$brand_root/usr/share/pixmaps/fedora-logo.png")" \
    "hardlinked destination is replaced by a standalone regular file"
for mapping in \
    '256:/usr/share/pixmaps/fedora-logo.png' \
    '128:/usr/share/pixmaps/fedora-logo-small.png' \
    '48:/usr/share/icons/hicolor/48x48/apps/anaconda.png' \
    '48:/usr/share/icons/oxygen/48x48/apps/anaconda.png' \
    '128:/usr/share/anaconda/pixmaps/sidebar-logo.png' \
    '96:/usr/share/anaconda/pixmaps/anaconda_header.png'; do
    size=${mapping%%:*}
    target=${mapping#*:}
    assert_cmd_success "generic-logos target restored: $target" cmp -s \
        "$brand_root/usr/share/icons/hicolor/${size}x${size}/apps/noid-privacy-logo.png" \
        "$brand_root$target"
done
for svg in \
    /usr/share/icons/hicolor/scalable/apps/fedora-logo-icon.svg \
    /usr/share/icons/hicolor/scalable/apps/fedora-logo-sprite.svg \
    /usr/share/icons/hicolor/scalable/apps/anaconda.svg \
    /usr/share/pixmaps/fedora-logo-sprite.svg; do
    if [ ! -e "$brand_root$svg" ] && [ ! -L "$brand_root$svg" ]; then
        _pass "restored vendor SVG removed: $svg"
    else
        _fail "restored vendor SVG survives: $svg"
    fi
done
assert_eq 1 "$(grep -c '^WatermarkVerticalAlignment=.73$' \
    "$brand_root/usr/share/plymouth/themes/bgrt/bgrt.plymouth")" \
    "Plymouth watermark alignment converges from a new upstream value"
assert_eq 1 "$(grep -c '^VerticalAlignment=.82$' \
    "$brand_root/usr/share/plymouth/themes/bgrt/bgrt.plymouth")" \
    "Plymouth spinner alignment converges from a new upstream value"
assert_eq 3 "$(grep -c '^UseFirmwareBackground=false$' \
    "$brand_root/usr/share/plymouth/themes/bgrt/bgrt.plymouth")" \
    "every Plymouth firmware-background section converges"
assert_cmd_success "branding recovery is idempotent" \
    env PATH="$TMPDIR/test-bin:$PATH" "$brand_fixture"
sed -i '/^VerticalAlignment=/d' \
    "$brand_root/usr/share/plymouth/themes/bgrt/bgrt.plymouth"
assert_cmd_failure "Plymouth key drift fails visibly" \
    env PATH="$TMPDIR/test-bin:$PATH" "$brand_fixture"

# --- Sole target-kernel Dracut writer + Plymouth content proof --------------
assert_not_grep 'noid-plymouth-firstboot' "$M32_FILE" \
    "M32: retired competing firstboot writer and cleanup path are absent"
assert_not_grep_extended \
    '^[[:space:]]*(sudo[[:space:]]+)?(dracut|kernel-install)([[:space:]]|$)' \
    "$M32_FILE" \
    "M32: branding module never rewrites a target-kernel initramfs"
assert_grep_fixed 'noid-dracut-hostonly-firstboot.service' "$M21_FILE" \
    "M21: sole transactional firstboot Dracut service"
assert_grep_fixed 'grep -qx plymouth "$modules"' "$M21_FILE" \
    "M21: candidate requires the Plymouth Dracut module"
for artifact in \
    etc/plymouth/plymouthd.conf \
    usr/share/plymouth/themes/bgrt/bgrt.plymouth \
    usr/share/plymouth/themes/spinner/watermark.png; do
    assert_grep_fixed "$artifact" "$M21_FILE" \
        "M21: candidate validates Plymouth artifact $artifact"
done
assert_grep_fixed \
    "printf 'install_optional_items+=\" %s \"\\n' \"\$f\"" "$M32_FILE" \
    "M32 fontconfig snapshot tolerates later package removals"
assert_grep_fixed \
    "grep -q '^install_optional_items+=\" /etc/fonts/conf.d/[^ ]*\\.conf \"$'" \
    "$M32_FILE" \
    "M32 verifies that the generated fontconfig drop-in is nonempty"
assert_not_grep_fixed \
    "printf 'install_items+=\" %s \"" "$M32_FILE" \
    "M32 does not freeze conf.d symlinks as mandatory Dracut items"
assert_grep_fixed \
    'DARK_URI="file:///usr/share/backgrounds/noid-privacy/default-dark.png"' \
    "$M32_FILE" "M32 uses its mandatory verified dark wallpaper consistently"
assert_not_grep_fixed \
    'DARK_URI="file:///usr/share/backgrounds/noid-privacy/default.png"' \
    "$M32_FILE" "M32 carries no unreachable light-wallpaper fallback"

# --- 99-finalize: Module 32 plymouth checks ---------------------------------
# The bgrt-theme switch removed custom .plymouth/.script files
# from finalize cross-checks, followed by vestigial Plymouth
# theme-dir cleanup. M99 verify covers M32 trademark-notice.
assert_grep_fixed 'Theme=bgrt' "$FINALIZE_FILE" \
    "99-finalize: asserts plymouthd.conf Theme=bgrt"
assert_grep_fixed 'unexpected local UseSimpledrmNoLuks override' "$FINALIZE_FILE" \
    "99-finalize: rejects the retired no-LUKS renderer-policy override"
assert_grep_fixed 'retired competing Plymouth Dracut writer remains' "$FINALIZE_FILE" \
    "99-finalize: rejects a competing M32 firstboot Dracut writer"
assert_grep_fixed 'trademark-notice.md' "$FINALIZE_FILE" \
    "99-finalize: asserts M32 trademark-notice.md cross-check (Lesson #26)"

# --- M32 BLS title ownership: compose-atomic + runtime queued ---------------
extract_heredoc "$M32_FILE" "RESTORE_EOF" "$TMPDIR/noid-restore-identity" \
    || _fail "M32 identity helper extraction"
extract_heredoc "$M32_FILE" "IDENTITY_BLS_SERVICE_EOF" \
    "$TMPDIR/noid-identity-bls-refresh.service" \
    || _fail "M32 identity BLS service extraction"
extract_heredoc "$M32_FILE" "IDENTITY_BLS_PATH_EOF" \
    "$TMPDIR/noid-identity-bls-refresh.path" \
    || _fail "M32 identity BLS path extraction"
extract_heredoc "$M32_FILE" "IDENTITY_BLS_TMPFILES_EOF" \
    "$TMPDIR/noid-identity-bls-refresh.conf" \
    || _fail "M32 identity BLS tmpfiles extraction"
assert_cmd_success "M32 runtime identity helper parses" \
    bash -n "$TMPDIR/noid-restore-identity"
assert_cmd_failure "M32 identity helper rejects an unknown argument" \
    bash "$TMPDIR/noid-restore-identity" --unexpected
assert_cmd_failure "M32 identity helper rejects surplus arguments" \
    bash "$TMPDIR/noid-restore-identity" --bls-only unexpected
assert_cmd_success "M32 runtime identity helper passes ShellCheck" \
    shellcheck -S warning "$TMPDIR/noid-restore-identity"
assert_not_grep 'sed -i.*title Fedora Linux' "$M32_FILE" \
    "no compose or runtime BLS title update uses in-place publication"
assert_grep_fixed 'mv -fT -- "$bls_tmp" "$bls"' "$M32_FILE" \
    "compose-exclusive BLS title publication is atomic"
assert_grep_fixed 'queue_bls_refresh' "$TMPDIR/noid-restore-identity" \
    "fedora-release callback queues its BLS work"
assert_grep_fixed '"$SYSTEMCTL" start --no-block' "$TMPDIR/noid-restore-identity" \
    "package callback dispatches but never waits on the BLS service"
assert_grep_fixed 'exec 9>"$BOOT_LOCK"' "$TMPDIR/noid-restore-identity" \
    "runtime BLS writer takes the shared boot-mutation lock"
assert_grep_fixed 'basis_record=$("$GUARD"' \
    "$TMPDIR/noid-restore-identity" \
    "runtime BLS writer requires M21's terminal-basis guard"
assert_grep_fixed 'stat -c '\''%U:%G:%a'\'' "$GUARD")" = root:root:755' \
    "$TMPDIR/noid-restore-identity" \
    "runtime BLS writer executes only the canonical root-owned guard"
assert_grep_fixed 'mv -fT -- "$temporary" "$bls"' \
    "$TMPDIR/noid-restore-identity" \
    "runtime BLS entries publish by same-directory atomic rename"
assert_grep_fixed '[ "$(stat -Lc %h "$bls")" -eq 1 ]' \
    "$TMPDIR/noid-restore-identity" \
    "runtime BLS writer rejects hardlinked entries"
assert_grep_fixed 'publish_root_file /usr/lib/os-release 0644' \
    "$TMPDIR/noid-restore-identity" \
    "runtime identity repair publishes vendor os-release atomically"
assert_grep_fixed 'publish_relative_symlink /etc/os-release ../usr/lib/os-release' \
    "$TMPDIR/noid-restore-identity" \
    "runtime identity repair enforces the canonical relative os-release link"
assert_grep_fixed 'rm -f -- "$PENDING"' "$TMPDIR/noid-restore-identity" \
    "durable request retires only after every BLS entry converges"
assert_not_grep_fixed 'if [ -x "$RESTORECON" ]; then' \
    "$TMPDIR/noid-restore-identity" \
    "identity queue and BLS publications cannot skip SELinux verification"
assert_eq 'f /run/lock/noid-identity-bls-refresh.lock 0600 root root -' \
    "$(cat "$TMPDIR/noid-identity-bls-refresh.conf")" \
    "queue handoff lock is recreated on every boot"
assert_not_grep_fixed 'Requires=noid-dracut-hostonly-firstboot.service' \
    "$TMPDIR/noid-identity-bls-refresh.service" \
    "identity service does not pull M21 Dracut onto the login target path"
assert_grep_fixed 'After=local-fs.target systemd-tmpfiles-setup.service noid-dracut-hostonly-firstboot.service' \
    "$TMPDIR/noid-identity-bls-refresh.service" \
    "identity service retains non-pulling ordering after M21 when co-scheduled"
assert_not_grep_fixed 'Before=multi-user.target' \
    "$TMPDIR/noid-identity-bls-refresh.service" \
    "identity service carries no redundant explicit target ordering"
assert_grep_fixed 'ConditionKernelCommandLine=!rd.live.image' \
    "$TMPDIR/noid-identity-bls-refresh.service" \
    "identity service cannot mutate the Live ISO"
assert_grep_fixed 'SuccessExitStatus=75' \
    "$TMPDIR/noid-identity-bls-refresh.service" \
    "nonterminal firstboot state is a durable defer, not false success"
assert_grep_fixed 'ReadWritePaths=/boot /var/lib/noid-privacy /run/lock/noid-identity-bls-refresh.lock /run/lock/noid-boot-mutation.lock' \
    "$TMPDIR/noid-identity-bls-refresh.service" \
    "strict identity service can write the shared boot-lock inode"
assert_not_grep '^ProtectKernelModules=yes$' \
    "$TMPDIR/noid-identity-bls-refresh.service" \
    "identity service does not hide module evidence required by the M21 guard"
assert_grep_fixed 'ProtectKernelModules=no' \
    "$TMPDIR/noid-identity-bls-refresh.service" \
    "identity service keeps exact target-module bytes readable"
assert_grep_fixed 'CapabilityBoundingSet=~CAP_SYS_MODULE' \
    "$TMPDIR/noid-identity-bls-refresh.service" \
    "identity service cannot acquire the module-management capability"
assert_grep_fixed 'SystemCallFilter=~@module' \
    "$TMPDIR/noid-identity-bls-refresh.service" \
    "identity service blocks every systemd module-management syscall"
assert_grep_fixed 'SystemCallErrorNumber=EPERM' \
    "$TMPDIR/noid-identity-bls-refresh.service" \
    "blocked module syscalls fail closed with EPERM"
assert_grep_fixed 'PathChanged=/var/lib/noid-privacy/identity-bls-refresh.pending' \
    "$TMPDIR/noid-identity-bls-refresh.path" \
    "a request arriving at service handoff is retriggered"

mkdir -p "$TMPDIR/systemd-verify"
sed -e 's#^ExecStart=.*#ExecStart=/bin/true#' \
    "$TMPDIR/noid-identity-bls-refresh.service" \
    > "$TMPDIR/systemd-verify/noid-identity-bls-refresh.service"
cp "$TMPDIR/noid-identity-bls-refresh.path" \
    "$TMPDIR/systemd-verify/noid-identity-bls-refresh.path"
cat > "$TMPDIR/systemd-verify/noid-dracut-hostonly-firstboot.service" <<'VERIFY_M21_EOF'
[Unit]
Description=M21 verification dependency stub

[Service]
Type=oneshot
ExecStart=/bin/true
VERIFY_M21_EOF
if unit_verify_output=$(systemd-analyze verify \
        "$TMPDIR/systemd-verify/noid-identity-bls-refresh.service" \
        "$TMPDIR/systemd-verify/noid-identity-bls-refresh.path" \
        "$TMPDIR/systemd-verify/noid-dracut-hostonly-firstboot.service" \
        2>&1); then
    _pass "M32 identity BLS service/path units validate"
else
    _fail "M32 identity BLS service/path units validate: $unit_verify_output"
fi

bls_release_line=$(grep -nF 'flock -u 7' "$M25_FILE" | head -1 | cut -d: -f1)
identity_start_line=$(grep -nF 'systemctl start noid-identity-bls-refresh.service' \
    "$M25_FILE" | head -1 | cut -d: -f1)
nvidia_queue_line=$(grep -nF 'queued_marker=$(sudo /usr/libexec/noid-nvidia-initramfs-queue' \
    "$M25_FILE" | head -1 | cut -d: -f1)
if [ -n "$bls_release_line" ] && [ -n "$identity_start_line" ] \
        && [ -n "$nvidia_queue_line" ] \
        && [ "$bls_release_line" -lt "$identity_start_line" ] \
        && [ "$identity_start_line" -lt "$nvidia_queue_line" ]; then
    _pass "M25 releases the boot lock, drains M32, then enters M19"
else
    _fail "M25/M32/M19 runtime lock ordering can deadlock or lose work"
fi

# Behavioral fixture: adapt only absolute roots, ownership expectations,
# external tools and the root/live guards. The exact queue schema, lock order,
# guard decision, BLS validation, atomic replacement and pending retirement run.
fixture="$TMPDIR/noid-restore-identity.fixture"
fixture_root="$EXEC_FIXTURE_DIR"
mkdir -p "$fixture_root/state" "$fixture_root/boot/loader/entries" \
    "$fixture_root/run" "$fixture_root/usr/lib" "$fixture_root/etc"
chmod 0755 "$fixture_root/state" "$fixture_root/usr" "$fixture_root/usr/lib" \
    "$fixture_root/etc"
: > "$fixture_root/cmdline"
sed \
    -e "s#STATE_DIR=/var/lib/noid-privacy#STATE_DIR=$fixture_root/state#" \
    -e "s#BOOT_LOCK=/run/lock/noid-boot-mutation.lock#BOOT_LOCK=$fixture_root/run/boot.lock#" \
    -e "s#QUEUE_LOCK=/run/lock/noid-identity-bls-refresh.lock#QUEUE_LOCK=$fixture_root/run/queue.lock#" \
    -e "s#BLS_DIR=/boot/loader/entries#BLS_DIR=$fixture_root/boot/loader/entries#" \
    -e "s#GUARD=/usr/libexec/noid-boot-mutation-guard#GUARD=$fixture_root/guard#" \
    -e 's#SYSTEMCTL=/usr/bin/systemctl#SYSTEMCTL=/bin/true#' \
    -e 's#RESTORECON=/usr/sbin/restorecon#RESTORECON=/bin/true#' \
    -e 's#MATCHPATHCON=/usr/sbin/matchpathcon#MATCHPATHCON=/bin/true#' \
    -e 's#CHCON=/usr/bin/chcon#CHCON=/bin/true#' \
    -e "s#EXPECTED_OWNER=root:root#EXPECTED_OWNER=$current_user:$current_group#" \
    -e 's#\.\./usr/lib/#@@FIXTURE_REL_USR_LIB@@/#g' \
    -e "s#/usr/lib/#$fixture_root/usr/lib/#g" \
    -e "s#/etc/#$fixture_root/etc/#g" \
    -e 's#@@FIXTURE_REL_USR_LIB@@/#../usr/lib/#g' \
    -e "s#/proc/cmdline#$fixture_root/cmdline#g" \
    -e "s#root:root:755#$current_user:$current_group:755#g" \
    -e "s#root:root:600:1#$current_user:$current_group:600:1#g" \
    -e "s#root:root:600#$current_user:$current_group:600#g" \
    -e "s#root:wheel:660#$current_user:$current_group:660#g" \
    -e "s#chown root:root#chown $current_user:$current_group#g" \
    -e 's#^\[ "$(id -u)" -eq 0 \] || fail "must run as root"$#:#' \
    -e 's#@@BRAND_NAME@@#NoID Privacy Workstation#g' \
    "$TMPDIR/noid-restore-identity" > "$fixture"
chmod 0755 "$fixture"
cat > "$fixture_root/guard" <<'GUARD_EOF'
#!/bin/bash
printf 'basis=hostonly\n'
GUARD_EOF
chmod 0755 "$fixture_root/guard"
install -m 0660 /dev/null "$fixture_root/run/boot.lock"
install -m 0600 /dev/null "$fixture_root/run/queue.lock"
cat > "$fixture_root/boot/loader/entries/kernel.conf" <<'BLS_EOF'
title Fedora Linux (6.12.0)
version 6.12.0
linux /vmlinuz-6.12.0
initrd /initramfs-6.12.0.img
options root=UUID=fixture ro
BLS_EOF
chmod 0640 "$fixture_root/boot/loader/entries/kernel.conf"
printf 'version=1\n' > "$fixture_root/state/identity-bls-refresh.pending"
chmod 0600 "$fixture_root/state/identity-bls-refresh.pending"
if fixture_output=$(bash "$fixture" --bls-only 2>&1); then
    _pass "guarded fixture converges a Fedora BLS title"
else
    _fail "guarded fixture converges a Fedora BLS title: $fixture_output"
fi
assert_grep_fixed 'title NoID Privacy Workstation (6.12.0)' \
    "$fixture_root/boot/loader/entries/kernel.conf" \
    "runtime BLS rewrite preserves the complete title suffix"
assert_eq 640 "$(stat -c %a "$fixture_root/boot/loader/entries/kernel.conf")" \
    "runtime BLS publication preserves file mode"
assert_cmd_failure "pending marker retires after complete convergence" \
    test -e "$fixture_root/state/identity-bls-refresh.pending"

sed -i 's/^title .*/title User Custom Kernel/' \
    "$fixture_root/boot/loader/entries/kernel.conf"
printf 'version=1\n' > "$fixture_root/state/identity-bls-refresh.pending"
chmod 0600 "$fixture_root/state/identity-bls-refresh.pending"
if fixture_output=$(bash "$fixture" --bls-only 2>&1); then
    _pass "custom BLS title is a converged no-op"
else
    _fail "custom BLS title is a converged no-op: $fixture_output"
fi
assert_grep_fixed 'title User Custom Kernel' \
    "$fixture_root/boot/loader/entries/kernel.conf" \
    "runtime identity repair preserves a user-customized title"

cat > "$fixture_root/guard" <<'GUARD_FAIL_EOF'
#!/bin/bash
exit 1
GUARD_FAIL_EOF
chmod 0755 "$fixture_root/guard"
printf 'version=1\n' > "$fixture_root/state/identity-bls-refresh.pending"
chmod 0600 "$fixture_root/state/identity-bls-refresh.pending"
set +e
bash "$fixture" --bls-only >/dev/null 2>&1
defer_rc=$?
set -e
assert_eq 75 "$defer_rc" "nonterminal M21 basis returns the durable defer status"
assert_file_exists "$fixture_root/state/identity-bls-refresh.pending" \
    "deferred M21 basis retains the durable BLS request"

cat > "$fixture_root/guard" <<'GUARD_EOF'
#!/bin/bash
printf 'basis=generic\n'
GUARD_EOF
chmod 0755 "$fixture_root/guard"
mv "$fixture_root/boot/loader/entries/kernel.conf" \
    "$fixture_root/boot/loader/entries/kernel.target"
ln -s kernel.target "$fixture_root/boot/loader/entries/kernel.conf"
assert_cmd_failure "symlink BLS entry fails closed" bash "$fixture" --bls-only
assert_file_exists "$fixture_root/state/identity-bls-refresh.pending" \
    "failed BLS validation retains the durable request"

rm -f "$fixture_root/boot/loader/entries/kernel.conf"
mv "$fixture_root/boot/loader/entries/kernel.target" \
    "$fixture_root/boot/loader/entries/kernel.conf"
ln "$fixture_root/boot/loader/entries/kernel.conf" \
    "$fixture_root/boot/loader/entries/kernel.peer"
assert_cmd_failure "hardlinked BLS entry fails closed" bash "$fixture" --bls-only
assert_file_exists "$fixture_root/state/identity-bls-refresh.pending" \
    "hardlink rejection retains the durable request"

identity_symlink_victim="$fixture_root/identity-symlink-victim"
printf 'identity-symlink-victim-must-not-change\n' >"$identity_symlink_victim"
chmod 0644 "$identity_symlink_victim"
ln -s "$identity_symlink_victim" "$fixture_root/usr/lib/os-release"
ln -s "$identity_symlink_victim" "$fixture_root/etc/os-release"
identity_hardlink_victim="$fixture_root/identity-hardlink-victim"
printf 'identity-hardlink-victim-must-not-change\n' >"$identity_hardlink_victim"
chmod 0644 "$identity_hardlink_victim"
ln "$identity_hardlink_victim" "$fixture_root/etc/system-release"
if fixture_output=$(bash "$fixture" 2>&1); then
    _pass "runtime identity helper atomically restores the complete identity set"
else
    _fail "runtime identity helper atomically restores the complete identity set: $fixture_output"
fi
assert_grep_fixed 'identity-symlink-victim-must-not-change' \
    "$identity_symlink_victim" \
    "identity publication never follows an existing vendor-file symlink"
assert_grep_fixed 'identity-hardlink-victim-must-not-change' \
    "$identity_hardlink_victim" \
    "identity publication never overwrites a hardlink peer"
assert_eq '../usr/lib/os-release' \
    "$(readlink "$fixture_root/etc/os-release")" \
    "runtime identity repair publishes the canonical os-release link text"
assert_eq '../usr/lib/issue' "$(readlink "$fixture_root/etc/issue")" \
    "runtime identity repair publishes the canonical issue link text"
assert_eq '../usr/lib/issue.net' "$(readlink "$fixture_root/etc/issue.net")" \
    "runtime identity repair publishes the canonical issue.net link text"
assert_grep_fixed 'NAME="NoID Privacy Workstation"' \
    "$fixture_root/usr/lib/os-release" \
    "runtime identity repair publishes the exact product NAME"
assert_eq 1 "$(stat -Lc %h "$fixture_root/usr/lib/os-release")" \
    "runtime vendor identity file has one link"
assert_eq 1 "$(stat -Lc %h "$fixture_root/etc/system-release")" \
    "runtime regular identity overlay has one link"

test_finish
