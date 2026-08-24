#!/bin/bash
# 16-firefox-structural — M16 regression test
#
# Covers: NoID Privacy Firefox Hardening v1.0 (post arkenfox absorption),
# uBO seed pinning + explicit-update validation, managed storage manifest,
# harden-profile CLI helper, M25 cross-reference.
# Would catch: regression to external arkenfox fetch, missing UBO pinning,
# wrong extension install path, managed storage in wrong dir, broken helper.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/16-firefox.ks"
MASTER_KS="$PROJECT_ROOT/kickstart/master.ks"
REVERT_DOC="$PROJECT_ROOT/docs/revert-uninstall.md"

test_start "16-firefox-structural"

assert_file_exists "$KS_FILE"
assert_cmd_success "bash -n $KS_FILE" bash -n "$KS_FILE"
assert_grep_fixed \
    '%packages --exclude-weakdeps --inst-langs=en:de:fr:es:es_AR:es_CL:es_ES:es_MX:it:pt:pt_BR:pt_PT:nl:pl:ru:zh:zh_CN:zh_TW:ja:ko:ar' \
    "$MASTER_KS" \
    "compose retains every regional Firefox payload behind es/pt/zh aliases"
assert_grep_fixed 'Firefox 152 review added explicit GMP/Widevine updater' \
    "$PROJECT_ROOT/firefox/noid-firefox-hardening.js" \
    "Firefox source header records the active 152 review adoption"
assert_grep_fixed 'Firefox 153 review added the Section 9003 ASRouter provider' \
    "$PROJECT_ROOT/firefox/noid-firefox-hardening.js" \
    "Firefox source header records the active 153 review adoption"
assert_grep_fixed 'Section 2811 above.' \
    "$PROJECT_ROOT/firefox/noid-firefox-hardening.js" \
    "sanitizer cross-reference names the surviving section"
assert_not_grep 'Section 2815 above.' \
    "$PROJECT_ROOT/firefox/noid-firefox-hardening.js" \
    "sanitizer source has no stale deleted-section reference"

# --- arkenfox absorption: NO arkenfox external fetch -----------------------
# Regression check: arkenfox SHA256 vars must be GONE (would indicate we
# reverted to external-fetch model).
if grep -qE '^ARKENFOX_COMMIT=' "$KS_FILE" || grep -qE '^ARKENFOX_SHA256_' "$KS_FILE"; then
    _fail "arkenfox external-fetch vars still present (absorption reverted?)"
else
    _pass "arkenfox external-fetch vars correctly removed (post-absorption)"
fi

# Regression: raw.githubusercontent.com/arkenfox fetch must NOT be active
if grep -qE '^[^#]*raw\.githubusercontent\.com/arkenfox' "$KS_FILE"; then
    _fail "active raw.githubusercontent.com/arkenfox/ fetch present"
else
    _pass "no active arkenfox GitHub fetch (post-absorption)"
fi

# --- NoID Privacy Firefox Hardening version string ---------------------------------
assert_grep_fixed 'NOID_FIREFOX_HARDENING_VERSION=' "$KS_FILE" "NoID Privacy hardening version var"
assert_grep_fixed 'arkenfox144' "$KS_FILE" "version string references arkenfox v144 origin"

# Fedora launcher Widevine relabel fix: the normal disabled/absent CDM path is
# silent, while restorecon errors for paths that actually exist remain visible.
assert_grep_fixed 'FIREFOX_LAUNCHER_SOURCE_SHA256=12e361bb42c030a9ffa940c641ff3ddf53ea097d40a7b2ea4903cd2c954dcc2e' "$KS_FILE" \
    "Firefox vendor launcher source is exact-hash pinned"
assert_grep_fixed 'owned_launcher=/usr/local/bin/firefox' "$KS_FILE" \
    "Firefox customization is published as an owned /usr/local launcher"
assert_grep_fixed 'owned_desktop=/usr/local/share/applications/org.mozilla.firefox.desktop' "$KS_FILE" \
    "Firefox desktop customization uses XDG precedence"
assert_grep_fixed '/etc/dnf/libdnf5-plugins/actions.d/noid-firefox.actions' \
    "$REVERT_DOC" "Firefox revert disables package-transaction reassertion"
assert_grep_fixed '/usr/local/share/applications/org.mozilla.firefox.desktop' \
    "$REVERT_DOC" "Firefox revert removes the owned XDG desktop overlay"
assert_grep_fixed '/etc/firefox/policies/policies.json' "$REVERT_DOC" \
    "Firefox revert removes the current minimal enterprise policy"
assert_grep_fixed '/usr/local/lib/noid-privacy/validate-ubo-policy.py' \
    "$REVERT_DOC" "Firefox revert removes the uBO policy validator"
assert_grep_fixed 'Existing profiles can retain values previously copied into prefs.js' \
    "$REVERT_DOC" "Firefox revert does not promise defaults for a reused profile"
assert_grep_fixed '/usr/bin/firefox --ProfileManager' "$REVERT_DOC" \
    "Firefox revert uses a fresh profile for a guaranteed stock preference state"
assert_not_grep 'sudo dnf reinstall -y firefox' "$REVERT_DOC" \
    "Firefox revert does not reinstall an already pristine RPM payload"
assert_not_grep 'Firefox launcher patches' "$REVERT_DOC" \
    "Firefox revert does not claim that M16 patches vendor launcher bytes"
REVERT_BLOCK=$(mktemp /var/tmp/noid-firefox-revert.XXXXXXXX)
trap 'rm -f -- "$REVERT_BLOCK"' EXIT
awk '
    /^\*\*Step 2 —/ { in_step = 1; next }
    in_step && /^```bash$/ { in_block = 1; next }
    in_block && /^```$/ { exit }
    in_block { print }
' "$REVERT_DOC" > "$REVERT_BLOCK"
if [ -s "$REVERT_BLOCK" ]; then
    _pass "complete Firefox revert command block is present"
else
    _fail "complete Firefox revert command block is present"
fi
assert_cmd_success "complete Firefox revert command block parses" \
    bash -n "$REVERT_BLOCK"
rm -f -- "$REVERT_BLOCK"
trap - EXIT
assert_grep_fixed 'shopt -s nullglob' "$KS_FILE" \
    "Firefox launcher treats absent Widevine paths as an empty set"
assert_grep_fixed 'restorecon -vr -- "${widevine_paths[@]}"' "$KS_FILE" \
    "Firefox launcher still reports real restorecon failures"
assert_not_grep 'restorecon -vr.*2>/dev/null\|restorecon -vr.*|| true' "$KS_FILE" \
    "Firefox launcher fix does not swallow relabel failures"
assert_grep_fixed 'prepare_firefox_launch_args "$@"' "$KS_FILE" \
    "ordinary Firefox invocations resolve the canonical hardened profile by path"
assert_grep_fixed 'if [ -f "$HOME/.mozilla/firefox/profiles.ini" ]; then' "$KS_FILE" \
    "owned launcher does not let an empty legacy directory redirect Fedora helpers"
assert_grep_fixed '-ProfileManager|--ProfileManager|-CreateProfile|--CreateProfile' "$KS_FILE" \
    "explicit Firefox profile-management invocations retain upstream semantics"

# --- Gzip+base64 embedded user.js --------------------------------------------
assert_grep_fixed 'HARDENING_GZ_B64_EOF' "$KS_FILE" "user.js gzip+base64 heredoc marker"
assert_grep_fixed 'base64 -d' "$KS_FILE" "base64 decode step"
assert_grep_fixed '| gunzip >' "$KS_FILE" "gunzip decode step"
assert_grep_fixed 'NOID-COMPLETE' "$KS_FILE" "NoID Privacy parrot marker (post-decode sanity)"
for local_sb_pref in \
    malware.enabled \
    phishing.enabled \
    downloads.enabled \
    blockedURIs.enabled; do
    assert_grep_fixed \
        "user_pref(\"browser.safebrowsing.${local_sb_pref}\", true);" \
        "$PROJECT_ROOT/firefox/noid-firefox-hardening.js" \
        "Firefox keeps local Safe Browsing protection active: ${local_sb_pref}"
done
assert_grep_fixed \
    'user_pref("browser.safebrowsing.downloads.remote.enabled", false);' \
    "$PROJECT_ROOT/firefox/noid-firefox-hardening.js" \
    "Firefox disables only per-download remote reputation"
assert_not_grep_extended \
    '^[[:space:]]*user_pref\("browser\.safebrowsing\.update\.enabled",[[:space:]]*false\)' \
    "$PROJECT_ROOT/firefox/noid-firefox-hardening.js" \
    "Firefox leaves local Safe Browsing list updates enabled"

# --- uBO first-install seed + explicit-update validator ---------------------
assert_grep_fixed 'UBO_SHA256=' "$KS_FILE"
assert_grep_fixed 'UBO_VERSION=' "$KS_FILE"
assert_grep_fixed 'verify_sha256()' "$KS_FILE"
assert_grep_fixed 'sha256sum' "$KS_FILE"
assert_grep_fixed 'github.com/gorhill/uBlock/releases/download/' "$KS_FILE"
assert_grep_fixed 'name: Verify pinned uBO XPI bytes' \
    "$PROJECT_ROOT/.github/workflows/ci.yml" \
    "CI downloads the pinned uBO artifact"
assert_grep_fixed 'UBO_SHA: ${{ steps.pins.outputs.UBO_SHA }}' \
    "$PROJECT_ROOT/.github/workflows/ci.yml" \
    "CI consumes the kickstart uBO SHA pin"
assert_grep_fixed "printf '%s  %s\\n' \"\$UBO_SHA\" \"\$tmp/uBlock.xpi\" | sha256sum -c -" \
    "$PROJECT_ROOT/.github/workflows/ci.yml" \
    "CI verifies the downloaded uBO bytes"
assert_not_grep 'addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi' "$KS_FILE"
assert_grep_fixed 'NOID_CACHE_BASE_URL="${NOID_CACHE_BASE_URL:-}"' "$KS_FILE" \
    "M16 accepts the canonical builder's loopback cache"
assert_grep_fixed "curl -fsS --proto '=http' --max-redirs 0" "$KS_FILE" \
    "M16 local build-cache fetch cannot redirect or change protocol"
assert_grep_fixed "--proto '=https' --proto-redir '=https' --tlsv1.2" "$KS_FILE" \
    "M16 external uBO redirect chain remains HTTPS-only"
assert_eq 2 "$(grep -cF -- '--connect-timeout 15 --max-time 300' "$KS_FILE" || true)" \
    "both uBO fetch paths have bounded connection and total runtimes"
assert_eq 2 "$(grep -cF -- '--max-filesize "$UBO_SIZE_EXPECTED"' "$KS_FILE" || true)" \
    "both uBO fetch paths reject an oversized response during transfer"
assert_not_grep_extended 'OFFLINE=1|offline=\$\{OFFLINE' "$KS_FILE" \
    "retired OFFLINE switch cannot create a false air-gap claim"
assert_grep_fixed 'UBO_CACHE_RELATIVE="ubo/${UBO_VERSION}/uBlock0_${UBO_VERSION}.firefox.signed.xpi"' "$KS_FILE" \
    "M16 accepts only the canonical reduced-dependency relative path"

BUILD_ISO="$PROJECT_ROOT/scripts/build-iso.sh"
BUILD_REDUCED="$PROJECT_ROOT/scripts/build-offline.sh"
OFFLINE_PREP="$PROJECT_ROOT/scripts/offline-prep.sh"
assert_grep_fixed 'stage_reduced_dependency_cache()' "$BUILD_ISO" \
    "canonical builder stages the reduced-dependency cache"
assert_grep_fixed 'cached uBO XPI failed the source-pinned SHA256/size gate' "$BUILD_ISO"
assert_grep_fixed '"${REPO_ROOT}/scripts/build-iso.sh" "$@"' "$BUILD_REDUCED" \
    "reduced-dependency wrapper cannot bypass canonical release gates"
assert_not_grep 'livemedia-creator' "$BUILD_REDUCED" \
    "reduced-dependency wrapper never invokes lorax directly"
for reduced_script in "$BUILD_REDUCED" "$OFFLINE_PREP"; do
    assert_grep_fixed 'export PATH=/usr/sbin:/usr/bin' "$reduced_script" \
        "reduced-dependency helper resolves only Fedora system tools"
done
assert_not_grep 'rpmfusion-free-release' "$OFFLINE_PREP" \
    "prep cache has no dead unverified RPM Fusion payload"
assert_not_grep 'vscodium.*pub\.gpg' "$OFFLINE_PREP" \
    "prep cache has no unused mutable VSCodium key payload"
assert_not_grep 'reposync\|--minimal\|fedora-44' "$OFFLINE_PREP" \
    "dead unwired Fedora mirror mode is removed"
assert_grep_fixed "--proto '=https' --request GET --max-redirs 0" "$OFFLINE_PREP" \
    "prep disables curl automatic redirects and requires HTTPS"
assert_grep_fixed 'release-assets.githubusercontent.com' "$OFFLINE_PREP" \
    "prep constrains post-release redirects to the reviewed asset host"
assert_grep_fixed 'NOID_REDUCED_DEPENDENCY_CACHE_V1' "$OFFLINE_PREP" \
    "prep emits a versioned exact cache contract"
for signal_contract in \
    "trap 'exit 129' HUP" \
    "trap 'exit 130' INT" \
    "trap 'exit 143' TERM"; do
    assert_grep_fixed "$signal_contract" "$OFFLINE_PREP" \
        "reduced-dependency prep preserves the signal-derived exit status"
done
assert_grep_fixed 'cmp -s -- "$TMP_EXPECTED" "$MANIFEST"' "$BUILD_REDUCED" \
    "wrapper authenticates manifest fields against repository pins"
assert_not_grep 'optional Fedora mirror\|mirror is staged' "$BUILD_REDUCED" \
    "wrapper makes no dead mirror claim"
for pin_file in "$OFFLINE_PREP" "$BUILD_REDUCED"; do
    assert_grep_fixed 'readonly UBO_VERSION="1.73.0"' "$pin_file" \
        "reduced-dependency helper version pin matches M16"
    assert_grep_fixed 'readonly UBO_SHA256="bccc51a773150af4af6e1fd62c7bfdeb7238b79ff2381b998fa9f2e38f64786a"' \
        "$pin_file" "reduced-dependency helper SHA-256 pin matches M16"
    assert_grep_fixed 'readonly UBO_SIZE="4679419"' "$pin_file" \
        "reduced-dependency helper size pin matches M16"
done
assert_grep_fixed 'local expected_size=4679419' "$BUILD_ISO" \
    "canonical builder cache size pin matches M16"
assert_grep_fixed 'local expected_sha="bccc51a773150af4af6e1fd62c7bfdeb7238b79ff2381b998fa9f2e38f64786a"' \
    "$BUILD_ISO" "canonical builder cache SHA-256 pin matches M16"

# --- Extension install path (Mozilla distribution-bundled + legacy symlink) -
assert_grep_fixed '/usr/lib64/firefox/distribution/extensions' "$KS_FILE" \
    "uBO distribution-bundled install path"
assert_grep_fixed 'mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}' "$KS_FILE"

# --- Langpack durability: reassert re-mirrors langpacks on firefox upgrade ----
assert_grep_fixed 'LPSRC=/usr/lib64/firefox/langpacks' "$KS_FILE" \
    "noid-firefox-reassert langpack re-sync on firefox upgrade"

# --- Managed storage manifest (current narrow schema, no IDB hacks) ---------
assert_grep_fixed '/usr/lib64/mozilla/managed-storage' "$KS_FILE"
assert_grep_fixed 'uBlock0@raymondhill.net.json' "$KS_FILE"
assert_grep_fixed 'UBO_POLICY_SOURCE="$SHARE_DIR/uBlock0@raymondhill.net.json"' \
    "$KS_FILE" "uBO policy has a durable canonical source for exact restoration"
assert_grep_fixed 'install -o root -g root -m 0644 -- "$UBO_POLICY_SOURCE"' \
    "$KS_FILE" "active uBO policy is derived from its canonical source"
assert_grep_fixed 'cmp -s -- "$UBO_POLICY_SOURCE"' "$KS_FILE" \
    "M16 final gate binds active uBO policy to its canonical source"
assert_grep_fixed '"toOverwrite": {' "$KS_FILE" \
    "uBO uses the current managed-policy branch"
assert_grep_fixed '"filterLists": [' "$KS_FILE" \
    "uBO policy narrowly manages its filter-list set"
assert_not_grep '"adminSettings":' "$KS_FILE" \
    "uBO does not use the deprecated backup-format policy"
assert_not_grep '"advancedSettings":' "$KS_FILE" \
    "uBO keeps upstream advanced-setting defaults"
assert_not_grep 'UBO_SELFIE_DELAY_SECONDS=' "$KS_FILE" \
    "uBO does not force an experimental startup-cache delay"
assert_grep_fixed 'UBO_POLICY_VALIDATOR="/usr/local/lib/noid-privacy/validate-ubo-policy.py"' \
    "$KS_FILE" "uBO policy compatibility validator has one canonical path"
assert_grep_fixed '"managed_storage.json"' "$KS_FILE" \
    "uBO candidate must advertise the managed filter-list schema"
assert_grep_fixed '"assets/assets.json"' "$KS_FILE" \
    "uBO candidate assets are checked against every managed list token"
if python3 - "$KS_FILE" <<'UBO_MANAGED_PYEOF'
import json
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
count_match = re.search(
    r"^EXPECTED_FILTER_LIST_COUNT=([0-9]+)$",
    source,
    flags=re.MULTILINE,
)
manifest_match = re.search(
    r"<<'UBOMANIFEST_EOF'\n(.*?)\nUBOMANIFEST_EOF",
    source,
    flags=re.DOTALL,
)
assert count_match and manifest_match
managed = json.loads(manifest_match.group(1))
expected = [
    "user-filters",
    "ublock-filters",
    "ublock-badware",
    "ublock-privacy",
    "ublock-quick-fixes",
    "ublock-unbreak",
    "easylist",
    "easyprivacy",
    "urlhaus-1",
    "plowe-0",
    "adguard-spyware-url",
    "block-lan",
    "curben-phishing",
]
assert len(expected) == int(count_match.group(1))
assert managed == {
    "name": "uBlock0@raymondhill.net",
    "description": (
        "NoID Privacy Workstation 44 - uBlock Origin managed "
        "filter-list baseline (Module 16)"
    ),
    "type": "storage",
    "data": {"toOverwrite": {"filterLists": expected}},
}
UBO_MANAGED_PYEOF
then
    _pass "uBO policy manages only the exact reviewed filter-list baseline"
else
    _fail "uBO policy manages only the exact reviewed filter-list baseline"
fi

# --- Firefox core archive must stay RPM-owned -------------------------------
# A retired implementation patched /usr/lib64/firefox/browser/omni.ja with zip --update
# to remove Fedora bookmarks. Live testing showed broken Firefox/Playground
# first-launch chrome/content. Regression guard: M16 may write the safe
# /usr/share/bookmarks fallback, but must not modify omni.ja.
if awk '
    /^[[:space:]]*#/ { next }
    /OMNI_JA=|ORIG_BOOKMARKS_PATH=/ { found=1 }
    /zip[[:space:]].*--update.*omni[.]ja/ { found=1 }
    /zip[[:space:]].*"\$OMNI_JA"/ { found=1 }
    END { exit(found ? 0 : 1) }
' "$KS_FILE"; then
    _fail "M16 still patches Firefox omni.ja"
else
    _pass "M16 does not patch Firefox omni.ja"
fi
assert_grep_fixed '/usr/share/bookmarks/default-bookmarks.html' "$KS_FILE" \
    "safe empty bookmarks fallback path"
assert_grep_extended '^-fedora-bookmarks$' "$PROJECT_ROOT/kickstart/snippets/26-package-set.ks" \
    "M26 excludes fedora-bookmarks"
assert_not_grep 'AutoConfig processed-marker\|AutoConfig processed marker\|exact defaultPref above' \
    "$KS_FILE" "M16 does not document a synthetic distributor processed preference"
assert_grep_fixed 'see docs/pin-inventory.md for the refresh workflow' "$KS_FILE" \
    "uBO source comment points to the repository pin inventory"
assert_file_exists "$PROJECT_ROOT/docs/pin-inventory.md" \
    "uBO pin inventory target exists"

# --- XDG autostart for firstrun setup ---------------------------------------
# Source uses XDG_AUTOSTART_DIR variable (defined as /etc/xdg/autostart at top
# of M16). Match the variable construction — the test previously searched
# for a literal path that only exists via variable expansion.
assert_grep_fixed '$XDG_AUTOSTART_DIR/noid-firefox-setup.desktop' "$KS_FILE"
assert_grep_fixed 'SKEL_EXTENSION_PREFS_EOF' "$KS_FILE" \
    "root-owned Firefox seed includes uBO private-window permission JSON"
assert_grep_fixed 'cp -a "$SKEL_FF_BASE/default-release/extension-preferences.json"' \
    "$KS_FILE" "Live-mode existing-user mirror includes the permission seed"
assert_grep_fixed 'user_gid=$(id -g "$user_name" 2>/dev/null) || continue' \
    "$KS_FILE" "existing-user mirror resolves the account primary group"
assert_grep_fixed 'install -d -m 0700 -o "$user_uid" -g "$user_gid" "$user_home/.config"' \
    "$KS_FILE" "existing-user mirror owns the XDG configuration parent"
assert_grep_fixed 'install -d -m 0700 -o "$user_uid" -g "$user_gid" "$user_home/.config/mozilla"' \
    "$KS_FILE" "existing-user mirror owns the Mozilla configuration parent"
assert_grep_fixed 'chmod 600 "$SKEL_FF_PROFILE/extension-preferences.json"' \
    "$KS_FILE" "root-owned permission seed is private"
assert_grep_fixed 'chmod 600 "$SKEL_FF_PROFILE/user.js"' "$KS_FILE" \
    "root-owned Firefox user.js seed matches the helper's private-file contract"
assert_grep_fixed \
    '$ff_skel|etc/skel/.config/mozilla/firefox/default-release/user.js|600' \
    "$PROJECT_ROOT/tests/pre-ship/19-browser-image-parity.sh" \
    "browser image parity enforces the private Firefox user.js seed mode"

# Module success must be declared only after core + Anaconda + exact final
# deployment gates, and M99 must require the resulting health stamp.
assert_grep_fixed 'stamp-16-firefox.ok' "$KS_FILE" "M16 writes a Firefox health stamp"
assert_grep_fixed '"16:firefox"' "$PROJECT_ROOT/kickstart/snippets/99-finalize.ks" \
    "M99 requires the exact M16 Firefox stamp"
assert_grep_fixed 'Step 1b/8: Invalidate stale Firefox build-health evidence' \
    "$KS_FILE" "M16 retires prior success before its first payload mutation"
assert_grep_fixed 'Prior Module 16 health stamp is absent' "$KS_FILE" \
    "M16 confirms stale health evidence is absent"
assert_grep_fixed 'cleanup_firefox_health_stamp()' "$KS_FILE" \
    "M16 has failure cleanup for a partially published stamp"
assert_grep_fixed 'matchpathcon -V "$STAMP_TMP"' "$KS_FILE" \
    "M16 verifies the staged health-stamp SELinux context"
assert_grep_fixed 'matchpathcon -V "$STAMP"' "$KS_FILE" \
    "M16 verifies the published health-stamp SELinux context"
assert_grep_fixed '"0:0:644:1"' "$KS_FILE" \
    "M16 verifies exact health-stamp owner, mode and link count"
assert_grep_fixed 'Exact Module 16 health stamp published atomically' "$KS_FILE" \
    "M16 declares health only after the closed publication gate"
assert_not_grep 'restorecon "$STAMP" 2>/dev/null || true' "$KS_FILE" \
    "M16 no longer suppresses health-stamp relabel failures"
assert_grep_fixed 'Final gate: exact Firefox deployment contracts' "$KS_FILE" \
    "M16 has one closed final deployment gate"
assert_grep_fixed 'canonical and skel Firefox user.js differ' "$KS_FILE" \
    "M16 final gate compares canonical/skel user.js bytes"
assert_grep_fixed 'final Firefox langpack name set differs from RPM source' "$KS_FILE" \
    "M16 final gate compares the complete langpack set"
assert_grep_fixed 'source_langpacks=$(find -L "$FIREFOX_LANGPACK_SRC"' "$KS_FILE" \
    "M16 final gate includes non-dangling RPM langpack aliases"
for helper_path in \
    '"$UBO_POLICY_VALIDATOR"' \
    /usr/local/lib/noid-privacy/validate-webextension.py \
    /usr/local/lib/noid-privacy/verify-firefox-xpi-signature \
    /usr/local/lib/noid-privacy/firefox-profiles.sh; do
    assert_grep_fixed "restorecon -F $helper_path" "$KS_FILE" \
        "Firefox helper is relabelled after publication: $helper_path"
done
assert_grep_fixed 'matchpathcon -V "$helper_path"' "$KS_FILE" \
    "M16 final gate verifies every Firefox helper SELinux context"
assert_grep_fixed 'Anaconda Firefox profile lacks one exact hardening block' "$KS_FILE" \
    "M16 final gate validates every Anaconda browser profile"
assert_not_grep '\[WARN\].*firefox.desktop\|\[WARN\].*anaconda-webui\|\[WARN\].*firefox-theme' \
    "$KS_FILE" "required launcher/Anaconda artifacts are never optionalized"
M16_STEP8_LINE=$(grep -nF 'log "Step 8/8: Anaconda WebUI Firefox profile hardening"' "$KS_FILE" | cut -d: -f1 || true)
M16_FINAL_LINE=$(grep -nF 'log "Final gate: exact Firefox deployment contracts"' "$KS_FILE" | cut -d: -f1 || true)
M16_COMPLETE_LINE=$(grep -nF 'log "=== Module 16: Firefox Hardening COMPLETE ==="' "$KS_FILE" | cut -d: -f1 || true)
if [ -n "$M16_STEP8_LINE" ] && [ -n "$M16_FINAL_LINE" ] && [ -n "$M16_COMPLETE_LINE" ] && \
   [ "$M16_STEP8_LINE" -lt "$M16_FINAL_LINE" ] && [ "$M16_FINAL_LINE" -lt "$M16_COMPLETE_LINE" ]; then
    _pass "M16 COMPLETE occurs only after Anaconda and final gates"
else
    _fail "M16 COMPLETE occurs only after Anaconda and final gates"
fi

M16_INVALIDATE_LINE=$(grep -nF \
    'Step 1b/8: Invalidate stale Firefox build-health evidence' \
    "$KS_FILE" | cut -d: -f1 || true)
M16_FIRST_PAYLOAD_LINE=$(grep -nF \
    'Step 3/8: Install NoID Privacy Firefox hardening' \
    "$KS_FILE" | cut -d: -f1 || true)
M16_STAMP_OK_LINE=$(grep -nF \
    'Exact Module 16 health stamp published atomically' \
    "$KS_FILE" | cut -d: -f1 || true)
if [ -n "$M16_INVALIDATE_LINE" ] && [ -n "$M16_FIRST_PAYLOAD_LINE" ] \
   && [ -n "$M16_STAMP_OK_LINE" ] \
   && [ "$M16_INVALIDATE_LINE" -lt "$M16_FIRST_PAYLOAD_LINE" ] \
   && [ "$M16_FINAL_LINE" -lt "$M16_STAMP_OK_LINE" ] \
   && [ "$M16_STAMP_OK_LINE" -lt "$M16_COMPLETE_LINE" ]; then
    _pass "M16 invalidates old evidence before mutation and publishes after verification"
else
    _fail "M16 invalidates old evidence before mutation and publishes after verification"
fi

# Execute the health-evidence boundary with disposable state and command
# fixtures. Old evidence must be retired before mutation; every failed
# candidate/final publication must remain stamp-less and leave no temp file.
M16_STAMP_FIXTURE=$(mktemp -d "$PROJECT_ROOT/.test-firefox-stamp.XXXXXXXX")
trap 'rm -r -- "$M16_STAMP_FIXTURE"' EXIT
M16_STAMP_STATE="$M16_STAMP_FIXTURE/state"
M16_STAMP_BIN="$M16_STAMP_FIXTURE/bin"
M16_STAMP_INVALIDATE="$M16_STAMP_FIXTURE/invalidate.sh"
M16_STAMP_PUBLISH="$M16_STAMP_FIXTURE/publish.sh"
M16_STAMP_UID=$(id -u)
M16_STAMP_GID=$(id -g)
mkdir -p "$M16_STAMP_BIN"

cat > "$M16_STAMP_BIN/restorecon" <<'M16_STAMP_RESTORECON_EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${!#}"
case "${FAKE_RESTORECON_FAIL:-}" in
    all) exit 1 ;;
    final)
        case "$target" in
            */stamp-16-firefox.ok) exit 1 ;;
        esac
        ;;
esac
exit 0
M16_STAMP_RESTORECON_EOF
cat > "$M16_STAMP_BIN/matchpathcon" <<'M16_STAMP_MATCHPATHCON_EOF'
#!/usr/bin/env bash
exit 0
M16_STAMP_MATCHPATHCON_EOF
cat > "$M16_STAMP_BIN/mv" <<'M16_STAMP_MV_EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${FAKE_MV_FAIL:-0}" -eq 1 ]; then
    exit 1
fi
exec /usr/bin/mv "$@"
M16_STAMP_MV_EOF
chmod 0700 "$M16_STAMP_BIN/restorecon" \
    "$M16_STAMP_BIN/matchpathcon" "$M16_STAMP_BIN/mv"

{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'log() { :; }' \
        "STAMP_DIR=$M16_STAMP_STATE" \
        'STAMP="$STAMP_DIR/stamp-16-firefox.ok"'
    sed -n \
        '/^# M16_HEALTH_INVALIDATION_BEGIN$/,/^# M16_HEALTH_INVALIDATION_END$/p' \
        "$KS_FILE" |
        sed -e "s/-o root -g root/-o $M16_STAMP_UID -g $M16_STAMP_GID/" \
            -e "s/0:0:755/$M16_STAMP_UID:$M16_STAMP_GID:755/"
} > "$M16_STAMP_INVALIDATE"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'log() { :; }' \
        "STAMP_DIR=$M16_STAMP_STATE" \
        'STAMP="$STAMP_DIR/stamp-16-firefox.ok"'
    sed -n \
        '/^# M16_HEALTH_PUBLICATION_BEGIN$/,/^# M16_HEALTH_PUBLICATION_END$/p' \
        "$KS_FILE" |
        sed -e "s/chown root:root/chown $M16_STAMP_UID:$M16_STAMP_GID/" \
            -e "s/0:0:755/$M16_STAMP_UID:$M16_STAMP_GID:755/" \
            -e "s/0:0:644:1/$M16_STAMP_UID:$M16_STAMP_GID:644:1/"
} > "$M16_STAMP_PUBLISH"
chmod 0700 "$M16_STAMP_INVALIDATE" "$M16_STAMP_PUBLISH"

mkdir -m 0755 "$M16_STAMP_STATE"
printf '%s\n' 'module=16' 'name=firefox' 'status=ok' \
    > "$M16_STAMP_STATE/stamp-16-firefox.ok"
assert_cmd_success "M16 rerun retires a prior success stamp" \
    env PATH="$M16_STAMP_BIN:$PATH" "$M16_STAMP_INVALIDATE"
if [ ! -e "$M16_STAMP_STATE/stamp-16-firefox.ok" ]; then
    _pass "M16 stale success evidence is absent before payload mutation"
else
    _fail "M16 stale success evidence is absent before payload mutation"
fi

rmdir "$M16_STAMP_STATE"
mkdir "$M16_STAMP_FIXTURE/state-target"
ln -s "$M16_STAMP_FIXTURE/state-target" "$M16_STAMP_STATE"
printf '%s\n' 'must-survive' \
    > "$M16_STAMP_FIXTURE/state-target/stamp-16-firefox.ok"
assert_cmd_failure "M16 rejects a symlinked shared state directory" \
    env PATH="$M16_STAMP_BIN:$PATH" "$M16_STAMP_INVALIDATE"
assert_grep_fixed 'must-survive' \
    "$M16_STAMP_FIXTURE/state-target/stamp-16-firefox.ok" \
    "M16 never traverses an unsafe state-directory symlink"
rm "$M16_STAMP_STATE"
rm -r "$M16_STAMP_FIXTURE/state-target"
mkdir -m 0755 "$M16_STAMP_STATE"

chmod 0777 "$M16_STAMP_STATE"
printf '%s\n' 'must-also-survive' \
    > "$M16_STAMP_STATE/stamp-16-firefox.ok"
assert_cmd_failure "M16 detects shared state-directory metadata drift" \
    env PATH="$M16_STAMP_BIN:$PATH" "$M16_STAMP_INVALIDATE"
assert_eq "$M16_STAMP_UID:$M16_STAMP_GID:777" \
    "$(stat -c '%u:%g:%a' "$M16_STAMP_STATE")" \
    "M16 does not normalize unsafe shared-directory metadata"
assert_grep_fixed 'must-also-survive' \
    "$M16_STAMP_STATE/stamp-16-firefox.ok" \
    "M16 does not touch a stamp through a drifted state boundary"
rm "$M16_STAMP_STATE/stamp-16-firefox.ok"
chmod 0755 "$M16_STAMP_STATE"

assert_cmd_failure "M16 rejects a health-stamp candidate label failure" \
    env PATH="$M16_STAMP_BIN:$PATH" FAKE_RESTORECON_FAIL=all \
        "$M16_STAMP_PUBLISH"
if [ ! -e "$M16_STAMP_STATE/stamp-16-firefox.ok" ] \
   && [ -z "$(find "$M16_STAMP_STATE" -maxdepth 1 \
        -name '.stamp-16-firefox.ok.*' -print -quit)" ]; then
    _pass "M16 candidate-label failure leaves no plausible health evidence"
else
    _fail "M16 candidate-label failure leaves no plausible health evidence"
fi

assert_cmd_failure "M16 retires a stamp after final-label failure" \
    env PATH="$M16_STAMP_BIN:$PATH" FAKE_RESTORECON_FAIL=final \
        "$M16_STAMP_PUBLISH"
if [ ! -e "$M16_STAMP_STATE/stamp-16-firefox.ok" ]; then
    _pass "M16 final-label failure removes the published success stamp"
else
    _fail "M16 final-label failure removes the published success stamp"
fi

assert_cmd_failure "M16 rejects an atomic health-stamp rename failure" \
    env PATH="$M16_STAMP_BIN:$PATH" FAKE_MV_FAIL=1 "$M16_STAMP_PUBLISH"
if [ ! -e "$M16_STAMP_STATE/stamp-16-firefox.ok" ] \
   && [ -z "$(find "$M16_STAMP_STATE" -maxdepth 1 \
        -name '.stamp-16-firefox.ok.*' -print -quit)" ]; then
    _pass "M16 rename failure leaves no stamp or staged candidate"
else
    _fail "M16 rename failure leaves no stamp or staged candidate"
fi

assert_cmd_success "M16 publishes exact health evidence after all gates" \
    env PATH="$M16_STAMP_BIN:$PATH" "$M16_STAMP_PUBLISH"
assert_grep_fixed 'module=16' "$M16_STAMP_STATE/stamp-16-firefox.ok"
assert_grep_fixed 'name=firefox' "$M16_STAMP_STATE/stamp-16-firefox.ok"
assert_grep_fixed 'version=1' "$M16_STAMP_STATE/stamp-16-firefox.ok"
assert_grep_fixed 'status=ok' "$M16_STAMP_STATE/stamp-16-firefox.ok"
assert_eq 6 "$(wc -l < "$M16_STAMP_STATE/stamp-16-firefox.ok")" \
    "M16 published health stamp has the exact six-line schema"
rm -r -- "$M16_STAMP_FIXTURE"
trap - EXIT
M16_STAMP_FIXTURE=

# Execute the Anaconda transaction against disposable package-tree fixtures.
# A publication failure must leave all vendor bytes untouched; a successful
# rerun must be byte-idempotent and reject a modified managed suffix.
ANACONDA_TXN_FIXTURE=$(mktemp -d "$PROJECT_ROOT/.test-anaconda-firefox.XXXXXXXX")
trap '[ -z "${ANACONDA_TXN_FIXTURE:-}" ] || rm -r -- "$ANACONDA_TXN_FIXTURE"' EXIT
ANACONDA_TXN_TREE="$ANACONDA_TXN_FIXTURE/firefox-theme"
ANACONDA_TXN_SCRIPT="$ANACONDA_TXN_FIXTURE/step8.sh"
ANACONDA_TXN_BIN="$ANACONDA_TXN_FIXTURE/bin"
mkdir -p "$ANACONDA_TXN_BIN"
for profile in live default extlink; do
    mkdir -p "$ANACONDA_TXN_TREE/$profile"
    printf 'user_pref("fixture.upstream.%s", true);\n' "$profile" \
        > "$ANACONDA_TXN_TREE/$profile/user.js"
done
{
    printf '%s\n' '#!/bin/bash' 'set -euo pipefail' 'log() { :; }'
    sed -n '/^ANACONDA_FF_THEME_DIR=/,/^log "    Anaconda Firefox-theme hardened/p' \
        "$KS_FILE"
} > "$ANACONDA_TXN_SCRIPT"
ANACONDA_TXN_UID=$(id -u)
ANACONDA_TXN_GID=$(id -g)
sed -i \
    -e "s|^ANACONDA_FF_THEME_DIR=.*|ANACONDA_FF_THEME_DIR=$ANACONDA_TXN_TREE|" \
    -e "s|chown root:root|chown $ANACONDA_TXN_UID:$ANACONDA_TXN_GID|g" \
    -e "s|0:0:644:1|$ANACONDA_TXN_UID:$ANACONDA_TXN_GID:644:1|g" \
    "$ANACONDA_TXN_SCRIPT"
chmod 0700 "$ANACONDA_TXN_SCRIPT"
cat > "$ANACONDA_TXN_BIN/mv" <<'ANACONDA_TXN_MV_EOF'
#!/bin/sh
exit 1
ANACONDA_TXN_MV_EOF
chmod 0700 "$ANACONDA_TXN_BIN/mv"
ANACONDA_VENDOR_SHA=$(sha256sum \
    "$ANACONDA_TXN_TREE/live/user.js" \
    "$ANACONDA_TXN_TREE/default/user.js" \
    "$ANACONDA_TXN_TREE/extlink/user.js")
assert_cmd_failure "failed Anaconda publication preserves all vendor inputs" \
    env PATH="$ANACONDA_TXN_BIN:$PATH" bash "$ANACONDA_TXN_SCRIPT"
assert_eq "$ANACONDA_VENDOR_SHA" \
    "$(sha256sum "$ANACONDA_TXN_TREE/live/user.js" \
        "$ANACONDA_TXN_TREE/default/user.js" \
        "$ANACONDA_TXN_TREE/extlink/user.js")" \
    "failed Anaconda publication leaves no partial hardening marker"
assert_cmd_success "Anaconda hardening publishes all exact suffixes atomically" \
    bash "$ANACONDA_TXN_SCRIPT"
ANACONDA_HARDENED_SHA=$(sha256sum \
    "$ANACONDA_TXN_TREE/live/user.js" \
    "$ANACONDA_TXN_TREE/default/user.js" \
    "$ANACONDA_TXN_TREE/extlink/user.js")
assert_cmd_success "Anaconda hardening rerun is byte-idempotent" \
    bash "$ANACONDA_TXN_SCRIPT"
assert_eq "$ANACONDA_HARDENED_SHA" \
    "$(sha256sum "$ANACONDA_TXN_TREE/live/user.js" \
        "$ANACONDA_TXN_TREE/default/user.js" \
        "$ANACONDA_TXN_TREE/extlink/user.js")" \
    "Anaconda rerun preserves the exact completed suffixes"
printf '%s\n' '// modified after managed suffix' \
    >> "$ANACONDA_TXN_TREE/live/user.js"
ANACONDA_MODIFIED_SHA=$(sha256sum "$ANACONDA_TXN_TREE/live/user.js" | awk '{print $1}')
assert_cmd_failure "Anaconda hardening rejects a modified managed suffix" \
    bash "$ANACONDA_TXN_SCRIPT"
assert_eq "$ANACONDA_MODIFIED_SHA" \
    "$(sha256sum "$ANACONDA_TXN_TREE/live/user.js" | awk '{print $1}')" \
    "Anaconda suffix rejection preserves review evidence"
rm -r -- "$ANACONDA_TXN_FIXTURE"
ANACONDA_TXN_FIXTURE=
trap - EXIT

# X-GNOME-Autostart-Phase (GNOME 49+ bug) must NOT appear as an active line.
if grep -Pn '^\s*X-GNOME-Autostart-Phase\s*=' "$KS_FILE" >/dev/null 2>&1; then
    _fail "X-GNOME-Autostart-Phase= line present (autostart-phase regression)"
else
    _pass "no active X-GNOME-Autostart-Phase= line (autostart-phase hold)"
fi

# --- firefox/ dir + canonical user.js in repo -------------------------------
FIREFOX_JS="$PROJECT_ROOT/firefox/noid-firefox-hardening.js"
ARKENFOX_LICENSE="$PROJECT_ROOT/licenses/arkenfox-user.js-MIT.txt"
if [ -f "$FIREFOX_JS" ]; then
    _pass "firefox/noid-firefox-hardening.js present in repo (source of truth)"
    # Sanity: NoID Privacy header + NoID Privacy parrot + FPP enabled
    assert_grep_fixed 'NoID Privacy Workstation — Firefox Hardening' "$FIREFOX_JS" "NoID Privacy header"
    assert_grep_fixed 'derived from arkenfox user.js v144.0' "$FIREFOX_JS" "arkenfox attribution"
    assert_not_grep_extended '^\*[[:space:]]+date:' "$FIREFOX_JS" \
        "Firefox source does not ship a self-date that drifts from its review history"
    assert_grep_fixed 'Firefox 153 review added the Section 9003 ASRouter provider' "$FIREFOX_JS" \
        "Firefox source records current packaged-release review coverage"
    assert_grep_fixed 'This file is maintained by the NoID Privacy project' "$FIREFOX_JS" \
        "Firefox source assigns ongoing maintenance to NoID Privacy"
    assert_not_grep 'Electrolysis/Fission.*locked' "$FIREFOX_JS" \
        "Firefox source does not claim native site isolation is policy-locked"
    assert_not_grep 'AI/ML fully disabled' "$FIREFOX_JS" \
        "Firefox source scopes AI controls without claiming all ML is disabled"
    assert_grep_fixed 'current Mozilla AI enhancements blocked through' "$FIREFOX_JS" \
        "Firefox source names the maintained AI-control boundary"
    assert_not_grep 'Let.s Encrypt OCSP dead since May' "$FIREFOX_JS" \
        "Firefox source does not misdate the end of a CA responder service"
    assert_grep_fixed 'Firefox 142 put CRLite into production' "$FIREFOX_JS" \
        "Firefox source records the current CRLite production boundary"
    assert_not_grep_extended 'wind-down|potentially (the )?(last|final)|final upstream release' \
        "$FIREFOX_JS" \
        "Firefox source contains no speculative upstream end-of-life claim"
    for asrouter_provider in \
        message-groups \
        onboarding \
        cfr \
        messaging-experiments; do
        asrouter_pref="user_pref(\"browser.newtabpage.activity-stream.asrouter.providers.${asrouter_provider}\", \"null\");"
        assert_eq 1 "$(grep -Fxc -- "$asrouter_pref" "$FIREFOX_JS" || true)" \
            "Firefox 153 ASRouter provider is disabled exactly once: $asrouter_provider"
        assert_eq 1 "$(grep -Fxc -- "$asrouter_pref" "$KS_FILE" || true)" \
            "Anaconda Firefox disables the ASRouter provider exactly once: $asrouter_provider"
    done
    assert_grep_fixed 'without enabling in-memory base telemetry as a workaround' \
        "$FIREFOX_JS" "ASRouter fix preserves the stronger telemetry-off model"
    assert_eq 1 \
        "$(grep -Fxc -- 'user_pref("toolkit.telemetry.unified", false);' "$FIREFOX_JS" || true)" \
        "Firefox keeps unified base telemetry disabled exactly once"
    assert_not_grep 'user_pref(\"toolkit.telemetry.unified\", true);' "$FIREFOX_JS" \
        "ASRouter launch fix never enables unified base telemetry"
    assert_eq 1 \
        "$(grep -Fxc -- 'user_pref("network.lna.websocket.enabled", true);' "$FIREFOX_JS" || true)" \
        "Firefox source enables the LNA WebSocket arm exactly once"
    assert_grep_fixed 'Bug 2042339 enables the gate for Firefox 154' "$FIREFOX_JS" \
        "Firefox LNA WebSocket rationale cites the upstream enabling change"
    assert_grep_fixed 'NOID-COMPLETE' "$FIREFOX_JS" "NoID Privacy end parrot"
    assert_not_grep_extended '^[[:space:]]*user_pref\("privacy\.trackingprotection\.allow_list\.convenience\.enabled"' "$FIREFOX_JS" "ETP convenience choice is not profile-enforced"
    if python3 - "$FIREFOX_JS" <<'UNIQUE_PREFS_PYEOF'
import collections
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
active = re.findall(
    r'^[ \t]*user_pref\("([^"]+)",[ \t]*.*\);(?:[ \t]*//.*)?[ \t]*$',
    source,
    flags=re.MULTILINE,
)
duplicates = sorted(
    key
    for key, count in collections.Counter(active).items()
    if count > 1 and key != "_user.js.parrot"
)
assert not duplicates, duplicates
UNIQUE_PREFS_PYEOF
    then
        _pass "canonical Firefox active preferences are unique"
    else
        _fail "canonical Firefox active preferences are unique"
    fi
    if python3 - "$FIREFOX_JS" <<'COMMENT_STRUCTURE_PYEOF'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
inside = False
line = 1
for index in range(len(source) - 1):
    pair = source[index:index + 2]
    if pair == "/*":
        assert not inside, f"nested block-comment opener at line {line}"
        inside = True
    elif pair == "*/" and inside:
        inside = False
    if source[index] == "\n":
        line += 1
assert not inside, "unterminated block comment"
COMMENT_STRUCTURE_PYEOF
    then
        _pass "canonical Firefox block-comment structure is unambiguous"
    else
        _fail "canonical Firefox block-comment structure is unambiguous"
    fi
    for sanitizer_pref in \
        'user_pref("privacy.clearOnShutdown_v2.cookiesAndStorage", false);' \
        'user_pref("privacy.clearOnShutdown_v2.browsingHistoryAndDownloads", false);' \
        'user_pref("privacy.clearOnShutdown_v2.cache", true);' \
        'user_pref("privacy.clearOnShutdown_v2.formdata", true);' \
        'user_pref("privacy.clearOnShutdown_v2.siteSettings", false);'; do
        assert_eq 1 "$(grep -Fxc -- "$sanitizer_pref" "$FIREFOX_JS" || true)" \
            "productive profile pins current shutdown category: $sanitizer_pref"
    done
    assert_grep_fixed \
        'user_pref("privacy.sanitize.clearOnShutdown.hasMigratedToNewPrefs3", true);' \
        "$FIREFOX_JS" "shutdown categories are protected from legacy migration"
    assert_grep_fixed \
        'user_pref("privacy.sanitize.cpd.hasMigratedToNewPrefs3", true);' \
        "$FIREFOX_JS" "manual-clear categories are protected from legacy migration"
    assert_not_grep_extended \
        '^[[:space:]]*user_pref\("privacy\.sanitize\.clearOnShutdown\.hasMigratedToNewPrefs",' \
        "$FIREFOX_JS" "obsolete unversioned shutdown-migration marker is absent"
    for retired_sanitizer_pref in \
        privacy.clearOnShutdown_v2.historyFormDataAndDownloads \
        privacy.clearOnShutdown_v2.downloads \
        privacy.clearSiteData.historyFormDataAndDownloads \
        privacy.clearHistory.historyFormDataAndDownloads; do
        assert_not_grep_extended \
            "^[[:space:]]*user_pref\\(\"${retired_sanitizer_pref//./\\.}\"," \
            "$FIREFOX_JS" \
            "retired sanitizer migration/redundancy pref absent: $retired_sanitizer_pref"
    done
    for manual_prefix in privacy.clearSiteData privacy.clearHistory; do
        for manual_suffix in \
            'cache", true' \
            'cookiesAndStorage", false' \
            'browsingHistoryAndDownloads", false' \
            'formdata", true' \
            'siteSettings", false'; do
            manual_pref="user_pref(\"${manual_prefix}.${manual_suffix});"
            assert_eq 1 "$(grep -Fxc -- "$manual_pref" "$FIREFOX_JS" || true)" \
                "manual sanitizer pins current category: $manual_pref"
        done
    done
    assert_grep_fixed \
        'https://searchfox.org/mozilla-central/source/browser/modules/Sanitizer.sys.mjs' \
        "$FIREFOX_JS" "sanitizer migration contract cites Mozilla source"
else
    _fail "firefox/noid-firefox-hardening.js missing (canonical source file)"
fi
assert_file_exists "$ARKENFOX_LICENSE" "exact arkenfox v144 MIT notice retained in repository"
assert_eq 2bf289bdd22188ccff2bf34c9a20a75c45b84f42f887da7e177d9bfd1bac3c1a \
    "$(sha256sum "$ARKENFOX_LICENSE" | awk '{print $1}')" \
    "arkenfox tag-144.0 MIT notice hash"
if cmp -s \
    <(awk '/^\/\* ARKENFOX MIT NOTICE BEGIN$/ { copy=1; next }
           /^ARKENFOX MIT NOTICE END \*\/$/ { copy=0; found_end=1; next }
           copy { print }
           END { if (!found_end) exit 1 }' "$FIREFOX_JS") \
    "$ARKENFOX_LICENSE"; then
    _pass "Firefox source retains the exact complete arkenfox MIT notice"
else
    _fail "Firefox source retains the exact complete arkenfox MIT notice"
fi
assert_grep_fixed 'LICENSE_DIR=/usr/share/licenses/noid-privacy' "$KS_FILE" \
    "M16 owns the image license inventory directory"
assert_grep_fixed 'ARKENFOX_LICENSE="$LICENSE_DIR/arkenfox-user.js-MIT.txt"' "$KS_FILE" \
    "M16 installs the arkenfox notice into the image license inventory"
assert_grep_fixed '2bf289bdd22188ccff2bf34c9a20a75c45b84f42f887da7e177d9bfd1bac3c1a' "$KS_FILE" \
    "M16 binds the installed arkenfox notice to the tag-144.0 bytes"

# The generated AutoConfig must contain exactly this five-member lock set.
# Binding each full line prevents an aggregate count from accepting duplicate
# or unrelated preferences while one required lock silently disappears.
EXPECTED_LOCK_PREFS=(
    'lockPref("browser.profiles.enabled", false);'
    'lockPref("browser.profiles.created", false);'
    'lockPref("browser.newtabpage.activity-stream.default.sites", "");'
    'lockPref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts", false);'
    'lockPref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts.havePinned", "");'
)
for expected_lock_pref in "${EXPECTED_LOCK_PREFS[@]}"; do
    assert_eq 1 \
        "$(grep -Fxc -- "    echo '$expected_lock_pref'" "$KS_FILE" || true)" \
        "M16 emits exactly one $expected_lock_pref"
done
assert_grep_fixed 'grep -Fxc -- "$expected_lock_pref" "${FIREFOX_LIB_DIR}/mozilla.cfg"' "$KS_FILE" \
    "M16 verifies every complete lockPref identity after generation"
assert_grep_fixed '"${#EXPECTED_LOCK_PREFS[@]}"' "$KS_FILE" \
    "M16 rejects extra lockPref entries outside the exact expected set"

# --- FPP + provider-neutral DNS prefs verified in canonical source ----------
# These prefs are now embedded (gzip+base64) in M16 user.js. Assert them
# against firefox/noid-firefox-hardening.js (git-tracked source of truth).
if [ -f "$FIREFOX_JS" ]; then
    assert_grep_extended 'privacy\.fingerprintingProtection.*true' "$FIREFOX_JS" "FPP enabled (canonical)"
    assert_grep_extended 'privacy\.resistFingerprinting.*false' "$FIREFOX_JS" "RFP off (canonical, FPP-preferred)"
    assert_not_grep_extended '^[[:space:]]*user_pref\("network\.trr\.' "$FIREFOX_JS" \
        "profile user.js never resets the user-selected Secure DNS mode or provider"
    assert_eq 1 "$(grep -Fxc 'user_pref("network.dns.disableIPv6", false);' "$FIREFOX_JS")" \
        "Firefox retains exactly one active VPN-compatible IPv6 resolver preference"
    assert_not_grep_extended '^[[:space:]]*user_pref\("network\.dns\.disableIPv6",[[:space:]]*true\);' \
        "$FIREFOX_JS" "Firefox does not suppress a provider VPN IPv6/NAT64 path"
    assert_grep_fixed 'provider-compatible system/VPN DNS by default' "$FIREFOX_JS" \
        "canonical Firefox header matches the current resolver contract"
    assert_not_grep 'DoH bootstrap to Quad9' "$FIREFOX_JS" \
        "canonical Firefox header does not advertise the retired DoH path"
    assert_grep_fixed 'defaultPref("network.trr.mode", 5);' "$KS_FILE" \
        "AutoConfig defaults Firefox to the provider-neutral OS/VPN resolver"
    assert_eq 1 \
        "$(grep -Fxc '    '\''defaultPref("doh-rollout.home-region", "global");'\''' "$KS_FILE" || true)" \
        "Firefox seeds exactly one global DoH catalogue without country lookup"
    assert_not_grep_extended '(defaultPref|user_pref|lockPref)\("network\.trr\.(uri|custom_uri|bootstrapAddr)"' \
        "$KS_FILE" "AutoConfig does not force a browser DoH provider or stale bootstrap address"
    assert_not_grep_extended '^[[:space:]]*user_pref\("browser\.uiCustomization\.state"' \
        "$FIREFOX_JS" "profile user.js never reasserts browser-owned toolbar state"
    assert_eq 1 \
        "$(grep -cF -- 'TOOLBAR_DEFAULT_PREF=' "$KS_FILE" || true)" \
        "M16 defines exactly one initial toolbar default"
    assert_not_grep_extended '^[[:space:]]*[A-Za-z_].*\|\| echo 0' "$KS_FILE" \
        "M16 normalizes fallible numeric probes without multi-line substitutions"
    assert_grep_fixed 'grep -Fxc -- "$TOOLBAR_DEFAULT_PREF"' "$KS_FILE" \
        "M16 exact-verifies the initial toolbar default"
    assert_grep_fixed 'assert toolbar["currentVersion"] == 24' "$KS_FILE" \
        "M16 validates the reviewed Firefox CustomizableUI schema"
    assert_grep_fixed 'nav_bar.count("ublock0_raymondhill_net-browser-action") == 1' \
        "$KS_FILE" "M16 validates the initial uBO toolbar placement"
    assert_grep_fixed 'nav_bar.count("reset-pbm-toolbar-button") == 1' \
        "$KS_FILE" "M16 validates the standard toolbar migration"
    assert_grep_fixed 'USER_OWNED_DEFAULT_PREFS=(' "$KS_FILE" \
        "M16 declares the reviewed user-owned Firefox default set"
    assert_grep_fixed 'for expected_user_default in "${USER_OWNED_DEFAULT_PREFS[@]}"; do' \
        "$KS_FILE" "M16 exact-verifies every user-owned Firefox default"
    assert_not_grep_extended \
        '(defaultPref|user_pref|lockPref)\("media\.hardware-video-decoding\.force-enabled"' \
        "$KS_FILE" "M16 never overrides Firefox hardware-video qualification"
    assert_not_grep_extended \
        '(defaultPref|user_pref|lockPref)\("gfx\.webrender\.all"' \
        "$KS_FILE" "M16 never overrides Firefox WebRender qualification"
    assert_grep_fixed 'both settings override Firefox'"'"'s blocklist' "$KS_FILE" \
        "Firefox documentation explains why force switches remain native"
    if python3 - "$KS_FILE" "$FIREFOX_JS" <<'USER_DEFAULTS_PYEOF'
import json
import pathlib
import re
import sys

kickstart = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
source = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
match = re.search(
    r"^USER_OWNED_DEFAULT_PREFS=\(\n(.*?)^\)$",
    kickstart,
    flags=re.MULTILINE | re.DOTALL,
)
assert match
lines = re.findall(
    r"^[ \t]+'(defaultPref\(\"[^\"\n]+\", .*\);)'$",
    match.group(1),
    flags=re.MULTILINE,
)
actual = {}
for line in lines:
    parsed = re.fullmatch(r'defaultPref\("([^"]+)", (.*)\);', line)
    assert parsed
    key, value = parsed.groups()
    assert key not in actual
    actual[key] = json.loads(value)

expected = {
    "browser.startup.page": 1,
    "browser.startup.homepage": "about:home",
    "browser.newtabpage.enabled": True,
    "browser.sessionstore.persist_closed_tabs_between_sessions": False,
    "browser.search.separatePrivateDefault": True,
    "browser.search.separatePrivateDefault.ui.enabled": True,
    "general.smoothScroll": True,
    "privacy.trackingprotection.allow_list.convenience.enabled": False,
    "privacy.globalprivacycontrol.enabled": False,
    "services.sync.engine.passwords": False,
    "services.sync.engine.tabs": False,
    "browser.ipProtection.enabled": False,
    "browser.ipProtection.locationListCache": "",
    "browser.ipProtection.userEnabled": False,
    "browser.ipProtection.autoStartEnabled": False,
    "browser.ipProtection.autoStartPrivateEnabled": False,
    "extensions.ml.enabled": False,
    "browser.ml.chat.enabled": False,
    "browser.ml.chat.shortcuts": False,
    "browser.ml.chat.sidebar": False,
    "browser.tabs.groups.smart.enabled": False,
    "browser.tabs.groups.smart.userEnabled": False,
    "browser.ai.control.default": "blocked",
    "browser.ai.control.sidebarChatbot": "blocked",
    "browser.ai.control.linkPreviewKeyPoints": "blocked",
    "browser.ai.control.smartTabGroups": "blocked",
    "browser.ai.control.translations": "blocked",
    "browser.ai.control.pdfjsAltText": "blocked",
    "browser.ai.control.smartWindow": "blocked",
    "sidebar.main.tools": "syncedtabs,history,bookmarks",
    "sidebar.notification.badge.aichat": False,
    "browser.newtabpage.activity-stream.showSponsored": False,
    "browser.newtabpage.activity-stream.showSponsoredTopSites": False,
    "browser.newtabpage.activity-stream.showSponsoredCheckboxes": False,
    "browser.newtabpage.activity-stream.feeds.section.topstories": False,
    "browser.newtabpage.activity-stream.feeds.topsites": True,
    "browser.newtabpage.activity-stream.feeds.section.highlights": False,
    "browser.newtabpage.activity-stream.feeds.weatherfeed": False,
    "browser.newtabpage.activity-stream.showWeather": False,
    "browser.newtabpage.activity-stream.system.showWeather": False,
    "browser.newtabpage.activity-stream.widgets.weather.enabled": False,
    "browser.newtabpage.activity-stream.widgets.weatherForecast.enabled": False,
    "browser.newtabpage.activity-stream.widgets.system.weather.enabled": False,
    "browser.newtabpage.activity-stream.widgets.system.weatherForecast.enabled": False,
    "browser.newtabpage.activity-stream.weather.locationSearchEnabled": False,
    "browser.newtabpage.activity-stream.nova.enabled": False,
    "browser.urlbar.weather.featureGate": False,
    "browser.urlbar.suggest.weather": False,
    "doh-rollout.home-region": "global",
    "browser.region.network.url": "",
    "browser.region.network.scan": False,
    "browser.region.update.enabled": False,
    "browser.newtabpage.activity-stream.newtabWallpapers.enabled": False,
    "browser.newtabpage.activity-stream.newtabWallpapers.user.enabled": False,
}
assert actual == expected
assert not re.search(
    r'^user_pref\("browser\.ml\.enable",',
    source,
    flags=re.MULTILINE,
)
for key in expected:
    assert not re.search(
        rf'^user_pref\("{re.escape(key)}",',
        source,
        flags=re.MULTILINE,
    ), key
USER_DEFAULTS_PYEOF
    then
        _pass "reviewed Firefox UI/application defaults are exact and absent from profile user.js"
    else
        _fail "reviewed Firefox UI/application defaults are exact and absent from profile user.js"
    fi
    assert_not_grep 'browser\.newtabpage\.activity-stream\.feeds\.wallpaperfeed' \
        "$KS_FILE" "retired Firefox wallpaper-feed pref is absent"
    assert_not_grep 'distribution\.fedora\.bookmarksProcessed' \
        "$KS_FILE" "dead Fedora distributor bookmark marker is absent"
    assert_grep_fixed 'user_pref("security.tls.enable_kyber", true);' "$FIREFOX_JS" \
        "hybrid TLS client capability explicit (canonical)"
    assert_grep_fixed 'user_pref("signon.rememberSignons", false);' "$FIREFOX_JS" \
        "Firefox credential saving is actually disabled"
    assert_grep_fixed 'user_pref("dom.private-attribution.submission.enabled", false);' \
        "$FIREFOX_JS" "Firefox active PPA submission gate is disabled"
    assert_not_grep 'user_pref("dom.private-attribution.enabled"' "$FIREFOX_JS" \
        "retired Firefox PPA master-pref name is not shipped as cosmetic security"
    assert_not_grep 'user_pref("security.qwacs.enabled"' "$FIREFOX_JS" \
        "native Firefox desktop QWAC verification/display is not disabled"
    assert_grep_fixed 'security.qwacs.enabled to @IS_NOT_ANDROID@ (true on' \
        "$FIREFOX_JS" "Firefox source records the exact current QWAC platform default"
    assert_grep_fixed 'desktop, false on Android)' "$FIREFOX_JS" \
        "Firefox source resolves the current QWAC platform macro"
    assert_grep_fixed 'neither overrides the switch nor enables QWAC test' \
        "$FIREFOX_JS" "Firefox source preserves QWAC policy and test-anchor boundaries"
    assert_not_grep 'current Linux.*default remains disabled' "$FIREFOX_JS" \
        "Firefox source does not repeat the disproven Linux-default claim"
    for update_pref in \
        'user_pref("app.update.auto", false);' \
        'user_pref("extensions.update.enabled", false);' \
        'user_pref("extensions.update.autoUpdateDefault", false);' \
        'user_pref("extensions.systemAddon.update.enabled", false);'; do
        assert_grep_fixed "$update_pref" "$FIREFOX_JS" \
            "Firefox background updater is disabled: $update_pref"
    done
    for privacy_pref in \
        'user_pref("browser.pagethumbnails.capturing_disabled", true);' \
        'user_pref("media.eme.enabled", false);' \
        'user_pref("media.gmp-manager.updateEnabled", false);' \
        'user_pref("media.gmp-widevinecdm.enabled", false);' \
        'user_pref("media.gmp-widevinecdm.allow-chromium-update", false);'; do
        assert_eq 1 "$(grep -Fxc -- "$privacy_pref" "$FIREFOX_JS" || true)" \
            "Firefox profile-enforced privacy default is exact: $privacy_pref"
    done
    assert_not_grep 'user_pref("media.eme.enabled", true);' "$FIREFOX_JS" \
        "canonical Firefox profile never silently enables DRM"
    assert_not_grep_extended \
        '^[[:space:]]*user_pref\("browser\.sessionstore\.max_tabs_undo",[[:space:]]*0\);' \
        "$FIREFOX_JS" \
        "closed-tab privacy default preserves current-session Undo Closed Tab"
    assert_grep_fixed 'Ctrl+Shift+T remains available' \
        "$KS_FILE" \
        "Firefox documentation names the preserved current-session recovery UX"
    for retired_pref in \
        app.update.enabled \
        app.update.background.scheduling.enabled \
        browser.contentblocking.report.enabled \
        browser.newtabpage.activity-stream.feeds.telemetry \
        browser.ml.pdf.alt.enabled \
        browser.shell.shortcutFavicons \
        geo.provider.ms-windows-location \
        geo.provider.use_corelocation \
        media.gmp-widevinecdm.autoupdate \
        network.gio.supported-protocols \
        toolkit.telemetry.coverage.opt-out \
        toolkit.winRegisterApplicationRestart; do
        assert_not_grep_fixed "user_pref(\"${retired_pref}\"" "$FIREFOX_JS" \
            "Firefox/Fedora does not ship retired or foreign-platform key: $retired_pref"
    done
fi

for retired_installer_pref in \
    app.update.enabled \
    app.update.background.scheduling.enabled \
    browser.newtabpage.activity-stream.feeds.telemetry \
    datareporting.dau.enabled \
    extensions.pocket.enabled \
    messaging-system.rsexperimentloader.enabled \
    nimbus.testing.testingEnabled \
    toolkit.telemetry.coverage.opt-out; do
    assert_not_grep_fixed "user_pref(\"${retired_installer_pref}\"" "$KS_FILE" \
        "M16 does not claim an inert Firefox 153 installer pref: $retired_installer_pref"
done

# Drift-proof Firefox maintenance contracts: generated payload size is measured
# by the build, Bugzilla owns the affected-version range, and one count constant
# feeds both exact managed-storage verification layers.
assert_not_grep_extended 'embedded as gzip\+base64 \([0-9]+ bytes' "$KS_FILE" \
    "M16 does not embed a manually maintained Firefox source byte count"
assert_not_grep 'Firefox 147-152' "$KS_FILE" \
    "M16 does not freeze Mozilla Bug 2003137 to a stale Firefox range"
assert_grep_fixed 'Mozilla Bug 2003137' "$KS_FILE" \
    "M16 names the upstream XDG profile defect without a stale version ceiling"
assert_grep_fixed 'NoID Privacy owns ongoing release-note, source-default and runtime review' \
    "$KS_FILE" "M16 assigns ongoing Firefox maintenance to NoID Privacy"
assert_not_grep_extended 'potentially final release|final release lands' "$KS_FILE" \
    "M16 contains no speculative arkenfox end-of-life trigger"
assert_not_grep '23 filter lists' "$KS_FILE" \
    "Firefox user guidance does not duplicate the managed filter-list count"
assert_grep_fixed 'manually selected regional/extra lists and uBO' "$KS_FILE" \
    "Firefox guidance discloses the managed regional-list trade-off"
assert_grep_fixed 'do not persist while `toOverwrite.filterLists` is active' \
    "$KS_FILE" "Firefox guidance states exact managed-list replacement semantics"
assert_grep_fixed 'sudo rm -f /usr/lib64/mozilla/managed-storage/uBlock0@raymondhill.net.json' \
    "$KS_FILE" "Firefox guidance gives the system-wide managed-list opt-out"
assert_grep_fixed 'sudo install -o root -g root -m 0644 /usr/share/noid-firefox/uBlock0@raymondhill.net.json' \
    "$KS_FILE" "Firefox guidance gives an exact managed-list restore path"
assert_grep_fixed 'relinquishes the three NoID Privacy-enforced additions' "$KS_FILE" \
    "Firefox guidance names the opt-out protection trade-off"
assert_grep_fixed 'python3 - "$EXPECTED_FILTER_LIST_COUNT"' "$KS_FILE" \
    "M16 passes the canonical filter-list count into its final JSON gate"
assert_grep_fixed 'expected_filter_list_count = int(sys.argv[1])' "$KS_FILE" \
    "M16 final JSON gate parses the canonical filter-list count"
assert_grep_fixed 'assert len(expected_filter_lists) == expected_filter_list_count' \
    "$KS_FILE" "M16 final JSON gate uses the canonical filter-list count"
assert_grep_fixed '"data": {"toOverwrite": {"filterLists": expected_filter_lists}},' \
    "$KS_FILE" "M16 final JSON gate checks the exact narrow uBO policy"
assert_not_grep 'selectedFilterLists' "$KS_FILE" \
    "M16 no longer carries the deprecated backup-format list key"
assert_not_grep 'selfieDelayInSeconds' "$KS_FILE" \
    "M16 leaves uBO's startup-cache delay at the upstream default"
for count_var in \
    FIREFOX_WIDEVINE_ANCHOR_COUNT \
    widevine_anchor_count \
    legacy_root_anchor_count \
    exec_anchor_count \
    relaunch_anchor_count; do
    assert_grep_fixed "${count_var}=\${${count_var}:-0}" "$KS_FILE" \
        "M16 normalizes empty grep counts: $count_var"
done

# --- Step 6d noid-firefox-harden-profile CLI helper (post-absorption) -------
# Context: XDG-autostart firstboot setup hardens only the default Firefox
# profile (one-shot via state-file guard). Update All later initializes a
# safely registered profile with no user.js; a foreign user.js or the exact
# helper-created exclusion preserves opt-out. The helper also supports
# immediate explicit opt-in and --force.
assert_grep_fixed '/usr/local/bin/noid-firefox-harden-profile' "$KS_FILE" "helper install path"
assert_grep_fixed "'HARDEN_EOF'"                               "$KS_FILE" "helper heredoc marker"

# --- Step 6b2 noid-firefox-relax-webrtc escape-hatch -----------------------
assert_grep_fixed '/usr/local/bin/noid-firefox-relax-webrtc' "$KS_FILE" "relax-webrtc CLI install path"
assert_grep_fixed "'RELAX_WEBRTC_EOF'"                       "$KS_FILE" "relax-webrtc heredoc marker"

# Extract the helper script + validate its internal structure
# The deployed WebExtension validator is executed by absolute path. NoID Privacy mounts
# /tmp noexec by design, so executable runtime fixtures belong on /var/tmp.
TMPDIR2=$(mktemp -d /var/tmp/noid-test16.XXXXXX)
# SC2064: single-quote outer + double-quote
# inner so $TMPDIR2 evaluates at trap-run-time, not trap-set-time.
trap 'rm -rf "$TMPDIR2"; [ -z "${REDUCED_FIXTURE:-}" ] || rm -rf "$REDUCED_FIXTURE"; [ -z "${FIREFOX_SETUP_FIXTURE:-}" ] || rm -rf "$FIREFOX_SETUP_FIXTURE"; [ -z "${HARDEN_FIXTURE:-}" ] || rm -rf "$HARDEN_FIXTURE"; [ -z "${FF_OVERLAY_FIXTURE:-}" ] || rm -rf "$FF_OVERLAY_FIXTURE"' EXIT
extract_heredoc "$KS_FILE" "HARDEN_EOF" "$TMPDIR2/harden.sh" || _fail "HARDEN_EOF extraction"
extract_heredoc "$KS_FILE" "FF_PROFILES_EOF" "$TMPDIR2/firefox-profiles.sh" \
    || _fail "FF_PROFILES_EOF extraction"
extract_heredoc "$KS_FILE" "RELAX_FPP_EOF" "$TMPDIR2/relax-fpp.sh" \
    || _fail "RELAX_FPP_EOF extraction"
extract_heredoc "$KS_FILE" "RELAX_WEBRTC_EOF" "$TMPDIR2/relax-webrtc.sh" \
    || _fail "RELAX_WEBRTC_EOF extraction"
extract_heredoc "$KS_FILE" "FIREFOX_DRM_EOF" "$TMPDIR2/firefox-drm.sh" \
    || _fail "FIREFOX_DRM_EOF extraction"
extract_heredoc "$KS_FILE" "FIREFOX_DOC_EOF" "$TMPDIR2/firefox-hardening.md" \
    || _fail "FIREFOX_DOC_EOF extraction"
extract_heredoc "$KS_FILE" "DRM_OVERRIDES_EOF" "$TMPDIR2/drm-overrides.js" \
    || _fail "DRM_OVERRIDES_EOF extraction"
extract_heredoc "$KS_FILE" "PINNED_SITES_PYEOF" "$TMPDIR2/pinned-sites.py" \
    || _fail "PINNED_SITES_PYEOF extraction"
extract_heredoc "$KS_FILE" "NOID_FF_REASSERT_EOF" "$TMPDIR2/firefox-reassert.sh" \
    || _fail "NOID_FF_REASSERT_EOF extraction"
extract_heredoc "$KS_FILE" "WEBEXT_VALIDATOR_PYEOF" \
    "$TMPDIR2/validate-webextension.py" \
    || _fail "WEBEXT_VALIDATOR_PYEOF extraction"
chmod 0755 "$TMPDIR2/validate-webextension.py"
extract_heredoc "$KS_FILE" "UBO_POLICY_VALIDATOR_PYEOF" \
    "$TMPDIR2/validate-ubo-policy.py" \
    || _fail "UBO_POLICY_VALIDATOR_PYEOF extraction"
chmod 0755 "$TMPDIR2/validate-ubo-policy.py"
assert_grep_fixed 'chown root:root "$UBO_POLICY_VALIDATOR"' "$KS_FILE" \
    "uBO policy validator has an explicit root ownership postcondition"
assert_grep_fixed 'restorecon -F "$UBO_POLICY_VALIDATOR"' "$KS_FILE" \
    "uBO policy validator receives its installed SELinux label"
extract_heredoc "$KS_FILE" "UBOMANIFEST_EOF" \
    "$TMPDIR2/ubo-managed-storage.json" \
    || _fail "UBOMANIFEST_EOF extraction"
extract_heredoc "$KS_FILE" "FIREFOX_XPI_SIGNATURE_EOF" \
    "$TMPDIR2/verify-firefox-xpi-signature" \
    || _fail "FIREFOX_XPI_SIGNATURE_EOF extraction"
extract_heredoc "$KS_FILE" "SKEL_EXTENSION_PREFS_EOF" \
    "$TMPDIR2/skel-extension-preferences.json" \
    || _fail "SKEL_EXTENSION_PREFS_EOF extraction"
assert_grep_fixed 'explicit user opt-in through `noid-complete-setup.sh`' \
    "$TMPDIR2/firefox-hardening.md" \
    "Firefox codec guidance names the Silent-Machine opt-in"
assert_grep_fixed '**Module 08 does not enable that service at first boot**' \
    "$TMPDIR2/firefox-hardening.md" \
    "Firefox codec guidance does not claim automatic first-boot provisioning"
assert_grep_fixed '`noid-help 26-optional-packages`, section' \
    "$TMPDIR2/firefox-hardening.md" \
    "Firefox codec guidance points to the shipped canonical help page"
assert_not_grep 'Module 08 codec documentation\|per-GPU / per-codec matrix' \
    "$TMPDIR2/firefox-hardening.md" \
    "Firefox codec guidance names no nonexistent document or matrix"
assert_not_grep_fixed '`--apply`' "$TMPDIR2/firefox-hardening.md" \
    "FPP documentation names no rejected --apply option"
if bash -c '. "$1"; noid_fpp_relaxation_block' _ \
        "$TMPDIR2/firefox-profiles.sh" > "$TMPDIR2/fpp-relaxation-block.js"; then
    _pass "shared helper emits the reviewed FPP block"
else
    _fail "shared helper emits the reviewed FPP block"
fi
if python3 - "$TMPDIR2/firefox-hardening.md" \
        "$TMPDIR2/fpp-relaxation-block.js" <<'FPP_DOC_BLOCK_PYEOF'
from pathlib import Path
import sys

documentation = Path(sys.argv[1]).read_text(encoding="utf-8")
emitted = Path(sys.argv[2]).read_text(encoding="utf-8").rstrip("\n")
anchor = "block at the end of the file:\n\n```\n"
if documentation.count(anchor) != 1:
    raise SystemExit("FPP documentation block anchor is missing or ambiguous")
documented = documentation.split(anchor, 1)[1].split("\n```", 1)[0]
if documented != emitted:
    raise SystemExit("documented FPP block differs from the emitted bytes")
FPP_DOC_BLOCK_PYEOF
then
    _pass "FPP documentation reproduces the emitted marker block byte-for-byte"
else
    _fail "FPP documentation reproduces the emitted marker block byte-for-byte"
fi
assert_cmd_success "Firefox skel extension-permission JSON is exact" \
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8")); assert d == {"uBlock0@raymondhill.net": {"permissions": ["internal:privateBrowsingAllowed"], "origins": [], "data_collection": []}}' \
    "$TMPDIR2/skel-extension-preferences.json"
assert_cmd_success "WebExtension validator Python syntax" \
    python3 -m py_compile "$TMPDIR2/validate-webextension.py"
assert_cmd_success "uBO policy validator Python syntax" \
    python3 -m py_compile "$TMPDIR2/validate-ubo-policy.py"
assert_cmd_success "native Firefox XPI signature helper parses" \
    bash -n "$TMPDIR2/verify-firefox-xpi-signature"
assert_cmd_success "native Firefox XPI signature helper passes ShellCheck" \
    shellcheck -s bash -S warning "$TMPDIR2/verify-firefox-xpi-signature"
assert_grep_fixed '/usr/bin/unshare --user --map-current-user --net' \
    "$TMPDIR2/verify-firefox-xpi-signature" \
    "native signature verification runs without network access"
assert_grep_fixed '--kill-child=KILL --mount-proc' \
    "$TMPDIR2/verify-firefox-xpi-signature" \
    "native signature verifier owns and kills the isolated Firefox PID namespace"
assert_grep_fixed 'addon.get("signedState") == 2' \
    "$TMPDIR2/verify-firefox-xpi-signature" \
    "native signature verification requires Firefox signed state"
assert_grep_fixed 'kill -KILL -- "$child"' \
    "$TMPDIR2/verify-firefox-xpi-signature" \
    "native signature verification has bounded exact-child cleanup"
assert_grep_fixed 'for _ in $(seq 1 300); do' \
    "$TMPDIR2/verify-firefox-xpi-signature" \
    "native signature verification allows a bounded 30-second slow-host window"
SIGNED_STATE_PARSER="$TMPDIR2/firefox-signed-state.py"
extract_heredoc "$TMPDIR2/verify-firefox-xpi-signature" \
    FIREFOX_SIGNED_STATE_PY "$SIGNED_STATE_PARSER" \
    || _fail "FIREFOX_SIGNED_STATE_PY extraction"
printf '%s\n' '{"addons":[{"id":"uBlock0@raymondhill.net","version":"1.73.0","type":"extension","signedState":2,"active":true,"visible":true,"path":"/fixture/uBO.xpi"}]}' \
    > "$TMPDIR2/signed-state.json"
assert_cmd_success "Firefox signed-state parser accepts exact native evidence" \
    python3 "$SIGNED_STATE_PARSER" "$TMPDIR2/signed-state.json" \
        uBlock0@raymondhill.net 1.73.0 /fixture/uBO.xpi
sed 's/"signedState":2/"signedState":0/' "$TMPDIR2/signed-state.json" \
    > "$TMPDIR2/unsigned-state.json"
assert_cmd_failure "Firefox signed-state parser rejects unsigned native evidence" \
    python3 "$SIGNED_STATE_PARSER" "$TMPDIR2/unsigned-state.json" \
        uBlock0@raymondhill.net 1.73.0 /fixture/uBO.xpi

create_test_xpi() {
    local path="$1" identity="$2" version="$3" minimum="$4" maximum="$5" signed="$6"
    python3 - "$path" "$identity" "$version" "$minimum" "$maximum" "$signed" <<'TEST_XPI_PY'
import json
import sys
import zipfile

path, identity, version, minimum, maximum, signed = sys.argv[1:]
gecko = {}
if identity != "-":
    gecko["id"] = identity
if minimum != "-":
    gecko["strict_min_version"] = minimum
if maximum != "-":
    gecko["strict_max_version"] = maximum
manifest = {
    "manifest_version": 2,
    "name": "NoID Privacy structural fixture",
    "version": version,
    "browser_specific_settings": {"gecko": gecko},
}
with zipfile.ZipFile(path, "w") as bundle:
    bundle.writestr("manifest.json", json.dumps(manifest))
    bundle.writestr("background.js", "// fixture\n")
    if signed == "1":
        bundle.writestr("META-INF/manifest.mf", "fixture\n")
        bundle.writestr("META-INF/mozilla.sf", "fixture\n")
        bundle.writestr("META-INF/mozilla.rsa", "fixture\n")
TEST_XPI_PY
}

create_test_xpi "$TMPDIR2/ubo-valid.xpi" uBlock0@raymondhill.net 1.73.0 128.0 '200.*' 1
assert_cmd_success "signed compatible uBO fixture validates" \
    python3 "$TMPDIR2/validate-webextension.py" "$TMPDIR2/ubo-valid.xpi" \
        uBlock0@raymondhill.net 1.73.0 1 150.0
create_test_xpi "$TMPDIR2/ubo-unbounded.xpi" uBlock0@raymondhill.net 1.73.0 128.0 '*' 1
assert_cmd_success "literal wildcard maximum is treated as unbounded" \
    python3 "$TMPDIR2/validate-webextension.py" "$TMPDIR2/ubo-unbounded.xpi" \
        uBlock0@raymondhill.net 1.73.0 1 152.0
create_test_xpi "$TMPDIR2/ubo-unsigned.xpi" uBlock0@raymondhill.net 1.73.0 - - 0
assert_cmd_failure "uBO validator rejects a missing Mozilla signature container" \
    python3 "$TMPDIR2/validate-webextension.py" "$TMPDIR2/ubo-unsigned.xpi" \
        uBlock0@raymondhill.net 1.73.0 1 150.0
create_test_xpi "$TMPDIR2/ubo-wrong-id.xpi" attacker@example.invalid 1.73.0 - - 1
assert_cmd_failure "uBO validator rejects a manifest identity mismatch" \
    python3 "$TMPDIR2/validate-webextension.py" "$TMPDIR2/ubo-wrong-id.xpi" \
        uBlock0@raymondhill.net 1.73.0 1 150.0
create_test_xpi "$TMPDIR2/ubo-incompatible.xpi" uBlock0@raymondhill.net 1.73.0 999.0 - 1
assert_cmd_failure "uBO validator rejects incompatible browser bounds" \
    python3 "$TMPDIR2/validate-webextension.py" "$TMPDIR2/ubo-incompatible.xpi" \
        uBlock0@raymondhill.net 1.73.0 1 150.0
create_test_xpi "$TMPDIR2/legacy-amo-no-id.xpi" - 2.0 128.0 '*' 1
assert_cmd_failure "missing manifest ID is rejected outside a marketplace-bound transaction" \
    python3 "$TMPDIR2/validate-webextension.py" "$TMPDIR2/legacy-amo-no-id.xpi" \
        '{01234567-89ab-cdef-0123-456789abcdef}' 2.0 1 150.0
assert_cmd_success "marketplace-bound legacy AMO artifact may defer ID proof to native Firefox" \
    python3 "$TMPDIR2/validate-webextension.py" "$TMPDIR2/legacy-amo-no-id.xpi" \
        '{01234567-89ab-cdef-0123-456789abcdef}' 2.0 1 150.0 1

# Every future uBO candidate must still support the complete root-managed
# filter-list policy before Update All may publish that XPI.
python3 - "$TMPDIR2/ubo-managed-storage.json" \
    "$TMPDIR2/ubo-policy-valid.xpi" <<'UBO_POLICY_FIXTURE_PY'
import json
import sys
import zipfile

policy_path, xpi_path = sys.argv[1:]
with open(policy_path, encoding="utf-8") as handle:
    policy = json.load(handle)
tokens = policy["data"]["toOverwrite"]["filterLists"]
assets = {
    token: {
        "content": "filters",
        "contentURL": f"assets/fixture/{token}.txt",
    }
    for token in tokens
    if token != "user-filters"
}
manifest = {
    "manifest_version": 2,
    "name": "uBO policy fixture",
    "version": "1.73.0",
    "browser_specific_settings": {
        "gecko": {"id": "uBlock0@raymondhill.net"},
    },
}
managed_schema = {
    "properties": {
        "toOverwrite": {
            "properties": {
                "filterLists": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
        },
    },
}
with zipfile.ZipFile(xpi_path, "w") as archive:
    archive.writestr("manifest.json", json.dumps(manifest))
    archive.writestr("managed_storage.json", json.dumps(managed_schema))
    archive.writestr("assets/assets.json", json.dumps(assets))
UBO_POLICY_FIXTURE_PY
assert_cmd_success "uBO policy matches every candidate fixture asset" \
    python3 "$TMPDIR2/validate-ubo-policy.py" \
        "$TMPDIR2/ubo-policy-valid.xpi" \
        "$TMPDIR2/ubo-managed-storage.json"
python3 - "$TMPDIR2/ubo-managed-storage.json" \
    "$TMPDIR2/ubo-policy-unsupported.json" <<'UBO_POLICY_MUTATE_PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    policy = json.load(handle)
policy["data"]["toOverwrite"]["filterLists"].append("removed-upstream-list")
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(policy, handle)
UBO_POLICY_MUTATE_PY
assert_cmd_failure "uBO policy gate rejects a removed candidate list token" \
    python3 "$TMPDIR2/validate-ubo-policy.py" \
        "$TMPDIR2/ubo-policy-valid.xpi" \
        "$TMPDIR2/ubo-policy-unsupported.json"
python3 - "$TMPDIR2/ubo-managed-storage.json" \
    "$TMPDIR2/ubo-policy-legacy.json" <<'UBO_POLICY_LEGACY_PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    policy = json.load(handle)
policy["data"] = {"adminSettings": "{}"}
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(policy, handle)
UBO_POLICY_LEGACY_PY
assert_cmd_failure "uBO policy gate rejects deprecated backup-format policy" \
    python3 "$TMPDIR2/validate-ubo-policy.py" \
        "$TMPDIR2/ubo-policy-valid.xpi" \
        "$TMPDIR2/ubo-policy-legacy.json"

# helper must be bash -n clean
if bash -n "$TMPDIR2/harden.sh" 2>/dev/null; then
    _pass "harden helper: bash -n clean"
else
    _fail "harden helper: bash -n errors"
fi
HARDEN_HELP_OUT="$TMPDIR2/harden-help.out"
if env HOME="$TMPDIR2/nonexistent-home" XDG_CONFIG_HOME="$TMPDIR2/nonexistent-config" \
    bash "$TMPDIR2/harden.sh" --help >"$HARDEN_HELP_OUT" 2>&1; then
    _pass "harden helper: --help is independent of install, profile, and lock state"
else
    _fail "harden helper: --help is independent of install, profile, and lock state"
fi
assert_grep_fixed '75 another profile operation holds the lock / Firefox still running' \
    "$HARDEN_HELP_OUT" "harden helper help includes retry exit code 75"
assert_grep_fixed 'and reset FPP/WebRTC opt-ins' "$HARDEN_HELP_OUT" \
    "harden helper help discloses the force-reset compatibility trade-off"
assert_not_grep '^ERROR:' "$HARDEN_HELP_OUT" \
    "harden helper help does not enter runtime prerequisite checks"
assert_not_grep '^set -uo pipefail$' "$HARDEN_HELP_OUT" \
    "harden helper help stops at the comment header"
assert_cmd_success "shared Firefox profile library: bash -n clean" \
    bash -n "$TMPDIR2/firefox-profiles.sh"
assert_grep_fixed 'firefox_process_active()' "$TMPDIR2/firefox-profiles.sh" \
    "shared profile helper owns process-state-aware Firefox detection"
assert_cmd_success "a live Firefox candidate remains active" \
    env FIREFOX_PROFILE_LIBRARY="$TMPDIR2/firefox-profiles.sh" bash -c '
        . "$FIREFOX_PROFILE_LIBRARY"
        pgrep() { printf "%s\n" "$$"; }
        firefox_process_active
    '
assert_cmd_success "an unreaped Firefox candidate is inactive" \
    python3 - "$TMPDIR2/firefox-profiles.sh" <<'FF_ZOMBIE_FIXTURE_PYEOF'
import os
import pathlib
import subprocess
import sys
import time

library = sys.argv[1]
child = os.fork()
if child == 0:
    os._exit(0)
try:
    status = pathlib.Path(f"/proc/{child}/status")
    for _ in range(100):
        if status.exists():
            fields = {
                line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                for line in status.read_text(encoding="utf-8").splitlines()
                if ":" in line
            }
            if fields.get("State", "").startswith("Z"):
                break
        time.sleep(0.02)
    else:
        raise SystemExit("fixture child did not reach the zombie state")
    environment = os.environ.copy()
    environment["FIREFOX_ZOMBIE_PID"] = str(child)
    result = subprocess.run(
        [
            "bash", "-c",
            '. "$1"; pgrep() { printf "%s\\n" "$FIREFOX_ZOMBIE_PID"; }; '
            '! firefox_process_active',
            "bash", library,
        ],
        env=environment,
        check=False,
    )
    if result.returncode:
        raise SystemExit(result.returncode)
finally:
    os.waitpid(child, 0)
FF_ZOMBIE_FIXTURE_PYEOF

run_firefox_launch_arg_fixture() {
    bash -s -- "$TMPDIR2/firefox-profiles.sh" <<'FF_LAUNCH_ARG_FIXTURE_EOF'
set -euo pipefail
library=$1
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
export HOME="$fixture/home"
export XDG_CONFIG_HOME="$HOME/config"
root="$XDG_CONFIG_HOME/mozilla/firefox"
mkdir -p "$root/hash.default-release" "$root/hash.playground"
chmod 0700 "$HOME" "$XDG_CONFIG_HOME" \
    "$XDG_CONFIG_HOME/mozilla" "$root" \
    "$root/hash.default-release" "$root/hash.playground"
cat > "$root/profiles.ini" <<'FF_LAUNCH_PROFILES_EOF'
[Profile1]
Name=playground
IsRelative=1
Path=hash.playground

[Profile0]
Name=default-release
IsRelative=1
Path=hash.default-release
Default=1

[Profile2]
Name=external-absolute
IsRelative=0
Path=/user/chosen/external-profile

[General]
StartWithLastProfile=1
Version=2
FF_LAUNCH_PROFILES_EOF
chmod 0600 "$root/profiles.ini"
. "$library"

prepare_firefox_launch_args --new-window https://example.invalid/
[[ ${#NOID_FF_LAUNCH_ARGS[@]} -eq 4 ]]
[[ ${NOID_FF_LAUNCH_ARGS[0]} == --profile ]]
[[ ${NOID_FF_LAUNCH_ARGS[1]} == "$root/hash.default-release" ]]
[[ ${NOID_FF_LAUNCH_ARGS[2]} == --new-window ]]
[[ ${NOID_FF_LAUNCH_ARGS[3]} == https://example.invalid/ ]]

prepare_firefox_launch_args -P playground -no-remote
[[ ${#NOID_FF_LAUNCH_ARGS[@]} -eq 3 ]]
[[ ${NOID_FF_LAUNCH_ARGS[0]} == --profile ]]
[[ ${NOID_FF_LAUNCH_ARGS[1]} == "$root/hash.playground" ]]
[[ ${NOID_FF_LAUNCH_ARGS[2]} == -no-remote ]]

prepare_firefox_launch_args -pplayground --safe-mode
[[ ${#NOID_FF_LAUNCH_ARGS[@]} -eq 3 ]]
[[ ${NOID_FF_LAUNCH_ARGS[0]} == --profile ]]
[[ ${NOID_FF_LAUNCH_ARGS[1]} == "$root/hash.playground" ]]
[[ ${NOID_FF_LAUNCH_ARGS[2]} == --safe-mode ]]

for ordinary_option in -private-window -preferences -purgecaches; do
    prepare_firefox_launch_args "$ordinary_option"
    [[ ${#NOID_FF_LAUNCH_ARGS[@]} -eq 3 ]]
    [[ ${NOID_FF_LAUNCH_ARGS[0]} == --profile ]]
    [[ ${NOID_FF_LAUNCH_ARGS[1]} == "$root/hash.default-release" ]]
    [[ ${NOID_FF_LAUNCH_ARGS[2]} == "$ordinary_option" ]]
done
prepare_firefox_launch_args -profilemanager
[[ ${NOID_FF_LAUNCH_ARGS[*]} == -profilemanager ]]

prepare_firefox_launch_args --profile /user/chosen --private-window
[[ ${NOID_FF_LAUNCH_ARGS[*]} == \
    "--profile /user/chosen --private-window" ]]
prepare_firefox_launch_args --ProfileManager
[[ ${NOID_FF_LAUNCH_ARGS[*]} == --ProfileManager ]]
prepare_firefox_launch_args -P external-profile -no-remote
[[ ${NOID_FF_LAUNCH_ARGS[*]} == \
    "-P external-profile -no-remote" ]]

mv "$root/profiles.ini" "$root/profiles.ini.absent"
if prepare_firefox_launch_args about:newtab; then
    exit 1
fi
prepare_firefox_launch_args --version
[[ ${NOID_FF_LAUNCH_ARGS[*]} == --version ]]
FF_LAUNCH_ARG_FIXTURE_EOF
}

assert_cmd_success \
    "Firefox launcher binds safe XDG profiles while preserving explicit user selectors" \
    run_firefox_launch_arg_fixture
assert_cmd_success "Firefox FPP relaxation helper: bash -n clean" \
    bash -n "$TMPDIR2/relax-fpp.sh"
assert_cmd_success "Firefox WebRTC relaxation helper: bash -n clean" \
    bash -n "$TMPDIR2/relax-webrtc.sh"
assert_grep_fixed 'They reduce candidate exposure but cannot guarantee' \
    "$TMPDIR2/relax-webrtc.sh" \
    "WebRTC escape hatch states the remaining address-disclosure limit"
assert_not_grep 'STUN only ever sees the VPN address' \
    "$TMPDIR2/relax-webrtc.sh" \
    "WebRTC escape hatch makes no VPN-dependent leak guarantee"
assert_cmd_success "Firefox DRM consent helper: bash -n clean" \
    bash -n "$TMPDIR2/firefox-drm.sh"
assert_cmd_success "Firefox DRM consent helper: ShellCheck clean" \
    shellcheck -s bash -S warning "$TMPDIR2/firefox-drm.sh"
assert_eq 1 "$(grep -Fxc '// NOID-DRM-OPT-IN-BEGIN' "$TMPDIR2/drm-overrides.js" || true)" \
    "DRM overlay has one exact begin marker"
assert_eq 1 "$(grep -Fxc '// NOID-DRM-OPT-IN-END' "$TMPDIR2/drm-overrides.js" || true)" \
    "DRM overlay has one exact end marker"
for drm_pref in \
    'user_pref("media.eme.enabled", true);' \
    'user_pref("media.gmp-manager.updateEnabled", true);' \
    'user_pref("media.gmp-widevinecdm.enabled", true);' \
    'user_pref("media.gmp-widevinecdm.allow-chromium-update", true);'; do
    assert_eq 1 "$(grep -Fxc -- "$drm_pref" "$TMPDIR2/drm-overrides.js" || true)" \
        "DRM overlay contains one exact inverse: $drm_pref"
done
assert_cmd_success "local pinned-site generator executes" \
    python3 "$TMPDIR2/pinned-sites.py" "$TMPDIR2/generated-mozilla.cfg"
assert_cmd_success "all eight shipped pins have local 96px data-URI icons" \
    python3 - "$TMPDIR2/generated-mozilla.cfg" <<'PIN_TEST_PYEOF'
import json, re, sys
line = open(sys.argv[1], encoding="utf-8").read().strip()
match = re.fullmatch(
    r'defaultPref\("browser\.newtabpage\.pinned", ("(?:\\.|[^"\\])*")\);',
    line,
)
assert match
pins = json.loads(json.loads(match.group(1)))
assert len(pins) == 8
assert len({pin["url"] for pin in pins}) == 8
assert pins[0]["url"] == "https://noid-privacy.com/linux.html"
assert all(pin["favicon"].startswith("data:image/svg+xml,%3Csvg") for pin in pins)
assert all(pin["faviconSize"] == 96 for pin in pins)
PIN_TEST_PYEOF
assert_cmd_success "Firefox package-update reassert is valid bash" \
    bash -n "$TMPDIR2/firefox-reassert.sh"
assert_grep_fixed "rpm -q --qf '%{FILEDIGESTALGO}' firefox" \
    "$TMPDIR2/firefox-reassert.sh" \
    "future overlay generation requires SHA-256 RPM metadata"
assert_grep_fixed 'actual=$(sha256sum "$path"' "$TMPDIR2/firefox-reassert.sh" \
    "vendor inputs must match their signed RPM payload"
assert_grep_fixed 'mv -fT -- "$launcher_tmp" "$owned_launcher"' "$TMPDIR2/firefox-reassert.sh" \
    "owned Firefox launcher is atomically published"
assert_grep_fixed 'mv -fT -- "$desktop_tmp" "$owned_desktop"' "$TMPDIR2/firefox-reassert.sh" \
    "owned Firefox desktop overlay is atomically published"
assert_grep_fixed 'desktop_stage_dir=$(mktemp -d /usr/local/share/applications/.noid-firefox-overlay.XXXXXXXX)' \
    "$TMPDIR2/firefox-reassert.sh" \
    "Firefox desktop overlay stages below a private same-filesystem directory"
assert_grep_fixed 'desktop_tmp="$desktop_stage_dir/org.mozilla.firefox.desktop"' \
    "$TMPDIR2/firefox-reassert.sh" \
    "private Firefox staging retains the validator-required desktop suffix"
assert_not_grep 'mktemp --suffix=.desktop /usr/local/share/applications/' \
    "$TMPDIR2/firefox-reassert.sh" \
    "no unreadable temporary desktop entry is exposed to XDG monitors"
assert_not_grep_extended 'rpm-verify-allowlist|sed -i.*[[:space:]]"\$vendor_(launcher|desktop)"$' \
    "$TMPDIR2/firefox-reassert.sh" \
    "Firefox generator never normalizes or edits vendor RPM payloads"
assert_not_grep 'cat > /usr/lib64/firefox/distribution/distribution.ini' "$KS_FILE" \
    "Firefox distribution.ini remains package-owned and pristine"
for firefox_action_package in firefox firefox-langpacks; do
    assert_grep_fixed "post_transaction:${firefox_action_package}:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-firefox-reassert\\ >/dev/null" "$KS_FILE" \
        "$firefox_action_package action is host-scoped, isolates stdout and makes failure transaction-visible"
done

# Exercise the real overlay generator against pristine mock RPM payloads. This
# catches path/publication bugs that token checks cannot, and proves a changed
# vendor payload fails before replacing the last known-good owned overlay.
FF_OVERLAY_FIXTURE=$(mktemp -d "$PROJECT_ROOT/.test-firefox-overlay.XXXXXXXX")
mkdir -p "$FF_OVERLAY_FIXTURE/vendor/applications" \
    "$FF_OVERLAY_FIXTURE/owned/bin" "$FF_OVERLAY_FIXTURE/owned/applications" \
    "$FF_OVERLAY_FIXTURE/langpacks" "$FF_OVERLAY_FIXTURE/dist-extensions" \
    "$FF_OVERLAY_FIXTURE/mock-bin" "$FF_OVERLAY_FIXTURE/autoconfig-cache" \
    "$FF_OVERLAY_FIXTURE/firefox/defaults/pref"
printf '%s\n' 'current German langpack bytes' \
    > "$FF_OVERLAY_FIXTURE/langpacks/langpack-de@firefox.mozilla.org.xpi"
printf '%s\n' 'current French langpack bytes' \
    > "$FF_OVERLAY_FIXTURE/langpacks/langpack-fr@firefox.mozilla.org.xpi"
printf '%s\n' 'current regional Spanish langpack bytes' \
    > "$FF_OVERLAY_FIXTURE/langpacks/langpack-es-AR@firefox.mozilla.org.xpi"
ln -s 'langpack-es-AR@firefox.mozilla.org.xpi' \
    "$FF_OVERLAY_FIXTURE/langpacks/langpack-es@firefox.mozilla.org.xpi"
ln -s 'langpack-pt-PT@firefox.mozilla.org.xpi' \
    "$FF_OVERLAY_FIXTURE/langpacks/langpack-pt@firefox.mozilla.org.xpi"
printf '%s\n' 'outdated German langpack bytes' \
    > "$FF_OVERLAY_FIXTURE/dist-extensions/langpack-de@firefox.mozilla.org.xpi"
printf '%s\n' 'stale locale bytes' \
    > "$FF_OVERLAY_FIXTURE/dist-extensions/langpack-stale@firefox.mozilla.org.xpi"
printf '%s\n' '// canonical Firefox policy fixture' \
    > "$FF_OVERLAY_FIXTURE/autoconfig-cache/mozilla.cfg"
printf '%s\n' 'pref("general.config.filename", "mozilla.cfg");' \
    > "$FF_OVERLAY_FIXTURE/autoconfig-cache/autoconfig.js"
printf '%s\n' 'pref("intl.locale.requested", "");' \
    > "$FF_OVERLAY_FIXTURE/autoconfig-cache/noid-locale.js"
cat > "$FF_OVERLAY_FIXTURE/vendor/firefox" <<'FF_VENDOR_LAUNCHER_EOF'
#!/usr/bin/bash
if [ -d "$HOME/.mozilla" ]; then
  MOZ_CONFIG_DIR="$HOME/.mozilla"
else
  MOZ_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/mozilla"
fi
MOZ_PROGRAM=/bin/true
export MOZ_APP_LAUNCHER="/usr/bin/firefox"
if [ -d "$MOZ_CONFIG_DIR" ]; then
    (restorecon -vr $MOZ_CONFIG_DIR/firefox/*/gmp-widevinecdm/* &)
fi
exec $MOZ_PROGRAM "$@"
FF_VENDOR_LAUNCHER_EOF
cat > "$FF_OVERLAY_FIXTURE/vendor/applications/org.mozilla.firefox.desktop" <<'FF_VENDOR_DESKTOP_EOF'
[Desktop Entry]
Type=Application
Name=Firefox
Exec=firefox %u
Actions=new-window;new-private-window;profile-manager-window;
[Desktop Action new-window]
Name=New Window
Exec=firefox --new-window %u
[Desktop Action new-private-window]
Name=New Private Window
Exec=firefox --private-window %u
[Desktop Action profile-manager-window]
Name=Profile Manager
Exec=firefox --ProfileManager
FF_VENDOR_DESKTOP_EOF
chmod 0755 "$FF_OVERLAY_FIXTURE/vendor/firefox"
sed -i "s#/usr/bin/firefox#$FF_OVERLAY_FIXTURE/vendor/firefox#" \
    "$FF_OVERLAY_FIXTURE/vendor/firefox"
cat > "$FF_OVERLAY_FIXTURE/mock-bin/rpm" <<'FF_MOCK_RPM_EOF'
#!/usr/bin/bash
case "$*" in
    *FILEDIGESTALGO*) printf '8' ;;
    *FILESTATES*FILELINKTOS*FILEDIGESTS*)
        printf '%s\t0\t\t%s\n' "$FF_LANGPACK_DE" "$FF_LANGPACK_DE_DIGEST"
        printf '%s\t0\t\t%s\n' "$FF_LANGPACK_FR" "$FF_LANGPACK_FR_DIGEST"
        printf '%s\t0\t\t%s\n' "$FF_LANGPACK_ES_AR" "$FF_LANGPACK_ES_AR_DIGEST"
        printf '%s\t0\t%s\t\n' "$FF_LANGPACK_ES" \
            'langpack-es-AR@firefox.mozilla.org.xpi'
        printf '%s\t2\t\t%s\n' "$FF_LANGPACK_PT_PT" \
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        printf '%s\t0\t%s\t\n' "$FF_LANGPACK_PT" \
            'langpack-pt-PT@firefox.mozilla.org.xpi'
        ;;
    *FILEDIGESTS*)
        case "${FF_MOCK_RPM_DIGEST_MODE:-}" in
            duplicate)
                printf '%s\t%s\n' "$FF_VENDOR_LAUNCHER" "$FF_VENDOR_LAUNCHER_DIGEST"
                printf '%s\t%s\n' "$FF_VENDOR_LAUNCHER" "$FF_VENDOR_LAUNCHER_DIGEST"
                printf '%s\t%s\n' "$FF_VENDOR_DESKTOP" "$FF_VENDOR_DESKTOP_DIGEST"
                ;;
            empty)
                printf '%s\t%s\n' "$FF_VENDOR_LAUNCHER" ""
                printf '%s\t%s\n' "$FF_VENDOR_DESKTOP" "$FF_VENDOR_DESKTOP_DIGEST"
                ;;
            *)
                printf '%s\t%s\n' "$FF_VENDOR_LAUNCHER" "$FF_VENDOR_LAUNCHER_DIGEST"
                printf '%s\t%s\n' "$FF_VENDOR_DESKTOP" "$FF_VENDOR_DESKTOP_DIGEST"
                ;;
        esac
        ;;
    *) exit 2 ;;
esac
FF_MOCK_RPM_EOF
chmod 0755 "$FF_OVERLAY_FIXTURE/mock-bin/rpm"
for mock in restorecon logger chown; do
    ln -s /usr/bin/true "$FF_OVERLAY_FIXTURE/mock-bin/$mock"
done
sed \
    -e 's/-o root -g root //g' \
    -e "s#^PATH=/usr/sbin:/usr/bin\$#PATH=$FF_OVERLAY_FIXTURE/mock-bin:/usr/sbin:/usr/bin#" \
    -e "s#/usr/share/noid-firefox#$FF_OVERLAY_FIXTURE/autoconfig-cache#g" \
    -e "s#/usr/lib64/firefox/defaults/pref#$FF_OVERLAY_FIXTURE/firefox/defaults/pref#g" \
    -e "s#/usr/lib64/firefox/mozilla.cfg#$FF_OVERLAY_FIXTURE/firefox/mozilla.cfg#g" \
    -e "s#/usr/local/share/applications#$FF_OVERLAY_FIXTURE/owned/applications#g" \
    -e "s#/usr/local/bin#$FF_OVERLAY_FIXTURE/owned/bin#g" \
    -e "s#/usr/share/applications/org.mozilla.firefox.desktop#$FF_OVERLAY_FIXTURE/vendor/applications/org.mozilla.firefox.desktop#g" \
    -e "s#/usr/bin/firefox#$FF_OVERLAY_FIXTURE/vendor/firefox#g" \
    -e "s#/usr/lib64/firefox/distribution/extensions#$FF_OVERLAY_FIXTURE/dist-extensions#g" \
    -e "s#/usr/lib64/firefox/langpacks#$FF_OVERLAY_FIXTURE/langpacks#g" \
    -e "s#/run/noid-firefox-overlay.lock#$FF_OVERLAY_FIXTURE/overlay.lock#g" \
    "$TMPDIR2/firefox-reassert.sh" > "$FF_OVERLAY_FIXTURE/reassert.sh"
chmod 0755 "$FF_OVERLAY_FIXTURE/reassert.sh"
FF_VENDOR_LAUNCHER="$FF_OVERLAY_FIXTURE/vendor/firefox"
FF_VENDOR_DESKTOP="$FF_OVERLAY_FIXTURE/vendor/applications/org.mozilla.firefox.desktop"
FF_LANGPACK_DE="$FF_OVERLAY_FIXTURE/langpacks/langpack-de@firefox.mozilla.org.xpi"
FF_LANGPACK_FR="$FF_OVERLAY_FIXTURE/langpacks/langpack-fr@firefox.mozilla.org.xpi"
FF_LANGPACK_ES_AR="$FF_OVERLAY_FIXTURE/langpacks/langpack-es-AR@firefox.mozilla.org.xpi"
FF_LANGPACK_ES="$FF_OVERLAY_FIXTURE/langpacks/langpack-es@firefox.mozilla.org.xpi"
FF_LANGPACK_PT_PT="$FF_OVERLAY_FIXTURE/langpacks/langpack-pt-PT@firefox.mozilla.org.xpi"
FF_LANGPACK_PT="$FF_OVERLAY_FIXTURE/langpacks/langpack-pt@firefox.mozilla.org.xpi"
FF_VENDOR_LAUNCHER_DIGEST=$(sha256sum "$FF_VENDOR_LAUNCHER" | awk '{print $1}')
FF_VENDOR_DESKTOP_DIGEST=$(sha256sum "$FF_VENDOR_DESKTOP" | awk '{print $1}')
FF_LANGPACK_DE_DIGEST=$(sha256sum "$FF_LANGPACK_DE" | awk '{print $1}')
FF_LANGPACK_FR_DIGEST=$(sha256sum "$FF_LANGPACK_FR" | awk '{print $1}')
FF_LANGPACK_ES_AR_DIGEST=$(sha256sum "$FF_LANGPACK_ES_AR" | awk '{print $1}')
export FF_VENDOR_LAUNCHER FF_VENDOR_DESKTOP \
    FF_VENDOR_LAUNCHER_DIGEST FF_VENDOR_DESKTOP_DIGEST \
    FF_LANGPACK_DE FF_LANGPACK_FR FF_LANGPACK_ES_AR FF_LANGPACK_ES \
    FF_LANGPACK_PT_PT FF_LANGPACK_PT FF_LANGPACK_DE_DIGEST \
    FF_LANGPACK_FR_DIGEST FF_LANGPACK_ES_AR_DIGEST
ff_vendor_before=$(sha256sum "$FF_VENDOR_LAUNCHER" "$FF_VENDOR_DESKTOP")
if PATH="$FF_OVERLAY_FIXTURE/mock-bin:$PATH" bash "$FF_OVERLAY_FIXTURE/reassert.sh"; then
    _pass "Firefox overlay generator executes against pristine signed-payload fixture"
else
    _fail "Firefox overlay generator executes against pristine signed-payload fixture"
fi
assert_eq \
    "$(printf '%s\n' \
        'langpack-de@firefox.mozilla.org.xpi' \
        'langpack-es-AR@firefox.mozilla.org.xpi' \
        'langpack-es@firefox.mozilla.org.xpi' \
        'langpack-fr@firefox.mozilla.org.xpi' | LC_ALL=C sort)" \
    "$(find "$FF_OVERLAY_FIXTURE/dist-extensions" -maxdepth 1 -type f -name 'langpack-*.xpi' -printf '%f\n' | LC_ALL=C sort)" \
    "Firefox reassert converges regular payloads plus resolvable signed aliases"
assert_cmd_success "regular German langpack bytes are current" \
    cmp -s "$FF_LANGPACK_DE" \
    "$FF_OVERLAY_FIXTURE/dist-extensions/$(basename "$FF_LANGPACK_DE")"
assert_cmd_success "regular French langpack bytes are current" \
    cmp -s "$FF_LANGPACK_FR" \
    "$FF_OVERLAY_FIXTURE/dist-extensions/$(basename "$FF_LANGPACK_FR")"
assert_cmd_success "regional Spanish langpack bytes are current" \
    cmp -s "$FF_LANGPACK_ES_AR" \
    "$FF_OVERLAY_FIXTURE/dist-extensions/$(basename "$FF_LANGPACK_ES_AR")"
assert_cmd_success "signed generic Spanish alias publishes target bytes as a regular XPI" \
    cmp -s "$FF_LANGPACK_ES_AR" \
    "$FF_OVERLAY_FIXTURE/dist-extensions/$(basename "$FF_LANGPACK_ES")"
if [ ! -e "$FF_OVERLAY_FIXTURE/dist-extensions/$(basename "$FF_LANGPACK_PT")" ]; then
    _pass "Firefox reassert skips an RPM alias whose language-filtered target is absent"
else
    _fail "Firefox reassert skips an RPM alias whose language-filtered target is absent"
fi
if [ ! -e "$FF_OVERLAY_FIXTURE/dist-extensions/langpack-stale@firefox.mozilla.org.xpi" ]; then
    _pass "Firefox reassert removes a stale distribution langpack"
else
    _fail "Firefox reassert removes a stale distribution langpack"
fi
ff_langpack_before=$(sha256sum \
    "$FF_OVERLAY_FIXTURE/dist-extensions/langpack-de@firefox.mozilla.org.xpi")
printf '%s\n' 'future German bytes must not publish after failed preflight' \
    > "$FF_OVERLAY_FIXTURE/langpacks/langpack-de@firefox.mozilla.org.xpi"
FF_LANGPACK_DE_DIGEST=$(sha256sum "$FF_LANGPACK_DE" | awk '{print $1}')
export FF_LANGPACK_DE_DIGEST
ln -sfn "$FF_LANGPACK_DE" "$FF_LANGPACK_ES"
assert_cmd_failure "Firefox reassert rejects a package alias whose link text was replaced" \
    env PATH="$FF_OVERLAY_FIXTURE/mock-bin:$PATH" \
    bash "$FF_OVERLAY_FIXTURE/reassert.sh"
assert_eq "$ff_langpack_before" \
    "$(sha256sum "$FF_OVERLAY_FIXTURE/dist-extensions/langpack-de@firefox.mozilla.org.xpi")" \
    "failed source preflight preserves the complete installed langpack set"
ln -sfn 'langpack-es-AR@firefox.mozilla.org.xpi' "$FF_LANGPACK_ES"
printf '%s\n' 'current German langpack bytes' \
    > "$FF_OVERLAY_FIXTURE/langpacks/langpack-de@firefox.mozilla.org.xpi"
FF_LANGPACK_DE_DIGEST=$(sha256sum "$FF_LANGPACK_DE" | awk '{print $1}')
export FF_LANGPACK_DE_DIGEST
for autoconfig_file in mozilla.cfg autoconfig.js noid-locale.js; do
    case "$autoconfig_file" in
        mozilla.cfg) autoconfig_dst="$FF_OVERLAY_FIXTURE/firefox/mozilla.cfg" ;;
        *) autoconfig_dst="$FF_OVERLAY_FIXTURE/firefox/defaults/pref/$autoconfig_file" ;;
    esac
    assert_cmd_success "$autoconfig_file is restored byte-exactly" \
        cmp -s "$FF_OVERLAY_FIXTURE/autoconfig-cache/$autoconfig_file" \
        "$autoconfig_dst"
done
printf '%s\n' '// stock overwrite' > "$FF_OVERLAY_FIXTURE/firefox/mozilla.cfg"
assert_cmd_success "Firefox reassert repairs an AutoConfig package stomp" \
    env PATH="$FF_OVERLAY_FIXTURE/mock-bin:$PATH" \
    bash "$FF_OVERLAY_FIXTURE/reassert.sh"
assert_cmd_success "repaired Firefox AutoConfig matches its canonical cache" \
    cmp -s "$FF_OVERLAY_FIXTURE/autoconfig-cache/mozilla.cfg" \
    "$FF_OVERLAY_FIXTURE/firefox/mozilla.cfg"
mv "$FF_OVERLAY_FIXTURE/autoconfig-cache/autoconfig.js" \
    "$FF_OVERLAY_FIXTURE/autoconfig-cache/autoconfig.js.missing"
ff_autoconfig_before=$(sha256sum "$FF_OVERLAY_FIXTURE/firefox/mozilla.cfg" \
    "$FF_OVERLAY_FIXTURE/firefox/defaults/pref/noid-locale.js")
assert_cmd_failure "Firefox reassert fails closed on a partial canonical cache" \
    env PATH="$FF_OVERLAY_FIXTURE/mock-bin:$PATH" \
    bash "$FF_OVERLAY_FIXTURE/reassert.sh"
assert_eq "$ff_autoconfig_before" \
    "$(sha256sum "$FF_OVERLAY_FIXTURE/firefox/mozilla.cfg" \
        "$FF_OVERLAY_FIXTURE/firefox/defaults/pref/noid-locale.js")" \
    "failed cache preflight preserves the other AutoConfig destinations"
mv "$FF_OVERLAY_FIXTURE/autoconfig-cache/autoconfig.js.missing" \
    "$FF_OVERLAY_FIXTURE/autoconfig-cache/autoconfig.js"

for ff_digest_mode in duplicate empty; do
    ff_digest_before=$(sha256sum \
        "$FF_OVERLAY_FIXTURE/owned/bin/firefox" \
        "$FF_OVERLAY_FIXTURE/owned/applications/org.mozilla.firefox.desktop")
    set +e
    ff_digest_output=$(
        FF_MOCK_RPM_DIGEST_MODE="$ff_digest_mode" \
        PATH="$FF_OVERLAY_FIXTURE/mock-bin:$PATH" \
            bash "$FF_OVERLAY_FIXTURE/reassert.sh" 2>&1
    )
    ff_digest_rc=$?
    set -e
    ff_digest_after=$(sha256sum \
        "$FF_OVERLAY_FIXTURE/owned/bin/firefox" \
        "$FF_OVERLAY_FIXTURE/owned/applications/org.mozilla.firefox.desktop")
    if [ "$ff_digest_rc" -eq 1 ] \
       && printf '%s\n' "$ff_digest_output" \
            | grep -qF 'cannot obtain RPM digest' \
       && [ "$ff_digest_before" = "$ff_digest_after" ]; then
        _pass "a $ff_digest_mode RPM digest line fails closed before any overlay mutation"
    else
        _fail "a $ff_digest_mode RPM digest line was accepted or mutated overlays (rc=$ff_digest_rc)"
    fi
done
assert_grep_fixed 'prepare_firefox_launch_args "$@"' \
    "$FF_OVERLAY_FIXTURE/owned/bin/firefox" \
    "derived Firefox launcher resolves the canonical profile by path"
assert_grep_fixed 'if [ -f "$HOME/.mozilla/firefox/profiles.ini" ]; then' \
    "$FF_OVERLAY_FIXTURE/owned/bin/firefox" \
    "derived Firefox launcher selects legacy Fedora helpers only for a registered legacy tree"
assert_grep_fixed "export MOZ_APP_LAUNCHER=\"$FF_OVERLAY_FIXTURE/owned/bin/firefox\"" \
    "$FF_OVERLAY_FIXTURE/owned/bin/firefox" \
    "Firefox self-relaunch stays on the owned canonical-profile launcher"
assert_grep_fixed "Exec=$FF_OVERLAY_FIXTURE/owned/bin/firefox %u" \
    "$FF_OVERLAY_FIXTURE/owned/applications/org.mozilla.firefox.desktop" \
    "derived Firefox desktop selects the owned launcher"
assert_not_grep 'profile-manager-window' \
    "$FF_OVERLAY_FIXTURE/owned/applications/org.mozilla.firefox.desktop" \
    "derived Firefox desktop omits the disabled profile-manager action"
if ! find "$FF_OVERLAY_FIXTURE/owned/applications" -mindepth 1 -maxdepth 1 \
        -type d -name '.noid-firefox-overlay.*' -print -quit | grep -q .; then
    _pass "successful Firefox overlay generation removes its private staging directory"
else
    _fail "successful Firefox overlay generation removes its private staging directory"
fi
assert_eq "$ff_vendor_before" "$(sha256sum "$FF_VENDOR_LAUNCHER" "$FF_VENDOR_DESKTOP")" \
    "Firefox overlay generation preserves vendor bytes"
ff_owned_before=$(sha256sum "$FF_OVERLAY_FIXTURE/owned/bin/firefox" \
    "$FF_OVERLAY_FIXTURE/owned/applications/org.mozilla.firefox.desktop")
printf '\n# unexpected vendor drift\n' >> "$FF_VENDOR_LAUNCHER"
if PATH="$FF_OVERLAY_FIXTURE/mock-bin:$PATH" bash "$FF_OVERLAY_FIXTURE/reassert.sh" \
        >/dev/null 2>&1; then
    _fail "Firefox overlay generator rejects vendor drift"
else
    _pass "Firefox overlay generator rejects vendor drift"
fi
assert_eq "$ff_owned_before" "$(sha256sum "$FF_OVERLAY_FIXTURE/owned/bin/firefox" \
    "$FF_OVERLAY_FIXTURE/owned/applications/org.mozilla.firefox.desktop")" \
    "failed Firefox regeneration preserves the last known-good overlays"
if ! find "$FF_OVERLAY_FIXTURE/owned/applications" -mindepth 1 -maxdepth 1 \
        -type d -name '.noid-firefox-overlay.*' -print -quit | grep -q .; then
    _pass "failed Firefox overlay generation removes its private staging directory"
else
    _fail "failed Firefox overlay generation removes its private staging directory"
fi

assert_grep_extended '^harden_profile\(\)'                     "$TMPDIR2/harden.sh" "helper fn: harden_profile"
assert_grep_fixed 'profile_dir_for "$target_name"'             "$TMPDIR2/harden.sh" "helper uses shared profile_dir_for"
assert_grep_fixed '--all)'                                     "$TMPDIR2/harden.sh" "helper flag: --all"
assert_grep_fixed '--force)'                                   "$TMPDIR2/harden.sh" "helper flag: --force"
assert_grep_fixed 'apply_userjs "$target_name" "$apply_mode"'  "$TMPDIR2/harden.sh" "helper applies the selected supported user.js mode"
assert_grep_fixed 'repair_ubo_profile_local "$target_name"'  "$TMPDIR2/harden.sh" \
    "helper repairs invalid uBO while preserving validated newer bytes"
assert_grep_fixed 'patch_ubo_pb_permission "$target_name"'     "$TMPDIR2/harden.sh" "helper grants uBO PB permission"
assert_grep_fixed 'profile_hardening_complete "$target_name"' "$TMPDIR2/harden.sh" "helper validates complete postcondition"
assert_grep_fixed 'profile_mutable_file_safe "$pdir" "$prefs"' "$TMPDIR2/firefox-profiles.sh" \
    "profile completion accepts only safely contained browser-owned mutable state"
assert_grep_fixed 'NOID_FF_UBO_SHA256=' "$TMPDIR2/firefox-profiles.sh" \
    "shared profile helper carries exact uBO SHA-256"
assert_grep_fixed 'NOID_FF_UBO_SIZE=' "$TMPDIR2/firefox-profiles.sh" \
    "shared profile helper carries exact uBO size"
assert_grep_fixed 'name<TAB>relative-path<TAB>IsRelative<TAB>default' \
    "$TMPDIR2/firefox-profiles.sh" \
    "shared profile record explicitly carries IsRelative"
assert_grep_fixed 'if relative == "0":' \
    "$TMPDIR2/firefox-profiles.sh" \
    "shared profile helper ignores absolute registrations outside its write boundary"
assert_grep_fixed 'raise SystemExit(f"{section}: invalid IsRelative value")' \
    "$TMPDIR2/firefox-profiles.sh" \
    "shared profile helper still rejects malformed IsRelative state"
assert_grep_fixed 'validate_noid_marker_pair' "$TMPDIR2/relax-fpp.sh" \
    "FPP relaxation validates exact marker structure"
assert_grep_fixed 'validate_noid_marker_pair' "$TMPDIR2/relax-webrtc.sh" \
    "WebRTC relaxation validates exact marker structure"
assert_grep_fixed 'profile_drm_opt_in_state' "$TMPDIR2/firefox-profiles.sh" \
    "shared profile helper validates the versioned DRM consent sentinel"
assert_grep_fixed 'NOID_FF_USERJS_DRM_OVERRIDES' "$TMPDIR2/firefox-profiles.sh" \
    "Update-All profile re-application composes the reviewed DRM overlay"
assert_grep_fixed 'noid_supported_relaxation_state' "$TMPDIR2/firefox-profiles.sh" \
    "Update-All preserves only exact supported compatibility opt-ins"
assert_grep_fixed 'profile_userjs_supported "$name" "$pdir"' \
    "$TMPDIR2/firefox-profiles.sh" \
    "profile completion validates the complete supported user.js composition"
assert_grep_fixed 'profile_userjs_noid_managed' "$TMPDIR2/firefox-profiles.sh" \
    "shared helper distinguishes managed legacy state from exact completeness"
assert_grep_fixed 'reset-relaxations' "$TMPDIR2/harden.sh" \
    "explicit harden-profile force owns compatibility-opt-in reset"
assert_grep_fixed 'NOID_FIREFOX_DRM_OPT_IN_V1' "$TMPDIR2/firefox-drm.sh" \
    "DRM consent helper publishes the exact versioned sentinel"
assert_grep_fixed 'backup_noid_userjs' "$TMPDIR2/firefox-drm.sh" \
    "DRM consent changes retain a recoverable user.js backup"
assert_grep_fixed 'rollback_userjs_or_fail()' "$TMPDIR2/firefox-drm.sh" \
    "DRM consent failures use one explicit rollback path"
assert_grep_fixed 'Consent state may be inconsistent; recover from retained backup:' \
    "$TMPDIR2/firefox-drm.sh" \
    "a failed DRM rollback reports the retained recovery artifact"
assert_not_grep 'noid_atomic_install_file "$backup" "$userjs" 600 || true' \
    "$TMPDIR2/firefox-drm.sh" \
    "DRM consent rollback failures are never swallowed"
assert_grep_fixed 'fmt_banner "NoID Privacy — Firefox DRM"' "$TMPDIR2/firefox-drm.sh" \
    "DRM consent helper uses the shared NoID Privacy terminal presentation"
assert_grep_fixed 'Enable DRM for Firefox default-release? [y/N]' \
    "$TMPDIR2/firefox-drm.sh" \
    "interactive DRM flow asks explicitly for default-release"
assert_grep_fixed 'Enable DRM for Firefox Playground? [y/N]' \
    "$TMPDIR2/firefox-drm.sh" \
    "interactive DRM flow asks independently for Playground"
assert_grep_fixed 'before invoking either profile-local transaction' \
    "$TMPDIR2/firefox-drm.sh" \
    "both profile consents are collected before any mutation"
assert_grep_fixed 'Interactive profile consent requires a terminal.' \
    "$TMPDIR2/firefox-drm.sh" \
    "non-interactive implicit enable fails closed"
assert_not_grep 'profile_was_explicit' "$TMPDIR2/firefox-drm.sh" \
    "obsolete enable-default-before-Playground flow is absent"
assert_grep_fixed 'noid-firefox-drm enable              # asks independently for both shipped profiles' \
    "$KS_FILE" "Firefox DRM troubleshooting names the two-profile coordinator"
assert_grep_fixed 'noid-firefox-drm enable default-release' \
    "$KS_FILE" "Firefox DRM troubleshooting shows the explicit default profile"
assert_not_grep 'interactive helper enables only' "$KS_FILE" \
    "Firefox DRM guidance does not describe the retired sequential-consent flow"
assert_grep_fixed 'asks separate `[y/N]`' "$TMPDIR2/firefox-hardening.md" \
    "deployed DRM documentation matches independent profile consent"
assert_grep_fixed 'both answers default to No' "$TMPDIR2/firefox-hardening.md" \
    "deployed DRM documentation records the fail-closed defaults"
assert_grep_fixed '`status` and `disable` target `default-release`' \
    "$TMPDIR2/firefox-hardening.md" \
    "deployed DRM documentation scopes no-argument status and disable"
assert_grep_fixed 'noid-firefox-drm disable playground' \
    "$TMPDIR2/firefox-hardening.md" \
    "deployed DRM documentation gives the separate Playground opt-out"
assert_not_grep 'interactive helper enables only' "$TMPDIR2/firefox-hardening.md" \
    "stale sequential DRM-consent documentation is absent"
assert_grep_fixed "First use uBlock Origin's Logger" \
    "$TMPDIR2/firefox-hardening.md" \
    "uBO troubleshooting diagnoses network-filter breakage with the Logger"
assert_grep_fixed 'Cosmetic-filtering' "$TMPDIR2/firefox-hardening.md" \
    "uBO troubleshooting distinguishes cosmetic and network filtering"
assert_not_grep 'No-cosmetic-filtering checkbox' "$TMPDIR2/firefox-hardening.md" \
    "uBO troubleshooting no longer offers an ineffective cosmetic toggle"
assert_grep_fixed 'plus Firefox Playground' "$TMPDIR2/firefox-hardening.md" \
    "deployed profile inventory includes both shipped Firefox profiles"
assert_grep_fixed 'local-list protection and updates remain on' \
    "$TMPDIR2/firefox-hardening.md" \
    "new-profile guidance preserves local Safe Browsing update semantics"
assert_grep_fixed 'does not store and re-suggest' "$TMPDIR2/firefox-hardening.md" \
    "form-history guidance does not claim to stop page-side input access"
assert_grep_fixed 'coverage is not identical on every Linux/font configuration' \
    "$TMPDIR2/firefox-hardening.md" \
    "FPP guidance does not overstate platform-dependent font restriction"
assert_grep_fixed 'privacy-versus-security trade-off' "$TMPDIR2/firefox-hardening.md" \
    "Safe Browsing guidance discloses the remote-reputation coverage trade-off"
assert_grep_fixed 'maintained list-update mechanism' "$TMPDIR2/firefox-hardening.md" \
    "Safe Browsing guidance keeps local protection updates explicit"
assert_grep_fixed "Firefox 153's native QWAC verification/display remains enabled on desktop" \
    "$TMPDIR2/firefox-hardening.md" \
    "deployed Firefox documentation preserves native desktop QWAC verification"
assert_grep_fixed '`@IS_NOT_ANDROID@` resolves to true there and false on Android' \
    "$TMPDIR2/firefox-hardening.md" \
    "deployed Firefox documentation records the exact QWAC platform boundary"
second_drm_prompt_line=$(grep -nF \
    'Enable DRM for Firefox Playground? [y/N]' \
    "$TMPDIR2/firefox-drm.sh" | cut -d: -f1 || true)
first_drm_transaction_line=$(grep -nF \
    'Starting the approved default-release transaction.' \
    "$TMPDIR2/firefox-drm.sh" | cut -d: -f1 || true)
if [ -n "$second_drm_prompt_line" ] && \
   [ -n "$first_drm_transaction_line" ] && \
   [ "$second_drm_prompt_line" -lt "$first_drm_transaction_line" ]; then
    _pass "both DRM questions precede the first profile transaction"
else
    _fail "both DRM questions precede the first profile transaction"
fi
assert_grep_fixed 'status default-release >/dev/null' "$TMPDIR2/firefox-drm.sh" \
    "coordinator preflights default-release before any write"
assert_grep_fixed 'status playground >/dev/null' "$TMPDIR2/firefox-drm.sh" \
    "coordinator preflights Playground before any write"
assert_not_grep 'apply_userjs "$name"' "$TMPDIR2/relax-fpp.sh" \
    "FPP restore does not erase unrelated user overrides"
assert_not_grep 'apply_userjs "$name"' "$TMPDIR2/relax-webrtc.sh" \
    "WebRTC restore does not erase unrelated user overrides"
# Post-absorption helper installs only user.js. Detect the three retired
# arkenfox artifacts independently of the publication command used.
if awk '!/^[[:space:]]*#/ && /(user-overrides\.js|updater\.sh|prefsCleaner\.sh)/ { found = 1 } END { exit !found }' \
        "$TMPDIR2/harden.sh"; then
    _fail "helper publishes a retired arkenfox artifact"
else
    _pass "helper publishes no retired arkenfox artifact"
fi

# Execute the CLI against a registered profile. Missing/tampered source bytes
# must fail before publication; a partial profile must be repaired rather than
# skipped merely because user.js already contains the marker.
HARDEN_FIXTURE=$(mktemp -d "$PROJECT_ROOT/.test-firefox-harden.XXXXXXXX")
HARDEN_SOURCE="$HARDEN_FIXTURE/source"
HARDEN_CONFIG="$HARDEN_FIXTURE/config"
HARDEN_PROFILE="$HARDEN_CONFIG/mozilla/firefox/work.profile"
HARDEN_LIBRARY="$HARDEN_FIXTURE/firefox-profiles.sh"
HARDEN_SCRIPT="$HARDEN_FIXTURE/noid-firefox-harden-profile"
HARDEN_RELAX_FPP="$HARDEN_FIXTURE/noid-firefox-relax-fpp"
HARDEN_RELAX_WEBRTC="$HARDEN_FIXTURE/noid-firefox-relax-webrtc"
HARDEN_DRM="$HARDEN_FIXTURE/noid-firefox-drm"
HARDEN_BIN="$HARDEN_FIXTURE/bin"
mkdir -p "$HARDEN_SOURCE" "$HARDEN_PROFILE" "$HARDEN_FIXTURE/home" "$HARDEN_BIN"
chmod 700 "$HARDEN_PROFILE"
cp "$TMPDIR2/firefox-profiles.sh" "$HARDEN_LIBRARY"
cp "$TMPDIR2/harden.sh" "$HARDEN_SCRIPT"
cp "$TMPDIR2/relax-fpp.sh" "$HARDEN_RELAX_FPP"
cp "$TMPDIR2/relax-webrtc.sh" "$HARDEN_RELAX_WEBRTC"
cp "$TMPDIR2/firefox-drm.sh" "$HARDEN_DRM"
cp "$TMPDIR2/drm-overrides.js" "$HARDEN_SOURCE/drm-overrides.js"
printf '%s\n' \
    '// NoID Privacy Workstation Firefox harden-profile fixture' \
    'user_pref("_noid.fixture", true);' > "$HARDEN_SOURCE/user.js"
create_test_xpi "$HARDEN_SOURCE/ubo.xpi" uBlock0@raymondhill.net 1.73.0 - - 1
HARDEN_UBO_SHA=$(sha256sum "$HARDEN_SOURCE/ubo.xpi" | awk '{print $1}')
HARDEN_UBO_SIZE=$(stat -c '%s' "$HARDEN_SOURCE/ubo.xpi")
sed -i \
    -e "s|^NOID_FF_USERJS_BASE=.*|NOID_FF_USERJS_BASE=\"$HARDEN_SOURCE/user.js\"|" \
    -e "s|^NOID_FF_USERJS_DRM_OVERRIDES=.*|NOID_FF_USERJS_DRM_OVERRIDES=\"$HARDEN_SOURCE/drm-overrides.js\"|" \
    -e "s|^NOID_FF_UBO_XPI=.*|NOID_FF_UBO_XPI=\"$HARDEN_SOURCE/ubo.xpi\"|" \
    -e "s|^NOID_FF_UBO_SHA256=.*|NOID_FF_UBO_SHA256=\"$HARDEN_UBO_SHA\"|" \
    -e "s|^NOID_FF_UBO_SIZE=.*|NOID_FF_UBO_SIZE=$HARDEN_UBO_SIZE|" \
    -e "s|^NOID_FF_WEBEXT_VALIDATOR=.*|NOID_FF_WEBEXT_VALIDATOR=\"$TMPDIR2/validate-webextension.py\"|" \
    "$HARDEN_LIBRARY"
sed -i \
    -e "s|^SOURCE_DIR=.*|SOURCE_DIR=$HARDEN_SOURCE|" \
    -e "s|/usr/local/lib/noid-privacy/firefox-profiles.sh|$HARDEN_LIBRARY|g" \
    "$HARDEN_SCRIPT"
sed -i \
    -e "s|/usr/local/lib/noid-privacy/firefox-profiles.sh|$HARDEN_LIBRARY|g" \
    "$HARDEN_RELAX_FPP" "$HARDEN_RELAX_WEBRTC" "$HARDEN_DRM"
cat > "$HARDEN_CONFIG/mozilla/firefox/profiles.ini" <<'HARDEN_PROFILES_EOF'
[Profile0]
Name=work
IsRelative=1
Path=work.profile
Default=1

[General]
StartWithLastProfile=1
HARDEN_PROFILES_EOF
cat > "$HARDEN_BIN/pgrep" <<'HARDEN_PGREP_EOF'
#!/bin/sh
[ -z "${NOID_TEST_FIREFOX_PID:-}" ] || {
    printf '%s\n' "$NOID_TEST_FIREFOX_PID"
    exit 0
}
exit 1
HARDEN_PGREP_EOF
chmod 700 "$HARDEN_BIN/pgrep"
run_harden_fixture() {
    env HOME="$HARDEN_FIXTURE/home" XDG_CONFIG_HOME="$HARDEN_CONFIG" \
        PATH="$HARDEN_BIN:$PATH" bash "$HARDEN_SCRIPT" "$@"
}
run_profile_complete_fixture() {
    env HOME="$HARDEN_FIXTURE/home" XDG_CONFIG_HOME="$HARDEN_CONFIG" \
        PATH="$HARDEN_BIN:$PATH" bash -c \
        '. "$1"; profile_hardening_complete work' bash "$HARDEN_LIBRARY"
}
run_apply_userjs_fixture() {
    local mode="${1:-preserve-supported}"
    env HOME="$HARDEN_FIXTURE/home" XDG_CONFIG_HOME="$HARDEN_CONFIG" \
        PATH="$HARDEN_BIN:$PATH" bash -c \
        '. "$1"; apply_userjs work "$2"' bash "$HARDEN_LIBRARY" "$mode"
}
run_repair_with_failed_publish_fixture() {
    env HOME="$HARDEN_FIXTURE/home" XDG_CONFIG_HOME="$HARDEN_CONFIG" \
        PATH="$HARDEN_BIN:$PATH" bash -c \
        '. "$1"; mktemp() { return 1; }; repair_ubo_profile_local work' \
        bash "$HARDEN_LIBRARY"
}
run_relax_fixture() {
    local script="$1"; shift
    env HOME="$HARDEN_FIXTURE/home" XDG_CONFIG_HOME="$HARDEN_CONFIG" \
        PATH="$HARDEN_BIN:$PATH" bash "$script" "$@"
}
run_drm_fixture() {
    env HOME="$HARDEN_FIXTURE/home" XDG_CONFIG_HOME="$HARDEN_CONFIG" \
        PATH="$HARDEN_BIN:$PATH" bash "$HARDEN_DRM" "$@"
}

mv "$HARDEN_SOURCE/ubo.xpi" "$HARDEN_SOURCE/ubo.xpi.missing"
assert_cmd_failure "harden-profile rejects a missing required uBO source" \
    run_harden_fixture work
if [ ! -e "$HARDEN_PROFILE/user.js" ] && \
   [ ! -e "$HARDEN_PROFILE/extensions/uBlock0@raymondhill.net.xpi" ]; then
    _pass "missing uBO source publishes no partial hardening files"
else
    _fail "missing uBO source publishes no partial hardening files"
fi
mv "$HARDEN_SOURCE/ubo.xpi.missing" "$HARDEN_SOURCE/ubo.xpi"

assert_cmd_success "harden-profile installs all required profile outputs" \
    run_harden_fixture work
if cmp -s "$HARDEN_SOURCE/user.js" "$HARDEN_PROFILE/user.js"; then
    _pass "harden-profile installs canonical user.js bytes"
else
    _fail "harden-profile installs canonical user.js bytes"
fi
assert_eq "$HARDEN_UBO_SHA" \
    "$(sha256sum "$HARDEN_PROFILE/extensions/uBlock0@raymondhill.net.xpi" | awk '{print $1}')" \
    "harden-profile installs exact reviewed uBO bytes"

# Listing is read-only and stays available while Firefox owns live profile
# files. A mutating request under the same process evidence retains the gate.
sleep 30 &
HARDEN_ACTIVE_FIREFOX_PID=$!
assert_cmd_success "read-only hardening status works while Firefox is running" \
    env NOID_TEST_FIREFOX_PID="$HARDEN_ACTIVE_FIREFOX_PID" \
        HOME="$HARDEN_FIXTURE/home" XDG_CONFIG_HOME="$HARDEN_CONFIG" \
        PATH="$HARDEN_BIN:$PATH" bash "$HARDEN_SCRIPT" --list
assert_cmd_failure "profile mutation remains blocked while Firefox is running" \
    env NOID_TEST_FIREFOX_PID="$HARDEN_ACTIVE_FIREFOX_PID" \
        HOME="$HARDEN_FIXTURE/home" XDG_CONFIG_HOME="$HARDEN_CONFIG" \
        PATH="$HARDEN_BIN:$PATH" bash "$HARDEN_SCRIPT" work
kill "$HARDEN_ACTIVE_FIREFOX_PID" 2>/dev/null || true
wait "$HARDEN_ACTIVE_FIREFOX_PID" 2>/dev/null || true

if python3 - "$HARDEN_PROFILE/extension-preferences.json" <<'HARDEN_PREFS_PYEOF'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
assert data["uBlock0@raymondhill.net"]["permissions"] == ["internal:privateBrowsingAllowed"]
HARDEN_PREFS_PYEOF
then
    _pass "harden-profile grants uBO private-window permission"
else
    _fail "harden-profile grants uBO private-window permission"
fi

# Firefox's legacy JSONFile writer recreates extension-preferences.json as
# 0644. It remains private only through the current-user-owned 0700 profile.
chmod 644 "$HARDEN_PROFILE/extension-preferences.json"
assert_cmd_success "Firefox-native 0644 permission store remains hardened in a private profile" \
    run_profile_complete_fixture
chmod 664 "$HARDEN_PROFILE/extension-preferences.json"
assert_cmd_failure "group-writable Firefox permission store is never complete" \
    run_profile_complete_fixture
chmod 644 "$HARDEN_PROFILE/extension-preferences.json"
chmod 755 "$HARDEN_PROFILE"
assert_cmd_failure "Firefox-native readable permission store requires a private profile" \
    run_profile_complete_fixture
chmod 700 "$HARDEN_PROFILE"

rm -f "$HARDEN_PROFILE/extensions/uBlock0@raymondhill.net.xpi"
assert_cmd_success "partial hardening is repaired instead of marker-skipped" \
    run_harden_fixture work
assert_eq "$HARDEN_UBO_SHA" \
    "$(sha256sum "$HARDEN_PROFILE/extensions/uBlock0@raymondhill.net.xpi" | awk '{print $1}')" \
    "partial repair restores exact uBO bytes"

printf '%s' 'invalid installed uBO evidence' \
    > "$HARDEN_PROFILE/extensions/uBlock0@raymondhill.net.xpi"
HARDEN_INVALID_UBO_SHA=$(sha256sum \
    "$HARDEN_PROFILE/extensions/uBlock0@raymondhill.net.xpi" | awk '{print $1}')
assert_cmd_failure "failed atomic uBO repair preserves the invalid prior evidence" \
    run_repair_with_failed_publish_fixture
assert_eq "$HARDEN_INVALID_UBO_SHA" \
    "$(sha256sum "$HARDEN_PROFILE/extensions/uBlock0@raymondhill.net.xpi" | awk '{print $1}')" \
    "failed uBO repair never creates an absent or partial destination"
assert_cmd_success "successful atomic uBO repair replaces invalid regular bytes" \
    run_harden_fixture work
assert_eq "$HARDEN_UBO_SHA" \
    "$(sha256sum "$HARDEN_PROFILE/extensions/uBlock0@raymondhill.net.xpi" | awk '{print $1}')" \
    "successful uBO repair publishes the exact reviewed bytes"

# Automatic enrollment needs a durable user-controlled exclusion because a
# genuinely new profile and an intentionally empty dev profile both lack
# user.js. --all and Update All must respect the exact marker, while an
# explicit named harden is the opt-in that removes it.
HARDEN_DEV_PROFILE="$HARDEN_CONFIG/mozilla/firefox/dev.profile"
mkdir -m 700 "$HARDEN_DEV_PROFILE"
cp "$HARDEN_CONFIG/mozilla/firefox/profiles.ini" \
    "$HARDEN_FIXTURE/profiles.work-only"
printf '%s\n' \
    '' \
    '[Profile1]' \
    'Name=dev' \
    'IsRelative=1' \
    'Path=dev.profile' \
    >> "$HARDEN_CONFIG/mozilla/firefox/profiles.ini"
assert_cmd_failure "--exclude refuses an already NoID Privacy-managed Firefox profile" \
    run_harden_fixture --exclude work
assert_cmd_success "--exclude records an automatic-hardening opt-out for a new profile" \
    run_harden_fixture --exclude dev
assert_grep_fixed NOID_FIREFOX_HARDENING_DISABLED_V1 \
    "$HARDEN_DEV_PROFILE/.noid-firefox-hardening-disabled" \
    "Firefox automatic-hardening exclusion has exact content"
assert_eq 600 \
    "$(stat -c '%a' "$HARDEN_DEV_PROFILE/.noid-firefox-hardening-disabled")" \
    "Firefox automatic-hardening exclusion is private"
assert_cmd_success "--all preserves an explicitly excluded Firefox profile" \
    run_harden_fixture --all
if [ ! -e "$HARDEN_DEV_PROFILE/user.js" ]; then
    _pass "--all publishes no hardening bytes in an excluded profile"
else
    _fail "--all publishes no hardening bytes in an excluded profile"
fi
assert_cmd_success "named Firefox hardening is explicit opt-in after exclusion" \
    run_harden_fixture dev
if [ ! -e "$HARDEN_DEV_PROFILE/.noid-firefox-hardening-disabled" ] && \
   cmp -s "$HARDEN_SOURCE/user.js" "$HARDEN_DEV_PROFILE/user.js"; then
    _pass "explicit Firefox opt-in clears exclusion and publishes canonical user.js"
else
    _fail "explicit Firefox opt-in clears exclusion and publishes canonical user.js"
fi
cp "$HARDEN_FIXTURE/profiles.work-only" \
    "$HARDEN_CONFIG/mozilla/firefox/profiles.ini"

# Non-force CLI paths may repair exact supported state, but must never replace
# an existing foreign/stale/manual user.js. --all reports and skips it.
printf '%s\n' 'user_pref("fixture.manual.override", true);' \
    >> "$HARDEN_PROFILE/user.js"
HARDEN_MANUAL_SHA=$(sha256sum "$HARDEN_PROFILE/user.js" | awk '{print $1}')
assert_cmd_failure "named non-force hardening rejects a noncanonical user.js" \
    run_harden_fixture work
assert_eq "$HARDEN_MANUAL_SHA" \
    "$(sha256sum "$HARDEN_PROFILE/user.js" | awk '{print $1}')" \
    "named non-force rejection preserves noncanonical user.js bytes"
assert_cmd_success "--all safely skips a noncanonical user.js" \
    run_harden_fixture --all
assert_eq "$HARDEN_MANUAL_SHA" \
    "$(sha256sum "$HARDEN_PROFILE/user.js" | awk '{print $1}')" \
    "--all skip preserves noncanonical user.js bytes"
cp "$HARDEN_SOURCE/user.js" "$HARDEN_PROFILE/user.js"
chmod 600 "$HARDEN_PROFILE/user.js"

# Update All's ownership predicate is deliberately broader than completeness:
# it accepts one safe legacy NoID Privacy boundary pair, not arbitrary text mentions.
HARDEN_MANAGED_PROFILE="$HARDEN_FIXTURE/managed.profile"
mkdir -m 700 "$HARDEN_MANAGED_PROFILE"
printf '%s\n' \
    '*    name: NoID Privacy Workstation — Firefox Hardening' \
    'user_pref("_noid.legacy.fixture", true);' \
    'user_pref("_user.js.parrot", "NOID-COMPLETE: full hardening applied");' \
    > "$HARDEN_MANAGED_PROFILE/user.js"
chmod 600 "$HARDEN_MANAGED_PROFILE/user.js"
assert_cmd_success "managed-state detector accepts one safe NoID Privacy boundary pair" \
    env HOME="$HARDEN_FIXTURE/home" XDG_CONFIG_HOME="$HARDEN_CONFIG" \
        bash -c '. "$1"; profile_userjs_noid_managed "$2"' \
        bash "$HARDEN_LIBRARY" "$HARDEN_MANAGED_PROFILE"
printf '%s\n' \
    'user_pref("_user.js.parrot", "NOID-COMPLETE: full hardening applied");' \
    >> "$HARDEN_MANAGED_PROFILE/user.js"
assert_cmd_failure "managed-state detector rejects duplicate ownership boundaries" \
    env HOME="$HARDEN_FIXTURE/home" XDG_CONFIG_HOME="$HARDEN_CONFIG" \
        bash -c '. "$1"; profile_userjs_noid_managed "$2"' \
        bash "$HARDEN_LIBRARY" "$HARDEN_MANAGED_PROFILE"

assert_cmd_failure "harden-profile rejects surplus positional arguments" \
    run_harden_fixture work surplus
cp "$HARDEN_CONFIG/mozilla/firefox/profiles.ini" "$HARDEN_FIXTURE/profiles.valid"
HARDEN_EXTERNAL="$HARDEN_FIXTURE/external.profile"
mkdir -p "$HARDEN_EXTERNAL"
cat > "$HARDEN_CONFIG/mozilla/firefox/profiles.ini" <<HARDEN_ABSOLUTE_EOF
[Profile0]
Name=absolute
IsRelative=0
Path=$HARDEN_EXTERNAL
Default=1
HARDEN_ABSOLUTE_EOF
assert_cmd_success "Firefox profile helper ignores absolute destinations" \
    run_harden_fixture --all
if [ ! -e "$HARDEN_EXTERNAL/user.js" ]; then
    _pass "ignored absolute Firefox destination remains untouched"
else
    _fail "ignored absolute Firefox destination remains untouched"
fi
cat > "$HARDEN_CONFIG/mozilla/firefox/profiles.ini" <<'HARDEN_TRAVERSAL_EOF'
[Profile0]
Name=traversal
IsRelative=1
Path=../external.profile
Default=1
HARDEN_TRAVERSAL_EOF
assert_cmd_failure "Firefox profile helper rejects traversal" \
    run_harden_fixture --all
ln -s "$HARDEN_EXTERNAL" "$HARDEN_CONFIG/mozilla/firefox/symlink.profile"
cat > "$HARDEN_CONFIG/mozilla/firefox/profiles.ini" <<'HARDEN_SYMLINK_PROFILE_EOF'
[Profile0]
Name=symlinked
IsRelative=1
Path=symlink.profile
Default=1
HARDEN_SYMLINK_PROFILE_EOF
assert_cmd_failure "Firefox profile helper rejects symlinked profile paths" \
    run_harden_fixture --all
rm -f "$HARDEN_CONFIG/mozilla/firefox/symlink.profile"
cp "$HARDEN_FIXTURE/profiles.valid" "$HARDEN_CONFIG/mozilla/firefox/profiles.ini"

printf '%s' 'Firefox user.js symlink victim' > "$HARDEN_FIXTURE/userjs-victim"
rm -f "$HARDEN_PROFILE/user.js"
ln -s "$HARDEN_FIXTURE/userjs-victim" "$HARDEN_PROFILE/user.js"
assert_cmd_failure "Firefox writer rejects symlinked user.js" \
    run_harden_fixture --force work
assert_eq 'Firefox user.js symlink victim' "$(cat "$HARDEN_FIXTURE/userjs-victim")" \
    "Firefox writer preserves symlink target bytes"
rm -f "$HARDEN_PROFILE/user.js"
cp "$HARDEN_SOURCE/user.js" "$HARDEN_PROFILE/user.js"
chmod 600 "$HARDEN_PROFILE/user.js"

HARDEN_LOCK="$HARDEN_FIXTURE/home/.local/state/noid-privacy/firefox-profile-operations.lock"
exec 7>"$HARDEN_LOCK"
flock -n 7
set +e
run_harden_fixture work >/dev/null 2>&1
HARDEN_LOCK_RC=$?
set -e
flock -u 7
exec 7>&-
assert_eq 75 "$HARDEN_LOCK_RC" "concurrent Firefox profile operation returns retry code 75"

# Relaxation helpers must preserve unrelated content, retain unique backups,
# and reject every malformed marker topology without changing a byte.
printf '%s\n' '// user-owned Firefox override sentinel' \
    'user_pref("fixture.user.override", 77);' >> "$HARDEN_PROFILE/user.js"
assert_cmd_success "FPP relaxation applies through atomic marker rewrite" \
    run_relax_fixture "$HARDEN_RELAX_FPP"
assert_grep_fixed '// NOID-RELAX-FPP-BEGIN' "$HARDEN_PROFILE/user.js" \
    "FPP relaxation publishes begin marker"
assert_grep_fixed 'user_pref("privacy.fingerprintingProtection.pbmode", false);' \
    "$HARDEN_PROFILE/user.js" \
    "FPP relaxation disables private-window fingerprinting protection"
assert_grep_fixed 'user_pref("fixture.user.override", 77);' "$HARDEN_PROFILE/user.js" \
    "FPP apply preserves unrelated user override"
assert_cmd_success "FPP restore removes only its exact block" \
    run_relax_fixture "$HARDEN_RELAX_FPP" --restore
assert_not_grep '// NOID-RELAX-FPP-BEGIN\|// NOID-RELAX-FPP-END' \
    "$HARDEN_PROFILE/user.js" "FPP restore removes both markers"
assert_grep_fixed 'user_pref("fixture.user.override", 77);' "$HARDEN_PROFILE/user.js" \
    "FPP restore preserves unrelated user override"
if [ "$(find "$HARDEN_PROFILE" -maxdepth 1 -type f -name 'user.js.bak-noid-*' | wc -l)" -ge 2 ]; then
    _pass "relax/apply and restore retain collision-safe backups"
else
    _fail "relax/apply and restore retain collision-safe backups"
fi

for malformed in missing_end duplicate reversed; do
    cp "$HARDEN_SOURCE/user.js" "$HARDEN_PROFILE/user.js"
    case "$malformed" in
        missing_end)
            printf '%s\n' '// NOID-RELAX-FPP-BEGIN' >> "$HARDEN_PROFILE/user.js"
            ;;
        duplicate)
            printf '%s\n' '// NOID-RELAX-FPP-BEGIN' '// NOID-RELAX-FPP-END' \
                '// NOID-RELAX-FPP-BEGIN' '// NOID-RELAX-FPP-END' >> "$HARDEN_PROFILE/user.js"
            ;;
        reversed)
            printf '%s\n' '// NOID-RELAX-FPP-END' '// NOID-RELAX-FPP-BEGIN' \
                >> "$HARDEN_PROFILE/user.js"
            ;;
    esac
    HARDEN_MARKER_SHA=$(sha256sum "$HARDEN_PROFILE/user.js" | awk '{print $1}')
    assert_cmd_failure "FPP relaxation rejects $malformed marker topology" \
        run_relax_fixture "$HARDEN_RELAX_FPP"
    assert_eq "$HARDEN_MARKER_SHA" \
        "$(sha256sum "$HARDEN_PROFILE/user.js" | awk '{print $1}')" \
        "$malformed marker rejection preserves user.js bytes"
done
cp "$HARDEN_SOURCE/user.js" "$HARDEN_PROFILE/user.js"
printf '%s\n' 'user_pref("fixture.webrtc.override", 88);' >> "$HARDEN_PROFILE/user.js"
assert_cmd_success "WebRTC relaxation applies through atomic marker rewrite" \
    run_relax_fixture "$HARDEN_RELAX_WEBRTC"
assert_cmd_success "WebRTC restore removes only its exact block" \
    run_relax_fixture "$HARDEN_RELAX_WEBRTC" --restore
assert_grep_fixed 'user_pref("fixture.webrtc.override", 88);' "$HARDEN_PROFILE/user.js" \
    "WebRTC restore preserves unrelated user override"
assert_cmd_failure "WebRTC relaxation rejects surplus arguments" \
    run_relax_fixture "$HARDEN_RELAX_WEBRTC" apply surplus

# The formerly failing order is WebRTC first, then FPP. The second helper must
# normalize both exact blocks to FPP-then-WebRTC without losing unrelated
# user content, so the shared completeness predicate accepts the result.
cp "$HARDEN_SOURCE/user.js" "$HARDEN_PROFILE/user.js"
printf '%s\n' 'user_pref("fixture.reverse.order", 99);' \
    >> "$HARDEN_PROFILE/user.js"
assert_cmd_success "WebRTC opt-in applies before reverse-order normalization" \
    run_relax_fixture "$HARDEN_RELAX_WEBRTC"
assert_cmd_success "FPP opt-in normalizes a prior WebRTC block" \
    run_relax_fixture "$HARDEN_RELAX_FPP"
HARDEN_FPP_LINE=$(grep -nFx '// NOID-RELAX-FPP-BEGIN' \
    "$HARDEN_PROFILE/user.js" | cut -d: -f1 || true)
HARDEN_WEBRTC_LINE=$(grep -nFx '// NOID-RELAX-WEBRTC-BEGIN' \
    "$HARDEN_PROFILE/user.js" | cut -d: -f1 || true)
if [ -n "$HARDEN_FPP_LINE" ] && [ -n "$HARDEN_WEBRTC_LINE" ] && \
   [ "$HARDEN_FPP_LINE" -lt "$HARDEN_WEBRTC_LINE" ]; then
    _pass "relaxation helpers publish the canonical FPP-then-WebRTC order"
else
    _fail "relaxation helpers publish the canonical FPP-then-WebRTC order"
fi
assert_grep_fixed 'user_pref("fixture.reverse.order", 99);' \
    "$HARDEN_PROFILE/user.js" \
    "relaxation order normalization preserves unrelated user content"
cp "$HARDEN_SOURCE/user.js" "$HARDEN_PROFILE/user.js"
assert_cmd_success "WebRTC-only supported state reapplies for completion gate" \
    run_relax_fixture "$HARDEN_RELAX_WEBRTC"
assert_cmd_success "FPP normalizes the supported reverse-order state" \
    run_relax_fixture "$HARDEN_RELAX_FPP"
assert_cmd_success "reverse CLI order satisfies the exact completion gate" \
    run_profile_complete_fixture

# Update All must retain both exact user-requested compatibility modes while
# replacing stale canonical content. Altered blocks fail closed and survive
# byte-for-byte until an explicit --force reset.
cp "$HARDEN_SOURCE/user.js" "$HARDEN_PROFILE/user.js"
assert_cmd_success "FPP opt-in fixture applies before update convergence" \
    run_relax_fixture "$HARDEN_RELAX_FPP"
assert_cmd_success "WebRTC opt-in fixture applies before update convergence" \
    run_relax_fixture "$HARDEN_RELAX_WEBRTC"
printf '%s\n' 'user_pref("fixture.stale.canonical", true);' \
    >> "$HARDEN_PROFILE/user.js"
assert_cmd_failure "stale user.js cannot satisfy the exact completion gate" \
    run_profile_complete_fixture
assert_cmd_success "Update-All composition preserves exact FPP and WebRTC opt-ins" \
    run_apply_userjs_fixture
assert_grep_fixed '// NOID-RELAX-FPP-BEGIN' "$HARDEN_PROFILE/user.js" \
    "Update-All composition retains the exact FPP opt-in"
assert_grep_fixed '// NOID-RELAX-WEBRTC-BEGIN' "$HARDEN_PROFILE/user.js" \
    "Update-All composition retains the exact WebRTC opt-in"
assert_not_grep 'fixture.stale.canonical' "$HARDEN_PROFILE/user.js" \
    "Update-All composition replaces stale unsupported user.js content"
assert_cmd_success "preserved compatibility choices satisfy the exact completion gate" \
    run_profile_complete_fixture
sed -i 's/fingerprintingProtection", false/fingerprintingProtection", true/' \
    "$HARDEN_PROFILE/user.js"
HARDEN_ALTERED_RELAX_SHA=$(sha256sum "$HARDEN_PROFILE/user.js" | awk '{print $1}')
assert_cmd_failure "altered FPP opt-in is never carried into regenerated user.js" \
    run_apply_userjs_fixture
assert_eq "$HARDEN_ALTERED_RELAX_SHA" \
    "$(sha256sum "$HARDEN_PROFILE/user.js" | awk '{print $1}')" \
    "rejected altered compatibility block is preserved for explicit review"
assert_cmd_failure "non-force CLI refuses an altered compatibility block" \
    run_harden_fixture work
assert_eq "$HARDEN_ALTERED_RELAX_SHA" \
    "$(sha256sum "$HARDEN_PROFILE/user.js" | awk '{print $1}')" \
    "non-force compatibility refusal preserves altered bytes"
assert_cmd_success "explicit harden-profile force resets compatibility opt-ins" \
    run_harden_fixture --force work
assert_not_grep '// NOID-RELAX-FPP-BEGIN\|// NOID-RELAX-WEBRTC-BEGIN' \
    "$HARDEN_PROFILE/user.js" \
    "explicit force returns user.js to the canonical compatibility defaults"
assert_cmd_success "force-reset profile satisfies the exact completion gate" \
    run_profile_complete_fixture

# DRM consent is explicit, preserves unrelated user lines and persists through
# the same apply_userjs path used by Update-All. Disable removes only its exact
# block and sentinel.
cp "$HARDEN_SOURCE/user.js" "$HARDEN_PROFILE/user.js"
printf '%s\n' 'user_pref("fixture.drm.preserve", 99);' >> "$HARDEN_PROFILE/user.js"
assert_cmd_success "DRM status reports pristine default disabled" \
    run_drm_fixture status work
assert_cmd_success "DRM opt-in atomically publishes block + consent sentinel" \
    run_drm_fixture enable work
assert_grep_fixed '// NOID-DRM-OPT-IN-BEGIN' "$HARDEN_PROFILE/user.js" \
    "DRM opt-in publishes its exact begin marker"
assert_grep_fixed 'user_pref("fixture.drm.preserve", 99);' "$HARDEN_PROFILE/user.js" \
    "DRM opt-in preserves unrelated user.js lines"
assert_grep_fixed 'NOID_FIREFOX_DRM_OPT_IN_V1' \
    "$HARDEN_PROFILE/.noid-drm-enabled" \
    "DRM opt-in publishes the exact private consent sentinel"
assert_eq 600 "$(stat -c '%a' "$HARDEN_PROFILE/.noid-drm-enabled")" \
    "DRM consent sentinel is private"
HARDEN_DRM_ENABLED_SHA=$(sha256sum "$HARDEN_PROFILE/user.js" | awk '{print $1}')
HARDEN_DRM_BACKUPS_AFTER_ENABLE=$(find "$HARDEN_PROFILE" -maxdepth 1 -type f \
    -name 'user.js.bak-noid-*' | wc -l)
assert_cmd_success "repeated DRM enable is a read-only success" \
    run_drm_fixture enable work
assert_eq "$HARDEN_DRM_ENABLED_SHA" \
    "$(sha256sum "$HARDEN_PROFILE/user.js" | awk '{print $1}')" \
    "repeated DRM enable preserves user.js bytes"
assert_eq "$HARDEN_DRM_BACKUPS_AFTER_ENABLE" \
    "$(find "$HARDEN_PROFILE" -maxdepth 1 -type f -name 'user.js.bak-noid-*' | wc -l)" \
    "repeated DRM enable creates no no-op backup"
assert_cmd_success "DRM status reports explicit opt-in enabled" \
    run_drm_fixture status work
# The exact two-part consent record is fail-closed. A missing marker with a
# surviving sentinel must not be re-added implicitly even for `enable`.
cp "$HARDEN_SOURCE/user.js" "$HARDEN_PROFILE/user.js"
HARDEN_DRM_INCONSISTENT_SHA=$(sha256sum "$HARDEN_PROFILE/user.js" | awk '{print $1}')
assert_cmd_failure "DRM enable rejects sentinel/user.js disagreement" \
    run_drm_fixture enable work
assert_eq "$HARDEN_DRM_INCONSISTENT_SHA" \
    "$(sha256sum "$HARDEN_PROFILE/user.js" | awk '{print $1}')" \
    "DRM disagreement rejection preserves user.js bytes"
cat "$HARDEN_SOURCE/user.js" "$HARDEN_SOURCE/drm-overrides.js" \
    > "$HARDEN_PROFILE/user.js"
assert_cmd_success "Update-All apply_userjs path preserves DRM consent" \
    env HOME="$HARDEN_FIXTURE/home" XDG_CONFIG_HOME="$HARDEN_CONFIG" \
        bash -c '. "$1"; apply_userjs work' _ "$HARDEN_LIBRARY"
if cmp -s "$HARDEN_PROFILE/user.js" \
        <(cat "$HARDEN_SOURCE/user.js" "$HARDEN_SOURCE/drm-overrides.js"); then
    _pass "DRM consent re-application is exact base + reviewed overlay"
else
    _fail "DRM consent re-application is exact base + reviewed overlay"
fi
assert_cmd_success "DRM opt-out removes only supported consent state" \
    run_drm_fixture disable work
assert_not_grep '// NOID-DRM-OPT-IN-BEGIN\|// NOID-DRM-OPT-IN-END' \
    "$HARDEN_PROFILE/user.js" "DRM opt-out removes both markers"
if [ ! -e "$HARDEN_PROFILE/.noid-drm-enabled" ]; then
    _pass "DRM opt-out removes the versioned consent sentinel"
else
    _fail "DRM opt-out removes the versioned consent sentinel"
fi
HARDEN_DRM_DISABLED_SHA=$(sha256sum "$HARDEN_PROFILE/user.js" | awk '{print $1}')
HARDEN_DRM_BACKUPS_AFTER_DISABLE=$(find "$HARDEN_PROFILE" -maxdepth 1 -type f \
    -name 'user.js.bak-noid-*' | wc -l)
assert_cmd_success "repeated DRM disable is a read-only success" \
    run_drm_fixture disable work
assert_eq "$HARDEN_DRM_DISABLED_SHA" \
    "$(sha256sum "$HARDEN_PROFILE/user.js" | awk '{print $1}')" \
    "repeated DRM disable preserves user.js bytes"
assert_eq "$HARDEN_DRM_BACKUPS_AFTER_DISABLE" \
    "$(find "$HARDEN_PROFILE" -maxdepth 1 -type f -name 'user.js.bak-noid-*' | wc -l)" \
    "repeated DRM disable creates no no-op backup"

ln -s "$HARDEN_FIXTURE/nonexistent-drm-sentinel" \
    "$HARDEN_PROFILE/.noid-drm-enabled"
HARDEN_DRM_SHA=$(sha256sum "$HARDEN_PROFILE/user.js" | awk '{print $1}')
assert_cmd_failure "DRM helper rejects a symlinked consent sentinel" \
    run_drm_fixture status work
assert_eq "$HARDEN_DRM_SHA" \
    "$(sha256sum "$HARDEN_PROFILE/user.js" | awk '{print $1}')" \
    "invalid DRM sentinel rejection preserves user.js bytes"
rm -f "$HARDEN_PROFILE/.noid-drm-enabled"

# Exercise the double-failure path rather than only pinning its wording. The
# first install publishes user.js, the second fails sentinel publication and
# the third fails the attempted rollback. The action must fail loudly, retain
# the backup and identify the inconsistent-state risk.
cp "$HARDEN_SOURCE/user.js" "$HARDEN_PROFILE/user.js"
cat > "$HARDEN_BIN/install" <<'HARDEN_DRM_INSTALL_FAIL_EOF'
#!/bin/bash
set -euo pipefail
counter=${NOID_DRM_INSTALL_COUNTER:?}
count=$(cat "$counter" 2>/dev/null || echo 0)
count=$((count + 1))
printf '%s\n' "$count" > "$counter"
if [ "$count" -ge 2 ]; then
    exit 70
fi
exec /usr/bin/install "$@"
HARDEN_DRM_INSTALL_FAIL_EOF
chmod 0700 "$HARDEN_BIN/install"
export NOID_DRM_INSTALL_COUNTER="$HARDEN_FIXTURE/drm-install-counter"
if run_drm_fixture enable work >"$HARDEN_FIXTURE/drm-rollback-failure.out" 2>&1; then
    _fail "DRM double publication/rollback failure remains fatal"
else
    _pass "DRM double publication/rollback failure remains fatal"
fi
assert_grep_fixed 'Consent state may be inconsistent; recover from retained backup:' \
    "$HARDEN_FIXTURE/drm-rollback-failure.out" \
    "DRM double failure reports the retained recovery artifact"
if find "$HARDEN_PROFILE" -maxdepth 1 -type f \
        -name 'user.js.bak-noid-*' -print -quit | grep -q .; then
    _pass "DRM double failure retains a user.js recovery backup"
else
    _fail "DRM double failure retains a user.js recovery backup"
fi
unset NOID_DRM_INSTALL_COUNTER
rm -f "$HARDEN_BIN/install" "$HARDEN_FIXTURE/drm-install-counter"
cp "$HARDEN_SOURCE/user.js" "$HARDEN_PROFILE/user.js"

# An implicit enable is a two-profile consent coordinator. Exercise it through
# a real PTY: both questions are asked before mutation, each defaults to No,
# and either profile can be selected independently. The explicit child
# transactions above remain the only mutating code path.
HARDEN_DEFAULT_PROFILE="$HARDEN_CONFIG/mozilla/firefox/default-release.profile"
HARDEN_PLAYGROUND_PROFILE="$HARDEN_CONFIG/mozilla/firefox/playground.profile"
mkdir -p "$HARDEN_DEFAULT_PROFILE" "$HARDEN_PLAYGROUND_PROFILE"
chmod 700 "$HARDEN_DEFAULT_PROFILE" "$HARDEN_PLAYGROUND_PROFILE"
cp "$HARDEN_SOURCE/user.js" "$HARDEN_DEFAULT_PROFILE/user.js"
cp "$HARDEN_SOURCE/user.js" "$HARDEN_PLAYGROUND_PROFILE/user.js"
chmod 600 "$HARDEN_DEFAULT_PROFILE/user.js" "$HARDEN_PLAYGROUND_PROFILE/user.js"
cat >> "$HARDEN_CONFIG/mozilla/firefox/profiles.ini" <<'HARDEN_DRM_PROFILES_EOF'

[Profile1]
Name=default-release
IsRelative=1
Path=default-release.profile

[Profile2]
Name=playground
IsRelative=1
Path=playground.profile
HARDEN_DRM_PROFILES_EOF

run_drm_interactive_fixture() {
    local answers="$1"
    env HOME="$HARDEN_FIXTURE/home" XDG_CONFIG_HOME="$HARDEN_CONFIG" \
        PATH="$HARDEN_BIN:$PATH" \
        python3 - "$HARDEN_DRM" "$answers" <<'HARDEN_DRM_PTY_PYEOF'
import errno
import os
import pty
import select
import signal
import sys

script, answers = sys.argv[1:]
pid, fd = pty.fork()
if pid == 0:
    try:
        os.execv("/usr/bin/bash", ["bash", script, "enable"])
    except OSError:
        os._exit(127)

os.write(fd, answers.encode("utf-8"))
while True:
    readable, _, _ = select.select([fd], [], [], 10)
    if not readable:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        raise SystemExit("DRM consent fixture timed out waiting for the child")
    try:
        chunk = os.read(fd, 4096)
    except OSError as error:
        if error.errno == errno.EIO:
            break
        raise
    if not chunk:
        break
    os.write(sys.stdout.fileno(), chunk)

_, status = os.waitpid(pid, 0)
if os.WIFEXITED(status):
    raise SystemExit(os.WEXITSTATUS(status))
raise SystemExit(128 + os.WTERMSIG(status))
HARDEN_DRM_PTY_PYEOF
}

# Bind the non-interactive contract explicitly. A release test may itself run
# under a PTY, but that must never turn this negative fixture into a live prompt.
assert_cmd_failure "implicit non-interactive DRM enable never chooses a profile" \
    run_drm_fixture enable </dev/null
assert_cmd_success "interactive empty answers default both Firefox profiles to No" \
    run_drm_interactive_fixture $'\n\n'
for profile_dir in "$HARDEN_DEFAULT_PROFILE" "$HARDEN_PLAYGROUND_PROFILE"; do
    assert_not_grep '// NOID-DRM-OPT-IN-BEGIN' "$profile_dir/user.js" \
        "empty answers publish no DRM block in $(basename "$profile_dir")"
    if [ ! -e "$profile_dir/.noid-drm-enabled" ]; then
        _pass "empty answers publish no consent sentinel in $(basename "$profile_dir")"
    else
        _fail "empty answers publish no consent sentinel in $(basename "$profile_dir")"
    fi
done
assert_cmd_success "interactive n/n leaves both Firefox profiles DRM-free" \
    run_drm_interactive_fixture $'n\nn\n'
for profile_dir in "$HARDEN_DEFAULT_PROFILE" "$HARDEN_PLAYGROUND_PROFILE"; do
    assert_not_grep '// NOID-DRM-OPT-IN-BEGIN' "$profile_dir/user.js" \
        "n/n publishes no DRM block in $(basename "$profile_dir")"
    if [ ! -e "$profile_dir/.noid-drm-enabled" ]; then
        _pass "n/n publishes no consent sentinel in $(basename "$profile_dir")"
    else
        _fail "n/n publishes no consent sentinel in $(basename "$profile_dir")"
    fi
done

assert_cmd_success "interactive y/n enables only default-release" \
    run_drm_interactive_fixture $'y\nn\n'
assert_grep_fixed '// NOID-DRM-OPT-IN-BEGIN' "$HARDEN_DEFAULT_PROFILE/user.js" \
    "y/n enables default-release"
assert_not_grep '// NOID-DRM-OPT-IN-BEGIN' "$HARDEN_PLAYGROUND_PROFILE/user.js" \
    "y/n leaves Playground DRM-free"
assert_cmd_success "explicit default-release opt-out restores the fixture" \
    run_drm_fixture disable default-release

assert_cmd_success "interactive n/y enables only Firefox Playground" \
    run_drm_interactive_fixture $'n\ny\n'
assert_not_grep '// NOID-DRM-OPT-IN-BEGIN' "$HARDEN_DEFAULT_PROFILE/user.js" \
    "n/y leaves default-release DRM-free"
assert_grep_fixed '// NOID-DRM-OPT-IN-BEGIN' "$HARDEN_PLAYGROUND_PROFILE/user.js" \
    "n/y enables Playground"
assert_cmd_success "explicit Playground opt-out restores the fixture" \
    run_drm_fixture disable playground
cp "$HARDEN_FIXTURE/profiles.valid" "$HARDEN_CONFIG/mozilla/firefox/profiles.ini"

printf '%s' 'tampered source bytes' > "$HARDEN_SOURCE/ubo.xpi"
HARDEN_INSTALLED_SHA_BEFORE=$(sha256sum "$HARDEN_PROFILE/extensions/uBlock0@raymondhill.net.xpi" | awk '{print $1}')
assert_cmd_failure "harden-profile rejects source bytes that differ from pin" \
    run_harden_fixture --force work
assert_eq "$HARDEN_INSTALLED_SHA_BEFORE" \
    "$(sha256sum "$HARDEN_PROFILE/extensions/uBlock0@raymondhill.net.xpi" | awk '{print $1}')" \
    "tampered source cannot replace installed reviewed uBO"

# First-login setup must not wait before hardening or kill a visible browser.
extract_heredoc "$KS_FILE" "SETUPSCRIPT_EOF" "$TMPDIR2/setup.sh" || _fail "SETUPSCRIPT_EOF extraction"
extract_heredoc "$KS_FILE" "PROFILE_RECONCILE_PYEOF" "$TMPDIR2/profile-reconcile.py" \
    || _fail "PROFILE_RECONCILE_PYEOF extraction"

# The package reassert is an internal zero-argument root action. The XDG setup
# accepts either its public zero-argument start or the exact internal
# --detached re-entry. Replace each first host effect with a marker to prove
# hostile argv is rejected before RPM/overlay or kernel-cmdline access.
M16_ARGV_ROOT="$TMPDIR2/m16-argv-fixtures"
M16_ARGV_MARKER="$M16_ARGV_ROOT/effect-reached"
mkdir -p "$M16_ARGV_ROOT"

make_m16_argv_fixture() {
    local source=$1 anchor=$2 fixture=$3

    awk -v anchor="$anchor" -v marker="$M16_ARGV_MARKER" '
        !done && $0 == anchor {
            print "/usr/bin/printf \047%s\\n\047 reached > \047" marker "\047"
            print "exit 97"
            done=1
            next
        }
        { print }
        END { if (!done) exit 1 }
    ' "$source" > "$fixture"
    chmod 0700 "$fixture"
}

assert_m16_argv_rejected() {
    local name=$1 fixture=$2 diagnostic=$3 surplus_mode=$4
    local vector rc stdout stderr
    local -a argv

    for vector in unknown empty surplus newline escape; do
        case "$vector" in
            unknown) argv=(--unknown) ;;
            empty) argv=('') ;;
            surplus)
                if [ "$surplus_mode" = detached ]; then
                    argv=(--detached extra)
                else
                    argv=(one two)
                fi
                ;;
            newline) argv=($'hostile\nargument') ;;
            escape) argv=($'hostile\033argument') ;;
        esac

        rm -f "$M16_ARGV_MARKER"
        set +e
        stdout=$(PATH="$M16_ARGV_ROOT/untrusted-path" /bin/bash "$fixture" \
            "${argv[@]}" 2>"$M16_ARGV_ROOT/stderr")
        rc=$?
        set -e
        stderr=$(cat "$M16_ARGV_ROOT/stderr")

        assert_eq 2 "$rc" "$name rejects $vector argv before its first effect"
        assert_eq '' "$stdout" "$name keeps stdout empty for $vector argv"
        assert_eq "$diagnostic" "$stderr" "$name emits constant diagnostic for $vector argv"
        if [ -e "$M16_ARGV_MARKER" ]; then
            _fail "$name reached its first effect for $vector argv"
        else
            _pass "$name keeps its first effect unreachable for $vector argv"
        fi
    done
}

make_m16_argv_fixture "$TMPDIR2/firefox-reassert.sh" \
    'install -d -m 0755 /usr/local/bin /usr/local/share/applications' \
    "$M16_ARGV_ROOT/firefox-reassert"
make_m16_argv_fixture "$TMPDIR2/setup.sh" \
    'CMDLINE_FILE=/proc/cmdline' "$M16_ARGV_ROOT/firefox-setup"
assert_cmd_success "Firefox reassert argv fixture Bash syntax" \
    /bin/bash -n "$M16_ARGV_ROOT/firefox-reassert"
assert_cmd_success "Firefox setup argv fixture Bash syntax" \
    /bin/bash -n "$M16_ARGV_ROOT/firefox-setup"
assert_m16_argv_rejected \
    "Firefox reassert" "$M16_ARGV_ROOT/firefox-reassert" \
    "ERROR: noid-firefox-reassert accepts no arguments" zero
assert_m16_argv_rejected \
    "Firefox setup" "$M16_ARGV_ROOT/firefox-setup" \
    "ERROR: noid-firefox-setup accepts only zero arguments or --detached" detached

rm -f "$M16_ARGV_MARKER"
set +e
PATH="$M16_ARGV_ROOT/untrusted-path" /bin/bash \
    "$M16_ARGV_ROOT/firefox-reassert" >/dev/null 2>"$M16_ARGV_ROOT/stderr"
M16_VALID_RC=$?
set -e
assert_eq 97 "$M16_VALID_RC" "Firefox reassert accepts its zero-argument contract"
assert_file_exists "$M16_ARGV_MARKER" \
    "Firefox reassert reaches its first effect without argv"
for setup_contract in zero detached; do
    rm -f "$M16_ARGV_MARKER"
    set +e
    if [ "$setup_contract" = detached ]; then
        PATH="$M16_ARGV_ROOT/untrusted-path" /bin/bash \
            "$M16_ARGV_ROOT/firefox-setup" --detached \
            >/dev/null 2>"$M16_ARGV_ROOT/stderr"
    else
        PATH="$M16_ARGV_ROOT/untrusted-path" /bin/bash \
            "$M16_ARGV_ROOT/firefox-setup" \
            >/dev/null 2>"$M16_ARGV_ROOT/stderr"
    fi
    M16_VALID_RC=$?
    set -e
    assert_eq 97 "$M16_VALID_RC" \
        "Firefox setup accepts its exact $setup_contract contract"
    assert_file_exists "$M16_ARGV_MARKER" \
        "Firefox setup reaches its first effect for $setup_contract"
done
assert_grep_fixed 'PATH=/usr/sbin:/usr/bin' "$TMPDIR2/firefox-reassert.sh" \
    "Firefox root reassert uses a closed system command path"
assert_grep_fixed 'export PATH' "$TMPDIR2/firefox-reassert.sh" \
    "Firefox root reassert exports its closed command path"

assert_cmd_success "profile reconciler Python syntax" \
    python3 -m py_compile "$TMPDIR2/profile-reconcile.py"
assert_grep_fixed 'unrelated registrations preserved' "$TMPDIR2/profile-reconcile.py" \
    "profile reconciler preserves custom registrations"
assert_grep_fixed 'generated_default and not os.path.isdir(full_path)' \
    "$TMPDIR2/profile-reconcile.py" \
    "only proven missing generated-default registrations are removed"

PROFILE_FIXTURE="$TMPDIR2/profile-fixture"
mkdir -p "$PROFILE_FIXTURE/hash.default-release" "$PROFILE_FIXTURE/custom.profile"
cat > "$PROFILE_FIXTURE/profiles.ini" <<'PROFILE_FIXTURE_EOF'
[Profile0]
Name=default
IsRelative=1
Path=stale.default
Default=1

[Profile1]
Name=Custom Research
IsRelative=1
Path=custom.profile

[General]
StartWithLastProfile=1
PROFILE_FIXTURE_EOF
assert_cmd_success "profile reconciler runtime fixture" \
    python3 "$TMPDIR2/profile-reconcile.py" "$PROFILE_FIXTURE/profiles.ini" \
        "$PROFILE_FIXTURE" hash.default-release
assert_grep_fixed 'Name=Custom Research' "$PROFILE_FIXTURE/profiles.ini" \
    "unrelated registered profile survives setup rerun"
assert_grep_fixed 'Path=custom.profile' "$PROFILE_FIXTURE/profiles.ini" \
    "unrelated profile path survives setup rerun"
assert_grep_fixed 'Name=default-release' "$PROFILE_FIXTURE/profiles.ini" \
    "active profile receives canonical launcher name"
assert_not_grep 'Path=stale.default' "$PROFILE_FIXTURE/profiles.ini" \
    "missing generated default orphan is removed"
if grep -qF 'sleep 10' "$TMPDIR2/setup.sh"; then
    _fail "setup script has pre-hardening sleep 10 race"
else
    _pass "setup script has no pre-hardening sleep 10 race"
fi
if grep -qE 'pkill .*firefox|pkill .*contentproc' "$TMPDIR2/setup.sh"; then
    _fail "setup script still broadly kills Firefox processes"
else
    _pass "setup script does not broadly kill user Firefox processes"
fi
assert_not_grep_extended 'rm -f .*places\.sqlite|rm -f .*favicons\.sqlite|rm -rf .*bookmarkbackups' \
    "$TMPDIR2/setup.sh" \
    "automatic setup contains no destructive history/bookmark cleanup"
assert_not_grep_extended 'quarantin.*orphan|mv .*orphan' "$TMPDIR2/setup.sh" \
    "automatic setup never moves a profile based on an orphan heuristic"
assert_grep_fixed 'required_outputs_valid()' "$TMPDIR2/setup.sh" \
    "success state and installed outputs share one exact validator"
assert_grep_fixed 'profile_userjs_supported default-release "$ACTIVE_PROFILE"' \
    "$TMPDIR2/setup.sh" \
    "recurring setup shares the FPP/WebRTC-aware user.js predicate"
assert_grep_fixed 'if ! atomic_install "$UBO_XPI" "$UBO_TARGET" 644' "$TMPDIR2/setup.sh" \
    "uBO profile install is atomic and required"
assert_grep_fixed 'preserved existing xulstore.json byte-for-byte' "$TMPDIR2/setup.sh" \
    "existing Firefox window state is explicitly preserved"
assert_not_grep_extended 'touch "\$STATE_FILE"|WARN: extension-preferences.json patch failed' \
    "$TMPDIR2/setup.sh" \
    "setup cannot stamp success after a best-effort permission update"
assert_grep_fixed 'NOID_TEST_CMDLINE_FILE' "$TMPDIR2/setup.sh" \
    "Firefox setup fixture cannot inherit the host kernel command line"
assert_grep_fixed 'FIREFOX_CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/mozilla/firefox"' \
    "$TMPDIR2/setup.sh" "Firefox setup honors the XDG configuration root"
assert_grep_fixed 'validate_active_profile_boundary "$ACTIVE_PROFILE"' \
    "$TMPDIR2/setup.sh" "automatic setup validates its complete profile write boundary"
assert_grep_fixed 'PROFILE_HELPER="/usr/local/lib/noid-privacy/firefox-profiles.sh"' \
    "$TMPDIR2/setup.sh" "first-login setup names the shared profile helper exactly"
assert_grep_fixed 'if [[ ! -f "$PROFILE_HELPER" ]] || [[ -L "$PROFILE_HELPER" ]]; then' \
    "$TMPDIR2/setup.sh" "first-login setup rejects a missing or symlinked profile helper"
assert_grep_fixed '. "$PROFILE_HELPER"' "$TMPDIR2/setup.sh" \
    "first-login setup loads the shared process guard"
SETUP_PROFILE_SOURCE_LINE=$(grep -nF '. "$PROFILE_HELPER"' "$TMPDIR2/setup.sh" \
    | cut -d: -f1 || true)
SETUP_PROCESS_GUARD_LINE=$(grep -nF 'if firefox_process_active; then' \
    "$TMPDIR2/setup.sh" | head -n1 | cut -d: -f1 || true)
if [ -n "$SETUP_PROFILE_SOURCE_LINE" ] && \
   [ -n "$SETUP_PROCESS_GUARD_LINE" ] && \
   [ "$SETUP_PROFILE_SOURCE_LINE" -lt "$SETUP_PROCESS_GUARD_LINE" ]; then
    _pass "first-login setup loads the shared helper before process detection"
else
    _fail "first-login setup loads the shared helper before process detection"
fi
assert_grep_fixed 'if firefox_process_active; then' "$TMPDIR2/setup.sh" \
    "first-login process detection ignores dead tasks through the shared guard"
for profile_writer in "$TMPDIR2/harden.sh" "$TMPDIR2/relax-fpp.sh" \
        "$TMPDIR2/relax-webrtc.sh" "$TMPDIR2/firefox-drm.sh"; do
    assert_grep_fixed 'if firefox_process_active; then' "$profile_writer" \
        "profile writer uses process-state-aware Firefox detection"
done

# Runtime contract: exercise success, exact-state skip, drift repair, invalid
# inputs, conflicting user configuration, and lock contention against a real
# filesystem tree. The fixture carries established history/bookmark/window
# sentinels whose bytes must survive every path.
FIREFOX_SETUP_FIXTURE=$(mktemp -d "$PROJECT_ROOT/.test-firefox-setup.XXXXXXXX")
FF_SETUP_HOME="$FIREFOX_SETUP_FIXTURE/home"
FF_SETUP_STATE="$FIREFOX_SETUP_FIXTURE/state"
FF_SETUP_SOURCE="$FIREFOX_SETUP_FIXTURE/source"
FF_SETUP_BIN="$FIREFOX_SETUP_FIXTURE/bin"
FF_SETUP_CONFIG="$FIREFOX_SETUP_FIXTURE/xdg-config"
FF_SETUP_FIREFOX_ROOT="$FF_SETUP_CONFIG/mozilla/firefox"
FF_SETUP_PROFILE="$FF_SETUP_FIREFOX_ROOT/default-release"
FF_SETUP_SCRIPT="$FIREFOX_SETUP_FIXTURE/setup.sh"
FF_SETUP_LIBRARY="$FIREFOX_SETUP_FIXTURE/firefox-profiles.sh"
FF_SETUP_INSTALLED_CMDLINE="$FIREFOX_SETUP_FIXTURE/installed.cmdline"
FF_SETUP_LIVE_CMDLINE="$FIREFOX_SETUP_FIXTURE/live.cmdline"
mkdir -p "$FF_SETUP_HOME" "$FF_SETUP_PROFILE/bookmarkbackups" \
    "$FF_SETUP_SOURCE" "$FF_SETUP_BIN"
chmod 700 "$FF_SETUP_PROFILE"
printf '%s\n' 'root=UUID=fixture quiet' > "$FF_SETUP_INSTALLED_CMDLINE"
printf '%s\n' 'root=live:CDLABEL=NOID rd.live.image quiet' > "$FF_SETUP_LIVE_CMDLINE"
cp "$TMPDIR2/setup.sh" "$FF_SETUP_SCRIPT"
cp "$TMPDIR2/firefox-profiles.sh" "$FF_SETUP_LIBRARY"
printf '%s\n' \
    '// NoID Privacy Firefox setup runtime fixture' \
    'user_pref("_noid.fixture", true);' > "$FF_SETUP_SOURCE/user.js"
cp "$TMPDIR2/drm-overrides.js" "$FF_SETUP_SOURCE/user-drm-overrides.js"
create_test_xpi "$FF_SETUP_SOURCE/ubo.xpi" uBlock0@raymondhill.net 1.73.0 - - 1
FF_SETUP_UBO_SHA=$(sha256sum "$FF_SETUP_SOURCE/ubo.xpi" | awk '{print $1}')
FF_SETUP_UBO_SIZE=$(stat -c '%s' "$FF_SETUP_SOURCE/ubo.xpi")
sed -i \
    -e "s|^NOID_FF_USERJS_BASE=.*|NOID_FF_USERJS_BASE=\"$FF_SETUP_SOURCE/user.js\"|" \
    -e "s|^NOID_FF_USERJS_DRM_OVERRIDES=.*|NOID_FF_USERJS_DRM_OVERRIDES=\"$FF_SETUP_SOURCE/user-drm-overrides.js\"|" \
    "$FF_SETUP_LIBRARY"
sed -i \
    -e "s|^SOURCE_DIR=.*|SOURCE_DIR=\"$FF_SETUP_SOURCE\"|" \
    -e "s|^UBO_XPI=.*|UBO_XPI=\"$FF_SETUP_SOURCE/ubo.xpi\"|" \
    -e "s|^UBO_SHA256=.*|UBO_SHA256=\"$FF_SETUP_UBO_SHA\"|" \
    -e "s|^UBO_SIZE_EXPECTED=.*|UBO_SIZE_EXPECTED=$FF_SETUP_UBO_SIZE|" \
    -e "s|^WEBEXT_VALIDATOR=.*|WEBEXT_VALIDATOR=\"$TMPDIR2/validate-webextension.py\"|" \
    -e "s|^PROFILE_HELPER=.*|PROFILE_HELPER=\"$FF_SETUP_LIBRARY\"|" \
    -e "s|/usr/local/bin/noid-firefox-playground-init.sh|$FIREFOX_SETUP_FIXTURE/nonexistent-playground-init.sh|g" \
    "$FF_SETUP_SCRIPT"
cat > "$FF_SETUP_BIN/pgrep" <<'FF_SETUP_PGREP_EOF'
#!/bin/sh
set -eu
: "${NOID_TEST_PGREP_LOG:?}"
printf '%s\n' "$*" >> "$NOID_TEST_PGREP_LOG"
exit 1
FF_SETUP_PGREP_EOF
cat > "$FF_SETUP_BIN/notify-send" <<'FF_SETUP_NOTIFY_EOF'
#!/bin/sh
set -eu
[ -z "${DBUS_SESSION_BUS_ADDRESS+x}" ]
[ -z "${DISPLAY+x}" ]
[ -z "${WAYLAND_DISPLAY+x}" ]
: "${NOID_TEST_NOTIFY_LOG:?}"
printf '%s\n' "$*" >> "$NOID_TEST_NOTIFY_LOG"
FF_SETUP_NOTIFY_EOF
cat > "$FF_SETUP_BIN/logger" <<'FF_SETUP_LOGGER_EOF'
#!/bin/sh
set -eu
: "${NOID_TEST_LOGGER_LOG:?}"
printf '%s\n' "$*" >> "$NOID_TEST_LOGGER_LOG"
FF_SETUP_LOGGER_EOF
chmod 700 "$FF_SETUP_BIN/pgrep" "$FF_SETUP_BIN/notify-send" \
    "$FF_SETUP_BIN/logger"
cat > "$FF_SETUP_FIREFOX_ROOT/profiles.ini" <<'FF_SETUP_PROFILES_EOF'
[Profile0]
Name=default-release
IsRelative=1
Path=default-release
Default=1

[General]
StartWithLastProfile=1
Version=2
FF_SETUP_PROFILES_EOF
printf '%s' 'established places database sentinel' > "$FF_SETUP_PROFILE/places.sqlite"
printf '%s' 'established favicons database sentinel' > "$FF_SETUP_PROFILE/favicons.sqlite"
printf '%s' 'established bookmark backup sentinel' \
    > "$FF_SETUP_PROFILE/bookmarkbackups/bookmarks-2026-07-13.jsonlz4"
printf '%s' 'established xulstore window-state sentinel' > "$FF_SETUP_PROFILE/xulstore.json"
cat > "$FF_SETUP_PROFILE/extension-preferences.json" <<'FF_SETUP_PREFS_EOF'
{
  "keep@example.invalid": {
    "permissions": ["fixture:preserve"],
    "origins": [],
    "data_collection": []
  }
}
FF_SETUP_PREFS_EOF
chmod 600 "$FF_SETUP_PROFILE/extension-preferences.json"

FF_PLACES_SHA=$(sha256sum "$FF_SETUP_PROFILE/places.sqlite" | awk '{print $1}')
FF_FAVICONS_SHA=$(sha256sum "$FF_SETUP_PROFILE/favicons.sqlite" | awk '{print $1}')
FF_BOOKMARK_SHA=$(sha256sum "$FF_SETUP_PROFILE/bookmarkbackups/bookmarks-2026-07-13.jsonlz4" | awk '{print $1}')
FF_XULSTORE_SHA=$(sha256sum "$FF_SETUP_PROFILE/xulstore.json" | awk '{print $1}')
assert_profile_data_preserved() {
    assert_eq "$FF_PLACES_SHA" \
        "$(sha256sum "$FF_SETUP_PROFILE/places.sqlite" | awk '{print $1}')" \
        "established places.sqlite bytes survive setup path"
    assert_eq "$FF_FAVICONS_SHA" \
        "$(sha256sum "$FF_SETUP_PROFILE/favicons.sqlite" | awk '{print $1}')" \
        "established favicons.sqlite bytes survive setup path"
    assert_eq "$FF_BOOKMARK_SHA" \
        "$(sha256sum "$FF_SETUP_PROFILE/bookmarkbackups/bookmarks-2026-07-13.jsonlz4" | awk '{print $1}')" \
        "established bookmark backup bytes survive setup path"
    assert_eq "$FF_XULSTORE_SHA" \
        "$(sha256sum "$FF_SETUP_PROFILE/xulstore.json" | awk '{print $1}')" \
        "established xulstore.json bytes survive setup path"
}
run_setup_fixture() {
    local cmdline_file=${1:-$FF_SETUP_INSTALLED_CMDLINE}
    env -u DBUS_SESSION_BUS_ADDRESS -u DISPLAY -u WAYLAND_DISPLAY \
        HOME="$FF_SETUP_HOME" XDG_CONFIG_HOME="$FF_SETUP_CONFIG" \
        XDG_STATE_HOME="$FF_SETUP_STATE" \
        NOID_TEST_MODE=1 NOID_TEST_CMDLINE_FILE="$cmdline_file" \
        NOID_TEST_NOTIFY_LOG="$FIREFOX_SETUP_FIXTURE/notifications.log" \
        NOID_TEST_LOGGER_LOG="$FIREFOX_SETUP_FIXTURE/logger.log" \
        NOID_TEST_PGREP_LOG="$FIREFOX_SETUP_FIXTURE/pgrep.log" \
        NOID_TEST_LOGGER_BACKEND="$FF_SETUP_BIN/logger" \
        PATH="$FF_SETUP_BIN:$PATH" bash "$FF_SETUP_SCRIPT" --detached
}

assert_cmd_success "Firefox setup live fixture is an explicit no-op" \
    run_setup_fixture "$FF_SETUP_LIVE_CMDLINE"
if [ ! -e "$FF_SETUP_STATE/noid-privacy/firefox-setup.done" ]; then
    _pass "live fixture cannot publish installed-user state"
else
    _fail "live fixture cannot publish installed-user state"
fi
assert_cmd_success "Firefox setup runtime fixture completes" run_setup_fixture
assert_file_exists "$FIREFOX_SETUP_FIXTURE/pgrep.log" \
    "runtime setup executes the sourced process guard"
assert_profile_data_preserved
FF_SETUP_DONE="$FF_SETUP_STATE/noid-privacy/firefox-setup.done"
assert_file_exists "$FF_SETUP_DONE" "setup publishes success state after postconditions"
assert_eq 4 "$(wc -l < "$FF_SETUP_DONE")" "setup state has exact four-line schema"
assert_grep_fixed 'NOID_FIREFOX_SETUP_V1' "$FF_SETUP_DONE" "setup state schema is versioned"
assert_grep_fixed "profile=$(readlink -e "$FF_SETUP_PROFILE")" "$FF_SETUP_DONE" \
    "setup state is bound to the canonical active profile"
assert_not_grep "$FF_SETUP_HOME/.config/mozilla/firefox" "$FF_SETUP_DONE" \
    "setup does not silently fall back from the explicit XDG configuration root"
assert_grep_fixed "userjs_sha256=$(sha256sum "$FF_SETUP_SOURCE/user.js" | awk '{print $1}')" \
    "$FF_SETUP_DONE" "setup state is bound to canonical user.js bytes"
assert_grep_fixed "ubo_sha256=$FF_SETUP_UBO_SHA" "$FF_SETUP_DONE" \
    "setup state is bound to reviewed uBO bytes"
assert_eq 600 "$(stat -c '%a' "$FF_SETUP_DONE")" "setup state is private"
if python3 - "$FF_SETUP_PROFILE/extension-preferences.json" <<'FF_SETUP_VALIDATE_PREFS_EOF'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
assert data["keep@example.invalid"]["permissions"] == ["fixture:preserve"]
assert data["uBlock0@raymondhill.net"]["permissions"] == ["internal:privateBrowsingAllowed"]
FF_SETUP_VALIDATE_PREFS_EOF
then
    _pass "permission update preserves unrelated extension records"
else
    _fail "permission update preserves unrelated extension records"
fi

if run_setup_fixture > "$FIREFOX_SETUP_FIXTURE/exact-state.log" 2>&1; then
    _pass "exact valid state rerun succeeds"
else
    _fail "exact valid state rerun succeeds"
fi
assert_grep_fixed 'exact setup state and required outputs are valid, skip' \
    "$FIREFOX_SETUP_FIXTURE/exact-state.log" \
    "exact state skips only after installed-output validation"
assert_profile_data_preserved

chmod 644 "$FF_SETUP_PROFILE/extension-preferences.json"
if run_setup_fixture > "$FIREFOX_SETUP_FIXTURE/native-permission-mode.log" 2>&1; then
    _pass "recurring setup accepts Firefox-native permission-store mode"
else
    sed 's/^/    setup: /' "$FIREFOX_SETUP_FIXTURE/native-permission-mode.log"
    _fail "recurring setup accepts Firefox-native permission-store mode"
fi
assert_grep_fixed 'exact setup state and required outputs are valid, skip' \
    "$FIREFOX_SETUP_FIXTURE/native-permission-mode.log" \
    "Firefox-native permission mode does not trigger a rewrite loop"
assert_eq 644 "$(stat -c '%a' "$FF_SETUP_PROFILE/extension-preferences.json")" \
    "recurring setup preserves Firefox-owned permission-store mode"
chmod 600 "$FF_SETUP_PROFILE/extension-preferences.json"

# A supported explicit DRM overlay remains a valid setup state. The recurring
# XDG autostart must neither reject nor replace it on the next login.
cat "$FF_SETUP_SOURCE/user.js" "$FF_SETUP_SOURCE/user-drm-overrides.js" \
    > "$FF_SETUP_PROFILE/user.js"
printf '%s\n' NOID_FIREFOX_DRM_OPT_IN_V1 \
    > "$FF_SETUP_PROFILE/.noid-drm-enabled"
chmod 600 "$FF_SETUP_PROFILE/user.js" "$FF_SETUP_PROFILE/.noid-drm-enabled"
FF_SETUP_DRM_SHA=$(sha256sum "$FF_SETUP_PROFILE/user.js" | awk '{print $1}')
if run_setup_fixture > "$FIREFOX_SETUP_FIXTURE/drm-consent.log" 2>&1; then
    _pass "recurring Firefox setup accepts supported DRM consent state"
else
    sed 's/^/    setup: /' "$FIREFOX_SETUP_FIXTURE/drm-consent.log"
    _fail "recurring Firefox setup accepts supported DRM consent state"
fi
assert_eq "$FF_SETUP_DRM_SHA" \
    "$(sha256sum "$FF_SETUP_PROFILE/user.js" | awk '{print $1}')" \
    "recurring setup preserves the exact DRM overlay bytes"
assert_grep_fixed 'exact setup state and required outputs are valid, skip' \
    "$FIREFOX_SETUP_FIXTURE/drm-consent.log" \
    "supported DRM consent satisfies the exact recurring setup gate"
assert_profile_data_preserved
rm -f "$FF_SETUP_PROFILE/.noid-drm-enabled"
cp "$FF_SETUP_SOURCE/user.js" "$FF_SETUP_PROFILE/user.js"
chmod 600 "$FF_SETUP_PROFILE/user.js"

# Supported FPP/WebRTC compatibility choices are part of the shared user.js
# contract. The recurring login job must accept and preserve their canonical
# bytes instead of raising a review error on every session.
env HOME="$FF_SETUP_HOME" XDG_CONFIG_HOME="$FF_SETUP_CONFIG" \
    bash -c '. "$1"; noid_fpp_relaxation_block; noid_webrtc_relaxation_block' \
    bash "$FF_SETUP_LIBRARY" >> "$FF_SETUP_PROFILE/user.js"
FF_SETUP_RELAX_SHA=$(sha256sum "$FF_SETUP_PROFILE/user.js" | awk '{print $1}')
if run_setup_fixture > "$FIREFOX_SETUP_FIXTURE/compatibility-opt-ins.log" 2>&1; then
    _pass "recurring Firefox setup accepts supported compatibility opt-ins"
else
    sed 's/^/    setup: /' "$FIREFOX_SETUP_FIXTURE/compatibility-opt-ins.log"
    _fail "recurring Firefox setup accepts supported compatibility opt-ins"
fi
assert_eq "$FF_SETUP_RELAX_SHA" \
    "$(sha256sum "$FF_SETUP_PROFILE/user.js" | awk '{print $1}')" \
    "recurring setup preserves supported FPP/WebRTC bytes"
assert_grep_fixed 'exact setup state and required outputs are valid, skip' \
    "$FIREFOX_SETUP_FIXTURE/compatibility-opt-ins.log" \
    "supported compatibility choices satisfy the recurring setup gate"
cp "$FF_SETUP_SOURCE/user.js" "$FF_SETUP_PROFILE/user.js"
chmod 600 "$FF_SETUP_PROFILE/user.js"

# An exact state record is not trusted blindly: missing installed uBO is
# repaired and all user-owned data remains unchanged.
rm -f "$FF_SETUP_PROFILE/extensions/uBlock0@raymondhill.net.xpi"
if run_setup_fixture > "$FIREFOX_SETUP_FIXTURE/drift-repair.log" 2>&1; then
    _pass "exact-state output drift is repaired"
else
    sed 's/^/    setup: /' "$FIREFOX_SETUP_FIXTURE/drift-repair.log"
    _fail "exact-state output drift is repaired"
fi
assert_eq "$FF_SETUP_UBO_SHA" \
    "$(sha256sum "$FF_SETUP_PROFILE/extensions/uBlock0@raymondhill.net.xpi" | awk '{print $1}')" \
    "repaired profile uBO matches reviewed bytes"
assert_profile_data_preserved

# An Update-All-advanced profile XPI is user-owned state: a full re-run (state
# record removed) must preserve its exact bytes instead of downgrading
# them to the image seed, and still complete successfully.
rm -f "$FF_SETUP_DONE"
create_test_xpi "$FF_SETUP_PROFILE/extensions/uBlock0@raymondhill.net.xpi" \
    uBlock0@raymondhill.net 1.73.0 - - 1
FF_UPDATED_UBO_SHA=$(sha256sum \
    "$FF_SETUP_PROFILE/extensions/uBlock0@raymondhill.net.xpi" | awk '{print $1}')
if run_setup_fixture > "$FIREFOX_SETUP_FIXTURE/preserve-update.log" 2>&1; then
    _pass "full re-run accepts an Update-All-advanced profile uBO"
else
    sed 's/^/    setup: /' "$FIREFOX_SETUP_FIXTURE/preserve-update.log"
    _fail "full re-run accepts an Update-All-advanced profile uBO"
fi
assert_eq "$FF_UPDATED_UBO_SHA" \
    "$(sha256sum "$FF_SETUP_PROFILE/extensions/uBlock0@raymondhill.net.xpi" | awk '{print $1}')" \
    "Update-All-advanced profile uBO is preserved, never downgraded"
assert_grep_fixed 'preserved existing validated uBO XPI' \
    "$FIREFOX_SETUP_FIXTURE/preserve-update.log" \
    "setup names the preserve decision explicitly"
assert_file_exists "$FF_SETUP_DONE" \
    "setup republishes success state around a preserved updated XPI"
assert_profile_data_preserved
# Restore the reviewed seed bytes for the scenarios below.
rm -f "$FF_SETUP_DONE" \
    "$FF_SETUP_PROFILE/extensions/uBlock0@raymondhill.net.xpi"
assert_cmd_success "reseed restores the reviewed uBO fixture" run_setup_fixture

# Invalid extension preference JSON is user-owned evidence. Preserve it,
# fail closed, and never publish success.
rm -f "$FF_SETUP_DONE"
printf '%s' '{invalid-user-json' > "$FF_SETUP_PROFILE/extension-preferences.json"
FF_INVALID_PREFS_SHA=$(sha256sum "$FF_SETUP_PROFILE/extension-preferences.json" | awk '{print $1}')
assert_cmd_failure "invalid extension preferences abort setup" run_setup_fixture
assert_eq "$FF_INVALID_PREFS_SHA" \
    "$(sha256sum "$FF_SETUP_PROFILE/extension-preferences.json" | awk '{print $1}')" \
    "invalid user extension preferences are preserved byte-for-byte"
if [ ! -e "$FF_SETUP_DONE" ]; then
    _pass "failed permission update publishes no success state"
else
    _fail "failed permission update publishes no success state"
fi
assert_profile_data_preserved
rm -f "$FF_SETUP_PROFILE/extension-preferences.json"
if run_setup_fixture > "$FIREFOX_SETUP_FIXTURE/preference-recovery.log" 2>&1; then
    _pass "setup recovers after reviewed removal of invalid preferences"
else
    sed 's/^/    setup: /' "$FIREFOX_SETUP_FIXTURE/preference-recovery.log"
    _fail "setup recovers after reviewed removal of invalid preferences"
fi

# Required source absence and a conflicting user.js both fail before a new
# success record; the conflicting user.js remains untouched.
rm -f "$FF_SETUP_DONE"
mv "$FF_SETUP_SOURCE/ubo.xpi" "$FF_SETUP_SOURCE/ubo.xpi.missing"
assert_cmd_failure "missing required uBO source aborts setup" run_setup_fixture
if [ ! -e "$FF_SETUP_DONE" ]; then
    _pass "missing required uBO source publishes no success state"
else
    _fail "missing required uBO source publishes no success state"
fi
mv "$FF_SETUP_SOURCE/ubo.xpi.missing" "$FF_SETUP_SOURCE/ubo.xpi"
printf '%s' 'user-owned noncanonical user.js' > "$FF_SETUP_PROFILE/user.js"
FF_CONFLICT_USERJS_SHA=$(sha256sum "$FF_SETUP_PROFILE/user.js" | awk '{print $1}')
assert_cmd_failure "noncanonical established user.js requires explicit review" run_setup_fixture
assert_eq "$FF_CONFLICT_USERJS_SHA" \
    "$(sha256sum "$FF_SETUP_PROFILE/user.js" | awk '{print $1}')" \
    "noncanonical established user.js is preserved byte-for-byte"
if [ ! -e "$FF_SETUP_DONE" ]; then
    _pass "user.js conflict publishes no success state"
else
    _fail "user.js conflict publishes no success state"
fi
assert_profile_data_preserved
assert_grep_fixed 'NoID Privacy Firefox Setup Error' \
    "$FIREFOX_SETUP_FIXTURE/notifications.log" \
    "setup error notification is captured inside the fixture"
assert_grep_fixed 'NoID Privacy Firefox Setup Needs Review' \
    "$FIREFOX_SETUP_FIXTURE/notifications.log" \
    "review notification is captured inside the fixture"
assert_file_exists "$FIREFOX_SETUP_FIXTURE/logger.log" \
    "setup journal traffic is captured inside the fixture"
cp "$FF_SETUP_SOURCE/user.js" "$FF_SETUP_PROFILE/user.js"
chmod 600 "$FF_SETUP_PROFILE/user.js"

# The per-user lock makes concurrent mutation impossible and uses the retry
# exit code without claiming success.
FF_SETUP_LOCK="$FF_SETUP_STATE/noid-privacy/firefox-profile-operations.lock"
exec 8>"$FF_SETUP_LOCK"
flock -n 8
set +e
run_setup_fixture > "$FIREFOX_SETUP_FIXTURE/locked.log" 2>&1
FF_LOCKED_RC=$?
set -e
flock -u 8
exec 8>&-
assert_eq 75 "$FF_LOCKED_RC" "concurrent setup returns the explicit retry code"
if [ ! -e "$FF_SETUP_DONE" ]; then
    _pass "lock contention performs no success publication"
else
    _fail "lock contention performs no success publication"
fi
assert_profile_data_preserved
if run_setup_fixture > "$FIREFOX_SETUP_FIXTURE/lock-retry.log" 2>&1; then
    _pass "interrupted/locked setup is safely retryable"
else
    sed 's/^/    setup: /' "$FIREFOX_SETUP_FIXTURE/lock-retry.log"
    _fail "interrupted/locked setup is safely retryable"
fi
assert_profile_data_preserved

# A valid Firefox profile may live below multiple relative path components.
# Registration reconciliation must retain that complete path instead of
# collapsing it to the leaf directory name.
FF_SETUP_NESTED_PROFILE="$FF_SETUP_FIREFOX_ROOT/profiles/nested/default-release"
mkdir -p "$(dirname "$FF_SETUP_NESTED_PROFILE")"
mv "$FF_SETUP_PROFILE" "$FF_SETUP_NESTED_PROFILE"
FF_SETUP_PROFILE="$FF_SETUP_NESTED_PROFILE"
cat > "$FF_SETUP_FIREFOX_ROOT/profiles.ini" <<'FF_SETUP_NESTED_PROFILE_EOF'
[Profile0]
Name=default-release
IsRelative=1
Path=profiles/nested/default-release
Default=1

[General]
StartWithLastProfile=1
Version=2
FF_SETUP_NESTED_PROFILE_EOF
if run_setup_fixture > "$FIREFOX_SETUP_FIXTURE/nested-profile.log" 2>&1; then
    _pass "automatic setup supports a nested relative profile"
else
    sed 's/^/    setup: /' "$FIREFOX_SETUP_FIXTURE/nested-profile.log"
    _fail "automatic setup supports a nested relative profile"
fi
assert_grep_fixed 'Path=profiles/nested/default-release' \
    "$FF_SETUP_FIREFOX_ROOT/profiles.ini" \
    "profiles.ini retains every nested relative path component"
assert_not_grep_extended '^Path=default-release$' \
    "$FF_SETUP_FIREFOX_ROOT/profiles.ini" \
    "nested profile registration is never collapsed to its basename"
assert_grep_fixed "profile=$(readlink -e "$FF_SETUP_PROFILE")" "$FF_SETUP_DONE" \
    "setup state binds to the canonical nested active profile"
assert_profile_data_preserved

# User-controlled Firefox metadata may name external absolute or symlinked
# profiles. Automatic first-login setup must never treat either as write
# authority, even when the target is current-user-owned and writable.
FF_EXTERNAL_PROFILE="$FIREFOX_SETUP_FIXTURE/external-profile"
mkdir -p "$FF_EXTERNAL_PROFILE"
chmod 700 "$FF_EXTERNAL_PROFILE"
printf '%s' 'external profile sentinel' > "$FF_EXTERNAL_PROFILE/user.js"
FF_EXTERNAL_SHA=$(sha256sum "$FF_EXTERNAL_PROFILE/user.js" | awk '{print $1}')
rm -f "$FF_SETUP_DONE"
cat > "$FF_SETUP_FIREFOX_ROOT/profiles.ini" <<FF_SETUP_EXTERNAL_PROFILE_EOF
[Profile0]
Name=default-release
IsRelative=0
Path=$FF_EXTERNAL_PROFILE
Default=1
FF_SETUP_EXTERNAL_PROFILE_EOF
assert_cmd_failure "automatic setup rejects an external absolute profile" \
    run_setup_fixture
assert_eq "$FF_EXTERNAL_SHA" \
    "$(sha256sum "$FF_EXTERNAL_PROFILE/user.js" | awk '{print $1}')" \
    "rejected external profile bytes remain untouched"
if [ ! -e "$FF_SETUP_DONE" ]; then
    _pass "external profile rejection publishes no setup state"
else
    _fail "external profile rejection publishes no setup state"
fi

ln -s "$FF_EXTERNAL_PROFILE" "$FF_SETUP_FIREFOX_ROOT/linked-profile"
cat > "$FF_SETUP_FIREFOX_ROOT/profiles.ini" <<'FF_SETUP_LINKED_PROFILE_EOF'
[Profile0]
Name=default-release
IsRelative=1
Path=linked-profile
Default=1
FF_SETUP_LINKED_PROFILE_EOF
assert_cmd_failure "automatic setup rejects a symlinked in-root profile" \
    run_setup_fixture
assert_eq "$FF_EXTERNAL_SHA" \
    "$(sha256sum "$FF_EXTERNAL_PROFILE/user.js" | awk '{print $1}')" \
    "rejected symlink target bytes remain untouched"
if [ ! -e "$FF_SETUP_DONE" ]; then
    _pass "symlinked profile rejection publishes no setup state"
else
    _fail "symlinked profile rejection publishes no setup state"
fi

# --- M25 noid-update-all.sh cross-check -------------------------------------
M25_FILE="$PROJECT_ROOT/kickstart/snippets/25-update-process.ks"
assert_grep_fixed 'HARDENED_PROFILES'             "$M25_FILE" "M25: HARDENED_PROFILES (post-absorption)"
assert_grep_fixed 'UNHARDENED_PROFILES'           "$M25_FILE" "M25: detects unhardened profiles"
assert_grep_fixed 'noid-firefox-harden-profile'   "$M25_FILE" "M25: references helper in warning"
# Regression: M25 must NOT reference arkenfox updater.sh as active invocation
if grep -qE '^[^#]*\$\{profile_path\}/updater\.sh' "$M25_FILE"; then
    _fail "M25: still invokes arkenfox updater.sh (post-absorption regression)"
else
    _pass "M25: no active updater.sh invocation (post-absorption clean)"
fi

# --- Reduced-dependency cache runtime contract -----------------------------
# Patch only the fixture copies to use a tiny local payload. This exercises the
# complete redirect/manifest/tree logic without adding a network dependency to
# the structural suite.
REDUCED_FIXTURE=$(mktemp -d "$PROJECT_ROOT/.test-reduced-dependency.XXXXXXXX")
FIXTURE_REPO="$REDUCED_FIXTURE/repo"
FIXTURE_BIN="$REDUCED_FIXTURE/bin"
FIXTURE_CACHE="$REDUCED_FIXTURE/cache"
FIXTURE_BAD_CACHE="$REDUCED_FIXTURE/bad-cache"
mkdir -p "$FIXTURE_REPO/scripts" "$FIXTURE_BIN"
cp "$OFFLINE_PREP" "$FIXTURE_REPO/scripts/offline-prep.sh"
cp "$BUILD_REDUCED" "$FIXTURE_REPO/scripts/build-offline.sh"
sed -i "s#^export PATH=/usr/sbin:/usr/bin\$#export PATH=$FIXTURE_BIN:/usr/sbin:/usr/bin#" \
    "$FIXTURE_REPO/scripts/offline-prep.sh"
printf '%s' 'NoID Privacy reduced dependency fixture payload' > "$REDUCED_FIXTURE/payload.xpi"
FIXTURE_SHA=$(sha256sum "$REDUCED_FIXTURE/payload.xpi" | awk '{print $1}')
FIXTURE_SIZE=$(stat -c '%s' "$REDUCED_FIXTURE/payload.xpi")
sed -i -E \
    -e "s/^(readonly UBO_SHA256=)\"[0-9a-f]+\"/\\1\"$FIXTURE_SHA\"/" \
    -e "s/^(readonly UBO_SIZE=)\"[0-9]+\"/\\1\"$FIXTURE_SIZE\"/" \
    "$FIXTURE_REPO/scripts/offline-prep.sh" \
    "$FIXTURE_REPO/scripts/build-offline.sh"
chmod 0700 "$FIXTURE_REPO/scripts/offline-prep.sh" \
    "$FIXTURE_REPO/scripts/build-offline.sh"

cat > "$FIXTURE_BIN/curl" <<'FAKE_CURL_EOF'
#!/usr/bin/env bash
set -euo pipefail
headers=""
output=""
url=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --dump-header) headers="$2"; shift 2 ;;
        --output) output="$2"; shift 2 ;;
        --) url="$2"; shift 2 ;;
        *) shift ;;
    esac
done
[ -n "$headers" ] && [ -n "$output" ] && [ -n "$url" ]
case "$url" in
    https://github.com/*)
        redirect_host="${FAKE_REDIRECT_HOST:-release-assets.githubusercontent.com}"
        {
            printf 'HTTP/1.1 302 Found\r\n'
            printf 'Location: https://%s/reviewed-asset?fixture=1\r\n' "$redirect_host"
            if [ "${FAKE_DUPLICATE_LOCATION:-0}" = 1 ]; then
                printf 'Location: https://%s/second\r\n' "$redirect_host"
            fi
            printf '\r\n'
        } > "$headers"
        : > "$output"
        printf '302'
        ;;
    https://release-assets.githubusercontent.com/*)
        printf 'HTTP/1.1 200 OK\r\n\r\n' > "$headers"
        cp "$FAKE_PAYLOAD" "$output"
        printf '200'
        ;;
    *) exit 91 ;;
esac
FAKE_CURL_EOF
chmod 0700 "$FIXTURE_BIN/curl"

cat > "$FIXTURE_REPO/scripts/build-iso.sh" <<'FAKE_BUILDER_EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'cache=%s\nepoch=%s\nargs=%s\n' \
    "$NOID_BUILD_CACHE_DIR" "$SOURCE_DATE_EPOCH" "$*" > "$(dirname "$0")/../builder-invoked"
FAKE_BUILDER_EOF
chmod 0700 "$FIXTURE_REPO/scripts/build-iso.sh"

if env PATH="$FIXTURE_BIN:$PATH" FAKE_PAYLOAD="$REDUCED_FIXTURE/payload.xpi" \
    CACHE_DIR="$FIXTURE_CACHE" "$FIXTURE_REPO/scripts/offline-prep.sh" \
    > "$REDUCED_FIXTURE/prep.log" 2>&1; then
    _pass "reduced-dependency prep accepts reviewed redirect and pinned bytes"
else
    sed 's/^/    prep: /' "$REDUCED_FIXTURE/prep.log"
    _fail "reduced-dependency prep accepts reviewed redirect and pinned bytes"
fi
assert_grep_fixed 'NOID_REDUCED_DEPENDENCY_CACHE_V1' "$FIXTURE_CACHE/MANIFEST.txt" \
    "runtime manifest has exact versioned schema"
assert_grep_fixed "sha256=$FIXTURE_SHA" "$FIXTURE_CACHE/MANIFEST.txt" \
    "runtime manifest binds the repository-reviewed payload hash"
assert_eq 5 "$(wc -l < "$FIXTURE_CACHE/MANIFEST.txt")" \
    "runtime manifest has no unauthenticated extension fields"

assert_cmd_success "authenticated cache reaches only canonical builder" \
    env CACHE_DIR="$FIXTURE_CACHE" "$FIXTURE_REPO/scripts/build-offline.sh" --no-virt
assert_grep_fixed "cache=$FIXTURE_CACHE" "$FIXTURE_REPO/builder-invoked" \
    "canonical builder receives the verified cache root"
assert_grep_fixed 'args=--no-virt' "$FIXTURE_REPO/builder-invoked" \
    "canonical builder receives the reviewed option unchanged"

cp "$FIXTURE_CACHE/MANIFEST.txt" "$REDUCED_FIXTURE/manifest.saved"
printf 'extra=attacker-controlled\n' >> "$FIXTURE_CACHE/MANIFEST.txt"
rm -f "$FIXTURE_REPO/builder-invoked"
assert_cmd_failure "altered manifest is rejected before builder invocation" \
    env CACHE_DIR="$FIXTURE_CACHE" "$FIXTURE_REPO/scripts/build-offline.sh"
if [ ! -e "$FIXTURE_REPO/builder-invoked" ]; then
    _pass "altered manifest cannot reach canonical builder"
else
    _fail "altered manifest cannot reach canonical builder"
fi
cp "$REDUCED_FIXTURE/manifest.saved" "$FIXTURE_CACHE/MANIFEST.txt"

printf 'unexpected' > "$FIXTURE_CACHE/extra-file"
assert_cmd_failure "extra cache entry is rejected" \
    env CACHE_DIR="$FIXTURE_CACHE" "$FIXTURE_REPO/scripts/build-offline.sh"
rm -f "$FIXTURE_CACHE/extra-file"

PAYLOAD_FIXTURE_PATH="$FIXTURE_CACHE/ubo/1.73.0/uBlock0_1.73.0.firefox.signed.xpi"
mv "$PAYLOAD_FIXTURE_PATH" "$REDUCED_FIXTURE/payload.saved"
ln -s "$REDUCED_FIXTURE/payload.saved" "$PAYLOAD_FIXTURE_PATH"
assert_cmd_failure "symlinked cached payload is rejected" \
    env CACHE_DIR="$FIXTURE_CACHE" "$FIXTURE_REPO/scripts/build-offline.sh"
rm -f "$PAYLOAD_FIXTURE_PATH"
mv "$REDUCED_FIXTURE/payload.saved" "$PAYLOAD_FIXTURE_PATH"

assert_cmd_failure "unreviewed redirect host is rejected before payload publication" \
    env PATH="$FIXTURE_BIN:$PATH" FAKE_PAYLOAD="$REDUCED_FIXTURE/payload.xpi" \
        FAKE_REDIRECT_HOST=attacker.invalid CACHE_DIR="$FIXTURE_BAD_CACHE" \
        "$FIXTURE_REPO/scripts/offline-prep.sh"
if [ ! -e "$FIXTURE_BAD_CACHE/MANIFEST.txt" ] && \
   [ ! -e "$FIXTURE_BAD_CACHE/ubo/1.73.0/uBlock0_1.73.0.firefox.signed.xpi" ]; then
    _pass "failed redirect leaves no plausible cache publication"
else
    _fail "failed redirect leaves no plausible cache publication"
fi

assert_cmd_failure "duplicate redirect Location is rejected" \
    env PATH="$FIXTURE_BIN:$PATH" FAKE_PAYLOAD="$REDUCED_FIXTURE/payload.xpi" \
        FAKE_DUPLICATE_LOCATION=1 CACHE_DIR="$REDUCED_FIXTURE/duplicate-cache" \
        "$FIXTURE_REPO/scripts/offline-prep.sh"
mkdir "$REDUCED_FIXTURE/cache-target"
ln -s "$REDUCED_FIXTURE/cache-target" "$REDUCED_FIXTURE/cache-link"
assert_cmd_failure "prep rejects a symlinked parent before cache creation" \
    env CACHE_DIR="$REDUCED_FIXTURE/cache-link/new-cache" \
        "$FIXTURE_REPO/scripts/offline-prep.sh"
if [ ! -e "$REDUCED_FIXTURE/cache-target/new-cache" ]; then
    _pass "symlinked-parent rejection creates nothing at the link target"
else
    _fail "symlinked-parent rejection creates nothing at the link target"
fi
mkdir "$REDUCED_FIXTURE/component-cache" "$REDUCED_FIXTURE/component-target"
ln -s "$REDUCED_FIXTURE/component-target" \
    "$REDUCED_FIXTURE/component-cache/ubo"
assert_cmd_failure "prep rejects a symlinked cache component before traversal" \
    env CACHE_DIR="$REDUCED_FIXTURE/component-cache" \
        "$FIXTURE_REPO/scripts/offline-prep.sh"
if [ ! -e "$REDUCED_FIXTURE/component-target/1.73.0" ]; then
    _pass "symlinked cache component creates nothing at the link target"
else
    _fail "symlinked cache component creates nothing at the link target"
fi
assert_cmd_failure "retired --minimal contract fails before cache creation" \
    env CACHE_DIR="$REDUCED_FIXTURE/minimal-cache" \
        "$FIXTURE_REPO/scripts/offline-prep.sh" --minimal
if [ ! -e "$REDUCED_FIXTURE/minimal-cache" ]; then
    _pass "invalid prep CLI creates no cache state"
else
    _fail "invalid prep CLI creates no cache state"
fi
assert_cmd_success "prep help needs no cache or network" \
    env CACHE_DIR=relative "$FIXTURE_REPO/scripts/offline-prep.sh" --help
assert_cmd_success "wrapper help needs no cache or Git state" \
    env CACHE_DIR=relative "$FIXTURE_REPO/scripts/build-offline.sh" --help

test_finish
