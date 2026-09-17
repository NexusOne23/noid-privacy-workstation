#!/bin/bash
# 36-branding-structural — M32 Fedora trademark rebrand regression test
#
# Covers: M32 %post rebrand (os-release, canonical issue links,
# system-release, trademark-notice.md and ecosystem-and-support.md) plus the
# M26 package selection (generic-logos replaces fedora-logos and
# generic-release-notes is additive on Fedora 44).
# Would catch: trademark regression (fedora-logos back in %packages),
# os-release reverting to Fedora branding, missing trademark disclaimer,
# broken asset-install loop.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
M26_FILE="$PROJECT_ROOT/kickstart/snippets/26-package-set.ks"
M32_FILE="$PROJECT_ROOT/kickstart/snippets/32-branding.ks"

test_start "36-branding-structural"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

assert_file_exists "$M26_FILE"
assert_file_exists "$M32_FILE"
assert_cmd_success "bash -n $M32_FILE" bash -n "$M32_FILE"

# The product mark is exactly "NoID Privacy". Lower-case technical identifiers
# (`noid-*`, paths, package IDs) are intentionally separate. Patch files are
# excluded because removed preimage lines must remain byte-exact for `git apply`.
short_mark='No''ID'
# The official site's link label may mirror its registered hyphenated domain.
# This exact Markdown target is a domain presentation, not a product-mark
# spelling exception elsewhere in repository prose.
official_site_link="^README\\.md:[0-9]+:.*\\[${short_mark}-Privacy\\.com\\]\\(https://noid-privacy\\.com\\)"
bare_pattern="\\b${short_mark}\\b(?! Privacy)"
# Include untracked, non-ignored source just like the duplicate-mark scan.
bare_brand=$(git -C "$PROJECT_ROOT" grep --untracked --exclude-standard \
    -nP "$bare_pattern" -- ':!*.patch' 2>"$WORKDIR/bare-brand.err") \
    || brand_scan_status=$?
if [ "${brand_scan_status:-0}" -gt 1 ]; then
    sed 's/^/      /' "$WORKDIR/bare-brand.err" >&2
    _fail "brand mark scan could not run (git grep exit ${brand_scan_status})"
else
    bare_brand=$(printf '%s' "$bare_brand" | grep -vE "$official_site_link" || true)
    if [ -z "$bare_brand" ]; then
        _pass "repository text uses the complete NoID Privacy mark"
    else
        printf '%s\n' "$bare_brand" >&2
        _fail "standalone abbreviated product mark found outside patch preimages"
    fi
fi
unset brand_scan_status
spelling_pattern="${short_mark}-Privacy|${short_mark}[[:space:]]+PRIVACY"
hyphenated_brand=$(git -C "$PROJECT_ROOT" grep --untracked --exclude-standard \
    -nE "$spelling_pattern" -- ':!*.patch' 2>"$WORKDIR/spelling-brand.err") \
    || spelling_scan_status=$?
if [ "${spelling_scan_status:-0}" -gt 1 ]; then
    sed 's/^/      /' "$WORKDIR/spelling-brand.err" >&2
    _fail "brand spelling scan could not run (git grep exit ${spelling_scan_status})"
else
    hyphenated_brand=$(printf '%s' "$hyphenated_brand" |
        grep -vE "$official_site_link" || true)
    if [ -z "$hyphenated_brand" ]; then
        _pass "repository text uses exact NoID Privacy capitalization and spacing"
    else
        printf '%s\n' "$hyphenated_brand" >&2
        _fail "noncanonical NoID Privacy spelling found outside patch preimages"
    fi
fi
unset spelling_scan_status
duplicate_scan_status=0
python3 - "$PROJECT_ROOT" <<'DUPLICATE_MARK_PYEOF' || duplicate_scan_status=$?
import os
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
try:
    repository_paths = subprocess.check_output(
        [
            "git", "-C", str(root), "ls-files", "-z",
            "--cached", "--others", "--exclude-standard",
        ],
        stderr=subprocess.PIPE,
    ).split(b"\0")
except (OSError, subprocess.CalledProcessError) as exc:
    print(f"duplicate-mark scan could not enumerate repository files: {exc}", file=sys.stderr)
    raise SystemExit(2)
for raw_path in repository_paths:
    if not raw_path:
        continue
    path = root / os.fsdecode(raw_path)
    if path.suffix == ".patch" or not path.is_file():
        continue
    try:
        payload = path.read_bytes()
    except OSError as exc:
        print(f"duplicate-mark scan could not read {path}: {exc}", file=sys.stderr)
        raise SystemExit(2)
    if b"\0" in payload:
        continue
    text = payload.decode("utf-8", errors="replace")
    if re.search(r"\bNoID Privacy\s+Privacy\b", text):
        print(f"duplicated NoID Privacy mark: {path}", file=sys.stderr)
        raise SystemExit(3)
DUPLICATE_MARK_PYEOF
case "$duplicate_scan_status" in
    0) _pass "repository text has no duplicated NoID Privacy mark across line breaks" ;;
    3) _fail "duplicated NoID Privacy mark found across line breaks" ;;
    *) _fail "duplicate-mark repository scan could not run" ;;
esac

# --- M26 package swap: fedora-logos OUT, generic-logos IN -------------------
# -fedora-logos must be present as explicit exclusion
assert_grep_extended '^-fedora-logos$' "$M26_FILE" "M26: fedora-logos explicitly excluded"
# Fedora 44 has no fedora-release-notes binary package; do not turn its absent
# name into vacuous compose evidence.
assert_not_grep_extended '^-fedora-release-notes$' "$M26_FILE" \
    "M26: nonexistent fedora-release-notes exclusion is absent"
# generic-logos included (official Fedora replacement, provides system-logos)
assert_grep_extended '^generic-logos$' "$M26_FILE" "M26: generic-logos included"
# generic-release-notes included
assert_grep_extended '^generic-release-notes$' "$M26_FILE" "M26: generic-release-notes included"

# --- M32 os-release rebrand (key fields) ------------------------------------
assert_grep_fixed 'NAME="${BRAND_NAME}"'          "$M32_FILE" "M32: os-release NAME templated"
assert_grep_fixed 'ID=${BRAND_ID}'                "$M32_FILE" "M32: os-release ID templated"
assert_grep_fixed 'ID_LIKE=fedora'                "$M32_FILE" "M32: os-release ID_LIKE=fedora (compat)"
assert_grep_fixed 'BRAND_NAME="NoID Privacy Workstation"' "$M32_FILE" "M32: brand name set"
assert_grep_fixed 'BRAND_ID="noid-privacy-workstation"'   "$M32_FILE" "M32: brand ID set"
assert_grep_fixed 'publish_root_file /usr/lib/os-release 0644' "$M32_FILE" \
    "M32: os-release vendor file is published atomically"
assert_grep_fixed 'publish_relative_symlink /etc/os-release ../usr/lib/os-release' \
    "$M32_FILE" "M32: /etc/os-release is the canonical relative compatibility link"
assert_not_grep 'cat > /etc/os-release' "$M32_FILE" \
    "M32: identity repair never follows an existing /etc/os-release symlink"
NOID_PROFILE="$WORKDIR/noid-privacy.conf"
extract_heredoc "$M32_FILE" "NOIDPROF_EOF" "$NOID_PROFILE" || \
    _fail "M32 Anaconda profile extraction"
for secret in root user luks; do
    assert_grep_extended "^[[:space:]]+${secret} [(]quality 1, length 15, strict[)]$" \
        "$NOID_PROFILE" "Anaconda ${secret} minimum is exactly 15"
done
assert_not_grep_extended 'length 14|minlen=14' "$NOID_PROFILE" \
    "Anaconda profile has no stale 14-character minimum"
assert_not_grep_extended '^(hidden_spokes|hidden_webui_pages)[[:space:]]*=' \
    "$NOID_PROFILE" \
    "Anaconda profile inherits Fedora Workstation UI inventories"
assert_not_grep 'anaconda-screen-network' "$NOID_PROFILE" \
    "Anaconda profile does not invent a nonexistent Fedora 44 WebUI page"
assert_grep_fixed 'can_change_root = False' "$NOID_PROFILE" \
    "Anaconda profile pins configured-root mutation off"
assert_grep_fixed 'can_change_users = False' "$NOID_PROFILE" \
    "Anaconda profile pins configured-user mutation off"

# --- M32 /etc/issue + /etc/issue.net canonical compatibility links ----------
assert_grep_fixed 'publish_relative_symlink /etc/issue ../usr/lib/issue' \
    "$M32_FILE" "M32: /etc/issue links to the branded vendor file"
assert_grep_fixed 'publish_relative_symlink /etc/issue.net ../usr/lib/issue.net' \
    "$M32_FILE" "M32: /etc/issue.net links to the branded vendor file"

# --- M32 trademark surfaces (issue.d drop-in REMOVED) ----
# /etc/issue.d/00-noid-trademark.issue was redundant text-clutter; trademark
# notice is preserved in /etc/os-release UPSTREAM_BASE field, full disclosure
# in trademark-notice.md, and welcome dialog (M13). Verify these instead:
assert_grep_fixed 'UPSTREAM_BASE='                       "$M32_FILE" "M32: os-release UPSTREAM_BASE field (Fedora attribution)"

# --- M32 system-release overlay ---------------------------------------------
assert_grep_fixed '/etc/system-release' "$M32_FILE" "M32: /etc/system-release overlay"

# --- M32 STEP 7c: ecosystem + support doc (website / siblings / donations) ---
# The distro's only in-system cross-platform and donation surface.
# Regression here would silently re-orphan the project (zero donation surface,
# invisible Android/Windows siblings) — exactly the state before this group.
M32_HEADER="$WORKDIR/m32-header.txt"
sed -n '1,30p' "$M32_FILE" > "$M32_HEADER"
assert_grep_fixed 'STEP 7a.1 32-branding.md' "$M32_HEADER" \
    "M32 header enumerates the branding-behavior document step"
assert_grep_fixed 'STEP 7b trademark-notice.md' "$M32_HEADER" \
    "M32 header enumerates the trademark document step"
assert_grep_fixed 'STEP 7c ecosystem-and-support.md' "$M32_HEADER" \
    "M32 header enumerates the ecosystem document step"
assert_grep_fixed '/usr/share/doc/noid-privacy/32-branding.md' "$M32_FILE" \
    "M32: 32-branding.md deployed"
assert_grep_fixed '/usr/share/doc/noid-privacy/trademark-notice.md' "$M32_FILE" \
    "M32: trademark-notice.md deployed"
assert_grep_fixed '/usr/share/doc/noid-privacy/ecosystem-and-support.md' "$M32_FILE" "M32: ecosystem-and-support.md deployed"
ECOSYSTEM_DOC="$WORKDIR/ecosystem-and-support.md"
extract_heredoc "$M32_FILE" ECOSYSTEM_EOF "$ECOSYSTEM_DOC" \
    || _fail "M32 ecosystem documentation extraction"
assert_grep_fixed 'https://buymeacoffee.com/noidprivacy' "$ECOSYSTEM_DOC" \
    "M32: donation link present in the ecosystem document"
assert_grep_fixed 'play.google.com/store/apps/details?id=com.noid.privacy' \
    "$ECOSYSTEM_DOC" "M32: Android sibling Google Play link"
assert_grep_fixed 'https://github.com/NexusOne23/noid-privacy-linux' \
    "$ECOSYSTEM_DOC" "M32: Linux audit-tool sibling link"
assert_grep_fixed 'applicable host tools are detected at runtime' \
    "$ECOSYSTEM_DOC" "M32: Linux audit-tool dependency claim is scoped"
assert_not_grep 'zero dependencies' "$ECOSYSTEM_DOC" \
    "M32: Linux audit tool does not deny its host-tool dependencies"
assert_not_grep_extended '[0-9]+\+?[[:space:]]+(settings|checks|categories)' \
    "$ECOSYSTEM_DOC" \
    "M32: mutable sibling-product counters stay on the maintained website"
assert_grep_fixed 'Everything current — downloads, docs, and pricing' \
    "$ECOSYSTEM_DOC" \
    "M32: installed document delegates current product facts to the website"
assert_not_grep 'one independent developer' "$ECOSYSTEM_DOC" \
    "M32: mutable maintainer-count claim is absent"
assert_not_grep 'only place the OS tells you' "$ECOSYSTEM_DOC" \
    "M32: ecosystem text matches its three documented local surfaces"
assert_grep_fixed 'original artwork retain' "$ECOSYSTEM_DOC" \
    "M32: ecosystem text preserves the artwork licensing boundary"

# --- M32 mandatory verified asset delivery ---------------------------------
assert_grep_fixed 'BRANDING_PAYLOAD='              "$M32_FILE" "M32: payload detection variable"
assert_not_grep 'HTTP fallback' "$M32_FILE" \
    "M32: canonical build-stage transport is not mislabeled as a fallback"
assert_grep_fixed 'mandatory branding SHA256SUMS could not be fetched' "$M32_FILE" "M32: missing manifest aborts"
assert_grep_fixed 'required_asset_count=0' "$M32_FILE" \
    "M32: required asset count starts from explicit enumeration"
assert_grep_fixed 'fetched $fetch_count of $required_asset_count required assets' "$M32_FILE" \
    "M32: incomplete payload reports derived expected count"
assert_not_grep_extended 'fetch_count.*-eq 44|verify_ok.*-ne 44|of 44 required assets' "$M32_FILE" \
    "M32: asset completeness gate has no stale magic count"
assert_grep_fixed 'branding manifest gate failed' "$M32_FILE" "M32: hash/missing-file gate is fatal"
assert_grep_fixed 'mktemp -d /var/tmp/noid-branding-fetch.XXXXXX' "$M32_FILE" \
    "M32: branding fetch uses a collision-safe disk-backed private directory"
assert_not_grep 'mktemp -d /tmp/noid-branding-fetch.' "$M32_FILE" \
    "M32: multi-file branding payload never consumes RAM-backed /tmp"
assert_grep_fixed \
    "curl -fsSL --proto '=http' --proto-redir '=http' --max-redirs 0" \
    "$M32_FILE" \
    "M32: every local staging request rejects redirects outside its fixed endpoint"
assert_grep_fixed 'BRANDING_MANIFEST_MAX_BYTES=65536' "$M32_FILE" \
    "M32: branding manifest transport has a conservative size ceiling"
assert_grep_fixed 'BRANDING_ASSET_MAX_BYTES=8388608' "$M32_FILE" \
    "M32: every branding asset transport has a conservative size ceiling"
assert_grep_fixed '--max-filesize "$BRANDING_MANIFEST_MAX_BYTES"' "$M32_FILE" \
    "M32: manifest request applies its size ceiling"
assert_grep_fixed '--max-filesize "$BRANDING_ASSET_MAX_BYTES"' "$M32_FILE" \
    "M32: asset requests apply their size ceiling"
assert_grep_fixed '--connect-timeout 5 --max-time 30' "$M32_FILE" \
    "M32: every local staging request has connection and wall-clock bounds"
assert_grep_fixed '[[ "$manifest_line" =~ ^([0-9a-f]{64})\ \ ([A-Za-z0-9._/-]+)$ ]]' \
    "$M32_FILE" "M32: manifest accepts only canonical lowercase SHA-256 rows"
assert_grep_fixed 'LC_ALL=C sort -u "$BRANDING_EXPECTED" >"$expected_sorted"' \
    "$M32_FILE" "M32: expected asset set is normalized independently"
assert_grep_fixed 'LC_ALL=C sort -u "$manifest_paths" >"$manifest_sorted"' \
    "$M32_FILE" "M32: manifest asset set is normalized independently"
assert_grep_fixed 'cmp -s "$expected_sorted" "$manifest_sorted"' \
    "$M32_FILE" "M32: manifest and fetch path sets must match exactly"
assert_grep_fixed 'sha256sum --check --strict --status SHA256SUMS' \
    "$M32_FILE" "M32: GNU strict checksum verification is the final gate"
assert_not_grep 'while read -r expected_sha rel_path' "$M32_FILE" \
    "M32: duplicate-count-only manifest verifier is retired"
payload_last_use=$(grep -nF 'src="$BRANDING_PAYLOAD/icons/noid-privacy-logo-${size}.png"' \
    "$M32_FILE" | tail -1 | cut -d: -f1 || true)
payload_cleanup=$(grep -nF '    cleanup_branding_fetch' "$M32_FILE" \
    | tail -1 | cut -d: -f1 || true)
if [ -n "$payload_last_use" ] && [ -n "$payload_cleanup" ] \
    && [ "$payload_cleanup" -gt "$payload_last_use" ]; then
    _pass "M32: private branding payload survives through its final STEP 8 consumer"
else
    _fail "M32: branding payload cleanup precedes its final consumer"
fi
assert_grep_fixed '[ "$LOGO_VARIANT_COUNT" -eq 8 ]' "$M32_FILE" \
    "M32: all eight verified logo-size sources are release-mandatory"
assert_grep_fixed '/usr/share/icons/hicolor'       "$M32_FILE" "M32: icon install path"
assert_grep_fixed 'wizard/welcome remain compatibility aliases' "$M32_FILE" \
    "M32: unused legacy icon names have an explicit compatibility owner"
assert_grep_fixed '/usr/share/backgrounds/noid-privacy' "$M32_FILE" "M32: wallpaper install path"
assert_grep_fixed '/usr/share/plymouth/themes/spinner' "$M32_FILE" "M32: Plymouth bgrt-spinner theme path"

# --- M32 dconf wallpaper override -------------------------------------------
assert_grep_fixed '/etc/dconf/db/distro.d/40-noid-wallpaper' "$M32_FILE" "M32: dconf wallpaper drop-in path"
assert_not_grep 'publish_root_file /etc/dconf/db/local.d/40-noid-wallpaper' \
    "$M32_FILE" "M32: inactive local dconf database receives no duplicate"
assert_grep_fixed 'rm -f -- /etc/dconf/db/local.d/40-noid-wallpaper' \
    "$M32_FILE" "M32: historical inactive local dconf duplicate is retired"
assert_grep_fixed 'STEP 5: dconf database compilation failed' "$M32_FILE" \
    "M32: dconf compilation failure participates in release gate"
assert_grep_fixed 'STEP 5: compiled distro database missing or empty' "$M32_FILE" \
    "M32: compiled active database is a release postcondition"
assert_grep_fixed 'DCONF_PROFILE=user dconf read -d' "$M32_FILE" \
    "M32: active profile defaults are read back after compilation"
assert_not_grep 'dconf update deferred to firstboot' "$M32_FILE" \
    "M32: no nonexistent first-boot dconf compiler fallback is claimed"
login_cleanup_line=$(grep -nF \
    'rm -f -- /etc/dconf/db/distro.d/42-noid-login-logo' \
    "$M32_FILE" | head -1 | cut -d: -f1 || true)
dconf_compile_line=$(grep -nF 'elif ! dconf update; then' \
    "$M32_FILE" | head -1 | cut -d: -f1 || true)
if [ -n "$login_cleanup_line" ] && [ -n "$dconf_compile_line" ] \
   && [ "$login_cleanup_line" -lt "$dconf_compile_line" ]; then
    _pass "M32: stale login-logo keyfile is retired before dconf compilation"
else
    _fail "M32: stale login-logo removal can leave a compiled default behind"
fi
assert_grep_fixed 'STEP 5b: login-screen-logo keyfile and compiled default absent' \
    "$M32_FILE" "M32: removed login logo is verified at both dconf layers"
assert_grep_fixed 'STEP 5: glib schema compilation failed' "$M32_FILE" \
    "M32: gschema compilation failure participates in release gate"
assert_grep_fixed 'STEP 5: glib-compile-schemas unavailable' "$M32_FILE" \
    "M32: missing compiler participates in release gate"
assert_not_grep 'glib-compile-schemas /usr/share/glib-2.0/schemas/ 2>&1.*[|][|][[:space:]]*true' "$M32_FILE" \
    "M32: gschema compiler failure is not swallowed"
assert_grep_fixed 'GSETTINGS_BACKEND=memory gsettings get' "$M32_FILE" \
    "M32: gschema defaults are verified without a session database"

# --- M32 light + dark wallpaper variants (drool-l / drool-d pattern) --------
# M32 handles both light and dark wallpaper variants
# (GNOME drool-l + drool-d, gnome-backgrounds package, CC-BY-SA-3.0).
# Regression would lose dark-mode support.
assert_grep_fixed 'wallpaper-dark.png'                        "$M32_FILE" "M32: dark wallpaper filename handled"
assert_grep_fixed '/usr/share/backgrounds/noid-privacy/default-dark.png' "$M32_FILE" "M32: dark wallpaper install path"
assert_grep_fixed 'DARK_URI='                                 "$M32_FILE" "M32: DARK_URI fallback logic present"
assert_grep_fixed "picture-uri-dark='\${DARK_URI}'"          "$M32_FILE" "M32: dconf picture-uri-dark uses DARK_URI variable"
assert_grep_fixed "picture-options='zoom'"                    "$M32_FILE" "M32: picture-options=zoom set (handles arbitrary aspect ratios)"

# --- M32 must NOT run plymouth-set-default-theme -R as active command -------
# The -R flag regenerates initrd using BUILD host kernel, not target. Must be
# deferred to firstboot. This is a known livemedia-creator gotcha.
# Check only ACTIVE command-lines (exclude #-comments + echo/log string args
# that mention the command as documentation).
if grep -vE '^\s*#' "$M32_FILE" | grep -vE 'echo\s|log\s|note\]' | grep -qE 'plymouth-set-default-theme\s+-R'; then
    _fail "M32: plymouth-set-default-theme -R runs as active command (wrong kernel for initrd)"
else
    _pass "M32: plymouth-set-default-theme -R correctly deferred (only in docs/echo)"
fi

# --- Trademark notice doc ---------------------------------------------------
TM_DOC="$PROJECT_ROOT/docs/trademark-notice.md"
assert_file_exists "$TM_DOC"
assert_grep_fixed 'registered trademark of Red Hat, Inc.' "$TM_DOC" "trademark-notice.md: Red Hat TM statement"
assert_grep_fixed 'NOT affiliated with'                   "$TM_DOC" "trademark-notice.md: non-affiliation"
assert_grep_fixed 'generic-logos'                         "$TM_DOC" "trademark-notice.md: references generic-logos"
assert_not_grep 'Own Plymouth boot theme' "$TM_DOC" \
    "trademark-notice.md: does not claim the retired custom theme"
INSTALLED_TM_DOC="$WORKDIR/installed-trademark-notice.md"
extract_heredoc "$M32_FILE" TRADEMARK_EOF "$INSTALLED_TM_DOC" \
    || _fail "M32 installed trademark documentation extraction"
assert_grep_fixed 'Substantive modification does not itself disqualify' \
    "$INSTALLED_TM_DOC" \
    "installed trademark notice accurately describes optional Remix branding"
assert_grep_fixed "These links do not by themselves replace a distributor's obligation" \
    "$INSTALLED_TM_DOC" \
    "installed trademark notice does not overclaim GPL source compliance"
assert_grep_fixed 'original NoID Privacy branding artwork is not' \
    "$INSTALLED_TM_DOC" \
    "installed trademark notice separates artwork from open-source code"
assert_not_grep 'composed entirely of free and open-source' "$INSTALLED_TM_DOC" \
    "installed trademark notice has no blanket FOSS claim"
assert_not_grep 'License texts are available in `/usr/share/licenses/<package>/` for all' \
    "$INSTALLED_TM_DOC" \
    "installed trademark notice has no universal package-path claim"
assert_not_grep 'Do NOT submit' "$INSTALLED_TM_DOC" \
    "installed trademark notice permits correctly scoped upstream reports"

# --- LICENSING.md trademark notice ------------------------------------------
LIC="$PROJECT_ROOT/LICENSING.md"
assert_grep_fixed 'TRADEMARK NOTICE' "$LIC" "LICENSING.md: has TRADEMARK NOTICE section"
assert_grep_fixed 'registered trademark of Red Hat'  "$LIC" "LICENSING.md: TM statement present"
assert_grep_fixed 'licenses/arkenfox-user.js-MIT.txt' "$LIC" \
    "LICENSING.md inventories the exact arkenfox notice"
assert_grep_fixed 'licenses/horlogeskynet-thunderbird-user.js-MIT.txt' "$LIC" \
    "LICENSING.md inventories the exact HorlogeSkynet notice"
assert_grep_fixed 'overrides/lorax/0001-drain-monitor-before-shutdown.patch' "$LIC" \
    "LICENSING.md classifies the Lorax monitor derivative"
assert_grep_fixed 'overrides/lorax/0002-precompute-live-required-space.patch' "$LIC" \
    "LICENSING.md classifies the Lorax creator derivative"
assert_grep_fixed 'overrides/lorax/0003-terminate-cancelled-process.patch' "$LIC" \
    "LICENSING.md classifies the Lorax executils derivative"
assert_grep_fixed 'overrides/lorax/0004-live-menu-default.patch' "$LIC" \
    "LICENSING.md classifies the Lorax Live-menu derivative"
assert_grep_fixed 'overrides/anaconda/live-os-initialization.py' "$LIC" \
    "LICENSING.md classifies the Anaconda Live-source derivative"
assert_grep_fixed 'overrides/noid-lan-xdp/noid-lan-xdp.bpf.c' "$LIC" \
    "LICENSING.md classifies the separately licensed BPF source"
assert_grep_fixed 'manifests/' "$LIC" \
    "LICENSING.md includes machine-readable policy manifests"
assert_grep_fixed 'and `tests/` except' "$LIC" \
    "LICENSING.md distinguishes code from the tests guide"
assert_grep_fixed 'tests/README.md' "$LIC" \
    "LICENSING.md excludes the tests guide from the code category"
assert_grep_fixed 'branding/SHA256SUMS' "$LIC" \
    "LICENSING.md classifies the branding integrity manifest as policy"
assert_grep_fixed 'branding/icons/regenerate-icons.sh' "$LIC" \
    "LICENSING.md classifies the branding generator as code"
assert_grep_fixed 'thunderbird/autoconfig.js' "$LIC" \
    "LICENSING.md includes standalone Thunderbird source"
assert_grep_fixed 'combined Firefox' "$LIC" \
    "LICENSING.md states the Firefox derivative's one file-level license"
assert_grep_fixed '4. Branding assets' "$LIC" \
    "LICENSING.md has the promised branding-license section"
assert_grep_fixed 'references the unmodified `firefox` icon' "$LIC" \
    "LICENSING.md records packaged Firefox icon lookup"
assert_grep_fixed 'does not ship a copy or modified derivative' "$LIC" \
    "LICENSING.md records the Firefox-logo ownership boundary"
assert_grep_fixed 'CC-BY-SA-3.0' "$LIC" \
    "LICENSING.md records the exact upstream wallpaper license"
assert_grep_fixed 'LICENSE TEXTS AND NOTICES' "$LIC" \
    "LICENSING.md classifies retained verbatim license texts"
assert_file_exists "$PROJECT_ROOT/licenses/arkenfox-user.js-MIT.txt"
assert_file_exists "$PROJECT_ROOT/licenses/horlogeskynet-thunderbird-user.js-MIT.txt"
assert_file_exists "$PROJECT_ROOT/licenses/GPL-2.0.txt"
assert_eq ddb9db7630752f8fdc6898f7c99a99eaeeac5213627ecb093df9c82f56175dc7 \
    "$(sha256sum "$PROJECT_ROOT/licenses/GPL-2.0.txt" | awk '{print $1}')" \
    "GPL-2.0 text matches the Fedora Lorax license payload"
assert_grep_fixed 'SPDX-License-Identifier: GPL-2.0-or-later' \
    "$PROJECT_ROOT/overrides/lorax/0001-drain-monitor-before-shutdown.patch" \
    "Lorax derivative retains its upstream file-level license"
assert_grep_fixed 'NoID Privacy modification notice' \
    "$PROJECT_ROOT/overrides/lorax/0001-drain-monitor-before-shutdown.patch" \
    "Lorax derivative carries a prominent change notice"
assert_grep_fixed 'SPDX-License-Identifier: GPL-2.0-or-later' \
    "$PROJECT_ROOT/overrides/lorax/0002-precompute-live-required-space.patch" \
    "Lorax creator derivative retains its upstream file-level license"
assert_grep_fixed 'NoID Privacy modification notice' \
    "$PROJECT_ROOT/overrides/lorax/0002-precompute-live-required-space.patch" \
    "Lorax creator derivative carries a prominent change notice"
assert_grep_fixed 'SPDX-License-Identifier: GPL-2.0-or-later' \
    "$PROJECT_ROOT/overrides/lorax/0003-terminate-cancelled-process.patch" \
    "Lorax executils derivative retains its upstream file-level license"
assert_grep_fixed 'NoID Privacy modification notice' \
    "$PROJECT_ROOT/overrides/lorax/0003-terminate-cancelled-process.patch" \
    "Lorax executils derivative carries a prominent change notice"
assert_grep_fixed 'SPDX-License-Identifier: GPL-2.0-or-later' \
    "$PROJECT_ROOT/overrides/lorax/0004-live-menu-default.patch" \
    "Lorax Live-menu derivative retains its upstream file-level license"
assert_grep_fixed 'NoID Privacy modification notice' \
    "$PROJECT_ROOT/overrides/lorax/0004-live-menu-default.patch" \
    "Lorax Live-menu derivative carries a prominent change notice"
assert_grep_fixed 'GNU General Public License v.2' \
    "$PROJECT_ROOT/overrides/anaconda/live-os-initialization.py" \
    "Anaconda derivative retains its upstream file-level license"
assert_grep_fixed 'NoID Privacy modification notice' \
    "$PROJECT_ROOT/overrides/anaconda/live-os-initialization.py" \
    "Anaconda derivative carries a prominent change notice"
assert_grep_fixed 'SPDX-License-Identifier: GPL-2.0-only' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "BPF source states its exact file-level license"
assert_grep_fixed 'license: MIT (combined derivative; full notice retained below)' \
    "$PROJECT_ROOT/firefox/noid-firefox-hardening.js" \
    "Firefox source states its combined file-level license"
assert_grep_fixed 'copyright: Copyright (c) 2026 NoID Privacy contributors' \
    "$PROJECT_ROOT/firefox/noid-firefox-hardening.js" \
    "Firefox source states the project contribution copyright"

# --- branding/ directory assets (Phase 1 wrapper expects these) -------------
BRANDING_DIR="$PROJECT_ROOT/branding"
if [ -d "$BRANDING_DIR" ]; then
    _pass "branding/ directory exists"
else
    _fail "branding/ directory missing"
fi
for asset in noid-privacy-logo.png noid-privacy-logo-512.png wallpaper.png wallpaper-dark.png; do
    if [ -f "$BRANDING_DIR/$asset" ]; then
        _pass "branding asset present: $asset"
    else
        _fail "branding asset missing: $asset"
    fi
done
# The bgrt-theme switch deleted the custom NoID Privacy .plymouth and
# .script files. Now branding/plymouth/ only ships logo.png + logo-watermark-
# 192.png used by bgrt spinner watermark.
if [ -f "$BRANDING_DIR/plymouth/logo.png" ] && [ -f "$BRANDING_DIR/plymouth/logo-watermark-192.png" ]; then
    _pass "plymouth bgrt-watermark assets present (logo.png + logo-watermark-192.png)"
else
    _fail "plymouth bgrt-watermark assets missing"
fi

# Verify both the exact 44-path payload contract and every PNG's IHDR dimensions
# without adding an image-tool dependency to the host or compose.
if python3 - "$BRANDING_DIR" <<'PNG_CONTRACT_PYEOF'
import hashlib
import pathlib
import re
import struct
import sys

root = pathlib.Path(sys.argv[1])
expected = {
    "wallpaper.png": (2048, 2048),
    "wallpaper-dark.png": (2048, 2048),
    "noid-privacy-logo.png": (1024, 1024),
    "noid-privacy-logo-512.png": (512, 512),
    "noid-privacy-avatar-256.png": (256, 256),
    "noid-privacy-avatar-128.png": (128, 128),
    "plymouth/logo.png": (512, 512),
    "plymouth/logo-watermark-192.png": (192, 192),
}
for label in ("setup", "wizard", "update", "welcome", "install", "network", "tools"):
    for size in (48, 64, 128, 256):
        expected[f"icons/noid-privacy-{label}-{size}.png"] = (size, size)
for size in (16, 24, 32, 48, 64, 96, 128, 256):
    expected[f"icons/noid-privacy-logo-{size}.png"] = (size, size)
assert len(expected) == 44

manifest = {}
for line in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
    if not line or line.startswith("#"):
        continue
    match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._/-]+)", line)
    assert match, line
    digest, rel_path = match.groups()
    assert rel_path not in manifest, rel_path
    manifest[rel_path] = digest
assert set(manifest) == set(expected)

for rel_path, dimensions in expected.items():
    payload = (root / rel_path).read_bytes()
    assert payload[:8] == b"\x89PNG\r\n\x1a\n", rel_path
    assert payload[12:16] == b"IHDR", rel_path
    assert struct.unpack(">I", payload[8:12])[0] == 13, rel_path
    assert struct.unpack(">II", payload[16:24]) == dimensions, rel_path
    assert hashlib.sha256(payload).hexdigest() == manifest[rel_path], rel_path
PNG_CONTRACT_PYEOF
then
    _pass "branding manifest is an exact 44-path set with pinned PNG dimensions"
else
    _fail "branding manifest/path/dimension contract"
fi

# --- scripts/build-iso.sh wrapper -------------------------------------------
BUILD_SCRIPT="$PROJECT_ROOT/scripts/build-iso.sh"
assert_file_exists "$BUILD_SCRIPT"
assert_cmd_success "bash -n $BUILD_SCRIPT" bash -n "$BUILD_SCRIPT"
assert_grep_fixed '--with-assets' "$BUILD_SCRIPT" "build-iso.sh: deprecated --with-assets alias documented"
assert_not_grep 'mock -r'         "$BUILD_SCRIPT" "build-iso.sh: obsolete mock chroot path absent"
assert_grep_fixed 'stage_branding_payload || exit 11' "$BUILD_SCRIPT" \
    "build-iso.sh: branding is mandatory in both build modes"
assert_grep_fixed 'stage_noid_audit || exit 11' "$BUILD_SCRIPT" \
    "build-iso.sh: audit bundle is mandatory in both build modes"
assert_grep_fixed 'BRANDING_HTTP_URL=\"http://127.0.0.1:${HTTP_PORT}/branding\"' "$BUILD_SCRIPT" \
    "build-iso.sh: no-virt branding URL is rewritten to loopback"
assert_grep_fixed 'NOID_AUDIT_URL=\"http://127.0.0.1:${HTTP_PORT}/branding/noid-privacy-linux.sh\"' "$BUILD_SCRIPT" \
    "build-iso.sh: no-virt audit URL is rewritten to loopback"
assert_grep_fixed 'CODIUM_LOCAL_BASE=\"http://127.0.0.1:${HTTP_PORT}/branding/codium\"' "$BUILD_SCRIPT" \
    "build-iso.sh: no-virt codium mirror is rewritten to loopback"
assert_grep_fixed 'ksflatten'     "$BUILD_SCRIPT" "build-iso.sh: kickstart flattening"
assert_grep_fixed 'SOURCE_DATE_EPOCH' "$BUILD_SCRIPT" "build-iso.sh: reproducibility epoch"
assert_grep_fixed '@@NOID_BUILD_EPOCH@@' "$M32_FILE" \
    "build-info timestamp is an explicit canonical-builder placeholder"
assert_grep_fixed '@@NOID_SOURCE_COMMIT@@' "$M32_FILE" \
    "build-info source commit is an explicit canonical-builder placeholder"
assert_grep_fixed '@@NOID_BASE_ISO_SHA256@@' "$M32_FILE" \
    "build-info records the verified Fedora base digest"
assert_grep_fixed 'date -u -d "@${NOID_BUILD_EPOCH}" +%F' "$M32_FILE" \
    "M32 interprets the injected integer as a Unix epoch"
assert_grep_fixed 'NOID_BUILD_TIMESTAMP_VALUE' "$M32_FILE" \
    "M32 verifies the nonempty canonical timestamp value"
assert_grep_fixed 's/@@NOID_BUILD_EPOCH@@/${SOURCE_DATE_EPOCH}/g' "$BUILD_SCRIPT" \
    "canonical builder injects the selected epoch into build-info"
assert_grep_fixed 'canonical build requires a clean source tree' "$BUILD_SCRIPT" \
    "canonical builder rejects provenance-ambiguous dirty inputs"
assert_grep_fixed 's/@@NOID_SOURCE_COMMIT@@/${NOID_SOURCE_COMMIT}/g' "$BUILD_SCRIPT" \
    "canonical builder injects the full source commit"
assert_grep_fixed 's/@@NOID_BASE_ISO_SHA256@@/${NOID_BASE_ISO_SHA256}/g' "$BUILD_SCRIPT" \
    "canonical builder injects the verified base-ISO digest"
assert_grep_fixed 'SOURCE_DATE_EPOCH must be an unsigned integer' "$BUILD_SCRIPT" \
    "canonical builder validates the epoch before injection"
assert_not_grep '--local-user ' "$BUILD_SCRIPT" \
    "build-iso.sh never signs an ISO checksum before VM qualification"
assert_grep_fixed 'NOID_REQUIRE_SIGNATURE' "$BUILD_SCRIPT" \
    "build-iso.sh rejects the obsolete build-and-sign transition explicitly"
assert_grep_fixed 'build-iso.sh only produces unsigned candidates' "$BUILD_SCRIPT" \
    "build-iso.sh cannot rebuild a signed replacement after VM sign-off"
assert_grep_fixed 'Candidate checksum intentionally unsigned' "$BUILD_SCRIPT" \
    "build-iso.sh: ordinary candidate build remains unsigned before VM sign-off"
assert_grep_fixed 'NOID_ANACONDA_PATCH_TMPDIR:-/var/tmp' \
    "$PROJECT_ROOT/scripts/anaconda-patch/build-updates-img.sh" \
    "Anaconda updates-image work defaults away from hardened /tmp tmpfs"
assert_grep_fixed 'Anaconda updates workdir is memory-backed' \
    "$PROJECT_ROOT/scripts/anaconda-patch/build-updates-img.sh" \
    "standalone updates.img builder rejects an overridden tmpfs workdir"
assert_grep_fixed 'NOID_ISO_TMPDIR:=/var/tmp' "$BUILD_SCRIPT" \
    "build-iso.sh: every host-side build stage defaults to disk-backed /var/tmp"
assert_grep_fixed 'BUILD_STAGE_DIR="$(mktemp -d -p "$ISO_BUILD_TMP_ROOT" noid-iso-stage.XXXXXX)"' \
    "$BUILD_SCRIPT" "build-iso.sh: one collision-safe private staging tree"
assert_grep_fixed 'tmpfs|ramfs)' "$BUILD_SCRIPT" \
    "build-iso.sh: memory-backed staging is rejected fail-closed"
assert_grep_fixed '--tmp "$ISO_BUILD_TMP_ROOT"' "$BUILD_SCRIPT" \
    "build-iso.sh: Lorax uses the same validated disk-backed parent"
assert_not_grep '/tmp/branding' "$BUILD_SCRIPT" \
    "build-iso.sh: no global fixed /tmp payload tree remains"
assert_not_grep_extended \
    '(^|[;&|[:space:]])(sudo([[:space:]]+-n)?[[:space:]]+)?rm[[:space:]]+-rf[^#]*"\$RESULT_DIR"' \
    "$BUILD_SCRIPT" \
    "build-iso.sh: retry cannot delete a prior Lorax result"
assert_grep_fixed 'sudo -n rm -rf -- "$TRANSACTION_ROOT"' "$BUILD_SCRIPT" \
    "build-iso.sh: failure cleanup is confined to its private transaction"
assert_grep_fixed 'sudo -n chown -R -- "$(id -u):$(id -g)" "$RESULT_DIR"' "$BUILD_SCRIPT" \
    "build-iso.sh: successful artifacts return to the signing user"
# These are exact literal source contracts, not expressions for this shell.
# shellcheck disable=SC2016
for privileged_build_command in \
    'sudo -n dnf clean expire-cache' \
    'sudo -n dnf makecache --refresh --setopt=fastestmirror=1' \
    'sudo -n dnf download --arch=x86_64' \
    'sudo -n chmod 0644 "$rpm_path"' \
    'sudo -n chown root:root "$rpm_path"' \
    'sudo -n /usr/bin/sh -c '\''umask 022; exec "$@"'\'' noid-lmc' \
    'sudo -n chown -- "$(id -u):$(id -g)" "${compose_logs[@]}"'; do
    assert_grep_fixed "$privileged_build_command" "$BUILD_SCRIPT" \
        "build-iso.sh: privileged build step remains noninteractive"
done
assert_not_grep 'VALIDSIG' "$BUILD_SCRIPT" \
    "build-iso.sh: candidate qualification cannot include premature signing"
ARCHIVE_SCRIPT="$PROJECT_ROOT/scripts/archive-build.sh"
assert_grep_fixed 'verify_release_signature "$PUBLIC_SIGNATURE"' "$ARCHIVE_SCRIPT" \
    "archive-build.sh authenticates the candidate checksum before copying"
assert_grep_fixed 'verify_release_signature "$SIGNOFF_SIGNATURE"' "$ARCHIVE_SCRIPT" \
    "archive-build.sh authenticates the VM approval before copying"
assert_not_grep 'first available GPG secret key' "$BUILD_SCRIPT" \
    "build-iso.sh: no first-key signing ambiguity"
assert_not_grep 'first available GPG secret key' "$ARCHIVE_SCRIPT" \
    "archive-build.sh: no first-key signing ambiguity"

test_finish
