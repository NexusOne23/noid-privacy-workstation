# ============================================================================
# Module 16 — Firefox Hardening (NoID Privacy-owned user.js + uBlock Origin)
# Canonical source-of-truth files:
#   - firefox/noid-firefox-hardening.js (user.js, derived from arkenfox v144.0 MIT)
# Status: LOCKED 2026-09-17 (v3.103) — advance the reviewed uBlock Origin seed to 1.75.0; document the FPP language excludes exactly.
#
# Covers:
#   - NoID Privacy Firefox Hardening (consolidated user.js — derived from
#     arkenfox v144.0, MIT) — gzip+base64-embedded, no GitHub fetch;
#     regenerate the blob via scripts/regen-firefox-embed.sh after ANY edit
#     to firefox/noid-firefox-hardening.js (CI gates on --check)
#   - Mozilla AutoConfig (autoconfig.js + mozilla.cfg, sandbox_enabled=true)
#     generated from user.js (user_pref -> defaultPref) + lockPref appends
#     (current profile-manager kill-switch, regional top-sites + search-
#     shortcut blockers) + reviewed user-owned application defaults, pinned
#     tiles and initial toolbar placement (all user-customizable)
#   - noid-locale.js system-pref (intl.locale.requested="" OS-locale
#     flow-through) + langpack activation via distribution/extensions/
#   - uBlock Origin pinned XPI (immutable GitHub release URL + SHA256 +
#     size + ZIP-magic check; offline-cache aware) staged to the
#     System-scope path; its exact curated filter-list baseline is enforced
#     through the current narrow managed-storage schema
#   - firefox-profiles.sh shared helper (registered-profile discovery,
#     apply_userjs, uBO profile-local install + PB permission)
#   - policies.json with EXACTLY ONE policy (SearchEngines.Default=
#     DuckDuckGo — the only working mechanism on Rapid Release)
#   - M26 fedora-bookmarks exclusion + empty default-bookmarks fallback (keeps
#     the Fedora first-run bookmark source empty without replacing distribution.ini)
#     + /etc/skel profile pre-bake, including uBO private-window permission
#     (1st-launch race fix) + mirror to pre-existing users (liveuser)
#   - first-run setup script + XDG autostart (silent-launch profile
#     detection, registration reconciliation, user.js + uBO + empty-
#     bookmarks-backup install) — full flow in SETUPSCRIPT_EOF
#   - noid-firefox-relax-fpp + noid-firefox-relax-webrtc +
#     noid-firefox-drm + noid-firefox-harden-profile CLIs and the
#     16-firefox-hardening.md user doc
#   - NoID Privacy-owned /usr/local launcher + XDG desktop overlay generated
#     from the exact signed Fedora payload; no Firefox-RPM file is rewritten
#   - Anaconda WebUI firefox-theme user.js hardening append (Normandy/
#     Nimbus/Push/Safe-Browsing/region/telemetry off during install)
#
# Deliberate deviations (do NOT re-litigate):
#   - uBO delivery is PROFILE-LOCAL (verified FF150 mechanism):
#     distribution-bundled scan does NOT auto-install regular extensions
#     (verified across all launch modes; locale addons DO
#     distribution-install — different code path). policies.json
#     ExtensionSettings was rejected ("managed by your organization" UI).
#   - omni.ja and distribution.ini are NEVER patched. The reviewed Fedora 44
#     distribution.ini declares no bookmarks; M16 does not synthesize a dead
#     distributor "processed" preference.
#   - defaultPref (not lockPref) for reviewed application/UI state, pinned
#     tiles and initial toolbar state: user_pref would wipe later user changes
#     every start, lockPref would block customization.
#   - AutoConfig uses defaultPref semantics (user override survives);
#     only the profile-manager + top-sites injectors are lockPref.
#   - installs.ini is NOT pre-baked (Firefox computes the install-hash
#     from the executable path; a hand-rolled hash forks a new profile).
#
# Constraint notes (keep when editing):
#   - mozilla.cfg line 1 MUST be a comment (parser skips L1); the
#     user_pref->defaultPref count parity is verify-gated.
#   - extensions.autoDisableScopes=10 is load-bearing (profile-scope XPIs
#     bit 1 + app-global langpacks bit 4 auto-enable).
#   - The skel profile dir ships 700 (cookies/keys after first run);
#     parent dirs 755.
#   - Verify-blocks use the canonical grep -c pattern; tests/16 has
#     whole-file negative asserts (AMO latest.xpi URL, active arkenfox
#     fetch, OMNI_JA=, active X-GNOME-Autostart-Phase line).
#
# Cross-references:
#   - Module 05: Firefox follows the system/VPN resolver by default; direct
#                WAN retains Module 05's strict-default Quad9 DoT boundary
#   - Module 07: the system boundary blocks unqualified physical-WAN IPv6;
#                Firefox must retain provider tunnel IPv6/NAT64 compatibility
#   - Module 13: AIDE /usr PERMS rule covers new paths, no aide.conf change needed
#   - Module 25: noid-update-all.sh rebuilds each supported user.js from the
#                canonical base plus reviewed consent overlay when present
#   - M33/M34: isolated + playground profiles source firefox-profiles.sh
#
# Testing: after image build, boot + create user + first GNOME login →
#   wait 10s → Firefox setup fires → browserleaks.com verification
# ============================================================================

%post --erroronfail --log=/var/log/ks-16-firefox.log

#==============================================================================
# Module 16 — Firefox Hardening
#==============================================================================

set -euo pipefail

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [Module 16] $*"
}

log "=== Start Module 16: Firefox Hardening ==="

#------------------------------------------------------------------------------
# Variables
#------------------------------------------------------------------------------
# Supply-chain pinning (Rule 11): every external download uses an immutable
# URL (commit SHA, release tag) + SHA256 verify. A git-tag move or AMO mirror
# compromise cannot silently swap the payload. Update expected SHAs when
# bumping versions; see docs/pin-inventory.md for the refresh workflow.

# Firefox hardening v1.0 — absorbed from arkenfox v144.
# See firefox/noid-firefox-hardening.js in repo + NoID Privacy-specific overrides.
# Shipped as base64+gzip-embedded in Step 3 below (no external fetch).
# Upstream attribution kept in file header (MIT, arkenfox @Thorin-Oakenpants).
NOID_FIREFOX_HARDENING_VERSION="1.0.0-arkenfox144"

# uBlock Origin — pin the image's first-install seed to one reviewed GitHub
# release. Later executable-extension updates are owned exclusively by the
# user-started M25 Update All workflow; Firefox background checks stay off.
UBO_VERSION="1.75.0"
UBO_URL="https://github.com/gorhill/uBlock/releases/download/${UBO_VERSION}/uBlock0_${UBO_VERSION}.firefox.signed.xpi"
UBO_SHA256="5b74415860456370644bd80f16125e865b0e6c356bb5dfcfb84069967eaa5287"
UBO_SIZE_EXPECTED=4650100

SHARE_DIR="/usr/share/noid-firefox"
UBO_POLICY_SOURCE="$SHARE_DIR/uBlock0@raymondhill.net.json"
EXTENSIONS_DIR="/usr/lib64/mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}"
MANAGED_STORAGE_DIR="/usr/lib64/mozilla/managed-storage"
XDG_AUTOSTART_DIR="/etc/xdg/autostart"
LOCAL_BIN_DIR="/usr/local/bin"
UBO_POLICY_VALIDATOR="/usr/local/lib/noid-privacy/validate-ubo-policy.py"
STAMP_DIR=/var/lib/noid-privacy
STAMP="$STAMP_DIR/stamp-16-firefox.ok"

EXPECTED_FILTER_LIST_COUNT=13

# Supply-chain verify helper: fail the build loud if hash mismatches.
verify_sha256() {
    local file="$1" expected="$2" label="$3"
    local actual
    actual=$(sha256sum "$file" | awk '{print $1}')
    if [ "$actual" != "$expected" ]; then
        log "  FAIL: SHA256 mismatch on $label"
        log "        expected: $expected"
        log "        actual:   $actual"
        exit 1
    fi
    log "  SHA256 verified: $label"
}

# Reduced-dependency cache support. The canonical builder exposes the reviewed
# bytes through its loopback-only payload server and sets NOID_CACHE_BASE_URL
# in the disposable flattened kickstart. SHA256 + exact-size verification
# below is authoritative. This is not an offline-build switch.
#
# arkenfox cache layout removed (user.js is embedded now,
# no GitHub fetch). Only uBO remains as external download.
#
fetch_or_cache() {
    local cache_relative="$1" url="$2" dest="$3"
    if [ -n "${NOID_CACHE_BASE_URL:-}" ]; then
        # The canonical builder injects one fixed loopback/build-gateway HTTP
        # origin. It serves reviewed local bytes directly and must never
        # redirect the guest to another origin or protocol.
        curl -fsS --proto '=http' --max-redirs 0 \
            --connect-timeout 15 --max-time 300 \
            --max-filesize "$UBO_SIZE_EXPECTED" --retry 3 --retry-delay 2 \
            -o "$dest" "${NOID_CACHE_BASE_URL%/}/${cache_relative}"
        log "  (cache) fetched $(basename "$dest") from build-host loopback payload"
    else
        # GitHub release assets redirect to their HTTPS asset host. Keep the
        # complete redirect chain encrypted and bounded; the exact size,
        # SHA-256 and extension identity gates below remain authoritative.
        curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 \
            --max-redirs 3 --connect-timeout 15 --max-time 300 \
            --max-filesize "$UBO_SIZE_EXPECTED" --retry 3 --retry-delay 2 \
            -o "$dest" "$url"
    fi
}

NOID_CACHE_BASE_URL="${NOID_CACHE_BASE_URL:-}"
UBO_CACHE_RELATIVE="ubo/${UBO_VERSION}/uBlock0_${UBO_VERSION}.firefox.signed.xpi"

#------------------------------------------------------------------------------
# Step 1: Verify Firefox package installed
#------------------------------------------------------------------------------
log "Step 1/8: Verify Firefox package installed"
if rpm -q firefox >/dev/null 2>&1; then
    FIREFOX_VERSION=$(rpm -q --qf '%{VERSION}-%{RELEASE}' firefox)
    log "  Firefox installed: $FIREFOX_VERSION"
else
    log "  FAIL: Firefox package not installed (expected via @workstation-product-environment)"
    exit 1
fi

# Fedora's launcher is an RPM-owned input. Pin its exact compose-time bytes;
# Step 6f derives a NoID Privacy-owned /usr/local launcher from this pristine
# payload and keeps the vendor file byte-identical across updates.
FIREFOX_LAUNCHER=/usr/bin/firefox
FIREFOX_LAUNCHER_SOURCE_SHA256=12e361bb42c030a9ffa940c641ff3ddf53ea097d40a7b2ea4903cd2c954dcc2e

verify_sha256 "$FIREFOX_LAUNCHER" "$FIREFOX_LAUNCHER_SOURCE_SHA256" \
    "pristine Fedora Firefox launcher"
FIREFOX_WIDEVINE_ANCHOR_COUNT=$(grep -cF \
    '    (restorecon -vr $MOZ_CONFIG_DIR/firefox/*/gmp-widevinecdm/* &)' \
    "$FIREFOX_LAUNCHER" 2>/dev/null || true)
FIREFOX_WIDEVINE_ANCHOR_COUNT=${FIREFOX_WIDEVINE_ANCHOR_COUNT:-0}
if [ "$FIREFOX_WIDEVINE_ANCHOR_COUNT" -ne 1 ]; then
    log "  FAIL: Fedora Widevine restorecon line is not the reviewed shape"
    exit 1
fi
bash -n "$FIREFOX_LAUNCHER"
log "  Firefox RPM launcher is pristine and structurally reviewed"

# M16_HEALTH_INVALIDATION_BEGIN
# A health stamp describes one fully completed M16 publication, not merely the
# last successful historical run. Validate the shared state boundary first,
# then retire any prior success before the first Firefox payload mutation. A
# failed rerun therefore cannot leave plausible green build evidence behind.
log "Step 1b/8: Invalidate stale Firefox build-health evidence"
if { [ -e "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; } \
   && { [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; }; then
    log "  FAIL: $STAMP_DIR exists but is not a real directory"
    exit 1
fi
if [ ! -e "$STAMP_DIR" ]; then
    install -d -m 0755 -o root -g root "$STAMP_DIR"
fi
if [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
        "0:0:755" ]; then
    log "  FAIL: $STAMP_DIR metadata is not root:root 0755"
    exit 1
fi
if ! restorecon -F -- "$STAMP_DIR" \
   || ! matchpathcon -V "$STAMP_DIR" >/dev/null; then
    log "  FAIL: $STAMP_DIR SELinux context is not canonical"
    exit 1
fi
if [ -e "$STAMP" ] || [ -L "$STAMP" ]; then
    if [ ! -f "$STAMP" ] && [ ! -L "$STAMP" ]; then
        log "  FAIL: health-stamp target is not a file or symlink: $STAMP"
        exit 1
    fi
    rm -f -- "$STAMP" || {
        log "  FAIL: cannot invalidate stale Module 16 health stamp"
        exit 1
    }
    sync -- "$STAMP_DIR"
fi
log "  Prior Module 16 health stamp is absent"
# M16_HEALTH_INVALIDATION_END

#------------------------------------------------------------------------------
# Step 2: Create directories
#------------------------------------------------------------------------------
log "Step 2/8: Create directories"
mkdir -p "$SHARE_DIR"
mkdir -p "$EXTENSIONS_DIR"
mkdir -p "$MANAGED_STORAGE_DIR"
mkdir -p "$XDG_AUTOSTART_DIR"
log "  Created: $SHARE_DIR, $EXTENSIONS_DIR, $MANAGED_STORAGE_DIR"

#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# Step 3: Install NoID Privacy Firefox Hardening (consolidated user.js)
#------------------------------------------------------------------------------
# Single consolidated noid-firefox-hardening.js (arkenfox v144.0 core, MIT,
# attribution in the file header + NoID Privacy image-scope overrides + ETP-tighten),
# embedded as deterministic gzip+base64 and decoded to
# /usr/share/noid-firefox/user.js — no external fetch and no runtime merge.
# NoID Privacy owns ongoing release-note, source-default and runtime review.
# The image stays self-contained; source of truth is firefox/noid-firefox-
# hardening.js (git-tracked; regenerate the blob after edits — see header).
log "Step 3/8: Install NoID Privacy Firefox hardening v${NOID_FIREFOX_HARDENING_VERSION}"

# Decode gzip+base64 blob into consolidated user.js
base64 -d <<'HARDENING_GZ_B64_EOF' | gunzip > "$SHARE_DIR/user.js"
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
uz87luYyUjOHzuz/BSEK1SDxiwEA
HARDENING_GZ_B64_EOF
chmod 644 "$SHARE_DIR/user.js"

# Sanity: size + NoID Privacy parrot marker
USERJS_SIZE=$(stat -c%s "$SHARE_DIR/user.js")
if [ "$USERJS_SIZE" -lt 80000 ]; then
    log "  FAIL: noid-firefox-hardening.js decoded too small ($USERJS_SIZE bytes, expected >80KB)"
    exit 1
fi
if ! grep -q 'NOID-COMPLETE' "$SHARE_DIR/user.js"; then
    log "  FAIL: NoID Privacy parrot marker NOID-COMPLETE missing in decoded user.js"
    exit 1
fi
log "  Installed $SHARE_DIR/user.js ($USERJS_SIZE bytes, NoID Privacy parrot verified)"

# Reviewed inverse overlay for the explicit DRM/Widevine consent action.  The
# canonical profile keeps EME and GMP updates off; firefox-profiles.sh appends
# this exact block only when the profile-local versioned opt-in sentinel is
# present.  Keeping the overlay root-owned and separate makes Update-All
# re-application preserve consent without weakening fresh profiles.
cat > "$SHARE_DIR/user-drm-overrides.js" <<'DRM_OVERRIDES_EOF'

// NOID-DRM-OPT-IN-BEGIN
// Explicit proprietary DRM opt-in. Managed with `noid-firefox-drm`.
user_pref("media.eme.enabled", true);
user_pref("media.gmp-manager.updateEnabled", true);
user_pref("media.gmp-widevinecdm.enabled", true);
user_pref("media.gmp-widevinecdm.allow-chromium-update", true);
user_pref("_noid.drm.enabled", true);
// NOID-DRM-OPT-IN-END
DRM_OVERRIDES_EOF
chmod 0644 "$SHARE_DIR/user-drm-overrides.js"
chown root:root "$SHARE_DIR/user-drm-overrides.js"
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$SHARE_DIR/user-drm-overrides.js" 2>/dev/null || true
fi

# Retain the exact MIT notice from the embedded arkenfox-derived source in the
# image-wide license inventory. The pinned digest is from upstream tag 144.0
# (commit bb45863be796d331717e2b5d6e490f0d3e3cf93f).
LICENSE_DIR=/usr/share/licenses/noid-privacy
ARKENFOX_LICENSE="$LICENSE_DIR/arkenfox-user.js-MIT.txt"
install -d -m 0755 "$LICENSE_DIR"
awk '/^\/\* ARKENFOX MIT NOTICE BEGIN$/ { copy=1; next }
     /^ARKENFOX MIT NOTICE END \*\/$/ { copy=0; found_end=1; next }
     copy { print }
     END { if (!found_end) exit 1 }' \
    "$SHARE_DIR/user.js" > "$ARKENFOX_LICENSE"
chmod 0644 "$ARKENFOX_LICENSE"
chown root:root "$ARKENFOX_LICENSE"
printf '%s  %s\n' \
    2bf289bdd22188ccff2bf34c9a20a75c45b84f42f887da7e177d9bfd1bac3c1a \
    "$ARKENFOX_LICENSE" | sha256sum -c -
log "  Installed exact arkenfox v144 MIT notice: $ARKENFOX_LICENSE"

# No updater.sh (eliminated — image updates via M25 noid-update-all.sh
# which re-runs kickstart-equivalent re-install). No separate user-overrides.js
# (consolidated into user.js). No merge step.

#------------------------------------------------------------------------------
# Step 3b: Install Mozilla AutoConfig (mozilla.cfg) — global pref enforcement
#------------------------------------------------------------------------------
# AutoConfig (mozilla.cfg) applies the prefs globally BEFORE profile-init —
# every current AND future profile (user.js-only delivery is fragile under
# FF150 profiles.ini/installs.ini semantics). Two files: the autoconfig.js
# pointer (obscure_value=0, sandbox enabled) + mozilla.cfg generated from
# user.js via user_pref->defaultPref sed; FIRST LINE of mozilla.cfg must be
# a comment (parser skips L1). defaultPref keeps user overrides possible —
# only the targeted kill-switches below use lockPref.
log "Step 3b/8: Install Mozilla AutoConfig (global pref enforcement)"

FIREFOX_LIB_DIR=/usr/lib64/firefox
AUTOCONFIG_PREF_DIR="${FIREFOX_LIB_DIR}/defaults/pref"

if [ ! -d "$FIREFOX_LIB_DIR" ]; then
    log "  FAIL: Firefox lib directory $FIREFOX_LIB_DIR missing"
    exit 1
fi

mkdir -p "$AUTOCONFIG_PREF_DIR"

# 3b.1 — autoconfig.js pointer (registers mozilla.cfg)
cat > "${AUTOCONFIG_PREF_DIR}/autoconfig.js" <<'AUTOCONFIG_EOF'
// NoID Privacy Workstation 44 — AutoConfig pointer (Module 16)
// Tells Firefox to load /usr/lib64/firefox/mozilla.cfg at startup,
// before any profile is initialized. Applies globally to all profiles.
//
// sandbox_enabled = true: NoID Privacy's mozilla.cfg uses only pref() /
// defaultPref() / lockPref() — all prefcalls.js-API functions that work
// in sandbox-enabled mode. Sandbox-enabled reduces blast-radius if
// mozilla.cfg is ever tampered with (no Components / Services / Cu.import /
// eval reachable from sandboxed code). Mozilla's long-term direction
// (Bug 1455601, Bug 1514451) is to remove the sandbox-disable option
// from release channels — NoID Privacy anticipates this.
// Cross-ref: M35 thunderbird.ks autoconfig pointer mirror.
pref("general.config.filename", "mozilla.cfg");
pref("general.config.obscure_value", 0);
pref("general.config.sandbox_enabled", true);
AUTOCONFIG_EOF
chmod 644 "${AUTOCONFIG_PREF_DIR}/autoconfig.js"
log "  Installed ${AUTOCONFIG_PREF_DIR}/autoconfig.js"

# 3b.2 — mozilla.cfg generated from user.js
# First line must be a comment (Mozilla parser skips L1 unconditionally).
# Convert user_pref( -> defaultPref( for AutoConfig syntax. Comments and
# block comments /* ... */ are valid JS, no further conversion needed.
{
    echo "// NoID Privacy Workstation 44 — Firefox AutoConfig (Module 16)"
    echo "// Source of truth: firefox/noid-firefox-hardening.js (sed-derived)"
    echo "// Generated at build time. To regenerate: re-run kickstart M16."
    echo "//"
    sed 's/^user_pref(/defaultPref(/g' "$SHARE_DIR/user.js"
} > "${FIREFOX_LIB_DIR}/mozilla.cfg"
chmod 644 "${FIREFOX_LIB_DIR}/mozilla.cfg"

# Sanity: defaultPref count must roughly match user_pref count in source
# minimal pattern (`2>/dev/null || true; ${var:-0}`)
# replaces broken `|| echo 0` (would produce multi-line "0\n0" on zero matches,
# breaking subsequent -ne arithmetic). Never fires in practice (files always
# have content) but pattern-consistency with M03/M11/M12/M14/M17 (reference).
SRC_USER_PREF_COUNT=$(grep -c '^user_pref(' "$SHARE_DIR/user.js" 2>/dev/null || true)
SRC_USER_PREF_COUNT=${SRC_USER_PREF_COUNT:-0}
CFG_DEFAULT_PREF_COUNT=$(grep -c '^defaultPref(' "${FIREFOX_LIB_DIR}/mozilla.cfg" 2>/dev/null || true)
CFG_DEFAULT_PREF_COUNT=${CFG_DEFAULT_PREF_COUNT:-0}
if [ "$SRC_USER_PREF_COUNT" != "$CFG_DEFAULT_PREF_COUNT" ]; then
    log "  FAIL: mozilla.cfg conversion mismatch (user_pref=$SRC_USER_PREF_COUNT, defaultPref=$CFG_DEFAULT_PREF_COUNT)"
    exit 1
fi
if ! head -1 "${FIREFOX_LIB_DIR}/mozilla.cfg" | grep -q '^//'; then
    log "  FAIL: mozilla.cfg first line is not a comment (Mozilla parser will swallow first pref)"
    exit 1
fi
log "  Installed ${FIREFOX_LIB_DIR}/mozilla.cfg ($CFG_DEFAULT_PREF_COUNT defaultPref entries)"

# 3b.3 — Append user-overridable application defaults + narrow lockPref entries.
# Firefox Secure DNS is off by image default so the OS resolver can honor the
# active VPN/private-link DNS scope. Keep this out of profile user.js: a user
# who deliberately enables Firefox Secure DNS must survive every restart and
# the M25 Update All profile reconciliation. The URI/provider remains entirely
# user-selected instead of retaining a stale bootstrap address.
#
# The same ownership rule applies to user-facing browser state whose documented
# contract promises a later Settings/about:config choice: startup/home,
# current-session closed-tab recovery, Home content, AI controls, Firefox IP
# Protection, Sync selection, GPC, private search, ETP convenience compatibility
# and hardware/accessibility preferences. They remain secure image defaults but
# never live in profile user.js.
#
# The toolbar state is application data, not a hardening control. Seed it only
# as a default so uBlock Origin is visible on the first launch while Firefox's
# prefs.js user value remains authoritative after any toolbar customization.
# Schema 24 matches the reviewed Fedora 44 Firefox CustomizableUI kVersion and
# includes its standard reset-pbm button migration.
USER_OWNED_DEFAULT_PREFS=(
    # Startup, search and compatibility/performance choices.
    'defaultPref("browser.startup.page", 1);'
    'defaultPref("browser.startup.homepage", "about:home");'
    'defaultPref("browser.newtabpage.enabled", true);'
    'defaultPref("browser.sessionstore.persist_closed_tabs_between_sessions", false);'
    'defaultPref("browser.search.separatePrivateDefault", true);'
    'defaultPref("browser.search.separatePrivateDefault.ui.enabled", true);'
    'defaultPref("general.smoothScroll", true);'
    'defaultPref("privacy.trackingprotection.allow_list.convenience.enabled", false);'
    'defaultPref("privacy.globalprivacycontrol.enabled", false);'

    # Account data stays local by default, but Firefox owns later Sync choices.
    'defaultPref("services.sync.engine.passwords", false);'
    'defaultPref("services.sync.engine.tabs", false);'

    # Optional Mozilla VPN/IP Protection starts inert without becoming a lock.
    'defaultPref("browser.ipProtection.enabled", false);'
    'defaultPref("browser.ipProtection.locationListCache", "");'
    'defaultPref("browser.ipProtection.userEnabled", false);'
    'defaultPref("browser.ipProtection.autoStartEnabled", false);'
    'defaultPref("browser.ipProtection.autoStartPrivateEnabled", false);'

    # Firefox AI Controls: block by default, preserve an explicit later choice.
    'defaultPref("extensions.ml.enabled", false);'
    'defaultPref("browser.ml.chat.enabled", false);'
    'defaultPref("browser.ml.chat.shortcuts", false);'
    'defaultPref("browser.ml.chat.sidebar", false);'
    'defaultPref("browser.tabs.groups.smart.enabled", false);'
    'defaultPref("browser.tabs.groups.smart.userEnabled", false);'
    'defaultPref("browser.ai.control.default", "blocked");'
    'defaultPref("browser.ai.control.sidebarChatbot", "blocked");'
    'defaultPref("browser.ai.control.linkPreviewKeyPoints", "blocked");'
    'defaultPref("browser.ai.control.smartTabGroups", "blocked");'
    'defaultPref("browser.ai.control.translations", "blocked");'
    'defaultPref("browser.ai.control.pdfjsAltText", "blocked");'
    'defaultPref("browser.ai.control.smartWindow", "blocked");'
    'defaultPref("sidebar.main.tools", "syncedtabs,history,bookmarks");'
    'defaultPref("sidebar.notification.badge.aichat", false);'

    # Firefox Home: local, quiet defaults. Visible controls and advanced
    # about:config feature gates remain owned by prefs.js after a user change.
    'defaultPref("browser.newtabpage.activity-stream.showSponsored", false);'
    'defaultPref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);'
    'defaultPref("browser.newtabpage.activity-stream.showSponsoredCheckboxes", false);'
    'defaultPref("browser.newtabpage.activity-stream.feeds.section.topstories", false);'
    'defaultPref("browser.newtabpage.activity-stream.feeds.topsites", true);'
    'defaultPref("browser.newtabpage.activity-stream.feeds.section.highlights", false);'
    'defaultPref("browser.newtabpage.activity-stream.feeds.weatherfeed", false);'
    'defaultPref("browser.newtabpage.activity-stream.showWeather", false);'
    'defaultPref("browser.newtabpage.activity-stream.system.showWeather", false);'
    'defaultPref("browser.newtabpage.activity-stream.widgets.weather.enabled", false);'
    'defaultPref("browser.newtabpage.activity-stream.widgets.weatherForecast.enabled", false);'
    'defaultPref("browser.newtabpage.activity-stream.widgets.system.weather.enabled", false);'
    'defaultPref("browser.newtabpage.activity-stream.widgets.system.weatherForecast.enabled", false);'
    'defaultPref("browser.newtabpage.activity-stream.weather.locationSearchEnabled", false);'
    'defaultPref("browser.newtabpage.activity-stream.nova.enabled", false);'
    'defaultPref("browser.urlbar.weather.featureGate", false);'
    'defaultPref("browser.urlbar.suggest.weather", false);'
    # Keep the DoH chooser usable without reviving Firefox's country lookup.
    # `global` selects only Mozilla's provider-neutral fallback catalogue; it
    # neither enables DoH nor selects a provider while network.trr.mode=5.
    'defaultPref("doh-rollout.home-region", "global");'
    'defaultPref("browser.region.network.url", "");'
    'defaultPref("browser.region.network.scan", false);'
    'defaultPref("browser.region.update.enabled", false);'
    'defaultPref("browser.newtabpage.activity-stream.newtabWallpapers.enabled", false);'
    'defaultPref("browser.newtabpage.activity-stream.newtabWallpapers.user.enabled", false);'
)
TOOLBAR_DEFAULT_PREF='defaultPref("browser.uiCustomization.state", "{\"placements\":{\"widget-overflow-fixed-list\":[],\"unified-extensions-area\":[],\"nav-bar\":[\"back-button\",\"forward-button\",\"stop-reload-button\",\"customizableui-special-spring1\",\"vertical-spacer\",\"urlbar-container\",\"customizableui-special-spring2\",\"downloads-button\",\"fxa-toolbar-menu-button\",\"unified-extensions-button\",\"ublock0_raymondhill_net-browser-action\",\"reset-pbm-toolbar-button\"],\"toolbar-menubar\":[\"menubar-items\"],\"TabsToolbar\":[\"firefox-view-button\",\"tabbrowser-tabs\",\"new-tab-button\",\"alltabs-button\"],\"vertical-tabs\":[],\"PersonalToolbar\":[\"personal-bookmarks\"]},\"seen\":[\"developer-button\",\"screenshot-button\",\"ublock0_raymondhill_net-browser-action\",\"reset-pbm-toolbar-button\"],\"dirtyAreaCache\":[\"nav-bar\",\"vertical-tabs\",\"toolbar-menubar\",\"TabsToolbar\",\"PersonalToolbar\",\"unified-extensions-area\"],\"currentVersion\":24,\"newElementCount\":2}");'
{
    echo ""
    echo "// NoID Privacy — provider-neutral, user-overridable DNS default"
    echo "// Firefox Secure DNS is off; NetworkManager/systemd-resolved owns"
    echo "// VPN/private split DNS and the direct-WAN Quad9 resolver path."
    echo 'defaultPref("network.trr.mode", 5);'
    echo ""
    echo "// NoID Privacy — secure user-facing defaults (all user-overridable)"
    printf '%s\n' "${USER_OWNED_DEFAULT_PREFS[@]}"
    echo ""
    echo "// NoID Privacy — initial uBO toolbar placement (user-overridable)"
    echo "// A prefs.js user value overrides this default after customization."
    printf '%s\n' "$TOOLBAR_DEFAULT_PREF"
} >> "${FIREFOX_LIB_DIR}/mozilla.cfg"

for expected_user_default in "${USER_OWNED_DEFAULT_PREFS[@]}"; do
    expected_user_default_count=$(grep -Fxc -- "$expected_user_default" \
        "${FIREFOX_LIB_DIR}/mozilla.cfg" 2>/dev/null || true)
    expected_user_default_count=${expected_user_default_count:-0}
    if [ "$expected_user_default_count" -ne 1 ]; then
        log "  FAIL: mozilla.cfg requires exactly one user-owned default: $expected_user_default"
        exit 1
    fi
done
log "  Appended ${#USER_OWNED_DEFAULT_PREFS[@]} secure user-overridable application defaults"

# Append lockPref() entries for FF150 new-profile-manager kill-switch.
# FF150 fix: the default browser.profiles.enabled=true
# triggers an empty Profile Picker dialog when users click `firefox -P
# default-release` launcher (the new toolbar-based profile manager is a
# parallel system that ignores legacy profiles.ini and shows empty list).
#
# user.js sets this to false per-profile, but new user-created profiles
# inherit Firefox defaults until first launch. lockPref enforces system-
# wide BEFORE any profile init, covering edge case: user creates profile
# via about:profiles or manual `firefox -P newprofile`. Cannot be unset
# via UI or about:config (lockPref is hard-locked).
{
    echo ""
    echo "// ============================================================"
    echo "// NoID Privacy — FF150 new profile manager kill-switch"
    echo "// lockPref overrides any user attempt to re-enable via UI."
    echo "// Why locked (not just default): without this, FF150 picker"
    echo "// dialog appears even with profiles.ini Default=1 set."
    echo "// ============================================================"
    echo 'lockPref("browser.profiles.enabled", false);'
    echo 'lockPref("browser.profiles.created", false);'
    echo ""
    echo "// ============================================================"
    echo "// NoID Privacy — Mozilla regional default top sites kill-switch"
    echo "// ============================================================"
    echo "// Mozilla's ActivityStream.sys.mjs has a getValue() function in"
    echo "// PREFS_CONFIG that dynamically generates locale-specific default"
    echo "// top-site URLs (Wikipedia, YouTube, Reddit, Amazon per locale)"
    echo "// at runtime, OVERRIDING any user_pref(default.sites, \"\") set in"
    echo "// user.js. The only Mozilla-supported way to defeat this dynamic"
    echo "// override on Rapid Release Firefox is lockPref() in AutoConfig —"
    echo "// it forces the value regardless of getValue(). tested on"
    echo "// ISO VM validation: with this lockPref, Wikipedia/YouTube/"
    echo "// Amazon/Reddit no longer appear in the new-tab Top Sites grid."
    echo 'lockPref("browser.newtabpage.activity-stream.default.sites", "");'
    echo ""
    echo "// ============================================================"
    echo "// NoID Privacy — block Mozilla search-engine shortcut auto-pin"
    echo "// ============================================================"
    echo "// SEPARATE Mozilla mechanism from regional default.sites (above):"
    echo "// TopSitesFeed.sys.mjs::_maybeInsertSearchShortcuts() reads"
    echo "// browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts"
    echo "// (default=true) and pins CUSTOM_SEARCH_SHORTCUTS = [@google,"
    echo "// @amazon, @baidu, @ecosia] into free Top-Sites slots automatically."
    echo "// default.sites=\"\" lockPref above does NOT block this — different"
    echo "// code path. Discovered during deployment validation (Google appeared"
    echo "// in fresh VM despite default.sites lockPref). Source verified via"
    echo "// firefox/components/newtab/lib/TopSitesFeed.sys.mjs."
    echo "//"
    echo "// Fix: lockPref both the master toggle + havePinned cache string."
    echo 'lockPref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts", false);'
    echo 'lockPref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts.havePinned", "");'
    echo ""
    echo "// ============================================================"
    echo "// NoID Privacy — initial pinned tiles + grid layout (defaultPref)"
    echo "// ============================================================"
    echo "// 8 NoID Privacy-curated tiles pre-pin the new-tab Top Sites grid out-of-"
    echo "// the-box: NoID Privacy / DuckDuckGo / Duck.ai / Proton Mail /"
    echo "// Signal / Mullvad VPN / Tor Project / Privacy Guides discuss."
    echo "//"
    echo "// CRITICAL: defaultPref (NOT user_pref in user.js, NOT lockPref)."
    echo "// user_pref re-applies every Firefox start and would WIPE user-"
    echo "// added shortcuts (live-confirmed: user-added Google"
    echo "// tile vanished after restart with user_pref). lockPref would"
    echo "// fully prevent customization. defaultPref sets the initial value"
    echo "// only when prefs.js has no user-set value yet — so user-added/"
    echo "// removed tiles in subsequent sessions are persisted in prefs.js"
    echo "// and override the default."
    echo "//"
    echo "// topSitesRows=4 matches host-Firefox UX (4-row grid = 24-32 slots"
    echo "// depending on window width; user can shrink via Settings > Home)."
    echo 'defaultPref("browser.newtabpage.activity-stream.topSitesRows", 4);'
} >> "${FIREFOX_LIB_DIR}/mozilla.cfg"

# Emit eight fully local, distinct monogram favicons. Current Firefox accepts the
# pinned-link favicon/faviconSize fields directly; a >=96 px declared icon
# prevents TopSitesFeed from entering its rich-icon/screenshot fallback. The
# canonical capture kill-switch remains the independent backstop.
python3 - "${FIREFOX_LIB_DIR}/mozilla.cfg" <<'PINNED_SITES_PYEOF'
import json
import sys
from urllib.parse import quote

sites = [
    ("https://noid-privacy.com/linux.html", "NoID Privacy", "N", "#5b4bdb", "#ffffff"),
    ("https://duckduckgo.com/", "DuckDuckGo", "D", "#de5833", "#ffffff"),
    ("https://duck.ai/", "Duck.ai", "AI", "#7a5cff", "#ffffff"),
    ("https://proton.me/mail", "Proton Mail", "P", "#6d4aff", "#ffffff"),
    ("https://signal.org/", "Signal", "S", "#3a76f0", "#ffffff"),
    ("https://mullvad.net/en", "Mullvad VPN", "M", "#ffcc00", "#111111"),
    ("https://www.torproject.org/download/", "Tor Project", "T", "#7d4698", "#ffffff"),
    ("https://discuss.privacyguides.net/", "Privacy Guides", "PG", "#246b5a", "#ffffff"),
]
pins = []
for url, title, label, background, foreground in sites:
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96">'
        f'<rect width="96" height="96" rx="20" fill="{background}"/>'
        '<text x="48" y="61" text-anchor="middle" font-family="sans-serif" '
        f'font-size="36" font-weight="700" fill="{foreground}">{label}</text>'
        '</svg>'
    )
    pins.append({
        "url": url,
        "title": title,
        "favicon": "data:image/svg+xml," + quote(svg, safe=""),
        "faviconSize": 96,
    })

with open(sys.argv[1], "a", encoding="utf-8") as handle:
    handle.write(
        'defaultPref("browser.newtabpage.pinned", '
        + json.dumps(json.dumps(pins, separators=(",", ":")))
        + ');\n'
    )
PINNED_SITES_PYEOF

# Verify the complete lockPref identity set, not merely an aggregate count.
# An exact count alone could accept five duplicated or unrelated preferences.
EXPECTED_LOCK_PREFS=(
    'lockPref("browser.profiles.enabled", false);'
    'lockPref("browser.profiles.created", false);'
    'lockPref("browser.newtabpage.activity-stream.default.sites", "");'
    'lockPref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts", false);'
    'lockPref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts.havePinned", "");'
)
for expected_lock_pref in "${EXPECTED_LOCK_PREFS[@]}"; do
    expected_lock_pref_count=$(grep -Fxc -- "$expected_lock_pref" "${FIREFOX_LIB_DIR}/mozilla.cfg" 2>/dev/null || true)
    expected_lock_pref_count=${expected_lock_pref_count:-0}
    if [ "$expected_lock_pref_count" -ne 1 ]; then
        log "  FAIL: mozilla.cfg requires exactly one: $expected_lock_pref"
        exit 1
    fi
done
LOCK_PREF_COUNT=$(grep -c '^lockPref(' "${FIREFOX_LIB_DIR}/mozilla.cfg" 2>/dev/null || true)
LOCK_PREF_COUNT=${LOCK_PREF_COUNT:-0}
if [ "$LOCK_PREF_COUNT" -ne "${#EXPECTED_LOCK_PREFS[@]}" ]; then
    log "  FAIL: mozilla.cfg lockPref set contains unexpected entries — expected ${#EXPECTED_LOCK_PREFS[@]}, got $LOCK_PREF_COUNT"
    exit 1
fi
DEFAULT_PINNED_COUNT=$(grep -c 'defaultPref("browser.newtabpage.pinned"' "${FIREFOX_LIB_DIR}/mozilla.cfg" 2>/dev/null || true)
DEFAULT_PINNED_COUNT=${DEFAULT_PINNED_COUNT:-0}
if [ "$DEFAULT_PINNED_COUNT" -ne 1 ]; then
    log "  FAIL: mozilla.cfg requires exactly one pinned defaultPref"
    exit 1
fi
TOOLBAR_DEFAULT_COUNT=$(grep -Fxc -- "$TOOLBAR_DEFAULT_PREF" \
    "${FIREFOX_LIB_DIR}/mozilla.cfg" 2>/dev/null || true)
TOOLBAR_DEFAULT_COUNT=${TOOLBAR_DEFAULT_COUNT:-0}
if [ "$TOOLBAR_DEFAULT_COUNT" -ne 1 ]; then
    log "  FAIL: mozilla.cfg requires exactly one reviewed toolbar defaultPref"
    exit 1
fi
if [ "$(grep -Fxc 'defaultPref("network.trr.mode", 5);' \
        "${FIREFOX_LIB_DIR}/mozilla.cfg" 2>/dev/null || true)" -ne 1 ] || \
   [ "$(grep -Fxc 'defaultPref("doh-rollout.home-region", "global");' \
        "${FIREFOX_LIB_DIR}/mozilla.cfg" 2>/dev/null || true)" -ne 1 ] || \
   grep -Eq '^defaultPref\("network\.trr\.(uri|custom_uri|bootstrapAddr)"' \
        "${FIREFOX_LIB_DIR}/mozilla.cfg"; then
    log "  FAIL: Firefox DNS default/chooser must remain user-overridable without a forced DoH provider"
    exit 1
fi
if ! python3 - "${FIREFOX_LIB_DIR}/mozilla.cfg" <<'PINNED_VALIDATE_PYEOF'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    lines = [line.rstrip("\n") for line in handle]
matches = [line for line in lines if line.startswith(
    'defaultPref("browser.newtabpage.pinned", ')]
assert len(matches) == 1
match = re.fullmatch(
    r'defaultPref\("browser\.newtabpage\.pinned", ("(?:\\.|[^"\\])*")\);',
    matches[0],
)
assert match
pins = json.loads(json.loads(match.group(1)))
assert len(pins) == 8
assert len({pin["url"] for pin in pins}) == 8
assert pins[0]["url"] == "https://noid-privacy.com/linux.html"
assert all(set(pin) == {"url", "title", "favicon", "faviconSize"} for pin in pins)
assert all(pin["favicon"].startswith("data:image/svg+xml,%3Csvg") for pin in pins)
assert all(pin["faviconSize"] == 96 for pin in pins)

toolbar_matches = [line for line in lines if line.startswith(
    'defaultPref("browser.uiCustomization.state", ')]
assert len(toolbar_matches) == 1
toolbar_match = re.fullmatch(
    r'defaultPref\("browser\.uiCustomization\.state", ("(?:\\.|[^"\\])*")\);',
    toolbar_matches[0],
)
assert toolbar_match
toolbar = json.loads(json.loads(toolbar_match.group(1)))
assert set(toolbar) == {
    "placements", "seen", "dirtyAreaCache", "currentVersion", "newElementCount",
}
assert toolbar["currentVersion"] == 24
nav_bar = toolbar["placements"]["nav-bar"]
assert nav_bar.count("ublock0_raymondhill_net-browser-action") == 1
assert nav_bar.count("reset-pbm-toolbar-button") == 1
assert toolbar["placements"]["unified-extensions-area"] == []
PINNED_VALIDATE_PYEOF
then
    log "  FAIL: pinned-tile or initial-toolbar defaults differ"
    exit 1
fi
log "  Appended $LOCK_PREF_COUNT lockPref entries (profiles + topsites default-blocker)"
log "  Appended pinned, toolbar + topSitesRows defaults (user-customizable)"

#------------------------------------------------------------------------------
# Step 3c: System-locale flow-through (parity with M35 Thunderbird)
#------------------------------------------------------------------------------
# OS-locale flow-through: empty intl.locale.requested + autoDisableScopes=10
# lets the matching RPM langpack auto-enable. MUST live in a system-pref
# file (read BEFORE autoconfig.cfg) — rationale + refs in the deployed
# NOID_LOCALE_JS_EOF heredoc. Pairs with Step 3d langpack activation.

log "Step 3c/8: Installing /usr/lib64/firefox/defaults/pref/noid-locale.js (locale flow-through)"

cat > "${AUTOCONFIG_PREF_DIR}/noid-locale.js" <<'NOID_LOCALE_JS_EOF'
// NoID Privacy Workstation 44 — system-locale flow-through (defense-in-depth)
// Empty intl.locale.requested triggers Firefox to read $LANG via libc setlocale.
// Reference: Mozilla Bug 1423532 + Debian Bug #997841.
// MUST be in system-pref-file (NOT user.js or mozilla.cfg) — Firefox Init-timing
// reads system-prefs BEFORE autoconfig.cfg, so empty here lets locale-init
// fall back to OS locale via gnu_get_libc_version() / setlocale().
// No JS, no sandbox-bypass, no env-var access from JS context.
// Paired with extensions.autoDisableScopes=10 in user.js (Mozilla langpacks
// at location=app-global auto-enable, allowing fr_FR → langpack-firefox-fr
// to activate matching OS-locale).
pref("intl.locale.requested", "");
pref("intl.regional_prefs.use_os_locales", true);
NOID_LOCALE_JS_EOF
chmod 644 "${AUTOCONFIG_PREF_DIR}/noid-locale.js"
chown root:root "${AUTOCONFIG_PREF_DIR}/noid-locale.js"

if ! grep -q '^pref("intl.locale.requested", "");$' "${AUTOCONFIG_PREF_DIR}/noid-locale.js"; then
    log "  FAIL: noid-locale.js missing intl.locale.requested pref"
    exit 1
fi
log "  Installed ${AUTOCONFIG_PREF_DIR}/noid-locale.js (2 prefs: intl.locale.requested + use_os_locales)"

#------------------------------------------------------------------------------
# Step 3d: Activate Firefox langpacks via distribution/extensions/
#------------------------------------------------------------------------------
# The firefox-langpacks RPM path (/usr/lib64/firefox/langpacks/) is NOT
# scanned since FF91 — the XPIs sit inert. Copying them to
# /usr/lib64/firefox/distribution/extensions makes Firefox distribution-
# install them per profile (locale-type addons ARE distribution-installed,
# UNLIKE regular WebExtensions — empirically verified, see Step 4). Without
# this, the Step-3c locale flow-through has no langpack to activate and the
# UI stays en-US.
log "Step 3d/8: Activate Firefox langpacks (distribution/extensions/)"

FIREFOX_LANGPACK_SRC="${FIREFOX_LIB_DIR}/langpacks"
FIREFOX_DIST_EXT="${FIREFOX_LIB_DIR}/distribution/extensions"

if [ ! -d "$FIREFOX_LANGPACK_SRC" ]; then
    log "  FAIL: $FIREFOX_LANGPACK_SRC missing — firefox-langpacks not installed (check master.ks %packages)"
    exit 1
fi

mkdir -p "$FIREFOX_DIST_EXT"
chmod 0755 "${FIREFOX_LIB_DIR}/distribution" "$FIREFOX_DIST_EXT"

_lp_count=0
for _lp in "$FIREFOX_LANGPACK_SRC"/langpack-*.xpi; do
    [ -f "$_lp" ] || continue
    install -m 0644 "$_lp" "$FIREFOX_DIST_EXT/"
    _lp_count=$((_lp_count + 1))
done

# SELinux context for the new distribution tree (M16 defense-in-depth pattern)
command -v restorecon >/dev/null 2>&1 && restorecon -R "${FIREFOX_LIB_DIR}/distribution" 2>/dev/null || true

if [ "$_lp_count" -eq 0 ]; then
    log "  FAIL: no langpack-*.xpi found in $FIREFOX_LANGPACK_SRC"
    exit 1
fi
log "  Activated ${_lp_count} Firefox langpacks via distribution/extensions/ (FF picks the OS-locale match on first profile start)"

#------------------------------------------------------------------------------
# Step 4: Fetch uBlock Origin XPI to system-scope staging path
#------------------------------------------------------------------------------
# The System-scope path is a stable STAGING location only — the setup
# script (Step 6) copies the verified XPI profile-local. Do NOT re-litigate:
# FF150 distribution-bundled scan does NOT auto-install regular extensions
# (verified across all launch modes), and policies.json
# ExtensionSettings triggers the "managed by your organization" UI hint.
# autoDisableScopes=10 keeps profile-scope XPIs + app-global langpacks
# auto-enabled.

log "Step 4/8: Acquire pinned uBlock Origin XPI v${UBO_VERSION}"

fetch_or_cache "$UBO_CACHE_RELATIVE" \
    "$UBO_URL" "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi"
verify_sha256 "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi" "$UBO_SHA256" "uBO XPI v${UBO_VERSION}"
UBO_SIZE=$(stat -c%s "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi")
if [ "$UBO_SIZE" -ne "$UBO_SIZE_EXPECTED" ]; then
    log "  FAIL: uBO XPI size mismatch ($UBO_SIZE bytes, expected $UBO_SIZE_EXPECTED)"
    exit 1
fi
# XPIs are ZIP files — verify magic bytes (defense in depth after SHA)
if ! file "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi" | grep -q 'Zip archive'; then
    log "  FAIL: uBO XPI not a valid ZIP archive"
    exit 1
fi
chmod 644 "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi"
chown root:root "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi"

log "  Fetched uBO XPI: $UBO_SIZE bytes → $EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi"
log "  (System-scope build-time cache — setup-script copies into active profile in Step 6)"

#------------------------------------------------------------------------------
# Step 5: Install uBlock Origin Managed Storage Manifest
#------------------------------------------------------------------------------
log "Step 5/8: Install uBO Managed Storage Manifest"
cat > "$UBO_POLICY_SOURCE" <<'UBOMANIFEST_EOF'
{
  "name": "uBlock0@raymondhill.net",
  "description": "NoID Privacy Workstation 44 - uBlock Origin managed filter-list baseline (Module 16)",
  "type": "storage",
  "data": {
    "toOverwrite": {
      "filterLists": [
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
        "curben-phishing"
      ]
    }
  }
}
UBOMANIFEST_EOF
chmod 644 "$UBO_POLICY_SOURCE"
chown root:root "$UBO_POLICY_SOURCE"
install -o root -g root -m 0644 -- "$UBO_POLICY_SOURCE" \
    "$MANAGED_STORAGE_DIR/uBlock0@raymondhill.net.json"
log "  Installed canonical and active uBO Managed Storage manifests"

#------------------------------------------------------------------------------
# Step 5b: Install /usr/local/lib/noid-privacy/firefox-profiles.sh
#------------------------------------------------------------------------------
# Single source of truth for profile discovery (registered profiles.ini
# entries, never `find -type d`). Sourced by the M16 CLIs + M33/M34/M25;
# the function inventory + per-function contracts live in the
# FF_PROFILES_EOF heredoc.
log "Step 5b/8: Install /usr/local/lib/noid-privacy/firefox-profiles.sh"

mkdir -p /usr/local/lib/noid-privacy
chmod 755 /usr/local/lib/noid-privacy

cat > "$UBO_POLICY_VALIDATOR" <<'UBO_POLICY_VALIDATOR_PYEOF'
#!/usr/bin/python3
"""Validate a uBO managed filter-list policy against one candidate XPI."""

import json
import os
import stat
import sys
import zipfile


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


if len(sys.argv) != 3:
    print("Usage: validate-ubo-policy.py UBO_XPI MANAGED_STORAGE_JSON", file=sys.stderr)
    raise SystemExit(2)

xpi_path, policy_path = sys.argv[1:]
for path, label in ((xpi_path, "uBO XPI"), (policy_path, "managed policy")):
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        fail(f"{label} is not inspectable: {exc}")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size == 0:
        fail(f"{label} is not a nonempty regular file")

try:
    with open(policy_path, encoding="utf-8") as handle:
        policy = json.load(handle)
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    fail(f"managed policy is not strict UTF-8 JSON: {exc}")

if not isinstance(policy, dict):
    fail("managed policy root is not an object")
if set(policy) != {"name", "description", "type", "data"}:
    fail("managed policy top-level keys differ")
if policy["name"] != "uBlock0@raymondhill.net" or policy["type"] != "storage":
    fail("managed policy identity or type differs")
if not isinstance(policy["description"], str) or not policy["description"]:
    fail("managed policy description is empty")
data = policy["data"]
if not isinstance(data, dict) or set(data) != {"toOverwrite"}:
    fail("managed policy must contain only toOverwrite")
overwrite = data["toOverwrite"]
if not isinstance(overwrite, dict) or set(overwrite) != {"filterLists"}:
    fail("managed policy must overwrite only filterLists")
filter_lists = overwrite["filterLists"]
if (
    not isinstance(filter_lists, list)
    or not filter_lists
    or any(not isinstance(item, str) or not item for item in filter_lists)
    or len(filter_lists) != len(set(filter_lists))
):
    fail("managed filter-list tokens are empty, duplicated or malformed")
if filter_lists.count("user-filters") != 1:
    fail("managed policy must select user-filters exactly once")

try:
    archive = zipfile.ZipFile(xpi_path)
except (OSError, zipfile.BadZipFile) as exc:
    fail(f"uBO XPI is not a valid ZIP archive: {exc}")

with archive:
    members = archive.infolist()

    def read_unique_json(name, maximum):
        matches = [entry for entry in members if entry.filename == name]
        if len(matches) != 1:
            fail(f"uBO XPI must contain exactly one {name}")
        entry = matches[0]
        if entry.is_dir() or entry.file_size == 0 or entry.file_size > maximum:
            fail(f"uBO XPI {name} has an invalid size or type")
        try:
            return json.loads(archive.read(entry).decode("utf-8"))
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            RuntimeError,
            zipfile.BadZipFile,
        ) as exc:
            fail(f"uBO XPI {name} is not strict UTF-8 JSON: {exc}")

    manifest = read_unique_json("manifest.json", 262144)
    if not isinstance(manifest, dict):
        fail("uBO XPI manifest root is not an object")
    browser_settings = manifest.get("browser_specific_settings")
    if not isinstance(browser_settings, dict):
        fail("uBO XPI browser-specific settings are malformed")
    gecko = browser_settings.get("gecko")
    if not isinstance(gecko, dict) or gecko.get("id") != "uBlock0@raymondhill.net":
        fail("uBO XPI manifest identity differs")

    schema = read_unique_json("managed_storage.json", 262144)
    try:
        filter_schema = (
            schema["properties"]["toOverwrite"]["properties"]["filterLists"]
        )
    except (KeyError, TypeError):
        fail("uBO XPI does not advertise toOverwrite.filterLists")
    if (
        not isinstance(filter_schema, dict)
        or filter_schema.get("type") != "array"
        or not isinstance(filter_schema.get("items"), dict)
        or filter_schema["items"].get("type") != "string"
    ):
        fail("uBO XPI filter-list policy schema differs")

    assets = read_unique_json("assets/assets.json", 4194304)
    if not isinstance(assets, dict):
        fail("uBO XPI asset registry root is not an object")
    for token in filter_lists:
        if token == "user-filters":
            continue
        record = assets.get(token)
        if not isinstance(record, dict) or record.get("content") != "filters":
            fail(f"uBO XPI does not provide selected filter list: {token}")
        locations = record.get("contentURL")
        if isinstance(locations, str):
            locations = [locations]
        if (
            not isinstance(locations, list)
            or not locations
            or any(
                not isinstance(location, str)
                or not (
                    location.startswith("https://")
                    or location.startswith("assets/")
                )
                for location in locations
            )
        ):
            fail(f"selected filter list has an unsafe content location: {token}")

print(f"OK: uBO policy selects {len(filter_lists)} candidate-supported filter lists")
UBO_POLICY_VALIDATOR_PYEOF
chmod 755 "$UBO_POLICY_VALIDATOR"
chown root:root "$UBO_POLICY_VALIDATOR"
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$UBO_POLICY_VALIDATOR" 2>/dev/null || true
fi

cat > /usr/local/lib/noid-privacy/validate-webextension.py <<'WEBEXT_VALIDATOR_PYEOF'
#!/usr/bin/python3
"""Validate a bounded Firefox/Thunderbird WebExtension archive.

Usage: validate-webextension.py ARCHIVE ID VERSION REQUIRE_SIGNATURE PRODUCT_VERSION [ALLOW_MISSING_ID]
Use '-' for any archive version or for no product-compatibility check. On
success the exact manifest version is printed; every failure is non-zero.
"""

import json
import os
from pathlib import PurePosixPath
import re
import stat
import sys
import zipfile

if len(sys.argv) not in {6, 7}:
    raise SystemExit(2)

archive, expected_id, expected_version, signature_arg, product_version = sys.argv[1:6]
allow_missing_arg = sys.argv[6] if len(sys.argv) == 7 else "0"
if signature_arg not in {"0", "1"} or allow_missing_arg not in {"0", "1"}:
    raise SystemExit(2)
require_signature = signature_arg == "1"
allow_missing_id = allow_missing_arg == "1"
version_pattern = re.compile(r"^[0-9]+(?:[.][0-9]+)*$")
if expected_version != "-" and not version_pattern.fullmatch(expected_version):
    raise SystemExit(2)

def numeric_version(value):
    match = re.match(r"^[0-9]+(?:[.][0-9]+)*", value)
    if not match:
        raise ValueError(f"invalid numeric version: {value!r}")
    return tuple(int(part) for part in match.group(0).split("."))

def pad(left, right):
    width = max(len(left), len(right))
    return left + (0,) * (width - len(left)), right + (0,) * (width - len(right))

def compatible(product, minimum, maximum):
    current = numeric_version(product)
    if minimum:
        low = numeric_version(minimum)
        if pad(current, low)[0] < pad(current, low)[1]:
            return False
    if maximum and maximum != "*":
        wildcard = maximum.endswith(".*")
        raw_maximum = maximum[:-2] if wildcard else maximum
        high = numeric_version(raw_maximum)
        if wildcard:
            width = len(high)
            if current[:width] > high:
                return False
        elif pad(current, high)[0] > pad(current, high)[1]:
            return False
    return True

archive_stat = os.lstat(archive)
if not stat.S_ISREG(archive_stat.st_mode) or stat.S_ISLNK(archive_stat.st_mode):
    raise SystemExit("archive is not a regular file")
if archive_stat.st_size <= 0 or archive_stat.st_size > 64 * 1024 * 1024:
    raise SystemExit("archive size outside policy")

with zipfile.ZipFile(archive) as bundle:
    entries = bundle.infolist()
    if not entries or len(entries) > 8192:
        raise SystemExit("entry count outside policy")
    seen = set()
    total = 0
    for entry in entries:
        name = entry.filename
        if not name or "\x00" in name or "\\" in name or name.startswith("/"):
            raise SystemExit("unsafe archive path")
        parts = PurePosixPath(name).parts
        if not parts or any(part in {"", ".", ".."} for part in parts):
            raise SystemExit("unsafe archive component")
        normalized = "/".join(parts)
        if normalized in seen:
            raise SystemExit("duplicate archive path")
        seen.add(normalized)
        if entry.flag_bits & 1:
            raise SystemExit("encrypted archive entry")
        mode = (entry.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(mode)
        if entry.is_dir():
            if file_type not in {0, stat.S_IFDIR}:
                raise SystemExit("directory/type mismatch")
        else:
            if file_type not in {0, stat.S_IFREG}:
                raise SystemExit("non-regular archive entry")
            if entry.file_size < 0 or entry.file_size > 64 * 1024 * 1024:
                raise SystemExit("entry size outside policy")
            total += entry.file_size
            if total > 256 * 1024 * 1024:
                raise SystemExit("expanded archive outside policy")
    if bundle.testzip() is not None:
        raise SystemExit("archive CRC failure")
    try:
        manifest_raw = bundle.read("manifest.json")
    except KeyError as exc:
        raise SystemExit("manifest.json missing") from exc
    if len(manifest_raw) > 1024 * 1024:
        raise SystemExit("manifest too large")
    try:
        manifest = json.loads(manifest_raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit("manifest unreadable") from exc
    if not isinstance(manifest, dict):
        raise SystemExit("manifest is not an object")
    gecko = (manifest.get("browser_specific_settings") or
             manifest.get("applications") or {}).get("gecko", {})
    if not isinstance(gecko, dict) or (gecko.get("id") is None and not allow_missing_id) \
            or (gecko.get("id") is not None and gecko.get("id") != expected_id):
        raise SystemExit("extension identity mismatch")
    version = manifest.get("version")
    if not isinstance(version, str) or not version_pattern.fullmatch(version):
        raise SystemExit("extension version is not bounded numeric form")
    if expected_version != "-" and version != expected_version:
        raise SystemExit("extension version mismatch")
    if manifest.get("update_url") not in {None, ""} or gecko.get("update_url") not in {None, ""}:
        raise SystemExit("archive carries an autonomous update URL")
    if require_signature:
        signature_files = {
            "META-INF/manifest.mf", "META-INF/mozilla.sf", "META-INF/mozilla.rsa"
        }
        if not signature_files.issubset(seen):
            raise SystemExit("Mozilla signature container missing")
    if product_version != "-" and not compatible(
            product_version, gecko.get("strict_min_version"),
            gecko.get("strict_max_version")):
        raise SystemExit("extension is incompatible with installed product")

print(version)
WEBEXT_VALIDATOR_PYEOF
chmod 755 /usr/local/lib/noid-privacy/validate-webextension.py
chown root:root /usr/local/lib/noid-privacy/validate-webextension.py
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/local/lib/noid-privacy/validate-webextension.py 2>/dev/null || true
fi
if ! python3 -c 'import pathlib; p=pathlib.Path("/usr/local/lib/noid-privacy/validate-webextension.py"); compile(p.read_text(), str(p), "exec")'; then
    log "FAIL: validate-webextension.py has syntax errors"
    exit 1
fi

cat > /usr/local/lib/noid-privacy/verify-firefox-xpi-signature <<'FIREFOX_XPI_SIGNATURE_EOF'
#!/bin/bash
# Ask the installed Firefox build to verify one candidate XPI in a disposable,
# network-isolated profile. A ZIP signature filename is not proof; Firefox's
# native add-on verifier is the authority. No candidate reaches a real profile
# unless this helper observes the exact signed/active identity below.
set -euo pipefail
PATH=/usr/sbin:/usr/bin
umask 077

[ "$#" -eq 3 ] || exit 2
archive=$1
expected_id=$2
expected_version=$3
[[ "$expected_id" =~ ^[A-Za-z0-9._+@{}-]+$ ]] || exit 2
[[ "$expected_version" =~ ^[0-9]+([.][0-9]+)*$ ]] || exit 2
[ "$(id -u)" -ne 0 ] || exit 2
[ -f "$archive" ] && [ ! -L "$archive" ] || exit 2
for required in /usr/bin/firefox /usr/bin/python3 /usr/bin/unshare; do
    [ -x "$required" ] || exit 1
done

work=$(mktemp -d /var/tmp/noid-firefox-xpi-verify.XXXXXX)
child=
cleanup() {
    if [ -n "${child:-}" ]; then
        # Firefox owns/reaps its content children. Signal only the exact
        # parent PID: a negative process-group signal can cross the caller's
        # group boundary when setsid fails before exec.
        kill -TERM -- "$child" 2>/dev/null || true
        for _ in $(seq 1 20); do
            kill -0 "$child" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL -- "$child" 2>/dev/null || true
        wait "$child" 2>/dev/null || true
    fi
    [ ! -L "$work" ] && rm -rf --one-file-system -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

profile=$work/profile
target=$profile/extensions/${expected_id}.xpi
install -d -m 0700 "$work/home" "$work/state" "$work/cache" \
    "$work/config" "$work/runtime" "$work/tmp" "$profile/extensions"
install -m 0600 -- "$archive" "$target"
cat > "$profile/user.js" <<'FIREFOX_XPI_PREFS_EOF'
user_pref("network.trr.mode", 5);
user_pref("extensions.update.enabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("browser.shell.checkDefaultBrowser", false);
FIREFOX_XPI_PREFS_EOF
chmod 0600 "$profile/user.js"

env -u DBUS_SESSION_BUS_ADDRESS -u DISPLAY -u WAYLAND_DISPLAY \
    HOME="$work/home" XDG_STATE_HOME="$work/state" \
    XDG_CACHE_HOME="$work/cache" XDG_CONFIG_HOME="$work/config" \
    XDG_RUNTIME_DIR="$work/runtime" TMPDIR="$work/tmp" \
    MOZ_CRASHREPORTER_DISABLE=1 \
    /usr/bin/unshare --user --map-current-user --net --pid --fork \
    --kill-child=KILL --mount-proc \
    /usr/bin/firefox --headless --no-remote --profile "$profile" \
    about:blank >/dev/null 2>&1 &
child=$!

for _ in $(seq 1 300); do
    if /usr/bin/python3 - "$profile/extensions.json" "$expected_id" \
            "$expected_version" "$target" <<'FIREFOX_SIGNED_STATE_PY' 2>/dev/null
import json
import os
import sys

path, expected_id, expected_version, expected_path = sys.argv[1:]
with open(path, encoding="utf-8") as source:
    database = json.load(source)
matches = [addon for addon in database.get("addons", [])
           if addon.get("id") == expected_id]
assert len(matches) == 1
addon = matches[0]
assert addon.get("version") == expected_version
assert addon.get("type") == "extension"
assert addon.get("signedState") == 2
assert addon.get("active") is True and addon.get("visible") is True
assert os.path.realpath(addon.get("path", "")) == os.path.realpath(expected_path)
FIREFOX_SIGNED_STATE_PY
    then
        exit 0
    fi
    kill -0 "$child" 2>/dev/null || exit 1
    sleep 0.1
done
exit 1
FIREFOX_XPI_SIGNATURE_EOF
chmod 755 /usr/local/lib/noid-privacy/verify-firefox-xpi-signature
chown root:root /usr/local/lib/noid-privacy/verify-firefox-xpi-signature
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/local/lib/noid-privacy/verify-firefox-xpi-signature 2>/dev/null || true
fi
if ! bash -n /usr/local/lib/noid-privacy/verify-firefox-xpi-signature; then
    log "FAIL: verify-firefox-xpi-signature has syntax errors"
    exit 1
fi

cat > /usr/local/lib/noid-privacy/firefox-profiles.sh <<'FF_PROFILES_EOF'
#!/bin/bash
# /usr/local/lib/noid-privacy/firefox-profiles.sh
#
# NoID Privacy Firefox profile management — single source of truth.
# All NoID Privacy Firefox modules source this library to get a consistent view
# of registered profiles and apply the supported user.js composition per profile.
#
# Profile discovery is via registered profiles.ini entries (not `find -type d`,
# which previously matched non-profile dirs: Crash Reports, Pending Pings,
# Profile Groups, firefox-mpris). Mozilla Bug 2003137 can make Firefox prefer an
# otherwise empty legacy ~/.mozilla/firefox tree over a valid XDG registry
# (https://bugzilla.mozilla.org/show_bug.cgi?id=2003137). The owned
# launcher therefore resolves registered XDG profiles through this helper and
# passes their validated path explicitly.

NOID_FF_USERJS_BASE="/usr/share/noid-firefox/user.js"
NOID_FF_USERJS_PLAYGROUND_OVERRIDES="/usr/share/noid-firefox/user-playground-overrides.js"
NOID_FF_USERJS_DRM_OVERRIDES="/usr/share/noid-firefox/user-drm-overrides.js"
NOID_FF_DRM_SENTINEL_BASENAME=".noid-drm-enabled"
NOID_FF_AUTO_EXCLUSION_BASENAME=".noid-firefox-hardening-disabled"
NOID_FF_AUTO_EXCLUSION_CONTENT="NOID_FIREFOX_HARDENING_DISABLED_V1"
NOID_FF_RELAX_FPP_BEGIN="// NOID-RELAX-FPP-BEGIN"
NOID_FF_RELAX_FPP_END="// NOID-RELAX-FPP-END"
NOID_FF_RELAX_WEBRTC_BEGIN="// NOID-RELAX-WEBRTC-BEGIN"
NOID_FF_RELAX_WEBRTC_END="// NOID-RELAX-WEBRTC-END"
NOID_FF_UBO_XPI="/usr/lib64/mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/uBlock0@raymondhill.net.xpi"
NOID_FF_UBO_SHA256="5b74415860456370644bd80f16125e865b0e6c356bb5dfcfb84069967eaa5287"
NOID_FF_UBO_SIZE=4650100
NOID_FF_WEBEXT_VALIDATOR="/usr/local/lib/noid-privacy/validate-webextension.py"

validate_ubo_profile_xpi() {
    local archive="$1"
    [ -x "$NOID_FF_WEBEXT_VALIDATOR" ] || return 1
    "$NOID_FF_WEBEXT_VALIDATOR" "$archive" \
        uBlock0@raymondhill.net - 1 - >/dev/null
}

noid_atomic_install_file() {
    local source="$1" destination="$2" mode="$3" parent temporary
    parent=$(dirname "$destination") || return 1
    [ -f "$source" ] && [ ! -L "$source" ] || return 1
    [ -d "$parent" ] && [ ! -L "$parent" ] || return 1
    [ ! -L "$destination" ] || return 1
    if [ -e "$destination" ] && [ ! -f "$destination" ]; then
        return 1
    fi
    temporary=$(mktemp "$parent/.$(basename "$destination").tmp.XXXXXXXX") || return 1
    if ! install -m "$mode" -- "$source" "$temporary" || \
       ! sync -- "$temporary" || \
       ! mv -fT -- "$temporary" "$destination" || \
       ! sync -- "$parent"; then
        rm -f -- "$temporary"
        return 1
    fi
}

profile_auto_hardening_excluded() {
    local pdir="$1" marker metadata
    marker="$pdir/$NOID_FF_AUTO_EXCLUSION_BASENAME"
    [ ! -L "$marker" ] || return 2
    if [ ! -e "$marker" ]; then
        return 1
    fi
    [ -f "$marker" ] || return 2
    metadata=$(stat -Lc '%u:%a:%h' -- "$marker" 2>/dev/null) || return 2
    [ "$metadata" = "$(id -u):600:1" ] || return 2
    cmp -s -- "$marker" \
        <(printf '%s\n' "$NOID_FF_AUTO_EXCLUSION_CONTENT") || return 2
}

publish_profile_auto_hardening_exclusion() {
    local pdir="$1" marker temporary
    [ -d "$pdir" ] && [ ! -L "$pdir" ] || return 1
    marker="$pdir/$NOID_FF_AUTO_EXCLUSION_BASENAME"
    [ ! -L "$marker" ] || return 1
    if [ -e "$marker" ]; then
        profile_auto_hardening_excluded "$pdir"
        return
    fi
    temporary=$(mktemp "$pdir/.noid-firefox-auto-exclusion.XXXXXXXX") \
        || return 1
    if ! printf '%s\n' "$NOID_FF_AUTO_EXCLUSION_CONTENT" > "$temporary" || \
       ! chmod 0600 "$temporary" || \
       ! noid_atomic_install_file "$temporary" "$marker" 600; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary"
    profile_auto_hardening_excluded "$pdir"
}

clear_profile_auto_hardening_exclusion() {
    local pdir="$1" marker
    marker="$pdir/$NOID_FF_AUTO_EXCLUSION_BASENAME"
    [ ! -L "$marker" ] || return 1
    if [ ! -e "$marker" ]; then
        return 0
    fi
    profile_auto_hardening_excluded "$pdir" || return 1
    rm -f -- "$marker" && sync -- "$pdir"
}

# Output XDG-Compliant Firefox profile root.
firefox_root() {
    printf '%s\n' "${XDG_CONFIG_HOME:-$HOME/.config}/mozilla/firefox"
}

noid_require_desktop_user() {
    [ "$(id -u)" -ne 0 ] && [ -n "${HOME:-}" ] && [ -d "$HOME" ]
}

# pgrep deliberately reports defunct tasks. A zombie (State Z) and the
# transient dead states (X/x) cannot execute or retain Firefox profile files,
# so they must not strand every profile-management workflow behind a false
# "Firefox is running" result. Every other state remains fail-closed. If an
# extant candidate cannot be parsed safely, treat it as active. A failed or
# malformed process query is also a reason to block mutation, never evidence
# that Firefox has exited.
firefox_process_active() {
    local process_name firefox_pid status_file firefox_state process_uid candidates query_rc
    if ! process_uid=$(id -u) || [[ ! "$process_uid" =~ ^[0-9]+$ ]]; then
        printf '%s\n' 'Firefox process owner could not be determined; refusing profile changes.' >&2
        return 0
    fi
    for process_name in firefox firefox-bin; do
        if candidates=$(pgrep -u "$process_uid" -x "$process_name" 2>/dev/null); then
            if [ -z "$candidates" ]; then
                printf '%s\n' 'Firefox process query returned no usable evidence; refusing profile changes.' >&2
                return 0
            fi
        else
            query_rc=$?
            # pgrep distinguishes a successful no-match query (1) from a
            # query/command failure. Even exit 1 must carry no candidate data.
            if [ "$query_rc" -eq 1 ] && [ -z "$candidates" ]; then
                continue
            fi
            printf '%s\n' 'Firefox process query failed; refusing profile changes.' >&2
            return 0
        fi
        while IFS= read -r firefox_pid; do
            if [[ ! "$firefox_pid" =~ ^[1-9][0-9]*$ ]]; then
                printf '%s\n' 'Firefox process query returned invalid evidence; refusing profile changes.' >&2
                return 0
            fi
            status_file="/proc/${firefox_pid}/status"
            if [ ! -r "$status_file" ]; then
                [ -e "/proc/${firefox_pid}" ] && return 0
                continue
            fi
            firefox_state=$(awk '$1 == "State:" { print $2; exit }' \
                "$status_file" 2>/dev/null || true)
            case "$firefox_state" in
                Z|X|x) continue ;;
                "") [ -e "/proc/${firefox_pid}" ] || continue ;;
            esac
            return 0
        done <<< "$candidates"
    done
    return 1
}

# Serialize every NoID Privacy profile mutation, including independent CLIs and the
# guided update workflow. The descriptor remains held by the calling shell.
acquire_firefox_profile_lock() {
    local state_dir lock_file
    noid_require_desktop_user || return 1
    state_dir="${XDG_STATE_HOME:-$HOME/.local/state}/noid-privacy"
    [ ! -L "$state_dir" ] || return 1
    mkdir -p "$state_dir" || return 1
    chmod 700 "$state_dir" || return 1
    lock_file="$state_dir/firefox-profile-operations.lock"
    [ ! -L "$lock_file" ] || return 1
    exec {NOID_FF_PROFILE_LOCK_FD}>"$lock_file" || return 1
    flock -n "$NOID_FF_PROFILE_LOCK_FD"
}

# Parse profiles.ini with a closed record model. Output:
#   name<TAB>relative-path<TAB>IsRelative<TAB>default
# NoID Privacy helpers intentionally manage only regular, current-user-owned profiles
# below the canonical Firefox root. Firefox may support external absolute
# profiles, but treating profiles.ini as authority to write arbitrary paths is
# outside this helper's safe boundary.
list_registered_profiles() {
    local root
    noid_require_desktop_user || return 1
    root=$(firefox_root) || return 1
    python3 - "$root" <<'PROFILE_LIST_PYEOF'
import configparser
import os
import re
import stat
import sys

raw_root = sys.argv[1]
uid = os.geteuid()
if not os.path.isabs(raw_root) or os.path.normpath(raw_root) != raw_root:
    raise SystemExit(f"unsafe Firefox root: {raw_root!r}")
if os.path.lexists(raw_root):
    root_stat = os.lstat(raw_root)
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        raise SystemExit("Firefox root is not a regular directory")
    if root_stat.st_uid != uid or root_stat.st_mode & 0o022:
        raise SystemExit("Firefox root ownership/mode is unsafe")
else:
    raise SystemExit(0)

ini = os.path.join(raw_root, "profiles.ini")
if not os.path.lexists(ini):
    raise SystemExit(0)
ini_stat = os.lstat(ini)
if not stat.S_ISREG(ini_stat.st_mode) or stat.S_ISLNK(ini_stat.st_mode):
    raise SystemExit("profiles.ini is not a regular file")
if ini_stat.st_uid != uid or ini_stat.st_mode & 0o022:
    raise SystemExit("profiles.ini ownership/mode is unsafe")

parser = configparser.ConfigParser(strict=True, interpolation=None)
parser.optionxform = str
with open(ini, encoding="utf-8") as handle:
    parser.read_file(handle)

seen_names = set()
seen_paths = set()
records = []
for section in parser.sections():
    if not re.fullmatch(r"Profile[0-9]+", section):
        continue
    name = parser.get(section, "Name", fallback="")
    path = parser.get(section, "Path", fallback="")
    relative = parser.get(section, "IsRelative", fallback="")
    default = parser.get(section, "Default", fallback="0")
    # Firefox supports absolute profiles, but they are outside this helper's
    # write boundary. Ignore that one registration instead of making an
    # unrelated safe default profile (and therefore the owned launcher)
    # unusable. Unknown IsRelative values remain malformed and fail closed.
    if relative == "0":
        continue
    if relative != "1":
        raise SystemExit(f"{section}: invalid IsRelative value")
    if not name or any(ch in name for ch in "\t\r\n"):
        raise SystemExit(f"{section}: invalid profile name")
    if name in seen_names:
        raise SystemExit(f"duplicate profile name: {name}")
    if (not path or os.path.isabs(path) or any(ch in path for ch in "\t\r\n")
            or os.path.normpath(path) != path
            or ".." in path.split(os.sep)):
        raise SystemExit(f"{section}: unsafe relative profile path")
    if path in seen_paths:
        raise SystemExit(f"duplicate profile path: {path}")
    if default not in {"0", "1"}:
        raise SystemExit(f"{section}: invalid Default value")
    candidate = os.path.join(raw_root, path)
    current = raw_root
    for component in path.split(os.sep):
        current = os.path.join(current, component)
        if not os.path.lexists(current):
            break
        component_stat = os.lstat(current)
        if stat.S_ISLNK(component_stat.st_mode):
            raise SystemExit(f"{section}: symlinked profile path component")
    if os.path.lexists(candidate):
        profile_stat = os.lstat(candidate)
        if not stat.S_ISDIR(profile_stat.st_mode):
            raise SystemExit(f"{section}: profile path is not a directory")
        if profile_stat.st_uid != uid or profile_stat.st_mode & 0o022:
            raise SystemExit(f"{section}: profile ownership/mode is unsafe")
    seen_names.add(name)
    seen_paths.add(path)
    records.append((name, path, relative, default))

for record in records:
    print("\t".join(record))
PROFILE_LIST_PYEOF
}

# Output a safe path below firefox_root, or return 1 if absent/invalid.
profile_dir_for() {
    local name="$1" records record_name path is_relative match=""
    records=$(list_registered_profiles) || return 1
    while IFS=$'\t' read -r record_name path is_relative _; do
        [ "$record_name" = "$name" ] || continue
        [ -z "$match" ] || return 1
        [ "$is_relative" = "1" ] || return 1
        match="$(firefox_root)/$path"
    done <<< "$records"
    [ -n "$match" ] || return 1
    printf '%s\n' "$match"
}

# Build the exact argv used by the owned Firefox launcher.
#
# Ordinary invocations are bound to the registered, hardened default-release
# path. A named -P/-p profile is converted only when the same safe XDG registry
# resolves it; this preserves the user's profile choice while avoiding the
# legacy-directory shadowing tracked as Mozilla Bug 2003137. Explicit path/profile-manager,
# profile-creation and diagnostic requests retain Firefox's own semantics.
#
# Result: global array NOID_FF_LAUNCH_ARGS. An unresolved ordinary default is
# a hard failure; an unresolved explicit named profile remains user-owned and
# is passed through unchanged.
prepare_firefox_launch_args() {
    local -a original=("$@") normalized=()
    local arg arg_lower named_name="" profile_path
    local i named_index=-1 named_width=0 named_count=0 bypass=0
    declare -ga NOID_FF_LAUNCH_ARGS=()

    for ((i = 0; i < ${#original[@]}; i++)); do
        arg=${original[$i]}
        arg_lower=${arg,,}
        # Firefox accepts these ordinary long options with one or two dashes.
        # Without this closed exception, -p?* mistakes them for a concatenated
        # -pNAME selector and skips the hardened default-profile binding.
        case "$arg_lower" in
            -profilemanager)
                bypass=1
                continue
                ;;
            -private|-private-window|-preferences|-purgecaches)
                continue
                ;;
        esac
        case "$arg" in
            -ProfileManager|--ProfileManager|-CreateProfile|--CreateProfile|\
            -CreateProfile=*|--CreateProfile=*|--help|-h|--version|-v|--full-version)
                bypass=1
                ;;
            -profile|--profile|-profile=*|--profile=*)
                bypass=1
                ;;
            -P|-p)
                if ((i + 1 >= ${#original[@]})); then
                    bypass=1
                    continue
                fi
                ((named_count += 1))
                if ((named_count == 1)); then
                    named_name=${original[$((i + 1))]}
                    named_index=$i
                    named_width=2
                fi
                ((i += 1))
                ;;
            -P?*|-p?*)
                ((named_count += 1))
                if ((named_count == 1)); then
                    named_name=${arg:2}
                    named_index=$i
                    named_width=1
                fi
                ;;
        esac
    done

    if ((bypass || named_count > 1)); then
        NOID_FF_LAUNCH_ARGS=("${original[@]}")
        return 0
    fi

    if ((named_count == 1)); then
        if ! profile_path=$(profile_dir_for "$named_name" 2>/dev/null) || \
           [ ! -d "$profile_path" ] || [ -L "$profile_path" ]; then
            NOID_FF_LAUNCH_ARGS=("${original[@]}")
            return 0
        fi
        for ((i = 0; i < ${#original[@]}; i++)); do
            if ((i == named_index)); then
                normalized+=(--profile "$profile_path")
                i=$((i + named_width - 1))
            else
                normalized+=("${original[$i]}")
            fi
        done
        NOID_FF_LAUNCH_ARGS=("${normalized[@]}")
        return 0
    fi

    profile_path=$(profile_dir_for default-release) || return 1
    [ -d "$profile_path" ] && [ ! -L "$profile_path" ] || return 1
    NOID_FF_LAUNCH_ARGS=(--profile "$profile_path" "${original[@]}")
}

# Create a profile via firefox -CreateProfile if not already registered.
# Returns 0 on success; 1 on failure.
ensure_profile() {
    local name="$1" existing
    noid_require_desktop_user || return 1
    [ -n "$name" ] && [ "${#name}" -le 32 ] || return 1
    case "$name" in *[!a-zA-Z0-9_-]*) return 1 ;; esac
    if existing=$(profile_dir_for "$name" 2>/dev/null); then
        [ -d "$existing" ] && [ ! -L "$existing" ]
        return
    fi
    if ! command -v firefox >/dev/null 2>&1; then
        return 1
    fi
    MOZ_HEADLESS=1 firefox --headless -no-remote -CreateProfile "$name" >/dev/null 2>&1 || return 1
    sleep 1  # allow profiles.ini commit
    profile_dir_for "$name" >/dev/null
}

# Report whether the exact profile-local DRM consent sentinel is absent or
# enabled. Any malformed/symlinked state is an error, never a silent opt-out.
profile_drm_opt_in_state() {
    local pdir="$1" sentinel mode owner
    sentinel="$pdir/$NOID_FF_DRM_SENTINEL_BASENAME"
    if [ ! -e "$sentinel" ] && [ ! -L "$sentinel" ]; then
        printf '%s\n' disabled
        return 0
    fi
    [ -f "$sentinel" ] && [ ! -L "$sentinel" ] || return 1
    mode=$(stat -c '%a' "$sentinel") || return 1
    owner=$(stat -c '%u' "$sentinel") || return 1
    [ "$mode" = 600 ] && [ "$owner" -eq "$(id -u)" ] || return 1
    grep -qx 'NOID_FIREFOX_DRM_OPT_IN_V1' "$sentinel" || return 1
    printf '%s\n' enabled
}

# The two supported compatibility choices are emitted from this shared source
# so the opt-in CLIs, Update All and completeness checks cannot drift apart.
noid_fpp_relaxation_block() {
    cat <<'NOID_FPP_RELAXATION_EOF'
// NOID-RELAX-FPP-BEGIN
// Created by noid-firefox-relax-fpp. Remove with:
//   noid-firefox-relax-fpp --restore
// This ONLY relaxes fingerprinting protection. DNS policy, HTTPS-Only, password
// manager off, Mozilla AI off, Nimbus off, telemetry off — all stay active.
user_pref("privacy.fingerprintingProtection", false);
user_pref("privacy.fingerprintingProtection.pbmode", false);
user_pref("privacy.resistFingerprinting", false);
// NOID-RELAX-FPP-END
NOID_FPP_RELAXATION_EOF
}

noid_webrtc_relaxation_block() {
    cat <<'NOID_WEBRTC_RELAXATION_EOF'
// NOID-RELAX-WEBRTC-BEGIN
// Created by noid-firefox-relax-webrtc. Remove with:
//   noid-firefox-relax-webrtc --restore
// This ONLY re-enables WebRTC. DNS policy, HTTPS-Only, password manager off,
// Mozilla AI off, Nimbus off, telemetry off, FPP on — all stay active.
// ICE candidate-reduction prefs stay on; they are not an IP-leak guarantee.
user_pref("media.peerconnection.enabled", true);
// NOID-RELAX-WEBRTC-END
NOID_WEBRTC_RELAXATION_EOF
}

# Print disabled/enabled only when a marker pair is absent or byte-exactly one
# of the supported blocks above. Malformed or altered blocks are never silently
# carried into a regenerated security configuration.
noid_supported_relaxation_state() {
    local path="$1" begin="$2" end="$3" emitter="$4"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        printf '%s\n' disabled
        return 0
    fi
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    validate_noid_marker_pair "$path" "$begin" "$end" || return 1
    if ! grep -Fxq -- "$begin" "$path"; then
        printf '%s\n' disabled
        return 0
    fi
    cmp -s \
        <(awk -v B="$begin" -v E="$end" '
            $0 == B { capture=1 }
            capture { print }
            capture && $0 == E { exit }
        ' "$path") \
        <("$emitter") || return 1
    printf '%s\n' enabled
}

# Re-emit the two supported compatibility blocks in their one canonical
# FPP-then-WebRTC order while preserving every unrelated user.js line. Each
# choice is enabled, disabled, or preserve. The current blocks must be exact
# even when the caller is changing only the other choice.
compose_userjs_relaxation_choice() {
    local path="$1" fpp_choice="$2" webrtc_choice="$3"
    local current_fpp current_webrtc fpp_state webrtc_state
    current_fpp=$(noid_supported_relaxation_state "$path" \
        "$NOID_FF_RELAX_FPP_BEGIN" "$NOID_FF_RELAX_FPP_END" \
        noid_fpp_relaxation_block) || return 1
    current_webrtc=$(noid_supported_relaxation_state "$path" \
        "$NOID_FF_RELAX_WEBRTC_BEGIN" "$NOID_FF_RELAX_WEBRTC_END" \
        noid_webrtc_relaxation_block) || return 1
    case "$fpp_choice" in
        preserve) fpp_state=$current_fpp ;;
        enabled|disabled) fpp_state=$fpp_choice ;;
        *) return 1 ;;
    esac
    case "$webrtc_choice" in
        preserve) webrtc_state=$current_webrtc ;;
        enabled|disabled) webrtc_state=$webrtc_choice ;;
        *) return 1 ;;
    esac
    awk -v FB="$NOID_FF_RELAX_FPP_BEGIN" \
        -v FE="$NOID_FF_RELAX_FPP_END" \
        -v WB="$NOID_FF_RELAX_WEBRTC_BEGIN" \
        -v WE="$NOID_FF_RELAX_WEBRTC_END" '
        $0 == FB || $0 == WB { skip=1; next }
        skip && ($0 == FE || $0 == WE) { skip=0; next }
        !skip { print }
    ' "$path" || return 1
    if [ "$fpp_state" = enabled ]; then
        noid_fpp_relaxation_block || return 1
    fi
    if [ "$webrtc_state" = enabled ]; then
        noid_webrtc_relaxation_block || return 1
    fi
}

# Emit the complete supported user.js state without publishing it.
# preserve-supported keeps only exact NoID Privacy compatibility blocks.
# reset-relaxations is reserved for an explicit harden-profile --force action.
compose_supported_userjs() {
    local name="$1" pdir="$2" mode="${3:-preserve-supported}"
    local userjs="$pdir/user.js" drm_state fpp_state webrtc_state
    [ -f "$NOID_FF_USERJS_BASE" ] && [ ! -L "$NOID_FF_USERJS_BASE" ] || return 1
    case "$mode" in
        preserve-supported)
            fpp_state=$(noid_supported_relaxation_state "$userjs" \
                "$NOID_FF_RELAX_FPP_BEGIN" "$NOID_FF_RELAX_FPP_END" \
                noid_fpp_relaxation_block) || return 1
            webrtc_state=$(noid_supported_relaxation_state "$userjs" \
                "$NOID_FF_RELAX_WEBRTC_BEGIN" "$NOID_FF_RELAX_WEBRTC_END" \
                noid_webrtc_relaxation_block) || return 1
            ;;
        reset-relaxations)
            fpp_state=disabled
            webrtc_state=disabled
            ;;
        *)
            return 1
            ;;
    esac
    drm_state=$(profile_drm_opt_in_state "$pdir") || return 1

    cat -- "$NOID_FF_USERJS_BASE" || return 1
    if [ "$name" = playground ]; then
        [ -f "$NOID_FF_USERJS_PLAYGROUND_OVERRIDES" ] && \
            [ ! -L "$NOID_FF_USERJS_PLAYGROUND_OVERRIDES" ] || return 1
        cat -- "$NOID_FF_USERJS_PLAYGROUND_OVERRIDES" || return 1
    fi
    if [ "$drm_state" = enabled ]; then
        [ -f "$NOID_FF_USERJS_DRM_OVERRIDES" ] && \
            [ ! -L "$NOID_FF_USERJS_DRM_OVERRIDES" ] || return 1
        cat -- "$NOID_FF_USERJS_DRM_OVERRIDES" || return 1
    fi
    if [ "$fpp_state" = enabled ]; then
        noid_fpp_relaxation_block || return 1
    fi
    if [ "$webrtc_state" = enabled ]; then
        noid_webrtc_relaxation_block || return 1
    fi
}

# Apply the exact supported composition to a registered profile. Regular
# Update/repair paths preserve reviewed compatibility opt-ins; only an explicit
# force operation may request reset-relaxations.
apply_userjs() {
    local name="$1" mode="${2:-preserve-supported}" pdir temporary
    [ "$#" -le 2 ] || return 1
    pdir=$(profile_dir_for "$name") || return 1
    [ -d "$pdir" ] && [ ! -L "$pdir" ] || return 1
    temporary=$(mktemp "$pdir/.user.js.combined.XXXXXXXX") || return 1
    if ! compose_supported_userjs "$name" "$pdir" "$mode" > "$temporary" || \
       ! chmod 600 "$temporary" || \
       ! sync -- "$temporary" || \
       ! noid_atomic_install_file "$temporary" "$pdir/user.js" 600 || \
       ! cmp -s "$temporary" "$pdir/user.js"; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary"
}

profile_userjs_supported() {
    local name="$1" pdir="$2" userjs state
    userjs="$pdir/user.js"
    [ -f "$userjs" ] && [ ! -L "$userjs" ] || return 1
    state=$(stat -c '%u:%a:%h' -- "$userjs") || return 1
    [ "$state" = "$(id -u):600:1" ] || return 1
    # A generator can emit a matching prefix before a later source/read fails.
    # Keep its exit status in the comparison contract, including for callers
    # that do not enable pipefail themselves. This remains a read-only check.
    (
        set -o pipefail
        compose_supported_userjs "$name" "$pdir" | cmp -s -- "$userjs" -
    )
}

# A managed signature is deliberately weaker than byte-exact completeness:
# Update All must recognize an older NoID Privacy base so it can converge it.
# Requiring both stable boundary records, safe ownership and exact cardinality
# avoids treating an unrelated user.js that merely mentions NoID Privacy as managed.
profile_userjs_noid_managed() {
    local pdir="$1" userjs state
    userjs="$pdir/user.js"
    [ -f "$userjs" ] && [ ! -L "$userjs" ] || return 1
    state=$(stat -c '%u:%a:%h' -- "$userjs") || return 1
    [ "$state" = "$(id -u):600:1" ] || return 1
    python3 - "$userjs" <<'NOID_USERJS_MANAGED_PYEOF'
import sys

start = "*    name: NoID Privacy Workstation — Firefox Hardening"
end = 'user_pref("_user.js.parrot", "NOID-COMPLETE: full hardening applied");'
with open(sys.argv[1], encoding="utf-8") as handle:
    lines = [line.rstrip("\n") for line in handle]
starts = [index for index, line in enumerate(lines) if line == start]
ends = [index for index, line in enumerate(lines) if line == end]
if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
    raise SystemExit(1)
NOID_USERJS_MANAGED_PYEOF
}

# Copy the uBO XPI into a named profile's extensions/ directory.
# This is the verified profile-local mechanism, restored after the
# distribution-bundled approach was confirmed non-functional
# under FF150 (XPI never registered in extensions.json across all tested
# launch modes). Used by Module 33 (isolated profiles) + Module 34
# (playground) for non-default-release profiles. Module 16 setup-script
# does the same install for the default-release profile inline.
#
# Requires user.js extensions.autoDisableScopes=10 (Profile bit 1 NOT in the
# disable mask) so Firefox auto-
# enables the Profile-scope XPI on next launch.
install_ubo_profile_local() {
    local name="$1" mode="${2:-preserve-valid}" pdir extension_dir target
    local actual_sha actual_size
    case "$mode" in
        preserve-valid|repair-invalid) ;;
        *) return 2 ;;
    esac
    pdir=$(profile_dir_for "$name") || return 1
    [ -d "$pdir" ] && [ ! -L "$pdir" ] || return 1
    [ -f "$NOID_FF_UBO_XPI" ] && [ ! -L "$NOID_FF_UBO_XPI" ] || return 1
    actual_size=$(stat -c '%s' "$NOID_FF_UBO_XPI") || return 1
    actual_sha=$(sha256sum "$NOID_FF_UBO_XPI" | awk '{print $1}') || return 1
    [ "$actual_size" -eq "$NOID_FF_UBO_SIZE" ] || return 1
    [ "$actual_sha" = "$NOID_FF_UBO_SHA256" ] || return 1

    extension_dir="$pdir/extensions"
    if [ -L "$extension_dir" ] || { [ -e "$extension_dir" ] && [ ! -d "$extension_dir" ]; }; then
        return 1
    fi
    install -d -m 700 "$extension_dir" || return 1
    target="$extension_dir/uBlock0@raymondhill.net.xpi"
    if [ -f "$target" ] && [ ! -L "$target" ]; then
        # A validated profile copy is user-owned current state. Preserve it:
        # M25 may have advanced it beyond the reviewed image seed.
        if validate_ubo_profile_xpi "$target"; then
            return 0
        fi
        [ "$mode" = repair-invalid ] || return 1
    else
        [ ! -e "$target" ] && [ ! -L "$target" ] || return 1
    fi
    noid_atomic_install_file "$NOID_FF_UBO_XPI" "$target" 644 || return 1
    [ "$(stat -c '%s' "$target")" -eq "$NOID_FF_UBO_SIZE" ] || return 1
    [ "$(sha256sum "$target" | awk '{print $1}')" = "$NOID_FF_UBO_SHA256" ] || return 1
    validate_ubo_profile_xpi "$target"
}

# Explicit hardening may repair an invalid regular uBO profile payload from
# the reviewed seed. A valid newer payload is always preserved.
repair_ubo_profile_local() {
    local name="$1" pdir target
    pdir=$(profile_dir_for "$name") || return 1
    target="$pdir/extensions/uBlock0@raymondhill.net.xpi"
    if [ -f "$target" ] && [ ! -L "$target" ] && validate_ubo_profile_xpi "$target"; then
        return 0
    fi
    [ ! -L "$target" ] || return 1
    if [ -e "$target" ] && [ ! -f "$target" ]; then return 1; fi
    install_ubo_profile_local "$name" repair-invalid
}

# Pre-seed extension-preferences.json with PB-allowed permission for uBO.
# Profile-local install activates uBO in normal windows, but private-
# browsing access requires an explicit per-extension permission grant.
patch_ubo_pb_permission() {
    local name="$1" pdir prefs
    pdir=$(profile_dir_for "$name") || return 1
    [ -d "$pdir" ] && [ ! -L "$pdir" ] || return 1
    prefs="$pdir/extension-preferences.json"
    [ ! -L "$prefs" ] || return 1
    if [ -e "$prefs" ] && [ ! -f "$prefs" ]; then return 1; fi
    python3 - "$prefs" <<'PYEOF' || return 1
import json, os, sys, tempfile
path = sys.argv[1]
if os.path.exists(path):
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"refusing to overwrite invalid {path}: {exc}", file=sys.stderr)
        sys.exit(1)
else:
    d = {}
if not isinstance(d, dict):
    print(f"refusing to overwrite non-object JSON in {path}", file=sys.stderr)
    sys.exit(1)
d["uBlock0@raymondhill.net"] = {
    "permissions": ["internal:privateBrowsingAllowed"],
    "origins": [],
    "data_collection": []
}
parent = os.path.dirname(path)
fd, temporary = tempfile.mkstemp(prefix=".extension-preferences.json.tmp.", dir=parent)
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(d, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PYEOF
[ "$(stat -c '%a' "$prefs")" = 600 ] || return 1
}

# Firefox owns extension-preferences.json after the initial seed and rewrites
# its legacy JSONFile with the browser's native 0644 mode. Accept that form
# only when the containing profile remains private; NoID Privacy writers still publish
# 0600. Group/other-writable state is never accepted.
profile_mutable_file_safe() {
    local pdir="$1" path="$2" uid pdir_uid path_uid pdir_mode path_mode
    [ -d "$pdir" ] && [ ! -L "$pdir" ] || return 1
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    uid=$(id -u) || return 1
    pdir_uid=$(stat -c '%u' -- "$pdir") || return 1
    path_uid=$(stat -c '%u' -- "$path") || return 1
    pdir_mode=$(stat -c '%a' -- "$pdir") || return 1
    path_mode=$(stat -c '%a' -- "$path") || return 1
    [ "$pdir_uid" = "$uid" ] && [ "$path_uid" = "$uid" ] || return 1
    case "$path_mode" in
        600) return 0 ;;
        640|644) [ "$pdir_mode" = 700 ] ;;
        *) return 1 ;;
    esac
}

validate_noid_marker_pair() {
    local path="$1" begin="$2" end="$3"
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    python3 - "$path" "$begin" "$end" <<'MARKER_VALIDATE_PYEOF'
import sys
path, begin, end = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    lines = [line.rstrip("\n") for line in handle]
begins = [i for i, line in enumerate(lines) if line == begin]
ends = [i for i, line in enumerate(lines) if line == end]
if len(begins) != len(ends) or len(begins) > 1:
    raise SystemExit("invalid marker cardinality")
if begins and begins[0] >= ends[0]:
    raise SystemExit("reversed marker pair")
MARKER_VALIDATE_PYEOF
}

backup_noid_userjs() {
    local path="$1" backup
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    backup=$(mktemp "$(dirname "$path")/user.js.bak-noid-$(date -u +%Y%m%dT%H%M%S)-XXXXXXXX") || return 1
    if ! cp --preserve=mode,timestamps -- "$path" "$backup" || \
       ! sync -- "$backup"; then
        rm -f -- "$backup"
        return 1
    fi
    printf '%s\n' "$backup"
}

# A profile is complete only when all three required profile-local outputs are
# valid. This prevents a partial earlier run from becoming an idempotent skip.
profile_hardening_complete() {
    local name="$1" pdir userjs ubo prefs
    pdir=$(profile_dir_for "$name") || return 1
    userjs="$pdir/user.js"
    ubo="$pdir/extensions/uBlock0@raymondhill.net.xpi"
    prefs="$pdir/extension-preferences.json"
    profile_userjs_supported "$name" "$pdir" || return 1
    validate_ubo_profile_xpi "$ubo" || return 1
    profile_mutable_file_safe "$pdir" "$prefs" || return 1
    python3 - "$prefs" <<'PROFILE_COMPLETE_PYEOF'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
record = data["uBlock0@raymondhill.net"]
assert record["permissions"] == ["internal:privateBrowsingAllowed"]
assert record["origins"] == []
assert record["data_collection"] == []
PROFILE_COMPLETE_PYEOF
}
FF_PROFILES_EOF

chmod 644 /usr/local/lib/noid-privacy/firefox-profiles.sh
chown root:root /usr/local/lib/noid-privacy/firefox-profiles.sh
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/local/lib/noid-privacy/firefox-profiles.sh 2>/dev/null || true
fi

if ! bash -n /usr/local/lib/noid-privacy/firefox-profiles.sh; then
    log "FAIL: firefox-profiles.sh has syntax errors"
    exit 1
fi
log "  Installed /usr/local/lib/noid-privacy/firefox-profiles.sh"

#------------------------------------------------------------------------------
# Step 5c: /etc/firefox/policies/policies.json (minimal, search only)
#------------------------------------------------------------------------------
# EXACTLY ONE policy ships (SearchEngines.Default=DuckDuckGo): prefs cannot
# set the default engine on Rapid Release (search.json.mozlz4 + Remote
# Settings architecture), and a single minimal policy keeps the "managed by
# your organization" hint out of all main UI (verified). A wider
# policies.json (ExtensionSettings) was rejected for exactly that UI hint.
# SearchEngines works on Rapid Release despite ESR-only forum claims
# (official admin-docs + live test).

install -d -m 755 /etc/firefox/policies
cat > /etc/firefox/policies/policies.json <<'POLICIES_JSON_EOF'
{
  "policies": {
    "SearchEngines": {
      "Default": "DuckDuckGo"
    }
  }
}
POLICIES_JSON_EOF
chmod 644 /etc/firefox/policies/policies.json
chown root:root /etc/firefox/policies/policies.json
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /etc/firefox/policies/policies.json 2>/dev/null || true
fi

# Sanity: verify JSON parseable
if ! python3 -c "import json; json.load(open('/etc/firefox/policies/policies.json'))" 2>/dev/null; then
    log "  FAIL: /etc/firefox/policies/policies.json invalid JSON"
    exit 1
fi
log "  Installed /etc/firefox/policies/policies.json (DuckDuckGo as default search)"

#------------------------------------------------------------------------------
# Step 5d: Empty Fedora default bookmarks without patching Firefox omni.ja
#------------------------------------------------------------------------------
# omni.ja is NEVER patched (zip --update corrupted Firefox chrome/content —
# definitively rejected; tests/16 guards the regression). Instead: M26
# excludes fedora-bookmarks, this step ships an empty /usr/share/bookmarks
# fallback, and Step 5e seeds a valid empty bookmark backup before the first
# profile start. No synthetic distributor processed preference is involved.

mkdir -p /usr/share/bookmarks
cat > /usr/share/bookmarks/default-bookmarks.html <<'EMPTY_BOOKMARKS_EOF'
<!DOCTYPE NETSCAPE-Bookmark-file-1>
<!-- NoID Privacy: empty bookmarks template. Firefox omni.ja is not modified. -->
<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
<TITLE>Bookmarks</TITLE>
<H1>Bookmarks Menu</H1>

<DL><p>
    <DT><H3 PERSONAL_TOOLBAR_FOLDER="true">Bookmarks Toolbar</H3>
    <DL><p>
    </DL><p>
</DL><p>
EMPTY_BOOKMARKS_EOF
chmod 644 /usr/share/bookmarks/default-bookmarks.html
chown root:root /usr/share/bookmarks/default-bookmarks.html
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/share/bookmarks/default-bookmarks.html 2>/dev/null || true
fi
log "  Installed empty /usr/share/bookmarks/default-bookmarks.html (omni.ja untouched)"

# The signed Firefox RPM's distribution.ini stays byte-pristine. The package
# exclusion, empty fallback and empty initial backup are all NoID Privacy-owned
# surfaces; no recurring Firefox-package mutation is required.
if ! rpm -Vf /usr/lib64/firefox/distribution/distribution.ini >/dev/null 2>&1; then
    log "  FAIL: Firefox distribution.ini differs from its signed RPM payload"
    exit 1
fi
log "  Firefox distribution.ini remains pristine"

#------------------------------------------------------------------------------
# Step 5e: /etc/skel pre-bake — eliminate the first-launch race
#------------------------------------------------------------------------------
# Pre-bake the seeded profile (profiles.ini + user.js + uBO XPI + empty
# bookmarks backup) into /etc/skel so the FIRST launch is already hardened —
# the xdg-autostart setup script races the user's dock-click otherwise.
# The setup script stays for warmup/refresh/drift but is out of the
# 1st-launch critical path. (NO installs.ini — see the comment below.)
log "Step 5e/8: Pre-bake Firefox profile into /etc/skel (1st-launch race fix)"

SKEL_FF_BASE="/etc/skel/.config/mozilla/firefox"
SKEL_FF_PROFILE="$SKEL_FF_BASE/default-release"

mkdir -p "$SKEL_FF_PROFILE/extensions"
mkdir -p "$SKEL_FF_PROFILE/bookmarkbackups"

# user.js — copy from /usr/share/noid-firefox/user.js (already written by Step 3)
cp "$SHARE_DIR/user.js" "$SKEL_FF_PROFILE/user.js"
chmod 600 "$SKEL_FF_PROFILE/user.js"

# uBO XPI — copy from /usr/lib64/mozilla/extensions/{ec8030f7-...}/ (Step 4 fetch)
cp "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi" "$SKEL_FF_PROFILE/extensions/uBlock0@raymondhill.net.xpi"
chmod 644 "$SKEL_FF_PROFILE/extensions/uBlock0@raymondhill.net.xpi"

# uBO private-window permission — the profile-local XPI is active in ordinary
# windows without this file, but Firefox requires the explicit per-extension
# record for private windows. This belongs in the same first-launch seed as
# user.js and the XPI; relying on the later XDG setup job left Live sessions
# permanently incomplete because their pre-baked profile otherwise looked
# usable before the job ran.
cat > "$SKEL_FF_PROFILE/extension-preferences.json" <<'SKEL_EXTENSION_PREFS_EOF'
{
  "uBlock0@raymondhill.net": {
    "permissions": [
      "internal:privateBrowsingAllowed"
    ],
    "origins": [],
    "data_collection": []
  }
}
SKEL_EXTENSION_PREFS_EOF
chmod 600 "$SKEL_FF_PROFILE/extension-preferences.json"

# Empty bookmarks JSON backup — Mozilla initPlaces() restores from this on
# first profile launch (places.sqlite missing → DATABASE_STATUS_CREATE → look
# for backup → restore empty tree → 0 Fedora bookmarks).
# Filename must match Mozilla regex: bookmarks-YYYY-MM-DD.json (no hash, simplest valid form).
SKEL_BM_TS=$(date +%s%6N)
SKEL_BM_DATE=$(date +%Y-%m-%d)
cat > "$SKEL_FF_PROFILE/bookmarkbackups/bookmarks-${SKEL_BM_DATE}.json" <<SKEL_BACKUP_EOF
{
  "guid": "root________",
  "title": "",
  "index": 0,
  "dateAdded": ${SKEL_BM_TS},
  "lastModified": ${SKEL_BM_TS},
  "id": 1,
  "typeCode": 2,
  "type": "text/x-moz-place-container",
  "root": "placesRoot",
  "children": [
    {"guid": "menu________", "title": "menu", "index": 0, "dateAdded": ${SKEL_BM_TS}, "lastModified": ${SKEL_BM_TS}, "id": 2, "typeCode": 2, "type": "text/x-moz-place-container", "root": "bookmarksMenuFolder", "children": []},
    {"guid": "toolbar_____", "title": "toolbar", "index": 1, "dateAdded": ${SKEL_BM_TS}, "lastModified": ${SKEL_BM_TS}, "id": 3, "typeCode": 2, "type": "text/x-moz-place-container", "root": "toolbarFolder", "children": []},
    {"guid": "tags________", "title": "tags", "index": 2, "dateAdded": ${SKEL_BM_TS}, "lastModified": ${SKEL_BM_TS}, "id": 4, "typeCode": 2, "type": "text/x-moz-place-container", "root": "tagsFolder", "children": []},
    {"guid": "unfiled_____", "title": "unfiled", "index": 3, "dateAdded": ${SKEL_BM_TS}, "lastModified": ${SKEL_BM_TS}, "id": 5, "typeCode": 2, "type": "text/x-moz-place-container", "root": "unfiledBookmarksFolder", "children": []},
    {"guid": "mobile______", "title": "mobile", "index": 4, "dateAdded": ${SKEL_BM_TS}, "lastModified": ${SKEL_BM_TS}, "id": 6, "typeCode": 2, "type": "text/x-moz-place-container", "root": "mobileFolder", "children": []}
  ]
}
SKEL_BACKUP_EOF
chmod 644 "$SKEL_FF_PROFILE/bookmarkbackups/bookmarks-${SKEL_BM_DATE}.json"

# profiles.ini — point to our pre-baked profile
cat > "$SKEL_FF_BASE/profiles.ini" <<'SKEL_PROFILES_EOF'
[Profile0]
Name=default-release
IsRelative=1
Path=default-release
Default=1

[General]
StartWithLastProfile=1
Version=2
SKEL_PROFILES_EOF
chmod 644 "$SKEL_FF_BASE/profiles.ini"

# Do not ship installs.ini. Firefox 67+ computes its install-
# hash from the canonical firefox executable path. Pre-baking installs.ini
# with a hand-rolled hash like [NoID000000000000] does NOT match the real
# computed hash — Firefox treats it as foreign and either falls back to
# profiles.ini Default=1 (good) OR creates a new profile and writes its OWN
# [REAL_HASH] entry to installs.ini (bad). We let Firefox auto-write on first
# launch: it reads our profiles.ini Default=1, uses default-release, and
# generates installs.ini with the real install-hash + Locked=1 itself. From
# the second launch onwards, installs.ini correctly pins our profile.

# Tree perms: parent dirs stay traversable (755), but the profile directory
# itself is 700 — once the user runs Firefox it holds cookies.sqlite /
# key4.db / cert9.db / places.sqlite / session state, which must not be
# world-readable. Matches the Module 34 playground-profile convention.
chown -R root:root "$SKEL_FF_BASE"
chmod -R go-w "$SKEL_FF_BASE"
find "$SKEL_FF_BASE" -type d -exec chmod 755 {} \;
chmod 700 "$SKEL_FF_PROFILE"

log "  Pre-baked /etc/skel/.config/mozilla/firefox/default-release/ (user.js + uBO XPI + PB permission + empty bookmarks)"

# /etc/skel is consulted only at USER-CREATION time — liveuser already
# exists before %post, so mirror the pre-bake directly into any existing
# real user home (uid >= 1000). New users created later get it via skel.
log "  Mirroring pre-bake to existing real users (Live-mode liveuser + similar)"
for user_home in /home/*; do
    [ -d "$user_home" ] || continue
    user_name=$(basename "$user_home")
    # Skip system home dirs that aren't real users (uid < 1000)
    user_uid=$(id -u "$user_name" 2>/dev/null) || continue
    [ "$user_uid" -ge 1000 ] || continue
    user_gid=$(id -g "$user_name" 2>/dev/null) || continue

    target_base="$user_home/.config/mozilla/firefox"
    for user_path in \
        "$user_home/.config" \
        "$user_home/.config/mozilla" \
        "$target_base"; do
        if [ -L "$user_path" ] || { [ -e "$user_path" ] && [ ! -d "$user_path" ]; }; then
            log "  FAIL: unsafe existing Firefox seed path: $user_path"
            exit 1
        fi
    done
    install -d -m 0700 -o "$user_uid" -g "$user_gid" "$user_home/.config"
    install -d -m 0700 -o "$user_uid" -g "$user_gid" "$user_home/.config/mozilla"
    install -d -m 0700 -o "$user_uid" -g "$user_gid" "$target_base"
    install -d -m 0700 -o "$user_uid" -g "$user_gid" \
        "$target_base/default-release/extensions" \
        "$target_base/default-release/bookmarkbackups"
    # Use cp -a to preserve mode + timestamps. The trailing /. on source
    # copies CONTENTS of the dir (including dotfiles) into existing target,
    # which avoids the "subdir nesting" that plain `cp -r src dst` would do
    # if dst already exists.
    cp -a "$SKEL_FF_BASE/profiles.ini" "$target_base/profiles.ini"
    cp -a "$SKEL_FF_BASE/default-release/user.js" "$target_base/default-release/user.js"
    cp -a "$SKEL_FF_BASE/default-release/extensions/uBlock0@raymondhill.net.xpi" \
          "$target_base/default-release/extensions/uBlock0@raymondhill.net.xpi"
    cp -a "$SKEL_FF_BASE/default-release/extension-preferences.json" \
          "$target_base/default-release/extension-preferences.json"
    cp -a "$SKEL_FF_BASE/default-release/bookmarkbackups/." \
          "$target_base/default-release/bookmarkbackups/"
    chown -R "$user_uid:$user_gid" "$user_home/.config/mozilla/firefox"
    # Profile dir 700 — the mkdir -p above created it under the %post umask;
    # force owner-only so the profile (future cookies/keys/history) is private.
    chmod 700 "$target_base/default-release"
    log "    Mirrored to $user_home (uid=$user_uid)"
done

log "  1st-launch race eliminated: liveuser + future installed users get seeded profile"

#------------------------------------------------------------------------------
# Step 6: Install first-run setup script + XDG autostart entry
#------------------------------------------------------------------------------
log "Step 6/8: Install first-run setup script + XDG autostart entry"

cat > "$LOCAL_BIN_DIR/noid-firefox-setup.sh" <<'SETUPSCRIPT_EOF'
#!/bin/bash
# NoID Privacy Workstation 44 - Firefox Hardening First-Run Setup v2
# Module 16 — silent-launch + per-profile deployment.
#
# Root cause of the former first-launch bug: the setup script created a stub profile
# at .config/mozilla/firefox/default-release/ + minimal profiles.ini. Firefox 150
# *ignored* that on first launch (no [Install<HASH>] section in installs.ini)
# and created its OWN hash-based profile (e.g. tn0ohv56.default-release-1) +
# wrote installs.ini pointing to its hash-profile. Our user.js + XPI landed in
# the orphaned default-release/ dir → never used.
#
# v2 fix: let Firefox create its profile FIRST (silent --headless launch),
# detect the active profile from installs.ini, THEN drop user.js + uBO
# Private-Browsing permission in.
#
# Flow:
#   1. Self-detach via setsid and take a per-user, non-blocking lock
#   2. Validate the exact canonical base/consent-overlay + uBO source bytes
#   3. Detect active profile via installs.ini Default= (or profiles.ini fallback).
#      If none, run `firefox --headless --no-remote --new-instance` for ~6s to
#      force profile creation, then re-detect.
#   4. Refuse to race Firefox or overwrite noncanonical user configuration
#   5. Atomically install required files without deleting history, bookmarks,
#      favicons, backups, window state, or any profile directory
#   6. Validate every required postcondition and atomically publish an exact,
#      content-bound state record; an interrupted run is safely retryable

set -euo pipefail

case "$#" in
    0) ;;
    1) [ "$1" = --detached ] || {
        printf '%s\n' 'ERROR: noid-firefox-setup accepts only zero arguments or --detached' >&2
        exit 2
    } ;;
    *)
        printf '%s\n' 'ERROR: noid-firefox-setup accepts only zero arguments or --detached' >&2
        exit 2
        ;;
esac

CMDLINE_FILE=/proc/cmdline
if [ "${NOID_TEST_MODE:-0}" = 1 ]; then
    CMDLINE_FILE=${NOID_TEST_CMDLINE_FILE:?NOID_TEST_CMDLINE_FILE is required in test mode}
fi

# Skip in live-ISO mode. Per-user Firefox profile setup
# in live overlay-fs is wasted work — overlay doesn't persist to installed
# system, plus Firefox setup running during Anaconda install confuses UX.
# Installed system has no `rd.live.image` cmdline, so script runs normally.
if grep -q "rd.live.image" "$CMDLINE_FILE" 2>/dev/null; then
    logger -t "noid-firefox-setup" "skip: rd.live.image (live-ISO mode)" 2>/dev/null || true
    exit 0
fi

if [[ "${1:-}" != "--detached" ]]; then
    exec setsid "$0" --detached &>/dev/null &
    exit 0
fi

FIREFOX_CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/mozilla/firefox"
INSTALLS_INI="$FIREFOX_CONFIG/installs.ini"
PROFILES_INI="$FIREFOX_CONFIG/profiles.ini"
SOURCE_DIR="/usr/share/noid-firefox"
UBO_XPI="/usr/lib64/mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/uBlock0@raymondhill.net.xpi"
STATE_FILE="${XDG_STATE_HOME:-$HOME/.local/state}/noid-privacy/firefox-setup.done"
STATE_DIR="$(dirname "$STATE_FILE")"
LOCK_FILE="$STATE_DIR/firefox-profile-operations.lock"
UBO_SHA256="5b74415860456370644bd80f16125e865b0e6c356bb5dfcfb84069967eaa5287"
UBO_SIZE_EXPECTED=4650100
WEBEXT_VALIDATOR="/usr/local/lib/noid-privacy/validate-webextension.py"
PROFILE_HELPER="/usr/local/lib/noid-privacy/firefox-profiles.sh"
LOG_TAG="noid-firefox-setup"

log() { logger -t "$LOG_TAG" -- "$*" 2>/dev/null || true; echo "[$LOG_TAG] $*" >&2; }
notify() {
    notify-send --urgency="$1" --icon="$2" "$3" "$4" 2>/dev/null || true
}

if [[ ! -f "$PROFILE_HELPER" ]] || [[ -L "$PROFILE_HELPER" ]]; then
    log "FATAL: shared Firefox profile helper is missing or unsafe"
    exit 1
fi
# The FF_PROFILES_EOF library is extracted and linted independently; its
# installed absolute path does not exist in the temporary lint workspace.
# shellcheck source=/dev/null
. "$PROFILE_HELPER"

# XDG paths are valid only when absolute. Reject malformed input before a
# headless Firefox launch can create state at a path different from the one
# this setup transaction will later validate.
if ! python3 - "$FIREFOX_CONFIG" <<'FIREFOX_ROOT_PATH_PYEOF'
import os
import sys

path = sys.argv[1]
if not os.path.isabs(path) or os.path.normpath(path) != path:
    raise SystemExit("Firefox root is not an absolute normalized XDG path")
FIREFOX_ROOT_PATH_PYEOF
then
    log "FATAL: invalid XDG Firefox configuration root"
    exit 1
fi

# Resolve one detected active profile only when it remains inside the canonical
# current-user Firefox root. Firefox supports external absolute profiles, but
# profiles.ini/installs.ini is user-controlled metadata and is not authority
# for this automatic setup job to write an arbitrary filesystem path.
validate_active_profile_boundary() {
    python3 - "$FIREFOX_CONFIG" "$1" <<'ACTIVE_PROFILE_BOUNDARY_PYEOF'
import os
import stat
import sys

raw_root, raw_profile = sys.argv[1:]
uid = os.geteuid()

def reject(message):
    print(f"unsafe active Firefox profile: {message}", file=sys.stderr)
    raise SystemExit(1)

for label, path in (("Firefox root", raw_root), ("profile", raw_profile)):
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        reject(f"{label} is not an absolute normalized path")

if raw_profile == raw_root:
    reject("profile resolves to the Firefox root itself")
try:
    if os.path.commonpath((raw_root, raw_profile)) != raw_root:
        reject("profile is outside the Firefox root")
except ValueError:
    reject("profile and Firefox root do not share a path domain")

root_stat = os.lstat(raw_root)
if (not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode)
        or root_stat.st_uid != uid or root_stat.st_mode & 0o022):
    reject("Firefox root ownership, mode or type is unsafe")

relative = os.path.relpath(raw_profile, raw_root)
current = raw_root
for component in relative.split(os.sep):
    if component in {"", ".", ".."}:
        reject("profile has an unsafe path component")
    current = os.path.join(current, component)
    component_stat = os.lstat(current)
    if stat.S_ISLNK(component_stat.st_mode):
        reject("profile path contains a symbolic link")

profile_stat = os.lstat(raw_profile)
if (not stat.S_ISDIR(profile_stat.st_mode)
        or profile_stat.st_uid != uid or profile_stat.st_mode & 0o022):
    reject("profile ownership, mode or type is unsafe")

root_real = os.path.realpath(raw_root)
profile_real = os.path.realpath(raw_profile)
try:
    if os.path.commonpath((root_real, profile_real)) != root_real:
        reject("canonical profile escapes the canonical Firefox root")
except ValueError:
    reject("canonical profile and root do not share a path domain")
print(profile_real)
ACTIVE_PROFILE_BOUNDARY_PYEOF
}

# Install one reviewed regular file through a same-directory temporary file.
# Same-filesystem rename prevents a crash from publishing partial bytes.
atomic_install() {
    local source="$1" destination="$2" mode="$3" parent temporary
    parent="$(dirname "$destination")"
    [[ -f "$source" ]] && [[ ! -L "$source" ]] || return 1
    [[ -d "$parent" ]] && [[ ! -L "$parent" ]] || return 1
    [[ ! -L "$destination" ]] || return 1
    if [[ -e "$destination" ]] && [[ ! -f "$destination" ]]; then
        return 1
    fi
    temporary=$(mktemp "$parent/.$(basename "$destination").tmp.XXXXXXXX") || return 1
    if ! install -m "$mode" -- "$source" "$temporary" || \
       ! sync -- "$temporary" || \
       ! mv -fT -- "$temporary" "$destination" || \
       ! sync -- "$parent"; then
        rm -f -- "$temporary"
        return 1
    fi
}

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
[ ! -L "$LOCK_FILE" ] || { log "FATAL: setup lock is symlinked"; exit 1; }
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    log "another setup instance holds the per-user lock; retry on next login"
    exit 75
fi

if [[ ! -f "$SOURCE_DIR/user.js" ]] || [[ -L "$SOURCE_DIR/user.js" ]]; then
    log "FATAL: $SOURCE_DIR/user.js not found"
    notify critical dialog-error "NoID Privacy Firefox Setup Error" \
        "Source $SOURCE_DIR/user.js not found. Setup aborted."
    exit 1
fi
if [[ ! -f "$UBO_XPI" ]] || [[ -L "$UBO_XPI" ]]; then
    log "FATAL: required regular uBlock Origin XPI is unavailable"
    notify critical dialog-error "NoID Privacy Firefox Setup Error" \
        "Required uBlock Origin package is unavailable. Setup aborted without a success state."
    exit 1
fi
if [[ "$(stat -c '%s' "$UBO_XPI")" -ne "$UBO_SIZE_EXPECTED" ]] || \
   [[ "$(sha256sum "$UBO_XPI" | awk '{print $1}')" != "$UBO_SHA256" ]]; then
    log "FATAL: required uBlock Origin XPI differs from the reviewed bytes"
    exit 1
fi
if [[ ! -x "$WEBEXT_VALIDATOR" ]] || \
   ! "$WEBEXT_VALIDATOR" "$UBO_XPI" uBlock0@raymondhill.net \
        - 1 - >/dev/null; then
    log "FATAL: required uBlock Origin XPI fails structure/identity/signature validation"
    exit 1
fi

# ---------------------------------------------------------------------------
# Detect active profile (NoID Privacy v2: post-Firefox-launch detection)
# Section in installs.ini is bare hex hash like [11457493C5A56847], NOT
# [Install<HASH>]. Match any [<hex>] section with a Default= line.
# ---------------------------------------------------------------------------
detect_active_profile() {
    local active=""

    # Method A: installs.ini per-Install Default=
    if [[ -f "$INSTALLS_INI" ]]; then
        active=$(awk '
            /^\[[0-9A-Fa-f]+\]/ { in_install=1; next }
            /^\[/                { in_install=0; next }
            /^Default=/ {
                if (in_install) { sub("^Default=", ""); print; exit }
            }
        ' "$INSTALLS_INI")
        if [[ -n "$active" ]]; then
            [[ "$active" == /* ]] || active="$FIREFOX_CONFIG/$active"
            if [[ -d "$active" ]]; then
                echo "$active"
                return 0
            fi
        fi
    fi

    # Method B: profiles.ini Default=1 fallback. Per-section state flushes at
    # every section header (and at END), so an earlier [ProfileN] carrying
    # Default=1 wins even when later sections follow it; awk `exit` would
    # still run END, hence the printed-once flag.
    if [[ -f "$PROFILES_INI" ]]; then
        active=$(awk '
            /^\[/ { if (!done && is_default && path) { print path; done=1 }
                    is_default=0; path="" }
            /^Path=/      { sub("^Path=", ""); path=$0 }
            /^Default=1/  { is_default=1 }
            END { if (!done && is_default && path) print path }
        ' "$PROFILES_INI")
        if [[ -n "$active" ]]; then
            [[ "$active" == /* ]] || active="$FIREFOX_CONFIG/$active"
            if [[ -d "$active" ]]; then
                echo "$active"
                return 0
            fi
        fi
    fi

    # Method C: scan for hash-named or plain default-release profile dir
    for active in "$FIREFOX_CONFIG"/*.default-release "$FIREFOX_CONFIG"/*.default \
                  "$FIREFOX_CONFIG/default-release" "$FIREFOX_CONFIG/default"; do
        if [[ -d "$active" ]]; then
            echo "$active"
            return 0
        fi
    done

    return 1
}

ACTIVE_PROFILE=""
ACTIVE_PROFILE=$(detect_active_profile 2>/dev/null) || true

if [[ -n "$ACTIVE_PROFILE" ]]; then
    log "active profile detected without launch: $ACTIVE_PROFILE"
fi

# If no profile yet, force Firefox to create one via headless launch
if [[ -z "$ACTIVE_PROFILE" ]]; then
    log "no profile yet → silent-launch firefox to force creation"

    if firefox_process_active; then
        log "firefox already running, defer + retry"
        sleep 3
        ACTIVE_PROFILE=$(detect_active_profile 2>/dev/null) || true
    else
        FF_PID=""
        # Silent-launch on about:newtab (NOT about:blank) so
        # Activity Stream React app warm-starts + caches its initial state.
        # Otherwise user's first real launch shows blank page (no logo, no
        # search box, no tile grid) and requires a 2nd launch to render.
        # This resolves the observed first-launch blank-page symptom.
        timeout 8 env MOZ_HEADLESS=1 firefox --headless --no-remote --new-instance about:newtab \
            >/dev/null 2>&1 &
        FF_PID=$!
        sleep 6
        kill "$FF_PID" 2>/dev/null || true
        wait "$FF_PID" 2>/dev/null || true
        sleep 2  # allow flush

        ACTIVE_PROFILE=$(detect_active_profile 2>/dev/null) || true
    fi
fi

if [[ -z "$ACTIVE_PROFILE" ]]; then
    log "FATAL: could not detect Firefox profile after silent-launch"
    notify critical dialog-error "NoID Privacy Firefox Setup Error" \
        "Could not detect Firefox profile. Setup aborted — please open Firefox manually once, then re-run noid-firefox-setup.sh."
    exit 1
fi

if ! ACTIVE_PROFILE=$(validate_active_profile_boundary "$ACTIVE_PROFILE"); then
    log "FATAL: active profile is outside the safe automatic-write boundary"
    notify critical dialog-error "NoID Privacy Firefox Setup Error" \
        "The detected Firefox profile is unsafe for automatic setup. No profile bytes were changed."
    exit 1
fi

if [[ ! -w "$ACTIVE_PROFILE" ]]; then
    log "FATAL: profile $ACTIVE_PROFILE not writable"
    notify critical dialog-error "NoID Privacy Firefox Setup Error" \
        "Firefox profile $ACTIVE_PROFILE not writable. Setup aborted."
    exit 1
fi

SOURCE_USERJS_SHA256=$(sha256sum "$SOURCE_DIR/user.js" | awk '{print $1}')
DRM_OVERLAY="$SOURCE_DIR/user-drm-overrides.js"
DRM_SENTINEL="$ACTIVE_PROFILE/.noid-drm-enabled"
expected_state() {
    printf '%s\n' \
        NOID_FIREFOX_SETUP_V1 \
        "profile=$ACTIVE_PROFILE" \
        "userjs_sha256=$SOURCE_USERJS_SHA256" \
        "ubo_sha256=$UBO_SHA256"
}

# Return disabled/enabled only for the two exact supported consent states.
# Malformed/symlinked state is an error and never causes a silent overwrite.
supported_drm_state() {
    local mode owner
    if [[ ! -e "$DRM_SENTINEL" ]] && [[ ! -L "$DRM_SENTINEL" ]]; then
        printf '%s\n' disabled
        return 0
    fi
    [[ -f "$DRM_SENTINEL" ]] && [[ ! -L "$DRM_SENTINEL" ]] || return 1
    mode=$(stat -c '%a' "$DRM_SENTINEL") || return 1
    owner=$(stat -c '%u' "$DRM_SENTINEL") || return 1
    [[ "$mode" == 600 ]] && [[ "$owner" -eq "$(id -u)" ]] || return 1
    grep -qx 'NOID_FIREFOX_DRM_OPT_IN_V1' "$DRM_SENTINEL" || return 1
    [[ -f "$DRM_OVERLAY" ]] && [[ ! -L "$DRM_OVERLAY" ]] || return 1
    printf '%s\n' enabled
}

supported_userjs_matches() {
    [[ -f "$ACTIVE_PROFILE/user.js" ]] && \
        [[ ! -L "$ACTIVE_PROFILE/user.js" ]] || return 1
    profile_userjs_supported default-release "$ACTIVE_PROFILE"
}

install_supported_userjs() {
    local state temporary
    # A byte-exact shared-library composition may include either supported
    # compatibility opt-in. Preserve it instead of rewriting it on login.
    if supported_userjs_matches; then
        return 0
    fi
    state=$(supported_drm_state) || return 1
    if [[ "$state" == disabled ]]; then
        atomic_install "$SOURCE_DIR/user.js" "$ACTIVE_PROFILE/user.js" 600
        return
    fi
    temporary=$(mktemp "$ACTIVE_PROFILE/.user.js.setup-drm.XXXXXXXX") || return 1
    if ! cat -- "$SOURCE_DIR/user.js" "$DRM_OVERLAY" > "$temporary" || \
       ! chmod 600 "$temporary" || \
       ! atomic_install "$temporary" "$ACTIVE_PROFILE/user.js" 600; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary"
}

required_outputs_valid() {
    local installed_ubo="$ACTIVE_PROFILE/extensions/uBlock0@raymondhill.net.xpi"
    local extension_preferences="$ACTIVE_PROFILE/extension-preferences.json"
    # The installed uBO XPI is validated for archive structure, exact identity
    # and Mozilla signature-container presence. After the reviewed seed, the
    # profile copy is user-owned state: the
    # privacy defaults disable automatic add-on update checks
    # (extensions.update.enabled=false — no background calls to Mozilla),
    # so a newer uBO lands only through the user-started M25 Update All
    # workflow. Re-pinning the profile bytes here would downgrade any such
    # update at the next login. The seed SOURCE below
    # /usr/lib64/mozilla remains byte-pinned.
    supported_userjs_matches && \
    [[ -d "$ACTIVE_PROFILE/extensions" ]] && [[ ! -L "$ACTIVE_PROFILE/extensions" ]] && \
    [[ -f "$installed_ubo" ]] && [[ ! -L "$installed_ubo" ]] && \
    "$WEBEXT_VALIDATOR" "$installed_ubo" uBlock0@raymondhill.net \
        - 1 - >/dev/null && \
    [[ -f "$extension_preferences" ]] && [[ ! -L "$extension_preferences" ]] && \
    python3 - "$extension_preferences" <<'OUTPUT_VALIDATION_PYEOF'
import json, os, stat, sys
path = sys.argv[1]
file_stat = os.lstat(path)
profile_stat = os.lstat(os.path.dirname(path))
mode = stat.S_IMODE(file_stat.st_mode)
profile_mode = stat.S_IMODE(profile_stat.st_mode)
with open(path, encoding="utf-8") as handle:
    data = json.load(handle)
assert file_stat.st_uid == os.geteuid()
assert profile_stat.st_uid == os.geteuid()
assert mode == 0o600 or (mode in {0o640, 0o644} and profile_mode == 0o700)
assert data["uBlock0@raymondhill.net"]["permissions"] == ["internal:privateBrowsingAllowed"]
assert data["uBlock0@raymondhill.net"]["origins"] == []
assert data["uBlock0@raymondhill.net"]["data_collection"] == []
OUTPUT_VALIDATION_PYEOF
}
if [[ -e "$STATE_FILE" ]] || [[ -L "$STATE_FILE" ]]; then
    if [[ -f "$STATE_FILE" ]] && [[ ! -L "$STATE_FILE" ]] && \
       cmp -s "$STATE_FILE" <(expected_state) && required_outputs_valid; then
        log "exact setup state and required outputs are valid, skip"
        exit 0
    fi
    [[ ! -L "$STATE_FILE" ]] || { log "FATAL: setup state is symlinked"; exit 1; }
    log "stale/incomplete setup state found; rechecking safely without deleting profile data"
fi

# Do not race a user's running browser. The setup-owned headless process, when
# needed, has already been terminated and waited above.
if firefox_process_active; then
    log "Firefox is running; no profile bytes changed, retry on next login"
    exit 75
fi

# An existing noncanonical user.js is user-owned configuration. Automatic
# first-login setup never overwrites it; the explicit harden-profile --force
# workflow is the reviewable replacement path.
if [[ -e "$ACTIVE_PROFILE/user.js" ]] || [[ -L "$ACTIVE_PROFILE/user.js" ]]; then
    [[ -f "$ACTIVE_PROFILE/user.js" ]] && [[ ! -L "$ACTIVE_PROFILE/user.js" ]] || {
        log "FATAL: active profile user.js is non-regular or symlinked"
        exit 1
    }
    if ! supported_userjs_matches; then
        log "FATAL: existing noncanonical user.js preserved; explicit --force review required"
        notify critical dialog-error "NoID Privacy Firefox Setup Needs Review" \
            "Existing Firefox user.js was preserved. Run noid-firefox-harden-profile --force only after review."
        exit 1
    fi
fi

# Never move or delete a profile directory automatically. Filename/sentinel
# heuristics cannot prove that a restored or partially initialized directory is
# disposable. Reconcile registration metadata only; every directory and every
# user data file remains byte-addressable at its original path. Firefox stores
# paths relative to its configuration root, so preserve every nested component.
if ! ACTIVE_RELATIVE=$(python3 - "$FIREFOX_CONFIG" "$ACTIVE_PROFILE" <<'ACTIVE_RELATIVE_PYEOF'
import os
import sys

root, profile = map(os.path.realpath, sys.argv[1:])
try:
    if os.path.commonpath((root, profile)) != root:
        raise SystemExit("active profile is outside the Firefox root")
except ValueError as exc:
    raise SystemExit("active profile and Firefox root have incompatible paths") from exc
relative = os.path.relpath(profile, root)
if relative in {"", ".", ".."} or relative.startswith(f"..{os.sep}"):
    raise SystemExit("active profile has no safe relative registration path")
print(relative)
ACTIVE_RELATIVE_PYEOF
); then
    log "FATAL: active profile registration path is unsafe"
    exit 1
fi
log "profile-data preservation active — no orphan directory mutation"

# Reconcile profiles.ini without deleting unrelated registrations.
if [[ -L "$PROFILES_INI" ]] || \
   { [[ -e "$PROFILES_INI" ]] && [[ ! -f "$PROFILES_INI" ]]; }; then
    log "FATAL: profiles.ini is non-regular or symlinked"
    exit 1
fi
if ! python3 - "$PROFILES_INI" "$FIREFOX_CONFIG" "$ACTIVE_RELATIVE" <<'PROFILE_RECONCILE_PYEOF'
import configparser
import os
import stat
import sys
import tempfile

ini_path, config_dir, active_relative = sys.argv[1], sys.argv[2], sys.argv[3]

cp = configparser.ConfigParser(strict=False, interpolation=None)
cp.optionxform = str  # preserve key case
cp.read(ini_path)

profile_sections = [s for s in cp.sections() if s.startswith("Profile")]
active_section = None

for sec in list(profile_sections):
    path = cp.get(sec, "Path", fallback="")
    is_relative = cp.get(sec, "IsRelative", fallback="1") != "0"
    full_path = os.path.join(config_dir, path) if is_relative else path
    full_path = os.path.normpath(full_path)
    if is_relative and os.path.normpath(path) == active_relative:
        active_section = sec
        continue

    # Remove only a proven Firefox-generated default registration whose path
    # is already absent. No directory is moved or deleted here. Custom names
    # and every existing profile remain registered, including absolute paths.
    leaf = os.path.basename(os.path.normpath(path))
    name = cp.get(sec, "Name", fallback="")
    generated_default = (
        name in {"default", "default-release"}
        and (leaf in {"default", "default-release"}
             or leaf.endswith(".default")
             or leaf.endswith(".default-release"))
    )
    if generated_default and not os.path.isdir(full_path):
        cp.remove_section(sec)

if active_section is None:
    used = {
        int(s[7:]) for s in cp.sections()
        if s.startswith("Profile") and s[7:].isdigit()
    }
    index = 0
    while index in used:
        index += 1
    active_section = f"Profile{index}"
    cp.add_section(active_section)

for sec in [s for s in cp.sections() if s.startswith("Profile")]:
    if sec != active_section:
        cp.remove_option(sec, "Default")
        if cp.get(sec, "Name", fallback="") == "default-release":
            raise SystemExit(
                f"conflicting non-orphan default-release registration: {sec}"
            )

cp.set(active_section, "Name", "default-release")
cp.set(active_section, "IsRelative", "1")
cp.set(active_section, "Path", active_relative)
cp.set(active_section, "Default", "1")

old_mode = stat.S_IMODE(os.stat(ini_path).st_mode) if os.path.exists(ini_path) else 0o600
fd, tmp_path = tempfile.mkstemp(prefix=".profiles.ini.", dir=config_dir, text=True)
try:
    with os.fdopen(fd, "w") as f:
        # Mozilla profiles.ini uses key=value without added spaces.
        cp.write(f, space_around_delimiters=False)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp_path, old_mode)
    os.replace(tmp_path, ini_path)
finally:
    if os.path.exists(tmp_path):
        os.unlink(tmp_path)

print(
    f"profiles.ini reconciled: {active_section} -> {active_relative}; "
    "unrelated registrations preserved"
)
PROFILE_RECONCILE_PYEOF
then
    log "FAIL: profiles.ini reconciliation failed"
    notify critical dialog-error "NoID Privacy Firefox Setup Error" \
        "profiles.ini could not be reconciled safely. No unrelated profile registration was deleted."
    exit 1
fi

# Post-rewrite hard-validation: locate the named launcher profile by section;
# the first [Profile*] entry may legitimately be an unrelated custom profile.
if ! PROFILE_CONTRACT=$(python3 - "$PROFILES_INI" "$ACTIVE_RELATIVE" <<'PROFILE_VALIDATE_PYEOF'
import configparser, sys
path, active_relative = sys.argv[1], sys.argv[2]
cp = configparser.ConfigParser(strict=False, interpolation=None)
cp.optionxform = str
with open(path, encoding="utf-8") as handle:
    cp.read_file(handle)
matches = [
    section for section in cp.sections()
    if section.startswith("Profile")
    and cp.get(section, "Name", fallback="") == "default-release"
]
if len(matches) != 1:
    raise SystemExit(f"expected one default-release registration, found {len(matches)}")
section = matches[0]
actual_path = cp.get(section, "Path", fallback="")
is_relative = cp.get(section, "IsRelative", fallback="")
is_default = cp.get(section, "Default", fallback="")
if (actual_path, is_relative, is_default) != (active_relative, "1", "1"):
    raise SystemExit(
        f"{section}: Path={actual_path!r}, IsRelative={is_relative!r}, "
        f"Default={is_default!r}"
    )
print(f"{section}: Name=default-release, Path={actual_path}, Default=1")
PROFILE_VALIDATE_PYEOF
); then
    log "FAIL: profiles.ini validation failed"
    log "      launcher 'firefox -P default-release' would not resolve to active profile"
    notify critical dialog-error "NoID Privacy Firefox Setup Error" \
        "profiles.ini validation failed. Setup aborted without changing profile data."
    exit 1
fi
log "profiles.ini validated: $PROFILE_CONTRACT"

log "registration reconciliation complete; profile directories untouched"

# ---------------------------------------------------------------------------
# Install the reviewed configuration and extension without mutating user data
# ---------------------------------------------------------------------------
if ! install_supported_userjs; then
    log "FATAL: atomic user.js install failed"
    exit 1
fi
log "installed supported user.js state → $ACTIVE_PROFILE/user.js"

# xulstore.json is user-owned window state. Seed it only when absent, using a
# non-replacing hard-link publication so a concurrent creator is preserved.
# Established window geometry is never overwritten.
XULSTORE="$ACTIVE_PROFILE/xulstore.json"
if [[ -e "$XULSTORE" ]] || [[ -L "$XULSTORE" ]]; then
    if [[ ! -f "$XULSTORE" ]] || [[ -L "$XULSTORE" ]]; then
        log "FATAL: xulstore.json is non-regular or symlinked"
        exit 1
    fi
    log "preserved existing xulstore.json byte-for-byte"
else
    XULSTORE_TMP=$(mktemp "$ACTIVE_PROFILE/.xulstore.json.tmp.XXXXXXXX")
    printf '%s\n' '{"chrome://browser/content/browser.xhtml":{"main-window":{"sizemode":"maximized","screenX":"0","screenY":"0","width":"1366","height":"768"}}}' > "$XULSTORE_TMP"
    chmod 600 "$XULSTORE_TMP"
    sync -- "$XULSTORE_TMP"
    if ln -- "$XULSTORE_TMP" "$XULSTORE"; then
        rm -f -- "$XULSTORE_TMP"
        sync -- "$ACTIVE_PROFILE"
        log "seeded xulstore.json for a previously uninitialized profile"
    else
        rm -f -- "$XULSTORE_TMP"
        if [[ -f "$XULSTORE" ]] && [[ ! -L "$XULSTORE" ]]; then
            log "preserved concurrently created xulstore.json"
        else
            log "FATAL: could not safely seed xulstore.json"
            exit 1
        fi
    fi
fi

# Install uBlock Origin XPI profile-local using the verified mechanism.
# Mozilla's
# distribution-bundled auto-install does NOT register the XPI in
# extensions.json under FF150 — extensions.json stayed empty across
# all tested launch modes. Profile-local copy + extensions.autoDisableScopes=10
# (Profile bit 1 NOT in the disable-list) is
# the verified working path.
#
# When the user clicks Firefox next, ExtensionManager scans
# profile/extensions/ at full-init startup, registers uBO (Profile-scope
# = bit 1, NOT in autoDisableScopes=10 disable mask), and PB permission
# is already granted via extension-preferences.json.
EXTENSIONS_DIR_PROFILE="$ACTIVE_PROFILE/extensions"
if [[ -L "$EXTENSIONS_DIR_PROFILE" ]] || \
   { [[ -e "$EXTENSIONS_DIR_PROFILE" ]] && [[ ! -d "$EXTENSIONS_DIR_PROFILE" ]]; }; then
    log "FATAL: profile extensions path is non-directory or symlinked"
    exit 1
fi
install -d -m 700 "$EXTENSIONS_DIR_PROFILE"
UBO_TARGET="$EXTENSIONS_DIR_PROFILE/uBlock0@raymondhill.net.xpi"
if [[ -L "$UBO_TARGET" ]]; then
    log "FATAL: profile uBO XPI is symlinked"
    exit 1
fi
if [[ -f "$UBO_TARGET" ]]; then
    # Seed-once contract: an existing profile XPI is user-owned state
    # (M25's user-triggered signed add-on updates land at this exact path).
    # Preserve only a structurally valid, correctly identified, Mozilla-signed
    # payload; never bless an arbitrary pre-positioned file as setup-complete.
    if ! "$WEBEXT_VALIDATOR" "$UBO_TARGET" uBlock0@raymondhill.net \
            - 1 - >/dev/null; then
        log "FATAL: existing profile uBO XPI fails identity/signature validation"
        exit 1
    fi
    log "preserved existing validated uBO XPI → $UBO_TARGET"
elif ! atomic_install "$UBO_XPI" "$UBO_TARGET" 644; then
    log "FATAL: atomic uBlock Origin install failed"
    exit 1
else
    log "installed reviewed uBO XPI → $UBO_TARGET"
fi
if ! "$WEBEXT_VALIDATOR" "$UBO_TARGET" uBlock0@raymondhill.net \
        - 1 - >/dev/null; then
    log "FATAL: installed profile uBO XPI fails final validation"
    exit 1
fi

# Fresh accounts already receive the empty initial bookmark backup from
# /etc/skel before Firefox starts; M26 excludes the Fedora bookmark package
# and the system fallback is empty. An established profile's places/favicons
# databases and every bookmark backup are user data: this automatic refresh
# never touches them.
log "preserved places, favicons, bookmark backups, and all other profile data"

EXT_PREFS="$ACTIVE_PROFILE/extension-preferences.json"
if [[ -L "$EXT_PREFS" ]] || { [[ -e "$EXT_PREFS" ]] && [[ ! -f "$EXT_PREFS" ]]; }; then
    log "FATAL: extension-preferences.json is non-regular or symlinked"
    exit 1
fi
if ! python3 - "$EXT_PREFS" <<'PYEOF'
import json, os, stat, sys, tempfile
path = sys.argv[1]
if os.path.exists(path):
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"refusing to overwrite invalid {path}: {exc}", file=sys.stderr)
        sys.exit(1)
else:
    d = {}
if not isinstance(d, dict):
    print(f"refusing to overwrite non-object JSON in {path}", file=sys.stderr)
    sys.exit(1)
d["uBlock0@raymondhill.net"] = {
    "permissions": ["internal:privateBrowsingAllowed"],
    "origins": [],
    "data_collection": []
}
parent = os.path.dirname(path)
fd, temporary = tempfile.mkstemp(prefix=".extension-preferences.json.tmp.", dir=parent)
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)
    directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PYEOF
then
    log "FATAL: extension-preferences.json could not be updated atomically"
    exit 1
fi
log "extension-preferences.json → uBlock0 PB-allowed (grants private-window access)"

# Publish success only after every required postcondition is true. The state
# binds the exact profile and both reviewed inputs, so drift triggers a safe
# recheck instead of a blind skip.
if ! required_outputs_valid; then
    log "FATAL: required setup postcondition failed; success state not written"
    exit 1
fi

STATE_TMP=$(mktemp "$STATE_DIR/.firefox-setup.done.tmp.XXXXXXXX")
expected_state > "$STATE_TMP"
chmod 600 "$STATE_TMP"
sync -- "$STATE_TMP"
mv -fT -- "$STATE_TMP" "$STATE_FILE"
sync -- "$STATE_DIR"

# Notification consolidation:
# and DDG is already the default anyway): notification
# moved out of M16. M34 (firefox-playground) runs immediately after M16
# during first-login autostart and sends ONE combined notification
# covering both profiles. DDG hint removed because DuckDuckGo is already
# the default search engine (set via the search-only policies.json,
# Step 5c) — the "switch to DDG" tip was misleading.
#
# Orphan-stamp removal.
# A prior version attempted to create /var/lib/noid-privacy/firefox-default-
# release.ready as a "stamp file" supposedly read by M34. Reality check:
#   1. M34 source (973 LOC) has ZERO references to this path. It uses
#      its own stamp /var/lib/noid-privacy/stamp-34-firefox-playground.ok
#      for health-checking, not the M16-suspected stamp.
#   2. M16→M34 sequencing happens via direct chaining at script-end
#      (line ~2080 invokes /usr/local/bin/noid-firefox-playground-init.sh
#      synchronously to enforce this ordering).
#   3. The creation itself was broken: setup-script runs as user, but
#      /var/lib/noid-privacy is root:root 700 at first-boot timing →
#      mkdir + touch fail silently due to `|| true`.
# A prior stamp-based handoff only implemented the M16
# side; M34 implementation never landed. Removed as dead code.

log "setup complete"

# Profile-local work is complete. Release the shared lock before chaining the
# independent playground transaction, which acquires the same lock itself.
flock -u 9
exec 9>&-

# Do not clean up arbitrary user Firefox
# processes here. Earlier builds used broad pkill/pkill -f cleanup to remove
# headless-launch leftovers before chaining playground-init. That was unsafe:
# if the user opened Firefox during first-login setup, the visible browser
# could be terminated. The setup path already kills/waits its own $FF_PID, and
# Module 34 no longer defers on arbitrary Firefox subprocesses.

# Chain to playground-init for deterministic
# sequencing. Both XDG autostart hooks (firefox-setup + firefox-playground-init)
# fire in PARALLEL at GNOME login. Chaining from setup-script end guarantees:
# setup-script done → marker written → firefox cleanup → THEN playground-init.
if [[ -x /usr/local/bin/noid-firefox-playground-init.sh ]]; then
    log "chaining to noid-firefox-playground-init.sh (sequential, no race)"
    /usr/local/bin/noid-firefox-playground-init.sh || \
        log "WARN: playground-init returned non-zero (non-fatal)"
fi

exit 0
SETUPSCRIPT_EOF
chmod 755 "$LOCAL_BIN_DIR/noid-firefox-setup.sh"
chown root:root "$LOCAL_BIN_DIR/noid-firefox-setup.sh"
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$LOCAL_BIN_DIR/noid-firefox-setup.sh" 2>/dev/null || true
fi

cat > "$XDG_AUTOSTART_DIR/noid-firefox-setup.desktop" <<'AUTOSTART_EOF'
[Desktop Entry]
Type=Application
Name=NoID Privacy Firefox Setup
Comment=First-run Firefox hardening setup (NoID Privacy Firefox Hardening v1.0 + uBlock Origin)
Exec=/usr/local/bin/noid-firefox-setup.sh
NoDisplay=true
Terminal=false
X-GNOME-Autostart-enabled=true
# NOTE: X-GNOME-Autostart-Phase REMOVED.
# GNOME 49+ (Fedora 44 ships GNOME 50) rejects .desktop files that use
# this key and logs an error in journalctl. gnome-session no longer
# manages session services via this key — only user-level app autostart
# via XDG. Removing the key reverts to the default "Application" phase,
# which is handled by the generic XDG autostart mechanism (fires after
# login + shell-ready).
AUTOSTART_EOF
chmod 644 "$XDG_AUTOSTART_DIR/noid-firefox-setup.desktop"

log "  Installed setup script + autostart entry"

#------------------------------------------------------------------------------
# Step 6b: Install /usr/local/bin/noid-firefox-relax-fpp escape-hatch
#------------------------------------------------------------------------------
# Some sites break under FPP Canvas/WebGL randomization or font restriction.
# Rather than teaching users to manually edit user.js, ship a
# script that creates a per-profile relaxation overlay. Preserves DNS choice,
# HTTPS-Only, Nimbus block, AI block, Mozilla VPN block, password manager
# block — ONLY relaxes the fingerprinting protection layer.

log "Step 6b/8: Install noid-firefox-relax-fpp escape-hatch"

cat > /usr/local/bin/noid-firefox-relax-fpp <<'RELAX_FPP_EOF'
#!/bin/bash
# noid-firefox-relax-fpp — relax Firefox Fingerprinting Protection for compat.
#
# Firefox does NOT load arbitrary *.js files from a profile — only
# `prefs.js` (engine-managed) and `user.js` (user overrides). This script
# patches user.js itself with markers so the prefs ARE loaded; --restore
# removes only that exact block and preserves every unrelated user line.
#
# Markers:
#   // NOID-RELAX-FPP-BEGIN — start of relaxation block
#   // NOID-RELAX-FPP-END   — end of relaxation block
#
# Profile discovery: registered profiles only (parsed from profiles.ini
# via the shared helper) — never scans non-profile dirs (Crash Reports,
# Pending Pings, Profile Groups, firefox-mpris).
#
# Usage:
#   noid-firefox-relax-fpp           # relax all registered profiles
#   noid-firefox-relax-fpp --restore # remove only the exact marked block
#   noid-firefox-relax-fpp --help

set -euo pipefail

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — Firefox FPP" \
    NOID_FMT_AUTO_SUBTITLE="Per-profile compatibility override" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

# Source shared profile helper.
if [ -r /usr/local/lib/noid-privacy/firefox-profiles.sh ]; then
    . /usr/local/lib/noid-privacy/firefox-profiles.sh
else
    echo "ERROR: missing /usr/local/lib/noid-privacy/firefox-profiles.sh" >&2
    echo "       Module 16 install may be incomplete." >&2
    exit 2
fi

MARK_BEGIN="$NOID_FF_RELAX_FPP_BEGIN"
MARK_END="$NOID_FF_RELAX_FPP_END"

if [ "$(id -u)" -eq 0 ]; then
    echo "Run as your normal user (not root) — Firefox profiles live in your home." >&2
    echo "If you ran this via sudo, retry without sudo:" >&2
    echo "  noid-firefox-relax-fpp" >&2
    exit 1
fi

if [ "$#" -gt 1 ]; then
    echo "ERROR: expected zero arguments or one action (try --help)" >&2
    exit 2
fi
ACTION="${1:-apply}"

case "$ACTION" in
    --help|-h)
        cat <<HELP
noid-firefox-relax-fpp — relax Firefox fingerprinting protection for site
compatibility. Keeps the DNS policy, HTTPS-Only, password manager disabled, telemetry
off, Mozilla AI off, uBlock Origin active.

Patches user.js in each registered Firefox profile with a marked block.
Close Firefox before running. Restart Firefox to apply.

Usage:
  noid-firefox-relax-fpp           # apply relaxation
  noid-firefox-relax-fpp --restore # remove only the exact marked block
HELP
        exit 0
        ;;
    --restore|restore)
        ACTION_MODE=restore
        ;;
    apply|"")
        ACTION_MODE=apply
        ;;
    *)
        echo "Unknown action: $ACTION (try --help)" >&2
        exit 1
        ;;
esac

if ! acquire_firefox_profile_lock; then
    echo "Another Firefox profile operation is active; retry later." >&2
    exit 75
fi

if firefox_process_active; then
    echo "Firefox is running. Close all Firefox windows and retry." >&2
    exit 1
fi

FF_ROOT="$(firefox_root)"
if [ ! -d "$FF_ROOT" ]; then
    echo "No Firefox config dir found at $FF_ROOT." >&2
    echo "Start Firefox once to create a profile, then retry." >&2
    exit 1
fi

# Iterate REGISTERED and path-validated profiles only.
if ! PROFILE_RECORDS=$(list_registered_profiles); then
    echo "Firefox profiles.ini failed the safe record contract." >&2
    exit 1
fi
COUNT=0
FAILED=0
while IFS=$'\t' read -r name _; do
    [ -n "$name" ] || continue
    pdir=$(profile_dir_for "$name") || continue
    [ -d "$pdir" ] || continue
    if [ ! -f "$pdir/user.js" ] || [ -L "$pdir/user.js" ]; then
        echo "ERROR: $name has no safe regular user.js" >&2
        FAILED=$((FAILED + 1))
        continue
    fi

    if ! validate_noid_marker_pair "$pdir/user.js" "$MARK_BEGIN" "$MARK_END"; then
        echo "ERROR: $name has missing/duplicate/reversed FPP markers; file preserved" >&2
        FAILED=$((FAILED + 1))
        continue
    fi

    case "$ACTION_MODE" in
        apply)
            tmpf=$(mktemp "$pdir/.user.js.relax-fpp.XXXXXXXX")
            if ! compose_userjs_relaxation_choice \
                    "$pdir/user.js" enabled preserve > "$tmpf" || \
               ! backup=$(backup_noid_userjs "$pdir/user.js") || \
               ! noid_atomic_install_file "$tmpf" "$pdir/user.js" 600 || \
               ! validate_noid_marker_pair "$pdir/user.js" "$MARK_BEGIN" "$MARK_END" || \
               ! validate_noid_marker_pair "$pdir/user.js" \
                    "$NOID_FF_RELAX_WEBRTC_BEGIN" "$NOID_FF_RELAX_WEBRTC_END"; then
                rm -f -- "$tmpf"
                echo "ERROR: atomic FPP update failed for $name" >&2
                FAILED=$((FAILED + 1))
                continue
            fi
            rm -f -- "$tmpf"
            echo "Relaxed: $name → $pdir/user.js (backup: $(basename "$backup"))"
            COUNT=$((COUNT + 1))
            ;;
        restore)
            if ! grep -Fxq -- "$MARK_BEGIN" "$pdir/user.js"; then
                echo "Already restored: $name (no FPP block)"
                COUNT=$((COUNT + 1))
                continue
            fi
            tmpf=$(mktemp "$pdir/.user.js.restore-fpp.XXXXXXXX")
            if ! compose_userjs_relaxation_choice \
                    "$pdir/user.js" disabled preserve > "$tmpf" || \
               ! backup=$(backup_noid_userjs "$pdir/user.js") || \
               ! noid_atomic_install_file "$tmpf" "$pdir/user.js" 600 || \
               ! validate_noid_marker_pair "$pdir/user.js" "$MARK_BEGIN" "$MARK_END" || \
               ! validate_noid_marker_pair "$pdir/user.js" \
                    "$NOID_FF_RELAX_WEBRTC_BEGIN" "$NOID_FF_RELAX_WEBRTC_END"; then
                rm -f -- "$tmpf"
                echo "ERROR: atomic FPP restore failed for $name" >&2
                FAILED=$((FAILED + 1))
                continue
            fi
            rm -f -- "$tmpf"
            echo "Restored: $name → preserved unrelated user.js lines (backup: $(basename "$backup"))"
            COUNT=$((COUNT + 1))
            ;;
    esac
done <<< "$PROFILE_RECORDS"

if [ "$FAILED" -gt 0 ]; then
    echo "Failed safely for $FAILED profile(s); affected files were preserved." >&2
    exit 1
fi

if [ "$COUNT" -eq 0 ]; then
    case "$ACTION_MODE" in
        apply)   echo "No registered Firefox profile found. Nothing to relax." >&2 ;;
        restore) echo "No registered Firefox profile found. Nothing to restore." >&2 ;;
    esac
    exit 1
fi

echo ""
case "$ACTION_MODE" in
    apply)
        echo "Done. Relaxed $COUNT profile(s)."
        echo "Restart Firefox for change to apply."
        echo ""
        echo "To restore full fingerprinting protection:"
        echo "  noid-firefox-relax-fpp --restore"
        ;;
    restore)
        echo "Done. Removed the exact FPP block from $COUNT profile(s); unrelated lines preserved."
        echo "Restart Firefox for change to apply."
        ;;
esac
RELAX_FPP_EOF

chmod 755 /usr/local/bin/noid-firefox-relax-fpp
chown root:root /usr/local/bin/noid-firefox-relax-fpp
log "  Installed /usr/local/bin/noid-firefox-relax-fpp (755)"

#------------------------------------------------------------------------------
# Step 6b2: Install /usr/local/bin/noid-firefox-relax-webrtc escape-hatch
#------------------------------------------------------------------------------
# WebRTC ships OFF (media.peerconnection.enabled=false), so Firefox does not
# generate ICE/STUN candidates. That also breaks browser-based video calls
# (Meet / Jitsi / Discord-web). Rather than teaching users to edit user.js,
# ship a script that re-enables WebRTC per-profile while keeping the ICE
# candidate-reduction prefs (proxy-only / default-route-only) active. Those
# prefs are useful defense in depth, not a guarantee across split routes,
# proxies or VPN configurations. --restore reverts to the canonical
# WebRTC-off state. Mirrors noid-firefox-relax-fpp.

log "Step 6b2/8: Install noid-firefox-relax-webrtc escape-hatch"

cat > /usr/local/bin/noid-firefox-relax-webrtc <<'RELAX_WEBRTC_EOF'
#!/bin/bash
# noid-firefox-relax-webrtc — re-enable Firefox WebRTC for video calls.
#
# Firefox does NOT load arbitrary *.js files from a profile — only
# `prefs.js` (engine-managed) and `user.js` (user overrides). This script
# patches user.js itself with markers so the pref IS loaded; --restore removes
# only that exact block, preserving every unrelated user line and exposing the
# earlier canonical WebRTC-off preference again.
#
# Markers:
#   // NOID-RELAX-WEBRTC-BEGIN — start of relaxation block
#   // NOID-RELAX-WEBRTC-END   — end of relaxation block
#
# Profile discovery: registered profiles only (parsed from profiles.ini
# via the shared helper) — never scans non-profile dirs.
#
# Usage:
#   noid-firefox-relax-webrtc           # enable WebRTC in all registered profiles
#   noid-firefox-relax-webrtc --restore # remove only the exact marked block
#   noid-firefox-relax-webrtc --help

set -euo pipefail

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — Firefox WebRTC" \
    NOID_FMT_AUTO_SUBTITLE="Per-profile leak trade-off" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

# Source shared profile helper.
if [ -r /usr/local/lib/noid-privacy/firefox-profiles.sh ]; then
    . /usr/local/lib/noid-privacy/firefox-profiles.sh
else
    echo "ERROR: missing /usr/local/lib/noid-privacy/firefox-profiles.sh" >&2
    echo "       Module 16 install may be incomplete." >&2
    exit 2
fi

MARK_BEGIN="$NOID_FF_RELAX_WEBRTC_BEGIN"
MARK_END="$NOID_FF_RELAX_WEBRTC_END"

if [ "$(id -u)" -eq 0 ]; then
    echo "Run as your normal user (not root) — Firefox profiles live in your home." >&2
    echo "If you ran this via sudo, retry without sudo:" >&2
    echo "  noid-firefox-relax-webrtc" >&2
    exit 1
fi

if [ "$#" -gt 1 ]; then
    echo "ERROR: expected zero arguments or one action (try --help)" >&2
    exit 2
fi
ACTION="${1:-apply}"

case "$ACTION" in
    --help|-h)
        cat <<HELP
noid-firefox-relax-webrtc — re-enable Firefox WebRTC for browser video calls
(Meet / Jitsi / Discord-web). Keeps DNS policy, HTTPS-Only, password manager disabled,
telemetry off, Mozilla AI off, FPP + uBlock Origin active. The ICE privacy
prefs (proxy-only when a proxy is configured and default-route-only candidate
selection) stay on. They reduce candidate exposure but cannot guarantee that a
local or non-VPN address is hidden under every split-route, proxy or VPN setup.
Use the WebRTC-off default when address disclosure must be prevented.

Patches user.js in each registered Firefox profile with a marked block.
Close Firefox before running. Restart Firefox to apply.

Usage:
  noid-firefox-relax-webrtc           # enable WebRTC
  noid-firefox-relax-webrtc --restore # remove only the exact marked block
HELP
        exit 0
        ;;
    --restore|restore)
        ACTION_MODE=restore
        ;;
    apply|"")
        ACTION_MODE=apply
        ;;
    *)
        echo "Unknown action: $ACTION (try --help)" >&2
        exit 1
        ;;
esac

if ! acquire_firefox_profile_lock; then
    echo "Another Firefox profile operation is active; retry later." >&2
    exit 75
fi

if firefox_process_active; then
    echo "Firefox is running. Close all Firefox windows and retry." >&2
    exit 1
fi

FF_ROOT="$(firefox_root)"
if [ ! -d "$FF_ROOT" ]; then
    echo "No Firefox config dir found at $FF_ROOT." >&2
    echo "Start Firefox once to create a profile, then retry." >&2
    exit 1
fi

# Iterate REGISTERED and path-validated profiles only.
if ! PROFILE_RECORDS=$(list_registered_profiles); then
    echo "Firefox profiles.ini failed the safe record contract." >&2
    exit 1
fi
COUNT=0
FAILED=0
while IFS=$'\t' read -r name _; do
    [ -n "$name" ] || continue
    pdir=$(profile_dir_for "$name") || continue
    [ -d "$pdir" ] || continue
    if [ ! -f "$pdir/user.js" ] || [ -L "$pdir/user.js" ]; then
        echo "ERROR: $name has no safe regular user.js" >&2
        FAILED=$((FAILED + 1))
        continue
    fi

    if ! validate_noid_marker_pair "$pdir/user.js" "$MARK_BEGIN" "$MARK_END"; then
        echo "ERROR: $name has missing/duplicate/reversed WebRTC markers; file preserved" >&2
        FAILED=$((FAILED + 1))
        continue
    fi

    case "$ACTION_MODE" in
        apply)
            tmpf=$(mktemp "$pdir/.user.js.relax-webrtc.XXXXXXXX")
            if ! compose_userjs_relaxation_choice \
                    "$pdir/user.js" preserve enabled > "$tmpf" || \
               ! backup=$(backup_noid_userjs "$pdir/user.js") || \
               ! noid_atomic_install_file "$tmpf" "$pdir/user.js" 600 || \
               ! validate_noid_marker_pair "$pdir/user.js" "$MARK_BEGIN" "$MARK_END" || \
               ! validate_noid_marker_pair "$pdir/user.js" \
                    "$NOID_FF_RELAX_FPP_BEGIN" "$NOID_FF_RELAX_FPP_END"; then
                rm -f -- "$tmpf"
                echo "ERROR: atomic WebRTC update failed for $name" >&2
                FAILED=$((FAILED + 1))
                continue
            fi
            rm -f -- "$tmpf"
            echo "WebRTC enabled: $name → $pdir/user.js (backup: $(basename "$backup"))"
            COUNT=$((COUNT + 1))
            ;;
        restore)
            if ! grep -Fxq -- "$MARK_BEGIN" "$pdir/user.js"; then
                echo "Already restored: $name (no WebRTC block)"
                COUNT=$((COUNT + 1))
                continue
            fi
            tmpf=$(mktemp "$pdir/.user.js.restore-webrtc.XXXXXXXX")
            if ! compose_userjs_relaxation_choice \
                    "$pdir/user.js" preserve disabled > "$tmpf" || \
               ! backup=$(backup_noid_userjs "$pdir/user.js") || \
               ! noid_atomic_install_file "$tmpf" "$pdir/user.js" 600 || \
               ! validate_noid_marker_pair "$pdir/user.js" "$MARK_BEGIN" "$MARK_END" || \
               ! validate_noid_marker_pair "$pdir/user.js" \
                    "$NOID_FF_RELAX_FPP_BEGIN" "$NOID_FF_RELAX_FPP_END"; then
                rm -f -- "$tmpf"
                echo "ERROR: atomic WebRTC restore failed for $name" >&2
                FAILED=$((FAILED + 1))
                continue
            fi
            rm -f -- "$tmpf"
            echo "Restored WebRTC-off: $name → preserved unrelated user.js lines (backup: $(basename "$backup"))"
            COUNT=$((COUNT + 1))
            ;;
    esac
done <<< "$PROFILE_RECORDS"

if [ "$FAILED" -gt 0 ]; then
    echo "Failed safely for $FAILED profile(s); affected files were preserved." >&2
    exit 1
fi

if [ "$COUNT" -eq 0 ]; then
    case "$ACTION_MODE" in
        apply)   echo "No registered Firefox profile found. Nothing to change." >&2 ;;
        restore) echo "No registered Firefox profile found. Nothing to restore." >&2 ;;
    esac
    exit 1
fi

echo ""
case "$ACTION_MODE" in
    apply)
        echo "Done. WebRTC enabled in $COUNT profile(s)."
        echo "Restart Firefox for change to apply."
        echo ""
        echo "To restore WebRTC-off (privacy default):"
        echo "  noid-firefox-relax-webrtc --restore"
        ;;
    restore)
        echo "Done. Removed the exact WebRTC block from $COUNT profile(s); unrelated lines preserved."
        echo "Restart Firefox for change to apply."
        ;;
esac
RELAX_WEBRTC_EOF

chmod 755 /usr/local/bin/noid-firefox-relax-webrtc
chown root:root /usr/local/bin/noid-firefox-relax-webrtc
log "  Installed /usr/local/bin/noid-firefox-relax-webrtc (755)"

#------------------------------------------------------------------------------
# Step 6b3: explicit Firefox DRM/Widevine consent helper
#------------------------------------------------------------------------------
log "Step 6b3/8: Install noid-firefox-drm consent helper"

cat > /usr/local/bin/noid-firefox-drm <<'FIREFOX_DRM_EOF'
#!/bin/bash
# Explicit, profile-local opt-in/out for proprietary Widevine and its network
# updater. The versioned sentinel makes the choice survive the supported
# Update-All user.js re-application path.
set -euo pipefail

FMT_LIB=/usr/local/lib/noid-privacy/agent-install-format.sh
# shellcheck source=/dev/null
if [ -r "$FMT_LIB" ]; then . "$FMT_LIB"; else
    fmt_banner(){ echo "== $1 =="; [ -n "${2:-}" ] && echo "   $2"; }
    fmt_step(){ echo "[$1/$2] $3"; }; fmt_ok(){ echo "  OK: $1"; }
    fmt_info(){ echo "  - $1"; }; fmt_warn(){ echo "  ! $1" >&2; }
    fmt_err(){ echo "  ERROR: $1" >&2; }; fmt_note(){ echo "$1"; }
    fmt_done(){ echo "$1"; }
fi
fail() { fmt_err "$*"; exit 1; }

usage() {
    cat <<'USAGE_EOF'
Usage: noid-firefox-drm {enable|disable|status} [profile-name]

Without a profile, status/disable target "default-release"; enable is the
interactive two-profile consent flow described below. Close Firefox before
enable/disable.
Enabling permits Firefox to contact Mozilla/Google update infrastructure and
download Google's proprietary Widevine CDM. Disabling prevents future GMP
checks after restart; Firefox also removes installed Widevine when EME is off.

An interactive `enable` without a profile asks separately for default-release
and Firefox Playground before changing either profile. Both answers default to
No. Non-interactive callers must name the intended profile explicitly.
USAGE_EOF
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || { usage >&2; exit 2; }
action=$1
profile_name=${2:-default-release}
case "$action" in enable|disable|status) ;; *) usage >&2; exit 2 ;; esac

if [ ! -r /usr/local/lib/noid-privacy/firefox-profiles.sh ]; then
    fail "Firefox profile helper is missing"
fi
# shellcheck source=/dev/null
. /usr/local/lib/noid-privacy/firefox-profiles.sh
noid_require_desktop_user || fail "Run as the desktop user, not root."

answer_is_yes() {
    case "$1" in
        [yY]|[yY][eE][sS]|[jJ]|[jJ][aA]) return 0 ;;
        *) return 1 ;;
    esac
}

# The Setup entry point intentionally omits a profile. Collect both independent
# consents before invoking either profile-local transaction, so default-release
# is never enabled merely by opening the helper. Automation has no terminal in
# which to obtain consent and must use an explicit profile argument.
if [ "$action" = enable ] && [ "$#" -eq 1 ]; then
    [ -t 0 ] || {
        fail "Interactive profile consent requires a terminal. Name default-release or playground explicitly."
    }
    fmt_banner "NoID Privacy — Firefox DRM" "independent profile-local Widevine consent"
    fmt_warn "Enabling permits Mozilla/Google network access and a proprietary Widevine download."
    fmt_note "Each profile stays DRM-free unless you answer Yes for that profile."
    default_selected=0
    playground_selected=0
    read -r -p "Enable DRM for Firefox default-release? [y/N] " answer || answer=
    if answer_is_yes "$answer"; then
        default_selected=1
    fi
    read -r -p "Enable DRM for Firefox Playground? [y/N] " answer || answer=
    if answer_is_yes "$answer"; then
        playground_selected=1
    fi

    if [ "$default_selected" -eq 0 ] && [ "$playground_selected" -eq 0 ]; then
        fmt_done "No Firefox profile changed; DRM remains disabled."
        exit 0
    fi
    # Validate every selected profile before the first write. The explicit
    # transactions repeat these fail-closed checks immediately before mutation.
    if [ "$default_selected" -eq 1 ]; then
        /usr/bin/bash "$0" status default-release >/dev/null || {
            fail "default-release is not in a supported DRM consent state; no profile changed."
        }
    fi
    if [ "$playground_selected" -eq 1 ]; then
        /usr/bin/bash "$0" status playground >/dev/null || {
            fail "Firefox Playground is not in a supported DRM consent state; no profile changed."
        }
    fi
    if firefox_process_active; then
        fail "Close Firefox before changing DRM state; no profile changed."
    fi
    if [ "$default_selected" -eq 1 ]; then
        fmt_info "Starting the approved default-release transaction."
        /usr/bin/bash "$0" enable default-release || {
            fail "default-release DRM opt-in failed; Playground was not changed."
        }
    fi
    if [ "$playground_selected" -eq 1 ]; then
        fmt_info "Starting the approved Firefox Playground transaction."
        /usr/bin/bash "$0" enable playground || {
            if [ "$default_selected" -eq 1 ]; then
                fail "Playground opt-in failed after default-release completed; default-release remains enabled."
            fi
            fail "Firefox Playground DRM opt-in failed; default-release was not changed."
        }
    fi
    fmt_done "Selected Firefox DRM opt-ins complete"
    exit 0
fi

fmt_banner "NoID Privacy — Firefox DRM" "profile-local Widevine consent"
fmt_info "Action: $action"
fmt_info "Target profile: $profile_name"
if [ "$profile_name" = default-release ]; then
    fmt_note "This run targets only default-release; Firefox Playground is unchanged."
    fmt_note "Manual Playground opt-in: noid-firefox-drm enable playground"
else
    fmt_note "This run targets only '$profile_name'; default-release is unchanged."
fi
if [ "$action" = status ]; then
    fmt_step 1 1 "Validate profile and read consent state"
else
    fmt_step 1 2 "Validate target profile and consent state"
fi

pdir=$(profile_dir_for "$profile_name") || {
    fail "Registered profile not found or unsafe: $profile_name"
}
userjs="$pdir/user.js"
sentinel="$pdir/$NOID_FF_DRM_SENTINEL_BASENAME"
mark_begin='// NOID-DRM-OPT-IN-BEGIN'
mark_end='// NOID-DRM-OPT-IN-END'
[ -f "$userjs" ] && [ ! -L "$userjs" ] && \
    grep -q 'NoID Privacy Workstation' "$userjs" || {
        fail "Profile is not safely NoID Privacy-hardened: $profile_name"
    }
[ -f "$NOID_FF_USERJS_DRM_OVERRIDES" ] && \
    [ ! -L "$NOID_FF_USERJS_DRM_OVERRIDES" ] || {
        fail "Reviewed DRM overlay is missing."
    }
validate_noid_marker_pair "$NOID_FF_USERJS_DRM_OVERRIDES" \
    "$mark_begin" "$mark_end" || {
        fail "Reviewed DRM overlay markers are invalid."
    }
validate_noid_marker_pair "$userjs" "$mark_begin" "$mark_end" || {
    fail "Profile DRM marker state is malformed; no change made."
}
drm_state=$(profile_drm_opt_in_state "$pdir") || {
    fail "Profile DRM consent sentinel is malformed; no change made."
}
has_block=0
grep -Fxq -- "$mark_begin" "$userjs" && has_block=1

# Sentinel and marker are one consent record. Never infer intent or silently
# repair only half of it; all actions require one of the two exact states.
if { [ "$drm_state" = enabled ] && [ "$has_block" -ne 1 ]; } || \
   { [ "$drm_state" = disabled ] && [ "$has_block" -ne 0 ]; }; then
    fail "DRM consent sentinel and user.js disagree; no change made."
fi
fmt_ok "Profile registration and consent record are consistent"

if [ "$action" = status ]; then
    if [ "$drm_state" = enabled ] && [ "$has_block" -eq 1 ]; then
        fmt_done "DRM enabled for profile: $profile_name"
        exit 0
    fi
    if [ "$drm_state" = disabled ] && [ "$has_block" -eq 0 ]; then
        fmt_done "DRM disabled for profile: $profile_name"
        exit 0
    fi
    fail "Unreachable DRM consent state."
fi

if firefox_process_active; then
    fail "Close Firefox before changing DRM state."
fi
acquire_firefox_profile_lock || {
    fmt_err "Another Firefox profile operation is active."
    exit 75
}

# Exact already-requested states are read-only successes. Do this after taking
# the shared lock so another profile transaction cannot change the consent
# record between validation and return.
if [ "$action" = enable ] && [ "$drm_state" = enabled ] && [ "$has_block" -eq 1 ]; then
    fmt_info "DRM was already enabled for profile: $profile_name"
    fmt_done "Firefox DRM opt-in is active"
    exit 0
fi
if [ "$action" = disable ] && [ "$drm_state" = disabled ] && [ "$has_block" -eq 0 ]; then
    fmt_info "DRM was already disabled for profile: $profile_name"
    fmt_done "Firefox DRM privacy default is active"
    exit 0
fi

temporary=$(mktemp "$pdir/.user.js.drm.XXXXXXXX") || exit 1
trap 'rm -f -- "$temporary" "${sentinel_tmp:-}"' EXIT
backup=$(backup_noid_userjs "$userjs") || exit 1
rollback_userjs_or_fail() {
    local context=$1
    if noid_atomic_install_file "$backup" "$userjs" 600; then
        return 0
    fi
    fmt_err "CRITICAL: $context and the automatic user.js rollback also failed."
    fmt_err "Consent state may be inconsistent; recover from retained backup: $backup"
    return 1
}

case "$action" in
    enable)
        fmt_step 2 2 "Enable EME and Widevine updates for $profile_name"
        if [ "$drm_state" = disabled ] && [ "$has_block" -eq 1 ]; then
            fail "user.js contains DRM opt-in without the consent sentinel."
        fi
        if [ "$has_block" -eq 0 ]; then
            cat -- "$userjs" "$NOID_FF_USERJS_DRM_OVERRIDES" > "$temporary"
            noid_atomic_install_file "$temporary" "$userjs" 600 || exit 1
        fi
        if [ "$drm_state" = disabled ]; then
            sentinel_tmp=$(mktemp "$pdir/.noid-drm-enabled.XXXXXXXX") || {
                rollback_userjs_or_fail "DRM sentinel staging failed" || exit 1
                exit 1
            }
            printf '%s\n' 'NOID_FIREFOX_DRM_OPT_IN_V1' > "$sentinel_tmp"
            chmod 600 "$sentinel_tmp"
            if ! noid_atomic_install_file "$sentinel_tmp" "$sentinel" 600; then
                rollback_userjs_or_fail "DRM sentinel publication failed" || exit 1
                exit 1
            fi
        fi
        fmt_ok "Consent record enabled for profile: $profile_name"
        fmt_info "Backup: $(basename "$backup")"
        fmt_info "Restart Firefox; Widevine may now download from Mozilla/Google."
        fmt_done "Firefox DRM opt-in complete"
        ;;
    disable)
        fmt_step 2 2 "Restore the DRM-off privacy default for $profile_name"
        [ "$drm_state" = enabled ] && [ "$has_block" -eq 1 ] || {
            fail "Inconsistent DRM state; no change made."
        }
        awk -v begin="$mark_begin" -v end="$mark_end" '
            $0 == begin { skip=1; next }
            $0 == end { skip=0; next }
            !skip { print }
            END { if (skip) exit 1 }
        ' "$userjs" > "$temporary"
        noid_atomic_install_file "$temporary" "$userjs" 600 || exit 1
        if ! rm -f -- "$sentinel"; then
            rollback_userjs_or_fail "DRM sentinel removal failed" || exit 1
            exit 1
        fi
        fmt_ok "Consent record disabled for profile: $profile_name"
        fmt_info "Backup: $(basename "$backup")"
        fmt_info "Restart Firefox; future GMP/Widevine checks are blocked."
        fmt_done "Firefox DRM privacy default restored"
        ;;
esac

# Remove this action's scratch files and release the cross-helper profile lock
# before returning to a coordinator or another profile operation.
rm -f -- "$temporary" "${sentinel_tmp:-}"
trap - EXIT
exec {NOID_FF_PROFILE_LOCK_FD}>&-
FIREFOX_DRM_EOF

chmod 755 /usr/local/bin/noid-firefox-drm
chown root:root /usr/local/bin/noid-firefox-drm
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/local/bin/noid-firefox-drm 2>/dev/null || true
fi
log "  Installed /usr/local/bin/noid-firefox-drm (755)"

#------------------------------------------------------------------------------
# Step 6c: Install /usr/share/doc/noid-privacy/16-firefox-hardening.md
#------------------------------------------------------------------------------
# User-facing doc for Module 16 (Firefox hardening overview + FPP escape-hatch).
# Matches the pattern used by other Modules (15 Intel ME, 18 Flatpak, 19 NVIDIA,
# 20 Rollback, 21 Kernel Modules, 22 LUKS, 24 fwupd, ssh-server-opt-in).
log "Step 6c/8: Install /usr/share/doc/noid-privacy/16-firefox-hardening.md"

mkdir -p /usr/share/doc/noid-privacy

cat > /usr/share/doc/noid-privacy/16-firefox-hardening.md <<'FIREFOX_DOC_EOF'
# Firefox Hardening (Module 16)

The NoID Privacy Workstation image ships Firefox with two layers of pre-configured
protection: **NoID Privacy Firefox Hardening v1.0** (derived from arkenfox v144.0, MIT;
hundreds of consolidated user_pref directives in a single file, including NoID Privacy
image-scope overrides: provider-compatible DNS, FPP, Mozilla AI block, Nimbus clear, PPA + LNA, etc.;
Firefox 153's native QWAC verification/display remains enabled on desktop because
`@IS_NOT_ANDROID@` resolves to true there and false on Android), and
**uBlock Origin** (reviewed pinned release as first-install seed) pre-configured
via Managed Storage Manifest. After that seed, the extension is yours: the image
never downgrades your profile copy. The privacy defaults disable automatic
add-on update checks (no background executable-extension refresh). The current
Mozilla-signed stable release is fetched only when you explicitly start
`noid-update-all.sh`; the workflow verifies the fixed upstream repository,
GitHub asset digest, archive identity/version/compatibility, Firefox's native
signature state and the no-downgrade postcondition, then records SHA-256
evidence. The same run enumerates every profile-owned extension in every
registered Firefox profile and advances all additional AMO extensions through
AMO's compatibility-filtered official API with the same native signature,
atomic-publication and evidence gates. Filter-list content continues to refresh
inside uBO; that content feed is separate from executable XPI updates.

### Defaults versus user-owned choices

The profile `user.js` continues to enforce the privacy/security baseline.
Settings whose own contract permits a later user choice are deliberately absent
from that file and supplied only as AutoConfig `defaultPref()` values:
startup/homepage, Firefox Home content, private-search selection, Sync
Passwords/Open Tabs, AI Controls, Firefox IP Protection, GPC, the ETP
convenience allowlist, hardware video decoding, WebRender and smooth scrolling.
A value stored by Firefox in `prefs.js` after the user changes a visible control
or an advanced `about:config` feature gate therefore wins across restarts and
Update All. Weather, wallpaper and Mozilla IP Protection have upstream rollout
or system gates, so their normal UI may be absent until those related gates are
also enabled. This does not turn off any NoID Privacy default; it prevents the
default layer from masquerading as a lock.

## What's active out of the box

### Privacy / Telemetry
- Mozilla telemetry, Studies, Normandy, crash reports → **off** (arkenfox)
- Mozilla's four Firefox 153 Messaging System providers → **off**. This keeps
  onboarding, CFR, message-group and messaging-experiment work silent and avoids
  ASRouter querying an intentionally uninitialized telemetry session at launch.
  Unified base telemetry remains off rather than being enabled as a workaround.
- Firefox generative AI Controls → **blocked**, including Firefox-provided AI
  for extensions. The former NoID Privacy catch-all `browser.ml.enable=false` override
  is deliberately absent: Firefox's native AI Controls do not reverse it,
  and Mozilla documents that the panel does not govern traditional ML. Remote
  suggestions, personalization and telemetry remain disabled separately.
- Mozilla VPN "IP Protection" (`browser.ipProtection.enabled`) → **off**
- Nimbus A/B experiments → profile cleared, UUIDs rotate on every start
- Captcha detection telemetry → **off**
- Firefox Sync pre-configured: **no** (user opt-in, passwords + tabs excluded when enabled)

### Network / DNS
- **System/VPN DNS by default** (`network.trr.mode=5`, user-overridable)
- Direct WAN uses NoID Privacy's strict authenticated global/physical Quad9
  DoT; an active VPN/private `~.` DNS scope takes precedence
- IPv6 answers remain usable inside a VPN tunnel; the NoID Privacy system
  boundary, rather than Firefox, blocks unqualified physical-WAN IPv6
- **WebRTC disabled** (`media.peerconnection.enabled=false`) — prevents Firefox
  from generating WebRTC ICE/STUN candidates.
  Browser video calls (Meet / Jitsi / Discord-web) break with WebRTC off. If you
  need them, run `noid-firefox-relax-webrtc` (close Firefox first, then restart) —
  its ICE candidate-reduction prefs stay on, but they are not an IP-leak
  guarantee for every split-route, proxy or VPN configuration.
  `noid-firefox-relax-webrtc --restore` puts WebRTC back off.
- Encrypted Client Hello (ECH) on (DNS + HTTP/3)
- HTTPS-Only Mode **on**

### Cookies / Sessions
- Total Cookie Protection (isolated per-domain cookie jars)
- Bounce Tracking Protection on
- Cookies persist across restarts (login comfort — `clearOnShutdown_v2.cookiesAndStorage=false`)

### Passwords / Autofill
- Password manager **off** (external manager / airgap strategy)
- Payment autofill **off**
- Address autofill **off**
- Form-history autocomplete **off** (Firefox does not store and re-suggest
  previously entered form values)

### Fingerprinting Protection (FPP)
- **FPP active** rather than RFP; letterboxing stays off for UX
- `+AllTargets` with minus-excludes for breakage:
  - `-CSSPrefersColorScheme` (real dark/light theme)
  - `-JSDateTimeUTC` (real timezone)
  - `-RoundWindowSize` (real window size)
  - `-Navigator*` (real browser identity — Linux counterproductive to spoof)
  - `-KeyboardEvents` (real layout)
  - `-SiteSpecificZoom` (site zoom allowed)
  - `-JSLocalePrompt`, `-JSLocale` (real web-content language — see below)
- **Canvas + WebGL randomization ACTIVE**
- Font-visibility reduction follows Firefox's current FPP platform support;
  coverage is not identical on every Linux/font configuration
- Remote FPP overrides **off** (Mozilla cannot relax FPP via remote)
- FPP targets `JSLocalePrompt` and `JSLocale` → **excluded**: web-content
  language follows the system locale (`Accept-Language`, `navigator.language`,
  `Intl`). Under `+AllTargets` `JSLocalePrompt` arms Firefox's RFP "request
  English versions" machinery, which permanently rewrites
  `intl.accept_languages` to `en-US, en` the moment `privacy.spoof_english`
  becomes 2, while the shipped `user.js` silently resets that switch to 1
  afterwards; `JSLocale` is the separate JS-locale spoof. An already affected
  profile shows English on sites such as Amazon despite a German UI, gets
  offers to translate German pages into English and can hit locale redirect
  loops (Disney+). Fix it once: `about:config` → `intl.accept_languages` →
  reset, or Settings → Language → web-content languages

### Certificates
- CRLite mode 2 (Firefox 142+ production on-device revocation checking)
- OCSP hard-fail **off**; this does not disable Firefox's maintained revocation
  flow, but avoids failing a connection solely because a fallback responder is
  unavailable
- TLS 0-RTT **off**, Safe Negotiation enforced, Cert Pinning strict

### Safe Browsing
- Local phishing, malware, blocked-URI and download-list protection stays
  enabled, including Mozilla's maintained list-update mechanism
- The separate full per-download application-reputation request is **off**.
  This avoids submitting executable-file metadata such as name, origin, size
  and hash to the reputation service, but gives up its additional server-side
  verdicts for uncommon or potentially unwanted downloads. That is an explicit
  privacy-versus-security trade-off, not a claim of equivalent coverage

### Extensions
- **uBlock Origin** (shipped via `/usr/lib64/mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/` + a managed-storage manifest)
- The current `toOverwrite.filterLists` schema enforces uBO's upstream default
  core plus three narrow additions: URL-tracking protection, phishing defence
  and outsider-to-LAN request blocking. Broad regional, cookie-notice and
  annoyance bundles are not forced: upstream warns that adding more lists
  increases breakage, and a locale-neutral image must not enable unrelated
  language lists for every user
- uBO retains its own supported defaults for startup snapshots, automatic
  filter-content updates and Firefox launch-time request suspension; NoID Privacy
  does not pin an experimental advanced setting or create an early
  request bypass
- Only the selected filter-list set is administrator-managed and re-applied at
  uBO launch. Trusted sites, dynamic/URL rules, My filters and other UI choices
  remain user-owned. The baseline is global rather than country-specific:
  manually selected regional/extra lists and uBO's locale-selected additions
  do not persist while `toOverwrite.filterLists` is active. This avoids forcing
  every language list on every user, but users who prioritize regional rules
  can opt the whole system out after closing Firefox:
  `sudo rm -f /usr/lib64/mozilla/managed-storage/uBlock0@raymondhill.net.json`.
  Restore the exact reviewed baseline with
  `sudo install -o root -g root -m 0644 /usr/share/noid-firefox/uBlock0@raymondhill.net.json /usr/lib64/mozilla/managed-storage/uBlock0@raymondhill.net.json`.
  The opt-out relinquishes the three NoID Privacy-enforced additions and lets uBO own
  default/locale/manual list selection; executable XPI updates remain the
  separate, explicit Update All path

### New Tab Page Cleanup
- Sponsored content and Pocket Stories → **off**
- Eight curated Top Sites remain visible with embedded local monogram icons.
  The global page-thumbnail kill-switch covers shipped, user-added, pinned and
  history-derived tiles alike, so Firefox cannot pre-load their pages for a
  screenshot before a click. User-added tiles may still reuse favicons already
  collected during a normal visit or Firefox's local Top-Sites icon catalog
- Weather (classic + Nova/widget feeds), unsolicited country lookup and
  AccuWeather/Merino traffic → **off**
- Remote wallpaper feed and `newtab-wallpapers-v2` attachments → **off**
- Urlbar weather suggestions → **off**
- Highlights, CFR (Contextual Feature Recommendations) → **off**
- New Tab telemetry → **off**

### Address Bar Suggestions (Firefox Suggest)
- Firefox Suggest in the address bar → **off**: sponsored results (adMarketplace),
  Wikipedia, add-on, MDN, Yelp, stock-market and important-date suggestions are
  all gated off (`browser.urlbar.quicksuggest.enabled`,
  `browser.urlbar.suggest.quicksuggest.all`, `browser.urlbar.suggest.quicksuggest.sponsored`
  and the per-feature `featureGate` prefs). Firefox 156 switches these on by
  region and locale (Germany, France, Italy; US/UK earlier) on the default pref
  branch at every start. The profile `user.js` keeps the user-branch value off,
  and because the unsolicited country lookup is disabled the home region stays
  unset, so the regional default never flips. Nimbus rollouts and Normandy are
  off, so no remote experiment can re-enable it either

### DRM / Widevine
- Encrypted Media Extensions and Widevine → **off** on a pristine profile
- GMP metadata checks → **off**, including Firefox's browser-idle update task
- Opt in only after closing Firefox with `noid-firefox-drm enable`. It asks
  independently for `default-release` and Firefox Playground before changing
  either profile; both answers default to No.
- Non-interactive callers must explicitly name one target profile, for example
  `noid-firefox-drm enable default-release`.
- Without a profile, `status` and `disable` target `default-release`; inspect
  or disable Playground separately with `noid-firefox-drm status playground`
  or `noid-firefox-drm disable playground`. The versioned profile consent
  survives the supported Update-All hardening re-application.
- Enabling permits Firefox to contact Mozilla/Google infrastructure and install
  Google's proprietary Widevine CDM; that privacy/provenance cost is explicit

### Sidebar
- AI Chat (`sidebar.main.tools`) **removed** — keeps synced tabs + history + bookmarks

## Escape-hatch: `noid-firefox-relax-fpp`

Some sites break under FPP Canvas/WebGL randomization or font restriction:
- Online image editors (Canva, Photopea, Figma image-work) — randomized canvas export
- WebGL configurators (car/furniture 3D viewers, online games) — distorted textures
- Sites that use browser fingerprint for DRM validation
- Draw/3D tools that read back Canvas/WebGL pixels

### Usage

```bash
# Close Firefox first (script will check), then:
noid-firefox-relax-fpp              # apply: disable FPP in all detected profiles
noid-firefox-relax-fpp --restore    # undo: remove only the exact marked block
noid-firefox-relax-fpp --help
```

### How it works

The script patches each registered Firefox profile's `user.js` with a marked
block at the end of the file:

```
// NOID-RELAX-FPP-BEGIN
// Created by noid-firefox-relax-fpp. Remove with:
//   noid-firefox-relax-fpp --restore
// This ONLY relaxes fingerprinting protection. DNS policy, HTTPS-Only, password
// manager off, Mozilla AI off, Nimbus off, telemetry off — all stay active.
user_pref("privacy.fingerprintingProtection", false);
user_pref("privacy.fingerprintingProtection.pbmode", false);
user_pref("privacy.resistFingerprinting", false);
// NOID-RELAX-FPP-END
```

Because Firefox processes `user.js` top-to-bottom and last-write-wins, the
marked block overrides the three FPP prefs that the canonical NoID Privacy `user.js`
sets earlier.

> **Why marked-block-in-user.js, not a separate overlay file**:
> Firefox does NOT load arbitrary `*.js` files from a profile's
> root — only `prefs.js` (engine-managed) and `user.js` (user overrides).
> A previous version of this script wrote a separate `noid-relax-fpp.js`
> next to `user.js`, which Firefox silently ignored. The script reported
> success but FPP stayed active. Patching `user.js` itself with a marked
> block makes the relaxation actually take effect. `--restore` strips only
> that validated block, preserving all unrelated profile-owned lines.

### What stays active after applying the relaxation

**Only FPP is relaxed** — every other layer remains intact:

- System/VPN DNS default, HTTPS-Only Mode, ECH
- WebRTC remains off (no WebRTC ICE/STUN candidate generation)
- Password manager off, form autofill off
- uBlock Origin + the managed filter-list baseline
- Telemetry off, Mozilla AI off, Nimbus off, IP Protection off
- Total Cookie Protection, Bounce Tracking Protection
- CRLite mode 2, cert pinning strict
- Captcha detection telemetry off

### Restore full protection

```bash
noid-firefox-relax-fpp --restore
```

Strips the `// NOID-RELAX-FPP-BEGIN ... // NOID-RELAX-FPP-END` block from
each registered profile's `user.js` after requiring exactly zero or one
correctly ordered marker pair. It retains a collision-safe backup, publishes
the rewrite atomically and preserves every line outside the block. Restart
Firefox — the earlier canonical FPP preference is active again.

### Safety

- **User-mode** (runs without sudo — profiles live in `$HOME`)
- **Iterates registered profiles only** via the shared helper
  (`list_registered_profiles` parses `profiles.ini`) — never scans
  non-profile dirs like `Crash Reports`, `Pending Pings`, `Profile
  Groups`, `firefox-mpris`
- **Refuses to run while Firefox is open** (pgrep check)
- **Idempotent**: reapplying the no-argument command first strips any existing
  marked block before appending a fresh one
- **Update-stable**: `noid-update-all.sh` preserves only byte-exact supported
  FPP/WebRTC compatibility blocks while refreshing the canonical base
- **`--restore` is complete rollback** in a single command: it strips only
  the validated marker block and preserves every unrelated `user.js` line
  (playground overrides included)

## Profile creation

NoID Privacy seeds and registers the active profile under the maintained
`~/.config/mozilla/firefox/` XDG path. Mozilla Bug 2003137 tracks an upstream
edge case where a stray, otherwise empty `~/.mozilla/firefox/` can shadow that
valid XDG registry. The owned launcher therefore resolves registered profiles through
the path-bounded shared helper and invokes Firefox with its documented
`--profile <path>` selector. Explicit profile-manager, profile-creation and
external-path requests retain Firefox's own semantics. The image ships
`/usr/share/noid-firefox/user.js` (the canonical consolidated NoID Privacy
Firefox Hardening base), which is copied into the default profile by the
first-run setup script (XDG autostart). An explicit DRM opt-in adds only the
reviewed root-owned consent overlay. Mozilla AutoConfig also applies the base
prefs as global `defaultPref()` values before any profile starts.

Closed tabs remain available to Firefox's normal Undo Closed Tab action during
the current run. They are not carried into the next browser run by default:
this avoids retaining old page state indefinitely and avoids parsing that
unneeded state on the next startup. The setting is a user-overridable
`defaultPref`, not a lock; changing
`browser.sessionstore.persist_closed_tabs_between_sessions` in `about:config`
survives restarts. NoID Privacy deliberately does not set
`browser.sessionstore.max_tabs_undo=0`, so Ctrl+Shift+T remains available
during the current run.

Upstream references: [Mozilla Bug 2003137](https://bugzilla.mozilla.org/show_bug.cgi?id=2003137)
and the documented Firefox [`--profile <path>` command-line selector](https://firefox-source-docs.mozilla.org/browser/CommandLineParameters.html).

### Multiple profiles (about:profiles / `firefox -P`)

The first-run setup script writes profile-local state for **exactly one
profile** — the default (profiles.ini `Default=1` entry or `default-release`
dir). If you later create additional profiles via `about:profiles` or
`firefox -P`, they inherit AutoConfig defaults immediately. A user-started
`noid-update-all.sh` then initializes every safely registered profile whose
`user.js` is absent, unless the exact explicit exclusion below exists. The
helper applies the same state immediately without waiting for an update.

**What a new profile still has** (global mechanisms, profile-independent):

- NoID Privacy Firefox prefs via Mozilla AutoConfig `defaultPref()`
- uBO managed-storage configuration is system-present but remains inert until
  the helper installs the profile-local extension
- Firefox's internal sandbox (Fission + seccomp + namespaces)
- Wayland session isolation

**What a new profile is MISSING** (profile-local files in `<profile>/`):

- NoID Privacy Firefox Hardening `user.js` v1.0 (single consolidated file, derived
  from arkenfox v144.0, MIT; its profile-enforced set includes WebRTC off,
  provider-compatible DNS, FPP,
  telemetry off, Pocket off, Normandy off, remote per-download Safe Browsing
  reputation off while local-list protection and updates remain on, HTTPS-Only
  mode, Encrypted Client Hello, plus NoID Privacy-specific overrides +
  ETP-tighten — baked in at image build)
- exact reviewed uBlock Origin XPI copied into `<profile>/extensions/`
- `extension-preferences.json` entry granting uBO access to private windows

**Result before the next Update All or an explicit helper run**: a new profile
still receives NoID Privacy's global hardened defaults, but temporarily lacks
the canonical profile-local `user.js`, uBO XPI and Private-Browsing grant.

### Harden a new profile

Use the bundled CLI helper:

```bash
# list all profiles + hardening status
noid-firefox-harden-profile

# harden a specific profile (matches by short name, e.g. "work" matches
# "<random-id>.work" profile directory)
noid-firefox-harden-profile work

# harden all safely repairable profiles; existing noncanonical user.js is skipped
noid-firefox-harden-profile --all

# keep one new/unhardened profile outside automatic enrollment
noid-firefox-harden-profile --exclude dev

# after review: replace user.js and reset FPP/WebRTC compatibility opt-ins
noid-firefox-harden-profile --force work
```

After running, **restart Firefox** to activate NoID Privacy Firefox Hardening
and the profile-local uBlock Origin extension in the hardened profile.
Subsequent `noid-update-all.sh` runs also initialize new safely registered
profiles with no `user.js`, then rebuild the canonical base plus any reviewed
DRM consent and byte-exact FPP/WebRTC compatibility opt-ins for all profiles
managed by NoID Privacy. Unsupported manual lines in a managed `user.js` are
not an update-stable customization surface; use the documented helpers for
supported exceptions.

### Intentionally-unhardened profiles

Some users keep a "dev" or "test" profile without NoID Privacy hardening for
DevTools access or WebExtension testing that FPP would break. Before the next
Update All, run `noid-firefox-harden-profile --exclude <profile-name>`. This
publishes one private, exact profile-local exclusion marker; `--all` and Update
All leave the profile untouched. A later named
`noid-firefox-harden-profile <profile-name>` is the explicit opt-in and removes
the marker after the full postcondition succeeds.

An existing foreign, stale or manually modified `user.js` is also never
overwritten implicitly; Update All reports and skips it. `--force` explicitly
replaces that file and resets the supported FPP/WebRTC compatibility opt-ins to
the secure defaults. `--exclude` does not remove an already applied hardening
state; use the documented removal workflow first if that is the intent.

## Updates

- **NoID Privacy Firefox Hardening**: `noid-update-all.sh` (Module 25) Step 5
  initializes every safely registered new profile with no `user.js` unless it
  carries the explicit exclusion, and rebuilds every profile managed
  by NoID Privacy from `/usr/share/noid-firefox/user.js`, retaining only the exact
  reviewed DRM consent and FPP/WebRTC compatibility opt-ins (no external
  fetch, no arkenfox dependency — post-absorption)
- **uBlock Origin**: `noid-update-all.sh` updates every hardened profile from
  the current Mozilla-signed stable upstream XPI; Firefox background add-on
  checks remain disabled
- **Other profile extensions**: `noid-update-all.sh` updates every AMO extension
  in every registered profile through the compatibility-filtered official API;
  built-in/system add-ons remain owned by the Firefox RPM transaction
- **Firefox itself**: updates via `dnf upgrade` (system package, not Mozilla's
  auto-updater)

## Troubleshooting

### Site says "Canvas check failed" / "WebGL renderer check failed"
→ `noid-firefox-relax-fpp` (temporary) + restart Firefox. After work,
`noid-firefox-relax-fpp --restore` + restart.

### Site says "Cookies disabled" / login doesn't persist

First use uBlock Origin's Logger and reload the page to determine whether a
network filter actually blocked a required request. Cosmetic-filtering
controls only hide page elements and cannot repair a blocked network request.
For diagnosis, Ctrl-click uBO's large power button to trust only the current
page; a normal click persists a whole-site Trusted-sites exception and exposes
that site to all traffic uBO would otherwise block. Prefer a narrow exception
filter or report a faulty list rule once the Logger identifies it.

"Block Outsider Intrusion into LAN" deliberately stops public pages from
reaching loopback or private-network services. If a trusted web application
really must reach a local device, review that exact destination before adding
a narrow uBO exception; do not disable the LAN list merely to fix an unrelated
login problem.

### Site embeds (Disqus comments / YouTube / Twitter / Codepen) don't load

NoID Privacy disables Mozilla's "convenience" ETP allowlist by default (`privacy.trackingprotection.allow_list.convenience.enabled=false`).
Rationale: defense-in-depth (uBlock Origin's filter lists already block most
convenience-trackers) + privacy-distro positioning (don't trust Mozilla's
curated allowlist with tracker exceptions).

If a specific embed fails AND uBO doesn't block it for separate privacy
reasons, two ways to re-enable:

**Per-site (preferred — minimal exposure):**
- Settings → Privacy & Security → Enhanced Tracking Protection
- "Manage Exceptions" → add the site

**Globally (if many sites affected):**
- about:config → search `privacy.trackingprotection.allow_list.convenience.enabled`
- toggle to `true`

The pref ships as `defaultPref` (NOT `lockPref`) — your override sticks across
restarts. Other tightening (uBO filter lists, FPP, DNS policy) remains active.

Mozilla's allowlist URL: https://etp-exceptions.mozilla.org/ (curated by Mozilla)

### Video playback breaks (DRM error)
→ DRM is intentionally off until explicit consent. Close Firefox, run:

```bash
noid-firefox-drm enable              # asks independently for both shipped profiles
noid-firefox-drm enable default-release
noid-firefox-drm enable playground
noid-firefox-drm enable work         # any other named registered profile
noid-firefox-drm status
noid-firefox-drm status playground
```

Without an explicit profile, the interactive helper asks separate `[y/N]`
questions for `default-release` and Firefox Playground before changing either
profile; both answers default to No. A non-interactive `enable` must name
exactly one registered profile. Restart Firefox afterward. The helper enables
EME and the GMP/Widevine updater together, so Firefox may contact
Mozilla/Google and download the proprietary CDM. To return to the
no-metadata/no-CDM default, close Firefox and run `noid-firefox-drm disable`
for `default-release`, plus `noid-firefox-drm disable playground` if that
profile was enabled, then restart.

### Firefox Sync wanted
→ about:preferences#sync → sign in with Mozilla account. Tabs + Passwords are
set to NOT sync by default — flip via about:preferences#sync → "Choose what
to sync" if you want them.

### Secure DNS, VPN DNS and slow first lookups

Firefox defaults to the operating-system resolver (`network.trr.mode=5`).
This lets `systemd-resolved` use an active VPN/private `~.` DNS scope; without
one, NoID Privacy's global Quad9 resolver is used. Direct-WAN Quad9 uses
strict authenticated DoT and fails closed when TLS is unavailable. The
explicit VPN/captive-portal compatibility mode permits DNS/53 fallback.

Firefox's country lookup remains disabled. A narrow
`doh-rollout.home-region=global` default initializes only the built-in Secure
DNS provider catalogue, so the chooser remains available without discovering
or publishing a location. It does not activate DoH or preselect a provider.

The setting is deliberately a user-overridable AutoConfig `defaultPref` and
is absent from the profile `user.js`. A choice made under Settings → Privacy
& Security → DNS over HTTPS therefore survives browser restarts and Update
All. Enabling browser Secure DNS creates a separate resolver path: that may be
desirable for fail-closed encrypted DNS on direct WAN, but it bypasses the DNS
selection and filtering of an active desktop VPN. Proton VPN and Mullvad both
recommend Secure DNS off while their desktop VPN is active.

For a slow first lookup, compare the effective paths:

```bash
resolvectl query example.com
curl -sS -o /dev/null -w 'dns=%{time_namelookup} total=%{time_total}\n' \
  https://example.com
```

Then inspect Firefox Settings → Privacy & Security → DNS over HTTPS. Do not
assume that a browser-selected provider and the active VPN resolver are the
same trust boundary.

## Spotify / other dedicated profiles

No dedicated media/Spotify profile is shipped. The complete image manages
`default-release` plus Firefox Playground; power users can create additional
registered profiles:

1. Create additional profile: Firefox → `about:profiles`
2. Run `noid-firefox-harden-profile <profile-name>` (installs NoID Privacy
   `user.js`, the reviewed uBO XPI and its private-window permission)

## References

- NoID Privacy Firefox Hardening (this project): `firefox/noid-firefox-hardening.js`
  in the NoID Privacy Workstation repository
- arkenfox user.js (upstream, our v1.0 basis): https://github.com/arkenfox/user.js
  (MIT license, attribution retained in user.js header — our hardening is
  derived from arkenfox v144.0)
- uBlock Origin: https://github.com/gorhill/uBlock
- uBlock Origin filter-list guidance:
  https://github.com/gorhill/uBlock/wiki/Dashboard:-Filter-lists
- uBlock Origin popup/trusted-site behavior:
  https://github.com/gorhill/uBlock/wiki/Quick-guide:-popup-user-interface
- Mozilla Firefox privacy guide: https://support.mozilla.org/en-US/products/firefox/privacy-and-security

## Hardware Video Acceleration (HW-decode)

Firefox uses its native Fedora/Mozilla GPU qualification. NoID Privacy does
not force `media.hardware-video-decoding.force-enabled` or
`gfx.webrender.all`: both settings override Firefox's blocklist rather than
normally enabling a supported device. Fedora Firefox enables qualified
Intel/AMD VA-API decoding by default, while Firefox retains its driver probe,
blocklist and failed-sanity-test fallback on every GPU.

### Codec drivers + per-GPU support

Codec drivers (Intel/AMD VA-API, OpenH264, full ffmpeg, AV1 via dav1d) are an
explicit user opt-in through `noid-complete-setup.sh` (or an explicit start of
`noid-firstboot-setup.service`). **Module 08 does not enable that service at first boot**:
Fedora's patent-stripped defaults remain in place until the user
chooses the RPM Fusion swap. See `noid-help 26-optional-packages`, section
"RPM Fusion codec stack", for the package and network/repository trade-off.

**NVIDIA**: NoID Privacy does not install a VA-driver package merely because an
NVIDIA PCI device exists. Nouveau video profiles depend on the GPU generation
and available firmware; it may use profiles exposed by Fedora Mesa, otherwise
Firefox falls back to software decode. The proprietary path also keeps software
decode by design — the unsupported NVDEC bridge would require disabling
Firefox's media-decoder sandbox (`MOZ_DISABLE_RDD_SANDBOX=1`, which Mozilla
calls a major security risk). Hybrid Intel/NVIDIA systems retain the Intel
VA-API backend. See Module 19 (`19-nvidia-drivers.md`).

**DRM streaming (Netflix / Prime / Disney+)**: hardware decode of DRM content
is not achievable on standard Linux — the Widevine CDM runs its own internal
software decoder and bypasses VA-API (Mozilla Bug 1700815, open since 2021).
Linux gets only Widevine L3 (software), so streaming services cap resolution
regardless of GPU. Not a NoID Privacy limitation; it affects every Linux browser.

### Native defaults — no user.js editing needed

Do not add force-enable preferences for normal operation. After the explicit
codec opt-in, Firefox can use a vendor-specific VA-API path that passes its
native qualification. NVIDIA uses only supported profiles exposed by the
selected driver (or an iGPU on a hybrid system) and otherwise falls back to
software decode. NoID Privacy never disables the RDD media sandbox to force an
unsupported proprietary-driver bridge.

### Rollback if video artifacts appear

If a qualified driver nevertheless shows artifacts, set
`media.hardware-video-decoding.enabled=false` in `about:config`, then restart
Firefox. The browser-owned value survives Update All and video falls back to
software decoding.

### Verification

Check if HW-decode is active:

1. Open `about:support` in Firefox
2. Scroll to **Graphics** section
3. Look for `HARDWARE_VIDEO_DECODING` row
4. Value `available by default` means the native supported path is active.
   `force enabled by user` indicates a local override and should be reset
   before diagnosing driver or playback failures.

Live monitoring while playing a video:

- Intel: `sudo intel_gpu_top` — watch Video bar above 0 %
- AMD: `radeontop` (overall GPU usage)
- NVIDIA: `nvidia-smi pmon` or `nvtop` — firefox process with `C` in Type column
FIREFOX_DOC_EOF

chmod 644 /usr/share/doc/noid-privacy/16-firefox-hardening.md
chown root:root /usr/share/doc/noid-privacy/16-firefox-hardening.md
log "  Installed /usr/share/doc/noid-privacy/16-firefox-hardening.md"

#------------------------------------------------------------------------------
# Step 6d: Install noid-firefox-harden-profile CLI helper
#------------------------------------------------------------------------------
# Profiles created later via about:profiles / `firefox -P` keep the global
# mechanisms (AutoConfig defaults, managed-storage, sandbox) but initially lack
# the profile-local user.js + validated uBO XPI + PB-permission grant. M25
# automatically initializes safely registered profiles with no user.js and
# re-applies managed profiles. A foreign user.js or this helper's exact
# `--exclude` marker preserves an explicit opt-out.
# Usage + exit codes in the HARDEN_EOF heredoc.

log "Step 6d/8: Install noid-firefox-harden-profile CLI helper"

cat > "$LOCAL_BIN_DIR/noid-firefox-harden-profile" <<'HARDEN_EOF'
#!/bin/bash
# noid-firefox-harden-profile — apply NoID Privacy Firefox user.js to Firefox profile(s)
#
# Ships the consolidated NoID Privacy Firefox Hardening user.js (derived from arkenfox
# v144.0, MIT) into Firefox profiles that the XDG-autostart
# first-run setup missed (typically: profiles created via about:profiles or
# `firefox -P` after first boot).
#
# Profile discovery via shared helper (registered profiles only — never
# `find -type d`, which would match non-profile dirs: Crash Reports,
# Pending Pings, Profile Groups, firefox-mpris). apply_userjs handles
# base + playground correctly. The helper then installs the exact reviewed
# uBO XPI profile-local and grants its Private-Browsing permission. The wider ExtensionSettings
# policies.json was removed because Firefox displayed "managed by
# your organization" on every profile; only Step 5c's search-only policy ships.
#
# Idempotent: a profile is complete only when its user.js, validated uBO identity and
# Private-Browsing permission all validate. Partial runs with an absent or exact
# supported user.js are repaired. Existing noncanonical user.js files are
# preserved unless --force explicitly replaces them.
#
# Usage:
#   noid-firefox-harden-profile                  List profiles + status
#   noid-firefox-harden-profile <name>           Harden a specific profile
#                                                (by exact Name from profiles.ini)
#   noid-firefox-harden-profile --all            Harden every registered
#                                                safely repairable profile
#   noid-firefox-harden-profile --exclude <name> Exclude an unhardened profile
#                                                from automatic enrollment
#   noid-firefox-harden-profile --force <name>   Overwrite existing user.js
#                                                and reset FPP/WebRTC opt-ins
#   noid-firefox-harden-profile --help           This help
#
# Exit codes:
#   0  success (or idempotent no-op)
#   1  invalid input, missing profile, or profile-specific hardening failure
#   2  shared helper, source bundle, or profile registry missing or invalid
#   75 another profile operation holds the lock / Firefox still running

set -uo pipefail

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — Firefox Hardening" \
    NOID_FMT_AUTO_SUBTITLE="Managed profile state" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

# Help is deliberately state-independent: it must not require the installed
# helper library, a Firefox profile, the source bundle, or an available lock.
case "${1:-}" in
    -h|--help|help)
        if [ "$#" -ne 1 ]; then
            echo "ERROR: surplus/conflicting arguments. Try --help." >&2
            exit 1
        fi
        sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
        exit 0
        ;;
esac

SOURCE_DIR=/usr/share/noid-firefox

# Source shared profile helper.
if [ -r /usr/local/lib/noid-privacy/firefox-profiles.sh ]; then
    . /usr/local/lib/noid-privacy/firefox-profiles.sh
else
    echo "ERROR: missing /usr/local/lib/noid-privacy/firefox-profiles.sh" >&2
    echo "       Module 16 install may be incomplete." >&2
    exit 2
fi

if [ "$(id -u)" -eq 0 ]; then
    echo "ERROR: run as the normal desktop user, never through sudo." >&2
    exit 1
fi

case "$#" in
    0|1) ;;
    2) [[ "$1" =~ ^--(force|exclude)$ ]] || {
           echo "ERROR: surplus/conflicting arguments. Try --help." >&2
           exit 1
       } ;;
    *) echo "ERROR: surplus/conflicting arguments. Try --help." >&2; exit 1 ;;
esac

READ_ONLY=0
case "${1:-}" in
    ""|list|--list) READ_ONLY=1 ;;
esac
if [ "$READ_ONLY" -eq 0 ]; then
    if ! acquire_firefox_profile_lock; then
        echo "ERROR: another Firefox profile operation is active; retry later." >&2
        exit 75
    fi
    if firefox_process_active; then
        echo "ERROR: close Firefox before changing profile files." >&2
        exit 75
    fi
fi

# --- Preflight --------------------------------------------------------------
if [ ! -f "$SOURCE_DIR/user.js" ] || [ -L "$SOURCE_DIR/user.js" ]; then
    echo "ERROR: source file $SOURCE_DIR/user.js missing." >&2
    echo "       The NoID Privacy Firefox bundle (Module 16) may be incomplete." >&2
    exit 2
fi
ubo_source_size=$(stat -c '%s' "$NOID_FF_UBO_XPI" 2>/dev/null || true)
ubo_source_size=${ubo_source_size:-0}
if [ ! -f "$NOID_FF_UBO_XPI" ] || [ -L "$NOID_FF_UBO_XPI" ] || \
   [ "$ubo_source_size" -ne "$NOID_FF_UBO_SIZE" ] || \
   [ "$(sha256sum "$NOID_FF_UBO_XPI" 2>/dev/null | awk '{print $1}')" != "$NOID_FF_UBO_SHA256" ]; then
    echo "ERROR: reviewed uBlock Origin XPI is missing or differs from its exact pin." >&2
    exit 2
fi

FIREFOX_CONFIG="$(firefox_root)"
if [ ! -d "$FIREFOX_CONFIG" ]; then
    echo "ERROR: $FIREFOX_CONFIG does not exist." >&2
    echo "       Launch Firefox once to create the default profile, then re-run." >&2
    exit 2
fi

# --- Profile discovery (registered only) ----------------------
HARDENED_NAMES=()
REPAIRABLE_NAMES=()
PROTECTED_NAMES=()
EXCLUDED_NAMES=()
HARDENED_PATHS=()
REPAIRABLE_PATHS=()
PROTECTED_PATHS=()
EXCLUDED_PATHS=()

if ! PROFILE_RECORDS=$(list_registered_profiles); then
    echo "ERROR: profiles.ini failed the safe path/ownership record contract." >&2
    exit 2
fi
while IFS=$'\t' read -r name _; do
    [ -n "$name" ] || continue
    pdir=$(profile_dir_for "$name") || continue
    [ -d "$pdir" ] || continue
    if profile_auto_hardening_excluded "$pdir"; then
        EXCLUDED_NAMES+=("$name")
        EXCLUDED_PATHS+=("$pdir")
    else
        exclusion_rc=$?
        if [ "$exclusion_rc" -ne 1 ]; then
            PROTECTED_NAMES+=("$name")
            PROTECTED_PATHS+=("$pdir")
        elif profile_hardening_complete "$name"; then
            HARDENED_NAMES+=("$name")
            HARDENED_PATHS+=("$pdir")
        elif { [ ! -e "$pdir/user.js" ] && [ ! -L "$pdir/user.js" ]; } || \
             profile_userjs_supported "$name" "$pdir"; then
            REPAIRABLE_NAMES+=("$name")
            REPAIRABLE_PATHS+=("$pdir")
        else
            PROTECTED_NAMES+=("$name")
            PROTECTED_PATHS+=("$pdir")
        fi
    fi
done <<< "$PROFILE_RECORDS"

# --- Harden function --------------------------------------------------------
# Uses apply_userjs from the helper which handles base vs playground correctly.
harden_profile() {
    local target_name="$1" reset_relaxations="${2:-0}" pdir apply_mode=preserve-supported
    pdir=$(profile_dir_for "$target_name") || {
        echo "ERROR: profile not registered: $target_name" >&2
        return 1
    }
    [ -d "$pdir" ] || {
        echo "ERROR: profile dir missing: $pdir" >&2
        return 1
    }
    [ -w "$pdir" ] || {
        echo "ERROR: profile dir not writable: $pdir" >&2
        return 1
    }
    if [ "$reset_relaxations" -eq 1 ]; then
        apply_mode=reset-relaxations
        echo "  [INFO] --force resets supported FPP/WebRTC compatibility opt-ins for $target_name"
    fi
    apply_userjs "$target_name" "$apply_mode" || {
        echo "ERROR: apply_userjs failed for $target_name" >&2
        return 1
    }
    repair_ubo_profile_local "$target_name" || {
        echo "ERROR: validated uBO profile-local repair failed for $target_name" >&2
        return 1
    }
    patch_ubo_pb_permission "$target_name" || {
        echo "ERROR: could not grant uBO Private-Browsing permission for $target_name" >&2
        return 1
    }
    profile_hardening_complete "$target_name" || {
        echo "ERROR: postcondition failed for $target_name" >&2
        return 1
    }
    clear_profile_auto_hardening_exclusion "$pdir" || {
        echo "ERROR: could not clear the automatic-hardening exclusion for $target_name" >&2
        return 1
    }
    echo "  [OK] hardened: $target_name → $pdir (user.js + validated uBO + private-window permission)"
    return 0
}

print_list() {
    echo "Firefox profiles at: $FIREFOX_CONFIG (registered in profiles.ini)"
    echo
    if [ "${#HARDENED_NAMES[@]}" -gt 0 ]; then
        echo "Already hardened (user.js + validated uBO + private-window permission):"
        for n in "${HARDENED_NAMES[@]}"; do echo "  [hardened]    $n"; done
    fi
    if [ "${#REPAIRABLE_NAMES[@]}" -gt 0 ]; then
        echo "Safely repairable (no user.js or exact supported composition):"
        for n in "${REPAIRABLE_NAMES[@]}"; do echo "  [repairable]  $n"; done
        echo
        echo "To harden safely repairable profiles:"
        echo "  noid-firefox-harden-profile <profile-name>"
        echo "  noid-firefox-harden-profile --all"
    fi
    if [ "${#PROTECTED_NAMES[@]}" -gt 0 ]; then
        echo "Protected from implicit overwrite (foreign/stale/modified user.js):"
        for n in "${PROTECTED_NAMES[@]}"; do echo "  [review]      $n"; done
        echo "  Review first; only an explicit --force replaces these files."
    fi
    if [ "${#EXCLUDED_NAMES[@]}" -gt 0 ]; then
        echo "Explicitly excluded from automatic hardening:"
        for n in "${EXCLUDED_NAMES[@]}"; do echo "  [excluded]    $n"; done
        echo "  Harden one by name to opt in and remove its exclusion."
    fi
    if [ "${#HARDENED_NAMES[@]}" -eq 0 ] && \
       [ "${#REPAIRABLE_NAMES[@]}" -eq 0 ] && \
       [ "${#PROTECTED_NAMES[@]}" -eq 0 ] && \
       [ "${#EXCLUDED_NAMES[@]}" -eq 0 ]; then
        echo "No registered Firefox profiles found. Launch Firefox once to create the default."
    fi
}

# --- Argument dispatch ------------------------------------------------------
FORCE=0
EXCLUDE=0
case "${1:-}" in
    ""|list|--list)
        print_list
        exit 0
        ;;
    --all)
        if [ "${#REPAIRABLE_NAMES[@]}" -eq 0 ]; then
            echo "No safely repairable Firefox profiles. Nothing changed."
            if [ "${#PROTECTED_NAMES[@]}" -gt 0 ]; then
                echo "Review protected profile(s) individually; --all never overwrites their user.js."
            fi
            if [ "${#EXCLUDED_NAMES[@]}" -gt 0 ]; then
                echo "Explicitly excluded profile(s) remain untouched."
            fi
            exit 0
        fi
        echo "Hardening ${#REPAIRABLE_NAMES[@]} safely repairable profile(s)..."
        failed=0
        for n in "${REPAIRABLE_NAMES[@]}"; do
            harden_profile "$n" || failed=$((failed + 1))
        done
        if [ "${#PROTECTED_NAMES[@]}" -gt 0 ]; then
            echo "Skipped ${#PROTECTED_NAMES[@]} protected profile(s) with noncanonical user.js."
        fi
        if [ "${#EXCLUDED_NAMES[@]}" -gt 0 ]; then
            echo "Skipped ${#EXCLUDED_NAMES[@]} explicitly excluded profile(s)."
        fi
        echo
        if [ "$failed" -gt 0 ]; then
            echo "DONE with $failed errors."
            exit 1
        else
            echo "DONE. Restart Firefox to activate NoID Privacy hardening in the hardened profile(s)."
            echo "Tip: next run of 'noid-update-all.sh' will keep them updated."
            exit 0
        fi
        ;;
    --force)
        FORCE=1
        shift
        NAME="${1:-}"
        if [ -z "$NAME" ]; then
            echo "ERROR: --force requires a profile name." >&2
            exit 1
        fi
        ;;
    --exclude)
        EXCLUDE=1
        shift
        NAME="${1:-}"
        if [ -z "$NAME" ]; then
            echo "ERROR: --exclude requires a profile name." >&2
            exit 1
        fi
        ;;
    --*)
        echo "ERROR: unknown flag '$1'. Try --help." >&2
        exit 1
        ;;
    *)
        NAME="$1"
        ;;
esac

# --- Single-profile harden path ---------------------------------------------
PROFILE_DIR=$(profile_dir_for "$NAME") || {
    echo "ERROR: profile '$NAME' not registered in profiles.ini." >&2
    echo
    print_list
    exit 1
}

if [ "$EXCLUDE" -eq 1 ]; then
    if profile_hardening_complete "$NAME" || \
       profile_userjs_noid_managed "$PROFILE_DIR"; then
        echo "ERROR: profile '$NAME' is already NoID Privacy-managed; --exclude does not remove hardening." >&2
        echo "       Use the documented removal workflow first if that is your intent." >&2
        exit 1
    fi
    publish_profile_auto_hardening_exclusion "$PROFILE_DIR" || {
        echo "ERROR: could not publish a safe automatic-hardening exclusion for '$NAME'." >&2
        exit 1
    }
    echo "Profile '$NAME' is excluded from automatic NoID Privacy hardening."
    echo "Run 'noid-firefox-harden-profile $NAME' to opt in explicitly."
    exit 0
fi

# Idempotent check (all three profile-local outputs valid)
if profile_hardening_complete "$NAME" && [ "$FORCE" -eq 0 ]; then
    echo "Profile '$NAME' already hardened (user.js + validated uBO + private-window permission)."
    echo "After review, --force replaces user.js and resets FPP/WebRTC opt-ins:"
    echo "  noid-firefox-harden-profile --force $NAME"
    exit 0
fi

if [ "$FORCE" -eq 0 ] && \
   { [ -e "$PROFILE_DIR/user.js" ] || [ -L "$PROFILE_DIR/user.js" ]; } && \
   ! profile_userjs_supported "$NAME" "$PROFILE_DIR"; then
    echo "ERROR: profile '$NAME' has a foreign, stale or manually modified user.js." >&2
    echo "       It was preserved. Review it before an explicit --force replacement." >&2
    exit 1
fi

echo "Hardening profile: $NAME → $PROFILE_DIR"
harden_profile "$NAME" "$FORCE" || exit 1
echo
echo "DONE. Restart Firefox to activate NoID Privacy Firefox Hardening in profile '$NAME'."
echo "Tip: 'noid-update-all.sh' reapplies the supported user.js composition weekly."
exit 0
HARDEN_EOF

chmod 755 "$LOCAL_BIN_DIR/noid-firefox-harden-profile"
chown root:root "$LOCAL_BIN_DIR/noid-firefox-harden-profile"
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$LOCAL_BIN_DIR/noid-firefox-harden-profile" 2>/dev/null || true
fi
log "  Installed /usr/local/bin/noid-firefox-harden-profile"

#------------------------------------------------------------------------------
# Step 6e: Firefox launcher/desktop ownership boundary
#------------------------------------------------------------------------------
log "Step 6e/8: Preserve signed Fedora launcher and desktop payloads"
FF_VENDOR_DESKTOP=/usr/share/applications/org.mozilla.firefox.desktop
[ -f "$FF_VENDOR_DESKTOP" ] && [ ! -L "$FF_VENDOR_DESKTOP" ] \
    || { log "  [FAIL] pristine Fedora Firefox desktop entry missing"; exit 1; }
if ! rpm -Vf "$FF_VENDOR_DESKTOP" >/dev/null 2>&1; then
    log "  [FAIL] Fedora Firefox desktop entry differs from its RPM payload"
    exit 1
fi
log "  Signed Fedora launcher and desktop entry remain byte-pristine"

#------------------------------------------------------------------------------
# Step 6f: derive NoID Privacy-owned launcher and XDG desktop overlays
#------------------------------------------------------------------------------
# The generator accepts only the exact signed RPM payload, stages both derived
# files on their destination filesystems, validates them, and atomically
# publishes them under /usr/local. XDG/PATH precedence selects these owned
# overlays while /usr/bin and /usr/share/applications remain pristine.
log "Step 6f/8: Generate owned launcher + XDG overlay and install update hook"

# Cache the final AutoConfig payload for runtime re-assertion. The three
# files below live inside the firefox package tree as unowned files: plain
# RPM upgrades keep them in place, but reinstall/obsoletes/tree-restructure
# paths drop them silently. The reassert helper re-installs them from this
# cache on every firefox transaction (mirrors the M35 Thunderbird cache).
install -d -m 0755 /usr/share/noid-firefox
for ff_autoconfig in \
    "/usr/lib64/firefox/mozilla.cfg::mozilla.cfg" \
    "/usr/lib64/firefox/defaults/pref/autoconfig.js::autoconfig.js" \
    "/usr/lib64/firefox/defaults/pref/noid-locale.js::noid-locale.js"; do
    ff_src="${ff_autoconfig%%::*}"
    ff_dst="/usr/share/noid-firefox/${ff_autoconfig##*::}"
    if [ ! -f "$ff_src" ]; then
        log "  FAIL: AutoConfig cache source missing: $ff_src"
        exit 1
    fi
    install -m 0644 "$ff_src" "$ff_dst"
done
log "  Cached Firefox AutoConfig payload in /usr/share/noid-firefox (runtime re-assert source)"

cat > /usr/local/sbin/noid-firefox-reassert <<'NOID_FF_REASSERT_EOF'
#!/usr/bin/bash
# Regenerate NoID Privacy-owned Firefox launcher/XDG overlays after an RPM
# update. Never write a file owned by the Firefox RPM.
set -euo pipefail
PATH=/usr/sbin:/usr/bin
export PATH
if [ "$#" -ne 0 ]; then
    printf '%s\n' 'ERROR: noid-firefox-reassert accepts no arguments' >&2
    exit 2
fi

fail() {
    logger -t noid-firefox-reassert "FAILED: $*"
    printf 'noid-firefox-reassert: %s\n' "$*" >&2
    exit 1
}

vendor_digest() {
    local path=$1 digest actual
    [ "$(rpm -q --qf '%{FILEDIGESTALGO}' firefox 2>/dev/null)" = 8 ] \
        || fail "Firefox RPM does not declare SHA-256 file digests"
    # The reader must consume rpm's complete file list: an early-exit awk can
    # close the pipe while rpm is still writing, and under pipefail the
    # resulting SIGPIPE (exit 141) would abort this script without reaching
    # fail().
    digest=$(rpm -q --qf '[%{FILENAMES}\t%{FILEDIGESTS}\n]' firefox 2>/dev/null \
        | awk -F '\t' -v p="$path" '
            $1 == p { count++; digest=$2 }
            END { if (count != 1 || digest == "") exit 1; print digest }
        ') || fail "cannot obtain RPM digest for $path"
    [ "${#digest}" -eq 64 ] || fail "cannot obtain RPM digest for $path"
    actual=$(sha256sum "$path" | awk '{print $1}')
    [ "$actual" = "$digest" ] || fail "$path differs from its signed RPM payload"
}

vendor_launcher=/usr/bin/firefox
owned_launcher=/usr/local/bin/firefox
vendor_desktop=/usr/share/applications/org.mozilla.firefox.desktop
owned_desktop=/usr/local/share/applications/org.mozilla.firefox.desktop
install -d -m 0755 /usr/local/bin /usr/local/share/applications
exec 9>/run/noid-firefox-overlay.lock
flock -w 300 9 || fail "timed out waiting for Firefox overlay regeneration"
vendor_digest "$vendor_launcher"
vendor_digest "$vendor_desktop"
widevine_anchor_count=$(grep -cF \
    '    (restorecon -vr $MOZ_CONFIG_DIR/firefox/*/gmp-widevinecdm/* &)' \
    "$vendor_launcher" 2>/dev/null || true)
widevine_anchor_count=${widevine_anchor_count:-0}
legacy_root_anchor_count=$(grep -cF 'if [ -d "$HOME/.mozilla" ]; then' \
    "$vendor_launcher" 2>/dev/null || true)
legacy_root_anchor_count=${legacy_root_anchor_count:-0}
exec_anchor_count=$(grep -cF 'exec $MOZ_PROGRAM "$@"' \
    "$vendor_launcher" 2>/dev/null || true)
exec_anchor_count=${exec_anchor_count:-0}
relaunch_anchor_count=$(grep -Fxc "export MOZ_APP_LAUNCHER=\"$vendor_launcher\"" \
    "$vendor_launcher" 2>/dev/null || true)
relaunch_anchor_count=${relaunch_anchor_count:-0}
[ "$widevine_anchor_count" -eq 1 ] \
    || fail "reviewed Widevine relabel anchor changed"
[ "$legacy_root_anchor_count" -eq 1 ] \
    || fail "reviewed Fedora profile-root anchor changed"
[ "$exec_anchor_count" -eq 1 ] \
    || fail "reviewed Firefox exec anchor changed"
[ "$relaunch_anchor_count" -eq 1 ] \
    || fail "reviewed Firefox relaunch anchor changed"

launcher_tmp=
desktop_stage_dir=
desktop_tmp=
langpack_tmp=
cleanup() {
    [ -z "${launcher_tmp:-}" ] || rm -f -- "$launcher_tmp"
    [ -z "${desktop_tmp:-}" ] || rm -f -- "$desktop_tmp" "${desktop_tmp}.filtered"
    if [ -n "${desktop_stage_dir:-}" ]; then
        rmdir -- "$desktop_stage_dir" 2>/dev/null || true
    fi
    [ -z "${langpack_tmp:-}" ] || rm -f -- "$langpack_tmp"
}
trap cleanup EXIT
launcher_tmp=$(mktemp /usr/local/bin/.firefox.XXXXXX)
desktop_stage_dir=$(mktemp -d /usr/local/share/applications/.noid-firefox-overlay.XXXXXXXX)
desktop_tmp="$desktop_stage_dir/org.mozilla.firefox.desktop"
cp -- "$vendor_launcher" "$launcher_tmp"
sed -i 's|^if \[ -d "$HOME/\.mozilla" \]; then$|if [ -f "$HOME/.mozilla/firefox/profiles.ini" ]; then|' \
    "$launcher_tmp"
sed -i '\|    (restorecon -vr $MOZ_CONFIG_DIR/firefox/\*/gmp-widevinecdm/\* &)|c\    (\n      shopt -s nullglob\n      widevine_paths=("$MOZ_CONFIG_DIR"/firefox/*/gmp-widevinecdm/*)\n      if [ "${#widevine_paths[@]}" -gt 0 ]; then\n        restorecon -vr -- "${widevine_paths[@]}"\n      fi\n    ) \&' "$launcher_tmp"
command -v python3 >/dev/null 2>&1 \
    || fail "python3 is unavailable for the reviewed Firefox launcher transform"
python3 - "$launcher_tmp" <<'NOID_FF_LAUNCHER_PATCH_PYEOF'
from pathlib import Path
import sys

path = Path(sys.argv[1])
data = path.read_text(encoding="utf-8")
anchor = 'exec $MOZ_PROGRAM "$@"'
if data.count(anchor) != 1:
    raise SystemExit("reviewed Firefox exec anchor changed during transform")
launch_block = '''\
# NoID Privacy: resolve registered XDG profiles to an explicit, validated path.
# This avoids the legacy-profile shadowing tracked as Mozilla Bug 2003137.
# Explicit path/manager/creation requests remain native.
NOID_FF_PROFILE_HELPER=/usr/local/lib/noid-privacy/firefox-profiles.sh
if [ ! -f "$NOID_FF_PROFILE_HELPER" ] || [ -L "$NOID_FF_PROFILE_HELPER" ]; then
  echo "NoID Privacy: Firefox profile helper is missing or unsafe." >&2
  exit 1
fi
. "$NOID_FF_PROFILE_HELPER"
if ! prepare_firefox_launch_args "$@"; then
  echo "NoID Privacy: the hardened default-release profile is unavailable." >&2
  echo "Run noid-firefox-harden-profile or use --ProfileManager explicitly." >&2
  exit 1
fi
set -- "${NOID_FF_LAUNCH_ARGS[@]}"
unset NOID_FF_LAUNCH_ARGS
'''
path.write_text(data.replace(anchor, launch_block + anchor), encoding="utf-8")
NOID_FF_LAUNCHER_PATCH_PYEOF
sed -i "s|^export MOZ_APP_LAUNCHER=\"$vendor_launcher\"$|export MOZ_APP_LAUNCHER=\"$owned_launcher\"|" \
    "$launcher_tmp"
bash -n "$launcher_tmp" || fail "derived Firefox launcher is not valid Bash"
chmod 0755 "$launcher_tmp"; chown root:root "$launcher_tmp"
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$launcher_tmp" || fail "cannot label derived Firefox launcher"
fi
sync -- "$launcher_tmp"
mv -fT -- "$launcher_tmp" "$owned_launcher"
launcher_tmp=
sync -- "$owned_launcher"; sync -- /usr/local/bin

cp -- "$vendor_desktop" "$desktop_tmp"
sed -i 's|^Exec=firefox %u$|Exec=/usr/local/bin/firefox %u|' "$desktop_tmp"
sed -i 's|^Exec=firefox --new-window %u$|Exec=/usr/local/bin/firefox --new-window %u|' "$desktop_tmp"
sed -i 's|^Exec=firefox --private-window %u$|Exec=/usr/local/bin/firefox --private-window %u|' "$desktop_tmp"
if grep -q '^\[Desktop Action profile-manager-window\]' "$desktop_tmp"; then
    sed -i 's|^\(Actions=.*\);profile-manager-window\(;\?\)|\1\2|' "$desktop_tmp"
    sed -i 's|^\(Actions=\)profile-manager-window;|\1|' "$desktop_tmp"
    awk '/^\[Desktop Action profile-manager-window\]$/ { skip=1; next }
         skip && /^\[/ { skip=0 }
         !skip' "$desktop_tmp" > "${desktop_tmp}.filtered"
    mv -f -- "${desktop_tmp}.filtered" "$desktop_tmp"
fi
grep -qx 'Exec=/usr/local/bin/firefox %u' "$desktop_tmp" \
    || fail "derived Firefox desktop main Exec is not canonical"
if command -v desktop-file-validate >/dev/null 2>&1; then
    desktop-file-validate "$desktop_tmp" || fail "derived Firefox desktop entry is invalid"
fi
chmod 0644 "$desktop_tmp"; chown root:root "$desktop_tmp"
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$desktop_tmp" || fail "cannot label derived Firefox desktop entry"
fi
sync -- "$desktop_tmp"
mv -fT -- "$desktop_tmp" "$owned_desktop"
desktop_tmp=
rmdir -- "$desktop_stage_dir" \
    || fail "cannot remove private Firefox desktop staging directory"
desktop_stage_dir=
sync -- "$owned_desktop"; sync -- /usr/local/share/applications

# Converge distribution/extensions/ to the exact current firefox-langpacks
# name/byte set. The Step-3d copies are not RPM-owned, so an update can
# otherwise leave stale entries, omit newly packaged locales, or retain old
# bytes that Firefox marks appDisabled after a browser major upgrade.
#
# Fedora marks regional XPIs with RPM language tags and also ships a small set
# of generic-locale aliases as relative symlinks. RPM may install an alias while
# omitting its regional target under the transaction's install-lang selection.
# Accept only aliases whose state and link text exactly match the signed RPM
# header. A missing target in RPM state 2 is an intentionally unavailable alias;
# skip it. A present target must itself be a state-0, SHA-256-verified regular
# firefox-langpacks payload. No filesystem-discovered or cross-directory link is
# ever followed, and every published destination remains a regular file.
LPSRC=/usr/lib64/firefox/langpacks
LPDST=/usr/lib64/firefox/distribution/extensions
if [ ! -d "$LPSRC" ] || [ -L "$LPSRC" ]; then
    fail "Firefox langpack source directory is missing or symlinked"
fi
if [ -L "$LPDST" ] || { [ -e "$LPDST" ] && [ ! -d "$LPDST" ]; }; then
    fail "Firefox distribution extension directory is unsafe"
fi
install -d -m 0755 -o root -g root "$LPDST"
shopt -s nullglob
langpack_candidates=("$LPSRC"/langpack-*.xpi)
[ "${#langpack_candidates[@]}" -gt 0 ] \
    || fail "Firefox langpack source directory has no candidates"
[ "$(rpm -q --qf '%{FILEDIGESTALGO}' firefox-langpacks 2>/dev/null)" = 8 ] \
    || fail "firefox-langpacks RPM does not declare SHA-256 file digests"
langpack_rpm_manifest=$(rpm -q --qf \
    '[%{FILENAMES}\t%{FILESTATES}\t%{FILELINKTOS}\t%{FILEDIGESTS}\n]' \
    firefox-langpacks 2>/dev/null) \
    || fail "cannot read firefox-langpacks RPM file metadata"

langpack_rpm_field() {
    local path=$1 column=$2
    # Consume the complete manifest so the producer cannot receive SIGPIPE
    # under pipefail when the requested record appears before the pipe fills.
    # Requiring exactly one record also rejects ambiguous RPM metadata.
    printf '%s\n' "$langpack_rpm_manifest" \
        | awk -F '\t' -v p="$path" -v c="$column" '
            $1 == p { count++; value=$c }
            END {
                if (count != 1) exit 1
                print value
            }
        '
}

verify_regular_langpack() {
    local path=$1 state link digest actual
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    state=$(langpack_rpm_field "$path" 2) || return 1
    link=$(langpack_rpm_field "$path" 3) || return 1
    digest=$(langpack_rpm_field "$path" 4) || return 1
    [ "$state" = 0 ] && [ -z "$link" ] && [ "${#digest}" -eq 64 ] \
        || return 1
    actual=$(sha256sum "$path" | awk '{print $1}') || return 1
    [ "$actual" = "$digest" ]
}

declare -A source_langpack_paths=()
for _lp in "${langpack_candidates[@]}"; do
    _n=${_lp##*/}
    if [ -L "$_lp" ]; then
        _state=$(langpack_rpm_field "$_lp" 2) \
            || fail "Firefox langpack alias is absent from RPM metadata: $_n"
        _expected_link=$(langpack_rpm_field "$_lp" 3) \
            || fail "Firefox langpack alias metadata is incomplete: $_n"
        _actual_link=$(readlink -- "$_lp") \
            || fail "cannot read Firefox langpack alias: $_n"
        case "$_expected_link" in
            ''|*/*|.|..|*[!A-Za-z0-9._@+-]*)
                fail "Firefox RPM declares an unsafe langpack alias: $_n"
                ;;
        esac
        case "$_expected_link" in
            langpack-*.xpi) ;;
            *) fail "Firefox RPM langpack alias target has an unexpected name: $_n" ;;
        esac
        [ "$_state" = 0 ] && [ "$_actual_link" = "$_expected_link" ] \
            || fail "Firefox langpack alias differs from its RPM payload: $_n"
        _target="$LPSRC/$_expected_link"
        if [ ! -e "$_target" ] && [ ! -L "$_target" ]; then
            _target_state=$(langpack_rpm_field "$_target" 2) \
                || fail "Firefox langpack alias target is absent from RPM metadata: $_n"
            [ "$_target_state" = 2 ] \
                || fail "Firefox langpack alias target is unexpectedly missing: $_n"
            continue
        fi
        verify_regular_langpack "$_target" \
            || fail "Firefox langpack alias target is not a pristine RPM payload: $_n"
        source_langpack_paths["$_n"]="$_target"
    elif [ -f "$_lp" ]; then
        verify_regular_langpack "$_lp" \
            || fail "Firefox langpack is not a pristine RPM payload: $_n"
        source_langpack_paths["$_n"]="$_lp"
    else
        fail "Firefox langpack source has an unsupported file type: $_n"
    fi
done
[ "${#source_langpack_paths[@]}" -gt 0 ] \
    || fail "Firefox langpack source set has no installed regular payloads"
mapfile -t source_langpack_names < <(
    printf '%s\n' "${!source_langpack_paths[@]}" | LC_ALL=C sort
)
for _lp in "$LPDST"/langpack-*.xpi; do
    [ -f "$_lp" ] && [ ! -L "$_lp" ] \
        || fail "Firefox langpack destination is non-regular or symlinked: $_lp"
done
for _n in "${source_langpack_names[@]}"; do
    _lp=${source_langpack_paths[$_n]}
    _dst="$LPDST/$_n"
    langpack_tmp=$(mktemp "$LPDST/.noid-firefox-langpack.XXXXXX") \
        || fail "cannot stage Firefox langpack: $_n"
    if ! install -m 0644 -o root -g root "$_lp" "$langpack_tmp"; then
        rm -f -- "$langpack_tmp"
        langpack_tmp=
        fail "cannot stage Firefox langpack: $_n"
    fi
    if command -v restorecon >/dev/null 2>&1; then
        restorecon -F "$langpack_tmp" \
            || { rm -f -- "$langpack_tmp"; langpack_tmp=; fail "cannot label Firefox langpack: $_n"; }
    fi
    sync -- "$langpack_tmp"
    mv -fT -- "$langpack_tmp" "$_dst" \
        || { rm -f -- "$langpack_tmp"; langpack_tmp=; fail "cannot publish Firefox langpack: $_n"; }
    langpack_tmp=
done
for _lp in "$LPDST"/langpack-*.xpi; do
    _n=${_lp##*/}
    if [ -z "${source_langpack_paths[$_n]+present}" ]; then
        rm -f -- "$_lp" || fail "cannot remove stale Firefox langpack: $_n"
    fi
done
if command -v restorecon >/dev/null 2>&1; then
    restorecon -R "$LPDST" || fail "cannot label Firefox distribution extensions"
fi
source_langpack_set=$(printf '%s\n' "${source_langpack_names[@]}")
installed_langpack_set=$(find "$LPDST" -maxdepth 1 -type f -name 'langpack-*.xpi' \
    -printf '%f\n' | LC_ALL=C sort)
[ "$source_langpack_set" = "$installed_langpack_set" ] \
    || fail "final Firefox langpack name set differs from RPM source"
while IFS= read -r _n; do
    [ -n "$_n" ] || continue
    cmp -s "${source_langpack_paths[$_n]}" "$LPDST/$_n" \
        || fail "final Firefox langpack bytes differ: $_n"
done <<< "$source_langpack_set"
sync -- "$LPDST"

# Re-assert the AutoConfig payload inside the firefox package tree from the
# canonical cache. Preflight the complete source set before any publication:
# a partial/missing cache must make the DNF action fail visibly, not leave a
# silently incomplete policy. Publish beside each destination then rename so a
# concurrently starting browser never observes a truncated configuration.
autoconfig_changed=0
autoconfig_pairs=(
    "/usr/share/noid-firefox/mozilla.cfg::/usr/lib64/firefox/mozilla.cfg" \
    "/usr/share/noid-firefox/autoconfig.js::/usr/lib64/firefox/defaults/pref/autoconfig.js" \
    "/usr/share/noid-firefox/noid-locale.js::/usr/lib64/firefox/defaults/pref/noid-locale.js"
)
for src_dst in "${autoconfig_pairs[@]}"; do
    src="${src_dst%%::*}"
    if [ ! -f "$src" ] || [ -L "$src" ]; then
        fail "canonical AutoConfig source missing, non-regular or symlinked: $src"
    fi
done

publish_autoconfig() {
    local src=$1 dst=$2 parent tmp
    parent=${dst%/*}
    install -d -m 0755 -o root -g root "$parent"
    if [ -f "$dst" ] && [ ! -L "$dst" ] && cmp -s "$src" "$dst" \
            && [ "$(stat -c %a "$dst" 2>/dev/null || true)" = 644 ]; then
        return 0
    fi
    tmp=$(mktemp "$parent/.noid-firefox-autoconfig.XXXXXX") \
        || fail "cannot stage $dst"
    if ! install -m 0644 -o root -g root "$src" "$tmp"; then
        rm -f -- "$tmp"
        fail "cannot stage canonical AutoConfig for $dst"
    fi
    if command -v restorecon >/dev/null 2>&1; then
        restorecon -F "$tmp" || { rm -f -- "$tmp"; fail "cannot label staged $dst"; }
    fi
    sync -- "$tmp"
    mv -fT -- "$tmp" "$dst" || { rm -f -- "$tmp"; fail "cannot publish $dst"; }
    if command -v restorecon >/dev/null 2>&1; then
        restorecon -F "$dst" || fail "cannot label published $dst"
    fi
    [ -f "$dst" ] && [ ! -L "$dst" ] && cmp -s "$src" "$dst" \
        && [ "$(stat -c %a "$dst" 2>/dev/null || true)" = 644 ] \
        || fail "AutoConfig postcondition failed for $dst"
    sync -- "$dst"
    sync -- "$parent"
    autoconfig_changed=1
}

for src_dst in "${autoconfig_pairs[@]}"; do
    src="${src_dst%%::*}"
    dst="${src_dst#*::}"
    publish_autoconfig "$src" "$dst"
done
if [ "$autoconfig_changed" -eq 1 ]; then
    logger -t noid-firefox-reassert "re-asserted AutoConfig payload inside the firefox package tree"
fi
logger -t noid-firefox-reassert "regenerated owned Firefox launcher/XDG overlays and langpacks"
NOID_FF_REASSERT_EOF
chmod 755 /usr/local/sbin/noid-firefox-reassert
chown root:root /usr/local/sbin/noid-firefox-reassert

mkdir -p /etc/dnf/libdnf5-plugins/actions.d
cat > /etc/dnf/libdnf5-plugins/actions.d/noid-firefox.actions <<'NOID_FF_ACTIONS_EOF'
# Regenerate NoID Privacy-owned launcher/XDG overlays from the newly installed,
# signed Firefox RPM payload. Vendor-owned files remain pristine.
# Format: callback:package_filter:direction:options:command
post_transaction:firefox:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-firefox-reassert\ >/dev/null
post_transaction:firefox-langpacks:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-firefox-reassert\ >/dev/null
NOID_FF_ACTIONS_EOF
chmod 644 /etc/dnf/libdnf5-plugins/actions.d/noid-firefox.actions
/usr/local/sbin/noid-firefox-reassert
log "  Installed Firefox overlay generator + post-transaction action"

#------------------------------------------------------------------------------
# Step 7: Verification
#------------------------------------------------------------------------------
log "Step 7/8: Verification"
fail=0

# File existence checks
# Post arkenfox absorption, one consolidated base plus the reviewed DRM consent
# overlay ship (not user-overrides.js/updater.sh/prefsCleaner.sh).
for path in \
    "$SHARE_DIR/user.js" \
    "$SHARE_DIR/user-drm-overrides.js" \
    "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi" \
    "$MANAGED_STORAGE_DIR/uBlock0@raymondhill.net.json" \
    "$LOCAL_BIN_DIR/noid-firefox-setup.sh" \
    /usr/local/bin/noid-firefox-drm \
    "$XDG_AUTOSTART_DIR/noid-firefox-setup.desktop"
do
    if [ ! -f "$path" ]; then
        log "  FAIL: $path missing"
        fail=$((fail + 1))
    fi
done

# Verify consolidated user.js integrity (v2 post arkenfox absorption)
if ! grep -q '_user.js.parrot' "$SHARE_DIR/user.js"; then
    log "  FAIL: arkenfox-derived parrot markers missing in user.js"
    fail=$((fail + 1))
fi
if ! grep -q 'NOID-COMPLETE' "$SHARE_DIR/user.js"; then
    log "  FAIL: NoID Privacy end-parrot marker missing in user.js (decode failed?)"
    fail=$((fail + 1))
fi
if ! grep -q 'SECTION: MOZILLA AI / CLOUD-VPN / NIMBUS BLOCK' "$SHARE_DIR/user.js"; then
    log "  FAIL: NoID Privacy image overrides MOZILLA AI BLOCK section missing in user.js"
    fail=$((fail + 1))
fi

# Verify the exact current managed-storage schema. Only the filter-list set is
# managed; legacy backup-format adminSettings would also wipe user-owned rules,
# trusted sites, imported lists and My filters on every uBO launch.
if ! python3 - "$MANAGED_STORAGE_DIR/uBlock0@raymondhill.net.json" \
        "$EXPECTED_FILTER_LIST_COUNT" <<'UBO_POLICY_PYEOF'
import json
import sys

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
with open(sys.argv[1], encoding="utf-8") as handle:
    managed = json.load(handle)
assert managed == {
    "name": "uBlock0@raymondhill.net",
    "description": (
        "NoID Privacy Workstation 44 - uBlock Origin managed "
        "filter-list baseline (Module 16)"
    ),
    "type": "storage",
    "data": {"toOverwrite": {"filterLists": expected}},
}
assert len(expected) == int(sys.argv[2])
UBO_POLICY_PYEOF
then
    log "  FAIL: managed uBO filter-list policy differs from the exact current schema"
    fail=$((fail + 1))
else
    log "  OK: exact $EXPECTED_FILTER_LIST_COUNT-list uBO policy preserves user-owned settings"
fi
if ! "$UBO_POLICY_VALIDATOR" \
        "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi" \
        "$MANAGED_STORAGE_DIR/uBlock0@raymondhill.net.json"; then
    log "  FAIL: managed uBO filter-list policy is incompatible with the pinned XPI"
    fail=$((fail + 1))
else
    log "  OK: every managed filter-list token is supported by the pinned uBO XPI"
fi

# Verify setup script bash syntax
if ! bash -n "$LOCAL_BIN_DIR/noid-firefox-setup.sh" 2>/dev/null; then
    log "  FAIL: noid-firefox-setup.sh bash syntax error"
    fail=$((fail + 1))
fi

# Verify autostart desktop file is parseable (basic key-value format)
if ! grep -q '^Exec=/usr/local/bin/noid-firefox-setup.sh$' "$XDG_AUTOSTART_DIR/noid-firefox-setup.desktop"; then
    log "  FAIL: autostart desktop file Exec line malformed"
    fail=$((fail + 1))
fi

if [ "$fail" -gt 0 ]; then
    log "=== Module 16 FAILED with $fail errors ==="
    exit 1
fi

log "  Core Firefox artifacts passed the pre-Anaconda verification"

#------------------------------------------------------------------------------
# Step 8: Anaconda WebUI Firefox profile hardening
#------------------------------------------------------------------------------
# Anaconda WebUI renders the install UI in a Firefox profile built from
# /usr/share/anaconda/firefox-theme/{live,default,extlink}/user.js. The
# upstream templates set only 6 privacy prefs — Normandy/Nimbus/Push/Safe-
# Browsing/region beacons stay active during the ~10-15-min install window
# (observed Mozilla-GCP traffic with a unique nimbus.profileId).
# Fix: APPEND comprehensive overrides to all three templates (later wins in
# user.js semantics; upstream UI-behavior prefs preserved — NOT replace).
# The exact suffix is staged separately, published atomically and skipped only
# when a byte-identical completed block is already present.

log "Step 8/8: Anaconda WebUI Firefox profile hardening"

ANACONDA_FF_THEME_DIR=/usr/share/anaconda/firefox-theme
NOID_ANACONDA_FF_MARKER="// === NoID Privacy — Anaconda WebUI Firefox profile hardening ==="
ANACONDA_FF_BLOCK_TMP=
ANACONDA_FF_TARGET_TMP=
cleanup_anaconda_ff_temps() {
    [ -z "${ANACONDA_FF_TARGET_TMP:-}" ] \
        || rm -f -- "$ANACONDA_FF_TARGET_TMP"
    [ -z "${ANACONDA_FF_BLOCK_TMP:-}" ] \
        || rm -f -- "$ANACONDA_FF_BLOCK_TMP"
}
trap cleanup_anaconda_ff_temps EXIT

ANACONDA_FF_BLOCK_TMP=$(mktemp /var/tmp/noid-anaconda-firefox.XXXXXXXX)
cat > "$ANACONDA_FF_BLOCK_TMP" <<'NOID_ANACONDA_FF_EOF'

// === NoID Privacy — Anaconda WebUI Firefox profile hardening ===
// Disable all Mozilla-cloud / Google-safe-browsing / Push / Region / Update
// outbound traffic. Anaconda WebUI is local-only (cockpit-ws on 127.0.0.1:80);
// no external network needed during install. Preserves Anaconda UI functionality
// (extlink protocol handler, custom toolbar, etc. defined above).

// 1. Connectivity / captive-portal detection
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false);
user_pref("captivedetect.canonicalURL", "");

// 2. Normandy (studies / A-B testing) — full disable
user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");
user_pref("app.normandy.first_run", false);
user_pref("app.shield.optoutstudies.enabled", false);

// 3. Nimbus remote-configuration rollouts
user_pref("nimbus.rollouts.enabled", false);

// 4. Mozilla Settings Sync (services.settings.*) — disable
user_pref("services.settings.server", "data:,");
user_pref("services.settings.poll_interval", 0);

// 5. Telemetry — full disable (extends upstream's partial config)
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.bhrPing.enabled", false);
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false);
user_pref("toolkit.telemetry.newProfilePing.enabled", false);
user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false);
user_pref("toolkit.telemetry.updatePing.enabled", false);
user_pref("toolkit.telemetry.server", "data:,");
user_pref("toolkit.coverage.opt-out", true);
user_pref("datareporting.healthreport.service.enabled", false);

// 6. Safe Browsing (Google + Mozilla list updates)
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.enabled", false);
user_pref("browser.safebrowsing.provider.google4.gethashURL", "");
user_pref("browser.safebrowsing.provider.google4.updateURL", "");
user_pref("browser.safebrowsing.provider.mozilla.gethashURL", "");
user_pref("browser.safebrowsing.provider.mozilla.updateURL", "");

// 7. Push notifications (Mozilla Push Service)
user_pref("dom.push.enabled", false);
user_pref("dom.push.connection.enabled", false);
user_pref("dom.push.serverURL", "");
user_pref("dom.webnotifications.enabled", false);

// 8. Region / Geolocation
user_pref("browser.region.network.url", "");
user_pref("browser.region.update.enabled", false);
user_pref("geo.enabled", false);
user_pref("geo.provider.network.url", "");

// 9. Crash reports
user_pref("breakpad.reportURL", "");
user_pref("browser.tabs.crashReporting.sendReport", false);

// 10. Update mechanisms (Live-ISO is read-only; updates are inapplicable)
user_pref("app.update.auto", false);
user_pref("extensions.update.enabled", false);
user_pref("extensions.systemAddon.update.enabled", false);

// 11. GMP / DRM updaters (Widevine, OpenH264)
user_pref("media.gmp-gmpopenh264.enabled", false);
user_pref("media.gmp-widevinecdm.enabled", false);

// 12. Search suggestions / sync (no external search needed)
user_pref("browser.search.suggest.enabled", false);
user_pref("browser.urlbar.suggest.searches", false);
user_pref("browser.search.update", false);

// 13. TRR (Mozilla DoH) — use system DNS in the isolated installer context
user_pref("network.trr.mode", 5);

// 14. Recommendations
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);

// 15. Firefox Account / Sync
user_pref("identity.fxaccounts.enabled", false);
user_pref("services.sync.engine.addons", false);

// 16. WebRTC (no peer-to-peer in install context)
user_pref("media.peerconnection.enabled", false);

// 17. Firefox 153 Messaging System / ASRouter providers
// The installer UI uses none of these message sources. Disabling the complete
// built-in provider set also avoids ASRouter querying uninitialized telemetry
// session dates while the install profile keeps telemetry disabled.
user_pref("browser.newtabpage.activity-stream.asrouter.providers.message-groups", "null");
user_pref("browser.newtabpage.activity-stream.asrouter.providers.onboarding", "null");
user_pref("browser.newtabpage.activity-stream.asrouter.providers.cfr", "null");
user_pref("browser.newtabpage.activity-stream.asrouter.providers.messaging-experiments", "null");

// === END NoID Privacy hardening ===
NOID_ANACONDA_FF_EOF
chmod 0600 "$ANACONDA_FF_BLOCK_TMP"
ANACONDA_FF_BLOCK_SIZE=$(stat -c '%s' "$ANACONDA_FF_BLOCK_TMP")

anaconda_ff_block_is_exact_suffix() {
    local target="$1" target_size
    [ -f "$target" ] && [ ! -L "$target" ] || return 1
    [ "$(grep -Fxc "$NOID_ANACONDA_FF_MARKER" "$target" 2>/dev/null || true)" -eq 1 ] \
        || return 1
    [ "$(grep -Fxc '// === END NoID Privacy hardening ===' \
        "$target" 2>/dev/null || true)" -eq 1 ] || return 1
    target_size=$(stat -c '%s' "$target") || return 1
    [ "$target_size" -ge "$ANACONDA_FF_BLOCK_SIZE" ] || return 1
    tail -c "$ANACONDA_FF_BLOCK_SIZE" "$target" \
        | cmp -s - "$ANACONDA_FF_BLOCK_TMP"
}

if [ ! -d "$ANACONDA_FF_THEME_DIR" ] || [ -L "$ANACONDA_FF_THEME_DIR" ]; then
    log "  [FAIL] $ANACONDA_FF_THEME_DIR not found — required Anaconda WebUI profile tree absent"
    exit 1
else
    for profile in live default extlink; do
        profile_dir="$ANACONDA_FF_THEME_DIR/$profile"
        target="$profile_dir/user.js"
        if [ ! -d "$profile_dir" ] || [ -L "$profile_dir" ] || \
           [ ! -f "$target" ] || [ -L "$target" ]; then
            log "  [FAIL] $target missing — required installer-browser profile contract absent"
            exit 1
        fi

        marker_count=$(grep -Fxc "$NOID_ANACONDA_FF_MARKER" \
            "$target" 2>/dev/null || true)
        if [ "$marker_count" -ne 0 ]; then
            if ! anaconda_ff_block_is_exact_suffix "$target"; then
                log "  [FAIL] $target contains a partial or modified NoID Privacy block"
                exit 1
            fi
            chmod 0644 "$target"
            chown root:root "$target"
            command -v restorecon >/dev/null 2>&1 \
                && restorecon -F "$target" 2>/dev/null || true
            log "  [SKIP] $target already ends in the exact hardening block"
            continue
        fi

        # Publish the complete suffix atomically. A failed copy, sync or rename
        # leaves the package-owned input intact and no misleading marker behind.
        ANACONDA_FF_TARGET_TMP=$(mktemp "$profile_dir/.user.js.noid.XXXXXXXX")
        if ! cp -- "$target" "$ANACONDA_FF_TARGET_TMP" || \
           ! cat "$ANACONDA_FF_BLOCK_TMP" >> "$ANACONDA_FF_TARGET_TMP" || \
           ! anaconda_ff_block_is_exact_suffix "$ANACONDA_FF_TARGET_TMP" || \
           ! chmod 0644 "$ANACONDA_FF_TARGET_TMP" || \
           ! chown root:root "$ANACONDA_FF_TARGET_TMP" || \
           ! sync -- "$ANACONDA_FF_TARGET_TMP" || \
           ! mv -fT -- "$ANACONDA_FF_TARGET_TMP" "$target" || \
           ! sync -- "$profile_dir"; then
            log "  [FAIL] atomic Anaconda Firefox hardening publication failed: $target"
            exit 1
        fi
        ANACONDA_FF_TARGET_TMP=
        command -v restorecon >/dev/null 2>&1 \
            && restorecon -F "$target" 2>/dev/null || true
        log "  [OK] $target — exact NoID Privacy hardening block published atomically"
    done
fi

# Verification of Step 8
ff_theme_fail=0
for profile in live default extlink; do
    target="$ANACONDA_FF_THEME_DIR/$profile/user.js"
    if [ ! -f "$target" ] || [ -L "$target" ]; then
        log "  [FAIL] required Anaconda profile disappeared before final verification: $target"
        ff_theme_fail=$((ff_theme_fail + 1))
        continue
    fi
    if ! anaconda_ff_block_is_exact_suffix "$target" || \
       [ "$(stat -c '%u:%g:%a:%h' "$target")" != "0:0:644:1" ]; then
        log "  [FAIL] $target differs from the exact hardening suffix/metadata"
        ff_theme_fail=$((ff_theme_fail + 1))
    fi
done

if [ "$ff_theme_fail" -gt 0 ]; then
    log "=== Module 16: Anaconda firefox-theme hardening FAILED ($ff_theme_fail errors) ==="
    exit 1
fi

log "    Anaconda Firefox-theme hardened (live + default + extlink — Bug #61 fix)"

#------------------------------------------------------------------------------
# Final closed deployment gate + health stamp
#------------------------------------------------------------------------------
log "Final gate: exact Firefox deployment contracts"
final_fail=0

require_regular() {
    local path="$1"
    if [ ! -f "$path" ] || [ -L "$path" ] || [ ! -s "$path" ]; then
        log "  [FAIL] missing, empty, non-regular or symlinked: $path"
        final_fail=$((final_fail + 1))
    fi
}

for path in \
    "$SHARE_DIR/user.js" \
    "$SHARE_DIR/user-drm-overrides.js" \
    "$ARKENFOX_LICENSE" \
    "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi" \
    "$MANAGED_STORAGE_DIR/uBlock0@raymondhill.net.json" \
    "$FIREFOX_LIB_DIR/mozilla.cfg" \
    "$AUTOCONFIG_PREF_DIR/autoconfig.js" \
    "$AUTOCONFIG_PREF_DIR/noid-locale.js" \
    /etc/firefox/policies/policies.json \
    /usr/lib64/firefox/distribution/distribution.ini \
    /usr/share/applications/org.mozilla.firefox.desktop \
    /usr/local/bin/firefox \
    /usr/local/share/applications/org.mozilla.firefox.desktop \
    "$UBO_POLICY_SOURCE" \
    "$UBO_POLICY_VALIDATOR" \
    /usr/local/lib/noid-privacy/validate-webextension.py \
    /usr/local/lib/noid-privacy/verify-firefox-xpi-signature \
    /usr/local/lib/noid-privacy/firefox-profiles.sh \
    "$LOCAL_BIN_DIR/noid-firefox-setup.sh" \
    "$LOCAL_BIN_DIR/noid-firefox-harden-profile" \
    /usr/local/bin/noid-firefox-relax-fpp \
    /usr/local/bin/noid-firefox-relax-webrtc \
    /usr/local/bin/noid-firefox-drm \
    /usr/local/sbin/noid-firefox-reassert \
    /etc/dnf/libdnf5-plugins/actions.d/noid-firefox.actions \
    "$XDG_AUTOSTART_DIR/noid-firefox-setup.desktop" \
    "$SKEL_FF_BASE/profiles.ini" \
    "$SKEL_FF_PROFILE/user.js" \
    "$SKEL_FF_PROFILE/extension-preferences.json" \
    "$SKEL_FF_PROFILE/extensions/uBlock0@raymondhill.net.xpi"; do
    require_regular "$path"
done

for helper_path in \
    "$UBO_POLICY_VALIDATOR" \
    /usr/local/lib/noid-privacy/validate-webextension.py \
    /usr/local/lib/noid-privacy/verify-firefox-xpi-signature \
    /usr/local/lib/noid-privacy/firefox-profiles.sh; do
    if ! matchpathcon -V "$helper_path" >/dev/null; then
        log "  [FAIL] installed Firefox helper SELinux context differs: $helper_path"
        final_fail=$((final_fail + 1))
    fi
done

if ! cmp -s -- "$UBO_POLICY_SOURCE" \
        "$MANAGED_STORAGE_DIR/uBlock0@raymondhill.net.json"; then
    log "  [FAIL] active uBO policy differs from its canonical source"
    final_fail=$((final_fail + 1))
fi

for python_path in \
    "$UBO_POLICY_VALIDATOR" \
    /usr/local/lib/noid-privacy/validate-webextension.py; do
    if ! python3 -c 'import pathlib,sys; p=pathlib.Path(sys.argv[1]); compile(p.read_text(), str(p), "exec")' \
            "$python_path" 2>/dev/null; then
        log "  [FAIL] installed Python validator does not parse: $python_path"
        final_fail=$((final_fail + 1))
    fi
    if [ "$(stat -c '%U:%G:%a' "$python_path" 2>/dev/null || true)" != \
            "root:root:755" ]; then
        log "  [FAIL] installed Python validator metadata differs: $python_path"
        final_fail=$((final_fail + 1))
    fi
done

for shell_path in \
    /usr/local/lib/noid-privacy/verify-firefox-xpi-signature \
    /usr/local/lib/noid-privacy/firefox-profiles.sh \
    "$LOCAL_BIN_DIR/noid-firefox-setup.sh" \
    "$LOCAL_BIN_DIR/noid-firefox-harden-profile" \
    /usr/local/bin/noid-firefox-relax-fpp \
    /usr/local/bin/noid-firefox-relax-webrtc \
    /usr/local/bin/noid-firefox-drm \
    /usr/local/bin/firefox \
    /usr/local/sbin/noid-firefox-reassert; do
    if ! bash -n "$shell_path" 2>/dev/null; then
        log "  [FAIL] installed shell payload does not parse: $shell_path"
        final_fail=$((final_fail + 1))
    fi
done

if [ "$(grep -Fxc '// NOID-DRM-OPT-IN-BEGIN' "$SHARE_DIR/user-drm-overrides.js" 2>/dev/null || true)" -ne 1 ] || \
   [ "$(grep -Fxc '// NOID-DRM-OPT-IN-END' "$SHARE_DIR/user-drm-overrides.js" 2>/dev/null || true)" -ne 1 ] || \
   ! grep -qx 'user_pref("media.gmp-manager.updateEnabled", true);' \
       "$SHARE_DIR/user-drm-overrides.js"; then
    log "  [FAIL] exact Firefox DRM consent overlay differs"
    final_fail=$((final_fail + 1))
fi

if ! cmp -s "$SHARE_DIR/user.js" "$SKEL_FF_PROFILE/user.js"; then
    log "  [FAIL] canonical and skel Firefox user.js differ"
    final_fail=$((final_fail + 1))
fi
if grep -Eq '^[[:space:]]*user_pref\("browser\.uiCustomization\.state"' \
        "$SHARE_DIR/user.js" || \
   [ "$(grep -Fxc -- "$TOOLBAR_DEFAULT_PREF" \
        "$FIREFOX_LIB_DIR/mozilla.cfg" 2>/dev/null || true)" -ne 1 ]; then
    log "  [FAIL] Firefox toolbar state is not one user-overridable AutoConfig default"
    final_fail=$((final_fail + 1))
fi
if ! cmp -s "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi" \
        "$SKEL_FF_PROFILE/extensions/uBlock0@raymondhill.net.xpi"; then
    log "  [FAIL] staged and skel uBO XPI differ"
    final_fail=$((final_fail + 1))
fi
final_ubo_size=$(stat -c '%s' \
    "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi" 2>/dev/null || true)
final_ubo_size=${final_ubo_size:-0}
if [ "$final_ubo_size" -ne "$UBO_SIZE_EXPECTED" ] || \
   [ "$(sha256sum "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi" 2>/dev/null | awk '{print $1}')" != "$UBO_SHA256" ]; then
    log "  [FAIL] final uBO XPI differs from exact source pin"
    final_fail=$((final_fail + 1))
fi
if ! "$UBO_POLICY_VALIDATOR" \
        "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi" \
        "$MANAGED_STORAGE_DIR/uBlock0@raymondhill.net.json"; then
    log "  [FAIL] final managed uBO policy is incompatible with the pinned XPI"
    final_fail=$((final_fail + 1))
fi

if ! python3 - "$EXPECTED_FILTER_LIST_COUNT" \
        /etc/firefox/policies/policies.json \
        "$MANAGED_STORAGE_DIR/uBlock0@raymondhill.net.json" \
        "$SKEL_FF_PROFILE/extension-preferences.json" <<'FINAL_JSON_PYEOF'
import json, sys
expected_filter_list_count = int(sys.argv[1])
expected_filter_lists = [
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
assert len(expected_filter_lists) == expected_filter_list_count
with open(sys.argv[2], encoding="utf-8") as handle:
    policies = json.load(handle)
assert policies == {"policies": {"SearchEngines": {"Default": "DuckDuckGo"}}}
with open(sys.argv[3], encoding="utf-8") as handle:
    managed = json.load(handle)
assert managed == {
    "name": "uBlock0@raymondhill.net",
    "description": (
        "NoID Privacy Workstation 44 - uBlock Origin managed "
        "filter-list baseline (Module 16)"
    ),
    "type": "storage",
    "data": {"toOverwrite": {"filterLists": expected_filter_lists}},
}
with open(sys.argv[4], encoding="utf-8") as handle:
    seed_preferences = json.load(handle)
assert seed_preferences == {
    "uBlock0@raymondhill.net": {
        "permissions": ["internal:privateBrowsingAllowed"],
        "origins": [],
        "data_collection": [],
    }
}
FINAL_JSON_PYEOF
then
    log "  [FAIL] final Firefox policy/managed-storage/skel-permission schema differs"
    final_fail=$((final_fail + 1))
fi

if ! grep -qx 'pref("general.config.filename", "mozilla.cfg");' "$AUTOCONFIG_PREF_DIR/autoconfig.js" || \
   ! grep -qx 'pref("general.config.obscure_value", 0);' "$AUTOCONFIG_PREF_DIR/autoconfig.js" || \
   ! grep -qx 'pref("general.config.sandbox_enabled", true);' "$AUTOCONFIG_PREF_DIR/autoconfig.js" || \
   ! grep -qx 'lockPref("browser.profiles.enabled", false);' "$FIREFOX_LIB_DIR/mozilla.cfg" || \
   ! grep -qx 'lockPref("browser.newtabpage.activity-stream.default.sites", "");' "$FIREFOX_LIB_DIR/mozilla.cfg" || \
   ! grep -qx 'defaultPref("network.trr.mode", 5);' "$FIREFOX_LIB_DIR/mozilla.cfg" || \
   ! grep -qx 'defaultPref("doh-rollout.home-region", "global");' "$FIREFOX_LIB_DIR/mozilla.cfg" || \
   ! grep -qx 'defaultPref("browser.sessionstore.persist_closed_tabs_between_sessions", false);' \
       "$FIREFOX_LIB_DIR/mozilla.cfg" || \
   grep -Eq '^defaultPref\("network\.trr\.(uri|custom_uri|bootstrapAddr)"' \
       "$FIREFOX_LIB_DIR/mozilla.cfg"; then
    log "  [FAIL] final Firefox AutoConfig pointer/lock contract differs"
    final_fail=$((final_fail + 1))
fi

if ! grep -qF 'prepare_firefox_launch_args "$@"' /usr/local/bin/firefox || \
   ! grep -qF 'if [ -f "$HOME/.mozilla/firefox/profiles.ini" ]; then' \
       /usr/local/bin/firefox || \
   ! grep -qx 'Exec=/usr/local/bin/firefox %u' \
       /usr/local/share/applications/org.mozilla.firefox.desktop || \
   ! rpm -Vf /usr/bin/firefox >/dev/null 2>&1 || \
   ! rpm -Vf /usr/share/applications/org.mozilla.firefox.desktop >/dev/null 2>&1 || \
   ! rpm -Vf /usr/lib64/firefox/distribution/distribution.ini >/dev/null 2>&1 || \
   ! grep -qx 'Exec=/usr/local/bin/noid-firefox-setup.sh' \
       "$XDG_AUTOSTART_DIR/noid-firefox-setup.desktop"; then
    log "  [FAIL] final owned-overlay/vendor-pristine/autostart contract differs"
    final_fail=$((final_fail + 1))
fi

# Follow non-dangling RPM alias symlinks just as the publication path does;
# keep each alias basename in the expected set even though its destination is
# materialized as a regular file below FIREFOX_DIST_EXT.
source_langpacks=$(find -L "$FIREFOX_LANGPACK_SRC" -maxdepth 1 -type f \
    -name 'langpack-*.xpi' -printf '%f\n' | LC_ALL=C sort)
installed_langpacks=$(find "$FIREFOX_DIST_EXT" -maxdepth 1 -type f \
    -name 'langpack-*.xpi' -printf '%f\n' | LC_ALL=C sort)
if [ -z "$source_langpacks" ] || [ "$source_langpacks" != "$installed_langpacks" ]; then
    log "  [FAIL] final Firefox langpack name set differs from RPM source"
    final_fail=$((final_fail + 1))
else
    while IFS= read -r langpack; do
        cmp -s "$FIREFOX_LANGPACK_SRC/$langpack" "$FIREFOX_DIST_EXT/$langpack" || {
            log "  [FAIL] Firefox langpack bytes differ: $langpack"
            final_fail=$((final_fail + 1))
        }
    done <<< "$source_langpacks"
fi

for profile in live default extlink; do
    target="$ANACONDA_FF_THEME_DIR/$profile/user.js"
    if ! anaconda_ff_block_is_exact_suffix "$target" || \
       [ "$(stat -c '%u:%g:%a:%h' "$target" 2>/dev/null || true)" != "0:0:644:1" ]; then
        log "  [FAIL] Anaconda Firefox profile lacks one exact hardening block: $profile"
        final_fail=$((final_fail + 1))
    fi
done

if [ "$final_fail" -gt 0 ]; then
    log "=== Module 16 FINAL GATE FAILED with $final_fail errors ==="
    exit 1
fi

rm -f -- "$ANACONDA_FF_BLOCK_TMP"
ANACONDA_FF_BLOCK_TMP=
trap - EXIT

# M16_HEALTH_PUBLICATION_BEGIN
if [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ] \
   || [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
        "0:0:755" ] \
   || ! matchpathcon -V "$STAMP_DIR" >/dev/null; then
    log "  FAIL: shared health-stamp directory drifted before publication"
    exit 1
fi

STAMP_TMP=
STAMP_PUBLISHED=0
cleanup_firefox_health_stamp() {
    if [ -n "${STAMP_TMP:-}" ]; then
        rm -f -- "$STAMP_TMP" || true
    fi
    if [ "${STAMP_PUBLISHED:-0}" -eq 1 ]; then
        if ! rm -f -- "$STAMP"; then
            log "  FAIL: could not retire incomplete Module 16 health stamp"
        fi
        sync -- "$STAMP_DIR" >/dev/null 2>&1 || true
    fi
}
firefox_stamp_fail() {
    log "  FAIL: $*"
    exit 1
}
verify_firefox_health_stamp() {
    local path="$1"
    [ -f "$path" ] \
        && [ ! -L "$path" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' -- "$path" 2>/dev/null || true)" = \
            "0:0:644:1" ] \
        && [ "$(wc -l < "$path")" -eq 6 ] \
        && [ "$(grep -c '^module=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^name=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^version=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^status=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^timestamp=' "$path" || true)" -eq 1 ] \
        && grep -qxF 'module=16' "$path" \
        && grep -qxF 'name=firefox' "$path" \
        && grep -qxF 'version=1' "$path" \
        && grep -qxF 'status=ok' "$path" \
        && grep -Eq \
            '^timestamp=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' \
            "$path"
}
trap cleanup_firefox_health_stamp EXIT

STAMP_TMP=$(mktemp "$STAMP_DIR/.stamp-16-firefox.ok.XXXXXXXX") \
    || firefox_stamp_fail "cannot create Module 16 health-stamp candidate"
cat > "$STAMP_TMP" <<STAMP_EOF || \
    firefox_stamp_fail "cannot write Module 16 health-stamp candidate"
# NoID Privacy — Module 16 Health Stamp
module=16
name=firefox
version=1
status=ok
timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
STAMP_EOF
chmod 0644 "$STAMP_TMP" \
    || firefox_stamp_fail "cannot set Module 16 health-stamp mode"
chown root:root "$STAMP_TMP" \
    || firefox_stamp_fail "cannot set Module 16 health-stamp ownership"
restorecon -F -- "$STAMP_TMP" \
    || firefox_stamp_fail "cannot label Module 16 health-stamp candidate"
matchpathcon -V "$STAMP_TMP" >/dev/null \
    || firefox_stamp_fail "Module 16 health-stamp candidate label differs"
if ! verify_firefox_health_stamp "$STAMP_TMP"; then
    firefox_stamp_fail "staged Module 16 health-stamp contract is invalid"
fi
sync -- "$STAMP_TMP" \
    || firefox_stamp_fail "cannot sync Module 16 health-stamp candidate"
if ! mv -fT -- "$STAMP_TMP" "$STAMP"; then
    rm -f -- "$STAMP" || true
    firefox_stamp_fail "cannot publish Module 16 health stamp"
fi
STAMP_TMP=
STAMP_PUBLISHED=1
restorecon -F -- "$STAMP" \
    || firefox_stamp_fail "cannot label published Module 16 health stamp"
matchpathcon -V "$STAMP" >/dev/null \
    || firefox_stamp_fail "published Module 16 health-stamp label differs"
sync -- "$STAMP" \
    || firefox_stamp_fail "cannot sync published Module 16 health stamp"
sync -- "$STAMP_DIR" \
    || firefox_stamp_fail "cannot sync Module 16 health-stamp directory"
if ! verify_firefox_health_stamp "$STAMP"; then
    firefox_stamp_fail "published Module 16 health-stamp contract is invalid"
fi
STAMP_PUBLISHED=0
trap - EXIT
log "  Exact Module 16 health stamp published atomically"
# M16_HEALTH_PUBLICATION_END

log "=== Module 16: Firefox Hardening COMPLETE ==="
log "    NoID Privacy Firefox Hardening v${NOID_FIREFOX_HARDENING_VERSION} installed (${USERJS_SIZE:-unknown} bytes)"
log "    uBlock Origin XPI verified (${UBO_SIZE:-unknown} bytes) + managed storage manifest"
log "    Core, Anaconda WebUI and final deployment gates passed; health stamp written"

%end
