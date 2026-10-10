# ============================================================================
# Module 16 — Firefox Hardening (NoID Privacy-owned user.js + uBlock Origin)
# Canonical source-of-truth files:
#   - firefox/noid-firefox-hardening.js (user.js, derived from arkenfox v144.0 MIT)
# Status: LOCKED 2026-10-08 (v3.116) — keep the web-content language list out of Sync and turn off the add-on metadata cache.
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
#     flow-through) + per-locale langpack staging below
#     distribution/extensions/locale-<tag>/
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
#     only the profile-manager + top-sites injectors and the Sync control of
#     the web-content language list are lockPref.
#   - installs.ini is NOT pre-baked (Firefox computes the install-hash
#     from the executable path; a hand-rolled hash forks a new profile).
#
# Constraint notes (keep when editing):
#   - mozilla.cfg line 1 MUST be a comment (parser skips L1); the
#     user_pref->defaultPref count parity is verify-gated.
#   - extensions.autoDisableScopes=10 is load-bearing (profile-scope XPIs,
#     bit 1: the uBO copy and the distribution-installed langpack, stay enabled).
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
# Supply-chain pinning: every external download is bound to an exact release
# URL plus size and SHA256 verification. A git-tag move or AMO mirror
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
xak0l3HdOSx3/y+d0f15fI4BAA==
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
# The seed is the state Firefox 156 (CustomizableUI schema 26) writes for a
# fresh profile with uBlock Origin under these defaults. A later Firefox
# release migrates an older seed forward on first start.
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
TOOLBAR_DEFAULT_PREF='defaultPref("browser.uiCustomization.state", "{\"placements\":{\"widget-overflow-fixed-list\":[],\"unified-extensions-area\":[],\"nav-bar\":[\"back-button\",\"forward-button\",\"stop-reload-button\",\"customizableui-special-spring1\",\"vertical-spacer\",\"urlbar-container\",\"customizableui-special-spring2\",\"downloads-button\",\"fxa-toolbar-menu-button\",\"reset-pbm-toolbar-button\",\"ublock0_raymondhill_net-browser-action\",\"unified-extensions-button\"],\"toolbar-menubar\":[\"menubar-items\"],\"TabsToolbar\":[\"tabbrowser-tabs\",\"new-tab-button\",\"customizableui-special-spring3\",\"alltabs-button\",\"smartwindow-group-tabs-button\",\"ai-window-toggle\"],\"vertical-tabs\":[],\"PersonalToolbar\":[\"personal-bookmarks\"]},\"seen\":[\"reset-pbm-toolbar-button\",\"ublock0_raymondhill_net-browser-action\",\"developer-button\",\"screenshot-button\"],\"dirtyAreaCache\":[\"unified-extensions-area\",\"nav-bar\",\"TabsToolbar\",\"vertical-tabs\",\"toolbar-menubar\",\"PersonalToolbar\"],\"currentVersion\":26,\"newElementCount\":3}");'
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
    echo "// it forces the value regardless of getValue(). With this lockPref,"
    echo "// Wikipedia/YouTube/Amazon/Reddit do not appear in the new-tab Top"
    echo "// Sites grid."
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
    echo "// code path (browser/extensions/newtab/lib/TopSitesFeed.sys.mjs in the"
    echo "// Firefox source tree)."
    echo "//"
    echo "// Fix: lockPref both the master toggle + havePinned cache string."
    echo 'lockPref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts", false);'
    echo 'lockPref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts.havePinned", "");'
    echo ""
    echo "// ============================================================"
    echo "// NoID Privacy — keep the web-content language list per machine"
    echo "// ============================================================"
    echo "// intl.accept_languages stays at Firefox's \"und\" default, which"
    echo "// derives Accept-Language, navigator.languages and Intl from the"
    echo "// negotiated system locale. Firefox Sync syncs that list by default"
    echo "// and would import an account's stored value (for example an English"
    echo "// list from another machine) on every new installation. Each incoming"
    echo "// Sync record also carries this control pref as true and is applied"
    echo "// before the list, so a defaultPref would be overwritten; only a lock"
    echo "// keeps the list out of Sync in both directions. Other synced settings"
    echo "// and the user's own language choice in Settings stay unaffected."
    echo 'lockPref("services.sync.prefs.sync.intl.accept_languages", false);'
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
    echo "// topSitesRows=4 shows a four-row grid (up to 32 tiles depending on"
    echo "// window width); users can change it under Settings > Home."
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
# An exact count alone could accept duplicated or unrelated preferences.
EXPECTED_LOCK_PREFS=(
    'lockPref("browser.profiles.enabled", false);'
    'lockPref("browser.profiles.created", false);'
    'lockPref("browser.newtabpage.activity-stream.default.sites", "");'
    'lockPref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts", false);'
    'lockPref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts.havePinned", "");'
    'lockPref("services.sync.prefs.sync.intl.accept_languages", false);'
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
assert toolbar["currentVersion"] == 26
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
# OS-locale flow-through: empty intl.locale.requested lets Firefox negotiate
# the OS locale, install the matching staged RPM langpack into the profile and
# keep it enabled (autoDisableScopes=10 leaves profile scope enabled). MUST
# live in a system-pref file (read BEFORE mozilla.cfg) — rationale + refs in
# the deployed NOID_LOCALE_JS_EOF heredoc. Pairs with Step 3d langpack staging.

log "Step 3c/8: Installing /usr/lib64/firefox/defaults/pref/noid-locale.js (locale flow-through)"

cat > "${AUTOCONFIG_PREF_DIR}/noid-locale.js" <<'NOID_LOCALE_JS_EOF'
// NoID Privacy Workstation 44 — system-locale flow-through (defense-in-depth)
// An empty intl.locale.requested makes Firefox negotiate the OS locale
// (LANG/LC_* via its OS preferences) instead of a fixed UI language.
// Reference: Mozilla Bug 1423532 + Debian Bug #997841.
// MUST be in system-pref-file (NOT user.js or mozilla.cfg) — Firefox Init-timing
// reads system-prefs BEFORE mozilla.cfg, so empty here lets locale-init
// fall back to the OS locale.
// No JS, no sandbox-bypass, no env-var access from JS context.
// Paired with the per-locale langpack staging in distribution/extensions:
// Firefox installs only the negotiated pack (for example fr_FR -> the fr
// langpack) into the profile, where extensions.autoDisableScopes=10 in
// user.js keeps profile-scope add-ons enabled.
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
# Step 3d: Stage Firefox langpacks per locale below distribution/extensions/
#------------------------------------------------------------------------------
# The firefox-langpacks RPM path (/usr/lib64/firefox/langpacks/) is NOT
# scanned since FF91 — the XPIs sit inert. Firefox installs distribution
# add-ons into each new profile (profile scope): an XPI directly below
# distribution/extensions would reach EVERY profile, while the
# locale-<tag>/ sub-directories are negotiated against the requested (OS)
# locales, so only the matching language pack is installed. RPM alias
# symlinks (for example es -> es-AR) are not staged: their archives carry the
# regional add-on ID and the negotiation already maps a generic OS locale to
# a regional directory. Without this, the Step-3c locale flow-through has no
# langpack to activate and the UI stays en-US. Step 6f re-converges the tree
# against the signed firefox-langpacks payload.
log "Step 3d/8: Stage Firefox langpacks per locale (distribution/extensions/locale-<tag>/)"

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
    [ -f "$_lp" ] && [ ! -L "$_lp" ] || continue
    _lp_name=${_lp##*/}
    _lp_tag=${_lp_name#langpack-}
    _lp_tag=${_lp_tag%@firefox.mozilla.org.xpi}
    if [ "langpack-${_lp_tag}@firefox.mozilla.org.xpi" != "$_lp_name" ] || \
       [[ ! "$_lp_tag" =~ ^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$ ]]; then
        log "  FAIL: unexpected Firefox langpack name: $_lp_name"
        exit 1
    fi
    install -d -m 0755 "$FIREFOX_DIST_EXT/locale-$_lp_tag"
    install -m 0644 "$_lp" "$FIREFOX_DIST_EXT/locale-$_lp_tag/$_lp_name"
    _lp_count=$((_lp_count + 1))
done

# SELinux context for the new distribution tree (M16 defense-in-depth pattern)
command -v restorecon >/dev/null 2>&1 && restorecon -R "${FIREFOX_LIB_DIR}/distribution" 2>/dev/null || true

if [ "$_lp_count" -eq 0 ]; then
    log "  FAIL: no langpack-*.xpi found in $FIREFOX_LANGPACK_SRC"
    exit 1
fi
log "  Staged ${_lp_count} Firefox langpacks below distribution/extensions/locale-<tag>/ (each new profile installs only the negotiated OS-locale pack)"

#------------------------------------------------------------------------------
# Step 4: Fetch uBlock Origin XPI to system-scope staging path
#------------------------------------------------------------------------------
# The System-scope path is a stable STAGING location only — the setup
# script (Step 6) copies the verified XPI profile-local. Do NOT re-litigate:
# FF150 distribution-bundled scan does NOT auto-install regular extensions
# (verified across all launch modes), and policies.json
# ExtensionSettings triggers the "managed by your organization" UI hint.
# autoDisableScopes=10 keeps profile-scope XPIs (the uBO copy and the
# distribution-installed langpack) auto-enabled.

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

Usage: validate-webextension.py ARCHIVE ID VERSION REQUIRE_SIGNATURE PRODUCT_VERSION [ALLOW_MISSING_ID [COMPATIBILITY_FILE]]
Use '-' for any archive version or for no product-compatibility check. On
success the exact manifest version is printed; every failure is non-zero.
"""

import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
import sys
import zipfile

if len(sys.argv) not in {6, 7, 8}:
    raise SystemExit(2)

archive, expected_id, expected_version, signature_arg, product_version = sys.argv[1:6]
allow_missing_arg = sys.argv[6] if len(sys.argv) >= 7 else "0"
compatibility_file = sys.argv[7] if len(sys.argv) == 8 else "-"
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
    minimum, maximum = gecko.get("strict_min_version"), gecko.get("strict_max_version")
    # Marketplaces can extend compatibility without replacing an XPI. Accept
    # only an authenticated caller-supplied native update record bound to the
    # exact archive, ID and version. The archive itself remains unchanged.
    if compatibility_file != "-":
        metadata_stat = os.lstat(compatibility_file)
        if not stat.S_ISREG(metadata_stat.st_mode) or not 0 < metadata_stat.st_size <= 1048576:
            raise SystemExit("unsafe compatibility metadata")
        with open(compatibility_file, encoding="utf-8") as source:
            metadata = json.load(source)
        updates = metadata.get("addons", {}).get(expected_id, {}).get("updates", [])
        matches = [item for item in updates if item.get("version") == version]
        if len(matches) > 1:
            raise SystemExit("ambiguous compatibility metadata")
        if matches:
            update = matches[0]
            with open(archive, "rb") as source:
                digest = hashlib.file_digest(source, "sha256").hexdigest()
            if update.get("update_hash") != "sha256:" + digest:
                raise SystemExit("compatibility metadata archive digest mismatch")
            bounds = update.get("applications", {}).get("gecko", {})
            minimum = bounds.get("strict_min_version")
            maximum = bounds.get("strict_max_version")
            if not isinstance(minimum, str) or not version_pattern.fullmatch(minimum) \
                    or not isinstance(maximum, str) or not re.fullmatch(
                        r"\*|[0-9]+(?:[.][0-9]+)*(?:[.]\*)?", maximum):
                raise SystemExit("invalid compatibility metadata bounds")
    if product_version != "-" and not compatible(product_version, minimum, maximum):
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
# which also matches non-profile dirs: Crash Reports, Pending Pings,
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
NOID_FF_RELAX_FPP_SITES_BEGIN="// NOID-RELAX-FPP-SITES-BEGIN"
NOID_FF_RELAX_FPP_SITES_END="// NOID-RELAX-FPP-SITES-END"
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

# Report whether any Firefox profile registry exists: the XDG root or the
# legacy ~/.mozilla/firefox tree that Firefox still honours.
firefox_profile_registry_present() {
    local path
    for path in "$(firefox_root)/profiles.ini" "$HOME/.mozilla/firefox/profiles.ini"; do
        if [ -e "$path" ] || [ -L "$path" ]; then
            return 0
        fi
    done
    return 1
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
# Result: global array NOID_FF_LAUNCH_ARGS. Without any profile registry the
# invocation stays native so Firefox can create its first profiles. With a
# registry, an unresolved ordinary default is a hard failure; an unresolved
# explicit named profile remains user-owned and is passed through unchanged.
# shellcheck disable=SC2034  # NOID_FF_LAUNCH_ARGS is read by the sourcing launcher.
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

    # An account without any Firefox profile registry keeps Firefox's native
    # first-run semantics, so Firefox creates and registers its own profiles.
    # Once a registry exists, ordinary launches bind the hardened
    # default-release profile by path or refuse.
    if ! firefox_profile_registry_present; then
        NOID_FF_LAUNCH_ARGS=("${original[@]}")
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

# The supported compatibility choices are emitted from this shared source so
# the opt-in CLIs, Update All and completeness checks cannot drift apart.
# The FPP relaxation narrows the fingerprinting-protection target list to the
# baseline set stock Firefox applies in its Standard mode. It cannot switch FPP
# off to reach that baseline: Firefox re-applies the Strict category set at
# every start, so an Enhanced Tracking Protection category preference in this
# block would be reverted. While FPP is on, Firefox ignores the baseline set
# entirely (nsRFPService::GetFingerprintingProtectionType), so an empty target
# list would leave less protection than an unhardened Firefox. The three
# targets are RFPTargetsDefaultBaseline.inc's desktop set at
# FIREFOX_156_0_RELEASE; tests/pre-ship/16-fpp-relaxation-runtime.sh compares
# them with the shipped binary's own baseline set.
noid_fpp_relaxation_block() {
    cat <<'NOID_FPP_RELAXATION_EOF'
// NOID-RELAX-FPP-BEGIN
// Created by noid-firefox-relax-fpp. Remove with:
//   noid-firefox-relax-fpp --restore
// This ONLY relaxes fingerprinting protection, to exactly the baseline targets
// stock Firefox applies in its Standard mode: efficient canvas randomization,
// available-screen and touch-point normalization. Enhanced Tracking Protection
// stays Strict. DNS policy, HTTPS-Only, password manager off, Mozilla AI off,
// Nimbus off, telemetry off — all stay active.
user_pref("privacy.fingerprintingProtection.overrides", "-AllTargets,+EfficientCanvasRandomization,+ScreenAvailToResolution,+MaxTouchPointsCollapse");
// NOID-RELAX-FPP-END
NOID_FPP_RELAXATION_EOF
}

# The exact block releases v1.5 to v1.8 emitted. It set the two Strict-category
# FPP preferences, which Firefox resets at every start, so it never relaxed
# anything. It is recognized only to retire it: the composition drops it
# instead of refusing the profile as altered, and the effective protection of
# that profile stays exactly what it was. Nothing emits it.
noid_fpp_relaxation_block_retired_v18() {
    cat <<'NOID_FPP_RELAXATION_RETIRED_V18_EOF'
// NOID-RELAX-FPP-BEGIN
// Created by noid-firefox-relax-fpp. Remove with:
//   noid-firefox-relax-fpp --restore
// This ONLY relaxes fingerprinting protection. DNS policy, HTTPS-Only, password
// manager off, Mozilla AI off, Nimbus off, telemetry off — all stay active.
user_pref("privacy.fingerprintingProtection", false);
user_pref("privacy.fingerprintingProtection.pbmode", false);
user_pref("privacy.resistFingerprinting", false);
// NOID-RELAX-FPP-END
NOID_FPP_RELAXATION_RETIRED_V18_EOF
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

# A per-site canvas exception lifts exactly the two targets that together make
# a first-party page read placeholder data back from its own canvas, which
# breaks in-browser image cropping and editors. Measured on Firefox 156, either
# target alone still returns placeholder pixels. The third-party extraction
# target stays on, so frames from other sites keep the block, and no other
# target changes.
NOID_FF_FPP_SITE_OVERRIDES="-CanvasImageExtractionPrompt,-CanvasExtractionBeforeUserInputIsBlocked"

# Firefox validates each granular override against its own JSON schema and
# drops a failing entry without any message. This is the schema's
# firstPartyDomain pattern, lower-case and without its "*" wildcard, so every
# emitted entry is one Firefox keeps.
noid_fpp_site_syntax_valid() {
    local domain="$1"
    case "$domain" in
        ''|*$'\n'*) return 1 ;;
    esac
    [ "${#domain}" -le 253 ] || return 1
    printf '%s\n' "$domain" | LC_ALL=C grep -Eqx \
        '([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}'
}

# Firefox keys an override by the registrable domain of the top-level page, so
# an entry naming a subdomain or a public suffix never matches. Print the
# registrable domain libpsl derives from the system public suffix list. Exit 1
# when the name is itself a public suffix, 2 when the list cannot be read.
noid_fpp_site_registrable_domain() {
    python3 - "$1" <<'NOID_FPP_SITE_PSL_PYEOF'
import ctypes
import sys

try:
    psl = ctypes.CDLL("libpsl.so.5")
except OSError:
    raise SystemExit(2)
psl.psl_latest.restype = ctypes.c_void_p
psl.psl_latest.argtypes = [ctypes.c_char_p]
psl.psl_registrable_domain.restype = ctypes.c_char_p
psl.psl_registrable_domain.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
psl.psl_free.restype = None
psl.psl_free.argtypes = [ctypes.c_void_p]
host = sys.argv[1].encode("ascii")
context = psl.psl_latest(None)
if not context:
    raise SystemExit(2)
try:
    registrable = psl.psl_registrable_domain(context, host)
finally:
    psl.psl_free(context)
if not registrable:
    raise SystemExit(1)
print(registrable.decode("ascii"))
NOID_FPP_SITE_PSL_PYEOF
}

# Emit the per-site block for a strictly ascending, duplicate-free site list.
# One "// site:" record per generated entry lets the state check recover the
# list and regenerate the block byte-exactly.
noid_fpp_site_relaxation_block() {
    local domain json="" separator=""
    [ "$#" -gt 0 ] || return 1
    for domain in "$@"; do
        noid_fpp_site_syntax_valid "$domain" || return 1
    done
    [ "$(printf '%s\n' "$@")" = "$(printf '%s\n' "$@" | LC_ALL=C sort -u)" ] \
        || return 1
    printf '%s\n' \
        "$NOID_FF_RELAX_FPP_SITES_BEGIN" \
        '// Created by noid-firefox-relax-fpp --site. Remove a site with:' \
        '//   noid-firefox-relax-fpp --site-restore <domain>' \
        '// This ONLY lifts the canvas readback block on the sites listed below, so' \
        '// their pages can read back their own canvas pixels (in-browser image' \
        '// cropping and editors). Each entry covers the whole registrable domain.' \
        '// Frames from other sites keep the block. No other fingerprinting' \
        '// protection target changes.'
    for domain in "$@"; do
        printf '// site: %s\n' "$domain"
        json+="$separator{\\\"firstPartyDomain\\\":\\\"$domain\\\",\\\"overrides\\\":\\\"$NOID_FF_FPP_SITE_OVERRIDES\\\"}"
        separator=","
    done
    printf 'user_pref("privacy.fingerprintingProtection.granularOverrides", "[%s]");\n' \
        "$json"
    printf '%s\n' "$NOID_FF_RELAX_FPP_SITES_END"
}

# Print the sites of a byte-exact per-site block, one per line, or nothing when
# the file has no block. A block that does not regenerate byte-exactly from its
# own site records is altered and fails closed, like the fixed blocks above.
noid_fpp_relaxation_sites() {
    local path="$1" block
    local -a sites=()
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        return 0
    fi
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    validate_noid_marker_pair "$path" \
        "$NOID_FF_RELAX_FPP_SITES_BEGIN" "$NOID_FF_RELAX_FPP_SITES_END" \
        || return 1
    grep -Fxq -- "$NOID_FF_RELAX_FPP_SITES_BEGIN" "$path" || return 0
    block=$(awk -v B="$NOID_FF_RELAX_FPP_SITES_BEGIN" \
            -v E="$NOID_FF_RELAX_FPP_SITES_END" '
            $0 == B { capture=1 }
            capture { print }
            capture && $0 == E { exit }
        ' "$path") || return 1
    mapfile -t sites < <(printf '%s\n' "$block" | sed -n 's|^// site: ||p')
    [ "${#sites[@]}" -gt 0 ] || return 1
    cmp -s <(printf '%s\n' "$block") \
        <(noid_fpp_site_relaxation_block "${sites[@]}") || return 1
    printf '%s\n' "${sites[@]}"
}

# Print disabled/enabled only when a marker pair is absent or byte-exactly one
# of the supported blocks above. An optional retired block a caller names reads
# as disabled, so it is dropped rather than carried forward. Malformed or
# altered blocks are never silently carried into a regenerated security
# configuration.
noid_supported_relaxation_state() {
    local path="$1" begin="$2" end="$3" emitter="$4" retired_emitter="${5:-}"
    local block
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
    block=$(awk -v B="$begin" -v E="$end" '
            $0 == B { capture=1 }
            capture { print }
            capture && $0 == E { exit }
        ' "$path") || return 1
    if cmp -s <(printf '%s\n' "$block") <("$emitter"); then
        printf '%s\n' enabled
        return 0
    fi
    [ -n "$retired_emitter" ] || return 1
    cmp -s <(printf '%s\n' "$block") <("$retired_emitter") || return 1
    printf '%s\n' disabled
}

# Re-emit the supported compatibility blocks in their one canonical
# FPP, WebRTC, per-site order while preserving every unrelated user.js line.
# The FPP and WebRTC choices are enabled, disabled, or preserve. The per-site
# choice is preserve (the default) or set followed by the complete new site
# list; an empty list removes the block. The current blocks must be exact even
# when the caller is changing only another choice.
compose_userjs_relaxation_choice() {
    [ "$#" -ge 3 ] || return 1
    local path="$1" fpp_choice="$2" webrtc_choice="$3" sites_choice="${4:-preserve}"
    local current_fpp current_webrtc current_sites fpp_state webrtc_state
    local -a sites=()
    shift "$(( $# < 4 ? 3 : 4 ))"
    current_fpp=$(noid_supported_relaxation_state "$path" \
        "$NOID_FF_RELAX_FPP_BEGIN" "$NOID_FF_RELAX_FPP_END" \
        noid_fpp_relaxation_block noid_fpp_relaxation_block_retired_v18) \
        || return 1
    current_webrtc=$(noid_supported_relaxation_state "$path" \
        "$NOID_FF_RELAX_WEBRTC_BEGIN" "$NOID_FF_RELAX_WEBRTC_END" \
        noid_webrtc_relaxation_block) || return 1
    current_sites=$(noid_fpp_relaxation_sites "$path") || return 1
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
    case "$sites_choice" in
        preserve)
            [ "$#" -eq 0 ] || return 1
            [ -z "$current_sites" ] || mapfile -t sites <<< "$current_sites"
            ;;
        set) sites=("$@") ;;
        *) return 1 ;;
    esac
    awk -v FB="$NOID_FF_RELAX_FPP_BEGIN" \
        -v FE="$NOID_FF_RELAX_FPP_END" \
        -v WB="$NOID_FF_RELAX_WEBRTC_BEGIN" \
        -v WE="$NOID_FF_RELAX_WEBRTC_END" \
        -v SB="$NOID_FF_RELAX_FPP_SITES_BEGIN" \
        -v SE="$NOID_FF_RELAX_FPP_SITES_END" '
        $0 == FB || $0 == WB || $0 == SB { skip=1; next }
        skip && ($0 == FE || $0 == WE || $0 == SE) { skip=0; next }
        !skip { print }
    ' "$path" || return 1
    if [ "$fpp_state" = enabled ]; then
        noid_fpp_relaxation_block || return 1
    fi
    if [ "$webrtc_state" = enabled ]; then
        noid_webrtc_relaxation_block || return 1
    fi
    if [ "${#sites[@]}" -gt 0 ]; then
        noid_fpp_site_relaxation_block "${sites[@]}" || return 1
    fi
}

# Emit the complete supported user.js state without publishing it.
# preserve-supported keeps only exact NoID Privacy compatibility blocks.
# reset-relaxations is reserved for an explicit harden-profile --force action.
compose_supported_userjs() {
    local name="$1" pdir="$2" mode="${3:-preserve-supported}"
    local userjs="$pdir/user.js" drm_state fpp_state webrtc_state sites_state
    local -a sites=()
    [ -f "$NOID_FF_USERJS_BASE" ] && [ ! -L "$NOID_FF_USERJS_BASE" ] || return 1
    case "$mode" in
        preserve-supported)
            fpp_state=$(noid_supported_relaxation_state "$userjs" \
                "$NOID_FF_RELAX_FPP_BEGIN" "$NOID_FF_RELAX_FPP_END" \
                noid_fpp_relaxation_block \
                noid_fpp_relaxation_block_retired_v18) || return 1
            webrtc_state=$(noid_supported_relaxation_state "$userjs" \
                "$NOID_FF_RELAX_WEBRTC_BEGIN" "$NOID_FF_RELAX_WEBRTC_END" \
                noid_webrtc_relaxation_block) || return 1
            sites_state=$(noid_fpp_relaxation_sites "$userjs") || return 1
            [ -z "$sites_state" ] || mapfile -t sites <<< "$sites_state"
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
    if [ "${#sites[@]}" -gt 0 ]; then
        noid_fpp_site_relaxation_block "${sites[@]}" || return 1
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

# The profile and its subdirectories are owner-only from the start: useradd
# copies /etc/skel with its modes, and the cp -a below copies the source
# directory's mode onto every seeded Live profile.
mkdir -p "$SKEL_FF_BASE"
install -d -m 0700 "$SKEL_FF_PROFILE" \
    "$SKEL_FF_PROFILE/extensions" "$SKEL_FF_PROFILE/bookmarkbackups"

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
# and every directory inside it are 700 — once the user runs Firefox it holds
# cookies.sqlite / key4.db / cert9.db / places.sqlite / session state, which
# must not be world-readable. Matches the Module 34 playground-profile
# convention. The 755 pass prunes the profile so it cannot reopen the
# subdirectories created owner-only above.
chown -R root:root "$SKEL_FF_BASE"
chmod -R go-w "$SKEL_FF_BASE"
find "$SKEL_FF_BASE" -path "$SKEL_FF_PROFILE" -prune -o -type d -exec chmod 755 {} +
find "$SKEL_FF_PROFILE" -type d -exec chmod 700 {} +

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
    # Profile directories stay owner-only (future cookies/keys/history): cp -a
    # carries the skel source directory's mode onto bookmarkbackups.
    chmod 700 "$target_base/default-release" \
        "$target_base/default-release/extensions" \
        "$target_base/default-release/bookmarkbackups"
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
#      If none, run the signed vendor launcher `/usr/bin/firefox --headless
#      --no-remote --new-instance` for ~6s so Firefox creates and registers its
#      native first-run profiles, then re-detect.
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
VENDOR_FIREFOX="/usr/bin/firefox"
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
        # The signed vendor launcher creates Firefox's native first-run
        # profiles; the owned /usr/local launcher has no default-release
        # target to bind yet. Silent-launch on about:newtab (NOT about:blank)
        # so the Activity Stream React app warm-starts and caches its initial
        # state; otherwise the user's first real launch shows a blank page
        # (no logo, no search box, no tile grid) until a second launch.
        timeout 8 env MOZ_HEADLESS=1 "$VENDOR_FIREFOX" --headless --no-remote --new-instance about:newtab \
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
        "Firefox created no detectable profile. Setup aborted — run 'firefox --ProfileManager' to create the default-release profile, then run noid-firefox-setup.sh again."
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
    # A byte-exact shared-library composition may include any supported
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
    # Preserve only a structurally valid, correctly identified payload that
    # carries a Mozilla signature container (Firefox verifies the signature
    # itself at load); never bless an arbitrary pre-positioned file as
    # setup-complete.
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

# M34 sends the single combined first-login notification for both profiles;
# no stamp handoff exists between M16 and M34 (the chained call below orders
# them).

log "setup complete"

# Profile-local work is complete. Release the shared lock before chaining the
# independent playground transaction, which acquires the same lock itself.
flock -u 9
exec 9>&-

# Do not clean up arbitrary user Firefox processes here: a broad pkill could
# terminate a browser the user opened during first-login setup. The setup path
# only kills and waits for its own $FF_PID.

# Chain to playground-init for deterministic
# sequencing. Both XDG autostart hooks (firefox-setup + firefox-playground-init)
# fire in PARALLEL at GNOME login. Chaining from setup-script end guarantees:
# setup-script done → state written → THEN playground-init.
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
# block — ONLY relaxes the fingerprinting protection layer, and only down to
# the baseline targets stock Firefox applies in its Standard mode. Its --site
# mode instead lifts only the canvas readback block on one registrable domain.

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
#   // NOID-RELAX-FPP-SITES-BEGIN ... -END — per-site canvas exceptions
#
# Profile discovery: registered profiles only (parsed from profiles.ini
# via the shared helper) — never scans non-profile dirs (Crash Reports,
# Pending Pings, Profile Groups, firefox-mpris).
#
# Usage:
#   noid-firefox-relax-fpp                         # relax all registered profiles
#   noid-firefox-relax-fpp --restore               # remove only the exact marked block
#   noid-firefox-relax-fpp --site <domain>         # canvas exception for one site
#   noid-firefox-relax-fpp --site-restore <domain> # remove that site's exception
#   noid-firefox-relax-fpp --sites                 # list site exceptions
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

if [ "$#" -gt 2 ]; then
    echo "ERROR: expected at most one action and one domain (try --help)" >&2
    exit 2
fi
ACTION="${1:-apply}"
SITE=""

case "$ACTION" in
    --site|--site-restore)
        if [ "$#" -ne 2 ]; then
            echo "ERROR: $ACTION needs exactly one domain, for example:" >&2
            echo "  noid-firefox-relax-fpp $ACTION youtube.com" >&2
            exit 2
        fi
        case "$2" in
            *$'\n'*) ;;
            *) SITE=$(printf '%s' "$2" | LC_ALL=C tr 'A-Z' 'a-z') ;;
        esac
        if ! noid_fpp_site_syntax_valid "$SITE"; then
            echo "ERROR: not a plain domain name Firefox accepts for a site exception." >&2
            echo "       Give the bare site domain, for example:" >&2
            echo "  noid-firefox-relax-fpp $ACTION youtube.com" >&2
            exit 2
        fi
        ;;
    *)
        if [ "$#" -gt 1 ]; then
            echo "ERROR: expected zero arguments or one action (try --help)" >&2
            exit 2
        fi
        ;;
esac

case "$ACTION" in
    --help|-h)
        cat <<HELP
noid-firefox-relax-fpp — relax Firefox fingerprinting protection for site
compatibility to the baseline targets stock Firefox applies in its Standard
mode (efficient canvas randomization, available-screen and touch-point
normalization), never below them. Keeps Enhanced Tracking Protection Strict,
the DNS policy, HTTPS-Only, password manager disabled, telemetry off, Mozilla
AI off, uBlock Origin active.

Patches user.js in each registered Firefox profile with a marked block.
Close Firefox before running. Restart Firefox to apply.

Usage:
  noid-firefox-relax-fpp           # apply relaxation
  noid-firefox-relax-fpp --restore # remove only the exact marked block

Per-site canvas exception: when one site's in-browser image cropping or
editing produces striped or noisy images, lift only the canvas readback block
on that site instead of relaxing every site.
  noid-firefox-relax-fpp --site <domain>          # add the exception
  noid-firefox-relax-fpp --site-restore <domain>  # remove it again
  noid-firefox-relax-fpp --sites                  # list exceptions per profile
<domain> is the site's registrable domain, for example youtube.com; it covers
subdomains such as studio.youtube.com. Frames from other sites keep the block.
The listed site can then read a canvas fingerprint. A page Firefox restores at
startup may need one reload before the exception applies.
HELP
        exit 0
        ;;
    --restore|restore)
        ACTION_MODE=restore
        ;;
    apply|"")
        ACTION_MODE=apply
        ;;
    --site)
        ACTION_MODE=site-add
        ;;
    --site-restore)
        ACTION_MODE=site-remove
        ;;
    --sites)
        ACTION_MODE=site-list
        ;;
    *)
        echo "Unknown action: $ACTION (try --help)" >&2
        exit 1
        ;;
esac

# Firefox keys a site exception by the top-level page's registrable domain, so
# an entry for a subdomain or a public suffix would be inert. Refuse it here
# instead of writing an exception that silently does nothing.
if [ "$ACTION_MODE" = site-add ]; then
    if REGISTRABLE=$(noid_fpp_site_registrable_domain "$SITE"); then
        PSL_RC=0
    else
        PSL_RC=$?
    fi
    case "$PSL_RC" in
        0)
            if [ "$REGISTRABLE" != "$SITE" ]; then
                echo "ERROR: Firefox applies a site exception to a whole registrable domain;" >&2
                echo "       an entry for $SITE would never match. Use:" >&2
                echo "  noid-firefox-relax-fpp --site $REGISTRABLE" >&2
                exit 2
            fi
            ;;
        1)
            echo "ERROR: $SITE is a public suffix shared by many sites, not one site." >&2
            exit 2
            ;;
        *)
            echo "ERROR: cannot read the system public suffix list (libpsl); nothing changed." >&2
            exit 1
            ;;
    esac
fi

# Listing is read-only and stays available while Firefox runs.
if [ "$ACTION_MODE" != site-list ]; then
    if ! acquire_firefox_profile_lock; then
        echo "Another Firefox profile operation is active; retry later." >&2
        exit 75
    fi

    if firefox_process_active; then
        echo "Firefox is running. Close all Firefox windows and retry." >&2
        exit 1
    fi
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
SITES_REMAIN=0
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

    if ! current_sites=$(noid_fpp_relaxation_sites "$pdir/user.js"); then
        echo "ERROR: $name has an altered or malformed site-exception block; file preserved" >&2
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
                    "$NOID_FF_RELAX_WEBRTC_BEGIN" "$NOID_FF_RELAX_WEBRTC_END" || \
               ! validate_noid_marker_pair "$pdir/user.js" \
                    "$NOID_FF_RELAX_FPP_SITES_BEGIN" "$NOID_FF_RELAX_FPP_SITES_END"; then
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
            [ -z "$current_sites" ] || SITES_REMAIN=1
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
                    "$NOID_FF_RELAX_WEBRTC_BEGIN" "$NOID_FF_RELAX_WEBRTC_END" || \
               ! validate_noid_marker_pair "$pdir/user.js" \
                    "$NOID_FF_RELAX_FPP_SITES_BEGIN" "$NOID_FF_RELAX_FPP_SITES_END"; then
                rm -f -- "$tmpf"
                echo "ERROR: atomic FPP restore failed for $name" >&2
                FAILED=$((FAILED + 1))
                continue
            fi
            rm -f -- "$tmpf"
            echo "Restored: $name → preserved unrelated user.js lines (backup: $(basename "$backup"))"
            COUNT=$((COUNT + 1))
            ;;
        site-list)
            if [ -n "$current_sites" ]; then
                echo "$name: $(printf '%s\n' "$current_sites" | paste -sd ' ' -)"
            else
                echo "$name: no site exceptions"
            fi
            COUNT=$((COUNT + 1))
            ;;
        site-add|site-remove)
            listed=0
            if printf '%s\n' "$current_sites" | grep -Fxq -- "$SITE"; then
                listed=1
            fi
            if [ "$ACTION_MODE" = site-add ] && [ "$listed" -eq 1 ]; then
                echo "Already listed: $name ($SITE)"
                COUNT=$((COUNT + 1))
                continue
            fi
            if [ "$ACTION_MODE" = site-remove ] && [ "$listed" -eq 0 ]; then
                echo "Not listed: $name ($SITE)"
                COUNT=$((COUNT + 1))
                continue
            fi
            new_sites=()
            if [ "$ACTION_MODE" = site-add ]; then
                mapfile -t new_sites < <(
                    { [ -z "$current_sites" ] || printf '%s\n' "$current_sites"
                      printf '%s\n' "$SITE"; } | LC_ALL=C sort -u)
            else
                mapfile -t new_sites < <(printf '%s\n' "$current_sites" | \
                    grep -Fxv -e "$SITE" -e '' || true)
            fi
            tmpf=$(mktemp "$pdir/.user.js.site-fpp.XXXXXXXX")
            if ! compose_userjs_relaxation_choice \
                    "$pdir/user.js" preserve preserve set "${new_sites[@]}" > "$tmpf" || \
               ! backup=$(backup_noid_userjs "$pdir/user.js") || \
               ! noid_atomic_install_file "$tmpf" "$pdir/user.js" 600 || \
               ! validate_noid_marker_pair "$pdir/user.js" "$MARK_BEGIN" "$MARK_END" || \
               ! validate_noid_marker_pair "$pdir/user.js" \
                    "$NOID_FF_RELAX_WEBRTC_BEGIN" "$NOID_FF_RELAX_WEBRTC_END" || \
               ! validate_noid_marker_pair "$pdir/user.js" \
                    "$NOID_FF_RELAX_FPP_SITES_BEGIN" "$NOID_FF_RELAX_FPP_SITES_END"; then
                rm -f -- "$tmpf"
                echo "ERROR: atomic site-exception update failed for $name" >&2
                FAILED=$((FAILED + 1))
                continue
            fi
            rm -f -- "$tmpf"
            if [ "$ACTION_MODE" = site-add ]; then
                echo "Canvas exception added: $name → $SITE (backup: $(basename "$backup"))"
            else
                echo "Canvas exception removed: $name → $SITE (backup: $(basename "$backup"))"
            fi
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
        apply)       echo "No registered Firefox profile found. Nothing to relax." >&2 ;;
        restore)     echo "No registered Firefox profile found. Nothing to restore." >&2 ;;
        site-add)    echo "No registered Firefox profile found. Nothing to change." >&2 ;;
        site-remove) echo "No registered Firefox profile found. Nothing to restore." >&2 ;;
        site-list)   echo "No registered Firefox profile found." >&2 ;;
    esac
    exit 1
fi

[ "$ACTION_MODE" != site-list ] || exit 0

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
        if [ "$SITES_REMAIN" -eq 1 ]; then
            echo "Per-site canvas exceptions stay; list them with: noid-firefox-relax-fpp --sites"
        fi
        ;;
    site-add)
        echo "Done. Canvas exception for $SITE in $COUNT profile(s)."
        echo "Restart Firefox for change to apply."
        echo ""
        echo "To remove it again:"
        echo "  noid-firefox-relax-fpp --site-restore $SITE"
        ;;
    site-remove)
        echo "Done. No canvas exception for $SITE in $COUNT profile(s)."
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
                    "$NOID_FF_RELAX_FPP_BEGIN" "$NOID_FF_RELAX_FPP_END" || \
               ! validate_noid_marker_pair "$pdir/user.js" \
                    "$NOID_FF_RELAX_FPP_SITES_BEGIN" "$NOID_FF_RELAX_FPP_SITES_END"; then
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
                    "$NOID_FF_RELAX_FPP_BEGIN" "$NOID_FF_RELAX_FPP_END" || \
               ! validate_noid_marker_pair "$pdir/user.js" \
                    "$NOID_FF_RELAX_FPP_SITES_BEGIN" "$NOID_FF_RELAX_FPP_SITES_END"; then
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
image-scope overrides: provider-compatible DNS, FPP, Mozilla AI block, Nimbus clear, LNA, etc.;
Firefox 153's native QWAC verification/display remains enabled on desktop because
`@IS_NOT_ANDROID@` resolves to true there and false on Android), and
**uBlock Origin** (reviewed pinned release as first-install seed) pre-configured
via Managed Storage Manifest. After that seed, the extension is yours: the image
never downgrades your profile copy. The privacy defaults disable automatic
add-on update checks (no background executable-extension refresh). The current
Mozilla-signed release is fetched only when you explicitly start
`noid-update-all.sh`; the workflow resolves it through AMO's
compatibility-filtered official API and verifies the API-bound size and
SHA-256, archive identity/version/compatibility, Firefox's native signature
state and the no-downgrade postcondition, then records SHA-256 evidence. The same run enumerates every profile-owned extension in every
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
  for extensions. NoID Privacy does not set a catch-all `browser.ml.enable=false`
  override: Firefox's native AI Controls do not reverse it,
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
- Web-content language list stays **per machine**: AutoConfig locks
  `services.sync.prefs.sync.intl.accept_languages` to `false`. Firefox Sync
  syncs that list by default, so signing in on a new installation would
  otherwise import a list stored in the account (for example the English list
  above) instead of deriving it from this system's locale. The list is neither
  imported nor uploaded; every other synced setting is unchanged, and a list
  chosen in Settings still applies locally. A value Sync already imported stays
  until the one-time reset above.

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
- **uBlock Origin** (reviewed seed staged under `/usr/lib64/mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/`, installed profile-locally into each managed profile, plus a managed-storage manifest)
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
- In-browser image cropping (for example YouTube Studio banners and profile
  pictures) — striped or noisy uploads; the per-site `--site` exception below
  fixes this for one site
- WebGL configurators (car/furniture 3D viewers, online games) — distorted textures
- Sites that use browser fingerprint for DRM validation
- Draw/3D tools that read back Canvas/WebGL pixels

### Usage

```bash
# Close Firefox first (script will check), then:
noid-firefox-relax-fpp              # apply: stock-Firefox baseline targets in all registered profiles
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
// This ONLY relaxes fingerprinting protection, to exactly the baseline targets
// stock Firefox applies in its Standard mode: efficient canvas randomization,
// available-screen and touch-point normalization. Enhanced Tracking Protection
// stays Strict. DNS policy, HTTPS-Only, password manager off, Mozilla AI off,
// Nimbus off, telemetry off — all stay active.
user_pref("privacy.fingerprintingProtection.overrides", "-AllTargets,+EfficientCanvasRandomization,+ScreenAvailToResolution,+MaxTouchPointsCollapse");
// NOID-RELAX-FPP-END
```

Because Firefox processes `user.js` top-to-bottom and the last value wins,
the marked block replaces the canonical FPP target list with the three
baseline targets. FPP itself and the Strict Enhanced Tracking Protection
category stay switched on: Firefox re-applies the Strict category preferences
at every start, so the block deliberately changes only the target list.

While FPP is on, Firefox ignores its own baseline set and applies only this
list, so an empty list would leave less protection than an unhardened
Firefox. The block therefore names the baseline set explicitly. The canonical
list's full canvas and WebGL randomization, font restriction, fdlibm math and
hardware-concurrency targets are lifted, and the profile keeps exactly what
stock Firefox keeps in Standard mode, including its lighter efficient canvas
randomization. A site that still breaks also breaks in stock Firefox, apart
from Mozilla's remote per-site exemptions, which NoID Privacy keeps disabled.
Releases v1.5 to v1.8 wrote a block that switched the Strict-category FPP
preferences off; Firefox resets those at every start, so it never relaxed
anything. Update All and both relaxation commands remove that block without
changing the profile's effective protection; run `noid-firefox-relax-fpp`
again to relax the profile.

> **Why marked-block-in-user.js, not a separate overlay file**:
> Firefox does NOT load arbitrary `*.js` files from a profile's
> root — only `prefs.js` (engine-managed) and `user.js` (user overrides).
> Patching `user.js` itself with a marked block is what makes the relaxation
> take effect. `--restore` strips only that validated block, preserving all
> unrelated profile-owned lines.

### What stays active after applying the relaxation

**Only the FPP target list is relaxed**, to the stock-Firefox baseline —
every other layer remains intact:

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
Firefox — the canonical FPP target list is active again.

### One site only: `--site`

When one site's in-browser image cropping or editing produces striped or
noisy images, Firefox is returning placeholder data instead of the real pixels
while the page reads its own canvas back. Lift only that block, on that one
site, instead of relaxing every site:

```bash
# Close Firefox first (script will check), then:
noid-firefox-relax-fpp --site youtube.com          # add the exception
noid-firefox-relax-fpp --sites                     # list exceptions per profile
noid-firefox-relax-fpp --site-restore youtube.com  # remove it again
```

Name the site's registrable domain; the exception covers its subdomains such
as `studio.youtube.com`. Firefox matches a site exception only against the
registrable domain of the top-level page and silently ignores an entry it does
not accept, so the command refuses a subdomain, a public suffix such as
`co.uk`, an IP address and any name outside Firefox's accepted pattern rather
than writing an exception that would do nothing.

The command adds one marked block to each registered profile's `user.js`.
For youtube.com it reads:

```
// NOID-RELAX-FPP-SITES-BEGIN
// Created by noid-firefox-relax-fpp --site. Remove a site with:
//   noid-firefox-relax-fpp --site-restore <domain>
// This ONLY lifts the canvas readback block on the sites listed below, so
// their pages can read back their own canvas pixels (in-browser image
// cropping and editors). Each entry covers the whole registrable domain.
// Frames from other sites keep the block. No other fingerprinting
// protection target changes.
// site: youtube.com
user_pref("privacy.fingerprintingProtection.granularOverrides", "[{\"firstPartyDomain\":\"youtube.com\",\"overrides\":\"-CanvasImageExtractionPrompt,-CanvasExtractionBeforeUserInputIsBlocked\"}]");
// NOID-RELAX-FPP-SITES-END
```

The two lifted targets are exactly what makes the readback return placeholder
data; either one alone does not help. Frames from other sites embedded in the
listed site keep the block, and no other fingerprinting protection target
changes. The trade-off: the listed site can read a canvas fingerprint again.
Firefox keeps a removed `user.js` value in `prefs.js`, so the canonical
`user.js` sets this preference to an empty list before the block; removing the
last site therefore restores the block at the next start. The command owns
the preference, so a value set by hand in `about:config` is replaced at the
next start. A page Firefox restores at startup may need one reload before the
exception applies. `--restore` leaves site exceptions in place; remove each
with `--site-restore`.

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
  FPP, WebRTC and per-site compatibility blocks while refreshing the canonical
  base
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
first-run setup script (XDG autostart). An account without any Firefox profile
registry starts Firefox natively so Firefox can create its first profiles; once
a registry exists, a launch without a safe `default-release` profile stops
with a recovery hint (`firefox --ProfileManager`). An explicit DRM opt-in adds only the
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

# harden a specific profile by its exact profiles.ini Name (as shown in
# about:profiles)
noid-firefox-harden-profile work

# harden all safely repairable profiles; existing noncanonical user.js is skipped
noid-firefox-harden-profile --all

# keep one new/unhardened profile outside automatic enrollment
noid-firefox-harden-profile --exclude dev

# after review: replace user.js and reset FPP, WebRTC and per-site opt-ins
noid-firefox-harden-profile --force work
```

After running, **restart Firefox** to activate NoID Privacy Firefox Hardening
and the profile-local uBlock Origin extension in the hardened profile.
Subsequent `noid-update-all.sh` runs also initialize new safely registered
profiles with no `user.js`, then rebuild the canonical base plus any reviewed
DRM consent and byte-exact FPP, WebRTC and per-site compatibility opt-ins for all profiles
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
replaces that file and resets the supported FPP, WebRTC and per-site opt-ins to
the secure defaults. `--exclude` does not remove an already applied hardening
state; use the documented removal workflow first if that is the intent.

## Updates

- **NoID Privacy Firefox Hardening**: `noid-update-all.sh` (Module 25) Step 5
  initializes every safely registered new profile with no `user.js` unless it
  carries the explicit exclusion, and rebuilds every profile managed
  by NoID Privacy from `/usr/share/noid-firefox/user.js`, retaining only the exact
  reviewed DRM consent and FPP, WebRTC and per-site opt-ins (no external
  fetch, no arkenfox dependency — post-absorption)
- **uBlock Origin**: `noid-update-all.sh` updates every hardened profile to
  the current Mozilla-signed release resolved through AMO's official API;
  Firefox background add-on checks remain disabled
- **Other profile extensions**: `noid-update-all.sh` updates every AMO extension
  in every registered profile through the compatibility-filtered official API;
  built-in/system add-ons remain owned by the Firefox RPM transaction
- **Firefox itself**: updates via `dnf upgrade` (system package, not Mozilla's
  auto-updater)

## Troubleshooting

### Site says "Canvas check failed" / "WebGL renderer check failed"
→ `noid-firefox-relax-fpp` (temporary) + restart Firefox. After work,
`noid-firefox-relax-fpp --restore` + restart.

### Image cropped or edited in the browser uploads striped or noisy
→ `noid-firefox-relax-fpp --site <domain>` (for example `youtube.com`) +
restart Firefox. This lifts only the canvas readback block on that one site.
Remove it with `noid-firefox-relax-fpp --site-restore <domain>`.

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
#                                                and reset FPP, WebRTC, site opt-ins
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
        echo "  [INFO] --force resets supported FPP, WebRTC and per-site opt-ins for $target_name"
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
    echo "After review, --force replaces user.js and resets FPP, WebRTC and per-site opt-ins:"
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
echo "Tip: each user-started 'noid-update-all.sh' run reapplies the supported user.js composition."
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

# Exit status: 0 success, 1 failure, 2 usage. 75 (EX_TEMPFAIL) is a warning:
# everything else converged, but the signed firefox-langpacks payload has no
# regular language pack and the previously published packs, all still
# compatible with the installed Firefox, were kept. The DNF action maps it to
# success; Update All reports it as WARN.
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

# Re-assert the AutoConfig payload inside the firefox package tree from the
# canonical cache first. It carries the hardening policy and depends only on
# that cache, so a changed vendor anchor or a defective firefox-langpacks
# build (156.0.1-1.fc44 shipped only dangling aliases) must not block its
# repair. Preflight the complete source set before any publication: a
# partial/missing cache must make the DNF action fail visibly, not leave a
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
# A destination that already carries the staged bytes, mode, root ownership,
# single link and policy label keeps its inode. Replacing identical bytes
# would make every Update All and DNF action show up as AIDE drift.
converged_publication() {
    local staged=$1 destination=$2 mode=$3
    [ -f "$destination" ] && [ ! -L "$destination" ] \
        && [ "$(stat -c '%u:%g:%a:%h' -- "$destination" 2>/dev/null)" = "0:0:$mode:1" ] \
        && cmp -s -- "$staged" "$destination" \
        && { ! command -v matchpathcon >/dev/null 2>&1 \
             || matchpathcon -V "$destination" >/dev/null 2>&1; }
}
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
  echo "NoID Privacy: no safe default-release Firefox profile is registered." >&2
  echo "Recover with 'firefox --ProfileManager' (create or select default-release)," >&2
  echo "or start another profile with 'firefox -P <name>'." >&2
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
if converged_publication "$launcher_tmp" "$owned_launcher" 755; then
    rm -f -- "$launcher_tmp"
else
    sync -- "$launcher_tmp"
    mv -fT -- "$launcher_tmp" "$owned_launcher"
fi
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
if converged_publication "$desktop_tmp" "$owned_desktop" 644; then
    rm -f -- "$desktop_tmp"
else
    sync -- "$desktop_tmp"
    mv -fT -- "$desktop_tmp" "$owned_desktop"
fi
desktop_tmp=
rmdir -- "$desktop_stage_dir" \
    || fail "cannot remove private Firefox desktop staging directory"
desktop_stage_dir=
sync -- "$owned_desktop"; sync -- /usr/local/share/applications

# Converge distribution/extensions/ to one locale-<tag>/ directory per regular
# firefox-langpacks payload. Firefox installs every XPI placed directly below
# distribution/extensions into each new profile, but negotiates the
# locale-<tag>/ sub-directories against the requested (OS) locales, so only
# the matching language pack reaches a profile. These copies are not
# RPM-owned, so an update can otherwise leave stale entries, omit newly
# packaged locales, or retain old bytes that Firefox marks appDisabled after a
# browser major upgrade; a flat XPI left by an older layout is removed.
#
# Fedora also ships a small set of generic-locale aliases as relative
# symlinks (for example es -> es-AR). Their archives carry the regional add-on
# ID and Firefox's negotiation already maps a generic OS locale to a regional
# directory, so aliases are never published. Each alias must still match the
# signed RPM header exactly. Every published payload is a state-0,
# SHA-256-verified regular firefox-langpacks file; no link is ever followed
# and every destination remains a regular file below a real directory.
# This step runs last, and a rejected source set fails before any publication,
# so a defective langpack build keeps the previously published packs.
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

# Keys are destination paths relative to LPDST: locale-<tag>/<file name>.
declare -A source_langpack_paths=()
declare -A source_langpack_dirs=()
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
        continue
    elif [ -f "$_lp" ]; then
        verify_regular_langpack "$_lp" \
            || fail "Firefox langpack is not a pristine RPM payload: $_n"
        _tag=${_n#langpack-}
        _tag=${_tag%@firefox.mozilla.org.xpi}
        [ "langpack-${_tag}@firefox.mozilla.org.xpi" = "$_n" ] \
            && [[ "$_tag" =~ ^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$ ]] \
            || fail "Firefox langpack has an unexpected name: $_n"
        source_langpack_paths["locale-$_tag/$_n"]="$_lp"
        source_langpack_dirs["locale-$_tag"]=1
    else
        fail "Firefox langpack source has an unsupported file type: $_n"
    fi
done
# Preflight the destination before any publication or evaluation: no symlink
# anywhere, the legacy flat XPIs and every locale payload are regular files,
# and every locale-* entry is a real directory.
[ -z "$(find "$LPDST" -mindepth 1 -type l -print -quit)" ] \
    || fail "Firefox distribution extension tree contains a symlink"
published_langpacks=("$LPDST"/langpack-*.xpi "$LPDST"/locale-*/langpack-*.xpi)
for _lp in "${published_langpacks[@]}"; do
    [ -f "$_lp" ] \
        || fail "Firefox langpack destination is non-regular: $_lp"
done
for _lp_dir in "$LPDST"/locale-*; do
    [ -d "$_lp_dir" ] \
        || fail "Firefox langpack locale entry is not a directory: $_lp_dir"
done

# A source set without a regular payload is only a warning when the signed
# header itself declares none (Fedora's firefox-langpacks-156.0.1-1.fc44
# shipped nothing but dangling aliases) and every previously published pack
# still declares compatibility with the installed Firefox. A header-declared
# pack missing on disk, an empty published set or an incompatible pack stays a
# failure. Nothing below LPDST changes in any of these cases.
if [ "${#source_langpack_paths[@]}" -eq 0 ]; then
    header_regular_langpacks=$(printf '%s\n' "$langpack_rpm_manifest" \
        | awk -F '\t' -v dir="$LPSRC/" '
            index($1, dir) == 1 && $3 == "" \
                && substr($1, length(dir) + 1) ~ /^langpack-[^\/]*\.xpi$/ { count++ }
            END { print count + 0 }
        ')
    [ "$header_regular_langpacks" -eq 0 ] \
        || fail "firefox-langpacks declares language packs that are not installed; previously published language packs were kept"
    [ "${#published_langpacks[@]}" -gt 0 ] \
        || fail "installed firefox-langpacks package contains no regular language pack and none was published before"
    firefox_version=$(rpm -q --qf '%{VERSION}' firefox 2>/dev/null) \
        || fail "cannot read the installed Firefox version"
    [[ "$firefox_version" =~ ^[0-9]+(\.[0-9]+)*$ ]] \
        || fail "installed Firefox version is not a plain release version: $firefox_version"
    if ! python3 - "$firefox_version" "${published_langpacks[@]}" \
            <<'NOID_FF_LANGPACK_COMPAT_PYEOF'
import json
import sys
import zipfile


def version_key(version):
    key = []
    for part in version.split("."):
        if part == "*":
            key.append((float("inf"), 1, ""))
            continue
        digits = len(part) - len(part.lstrip("0123456789"))
        suffix = part[digits:]
        key.append((int(part[:digits] or 0), 0 if suffix else 1, suffix))
    return key


def compare(left, right):
    a, b = version_key(left), version_key(right)
    width = max(len(a), len(b))
    a += [(0, 1, "")] * (width - len(a))
    b += [(0, 1, "")] * (width - len(b))
    return (a > b) - (a < b)


application = sys.argv[1]
failures = 0
for path in sys.argv[2:]:
    try:
        with zipfile.ZipFile(path) as archive:
            info = archive.getinfo("manifest.json")
            if info.file_size > 1 << 20:
                raise ValueError("manifest.json is oversized")
            manifest = json.loads(archive.read(info).decode("utf-8"))
        settings = manifest.get("browser_specific_settings") if isinstance(manifest, dict) else None
        gecko = settings.get("gecko") if isinstance(settings, dict) else None
        low = gecko.get("strict_min_version") if isinstance(gecko, dict) else None
        high = gecko.get("strict_max_version") if isinstance(gecko, dict) else None
        if not isinstance(low, str) or not isinstance(high, str):
            raise ValueError("declares no strict Firefox version range")
        if compare(low, application) > 0 or compare(application, high) > 0:
            raise ValueError(f"supports Firefox {low} to {high} only")
    except (OSError, KeyError, ValueError, zipfile.BadZipFile) as error:
        print(f"{path}: {error}", file=sys.stderr)
        failures += 1
sys.exit(1 if failures else 0)
NOID_FF_LANGPACK_COMPAT_PYEOF
    then
        fail "installed firefox-langpacks package contains no regular language pack and the previously published language packs do not all support Firefox $firefox_version"
    fi
    langpack_warning="installed firefox-langpacks package contains no regular language pack; kept the ${#published_langpacks[@]} previously published language packs, which support Firefox $firefox_version"
    logger -t noid-firefox-reassert "WARNING: $langpack_warning"
    printf 'noid-firefox-reassert: WARNING: %s\n' "$langpack_warning" >&2
    exit 75
fi
mapfile -t source_langpack_names < <(
    printf '%s\n' "${!source_langpack_paths[@]}" | LC_ALL=C sort
)
for _rel in "${source_langpack_names[@]}"; do
    _lp=${source_langpack_paths[$_rel]}
    _lp_dir="$LPDST/${_rel%%/*}"
    install -d -m 0755 -o root -g root "$_lp_dir" \
        || fail "cannot create Firefox langpack directory: ${_rel%%/*}"
    langpack_tmp=$(mktemp "$_lp_dir/.noid-firefox-langpack.XXXXXX") \
        || fail "cannot stage Firefox langpack: $_rel"
    if ! install -m 0644 -o root -g root "$_lp" "$langpack_tmp"; then
        rm -f -- "$langpack_tmp"
        langpack_tmp=
        fail "cannot stage Firefox langpack: $_rel"
    fi
    if command -v restorecon >/dev/null 2>&1; then
        restorecon -F "$langpack_tmp" \
            || { rm -f -- "$langpack_tmp"; langpack_tmp=; fail "cannot label Firefox langpack: $_rel"; }
    fi
    if converged_publication "$langpack_tmp" "$LPDST/$_rel" 644; then
        rm -f -- "$langpack_tmp"
        langpack_tmp=
        continue
    fi
    sync -- "$langpack_tmp"
    mv -fT -- "$langpack_tmp" "$LPDST/$_rel" \
        || { rm -f -- "$langpack_tmp"; langpack_tmp=; fail "cannot publish Firefox langpack: $_rel"; }
    langpack_tmp=
done
for _lp in "$LPDST"/langpack-*.xpi; do
    rm -f -- "$_lp" || fail "cannot remove flat Firefox langpack: ${_lp##*/}"
done
for _lp in "$LPDST"/locale-*/langpack-*.xpi; do
    _rel=${_lp#"$LPDST"/}
    if [ -z "${source_langpack_paths[$_rel]+present}" ]; then
        rm -f -- "$_lp" || fail "cannot remove stale Firefox langpack: $_rel"
    fi
done
for _lp_dir in "$LPDST"/locale-*; do
    _rel=${_lp_dir#"$LPDST"/}
    if [ -z "${source_langpack_dirs[$_rel]+present}" ]; then
        rmdir -- "$_lp_dir" \
            || fail "stale Firefox langpack directory is not empty: $_rel"
    fi
done
if command -v restorecon >/dev/null 2>&1; then
    restorecon -R "$LPDST" || fail "cannot label Firefox distribution extensions"
fi
source_langpack_set=$(printf '%s\n' "${source_langpack_names[@]}")
installed_langpack_set=$(find "$LPDST" -mindepth 1 -name 'langpack-*.xpi' \
    -printf '%P\n' | LC_ALL=C sort)
[ "$source_langpack_set" = "$installed_langpack_set" ] \
    || fail "final Firefox langpack name set differs from RPM source"
installed_langpack_dirs=$(find "$LPDST" -mindepth 1 -maxdepth 1 -name 'locale-*' \
    -printf '%P\n' | LC_ALL=C sort)
[ "$(printf '%s\n' "${!source_langpack_dirs[@]}" | LC_ALL=C sort)" = \
    "$installed_langpack_dirs" ] \
    || fail "final Firefox langpack locale directory set differs from RPM source"
while IFS= read -r _rel; do
    [ -n "$_rel" ] || continue
    [ -f "$LPDST/$_rel" ] && [ ! -L "$LPDST/$_rel" ] \
        && cmp -s "${source_langpack_paths[$_rel]}" "$LPDST/$_rel" \
        || fail "final Firefox langpack bytes differ: $_rel"
done <<< "$source_langpack_set"
sync -- "$LPDST"
# Every admin overlay shadows the vendor entry with the same desktop-file ID, so
# GIO resolves its MimeType only through this directory's cache. A cache older
# than any overlay hides that handler (fresh v1.9: no mailto: handler).
admin_apps=/usr/local/share/applications
if [ ! -f "$admin_apps/mimeinfo.cache" ] || [ -L "$admin_apps/mimeinfo.cache" ] \
   || [ "$(stat -c '%a' "$admin_apps/mimeinfo.cache")" != 644 ] \
   || [ -n "$(find "$admin_apps" -maxdepth 1 -name '*.desktop' \
              -newer "$admin_apps/mimeinfo.cache" -print -quit)" ]; then
    # The cache must stay world-readable whatever umask the DNF action or
    # Update All caller has (M10 sets 027 for login shells).
    (umask 022 && update-desktop-database "$admin_apps") \
        || fail "cannot refresh the admin desktop MIME cache"
fi
logger -t noid-firefox-reassert "regenerated owned Firefox launcher/XDG overlays and langpacks"
NOID_FF_REASSERT_EOF
chmod 755 /usr/local/sbin/noid-firefox-reassert
chown root:root /usr/local/sbin/noid-firefox-reassert

mkdir -p /etc/dnf/libdnf5-plugins/actions.d
cat > /etc/dnf/libdnf5-plugins/actions.d/noid-firefox.actions <<'NOID_FF_ACTIONS_EOF'
# Regenerate NoID Privacy-owned launcher/XDG overlays from the newly installed,
# signed Firefox RPM payload. Vendor-owned files remain pristine.
# Exit 75 is the helper's language-pack warning: its stderr line stays
# visible, but the completed transaction is not reported as failed.
# Format: callback:package_filter:direction:options:command
post_transaction:firefox:in:enabled=host-only raise_error=1:/usr/bin/sh -c (/usr/local/sbin/noid-firefox-reassert\ ||\ [\ \$?\ -eq\ 75\ ])\ >/dev/null
post_transaction:firefox-langpacks:in:enabled=host-only raise_error=1:/usr/bin/sh -c (/usr/local/sbin/noid-firefox-reassert\ ||\ [\ \$?\ -eq\ 75\ ])\ >/dev/null
NOID_FF_ACTIONS_EOF
chmod 644 /etc/dnf/libdnf5-plugins/actions.d/noid-firefox.actions
# The compose accepts only full success; the exit-75 warning aborts it too.
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
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);

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

log "    Anaconda Firefox-theme hardened (live + default + extlink)"

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

# The published tree holds exactly one locale-<tag>/<payload> per regular RPM
# langpack payload; RPM alias symlinks are never staged and no XPI sits
# directly below FIREFOX_DIST_EXT.
expected_langpacks=$(find "$FIREFOX_LANGPACK_SRC" -maxdepth 1 -type f \
    -name 'langpack-*@firefox.mozilla.org.xpi' -printf '%f\n' \
    | sed -E 's|^langpack-(.+)@firefox\.mozilla\.org\.xpi$|locale-\1/&|' \
    | LC_ALL=C sort)
installed_langpacks=$(find "$FIREFOX_DIST_EXT" -mindepth 1 \
    \( -type f -o -type l \) -printf '%P\n' | LC_ALL=C sort)
installed_langpack_dirs=$(find "$FIREFOX_DIST_EXT" -mindepth 1 -type d \
    -printf '%P\n' | LC_ALL=C sort)
if [ -z "$expected_langpacks" ] \
   || [ "$expected_langpacks" != "$installed_langpacks" ] \
   || [ "$(printf '%s\n' "$expected_langpacks" | cut -d/ -f1 | LC_ALL=C sort)" != \
        "$installed_langpack_dirs" ]; then
    log "  [FAIL] final Firefox langpack name set differs from RPM source"
    final_fail=$((final_fail + 1))
else
    while IFS= read -r langpack; do
        cmp -s "$FIREFOX_LANGPACK_SRC/${langpack#*/}" "$FIREFOX_DIST_EXT/$langpack" || {
            log "  [FAIL] Firefox langpack bytes differ: $langpack"
            final_fail=$((final_fail + 1))
        }
    done <<< "$expected_langpacks"
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
