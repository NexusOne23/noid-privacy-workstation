# ============================================================================
# Module 34 — Firefox Playground (Separate Browser-Data Profile)
# Status: LOCKED 2026-08-02 (v25) — reject unexpected initializer arguments.
#
# Scope: Ship a SECOND pre-configured Firefox profile ("playground") with
# private-browsing-always behavior, shutdown sanitization and its own GNOME
# launcher identity. Complements the M16 productive profile.
#
# Three-line UX:
#   - Click "Firefox"               → productive profile (default)
#   - Click "Firefox (Playground)"  → separate private-session profile
#   - NoID Privacy's ordinary Firefox launcher targets the productive profile
#
# Separate profiles reduce routine browser-state mixing. This is data/session
# separation, not an OS sandbox: same-user processes can read both profile
# trees, and private browsing does not hide traffic from sites or the network.
#
# Files shipped:
#   /usr/share/noid-firefox/user-playground-overrides.js       JS config
#   /usr/share/applications/firefox-playground.desktop         2nd launcher
#   /etc/dconf/db/distro.d/16-noid-firefox-playground          dconf default
#   /usr/local/bin/noid-firefox-playground-init.sh             per-user setup
#   /etc/xdg/autostart/
#       noid-firefox-playground-init.desktop                   first-login hook
#   + health stamp
#
# Constraint notes (keep on future edits):
#   - The launcher uses `Icon=firefox`: freedesktop icon-theme lookup resolves
#     the unmodified icon supplied by Fedora's Firefox package. The owned M16
#     wrapper resolves the registered XDG profile explicitly; GTK's `--name`
#     and `--class` bind native Wayland and X11 identity to the desktop ID.
#     No duplicate artwork, renderer or runtime font dependency is needed.
#   - Exact custom-icon paths shipped by older v1.4 development images are
#     retired idempotently. They are NoID Privacy-owned compatibility debris,
#     not package-owned Firefox artwork.
#   - The dconf favorites keyfile is NOT locked (user can customize), and
#     firefox-playground stays in the app-grid, not pinned to the dock.
#   - M16 must run before M34 (base user.js prerequisite — runtime-checked).
#
# Dependencies: none added here. Hard compose/runtime inputs are M16's user.js,
# firefox-profiles.sh and Firefox launcher; firefox, python3 and /usr/bin/rpm;
# plus dconf and desktop-file-utils. Optional runtime integration uses M13's
# wait-fedora-welcome.sh and libnotify's notify-send; absence does not block
# profile initialization.
# ============================================================================

%post --log=/var/log/ks-34-firefox-playground.log --erroronfail
set -euo pipefail

PHASE=""
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [M34] ${PHASE}: $*"; }
die() { log "FAIL: $*"; exit 1; }
STAMP_DIR=/var/lib/noid-privacy
STAMP="$STAMP_DIR/stamp-34-firefox-playground.ok"
STAMP_TMP=""
STAMP_PUBLICATION_ACTIVE=0
OVERRIDES_TMP=""
DESKTOP_TMP=""
DCONF_TMP=""
INIT_TMP=""
AUTOSTART_TMP=""
cleanup_m34_health_stamp() {
    local saved_rc=$? candidate
    trap - EXIT
    trap '' HUP INT TERM
    for candidate in \
        "${OVERRIDES_TMP:-}" "${DESKTOP_TMP:-}" "${DCONF_TMP:-}" \
        "${INIT_TMP:-}" "${AUTOSTART_TMP:-}" "${STAMP_TMP:-}"; do
        [ -n "$candidate" ] || continue
        if ! rm -f -- "$candidate"; then
            log "FAIL: could not retire staged Module 34 payload: $candidate"
        fi
    done
    if [ "${STAMP_PUBLICATION_ACTIVE:-0}" -eq 1 ]; then
        if ! rm -f -- "$STAMP"; then
            log "FAIL: could not retire incomplete Module 34 health stamp"
        fi
        sync -- "$STAMP_DIR" >/dev/null 2>&1 || true
    fi
    return "$saved_rc"
}
trap cleanup_m34_health_stamp EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

ensure_root_dir() {
    local path="$1" mode="$2" state
    case "$path" in
        /*) ;;
        *) die "managed directory is not absolute: $path" ;;
    esac
    if [ -L "$path" ] || { [ -e "$path" ] && [ ! -d "$path" ]; }; then
        die "unsafe managed directory: $path"
    fi
    if [ ! -e "$path" ]; then
        install -d -o root -g root -m "$mode" -- "$path" ||
            die "cannot create managed directory: $path"
    else
        chown root:root -- "$path" ||
            die "cannot set managed-directory owner: $path"
        chmod "$mode" -- "$path" ||
            die "cannot set managed-directory mode: $path"
    fi
    [ "$(readlink -f -- "$path" 2>/dev/null)" = "$path" ] ||
        die "managed-directory path contains a symlink: $path"
    state=$(stat -Lc '%u:%g:%a' -- "$path" 2>/dev/null || echo "")
    [ "$state" = "0:0:$mode" ] ||
        die "managed-directory postcondition failed: $path ($state)"
    /usr/sbin/restorecon -F -- "$path" ||
        die "cannot label managed directory: $path"
    /usr/sbin/matchpathcon -V "$path" >/dev/null ||
        die "managed-directory label differs: $path"
    sync -- "$path" ||
        die "cannot sync managed directory: $path"
}

publish_root_file() {
    local tmp="$1" target="$2" mode="$3" parent parent_state parent_mode state
    case "$target" in
        /*) ;;
        *) die "payload target is not absolute: $target" ;;
    esac
    parent=$(dirname -- "$target")
    [ "$(dirname -- "$tmp")" = "$parent" ] ||
        die "temporary payload is not in target directory: $target"
    [ -d "$parent" ] && [ ! -L "$parent" ] ||
        die "unsafe payload parent: $parent"
    [ "$(readlink -f -- "$parent" 2>/dev/null)" = "$parent" ] ||
        die "payload parent path contains a symlink: $parent"
    parent_state=$(stat -Lc '%u:%g:%a' -- "$parent" 2>/dev/null || echo "")
    case "$parent_state" in
        0:0:*) parent_mode=${parent_state##*:} ;;
        *) die "payload parent is not root-owned: $parent ($parent_state)" ;;
    esac
    [[ "$parent_mode" =~ ^[0-7]{3,4}$ ]] ||
        die "payload parent has an invalid mode: $parent ($parent_mode)"
    (( (8#$parent_mode & 0022) == 0 )) ||
        die "payload parent is group/other-writable: $parent ($parent_mode)"
    [ -f "$tmp" ] && [ ! -L "$tmp" ] &&
        [ "$(stat -Lc '%h' -- "$tmp" 2>/dev/null)" = 1 ] ||
        die "unsafe temporary payload: $tmp"
    chown root:root -- "$tmp" || die "cannot set payload owner: $target"
    chmod "$mode" -- "$tmp" || die "cannot set payload mode: $target"
    sync -- "$tmp" || die "cannot sync staged payload: $target"
    mv -fT -- "$tmp" "$target" || die "cannot publish payload: $target"
    /usr/sbin/restorecon -F -- "$target" ||
        die "cannot label published payload: $target"
    /usr/sbin/matchpathcon -V "$target" >/dev/null ||
        die "published payload label differs: $target"
    sync -- "$target" || die "cannot sync published payload: $target"
    sync -- "$parent" || die "cannot sync payload directory: $parent"
    state=$(stat -Lc '%u:%g:%a:%h' -- "$target" 2>/dev/null || echo "")
    [ -f "$target" ] && [ ! -L "$target" ] &&
        [ "$state" = "0:0:$mode:1" ] ||
        die "payload postcondition failed: $target ($state)"
}

verify_owned_regular() {
    local path="$1" expected_mode="$2"
    [ -f "$path" ] &&
        [ ! -L "$path" ] &&
        [ "$(readlink -f -- "$path" 2>/dev/null)" = "$path" ] &&
        [ "$(stat -Lc '%u:%g:%a:%h' -- "$path" 2>/dev/null)" = \
            "0:0:${expected_mode}:1" ] &&
        /usr/sbin/matchpathcon -V "$path" >/dev/null
}

verify_root_directory_boundary() {
    local path="$1" state mode
    [ -d "$path" ] && [ ! -L "$path" ] || return 1
    [ "$(readlink -f -- "$path" 2>/dev/null)" = "$path" ] || return 1
    state=$(stat -Lc '%u:%g:%a' -- "$path" 2>/dev/null) || return 1
    case "$state" in
        0:0:*) mode=${state##*:} ;;
        *) return 1 ;;
    esac
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$mode & 0022) == 0 )) || return 1
    /usr/sbin/matchpathcon -V "$path" >/dev/null
}

log "=== Module 34 Firefox Playground start ==="

# M34_HEALTH_INVALIDATION_BEGIN
# This stamp covers the complete Playground payload below. Validate shared
# state without normalizing drift, then retire any earlier success before the
# first owned payload mutation.
PHASE="P0-health-invalidation"
if { [ -e "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; } \
   && { [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; }; then
    die "$STAMP_DIR exists but is not a real directory"
fi
if [ ! -e "$STAMP_DIR" ]; then
    install -d -m 0755 -o root -g root "$STAMP_DIR"
fi
if [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
        0:0:755 ]; then
    die "$STAMP_DIR metadata is not root:root 0755"
fi
if [ ! -x /usr/sbin/restorecon ] || [ ! -x /usr/sbin/matchpathcon ] \
   || ! /usr/sbin/restorecon -F -- "$STAMP_DIR" \
   || ! /usr/sbin/matchpathcon -V "$STAMP_DIR" >/dev/null; then
    die "$STAMP_DIR SELinux context is not canonical"
fi
if [ -e "$STAMP" ] || [ -L "$STAMP" ]; then
    if [ ! -f "$STAMP" ] && [ ! -L "$STAMP" ]; then
        die "health-stamp target is not a file or symlink: $STAMP"
    fi
    rm -f -- "$STAMP" \
        || die "cannot invalidate stale Module 34 health stamp"
    sync -- "$STAMP_DIR"
fi
log "  [OK] prior Module 34 health stamp is absent"
# M34_HEALTH_INVALIDATION_END

# ----------------------------------------------------------------------------
# Phase 1 — ensure directories
# ----------------------------------------------------------------------------
PHASE="P1-setup"
log "Creating directories"
ensure_root_dir /usr/share/noid-firefox 755
ensure_root_dir /usr/share/applications 755
ensure_root_dir /etc/dconf/db/distro.d 755
ensure_root_dir /etc/xdg/autostart 755
ensure_root_dir /usr/local/bin 755

# M16 inputs are a root-owned trust boundary because the per-user initializer
# sources the helper and concatenates the base configuration.
verify_owned_regular /usr/share/noid-firefox/user.js 644 ||
    die "M16 base user.js is missing or has unsafe metadata"
verify_owned_regular /usr/local/lib/noid-privacy/firefox-profiles.sh 644 ||
    die "M16 Firefox profile helper is missing or has unsafe metadata"
verify_owned_regular /usr/local/bin/firefox 755 ||
    die "M16 owned Firefox launcher is missing or has unsafe metadata"
for required_tool in \
    /usr/bin/desktop-file-validate /usr/bin/update-desktop-database \
    /usr/bin/dconf /usr/bin/rpm; do
    [ -x "$required_tool" ] ||
        die "required executable is missing: $required_tool"
done

# ----------------------------------------------------------------------------
# Phase 2 — Write user-playground-overrides.js
# ----------------------------------------------------------------------------
PHASE="P2-overrides"
log "Writing /usr/share/noid-firefox/user-playground-overrides.js"

OVERRIDES_TARGET=/usr/share/noid-firefox/user-playground-overrides.js
OVERRIDES_TMP=$(mktemp /usr/share/noid-firefox/.user-playground-overrides.js.XXXXXX) ||
    die "cannot create Playground-overrides temporary file"
cat > "$OVERRIDES_TMP" <<'OVERRIDES_EOF'
// ============================================================================
// NoID Privacy Firefox Hardening — Playground Private-Session Overrides
// Source: Module 34 (Firefox Playground) via noid-firefox-playground-init.sh
// This file is APPENDED to the base /usr/share/noid-firefox/user.js when a
// new playground profile is created. Its base DNS default follows the
// system/VPN resolver. These overrides do not change the base FPP, TCP,
// uBlock, DNS or telemetry controls; they add private-session cleanup.
// ============================================================================

// --- Profile-kind marker -------------------------------------------------
// Local classification marker in the composed user.js. It helps NoID Privacy tools
// distinguish the intended configuration, but it is user-owned state and is
// not an integrity attestation.
user_pref("_noid.profile.kind", "playground");

// --- Always-Private-Browsing ---------------------------------------------
// Firefox discards private-session history, form/search entries, download-list
// entries, cookies, cache and offline website data when the private session
// ends. Saved download files and newly created bookmarks remain. This is not
// anonymity, an OS sandbox or protection from same-user malware.
// Primary reference:
// https://support.mozilla.org/en-US/kb/private-browsing-use-firefox-without-history
user_pref("browser.privatebrowsing.autostart", true);

// uBlock Origin must run in PB windows for phishing + LAN-intrusion filter
// coverage. The EFFECTIVE grant is the per-extension
// internal:privateBrowsingAllowed permission seeded into
// extension-preferences.json by the shared M16 helper and verified before the
// ready marker is published.

// --- Shutdown sanitization ------------------------------------------------
// Keep the shutdown sanitizer enabled as defense in depth if browser data is
// ever persisted beyond the private-session lifetime.
//
// Current Firefox reads privacy.clearOnShutdown_v2.* and exposes exactly these
// five categories in its shutdown-sanitizer state. The M16 base pins Firefox's
// current v3 migration marker, so obsolete migration-category prefs are not
// carried into this profile. Site permissions include grants and denials; a
// disposable untrusted-browsing profile retains neither across sessions.
// Primary source:
// https://searchfox.org/mozilla-central/source/browser/modules/Sanitizer.sys.mjs
user_pref("privacy.sanitize.sanitizeOnShutdown", true);
user_pref("privacy.clearOnShutdown_v2.cookiesAndStorage", true);
user_pref("privacy.clearOnShutdown_v2.browsingHistoryAndDownloads", true);
user_pref("privacy.clearOnShutdown_v2.cache", true);
user_pref("privacy.clearOnShutdown_v2.formdata", true);
user_pref("privacy.clearOnShutdown_v2.siteSettings", true);

// --- No history persistence at all --------------------------------------
// Prevent Places from recording browsing history for this profile.
user_pref("places.history.enabled", false);

// --- No session restore ---------------------------------------------------
// Crash-restore + tab-history would leak state across "sessions" that the
// user expects to be discarded.
user_pref("browser.sessionstore.resume_from_crash", false);
user_pref("browser.sessionstore.max_tabs_undo", 0);
user_pref("browser.sessionstore.max_windows_undo", 0);
user_pref("browser.sessionstore.privacy_level", 2);

// --- No saved passwords / autofill --------------------------------------
// Throwaway profile — do not offer to save credentials.
user_pref("signon.rememberSignons", false);
user_pref("signon.autofillForms", false);
user_pref("signon.generation.enabled", false);
user_pref("signon.management.page.breach-alerts.enabled", false);
user_pref("extensions.formautofill.addresses.enabled", false);
user_pref("extensions.formautofill.creditCards.enabled", false);

// --- No disk cache --------------------------------------------------------
user_pref("browser.cache.memory.enable", true);
user_pref("browser.cache.disk.enable", false);

// --- Clean startup page ---------------------------------------------------
// No homepage or new-tab content.
user_pref("browser.startup.homepage", "about:blank");
user_pref("browser.startup.page", 0);                 // 0 = blank
user_pref("browser.newtabpage.enabled", false);
user_pref("browser.newtabpage.activity-stream.feeds.topsites", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);
user_pref("browser.newtabpage.activity-stream.showSponsored", false);
user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);

// --- Tell Firefox this is a "clean" profile: suppress welcome splashes --
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("startup.homepage_welcome_url", "");
user_pref("startup.homepage_welcome_url.additional", "");
user_pref("startup.homepage_override_url", "");
user_pref("browser.aboutwelcome.enabled", false);

// --- No Firefox account ----------------------------------------------------
user_pref("identity.fxaccounts.enabled", false);

// ============================================================================
// End playground overrides. The base NoID Privacy Firefox Hardening user.js (shipped
// by M16) is concatenated BEFORE this file, so these preferences take
// precedence via the last-write-wins rule in Firefox prefs.js reconciliation.
// ============================================================================
OVERRIDES_EOF

publish_root_file "$OVERRIDES_TMP" "$OVERRIDES_TARGET" 644
OVERRIDES_TMP=""
log "  [OK] user-playground-overrides.js written ($(wc -l < "$OVERRIDES_TARGET") lines)"

# ----------------------------------------------------------------------------
# Phase 3 — Retire legacy aliases and verify the packaged Firefox icon
# ----------------------------------------------------------------------------
PHASE="P3-icon"
log "Converging on the Fedora Firefox package icon"

# Older v1.4 development images installed custom PNGs at these exact
# NoID Privacy-owned paths; an intermediate live deployment used symlink
# aliases there. The current launcher uses Icon=firefox directly, so keeping
# either form creates upgrade-only state that a fresh image does not have.
# Remove regular files/symlinks only and fail on an unexpected object type.
LEGACY_PLAYGROUND_ICON_SIZES="48 64 128 256"
legacy_playground_icons_removed=0
for size in $LEGACY_PLAYGROUND_ICON_SIZES; do
    legacy_playground_icon="/usr/share/icons/hicolor/${size}x${size}/apps/firefox-playground.png"
    legacy_playground_icon_parent=$(dirname -- "$legacy_playground_icon")
    verify_root_directory_boundary "$legacy_playground_icon_parent" ||
        die "unsafe legacy-icon parent boundary: $legacy_playground_icon_parent"
    if [ -e "$legacy_playground_icon" ] || [ -L "$legacy_playground_icon" ]; then
        if [ ! -f "$legacy_playground_icon" ] && [ ! -L "$legacy_playground_icon" ]; then
            die "Unexpected non-regular legacy icon object: $legacy_playground_icon"
        fi
        rm -f -- "$legacy_playground_icon" \
            || die "Could not retire legacy icon: $legacy_playground_icon"
        sync -- "$legacy_playground_icon_parent" \
            || die "Could not sync legacy-icon parent: $legacy_playground_icon_parent"
        legacy_playground_icons_removed=$((legacy_playground_icons_removed + 1))
    fi
done
log "  [OK] legacy custom Playground icon aliases absent ($legacy_playground_icons_removed retired)"

firefox_icon_count=0
shopt -s nullglob
firefox_icons=(
    /usr/share/icons/hicolor/*/apps/firefox.png
    /usr/share/icons/hicolor/symbolic/apps/firefox*-symbolic.svg
)
shopt -u nullglob
for firefox_icon in "${firefox_icons[@]}"; do
    verify_owned_regular "$firefox_icon" 644 ||
        die "Firefox icon has unsafe metadata or label: $firefox_icon"
    firefox_icon_package=$(
        /usr/bin/rpm -qf --qf '%{NAME}\n' -- "$firefox_icon" 2>/dev/null
    ) || die "Firefox icon is not owned by an installed RPM: $firefox_icon"
    [ "$firefox_icon_package" = firefox ] ||
        die "Firefox icon is not owned by the firefox package: $firefox_icon"
    firefox_icon_count=$((firefox_icon_count + 1))
done
[ "$firefox_icon_count" -gt 0 ] \
    || die "Fedora Firefox icon missing — firefox package payload is incomplete"
log "  [OK] firefox-RPM-owned icon available ($firefox_icon_count verified variant(s))"

# ----------------------------------------------------------------------------
# Phase 4 — Write firefox-playground.desktop
# ----------------------------------------------------------------------------
PHASE="P4-desktop"
log "Writing /usr/share/applications/firefox-playground.desktop"

DESKTOP_TARGET=/usr/share/applications/firefox-playground.desktop
DESKTOP_TMP=$(mktemp --suffix=.desktop /usr/share/applications/.firefox-playground.XXXXXX) ||
    die "cannot create Playground desktop-entry temporary file"
cat > "$DESKTOP_TMP" <<'DESKTOP_EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Firefox (Playground)
GenericName=Private-session Web Browser
Comment=Separate Firefox profile that discards private-session browser data; saved files and bookmarks persist.
# GTK3/GDK's --name option sets the program name used for the native Wayland
# app_id, while --class sets the X11/XWayland program class. Both use the
# desktop ID `firefox-playground`, and StartupWMClass supplies the standardized
# X11 matching hint. Mozilla's Linux profile-grouping issue documents this
# backend split and the two-option Fedora RPM result.
# Primary references:
# https://docs.gtk.org/gtk3/running.html
# https://specifications.freedesktop.org/desktop-entry/latest/recognized-keys.html
# https://bugzilla.mozilla.org/show_bug.cgi?id=1577056
# --no-remote is a current Firefox startup parameter and implies
# --new-instance. It keeps this named profile in its own Firefox instance:
# https://firefox-source-docs.mozilla.org/browser/CommandLineParameters.html
Exec=/usr/local/bin/firefox -P playground --no-remote --name firefox-playground --class firefox-playground %u
Icon=firefox
Terminal=false
Categories=Network;WebBrowser;
MimeType=text/html;text/xml;application/xhtml+xml;application/vnd.mozilla.xul+xml;text/mml;x-scheme-handler/http;x-scheme-handler/https;
StartupNotify=true
StartupWMClass=firefox-playground
Keywords=browser;web;internet;privacy;incognito;untrusted;playground;
Actions=new-private-window;

[Desktop Action new-private-window]
Name=New Private Window
Exec=/usr/local/bin/firefox -P playground --no-remote --name firefox-playground --class firefox-playground --private-window %u
DESKTOP_EOF

/usr/bin/desktop-file-validate "$DESKTOP_TMP" ||
    die "firefox-playground.desktop failed desktop-file validation"
publish_root_file "$DESKTOP_TMP" "$DESKTOP_TARGET" 644
DESKTOP_TMP=""
log "  [OK] firefox-playground.desktop written"

# The cache is required for the launcher's declared MIME/protocol associations.
# desktop-file-utils is already a hard prerequisite, so a failed rebuild is an
# incomplete image contract rather than a warning-only cosmetic issue.
if ! /usr/bin/update-desktop-database /usr/share/applications 2>&1 \
        | /usr/bin/tee -a /var/log/ks-34-firefox-playground.log; then
    die "update-desktop-database failed — MIME cache is incomplete"
fi
log "  [OK] desktop MIME cache rebuilt"

# ----------------------------------------------------------------------------
# Phase 5 — Write dconf distro default: GNOME Shell favorite-apps
# ----------------------------------------------------------------------------
PHASE="P5-dconf"
log "Writing dconf distro-default for GNOME Shell favorite-apps"

# Non-locked — user can remove via right-click → Remove from Favorites.
DCONF_TARGET=/etc/dconf/db/distro.d/16-noid-firefox-playground
DCONF_TMP=$(mktemp /etc/dconf/db/distro.d/.16-noid-firefox-playground.XXXXXX) ||
    die "cannot create Playground dconf temporary file"
cat > "$DCONF_TMP" <<'DCONF_EOF'
# ============================================================================
# NoID Privacy — GNOME Shell default favorites (Dash)
# Sets default favorites; user can customize via Activities → right-click
# → Remove/Add from Favorites. NOT locked.
# Firefox (Playground) is deliberately not part of this list — it stays in
# the app-grid (see the ordering rationale below).
# ============================================================================

[org/gnome/shell]
# Fedora 44/GNOME 50 desktop IDs, in the intended order:
# Firefox → Thunderbird → Software → Files → Terminal → Settings.
# Firefox Playground remains available from the app grid.
favorite-apps=['org.mozilla.firefox.desktop', 'net.thunderbird.Thunderbird.desktop', 'org.gnome.Software.desktop', 'org.gnome.Nautilus.desktop', 'org.gnome.Ptyxis.desktop', 'org.gnome.Settings.desktop']
DCONF_EOF

publish_root_file "$DCONF_TMP" "$DCONF_TARGET" 644
DCONF_TMP=""
log "  [OK] dconf keyfile 16-noid-firefox-playground written"

# Compile dconf db. This is a required image default; there is no first-boot
# compiler in this module, so a missing tool or failed compile must abort.
/usr/bin/dconf update 2>&1 |
    /usr/bin/tee -a /var/log/ks-34-firefox-playground.log
log "  [OK] dconf db compiled"

# ----------------------------------------------------------------------------
# Phase 6 — Write noid-firefox-playground-init.sh (per-user first-login)
# ----------------------------------------------------------------------------
PHASE="P6-init-script"
log "Writing /usr/local/bin/noid-firefox-playground-init.sh"

INIT_TARGET=/usr/local/bin/noid-firefox-playground-init.sh
INIT_TMP=$(mktemp /usr/local/bin/.noid-firefox-playground-init.sh.XXXXXX) ||
    die "cannot create Playground initializer temporary file"
cat > "$INIT_TMP" <<'INIT_EOF'
#!/bin/bash
# noid-firefox-playground-init — first-login per-user creator of the
# private-session Firefox "playground" profile.
# Part of NoID Privacy Workstation, Module 34 Firefox Playground.
# Invoked by /etc/xdg/autostart/noid-firefox-playground-init.desktop.
# Idempotent via the content-validated XDG configuration marker.

set -euo pipefail
PATH=/usr/local/bin:/usr/sbin:/usr/bin
export PATH
umask 077

if [ "$#" -ne 0 ]; then
    printf '%s\n' 'Usage: noid-firefox-playground-init.sh' >&2
    exit 2
fi

# Live-image profile state is overlay-local and does not persist to the
# installed system, so initialization belongs to the installed first login.
if grep -q "rd.live.image" /proc/cmdline 2>/dev/null; then
    logger -t "noid-firefox-playground-init" "skip: rd.live.image (live-ISO mode)" 2>/dev/null || true
    exit 0
fi

PROFILE_NAME="playground"
BASE_USERJS="/usr/share/noid-firefox/user.js"
PLAYGROUND_OVERRIDES="/usr/share/noid-firefox/user-playground-overrides.js"
PROFILE_HELPER="/usr/local/lib/noid-privacy/firefox-profiles.sh"
FIREFOX_LAUNCHER="/usr/local/bin/firefox"
WELCOME_HELPER="/usr/local/lib/noid-privacy/wait-fedora-welcome.sh"
TAG="noid-firefox-playground-init"
XULSTORE_TMP=""
NOID_BM_TMP=""
MARKER_TMP=""
MARKER_PUBLICATION_ACTIVE=0

_log() { logger -t "$TAG" -- "$*" 2>/dev/null || true; echo "$*" >&2; }

cleanup_playground_init() {
    local saved_rc=$? candidate
    trap - EXIT
    trap '' HUP INT TERM
    for candidate in \
        "${XULSTORE_TMP:-}" "${NOID_BM_TMP:-}" "${MARKER_TMP:-}"; do
        [ -n "$candidate" ] || continue
        if ! rm -f -- "$candidate"; then
            _log "could not retire staged per-user payload: $candidate"
        fi
    done
    if [ "${MARKER_PUBLICATION_ACTIVE:-0}" -eq 1 ]; then
        if ! rm -f -- "$MARKER"; then
            _log "could not retire unverified published playground marker"
        fi
        if ! sync -- "$MARKER_DIR"; then
            _log "could not sync marker directory during failure cleanup"
        fi
    fi
    return "$saved_rc"
}
trap cleanup_playground_init EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# This per-user workflow must never source or concatenate a replaceable
# system payload.
trusted_root_file() {
    local path="$1" mode="$2"
    [ -f "$path" ] && [ ! -L "$path" ] &&
        [ "$(readlink -f -- "$path" 2>/dev/null)" = "$path" ] &&
        [ "$(stat -Lc '%u:%g:%a:%h' -- "$path" 2>/dev/null)" = \
            "0:0:${mode}:1" ] &&
        /usr/sbin/matchpathcon -V "$path" >/dev/null 2>&1
}

# Defensive: run only for a real non-root desktop session with a valid HOME.
HOME_DIR="${HOME:-}"
if [ -z "$HOME_DIR" ] || [ ! -d "$HOME_DIR" ]; then
    _log "HOME unset or missing — exiting"
    exit 0
fi
if [ "$(id -u)" -eq 0 ]; then
    _log "skipping root execution — run only in the desktop-user session"
    exit 1
fi
CURRENT_USER=$(id -un 2>/dev/null || true)
case "$CURRENT_USER" in
    root|"")
        _log "could not identify a non-root desktop user — exiting"
        exit 0
        ;;
esac

CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME_DIR/.config}"
MOZILLA_DIR="$CONFIG_HOME/mozilla/firefox"
MARKER_DIR="$CONFIG_HOME/noid-privacy"
MARKER="$MARKER_DIR/firefox-playground-init.done"
MARKER_CONTENT="NOID_FIREFOX_PLAYGROUND_READY_V1"
SETUP_MARKER="${XDG_STATE_HOME:-$HOME_DIR/.local/state}/noid-privacy/firefox-setup.done"

if ! command -v python3 >/dev/null 2>&1; then
    _log "python3 missing — installed image is incomplete"
    exit 1
fi
if ! python3 - "$CONFIG_HOME" "$MOZILLA_DIR" "$MARKER_DIR" "$SETUP_MARKER" <<'XDG_PATHS_PYEOF'
import os
import sys

for path in sys.argv[1:]:
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise SystemExit(f"invalid absolute normalized XDG path: {path!r}")
XDG_PATHS_PYEOF
then
    _log "invalid XDG configuration/state path — refusing automatic writes"
    exit 1
fi

# Prerequisite files from M16 + M34.
if ! trusted_root_file "$BASE_USERJS" 644; then
    _log "base user.js is missing or has unsafe metadata — M16 install incomplete"
    exit 1
fi
if ! trusted_root_file "$PLAYGROUND_OVERRIDES" 644; then
    _log "playground overrides are missing or have unsafe metadata — M34 install incomplete"
    exit 1
fi
if ! trusted_root_file "$FIREFOX_LAUNCHER" 755; then
    _log "owned Firefox launcher is missing or unsafe — M16 install incomplete"
    exit 1
fi

# Source the shared profile helper before trusting any marker. The marker is
# workflow evidence only; the registered profile and all required outputs must
# still pass the current hardening contract.
if ! trusted_root_file "$PROFILE_HELPER" 644; then
    _log "shared helper is missing or has unsafe metadata — M16 install incomplete"
    exit 1
fi
# shellcheck source=/dev/null
. "$PROFILE_HELPER"

playground_marker_valid() {
    local marker_state
    [ -f "$MARKER" ] && [ ! -L "$MARKER" ] || return 1
    marker_state=$(stat -c '%u:%a:%h' -- "$MARKER") || return 1
    [ "$marker_state" = "$(id -u):600:1" ] || return 1
    cmp -s -- "$MARKER" <(printf '%s\n' "$MARKER_CONTENT")
}

setup_marker_profile() {
    local expected_userjs_sha
    expected_userjs_sha=$(sha256sum "$BASE_USERJS" | awk '{print $1}') ||
        return 1
    python3 - "$SETUP_MARKER" "$MOZILLA_DIR" \
        "$expected_userjs_sha" "$NOID_FF_UBO_SHA256" <<'SETUP_MARKER_PYEOF'
import os
import stat
import sys

path, firefox_root, expected_userjs_sha, expected_ubo_sha = sys.argv[1:]
try:
    marker = os.lstat(path)
except FileNotFoundError:
    raise SystemExit(1)
if (not stat.S_ISREG(marker.st_mode) or stat.S_ISLNK(marker.st_mode)
        or marker.st_uid != os.geteuid()
        or stat.S_IMODE(marker.st_mode) != 0o600
        or marker.st_nlink != 1):
    raise SystemExit(1)
try:
    with open(path, encoding="utf-8") as handle:
        lines = handle.read().splitlines()
except (OSError, UnicodeError):
    raise SystemExit(1)
if len(lines) != 4 or lines[0] != "NOID_FIREFOX_SETUP_V1":
    raise SystemExit(1)
if lines[2] != f"userjs_sha256={expected_userjs_sha}":
    raise SystemExit(1)
if lines[3] != f"ubo_sha256={expected_ubo_sha}":
    raise SystemExit(1)
prefix = "profile="
if not lines[1].startswith(prefix):
    raise SystemExit(1)
profile = lines[1][len(prefix):]
if (not os.path.isabs(profile) or os.path.normpath(profile) != profile
        or profile == firefox_root):
    raise SystemExit(1)
try:
    if os.path.commonpath((firefox_root, profile)) != firefox_root:
        raise SystemExit(1)
except ValueError:
    raise SystemExit(1)
print(profile)
SETUP_MARKER_PYEOF
}

setup_marker_valid() {
    setup_marker_profile >/dev/null
}

if [ -e "$MARKER" ] || [ -L "$MARKER" ]; then
    if [ -L "$MARKER" ] || [ ! -f "$MARKER" ]; then
        _log "playground ready marker is non-regular or symlinked"
        exit 1
    fi
    if playground_marker_valid && profile_hardening_complete "$PROFILE_NAME"; then
        exit 0
    fi
    _log "stale/incomplete playground state found — repairing without deleting user data"
fi

# M16 owns canonical default-profile registration. Wait for its exact setup
# evidence before registering the second profile; otherwise defer without
# changing profiles.ini or profile bytes.
for ((attempt = 0; attempt < 30; attempt++)); do
    setup_marker_valid && break
    sleep 2
done
if ! setup_marker_valid; then
    _log "valid setup state not found after 60s — defer playground-init to next login"
    exit 0
fi

SETUP_PROFILE=$(setup_marker_profile) || {
    _log "M16 setup marker changed during validation — defer to next login"
    exit 0
}
REGISTERED_DEFAULT=$(profile_dir_for default-release 2>/dev/null || true)
if [ "$REGISTERED_DEFAULT" != "$SETUP_PROFILE" ] ||
   ! profile_hardening_complete default-release; then
    _log "M16 default profile does not satisfy the current hardening contract — defer"
    exit 0
fi

# Any live Firefox instance can hold profiles.ini or shared profile state.
# The M16 helper ignores only dead/zombie tasks, so this remains fail-closed
# without the old command-line substring heuristics.
if firefox_process_active; then
    _log "Firefox is running; no profile bytes changed — defer to next login"
    exit 75
fi

# Use the shared descriptor-backed flock. Unlike a mkdir sentinel, the lock is
# released automatically on process exit and cannot permanently strand setup
# after a crash.
if ! acquire_firefox_profile_lock; then
    _log "another Firefox profile operation is active — defer to next login"
    exit 75
fi

# Close the check/lock race before touching any Firefox state.
if firefox_process_active; then
    _log "Firefox started while acquiring the profile lock; no profile bytes changed"
    exit 75
fi

if [ -L "$MARKER_DIR" ] || { [ -e "$MARKER_DIR" ] && [ ! -d "$MARKER_DIR" ]; }; then
    _log "marker directory is non-directory or symlinked"
    exit 1
fi
if [ ! -d "$MARKER_DIR" ]; then
    install -d -m 700 -- "$MARKER_DIR"
fi
MARKER_DIR_STATE=$(stat -c '%u:%a' -- "$MARKER_DIR")
if [ "$MARKER_DIR_STATE" != "$(id -u):700" ]; then
    _log "marker directory ownership/mode is unsafe"
    exit 1
fi

if playground_marker_valid && profile_hardening_complete "$PROFILE_NAME"; then
    exit 0
fi

if [ -L "$MOZILLA_DIR" ] || { [ -e "$MOZILLA_DIR" ] && [ ! -d "$MOZILLA_DIR" ]; }; then
    _log "Firefox profile root is non-directory or symlinked"
    exit 1
fi
if [ ! -d "$MOZILLA_DIR" ]; then
    install -d -m 700 -- "$MOZILLA_DIR"
fi
MOZILLA_DIR_STATE=$(stat -c '%u:%a' -- "$MOZILLA_DIR" 2>/dev/null || echo "")
MOZILLA_DIR_MODE=${MOZILLA_DIR_STATE#*:}
if [ "${MOZILLA_DIR_STATE%%:*}" != "$(id -u)" ] ||
   ! [[ "$MOZILLA_DIR_MODE" =~ ^[0-7]{3,4}$ ]] ||
   (( (8#$MOZILLA_DIR_MODE & 0022) != 0 )); then
    _log "Firefox profile root ownership/mode is unsafe"
    exit 1
fi

# Track whether the profile is freshly-created (notify only first time).
PROFILE_EXISTS=0
if profile_dir_for "$PROFILE_NAME" >/dev/null 2>&1; then
    PROFILE_EXISTS=1
    _log "playground profile already registered — refreshing user.js"
fi

# Create and register using the current shared M16 profile helper.
if ! ensure_profile "$PROFILE_NAME"; then
    _log "ensure_profile failed for $PROFILE_NAME"
    exit 1
fi

PROFILE_DIR=$(profile_dir_for "$PROFILE_NAME") || {
    _log "profile_dir_for returned nothing for $PROFILE_NAME"
    exit 1
}

if [ ! -d "$PROFILE_DIR" ]; then
    install -d -m 700 -- "$PROFILE_DIR"
fi
PROFILE_DIR_STATE=$(stat -c '%u:%a' -- "$PROFILE_DIR" 2>/dev/null || echo "")
if [ "$PROFILE_DIR_STATE" != "$(id -u):700" ]; then
    _log "playground profile directory ownership/mode is unsafe"
    exit 1
fi

# Apply user.js via helper (handles base + playground overrides correctly).
if ! apply_userjs "$PROFILE_NAME"; then
    _log "apply_userjs failed for $PROFILE_NAME"
    exit 1
fi

# xulstore.json is user-owned window state. Seed a maximized first launch only
# while the file is absent; a repair must never reset established geometry.
XULSTORE="$PROFILE_DIR/xulstore.json"
if [ -e "$XULSTORE" ] || [ -L "$XULSTORE" ]; then
    if [ ! -f "$XULSTORE" ] || [ -L "$XULSTORE" ]; then
        _log "xulstore.json is non-regular or symlinked"
        exit 1
    fi
    _log "preserved existing xulstore.json byte-for-byte"
else
    XULSTORE_TMP=$(mktemp "$PROFILE_DIR/.xulstore.json.tmp.XXXXXXXX") || {
        _log "could not create staged xulstore.json"
        exit 1
    }
    printf '%s\n' '{"chrome://browser/content/browser.xhtml":{"main-window":{"sizemode":"maximized","screenX":"0","screenY":"0","width":"1366","height":"768"}}}' > "$XULSTORE_TMP"
    chmod 600 "$XULSTORE_TMP"
    sync -- "$XULSTORE_TMP"
    if ln -- "$XULSTORE_TMP" "$XULSTORE"; then
        if ! rm -f -- "$XULSTORE_TMP"; then
            _log "could not retire staged xulstore.json"
            exit 1
        fi
        XULSTORE_TMP=""
        sync -- "$PROFILE_DIR"
        if [ "$(stat -Lc '%u:%a:%h' -- "$XULSTORE" 2>/dev/null || echo "")" != \
             "$(id -u):600:1" ]; then
            _log "seeded xulstore.json failed its metadata postcondition"
            exit 1
        fi
        _log "seeded xulstore.json for the uninitialized playground profile"
    else
        if ! rm -f -- "$XULSTORE_TMP"; then
            _log "could not retire staged xulstore.json after publish race"
            exit 1
        fi
        XULSTORE_TMP=""
        if [ -f "$XULSTORE" ] && [ ! -L "$XULSTORE" ]; then
            _log "preserved concurrently created xulstore.json"
        else
            _log "could not safely seed xulstore.json"
            exit 1
        fi
    fi
fi

# Firefox omni.ja stays untouched. Fedora's packaged archive may still carry
# distro default bookmarks even when the separate fedora-bookmarks package is
# excluded. The native empty-backup seed below makes Firefox restore an empty
# Places tree before its default-bookmark import path; no places.sqlite deletion
# or browser-process race is used.

# Install the pinned profile-local uBlock Origin payload, then grant and verify
# its separate Firefox private-window permission. The shared M16 helper owns
# both current contracts.
if ! install_ubo_profile_local "$PROFILE_NAME"; then
    _log "install_ubo_profile_local FAILED — refusing to mark playground ready"
    exit 1
fi
if ! patch_ubo_pb_permission "$PROFILE_NAME"; then
    _log "patch_ubo_pb_permission FAILED — refusing a private-only profile without uBO permission"
    exit 1
fi
if ! profile_hardening_complete "$PROFILE_NAME"; then
    _log "complete playground hardening postcondition failed — refusing ready state"
    exit 1
fi

# Seed the same empty, native Firefox bookmark-backup contract as M16 only
# while no backup exists. Never delete or replace user-created bookmarks.
NOID_BM_DIR="$PROFILE_DIR/bookmarkbackups"
if [ -L "$NOID_BM_DIR" ] || { [ -e "$NOID_BM_DIR" ] && [ ! -d "$NOID_BM_DIR" ]; }; then
    _log "bookmark backup path is non-directory or symlinked"
    exit 1
fi
if [ ! -d "$NOID_BM_DIR" ]; then
    install -d -m 700 -- "$NOID_BM_DIR"
fi
NOID_BM_DIR_STATE=$(stat -c '%u:%a' -- "$NOID_BM_DIR")
if [ "$NOID_BM_DIR_STATE" != "$(id -u):700" ]; then
    _log "bookmark backup directory ownership/mode is unsafe"
    exit 1
fi

shopt -s nullglob
NOID_BM_EXISTING=(
    "$NOID_BM_DIR"/bookmarks-*.json
    "$NOID_BM_DIR"/bookmarks-*.jsonlz4
)
shopt -u nullglob
for NOID_BM_BACKUP in "${NOID_BM_EXISTING[@]}"; do
    if [ ! -f "$NOID_BM_BACKUP" ] || [ -L "$NOID_BM_BACKUP" ]; then
        _log "bookmark backup candidate is non-regular or symlinked"
        exit 1
    fi
done

if [ "${#NOID_BM_EXISTING[@]}" -gt 0 ]; then
    _log "preserved existing Firefox bookmark backups"
else
    NOID_BM_TS=$(date +%s%6N)
    NOID_BM_DATE=$(date +%Y-%m-%d)
    NOID_BM_TARGET="$NOID_BM_DIR/bookmarks-${NOID_BM_DATE}.json"
    NOID_BM_TMP=$(mktemp "$NOID_BM_DIR/.bookmarks-empty.tmp.XXXXXXXX") || {
        _log "could not create staged Firefox bookmark backup"
        exit 1
    }
    cat > "$NOID_BM_TMP" <<BOOKMARKS_BACKUP_EOF
{
  "guid": "root________",
  "title": "",
  "index": 0,
  "dateAdded": ${NOID_BM_TS},
  "lastModified": ${NOID_BM_TS},
  "id": 1,
  "typeCode": 2,
  "type": "text/x-moz-place-container",
  "root": "placesRoot",
  "children": [
    {"guid": "menu________", "title": "menu", "index": 0, "dateAdded": ${NOID_BM_TS}, "lastModified": ${NOID_BM_TS}, "id": 2, "typeCode": 2, "type": "text/x-moz-place-container", "root": "bookmarksMenuFolder", "children": []},
    {"guid": "toolbar_____", "title": "toolbar", "index": 1, "dateAdded": ${NOID_BM_TS}, "lastModified": ${NOID_BM_TS}, "id": 3, "typeCode": 2, "type": "text/x-moz-place-container", "root": "toolbarFolder", "children": []},
    {"guid": "tags________", "title": "tags", "index": 2, "dateAdded": ${NOID_BM_TS}, "lastModified": ${NOID_BM_TS}, "id": 4, "typeCode": 2, "type": "text/x-moz-place-container", "root": "tagsFolder", "children": []},
    {"guid": "unfiled_____", "title": "unfiled", "index": 3, "dateAdded": ${NOID_BM_TS}, "lastModified": ${NOID_BM_TS}, "id": 5, "typeCode": 2, "type": "text/x-moz-place-container", "root": "unfiledBookmarksFolder", "children": []},
    {"guid": "mobile______", "title": "mobile", "index": 4, "dateAdded": ${NOID_BM_TS}, "lastModified": ${NOID_BM_TS}, "id": 6, "typeCode": 2, "type": "text/x-moz-place-container", "root": "mobileFolder", "children": []}
  ]
}
BOOKMARKS_BACKUP_EOF
    chmod 600 "$NOID_BM_TMP"
    sync -- "$NOID_BM_TMP"
    if ln -- "$NOID_BM_TMP" "$NOID_BM_TARGET"; then
        if ! rm -f -- "$NOID_BM_TMP"; then
            _log "could not retire staged Firefox bookmark backup"
            exit 1
        fi
        NOID_BM_TMP=""
        sync -- "$NOID_BM_DIR"
        if [ "$(stat -Lc '%u:%a:%h' -- "$NOID_BM_TARGET" 2>/dev/null || echo "")" != \
             "$(id -u):600:1" ]; then
            _log "seeded Firefox bookmark backup failed its metadata postcondition"
            exit 1
        fi
        _log "seeded empty bookmarks backup → skip Fedora default-bookmarks import"
    else
        if ! rm -f -- "$NOID_BM_TMP"; then
            _log "could not retire staged Firefox bookmark backup after publish race"
            exit 1
        fi
        NOID_BM_TMP=""
        if [ -f "$NOID_BM_TARGET" ] && [ ! -L "$NOID_BM_TARGET" ]; then
            _log "preserved concurrently created Firefox bookmark backup"
        else
            _log "could not safely seed Firefox bookmark backup"
            exit 1
        fi
    fi
fi

if [ ! -r "$PROFILE_DIR/user.js" ]; then
    _log "user.js missing after successful apply_userjs — refusing ready state"
    exit 1
fi
if ! profile_hardening_complete "$PROFILE_NAME"; then
    _log "final playground hardening postcondition failed — refusing ready state"
    exit 1
fi

if [ -L "$MARKER" ] || { [ -e "$MARKER" ] && [ ! -f "$MARKER" ]; }; then
    _log "playground ready marker became unsafe"
    exit 1
fi
MARKER_TMP=$(mktemp "$MARKER_DIR/.firefox-playground-init.done.tmp.XXXXXXXX") || {
    _log "could not create staged playground ready marker"
    exit 1
}
printf '%s\n' "$MARKER_CONTENT" > "$MARKER_TMP"
chmod 600 "$MARKER_TMP"
sync -- "$MARKER_TMP"
MARKER_PUBLICATION_ACTIVE=1
mv -fT -- "$MARKER_TMP" "$MARKER"
MARKER_TMP=""
sync -- "$MARKER_DIR"
if ! playground_marker_valid; then
    if ! rm -f -- "$MARKER"; then
        _log "published invalid ready marker could not be retired"
    fi
    if ! sync -- "$MARKER_DIR"; then
        _log "ready-marker directory sync failed during retirement"
    fi
    _log "published playground ready marker failed validation"
    exit 1
fi
MARKER_PUBLICATION_ACTIVE=0

# Profile mutation is complete. Do not retain the shared lock while a desktop
# notification waits for another application to close.
flock -u "$NOID_FF_PROFILE_LOCK_FD"
exec {NOID_FF_PROFILE_LOCK_FD}>&-

# Notify only fires when this is the FIRST init run (PROFILE_EXISTS=0
# at script start) — re-runs from chained setup-script invocations should
# not show "ready again" duplicate notification.
if [ "$PROFILE_EXISTS" -eq 0 ]; then
    NOID_LOGO="/usr/share/pixmaps/noid-privacy-logo.png"
    # Defer only the visible notification while Fedora Welcome is active.
    # Never source an optional helper whose root-owned metadata is unsafe.
    if trusted_root_file "$WELCOME_HELPER" 644; then
        # shellcheck source=/dev/null
        . "$WELCOME_HELPER"
        noid_wait_fedora_welcome 600 20
    elif [ -e "$WELCOME_HELPER" ] || [ -L "$WELCOME_HELPER" ]; then
        _log "welcome-wait helper has unsafe metadata — notification proceeds without sourcing it"
    fi
    notify-send --urgency=normal --icon="$NOID_LOGO" \
        "NoID Privacy: Firefox ready" \
        "Hardening + uBlock Origin active. Playground discards private-session browser data; saved files and bookmarks persist." \
        2>/dev/null || true
fi

USERJS_LINES=$(wc -l < "$PROFILE_DIR/user.js")
_log "playground profile initialized at $PROFILE_DIR (user.js $USERJS_LINES lines, uBlock PB permission verified)"
trap - EXIT HUP INT TERM
exit 0
INIT_EOF

if ! bash -n "$INIT_TMP"; then
    die "noid-firefox-playground-init.sh has syntax errors"
fi
publish_root_file "$INIT_TMP" "$INIT_TARGET" 755
INIT_TMP=""
log "  [OK] noid-firefox-playground-init.sh written + syntax-clean"

# ----------------------------------------------------------------------------
# Phase 7 — Write XDG autostart for first-login invocation
# ----------------------------------------------------------------------------
PHASE="P7-autostart"
log "Writing /etc/xdg/autostart/noid-firefox-playground-init.desktop"

AUTOSTART_TARGET=/etc/xdg/autostart/noid-firefox-playground-init.desktop
AUTOSTART_TMP=$(mktemp --suffix=.desktop /etc/xdg/autostart/.noid-firefox-playground-init.XXXXXX) ||
    die "cannot create Playground autostart temporary file"
cat > "$AUTOSTART_TMP" <<'AUTOSTART_EOF'
[Desktop Entry]
Type=Application
Version=1.0
Name=NoID Privacy Firefox Playground Init
Comment=Create the separate private-session Firefox profile at first login
Exec=/usr/local/bin/noid-firefox-playground-init.sh
TryExec=/usr/local/bin/noid-firefox-playground-init.sh
Terminal=false
Hidden=false
NoDisplay=true
StartupNotify=false
X-GNOME-Autostart-enabled=true
# NOTE: OnlyShowIn=GNOME omitted for DE-agnostic parity.
# The init script uses Firefox's profile CLI and filesystem operations only.
# Per XDG spec OnlyShowIn should only restrict where DE-specific behavior
# exists. dconf favorite-apps defaults are applied system-wide in M34 Phase 5,
# not in this per-user init script. Matches the M13 welcome.desktop
# OnlyShowIn cleanup.
AUTOSTART_EOF

/usr/bin/desktop-file-validate "$AUTOSTART_TMP" ||
    die "Playground autostart desktop entry failed validation"
publish_root_file "$AUTOSTART_TMP" "$AUTOSTART_TARGET" 644
AUTOSTART_TMP=""
log "  [OK] XDG autostart entry written"

# ----------------------------------------------------------------------------
# Phase 8 — SELinux context restore
# ----------------------------------------------------------------------------
PHASE="P8-selinux"
log "Restoring SELinux contexts"

for payload in \
    /usr/share/noid-firefox/user-playground-overrides.js \
    /usr/share/applications/firefox-playground.desktop \
    /etc/dconf/db/distro.d/16-noid-firefox-playground \
    /usr/local/bin/noid-firefox-playground-init.sh \
    /etc/xdg/autostart/noid-firefox-playground-init.desktop; do
    /usr/sbin/restorecon -F -- "$payload" ||
        die "restorecon failed for Module 34 payload: $payload"
    /usr/sbin/matchpathcon -V "$payload" >/dev/null ||
        die "SELinux context differs for Module 34 payload: $payload"
done
log "  [OK] every Module 34 payload has its canonical SELinux context"

# ----------------------------------------------------------------------------
# Phase 9 — Verification
# ----------------------------------------------------------------------------
PHASE="P9-verify"
log "Running verification"

checks=0
fails=0

check() {
    local desc="$1"
    shift
    checks=$((checks + 1))
    if "$@"; then
        log "  [OK] $desc"
    else
        fails=$((fails + 1))
        log "  [FAIL] $desc"
    fi
}

# --- Overrides JS ---
check "user-playground-overrides.js regular root:root 0644 link-count=1" \
    verify_owned_regular /usr/share/noid-firefox/user-playground-overrides.js 644
overrides_size=$(stat -c %s /usr/share/noid-firefox/user-playground-overrides.js 2>/dev/null || echo 0)
overrides_size=${overrides_size:-0}
check "user-playground-overrides.js > 1KB (actual: $overrides_size bytes)" \
    test "$overrides_size" -gt 1024

for pref in "browser.privatebrowsing.autostart" \
            "privacy.sanitize.sanitizeOnShutdown" \
            "privacy.clearOnShutdown_v2.cookiesAndStorage" \
            "privacy.clearOnShutdown_v2.browsingHistoryAndDownloads" \
            "privacy.clearOnShutdown_v2.cache" \
            "privacy.clearOnShutdown_v2.formdata" \
            "privacy.clearOnShutdown_v2.siteSettings"; do
    if grep -qxF "user_pref(\"$pref\", true);" \
            /usr/share/noid-firefox/user-playground-overrides.js; then
        checks=$((checks + 1))
        log "  [OK] overrides set pref true: $pref"
    else
        checks=$((checks + 1))
        fails=$((fails + 1))
        log "  [FAIL] overrides do not set pref true: $pref"
    fi
done
for pref in "places.history.enabled" "signon.rememberSignons"; do
    if grep -qxF "user_pref(\"$pref\", false);" \
            /usr/share/noid-firefox/user-playground-overrides.js; then
        checks=$((checks + 1))
        log "  [OK] overrides set pref false: $pref"
    else
        checks=$((checks + 1))
        fails=$((fails + 1))
        log "  [FAIL] overrides do not set pref false: $pref"
    fi
done

# --- .desktop file ---
check "firefox-playground.desktop regular root:root 0644 link-count=1" \
    verify_owned_regular /usr/share/applications/firefox-playground.desktop 644
check "firefox-playground.desktop passes desktop-file validation" \
    /usr/bin/desktop-file-validate /usr/share/applications/firefox-playground.desktop

for kw in "Name=Firefox (Playground)" \
          "Exec=/usr/local/bin/firefox -P playground --no-remote --name firefox-playground --class firefox-playground %u" \
          "Exec=/usr/local/bin/firefox -P playground --no-remote --name firefox-playground --class firefox-playground --private-window %u" \
          "Categories=Network;WebBrowser;"; do
    if grep -qxF "$kw" /usr/share/applications/firefox-playground.desktop 2>/dev/null; then
        checks=$((checks + 1))
        log "  [OK] .desktop contains: $kw"
    else
        checks=$((checks + 1))
        fails=$((fails + 1))
        log "  [FAIL] .desktop missing: $kw"
    fi
done

# Icon lookup must be the exact package-owned name, not the retired custom
# prefix (for which grep -qF "Icon=firefox" would be an unsafe substring test).
desktop_icon_count=$(grep -xcF 'Icon=firefox' \
    /usr/share/applications/firefox-playground.desktop 2>/dev/null || true)
check "desktop uses exactly one packaged Firefox icon lookup" \
    test "$desktop_icon_count" -eq 1
if grep -qxF 'Icon=firefox-playground' \
        /usr/share/applications/firefox-playground.desktop 2>/dev/null; then
    checks=$((checks + 1))
    fails=$((fails + 1))
    log "  [FAIL] desktop references the retired custom icon"
else
    checks=$((checks + 1))
    log "  [OK] desktop does not reference the retired custom icon"
fi

# --- Packaged Firefox icon ---
# Re-scan the filesystem instead of reusing Phase 3's already-gated count.
phase9_firefox_icon_count=0
shopt -s nullglob
phase9_firefox_icons=(
    /usr/share/icons/hicolor/*/apps/firefox.png
    /usr/share/icons/hicolor/symbolic/apps/firefox*-symbolic.svg
)
shopt -u nullglob
for phase9_firefox_icon in "${phase9_firefox_icons[@]}"; do
    if [ -f "$phase9_firefox_icon" ] && [ ! -L "$phase9_firefox_icon" ]; then
        phase9_firefox_icon_count=$((phase9_firefox_icon_count + 1))
    fi
done
check "packaged Firefox icon still present (actual: $phase9_firefox_icon_count variant(s))" \
    test "$phase9_firefox_icon_count" -ge 1

# --- Legacy custom icon paths absent ---
legacy_playground_icon_count=0
for size in $LEGACY_PLAYGROUND_ICON_SIZES; do
    legacy_playground_icon="/usr/share/icons/hicolor/${size}x${size}/apps/firefox-playground.png"
    if [ -e "$legacy_playground_icon" ] || [ -L "$legacy_playground_icon" ]; then
        legacy_playground_icon_count=$((legacy_playground_icon_count + 1))
    fi
done
check "legacy custom Playground icon aliases absent" \
    test "$legacy_playground_icon_count" -eq 0

# --- dconf distro default ---
check "dconf keyfile regular root:root 0644 link-count=1" \
    verify_owned_regular /etc/dconf/db/distro.d/16-noid-firefox-playground 644

expected_favorites="favorite-apps=['org.mozilla.firefox.desktop', 'net.thunderbird.Thunderbird.desktop', 'org.gnome.Software.desktop', 'org.gnome.Nautilus.desktop', 'org.gnome.Ptyxis.desktop', 'org.gnome.Settings.desktop']"
# This is the compiled distro default, not mutable per-user dconf state:
# require the exact reviewed six-entry order and keep Playground app-grid-only.
if grep -qxF "$expected_favorites" \
        /etc/dconf/db/distro.d/16-noid-firefox-playground 2>/dev/null; then
    checks=$((checks + 1))
    log "  [OK] dconf default has the exact six reviewed favorites"
else
    checks=$((checks + 1))
    fails=$((fails + 1))
    log "  [FAIL] dconf default does not match the six reviewed favorites"
fi

# --- dconf unlocked (user can customize) ---
if [ -e /etc/dconf/db/distro.d/locks/16-noid-firefox-playground ] ||
   [ -L /etc/dconf/db/distro.d/locks/16-noid-firefox-playground ]; then
    checks=$((checks + 1))
    fails=$((fails + 1))
    log "  [FAIL] dconf lock file exists — favorites should be unlocked"
else
    checks=$((checks + 1))
    log "  [OK] no dconf lock file (user can customize favorites)"
fi

# --- Init script ---
check "noid-firefox-playground-init.sh regular root:root 0755 link-count=1" \
    verify_owned_regular /usr/local/bin/noid-firefox-playground-init.sh 755
check "noid-firefox-playground-init.sh bash -n clean" \
    bash -n /usr/local/bin/noid-firefox-playground-init.sh

for kw in "/usr/local/lib/noid-privacy/firefox-profiles.sh" \
          "ensure_profile " \
          "apply_userjs " \
          "firefox-playground-init.done" \
          "user.js"; do
    if grep -qF "$kw" /usr/local/bin/noid-firefox-playground-init.sh 2>/dev/null; then
        checks=$((checks + 1))
        log "  [OK] init-script contains: $kw"
    else
        checks=$((checks + 1))
        fails=$((fails + 1))
        log "  [FAIL] init-script missing: $kw"
    fi
done

# --- XDG autostart ---
check "XDG autostart regular root:root 0644 link-count=1" \
    verify_owned_regular /etc/xdg/autostart/noid-firefox-playground-init.desktop 644
check "XDG autostart passes desktop-file validation" \
    /usr/bin/desktop-file-validate /etc/xdg/autostart/noid-firefox-playground-init.desktop

if grep -qxF "Exec=/usr/local/bin/noid-firefox-playground-init.sh" \
       /etc/xdg/autostart/noid-firefox-playground-init.desktop 2>/dev/null; then
    checks=$((checks + 1))
    log "  [OK] autostart Exec points to init script"
else
    checks=$((checks + 1))
    fails=$((fails + 1))
    log "  [FAIL] autostart Exec wrong"
fi
if grep -qxF "TryExec=/usr/local/bin/noid-firefox-playground-init.sh" \
       /etc/xdg/autostart/noid-firefox-playground-init.desktop 2>/dev/null; then
    checks=$((checks + 1))
    log "  [OK] autostart TryExec gates the installed init script"
else
    checks=$((checks + 1))
    fails=$((fails + 1))
    log "  [FAIL] autostart TryExec missing/wrong"
fi

log "Verification: $((checks - fails))/$checks passed"
if [ "$fails" -gt 0 ]; then
    die "$fails verification check(s) FAILED"
fi

# ----------------------------------------------------------------------------
# Phase 10 — Health stamp
# ----------------------------------------------------------------------------
PHASE="P10-stamp"
# M34_HEALTH_PUBLICATION_BEGIN
if [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ] \
   || [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
        0:0:755 ] \
   || ! /usr/sbin/matchpathcon -V "$STAMP_DIR" >/dev/null; then
    die "shared health-stamp directory drifted before Module 34 publication"
fi

verify_m34_health_stamp() {
    local path="$1"
    [ -f "$path" ] \
        && [ ! -L "$path" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' -- "$path" 2>/dev/null || true)" = \
            0:0:644:1 ] \
        && [ "$(wc -l < "$path")" -eq 11 ] \
        && [ "$(grep -c '^module=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^name=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^version=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^status=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^timestamp=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^checks_passed=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^checks_total=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^icon_name=' "$path" || true)" -eq 1 ] \
        && grep -qFx '# NoID Privacy — Module 34 Health Stamp' "$path" \
        && grep -qFx \
            '# Written at end of %post verification when all checks pass.' \
            "$path" \
        && grep -qFx \
            '# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.' \
            "$path" \
        && grep -qFx 'module=34' "$path" \
        && grep -qFx 'name=firefox-playground' "$path" \
        && grep -qFx 'version=1' "$path" \
        && grep -qFx 'status=ok' "$path" \
        && grep -Eq \
            '^timestamp=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' \
            "$path" \
        && grep -qFx "checks_passed=$((checks - fails))" "$path" \
        && grep -qFx "checks_total=$checks" "$path" \
        && grep -qFx 'icon_name=firefox' "$path"
}

STAMP_TMP=$(mktemp "$STAMP_DIR/.stamp-34-firefox-playground.ok.XXXXXXXX") ||
    die "cannot create Module 34 stamp temporary file"
cat > "$STAMP_TMP" <<STAMP_EOF
# NoID Privacy — Module 34 Health Stamp
# Written at end of %post verification when all checks pass.
# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.
module=34
name=firefox-playground
version=1
status=ok
timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
checks_passed=$((checks - fails))
checks_total=$checks
icon_name=firefox
STAMP_EOF

chown root:root -- "$STAMP_TMP"
chmod 0644 -- "$STAMP_TMP"
/usr/sbin/restorecon -F -- "$STAMP_TMP" \
    || die "cannot label Module 34 health-stamp candidate"
/usr/sbin/matchpathcon -V "$STAMP_TMP" >/dev/null \
    || die "Module 34 health-stamp candidate label differs"
verify_m34_health_stamp "$STAMP_TMP" \
    || die "staged Module 34 health-stamp contract is invalid"
sync -- "$STAMP_TMP" \
    || die "cannot sync Module 34 health-stamp candidate"

STAMP_PUBLICATION_ACTIVE=1
publish_root_file "$STAMP_TMP" "$STAMP" 644
STAMP_TMP=""
/usr/sbin/restorecon -F -- "$STAMP" \
    || die "cannot label published Module 34 health stamp"
/usr/sbin/matchpathcon -V "$STAMP" >/dev/null \
    || die "published Module 34 health-stamp label differs"
sync -- "$STAMP" \
    || die "cannot sync published Module 34 health stamp"
sync -- "$STAMP_DIR" \
    || die "cannot sync Module 34 health-stamp directory"
verify_m34_health_stamp "$STAMP" \
    || die "published Module 34 health-stamp contract is invalid"
STAMP_PUBLICATION_ACTIVE=0
log "  [OK] exact Module 34 health stamp published atomically"
# M34_HEALTH_PUBLICATION_END

trap - EXIT HUP INT TERM
log "=== Module 34 Firefox Playground complete ==="
%end
