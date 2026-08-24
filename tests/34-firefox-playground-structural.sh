#!/bin/bash
# 34-firefox-playground-structural — Module 34 regression test
#
# M34 ships a second, private-session Firefox profile "playground" via:
#   - /usr/share/noid-firefox/user-playground-overrides.js
#   - /usr/share/applications/firefox-playground.desktop
#   - /etc/dconf/db/distro.d/16-noid-firefox-playground
#   - /usr/local/bin/noid-firefox-playground-init.sh
#   - /etc/xdg/autostart/noid-firefox-playground-init.desktop
#
# This test extracts each heredoc and asserts structural invariants:
#   - Heredocs produce files above minimum size
#   - Current Firefox shutdown-sanitizer prefs are exact
#   - .desktop file has correct Exec + Icon + Categories
#   - Init script is bash -n clean, content-idempotent, fail-closed around
#     running Firefox and delegates profile work to the M16 helper
#   - packaged Firefox icon lookup + exact legacy custom-icon retirement
#   - dconf keyfile has the exact reviewed defaults and is unlocked
#   - Stamp pattern + ordering

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/34-firefox-playground.ks"
FIREFOX_SOURCE="$PROJECT_ROOT/firefox/noid-firefox-hardening.js"

test_start "34-firefox-playground-structural"

if [ ! -f "$KS_FILE" ]; then
    _fail "M34 snippet missing: $KS_FILE"
    test_finish
    exit 1
fi

assert_cmd_success "M34 snippet passes bash -n" bash -n "$KS_FILE"

TMPDIR="$(mktemp -d)"
# Fake SELinux/publication commands must execute on the hardened development
# host, whose /tmp is noexec.
EXEC_FIXTURE_DIR="$(mktemp -d "$PROJECT_ROOT/.test-m34-fixture.XXXXXX")"
trap 'rm -rf "$TMPDIR" "$EXEC_FIXTURE_DIR"' EXIT

# --- extract heredocs -------------------------------------------------------

extract_heredoc "$KS_FILE" "OVERRIDES_EOF" "$TMPDIR/user-playground-overrides.js"         || true
extract_heredoc "$KS_FILE" "DESKTOP_EOF"   "$TMPDIR/firefox-playground.desktop"           || true
extract_heredoc "$KS_FILE" "DCONF_EOF"     "$TMPDIR/16-noid-firefox-playground"           || true
extract_heredoc "$KS_FILE" "INIT_EOF"      "$TMPDIR/noid-firefox-playground-init.sh"      || true
extract_heredoc "$KS_FILE" "AUTOSTART_EOF" "$TMPDIR/noid-firefox-playground-init.desktop" || true

# --- %packages block: ImageMagick must NOT be declared ----------------------
# The current package-owned icon lookup needs no renderer. Regression check:
# prevent re-introduction of the old runtime dependency.
if awk '/^%packages/,/^%end/' "$KS_FILE" 2>/dev/null | grep -qE '^ImageMagick\s*$'; then
    _fail "%packages re-introduces unnecessary ImageMagick"
else
    _pass "%packages does NOT declare ImageMagick (package-owned icon lookup)"
fi

# --- user-playground-overrides.js structural ------------------------------

assert_file_min_size "$TMPDIR/user-playground-overrides.js" 1024 "overrides JS > 1KB"
assert_grep_fixed 'system/VPN resolver' \
    "$TMPDIR/user-playground-overrides.js" \
    "playground inheritance comment matches the current resolver contract"
assert_not_grep 'FPP, DoH' "$TMPDIR/user-playground-overrides.js" \
    "playground docs do not resurrect forced Firefox DoH"

# Current Firefox private-session and shutdown-sanitizer contract.
for pref in "browser.privatebrowsing.autostart" \
            "privacy.sanitize.sanitizeOnShutdown" \
            "privacy.clearOnShutdown_v2.cookiesAndStorage" \
            "privacy.clearOnShutdown_v2.browsingHistoryAndDownloads" \
            "privacy.clearOnShutdown_v2.cache" \
            "privacy.clearOnShutdown_v2.formdata" \
            "privacy.clearOnShutdown_v2.siteSettings" \
            "places.history.enabled" \
            "browser.sessionstore.resume_from_crash" \
            "signon.rememberSignons" \
            "browser.cache.disk.enable" \
            "browser.newtabpage.enabled"; do
    assert_grep_fixed "$pref" "$TMPDIR/user-playground-overrides.js" "private-session pref: $pref"
done

# A disposable profile retains neither permission grants nor denials.
assert_grep_fixed '"privacy.clearOnShutdown_v2.siteSettings", true' \
    "$TMPDIR/user-playground-overrides.js" \
    "current sanitizer clears site permissions"

for obsolete_pref in \
    extensions.allowPrivateBrowsingByDefault \
    extensions.PrivateBrowsing.notification \
    browser.download.manager.retention \
    browser.cache.memory.max_entry_size \
    browser.cache.disk_cache_ssl \
    browser.newtab.url \
    browser.newtabpage.activity-stream.enabled \
    privacy.clearOnShutdown_v2.historyFormDataAndDownloads \
    privacy.clearOnShutdown_v2.downloads \
    privacy.clearOnShutdown.cache \
    privacy.clearOnShutdown.cookies \
    privacy.clearOnShutdown.downloads \
    privacy.clearOnShutdown.formdata \
    privacy.clearOnShutdown.history \
    privacy.clearOnShutdown.offlineApps \
    privacy.clearOnShutdown.sessions \
    privacy.clearOnShutdown.siteSettings; do
    assert_not_grep "$obsolete_pref" "$TMPDIR/user-playground-overrides.js" \
        "obsolete/redundant pref absent: $obsolete_pref"
done
assert_grep_fixed 'Saved download files and newly created bookmarks remain' \
    "$TMPDIR/user-playground-overrides.js" \
    "private-browsing persistence boundary is explicit"
assert_grep_fixed 'not an integrity attestation' \
    "$TMPDIR/user-playground-overrides.js" \
    "custom profile marker is not misrepresented as evidence"
assert_grep_fixed 'https://support.mozilla.org/en-US/kb/private-browsing-use-firefox-without-history' \
    "$TMPDIR/user-playground-overrides.js" \
    "private-browsing claim cites Mozilla"
assert_grep_fixed 'https://searchfox.org/mozilla-central/source/browser/modules/Sanitizer.sys.mjs' \
    "$TMPDIR/user-playground-overrides.js" \
    "shutdown-sanitizer claim cites Mozilla source"
assert_not_grep 'private-session container' \
    "$TMPDIR/user-playground-overrides.js" \
    "Playground does not mislabel Private Browsing as a container"

# Verify the actual M16+M34 user.js composition, not only the override fragment.
if [ -f "$FIREFOX_SOURCE" ]; then
    cat "$FIREFOX_SOURCE" "$TMPDIR/user-playground-overrides.js" \
        > "$TMPDIR/composed-playground-user.js"
    assert_grep_fixed \
        'user_pref("privacy.sanitize.clearOnShutdown.hasMigratedToNewPrefs3", true);' \
        "$TMPDIR/composed-playground-user.js" \
        "composed Playground profile pins the current shutdown migration marker"
    for composed_pref in \
        privacy.clearOnShutdown_v2.cookiesAndStorage \
        privacy.clearOnShutdown_v2.browsingHistoryAndDownloads \
        privacy.clearOnShutdown_v2.cache \
        privacy.clearOnShutdown_v2.formdata \
        privacy.clearOnShutdown_v2.siteSettings; do
        composed_last=$(grep -F "user_pref(\"$composed_pref\"," \
            "$TMPDIR/composed-playground-user.js" | tail -n 1 || true)
        assert_eq "user_pref(\"$composed_pref\", true);" "$composed_last" \
            "composed Playground profile ends with current true value: $composed_pref"
    done
    for retired_composed_pref in \
        privacy.clearOnShutdown_v2.historyFormDataAndDownloads \
        privacy.clearOnShutdown_v2.downloads; do
        assert_not_grep "$retired_composed_pref" \
            "$TMPDIR/composed-playground-user.js" \
            "retired shutdown category absent from complete composition: $retired_composed_pref"
    done
else
    _fail "canonical M16 Firefox source missing: $FIREFOX_SOURCE"
fi

# --- firefox-playground.desktop structural --------------------------------

assert_file_min_size "$TMPDIR/firefox-playground.desktop" 256 "desktop file > 256 bytes"
assert_cmd_success "Playground desktop entry validates" \
    desktop-file-validate "$TMPDIR/firefox-playground.desktop"

assert_grep_fixed "Name=Firefox (Playground)"                 "$TMPDIR/firefox-playground.desktop"
assert_grep_fixed \
    "Exec=/usr/local/bin/firefox -P playground --no-remote --name firefox-playground --class firefox-playground %u" \
    "$TMPDIR/firefox-playground.desktop" \
    "main launcher uses the owned wrapper and stable Wayland/X11 identity"
assert_grep_fixed \
    "Exec=/usr/local/bin/firefox -P playground --no-remote --name firefox-playground --class firefox-playground --private-window %u" \
    "$TMPDIR/firefox-playground.desktop" \
    "private-window action uses the same owned wrapper and identity"
assert_grep_fixed "Icon=firefox"                              "$TMPDIR/firefox-playground.desktop"
assert_not_grep '^Icon=firefox-playground$'                   "$TMPDIR/firefox-playground.desktop" \
    "desktop does not reference a duplicate Playground icon"
assert_grep_fixed "Categories=Network;WebBrowser;"            "$TMPDIR/firefox-playground.desktop"
assert_grep_fixed "MimeType="                                 "$TMPDIR/firefox-playground.desktop" "MimeType declared"
assert_not_grep 'x-scheme-handler/ftp' "$TMPDIR/firefox-playground.desktop" \
    "retired Firefox FTP handler is not advertised"
assert_not_grep 'Clears everything' "$TMPDIR/firefox-playground.desktop" \
    "launcher does not overclaim private-session deletion"
assert_grep_fixed 'saved files and bookmarks persist' \
    "$TMPDIR/firefox-playground.desktop" \
    "launcher states the important persistence boundary"
assert_grep_fixed "Actions=new-private-window;" \
    "$TMPDIR/firefox-playground.desktop" "right-click actions"
assert_grep_fixed "StartupNotify=true" "$TMPDIR/firefox-playground.desktop"
# StartupWMClass=firefox-playground pairs with GTK3's X11 program class, while
# --name supplies the corresponding native-Wayland program name/app_id.
assert_grep_fixed "StartupWMClass=firefox-playground" "$TMPDIR/firefox-playground.desktop"
assert_grep_fixed 'GTK3/GDK'\''s --name option sets the program name used for the native Wayland' \
    "$TMPDIR/firefox-playground.desktop" \
    "launcher documents the native-Wayland identity mechanism"
assert_grep_fixed 'while --class sets the X11/XWayland program class' \
    "$TMPDIR/firefox-playground.desktop" \
    "launcher documents the X11/XWayland identity mechanism"
assert_grep_fixed 'https://bugzilla.mozilla.org/show_bug.cgi?id=1577056' \
    "$TMPDIR/firefox-playground.desktop" \
    "backend split and Fedora two-option behavior cite Mozilla's primary record"
assert_not_grep 'pgrep -P playground' "$TMPDIR/firefox-playground.desktop" \
    "launcher has no invalid parent-PID example"
assert_grep_fixed 'https://firefox-source-docs.mozilla.org/browser/CommandLineParameters.html' \
    "$TMPDIR/firefox-playground.desktop" \
    "no-remote behavior cites current Firefox source documentation"
assert_grep_fixed 'https://docs.gtk.org/gtk3/running.html' \
    "$TMPDIR/firefox-playground.desktop" \
    "GTK class claim cites the maintained primary documentation"
assert_grep_fixed 'https://specifications.freedesktop.org/desktop-entry/latest/recognized-keys.html' \
    "$TMPDIR/firefox-playground.desktop" \
    "StartupWMClass claim cites the current primary specification"

# --- dconf keyfile structural ---------------------------------------------

assert_grep_fixed "[org/gnome/shell]"        "$TMPDIR/16-noid-firefox-playground"
assert_grep_fixed "favorite-apps="           "$TMPDIR/16-noid-firefox-playground"
assert_grep_fixed "firefox.desktop"          "$TMPDIR/16-noid-firefox-playground" "productive pinned"
assert_grep_fixed \
    "favorite-apps=['org.mozilla.firefox.desktop', 'net.thunderbird.Thunderbird.desktop', 'org.gnome.Software.desktop', 'org.gnome.Nautilus.desktop', 'org.gnome.Ptyxis.desktop', 'org.gnome.Settings.desktop']" \
    "$TMPDIR/16-noid-firefox-playground" \
    "Fedora 44/GNOME 50 favorites contract is exact"

# firefox-playground was REMOVED from favorite-apps per user preference.
# Playground is reachable
# via app-grid only (firefox-playground.desktop present in
# /usr/share/applications/, verified above). The dconf favorite-apps line
# now contains only the productive 6 default apps. Verify regression: if
# someone re-adds playground to favorites, this test catches it.
if grep -qE '^favorite-apps=.*firefox-playground\.desktop' "$TMPDIR/16-noid-firefox-playground" 2>/dev/null; then
    _fail "favorite-apps: firefox-playground re-pinned (user-pref: app-grid only)"
else
    _pass "favorite-apps: firefox-playground correctly NOT pinned (user-pref)"
fi

# Snippet MUST NOT create a dconf lock file for this keyfile.
# We look for an actual file-WRITE (cat >, echo >, touch), NOT the file-existence
# check the snippet runs inside its own verification block.
if grep -qE '(cat\s*>|echo[^>]*>|touch|tee)\s+[^|]*locks/16-noid-firefox-playground' "$KS_FILE"; then
    _fail "M34 creates a dconf lock file — favorites should be unlocked (user can customize)"
else
    _pass "M34 does not create dconf lock file (favorites user-customizable)"
fi

# --- noid-firefox-playground-init.sh structural --------------------------

assert_file_min_size "$TMPDIR/noid-firefox-playground-init.sh" 1024 \
    "init script > 1KB"
assert_cmd_success "init script bash -n clean" \
    bash -n "$TMPDIR/noid-firefox-playground-init.sh"
assert_grep_fixed 'set -euo pipefail' "$TMPDIR/noid-firefox-playground-init.sh" \
    "init script fails on unhandled setup errors"
assert_grep_fixed 'PATH=/usr/local/bin:/usr/sbin:/usr/bin' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "init script uses a deterministic trusted executable path"
assert_grep_fixed 'umask 077' "$TMPDIR/noid-firefox-playground-init.sh" \
    "init script creates per-user state privately by default"
assert_grep_fixed 'if [ "$#" -ne 0 ]; then' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "initializer accepts exactly its argumentless autostart contract"
arg_gate_line=$(grep -nF 'if [ "$#" -ne 0 ]; then' \
    "$TMPDIR/noid-firefox-playground-init.sh" | cut -d: -f1 || true)
live_guard_line=$(grep -nF 'if grep -q "rd.live.image" /proc/cmdline' \
    "$TMPDIR/noid-firefox-playground-init.sh" | cut -d: -f1 || true)
if [ -n "$arg_gate_line" ] && [ -n "$live_guard_line" ] \
   && [ "$arg_gate_line" -lt "$live_guard_line" ]; then
    _pass "initializer rejects arguments before inspecting host or profile state"
else
    _fail "initializer argument gate is not the first runtime boundary"
fi
set +e
bash "$TMPDIR/noid-firefox-playground-init.sh" --unexpected \
    > "$TMPDIR/init-unknown.out" 2>&1
unknown_arg_rc=$?
bash "$TMPDIR/noid-firefox-playground-init.sh" --one --two \
    > "$TMPDIR/init-surplus.out" 2>&1
surplus_arg_rc=$?
set -e
assert_eq 2 "$unknown_arg_rc" \
    "initializer rejects one unknown argument with usage status"
assert_eq 2 "$surplus_arg_rc" \
    "initializer rejects surplus arguments with usage status"
assert_grep_fixed 'Usage: noid-firefox-playground-init.sh' \
    "$TMPDIR/init-unknown.out" \
    "unknown initializer argument produces a bounded usage diagnostic"
assert_grep_fixed 'Usage: noid-firefox-playground-init.sh' \
    "$TMPDIR/init-surplus.out" \
    "surplus initializer arguments produce a bounded usage diagnostic"
assert_grep_fixed 'FIREFOX_LAUNCHER="/usr/local/bin/firefox"' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "init script authenticates the NoID Privacy-owned Firefox launcher"
assert_grep_fixed 'trap cleanup_playground_init EXIT' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "init script always retires unpublished per-user candidates"
for signal_trap in \
    "trap 'exit 129' HUP" \
    "trap 'exit 130' INT" \
    "trap 'exit 143' TERM"; do
    assert_grep_fixed "$signal_trap" \
        "$TMPDIR/noid-firefox-playground-init.sh" \
        "init script maps signals through its cleanup boundary"
done
assert_grep_fixed "trap '' HUP INT TERM" \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "per-user cleanup cannot be recursively interrupted"
for staged_candidate in \
    '"${XULSTORE_TMP:-}"' \
    '"${NOID_BM_TMP:-}"' \
    '"${MARKER_TMP:-}"'; do
    assert_grep_fixed "$staged_candidate" \
        "$TMPDIR/noid-firefox-playground-init.sh" \
        "per-user cleanup covers staged candidate: $staged_candidate"
done

for marker in 'firefox-playground-init.done' \
              'user-playground-overrides.js' \
              'profiles.ini' \
              'ensure_profile "$PROFILE_NAME"' \
              'profile_dir_for "$PROFILE_NAME"' \
              'apply_userjs "$PROFILE_NAME"' \
              'patch_ubo_pb_permission "$PROFILE_NAME"' \
              'MARKER=' \
              'firefox_process_active'; do
    assert_grep_fixed "$marker" "$TMPDIR/noid-firefox-playground-init.sh" \
        "init script uses: $marker"
done
assert_grep_fixed 'refusing to mark playground ready' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "missing uBO prevents the ready marker"
assert_grep_fixed 'refusing a private-only profile without uBO permission' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "missing private-window permission prevents the ready marker"
assert_not_grep 'extension-preferences.json patch failed (non-fatal)' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "private-window permission patch is not downgraded to non-fatal"
assert_not_grep '^EXT_PREFS=' "$TMPDIR/noid-firefox-playground-init.sh" \
    "PB permission logic is not duplicated outside the M16 shared helper"
assert_grep_fixed 'user.js missing after successful apply_userjs' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "init verifies user.js before publishing the ready marker"
assert_grep_fixed 'CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME_DIR/.config}"' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "playground profile and marker honor XDG_CONFIG_HOME"
assert_not_grep 'MOZILLA_DIR="$HOME/.config/' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "playground profile root is not hard-coded below HOME"
assert_grep_fixed 'setup_marker_valid()' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "setup sequencing trusts only the exact M16 state shape"
assert_grep_fixed 'lines[2] != f"userjs_sha256={expected_userjs_sha}"' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "M16 marker is bound to the current base user.js hash"
assert_grep_fixed 'lines[3] != f"ubo_sha256={expected_ubo_sha}"' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "M16 marker is bound to the reviewed uBO seed hash"
assert_grep_fixed 'REGISTERED_DEFAULT=$(profile_dir_for default-release' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "marker profile is compared with the registered productive profile"
assert_grep_fixed 'profile_hardening_complete default-release' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "productive profile must satisfy current hardening before M34 mutates state"
assert_grep_fixed 'profile_hardening_complete "$PROFILE_NAME"' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "ready marker never replaces live hardening validation"
assert_grep_fixed 'acquire_firefox_profile_lock' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "playground uses the shared descriptor-backed profile lock"
firefox_active_checks=$(grep -cF 'if firefox_process_active; then' \
    "$TMPDIR/noid-firefox-playground-init.sh" || true)
if [ "$firefox_active_checks" -eq 2 ]; then
    _pass "running-Firefox state is checked before and after profile-lock acquisition"
else
    _fail "expected two running-Firefox checks, found $firefox_active_checks"
fi
assert_not_grep 'pgrep -u .* -fa firefox' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "fragile Firefox command-line substring matching is absent"
for trusted_payload in \
    'trusted_root_file "$BASE_USERJS" 644' \
    'trusted_root_file "$PLAYGROUND_OVERRIDES" 644' \
    'trusted_root_file "$PROFILE_HELPER" 644' \
    'trusted_root_file "$FIREFOX_LAUNCHER" 755' \
    'trusted_root_file "$WELCOME_HELPER" 644'; do
    assert_grep_fixed "$trusted_payload" "$TMPDIR/noid-firefox-playground-init.sh" \
        "initializer authenticates sourced/composed payload: $trusted_payload"
done
assert_grep_fixed '/usr/sbin/matchpathcon -V "$path"' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "initializer authenticates trusted root payload SELinux labels"
assert_not_grep 'LOCKDIR="$MARKER.lock"' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "crash-strandable mkdir marker lock is absent"
assert_grep_fixed 'preserved existing xulstore.json byte-for-byte' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "repair preserves user-owned Firefox window state"
assert_grep_fixed 'preserved existing Firefox bookmark backups' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "repair preserves existing Firefox bookmark backups"
assert_grep_fixed 'seeded xulstore.json failed its metadata postcondition' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "new xulstore seed has an exact postcondition"
assert_grep_fixed 'seeded Firefox bookmark backup failed its metadata postcondition' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "new bookmark seed has an exact postcondition"
assert_grep_fixed 'NOID_FIREFOX_PLAYGROUND_READY_V1' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "playground ready marker is content-bound"
assert_grep_fixed 'cmp -s -- "$MARKER" <(printf' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "playground ready marker requires exact complete content"
assert_grep_fixed 'published invalid ready marker could not be retired' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "post-publication marker retirement failure is visible"
assert_grep_fixed 'MARKER_PUBLICATION_ACTIVE=1' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "published ready marker stays quarantinable through final validation"
assert_grep_fixed 'rm -f -- "$MARKER"' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "failure cleanup retires an unverified published ready marker"
assert_not_grep 'rm -f -- "$MARKER" || true' \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "invalid published marker retirement is never silently suppressed"
marker_publish_line=$(grep -n 'mv -fT -- "$MARKER_TMP" "$MARKER"' \
    "$TMPDIR/noid-firefox-playground-init.sh" | cut -d: -f1 || true)
final_postcondition_line=$(grep -n 'final playground hardening postcondition failed' \
    "$TMPDIR/noid-firefox-playground-init.sh" | cut -d: -f1 || true)
if [ -n "$marker_publish_line" ] && [ -n "$final_postcondition_line" ] && \
   [ "$marker_publish_line" -gt "$final_postcondition_line" ]; then
    _pass "ready marker is atomically published after final postconditions"
else
    _fail "ready marker publication precedes final postconditions"
fi

# Execute the exact per-user cleanup function under termination. A structural
# grep alone would not prove that all unpublished profile candidates disappear
# while the signal exit status remains visible.
m34_init_cleanup_root="$EXEC_FIXTURE_DIR/init-cleanup"
m34_init_cleanup_fixture="$m34_init_cleanup_root/run.sh"
mkdir -p "$m34_init_cleanup_root"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        '_log() { :; }' \
        'XULSTORE_TMP="$1/xulstore.tmp"' \
        'NOID_BM_TMP="$1/bookmark.tmp"' \
        'MARKER_TMP="$1/marker.tmp"' \
        'MARKER_DIR="$1"' \
        'MARKER="$1/published-marker"' \
        'MARKER_PUBLICATION_ACTIVE=1' \
        'touch "$XULSTORE_TMP" "$NOID_BM_TMP" "$MARKER_TMP" "$MARKER"'
    sed -n '/^cleanup_playground_init() {$/,/^}$/p' \
        "$TMPDIR/noid-firefox-playground-init.sh"
    printf '%s\n' 'trap cleanup_playground_init EXIT' \
        "trap 'exit 129' HUP" "trap 'exit 130' INT" "trap 'exit 143' TERM" \
        'kill -TERM "$$"' 'exit 99'
} > "$m34_init_cleanup_fixture"
chmod 0700 "$m34_init_cleanup_fixture"
if bash "$m34_init_cleanup_fixture" "$m34_init_cleanup_root"; then
    m34_init_cleanup_rc=0
else
    m34_init_cleanup_rc=$?
fi
assert_eq 143 "$m34_init_cleanup_rc" \
    "per-user cleanup preserves the SIGTERM-derived failure status"
if [ ! -e "$m34_init_cleanup_root/xulstore.tmp" ] \
   && [ ! -e "$m34_init_cleanup_root/bookmark.tmp" ] \
   && [ ! -e "$m34_init_cleanup_root/marker.tmp" ] \
   && [ ! -e "$m34_init_cleanup_root/published-marker" ]; then
    _pass "per-user SIGTERM cleanup retires every staged and unverified marker"
else
    _fail "per-user SIGTERM cleanup retires every staged and unverified marker"
fi

lock_release_line=$(grep -n 'flock -u "$NOID_FF_PROFILE_LOCK_FD"' \
    "$TMPDIR/noid-firefox-playground-init.sh" | cut -d: -f1 || true)
notification_wait_line=$(grep -n 'noid_wait_fedora_welcome 600 20' \
    "$TMPDIR/noid-firefox-playground-init.sh" | cut -d: -f1 || true)
if [ -n "$lock_release_line" ] && [ -n "$notification_wait_line" ] && \
   [ "$lock_release_line" -lt "$notification_wait_line" ]; then
    _pass "profile lock is released before the bounded notification wait"
else
    _fail "profile lock remains held during the notification wait"
fi

# The system dconf default must be compiled during the build, not merely
# announced after a swallowed failure.
assert_grep_fixed '/usr/bin/dconf update 2>&1 |' "$KS_FILE" \
    "dconf database compile is executed"
assert_grep_fixed '/usr/bin/tee -a /var/log/ks-34-firefox-playground.log' \
    "$KS_FILE" "dconf compiler output is captured in the module log"
assert_not_grep 'dconf update returned non-zero' "$KS_FILE" \
    "dconf compile failure is not converted into success"

# Installer phases must be contiguous so the build log cannot imply that an
# unlogged phase was skipped after a feature removal.
phase_sequence=$(grep -oE '^PHASE="P[0-9]+-[^"]+"' "$KS_FILE" |
    sed -E 's/^PHASE="(P[0-9]+)-.*"$/\1/' | paste -sd' ' - || true)
if [ "$phase_sequence" = "P0 P1 P2 P3 P4 P5 P6 P7 P8 P9 P10" ]; then
    _pass "M34 installer phases are contiguous P0-P10"
else
    _fail "M34 installer phase sequence drifted: $phase_sequence"
fi
assert_not_grep 'Phase 11\|P11-' "$KS_FILE" \
    "M34 has no stale pre-renumbering phase"

# Outer installer file and relabel postconditions are exact.
assert_grep_fixed 'set -euo pipefail' "$KS_FILE" \
    "M34 installer treats unset variables as errors"
assert_grep_fixed 'ensure_root_dir()' "$KS_FILE" \
    "M34 installer validates each managed directory"
assert_grep_fixed 'publish_root_file()' "$KS_FILE" \
    "M34 installer has a checked atomic publisher"
assert_grep_fixed 'verify_owned_regular()' "$KS_FILE" \
    "M34 installer verifies regular-file ownership and link count"
assert_grep_fixed '[ "$(readlink -f -- "$path" 2>/dev/null)" = "$path" ]' \
    "$KS_FILE" "root-file validators reject symlinked path components"
assert_grep_fixed '/usr/sbin/matchpathcon -V "$path"' "$KS_FILE" \
    "root-file validators enforce expected SELinux labels"
assert_grep_fixed 'sync -- "$tmp"' "$KS_FILE" \
    "atomic publisher durably stages payload bytes before rename"
assert_grep_fixed 'sync -- "$parent"' "$KS_FILE" \
    "atomic publisher durably records each directory rename"
assert_grep_fixed 'verify_owned_regular /usr/local/bin/firefox 755' \
    "$KS_FILE" "M34 requires the exact M16-owned Firefox launcher"
assert_grep_fixed 'verify_owned_regular /usr/local/bin/noid-firefox-playground-init.sh 755' \
    "$KS_FILE" "M34 installer verifies exact init-script metadata"
assert_grep_fixed 'verify_owned_regular /etc/xdg/autostart/noid-firefox-playground-init.desktop 644' \
    "$KS_FILE" "M34 installer verifies exact autostart metadata"
assert_not_grep 'restorecon .*|| true' "$KS_FILE" \
    "M34 installer does not suppress relabel failures"
for signal_trap in \
    "trap 'exit 129' HUP" \
    "trap 'exit 130' INT" \
    "trap 'exit 143' TERM"; do
    assert_grep_fixed "$signal_trap" "$KS_FILE" \
        "M34 installer maps signals through failure cleanup"
done
assert_grep_fixed "trap '' HUP INT TERM" "$KS_FILE" \
    "M34 cleanup cannot be recursively interrupted"
for staged_candidate in \
    '"${OVERRIDES_TMP:-}"' \
    '"${DESKTOP_TMP:-}"' \
    '"${DCONF_TMP:-}"' \
    '"${INIT_TMP:-}"' \
    '"${AUTOSTART_TMP:-}"' \
    '"${STAMP_TMP:-}"'; do
    assert_grep_fixed "$staged_candidate" "$KS_FILE" \
        "installer cleanup covers staged candidate: $staged_candidate"
done
assert_not_grep 'eval ' "$KS_FILE" \
    "M34 verification executes argv directly instead of eval"
desktop_validate_line=$(grep -nF '/usr/bin/desktop-file-validate "$DESKTOP_TMP"' "$KS_FILE" |
    cut -d: -f1 || true)
desktop_publish_line=$(grep -nF 'publish_root_file "$DESKTOP_TMP" "$DESKTOP_TARGET" 644' \
    "$KS_FILE" | cut -d: -f1 || true)
if [ -n "$desktop_validate_line" ] && [ -n "$desktop_publish_line" ] &&
   [ "$desktop_validate_line" -lt "$desktop_publish_line" ]; then
    _pass "application desktop entry is validated before publication"
else
    _fail "application desktop entry is published before validation"
fi
autostart_validate_line=$(grep -nF '/usr/bin/desktop-file-validate "$AUTOSTART_TMP"' "$KS_FILE" |
    cut -d: -f1 || true)
autostart_publish_line=$(grep -nF 'publish_root_file "$AUTOSTART_TMP" "$AUTOSTART_TARGET" 644' \
    "$KS_FILE" | cut -d: -f1 || true)
if [ -n "$autostart_validate_line" ] && [ -n "$autostart_publish_line" ] &&
   [ "$autostart_validate_line" -lt "$autostart_publish_line" ]; then
    _pass "autostart desktop entry is validated before publication"
else
    _fail "autostart desktop entry is published before validation"
fi
assert_grep_fixed 'grep -qxF "$expected_favorites"' "$KS_FILE" \
    "installer verifies the exact reviewed dconf default"
for publish_contract in \
    'publish_root_file "$OVERRIDES_TMP" "$OVERRIDES_TARGET" 644' \
    'publish_root_file "$DESKTOP_TMP" "$DESKTOP_TARGET" 644' \
    'publish_root_file "$DCONF_TMP" "$DCONF_TARGET" 644' \
    'publish_root_file "$INIT_TMP" "$INIT_TARGET" 755' \
    'publish_root_file "$AUTOSTART_TMP" "$AUTOSTART_TARGET" 644' \
    'publish_root_file "$STAMP_TMP" "$STAMP" 644'; do
    assert_grep_fixed "$publish_contract" "$KS_FILE" \
        "atomic payload publication: $publish_contract"
done
if direct_write_errors=$(python3 - "$KS_FILE" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
targets = {
    "OVERRIDES_TARGET": "/usr/share/noid-firefox/user-playground-overrides.js",
    "DESKTOP_TARGET": "/usr/share/applications/firefox-playground.desktop",
    "DCONF_TARGET": "/etc/dconf/db/distro.d/16-noid-firefox-playground",
    "INIT_TARGET": "/usr/local/bin/noid-firefox-playground-init.sh",
    "AUTOSTART_TARGET": "/etc/xdg/autostart/noid-firefox-playground-init.desktop",
}
errors = []
for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
    if line.lstrip().startswith("#"):
        continue
    for variable, literal in targets.items():
        token = rf'(?:["\x27]?{re.escape(literal)}["\x27]?|["\x27]?\${variable}["\x27]?)'
        patterns = (
            rf'>>?[ \t]*{token}',
            rf'\b(?:cp|install|tee|truncate)\b[^#\n]*{token}',
            rf'\bsed\b[^#\n]*-[A-Za-z]*i[A-Za-z]*[^#\n]*{token}',
            rf'\bdd\b[^#\n]*\bof={token}',
        )
        if any(re.search(pattern, line) for pattern in patterns):
            errors.append(f"{path.name}:{line_no}: {variable}: {line.strip()}")
if errors:
    print("\n".join(errors))
    raise SystemExit(1)
PY
); then
    _pass "owned M34 targets have no direct symlink-following writer"
else
    _fail "direct symlink-following writer targets an owned M34 path"
    printf '%s\n' "$direct_write_errors" | sed 's/^/      /'
fi

# Script must refuse to run as root.
assert_grep_fixed 'root|""' "$TMPDIR/noid-firefox-playground-init.sh" \
    "init script refuses root user"

# Script must defer any profile mutation while Firefox is active.
assert_grep_fixed "Firefox is running; no profile bytes changed" \
    "$TMPDIR/noid-firefox-playground-init.sh" \
    "init script defers safely while Firefox is active"

# --- XDG autostart structural ---------------------------------------------

assert_grep_fixed "Exec=/usr/local/bin/noid-firefox-playground-init.sh" \
    "$TMPDIR/noid-firefox-playground-init.desktop" \
    "autostart Exec points to init script"
assert_grep_fixed "TryExec=/usr/local/bin/noid-firefox-playground-init.sh" \
    "$TMPDIR/noid-firefox-playground-init.desktop" \
    "autostart is gated on the installed executable"
assert_grep_fixed "NoDisplay=true" "$TMPDIR/noid-firefox-playground-init.desktop" \
    "autostart NoDisplay=true (invisible in menu)"
assert_grep_fixed "X-GNOME-Autostart-enabled=true" \
    "$TMPDIR/noid-firefox-playground-init.desktop"
assert_cmd_success "Playground autostart entry validates" \
    desktop-file-validate "$TMPDIR/noid-firefox-playground-init.desktop"

# --- Packaged Firefox icon structural --------------------------------------

assert_grep_fixed '/usr/share/icons/hicolor/*/apps/firefox.png' "$KS_FILE" \
    "M34 verifies the packaged Firefox icon"
assert_grep_fixed '/usr/share/icons/hicolor/symbolic/apps/firefox*-symbolic.svg' \
    "$KS_FILE" "optional symbolic Firefox icon is a nullglob-aware pattern"
assert_not_grep '/usr/share/icons/hicolor/symbolic/apps/firefox-symbolic.svg' \
    "$KS_FILE" "missing optional symbolic artwork cannot become a literal path"
assert_grep_fixed 'firefox_icon_count' "$KS_FILE" \
    "M34 gates the packaged Firefox icon postcondition"
assert_grep_fixed 'verify_owned_regular "$firefox_icon" 644' "$KS_FILE" \
    "every resolved Firefox icon has exact root metadata and SELinux label"
assert_grep_fixed '/usr/bin/rpm -qf --qf' \
    "$KS_FILE" \
    "every resolved Firefox icon is resolved through the RPM database"
assert_grep_fixed '[ "$firefox_icon_package" = firefox ]' \
    "$KS_FILE" \
    "every resolved Firefox icon is required to belong to the Firefox RPM"
assert_grep_fixed 'verify_root_directory_boundary "$legacy_playground_icon_parent"' \
    "$KS_FILE" \
    "legacy-icon retirement remains inside a verified root-owned directory"
assert_not_grep '/icons/firefox-playground-' "$KS_FILE" \
    "M34 has no custom Playground icon payload dependency"
assert_grep_fixed 'LEGACY_PLAYGROUND_ICON_SIZES="48 64 128 256"' "$KS_FILE" \
    "M34 scopes legacy cleanup to the four formerly owned sizes"
assert_grep_fixed 'rm -f -- "$legacy_playground_icon"' "$KS_FILE" \
    "M34 retires exact legacy custom-icon paths"
assert_grep_fixed 'Unexpected non-regular legacy icon object' "$KS_FILE" \
    "M34 refuses to delete an unexpected object type"
assert_grep_fixed 'legacy custom Playground icon aliases absent' "$KS_FILE" \
    "M34 verifies post-upgrade absence"
assert_not_grep_extended \
    'install[^#]*firefox-playground[.]png|ln[^#]*firefox-playground[.]png' \
    "$KS_FILE" "M34 never installs or links a duplicate Firefox icon"
if grep -qE '^[^#]*\bmagick\b' "$KS_FILE" || grep -qE '^[^#]*\bconvert\b.*-annotate' "$KS_FILE"; then
    _fail "Module 34 re-introduces unnecessary runtime ImageMagick"
else
    _pass "Module 34 has no runtime ImageMagick invocation"
fi
if grep -qE '^[^#]*LiberationSans-Bold\.ttf' "$KS_FILE"; then
    _fail "Module 34 references an unnecessary runtime font path"
else
    _pass "Module 34 has no runtime font dependency"
fi
assert_not_grep 'gtk-update-icon-cache' "$KS_FILE" \
    "M34 does not rebuild the icon cache when it installs no icon"
assert_grep_fixed 'phase9_firefox_icon_count=0' "$KS_FILE" \
    "Phase 9 starts a fresh packaged-icon filesystem scan"
assert_grep_fixed 'packaged Firefox icon still present' "$KS_FILE" \
    "Phase 9 reports the re-evaluated icon postcondition"
assert_not_grep 'test "$firefox_icon_count" -ge 1' "$KS_FILE" \
    "Phase 9 does not reuse Phase 3's guaranteed-success counter"
assert_grep_fixed 'die "update-desktop-database failed — MIME cache is incomplete"' \
    "$KS_FILE" \
    "desktop MIME-cache failure aborts the incomplete image build"
assert_not_grep '\[WARN\].*update-desktop-database' "$KS_FILE" \
    "desktop MIME-cache failure is not downgraded to a warning"

# Execute the exact production Phase 9 block against the extracted payloads.
# This proves both its checks and its dynamic cardinality; the health-stamp
# fixture below must not inject a guessed or historical number.
m34_verify_root="$EXEC_FIXTURE_DIR/runtime-verify"
m34_verify_fixture="$m34_verify_root/run.sh"
mkdir -p "$m34_verify_root/icons/64x64/apps"
touch "$m34_verify_root/icons/64x64/apps/firefox.png"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'PHASE=test' \
        'log() { printf "%s\n" "$*" >&2; }' \
        'die() { log "$*"; exit 1; }' \
        'verify_owned_regular() { return 0; }' \
        'LEGACY_PLAYGROUND_ICON_SIZES="48 64 128 256"'
    sed -n \
        '/^# Phase 9 — Verification$/,/^# Phase 10 — Health stamp$/p' \
        "$KS_FILE" |
        sed '$d' |
        sed \
            -e "s|/etc/dconf/db/distro.d/locks/16-noid-firefox-playground|$m34_verify_root/dconf.lock|g" \
            -e "s|/usr/share/noid-firefox/user-playground-overrides.js|$TMPDIR/user-playground-overrides.js|g" \
            -e "s|/usr/share/applications/firefox-playground.desktop|$TMPDIR/firefox-playground.desktop|g" \
            -e "s|/etc/dconf/db/distro.d/16-noid-firefox-playground|$TMPDIR/16-noid-firefox-playground|g" \
            -e "s|/usr/local/bin/noid-firefox-playground-init.sh|$TMPDIR/noid-firefox-playground-init.sh|g" \
            -e "s|/etc/xdg/autostart/noid-firefox-playground-init.desktop|$TMPDIR/noid-firefox-playground-init.desktop|g" \
            -e "s|Exec=$TMPDIR/noid-firefox-playground-init.sh|Exec=/usr/local/bin/noid-firefox-playground-init.sh|g" \
            -e "s|TryExec=$TMPDIR/noid-firefox-playground-init.sh|TryExec=/usr/local/bin/noid-firefox-playground-init.sh|g" \
            -e "s|/usr/share/icons/hicolor|$m34_verify_root/icons|g"
    printf '%s\n' 'printf "%s:%s\n" "$checks" "$fails"'
} > "$m34_verify_fixture"
chmod 0700 "$m34_verify_fixture"
m34_runtime_verification=$("$m34_verify_fixture")
m34_expected_runtime_checks=35
assert_eq "$m34_expected_runtime_checks:0" "$m34_runtime_verification" \
    "exact M34 Phase 9 executes all 35 current checks successfully"

# --- Health stamp pattern --------------------------------------------------

assert_grep_fixed "stamp-34-firefox-playground.ok" "$KS_FILE" "stamp file path"
assert_grep_fixed "module=34"                     "$KS_FILE" "stamp module=34"
assert_grep_fixed "status=ok"                      "$KS_FILE" "stamp status=ok"
assert_grep_fixed "icon_name=firefox"               "$KS_FILE" "stamp records icon lookup name"
assert_grep_fixed 'verify_m34_health_stamp()' "$KS_FILE" \
    "M34 validates staged and final health evidence with one exact schema"
assert_grep_fixed 'STAMP_PUBLICATION_ACTIVE=1' "$KS_FILE" \
    "published M34 evidence remains removable through every final gate"
assert_grep_fixed '/usr/sbin/matchpathcon -V "$STAMP_TMP"' "$KS_FILE" \
    "M34 verifies the staged candidate SELinux context"
assert_grep_fixed '/usr/sbin/matchpathcon -V "$STAMP"' "$KS_FILE" \
    "M34 verifies the final stamp SELinux context"

# Historical success must be retired before the first owned payload mutation;
# replacement evidence remains after the complete verification guard.
guard_line=$(grep -n 'fails.*-gt 0' "$KS_FILE" | head -1 | cut -d: -f1 || true)
invalidate_line=$(grep -nF \
    '# M34_HEALTH_INVALIDATION_BEGIN' "$KS_FILE" | cut -d: -f1 || true)
first_payload_line=$(grep -nF \
    'ensure_root_dir /usr/share/noid-firefox 755' \
    "$KS_FILE" | cut -d: -f1 || true)
publish_line=$(grep -nF \
    '# M34_HEALTH_PUBLICATION_BEGIN' "$KS_FILE" | cut -d: -f1 || true)
complete_line=$(grep -nF \
    'log "=== Module 34 Firefox Playground complete ==="' \
    "$KS_FILE" | cut -d: -f1 || true)
if [ -n "$guard_line" ] && [ -n "$invalidate_line" ] \
   && [ -n "$first_payload_line" ] && [ -n "$publish_line" ] \
   && [ -n "$complete_line" ] \
   && [ "$invalidate_line" -lt "$first_payload_line" ] \
   && [ "$guard_line" -lt "$publish_line" ] \
   && [ "$publish_line" -lt "$complete_line" ]; then
    _pass "M34 retires old health before mutation and publishes after verification"
else
    _fail "M34 health-stamp ordering is not failure-atomic"
fi

# Execute the exact production health-boundary blocks under every material
# publication failure.
m34_stamp_root="$EXEC_FIXTURE_DIR/health-stamp"
m34_stamp_state="$m34_stamp_root/state"
m34_stamp_bin="$m34_stamp_root/bin"
m34_stamp_invalidate="$m34_stamp_root/invalidate.sh"
m34_stamp_publish="$m34_stamp_root/publish.sh"
m34_stamp_uid=$(id -u)
m34_stamp_gid=$(id -g)
mkdir -p "$m34_stamp_bin"

cat > "$m34_stamp_bin/restorecon" <<'M34_STAMP_RESTORECON_EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${!#}"
case "${FAKE_RESTORECON_FAIL:-}" in
    all) exit 1 ;;
    final)
        case "$target" in
            */stamp-34-firefox-playground.ok) exit 1 ;;
        esac
        ;;
esac
exit 0
M34_STAMP_RESTORECON_EOF
cat > "$m34_stamp_bin/matchpathcon" <<'M34_STAMP_MATCHPATHCON_EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${!#}"
case "${FAKE_MATCHPATHCON_FAIL:-}" in
    all) exit 1 ;;
    final)
        case "$target" in
            */stamp-34-firefox-playground.ok) exit 1 ;;
        esac
        ;;
esac
case "${FAKE_MATCHPATHCON_TERM:-}" in
    final)
        case "$target" in
            */stamp-34-firefox-playground.ok)
                kill -TERM "$PPID"
                sleep 1
                ;;
        esac
        ;;
esac
exit 0
M34_STAMP_MATCHPATHCON_EOF
cat > "$m34_stamp_bin/mv" <<'M34_STAMP_MV_EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${FAKE_MV_FAIL:-0}" -eq 1 ]; then
    exit 1
fi
exec /usr/bin/mv "$@"
M34_STAMP_MV_EOF
chmod 0700 "$m34_stamp_bin/restorecon" \
    "$m34_stamp_bin/matchpathcon" "$m34_stamp_bin/mv"

{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'PHASE=test' 'log() { :; }' 'die() { exit 1; }' \
        "STAMP_DIR=$m34_stamp_state" \
        'STAMP="$STAMP_DIR/stamp-34-firefox-playground.ok"'
    sed -n \
        '/^# M34_HEALTH_INVALIDATION_BEGIN$/,/^# M34_HEALTH_INVALIDATION_END$/p' \
        "$KS_FILE" |
        sed -e "s|-o root -g root|-o $m34_stamp_uid -g $m34_stamp_gid|" \
            -e "s|0:0:755|$m34_stamp_uid:$m34_stamp_gid:755|" \
            -e "s|/usr/sbin/restorecon|$m34_stamp_bin/restorecon|g" \
            -e "s|/usr/sbin/matchpathcon|$m34_stamp_bin/matchpathcon|g"
} > "$m34_stamp_invalidate"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'PHASE=test' 'log() { :; }' 'die() { exit 1; }' \
        "STAMP_DIR=$m34_stamp_state" \
        'STAMP="$STAMP_DIR/stamp-34-firefox-playground.ok"' \
        'STAMP_TMP=' 'STAMP_PUBLICATION_ACTIVE=0' \
        "checks=$m34_expected_runtime_checks" 'fails=0'
    sed -n '/^cleanup_m34_health_stamp() {$/,/^}$/p' "$KS_FILE"
    printf '%s\n' 'trap cleanup_m34_health_stamp EXIT' \
        "trap 'exit 129' HUP" "trap 'exit 130' INT" "trap 'exit 143' TERM"
    awk '
        /^publish_root_file\(\) \{$/ { capture = 1 }
        capture { print }
        capture && /^\}$/ { exit }
    ' "$KS_FILE" |
        sed -e "s|chown root:root|chown $m34_stamp_uid:$m34_stamp_gid|g" \
            -e "s|0:0:|$m34_stamp_uid:$m34_stamp_gid:|g" \
            -e "s|/usr/sbin/restorecon|$m34_stamp_bin/restorecon|g" \
            -e "s|/usr/sbin/matchpathcon|$m34_stamp_bin/matchpathcon|g"
    sed -n \
        '/^# M34_HEALTH_PUBLICATION_BEGIN$/,/^# M34_HEALTH_PUBLICATION_END$/p' \
        "$KS_FILE" |
        sed -e "s|chown root:root|chown $m34_stamp_uid:$m34_stamp_gid|g" \
            -e "s|0:0:|$m34_stamp_uid:$m34_stamp_gid:|g" \
            -e "s|/usr/sbin/restorecon|$m34_stamp_bin/restorecon|g" \
            -e "s|/usr/sbin/matchpathcon|$m34_stamp_bin/matchpathcon|g"
} > "$m34_stamp_publish"
chmod 0700 "$m34_stamp_invalidate" "$m34_stamp_publish"

mkdir -m 0755 "$m34_stamp_state"
printf '%s\n' 'module=34' 'name=firefox-playground' 'status=ok' \
    > "$m34_stamp_state/stamp-34-firefox-playground.ok"
assert_cmd_success "M34 rerun invalidates its prior build-success stamp" \
    env PATH="$m34_stamp_bin:$PATH" bash "$m34_stamp_invalidate"
if [ ! -e "$m34_stamp_state/stamp-34-firefox-playground.ok" ]; then
    _pass "M34 old success evidence is absent before payload publication"
else
    _fail "M34 old success evidence is absent before payload publication"
fi

chmod 0777 "$m34_stamp_state"
printf '%s\n' 'must-survive' \
    > "$m34_stamp_state/stamp-34-firefox-playground.ok"
assert_cmd_failure "M34 rejects shared state-directory metadata drift" \
    env PATH="$m34_stamp_bin:$PATH" bash "$m34_stamp_invalidate"
assert_eq "$m34_stamp_uid:$m34_stamp_gid:777" \
    "$(stat -c '%u:%g:%a' "$m34_stamp_state")" \
    "M34 does not normalize drifted shared-directory metadata"
assert_grep_fixed 'must-survive' \
    "$m34_stamp_state/stamp-34-firefox-playground.ok" \
    "M34 does not traverse a drifted shared state boundary"
rm "$m34_stamp_state/stamp-34-firefox-playground.ok"
chmod 0755 "$m34_stamp_state"

assert_cmd_failure "M34 rejects a health-stamp candidate label failure" \
    env PATH="$m34_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=all \
        bash "$m34_stamp_publish"
if [ ! -e "$m34_stamp_state/stamp-34-firefox-playground.ok" ] \
   && [ -z "$(find "$m34_stamp_state" -maxdepth 1 \
        -name '.stamp-34-firefox-playground.ok.*' -print -quit)" ]; then
    _pass "M34 candidate-label failure leaves no plausible health evidence"
else
    _fail "M34 candidate-label failure leaves no plausible health evidence"
fi

assert_cmd_failure "M34 retires a stamp after final-label failure" \
    env PATH="$m34_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=final \
        bash "$m34_stamp_publish"
if [ ! -e "$m34_stamp_state/stamp-34-firefox-playground.ok" ]; then
    _pass "M34 final-label failure removes the published success stamp"
else
    _fail "M34 final-label failure removes the published success stamp"
fi

assert_cmd_failure "M34 quarantines a published stamp on SIGTERM before final verification" \
    env PATH="$m34_stamp_bin:$PATH" FAKE_MATCHPATHCON_TERM=final \
        bash "$m34_stamp_publish"
if [ ! -e "$m34_stamp_state/stamp-34-firefox-playground.ok" ] \
   && [ -z "$(find "$m34_stamp_state" -maxdepth 1 \
        -name '.stamp-34-firefox-playground.ok.*' -print -quit)" ]; then
    _pass "M34 SIGTERM window leaves no published or staged success evidence"
else
    _fail "M34 SIGTERM window leaves no published or staged success evidence"
fi

assert_cmd_failure "M34 rejects an atomic health-stamp rename failure" \
    env PATH="$m34_stamp_bin:$PATH" FAKE_MV_FAIL=1 \
        bash "$m34_stamp_publish"
if [ ! -e "$m34_stamp_state/stamp-34-firefox-playground.ok" ] \
   && [ -z "$(find "$m34_stamp_state" -maxdepth 1 \
        -name '.stamp-34-firefox-playground.ok.*' -print -quit)" ]; then
    _pass "M34 rename failure leaves no stamp or staged candidate"
else
    _fail "M34 rename failure leaves no stamp or staged candidate"
fi

assert_cmd_success "M34 publishes exact health evidence after all gates" \
    env PATH="$m34_stamp_bin:$PATH" bash "$m34_stamp_publish"
assert_grep_fixed 'module=34' \
    "$m34_stamp_state/stamp-34-firefox-playground.ok"
assert_grep_fixed 'name=firefox-playground' \
    "$m34_stamp_state/stamp-34-firefox-playground.ok"
assert_grep_fixed "checks_passed=$m34_expected_runtime_checks" \
    "$m34_stamp_state/stamp-34-firefox-playground.ok"
assert_grep_fixed "checks_total=$m34_expected_runtime_checks" \
    "$m34_stamp_state/stamp-34-firefox-playground.ok"
assert_grep_fixed 'icon_name=firefox' \
    "$m34_stamp_state/stamp-34-firefox-playground.ok"
assert_eq 11 \
    "$(wc -l < "$m34_stamp_state/stamp-34-firefox-playground.ok")" \
    "M34 published health stamp has the exact eleven-line schema"

# --- Claim hygiene ---------------------------------------------------------

assert_not_grep 'SentinelOne\|Katz Stealer' "$KS_FILE" \
    "unsupported product/report attribution is absent"
assert_grep_fixed 'This is data/session' "$KS_FILE" \
    "header labels the mechanism as data/session separation"
assert_grep_fixed 'separation, not an OS sandbox' "$KS_FILE" \
    "header states the exact profile-separation boundary"

# --- M16 dependency ordering check -----------------------------------------
# M34 needs /usr/share/noid-firefox/user.js from M16. Master.ks must
# include M16 before M34 (handled in master.ks include-order test).
# Here we just check the snippet asserts M16's file at runtime:
assert_grep_fixed "/usr/share/noid-firefox/user.js" "$KS_FILE" \
    "snippet references M16 base user.js"
assert_grep_fixed "M16 must run before M34" "$KS_FILE" \
    "runtime dependency documented"
assert_grep_fixed '/usr/bin/rpm' "$KS_FILE" \
    "hard build-time RPM-query dependency is documented"
assert_grep_fixed 'libnotify' "$KS_FILE" \
    "optional notify-send runtime integration is documented"
assert_grep_fixed 'wait-fedora-welcome.sh' "$KS_FILE" \
    "optional M13 welcome-ordering integration is documented"

test_finish
