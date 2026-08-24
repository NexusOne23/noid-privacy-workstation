#!/bin/bash
# 32-avatar-face — M32 Avatar + login-screen logo regression test
#
# Covers: branding expansion. Verifies M32 installs the NoID Privacy logo as the
# user-avatar default (/etc/skel/.face{,.icon}) and system face-gallery entry,
# keeps the removed GDM login-logo override absent, and never locks the
# wallpaper/avatar choices. These are defaults only: users retain full freedom
# to replace both through GNOME Settings.
# Would catch: missing install lines, dconf override pointing to wrong
# logo path, locks file created by mistake (would remove user freedom).

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
M32_FILE="$PROJECT_ROOT/kickstart/snippets/32-branding.ks"
FINALIZE_FILE="$PROJECT_ROOT/kickstart/snippets/99-finalize.ks"
ICON_GENERATOR="$PROJECT_ROOT/branding/icons/regenerate-icons.sh"

test_start "32-avatar-face"

assert_file_exists "$M32_FILE"
assert_file_exists "$FINALIZE_FILE"
assert_file_exists "$ICON_GENERATOR"
assert_cmd_success "bash -n $M32_FILE" bash -n "$M32_FILE"

TMPDIR="$(mktemp -d "${TMPDIR:-/var/tmp}/noid-m32-avatar.XXXXXX")"
trap 'rm -rf "$TMPDIR"' EXIT
extract_heredoc "$M32_FILE" ECOSYSTEM_EOF "$TMPDIR/ecosystem-and-support.md" \
    || _fail "M32 ecosystem documentation extraction"
extract_heredoc "$M32_FILE" BRANDING_DOC_EOF "$TMPDIR/32-branding.md" \
    || _fail "M32 branding documentation extraction"
extract_heredoc "$M32_FILE" LIVE_AVATAR_SCRIPT_EOF "$TMPDIR/live-avatar.sh" \
    || _fail "M32 live-avatar helper extraction"
extract_heredoc "$M32_FILE" AVATAR_SCRIPT_EOF "$TMPDIR/user-avatar.sh" \
    || _fail "M32 installed-user avatar helper extraction"
assert_cmd_success "M32: live-avatar helper parses" \
    bash -n "$TMPDIR/live-avatar.sh"
assert_cmd_success "M32: installed-user avatar helper parses" \
    bash -n "$TMPDIR/user-avatar.sh"
assert_cmd_failure "M32: live-avatar helper rejects an unknown argument" \
    bash "$TMPDIR/live-avatar.sh" --unexpected
assert_cmd_failure "M32: live-avatar helper rejects surplus arguments" \
    bash "$TMPDIR/live-avatar.sh" alpha beta
assert_cmd_failure "M32: installed-user avatar helper rejects an unknown argument" \
    bash "$TMPDIR/user-avatar.sh" --unexpected
assert_cmd_failure "M32: installed-user avatar helper rejects surplus arguments" \
    bash "$TMPDIR/user-avatar.sh" alpha beta
if command -v shellcheck >/dev/null 2>&1; then
    assert_cmd_success "M32: live-avatar helper passes ShellCheck warnings" \
        shellcheck -s bash -S warning "$TMPDIR/live-avatar.sh"
    assert_cmd_success "M32: installed-user avatar helper passes ShellCheck warnings" \
        shellcheck -s bash -S warning "$TMPDIR/user-avatar.sh"
else
    printf '%s\n' '  [SKIP] M32: shellcheck unavailable; avatar helper lint skipped'
fi

# --- M32: user-avatar install to /etc/skel/.face + .face.icon -----------
assert_grep_fixed '/etc/skel/.face.icon' "$M32_FILE" \
    "M32: user-avatar copied to /etc/skel/.face.icon (AccountsService fallback)"
assert_grep_fixed '/etc/skel/.face' "$M32_FILE" \
    "M32: user-avatar copied to /etc/skel/.face (legacy path)"

# --- M32: system face-gallery entry --------------------------------------
assert_grep_fixed '/usr/share/pixmaps/faces/noid-privacy.png' "$M32_FILE" \
    "M32: NoID Privacy logo installed in system face-gallery"
assert_grep_fixed 'app_icon_count=0' "$M32_FILE" \
    "M32: launcher-icon postcondition counts the installed class"
assert_grep_fixed '[ "$app_icon_count" -eq 28 ]' "$M32_FILE" \
    "M32: all 7x4 launcher and compatibility icons are mandatory"
assert_grep_fixed 'STEP 4: 28 launcher icons and all 3 avatar targets installed' \
    "$M32_FILE" \
    "M32: launcher and avatar multi-file classes have an explicit postcondition"
assert_grep_fixed 'mandatory, SHA256-verified' "$ICON_GENERATOR" \
    "M32: icon generator accurately describes the sole verified transport"
assert_grep_fixed 'deliberate compatibility aliases' "$ICON_GENERATOR" \
    "M32: retained wizard/welcome artwork has an explicit compatibility role"
assert_grep_fixed 'All four sizes carry the white outlined' "$M32_FILE" \
    "M32: launcher-icon comment matches the all-size label generator"

# --- login-screen logo dconf REMOVED ------------------
# Login-screen-logo dconf override removed per user choice (Option A) —
# 512x512 NoID Privacy-shield-with-text logo rendered massively oversized on GDM 50
# login-screen, overlapping user-avatar slot. User-avatar via M32 STEP 4 +
# AccountsService Icon= (noid-user-avatar-backfill.service) now
# carries NoID Privacy identity instead. Filename `42-noid-login-logo` still in
# source via `rm -f` defensive cleanup — verify it points to deletion not
# creation.
assert_grep_fixed 'rm -f -- /etc/dconf/db/distro.d/42-noid-login-logo' "$M32_FILE" \
    "M32: login-screen logo dconf RM (login-logo overlay removed)"
assert_not_grep "logo='/usr/share/pixmaps/noid-privacy-logo.png'" "$M32_FILE" \
    "M32: dconf login-screen logo content NOT present (per Fix 3=A)"
assert_not_grep "^logo='" "$M32_FILE" \
    "M32: no dconf login-screen-logo write (per Fix 3=A)"

# --- noid-user-avatar-backfill.service -------------
# Generic AccountsService Icon= backfill for UID>=1000 users.
# Option B uses a pure sentinel-based oneshot at graphical.target.
# VM testing led to a path-unit watcher
# alongside the original service. Reason: with the F44 GIS-driven flow
# (no Anaconda `user --name=`), the service runs at graphical.target BEFORE
# GIS creates the user → 0 humans found → sentinel never written for the
# new user → user gets GIS-letter Icon. The path-unit watches /etc/passwd
# and re-triggers the (still sentinel-idempotent) service when GIS adds
# a user. Sentinel design retained — already-processed users get skipped.
assert_grep_fixed 'noid-user-avatar-backfill.service' "$M32_FILE" \
    "M32: noid-user-avatar-backfill.service deployed (AccountsService Icon= for Anaconda/GIS users)"
assert_grep_fixed 'avatar-set' "$M32_FILE" \
    "M32: sentinel-based one-shot per user"
assert_grep_fixed '/usr/local/sbin/noid-user-avatar-backfill.sh' "$M32_FILE" \
    "M32: backfill script path"
# The path unit discovers the account; the helper retries the maintained
# AccountsService API until the expected UID/name object is observable.
assert_grep_fixed 'noid-user-avatar-backfill.path' "$M32_FILE" \
    "M32: noid-user-avatar-backfill.path watcher (fires backfill when GIS adds user)"
assert_grep_fixed 'PathChanged=/etc/passwd' "$M32_FILE" \
    "M32: path-unit watches /etc/passwd for new-user trigger"
assert_grep_fixed 'systemctl enable noid-user-avatar-backfill.path' "$M32_FILE" \
    "M32: path-unit enabled at install"
assert_grep_fixed 'if [[ ! -f "$sentinel" ]]; then' "$M32_FILE" \
    "M32: default avatar content is provisioned only before the per-user sentinel"
assert_grep_fixed 'publish_root_file "$sentinel" 0600 </dev/null' "$M32_FILE" \
    "M32: avatar provisioning sentinel is atomically sealed mode 0600"
assert_grep_fixed 'publish_root_file "$user_file" 0600' "$M32_FILE" \
    "M32: AccountsService user records are atomically published mode 0600"
assert_grep_fixed 'org.freedesktop.Accounts FindUserById x "$uid"' "$M32_FILE" \
    "M32: passwd-triggered helper resolves the native AccountsService user object"
assert_grep_fixed 'org.freedesktop.Accounts.User SetIconFile s "$icon_target"' \
    "$M32_FILE" \
    "M32: avatar pointer is published through the maintained AccountsService API"
assert_not_grep 'serializes its pointer update' "$M32_FILE" \
    "M32: documentation does not invent a D-Bus serialization guarantee"
assert_not_grep 'remain below that limit' "$M32_FILE" \
    "M32: retry rationale does not overstate the inherited service timeout"
assert_grep_fixed '[ "$provisional" = yes ]' "$M32_FILE" \
    "M32: the first unsealed pass defers strict record normalization"
assert_grep_fixed 'normalize_account_record "$user_file"' "$M32_FILE" \
    "M32: the final pass restores the private AccountsService record mode"
assert_grep_fixed 'avatar_file_safe "$icon_target"' "$M32_FILE" \
    "M32: existing avatar files require safe regular-file metadata"
assert_grep_fixed 'valid_user_name "$user" || continue' "$M32_FILE" \
    "M32: NSS names are constrained before becoming path components"
assert_grep_fixed 'ExecStart=/usr/local/sbin/noid-live-avatar-backfill.sh' \
    "$M32_FILE" \
    "M32: live-image service uses the hardened publication helper"
assert_grep_fixed 'publish_file "$USER_RECORD" root root 0600' "$M32_FILE" \
    "M32: liveuser AccountsService record is atomically normalized to mode 0600"
assert_not_grep 'AccountsService/users/liveuser && chmod 644' "$M32_FILE" \
    "M32: obsolete direct mode-0644 liveuser record write is absent"
assert_not_grep '/locks/40-noid-wallpaper' "$M32_FILE" \
    "M32: wallpaper remains an unlocked default that users can replace"

# Behavioral fixture for the installed-user helper. A user namespace makes
# fixture files appear root-owned without touching the host. This exercises
# initial publication, steady-state user-avatar preservation, and rejection
# of symlink/hardlink destinations.
if command -v bwrap >/dev/null 2>&1 \
    && bwrap --unshare-user --uid 0 --gid 0 \
        --ro-bind /usr /usr --ro-bind /bin /bin \
        --ro-bind /lib /lib --ro-bind /lib64 /lib64 \
        --ro-bind /etc /etc \
        --proc /proc --dev /dev --tmpfs /tmp \
        /usr/bin/true >/dev/null 2>&1; then
    FIXTURE="$TMPDIR/fixture"
    mkdir -p \
        "$FIXTURE/bin" \
        "$FIXTURE/home/alice" \
        "$FIXTURE/usr/share/pixmaps/faces" \
        "$FIXTURE/var/lib/AccountsService" \
        "$FIXTURE/var/lib/noid-privacy"
    chmod 0755 "$FIXTURE/home/alice" "$FIXTURE/var/lib/AccountsService"
    chmod 0755 "$FIXTURE/var/lib/noid-privacy"
    printf '%s\n' 'avatar-v1' \
        >"$FIXTURE/usr/share/pixmaps/faces/noid-privacy.png"
    chmod 0644 "$FIXTURE/usr/share/pixmaps/faces/noid-privacy.png"
    printf '%s\n' \
        '#!/bin/sh' \
        '[ "$1" = passwd ] || exit 2' \
        'printf "%s\n" "alice:x:1000:1000::/fixture/home/alice:/bin/bash"' \
        >"$FIXTURE/bin/getent"
    printf '%s\n' '#!/bin/sh' 'exit 0' >"$FIXTURE/bin/restorecon"
    printf '%s\n' '#!/bin/sh' 'exit 0' >"$FIXTURE/bin/matchpathcon"
    printf '%s\n' '#!/bin/sh' 'exit 0' >"$FIXTURE/bin/logger"
    cat >"$FIXTURE/bin/busctl" <<'BUSCTL_FIXTURE_EOF'
#!/bin/sh
set -eu
[ "$1" = --system ] || exit 2
[ "$2" = --timeout=1s ] || [ "$2" = --timeout=5s ] || exit 2
timeout_arg=$2
shift 2
case "$1" in
    call)
        shift
        if [ "$1" = org.freedesktop.Accounts ] \
            && [ "$2" = /org/freedesktop/Accounts ] \
            && [ "$3" = org.freedesktop.Accounts ] \
            && [ "$4" = FindUserById ] \
            && [ "$5" = x ] && [ "$6" = 1000 ] \
            && [ "$timeout_arg" = --timeout=1s ]; then
            if [ -e /fixture/accounts-create-pending ]; then
                printf '%s\n' \
                    '[User]' \
                    'Icon=/fixture/home/alice/.face' \
                    'SystemAccount=false' \
                    > /fixture/var/lib/AccountsService/users/alice
                chmod 0644 /fixture/var/lib/AccountsService/users/alice
                rm -f /fixture/accounts-create-pending
                printf '%s\n' CREATE_COMPLETE >> /fixture/busctl-order
            fi
            printf '%s\n' 'FIND_USER' >> /fixture/busctl-calls
            printf '%s\n' FIND_USER >> /fixture/busctl-order
            printf '%s\n' 'o "/org/freedesktop/Accounts/User1000"'
            exit 0
        fi
        if [ "$1" = org.freedesktop.Accounts ] \
            && [ "$2" = /org/freedesktop/Accounts/User1000 ] \
            && [ "$3" = org.freedesktop.Accounts.User ] \
            && [ "$4" = SetIconFile ] \
            && [ "$5" = s ] \
            && [ "$6" = /fixture/var/lib/AccountsService/icons/alice ] \
            && [ "$timeout_arg" = --timeout=5s ]; then
            printf '%s\n' SET_ICON >> /fixture/busctl-calls
            [ ! -e /fixture/busctl-fail-set ] || exit 1
            [ ! -e /fixture/accounts-create-pending ] || exit 3
            printf '%s\n' \
                '[User]' \
                'Icon=/fixture/var/lib/AccountsService/icons/alice' \
                'SystemAccount=false' \
                > /fixture/var/lib/AccountsService/users/alice
            chmod 0644 /fixture/var/lib/AccountsService/users/alice
            printf '%s\n' SET_ICON >> /fixture/busctl-order
            exit 0
        fi
        ;;
    get-property)
        shift
        [ "$1" = org.freedesktop.Accounts ] \
            && [ "$2" = /org/freedesktop/Accounts/User1000 ] \
            && [ "$3" = org.freedesktop.Accounts.User ] \
            || exit 2
        case "$4" in
            UserName) printf '%s\n' 's "alice"' ;;
            Uid) printf '%s\n' 't 1000' ;;
            *) exit 2 ;;
        esac
        exit 0
        ;;
esac
exit 2
BUSCTL_FIXTURE_EOF
    chmod 0755 \
        "$FIXTURE/bin/getent" \
        "$FIXTURE/bin/restorecon" \
        "$FIXTURE/bin/matchpathcon" \
        "$FIXTURE/bin/logger" \
        "$FIXTURE/bin/busctl"
    cp "$TMPDIR/user-avatar.sh" "$FIXTURE/user-avatar.sh"
    sed -i \
        -e 's|^SOURCE=.*|SOURCE="/fixture/usr/share/pixmaps/faces/noid-privacy.png"|' \
        -e 's|^SENTINEL_DIR=.*|SENTINEL_DIR="/fixture/var/lib/noid-privacy/avatar-set"|' \
        -e 's|^ICONS_DIR=.*|ICONS_DIR="/fixture/var/lib/AccountsService/icons"|' \
        -e 's|^USERS_DIR=.*|USERS_DIR="/fixture/var/lib/AccountsService/users"|' \
        -e 's|^RESTORECON=.*|RESTORECON=/fixture/bin/restorecon|' \
        -e 's|^MATCHPATHCON=.*|MATCHPATHCON=/fixture/bin/matchpathcon|' \
        -e 's|^BUSCTL=.*|BUSCTL=/fixture/bin/busctl|' \
        -e 's/^[[:space:]]*sleep 10$/    sleep 0/' \
        "$FIXTURE/user-avatar.sh"
    chmod 0755 "$FIXTURE/user-avatar.sh"

    run_avatar_fixture() {
        bwrap --die-with-parent --unshare-all --uid 0 --gid 0 \
            --ro-bind /usr /usr --ro-bind /bin /bin \
            --ro-bind /lib /lib --ro-bind /lib64 /lib64 \
            --ro-bind /etc /etc \
            --proc /proc --dev /dev --tmpfs /tmp \
            --bind "$FIXTURE" /fixture \
            --setenv PATH /fixture/bin:/usr/bin:/bin \
            /fixture/user-avatar.sh
    }

    : >"$FIXTURE/accounts-create-pending"
    if avatar_output=$(run_avatar_fixture 2>&1); then
        _pass "M32: installed-user avatar helper runs in isolated fixture"
    else
        printf '%s\n' "$avatar_output" >&2
        _fail "M32: installed-user avatar helper runs in isolated fixture"
        test_finish
        exit 1
    fi
    assert_cmd_success "M32: fixture avatar content matches canonical source" \
        cmp -s \
            "$FIXTURE/usr/share/pixmaps/faces/noid-privacy.png" \
            "$FIXTURE/var/lib/AccountsService/icons/alice"
    assert_eq "644:1" \
        "$(stat -c '%a:%h' "$FIXTURE/var/lib/AccountsService/icons/alice")" \
        "M32: fixture avatar has safe mode and link count"
    assert_eq "600:1" \
        "$(stat -c '%a:%h' "$FIXTURE/var/lib/AccountsService/users/alice")" \
        "M32: fixture AccountsService record is private and standalone"
    assert_eq "1" \
        "$(grep -c '^Icon=/fixture/var/lib/AccountsService/icons/alice$' \
            "$FIXTURE/var/lib/AccountsService/users/alice")" \
        "M32: fixture record has exactly one canonical Icon field"
    assert_eq "600:1" \
        "$(stat -c '%a:%h' "$FIXTURE/var/lib/noid-privacy/avatar-set/alice")" \
        "M32: fixture sentinel is private and standalone"
    assert_eq $'CREATE_COMPLETE\nFIND_USER\nSET_ICON' \
        "$(cat "$FIXTURE/busctl-order")" \
        "M32: native API runs only after the simulated CreateUser cache publication"

    rm -f "$FIXTURE/var/lib/noid-privacy/avatar-set/alice"
    printf '%s\n' \
        '[User]' \
        'Icon=/fixture/home/alice/.face' \
        'SystemAccount=false' \
        >"$FIXTURE/var/lib/AccountsService/users/alice"
    chmod 0644 "$FIXTURE/var/lib/AccountsService/users/alice"
    : >"$FIXTURE/busctl-fail-set"
    assert_cmd_failure "M32: failed native SetIconFile prevents sentinel sealing" \
        run_avatar_fixture
    assert_cmd_failure "M32: failed native SetIconFile leaves user unsealed" \
        test -e "$FIXTURE/var/lib/noid-privacy/avatar-set/alice"
    rm -f "$FIXTURE/busctl-fail-set"
    assert_cmd_success "M32: native SetIconFile retry converges and seals" \
        run_avatar_fixture

    printf '%s\n' 'user-selected-avatar' \
        >"$FIXTURE/var/lib/AccountsService/icons/alice"
    chmod 0644 "$FIXTURE/var/lib/AccountsService/icons/alice"
    assert_cmd_success "M32: sealed steady-state helper rerun succeeds" \
        run_avatar_fixture
    assert_eq "user-selected-avatar" \
        "$(cat "$FIXTURE/var/lib/AccountsService/icons/alice")" \
        "M32: sealed helper preserves user-selected avatar content"

    printf '%s\n' 'symlink-victim' >"$FIXTURE/symlink-victim"
    rm -f "$FIXTURE/var/lib/AccountsService/users/alice"
    ln -s /fixture/symlink-victim \
        "$FIXTURE/var/lib/AccountsService/users/alice"
    assert_cmd_failure "M32: helper rejects an AccountsService-record symlink" \
        run_avatar_fixture
    assert_eq "symlink-victim" "$(cat "$FIXTURE/symlink-victim")" \
        "M32: AccountsService-record symlink victim remains unchanged"

    rm -f \
        "$FIXTURE/var/lib/AccountsService/users/alice" \
        "$FIXTURE/var/lib/AccountsService/icons/alice"
    printf '%s\n' 'hardlink-victim' >"$FIXTURE/hardlink-victim"
    chmod 0644 "$FIXTURE/hardlink-victim"
    ln "$FIXTURE/hardlink-victim" \
        "$FIXTURE/var/lib/AccountsService/icons/alice"
    assert_cmd_failure "M32: helper rejects a hardlinked avatar" \
        run_avatar_fixture
    assert_eq "hardlink-victim" "$(cat "$FIXTURE/hardlink-victim")" \
        "M32: avatar hardlink peer remains unchanged"

    # alice is the fixture's last (and only) passwd row. Once sealed, removing
    # her avatar is a legitimate user choice and must not leak a false status
    # from the loop into the helper's outer set -e execution.
    rm -f "$FIXTURE/var/lib/AccountsService/icons/alice"
    assert_cmd_success \
        "M32: sealed last passwd user with no avatar is a successful no-op" \
        run_avatar_fixture
    assert_cmd_failure \
        "M32: sealed no-avatar state is preserved instead of reprovisioned" \
        test -e "$FIXTURE/var/lib/AccountsService/icons/alice"
else
    printf '%s\n' \
        '  [SKIP] M32: bwrap behavioral fixture unavailable; structural coverage retained'
fi

# Mutable sibling-product counters belong to the maintained project website,
# not an installed image document that remains unchanged between releases.
assert_grep_fixed 'Mutable counts and release versions stay on the project' \
    "$M32_FILE" \
    "M32: source comment delegates current sibling facts to the website"
assert_not_grep_extended '[0-9]+\+?[[:space:]]+(settings|checks|categories)' \
    "$TMPDIR/ecosystem-and-support.md" \
    "M32: installed ecosystem document carries no mutable product counters"
assert_grep_fixed 'Local privacy/security audit and hardening guidance' \
    "$TMPDIR/ecosystem-and-support.md" \
    "M32: Android sibling uses a stable functional description"
assert_grep_fixed 'Non-remediating-by-default privacy/security audit (single-file pure Bash; applicable host tools are detected at runtime)' \
    "$TMPDIR/ecosystem-and-support.md" \
    "M32: Linux sibling accurately describes its runtime capability boundary"
assert_not_grep 'zero dependencies' "$TMPDIR/ecosystem-and-support.md" \
    "M32: Linux sibling does not overclaim the absence of host-tool dependencies"
assert_not_grep_extended 'Thunderbird.*(donation|appeal)|(donation|appeal).*Thunderbird' \
    "$TMPDIR/ecosystem-and-support.md" \
    "M32: ecosystem document makes no unsupported Thunderbird appeal claim"
assert_grep_fixed 'image (Module 17)' "$TMPDIR/ecosystem-and-support.md" \
    "M32: ecosystem document attributes only the enforced GNOME reminder control"
assert_grep_fixed 'newly discovered user'\''s initial settling window' \
    "$TMPDIR/32-branding.md" \
    "M32: avatar document describes the actual pre-seal provisioning window"
assert_grep_fixed 'Avatar choices made after sealing persist' \
    "$TMPDIR/32-branding.md" \
    "M32: avatar document states the precise persistence boundary"
assert_not_grep 'human users that have not chosen one' "$TMPDIR/32-branding.md" \
    "M32: avatar document does not overclaim pre-seal choice detection"

# --- 99-finalize: verification block ----------------
assert_grep_fixed '/etc/skel/.face.icon' "$FINALIZE_FILE" \
    "99-finalize: asserts /etc/skel/.face.icon present"
assert_grep_fixed '/usr/share/pixmaps/faces/noid-privacy.png' "$FINALIZE_FILE" \
    "99-finalize: asserts face-gallery entry present"
assert_grep_fixed '42-noid-login-logo' "$FINALIZE_FILE" \
    "99-finalize: defensive absence-check for login-logo dconf (per Fix 3=A)"
assert_not_grep "logo='/usr/share/pixmaps/noid-privacy-logo.png'" "$FINALIZE_FILE" \
    "99-finalize: NO content-check for the removed login-logo setting"

test_finish
