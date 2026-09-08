#!/usr/bin/env bash
# Candidate-only two-phase GNOME logout cleanup lifecycle gate.
# Run prepare, log out and back in, then run verify for each pass identity.
set -euo pipefail

TEST_NAME=17-privacy-cleanup-runtime
PASS_ID=${1:-}
PHASE=${2:-}
case "$PASS_ID:$PHASE" in
    live:prepare|live:verify|fresh-install:prepare|fresh-install:verify|reboot:prepare|reboot:verify) ;;
    *)
        echo "Usage: bash $0 {live|fresh-install|reboot} {prepare|verify}" >&2
        exit 2
        ;;
esac

fail() { echo "FAIL  $TEST_NAME [$PASS_ID/$PHASE]: $*" >&2; exit 1; }
[[ $EUID -ne 0 ]] || fail "run as the normal GNOME user, not root"

for required_command in \
    awk chmod find grep journalctl ln loginctl matchpathcon mkdir readlink rm \
    rmdir sed stat sync systemctl; do
    command -v "$required_command" >/dev/null 2>&1 || \
        fail "required command missing: $required_command"
done

grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
[[ ${XDG_CURRENT_DESKTOP:-} == *GNOME* ]] || fail "active desktop is not GNOME"
[[ -n ${DBUS_SESSION_BUS_ADDRESS:-} ]] || fail "session D-Bus address is missing"

# Keep this selector byte-identical to 17-session-lifecycle-runtime.sh. The
# structural suite enforces that shared contract and exercises its rejection
# path with a serial session.
# NOID_USER_SESSION_SELECTOR_BEGIN
session_id=$(loginctl show-user "$UID" -p Display --value 2>/dev/null) || \
    fail "could not identify logind's primary graphical session"
[[ -n $session_id && $session_id != *$'\n'* ]] || \
    fail "logind did not publish one primary graphical session"
session_uid=$(loginctl show-session "$session_id" -p User --value 2>/dev/null) || \
    fail "could not inspect primary session UID: $session_id"
session_class=$(loginctl show-session "$session_id" -p Class --value 2>/dev/null) || \
    fail "could not inspect primary session class: $session_id"
session_type=$(loginctl show-session "$session_id" -p Type --value 2>/dev/null) || \
    fail "could not inspect primary session type: $session_id"
session_remote=$(loginctl show-session "$session_id" -p Remote --value 2>/dev/null) || \
    fail "could not inspect primary session locality: $session_id"
session_active=$(loginctl show-session "$session_id" -p Active --value 2>/dev/null) || \
    fail "could not inspect primary session activity: $session_id"
session_state=$(loginctl show-session "$session_id" -p State --value 2>/dev/null) || \
    fail "could not inspect primary session state: $session_id"
[[ $session_uid == "$UID" ]] || fail "primary graphical session belongs to another UID"
[[ $session_class == user ]] || fail "primary graphical session is not class=user"
[[ $session_type =~ ^(wayland|x11)$ ]] || fail "primary session is not graphical"
[[ $session_remote == no ]] || fail "primary graphical session is remote"
[[ $session_active == yes && $session_state == active ]] || \
    fail "primary graphical session is not active"
# NOID_USER_SESSION_SELECTOR_END

unit=/etc/systemd/user/noid-gnome-shell-privacy-cleanup.service
helper=/usr/local/libexec/noid-gnome-privacy-cleanup
wants=/etc/systemd/user/gnome-session-shutdown.target.wants/noid-gnome-shell-privacy-cleanup.service
[[ -f $unit && ! -L $unit \
   && $(stat -c '%U:%G:%a:%h' "$unit") == root:root:644:1 ]] || \
    fail "cleanup unit metadata invalid"
[[ -x $helper && ! -L $helper \
   && $(stat -c '%U:%G:%a:%h' "$helper") == root:root:755:1 ]] || \
    fail "cleanup helper metadata invalid"
matchpathcon -V "$unit" >/dev/null 2>&1 || fail "cleanup unit SELinux context invalid"
matchpathcon -V "$helper" >/dev/null 2>&1 || fail "cleanup helper SELinux context invalid"
[[ -L $wants && $(readlink "$wants") == "$unit" ]] || \
    fail "GNOME shutdown target link invalid"
[[ $(systemctl --user show noid-gnome-shell-privacy-cleanup.service \
        -p FragmentPath --value) == "$unit" ]] || \
    fail "loaded cleanup unit fragment differs"
grep -qxF 'Before=gnome-session-shutdown.target gnome-session-restart-dbus.service' \
    "$unit" || fail "shutdown ordering edge missing"
grep -qxF 'ExecStart=/usr/local/libexec/noid-gnome-privacy-cleanup' "$unit" || \
    fail "cleanup execution path differs"

[[ ${HOME:-} == /* ]] || fail "HOME must be absolute"
state_home=${XDG_STATE_HOME:-$HOME/.local/state}
data_home=${XDG_DATA_HOME:-$HOME/.local/share}
cache_home=${XDG_CACHE_HOME:-$HOME/.cache}

verify_owned_real_root() {
    local path=$1 label=$2 canonical normalized
    [[ $path == /* && -d $path && ! -L $path ]] || \
        fail "$label is missing, relative, non-directory or symlinked"
    canonical=$(readlink -e -- "$path") || fail "cannot canonicalize $label"
    normalized=$(readlink -m -- "$path") || fail "cannot normalize $label"
    [[ $canonical == "$normalized" ]] || fail "$label contains a symlinked path component"
    [[ $(stat -c '%u' "$canonical") == "$EUID" ]] || \
        fail "$label is not owned by the invoking user"
}

verify_owned_real_root "$state_home" XDG_STATE_HOME
verify_owned_real_root "$data_home" XDG_DATA_HOME
verify_owned_real_root "$cache_home" XDG_CACHE_HOME

state_namespace="$state_home/noid-audit"
state_root="$state_namespace/privacy-cleanup"
state="$state_root/$PASS_ID"
shell_dir="$data_home/gnome-shell"
token="NOID_CLEANUP_${PASS_ID//-/_}_CANARY"
thumb="$cache_home/thumbnails/noid-audit-$PASS_ID/canary"
ff_legacy_root="$HOME/.mozilla"
ff_legacy_profiles="$ff_legacy_root/firefox"
ff_dir="$ff_legacy_profiles/noid-cleanup-audit-$PASS_ID"
tb_root="$HOME/.thunderbird"
tb_dir="$tb_root/noid-cleanup-audit-$PASS_ID"

if [[ $PHASE == prepare ]]; then
    [[ ! -e $state && ! -L $state ]] || fail "pending state already exists: $state"
    for managed_state_dir in "$state_namespace" "$state_root"; do
        [[ ! -L $managed_state_dir ]] || \
            fail "audit state directory is symlinked: $managed_state_dir"
        [[ ! -e $managed_state_dir || -d $managed_state_dir ]] || \
            fail "audit state path is not a directory: $managed_state_dir"
    done
    for parent in "$ff_legacy_root" "$ff_legacy_profiles" "$tb_root"; do
        [[ ! -L $parent ]] || fail "Mozilla canary parent is symlinked: $parent"
        [[ ! -e $parent || -d $parent ]] || \
            fail "Mozilla canary parent is not a directory: $parent"
    done
    for canary_path in "$ff_dir" "$tb_dir" "${thumb%/*}"; do
        [[ ! -e $canary_path && ! -L $canary_path ]] || \
            fail "canary path already exists: $canary_path"
    done
    for managed_parent in "$shell_dir" "$cache_home/thumbnails"; do
        [[ ! -L $managed_parent ]] || \
            fail "cleanup canary parent is symlinked: $managed_parent"
        [[ ! -e $managed_parent || -d $managed_parent ]] || \
            fail "cleanup canary parent is not a directory: $managed_parent"
    done
    for shell_state in \
        "$shell_dir/application_state" \
        "$shell_dir/session-active-history.json"; do
        [[ ! -L $shell_state ]] || fail "GNOME state canary target is symlinked: $shell_state"
        [[ ! -e $shell_state || -f $shell_state ]] || \
            fail "GNOME state canary target is not a regular file: $shell_state"
        if [[ -f $shell_state ]] && grep -qxF "$token" "$shell_state"; then
            fail "GNOME state canary token already exists: $shell_state"
        fi
    done

    state_namespace_preexisting=0
    state_root_preexisting=0
    shell_dir_preexisting=0
    application_state_preexisting=0
    session_history_preexisting=0
    thumbnails_root_preexisting=0
    firefox_root_preexisting=0
    firefox_profiles_preexisting=0
    thunderbird_root_preexisting=0
    [[ -d $state_namespace ]] && state_namespace_preexisting=1
    [[ -d $state_root ]] && state_root_preexisting=1
    [[ -d $shell_dir ]] && shell_dir_preexisting=1
    [[ -f $shell_dir/application_state ]] && application_state_preexisting=1
    [[ -f $shell_dir/session-active-history.json ]] && session_history_preexisting=1
    [[ -d $cache_home/thumbnails ]] && thumbnails_root_preexisting=1
    [[ -d $ff_legacy_root ]] && firefox_root_preexisting=1
    [[ -d $ff_legacy_profiles ]] && firefox_profiles_preexisting=1
    [[ -d $tb_root ]] && thunderbird_root_preexisting=1

    cleanup_prepare_active=1
    # shellcheck disable=SC2317,SC2329 # invoked indirectly by the EXIT trap below
    cleanup_prepare() {
        local rc=$1 path expected
        trap - EXIT HUP INT TERM
        set +e
        if (( cleanup_prepare_active == 0 || rc == 0 )); then
            exit "$rc"
        fi

        cleanup_token_line() {
            local path=$1 existed=$2
            if [[ -f $path && ! -L $path ]]; then
                sed -i -- "/^${token}$/d" "$path"
                if (( existed == 0 )) && [[ ! -s $path ]]; then
                    rm -f -- "$path"
                fi
            fi
        }
        cleanup_token_line \
            "$shell_dir/application_state" "$application_state_preexisting"
        cleanup_token_line \
            "$shell_dir/session-active-history.json" "$session_history_preexisting"

        if [[ -f $thumb && ! -L $thumb ]] && grep -qxF "$token" "$thumb"; then
            rm -f -- "$thumb"
        fi
        for path in "$ff_dir/lock" "$tb_dir/lock"; do
            expected='127.0.0.1:+45170'
            [[ $path == "$tb_dir/lock" ]] && expected='127.0.0.1:+45171'
            if [[ -L $path && $(readlink -- "$path") == "$expected" ]]; then
                rm -f -- "$path"
            fi
        done
        for path in "$ff_dir/.parentlock" "$tb_dir/.parentlock"; do
            expected="$token-ff-parent"
            [[ $path == "$tb_dir/.parentlock" ]] && expected="$token-tb-parent"
            if [[ -f $path && ! -L $path ]] && grep -qxF "$expected" "$path"; then
                rm -f -- "$path"
            fi
        done

        rmdir -- "${thumb%/*}" "$ff_dir" "$tb_dir" 2>/dev/null
        rm -f -- \
            "$state/firefox-legacy-root.preexisting" \
            "$state/firefox-legacy-profiles.preexisting" \
            "$state/thunderbird-root.preexisting" \
            "$state/journal-cursor" \
            "$state/session-context"
        rmdir -- "$state" 2>/dev/null

        (( thumbnails_root_preexisting == 1 )) || rmdir -- "$cache_home/thumbnails" 2>/dev/null
        (( shell_dir_preexisting == 1 )) || rmdir -- "$shell_dir" 2>/dev/null
        (( firefox_profiles_preexisting == 1 )) || rmdir -- "$ff_legacy_profiles" 2>/dev/null
        (( firefox_root_preexisting == 1 )) || rmdir -- "$ff_legacy_root" 2>/dev/null
        (( thunderbird_root_preexisting == 1 )) || rmdir -- "$tb_root" 2>/dev/null
        (( state_root_preexisting == 1 )) || rmdir -- "$state_root" 2>/dev/null
        (( state_namespace_preexisting == 1 )) || rmdir -- "$state_namespace" 2>/dev/null
        exit "$rc"
    }
    trap 'cleanup_prepare "$?"' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    mkdir -p "$state"
    chmod 0700 "$state_namespace" "$state_root" "$state"
    for managed_state_dir in "$state_namespace" "$state_root" "$state"; do
        verify_owned_real_root "$managed_state_dir" "audit state directory"
        [[ $(stat -c '%u:%a' "$managed_state_dir") == "$EUID:700" ]] || \
            fail "audit state directory metadata differs: $managed_state_dir"
    done
    state_files=()
    if [[ -d $ff_legacy_root ]]; then
        printf '%s\n' preexisting > "$state/firefox-legacy-root.preexisting"
        state_files+=("$state/firefox-legacy-root.preexisting")
    fi
    if [[ -d $ff_legacy_profiles ]]; then
        printf '%s\n' preexisting > "$state/firefox-legacy-profiles.preexisting"
        state_files+=("$state/firefox-legacy-profiles.preexisting")
    fi
    if [[ -d $tb_root ]]; then
        printf '%s\n' preexisting > "$state/thunderbird-root.preexisting"
        state_files+=("$state/thunderbird-root.preexisting")
    fi
    mkdir -p "$shell_dir" "${thumb%/*}" "$ff_dir" "$tb_dir"
    printf '%s\n' "$token" >> "$shell_dir/application_state"
    printf '%s\n' "$token" >> "$shell_dir/session-active-history.json"
    printf '%s\n' "$token" > "$thumb"
    ln -s '127.0.0.1:+45170' "$ff_dir/lock"
    printf '%s\n' "$token-ff-parent" > "$ff_dir/.parentlock"
    ln -s '127.0.0.1:+45171' "$tb_dir/lock"
    printf '%s\n' "$token-tb-parent" > "$tb_dir/.parentlock"
    cursor=$(journalctl --user -n 0 --show-cursor --no-pager -o cat 2>/dev/null | \
        awk '$1 == "--" && $2 == "cursor:" && NF == 3 {print $3; found++}
             END {exit found != 1}') || fail "cannot capture one user-journal cursor"
    [[ -n $cursor && $cursor != *[[:space:]]* ]] || \
        fail "captured user-journal cursor is malformed"
    printf '%s\n' "$cursor" > "$state/journal-cursor"
    state_files+=("$state/journal-cursor")
    boot_id=$(< /proc/sys/kernel/random/boot_id)
    printf 'boot=%s\nsession=%s\n' "$boot_id" "$session_id" > "$state/session-context"
    state_files+=("$state/session-context")
    chmod 0600 "${state_files[@]}"
    sync -- "${state_files[@]}" "$shell_dir/application_state" \
        "$shell_dir/session-active-history.json" "$thumb" \
        "$ff_dir/.parentlock" "$tb_dir/.parentlock"
    sync -- "$state"
    cleanup_prepare_active=0
    trap - EXIT HUP INT TERM
    echo "PASS  $TEST_NAME [$PASS_ID/prepare]: canaries durable; log out of GNOME, log back in, then run verify"
    exit 0
fi

[[ -d $state && ! -L $state ]] || fail "prepare state missing"
for managed_state_dir in "$state_namespace" "$state_root" "$state"; do
    verify_owned_real_root "$managed_state_dir" "audit state directory"
    [[ $(stat -c '%u:%a' "$managed_state_dir") == "$EUID:700" ]] || \
        fail "audit state directory metadata differs: $managed_state_dir"
done
cursor_file="$state/journal-cursor"
[[ -f $cursor_file && ! -L $cursor_file \
   && $(stat -c '%u:%a:%h' "$cursor_file") == "$EUID:600:1" ]] || \
    fail "prepare journal cursor metadata differs"
cursor=$(<"$cursor_file")
[[ -n $cursor && $cursor != *[[:space:]]* ]] || fail "prepare journal cursor is malformed"
session_context="$state/session-context"
[[ -f $session_context && ! -L $session_context \
   && $(stat -c '%u:%a:%h' "$session_context") == "$EUID:600:1" ]] || \
    fail "prepare session context metadata differs"
mapfile -t prepared_context < "$session_context"
[[ ${#prepared_context[@]} -eq 2 \
   && ${prepared_context[0]} == boot=* \
   && ${prepared_context[1]} == session=* ]] || \
    fail "prepare session context schema differs"
prepared_boot=${prepared_context[0]#boot=}
prepared_session=${prepared_context[1]#session=}
current_boot=$(< /proc/sys/kernel/random/boot_id)
[[ -n $prepared_boot && $prepared_boot == "$current_boot" ]] || \
    fail "verify did not run in the prepare boot"
[[ -n $prepared_session && $prepared_session != "$session_id" ]] || \
    fail "verify did not observe a new graphical session identity"
if grep -qF "$token" "$shell_dir/application_state" 2>/dev/null; then
    fail "application_state retained the pre-logout canary"
fi
if grep -qF "$token" "$shell_dir/session-active-history.json" 2>/dev/null; then
    fail "session-active-history retained the pre-logout canary"
fi
[[ ! -e $thumb && ! -L $thumb ]] || fail "thumbnail canary survived logout"
cleanup_journal=$(journalctl --user -u noid-gnome-shell-privacy-cleanup.service \
    --after-cursor="$cursor" --no-pager -o cat 2>/dev/null) || \
    fail "cannot read the cursor-bracketed cleanup journal"
grep -qF 'noid-gnome-privacy-cleanup: OK:' <<<"$cleanup_journal" || \
    fail "successful ordered cleanup is absent from the user journal"

remove_exact_profile_canary() {
    local directory=$1 expected_lock=$2 expected_parent=$3 label=$4 unexpected
    [[ -d $directory && ! -L $directory ]] || fail "$label canary directory is unsafe"
    [[ $(readlink "$directory/lock" 2>/dev/null) == "$expected_lock" ]] || \
        fail "$label profile lock was removed or changed"
    [[ -f $directory/.parentlock && ! -L $directory/.parentlock \
       && $(stat -c '%u:%h' "$directory/.parentlock") == "$EUID:1" ]] || \
        fail "$label parent lock metadata differs"
    grep -qxF "$expected_parent" "$directory/.parentlock" || \
        fail "$label parent lock was removed or changed"
    unexpected=$(find -P "$directory" -mindepth 1 -maxdepth 1 \
        ! -name lock ! -name .parentlock -print -quit)
    [[ -z $unexpected ]] || fail "$label canary directory gained an unexpected entry"
    rm -f -- "$directory/lock" "$directory/.parentlock"
    rmdir -- "$directory" || fail "cannot remove exact empty $label canary directory"
}

remove_exact_profile_canary \
    "$ff_dir" '127.0.0.1:+45170' "$token-ff-parent" Firefox
remove_exact_profile_canary \
    "$tb_dir" '127.0.0.1:+45171' "$token-tb-parent" Thunderbird
thumb_canary_dir=${thumb%/*}
[[ ! -L $thumb_canary_dir ]] || fail "thumbnail canary directory became a symlink"
if [[ -d $thumb_canary_dir ]]; then
    [[ -z $(find -P "$thumb_canary_dir" -mindepth 1 -maxdepth 1 -print -quit) ]] || \
        fail "thumbnail canary directory gained an unexpected entry"
    rmdir -- "$thumb_canary_dir" || fail "cannot remove exact empty thumbnail canary directory"
elif [[ -e $thumb_canary_dir ]]; then
    fail "thumbnail canary path became a non-directory"
fi

# The gate may be the first process to create these legacy Mozilla parents.
# Restore that pre-test absence after removing the exact canaries. An empty
# ~/.mozilla/firefox is behaviorally significant on Firefox 147+: it can make
# Firefox ignore a valid XDG profile registry. Never remove a pre-existing or
# non-empty directory, and never follow a replacement symlink.
remove_test_created_empty_parent() {
    local path=$1 marker=$2 label=$3
    if [[ -e $marker || -L $marker ]]; then
        [[ -f $marker && ! -L $marker ]] || \
            fail "$label pre-test marker is unsafe"
        grep -qxF preexisting "$marker" || \
            fail "$label pre-test marker is malformed"
        return 0
    fi
    [[ ! -L $path ]] || fail "$label became a symlink"
    [[ ! -e $path || -d $path ]] || fail "$label became a non-directory"
    if [[ -d $path ]] && \
       [[ -z $(find -P "$path" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
        rmdir -- "$path" || fail "cannot remove test-created empty $label"
    fi
}

remove_test_created_empty_parent \
    "$ff_legacy_profiles" "$state/firefox-legacy-profiles.preexisting" \
    "Firefox legacy profile root"
remove_test_created_empty_parent \
    "$ff_legacy_root" "$state/firefox-legacy-root.preexisting" \
    "Firefox legacy root"
remove_test_created_empty_parent \
    "$tb_root" "$state/thunderbird-root.preexisting" \
    "Thunderbird root"

unexpected_state=$(find -P "$state" -mindepth 1 -maxdepth 1 \
    ! -name journal-cursor \
    ! -name session-context \
    ! -name firefox-legacy-root.preexisting \
    ! -name firefox-legacy-profiles.preexisting \
    ! -name thunderbird-root.preexisting \
    -print -quit)
[[ -z $unexpected_state ]] || fail "cleanup state contains an unexpected entry"
for state_file in \
    "$state/journal-cursor" \
    "$state/session-context" \
    "$state/firefox-legacy-root.preexisting" \
    "$state/firefox-legacy-profiles.preexisting" \
    "$state/thunderbird-root.preexisting"; do
    if [[ -e $state_file || -L $state_file ]]; then
        [[ -f $state_file && ! -L $state_file \
           && $(stat -c '%u:%a:%h' "$state_file") == "$EUID:600:1" ]] || \
            fail "cleanup state file is unsafe: $state_file"
        rm -f -- "$state_file"
    fi
done
rmdir -- "$state" || fail "cannot remove exact empty cleanup state"
echo "PASS  $TEST_NAME [$PASS_ID/verify]: logout removed exact GNOME/cache canaries after producers stopped; Mozilla locks remained intact"
