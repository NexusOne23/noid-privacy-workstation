#!/bin/bash
# Behavioral fixtures for M17's transactional per-user first-login helper.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/17-gnome-hardening.ks"
# The hardened image mounts /tmp noexec; behavioral fixtures must execute the
# extracted helper and command mocks from the repository filesystem.
TEST_TMPDIR=$(mktemp -d "$PROJECT_ROOT/.test-firstrun.XXXXXX")
if [ "${NOID_TEST_KEEP_TMP:-0}" = 1 ]; then
    printf 'fixture tmp retained: %s\n' "$TEST_TMPDIR" >&2
else
    trap 'rm -rf "$TEST_TMPDIR"' EXIT
fi

test_start "17-user-firstrun-fixture"

SCRIPT="$TEST_TMPDIR/noid-user-firstrun"
SERVICE="$TEST_TMPDIR/noid-user-firstrun.service"
extract_heredoc "$KS_FILE" FIRSTRUN_SCRIPT_EOF "$SCRIPT" || \
    _fail "extract first-login helper"
extract_heredoc "$KS_FILE" FIRSTRUN_SVC_EOF "$SERVICE" || \
    _fail "extract first-login service"

# Exercise the production helper's hard-coded static-link validation against
# a real, unprivileged fixture tree. Only the extracted scratch copy is
# rewritten; the embedded production owner/path constants remain pinned by
# the structural tests below.
STATIC_SYSTEMD="$TEST_TMPDIR/static-systemd"
STATIC_WANTS_DIR="$STATIC_SYSTEMD/graphical-session.target.wants"
STATIC_WANTS="$STATIC_WANTS_DIR/usbguard-notifier.service"
STATIC_TARGET="$STATIC_SYSTEMD/usbguard-notifier.service"
STATIC_OTHER="$STATIC_SYSTEMD/not-the-notifier.service"
STATIC_OWNER="$(id -u):$(id -g)"
mkdir -p "$STATIC_WANTS_DIR"

restore_static_notifier() {
    rm -f -- "$STATIC_WANTS" "$STATIC_TARGET" "$STATIC_OTHER"
    : > "$STATIC_TARGET"
    chmod 0644 "$STATIC_TARGET"
    ln -s "$STATIC_TARGET" "$STATIC_WANTS"
}

restore_static_notifier
sed -i \
    -e "s#^NOTIFIER_WANTS=.*#NOTIFIER_WANTS=$STATIC_WANTS#" \
    -e "s#^NOTIFIER_TARGET=.*#NOTIFIER_TARGET=$STATIC_TARGET#" \
    -e "s#^STATIC_OWNER=.*#STATIC_OWNER=$STATIC_OWNER#" \
    "$SCRIPT"
chmod 0755 "$SCRIPT"
assert_cmd_success "first-login helper parses" bash -n "$SCRIPT"
assert_cmd_success "first-login helper passes ShellCheck" \
    shellcheck -x -S warning "$SCRIPT"
assert_cmd_success "first-login service verifies" \
    systemd-analyze verify "$SERVICE"
assert_grep_fixed 'PartOf=graphical-session.target' "$SERVICE" \
    "first-login lifecycle is stopped with the graphical session"
assert_grep_fixed 'ConditionEnvironment=XDG_SESSION_CLASS=user' "$SERVICE" \
    "first-login unit is restricted to real user sessions"
assert_grep_fixed 'ExecCondition=/usr/bin/systemctl --user --quiet is-active graphical-session.target' \
    "$SERVICE" "queued retries skip cleanly after graphical logout"

make_fixture() {
    local root="$TEST_TMPDIR/$1"
    local fixture_home="$root/home"
    mkdir -p "$fixture_home/Downloads" "$root/bin" "$root/mock"
    printf 'LANG="de_DE.UTF-8"\n' > "$root/locale.conf"

    cat > "$root/bin/gsettings" <<'GSETTINGS_EOF'
#!/bin/bash
set -u
case "${1:-}" in
    get)
        [ ! -e "$MOCK_STATE/fail-gsettings-get" ] || exit 1
        if [ -f "$MOCK_STATE/region" ]; then
            printf "'%s'\n" "$(<"$MOCK_STATE/region")"
        else
            printf "''\n"
        fi
        ;;
    set)
        [ ! -e "$MOCK_STATE/fail-gsettings-set" ] || exit 1
        printf '%s' "${4:-}" > "$MOCK_STATE/region"
        ;;
    *) exit 2 ;;
esac
GSETTINGS_EOF

    cat > "$root/bin/xdg-user-dir" <<'XDG_USER_DIR_EOF'
#!/bin/bash
set -u
[ "$#" -eq 1 ] && [ "$1" = DOWNLOAD ] || exit 2
if [ -f "$MOCK_STATE/download-dir" ]; then
    printf '%s\n' "$(<"$MOCK_STATE/download-dir")"
else
    printf '%s/Downloads\n' "$HOME"
fi
XDG_USER_DIR_EOF

    cat > "$root/bin/gio" <<'GIO_EOF'
#!/bin/bash
set -u
printf '%s\n' "$*" >> "$MOCK_STATE/gio.log"
case "${1:-}" in
    info)
        [ ! -e "$MOCK_STATE/fail-gio-info" ] || exit 1
        [ "$#" -eq 3 ] || exit 2
        case "${2:-}" in
            --attributes=metadata::nautilus-icon-view-sort-by,metadata::nautilus-icon-view-sort-reversed) ;;
            *) exit 2 ;;
        esac
        [ -d "${3:-}" ] || exit 1
        printf 'display name: Downloads\nattributes:\n'
        if [ -f "$MOCK_STATE/download-sort-by" ]; then
            printf '  metadata::nautilus-icon-view-sort-by: %s\n' \
                "$(<"$MOCK_STATE/download-sort-by")"
        fi
        if [ -f "$MOCK_STATE/download-sort-reversed" ]; then
            printf '  metadata::nautilus-icon-view-sort-reversed: %s\n' \
                "$(<"$MOCK_STATE/download-sort-reversed")"
        fi
        ;;
    set)
        [ "$#" -eq 6 ] && [ "${2:-}" = -t ] \
            && [ "${3:-}" = string ] && [ -d "${4:-}" ] || exit 2
        case "${5:-}" in
            metadata::nautilus-icon-view-sort-by)
                [ ! -e "$MOCK_STATE/fail-gio-set-sort-by" ] || exit 1
                [ "${6:-}" = name ] || exit 2
                printf '%s' "$6" > "$MOCK_STATE/download-sort-by"
                ;;
            metadata::nautilus-icon-view-sort-reversed)
                [ ! -e "$MOCK_STATE/fail-gio-set-sort-reversed" ] || exit 1
                [ "${6:-}" = false ] || exit 2
                printf '%s' "$6" > "$MOCK_STATE/download-sort-reversed"
                ;;
            *) exit 2 ;;
        esac
        ;;
    *) exit 2 ;;
esac
GIO_EOF

    cat > "$root/bin/systemctl" <<'SYSTEMCTL_EOF'
#!/bin/bash
set -u
printf '%s\n' "$*" >> "$MOCK_STATE/systemctl.log"
[ "${1:-}" = "--user" ] || exit 2
action=${2:-}
unit=${3:-}
case "$action" in
    daemon-reload)
        [ ! -e "$MOCK_STATE/fail-daemon-reload" ]
        ;;
    preset)
        [ ! -e "$MOCK_STATE/fail-preset-$unit" ] || exit 1
        if [ -e "$MOCK_STATE/preset-disabled-$unit" ]; then
            rm -f "$MOCK_STATE/enabled-$unit"
        else
            : > "$MOCK_STATE/enabled-$unit"
        fi
        ;;
    start)
        [ ! -e "$MOCK_STATE/fail-start-$unit" ] || exit 1
        : > "$MOCK_STATE/active-$unit"
        ;;
    is-enabled)
        [ "${3:-}" = "--quiet" ] || exit 2
        [ -f "$MOCK_STATE/enabled-${4:-}" ]
        ;;
    is-active)
        [ "${3:-}" = "--quiet" ] || exit 2
        [ -f "$MOCK_STATE/active-${4:-}" ]
        ;;
    *) exit 2 ;;
esac
SYSTEMCTL_EOF

    cat > "$root/bin/sync" <<'SYNC_EOF'
#!/bin/bash
set -u
printf '%s\n' "$*" >> "$MOCK_STATE/sync.log"
if [ -e "$MOCK_STATE/fail-next-sync" ]; then
    rm -f -- "$MOCK_STATE/fail-next-sync"
    exit 1
fi
[ ! -e "$MOCK_STATE/fail-all-sync" ] || exit 1
exit 0
SYNC_EOF
    chmod 0755 "$root/bin/gio" "$root/bin/gsettings" "$root/bin/systemctl" \
        "$root/bin/sync" "$root/bin/xdg-user-dir"
    printf '%s\n' "$root"
}

run_fixture() {
    local root=$1
    env HOME="$root/home" \
        XDG_SESSION_CLASS=user \
        XDG_CONFIG_HOME="$root/home/.config" \
        NOID_FIRSTRUN_LOCALE_CONF="$root/locale.conf" \
        MOCK_STATE="$root/mock" \
        PATH="$root/bin:/usr/bin:/bin" \
        "$SCRIPT"
}

marker_is_exact() {
    local marker=$1 task=$2 expected expected_size
    expected=$(printf 'version=2\nstatus=complete\ntask=%s' "$task")
    expected_size=$((${#expected} + 1))
    [ -f "$marker" ] && [ ! -L "$marker" ] \
        && [ "$(stat -c '%u:%a:%h:%s' "$marker")" = \
            "$(id -u):600:1:$expected_size" ] \
        && [ "$(<"$marker")" = "$expected" ]
}

libvirt_config_is_exact() {
    local root=$1 dir="$1/home/.config/libvirt" conf
    conf=$dir/qemu.conf
    [ -d "$dir" ] && [ ! -L "$dir" ] \
        && [ "$(stat -c '%u:%a' "$dir")" = "$(id -u):700" ] \
        && [ -f "$conf" ] && [ ! -L "$conf" ] \
        && [ "$(stat -c '%u:%a:%h' "$conf")" = "$(id -u):600:1" ] \
        && [ "$(grep -Ec '^[[:space:]]*max_core[[:space:]]*=' "$conf")" -eq 1 ] \
        && [ "$(grep -Ec '^[[:space:]]*max_core[[:space:]]*=[[:space:]]*0[[:space:]]*(#.*)?$' "$conf")" -eq 1 ] \
        && [ "$(grep -Ec '^[[:space:]]*dump_guest_core[[:space:]]*=' "$conf")" -eq 1 ] \
        && [ "$(grep -Ec '^[[:space:]]*dump_guest_core[[:space:]]*=[[:space:]]*0[[:space:]]*(#.*)?$' "$conf")" -eq 1 ]
}

# GNOME Initial Setup can own a graphical target without a real user session.
# The helper must return success before deriving or writing any home state, so
# systemd does not retry forever against the pseudo-user.
pseudo=$(make_fixture pseudo_user)
assert_cmd_success "pseudo-user session exits cleanly" \
    env HOME="$pseudo/home" XDG_SESSION_CLASS=greeter \
        XDG_CONFIG_HOME="$pseudo/home/.config" \
        NOID_FIRSTRUN_LOCALE_CONF="$pseudo/locale.conf" \
        MOCK_STATE="$pseudo/mock" PATH="$pseudo/bin:/usr/bin:/bin" "$SCRIPT"
if [ ! -e "$pseudo/home/.config" ] \
   && [ ! -e "$pseudo/mock/systemctl.log" ]; then
    _pass "pseudo-user session writes no home or user-manager state"
else
    _fail "pseudo-user session mutated home or user-manager state"
fi

# Happy path: an obsolete empty sentinel cannot suppress the v2 transaction.
happy=$(make_fixture happy)
mkdir -p "$happy/home/.config"
: > "$happy/home/.config/noid-user-firstrun.done"
assert_cmd_success "happy path completes all tasks" run_fixture "$happy"
assert_eq de_DE.UTF-8 "$(<"$happy/mock/region")" \
    "empty GNOME region is synchronized from one valid LANG"
for task in region nautilus_download_sort libvirt_qemu_core noid_update_reminder \
        usbguard_notifier complete; do
    assert_cmd_success "exact atomic marker: $task" marker_is_exact \
        "$happy/home/.config/noid-user-firstrun/${task}-v2.done" "$task"
done
assert_cmd_success "fresh session libvirt configuration is exact" \
    libvirt_config_is_exact "$happy"
assert_eq name "$(<"$happy/mock/download-sort-by")" \
    "fresh Downloads metadata selects name sorting"
assert_eq false "$(<"$happy/mock/download-sort-reversed")" \
    "fresh Downloads metadata selects ascending sorting"
if [ ! -e "$happy/home/.config/noid-user-firstrun.done" ]; then
    _pass "legacy empty sentinel is retired only after v2 completion"
else
    _fail "legacy empty sentinel survived v2 completion"
fi
assert_eq 1 "$(grep -c '^--user preset ' "$happy/mock/systemctl.log")" \
    "only the update timer preset is applied"
assert_eq 2 "$(grep -c '^--user start ' "$happy/mock/systemctl.log")" \
    "both units start in the first live session"
assert_eq "$STATIC_TARGET" "$(readlink "$STATIC_WANTS")" \
    "notifier fixture uses the exact absolute static target"
assert_not_grep 'preset-all' "$happy/mock/systemctl.log" \
    "fixture never invokes the open-ended preset-all operation"
assert_not_grep '^--user preset usbguard-notifier.service$' \
    "$happy/mock/systemctl.log" "static notifier never receives a preset"
assert_eq 14 "$(wc -l < "$happy/mock/sync.log")" \
    "six markers plus the libvirt file each fsync bytes and directories"

# A completed transaction is a no-write fast path on later logins.
complete_marker="$happy/home/.config/noid-user-firstrun/complete-v2.done"
complete_inode=$(stat -c %i "$complete_marker")
libvirt_conf="$happy/home/.config/libvirt/qemu.conf"
libvirt_hash=$(sha256sum "$libvirt_conf")
libvirt_inode=$(stat -c %i "$libvirt_conf")
: > "$happy/mock/systemctl.log"
: > "$happy/mock/sync.log"
: > "$happy/mock/gio.log"
assert_cmd_success "completed transaction remains idempotent" run_fixture "$happy"
assert_eq "$complete_inode" "$(stat -c %i "$complete_marker")" \
    "later login preserves the complete-marker inode"
assert_eq 0 "$(wc -l < "$happy/mock/systemctl.log")" \
    "later login repeats no completed unit task"
assert_eq 0 "$(wc -l < "$happy/mock/sync.log")" \
    "later login performs no marker write or durability flush"
assert_eq 0 "$(grep -c '^set ' "$happy/mock/gio.log" || true)" \
    "later login repeats no completed Downloads mutation"
assert_eq "$libvirt_hash" "$(sha256sum "$libvirt_conf")" \
    "later login preserves session libvirt bytes"
assert_eq "$libvirt_inode" "$(stat -c %i "$libvirt_conf")" \
    "later login preserves the session libvirt inode"

# A correct existing user file is authoritative and remains byte/inode exact.
existing_libvirt=$(make_fixture existing_libvirt)
mkdir -p "$existing_libvirt/home/.config/libvirt"
printf '%s\n' '# user documentation' 'max_core = 0' 'dump_guest_core = 0' \
    > "$existing_libvirt/home/.config/libvirt/qemu.conf"
existing_hash=$(sha256sum "$existing_libvirt/home/.config/libvirt/qemu.conf")
existing_inode=$(stat -c %i "$existing_libvirt/home/.config/libvirt/qemu.conf")
assert_cmd_success "valid existing libvirt configuration completes" \
    run_fixture "$existing_libvirt"
assert_cmd_success "valid existing libvirt configuration remains exact" \
    libvirt_config_is_exact "$existing_libvirt"
assert_eq "$existing_hash" \
    "$(sha256sum "$existing_libvirt/home/.config/libvirt/qemu.conf")" \
    "valid existing libvirt bytes remain user-owned"
assert_eq "$existing_inode" \
    "$(stat -c %i "$existing_libvirt/home/.config/libvirt/qemu.conf")" \
    "valid existing libvirt inode is not replaced"

# Missing active keys are appended atomically while unrelated settings and
# commented vendor examples survive unchanged.
partial_libvirt=$(make_fixture partial_libvirt)
mkdir -p "$partial_libvirt/home/.config/libvirt"
printf '%s\n' '# user comment' 'security_driver = "selinux"' \
    'max_core = 0 # retained' '#dump_guest_core = 1' \
    > "$partial_libvirt/home/.config/libvirt/qemu.conf"
partial_prefix=$(head -n 4 \
    "$partial_libvirt/home/.config/libvirt/qemu.conf" | sha256sum)
assert_cmd_success "partial libvirt configuration is completed" \
    run_fixture "$partial_libvirt"
assert_cmd_success "completed partial libvirt configuration is exact" \
    libvirt_config_is_exact "$partial_libvirt"
assert_eq "$partial_prefix" \
    "$(head -n 4 "$partial_libvirt/home/.config/libvirt/qemu.conf" | sha256sum)" \
    "partial completion preserves all existing user lines"

exercise_rejected_libvirt_file() {
    local name=$1 content=$2 root conf before
    root=$(make_fixture "libvirt_reject_$name")
    mkdir -p "$root/home/.config/libvirt"
    printf '%s\n' "$content" > "$root/home/.config/libvirt/qemu.conf"
    conf=$root/home/.config/libvirt/qemu.conf
    before=$(sha256sum "$conf")
    if run_fixture "$root" >/dev/null 2>&1; then
        _fail "hostile libvirt configuration is rejected: $name"
    else
        _pass "hostile libvirt configuration is rejected: $name"
    fi
    assert_eq "$before" "$(sha256sum "$conf")" \
        "rejected $name content remains byte-identical"
    if [ ! -e "$root/home/.config/noid-user-firstrun/libvirt_qemu_core-v2.done" ] \
       && [ ! -e "$root/home/.config/noid-user-firstrun/complete-v2.done" ]; then
        _pass "rejected $name cannot publish libvirt or complete state"
    else
        _fail "rejected $name published false completion"
    fi
}

exercise_rejected_libvirt_file nonzero-max \
    $'max_core = "unlimited"\ndump_guest_core = 0'
exercise_rejected_libvirt_file nonzero-dump \
    $'max_core = 0\ndump_guest_core = 1'
exercise_rejected_libvirt_file duplicate-max \
    $'max_core = 0\nmax_core = 0\ndump_guest_core = 0'

symlink_libvirt=$(make_fixture symlink_libvirt)
mkdir -p "$symlink_libvirt/home/.config/libvirt"
printf '%s\n' do-not-touch > "$symlink_libvirt/target"
ln -s "$symlink_libvirt/target" \
    "$symlink_libvirt/home/.config/libvirt/qemu.conf"
symlink_target_hash=$(sha256sum "$symlink_libvirt/target")
if run_fixture "$symlink_libvirt" >/dev/null 2>&1; then
    _fail "symlinked libvirt qemu.conf is rejected"
else
    _pass "symlinked libvirt qemu.conf is rejected"
fi
assert_eq "$symlink_target_hash" "$(sha256sum "$symlink_libvirt/target")" \
    "rejected libvirt symlink target remains byte-identical"

hardlink_libvirt=$(make_fixture hardlink_libvirt)
mkdir -p "$hardlink_libvirt/home/.config/libvirt"
printf '%s\n' 'max_core = 0' 'dump_guest_core = 0' \
    > "$hardlink_libvirt/shared"
ln "$hardlink_libvirt/shared" \
    "$hardlink_libvirt/home/.config/libvirt/qemu.conf"
if run_fixture "$hardlink_libvirt" >/dev/null 2>&1; then
    _fail "hard-linked libvirt qemu.conf is rejected"
else
    _pass "hard-linked libvirt qemu.conf is rejected"
fi
assert_eq 2 "$(stat -c %h "$hardlink_libvirt/shared")" \
    "rejected libvirt hardlink is not replaced"

oversized_libvirt=$(make_fixture oversized_libvirt)
mkdir -p "$oversized_libvirt/home/.config/libvirt"
truncate -s 1048577 "$oversized_libvirt/home/.config/libvirt/qemu.conf"
if run_fixture "$oversized_libvirt" >/dev/null 2>&1; then
    _fail "oversized libvirt qemu.conf is rejected"
else
    _pass "oversized libvirt qemu.conf is rejected"
fi
assert_eq 1048577 \
    "$(stat -c %s "$oversized_libvirt/home/.config/libvirt/qemu.conf")" \
    "rejected oversized libvirt file is not rewritten"

# Exact content alone is insufficient: mode, link count and final byte remain
# part of the marker trust contract and are repaired atomically.
chmod 0644 "$complete_marker"
assert_cmd_success "wrong-mode complete marker is repaired" run_fixture "$happy"
assert_cmd_success "repaired complete marker is exact" \
    marker_is_exact "$complete_marker" complete
printf '\n' >> "$complete_marker"
assert_cmd_success "extra trailing marker byte is repaired" run_fixture "$happy"
assert_cmd_success "byte-repaired complete marker is exact" \
    marker_is_exact "$complete_marker" complete
complete_hardlink="$happy/complete-marker-hardlink"
ln "$complete_marker" "$complete_hardlink"
assert_cmd_success "hardlinked complete marker is replaced" run_fixture "$happy"
assert_cmd_success "link-repaired complete marker is exact" \
    marker_is_exact "$complete_marker" complete
assert_eq 1 "$(stat -c %h "$complete_hardlink")" \
    "replacing a hardlinked marker does not mutate the other name"

# Global completion cannot remain asserted while a required task is invalid,
# even when the subsequent durability boundary itself reports failure.
stale_complete=$(make_fixture stale_complete)
assert_cmd_success "stale-complete fixture reaches initial completion" \
    run_fixture "$stale_complete"
printf 'corrupt\n' > \
    "$stale_complete/home/.config/noid-user-firstrun/region-v2.done"
: > "$stale_complete/mock/fail-all-sync"
if run_fixture "$stale_complete" >/dev/null 2>&1; then
    _fail "failed stale-complete invalidation returns non-zero"
else
    _pass "failed stale-complete invalidation returns non-zero"
fi
if [ ! -e "$stale_complete/home/.config/noid-user-firstrun/complete-v2.done" ]; then
    _pass "invalid required task leaves no visible global completion"
else
    _fail "invalid required task retained stale global completion"
fi
rm -f -- "$stale_complete/mock/fail-all-sync"
assert_cmd_success "stale-complete retry repairs the transaction" \
    run_fixture "$stale_complete"
assert_cmd_success "stale-complete retry restores exact completion" \
    marker_is_exact \
    "$stale_complete/home/.config/noid-user-firstrun/complete-v2.done" complete

# A pre-existing user region is authoritative and need not parse locale.conf.
owned=$(make_fixture user_owned_region)
printf '%s' 'fr_FR.UTF-8' > "$owned/mock/region"
printf '%s\n' 'LANG="unterminated' > "$owned/locale.conf"
assert_cmd_success "pre-existing user region remains authoritative" run_fixture "$owned"
assert_eq fr_FR.UTF-8 "$(<"$owned/mock/region")" \
    "first-login helper does not overwrite a user region"

# Any complete pre-existing Nautilus sort state is user-owned. The first-login
# default must commit its task without replacing that state.
owned_sort=$(make_fixture user_owned_download_sort)
printf '%s' mtime > "$owned_sort/mock/download-sort-by"
printf '%s' true > "$owned_sort/mock/download-sort-reversed"
assert_cmd_success "pre-existing Downloads sort remains authoritative" \
    run_fixture "$owned_sort"
assert_eq mtime "$(<"$owned_sort/mock/download-sort-by")" \
    "first-login helper preserves a user Downloads sort column"
assert_eq true "$(<"$owned_sort/mock/download-sort-reversed")" \
    "first-login helper preserves a user Downloads sort direction"
assert_eq 0 "$(grep -c '^set ' "$owned_sort/mock/gio.log" || true)" \
    "user-owned Downloads metadata receives no write"

# The native metadata interface exposes one attribute per call. If the helper
# is interrupted after publishing name but before ascending, the exact prefix
# is recovered on retry without replaying independently completed tasks.
interrupted_sort=$(make_fixture interrupted_download_sort)
: > "$interrupted_sort/mock/fail-gio-set-sort-reversed"
if run_fixture "$interrupted_sort" >/dev/null 2>&1; then
    _fail "partial Downloads metadata write returns non-zero"
else
    _pass "partial Downloads metadata write returns non-zero"
fi
assert_eq name "$(<"$interrupted_sort/mock/download-sort-by")" \
    "interrupted Downloads task retains its exact first write"
if [ ! -e "$interrupted_sort/mock/download-sort-reversed" ] \
   && [ ! -e "$interrupted_sort/home/.config/noid-user-firstrun/nautilus_download_sort-v2.done" ] \
   && [ ! -e "$interrupted_sort/home/.config/noid-user-firstrun/complete-v2.done" ]; then
    _pass "partial Downloads state cannot publish task or global completion"
else
    _fail "partial Downloads state published false completion"
fi
rm -f -- "$interrupted_sort/mock/fail-gio-set-sort-reversed"
: > "$interrupted_sort/mock/gio.log"
: > "$interrupted_sort/mock/systemctl.log"
assert_cmd_success "partial Downloads metadata retry completes" \
    run_fixture "$interrupted_sort"
assert_eq false "$(<"$interrupted_sort/mock/download-sort-reversed")" \
    "retry completes ascending Downloads metadata"
assert_eq 0 "$(grep -c 'metadata::nautilus-icon-view-sort-by name$' \
    "$interrupted_sort/mock/gio.log" || true)" \
    "retry does not repeat the completed name-metadata write"
assert_eq 0 "$(wc -l < "$interrupted_sort/mock/systemctl.log")" \
    "Downloads-only retry repeats no completed unit task"

# xdg-user-dirs represents a disabled Downloads directory as HOME. That is not
# a distinct Nautilus Downloads view and must not create metadata on Home.
disabled_download=$(make_fixture disabled_download)
printf '%s' "$disabled_download/home" > "$disabled_download/mock/download-dir"
assert_cmd_success "disabled Downloads mapping completes without metadata" \
    run_fixture "$disabled_download"
if [ ! -e "$disabled_download/mock/download-sort-by" ] \
   && [ ! -e "$disabled_download/mock/download-sort-reversed" ]; then
    _pass "disabled Downloads mapping leaves Home metadata untouched"
else
    _fail "disabled Downloads mapping mutated Home metadata"
fi

# Every hostile representation of the static notifier contract must fail
# closed after retaining unrelated region/update progress. Restoring the exact
# absolute link permits a retry of only the unfinished notifier task.
exercise_hostile_static_link() {
    local name=$1 mutation=$2 root
    restore_static_notifier
    root=$(make_fixture "hostile_$name")
    case "$mutation" in
        absent)
            rm -f -- "$STATIC_WANTS"
            ;;
        regular)
            rm -f -- "$STATIC_WANTS"
            : > "$STATIC_WANTS"
            ;;
        relative)
            rm -f -- "$STATIC_WANTS"
            ln -s ../usbguard-notifier.service "$STATIC_WANTS"
            ;;
        wrong-target)
            rm -f -- "$STATIC_WANTS"
            : > "$STATIC_OTHER"
            chmod 0644 "$STATIC_OTHER"
            ln -s "$STATIC_OTHER" "$STATIC_WANTS"
            ;;
        unsafe-target)
            rm -f -- "$STATIC_WANTS" "$STATIC_TARGET"
            : > "$STATIC_OTHER"
            chmod 0644 "$STATIC_OTHER"
            ln -s "$STATIC_OTHER" "$STATIC_TARGET"
            ln -s "$STATIC_TARGET" "$STATIC_WANTS"
            ;;
        *) _fail "unknown hostile-link mutation: $mutation" ;;
    esac
    if run_fixture "$root" >/dev/null 2>&1; then
        _fail "hostile static link is rejected: $name"
    else
        _pass "hostile static link is rejected: $name"
    fi
    assert_cmd_success "hostile $name retains region progress" marker_is_exact \
        "$root/home/.config/noid-user-firstrun/region-v2.done" region
    assert_cmd_success "hostile $name retains update progress" marker_is_exact \
        "$root/home/.config/noid-user-firstrun/noid_update_reminder-v2.done" \
        noid_update_reminder
    assert_cmd_success "hostile $name retains Downloads progress" marker_is_exact \
        "$root/home/.config/noid-user-firstrun/nautilus_download_sort-v2.done" \
        nautilus_download_sort
    assert_cmd_success "hostile $name retains libvirt progress" marker_is_exact \
        "$root/home/.config/noid-user-firstrun/libvirt_qemu_core-v2.done" \
        libvirt_qemu_core
    if [ ! -e "$root/home/.config/noid-user-firstrun/usbguard_notifier-v2.done" ] \
       && [ ! -e "$root/home/.config/noid-user-firstrun/complete-v2.done" ]; then
        _pass "hostile $name cannot publish notifier or complete state"
    else
        _fail "hostile $name published false completion state"
    fi
    restore_static_notifier
    : > "$root/mock/systemctl.log"
    assert_cmd_success "hostile $name retry completes only notifier" \
        run_fixture "$root"
    assert_eq 0 "$(grep -c 'noid-update-reminder.timer' "$root/mock/systemctl.log" || true)" \
        "hostile $name retry does not repeat the update task"
    assert_eq 0 "$(grep -c '^--user preset ' "$root/mock/systemctl.log" || true)" \
        "hostile $name retry never presets the static notifier"
    assert_eq 2 "$(grep -c 'usbguard-notifier.service' "$root/mock/systemctl.log")" \
        "hostile $name retry starts and proves the notifier active"
}

exercise_hostile_static_link absent absent
exercise_hostile_static_link regular-file regular
exercise_hostile_static_link relative-link relative
exercise_hostile_static_link wrong-target wrong-target
exercise_hostile_static_link unsafe-target unsafe-target
restore_static_notifier

# A malformed duplicate LANG is fatal only to region; the independent
# Downloads and unit tasks complete and are not repeated after repair.
malformed=$(make_fixture malformed_locale)
printf 'LANG=de_DE.UTF-8\nLANG=en_US.UTF-8\n' > "$malformed/locale.conf"
if run_fixture "$malformed" >/dev/null 2>&1; then
    _fail "duplicate LANG failure returns non-zero"
else
    _pass "duplicate LANG failure returns non-zero"
fi
if [ ! -e "$malformed/home/.config/noid-user-firstrun/region-v2.done" ] \
   && marker_is_exact \
        "$malformed/home/.config/noid-user-firstrun/nautilus_download_sort-v2.done" \
        nautilus_download_sort \
   && marker_is_exact \
        "$malformed/home/.config/noid-user-firstrun/noid_update_reminder-v2.done" \
        noid_update_reminder \
   && marker_is_exact \
        "$malformed/home/.config/noid-user-firstrun/libvirt_qemu_core-v2.done" \
        libvirt_qemu_core \
   && marker_is_exact \
        "$malformed/home/.config/noid-user-firstrun/usbguard_notifier-v2.done" \
        usbguard_notifier; then
    _pass "malformed locale cannot erase independent task progress"
else
    _fail "malformed locale produced incorrect task-state partition"
fi
printf 'LANG=en_US.UTF-8\n' > "$malformed/locale.conf"
: > "$malformed/mock/systemctl.log"
assert_cmd_success "locale-only retry reaches completion" run_fixture "$malformed"
assert_eq 0 "$(wc -l < "$malformed/mock/systemctl.log")" \
    "locale-only retry does not touch completed units"

# A failed file fsync cannot publish that task or global completion. Other
# independently durable tasks remain available for a no-repeat retry.
durability=$(make_fixture durability_failure)
: > "$durability/mock/fail-next-sync"
if run_fixture "$durability" >/dev/null 2>&1; then
    _fail "marker fsync failure returns non-zero"
else
    _pass "marker fsync failure returns non-zero"
fi
if [ ! -e "$durability/home/.config/noid-user-firstrun/region-v2.done" ] \
   && marker_is_exact \
        "$durability/home/.config/noid-user-firstrun/nautilus_download_sort-v2.done" \
        nautilus_download_sort \
   && marker_is_exact \
        "$durability/home/.config/noid-user-firstrun/noid_update_reminder-v2.done" \
        noid_update_reminder \
   && marker_is_exact \
        "$durability/home/.config/noid-user-firstrun/libvirt_qemu_core-v2.done" \
        libvirt_qemu_core \
   && marker_is_exact \
        "$durability/home/.config/noid-user-firstrun/usbguard_notifier-v2.done" \
        usbguard_notifier \
   && [ ! -e "$durability/home/.config/noid-user-firstrun/complete-v2.done" ]; then
    _pass "fsync failure cannot publish failed-task or complete state"
else
    _fail "fsync failure produced incorrect durable task partition"
fi
: > "$durability/mock/systemctl.log"
assert_cmd_success "fsync retry completes only missing region" \
    run_fixture "$durability"
assert_eq 0 "$(wc -l < "$durability/mock/systemctl.log")" \
    "fsync retry repeats no completed unit task"

# A preset conflict that leaves a unit disabled fails its postcondition even
# when the command itself returned success.
conflict=$(make_fixture preset_conflict)
: > "$conflict/mock/preset-disabled-noid-update-reminder.timer"
if run_fixture "$conflict" >/dev/null 2>&1; then
    _fail "disabled postcondition after successful preset is rejected"
else
    _pass "disabled postcondition after successful preset is rejected"
fi
if [ ! -e "$conflict/home/.config/noid-user-firstrun/noid_update_reminder-v2.done" ] \
   && [ ! -e "$conflict/home/.config/noid-user-firstrun/complete-v2.done" ]; then
    _pass "preset conflict cannot publish update or complete state"
else
    _fail "preset conflict published false completion state"
fi

# An unavailable user manager leaves region and Downloads complete but neither
# unit marked.
no_bus=$(make_fixture unavailable_user_bus)
: > "$no_bus/mock/fail-daemon-reload"
if run_fixture "$no_bus" >/dev/null 2>&1; then
    _fail "unavailable user manager returns non-zero"
else
    _pass "unavailable user manager returns non-zero"
fi
if marker_is_exact "$no_bus/home/.config/noid-user-firstrun/region-v2.done" region \
   && marker_is_exact \
        "$no_bus/home/.config/noid-user-firstrun/nautilus_download_sort-v2.done" \
        nautilus_download_sort \
   && marker_is_exact \
        "$no_bus/home/.config/noid-user-firstrun/libvirt_qemu_core-v2.done" \
        libvirt_qemu_core \
   && [ ! -e "$no_bus/home/.config/noid-user-firstrun/noid_update_reminder-v2.done" ] \
   && [ ! -e "$no_bus/home/.config/noid-user-firstrun/usbguard_notifier-v2.done" ]; then
    _pass "user-manager failure retains independent region and Downloads tasks"
else
    _fail "user-manager failure produced incorrect task markers"
fi

# A symlinked state directory is rejected rather than writing through it.
symlinked=$(make_fixture symlink_state)
mkdir -p "$symlinked/home/.config" "$symlinked/redirect"
ln -s "$symlinked/redirect" "$symlinked/home/.config/noid-user-firstrun"
if run_fixture "$symlinked" >/dev/null 2>&1; then
    _fail "symlinked state directory is rejected"
else
    _pass "symlinked state directory is rejected"
fi
assert_eq 0 "$(find "$symlinked/redirect" -mindepth 1 -print | wc -l)" \
    "symlink rejection writes nothing through the redirect"

test_finish
