#!/usr/bin/env bash
# Regenerate admin-owned VSCodium desktop launchers from the current pristine
# RPM payload while routing only VSCodium's own Exec entries through the native
# default-GPU selector.
set -euo pipefail
umask 022
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin

if [[ $# -ne 0 ]]; then
    printf 'Usage: noid-codium-launcher-sync\n' >&2
    exit 2
fi

VENDOR_DIR=/usr/share/applications
ADMIN_DIR=/usr/local/share/applications
EXPECTED_PACKAGE=codium
VENDOR_EXECUTABLE=/usr/share/codium/codium
LAUNCH_WRAPPER=/usr/libexec/noid-codium-launch
DESKTOP_NAMES=(
    codium.desktop
    codium-url-handler.desktop
)

fail() {
    printf 'noid-codium-launcher-sync: %s\n' "$*" >&2
    exit 1
}

[[ $EUID -eq 0 ]] || fail "must run as root"
for command_name in awk chmod chown cmp desktop-file-validate grep install \
        matchpathcon mktemp mv readlink rm rmdir rpm sed sha256sum stat sync \
        update-desktop-database restorecon; do
    command -v "$command_name" >/dev/null 2>&1 || \
        fail "required command missing: $command_name"
done
[[ -f $LAUNCH_WRAPPER && ! -L $LAUNCH_WRAPPER \
   && -x $LAUNCH_WRAPPER ]] || fail "launch wrapper is missing or unsafe"

if [[ -e $ADMIN_DIR || -L $ADMIN_DIR ]]; then
    [[ -d $ADMIN_DIR && ! -L $ADMIN_DIR \
       && $(stat -c '%U:%G:%a' "$ADMIN_DIR" 2>/dev/null || true) == \
          root:root:755 ]] || fail "admin application directory is unsafe"
else
    install -d -m 0755 -o root -g root "$ADMIN_DIR"
fi

tmp_dir=$(mktemp -d -- "$ADMIN_DIR/.noid-codium.XXXXXXXX") || \
    fail "cannot allocate an admin-directory temporary"
declare -a candidates=()
cleanup() {
    local candidate
    for candidate in "${candidates[@]:-}"; do
        if [[ -n $candidate && -f $candidate && ! -L $candidate ]]; then
            rm -f -- "$candidate"
        fi
    done
    if [[ -n ${tmp_dir:-} && -d $tmp_dir && ! -L $tmp_dir ]]; then
        rmdir -- "$tmp_dir" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

validate_vendor_launcher() {
    local vendor_file=$1 dump_record dump_path expected_size expected_mtime
    local expected_sha expected_mode expected_owner expected_group dump_config
    local dump_doc dump_rdev dump_caps dump_extra expected_permissions

    [[ -f $vendor_file && ! -L $vendor_file ]] || \
        fail "vendor launcher is missing, non-regular or symlinked: $vendor_file"
    [[ $(rpm -qf --qf '%{NAME}\n' "$vendor_file" 2>/dev/null || true) == \
       "$EXPECTED_PACKAGE" ]] || fail "vendor launcher RPM owner differs: $vendor_file"

    dump_record=$(rpm -q --dump "$EXPECTED_PACKAGE" 2>/dev/null | \
        awk -v path="$vendor_file" \
            '$1 == path {print; found=1} END {exit !found}') || dump_record=
    read -r dump_path expected_size expected_mtime expected_sha expected_mode \
        expected_owner expected_group dump_config dump_doc dump_rdev dump_caps \
        dump_extra <<< "$dump_record"
    [[ $dump_path == "$vendor_file" \
       && $expected_mode =~ ^0100(644|755)$ \
       && $expected_owner == root && $expected_group == root \
       && ${dump_config:-}:${dump_doc:-}:${dump_rdev:-}:${dump_caps:-} == \
          0:0:0:X \
       && -z ${dump_extra:-} ]] || fail "vendor launcher RPM record is malformed"
    expected_permissions=${expected_mode: -3}
    [[ $(stat -c '%s:%Y:%U:%G:%a' "$vendor_file" 2>/dev/null || true) == \
       "$expected_size:$expected_mtime:$expected_owner:$expected_group:$expected_permissions" ]] || \
        fail "vendor launcher metadata differs from the RPM record"
    [[ $(sha256sum "$vendor_file" | awk '{print $1}') == "$expected_sha" ]] || \
        fail "vendor launcher bytes differ from the RPM record"
}

for desktop_name in "${DESKTOP_NAMES[@]}"; do
    vendor_file=$VENDOR_DIR/$desktop_name
    admin_file=$ADMIN_DIR/$desktop_name
    candidate=$tmp_dir/$desktop_name

    validate_vendor_launcher "$vendor_file"
    exec_count=$(grep -c '^Exec=' "$vendor_file" || true)
    vendor_exec_count=$(grep -c \
        "^Exec=${VENDOR_EXECUTABLE}\\([[:space:]]\\|$\\)" \
        "$vendor_file" || true)
    [[ $exec_count -ge 1 && $vendor_exec_count -eq $exec_count ]] || \
        fail "vendor launcher has an unreviewed execution path: $vendor_file"

    if [[ -e $admin_file || -L $admin_file ]]; then
        [[ -f $admin_file && ! -L $admin_file \
           && $(stat -c '%U:%G:%a' "$admin_file" 2>/dev/null || true) == \
              root:root:644 ]] || fail "existing admin launcher is unsafe: $admin_file"
    fi

    candidates+=("$candidate")
    sed -E "s#^Exec=${VENDOR_EXECUTABLE}([[:space:]]|$)#Exec=${LAUNCH_WRAPPER}\\1#" \
        "$vendor_file" > "$candidate" || fail "cannot generate launcher: $desktop_name"
    chown root:root "$candidate"
    chmod 0644 "$candidate"
    desktop-file-validate "$candidate" || \
        fail "generated launcher is invalid: $desktop_name"
    [[ $(grep -c "^Exec=${LAUNCH_WRAPPER}\\([[:space:]]\\|$\\)" \
            "$candidate" || true) -eq $exec_count ]] || \
        fail "generated launcher wrapper coverage differs: $desktop_name"
    [[ $(grep -c "^Exec=${VENDOR_EXECUTABLE}\\([[:space:]]\\|$\\)" \
            "$candidate" || true) -eq 0 ]] || \
        fail "generated launcher retained a direct VSCodium path: $desktop_name"
    sed -E "s#^Exec=${LAUNCH_WRAPPER}([[:space:]]|$)#Exec=${VENDOR_EXECUTABLE}\\1#" \
        "$candidate" | cmp -s - "$vendor_file" || \
        fail "generated launcher changed bytes outside Exec routing: $desktop_name"
done

for candidate in "${candidates[@]}"; do
    desktop_name=${candidate##*/}
    admin_file=$ADMIN_DIR/$desktop_name
    sync -- "$candidate"
    mv -fT -- "$candidate" "$admin_file"
    restorecon -F "$admin_file" || fail "cannot label launcher: $desktop_name"
    [[ $(stat -c '%U:%G:%a' "$admin_file" 2>/dev/null || true) == \
       root:root:644 ]] || fail "published launcher metadata differs: $desktop_name"
    matchpathcon -V "$admin_file" >/dev/null 2>&1 || \
        fail "published launcher SELinux context differs: $desktop_name"
done
candidates=()
update-desktop-database "$ADMIN_DIR" || fail "cannot refresh the desktop MIME cache"
sync -- "$ADMIN_DIR"
rmdir -- "$tmp_dir"
tmp_dir=
trap - EXIT HUP INT TERM
printf 'VSCodium desktop launchers synchronized to the default-GPU wrapper\n'
