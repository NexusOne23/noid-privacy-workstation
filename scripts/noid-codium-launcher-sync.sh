#!/usr/bin/env bash
# Regenerate admin-owned VSCodium desktop launchers from the current pristine
# RPM payload while routing only VSCodium's own Exec entries through the native
# default-GPU selector. --prune removes those generated launchers once the
# codium package is no longer installed, so no dead desktop entry or MIME
# handler remains after the package is removed.
set -euo pipefail
umask 022
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin

MODE=sync
case "$#:${1:-}" in
    0:) ;;
    1:--prune) MODE=prune ;;
    *)
        printf 'Usage: noid-codium-launcher-sync [--prune]\n' >&2
        exit 2
        ;;
esac

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
for command_name in awk chmod chown cmp desktop-file-validate find grep install \
        matchpathcon mktemp mv readlink rm rmdir rpm sed sha256sum stat sync \
        update-desktop-database restorecon; do
    command -v "$command_name" >/dev/null 2>&1 || \
        fail "required command missing: $command_name"
done

if [[ -e $ADMIN_DIR || -L $ADMIN_DIR ]]; then
    [[ -d $ADMIN_DIR && ! -L $ADMIN_DIR \
       && $(stat -c '%U:%G:%a' "$ADMIN_DIR" 2>/dev/null || true) == \
          root:root:755 ]] || fail "admin application directory is unsafe"
elif [[ $MODE == prune ]]; then
    printf 'No admin application directory; nothing to prune\n'
    exit 0
else
    install -d -m 0755 -o root -g root "$ADMIN_DIR"
fi

# The package-removal path deletes only launchers this helper generated: a
# root-owned regular file whose every Exec entry routes through the wrapper.
# An administrator's own replacement file is reported and left in place.
prune_generated_launchers() {
    local desktop_name admin_file exec_count wrapper_count query removed=0
    # Distinguish an absent package from an unreadable RPM database so a
    # query failure can never delete working launchers.
    query=$(rpm -q --qf '%{NAME}\n' "$EXPECTED_PACKAGE" 2>&1 || true)
    case "$query" in
        "$EXPECTED_PACKAGE"|"$EXPECTED_PACKAGE"$'\n'*)
            printf 'VSCodium is installed; its launchers stay synchronized\n'
            return 0
            ;;
        "package $EXPECTED_PACKAGE is not installed") ;;
        *) fail "cannot determine whether $EXPECTED_PACKAGE is installed" ;;
    esac
    for desktop_name in "${DESKTOP_NAMES[@]}"; do
        admin_file=$ADMIN_DIR/$desktop_name
        [[ -e $admin_file || -L $admin_file ]] || continue
        [[ -f $admin_file && ! -L $admin_file \
           && $(stat -c '%U:%G:%a:%h' "$admin_file" 2>/dev/null || true) == \
              root:root:644:1 ]] || fail "existing admin launcher is unsafe: $admin_file"
        exec_count=$(grep -c '^Exec=' "$admin_file" || true)
        wrapper_count=$(grep -c \
            "^Exec=${LAUNCH_WRAPPER}\\([[:space:]]\\|$\\)" \
            "$admin_file" || true)
        if [[ $exec_count -lt 1 || $wrapper_count -ne $exec_count ]]; then
            printf 'noid-codium-launcher-sync: keeping administrator launcher: %s\n' \
                "$admin_file" >&2
            continue
        fi
        rm -f -- "$admin_file"
        removed=1
    done
    if [[ $removed -eq 1 ]]; then
        update-desktop-database "$ADMIN_DIR" || \
            fail "cannot refresh the desktop MIME cache"
        sync -- "$ADMIN_DIR"
    fi
    printf 'VSCodium is not installed; generated desktop launchers pruned\n'
}

if [[ $MODE == prune ]]; then
    prune_generated_launchers
    exit 0
fi

[[ -f $LAUNCH_WRAPPER && ! -L $LAUNCH_WRAPPER \
   && -x $LAUNCH_WRAPPER ]] || fail "launch wrapper is missing or unsafe"

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
    local dump_doc dump_rdev dump_symlink dump_extra expected_permissions

    [[ -f $vendor_file && ! -L $vendor_file ]] || \
        fail "vendor launcher is missing, non-regular or symlinked: $vendor_file"
    [[ $(rpm -qf --qf '%{NAME}\n' "$vendor_file" 2>/dev/null || true) == \
       "$EXPECTED_PACKAGE" ]] || fail "vendor launcher RPM owner differs: $vendor_file"

    dump_record=$(rpm -q --dump "$EXPECTED_PACKAGE" 2>/dev/null | \
        awk -v path="$vendor_file" \
            '$1 == path {print; found=1} END {exit !found}') || dump_record=
    # rpm --dump columns: path size mtime digest mode owner group isconfig
    # isdoc rdev symlink. Column 11 is the symlink target (X = none), not a
    # file-capability field.
    read -r dump_path expected_size expected_mtime expected_sha expected_mode \
        expected_owner expected_group dump_config dump_doc dump_rdev dump_symlink \
        dump_extra <<< "$dump_record"
    [[ $dump_path == "$vendor_file" \
       && $expected_mode =~ ^0100(644|755)$ \
       && $expected_owner == root && $expected_group == root \
       && ${dump_config:-}:${dump_doc:-}:${dump_rdev:-}:${dump_symlink:-} == \
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

# A launcher that already carries the generated bytes and metadata keeps its
# inode, and the MIME cache is rebuilt only when it is missing or older than an
# admin launcher (including the Firefox/Thunderbird overlays): replacing
# identical files would surface as AIDE drift after every DNF transaction.
launchers_changed=0
if [[ ! -f $ADMIN_DIR/mimeinfo.cache || -L $ADMIN_DIR/mimeinfo.cache \
      || $(stat -c '%a' "$ADMIN_DIR/mimeinfo.cache") != 644 ]] \
   || [[ -n $(find "$ADMIN_DIR" -maxdepth 1 -name '*.desktop' \
              -newer "$ADMIN_DIR/mimeinfo.cache" -print -quit) ]]; then
    launchers_changed=1
fi
for candidate in "${candidates[@]}"; do
    desktop_name=${candidate##*/}
    admin_file=$ADMIN_DIR/$desktop_name
    if [[ -f $admin_file && ! -L $admin_file \
          && $(stat -c '%U:%G:%a:%h' "$admin_file" 2>/dev/null || true) == \
             root:root:644:1 ]] \
       && cmp -s -- "$candidate" "$admin_file" \
       && matchpathcon -V "$admin_file" >/dev/null 2>&1; then
        rm -f -- "$candidate"
        continue
    fi
    launchers_changed=1
    sync -- "$candidate"
    mv -fT -- "$candidate" "$admin_file"
    restorecon -F "$admin_file" || fail "cannot label launcher: $desktop_name"
    [[ $(stat -c '%U:%G:%a' "$admin_file" 2>/dev/null || true) == \
       root:root:644 ]] || fail "published launcher metadata differs: $desktop_name"
    matchpathcon -V "$admin_file" >/dev/null 2>&1 || \
        fail "published launcher SELinux context differs: $desktop_name"
done
candidates=()
if [[ $launchers_changed -eq 1 ]]; then
    update-desktop-database "$ADMIN_DIR" || fail "cannot refresh the desktop MIME cache"
fi
sync -- "$ADMIN_DIR"
rmdir -- "$tmp_dir"
tmp_dir=
trap - EXIT HUP INT TERM
printf 'VSCodium desktop launchers synchronized to the default-GPU wrapper\n'
