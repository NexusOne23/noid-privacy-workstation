#!/usr/bin/env bash
# Publish an admin GNOME Software launcher that preserves explicit user launch
# while the separate session-bus admin descriptor blocks unsolicited starts.
# Standard desktop actions expose the one-shot RPM view and GNOME Software's
# own graceful --quit path; closing its last window alone intentionally leaves
# the upstream process held.
set -euo pipefail
umask 022
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin

if [[ $# -ne 0 ]]; then
    echo "Usage: noid-gnome-software-launcher-sync" >&2
    exit 2
fi

VENDOR_FILE=/usr/share/applications/org.gnome.Software.desktop
ADMIN_DIR=/usr/local/share/applications
ADMIN_FILE=$ADMIN_DIR/org.gnome.Software.desktop
EXPECTED_PACKAGE=gnome-software

fail() {
    echo "noid-gnome-software-launcher-sync: $*" >&2
    exit 1
}

[[ $EUID -eq 0 ]] || fail "must run as root"
for command_name in awk chmod chown desktop-file-edit desktop-file-install \
        desktop-file-validate grep install matchpathcon mktemp mv rm rmdir rpm \
        sha256sum restorecon stat sync; do
    command -v "$command_name" >/dev/null 2>&1 || \
        fail "required command missing: $command_name"
done

[[ -f $VENDOR_FILE && ! -L $VENDOR_FILE ]] || \
    fail "vendor launcher is missing, non-regular or symlinked"
[[ $(rpm -qf --qf '%{NAME}\n' "$VENDOR_FILE" 2>/dev/null || true) == \
   "$EXPECTED_PACKAGE" ]] || fail "vendor launcher RPM owner differs"

dump_record=$(rpm -q --dump "$EXPECTED_PACKAGE" 2>/dev/null | \
    awk -v path="$VENDOR_FILE" \
        '$1 == path {print; found=1} END {exit !found}') || dump_record=
read -r dump_path expected_size expected_mtime expected_sha expected_mode \
    expected_owner expected_group dump_config dump_doc dump_rdev dump_caps \
    dump_extra <<< "$dump_record"
[[ $dump_path == "$VENDOR_FILE" \
   && $expected_mode == 0100644 \
   && ${dump_config:-}:${dump_doc:-}:${dump_rdev:-}:${dump_caps:-} == 0:0:0:X \
   && -z ${dump_extra:-} ]] || fail "vendor launcher RPM record is malformed"
[[ $(stat -c '%s:%Y:%U:%G:%a' "$VENDOR_FILE" 2>/dev/null || true) == \
   "$expected_size:$expected_mtime:$expected_owner:$expected_group:644" ]] || \
    fail "vendor launcher metadata differs from the RPM record"
[[ $(sha256sum "$VENDOR_FILE" | awk '{print $1}') == "$expected_sha" ]] || \
    fail "vendor launcher bytes differ from the RPM record"

vendor_actions_count=$(awk '
    $0 == "[Desktop Entry]" { in_entry=1; next }
    /^\[/ { in_entry=0 }
    in_entry && /^Actions=/ { count++ }
    END { print count + 0 }
' "$VENDOR_FILE")
[[ $vendor_actions_count -le 1 ]] || fail "vendor launcher has duplicate Actions keys"
vendor_actions=$(awk '
    $0 == "[Desktop Entry]" { in_entry=1; next }
    /^\[/ { in_entry=0 }
    in_entry && /^Actions=/ { print substr($0, 9) }
' "$VENDOR_FILE")
vendor_actions=${vendor_actions%;}
for noid_action in NoIDFedoraRPM NoIDQuit; do
    case ";$vendor_actions;" in
        *";$noid_action;"*)
            fail "vendor launcher already owns the $noid_action action"
            ;;
    esac
    [[ $(grep -c "^\[Desktop Action $noid_action\]$" "$VENDOR_FILE") -eq 0 ]] || \
        fail "vendor launcher already owns the $noid_action action group"
done
if [[ -n $vendor_actions ]]; then
    admin_actions="$vendor_actions;NoIDFedoraRPM;NoIDQuit;"
else
    admin_actions='NoIDFedoraRPM;NoIDQuit;'
fi

if [[ -e $ADMIN_DIR || -L $ADMIN_DIR ]]; then
    [[ -d $ADMIN_DIR && ! -L $ADMIN_DIR \
       && $(stat -c '%U:%G:%a' "$ADMIN_DIR" 2>/dev/null || true) == \
          root:root:755 ]] || fail "admin application directory is unsafe"
else
    install -d -m 0755 -o root -g root "$ADMIN_DIR"
fi

tmp_dir=$(mktemp -d -- "$ADMIN_DIR/.noid-gnome-software.XXXXXXXX") || \
    fail "cannot allocate an admin-directory temporary"
candidate=$tmp_dir/org.gnome.Software.desktop
cleanup() {
    if [[ -n ${candidate:-} && -e ${candidate:-} ]]; then
        rm -f -- "$candidate"
    fi
    if [[ -n ${tmp_dir:-} && -d ${tmp_dir:-} ]]; then
        rmdir -- "$tmp_dir" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

desktop-file-install \
    --dir="$tmp_dir" \
    --mode=0644 \
    --set-key=DBusActivatable \
    --set-value=false \
    "$VENDOR_FILE" || fail "cannot generate the admin launcher"
[[ -f $candidate && ! -L $candidate ]] || fail "generated launcher is unsafe"
printf '\n[Desktop Action NoIDFedoraRPM]\nName=Open GNOME Software with Fedora RPMs\nName[de]=GNOME Software mit Fedora-RPMs öffnen\nExec=/usr/local/bin/noid-gnome-software-rpm\n\n[Desktop Action NoIDQuit]\nName=Quit completely\nName[de]=Vollständig beenden\nExec=/usr/local/bin/noid-gnome-software-quit\n' \
    >> "$candidate" || fail "cannot add the NoID Privacy desktop actions"
desktop-file-edit \
    --set-key=Actions \
    --set-value="$admin_actions" \
    "$candidate" || fail "cannot publish the complete-quit action reference"
chown root:root "$candidate"
chmod 0644 "$candidate"
desktop-file-validate "$candidate" || fail "generated launcher is invalid"
[[ $(grep -c '^DBusActivatable=' "$candidate") -eq 1 ]] || \
    fail "generated launcher activation key count differs"
grep -qxF 'DBusActivatable=false' "$candidate" || \
    fail "generated launcher does not force direct execution"
grep -qxF 'Exec=gnome-software %U' "$candidate" || \
    fail "generated launcher lost Fedora's explicit execution path"
grep -qxF "Actions=$admin_actions" "$candidate" || \
    fail "generated launcher action list differs"
[[ $(grep -c '^\[Desktop Action NoIDQuit\]$' "$candidate") -eq 1 ]] || \
    fail "generated launcher complete-quit action count differs"
[[ $(grep -c '^\[Desktop Action NoIDFedoraRPM\]$' "$candidate") -eq 1 ]] || \
    fail "generated launcher Fedora RPM action count differs"
grep -qxF 'Exec=/usr/local/bin/noid-gnome-software-rpm' "$candidate" || \
    fail "generated launcher lost the Fedora RPM one-shot path"
grep -qxF 'Exec=/usr/local/bin/noid-gnome-software-quit' "$candidate" || \
    fail "generated launcher lost the graceful complete-quit path"

sync -- "$candidate"
mv -fT -- "$candidate" "$ADMIN_FILE"
candidate=
restorecon -F "$ADMIN_FILE" || fail "cannot label the admin launcher"
[[ $(stat -c '%U:%G:%a' "$ADMIN_FILE" 2>/dev/null || true) == \
   root:root:644 ]] || fail "published launcher metadata differs"
matchpathcon -V "$ADMIN_FILE" >/dev/null 2>&1 || \
    fail "published launcher SELinux context differs"
sync -- "$ADMIN_FILE"
sync -- "$ADMIN_DIR"
rmdir -- "$tmp_dir"
tmp_dir=
trap - EXIT HUP INT TERM
