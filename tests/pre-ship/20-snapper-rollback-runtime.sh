#!/usr/bin/env bash
# Candidate-only M20 lifecycle and destructive rollback gate. The fresh-install
# pass intentionally selects a just-created disposable rollback root. Run it
# only after M21's reboot pass has confirmed a terminal boot basis, and last
# before the separate rollback reboot. The reboot pass proves that root
# actually booted and that a post-snapshot probe disappeared.
set -euo pipefail
export LC_ALL=C
export TZ=UTC
export PATH=/usr/sbin:/usr/bin
export BASH_ENV=/dev/null
export ENV=/dev/null
IFS=$' \t\n'
umask 077
unset CDPATH GLOBIGNORE PYTHONHOME PYTHONPATH TMPDIR

TEST_NAME=20-snapper-rollback-runtime

PASS_ID=unresolved
fail() { echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2; exit 1; }
note() { echo "  [$PASS_ID] $*"; }

[[ $# -eq 1 ]] || {
    echo "usage: $0 {live|fresh-install|reboot}" >&2
    exit 2
}
PASS_ID=$1
case "$PASS_ID" in
    live|fresh-install|reboot) ;;
    *) fail "pass identity must be live, fresh-install or reboot" ;;
esac

[[ $(id -u) -eq 0 ]] || fail "run with sudo as documented"
[[ $(grep -c '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || true) \
    -eq 1 ]] || \
    fail "not running inside the NoID Privacy candidate"
for tool in \
        awk btrfs cat chmod chown cmp date dirname findmnt flock getenforce \
        getent grep id lsattr matchpathcon mktemp mv python3 readlink rm rpm \
        runuser sha256sum snapper stat sudo sync systemctl \
        systemd-detect-virt timeout tr visudo wc; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing command: $tool"
done

SCRIPT_PATH=$(readlink -e -- "$0") || fail "cannot resolve gate path"
REPO_ROOT=$(cd "$(dirname "$SCRIPT_PATH")/../.." && pwd -P) || \
    fail "cannot resolve repository root"
M20_REPO="$REPO_ROOT/kickstart/snippets/20-snapper.ks"
M21_REPO="$REPO_ROOT/kickstart/snippets/21-kernel-module-blacklist.ks"
for source_path in "$M20_REPO" "$M21_REPO"; do
    [[ -f $source_path && ! -L $source_path && -s $source_path \
       && $(readlink -e -- "$source_path") == "$source_path" ]] || \
        fail "canonical source is missing, empty, symlinked or non-canonical: $source_path"
done
[[ $(getenforce) == Enforcing ]] || fail "SELinux is not enforcing"
virtualization=$(systemd-detect-virt --vm 2>/dev/null || true)
case "$virtualization" in
    kvm|qemu) ;;
    *) fail "destructive lifecycle proof requires the documented disposable QEMU/KVM VM" ;;
esac

TEST_TMP=$(mktemp -d /tmp/noid-snapper-runtime.XXXXXXXX) || \
    fail "cannot create private runtime workspace"
STATE_DIR=
STATE_CANDIDATE=
cleanup() {
    local rc=$?
    trap - EXIT
    if [[ -n $STATE_CANDIDATE && -n $STATE_DIR \
       && $STATE_CANDIDATE == "$STATE_DIR"/.runtime-gate.* ]]; then
        rm -f -- "$STATE_CANDIDATE" || rc=1
    fi
    rm -rf -- "$TEST_TMP" || rc=1
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if ! python3 -I - "$M20_REPO" "$M21_REPO" "$TEST_TMP" <<'EXTRACT_SOURCES_PYEOF'
import pathlib
import re
import sys

m20_path, m21_path, output_path = map(pathlib.Path, sys.argv[1:])
sources = (
    m20_path.read_text(encoding="utf-8"),
    m21_path.read_text(encoding="utf-8"),
)
payloads = (
    (0, "SNAPPER_ROOT_CONFIG_EOF", "/etc/snapper/configs/root"),
    (0, "SNAPPER_INIT_EOF", "/usr/local/bin/noid-snapper-init.sh"),
    (0, "SNAPPER_INIT_SERVICE_EOF",
     "/etc/systemd/system/noid-snapper-init.service"),
    (0, "CLEANUP_TIMER_EOF",
     "/etc/systemd/system/snapper-cleanup.timer.d/99-noid-frequency.conf"),
    (0, "CLEANUP_SERVICE_EOF",
     "/etc/systemd/system/snapper-cleanup.service.d/99-noid-live-guard.conf"),
    (0, "SNAPPER_CREATE_EOF", "/usr/libexec/noid-snapper-create"),
    (0, "SNAPPER_STATUS_EOF", "/usr/libexec/noid-snapper-status"),
    (0, "SNAPPER_ROLLBACK_EOF", "/usr/libexec/noid-snapper-rollback"),
    (0, "SNAPPER_STATUS_SUDO_EOF",
     "/etc/sudoers.d/noid-snapper-status"),
    (0, "SNAPPER_PRUNE_EOF", "/usr/local/sbin/noid-snapper-prune.sh"),
    (0, "SNAPPER_PRUNE_SERVICE_EOF",
     "/etc/systemd/system/noid-snapper-prune.service"),
    (0, "SNAPPER_PRUNE_TIMER_EOF",
     "/etc/systemd/system/noid-snapper-prune.timer"),
    (1, "BOOT_MUTATION_GUARD_EOF",
     "/usr/libexec/noid-boot-mutation-guard"),
    (1, "BOOT_MUTATION_TMPFILES_EOF",
     "/usr/lib/tmpfiles.d/noid-boot-mutation-lock.conf"),
)
for source_index, marker, target in payloads:
    pattern = re.compile(
        rf"^cat > {re.escape(target)} <<'{re.escape(marker)}'\n"
        rf"(.*?)^{re.escape(marker)}$",
        re.MULTILINE | re.DOTALL,
    )
    matches = pattern.findall(sources[source_index])
    assert len(matches) == 1, (marker, len(matches))
    (output_path / marker).write_text(matches[0], encoding="utf-8")
EXTRACT_SOURCES_PYEOF
then
    fail "cannot extract unique canonical M20/M21 payloads"
fi

require_root_file() {
    local path=$1 mode=$2 canonical metadata
    [[ -f $path && ! -L $path && -s $path ]] || \
        fail "missing, empty, non-regular or symlinked: $path"
    canonical=$(readlink -e -- "$path") || \
        fail "cannot canonicalize root payload: $path"
    # Fedora 42 merged sbin into bin, so /usr/local/sbin and /usr/sbin are
    # vendor symlinks to their bin siblings. A managed payload installed under
    # the admin path therefore always resolves one level, which is not a
    # symlink escape. Accept exactly that vendor rewrite and nothing else.
    [[ $canonical == "$path" \
       || $canonical == "/usr/local/bin/${path#/usr/local/sbin/}" \
       || $canonical == "/usr/bin/${path#/usr/sbin/}" ]] || \
        fail "root payload path is non-canonical: $path"
    metadata=$(stat -c '%u:%g:%a:%h:%F' -- "$path") || \
        fail "cannot inspect root payload: $path"
    [[ $metadata == "0:0:$mode:1:regular file" ]] || \
        fail "unsafe owner/mode/type/hardlink count: $path ($metadata)"
    matchpathcon -V "$path" >/dev/null || \
        fail "root payload SELinux label differs: $path"
}

require_rpm_file() {
    local path=$1 package=$2 mode=$3 package_record digest actual
    require_root_file "$path" "$mode"
    package_record=$(rpm -qf --qf '%{NAME}|%{FILEDIGESTALGO}\n' "$path") || \
        fail "cannot resolve RPM owner: $path"
    [[ $package_record == "$package|8" ]] || \
        fail "RPM owner or digest algorithm differs: $path ($package_record)"
    digest=$(rpm -qf --qf '[%{FILENAMES}|%{FILEDIGESTS}\n]' "$path" | \
        awk -F'|' -v path="$path" '
            $1 == path { digest=$2; count++ }
            END {
                if (count != 1 || digest !~ /^[0-9a-f]{64}$/) exit 1
                print digest
            }
        ') || fail "cannot resolve exact RPM digest: $path"
    actual=$(sha256sum -- "$path" | awk '{ print $1 }') || \
        fail "cannot hash RPM payload: $path"
    [[ $actual == "$digest" ]] || fail "RPM payload bytes differ: $path"
}

for specification in \
        "SNAPPER_ROOT_CONFIG_EOF|/etc/snapper/configs/root|640" \
        "SNAPPER_INIT_EOF|/usr/local/bin/noid-snapper-init.sh|755" \
        "SNAPPER_INIT_SERVICE_EOF|/etc/systemd/system/noid-snapper-init.service|644" \
        "CLEANUP_TIMER_EOF|/etc/systemd/system/snapper-cleanup.timer.d/99-noid-frequency.conf|644" \
        "CLEANUP_SERVICE_EOF|/etc/systemd/system/snapper-cleanup.service.d/99-noid-live-guard.conf|644" \
        "SNAPPER_CREATE_EOF|/usr/libexec/noid-snapper-create|755" \
        "SNAPPER_STATUS_EOF|/usr/libexec/noid-snapper-status|755" \
        "SNAPPER_ROLLBACK_EOF|/usr/libexec/noid-snapper-rollback|755" \
        "SNAPPER_STATUS_SUDO_EOF|/etc/sudoers.d/noid-snapper-status|440" \
        "SNAPPER_PRUNE_EOF|/usr/local/sbin/noid-snapper-prune.sh|755" \
        "SNAPPER_PRUNE_SERVICE_EOF|/etc/systemd/system/noid-snapper-prune.service|644" \
        "SNAPPER_PRUNE_TIMER_EOF|/etc/systemd/system/noid-snapper-prune.timer|644" \
        "BOOT_MUTATION_GUARD_EOF|/usr/libexec/noid-boot-mutation-guard|755" \
        "BOOT_MUTATION_TMPFILES_EOF|/usr/lib/tmpfiles.d/noid-boot-mutation-lock.conf|644"; do
    IFS='|' read -r marker installed mode <<< "$specification"
    require_root_file "$installed" "$mode"
    cmp -s -- "$TEST_TMP/$marker" "$installed" || \
        fail "installed payload differs from canonical source: $installed"
done
require_rpm_file /usr/bin/snapper snapper 755
require_rpm_file /usr/bin/btrfs btrfs-progs 755
require_rpm_file /usr/lib/systemd/system/snapper-cleanup.timer snapper 644
require_rpm_file /usr/lib/systemd/system/snapper-cleanup.service snapper 644
[[ -L /usr/local/sbin/noid-snap-rollback \
   && $(readlink -- /usr/local/sbin/noid-snap-rollback) == \
        /usr/libexec/noid-snapper-rollback \
   && $(stat -c '%u:%g:%a:%h:%F' -- /usr/local/sbin/noid-snap-rollback) == \
        '0:0:777:1:symbolic link' ]] || \
    fail "rollback convenience link identity or metadata drifted"
matchpathcon -V /usr/local/sbin/noid-snap-rollback >/dev/null || \
    fail "rollback convenience link SELinux label differs"

RUNTIME_LOCK=/run/lock/noid-snapper-runtime-gate.lock
[[ $(readlink -e -- /run/lock) == /run/lock \
   && $(stat -c '%u:%g:%a:%F' -- /run/lock) == '0:0:755:directory' \
   && ! -L $RUNTIME_LOCK ]] || fail "runtime-lock boundary is unsafe"
# Fedora's file_contexts declares `/run/lock/.*  <<none>>`: a lock file below
# the lock directory has no context of its own by policy and inherits
# var_lock_t from its parent, so matchpathcon -V can never succeed on it.
# Require the inheritance the policy actually specifies instead.
lock_dir_type=$(stat -c '%C' -- /run/lock | cut -d: -f3) || \
    fail "cannot read runtime-lock directory label"
[[ $lock_dir_type == var_lock_t ]] || \
    fail "runtime-lock directory type differs: $lock_dir_type"
require_inherited_lock_type() {
    local actual
    actual=$(stat -c '%C' -- "$1" | cut -d: -f3) || return 1
    [[ $actual == "$lock_dir_type" ]]
}
# The lock carries no payload, and `stat -c %F` reports a zero-byte file as
# "regular empty file", so the regular-file property is asserted with -f/! -L
# rather than through the descriptive type string.
if [[ -e $RUNTIME_LOCK ]]; then
    [[ -f $RUNTIME_LOCK && ! -L $RUNTIME_LOCK \
       && $(stat -c '%u:%g:%a:%h' -- "$RUNTIME_LOCK") == '0:0:600:1' ]] \
        && require_inherited_lock_type "$RUNTIME_LOCK" \
        || fail "existing runtime lock is unsafe"
fi
exec 7>"$RUNTIME_LOCK"
[[ -f $RUNTIME_LOCK && ! -L $RUNTIME_LOCK \
   && $(stat -c '%u:%g:%a:%h' -- "$RUNTIME_LOCK") == '0:0:600:1' ]] \
    && require_inherited_lock_type "$RUNTIME_LOCK" \
    || fail "runtime lock publication is unsafe"
flock -n 7 || fail "another Snapper runtime gate is active"

status_read() {
    /usr/libexec/noid-snapper-status
}

cmdline_key_count() {
    local wanted=$1 token count=0
    local -a kernel_cmdline=()
    read -r -a kernel_cmdline < /proc/cmdline || \
        fail "cannot read the kernel command line"
    for token in "${kernel_cmdline[@]}"; do
        case "$token" in
            "$wanted"|"$wanted"=*) count=$((count + 1)) ;;
        esac
    done
    printf '%s\n' "$count"
}

assert_live_condition_rejects() {
    local unit=$1 condition next
    systemctl start "$unit" || fail "$unit start job failed instead of being condition-skipped"
    systemctl is-active --quiet "$unit" && fail "$unit became active on Live"
    systemctl is-failed --quiet "$unit" && fail "$unit is failed instead of cleanly skipped on Live"
    condition=$(systemctl show --property=ConditionResult --value "$unit") || \
        fail "cannot read $unit ConditionResult"
    [ "$condition" = no ] || fail "$unit did not record the rejected Live condition: $condition"
    case "$unit" in
        *.timer)
            next=$(systemctl show --property=NextElapseUSecRealtime --value "$unit") || \
                fail "cannot read $unit next trigger"
            [ -z "$next" ] || [ "$next" = n/a ] || \
                fail "$unit retained a Live trigger despite the rejected condition: $next"
            ;;
    esac
}

assert_installed_timer() {
    local unit=$1 condition next persistent
    systemctl is-enabled --quiet "$unit" || fail "$unit is not enabled after installation"
    systemctl is-active --quiet "$unit" || fail "$unit is not active after installation"
    condition=$(systemctl show --property=ConditionResult --value "$unit") || \
        fail "cannot read $unit ConditionResult"
    [ "$condition" = yes ] || fail "$unit installed condition did not pass: $condition"
    next=$(systemctl show --property=NextElapseUSecRealtime --value "$unit") || \
        fail "cannot read $unit next trigger"
    [ -n "$next" ] && [ "$next" != n/a ] || fail "$unit has no installed next trigger"
    persistent=$(systemctl show --property=Persistent --value "$unit") || \
        fail "cannot read $unit Persistent property"
    [ "$persistent" = yes ] || fail "$unit lost installed Persistent=true semantics: $persistent"
}

live_image_count=$(cmdline_key_count rd.live.image)
[ -d /usr/libexec/snapper/plugins ] \
    && [ ! -L /usr/libexec/snapper/plugins ] \
    && [ "$(stat -c '%u:%g:%a:%F' /usr/libexec/snapper/plugins \
            2>/dev/null || true)" = '0:0:755:directory' ] \
    || fail "empty Snapper plugin boundary is missing or unsafe"
if [[ $PASS_ID == live ]]; then
    [[ $live_image_count -eq 1 ]] || \
        fail "live pass requires exactly one rd.live.image parameter"
    [[ ! -e /.snapshots/.noid-state/init.done \
       && ! -L /.snapshots/.noid-state/init.done ]] || \
        fail "Snapper firstboot marker was created in live mode"
    live_status=''
    if live_status=$(status_read 2>/dev/null); then
        case "$live_status" in
            *' boot=degraded '*) ;;
            *) fail "live overlay was reported rollback-ready: $live_status" ;;
        esac
    fi
    assert_live_condition_rejects noid-snapper-init.service
    assert_live_condition_rejects snapper-cleanup.timer
    assert_live_condition_rejects snapper-cleanup.service
    assert_live_condition_rejects noid-snapper-prune.timer
    echo "PASS  $TEST_NAME [$PASS_ID]: artifacts present; cleanup timers and direct vendor cleanup are condition-skipped; live overlay never becomes rollback-ready"
    exit 0
fi

[[ $live_image_count -eq 0 ]] || fail "installed pass retains rd.live.image"
[ "$(findmnt --target / -n -o FSTYPE 2>/dev/null)" = btrfs ] || \
    fail "installed root is not Btrfs"
assert_installed_timer snapper-cleanup.timer
assert_installed_timer noid-snapper-prune.timer
systemctl is-enabled --quiet noid-snapper-init.service || \
    fail "Snapper initializer is not enabled"
systemctl is-failed --quiet noid-snapper-init.service && \
    fail "Snapper initializer is failed"

STATE_DIR=/.snapshots/.noid-state
INIT_MARKER=$STATE_DIR/init.done
BOOT_STATE=$STATE_DIR/boot-model.ready
GATE_STATE=$STATE_DIR/runtime-gate.state
PROBE=/etc/noid-snapper-runtime-probe
BOOT_LOCK=/run/lock/noid-boot-mutation.lock
BOOT_GUARD=/usr/libexec/noid-boot-mutation-guard

for path in "$STATE_DIR" "$INIT_MARKER" "$BOOT_STATE"; do
    [ -e "$path" ] && [ ! -L "$path" ] || fail "missing or symlinked stable state: $path"
done
[ -d "$STATE_DIR" ] || fail "stable state path is not a directory"
[ "$(stat -c '%u:%g:%a:%F' "$STATE_DIR")" = '0:0:700:directory' ] || \
    fail "stable state directory metadata drifted"
[ -f "$INIT_MARKER" ] && [ ! -s "$INIT_MARKER" ] \
    && [ "$(stat -c '%u:%g:%a:%h:%F' "$INIT_MARKER")" = \
        '0:0:600:1:regular empty file' ] || \
    fail "initializer marker metadata drifted"
[ -f "$BOOT_STATE" ] \
    && [ "$(stat -c '%u:%g:%a:%h:%F' "$BOOT_STATE")" = \
        '0:0:600:1:regular file' ] || fail "boot-model state metadata drifted"
for path in /.snapshots "$STATE_DIR" "$INIT_MARKER" "$BOOT_STATE"; do
    matchpathcon -V "$path" >/dev/null || \
        fail "stable state SELinux label differs: $path"
done
[ "$(cat "$BOOT_STATE")" = $'MODEL=default-subvolume-v1\nSNAPSHOTS_FSROOT=/snapshots\nLIBVIRT_FSROOT=/libvirt' ] || \
    fail "boot-model state schema drifted"
[ -f "$BOOT_LOCK" ] && [ ! -L "$BOOT_LOCK" ] \
    && [ "$(stat -c '%U:%G:%a:%h:%F' "$BOOT_LOCK")" = \
        'root:wheel:660:1:regular empty file' ] \
    && require_inherited_lock_type "$BOOT_LOCK" \
    || fail "shared boot-mutation lock is missing or unsafe"
[ -f "$BOOT_GUARD" ] && [ ! -L "$BOOT_GUARD" ] && [ -x "$BOOT_GUARD" ] \
    || fail "central boot-mutation guard is missing or unsafe"

has_mount_option() {
    local target=$1 wanted=$2 options
    options=$(findmnt --target "$target" -n -o OPTIONS 2>/dev/null) || return 1
    tr ',' '\n' <<<"$options" | grep -qxF "$wanted"
}

[ "$(findmnt --target /.snapshots -n -o TARGET)" = /.snapshots ] && \
[ "$(findmnt --target /.snapshots -n -o FSROOT)" = /snapshots ] && \
[ "$(findmnt --target /.snapshots -n -o FSTYPE)" = btrfs ] || \
    fail "stable snapshot subvolume is not an exact mount"
has_mount_option /.snapshots nosuid && has_mount_option /.snapshots nodev && \
has_mount_option /.snapshots noexec || fail "snapshot mount hardening drifted"
[ "$(findmnt --target /var/lib/libvirt -n -o TARGET)" = /var/lib/libvirt ] && \
[ "$(findmnt --target /var/lib/libvirt -n -o FSROOT)" = /libvirt ] && \
[ "$(findmnt --target /var/lib/libvirt -n -o FSTYPE)" = btrfs ] || \
    fail "stable libvirt subvolume is not an exact mount"
[ "$(findmnt --mountpoint /var/lib/libvirt -n -o TARGET 2>/dev/null | wc -l)" -eq 1 ] || \
    fail "stable libvirt subvolume is mounted more than once"
has_mount_option /var/lib/libvirt nosuid && \
has_mount_option /var/lib/libvirt nodev || fail "libvirt mount hardening drifted"
lsattr -d /var/lib/libvirt 2>/dev/null | awk '{print $1}' | grep -q C || \
    fail "libvirt subvolume is not nodatacow"
root_device=$(findmnt --target / -n -o MAJ:MIN 2>/dev/null) || \
    fail "cannot identify the installed root filesystem"
[ -n "$root_device" ] && \
[ "$(findmnt --target /.snapshots -n -o MAJ:MIN 2>/dev/null)" = "$root_device" ] && \
[ "$(findmnt --target /var/lib/libvirt -n -o MAJ:MIN 2>/dev/null)" = "$root_device" ] || \
    fail "stable subvolume mounts are not on the installed root filesystem"

python3 -I - /etc/fstab <<'FSTAB_PY' || fail "installed fstab violates the rollback contract"
import pathlib
import sys

rows = []
for raw in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    fields = line.split()
    if len(fields) < 6:
        raise SystemExit(1)
    rows.append(fields)

def one(target):
    matches = [row for row in rows if row[1] == target]
    if len(matches) != 1:
        raise SystemExit(1)
    return matches[0]

root = one("/")
snapshots = one("/.snapshots")
libvirt = one("/var/lib/libvirt")
if root[2] != "btrfs" or any(
    item.startswith(("subvol=", "subvolid=")) for item in root[3].split(",")
):
    raise SystemExit(1)
if snapshots[0] != root[0] or libvirt[0] != root[0]:
    raise SystemExit(1)
for row, expected_options in (
    (
        snapshots,
        "subvol=snapshots,nosuid,nodev,noexec,x-systemd.device-timeout=0",
    ),
    (
        libvirt,
        "subvol=libvirt,nosuid,nodev,x-systemd.device-timeout=0",
    ),
):
    if len(row) != 6 or row[2] != "btrfs" \
            or row[3] != expected_options or row[4:] != ["0", "0"]:
        raise SystemExit(1)
FSTAB_PY

check_boot_tokens() {
    local file=$1 options root_count
    [ -f "$file" ] && [ ! -L "$file" ] || return 1
    if [ "$file" = /etc/kernel/cmdline ]; then
        options=$(cat "$file")
    else
        [ "$(awk '$1 == "options" {count++} END {print count+0}' "$file")" -eq 1 ] || return 1
        options=$(awk '$1 == "options" {$1=""; sub(/^ /,""); print}' "$file")
    fi
    root_count=$(tr ' ' '\n' <<<"$options" | grep -cE '^root=[^[:space:]]+' || true)
    [ "$root_count" -eq 1 ] || return 1
    ! tr ' ' '\n' <<<"$options" | grep -qE '^rootflags=.*(subvol=|subvolid=)'
}
check_boot_tokens /etc/kernel/cmdline || fail "future-kernel command line is unsafe"
bls_count=0
for entry in /boot/loader/entries/*.conf; do
    [ -e "$entry" ] || continue
    check_boot_tokens "$entry" || fail "unsafe BLS entry: $entry"
    bls_count=$((bls_count + 1))
done
[ "$bls_count" -gt 0 ] || fail "no BLS entries found"

root_id=$(btrfs inspect-internal rootid /) || \
    fail "cannot resolve the running Btrfs root ID"
default_id=$(btrfs subvolume get-default / | awk '$1 == "ID" {print $2}') || \
    fail "cannot resolve the Btrfs default ID"
[[ $root_id =~ ^[1-9][0-9]*$ && $default_id =~ ^[1-9][0-9]*$ ]] || \
    fail "running/default Btrfs root identity is invalid"

read_status() {
    status=$(status_read) || fail "status helper failed"
    [[ $status =~ ^count=([0-9]+)[[:space:]]boot=(ready|reboot-required|degraded)[[:space:]]default=(none|[0-9]+)[[:space:]]active=(none|[0-9]+)[[:space:]]retention=(unknown|ok|protected|clock-guard|degraded)$ ]] || \
        fail "status helper schema invalid: $status"
    status_boot=${BASH_REMATCH[2]}
    status_default=${BASH_REMATCH[3]}
    status_active=${BASH_REMATCH[4]}
}

snapshot_record_matches() {
    local number=$1 description=$2 expected_default=$3 expected_active=$4
    snapper -c root --jsonout --iso list --disable-used-space \
        | python3 -I -c '
import json
import sys

number = int(sys.argv[1])
description = sys.argv[2]
expected_default = sys.argv[3]
expected_active = sys.argv[4]
obj = json.load(sys.stdin)
rows = obj.get("root")
if not isinstance(rows, list):
    raise SystemExit(1)
matches = []
seen = set()
for row in rows:
    if not isinstance(row, dict) or type(row.get("number")) is not int:
        raise SystemExit(1)
    current = row["number"]
    if current < 0 or current in seen:
        raise SystemExit(1)
    seen.add(current)
    if type(row.get("default")) is not bool or type(row.get("active")) is not bool:
        raise SystemExit(1)
    if current == number:
        matches.append(row)
if len(matches) != 1:
    raise SystemExit(1)
row = matches[0]
if row.get("description") != description:
    raise SystemExit(1)
for expected, key in ((expected_default, "default"), (expected_active, "active")):
    if expected != "any" and row[key] != (expected == "true"):
        raise SystemExit(1)
' "$number" "$description" "$expected_default" "$expected_active"
}

snapshot_description_exists() {
    local description=$1
    snapper -c root --jsonout --iso list --disable-used-space \
        | python3 -I -c '
import json
import sys

description = sys.argv[1]
obj = json.load(sys.stdin)
rows = obj.get("root")
if not isinstance(rows, list):
    raise SystemExit(1)
seen = set()
found = 0
for row in rows:
    if not isinstance(row, dict) or type(row.get("number")) is not int:
        raise SystemExit(1)
    number = row["number"]
    if number < 0 or number in seen:
        raise SystemExit(1)
    seen.add(number)
    if type(row.get("default")) is not bool or type(row.get("active")) is not bool:
        raise SystemExit(1)
    if number > 0 and row.get("description") == description:
        found += 1
raise SystemExit(0 if found >= 1 else 1)
' "$description"
}

require_state_file() {
    local path=$1
    [[ -f $path && ! -L $path \
       && $(stat -c '%u:%g:%a:%h:%F' -- "$path") == \
            '0:0:600:1:regular file' ]] \
        && matchpathcon -V "$path" >/dev/null \
        || fail "persistent rollback evidence is unsafe: $path"
}

load_gate_state() {
    local parsed
    require_state_file "$GATE_STATE"
    parsed=$(python3 -I - "$GATE_STATE" <<'PARSE_GATE_STATE_PYEOF'
import datetime
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
if not text.endswith("\n") or "\r" in text:
    raise SystemExit(1)
lines = text.splitlines()
if not lines or not lines[0].startswith("STATUS="):
    raise SystemExit(1)
status = lines[0][7:]
positive = re.compile(r"[1-9][0-9]*").fullmatch
stamp = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
).fullmatch
if status == "prepared":
    keys = ("STATUS", "TARGET", "STAGED_FROM_ROOT_ID", "PREPARED_AT")
elif status == "staged":
    keys = (
        "STATUS", "TARGET", "SELECTED_SNAPSHOT", "SELECTED_ROOT_ID",
        "STAGED_FROM_ROOT_ID", "STAGED_AT",
    )
elif status == "passed":
    keys = (
        "STATUS", "TARGET", "SELECTED_SNAPSHOT", "SELECTED_ROOT_ID",
        "STAGED_FROM_ROOT_ID", "VERIFIED_AT",
    )
else:
    raise SystemExit(1)
if len(lines) != len(keys):
    raise SystemExit(1)
values = {}
for line, key in zip(lines, keys, strict=True):
    prefix = key + "="
    if not line.startswith(prefix):
        raise SystemExit(1)
    values[key] = line[len(prefix):]
for key in ("TARGET", "STAGED_FROM_ROOT_ID"):
    if not positive(values[key]):
        raise SystemExit(1)
if status != "prepared":
    for key in ("SELECTED_SNAPSHOT", "SELECTED_ROOT_ID"):
        if not positive(values[key]):
            raise SystemExit(1)
time_key = {
    "prepared": "PREPARED_AT",
    "staged": "STAGED_AT",
    "passed": "VERIFIED_AT",
}[status]
value = values[time_key]
if not stamp(value):
    raise SystemExit(1)
try:
    parsed = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
except ValueError:
    raise SystemExit(1)
if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
    raise SystemExit(1)
# A STATUS=prepared record legitimately carries two empty SELECTED_* fields, so
# the separator must NOT be an IFS whitespace character: bash collapses runs of
# whitespace delimiters and drops empty fields even when IFS names only the tab.
# With a tab, `prepared\t7\t\t\t256\t<stamp>` reads back as four fields, shifting
# STAGED_FROM_ROOT_ID into gate_selected and silently emptying gate_staged_from.
# Every field here is a positive integer, one of three literal phases, or an
# ISO stamp, so the pipe cannot occur inside one -- and the guard below refuses
# the record if it ever does.
record = (
    status,
    values["TARGET"],
    values.get("SELECTED_SNAPSHOT", ""),
    values.get("SELECTED_ROOT_ID", ""),
    values["STAGED_FROM_ROOT_ID"],
    value,
)
if any("|" in field or "\n" in field for field in record):
    raise SystemExit(1)
print(*record, sep="|")
PARSE_GATE_STATE_PYEOF
    ) || fail "rollback gate evidence schema is invalid"
    IFS='|' read -r gate_phase gate_target gate_selected \
        gate_selected_id gate_staged_from gate_stamp gate_extra <<< "$parsed"
    # gate_selected/gate_selected_id are empty by design for `prepared`; every
    # other field is mandatory in all three phases. A seventh field means the
    # producer and this consumer disagree about the record shape.
    [[ -n $gate_phase && -n $gate_target && -n $gate_staged_from \
       && -n $gate_stamp && -z ${gate_extra:-} ]] || \
        fail "rollback gate evidence record framing is invalid"
}

publish_gate_state() {
    local expected_phase=$1 payload=$2
    STATE_CANDIDATE=$(mktemp "$STATE_DIR/.runtime-gate.XXXXXX") || \
        fail "cannot create rollback evidence candidate"
    printf '%s' "$payload" > "$STATE_CANDIDATE" || \
        fail "cannot write rollback evidence candidate"
    chown root:root "$STATE_CANDIDATE" || \
        fail "cannot own rollback evidence candidate"
    chmod 0600 "$STATE_CANDIDATE" || \
        fail "cannot protect rollback evidence candidate"
    matchpathcon -V "$STATE_CANDIDATE" >/dev/null || \
        fail "rollback evidence candidate SELinux label differs"
    sync -- "$STATE_CANDIDATE" || fail "cannot sync rollback evidence candidate"
    mv -fT -- "$STATE_CANDIDATE" "$GATE_STATE" || \
        fail "cannot publish rollback evidence"
    STATE_CANDIDATE=
    sync -- "$GATE_STATE" "$STATE_DIR" || \
        fail "cannot durably publish rollback evidence"
    load_gate_state
    [[ $gate_phase == "$expected_phase" ]] || \
        fail "published rollback evidence has the wrong phase"
}

load_ready_record() {
    local parsed
    require_state_file "$READY_STATE"
    parsed=$(python3 -I - "$READY_STATE" <<'PARSE_READY_PYEOF'
import datetime
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
if not text.endswith("\n") or "\r" in text:
    raise SystemExit(1)
lines = text.splitlines()
keys = ("TARGET", "DEFAULT_SNAPSHOT", "VERIFIED_AT")
if len(lines) != len(keys):
    raise SystemExit(1)
values = {}
for line, key in zip(lines, keys, strict=True):
    prefix = key + "="
    if not line.startswith(prefix):
        raise SystemExit(1)
    values[key] = line[len(prefix):]
if not re.fullmatch(r"[1-9][0-9]*", values["TARGET"]) \
        or not re.fullmatch(r"[1-9][0-9]*", values["DEFAULT_SNAPSHOT"]) \
        or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            values["VERIFIED_AT"],
        ):
    raise SystemExit(1)
try:
    stamp = datetime.datetime.strptime(values["VERIFIED_AT"], "%Y-%m-%dT%H:%M:%SZ")
except ValueError:
    raise SystemExit(1)
if stamp.strftime("%Y-%m-%dT%H:%M:%SZ") != values["VERIFIED_AT"]:
    raise SystemExit(1)
print(values["TARGET"], values["DEFAULT_SNAPSHOT"], sep="\t")
PARSE_READY_PYEOF
    ) || fail "ready rollback evidence schema is invalid"
    IFS=$'\t' read -r ready_target ready_selected <<< "$parsed"
}

load_pending_record() {
    local parsed
    require_state_file "$PENDING_STATE"
    parsed=$(python3 -I - "$PENDING_STATE" <<'PARSE_PENDING_PYEOF'
import datetime
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
if not text.endswith("\n") or "\r" in text:
    raise SystemExit(1)
lines = text.splitlines()
keys = ("TARGET", "ORIGINAL_DEFAULT_ID", "REQUESTED_AT")
if len(lines) != len(keys):
    raise SystemExit(1)
values = {}
for line, key in zip(lines, keys, strict=True):
    prefix = key + "="
    if not line.startswith(prefix):
        raise SystemExit(1)
    values[key] = line[len(prefix):]
if not re.fullmatch(r"[1-9][0-9]*", values["TARGET"]) \
        or not re.fullmatch(r"[1-9][0-9]*", values["ORIGINAL_DEFAULT_ID"]) \
        or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            values["REQUESTED_AT"],
        ):
    raise SystemExit(1)
try:
    stamp = datetime.datetime.strptime(values["REQUESTED_AT"], "%Y-%m-%dT%H:%M:%SZ")
except ValueError:
    raise SystemExit(1)
if stamp.strftime("%Y-%m-%dT%H:%M:%SZ") != values["REQUESTED_AT"]:
    raise SystemExit(1)
print(values["TARGET"], values["ORIGINAL_DEFAULT_ID"], sep="\t")
PARSE_PENDING_PYEOF
    ) || fail "pending rollback evidence schema is invalid"
    IFS=$'\t' read -r pending_target pending_original_id <<< "$parsed"
}

PROBE_EXPECTED="$TEST_TMP/runtime-probe.expected"
printf '%s\n' 'this file must disappear after the tested rollback' > \
    "$PROBE_EXPECTED"
validate_probe() {
    [[ -f $PROBE && ! -L $PROBE \
       && $(stat -c '%u:%g:%a:%h:%F' -- "$PROBE") == \
            '0:0:600:1:regular file' ]] \
        && matchpathcon -V "$PROBE" >/dev/null \
        && cmp -s -- "$PROBE_EXPECTED" "$PROBE" \
        || fail "rollback probe bytes, metadata or SELinux label differ"
}
create_probe() {
    [[ ! -e $PROBE && ! -L $PROBE ]] || \
        fail "rollback probe path already exists"
    if ! python3 -I - "$PROBE" <<'CREATE_ROLLBACK_PROBE_PYEOF'
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
fd = None
try:
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    payload = memoryview(
        b"this file must disappear after the tested rollback\n"
    )
    while payload:
        payload = payload[os.write(fd, payload):]
    os.fsync(fd)
except BaseException:
    if fd is not None:
        os.close(fd)
        fd = None
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    raise
finally:
    if fd is not None:
        os.close(fd)
parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
CREATE_ROLLBACK_PROBE_PYEOF
    then
        fail "cannot create the exclusive rollback probe"
    fi
    validate_probe
}

read_status
snapshot_description_exists baseline-install || \
    fail "baseline-install snapshot is absent from machine-readable state"

[ "$(stat -c '%U:%G:%a' /etc/sudoers.d/noid-snapper-status)" = root:root:440 ] || \
    fail "Snapper status sudoers metadata drifted"
[ "$(grep -cEv '^[[:space:]]*(#|$)' /etc/sudoers.d/noid-snapper-status)" -eq 2 ] || \
    fail "Snapper status sudoers rule count drifted"
grep -qxF 'Cmnd_Alias NOID_SNAPPER_STATUS = /usr/libexec/noid-snapper-status ""' \
    /etc/sudoers.d/noid-snapper-status || fail "argument-free sudo command alias drifted"
grep -qxF '%wheel ALL=(root) NOPASSWD: NOID_SNAPPER_STATUS' \
    /etc/sudoers.d/noid-snapper-status || fail "wheel status rule drifted"
visudo -cf /etc/sudoers.d/noid-snapper-status >/dev/null || \
    fail "Snapper status sudoers file is invalid"

passwd_db=$(getent passwd) || fail "cannot enumerate candidate user accounts"
mapfile -t desktop_users < <(
    awk -F: \
        '$3 >= 1000 && $3 < 65534 && $7 !~ /(nologin|false)$/ {print $1}' \
        <<< "$passwd_db"
)
[ "${#desktop_users[@]}" -gt 0 ] || fail "no installed desktop user found"
wheel_users=0
for desktop_user in "${desktop_users[@]}"; do
    if timeout 10 runuser -u "$desktop_user" -- \
            snapper -c root list >/dev/null 2>&1; then
        fail "$desktop_user received arbitrary Snapper list access"
    fi
    desktop_groups=$(id -nG "$desktop_user") || \
        fail "cannot resolve groups for desktop user $desktop_user"
    if [[ " $desktop_groups " == *' wheel '* ]]; then
        wheel_users=$((wheel_users + 1))
        user_status=$(timeout 10 runuser -u "$desktop_user" -- \
            sudo -n /usr/libexec/noid-snapper-status) || \
            fail "fixed status boundary failed for wheel user $desktop_user"
        [ "$user_status" = "$status" ] || \
            fail "sanitized status differs for wheel user $desktop_user"
        if timeout 10 runuser -u "$desktop_user" -- \
                sudo -n /usr/libexec/noid-snapper-status unexpected \
                >/dev/null 2>&1; then
            fail "sudoers accepted status-helper arguments for $desktop_user"
        fi
    elif timeout 10 runuser -u "$desktop_user" -- \
            sudo -n /usr/libexec/noid-snapper-status >/dev/null 2>&1; then
        fail "non-wheel user $desktop_user crossed the fixed status boundary"
    fi
done
[ "$wheel_users" -gt 0 ] || fail "no installed wheel desktop user found"

PENDING_STATE=$STATE_DIR/rollback.pending
READY_STATE=$STATE_DIR/rollback.ready

if [[ $PASS_ID == fresh-install ]]; then
    if [[ -e $GATE_STATE || -L $GATE_STATE ]]; then
        load_gate_state
    else
        gate_phase=absent
    fi
    case "$gate_phase" in
        absent)
            [[ ! -e $PROBE && ! -L $PROBE ]] || \
                fail "rollback probe already exists without gate evidence"
            [[ $root_id == "$default_id" && $status_boot == ready ]] || \
                fail "new rollback proof requires the running ready Btrfs default"
            boot_basis=$("$BOOT_GUARD") || \
                fail "terminal boot basis is unavailable; complete M21's reboot pass before Snapper fresh-install"
            case "$boot_basis" in
                basis=hostonly|basis=generic) ;;
                *) fail "central guard returned an invalid boot basis: $boot_basis" ;;
            esac
            gate_target=$(/usr/libexec/noid-snapper-create single \
                "NoID Privacy runtime rollback target") || \
                fail "cannot create disposable rollback target"
            [[ $gate_target =~ ^[1-9][0-9]*$ ]] || \
                fail "invalid rollback target number"
            snapshot_record_matches "$gate_target" \
                "NoID Privacy runtime rollback target" false false || \
                fail "disposable rollback target identity differs"
            gate_staged_from=$root_id
            prepared_at=$(date -u +%FT%TZ)
            publish_gate_state prepared \
                "STATUS=prepared
TARGET=$gate_target
STAGED_FROM_ROOT_ID=$gate_staged_from
PREPARED_AT=$prepared_at
"
            create_probe
            ;;
        prepared)
            [[ $gate_staged_from == "$root_id" ]] || \
                fail "prepared proof is not running from its recorded source root"
            snapshot_record_matches "$gate_target" \
                "NoID Privacy runtime rollback target" false false || \
                fail "prepared rollback target identity differs"
            if [[ $root_id == "$default_id" && $status_boot == ready ]]; then
                if [[ -e $PROBE || -L $PROBE ]]; then
                    validate_probe
                else
                    create_probe
                fi
            elif [[ $root_id != "$default_id" \
                    && $status_boot == reboot-required ]]; then
                validate_probe
            else
                fail "prepared rollback proof has an incoherent boot transition"
            fi
            ;;
        staged)
            [[ $gate_staged_from == "$root_id" \
               && $gate_selected_id == "$default_id" \
               && $gate_selected_id != "$root_id" \
               && $status_boot == reboot-required \
               && $status_default == "$gate_selected" ]] || \
                fail "staged rollback proof no longer matches the pre-reboot transition"
            validate_probe
            load_ready_record
            [[ $ready_target == "$gate_target" \
               && $ready_selected == "$gate_selected" ]] || \
                fail "staged gate and ready rollback evidence differ"
            snapshot_record_matches "$gate_selected" \
                "NoID Privacy rollback to snapshot $gate_target" true false || \
                fail "staged rollback snapshot identity differs"
            if "$BOOT_GUARD" >/dev/null 2>&1; then
                fail "central guard allowed a boot mutation before the selected root rebooted"
            fi
            echo "PASS  $TEST_NAME [$PASS_ID]: rollback target #$gate_selected already durably staged; reboot now"
            exit 0
            ;;
        passed)
            fail "rollback lifecycle already passed in this disposable candidate"
            ;;
        *) fail "internal rollback gate phase is invalid" ;;
    esac

    if [[ -e $PENDING_STATE || -L $PENDING_STATE ]]; then
        load_pending_record
        [[ $pending_target == "$gate_target" \
           && $pending_original_id == "$gate_staged_from" ]] || \
            fail "pending rollback does not belong to this runtime proof"
        /usr/libexec/noid-snapper-rollback --resume || \
            fail "checked rollback resume failed; persistent pending evidence remains"
    elif [[ $status_boot == ready && $root_id == "$default_id" ]]; then
        /usr/libexec/noid-snapper-rollback "$gate_target" || \
            fail "checked rollback failed; persistent pending evidence remains"
    elif [[ $status_boot != reboot-required ]]; then
        fail "prepared rollback cannot be resumed from the current boot state"
    fi

    read_status
    [[ $status_boot == reboot-required \
       && $status_default =~ ^[1-9][0-9]*$ ]] || \
        fail "published rollback is not the explicit reboot-required state: $status"
    gate_selected=$status_default
    load_ready_record
    [[ $ready_target == "$gate_target" \
       && $ready_selected == "$gate_selected" ]] || \
        fail "ready rollback evidence does not bind the runtime target/default"
    [[ ! -e $PENDING_STATE && ! -L $PENDING_STATE ]] || \
        fail "successful rollback retained pending evidence"
    gate_selected_id=$(btrfs inspect-internal rootid \
        "/.snapshots/$gate_selected/snapshot") || \
        fail "cannot resolve selected rollback root ID"
    [[ $gate_selected_id =~ ^[1-9][0-9]*$ \
       && $gate_selected_id != "$root_id" ]] || \
        fail "rollback did not select a distinct valid root"
    default_id=$(btrfs subvolume get-default / | awk '$1 == "ID" {print $2}') || \
        fail "cannot re-read the Btrfs default"
    [[ $default_id == "$gate_selected_id" ]] || \
        fail "selected rollback snapshot is not the Btrfs default"
    snapshot_record_matches "$gate_selected" \
        "NoID Privacy rollback to snapshot $gate_target" true false || \
        fail "selected rollback snapshot identity differs"
    validate_probe
    if "$BOOT_GUARD" >/dev/null 2>&1; then
        fail "central guard allowed a boot mutation before the selected root rebooted"
    fi
    staged_at=$(date -u +%FT%TZ)
    publish_gate_state staged \
        "STATUS=staged
TARGET=$gate_target
SELECTED_SNAPSHOT=$gate_selected
SELECTED_ROOT_ID=$gate_selected_id
STAGED_FROM_ROOT_ID=$gate_staged_from
STAGED_AT=$staged_at
"
    echo "PASS  $TEST_NAME [$PASS_ID]: rollback target #$gate_selected selected and durably staged; reboot now"
    exit 0
fi

[[ -e $GATE_STATE || -L $GATE_STATE ]] || \
    fail "fresh-install rollback evidence is missing"
load_gate_state
case "$gate_phase" in
    prepared)
        # If power was lost after Snapper published its ready record but before
        # this gate published `staged`, reconstruct only from the exact stable
        # helper evidence and the root that actually booted. A harder cut can
        # leave `pending` after the new default was published but before
        # `ready`; only that already-booted default may finish the checked
        # helper transaction in the reboot pass.
        if [[ -e $PENDING_STATE || -L $PENDING_STATE ]]; then
            load_pending_record
            [[ $pending_target == "$gate_target" \
               && $pending_original_id == "$gate_staged_from" ]] || \
                fail "pending rollback does not belong to the prepared runtime proof"
            [[ $root_id == "$default_id" \
               && $root_id != "$gate_staged_from" ]] || \
                fail "pending rollback must be resumed by fresh-install before its selected-root reboot"
            /usr/libexec/noid-snapper-rollback --resume || \
                fail "checked rollback resume failed after the selected root booted"
        fi
        load_ready_record
        [[ $ready_target == "$gate_target" ]] || \
            fail "prepared gate and ready rollback target differ"
        gate_selected=$ready_selected
        gate_selected_id=$(btrfs inspect-internal rootid \
            "/.snapshots/$gate_selected/snapshot") || \
            fail "cannot reconstruct selected rollback root ID"
        [[ $root_id == "$gate_selected_id" \
           && $default_id == "$gate_selected_id" ]] || \
            fail "prepared evidence did not boot its verified rollback default"
        reconstructed_at=$(date -u +%FT%TZ)
        publish_gate_state staged \
            "STATUS=staged
TARGET=$gate_target
SELECTED_SNAPSHOT=$gate_selected
SELECTED_ROOT_ID=$gate_selected_id
STAGED_FROM_ROOT_ID=$gate_staged_from
STAGED_AT=$reconstructed_at
"
        ;;
    staged|passed) ;;
    *) fail "reboot pass requires prepared, staged or passed evidence" ;;
esac

[[ $root_id == "$gate_selected_id" \
   && $default_id == "$gate_selected_id" ]] || \
    fail "reboot did not enter the selected Btrfs default"
[[ ! -e $PROBE && ! -L $PROBE ]] || \
    fail "post-snapshot probe survived rollback"
read_status
[[ $status_boot == ready \
   && $status_default == "$gate_selected" \
   && $status_active == "$gate_selected" ]] || \
    fail "selected root is not active/default/ready after reboot: $status"
snapshot_record_matches "$gate_selected" \
    "NoID Privacy rollback to snapshot $gate_target" true true || \
    fail "selected Snapper JSON identity drifted"
load_ready_record
[[ $ready_target == "$gate_target" \
   && $ready_selected == "$gate_selected" ]] || \
    fail "ready rollback evidence differs after reboot"
[[ ! -e $PENDING_STATE && ! -L $PENDING_STATE ]] || \
    fail "rollback reboot retained pending evidence"
boot_basis=$("$BOOT_GUARD") || \
    fail "terminal boot basis is unavailable after rollback reboot"
case "$boot_basis" in
    basis=hostonly|basis=generic) ;;
    *) fail "central guard returned an invalid post-rollback basis: $boot_basis" ;;
esac

if [[ $gate_phase != passed ]]; then
    verified_at=$(date -u +%FT%TZ)
    publish_gate_state passed \
        "STATUS=passed
TARGET=$gate_target
SELECTED_SNAPSHOT=$gate_selected
SELECTED_ROOT_ID=$gate_selected_id
STAGED_FROM_ROOT_ID=$gate_staged_from
VERIFIED_AT=$verified_at
"
fi

echo "PASS  $TEST_NAME [$PASS_ID]: selected root #$gate_selected booted active/default; post-snapshot probe is absent"
