#!/usr/bin/env bash
# Candidate-only M27 behavior gate. Attach one 768-MiB removable QEMU USB disk
# with four exact 128-MiB partitions (NOID_VFAT, NOID_EXFAT, NOID_NTFS,
# NOID_EXT4), one 128-MiB fixed QEMU USB ext4 disk (NOID_FIXED), and one
# 128-MiB native QEMU SD ext4 disk (NOID_SD) in every lifecycle pass.
#   sudo bash tests/pre-ship/20-hardware-tuning-runtime.sh live
#   sudo bash tests/pre-ship/20-hardware-tuning-runtime.sh fresh-install
#   sudo bash tests/pre-ship/20-hardware-tuning-runtime.sh reboot
set -euo pipefail
export LC_ALL=C
export PATH=/usr/local/bin:/usr/sbin:/usr/bin
export BASH_ENV=/dev/null
export ENV=/dev/null
IFS=$' \t\n'
umask 077
unset CDPATH GLOBIGNORE PYTHONHOME PYTHONPATH TMPDIR

TEST_NAME=20-hardware-tuning-runtime

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
        awk blkid blockdev busctl cat cmp dirname ethtool findmnt \
        getenforce grep id lsblk matchpathcon mktemp python3 readlink rm rpm sed \
        sha256sum sleep stat swapon systemctl systemd-detect-virt tuned-adm \
        udevadm udisksctl uname unlink; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing command: $tool"
done

SCRIPT_PATH=$(readlink -e -- "$0") || fail "cannot resolve gate path"
REPO_ROOT=$(cd "$(dirname "$SCRIPT_PATH")/../.." && pwd -P) || \
    fail "cannot resolve repository root"
M27_REPO="$REPO_ROOT/kickstart/snippets/27-hardware-tuning.ks"
[[ -f $M27_REPO && ! -L $M27_REPO && -s $M27_REPO \
   && $(readlink -e -- "$M27_REPO") == "$M27_REPO" ]] || \
    fail "canonical M27 source is missing, empty, symlinked or non-canonical"
[[ $(getenforce) == Enforcing ]] || fail "SELinux is not enforcing"
virtualization=$(systemd-detect-virt --vm 2>/dev/null || true)
case "$virtualization" in
    kvm|qemu) ;;
    *) fail "release storage probes require the documented disposable QEMU/KVM VM" ;;
esac

TEST_TMP=$(mktemp -d /tmp/noid-hardware-runtime.XXXXXXXX) || \
    fail "cannot create private runtime workspace"
ACTIVE_DEV=
ACTIVE_PROBE=
ACTIVE_MOUNTED=0
cleanup_fixture_state() {
    local cleanup_output
    if [[ -n $ACTIVE_PROBE && -f $ACTIVE_PROBE && ! -L $ACTIVE_PROBE ]]; then
        unlink -- "$ACTIVE_PROBE" 2>/dev/null || true
    fi
    if [[ $ACTIVE_MOUNTED -eq 1 && -n $ACTIVE_DEV ]] \
            && findmnt -rn -S "$ACTIVE_DEV" >/dev/null 2>&1; then
        cleanup_output=$(udisksctl unmount --block-device "$ACTIVE_DEV" \
            --no-user-interaction 2>&1) || \
            echo "  cleanup warning: $cleanup_output" >&2
    fi
    ACTIVE_DEV=
    ACTIVE_PROBE=
    ACTIVE_MOUNTED=0
}
cleanup() {
    cleanup_fixture_state
    rm -rf -- "$TEST_TMP"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if ! python3 -I - "$M27_REPO" "$TEST_TMP" <<'EXTRACT_M27_PYEOF'
import pathlib
import re
import sys

source_path, output_path = map(pathlib.Path, sys.argv[1:])
source = source_path.read_text(encoding="utf-8")
payloads = (
    ("WOL_LINK_EOF", "/etc/systemd/network/10-noid-no-wol.link",
     "10-noid-no-wol.link"),
    ("EARLYOOM_EOF", "/etc/default/earlyoom", "earlyoom"),
    ("NOID_TUNED_BALANCED_EOF",
     "/etc/tuned/profiles/noid-balanced/tuned.conf",
     "noid-balanced.conf"),
    ("NOID_TUNED_BATTERY_EOF",
     "/etc/tuned/profiles/noid-balanced-battery/tuned.conf",
     "noid-balanced-battery.conf"),
    ("NOID_TUNED_PPD_EOF", "/etc/tuned/ppd.conf", "ppd.conf"),
    ("NOID_TUNED_RECOMMEND_EOF", "/etc/tuned/recommend.conf",
     "recommend.conf"),
    ("EXTERNAL_STORAGE_EOF",
     "/etc/udev/rules.d/99-noid-external-storage-mount.rules",
     "99-noid-external-storage-mount.rules"),
)
for marker, target, name in payloads:
    pattern = re.compile(
        rf"^cat > {re.escape(target)} <<'{re.escape(marker)}'\n"
        rf"(.*?)^{re.escape(marker)}$",
        re.MULTILINE | re.DOTALL,
    )
    matches = pattern.findall(source)
    assert len(matches) == 1, (marker, len(matches))
    (output_path / name).write_text(matches[0], encoding="utf-8")
EXTRACT_M27_PYEOF
then
    fail "cannot extract unique canonical M27 payloads"
fi

require_root_file() {
    local path=$1 mode=$2 canonical metadata
    [[ -f $path && ! -L $path && -s $path ]] || \
        fail "missing, empty, non-regular or symlinked: $path"
    canonical=$(readlink -e -- "$path") || \
        fail "cannot canonicalize root payload: $path"
    [[ $canonical == "$path" ]] || fail "root payload path is non-canonical: $path"
    metadata=$(stat -c '%u:%g:%a:%h' -- "$path") || \
        fail "cannot inspect root payload: $path"
    [[ $metadata == "0:0:$mode:1" ]] || \
        fail "unsafe owner/mode/hardlink count: $path ($metadata)"
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
    # Fedora's kernel packages still carry their payload under the pre-merge
    # /lib prefix while the mounted file resolves through /usr/lib, so the
    # header file list and the live path spell the same file differently.
    # Accept exactly those two spellings and nothing else.
    local alt_path=$path
    case "$path" in
        /usr/lib/*) alt_path=${path#/usr} ;;
        /lib/*) alt_path=/usr$path ;;
    esac
    digest=$(rpm -qf --qf '[%{FILENAMES}|%{FILEDIGESTS}\n]' "$path" | \
        awk -F'|' -v path="$path" -v alt="$alt_path" '
            $1 == path || $1 == alt { digest=$2; count++ }
            END {
                if (count != 1 || digest !~ /^[0-9a-f]{64}$/) exit 1
                print digest
            }
        ') || fail "cannot resolve exact RPM digest: $path"
    actual=$(sha256sum -- "$path" | awk '{ print $1 }') || \
        fail "cannot hash RPM payload: $path"
    [[ $actual == "$digest" ]] || fail "RPM payload bytes differ: $path"
}

require_equal() {
    cmp -s -- "$1" "$2" || fail "byte mismatch: $1 != $2"
}

EXTERNAL_STORAGE_RULE=/etc/udev/rules.d/99-noid-external-storage-mount.rules
USB_SYNC_LEGACY_RULE=/etc/udev/rules.d/99-noid-usb-sync-mount.rules
USB_CACHE_LEGACY_RULE=/etc/udev/rules.d/99-noid-usb-write-through.rules
WOL_LINK=/etc/systemd/network/10-noid-no-wol.link
LEGACY_EEE_LINK=/etc/systemd/network/10-noid-no-eee.link
FEDORA_VENDOR_LINK=/usr/lib/systemd/network/99-default.link
EARLYOOM_CONFIG=/etc/default/earlyoom
IOSCHED_VENDOR=/usr/lib/udev/rules.d/60-block-scheduler.rules
ZRAM_VENDOR=/usr/lib/systemd/zram-generator.conf
TUNED_BALANCED=/etc/tuned/profiles/noid-balanced/tuned.conf
TUNED_BATTERY=/etc/tuned/profiles/noid-balanced-battery/tuned.conf
TUNED_PPD=/etc/tuned/ppd.conf
TUNED_RECOMMEND=/etc/tuned/recommend.conf
TUNED_VENDOR_BALANCED=/usr/lib/tuned/profiles/balanced/tuned.conf
TUNED_VENDOR_BATTERY=/usr/lib/tuned/profiles/balanced-battery/tuned.conf
THERMALD_VENDOR_UNIT=/usr/lib/systemd/system/thermald.service
for specification in \
        "$EXTERNAL_STORAGE_RULE|$TEST_TMP/99-noid-external-storage-mount.rules" \
        "$WOL_LINK|$TEST_TMP/10-noid-no-wol.link" \
        "$EARLYOOM_CONFIG|$TEST_TMP/earlyoom" \
        "$TUNED_BALANCED|$TEST_TMP/noid-balanced.conf" \
        "$TUNED_BATTERY|$TEST_TMP/noid-balanced-battery.conf" \
        "$TUNED_PPD|$TEST_TMP/ppd.conf" \
        "$TUNED_RECOMMEND|$TEST_TMP/recommend.conf"; do
    IFS='|' read -r installed canonical <<< "$specification"
    require_root_file "$installed" 644
    require_equal "$canonical" "$installed"
done
require_rpm_file "$FEDORA_VENDOR_LINK" systemd-udev 644
require_rpm_file "$IOSCHED_VENDOR" systemd-udev 644
require_rpm_file "$ZRAM_VENDOR" zram-generator-defaults 644
require_rpm_file "$TUNED_VENDOR_BALANCED" tuned 644
require_rpm_file "$TUNED_VENDOR_BATTERY" tuned 644
require_rpm_file "$THERMALD_VENDOR_UNIT" thermald 644
udevadm verify --no-style "$EXTERNAL_STORAGE_RULE" >/dev/null || \
    fail "installed udev rules fail native verification"
[[ ! -e $USB_SYNC_LEGACY_RULE && ! -L $USB_SYNC_LEGACY_RULE ]] || \
    fail "retired blanket-sync USB rule exists"
[[ ! -e $USB_CACHE_LEGACY_RULE && ! -L $USB_CACHE_LEGACY_RULE ]] || \
    fail "unsafe legacy USB cache-view rule exists"
[[ ! -e $LEGACY_EEE_LINK && ! -L $LEGACY_EEE_LINK ]] || \
    fail "retired global EEE override exists"
grep -Fqx 'ENV{ID_FS_USAGE}=="filesystem", SUBSYSTEMS=="usb", ENV{UDISKS_MOUNT_OPTIONS_DEFAULTS}="noexec"' \
    "$EXTERNAL_STORAGE_RULE" || fail "installed UDisks USB noexec rule is incomplete"
grep -Fqx 'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_DRIVE_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_DEFAULTS}="noexec"' \
    "$EXTERNAL_STORAGE_RULE" || fail "installed UDisks SD-reader noexec rule is incomplete"
grep -Fqx 'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_DRIVE_MEDIA_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_DEFAULTS}="noexec"' \
    "$EXTERNAL_STORAGE_RULE" || fail "installed UDisks native-SD noexec rule is incomplete"
grep -Fqx 'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_FS_TYPE}=="ntfs", SUBSYSTEMS=="usb", ENV{UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS}="ntfs3,ntfs"' \
    "$EXTERNAL_STORAGE_RULE" || fail "installed external-NTFS driver policy is incomplete"
grep -Fqx 'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_FS_TYPE}=="ntfs", ENV{ID_DRIVE_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS}="ntfs3,ntfs"' \
    "$EXTERNAL_STORAGE_RULE" || fail "installed SD-reader NTFS driver policy is incomplete"
grep -Fqx 'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_FS_TYPE}=="ntfs", ENV{ID_DRIVE_MEDIA_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS}="ntfs3,ntfs"' \
    "$EXTERNAL_STORAGE_RULE" || fail "installed native-SD NTFS driver policy is incomplete"
! grep -q 'ID_DRIVE_FLASH_MMC' "$EXTERNAL_STORAGE_RULE" || \
    fail "installed UDisks rule misclassifies internal eMMC as removable SD"
! grep -Eq '^[^#].*UDISKS_MOUNT_OPTIONS_DEFAULTS.*sync' \
    "$EXTERNAL_STORAGE_RULE" || fail "installed UDisks rule returned blanket sync"
! grep -Eq '^[^#].*(RUN\+?=.*queue/write_cache|ATTR\{queue/write_cache\}|echo[[:space:]]+write[[:space:]]+through[[:space:]]*>)' \
    "$EXTERNAL_STORAGE_RULE" || fail "installed USB rule mutates the kernel device-cache view"
! grep -Eq '^[^#].*bdi/(max_bytes|min_bytes|strict_limit)' \
    "$EXTERNAL_STORAGE_RULE" || fail "installed USB rule contains a BDI throttle"
note "installed udev rules pass the native parser"

# Performance ownership is itself a release contract. The candidate must use
# Fedora's maintained scheduler/zram files and contain none of M27's retired
# hardware guesses in /etc.
[[ ! -e /etc/udev/rules.d/60-noid-iosched.rules \
   && ! -L /etc/udev/rules.d/60-noid-iosched.rules ]] || \
    fail "retired NoID Privacy scheduler override exists"
[[ ! -e /etc/tmpfiles.d/noid-hwp-dynamic-boost.conf \
   && ! -L /etc/tmpfiles.d/noid-hwp-dynamic-boost.conf ]] || \
    fail "retired NoID Privacy HWP dynamic-boost override exists"
[[ ! -e /etc/systemd/zram-generator.conf \
   && ! -L /etc/systemd/zram-generator.conf ]] || \
    fail "retired full-file NoID Privacy zram override exists"
[[ ! -e /etc/systemd/zram-generator.conf.d/99-noid-privacy.conf \
   && ! -L /etc/systemd/zram-generator.conf.d/99-noid-privacy.conf ]] || \
    fail "retired NoID Privacy zram drop-in exists"
rpm -q earlyoom tuned tuned-ppd thermald intel-lpmd \
    zram-generator-defaults udisks2 >/dev/null 2>&1 || \
    fail "required M27 packages are incomplete"
note "scheduler and zram policy remain Fedora/kernel owned"

# A custom .link is the first matching file and therefore replaces, rather
# than supplements, Fedora's 99-default.link for eligible Ethernet devices.
# Keep the current vendor name/MAC behavior byte-for-value equivalent so the
# WoL control cannot silently change interface identity.
link_section_value() {
    awk -F= -v wanted_section="$2" -v wanted_key="$3" '
        $0 == "[" wanted_section "]" { inside = 1; next }
        /^\[/ { inside = 0 }
        inside && $1 == wanted_key {
            sub(/^[^=]*=/, "")
            print
            exit
        }
    ' "$1"
}
for naming_key in NamePolicy AlternativeNamesPolicy MACAddressPolicy; do
    noid_value=$(link_section_value "$WOL_LINK" Link "$naming_key")
    vendor_value=$(link_section_value "$FEDORA_VENDOR_LINK" Link "$naming_key")
    [ -n "$vendor_value" ] || \
        fail "Fedora 99-default.link lacks $naming_key"
    [ "$noid_value" = "$vendor_value" ] || \
        fail "NoID Privacy WoL link changes Fedora $naming_key"
done
[ "$(link_section_value "$WOL_LINK" Match Type)" = ether ] || \
    fail "NoID Privacy WoL link has the wrong Type scope"
[ "$(link_section_value "$WOL_LINK" Match Path)" = "pci-* usb-*" ] || \
    fail "NoID Privacy WoL link has the wrong Path scope"
[ "$(link_section_value "$WOL_LINK" Link WakeOnLan)" = off ] || \
    fail "NoID Privacy WoL link does not disable every WoL mode"
! grep -q '^\[EnergyEfficientEthernet\]$' "$WOL_LINK" || \
    fail "NoID Privacy WoL link unexpectedly overrides EEE"
note "WoL link preserves Fedora's predictable-interface naming and MAC policy; EEE is vendor-owned"

# Effective .link winner plus WoL state on every actual PCI/USB Ethernet
# link. A driver-exposed WoL state must be disabled. Drivers such as virtio_net
# implement neither get_wol nor set_wol, so complete absence of WoL capability
# and state is an explicit hardware N/A. At least one eligible VM NIC must
# exist per pass.
eligible_nics=0
wol_observable=0
for net_path in /sys/class/net/*; do
    [ -e "$net_path" ] || continue
    [ "$(cat "$net_path/type" 2>/dev/null || true)" = 1 ] || continue
    nic=${net_path##*/}
    properties=$(udevadm info --query=property --path="$net_path" 2>/dev/null || true)
    # systemd.link Type= uses udev DEVTYPE before the shared ARPHRD value.
    # WLAN/WWAN are therefore distinct from Type=ether even though Linux
    # exposes the usual Wi-Fi data interface as ARPHRD_ETHER (type 1).
    case $(sed -n 's/^DEVTYPE=//p' <<<"$properties") in
        wlan|wwan) continue ;;
    esac
    if ! grep -Eq '^ID_BUS=(pci|usb)$' <<<"$properties" && \
       ! grep -Eq '^ID_PATH=(pci|usb)-' <<<"$properties"; then
        continue
    fi
    eligible_nics=$((eligible_nics + 1))
    grep -qx 'ID_NET_LINK_FILE=/etc/systemd/network/10-noid-no-wol.link' \
        <<<"$properties" || fail "$nic did not select the NoID Privacy WoL .link"
    wol_output=$(ethtool "$nic" 2>&1) || \
        fail "$nic Wake-on-LAN state is not observable: $wol_output"
    if grep -Eq '^[[:space:]]*(Supports )?Wake-on:' <<<"$wol_output"; then
        grep -Eq '^[[:space:]]*Wake-on:' <<<"$wol_output" || \
            fail "$nic exposes Wake-on-LAN capability without a current state"
        grep -Eq '^[[:space:]]*Wake-on:[[:space:]]+d[[:space:]]*$' \
            <<<"$wol_output" || fail "$nic reports Wake-on-LAN enabled"
        wol_observable=$((wol_observable + 1))
        wol_state=disabled
    else
        wol_state="unsupported (N/A)"
    fi
    note "$nic: NoID Privacy .link won; WoL=$wol_state; EEE=Fedora/driver-owned"
done
[ "$eligible_nics" -gt 0 ] || fail "no PCI/USB Ethernet fixture is present"
note "WoL policy: $eligible_nics eligible NIC(s), $wol_observable with driver-visible WoL; EEE remains vendor-owned"

# Observe every active live scheduler. There is deliberately no universal
# M27 expected value: the available/selected scheduler is driver, Fedora and
# workload policy, and exact values are retained as evidence for this machine.
storage_checked=0
for block_path in /sys/class/block/*; do
    [ -f "$block_path/queue/scheduler" ] || continue
    dev=${block_path##*/}
    case "$dev" in nvme[0-9]*n[0-9]*|vd[a-z]|sd[a-z]) ;; *) continue ;; esac
    active=$(sed -n 's/.*\[\([^]]*\)\].*/\1/p' "$block_path/queue/scheduler")
    [ -n "$active" ] || fail "$dev has no selected I/O scheduler"
    storage_checked=$((storage_checked + 1))
    note "$dev: effective vendor/kernel scheduler=$active"

done
[ "$storage_checked" -gt 0 ] || fail "no observable block-device class is present"

# Prove the supported UDisks contract on USB removable=1, USB removable=0 and
# native SD, and across VFAT/exFAT/NTFS/ext4. Exact labels, filesystem types,
# sizes, distinct UUIDs and the QEMU/KVM boundary keep this destructive gate on
# disposable release fixtures. Every filesystem starts unmounted, receives a
# real `noexec,nodev,nosuid` default mount without blanket `sync`, and proves
# direct-exec denial plus interpreter readability. VFAT must retain UDisks'
# filesystem-specific `flush`; NTFS must use the udev-scoped `ntfs3,ntfs`
# priority and actually mount as ntfs3. Every USB matrix member also proves that
# an explicit allowed `exec` request overrides the default, so noexec is not
# misrepresented as an authorization boundary. The probe uses a `.com` suffix:
# UDisks' vfat `showexec` default otherwise removes its execute bits before the
# mount-level `noexec` control can be distinguished from ordinary file mode.
#
# Each pass fsyncs a deterministic integrity marker. fresh-install verifies
# live; reboot verifies live and fresh-install before adding its own marker.
# This turns the three lifecycle passes into cold persistence checks. USB
# devices complete UDisks power-off; SD completes clean unmount. The actual
# whole-device queue/write_cache and queue/fua values are read before I/O and
# required byte-for-byte unchanged before removal.
systemctl is-active --quiet udisks2.service || fail "udisks2.service is not active"
FIXTURE_BYTES=134217728
USB_MATRIX_DISK_BYTES=805306368
FIXTURE_DEV=
declare -A fixture_uuids=()
declare -A cache_view_before=()
find_fixture() {
    local label=$1 attempt
    local -a devices=()
    FIXTURE_DEV=
    for ((attempt = 0; attempt < 5; attempt++)); do
        mapfile -t devices < <(
            blkid -o device -t "LABEL=$label" 2>/dev/null || true
        )
        if [[ ${#devices[@]} -gt 1 ]]; then
            fail "fixture label is not unique: $label"
        fi
        if [[ ${#devices[@]} -eq 1 && -b ${devices[0]} ]]; then
            FIXTURE_DEV=$(readlink -e -- "${devices[0]}") || \
                fail "cannot canonicalize fixture: $label"
            return 0
        fi
        udevadm settle
        sleep 1
    done
    return 1
}

validate_fixture_identity() {
    local label=$1 dev=$2 expected_type=$3 expected_bytes=$4
    local uuid swap_devices
    [[ $dev == /dev/* && -b $dev && ${dev##*/} =~ ^[A-Za-z0-9._+-]+$ \
       && -e /sys/class/block/${dev##*/} ]] || \
        fail "$label did not resolve to one canonical block device"
    [[ $(blockdev --getsize64 "$dev") == "$expected_bytes" ]] || \
        fail "$label has the wrong disposable-fixture size"
    [[ $(blkid -s LABEL -o value "$dev") == "$label" \
       && $(blkid -s TYPE -o value "$dev") == "$expected_type" ]] || \
        fail "$label does not have the exact $expected_type fixture identity"
    uuid=$(blkid -s UUID -o value "$dev") || \
        fail "$label has no filesystem UUID"
    [[ -n $uuid && $uuid != *[[:space:]]* \
       && -z ${fixture_uuids[$uuid]+x} ]] || \
        fail "$label has an empty, malformed or reused filesystem UUID"
    fixture_uuids[$uuid]=$label
    if findmnt -rn -S "$dev" >/dev/null; then
        fail "$label must be unmounted before the release probe"
    fi
    swap_devices=$(swapon --show=NAME --noheadings --raw) || \
        fail "cannot inspect active swap before probing $label"
    if grep -qxF "$dev" <<< "$swap_devices"; then
        fail "$label is active swap, not a disposable filesystem fixture"
    fi
}

current_cache_view() {
    local whole=$1 block=${1##*/} write_cache fua
    [[ -r /sys/class/block/$block/queue/write_cache ]] || \
        fail "$whole has no readable queue/write_cache view"
    write_cache=$(<"/sys/class/block/$block/queue/write_cache")
    [[ -n $write_cache ]] || fail "$whole returned an empty write_cache view"
    fua=unavailable
    if [[ -r /sys/class/block/$block/queue/fua ]]; then
        fua=$(<"/sys/class/block/$block/queue/fua")
        [[ $fua == 0 || $fua == 1 ]] || fail "$whole returned invalid queue/fua=$fua"
    fi
    printf '%s|%s\n' "$write_cache" "$fua"
}

remember_cache_view() {
    local whole=$1 view
    if [[ -z ${cache_view_before[$whole]+x} ]]; then
        view=$(current_cache_view "$whole")
        cache_view_before[$whole]=$view
        note "$whole: initial kernel cache view=${view%|*}; fua=${view#*|}"
    fi
}

require_cache_view_unchanged() {
    local whole=$1 after
    [[ -n ${cache_view_before[$whole]+x} ]] || \
        fail "$whole cache-view baseline is missing"
    after=$(current_cache_view "$whole")
    [[ $after == "${cache_view_before[$whole]}" ]] || \
        fail "$whole kernel cache view changed (${cache_view_before[$whole]} -> $after)"
}

verify_mount_policy() {
    local label=$1 dev=$2 expected_type=$3
    local mount_output mount_source mount_options mount_target mount_fstype
    local exec_probe expected_target properties
    local direct_rc interpreter_output unmount_output
    local -a mount_records=()

    ACTIVE_DEV=$dev
    ACTIVE_MOUNTED=1
    mount_output=$(udisksctl mount --block-device "$dev" \
        --no-user-interaction 2>&1) || fail "$label UDisks mount failed: $mount_output"
    mapfile -t mount_records < <(
        findmnt -rn -S "$dev" -o SOURCE,TARGET,FSTYPE,OPTIONS
    )
    [[ ${#mount_records[@]} -eq 1 ]] || \
        fail "$label did not produce exactly one mount"
    read -r mount_source mount_target mount_fstype mount_options <<< "${mount_records[0]}"
    [[ $(readlink -e -- "$mount_source") == "$dev" ]] || \
        fail "$label mount source differs from the fixture"
    expected_target=/run/media/root/$label
    [[ $mount_target == "$expected_target" \
       && -d $mount_target && ! -L $mount_target \
       && $(readlink -e -- "$mount_target") == "$mount_target" ]] || \
        fail "$label mount target is outside the exact UDisks release path"
    ! grep -qw sync <<<"${mount_options//,/ }" || \
        fail "$label mounted with retired blanket sync: $mount_options"
    grep -qw noexec <<<"${mount_options//,/ }" || \
        fail "$label mounted without noexec: $mount_options"
    grep -qw nodev <<<"${mount_options//,/ }" || \
        fail "$label mounted without nodev: $mount_options"
    grep -qw nosuid <<<"${mount_options//,/ }" || \
        fail "$label mounted without nosuid: $mount_options"
    if [[ $expected_type == ntfs ]]; then
        [[ $mount_fstype == ntfs3 ]] || \
            fail "$label mounted with $mount_fstype instead of ntfs3"
    else
        [[ $mount_fstype == "$expected_type" ]] || \
            fail "$label mounted as $mount_fstype instead of $expected_type"
    fi
    if [[ $expected_type == vfat ]]; then
        grep -qw flush <<<"${mount_options//,/ }" || \
            fail "$label lost UDisks' filesystem-specific vfat flush default"
    fi

    properties=$(udevadm info --query=property --name="$dev" 2>/dev/null || true)
    grep -qx 'UDISKS_MOUNT_OPTIONS_DEFAULTS=noexec' <<<"$properties" || \
        fail "$label did not receive the UDisks noexec default"
    if [[ $expected_type == ntfs ]]; then
        grep -qx 'UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS=ntfs3,ntfs' \
            <<<"$properties" || fail "$label lacks the external-NTFS driver order"
    elif grep -q '^UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS=' <<<"$properties"; then
        fail "$label received an NTFS-only UDisks property"
    fi

    python3 -I - "$mount_target" "$label" "$PASS_ID" <<'INTEGRITY_PYEOF' || \
        fail "$label lifecycle integrity verification failed"
import hashlib
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
label = sys.argv[2]
phase = sys.argv[3]
prior = {
    "live": (),
    "fresh-install": ("live",),
    "reboot": ("live", "fresh-install"),
}[phase]

def content(for_phase):
    seed = hashlib.sha256(
        f"noid-privacy-m27-integrity|{label}|{for_phase}".encode("ascii")
    ).digest()
    return (seed * ((1048576 + len(seed) - 1) // len(seed)))[:1048576]

for previous in prior:
    path = root / f".noid-integrity-{previous}.bin"
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"missing safe prior marker: {previous}")
    if hashlib.sha256(path.read_bytes()).digest() != hashlib.sha256(content(previous)).digest():
        raise SystemExit(f"prior marker hash differs: {previous}")

current = root / f".noid-integrity-{phase}.bin"
fd = os.open(
    current,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
    0o600,
)
try:
    payload = memoryview(content(phase))
    while payload:
        payload = payload[os.write(fd, payload):]
    os.fsync(fd)
finally:
    os.close(fd)
if hashlib.sha256(current.read_bytes()).digest() != hashlib.sha256(content(phase)).digest():
    raise SystemExit("current marker hash differs after fsync")
INTEGRITY_PYEOF

    # vfat's UDisks `showexec` default exposes execute bits only for DOS
    # executable suffixes. Use `.com` on every filesystem so status 126 proves
    # the mount-level noexec boundary rather than an unexecutable file mode.
    exec_probe="$mount_target/.noid-noexec-probe.com"
    [[ ! -e $exec_probe && ! -L $exec_probe ]] || \
        fail "$label contains a pre-existing probe path"
    if ! python3 -I - "$exec_probe" <<'CREATE_PROBE_PYEOF'
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
fd = None
try:
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o700,
    )
    payload = memoryview(b"#!/bin/sh\nprintf noid-interpreter-ok\n")
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
CREATE_PROBE_PYEOF
    then
        fail "$label cannot create the exclusive noexec probe"
    fi
    ACTIVE_PROBE=$exec_probe
    [[ -f $exec_probe && ! -L $exec_probe \
       && $(stat -c '%u:%g:%a:%h' -- "$exec_probe") == 0:0:700:1 ]] || \
        fail "$label noexec probe metadata is invalid"
    direct_rc=0
    "$exec_probe" >/dev/null 2>&1 || direct_rc=$?
    [[ $direct_rc -eq 126 ]] || \
        fail "$label direct execution unexpectedly succeeded or failed with wrong status: $direct_rc"
    interpreter_output=$(/bin/sh "$exec_probe") || \
        fail "$label interpreter read failed"
    [[ $interpreter_output == noid-interpreter-ok ]] || \
        fail "$label interpreter boundary returned unexpected output"
    unlink -- "$exec_probe" || fail "$label noexec probe cleanup failed"
    ACTIVE_PROBE=
    unmount_output=$(udisksctl unmount --block-device "$dev" \
        --no-user-interaction 2>&1) || fail "$label UDisks unmount failed: $unmount_output"
    ACTIVE_MOUNTED=0
    ACTIVE_DEV=
    if findmnt -rn -S "$dev" >/dev/null; then
        fail "$label remains mounted after successful UDisks unmount"
    fi
    VERIFIED_MOUNT_OPTIONS=$mount_options
}

verify_explicit_exec_override() {
    local label=$1 dev=$2 mount_output mount_source mount_target mount_options
    local exec_probe output unmount_output
    local -a mount_records=()

    ACTIVE_DEV=$dev
    ACTIVE_MOUNTED=1
    mount_output=$(udisksctl mount --block-device "$dev" --options exec \
        --no-user-interaction 2>&1) || fail "$label explicit-exec mount failed: $mount_output"
    mapfile -t mount_records < <(findmnt -rn -S "$dev" -o SOURCE,TARGET,OPTIONS)
    [[ ${#mount_records[@]} -eq 1 ]] || fail "$label explicit-exec mount is ambiguous"
    read -r mount_source mount_target mount_options <<<"${mount_records[0]}"
    [[ $(readlink -e -- "$mount_source") == "$dev" ]] || \
        fail "$label explicit-exec source differs"
    expected_target=/run/media/root/$label
    [[ $mount_target == "$expected_target" \
       && -d $mount_target && ! -L $mount_target \
       && $(readlink -e -- "$mount_target") == "$mount_target" ]] || \
        fail "$label explicit-exec target is outside the exact UDisks release path"
    # `exec` is the VFS default and findmnt commonly omits it. Absence of
    # `noexec` plus a successful real direct execution below is the behavioral
    # positive control; requiring a literal `exec` token would be false.
    ! grep -qw noexec <<<"${mount_options//,/ }" || \
        fail "$label explicit exec request retained noexec: $mount_options"
    exec_probe="$mount_target/.noid-explicit-exec-probe.com"
    python3 -I - "$exec_probe" <<'CREATE_EXEC_PROBE_PYEOF' || \
        fail "$label cannot create explicit-exec probe"
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
try:
    payload = memoryview(b"#!/bin/sh\nprintf noid-explicit-exec-ok\n")
    while payload:
        payload = payload[os.write(fd, payload):]
    os.fsync(fd)
finally:
    os.close(fd)
CREATE_EXEC_PROBE_PYEOF
    ACTIVE_PROBE=$exec_probe
    [[ -f $exec_probe && ! -L $exec_probe \
       && $(stat -c '%u:%g:%a:%h' -- "$exec_probe") == 0:0:700:1 ]] || \
        fail "$label explicit-exec probe metadata is invalid"
    output=$("$exec_probe") || fail "$label explicit-exec probe did not execute"
    [[ $output == noid-explicit-exec-ok ]] || \
        fail "$label explicit-exec probe returned unexpected output"
    unlink -- "$exec_probe" || fail "$label explicit-exec probe cleanup failed"
    ACTIVE_PROBE=
    unmount_output=$(udisksctl unmount --block-device "$dev" \
        --no-user-interaction 2>&1) || fail "$label explicit-exec unmount failed: $unmount_output"
    ACTIVE_MOUNTED=0
    ACTIVE_DEV=
}

usb_matrix_whole=
for fixture in NOID_VFAT:vfat NOID_EXFAT:exfat NOID_NTFS:ntfs NOID_EXT4:ext4; do
    label=${fixture%:*}
    expected_type=${fixture#*:}
    find_fixture "$label" || fail "missing USB filesystem-matrix fixture: $label"
    dev=$FIXTURE_DEV
    validate_fixture_identity "$label" "$dev" "$expected_type" "$FIXTURE_BYTES"
    parent=$(lsblk -ndo PKNAME -- "$dev" | awk 'NF { print; exit }')
    [[ -n $parent ]] || fail "$label is not a partition of the USB matrix disk"
    whole=/dev/$parent
    if [[ -z $usb_matrix_whole ]]; then
        usb_matrix_whole=$whole
        [[ $(blockdev --getsize64 "$whole") == "$USB_MATRIX_DISK_BYTES" ]] || \
            fail "USB matrix whole disk is not the documented 768-MiB fixture"
        [[ $(blkid -s PTTYPE -o value "$whole") == gpt ]] || \
            fail "USB matrix whole disk is not GPT"
        [[ $(lsblk -ln -o TYPE -- "$whole" | grep -c '^part$') -eq 4 ]] || \
            fail "USB matrix disk does not contain exactly four partitions"
        [[ $(<"/sys/class/block/$parent/removable") == 1 ]] || \
            fail "USB matrix disk does not expose removable=1"
        whole_properties=$(udevadm info --query=property --name="$whole" 2>/dev/null || true)
        grep -qx 'ID_BUS=usb' <<<"$whole_properties" || \
            fail "USB matrix disk is not USB-backed"
        remember_cache_view "$whole"
    else
        [[ $whole == "$usb_matrix_whole" ]] || \
            fail "$label is not on the one USB matrix disk"
    fi
    properties=$(udevadm info --query=property --name="$dev" 2>/dev/null || true)
    grep -qx 'ID_BUS=usb' <<<"$properties" || fail "$label is not USB-backed"
    grep -qx 'ID_FS_USAGE=filesystem' <<<"$properties" || \
        fail "$label is not a filesystem fixture"
    verify_mount_policy "$label" "$dev" "$expected_type"
    note "$label: default UDisks mount options=$VERIFIED_MOUNT_OPTIONS"
    verify_explicit_exec_override "$label" "$dev"
done
[[ -n $usb_matrix_whole ]] || fail "USB filesystem matrix did not complete"
require_cache_view_unchanged "$usb_matrix_whole"
poweroff_output=$(udisksctl power-off --block-device "$usb_matrix_whole" \
    --no-user-interaction 2>&1) || \
    fail "USB matrix UDisks power-off failed: $poweroff_output"

find_fixture NOID_FIXED || fail "missing fixed USB fixture label=NOID_FIXED"
fixed_dev=$FIXTURE_DEV
validate_fixture_identity NOID_FIXED "$fixed_dev" ext4 "$FIXTURE_BYTES"
[[ -z $(lsblk -ndo PKNAME -- "$fixed_dev" | awk 'NF { print; exit }') ]] || \
    fail "NOID_FIXED must be a whole-device filesystem"
fixed_block=${fixed_dev##*/}
[[ $(<"/sys/class/block/$fixed_block/removable") == 0 ]] || \
    fail "NOID_FIXED does not expose removable=0"
fixed_properties=$(udevadm info --query=property --name="$fixed_dev" 2>/dev/null || true)
grep -qx 'ID_BUS=usb' <<<"$fixed_properties" || fail "NOID_FIXED is not USB-backed"
remember_cache_view "$fixed_dev"
verify_mount_policy NOID_FIXED "$fixed_dev" ext4
note "NOID_FIXED: USB removable=0; UDisks mount options=$VERIFIED_MOUNT_OPTIONS"
require_cache_view_unchanged "$fixed_dev"
poweroff_output=$(udisksctl power-off --block-device "$fixed_dev" \
    --no-user-interaction 2>&1) || fail "NOID_FIXED UDisks power-off failed: $poweroff_output"

find_fixture NOID_SD || \
    fail "missing preformatted native SD fixture label=NOID_SD after udev settle"
sd_dev=$FIXTURE_DEV
validate_fixture_identity NOID_SD "$sd_dev" ext4 "$FIXTURE_BYTES"
sd_block=${sd_dev##*/}
sd_properties=$(udevadm info --query=property --name="$sd_dev" 2>/dev/null || true)
grep -qx 'ID_FS_USAGE=filesystem' <<<"$sd_properties" || \
    fail "NOID_SD is not a filesystem fixture"
if ! grep -qx 'ID_DRIVE_FLASH_SD=1' <<<"$sd_properties" && \
   ! grep -qx 'ID_DRIVE_MEDIA_FLASH_SD=1' <<<"$sd_properties"; then
    fail "NOID_SD lacks UDisks SD classification"
fi
! grep -qx 'ID_DRIVE_FLASH_MMC=1' <<<"$sd_properties" || \
    fail "NOID_SD is misclassified as internal MMC/eMMC"
sd_device_path=$(readlink -f "/sys/class/block/$sd_block/device") || \
    fail "NOID_SD sysfs identity cannot be resolved"
case "$sd_device_path" in
    */mmc_host/*) ;;
    *) fail "NOID_SD is not attached through the native MMC/SD host path" ;;
esac
remember_cache_view "$sd_dev"
verify_mount_policy NOID_SD "$sd_dev" ext4
require_cache_view_unchanged "$sd_dev"
note "NOID_SD: native SD classification; UDisks mount options=$VERIFIED_MOUNT_OPTIONS"

udevadm settle
note "USB/SD noexec filesystem matrix, cold hashes and cache-view invariance verified; USB safe-power-off and SD clean-unmount complete"

# earlyoom must be running with the exact tokenized argv. This detects broken
# EnvironmentFile quoting that enablement or text greps cannot see.
systemctl is-enabled --quiet earlyoom.service || fail "earlyoom is not enabled"
systemctl is-active --quiet earlyoom.service || fail "earlyoom is not active"
earlyoom_pid=$(systemctl show earlyoom.service --property=MainPID --value)
[[ $earlyoom_pid =~ ^[1-9][0-9]*$ ]] || fail "earlyoom MainPID is invalid"
python3 -I - "$earlyoom_pid" <<'EARLYOOM_ARGV_PY' || fail "earlyoom argv differs"
import pathlib
import sys

actual = pathlib.Path("/proc", sys.argv[1], "cmdline").read_bytes().split(b"\0")
if actual and actual[-1] == b"":
    actual.pop()
expected = [
    b"/usr/bin/earlyoom", b"-m", b"5", b"-s", b"5", b"-r", b"3600",
    b"--prefer",
    b"^(Web Content|Isolated Web Co|Privileged Cont|firefox|chromium|chrome)",
    b"--avoid",
    b"^(systemd|Xwayland|pipewire|gnome-shell|gdm)",
]
raise SystemExit(0 if actual == expected else 1)
EARLYOOM_ARGV_PY
note "earlyoom is active with the exact configured argv"

# Enabled links alone do not prove either power-profile daemon works.
for unit in tuned.service tuned-ppd.service; do
    systemctl is-enabled --quiet "$unit" || fail "$unit is not enabled"
    systemctl is-active --quiet "$unit" || fail "$unit is not active"
done
tuned_state=$(tuned-adm active 2>&1) || fail "tuned-adm active failed"
grep -Eq '^Current active profile: .+' <<<"$tuned_state" || \
    fail "tuned has no active profile: $tuned_state"
tuned_profile=${tuned_state#Current active profile: }
if ! tuned_verify=$(tuned-adm verify --ignore-missing 2>&1); then
    # This gate refuses to run outside QEMU/KVM, and QEMU's ich9-ahci advertises
    # no SATA link-power-management capability: every write to
    # link_power_management_policy returns an error, so the profile's alpm
    # setting can never verify here. Accept exactly that unsettable-knob class
    # -- proved per host, not assumed -- and keep every other reported
    # difference a failure.
    alpm_settable=0
    alpm_present=0
    for alpm_knob in /sys/class/scsi_host/host*/link_power_management_policy; do
        [ -e "$alpm_knob" ] || continue
        alpm_present=1
        # Write the value back unchanged: settability is the question, and the
        # probe must not move a real controller off its applied policy.
        alpm_current=$(cat -- "$alpm_knob" 2>/dev/null) || continue
        if printf '%s\n' "$alpm_current" > "$alpm_knob" 2>/dev/null; then
            alpm_settable=1
            break
        fi
    done
    # The residual check is the only thing separating "just the unsettable knob"
    # from "several real differences", so absent evidence must never read as
    # clean evidence: an unreadable log, or a log without this run's verify
    # block, fails instead of silently granting the exception.
    tuned_log=/var/log/tuned/tuned.log
    [ -f "$tuned_log" ] && [ ! -L "$tuned_log" ] && [ -r "$tuned_log" ] || \
        fail "TuneD verification failed and $tuned_log is missing, a symlink or unreadable: $tuned_verify"
    tuned_residual=$(awk '
        /verifying profile\(s\)/ { failures = "" ; seen = 1 ; next }
        /verify: failed:/ {
            if ($0 !~ /device host[0-9]+: .alpm./) { failures = failures $0 "\n" }
        }
        END {
            if (!seen) { printf "%s\n", "no verify block recorded in the TuneD log" }
            printf "%s", failures
        }
    ' "$tuned_log") || \
        fail "TuneD verification failed and its log could not be parsed: $tuned_verify"
    [ "$alpm_present" -eq 1 ] && [ "$alpm_settable" -eq 0 ] \
        && [ -z "$tuned_residual" ] || \
        fail "TuneD exposed-setting verification failed: $tuned_verify"
    note "TuneD verification: only alpm differs; the emulated AHCI rejects every link_power_management_policy write"
fi
ppd_profile=$(busctl get-property net.hadess.PowerProfiles \
    /net/hadess/PowerProfiles net.hadess.PowerProfiles ActiveProfile 2>&1) || \
    fail "cannot read tuned-ppd ActiveProfile"
case "$ppd_profile|$tuned_profile" in
    's "balanced"|noid-balanced'|'s "balanced"|noid-balanced-battery'|\
    's "power-saver"|powersave'|\
    's "performance"|throughput-performance') ;;
    *) fail "public/internal power-profile mapping differs: $ppd_profile / $tuned_profile" ;;
esac
grep -Fqx 'include=balanced' "$TUNED_BALANCED" || \
    fail "noid-balanced does not inherit Fedora Balanced"
grep -Fqx 'include=balanced-battery' "$TUNED_BATTERY" || \
    fail "noid-balanced-battery does not inherit Fedora Balanced Battery"
vendor_modules=$(
    awk '
        $0 == "[modules]" { inside = 1; next }
        /^\[/ { inside = 0 }
        inside && $0 !~ /^[[:space:]]*(#|$)/ { print }
    ' "$TUNED_VENDOR_BALANCED"
)
vendor_battery_modules=$(
    awk '
        $0 == "[modules]" { inside = 1; next }
        /^\[/ { inside = 0 }
        inside && $0 !~ /^[[:space:]]*(#|$)/ { print }
    ' "$TUNED_VENDOR_BATTERY"
)
[ "$vendor_modules" = 'cpufreq_conservative=+r' ] || \
    fail "Fedora Balanced modules contract drifted; child override is too broad"
grep -Fqx 'include=balanced' "$TUNED_VENDOR_BATTERY" || \
    fail "Fedora Balanced Battery no longer inherits Balanced"
[ -z "$vendor_battery_modules" ] || \
    fail "Fedora Balanced Battery adds modules entries disabled by the child"
kernel_config="/usr/lib/modules/$(uname -r)/config"
require_rpm_file "$kernel_config" kernel-core 644
grep -Fqx 'CONFIG_CPU_FREQ_GOV_CONSERVATIVE=y' "$kernel_config" || \
    fail "running kernel does not build cpufreq_conservative in"
[ "$(grep -Fxc 'enabled=0' "$TUNED_BALANCED")" -eq 1 ] || \
    fail "noid-balanced does not disable exactly one inherited modules instance"
[ "$(grep -Fxc 'enabled=0' "$TUNED_BATTERY")" -eq 1 ] || \
    fail "noid-balanced-battery does not disable exactly one inherited modules instance"
grep -Fqx 'default=balanced' "$TUNED_PPD" || \
    fail "tuned-ppd public default is not Balanced"
grep -Fqx 'balanced=noid-balanced' "$TUNED_PPD" || \
    fail "tuned-ppd AC Balanced mapping differs"
grep -Fqx 'balanced=noid-balanced-battery' "$TUNED_PPD" || \
    fail "tuned-ppd battery Balanced mapping differs"
[ "$(tuned-adm recommend)" = noid-balanced ] || \
    fail "TuneD does not recommend the neutral Balanced child"
note "$ppd_profile -> $tuned_profile; tuned/tuned-ppd active, exposed settings and mappings exact"

# Effective vendor zram behavior. Algorithm and priority are recorded rather
# than prescribed because M27 no longer claims a workload-independent winner.
[ -e /sys/block/zram0 ] || fail "zram0 is absent"
zram_algorithm=$(sed -n 's/.*\[\([^]]*\)\].*/\1/p' \
    /sys/block/zram0/comp_algorithm)
[ -n "$zram_algorithm" ] || fail "zram0 has no selected compression algorithm"
zram_priority=$(swapon --show=NAME,PRIO --noheadings --raw | \
    awk '$1 == "/dev/zram0" {print $2}')
[ -n "$zram_priority" ] || fail "zram0 is not active swap"
note "zram0 active under Fedora policy: algorithm=$zram_algorithm priority=$zram_priority"

# CPU policy stays with kernel/tuned. Record the hardware path when present,
# but do not require an unbenchmarked global value.
if [ -f /sys/devices/system/cpu/intel_pstate/hwp_dynamic_boost ]; then
    hwp_dynamic_boost=$(cat /sys/devices/system/cpu/intel_pstate/hwp_dynamic_boost)
    [[ $hwp_dynamic_boost =~ ^[01]$ ]] || \
        fail "Intel HWP dynamic boost exposes invalid value: $hwp_dynamic_boost"
    note "Intel HWP dynamic boost vendor/tuned state=$hwp_dynamic_boost"
else
    note "Intel HWP dynamic boost path absent (hardware N/A)"
fi

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
live_image_count=$(cmdline_key_count rd.live.image)
if [[ $PASS_ID == live ]]; then
    [[ $live_image_count -eq 1 ]] || \
        fail "live pass requires exactly one rd.live.image parameter"
else
    [[ $live_image_count -eq 0 ]] || \
        fail "installed pass still has rd.live.image"
fi

# Fedora/upstream own runtime applicability. Upstream deliberately blocklists
# Lenovo's dytc_lapmode path to avoid competing thermal managers; its adaptive
# compatibility path can leave an enabled, inactive-success unit. The vendor
# ConditionVirtualization=no can do the same in a VM. Neither state is evidence
# that the userspace daemon is actively protecting the machine.
thermald_state=$(systemctl is-enabled thermald.service 2>/dev/null || true)
[ "$thermald_state" = enabled ] || \
    fail "thermald.service does not follow Fedora's enabled preset (state=$thermald_state)"
thermald_failed_state=$(systemctl is-failed thermald.service 2>/dev/null || true)
[ "$thermald_failed_state" != failed ] || fail "thermald.service is failed"
thermald_active_state=$(systemctl is-active thermald.service 2>/dev/null || true)
thermald_result=$(systemctl show thermald.service --property=Result --value)
thermald_exec_status=$(systemctl show thermald.service --property=ExecMainStatus --value)
# "success" covers a running thermald and upstream's own clean hardware-N/A
# exit (SuccessExitStatus=2).
[ "$thermald_result" = success ] || \
    fail "thermald.service has non-success result=$thermald_result"
note "thermald.service: enabled, active-state=$thermald_active_state, failed-state=$thermald_failed_state, result=$thermald_result, exec-status=$thermald_exec_status (Fedora/upstream applicability)"
lpmd_state=$(systemctl is-enabled intel_lpmd.service 2>/dev/null || true)
[ "$lpmd_state" = masked ] || \
    fail "intel_lpmd.service is not masked (state=$lpmd_state) — M08 single-EPP-writer policy"
lpmd_active=$(systemctl is-active intel_lpmd.service 2>/dev/null || true)
[ "$lpmd_active" != active ] || fail "intel_lpmd.service is running despite the M08 mask"
note "intel_lpmd.service: masked (single-EPP-writer), active-state=$lpmd_active"
if [ -r /sys/devices/platform/thinkpad_acpi/dytc_lapmode ]; then
    dytc_lapmode=$(cat /sys/devices/platform/thinkpad_acpi/dytc_lapmode)
    [[ $dytc_lapmode =~ ^[01]$ ]] || fail "dytc_lapmode exposes an invalid value"
    note "Lenovo DYTC lap/desk sensor present (value=$dytc_lapmode; inventory only)"
else
    note "Lenovo DYTC lap/desk sensor absent (hardware N/A)"
fi

echo "PASS  $TEST_NAME [$PASS_ID]: native rules + effective NIC/USB/SD/storage/OOM/power/zram states"
