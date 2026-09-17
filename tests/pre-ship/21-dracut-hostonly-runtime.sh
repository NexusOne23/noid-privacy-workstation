#!/usr/bin/env bash
# Candidate-only M21 lifecycle gate:
#   sudo bash tests/pre-ship/21-dracut-hostonly-runtime.sh live
#   sudo bash tests/pre-ship/21-dracut-hostonly-runtime.sh fresh-install
#   sudo bash tests/pre-ship/21-dracut-hostonly-runtime.sh reboot
# The fresh pass proves staged publication + bootable Generic BLS recovery.
# The reboot pass is the actual host-only bootability gate.
set -euo pipefail

TEST_NAME=21-dracut-hostonly-runtime
PASS_ID=${1:-invalid}

fail() { echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2; exit 1; }
note() { echo "  [$PASS_ID] $*"; }

[ "$#" -eq 1 ] || {
    echo "usage: $0 {live|fresh-install|reboot}" >&2
    exit 2
}
case "$PASS_ID" in live|fresh-install|reboot) ;; *) exit 2 ;; esac

if [ "$(id -u)" -ne 0 ]; then
    if sudo -n true >/dev/null 2>&1; then
        exec sudo -n "$0" "$PASS_ID"
    fi
    fail "run as root or establish sudo credentials first"
fi
grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
for tool in awk basename cmp grep grub2-editenv journalctl lsinitrd mktemp \
        modinfo python3 readlink sha256sum stat systemctl tr uname; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing command: $tool"
done

HELPER=/usr/libexec/noid-dracut-hostonly-configure
BOOT_GUARD=/usr/libexec/noid-boot-mutation-guard
REGENERATOR=/usr/libexec/noid-dracut-regenerate-all
UNIT=noid-dracut-hostonly-firstboot.service
TIMER=noid-dracut-hostonly-firstboot.timer
STATE=/var/lib/noid-privacy/dracut-hostonly.state
CONFIG=/etc/dracut.conf.d/99-noid-hostonly.conf
GSC_CONFIG=/etc/dracut.conf.d/98-noid-intel-gsc.conf
MARKER=/etc/noid-privacy/initramfs-hostonly
KERNEL=$(uname -r)
IMAGE=/boot/initramfs-$KERNEL.img
FALLBACK_IMAGE=/boot/initramfs-$KERNEL.noid-generic-fallback.img
FALLBACK_BLS=/boot/loader/entries/noid-generic-fallback-$KERNEL.conf
FALLBACK_ARG=noid.initramfs=generic-fallback
FALLBACK_BLS_ID=noid-generic-fallback-$KERNEL
BOOT_SUCCESS_REQUEST=/run/noid-privacy/hostonly-boot-success-needed
BOOT_SUCCESS_UNIT=noid-hostonly-boot-success.service
BOOT_SUCCESS_HELPER=/usr/libexec/noid-mark-hostonly-boot-success

[ -x "$HELPER" ] && [ ! -L "$HELPER" ] || fail "host-only helper missing or unsafe"
[ -x "$BOOT_GUARD" ] && [ ! -L "$BOOT_GUARD" ] || fail "boot-mutation guard missing or unsafe"
[ -x "$REGENERATOR" ] && [ ! -L "$REGENERATOR" ] || fail "guarded regenerator missing or unsafe"
[ -x "$BOOT_SUCCESS_HELPER" ] && [ ! -L "$BOOT_SUCCESS_HELPER" ] || \
    fail "first-login boot-success helper missing or unsafe"
systemctl is-enabled --quiet "$TIMER" || fail "$TIMER is not enabled"
[ ! -e "/etc/systemd/system/multi-user.target.wants/$UNIT" ] || \
    fail "$UNIT still blocks the normal target through direct enablement"
[ -L "/etc/systemd/system/multi-user.target.wants/$TIMER" ] || \
    fail "$TIMER lacks its native multi-user activation link"
[ ! -e /etc/dracut.conf.d/99-noid-omit-storage.conf ] || \
    fail "retired global storage omit exists"
[ ! -e /etc/dracut.conf.d/99-noid-compress.conf ] || \
    fail "retired LZ4 override exists"

state_value() {
    local key=$1
    awk -F= -v key="$key" '$1 == key { print substr($0, length(key) + 2); exit }' \
        "$STATE"
}

grub_env_value() {
    local key=$1
    grub2-editenv - list | \
        awk -F= -v key="$key" '$1 == key { print substr($0, length(key) + 2); exit }'
}

unit_completed_before() {
    local unit=$1 deadline=$2
    [[ $deadline =~ ^[1-9][0-9]*$ ]] || return 1
    journalctl -b -u "$unit" -o json --no-pager 2>/dev/null | \
        python3 -I -c '
import json
import sys

unit = sys.argv[1]
deadline = int(sys.argv[2])
found = False
for line in sys.stdin:
    try:
        entry = json.loads(line)
        timestamp = int(entry.get("__MONOTONIC_TIMESTAMP", "0"))
    except (json.JSONDecodeError, TypeError, ValueError):
        continue
    if (
        entry.get("SYSLOG_IDENTIFIER") == "systemd"
        # Fedora 44/systemd 259 does not persist source-location metadata on
        # this PID 1 job record. Bind it to journald-trusted process fields
        # instead of treating the optional _CODE_FUNC field as evidence.
        and entry.get("_PID") == "1"
        and entry.get("_UID") == "0"
        and entry.get("_GID") == "0"
        and entry.get("_COMM") == "systemd"
        and entry.get("_EXE") == "/usr/lib/systemd/systemd"
        and entry.get("_SYSTEMD_UNIT") == "init.scope"
        and entry.get("TID") == "1"
        and entry.get("UNIT") == unit
        and entry.get("JOB_RESULT") == "done"
        and 0 < timestamp <= deadline
    ):
        found = True
raise SystemExit(0 if found else 1)
' "$unit" "$deadline"
}

require_state() {
    [ -f "$STATE" ] && [ ! -L "$STATE" ] || fail "state file missing or unsafe"
    [ "$(stat -c '%U:%G:%a' "$STATE")" = root:root:600 ] || \
        fail "state metadata is not root:root 0600"
    [ "$(state_value policy_version)" = 2 ] || fail "unexpected policy version"
    [ "$(state_value target_kernel)" = "$KERNEL" ] || \
        fail "state target kernel differs from the running kernel"
    [ "$(state_value root_class)" = simple-single-device-luks2-btrfs ] || \
        fail "candidate VM is not the required simple LUKS2+Btrfs fixture"
}

check_image() {
    local image=$1 expect_hostonly=$2 listing modules required
    local module_path module_rel
    [ -f "$image" ] && [ ! -L "$image" ] || fail "image missing or unsafe: $image"
    [ "$(stat -c '%U:%G:%a' "$image")" = root:root:600 ] || \
        fail "image metadata differs: $image"
    listing=$(mktemp)
    modules=$(mktemp)
    trap 'rm -f -- "$listing" "$modules"' RETURN
    lsinitrd "$image" >"$listing" 2>&1 || fail "cannot inspect $image"
    lsinitrd -m "$image" >"$modules" 2>&1 || fail "cannot list Dracut modules: $image"
    grep -q 'etc/modprobe.d/noid-security-blacklist.conf' "$listing" || \
        fail "module deny policy missing from $image"
    if [ "$expect_hostonly" = yes ]; then
        grep -q 'etc/noid-privacy/initramfs-hostonly' "$listing" || \
            fail "host-only marker missing from $image"
        for required in btrfs crypt dm kernel-modules rootfs-block; do
            grep -qx "$required" "$modules" || \
                fail "required Dracut module $required missing from $image"
        done
        if grep -Eq '^(mdraid|iscsi|fcoe|nbd)$' "$modules"; then
            fail "unused storage Dracut module remains in host-only image"
        fi
    else
        ! grep -q 'etc/noid-privacy/initramfs-hostonly' "$listing" || \
            fail "Generic fallback contains the host-only marker"
    fi
    ! grep -Eq '/firewire-(core|net|ohci|sbp2)\.ko(\.(xz|zst|gz))?$' "$listing" || \
        fail "FireWire kernel object remains in $image"
    for required in mei_me mei_gsc_proxy; do
        module_path=$(modinfo -k "$KERNEL" -n "$required" 2>/dev/null || true)
        [ -n "$module_path" ] && [ "$module_path" != '(builtin)' ] || \
            fail "cannot resolve Intel GSC dependency for $KERNEL: $required"
        module_path=$(readlink -f "$module_path")
        module_rel=${module_path#/}
        if [ ! -f "$module_path" ] || ! cmp -s "$module_path" \
                <(lsinitrd -f "$module_rel" "$image" 2>/dev/null); then
            fail "runtime image lacks exact Intel GSC dependency bytes: $required"
        fi
    done
    rm -f -- "$listing" "$modules"
    trap - RETURN
}

[ -f "$GSC_CONFIG" ] && [ ! -L "$GSC_CONFIG" ] || \
    fail "Intel GSC Dracut dependency policy missing or unsafe"
[ "$(stat -c '%U:%G:%a' "$GSC_CONFIG")" = root:root:644 ] || \
    fail "Intel GSC Dracut dependency policy metadata differs"
grep -qxF 'add_drivers+=" mei_me mei_gsc_proxy "' "$GSC_CONFIG" || \
    fail "Intel GSC Dracut dependency selection differs"
! grep -q 'force_drivers' "$GSC_CONFIG" || \
    fail "Intel GSC dependencies are force-loaded"

if [ "$PASS_ID" = live ]; then
    grep -qE '(^|[[:space:]])rd\.live\.image([=[:space:]]|$)' /proc/cmdline || \
        fail "live pass lacks rd.live.image"
    [ ! -e "$STATE" ] || fail "installed-system state leaked into Live mode"
    [ ! -e "$CONFIG" ] && [ ! -e "$MARKER" ] || \
        fail "installed host-only policy leaked into Live mode"
    [ ! -e "$FALLBACK_BLS" ] && [ ! -e "$FALLBACK_IMAGE" ] || \
        fail "installed Generic recovery artifacts leaked into Live mode"
    [ ! -e "$BOOT_SUCCESS_REQUEST" ] || \
        fail "installed first-login boot-success request leaked into Live mode"
    if "$BOOT_GUARD" >/dev/null 2>&1; then
        fail "boot-mutation guard allowed the Live/installer environment"
    fi
    note "Live/installer boundary remains generic and unmodified"
    echo "PASS  $TEST_NAME [$PASS_ID]: no installed-system transition artifacts"
    exit 0
fi

! grep -qE '(^|[[:space:]])rd\.live\.image([=[:space:]]|$)' /proc/cmdline || \
    fail "installed pass retains rd.live.image"
mapfile -t SOURCE_BLS_MATCHES < <(
    grep -l -x "version $KERNEL" /boot/loader/entries/*.conf 2>/dev/null | sort
)
[ "${#SOURCE_BLS_MATCHES[@]}" -eq 1 ] || \
    fail "expected exactly one normal BLS entry for the running kernel"
SOURCE_BLS_ID=$(basename "${SOURCE_BLS_MATCHES[0]}" .conf)
SOURCE_BLS=${SOURCE_BLS_MATCHES[0]}
require_state
[ -f "$CONFIG" ] && [ ! -L "$CONFIG" ] || fail "host-only drop-in missing"
[ -f "$MARKER" ] && [ ! -L "$MARKER" ] || fail "host-only marker missing"
grep -qx 'hostonly="yes"' "$CONFIG" || fail "hostonly=yes missing"
grep -qx 'hostonly_mode="sloppy"' "$CONFIG" || fail "sloppy mode missing"
grep -qx 'hostonly_cmdline="no"' "$CONFIG" || fail "cmdline policy differs"
grep -qx 'policy_version=2' "$MARKER" || fail "marker policy version differs"
grep -qx 'mode=hostonly-sloppy' "$MARKER" || fail "marker mode differs"
check_image "$IMAGE" yes

if [ "$PASS_ID" = fresh-install ]; then
    [ "$(state_value phase)" = pending-reboot ] || \
        fail "fresh install is not waiting for the real bootability gate"
    [ "$(state_value prepared_boot_id)" = "$(cat /proc/sys/kernel/random/boot_id)" ] || \
        fail "fresh pending state was not prepared during this boot"
    check_image "$FALLBACK_IMAGE" no
    [ -f "$FALLBACK_BLS" ] && [ ! -L "$FALLBACK_BLS" ] || \
        fail "bootable Generic BLS fallback is missing"
    [ "$(stat -c '%U:%G:%a' "$FALLBACK_BLS")" = root:root:644 ] || \
        fail "Generic BLS fallback metadata differs"
    grep -qF "initrd /initramfs-$KERNEL.noid-generic-fallback.img" "$FALLBACK_BLS" || \
        fail "Generic BLS entry does not reference the retained image"
    grep -qF "$FALLBACK_ARG" "$FALLBACK_BLS" || \
        fail "Generic BLS entry lacks its recovery marker"
    source_options=$(awk '$1 == "options" {$1=""; sub(/^ /,""); print}' "$SOURCE_BLS")
    fallback_options=$(awk '$1 == "options" {$1=""; sub(/^ /,""); print}' "$FALLBACK_BLS")
    [ -n "$source_options" ] && \
    [ "$fallback_options" = "$source_options $FALLBACK_ARG" ] || \
        fail "Generic BLS options are not exact normal options plus one recovery marker"
    ! tr ' ' '\n' <<<"$fallback_options" | \
        grep -qE '^rootflags=.*(subvol=|subvolid=)' || \
        fail "Generic BLS still overrides the finalized Btrfs default"
    ! grep -Fqw -- "$FALLBACK_ARG" /proc/cmdline || \
        fail "fresh pass unexpectedly booted the recovery entry"
    [ "$(systemctl show "$UNIT" -p Result --value)" = success ] || \
        fail "transactional publication service did not succeed"
    [ "$(systemctl show "$TIMER" -p Result --value)" = success ] || \
        fail "nonblocking publication timer did not activate successfully"
    systemctl show "$UNIT" -p Before --value | tr ' ' '\n' | \
        grep -Eq '^(multi-user|graphical)\.target$' && \
        fail "long publication service remains ordered before a login target"
    [ "$(grub_env_value saved_entry)" = "$FALLBACK_BLS_ID" ] || \
        fail "Generic recovery entry is not the persistent GRUB default"
    [ "$(grub_env_value next_entry)" = "$SOURCE_BLS_ID" ] || \
        fail "host-only candidate is not armed as the one-shot next boot"
    [ -f "$BOOT_SUCCESS_REQUEST" ] && [ ! -L "$BOOT_SUCCESS_REQUEST" ] || \
        fail "ephemeral first-login boot-success request is missing or unsafe"
    [ "$(stat -c '%U:%G:%a' "$BOOT_SUCCESS_REQUEST")" = root:root:444 ] || \
        fail "ephemeral first-login boot-success request metadata differs"
    expected_request=$(printf 'policy_version=2\nprepared_boot_id=%s' \
        "$(cat /proc/sys/kernel/random/boot_id)")
    [ "$(<"$BOOT_SUCCESS_REQUEST")" = "$expected_request" ] || \
        fail "ephemeral first-login boot-success request is not boot-bound"
    [ -z "$(grub_env_value menu_show_once)" ] && \
    [ -z "$(grub_env_value menu_show_once_timeout)" ] || \
        fail "planned host-only trial still requests a visible GRUB menu"
    [ "$(grub_env_value boot_success)" = 1 ] || \
        fail "successful first-login transaction did not mark this boot successful"
    journalctl -b --no-pager \
        --grep='marked the current installed boot successful after first-login transaction' \
        >/dev/null 2>&1 || \
        fail "$BOOT_SUCCESS_UNIT lacks the successful current-boot event"
    image_before=$(sha256sum "$IMAGE" | awk '{print $1}')
    fallback_before=$(sha256sum "$FALLBACK_IMAGE" | awk '{print $1}')
    state_before=$(sha256sum "$STATE" | awk '{print $1}')
    if "$BOOT_GUARD" >/dev/null 2>&1; then
        fail "boot-mutation guard allowed pending-reboot"
    fi
    if "$REGENERATOR" >/dev/null 2>&1; then
        fail "later regenerator ran during the M21 boot trial"
    fi
    [ "$(sha256sum "$IMAGE" | awk '{print $1}')" = "$image_before" ] \
        && [ "$(sha256sum "$FALLBACK_IMAGE" | awk '{print $1}')" = "$fallback_before" ] \
        && [ "$(sha256sum "$STATE" | awk '{print $1}')" = "$state_before" ] || \
        fail "refused writer changed M21 transaction bytes"
    systemctl show "$UNIT" -p Requires --value | tr ' ' '\n' | \
        grep -qx noid-snapper-init.service || \
        fail "M21 does not require successful M20 finalization"
    systemctl show "$UNIT" -p After --value | tr ' ' '\n' | \
        grep -qx noid-snapper-init.service || \
        fail "M21 is not ordered after M20 finalization"
    systemctl show noid-snapper-init.service -p Before --value | tr ' ' '\n' | \
        grep -qx "$UNIT" || fail "M20 is not ordered before M21 publication"
    systemctl show noid-snapper-init.service -p Requires --value | tr ' ' '\n' | \
        grep -qx noid-firstboot-cmdline.service || \
        fail "M20 does not require successful M01 cmdline reconciliation"
    systemctl show noid-snapper-init.service -p After --value | tr ' ' '\n' | \
        grep -qx noid-firstboot-cmdline.service || \
        fail "M20 is not ordered after M01 cmdline reconciliation"
    [ "$(systemctl show noid-firstboot-cmdline.service -p Result --value)" = success ] || \
        fail "M01 cmdline reconciliation did not succeed before M20"
    [ "$(systemctl show noid-snapper-init.service -p Result --value)" = success ] || \
        fail "M20 finalization did not succeed before M21"
    m20_start=$(systemctl show noid-snapper-init.service \
        -p ExecMainStartTimestampMonotonic --value)
    m20_exit=$(systemctl show noid-snapper-init.service \
        -p ExecMainExitTimestampMonotonic --value)
    m21_start=$(systemctl show "$UNIT" -p ExecMainStartTimestampMonotonic --value)
    unit_completed_before noid-firstboot-cmdline.service "$m20_start" || \
        fail "runtime timestamps do not prove M01 completed before M20 started"
    [[ $m20_exit =~ ^[1-9][0-9]*$ ]] && [[ $m21_start =~ ^[1-9][0-9]*$ ]] && \
    [ "$m20_exit" -le "$m21_start" ] || \
        fail "runtime timestamps do not prove M20 completed before M21 started"
    note "candidate staged/published; Generic BLS fallback remains bootable"
    echo "PASS  $TEST_NAME [$PASS_ID]: phase=pending-reboot with durable Generic recovery"
    exit 0
fi

[ "$(state_value phase)" = complete ] || \
    fail "reboot did not confirm the host-only candidate"
[ "$("$BOOT_GUARD")" = basis=hostonly ] || \
    fail "shared guard does not recognize the confirmed host-only basis"
[ "$(state_value prepared_boot_id)" != "$(cat /proc/sys/kernel/random/boot_id)" ] || \
    fail "complete state lacks a distinct real reboot"
! grep -Fqw -- "$FALLBACK_ARG" /proc/cmdline || \
    fail "reboot pass used the Generic recovery entry"
[ ! -e "$FALLBACK_BLS" ] && [ ! -e "$FALLBACK_IMAGE" ] || \
    fail "Generic fallback was retired before/after the wrong state transition"
[ "$(systemctl show "$UNIT" -p Result --value)" = success ] || \
    fail "post-boot confirmation service did not succeed"
[ "$(grub_env_value saved_entry)" = "$SOURCE_BLS_ID" ] || \
    fail "confirmed host-only entry was not restored as the GRUB default"
[ -z "$(grub_env_value next_entry)" ] || \
    fail "one-shot host-only GRUB selection survived the reboot"
[ ! -e "$BOOT_SUCCESS_REQUEST" ] || \
    fail "ephemeral first-login request survived the reboot"
[ -z "$(grub_env_value menu_show_once)" ] && \
[ -z "$(grub_env_value menu_show_once_timeout)" ] || \
    fail "reboot retained a forced visible-menu request"
journalctl -b -u "$UNIT" --no-pager \
    --grep='host-only candidate boot confirmed; generic fallback retired' \
    >/dev/null 2>&1 || \
    fail "current-boot journal lacks the confirmation event"
if ! journalctl -b -1 --no-pager >/dev/null 2>&1; then
    fail "persistent previous-boot journal is unavailable"
fi
journalctl -b -1 --no-pager \
    --grep='marked the current installed boot successful after first-login transaction' \
    >/dev/null 2>&1 || \
    fail "previous boot lacks the first-login success bridge event"
if journalctl -b -1 --no-pager 2>/dev/null | \
        grep -Ei 'waiting for .*md.*clean|disassembling mdraid|mdraid.*wait.*clean'; then
    fail "first installed shutdown entered the retired mdraid wait path"
fi
note "host-only image actually booted; first shutdown has no mdraid wait evidence"
echo "PASS  $TEST_NAME [$PASS_ID]: distinct reboot confirmed, fallback retired"
