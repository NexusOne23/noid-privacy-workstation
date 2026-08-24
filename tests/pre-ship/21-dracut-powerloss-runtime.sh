#!/usr/bin/env bash
# Destructive candidate-VM proof for abrupt power loss during M21 publication.
# This gate never edits the installed helper. A transient BASH_ENV DEBUG trap
# stops its exact bytes after candidate publication and before the state write;
# the operator must then hard-stop the disposable VM from the KVM host.
set -euo pipefail

TEST_NAME=21-dracut-powerloss-runtime
ACTION=${1:-invalid}

fail() { echo "FAIL  $TEST_NAME [$ACTION]: $*" >&2; exit 1; }
pass() { echo "PASS  $TEST_NAME [$ACTION]: $*"; }
note() { echo "  [$ACTION] $*"; }

[ "$#" -eq 1 ] || {
    echo "usage: $0 {select-recovery|recover|arm|verify}" >&2
    exit 2
}
case "$ACTION" in select-recovery|recover|arm|verify) ;; *) exit 2 ;; esac

if [ "$(id -u)" -ne 0 ]; then
    if sudo -n true >/dev/null 2>&1; then
        exec sudo -n "$0" "$ACTION"
    fi
    fail "run as root or establish sudo credentials first"
fi
grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
grep -qE '(^|[[:space:]])rd\.live\.image([=[:space:]]|$)' /proc/cmdline && \
    fail "destructive power-loss gate is installed-VM-only"
for tool in awk basename chcon grep grub2-editenv grub2-reboot journalctl \
        logger lsinitrd ps restorecon stat sync systemctl systemd-detect-virt \
        systemd-run uname; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing command: $tool"
done
virtualization=$(systemd-detect-virt --vm 2>/dev/null || true)
case "$virtualization" in
    kvm|qemu) ;;
    *) fail "destructive power-loss gate requires a disposable QEMU/KVM VM" ;;
esac

HELPER=/usr/libexec/noid-dracut-hostonly-configure
BOOT_GUARD=/usr/libexec/noid-boot-mutation-guard
UNIT=noid-dracut-hostonly-firstboot.service
STATE=/var/lib/noid-privacy/dracut-hostonly.state
TEST_STATE=/var/lib/noid-privacy/dracut-powerloss-test.state
INJECT_ENV=/run/noid-dracut-powerloss-bashenv
INJECT_READY=/run/noid-dracut-powerloss-ready
INJECT_UNIT=noid-dracut-powerloss-inject.service
CONFIG=/etc/dracut.conf.d/99-noid-hostonly.conf
MARKER=/etc/noid-privacy/initramfs-hostonly
FALLBACK_ARG=noid.initramfs=generic-fallback
KERNEL=$(uname -r)
STANDARD_IMAGE=/boot/initramfs-$KERNEL.img
FALLBACK_IMAGE=/boot/initramfs-$KERNEL.noid-generic-fallback.img
FALLBACK_BLS=/boot/loader/entries/noid-generic-fallback-$KERNEL.conf
FALLBACK_BLS_ID=noid-generic-fallback-$KERNEL

[ -x "$HELPER" ] && [ ! -L "$HELPER" ] || fail "installed helper missing or unsafe"
[ -x "$BOOT_GUARD" ] && [ ! -L "$BOOT_GUARD" ] || fail "boot-mutation guard missing or unsafe"
mapfile -t SOURCE_BLS_MATCHES < <(
    grep -l -x "version $KERNEL" /boot/loader/entries/*.conf 2>/dev/null | sort
)
[ "${#SOURCE_BLS_MATCHES[@]}" -eq 1 ] || \
    fail "expected exactly one normal BLS entry for the running kernel"
SOURCE_BLS_ID=$(basename "${SOURCE_BLS_MATCHES[0]}" .conf)

value_from() {
    local file=$1 key=$2
    awk -F= -v key="$key" '$1 == key { print substr($0, length(key) + 2); exit }' \
        "$file"
}

grub_env_value() {
    local key=$1
    grub2-editenv - list | \
        awk -F= -v key="$key" '$1 == key { print substr($0, length(key) + 2); exit }'
}

require_state_phase() {
    local expected=$1
    [ -f "$STATE" ] && [ ! -L "$STATE" ] || fail "M21 state missing or unsafe"
    [ "$(stat -c '%U:%G:%a' "$STATE")" = root:root:600 ] || \
        fail "M21 state metadata differs"
    [ "$(value_from "$STATE" policy_version)" = 2 ] || fail "M21 policy version differs"
    [ "$(value_from "$STATE" target_kernel)" = "$KERNEL" ] || \
        fail "M21 target kernel differs"
    [ "$(value_from "$STATE" root_class)" = simple-single-device-luks2-btrfs ] || \
        fail "power-loss fixture is not simple single-device LUKS2+Btrfs"
    [ "$(value_from "$STATE" phase)" = "$expected" ] || \
        fail "expected M21 phase=$expected"
}

check_generic_standard() {
    local listing
    [ -f "$STANDARD_IMAGE" ] && [ ! -L "$STANDARD_IMAGE" ] || \
        fail "standard running-kernel image missing or unsafe"
    listing=$(mktemp)
    trap 'rm -f -- "$listing"' RETURN
    lsinitrd "$STANDARD_IMAGE" >"$listing" 2>&1 || fail "cannot inspect standard image"
    grep -q 'etc/modprobe.d/noid-security-blacklist.conf' "$listing" || \
        fail "Generic standard image lacks the module policy"
    ! grep -q 'etc/noid-privacy/initramfs-hostonly' "$listing" || \
        fail "standard image is still host-only after recovery"
    rm -f -- "$listing"
    trap - RETURN
}

require_test_state_phase() {
    local expected=$1
    [ -f "$TEST_STATE" ] && [ ! -L "$TEST_STATE" ] || \
        fail "durable power-loss test state is missing or unsafe"
    [ "$(stat -c '%U:%G:%a' "$TEST_STATE")" = root:root:600 ] || \
        fail "test-state metadata differs"
    [ "$(value_from "$TEST_STATE" test_version)" = 1 ] || \
        fail "test-state version differs"
    [ "$(value_from "$TEST_STATE" phase)" = "$expected" ] || \
        fail "expected test-state phase=$expected"
    [ "$(value_from "$TEST_STATE" kernel)" = "$KERNEL" ] || \
        fail "running kernel differs from the power-loss target"
}

journal_boot_id() {
    local offset=$1
    journalctl --list-boots --no-pager | \
        awk -v offset="$offset" '$1 == offset && !found { print $2; found=1 }'
}

normalize_boot_id() {
    local value=${1//-/}
    [[ $value =~ ^[0-9a-f]{32}$ ]] || fail "invalid boot ID"
    printf '%s\n' "$value"
}

require_abrupt_boot() {
    local offset=$1 expected_boot_id=$2 expected_normalized actual_boot_id
    expected_normalized=$(normalize_boot_id "$expected_boot_id")
    actual_boot_id=$(journal_boot_id "$offset")
    [ -n "$actual_boot_id" ] && [ "$actual_boot_id" = "$expected_normalized" ] || \
        fail "journal boot $offset does not match the injected-stop boot"
    journalctl -b "$offset" --no-pager >/dev/null 2>&1 || \
        fail "abrupt boot journal $offset is unavailable"
    journalctl -b "$offset" --no-pager \
        --grep="power-loss arm checkpoint boot_id=$expected_boot_id" \
        >/dev/null 2>&1 || \
        fail "injected-stop boot lacks its fsynchronized journal checkpoint"
    if journalctl -b "$offset" --no-pager \
            --grep='Reached target (System Power Off|Reboot)|systemd-shutdown.*Syncing filesystems' \
            >/dev/null 2>&1; then
        fail "injected-stop boot contains a clean shutdown path; hard power loss not proven"
    fi
}

check_recovered_generic() {
    require_state_phase recovered-generic
    check_generic_standard
    [ ! -e "$FALLBACK_IMAGE" ] && [ ! -e "$FALLBACK_BLS" ] || \
        fail "Generic recovery left fallback artifacts"
    [ ! -e "$CONFIG" ] && [ ! -e "$MARKER" ] || \
        fail "Generic recovery left host-only policy artifacts"
    [ "$(grub_env_value saved_entry)" = "$SOURCE_BLS_ID" ] || \
        fail "Generic recovery did not restore the normal GRUB default"
    [ -z "$(grub_env_value next_entry)" ] || \
        fail "Generic recovery left a one-shot GRUB entry"
    [ "$(systemctl show "$UNIT" -p Result --value)" = success ] || \
        fail "M21 recovery service did not succeed"
}

write_post_cut_checkpoint() {
    local cut_boot_id=$1 recovery_boot_id=$2 tmp
    tmp=$(mktemp "${TEST_STATE}.tmp.XXXXXX") || \
        fail "cannot reserve the post-cut checkpoint"
    if ! printf 'test_version=1\nphase=post-cut-recovery-observed\nkernel=%s\ncut_boot_id=%s\nrecovery_boot_id=%s\n' \
            "$KERNEL" "$cut_boot_id" "$recovery_boot_id" >"$tmp" || \
       ! chown root:root "$tmp" || ! chmod 0600 "$tmp" || \
       ! chcon --reference="$TEST_STATE" "$tmp" || ! sync -- "$tmp" || \
       ! mv -fT -- "$tmp" "$TEST_STATE" || \
       ! sync -- /var/lib/noid-privacy; then
        rm -f -- "$tmp"
        fail "cannot publish the post-cut recovery checkpoint"
    fi
}

case "$ACTION" in
    select-recovery)
        require_state_phase pending-reboot
        [ ! -e "$TEST_STATE" ] || \
            fail "old test state exists; use a fresh disposable clone"
        [ -f "$FALLBACK_IMAGE" ] && [ -f "$FALLBACK_BLS" ] || \
            fail "pending transaction lacks Generic recovery artifacts"
        [ "$(grub_env_value saved_entry)" = "$FALLBACK_BLS_ID" ] || \
            fail "Generic recovery is not the saved default"
        grub2-reboot "$FALLBACK_BLS_ID" >/dev/null || \
            fail "cannot select the Generic entry for recovery setup"
        [ "$(grub_env_value next_entry)" = "$FALLBACK_BLS_ID" ] || \
            fail "Generic setup reboot was not armed"
        sync -- /boot/grub2/grubenv
        sync -- /boot/grub2
        sync -- /boot
        pass "Generic recovery selected; reboot normally into it, then run recover"
        ;;

    recover)
        grep -Fqw -- "$FALLBACK_ARG" /proc/cmdline || \
            fail "recovery observation is only valid in the temporary Generic entry"
        check_recovered_generic
        current_unit_journal=$(journalctl -b -u "$UNIT" --no-pager 2>/dev/null || true)
        if [ ! -e "$TEST_STATE" ]; then
            grep -q 'generic recovery boot detected; generic image restored as the default' \
                <<<"$current_unit_journal" || \
                fail "current journal lacks the selected-recovery baseline evidence"
            pass "Generic setup recovery observed; reboot normally into the restored standard entry, then run arm"
            exit 0
        fi

        require_test_state_phase publication-stopped-before-state
        cut_boot_id=$(value_from "$TEST_STATE" boot_id)
        current_boot_id=$(cat /proc/sys/kernel/random/boot_id)
        [ -n "$cut_boot_id" ] && [ "$cut_boot_id" != "$current_boot_id" ] || \
            fail "no distinct recovery boot followed the injected stop"
        grep -q 'generic recovery boot detected after interrupted publication' \
            <<<"$current_unit_journal" || \
            fail "current journal lacks interrupted-publication recovery evidence"
        require_abrupt_boot -1 "$cut_boot_id"
        write_post_cut_checkpoint "$cut_boot_id" "$current_boot_id"
        pass "post-cut Generic recovery observed; reboot normally into the restored standard entry, then run verify"
        ;;

    arm)
        ! grep -Fqw -- "$FALLBACK_ARG" /proc/cmdline || \
            fail "temporary Generic recovery entry is not an allowed writer basis; reboot normally first"
        require_state_phase recovered-generic
        [ "$("$BOOT_GUARD")" = basis=generic ] || \
            fail "shared guard does not recognize the restored Generic basis"
        check_generic_standard
        [ ! -e "$FALLBACK_IMAGE" ] && [ ! -e "$FALLBACK_BLS" ] || \
            fail "recovery setup left fallback artifacts"
        [ ! -e "$CONFIG" ] && [ ! -e "$MARKER" ] || \
            fail "recovery setup left the host-only policy active"
        [ "$(grub_env_value saved_entry)" = "$SOURCE_BLS_ID" ] || \
            fail "normal entry was not restored after recovery setup"
        [ -z "$(grub_env_value next_entry)" ] || \
            fail "an unrelated one-shot GRUB entry is pending"
        [ ! -e "$TEST_STATE" ] || \
            fail "old test state exists; verify or remove it in this disposable clone"
        systemctl reset-failed "$INJECT_UNIT" >/dev/null 2>&1 || true
        rm -f -- "$INJECT_ENV" "$INJECT_READY"

        cat > "$INJECT_ENV" <<'INJECT_EOF'
if [ "${NOID_DRACUT_POWERLOSS_INJECT-}" = 1 ]; then
    __noid_dracut_powerloss_stop() {
        case "$BASH_COMMAND" in
            'prepared_boot_id=$(cat /proc/sys/kernel/random/boot_id)')
                trap - DEBUG
                printf '%s\n' ready > "$NOID_DRACUT_POWERLOSS_READY"
                printf 'test_version=1\nphase=publication-stopped-before-state\nkernel=%s\nboot_id=%s\n' \
                    "$NOID_DRACUT_POWERLOSS_KERNEL" \
                    "$NOID_DRACUT_POWERLOSS_BOOT_ID" \
                    > "$NOID_DRACUT_POWERLOSS_STATE"
                chown root:root "$NOID_DRACUT_POWERLOSS_STATE"
                chmod 0600 "$NOID_DRACUT_POWERLOSS_STATE"
                restorecon -F "$NOID_DRACUT_POWERLOSS_STATE" >/dev/null
                sync -- "$NOID_DRACUT_POWERLOSS_STATE"
                sync -- "${NOID_DRACUT_POWERLOSS_STATE%/*}"
                kill -STOP "$BASHPID"
                ;;
        esac
    }
    trap __noid_dracut_powerloss_stop DEBUG
fi
INJECT_EOF
        chown root:root "$INJECT_ENV"
        chmod 0600 "$INJECT_ENV"
        current_boot_id=$(cat /proc/sys/kernel/random/boot_id)
        # Keep an early failure loaded so the readiness loop can inspect its
        # state and journal instead of misreporting a 20-minute timeout.
        systemd-run --unit="$INJECT_UNIT" --no-block \
            --property=Type=exec \
            --setenv=BASH_ENV="$INJECT_ENV" \
            --setenv=NOID_DRACUT_POWERLOSS_INJECT=1 \
            --setenv=NOID_DRACUT_POWERLOSS_READY="$INJECT_READY" \
            --setenv=NOID_DRACUT_POWERLOSS_STATE="$TEST_STATE" \
            --setenv=NOID_DRACUT_POWERLOSS_KERNEL="$KERNEL" \
            --setenv=NOID_DRACUT_POWERLOSS_BOOT_ID="$current_boot_id" \
            /usr/bin/bash "$HELPER" --retry >/dev/null || \
            fail "cannot start the instrumented exact helper bytes"

        deadline=$((SECONDS + 1200))
        while [ ! -f "$INJECT_READY" ]; do
            if systemctl is-failed --quiet "$INJECT_UNIT"; then
                journalctl -u "$INJECT_UNIT" --no-pager -n 80 >&2 || true
                fail "instrumented helper failed before the target publication point"
            fi
            [ "$SECONDS" -lt "$deadline" ] || \
                fail "timed out waiting for the publication stop point"
            sleep 1
        done
        main_pid=$(systemctl show "$INJECT_UNIT" -p MainPID --value)
        [[ $main_pid =~ ^[1-9][0-9]*$ ]] || fail "injection unit has no main process"
        process_state=$(ps -o stat= -p "$main_pid" | awk '{print $1}')
        [[ $process_state == *T* ]] || fail "helper did not stop at the power-loss point"
        [ ! -e "$STATE" ] || fail "helper wrote M21 state before the injected stop"
        [ "$(grub_env_value saved_entry)" = "$FALLBACK_BLS_ID" ] || \
            fail "Generic is not the saved default at the stop point"
        [ -z "$(grub_env_value next_entry)" ] || \
            fail "candidate one-shot entry was armed before durable state"
        logger --tag noid-dracut-powerloss-test -- \
            "power-loss arm checkpoint boot_id=$current_boot_id"
        journalctl --sync
        [ "$(journal_boot_id 0)" = "$(normalize_boot_id "$current_boot_id")" ] || \
            fail "current boot is absent after the journal synchronization checkpoint"
        journalctl -b 0 -t noid-dracut-powerloss-test --no-pager \
            --grep="power-loss arm checkpoint boot_id=$current_boot_id" \
            >/dev/null 2>&1 || \
            fail "fsynchronized journal checkpoint is not readable"
        note "helper is SIGSTOPed after fsynced candidate publication and before state"
        note "on the KVM HOST now run: virsh destroy <disposable-domain>"
        note "start it again, unlock LUKS in the console, then run this gate with recover"
        pass "READY FOR HOST-SIDE HARD POWER CUT — do not use guest reboot/shutdown"
        ;;

    verify)
        require_test_state_phase post-cut-recovery-observed
        ! grep -Fqw -- "$FALLBACK_ARG" /proc/cmdline || \
            fail "final verification must run from the restored standard Generic entry"
        cut_boot_id=$(value_from "$TEST_STATE" cut_boot_id)
        recovery_boot_id=$(value_from "$TEST_STATE" recovery_boot_id)
        current_boot_id=$(cat /proc/sys/kernel/random/boot_id)
        [ -n "$cut_boot_id" ] && [ -n "$recovery_boot_id" ] && \
        [ "$cut_boot_id" != "$recovery_boot_id" ] && \
        [ "$current_boot_id" != "$cut_boot_id" ] && \
        [ "$current_boot_id" != "$recovery_boot_id" ] || \
            fail "final verification lacks three distinct lifecycle boots"
        [ "$(journal_boot_id -1)" = "$(normalize_boot_id "$recovery_boot_id")" ] || \
            fail "previous journal is not the observed Generic recovery boot"
        [ "$(journal_boot_id -2)" = "$(normalize_boot_id "$cut_boot_id")" ] || \
            fail "two-back journal is not the injected-stop boot"
        journalctl -b -1 -u "$UNIT" --no-pager \
            --grep='generic recovery boot detected after interrupted publication' \
            >/dev/null 2>&1 || \
            fail "previous journal lacks interrupted-publication recovery evidence"
        require_abrupt_boot -2 "$cut_boot_id"
        check_recovered_generic
        [ "$("$BOOT_GUARD")" = basis=generic ] || \
            fail "final restored Generic basis remains locked out"
        rm -f -- "$TEST_STATE" "$INJECT_ENV" "$INJECT_READY"
        sync -- /var/lib/noid-privacy
        pass "hard-cut publication recovered automatically through Generic BLS"
        ;;
esac
