#!/usr/bin/env bash
# Candidate-only M01 command-line gate. Run once in every lifecycle pass:
#   sudo bash tests/pre-ship/01-kernel-cmdline-runtime.sh live
#   sudo bash tests/pre-ship/01-kernel-cmdline-runtime.sh fresh-install
#   sudo bash tests/pre-ship/01-kernel-cmdline-runtime.sh reboot
set -euo pipefail

TEST_NAME=01-kernel-cmdline-runtime

fail() { echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2; exit 1; }

[ "$#" -eq 1 ] || {
    echo "usage: $0 {live|fresh-install|reboot}" >&2
    exit 2
}
PASS_ID=$1
case "$PASS_ID" in live|fresh-install|reboot) ;; *) exit 2 ;; esac

if [ "$(id -u)" -ne 0 ]; then
    if sudo -n true >/dev/null 2>&1; then
        exec sudo -n "$0" "$PASS_ID"
    fi
    fail "run as root or establish sudo credentials first"
fi

grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
for tool in journalctl lspci matchpathcon python3 stat systemctl; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing command: $tool"
done

PROJECT_ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
MANIFEST="$PROJECT_ROOT/manifests/kernel-cmdline.tsv"
CONTRACT="$PROJECT_ROOT/tests/01-karg-contract.py"
SOURCE="$PROJECT_ROOT/kickstart/snippets/01-bootloader.ks"
[ -f "$MANIFEST" ] && [ ! -L "$MANIFEST" ] || \
    fail "canonical kernel-command-line manifest missing or symlinked"
[ -f "$CONTRACT" ] && [ ! -L "$CONTRACT" ] || \
    fail "kernel-command-line verifier missing or symlinked"
[ -f "$SOURCE" ] && [ ! -L "$SOURCE" ] || \
    fail "canonical M01 source missing or symlinked"

activation_pending=0
if [ "$PASS_ID" = live ]; then
    grep -qE '(^|[[:space:]])rd\.live\.image([=[:space:]]|$)' /proc/cmdline || \
        fail "live pass lacks rd.live.image"
else
    ! grep -qE '(^|[[:space:]])rd\.live\.image([=[:space:]]|$)' /proc/cmdline || \
        fail "installed pass retains rd.live.image"
    SENTINEL=/var/lib/noid-privacy/.firstboot-cmdline-done
    REBOOT_MARKER=/var/lib/noid-privacy/.firstboot-cmdline-reboot-required
    if [ "$PASS_ID" = fresh-install ] \
            && { [ -e "$REBOOT_MARKER" ] || [ -L "$REBOOT_MARKER" ]; }; then
        activation_pending=1
        [ -f "$REBOOT_MARKER" ] && [ ! -L "$REBOOT_MARKER" ] || \
            fail "firstboot reboot marker is non-regular/symlinked"
        [ "$(stat -c '%U:%G:%a' "$REBOOT_MARKER")" = root:root:600 ] || \
            fail "firstboot reboot marker ownership/mode differs"
        [ ! -e "$SENTINEL" ] && [ ! -L "$SENTINEL" ] || \
            fail "pending firstboot state already carries a success seal"
    else
        [ -f "$SENTINEL" ] && [ ! -L "$SENTINEL" ] || \
            fail "firstboot cmdline sentinel missing/non-regular/symlinked"
        [ "$(stat -c '%U:%G:%a' "$SENTINEL")" = root:root:644 ] || \
            fail "firstboot cmdline sentinel ownership/mode differs"
    fi
    [ "$(systemctl show noid-firstboot-cmdline.service -p LoadState --value)" = loaded ] || \
        fail "noid-firstboot-cmdline.service is not loaded"
    [ "$(systemctl show noid-firstboot-cmdline.service -p Result --value)" = success ] || \
        fail "noid-firstboot-cmdline.service has no successful result"
fi

python3 "$CONTRACT" "$PASS_ID" /proc/cmdline "$MANIFEST" "$SOURCE" || \
    fail "effective arguments or semantic-karg/BLS transport contract differs"

if [ "$PASS_ID" != live ]; then
    command -v noid-status >/dev/null 2>&1 || fail "noid-status missing"
    status_reboot=$(noid-status --json | python3 -c '
import json
import sys
value = json.load(sys.stdin)["updates"]["reboot_required"]
if not isinstance(value, str):
    raise SystemExit("invalid reboot status type")
print(value)
') || fail "noid-status reboot state is unreadable"
    if [ "$activation_pending" -eq 1 ]; then
        required_safe_re='^REQUIRED \+ SAFE \(kernel [A-Za-z0-9._+-]+ → [A-Za-z0-9._+-]+; NVIDIA [A-Za-z0-9._+-]+ → [A-Za-z0-9._+-]+\)$'
        [[ $status_reboot =~ $required_safe_re ]] || \
            fail "noid-status hides the pending first-install activation"
    else
        [ "$status_reboot" = 'not required' ] || \
            fail "noid-status reports a reboot despite sealed firstboot state: $status_reboot"
    fi
fi

# A parameter can match the manifest and still do nothing: amd_iommu=on and
# srbds=on were accepted names whose value the kernel ignored. Every parser
# complaint about this boot's command line blocks the candidate, and so does a
# manifest kernel parameter that the kernel passed on to user space as unknown
# (a misspelled or retired name). Only these five managed families belong to
# user space by design.
USERSPACE_FAMILIES=" rhgb rd.emergency rd.shell systemd.ssh_auto plymouth.use-simpledrm "
kernel_log=$(journalctl -k -b 0 -o cat --no-pager 2>/dev/null) || \
    fail "kernel log for the current boot is unreadable"
[ -n "$kernel_log" ] || fail "kernel log for the current boot is empty"
parser_complaints=$(grep -E 'Unknown option|Ignoring unknown|Invalid option string' \
    <<< "$kernel_log" || true)
[ -z "$parser_complaints" ] || \
    fail "kernel rejected a command-line value: $(head -n 3 <<< "$parser_complaints" | tr '\n' ' ')"
passed_unknown=$(sed -n 's/.*Unknown kernel command line parameters "\(.*\)", will be passed to user space\..*/\1/p' \
    <<< "$kernel_log" | head -n 1)
for token in $passed_unknown; do
    family=${token%%=*}
    [[ $USERSPACE_FAMILIES == *" $family "* ]] && continue
    if awk -F'|' -v family="$family" '
            { split($2, part, "="); if (part[1] == family) found = 1 }
            END { exit !found }' "$MANIFEST"; then
        fail "kernel does not recognize manifest parameter: $token"
    fi
done

cpu_vendor=other
grep -q GenuineIntel /proc/cpuinfo 2>/dev/null && cpu_vendor=Intel
grep -q AuthenticAMD /proc/cpuinfo 2>/dev/null && cpu_vendor=AMD
echo "PASS  $TEST_NAME [$PASS_ID]: security arguments, evidence, native BLS transport and kernel acceptance; cpu_vendor=$cpu_vendor"
