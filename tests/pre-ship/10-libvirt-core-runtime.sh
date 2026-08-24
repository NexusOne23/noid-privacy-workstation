#!/usr/bin/env bash
# Candidate-only libvirt core-limit runtime gate for Module 10/17.
# It starts one transient, networkless, diskless 64 MiB QEMU process through
# each driver mode, proves the effective process boundary, and removes both.
set -euo pipefail
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin

TEST_NAME=10-libvirt-core-runtime
PASS_ID=${1:-}
case "$PASS_ID" in
    live|fresh-install|reboot) ;;
    *)
        echo "Usage: bash $0 {live|fresh-install|reboot}" >&2
        exit 2
        ;;
esac

fail() { echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2; exit 1; }
[[ $EUID -ne 0 ]] || fail "run as the normal desktop user, not root"

for required_command in cat grep id mktemp prlimit rm sh sleep stat sudo tr \
        virsh virt-xml-validate xargs; do
    command -v "$required_command" >/dev/null 2>&1 || \
        fail "required command missing: $required_command"
done
sudo -n true >/dev/null 2>&1 || fail "passwordless candidate sudo unavailable"
[[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || \
    fail "release gate requires user-accessible /dev/kvm"

system_conf=/etc/libvirt/qemu.conf
session_dir=${XDG_CONFIG_HOME:-$HOME/.config}/libvirt
session_conf=$session_dir/qemu.conf
doc=/usr/share/doc/noid-privacy/10-libvirt-core-dumps.md
user_name=$(id -un)
group_name=$(id -gn)

check_config() {
    local scope=$1 file=$2 metadata=$3 prefix=()
    [[ $scope == system ]] && prefix=(sudo -n)
    "${prefix[@]}" test -f "$file" || fail "$scope qemu.conf is not regular"
    "${prefix[@]}" test ! -L "$file" || fail "$scope qemu.conf is symlinked"
    [[ $("${prefix[@]}" stat -Lc '%U:%G:%a:%h' "$file") == "$metadata" ]] || \
        fail "$scope qemu.conf metadata differs"
    [[ $("${prefix[@]}" grep -Ec \
        '^[[:space:]]*max_core[[:space:]]*=' "$file") -eq 1 ]] || \
        fail "$scope qemu.conf max_core is not unique"
    [[ $("${prefix[@]}" grep -Ec \
        '^[[:space:]]*dump_guest_core[[:space:]]*=' "$file") -eq 1 ]] || \
        fail "$scope qemu.conf dump_guest_core is not unique"
    "${prefix[@]}" grep -Eq \
        '^[[:space:]]*max_core[[:space:]]*=[[:space:]]*0[[:space:]]*(#.*)?$' \
        "$file" || fail "$scope max_core is not zero"
    "${prefix[@]}" grep -Eq \
        '^[[:space:]]*dump_guest_core[[:space:]]*=[[:space:]]*0[[:space:]]*(#.*)?$' \
        "$file" || fail "$scope dump_guest_core is not zero"
}

check_config system "$system_conf" root:root:644:1
[[ -d $session_dir && ! -L $session_dir \
   && $(stat -Lc '%U:%G:%a' "$session_dir") == "$user_name:$group_name:700" ]] || \
    fail "session libvirt directory metadata differs"
check_config session "$session_conf" "$user_name:$group_name:600:1"
[[ -f $doc && ! -L $doc \
   && $(stat -Lc '%U:%G:%a:%h' "$doc") == root:root:644:1 ]] || \
    fail "libvirt core-boundary documentation missing"
[[ ! -e $system_conf.rpmnew && ! -e $system_conf.rpmsave ]] || \
    fail "unreviewed libvirt qemu.conf RPM sibling exists"

workdir=$(mktemp -d /var/tmp/noid-libvirt-core-runtime.XXXXXX)
system_name="noid-core-system-${UID}-$$"
session_name="noid-core-session-${UID}-$$"

session_virsh() { virsh -c qemu:///session "$@"; }
system_virsh() { sudo -n virsh -c qemu:///system "$@"; }

cleanup() {
    system_virsh dominfo "$system_name" >/dev/null 2>&1 \
        && system_virsh destroy "$system_name" >/dev/null 2>&1 || true
    session_virsh dominfo "$session_name" >/dev/null 2>&1 \
        && session_virsh destroy "$session_name" >/dev/null 2>&1 || true
    rm -rf -- "$workdir"
}
trap cleanup EXIT INT TERM

write_probe_xml() {
    local name=$1 output=$2
    # The documented release environment is KVM. Forcing TCG here would label
    # the system probe svirt_tcg_t and can make Fedora's systemd-machined
    # integration emit an unrelated AVC while the probe is destroyed. KVM
    # still starts the same qemu-system process whose libvirt core boundary is
    # under test.
    cat > "$output" <<PROBE_XML_EOF
<domain type='kvm'>
  <name>${name}</name>
  <memory unit='MiB'>64</memory>
  <currentMemory unit='MiB'>64</currentMemory>
  <vcpu placement='static'>1</vcpu>
  <os>
    <type arch='x86_64' machine='pc'>hvm</type>
    <boot dev='hd'/>
  </os>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>destroy</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <controller type='pci' model='pci-root'/>
    <memballoon model='none'/>
  </devices>
</domain>
PROBE_XML_EOF
    virt-xml-validate "$output" domain >/dev/null || \
        fail "generated $name XML does not validate"
}

find_session_qemu_pid() {
    local name=$1 proc cmd pid
    for proc in /proc/[0-9]*/cmdline; do
        [[ -r $proc ]] || continue
        cmd=$(tr '\0' ' ' < "$proc" 2>/dev/null || true)
        if [[ $cmd == /usr/bin/qemu-system-x86_64* \
           && $cmd == *"guest=${name},"* ]]; then
            pid=${proc#/proc/}
            printf '%s\n' "${pid%/cmdline}"
            return 0
        fi
    done
    return 1
}

check_qemu_process() {
    local scope=$1 pid=$2 limits cmdline
    if [[ $scope == system ]]; then
        limits=$(sudo -n prlimit --pid "$pid" --core --noheadings \
            --output SOFT,HARD | xargs)
        cmdline=$(sudo -n sh -c "tr '\\0' ' ' < '/proc/$pid/cmdline'")
    else
        limits=$(prlimit --pid "$pid" --core --noheadings \
            --output SOFT,HARD | xargs)
        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline")
    fi
    [[ $limits == '0 0' ]] || fail "$scope QEMU core limit differs: $limits"
    [[ $cmdline == *dump-guest-core=off* ]] || \
        fail "$scope QEMU lacks dump-guest-core=off"
}

system_xml=$workdir/system.xml
session_xml=$workdir/session.xml
write_probe_xml "$system_name" "$system_xml"
write_probe_xml "$session_name" "$session_xml"
system_virsh dominfo "$system_name" >/dev/null 2>&1 \
    && fail "system probe domain already exists"
session_virsh dominfo "$session_name" >/dev/null 2>&1 \
    && fail "session probe domain already exists"

system_virsh create "$system_xml" >/dev/null || fail "system probe failed to start"
[[ $(system_virsh domstate "$system_name" | xargs) == running ]] || \
    fail "system probe is not running"
system_pid=
for _ in {1..20}; do
    system_pid=$(sudo -n sh -c \
        "cat '/run/libvirt/qemu/${system_name}.pid' 2>/dev/null" || true)
    [[ -n $system_pid ]] && break
    sleep 0.1
done
[[ $system_pid =~ ^[1-9][0-9]*$ ]] || fail "system QEMU PID unavailable"
check_qemu_process system "$system_pid"
system_virsh destroy "$system_name" >/dev/null || fail "cannot remove system probe"

session_virsh create "$session_xml" >/dev/null || fail "session probe failed to start"
[[ $(session_virsh domstate "$session_name" | xargs) == running ]] || \
    fail "session probe is not running"
session_pid=
for _ in {1..20}; do
    session_pid=$(find_session_qemu_pid "$session_name" || true)
    [[ -n $session_pid ]] && break
    sleep 0.1
done
[[ $session_pid =~ ^[1-9][0-9]*$ ]] || fail "session QEMU PID unavailable"
check_qemu_process session "$session_pid"
session_virsh destroy "$session_name" >/dev/null || \
    fail "cannot remove session probe"

system_virsh dominfo "$system_name" >/dev/null 2>&1 \
    && fail "system probe survived destroy"
session_virsh dominfo "$session_name" >/dev/null 2>&1 \
    && fail "session probe survived destroy"
trap - EXIT INT TERM
rm -rf -- "$workdir"

echo "PASS  $TEST_NAME [$PASS_ID]: system/session QEMU core=0/0; transient probes removed"
