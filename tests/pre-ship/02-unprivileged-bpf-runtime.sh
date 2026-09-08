#!/usr/bin/env bash
# Candidate-only M02 semantic gate. Run in all lifecycle passes:
#   sudo bash tests/pre-ship/02-unprivileged-bpf-runtime.sh live
#   sudo bash tests/pre-ship/02-unprivileged-bpf-runtime.sh fresh-install
#   sudo bash tests/pre-ship/02-unprivileged-bpf-runtime.sh reboot
set -euo pipefail

TEST_NAME=02-unprivileged-bpf-runtime
PASS_ID=${1:-invalid}
fail() { echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2; exit 1; }

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
for tool in python3 setpriv sysctl; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing command: $tool"
done

HARDENING=/etc/sysctl.d/99-hardening.conf
[ -f "$HARDENING" ] && [ ! -L "$HARDENING" ] || \
    fail "installed M02 hardening file missing/non-regular/symlinked"
if grep -Eq '^(net\.ipv4\.tcp_congestion_control|net\.core\.default_qdisc|net\.core\.(rmem_max|wmem_max|netdev_budget|netdev_max_backlog)|net\.ipv4\.tcp_(rmem|wmem|fastopen|mtu_probing|slow_start_after_idle)|vm\.(vfs_cache_pressure|dirty_bytes|dirty_background_bytes|max_map_count|page-cluster|swappiness))[[:space:]]*=' \
        "$HARDENING"; then
    fail "installed M02 file contains an unbenchmarked performance override"
fi

SYSCTL=kernel.unprivileged_bpf_disabled
read_value() { sysctl -n "$SYSCTL"; }
[ "$(read_value)" = 1 ] || fail "$SYSCTL is not irreversible value 1"

# x86_64 is the repository's only release architecture. As uid/gid 65534 with
# all supplementary groups cleared, a minimal BPF_MAP_CREATE must be rejected
# at the bpf() syscall boundary with EPERM.
setpriv --reuid=65534 --regid=65534 --clear-groups \
    python3 - <<'BPF_SYSCALL_PY' || fail "unprivileged bpf() was not rejected with EPERM"
import ctypes
import errno
import struct

SYS_BPF_X86_64 = 321
BPF_MAP_CREATE = 0
BPF_MAP_TYPE_ARRAY = 2
attribute = bytearray(128)
struct.pack_into("IIII", attribute, 0, BPF_MAP_TYPE_ARRAY, 4, 4, 1)
buffer = (ctypes.c_ubyte * len(attribute)).from_buffer(attribute)
libc = ctypes.CDLL(None, use_errno=True)
result = libc.syscall(SYS_BPF_X86_64, BPF_MAP_CREATE,
                      ctypes.byref(buffer), len(attribute))
error = ctypes.get_errno()
raise SystemExit(0 if result == -1 and error == errno.EPERM else 1)
BPF_SYSCALL_PY

# Kernel documentation defines 1 as "disabled without recovery" for the
# running kernel. Attempt the prohibited administrative transition and prove
# both the return code and post-state. If a future kernel unexpectedly accepts
# it, immediately ratchet back to 1 before failing the disposable candidate.
transition_rc=0
sysctl -w "$SYSCTL=0" >/dev/null 2>&1 || transition_rc=$?
after=$(read_value)
if [ "$transition_rc" -eq 0 ] || [ "$after" != 1 ]; then
    sysctl -w "$SYSCTL=1" >/dev/null 2>&1 || true
    fail "administrator reset was accepted or changed state (rc=$transition_rc after=$after)"
fi

echo "PASS  $TEST_NAME [$PASS_ID]: value=1, bpf()=EPERM, root reset rejected"
