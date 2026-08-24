#!/usr/bin/env bash
# Candidate-only M07 no-hype runtime gate. Run in all lifecycle passes:
#   sudo bash tests/pre-ship/07-tcp-timestamps-runtime.sh live
#   sudo bash tests/pre-ship/07-tcp-timestamps-runtime.sh fresh-install
#   sudo bash tests/pre-ship/07-tcp-timestamps-runtime.sh reboot
set -euo pipefail

TEST_NAME=07-tcp-timestamps-runtime
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
for tool in grep stat sysctl; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing command: $tool"
done

M07_SYSCTL=/etc/sysctl.d/98-privacy-network.conf
[ -f "$M07_SYSCTL" ] && [ ! -L "$M07_SYSCTL" ] || \
    fail "M07 sysctl file is missing, non-regular or symlinked"
[ "$(stat -c '%u:%g:%a:%h' "$M07_SYSCTL")" = 0:0:640:1 ] || \
    fail "M07 sysctl metadata is not root:root 0640 nlink=1"
grep -Eq '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=[[:space:]]*0([[:space:]]*(#.*)?)?$' \
    "$M07_SYSCTL" || fail "M07 ip_forward boot default is missing"
if grep -Eq '^[[:space:]]*net\.ipv4\.tcp_timestamps[[:space:]]*=' "$M07_SYSCTL"; then
    fail "M07 still overrides the maintained TCP timestamp policy"
fi

# Reject any effective local/vendor regression to the retired value. Vendor
# files may explicitly retain value 1; NoID Privacy merely declines to override it.
for directory in /etc/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d \
                 /usr/lib/sysctl.d; do
    [ -d "$directory" ] || continue
    if grep -RHE '^[[:space:]]*net\.ipv4\.tcp_timestamps[[:space:]]*=[[:space:]]*0([[:space:]]*(#.*)?)?$' \
            "$directory" 2>/dev/null; then
        fail "installed sysctl tree contains a timestamp-disable override"
    fi
done
if [ -f /etc/sysctl.conf ] && \
   grep -Eq '^[[:space:]]*net\.ipv4\.tcp_timestamps[[:space:]]*=[[:space:]]*0([[:space:]]*(#.*)?)?$' \
       /etc/sysctl.conf; then
    fail "/etc/sysctl.conf contains a timestamp-disable override"
fi

[ "$(sysctl -n net.ipv4.tcp_timestamps)" = 1 ] || \
    fail "effective tcp_timestamps is not Linux's randomized value 1"

echo "PASS  $TEST_NAME [$PASS_ID]: tcp_timestamps=1, no disable override"
