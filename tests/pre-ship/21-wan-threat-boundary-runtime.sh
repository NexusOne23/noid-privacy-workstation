#!/usr/bin/env bash
# Candidate-only M06 no-hype boundary gate. Run in all lifecycle passes:
#   sudo bash tests/pre-ship/21-wan-threat-boundary-runtime.sh live
#   sudo bash tests/pre-ship/21-wan-threat-boundary-runtime.sh fresh-install
#   sudo bash tests/pre-ship/21-wan-threat-boundary-runtime.sh reboot
set -euo pipefail

TEST_NAME=21-wan-threat-boundary-runtime
PASS_ID=${1:-invalid}
PROBE_TABLE=noid_unprivileged_boundary_probe

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
for tool in grep nft python3 setpriv stat systemctl wc; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing command: $tool"
done

POLICY=/etc/nftables.d/noid-wan-strict.nft
STATUS=/run/noid-privacy/wan-strict-status
DOC=/usr/share/doc/noid-privacy/wan-egress-strict.md
for path in "$POLICY" "$STATUS" "$DOC"; do
    [ -f "$path" ] && [ ! -L "$path" ] || \
        fail "missing, non-regular or symlinked runtime contract: $path"
done
[ "$(stat -c '%u:%g:%a:%h' "$STATUS")" = 0:0:644:1 ] || \
    fail "runtime mode metadata is not root:root 0644 nlink=1"
IFS= read -r runtime_status < "$STATUS" || \
    fail "runtime mode is not one newline-terminated record"
status_lines=$(wc -l < "$STATUS") || fail "cannot count runtime mode lines"
status_bytes=$(wc -c < "$STATUS") || fail "cannot count runtime mode bytes"
[ "$status_lines" -eq 1 ] \
    && [ "$status_bytes" -eq $((${#runtime_status} + 1)) ] || \
    fail "runtime mode is not exactly one ASCII line"
case "$runtime_status" in
    MODE=DISABLED|MODE=GRACE_BOOTSTRAP|MODE=GRACE_PAUSED|MODE=STRICT|MODE=STRICT_EMPTY)
        note "published postcondition: $runtime_status"
        ;;
    MODE=ERROR) fail "published WAN postcondition is ERROR" ;;
    *) fail "invalid or unavailable published WAN postcondition" ;;
esac

systemctl is-enabled --quiet noid-wan-strict-status-publish.service || \
    fail "boot-complete WAN status publisher is not enabled"
! systemctl is-active --quiet noid-wan-strict-status-publish.service || \
    fail "completed WAN status publisher unexpectedly remains active"
! systemctl is-failed --quiet noid-wan-strict-status-publish.service || \
    fail "boot-complete WAN status publisher is failed"
[ "$(systemctl show -p Result --value \
        noid-wan-strict-status-publish.service 2>/dev/null)" = success ] || \
    fail "boot-complete WAN status publisher lacks a successful result"

if [ "$runtime_status" = MODE=DISABLED ]; then
    ! nft list table inet noid_wan_strict >/dev/null 2>&1 || \
        fail "DISABLED postcondition still has the M06 nft table"
    for unit in noid-wan-strict.service \
                noid-wan-strict-scan-profiles.path \
                noid-wan-strict-endpoint-expiry.timer; do
        unit_state=$(systemctl is-enabled "$unit" 2>/dev/null || true)
        case "$unit_state" in disabled|masked) ;; *)
            fail "DISABLED postcondition leaves $unit enabled"
        esac
        ! systemctl is-active --quiet "$unit" || \
            fail "DISABLED postcondition leaves $unit active"
    done
    for unit in noid-wan-strict-scan-profiles.service \
                noid-wan-strict-endpoint-expiry.service \
                noid-wan-strict-autoresume.timer \
                noid-wan-strict-autoresume.service; do
        ! systemctl is-active --quiet "$unit" || \
            fail "DISABLED postcondition leaves $unit active"
        ! systemctl is-failed --quiet "$unit" || \
            fail "DISABLED postcondition leaves $unit failed"
    done
else
    nft list chain inet noid_wan_strict output >/dev/null 2>&1 || \
        fail "active-policy postcondition lacks the nft inet output hook"
    nft list chain inet noid_wan_strict forward >/dev/null 2>&1 || \
        fail "active-policy postcondition lacks the nft inet forward hook"
    for unit in noid-wan-strict.service \
                noid-wan-strict-scan-profiles.path \
                noid-wan-strict-endpoint-expiry.timer; do
        systemctl is-enabled --quiet "$unit" || \
            fail "active-policy postcondition leaves $unit disabled"
        systemctl is-active --quiet "$unit" || \
            fail "active-policy postcondition leaves $unit inactive"
    done
    for unit in noid-wan-strict-scan-profiles.service \
                noid-wan-strict-endpoint-expiry.service; do
        ! systemctl is-failed --quiet "$unit" || \
            fail "active-policy postcondition leaves $unit failed"
    done
fi
for term in 'not described as malware-proof' AF_PACKET CAP_NET_RAW \
            CAP_NET_ADMIN CAP_SYS_ADMIN 'initial host network stack' \
            'no automatic wall-clock expiry'; do
    grep -Fq "$term" "$DOC" || fail "installed threat boundary omits: $term"
done
note "installed documentation names hook, capability and onboarding boundaries"

# UID/GID 65534 with no supplementary groups or inherited/ambient/bounding
# capabilities must not obtain either IP-raw or Ethernet packet sockets.
setpriv --reuid=65534 --regid=65534 --clear-groups \
    --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
    python3 - <<'RAW_SOCKET_PY' || \
    fail "unprivileged raw/packet socket boundary was not exact"
import errno
import socket

attempts = (
    (socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW, "IPv4 raw"),
    (socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3), "AF_PACKET"),
)
for family, socktype, protocol, label in attempts:
    try:
        candidate = socket.socket(family, socktype, protocol)
    except OSError as exc:
        if exc.errno not in (errno.EPERM, errno.EACCES):
            raise SystemExit(f"{label}: unexpected errno {exc.errno}")
    else:
        candidate.close()
        raise SystemExit(f"{label}: unexpectedly permitted")
RAW_SOCKET_PY
note "UID 65534 cannot create IPv4-raw or AF_PACKET sockets"

# The same capability-empty identity must not mutate the host nft namespace.
# A cleanup trap makes the probe bounded even if a future regression permits
# the command unexpectedly.
cleanup_probe() {
    nft delete table inet "$PROBE_TABLE" >/dev/null 2>&1 || true
}
trap cleanup_probe EXIT
cleanup_probe
if setpriv --reuid=65534 --regid=65534 --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        nft add table inet "$PROBE_TABLE" >/dev/null 2>&1; then
    fail "capability-empty UID 65534 mutated the host nft namespace"
fi
if nft list table inet "$PROBE_TABLE" >/dev/null 2>&1; then
    fail "rejected unprivileged nft probe nevertheless left a table"
fi
trap - EXIT
note "UID 65534 cannot mutate the host nft namespace"

echo "PASS  $TEST_NAME [$PASS_ID]: mode=${runtime_status#MODE=}, raw=EPERM, nft-mutation=EPERM"
