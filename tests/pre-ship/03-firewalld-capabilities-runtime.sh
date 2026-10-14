#!/usr/bin/env bash
# Candidate-only privilege and native reload gate, in every boot lifecycle.
set -euo pipefail
export LC_ALL=C PATH=/usr/sbin:/usr/bin BASH_ENV=/dev/null ENV=/dev/null
IFS=$' \t\n'
umask 077

TEST_NAME=03-firewalld-capabilities-runtime
PASS_ID=${1:-invalid}
fail() { echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2; exit 1; }
[[ $# -eq 1 ]] || exit 2
case "$PASS_ID" in live|fresh-install|reboot) ;; *) exit 2 ;; esac
[[ $(id -u) -eq 0 ]] || fail 'run with sudo'
grep -qx 'ID=noid-privacy-workstation' /etc/os-release || fail 'wrong candidate OS'
[[ $(getenforce) == Enforcing ]] || fail 'SELinux is not enforcing'
rpm -q libcap-ng-python3 >/dev/null || fail 'capability binding missing'

check_lan_policy() {
    local info active
    # M03 drops selected destinations/ports, then continues public egress.
    # firewalld supports --get-target only for permanent configuration.
    info=$(firewall-cmd --info-policy=block-lan-out) || fail 'cannot query runtime LAN policy'
    [[ $(awk '$1 == "target:" { count++; target=$2 }
        END { if (count != 1) exit 1; print target }' <<< "$info") == CONTINUE ]] ||
        fail 'runtime LAN policy target differs from Module 03'
    [[ $(firewall-cmd --permanent --policy=block-lan-out --get-target) == CONTINUE ]] ||
        fail 'permanent LAN policy target differs from Module 03'
    active=$(firewall-cmd --get-active-policies) || fail 'cannot query active policies'
    grep -qx block-lan-out <<< "$active" || fail 'LAN policy is inactive'
}

check_daemon() {
    local pid
    systemctl is-active --quiet firewalld.service || fail 'firewalld inactive'
    firewall-cmd --state >/dev/null || fail 'firewalld not ready'
    pid=$(systemctl show --value -p MainPID firewalld.service)
    [[ $pid =~ ^[1-9][0-9]*$ ]] || fail 'invalid daemon PID'
    python3 - "$pid" <<'CAPABILITIES_PY' || fail 'daemon capability contract failed'
from pathlib import Path
import sys


def check_status(text):
    rows = dict(line.split(':', 1) for line in text.splitlines() if ':' in line)
    # Linux UAPI bits: NET_ADMIN=12, NET_RAW=13, SYS_MODULE=16.
    expected = (1 << 12) | (1 << 13) | (1 << 16)
    assert [int(x) for x in rows['Uid'].split()] == [0, 0, 0, 0], 'unexpected daemon UID'
    for field in ('CapEff', 'CapPrm', 'CapBnd'):
        assert int(rows[field], 16) == expected, f'{field}: expected only three capabilities'
    for field in ('CapInh', 'CapAmb'):
        assert int(rows[field], 16) == 0, f'{field}: unexpected inherited/ambient capability'


def main():
    process = Path('/proc') / sys.argv[1]
    check_status((process / 'status').read_text())
    threads = sorted((process / 'task').glob('*/status'))
    assert threads, 'no daemon threads'
    for thread in threads:
        check_status(thread.read_text())


if __name__ == '__main__':
    main()
CAPABILITIES_PY
    [[ $(systemctl show --value -p MainPID firewalld.service) == "$pid" ]] ||
        fail 'daemon restarted while inspected'
    [[ $(firewall-cmd --get-default-zone) == drop ]] || fail 'default zone is not drop'
    check_lan_policy
}

check_daemon
firewall-cmd --reload >/dev/null || fail 'native reload failed'
check_daemon
echo "PASS  $TEST_NAME [$PASS_ID]: exact daemon/thread capabilities and reload"
