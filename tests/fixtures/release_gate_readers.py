#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Native shell counterexamples for candidate evidence readers and recovery."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

root = Path(sys.argv[1])
record = '--record' in sys.argv[2:]
results = []

def function(source, name):
    match = re.search(r'^' + re.escape(name) + r'\(\) \{\n.*?^\}', source, re.M | re.S)
    assert match, name
    return match.group() + '\n'

with tempfile.TemporaryDirectory(prefix='noid-gate-readers-', dir='/var/tmp') as scratch:
    work = Path(scratch)
    def run(label, body, mode, expected_error=False, retained=None):
        script = work / 'probe.sh'
        script.write_text('set -euo pipefail\nfail(){ echo "$*" >&2; exit 1; }\n' + body)
        env = dict(os.environ, TMPDIR=str(work), FIX_MODE=mode)
        result = subprocess.run(['/bin/bash', str(script)], env=env, capture_output=True, timeout=5)
        good = (result.returncode != 0) if expected_error else (result.returncode == 0)
        if retained is not None:
            good = good and retained.is_file()
        results.append(dict(test=label, case=mode, passed=good, exit=result.returncode))

    webui = (root / 'tests/pre-ship/17-liveinst-webui-runtime.sh').read_text()
    body = '''ss(){
    [ "$FIX_MODE" != query-error ] || return 2
    [ "$FIX_MODE" != present ] || printf 'listener\n'
    return 0
}
''' + function(webui, 'listener_rows') + 'rows=$(listener_rows)\n'
    for mode in ('empty', 'present', 'query-error'):
        run('WebUI listener reader', body, mode, mode == 'query-error')

    chrony = (root / 'tests/pre-ship/11-chrony-runtime.sh').read_text()
    body = '''journalctl(){
    case "$FIX_MODE:$*" in
        service-error:*" -u "*|kernel-error:*" -k "*) return 2 ;;
    esac
    echo 'clean journal fixture'
}
''' + function(chrony, 'chronyd_seccomp_failure') + function(chrony, 'check_no_seccomp_failure') + 'check_no_seccomp_failure\n'
    for mode in ('clean', 'service-error', 'kernel-error'):
        run('chrony journal capture', body, mode, mode != 'clean')

    live = work / 'chrony-state'
    backup = work / 'backup-root'
    live.mkdir()
    cleanup = function(chrony, 'cleanup').replace('/var/lib/chrony', str(live))
    for mode in ('restored', 'restore-error', 'stop-error', 'inventory-error'):
        if backup.exists():
            shutil.rmtree(backup)
        backup.mkdir()
        cookies = backup / 'cookies'
        cookies.mkdir()
        original = cookies / 'source.nts'
        original.write_bytes(b'fixture-cookie')
        body = '''systemctl(){ [ "$FIX_MODE:$1" != stop-error:stop ]; }
find(){ [ "$FIX_MODE:$1" != "inventory-error:$cookie_backup" ] || return 2; /usr/bin/find "$@"; }
mv(){ [ "$FIX_MODE" != restore-error ] || return 1; /bin/mv "$@"; }
TMPDIR="$TMPDIR/backup-root"
cookie_backup="$TMPDIR/cookies"
restore_cookie_backup=1
restart_service_on_cleanup=0
''' + cleanup + 'cleanup 0\n'
        run('chrony restore cleanup', body, mode, mode != 'restored', original if mode != 'restored' else live / 'source.nts')

    installed = (root / 'tests/pre-ship/41-installed-firstboot-runtime.sh').read_text()
    block = installed.split('# M41_INSTALLER_PACKAGE_GATE_BEGIN\n', 1)[1].split('# M41_INSTALLER_PACKAGE_GATE_END', 1)[0]
    body = '''tmp_dir=$TMPDIR
rpm(){
    [ "$FIX_MODE" != query-error ] || return 2
    case "$1" in
        -qa) printf 'bash\ndbus-tools\n'; [ "$FIX_MODE" != remnant ] || echo anaconda ;;
        -q) [ "$FIX_MODE:${2:-}" = remnant:anaconda ]; return ;;
        *) return 3 ;;
    esac
    return 0
}
dnf5(){ case "$*" in *--userinstalled*) echo dbus-tools;; esac; return 0; }
''' + block
    for mode in ('clean', 'remnant', 'query-error'):
        run('installed package inventory', body, mode, mode != 'clean')

    block = installed.split('rpm_verify=$tmp_dir/rpm-verify\n', 1)[1].split('\nclassify_m41_rpm_verify', 1)[0]
    body = '''tmp_dir=$TMPDIR
rpm_verify=$tmp_dir/rpm-verify
rpm(){
    case "$FIX_MODE" in
        clean) return 0 ;;
        drift) echo '.M....... /etc/sysconfig/fixture'; return 1 ;;
        query-error) echo 'error: cannot read database' >&2; return 1 ;;
    esac
}
''' + block
    for mode in ('clean', 'drift', 'query-error'):
        run('installed RPM verify capture', body, mode, mode == 'query-error')

print(json.dumps(results, indent=2))
if not record:
    assert all(item['passed'] for item in results), 'candidate gate lost failed evidence or recovery backup'
