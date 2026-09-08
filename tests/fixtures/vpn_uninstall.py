#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise extracted VPN uninstall branches with no host mutation authority."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

source = Path(sys.argv[1]).read_text()
record = '--record' in sys.argv[2:]
results = []
with tempfile.TemporaryDirectory(prefix='noid-vpn-remove-', dir='/var/tmp') as scratch:
    root = Path(scratch)
    for vendor, marker in [('Proton', 'PROTONVPN_INSTALL_EOF'), ('Mullvad', 'MULLVAD_INSTALL_EOF')]:
        payload = source.split("<<'" + marker + "'\n", 1)[1].split('\n' + marker, 1)[0]
        block = payload.split('if [ "$ACTION" = uninstall ]; then\n', 1)[1].split('\nfi\n', 1)[0]
        query = re.search(r'^pkg_installed\(\) \{\n.*?^\}', payload, re.M | re.S)
        script = root / 'uninstall'
        script.write_text('''#!/bin/bash
set -euo pipefail
fmt_banner(){ :; }; fmt_step(){ :; }
fmt_info(){ echo "info: $*"; }; fmt_ok(){ echo "ok: $*"; }
fmt_done(){ echo "done: $*"; }
fail(){ echo "error: $*" >&2; exit 1; }
sudo(){
    case "$1" in
        /usr/bin/env|rpm)
            if [ "$FIX_MODE" = query-error ]; then echo 'error: cannot open rpmdb' >&2; return 1; fi
            if [ -e "$FIX_INSTALLED" ]; then echo "$PKG"; return 0; fi
            echo "package $PKG is not installed"; return 1 ;;
        dnf)
            case "$FIX_MODE" in
                transaction-error) return 1 ;;
                remains-installed) return 0 ;;
                *) /bin/rm -f -- "$FIX_INSTALLED" ;;
            esac ;;
        rm)
            [ "$FIX_MODE" != remove-error ] || return 1
            [ "$*" = "rm -f -- $REPO_FILE" ] || return 97
            /bin/rm -f -- "$REPO_FILE" ;;
        *) return 98 ;;
    esac
}
''' + (query.group() + '\n' if query else '') + block + '\n')
        for mode in ('absent', 'installed', 'query-error', 'transaction-error', 'remains-installed', 'remove-error', 'broken-link'):
            repo = root / 'vendor.repo'
            installed = root / 'installed'
            repo.unlink(missing_ok=True)
            installed.unlink(missing_ok=True)
            if mode == 'broken-link':
                repo.symlink_to(root / 'missing')
            elif mode != 'absent':
                repo.write_text('private fixture\n')
            if mode in ('installed', 'transaction-error', 'remains-installed'):
                installed.touch()
            env = dict(os.environ, PKG='fixture-vpn', REPO_FILE=str(repo), FIX_MODE=mode, FIX_INSTALLED=str(installed))
            run = subprocess.run(['/bin/bash', str(script)], env=env, capture_output=True, text=True, timeout=5)
            error = mode in ('query-error', 'transaction-error', 'remains-installed', 'remove-error')
            passed = (run.returncode != 0) if error else (run.returncode == 0 and not os.path.lexists(repo))
            results.append(dict(vendor=vendor, case=mode, passed=passed, exit=run.returncode, repo_remains=os.path.lexists(repo)))
print(json.dumps(results, indent=2))
if not record:
    assert all(item['passed'] for item in results), 'VPN uninstall error or completion evidence was lost'
