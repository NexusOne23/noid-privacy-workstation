#!/bin/bash
# Exercise the post-activation revalidation hand-off with the actual generated
# dispatcher and the actual helper, against isolated commands.
#
# NetworkManager starts a no-wait script at once but holds the same event's
# awaited scripts, and every later event, until it exits. The dispatcher must
# therefore keep every event-time gate, hand only the bounded transaction to a
# per-event unit, fall back to the in-dispatcher transaction when the hand-off
# is unavailable, and never hand off pre-up. The helper must accept only a
# root-private closed request and apply the same outcome rule: only a contested
# gateway identity (exit 2) disconnects the link.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
test_start "M04 post-activation revalidation hand-off"
fixture=$(make_exec_tmpdir 04-arp-handoff)
trap 'rm -rf "$fixture"' EXIT
KS_FILE="$(find_project_root)/kickstart/snippets/04-arp-hardening.ks"
extract_heredoc "$KS_FILE" NM_TEMPLATE_EOF "$fixture/template"
extract_heredoc "$KS_FILE" ARP_REVALIDATE_EOF "$fixture/helper"
if python3 - "$fixture" <<'PY'
import os
from pathlib import Path
import re
import subprocess
import sys

root = Path(sys.argv[1])
bindir = root / 'bin'
bindir.mkdir()
runtime = root / 'run'
runtime.mkdir()
runtime.chmod(0o755)
spool = runtime / 'arp-revalidate'
state = root / 'state'
state.mkdir()
sysnet = root / 'sys/class/net'
(sysnet / 'eth0/device').mkdir(parents=True)
calls = root / 'calls'
owner = f'{os.getuid()}:{os.getgid()}:'
uuid = '11111111-2222-4333-8444-555555555555'
token_re = re.compile(r'^--no-ask-password start --no-block '
                      r'noid-arp-revalidate@([0-9]{1,20}-[0-9]{1,10})\.service$')

def executable(name, body):
    path = bindir / name
    path.write_text('#!/bin/bash\nset -euo pipefail\n' + body + '\n')
    path.chmod(0o755)
    return str(path)

# tests/lib.sh exports a `logger` shim that suffixes the tag with `-test` and
# forwards to NOID_TEST_LOGGER_BACKEND; point that backend at the recorder.
logger = executable('logger', 'printf "logger:%s\\n" "$*" >> "$FIXTURE/calls"')
nmcli = executable('nmcli', 'printf "nmcli:%s\\n" "$*" >> "$FIXTURE/calls"')
systemctl = executable('systemctl', 'printf "systemctl:%s\\n" "$*" >> "$FIXTURE/calls"; '
                       'exit "${SYSTEMCTL_RC:-0}"')
readiness = executable('readiness', 'printf "readiness:%s\\n" "$*" >> "$FIXTURE/calls"')
guard = executable('guard', ':')
arp = executable('arp', 'printf "refresh:%s:%s:%s\\n" "${NOID_ARP_IFACE:-}" '
                 '"${NOID_ARP_GATEWAY_IP:-}" "$*" >> "$FIXTURE/calls"; '
                 'exit "${REFRESH_RC:-0}"')

dispatcher_source = (root / 'template').read_text()
for old, new in {
    '@@WAN_IFACE@@': 'eth0', '@@GATEWAY_IP@@': '192.0.2.1',
    '@@GATEWAY_MAC@@': '02:00:00:00:00:01',
    '/usr/local/libexec/noid-network-readiness': readiness,
    '/usr/local/sbin/noid-arp-state-guard.sh': guard,
    '/usr/local/sbin/noid-arp-hardening.sh': arp,
    '/usr/bin/nmcli': nmcli,
    '/usr/bin/systemctl': systemctl,
    '/var/lib/noid-privacy': str(state),
    '/run/noid-privacy': str(runtime),
    '/sys/class/net': str(sysnet),
    '0:0:': owner,
    'chown root:root "$staged"': ':',
}.items():
    assert old in dispatcher_source, old
    dispatcher_source = dispatcher_source.replace(old, new)
helper_source = (root / 'helper').read_text()
for old, new in {
    '/usr/local/sbin/noid-arp-hardening.sh': arp,
    '/usr/bin/nmcli': nmcli,
    '/run/noid-privacy': str(runtime),
    '0:0:': owner,
}.items():
    assert old in helper_source, old
    helper_source = helper_source.replace(old, new)
for name, source in (('dispatcher', dispatcher_source), ('helper.sh', helper_source)):
    path = root / name
    path.write_text(source)
    path.chmod(0o755)
    subprocess.run(['bash', '-n', str(path)], check=True)
assert '/usr/bin/systemctl' not in dispatcher_source

(state / 'arp-hardening.state').write_text(
    'ENABLED=1\nWAN_IFACE=eth0\nGATEWAY_IP=192.0.2.1\n'
    'GATEWAY_MAC=02:00:00:00:00:01\nLEARNED_AT=2026-01-01T00:00:00Z\n')

def env(**extra):
    result = dict(os.environ, PATH=str(bindir) + ':' + os.environ['PATH'],
                  FIXTURE=str(root), CONNECTION_UUID=uuid,
                  NOID_TEST_LOGGER_BACKEND=logger)
    result.update({key: str(value) for key, value in extra.items()})
    return result

def requests():
    if not spool.exists():
        return []
    return sorted(p for p in spool.iterdir() if p.is_file())

def clear_spool():
    for request in requests():
        request.unlink()

def dispatch(event, gateway='192.0.2.1', script='dispatcher', **extra):
    calls.write_text('')
    proc = subprocess.run(['bash', str(root / script), 'eth0', event],
                          env=env(IP4_GATEWAY=gateway, **extra),
                          capture_output=True, timeout=20)
    return proc.returncode, calls.read_text().splitlines()

def handed_off(lines):
    return [m.group(1) for line in lines if line.startswith('systemctl:')
            for m in [token_re.match(line[len('systemctl:'):])] if m]

def check(label, condition, detail=None):
    assert condition, (label, detail)
    print('PASS:', label)

# --- dispatcher: an available hand-off ------------------------------------
clear_spool()
rc, lines = dispatch('up')
tokens = handed_off(lines)
check('up returns at once after the hand-off', rc == 0, lines)
check('up retires readiness at event time', 'readiness:offline' in lines, lines)
check('up hands exactly one opaque token to the unit manager',
      len(tokens) == 1 and len([l for l in lines if l.startswith('systemctl:')]) == 1, lines)
check('up runs no transaction inside the dispatcher',
      not [l for l in lines if l.startswith('refresh:')], lines)
check('a handed-off up never disconnects', not [l for l in lines if l.startswith('nmcli:')], lines)
pending = requests()
check('the hand-off publishes one request named by its token',
      [p.name for p in pending] == [tokens[0] + '.request'], pending)
check('the request carries the exact event in its closed schema',
      pending[0].read_text() == 'IFACE=eth0\nGATEWAY_IP=192.0.2.1\nACTION=up\n')
check('the request is owner-only', (pending[0].stat().st_mode & 0o777) == 0o600)
check('the spool is owner-only', (spool.stat().st_mode & 0o777) == 0o700)
check('the hand-off is journaled by interface',
      'logger:-t noid-arp-dispatcher-test revalidation handed off: interface=eth0' in lines, lines)
check('the journal and unit name carry no gateway address',
      not any('192.0.2.1' in l for l in lines if not l.startswith('refresh:')), lines)
up_request = pending[0]

rc, lines = dispatch('dhcp4-change')
tokens = handed_off(lines)
check('a renewal of the active link is handed off too', rc == 0 and len(tokens) == 1, lines)
check('the renewal request names its own event',
      (spool / (tokens[0] + '.request')).read_text()
      == 'IFACE=eth0\nGATEWAY_IP=192.0.2.1\nACTION=dhcp4-change\n')
check('each event keeps its own request', len(requests()) == 2)

# --- dispatcher: pre-up stays awaited --------------------------------------
clear_spool()
rc, lines = dispatch('pre-up', gateway='192.0.2.2', REFRESH_RC=0)
check('a pre-up gateway transition revalidates inside the dispatcher',
      rc == 0 and 'refresh:eth0:192.0.2.2:refresh' in lines, lines)
check('pre-up never queues a unit', not handed_off(lines) and not requests(), lines)

# --- dispatcher: an unavailable hand-off -----------------------------------
dispatch('up')                      # republish the activation marker
clear_spool()
for refresh_rc, want_rc, want_disconnect in ((0, 0, False), (73, 1, False), (2, 1, True)):
    rc, lines = dispatch('dhcp4-change', SYSTEMCTL_RC=1, REFRESH_RC=refresh_rc)
    label = f'unavailable hand-off, tool exit {refresh_rc}'
    check(f'{label}: the dispatcher revalidates in-process',
          'refresh:eth0:192.0.2.1:refresh' in lines and rc == want_rc, (rc, lines))
    check(f'{label}: the fallback is visible',
          'logger:-t noid-arp-dispatcher-test revalidation hand-off unavailable; '
          'revalidating in the dispatcher' in lines, lines)
    check(f'{label}: disconnect only for a contested identity',
          ('nmcli:device disconnect eth0' in lines) == want_disconnect, lines)
    check(f'{label}: no request is left behind', not requests())

# --- dispatcher: an untrusted spool is never used --------------------------
spool.rmdir()
elsewhere = root / 'elsewhere'
elsewhere.mkdir(mode=0o700)
spool.symlink_to(elsewhere)
rc, lines = dispatch('dhcp4-change', REFRESH_RC=0)
check('a symlinked spool forces the in-dispatcher path',
      rc == 0 and not handed_off(lines) and 'refresh:eth0:192.0.2.1:refresh' in lines, lines)
check('nothing is written through a symlinked spool', not list(elsewhere.iterdir()))
spool.unlink()
spool.mkdir(mode=0o755)
spool.chmod(0o755)
rc, lines = dispatch('dhcp4-change', REFRESH_RC=0)
check('a group/world-readable spool forces the in-dispatcher path',
      rc == 0 and not handed_off(lines) and 'refresh:eth0:192.0.2.1:refresh' in lines, lines)
spool.chmod(0o700)

# --- helper ----------------------------------------------------------------
def helper(token, body=None, mode=0o600, **extra):
    calls.write_text('')
    if body is not None:
        request = spool / f'{token}.request'
        request.write_text(body)
        request.chmod(mode)
    proc = subprocess.run(['bash', str(root / 'helper.sh'), token],
                          env=env(**extra), capture_output=True, timeout=20)
    return proc.returncode, calls.read_text().splitlines()

good = 'IFACE=eth0\nGATEWAY_IP=192.0.2.1\nACTION=up\n'
for refresh_rc, want_rc, want_disconnect in ((0, 0, False), (1, 1, False),
                                              (73, 1, False), (2, 1, True)):
    rc, lines = helper('100-1', good, REFRESH_RC=refresh_rc)
    label = f'helper, tool exit {refresh_rc}'
    check(f'{label}: runs the exact event transaction',
          [l for l in lines if l.startswith('refresh:')] == ['refresh:eth0:192.0.2.1:refresh'], lines)
    check(f'{label}: reports the outcome', rc == want_rc, (rc, lines))
    check(f'{label}: disconnect only for a contested identity',
          [l for l in lines if l.startswith('nmcli:')]
          == (['nmcli:device disconnect eth0'] if want_disconnect else []), lines)
    check(f'{label}: the request is consumed', not (spool / '100-1.request').exists())
    check(f'{label}: the outcome is journaled',
          any(l.startswith('logger:-t noid-arp-dispatcher-test ') for l in lines), lines)
    check(f'{label}: the journal carries no gateway address',
          not any('192.0.2.1' in l for l in lines if l.startswith('logger:')), lines)

rc, lines = helper('101-1', good.replace('ACTION=up', 'ACTION=dhcp4-change'))
check('helper accepts a renewal request', rc == 0 and 'refresh:eth0:192.0.2.1:refresh' in lines, lines)

for token in ('', 'abc', '1', '../1-1', '1-1/x', '1-1 2-2', '1' * 21 + '-1'):
    rc, lines = helper(token)
    check(f'helper rejects token {token!r}',
          rc == 2 and not [l for l in lines if l.startswith('refresh:')], lines)
rc, lines = helper('102-1')
check('helper rejects a missing request', rc == 2 and not [l for l in lines if l.startswith('refresh:')], lines)

rc, lines = helper('103-1', good, mode=0o644)
check('helper rejects a readable request without acting',
      rc == 2 and not [l for l in lines if l.startswith('refresh:')], lines)
(spool / '103-1.request').unlink()
target = root / 'target.request'
target.write_text(good)
target.chmod(0o600)
(spool / '104-1.request').symlink_to(target)
rc, lines = helper('104-1')
check('helper rejects a symlinked request',
      rc == 2 and not [l for l in lines if l.startswith('refresh:')] and target.exists(), lines)
(spool / '104-1.request').unlink()

for label, body in (
        ('an extra key', good + 'EXTRA=1\n'),
        ('a missing key', 'IFACE=eth0\nGATEWAY_IP=192.0.2.1\n'),
        ('reordered keys', 'GATEWAY_IP=192.0.2.1\nIFACE=eth0\nACTION=up\n'),
        ('no trailing newline', good.rstrip('\n')),
        ('a non-canonical gateway', good.replace('192.0.2.1', '192.000.2.1')),
        ('the unspecified gateway', good.replace('192.0.2.1', '0.0.0.0')),
        ('an IPv6 gateway', good.replace('192.0.2.1', '2001:db8::1')),
        ('a pre-up action', good.replace('ACTION=up', 'ACTION=pre-up')),
        ('an unsafe interface', good.replace('IFACE=eth0', 'IFACE=../eth0')),
        ('an empty value', good.replace('IFACE=eth0', 'IFACE=')),
        ('a non-ASCII value', good.replace('eth0', 'ëth0'))):
    rc, lines = helper('105-1', body)
    check(f'helper rejects {label}',
          rc == 2 and not [l for l in lines if l.startswith('refresh:')], (rc, lines))
    check(f'helper consumes the rejected request with {label}',
          not (spool / '105-1.request').exists())

# --- negative controls -----------------------------------------------------
mutated = helper_source.replace('if [ "$rc" -eq 2 ]; then', 'if [ "$rc" -ne 0 ]; then')
assert mutated != helper_source
(root / 'helper.sh').write_text(mutated)
rc, lines = helper('106-1', good, REFRESH_RC=73)
check('negative control: a helper that disconnects on any failure is caught',
      'nmcli:device disconnect eth0' in lines, lines)
(root / 'helper.sh').write_text(helper_source)

mutated = dispatcher_source.replace('if [ "$ACTION" != pre-up ] && defer_refresh; then',
                                    'if defer_refresh; then')
assert mutated != dispatcher_source
(root / 'mutated-dispatcher').write_text(mutated)
clear_spool()
rc, lines = dispatch('pre-up', gateway='192.0.2.2', script='mutated-dispatcher')
check('negative control: a dispatcher that hands off pre-up is caught',
      handed_off(lines) and not [l for l in lines if l.startswith('refresh:')], lines)
PY
then
    _pass "dispatcher hand-off, helper outcome rule, request trust and negative controls"
else
    _fail "revalidation hand-off fixture failed"
fi
test_finish
