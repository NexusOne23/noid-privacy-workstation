#!/bin/bash
# Exercise gateway failover using the actual dispatcher and isolated commands.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
test_start "M04 remaining physical gateway after link removal"
fixture=$(make_exec_tmpdir 04-arp-failover)
trap 'rm -rf "$fixture"' EXIT
extract_heredoc "$(find_project_root)/kickstart/snippets/04-arp-hardening.ks" \
    NM_TEMPLATE_EOF "$fixture/template"
if python3 - "$fixture" <<'PY'
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1])
source = (root / 'template').read_text()
bindir = root / 'bin'
bindir.mkdir()
runtime = root / 'run'
runtime.mkdir(mode=0o755)
runtime.chmod(0o755)
state = root / 'state'
state.mkdir()
sysnet = root / 'sys/class/net'
sysnet.mkdir(parents=True)
log = root / 'calls'
routes = root / 'routes.json'

def executable(name, body):
    path = bindir / name
    path.write_text('#!/bin/bash\nset -euo pipefail\n' + body + '\n')
    path.chmod(0o755)
    return str(path)

executable('ip', 'test "$*" = "-j -4 route show default"; cat "$FIXTURE/routes.json"')
executable('logger', ':')
executable('nmcli', 'printf "disconnect:%s\\n" "$*" >> "$FIXTURE/calls"')
readiness = executable('readiness', 'printf "readiness:%s\\n" "$*" >> "$FIXTURE/calls"')
guard = executable('guard', 'test "${GUARD_FAIL:-0}" = 0')
busctl = executable('busctl', 'case "${SLEEPING:-0}" in 1) echo "b true" ;; err) exit 1 ;; *) echo "b false" ;; esac')
arp = executable('arp', 'printf "refresh:%s:%s:%s\\n" "$NOID_ARP_IFACE" "$NOID_ARP_GATEWAY_IP" "$*" >> "$FIXTURE/calls"; exit "${REFRESH_RC:-0}"')
replacements = {
    '@@WAN_IFACE@@': 'eth0', '@@GATEWAY_IP@@': '192.0.2.1',
    '@@GATEWAY_MAC@@': '02:00:00:00:00:01',
    '/usr/local/libexec/noid-network-readiness': readiness,
    '/usr/local/sbin/noid-arp-state-guard.sh': guard,
    '/usr/local/sbin/noid-arp-hardening.sh': arp,
    '/usr/bin/nmcli': str(bindir / 'nmcli'),
    '/usr/bin/busctl': busctl,
    '/var/lib/noid-privacy': str(state),
    '/run/noid-privacy': str(runtime),
    '/sys/class/net': str(sysnet),
    '0:0:755': f'{os.getuid()}:{os.getgid()}:755',
}
for old, new in replacements.items():
    source = source.replace(old, new)
dispatcher = root / 'dispatcher'
dispatcher.write_text(source)
subprocess.run(['bash', '-n', str(dispatcher)], check=True)

def nic(name, carrier='1', hardware=True):
    path = sysnet / name
    path.mkdir(exist_ok=True)
    if hardware:
        (path / 'device').mkdir(exist_ok=True)
    (path / 'carrier').write_text(carrier + '\n')
    (path / 'operstate').write_text('up\n' if carrier == '1' else 'down\n')

nic('eth0')
nic('eth1')
nic('wg0', hardware=False)
nic('eth2', carrier='0')
route = {'dst':'default','gateway':'198.51.100.1','dev':'eth1','metric':100,'flags':[]}

def run(label, *, event='down', iface='eth0', route_set=None, current='eth0',
        guard_fail=False, refresh_rc=0, disabled=False, want_refresh=True,
        want_offline=True, want_rc=0, want_disconnect=False, sleeping='0'):
    routes.write_text(json.dumps([route] if route_set is None else route_set))
    (state / 'arp-hardening.state').write_text('ENABLED=1\nWAN_IFACE=' + current +
        '\nGATEWAY_IP=192.0.2.1\nGATEWAY_MAC=02:00:00:00:00:01\nLEARNED_AT=2026-01-01T00:00:00Z\n')
    optout = state / 'arp-hardening.disabled'
    optout.unlink(missing_ok=True)
    if disabled:
        optout.touch()
    log.write_text('')
    env = dict(os.environ, PATH=str(bindir)+':'+os.environ['PATH'], FIXTURE=str(root),
               GUARD_FAIL=str(int(guard_fail)), REFRESH_RC=str(refresh_rc),
               SLEEPING=sleeping)
    proc = subprocess.run(['bash',str(dispatcher),iface,event],env=env,capture_output=True,timeout=10)
    calls = log.read_text().splitlines()
    assert proc.returncode == want_rc, (label, proc.returncode, proc.stderr.decode(), calls)
    assert ('readiness:offline' in calls) == want_offline, (label,calls)
    expected = ['refresh:eth1:198.51.100.1:refresh'] if want_refresh else []
    assert [x for x in calls if x.startswith('refresh:')] == expected, (label,calls)
    assert [x for x in calls if x.startswith('disconnect:')] == (
        ['disconnect:device disconnect eth1'] if want_disconnect else []), (label,calls)
    assert 'readiness:ready' not in calls, 'dispatcher must never publish readiness itself'
    print('PASS:',label)

run('remaining routed physical link receives exact native refresh')
run('pre-down retires but does not switch before deactivation',event='pre-down',want_refresh=False)
run('unrelated link down preserves pinned readiness',iface='eth1',want_refresh=False,want_offline=False)
run('no alternative route stays safely offline',route_set=[],want_refresh=False)
run('removed route is never selected',route_set=[dict(route,dev='eth0')],want_refresh=False)
run('virtual tunnel route is never used as a physical gateway',route_set=[dict(route,dev='wg0')],want_refresh=False)
run('carrierless physical route is skipped',route_set=[dict(route,dev='eth2')],want_refresh=False)
run('linkdown route is skipped',route_set=[dict(route,flags=['linkdown'])],want_refresh=False)
run('route without gateway is skipped',route_set=[{'dst':'default','dev':'eth1'}],want_refresh=False)
run('invalid gateway is rejected',route_set=[dict(route,gateway='not-an-address')],want_refresh=False,want_rc=1)
run('bad state prevents any recovery',guard_fail=True,want_refresh=False,want_rc=1)
run('an explicit pin opt-out is preserved',disabled=True,want_refresh=False,want_offline=False)
run('queued old-generation down cannot retire a new pin',current='eth1',want_refresh=False,want_offline=False)
run('transient refresh failure leaves interface up',refresh_rc=1,want_rc=1)
run('contested replacement gateway disconnects only that link',refresh_rc=2,want_rc=1,want_disconnect=True)
run('nonphysical route cannot shadow remaining physical route',route_set=[dict(route,dev='wg0',metric=1),route])
# logind announced sleep: every link is going down and the task freeze follows,
# so readiness is retired but no remaining-link transaction is started.
run('sleep teardown retires readiness without a remaining-link transaction',sleeping='1',want_refresh=False)
run('unreachable logind keeps the remaining-link revalidation',sleeping='err')
(sysnet/'eth0/device').rmdir()
(sysnet/'eth0/carrier').unlink()
(sysnet/'eth0/operstate').unlink()
(sysnet/'eth0').rmdir()
run('hot-unplug after sysfs removal still retires and revalidates')

# Remove the sleep check, then require the sleep assertion to detect it.
sleep_gate = '        if preparing_for_sleep; then\n'
assert source.count(sleep_gate) == 1
dispatcher.write_text(source.replace(sleep_gate, '        if false; then\n'))
try:
    run('sleep mutation control',sleeping='1',want_refresh=False)
except AssertionError:
    print('PASS: a sleep-time remaining-link transaction is detected')
else:
    raise AssertionError('sleep mutation control silently passed')

# Remove the recovery call, then require the positive assertion to detect it.
assert 'refresh_remaining_gateway' in source
dispatcher.write_text(source.replace('        refresh_remaining_gateway\n','        :\n'))
try:
    run('mutation control')
except AssertionError:
    print('PASS: removing recovery is detected')
else:
    raise AssertionError('mutation control silently passed')
PY
then
    _pass "dispatcher failover, owner decisions, hot-unplug and negative controls"
else
    _fail "dispatcher failover fixture failed"
fi
test_finish
