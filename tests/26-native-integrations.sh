#!/bin/bash
# Native integration boundaries: exercise the compose checker with valid
# payloads and with injected activation, privilege and configuration changes.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
test_start "26-native-integrations"
PROJECT_ROOT="$(find_project_root)"

if python3 - "$PROJECT_ROOT/kickstart/snippets/26-package-set.ks" <<'PY'
import pathlib
import subprocess
import sys
import tempfile
import types
import os
import xml.etree.ElementTree as ET

source = pathlib.Path(sys.argv[1]).read_text()
code = source.split("<<'NATIVE_INTEGRATIONS_EOF'\n", 1)[1].split('\nNATIVE_INTEGRATIONS_EOF', 1)[0]
gate = {'__name__': 'fixture'}
exec(compile(code, 'native-integrations', 'exec'), gate)
checks = 0


def rejects(fn, *args):
    global checks
    try:
        fn(*args)
    except (RuntimeError, ValueError, FileNotFoundError, subprocess.CalledProcessError):
        checks += 1
    else:
        raise AssertionError('unsafe or unreadable fixture accepted')


inventory = gate['check_inventory']
selection = gate['check_selection']
selection(gate['PACKAGES'])
checks += 1
rejects(selection, gate['PACKAGES'][1:])
for help_package in ('libreoffice-help-de', 'libreoffice-help-en', 'libreoffice-help-ja'):
    rejects(selection, [*gate['PACKAGES'], help_package])
# Every reviewed package is selected directly or is a named hard dependency;
# wrapping a hyphenated RPM name must not silently create two fixture packages.
direct = source.split('MUST_PRESENT=(', 1)[1].split('\n)', 1)[0].split()
hard = {'ibus-table', 'ibus-table-chinese', 'kernel-tools-libs',
        'langpacks-core-pt_BR', 'langpacks-core-zh_TW', 'langpacks-fonts-zh_TW',
        'pulseaudio-utils', 'python3-pysocks'}
assert len(gate['PACKAGES']) == 57
assert set(gate['PACKAGES']) <= set(direct) | hard
checks += 2
camera_inventory = '/usr/lib/udev/rules.d/70-libcamera.rules\t33188\t(none)\n'
for package in gate['PACKAGES']:
    valid = ''.join(f'{path}\t33188\t(none)\n'
                    for path in gate['ALLOWED'].get(package, ()))
    inventory(package, valid)
    checks += 1
for path in ('/etc/xdg/autostart/extra.desktop', '/usr/lib/systemd/system/extra.service',
             '/usr/lib/systemd/user-generators/extra', '/usr/lib/udev/rules.d/extra.rules',
             '/usr/share/dbus-1/system-services/extra.service', '/etc/cron.d/extra',
             '/etc/profile.d/extra.sh', '/usr/lib/modules-load.d/extra.conf',
             '/usr/lib/dracut/modules.d/extra/module-setup.sh', '/usr/lib/kernel/install.d/extra',
             '/usr/lib/binfmt.d/extra.conf', '/usr/lib64/libdnf5/plugins/extra.so',
             '/usr/lib64/rpm-plugins/extra.so', '/usr/share/p11-kit/pkcs11/modules/extra.module',
             '/usr/share/polkit-1/rules.d/extra.rules'):
    rejects(inventory, 'libcamera', camera_inventory + f'{path}\t33188\t(none)\n')
for mode, caps in ((0o104755, '(none)'), (0o102755, '(none)'), (0o100755, 'cap_net_admin=ep')):
    rejects(inventory, 'libcamera', camera_inventory + f'/usr/bin/extra\t{mode}\t{caps}\n')
rejects(inventory, 'kernel-tools', '')
rejects(inventory, 'wrong-owner', '/usr/lib/udev/rules.d/70-libcamera.rules\t33188\t(none)\n')
rejects(inventory, 'libcamera', 'malformed inventory')

with tempfile.TemporaryDirectory(prefix='noid-native-fixture-') as tmp:
    root = pathlib.Path(tmp)
    def put(path, content):
        target = root / path.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        return target
    for unit in ('cpupower.service', 'kvm_stat.service'):
        target = put('/etc/systemd/system/' + unit, '')
        target.unlink()
        target.symlink_to('/dev/null')
    put('/usr/lib/modules-load.d/fuse-overlayfs.conf', '# native\nfuse\n')
    put('/usr/lib/udev/rules.d/70-libcamera.rules', 'SUBSYSTEM=="dma_heap", GROUP="video", MODE="0660"\n')
    put('/etc/pki/tls/openssl.d/pkcs11-provider.conf', '# provider remains opt-in\n')
    for module, suffix in (('btrfs', 'manage-btrfs'), ('lvm2', 'manage-lvm')):
        put(f'/usr/share/polkit-1/actions/org.freedesktop.UDisks2.{module}.policy',
            f'<policyconfig><action id="org.freedesktop.udisks2.{module}.{suffix}"><defaults>'
            '<allow_any>auth_admin</allow_any><allow_inactive>auth_admin</allow_inactive>'
            '<allow_active>auth_admin_keep</allow_active></defaults></action></policyconfig>')
    for name in ('audit', 'systemd_inhibit'):
        put(f'/usr/lib/rpm/macros.d/macros.transaction_{name}',
            f'%__transaction_{name}    %{{__plugindir}}/{name}.so\n')
    settings = gate['check_settings']
    settings(root)
    checks += 1
    for path, old, new in (
        ('usr/lib/udev/rules.d/70-libcamera.rules', '0660', '0666'),
        ('usr/lib/modules-load.d/fuse-overlayfs.conf', 'fuse', 'fuse\nextra'),
        ('etc/pki/tls/openssl.d/pkcs11-provider.conf', '# provider remains opt-in', 'activate=1'),
        ('usr/share/polkit-1/actions/org.freedesktop.UDisks2.btrfs.policy', 'auth_admin_keep', 'yes'),
        ('usr/lib/rpm/macros.d/macros.transaction_audit', 'audit.so', 'other.so'),
    ):
        target = root / path
        original = target.read_text()
        target.write_text(original.replace(old, new))
        rejects(settings, root)
        target.write_text(original)
    mask = root / 'etc/systemd/system/cpupower.service'
    mask.unlink()
    rejects(settings, root)
    mask.symlink_to('/dev/null')
    missing = root / 'usr/lib/modules-load.d/fuse-overlayfs.conf'
    missing.unlink()
    rejects(settings, root)

def rpm_failure(*args, **kwargs):
    raise subprocess.CalledProcessError(1, 'rpm')

gate['subprocess'] = types.SimpleNamespace(check_output=rpm_failure)
rejects(gate['main'])
assert len(gate['PACKAGES']) == len(set(gate['PACKAGES']))

runtime = pathlib.Path(sys.argv[1]).parents[2] / 'tests/pre-ship/03-firewalld-capabilities-runtime.sh'
runtime_source = runtime.read_text()
firewall_source = pathlib.Path(sys.argv[1]).with_name('03-firewalld.ks').read_text()
policy_xml = firewall_source.split("<< 'POLICY_EOF'\n", 1)[1].split('\nPOLICY_EOF', 1)[0]
assert ET.fromstring(policy_xml).get('target') == 'CONTINUE'
policy_check = 'check_lan_policy() {' + runtime_source.split('check_lan_policy() {', 1)[1].split('\n}\n', 1)[0] + '\n}\n'
policy_fixture = r'''
set -euo pipefail
fail() { exit 1; }
firewall-cmd() {
    case "$*" in
        --info-policy=block-lan-out)
            test "${QUERY_FAIL:-0}" = 0 || return 17
            printf '%s\n' "$RUNTIME_INFO" ;;
        '--permanent --policy=block-lan-out --get-target')
            printf '%s\n' "$PERMANENT_TARGET" ;;
        --get-active-policies) printf '%s\n' "$ACTIVE_POLICIES" ;;
        *) return 2 ;; # Includes the unsupported runtime --get-target.
    esac
}
'''
valid_policy = {'RUNTIME_INFO': 'block-lan-out (active)\n  target: CONTINUE',
                'PERMANENT_TARGET': 'CONTINUE',
                'ACTIVE_POLICIES': 'allow-host-ipv6\nblock-lan-out\n  ingress-zones: HOST'}
policy_cases = [({}, True), ({'RUNTIME_INFO': '  target: DROP'}, False),
                ({'RUNTIME_INFO': '  target: CONTINUE\n  target: ACCEPT'}, False),
                ({'RUNTIME_INFO': 'block-lan-out (active)'}, False),
                ({'PERMANENT_TARGET': 'ACCEPT'}, False),
                ({'ACTIVE_POLICIES': 'other-block-lan-out'}, False),
                ({'QUERY_FAIL': '1'}, False)]
for change, expected in policy_cases:
    result = subprocess.run(['bash', '-c', policy_fixture + policy_check + 'check_lan_policy'],
                            env={**os.environ, **valid_policy, **change}, capture_output=True)
    assert (result.returncode == 0) == expected, change
    checks += 1
code = runtime.read_text().split("<<'CAPABILITIES_PY'", 1)[1].split('\n', 1)[1].split('\nCAPABILITIES_PY', 1)[0]
cap_gate = {'__name__': 'fixture'}
exec(compile(code, 'capabilities-fixture', 'exec'), cap_gate)
valid = 'Uid:\t0 0 0 0\nCapEff:\t13000\nCapPrm:\t13000\nCapBnd:\t13000\nCapInh:\t0\nCapAmb:\t0\n'
cap_gate['check_status'](valid)
checks += 1
for bad in (valid.replace('CapEff:\t13000', 'CapEff:\t1ffffffffff'),
            valid.replace('CapPrm:\t13000', 'CapPrm:\t1000'),
            valid.replace('CapBnd:\t13000', 'CapBnd:\t1ffffffffff'),
            valid.replace('CapAmb:\t0', 'CapAmb:\t1000'),
            valid.replace('CapInh:\t0', 'CapInh:\t1000'),
            valid.replace('Uid:\t0 0 0 0', 'Uid:\t1000 0 0 0'),
            valid.replace('CapEff:\t13000\n', '')):
    try:
        cap_gate['check_status'](bad)
    except (AssertionError, KeyError, ValueError):
        checks += 1
    else:
        raise AssertionError('incorrect daemon capabilities accepted')
print(f'PASS: {checks} native integration contract cases')
PY
then
    _pass "native integration checker accepts valid payloads and rejects unsafe changes"
else
    _fail "native integration contract fixtures"
fi
assert_cmd_success "unknown weak relationships and malformed exceptions fail closed" \
    python3 "$PROJECT_ROOT/tests/fixtures/weak_dependencies.py" "$PROJECT_ROOT"
test_finish
