#!/usr/bin/env bash
# Real AT-SPI gate for the four first-party GTK applications.
# Run as the normal GNOME user in every candidate pass. It never starts the
# Update mutation: only the idle page and read-only application surfaces are
# inspected.
set -euo pipefail

TEST_NAME=13-first-party-app-accessibility-runtime
PASS_ID=${1:-}
case "$PASS_ID" in
    live|fresh-install|reboot) ;;
    *) echo "Usage: bash $0 {live|fresh-install|reboot}" >&2; exit 2 ;;
esac

fail() { echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2; exit 1; }
[[ $EUID -ne 0 ]] || fail "run as the normal GNOME user, not root"
grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
[[ ${XDG_CURRENT_DESKTOP:-} == *GNOME* ]] || fail "active desktop is not GNOME"
[[ -n ${DBUS_SESSION_BUS_ADDRESS:-} ]] || fail "session D-Bus address is missing"
[[ -n ${WAYLAND_DISPLAY:-${DISPLAY:-}} ]] || fail "graphical display is missing"

python3 - "$PASS_ID" <<'PY'
import os
import signal
import subprocess
import sys
import time
import warnings

import gi
gi.require_version('Atspi', '2.0')
from gi.repository import Atspi

pass_id = sys.argv[1]
desktop = Atspi.get_desktop(0)
semantic_roles = {
    'switch', 'list item', 'page tab', 'entry', 'combo box',
}
interactive_roles = semantic_roles | {
    'button', 'push button menu', 'toggle button', 'radio button',
}


def children(node):
    try:
        return [node.get_child_at_index(i)
                for i in range(node.get_child_count())]
    except Exception:
        return []


def walk(node):
    yield node
    for child in children(node):
        yield from walk(child)


def find_frame(title, process_id=None):
    for app_index in range(desktop.get_child_count()):
        app = desktop.get_child_at_index(app_index)
        for node in walk(app):
            try:
                if (node.get_role_name() == 'frame'
                        and node.get_name() == title
                        and (process_id is None
                             or node.get_process_id() == process_id)):
                    return node
            except Exception:
                continue
    return None


def wait_for_frame(title, proc, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        returncode = proc.poll()
        if returncode is not None:
            raise RuntimeError(
                f'launcher exited before its window appeared: '
                f'{title} (exit {returncode})')
        frame = find_frame(title, proc.pid)
        if frame is not None:
            return frame
        time.sleep(0.2)
    raise RuntimeError(f'window did not appear: {title}')


def visible(node):
    try:
        state = node.get_state_set()
        return (state.contains(Atspi.StateType.VISIBLE)
                and state.contains(Atspi.StateType.SHOWING))
    except Exception:
        return False


def has_ancestor_role(node, role):
    current = node.get_parent()
    while current is not None:
        if current.get_role_name() == role:
            return True
        current = current.get_parent()
    return False


def inspect(frame, application, observed):
    defects = []
    for node in walk(frame):
        try:
            role = node.get_role_name()
            if role not in interactive_roles or not visible(node):
                continue
            # GtkComboBox keeps non-popup model rows in the AT-SPI tree. The
            # app owns and verifies the named/described combo itself; these
            # internal option objects are not separate visible app controls.
            if role == 'list item' and has_ancestor_role(node, 'combo box'):
                continue
            actionable = node.get_n_actions() > 0
            if not actionable and role not in semantic_roles:
                continue
            name = ' '.join((node.get_name() or '').split())
            description = ' '.join((node.get_description() or '').split())
            if not name:
                defects.append(f'{application}: unnamed visible {role}')
                continue
            observed.add(name)
            relation_descriptions = []
            for relation in node.get_relation_set():
                if relation.get_relation_type() != Atspi.RelationType.DESCRIBED_BY:
                    continue
                for index in range(relation.get_n_targets()):
                    target = relation.get_target(index)
                    text = ' '.join((target.get_name() or '').split())
                    if text:
                        relation_descriptions.append(text)
            if role in semantic_roles and not description and \
                    not relation_descriptions:
                defects.append(
                    f'{application}: {role} {name!r} has no explicit description')
        except Exception as exc:
            defects.append(f'{application}: AT-SPI read failed: {type(exc).__name__}')
    return defects


def invoke(node, preferred=('click', 'activate', 'toggle')):
    for wanted in preferred:
        for index in range(node.get_n_actions()):
            # Fedora 44's GIR correctly points at atspi_action_get_action_name,
            # but PyGObject 3.56 inherits the deprecation flag from its old
            # shadowed get_name alias. Keep the maintained call and silence
            # only that binding-generated false warning.
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    'ignore',
                    message='Atspi.Action.get_action_name is deprecated',
                    category=DeprecationWarning)
                name = node.get_action_name(index)
            if name == wanted or name.endswith('.' + wanted):
                return bool(node.do_action(index))
    return False


def process_group_exists(process_group):
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def terminate_process_group(proc, timeout=5):
    process_group = proc.pid
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=timeout)

    deadline = time.monotonic() + timeout
    while process_group_exists(process_group) and time.monotonic() < deadline:
        time.sleep(0.1)
    if process_group_exists(process_group):
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + timeout
        while process_group_exists(process_group) and time.monotonic() < deadline:
            time.sleep(0.1)
    if process_group_exists(process_group):
        raise RuntimeError(
            f'test-owned process group survived cleanup: {process_group}')


def exact_user_processes(name):
    result = subprocess.run(
        ['pgrep', '--euid', str(os.geteuid()), '--exact', name],
        text=True, capture_output=True, check=False)
    if result.returncode == 1:
        return set()
    if result.returncode != 0:
        raise RuntimeError(
            f'cannot inventory exact user processes {name!r}: '
            f'{result.stderr.strip()}')
    return {int(line) for line in result.stdout.splitlines() if line.strip()}


def close_application(frame, proc, timeout=5):
    if not invoke(frame, ('close',)):
        terminate_process_group(proc, timeout)
        raise RuntimeError(
            'application frame exposes no working native close action')
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        terminate_process_group(proc, timeout)
        raise RuntimeError(
            'application did not exit after its native close action')
    if process_group_exists(proc.pid):
        terminate_process_group(proc, timeout)
        raise RuntimeError(
            f'test-owned process group survived native close: {proc.pid}')


apps = [
    {
        'name': 'Setup',
        'title': 'NoID Privacy Setup',
        'argv': ['/usr/local/bin/noid-welcome.sh', '--again'],
        'expected': {
            'Disable Microphone',
            'Open GNOME Software with Fedora RPMs',
        },
        'forbidden': {'Faster App Install via Terminal'},
    },
    {
        'name': 'Network',
        'title': 'NoID Privacy Network',
        'argv': ['/usr/local/bin/noid-network'],
        'expected': {
            'WAN Privacy', 'LAN Exceptions', 'DNS Privacy', 'Network Status',
            'WAN physical-egress policy enabled',
            'Audit WAN-egress-strict', 'Audit firewall policy',
            'Audit nftables rules and counters', 'Audit tunnel MTU',
        },
    },
    {
        'name': 'Update',
        'title': 'NoID Privacy Update',
        'argv': ['/usr/local/bin/noid-update'],
        'expected': {'Verify files with AIDE', 'Start Update'},
    },
    {
        'name': 'Tools',
        'title': 'NoID Privacy Tools',
        'argv': ['/usr/local/bin/noid-tools'],
        'expected': {'System Status Overview', 'LUKS Header Backup'},
    },
]

all_defects = []
for spec in apps:
    if find_frame(spec['title']) is not None:
        raise RuntimeError(
            f"pre-existing window must be closed before this gate: "
            f"{spec['title']}")
    if spec['name'] == 'Setup' and exact_user_processes('pw-mon'):
        raise RuntimeError(
            'pre-existing pw-mon must be retired before this gate')
    # Reproduce the launcher contract: first-party apps inherit the actual
    # session renderer, including M19's narrow hybrid-laptop GL policy when it
    # legitimately applies. Do not hide default-renderer regressions with a
    # test-only software-renderer override.
    proc = subprocess.Popen(
        spec['argv'], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)
    frame = None
    try:
        frame = wait_for_frame(spec['title'], proc)
        observed = set()
        all_defects.extend(inspect(frame, spec['name'], observed))

        if spec['name'] == 'Network':
            tabs = {}
            for node in walk(frame):
                try:
                    if node.get_role_name() == 'page tab' and visible(node):
                        tabs[node.get_name() or ''] = node
                except Exception:
                    continue
            for title in (
                    'WAN Privacy', 'LAN Exceptions', 'DNS Privacy',
                    'Network Status'):
                tab = tabs.get(title)
                if tab is None:
                    all_defects.append(f'Network: missing named page tab {title!r}')
                    continue
                if not invoke(tab, ('click', 'activate')):
                    all_defects.append(f'Network: page tab is not actionable: {title!r}')
                    continue
                time.sleep(0.4)
                all_defects.extend(inspect(frame, spec['name'], observed))

        missing = spec['expected'] - observed
        if missing:
            all_defects.append(
                f"{spec['name']}: expected names not exposed: {sorted(missing)!r}")
        forbidden = spec.get('forbidden', set()) & observed
        if forbidden:
            all_defects.append(
                f"{spec['name']}: retired names still exposed: "
                f"{sorted(forbidden)!r}")
    finally:
        if frame is None:
            terminate_process_group(proc)
        else:
            close_application(frame, proc)
        if spec['name'] == 'Setup':
            deadline = time.monotonic() + 5
            leaked_pwmon = exact_user_processes('pw-mon')
            while leaked_pwmon and time.monotonic() < deadline:
                time.sleep(0.1)
                leaked_pwmon = exact_user_processes('pw-mon')
            if leaked_pwmon:
                raise RuntimeError(
                    f'Setup left pw-mon running after native close: '
                    f'{sorted(leaked_pwmon)!r}')

if all_defects:
    for defect in sorted(set(all_defects)):
        print(f'FAIL  {defect}', file=sys.stderr)
    raise SystemExit(1)
print(
    'PASS  13-first-party-app-accessibility-runtime '
    f'[{pass_id}]: Setup, Network, Update and Tools expose named/described controls')
PY
