#!/bin/bash
# 37-noid-tools-structural — NoID Privacy Tools app structural test
#
# Covers: Module 37 heredocs (app + desktop entry), the curated helper
# CATALOG contract (paths exist as repo deploy targets, exact action-level
# privilege routing, read-only default verbs, unique emoji prefixes), the
# coverage gate (catalog ∪ SWEEP_EXCLUDE must cover every deployed helper
# basename so a new helper forces a conscious curation decision), the
# fresh-image runtime inventory gate, the shared single-hold terminal
# wrapper, and the cross-module wiring (master.ks include, M99 stamp
# adoption, M32 icon label loops, branding icon assets + manifest).
#
# Would catch: app deleted, dead catalog row (path without deploy target),
# uncurated new helper, unreviewed root action, mutating drop-down default,
# wrapper losing the exit-0/single-hold contract, missing icon wiring or
# stamp adoption drift.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/37-noid-tools-app.ks"
M32_FILE="$PROJECT_ROOT/kickstart/snippets/32-branding.ks"
M99_FILE="$PROJECT_ROOT/kickstart/snippets/99-finalize.ks"
MASTER_KS="$PROJECT_ROOT/kickstart/master.ks"

test_start "37-noid-tools-structural"

assert_file_exists "$KS_FILE"
assert_cmd_success "bash -n $KS_FILE" bash -n "$KS_FILE"

# --- Validated, atomic root-owned publication -------------------------------
assert_grep_fixed "cat > \"\$TOOLS_CANDIDATE\" <<'NOID_TOOLS_PY_EOF'" "$KS_FILE"
assert_grep_fixed \
    'publish_root_file "$TOOLS_CANDIDATE" /usr/local/bin/noid-tools 0755' \
    "$KS_FILE" "validated app candidate is atomically published"
assert_grep_fixed \
    "cat > \"\$DESKTOP_CANDIDATE\" <<'NOID_TOOLS_DESKTOP_EOF'" "$KS_FILE"
assert_grep_fixed \
    'publish_root_file "$DESKTOP_CANDIDATE"' "$KS_FILE" \
    "validated desktop candidate is atomically published"
assert_grep_fixed \
    'publish_root_file "$STAMP_CANDIDATE" "$STAMP" 0644' "$KS_FILE" \
    "health evidence is atomically published only after verification"
assert_not_grep 'cat > /usr/local/bin/noid-tools' "$KS_FILE" \
    "app payload is never truncated in place"
assert_not_grep 'cat > /usr/share/applications/noid-tools.desktop' "$KS_FILE" \
    "desktop payload is never truncated in place"
assert_grep_fixed '/usr/bin/desktop-file-validate "$DESKTOP_CANDIDATE"' \
    "$KS_FILE" "desktop candidate validates before publication"
assert_grep_fixed 'noid-tools candidate has invalid Python syntax' "$KS_FILE" \
    "Python candidate parses before publication"
assert_grep_fixed \
    "open('/usr/local/bin/noid-tools', encoding='utf-8').read()" "$KS_FILE" \
    "installed emoji-bearing Python payload is decoded explicitly as UTF-8"
assert_grep_fixed 'PATH=/usr/sbin:/usr/bin:/sbin:/bin' "$KS_FILE" \
    "M37 pins its root installer command-search path"
assert_grep_fixed 'cmp -s -- "$TOOLS_CANDIDATE" /usr/local/bin/noid-tools' \
    "$KS_FILE" "M37 final app gate binds installed bytes to the candidate"
assert_grep_fixed 'cmp -s -- "$DESKTOP_CANDIDATE"' "$KS_FILE" \
    "M37 final desktop gate binds installed bytes to the candidate"
for path in /usr/local/bin/noid-tools \
        /usr/lib/noid-privacy/noid_ui.py \
        /usr/share/applications/noid-tools.desktop; do
    assert_grep_fixed "/usr/sbin/matchpathcon -V $path" "$KS_FILE" \
        "M37 final trust boundary verifies the label: $path"
done

# --- Extract + parse the app -----------------------------------------------
TMP_APP="$(mktemp --suffix=.py)"
TMP_DESKTOP="$(mktemp --suffix=.desktop)"
EXEC_FIXTURE_DIR="$(mktemp -d /var/tmp/noid-m37-fixture.XXXXXXXX)"
trap 'rm -f "$TMP_APP" "$TMP_DESKTOP"; rm -rf "$EXEC_FIXTURE_DIR"' EXIT
extract_heredoc "$KS_FILE" "NOID_TOOLS_PY_EOF" "$TMP_APP"
assert_cmd_success "noid-tools parses (python3 ast)" \
    python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$TMP_APP"
assert_grep_fixed "APP_ID = 'com.noidprivacy.Tools'" "$TMP_APP"
assert_grep_extended '^import noid_ui$' "$TMP_APP"
# Argument handling is exercised through main() alone, never by running the
# app. The module imports gi, requires the Gtk-4.0 and Adw-1 typelibs and pulls
# /usr/lib/noid-privacy/noid_ui.py, none of which exist on a plain Fedora build
# host -- tests/README.md declares only pykickstart, ShellCheck, GNU patch, Git
# and Python 3, and docs/test-strategy.md forbids semantic tests depending on
# live system state. Executing it made the positive check fail in CI while the
# two negative checks passed for the wrong reason: a ModuleNotFoundError also
# exits non-zero, so they stayed green even with no argument validation at all.
assert_cmd_success "noid-tools argument handling is exact without a GUI stack" \
    python3 - "$TMP_APP" <<'PY'
import ast
import contextlib
import io
import sys

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
fn = next(node for node in tree.body
          if isinstance(node, ast.FunctionDef) and node.name == 'main')
module = ast.Module(body=[fn], type_ignores=[])
ast.fix_missing_locations(module)

GUI_SENTINEL = 99

class InventoryError(Exception):
    pass

class FakeApp:
    created = 0

    def __init__(self):
        self.__class__.created += 1

    def run(self, argv):
        return GUI_SENTINEL

namespace = {
    'sys': sys,
    '__doc__': 'NoID Privacy Tools',
    'InventoryError': InventoryError,
    '_sweep_entries': lambda: [],
    '_is_safe_privilege_launcher': lambda: True,
    'SUDO': '/usr/bin/pkexec',
    'NoIDToolsApp': FakeApp,
}
exec(compile(module, '<noid-tools-main>', 'exec'), namespace)
main = namespace['main']

def run(argv):
    saved = sys.argv
    sys.argv = ['noid-tools'] + argv
    try:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            rc = main()
        return rc, stdout.getvalue(), stderr.getvalue()
    finally:
        sys.argv = saved

assert run(['--help'])[0] == 0, '--help must succeed'
assert run(['-h'])[0] == 0, '-h must succeed'
assert run(['--verify-privilege-launcher'])[0] == 0
assert run(['--verify-fresh-inventory'])[0] == 0
invalid = [
    ['--unknown'],
    ['--unknown', '--help'],
    ['--help', '--unknown'],
    ['--verify-fresh-inventory', 'extra'],
    ['--verify-privilege-launcher', 'extra'],
    [''],
    ['line-one\nline-two'],
    ['\x1b[31mterminal-control'],
]
for argv in invalid:
    before = FakeApp.created
    rc, stdout, stderr = run(argv)
    assert rc == 2, f'invalid argv was accepted: {argv!r}'
    assert not stdout, f'invalid argv wrote stdout: {argv!r}'
    assert FakeApp.created == before, f'invalid argv reached GUI: {argv!r}'
    assert stderr.count('\n') == 1 and stderr.isascii(), \
        f'invalid diagnostic is not one printable ASCII line: {stderr!r}'
    assert all(ord(char) >= 32 or char == '\n' for char in stderr), \
        f'invalid diagnostic contains terminal control bytes: {stderr!r}'
# Only a completely empty argv may reach the GUI.
before = FakeApp.created
assert run([])[0] == GUI_SENTINEL, \
    'no-argument launch must reach the GUI path'
assert FakeApp.created == before + 1, 'valid launch did not instantiate once'
PY
assert_grep_fixed 'dropdown.set_selected(0)' "$TMP_APP" \
    "every multi-action drop-down explicitly selects its safe first action"
assert_grep_fixed 'dropdown.set_size_request(VERB_DROPDOWN_MIN_WIDTH, -1)' \
    "$TMP_APP" \
    "drop-down keeps a reviewed minimum while allowing accessibility growth"
assert_grep_fixed 'if selected >= len(verbs):' "$TMP_APP" \
    "invalid GTK list positions are bounds-checked before indexing"
assert_grep_fixed "self._toast('Select an action first.', 4)" "$TMP_APP" \
    "an invalid selection reaches visible UX instead of an IndexError"
assert_not_grep 'LEGACY_MARKERS' "$TMP_APP" \
    "substring heuristics cannot hide unclassified helper names"
assert_grep_fixed \
    'Non-remediating defaults for hardening and privacy diagnostics' "$TMP_APP" \
    "diagnostic group scopes its no-mutation claim to remediation"
assert_grep_fixed 'does not remediate by default' "$TMP_APP" \
    "audit row states the upstream default without denying ordinary logs"
assert_not_grep 'reports UNKNOWN honestly, changes nothing' "$TMP_APP" \
    "audit row carries no absolute no-write claim"

# --- Shared single-hold terminal contract ----------------------------------
assert_grep_fixed "'NOID_WELCOME_SPAWN=1 ' + shlex.join(argv)" "$TMP_APP" \
    "wrapper marks GUI-owned terminals for companion scripts"
assert_grep_fixed 'read -r -p "Press ENTER to close..." || :; exit 0' "$TMP_APP" \
    "wrapper holds once and exits 0 (no terminal-level second hold)"
assert_not_grep '^import shutil$' "$TMP_APP" \
    "terminal selection never consults a caller-controlled PATH"
assert_not_grep 'shutil.which' "$TMP_APP" \
    "terminal selection has no PATH lookup fallback"
for terminal in ptyxis gnome-terminal xterm; do
    assert_grep_fixed "'/usr/bin/$terminal'" "$TMP_APP" \
        "terminal candidate is an absolute system path: $terminal"
done
assert_grep_fixed "'/usr/bin/bash', '-c'" "$TMP_APP" \
    "terminal helper shell is an absolute system path"
assert_grep_fixed 'if _is_safe_executable(binary):' "$TMP_APP" \
    "terminal candidates pass the root-owned executable predicate"
assert_cmd_success "hostile PATH cannot redirect the terminal launcher" \
    python3 - "$TMP_APP" <<'PY'
import ast
import sys

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
spawn = next(node for node in tree.body
             if isinstance(node, ast.FunctionDef)
             and node.name == '_spawn_terminal')

class FakeSubprocess:
    DEVNULL = object()
    calls = []

    @classmethod
    def Popen(cls, argv, **kwargs):
        cls.calls.append((argv, kwargs))
        return object()

namespace = {
    '_is_safe_executable': lambda path: path == '/usr/bin/ptyxis',
    'subprocess': FakeSubprocess,
    'sys': sys,
}
exec(compile(ast.Module(body=[spawn], type_ignores=[]),
             '<terminal-probe>', 'exec'), namespace)
assert namespace['_spawn_terminal']('fixed command') is True
assert len(FakeSubprocess.calls) == 1
argv, kwargs = FakeSubprocess.calls[0]
assert argv == [
    '/usr/bin/ptyxis', '--', '/usr/bin/bash', '-c', 'fixed command']
assert kwargs['start_new_session'] is True
PY
assert_grep_fixed "'💤', 'Laptop Lid Close'" "$TMP_APP" \
    "lid action uses the same curated tool-row style"
assert_grep_fixed "'/usr/local/bin/noid-toggle-lid-action'" "$TMP_APP" \
    "lid row targets the canonical M17 helper"
assert_grep_fixed \
    "('Status', ['status']), ('Suspend', ['suspend'])" "$TMP_APP" \
    "lid row exposes explicit status and confirmed suspend actions"
assert_grep_fixed \
    "('Lock', ['lock']), ('Reset', ['reset'])" "$TMP_APP" \
    "lid row exposes lock and lower-policy reset actions"
assert_grep_fixed "'🌐', 'DNS Privacy Transport'" "$TMP_APP" \
    "DNS privacy transport uses the same curated tool-row style"
assert_grep_fixed "'/usr/local/sbin/noid-dns-mode'" "$TMP_APP" \
    "DNS transport row targets the canonical M05 helper"
assert_grep_fixed \
    "('Status', ['status']), ('Strict', ['strict'])" "$TMP_APP" \
    "DNS transport defaults to read-only status and exposes strict mode first"
assert_grep_fixed \
    "('VPN compat.', ['opportunistic']), ('Plaintext', ['off'])" "$TMP_APP" \
    "DNS transport names compatibility and plaintext trade-offs explicitly"
assert_grep_fixed \
    "'/usr/local/bin/noid-pending-reboot-check.sh'," "$TMP_APP" \
    "pending-reboot row targets the canonical M25 helper"
assert_grep_fixed "('Check', ['--status'])" "$TMP_APP" \
    "pending-reboot row uses the immediate read-only status path"
assert_grep_fixed "'noid-codium-launcher-sync': 'transaction-recovery'," \
    "$TMP_APP" \
    "root-only VSCodium desktop reconciliation stays out of the user tool catalog"
assert_grep_fixed "'noid-gnome-software-rpm': 'app-support'," "$TMP_APP" \
    "the Setup/desktop Fedora-RPM action stays out of the terminal catalog"
assert_grep_fixed "'noid-host-identity': 'transaction-recovery'," "$TMP_APP" \
    "the post-Tools host-identity lifecycle is classified without a dead row"

# --- Desktop entry ----------------------------------------------------------
extract_heredoc "$KS_FILE" "NOID_TOOLS_DESKTOP_EOF" "$TMP_DESKTOP"
assert_grep_fixed 'Exec=/usr/local/bin/noid-tools' \
    "$TMP_DESKTOP" \
    "Tools desktop launch inherits GTK's maintained renderer selection"
assert_not_grep 'GSK_RENDERER=' "$TMP_DESKTOP" \
    "Tools launcher does not pin a renderer"
assert_grep_fixed 'Icon=noid-privacy-tools' "$TMP_DESKTOP"
assert_grep_fixed 'StartupWMClass=com.noidprivacy.Tools' "$TMP_DESKTOP"
assert_grep_fixed 'Categories=System;' "$TMP_DESKTOP"
if command -v desktop-file-validate >/dev/null 2>&1; then
    assert_cmd_success "noid-tools.desktop validates" \
        desktop-file-validate "$TMP_DESKTOP"
fi

# --- CATALOG contract: coverage, dead rows, safe defaults, unique emojis ---
if python3 - "$TMP_APP" "$PROJECT_ROOT" <<'PY'
import ast
import collections
import pathlib
import re
import sys

app_path, project_root = sys.argv[1], sys.argv[2]
tree = ast.parse(open(app_path, encoding='utf-8').read())

def literal(name):
    for node in tree.body:
        if isinstance(node, ast.Assign) and \
                any(isinstance(t, ast.Name) and t.id == name
                    for t in node.targets):
            return ast.literal_eval(node.value)
    raise SystemExit(f'{name} literal not found in the app')

catalog = literal('CATALOG')
exclude = literal('SWEEP_EXCLUDE')
empty_default_safety = literal('EMPTY_ARGV_DEFAULT_SAFETY')
sudo_actions = literal('SUDO_ACTIONS')

if exclude.get('noid-wireguard-mtu-reconcile') != 'internal-hook':
    raise SystemExit(
        'the event-only WireGuard MTU worker must stay out of user-facing Tools')

entries = [entry for _t, _d, group in catalog for entry in group]
if not isinstance(exclude, dict):
    raise SystemExit('SWEEP_EXCLUDE must classify every exclusion by reason')
valid_exclusion_classes = {
    'internal-hook', 'app-support', 'facade-backend', 'session-worker',
    'transaction-recovery', 'app-surface', 'required-arguments',
}
unknown_exclusion_classes = set(exclude.values()) - valid_exclusion_classes
if unknown_exclusion_classes:
    raise SystemExit(
        f'unknown SWEEP_EXCLUDE classes: {sorted(unknown_exclusion_classes)!r}')
missing_exclusion_classes = valid_exclusion_classes - set(exclude.values())
if missing_exclusion_classes:
    raise SystemExit(
        f'unexercised SWEEP_EXCLUDE classes: {sorted(missing_exclusion_classes)!r}')
if len(entries) < 40:
    raise SystemExit(f'catalog implausibly small: {len(entries)} entries')

# 1. Unique emoji prefixes across the whole catalog.
emojis = [entry[0] for entry in entries]
dups = {g: n for g, n in collections.Counter(emojis).items() if n > 1}
if dups:
    raise SystemExit(f'duplicate emoji prefixes: {dups!r}')

# 2. Resolve every current producer form: direct cat/install/ln/stage targets,
#    backslash-continued commands, and simple variable-directory/exact-path
#    targets. Fedora merges /usr/local/sbin into bin at runtime, so coverage
#    and collision checks are deliberately basename-based.
path_re = r'/usr/local/(?:bin|sbin)/noid-[A-Za-z0-9._-]+'
writer_command_re = (
    r'(?:cat\s*>|install\b|ln\s+-|mv\s+-fT\b|'
    r'(?:publish|stage)_root_file\b|publish_(?:bin|doc|file)\b|'
    r'(?:[A-Za-z_][A-Za-z0-9_]*_)?install_file\b)'
)

def discover_writers(text, writer):
    discovered = collections.defaultdict(set)
    logical = re.sub(r'\\\n\s*', ' ', text)
    for line in logical.splitlines():
        if re.match(rf'^\s*{writer_command_re}', line):
            for path in re.findall(path_re, line):
                discovered[path].add(writer)

    directory_vars = {
        match.group(1): match.group(2)
        for match in re.finditer(
            r'^([A-Za-z_][A-Za-z0-9_]*)=["\']?'
            r'(/usr/local/(?:bin|sbin))["\']?$',
            text, re.M)
    }
    for var, directory in directory_vars.items():
        for name in re.findall(
                rf'(?:\$\{{?{re.escape(var)}\}}?)/?'
                r'(noid-[A-Za-z0-9._-]+)', text):
            discovered[f'{directory}/{name}'].add(writer)

    file_vars = {
        match.group(1): match.group(2)
        for match in re.finditer(
            rf'^([A-Za-z_][A-Za-z0-9_]*)=["\']?({path_re})["\']?$',
            text, re.M)
    }
    for var, path in file_vars.items():
        if re.search(
                rf'(?:{writer_command_re}|curl\b)[^\n]*'
                rf'(?:\$\{{?{re.escape(var)}\}}?)', logical):
            discovered[path].add(writer)
    return discovered

writer_map = collections.defaultdict(set)
for source in pathlib.Path(project_root, 'kickstart', 'snippets').glob('*.ks'):
    found = discover_writers(source.read_text(encoding='utf-8'), source.stem)
    for path, writers in found.items():
        writer_map[path].update(writers)

# Mutation controls for every reviewed writer spelling. These keep the
# coverage gate honest when a producer publishes through a named helper or an
# atomic rename instead of a direct cat/install command.
writer_fixture = '''
publish_bin /tmp/source /usr/local/bin/noid-writer-bin
publish_doc /usr/local/bin/noid-writer-doc
publish_file /tmp/source /usr/local/sbin/noid-writer-file
install_file /tmp/source /usr/local/bin/noid-writer-install
mv -fT -- /tmp/source /usr/local/bin/noid-writer-mv
'''
fixture_paths = set(discover_writers(writer_fixture, 'fixture'))
expected_fixture_paths = {
    '/usr/local/bin/noid-writer-bin',
    '/usr/local/bin/noid-writer-doc',
    '/usr/local/sbin/noid-writer-file',
    '/usr/local/bin/noid-writer-install',
    '/usr/local/bin/noid-writer-mv',
}
if fixture_paths != expected_fixture_paths:
    raise SystemExit(
        'helper-writer recognition drifted: '
        f'missing={sorted(expected_fixture_paths - fixture_paths)!r}, '
        f'extra={sorted(fixture_paths - expected_fixture_paths)!r}')

deployed = set(writer_map)
dead = [e[3] for e in entries if e[3] not in deployed]
if dead:
    raise SystemExit(f'catalog rows without a deploy target: {dead!r}')

# The launcher argv must match each producer's real interface exactly.
by_path = {entry[3]: entry for entry in entries}
expected_actions = {
    '/usr/local/sbin/noid-aide-check.sh': [('Run check', [])],
    '/usr/local/bin/noid-network-audit': [
        ('WAN', ['wan']), ('Firewall', ['firewall']),
        ('nftables', ['nft']), ('Tunnel MTU', ['mtu'])],
    '/usr/local/sbin/noid-lan-xdp': [('Status', ['status'])],
    '/usr/local/bin/noid-autostart-netwait': [('Check', ['--check'])],
    '/usr/local/bin/noid-integrity-check': [
        ('Standard', []), ('Extended', ['--all']), ('Brief', ['--brief'])],
    '/usr/local/bin/noid-firefox-relax-fpp': [
        ('Usage', ['--help']), ('Apply', []), ('Restore', ['--restore'])],
    '/usr/local/bin/noid-firefox-relax-webrtc': [
        ('Usage', ['--help']), ('Apply', []), ('Restore', ['--restore'])],
    '/usr/local/bin/noid-thunderbird-harden-profile': [
        ('Apply all', ['--all'])],
}
for path, expected in expected_actions.items():
    if by_path[path][4] != expected:
        raise SystemExit(
            f'catalog action drift for {path}: {by_path[path][4]!r}')

# Every action that requires a root process is explicitly bound to its visible
# label. Status/per-user/self-elevating helpers remain unprivileged.
expected_sudo_actions = {
    ('/usr/local/sbin/noid-aide-check.sh', 'Run check'),
    ('/usr/local/sbin/noid-aide-baseline-review', 'Status'),
    ('/usr/local/sbin/noid-aide-baseline-review', 'Prepare'),
    ('/usr/local/sbin/noid-toggle-aide', 'Enable'),
    ('/usr/local/sbin/noid-toggle-aide', 'Disable'),
    ('/usr/local/bin/noid-toggle-aide-popup', 'Enable'),
    ('/usr/local/bin/noid-toggle-aide-popup', 'Disable'),
    ('/usr/local/sbin/noid-toggle-audit-notify', 'Enable'),
    ('/usr/local/sbin/noid-toggle-audit-notify', 'Disable'),
    ('/usr/local/sbin/noid-toggle-wan-strict', 'Enable'),
    ('/usr/local/sbin/noid-toggle-wan-strict', 'Disable'),
    ('/usr/local/sbin/noid-wan-strict', 'Status'),
    ('/usr/local/sbin/noid-wan-strict', 'Pause 5 min'),
    ('/usr/local/sbin/noid-wan-strict', 'Pause 30 min'),
    ('/usr/local/sbin/noid-wan-strict', 'Resume'),
    ('/usr/local/sbin/noid-wan-strict', 'Block WAN'),
    ('/usr/local/sbin/noid-wan-strict', 'Rescan'),
    ('/usr/local/sbin/noid-arp-hardening.sh', 'Status'),
    ('/usr/local/sbin/noid-arp-hardening.sh', 'Re-learn'),
    ('/usr/local/bin/noid-dns-diagnose', 'Evidence'),
    ('/usr/local/sbin/noid-toggle-bluetooth', 'Enable'),
    ('/usr/local/sbin/noid-toggle-bluetooth', 'Disable'),
    ('/usr/local/bin/noid-toggle-bash-history', 'Ephemeral'),
    ('/usr/local/bin/noid-toggle-bash-history', 'Persistent'),
    ('/usr/local/sbin/noid-toggle-gaming', 'Enable'),
    ('/usr/local/sbin/noid-toggle-gaming', 'Disable'),
    # M05 Step 4b — unmasks the CUPS print stack. Reviewed: it never unmasks
    # cups-browsed, avahi or wsdd and never touches the firewall, so the
    # discovery surface stays closed in both states.
    ('/usr/local/sbin/noid-toggle-printing', 'Enable'),
    ('/usr/local/sbin/noid-toggle-printing', 'Disable'),
    ('/usr/local/bin/noid-toggle-gsk-gl', 'Automatic'),
    ('/usr/local/bin/noid-toggle-gsk-gl', 'Enable'),
    ('/usr/local/bin/noid-toggle-gsk-gl', 'Disable'),
    ('/usr/local/bin/noid-usbguard-devices', 'Overview'),
    ('/usr/local/bin/noid-usbguard-devices', 'Manage'),
    ('/usr/local/bin/noid-usbguard-devices', 'Allow'),
    ('/usr/local/bin/noid-usbguard-devices', 'Revoke'),
    ('/usr/local/bin/noid-snap-pre', 'Create'),
    ('/usr/local/sbin/noid-grub-password', 'Set'),
    ('/usr/local/sbin/noid-grub-password', 'Remove'),
    ('/usr/local/bin/noid-mei-lockdown', 'Undo'),
    ('/usr/local/bin/noid-toggle-thirdparty-repos', 'Minimal'),
    ('/usr/local/bin/noid-toggle-thirdparty-repos', 'Restore'),
    ('/usr/local/sbin/noid-toggle-fedora-flatpaks', 'Enable'),
    ('/usr/local/sbin/noid-toggle-fedora-flatpaks', 'Disable'),
    ('/usr/local/bin/noid-install-displaylink', 'Install'),
    ('/usr/local/bin/noid-install-displaylink', 'Uninstall'),
}
if sudo_actions != expected_sudo_actions:
    raise SystemExit(
        'SUDO_ACTIONS drifted from reviewed producer contracts: '
        f'missing={sorted(expected_sudo_actions - sudo_actions)!r}, '
        f'extra={sorted(sudo_actions - expected_sudo_actions)!r}')
catalog_actions = {
    (entry[3], label)
    for entry in entries
    for label, _argv in entry[4]
}
if not sudo_actions <= catalog_actions:
    raise SystemExit(
        f'SUDO_ACTIONS contains stale/non-catalog actions: '
        f'{sorted(sudo_actions - catalog_actions)!r}')

# 3. Coverage gate: every deployed bin OR sbin helper basename is curated
#    or deliberately excluded (a new helper forces a classification).
paths_by_name = collections.defaultdict(set)
for path in deployed:
    paths_by_name[path.rsplit('/', 1)[1]].add(path)
collisions = {name: sorted(paths) for name, paths in paths_by_name.items()
              if len(paths) != 1}
if collisions:
    raise SystemExit(f'unified /usr/local helper basename collisions: '
                     f'{collisions!r}')
helper_names = set(paths_by_name)
covered = ({e[3].rsplit('/', 1)[1] for e in entries} | set(exclude))
uncovered = sorted(helper_names - covered)
if uncovered:
    raise SystemExit(
        f'helpers neither curated nor excluded: {uncovered!r}')
stale_exclude = sorted(set(exclude) - helper_names)
if stale_exclude:
    raise SystemExit(f'SWEEP_EXCLUDE entries without a repo target: '
                     f'{stale_exclude!r}')

# 3b. Install-order gate: Module 37's build-time verify demands every
#     curated helper present + executable, so each one must be written by
#     a snippet whose %include runs BEFORE 37-noid-tools-app in master.ks
#     (2026-07-21 v1.4 build abort: noid-audit arrives in M40, which ran
#     after M37 in the original include order).
master = open(f'{project_root}/kickstart/master.ks',
              encoding='utf-8').read()
order = re.findall(r'^%include snippets/(\S+)\.ks', master, re.M)
pos = {name: i for i, name in enumerate(order)}
m37 = pos['37-noid-tools-app']
late = sorted(
    e[3] for e in entries
    if not any(pos.get(w, m37 + 1) < m37
               for w in writer_map.get(e[3], set())))
if late:
    raise SystemExit(
        f'curated helpers not installed before Module 37: {late!r}')

# 4. Drop-down safety: every multi-verb default (index 0) must be one of the
#    exact reviewed read-only, dry-run, usage or confirmation-gated actions.
#    An allowlist fails closed on new spellings such as `auto` or `arm-empty`
#    instead of trying to predict every future mutating verb.
reviewed_defaults = {
    ('/usr/local/bin/noid-help', 'Topics', ()),
    ('/usr/local/bin/noid-audit', 'Offline', ()),
    ('/usr/local/bin/noid-integrity-check', 'Standard', ()),
    ('/usr/local/bin/noid-dns-diagnose', 'Status', ('status',)),
    ('/usr/local/sbin/noid-aide-baseline-review', 'Status', ('status',)),
    ('/usr/local/sbin/noid-toggle-aide', 'Status', ('status',)),
    ('/usr/local/bin/noid-toggle-aide-popup', 'Status', ('status',)),
    ('/usr/local/sbin/noid-toggle-audit-notify', 'Status', ('status',)),
    ('/usr/local/sbin/noid-toggle-wan-strict', 'Status', ('status',)),
    ('/usr/local/sbin/noid-dns-mode', 'Status', ('status',)),
    ('/usr/local/sbin/noid-wan-strict', 'Status', ('status',)),
    ('/usr/local/bin/noid-lan-allow', 'List', ('--list',)),
    ('/usr/local/bin/noid-network-audit', 'WAN', ('wan',)),
    ('/usr/local/sbin/noid-arp-hardening.sh', 'Status', ('status',)),
    ('/usr/local/sbin/noid-toggle-bluetooth', 'Status', ('status',)),
    ('/usr/local/sbin/noid-toggle-location', 'Status', ('status',)),
    ('/usr/local/bin/noid-toggle-microphone', 'Status', ('status',)),
    ('/usr/local/bin/noid-toggle-bash-history', 'Status', ('status',)),
    ('/usr/local/sbin/noid-toggle-gaming', 'Status', ('status',)),
    ('/usr/local/sbin/noid-toggle-printing', 'Status', ('status',)),
    ('/usr/local/bin/noid-toggle-gsk-gl', 'Status', ('status',)),
    ('/usr/local/bin/noid-toggle-lid-action', 'Status', ('status',)),
    ('/usr/local/bin/noid-usbguard-devices', 'Manage', ()),
    ('/usr/local/bin/noid-luks-backup.sh', 'Backup', ()),
    ('/usr/local/sbin/noid-grub-password', 'Set', ()),
    ('/usr/local/bin/noid-mei-lockdown', 'Status', ('--status',)),
    ('/usr/local/bin/noid-firefox-relax-fpp', 'Usage', ('--help',)),
    ('/usr/local/bin/noid-firefox-relax-webrtc', 'Usage', ('--help',)),
    ('/usr/local/bin/noid-firefox-drm', 'Status', ('status',)),
    ('/usr/local/bin/noid-firefox-create-isolated-profile', 'List', ('--list',)),
    ('/usr/local/bin/noid-firefox-harden-profile', 'Status', ()),
    ('/usr/local/bin/noid-toggle-thirdparty-repos', 'Status', ('status',)),
    ('/usr/local/sbin/noid-toggle-fedora-flatpaks', 'Status', ('status',)),
    ('/usr/local/bin/noid-install-displaylink', 'Usage', ('--help',)),
    ('/usr/local/bin/noid-claude-install', 'Install', ()),
    ('/usr/local/bin/noid-codex-install', 'Install', ()),
    ('/usr/local/bin/noid-protonvpn-install', 'Install', ()),
    ('/usr/local/bin/noid-mullvad-install', 'Install', ()),
    ('/usr/local/bin/noid-nvidia-install.sh', 'Dry-run', ('--dry-run',)),
    ('/usr/local/bin/noid-complete-setup.sh', 'Dry-run', ('--dry-run',)),
}
actual_defaults = {
    (entry[3], entry[4][0][0], tuple(entry[4][0][1]))
    for entry in entries if len(entry[4]) > 1
}
if actual_defaults != reviewed_defaults:
    raise SystemExit(
        'multi-verb defaults drifted from the reviewed allowlist: '
        f'missing={sorted(reviewed_defaults - actual_defaults)!r}, '
        f'extra={sorted(actual_defaults - reviewed_defaults)!r}')

empty_defaults = {
    e[3] for e in entries if len(e[4]) > 1 and not e[4][0][1]
}
if set(empty_default_safety) != empty_defaults:
    raise SystemExit(
        'EMPTY_ARGV_DEFAULT_SAFETY does not exactly classify empty defaults: '
        f'manifest={sorted(empty_default_safety)!r}, '
        f'catalog={sorted(empty_defaults)!r}')
valid_safety = {'read-only', 'interactive-confirmed'}
if set(empty_default_safety.values()) - valid_safety:
    raise SystemExit('unknown empty-default safety classification')

confirming = {
    path for path, safety in empty_default_safety.items()
    if safety == 'interactive-confirmed'
}
confirmation_contracts = {
    '/usr/local/bin/noid-usbguard-devices': (
        'kickstart/snippets/14-usbguard.ks',
        (('action = prompt("Select action: ").strip().lower()',
          'os.execv(ALLOW_HELPER, [ALLOW_HELPER])'),)),
    '/usr/local/bin/noid-luks-backup.sh': (
        'kickstart/snippets/22-luks-partitioning.ks',
        (('read -rp "Proceed? [y/N] " ans',
          'perform_backup_transaction "$luks_dev" "$BACKUP_PATH"'),)),
    '/usr/local/sbin/noid-grub-password': (
        'kickstart/snippets/01-bootloader.ks',
        (("printf 'Enter new GRUB password: ' >/dev/tty",
          'mv -fT -- "$TMP_GRUB" "$GRUB_CFG"'),)),
    '/usr/local/bin/noid-claude-install': (
        'kickstart/snippets/13-aide-welcome.ks',
        (('read -r -p "Install the reviewed native CLI? [y/N] " answer',
          '            cli_install_pinned'),
         ('read -r -p "Install the pinned Claude Code VSCodium extension? '
          '[y/N] " ext',
          '            VSIX=$(mktemp /var/tmp/noid-claude-ext.'))),
    '/usr/local/bin/noid-codex-install': (
        'kickstart/snippets/13-aide-welcome.ks',
        (('read -r -p "Install the reviewed native Codex CLI? [y/N] " answer',
          '            ARCHIVE=$(mktemp /var/tmp/noid-codex.'),
         ('read -r -p "Install the pinned Codex VSCodium extension? [y/N] " '
          'ext',
          '            VSIX=$(mktemp /var/tmp/noid-codex-ext.'))),
    '/usr/local/bin/noid-protonvpn-install': (
        'kickstart/snippets/13-aide-welcome.ks',
        (('read -r -p "Install Proton VPN now? [y/N] " a',
          'TMPKEY=$(mktemp /tmp/noid-protonvpn-key.'),)),
    '/usr/local/bin/noid-mullvad-install': (
        'kickstart/snippets/13-aide-welcome.ks',
        (('read -r -p "Install Mullvad VPN now? [y/N] " a',
          'TMPKEY=$(mktemp /tmp/noid-mullvad-key.'),)),
}
if set(confirmation_contracts) != confirming:
    raise SystemExit(
        'interactive-confirmed defaults lack exact producer contracts')
for path, (relative, pairs) in confirmation_contracts.items():
    producer = pathlib.Path(project_root, relative).read_text(encoding='utf-8')
    offset = 0
    for prompt, action in pairs:
        prompt_pos = producer.find(prompt, offset)
        action_pos = producer.find(action, prompt_pos + len(prompt))
        if prompt_pos < 0 or action_pos < 0:
            raise SystemExit(
                f'confirmation no longer gates selected action for {path}')
        offset = action_pos + len(action)

# 5. Every verb argv is a list of strings (argv-safe, no shell strings).
for e in entries:
    for label, argv in e[4]:
        if not isinstance(argv, list) or \
                not all(isinstance(a, str) for a in argv):
            raise SystemExit(f'non-argv verb on {e[3]}: {label!r}')

# 6. Pango-markup safety: Adw parses titles/subtitles/descriptions as
#    markup — a bare '&' silently breaks rendering (group titles vanished
#    on the reference host until escaped).
def markup_safe(text):
    return '&' not in text.replace('&amp;', '')
for title, desc, _group in catalog:
    if not markup_safe(title) or not markup_safe(desc):
        raise SystemExit(f'bare & in group text: {title!r}')
for e in entries:
    if not markup_safe(e[1]) or not markup_safe(e[2]):
        raise SystemExit(f'bare & in row text: {e[1]!r}')

# 7. Drop-down label brevity: the compact minimum-width selector targets
#    short actions; longer labels would make the row needlessly wide.
for e in entries:
    for label, _argv in e[4]:
        if len(label) > 14:
            raise SystemExit(f'verb label too long ({len(label)}): {label!r}')

# 8. Subtitle source uniformity: one 80-120 char band targets compact,
#    consistent wrapping without pretending to control font/accessibility size.
for e in entries:
    if not 80 <= len(e[2]) <= 120:
        raise SystemExit(
            f'subtitle outside the 80-120 band ({len(e[2])}): {e[1]!r}')
PY
then
    _pass "catalog contract: coverage, live rows, safe defaults, unique emojis"
else
    _fail "catalog contract violated"
fi

# --- Runtime inventory and selector fail-closed fixtures --------------------
if python3 - "$TMP_APP" <<'PY'
import ast
import os
import pathlib
import re
import stat
import sys
import tempfile
import types

app_path = pathlib.Path(sys.argv[1])
tree = ast.parse(app_path.read_text(encoding='utf-8'))

def assignment_literal(name):
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == name
                for target in node.targets):
            return ast.literal_eval(node.value)
    raise RuntimeError(f'missing assignment: {name}')

def assignment_regex(name):
    for node in tree.body:
        if not (isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == name
                for target in node.targets)):
            continue
        if (not isinstance(node.value, ast.Call)
                or not isinstance(node.value.func, ast.Attribute)
                or not isinstance(node.value.func.value, ast.Name)
                or node.value.func.value.id != 're'
                or node.value.func.attr != 'compile'
                or len(node.value.args) != 1
                or node.value.keywords):
            raise RuntimeError(f'{name} is not a plain re.compile literal')
        pattern = ast.literal_eval(node.value.args[0])
        if not isinstance(pattern, str):
            raise RuntimeError(f'{name} pattern is not a string')
        return re.compile(pattern)
    raise RuntimeError(f'missing assignment: {name}')

def top_level(name, node_type):
    for node in tree.body:
        if isinstance(node, node_type) and node.name == name:
            return node
    raise RuntimeError(f'missing node: {name}')

catalog = assignment_literal('CATALOG')
exclude = assignment_literal('SWEEP_EXCLUDE')
stray_suffixes = assignment_literal('SWEEP_STRAY_SUFFIXES')
sudo_actions = assignment_literal('SUDO_ACTIONS')
sudo_path = assignment_literal('SUDO')
sweep_name_re = assignment_regex('SWEEP_NAME_RE')
if sudo_path != '/usr/bin/sudo':
    raise SystemExit(f'privilege launcher path drifted: {sudo_path!r}')
inventory_class = top_level('InventoryError', ast.ClassDef)
sweep_function = top_level('_sweep_entries', ast.FunctionDef)

real_os = os

class RootViewOS:
    X_OK = real_os.X_OK

    @staticmethod
    def lstat(path):
        metadata = real_os.lstat(path)
        return types.SimpleNamespace(
            st_mode=metadata.st_mode,
            st_uid=0,
        )

namespace = {
    'os': RootViewOS,
    'stat': stat,
    'Path': pathlib.Path,
    'CATALOG': catalog,
    'SWEEP_EXCLUDE': exclude,
    'SWEEP_NAME_RE': sweep_name_re,
    'SWEEP_STRAY_SUFFIXES': stray_suffixes,
    'SWEEP_DIR': '',
}
module = ast.Module(
    body=[inventory_class, sweep_function],
    type_ignores=[],
)
ast.fix_missing_locations(module)
exec(compile(module, str(app_path), 'exec'), namespace)

with tempfile.TemporaryDirectory(prefix='noid-tools-inventory.',
                                 dir='/var/tmp') as temporary:
    root = pathlib.Path(temporary)
    curated_name = pathlib.Path(catalog[0][2][0][3]).name
    excluded_name = sorted(exclude)[0]
    for name in (curated_name, excluded_name, 'noid-Upper_tool.py',
                 'noid-harden-new', 'noid-plain', 'noid-plain.rpmsave',
                 'noid-tool.bash'):
        (root / name).write_text('fixture', encoding='utf-8')
    (root / 'noid-link').symlink_to(root / 'noid-plain')
    os.chmod(root / 'noid-harden-new', 0o700)

    namespace['SWEEP_DIR'] = str(root)
    found = [pathlib.Path(path).name
             for path in namespace['_sweep_entries']()]
    expected = ['noid-Upper_tool.py', 'noid-harden-new', 'noid-link',
                'noid-plain', 'noid-tool.bash']
    if found != expected:
        raise SystemExit(
            f'inventory did not expose every unclassified entry: {found!r}')

    namespace['SWEEP_DIR'] = str(root / 'missing')
    try:
        namespace['_sweep_entries']()
    except namespace['InventoryError']:
        pass
    else:
        raise SystemExit('missing helper directory failed open')

# Independently execute the closed root-owned executable predicate.
safe_function = top_level('_is_safe_executable', ast.FunctionDef)
privilege_function = top_level(
    '_is_safe_privilege_launcher', ast.FunctionDef)

class RootExecutableOS:
    X_OK = os.X_OK

    @staticmethod
    def lstat(path):
        metadata = os.lstat(path)
        return types.SimpleNamespace(
            st_mode=metadata.st_mode,
            st_uid=0,
            st_gid=0,
            st_nlink=metadata.st_nlink,
        )

    @staticmethod
    def access(path, mode):
        return os.access(path, mode)

safe_namespace = {
    'os': RootExecutableOS,
    'stat': stat,
    'SUDO': sudo_path,
}
safe_module = ast.Module(
    body=[safe_function, privilege_function],
    type_ignores=[],
)
ast.fix_missing_locations(safe_module)
exec(compile(safe_module, str(app_path), 'exec'), safe_namespace)
with tempfile.TemporaryDirectory(prefix='noid-tools-exec.',
                                 dir='/var/tmp') as temporary:
    root = pathlib.Path(temporary)
    executable = root / 'noid-executable'
    executable.write_text('fixture', encoding='utf-8')
    os.chmod(executable, 0o700)
    root_only = root / 'noid-root-only'
    root_only.write_text('fixture', encoding='utf-8')
    # The fixture is owned by the test user. Give only "other" execute so
    # os.access() denies the owner while the mocked root metadata still has
    # an execute bit, modelling a root-only helper without chown privileges.
    os.chmod(root_only, 0o001)
    nonexec = root / 'noid-nonexec'
    nonexec.write_text('fixture', encoding='utf-8')
    privileged = root / 'noid-unexpected-setid'
    privileged.write_text('fixture', encoding='utf-8')
    os.chmod(privileged, 0o4700)
    symlink = root / 'noid-symlink'
    symlink.symlink_to(executable)
    predicate = safe_namespace['_is_safe_executable']
    if (not predicate(executable)
            or predicate(root_only)
            or not predicate(root_only, allow_root_only=True)
            or predicate(nonexec, allow_root_only=True)
            or predicate(privileged, allow_root_only=True)
            or predicate(symlink, allow_root_only=True)):
        raise SystemExit('safe-executable predicate accepted unsafe state')

    hardened_sudo = root / 'sudo-hardened'
    hardened_sudo.write_text('fixture', encoding='utf-8')
    os.chmod(hardened_sudo, 0o4111)
    fedora_sudo = root / 'sudo-fedora'
    fedora_sudo.write_text('fixture', encoding='utf-8')
    os.chmod(fedora_sudo, 0o4755)
    no_setuid = root / 'sudo-no-setuid'
    no_setuid.write_text('fixture', encoding='utf-8')
    os.chmod(no_setuid, 0o0111)
    writable_sudo = root / 'sudo-writable'
    writable_sudo.write_text('fixture', encoding='utf-8')
    os.chmod(writable_sudo, 0o4133)
    setgid_sudo = root / 'sudo-setgid'
    setgid_sudo.write_text('fixture', encoding='utf-8')
    os.chmod(setgid_sudo, 0o6111)
    sudo_symlink = root / 'sudo-symlink'
    sudo_symlink.symlink_to(hardened_sudo)
    sudo_predicate = safe_namespace['_is_safe_privilege_launcher']
    if (not sudo_predicate(hardened_sudo)
            or not sudo_predicate(fedora_sudo)
            or sudo_predicate(no_setuid)
            or sudo_predicate(writable_sudo)
            or sudo_predicate(setgid_sudo)
            or sudo_predicate(sudo_symlink)):
        raise SystemExit(
            'privilege-launcher predicate rejected canonical sudo metadata '
            'or accepted an unsafe form')

# Execute the exact privilege router without importing GTK.
action_function = top_level('_action_argv', ast.FunctionDef)
action_namespace = {
    'SUDO': sudo_path,
    'SUDO_ACTIONS': sudo_actions,
}
action_module = ast.Module(body=[action_function], type_ignores=[])
ast.fix_missing_locations(action_module)
exec(compile(action_module, str(app_path), 'exec'), action_namespace)
action_argv = action_namespace['_action_argv']
if action_argv(
        '/usr/local/sbin/noid-wan-strict', 'Status', ['status']) != [
            '/usr/bin/sudo', '--',
            '/usr/local/sbin/noid-wan-strict', 'status']:
    raise SystemExit('reviewed root action did not receive exact sudo argv')
if action_argv(
        '/usr/local/sbin/noid-toggle-wan-strict', 'Status', ['status']) != [
            '/usr/local/sbin/noid-toggle-wan-strict', 'status']:
    raise SystemExit('unprivileged status action was broadened to root')

# Execute the selector guard without importing GTK or constructing a window.
tools_window = top_level('ToolsWindow', ast.ClassDef)
selector = next(
    node for node in tools_window.body
    if isinstance(node, ast.FunctionDef) and node.name == '_selected_argv')
selector.decorator_list = []
selector_module = ast.Module(body=[selector], type_ignores=[])
ast.fix_missing_locations(selector_module)
selector_namespace = {'_action_argv': action_argv}
exec(compile(selector_module, str(app_path), 'exec'), selector_namespace)

class Selection:
    def __init__(self, value):
        self.value = value

    def get_selected(self):
        return self.value

verbs = [('Status', ['status']), ('Enable', ['on'])]
select = selector_namespace['_selected_argv']
if select('/helper', verbs, Selection(0)) != ['/helper', 'status']:
    raise SystemExit('valid default selection does not resolve exactly')
if select('/helper', verbs, Selection(2**32 - 1)) is not None:
    raise SystemExit('GTK invalid-list-position is not rejected')
PY
then
    _pass "runtime inventory and drop-down selection fail closed"
else
    _fail "runtime inventory/drop-down fail-closed contract violated"
fi

# --- Cross-module wiring ----------------------------------------------------
assert_grep_fixed '%include snippets/37-noid-tools-app.ks' "$MASTER_KS" \
    "master.ks includes Module 37"
assert_grep_fixed '"37:noid-tools-app"' "$M99_FILE" \
    "M99 EXPECTED_STAMPS adopts the Module 37 stamp"
assert_grep_fixed 'stamp-37-noid-tools-app.ok' "$KS_FILE" \
    "stamp filename matches the M99 default spec mapping"
assert_grep_extended 'for label in setup wizard update welcome install network tools; do' \
    "$M32_FILE" "M32 fetch + install loops carry the tools icon label"
assert_eq 3 \
    "$(grep -cF 'for label in setup wizard update welcome install network tools; do' \
        "$M32_FILE" || true)" \
    "all three M32 icon loops carry the complete reviewed label set"
for size in 48 64 128 256; do
    assert_file_exists "$PROJECT_ROOT/branding/icons/noid-privacy-tools-${size}.png"
    assert_grep_fixed "icons/noid-privacy-tools-${size}.png" \
        "$PROJECT_ROOT/branding/SHA256SUMS" \
        "branding manifest carries tools icon ${size}px"
done
assert_grep_fixed '[tools]="Tools"' \
    "$PROJECT_ROOT/branding/icons/regenerate-icons.sh" \
    "icon generator includes the tools label"
assert_grep_fixed 'magick mogrify -strip -define png:exclude-chunk=tIME' \
    "$PROJECT_ROOT/branding/icons/regenerate-icons.sh" \
    "icon generator explicitly excludes PNG timestamp metadata"

# --- Install-time evidence --------------------------------------------------
assert_grep_fixed '--verify-fresh-inventory' "$TMP_APP" \
    "app exposes the closed fresh-image inventory verifier"
assert_grep_fixed '--verify-privilege-launcher' "$TMP_APP" \
    "app exposes the canonical sudo metadata verifier"
assert_grep_fixed \
    'python3 "$TOOLS_CANDIDATE" --verify-privilege-launcher' "$KS_FILE" \
    "M37 rejects an unsafe privilege launcher before publication"
assert_grep_fixed '/usr/local/bin/noid-tools --verify-fresh-inventory' \
    "$KS_FILE" "M37 fails the image build on unclassified runtime helpers"
assert_grep_fixed "stat -Lc '%u:%g:%a:%h' /usr/local/bin/noid-tools" \
    "$KS_FILE" "M37 verifies exact executable ownership, mode and link count"
assert_grep_fixed '8#$helper_mode & 07022' "$KS_FILE" \
    "M37 rejects writable or unexpectedly set-ID curated helpers"
assert_grep_fixed 'catalog_path_count=$(printf' "$KS_FILE" \
    "M37 counts the helper paths actually scraped from the installed catalog"
assert_grep_fixed 'if [ "$catalog_path_count" -lt 40 ]; then' "$KS_FILE" \
    "M37 fails closed when the curated-helper scrape is empty or implausible"
assert_grep_fixed 'curated helper inventory is implausibly small' "$KS_FILE" \
    "M37 reports a vacuous curated-helper verification distinctly"
assert_grep_fixed "stat -Lc '%u:%g:%a:%h' /usr/share/applications/noid-tools.desktop" \
    "$KS_FILE" "M37 verifies exact desktop ownership, mode and link count"
assert_not_grep 'restorecon .*2>/dev/null || true' "$KS_FILE" \
    "M37 does not hide SELinux relabel failures"

# --- Failure-atomic health evidence ----------------------------------------
assert_grep_fixed 'verify_m37_health_stamp()' "$KS_FILE" \
    "M37 validates staged and final health evidence with one exact schema"
assert_grep_fixed 'STAMP_PUBLICATION_ACTIVE=1' "$KS_FILE" \
    "published M37 evidence remains removable through every final gate"
assert_grep_fixed 'ROOT_PUBLICATION_TMP=$temporary' "$KS_FILE" \
    "M37 registers the active root-publication candidate for cleanup"
assert_grep_fixed "trap 'exit 129' HUP" "$KS_FILE" \
    "M37 preserves a HUP-derived failure status"
assert_grep_fixed "trap 'exit 130' INT" "$KS_FILE" \
    "M37 preserves an INT-derived failure status"
assert_grep_fixed "trap 'exit 143' TERM" "$KS_FILE" \
    "M37 preserves a TERM-derived failure status"
assert_grep_fixed "trap '' HUP INT TERM" "$KS_FILE" \
    "M37 bounds signal deferral to its atomic publication window"
assert_grep_fixed '/usr/sbin/matchpathcon -V "$STAMP_CANDIDATE"' "$KS_FILE" \
    "M37 verifies the staged candidate SELinux context"
assert_grep_fixed '/usr/sbin/matchpathcon -V "$STAMP"' "$KS_FILE" \
    "M37 verifies the final stamp SELinux context"

invalidate_line=$(grep -nF \
    '# M37_HEALTH_INVALIDATION_BEGIN' "$KS_FILE" | cut -d: -f1 || true)
first_payload_line=$(grep -nF \
    'ensure_root_dir /usr/local/bin 0755' "$KS_FILE" | cut -d: -f1 || true)
verify_guard_line=$(grep -nF \
    'if [ "$ver_fail" -eq 0 ]; then' "$KS_FILE" | cut -d: -f1 || true)
publish_line=$(grep -nF \
    '# M37_HEALTH_PUBLICATION_BEGIN' "$KS_FILE" | cut -d: -f1 || true)
complete_line=$(grep -nF \
    'log "=== Module 37 complete: NoID Privacy Tools App installed ==="' \
    "$KS_FILE" | cut -d: -f1 || true)
if [ -n "$invalidate_line" ] && [ -n "$first_payload_line" ] \
   && [ -n "$verify_guard_line" ] && [ -n "$publish_line" ] \
   && [ -n "$complete_line" ] \
   && [ "$invalidate_line" -lt "$first_payload_line" ] \
   && [ "$verify_guard_line" -lt "$publish_line" ] \
   && [ "$publish_line" -lt "$complete_line" ]; then
    _pass "M37 retires old health before mutation and publishes after verification"
else
    _fail "M37 health-stamp ordering is not failure-atomic"
fi

# Execute the exact production health-boundary blocks under every material
# publication failure.
m37_stamp_root="$EXEC_FIXTURE_DIR/health-stamp"
m37_stamp_state="$m37_stamp_root/state"
m37_stamp_bin="$m37_stamp_root/bin"
m37_stamp_invalidate="$m37_stamp_root/invalidate.sh"
m37_stamp_publish="$m37_stamp_root/publish.sh"
m37_stamp_uid=$(id -u)
m37_stamp_gid=$(id -g)
mkdir -p "$m37_stamp_bin"

cat > "$m37_stamp_bin/restorecon" <<'M37_STAMP_RESTORECON_EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${!#}"
case "${FAKE_RESTORECON_FAIL:-}" in
    all) exit 1 ;;
    final)
        case "$target" in
            */stamp-37-noid-tools-app.ok) exit 1 ;;
        esac
        ;;
esac
exit 0
M37_STAMP_RESTORECON_EOF
cat > "$m37_stamp_bin/matchpathcon" <<'M37_STAMP_MATCHPATHCON_EOF'
#!/usr/bin/env bash
exit 0
M37_STAMP_MATCHPATHCON_EOF
cat > "$m37_stamp_bin/mv" <<'M37_STAMP_MV_EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${FAKE_MV_FAIL:-0}" -eq 1 ]; then
    exit 1
fi
exec /usr/bin/mv "$@"
M37_STAMP_MV_EOF
chmod 0700 "$m37_stamp_bin/restorecon" \
    "$m37_stamp_bin/matchpathcon" "$m37_stamp_bin/mv"

{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'log() { :; }' 'fail() { exit 1; }' \
        "STAMP_DIR=$m37_stamp_state" \
        'STAMP="$STAMP_DIR/stamp-37-noid-tools-app.ok"'
    sed -n \
        '/^# M37_HEALTH_INVALIDATION_BEGIN$/,/^# M37_HEALTH_INVALIDATION_END$/p' \
        "$KS_FILE" |
        sed -e "s|-o root -g root|-o $m37_stamp_uid -g $m37_stamp_gid|" \
            -e "s|0:0:755|$m37_stamp_uid:$m37_stamp_gid:755|" \
            -e "s|/usr/sbin/restorecon|$m37_stamp_bin/restorecon|g" \
            -e "s|/usr/sbin/matchpathcon|$m37_stamp_bin/matchpathcon|g"
} > "$m37_stamp_invalidate"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'log() { :; }' 'fail() { exit 1; }' \
        'TOOLS_CANDIDATE=' 'DESKTOP_CANDIDATE=' \
        'STAMP_CANDIDATE=' 'ROOT_PUBLICATION_TMP=' \
        'STAMP_PUBLICATION_ACTIVE=0' \
        "STAMP_DIR=$m37_stamp_state" \
        'STAMP="$STAMP_DIR/stamp-37-noid-tools-app.ok"' \
        'ver_ok=7' 'ver_fail=0'
    sed -n '/^cleanup_candidates() {$/,/^}$/p' "$KS_FILE"
    printf '%s\n' 'trap cleanup_candidates EXIT'
    awk '
        /^publish_root_file\(\) \{$/ { capture = 1 }
        capture { print }
        capture && /^\}$/ { exit }
    ' "$KS_FILE" |
        sed -e "s|-o root -g root|-o $m37_stamp_uid -g $m37_stamp_gid|g" \
            -e "s|chown root:root|chown $m37_stamp_uid:$m37_stamp_gid|g" \
            -e "s|0:0:|$m37_stamp_uid:$m37_stamp_gid:|g"
    sed -n \
        '/^# M37_HEALTH_PUBLICATION_BEGIN$/,/^# M37_HEALTH_PUBLICATION_END$/p' \
        "$KS_FILE" |
        sed -e "s|chown root:root|chown $m37_stamp_uid:$m37_stamp_gid|g" \
            -e "s|0:0:|$m37_stamp_uid:$m37_stamp_gid:|g" \
            -e "s|/usr/sbin/restorecon|$m37_stamp_bin/restorecon|g" \
            -e "s|/usr/sbin/matchpathcon|$m37_stamp_bin/matchpathcon|g"
} > "$m37_stamp_publish"
chmod 0700 "$m37_stamp_invalidate" "$m37_stamp_publish"

mkdir -m 0755 "$m37_stamp_state"
printf '%s\n' 'module=37' 'name=noid-tools-app' 'status=ok' \
    > "$m37_stamp_state/stamp-37-noid-tools-app.ok"
assert_cmd_success "M37 rerun invalidates its prior build-success stamp" \
    env PATH="$m37_stamp_bin:$PATH" "$m37_stamp_invalidate"
if [ ! -e "$m37_stamp_state/stamp-37-noid-tools-app.ok" ]; then
    _pass "M37 old success evidence is absent before payload publication"
else
    _fail "M37 old success evidence is absent before payload publication"
fi

chmod 0777 "$m37_stamp_state"
printf '%s\n' 'must-survive' > "$m37_stamp_state/stamp-37-noid-tools-app.ok"
assert_cmd_failure "M37 rejects shared state-directory metadata drift" \
    env PATH="$m37_stamp_bin:$PATH" "$m37_stamp_invalidate"
assert_eq "$m37_stamp_uid:$m37_stamp_gid:777" \
    "$(stat -c '%u:%g:%a' "$m37_stamp_state")" \
    "M37 does not normalize drifted shared-directory metadata"
assert_grep_fixed 'must-survive' \
    "$m37_stamp_state/stamp-37-noid-tools-app.ok" \
    "M37 does not traverse a drifted shared state boundary"
rm "$m37_stamp_state/stamp-37-noid-tools-app.ok"
chmod 0755 "$m37_stamp_state"

assert_cmd_failure "M37 rejects a health-stamp candidate label failure" \
    env PATH="$m37_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=all \
        "$m37_stamp_publish"
if [ ! -e "$m37_stamp_state/stamp-37-noid-tools-app.ok" ] \
   && [ -z "$(find "$m37_stamp_state" -maxdepth 1 \
        -name '.stamp-37-noid-tools-app.ok.*' -print -quit)" ]; then
    _pass "M37 candidate-label failure leaves no plausible health evidence"
else
    _fail "M37 candidate-label failure leaves no plausible health evidence"
fi

assert_cmd_failure "M37 retires a stamp after final-label failure" \
    env PATH="$m37_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=final \
        "$m37_stamp_publish"
if [ ! -e "$m37_stamp_state/stamp-37-noid-tools-app.ok" ]; then
    _pass "M37 final-label failure removes the published success stamp"
else
    _fail "M37 final-label failure removes the published success stamp"
fi

assert_cmd_failure "M37 rejects an atomic health-stamp rename failure" \
    env PATH="$m37_stamp_bin:$PATH" FAKE_MV_FAIL=1 "$m37_stamp_publish"
if [ ! -e "$m37_stamp_state/stamp-37-noid-tools-app.ok" ] \
   && [ -z "$(find "$m37_stamp_state" -maxdepth 1 \
        -name '.stamp-37-noid-tools-app.ok.*' -print -quit)" ]; then
    _pass "M37 rename failure leaves no stamp or staged candidate"
else
    _fail "M37 rename failure leaves no stamp or staged candidate"
fi

assert_cmd_success "M37 publishes exact health evidence after all gates" \
    env PATH="$m37_stamp_bin:$PATH" "$m37_stamp_publish"
assert_grep_fixed 'module=37' \
    "$m37_stamp_state/stamp-37-noid-tools-app.ok"
assert_grep_fixed 'name=noid-tools-app' \
    "$m37_stamp_state/stamp-37-noid-tools-app.ok"
assert_grep_fixed 'checks_passed=7' \
    "$m37_stamp_state/stamp-37-noid-tools-app.ok"
assert_grep_fixed 'checks_total=7' \
    "$m37_stamp_state/stamp-37-noid-tools-app.ok"
assert_eq 10 "$(wc -l < "$m37_stamp_state/stamp-37-noid-tools-app.ok")" \
    "M37 published health stamp has the exact ten-line schema"

# A signal outside the bounded rename window must retain its signal-derived
# status and retire the registered root-publication candidate.
m37_signal_script="$EXEC_FIXTURE_DIR/root-signal-cleanup.sh"
m37_signal_ready="$EXEC_FIXTURE_DIR/root-signal.ready"
m37_signal_candidate="$EXEC_FIXTURE_DIR/root-signal.candidate"
{
    printf '%s\n' '#!/usr/bin/bash' 'set -euo pipefail' \
        'log() { :; }' \
        "STAMP_DIR=$EXEC_FIXTURE_DIR" \
        'STAMP="$STAMP_DIR/stamp-37-noid-tools-app.ok"' \
        'STAMP_PUBLICATION_ACTIVE=0' \
        "ROOT_PUBLICATION_TMP=$m37_signal_candidate" \
        'TOOLS_CANDIDATE=' 'DESKTOP_CANDIDATE=' 'STAMP_CANDIDATE='
    sed -n '/^cleanup_candidates() {$/,/^}$/p' "$KS_FILE"
    printf '%s\n' \
        'trap cleanup_candidates EXIT' \
        "trap 'exit 129' HUP" \
        "trap 'exit 130' INT" \
        "trap 'exit 143' TERM" \
        "printf '%s\\n' candidate > \"$m37_signal_candidate\"" \
        "printf '%s\\n' ready > \"$m37_signal_ready\"" \
        'while :; do :; done'
} > "$m37_signal_script"
chmod 0700 "$m37_signal_script"
"$m37_signal_script" &
m37_signal_pid=$!
for _ in $(seq 1 500); do
    [ -e "$m37_signal_ready" ] && break
    sleep 0.01
done
set +e
kill -TERM "$m37_signal_pid" 2>/dev/null
wait "$m37_signal_pid"
m37_signal_rc=$?
set -e
if [ "$m37_signal_rc" -eq 143 ] \
   && [ ! -e "$m37_signal_candidate" ]; then
    _pass "M37 TERM cleanup retires the active root-publication candidate"
else
    _fail "M37 TERM cleanup leaked a candidate or returned $m37_signal_rc"
fi

test_finish
