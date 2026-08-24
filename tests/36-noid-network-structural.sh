#!/bin/bash
# 36-noid-network-structural — verify Module 36 NoID Privacy Network App
#
# Standalone GTK4+libadwaita GUI for WAN-egress-strict, LAN exceptions,
# global resolver selection and verified local network state.
#
# Covers:
#   - /usr/local/bin/noid-network Python heredoc (NOID_NETWORK_PY_EOF)
#   - /usr/local/bin/noid-network-audit shell heredoc
#   - /usr/share/applications/noid-network.desktop heredoc
#   - 4 ViewStack pages + persistent identity + adaptive section navigation
#   - Backend CLI invocations (WAN_TOGGLE_CLI / WAN_STRICT_CLI / LAN_ALLOW_CLI)
#   - exact noninteractive sudo / installed pkexec fallback + rc-check toast
#   - Verify block (STEP 4)

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/36-noid-network-app.ks"
M06_FILE="$PROJECT_ROOT/kickstart/snippets/06-vpn-killswitch.ks"

test_start "36-noid-network-structural"

assert_file_exists "$KS_FILE"
assert_file_exists "$M06_FILE"
assert_cmd_success "bash -n $KS_FILE" bash -n "$KS_FILE"
assert_grep_fixed 'one of the four' "$KS_FILE" \
    "module header counts all four first-party NoID Privacy apps"
assert_grep_fixed 'beside Setup, Update and Tools' "$KS_FILE" \
    "module header names the other three first-party apps"
assert_not_grep 'Module 36 v[0-9]' "$KS_FILE" \
    "install logs do not carry a manually drifting module version"

TMPDIR="$(mktemp -d /var/tmp/noid-m36-test.XXXXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

extract_heredoc "$KS_FILE" "NOID_NETWORK_PY_EOF"      "$TMPDIR/noid-network" || _fail "Python heredoc extraction"
extract_heredoc "$KS_FILE" "NOID_NETWORK_AUDIT_EOF"   "$TMPDIR/noid-network-audit" || _fail "audit heredoc extraction"
extract_heredoc "$KS_FILE" "NOID_NETWORK_DESKTOP_EOF" "$TMPDIR/noid-network.desktop" || _fail "desktop heredoc extraction"

# --- Python: syntax + structural symbols -----------------------------------
assert_cmd_success "Python ast.parse" python3 -c "import ast; ast.parse(open('$TMPDIR/noid-network').read())"
assert_cmd_success "audit bash syntax" bash -n "$TMPDIR/noid-network-audit"
audit_smoke="$TMPDIR/noid-network-audit-smoke"
cp -- "$TMPDIR/noid-network-audit" "$audit_smoke"
sed -i \
    -e "s#^FMT_LIB=.*#FMT_LIB=$TMPDIR/absent-format/agent-install-format.sh#" \
    -e "s#^FMT_PARENT=.*#FMT_PARENT=$TMPDIR/absent-format#" \
    "$audit_smoke"
assert_cmd_success "audit help smoke uses its source-owned fallback formatter" \
    bash "$audit_smoke" --help
assert_grep_fixed 'PATH=/usr/sbin:/usr/bin:/sbin:/bin' "$audit_smoke" \
    "audit pins its command-search path before invoking any bare utility"

audit_expect_rc() {
    local expected=$1 description=$2 actual
    shift 2
    set +e
    /usr/bin/bash "$audit_smoke" "$@" \
        >"$TMPDIR/audit-argv.stdout" 2>"$TMPDIR/audit-argv.stderr"
    actual=$?
    set -e
    if [ "$actual" -eq "$expected" ]; then
        _pass "$description"
    else
        _fail "$description (expected $expected, got $actual)"
    fi
}

audit_expect_rc 2 "audit rejects surplus help arguments" --help '' extra
audit_expect_rc 2 "audit rejects an explicit empty worker argument" wan ''
audit_expect_rc 2 "audit rejects a third root-worker argument before privilege" \
    wan --root-worker extra
audit_expect_rc 2 "audit rejects an unknown mode" 'wan; rm -rf /'

fake_path_bin="$TMPDIR/fake-path-bin"
fake_cat_marker="$TMPDIR/fake-cat-called"
mkdir -p "$fake_path_bin"
cat >"$fake_path_bin/cat" <<'FAKE_CAT_EOF'
#!/bin/sh
: >"$NOID_TEST_FAKE_CAT_MARKER"
exec /usr/bin/cat "$@"
FAKE_CAT_EOF
chmod 700 "$fake_path_bin/cat"
if NOID_TEST_FAKE_CAT_MARKER="$fake_cat_marker" \
        PATH="$fake_path_bin" /usr/bin/bash "$audit_smoke" --help \
        >"$TMPDIR/audit-path.stdout" 2>"$TMPDIR/audit-path.stderr" \
        && [ ! -e "$fake_cat_marker" ]; then
    _pass "audit help ignores a hostile caller PATH"
else
    _fail "audit help ignored neither a hostile caller PATH nor its fake cat"
fi

# Core constants + paths
assert_grep_fixed "APP_ID = 'com.noidprivacy.Network'" "$TMPDIR/noid-network"
assert_grep_fixed "WAN_STATEFILE = '/var/lib/noid-privacy/wan-strict-endpoints.txt'" "$TMPDIR/noid-network"
assert_grep_fixed "WAN_STATUS_FILE = '/run/noid-privacy/wan-strict-status'" "$TMPDIR/noid-network"
assert_grep_fixed "WAN_TOGGLE_CLI = '/usr/local/sbin/noid-toggle-wan-strict'" "$TMPDIR/noid-network"
assert_grep_fixed "WAN_STRICT_CLI = '/usr/local/sbin/noid-wan-strict'"        "$TMPDIR/noid-network"
assert_grep_fixed "LAN_ALLOW_CLI = '/usr/local/bin/noid-lan-allow'"           "$TMPDIR/noid-network"
assert_grep_fixed "DNS_MODE_CLI = '/usr/local/sbin/noid-dns-mode'"            "$TMPDIR/noid-network"
assert_grep_fixed "NETWORK_AUDIT_CLI = '/usr/local/bin/noid-network-audit'"   "$TMPDIR/noid-network"
for contract in \
    "SUDO_CLI = '/usr/bin/sudo'" \
    "PKEXEC_CLI = '/usr/bin/pkexec'" \
    "NMCLI_CLI = '/usr/bin/nmcli'" \
    "IP_CLI = '/usr/bin/ip'" \
    "FIREWALL_CLI = '/usr/bin/firewall-cmd'" \
    "RESOLVECTL_CLI = '/usr/bin/resolvectl'" \
    "WAN_STATE_DIR = '/var/lib/noid-privacy'" \
    "WAN_RUNTIME_DIR = '/run/noid-privacy'"; do
    assert_grep_fixed "$contract" "$TMPDIR/noid-network" \
        "GUI pins system interface: $contract"
done
assert_grep_fixed 'status|pause|resume|arm-empty|reset|scan-profiles' \
    "$TMPDIR/noid-network" \
    "GUI help enumerates every reachable WAN-strict backend verb"
assert_not_grep '^import shutil$' "$TMPDIR/noid-network" \
    "GUI does not resolve trusted system programs through user PATH"
assert_grep_fixed 'def _read_root_published_ascii' "$TMPDIR/noid-network" \
    "WAN views share one root-published state reader"
assert_grep_fixed "getattr(os, 'O_NOFOLLOW', 0)" "$TMPDIR/noid-network" \
    "state reader refuses a symlink at open time"
assert_grep_fixed "(opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)" \
    "$TMPDIR/noid-network" \
    "state reader detects an identity change between inspection and open"
assert_grep_fixed "ROOT_STATE_MAX_BYTES = 1024 * 1024" \
    "$TMPDIR/noid-network" \
    "root-published GUI state has a fixed memory bound"
assert_grep_fixed "parts[3] not in ('tcp', 'udp')" "$TMPDIR/noid-network" \
    "WAN state parser validates transport"
assert_grep_fixed \
    "parts[2] not in ('literal', 'authenticated', 'retained')" \
    "$TMPDIR/noid-network" \
    "WAN state parser validates provenance"
assert_grep_fixed "WAN_STATE_HEADER = 'NOID-WAN-ENDPOINTS-V2'" "$TMPDIR/noid-network" \
    "WAN state parser pins the closed v2 schema"
assert_grep_fixed 'not 1 <= port <= 65535' "$TMPDIR/noid-network" \
    "WAN state parser validates destination port"
assert_grep_fixed "row.set_title(f'{proto.upper()} {endpoint_label}')" "$TMPDIR/noid-network" \
    "WAN page renders exact endpoint tuples"
assert_grep_fixed 'def _group_wan_endpoint_records' "$TMPDIR/noid-network" \
    "WAN page groups profile provenance by the enforced tuple"
assert_grep_fixed 'Duplicate endpoint state entry; strict bootstrap' \
    "$TMPDIR/noid-network" \
    "GUI rejects duplicate records exactly like the endpoint authority"
assert_not_grep 'except Exception:' "$TMPDIR/noid-network" \
    "WAN state read does not swallow arbitrary exceptions"

assert_cmd_success "WAN state readers enforce metadata and M06's closed schema" \
    python3 - "$TMPDIR/noid-network" "$TMPDIR/wan-state-fixture" <<'PY'
import ast
import ipaddress
import os as real_os
from pathlib import Path
import re
import stat
import sys
from types import SimpleNamespace
import uuid

tree = ast.parse(Path(sys.argv[1]).read_text(encoding='utf-8'))
wanted = {
    '_read_root_published_ascii', '_wan_runtime_mode', '_validate_ip',
    '_validate_endpoint_ip', '_wan_endpoint_records',
    # Composed below against the producer. Exercising the two halves in
    # separate fixtures let a 7-tuple producer feed an 8-name consumer
    # unnoticed, which raised ValueError in _refresh_wan_endpoints on every
    # installed host that had actually pinned an endpoint.
    '_group_wan_endpoint_records',
}
nodes = [
    node for node in tree.body
    if isinstance(node, ast.FunctionDef) and node.name in wanted
]
module = ast.Module(body=nodes, type_ignores=[])
ast.fix_missing_locations(module)

root = Path(sys.argv[2])
state_dir = root / 'var/lib/noid-privacy'
runtime_dir = root / 'run/noid-privacy'
state_dir.mkdir(parents=True)
runtime_dir.mkdir(parents=True)
state_dir.chmod(0o755)
runtime_dir.chmod(0o755)
state_file = state_dir / 'wan-strict-endpoints.txt'
status_file = runtime_dir / 'wan-strict-status'

def as_root(value):
    return SimpleNamespace(
        st_mode=value.st_mode,
        st_uid=0,
        st_gid=0,
        st_nlink=value.st_nlink,
        st_dev=value.st_dev,
        st_ino=value.st_ino,
        st_size=value.st_size,
    )

class RootMetadataOS:
    path = real_os.path
    O_RDONLY = real_os.O_RDONLY
    O_CLOEXEC = real_os.O_CLOEXEC
    O_NOFOLLOW = getattr(real_os, 'O_NOFOLLOW', 0)
    open = staticmethod(real_os.open)
    close = staticmethod(real_os.close)
    fdopen = staticmethod(real_os.fdopen)

    @staticmethod
    def lstat(path):
        return as_root(real_os.lstat(path))

    @staticmethod
    def fstat(fd):
        return as_root(real_os.fstat(fd))

namespace = {
    'os': RootMetadataOS,
    'stat': stat,
    'sys': sys,
    're': re,
    'uuid': uuid,
    'ipaddress': ipaddress,
    'WAN_STATEFILE': str(state_file),
    'WAN_STATE_DIR': str(state_dir),
    'WAN_STATE_HEADER': 'NOID-WAN-ENDPOINTS-V2',
    'WAN_STATUS_FILE': str(status_file),
    'WAN_RUNTIME_DIR': str(runtime_dir),
    'ROOT_STATE_MAX_BYTES': 1024 * 1024,
}
exec(compile(module, '<wan-state-fixture>', 'exec'), namespace)
parse = namespace['_wan_endpoint_records']
runtime = namespace['_wan_runtime_mode']

profile = 'c1a31175-af28-4427-8888-5c9fadd7ec68'
fingerprint = 'a' * 64
record = (
    f'{profile} {fingerprint} literal udp 198.51.100.7 443 0\n'
)
retained_record = (
    f'{profile} {fingerprint} retained udp 198.51.100.8 443 4102444800\n'
)

assert parse() == ([], None)
state_file.write_text('', encoding='ascii')
state_file.chmod(0o644)
assert parse() == ([], None)
state_file.write_text('NOID-WAN-ENDPOINTS-V2\n' + record, encoding='ascii')
records, error = parse()
assert error is None
assert records == [
    ('udp', '198.51.100.7', 443, 'ipv4', 'literal', profile, fingerprint, 0)
]

# M06's current closed V2 schema also publishes a bounded `retained` lease
# when a provider-owned runtime profile disappears. The GUI must render that
# valid record rather than reporting a corrupt endpoint state.
state_file.write_text(
    'NOID-WAN-ENDPOINTS-V2\n' + record + retained_record,
    encoding='ascii')
records, error = parse()
assert error is None
assert records == [
    ('udp', '198.51.100.7', 443, 'ipv4', 'literal', profile, fingerprint, 0),
    ('udp', '198.51.100.8', 443, 'ipv4', 'retained', profile, fingerprint,
     4102444800),
]
state_file.write_text(
    'NOID-WAN-ENDPOINTS-V2\n'
    f'{profile} {fingerprint} retained udp 198.51.100.8 443 0\n',
    encoding='ascii')
assert parse()[0] == [] and 'Invalid' in parse()[1]

state_file.write_text('NOID-WAN-ENDPOINTS-V2\n' + record, encoding='ascii')
records, error = parse()
assert error is None

# Composition: exactly what _refresh_wan_endpoints does. This is the check the
# two isolated fixtures could not perform, and the one that fails loudly if the
# producer's append arity ever drifts from the consumer's unpack again.
group = namespace['_group_wan_endpoint_records']
grouped = group(records)
assert len(grouped) == 1
proto, address, port, family, details = grouped[0]
assert (proto, address, port, family) == ('udp', '198.51.100.7', 443, 'ipv4')
assert details == ((('literal', profile, fingerprint, 0)),)

state_file.write_text(
    'NOID-WAN-ENDPOINTS-V2\n' + record + record, encoding='ascii')
assert parse()[0] == [] and 'Duplicate' in parse()[1]
state_file.write_text(
    'NOID-WAN-ENDPOINTS-V2\n'
    f'{profile} {fingerprint} literal udp 127.0.0.1 443 0\n',
    encoding='ascii')
assert parse()[0] == [] and 'Invalid' in parse()[1]
state_file.write_text(
    'NOID-WAN-ENDPOINTS-V2\n'
    f'{profile} {fingerprint} literal udp 198.51.100.7 +443 0\n',
    encoding='ascii')
assert parse()[0] == [] and 'Invalid' in parse()[1]

state_file.write_text('NOID-WAN-ENDPOINTS-V2\n' + record, encoding='ascii')
state_file.chmod(0o666)
assert parse()[0] == [] and 'metadata' in parse()[1]
state_file.chmod(0o644)
state_dir.chmod(0o777)
assert parse()[0] == [] and 'parent metadata' in parse()[1]
state_dir.chmod(0o755)
with state_file.open('wb') as stream:
    stream.truncate(1024 * 1024 + 1)
state_file.chmod(0o644)
assert parse()[0] == [] and 'metadata' in parse()[1]

real_file = state_dir / 'real-state'
state_file.unlink()
real_file.write_text('NOID-WAN-ENDPOINTS-V2\n' + record, encoding='ascii')
real_file.chmod(0o644)
state_file.symlink_to(real_file.name)
assert parse()[0] == [] and 'metadata' in parse()[1]
state_file.unlink()
real_os.link(real_file, state_file)
assert parse()[0] == [] and 'metadata' in parse()[1]
state_file.unlink()
real_file.unlink()

status_file.write_text('MODE=STRICT\n', encoding='ascii')
status_file.chmod(0o644)
assert runtime() == 'STRICT'
status_file.write_text('MODE=STRICT\nextra\n', encoding='ascii')
assert runtime() == 'ERROR'
status_file.unlink()
assert runtime() == 'UNKNOWN'
runtime_dir.chmod(0o777)
assert runtime() == 'ERROR'
PY
assert_not_grep 'Works with any WireGuard/OpenVPN client' "$TMPDIR/noid-network" \
    "GUI does not claim universal provider compatibility"
assert_grep_fixed 'def _wan_runtime_mode' "$TMPDIR/noid-network" \
    "GUI consumes one machine-readable WAN status contract"
assert_grep_fixed 'def _wan_feature_enabled' "$TMPDIR/noid-network" \
    "GUI derives feature-switch state from the published runtime mode"
assert_not_grep '_flag_file_present\|WAN_FLAG' "$TMPDIR/noid-network" \
    "GUI never short-circuits the published mode with flag-only inference"
assert_grep_fixed "initial_mode not in {'ERROR', 'UNKNOWN'}" "$TMPDIR/noid-network" \
    "unverifiable WAN state disables the GUI toggle"
assert_grep_fixed "WAN physical-egress policy enabled" "$TMPDIR/noid-network" \
    "feature switch does not label bootstrap grace as strict"
for mode in DISABLED GRACE_BOOTSTRAP GRACE_PAUSED STRICT STRICT_EMPTY ERROR UNKNOWN; do
    assert_grep_fixed "'$mode'" "$TMPDIR/noid-network" "GUI renders WAN state $mode"
done
assert_not_grep 'Strict mode active' "$TMPDIR/noid-network" \
    "feature switch does not label enabled bootstrap grace as strict"
assert_not_grep 'ENABLED — endpoint-pinned, bypass-blocked' "$TMPDIR/noid-network" \
    "status page has no flag-only strict overclaim"
assert_grep_fixed "def _lan_global_state" "$TMPDIR/noid-network" \
    "GUI consumes the backend's cross-layer LAN state contract"
assert_grep_fixed "[LAN_ALLOW_CLI, '--global-state']" "$TMPDIR/noid-network" \
    "GUI does not infer global LAN state from firewalld alone"
assert_not_grep 'def _lan_global_blocked' "$TMPDIR/noid-network" \
    "historical firewalld-only LAN status path is absent"
assert_grep_fixed "state in ('BLOCKED', 'ALLOWED')" "$TMPDIR/noid-network" \
    "unknown LAN state is never rendered optimistically"
assert_grep_fixed "state != 'INCONSISTENT' and not self._action_busy" \
    "$TMPDIR/noid-network" "inconsistent or busy LAN state disables mutation"
assert_grep_fixed 'ERROR — enforcement state is unverifiable; control disabled' \
    "$TMPDIR/noid-network" "inconsistent LAN state is visibly distinguished from BLOCKED"

# GTK4 + Adw imports
assert_grep_fixed "gi.require_version('Gtk', '4.0')" "$TMPDIR/noid-network"
assert_grep_fixed "gi.require_version('Adw', '1')"   "$TMPDIR/noid-network"

# 4 ViewStack pages
assert_grep_fixed "_build_wan_page"    "$TMPDIR/noid-network" "WAN Privacy page"
assert_grep_fixed "_build_lan_page"    "$TMPDIR/noid-network" "LAN Exceptions page"
assert_grep_fixed "_build_dns_page"    "$TMPDIR/noid-network" "DNS Privacy page"
assert_grep_fixed "_build_status_page" "$TMPDIR/noid-network" "Network Status page"
assert_grep_fixed "Adw.ViewStack"      "$TMPDIR/noid-network"
assert_grep_fixed "noid_ui.sectioned_app_bars" "$TMPDIR/noid-network" \
    "Network keeps the shared identity header beside adaptive navigation"
assert_grep_fixed "self, 'NoID Privacy Network', 'Privacy controls and local state'" \
    "$TMPDIR/noid-network" "Network passes its window to the breakpoint contract"
assert_grep_fixed 'toolbar.add_top_bar(header)' "$TMPDIR/noid-network" \
    "Network places the identity in the first top row"
assert_grep_fixed 'toolbar.add_top_bar(section_bar)' "$TMPDIR/noid-network" \
    "Network places section tabs in the second top row"
assert_grep_fixed "Adw.ToastOverlay"   "$TMPDIR/noid-network"
assert_grep_fixed 'import noid_ui' "$TMPDIR/noid-network" \
    "Network imports the shared UI contract"
assert_grep_fixed 'self.lan_ip_entry,' "$TMPDIR/noid-network" \
    "LAN entry is passed to the shared accessibility helper"
assert_grep_fixed 'Enter the one directly attached IPv4 peer to allow' \
    "$TMPDIR/noid-network" "LAN entry has an explicit input description"
assert_grep_fixed "self.lan_add_button, 'Add LAN exception'" \
    "$TMPDIR/noid-network" "LAN primary action names its exact effect"
assert_grep_fixed 'noid_ui.accessible_row(row)' "$TMPDIR/noid-network" \
    "dynamic Network rows publish explicit AT-SPI semantics"
assert_grep_fixed 'return noid_ui.action_row(emoji, title, subtitle, callback)' \
    "$TMPDIR/noid-network" "Network actions use the shared native button contract"
assert_grep_fixed "super().__init__(APP_ID, 'noid-privacy-network')" \
    "$TMPDIR/noid-network" "Network uses the shared one-instance base"
assert_not_grep 'Gio.ApplicationFlags.NON_UNIQUE' "$TMPDIR/noid-network" \
    "Network cannot open racing duplicate privileged-control windows"
assert_grep_fixed 'def _sync_wan_controls' "$TMPDIR/noid-network" \
    "WAN state has one closed UI synchronizer"
assert_grep_fixed 'self._sync_wan_controls()' "$TMPDIR/noid-network" \
    "visible WAN refresh re-synchronizes state and sensitivity"
assert_grep_fixed 'def _refresh_lan_page' "$TMPDIR/noid-network" \
    "LAN state has one complete page-refresh boundary"
assert_grep_fixed 'def _start_privileged' "$TMPDIR/noid-network" \
    "Network serializes privileged mutations"
assert_grep_fixed 'Another privileged network action is still running.' \
    "$TMPDIR/noid-network" "overlapping privileged mutations are rejected visibly"
assert_grep_fixed 'Network action still running' "$TMPDIR/noid-network" \
    "Network keeps its action lifecycle owned until backend completion"
assert_grep_fixed 'if not endpoints and read_error is None:' \
    "$TMPDIR/noid-network" "invalid WAN state cannot also claim an empty state"
assert_grep_fixed 'On — all locally classified destinations are reachable' \
    "$TMPDIR/noid-network" "LAN global subtitle follows the actual backend state"

assert_cmd_success "WAN endpoint rows collapse only identical enforced tuples" \
    python3 - "$TMPDIR/noid-network" <<'PY'
import ast
import sys

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
fn = next(node for node in tree.body
          if isinstance(node, ast.FunctionDef)
          and node.name == '_group_wan_endpoint_records')
module = ast.Module(body=[fn], type_ignores=[])
ast.fix_missing_locations(module)
namespace = {}
exec(compile(module, '<wan-endpoint-groups>', 'exec'), namespace)
group = namespace['_group_wan_endpoint_records']

records = [
    ('udp', '192.0.2.10', 443, 'ipv4', 'literal',
     '11111111-1111-4111-8111-111111111111', 'a' * 64, 0),
    ('udp', '192.0.2.10', 443, 'ipv4', 'literal',
     '22222222-2222-4222-8222-222222222222', 'b' * 64, 0),
    ('tcp', '2001:db8::10', 443, 'ipv6', 'authenticated',
     '33333333-3333-4333-8333-333333333333', 'c' * 64, 2000000000),
]
groups = group(records)
assert len(groups) == 2
ipv4 = next(item for item in groups if item[3] == 'ipv4')
ipv6 = next(item for item in groups if item[3] == 'ipv6')
assert ipv4[:4] == ('udp', '192.0.2.10', 443, 'ipv4')
assert len(ipv4[4]) == 2
assert {detail[1] for detail in ipv4[4]} == {
    '11111111-1111-4111-8111-111111111111',
    '22222222-2222-4222-8222-222222222222',
}
assert ipv6[:4] == ('tcp', '2001:db8::10', 443, 'ipv6')
assert len(ipv6[4]) == 1
PY

# DNS transport page consumes only the closed backend schema and keeps
# global/physical system policy separate from provider/private routing.
assert_grep_fixed "def _dns_mode_state" "$TMPDIR/noid-network" \
    "DNS page consumes one versioned machine state"
assert_grep_fixed "lines[0] != 'NOID-DNS-MODE-V2'" "$TMPDIR/noid-network" \
    "DNS page rejects stale or open-ended status schemas"
assert_grep_fixed "'selection', 'configured', 'runtime_global'," \
    "$TMPDIR/noid-network" \
    "DNS page requires selected, merged and runtime global truth"
assert_grep_fixed "'physical_configured', 'physical_runtime', 'scope', 'link_mode'" \
    "$TMPDIR/noid-network" \
    "DNS page requires physical-profile, physical-runtime and routing truth"
assert_grep_fixed "state['selection'] not in {" "$TMPDIR/noid-network" \
    "DNS page validates the selector-owned mode enum"
assert_grep_fixed "state['scope'] not in {" \
    "$TMPDIR/noid-network" "DNS page validates the routing-scope enum"
assert_grep_fixed "'Strict (default) — authenticated, fail closed'" \
    "$TMPDIR/noid-network" \
    "DNS page exposes the strict authenticated image default"
assert_grep_fixed "'Opportunistic — pre-VPN / captive portal'" \
    "$TMPDIR/noid-network" \
    "DNS page names the bootstrap/captive-portal compatibility choice"
assert_grep_fixed "'Off — plaintext DNS'" "$TMPDIR/noid-network" \
    "DNS page names the privacy loss of disabling DoT"
assert_grep_fixed "VPN/private ~. link takes precedence" "$TMPDIR/noid-network" \
    "DNS page identifies provider routing precedence"
assert_grep_fixed "'Managed physical-profile transport'" "$TMPDIR/noid-network" \
    "DNS page displays physical profile and runtime state separately"
assert_grep_fixed "DoT=no; effective per-link setting" "$TMPDIR/noid-network" \
    "VPN-internal DNS is labeled as effective link state without false ownership"
assert_grep_fixed "unset transport independently inherits NoID Privacy’s generic" \
    "$TMPDIR/noid-network" \
    "DNS page attributes an unset tunnel transport to NoID Privacy"
assert_grep_fixed "best-effort opportunistic default, which can fall back to DNS/53" \
    "$TMPDIR/noid-network" \
    "DNS page states the exact unset-tunnel downgrade boundary"
assert_grep_fixed "until Strict is selected again. It does not control tunnel" \
    "$TMPDIR/noid-network" \
    "DNS page warns that physical compatibility persists but does not control the tunnel"
assert_not_grep 'provider/tunnel link policy\|per-link DNS remain provider-owned' \
    "$TMPDIR/noid-network" \
    "DNS page does not misattribute inherited tunnel transport"
assert_grep_fixed 'otherwise a managed physical ~.' "$TMPDIR/noid-network" \
    "status page does not mislabel a routed physical DNS scope as global fallback"
assert_not_grep "physical NICs fall back.*global config" "$TMPDIR/noid-network" \
    "status page carries no stale physical-to-global routing claim"
assert_grep_fixed "self.dns_mode.set_sensitive(False)" "$TMPDIR/noid-network" \
    "failed DNS status disables mutation without a hidden second status read"
assert_grep_fixed "self.dns_reset_row.set_sensitive(False)" \
    "$TMPDIR/noid-network" \
    "failed DNS status also disables reset until an explicit refresh succeeds"
assert_grep_fixed "[DNS_MODE_CLI, mode]" "$TMPDIR/noid-network" \
    "DNS mutations invoke the exact pinned backend with a closed mode"
assert_grep_fixed "mode not in {'opportunistic', 'strict', 'off', 'reset'}" \
    "$TMPDIR/noid-network" "DNS action dispatch is closed"
assert_grep_fixed "self._apply_dns_mode('reset')" "$TMPDIR/noid-network" \
    "DNS page exposes the selector-only image-policy reset"
assert_grep_fixed "Use strict authenticated DNS-over-TLS?" "$TMPDIR/noid-network" \
    "strict DNS availability trade-off requires explicit confirmation"
assert_grep_fixed "Enable pre-VPN DNS compatibility?" "$TMPDIR/noid-network" \
    "opportunistic DNS/53 downgrade requires explicit confirmation"
assert_grep_fixed "prevents resolving the VPN endpoint" "$TMPDIR/noid-network" \
    "compatibility dialog names the physical DNS bootstrap failure"
assert_grep_fixed "It does not control tunnel" "$TMPDIR/noid-network" \
    "compatibility dialog separates physical bootstrap and tunnel DNS"
assert_grep_fixed "Disable NoID Privacy DNS-over-TLS?" "$TMPDIR/noid-network" \
    "plaintext DNS privacy loss requires explicit confirmation"
assert_grep_fixed 'VPN-compatible opportunistic DoT selected globally and on physical links' \
    "$TMPDIR/noid-network" \
    "DNS success toast covers both managed DNS policy layers"
assert_grep_fixed 'Strict authenticated DoT selected globally and on physical links' \
    "$TMPDIR/noid-network" \
    "strict DNS success toast covers global and physical policy"
assert_not_grep 'global DoT active\|Global DoT active' "$TMPDIR/noid-network" \
    "per-link DNS precedence cannot coexist with a false global-active toast"

assert_cmd_success "all privileged launches pass through one serializer" \
    python3 - "$TMPDIR/noid-network" <<'PY'
import ast, sys
tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
parents = {}
for node in ast.walk(tree):
    for child in ast.iter_child_nodes(node):
        parents[child] = node
calls = [n for n in ast.walk(tree)
         if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
         and n.func.id == '_privileged_async']
assert len(calls) == 1
node = calls[0]
while node in parents and not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
    node = parents[node]
assert isinstance(node, ast.FunctionDef) and node.name == '_start_privileged'
PY

assert_cmd_success "every LAN refresh event synchronizes list and controls" \
    python3 - "$TMPDIR/noid-network" <<'PY'
import ast, sys

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
window = next(node for node in tree.body
              if isinstance(node, ast.ClassDef) and node.name == 'NetworkWindow')
methods = {node.name: node for node in window.body
           if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
refresh = methods['_refresh_lan_page']
refresh_calls = [node.func.attr for node in ast.walk(refresh)
                 if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute)
                 and isinstance(node.func.value, ast.Name)
                 and node.func.value.id == 'self']
assert refresh_calls == ['_refresh_lan_exceptions', '_sync_lan_controls']

direct_exception_callers = set()
page_refresh_callers = set()
for name, method in methods.items():
    for node in ast.walk(method):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == 'self'):
            if node.func.attr == '_refresh_lan_exceptions':
                direct_exception_callers.add(name)
            elif node.func.attr == '_refresh_lan_page':
                page_refresh_callers.add(name)
assert direct_exception_callers == {'_refresh_lan_page'}
assert {'_build_lan_page', '_on_page_changed', '_wait_then_refresh_lan'} \
       <= page_refresh_callers
PY

# Privilege routing + lifecycle/rc classification. Direct backend invocation is
# load-bearing: `pkexec bash -c` bypassed M08's narrow program allowlist.
assert_grep_fixed "_privileged_async"  "$TMPDIR/noid-network"
assert_not_grep "_pkexec_shell_async" "$TMPDIR/noid-network" \
    "no privileged action hides its backend behind bash"
assert_not_grep "'pkexec', 'bash'" "$TMPDIR/noid-network" \
    "polkit always sees the exact pinned backend program"
assert_grep_fixed "[WAN_TOGGLE_CLI, 'off', '--yes']" "$TMPDIR/noid-network"
assert_grep_fixed "[WAN_STRICT_CLI, 'reset', '--yes']" "$TMPDIR/noid-network"
assert_grep_fixed "[WAN_STRICT_CLI, 'arm-empty', '--yes']" "$TMPDIR/noid-network"
assert_grep_fixed "'Restore onboarding/bootstrap mode'" "$TMPDIR/noid-network" \
    "full-grace reset is not mislabeled as narrow endpoint cleanup"
# The row must name what the user ends up with, not the internal state name.
# "Block ordinary physical WAN" read as a hardening switch; the actual effect
# is that this machine has no ordinary network access until a VPN comes up,
# and that belongs in the line the user reads before tapping it.
assert_grep_fixed "'Block internet until a VPN connects'" "$TMPDIR/noid-network" \
    "Network exposes the confirmed no-VPN STRICT_EMPTY choice by its outcome"
assert_not_grep "'Block ordinary physical WAN'" "$TMPDIR/noid-network" \
    "the withdrawn state-named label is gone from the row and the dialog"
assert_grep_fixed "'No ordinary network access from this machine — enters STRICT_EMPTY'" \
    "$TMPDIR/noid-network" \
    "the subtitle keeps STRICT_EMPTY discoverable beside the plain consequence"
assert_grep_fixed \
    "'systemd-resolved bootstrap exception remains until a supported '" \
    "$TMPDIR/noid-network" \
    "Network's STRICT_EMPTY confirmation states the exact resolver exception"
assert_grep_fixed "[LAN_ALLOW_CLI, 'on', '--yes']" "$TMPDIR/noid-network"
assert_grep_fixed "[DNS_MODE_CLI, mode]" "$TMPDIR/noid-network"
assert_grep_fixed "def _finish_privileged_action" "$TMPDIR/noid-network"
assert_grep_fixed "os.set_blocking(proc.stderr.fileno(), False)" \
    "$TMPDIR/noid-network" \
    "privileged stderr is nonblocking before GUI polling begins"
assert_grep_fixed "def _drain_privileged_stderr" "$TMPDIR/noid-network" \
    "every GUI poll drains backend diagnostics without pipe deadlock"
assert_grep_fixed "PRIVILEGED_STDERR_TAIL_LIMIT = 4096" \
    "$TMPDIR/noid-network" \
    "retained privileged diagnostics have a fixed memory bound"
assert_grep_fixed "os.killpg(proc.pid, signal.SIGTERM)" "$TMPDIR/noid-network" \
    "timed-out privileged process group is terminated"
assert_grep_fixed "os.killpg(proc.pid, signal.SIGKILL)" "$TMPDIR/noid-network" \
    "unresponsive privileged process group is killed"
assert_grep_fixed "rc = proc.wait()" "$TMPDIR/noid-network" \
    "finished privileged actions are explicitly reaped"
assert_grep_fixed "return ('orphaned', None)" "$TMPDIR/noid-network" \
    "an unsignalable root backend cannot block the GTK thread"
assert_eq 6 "$(grep -c "^        if .* == 'orphaned':" "$TMPDIR/noid-network")" \
    "every privileged callback keeps polling an orphaned root backend"
assert_grep_fixed "Cancelled — no change made" "$TMPDIR/noid-network" "pkexec-cancel toast"
assert_grep_fixed "privileged action failed (exit" "$TMPDIR/noid-network" \
    "backend failures are not mislabeled as cancellation"
assert_grep_fixed "privileged action could not be started" "$TMPDIR/noid-network" \
    "spawn failure is visible in the GUI"
assert_grep_fixed "username == 'liveuser' and live_boot" "$TMPDIR/noid-network" \
    "passwordless privilege route is restricted to the exact Live account and boot"
assert_grep_fixed "Path('/run/initramfs/livedev').exists()" "$TMPDIR/noid-network" \
    "passwordless privilege route requires the initramfs Live-media marker"
# See tests/05: exit status alone is "permitted by policy", not "passwordless".
assert_grep_fixed "'-n', '-l', '-l', '--'" \
    "$TMPDIR/noid-network" \
    "Network asks for the matching sudoers entry, not just permission"
assert_grep_fixed "'!authenticate' in listing" \
    "$TMPDIR/noid-network" \
    "Network requires an explicit passwordless tag before choosing sudo"
assert_grep_fixed "LC_ALL='C.UTF-8'" \
    "$TMPDIR/noid-network" \
    "Network reads the translated sudo listing under a pinned locale"
assert_grep_fixed "return [SUDO_CLI, '-n', '--'] + argv" \
    "$TMPDIR/noid-network" \
    "authorized sudo route is noninteractive and preserves argv boundaries"
assert_grep_fixed "return [PKEXEC_CLI] + argv" "$TMPDIR/noid-network" \
    "installed sessions without noninteractive sudo retain narrow polkit"

assert_cmd_success "privilege argv selection is closed over Live, sudo, and polkit paths" \
    python3 - "$TMPDIR/noid-network" <<'PY'
import ast
import sys

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
wanted = {'_noninteractive_sudo_authorizes', '_privileged_argv'}
functions = [node for node in tree.body
             if isinstance(node, ast.FunctionDef) and node.name in wanted]
assert {node.name for node in functions} == wanted
module = ast.Module(body=functions, type_ignores=[])
ast.fix_missing_locations(module)

class FakeSubprocess:
    DEVNULL = object()
    PIPE = object()

    class TimeoutExpired(Exception):
        pass

    returncode = 1
    stdout = ''
    calls = []

    @classmethod
    def run(cls, argv, **kwargs):
        cls.calls.append((argv, kwargs))
        return type('Result', (), {'returncode': cls.returncode,
                                   'stdout': cls.stdout})()

namespace = {
    '_is_live_session': lambda: False,
    'subprocess': FakeSubprocess,
    'os': type('FakeOS', (), {'environ': {}})(),
    'sys': sys,
    'SUDO_CLI': '/usr/bin/sudo',
    'PKEXEC_CLI': '/usr/bin/pkexec',
}
exec(compile(module, '<noid-network-privilege>', 'exec'), namespace)
backend = ['/usr/local/bin/noid-lan-allow', '--list']

# Policy refuses the command outright: polkit route.
assert namespace['_privileged_argv'](backend) == ['/usr/bin/pkexec'] + backend
assert FakeSubprocess.calls[-1][0] == \
       ['/usr/bin/sudo', '-n', '-l', '-l', '--'] + backend
assert FakeSubprocess.calls[-1][1]['timeout'] == 3
assert FakeSubprocess.calls[-1][1]['check'] is False
assert FakeSubprocess.calls[-1][1]['env']['LC_ALL'] == 'C.UTF-8'
assert "listing.count('Matched:') == 1" in open(
    sys.argv[1], encoding='utf-8').read()

# The regression this guards: sudo answers "permitted by the security policy"
# for a PASSWD-tagged %wheel rule, so exit 0 alone must NOT select sudo --
# `sudo -n` would then fail with "a password is required".
FakeSubprocess.returncode = 0
FakeSubprocess.stdout = (
    'Sudoers entry: /etc/sudoers.d/10-wheel\n'
    '    RunAsUsers: ALL\n'
    '    Options: setenv\n'
    '    Matched: /usr/local/bin/noid-lan-allow --list\n')
assert namespace['_privileged_argv'](backend) == ['/usr/bin/pkexec'] + backend

# Only an explicitly passwordless matching entry selects sudo.
FakeSubprocess.stdout = (
    'Sudoers entry: /etc/sudoers.d/90-owner\n'
    '    RunAsUsers: ALL\n'
    '    Options: !authenticate\n'
    '    Matched: /usr/local/bin/noid-lan-allow --list\n')
assert namespace['_privileged_argv'](backend) == \
       ['/usr/bin/sudo', '-n', '--'] + backend

FakeSubprocess.stdout = (
    'Sudoers entry: /etc/sudoers.d/90-owner\n'
    '    Options: !authenticate\n'
    '    Matched: /usr/local/bin/noid-lan-allow --list\n'
    'Sudoers entry: /etc/sudoers.d/10-wheel\n'
    '    Options: setenv\n'
    '    Matched: /usr/local/bin/noid-lan-allow --list\n')
assert namespace['_privileged_argv'](backend) == ['/usr/bin/pkexec'] + backend

call_count = len(FakeSubprocess.calls)
namespace['_is_live_session'] = lambda: True
assert namespace['_privileged_argv'](backend) == \
       ['/usr/bin/sudo', '-n', '--'] + backend
assert len(FakeSubprocess.calls) == call_count
assert backend == ['/usr/local/bin/noid-lan-allow', '--list']
PY

assert_cmd_success "Live privilege detection requires account, kernel token, and marker" \
    python3 - "$TMPDIR/noid-network" <<'PY'
import ast
import sys
from types import SimpleNamespace

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
fn = next(node for node in tree.body
          if isinstance(node, ast.FunctionDef)
          and node.name == '_is_live_session')
module = ast.Module(body=[fn], type_ignores=[])
ast.fix_missing_locations(module)

state = {'user': 'liveuser', 'cmdline': 'quiet rd.live.image', 'marker': True}
class FakePwd:
    @staticmethod
    def getpwuid(_uid):
        return SimpleNamespace(pw_name=state['user'])
class FakePath:
    def __init__(self, path): self.path = path
    def read_text(self, **_kwargs): return state['cmdline']
    def exists(self): return state['marker']
namespace = {
    'pwd': FakePwd,
    'os': SimpleNamespace(getuid=lambda: 1000),
    'Path': FakePath,
    'sys': sys,
}
exec(compile(module, '<noid-network-live-detect>', 'exec'), namespace)
detect = namespace['_is_live_session']
assert detect() is True
state['user'] = 'alice'
assert detect() is False
state['user'] = 'liveuser'
state['cmdline'] = 'quiet rd.live.imagefoo'
assert detect() is False
state['cmdline'] = 'quiet rd.live.image=1'
assert detect() is True
state['marker'] = False
assert detect() is False
PY

# Execute the pure process-lifecycle helper without importing GTK. AST-select
# only the constants/functions under test, then drive every outcome with a
# fake Popen object. This catches rc-classification and orphaned-timeout
# regressions that source greps cannot.
assert_cmd_success "privileged action lifecycle handles every terminal state" \
    python3 - "$TMPDIR/noid-network" <<'PY'
import ast
import os
import re
import signal
import subprocess
import sys

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
wanted = {'_drain_privileged_stderr', '_finish_privileged_action',
          '_privileged_failure_text', '_privileged_stderr_tail'}
nodes = []
for node in tree.body:
    if isinstance(node, ast.Assign):
        if any(isinstance(t, ast.Name) and t.id in {
                'ACTION_POLL_LIMIT', 'ACTION_TERM_GRACE_POLLS',
                'ACTION_KILL_GRACE_POLLS',
                'PRIVILEGED_STDERR_TAIL_LIMIT'}
               for t in node.targets):
            nodes.append(node)
    elif isinstance(node, ast.FunctionDef) and node.name in wanted:
        nodes.append(node)
module = ast.Module(body=nodes, type_ignores=[])
ast.fix_missing_locations(module)
ns = {
    'os': os, 're': re, 'signal': signal,
    'subprocess': subprocess, 'sys': sys,
}
exec(compile(module, '<noid-network-lifecycle>', 'exec'), ns)
finish = ns['_finish_privileged_action']
message = ns['_privileged_failure_text']
stderr_tail = ns['_privileged_stderr_tail']
drain = ns['_drain_privileged_stderr']

class FakeProc:
    def __init__(self, rc, waits=None):
        self.returncode = rc
        self.pid = 424242
        self.waits = list(waits or [])
        self.wait_calls = []
        self.stderr = None
    def poll(self):
        return self.returncode
    def wait(self, timeout=None):
        self.wait_calls.append(timeout)
        if self.waits:
            item = self.waits.pop(0)
            if isinstance(item, BaseException):
                raise item
            self.returncode = item
        return self.returncode

assert finish(None, [0]) == ('spawn-error', None)
assert 'could not be started' in message('spawn-error', None)

for rc, expected in ((0, 'success'), (126, 'cancelled'), (7, 'failed')):
    proc = FakeProc(rc)
    state, got_rc = finish(proc, [0])
    assert (state, got_rc) == (expected, rc)
    assert proc.wait_calls == [None]
assert message('cancelled', 126).startswith('Cancelled')
assert 'exit 7' in message('failed', 7)

pending = FakeProc(None)
assert finish(pending, [0]) == ('pending', None)
assert pending.wait_calls == []

kills = []
real_killpg = os.killpg
os.killpg = lambda pid, sig: kills.append((pid, sig))
try:
    timeout_proc = FakeProc(None)
    timeout_attempts = [119]
    assert finish(timeout_proc, timeout_attempts) == ('pending', None)
    for _ in range(3):
        assert finish(timeout_proc, timeout_attempts) == ('pending', None)
    assert finish(timeout_proc, timeout_attempts) == ('pending', None)
    timeout_proc.returncode = -signal.SIGKILL
    state, rc = finish(timeout_proc, timeout_attempts)
finally:
    os.killpg = real_killpg
assert (state, rc) == ('timeout', -signal.SIGKILL)
assert kills == [
    (timeout_proc.pid, signal.SIGTERM),
    (timeout_proc.pid, signal.SIGKILL),
]
assert timeout_proc.wait_calls == [None]
assert 'timed out' in message(state, rc)

# The installed pkexec route can become root before timeout. An unprivileged
# GUI then receives EPERM for both signals; eight bounded GLib polls must end
# in an explicit state without ever calling wait() on the live child.
permission_proc = FakeProc(None)
permission_attempts = [119]
signal_attempts = []
def deny_signal(pid, sig):
    signal_attempts.append((pid, sig))
    raise PermissionError('root-owned process group')
os.killpg = deny_signal
try:
    for _ in range(8):
        assert finish(permission_proc, permission_attempts) == ('pending', None)
    state, rc = finish(permission_proc, permission_attempts)
finally:
    os.killpg = real_killpg
assert (state, rc) == ('orphaned', None)
assert signal_attempts == [
    (permission_proc.pid, signal.SIGTERM),
    (permission_proc.pid, signal.SIGKILL),
]
assert permission_proc.wait_calls == []
assert 'could not be stopped' in message(state, rc)
assert finish(permission_proc, permission_attempts) == ('pending', None)
permission_proc.returncode = 0
assert finish(permission_proc, permission_attempts) == ('timeout', 0)
assert permission_proc.wait_calls == [None]

# stderr surfacing: no retained stderr yields '', a bounded tail yields one
# sanitized final line, and the failure text carries the detail verbatim.
assert stderr_tail(FakeProc(1)) == ''
detailed = FakeProc(1)
detailed._noid_stderr_tail = (
    b'noise\n\x1b[31mper-IP exceptions require the verified '
    b'default BLOCKED mode\x1b[0m\n')
assert stderr_tail(detailed) == (
    'per-IP exceptions require the verified default BLOCKED mode')
assert message('failed', 1, 'why it failed') == (
    'ERROR — privileged action failed (exit 1): why it failed')
assert message('failed', 1) == 'ERROR — privileged action failed (exit 1)'

# The real nonblocking drainer never retains more than the advertised bound
# and closes the descriptor after the terminal read.
read_fd, write_fd = os.pipe()
os.set_blocking(read_fd, False)
stream = os.fdopen(read_fd, 'rb', buffering=0)
drained = FakeProc(None)
drained.stderr = stream
drained._noid_stderr_tail = b''
os.write(write_fd, b'A' * 5000)
drain(drained)
os.close(write_fd)
drain(drained, final=True)
assert len(drained._noid_stderr_tail) == 4096
assert stream.closed
PY

# Exercise the launch-time failure boundary independently of GTK. If making
# stderr nonblocking fails, both reap attempts remain bounded before the GUI
# receives a spawn error.
assert_cmd_success "privileged launch setup failure remains bounded" \
    python3 - "$TMPDIR/noid-network" <<'PY'
import ast
import os
import signal
import subprocess
import sys

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
node = next(
    item for item in tree.body
    if isinstance(item, ast.FunctionDef) and item.name == '_privileged_async')
module = ast.Module(body=[node], type_ignores=[])
ast.fix_missing_locations(module)

class FakeStream:
    def __init__(self):
        self.closed = False
    def fileno(self):
        return 73
    def close(self):
        self.closed = True

class FakeProc:
    def __init__(self, waits=None):
        self.pid = 424242
        self.stderr = FakeStream()
        self.waits = list(waits or [])
        self.wait_calls = []
    def wait(self, timeout=None):
        self.wait_calls.append(timeout)
        if self.waits:
            item = self.waits.pop(0)
            if isinstance(item, BaseException):
                raise item
            return item
        return 0

created = []
failed_proc = FakeProc([
    subprocess.TimeoutExpired('pkexec', 2),
    subprocess.TimeoutExpired('pkexec', 2),
])

def fake_popen(argv, **kwargs):
    created.append((argv, kwargs))
    return failed_proc

kills = []
real_popen = subprocess.Popen
real_set_blocking = os.set_blocking
real_killpg = os.killpg
subprocess.Popen = fake_popen
os.set_blocking = lambda _fd, _enabled: (_ for _ in ()).throw(
    OSError('fixture failure'))
os.killpg = lambda pid, sig: kills.append((pid, sig))
try:
    namespace = {
        'os': os,
        'signal': signal,
        'subprocess': subprocess,
        'sys': sys,
        '_privileged_argv': lambda argv: ['/usr/bin/pkexec'] + argv,
    }
    exec(compile(module, '<noid-network-launch-failure>', 'exec'), namespace)
    launch = namespace['_privileged_async']
    assert launch(['/usr/local/sbin/noid-toggle-wan-strict', 'on']) is None
finally:
    subprocess.Popen = real_popen
    os.set_blocking = real_set_blocking
    os.killpg = real_killpg

assert created == [(
    ['/usr/bin/pkexec', '/usr/local/sbin/noid-toggle-wan-strict', 'on'],
    {
        'stdin': subprocess.DEVNULL,
        'stdout': subprocess.DEVNULL,
        'stderr': subprocess.PIPE,
        'start_new_session': True,
    },
)]
assert kills == [
    (failed_proc.pid, signal.SIGTERM),
    (failed_proc.pid, signal.SIGKILL),
]
assert failed_proc.wait_calls == [2, 2]
assert failed_proc.stderr.closed

# The success path keeps the stream open for periodic draining and initializes
# the bounded byte tail before returning the handle.
healthy_proc = FakeProc()
subprocess.Popen = lambda _argv, **_kwargs: healthy_proc
os.set_blocking = lambda fd, enabled: (
    None if (fd, enabled) == (73, False) else (_ for _ in ()).throw(
        AssertionError((fd, enabled))))
try:
    returned = launch(['/usr/local/sbin/noid-toggle-wan-strict', 'off'])
finally:
    subprocess.Popen = real_popen
    os.set_blocking = real_set_blocking
assert returned is healthy_proc
assert returned._noid_stderr_tail == b''
assert not returned.stderr.closed
PY

# LAN per-IP duration map (Permanent + 3 presets + exact edited CLI values)
assert_grep_fixed "Permanent" "$TMPDIR/noid-network"
assert_grep_fixed 'LAN_DURATION_PRESETS = (' "$TMPDIR/noid-network" \
    "duration presets have one typed source of truth"
assert_grep_fixed "choices.append((minutes, f'{minutes} minutes (existing)'))" \
    "$TMPDIR/noid-network" \
    "non-preset CLI duration is represented without rounding"
assert_grep_fixed 'self._set_lan_duration_options(kind, duration)' \
    "$TMPDIR/noid-network" \
    "editing rebuilds the duration model from the exact backend value"
assert_not_grep "2 if kind == 'temporary' else 0" "$TMPDIR/noid-network" \
    "unknown temporary durations cannot silently become 60 minutes"
assert_grep_fixed "['Outbound only', 'Inbound only', 'Both directions']" \
    "$TMPDIR/noid-network" "GUI exposes exactly the three direction choices"
assert_grep_fixed "inbound_capable = self.lan_direction.get_selected() in (1, 2)" \
    "$TMPDIR/noid-network" \
    "protocol and port controls are visible only for inbound-capable directions"
assert_grep_fixed "[LAN_ALLOW_CLI, '--list-machine']" "$TMPDIR/noid-network" \
    "GUI consumes only the backend's closed machine schema"
assert_grep_fixed "lines[0] != 'NOID-LAN-EXCEPTIONS-V2'" "$TMPDIR/noid-network" \
    "GUI rejects stale or open-ended exception-list schemas"
assert_grep_fixed "len(parts) != 8" "$TMPDIR/noid-network" \
    "GUI requires every direction and selector field"
assert_grep_fixed "direction in ('inbound', 'both')" "$TMPDIR/noid-network" \
    "inbound selector parsing applies to inbound and both"
assert_grep_fixed "1 <= start <= end <= 65535" "$TMPDIR/noid-network" \
    "rendered inbound selectors enforce exact port boundaries"
assert_grep_fixed "'document-edit-symbolic'" "$TMPDIR/noid-network" \
    "each committed exception can be loaded for an atomic edit"
assert_grep_fixed 'narrowing-first, fail-closed replacement' "$TMPDIR/noid-network" \
    "edit UX names the backend replacement failure semantics"
assert_grep_fixed "if family != 'ipv4':" "$TMPDIR/noid-network" \
    "new LAN grants are locally restricted to the backend's IPv4 contract"
assert_grep_fixed 'IPv6 LAN exceptions are not supported by the current XDP/NDP boundary.' \
    "$TMPDIR/noid-network" "IPv6 rejection names the missing enforcement contract"
assert_grep_fixed 'def _run_cmd_checked' "$TMPDIR/noid-network" \
    "LAN list failures cannot masquerade as an empty list"
assert_grep_fixed 'The backend list command failed; no empty-state claim is made' \
    "$TMPDIR/noid-network" "LAN list failure is visible and non-optimistic"
assert_grep_fixed 'The closed list schema failed; no entries were rendered.' \
    "$TMPDIR/noid-network" \
    "malformed LAN output makes no partial enforcement claim"
assert_cmd_success "malformed LAN list output clears every parsed record" \
    python3 - "$TMPDIR/noid-network" <<'PY'
import ast
import sys

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
window = next(node for node in tree.body
              if isinstance(node, ast.ClassDef)
              and node.name == 'NetworkWindow')
method = next(node for node in window.body
              if isinstance(node, ast.FunctionDef)
              and node.name == '_refresh_lan_exceptions')
guard = next(node for node in ast.walk(method)
             if isinstance(node, ast.If)
             and isinstance(node.test, ast.Name)
             and node.test.id == 'malformed')
assert any(
    isinstance(node, ast.Assign)
    and any(isinstance(target, ast.Name) and target.id == 'exceptions'
            for target in node.targets)
    and isinstance(node.value, ast.List) and not node.value.elts
    for node in guard.body
)
PY
assert_grep_fixed 'No named NetworkManager killswitch profile detected' \
    "$TMPDIR/noid-network" "killswitch row states only its actual name heuristic"
assert_grep_fixed 'This is not a universal killswitch verdict' \
    "$TMPDIR/noid-network" "provider-specific killswitch limits are explicit"
assert_grep_fixed 'ACTIVE — locally classified destinations blocked;' \
    "$TMPDIR/noid-network" \
    "LAN status does not understate the enforced destination classes as RFC1918-only"

assert_cmd_success "LAN form emits only closed direction/selector CLI combinations" \
    python3 - "$TMPDIR/noid-network" <<'PY'
import ast
import ipaddress
import re
import sys

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
nodes = []
for node in tree.body:
    if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name)
            and target.id in ('LAN_ALLOW_CLI', 'LAN_DURATION_PRESETS')
            for target in node.targets):
        nodes.append(node)
    elif isinstance(node, ast.FunctionDef) and node.name in (
            '_validate_ip', '_lan_duration_options'):
        nodes.append(node)
    elif isinstance(node, ast.ClassDef) and node.name == 'NetworkWindow':
        method = next(item for item in node.body
                      if isinstance(item, ast.FunctionDef)
                      and item.name == '_lan_add')
        nodes.append(ast.ClassDef(
            name='NetworkWindow', bases=[], keywords=[],
            body=[method], decorator_list=[]))
module = ast.Module(body=nodes, type_ignores=[])
ast.fix_missing_locations(module)
ns = {'ipaddress': ipaddress, 're': re}
exec(compile(module, '<noid-network-lan-form>', 'exec'), ns)

class Text:
    def __init__(self, value): self.value = value
    def get_text(self): return self.value

class Select:
    def __init__(self, value): self.value = value
    def get_selected(self): return self.value

def submit(ip='198.19.7.20', direction=0, protocol=0, ports='', duration=0,
           duration_values=(None, 15, 60, 240)):
    window = ns['NetworkWindow']()
    window.lan_ip_entry = Text(ip)
    window.lan_direction = Select(direction)
    window.lan_protocol = Select(protocol)
    window.lan_ports_entry = Text(ports)
    window.lan_duration = Select(duration)
    window._lan_duration_minutes = list(duration_values)
    window.toasts = []
    window.calls = []
    window._toast = lambda message, **kwargs: window.toasts.append(message)
    def start(argv):
        window.calls.append(argv)
        return False, None
    window._start_privileged = start
    window._lan_add()
    return window.calls, window.toasts

cli = ns['LAN_ALLOW_CLI']
assert submit()[0] == [[
    cli, '--add', '198.19.7.20', '--direction', 'outbound']]
assert submit(direction=1, protocol=0, ports='443')[0] == [[
    cli, '--add', '198.19.7.20', '--direction', 'inbound',
    '--protocol', 'tcp', '--ports', '443']]
assert submit(direction=2, protocol=1, ports='5300-5301', duration=2)[0] == [[
    cli, '--add', '198.19.7.20', '--direction', 'both',
    '--protocol', 'udp', '--ports', '5300-5301', '--temp', '60']]

# Every backend-supported audit edge value round-trips without widening or
# shortening. Presets retain their normal row; other values gain one exact row.
duration_options = ns['_lan_duration_options']
for expected_minutes in (1, 5, 15, 30, 60, 240, 1440):
    choices, selected = duration_options(
        'temporary', expected_minutes * 60)
    assert choices[selected][0] == expected_minutes
    values = [minutes for minutes, _label in choices]
    calls, messages = submit(duration=selected, duration_values=values)
    assert messages == []
    assert calls == [[
        cli, '--add', '198.19.7.20', '--direction', 'outbound',
        '--temp', str(expected_minutes)]], expected_minutes

for bad_kind, bad_duration in (
        ('permanent', 60), ('temporary', 0), ('temporary', 61),
        ('temporary', 86460), ('unknown', 60)):
    try:
        duration_options(bad_kind, bad_duration)
    except ValueError:
        pass
    else:
        raise AssertionError((bad_kind, bad_duration))

calls, messages = submit(duration=999)
assert calls == [] and messages == ['Invalid duration selection']

for bad_ports in ('', '0', '65536', '2-1', '1-65536', '1-2-3', 'tcp/443'):
    calls, messages = submit(direction=1, ports=bad_ports)
    assert calls == [] and messages, bad_ports
for bad_direction in (3, 999):
    calls, messages = submit(direction=bad_direction)
    assert calls == [] and messages
for bad_protocol in (2, 999):
    calls, messages = submit(direction=1, protocol=bad_protocol, ports='443')
    assert calls == [] and messages
for bad_ip in ('fd00::1', 'not-an-ip'):
    calls, messages = submit(ip=bad_ip)
    assert calls == [] and messages
PY

# Network Status reads (no-sudo path)
assert_grep_fixed "NMCLI_CLI, '--terse', '--escape', 'yes'," \
    "$TMPDIR/noid-network" \
    "NetworkManager rows explicitly request escaped terse output"
assert_grep_fixed "'--fields', 'UUID,NAME,TYPE,DEVICE'" \
    "$TMPDIR/noid-network" \
    "one versioned active-connection snapshot feeds VPN and killswitch rows"
assert_grep_fixed "'connection', 'show', 'uuid', connection['uuid']" \
    "$TMPDIR/noid-network" \
    "killswitch priority lookup is UUID-bound instead of name-ambiguous"
assert_grep_fixed "return 'UNKNOWN — resolvectl query failed'" \
    "$TMPDIR/noid-network" \
    "resolver command failure cannot masquerade as an empty DNS state"
assert_grep_fixed "self.status_vpn_row.set_title('VPN state unavailable')" \
    "$TMPDIR/noid-network" \
    "NetworkManager failure cannot masquerade as no active VPN"
assert_grep_fixed "self.status_ks_row.set_title('Killswitch profile state unavailable')" \
    "$TMPDIR/noid-network" \
    "NetworkManager failure cannot masquerade as no named killswitch"
assert_grep_fixed 'self.status_vpn_row.set_use_markup(False)' \
    "$TMPDIR/noid-network" \
    "NetworkManager VPN names are rendered as literal text"
assert_grep_fixed 'self.status_ks_row.set_use_markup(False)' \
    "$TMPDIR/noid-network" \
    "NetworkManager killswitch names are rendered as literal text"
assert_grep_fixed "'IP unavailable'" "$TMPDIR/noid-network" \
    "VPN row does not render a blank address claim"

assert_cmd_success "NetworkManager parser handles escaping, UUID identity and command failure" \
    python3 - "$TMPDIR/noid-network" <<'PY'
import ast
import ipaddress
import json
from pathlib import Path
import re
import sys
import uuid

tree = ast.parse(Path(sys.argv[1]).read_text(encoding='utf-8'))
wanted = {'_nmcli_fields', '_active_nm_connections', '_device_address'}
nodes = [
    node for node in tree.body
    if isinstance(node, ast.FunctionDef) and node.name in wanted
]
window = next(
    node for node in tree.body
    if isinstance(node, ast.ClassDef) and node.name == 'NetworkWindow')
methods = [
    node for node in window.body
    if isinstance(node, ast.FunctionDef)
    and node.name in {'_get_vpn_state', '_get_killswitch_state'}
]
nodes.append(ast.ClassDef(
    name='NetworkWindow', bases=[], keywords=[], body=methods,
    decorator_list=[]))
module = ast.Module(body=nodes, type_ignores=[])
ast.fix_missing_locations(module)

calls = []
responses = []
def run(argv, timeout=3):
    calls.append((argv, timeout))
    return responses.pop(0)

namespace = {
    'uuid': uuid,
    'json': json,
    'ipaddress': ipaddress,
    're': re,
    'NMCLI_CLI': '/usr/bin/nmcli',
    'IP_CLI': '/usr/bin/ip',
    '_run_cmd_checked': run,
}
exec(compile(module, '<nmcli-fixture>', 'exec'), namespace)
fields = namespace['_nmcli_fields']
assert fields(r'uuid:Office\:VPN:wireguard:wg0', 4) == [
    'uuid', 'Office:VPN', 'wireguard', 'wg0']
assert fields(r'uuid:Office\\VPN:wireguard:wg0', 4) == [
    'uuid', r'Office\VPN', 'wireguard', 'wg0']
assert fields(r'uuid:bad\q:wireguard:wg0', 4) is None
assert fields('uuid:trailing:wireguard:wg0\\', 4) is None
assert fields('too:few:fields', 4) is None

connection_uuid = 'c1a31175-af28-4427-8888-5c9fadd7ec68'
responses.append((
    0,
    f'{connection_uuid}:Office\\:VPN:wireguard:wg0\n'
    '629a87ba-f228-484c-a1d0-b95b066dbfd7:'
    'pvpn-killswitch-perm:dummy:pvpnksintrf1\n',
))
records = namespace['_active_nm_connections']()
assert [item['name'] for item in records] == [
    'Office:VPN', 'pvpn-killswitch-perm']
assert calls[-1][0][:5] == [
    '/usr/bin/nmcli', '--terse', '--escape', 'yes', '--fields']

responses.append((1, ''))
assert namespace['_active_nm_connections']() is None
responses.append((0, f'{connection_uuid}:bad\\q:wireguard:wg0\n'))
assert namespace['_active_nm_connections']() is None
responses.append((0, 'NOT-A-UUID:name:wireguard:wg0\n'))
assert namespace['_active_nm_connections']() is None
responses.append((
    0,
    f'{connection_uuid}:one:wireguard:wg0\n'
    f'{connection_uuid}:two:wireguard:wg1\n',
))
assert namespace['_active_nm_connections']() is None

address_payload = json.dumps([{
    'ifname': 'wg0',
    'addr_info': [
        {'family': 'inet6', 'local': '2001:db8::2', 'scope': 'global'},
        {'family': 'inet', 'local': '10.2.0.2', 'scope': 'global'},
        {'family': 'inet6', 'local': 'fe80::1', 'scope': 'link'},
    ],
}])
responses.append((0, address_payload))
assert namespace['_device_address']('wg0') == '10.2.0.2'
responses.append((0, '{}'))
assert namespace['_device_address']('wg0') == ''
assert namespace['_device_address']('--') == ''

obj = namespace['NetworkWindow']()
namespace['_device_address'] = lambda device: '10.2.0.2'
vpn = obj._get_vpn_state(records)
assert vpn == {
    'name': 'Office:VPN', 'type': 'wireguard',
    'device': 'wg0', 'ip': '10.2.0.2',
}
responses.append((0, '0\n'))
killswitch = obj._get_killswitch_state(records)
assert killswitch == {'name': 'pvpn-killswitch-perm', 'priority': '0'}
assert calls[-1][0][-2:] == [
    'uuid', '629a87ba-f228-484c-a1d0-b95b066dbfd7']
responses.append((1, ''))
assert obj._get_killswitch_state(records)['priority'] == 'unavailable'
assert obj._get_vpn_state(None) is None
assert obj._get_killswitch_state(None) is None
PY

assert_grep_fixed "nmcli" "$TMPDIR/noid-network"
assert_grep_fixed "resolvectl" "$TMPDIR/noid-network"
assert_grep_fixed "stderr=subprocess.PIPE" "$TMPDIR/noid-network" \
    "privileged actions keep their stderr for failure surfacing"
assert_grep_fixed "_privileged_stderr_tail(proc)" "$TMPDIR/noid-network" \
    "failure toasts carry the backend's own refusal reason"
assert_grep_fixed 'Never render otherwise-valid' "$TMPDIR/noid-network" \
    "rejected endpoint state renders no tuple as pinned"
assert_grep_fixed "'\\n'.join(active)" "$TMPDIR/noid-network" \
    "DNS status lists every resolver link, not the first"
assert_grep_fixed "arp_known = arp_state.get('ENABLED') in ('0', '1')" \
    "$TMPDIR/noid-network" \
    "re-learn is available for both active pins and retained disabled identities"
assert_grep_fixed "arp_state.get('ENABLED') == '0'" "$TMPDIR/noid-network" \
    "GUI distinguishes the explicit kernel-pin opt-out"
assert_grep_fixed "if arp_state.get('ERROR')" "$TMPDIR/noid-network" \
    "GUI disables re-learning with an explicit inconsistent-state reason"
assert_grep_fixed "firewall-cmd" "$TMPDIR/noid-network"
assert_grep_fixed "policy_loaded = mode not in {'ERROR', 'UNKNOWN', 'DISABLED'}" \
    "$TMPDIR/noid-network" \
    "WAN reset and arm-empty controls require a loaded nft policy"
assert_grep_fixed "policy_loaded and mode != 'STRICT_EMPTY'" \
    "$TMPDIR/noid-network" \
    "arm-empty is unavailable when disabled or already STRICT_EMPTY"
assert_not_grep "valid and mode != 'STRICT_EMPTY'" "$TMPDIR/noid-network" \
    "DISABLED mode cannot retain the stale arm-empty sensitivity gate"
assert_grep_fixed 'only the documented ' "$TMPDIR/noid-network" \
    "persistent STRICT_EMPTY status names the resolver bootstrap exception"
assert_grep_fixed 'systemd-resolved bootstrap exception remains.' \
    "$TMPDIR/noid-network" \
    "STRICT_EMPTY status does not claim total physical-WAN silence"
assert_grep_fixed 'Direct physical-WAN traffic + ' "$TMPDIR/noid-network" \
    "WAN disable dialog covers wired and wireless physical links"
assert_grep_fixed 'Direct physical-WAN traffic + SO_BINDTODEVICE bypass' \
    "$M06_FILE" \
    "WAN backend disable warning covers wired and wireless physical links"
assert_not_grep 'Direct WLAN traffic' "$KS_FILE" \
    "M36 has no wireless-only description of physical-WAN exposure"
assert_not_grep 'Direct WLAN traffic' "$M06_FILE" \
    "M06 has no wireless-only description of physical-WAN exposure"
assert_grep_fixed 'def _resync_wan_switch(self, proc, attempts):' \
    "$TMPDIR/noid-network" \
    "WAN resync callback has no unused switch argument"
assert_not_grep '_resync_wan_switch, switch, proc' "$TMPDIR/noid-network" \
    "WAN resync call sites do not marshal an unused widget"
assert_grep_fixed 'narrowing-first, fail-closed replacement' \
    "$TMPDIR/noid-network" \
    "LAN edit toast describes the real replacement transaction"
assert_grep_fixed 'the old grant is withdrawn, not restored' \
    "$TMPDIR/noid-network" \
    "LAN edit toast states the failure boundary"
assert_not_grep 'replaces it atomically' "$TMPDIR/noid-network" \
    "LAN edit toast makes no false atomic-replacement promise"

# Three formatted, read-only audit tools. The GUI launches exact argv directly
# through the terminal; it never constructs an executable shell program.
assert_grep_fixed "mode not in {'wan', 'firewall', 'nft', 'mtu'}" "$TMPDIR/noid-network" \
    "GUI audit launcher validates one closed mode"
assert_grep_fixed "self._open_audit('mtu')" "$TMPDIR/noid-network" \
    "GUI exposes the tunnel-MTU audit through the same closed launcher"
assert_grep_fixed "NETWORK_AUDIT_CLI, mode" "$TMPDIR/noid-network" \
    "GUI passes the validated mode as a distinct argv element"
assert_grep_fixed "subprocess.Popen([terminal] + prefix + list(command_argv)" \
    "$TMPDIR/noid-network" "terminal preserves exact command argv boundaries"
assert_not_grep "'bash', '-c'\|bash -c" "$TMPDIR/noid-network" \
    "Network audit launch has no shell program string"
assert_not_grep "head -50\|head -n" "$TMPDIR/noid-network" \
    "Network audits never truncate security output"
for mode in wan firewall nft; do
    assert_grep_fixed "self._open_audit('$mode')" "$TMPDIR/noid-network" \
        "GUI exposes exact $mode audit mode"
done

assert_grep_fixed 'FMT_LIB=/usr/local/lib/noid-privacy/agent-install-format.sh' \
    "$TMPDIR/noid-network-audit" "audit uses shared NoID Privacy terminal formatting"
assert_grep_fixed "0:0:644:1" "$TMPDIR/noid-network-audit" \
    "audit sources the shared formatter only as one exact root-owned file"
assert_grep_fixed "0:0:755" "$TMPDIR/noid-network-audit" \
    "audit validates the formatter's root-owned parent directory"
assert_grep_fixed '/usr/sbin/matchpathcon -V "$FMT_LIB"' \
    "$TMPDIR/noid-network-audit" \
    "audit sources the formatter only with its canonical SELinux label"
assert_grep_fixed 'FORMAT_TRUSTED=0' "$TMPDIR/noid-network-audit" \
    "audit starts with formatter trust closed"
assert_grep_fixed 'AWK=/usr/bin/awk' "$TMPDIR/noid-network-audit" \
    "audit pins its awk parser binary"
assert_grep_fixed '"$JQ" "$AWK"' "$TMPDIR/noid-network-audit" \
    "audit preflights awk with every required parser"
assert_grep_fixed '"$AWK" -F:' "$TMPDIR/noid-network-audit" \
    "firewall field parser uses the preflighted awk path"
assert_not_grep '/usr/bin/awk -F:' "$TMPDIR/noid-network-audit" \
    "audit has no unguarded inline awk binary"
assert_grep_fixed 'using the built-in safe fallback' "$TMPDIR/noid-network-audit" \
    "invalid formatter metadata is visible and fails the audit"
assert_grep_fixed 'case "$MODE" in' "$TMPDIR/noid-network-audit" \
    "audit dispatch is closed"
assert_grep_fixed 'wan|firewall|nft|mtu)' "$TMPDIR/noid-network-audit" \
    "audit accepts exactly the four documented modes"
# --- tunnel-MTU audit: measured constants and read-only contract -------------
# Overhead 60/80 and the 16-byte floor are not style choices: they were
# measured on a 1456-byte outer link where 1396 still stalled and 1392 passed.
assert_grep_fixed 'WG_PAD=16' "$TMPDIR/noid-network-audit" \
    "inner MTU is floored to WireGuard's 16-byte padding boundary"
assert_grep_fixed 'WG_TRAILER=32' "$TMPDIR/noid-network-audit" \
    "WireGuard data-message trailer is pinned at 32 bytes"
assert_grep_fixed '$((40 + 8 + WG_TRAILER))' "$TMPDIR/noid-network-audit" \
    "IPv6 outer encapsulation overhead is derived, not hardcoded"
assert_grep_fixed '$((20 + 8 + WG_TRAILER))' "$TMPDIR/noid-network-audit" \
    "IPv4 outer encapsulation overhead is derived, not hardcoded"
assert_grep_fixed 'usable / WG_PAD * WG_PAD' "$TMPDIR/noid-network-audit" \
    "safe inner MTU is computed from the outer link, never a fixed value"
assert_not_grep_extended '(mtu|MTU)[^\n]*\b1392\b' "$TMPDIR/noid-network-audit" \
    "no host-specific MTU value is baked into the audit"
# A full-tunnel peer is only reachable via WireGuard's own fwmark exemption.
# Without the mark the lookup returns the tunnel and measures the inner link.
assert_grep_fixed 'mtu_tunnel_fwmark' "$TMPDIR/noid-network-audit" \
    "peer routing is resolved with the tunnel's WireGuard fwmark"
assert_grep_fixed 'route get "$host" mark "$mark"' "$TMPDIR/noid-network-audit" \
    "the marked route lookup is the one actually issued"
assert_grep_fixed '[ "$dev" != "$tunnel" ] || return 2' \
    "$TMPDIR/noid-network-audit" \
    "an endpoint routing back through its own tunnel is refused"
# A route-scoped or PMTU-cached mtu is a stricter ceiling than the device.
assert_grep_fixed 'route_mtu" -lt "$outer_mtu' "$TMPDIR/noid-network-audit" \
    "a stricter route MTU wins over the device MTU"
# RFC 8200 section 5.
assert_grep_fixed 'mtu_tunnel_ipv6_state' "$TMPDIR/noid-network-audit" \
    "the complete IPv6 state is evaluated before printing a correction"
assert_grep_fixed 'show "$1" allowed-ips' "$TMPDIR/noid-network-audit" \
    "IPv6 peer intent is detected even before an address is assigned"
assert_grep_fixed "printf 'link'" "$TMPDIR/noid-network-audit" \
    "link-local-only state is distinct from configured IPv6 user traffic"
assert_grep_fixed 'Only IPv6 link-local state is present' \
    "$TMPDIR/noid-network-audit" \
    "a sub-1280 IPv4 correction discloses its link-local IPv6 trade-off"
assert_grep_fixed 'that app reconfigures or recreates the tunnel; report the value' \
    "$TMPDIR/noid-network-audit" \
    "the runtime correction avoids promising one provider lifecycle"
assert_grep_fixed 'worst_safe" -lt 1280' "$TMPDIR/noid-network-audit" \
    "1280 is enforced as the IPv6 link-MTU floor"
assert_grep_fixed 'IPv6 state for $iface is unreadable' \
    "$TMPDIR/noid-network-audit" \
    "unreadable IPv6 state cannot authorize a sub-1280 command"
assert_grep_fixed '[ "${fields[j]}" = lock ]' "$TMPDIR/noid-network-audit" \
    "locked route MTUs retain their numeric ceiling"
# Unevaluable peers must not disappear before they are counted.
assert_not_grep_extended "endpoints=.*GREP\" -v '\\^\\(none\\)" \
    "$TMPDIR/noid-network-audit" \
    "peers without an endpoint are not filtered away before counting"
assert_grep_fixed 'peer endpoints could not be evaluated' \
    "$TMPDIR/noid-network-audit" \
    "unevaluable peers are reported and block a pass"
assert_grep_fixed "printf '%q'" "$TMPDIR/noid-network-audit" \
    "the printed correction quotes the interface name"
assert_grep_fixed 'mtu_nm_profile_state' "$TMPDIR/noid-network-audit" \
    "durable advice consults NetworkManager ownership flags"
assert_grep_fixed '[ "$flags" -eq 0 ]' "$TMPDIR/noid-network-audit" \
    "only a positively persistent NetworkManager profile gets a save command"
assert_grep_fixed 'runtime/provider-managed NetworkManager profile' \
    "$TMPDIR/noid-network-audit" \
    "volatile provider ownership is reported instead of silently persisted"
assert_grep_fixed 'canonical wg-quick configuration' \
    "$TMPDIR/noid-network-audit" \
    "a canonical wg-quick owner receives its native MTU line"
assert_grep_fixed 'Durable owner: not provable' "$TMPDIR/noid-network-audit" \
    "unknown ownership never becomes a guessed persistent profile"
assert_grep_fixed 'Locally fragmentation-free maximum' \
    "$TMPDIR/noid-network-audit" \
    "the verdict is scoped to locally observable state, not the whole path"
assert_not_grep_extended '\$IP[[:space:]]+link[[:space:]]+set' \
    "$TMPDIR/noid-network-audit" \
    "the MTU audit never changes a link; it only prints the correction"
assert_not_grep_extended '"\$NMCLI".*connection[[:space:]]+(modify|mod)' \
    "$TMPDIR/noid-network-audit" \
    "the MTU audit prints but never executes a NetworkManager profile edit"
assert_grep_fixed 'activation/route-change reconciler already attempted' \
    "$TMPDIR/noid-network-audit" \
    "residual MTU failure reports that automatic live reconciliation ran first"
assert_grep_fixed 'journalctl -b -t noid-wireguard-mtu --no-pager' \
    "$TMPDIR/noid-network-audit" \
    "residual MTU failure points to the reconciler journal"
assert_grep_fixed 'never edits' "$TMPDIR/noid-network-audit" \
    "read-only audit still distinguishes a live retry from provider mutation"
assert_grep_fixed '"$SUDO" -n -- "$TRUE"' "$TMPDIR/noid-network-audit" \
    "active NOPASSWD route is tested with one inert exact command"
assert_not_grep '"$SUDO" -n -v' "$TMPDIR/noid-network-audit" \
    "audit does not mistake timestamp validation for a NOPASSWD command check"
assert_grep_fixed 'SELF=/usr/local/bin/noid-network-audit' \
    "$TMPDIR/noid-network-audit" \
    "audit privilege transition is pinned to the installed root-owned helper"
assert_grep_fixed 'validate_self()' "$TMPDIR/noid-network-audit" \
    "audit revalidates its installed privilege-transition target"
assert_grep_fixed '0:0:755:1' "$TMPDIR/noid-network-audit" \
    "audit worker requires exact root ownership, mode and link count"
assert_grep_fixed '"$MATCHPATHCON" -V "$SELF"' \
    "$TMPDIR/noid-network-audit" \
    "audit worker requires its canonical SELinux label"
assert_grep_fixed 'if ! validate_self; then' "$TMPDIR/noid-network-audit" \
    "unsafe worker metadata aborts before sudo"
assert_grep_fixed 'exec "$SUDO" -n -- "$SELF" "$MODE" "$worker_flag"' \
    "$TMPDIR/noid-network-audit" \
    "audit enters one fixed non-interactive root worker after validation"
assert_grep_fixed 'CMD_OUTPUT=$("$@" 2>&1)' "$TMPDIR/noid-network-audit" \
    "fixed audit commands run directly inside the root worker"
assert_grep_fixed 'One fixed root-owned worker replaces one PAM/logind session per command.' \
    "$TMPDIR/noid-network-audit" \
    "audit documents why PAM remains enabled around one privilege transition"
assert_not_grep 'pam_session\|pam_systemd.*disable' "$TMPDIR/noid-network-audit" \
    "audit does not suppress the native PAM session boundary"
assert_not_grep 'sudo .*bash\|eval \|sh -c\|bash -c' "$TMPDIR/noid-network-audit" \
    "audit has no privileged shell or eval surface"
assert_grep_fixed 'noid-wan-strict.service:DISABLED)' "$TMPDIR/noid-network-audit" \
    "WAN audit models the exact user-opt-out service state"
assert_grep_fixed 'noid-wan-strict-status-publish.service:*)' \
    "$TMPDIR/noid-network-audit" \
    "WAN audit requires the boot publisher in enabled/successful oneshot state"
assert_grep_fixed '*:DISABLED)' "$TMPDIR/noid-network-audit" \
    "WAN audit requires watcher and timer silence during user opt-out"
assert_grep_fixed 'expected_enabled=disabled' "$TMPDIR/noid-network-audit" \
    "WAN disabled mode requires a disabled persistent service"
assert_grep_fixed 'expected_sub=exited' "$TMPDIR/noid-network-audit" \
    "WAN active modes require the completed persistent oneshot"
assert_grep_fixed 'expected_sub=waiting' "$TMPDIR/noid-network-audit" \
    "WAN watcher and timer require the active waiting state"
assert_grep_fixed 'parent=${WAN_STATUS_FILE%/*}' \
    "$TMPDIR/noid-network-audit" \
    "WAN audit validates the runtime-state parent before reading"
assert_grep_fixed '"$MATCHPATHCON" -V "$WAN_STATUS_FILE"' \
    "$TMPDIR/noid-network-audit" \
    "WAN audit binds the published runtime label"
for contract in 'LoadState=loaded' 'UnitFileState=$expected_enabled' \
                'ActiveState=$expected_active' 'SubState=$expected_sub' \
                'Result=success'; do
    assert_grep_fixed "$contract" "$TMPDIR/noid-network-audit" \
        "WAN systemd postcondition pins $contract"
done
assert_grep_fixed '--info-policy=block-lan-out' "$TMPDIR/noid-network-audit" \
    "firewall audit reads the NoID Privacy policy"
assert_grep_fixed '--permanent --info-policy=block-lan-out' \
    "$TMPDIR/noid-network-audit" "firewall audit reads saved policy"
assert_grep_fixed '--check-config' "$TMPDIR/noid-network-audit" \
    "firewall audit validates permanent configuration syntax"
assert_grep_fixed '/^[[:space:]]*interfaces:/d' "$TMPDIR/noid-network-audit" \
    "DROP parity separates dynamic interface bindings"
assert_grep_fixed '-j list ruleset' "$TMPDIR/noid-network-audit" \
    "nft audit parses the complete kernel ruleset"
assert_grep_fixed 'expected_topology=' "$TMPDIR/noid-network-audit" \
    "nft audit pins NoID Privacy hooks and priority"
assert_grep_fixed 'expected_counters=' "$TMPDIR/noid-network-audit" \
    "nft audit pins all four pass/block counters"
if python3 - "$M06_FILE" "$TMPDIR/noid-network-audit" <<'PY'
from pathlib import Path
import re
import sys

m06 = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
audit = Path(sys.argv[2]).read_text(encoding="utf-8")

inside = False
chain = None
topology = []
counters = []
for line in m06:
    if line == "cat > /etc/nftables.d/noid-wan-strict.nft <<'NFT_EOF'":
        inside = True
        continue
    if inside and line == "NFT_EOF":
        break
    if not inside:
        continue
    counter = re.match(r"^\s*counter\s+([A-Za-z0-9_.-]+)\s*\{", line)
    if counter:
        counters.append(counter.group(1))
    chain_match = re.match(r"^\s*chain\s+([A-Za-z0-9_.-]+)\s*\{\s*$", line)
    if chain_match:
        chain = chain_match.group(1)
        continue
    if chain is not None:
        base = re.match(
            r"^\s*type\s+(\w+)\s+hook\s+(\w+)\s+priority\s+(-?\d+)"
            r"\s*;\s*policy\s+(\w+)\s*;\s*$",
            line,
        )
        if base:
            topology.append((chain, *base.groups()))
        if line == "    }":
            chain = None

def ansi_c_literal(name):
    match = re.search(rf"^\s*{name}=\$'([^']*)'$", audit, re.MULTILINE)
    if not match:
        raise SystemExit(f"missing M36 {name} literal")
    return bytes(match.group(1), "ascii").decode("unicode_escape")

m06_topology = "\n".join("\t".join(row) for row in sorted(topology))
m06_counters = "\n".join(sorted(counters))
m36_topology = ansi_c_literal("expected_topology")
m36_counters = ansi_c_literal("expected_counters")
if m36_topology != m06_topology or m36_counters != m06_counters:
    print(f"M06 topology={m06_topology!r}", file=sys.stderr)
    print(f"M36 topology={m36_topology!r}", file=sys.stderr)
    print(f"M06 counters={m06_counters!r}", file=sys.stderr)
    print(f"M36 counters={m36_counters!r}", file=sys.stderr)
    raise SystemExit(1)
PY
then
    _pass "M36 nft audit literals exactly match M06's authoritative policy"
else
    _fail "M36 nft audit literals drifted from M06's authoritative policy"
fi
assert_grep_fixed 'list counters table inet firewalld' \
    "$TMPDIR/noid-network-audit" "firewalld counter read is complete"
if python3 - "$TMPDIR/noid-network-audit" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
actual = {
    line.strip()
    for line in path.read_text(encoding="utf-8").splitlines()
    if 'root_capture "$FIREWALL"' in line or 'root_capture "$NFT"' in line
}
expected = {
    'root_capture "$FIREWALL" --state',
    'root_capture "$FIREWALL" --check-config',
    'root_capture "$FIREWALL" --info-policy=block-lan-out',
    'root_capture "$FIREWALL" --permanent --info-policy=block-lan-out',
    'root_capture "$FIREWALL" --info-zone=drop',
    'root_capture "$FIREWALL" --permanent --info-zone=drop',
    'root_capture "$NFT" -n -p -y -j list ruleset',
    'root_capture "$NFT" -n -p -y list table inet noid_wan_strict',
    'root_capture "$NFT" -n -p -y -j list table inet noid_wan_strict',
    'root_capture "$NFT" -n -p -y list counters table inet noid_wan_strict',
    'root_capture "$NFT" -n -p -y list counters table inet firewalld',
}
if actual != expected:
    print(f"missing={sorted(expected - actual)!r}", file=sys.stderr)
    print(f"unexpected={sorted(actual - expected)!r}", file=sys.stderr)
    raise SystemExit(1)
PY
then
    _pass "audit uses only the reviewed read-only firewall and nft argv vectors"
else
    _fail "audit firewall/nft argv allowlist drifted or gained a mutation"
fi
assert_grep_fixed 'Press ENTER to close...' "$TMPDIR/noid-network-audit" \
    "GUI audit owns one explicit terminal hold"

# Gateway ARP-hardening re-learn (router-swap recovery)
assert_grep_fixed "ARP_CLI = '/usr/local/sbin/noid-arp-hardening.sh'" "$TMPDIR/noid-network"
assert_grep_fixed "ARP_STATE = '/var/lib/noid-privacy/arp-hardening.state'" "$TMPDIR/noid-network"
assert_grep_fixed "ARP_DISABLED = '/var/lib/noid-privacy/arp-hardening.disabled'" \
    "$TMPDIR/noid-network" \
    "GUI binds the explicit M04 kernel-pin opt-out marker"
assert_grep_fixed \
    "ARP_TEMPLATE = '/usr/share/noid-privacy/arp-hardening/90-arp-hardening.template'" \
    "$TMPDIR/noid-network" \
    "GUI binds M04's dispatcher source lifecycle"
assert_grep_fixed \
    "ARP_NOWAIT = '/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening'" \
    "$TMPDIR/noid-network" \
    "GUI binds M04's parallel post-activation dispatcher copy"
assert_grep_fixed "_arp_relearn" "$TMPDIR/noid-network" "ARP re-learn handler"
assert_grep_fixed "_refresh_arp" "$TMPDIR/noid-network" "ARP status refresh"
assert_grep_fixed "Re-learn gateway" "$TMPDIR/noid-network" "ARP re-learn row"
assert_grep_fixed 'metadata = os.lstat(ARP_STATE)' "$TMPDIR/noid-network" \
    "ARP state parser rejects symlink/non-regular metadata"
assert_grep_fixed 'metadata.st_uid != 0' "$TMPDIR/noid-network" \
    "ARP state parser requires root ownership"
assert_grep_fixed 'metadata.st_gid != 0 or metadata.st_nlink != 1' \
    "$TMPDIR/noid-network" \
    "ARP state parser binds root group and single-link metadata"
assert_grep_fixed 'stat.S_IMODE(parent.st_mode) != 0o755' \
    "$TMPDIR/noid-network" \
    "ARP state parser binds the root-owned non-writable parent"
assert_grep_fixed 'stat.S_IMODE(dispatcher_parent.st_mode) != 0o755' \
    "$TMPDIR/noid-network" \
    "ARP state parser binds NetworkManager's dispatcher parent"
assert_grep_fixed 'stat.S_IMODE(preup_parent.st_mode) != 0o755' \
    "$TMPDIR/noid-network" \
    "ARP state parser binds NetworkManager's awaited dispatcher parent"
assert_grep_fixed 'stat.S_IMODE(nowait_parent.st_mode) != 0o755' \
    "$TMPDIR/noid-network" \
    "ARP state parser binds NetworkManager's no-wait dispatcher parent"
assert_grep_fixed 'stat.S_IMODE(template.st_mode) != 0o644' \
    "$TMPDIR/noid-network" \
    "ARP state parser requires the root-owned dispatcher template"
assert_grep_fixed "!= 'no-wait.d/90-arp-hardening'" \
    "$TMPDIR/noid-network" \
    "active GUI state requires the exact normal no-wait dispatcher link"
assert_grep_fixed 'stat.S_IMODE(preup.st_mode) != 0o700' \
    "$TMPDIR/noid-network" \
    "active GUI state requires a root-private awaited copy"
assert_grep_fixed 'stat.S_IMODE(nowait.st_mode) != 0o700' \
    "$TMPDIR/noid-network" \
    "active GUI state requires a root-private no-wait copy"
assert_grep_fixed 'marker.st_size != 0' "$TMPDIR/noid-network" \
    "disabled GUI state requires the private empty marker"
assert_grep_fixed 'or os.path.lexists(ARP_DISPATCHER)' \
    "$TMPDIR/noid-network" \
    "disabled GUI state rejects a retained active dispatcher"
assert_grep_fixed "'ARP-hardening ERROR — state inconsistent'" \
    "$TMPDIR/noid-network" \
    "GUI distinguishes corruption from a valid empty pre-learning state"
assert_grep_fixed 'key not in expected or key in state or not val' \
    "$TMPDIR/noid-network" "ARP state parser rejects unknown and duplicate keys"
assert_grep_fixed "state['ENABLED'] not in ('0', '1')" \
    "$TMPDIR/noid-network" "ARP state parser accepts only the closed active/disabled enum"
assert_grep_fixed "[IP_CLI, '-4', 'neigh', 'show', 'to', gw_ip," \
    "$TMPDIR/noid-network" "kernel neighbour query is exact-IP scoped"
assert_grep_fixed "'dev', iface" "$TMPDIR/noid-network" \
    "kernel neighbour query is exact-interface scoped"
assert_grep_fixed 'kernel pin matches state' "$TMPDIR/noid-network" \
    "GUI labels kernel/state parity without claiming independent live observation"
assert_grep_fixed "parts[-1].lower() == 'permanent'" "$TMPDIR/noid-network" \
    "GUI reports a match only for an exact permanent neighbour"
assert_grep_fixed 'remains validated for' "$TMPDIR/noid-network" \
    "disabled pin status truthfully reports retained XDP identity"
assert_not_grep 'permanent ARP entry + nft' "$TMPDIR/noid-network" \
    "GUI does not claim the retired non-enforcing nft shadow filter"
assert_not_grep 'matches the live gateway\|live MAC' "$TMPDIR/noid-network" \
    "GUI has no false live-gateway observation claim"
if python3 - "$TMPDIR/noid-network" "$TMPDIR/arp-gui-fixture" <<'PY'
import ast
import ipaddress
import os as real_os
from pathlib import Path
import re
import stat
import sys
from types import SimpleNamespace

source = Path(sys.argv[1]).read_text(encoding="utf-8")
tree = ast.parse(source)
function = next(
    node for node in tree.body
    if isinstance(node, ast.FunctionDef) and node.name == "_arp_state"
)

root = Path(sys.argv[2])
state_dir = root / "var/lib/noid-privacy"
dispatcher_dir = root / "etc/NetworkManager/dispatcher.d"
preup_dir = dispatcher_dir / "pre-up.d"
nowait_dir = dispatcher_dir / "no-wait.d"
state_dir.mkdir(parents=True)
preup_dir.mkdir(parents=True)
nowait_dir.mkdir(parents=True)
state_dir.chmod(0o755)
dispatcher_dir.chmod(0o755)
preup_dir.chmod(0o755)
nowait_dir.chmod(0o755)
state_path = state_dir / "arp-hardening.state"
marker_path = state_dir / "arp-hardening.disabled"
dispatcher_path = dispatcher_dir / "90-arp-hardening"
preup_path = preup_dir / "90-arp-hardening"
nowait_path = nowait_dir / "90-arp-hardening"
template_path = root / "usr/share/noid-privacy/arp-hardening/90-arp-hardening.template"
template_path.parent.mkdir(parents=True)
template_path.write_text("#!/bin/bash\n", encoding="ascii")
template_path.chmod(0o644)

class RootMetadataOS:
    path = real_os.path
    readlink = staticmethod(real_os.readlink)

    @staticmethod
    def lstat(path):
        value = real_os.lstat(path)
        return SimpleNamespace(
            st_mode=value.st_mode,
            st_uid=0,
            st_gid=0,
            st_nlink=value.st_nlink,
            st_size=value.st_size,
        )

namespace = {
    "os": RootMetadataOS,
    "stat": stat,
    "re": re,
    "ipaddress": ipaddress,
    "ARP_STATE_DIR": str(state_dir),
    "ARP_STATE": str(state_path),
    "ARP_DISABLED": str(marker_path),
    "ARP_DISPATCHER": str(dispatcher_path),
    "ARP_PREUP": str(preup_path),
    "ARP_NOWAIT": str(nowait_path),
    "ARP_TEMPLATE": str(template_path),
}
module = ast.Module(body=[function], type_ignores=[])
ast.fix_missing_locations(module)
exec(compile(module, "<arp-state-fixture>", "exec"), namespace)
parse = namespace["_arp_state"]

def write_state(enabled):
    state_path.write_text(
        f"ENABLED={enabled}\n"
        "WAN_IFACE=test0\n"
        "GATEWAY_IP=192.0.2.1\n"
        "GATEWAY_MAC=52:54:00:aa:bb:cc\n"
        "LEARNED_AT=2026-07-27T00:00:00Z\n",
        encoding="ascii",
    )
    state_path.chmod(0o644)

assert parse() == {}
write_state(1)
preup_path.write_text("#!/bin/bash\nexit 0\n", encoding="ascii")
preup_path.chmod(0o700)
nowait_path.write_text("#!/bin/bash\nexit 0\n", encoding="ascii")
nowait_path.chmod(0o700)
dispatcher_path.symlink_to("no-wait.d/90-arp-hardening")
assert parse()["ENABLED"] == "1"

marker_path.touch(mode=0o600)
assert parse().get("ERROR") == "state-contract"
marker_path.unlink()

write_state(0)
dispatcher_path.unlink()
preup_path.unlink()
nowait_path.unlink()
marker_path.touch(mode=0o600)
assert parse()["ENABLED"] == "0"

marker_path.unlink()
assert parse().get("ERROR") == "state-contract"
marker_path.write_text("not-empty\n", encoding="ascii")
marker_path.chmod(0o600)
assert parse().get("ERROR") == "state-contract"

marker_path.write_text("", encoding="ascii")
marker_path.chmod(0o600)
nowait_path.write_text("#!/bin/bash\n", encoding="ascii")
nowait_path.chmod(0o700)
assert parse().get("ERROR") == "state-contract"
nowait_path.unlink()

state_dir.chmod(0o777)
assert parse().get("ERROR") == "state-contract"
PY
then
    _pass "GUI ARP parser enforces enabled/disabled multi-file lifecycle"
else
    _fail "GUI ARP parser enforces enabled/disabled multi-file lifecycle"
fi

# --- Desktop entry ---------------------------------------------------------
assert_grep_extended '^Type=Application$'                   "$TMPDIR/noid-network.desktop"
assert_grep_extended '^Name=NoID Privacy Network$'          "$TMPDIR/noid-network.desktop"
assert_grep_extended '^Exec=/usr/local/bin/noid-network$' \
    "$TMPDIR/noid-network.desktop" \
    "Network desktop launch inherits GTK's maintained renderer selection"
assert_not_grep 'GSK_RENDERER=' "$TMPDIR/noid-network.desktop" \
    "Network launcher does not pin a renderer"
assert_grep_extended '^Icon=noid-privacy-network$'          "$TMPDIR/noid-network.desktop"
assert_grep_extended '^StartupWMClass=com\.noidprivacy\.Network$' "$TMPDIR/noid-network.desktop"

# --- Module-level structural markers ---------------------------------------
assert_grep_fixed "Module 36" "$KS_FILE" "module header label"
assert_grep_fixed "STEP 1: /usr/local/bin/noid-network deployed" "$KS_FILE"
assert_grep_fixed "STEP 2: /usr/local/bin/noid-network-audit deployed" "$KS_FILE"
assert_grep_fixed "STEP 3: /usr/share/applications/noid-network.desktop deployed" "$KS_FILE"
assert_grep_fixed "STEP 4: Module 36 verify" "$KS_FILE"
for contract in \
    'publish_root_file "$NETWORK_CANDIDATE" /usr/local/bin/noid-network 0755' \
    'publish_root_file "$AUDIT_CANDIDATE" /usr/local/bin/noid-network-audit 0755' \
    'publish_root_file "$DESKTOP_CANDIDATE"' \
    'publish_root_file "$STAMP_CANDIDATE" "$STAMP" 0644' \
    'python3 -c '\''import ast, pathlib, sys; ast.parse' \
    'bash -n "$AUDIT_CANDIDATE"' \
    'mktemp --suffix=.desktop' \
    '/usr/bin/desktop-file-validate "$DESKTOP_CANDIDATE"'; do
    assert_grep_fixed "$contract" "$KS_FILE" \
        "M36 validates and atomically publishes: $contract"
done
assert_not_grep '^cat > /usr/local/bin/noid-network' "$KS_FILE" \
    "M36 never truncates the installed GUI or audit before validation"
assert_not_grep '^cat > /usr/share/applications/noid-network.desktop' "$KS_FILE" \
    "M36 never truncates the installed desktop entry before validation"
assert_not_grep '^[[:space:]]*cat > "\$STAMP"' "$KS_FILE" \
    "M36 never exposes a partially written health stamp"
assert_grep_fixed 'noid-network bytes/metadata/label verification failed' \
    "$KS_FILE" "STEP 4 GUI failure message names every checked contract"
assert_grep_fixed 'noid-network.desktop bytes/metadata/label verification failed' \
    "$KS_FILE" "STEP 4 desktop failure message names every checked contract"
assert_not_grep 'noid-network MISSING or not executable' "$KS_FILE" \
    "STEP 4 does not mislabel metadata or label drift as absence"
assert_not_grep 'noid-network.desktop MISSING' "$KS_FILE" \
    "STEP 4 does not mislabel desktop metadata or label drift as absence"
assert_not_grep 'if command -v desktop-file-validate' "$KS_FILE" \
    "required desktop validation cannot silently disappear from checks_total"
assert_grep_fixed 'if /usr/bin/desktop-file-validate' "$KS_FILE" \
    "STEP 4 always executes the already-required desktop validator"
assert_grep_fixed 'cannot invalidate stale Module 36 health stamp' "$KS_FILE" \
    "M36 invalidates stale success evidence before changing installed payloads"
assert_grep_fixed 'verify_m36_health_stamp()' "$KS_FILE" \
    "M36 validates staged and final health evidence with one exact schema"
assert_grep_fixed 'STAMP_PUBLICATION_ACTIVE=1' "$KS_FILE" \
    "published M36 evidence remains removable through every final gate"
assert_grep_fixed '/usr/sbin/matchpathcon -V "$STAMP_CANDIDATE"' "$KS_FILE" \
    "M36 verifies the staged candidate SELinux context"
assert_grep_fixed '/usr/sbin/matchpathcon -V "$STAMP"' "$KS_FILE" \
    "M36 verifies the final stamp SELinux context"
assert_grep_fixed '/usr/local/bin/noid-network --help' "$KS_FILE" \
    "M36 verify executes import/help smoke test"
assert_grep_fixed \
    'all five privileged backends have exact metadata, canonical aliases and labels' \
    "$KS_FILE" "M36 verify checks its complete backend trust contract"
assert_grep_fixed '[ "$(readlink -- /usr/local/sbin 2>/dev/null || true)" != bin ]' \
    "$KS_FILE" "M36 binds Fedora's exact unified local-sbin alias"
assert_grep_fixed \
    '/usr/local/sbin/noid-toggle-wan-strict|/usr/local/bin/noid-toggle-wan-strict' \
    "$KS_FILE" "M36 maps the public WAN toggle path to Fedora's canonical file"
assert_grep_fixed \
    '/usr/local/bin/noid-lan-allow|/usr/local/bin/noid-lan-allow' \
    "$KS_FILE" "M36 retains an already-canonical local-bin backend"
if grep -qF -- \
        '[ "$(readlink -e -- "$backend" 2>/dev/null || true)" != "$backend" ]' \
        "$KS_FILE"; then
    _fail "M36 never rejects Fedora's package-owned local-sbin alias"
else
    _pass "M36 never rejects Fedora's package-owned local-sbin alias"
fi

backend_fixture="$TMPDIR/backend-trust"
backend_fixture_bin="$backend_fixture/usr/local/bin"
backend_fixture_script="$backend_fixture/verify.sh"
mkdir -p "$backend_fixture_bin"
ln -s bin "$backend_fixture/usr/local/sbin"
for backend_name in noid-toggle-wan-strict noid-wan-strict noid-lan-allow \
        noid-dns-mode noid-arp-hardening.sh; do
    printf '%s\n' '#!/bin/sh' 'exit 0' > "$backend_fixture_bin/$backend_name"
    chmod 0755 "$backend_fixture_bin/$backend_name"
done
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail'
    awk '
        /^verify_backend_trust\(\) \{/ { capture = 1 }
        capture { print }
        capture && /^}$/ { exit }
    ' "$KS_FILE" |
        sed -e 's|/usr/sbin/matchpathcon|/usr/bin/true|g' \
            -e "s|0:0:755:1|$(id -u):$(id -g):755:1|g"
    printf '%s\n' 'verify_backend_trust "$1" "$2"'
} > "$backend_fixture_script"
chmod 0700 "$backend_fixture_script"
assert_cmd_success "M36 accepts Fedora's exact unified local-sbin backend alias" \
    "$backend_fixture_script" \
    "$backend_fixture/usr/local/sbin/noid-toggle-wan-strict" \
    "$backend_fixture_bin/noid-toggle-wan-strict"
assert_cmd_success "M36 accepts an already-canonical local-bin backend" \
    "$backend_fixture_script" \
    "$backend_fixture_bin/noid-lan-allow" \
    "$backend_fixture_bin/noid-lan-allow"
mkdir "$backend_fixture/usr/local/unexpected"
printf '%s\n' '#!/bin/sh' 'exit 0' \
    > "$backend_fixture/usr/local/unexpected/noid-toggle-wan-strict"
chmod 0755 "$backend_fixture/usr/local/unexpected/noid-toggle-wan-strict"
rm "$backend_fixture/usr/local/sbin"
ln -s unexpected "$backend_fixture/usr/local/sbin"
assert_cmd_failure "M36 rejects a redirected local-sbin backend alias" \
    "$backend_fixture_script" \
    "$backend_fixture/usr/local/sbin/noid-toggle-wan-strict" \
    "$backend_fixture_bin/noid-toggle-wan-strict"
for candidate_copy in \
    'cmp -s -- "$NETWORK_CANDIDATE" /usr/local/bin/noid-network' \
    'cmp -s -- "$AUDIT_CANDIDATE" /usr/local/bin/noid-network-audit' \
    'cmp -s -- "$DESKTOP_CANDIDATE"'; do
    assert_grep_fixed "$candidate_copy" "$KS_FILE" \
        "M36 final verification binds installed bytes: $candidate_copy"
done
assert_grep_fixed "stat -Lc '%u:%g:%a:%h' /usr/local/bin/noid-network" \
    "$KS_FILE" "M36 verifies exact executable ownership, mode and link count"
assert_grep_fixed "stat -Lc '%u:%g:%a:%h' /usr/local/bin/noid-network-audit" \
    "$KS_FILE" "M36 verifies exact audit executable ownership, mode and link count"
assert_grep_fixed "stat -Lc '%u:%g:%a:%h' /usr/share/applications/noid-network.desktop" \
    "$KS_FILE" "M36 verifies exact desktop ownership, mode and link count"
assert_not_grep 'restorecon .*2>/dev/null || true' "$KS_FILE" \
    "M36 does not hide SELinux relabel failures"

invalidate_line=$(grep -nF \
    '# M36_HEALTH_INVALIDATION_BEGIN' "$KS_FILE" | cut -d: -f1 || true)
first_payload_line=$(grep -nF \
    'ensure_root_dir /usr/local/bin 0755' "$KS_FILE" | cut -d: -f1 || true)
verify_guard_line=$(grep -nF \
    'if [ "$ver_fail" -eq 0 ]; then' "$KS_FILE" | cut -d: -f1 || true)
publish_line=$(grep -nF \
    '# M36_HEALTH_PUBLICATION_BEGIN' "$KS_FILE" | cut -d: -f1 || true)
complete_line=$(grep -nF \
    'log "=== Module 36 complete: NoID Privacy Network App installed ==="' \
    "$KS_FILE" | cut -d: -f1 || true)
if [ -n "$invalidate_line" ] && [ -n "$first_payload_line" ] \
   && [ -n "$verify_guard_line" ] && [ -n "$publish_line" ] \
   && [ -n "$complete_line" ] \
   && [ "$invalidate_line" -lt "$first_payload_line" ] \
   && [ "$verify_guard_line" -lt "$publish_line" ] \
   && [ "$publish_line" -lt "$complete_line" ]; then
    _pass "M36 retires old health before mutation and publishes after verification"
else
    _fail "M36 health-stamp ordering is not failure-atomic"
fi

# Execute the exact production health-boundary blocks under every material
# publication failure.
m36_stamp_root="$TMPDIR/health-stamp"
m36_stamp_state="$m36_stamp_root/state"
m36_stamp_bin="$m36_stamp_root/bin"
m36_stamp_invalidate="$m36_stamp_root/invalidate.sh"
m36_stamp_publish="$m36_stamp_root/publish.sh"
m36_stamp_uid=$(id -u)
m36_stamp_gid=$(id -g)
mkdir -p "$m36_stamp_bin"

# Keep the isolated publisher bound to the production STEP 4 counter.  A
# previously hard-coded ver_ok=8 let this fixture prove its own invented value
# while the real module had seven successful verification branches and
# correctly published 7/7.
m36_expected_checks=$(sed -n \
    '/^log "STEP 4: Module 36 verify"$/,/^# Module 36 health-stamp/p' \
    "$KS_FILE" | grep -cF 'ver_ok=$((ver_ok + 1))')
assert_eq 7 "$m36_expected_checks" \
    "M36 production verify retains the complete seven-check contract"

cat > "$m36_stamp_bin/restorecon" <<'M36_STAMP_RESTORECON_EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${!#}"
case "${FAKE_RESTORECON_FAIL:-}" in
    all) exit 1 ;;
    final)
        case "$target" in
            */stamp-36-noid-network.ok) exit 1 ;;
        esac
        ;;
esac
exit 0
M36_STAMP_RESTORECON_EOF
cat > "$m36_stamp_bin/matchpathcon" <<'M36_STAMP_MATCHPATHCON_EOF'
#!/usr/bin/env bash
exit 0
M36_STAMP_MATCHPATHCON_EOF
cat > "$m36_stamp_bin/mv" <<'M36_STAMP_MV_EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${FAKE_MV_FAIL:-0}" -eq 1 ]; then
    exit 1
fi
exec /usr/bin/mv "$@"
M36_STAMP_MV_EOF
chmod 0700 "$m36_stamp_bin/restorecon" \
    "$m36_stamp_bin/matchpathcon" "$m36_stamp_bin/mv"

{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'log() { :; }' 'fail() { exit 1; }' \
        "STAMP_DIR=$m36_stamp_state" \
        'STAMP="$STAMP_DIR/stamp-36-noid-network.ok"'
    sed -n \
        '/^# M36_HEALTH_INVALIDATION_BEGIN$/,/^# M36_HEALTH_INVALIDATION_END$/p' \
        "$KS_FILE" |
        sed -e "s|-o root -g root|-o $m36_stamp_uid -g $m36_stamp_gid|" \
            -e "s|0:0:755|$m36_stamp_uid:$m36_stamp_gid:755|" \
            -e "s|/usr/sbin/restorecon|$m36_stamp_bin/restorecon|g" \
            -e "s|/usr/sbin/matchpathcon|$m36_stamp_bin/matchpathcon|g"
} > "$m36_stamp_invalidate"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'log() { :; }' 'fail() { exit 1; }' \
        'NETWORK_CANDIDATE=' 'AUDIT_CANDIDATE=' 'DESKTOP_CANDIDATE=' \
        'STAMP_CANDIDATE=' 'ROOT_PUBLICATION_TMP=' \
        'STAMP_PUBLICATION_ACTIVE=0' \
        "STAMP_DIR=$m36_stamp_state" \
        'STAMP="$STAMP_DIR/stamp-36-noid-network.ok"' \
        "ver_ok=$m36_expected_checks" 'ver_fail=0'
    sed -n '/^cleanup_candidates() {$/,/^}$/p' "$KS_FILE"
    printf '%s\n' 'trap cleanup_candidates EXIT'
    awk '
        /^publish_root_file\(\) \{$/ { capture = 1 }
        capture { print }
        capture && /^\}$/ { exit }
    ' "$KS_FILE" |
        sed -e "s|-o root -g root|-o $m36_stamp_uid -g $m36_stamp_gid|g" \
            -e "s|chown root:root|chown $m36_stamp_uid:$m36_stamp_gid|g" \
            -e "s|0:0:|$m36_stamp_uid:$m36_stamp_gid:|g"
    sed -n \
        '/^# M36_HEALTH_PUBLICATION_BEGIN$/,/^# M36_HEALTH_PUBLICATION_END$/p' \
        "$KS_FILE" |
        sed -e "s|chown root:root|chown $m36_stamp_uid:$m36_stamp_gid|g" \
            -e "s|0:0:|$m36_stamp_uid:$m36_stamp_gid:|g" \
            -e "s|/usr/sbin/restorecon|$m36_stamp_bin/restorecon|g" \
            -e "s|/usr/sbin/matchpathcon|$m36_stamp_bin/matchpathcon|g"
} > "$m36_stamp_publish"
chmod 0700 "$m36_stamp_invalidate" "$m36_stamp_publish"

mkdir -m 0755 "$m36_stamp_state"
printf '%s\n' 'module=36' 'name=noid-network-app' 'status=ok' \
    > "$m36_stamp_state/stamp-36-noid-network.ok"
assert_cmd_success "M36 rerun invalidates its prior build-success stamp" \
    env PATH="$m36_stamp_bin:$PATH" "$m36_stamp_invalidate"
if [ ! -e "$m36_stamp_state/stamp-36-noid-network.ok" ]; then
    _pass "M36 old success evidence is absent before payload publication"
else
    _fail "M36 old success evidence is absent before payload publication"
fi

chmod 0777 "$m36_stamp_state"
printf '%s\n' 'must-survive' > "$m36_stamp_state/stamp-36-noid-network.ok"
assert_cmd_failure "M36 rejects shared state-directory metadata drift" \
    env PATH="$m36_stamp_bin:$PATH" "$m36_stamp_invalidate"
assert_eq "$m36_stamp_uid:$m36_stamp_gid:777" \
    "$(stat -c '%u:%g:%a' "$m36_stamp_state")" \
    "M36 does not normalize drifted shared-directory metadata"
assert_grep_fixed 'must-survive' \
    "$m36_stamp_state/stamp-36-noid-network.ok" \
    "M36 does not traverse a drifted shared state boundary"
rm "$m36_stamp_state/stamp-36-noid-network.ok"
chmod 0755 "$m36_stamp_state"

assert_cmd_failure "M36 rejects a health-stamp candidate label failure" \
    env PATH="$m36_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=all \
        "$m36_stamp_publish"
if [ ! -e "$m36_stamp_state/stamp-36-noid-network.ok" ] \
   && [ -z "$(find "$m36_stamp_state" -maxdepth 1 \
        -name '.stamp-36-noid-network.ok.*' -print -quit)" ]; then
    _pass "M36 candidate-label failure leaves no plausible health evidence"
else
    _fail "M36 candidate-label failure leaves no plausible health evidence"
fi

assert_cmd_failure "M36 retires a stamp after final-label failure" \
    env PATH="$m36_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=final \
        "$m36_stamp_publish"
if [ ! -e "$m36_stamp_state/stamp-36-noid-network.ok" ]; then
    _pass "M36 final-label failure removes the published success stamp"
else
    _fail "M36 final-label failure removes the published success stamp"
fi

assert_cmd_failure "M36 rejects an atomic health-stamp rename failure" \
    env PATH="$m36_stamp_bin:$PATH" FAKE_MV_FAIL=1 "$m36_stamp_publish"
if [ ! -e "$m36_stamp_state/stamp-36-noid-network.ok" ] \
   && [ -z "$(find "$m36_stamp_state" -maxdepth 1 \
        -name '.stamp-36-noid-network.ok.*' -print -quit)" ]; then
    _pass "M36 rename failure leaves no stamp or staged candidate"
else
    _fail "M36 rename failure leaves no stamp or staged candidate"
fi

assert_cmd_success "M36 publishes exact health evidence after all gates" \
    env PATH="$m36_stamp_bin:$PATH" "$m36_stamp_publish"
assert_grep_fixed 'module=36' \
    "$m36_stamp_state/stamp-36-noid-network.ok"
assert_grep_fixed 'name=noid-network-app' \
    "$m36_stamp_state/stamp-36-noid-network.ok"
assert_grep_fixed "checks_passed=$m36_expected_checks" \
    "$m36_stamp_state/stamp-36-noid-network.ok"
assert_grep_fixed "checks_total=$m36_expected_checks" \
    "$m36_stamp_state/stamp-36-noid-network.ok"
assert_eq 10 "$(wc -l < "$m36_stamp_state/stamp-36-noid-network.ok")" \
    "M36 published health stamp has the exact ten-line schema"

# Exercise the exact publication boundary as namespace root. This proves
# symlink replacement, parent/source rejection and last-known-good retention
# when relabeling fails before rename.
awk '
    /^log\(\) \{/ { copy=1 }
    /^log "=== Module 36 post-install:/ { exit }
    copy { print }
' "$KS_FILE" > "$TMPDIR/root-publish-helpers.sh"
cat > "$TMPDIR/root-publish-fixture.sh" <<'M36_ROOT_PUBLISH_FIXTURE_EOF'
#!/usr/bin/bash
set -euo pipefail
. /mnt/root-publish-helpers.sh
restorecon() { return 0; }
matchpathcon() { return 0; }

ensure_root_dir /mnt/managed 0750
[ "$(stat -Lc '%u:%g:%a' /mnt/managed)" = 0:0:750 ]
printf '%s\n' candidate > /mnt/source
chmod 0600 /mnt/source

mkdir /mnt/open-parent
chmod 0777 /mnt/open-parent
if ( ensure_root_dir /mnt/open-parent/child 0755 ); then
    exit 9
fi
[ ! -e /mnt/open-parent/child ]

printf '%s\n' victim > /mnt/victim
ln -s /mnt/victim /mnt/managed/target
publish_root_file /mnt/source /mnt/managed/target 0600
[ -f /mnt/managed/target ] && [ ! -L /mnt/managed/target ]
cmp -s /mnt/source /mnt/managed/target
[ "$(stat -Lc '%u:%g:%a:%h' /mnt/managed/target)" = 0:0:600:1 ]
[ "$(cat /mnt/victim)" = victim ]

chmod 0775 /mnt/managed
if ( publish_root_file /mnt/source /mnt/managed/writable-parent 0644 ); then
    exit 10
fi
[ ! -e /mnt/managed/writable-parent ]
chmod 0750 /mnt/managed

ln /mnt/source /mnt/source-hardlink
if ( publish_root_file /mnt/source /mnt/managed/hardlinked-source 0644 ); then
    exit 11
fi
[ ! -e /mnt/managed/hardlinked-source ]
unlink /mnt/source-hardlink

chmod 0666 /mnt/source
if ( publish_root_file /mnt/source /mnt/managed/writable-source 0644 ); then
    exit 14
fi
[ ! -e /mnt/managed/writable-source ]
chmod 0600 /mnt/source

mkdir /mnt/managed/directory-target
if ( publish_root_file /mnt/source /mnt/managed/directory-target 0644 ); then
    exit 12
fi
[ -d /mnt/managed/directory-target ]

printf '%s\n' previous > /mnt/managed/failure-target
if (
    restorecon() { return 1; }
    publish_root_file /mnt/source /mnt/managed/failure-target 0644
); then
    exit 13
fi
[ "$(cat /mnt/managed/failure-target)" = previous ]
! find /mnt/managed -maxdepth 1 -name '.noid-network-publish.*' \
    -print -quit | grep -q .
M36_ROOT_PUBLISH_FIXTURE_EOF
chmod 0700 "$TMPDIR/root-publish-fixture.sh"
if command -v bwrap >/dev/null 2>&1 && \
   bwrap --unshare-user --uid 0 --gid 0 --die-with-parent \
       --ro-bind / / --dev-bind /dev /dev --proc /proc /bin/true \
       >/dev/null 2>&1; then
    if bwrap --unshare-user --uid 0 --gid 0 --die-with-parent \
            --ro-bind / / --dev-bind /dev /dev --proc /proc \
            --bind "$TMPDIR" /mnt \
            /mnt/root-publish-fixture.sh; then
        _pass "root publication is atomic, path-bounded and failure-safe"
    else
        _fail "root publication behavioral trust-boundary fixture failed"
    fi
else
    _pass "root publication namespace fixture unavailable; structural gates retained"
fi

# A signal outside the bounded rename window must preserve its signal-derived
# status and retire every registered root-publication candidate.
m36_signal_script="$TMPDIR/root-signal-cleanup.sh"
m36_signal_ready="$TMPDIR/root-signal.ready"
m36_signal_candidate="$TMPDIR/root-signal.candidate"
{
    printf '%s\n' '#!/usr/bin/bash' 'set -euo pipefail' \
        'log() { :; }' \
        "STAMP_DIR=$TMPDIR" \
        'STAMP="$STAMP_DIR/stamp-36-noid-network.ok"' \
        'STAMP_PUBLICATION_ACTIVE=0' \
        "ROOT_PUBLICATION_TMP=$m36_signal_candidate" \
        'NETWORK_CANDIDATE=' 'AUDIT_CANDIDATE=' \
        'DESKTOP_CANDIDATE=' 'STAMP_CANDIDATE='
    sed -n '/^cleanup_candidates() {$/,/^}$/p' "$KS_FILE"
    printf '%s\n' \
        'trap cleanup_candidates EXIT' \
        "trap 'exit 129' HUP" \
        "trap 'exit 130' INT" \
        "trap 'exit 143' TERM" \
        "printf '%s\\n' candidate > \"$m36_signal_candidate\"" \
        "printf '%s\\n' ready > \"$m36_signal_ready\"" \
        'while :; do :; done'
} > "$m36_signal_script"
chmod 0700 "$m36_signal_script"
"$m36_signal_script" &
m36_signal_pid=$!
for _ in $(seq 1 500); do
    [ -e "$m36_signal_ready" ] && break
    sleep 0.01
done
set +e
kill -TERM "$m36_signal_pid" 2>/dev/null
wait "$m36_signal_pid"
m36_signal_rc=$?
set -e
if [ "$m36_signal_rc" -eq 143 ] \
   && [ ! -e "$m36_signal_candidate" ]; then
    _pass "M36 TERM cleanup retires the active root-publication candidate"
else
    _fail "M36 TERM cleanup leaked a candidate or returned $m36_signal_rc"
fi

# --- --section deep link ---------------------------------------------------
# Setup's network-printer step launches this app on LAN Exceptions, so the
# parser is a real contract between two shipped programs. Exercise the shipped
# functions themselves rather than grepping for them: lift the parser, usage
# and main entry point out with ast so the check needs no GTK import. Valid
# deep links must launch exactly once; every ambiguous or hostile vector must
# return usage status 2 before the application object is instantiated.
m36_section_probe() {
    python3 - "$TMPDIR/noid-network" <<'SECTION_PROBE_EOF'
import ast, sys, io, contextlib

source = open(sys.argv[1], encoding='utf-8').read()
tree = ast.parse(source)
wanted = {}
for node in tree.body:
    if (isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == 'NETWORK_SECTIONS'):
        wanted['const'] = node
    if isinstance(node, ast.FunctionDef) and node.name in (
            '_requested_section', '_print_usage', 'main'):
        wanted[node.name] = node
if set(wanted) != {'const', '_requested_section', '_print_usage', 'main'}:
    raise SystemExit('section parser entry-point contract is incomplete')

namespace = {'sys': sys, '__doc__': ''}
exec(compile(ast.Module(body=[wanted['const'], wanted['_requested_section'],
                             wanted['_print_usage'], wanted['main']],
                        type_ignores=[]), '<m36>', 'exec'), namespace)
sections = namespace['NETWORK_SECTIONS']
resolve = namespace['_requested_section']

if tuple(sections) != ('wan', 'lan', 'dns', 'status'):
    raise SystemExit('section allowlist drifted: %r' % (sections,))
cases = [
    (['--section', 'lan'], 'lan'),
    (['--section=dns'], 'dns'),
    (['--section', 'status'], 'status'),
    ([], None),
]
for argv, expected in cases:
    got = resolve(argv)
    if got != expected:
        raise SystemExit('argv %r resolved to %r, expected %r'
                         % (argv, got, expected))

invalid = [
    ['--section'],                         # trailing flag, no value
    ['--section', 'LAN'],                  # case-sensitive allowlist
    ['--section', ''],                     # explicit empty value
    ['--section='],                        # attached empty value
    ['--section', 'wan; rm -rf /'],        # shell metacharacters stay data
    ['--section', '../../etc/passwd'],
    ['--section', 'dns\n--help'],
    ['--section', 'lan', 'extra'],         # surplus positional argument
    ['--section', 'wan', '--section', 'dns'],
    ['--section=wan', '--section=dns'],
    ['--help', '--section', 'dns'],         # help must be exact too
    ['-h', 'extra'],
    ['--unknown'],
    ['positional'],
]
for argv in invalid:
    try:
        resolve(argv)
    except ValueError:
        pass
    else:
        raise SystemExit('invalid argv was accepted: %r' % (argv,))

class AppProbe:
    created = []

    def __init__(self, section):
        self.section = section
        self.run_argv = None
        self.__class__.created.append(self)

    def run(self, argv):
        self.run_argv = argv
        return 17

namespace['NoIDNetworkApp'] = AppProbe
main = namespace['main']
original_argv = sys.argv
try:
    for argv, section in (([], None), (['--section', 'lan'], 'lan'),
                          (['--section=dns'], 'dns')):
        before = len(AppProbe.created)
        sys.argv = ['noid-network'] + argv
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            rc = main()
        if rc != 17 or len(AppProbe.created) != before + 1:
            raise SystemExit('valid argv did not launch exactly once: %r' % argv)
        app = AppProbe.created[-1]
        if app.section != section or app.run_argv != ['noid-network']:
            raise SystemExit('valid argv launch contract drifted: %r' % argv)

    for argv in invalid:
        before = len(AppProbe.created)
        sys.argv = ['noid-network'] + argv
        stderr = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(stderr):
            rc = main()
        if rc != 2 or len(AppProbe.created) != before:
            raise SystemExit('invalid argv reached the application: %r' % argv)
        if stderr.getvalue().count('Usage:') != 1:
            raise SystemExit('invalid argv lacks one usage diagnostic: %r' % argv)

    for argv in (['--help'], ['-h']):
        before = len(AppProbe.created)
        sys.argv = ['noid-network'] + argv
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(io.StringIO()):
            rc = main()
        if rc != 0 or len(AppProbe.created) != before:
            raise SystemExit('exact help was not side-effect free: %r' % argv)
        if stdout.getvalue().count('Usage:') != 1:
            raise SystemExit('exact help lacks one usage block: %r' % argv)
finally:
    sys.argv = original_argv
print('ok')
SECTION_PROBE_EOF
}
assert_cmd_success "GUI accepts exact deep links and rejects hostile arguments before launch" \
    m36_section_probe
assert_grep_fixed "stack.set_visible_child_name(self._section)" \
    "$TMPDIR/noid-network" \
    "a named section actually switches the view stack"
assert_grep_fixed "stack.get_child_by_name(self._section)" \
    "$TMPDIR/noid-network" \
    "the deep link verifies the page exists before selecting it"
assert_grep_fixed "noid-network --section NAME  Open directly on one tab" \
    "$TMPDIR/noid-network" "--help documents the deep link"

test_finish
