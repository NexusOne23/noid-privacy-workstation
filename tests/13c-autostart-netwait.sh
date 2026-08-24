#!/bin/bash
# 13c-autostart-netwait — autostart network gate, helper and picker plumbing.
#
# XDG autostart has no ordering contract with NetworkManager. gnome-session
# starts every entry as soon as the session is ready, regularly seconds before
# wifi association completes, and a VPN client that probes its server once at
# startup then fails permanently. The visible symptom is indistinguishable from
# a firewall fault although no packet was dropped.
#
# `nm-online` cannot express the condition: it waits for "a connection", and a
# kill-switch placeholder such as ProtonVPN's dummy pvpn-killswitch-perm is a
# fully activated NetworkManager connection that owns the default route while
# nothing can leave the host. The whole point of this helper is that it does not
# fall for that, so the negative cases below are the load-bearing ones.
#
# Two properties must hold in every case:
#   1. a tunnel, dummy or other virtual device NEVER opens the gate;
#   2. the helper NEVER prevents an application from starting — every error,
#      an absent or unreachable NetworkManager, and the timeout all end in exec.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

ROOT=$(find_project_root)
KS_FILE="$ROOT/kickstart/snippets/13-aide-welcome.ks"
# /tmp is noexec on this image; executable fixtures live below /var/tmp.
TMPDIR=$(mktemp -d /var/tmp/noid-test-13c.XXXXXX)
cleanup() { chmod -R u+rwX "$TMPDIR" 2>/dev/null || true; rm -rf "$TMPDIR"; }
trap cleanup EXIT

NETWAIT="$TMPDIR/noid-autostart-netwait"
WELCOME_PY="$TMPDIR/welcome.py"
MOCKBIN="$TMPDIR/bin"
BAREBIN="$TMPDIR/bin-no-nm"
SYS_NET="$TMPDIR/sys-class-net"
DEVICES="$TMPDIR/devices"
STATES="$TMPDIR/states"
RAN="$TMPDIR/ran"

test_start "13c-autostart-netwait"

assert_file_exists "$KS_FILE"

# --- extraction ------------------------------------------------------------
if extract_heredoc "$KS_FILE" NETWAIT_EOF "$NETWAIT"; then
    _pass "the netwait helper is embedded in module 13"
else
    _fail "the netwait helper is embedded in module 13"
fi
chmod 0755 "$NETWAIT"
assert_cmd_success "the extracted helper is syntactically valid bash" \
    bash -n "$NETWAIT"
assert_grep_fixed 'NOID_FMT_AUTO_TITLE="NoID Privacy — Network Gate"' \
    "$NETWAIT" "interactive checks use the shared NoID Privacy CLI frame"
assert_grep_fixed 'NOID_FMT_AUTO_SUBTITLE="Physical-link readiness"' \
    "$NETWAIT" "the network gate states the condition it assesses"

if extract_heredoc "$KS_FILE" NOID_WELCOME_PY_EOF "$WELCOME_PY"; then
    _pass "the welcome UI is extractable for the picker checks"
else
    _fail "the welcome UI is extractable for the picker checks"
fi

# --- install contract in the kickstart --------------------------------------
assert_grep_fixed '/usr/local/bin/noid-autostart-netwait|755' "$KS_FILE" \
    "the helper is covered by the generated-artifact metadata gate"
assert_grep_fixed 'chmod 755 /usr/local/bin/noid-autostart-netwait' "$KS_FILE" \
    "the helper is installed 755"
assert_grep_fixed 'chown root:root /usr/local/bin/noid-autostart-netwait' \
    "$KS_FILE" "the helper is installed root-owned"
assert_grep_fixed 'bash -n /usr/local/bin/noid-autostart-netwait' "$KS_FILE" \
    "the build fails when the helper does not parse"
assert_grep_fixed "NETWAIT_CMD = '/usr/local/bin/noid-autostart-netwait'" \
    "$KS_FILE" "the picker points at the installed helper path"
assert_grep_fixed 'def _autostart_recommends_netwait(entry):' "$KS_FILE" \
    "the picker has a narrow semantic VPN-client initial value"
assert_grep_fixed "info['path'], info['filename'], prefer_netwait" "$KS_FILE" \
    "the add transaction consumes the visible VPN recommendation"
assert_not_grep_fixed 'vpn|ivpn|' "$KS_FILE" \
    "an IVPN name does not imply a dedicated NoID Privacy integration"

# --- mock NetworkManager ----------------------------------------------------
mkdir -p "$MOCKBIN" "$BAREBIN" "$SYS_NET"
# PATH is replaced wholesale during a probe so that BAREBIN can prove the
# absent-nmcli path. Everything the helper and the mock legitimately call must
# therefore exist in both directories, or a probe would fail for the wrong
# reason and every negative check below would pass vacuously.
for tool in sleep logger cat grep; do
    tool_path=$(command -v "$tool" 2>/dev/null) || continue
    ln -sf "$tool_path" "$MOCKBIN/$tool"
    ln -sf "$tool_path" "$BAREBIN/$tool"
done

cat > "$MOCKBIN/nmcli" <<'MOCK_NMCLI_EOF'
#!/bin/bash
# Minimal nmcli stand-in. Only the two invocations the helper makes are
# implemented; anything else fails, which would surface as a broken probe.
[ -n "${MOCK_NM_DOWN:-}" ] && exit 8
case "$*" in
    "-t -f DEVICE,TYPE device status")
        cat "$MOCK_DEVICES"
        ;;
    "-g GENERAL.STATE device show "*)
        # Last positional. Not ${*##* }: pattern removal on $* is applied to
        # every parameter separately, which would yield the whole command line.
        dev=${*: -1}
        line=$(grep -- "^${dev}=" "$MOCK_STATES" 2>/dev/null) || exit 10
        printf '%s\n' "${line#*=}"
        ;;
    *)
        exit 2
        ;;
esac
MOCK_NMCLI_EOF
chmod 0755 "$MOCKBIN/nmcli"

export MOCK_DEVICES="$DEVICES" MOCK_STATES="$STATES"
export NOID_AUTOSTART_NETWAIT_SYSFS="$SYS_NET"

# scenario <devices-spec> — each arg is "name:nmtype:state:physical(yes|no)"
scenario() {
    : > "$DEVICES"
    : > "$STATES"
    rm -rf "${SYS_NET:?}"/*
    local spec name typ state phys
    for spec in "$@"; do
        IFS=: read -r name typ state phys <<<"$spec"
        printf '%s:%s\n' "$name" "$typ" >> "$DEVICES"
        printf '%s=%s\n' "$name" "$state" >> "$STATES"
        mkdir -p "$SYS_NET/$name"
        if [ "$phys" = yes ]; then
            : > "$SYS_NET/$name/device"
        fi
    done
}

check_gate() { PATH="$MOCKBIN" "$NETWAIT" --check >/dev/null 2>&1; }

# Positive control for the harness itself. Without it a broken mock would make
# every "gate stays closed" check pass for the wrong reason.
scenario 'wlp3s0:wifi:100 (connected):yes' 'proton0:wireguard:100 (connected):no'
mock_devices=$(PATH="$MOCKBIN" nmcli -t -f DEVICE,TYPE device status 2>&1 | tr '\n' ' ')
assert_eq "wlp3s0:wifi proton0:wireguard " "$mock_devices" \
    "the mock NetworkManager answers the device query"
mock_state=$(PATH="$MOCKBIN" nmcli -g GENERAL.STATE device show wlp3s0 2>&1)
assert_eq "100 (connected)" "$mock_state" \
    "the mock NetworkManager answers the state query"

expect_closed() {
    local label=$1; shift
    scenario "$@"
    if check_gate; then
        _fail "gate stays closed: $label"
    else
        _pass "gate stays closed: $label"
    fi
}

expect_open() {
    local label=$1; shift
    scenario "$@"
    if check_gate; then
        _pass "gate opens: $label"
    else
        _fail "gate opens: $label"
    fi
}

# The exact boot state that broke ProtonVPN: the kill-switch dummy is activated
# and owns the default route while the wifi has not associated yet.
expect_closed "ProtonVPN kill-switch dummy alone" \
    'lo:loopback:100 (connected):no' \
    'pvpnksintrf1:dummy:100 (connected):no' \
    'wlp3s0:wifi:30 (disconnected):yes'
expect_closed "a WireGuard tunnel alone" \
    'proton0:wireguard:100 (connected):no' \
    'wlp3s0:wifi:20 (unavailable):yes'
expect_closed "an OpenVPN tun device alone" \
    'tun0:tun:100 (connected):no' \
    'enp4s0:ethernet:30 (disconnected):yes'
expect_closed "a Mullvad-style wg device alone" \
    'wg0-mullvad:wireguard:100 (connected):no'
expect_closed "loopback alone" 'lo:loopback:100 (connected):no'
expect_closed "a physical device that is merely configuring" \
    'wlp3s0:wifi:70 (ip-config):yes'
expect_closed "a physical device that is deactivating" \
    'wlp3s0:wifi:110 (deactivating):yes'
expect_closed "a bridge without an activated port" \
    'br0:bridge:100 (connected):no' \
    'enp4s0:ethernet:30 (disconnected):yes'
# A dummy with a bus symlink cannot occur on a real host, but the type reject
# must win regardless so the classifier has no single point of failure.
expect_closed "a dummy is rejected even with a bus device present" \
    'pvpnksintrf1:dummy:100 (connected):yes'
expect_closed "the p2p wifi device is not a carrier" \
    'p2p-dev-wlp3s0:wifi-p2p:100 (connected):yes'

expect_open "an associated wifi device" \
    'lo:loopback:100 (connected):no' \
    'pvpnksintrf1:dummy:100 (connected):no' \
    'wlp3s0:wifi:100 (connected):yes'
# Naming the accepting device is what makes --check a usable diagnostic, and it
# is the only way to prove the gate opened for the wifi and not for the dummy
# that is activated in the very same scenario.
gate_report=$(PATH="$MOCKBIN" "$NETWAIT" --check 2>&1)
assert_eq "physical network device activated: wlp3s0" "$gate_report" \
    "--check names the device that opened the gate"
expect_open "a wired device" 'enp4s0:ethernet:100 (connected):yes'
expect_open "an enslaved port under a bridge" \
    'br0:bridge:100 (connected):no' \
    'enp4s0:ethernet:100 (connected):yes'
expect_open "a USB-tethered phone (ethernet class)" \
    'enp0s20u1:ethernet:100 (connected):yes'
# PPPoE and mobile broadband have no bus symlink and are allowed by type.
expect_open "a PPPoE uplink without a bus device" \
    'ppp0:adsl:100 (connected):no'
expect_open "a mobile broadband uplink" 'wwan0:gsm:100 (connected):no'
# Acceptance rests on the kernel, so an unfamiliar type name still works.
expect_open "an unknown device type backed by real hardware" \
    'ib0:some-future-type:100 (connected):yes'
# nmcli's human-readable suffix is translated; the numeric prefix is not.
expect_open "a localized nmcli state string" \
    'wlp3s0:wifi:100 (verbunden):yes'
expect_closed "a localized non-activated state string" \
    'wlp3s0:wifi:30 (getrennt):yes'

# --- fail-open contract -----------------------------------------------------
run_helper() {
    rm -f "$RAN"
    PATH="$1" "$NETWAIT" "${@:2}" -- /bin/sh -c "echo started > '$RAN'"
}

scenario 'wlp3s0:wifi:100 (connected):yes'
if run_helper "$MOCKBIN" --settle 0 --quiet >/dev/null 2>&1 && [ -f "$RAN" ]; then
    _pass "the command runs when the link is already up"
else
    _fail "the command runs when the link is already up"
fi

scenario 'pvpnksintrf1:dummy:100 (connected):no' 'wlp3s0:wifi:30 (down):yes'
start=$(date +%s)
if run_helper "$MOCKBIN" --timeout 2 --settle 0 --quiet >/dev/null 2>&1 \
   && [ -f "$RAN" ]; then
    _pass "fail-open: the command still runs after the timeout"
else
    _fail "fail-open: the command still runs after the timeout"
fi
waited=$(( $(date +%s) - start ))
if [ "$waited" -ge 2 ] && [ "$waited" -le 8 ]; then
    _pass "the helper honours its timeout (${waited}s for a 2s budget)"
else
    _fail "the helper honours its timeout (${waited}s for a 2s budget)"
fi

if MOCK_NM_DOWN=1 run_helper "$MOCKBIN" --timeout 1 --settle 0 --quiet \
       >/dev/null 2>&1 && [ -f "$RAN" ]; then
    _pass "fail-open: an unreachable NetworkManager does not block the app"
else
    _fail "fail-open: an unreachable NetworkManager does not block the app"
fi

start=$(date +%s)
if run_helper "$BAREBIN" --timeout 30 --settle 0 --quiet >/dev/null 2>&1 \
   && [ -f "$RAN" ] && [ $(( $(date +%s) - start )) -le 3 ]; then
    _pass "fail-open: an absent nmcli starts the app immediately"
else
    _fail "fail-open: an absent nmcli starts the app immediately"
fi

scenario 'pvpnksintrf1:dummy:100 (connected):no'
start=$(date +%s)
if run_helper "$MOCKBIN" --timeout 0 --settle 0 --quiet >/dev/null 2>&1 \
   && [ -f "$RAN" ] && [ $(( $(date +%s) - start )) -le 3 ]; then
    _pass "--timeout 0 disables the wait entirely"
else
    _fail "--timeout 0 disables the wait entirely"
fi

# --- argument handling ------------------------------------------------------
scenario 'wlp3s0:wifi:100 (connected):yes'
got=$(PATH="$MOCKBIN" "$NETWAIT" --settle 0 --quiet -- /bin/sh -c \
        'printf "%s|" "$@"' _ one "two three" 2>/dev/null)
assert_eq "one|two three|" "$got" "arguments reach the application unmangled"

PATH="$MOCKBIN" "$NETWAIT" --settle 0 --quiet -- /bin/sh -c 'exit 42' \
    >/dev/null 2>&1 && rc=0 || rc=$?
assert_eq "42" "$rc" "the application's exit status is propagated"

PATH="$MOCKBIN" "$NETWAIT" --settle 0 --quiet >/dev/null 2>&1 && rc=0 || rc=$?
assert_eq "2" "$rc" "an invocation without a command is a usage error"

PATH="$MOCKBIN" "$NETWAIT" --not-a-flag -- /bin/true >/dev/null 2>&1 \
    && rc=0 || rc=$?
assert_eq "2" "$rc" "an unknown option is a usage error"

rm -f "$RAN"
PATH="$MOCKBIN" "$NETWAIT" --check >/dev/null 2>&1 || true
if [ ! -f "$RAN" ]; then
    _pass "--check runs no command"
else
    _fail "--check runs no command"
fi

# A malformed value must degrade to the default, never to an unbounded wait.
scenario 'pvpnksintrf1:dummy:100 (connected):no'
if timeout 6 env PATH="$MOCKBIN" NOID_AUTOSTART_NETWAIT_TIMEOUT=nonsense \
       "$NETWAIT" --timeout 1 --settle 0 --quiet -- /bin/true >/dev/null 2>&1
then
    _pass "a non-numeric timeout falls back instead of hanging"
else
    _fail "a non-numeric timeout falls back instead of hanging"
fi

# --- picker plumbing --------------------------------------------------------
# The Exec= rewrite is exercised directly. The surrounding UI needs GTK, so the
# three pure functions are lifted out of the welcome source and run alone.
python3 - "$WELCOME_PY" "$TMPDIR" <<'PICKER_EOF' > "$TMPDIR/picker.out"
import ast
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

source_path, workdir = sys.argv[1], sys.argv[2]
source = Path(source_path).read_text()
tree = ast.parse(source)

wanted_funcs = {
    '_autostart_recommends_netwait', '_autostart_add',
    '_netwait_enabled', '_netwait_strip', '_autostart_set_netwait'}
wanted_consts = {'NETWAIT_CMD'}
segments = []
for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name in wanted_funcs:
        segments.append(ast.get_source_segment(source, node))
        wanted_funcs.discard(node.name)
    elif isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in wanted_consts:
                segments.append(ast.get_source_segment(source, node))
                wanted_consts.discard(target.id)

results = []


def check(ok, label):
    results.append(('OK' if ok else 'FAIL', label))


if wanted_funcs or wanted_consts:
    missing = sorted(wanted_funcs | wanted_consts)
    check(False, 'picker gate symbols are present (missing: %s)' % missing)
    for state, label in results:
        print('%s\t%s' % (state, label))
    sys.exit(0)

check(True, 'picker gate symbols are present in the welcome source')

autostart = Path(workdir) / 'autostart'
autostart.mkdir(parents=True, exist_ok=True)
namespace = {
    'os': os, 're': re, 'shutil': shutil, 'tempfile': tempfile, 'Path': Path,
    'AUTOSTART_DIR': autostart,
    '_warn': lambda *a, **k: None,
}
exec('\n\n'.join(segments), namespace)

recommend = namespace['_autostart_recommends_netwait']
add = namespace['_autostart_add']
enabled = namespace['_netwait_enabled']
strip = namespace['_netwait_strip']
set_gate = namespace['_autostart_set_netwait']
shipped_cmd = namespace['NETWAIT_CMD']

check(shipped_cmd == '/usr/local/bin/noid-autostart-netwait',
      'the picker uses the installed helper path')
helper = Path(workdir) / 'noid-autostart-netwait'
helper.write_text('#!/bin/sh\nexit 0\n')
helper.chmod(0o755)
namespace['NETWAIT_CMD'] = str(helper)
cmd = str(helper)
check(not enabled('protonvpn-app'), 'a plain Exec is reported ungated')
check(enabled(cmd + ' -- protonvpn-app'), 'a gated Exec is reported gated')
check(not enabled(''), 'an empty Exec is reported ungated')
check(strip(cmd + ' -- protonvpn-app') == 'protonvpn-app',
      'the canonical wrapper is stripped')
check(strip(cmd + ' --timeout 60 -- protonvpn-app %U') == 'protonvpn-app %U',
      'a hand-edited wrapper with options is stripped')
check(strip('protonvpn-app %U') == 'protonvpn-app %U',
      'an ungated Exec survives stripping unchanged')

ORIGINAL = (
    '[Desktop Entry]\n'
    '# a comment that must survive\n'
    'Name=Proton VPN\n'
    'Name[de]=Proton VPN\n'
    'Exec=protonvpn-app %U\n'
    'Type=Application\n'
    'Icon=proton-vpn-logo\n'
    '\n'
    '[Desktop Action Quit]\n'
    'Exec=protonvpn-app --quit\n'
)
entry = autostart / 'proton.vpn.app.gtk.desktop'
source_entry = Path(workdir) / 'proton-source.desktop'
source_entry.write_text(ORIGINAL)
os.chmod(source_entry, 0o644)
proton = {
    'filename': entry.name, 'name': 'Proton VPN',
    'comment': 'Proton VPN GUI client', 'exec': 'protonvpn-app %U'}
mullvad = {
    'filename': 'net.mullvad.MullvadVPN.desktop', 'name': 'Mullvad VPN',
    'comment': '', 'exec': 'mullvad-vpn'}
wireguard = {
    'filename': 'wireguard-ui.desktop', 'name': 'WireGuard UI',
    'comment': 'WireGuard frontend', 'exec': 'wireguard-ui'}
openvpn = {
    'filename': 'openvpn-ui.desktop', 'name': 'OpenVPN UI',
    'comment': '', 'exec': 'openvpn-ui'}
ivpn = {
    'filename': 'net.ivpn.client.desktop', 'name': 'IVPN',
    'comment': '', 'exec': 'ivpn'}
firefox = {
    'filename': 'firefox.desktop', 'name': 'Firefox',
    'comment': 'Web Browser', 'exec': 'firefox %u'}
check(recommend(proton), 'Proton receives the VPN-client initial value')
check(recommend(mullvad), 'Mullvad receives the provider-neutral initial value')
check(recommend(wireguard), 'a generic WireGuard GUI receives the initial value')
check(recommend(openvpn), 'a generic OpenVPN GUI receives the initial value')
check(not recommend(ivpn), 'IVPN receives no unreviewed product-specific claim')
check(not recommend(firefox), 'an unrelated network app remains ungated')

check(add(source_entry, entry.name, recommend(proton)),
      'adding a recognized VPN app and its gate is one transaction')

gated = entry.read_text()
check('Exec=%s -- protonvpn-app %%U\n' % cmd in gated,
      'the recognized VPN app is wrapped on initial add')
check('[Desktop Action Quit]\nExec=protonvpn-app --quit\n' in gated,
      "a desktop action's Exec is left alone")
check('# a comment that must survive' in gated and 'Name[de]=Proton VPN' in gated,
      'comments and localized keys are preserved')
check(len(gated.splitlines()) == len(ORIGINAL.splitlines()),
      'no lines are added or lost')
check(oct(entry.stat().st_mode & 0o7777) == '0o644',
      'the file mode is preserved')

check(set_gate(entry.name, True), 'enabling twice succeeds')
check(entry.read_text() == gated, 'enabling twice does not double-wrap')

check(set_gate(entry.name, False), 'disabling the gate succeeds')
check(entry.read_text() == ORIGINAL,
      'disabling restores the file byte-for-byte')

firefox_source = Path(workdir) / 'firefox-source.desktop'
firefox_original = '[Desktop Entry]\nName=Firefox\nExec=firefox %u\nType=Application\n'
firefox_source.write_text(firefox_original)
check(add(firefox_source, firefox['filename'], recommend(firefox)),
      'adding an unrelated app succeeds without the gate')
check((autostart / firefox['filename']).read_text() == firefox_original,
      'an unrelated app remains byte-identical to its source')

namespace['NETWAIT_CMD'] = str(Path(workdir) / 'missing-netwait')
check(not add(source_entry, 'failed-gated.desktop', True),
      'a missing helper fails the gated add transaction')
check(not (autostart / 'failed-gated.desktop').exists(),
      'a failed gated add leaves no broken autostart entry')
namespace['NETWAIT_CMD'] = cmd

leftovers = [p.name for p in autostart.iterdir() if p.name.startswith('.')]
check(not leftovers, 'no temporary files are left behind (%s)' % leftovers)

noexec = autostart / 'mask.desktop'
noexec.write_text('[Desktop Entry]\nType=Application\nHidden=true\n')
check(not set_gate(noexec.name, True),
      'an entry without Exec= is refused instead of corrupted')
check(set_gate('does-not-exist.desktop', True) is False,
      'a missing entry is refused')

for state, label in results:
    print('%s\t%s' % (state, label))
PICKER_EOF

while IFS=$'\t' read -r state label; do
    [ -n "$label" ] || continue
    if [ "$state" = OK ]; then _pass "$label"; else _fail "$label"; fi
done < "$TMPDIR/picker.out"

test_finish
