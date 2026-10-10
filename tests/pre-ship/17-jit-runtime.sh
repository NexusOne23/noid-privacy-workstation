#!/usr/bin/env bash
# Candidate-only GJS/WebKitGTK JIT-default and explicit-opt-out behavior gate.
set -euo pipefail
ulimit -c 0

TEST_NAME=17-jit-runtime
PASS_ID=${1:-}
case "$PASS_ID" in
    live) ;;
    fresh-install) ;;
    reboot) ;;
    *)
        echo "Usage: bash $0 {live|fresh-install|reboot}" >&2
        exit 2
        ;;
esac
fail() { echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] || fail "run as the normal GNOME user, not root"
grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
[[ ${XDG_CURRENT_DESKTOP:-} == *GNOME* ]] || fail "active desktop is not GNOME"
[[ -n ${WAYLAND_DISPLAY:-} ]] || fail "native GNOME Wayland session is required"
[[ ${GJS_DISABLE_JIT:-} == 1 ]] || fail "session GJS JIT-disable default is absent"
[[ ${JavaScriptCoreUseJIT:-} == 0 ]] || fail "session WebKit JIT-disable default is absent"

for command_name in awk gjs grep matchpathcon mktemp python3 readlink rpm stat \
        systemctl; do
    command -v "$command_name" >/dev/null 2>&1 \
        || fail "required command missing: $command_name"
done
rpm -q gjs webkitgtk6.0 python3-gobject gtk4 >/dev/null \
    || fail "reviewed GJS/WebKitGTK probe dependencies are incomplete"

jit_env=/etc/environment.d/40-noid-disable-jit.conf
[[ -f $jit_env && ! -L $jit_env ]] \
    || fail "installed JIT environment file is missing, non-regular or symlinked"
[[ $(stat -c '%U:%G:%a:%h' "$jit_env" 2>/dev/null) == root:root:644:1 ]] \
    || fail "installed JIT environment file metadata is invalid"
matchpathcon -V "$jit_env" >/dev/null 2>&1 \
    || fail "installed JIT environment file SELinux label is invalid"
jit_active=$(awk '!/^[[:space:]]*(#|$)/ { print }' "$jit_env") \
    || fail "cannot read installed JIT environment assignments"
[[ $jit_active == $'JavaScriptCoreUseJIT=0\nGJS_DISABLE_JIT=1' ]] \
    || fail "installed JIT environment assignment set is not exact and closed"

manager_environment=$(systemctl --user show-environment) \
    || fail "cannot read user-manager environment"
grep -qxF 'GJS_DISABLE_JIT=1' <<<"$manager_environment" \
    || fail "user manager did not import the GJS default"
grep -qxF 'JavaScriptCoreUseJIT=0' <<<"$manager_environment" \
    || fail "user manager did not import the WebKitGTK default"

shell_pid=$(systemctl --user show org.gnome.Shell@user.service -p MainPID --value) \
    || fail "cannot query the managed GNOME Shell process"
[[ $shell_pid =~ ^[1-9][0-9]*$ \
   && $(readlink -e "/proc/$shell_pid/exe") == /usr/bin/gnome-shell ]] \
    || fail "managed GNOME Shell PID or executable is invalid"
python3 - "/proc/$shell_pid/environ" <<'JIT_ENV_PY' \
    || fail "GNOME Shell JIT environment is unreadable or differs"
from pathlib import Path
import sys

try:
    raw = Path(sys.argv[1]).read_bytes()
except OSError:
    raise SystemExit("cannot read managed process environment")
if not raw.endswith(b"\0"):
    raise SystemExit("managed process environment is empty or incomplete")
fields = [entry.partition(b"=") for entry in raw[:-1].split(b"\0")]
for name, expected in ((b"GJS_DISABLE_JIT", b"1"), (b"JavaScriptCoreUseJIT", b"0")):
    values = [value for key, separator, value in fields if key == name and separator]
    if values != [expected]:
        raise SystemExit("managed process JIT assignment is missing, ambiguous or differs")
JIT_ENV_PY

gjs_default=$(GJS_DEBUG_OUTPUT=stderr GJS_DEBUG_TOPICS='JS CTX' \
    gjs -c 'print("noid-gjs-ok")' 2>&1) \
    || fail "GJS failed under the shipped JIT-disabled default"
grep -qF 'noid-gjs-ok' <<<"$gjs_default" || fail "GJS default probe output is malformed"
if grep -qF 'Enabling JIT' <<<"$gjs_default"; then
    fail "GJS reports JIT enabled under the shipped default"
fi
gjs_optout=$(env -u GJS_DISABLE_JIT GJS_DEBUG_OUTPUT=stderr \
    GJS_DEBUG_TOPICS='JS CTX' gjs -c 'print("noid-gjs-optout-ok")' 2>&1) \
    || fail "documented GJS per-launch opt-out is not functional"
grep -qF 'noid-gjs-optout-ok' <<<"$gjs_optout" \
    || fail "GJS opt-out probe output is malformed"
grep -qF 'Enabling JIT' <<<"$gjs_optout" \
    || fail "unsetting GJS_DISABLE_JIT did not restore the reviewed JIT path"

tmp=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/noid-jit-runtime.XXXXXX")
trap 'rm -rf -- "$tmp"' EXIT HUP INT TERM

run_webkit_probe() {
    local jit_value=$1 output=$2 errors=$3 cache=$4
    env JavaScriptCoreUseJIT="$jit_value" JSC_dumpOptions=3 \
        XDG_CACHE_HOME="$cache" python3 - <<'PY' >"$output" 2>"$errors"
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("WebKit", "6.0")
from gi.repository import GLib, Gtk, WebKit

Gtk.init()
loop = GLib.MainLoop()
view = WebKit.WebView()
result = {"title": None}

def title_changed(webview, _property):
    title = webview.get_title()
    if title == "noid-webkit-ok":
        result["title"] = title
        loop.quit()

view.connect("notify::title", title_changed)
GLib.timeout_add_seconds(10, lambda: (loop.quit(), False)[1])
view.load_html(
    "<script>let x=1; for(let i=0;i<2000000;i++) "
    "x=(x*1664525+1013904223)|0; document.title='noid-webkit-ok';</script>",
    "about:blank",
)
loop.run()
if result["title"] != "noid-webkit-ok":
    raise SystemExit("local WebKitGTK JavaScript probe timed out")
print(result["title"])
PY
}

run_webkit_probe 0 "$tmp/webkit-default.out" "$tmp/webkit-default.err" \
    "$tmp/cache-default" || fail "WebKitGTK failed under JIT disablement"
grep -qxF 'noid-webkit-ok' "$tmp/webkit-default.out" \
    || fail "WebKitGTK default probe output is malformed"
for option in useJIT useBaselineJIT useDFGJIT useFTLJIT useRegExpJIT; do
    grep -q "${option}=false" "$tmp/webkit-default.err" \
        || fail "WebKitGTK default did not report ${option}=false"
    if grep -q "${option}=true" "$tmp/webkit-default.err"; then
        fail "WebKitGTK default also reported ${option}=true"
    fi
done

run_webkit_probe 1 "$tmp/webkit-optout.out" "$tmp/webkit-optout.err" \
    "$tmp/cache-optout" || fail "documented WebKitGTK per-launch opt-out failed"
grep -qxF 'noid-webkit-ok' "$tmp/webkit-optout.out" \
    || fail "WebKitGTK opt-out probe output is malformed"
grep -q 'useJIT=true' "$tmp/webkit-optout.err" \
    || fail "JavaScriptCoreUseJIT=1 did not restore the reviewed JIT path"
grep -q 'useBaselineJIT=true' "$tmp/webkit-optout.err" \
    || fail "WebKitGTK opt-out did not restore its baseline JIT"

echo "PASS  $TEST_NAME [$PASS_ID]: GJS/WebKitGTK JIT tiers are disabled by default, both local probes work, and explicit per-launch opt-outs restore the reviewed JIT paths"
