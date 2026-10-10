#!/usr/bin/env bash
# Prove against the candidate's own Firefox binary that noid-firefox-relax-fpp
# never relaxes below stock Firefox. While FPP is on, Firefox ignores its
# compiled baseline set and applies only privacy.fingerprintingProtection.
# overrides, so the relaxation must name that baseline set exactly. Launch two
# throwaway headless profiles -- the installed canonical user.js, and the same
# user.js plus the block the installed shared helper emits -- and read the
# enabled FPP and baseline target sets from nsIRFPService over Marionette.
#
# The per-site canvas exception is checked by behavior, because Firefox drops
# a granular override it does not accept without any message. A loopback page
# reads back its own canvas under local-only test host names: without the
# exception the readback must be placeholder data, with it exact on the listed
# registrable domain and its subdomain, and still placeholder data on another
# site, in another site's frame embedded in the listed one, and in the same
# profile once the block is removed again.
# Run once in the live candidate as the normal desktop user:
#   bash tests/pre-ship/16-fpp-relaxation-runtime.sh
set -euo pipefail
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin
umask 077

TEST_NAME=16-fpp-relaxation-runtime
fail() { echo "FAIL  $TEST_NAME: $*" >&2; exit 1; }

[ "$#" -eq 0 ] || {
    echo "usage: $0" >&2
    exit 2
}
[ "$(id -u)" -ne 0 ] || fail "run as the normal desktop user, not root"
for required_command in bash mktemp python3 rm stat; do
    command -v "$required_command" >/dev/null 2>&1 || \
        fail "required command missing: $required_command"
done

VENDOR_FIREFOX=/usr/lib64/firefox/firefox
BASE_USERJS=/usr/share/noid-firefox/user.js
PROFILE_HELPER=/usr/local/lib/noid-privacy/firefox-profiles.sh
for regular in "$VENDOR_FIREFOX" "$BASE_USERJS" "$PROFILE_HELPER"; do
    [ -f "$regular" ] && [ ! -L "$regular" ] || \
        fail "installed input is missing, non-regular or symlinked: $regular"
    [ "$(stat -c '%u' -- "$regular")" = 0 ] || \
        fail "installed input is not root-owned: $regular"
done

WORK=$(mktemp -d /var/tmp/noid-fpp-relaxation.XXXXXX) || \
    fail "cannot create private scratch directory"
trap 'rm -rf -- "$WORK"' EXIT

bash -c '. "$1"; noid_fpp_relaxation_block' _ "$PROFILE_HELPER" \
    > "$WORK/relaxation-block.js" || \
    fail "installed shared helper cannot emit the FPP relaxation block"
bash -c '. "$1"; noid_fpp_site_relaxation_block noid-canvas.test' _ \
    "$PROFILE_HELPER" > "$WORK/site-block.js" || \
    fail "installed shared helper cannot emit the per-site canvas block"

# The add path refuses inert entries through libpsl; prove the candidate ships
# a readable public suffix list and derives registrable domains from it.
registrable=$(bash -c '. "$1"; noid_fpp_site_registrable_domain studio.youtube.com' \
    _ "$PROFILE_HELPER") || fail "libpsl cannot derive a registrable domain"
[ "$registrable" = youtube.com ] || \
    fail "libpsl derived $registrable instead of youtube.com"
psl_rc=0
bash -c '. "$1"; noid_fpp_site_registrable_domain co.uk' _ "$PROFILE_HELPER" \
    >/dev/null || psl_rc=$?
[ "$psl_rc" = 1 ] || fail "libpsl did not report co.uk as a public suffix (rc $psl_rc)"

python3 - "$VENDOR_FIREFOX" "$BASE_USERJS" "$WORK/relaxation-block.js" \
        "$WORK" "$WORK/site-block.js" <<'FPP_RELAXATION_RUNTIME_PYEOF' || \
    fail "the FPP relaxations do not behave as specified in the shipped Firefox"
import http.server
import json
import os
import pathlib
import re
import signal
import socket
import subprocess
import sys
import threading
import time

firefox, base_userjs, block_path, work, site_block_path = sys.argv[1:6]
base = pathlib.Path(base_userjs).read_text(encoding="utf-8")
block = pathlib.Path(block_path).read_text(encoding="utf-8")
values = re.findall(
    r'^user_pref\("privacy\.fingerprintingProtection\.overrides", "([^"]*)"\);$',
    block, flags=re.MULTILINE)
if len(values) != 1:
    raise SystemExit("relaxation block must set the FPP target list exactly once")
relaxed_value = values[0]

SCRIPT = """
const service = Cc["@mozilla.org/rfp-service;1"].getService(Ci.nsIRFPService);
const words = set => [0, 1, 2, 3].map(index => set.getNth32BitSet(index));
return {
  fpp: words(service.enabledFingerprintingProtections),
  baseline: words(service.enabledFingerprintingProtectionsBaseline),
  fppEnabled: Services.prefs.getBoolPref("privacy.fingerprintingProtection"),
  rfpEnabled: Services.prefs.getBoolPref("privacy.resistFingerprinting"),
  overrides: Services.prefs.getStringPref(
    "privacy.fingerprintingProtection.overrides"),
  category: Services.prefs.getStringPref("browser.contentblocking.category"),
  version: Services.appinfo.version,
};
"""


def receive(sock):
    header = b""
    while not header.endswith(b":"):
        chunk = sock.recv(1)
        if not chunk:
            raise SystemExit("Marionette closed the connection")
        header += chunk
    length = int(header[:-1])
    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            raise SystemExit("Marionette closed the connection")
        payload += chunk
    return json.loads(payload)


def command(sock, message_id, name, parameters):
    data = json.dumps([0, message_id, name, parameters]).encode()
    sock.sendall(str(len(data)).encode() + b":" + data)
    reply = receive(sock)
    if reply[2] is not None:
        raise SystemExit(f"Marionette {name} failed: {reply[2]}")
    return reply[3]


def launch(label, userjs, probe, reuse=False):
    profile = pathlib.Path(work) / label
    profile.mkdir(mode=0o700, exist_ok=reuse)
    (profile / "user.js").write_text(
        userjs + 'user_pref("marionette.port", 0);\n', encoding="utf-8")
    process = subprocess.Popen(
        [firefox, "--marionette", "--remote-allow-system-access", "--headless",
         "--no-remote", "--profile", str(profile), "about:blank"],
        env=dict(os.environ, MOZ_HEADLESS="1"),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        port_file = profile / "MarionetteActivePort"
        deadline = time.monotonic() + 90
        while not (port_file.is_file() and port_file.read_text().strip()):
            if process.poll() is not None:
                raise SystemExit(f"{label}: Firefox exited before Marionette started")
            if time.monotonic() > deadline:
                raise SystemExit(f"{label}: Marionette did not start")
            time.sleep(0.2)
        port = int(port_file.read_text().strip())
        with socket.create_connection(("127.0.0.1", port), timeout=30) as sock:
            receive(sock)
            command(sock, 1, "WebDriver:NewSession", {})
            result = probe(sock)
            # A regular quit writes prefs.js, which the removal check needs.
            try:
                command(sock, 99, "Marionette:Quit", {"flags": ["eAttemptQuit"]})
            except (OSError, SystemExit):
                pass
        process.wait(timeout=30)
        return result
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()


def rfp_state(sock):
    command(sock, 2, "Marionette:SetContext", {"value": "chrome"})
    return command(sock, 3, "WebDriver:ExecuteScript",
                   {"script": SCRIPT, "args": []})["value"]


def measure(label, userjs):
    return launch(label, userjs, rfp_state)


def bits(words):
    return {index * 32 + bit for index, word in enumerate(words)
            for bit in range(32) if word >> bit & 1}


canonical = measure("canonical", base)
relaxed = measure("relaxed", base + block)
for label, state in (("canonical", canonical), ("relaxed", relaxed)):
    if state["category"] != "strict":
        raise SystemExit(f"{label}: ETP category is {state['category']}, not strict")
    if state["fppEnabled"] is not True or state["rfpEnabled"] is not False:
        raise SystemExit(f"{label}: FPP must be on and RFP off")
baseline = bits(canonical["baseline"])
if not baseline or bits(relaxed["baseline"]) != baseline:
    raise SystemExit("Firefox reports no stable baseline target set")
if not baseline < bits(canonical["fpp"]):
    raise SystemExit("canonical FPP targets are not a strict superset of the baseline")
if relaxed["overrides"] != relaxed_value:
    raise SystemExit("relaxed profile did not apply the emitted FPP target list")
if bits(relaxed["fpp"]) != baseline:
    missing = sorted(baseline - bits(relaxed["fpp"]))
    extra = sorted(bits(relaxed["fpp"]) - baseline)
    raise SystemExit(
        f"relaxed FPP targets differ from Firefox {relaxed['version']}'s "
        f"baseline: missing {missing}, extra {extra}")
print(f"Firefox {relaxed['version']}: relaxed FPP targets equal the baseline "
      f"set {sorted(baseline)}; canonical keeps {len(bits(canonical['fpp']))}")

# The page draws a fixed many-colour image and reads it back with its own
# document principal at load time, before any user input. The frame variant
# embeds the same probe from another site and reports through postMessage.
site_block = pathlib.Path(site_block_path).read_text(encoding="utf-8")
granular = re.findall(
    r'^user_pref\("privacy\.fingerprintingProtection\.granularOverrides", "([^\n]*)"\);$',
    site_block, flags=re.MULTILINE)
if len(granular) != 1:
    raise SystemExit("per-site block must set the granular overrides exactly once")
LISTED, SUBDOMAIN, OTHER = "noid-canvas.test", "www.noid-canvas.test", "other-canvas.test"
PROBE = """<!doctype html><meta charset="utf-8"><body><script>
const W = 64, H = 64, c = document.createElement("canvas");
c.width = W; c.height = H;
const g = c.getContext("2d"), image = g.createImageData(W, H), source = image.data;
for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
  const i = (y * W + x) * 4;
  source[i] = (x * 7 + y * 3) & 255; source[i + 1] = (x * x + y * 5) & 255;
  source[i + 2] = (x ^ y) & 255; source[i + 3] = 255;
}
g.putImageData(image, 0, 0);
const read = g.getImageData(0, 0, W, H).data;
let wrong = 0;
for (let k = 0; k < read.length; k++) if (read[k] !== source[k]) wrong++;
const report = wrong + "/" + read.length;
if (window.parent !== window) window.parent.postMessage(report, "*");
else document.documentElement.dataset.noidCanvas = report;
window.addEventListener("message", event => {
  document.documentElement.dataset.noidFrame = String(event.data);
});
</script>"""


class Probe(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        body = PROBE
        if self.path.startswith("/framed"):
            body += f'<iframe src="http://{OTHER}:{self.server.server_port}/probe"></iframe>'
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Probe)
threading.Thread(target=server.serve_forever, daemon=True).start()
PORT = server.server_port
HARNESS = (
    f'user_pref("network.dns.localDomains", "{LISTED},{SUBDOMAIN},{OTHER}");\n'
    'user_pref("dom.security.https_only_mode", false);\n')


def readback_once(sock, url, attribute):
    command(sock, 11, "WebDriver:Navigate", {"url": url})
    settle = time.monotonic() + 15
    while time.monotonic() < settle:
        value = command(sock, 12, "WebDriver:ExecuteScript", {
            "script": "return document.documentElement.dataset[arguments[0]] || null;",
            "args": [attribute]})["value"]
        if value is not None:
            wrong, total = (int(part) for part in value.split("/"))
            return wrong, total
        time.sleep(0.2)
    raise SystemExit(f"{url}: the canvas probe reported nothing")


def readback(sock, url, attribute, want_exact):
    """Firefox applies granular overrides only some time after startup. An
    expected-exact page is therefore reloaded until it reads back exactly, for
    at most 30 s; an expected-blocked page is reloaded for 20 s and reports
    its least distorted readback, so a late-applied leak cannot pass."""
    deadline = time.monotonic() + (30 if want_exact else 20)
    best = None
    while True:
        wrong, total = readback_once(sock, url, attribute)
        if best is None or wrong < best[0]:
            best = (wrong, total)
        if (want_exact and wrong == 0) or time.monotonic() > deadline:
            return best
        time.sleep(2)


def canvas_probe(cases):
    def probe(sock):
        return {name: readback(sock, url, attribute, exact)
                for name, url, attribute, exact in cases}
    return probe


def removal_probe(sock):
    # Read the effective preference and wait for Firefox's own import of the
    # granular overrides, which otherwise runs some time after startup, so a
    # stale value cannot hide behind that delay.
    command(sock, 40, "Marionette:SetContext", {"value": "chrome"})
    value = command(sock, 41, "WebDriver:ExecuteScript", {"script": """
      const service = Cc["@mozilla.org/fingerprinting-webcompat-service;1"]
        .getService(Ci.nsIFingerprintingWebCompatService);
      return Promise.resolve(service.init()).then(() =>
        Services.prefs.getStringPref(
          "privacy.fingerprintingProtection.granularOverrides"));""",
        "args": []})["value"]
    command(sock, 42, "Marionette:SetContext", {"value": "content"})
    state = canvas_probe([("listed", f"http://{LISTED}:{PORT}/probe",
                           "noidCanvas", False)])(sock)
    state["pref"] = value
    return state


def blocked(result):
    wrong, total = result
    return total > 0 and wrong * 2 > total


try:
    listed_url = f"http://{LISTED}:{PORT}/probe"
    control = launch("site-control", base + HARNESS, canvas_probe([
        ("listed", listed_url, "noidCanvas", False)]))
    excepted = launch("site-exception", base + HARNESS + site_block, canvas_probe([
        ("listed", listed_url, "noidCanvas", True),
        ("subdomain", f"http://{SUBDOMAIN}:{PORT}/probe", "noidCanvas", True),
        ("other", f"http://{OTHER}:{PORT}/probe", "noidCanvas", False),
        ("frame", f"http://{LISTED}:{PORT}/framed", "noidFrame", False)]))
    # Firefox keeps a user.js value in prefs.js once the line is gone, so only
    # the canonical base's empty assignment can remove an exception again. The
    # check proves nothing unless Firefox persisted the value first.
    persisted = (pathlib.Path(work) / "site-exception" / "prefs.js").read_text(
        encoding="utf-8")
    if granular[0] not in persisted:
        raise SystemExit("Firefox did not persist the site exception in prefs.js")
    removed = launch("site-exception", base + HARNESS, removal_probe, reuse=True)
finally:
    server.shutdown()
if not blocked(control["listed"]):
    raise SystemExit(f"canonical profile read its canvas back unprotected: {control}")
for name in ("listed", "subdomain"):
    if excepted[name][0] != 0:
        raise SystemExit(f"site exception did not apply on the {name} host: {excepted}")
for name in ("other", "frame"):
    if not blocked(excepted[name]):
        raise SystemExit(f"site exception leaked to the {name} context: {excepted}")
if removed["pref"] != "" or not blocked(removed["listed"]):
    raise SystemExit(f"removing the site block left the exception active: {removed}")
print(f"per-site canvas exception: exact on {LISTED} and {SUBDOMAIN}, placeholder "
      f"data on {OTHER}, in its frame and after removal; canonical control "
      f"{control['listed']}")
FPP_RELAXATION_RUNTIME_PYEOF

echo "PASS  $TEST_NAME"
