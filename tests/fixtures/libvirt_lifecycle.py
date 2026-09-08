#!/usr/bin/env python3
"""Exercise the candidate gate's actual probe lifecycle without starting VMs."""
import pathlib
import re
import subprocess
import sys
import tempfile

source = pathlib.Path(sys.argv[1]).read_text()
setup = re.search(r"^workdir=\$\(mktemp .*?(?=^write_probe_xml\(\))", source, re.M | re.S)
sequence = re.search(r"^system_xml=\$workdir/system\.xml\n.*", source, re.M | re.S)
assert setup and sequence, "candidate lifecycle extraction failed"

# Only libvirt transport, process inspection and XML preparation are doubled.
# Creation flags, pre-existing-domain checks, traps and teardown are production.
harness = r'''
set -euo pipefail
export LC_ALL=C
TEST_NAME=libvirt-lifecycle-fixture
PASS_ID=fixture
fail() { echo "FAIL: $*" >&2; exit 1; }
'''+setup.group()+r'''
state=$1
mode=$2
mock_virsh() {
    local scope=$1 action=$2
    case "$action" in
        dominfo) test -f "$state/$scope" ;;
        create)
            test ! -e "$state/$scope" || return 1
            : > "$state/$scope"
            printf 'create %s\n' "$scope" >> "$state/calls"
            ;;
        domstate) printf 'running\n' ;;
        destroy)
            test -f "$state/$scope" || return 1
            rm -- "$state/$scope"
            printf 'destroy %s\n' "$scope" >> "$state/calls"
            ;;
        *) return 2 ;;
    esac
}
system_virsh() { mock_virsh system "$@"; }
session_virsh() { mock_virsh session "$@"; }
write_probe_xml() { :; }
sudo() { printf '4242\n'; }
find_session_qemu_pid() { printf '4243\n'; }
check_qemu_process() {
    case "$mode:$1" in
        core-failure:system|session-failure:session) fail 'injected core-limit failure' ;;
        interrupted:system) kill -TERM "$BASHPID" ;;
    esac
}
if [[ $mode == system-collision ]]; then : > "$state/system"; fi
if [[ $mode == session-collision ]]; then : > "$state/session"; fi
'''+sequence.group()

cases = {
    "success": (0, ["create system", "destroy system", "create session", "destroy session"], []),
    "system-collision": (1, [], ["system"]),
    "session-collision": (1, [], ["session"]),
    "core-failure": (1, ["create system", "destroy system"], []),
    "session-failure": (1, ["create system", "destroy system", "create session", "destroy session"], []),
    "interrupted": (143, ["create system", "destroy system"], []),
}
failed = 0
with tempfile.TemporaryDirectory(prefix="noid-libvirt-lifecycle-", dir="/var/tmp") as temporary:
    root = pathlib.Path(temporary)
    script = root / "fixture.sh"
    script.write_text(harness)
    for mode, (expected_rc, expected_calls, survivors) in cases.items():
        state = root / mode
        state.mkdir()
        (state / "calls").touch()
        result = subprocess.run(["bash", str(script), str(state), mode],
                                capture_output=True, text=True, timeout=10)
        calls = (state / "calls").read_text().splitlines()
        remaining = sorted(s for s in ("system", "session") if (state / s).exists())
        good = (result.returncode, calls, remaining) == (expected_rc, expected_calls, survivors)
        print(f"{'PASS' if good else 'FAIL'} {mode}: rc={result.returncode}, calls={calls}, remaining={remaining}")
        failed += not good
sys.exit(bool(failed))
