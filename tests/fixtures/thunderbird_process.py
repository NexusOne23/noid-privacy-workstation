#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Native process-query failures and child lifecycle for the actual M35 guard."""
import ctypes
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(sys.argv.pop(1)).read_text(encoding="utf-8")
START = SOURCE.index("thunderbird_process_active() {\n")
END = SOURCE.index("\n}\n", START) + 3
GUARD = SOURCE[START:END]

WRAPPERS = r'''
case "$TB_QUERY_MODE" in
    failed-uid) id() { return 1; } ;;
    partial-uid) id() { printf '%s\n' 1000; return 2; } ;;
    invalid-uid) id() { printf '%s\n' invalid; } ;;
esac
pgrep() {
    case "$TB_QUERY_MODE" in
        native-live|native-zombie|native-absent)
            /usr/bin/pgrep -p "$TB_CHILD_PID" -x "${@: -1}" ;;
        native-error) /usr/bin/pgrep --noid-fixture-invalid-option ;;
        missing-command) "$TB_MISSING_COMMAND" ;;
        partial-error) printf '%s\n' "$BASHPID"; return 2 ;;
        inconsistent-no-match) printf '%s\n' "$BASHPID"; return 1 ;;
        empty-success) return 0 ;;
        invalid-pid) printf '%s\n' invalid ;;
        zero-pid) printf '%s\n' 0 ;;
        negative-pid) printf '%s\n' -1 ;;
        second-name-error)
            [ "${@: -1}" != thunderbird ] || return 1
            return 2 ;;
        failed-uid|partial-uid|invalid-uid) return 1 ;;
        *) printf '%s\n' "$BASHPID" ;;
    esac
}
ps() {
    case "$TB_QUERY_MODE" in
        native-live|native-zombie|native-absent) /usr/bin/ps "$@" ;;
        native-ps-error) /usr/bin/ps --noid-fixture-invalid-option ;;
        missing-ps) "$TB_MISSING_COMMAND" ;;
        dead-partial-error) printf '%s\n' Z; return 2 ;;
        dead-inconsistent-no-match) printf '%s\n' Z; return 1 ;;
        empty-ps) return 0 ;;
        multiple-states) printf '%s\n' Z S ;;
        invalid-dead-state) printf '%s\n' Zinvalid ;;
        padded-dead) printf ' \tZ \t\n' ;;
        transient-dead) printf '%s\n' X ;;
        lower-dead) printf '%s\n' x ;;
        *) /usr/bin/ps "$@" ;;
    esac
}
if thunderbird_process_active; then exit 0; else exit 1; fi
'''


class ThunderbirdProcessTest(unittest.TestCase):
    def run_guard(self, mode, pid=""):
        with tempfile.TemporaryDirectory(prefix="noid-tb-process.", dir="/var/tmp") as raw:
            env = os.environ.copy()
            env.update(TB_QUERY_MODE=mode, TB_CHILD_PID=str(pid),
                       TB_MISSING_COMMAND=str(Path(raw) / "missing-command"))
            result = subprocess.run(["bash", "-c", "set -euo pipefail\n" + GUARD + WRAPPERS],
                                    env=env, capture_output=True, timeout=10, check=False)
            self.assertIn(result.returncode, (0, 1), "guard failed outside its boolean contract")
            return result.returncode

    def test_query_failures_block(self):
        for mode in ("native-error", "missing-command", "partial-error",
                     "inconsistent-no-match", "empty-success", "invalid-pid",
                     "zero-pid", "negative-pid", "second-name-error",
                     "failed-uid", "partial-uid", "invalid-uid"):
            with self.subTest(mode=mode):
                self.assertEqual(self.run_guard(mode), 0)

    def test_state_failures_block(self):
        for mode in ("native-ps-error", "missing-ps", "dead-partial-error",
                     "dead-inconsistent-no-match", "empty-ps", "multiple-states",
                     "invalid-dead-state"):
            with self.subTest(mode=mode):
                self.assertEqual(self.run_guard(mode), 0)

    def test_dead_state_format(self):
        for mode in ("padded-dead", "transient-dead", "lower-dead"):
            with self.subTest(mode=mode):
                self.assertEqual(self.run_guard(mode), 1)

    def test_native_lifecycle(self):
        # Only owned child tasks are selected; no user browser is launched/read.
        for name in (b"thunderbird", b"thunderbird-bin"):
            with self.subTest(name=name):
                ready_r, ready_w = os.pipe()
                release_r, release_w = os.pipe()
                child = os.fork()
                if child == 0:
                    os.close(ready_r)
                    os.close(release_w)
                    try:
                        if ctypes.CDLL(None).prctl(15, ctypes.c_char_p(name), 0, 0, 0):
                            os._exit(2)
                        os.write(ready_w, b"1")
                        os.close(ready_w)
                        os.read(release_r, 1)
                        os._exit(0)
                    except BaseException:
                        os._exit(3)
                os.close(ready_w)
                os.close(release_r)
                try:
                    self.assertEqual(os.read(ready_r, 1), b"1")
                    self.assertEqual(self.run_guard("native-live", child), 0)
                    os.write(release_w, b"1")
                    status = Path(f"/proc/{child}/status")
                    for _ in range(100):
                        state = [line for line in status.read_text().splitlines()
                                 if line.startswith("State:")]
                        if state and state[0].split()[1] == "Z":
                            break
                        time.sleep(0.01)
                    else:
                        self.fail("owned child did not reach zombie state")
                    self.assertEqual(self.run_guard("native-zombie", child), 1)
                finally:
                    os.close(ready_r)
                    os.close(release_w)
                    os.waitpid(child, 0)
                self.assertEqual(self.run_guard("native-absent", child), 1)

    def run_cli(self, mode, action, after_lock=False):
        with tempfile.TemporaryDirectory(prefix="noid-tb-cli.", dir="/var/tmp") as raw:
            root = Path(raw)
            home = root / "home"
            profiles = home / ".thunderbird"
            state = root / "state"
            binary = root / "bin"
            for directory in (home, profiles, state, binary):
                directory.mkdir(mode=0o700)
            canonical = root / "canonical.js"
            canonical.write_text('user_pref("_noid.thunderbird.hardening.version", "fixture");\n')
            canonical.chmod(0o644)
            (profiles / "profiles.ini").write_text(
                "[Profile0]\nName=one\nIsRelative=1\nPath=one.default\n"
                "[Profile1]\nName=two\nIsRelative=1\nPath=two.default\n")
            for name in ("one", "two"):
                directory = profiles / (name + ".default")
                directory.mkdir(mode=0o700)
                (directory / "user.js").write_text(
                    'user_pref("_noid.thunderbird.hardening.version", "old");\n')
                (directory / "user.js").chmod(0o600)
                (directory / "prefs.js").write_text("// existing preferences\n")
            opener = "<<'HARDEN_PROFILE_SH_EOF'\n"
            helper = SOURCE.split(opener)[1].split("\nHARDEN_PROFILE_SH_EOF\n")[0] + "\n"
            replacements = {
                r"^NOID_USERJS=.*$": 'NOID_USERJS="' + str(canonical) + '"',
                r"^PASSWD_HOME=.*$": 'PASSWD_HOME="' + str(home) + '"',
                r"^PATH=.*$": "PATH=" + str(binary) + ":/usr/sbin:/usr/bin:/sbin:/bin",
            }
            for pattern, value in replacements.items():
                helper, count = re.subn(pattern, value, helper, flags=re.MULTILINE)
                self.assertEqual(count, 1)
            self.assertEqual(helper.count("0:0:644:1"), 1)
            helper = helper.replace("0:0:644:1", f"{os.getuid()}:{os.getgid()}:644:1")
            executable = root / "harden.sh"
            executable.write_text(helper)
            functions = WRAPPERS.split("if thunderbird_process_active;")[0]
            for name in ("pgrep", "ps"):
                wrapper = binary / name
                wrapper.write_text(
                    '#!/bin/bash\nset -euo pipefail\n'
                    'if [ -f "$TB_MODE_FILE" ]; then TB_QUERY_MODE=$(cat "$TB_MODE_FILE"); fi\n'
                    + functions + name + ' "$@"\n')
                wrapper.chmod(0o700)
            (binary / "matchpathcon").symlink_to("/usr/bin/true")
            (binary / "flock").write_text(
                '#!/bin/bash\nset -euo pipefail\n/usr/bin/flock "$@"\n'
                'if [ "$TB_AFTER_LOCK_ERROR" = 1 ]; then '
                'printf "%s\\n" native-error > "$TB_MODE_FILE"; fi\n')
            (binary / "flock").chmod(0o700)
            env = os.environ.copy()
            env.update(HOME=str(home), XDG_STATE_HOME=str(state),
                       TB_QUERY_MODE=mode, TB_CHILD_PID=str(os.getpid()),
                       TB_MISSING_COMMAND=str(root / "missing-command"),
                       TB_MODE_FILE=str(root / "mode"),
                       TB_AFTER_LOCK_ERROR="1" if after_lock else "0")

            def snapshot():
                return {str(p.relative_to(profiles)):
                        (p.stat().st_mode, p.read_bytes() if p.is_file() else None)
                        for p in profiles.rglob("*")}

            before = snapshot()
            result = subprocess.run(["bash", str(executable), *action], env=env,
                                    capture_output=True, timeout=10, check=False)
            return result.returncode, before == snapshot()

    def test_cli_preserves_profiles_when_query_fails(self):
        if "<<'HARDEN_PROFILE_SH_EOF'\n" not in SOURCE:
            self.fail("full M35 source is required for profile-preservation cases")
        actions = (("one",), ("--all",), ("--automatic",),
                   ("--remove", "one"), ("--remove", "--all"))
        for action in actions:
            with self.subTest(action=action, mode="positive-native-no-match"):
                self.assertEqual(self.run_cli("native-absent", action), (0, False))
            for mode in ("native-error", "missing-command", "partial-error",
                         "empty-success", "second-name-error", "native-ps-error",
                         "dead-partial-error", "empty-ps", "multiple-states",
                         "invalid-dead-state"):
                with self.subTest(action=action, mode=mode):
                    self.assertEqual(self.run_cli(mode, action), (75, True))
            with self.subTest(action=action, mode="query-failed-after-lock"):
                self.assertEqual(self.run_cli("native-absent", action, True), (75, True))


if __name__ == "__main__":
    unittest.main()
