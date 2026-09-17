#!/usr/bin/python3
"""Exercise the source controller against private state and real probe PIDs.

No auditd configuration, reload, or desktop delivery is performed. The normal
root-owned health-file boundary uses native file metadata with only the owner
names substituted for rootless CI. A Python fixture parent stands in for auditd
in positive child-lifecycle cases; the real auditd-parent predicate is retained
in a separate rejection case. Argument records and process executables are real.
"""

import contextlib
import pathlib
import shlex
import subprocess
import sys
import tempfile
import time


def main():
    source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
    functions = source.split("plugin_pid() {", 1)[1].split("reload_auditd() {", 1)[0]
    functions = "plugin_pid() {" + functions
    dispatch = source.split('case "$ACTION" in', 1)[1]
    dispatch = 'case "$ACTION" in' + dispatch
    assert '[ "/proc/$parent/exe" -ef /usr/sbin/auditd ]' in functions
    positive_functions = functions.replace(
        '[ "/proc/$parent/exe" -ef /usr/sbin/auditd ]',
        '[ "/proc/$parent/exe" -ef /usr/bin/python3 ]',
    )
    checked = 0
    with tempfile.TemporaryDirectory(prefix="noid-audit-controller-") as temporary:
        root = pathlib.Path(temporary)
        health, degraded, config, calls = [
            root / name for name in ("health", "degraded", "config", "calls")
        ]
        plugin = root / "probe.py"
        plugin.write_text("import sys\nsys.stdin.read()\n", encoding="utf-8")
        prefix = "set -euo pipefail\n" + "\n".join(
            f"{key}={shlex.quote(str(value))}"
            for key, value in {
                "HEALTH": health, "DEGRADED": degraded, "CONF": config,
                "PLUGIN": plugin, "CALLS": calls,
            }.items()
        ) + "\n"
        prefix += r'''
stat() {
    [ "$#" -eq 3 ] && [ "$1" = -c ] \
        && [ "$2" = '%U:%G:%a:%h' ] && [ "$3" = "$HEALTH" ] || return 99
    /usr/bin/stat -c 'root:root:%a:%h' "$HEALTH"
}
set_active() {
    printf 'set_active=%s\n' "$1" >> "$CALLS"
    printf 'active = %s\n' "$1" > "$CONF"
}
reload_auditd() {
    printf 'reload\n' >> "$CALLS"
    if [ "${ACTION:-}" = on ]; then
        printf 'pid=%s\nstate=running\n' "$PROBE_PID" > "$HEALTH"
        chmod 0640 "$HEALTH"
    elif [ "${STOP_PROBE:-no}" = yes ]; then
        kill "$PROBE_PID"
    fi
}
'''

        def check(label, tail, expected=0, native_parent=False):
            nonlocal checked
            code = prefix + (functions if native_parent else positive_functions) + tail
            result = subprocess.run(
                ["/usr/bin/bash", "-c", code], capture_output=True, text=True,
                timeout=22,
            )
            assert result.returncode == expected, (
                label, result.returncode, result.stdout, result.stderr,
            )
            checked += 1

        def write_health(pid, extra="", state="running"):
            health.write_text(f"pid={pid}\nstate={state}\n{extra}", encoding="utf-8")
            health.chmod(0o640)

        @contextlib.contextmanager
        def process(arguments):
            child = subprocess.Popen(
                ["/usr/bin/python3", *arguments], stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            try:
                # Wait for exec before reading native procfs argument records.
                for _ in range(100):
                    if pathlib.Path(f"/proc/{child.pid}/cmdline").read_bytes().split(b"\0")[1:-1] == [
                        str(arg).encode() for arg in arguments
                    ]:
                        break
                    time.sleep(0.01)
                else:
                    raise AssertionError("probe did not reach its expected exec")
                yield child
            finally:
                if child.poll() is None:
                    child.terminate()
                child.wait(timeout=5)
                child.stdin.close()

        config.write_text("active = no\n", encoding="utf-8")
        check("no health", "plugin_running\n", 1)
        check("off before first start", "ACTION=off\n" + dispatch)
        assert calls.read_text() == "set_active=no\nreload\n"
        with process([str(plugin)]) as child:
            write_health(child.pid)
            check("exact live script and parent", "plugin_running\n")
            check("manual script is not auditd child", "plugin_running\n", 1, True)
            write_health(child.pid, extra=f"pid={child.pid}\n")
            check("duplicate pid", "plugin_running\n", 1)
            write_health(0)
            check("zero pid", "plugin_running\n", 1)
            write_health(child.pid, extra="state=stopped\n")
            check("ambiguous state", "plugin_running\n", 1)
            write_health(child.pid, state="stopped")
            check("stopped health", "plugin_running\n", 1)
            write_health(child.pid)
            health.chmod(0o666)
            check("writable health", "plugin_running\n", 1)
            health.unlink()
            target = root / "linked-health"
            target.write_text(f"pid={child.pid}\nstate=running\n")
            target.chmod(0o640)
            health.symlink_to(target)
            check("symlinked health", "plugin_running\n", 1)
            health.unlink()
            write_health(child.pid)
            degraded.write_text("status=degraded\n")
            before = health.read_bytes()
            calls.write_text("")
            check("refused activation", "ACTION=on\n" + dispatch, 1)
            assert health.read_bytes() == before and calls.read_text() == ""
            degraded.unlink()
            check("normal activation", f"ACTION=on\nPROBE_PID={child.pid}\n" + dispatch)
            assert calls.read_text() == "set_active=yes\nreload\n"
            calls.write_text("")
            check("normal shutdown", f"ACTION=off\nSTOP_PROBE=yes\nPROBE_PID={child.pid}\n" + dispatch)
            assert calls.read_text() == "set_active=no\nreload\n"
        check("dead recorded pid", "plugin_running\n", 1)
        for label, argument in [
            ("unrelated argument", str(plugin)),
            ("newline in argument", f"prefix\n{plugin}\nsuffix"),
        ]:
            with process(["-c", "import sys; sys.stdin.read()", argument]) as child:
                write_health(child.pid)
                check(label, "plugin_running\n", 1)
                calls.write_text("")
                check(label + " during shutdown", "ACTION=off\n" + dispatch)
                assert calls.read_text() == "set_active=no\nreload\n"
                assert child.poll() is None
    print(f"PASS: {checked} isolated audit-controller lifecycle cases")


if __name__ == "__main__":
    main()
