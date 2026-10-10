#!/usr/bin/python3
"""Exercise the source controller against private state and real probe PIDs.

No auditd configuration, reload, or desktop delivery is performed. The normal
root-owned health-file boundary uses native file metadata with only the owner
names substituted for rootless CI. A Python fixture parent stands in for auditd
in positive child-lifecycle cases; the real auditd-parent predicate is retained
in a separate rejection case. Argument records and process executables are real.
The real set_active() and boot-check verification run against private copies
of the plugin configuration and executable with only the SELinux label tools
and owner names doubled.
"""

import contextlib
import pathlib
import shlex
import subprocess
import sys
import tempfile
import time


STAT_AND_LABEL_DOUBLES = r'''
stat() {
    [ "$#" -eq 3 ] && [ "$1" = -c ] && [ "$2" = '%U:%G:%a:%h' ] || return 99
    case "$3" in
        "$HEALTH"|"$CONF"|"$PLUGIN")
            /usr/bin/stat -c 'root:root:%a:%h' "$3" 2>/dev/null ;;
        *) return 99 ;;
    esac
}
chown() { [ "$#" -eq 2 ] && [ "$1" = root:root ]; }
fixture_restorecon() { printf 'restorecon\n' >> "$CALLS"; }
fixture_matchpathcon() { return 0; }
'''


def main():
    source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
    functions = source.split("config_exact() {", 1)[1].split("reload_auditd() {", 1)[0]
    functions = "config_exact() {" + functions
    functions = functions.replace("/usr/bin/restorecon", "fixture_restorecon")
    functions = functions.replace("/usr/bin/matchpathcon", "fixture_matchpathcon")
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
        plugin.write_text(
            "#!/usr/bin/python3\nimport sys\nsys.stdin.read()\n", encoding="utf-8"
        )
        plugin.chmod(0o755)
        prefix = "set -euo pipefail\n" + "\n".join(
            f"{key}={shlex.quote(str(value))}"
            for key, value in {
                "HEALTH": health, "DEGRADED": degraded, "CONF": config,
                "PLUGIN": plugin, "CALLS": calls,
            }.items()
        ) + "\n"
        prefix += STAT_AND_LABEL_DOUBLES
        overrides = r'''
auditctl() {
    printf 'auditctl %s\n' "$*" >> "$CALLS"
}
set_active() {
    printf 'set_active=%s\n' "$1" >> "$CALLS"
    printf 'active = %s\n' "$1" > "$CONF"
}
systemctl() {
    case "$1" in
        is-system-running) printf '%s\n' "${FIX_SYSTEM_STATE:-running}" ;;
        is-enabled) [ "${FIX_UNIT_ENABLED:-no}" = yes ] ;;
        *) return 99 ;;
    esac
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
            code = (prefix + (functions if native_parent else positive_functions)
                    + overrides + tail)
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
        # `on` applies the same executable verification as boot-check and
        # leaves the plugin inactive when it fails.
        plugin.chmod(0o775)
        calls.write_text("")
        check("on refuses a writable plugin executable", "ACTION=on\n" + dispatch, 1)
        assert calls.read_text() == "set_active=no\nauditctl --signal reload\n"
        plugin.chmod(0o755)
        calls.write_text("")
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

        # A plain stop during shutdown keeps an enabled opt-in untouched; a
        # stopping system with a disabled unit and a live stop both retire it.
        calls.write_text("")
        check("shutdown stop keeps the enabled opt-in",
              "ACTION=off\nFIX_SYSTEM_STATE=stopping\nFIX_UNIT_ENABLED=yes\n" + dispatch)
        assert calls.read_text() == ""
        check("shutdown stop of a disabled unit retires the plugin",
              "ACTION=off\nFIX_SYSTEM_STATE=stopping\nFIX_UNIT_ENABLED=no\n" + dispatch)
        assert calls.read_text() == "set_active=no\nreload\n"
        calls.write_text("")
        check("explicit stop while running retires the plugin",
              "ACTION=off\nFIX_SYSTEM_STATE=running\nFIX_UNIT_ENABLED=yes\n" + dispatch)
        assert calls.read_text() == "set_active=no\nreload\n"

        checked += check_set_active(source, root)
        checked += check_boot_check(source, root)
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


def check_set_active(source, root):
    """An unchanged value keeps the file inode; a change replaces it atomically."""
    body = source.split("config_exact() {", 1)[1].split("plugin_pid() {", 1)[0]
    body = "config_exact() {" + body
    body = body.replace("/usr/bin/restorecon", "fixture_restorecon")
    body = body.replace("/usr/bin/matchpathcon", "fixture_matchpathcon")
    guard_start = body.index("    if grep -qxF \"active = $value\" \"$CONF\"; then")
    guard = body[guard_start:body.index("    awk -v value=", guard_start)]
    assert "return 0" in guard and "fixture_restorecon" in guard
    plugin_dir = root / "plugins.d"
    plugin_dir.mkdir()
    config = plugin_dir / "noid-notify.conf"
    calls = root / "set-active-calls"
    prefix = "set -euo pipefail\n" + f"CONF={shlex.quote(str(config))}\n" + \
        f"CALLS={shlex.quote(str(calls))}\n" + \
        "PLUGIN=/usr/local/bin/audit-notify.sh\nHEALTH=/nonexistent\n" + \
        STAT_AND_LABEL_DOUBLES

    def run(function_body, value):
        config.write_text(
            "active = yes\npath = /usr/local/bin/audit-notify.sh\n"
            "type = always\nformat = string\n", encoding="utf-8")
        config.chmod(0o640)
        calls.write_text("")
        before = config.stat().st_ino
        result = subprocess.run(
            ["/usr/bin/bash", "-c", prefix + function_body + f"set_active {value}\n"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0, (value, result.stdout, result.stderr)
        assert sorted(p.name for p in plugin_dir.iterdir()) == ["noid-notify.conf"]
        return before, config.stat().st_ino

    before, after = run(body, "yes")
    assert before == after, "unchanged plugin setting was republished"
    assert calls.read_text() == "restorecon\n"
    before, after = run(body, "no")
    assert before != after, "changed plugin setting was not replaced atomically"
    assert "active = no\n" in config.read_text(encoding="utf-8")
    assert oct(config.stat().st_mode & 0o777) == oct(0o640)
    # Negative control: without the unchanged-value guard the same call
    # replaces the inode, so the first assertion above is discriminating.
    before, after = run(body.replace(guard, ""), "yes")
    assert before != after
    return 3


def check_boot_check(source, root):
    """Valid state is never rewritten; any verification failure restores `no`."""
    functions = source.split("config_exact() {", 1)[1].split("plugin_pid() {", 1)[0]
    functions = "config_exact() {" + functions
    functions = functions.replace("/usr/bin/restorecon", "fixture_restorecon")
    functions = functions.replace("/usr/bin/matchpathcon", "fixture_matchpathcon")
    dispatch = 'case "$ACTION" in' + source.split('case "$ACTION" in', 1)[1]
    assert "    boot-check)" in dispatch
    state = root / "boot-check"
    state.mkdir()
    plugin_dir = state / "plugins.d"
    plugin_dir.mkdir()
    config = plugin_dir / "noid-notify.conf"
    plugin = state / "audit-notify.sh"
    calls = state / "calls"
    prefix = "set -euo pipefail\n" + "\n".join(
        f"{key}={shlex.quote(str(value))}"
        for key, value in {
            "CONF": config, "PLUGIN": plugin, "CALLS": calls,
            "HEALTH": state / "health", "DEGRADED": state / "degraded",
        }.items()
    ) + "\n" + STAT_AND_LABEL_DOUBLES
    canonical_inactive = (
        f"active = no\npath = {plugin}\ntype = always\nformat = string\n"
    )

    def reset(active="yes"):
        for entry in plugin_dir.iterdir():
            entry.unlink()
        config.write_text(
            f"active = {active}\npath = {plugin}\ntype = always\n"
            "format = string\n", encoding="utf-8")
        config.chmod(0o640)
        if plugin.is_symlink() or plugin.exists():
            plugin.unlink()
        plugin.write_text("#!/usr/bin/python3\nimport sys\n", encoding="utf-8")
        plugin.chmod(0o755)
        calls.write_text("")

    def boot_check():
        result = subprocess.run(
            ["/usr/bin/bash", "-c", prefix + functions + "ACTION=boot-check\n" + dispatch],
            capture_output=True, text=True, timeout=10,
        )
        leftovers = sorted(p.name for p in plugin_dir.iterdir() if p.name != "noid-notify.conf")
        assert leftovers == [], leftovers
        return result.returncode

    checked = 0
    for active in ("no", "yes"):
        reset(active)
        before = config.stat().st_ino
        assert boot_check() == 0, f"valid active={active} configuration was refused"
        assert config.stat().st_ino == before, "valid configuration was rewritten"
        assert calls.read_text() == ""
        checked += 1

    tamperings = {
        "writable plugin executable": lambda: plugin.chmod(0o775),
        "symlinked plugin executable": lambda: (
            plugin.rename(state / "real-plugin"), plugin.symlink_to(state / "real-plugin")),
        "foreign plugin interpreter": lambda: plugin.write_text(
            "#!/bin/sh\nexit 0\n", encoding="utf-8"),
        "missing plugin executable": lambda: plugin.unlink(),
        "world-writable configuration": lambda: config.chmod(0o666),
        "redirected plugin path": lambda: config.write_text(
            "active = yes\npath = /var/tmp/other\ntype = always\nformat = string\n",
            encoding="utf-8"),
        "duplicate activation lines": lambda: config.write_text(
            f"active = no\nactive = yes\npath = {plugin}\ntype = always\n"
            "format = string\n", encoding="utf-8"),
        "missing configuration": lambda: config.unlink(),
    }
    for label, tamper in tamperings.items():
        reset("yes")
        tamper()
        assert boot_check() == 1, f"boot-check accepted a {label}"
        assert config.read_text(encoding="utf-8") == canonical_inactive, label
        assert oct(config.stat().st_mode & 0o777) == oct(0o640), label
        assert not config.is_symlink(), label
        if (state / "real-plugin").exists():
            (state / "real-plugin").unlink()
        checked += 1
    return checked


if __name__ == "__main__":
    main()
