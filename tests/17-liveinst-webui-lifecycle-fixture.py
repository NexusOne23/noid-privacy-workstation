#!/usr/bin/python3
"""Behavioral fixture for the M17 Live-installer WebUI lifecycle helper."""

from __future__ import annotations

import importlib.util
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

# The helper is imported directly from the repository source path. Keep the
# fixture read-only with respect to that public source surface.
sys.dont_write_bytecode = True


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def load_helper(path: Path):
    spec = importlib.util.spec_from_file_location("noid_liveinst_lifecycle", path)
    require(spec is not None and spec.loader is not None, "cannot load helper spec")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def main(argv: list[str]) -> int:
    require(len(argv) == 1, "Usage: 17-liveinst-webui-lifecycle-fixture.py HELPER")
    helper_path = Path(argv[0]).resolve(strict=True)
    helper = load_helper(helper_path)

    with tempfile.TemporaryDirectory(prefix="noid-liveinst-lifecycle.", dir="/var/tmp") as raw:
        root = Path(raw)
        cmdline = root / "cmdline"
        anaconda = root / "anaconda"
        anaconda.mkdir(mode=0o700)
        pid_file = anaconda / "webui_script.pid"
        log_file = root / "systemctl.log"
        state_file = root / "state"
        state_file.write_text("inactive\n", encoding="utf-8")

        fake_systemctl = root / "systemctl"
        write_executable(
            fake_systemctl,
            """#!/bin/sh
set -eu
printf '%s\\n' "$1" >> "$NOID_FIXTURE_SYSTEMCTL_LOG"
case "$1" in
  stop)
    [ "${NOID_FIXTURE_STOP_FAIL:-0}" = 0 ] || exit 9
    printf 'inactive\\n' > "$NOID_FIXTURE_STATE"
    ;;
  show)
    [ "$(cat "$NOID_FIXTURE_STATE")" = inactive ] || exit 8
    printf 'ActiveState=inactive\\nSubState=dead\\nMainPID=0\\n'
    ;;
  *) exit 7 ;;
esac
""",
        )

        webui_script = root / "webui-desktop"
        write_executable(
            webui_script,
            """#!/usr/bin/bash
trap 'exit 0' TERM INT
while :; do
    /usr/bin/sleep 1
done
""",
        )

        helper.CMDLINE = cmdline
        helper.PID_FILE = pid_file
        helper.PROC_ROOT = Path("/proc")
        helper.SYSTEMCTL = str(fake_systemctl)
        helper.WEBUI_SCRIPT = str(webui_script)
        helper.REQUIRED_UID = os.getuid()
        helper.REQUIRED_GID = os.getgid()
        helper.PIDFILE_ATTEMPTS = 3
        helper.PIDFILE_RETRY_SECONDS = 0.01
        os.environ["NOID_FIXTURE_SYSTEMCTL_LOG"] = str(log_file)
        os.environ["NOID_FIXTURE_STATE"] = str(state_file)

        # An installed root must never stop the Live-only helper service.
        cmdline.write_text("quiet root=UUID=fixture\n", encoding="utf-8")
        require(helper.main([]) == 0, "non-Live root was rejected")
        require(not log_file.exists(), "non-Live root invoked systemctl")

        # The exact bash + webui-desktop -t live process must remain bound
        # until that same process instance exits, then stop and verify the unit.
        cmdline.write_text("quiet rd.live.image root=live:CDLABEL=fixture\n", encoding="utf-8")
        webui = subprocess.Popen(
            ["/usr/bin/bash", str(webui_script), "-t", "live"],
            start_new_session=True,
        )
        try:
            pid_file.write_text(f"{webui.pid}\n", encoding="ascii")
            pid_file.chmod(0o640)
            require(
                helper._read_pid_file() == webui.pid,
                "safe umask-0027 PID-file mode was rejected",
            )
            pid_file.chmod(0o664)
            try:
                helper._read_pid_file()
            except helper.LifecycleError:
                pass
            else:
                raise AssertionError("group-writable PID file was accepted")
            pid_file.chmod(0o644)
            result: list[int] = []
            worker = threading.Thread(
                target=lambda: result.append(helper.main([])), daemon=True
            )
            worker.start()
            time.sleep(0.2)
            require(worker.is_alive(), "pidfd watcher returned before WebUI exit")
            os.killpg(webui.pid, signal.SIGTERM)
            webui.wait(timeout=5)
            worker.join(timeout=5)
            require(not worker.is_alive(), "pidfd watcher did not observe WebUI exit")
            require(result == [0], f"valid lifecycle returned {result!r}")
            require(
                log_file.read_text(encoding="utf-8").splitlines() == ["stop", "show"],
                "valid lifecycle did not perform one exact stop/postcondition pair",
            )
        finally:
            if webui.poll() is None:
                os.killpg(webui.pid, signal.SIGKILL)
                webui.wait(timeout=5)

        # A PID naming any other process must never be waited on. It is a
        # visible failure, but still performs the narrow fail-closed unit stop.
        log_file.unlink()
        unrelated = subprocess.Popen(["/usr/bin/sleep", "30"], start_new_session=True)
        try:
            pid_file.write_text(f"{unrelated.pid}\n", encoding="ascii")
            require(helper.main([]) == 1, "unrelated PID was accepted as Fedora WebUI")
            require(unrelated.poll() is None, "helper killed an unrelated process")
            require(
                log_file.read_text(encoding="utf-8").splitlines() == ["stop", "show"],
                "identity failure did not perform the exact fail-closed service stop",
            )
        finally:
            os.killpg(unrelated.pid, signal.SIGKILL)
            unrelated.wait(timeout=5)

        # File-type validation must happen after a nonblocking open; otherwise
        # a damaged root-owned FIFO lifecycle record can stall the companion
        # before its narrow fail-closed service stop.
        pid_file.unlink()
        os.mkfifo(pid_file, mode=0o600)
        fifo_started = time.monotonic()
        try:
            helper._read_pid_file()
        except helper.LifecycleError:
            pass
        else:
            raise AssertionError("FIFO PID record was accepted")
        require(
            time.monotonic() - fifo_started < 0.5,
            "FIFO PID record blocked lifecycle validation",
        )

        # A symlinked PID record is rejected without dereference and cannot
        # suppress the same bounded service cleanup.
        log_file.unlink()
        target = root / "attacker-pid"
        target.write_text("2\n", encoding="ascii")
        pid_file.unlink()
        pid_file.symlink_to(target)
        require(helper.main([]) == 1, "symlinked PID record was accepted")
        require(
            log_file.read_text(encoding="utf-8").splitlines() == ["stop", "show"],
            "unsafe PID record suppressed the fail-closed service stop",
        )

        # A failed systemd stop must remain a failure rather than publishing a
        # false cleanup result.
        log_file.unlink()
        os.environ["NOID_FIXTURE_STOP_FAIL"] = "1"
        require(helper.main([]) == 1, "failed service stop was hidden")
        require(log_file.read_text(encoding="utf-8").splitlines() == ["stop"],
                "failed service stop used an unexpected command sequence")

    print("PASS  17-liveinst-webui-lifecycle-fixture")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
