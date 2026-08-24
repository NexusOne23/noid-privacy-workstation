#!/usr/bin/python3
"""Bind Fedora's Live-installer WebUI service to the exact WebUI process."""

from __future__ import annotations

import os
import re
import select
import stat
import subprocess
import sys
import time
from pathlib import Path


CMDLINE = Path("/proc/cmdline")
PID_FILE = Path("/run/anaconda/webui_script.pid")
PROC_ROOT = Path("/proc")
SYSTEMCTL = "/usr/bin/systemctl"
SERVICE = "webui-cockpit-ws.service"
WEBUI_SCRIPT = "/usr/libexec/anaconda/webui-desktop"
REQUIRED_UID = 0
REQUIRED_GID = 0
PIDFILE_ATTEMPTS = 50
PIDFILE_RETRY_SECONDS = 0.1


class LifecycleError(RuntimeError):
    """A lifecycle identity or postcondition could not be proven."""


def _is_live_boot() -> bool:
    try:
        tokens = CMDLINE.read_text(encoding="utf-8").split()
    except (OSError, UnicodeError) as exc:
        raise LifecycleError(f"cannot read kernel command line: {exc}") from exc
    return "rd.live.image" in tokens


def _read_pid_file() -> int:
    try:
        parent = os.lstat(PID_FILE.parent)
    except OSError as exc:
        raise LifecycleError(f"cannot inspect PID-file directory: {exc}") from exc
    if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
        raise LifecycleError("PID-file parent is not a real directory")
    if parent.st_uid != REQUIRED_UID or parent.st_gid != REQUIRED_GID:
        raise LifecycleError("PID-file parent ownership differs")
    if parent.st_mode & 0o022:
        raise LifecycleError("PID-file parent is group/other-writable")

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(PID_FILE, flags)
    except OSError as exc:
        raise LifecycleError(f"cannot safely open WebUI PID file: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise LifecycleError("WebUI PID file is not one regular inode")
        if metadata.st_uid != REQUIRED_UID or metadata.st_gid != REQUIRED_GID:
            raise LifecycleError("WebUI PID-file ownership differs")
        if metadata.st_mode & 0o022:
            raise LifecycleError("WebUI PID file is group/other-writable")
        payload = os.read(descriptor, 64)
        if os.read(descriptor, 1):
            raise LifecycleError("WebUI PID file exceeds the closed format")
    finally:
        os.close(descriptor)

    if not re.fullmatch(rb"[1-9][0-9]*\n?", payload):
        raise LifecycleError("WebUI PID file is not one canonical decimal PID")
    pid = int(payload)
    if pid <= 1:
        raise LifecycleError("WebUI PID is outside the allowed process range")
    return pid


def _proc_bytes(pid: int, name: str) -> bytes:
    try:
        return (PROC_ROOT / str(pid) / name).read_bytes()
    except OSError as exc:
        raise LifecycleError(f"cannot read /proc/{pid}/{name}: {exc}") from exc


def _validate_webui_process(pid: int) -> None:
    status_lines = _proc_bytes(pid, "status").splitlines()
    uid_lines = [line for line in status_lines if line.startswith(b"Uid:")]
    if len(uid_lines) != 1:
        raise LifecycleError("WebUI process has no unique Uid record")
    try:
        uid_fields = [int(field) for field in uid_lines[0].split()[1:]]
    except ValueError as exc:
        raise LifecycleError("WebUI process Uid record is malformed") from exc
    if uid_fields != [REQUIRED_UID] * 4:
        raise LifecycleError("WebUI process is not entirely root-owned")

    arguments = _proc_bytes(pid, "cmdline").rstrip(b"\0").split(b"\0")
    expected_tail = [os.fsencode(WEBUI_SCRIPT), b"-t", b"live"]
    if len(arguments) != 4:
        raise LifecycleError("WebUI process argument count differs")
    if arguments[0] not in (b"/usr/bin/bash", b"/bin/bash"):
        raise LifecycleError("WebUI process interpreter differs")
    if arguments[1:] != expected_tail:
        raise LifecycleError("WebUI process command line differs")


def _bind_webui_pidfd() -> tuple[int, int]:
    last_error: LifecycleError | None = None
    for attempt in range(PIDFILE_ATTEMPTS):
        pidfd = -1
        try:
            pid = _read_pid_file()
            try:
                pidfd = os.pidfd_open(pid, 0)
            except OSError as exc:
                raise LifecycleError(f"cannot open pidfd for WebUI PID {pid}: {exc}") from exc
            poller = select.poll()
            poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
            if poller.poll(0):
                raise LifecycleError("WebUI process exited before identity validation")
            _validate_webui_process(pid)
            if poller.poll(0):
                raise LifecycleError("WebUI process exited during identity validation")
            return pidfd, pid
        except LifecycleError as exc:
            last_error = exc
            if pidfd >= 0:
                os.close(pidfd)
            if attempt + 1 < PIDFILE_ATTEMPTS:
                time.sleep(PIDFILE_RETRY_SECONDS)
    raise last_error or LifecycleError("WebUI PID binding failed without a diagnostic")


def _wait_for_exit(pidfd: int) -> None:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    while True:
        try:
            events = poller.poll()
        except InterruptedError:
            continue
        if events:
            return


def _stop_webui_service() -> None:
    try:
        stopped = subprocess.run(
            [SYSTEMCTL, "stop", SERVICE],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LifecycleError(f"cannot stop {SERVICE}: {exc}") from exc
    if stopped.returncode != 0:
        detail = stopped.stderr.strip() or f"exit {stopped.returncode}"
        raise LifecycleError(f"failed to stop {SERVICE}: {detail}")

    try:
        shown = subprocess.run(
            [
                SYSTEMCTL,
                "show",
                SERVICE,
                "--property=ActiveState",
                "--property=SubState",
                "--property=MainPID",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LifecycleError(f"cannot inspect {SERVICE} postcondition: {exc}") from exc
    if shown.returncode != 0:
        detail = shown.stderr.strip() or f"exit {shown.returncode}"
        raise LifecycleError(f"cannot inspect {SERVICE} postcondition: {detail}")
    properties: dict[str, str] = {}
    for line in shown.stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in properties:
            raise LifecycleError("service postcondition output is not a unique key/value set")
        properties[key] = value
    expected = {"ActiveState": "inactive", "SubState": "dead", "MainPID": "0"}
    if properties != expected:
        raise LifecycleError(f"service postcondition differs: {properties!r}")


def main(argv: list[str]) -> int:
    if argv:
        print(
            "noid-liveinst-webui-lifecycle: ERROR: "
            "this internal helper accepts no arguments",
            file=sys.stderr,
        )
        return 2

    try:
        if not _is_live_boot():
            print("noid-liveinst-webui-lifecycle: non-Live root; no action")
            return 0
    except LifecycleError as exc:
        print(f"noid-liveinst-webui-lifecycle: ERROR: {exc}", file=sys.stderr)
        return 1

    pidfd = -1
    pid: int | None = None
    try:
        pidfd, pid = _bind_webui_pidfd()
        print(f"noid-liveinst-webui-lifecycle: bound WebUI PID {pid}")
        _wait_for_exit(pidfd)
        _stop_webui_service()
    except LifecycleError as exc:
        # A malformed/stale Fedora lifecycle record must not leave the known
        # Live-only root WebUI listener behind. Stop only its exact unit and
        # retain a failed companion unit so the drift is visible.
        cleanup_error: LifecycleError | None = None
        try:
            _stop_webui_service()
        except LifecycleError as stop_exc:
            cleanup_error = stop_exc
        detail = str(exc)
        if cleanup_error is not None:
            detail += f"; fail-closed stop also failed: {cleanup_error}"
        print(f"noid-liveinst-webui-lifecycle: ERROR: {detail}", file=sys.stderr)
        return 1
    finally:
        if pidfd >= 0:
            os.close(pidfd)
    print(f"noid-liveinst-webui-lifecycle: stopped {SERVICE} after WebUI PID {pid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
