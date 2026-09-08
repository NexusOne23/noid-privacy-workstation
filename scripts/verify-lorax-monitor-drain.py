#!/usr/bin/python3
"""Semantic fixture for NoID Privacy's private Lorax monitor drain override."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time


def fail(message: str) -> "NoReturn":
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


if len(sys.argv) != 2:
    fail("usage: verify-lorax-monitor-drain.py PATH/TO/monitor.py")

monitor_path = Path(sys.argv[1])
if not monitor_path.is_file() or monitor_path.is_symlink():
    fail("monitor module must be a regular, non-symlink file")

spec = importlib.util.spec_from_file_location("noid_lorax_monitor", monitor_path)
if spec is None or spec.loader is None:
    fail("could not construct import specification")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FixtureServer:
    def __init__(self, log_path: str, *, kill: bool = True) -> None:
        self.kill = kill
        self.log_error = False
        self.error_line = ""
        self.log_path = log_path


class BoundedTimeoutSocket:
    """Record the production timeout while shortening it for the fixture."""

    def __init__(self, wrapped: socket.socket) -> None:
        self.wrapped = wrapped
        self.timeout_requests: list[float] = []

    def settimeout(self, value: float) -> None:
        self.timeout_requests.append(value)
        self.wrapped.settimeout(0.05)

    def recv(self, size: int) -> bytes:
        return self.wrapped.recv(size)


ordinary = b"ordinary installer record\n"
fatal = b"Error in POSTIN scriptlet in rpm package fixture"
with tempfile.TemporaryDirectory(
    prefix="noid-lorax-monitor-fixture.", dir="/var/tmp"
) as temporary_dir:
    log_path = Path(temporary_dir) / "virt-install.log"
    reader, writer = socket.socketpair()
    first_record_sent = threading.Event()
    writer_errors = []

    def emit_with_shutdown_gap() -> None:
        try:
            writer.sendall(ordinary)
            first_record_sent.set()
            # Exceed the retired 100-ms idle window so the fixture proves that
            # a delayed final record is retained, not merely pre-queued bytes.
            time.sleep(0.25)
            writer.sendall(fatal)
            writer.shutdown(socket.SHUT_WR)
        except Exception as exc:  # pragma: no cover - reported below
            writer_errors.append(exc)
            first_record_sent.set()

    emitter = threading.Thread(target=emit_with_shutdown_gap, daemon=True)
    try:
        emitter.start()
        if not first_record_sent.wait(timeout=2):
            fail("delayed writer did not send its first record")
        server = FixtureServer(str(log_path))
        module.LogRequestHandler(reader, ("fixture", 0), server)
        emitter.join(timeout=2)
        if emitter.is_alive():
            fail("delayed writer did not terminate")
        if writer_errors:
            fail(f"delayed writer failed: {writer_errors[0]}")
    finally:
        reader.close()
        writer.close()

    expected = (ordinary + fatal).decode("utf-8")
    if log_path.read_text(encoding="utf-8") != expected:
        fail("shutdown drain did not preserve the exact queued log bytes")
    if not server.log_error:
        fail("unterminated final fatal record was not classified")
    if server.error_line != fatal.decode("utf-8"):
        fail("fatal-record evidence differs from the final queued record")

    # Keep the writer open after one unterminated record. EOF cannot make this
    # pass: the handler must arm its five-second production idle timeout and
    # return through the draining socket.timeout branch. The wrapper records
    # the requested value but shortens the wait so the release fixture is fast.
    idle_log_path = Path(temporary_dir) / "virt-install-idle.log"
    idle_reader_raw, idle_writer = socket.socketpair()
    idle_reader = BoundedTimeoutSocket(idle_reader_raw)
    idle_server = FixtureServer(str(idle_log_path))
    idle_writer.sendall(fatal)
    idle_handler = threading.Thread(
        target=module.LogRequestHandler,
        args=(idle_reader, ("idle-fixture", 0), idle_server),
        daemon=True,
    )
    try:
        idle_handler.start()
        idle_handler.join(timeout=1)
        if idle_handler.is_alive():
            fail("idle drain did not terminate through its bounded timeout")
    finally:
        idle_writer.close()
        idle_reader_raw.close()
        idle_handler.join(timeout=1)
    if idle_reader.timeout_requests[-1:] != [5.0]:
        fail("idle drain did not request the exact five-second production bound")
    if idle_log_path.read_text(encoding="utf-8") != fatal.decode("utf-8"):
        fail("idle drain did not preserve its exact unterminated record")
    if not idle_server.log_error or idle_server.error_line != fatal.decode("utf-8"):
        fail("idle-drained fatal record was not classified")

    oversized_log_path = Path(temporary_dir) / "virt-install-oversized.log"
    oversized_reader, oversized_writer = socket.socketpair()
    oversized_errors = []

    def emit_oversized_record() -> None:
        try:
            oversized_writer.sendall(b"x" * (1024 * 1024 + 1))
            oversized_writer.shutdown(socket.SHUT_WR)
        except Exception as exc:  # pragma: no cover - reported below
            oversized_errors.append(exc)

    oversized_emitter = threading.Thread(
        target=emit_oversized_record, daemon=True
    )
    oversized_server = FixtureServer(str(oversized_log_path), kill=False)
    logger_was_disabled = module.log.disabled
    try:
        # The rejection is the expected negative-fixture result, not a stager
        # error that should leak through logging.lastResort.
        module.log.disabled = True
        oversized_emitter.start()
        module.LogRequestHandler(
            oversized_reader, ("oversized-fixture", 0), oversized_server
        )
        oversized_emitter.join(timeout=2)
        if oversized_emitter.is_alive():
            fail("oversized-record writer did not terminate")
        if oversized_errors:
            fail(f"oversized-record writer failed: {oversized_errors[0]}")
    finally:
        module.log.disabled = logger_was_disabled
        oversized_reader.close()
        oversized_writer.close()
    if not oversized_server.log_error:
        fail("overlong unterminated virtio log record did not fail closed")
    if oversized_server.error_line != "virtio log record exceeds 1 MiB safety bound":
        fail("overlong virtio log failure evidence differs")

print("lorax monitor shutdown-drain fixture: PASS")
