#!/usr/bin/env python3
"""Run the extracted GRUB helper on a PTY and answer its two visible prompts."""

from __future__ import annotations

import os
import pty
import select
import signal
import sys
import time


PROMPT_TIMEOUT_SECONDS = 15
TERMINATE_GRACE_SECONDS = 2


def stop_timed_out_child(pid: int) -> int:
    """Bound termination and always reap a timed-out fixture child."""
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + TERMINATE_GRACE_SECONDS
    while time.monotonic() < deadline:
        waited_pid, waited_status = os.waitpid(pid, os.WNOHANG)
        if waited_pid == pid:
            return waited_status
        time.sleep(0.05)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    _waited_pid, waited_status = os.waitpid(pid, 0)
    return waited_status


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} HELPER FIXTURE_PASSWORD", file=sys.stderr)
        return 2
    helper, password = sys.argv[1:]
    pid, master = pty.fork()
    if pid == 0:
        # The hardened test host mounts /tmp noexec; invoke the extracted
        # fixture through its interpreter while retaining the PTY contract.
        os.execve("/bin/bash", ["bash", helper], os.environ.copy())

    output = bytearray()
    first_sent = False
    second_sent = False
    deadline = time.monotonic() + PROMPT_TIMEOUT_SECONDS
    status = None
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    data = os.read(master, 4096)
                except OSError:
                    data = b""
                if data:
                    output.extend(data)
                    if b"Enter new GRUB password: " in output and not first_sent:
                        os.write(master, password.encode() + b"\n")
                        first_sent = True
                    if b"Reenter new GRUB password: " in output and not second_sent:
                        os.write(master, password.encode() + b"\n")
                        second_sent = True
            waited_pid, waited_status = os.waitpid(pid, os.WNOHANG)
            if waited_pid == pid:
                status = waited_status
                break
        if status is None:
            status = stop_timed_out_child(pid)
            print("PTY fixture timed out", file=sys.stderr)
            return 124
    finally:
        os.close(master)

    sys.stdout.buffer.write(output)
    if not first_sent or not second_sent:
        print("PTY fixture did not observe both helper-owned prompts", file=sys.stderr)
        return 125
    return os.waitstatus_to_exitcode(status)


if __name__ == "__main__":
    raise SystemExit(main())
