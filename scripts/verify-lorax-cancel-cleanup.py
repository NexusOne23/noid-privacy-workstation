#!/usr/bin/python3
"""Semantic fixture for NoID Privacy's private Lorax cancel cleanup."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import time


def fail(message: str) -> "NoReturn":
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


if len(sys.argv) != 2:
    fail("usage: verify-lorax-cancel-cleanup.py PATH/TO/executils.py")

executils_path = Path(sys.argv[1])
if not executils_path.is_file() or executils_path.is_symlink():
    fail("executils module must be a regular, non-symlink file")

spec = importlib.util.spec_from_file_location(
    "noid_lorax_executils", executils_path
)
if spec is None or spec.loader is None:
    fail("could not construct import specification")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

captured: list[subprocess.Popen] = []


def cancel(process: subprocess.Popen) -> bool:
    captured.append(process)
    return False


started = time.monotonic()
return_code, _output = module._run_program(
    ["/usr/bin/sleep", "30"],
    callback=cancel,
)
elapsed = time.monotonic() - started

if len(captured) != 1:
    fail("cancel callback did not receive exactly one child process")
process = captured[0]
if process.poll() is None:
    # Never let a failing fixture reproduce the production orphan.
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)
    fail("cancelled child process remained active")
if return_code is None:
    fail("cancelled child process was not reaped")
if return_code == 0:
    fail("cancelled child process was reported as successful")
if elapsed >= 5:
    fail(f"ordinary TERM-responsive cancellation took too long: {elapsed:.3f}s")

normal_code, normal_output = module._run_program(
    ["/usr/bin/printf", "normal-completion"],
    callback=lambda _process: True,
    log_output=False,
)
if normal_code != 0 or normal_output != "normal-completion\n":
    fail("ordinary callback-driven process completion regressed")


class StubbornProcess:
    def __init__(self) -> None:
        self.returncode = None
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True

    def communicate(self, timeout=None):
        if timeout == 10:
            if not self.terminated:
                fail("hard-stop fixture was not terminated first")
            raise module.TimeoutExpired("stubborn-fixture", timeout)
        if not self.killed:
            fail("hard-stop fixture was reaped without the required kill")
        self.returncode = -9
        return ("forced-stop", None)


stubborn = StubbornProcess()
original_start_program = module.startProgram
module.startProgram = lambda *_args, **_kwargs: stubborn
try:
    stubborn_code, stubborn_output = module._run_program(
        ["/usr/bin/false"],
        callback=lambda _process: False,
        log_output=False,
    )
finally:
    module.startProgram = original_start_program
if (
    not stubborn.terminated
    or not stubborn.killed
    or stubborn_code != -9
    or stubborn_output != "forced-stop\n"
):
    fail("TERM-resistant cancellation did not use the bounded kill-and-reap fallback")


class ExitDuringCancelProcess:
    def __init__(self) -> None:
        self.returncode = None
        self.communicated = False

    def poll(self):
        return self.returncode

    def terminate(self) -> None:
        self.returncode = 0
        raise ProcessLookupError("child exited before TERM")

    def communicate(self, timeout=None):
        if timeout != 10:
            fail("exit-race fixture did not use the bounded reap path")
        self.communicated = True
        return ("completed-during-cancel", None)


exit_race = ExitDuringCancelProcess()
module.startProgram = lambda *_args, **_kwargs: exit_race
try:
    race_code, race_output = module._run_program(
        ["/usr/bin/true"],
        callback=lambda _process: False,
        log_output=False,
    )
finally:
    module.startProgram = original_start_program
if (
    not exit_race.communicated
    or race_code != 0
    or race_output != "completed-during-cancel\n"
):
    fail("child exit between poll and terminate was not reaped cleanly")

print("lorax cancelled-process cleanup fixture: PASS")
