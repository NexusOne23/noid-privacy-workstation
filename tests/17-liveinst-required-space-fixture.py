#!/usr/bin/python3
"""Behavioral fixture for the Live-installer required-space overlay."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import types

# The fixture imports the repository overlay directly. Keep that public source
# tree free of host-path-bearing bytecode even when the fixture is run without
# the interpreter's optional -B flag.
sys.dont_write_bytecode = True


def fail(message: str) -> "NoReturn":
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


if len(sys.argv) != 2:
    fail("usage: 17-liveinst-required-space-fixture.py PATH/TO/initialization.py")

source_path = Path(sys.argv[1])
if not source_path.is_file() or source_path.is_symlink():
    fail("initialization source must be one regular, non-symlink file")


def package(name: str) -> types.ModuleType:
    module = sys.modules.get(name)
    if module is None:
        module = types.ModuleType(name)
        module.__path__ = []
        sys.modules[name] = module
    return module


for package_name in (
    "blivet",
    "pyanaconda",
    "pyanaconda.core",
    "pyanaconda.modules",
    "pyanaconda.modules.common",
    "pyanaconda.modules.common.constants",
    "pyanaconda.modules.common.errors",
    "pyanaconda.modules.common.structures",
    "pyanaconda.modules.payloads",
    "pyanaconda.modules.payloads.source",
):
    package(package_name)

blivet_util = types.ModuleType("blivet.util")
blivet_util.mount = lambda *_args, **_kwargs: 0
sys.modules["blivet.util"] = blivet_util
sys.modules["blivet"].util = blivet_util

blivet_size = types.ModuleType("blivet.size")
blivet_size.Size = int
sys.modules["blivet.size"] = blivet_size


class FixtureLogger:
    def debug(self, *_args, **_kwargs):
        pass

    def info(self, *_args, **_kwargs):
        pass

    def warning(self, *_args, **_kwargs):
        pass


logger_module = types.ModuleType("pyanaconda.anaconda_loggers")
logger_module.get_module_logger = lambda _name: FixtureLogger()
sys.modules["pyanaconda.anaconda_loggers"] = logger_module

exec_calls: list[tuple[str, list[str]]] = []
util_module = types.ModuleType("pyanaconda.core.util")


def exec_with_capture(command: str, arguments: list[str]) -> str:
    exec_calls.append((command, arguments))
    return "29696      /fixture/source"


util_module.execWithCapture = exec_with_capture
sys.modules["pyanaconda.core.util"] = util_module

objects_module = types.ModuleType("pyanaconda.modules.common.constants.objects")
objects_module.DEVICE_TREE = object()
sys.modules[objects_module.__name__] = objects_module


class Storage:
    @staticmethod
    def get_proxy(_object):
        return None


services_module = types.ModuleType("pyanaconda.modules.common.constants.services")
services_module.STORAGE = Storage()
sys.modules[services_module.__name__] = services_module

errors_module = types.ModuleType("pyanaconda.modules.common.errors.payload")
errors_module.SourceSetupError = type("SourceSetupError", (RuntimeError,), {})
sys.modules[errors_module.__name__] = errors_module


class DeviceData:
    @staticmethod
    def from_structure(value):
        return value


structures_module = types.ModuleType("pyanaconda.modules.common.structures.storage")
structures_module.DeviceData = DeviceData
sys.modules[structures_module.__name__] = structures_module


class Task:
    pass


task_module = types.ModuleType("pyanaconda.modules.common.task")
task_module.Task = Task
sys.modules[task_module.__name__] = task_module


class SetUpMountTask:
    def __init__(self, target_mount):
        self._target_mount = target_mount

    def run(self):
        return None


mount_tasks_module = types.ModuleType(
    "pyanaconda.modules.payloads.source.mount_tasks"
)
mount_tasks_module.SetUpMountTask = SetUpMountTask
sys.modules[mount_tasks_module.__name__] = mount_tasks_module

spec = importlib.util.spec_from_file_location(
    "noid_live_os_initialization",
    source_path,
)
if spec is None or spec.loader is None:
    fail("could not construct import specification")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.REQUIRED_SPACE_MANIFEST_UID = os.getuid()
module.REQUIRED_SPACE_MANIFEST_GID = os.getgid()

valid_size = 8 * 1024 * 1024 * 1024


def manifest_payload(size: int) -> bytes:
    return (
        module.REQUIRED_SPACE_MANIFEST_MAGIC
        + b"\nbytes="
        + f"{size:020d}".encode("ascii")
        + b"\nheadroom="
        + str(module.REQUIRED_SPACE_MANIFEST_HEADROOM).encode("ascii")
        + b"\nanaconda_base_sha256="
        + module.SUPPORTED_ANACONDA_BASE_SHA256
        + b"\n"
    )


with tempfile.TemporaryDirectory(
    prefix="noid-live-size-fixture.",
    dir="/var/tmp",
) as temporary_dir:
    root = Path(temporary_dir) / "source"
    parent = root / "boot/loader/noid-privacy"
    parent.mkdir(parents=True)
    for directory in (root / "boot", root / "boot/loader", parent):
        directory.chmod(0o755)
    manifest = parent / "live-required-space-v1"
    manifest.write_bytes(manifest_payload(valid_size))
    manifest.chmod(0o644)

    task = module.SetUpLiveOSSourceTask("/fixture/image", str(root))
    if task._calculate_required_space() != valid_size:
        fail("valid manifest did not bypass the tree scan")
    if exec_calls:
        fail("valid manifest unexpectedly invoked the du fallback")

    manifest.unlink()
    if task._calculate_required_space() != 29696:
        fail("missing manifest did not retain Fedora's du fallback")
    if len(exec_calls) != 1 or exec_calls[-1][0] != "du":
        fail("missing manifest did not invoke exactly one du fallback")

    manifest.write_bytes(b"malformed\n")
    manifest.chmod(0o644)
    if task._calculate_required_space() != 29696:
        fail("malformed manifest did not retain Fedora's du fallback")
    if len(exec_calls) != 2:
        fail("malformed manifest did not invoke du exactly once")

    manifest.write_bytes(manifest_payload(valid_size))
    manifest.chmod(0o664)
    if task._calculate_required_space() != 29696:
        fail("writable manifest did not retain Fedora's du fallback")
    if len(exec_calls) != 3:
        fail("writable manifest did not invoke du exactly once")

    manifest.chmod(0o644)
    real_manifest = parent / "live-required-space-real"
    manifest.replace(real_manifest)
    manifest.symlink_to(real_manifest.name)
    if task._calculate_required_space() != 29696:
        fail("symlinked manifest did not retain Fedora's du fallback")
    if len(exec_calls) != 4:
        fail("symlinked manifest did not invoke du exactly once")

    manifest.unlink()
    os.mkfifo(manifest, mode=0o644)
    if task._calculate_required_space() != 29696:
        fail("FIFO manifest did not retain Fedora's du fallback")
    if len(exec_calls) != 5:
        fail("FIFO manifest did not invoke du exactly once")

print("Live-installer required-space manifest fixture: PASS")
