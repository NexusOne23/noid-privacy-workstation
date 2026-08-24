#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify that a NoID Privacy golden root contains no composed host state."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
import tempfile


SCHEMA = "NOID_ROOTFS_HYGIENE_V1"
ABSENT_PATHS = (
    "etc/brlapi.key",
    "etc/nvme/hostid",
    "etc/nvme/hostnqn",
    "root/anaconda-ks.cfg",
    "root/original-ks.cfg",
    "var/lib/noid-privacy/host-identity-installed.done",
    "var/lib/systemd/random-seed",
)
EMPTY_DIRECTORIES = (
    "etc/NetworkManager/system-connections",
    "var/lib/NetworkManager",
    "var/lib/chrony",
    "var/log/journal",
)
REQUIRED_DIRECTORIES = (
    "etc/NetworkManager/system-connections",
    "var/log",
    "var/log/journal",
)


class VerificationError(RuntimeError):
    """The verifier could not safely inspect its input."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--expected-uid", type=int, default=0)
    parser.add_argument("--expected-gid", type=int, default=0)
    return parser.parse_args()


def lstat(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise VerificationError(f"cannot inspect {path.name}: {error.strerror}") from error


def relative_entries(path: Path) -> list[Path]:
    try:
        return list(path.iterdir())
    except OSError as error:
        raise VerificationError(f"cannot enumerate {path.name}: {error.strerror}") from error


def descendant(root: Path, relative: str) -> Path:
    """Return a fixed descendant only after rejecting symlinked parents."""
    relative_path = Path(relative)
    parts = relative_path.parts
    if relative_path.is_absolute() or not parts or any(part in ("", ".", "..") for part in parts):
        raise VerificationError("invalid verifier path contract")
    current = root
    for component in parts[:-1]:
        current /= component
        metadata = lstat(current)
        if metadata is None:
            break
        if not stat.S_ISDIR(metadata.st_mode):
            raise VerificationError(f"unsafe parent in verifier path: {relative}")
    return root.joinpath(*parts)


def publish_report(path: Path, report: dict[str, object]) -> None:
    parent = path.parent
    parent_metadata = lstat(parent)
    if parent_metadata is None or not stat.S_ISDIR(parent_metadata.st_mode):
        raise VerificationError("report parent is not a real directory")
    if path.exists() or path.is_symlink():
        raise VerificationError("report target already exists")
    descriptor, temporary = tempfile.mkstemp(prefix=".rootfs-hygiene.", dir=parent)
    temporary_path = Path(temporary)
    try:
        payload = json.dumps(report, sort_keys=True, indent=2) + "\n"
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = -1
            output.write(payload)
            output.flush()
            os.fchmod(output.fileno(), 0o600)
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
        directory_descriptor = os.open(
            parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def verify(args: argparse.Namespace) -> tuple[dict[str, object], int]:
    if args.expected_uid < 0 or args.expected_gid < 0:
        raise VerificationError("expected ownership values must be non-negative")
    root = args.root
    root_metadata = lstat(root)
    if root_metadata is None or not stat.S_ISDIR(root_metadata.st_mode):
        raise VerificationError("root is not a real directory")
    if root.resolve(strict=True) != root.absolute():
        raise VerificationError("root path is not canonical")

    violations: list[str] = []
    checks = 0

    machine_id = descendant(root, "etc/machine-id")
    metadata = lstat(machine_id)
    checks += 1
    if metadata is None:
        violations.append("machine-id-missing")
    elif not stat.S_ISREG(metadata.st_mode):
        violations.append("machine-id-not-regular")
    elif (
        metadata.st_uid != args.expected_uid
        or metadata.st_gid != args.expected_gid
        or stat.S_IMODE(metadata.st_mode) != 0o444
        or metadata.st_nlink != 1
        or metadata.st_size != 0
    ):
        violations.append("machine-id-not-empty-canonical")

    dbus_machine_id = descendant(root, "var/lib/dbus/machine-id")
    metadata = lstat(dbus_machine_id)
    checks += 1
    if metadata is None:
        violations.append("dbus-machine-id-link-missing")
    elif not stat.S_ISLNK(metadata.st_mode):
        violations.append("dbus-machine-id-not-symlink")
    else:
        try:
            target = os.readlink(dbus_machine_id)
        except OSError as error:
            raise VerificationError("cannot read dbus machine-id link") from error
        if target != "/etc/machine-id":
            violations.append("dbus-machine-id-link-target-differs")

    for relative in ABSENT_PATHS:
        checks += 1
        if lstat(descendant(root, relative)) is not None:
            violations.append(f"forbidden-path-present:{relative}")

    for relative in REQUIRED_DIRECTORIES:
        checks += 1
        directory = descendant(root, relative)
        metadata = lstat(directory)
        if metadata is None or not stat.S_ISDIR(metadata.st_mode):
            violations.append(f"required-directory-invalid:{relative}")
            continue
        if metadata.st_uid != args.expected_uid or metadata.st_mode & 0o022:
            violations.append(f"required-directory-unsafe:{relative}")

    for relative in EMPTY_DIRECTORIES:
        checks += 1
        directory = descendant(root, relative)
        metadata = lstat(directory)
        if metadata is None:
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            violations.append(f"state-directory-invalid:{relative}")
        elif relative_entries(directory):
            violations.append(f"state-directory-not-empty:{relative}")

    log_root = descendant(root, "var/log")
    if lstat(log_root) is not None:
        try:
            for current, directory_names, file_names in os.walk(
                log_root, topdown=True, followlinks=False
            ):
                current_path = Path(current)
                for directory_name in list(directory_names):
                    candidate = current_path / directory_name
                    candidate_metadata = lstat(candidate)
                    if candidate_metadata is not None and stat.S_ISLNK(
                        candidate_metadata.st_mode
                    ):
                        violations.append("compose-log-nondirectory-present")
                        directory_names.remove(directory_name)
                if file_names:
                    violations.append("compose-log-file-present")
                    break
        except OSError as error:
            raise VerificationError("cannot recursively inspect log tree") from error
    checks += 1

    ssh_dir = descendant(root, "etc/ssh")
    if lstat(ssh_dir) is not None:
        for candidate in ssh_dir.glob("ssh_host_*_key"):
            if lstat(candidate) is not None:
                violations.append("ssh-host-private-key-present")
                break
    checks += 1

    unique_violations = sorted(set(violations))
    report: dict[str, object] = {
        "schema": SCHEMA,
        "verdict": "pass" if not unique_violations else "fail",
        "checks": checks,
        "violations": unique_violations,
    }
    return report, 0 if not unique_violations else 1


def main() -> int:
    args = parse_args()
    try:
        report, result = verify(args)
        publish_report(args.report, report)
    except VerificationError as error:
        print(f"ERROR: rootfs hygiene verification could not complete: {error}", file=sys.stderr)
        return 2
    if result:
        print("ERROR: final rootfs image-hygiene gate failed", file=sys.stderr)
    else:
        print("final rootfs image-hygiene gate: PASS")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
