#!/usr/bin/python3
"""Verify the mode-specific authoritative Lorax installation success lines."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import tempfile


MAX_LOG_BYTES = 256 * 1024 * 1024
FIRST_MARKERS = {
    "kvm": (
        "installation_finished",
        re.compile(
            r"^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3} "
            r"INFO pylorax: Installation finished without errors[.]$"
        ),
    ),
    "no-virt": (
        "anaconda_complete",
        re.compile(
            r"^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3} "
            r"INFO pylorax: Complete!$"
        ),
    ),
}
DISK_SUCCESS_MARKER = (
    "disk_image_success",
    re.compile(
        r"^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3} "
        r"INFO pylorax: Disk Image install successful$"
    ),
)


def atomic_report(path: pathlib.Path, report: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(report, stream, sort_keys=True, indent=2)
            stream.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_log(path: pathlib.Path) -> tuple[bytes, list[str]]:
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("livemedia log must be a regular non-symlink file")
        if metadata.st_size <= 0 or metadata.st_size > MAX_LOG_BYTES:
            raise ValueError("livemedia log is empty or exceeds the 256 MiB bound")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_LOG_BYTES + 1)
        final_metadata = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(raw) != metadata.st_size or len(raw) > MAX_LOG_BYTES:
        raise ValueError("livemedia log changed size while it was being read")
    if (
        final_metadata.st_dev != metadata.st_dev
        or final_metadata.st_ino != metadata.st_ino
        or final_metadata.st_size != metadata.st_size
        or final_metadata.st_mtime_ns != metadata.st_mtime_ns
        or final_metadata.st_ctime_ns != metadata.st_ctime_ns
    ):
        raise ValueError("livemedia log changed while it was being read")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"livemedia log is not strict UTF-8: {exc}") from exc
    lines = text.splitlines()
    if not lines:
        raise ValueError("livemedia log has no lines")
    return raw, lines


def verify(log_path: pathlib.Path, mode: str) -> tuple[bool, dict]:
    raw, lines = read_log(log_path)
    markers = (FIRST_MARKERS[mode], DISK_SUCCESS_MARKER)
    first_identifier = markers[0][0]
    marker_lines = {
        identifier: [
            index + 1 for index, line in enumerate(lines) if expression.fullmatch(line)
        ]
        for identifier, expression in markers
    }
    failures = [
        {"id": identifier, "actual": len(marker_lines[identifier]), "expected": 1}
        for identifier, _expression in markers
        if len(marker_lines[identifier]) != 1
    ]
    if not failures and not (
        marker_lines[first_identifier][0]
        < marker_lines["disk_image_success"][0]
    ):
        failures.append({
            "id": "marker_order",
            "actual": marker_lines,
            "expected": f"{first_identifier} before disk_image_success",
        })
    passed = not failures
    report = {
        "schema_version": 2,
        "mode": mode,
        "result": "pass" if passed else "fail",
        "log_name": log_path.name,
        "log_sha256": hashlib.sha256(raw).hexdigest(),
        "line_count": len(lines),
        "counts": {
            identifier: len(marker_lines[identifier])
            for identifier, _expression in markers
        },
        "marker_lines": marker_lines,
        "failures": failures,
    }
    return passed, report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True, choices=sorted(FIRST_MARKERS))
    parser.add_argument("--log", required=True, type=pathlib.Path)
    parser.add_argument("--report", required=True, type=pathlib.Path)
    args = parser.parse_args()
    try:
        passed, report = verify(args.log, args.mode)
    except (OSError, ValueError) as exc:
        report = {
            "schema_version": 2,
            "mode": args.mode,
            "result": "error",
            "error": str(exc),
        }
        atomic_report(args.report, report)
        print(f"livemedia-success-audit: ERROR: {exc}", file=os.sys.stderr)
        return 2
    atomic_report(args.report, report)
    if not passed:
        print(
            f"livemedia-success-audit: FAIL: {len(report['failures'])} contract failures",
            file=os.sys.stderr,
        )
        return 1
    print(
        "livemedia-success-audit: PASS: "
        f"exact ordered {args.mode} host success markers"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
