#!/bin/bash
# Complete Module 02 installed/runtime contract gate.
#
# Run once on the reference live session, once immediately after installation,
# and once after reboot. The gate is read-only: it verifies the three installed
# files byte-for-byte against M02, checks ownership/mode/link/type, and compares
# all 105 source directives with every concrete procfs node selected by each
# wildcard.

set -euo pipefail

PASS_ID="${1:-}"
case "$PASS_ID" in live|fresh-install|reboot) ;;
    *)
        echo "Usage: sudo $0 {live|fresh-install|reboot}" >&2
        exit 2
        ;;
esac

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/02-sysctl.ks"
SYSCTL_ROOT=/etc/sysctl.d
PROC_SYS_ROOT=/proc/sys
EXPECTED_UID=0
EXPECTED_GID=0

if [ "${NOID_TEST_MODE:-0}" = 1 ]; then
    [ -n "${NOID_TEST_KS_FILE:-}" ] \
        && [ -n "${NOID_TEST_SYSCTL_ROOT:-}" ] \
        && [ -n "${NOID_TEST_PROC_SYS_ROOT:-}" ] \
        && [ -n "${NOID_TEST_EXPECT_UID:-}" ] \
        && [ -n "${NOID_TEST_EXPECT_GID:-}" ] || {
            echo "FAIL [$PASS_ID]: incomplete test-only root contract" >&2
            exit 2
        }
    KS_FILE=$NOID_TEST_KS_FILE
    SYSCTL_ROOT=$NOID_TEST_SYSCTL_ROOT
    PROC_SYS_ROOT=$NOID_TEST_PROC_SYS_ROOT
    EXPECTED_UID=$NOID_TEST_EXPECT_UID
    EXPECTED_GID=$NOID_TEST_EXPECT_GID
elif [ "$(id -u)" -ne 0 ]; then
    echo "FAIL [$PASS_ID]: production runtime verification requires root" >&2
    exit 2
fi

if [ "${NOID_TEST_MODE:-0}" != 1 ]; then
    if ! systemctl is-active --quiet systemd-sysctl.service \
       || [ "$(systemctl show systemd-sysctl.service -P Result)" != success ]; then
        echo "FAIL [$PASS_ID]: systemd-sysctl.service is not active/successful" >&2
        exit 1
    fi
fi

python3 - "$PASS_ID" "$KS_FILE" "$SYSCTL_ROOT" "$PROC_SYS_ROOT" \
    "$EXPECTED_UID" "$EXPECTED_GID" <<'PY'
import glob
import os
import re
import stat
import sys
from pathlib import Path

pass_id, ks_name, sysctl_name, proc_name, uid_text, gid_text = sys.argv[1:]
ks_path = Path(ks_name)
sysctl_root = Path(sysctl_name)
proc_root = Path(proc_name)
expected_uid = int(uid_text)
expected_gid = int(gid_text)
EXPECTED_DIRECTIVES = 105

contracts = (
    ("99-audit-fixes.conf", "AUDIT_EOF"),
    ("99-hardening.conf", "HARDENING_EOF"),
    ("99-userns.conf", "USERNS_EOF"),
)
failures: list[str] = []


def extract_heredoc(source: str, marker: str) -> bytes:
    lines = source.splitlines(keepends=True)
    start = None
    for index, line in enumerate(lines):
        if re.search(r"<<\s*['\"]?" + re.escape(marker) + r"['\"]?\s*$", line.rstrip("\n")):
            start = index + 1
            break
    if start is None:
        raise ValueError(f"missing source heredoc {marker}")
    for index in range(start, len(lines)):
        if lines[index].rstrip("\r\n") == marker:
            return "".join(lines[start:index]).encode()
    raise ValueError(f"unterminated source heredoc {marker}")


def normalized(value: str) -> str:
    return " ".join(value.strip().split())


try:
    ks_source = ks_path.read_text()
except OSError as error:
    print(f"FAIL [{pass_id}]: cannot read M02 source: {error}", file=sys.stderr)
    raise SystemExit(1)

directives: list[tuple[str, str, str]] = []
for filename, marker in contracts:
    installed = sysctl_root / filename
    try:
        metadata = installed.lstat()
    except OSError as error:
        failures.append(f"{installed}: missing/unreadable ({error})")
        continue

    if not stat.S_ISREG(metadata.st_mode):
        failures.append(f"{installed}: not a regular non-symlink file")
    if metadata.st_nlink != 1:
        failures.append(f"{installed}: link count {metadata.st_nlink}, expected 1")
    if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
        failures.append(
            f"{installed}: owner {metadata.st_uid}:{metadata.st_gid}, "
            f"expected {expected_uid}:{expected_gid}"
        )
    mode = stat.S_IMODE(metadata.st_mode)
    if mode != 0o640:
        failures.append(f"{installed}: mode {mode:04o}, expected 0640")

    try:
        expected_bytes = extract_heredoc(ks_source, marker)
        installed_bytes = installed.read_bytes()
    except (OSError, ValueError) as error:
        failures.append(f"{installed}: source/installed read failed ({error})")
        continue
    if installed_bytes != expected_bytes:
        failures.append(f"{installed}: not byte-identical to its M02 heredoc")

    for number, raw_line in enumerate(expected_bytes.decode().splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"(-?)([^=\s]+)\s*=\s*(.*?)\s*", line)
        if match is None:
            failures.append(f"{filename}:{number}: malformed directive")
            continue
        key = match.group(2)
        value = re.split(r"\s+#", match.group(3), maxsplit=1)[0]
        directives.append((filename, key, normalized(value)))

if len(directives) != EXPECTED_DIRECTIVES:
    failures.append(
        f"directive count {len(directives)}, expected {EXPECTED_DIRECTIVES}"
    )

concrete_checks = 0
for filename, key, expected in directives:
    relative_pattern = key.replace(".", "/")
    candidate_pattern = str(proc_root / relative_pattern)
    candidates = sorted(Path(item) for item in glob.glob(candidate_pattern))
    if not candidates:
        failures.append(f"{filename}: {key}: no matching procfs node")
        continue
    for candidate in candidates:
        concrete_checks += 1
        try:
            actual = normalized(candidate.read_text())
        except OSError as error:
            failures.append(f"{key}: cannot read {candidate} ({error})")
            continue
        if actual != expected:
            failures.append(
                f"{key}: source/runtime mismatch at {candidate}: "
                f"expected {expected!r}, got {actual!r}"
            )

if failures:
    print(
        f"FAIL [{pass_id}]: M02 directives={len(directives)} "
        f"concrete_runtime_checks={concrete_checks} failures={len(failures)}",
        file=sys.stderr,
    )
    for failure in failures:
        print(f"  - {failure}", file=sys.stderr)
    raise SystemExit(1)

print(
    f"PASS [{pass_id}]: M02 files=3 directives={len(directives)} "
    f"concrete_runtime_checks={concrete_checks}; installed files are "
    "byte-identical to source and every selected procfs value matches"
)
PY
