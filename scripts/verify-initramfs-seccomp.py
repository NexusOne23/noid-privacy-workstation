#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify the seccomp SONAME and exact library in a newly built initramfs."""
import argparse
from pathlib import Path
import re
import subprocess
import sys


def verify(root: Path, image: Path) -> None:
    """Inspect with lsinitrd; never execute or mount the image's contents."""
    if image.is_symlink() or not image.is_file():
        raise ValueError("initramfs is missing or not a regular file")
    soname = "usr/lib64/libseccomp.so.2"
    source = root / soname
    if not source.is_symlink():
        raise ValueError("rootfs seccomp SONAME is not the expected library link")
    target = source.readlink()
    # Fedora uses a relative, versioned target in the same library directory.
    # Reject path escapes and changed packaging for explicit review.
    if not re.fullmatch(r"libseccomp\.so\.2\.[0-9.]+", str(target)):
        raise ValueError("rootfs seccomp SONAME has an unexpected target")
    library = source.parent / target
    if library.is_symlink() or not library.is_file():
        raise ValueError("rootfs seccomp library is missing or unsafe")
    expected = library.read_bytes()
    if expected[:6] != b"\x7fELF\x02\x01":
        raise ValueError("rootfs seccomp library is not an ELF64 little-endian object")
    listing = subprocess.run(["lsinitrd", str(image)], check=True,
                             capture_output=True, text=True).stdout
    records = [line.split() for line in listing.splitlines()]
    links = [row for row in records if len(row) >= 9 and row[8] == soname]
    if (len(links) != 1 or not links[0][0].startswith("l")
            or links[0][9:] != ["->", str(target)]):
        raise ValueError("initramfs lacks the exact seccomp SONAME link")
    relative = "usr/lib64/" + str(target)
    objects = [row for row in records if len(row) >= 9 and row[8] == relative]
    if len(objects) != 1 or not objects[0][0].startswith("-"):
        raise ValueError("initramfs seccomp library is missing or not regular")
    actual = subprocess.run(["lsinitrd", "-f", relative, str(image)],
                            check=True, capture_output=True).stdout
    if actual != expected:
        raise ValueError("initramfs seccomp library differs from the rootfs")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("image", type=Path)
    args = parser.parse_args()
    try:
        verify(args.root, args.image)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"FAIL: initramfs seccomp: {error}", file=sys.stderr)
        return 1
    print("PASS: initramfs contains the exact seccomp SONAME and library")
    return 0


if __name__ == "__main__":
    sys.exit(main())
