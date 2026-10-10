#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the checker against real cpio archives through native lsinitrd."""
import gzip
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


verifier = Path(sys.argv[1]).resolve()
library = Path("/usr/lib64/libseccomp.so.2")
assert library.is_symlink(), "Fedora libseccomp is required for this native fixture"
with tempfile.TemporaryDirectory(prefix="noid-seccomp-fixture-", dir="/var/tmp") as work:
    base = Path(work)
    root = base / "root"
    libdir = root / "usr/lib64"
    libdir.mkdir(parents=True)
    target = library.readlink()
    shutil.copyfile(library, libdir / target)
    (libdir / library.name).symlink_to(target)
    for case in ("valid", "missing-link", "missing-object", "wrong-link", "changed-object"):
        tree = base / case
        shutil.copytree(root, tree, symlinks=True)
        soname = tree / "usr/lib64" / library.name
        obj = soname.parent / target
        if case == "missing-link":
            soname.unlink()
        elif case == "missing-object":
            obj.unlink()
        elif case == "wrong-link":
            soname.unlink()
            soname.symlink_to("libseccomp.so.2.0")
        elif case == "changed-object":
            obj.write_bytes(obj.read_bytes() + b"changed")
        names = b"\0".join(str(p.relative_to(tree)).encode() for p in sorted(tree.rglob("*"))) + b"\0"
        archive = subprocess.run(["cpio", "--null", "-o", "-H", "newc"], cwd=tree,
                                 input=names, capture_output=True, check=True).stdout
        image = base / (case + ".img")
        image.write_bytes(gzip.compress(archive))
        check = subprocess.run([sys.executable, "-B", "-I", str(verifier),
                                "--root", str(root), str(image)], capture_output=True, text=True)
        assert (check.returncode == 0) == (case == "valid"), (case, check.stdout, check.stderr)
        print(case + ": expected verdict confirmed")
