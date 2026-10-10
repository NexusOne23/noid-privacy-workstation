#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Use a portable user xattr only inside the rootfs verifier's source fixtures.

Production always reads security.selinux. The VM probe separately exercises
that real kernel namespace; this adapter lets source tests run unprivileged.
"""
import os
from pathlib import Path
import runpy
import sys
from unittest.mock import patch

verifier = Path(sys.argv.pop(1)).resolve(strict=True)
native_getxattr = os.getxattr


def fixture_getxattr(path, name, **kwargs):
    assert name == "security.selinux", "unexpected verifier xattr"
    return native_getxattr(path, "user.noid-selinux", **kwargs)


with patch.object(os, "getxattr", fixture_getxattr):
    runpy.run_path(str(verifier), run_name="__main__")
