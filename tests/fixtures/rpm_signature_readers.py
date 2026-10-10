#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject incomplete key evidence before trusting the isolated RPM keyring."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(sys.argv.pop(1)).resolve()
FIXTURE = r'''
set -euo pipefail
source "$1"
mode=$2
key=$3
package=$4
fingerprint=0123456789ABCDEF0123456789ABCDEF01234567
gpg() {
    printf 'pub:::::::::\nfpr:::::::::%s:\n' "$fingerprint"
    [ "$mode" != failed-gpg ] || return 74
}
awk() {
    command awk "$@" || return
    case "$mode:$1" in
        failed-primary-parser:-F:|failed-imported-parser:'NF { print toupper($1) }')
            return 74 ;;
    esac
}
rpmkeys() {
    case " $* " in
        *' --import '*) [ "$mode" != failed-import ] ;;
        *' --list '*)
            if [ "$mode" = foreign-import ]; then
                printf '%s\n' FEDCBA9876543210FEDCBA9876543210FEDCBA98
            else
                printf '%s\n' "$fingerprint"
            fi
            [ "$mode" != failed-list ] ;;
        *' --checksig '*) [ "$mode" != failed-signature ] ;;
        *) return 2 ;;
    esac
}
# A sourcing caller may use the verifier in an if/! condition. Its safety
# cannot depend on errexit being active inside the function.
if noid_verify_rpms_with_isolated_key "$key" "$fingerprint" "$package"; then
    exit 0
else
    exit 1
fi
'''


class SignatureReaders(unittest.TestCase):
    def test_reader_and_signature_failures(self):
        with tempfile.TemporaryDirectory(prefix="noid-rpm-readers-") as directory:
            root = Path(directory)
            key, package = root / "key", root / "package.rpm"
            key.touch()
            package.touch()
            env = dict(os.environ, TMPDIR=directory)
            for mode in ("clean", "failed-gpg", "failed-primary-parser",
                         "failed-imported-parser", "failed-import", "failed-list",
                         "foreign-import", "failed-signature"):
                with self.subTest(mode=mode):
                    result = subprocess.run(
                        ["bash", "-c", FIXTURE, "fixture", str(SOURCE), mode,
                         str(key), str(package)], env=env, text=True,
                        capture_output=True, timeout=15,
                    )
                    self.assertEqual(result.returncode, 0 if mode == "clean" else 1,
                                     result.stdout + result.stderr)
                    self.assertEqual(set(root.iterdir()), {key, package})


if __name__ == "__main__":
    unittest.main()
