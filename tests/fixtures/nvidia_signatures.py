#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Native signatures and modinfo against the complete M19 verifier.

Only RPM ownership/branch queries, MOK enrollment and module-name lookup are
fixtures. Compilation, signatures, compression, modinfo fields and verification
are native. No module is loaded, no host key is read and no RPM is installed.
"""

import gzip
import lzma
import os
from pathlib import Path
import shlex
import struct
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(sys.argv.pop(1)).read_text(encoding="utf-8")
MAGIC = b"~Module signature appended~\n"
PAYLOAD = b"NOID_SIGNED_PAYLOAD_ORIGINAL"
CHANGED = b"NOID_SIGNED_PAYLOAD_MODIFIED"
MODULES = ("nvidia", "nvidia_modeset", "nvidia_drm", "nvidia_uvm")


def checked(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, **kwargs).stdout


class ModuleSignatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="noid-signatures-", dir="/var/tmp")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        for name in ("trusted", "foreign"):
            checked(["openssl", "req", "-new", "-x509", "-newkey", "rsa:2048",
                     "-noenc", "-sha256", "-days", "1", "-set_serial", "0x1234567890",
                     "-subj", "/CN=NoID Privacy synthetic fixture/", "-keyout",
                     str(cls.root / f"{name}.key"), "-outform", "DER", "-out",
                     str(cls.root / f"{name}.der")])
        source = cls.root / "module.c"
        source.write_text('__attribute__((section(".modinfo"), used)) const char info[] = '
                          '"license=Dual MIT/GPL\\0version=fixture-version\\0'
                          'vermagic=fixture-kernel SMP\\0";\n'
                          'const char payload[] = "NOID_SIGNED_PAYLOAD_ORIGINAL";\n')
        checked(["clang", "-c", str(source), "-o", str(cls.root / "unsigned.ko")])
        cls.unsigned = (cls.root / "unsigned.ko").read_bytes()
        cls.good = cls.signed("trusted")
        cls.foreign = cls.signed("foreign", include_certificate=True)

    @classmethod
    def signed(cls, identity, include_certificate=False, opaque=False):
        signature = cls.root / "signature.der"
        args = ["openssl", "cms", "-sign", "-binary", "-noattr", "-md", "sha256",
                "-in", str(cls.root / "unsigned.ko"), "-signer",
                str(cls.root / f"{identity}.der"), "-inkey",
                str(cls.root / f"{identity}.key"), "-outform", "DER", "-out", str(signature)]
        if not include_certificate:
            args.append("-nocerts")
        if opaque:
            args.append("-nodetach")
        checked(args)
        sig = signature.read_bytes()
        return cls.unsigned + sig + struct.pack(">8BI", 0, 0, 2, 0, 0, 0, 0, 0, len(sig)) + MAGIC

    def setUp(self):
        self.case = tempfile.TemporaryDirectory(prefix="case-", dir=self.root)
        self.addCleanup(self.case.cleanup)
        self.tree = Path(self.case.name)
        self.modules = self.tree / "modules/fixture-kernel/extra/nvidia"
        self.modules.mkdir(parents=True)
        self.bin = self.tree / "bin"
        self.bin.mkdir()
        self.executable(self.bin / "rpm", r'''#!/bin/bash
case "$*" in
    '-q akmod-nvidia'|'-q xorg-x11-drv-nvidia-cuda') exit 0 ;;
    '-q akmod-nvidia-580xx'|'-q xorg-x11-drv-nvidia-580xx-cuda') exit 1 ;;
    '-q --qf %{EPOCHNUM}:%{VERSION}-%{RELEASE} akmod-nvidia'|\
    '-q --qf %{EPOCHNUM}:%{VERSION}-%{RELEASE} xorg-x11-drv-nvidia-cuda')
        printf '3:fixture-version-1.fc44' ;;
    '-q --qf %{VERSION} akmod-nvidia') printf fixture-version ;;
    '-qf --qf %{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE} '*)
        printf 'kmod-nvidia-fixture-kernel|3:fixture-version-1.fc44' ;;
    *) exit 99 ;;
esac
''')
        self.executable(self.bin / "modinfo", r'''#!/bin/bash
[ "$#" -eq 5 ] && [ "$1" = -F ] && [ "$4" = -k ] \
    && [ "$5" = fixture-kernel ] || exit 99
case "$3" in nvidia|nvidia_modeset|nvidia_drm|nvidia_uvm) ;; *) exit 99 ;; esac
exec /usr/bin/modinfo -F "$2" "$MODULE_TREE/$3.ko$MODULE_SUFFIX"
''')
        self.executable(self.bin / "mokutil", r'''#!/bin/bash
[ "$#" -eq 2 ] && [ "$1" = --test-key ] || exit 99
printf '%s is already enrolled\n' "$2"
exit 1
''')
        helper = SOURCE.split("<<'VERIFY_NV_EOF'\n", 1)[1].split("\nVERIFY_NV_EOF\n", 1)[0] + "\n"
        replacements = {
            '[ "$(id -u)" -eq 0 ]': f'[ "$(id -u)" -eq {os.getuid()} ]',
            "cert=/etc/pki/akmods/certs/public_key.der":
                f"cert={shlex.quote(str(self.root / 'trusted.der'))}",
            "/usr/lib/modules/": str(self.tree / "modules") + "/",
        }
        for old, new in replacements.items():
            self.assertIn(old, helper)
            helper = helper.replace(old, new)
        self.helper = self.tree / "verify.sh"
        self.helper.write_text(helper)

    @staticmethod
    def executable(path, text):
        path.write_text(text)
        path.chmod(0o755)

    def install(self, data, suffix="", changed_module=None):
        for module in MODULES:
            contents = data if changed_module is None or module == changed_module else self.good
            if suffix == ".xz":
                contents = lzma.compress(contents)
            elif suffix == ".gz":
                contents = gzip.compress(contents)
            elif suffix == ".zst":
                contents = checked(["zstd", "-q", "-c", f"--stream-size={len(contents)}"],
                                   input=contents)
            (self.modules / f"{module}.ko{suffix}").write_bytes(contents)

    def verify(self, suffix="", enrolled=False):
        env = {**os.environ, "PATH": f"{self.bin}:/usr/sbin:/usr/bin", "LC_ALL": "C",
               "MODULE_TREE": str(self.modules), "MODULE_SUFFIX": suffix}
        args = ["bash", str(self.helper), "fixture-kernel"]
        if enrolled:
            args.append("--require-enrolled")
        return subprocess.run(args, env=env, capture_output=True, text=True, timeout=15)

    def crypto_control(self, data, identity="trusted"):
        length = struct.unpack(">I", data[-len(MAGIC)-4:-len(MAGIC)])[0]
        start = len(data) - len(MAGIC) - 12 - length
        (self.tree / "content").write_bytes(data[:start])
        (self.tree / "signature.der").write_bytes(data[start:start+length])
        return subprocess.run(["openssl", "cms", "-verify", "-binary", "-inform", "DER",
                               "-in", str(self.tree / "signature.der"), "-content",
                               str(self.tree / "content"), "-certfile",
                               str(self.root / f"{identity}.der"), "-nointern", "-noverify",
                               "-out", "/dev/null"], capture_output=True).returncode

    def test_native_crypto_and_metadata_controls(self):
        self.assertEqual(self.crypto_control(self.good), 0)
        self.assertEqual(self.good.count(PAYLOAD), 1)
        bad = self.good.replace(PAYLOAD, CHANGED)
        self.assertNotEqual(self.crypto_control(bad), 0)
        for name, data in (("good", self.good), ("bad", bad), ("foreign", self.foreign)):
            (self.tree / f"{name}.ko").write_bytes(data)
        for field in ("license", "version", "vermagic", "sig_id", "sig_key"):
            values = [checked(["modinfo", "-F", field, str(self.tree / f"{name}.ko")])
                      for name in ("good", "bad", "foreign")]
            self.assertTrue(values[0])
            self.assertEqual(values, [values[0]] * 3)
        self.assertEqual(self.crypto_control(self.foreign, "foreign"), 0)
        self.assertNotEqual(self.crypto_control(self.foreign), 0)

    def test_valid_signed_modules_all_formats(self):
        for suffix in ("", ".xz", ".gz", ".zst"):
            with self.subTest(format=suffix or "plain"):
                self.install(self.good, suffix)
                result = self.verify(suffix, enrolled=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout,
                                 "branch=main\nkernel=fixture-kernel\nevr=3:fixture-version-1.fc44\n"
                                 "modules=verified\ncertificate=matched\nmok=enrolled\n")

    def test_changed_payload_in_each_module_is_rejected(self):
        for module in MODULES:
            with self.subTest(module=module):
                self.install(self.good.replace(PAYLOAD, CHANGED), changed_module=module)
                result = self.verify()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_changed_payload_all_compressions_is_rejected(self):
        for suffix in (".xz", ".gz", ".zst"):
            with self.subTest(format=suffix):
                self.install(self.good.replace(PAYLOAD, CHANGED), suffix)
                result = self.verify(suffix)
                self.assertNotEqual(result.returncode, 0)

    def test_same_serial_foreign_embedded_certificate_is_rejected(self):
        self.install(self.foreign)
        self.assertNotEqual(self.verify().returncode, 0)

    def test_modified_signature_is_rejected(self):
        bad = bytearray(self.good)
        bad[-len(MAGIC)-13] ^= 1
        self.install(bytes(bad))
        self.assertNotEqual(self.verify().returncode, 0)

    def test_unsigned_modules_are_rejected(self):
        self.install(self.unsigned)
        self.assertNotEqual(self.verify().returncode, 0)

    def test_embedded_content_cannot_hide_changed_module_bytes(self):
        attached = self.signed("trusted", opaque=True)
        self.assertEqual(attached.count(PAYLOAD), 2)
        self.install(attached.replace(PAYLOAD, CHANGED, 1))
        self.assertNotEqual(self.verify().returncode, 0)

    def test_trailing_signature_bytes_are_rejected(self):
        start = len(self.unsigned)
        end = len(self.good) - len(MAGIC) - 12
        envelope = self.good[start:end] + b"trailing garbage"
        altered = self.unsigned + envelope + struct.pack(
            ">8BI", 0, 0, 2, 0, 0, 0, 0, 0, len(envelope)) + MAGIC
        self.install(altered)
        self.assertNotEqual(self.verify().returncode, 0)

    def test_invalid_signature_trailers_are_rejected(self):
        header_start = len(self.good) - len(MAGIC) - 12
        headers = [bytes((1, 0, 2, 0, 0, 0, 0, 0)) + self.good[header_start+8:header_start+12],
                   struct.pack(">8BI", 0, 0, 2, 0, 0, 0, 0, 0, 0),
                   struct.pack(">8BI", 0, 0, 2, 0, 0, 0, 0, 0, len(self.good))]
        for header in headers:
            with self.subTest(header=header.hex()):
                self.install(self.good[:header_start] + header + MAGIC)
                self.assertNotEqual(self.verify().returncode, 0)


if __name__ == "__main__":
    unittest.main()
