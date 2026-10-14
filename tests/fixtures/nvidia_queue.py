#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise M19 queue reads with native find failures in a private tree.

The guard is run without systemd-inhibit. Queue paths and expected ownership
are mapped to this user's fixtures; systemctl/systemd-run only record calls.
No installer, driver build, live boot path or system service is invoked.
"""

import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(sys.argv.pop(1)).read_text(encoding="utf-8")


def payload(tag):
    return SOURCE.split(f"<<'{tag}'\n", 1)[1].split(f"\n{tag}\n", 1)[0] + "\n"


class QueueEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="noid-nvidia-queue-", dir="/var/tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.queue = self.root / "state/queue"
        self.queue.mkdir(parents=True)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.trace = self.root / "calls"
        self.find_status = self.root / "find-status"
        self.kernel = "9.9.9-fixture"
        self.marker = self.queue / "test.pending"
        self.marker.write_text(f"kernel={self.kernel}\nsource=post-transaction\n")
        self.marker.chmod(0o600)
        for name in ("modules", "boot"):
            (self.root / name).mkdir()
        modules = self.root / "modules" / self.kernel
        (modules / "kernel").mkdir(parents=True)
        (modules / "vmlinuz").write_text("fixture kernel\n")
        (self.root / "boot" / f"vmlinuz-{self.kernel}").write_text("fixture kernel\n")
        (self.root / "boot.lock").touch()
        self.executable(self.root / "boot-guard",
                        "#!/bin/bash\n"
                        "if [ \"${BOOT_GUARD_FAIL:-0}\" = 1 ]; then\n"
                        "    echo 'M21 still requires recovery' >&2\n"
                        "    exit 1\n"
                        "fi\n"
                        "printf 'basis=generic\\n'\n")
        self.executable(self.bin / "find", r'''#!/bin/bash
set -u
case "$FIND_CASE" in
    normal) /usr/bin/find "$@"; rc=$? ;;
    missing)
        if [ -d "$PRIVATE_QUEUE" ]; then
            mv -- "$PRIVATE_QUEUE" "$PRIVATE_QUEUE.saved" || exit 98
        fi
        /usr/bin/find "$@"; rc=$?
        ;;
    unreadable)
        chmod 000 "$PRIVATE_QUEUE" || exit 98
        /usr/bin/find "$@"; rc=$?
        chmod 755 "$PRIVATE_QUEUE" || exit 98
        ;;
    partial)
        /usr/bin/find "$PRIVATE_QUEUE" "$PRIVATE_QUEUE/absent" \
            -maxdepth 1 -type f -name '*.pending' -print
        rc=$?
        ;;
    recover)
        if [ ! -e "$FIND_STATUS" ]; then
            /usr/bin/find "$PRIVATE_QUEUE/absent" -maxdepth 1 -print
            rc=$?
        else
            /usr/bin/find "$@"; rc=$?
        fi
        ;;
    *) exit 99 ;;
esac
printf '%s\n' "$rc" >>"$FIND_STATUS"
exit "$rc"
''')
        for tool in ("systemctl", "systemd-run"):
            self.executable(self.bin / tool, "#!/bin/bash\n"
                            'printf "%s %s\\n" "${0##*/}" "$*" >>"$CALL_TRACE"\n'
                            'if [ "${1:-}" = is-active ]; then exit 3; fi\n')
        self.guard = self.root / "guard.sh"
        self.guard.write_text(payload("GUARD_NV_EOF").replace(
            "queue_dir=/var/lib/noid-nvidia-integrity/queue",
            f"queue_dir={shlex.quote(str(self.queue))}"))
        queue = payload("QUEUE_NV_EOF")
        replacements = {
            "state_dir=/var/lib/noid-nvidia-integrity":
                f"state_dir={shlex.quote(str(self.queue.parent))}",
            "/usr/lib/modules/": str(self.root / "modules") + "/",
            "/boot/vmlinuz-": str(self.root / "boot/vmlinuz-"),
            "/run/lock/noid-boot-mutation.lock": str(self.root / "boot.lock"),
            "/run/lock/noid-nvidia-queue.lock": str(self.root / "queue.lock"),
            "/usr/libexec/noid-boot-mutation-guard": str(self.root / "boot-guard"),
            "'0:0'": f"'{os.getuid()}:{os.getgid()}'",
            "'0:0:600:1'": f"'{os.getuid()}:{os.getgid()}:600:1'",
        }
        for old, new in replacements.items():
            self.assertIn(old, queue)
            queue = queue.replace(old, new)
        self.resume = self.root / "queue.sh"
        self.resume.write_text(queue)

    @staticmethod
    def executable(path, source):
        path.write_text(source)
        path.chmod(0o755)

    def env(self, case):
        return {**os.environ, "PATH": f"{self.bin}:/usr/sbin:/usr/bin",
                "LC_ALL": "C", "FIND_CASE": case,
                "PRIVATE_QUEUE": str(self.queue), "FIND_STATUS": str(self.find_status),
                "CALL_TRACE": str(self.trace)}

    def guard_result(self, case):
        process = subprocess.Popen(["bash", str(self.guard)], env=self.env(case),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        try:
            output, error = process.communicate(timeout=1.4)
            return process.returncode, output, error
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            output, error = process.communicate(timeout=3)
            return None, output, error
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()

    def assert_native_failure(self):
        statuses = self.find_status.read_text().splitlines()
        self.assertIn("1", statuses, "native find must actually fail")

    def test_native_failure_controls(self):
        for case in ("missing", "unreadable", "partial"):
            with self.subTest(case=case):
                if not self.queue.exists():
                    self.queue.with_suffix(".saved").rename(self.queue)
                result = subprocess.run([str(self.bin / "find"), str(self.queue),
                                         "-maxdepth", "1", "-type", "f", "-name",
                                         "*.pending", "-print", "-quit"],
                                        env=self.env(case), capture_output=True, text=True)
                self.assertEqual(result.returncode, 1)
                self.assertTrue(result.stderr)
                self.assertEqual(bool(result.stdout), case == "partial")

    def test_pending_keeps_guard_alive(self):
        self.assertIsNone(self.guard_result("normal")[0])
        self.assertEqual(set(self.find_status.read_text().splitlines()), {"0"})

    def test_empty_queue_releases_guard(self):
        self.marker.unlink()
        self.assertEqual(self.guard_result("normal")[0], 0)

    def test_unsafe_pending_object_keeps_guard_alive(self):
        self.marker.unlink()
        for kind in ("directory", "symlink"):
            with self.subTest(kind=kind):
                if kind == "directory":
                    self.marker.mkdir()
                else:
                    self.marker.symlink_to(self.root / "absent-target")
                try:
                    self.assertIsNone(self.guard_result("normal")[0])
                finally:
                    if kind == "directory":
                        self.marker.rmdir()
                    else:
                        self.marker.unlink()

    def test_failed_scan_keeps_guard_alive(self):
        for case in ("missing", "unreadable", "partial"):
            with self.subTest(case=case):
                if not self.queue.exists():
                    self.queue.with_suffix(".saved").rename(self.queue)
                result, _, _ = self.guard_result(case)
                self.assert_native_failure()
                self.assertIsNone(result, "a failed read must not release the inhibitor holder")

    def test_linked_queue_is_not_empty_evidence(self):
        saved = self.queue.with_suffix(".saved")
        self.queue.rename(saved)
        self.queue.symlink_to(saved, target_is_directory=True)
        self.assertTrue(self.queue.is_symlink())
        self.assertTrue(self.marker.is_file())
        with self.subTest(reader="guard"):
            self.assertIsNone(self.guard_result("normal")[0])
        with self.subTest(reader="resume"):
            result = subprocess.run(["bash", str(self.resume), "--resume"],
                                    env=self.env("normal"), capture_output=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(self.trace.exists())

    def test_guard_releases_after_successful_recovery(self):
        self.marker.unlink()
        result, _, _ = self.guard_result("recover")
        self.assertEqual(result, 0)
        self.assertEqual(self.find_status.read_text().splitlines(), ["1", "0"])

    def test_resume_empty_queue_does_not_schedule(self):
        self.marker.unlink()
        result = subprocess.run(["bash", str(self.resume), "--resume"],
                                env=self.env("normal"), capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.trace.exists())

    def test_resume_pending_starts_guard_before_worker(self):
        result = subprocess.run(["bash", str(self.resume), "--resume"],
                                env=self.env("normal"), capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.trace.read_text().splitlines()
        self.assertEqual(calls[0], "systemctl start noid-nvidia-reboot-guard.service")
        self.assertTrue(calls[-1].startswith("systemd-run --no-block --collect "))
        self.assertTrue(self.marker.exists())

    def run_queue(self, *args, **extra):
        return subprocess.run(["bash", str(self.resume), *args],
                              env={**self.env("normal"), **extra},
                              capture_output=True, text=True, timeout=5)

    def test_stable_basis_publishes_pending_task_then_guard_then_worker(self):
        self.marker.unlink()
        result = self.run_queue(self.kernel)
        self.assertEqual(result.returncode, 0, result.stderr)
        pending = sorted(self.queue.glob("*.pending"))
        self.assertEqual(len(pending), 1)
        self.assertEqual(list(self.queue.glob("*.deferred")), [])
        self.assertEqual(result.stdout, f"{pending[0]}\n")
        self.assertEqual(pending[0].read_text(),
                         f"kernel={self.kernel}\nsource=post-transaction\n")
        calls = self.trace.read_text().splitlines()
        self.assertEqual(calls[0], "systemctl start noid-nvidia-reboot-guard.service")
        self.assertTrue(calls[-1].startswith("systemd-run --no-block --collect "))

    def add_kernel(self, kernel):
        modules = self.root / "modules" / kernel
        (modules / "kernel").mkdir(parents=True)
        (modules / "vmlinuz").write_text("fixture kernel\n")
        (self.root / "boot" / f"vmlinuz-{kernel}").write_text("fixture kernel\n")

    def test_several_kernels_publish_under_one_lease_before_any_worker(self):
        self.marker.unlink()
        second = "9.9.10-fixture"
        self.add_kernel(second)
        result = self.run_queue(self.kernel, second)
        self.assertEqual(result.returncode, 0, result.stderr)
        pending = sorted(self.queue.glob("*.pending"))
        self.assertEqual(len(pending), 2)
        self.assertEqual(list(self.queue.glob("*.deferred")), [])
        self.assertEqual(sorted(path.read_text() for path in pending),
                         sorted(f"kernel={kernel}\nsource=post-transaction\n"
                                for kernel in (self.kernel, second)))
        self.assertEqual(sorted(result.stdout.splitlines()), [str(path) for path in pending])
        calls = self.trace.read_text().splitlines()
        workers = [call for call in calls if call.startswith("systemd-run ")]
        # One inhibitor for the whole batch, and every worker starts only
        # after all tasks are published and the boot lease is released.
        self.assertEqual(calls[0], "systemctl start noid-nvidia-reboot-guard.service")
        self.assertEqual(calls.count("systemctl start noid-nvidia-reboot-guard.service"), 1)
        self.assertEqual(len(workers), 2)
        self.assertTrue(all(call.startswith("systemd-run --no-block --collect ")
                            for call in workers))
        self.assertEqual(sorted(kernel for kernel in (self.kernel, second)
                                if any(f"for {kernel} " in call for call in workers)),
                         sorted((self.kernel, second)))

    def test_invalid_kernel_fails_the_call_without_blocking_valid_ones(self):
        self.marker.unlink()
        result = self.run_queue("9.9.11-absent", self.kernel)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("refusing an invalid or unsafe kernel payload", result.stderr)
        pending = sorted(self.queue.glob("*.pending"))
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].read_text(),
                         f"kernel={self.kernel}\nsource=post-transaction\n")
        self.assertEqual(result.stdout, f"{pending[0]}\n")
        calls = self.trace.read_text().splitlines()
        self.assertEqual(calls[0], "systemctl start noid-nvidia-reboot-guard.service")
        self.assertEqual(len([call for call in calls if call.startswith("systemd-run ")]), 1)

    def test_only_invalid_kernels_publish_nothing(self):
        self.marker.unlink()
        result = self.run_queue("9.9.11-absent")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(list(self.queue.iterdir()), [])
        self.assertFalse(self.trace.exists())

    def test_unstable_basis_keeps_a_durable_deferred_task(self):
        self.marker.unlink()
        result = self.run_queue(self.kernel, BOOT_GUARD_FAIL="1")
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertIn("deferred until Module 21 is stable", result.stderr)
        deferred = sorted(self.queue.glob("*.deferred"))
        self.assertEqual(len(deferred), 1)
        self.assertEqual(list(self.queue.glob("*.pending")), [])
        self.assertEqual(deferred[0].read_text(),
                         f"kernel={self.kernel}\nsource=post-transaction\n")
        self.assertEqual(deferred[0].stat().st_mode & 0o777, 0o600)
        self.assertFalse(self.trace.exists(), "no inhibitor or worker without a stable basis")
        self.assertEqual(self.guard_result("normal")[0], 0,
                         "a deferred task must not hold the shutdown inhibitor")
        resumed = self.run_queue("--resume")
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertEqual(list(self.queue.glob("*.deferred")), [])
        self.assertEqual(len(list(self.queue.glob("*.pending"))), 1)
        calls = self.trace.read_text().splitlines()
        self.assertEqual(calls[0], "systemctl start noid-nvidia-reboot-guard.service")
        self.assertTrue(calls[-1].startswith("systemd-run --no-block --collect "))

    def test_resume_failed_scan_is_not_success(self):
        for case in ("missing", "unreadable", "partial"):
            with self.subTest(case=case):
                if not self.queue.exists():
                    self.queue.with_suffix(".saved").rename(self.queue)
                result = subprocess.run(["bash", str(self.resume), "--resume"],
                                        env=self.env(case), capture_output=True, timeout=3)
                self.assert_native_failure()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.trace.exists())


if __name__ == "__main__":
    unittest.main()
