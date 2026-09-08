#!/usr/bin/env python3
"""Exercise extracted SWTPM rotation with private files and native logrotate."""
# SPDX-License-Identifier: GPL-3.0-or-later

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


if len(sys.argv) != 2 or os.getuid() == 0:
    raise SystemExit("usage: unprivileged python3 swtpm_rotation.py MODULE_42")
SOURCE = Path(sys.argv[1]).read_text(encoding="utf-8")


def exactly_one(pattern, text):
    matches = re.findall(pattern, text, re.M | re.S)
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one source block: {pattern}")
    return matches[0]


MISC = exactly_one(r"<<'MISC_LOGS_PRUNE_EOF'\n(.*?)\nMISC_LOGS_PRUNE_EOF", SOURCE)
QUOTE = exactly_one(r"^(quote_logrotate_path\(\) \{.*?^\})", MISC)
BLOCK = exactly_one(r"^(SWTPM_ELIGIBLE=0\n.*?)\n# Rotated archives are no longer VM-active", MISC)
BLOCK = BLOCK.replace("SWTPM_LOG_DIR=/var/log/swtpm/libvirt/qemu", 'SWTPM_LOG_DIR="$FIXTURE_ROOT/logs"')
BLOCK = BLOCK.replace("mktemp /tmp/noid-swtpm.conf.XXXXXX", 'mktemp "$FIXTURE_ROOT/tmp/noid-swtpm.conf.XXXXXX"')
BLOCK = BLOCK.replace("mktemp /tmp/noid-swtpm.list.XXXXXX", 'mktemp "$FIXTURE_ROOT/tmp/noid-swtpm.list.XXXXXX"')
BLOCK = BLOCK.replace("/usr/sbin/logrotate --force --state /dev/null", "fixture_logrotate --force --state /dev/null")
ADAPTERS = r'''
set -u
umask 077
LOG_TAG=noid-swtpm-fixture
logger() { :; }
date() { printf '%s\n' "$FIXTURE_DATE"; return "$FIXTURE_DATE_RC"; }
stat() {
    if [ "${1-}:${2-}" = '-c:%C' ]; then
        printf 'system_u:object_r:%s:s0\n' "$FIXTURE_CONTEXT"
    else
        command stat "$@"
    fi
}
id() {
    case "$*" in
        '-u tss') command id -u ;;
        '-g tss') command id -g ;;
        *) command id "$@" ;;
    esac
}
find() {
    command find "$@" || return
    return "$FIXTURE_FIND_RC"
}
cat_calls=0
cat() {
    cat_calls=$((cat_calls + 1))
    if [ "$cat_calls" -eq "$FIXTURE_FAIL_CAT_AT" ]; then
        case "$FIXTURE_CAT_MODE" in
            partial) command head -c 3 ;;
            complete) command cat ;;
        esac
        return 7
    fi
    command cat "$@"
}
mktemp() {
    case "$FIXTURE_ALLOC_FAIL:$*" in
        config:*noid-swtpm.conf.*|list:*noid-swtpm.list.*) return 7 ;;
    esac
    command mktemp "$@"
}
fixture_logrotate() {
    printf 'rotation invoked\n' >> "$FIXTURE_ROOT/calls"
    # SELinux classification is a controlled input above. Actual logrotate
    # uses the unchanged stanza with only its su identity rebound to this
    # ordinary fixture account; no real guest or host log is accessible here.
    sed "s/^    su tss tss$/    su $(command id -un) $(command id -gn)/" "$4" \
        > "$FIXTURE_ROOT/native.conf" || return
    /usr/sbin/logrotate --force --state /dev/null "$FIXTURE_ROOT/native.conf" \
        > "$FIXTURE_ROOT/native.stdout" 2> "$FIXTURE_ROOT/native.stderr"
}
'''


class SwtpmRotation(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="noid-swtpm-rotation.", dir="/var/tmp")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "logs").mkdir()
        (self.root / "tmp").mkdir()
        self.today = subprocess.check_output(["/usr/bin/date", "+%Y%m%d"], text=True).strip()
        self.logs = [self.root / "logs" / name for name in ("first.log", "quoted guest.log")]
        self.reset_fixture()

    def reset_fixture(self):
        for path in (self.root / "logs").iterdir():
            path.unlink()
        for name in ("calls", "native.conf", "native.stdout", "native.stderr"):
            (self.root / name).unlink(missing_ok=True)
        for log in self.logs:
            log.write_text("synthetic marker to retain\n", encoding="ascii")

    def run_rotation(self, **overrides):
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
            "FIXTURE_ROOT": str(self.root), "FIXTURE_DATE": self.today,
            "FIXTURE_DATE_RC": "0", "FIXTURE_CONTEXT": "virt_log_t",
            "FIXTURE_FIND_RC": "0", "FIXTURE_FAIL_CAT_AT": "0",
            "FIXTURE_CAT_MODE": "partial", "FIXTURE_ALLOC_FAIL": "",
            **{key: str(value) for key, value in overrides.items()},
        }
        result = subprocess.run(["bash", "-c", ADAPTERS + QUOTE + "\n" + BLOCK
                                 + '\n[ "$SWTPM_ROTATE_FAILURES" -eq 0 ]\n'],
                                env=environment, capture_output=True, text=True, timeout=20)
        self.assertEqual(list((self.root / "tmp").iterdir()), [], "temporary private names must be retired")
        return result

    def assert_untouched(self):
        self.assertFalse((self.root / "calls").exists(), "incomplete preparation must never invoke rotation")
        for log in self.logs:
            self.assertTrue(log.is_file(), "source must remain present")
            self.assertEqual(log.read_text(), "synthetic marker to retain\n")
            self.assertFalse(Path(str(log) + "-" + self.today).exists())

    def test_complete_configuration_rotates_natively_and_only_once_per_day(self):
        result = self.run_rotation()
        self.assertEqual(result.returncode, 0, result.stderr)
        for log in self.logs:
            self.assertEqual(log.read_text(), "")
            self.assertEqual(Path(str(log) + "-" + self.today).read_text(), "synthetic marker to retain\n")
        repeated = self.run_rotation()
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertEqual((self.root / "calls").read_text(), "rotation invoked\n")

    def test_protected_guest_label_defers_without_rotation(self):
        result = self.run_rotation(FIXTURE_CONTEXT="svirt_image_t")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_untouched()

    def test_unknown_context_is_a_visible_failure(self):
        result = self.run_rotation(FIXTURE_CONTEXT="unrecognized_t")
        self.assertNotEqual(result.returncode, 0)
        self.assert_untouched()

    def test_failed_date_read_never_authorizes_rotation(self):
        for output in (self.today, ""):
            with self.subTest(output_present=bool(output)):
                self.reset_fixture()
                result = self.run_rotation(FIXTURE_DATE=output, FIXTURE_DATE_RC=7)
                self.assertNotEqual(result.returncode, 0)
                self.assert_untouched()

    def test_malformed_date_cannot_escape_the_archive_contract(self):
        for output in ("", "invalid", self.today + "\nextra"):
            with self.subTest(output=output):
                self.reset_fixture()
                result = self.run_rotation(FIXTURE_DATE=output)
                self.assertNotEqual(result.returncode, 0)
                self.assert_untouched()

    def test_failed_stanza_write_discards_the_whole_candidate(self):
        for call in (1, 2):
            for mode in ("partial", "complete"):
                with self.subTest(call=call, mode=mode):
                    self.reset_fixture()
                    result = self.run_rotation(FIXTURE_FAIL_CAT_AT=call, FIXTURE_CAT_MODE=mode)
                    self.assertNotEqual(result.returncode, 0)
                    self.assert_untouched()

    def test_unrepresentable_path_never_publishes_a_partial_candidate(self):
        (self.root / "logs" / "newline\nguest.log").write_text("synthetic extra log\n")
        result = self.run_rotation()
        self.assertNotEqual(result.returncode, 0)
        self.assert_untouched()

    def test_failed_inventory_discards_complete_partial_output(self):
        result = self.run_rotation(FIXTURE_FIND_RC=7)
        self.assertNotEqual(result.returncode, 0)
        self.assert_untouched()

    def test_either_allocation_failure_is_visible_and_cleans_up(self):
        for failure in ("config", "list"):
            with self.subTest(failure=failure):
                self.reset_fixture()
                result = self.run_rotation(FIXTURE_ALLOC_FAIL=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assert_untouched()


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
