#!/usr/bin/python3
"""Exercise extracted production code; no network, sudo or real profiles."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
M16 = (ROOT / "kickstart/snippets/16-firefox.ks").read_text()
M25 = (ROOT / "kickstart/snippets/25-update-process.ks").read_text()
M35 = (ROOT / "kickstart/snippets/35-thunderbird.ks").read_text()


def heredoc(text, marker):
    return text.split("<<'" + marker + "'\n", 1)[1].split("\n" + marker, 1)[0] + "\n"


def function(text, name, following):
    return text[text.index(name + "() {"):text.index(following, text.index(name + "() {"))]


class Recovery(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="noid-extension-recovery.", dir="/var/tmp")
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.validator = self.work / "validator"
        self.validator.write_text(heredoc(M16, "WEBEXT_VALIDATOR_PYEOF"))
        self.validator.chmod(0o755)
        self.identity = "dkim_verifier@pl"
        self.old = self.xpi("old.xpi", "6.3.0", "153.*")
        self.new = self.xpi("new.xpi", "6.4.0", "155.*")

    def xpi(self, name, version, maximum, identity=None):
        path = self.work / name
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("manifest.json", json.dumps({"manifest_version": 2,
                "version": version, "applications": {"gecko": {
                    "id": identity or self.identity, "strict_min_version": "128.0",
                    "strict_max_version": maximum}}}))
        path.chmod(0o644)
        return path

    def metadata(self, archive, maximum="*", **changes):
        with zipfile.ZipFile(archive) as z:
            version = json.loads(z.read("manifest.json"))["version"]
        entry = {"version": version,
                 "update_hash": "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest(),
                 "applications": {"gecko": {"strict_min_version": "128.0", "strict_max_version": maximum}}}
        entry.update(changes)
        path = self.work / (archive.name + ".json")
        path.write_text(json.dumps({"addons": {self.identity: {"updates": [entry]}}}))
        path.chmod(0o644)
        return path

    def validate(self, archive, product="155.0", metadata="-"):
        return subprocess.run([str(self.validator), str(archive), self.identity, "-", "0",
                               product, "0", str(metadata)], capture_output=True, text=True)

    def test_exact_override_and_negative_controls(self):
        self.assertEqual(self.validate(self.old, "153.0.2").returncode, 0)
        self.assertNotEqual(self.validate(self.old).returncode, 0)
        self.assertEqual(self.validate(self.old, metadata=self.metadata(self.old)).returncode, 0)
        wrong = self.metadata(self.old, update_hash="sha256:" + "0" * 64)
        self.assertNotEqual(self.validate(self.old, metadata=wrong).returncode, 0)
        wrong = self.metadata(self.old, version="6.2.0")
        self.assertNotEqual(self.validate(self.old, metadata=wrong).returncode, 0)
        bounded = self.metadata(self.old, maximum="154.*")
        self.assertNotEqual(self.validate(self.old, metadata=bounded).returncode, 0)
        self.assertEqual(self.validate(self.old, metadata=self.metadata(self.old, "155.*")).returncode, 0)

    def test_metadata_never_masks_identity_or_archive_failure(self):
        metadata = self.metadata(self.old)
        foreign = self.xpi("foreign.xpi", "6.3.0", "153.*", "wrong@example.org")
        self.assertNotEqual(self.validate(foreign, metadata=metadata).returncode, 0)
        link = self.work / "metadata-link"
        link.symlink_to(metadata)
        self.assertNotEqual(self.validate(self.old, metadata=link).returncode, 0)
        self.old.write_bytes(b"not an archive")
        self.assertNotEqual(self.validate(self.old, metadata=metadata).returncode, 0)

    def refresh(self, candidate, current=None, availability=False, seed_compatible=False):
        seed_metadata = self.metadata(self.old, "*" if seed_compatible else "153.*")
        candidate_metadata = self.metadata(candidate)
        # If candidate is the seed, preserve separate old/new compatibility records.
        if candidate == self.old and not seed_compatible:
            seed_metadata = self.work / "old-compat.json"
            seed_metadata.write_text(candidate_metadata.read_text().replace('"*"', '"153.*"'))
        current_path, dst = self.work / "current.xpi", self.work / "active.xpi"
        if current:
            current_path.write_bytes(current.read_bytes())
            dst.write_bytes(current.read_bytes())
        body = function(M25, "refresh_managed_dkim", "# Keep the real profile")
        for old, new in {
            "/usr/share/noid-thunderbird/dkim-compatibility.json": seed_metadata,
            "/var/lib/noid-privacy/managed-extensions/dkim-compatibility.json": self.work / "current.json",
            "/usr/lib64/thunderbird/distribution/extensions/dkim_verifier@pl.xpi": dst,
        }.items():
            body = body.replace(old, str(new))
        helpers = function(M25, "payload_matches", "WEBEXT_VALIDATOR=")
        helpers += function(M25, "numeric_version_is_newer", "ubo_candidate_action()")
        variables = {"WEBEXT_VALIDATOR": self.validator, "TB_DKIM_SEED": self.old,
                     "TB_DKIM_SEED_VERSION": "6.3.0", "TB_DKIM_CURRENT": current_path,
                     "CANDIDATE": candidate, "METADATA": candidate_metadata,
                     "WORK": self.work}
        script = "set -euo pipefail\n" + "\n".join(k + "=" + shlex.quote(str(v)) for k, v in variables.items())
        script += '''
RED= GREEN= YELLOW= NC= TB_DKIM_SOURCE= TB_DKIM_SOURCE_VERSION= TB_DKIM_SOURCE_SHA256=
ERRORS=0 WARNINGS=0 tb_actions=0
DEFERRED_LIST=()
trusted_root_file() { [ -f "$1" ] && [ ! -L "$1" ]; }
sudo() { printf '%s\n' 155.0; }
cleanup_latest_xpi() { :; }
record_extension_check() { printf '%s\n' "$2" > "$WORK/check"; }
record_extension_update() { :; }
publish_managed_dkim_xpi() { cp "$1" "$2"; }
fetch_latest_xpi() {
 touch "$WORK/fetched"
 LATEST_XPI_ERROR_CLASS=availability
 LATEST_XPI_ERROR=offline
 AVAILABILITY_COMMAND
 LATEST_XPI_PATH=$CANDIDATE
 LATEST_XPI_COMPATIBILITY=$METADATA
 LATEST_XPI_SHA256=$(sha256sum "$CANDIDATE" | awk '{print $1}')
 LATEST_XPI_VERSION=$("$WEBEXT_VALIDATOR" "$CANDIDATE" dkim_verifier@pl - 0 -)
}
'''.replace("AVAILABILITY_COMMAND", "return 1" if availability else ":")
        script += helpers + body + "\nrefresh_managed_dkim\n"
        run = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        return run, current_path, dst

    def test_expired_seed_and_current_can_advance(self):
        run, current, active = self.refresh(self.new, current=self.old)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual(current.read_bytes(), self.new.read_bytes())
        self.assertEqual(active.read_bytes(), self.new.read_bytes())
        self.assertTrue((self.work / "fetched").exists())

    def test_equal_version_compatibility_only_repair(self):
        run, current, _ = self.refresh(self.old, current=self.old)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual(current.read_bytes(), self.old.read_bytes())
        self.assertEqual((self.work / "check").read_text().strip(), "updated")

    def test_no_downgrade_from_newer_incompatible_bytes(self):
        newer = self.xpi("newer.xpi", "6.5.0", "153.*")
        run, current, _ = self.refresh(self.new, current=newer)
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(current.read_bytes(), newer.read_bytes())

    def test_offline_compatible_fallback_and_incompatible_failure(self):
        run, _, _ = self.refresh(self.new, availability=True, seed_compatible=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual((self.work / "check").read_text().strip(), "failed")
        run, _, _ = self.refresh(self.new, availability=True)
        self.assertNotEqual(run.returncode, 0)

    def test_offline_never_downgrades_newer_incompatible_current(self):
        newer = self.xpi("newer.xpi", "6.5.0", "153.*")
        run, current, _ = self.refresh(self.new, current=newer,
                                       availability=True, seed_compatible=True)
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(current.read_bytes(), newer.read_bytes())

    def test_generic_extension_replaces_incompatible_old_bytes(self):
        profile = self.work / "profile"
        (profile / "extensions").mkdir(parents=True)
        target = profile / "extensions" / (self.identity + ".xpi")
        target.write_bytes(self.old.read_bytes())
        metadata = self.metadata(self.new)
        variables = {"WEBEXT_VALIDATOR": self.validator, "WORK": self.work,
                     "TARGET": target, "CANDIDATE": self.new, "METADATA": metadata}
        script = "set -euo pipefail\n" + "\n".join(
            k + "=" + shlex.quote(str(v)) for k, v in variables.items())
        script += '''
RED= GREEN= YELLOW= NC= ERRORS=0 WARNINGS=0
DEFERRED_LIST=()
THUNDERBIRD_COMPATIBILITY=native_fixture
native_fixture() { [ "$3" = 6.4.0 ]; }
browser_extension_inventory() { printf 'dkim_verifier@pl\\t6.3.0\\t%s\\tfixture\\n' "$TARGET" > "$2"; }
sudo() { printf '%s\\n' 155.0; }
record_extension_update() { :; }
record_extension_check() { printf '%s\\n' "$2" > "$WORK/check"; }
cleanup_marketplace_xpi() { :; }
atomic_install_profile_xpi() { cp "$1" "$2"; }
fetch_marketplace_xpi() {
 MARKETPLACE_PATH=$CANDIDATE
 MARKETPLACE_VERSION=6.4.0
 MARKETPLACE_SHA256=$(sha256sum "$CANDIDATE" | awk '{print $1}')
 MARKETPLACE_COMPATIBILITY=$METADATA
}
'''
        script += function(M25, "payload_matches", "WEBEXT_VALIDATOR=")
        script += function(M25, "numeric_version_is_newer", "ubo_candidate_action()")
        script += function(M25, "update_marketplace_extensions", "publish_managed_dkim_xpi()")
        script += '\nupdate_marketplace_extensions thunderbird atn\n[ "$ERRORS" -eq 0 ]\n'
        run = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual(target.read_bytes(), self.new.read_bytes())
        self.assertEqual((self.work / "check").read_text().strip(), "updated")

    def test_reassert_can_use_current_when_seed_has_expired(self):
        seed_meta = self.metadata(self.old, "153.*")
        current_meta = self.metadata(self.new)
        active = self.work / "active.xpi"
        body = M35.split("# DKIM Verifier: restore from", 1)[1]
        body = "# DKIM Verifier: restore from" + body.split('if [ "$autoconfig_changed"', 1)[0]
        replacements = {
            "/usr/local/lib/noid-privacy/validate-webextension.py": self.validator,
            "/usr/share/noid-thunderbird/dkim_verifier.xpi": self.old,
            "/var/lib/noid-privacy/managed-extensions/dkim_verifier@pl.xpi": self.new,
            "/usr/lib64/thunderbird/distribution/extensions/dkim_verifier@pl.xpi": active,
            "/usr/share/noid-thunderbird/dkim-compatibility.json": seed_meta,
            "/var/lib/noid-privacy/managed-extensions/dkim-compatibility.json": current_meta,
            "5ae95b4d560257b2e5722e1d3824a4031fb74d5d57b790dfc12f76a11dc1501a":
                hashlib.sha256(self.old.read_bytes()).hexdigest(),
            "0:0:644:1": f"{os.getuid()}:{os.getgid()}:644:1",
        }
        for old, new in replacements.items():
            body = body.replace(old, str(new))
        script = '''set -euo pipefail
fail() { printf '%s\\n' "$*" >&2; exit 1; }
rpm() { printf '%s\\n' 155.0; }
logger() { :; }
publish_managed_file() { cp "$1" "$2"; }
''' + body
        run = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual(active.read_bytes(), self.new.read_bytes())


if __name__ == "__main__":
    unittest.main(verbosity=2)
