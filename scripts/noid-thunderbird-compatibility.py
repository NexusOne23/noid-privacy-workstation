#!/usr/bin/python3
"""Apply a digest-bound marketplace compatibility update through Thunderbird.

Usage: noid-thunderbird-compatibility ARCHIVE ID VERSION PRODUCT_VERSION METADATA [PROFILE]
Without PROFILE, verify in a disposable profile. With PROFILE, update only the
matching installed add-on's compatibility through Addon.findUpdates. The worker
has no network, session bus or writable system files. Its temporary AutoConfig
never changes the installed AutoConfig sandbox or the user's update preferences.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("expected one regular file")
    return info


def main():
    if len(sys.argv) not in {6, 7} or os.getuid() == 0:
        raise ValueError(__doc__.splitlines()[2])
    archive, identity, version, product_version, metadata = sys.argv[1:6]
    if not re.fullmatch(r"[A-Za-z0-9{][A-Za-z0-9._+@{}-]{0,254}", identity):
        raise ValueError("invalid extension identity")
    validator = "/usr/local/lib/noid-privacy/validate-webextension.py"
    subprocess.run([validator, archive, identity, version, "0", product_version,
                    "1", metadata], check=True, stdout=subprocess.DEVNULL)
    archive = Path(archive).resolve(strict=True)
    regular(archive)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    supplied = json.loads(Path(metadata).read_text())
    updates = supplied["addons"][identity]["updates"]
    matches = [entry for entry in updates if entry["version"] == version
               and entry.get("update_hash") == "sha256:" + digest]
    if len(matches) != 1:
        raise ValueError("compatibility record is not bound to the archive")
    # Exclude update_link: this worker may apply compatibility, never install
    # executable updates or contact an origin carried by marketplace metadata.
    update = {key: matches[0][key] for key in
              ("version", "update_hash", "applications")}
    with tempfile.TemporaryDirectory(prefix="noid-tb-compat.", dir="/var/tmp") as tmp:
        work = Path(tmp)
        for name in ("home", "config", "cache", "runtime", "profile"):
            (work / name).mkdir(mode=0o700)
        actual_profile = len(sys.argv) == 7
        if actual_profile:
            original = Path(sys.argv[6])
            profile = original.resolve(strict=True)
            if original != profile or profile.stat().st_uid != os.getuid() \
                    or not profile.is_dir():
                raise ValueError("unsafe profile directory")
            installed = profile / "extensions" / (identity + ".xpi")
            if regular(installed).st_uid != os.getuid() \
                    or hashlib.sha256(installed.read_bytes()).hexdigest() != digest:
                raise ValueError("profile extension differs from validated archive")
            database = profile / "extensions.json"
            if database.is_file() and not database.is_symlink():
                records = json.loads(database.read_text()).get("addons", [])
                matching = [item for item in records if item.get("id") == identity
                            and item.get("version") == version]
                bounds = update["applications"]["gecko"]
                if len(matching) == 1:
                    addon = matching[0]
                    applications = addon.get("targetApplications", [])
                    if addon.get("appDisabled") is False \
                            and (addon.get("userDisabled") is True or addon.get("active") is True) \
                            and addon.get("path") == str(installed) and any(
                            item.get("id") == "toolkit@mozilla.org"
                            and item.get("minVersion") == bounds["strict_min_version"]
                            and item.get("maxVersion") == bounds["strict_max_version"]
                            for item in applications):
                        print(version)
                        return
            # The native profile lock remains the final arbiter of concurrent
            # browser use; never remove or bypass it.
        else:
            profile = work / "profile"
            (profile / "extensions").mkdir(mode=0o700)
            shutil.copyfile(archive, profile / "extensions" / (identity + ".xpi"))
        (work / "updates.json").write_text(json.dumps({"addons": {
            identity: {"updates": [update]}}}))
        (work / "autoconfig.js").write_text(
            'pref("general.config.filename", "mozilla.cfg");\n'
            'pref("general.config.obscure_value", 0);\n'
            'pref("general.config.sandbox_enabled", false);\n')
        result = work / "result.json"
        values = json.dumps({"id": identity, "version": version,
                             "url": (work / "updates.json").as_uri(),
                             "result": str(result), "fresh": not actual_profile})
        base = Path("/usr/share/noid-thunderbird/mozilla.cfg").read_text()
        code = r'''
// One-shot worker, mounted only inside the network-isolated process.
(function () {
 const job = JOB_VALUES;
 function finish(value) {
  const file = Components.classes["@mozilla.org/file/local;1"].createInstance(Components.interfaces.nsIFile);
  file.initWithPath(job.result);
  const out = Components.classes["@mozilla.org/network/file-output-stream;1"].createInstance(Components.interfaces.nsIFileOutputStream);
  const text = JSON.stringify(value);
  out.init(file, 0x02|0x08|0x20, 384, 0); out.write(text, text.length); out.close();
  Services.startup.quit(Components.interfaces.nsIAppStartup.eForceQuit);
 }
 if (job.fresh) defaultPref("extensions.autoDisableScopes", 0);
 Services.obs.addObserver(function ready() {
  Services.obs.removeObserver(ready, "final-ui-startup");
  (async () => {
   try {
    const {AddonManager} = ChromeUtils.importESModule("resource://gre/modules/AddonManager.sys.mjs");
    const addon = await AddonManager.getAddonByID(job.id);
    if (!addon || addon.version !== job.version) throw new Error("native add-on identity mismatch");
    const disabled = addon.userDisabled;
    const key = "extensions.update.url";
    if (Services.prefs.prefIsLocked(key)) throw new Error("update URL is user-locked");
    const hadUser = Services.prefs.prefHasUserValue(key);
    const old = Services.prefs.getStringPref(key);
    let done;
    try {
     Services.prefs.setStringPref(key, job.url);
     done = new Promise((resolve, reject) => addon.findUpdates({
      onUpdateFinished(a, status) { status === 0 ? resolve() : reject(new Error("native update status " + status)); }
     }, AddonManager.UPDATE_WHEN_USER_REQUESTED));
    } finally {
     if (hadUser) Services.prefs.setStringPref(key, old); else Services.prefs.clearUserPref(key);
    }
    await done;
    if (!addon.isCompatible || addon.userDisabled !== disabled || (!disabled && !addon.isActive))
     throw new Error("native compatibility/activation postcondition failed");
    finish({ok: true, id: addon.id, version: addon.version});
   } catch (error) { finish({ok: false, error: String(error)}); }
  })();
 }, "final-ui-startup");
})();
'''.replace("JOB_VALUES", values)
        (work / "mozilla.cfg").write_text(base + code)
        command = ["/usr/bin/bwrap", "--unshare-all", "--die-with-parent",
                   "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
                   "--tmpfs", "/home", "--tmpfs", "/run",
                   "--bind", str(work), str(work)]
        if actual_profile:
            command += ["--bind", str(profile), str(profile)]
        for source, destination in [
            ("autoconfig.js", "/usr/lib64/thunderbird/defaults/pref/autoconfig.js"),
            ("mozilla.cfg", "/usr/lib64/thunderbird/mozilla.cfg")]:
            command += ["--ro-bind", str(work / source), destination]
        for key, directory in [("HOME", "home"), ("XDG_CONFIG_HOME", "config"),
                               ("XDG_CACHE_HOME", "cache"), ("XDG_RUNTIME_DIR", "runtime")]:
            command += ["--setenv", key, str(work / directory)]
        for key in ("DBUS_SESSION_BUS_ADDRESS", "DISPLAY", "WAYLAND_DISPLAY"):
            command += ["--unsetenv", key]
        command += ["/usr/lib64/thunderbird/thunderbird", "--headless", "--no-remote",
                    "--profile", str(profile)]
        # timeout kills the complete namespace if native shutdown stalls.
        run = subprocess.run(["/usr/bin/timeout", "-k", "3s", "30s", *command],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if run.returncode or not result.is_file():
            raise ValueError("isolated native compatibility worker failed or timed out")
        verdict = json.loads(result.read_text())
        if verdict != {"ok": True, "id": identity, "version": version}:
            raise ValueError(verdict.get("error", "invalid native verdict"))
        print(version)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f"Thunderbird compatibility: {exc}", file=sys.stderr)
        sys.exit(1)
