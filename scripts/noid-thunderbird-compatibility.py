#!/usr/bin/python3
"""Apply a digest-bound marketplace compatibility update through Thunderbird.

Usage: noid-thunderbird-compatibility ARCHIVE ID VERSION PRODUCT_VERSION METADATA [PROFILE]
Without PROFILE, verify in a disposable profile. With PROFILE, update only the
matching installed add-on's compatibility through Addon.findUpdates. The worker
has no network, session bus or writable system files. Its temporary AutoConfig
never changes the installed AutoConfig sandbox or the user's update preferences.
"""

import hashlib
import configparser
import json
import os
from pathlib import Path
import pwd
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


def main(arguments=None, *, initialize=False):
    arguments = sys.argv[1:] if arguments is None else arguments
    if len(arguments) not in {5, 6} or os.getuid() == 0:
        raise ValueError(__doc__.splitlines()[2])
    archive, identity, version, product_version, metadata = arguments[:5]
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
        actual_profile = len(arguments) == 6
        if actual_profile:
            original = Path(arguments[5])
            profile = original.resolve(strict=True)
            if original != profile or profile.stat().st_uid != os.getuid() \
                    or not profile.is_dir():
                raise ValueError("unsafe profile directory")
            installed = profile / "extensions" / (identity + ".xpi")
            database = profile / "extensions.json"
            if initialize:
                # Let Thunderbird's native distribution installer create the
                # first add-on record, including its native opt-out state.
                # Never reinstall an extension removed from an existing profile.
                if installed.exists() or installed.is_symlink() \
                        or database.exists() or database.is_symlink():
                    raise ValueError("initial profile acquired extension state")
            elif regular(installed).st_uid != os.getuid() \
                    or hashlib.sha256(installed.read_bytes()).hexdigest() != digest:
                raise ValueError("profile extension differs from validated archive")
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


def startup(arguments):
    """Prepare only the managed canonical profile selected by the launcher.

    This is an offline part of a user-requested browser launch. Profile manager,
    diagnostics, missing profiles, removed add-ons and foreign/newer payloads
    retain Thunderbird's normal behavior. No extension database is rewritten.
    """
    selected = []
    for index, argument in enumerate(arguments):
        flag = argument.lower()
        if flag in {"-profilemanager", "--profilemanager", "-createprofile",
                    "--createprofile", "--help", "-h", "--version", "-v",
                    "--full-version"}:
            return
        if flag in {"-p", "-profile", "--profile"}:
            if index + 1 == len(arguments):
                return
            selected.append((flag, arguments[index + 1]))
    if len(selected) != 1 or selected[0] != ("-p", "default-release"):
        return
    uid = os.getuid()
    if uid == 0:
        raise ValueError("launch Thunderbird as the desktop user")
    home = Path(pwd.getpwuid(uid).pw_dir)
    if os.environ.get("HOME") != str(home):
        raise ValueError("HOME differs from the account database")
    root = home / ".thunderbird"
    profile = root / "default-release"
    for directory in (home, root, profile):
        try:
            info = directory.lstat()
        except FileNotFoundError:
            if directory == home:
                raise
            return  # A user may reset the profile; let Thunderbird handle it.
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid \
                or info.st_mode & 0o022 or directory.resolve(strict=True) != directory:
            raise ValueError("unsafe managed profile directory")
    registry = root / "profiles.ini"
    try:
        info = regular(registry)
    except FileNotFoundError:
        return
    if info.st_uid != uid or info.st_mode & 0o022:
        raise ValueError("unsafe managed profile registry")
    config = configparser.ConfigParser(interpolation=None)
    config.read_string(registry.read_text())
    matches = [config[section] for section in config.sections()
               if section.startswith("Profile")
               and config[section].get("Name") == "default-release"]
    if len(matches) != 1 or matches[0].get("IsRelative") != "1" \
            or matches[0].get("Path") != "default-release":
        return
    identity = "dkim_verifier@pl"
    installed = profile / "extensions" / (identity + ".xpi")
    database = profile / "extensions.json"
    initial = not database.exists() and not database.is_symlink() \
        and not installed.exists() and not installed.is_symlink()
    if not initial and not installed.exists() and not installed.is_symlink():
        return  # Respect native removal from an initialized profile.
    archive = Path("/usr/lib64/thunderbird/distribution/extensions") / (identity + ".xpi")
    info = regular(archive)
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("unsafe distribution extension")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if not initial:
        info = regular(installed)
        if info.st_uid != uid or info.st_mode & 0o022:
            raise ValueError("unsafe profile extension")
        if hashlib.sha256(installed.read_bytes()).hexdigest() != digest:
            return  # Preserve a different user-owned or newer extension.
    # A second window must keep using an already running Thunderbird. Native
    # profile locking remains authoritative if a process starts after this probe.
    query = subprocess.run(["/usr/bin/pgrep", "-u", str(uid), "-x",
                            "thunderbird|thunderbird-bin"],
                           capture_output=True, text=True, timeout=10)
    if query.returncode == 0:
        if not query.stdout or any(not re.fullmatch(r"[1-9][0-9]*", line)
                                   for line in query.stdout.splitlines()):
            raise ValueError("invalid Thunderbird process inventory")
        for pid in query.stdout.splitlines():
            try:
                executable = Path(os.readlink(f"/proc/{pid}/exe"))
            except FileNotFoundError:
                continue  # Exited process or zombie; no profile owner remains.
            if executable in {Path("/usr/lib64/thunderbird/thunderbird"),
                              Path("/usr/lib64/thunderbird/thunderbird-bin")}:
                return
        # A shell launcher is itself named thunderbird. It must not make its
        # own child skip the first-launch preparation before the native exec.
    elif query.returncode != 1 or query.stdout:
        raise ValueError("cannot establish Thunderbird process absence")
    for metadata in (Path("/var/lib/noid-privacy/managed-extensions/dkim-compatibility.json"),
                     Path("/usr/share/noid-thunderbird/dkim-compatibility.json")):
        if not metadata.exists() and not metadata.is_symlink():
            continue
        info = regular(metadata)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("unsafe compatibility record")
        updates = json.loads(metadata.read_text())["addons"][identity]["updates"]
        candidates = [item for item in updates
                      if item.get("update_hash") == "sha256:" + digest]
        if len(candidates) != 1:
            continue
        version = candidates[0]["version"]
        product = subprocess.run(["/usr/bin/rpm", "-q", "--qf", "%{VERSION}",
                                  "thunderbird"], check=True, capture_output=True,
                                 text=True, timeout=10).stdout
        main([str(archive), identity, version, product, str(metadata), str(profile)],
             initialize=initial)
        return
    raise ValueError("no digest-bound compatibility record for the distribution extension")


if __name__ == "__main__":
    try:
        if sys.argv[1:2] == ["--startup"]:
            startup(sys.argv[2:])
        else:
            main()
    except (OSError, ValueError, KeyError, configparser.Error,
            subprocess.SubprocessError) as exc:
        print(f"Thunderbird compatibility: {exc}", file=sys.stderr)
        sys.exit(1)
