# Revert & Uninstall

How to undo NoID Privacy hardening on a running system — partial revert for
specific Modules, full-system unhardening, or complete uninstall.

## Philosophy

Use the supported revert path for the specific feature. Some changes have a
toggle; storage and boot changes need a separate recovery workflow. This page
collects those boundaries and examples for quick reference.

## Tier 1: Partial revert (most common)

### Revert a single Module's hardening

Consult the Module's user doc in `/usr/share/doc/noid-privacy/NN-*.md`.
Check its supported toggle or recovery section before changing shared policy.

Examples:

```bash
# Enable the complete local print stack; verify the resulting state:
sudo noid-toggle-printing on
noid-toggle-printing status
# Restore the default later: sudo noid-toggle-printing off

# Enable Bluetooth through its radio/service policy:
sudo noid-toggle-bluetooth on
noid-toggle-bluetooth status
# Restore the default later: sudo noid-toggle-bluetooth off
```

Printing enables CUPS socket/path activation; discovery stays separately
controlled and network printers need an explicit LAN grant. Bluetooth enables
the radio and service, adding their traffic and attack surface. Review any
reported drift before accepting the result.

Deleting a shared sysctl or dconf file is not a targeted feature revert.
`99-hardening.conf` owns many kernel settings, and removing it does not reset
values already applied to the running kernel. `10-noid-gnome-privacy` owns
desktop privacy and lock defaults; it is not the GNOME Software update policy.
Use the owning module's documented procedure for the intended setting.

A two-command “vanilla firewalld” revert is deliberately not offered. Modules
03, 05 and 06 jointly own zones, policies, nftables/XDP boundaries and
NetworkManager dispatchers; merely changing the default zone leaves those
controls active and can create an inconsistent network posture. Use the owning
Module's reviewed toggle/recovery path for a specific behavior. No reviewed
all-network-unhardening helper is currently shipped; use the full reinstall
boundary below for a broadly vanilla network stack.

### Revert kernel cmdline

No generic blanket command-line revert is shipped. The installed system uses
Fedora BLS plus `/etc/kernel/cmdline`, and several settings have different
owners and recovery boundaries. Editing `/etc/default/grub` followed by a raw
`grub2-mkconfig`, `grubby`, `kernel-install` or `dracut` command can bypass the
shared M21 boot transaction or race a pending Snapper root selection.

Use the exact maintained path in the owning Module's installed guide. Examples
include `noid-toggle-gaming` for its IA32/vDSO32 arguments,
`noid-mei-restore-submodules`/`noid-mei-lockdown` for the MEI policy and
`noid-nvidia-install.sh --rollback` for the proprietary graphics lifecycle.
M01's signature/lockdown and root-storage arguments are boot trust constraints,
not a supported one-command partial revert. For a broadly vanilla kernel
command line, use the documented full reinstall boundary below instead of
guessing a list of flags.

### Revert browser hardening

NoID Privacy publishes Firefox integration across **seven ownership
surfaces**. They are an inventory, not seven independent security boundaries.
Removing only `/usr/share/noid-firefox` leaves active configuration and update
hooks behind.

**Step 1 — backup the profile data (history, bookmarks, cookies):**

Close every Firefox instance, including Playground, before taking the backup.
Keep Firefox closed through Step 2 and continue only after the backup succeeds.

```bash
(
set -euo pipefail
umask 077
firefox_root="${XDG_CONFIG_HOME:-$HOME/.config}/mozilla/firefox"
mkdir -p ~/firefox-backup
tar --xattrs --acls -C "${firefox_root%/firefox}" -cf \
    ~/firefox-backup/firefox-profile-$(date +%Y%m%d-%H%M%S).tar firefox
)
```

**Step 2 — close Firefox + remove the seven owned surfaces:**

```bash
# Surface 1: stop future package-transaction reassertion, then remove the
# NoID Privacy-owned launcher + XDG desktop overlay. Fedora's RPM-owned
# /usr/bin/firefox and /usr/share/applications entry were never patched.
sudo rm -f /etc/dnf/libdnf5-plugins/actions.d/noid-firefox.actions
sudo rm -f /usr/local/bin/noid-firefox-reassert  # /usr/local/sbin is the same directory on Fedora
sudo rm -f /usr/local/bin/firefox
sudo rm -f /usr/local/share/applications/org.mozilla.firefox.desktop

# Surface 2: Mozilla AutoConfig, locale pointer, minimal search policy and
# uBlock managed storage.
sudo rm -f /usr/lib64/firefox/defaults/pref/autoconfig.js
sudo rm -f /usr/lib64/firefox/defaults/pref/noid-locale.js
sudo rm -f /usr/lib64/firefox/mozilla.cfg
sudo rm -f /etc/firefox/policies/policies.json
sudo rmdir /etc/firefox/policies /etc/firefox 2>/dev/null || true
sudo rm -f /usr/lib64/mozilla/managed-storage/uBlock0@raymondhill.net.json

# Surface 3: canonical bundle/cache, Firefox-only helpers and the installed
# arkenfox notice. validate-webextension.py stays: Thunderbird (M35) and Update
# All (M25) share it.
sudo rm -rf /usr/share/noid-firefox
sudo rm -f /usr/local/lib/noid-privacy/firefox-profiles.sh
sudo rm -f /usr/local/lib/noid-privacy/validate-ubo-policy.py
sudo rm -f /usr/local/lib/noid-privacy/verify-firefox-xpi-signature
sudo rm -f /usr/share/licenses/noid-privacy/arkenfox-user.js-MIT.txt

# Surface 4: remove only NoID Privacy-managed user.js files and profile-local uBO
# payloads. Do not delete an unrelated user-authored user.js.
firefox_root="${XDG_CONFIG_HOME:-$HOME/.config}/mozilla/firefox"
find -P "$firefox_root" -mindepth 2 -maxdepth 2 -type f -name user.js \
    -print0 2>/dev/null |
while IFS= read -r -d '' userjs; do
    if grep -qF '*    name: NoID Privacy Workstation — Firefox Hardening' \
            "$userjs"; then
        rm -f -- "$userjs"
    fi
done
find -P "$firefox_root" -mindepth 3 -maxdepth 3 -type f \
    -path '*/extensions/uBlock0@raymondhill.net.xpi' -print0 2>/dev/null |
while IFS= read -r -d '' xpi; do
    rm -f -- "$xpi"
done

# Remove only uBO's NoID Privacy-seeded private-browsing permission record; preserve
# records belonging to other extensions.
python3 - "$firefox_root" <<'PY'
import json
import os
import pathlib
import tempfile
import sys

root = pathlib.Path(sys.argv[1])
for path in root.glob("*/extension-preferences.json"):
    if path.is_symlink() or not path.is_file():
        continue
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or data.pop("uBlock0@raymondhill.net", None) is None:
        continue
    if not data:
        path.unlink()
        continue
    fd, temporary = tempfile.mkstemp(
        prefix=".extension-preferences.json.revert.", dir=path.parent
    )
    try:
        os.fchmod(fd, path.stat().st_mode & 0o777)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
PY

# Surface 5: first-login hooks, M16 helpers, the empty default-bookmarks
# seed and the pre-baked /etc/skel profile that every future account would
# otherwise inherit.
sudo rm -f /etc/xdg/autostart/noid-firefox-setup.desktop
sudo rm -f /usr/local/bin/noid-firefox-setup.sh
sudo rm -f /usr/local/bin/noid-firefox-relax-fpp
sudo rm -f /usr/local/bin/noid-firefox-relax-webrtc
sudo rm -f /usr/local/bin/noid-firefox-drm
sudo rm -f /usr/local/bin/noid-firefox-harden-profile
sudo rm -f /usr/share/bookmarks/default-bookmarks.html
sudo rm -rf /etc/skel/.config/mozilla/firefox

# Surface 6: Playground integration. Preserve the profile directory itself;
# it can contain user data and should be removed only through Profile Manager
# after review.
sudo rm -f /etc/xdg/autostart/noid-firefox-playground-init.desktop
sudo rm -f /usr/local/bin/noid-firefox-playground-init.sh
sudo rm -f /usr/local/bin/noid-firefox-create-isolated-profile
sudo rm -f /usr/share/applications/firefox-playground.desktop
sudo rm -f /etc/dconf/db/distro.d/16-noid-firefox-playground
sudo dconf update

# Surface 7: per-user setup markers and build-time health stamps.
state_root="${XDG_STATE_HOME:-$HOME/.local/state}/noid-privacy"
rm -f "$state_root/firefox-setup.done" \
      "${XDG_CONFIG_HOME:-$HOME/.config}/noid-privacy/firefox-playground-init.done"
sudo rm -f /var/lib/noid-privacy/stamp-16-firefox.ok \
           /var/lib/noid-privacy/stamp-34-firefox-playground.ok

# Refresh application metadata when the helpers are available.
command -v update-desktop-database >/dev/null &&
    sudo update-desktop-database /usr/local/share/applications /usr/share/applications
```

The copied language XPIs under
`/usr/lib64/firefox/distribution/extensions/` are locale support rather than a
hardening control. They are intentionally left in place: deleting a glob there
cannot distinguish every future package/user-owned extension safely.

**Step 3 — verify the ownership boundary and create a stock profile:**

```bash
# Fedora-owned inputs must still verify; a normal NoID Privacy revert does not require
# reinstalling Firefox.
rpm -Vf /usr/bin/firefox
rpm -Vf /usr/share/applications/org.mozilla.firefox.desktop
rpm -Vf /usr/lib64/firefox/distribution/distribution.ini

# Existing profiles can retain values previously copied into prefs.js even
# after user.js and AutoConfig are removed. For a guaranteed stock preference
# state, create a new profile and selectively import the backed-up user data.
/usr/bin/firefox --ProfileManager
```

In the new profile, `about:policies` must no longer show the NoID Privacy
DuckDuckGo policy, and `about:addons` must not contain the removed profile-local
uBlock install. Existing profiles are preserved for recovery; deleting them is
a separate user-data decision.

## Tier 2: Full unhardening (less common)

### No interactive unhardening helper is shipped

The image ships no interactive helper that enumerates Module decisions and
reverts them selectively. Full unhardening is a manual, per-Module procedure:
create a pre-revert Snapper snapshot first, follow each Module's revert
section, and keep AIDE evidence for a separate user-owned candidate review.

### Manual full unhardening

No reviewed full-unhardening artifact is currently shipped. Do not use globbed
`rm`, broad `systemctl disable noid-*`, or a guessed list of unit masks as a
substitute: those operations can remove unrelated/user-owned paths, omit module
state and destroy the evidence needed to diagnose a partial revert.

For a deterministic vanilla state, back up user data and reinstall from
independently verified Fedora media. For a partial revert, use the exact
per-module guide, record the before/after bytes and unit state, and verify the
module's postconditions before proceeding to the next one. Preserve the active
AIDE database and reports while changes are being reviewed; do not overwrite
the database merely because the expected revert produced differences.

## Tier 3: Complete uninstall

NoID Privacy is installed as part of an ISO-based install. There is no
"uninstall" action per se — the system stays running. For a clean
state, either:

- Full unhardening (Tier 2 above) — brings to vanilla-ish Fedora 44
  state while preserving data.
- Fresh install of vanilla Fedora 44 from independently verified media — the
  cleanest supported way to remove NoID Privacy configuration, but not a guarantee
  about firmware, retained user data, backups or installation media.

## Recovery paths

### If unhardening breaks the system

```bash
(
set -euo pipefail
snapshot_id="${NOID_SNAPSHOT_ID:?export NOID_SNAPSHOT_ID with the reviewed pre-unhardening snapshot number}"
sudo snapper -c root list
sudo noid-snap-rollback "$snapshot_id"
sudo reboot
)
```

### If you accidentally removed something critical

```bash
(
set -euo pipefail
snapshot_id="${NOID_SNAPSHOT_ID:?export NOID_SNAPSHOT_ID with the reviewed snapshot number}"
# Check snapper list for a recent snapshot
sudo snapper -c root list
sudo noid-snap-rollback "$snapshot_id"
sudo reboot
)
```

These commands apply only when the checked NoID Privacy boot model was ready and the
snapshot existed before the change. The wrapper refuses snapshots whose fstab
or future-kernel command line predates that model.

### If AIDE alerts during unhardening

Expected changes still require review; their scale does not make them trusted.
Keep the report and package/change records. If the system still has the NoID Privacy
workflow and the user deliberately chooses a new trust boundary:

```bash
sudo noid-aide-baseline-review prepare
# Review the candidate report and metadata yourself, then use the tool's
# exact SHA-256 commit flow. Do not copy aide.db.new.gz into place directly.
```

## Storage and firmware require separate recovery workflows

- **LUKS2 FDE** — partition-level; removing it safely requires a verified
  backup, reinstall/repartition or reformat, and selective data restoration.
  Closing a currently unused mapping does not decrypt the on-disk container.
- **Btrfs subvolume layout** — tied to the checked boot and rollback model.
  This guide supplies no in-place layout migration; a backed-up reinstall is
  the supported path to a different layout.
- **Secure Boot mode and enrolled keys** — separate firmware and trust-store
  settings. Removing NoID Privacy files does not undo them; inspect firmware
  setup and the applicable key-enrollment procedure.
- **GRUB stub at `/boot/efi/EFI/fedora/grub.cfg`** — a bootloader artifact,
  not an application setting. Use the installer or supported boot recovery
  procedure rather than deleting it from a running installation.

A reinstall does not itself reset firmware settings or enrolled keys.

## Feedback + contribution

If you've done an unhardening migration and have edge-case notes,
please open a PR to this doc or file an issue. Real-world unhardening
stories help improve the experience.
