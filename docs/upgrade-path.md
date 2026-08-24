# Upgrade path

There are two distinct update boundaries: upstream package updates on an
installed image, and changes to this repository's image policy.

## Installed-system package updates

`noid-update-all.sh` is user-initiated. Its current workflow includes a
pre-change root snapshot when Snapper is available, DNF/Flatpak updates,
selected firmware handling, reapplication of cached browser/mail integration,
consent-gated vendor-channel refreshes of opted-in Claude/Codex components
with recorded version + SHA-256 evidence, an AIDE check against an existing
user-owned baseline and a reboot comparison. It acquires no agent payload
itself, touches no never-opted-in component, and never creates or replaces
the AIDE baseline.
After the RPM transaction it reloads and verifies the physical-link
XDP/TC boundary against the running kernel. Each subsystem reports failure or
skip state; the reminder timer does not install updates by itself.

A newly installed kernel is not the running kernel and cannot be accepted by
its verifier in advance. At the next boot, the topology service loads the
pinned object into that kernel, attaches XDP and TC, and verifies both live
links. NetworkManager has a hard requirement on the independent firewalld,
topology and netdev-L2 baseline. If only XDP/TC is incompatible, those layers
remain active and WAN repair access is retained, while the system publishes a
prominent `DEGRADED` health state. Rebooting into the previous Fedora kernel
from GRUB is the documented full-protection rollback. See
[`hardware-network-compatibility.md`](hardware-network-compatibility.md).

This updates packages and reasserts only the integration explicitly coded in
Module 25. It is not a general migration engine for every later kickstart
change.

## Repository policy changes

Pulling a newer repository revision does not modify an existing installation.
New sysctls, masks, firewall rules, package-set decisions, retention changes or
first-boot helpers normally require a newly built/reinstalled image unless a
specific, reviewed migration is shipped. No generic `noid-diff-apply` tool is
currently provided.

Before reinstalling:

1. Back up user data, credentials and configuration outside the target disk.
2. Build or download the intended release and verify its checksum/signature.
3. Test the ISO and install path in a VM representative of the target layout.
4. Prefer a separate disk/partition when preserving an easy fallback matters.
5. Restore data selectively and re-review LAN/VPN/USB exceptions.

## Fedora major-version changes

An in-place Fedora `system-upgrade` changes upstream packages but cannot
guarantee that the resulting state matches a fresh NoID Privacy compose for the new
base. A Fedora-major migration is supported only when a release explicitly
documents and tests it. Until then, use a verified fresh-install workflow; no
date or version number is promised in advance.

## Component boundaries

| Component | Installed-system mechanism | Boundary |
|---|---|---|
| Fedora RPMs/kernel | user-run DNF via update-all; running-kernel XDP/TC refresh, then boot-time verification by the new kernel | Fedora repository trust; XDP-only rejection is a notified WAN-recovery state, while baseline firewall/topology failure blocks activation |
| Flatpaks | user-run `flatpak update`; explicit `noid-toggle-fedora-flatpaks` stable-OCI opt-in | image-owned Flathub remotes start from one pinned descriptor/key identity; user-added remotes and each app's permissions remain separate trust decisions |
| Firefox/Thunderbird integration | cached source re-deployed by Module 25 | cached pins/config are not automatically replaced by a newer repo revision |
| Claude/Codex CLIs and editor extensions | Update All invokes the M13 helpers' `--update` mode: opted-in components refresh over the vendor channel with identity/structure validation and recorded version + SHA-256 evidence | never-opted-in components stay untouched; install-time pins change only with a reviewed NoID Privacy release. The managed GNOME extension's cached image seed remains exact-pin checked, but an owner-started Update All may replace the installed tree from its fixed EGO identity without an upstream artifact signature; this is the documented mutable-pin exception |
| Firmware | explicit fwupd step/confirmation | vendor/LVFS support and firmware platform trust |
| NoID Privacy kickstart policy | rebuild/reinstall unless a scoped migration exists | not an automatic installed-system feed |

## Rollback

On the expected Btrfs root layout, inspect and select the correct snapshot:

```bash
sudo /usr/libexec/noid-snapper-status
# Continue only when the status reports: boot=ready
sudo snapper -c root list
sudo noid-snap-rollback <snapshot-id>
sudo reboot
```

This rolls back the configured root snapshot boundary, not `/home`, firmware,
external disks, remote accounts or all application state. Confirm the exact
layout and snapshot before relying on it as recovery. Do not proceed when the
status is not `boot=ready`. The wrapper independently requires the native
default-subvolume boot contract and refuses unsafe fstab/future-kernel state;
GRUB does not list snapshots.

Release validation for updates belongs in
[`release-process.md`](release-process.md); structural tests alone do not prove
an installed-system upgrade path.
