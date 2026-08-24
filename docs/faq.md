# FAQ

## Why another hardened Linux distro?

NoID Privacy targets a gap between:

- Minimal-surface "secure" distros that break daily-driver workflow
  (Tails is amnesic, Qubes needs dedicated HW, Whonix routes all
  traffic through Tor).
- Vanilla Fedora, whose general-purpose defaults intentionally retain more
  discovery, integration and browser behavior than this project's threat model.

NoID Privacy is a daily-driver desktop with defense in depth.

## How much of Fedora do I lose?

Several user-facing integrations are intentionally disabled, removed or made
opt-in: printing/discovery, Bluetooth, location, some GNOME services, server
features, 32-bit gaming compatibility and others. Flatpak, Firefox, Thunderbird,
VSCodium and ordinary development tools remain available, but compatibility is
workload- and hardware-dependent. Use the documented helpers instead of assuming
that unmasking one unit fully restores a feature.

## Can I install NoID Privacy on an existing Fedora system?

Partially. See [`docs/migration-from-vanilla.md`](migration-from-vanilla.md).
Full parity is not promised by in-place migration; encryption and storage layout
also depend on Anaconda choices.

## Does NoID Privacy work on AMD CPUs?

Yes. Module 15 (Intel ME) is inert on AMD — the module blacklist has
nothing to match, the udev PCI rule has no Intel ME to block. Module
15 ships an AMD-PSP hardware-layer doc at
`/usr/share/doc/noid-privacy/15-amd-psp-hardware-layer.md`.

## Does NoID Privacy work on laptops?

Laptops are a primary target, not a universal compatibility guarantee. NoID Privacy
does not force a backlight driver or suspend mode from the broad SMBIOS chassis
class: the kernel, firmware and maintained model-specific quirks choose those
defaults. Apply `acpi_backlight=` or `mem_sleep_default=` only as a reversible,
device-specific workaround after reproducing and measuring the actual failure.

## What about NVIDIA?

By design, this image does NOT install proprietary NVIDIA drivers at
build. Module 19 ships user documentation at
`/usr/share/doc/noid-privacy/19-nvidia-drivers.md` that explains:

- Which cards work with Fedora's open NVIDIA graphics stack
  (nouveau / NVK).
- When the user should install `akmod-nvidia` from RPM Fusion.
- How nouveau is blacklisted on the **kernel command line** (via grubby:
  `rd.driver.blacklist=nouveau,nova_core modprobe.blacklist=nouveau,nova_core`),
  and how the nvidia module is baked into the initramfs. (NoID Privacy does NOT
  create `/etc/modprobe.d/nvidia.conf` or `blacklist-nouveau.conf` — DRM
  modeset is the driver default. Dracut uses both the RPM Fusion vendor's
  `99-nvidia-dracut.conf` omit-file and NoID Privacy's conditional
  `/etc/dracut.conf.d/99-noid-nvidia-initramfs.conf` add-drivers override.)
- AIDE drift review after install; no installer or driver helper replaces the
  active integrity baseline.

Post-install users should run the shipped `noid-nvidia-install.sh` workflow.
It detects the supported driver branch, creates the akmods signing key before
the module build, verifies the built module/signature and guides MOK enrollment.
A bare `dnf install akmod-nvidia` is not claimed to complete that Secure Boot
workflow safely on every machine.

## Why no Steam in the default?

- Steam brings a substantial 32-bit/multilib and third-party runtime surface and a
  potential fingerprinting surface.
- Users who want Steam enable **Gaming-Mode** (Setup app toggle or
  `sudo noid-toggle-gaming on`) — it changes the two repository-managed
  compatibility settings. After the required reboot, Setup's completion row
  (or the same CLI command) installs Steam from RPM Fusion while i686 execution
  is live. The Steam Flatpak is community-maintained (not publisher-verified), so the RPM is the
  delivery path — see [`docs/gaming.md`](gaming.md).

## Why not use Flatpak for everything?

- GNOME itself, NetworkManager, firewalld, kernel, systemd are all
  system-level, not Flatpak-packageable.
- Firefox is RPM for privacy reasons (the locally maintained NoID Privacy
  Firefox Hardening derivative of the arkenfox v144.0 snapshot, plus uBO
  managed-storage integration, is simpler with the RPM than the Flatpak).
- Flatpak for user-space apps (Signal, LibreOffice, etc.) is the
  recommended pattern.

## Is VSCodium shipped by default?

Yes, via Module 08. It's RPM-installed from the paulcarroty repo with
GPG verification (`gpgcheck=1` + `repo_gpgcheck=1`). VSCodium removes
Microsoft's branding and telemetry from its VS Code build. Installed
extensions remain separate vendor code and privacy boundaries; VSCodium's
build choice does not make every extension private or trusted.

## What about Mesa / nouveau / NVK?

The image uses Fedora's current Mesa/nouveau/NVK packages by default. Feature,
performance and power-management support vary by GPU generation, kernel and
Mesa release; this project has no controlled percentage benchmark that applies
to every card. Use the Module 19 matrix and its verified opt-in proprietary
driver workflow when CUDA or vendor-driver behavior is required.

## How do I verify an ISO I downloaded?

```bash
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS
```

The maintainer release key fingerprint is documented in
[`docs/gpg-trust-chain.md`](gpg-trust-chain.md); cross-check it through an
independent public channel.

## Is there a community for this?

Use the repository's current Issues/Discussions settings for public bugs and
questions. Security reports follow [`SECURITY.md`](../SECURITY.md); no contact
address is copied into this repository.

## Can I use this for work?

Depends on your employer's policy. NoID Privacy is CC BY-SA 4.0 (docs) +
GPL-3.0-or-later (code). No warranty. No compliance claims (not HIPAA, PCI, SOC2).
Suitability is an organizational risk/compliance decision; the project makes
no classification or regulated-workload claim.

## How often do I need to update?

Weekly is ideal. `noid-update-all.sh` combines DNF + Flatpak +
re-apply of the embedded NoID Privacy Firefox user.js + a check against the
existing user-owned AIDE baseline. It preserves reported drift instead of
accepting it. The reminder timer is active in the user session.

## Can I run this in a VM?

Yes. The image boots fine in KVM/QEMU with virtio drivers. Some
hardware-specific steps (Intel ME blacklist) are harmless no-ops in
a VM.

## Does the image phone home?

The project adds no NoID Privacy telemetry or anonymous usage pings, and automatic
package/firmware polling is disabled. This is not a promise of zero traffic
from Fedora components, user actions, installed applications, VPN clients or
firmware OOB.

Documented image-controlled background/control traffic includes:

- DHCP and standard ARP required for IPv4 conflict detection, address defence
  and use of the WAN gateway. Permanent neighbour pins do not authenticate
  Ethernet frames.
- chrony NTS to 6 configured operator-supported EU endpoints. The release gate
  verifies current NTS-KE, reachability and source-selection state; the count
  alone is not availability or independence proof.
- when WAN-egress-strict is enabled, event-triggered resolution of configured
  hostname VPN endpoints on boot, profile changes and relevant NetworkManager
  events. Its five-minute expiry job only removes bounded local records and
  does not refresh DNS.

The complete automatic-execution inventory distinguishes resident processes,
one-shots, timers, paths and native event hooks in
[`automatic-execution.md`](automatic-execution.md).

Foreground applications create ordinary DNS traffic through the active
system/VPN resolver by default, or through browser Secure DNS when the user
enables it. DNF/Flatpak updates, cloud applications and the explicit
`noid-dns-diagnose probe TARGET` command also create traffic when invoked. The
DNS diagnostic has no background timer or fixed probe target.

## What's the release cadence?

There is no guaranteed calendar cadence. A release is ready only after the
gates in [`docs/release-process.md`](release-process.md) pass.

## Why Quad9 for DNS and not Cloudflare?

The project selects Quad9's security-filtering service as one explicit
third-party resolver; that centralizes DNS trust and is not anonymity. Provider
policy can change, so review the current Quad9 documentation. Use
`noid-dns-mode` for the supported transport modes. To select a different
upstream, follow the installed
`/usr/share/doc/noid-privacy/11-dns-custom.md` and add a lexically
later local drop-in; do not edit NoID Privacy's image-owned
`99-privacy.conf` directly.

## Does the image protect against PRISM / NSA?

No. See [`docs/scope.md`](scope.md). State-actor threat model is
explicitly out of scope. The image reduces selected commodity tracking and
local-network exposures; it does not make users anonymous or prevent every
public-WiFi/ISP observation.

## How do I report a security vulnerability?

See [`SECURITY.md`](../SECURITY.md). Do not file public issues for
security matters.

## Can I contribute?

Yes. See [`CONTRIBUTING.md`](../CONTRIBUTING.md). Tests must pass
(`bash tests/run-all.sh`), `bash -n` clean, docs updated.

## Is this affiliated with Fedora Project / Red Hat?

No. Independent project. Uses Fedora 44 as a base; not endorsed by
the Fedora Project. "Fedora" is a trademark of Red Hat; this project
uses the trademark descriptively per the Fedora trademark policy.
