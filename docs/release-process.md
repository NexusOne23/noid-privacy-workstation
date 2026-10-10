# Releases and ISO verification

NoID Privacy Workstation releases provide a tested installation image, matching
source code, a SHA-256 checksum and a detached release-key signature.

## Versions

Stable versions use `vX.Y`; fixes may use `vX.Y.Z`. The version comes from
`NOID_VERSION` in `kickstart/snippets/32-branding.ks` and appears in the ISO
filename and `/etc/noid-build-info`. Releases have no fixed calendar schedule.

## ISO checks

The ISO is checked in QEMU/KVM through Live boot, installation, first login and
reboot. The checks cover:

| Area | Coverage |
|------|----------|
| Boot and installation | UEFI, Secure Boot, installer, encrypted installation and subsequent boots |
| Desktop and applications | GNOME login/logout, first-party tools, Firefox, Thunderbird and Flatpak |
| Security and privacy | Kernel settings, SELinux, audit, firewall/LAN isolation, USBGuard and silent defaults |
| Networking and time | DNS, VPN-compatible behavior, NTS and reconnect/resume behavior |
| Storage and recovery | LUKS, filesystem permissions, removable media, initramfs recovery and Snapper rollback |
| Integrity | AIDE behavior, clean image contents and distinct identities for independent installations |
| Packages | Fedora package signatures and freshness against current repository metadata |

The [release notes](https://github.com/NexusOne23/noid-privacy-workstation/releases)
identify the ISO and summarize the completed checks and their results.
VM results cover the tested virtual hardware; hardware-specific results, such
as NVIDIA installation and driver updates, require the corresponding hardware.
The [test scripts and usage reference](../tests/README.md#pre-ship-gates) are
public. See [test coverage](test-strategy.md) for the distinction between source
checks and tests of the running image.

## Build and signature

Build from a clean source checkout using the [build instructions](build.md):

```bash
./scripts/build-iso.sh
```

The builder produces an unsigned candidate and its `SHA256SUMS`. The release
signature covers that exact checksum file after ISO validation; signing does
not rebuild or modify the ISO. The signed release tag carries the same source
tree as the build revision recorded in the image's `NOID_SOURCE_COMMIT`.
Complete ISO builds are not claimed to be byte-for-byte reproducible; see
[build reproducibility](build-reproducibility.md).

## Downloads

The [website download page](https://noid-privacy.com/linux.html) provides the
ISO, `SHA256SUMS`, `SHA256SUMS.asc`, the release public key and verification
instructions. GitHub releases provide the same checksum and signature.
The ISO is hosted on the website because GitHub requires each individual
release asset to be under 2 GiB.

Release-key fingerprint:

```text
1ACB FCE4 9687 FEBB 9101 0E52 F8E3 F11D 6962 256F
```

Follow the complete [download-verification instructions](../README.md#-download-the-iso).
Confirm the fingerprint through an independent channel, require a valid
signature from that exact key, then check the ISO checksum. Stop if any step
fails.
