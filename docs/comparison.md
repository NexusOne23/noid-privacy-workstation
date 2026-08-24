# Comparison: NoID Privacy Workstation 44, Kicksecure 18 and secureblue

This is a bounded architecture comparison, not a security ranking. Security
depends on the selected image, firmware, configuration, update state and user
behavior. The two peer projects are moving targets, so this document avoids
feature-absence claims unless their own documentation states the boundary.

## Verification snapshot

Peer-project facts were checked against project-controlled sources on
**2026-07-29**. The NoID Privacy Workstation row was refreshed against the
local v1.7 release source on **2026-08-23**:

| Project | Snapshot used here | Important version boundary |
|---|---|---|
| NoID Privacy Workstation | local v1.7 release source | Release qualification binds the exact source commit, ISO digest, signature and required evidence; a version label alone does not qualify different bytes |
| Kicksecure | stable LXQt ISO 18.2.1.9; Kicksecure 18 documentation | Debian 13 “Trixie”; defaults differ between new GUI images, CLI images and distro-morph installs |
| secureblue | symbolic release v4.9.2 and feature documentation reviewed at the peer snapshot | Images are rolling and are rebuilt after merged changes; a release tag is not an immutable image version |

Re-check the linked upstream pages for any later decision. “Not documented in
the reviewed source” is not evidence that a feature does not exist.

## Architectural fit

| Dimension | Kicksecure GUI | secureblue | NoID Privacy Workstation 44 |
|---|---|---|---|
| Base/delivery | Debian 13, mutable APT system | Fedora Atomic OCI image, deployment-based updates | Fedora 44 Workstation, mutable DNF system |
| Administrative workflow | new GUI images use separate `user` and `sysmaint` roles/sessions; other installation types differ | removes `sudo`, `su` and `pkexec` in favor of `run0` | conventional `sudo`, hardened timeout and login policy |
| Browser choice | `browser-choice` lets the user install a browser | Trivalent, a hardened Chromium derivative | Fedora Firefox with repository-owned preferences and pinned uBlock Origin |
| Integrity/rollback model | Debian packages plus project hardening; consult Kicksecure for the selected install type | signed Atomic image/deployments and project provenance mechanisms | Btrfs root snapshots when the required layout exists, plus AIDE detection; neither is authenticated image deployment |
| Primary workflow fit | security-focused Debian desktop and Whonix ecosystem | immutable/Atomic host with container-oriented workflows | mutable GNOME developer/admin workstation |

These are different trust and usability choices. NoID Privacy does not claim
that mutable DNF plus Snapper is equivalent to an authenticated Atomic image,
or that AIDE is preventive verified boot.

## Selected security differences

### Browser and memory hardening

- secureblue documents globally enabled `hardened_malloc`, including Flatpaks,
  and ships Trivalent with SELinux confinement.
- Kicksecure provides an interactive browser-choice workflow rather than one
  universal browser default across all installation forms.
- NoID Privacy deliberately retains Fedora Firefox. Its local policy currently
  contains hundreds of profile-hardening `user_pref` directives, a generated
  AutoConfig layer with separately reviewed user-overridable defaults plus five
  narrow `lockPref` directives, and a SHA-256-pinned uBlock Origin package.
  Firefox JIT remains enabled. The project does not preload
  `hardened_malloc` globally because replacement-allocator compatibility with
  Fedora Firefox is an unresolved product boundary; see
  [design-decisions.md](design-decisions.md).

No browser choice eliminates engine zero-days, behavioral fingerprinting or
account linkage. NoID Privacy's ECH and hybrid TLS client settings protect a connection
only when the server supplies valid parameters and the handshake negotiates
them.

### Privilege boundary

- Kicksecure documents `user-sysmaint-split` as the default for new GUI images:
  daily use and system maintenance happen in separate accounts/sessions. It is
  not the default for CLI images, servers or existing distro-morph installs.
- secureblue documents removal of `sudo`, `su` and `pkexec` and use of `run0`.
- NoID Privacy keeps the familiar `sudo` model with a three-minute timestamp,
  `faillock` and password-quality policy. It therefore retains a larger
  same-session administration boundary than a separate maintenance role.

### Host integrity and updates

- secureblue's Atomic deployment and signature/provenance workflow is the
  strongest fit of these three when authenticated image delivery is the main
  requirement.
- NoID Privacy uses user-initiated DNF/Flatpak/firmware/AI-tool update
  orchestration, root-subvolume pre-snapshots and optional daily AIDE checks
  only after the user reviews and accepts a baseline and enables the timer. A
  snapshot can roll back system state but is not content-addressed,
  tamper-proof or an independent audit record. AIDE detects changes after the
  fact.
- Kicksecure remains a mutable Debian system; its exact update, live-mode and
  maintenance behavior depends on the chosen image and documented mode.

NoID Privacy exports `SOURCE_DATE_EPOCH` and pins selected external artifacts, but a
byte-reproducible complete ISO has not been demonstrated. See
[build-reproducibility.md](build-reproducibility.md).

### Network posture

NoID Privacy's distinguishing local policy is a WAN-client workstation
baseline:

- unsolicited host ingress is dropped;
- static local/link-local/multicast destinations and every currently connected
  on-link prefix are blocked for ordinary host egress;
- link bootstrap and ARP resolution of the selected gateway remain necessary
  control-plane traffic for WAN connectivity; ordinary gateway-addressed IP
  traffic is not thereby allowed;
- a root-authorized NoID Privacy Network exception can allow a specific LAN peer;
- WAN-strict mode can limit physical-interface traffic to exact saved VPN
  endpoint IP/transport/port tuples.

This is a host-OS statement. It cannot constrain Intel AMT or another
firmware-owned out-of-band network path, a separate NIC computer, compromised
firmware, traffic generated before the policy is active, or an explicitly
authorized exception. Kicksecure and secureblue have their own firewall and
network-hardening policies; this document does not infer absence or equivalence
from a different implementation.

### Firmware boundary

NoID Privacy blocks Linux driver binding for its enumerated Intel KT/SOL PCI
functions and keeps selected MEI functionality available for platform-dependent
fwupd inspection. This does **not** disable Intel ME or AMT. AMT must be
unprovisioned/disabled in firmware, and every AMT-capable network path must be
removed or disabled if that threat is in scope. AMD PSP is documentation and
platform-awareness only: unloading `ccp` does not disable PSP and may remove
useful host functions. See [threat-model.md](threat-model.md).

### Post-quantum status

NoID Privacy explicitly prefers supported OpenSSH hybrid key exchanges and enables the
Mozilla hybrid TLS client preference. Coverage remains per-session and
peer-dependent. When encryption is selected, the release expects LUKS2
`aes-xts-plain64` with a 512-bit combined XTS key; verify the installed header
and each enabled keyslot with `cryptsetup luksDump`. Passphrase entropy and the
actual KDF parameters still matter. WireGuard, OpenPGP, Secure Boot, MOK and RPM-signature migration are
upstream/protocol gaps; see [post-quantum-readiness.md](post-quantum-readiness.md).

## Locally auditable NoID Privacy properties

The following figures are derived from this repository rather than competitor
marketing:

- 106 static sysctl assignments plus one generated runtime assignment per WAN interface;
- 50 shared kernel-command-line tokens plus up to 7 conditional
  tokens (the Intel and AMD branches are mutually exclusive);
- 53 effective loadable-module denies within a 134-state module inventory;
- 132 b64/b32-complete audit rules ending in immutable audit configuration;
- hundreds of Firefox profile-hardening preferences plus a generated,
  separately tested AutoConfig default/lock layer;
- 84 structural test programs and four sandbox smoke tests;
- 52 installed user-document pages.

Counts describe configuration volume, not security quality. Structural tests
prove selected source invariants; they do not replace a real ISO install, VM
matrix, bare-metal test, external audit or exploit assessment.

## Choose by requirement

| Requirement | Better starting point |
|---|---|
| Tor-routed anonymity or compartmentalized anonymity | Whonix or Tails; base Kicksecure, secureblue and NoID Privacy alone are not substitutes |
| Separate daily-use and maintenance roles | a new Kicksecure GUI image |
| Atomic Fedora host and signed/provenance-oriented image delivery | secureblue |
| Hardened Chromium with secureblue's current Trivalent policy | secureblue |
| Mutable Fedora GNOME workflow with direct DNF/systemd administration | NoID Privacy, if its documented trade-offs match the threat model |
| Default host-side LAN egress isolation with explicit peer exceptions | NoID Privacy's implemented policy, subject to the firmware/control-plane boundaries above |
| Anti-forensic or amnesic production workflow | evaluate Tails and Kicksecure's current live-mode/ram-wipe documentation; NoID Privacy is not designed as an amnesic OS |
| VM isolation against a targeted endpoint compromise | Qubes OS; none of these desktop configurations creates that boundary by itself |

Avoid NoID Privacy when you require ARM, legacy BIOS, enterprise multi-user
directory integration, an authenticated immutable base, or a proven
reproducible image. TPM 2.0 is optional; UEFI is required, while firmware Secure
Boot is strongly recommended but cannot be enabled by the image itself.

## NoID Privacy residual weaknesses

- single-maintainer/bus-factor risk;
- no completed independent project-wide security audit;
- no authenticated atomic base or dm-verity/UKI verified-root guarantee;
- no demonstrated byte-reproducible complete ISO;
- conventional same-session `sudo` boundary;
- Firefox JIT remains enabled and global `hardened_malloc` is not deployed;
- no RAM wipe, TCP-ISN replacement or production amnesic design;
- LAN enforcement cannot control firmware OOB paths;
- structural and sandbox tests do not establish real-hardware correctness.

## Sources

### NoID Privacy

- this repository: [INDEX.md](../INDEX.md), [threat-model.md](threat-model.md),
  [test-strategy.md](test-strategy.md), and
  [build-reproducibility.md](build-reproducibility.md)

### Kicksecure (project-controlled)

- [Kicksecure documentation](https://www.kicksecure.com/wiki/Documentation)
- [Kicksecure 18 / Debian base](https://www.kicksecure.com/wiki/Main_Page)
- [stable LXQt ISO version](https://www.kicksecure.com/wiki/ISO)
- [`sysmaint` installation/default matrix](https://www.kicksecure.com/wiki/Sysmaint)
- [browser-choice](https://www.kicksecure.com/wiki/Browser-choice)
- [persistent/live modes](https://www.kicksecure.com/wiki/Persistent_Mode)
- [verified-boot boundary](https://www.kicksecure.com/wiki/Verified_Boot)

### secureblue (project-controlled)

- [current features](https://secureblue.dev/features)
- [project repository](https://github.com/secureblue/secureblue)
- [symbolic v4.9.2 release](https://github.com/secureblue/secureblue/releases/tag/v4.9.2)
- [Trivalent repository](https://github.com/secureblue/Trivalent)

The snapshot date is part of the claim. Re-verify volatile peer-project facts at
every NoID Privacy release.
