# Scope — Target Audience, Anti-Targets, Out-of-Scope

NoID Privacy Workstation 44 is a LAN-isolated, WAN-client-oriented hardening of
Fedora Workstation 44 that preserves a general-purpose GNOME desktop. Hardening
has workload- and hardware-dependent performance, power and memory costs. See
[`docs/performance-profile.md`](performance-profile.md) for the honest
accounting.

It is *not* a classified-data workstation, Tor-anonymity OS, or
compartmented national-security system. This document lists target
audience, explicit anti-targets, and the attacker classes + use-cases
that are **out of scope** so users can make informed deployment
decisions.

## Target audience — ideal user

- **Privacy-aware** + Linux-affine + Fedora-familiar
- **Single-user** workstation (developer / sysadmin / creator / researcher)
- Accepts **WAN-only workflow** — direct-to-internet or optional via VPN
- **LAN-isolation is a feature, not a bug** (no printer-sharing, no
  NAS-mount, no smart-home-hub integration, no Bonjour/mDNS)
- **Threat-model fit**: privacy + surveillance-resistance, NOT state-
  level anonymity

## Anti-targets — explicitly NOT for

- **Gaming-first rigs** — NoID Privacy is not latency/throughput-tuned for
  competitive play: congestion control/qdisc remain Fedora/kernel policy, and
  the hardening has workload-dependent costs on allocation-/syscall-heavy paths
  (see [`docs/performance-profile.md`](performance-profile.md) for the
  honest cost breakdown). **Gaming Mode** can relax the two repository-managed
  compatibility settings, then install Steam after the required reboot
  (32-bit execution + the Wine W^X SELinux boolean). That makes gaming
  possible, not guaranteed: Proton, GPU drivers and
  anti-cheat support remain title-, vendor- and version-dependent.
- **Multi-user / family systems** — single-user design; LAN-isolation
  blocks the shared-printer / shared-NAS / shared-media use-cases
  families depend on
- **Enterprise / AD / LDAP** — `sssd` and centralized-management integration
  are not shipped. The image assumes one user on one machine.
- **Operational whistleblowing** — Tor Browser is available as an
  optional Flatpak install, but the image is *not a Tor-default OS*.
  Use **Tails** (amnesic) or **Whonix** (VM-isolated Tor) for real
  operational anonymity.
- **Home-server / NAS / smart-home hub** — local and directly connected
  destinations are blocked by default. Access requires a deliberate per-peer
  exception in NoID Privacy Network.
- **ARM architecture** — `x86_64` hardcoded in the metalink URL; no
  aarch64 build. Raspberry Pi and Apple Silicon unsupported.
- **Non-UEFI systems** — BIOS-only legacy hardware is rejected. TPM 2.0 is
  optional and is not used for automatic LUKS unlock by this image. Secure Boot
  is strongly recommended, but its enabled/key state is controlled by platform
  firmware rather than the installer.

## Architecture — the four pillars (why the anti-targets exist)

1. **LAN-isolated** — the host OS accepts no new inbound connections on a
   physical LAN/WLAN and blocks host-generated application traffic to the
   directly connected network, including unusual/public prefixes. DHCP,
   EAPOL and standard ARP—including IPv4 conflict detection, address defence
   and gateway resolution—remain; ordinary IP traffic addressed to LAN peers or the gateway is not a
   control-plane exception.
   Per-IP exceptions are explicit through the Network app. Firmware OOB such
   as Intel AMT is outside the host firewall and requires the UEFI/MEBx and
   hardware checklist in Module 15.
2. **WAN-only** — egress goes to public internet only. Direct-to-ISP is
   supported in bootstrap-grace or through an explicit strict-mode
   pause/disable. VPN is **optional and provider-neutral** — the user installs
   a provider client or imports a generic NetworkManager WireGuard/OpenVPN
   profile. The image ships no hardcoded client, but its independent WAN-strict
   layer restricts physical egress to exact supported VPN endpoint
   `IP + transport + port` tuples after strict mode is armed. Provider
   route/DNS killswitch behavior remains a separate verification target.
   `GRACE_BOOTSTRAP` is an explicit unexpired
   onboarding/no-VPN-decision state with direct IPv4 WAN, not a protected
   strict mode. M06's nft `inet` output/forward boundary covers host-stack
   IPv4/IPv6 traffic; `CAP_NET_RAW` link-layer injection, privileged network
   administration/namespaces, non-IP paths and firmware out-of-band traffic
   remain outside that claim.
3. **Hardened host baseline** — 106 static sysctl params + one generated
   durable parameter for the selected physical interface and event-time
   enforcement on every physical pre-up + 50 shared
   kernel-command-line tokens, plus up to 7 conditional tokens
   (Intel CPU: 5 or AMD CPU: 1 — mutually exclusive — plus NVIDIA GPU: 1,
   LUKS unlock-retry: 1), + a
   134-state module
   policy with 53 effective loadable-module denies +
   SELinux enforcing + custom NoID Privacy SELinux module v1.7 + reviewed
   systemd service hardening drop-ins
   + optional installer-selected LUKS2 + a Secure-Boot-capable Fedora chain
   when firmware Secure Boot is enabled + **vendor-aware firmware posture** (Intel
   ME: one host-side ME-specific control — KT/SOL PCI driver_override=none
   — + 3 opt-in MEI sub-module blocks per Kicksecure-consensus v13, with
   generic IOMMU isolation + core `mei`/`mei_me` kept available for fwupd
   attributes on supported platforms (no fixed HSI level is promised); AMD
   PSP: awareness/docs only — `ccp` remains available for platform-dependent
   crypto/fTPM functions, while generic IOMMU and available fwupd attributes
   do not disable PSP, plus PSB OTP warnings +
   CVE-2025-2884/2021-3764/faulTPM documentation) + USBGuard + AIDE.
4. **Privacy-focused defaults** — NoID Privacy Firefox Hardening v1.0 (derived from arkenfox
   v144.0, MIT — embedded in repo since 2026-04-22) + FPP (Fingerprint
   Protection) + uBlock Origin + provider-compatible system/VPN DNS by
   default (strict global/physical Quad9 when no VPN/private scope is active) + MAC randomization
   + Cookie-isolation (dFPI, Total Cookie Protection) + no project telemetry
   (the two GNOME outbound telemetry settings closed) + Canvas + WebGL
   randomization active.

---

## Out-of-scope attacker classes + use-cases

The following sections enumerate specific threats and use-cases that
are **explicitly out of scope**. Users with these requirements should
use a different tool.

## Physical access attacks

### 1. Full physical seizure + forensic tooling
Attacker takes the device, images the disk, submits to a forensics lab
with commercial tools (Cellebrite, GrayKey, X-Ways).

**Why out of scope**: when the user selects disk encryption, the current
release expects LUKS2 AES-XTS with two AES-256 keys and an Argon2id passphrase
keyslot. The actual container, cipher and active keyslot KDF must be verified
on the installed system. Offline resistance then depends strongly on
passphrase entropy and those observed parameters. Encryption is not selected
or verified merely by booting the live image, and this is not an amnesic
system: the installed disk retains state.

### 2. Evil-maid on the EFI partition or GRUB
Attacker has brief physical access while the system is running or in
suspend, modifies `/boot/efi/EFI/*`, injects malicious bootloader, waits
for user to boot (unlocks LUKS → captures passphrase).

**Why out of scope**: Secure Boot + lockdown=integrity + module signing
make this harder but not impossible. An attacker who can flash the
motherboard BIOS or substitute a signed-but-backdoored Microsoft-CA
shim bypasses this chain. Mitigations that would help: (a) TPM-bound
LUKS keys with PCR measurements tying unlock to firmware+bootloader
state, (b) tamper-evident seals on the device. NoID Privacy does not implement
(a) as a generic default because PCR policy, recovery-key handling,
firmware/update transitions and re-enrollment must be designed and tested for
the exact platform; (b) is an operational procedure outside the image.

### 3. Cold-boot attack on RAM
Attacker with physical access dumps LUKS master key from RAM within
seconds of power-off.

**Why out of scope**: not defended. For highly sensitive data, fully shut down
rather than suspend and retain physical custody until volatile memory has lost
state. A self-encrypting drive is not a substitute for this RAM boundary, and
NoID Privacy makes no universal memory-encryption or cold-boot-resistance claim.

## Firmware-level attacks

### 4. Malicious BIOS/UEFI from factory
OEM ships hardware with a pre-compromised EFI firmware containing
backdoored UEFI drivers that the Secure Boot chain cannot detect.

**Why out of scope**: the host OS cannot establish a trustworthy root below
already-compromised platform firmware. The user necessarily trusts the OEM and
hardware/firmware supply chain beyond what this image can verify.
Mitigations: buy through a reviewed supply chain, apply the exact
manufacturer-signed firmware intended for the platform, and inspect the
platform security attributes that fwupd actually exposes. A published update
checksum authenticates downloaded bytes only under the vendor's signing or
publication trust; it does not prove that the running firmware was never
compromised.

### 5. Intel ME persistent firmware malware
ME firmware is compromised below the OS; no OS-level mitigation catches
it.

**Why out of scope**: the ME mitigation (Module 15, v13
Kicksecure-consensus) reduces
attack surface but does not eliminate a pre-compromised ME. Hardware
mitigations include keeping firmware current and applying the Module 15
hardware checklist. Supported fwupd MEI attributes can expose BootGuard state,
but the overall HSI
level remains hardware-, firmware-, runtime-, and fwupd-version-dependent. See
the installed [Intel ME hardware-layer guide](15-intel-me-hardware-layer.md).

### 6. Compromised SSD firmware
Attacker replaces or modifies SSD firmware to exfiltrate data or
establish persistence below the filesystem.

**Why out of scope**: the host cannot reliably inspect or confine a malicious
storage controller below its command interface. LUKS protects plaintext at
rest when correctly enabled and unlocked only on a trusted host, but it does
not make malicious device firmware trustworthy.

## State-actor and APT threats

### 7. Custom 0-day exploit chain
Attacker with nation-state budget develops a privilege-escalation chain
targeting a specific Module of the image (e.g. a kernel 0-day combined
with a SELinux domain bypass).

**Why out of scope**: the controls may reduce exploitability or persistence
options, but they cannot promise resistance to a tailored zero-day chain. AIDE
and audit logs are after-the-fact signals and can be evaded or modified by a
privileged attacker; they do not guarantee detection before persistence.

### 8. Targeted supply-chain attack on Fedora infrastructure
Fedora's build servers are compromised; malicious packages are signed
by Fedora's legitimate key and published to mirrors.

**Why out of scope**: a malicious package signed and published through trusted
Fedora infrastructure passes this image's normal package-authentication gate.
Fedora's package-level reproducibility work may support investigation, but this
project does not provide an independent Fedora rebuild/attestation layer.

### 9. Targeted supply-chain attack on uBlock Origin
Upstream compromise: attacker releases a malicious uBO XPI.

**Partial defence**: Module 16 pins the image/recovery seed to a specific uBO
release tag and SHA-256, so a force-moved tag cannot redirect the build. Later
versions advance only in a user-started Update All transaction through the
fixed official repository, release digest, structure/identity/compatibility
checks and Firefox's native signature verdict. That moving release channel is
still an explicit upstream trust boundary; local validation cannot prove that
an upstream-authorized release is benign.

(arkenfox is no longer fetched at build time: the NoID Privacy Firefox user.js
was absorbed 2026-04-22 and is shipped as an in-repo derivative work
of v144.0. Future version bumps require an explicit in-repo refresh +
review, not an automatic upstream fetch. Thunderbird follows the same local
derivative contract for its tagged HorlogeSkynet v140.2 basis; Update All
reapplies local NoID Privacy bytes and never imports either upstream `user.js`.)

## Application-layer threats

### 10. Malicious Wayland compositor / compromised GNOME Shell
A compromised GNOME Shell extension or compositor can observe or manipulate
the graphical session. Ordinary Wayland clients do not automatically receive
global capture privileges, but trusted portals and input/capture grants remain
security boundaries.

**Why out of scope**: GNOME Shell extensions run in the compositor's session
context; compromising Shell exposes that session. NoID Privacy ships reviewed
extension seeds and disables background extension updates. A user-started
Update All run advances non-RPM system extensions through EGO; EGO does not
provide a cryptographic publisher signature, so this owner-selected convenience
path trusts the fixed EGO identity plus structural and compatibility checks.
Those payloads remain trusted code.

### 11. DNS leak via application bypassing system resolver
Firefox and Thunderbird use the system resolver by default. Without a
more-specific per-link scope, that resolver uses strict authenticated global
Quad9 DoT and fails closed when TLS cannot be used. The user can explicitly
select opportunistic global + physical transport for VPN/captive-portal
compatibility, which permits downgrade to DNS/53, or plaintext recovery mode.
VPN/private `~.` link DNS is deliberately provider-neutral and takes
precedence. NoID Privacy does not rewrite those profiles: an unset
`connection.dns-over-tls` inherits the image's generic `opportunistic`
connection default, while an explicit profile value wins. That best-effort mode
tries DoT but permits unauthenticated DNS/53 fallback and is not MITM-resistant.
An app with its own bundled resolver—or a user-enabled browser Secure DNS
provider—can bypass the system/VPN resolver path.

**Why out of scope**: per-app DNS bypass is possible and not blocked.
NoID Privacy cannot force an application-controlled resolver through the configured
system DNS path without a separate endpoint allow-list, which is not shipped.

## Sociotechnical threats

### 12. Coercion to unlock
User is compelled (legally or physically) to unlock the device.

**Why out of scope**: no OS protects against a user who unlocks their
own disk. Mitigation: duress passphrase features (cryptsetup
`--header` + spare key) are a manual workflow outside the image scope.

### 13. Phishing / social engineering
User enters credentials into a phishing page that looks legitimate.

**Partial defence**: Firefox + uBlock filter lists and Quad9's malware-blocking
resolver can reject some known malicious destinations. Firefox credential
saving is disabled by the project policy, but Thunderbird and an explicitly
used external password manager remain separate credential stores. These
controls do not recognize every phishing site; user verification is required.

### 14. Maliciously crafted media file
PDF, video, image with an embedded exploit targeting the renderer.

**Partial defence**: Flatpak sandboxing for media apps; Firefox
sandboxing for web media. But if the user opens a file with a host-
native tool (e.g. `xdg-open` → `papers`), no extra isolation applies.

## Operational non-scope

### 15. Unattended daily-driver data loss
User makes a mistake — `rm -rf`, pours coffee on the laptop, LUKS key
forgotten.

**Not in scope**: backups are the user's responsibility. NoID Privacy ships
Btrfs root-subvolume snapshots (when the required layout exists) which aid
system rollback but do not snapshot the separate `/home` subvolume and are not
a backup (same disk = single point of failure). Use external 3-2-1
backups for data safety.

### 16. Regulatory compliance (HIPAA, PCI, FedRAMP)
NoID Privacy does not claim compliance with any regulatory framework.

**Not in scope**: compliance is the deployer's problem. The image
provides documented controls that may *simplify* part of a compliance project but
does not substitute for the accreditation work.

---

## TL;DR

NoID Privacy Workstation is a **LAN-isolated, WAN-client-oriented Fedora 44
daily-driver**, subject to documented DHCP/EAPOL/standard-ARP, explicit-peer and
firmware-OOB boundaries. It
raises the bar for passive surveillance, commodity malware, local LAN
attackers, USB attack devices, and fingerprinting. It is **not**:

- A classified-data workstation.
- An amnesic live system (use Tails).
- A compartmented security kernel (use Qubes).
- A forensically-resistant device (use dedicated cold-storage + travel
  laptops).
- A system that promises resistance to tailored state-actor exploit chains.

Choose the right tool for the threat model you're actually facing.
