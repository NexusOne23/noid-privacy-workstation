# Threat Model

This document describes the attacker classes NoID Privacy Workstation
aims to defend against, the trust assumptions made, and the defences in
depth that implement those goals.

## Summary — who this protects, who it doesn't

| Threat class | Coverage | Primary mechanism / boundary |
|---|---|---|
| Ad / tracker fingerprinting | Mitigated | NoID Privacy Firefox Hardening v1.0 (arkenfox v144.0 derived) + FPP + uBlock; behavior and account identity remain linkable |
| ISP + local-network surveillance | Partial | Strict-default global/physical Quad9 DoT, best-effort opportunistic DNS for unset VPN/private profiles, optional VPN and LAN isolation; opportunistic transport can be downgraded to DNS/53, and without a VPN the ISP still sees destination IPs/timing |
| Data broker profiling | Partial | dFPI (Total Cookie Protection) and MAC randomization reduce passive linkage; logins and behavior can still identify the user |
| Local-network (LAN) attacks | Strong layered mitigation | inbound IP DROP, topology-aware LAN-egress guard, permanent gateway/approved-peer neighbour pins, and native IPv4 conflict detection; DHCP, EAPOL and standard ARP remain necessary link traffic |
| Software supply chain | Partial | signed/pinned sources and integrity checks reduce risk; upstream Fedora and explicitly selected third parties remain trusted |
| Browser memory corruption | Mitigated | Firefox Fission, seccomp, namespaces, SELinux, and timely updates reduce impact; they do not eliminate engine vulnerabilities |
| Kernel exploits | Mitigated | 106 static sysctl assignments + one generated durable assignment for the selected physical interface and event-time enforcement on every physical pre-up + a 134-state module inventory with 53 effective loadable-module denies + 50 shared kernel-command-line tokens (+ up to 7 hardware-conditional); built-ins and kernel zero-days remain residual risk |
| USB attack devices | Strong mitigation after enrollment | USBGuard default block plus firstboot policy; already-authorized or controller-level attacks remain possible |
| Evil-maid at rest | Conditional | LUKS2 + Secure Boot, only if encryption is selected and firmware/key state remains trustworthy |
| Intel ME / AMT persistence | Limited host-side reduction | KT/SOL driver-binding block + fwupd visibility; AMT requires UEFI/MEBx and hardware/network-path action outside the host firewall |
| AMD PSP persistence | Documentation + generic layers | PSP is below the host-OS boundary and is not host-disableable; IOMMU/Secure Boot, available fwupd inspection, and PSB/CVE guidance do not disable it |
| — | — | — |
| State-level traffic analysis | ❌ | Beyond desktop-OS threat model |
| Targeted endpoint-exploit (APT) | ❌ | No VM-boundary (use Qubes) |
| Compromised VPN provider | ❌ | User's responsibility (choose no-logs provider) |
| Account-linking (Gmail, GitHub) | ❌ | Defeats pseudonymity (user choice) |
| Physical coercion | ❌ | "$5 wrench attack" — no OS defends this |
| Zero-days between disclosure + update | ❌ | Normal AV-gap |
| Upstream Fedora supply-chain | ❌ | xz-utils-class events (koji reproducibility partial) |
| Social engineering / phishing | ❌* | (*NoID Privacy Firefox hardening + uBO partial, user vigilance required) |

See [`scope.md`](scope.md) for the full out-of-scope list with per-threat rationale.

---

## VPN clarification (important)

NoID Privacy Workstation is **VPN-optional and provider-neutral**:

- The image does **not** ship a hardcoded VPN client
- Users install a provider client or import a generic NetworkManager
  WireGuard/OpenVPN profile
- A provider client may supply its own persistent killswitch; that capability
  and configuration must be verified for the selected client
- Image-level safety net: `50-vpn-zone-enforce` NM dispatcher ensures
  genuine VPN interfaces land in the inbound-DROP `noid-vpn` zone
- Independent WAN-strict layer: after a supported profile yields an exact
  `server IP + TCP/UDP + port` tuple, physical-WAN egress is limited to those
  tuples. Unknown profile schemas fail closed; provider route/DNS behavior is
  still tested separately.

The runtime mode is part of this claim. `GRACE_BOOTSTRAP` is a deliberate,
non-expiring onboarding/no-VPN decision state with direct IPv4 WAN; it is not
strict protection. The nft `inet` output/forward hooks cover IPv4/IPv6 traffic
through the initial host network stack. They are not a malware-proof boundary:
`CAP_NET_RAW`/`AF_PACKET` link-layer injection, `CAP_NET_ADMIN` firewall or
route control, `CAP_SYS_ADMIN` network-namespace/device control, non-IP link
traffic and firmware out-of-band paths remain outside M06's claim. Ordinary
unprivileged applications receive none of those capabilities by default; the
three-pass candidate gate verifies that raw/packet sockets and an nft mutation
are rejected for UID 65534.

The **LAN-isolation + WAN-only** architecture is independent of VPN:
the static policy blocks known local/link-local/multicast ranges and the
topology-aware nftables guard additionally blocks every directly connected
prefix, regardless of whether that prefix uses private or public address
space. A default-drop XDP program additionally rejects unsolicited physical
ingress before AF_PACKET; its TC companion admits only bounded reverse tuples
that were observed leaving after nftables filtering. Explicit per-IP NoID Privacy
Network exceptions are the only LAN application-data escape hatch. DHCP,
EAPOL and standard ARP—including native IPv4 conflict detection—remain
necessary link boundaries; this does not authorize ordinary IP traffic addressed to
the gateway. Direct-to-ISP is available during the
initial bootstrap-grace state or by an explicit WAN-strict pause/disable; once
strict VPN tuples are armed, disconnecting the tunnel does not silently restore
direct internet egress.

---

## Design principles

1. **Silent-machine baseline** — no NoID Privacy telemetry and no LAN discovery
   broadcasts. Documented automatic control traffic still exists where the
   configured function requires it, including DHCP/ARP and enabled NTS/DNS
   health checks; user-installed applications can add their own traffic.
2. **Defense in depth** — independent controls are used where the platform
   permits. Intel AMT is an explicit boundary: host firewall, IOMMU and
   KT/SOL driver-binding controls do not disable its firmware OOB path.
   UEFI/MEBx unprovisioning plus disabling every AMT-capable wired/wireless
   interface is a user-controlled prerequisite.
3. **Reversibility** — hardening decisions are documented with their
   trade-off + reversal procedure. Users who need a specific hardening
   off can revert.
4. **Integrity failures stay visible** — AIDE reports file-integrity drift and
   returns a non-zero status; it is detection, not a boot gate. When LUKS is
   selected, failure to unlock the root volume prevents that encrypted system
   from booting. When Secure Boot is actually enabled in platform firmware, its
   signature policy rejects an untrusted boot component; this image requires
   UEFI but cannot itself enable or provision firmware Secure Boot.

## Attacker classes (in-scope)

### 1. Passive network surveillance

- **Capability**: full packet capture on any network the user touches
  (home, café, office, mobile hotspot).
- **Defences** (image-level, without VPN):
  - Firefox, Thunderbird and ordinary resolver clients use systemd-resolved.
    Without a more-specific link scope, global Quad9 uses strict authenticated
    DoT and fails closed when port 853 or certificate validation is unavailable.
    The user may explicitly select opportunistic global + physical transport
    for VPN/captive-portal compatibility, which permits downgrade to DNS/53, or
    an explicit plaintext recovery mode through `noid-dns-mode`.
    An active VPN/private `~.` link resolver supersedes the global scope.
    NoID Privacy does not rewrite that profile: an unset
    `connection.dns-over-tls` inherits the image's generic `opportunistic`
    connection default, while an explicit profile value wins. This best-effort
    mode tries DoT but permits DNS/53 fallback, cannot authenticate the resolver
    in systemd-resolved's opportunistic mode, and is not MITM-resistant. A user
    may opt into a separate browser Secure DNS provider, with that bypass made
    explicit.
  - Chrony NTS-only (no plaintext NTP, 6 configured operator-supported EU
    endpoints; candidate runtime evidence must prove current authenticated
    operation).
  - No mDNS/WSD/SSDP/LLMNR/NetBIOS broadcasts (services masked + ports
    blocked in block-lan-out policy).
  - Physical-WAN IPv6 is disabled through default-off kernel policy,
    per-physical-pre-up enforcement and NetworkManager
    `ipv6.method=disabled`; VPN-internal IPv6 remains a separate profile
    boundary.
  - Firefox ECH (Encrypted Client Hello) enabled; it hides the inner
    ClientHello/SNI only where a valid ECH configuration is obtained and ECH
    is successfully negotiated.
- **Defences** (optional VPN layer, user-installed):
  - Image ships `50-vpn-zone-enforce` dispatcher to ensure genuine VPN
    interfaces land in firewalld `noid-vpn` (target DROP).
  - WAN-strict allows only exact saved VPN endpoint transport/port tuples on
    physical interfaces after strict mode is armed; same-IP other-port traffic
    remains blocked.
  - A provider client may add a stronger route/DNS killswitch; verify its
    behavior with the tunnel both up and down.
  - Image is **provider-neutral** — no hardcoded VPN dependency.
- **Residual risk**: without VPN, the ISP sees destination IPs and encrypted
  traffic metadata. With VPN, the ISP still sees the VPN endpoint IP and
  timing/volume; transport-specific metadata can reveal more. The VPN provider
  can observe the tunnel's egress side and could be compelled to log.

### 2. Network tracking across locations

- **Capability**: correlate the user's device across multiple physical
  networks via MAC address, hostname, DHCP options.
- **Defences**:
  - Fedora/NetworkManager `wifi.cloned-mac-address=stable-ssid`: a stable
    pseudonymous MAC per SSID, interface and installation identity (different
    across SSIDs, stable within the same SSID).
  - Ethernet uses a stable pseudonymous cloned MAC per connection profile;
    this is not automatic per-physical-LAN separation.
  - DHCP uses the active cloned MAC as its client identity and does not
    advertise the hostname.
- **Residual risk**: the same Wi-Fi network can recognize repeat visits;
  operators sharing an identical SSID can compare the same pseudonym, and a
  reused Ethernet profile remains linkable across wired LANs. MAC addresses
  are not authentication, and timing and traffic-fingerprinting attacks remain.

### 3. Browser fingerprinting

- **Capability**: server-side fingerprinting via Canvas, WebGL,
  AudioContext, fonts, screen metrics, WebRTC leaks.
- **Defences**:
  - NoID Privacy Firefox Hardening v1.0 user.js (hundreds of active
    profile-hardening preferences, embedded, derived from arkenfox v144.0
    released 2026-04-20, MIT — absorbed 2026-04-22, no upstream fetch).
  - FPP (`privacy.fingerprintingProtection=true`) with +AllTargets and
    targeted excludes for known-breakage keys (real timezone, real
    dark/light theme, real keyboard).
  - Canvas + WebGL randomization active.
  - WebRTC `media.peerconnection.enabled=false`.
- **Residual risk**: behavioural fingerprinting (keystroke dynamics,
  mouse patterns, scroll timing) cannot be blocked at the browser layer.

### 4. USB attack devices

- **Capability**: attacker has brief physical access to plug a malicious
  USB device (O.MG cable, Rubber Ducky, BadUSB, keyloggers).
- **Defences**:
  - USBGuard whitelist policy (any new device blocked until explicitly
    allowed).
  - Firstboot policy captures the user's legit USB baseline.
  - USBGuard's implicit-block policy deauthorizes new devices at the
    kernel USB-authorization layer until explicitly allowed.
- **Residual risk**: USBGuard does not make already-authorized devices,
  internal/controller-level paths, malicious charging hardware or
  electrical-damage devices trustworthy. Sustained physical access remains
  outside this device-enrollment boundary.

### 5. Local network attacker (hostile LAN)

- **Capability**: attacker on the same WiFi/wired network (café,
  conference, workplace) performs ARP spoofing, DHCP exhaustion, rogue
  DNS, lateral-move scans.
- **Defences**:
  - Bounded gateway/approved-peer learning followed by exact permanent kernel
    neighbour pins. The nft ARP table holds coordination state only and has no
    packet hook, so RFC 5227 conflict detection and address defence still work.
  - firewalld `drop` zone default, LAN-drop-all policy (block-lan-out).
  - A default-drop XDP/TC pair rejects unsolicited physical frames before raw
    packet sockets and admits gateway IPv4 only as a bounded reverse flow.
  - No LAN-reachable application services are enabled by the image
    (`openssh-server` is absent; mDNS/wsdd/Samba are not exposed). Loopback
    listeners and required client/control-plane sockets are a separate boundary.
  - Per-connection stable MAC reduces cross-network tracking; native ACD
    catches duplicate IPv4 assignment while permanent pins resist ordinary
    gateway/approved-peer cache replacement.
- **Residual risk**: DHCP/EAPOL and standard ARP are unavoidable link
  exchanges and ARP remains visible to packet sockets. Ethernet/Wi-Fi source
  MACs are not cryptographic: an
  attacker who spoofs the pinned gateway and guesses an active reverse tuple
  can reach later conntrack/firewall layers. Encrypted-but-visible VPN or
  encrypted-DNS flows can also reveal this is a hardened host.

### 6. Commodity malware / drive-by

- **Capability**: user clicks a malicious link; visits a compromised
  site; runs a curl|bash from a stranger's docs page; opens a malicious
  PDF.
- **Defences**:
  - Flatpak sandboxing and global sensitive-directory/D-Bus denials for GUI
    apps installed as Flatpaks (see `18-flatpak-trust-model.md` shipped in
    `/usr/share/doc/noid-privacy/`). Native GUI apps remain outside Flatpak and
    rely on their own sandboxing plus the host SELinux/systemd/browser layers.
  - SELinux enforcing constrains policy-covered actions; immutable auditd
    rules preserve selected security-relevant event evidence. Neither is a
    categorical privilege-escalation detector.
  - After the user reviews and accepts a baseline and enables its timer, AIDE
    daily scans detect covered file drift.
  - Hardened sysctl (user.max_user_namespaces=256,
    kernel.unprivileged_bpf_disabled=1 — irreversible for the running boot).
  - No setuid shells. A native tmpfiles/dnf5 policy removes five unnecessary
    SUID workflows while retaining Fedora privilege on four load-bearing
    account/consolehelper/GNOME paths; every remaining SUID binary stays an
    explicit RPM/AIDE/runtime audit item.
  - bubblewrap available (Flatpak's sandbox substrate).
- **Residual risk**: sophisticated exploit chains targeting 0-day
  kernel vulnerabilities can bypass sandboxing.

### 7. Firmware-level (Intel ME / AMT, AMD PSP / ASP)

- **Capability**: Intel Management Engine firmware receives remote
  command, uses KT/SOL redirection to inject keystrokes or read serial
  consoles; AMT allows out-of-band remote administration. AMD Platform
  Security Processor (PSP, formerly ASP) is a below-OS security
  coprocessor, but is not itself an AMT-equivalent remote-management stack;
  product-specific AMD DASH/AIM-T capability is a separate OOB boundary.
- **Host-side controls — Intel** (Module 15):
    1. `mei` + `mei_me` core modules kept available for supported fwupd
       attributes. The overall HSI score remains platform-, firmware-,
       runtime-, and fwupd-version-dependent.
    2. KT/SOL PCI functions (27 IDs across 6th–17th Intel gen +
       Sapphire Rapids workstation) use `driver_override=none`, preventing a
       Linux driver binding but not disabling firmware-owned AMT/SOL/KVM.
    3. Generic IOMMU translated domains, UEFI Secure Boot and
       `lockdown=integrity` harden the host; they are not AMT containment.
    4. Required user action: fully unprovision/disable AMT in UEFI/MEBx,
       disable/remove every AMT-capable integrated Ethernet and compatible
       Wi-Fi path, and use a non-AMT adapter for WAN where practical.

  **Sub-modules `mei_hdcp`/`mei_pxp`/`mei_wdt` are LOADED by default**
  (cost outweighed benefit per Kicksecure security-misc Issue #239,
  2025). Each remains opt-in blockable via
  `noid-mei-restore-submodules --block hdcp|pxp|wdt` (choose one token):
  - `mei_hdcp` block → 4K Netflix/Disney+/Prime HDCP streams downgrade.
  - `mei_pxp` block → HuC HW-accel HEVC/AV1 decode breaks on Gen12+ iGPU.
  - `mei_wdt` block → breaks platforms that use the ME watchdog for remote
    management/recovery; opt in only when that function is not required.
- **Defences — AMD (awareness / docs only — PSP not host-disableable)** (Module 15 Step 4b):
    1. `ccp` module **kept available by default** because it can back
       platform crypto, RNG, and fTPM functions. Those dependencies vary by
       machine: neither loading nor blacklisting `ccp` universally controls
       fTPM or disables the PSP.
    2. IOMMU isolation (`amd_iommu=on`, auto-set via CPU detection).
    3. Platform Secure Boot (PSB) awareness — product-specific provisioning
       can burn irreversible OTP fuses; the user doc warns against enabling it
       without exact vendor documentation and a recovery plan.
    4. UEFI Secure Boot + lockdown=integrity (shared with Intel path).
    5. Available fwupd security attributes can surface some platform state;
       they do not guarantee PSP coverage or a particular HSI level.
    6. CVE awareness documentation — CVE-2025-2884 (TCG TPM 2.0
       reference-code out-of-bounds read, CVSS 6.6 medium).
       [AMD-SB-4011](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-4011.html)
       is authoritative: affected TPM implementation and
       minimum firmware differ by processor family, so there is no universal
       AGESA version. Also tracked: CVE-2021-3764
       (`ccp_run_aes_gcm_cmd()` local DoS; use the maintained Fedora kernel)
       and faulTPM (fault-injection attacks on Ryzen fTPM).
- **Residual risk**: ME/PSP firmware below the OS boundary is not fully
  controllable by the host. Blacklisting the Linux `ccp` driver does not
  switch off PSP firmware and can remove useful host functions. Mitigations
  reduce but do not eliminate firmware-class threats on either vendor.
  Intel documents AMT as operating independently of the OS, so host
  firewalld/nftables rules cannot enforce the LAN/WAN claim against AMT OOB.
  Pre-compromised PSP/ME firmware from factory = out-of-scope (see
  `scope.md` §4).

## Trust assumptions (things we trust)

- The Linux kernel, compiled by Fedora, signed by Fedora's release key.
- Fedora 44 repositories and GPG keys (imported at install time).
- Platform firmware and its configured UEFI Secure Boot trust anchors; when
  Secure Boot is enabled, Fedora's currently signed shim/GRUB/kernel chain. The
  exact Microsoft/OEM CA set is platform- and firmware-state-dependent and is
  not provisioned by this image.
- Firefox release binaries and Mozilla CA (required for Firefox to trust
  certs — no realistic alternative).
- arkenfox upstream as the historical source of the Firefox user.js
  baseline (v144.0 snapshot absorbed into this repo 2026-04-22; no
  runtime network trust in arkenfox post-absorption).
- HorlogeSkynet upstream as the historical source of the Thunderbird user.js
  baseline (tagged v140.2 snapshot); the carried NoID Privacy derivative is maintained
  and embedded locally, with no build/runtime upstream-user.js fetch.
- uBlock Origin's image seed at the pinned GitHub release tag, plus the fixed
  official channel and Firefox native-signature boundary used only by the
  user-started Update All transaction for later versions.
- VSCodium's upstream repository and signing identity. The local key material
  is accepted only after an exact full-fingerprint match
  (`1302DE60231889FE1EBACADC54678CF75A278D9C`); package and repository-metadata
  signatures are required. This removes first-import TOFU but does not remove
  trust in the upstream key holder, repository or binaries.

### Repository metadata and package-signature boundary

DNF treats RPM payload-signature enforcement (`gpgcheck`, exposed by DNF5 as
effective `pkg_gpgcheck`) separately from OpenPGP verification of repository
metadata (`repo_gpgcheck`). NoID Privacy requires payload-signature
verification for every enabled repository and treats a missing package check
as an update error. `noid-update-all.sh` inventories DNF5's effective state
after the user-started metadata refresh and reports every enabled repository
without metadata OpenPGP verification separately. The live inventory is
authoritative because enabled repositories are user-changeable.

NoID Privacy Workstation enables metadata verification whenever the publisher
supplies a DNF-compatible `repomd.xml` signature; the shipped VSCodium
repository is the current example (`repo_gpgcheck=1` plus an exact locally
pinned signing key).
The Fedora 44 Cisco OpenH264 endpoint configured by Module 08 does not publish
`repomd.xml.asc`, so that repository deliberately keeps `repo_gpgcheck=0`.
Enabling it would make the metadata refresh fail; it cannot create a signature
that the distribution endpoint does not supply.

For Cisco OpenH264, the accepted residual boundary is an HTTPS Fedora
metalink, a local Fedora package key and mandatory RPM payload-signature
verification. This prevents an unsigned payload from satisfying the
transaction, but it does not OpenPGP-authenticate repository metadata or its
freshness: a compromised trusted distribution path can hide updates or change
which still-valid signed candidates are visible. Fedora builds and signs the
RPMs, Cisco distributes those exact binaries, and `skip_if_unavailable=False`
makes a distribution-path outage visible instead of silently dropping the
repository.

## Trust non-assumptions (things we don't trust)

- Intel Management Engine firmware, AMT SKU configuration.
- OEM UEFI firmware SMM drivers (partial mitigation via Secure Boot +
  IOMMU).
- Upstream Fedora `audit` rules (we override with 132 hardened
  b64/b32-complete rules).
- Fedora default `systemctl list-unit-files` state (the project masks an
  explicit cross-module set of unused units; `MASK_LIST_EOF` in Module 08 and
  the service-specific modules are authoritative because the set evolves).
- Fedora default DNS resolver config (we replace it with strict authenticated
  global + physical Quad9 DoT; the explicit compatibility mode permits a
  documented DNS/53 downgrade, while provider-neutral VPN/private DNS takes
  precedence; Firefox and Thunderbird follow that system path by default).
- Fedora default GNOME dconf profile (we override with `/etc/dconf/db/distro.d/`).

## Post-Quantum Cryptography (PQC) status

**Threat model**: a future cryptographically relevant quantum computer
(CRQC) would break RSA, ECC (including Curve25519 and NIST P-curves), and
finite-field DH. NIST says no one knows when such a machine will exist;
estimates range from a few years to a few decades. Symmetric 256-bit
cryptography retains a conservative margin of roughly 128 bits against ideal
generic quantum key search, rather than suffering Shor's exponential
public-key break.

**Active threat today**: "harvest now, decrypt later" — an adversary records
classically protected traffic now and attacks its public-key exchange after a
CRQC arrives. Short-lived ephemeral Curve25519 keys give forward secrecy
against later long-term-key theft, but do not make a recorded Curve25519
exchange PQ-resistant.

### Coverage matrix (layers controlled by NoID Privacy)

| Layer | Mechanism | PQ status |
|-------|-----------|-----------|
| Disk-at-rest (LUKS) | Expected AES-XTS with two AES-256 keys + Argon2id keyslot; verify installed header/keyslot | Strong symmetric PQ margin when observed; passphrase and parameters still matter |
| SSH transport | hybrid algorithms first, Curve25519 fallback (Module 09) | Hybrid only when `mlkem768x25519` or `sntrup761x25519` is negotiated |
| TLS 1.3 (Firefox + Thunderbird) | explicit hybrid-client pref, NSS 3.118+ default group | Hybrid-capable; selected peer and handshake determine coverage |
| DNS transport | Strict authenticated global + physical Quad9 DoT by default; optional opportunistic/off selector; VPN/private per-link DNS precedence with NoID Privacy's best-effort opportunistic fallback for unset profiles; Thunderbird/DKIM follow the active OS/VPN resolver; optional browser Secure DNS | No image-wide PQ guarantee; active resolver, DNS/53 downgrade, compatibility fallback and endpoint negotiation are scope-dependent |
| Browser HTTPS | Firefox/NSS hybrid-capable client | Hybrid only when the connection negotiates `X25519MLKEM768` |

### Upstream-dependent gaps (NOT fixable by NoID Privacy)

| Layer | Mechanism | PQ status |
|-------|-----------|-----------|
| WireGuard (provider-managed or self-managed) | classical Curve25519 handshake; an independently provisioned strong preshared key can add a symmetric layer | No standardised interoperable PQ handshake mode verified in this audit |
| OpenPGP / GnuPG email | installed client support and correspondent keys vary | RFC 9980 defines PQ/traditional algorithms; installed GnuPG 2.4.9 has no PQ public-key algorithm and generic Thunderbird/GnuPG interoperability is not established |
| Secure Boot chain | platform/upstream classical signatures | Platform/distribution migration required |
| MOK keys (NVIDIA-driver signing, Module 19) | local classical signature | No PQ kernel-module-signing path provided |
| Fedora RPM signatures | upstream classical signatures | Distribution migration required |

Lockdown, Secure Boot, signed repositories, TLS, and AIDE remain useful
defence-in-depth today, but none converts a classical signature or key exchange
into a PQ one. The image cannot fix peer, protocol, firmware, or distribution
signature gaps unilaterally.

### HNDL priorities

- Long-lived public-key-encrypted mail is a high-priority concern because the
  original ciphertext may already have been copied.
- WireGuard and any TLS/SSH session that negotiates a classical fallback remain
  recordable classical exchanges.
- Browser TLS and SSH have hybrid-capable client paths, but each session must
  be verified rather than labelled globally protected.
- LUKS has a strong symmetric margin but still depends on passphrase entropy,
  KDF parameters, and protection against offline copies.

### Maintenance posture

- **Watch-items** (release backlog): IETF WireGuard-PQ extension drafts,
  RFC 9980 implementation/interoperability in GnuPG and Thunderbird, and the
  UEFI/Microsoft Secure Boot PQ-key migration timeline.
- Re-verify the actual negotiated algorithms and package capabilities for each
  release; client capability is not equivalent to endpoint coverage.

For a full user-facing PQ status guide (configuration knobs, opt-out
options, future-proofing recommendations), see
[`docs/post-quantum-readiness.md`](post-quantum-readiness.md).

## Scope boundary

For explicit out-of-scope threats (physical seizure, evil-maid on the
BIOS flash, state-actor custom 0-day), see [`docs/scope.md`](scope.md).
