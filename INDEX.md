# NoID Privacy Workstation 44 — repository index

The supported compose entry point is [`kickstart/master.ks`](kickstart/master.ks).
It includes 42 snippets in module order except for dependency-driven positions
documented in the master's constraint list (notably M11b after M11 and M40
before M37). Some snippets harden the base,
while others provide applications, documentation, branding, cleanup or final
verification; the module count is not a security score.

## Kickstart modules

| Module | Purpose and important boundary |
|---|---|
| [`01-bootloader.ks`](kickstart/snippets/01-bootloader.ks) | GRUB/kernel-command-line hardening and optional GRUB-password guidance. Firmware Secure Boot state remains external. |
| [`02-sysctl.ks`](kickstart/snippets/02-sysctl.ks) | Kernel/network sysctl baseline with runtime verification and documented compatibility exceptions. |
| [`03-firewalld.ks`](kickstart/snippets/03-firewalld.ks) | Physical-interface inbound DROP, forwarding controls and firewalld policy deployment. |
| [`04-arp-hardening.ks`](kickstart/snippets/04-arp-hardening.ks) | Closed pre-network gateway-identity validation plus a transactional permanent neighbour pin; M03 retains the identity for its fail-closed XDP return gate while native IPv4 ACD/ARP remains enabled. |
| [`05-lan-isolation.ks`](kickstart/snippets/05-lan-isolation.ks) | Owns strict-default global + physical Quad9 DoT and its explicit opportunistic/off selector. VPN/private per-link transport is a separate M23-owned default/profile boundary; M05 never rewrites those profiles. Also owns LAN service suppression, policy toggles and exact peer exceptions. |
| [`06-vpn-killswitch.ks`](kickstart/snippets/06-vpn-killswitch.ks) | VPN-interface classification, lower-only live WireGuard MTU reconciliation, and opt-in WAN-strict mode with libnm-reconciled literal/runtime-confirmed tuples plus bounded DNS candidates. Provider routing/DNS behavior is a separate boundary. |
| [`07-ipv6-privacy.ks`](kickstart/snippets/07-ipv6-privacy.ks) | Locked physical-interface IPv6-off transaction and runtime status; VPN-internal IPv6 is a separate boundary and physical-WAN reactivation is not release-qualified. |
| [`08-service-minimization.ks`](kickstart/snippets/08-service-minimization.ks) | Service masks/drop-ins, privacy toggles, AI-agent configuration, VSCodium/Claude integration and optional native Claude/Codex installers. |
| [`09-ssh.ks`](kickstart/snippets/09-ssh.ks) | Hardened SSH client defaults and an opt-in server template; `sshd` is absent/off by default. |
| [`10-pam-login.ks`](kickstart/snippets/10-pam-login.ks) | PAM/authselect, password-quality, faillock, sudo and shell-history policy. |
| [`11-dns-ntp.ks`](kickstart/snippets/11-dns-ntp.ks) | Owns chrony NTS time synchronization only. DNS/resolved policy belongs to M05; timing endpoint metadata is not hidden. |
| [`11b-dns-health.ks`](kickstart/snippets/11b-dns-health.ks) | Manual, evidence-first DNS diagnostics; active queries require an explicit target and no automatic recovery is installed. |
| [`12-selinux-auditd.ks`](kickstart/snippets/12-selinux-auditd.ks) | SELinux enforcing baseline, immutable audit rules and optional desktop audit notifications. |
| [`13-aide-welcome.ks`](kickstart/snippets/13-aide-welcome.ks) | User-owned AIDE candidate review/commit and check workflows, status/welcome UI, notification toggles and per-user native AI CLI installers. |
| [`14-usbguard.ks`](kickstart/snippets/14-usbguard.ks) | First-boot USBGuard policy, IPC authorization and reviewed device-allow workflow. |
| [`15-intel-me-mitigation.ks`](kickstart/snippets/15-intel-me-mitigation.ks) | Intel MEI/KT/SOL host-driver surface reduction and hardware-boundary guidance; it does not disable ME/AMT or AMD PSP. |
| [`16-firefox.ks`](kickstart/snippets/16-firefox.ks) | Firefox profile/AutoConfig hardening, pinned uBlock Origin and managed extension defaults. |
| [`17-gnome-hardening.ks`](kickstart/snippets/17-gnome-hardening.ks) | GNOME privacy defaults, selected user-service/D-Bus suppression, Live-installer lifecycle control, Fedora-stock Mutter runtime gates and the non-persistent Fedora-RPM GNOME Software action. |
| [`18-flatpak-sandboxing.ks`](kickstart/snippets/18-flatpak-sandboxing.ks) | Flatpak version gate, remote policy and global sandbox overrides plus RPM/Flatpak/AppImage selection guidance. Per-app permissions remain reviewable. |
| [`19-nvidia-mok-docs.ks`](kickstart/snippets/19-nvidia-mok-docs.ks) | Opt-in proprietary NVIDIA installation, module-signature checks and MOK guidance. |
| [`20-snapper.ks`](kickstart/snippets/20-snapper.ks) | Native Btrfs-default Snapper model, checked CLI rollback and a measured 30-day deletion target for eligible snapshots. Active/default roots are protected; `/home` is outside rollback. |
| [`21-kernel-module-blacklist.ks`](kickstart/snippets/21-kernel-module-blacklist.ks) | Module blacklist/install-deny baseline plus documented hardware escape hatches. |
| [`22-luks-partitioning.ks`](kickstart/snippets/22-luks-partitioning.ks) | Conditional LUKS/Btrfs detection, mount hardening, scrub timer and header-backup helper. Encryption is selected in Anaconda, not forced by this module. |
| [`23-networkmanager.ks`](kickstart/snippets/23-networkmanager.ks) | MAC privacy plus per-profile connection/default reconciliation: physical Ethernet/Wi-Fi starts fail-closed at strict DoT, while unset non-physical/VPN/private profiles inherit best-effort opportunistic DoT with DNS/53 fallback and explicit profile values win. Global resolved/DNS selection remains M05-owned. |
| [`24-firmware-fwupd.ks`](kickstart/snippets/24-firmware-fwupd.ks) | fwupd/LVFS privacy defaults, disabled polling and user-initiated firmware workflow. |
| [`25-update-process.ks`](kickstart/snippets/25-update-process.ks) | User-initiated update orchestrator/GUI, snapshots, package/firmware/agent updates and check-only AIDE evidence. |
| [`26-package-set.ks`](kickstart/snippets/26-package-set.ks) | Explicit workstation package additions/removals and post-install verification. |
| [`27-hardware-tuning.ks`](kickstart/snippets/27-hardware-tuning.ks) | zram, earlyoom, tuned, I/O and hardware-conditional thermal/audio settings. |
| [`28-local-ai-docs.ks`](kickstart/snippets/28-local-ai-docs.ks) | Installs the local-AI guide; no model runtime is installed or started automatically. |
| [`29-user-docs.ks`](kickstart/snippets/29-user-docs.ks) | Tier-A getting-started and VPN documentation. |
| [`30-user-docs-tier-b.ks`](kickstart/snippets/30-user-docs-tier-b.ks) | Tier-B operational docs and the `noid-help` navigator. |
| [`31-user-docs-tier-c.ks`](kickstart/snippets/31-user-docs-tier-c.ks) | Architecture, troubleshooting and canonical product-boundary documentation. |
| [`32-branding.ks`](kickstart/snippets/32-branding.ks) | Derivative identity, artwork, release metadata and trademark disclosures. |
| [`33-operational-hygiene.ks`](kickstart/snippets/33-operational-hygiene.ks) | User-invoked integrity/OAuth/profile-isolation helpers and docs; no background scanner. |
| [`34-firefox-playground.ks`](kickstart/snippets/34-firefox-playground.ks) | Separate amnesic Firefox profile and launcher. It is browser-profile isolation, not a VM boundary. |
| [`35-thunderbird.ks`](kickstart/snippets/35-thunderbird.ks) | Thunderbird profile/AutoConfig defaults, pinned DKIM Verifier, provider-neutral OS/VPN DNS, minimal DuckDuckGo policy and profile helper. External GnuPG smartcard support is experimental. |
| [`36-noid-network-app.ks`](kickstart/snippets/36-noid-network-app.ks) | GTK UI for LAN exceptions, WAN-strict control and policy status. |
| [`37-noid-tools-app.ks`](kickstart/snippets/37-noid-tools-app.ks) | GTK launcher for the curated noid-* helper CLIs with read-only default verbs. It runs each helper in a terminal; it adds no privilege path of its own. |
| [`40-audit-bundle.ks`](kickstart/snippets/40-audit-bundle.ks) | SHA-pinned supplemental NoID Privacy Linux posture inventory, offline and non-remediating by default; ordinary service/access logging can still occur. Explicit evidence-capture flags remain separate operator actions. It reports UNKNOWN/NOT_TESTED explicitly and cannot replace candidate-specific release gates. |
| [`41-anaconda-cleanup.ks`](kickstart/snippets/41-anaconda-cleanup.ks) | Transactional first-boot cleanup of live-user/installer remnants. |
| [`42-forensic-retention.ks`](kickstart/snippets/42-forensic-retention.ks) | Scheduled 30-day pruning for exact listed system traces plus a stopped-daemon boundary for NetworkManager's RAM-backed history. M20 separately owns snapshot retention; user/application data is outside M42's scope. |
| [`99-finalize.ks`](kickstart/snippets/99-finalize.ks) | Cross-module artifact/state checks that reject compose-created AIDE trust state. Runtime/hardware validation and explicit user baseline review are still required. |

## Other source trees

- [`scripts/`](scripts/) — canonical build, offline preparation and archive
  helpers.
- [`tests/`](tests/) — structural tests, embedded-script ShellCheck/syntax
  extraction, smoke tests and installed-system pre-ship checks.
- [`firefox/`](firefox/) and [`thunderbird/`](thunderbird/) — canonical browser
  preference sources; regeneration scripts gate their embedded kickstart copies.
- [`licenses/`](licenses/) — exact tag-bound third-party notices extracted
  byte-for-byte into the image license inventory by the consuming modules.
- [`overrides/noid-lan-xdp/`](overrides/noid-lan-xdp/) — LAN-XDP BPF source,
  controller script and the pinned prebuilt object; regeneration-checked into
  its consuming module.
- [`manifests/`](manifests/) — exact data manifests (ACLs, kernel command line,
  chrony sources, Flathub descriptor, language packs) consumed by modules and
  tests.
- [`branding/`](branding/) — original NoID Privacy artwork with a checked
  SHA-256 inventory, staged by the build wrapper.
- [`docs/`](docs/) — build, threat-model, security-boundary, operation and
  release documentation. Image-shipped user docs are generated from or embedded
  in the applicable modules and parity-checked where a standalone source exists.

## High-level documentation

- [`README.md`](README.md) — project overview and bounded claims.
- [`docs/threat-model.md`](docs/threat-model.md) and
  [`docs/scope.md`](docs/scope.md) — attacker model, guarantees and exclusions.
- [`docs/firewall-policies-explained.md`](docs/firewall-policies-explained.md),
  [`docs/hardware-network-compatibility.md`](docs/hardware-network-compatibility.md),
  [`docs/wan-egress-strict.md`](docs/wan-egress-strict.md) and
  [`docs/log-retention.md`](docs/log-retention.md) — exact network and retention
  semantics.
- [`docs/ai-workspace.md`](docs/ai-workspace.md) and
  [`docs/28-local-ai.md`](docs/28-local-ai.md) — cloud-agent and local-inference
  privacy boundaries.
- [`docs/build.md`](docs/build.md),
  [`docs/build-reproducibility.md`](docs/build-reproducibility.md) and
  [`docs/release-process.md`](docs/release-process.md) — supported build path,
  reproducibility limits and release gates.
- [`docs/pin-inventory.md`](docs/pin-inventory.md) — every pinned third-party
  artifact, its official channel, pin locations, and the refresh procedure.
- [`CHANGELOG.md`](CHANGELOG.md) — release-facing changes; source history is not
  a substitute for the verification gates above.

## Validation entry points

```bash
# Source checkout / build host: no candidate-runtime claims.
bash tests/run-all.sh
sudo bash tests/smoke/run-all.sh
bash tests/pre-ship/09-ssh-fix-phase-disabled.sh
sudo -v
scripts/build-iso.sh

# Only after the unsigned candidate exists: execute every command and action
# in the canonical pre-ship block of tests/README.md inside the candidate's
# live/fresh-install/reboot lifecycle (and controlled WAN where required),
# never against the build host. Retain a sorted executable inventory and a
# result ledger; the short examples here must not become a competing partial
# matrix.
```

The structural suite validates source invariants; smoke tests exercise selected
helpers in disposable roots. A successful ISO build still requires the manual
live/install/reboot matrix and installed-VM package-freshness gate in
[`docs/release-process.md`](docs/release-process.md) before signing or publishing.
The M17 pre-ship script proves source integration only; its own header describes
the separate candidate ISO/RPM inspection that must follow the build.
