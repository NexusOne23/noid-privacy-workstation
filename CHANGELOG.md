# Changelog

All notable changes to NoID Privacy Workstation are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Release headings use the project convention `vMAJOR.MINOR`.

This file records release-level, user-visible highlights. Detailed
implementation history, validation evidence and individual pin changes remain
available in the Git history, module sources and project documentation.

## [v1.8] - 2026-09-02

Correctness and evidence-integrity release for the Fedora 44 / GNOME 50 base.
It keeps the documented silent-machine and threat-model boundaries while making
failed queries, partial reads and interrupted runs fail closed instead of
passing as success, and refreshes every changed external artifact through exact
evidence.

### Changed

- Allowed agents to run full system updates only when the user explicitly
  requests that invocation. General audit or continuation requests remain
  insufficient; separate high-risk actions and AIDE baseline changes retain
  their existing authorization boundaries.
- Verified the Fedora build base independently of the release user's GPG setup,
  including on a fresh account without a keyring.
- Integrated the published Linux audit tool v3.7.2 at commit `706cb0a`, with
  matching source, byte-count and SHA-256 pins for the image and support medium.
- Refreshed the consent-gated Claude Code CLI/VSIX seeds to 2.1.265, Codex CLI
  to 0.153.4 and Codex VSCodium to 26.5901.22334; advanced the signed uBlock
  Origin seed to 1.74.0 and the reviewed Just Perfection seed to v37.
- Refreshed the documentation-only Ollama, llama.cpp and llama-vscode
  evaluation pins and the Ornith 1.5 reference records, and advanced the
  reviewed Fedora-signed Lorax build stack from 44.6 to 44.7.
- Respected custom XDG data directories, hidden launcher overrides and literal
  search paths across Setup's autostart picker and the session environment
  generators, and interpreted network wait durations as bounded decimal values.
- Routed every printing opt-in in the user guides through
  `noid-toggle-printing`, and clarified that the cross-agent policy retains
  higher-priority client rules and that its multi-license description applies
  to the Workstation repository.
- Moved the source suite's desktop and permission fixtures to an ordinary user
  account in CI and retired the legacy whole-test exception list, so no
  tolerated failure remains in the release gate.
- Corrected documentation and comments that had drifted from the shipped code:
  licensing inventory, module attribution in the index, the Update All step
  list, the Firefox revert surfaces, the WAN-strict component table, the
  tmpfiles inventory and the mutable-pin exceptions.

### Fixed

- Preserved VPN uninstall failures until removal is verified, diagnosed VPN
  routes across routing tables, and bounded NetworkManager readiness probes so
  a hung client or unavailable clock cannot indefinitely delay an autostart
  application.
- Refreshed XDP gateway admission when an interface changes IPv4 subnets and
  retained the previous policy when an address query fails. Concurrent first
  LAN, ARP-pin and topology transactions share one lock, and every fail-closed
  exit is reported through its one-line diagnostic contract.
- Preserved DNS rollback after filesystem errors, verified restored default
  profiles against their previous link state, and kept saved endpoint state and
  nftables consistent after directory-sync failures.
- Stopped WireGuard MTU reconciliation when interface or firewall-mark queries
  fail or return invalid marks, so an unreadable mark can no longer select an
  unrelated unmarked route and authorize an incorrect live MTU change.
- Blocked Firefox and Thunderbird profile changes when process queries fail or
  return invalid evidence, rejected incomplete profile configurations even when
  the generated prefix matches, and added two bounded retries for transient
  outages of the official Thunderbird add-on channel.
- Blocked reboot readiness on incomplete kernel inventories or failed NVIDIA
  queue queries, matched running-kernel boot entries by their exact version,
  and made Update All validate its canonical reboot-readiness record before
  publishing it.
- Kept the NVIDIA shutdown/sleep inhibitor active when its queue cannot be read
  or holds an unsafe pending object, and rejected unreadable GPU attributes,
  incomplete device inventories and failed connector scans before enabling the
  GTK/Mutter offload workaround.
- Checked persistent mount flags in the actual fstab options field and in their
  effective order, verified LUKS backup staging permissions on the pinned
  directory itself, and bound scheduled AIDE report filenames to the systemd
  invocation with exact retention for new and legacy names.
- Rejected empty, surplus, combined and ambiguous arguments before Bluetooth,
  Location, Gaming, Bash-history, codec, MEI and GRUB password changes, so
  commands such as `on --help` can no longer apply them silently.
- Stopped Plymouth branding publication, Lorax override staging, the final
  image-hygiene gate and the compose and release gates on failed reads or
  interruption, instead of publishing a clean report or a successful run.
- Verified weak-dependency settings, Flatpak remote identities and PipeWire
  capture inventories with their native readers, so case differences, INI-only
  inheritance, invalid syntax or malformed inventories can no longer conceal a
  missing value.
- Bounded the JIT and GNOME renderer release checks to the managed Shell
  process and exact environment records, so text inside an unrelated value can
  no longer masquerade as an enabled setting.
- Forwarded Network tab requests to the already-running application, so Setup's
  printer shortcut opens LAN Exceptions even when Network is already open, and
  let `noid-aide-baseline-review help` answer without root.
- Corrected recovery, Thunderbird calendar, SSH known-host, TLS-probe, browser
  comparison, first-boot timing and local-AI guidance where it no longer
  matched the shipped code, and stopped executable examples before reboot,
  service restart, mounting or download when their preconditions fail.

### Security

- Disabled IPv6 type-2 source-routing processing with the kernel's negative
  `accept_source_route` value; zero still permits that processing subject to
  separate Mobile IPv6 checks. This excludes Mobile IPv6 type-2 routing while
  preserving ordinary routed VPN traffic.
- Verified every NVIDIA module's actual PKCS#7 signature against the exact
  local akmods certificate before approving a boot image. Damaged payloads and
  foreign signatures with matching certificate metadata are rejected.
- Kept quoted USB device names and serials separate from policy attributes in
  the USBGuard manager and admission helper, so device text can no longer hide
  HID warnings, bypass controller-rule protection, invent rule conditions or
  trigger false ModeSwitch recognition.
- Made the USBGuard stop-recovery override shadow Fedora's exact global
  `10-timeout-abort.conf` basename, so systemd actually selects the intended
  15-second direct-kill path instead of lexicographically restoring SIGABRT.
- Applied the LUKS unlock-retry policy token-exactly to every `rd.luks.uuid` in
  the target compose, the command-line canonicalizer and the first-boot helper,
  so multi-volume encrypted layouts no longer leave a volume without its policy
  or diverge between the three writers.
- Made the installed SELinux release gate enforce Fedora 44's real schema
  baseline while reporting newer kernel-extension coverage separately, so an
  absent vendor capability is no longer an impossible release requirement and
  an enabled capability with missing access vectors still fails closed.
- Required the exact release signer and usable signature/key status in the
  download-verification recipe, authenticated the archive's private candidate
  copy before publication, and made the audit starter validate every parent
  directory before trusting its pinned payload or version marker.
- Reapplied the root-only permission policy after `crontabs` transactions as
  well, since that package owns the periodic cron directories, and bound the
  compose finalizer's trigger inventory to Module 10's action file so the two
  cannot drift apart again.
- Prevented filenames containing colons from hiding private-data matches in the
  source-tree privacy check, and kept password hashes and gateway values out of
  diagnostic output and journals.

## [v1.7] - 2026-08-23

Boot-safety, network-policy and reviewed-tooling release for the Fedora 44 /
GNOME 50 base. It keeps updates user-operated and the local-AI stack optional
while making reboot decisions explicit, preserving constrained DHCP operation
and refreshing every changed external artifact through exact evidence.

### Added

- Added a canonical two-axis reboot verdict that reports activation need and
  boot safety independently, retains exact boot blockers across an interrupted
  update and prevents every GUI, login and status surface from offering an
  unsafe restart.
- Added a bounded one-boot pstore capture procedure for diagnosing hangs before
  persistent logging starts without weakening the image's normal no-pstore
  privacy default.
- Added reviewed, immutable Ornith 1.5 candidate metadata and an explicit Llama
  4 evaluation boundary without presenting publisher claims as local benchmark
  results.

### Changed

- Refined DHCPv4 egress so only the required link-local bootstrap traffic is
  admitted while explicit per-peer LAN grants remain intact before, during and
  after lease acquisition.
- Refreshed the consent-gated seeds to Claude Code CLI/VSIX 2.1.241, Codex CLI
  0.149.1 and Codex VSCodium 26.5818.61809; pinned the Linux auditor at v3.7.2
  and the documentation-only Ollama, llama.cpp and llama-vscode evaluations at
  0.32.15, b10605 and 0.0.63 with exact reviewed sizes and SHA-256 values.
- Consolidated updater, login, status and GUI reboot presentation on the same
  canonical kernel/NVIDIA reader and retained fail-closed handling for
  malformed state.
- Tightened helper failure propagation and compose-log classification so
  failed cleanups, generated candidates and known benign diagnostics cannot be
  mistaken for successful or unexplained release evidence.

### Fixed

- Reconciled the fresh-install GDM log directory to its canonical ownership,
  mode and SELinux label before the first graphical login.
- Described the one-time pending reboot with a neutral reboot icon as a
  verified boot-policy or update activation instead of misidentifying every
  first boot as an update.
- Corrected NVIDIA akmods repair semantics so a missing exact kmod uses install
  rather than reinstall, an rpmdb failure remains distinguishable from normal
  absence, and the generated package is required as a postcondition.
- Preserved the NVIDIA repair diagnostic on unreadable RPM inventory instead
  of clearing it before the failure summary.
- Reset the actual reboot marker fields before every graphical update run, so
  an early second-run failure cannot reuse the prior run's safe verdict.
- Rejected unsolicited DHCP replies on statically addressed links before
  AF_PACKET while retaining the exact request-correlated DHCP bootstrap needed
  by dynamically addressed links.
- Preserved global network readiness when an unrelated gatewayless physical
  LAN or dock activates, while retiring it fail-closed when the pinned WAN
  loses its gateway or the recorded state is invalid.
- Repaired helper error boundaries and explicit LAN-grant restoration around
  firewall transactions.
- Restored NTS automatically after a bounded DNS or NTS-KE startup timeout,
  using native exponential retry backoff only while the gateway/XDP readiness
  boundary remains valid.

### Security

- Completed the narrowly scoped SELinux HugeTLB permissions for yescrypt
  password creation, history maintenance and verification without broadening
  unrelated authentication domains.
- Bound Firefox and Thunderbird local-network WebSocket exceptions to the
  intended Local Network Access policy arm instead of broadening unrelated
  WebSocket behavior.
- Kept reboot readiness fail-closed when NVIDIA, initramfs, kernel-command-line,
  BLS identity or state publication evidence is incomplete.
- Documented the still-open Ollama tensor-redirect SSRF boundary and retained
  loopback-only, no-cloud and host-egress mitigations for optional evaluation.

## [v1.6] - 2026-08-14

Reliability, installation-hygiene and hardware-compatibility release for the
Fedora 44 / GNOME 50 base. It keeps the documented silent-machine and threat-
model boundaries while making installed identities unique, repairing the
hybrid-GPU session path and removing temporary policy that Fedora now owns.

### Added

- Added a fail-closed first-boot identity transition that creates fresh
  machine, random-seed, BRLAPI and NVMe host identities for every installation
  instead of inheriting compose-time values.
- Added final-SquashFS hygiene and independent two-install uniqueness gates to
  prevent build-host state, installer evidence or shared identities from
  reaching a signed image unnoticed.

### Changed

- Returned thermal policy completely to Fedora after the fixed Fedora 44
  `thermald` build made the temporary platform bridge obsolete.
- Made neutral UTC the untouched Live and installer default while preserving
  the timezone consciously selected during setup and across reboot.
- Kept Firefox on the system resolver by default while restoring its built-in
  Secure DNS provider chooser without country lookup, automatic DoH enablement
  or a forced provider; the same policy applies to default and Playground
  profiles.
- Refined Update All diagnostics so transient marketplace, EGO and Open-VSX
  outages defer with warnings while malformed identity, structure or digest
  evidence remains an error. The service-restart hint is now cache-only and
  isolated from unrelated repository configuration, with no network fallback.
- Refreshed the reviewed local-AI guidance pins and retained their exact
  artifact, checksum, loopback and no-background-service boundaries.

### Fixed

- Allowed automatic time to recover a certificate-valid firmware RTC offset
  after NTS authentication and source selection, so a fresh installation no
  longer disables automatic time when firmware stored local civil time.
- Preserved Fedora's `dbus-tools` runtime through first-boot cleanup so the
  hybrid Intel/NVIDIA session helper can publish `GSK_RENDERER=gl`; affected
  GTK applications no longer initialize the NVIDIA render node during ordinary
  starts.
- Refreshed the reviewed v3.7.1 Linux auditor so DNS and HTTPS egress identity
  checks stay within one address family, eliminating false mismatch warnings
  on dual-stack tunnels.
- Disabled Mutter's optional automatic Xwayland teardown after a reproduced
  GNOME session failure, retaining native Wayland defaults and explicit X11
  compatibility without selecting an experimental Mutter feature.
- Corrected installed-image cleanup for Fedora's native `/root` mode, Anaconda
  post-install state, Live-installer Dracut metadata umask and merged-`sbin`
  command resolution, preventing false cleanup failure or first-login stalls.
- Kept strict IPv4 reverse-path filtering in force across NetworkManager
  activation instead of repairing a temporarily loosened value afterward.
- Stopped status inspection from waking fwupd solely to report security state,
  and made closed/orphaned vTPM log rotation respect active-VM SELinux labels.

### Security

- Raised the Flatpak security floor to 1.18.1, requiring Fedora's update for
  the upstream sandbox, system-helper and extraction boundary fixes.
- Closed Fedora 44's SELinux policy gap for libxcrypt Yescrypt's optional
  HugeTLB mapping with two domain-specific map-only permissions, so normal
  password changes and GDM logins no longer emit enforcing AVCs while all
  password-data and filesystem permissions remain unchanged.
- Retired exact Anaconda and Kickstart evidence before login and bound GDM and
  user-session admission to successful host-identity and cleanup transitions.
- Promoted the host-identity helper to the same AIDE secure-path contract as
  the other privileged NoID Privacy helpers and documented its rescue repair
  path.

## [v1.5] - 2026-08-08

Audit-driven reliability and usability release for the Fedora 44 / GNOME 50
base. It preserves the silent-machine defaults and documented threat-model
ceiling while repairing controls that could become inert, strengthening
verification and making supported opt-ins easier to find.

### Added

- Added a one-shot Fedora RPM view to GNOME Software through Setup and the
  app-grid context menu. Ordinary launches remain Flatpak-only, the selection
  does not persist, and AppImages remain a documented manual exception without
  background integration.
- Added guided Setup flows for printing and USB devices. Both retain the
  existing service-minimized, whitelist-based defaults and explain the
  follow-up authorization needed for local or network hardware.
- Added read-only WAN-strict, firewalld, nftables and WireGuard MTU audits to
  the Network app, and exposed WAN-strict state in `noid-status`.

### Changed

- Changed unset VPN/private NetworkManager profiles from forced `DoT=no` to
  best-effort opportunistic DoT. Global and physical Quad9 remain strict and
  fail-closed, incompatible resolvers may still use DNS/53 on the selected
  per-link route, and explicit profile values remain authoritative.
- Extended WAN-strict endpoint handling to transient provider profiles and
  directly configured WireGuard tunnels. Bounded retained leases, peer-key
  identity and exact revoke paths preserve connectivity without making the
  image provider-specific.
- Unified the user-facing CLI presentation across status, Tools and guided
  installers while preserving the existing brief and JSON contracts.
- Returned the first-party GTK apps to Fedora's maintained renderer selection,
  standardized their resizable start size, and kept the dedicated NVIDIA
  renderer policy limited to affected hybrid systems.
- Made Flatpak and browser-extension maintenance more state-aware: empty
  Flatpak scopes avoid network work, interrupted related-ref transactions get
  bounded resumptions, signed catalogs are checked as live trust state, and
  uBlock Origin/DKIM updates retain explicit identity and compatibility gates.
- Refreshed the reviewed opt-in seeds to Claude Code CLI/VSIX 2.1.226, Codex CLI
  0.147.0, Codex VSCodium 26.5803.41515 and signed uBlock Origin 1.73.0.
  Background updaters remain disabled and the initial bytes remain pinned by
  exact source, size and SHA-256.
- Refreshed the documentation-only local-AI evaluation pins to Ollama 0.32.6,
  llama.cpp b10326 and llama-vscode 0.0.59. The current VSIX profile keeps RAG
  disabled, separates edit/delete consent and prevents workspace-owned DSL
  scripts from entering its direct shell-execution path by default.

### Fixed

- Repaired physical-network and VPN convergence across early XDP retries,
  already-pinned XDP/TC recognition, OpenVPN endpoint arming, retained-provider
  state display, gateway replacement, overlapping LAN prefixes and
  multi-adapter readiness.
- Kept active WireGuard links within the fragmentation-free ceiling of their
  real outer route without rewriting provider profiles, and moved safe
  post-activation work out of NetworkManager's serial dispatcher queue so VPN
  autoconnect no longer stalls behind completed WLAN work.
- Made Gaming Mode idempotent and split Steam's multilib installation into an
  explicit post-reboot stage, preventing package work before the running kernel
  actually permits the required 32-bit ABI.
- Kept the installed-only Gaming toggle and Steam transaction off transient
  Live media, where no durable BLS next-boot state exists, and made CLI status
  report that boundary without a false mixed-state warning.
- Preserved Fedora's root-only `System.map` files for depmod, repaired NVIDIA
  module-index and first-activation verification, and kept failed akmod or
  incomplete installer-cleanup work retryable instead of sealing false
  success.
- Fixed first-user avatar publication, VPN-app autostart gating, fresh Nautilus
  defaults and Setup layout while retaining user ownership of later desktop
  choices.
- Fixed every GNOME Software RPM-opt-in compose and pre-ship gate to
  authenticate its one active argumentless sudoers command instead of
  rejecting harmless comment wrapping by physical line count.
- Closed libvirt's privileged system-QEMU core-limit bypass with its native
  `max_core` ceiling, and made per-user QEMU sessions start cleanly under the
  existing hard zero limit without overwriting conflicting user configuration.
- Allowed the reviewed Claude/Codex extension transactions to use Codium's
  supported live install command, report partial failures accurately and defer
  activation until the editor is reloaded.
- Restored Chrony transition handling and raised its bounded asynchronous-DNS
  window so NTS sources become usable after real network readiness without
  generalizing one provider-specific timeout.
- Restored DKIM updates, critical audit notifications, WAN-strict disable after
  a latched unit failure and the ISO compose gate that had drifted from its
  helper.
- Reapplied the documented Btrfs scrub rate after Fedora's resume path resets
  it, and supplied Snapper's empty native plugin directory to remove recurring
  successful-operation noise without adding hooks or background work.
- Classified fresh-install journal noise against exact positive postconditions
  and corrected the OpenVPN, firmware, local-AI and post-quantum documentation
  where earlier guidance no longer matched the Fedora 44 image.

### Security

- Revalidated each complete USBGuard device descriptor at the final runtime
  authorization boundary, so a recycled numeric handle during snapshot or
  portable-rule persistence cannot authorize a replacement device.
- Closed a Flatpak escape path through the per-user systemd manager on the
  session bus.
- Closed argument and command-resolution boundaries across privileged udev,
  systemd, package-hook and autostart helpers; public commands retain only
  their documented interfaces.
- Verified third-party release RPMs before trusting extracted repository keys
  and preserved fwupd's root-only local history across on-demand activation.
- Prevented one-time boot arguments such as `enforcing=0` or `nomodeset`
  from silently entering the permanent command line.
- Restored AIDE coverage of symlink targets and file types, and bound
  first-boot and retention health evidence to the exact payload bytes it
  certifies.
- Removed gateway hardware and address values from journals and made
  release-critical provenance, branding, NTS and structural gates fail closed
  when their checks cannot run.

## [v1.4] - 2026-07-26

Architecture, reliability and verification release for the Fedora 44 / GNOME 50
base. It strengthens the network and integrity boundaries, completes the
first-party app suite and removes several fragile or overstated mechanisms
without changing the documented threat-model ceiling.

### Added

- Added **NoID Privacy Tools**, a curated GTK4/libadwaita launcher for every
  supported user-facing command, with safe defaults for multi-action helpers
  and a complete CLI inventory through `noid --help`.
- Added a global and physical-link DNS transport selector to Setup, Network,
  Tools and the CLI. The default is strict authenticated Quad9 DoT;
  opportunistic mode is the explicit VPN/captive-portal choice with DNS/53
  fallback. VPN and private per-link DNS stay provider-compatible.
- Added guided controls for Proton VPN, Mullvad VPN, Fedora Flatpaks,
  laptop-lid behavior, Firefox DRM and checked Snapper rollback. Both VPN
  installers verify the vendor signing-key fingerprint before import.

### Changed

- Reworked the physical-network boundary around transactional gateway pinning,
  topology-aware LAN isolation and verified XDP/TC ingress enforcement.
  Temporary IPv4 peer grants, hotplug handling and WAN-strict VPN endpoints
  reconcile from closed, rollback-capable state; unsupported IPv6 peer grants
  fail before mutation.
- Unified Setup, Update, Network and Tools around one first-party application
  design and accessibility contract, preserving exact argument boundaries for
  every privileged action.
- Made boot state converge through one canonical kernel-command-line, BLS and
  initramfs contract. Update All now distinguishes userspace, kernel and NVIDIA
  work, reports incomplete work explicitly and retains recovery evidence
  instead of relying on timing or a surprise restart.
- Made AIDE evidence fully user-owned. Image creation, first boot, scheduled
  checks and guided updates no longer initialize, update or replace the trusted
  database; baseline changes require a reviewed candidate and exact hash
  confirmation.
- Rebuilt Firefox and Thunderbird profile management around registered,
  path-safe named profiles, atomic writers and explicit consent. Executable
  add-ons stay free of background updates and advance only through the
  user-started update workflow, checked against their official marketplaces.
- Moved GNOME integration back to maintained platform surfaces — systemd,
  D-Bus, dconf and XDG administration instead of service rewrites — and retired
  the local Mutter patch once its replacement reached Fedora.
- Reworked recovery, VPN, DNS, firmware, local-AI, SSH, Thunderbolt, LUKS and
  threat-model documentation so claims describe the implemented boundary and
  its trade-offs rather than universal protection.

### Fixed

- Fixed a locale defect that removed networking on every non-English
  installation. Deployed helpers compared `stat -c %F` against the English
  literal `directory`, but systemd hands each service the installation's
  `LANG`, so the field arrived translated. The physical-LAN topology guard
  fail-closed within milliseconds — before firewalld or nftables — and, because
  NetworkManager hard-requires it, took the whole network with it. A compose
  contract now fails the build when a deployed heredoc helper compares
  `stat -c %F` without exporting the C locale.
- Restored the graphical login on first boot: the Live-authorization cleanup
  could not complete its unconditional NetworkManager reload, and `gdm.service`
  hard-requires that cleanup.
- Closed the first physical-link DNS activation interval. NetworkManager now
  applies a device-matched strict DoT default to Ethernet and Wi-Fi before the
  asynchronous dispatcher replaces DHCP DNS with named Quad9.
- Removed two major installation delays and the fresh-install login stall: the
  Live installer consumes a compose-time size manifest instead of rescanning
  the SquashFS tree, and boot-policy publication no longer repeats a full
  initramfs build on the graphical critical path.
- Fixed reproducible first-window and first-pointer stalls on qualified
  Intel/AMD-primary NVIDIA-offload topologies, preserving explicit
  discrete-GPU offload.
- Fixed intermittent long Flatpak installs caused by failed multiplexed HTTP/2
  object transfers, without changing TLS, signatures or remote trust.
- Made first-boot Live-account cleanup recoverable: possible `/home/liveuser`
  remnants move atomically into root-private quarantine instead of being
  recursively deleted, and unsafe boundaries fail closed before GDM starts.
- Restored a clean boot console by returning `quiet` to the canonical kernel
  command line, while keeping `loglevel=4` for early storage and LUKS
  diagnostics.
- Made the normal graphical Live entry the three-second boot-menu default, with
  Fedora's media-check path explicitly selectable.
- Kept provider-created transient VPN profiles transient when assigning the
  inbound-DROP `noid-vpn` zone, so a disconnect or reboot leaves no stale
  autoconnect tunnel profile behind.
- Kept chrony sources offline until the gateway/XDP readiness event by shadowing
  Fedora's competing dispatchers through the administrator tier, leaving the RPM
  payload pristine.
- Corrected the codec opt-in consent text to disclose that the RPM Fusion and
  Fedora metalinks can select HTTP mirrors; package signatures still protect
  integrity, but transfer privacy is not claimed.
- Corrected the MAC-privacy boundary to name Fedora's actual per-SSID mode and
  the remaining same-SSID and wired-profile linkability.
- Aligned the Firefox 153 policy with current platform contracts: removed
  retired defaults, stopped disabling native desktop QWAC verification, and
  corrected WebRTC, CRLite, AI, Safe Browsing, fingerprinting and DRM guidance.
- Fixed a large set of Live, fresh-install and reboot lifecycle ordering
  defects across first login, USBGuard, GNOME Initial Setup, installer cleanup
  and user services, and restored RPM-native ownership, modes and labels after
  Anaconda's Live-image transfer.

### Security

- Strengthened release provenance with exact source and artifact pins,
  reproducible private staging, signed-package verification, non-persisted CI
  credentials and a write-once candidate/archive handoff.
- Made compose health stamps failure-atomic: modules retire stale success
  before mutation and publish schema- and SELinux-verified replacements only
  after all current checks pass.
- Closed privilege and session-identity gaps across root helpers, sudo policy,
  Polkit, Live sessions, greeter accounts and graphical user services. Helpers
  validate exact callers, arguments, paths and runtime ownership before
  mutation.
- Tightened USBGuard administration, removable-media `noexec`, audit coverage
  and root-owned state publication. Audit-storage degradation stays visible
  without sending the locked-root system to single-user mode.
- Reconciled module-load and unprivileged BPF policy, SSH and password policy,
  shell history, SUID handling and NVIDIA module identity with the effective
  Fedora 44 interfaces.
- Replaced the locally patched security auditor with the byte-identical,
  reviewed public `v3.7.1` payload. The canonical builder fetches its full,
  immutable Git commit URL and independently enforces commit, byte count and
  SHA-256; network-active checks remain explicit opt-ins and local evidence
  collection stays the default.

## [v1.3] - 2026-06-22

Reliability and refinement release on top of v1.2. Core hardening defaults are
unchanged.

### Added

- Added a gateway ARP re-learn action to the Network app for router replacement
  and connected-without-internet recovery.
- Added a static Project & Ecosystem section to Setup and the
  `ecosystem-and-support.md` guide, without timers, popups or background
  traffic.
- Added llama-vscode and Cline to the local-AI editor guidance.

### Changed

- Updated firmware/HSI, Secure Boot and local-AI guidance. v1.4 later corrected
  the remaining aggregate-HSI and Continue-status overstatements.

### Fixed

- Fixed LUKS boot-prompt reliability by adding unlimited passphrase retries to
  the first-boot `rd.luks.options` contract.
- Fixed NVIDIA MOK probing, initramfs handling and the hybrid GTK renderer
  selection.
- Fixed fresh-install repository setup and firstboot sandbox behavior.
- Made update reboot detection non-blocking and the GUI reboot state and run
  summary locale-independent.
- Fixed forensic-retention namespace handling and several verification-gate
  drift issues.

## [v1.2] - 2026-06-14

Targeted reliability release for time sync, updates, NVIDIA, browsers and
security baselines. Core hardening defaults are unchanged.

### Changed

- Expanded and corrected the chrony NTS source set and fixed the restricted
  service's seccomp-level description.
- Refreshed the bundled Linux auditor and Claude extension seed.
- Raised the minimum `xdg-desktop-portal` security baseline and corrected the
  documented kernel-CVE status.

### Fixed

- Made Flatpak parsing, restart checks and update summary accounting
  locale-robust.
- Prevented the NVIDIA kernel-install hook from deadlocking against Update
  All's active RPM transaction.
- Corrected Snapper log rotation so the intended age cap also bounds the active
  log.
- Completed Firefox's amnesic shutdown migration for the Playground profile.

## [v1.1] - 2026-06-08

Maintenance release focused on hardware enablement, VPN resilience, privacy
controls and RPM-upgrade durability. Core hardening defaults are unchanged.

### Added

- Extended the Location switch across GNOME, GeoClue network sources and the
  greeter, with live synchronization between supported front ends.
- Added live synchronization for Setup's Camera, Microphone, Location and
  Bluetooth switches.
- Added an automatic WireGuard keepalive compatibility dispatcher. v1.4
  removed it because runtime state could not distinguish an omitted value from
  an explicit zero.

### Changed

- Migrated package-update reconciliation from the obsolete DNF4 hook to
  `libdnf5-plugin-actions`.
- Updated the pinned uBlock Origin and DKIM Verifier payloads.

### Fixed

- Prevented failed NVIDIA akmod builds from replacing a known-good initramfs
  and rebuilt images after driver-only updates.
- Restored Firefox launcher, GNOME service-suppression and branding state after
  relevant RPM upgrades.
- Fixed first-boot AIDE reliability and protected the DNS-health log.

## [v1.0] - 2026-06-04

First stable release, consolidating the modular hardening stack and its initial
hardware, privacy, recovery and usability workflows.

### Added

- Added the modular Fedora/GNOME image architecture with fail-closed
  compose-time verification for release-critical artifacts.
- Added bootloader and opt-in GRUB authorization, kernel-command-line, sysctl
  and module-load hardening with CPU-vendor-specific first-boot handling.
- Added firewalld DROP defaults, LAN isolation, gateway ARP pinning,
  provider-neutral WAN-strict support, MAC randomization and DHCP route
  hardening.
- Added service minimization, silent-machine defaults, GNOME privacy policy and
  the initial dual-Flathub trust model.
- Added SSH client hardening and server opt-in guidance, PAM/login policy,
  USBGuard whitelist-only operation and device-recovery guidance.
- Added SELinux enforcing, immutable auditd, AIDE integration and bounded
  retention for selected system evidence.
- Added Snapper recovery, LUKS and mount hardening, explicit firmware updates
  and guided system-update orchestration.
- Added hardened Firefox, Firefox Playground and Thunderbird profiles with
  pinned uBlock Origin and DKIM Verifier payloads.
- Added NoID Privacy branding, the curated package set, the Setup, Update and
  Network apps, bundled audit tooling and tiered user documentation.
- Added signed NVIDIA akmod support for fresh Secure Boot installations and a
  conservative, reversible NVIDIA suspend policy.
- Added a native systemd link policy to avoid Energy-Efficient-Ethernet drops
  on physical Ethernet.
- Added persistent microphone privacy enforcement across first boot and later
  sessions.
- Added a manual Live-session path for the Setup app while keeping automatic
  Live startup suppressed.
