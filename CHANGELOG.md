# Changelog

All notable changes to NoID Privacy Workstation are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Release headings use the project convention `vMAJOR.MINOR[.PATCH]`.

This file records release-level, user-visible highlights. Detailed
implementation history, validation evidence and individual pin changes remain
available in the Git history, module sources and project documentation.

## [v1.9] - 2026-10-03

Correctness and security release for the Fedora 44 / GNOME 50 base. It fixes
guards that failed open, network and update paths that reported success they
had not reached, and apps that promised outcomes they did not deliver. The
image ships Fedora's signed xdg-dbus-proxy security update. The documented
silent-machine, LAN-isolation and threat-model boundaries are unchanged.

### Added

- Native Intel NPU firmware, Orca system-information support and Unicode
  matching for Typing Booster.
- Native camera, Intel video, AMD monitoring, storage and container backends;
  translated Qt dialogs and manual pages; and RPM transaction audit/inhibit
  plugins. Camera privacy defaults and administrator authorization remain in
  place; TuneD remains the CPU-policy owner. Optional LibreOffice help is not
  preinstalled.
- `noid-firefox-relax-fpp --site <domain>` lifts Firefox's canvas readback
  block for one site, for in-browser image cropping and editors that otherwise
  produce striped or noisy uploads, such as YouTube Studio banners. The
  exception covers the registrable domain and its subdomains, keeps the block
  for frames from other sites and changes no other fingerprinting protection;
  the listed site can then read a canvas fingerprint. Subdomains, public
  suffixes and names Firefox would ignore are refused. `--sites` lists the
  exceptions, also in the Tools app, and `--site-restore` removes one.
- Thunderbird profiles take durable owner overrides from `user-overrides.js` in
  the profile directory, applied after the NoID Privacy values on every
  hardening and Update All run. Values appended to `user.js` itself, as the
  guides used to suggest, were replaced by the next Update All.

### Changed

- Clarify shared agent instructions for untrusted content, existing user
  authorization, complete verification inputs, weak dependencies and client
  instruction discovery. Production AIDE evidence remains user-owned;
  expressly authorized disposable-guest tests have a separate, limited scope.
- Complete installer package cleanup before the first login, avoiding an
  SELinux-blocked RPM user-service bridge while preserving native scriptlets
  and the service sandbox. Later boots validate the completion marker.
- Bound failed NTS key-exchange retry backoff to 256 seconds, preserving
  authenticated time recovery after network outages without a daemon restart.
- ISO builds reject newly unmet weak dependencies until their native consumer
  and an explicit package-policy exception have been reviewed.
- Bound the unchanged Linux audit tool v3.7.2 at commit `c14a930` to its
  current public source, with matching image and support-media references.
- Simplified the public test and release documentation while retaining the
  runnable test reference and download-verification instructions.
- Performance troubleshooting distinguishes Firefox's shutdown web-cache
  clearing from uBlock Origin's deferred filter-engine cache, and separates
  desktop readiness from service timings and manual boot input waits.
- Added the libdnf5 systemd-inhibit plugin, so shutdown and sleep wait for a
  running package transaction; `wl-clipboard`, which KeePassXC needs to clear
  copied passwords on Wayland; KeePassXC's Adwaita window decorations;
  PipeWire's JACK library in place of the standalone JACK server; and
  `adwaita-mono-fonts`, GNOME 50's monospace default. None of them adds a
  service or other activation path. Hosts installed from v1.8 reach the same
  package state with the commands in `known-failures.md`.
- Removed Rygel and the two PackageKit session helpers; nothing in the image
  requires them. Neither PackageKit's session name, its codec and font install
  requests nor the quit helper can start GNOME Software with its default
  plugins any more.
- The Network app reports the mode actually in effect after every WAN action,
  offers a confirmed re-enable for a disabled gateway pin, keeps the selected
  DNS mode readable, asks before a reset imposes strict DNS-over-TLS and shows
  deadlines in local time.
- The Tools app runs the LAN XDP status and a new complete integrity scan as
  root and offers an interactive inverse for "Block WAN".
- The Update app keeps its header readable in every state, shows skipped steps
  as skipped, attributes pre-DNF work to the DNF step and reports a concurrent
  run instead of "Finished with errors". Update All runs opt-in agent
  self-updaters without the cached administrator credential, skips firmware on
  Live media, removes the generated VSCodium launchers once codium is
  uninstalled and re-verifies NVIDIA modules for every installed kernel after a
  driver change.
- The Snapper rollback wrapper keeps a bootable kernel whose modules exist in
  the restored snapshot, or refuses and names the kernel to install.
- Setup creates the first Firefox profile when none exists, and a new profile
  no longer receives about 100 language add-ons.
- The image ships the COPYING and GPL-2.0 texts under
  `/usr/share/licenses/noid-privacy` and the complete source and build script
  of the GPL-2.0-only XDP object under
  `/usr/share/noid-privacy/source/noid-lan-xdp/`. The trademark notice follows
  the GNOME Foundation's own statement and adds a non-affiliation line.
- Consent-gated agent seeds: Claude Code CLI and VSIX 2.1.296 and Codex CLI
  0.162.1, each verified against the vendor's signed manifest or published
  checksum. The documentation-only local-AI evaluation pins move to Ollama
  v0.35.1, which includes the fix for CVE-2026-103663, llama.cpp b11429 (the
  build of the stable v0.6.0 release, which includes the fix for
  CVE-2026-107183) and llama-vscode 0.0.68.
- Build and test tooling rejects failed, partial or interrupted runs instead of
  reporting success, the full audit suite also runs on Live media, and the
  offline audit support medium carries the compiler and headers its complete
  BPF test suite needs. Details are in the Git history.

### Fixed

- Update All counts the same ten main steps in the terminal and the window.
  A finished run with a skipped check shows a full progress bar and names the
  skipped step instead of stopping at "9 of 10 complete"; a run with only
  non-blocking warnings no longer claims that updates were applied.
- The NVIDIA driver opt-in no longer leaves an `akmods.rpmnew` file that Update
  All reported as a configuration warning on every run. Installations of the
  first v1.9 image can remove it as described in
  [known failure modes](docs/known-failures.md).
- Setup records the pinned Claude Code CLI as a native installation, so the
  first Update All no longer asks to run `claude install`.
- Retry a transient missing-setting response when reading the microphone
  policy, also in the Setup app, whose microphone switch could briefly show
  the microphone as blocked and log a warning. The bounded retry requires an
  observed value; persistent absence, command errors and invalid output still
  report a degraded state.
- Revalidate the remaining physical gateway when the pinned network adapter
  disconnects, so time synchronisation and VPN endpoint resolution recover
  after undocking. Existing gateway verification and LAN filters remain in force.
- Release builds use Fedora's current repository metadata even when nearby
  mirrors still offer an older permitted snapshot, preventing already
  available security updates from being omitted from a new image.
- `noid-firefox-relax-fpp` relaxes fingerprinting protection on Firefox 156, to
  exactly the baseline stock Firefox applies in Standard mode and never below
  it. The block that v1.5 to v1.8 wrote never took effect; it is removed
  without changing a profile's protection.
- New installations and the Live session register Thunderbird for `mailto:`
  links and Firefox as a web handler again.
- AIDE: Update All and package changes no longer make it report NoID Privacy's
  own unchanged files on every run, so an update without package changes ends
  with "AIDE check found no differences". After daily checks are enabled, the
  toggle, the baseline step and the documentation name the two paths the first
  check reports, and the opt-in desktop popup is delivered; it could never
  reach the desktop session before.
- The Live system starts about 14 seconds faster, because it no longer rebuilds
  caches on every boot that the image already contains, and it no longer offers
  "Firefox (Playground)", which there only opened Firefox's profile chooser.
- DNS no longer stays degraded after login when a system-wide VPN connects
  before it. Encryption and DNSSEC for that VPN's DNS servers could stay off
  for hours, and signed domains failed to resolve.
- Boot-menu titles of a new installation are correct after the first reboot
  instead of the second.
- Installed systems repair what Anaconda's copy of the Live image loses:
  `/boot/grub2` returns to 0700 root:root, selinux-policy's
  `/etc/sysconfig/selinux` alias exists again, and about 600 package files
  regain their timestamps, so `rpm -Va` and `noid-integrity-check` no longer
  report them.
- QEMU standard-VGA guests keep the graphical boot splash: the image no longer
  carries a build-only denylist for the `bochs` display driver.
- Low-disk alerts lead with the problem and the free space left on the system
  disk; the consequence for the security audit log follows.
- Setup, Update, Tools and Network show the NoID Privacy mark without its
  unreadable label in the header, and the small app icon sizes use the
  unlabeled mark.
- A Fedora firefox-langpacks build without language packs (156.0.1-1) no longer
  stops the Firefox hardening repair or fails the DNF step. It is a warning
  while the previously installed language packs still support the installed
  Firefox, and an error once they no longer do.
- The Live system's `machine-id` carries its correct SELinux label, which
  removes a systemd AVC, and libvirt's `virtqemud` may read, but not write, the
  network sysctls for its IPv6 state query, which removes seven AVCs after
  reboot.
- Thunderbird starts when its profile is missing or the offline DKIM
  compatibility preparation fails, and DKIM Verifier is enabled from the first
  managed launch instead of only after Update All.
- WAN-strict: gateway-pin changes are journalled, so an interrupted change no
  longer leaves NetworkManager unable to start; `recover` also restores the
  kernel pin, `reset` repairs a damaged pin and a failed recovery can be
  retried without losing its evidence. `arm-empty` keeps the endpoint of a
  running tunnel and still arms when endpoint discovery fails, `resume` no
  longer claims strict mode on a never-armed host, and a profile that lists its
  gateway twice no longer breaks reconciliation.
- A failed location apply no longer leaves GeoClue sources enabled; systemd
  retries it.
- The emergency USBGuard fallback admits multi-interface receivers and devices
  behind hubs, so it no longer locks users out at the login screen, and USB
  admission is in place before any login.
- Host-identity drift after the first boot, such as a regenerated NVMe host
  NQN, no longer blocks every non-root login; it is reported instead.
- NVIDIA verification tolerates RPM Fusion's diverging akmod and CUDA release
  numbers, queued module rebuilds survive a busy boot, and the rebuilds for
  several kernels run one after another, so shutdown waits until all of them
  are done.
- Helpers: the DisplayLink helper runs again, `noid-dns-mode reset` checks the
  strict certificate-name precondition, the Intel ME helper's modprobe conflict
  check finds real conflicts, including in symlinked configuration files, and
  `noid-nvidia-install.sh` and `noid-luks-backup.sh` keep their real exit
  status without a terminal. Seeded Firefox profiles create their
  subdirectories owner-only.
- After a USB or SD mount, user sessions that start later still track mounts.
- `dnf` queries by normal users work again after a package transaction from a
  root shell (`sudo -i`, `su -`).
- After the documented Firefox revert, Update All skips its Firefox step
  instead of reporting integrity errors, and Setup and Tools mark the removed
  helpers. Without the revert marker a missing Firefox integration remains an
  error.
- The kernel command line no longer carries `amd_iommu=on` and `srbds=on`,
  which had no effect: the kernel has no `amd_iommu=on` option and acts on
  `srbds=` only for `off`. AMD-Vi and the SRBDS mitigation stay on by default.
- The 30-day log retention now holds in practice. The journal and rotated log
  archives are pruned by the age of their oldest record, also after power-off
  gaps, and Fedora package logs that kept data far longer follow the same
  policy: akmods, firewalld, Plymouth's boot.log, psacct, glusterfs,
  wpa_supplicant, chrony, iscsiuio, PPP and DNF 4's hawkey.log. The retention
  guide names the DNF transaction history, current libvirt leases and colord's
  device mapping as deliberately kept system state.
- The Codex installer note names the shipped defaults: no approval prompts and
  `danger-full-access`.
- Update All's add-on checks for Firefox and Thunderbird profiles continue an
  interrupted add-on download on each retry instead of restarting it, so a
  download server that closes the connection mid-transfer no longer exhausts
  every attempt. A failed request is reported in one line naming the failure
  instead of raw TLS error output. Size and SHA-256 still bind every
  downloaded add-on.
- `noid-integrity-check` no longer reports a red "malformed output" failure for
  its RPM section on systems in German and most other shipped languages; RPM
  verification runs in the C locale, so changed package files appear as the
  usual drift notice.
- Firefox Sync no longer imports or uploads the list of languages Firefox
  requests from websites. Signing in on a new installation could import an
  English list stored in the account, so websites received English despite a
  localized system; the list now follows the system language. A list chosen in
  Firefox's settings is kept.
- After each Wi-Fi lease renewal or reapply, NetworkManager no longer waits
  several seconds for the LAN topology refresh and gateway revalidation before
  it handles the next connection event, such as a VPN starting at login. Both
  now run as separate short-lived services with unchanged checks and outcomes.
- A suspend of more than ten minutes no longer ends with a failed LAN topology
  refresh in the log. While the system prepares to sleep, NoID Privacy no
  longer starts LAN topology, remaining-gateway or VPN endpoint teardown work
  and only queues the pause of time synchronisation, so a network step that
  the suspend interrupts leaves nothing half done. The reconnect after waking
  runs the complete checks again before the link is used, and time
  synchronisation stays paused until the gateway is verified.
- The Live medium's text-console login no longer suggests
  `systemctl enable --now cockpit.socket`. Cockpit arrives only as a dependency
  of the installer and stays masked, so the hint named a command that could not
  work.
- After the first login, the installed system now really marks its first boot
  as successful before the planned restart. The step's sandbox options had
  turned off Fedora's boot-flag helper, which then did nothing while the step
  reported success; only Fedora's own timer set the flag two minutes later, so
  a quicker restart could show the GRUB menu. The step now fails visibly if the
  helper does not act.
- The documentation was reviewed line by line against the code. Corrections
  include the AMD `ccp` driver, which is built into the Fedora 44 kernel, the
  microphone opt-in `noid-toggle-microphone`, the update channels of DKIM
  Verifier and uBlock Origin, Thunderbird menu paths, GRUB keys, retention
  periods, the WAN-strict trust boundary, the security-reporting path and the
  ntfs-3g fallback on kernels without ntfs3. Installed configuration and
  documentation no longer contain development notes. The known failure modes
  now explain why wired and Wi-Fi connections are down at the login screen, the
  journal messages on the first boot after a Snapper root rollback, the
  messages of a normal shutdown, and that network and VPN profiles saved in the
  Live session, including a WireGuard private key, move into the installation.

### Security

- Retain libseccomp in Live and installed boot images, so systemd's early-boot
  syscall sandbox remains available. Release checks verify the library in the
  final ISO and the installed initramfs.
- Include firewalld's native capability-reduction binding, so the daemon
  drops to its three required Linux capabilities. Existing installations need
  the targeted package steps in
  [known failure modes](docs/known-failures.md#missing-native-workstation-integrations);
  an ordinary package upgrade does not install the missing binding.
- Include the defensive XML parser used by optional WS-Discovery, preventing
  a fallback to the standard parser. Discovery remains disabled by default.
- Wait for GNOME's notification service before displaying a degraded LAN
  protection warning at login; suppress the warning if protection recovers
  during that bounded wait.
- The journal no longer keeps a second copy of every audit record. That copy
  exposed audit records, such as full `sudo` command lines, to every `wheel`
  member without authentication. The audit trail now lives only in the
  root-only `/var/log/audit`.
- A failed network topology refresh no longer leaves a new physical link active
  without XDP, the L2 guard or WAN-strict coverage; the link is taken down.
  Renamed adapters and interface names that contain a dash are covered, the
  topology guard no longer restarts NetworkManager on every firewalld restart,
  and the LAN state requires the permanent and runtime block-lan-out policies
  to agree.
- Audited `fsmount`, `move_mount` and `mount_setattr`, because Fedora 44's
  util-linux never calls `mount(2)`. The audit notification plugin is verified
  before auditd can start it.
- The SSH opt-in guide's preconditions no longer fail open under `&&` chains,
  and the guide requires the SSH user to be in wheel.
- The sudoers drop-in no longer re-adds PS1 and PS2 to env_keep.
- Turned off Thunderbird's Microsoft AutoDiscover channel, which sent the full
  e-mail address (once over plain HTTP) and could send the typed password to
  the domain's web host. Claude Code's official plugin-marketplace auto-install
  is off in the new-user template.
- Firefox no longer sends the IDs of all installed add-ons and its UI language
  to addons.mozilla.org on first start and daily after: the add-on metadata
  cache is off, as in Thunderbird. about:addons no longer shows AMO
  descriptions, ratings and screenshots; the add-on blocklist and add-on
  updates do not depend on the cache.
- Requires bubblewrap 0.12.0 or newer (CVE-2026-87766): during sandbox setup, a
  symlink through /oldroot let an app create files outside its sandbox. Fedora
  44's release repository still carries 0.11.0, so the compose and Update All
  enforce the floor.
- Requires udisks2 2.11.2 or newer, which fixes the local privilege escalation
  CVE-2026-7867.
- Ships Fedora's signed xdg-dbus-proxy 0.1.9, which fixes a D-Bus
  message-filtering bypass (CVE-2026-94422); no private backport is used.

## [v1.8] - 2026-09-22

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
- Integrated the published Linux audit tool v3.7.2 at commit `8fe9efe`, with
  matching source, byte-count and SHA-256 pins for the image and support medium.
- Refreshed the consent-gated Claude Code CLI/VSIX seeds to 2.1.278, Codex CLI
  to 0.155.1 and Codex VSCodium to 26.5908.31748; advanced the signed uBlock
  Origin seed to 1.75.0 and kept the reviewed Just Perfection seed at v37 and
  the DKIM Verifier seed at 6.3.0, both re-verified byte-exact against their
  publishers.
- Refreshed the documentation-only Ollama, llama.cpp and llama-vscode
  evaluation pins and the Ornith 1.5 reference records, and advanced the
  reviewed Fedora-signed Lorax build stack from 44.6 to 44.7.
- Rebased the reviewed Thunderbird hardening base to the HorlogeSkynet v140.3
  snapshot; both preferences it changed were already covered, one by the shipped
  post-base section and one by Thunderbird 153's own library loader.
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

- Reconciled the fresh-install GDM log directory to its canonical ownership,
  mode and SELinux label before the first graphical login.
- Described the one-time pending reboot with a neutral reboot icon as a
  verified boot-policy or update activation instead of misidentifying every
  first boot as an update.
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
- Kept seeded extensions working across browser upgrades. The unchanged
  DKIM Verifier 6.3.0 archive declares Thunderbird compatibility only up to
  153, while the authenticated add-on channel authorizes those exact bytes for
  later releases; on Thunderbird 155, reassertion and the updater both waited
  for a compatible local copy. That digest-bound record is now applied through
  Thunderbird's native offline update path with global compatibility checks
  left enabled. Recovery never silently downgrades a newer payload, preserves
  user-disabled state and update preferences, and follows the same order for
  uBlock Origin and other profile-owned extensions.
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
- Excluded the two fingerprinting-protection language targets in Firefox, so its
  "request English versions" machinery can no longer rewrite a profile's
  accept-language list to English behind the suppressed prompt. Web content again
  follows the system locale; an already affected profile is repaired by resetting
  `intl.accept_languages` once.

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
- Kept address-bar Firefox Suggest off on the profile's user branch through the
  FF146+ master switch, so Firefox 156's regional activation of sponsored and
  Wikipedia suggestions cannot reach a fresh profile through Mozilla's
  preference migration.

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
  0.149.0 and Codex VSCodium 26.5818.41509; pinned the Linux auditor at v3.7.2
  and the documentation-only Ollama, llama.cpp and llama-vscode evaluations at
  0.32.15, b10593 and 0.0.63 with exact reviewed sizes and SHA-256 values.
- Consolidated updater, login, status and GUI reboot presentation on the same
  canonical kernel/NVIDIA reader and retained fail-closed handling for
  malformed state.
- Tightened helper failure propagation and compose-log classification so
  failed cleanups, generated candidates and known benign diagnostics cannot be
  mistaken for successful or unexplained release evidence.

### Fixed

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
