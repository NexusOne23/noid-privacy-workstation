# NoID Privacy automatic-execution inventory

## Scope and method

This is the canonical review of work that NoID Privacy can start without a
fresh command from the logged-in user. It covers project-owned system and user
units, timers, paths, XDG autostarts, NetworkManager dispatchers, udev rules,
DNF5 actions, system and environment generators, D-Bus activation policy,
WirePlumber policy, audit dispatch, tmpfiles and login/session environment
hooks. It also names the Fedora services and timers that the image explicitly
enables, retains or suppresses.

The source tree is authoritative for the next image. Compare it with an
installed system through `systemctl list-unit-files`, `systemctl list-units`,
`systemctl list-timers`, the user manager, the process inventory and the
relevant configuration directories (see "Live inspection" below). Host-only
additions, such as units created by an explicitly run NVIDIA installer, are
not image defaults.

An enabled unit is not necessarily a process. `Type=oneshot` units in
`active (exited)` state have no worker left, `.path` and `.timer` units are PID
1 metadata, and dispatchers/rules run only for their event. The only
continuously running project-owned service in an ordinary eligible graphical
session is `noid-location-sync.service`; its shell watcher and local
`gsettings monitor` child implement that one service. Maintained policy engines
such as firewalld, auditd, restricted chrony and USBGuard are listed separately
below.

## Decision summary

- Keep every currently shipped automatic surface. Each has a bounded policy,
  recovery, retention or first-run owner; no obsolete polling daemon remains.
- Keep the five forensic-retention timers separate. Their different writable
  paths and service sandboxes isolate failures and avoid giving one large
  cleanup process union access to every retained evidence source.
- Keep update installation user-initiated. The weekly user timer only displays
  a local notification.
- Keep AIDE automatic checks disabled until the user reviews and accepts a
  baseline and explicitly enables the timer.
- Keep WAN-strict event reconciliation and five-minute lease expiry only while
  WAN-strict is enabled. They are part of the fail-closed endpoint contract,
  not general network monitoring.
- Keep NetworkManager history pruning, with its documented opt-out marker,
  because generated state has no maintained live-clear API. Do not restart
  networking daily merely to make the retention boundary exact.
- Keep the location watcher. GNOME can change its location setting outside the
  Setup app; the local watcher is the narrow bridge that keeps GeoClue's root
  configuration aligned. The watcher opens no network connection itself. When
  the user explicitly enables location, it removes the source-blocking override
  and restarts an already active GeoClue service, which may then use its own
  configured location sources.
- Do not expose internal event workers as if each were a supported user CLI.
  NoID Privacy Tools contains safe fixed actions; `noid-help commands` deliberately
  remains the complete raw executable inventory, including internal hooks.

## Network activity

The image adds no project telemetry or package/firmware polling. Automatic
image-controlled network or link-control activity is limited to:

- DHCP and standard ARP needed for IPv4 addressing, conflict detection and the
  gateway;
- chrony NTS/NTP against the configured sources;
- when WAN-strict is enabled, event-triggered resolution of hostname-based VPN
  endpoints and bounded candidate reconciliation on boot, profile changes and
  relevant NetworkManager events.

The WAN-strict five-minute expiry job removes expired local records and
re-derives current endpoint tuples from loaded profiles and running WireGuard
tunnels, issuing a bounded `retained` lease for an unmanaged tunnel's
completed handshake; it never resolves names or refreshes DNS candidates.
Retention timers, the update reminder, the location watcher itself, XDG health
checks, DNF actions, udev rules and the system/user first-run jobs do not open
Internet connections. An explicitly enabled location setting permits
GeoClue's own configured sources again; user applications, VPN clients, Fedora
services, firmware and explicit update/diagnostic commands remain separate
traffic owners.

## System-manager timers

| Timer | Default/trigger | Decision |
| --- | --- | --- |
| `aide-check.timer` / `aide-check.service` | disabled until user baseline acceptance | Keep: check-only integrity evidence; never creates or replaces a baseline. |
| `noid-audit-prune.timer` / `noid-audit-prune.service` | daily, persistent | Keep: exact rotated-audit 30-day boundary. |
| `noid-auditd-rotate.timer` / `noid-auditd-rotate.service` | daily, persistent | Keep: native auditd rotation before age pruning. |
| `noid-btrfs-scrub.timer` / `noid-btrfs-scrub.service` | monthly | Keep: native local checksum validation, no network. |
| `noid-install-logs-prune.timer` / `noid-install-logs-prune.service` | daily, persistent | Keep: exact install-log and Kickstart-artifact boundary. |
| `noid-misc-logs-prune.timer` / `noid-misc-logs-prune.service` | daily, persistent | Keep: bounded AIDE/log/accounting/closed-VM evidence and 30-day journal archives with live-writer deferrals. |
| `noid-nm-privacy-prune.timer` / `noid-nm-privacy-prune.service` | daily, persistent | Keep: removes only generated NM history at safe lifecycle boundaries; `/etc/noid-privacy/disable-nm-history-prune` is the opt-out. |
| `noid-snapper-prune.timer` / `noid-snapper-prune.service` | daily, persistent | Keep: age policy; complements rather than duplicates Snapper's native number cleanup. |
| `noid-wan-strict-endpoint-expiry.timer` / `noid-wan-strict-endpoint-expiry.service` | every five minutes while WAN-strict is enabled | Keep: expires bounded authenticated/retained endpoint leases and re-pins running unmanaged WireGuard endpoints without resolving names. |
| `noid-dracut-hostonly-firstboot.timer` / `noid-dracut-hostonly-firstboot.service` | once after each installed boot; no recurring next elapse | Keep: resumes/converges a transactional initramfs request off the login path. `active (running)` here is timer state, not a worker process. |
| `noid-nm-scope-physical-profiles.timer` / `noid-nm-scope-physical-profiles.service` | two-minute retry only until the account-completion flag exists | Keep: closes the initial GNOME-created profile ownership gap, then its condition suppresses all later runs. |
| `noid-lan-expiry-reconcile.timer` / `noid-lan-expiry-reconcile.service` | disabled normally; generated for a temporary LAN exception | Keep: deadline-driven fail-closed revocation, not polling. |

Fedora's `fstrim.timer`, `logrotate.timer`, `systemd-tmpfiles-clean.timer` and
Snapper's `snapper-cleanup.timer` / `snapper-cleanup.service` remain maintained
vendor mechanisms. Module 08 also deliberately keeps Fedora's weekly
`raid-check.timer`: its service exits without work unless mdraid arrays exist,
and masking it would drop corruption detection for RAID deployments. The image
masks automatic `dnf-makecache.timer`, `dnf5-makecache.timer`,
`fwupd-refresh.timer` and `plocate-updatedb.timer`.

## System-manager path activation

| Path and paired service | Event | Decision |
| --- | --- | --- |
| `noid-audit-event-notify.path` / `noid-audit-event-notify.service` | non-empty opt-in audit-notification spool | Keep: dormant while the audit plugin is off; no worker or network while empty. |
| `noid-audit-storage-notify.path` / `noid-audit-storage-notify.service` | audit-storage degradation marker | Keep: local high-signal failure notification. |
| `noid-identity-bls-refresh.path` / `noid-identity-bls-refresh.service` | durable boot-loader identity request | Keep: transactional recovery after explicit package/identity work. |
| `noid-usbguard-add-user.path` / `noid-usbguard-add-user.service` | `/etc/passwd` changes | Keep: grants only the named USBGuard IPC policy to newly created eligible users. |
| `noid-user-avatar-backfill.path` / `noid-user-avatar-backfill.service` | `/etc/passwd` changes | Keep: sentinel-idempotent local avatar metadata for new human users. |
| `noid-wan-strict-scan-profiles.path` / `noid-wan-strict-scan-profiles.service` | system NM profile changes | Keep only with WAN-strict: reconciles exact supported endpoint schemas. |
| `noid-liveinst-webui-lifecycle.path` / `noid-liveinst-webui-lifecycle.service` | Live installer lifecycle record | Keep: `rd.live.image` condition makes it inert on installed systems. |

## Boot, first-run and recovery services

All names below are `oneshot`, condition-gated or event-triggered unless stated
otherwise. `RemainAfterExit=yes` records a completed policy state; it is not a
resident daemon.

| Boundary | Units | Decision |
| --- | --- | --- |
| Installation retirement | `noid-anaconda-cleanup.service`, `noid-anaconda-maintenance.service` | Keep: remove Live authorization and perform cache-only package hygiene before the first login; later boots validate completion markers. |
| Network bootstrap | `noid-arp-hardening-firstboot.service`, `noid-arp-state-guard.service`, `noid-firewalld-zone-enforce.service`, `noid-lan-topology-guard.service`, `noid-lan-topology-hotplug@.service`, `noid-lan-topology-event@.service`, `noid-arp-revalidate@.service`, `noid-wan-ipv6-disable-firstboot.service`, `noid-wan-strict.service`, `noid-wan-strict-status-publish.service`, `noid-wan-strict-tunnel-scan.service` | Keep: load-bearing fail-closed link, topology and tunnel policy. The status publisher changes no policy; it restores the verified reboot-volatile GUI/CLI contract even when explicit opt-out keeps the main WAN-strict service disabled. |
| Network readiness | `noid-chrony-network-offline.service`, `noid-chrony-network-online.service` | Keep: event consumers prevent NTS from racing gateway/XDP convergence. |
| Temporary LAN expiry | `noid-lan-expiry-reconcile.service`, `noid-lan-expiry-failure.service` | Keep: reconcile at boot/deadline; stop networking if revocation cannot be proved. |
| Kernel/platform | `noid-firstboot-cmdline.service`, `noid-cpu-vendor-detect-firstboot.service`, `noid-mei-kt-enforce.service`, `noid-fss-keys-firstboot.service` | Keep: conditional local boot/platform convergence. |
| Storage/recovery | `noid-dracut-hostonly-firstboot.service`, `noid-mount-hardening.service`, `noid-snapper-init.service`, `noid-live-payload-acl-restore.service` | Keep: transactional boot/storage state. The early ACL restore reasserts the exact two-path contract lost at the SquashFS transport boundary. |
| USBGuard | `noid-usbguard-firstboot.service`, `noid-usbguard-live-init.service`, `noid-usbguard-remove-gnome-wildcard.service` | Keep: installed and Live modes are condition-separated; broad wildcard removal is verified. |
| Live-only/local identity | `noid-live-mount-hardening.service`, `noid-skel-avatar-backfill.service`, `noid-user-avatar-backfill.service` | Keep: Live conditions or sentinel-idempotent installed behavior. |
| Per-machine identity | `noid-host-identity.service` | Keep: on every boot, before login, creates a missing BRLTTY API key or NVMe host ID/NQN (or resumes an incomplete first publication) and never rotates a validated identity; after the first installed transition it only reports a changed identity in the journal and never blocks login; local only, no network. |
| User-selected codec setup | `noid-firstboot-setup.service` | Keep installed but disabled: runs only when explicitly started by `noid-complete-setup.sh`. |
| User-selected audit alerts | `audit-notify.service` | Keep installed but disabled: the oneshot controller enables the local audit plugin only after explicit opt-in; `RemainAfterExit` records state and leaves no worker. |
| Audit-alert opt-in integrity | `noid-audit-notify-boot-check.service` | Keep: runs before auditd on every boot; an inactive or verified plugin configuration is left untouched, and a persisted opt-in whose configuration or plugin executable fails the controller's verification is reset to `active = no`; local only, no network, never blocks auditd. |

The explicitly invoked NVIDIA workflow can create
`noid-nvidia-initramfs-resume.service`,
`noid-nvidia-postboot-verify.service`,
`noid-nvidia-reboot-guard.service` and transient
`noid-nvidia-initramfs-<token>.service` jobs. These are not default-image
background work. They exist only to finish, verify or inhibit shutdown around
an already requested signed-module/initramfs transaction.

WAN-strict can also create transient `noid-wan-strict-autoresume.timer` and
`noid-wan-strict-autoresume.service` units after an explicit pause, plus a
short-lived `noid-wan-strict-endpoint-pin-retry-<digest>.service` when its
shared transaction lock is busy. Both are bounded recovery, not periodic
polling.

## User-manager activation

| Unit | Activation | Decision |
| --- | --- | --- |
| `noid-location-sync.service` | enabled for eligible wheel graphical sessions; continuously monitors one local GSettings key | Keep: the sole long-lived NoID Privacy service; its watcher opens no network connection, while an explicit enabled state permits GeoClue's own sources. A failed reconciliation restarts it; five failed starts within ten minutes leave it failed. |
| `noid-agent-policy-adapters.service` | eligible-user session one-shot | Keep: idempotently publishes adapters to the canonical agent policy without network access. |
| `noid-vscodium-repo-key-seed.service` | eligible-user session one-shot | Keep: local metadata trust seed; restricted to `AF_UNIX`. |
| `noid-gsk-session-environment.service` | graphical-session one-shot plus clear on stop | Keep: applies the selected GTK renderer environment and leaves no worker. |
| `noid-gnome-shell-privacy-cleanup.service` | GNOME session shutdown one-shot | Keep: clears exact session-owned privacy state at the native lifecycle boundary. |
| `noid-update-reminder.timer` / `noid-update-reminder.service` | weekly, persistent user timer | Keep: local notification only; never launches an update or network request. |
| `noid-user-firstrun.service` | every eligible graphical login (static `graphical-session.target.wants` link); completed tasks are skipped by their markers | Keep: creates bounded per-user desktop and libvirt-session state, enables the update-reminder timer and starts the static USBGuard notifier without network access; after completion it only re-validates its markers and exits. |
| `noid-usbguard-login-catchup.service` | once per eligible local graphical session (static `graphical-session.target.wants` link) | Keep: reports USB devices that USBGuard blocked before the graphical login; local IPC only, restricted to `AF_UNIX`. |
| `noid-hostonly-boot-success.path` / `noid-hostonly-boot-success.service` | statically pulled in by `noid-user-firstrun.service`; condition-gated on a pending host-only trial request in `/run/noid-privacy` | Keep: commits success evidence after a real eligible session. |
| `noid-blocked-session-service.service` | masked fixture unit | Keep masked: regression/evidence surface, never executable. |

The Fedora-owned `usbguard-notifier.service` is deliberately linked into every
graphical session by Module 14's static `graphical-session.target.wants` link
(the bounded first-run transaction only verifies that link and starts the
notifier in the first session) and then stays running as the local desktop
notification client. It waits on USBGuard's local IPC; it
is not a project daemon and does not discover devices over the network.

The location watcher crosses privilege through only
`/etc/sudoers.d/49-noid-location-apply`, which authorizes the exact
`noid-location-apply true|false` calls for eligible wheel users. It never
prompts or grants a general shell. Any failed reconciliation, including one
inside the monitor loop, terminates the watcher so systemd records the
failure and restarts it; a persistent failure stops after five starts within
ten minutes instead of looping.

## XDG session autostarts

Each entry performs a bounded check or idempotent first-run task and exits:

- `noid-firefox-playground-init.desktop` — local Playground profile seed;
- `noid-firefox-setup.desktop` — local Firefox profile convergence;
- `noid-lan-xdp-health.desktop` — notify only when the physical boundary is
  degraded;
- `noid-pending-reboot.desktop` — local pending-reboot notification;
- `noid-welcome.desktop` — opens Setup only until its completion state says it
  is no longer needed.

There is no XDG resident monitor. User-added VPN/application autostarts are
explicit user configuration and are outside this image-owned list.

NoID Privacy also writes `Hidden=true`, `NoDisplay=true` and
`X-GNOME-Autostart-enabled=false` overrides for
`localsearch-3.desktop`, `org.gnome.Evolution-alarm-notify.desktop` and
`geoclue-demo-agent.desktop`. These are negative
activation policy: they prevent the corresponding vendor/session programs
from starting automatically and do not create replacement workers. The
idempotent `noid-restore-gnome-flow` helper restores those exact overrides
only during the package transactions listed below. GNOME Shell's tour offer is
kept off by the unlocked `welcome-dialog-last-shown-version` dconf default, not
by an autostart entry.

## NetworkManager dispatchers

Dispatchers run only for NetworkManager events. `pre-up.d` contains awaited
activation gates. Expensive ordinary post-activation work for M03/M04/M06 has
an exact second copy under `no-wait.d` (M06's WAN-strict scan exists only
there), and its root dispatcher entry points there. NetworkManager starts a
`no-wait.d` script at once, but runs the awaited scripts of the same event, and
every later event, only after it exits. The M03 topology refresh and the M04
gateway revalidation therefore hand their transaction to a per-event oneshot
(`noid-lan-topology-event@.service`, `noid-arp-revalidate@.service`) and
return, so a later tunnel's awaited `pre-up` is not serialized behind them; if
that hand-off is unavailable they run the transaction themselves as before.
These units are never enabled and leave nothing running. The state/finalizer
gates require the paired copies to be byte-identical. These are event programs,
not resident processes.

- `04-iscsi` — root-owned no-op override for the unused vendor iSCSI hook;
- `25-noid-arp-initial-learn` — guarded initial gateway identity learning;
- `30-noid-lan-topology-guard` — awaited pre-up topology gate plus no-wait
  post-activation/lease refresh handed to `noid-lan-topology-event@.service`;
- `40-noid-connection-defaults` — physical-profile privacy defaults;
- `41-noid-resolved-feature-reset` — on a physical profile's `up` only, asks
  systemd-resolved to re-probe every DNS server's feature level, so a
  system-wide VPN that autoconnected before login without an underlay does not
  stay degraded (no TLS, no DNSSEC) afterwards; it changes no server, mode or
  cache;
- `45-noid-wireguard-mtu` — awaited activation and no-wait physical/lease
  rechecks that lower only an oversized live WireGuard link from its evaluated
  peer routes; no profile is saved, reconnected or rewritten;
- `50-vpn-zone-enforce` — runtime inbound-DROP zone for genuine tunnels;
- `55-wan-ipv6-refresh` — physical-WAN IPv6 boundary refresh;
- `55-wan-strict-scan-on-network-up` — no-wait strict endpoint/candidate
  reconciliation;
- `58-wan-strict-tunnel-down` — removes volatile active proof;
- `60-vpn-endpoint-pin` — promotes authenticated supported endpoint evidence;
- `90-arp-hardening` — awaited gateway-pin restore plus no-wait maintained
  post-DHCP identity reconciliation handed to `noid-arp-revalidate@.service`;
- `99-noid-sysctl-reapply` — exact network sysctl reassertion after events;
- `pre-up.d/20-noid-wan-strict-boot-guard` — blocks physical activation if an
  armed fail-closed state cannot be reconstructed.

Fedora's `20-chrony-dhcp` and `20-chrony-onoffline` payloads remain pristine in
`/usr/lib/NetworkManager/dispatcher.d`, but Module 11 shadows them with exact
no-op files in `/etc/NetworkManager/dispatcher.d`. They therefore do not import
DHCP time sources or bypass the gateway/XDP readiness consumers. No polling
loop was added.

## udev, package transactions and generators

The six NoID Privacy udev rules are event-only:

- `62-noid-mutter-headless-offload.rules`;
- `71-noid-wan-strict-tunnel-hotplug.rules`;
- `99-noid-lan-topology-hotplug.rules`;
- `99-noid-mei-kt-block.rules`;
- `99-noid-external-storage-mount.rules`;
- `99-zz-noid-bluetooth-default.rules`.

They select local GPU/session behavior, queue exact network-policy one-shots,
block listed ME KT/SOL host-driver binding, apply external-storage mount defaults
or restore the default Bluetooth block. None is a daemon.

DNF5 actions run only inside an explicit DNF invocation. The VSCodium
metadata-key action runs whenever DNF configures repositories (including
queries and GNOME Software's DNF daemon sessions); all others run only in
package transactions. The complete set is `noid-branding.actions`, `noid-codium-launcher.actions`,
`noid-dnf5-state.actions`, `noid-firefox.actions`, `noid-gnome-flow.actions`,
`noid-gnome-privacy-contract.actions`,
`noid-gnome-software-launcher.actions`,
`noid-gsk-settings-launcher.actions`, `noid-identity.actions`,
`noid-logrotate.actions`, `noid-permission-policy.actions`,
`noid-selinux-policy.actions`, `noid-thunderbird.actions` and
`noid-vscodium-repo-key.actions`.
`noid-nvidia-initramfs.actions` appears only after the explicit NVIDIA
workflow installs it. These actions restore image-owned overlays, re-apply
Module 42's 30-day logrotate stanzas when an owning package is installed and
retire their RPM leftovers when it is removed, keep DNF5's package-inventory
state readable after every transaction, or queue transactional recovery; they
do not schedule package downloads.

GNOME Software's admin launcher also exposes two user-selected desktop
actions. **Open GNOME Software with Fedora RPMs** starts one foreground process
with the `appstream` and `dnf5` plugins added to the ordinary Flatpak-only set;
it writes no setting and schedules nothing. **Quit completely** asks GNOME
Software to shut down gracefully and stops the DNF5 backend only after proving
that no package-manager session remains. Neither action runs automatically.

`/usr/lib/systemd/system-generators/noid-lan-expiry-generator` reads only the
validated runtime expiry schedule (`/run/noid-privacy/lan-expiry-schedule`,
published by `noid-lan-allow` from the durable exception state) at manager
generation time. It emits an exact deadline drop-in for the static reconcile
timer, or an immediate fail-closed reconcile request. It
does not stay resident.

The system and user environment generators both named
`99-noid-xdg-cleanup` run only when their respective systemd manager builds an
environment. They remove trailing slashes from the already assembled
`XDG_DATA_DIRS` value after Fedora's Flatpak generators and print the corrected
assignment; they do not stay resident or access the network.

## Other automatic native surfaces

- The NoID Privacy tmpfiles files create exact runtime directories, locks, markers or
  permission-policy state when Fedora's native tmpfiles units run:
  `90-noid-permission-policy.conf`, `90-noid-dnf5-state.conf`, `noid-runtime.conf`,
  `noid-samba-cleanup.conf`, `noid-wan-ipv6.conf`,
  `noid-wan-strict.conf`, `noid-aide-lock.conf`,
  `noid-boot-mutation-lock.conf`, `noid-identity-bls-refresh.conf`,
  `noid-libmount-utab-event.conf` and `noid-update-lock.conf`. The M08 override `/etc/tmpfiles.d/tmp.conf`
  additionally shortens Fedora's aging thresholds to 1 day for `/tmp` and
  7 days for `/var/tmp`; Fedora's own daily `systemd-tmpfiles-clean.timer`
  performs that deletion. The M08 mask `/etc/tmpfiles.d/cockpit-ws.conf`
  (a `/dev/null` symlink) removes the Live-only cockpit-ws entry that would
  publish a login-banner hint for the masked `cockpit.socket`. They contain
  no network operation.
- `/etc/audit/plugins.d/noid-notify.conf` ships with `active = no`. The user
  toggle owns activation; the spool path is merely its local delivery half. An
  opted-in value persists across reboots and is re-verified before auditd starts.
- `/etc/profile.d/98-noid-bash-history.sh` and
  `/etc/profile.d/99-noid-security-umask.sh` run in interactive shell setup.
  `/etc/environment.d/40-noid-disable-jit.conf` and
  `/etc/environment.d/45-noid-wayland.conf` provide application-overridable
  session defaults through systemd's maintained environment generator. None
  is a background service. No project-owned `pam_exec`, cron/anacron or `systemd-sleep`
  hook is shipped.
- `90-noid-microphone-privacy.conf` loads
  `noid-microphone-privacy.lua` inside Fedora's existing WirePlumber process.
  Keep: it mutes current and newly discovered capture sources while the local
  privacy setting is active, including a one-second in-process integrity
  fallback. It adds no process and performs no network operation.
- `50-noid-disable-bluez.conf` is another policy fragment loaded by the
  existing WirePlumber process while Bluetooth is disabled. It prevents the
  BlueZ monitor and SPA library from loading; the supported Bluetooth toggle
  removes or restores the fragment. It adds no process or network activity.
- The session-bus admin descriptors for `org.gnome.OnlineAccounts`,
  `org.gnome.Identity` and `org.freedesktop.PackageKit` route unsolicited
  activation to the globally masked `noid-blocked-session-service.service`;
  the matching D-Bus policy independently denies the GOA and Identity names
  and the three PackageKit session interfaces (`Query`, `Modify`, `Modify2`).
  GNOME Software's own `org.freedesktop.PackageKit` descriptor would otherwise
  start the vendor binary directly for any caller of that name, such as the
  GStreamer codec helper or the GTK3 font module that Module 26 excludes.
  Fedora's `org.gnome.Software.service` descriptor stays package-owned and
  routes to the separately masked `gnome-software.service`; the retired
  `/usr/local` direct-exec shadow is required absent. Keep: these are
  activation blockers, not workers.
- `/etc/polkit-1/rules.d/60-noid-toggle-privacy-services.rules` is consulted
  only for an explicit `pkexec` request to one of its exact reviewed helper
  paths. It returns uncached administrator authentication and never starts a
  background worker. The retired broad USBGuard rule
  `50-noid-usbguard.rules` is required absent.
- The dracut files are build-time/initramfs configuration and boot content,
  not host background daemons.

## Automatic designs that must stay absent

The following names belong to no current design. Module or finalization checks
require each to be absent, so none can return silently. Units:
`noid-aide-firstboot-rebaseline.service`,
`noid-aide-firstboot-rebaseline.timer`,
`noid-aide-rebaseline-on-boot.service`, `noid-dns-health.service`,
`noid-dns-health.timer`, `noid-suid-harden.service`,
`noid-suid-harden.timer`, `noid-flatseal-install.service`,
`noid-firstboot-codec-swap.service`, `noid-mic-privacy-enforce.service`,
`noid-plymouth-firstboot.service`,
`noid-plymouth-firstboot-cleanup.service`,
`noid-arp-bootstrap.service`,
`noid-chrony-network-online.path` and `noid-grub-menu-show.service`.
NetworkManager hooks: `25-noid-arp-bootstrap-learn`,
`58-wan-strict-clean-disconnect`, `70-pvpn-killswitch-dns-fix` and
`80-vpn-keepalive`. udev rules: `60-noid-iosched.rules`,
`99-noid-usb-sync-mount.rules`, `99-noid-usb-write-through.rules` and
`99-noid-binfmt-disable.rules`. Other files: the `noid-dbus-suppress.actions`
package hook, `/etc/tmpfiles.d/noid-disable-iscsi-dispatcher.conf`,
`/etc/tmpfiles.d/noid-hwp-dynamic-boost.conf`,
`/etc/environment.d/50-noid-xdg-paths.conf` and the `55-noid-gsk-renderer`
user-environment generator; the bounded
`noid-gsk-session-environment.service` listed above covers that renderer
need. Ordinary `noid-network.desktop`, `noid-tools.desktop` and
`noid-update-all.desktop` files are app launchers, not XDG autostarts.

## Fedora services intentionally used

The image explicitly enables or selects `firewalld.service`, `auditd.service`,
`chronyd-restricted.service`, `usbguard.service`,
`usbguard-dbus.service`, `earlyoom.service`, `tuned.service`,
`tuned-ppd.service`, the hardware-conditional `thermald.service` and
Snapper's `snapper-cleanup.timer`. Firewalld, auditd, restricted
chrony and USBGuard are load-bearing policy engines. EarlyOOM is the selected
local memory-pressure safety mechanism; TuneD and its power-profiles-daemon
facade are one backend plus one compatibility surface, not competing tuners.
Thermald follows Fedora's hardware condition. Snapper cleanup is local storage
maintenance; the project-owned `noid-btrfs-scrub.timer` is listed under the
system-manager timers above.

Module 08 also deliberately retains these Fedora units instead of masking
them:

- `raid-check.timer`, `mcelog.service`, `smartd.service`, `mdmonitor.service`
  and the mdadm reshape template: local, self-conditional safety and recovery
  monitors without network egress;
- `switcheroo-control.service`: the hybrid-GPU D-Bus helper, kept enabled and
  sandboxed by a NoID Privacy drop-in;
- the socket-activated core libvirt daemons (`virtqemud`, `virtnetworkd`,
  `virtstoraged`, `virtlogd`, `virtnodedevd`), because VM hosting is a
  supported workload; the optional families and legacy `libvirtd` are masked;
- the D-Bus-activated `dnf5daemon-server.service` (explicit GNOME Software RPM
  use), `geoclue.service` (sources gated by the location setting) and
  `bluetooth.service` (radio kept off by the rfkill enforcer until opt-in).

Automatic package-cache refresh, firmware refresh, location discovery,
printing/discovery, UPnP/DLNA media sharing, remote-login and unused server
surfaces remain disabled, masked, removed or opt-in as documented by Modules
05, 08, 11, 17, 18, 21 and 24 and the installed `08-masked-services.md` guide.
Module 17 masks the user unit `rygel.service`, so a session D-Bus request for
`org.gnome.Rygel1` cannot start Rygel's media server; GNOME Settings Media
Sharing cannot be enabled while that mask exists.

## Live inspection

Use the live system as authority for a particular machine:

```bash
systemctl list-unit-files 'noid-*'
systemctl list-units 'noid-*' --all
systemctl list-timers 'noid-*' 'aide-check.timer' --all

systemctl --user list-unit-files 'noid-*'
systemctl --user list-units 'noid-*' --all
systemctl --user list-timers 'noid-*' --all

find /etc/xdg/autostart -maxdepth 1 -name 'noid-*.desktop' -print
find /etc/NetworkManager/dispatcher.d -type f -o -type l
find /etc/udev/rules.d -maxdepth 1 -name '*noid*' -print
find /etc/dnf/libdnf5-plugins/actions.d -maxdepth 1 -name 'noid-*' -print
```

`noid-integrity-check --section timers` classifies every installed system
timer by source. A missing or unexpected live surface remains evidence to
investigate; this repository inventory never overrides inspected host state.
