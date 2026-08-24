# Known failure modes and safe diagnostics

This is a symptom-to-module index, not a waiver for failing tests. Confirm the
actual state before changing hardening, retain the recovery path, and restore
the default after a temporary exception.

## M01 — boot or third-party module failure

Unsigned/out-of-tree modules can fail under Secure Boot/lockdown or after a
kernel update.

```bash
uname -r
mokutil --sb-state
journalctl -b -k | grep -iE 'lockdown|module.*sig|unsigned|verification'
akmods --force --kernels "$(uname -r)"
```

Boot a known prior kernel from GRUB if necessary. For NVIDIA, use the shipped
`noid-nvidia-install.sh`/MOK guide so key creation, build and signature checks
stay in one workflow. Do not sign an assumed module path or disable Secure Boot
globally without identifying the failed module.

If initramfs recovery is intentionally suppressed and the system cannot reach
userspace, boot a prior kernel or a verified rescue medium. A blank/hung display
alone does not prove the root cause; collect the previous-boot journal with
`journalctl -b -1` after recovery.

On an older NoID Privacy image, a generated kmod can exist for a newly installed,
not-yet-running kernel while `modinfo -k <new-version> <module>` still fails.
Those images deleted both `System.map` files, causing RPM Fusion's generated
kmod scriptlet to fall back from target-specific depmod to unqualified
`depmod -a`, which indexes only the running kernel. Current images retain both
package files as root-only 0600 and the NVIDIA worker also converges its exact
target index before verification. Diagnose this state by comparing the kmod
files with `/usr/lib/modules/<new-version>/modules.dep`; never treat another
unqualified depmod or a repeated queue resume as proof of repair.

### One-boot pstore capture for an early hang

The normal image intentionally disables EFI/ERST pstore with
`efi_pstore.pstore_disable=1 erst_disable`; `systemd-pstore` additionally uses
`Storage=none`, so it neither copies records into `/var/lib/systemd/pstore` nor
unlinks firmware-backed records. This minimizes persistent kernel and hardware
identifiers. It also means an early hang can leave no previous-boot journal.

For one diagnostic boot only, press `e` on the selected GRUB entry, edit its
`linux` line, remove both disabling tokens and append:

```text
efi_pstore.pstore_disable=N printk.always_kmsg_dump=Y
```

Boot that edited entry with Ctrl-X. This changes only the selected boot; do not
use `grubby` or rewrite the persistent command line for a one-time capture.
The firmware and kernel must actually provide a pstore backend, and its small
buffer may contain only the tail of the kernel log, so an empty result does not
prove that no failure occurred.

If the diagnostic boot resets or hangs, make the same temporary GRUB edit on
the immediately following recovery boot. Otherwise the normal disable tokens
prevent the EFI/ERST backend from exposing the retained record. Inspect before
deleting anything:

```bash
find /sys/fs/pstore -maxdepth 1 -type f -printf '%f %s bytes\n'
sudo sed -n '1,240p' /sys/fs/pstore/dmesg-* 2>/dev/null
```

Copy the original files to protected local evidence before filtering them.
Kernel logs can contain device serials, filesystem paths, network addresses
and other machine-identifying values; redact those values before sharing.
Removing a file from `/sys/fs/pstore` erases the corresponding persistent
record, so retain it until the evidence decision is complete. Boot normally
after capture to restore NoID Privacy's default suppression.

## A normal boot shows failures only

The canonical kernel command line carries `rhgb quiet`. `quiet` is parsed by
PID 1, not only by the kernel: systemd drops to `SHOW_STATUS_ERROR`, so the
console carries `[FAILED]` lines and nothing else. Without it every
`[ OK ] Started ...` transition is printed and a real failure is lost in the
flood — the state a boot is in when it looks like a debug trace.

`loglevel=4` is deliberately *not* lowered alongside it. It keeps
KERN_ERR and more severe kernel messages on the console, which is load-bearing
with `rd.shell=0 rd.emergency=halt`: an early storage or LUKS failure must not
become an opaque black screen. Two consequences follow and are expected:

- Informational kernel errors from unrelated subsystems stay visible when
  Plymouth is not covering the console — for example
  `virt/tdx: TDX not supported by the host platform`. That is `tdx_enable()`
  reporting an absent CPU feature and returning `-ENODEV`; it is not a
  NoID Privacy dependency and nothing is disabled by it. It cannot be silenced
  per message, only by lowering the console threshold, which would take the
  LUKS and storage diagnostics with it.
- The journal is unaffected either way. `journalctl -b -k` still has every
  message regardless of what reached the console.

## Explicit Live-media check is intentionally verbose

The normal graphical Live entry is the three-second default. Selecting
`Test this media & start NoID Privacy Workstation 44` explicitly instead runs
the native checksum path without `rhgb`, so early kernel and systemd diagnostics
are visible. `Supported ISO: no` is not a checksum failure: isomd5sum uses that
bit for media marked as a supported distribution format (for example pressed
media), while the final checksum result decides integrity. NoID Privacy does
not set that bypass flag on a user-written ISO.

With the deliberate `debugfs=off` kernel policy, drivers such as iwlwifi,
nouveau or CEC may also report that they could not create an optional debugfs
directory. On the Fedora 44 7.1 kernel, `debugfs=no-mount` is a deprecated
alias for `debugfs=off`, so substituting it does not change the result. Making
those registrations succeed requires `debugfs=on`, which registers the
filesystem and is a different security policy; Fedora's systemd then normally
pulls in `sys-kernel-debug.mount` during sysinit. Diagnose an actual device
failure from its functional state and complete journal, not from the expected
missing-debug-interface message.
Likewise, `virt/tdx: TDX not supported by the host platform` reports an absent
optional CPU/firmware facility; it is not a requirement for this workstation.
Fedora's kernel builds `CONFIG_INTEL_TDX_HOST=y`, and the upstream
`tdx_enable` subsystem initcall currently emits this as `pr_err` before
returning `-ENODEV` on a non-TDX host. A generic
`initcall_blacklist=tdx_enable` would also disable TDX on hardware that really
supports it, so it is not a portable-image fix.

Other hardware-discovery lines must be classified from their exact producer,
not hidden with a lower console log level:

- `ie31200_edac ... mapping multiple BARs`, paired with a `resource sanity
  check` against `PNP0C02`, means the firmware resource window does not cover
  the complete Intel MCHBAR mapping requested by the in-tree EDAC driver. The
  mapping continues. Do not blacklist EDAC solely to remove the warning;
  check firmware updates and the resulting EDAC controller state.
- `r8169 ... can't disable ASPM; OS doesn't have ASPM control` means ACPI did
  not grant the OS control needed for the in-tree Realtek driver's defensive
  ASPM request. It is not caused by NoID Privacy's EEE or power policy. Do not
  add `pcie_aspm=force` generically; verify the link and use vendor firmware
  guidance for that machine.
- `spi-nor spi0.0: supply vcc not found, using dummy regulator` is the kernel
  regulator core's fallback when firmware does not describe a separately
  controllable supply. The SPI-NOR probe then proceeds with the always-on
  dummy supply; validate the resulting device instead of inventing an ACPI
  regulator in the image.
- `block nvme...: No UUID available providing old NGUID` is the NVMe sysfs
  compatibility path: the namespace supplied no UUID, so the kernel returns
  its older NGUID identifier. It does not report filesystem or LUKS damage.
- `system.journal corrupted or uncleanly shut down, renaming and replacing`
  says journald has already retired and replaced that journal file. After a
  forced power-off, retain the renamed file as evidence and verify the next
  clean shutdown/boot rather than deleting or rebaselining evidence.

`kauditd_printk_skb: N callbacks suppressed` is printk's rate limiter naming
the function it throttled, not an audit-subsystem fault. No userspace auditd
is connected yet in the initramfs, so the kernel prints audit records through
printk, and `audit=1` on the kernel command line plus Module 12's rule set
generate more early records than printk emits per interval. Typically visible
around the LUKS passphrase prompt, where the console is already waiting. Only
the console copy is dropped. A real audit-buffer overflow reports
`audit: backlog limit exceeded` instead, and the `lost` counter that
`tests/pre-ship/31-installed-enforcing-avc.sh` requires to be zero comes from
`auditctl -s`, which this line does not affect. Do not lower
`audit_backlog_limit`, drop `audit=1` or raise the console log level to
silence it; read the retained records with `ausearch` once auditd is running.

Fedora 44 systemd 259 still applies `.link` EEE through the legacy 32-bit
`ETHTOOL_GEEE`/`ETHTOOL_SEEE` ABI. Newer link modes cannot be represented by
that ABI and make the kernel print `Ethtool ioctl interface doesn't support
passing EEE linkmodes beyond bit 32`. NoID Privacy therefore leaves EEE with
Fedora, the driver and the link partner; its separate Wake-on-LAN default-off
policy does not configure EEE.

## Host-identity gate blocks local sessions

`gdm.service` and `systemd-user-sessions.service` intentionally require both
`noid-host-identity.service` and the installed-target security cleanup. A
failed host-identity contract therefore keeps graphical and ordinary console
sessions closed instead of admitting a login with missing, malformed or
partially published BRLAPI/NVMe identity state.

Use a verified rescue environment or emergency root shell and preserve the
first failure before changing anything:

```bash
systemctl status noid-host-identity.service
journalctl -b -u noid-host-identity.service
/usr/local/bin/noid-host-identity --check
getent -s files group brlapi
```

Do not print or publish the contents of `/etc/brlapi.key`,
`/etc/nvme/hostid` or `/etc/nvme/hostnqn`. If the files are invalid and no
non-PCIe NVMe controller is active, the supported repair rotates the BRLAPI
key and the internally coupled NVMe identity pair, then verifies their modes,
labels and schema:

```bash
/usr/local/bin/noid-host-identity --repair
systemctl restart noid-host-identity.service
/usr/local/bin/noid-host-identity --check
```

Reboot normally after the service and check both pass. `--repair` deliberately
refuses while an NVMe-over-Fabrics controller is active: in that case retain
the configured storage identity and recover it from the administrator's known
good storage configuration rather than rotating it underneath the fabric.
Likewise, repair a missing local `brlapi` group/package contract first; do not
weaken or remove the `Requires=` gates to make the login screen appear.

## M03 — physical coldplug boot dependency cascade (cause unverified)

An affected pre-fix image reported `226/NAMESPACE` for
`noid-lan-topology-guard.service`; `noid-lan-expiry-reconcile.service` and
`NetworkManager.service` then failed through their dependency chain, while
`noid-lan-expiry-failure.service` was the expected notifier. Preserve those
observations, but do not attribute them to physical coldplug outrunning
`systemd-tmpfiles-setup.service`: ordinary service units already have default
`Requires=`/`After=` dependencies on `sysinit.target`, and Fedora orders
`systemd-tmpfiles-setup.service` before that target. The later explicit M03
`Requires=`/`After=` edges document the shared runtime owner and propagate its
failure, but did not create a previously absent boot order and therefore do
not prove that they fixed the observed `226/NAMESPACE` event.

If it recurs, retain the complete boot journal and inspect the exact failed
namespace path, the installed `ReadWritePaths=`, the status of
`systemd-tmpfiles-setup.service`, and the identity of `/run/noid-privacy`.
Treat the historical cause as unverified until that evidence identifies it.
Do not remove NetworkManager's fail-closed dependency or rate-limit the console
to hide the cascade.

## M03–M05 — LAN peer unreachable

Physical links use inbound DROP and local/on-link destination blocking. Allow
only the reviewed peer through NoID Privacy Network or the CLI:

```bash
sudo noid-lan-allow --add 192.168.1.50 --direction outbound --temp 60
sudo noid-lan-allow --list
sudo nft list table inet noid_lan_topology
firewall-cmd --get-active-zones
```

This outbound-only exception permits host-initiated traffic to that peer plus
correlated replies; it does not permit a new inbound connection. An inbound or
bidirectional exception must additionally name `--protocol tcp|udp` and an
exact `--ports PORT|START-END` selector. Revert the exception when finished:

```bash
sudo noid-lan-allow --revert 192.168.1.50
```

## M06 — WAN-strict blocks connectivity

WAN-strict is separate from ordinary LAN isolation. NetworkManager/libnm is
the profile authority. Literal endpoints are durable; hostname answers are
only 120-second handshake candidates until supported runtime evidence promotes
the actually used tuple. Profile deletion/change and expiry reconcile stale
state instead of accumulating it.

```bash
noid-toggle-wan-strict status
sudo nft list table inet noid_wan_strict
sudo cat /var/lib/noid-privacy/wan-strict-endpoints.txt 2>/dev/null
journalctl -u noid-wan-strict.service -b --no-pager
```

Use the helper's bounded `pause` only for diagnosis. `reset` clears records and
the armed marker, intentionally reopening bootstrap grace. Do not
insert an ad-hoc broad nft accept rule as a “fix”.

## M08 — Bluetooth, location or optional services

Bluetooth default-off is a flag-gated rfkill policy, not a permanent service
mask:

```bash
noid-toggle-bluetooth status
rfkill list bluetooth
sudo noid-toggle-bluetooth on
```

BlueZ can be active while the radio is blocked, so service state alone is not
the postcondition. For location, use `noid-toggle-location status|on|off`; the
per-user GNOME setting is the authoritative user choice.

Printing/discovery and smartcard stacks involve multiple units/packages and
network exceptions. Follow the applicable optional-package/device guide rather
than unmasking one guessed unit. Module 35's smartcard guide, for example,
requires explicit PC/SC unmasking and a sign/decrypt test.

A D-Bus client can still request a deliberately masked service. On the default
image this can produce `Activation request for 'org.freedesktop.home1' failed.`,
the equivalent `org.freedesktop.ModemManager1` line, or an activation failure
for `org.freedesktop.Tracker3.Miner.Files` or
`org.freedesktop.MalcontentTimer1`. Those lines are consistent with the silent
machine policy only while their exact owner remains masked and the requesting
UI/session continues without the optional feature:

```bash
systemctl is-enabled systemd-homed.service ModemManager.service \
  malcontent-timerd.service
systemctl --user is-enabled localsearch-3.service
systemctl --failed
```

Do not unmask a service merely to remove its rejected activation line. If the
user explicitly enabled that capability, or the requester fails with it, the
same message is no longer expected and the mask/feature contract must be
reviewed. With Location off, GeoClue's `No sources enabled in configuration`
is the corresponding no-source result; compare it with
`noid-toggle-location status` before classifying it.

`gkr-pam: unable to locate daemon control file` can occur once while GDM hands
the login secret to a keyring daemon whose control environment is not yet
published. Treat it as transient only if the logged-in session subsequently
owns `org.freedesktop.secrets` and applications can use the keyring:

```bash
busctl --user status org.freedesktop.secrets
```

A missing owner after login, repeated unlock prompts, or an application unable
to retrieve its stored credential is a real keyring fault, not this startup
ordering case.

The GDM greeter can also leave a failed transient
`org.gnome.Settings.GlobalShortcutsProvider` unit while handing the compositor
to the real desktop session. Classify it as cosmetic only when the provider
first reports `Lost connection to Wayland compositor`, the failed unit belongs
to the GDM runtime UID rather than the logged-in account, and the current user
manager is clean:

```bash
sudo journalctl -b -u 'dbus-*-org.gnome.Settings.GlobalShortcutsProvider@*.service' \
  --no-pager
systemctl --user --failed
```

A provider failure in the active user's manager, or broken global-shortcut
registration in that session, is not the greeter-handoff case.

GNOME Shell may request the optional `org.freedesktop.bolt.enroll` PolicyKit
action even when the `bolt` package is deliberately absent. The resulting
`Action ... is not registered` line is inert only while both the package and
service are absent and Thunderbolt enrollment was not enabled:

```bash
rpm -q bolt
systemctl status bolt.service --no-pager
```

If the user selected Thunderbolt support or hardware enrollment is expected,
the missing action is a real incomplete optional-stack installation. Do not
invent a local PolicyKit action merely to silence GNOME Shell.

## M10 — faillock

```bash
faillock --user "$USER"
```

Wait for the configured timeout or have an authorized administrator reset the
correct account. Do not weaken global PAM policy to recover one lockout.

## M11 — resolver/NTS on restrictive networks

Corporate/captive networks can block the preferred Quad9 DoT path, block an
explicitly selected browser Secure DNS endpoint, or require a local
resolver/portal. Inspect instead of assuming DNS is the cause:

```bash
resolvectl status
resolvectl query example.com
sudo chronyc -N tracking
sudo chronyc -N sources -v
journalctl -u systemd-resolved -u chronyd-restricted.service -b --no-pager
```

Use the DNS customization guide for a deliberate resolver exception and revert
it afterward. Global and managed physical Quad9 use strict authenticated DoT
by default. If that prevents VPN or captive-portal setup, deliberately enable
the opportunistic compatibility mode, which permits DNS/53 fallback on the
physical bootstrap path. VPN/private DNS remains an independent per-link scope:
an unset profile inherits best-effort opportunistic DoT with DNS/53 fallback,
while an explicit profile value wins.
Resolver changes do not themselves grant access to a local portal destination;
the LAN policy may also require an exact peer exception.

Chrony starts all six NTS hostnames offline and resolves them asynchronously
only after M04 publishes the gateway/XDP readiness boundary. On a slow
VPN/private-DNS transition, the journal may therefore show sources as
`ID#000000000X` before their addresses are known. Current images wait up to two
minutes and require the configured `minsources 3` count to be online; one
resolved name is not reported as a usable transition. Inspect the address-free
aggregate evidence without exposing server or local-network identities:

```bash
journalctl -b -t noid-network-readiness --no-pager
sudo chronyc -n activity
systemctl status noid-chrony-network-online.service --no-pager
```

`unknown` decreasing while `online`/`burst` increase is resolver convergence,
not proof of an NTS-KE failure. Bounded exhaustion is still fail-visible and
returns all sources offline; a later verified physical-link event retries the
transition.

`NTS-KE session with ...:4460 (...) timed out` is a later, separate TLS path.
One measured Proton exit allowed four configured operators but timed out both
`ntppool1.time.nl` and `ntppool2.time.nl`; the same two sources completed NTS-KE
without that VPN. This proves only that source/exit combination, not a general
Proton or time.nl policy. If `chronyc activity` still reports at least the
configured three usable sources, `timedatectl` reports synchronization and
tracking is current, time service remains functional with reduced redundancy.
Change the user-selected VPN exit and re-observe before blaming the image or
removing a configured source. A timeout with no VPN, fewer than three usable
sources, or loss of synchronization is a different failure.

An RTC offset which is still inside the NTS certificates' validity window is a
normal automatic-time bootstrap case. This includes firmware storing local
civil time while Linux correctly interprets the RTC as UTC. Chrony must select
the NTS-authenticated sources, apply the early `makestep`, remain active and
subsequently discipline the RTC through `rtcsync`. `NTP=no` together with a
failed `chronyd-restricted.service` after such an offset is a regression, not a
reason to require manual recovery.

If the RTC is so wrong that NTS TLS certificates are not yet valid or already
expired, `chronyc makestep` has no authenticated measurement to apply. Obtain
exact UTC independently, change to a physical text console (`Ctrl+Alt+F3`) and
use the fail-closed helper:

```bash
sudo noid-time-recovery set 2026-07-13T18:42:00Z
sudo chronyc -N authdata
sudo chronyc tracking
```

The value is an example and must be replaced. The helper refuses SSH and
graphical pseudo-terminals, requires an exact timestamp-bound confirmation and
does not add plaintext NTP or `nocerttimecheck`. See
`/usr/share/doc/noid-privacy/11-time-recovery.md`.

## M23 — the first saved WLAN appears to connect twice

This can be one profile completing its installed-user privacy transition, not
a duplicate WLAN. A profile created after GNOME Initial Setup initially has no
user permission. M23 first applies the reapplicable network policy, persists
`connection.permissions=user:<local-account>`, and then asks NetworkManager to
reapply the active connection. NetworkManager deliberately rejects that
non-reapplicable metadata; the account-completion helper therefore activates
the same UUID on the same device once and requires a final successful reapply.

Confirm the identity without publishing the SSID, UUID or lease address:

```bash
journalctl -b -t noid-nm-defaults -t noid-nm-scope --no-pager
systemctl status noid-nm-scope-physical-profiles.timer --no-pager
sudo stat -Lc '%U:%G:%a:%s' \
  /var/lib/noid-privacy/nm-physical-profiles-scoped.flag
nmcli -t -f TYPE connection show | sort | uniq -c
```

A clean completed state has one root-owned `0600` empty completion marker, the
retry timer inactive/condition-skipped on later boots, and no second saved Wi-Fi
profile. Later activations do not repeat the permission reactivation. A
different UUID, a recurring reconnect, an active retry timer after completion
or any `FAIL:` line is a separate fault to investigate.

## M12 — SELinux/audit denial

An AVC is evidence to investigate, not automatically “benign upstream noise”.

```bash
getenforce
sudo ausearch -m AVC,USER_AVC -ts boot | tail -100
sudo audit2why -a 2>/dev/null | tail -100
systemctl --failed
```

Confirm the denied operation, executable/package owner, final service result
and recurrence. Do not generate/install an `audit2allow` module blindly. Fix
the service confinement or upstream policy root cause, and keep enforcing mode
unless a narrowly bounded diagnostic explicitly requires otherwise.

## M13 — AIDE differences

```bash
sudo /usr/local/sbin/noid-aide-check.sh
journalctl -u aide-check.service -b --no-pager
```

The wrapper validates the active database/configuration boundary, serializes
the run and preserves a timestamped report. It returns AIDE's bitmask:
ordinary differences are not the same as an execution/config/database error.
Review paths and package/update history before changing trust state.
`noid-aide-baseline-review prepare` creates only a candidate; the user must
review its report and commit the exact SHA-256 interactively. Never replace
the live database from a failed, missing or unreviewed `.new` candidate merely
to silence a warning.

Repository tests intentionally run an unprivileged AIDE comparison against a
temporary fixture. Fedora's AIDE binary is built with audit support, so a
fixture that detects changes can additionally log
`Failed sending audit message:added=... removed=... changed=...` when its
userspace anomaly notification lacks audit-write authority. Attribute that
line to the harness only when verbose journal metadata binds it to the
temporary fixture and the test time window; `auditctl -s` must still report
`lost 0`. A line from `aide-check.service`, a real database path, or an
unrelated time is not a test artefact and must be investigated.

## M14 — unknown USB device blocked

```bash
sudo usbguard list-devices
sudo noid-usbguard-devices allow
```

Review vendor/product/serial/interface attributes displayed by the helper.
Avoid `usbguard generate-policy >> rules.conf`: it can bless every currently
connected device and create duplicate/broad rules.

## M15/M24 — MEI or fwupd HSI variation

NoID Privacy keeps core `mei`/`mei_me` available for supported firmware visibility and
blocks only the enumerated KT/SOL host bindings by default. Kernel, firmware,
CPU and fwupd versions can change which HSI attributes are available and how
the aggregate score is classified.

```bash
uname -r
grep CONFIG_INTEL_MEI /boot/config-"$(uname -r)" 2>/dev/null
lsmod | grep '^mei' || true
fwupdmgr --version
fwupdmgr security
```

Treat the per-attribute output as authoritative for that platform. Do not claim
a fixed HSI level, equate missing visibility with a mitigation, or patch signed
shim/firmware bytes locally. Intel AMT OOB and AMD PSP remain hardware/firmware
boundaries described in the threat model.

## M16 — Firefox profile or uBlock integration missing

```bash
/usr/local/bin/noid-firefox-setup.sh
python3 -m json.tool \
  /usr/lib64/mozilla/managed-storage/uBlock0@raymondhill.net.json >/dev/null
```

Close Firefox before reapplying profile files. Confirm the exact profile path
and inspect `about:addons`; file presence is not proof that an extension loaded
or received its expected permissions.

## M17 — GNOME online/integration panel remains visible

Some GNOME Settings panels can remain visible even when the corresponding
D-Bus activation route is denied. Inspect the admin route, its static mask,
the fallback session policy and the pristine vendor payload:

```bash
grep -E '^(Exec|SystemdService)=' \
  /usr/local/share/dbus-1/services/org.gnome.OnlineAccounts.service
readlink /etc/systemd/user/noid-blocked-session-service.service
grep -F 'org.gnome.OnlineAccounts' \
  /etc/dbus-1/session.d/20-noid-blocked-services.conf
rpm -Vf /usr/share/dbus-1/services/org.gnome.OnlineAccounts.service
systemctl --user --failed
```

A visible empty panel is cosmetic only after the higher-priority admin route,
`/dev/null` mask, fallback policy and pristine lower-priority RPM descriptor
are all verified. Fedora's GOA and Identity descriptors expose only `Exec`
routes. On the validated Fedora 44 session, the mandatory policy alone returned
`AccessDenied` only after both processes had started. Their two administrator
descriptors are therefore intentionally retained; dbus-broker reports the
lower-priority vendor names as duplicates at session start or configuration
reload. Removing those descriptors only to silence the diagnostics weakens the
silent-machine boundary.

GNOME Software and Tracker are intentionally different: there must be no
`/usr/local` service override for them. Fedora's vendor descriptors route
directly to masked systemd user units, so unsolicited Software activation
fails immediately and Nautilus' LocalSearch request reaches static unit state
instead of spawning a false helper process.

## M20 — snapshots grow or rollback surprises

```bash
sudo snapper -c root list
sudo /usr/libexec/noid-snapper-status
systemctl status noid-snapper-prune.timer --no-pager
journalctl -u noid-snapper-prune.service --since today --no-pager
```

The project pruner targets every eligible numbered snapshot older than 30 days,
including `important=yes`/baseline snapshots. An active or Btrfs-default root
cannot be deleted and is reported as `protected` until another root is selected;
the first observation or a large/backward clock step reports `clock-guard` and
defers deletion. Export a long-term recovery point off-host before it becomes
eligible. Root rollback does not roll back `/home`, firmware or
remote/application state.

## M22 — mount option or encryption expectation differs

An early-boot line such as

```text
systemd-escape: Input 'luks-…' is not an absolute file system path, escaping is likely not going to be reversible.
```

is a Fedora 44 dracut 108 diagnostic, not evidence that the LUKS UUID or mapper
is damaged. Dracut's own `70crypt/module-setup.sh` emits
`rd.luks.uuid=luks-<UUID>`. Its `70crypt/parse-crypt.sh` later constructs the
mapper name `luks-<UUID>` and passes that non-path name through
`dev_unit_name()`; the installed `80base/dracut-dev-lib.sh` implements that
helper with `systemd-escape -p`, whose path mode emits the warning. The escaped
unit instance remains usable.

Verify the positive boot result instead of rewriting a working kernel command
line to hide the message:

```bash
systemctl --failed --no-pager
systemctl status 'systemd-cryptsetup@*.service' --no-pager
findmnt -no SOURCE,FSTYPE /
```

On a healthy boot the corresponding `systemd-cryptsetup@luks\x2d….service`
finishes successfully and the root filesystem resolves through that mapper.
Treat an actual failed cryptsetup unit, missing mapper or failed root mount as a
storage fault; this warning alone is cosmetic. Re-check the installed dracut
source after an update because the diagnostic originates upstream.

Encryption is selected in Anaconda and is not forced by Module 22. Inspect the
real layout and LUKS metadata:

```bash
lsblk -f
findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS / /home /tmp /var/tmp 2>/dev/null
sudo cryptsetup luksDump /dev/<reviewed-luks-device>
```

`/home` intentionally remains executable for supported user application
workflows. Adding `noexec` is a compatibility/security trade-off, not a generic
repair. Never substitute an example block device without checking `lsblk`.

## M25 — update orchestrator refuses or reports partial failure

Run it as the normal user; internal privilege prompts handle system steps:

```bash
noid-update-all.sh
```

Do not invoke the whole script with `sudo`. Read the failed step and retained
log; a snapshot or AIDE result does not make an earlier failed package/firmware
operation successful.

Firefox and GNOME Software package updates also run host-only
post-transaction compatibility guards. They authenticate the newly installed
Fedora payload and regenerate only NoID Privacy-owned launcher/XDG overlays.
Those guards deliberately use the DNF5 Actions plug-in's `raise_error=1`:
if an upstream launcher layout or required semantic anchor changes, the DNF
command reports failure instead of accepting an unreviewed transformation.
The RPM transaction may already be complete at that point, while the previous
known-good NoID Privacy overlay remains in place.

Do not weaken an anchor or repeatedly reinstall the package to hide this
failure. Inspect the exact vendor delta and the helper error first:

```bash
sudo rpm -V firefox gnome-software
journalctl -t noid-firefox-reassert -b --no-pager
sudo /usr/local/sbin/noid-firefox-reassert
sudo /usr/local/sbin/noid-gnome-software-launcher-sync
```

An unchanged helper failure after a signed Fedora package update is an
integration-review event: update to a NoID Privacy revision that supports the
new payload, or review and test the new vendor semantics before changing the
guard.

### Flatpak platform or graphics extension remains pending

An empty Flatpak installation has no app, runtime or related graphics ref to
update. Current Update All therefore skips a scope only after its local
`flatpak list` inventory proves that scope empty; it does not preinstall large
runtime drivers before an application needs them. Once any ref exists, the
ordinary system/user update and unused-runtime cleanup paths run.

Flatpak 1.18 can exit zero after an optional related-ref mutation failed and
print only `Warning: Failed to install ...`. This was observed with the
version-matched NVIDIA GL extension after the Freedesktop runtime itself and
its Mesa extensions installed successfully. Current Update All recognizes the
exact `LC_ALL=C` install/update/uninstall warning, makes at most two resumable
whole-transaction retries, and reports one non-blocking warning if the third
attempt remains incomplete. A real non-zero Flatpak process status remains a
hard Step 3 error. The GUI and CLI finish as completed with warnings for the
exit-zero related-ref case; they never force HTTP/1.1.

GNOME Software can continue showing **Update** for the parent Freedesktop
Platform in that state. This is not necessarily stale UI: libflatpak returns an
installed parent as an update candidate when a `should-download` related ref is
missing. A normal installed-ref update listing can therefore be empty while a
transaction still offers the missing extension. Inspect the actual proposal
without accepting it, then answer `n`:

```bash
flatpak --gl-drivers
flatpak list --system --runtime
flatpak update --system
sudo flatpak repair --system --dry-run
journalctl -b _COMM=flatpak --no-pager
```

Repeated libostree `[56] Failure when receiving data from the peer` lines are
transport failures, not evidence that the deployed parent runtime is corrupt.
On one measured Proton exit, direct HTTP/2 object downloads sometimes completed
and sometimes ended early; the VPN link and fragmentation-free MTU remained
stable, and reducing libostree from its default eight concurrent requests to
one did not cure the pull. That evidence rules out a general HTTP/2 or
parallelism defect, but does not identify the external CDN/exit root cause.
Do not persist an HTTP/1.1 downgrade or claim a provider-wide failure from that
one path. Wait or deliberately select another user-chosen VPN exit, rerun the
supported updater, and require that the related ref is installed and no longer
offered before treating GNOME Software's button as stale.

## M28 — no local AI runtime after installation

Expected: Module 28 is documentation-only and installs/enables nothing. Follow
the current `28-local-ai.md`, bind servers to loopback and verify the actual
listener/container/extension path.

## M08/M13 — Codex VSCodium extension blank panel on startup (conditional)

The opt-in `openai.chatgpt` extension (installed by `noid-codex-install`,
configured under Module 08) can leave the Codex panel blank after a normal
VSCodium launch: the activity icon and Command-Palette commands appear and the
pinned app-server backend spawns, but the webview never renders.

[Upstream issue #32388](https://github.com/openai/codex/issues/32388) reports
the same Linux symptom and `--disable-extension` workaround. The fact that an
otherwise irrelevant command-line option changes the outcome is consistent
with an activation-order or timing problem, but the open report does not
establish a root cause or universally rule out authentication, network,
profile-state or extension-interaction causes.
[Issue #33521](https://github.com/openai/codex/issues/33521) is a separate
Linux renderer-crash report, not confirmation of the blank-panel root cause.

This workaround is not part of the NoID Privacy launcher and must not be
applied proactively. Current NoID Privacy validation has also observed normal
Codex rendering without the flag, while upstream #32388 remains open and other
users report intermittent failures on later extension builds. A successful
start therefore proves the local symptom is absent; it does not establish a
universal upstream fix.

Only after reproducing the exact blank-panel symptom with VSCodium fully quit,
try one diagnostic launch with any `--disable-extension` name (a nonexistent
one is fine):

```bash
codium --disable-extension noid.codex-timing-workaround-32388
```

VSCodium must be fully quit first; a running instance forwards the invocation
and ignores the flag. Recreating `~/.codex` did not help the reporter in
[issue #28280](https://github.com/openai/codex/issues/28280), but that separate
Windows report does not prove the result for every Linux blank-panel case. Do
not persist the dummy flag: retain the normal launcher, capture the extension
log and re-test after a reviewed extension update.

## M34 — Firefox Playground missing or opens the wrong profile

Close Firefox, inspect the marker/profile registration and run the idempotent
initializer:

```bash
ls -l ~/.config/noid-privacy/firefox-playground-init.done
grep -A2 '^Name=playground' ~/.config/mozilla/firefox/profiles.ini
/usr/local/bin/noid-firefox-playground-init.sh
```

Do not delete an unknown profile directory. Quarantine it first if recreation
is necessary. The Playground profile is amnesic browser state, not process/VM
isolation from the productive desktop.

## M35 — Thunderbird settings or DKIM/smartcard path fails

```bash
rpm -q thunderbird
sha256sum /usr/lib64/thunderbird/distribution/extensions/dkim_verifier@pl.xpi
python3 -m json.tool /etc/thunderbird/policies/policies.json >/dev/null
```

The DKIM Verifier uses WebExtension storage; old
`extensions.dkim_verifier.*` Gecko prefs are inert. Thunderbird and the
extension's provider-neutral JSDNS default follow the active system/VPN
resolver. Confirm the extension's effective DNS setting after profile startup
if a user changed it.

Thunderbird 152 accepts only its compiled Remote Settings endpoint; do not use
the unsupported `MOZ_REMOTE_SETTINGS_DEVTOOLS` override or diagnose a blank
`services.settings.server` pref as a supported fix. `MailGlue` initializes
Thunderbird's signed `RemoteSecuritySettings` clients, including
`security-state/cert-revocations`: that client downloads, hash-checks and
installs CRLite full filters and deltas. NoID Privacy therefore keeps CRLite
downloads enabled and enforcement at mode 2, alongside OneCRL, OCSP/stapling
and the signed add-on blocklist. Packaged Remote Settings dumps remain startup
and offline fallback data; they are not a substitute for the live signed
refresh path.

If CRLite appears unavailable, first confirm that
`security.remote_settings.crlite_filters.enabled` is `true` and
`security.pki.crlite_mode` is `2`. A newly created profile may not have a
filter immediately because Thunderbird schedules Remote Security Settings as a
best-effort idle task. Until a usable filter is installed, certificate
validation retains the other revocation mechanisms; do not claim CRLite
coverage merely from the preference values.

External GnuPG smartcard support is experimental and covers secret-key signing
and decryption, not public-key encryption/verification. Test both operations
after Thunderbird/GnuPG/token updates.

## M41 — live installer remnants remain

```bash
systemctl status noid-anaconda-cleanup.service --no-pager
journalctl -u noid-anaconda-cleanup.service -b --no-pager
systemctl status noid-anaconda-maintenance.service --no-pager
journalctl -u noid-anaconda-maintenance.service -b --no-pager
getent -s files passwd liveuser || true
sudo getent -s files shadow liveuser || true
getent -s files group liveuser || true
sudo getent -s files gshadow liveuser || true
sudo stat /var/lib/noid-privacy/anaconda-cleanup-security.done \
  /var/lib/noid-privacy/anaconda-cleanup.done
sudo find /home/.noid-liveuser-quarantine \
  /var/spool/mail/.noid-liveuser-quarantine \
  -mindepth 1 -maxdepth 1 -printf '%p\n' 2>/dev/null
```

The short pre-login stage publishes
`anaconda-cleanup-security.done` only after local account/authentication state,
the exact AccountsService remnant, GDM, restricted chronyd and compose-profile
postconditions pass. A failure in that stage intentionally keeps graphical
login gated and retries on the next boot. Once GDM is available, the separate
maintenance unit repairs RPM metadata, removes installer packages through
DNF5, converges package reasons/autoremove and publishes
`anaconda-cleanup.done`. A maintenance failure is visible and retryable but
does not take the already-safe login screen away.

A compose-created NetworkManager profile is archived only when its complete
bytes match the build-recorded digest and its bound interface is absent;
absence from `/sys/class/net` alone is not deletion authority. Use a local
console or rescue environment and the exact journal diagnostic; do not
manually delete users, profiles or packages before identifying the failed
contract. If Anaconda left an exact
`/home/liveuser` or mail remnant, M41 moves it intact to the root-private
same-filesystem quarantine shown above rather than deleting it. Review those
bytes from rescue/root context. Restore or remove a quarantined entry only
after identifying its owner and purpose; an existing quarantine destination
intentionally blocks automatic login rather than overwriting earlier evidence.

## M42 — retention did not prune or pruned an expected baseline

```bash
systemctl list-timers --all | grep -E 'noid-.*prune|noid-auditd-rotate'
journalctl --since today -u 'noid-*-prune.service' --no-pager
systemctl show NetworkManager.service -p ActiveState -p MainPID
systemctl show upower.service -p ActiveState -p MainPID
sudo test ! -e /etc/noid-privacy/disable-nm-history-prune
```

The exact 30-day log contract applies only to sources listed in
`log-retention.md`. M20 separately gives eligible Snapper snapshots a measured
30-day deletion target with explicit active/default and clock-continuity
exceptions. Neither mechanism is secure deletion or covers user/application
data. Restore an exported backup if a deliberately long-lived snapshot was
deleted after becoming eligible.

An active `noid-nm-privacy-prune` timer run intentionally sanitizes legacy
generated keys in exact `.nmconnection` files but does not clear the global
`seen-bssids` / `timestamps` databases while NetworkManager has a main process.
Those databases are RAM-backed and are atomically cleared before the next
ordinary NetworkManager start. Do not treat the documented deferral as a
successful live clear, and do not restart networking casually: it interrupts
the current connection and any VPN. If the pre-start pass failed, inspect:

```bash
sudo systemctl status noid-nm-privacy-prune.service --no-pager
sudo journalctl -u noid-nm-privacy-prune.service \
  -u NetworkManager.service -b --no-pager
sudo stat -Lc '%U:%G:%a:%F' \
  /var/lib/NetworkManager \
  /etc/NetworkManager/system-connections
```

The complete opt-out marker and restore procedure are documented in
[`log-retention.md`](log-retention.md); disabling only the daily timer does not
remove the NetworkManager pre-start boundary.

UPower likewise has no maintained external file-prune API or cooperating lock.
The daily pass therefore defers its `history-*.dat` scope while `upowerd` has a
main process, and the exact old-file prune runs before the next UPower start.
Do not restart UPower merely to force retention; a long bootless session may
honestly exceed the 30-day file-mtime target without a writer race.

## M06 — WireGuard tunnel MTU exceeds the outer link (TLS stalls, NTS-KE fails)

On the Fedora 44 candidate measured here, NetworkManager's
`wireguard.mtu = 0` default materialises as a 1420-byte tunnel MTU. NetworkManager
documents that this default, unlike `wg-quick`, does not derive from the current
routes when the connection activates. On an outer link smaller than 1500 bytes
the tunnel can therefore be oversized, every full-size inner packet can force
outer fragmentation, and a path that drops those fragments silently breaks
large TLS flights.

The symptom does not look like a network fault. Small connections work, DNS
works, plain NTP over UDP works. What fails is the first large TLS handshake:

```
TLS handshake with 192.53.103.108:4460 (ptbtime1.ptb.de) failed : Error in the pull function.
```

Chrony then reports its NTS sources as unreachable, which reads like an outage
at the time-service operator. It is not. An already-running chronyd keeps
synchronising because NTS-KE runs once over TCP and the subsequent
authenticated NTP exchange uses small UDP packets that fit — so the defect is
invisible until a fresh install, a cookie-less restart or a key rotation forces
a new key establishment.

### Confirm it

```bash
noid-network-audit mtu
```

The audit resolves each WireGuard peer endpoint, follows the route to it, reads
the outer link MTU and reports the largest inner MTU that still fits:

```
 - Peer routing evaluated with WireGuard fwmark 0x150c17a6
 - Locally fragmentation-free maximum: 1392 (outer wlp0s20f0u1 MTU 1456, inet endpoint, overhead 60)
ERR: proton0 exceeds the local maximum by 28 bytes
```

The peer route is resolved with the tunnel's own WireGuard fwmark. Without it a
full-tunnel peer (`AllowedIPs 0.0.0.0/0`) resolves back through the tunnel and
the audit would measure the inner link as if it were the outer one; that case is
reported as indeterminate instead of being measured. A route-scoped or
PMTU-cached `mtu` (including the `mtu lock N` form) is treated as a stricter
ceiling than the device MTU, and a peer whose endpoint or route cannot be
resolved fails the audit rather than disappearing behind a healthy second peer.

"Locally" is exact: a passive audit sees this host's links and routes. A smaller
PMTU further along the path cannot be excluded from here.

The maximum is computed, never assumed:

```
IPv4 outer: 20 (IP) + 8 (UDP) + 32 (WireGuard header + Poly1305 tag) = 60
IPv6 outer: 40 (IP) + 8 (UDP) + 32                                   = 80
safe inner = floor((outer MTU - overhead) / 16) * 16
```

The 16-byte floor is required because WireGuard pads the plaintext to a 16-byte
boundary. On a 1456-byte outer link this is why 1396 still fails and 1392
passes: 1396 pads to 1408, which no longer fits.

### Correct it

Images from v1.5 onward correct this condition at the activation boundary. The
awaited `pre-up.d/45-noid-wireguard-mtu` hook evaluates the activating
WireGuard interface before NetworkManager completes activation. Its
event-only `no-wait.d` twin evaluates all active WireGuard interfaces again
after physical-link, lease, reapply and connectivity changes. Both call the
same root-owned helper and stay out of NetworkManager's serialized ordinary
dispatcher queue.

The helper applies the calculation above to every peer and uses the strictest
successfully resolved outer route. It is fail-closed with respect to mutation:
one unresolved endpoint, unreadable route/link state or an unsafe IPv6 result
leaves the live MTU unchanged and emits a warning. It never raises an existing
smaller MTU. A successful correction changes only the active kernel link; it
does not edit, save, reconnect or recreate the owning NetworkManager,
provider, `wg-quick` or systemd-networkd profile. This is provider-neutral and
avoids the lifecycle race caused by the retired profile-mutating dispatchers.

The independent audit remains the supported confirmation and manual recovery
path. It prints the exact immediate command and deliberately does not run it:

```bash
sudo ip link set dev proton0 mtu 1392    # value from the audit, not a constant
```

If the audit still reports an oversized interface, the automatic live
reconciler either could not complete with the evidence available at its event
or the route/interface state changed afterward. Read its bounded diagnostics
before applying the one-off command:

```bash
journalctl -b -t noid-wireguard-mtu --no-pager
```

If the tunnel has a global/ULA IPv6 address or IPv6 AllowedIP and the computed
maximum is below 1280, the audit prints no command at all. RFC 8200 section 5
sets 1280 as the minimum IPv6 link MTU, so lowering the tunnel would break IPv6
instead of fixing the stall; the audit reports that no safe correction exists
on that outer path. Link-local state alone is reported but does not block an
otherwise IPv4-only correction, because NetworkManager commonly creates it on
WireGuard links without usable IPv6. An unreadable IPv6 state is fail-closed
and prints no command.

The command lowers one live interface and persists nothing. A provider may
replace the interface on reconnect; the awaited activation hook then computes
the new live value again. NoID Privacy still does not rewrite provider
profiles automatically: two earlier dispatchers that mutated Proton profiles
and WireGuard peers were retired (M06 STEP 5b/5c) because they raced the
provider's own lifecycle and overrode intent that cannot be observed at
runtime. The current helper owns only a lower-only kernel-link postcondition.

The durable guidance is ownership-specific and remains read-only:

- a persistent NetworkManager WireGuard profile gets an exact
  `nmcli connection modify uuid ... wireguard.mtu <computed>` command;
- an UNSAVED, NM-generated, volatile or external NetworkManager profile is
  identified as provider-owned, and the audit directs the user to the VPN
  application's own MTU setting instead of turning its runtime object into a
  stale disk profile;
- a regular canonical `/etc/wireguard/<interface>.conf` gets the exact
  `MTU = <computed>` line for its `[Interface]` section, but the key-bearing
  file is never opened or edited by the audit;
- unknown ownership stays unknown and is handed back to the application or
  service that creates the interface.

A standard 1500-byte outer link needs no change at all: 1440 is safe there, so
the 1420 default fits.

### Do not

- Do not hardcode 1392 in a profile or local override. It is correct only for a
  1456-byte outer link; the image helper computes the current value.
- Do not clamp MSS via `tcp option maxseg size set rt mtu` as the sole remedy:
  the route already reports the oversized 1420, so the derived MSS stays wrong.
- Do not set `net.ipv4.tcp_mtu_probing=1` and call it fixed. Mode 1 only starts
  probing after a blackhole is detected, and it does not reliably prevent the
  first oversized server flight, which is the direction that fails here.
