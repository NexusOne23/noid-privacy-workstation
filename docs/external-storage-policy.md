# External-storage mount policy

## Decision

NoID Privacy applies a UDisks `noexec` default to dynamically mounted USB
filesystems and recognized SD media. It does not add blanket `sync`, change
`queue/write_cache`, or impose a block-device writeback/BDI limit. Safe eject
or UDisks power-off remains the durability contract before physical removal.

For NTFS within that same external-media scope, the udev rule sets
`UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS=ntfs3,ntfs`. This prefers Fedora's signed,
in-tree ntfs3 driver and retains ntfs-3g as fallback. It does not replace or
own the administrator's global `/etc/udisks2/mount_options.conf`.

The policy is a dynamic-mount default, not an execution authorization
boundary. `noexec` blocks direct execution from the mount, but an interpreter
can still read a script, and an explicit UDisks caller can request the allowed
`exec` option. `/etc/fstab` and direct administrator mounts are separate.

Canonical implementation: Module 27's
`/etc/udev/rules.d/99-noid-external-storage-mount.rules`. Module 27 and Module
99 remove both retired predecessors, `99-noid-usb-sync-mount.rules` and
`99-noid-usb-write-through.rules`.

## Why blanket sync was removed

`mount(8)` defines `sync` as synchronous filesystem I/O and warns that it may
shorten the life of media with limited write cycles. The lifetime effect is
device-specific, so NoID Privacy does not present wear as certain. The
measured throughput and latency cost is the decisive result.

On 2026-08-03, the exact authorized 32 GB-class SanDisk USB test device was
partitioned into 6 GiB VFAT, exFAT, NTFS and ext4 filesystems. Each filesystem
was mounted through UDisks first with the old `sync,noexec` rule and then with
the candidate `noexec` rule. The bulk probe wrote 64 MiB with final fsync; the
small-file probe wrote 200 files and completed a filesystem sync.

| Filesystem | 64 MiB + fsync, old sync | 64 MiB + fsync, candidate | 200 files, old sync | 200 files, candidate |
| --- | ---: | ---: | ---: | ---: |
| VFAT | 136.035 s / 0.47 MiB/s | 2.434 s / 26.29 MiB/s | 34.909 s | 24.396 s |
| exFAT | 4.800 s / 13.33 MiB/s | 1.908 s / 33.54 MiB/s | 2.099 s | 0.351 s |
| NTFS | 2.250 s / 28.44 MiB/s | 2.285 s / 28.01 MiB/s | 2.704 s | 0.824 s |
| ext4 | 2.337 s / 27.39 MiB/s | 2.435 s / 26.28 MiB/s | 12.116 s | 0.499 s |

These values characterize one device and host, not every flash controller.
They are sufficient to reject a distro-wide option whose cost can be extreme
and whose durability benefit cannot make active removal universally safe.

The candidate mounts all contained `noexec,nodev,nosuid`, contained no
`sync`, and retained UDisks' filesystem-specific `flush` default on VFAT.
Direct execution failed with status 126; interpreter execution succeeded. An
explicit UDisks `exec` request succeeded on all four filesystems, confirming
the documented default boundary. The executable probe uses a `.com` suffix so
UDisks' VFAT `showexec` default retains its execute bits; without that positive
control, VFAT could reject the file because of its emulated mode before
mount-level `noexec` was exercised.

After UDisks power-off and a physical replug, read-only `fsck.vfat`,
`fsck.exfat`, `ntfsfix --no-action` and `e2fsck -f -n` checks passed before
mounting. Every baseline and candidate payload hash matched after cold
remount. One exFAT unmount initially returned busy, had no observable holder,
and succeeded after filesystem sync and udev settlement; it did not reproduce
and is recorded as an observation rather than a confirmed defect.

A repeat with the corrected `.com` positive control passed the default and
explicit-override boundary on all four filesystems and passed the same
read-only filesystem checks. UDisks reported successful power-off, but its
daemon log also recorded that this exact device rejected `SYNCHRONIZE CACHE`;
it ignored that command failure, then successfully sent `START STOP UNIT` and
removed the USB device through sysfs. The kernel had reported the device write
cache disabled and FUA unsupported. This proves that the supported workflow
completed on this unit, not that every bridge implements a hardware flush; it
reinforces rather than removes the documented active-removal limit.

## NTFS driver finding

The Fedora 44 validation host used UDisks 2.11.1-2.fc44, ntfs-3g
2026.2.25-1.fc44 and the Fedora kernel 7.1.5-201.fc44. UDisks with Fedora's
packaged `ntfs,ntfs3` order failed reproducibly to mount a clean NTFS volume
read/write through ntfs-3g. No process holder or SELinux denial was present;
ntfs-3g read-only worked. Direct and UDisks ntfs3 read/write mounts succeeded.

The signed Fedora UDisks source package explains the divergence: upstream
2.11.1 uses `ntfs_drivers=ntfs3,ntfs`, while Fedora's spec rewrites it to
`ntfs,ntfs3`. Fedora permits this distributor choice, and UDisks documents
driver priorities and udev overrides. The exact udev-scoped property was then
validated without any active `/etc/udisks2/mount_options.conf`: UDisks mounted
the external volume as ntfs3, completed write/fsync/hash/unmount, and retained
`noexec,nodev,nosuid`.

The Fedora testing ntfs-3g 2026.2.25-2 build was also extracted and tried. Its
new `ntfs-3g-mount` symlink did not fix the read/write failure, so NoID Privacy
does not claim that update resolves the observed problem.

This is deliberately scoped to external USB/recognized-SD NTFS. Internal or
administrator-managed NTFS retains Fedora policy, and ntfs-3g remains a
fallback if ntfs3 is unavailable.

## Rejected alternatives

- `queue/write_cache="write through"`: kernel documentation says writing this
  sysfs file changes the kernel's view, not device state, and can suppress
  cache flushes. The old rule was unsafe and remains absent.
- Per-device BDI dirty-byte limits: BDI attributes exist only on the whole
  disk on the tested topology, while filesystem identity is attached to
  partition events. A disk-scoped value would also conflate cheap flash with
  high-performance USB NVMe and depend on host memory policy. Throttling is
  not a durability guarantee.
- `commit=1` for ext4: it is filesystem-specific and primarily bounds journal
  commit behavior; it does not establish a uniform contract for overwritten
  dirty data, VFAT, exFAT or NTFS and does not control the device cache.
- A NoID Privacy-specific safe-removal toggle: UDisks/GNOME already provides the
  maintained eject/power-off workflow, while administrators can use stable
  per-device UDisks configuration where a special mount policy is required.

## Platform comparison and limits

Windows defaults modern external media to Quick removal, with write caching
disabled unless the user selects Better performance, but Microsoft still
documents safe removal. macOS tells users to eject storage before disconnect.
Fedora/UDisks uses delayed writes plus filesystem-specific defaults such as
VFAT `flush`. These are different implementations, not proof that active yank
is safe on every bridge, filesystem or device cache.

NoID Privacy therefore follows Fedora's maintained UDisks mechanism, removes
the universally expensive `sync` addition, preserves filesystem defaults, and
makes power-off/eject explicit. No generic Linux option can guarantee safety
when a process is still writing, hardware lies about cache completion, power
fails, or a device is physically removed mid-command.

## Regression and release evidence

The source test extracts the exact udev payload and passes it through
`udevadm verify`. Compose and finalization check root ownership, mode, exact
USB/SD/NTFS properties, absence of both retired rules, and absence of active
`sync`, BDI and `queue/write_cache` mutations.

The mandatory QEMU/KVM lifecycle gate uses one removable USB GPT disk with
VFAT/exFAT/NTFS/ext4 partitions, a fixed (`removable=0`) USB ext4 disk and a
native SD ext4 disk. Across `live`, `fresh-install` and `reboot`, it checks
actual mount flags and drivers, the noexec/interpreter/explicit-exec boundary,
VFAT `flush`, whole-device cache-view invariance, fsynced cold hashes, UDisks
power-off for USB, and clean SD unmount. Exact fixture construction and the
rest of the release matrix are in [release-process.md](release-process.md);
the trust-boundary rationale is in [test-strategy.md](test-strategy.md).

## Primary sources

- [UDisks configurable mount options](https://storaged.org/doc/udisks2-api/latest/mount_options.html)
- [UDisks Drive.PowerOff](https://storaged.org/doc/udisks2-api/latest/gdbus-org.freedesktop.UDisks2.Drive.html)
- [util-linux mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
- [Linux kernel queue sysfs documentation](https://docs.kernel.org/5.10/block/queue-sysfs.html)
- [UDisks 2.11.1 builtin mount options](https://raw.githubusercontent.com/storaged-project/udisks/udisks-2.11.1/data/builtin_mount_options.conf)
- [UDisks 2.11.1 udev override implementation](https://raw.githubusercontent.com/storaged-project/udisks/udisks-2.11.1/src/udiskslinuxmountoptions.c)
- [Fedora 44 UDisks spec](https://src.fedoraproject.org/rpms/udisks2/raw/f44/f/udisks2.spec)
- [Microsoft external-storage removal policy](https://learn.microsoft.com/en-us/windows/client-management/client-tools/change-default-removal-policy-external-storage-media)
- [Microsoft safe removal guidance](https://support.microsoft.com/en-us/windows/safely-remove-hardware-in-windows-1ee6677d-4e6c-4359-efca-fd44b9cec369)
- [Apple external-storage guidance](https://support.apple.com/guide/mac-help/connect-storage-devices-mac-mchl027f1d66/mac)
