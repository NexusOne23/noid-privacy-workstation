# Disk Encryption & Mount Hardening — NoID Privacy

## Encryption

NoID Privacy relies on Fedora's Anaconda installer for disk encryption.
During installation, choose **"Encrypt my data"** in the storage dialog.
The current release expects the following installed layout when encryption is
selected, but the actual container, cipher and active keyslot KDF are installed
state and must be verified after installation:

- **LUKS2**; the expected active passphrase keyslot uses **Argon2id**
  (memory-hard), but this is not inferable from `lsblk` alone
- **AES-XTS-plain64** with a 512-bit combined key (two AES-256 keys; this
  must not be described as 512-bit security strength)
- **btrfs** filesystem with subvolumes for `/` and `/home`
- Separate `/boot` (ext4) and `/boot/efi` (FAT32) outside encryption

### Verifying Encryption Parameters

Confirm Anaconda enabled the expected LUKS2 parameters:

```bash
# Find your LUKS partition first
lsblk -f | grep crypto_LUKS

# Dump the LUKS header (replace nvme0n1p3 with your partition)
sudo cryptsetup luksDump /dev/nvme0n1p3 | grep -E 'Version:|Cipher|PBKDF:|Memory'
```

The exact values must be read from the installed keyslot. A typical compliant
result contains:
```
Version:        2
Cipher:         aes-xts-plain64
PBKDF:          argon2id
Memory:         <installed value in KiB>
```

If an active passphrase keyslot shows `pbkdf2` instead of `argon2id`, do not
silently relabel it compliant. A conversion changes a disk-unlock boundary:
retain an independently stored header backup and tested recovery path, identify
the exact keyslot, and follow the maintained `cryptsetup-luksConvertKey(8)`
procedure for the installed version. A representative command shape is:

```bash
# Create and verify an offline header backup before any key operation
noid-luks-backup.sh

# Convert the existing keyslot to argon2id
slot=0  # replace with the exact active passphrase slot from luksDump
sudo cryptsetup luksConvertKey /dev/nvme0n1p3 --key-slot "$slot" --pbkdf argon2id \
    --pbkdf-memory 1048576 --pbkdf-parallel 4
```

### Optional — review or raise the Argon2 memory cost

Cryptsetup benchmarks Argon2 parameters against the available machine and its
configured time/memory limits; this image does not enforce a universal
Anaconda value. RFC 9106's first general recommendation uses 2 GiB, while its
memory-constrained recommendation uses 64 MiB. Its application examples also
include other profiles; these are not proof that one value fits every boot
environment.

If the early-boot environment reliably has enough memory, 2 GiB can raise the
cost per guess. Measure unlock behavior and retain a tested header backup and
recovery path:

```bash
# Create and verify an offline header backup first
noid-luks-backup.sh

# Upgrade one exact keyslot to Argon2id with a 2 GiB memory request
slot=0  # replace with the exact active passphrase slot from luksDump
sudo cryptsetup luksConvertKey /dev/nvme0n1p3 \
    --key-slot "$slot" --pbkdf argon2id --pbkdf-memory 2097152
```

Do not blindly select a “maximum”: cryptsetup may reduce a requested memory cap
after benchmarking or because of available memory, and excessive early-boot
requirements can make recovery harder. Passphrase entropy remains critical
regardless of the memory figure.

**Verify after upgrade**:
```bash
sudo cryptsetup luksDump /dev/nvme0n1p3 | grep Memory
# Record the observed value; do not infer it from the requested cap.
```

### TPM2 Auto-Unlock — not enrolled or supported automatically

Modern Linux systems support TPM2-bound LUKS unlock via
`systemd-cryptenroll --tpm2-device=auto`, allowing password-less boot.

NoID Privacy **deliberately does NOT enroll TPM2 by default** for three reasons aligned
with the privacy-image threat model:

1. **Hardware binding** — TPM2-bound LUKS keys are tied to specific motherboard
   firmware state. If the motherboard fails or you migrate the drive to a
   different machine, you cannot decrypt the drive without a backup recovery
   passphrase. For privacy-conscious users, this trades hardware-failure
   recoverability for unlock convenience.
2. **Unattended-unlock boundary** — a bare TPM unlock can release a volume key
   without user presence unless it is combined with an appropriate PIN and
   measured/signed PCR policy. Passphrase-only unlock avoids unattended key
   release, but does **not** eliminate evil-maid attacks: a compromised boot
   chain or physical input-capture device can target the entered passphrase.
3. **Supply-chain trust** — TPM2 unlock requires trusting the TPM firmware,
   the platform vendor's BIOS implementation, and the Secure Boot chain
   (cross-ref Module 01 SecureBoot + Module 15 BootGuard). Privacy-image
   philosophy: minimize required trust assertions.

If you choose TPM2 unlock, follow the current Fedora/systemd documentation for
the exact platform and design a PCR policy, user-presence/PIN requirement,
recovery key and update/recovery test. NoID Privacy intentionally provides no generic
copy-paste enrollment command because a weak or unmeasured enrollment would
create a false security boundary.

### LUKS Header Backup (CRITICAL)

LUKS2 keeps redundant metadata, but damage to both metadata areas or required
keyslots can make the volume inaccessible. Create and test an offline header
backup immediately after installation.

#### Easy path — use the opt-in helper

NoID Privacy ships `noid-luks-backup.sh` which auto-detects your LUKS partition(s),
auto-detects mounted removable media, and wraps `cryptsetup luksHeaderBackup`
with a private staging directory, structural `luksDump` check, SHA-256
post-backup hash, durable file/directory sync, and explicit reminders to copy
to a second stick in a different physical location. An interrupted transaction
cleans its private staging directory; a fully published and verified file is
never deleted merely because the later evidence-log step failed.

The automatic path intentionally fails closed unless the target filesystem can
enforce a private `root:root` mode-0700 staging directory. Use a filesystem with
per-file POSIX ownership and modes, such as ext4, XFS or Btrfs, directly or
inside a LUKS container. Typical FAT32/exFAT desktop mounts cannot satisfy this
contract and are rejected. Reformatting a device erases its contents; copy any
existing data elsewhere first.

```bash
noid-luks-backup.sh                   # interactive backup
noid-luks-backup.sh --list-existing   # find backups on mounted media
noid-luks-backup.sh --verify FILE     # sanity-check a backup file
```

This is also available as "Back up LUKS header" in the first-boot
welcome menu (`noid-welcome.sh --again`).

The helper proves that cryptsetup produced a structurally parseable file with
the expected ownership, mode and hash, and that the mounted filesystem accepted
the synchronization requests. It does not perform a destructive header restore
or prove that removable-media hardware will never fail. Keep two copies, use
the desktop's safe-remove action, and periodically repeat `--verify`.

#### Manual walkthrough

If you prefer explicit control, use a POSIX-permissions-capable encrypted
external filesystem. If you enroll a recovery key, do that **before** the
header backup so the backup actually contains that keyslot:

```bash
# 1. Find your LUKS partition
lsblk -f | grep crypto_LUKS
# Example output: nvme0n1p3  crypto_LUKS  2  <uuid>

# 2. Optional: enroll and record a recovery key (this changes the header)
sudo systemd-cryptenroll /dev/nvme0n1p3 --recovery-key

# 3. Back up the resulting header to an EXTERNAL encrypted/POSIX USB filesystem
backup="/run/media/$USER/USB_LABEL/luks-header-$(date -u +%Y%m%dT%H%M%SZ).bin"
sudo cryptsetup luksHeaderBackup /dev/nvme0n1p3 --header-backup-file "$backup"
sudo chown "$(id -u):$(id -g)" "$backup"
chmod 0600 "$backup"
cryptsetup luksDump "$backup" >/dev/null
sha256sum "$backup"
sync "$backup"
sync "$(dirname -- "$backup")"

# 4. Copy the .bin file to a SECOND USB stick, stored in a DIFFERENT
#    physical location (friend's house, bank safe, parents' place).
#    Two copies, two places.
```

**Store the backup offline** — USB stick in a safe, separate location.
The header backup + recovery key together can decrypt the drive even if
you forget your passphrase. Never save the header on the same encrypted
disk it protects — that defeats the purpose.

A header backup plus any passphrase valid when that backup was created remains
able to decrypt the data even if that passphrase is later changed or removed
from the live header. Protect or securely retire old backups accordingly.

### Changing LUKS Passphrase

```bash
# Add a new passphrase (keeps old one active)
sudo cryptsetup luksAddKey /dev/nvme0n1p3

# Remove old passphrase (after verifying new one works)
sudo cryptsetup luksRemoveKey /dev/nvme0n1p3
```

Back up the header again after every keyslot, token, recovery-key or PBKDF
change. Do not remove the last independently tested unlock method.

### Additional drives (secondary SSD/HDD)

If you have additional drives beyond the OS installation drive (secondary
SSD, HDD for data, external NVMe), **encrypt them too**. Unencrypted
secondary drives are a common blind spot: anyone with physical access or
a recovery boot can read them unprotected.

```bash
# Replace nvme1n1 with your actual device (CHECK lsblk FIRST — this ERASES all data!)
sudo cryptsetup luksFormat --type luks2 \
    --cipher aes-xts-plain64 \
    --key-size 512 \
    --pbkdf argon2id \
    /dev/nvme1n1

# Open and create a single Btrfs filesystem
sudo cryptsetup open /dev/nvme1n1 luks-data
sudo mkfs.btrfs -L data /dev/mapper/luks-data
sudo install -d -m 0755 /mnt/data

# Auto-unlock on boot (requires separate passphrase OR keyfile on OS drive):
# sudo install -d -m 0700 -o root -g root /etc/luks-keys
# sudo dd if=/dev/urandom of=/etc/luks-keys/data.key bs=64 count=1 status=none conv=fsync
# sudo chmod 400 /etc/luks-keys/data.key
# sudo cryptsetup luksAddKey /dev/nvme1n1 /etc/luks-keys/data.key
# echo "luks-data  UUID=$(sudo blkid -s UUID -o value /dev/nvme1n1)  /etc/luks-keys/data.key  discard,nofail" | sudo tee -a /etc/crypttab
# echo "/dev/mapper/luks-data  /mnt/data  btrfs  nosuid,nodev,noexec,nodiscard,nofail,x-systemd.device-timeout=10s  0 0" | sudo tee -a /etc/fstab
```

Review `/etc/crypttab` and `/etc/fstab` first and add exactly one entry to each;
blindly appending a duplicate makes boot behavior ambiguous. A keyfile on the
OS drive couples the secondary drive's confidentiality to successful unlock of
the OS drive. External drives that travel should use a long independent
passphrase instead. Back up the header after adding the key.
For a drive that may be absent, `nofail` must be present in both entries; the
fstab device timeout also bounds the wait for a missing mapper.

## Mount Hardening

NoID Privacy applies these mount options at first boot:

| Mount | Options | Why / Deliberate omissions |
|-------|---------|-----|
| `/tmp` | nosuid,nodev,**noexec**,size=4G | Classic exploit payload target |
| `/dev/shm` | nosuid,nodev,**noexec** | Exploit fallback when `/tmp` is blocked; modern Electron/V8 handles noexec via `mprotect` fallback |
| `/var` | nosuid,nodev | DISA STIG RHEL 9 V-257869 requires `nodev`; `nosuid` is NoID Privacy defense in depth. Self-bind-mount. **noexec deliberately omitted** — breaks RPM scriptlets, dracut, systemd units, Ansible. Ordinary descendants inherit the flags; every nested mount remains its own policy boundary. |
| `/var/tmp` | nosuid,nodev | Persistent sibling of `/tmp`. **noexec deliberately omitted** for the package/build/install compatibility baseline. The historical dracut failure RHBZ#2274246 was fixed in dracut 102 and is not a current justification. Self-bind-mount when no existing entry; redundant given `/var` above but kept as defense-in-depth. |
| `/` | nodiscard | Disables Btrfs continuous async discard; weekly `fstrim.timer` batches disclosure. |
| `/home` | nosuid,nodev,nodiscard | **noexec deliberately omitted** — breaks Flatpak user installs, AppImages, `~/.local/bin`, Steam |
| `/boot` | nosuid,nodev,**noexec** | Kernel + initramfs — no legitimate SUID/device/exec needs |
| `/boot/efi` | nosuid,nodev,**noexec** | VFAT ESP defense-in-depth (VFAT ignores Unix perms, but kernel still enforces mount flags) |

The matrix applies to targets present as distinct `/etc/fstab` entries. M22
creates entries for `/tmp`, `/dev/shm`, `/var` and `/var/tmp`; a layout without
a separate `/home` or `/boot` inherits its parent filesystem's mount flags and
cannot receive independent `nosuid`, `nodev` or `noexec` flags there.
`/boot/efi` is not applicable on a system without an ESP entry.

These options are the project's compatibility baseline, but no mount policy can
promise compatibility with every application. If an application requires
executing from `/tmp` (rare), you can remount temporarily:

```bash
sudo mount -o remount,exec /tmp
# ... run your application ...
sudo mount -o remount,noexec /tmp
```

### Verifying Mount Hardening

Confirm the firstboot service applied the hardening:

```bash
for mp in / /tmp /dev/shm /var /var/tmp /home /boot /boot/efi; do
    printf '%-12s %s\n' "$mp" "$(findmnt -n "$mp" -o OPTIONS 2>/dev/null \
        | grep -oE 'nosuid|nodev|noexec' | tr '\n' ' ')"
done
```

Expected for each target present as a distinct fstab mount:
- `/tmp`, `/dev/shm`, `/boot`, `/boot/efi` → `nosuid nodev noexec`
- `/` → continuous discard disabled by policy (the kernel often omits the
  negative/default `nodiscard` token from `findmnt` output)
- `/var`, `/var/tmp` → `nosuid nodev` (noexec deliberately omitted)
- `/home` → `nosuid nodev`, plus the same continuous-discard policy as `/`

If any option is missing and the system has been booted at least once,
inspect the firstboot log:

```bash
sudo journalctl -u noid-mount-hardening.service --no-pager
```

To re-run the hardening manually (idempotent):

```bash
sudo rm -f /var/lib/noid-privacy/.mount-hardening-done
sudo systemctl restart noid-mount-hardening.service
```

## Btrfs Scrub

`btrfs-scrub.timer` starts a checksum-validation pass monthly with a native
128 MiB/s per-device limit. `Nice=19` and idle I/O priority remain additional
best-effort hints; the Btrfs limit is the dependable cap on schedulers that do
not implement idle priority.

The service has a native `findmnt` execution condition and starts the helper
only when `/` is Btrfs. On ext4 or XFS roots, a scheduled activation is skipped
without entering a failed or restart state; Btrfs scrub is not applicable.

Kernel 6.19 and newer can cancel a scrub during suspend, hibernate, filesystem
freeze or signal delivery. The service makes bounded retries and resumes saved
progress. Because Fedora 44's `btrfs scrub resume` has no `--limit` option, the
wrapper snapshots every existing per-device limit, applies 128 MiB/s during the
resume and restores the exact prior values on success, failure or signal. Exit
status 3 (uncorrectable errors) is left failed for explicit review instead of
being retried automatically. Before changing a limit, the wrapper atomically
records every original value in systemd's root-private
`/var/lib/noid-btrfs-scrub` state directory. If restoration fails, the bounded
service restart performs recovery only from that saved transaction; it neither
treats a leaked 128 MiB/s value as the original nor starts a duplicate scrub.
The transaction is removed only after every original value is restored.

A scrub detects checksum, metadata-header, superblock and read errors. It can
repair damage only when Btrfs has another verified copy. On the reference
single-device layout, metadata uses DUP and can normally be repaired from its
second copy; data uses `single`, so damaged data is detected but has no
filesystem replica to copy from. NOCOW/NODATASUM file data is outside the data
checksum guarantee. Scrub is not `fsck` and not a backup.

```bash
systemctl status btrfs-scrub.timer
sudo btrfs scrub status /
sudo journalctl -u btrfs-scrub.service --no-pager
```

## SSD TRIM / Discard

NoID Privacy explicitly mounts the Btrfs root and home subvolumes with `nodiscard` and
uses Fedora's `fstrim.timer` for a weekly batch. This avoids Btrfs' Linux 6.2+
default `discard=async`, which would otherwise emit discard requests as freed
extents accumulate.

- **Periodic TRIM** (NoID Privacy default): Batched weekly, reducing the timing detail
  exposed compared with continuous discard
- **Continuous discard**: Real-time block-free notification to SSD,
  exposing finer-grained filesystem allocation patterns through the LUKS layer

The dm-crypt mapping intentionally permits discard pass-through: without that
gate the weekly `fstrim` request could not reach the SSD. The permission itself
does not issue discard requests; `nodiscard` prevents Btrfs from generating
continuous requests, while the timer is the sole normal generator.

To verify all three layers:

```bash
findmnt -n -o OPTIONS /
findmnt -n -o OPTIONS /home
root_crypt_source=$(findmnt -n -o SOURCE / | sed -E 's|\[.*\]$||')
sudo cryptsetup status "${root_crypt_source#/dev/mapper/}"
systemctl status fstrim.timer
```

The two `findmnt` results must contain neither `discard` nor any
`discard=*` mode. Linux normally omits the negative/default `nodiscard` token
from the effective mount-option display; its absence is not a failure. The
crypt mapping is expected to show discard permission, and the timer is expected
to be enabled for the weekly batch.

For maximum paranoia (at cost of SSD performance over time):

```bash
sudo systemctl disable --now fstrim.timer
```

## Recommended Partition Layout

The table records the Fedora 44 Workstation automatic layout observed on the
reference installation. Firmware, storage topology and future installer
policy can change it; review Anaconda's proposed layout before installation
and verify the installed result with `lsblk`.

| Partition | Size | Type | Purpose |
|-----------|------|------|---------|
| /boot/efi | 600 MB | FAT32 | UEFI Secure Boot chain |
| /boot | 2 GiB | ext4 | Kernels, initramfs, BLS entries |
| / (LUKS) | Rest | btrfs | Encrypted root + home (subvolumes) |

**No disk-backed swap by default** — Fedora uses zram (compressed RAM swap).
It keeps this swap state in volatile memory, but it cannot retain a hibernation
image across power-off. Hibernate, hybrid sleep and suspend-then-hibernate are
therefore unavailable in the default layout. Enabling them requires a
deliberately provisioned encrypted disk-backed swap/resume target, verified
initramfs configuration and real power-cycle testing; zram alone is not enough.

**btrfs is required** for the snapshot-rollback feature (Module 20).
If you choose ext4 or XFS, snapshot-based rollback will not be available.

## Backup Strategy

**Important: Snapper snapshots are NOT a backup.** Snapper (Module 20)
can protect captured root-subvolume state against some misconfiguration and bad
updates, but does not include the separate `/home` subvolume. Snapshots live on the SAME encrypted volume
as the original data. They do not protect against:

- Physical drive failure
- LUKS header corruption
- Ransomware that encrypts all accessible data (including snapshots)
- Device theft or loss

For real data safety you need **off-device backups**.

### Recommended backup scope

| Target | Location | Frequency | Tool |
|--------|----------|-----------|------|
| `/home/<user>/` (personal files) | External encrypted USB/NVMe | Weekly (manual) | `rsync` / `borg` / `restic` |
| `/etc/` (system config) | External encrypted drive | After any major config change | `rsync -aAX --numeric-ids` |
| **LUKS header** of OS + data drives | **USB stick (physical safe)** | After every keyslot/token/PBKDF change | `noid-luks-backup.sh` |
| **Recovery key / passphrase** | **Paper in safe + USB stick (off-site)** | Once, on setup | Write down or `systemd-cryptenroll --recovery-key` output |

### Minimum viable (2 commands)

If you only do one thing, do these two commands after finishing setup:

```bash
# 1. Create a durably synchronized header backup on external media (CRITICAL)
noid-luks-backup.sh

# 2. Back up your home directory (run weekly)
rsync -aAX --numeric-ids \
    "/home/$USER/" /mnt/encrypted-usb/home-backup/
```

### Better: encrypted deduplicating backups (borg)

For real backup hygiene, install Fedora's signed `borgbackup` package. Run the
example manually, or explicitly opt into a schedule after deciding when the
external drive will be attached. These commands intentionally use the Borg 1.4
CLI shipped by Fedora 44; Borg 2 uses a different command syntax.

```bash
sudo dnf install borgbackup

# One-time init on external drive
borg init --encryption=repokey-blake2 /mnt/external/borg-repo

# Export the repository key to separate protected media and retain its passphrase
borg key export /mnt/external/borg-repo /mnt/second-protected-media/borg-repo.key

# Weekly snapshot
borg create --stats --compression zstd,3 \
    /mnt/external/borg-repo::$(date +%Y-%m-%d) \
    "/home/$USER"
```

The normal user cannot read every root-owned file below `/etc`; back up system
configuration separately with the root-owned `rsync -aAX --numeric-ids`
workflow from the table instead of silently accepting a partial Borg archive.

### Backup verification

An untested backup is not a dependable recovery plan. Quarterly, restore a
sample and periodically test a full recovery in an isolated destination. One
successful file restore is evidence for that file, not proof of every archive.

```bash
# Verify repository metadata and all stored data (can take a long time)
borg check --verify-data /mnt/external/borg-repo

# Pick a backup archive
borg list /mnt/external/borg-repo

# Borg extracts relative to the current directory; use a fresh private target.
archive=2026-04-15  # replace with an exact archive name from `borg list`
restore_dir=$(mktemp -d /var/tmp/noid-borg-test-restore.XXXXXX)
(cd "$restore_dir" && \
    borg extract "/mnt/external/borg-repo::${archive}" \
        "home/$USER/Documents/important.pdf")
# After inspecting/copying the restored sample:
rm -rf -- "$restore_dir"
```

`/var/tmp` is inside the root state covered by NoID Privacy's Snapper layout. For a
sensitive or full restore, use a dedicated encrypted external destination so a
temporary plaintext copy is not retained by a root snapshot.

### Off-site copy

A backup on an external drive sitting next to your computer protects against
drive failure and ransomware, but NOT against theft, fire, or flood. For
full protection, keep a second copy at a different physical location (family
member's place, bank safe deposit box, or a client-side-encrypted remote
target). A remote provider can still observe account, timing, size and network
metadata even when file contents are encrypted.

## Primary references

- [current cryptsetup manual pages and source](https://gitlab.com/cryptsetup/cryptsetup/-/tree/main/man)
- [cryptsetup FAQ — header backup and recovery](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/FAQ.md)
- [RFC 9106 — Argon2](https://www.rfc-editor.org/rfc/rfc9106.html)
- [systemd-cryptenroll](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html)
- [Fedora Btrfs installer layout](https://fedoraproject.org/wiki/Btrfs)
- [Btrfs mount options and discard](https://btrfs.readthedocs.io/en/latest/ch-mount-options.html)
- [Btrfs scrub semantics](https://btrfs.readthedocs.io/en/latest/btrfs-scrub.html)
- [GNU `sync` durability contract](https://www.gnu.org/software/coreutils/manual/html_node/sync-invocation.html)
- [DISA STIG document library](https://public.cyber.mil/stigs/downloads/)
- [BorgBackup documentation](https://borgbackup.readthedocs.io/en/stable/)
