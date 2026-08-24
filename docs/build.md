# Build Guide — NoID Privacy Workstation

## Requirements

- **Build host**: Fedora 44 x86_64 with the listed RPM tools available. The
  staging gate accepts exactly `lorax-44.6-1.fc44.x86_64` and rejects a
  different Lorax NEVRA or payload digest; keep this requirement synchronized
  with `scripts/stage-lorax-overrides.sh`. Other releases and immutable-host
  toolboxes are not claimed as tested.
- **Privilege**: `sudo` required (livemedia-creator chroots build env).
- **Base install ISO**: the default (KVM) build path needs a Fedora 44
  installer ISO to boot the build VM — `scripts/build-iso.sh` does **not**
  download it. Place the exact reviewed
  `Fedora-Server-netinst-x86_64-44-1.7.iso` into `/var/tmp/` or
  `~/Downloads/` before building (get it from the Fedora Project,
  <https://fedoraproject.org>). If it is missing the build aborts with a
  clear message naming the primary `/var/tmp` search path. The `--no-virt`
  path needs no install ISO, but is restricted to an SELinux-Enforcing
  virtualized build host that was itself booted with UEFI firmware.
- **Pinned audit payload**: the wrapper downloads `noid-privacy-linux.sh`
  from the full, immutable public Git commit recorded in Module 40. It then
  independently enforces the reviewed version, byte count, SHA-256 and Bash
  syntax before the file enters build staging. For a controlled offline or CI
  build, `NOID_AUDIT_SRC` may name a regular, non-symlink file; that override
  must produce the exact same reviewed bytes or the build aborts.
- **Disk space**: at least 12 GiB free in the selected disk-backed staging
  parent. The canonical wrapper stages every host-side intermediate below one
  private `/var/tmp/noid-iso-stage.*` directory by default and rejects
  `tmpfs`/`ramfs` parents. Also budget roughly 16 GiB in the repository
  filesystem for each retained KVM candidate at the current guest-disk size:
  `--keep-image` preserves the approximately 12.5 GiB `lmc-disk-*.img` beside
  the ISO and private evidence. Actual ISO/evidence size varies, and no prior
  candidate is pruned automatically.
- **RAM/CPU**: the default KVM compose assigns 16 GiB and 8 vCPU to its build
  guest and needs additional memory for the host. `QEMU_RAM` and
  `QEMU_VCPUS` are development overrides, not release-qualified lower-resource
  profiles.
- **Network**: required on every canonical online build. Some package bytes may
  be cached, but repository metadata and pinned vendor keys are refreshed.
- **Time**: depends on mirrors, CPU, storage and package state; no fixed
  completion time is promised.
- **Concurrency**: one canonical compose per release user and host. The wrapper
  acquires a nonblocking lock in that user's private runtime directory before
  sudo, network, staging or candidate work; concurrent checkouts fail early
  instead of competing for fixed host services.

## Host package dependencies

```bash
sudo dnf install -y \
    lorax-lmc-virt \
    lorax-lmc-novirt \
    anaconda \
    pykickstart \
    genisoimage \
    git \
    curl \
    patch
```

Verify versions:

```bash
livemedia-creator -V
rpm -q pykickstart
isoinfo -version
```

The ISO builder always stops at an unsigned candidate.
`NOID_REQUIRE_SIGNATURE=1` is rejected because rebuilding after VM sign-off
would produce different, unqualified bytes; sign the exact published candidate
directory later.

`NOID_ISO_TMPDIR` may select another absolute, writable staging parent. It
must be disk-backed and have at least 12 GiB free; the wrapper canonicalizes
the path and fails before the build if it resolves to `tmpfs` or `ramfs`.

## One-shot build command

The canonical build path is the wrapper at `scripts/build-iso.sh`. It
handles ksflatten (resolves all `%include` chains), the minimal native Anaconda
profile/BRLTTY overlay via loopback HTTP, build-time bootloader/partition munging
required for lorax phase 2 live-ISO assembly, branding asset SHA-verified
HTTP staging, audit-tool (`noid-privacy-linux.sh`) SHA-pinning, and
`SOURCE_DATE_EPOCH` variance reduction — none of which the bare
`livemedia-creator` command performs. Use the wrapper for any release
or end-user-facing build.

The KVM wrapper also blacklists only the transient installer's `bochs` DRM
module. This avoids the Fedora netinst kernel's reproduced QEMU standard-VGA
vblank failure while packages are installed. The build-only arguments are not
copied into the Live ISO or an installed system.

The Fedora-signed Lorax packages remain byte-unchanged. The wrapper stages the
exact hash/NEVRA-gated Python package and generic template tree privately and
applies the reviewed compose overrides there. One override closes Lorax 44.6's
cancellation path: when the installer log monitor rejects a build, the build
QEMU is terminated and reaped with a bounded hard-stop fallback instead of
surviving as an orphan. A separate template override makes the graphical normal
Live entry the three-second default; the native media-check entry remains
available explicitly, and the wrapper audits both final BIOS/UEFI configs.

```bash
cd noid-privacy-workstation
sudo -v
./scripts/build-iso.sh
```

Do not run the wrapper itself through `sudo`: local RPM signing and any later
release signing must remain in the invoking user's fingerprint-selected GnuPG
context. The wrapper elevates only the operations that require root. A normal
candidate build writes `SHA256SUMS` but deliberately does not create
`SHA256SUMS.asc`; sign only after the installed-VM release gates pass.

Each successful run prints and atomically publishes a new directory such as
`build-output/candidates/unsigned-candidate-<build-id>-<random>/`. A normal KVM
candidate contains the ISO, the retained `lmc-disk-*.img`, `SHA256SUMS`, and a
mode-`0700` `private-build-evidence/` directory. No run deletes or overwrites a
prior candidate; remove only explicitly reviewed, superseded candidate
directories when reclaiming space.

### Debug-only direct livemedia-creator invocation

The bare `livemedia-creator` command shown below is intentionally
**debug-only** and lacks every safety net listed above (authenticated Anaconda
profile overlay, Live-ISO bootloader fix, branding/audit-tool delivery,
SOURCE_DATE_EPOCH pin). Reach for it only when isolating a single
component during regression investigation.

```bash
sudo livemedia-creator \
    --make-iso \
    --iso-only \
    --iso-name=noid-privacy-workstation-44-$(date +%Y%m%d).iso \
    --ks=kickstart/master.ks \
    --project="NoID Privacy Workstation" \
    --releasever=44 \
    --no-virt \
    --tmp=/var/tmp
```

Output ISO lands in the current working directory.

## Important internal Lorax flags

| Flag                  | Purpose |
|-----------------------|---------|
| `--make-iso`          | Request ISO artifact (not qcow2/raw/tar) |
| `--iso-only`          | Strip the intermediate rootfs after ISO build |
| `--iso-name`          | Output filename |
| `--ks=<path>`         | Kickstart entry point; always `kickstart/master.ks` |
| `--project=<name>`    | Label used in ISO volume header and boot menu |
| `--releasever=44`     | Fedora release to pull packages from |
| `--no-virt`           | Development-only Anaconda dirinstall in a UEFI-booted virtualized build host; the wrapper requires SELinux `Enforcing`. The default release path uses the separately isolated KVM compose. |
| `--tmp=/var/tmp`      | Lorax work parent; the wrapper validates and shares it with all host-side staging. |

## Reproducible build

`SOURCE_DATE_EPOCH` reduces timestamp variance but does not guarantee identical
ISOs across hosts. Always use the canonical wrapper so the Anaconda patch,
local-payload checks, artifact naming, checksum, and optional signature stages
are included. Mutter itself remains the unmodified Fedora package:

```bash
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
sudo -v
./scripts/build-iso.sh
```

See [`build-reproducibility.md`](build-reproducibility.md) for the full
reproducibility workflow.

## Verify output

```bash
# Use the exact path printed by the build; do not substitute a mutable "latest".
CANDIDATE_DIR='build-output/candidates/unsigned-candidate-<build-id>-<random>'

# SHA256
(cd "$CANDIDATE_DIR" && sha256sum -c SHA256SUMS)

# Mount + inspect
sudo mkdir -p /mnt/iso
sudo mount -o loop,ro "$CANDIDATE_DIR"/noid-privacy-workstation-44-*.iso /mnt/iso
ls /mnt/iso
sudo umount /mnt/iso

# Boot in VM
qemu-system-x86_64 \
    -enable-kvm -m 4096 -smp 2 \
    -cdrom "$CANDIDATE_DIR"/noid-privacy-workstation-44-*.iso \
    -display sdl
```

Before the manual VM matrix in [`docs/release-process.md`](release-process.md),
run `bash tests/run-all.sh` against the source tree (structural tests) and
`sudo ./tests/smoke/run-all.sh` for bubblewrap-based runtime checks
(requires a prepared rootfs).

## Known build-time gotchas

### 1. `tmpfs` OOM

The wrapper defaults all host-side staging and Lorax work to `/var/tmp`.
Before doing work it follows symlinks, checks the actual filesystem type and
free space, and rejects `tmpfs`/`ramfs`. Thus a misconfigured
`/var/tmp → /tmp` symlink fails immediately instead of exhausting memory late
while extracting `install.img` or writing squashfs.

### 2. SELinux labels on build host

Lorax supports `--no-virt` with SELinux Enforcing, and denials in that mode are
bugs rather than a reason to disable enforcement. The wrapper therefore
requires the observed mode to be exactly `Enforcing` and refuses Permissive or
Disabled hosts. It also requires a full, UEFI-booted virtual machine: upstream
warns that an Anaconda directory-install bug could operate on real devices, so
run this development path only in a disposable build VM. Containers are not a
substitute because loop devices, mounts and correct SELinux labeling are
required. The default, release-qualified path remains the separately isolated
KVM compose. QEMU-only options such as `--virt-uefi`, `--ram` and `--vcpus` are
not passed through to Lorax in no-virt mode.

See the upstream Lorax
[`Anaconda image install (no-virt)` documentation](https://weldr.io/lorax/livemedia-creator.html#anaconda-image-install-no-virt).

### 3. Network-required first run

Module 16 (Firefox) obtains the pinned uBO XPI at `%post` time (the NoID Privacy user.js
is a reviewed repository-owned derivative embedded in the image; the build
never imports or applies a mutable upstream arkenfox `user.js`).
Without the verified reduced-dependency cache, a networkless M16 aborts.
Prepare the cache on a networked host and place it under
`/var/cache/noid-build/` (partial
offline-build mode shipped — see `offline-build.md`; full air-gap
support is future work).

### 4. Kickstart syntax errors

Run `pykickstart` validation before attempting a build:

```bash
ksflatten -c kickstart/master.ks -o /var/tmp/noid-master-flat.ks
ksvalidator -v F44 /var/tmp/noid-master-flat.ks
```

### 5. dnf5 vs dnf4 differences

Fedora 44 ships dnf5 as default. All our `%packages` blocks use
`--exclude-weakdeps` (required — prevents weak deps from re-introducing
services explicitly excluded elsewhere). If you build on a Fedora
edition with dnf4 still default, packages may resolve differently.

## Post-build: signing

For public release ISOs:

```bash
cd "$CANDIDATE_DIR"  # the exact directory that passed every VM gate
sha256sum noid-privacy-workstation-44-*.iso > SHA256SUMS
RELEASE_KEY_ID=1ACBFCE49687FEBB91010E52F8E3F11D6962256F
gpg --batch --yes --armor --detach-sign \
  --local-user "${RELEASE_KEY_ID}!" --output SHA256SUMS.asc SHA256SUMS
# → SHA256SUMS + SHA256SUMS.asc
```

After all release gates and explicit publication approval, publish the ISO +
`SHA256SUMS` + `SHA256SUMS.asc` on the project download host
(download page: <https://noid-privacy.com/linux.html>). The project does
**not** attach the ISO to a GitHub Release; GitHub requires each individual
release asset to be under 2 GiB. Users verify with:

```bash
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS
```

See [`docs/release-process.md`](release-process.md) for the full
release workflow.
