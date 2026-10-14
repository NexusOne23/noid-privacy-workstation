# Build Guide — NoID Privacy Workstation

## Requirements

- **Build host**: Fedora 44 x86_64 with the listed RPM tools available. The
  staging gate accepts exactly `lorax-44.7-1.fc44.x86_64` and rejects a
  different Lorax NEVRA or payload digest; keep this requirement synchronized
  with `scripts/stage-lorax-overrides.sh`. Other releases and immutable-host
  toolboxes are not claimed as tested.
- **Privilege**: `sudo` required (livemedia-creator chroots build env). The
  builder needs sudo credentials for the whole run, not only at the start: run
  `sudo -v` once, then keep the session available. Every privileged step uses
  `sudo -n`, and the wrapper refreshes the cached credential in the background
  with `sudo -n -v` (never prompting) until it exits. If the credential cannot
  be refreshed (for example because the sudoers timestamp policy forbids it),
  the next privileged step fails closed instead of prompting.
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
  parent (`NOID_ISO_TMPDIR`, default `/var/tmp`). Every wrapper-owned
  host-side intermediate lives below that parent — the private
  `noid-iso-stage.*` tree, Lorax's `--tmp` work tree, the Anaconda
  updates-image workdir and, after Lorax has finished, the final image-hygiene
  extraction — and the wrapper rejects `tmpfs`/`ramfs` parents. Also budget
  roughly 16 GiB in the repository filesystem for each retained KVM candidate
  at the current guest-disk size:
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
    python3-libdnf5 \
    genisoimage \
    git \
    curl \
    squashfs-tools \
    util-linux-core \
    iproute \
    xorriso \
    patch
```

The wrapper also refreshes the build host's DNF metadata as root and tries
`dnf download codium` to pre-stage the VSCodium RPM. That needs `dnf5-plugins`
and a configured VSCodium repository on the build host; if the download fails,
the wrapper logs a warning and Module 08 uses its signed remote fallback.

Verify versions:

```bash
livemedia-creator -V
rpm -q pykickstart
isoinfo -version
```

The ISO builder always stops at an unsigned candidate.
`NOID_REQUIRE_SIGNATURE=1` is rejected because rebuilding after ISO validation
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
HTTP staging, audit-tool (`noid-privacy-linux.sh`) SHA-pinning, and the
commit-derived build ID and injected build epoch — none of which the bare
`livemedia-creator` command performs. Use the wrapper for any release
or end-user-facing build.

For Fedora base and updates, the wrapper fetches the official HTTPS Metalinks
and retains only each document's current primary `repomd.xml` identity. Fedora
also advertises older valid identities while mirrors synchronize; accepting one
can omit already available security updates. The wrapper preserves the HTTPS
mirror inventory and all primary checksums, embeds the constrained documents
in an offline native Kickstart `%pre`, and lets Anaconda/librepo consume them
through `file://` Metalink URLs. A stale mirror must fail checksum validation
and another mirror must provide the selected current metadata. Original and
constrained XML plus their hashes are retained in `private-build-evidence/`.
This affects the disposable compose only. Installed repository configuration,
TLS verification and package-signature checks remain unchanged. Updates released
after this snapshot still require the installed package-freshness gate and,
when necessary, a new candidate. That gate fetches fresh current-only Metalinks
with the same helper, uses private DNF cache/state paths and fails if either
Fedora repository is unavailable; a stale mirror cannot produce a false clean
result. It does not install packages or change installed repository files.

Before publishing a candidate, the wrapper also checks the actual ISO RPM
database against the compose's Fedora metadata. Native libdnf5 evaluates
`Recommends`, `Suggests` and applicable missing `Supplements`/`Enhances`, including
versioned and conditional expressions. Each unmet relationship must have an
exact, explained entry in
[`weak-dependencies.json`](../manifests/weak-dependencies.json); required native
integrations must be installed. New relationships, missing required packages,
unavailable repositories and unreadable inventories fail the build. Review
the consuming program before changing the policy; do not automatically accept
the current missing set. This catches metadata drift, not undeclared optional
imports or every hardware-specific runtime dependency. The query runs on a
private database copy, without package transactions or DNF plugins, and keeps
its result in the candidate's private build evidence.

The KVM wrapper also blacklists only the transient installer's `bochs` DRM
module, through Dracut's `rd.driver.blacklist=` and the kernel's own
`module_blacklist=`. This avoids the Fedora netinst kernel's reproduced QEMU
standard-VGA vblank failure while packages are installed. It deliberately
avoids `modprobe.blacklist=`: Anaconda copies that argument into the compose
target as `/etc/modprobe.d/anaconda-denylist.conf`, and the final-SquashFS
hygiene gate rejects that file. The build-only arguments are not copied into
the Live ISO or an installed system.

The Fedora-signed Lorax packages remain byte-unchanged. The wrapper stages the
exact hash/NEVRA-gated Python package and generic template tree privately and
applies the reviewed compose overrides there. One override closes Lorax 44.7's
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

Do not run the wrapper itself through `sudo`: user-relative inputs (base-ISO
lookup, caches) and the later release signing stay in the invoking user's
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
profile overlay, build-only bootloader/partition edits, branding/audit-tool
delivery, build ID and epoch injection). It uses the unedited
`kickstart/master.ks`, so it cannot reproduce a complete compose: without the
wrapper's single-partition collapse Lorax phase 2 finds no kernels. Reach for
it only when isolating early Anaconda behaviour during regression
investigation, and run it only inside a disposable, UEFI-booted,
SELinux-Enforcing build VM — upstream warns that a no-virt directory-install
bug could operate on real devices.

```bash
sudo livemedia-creator \
    --make-iso \
    --iso-only \
    --iso-name=noid-privacy-workstation-44-$(date +%Y%m%d).iso \
    --ks=kickstart/master.ks \
    --project="NoID Privacy Workstation" \
    --releasever=44 \
    --no-virt \
    --tmp=/var/tmp \
    --resultdir=/var/tmp/noid-debug-result \
    --logfile=/var/tmp/noid-debug-livemedia.log
```

The ISO lands in the `--resultdir` directory, which must not exist yet; the
other logs (such as `program.log`) land beside `--logfile`. Without these two options Lorax writes the ISO
to its `--tmp` directory and `livemedia.log`/`program.log` to the current
working directory.

## Important internal Lorax flags

| Flag                  | Purpose |
|-----------------------|---------|
| `--make-iso`          | Request ISO artifact (not qcow2/raw/tar) |
| `--iso-only`          | Remove all ISO creation artifacts except the final ISO |
| `--iso-name`          | Output filename |
| `--ks=<path>`         | Kickstart entry point; the wrapper passes its flattened, build-edited copy of `kickstart/master.ks` |
| `--project=<name>`    | Product name substituted into the boot-menu templates |
| `--volid=<label>`     | ECMA-119 volume ID (`NOID_PRIVACY_F44`) |
| `--release`, `--bugurl` | Product release (`NOID_VERSION`) and bug-report URL written into the installer metadata |
| `--releasever=44`     | Fedora release to pull packages from |
| `--resultdir`, `--logfile` | Private unpublished result directory and compose log inside the candidate transaction |
| `--lorax-templates`   | The privately staged, patched Live template tree |
| `--extra-boot-args`   | The Live kernel-argument set audited against M01's manifest |
| `--keep-image`        | Retain the raw `lmc-disk-*.img` beside the ISO |
| `--virt-uefi`, `--ram`, `--vcpus`, `--iso`, `--kernel-args` | KVM build-guest firmware, resources, base installer ISO and transient installer arguments (KVM mode only) |
| `--no-virt`           | Development-only Anaconda dirinstall in a UEFI-booted virtualized build host; the wrapper requires SELinux `Enforcing`. The default release path uses the separately isolated KVM compose. |
| `--tmp=/var/tmp`      | Lorax work parent; the wrapper validates and shares it with all host-side staging. |

## Reproducible build

`SOURCE_DATE_EPOCH` (the commit time by default) sets the build ID, the
injected build epoch and the Anaconda updates-image archive timestamps. It is
deliberately not forwarded into the Lorax compose, so the ISO contents are not
timestamp-normalized and builds are not byte-identical. Always use the
canonical wrapper so the Anaconda profile overlay, local-payload checks,
artifact naming and checksum stages are included:

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

# Boot in a UEFI VM (BIOS installs are unsupported: the interactive
# installer has no up-front BIOS check and fails only at bootloader
# installation because grub2-pc is excluded; OVMF comes from edk2-ovmf)
cp /usr/share/edk2/ovmf/OVMF_VARS.fd /var/tmp/noid-test-vars.fd
qemu-system-x86_64 \
    -machine q35 -enable-kvm -m 4096 -smp 2 \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/edk2/ovmf/OVMF_CODE.fd \
    -drive if=pflash,format=raw,file=/var/tmp/noid-test-vars.fd \
    -cdrom "$CANDIDATE_DIR"/noid-privacy-workstation-44-*.iso
```

Before running the [ISO tests](../tests/README.md#pre-ship-gates),
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
`/var/cache/noid-build/`; see `offline-build.md`. This remains a networked
build with one pre-staged payload, and no offline or air-gapped build mode is
claimed.

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
sha256sum -c --strict SHA256SUMS  # verify the builder's manifest; never rewrite it
RELEASE_KEY_ID=1ACBFCE49687FEBB91010E52F8E3F11D6962256F
gpg --batch --yes --armor --detach-sign \
  --local-user "${RELEASE_KEY_ID}!" --output SHA256SUMS.asc SHA256SUMS
# → SHA256SUMS + SHA256SUMS.asc
```

After all release gates and explicit publication approval, publish the ISO +
`SHA256SUMS` + `SHA256SUMS.asc` on the project download host
(download page: <https://noid-privacy.com/linux.html>). The project does
**not** attach the ISO to a GitHub Release; GitHub requires each individual
release asset to be under 2 GiB. Users verify with the complete
[download-verification recipe](../README.md#-download-the-iso), including its
independent fingerprint check, exact signer/status checks and failure handling.

See [release verification](release-process.md) for source, signature and
download details.
