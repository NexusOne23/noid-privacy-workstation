# NoID Privacy Anaconda `inst.updates` payload

This directory builds the minimal overlay consumed only by the canonical
Fedora 44 KVM compose installer. Despite the historical directory name, it no
longer patches Anaconda's RPM transaction code.

## Security decision

The retired v7 implementation replaced
`transaction_progress.py` and accepted nonzero scriptlet results for broad
`(package, scriptlet)` pairs. That could turn an unrelated future failure into
success, and the marker-only idempotency path did not prove the expected patch
bytes. The successful July 2026 reference compose logged the known
`man-db-2.13.1-3.fc44` missing-unit message but no `script_error` callback or
NoID Privacy acceptance event. `codium` is installed later by a kickstart `%post`, so
the payload callback could not have authorized it at all.

NoID Privacy therefore keeps native Anaconda behavior: every RPM transaction failure
remains fatal. Module 99 rejects any surviving `NoID Privacy PATCH` or old safe-error
marker in the installed transaction handler. A release that starts failing must
fix the package/runtime cause or stop; it must not widen a generic bypass.

## Current payload

`build-updates-img.sh` stages exactly eight archive members:

- the native `/etc/anaconda/profile.d/noid-privacy.conf`, extracted from the
  unique Module 32 heredoc; and
- `/etc/systemd/system/brltty.service -> /dev/null`, effective only inside the
  fixed noninteractive build installer.

The BRLTTY mask prevents a QEMU profile with no Braille device from flooding
the private compose log with usbfs `ENODEV` errors. `inst.updates` is not copied
into the generated LiveOS or installed target, so this does not disable
user-facing Braille support.

The builder authenticates the exact Fedora netinst ISO through the repository's
pinned Fedora signature/digest verifier, requires exactly two arguments,
rejects existing/symlink output, uses normalized mtimes, sorted NUL-delimited
newc input, GNU cpio reproducible mode and `gzip -n`, and verifies the exact
member set plus extracted bytes/link. It fsyncs the complete file and publishes
with an atomic no-replace hard link on the destination filesystem.

## Usage

Canonical builds invoke this automatically:

```bash
sudo -v
./scripts/build-iso.sh
```

Standalone verification requires the reviewed base ISO and an absent absolute
destination:

```bash
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) \
  ./scripts/anaconda-patch/build-updates-img.sh \
  /var/tmp/Fedora-Server-netinst-x86_64-44-1.7.iso \
  /var/tmp/noid-anaconda-updates.img
```

Large and temporary work defaults to disk-backed `/var/tmp`; an overridden
`NOID_ANACONDA_PATCH_TMPDIR` must be an absolute writable non-symlink directory
and cannot resolve to `tmpfs` or `ramfs`.

## Files

| File | Purpose |
|---|---|
| `build-updates-img.sh` | Authenticated deterministic producer and verifier |
| `build-with-patched-anaconda.sh` | Deprecated muscle-memory shim; exits nonzero |
| `README.md` | Current boundary and reproduction contract |

Tests in `tests/00-anaconda-patch-structured.sh` reject any transaction handler
override and exercise the producer's argument, destination, reproducibility and
archive-behavior contract when the reviewed base ISO is locally available.
