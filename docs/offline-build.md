# Reduced-Dependency Build Cache

The script names are retained for operator compatibility, but NoID Privacy does
not ship an offline or air-gapped ISO builder. `offline-prep.sh` prepares one
reviewed payload: the uBlock Origin XPI consumed by Module 16.
`build-offline.sh` verifies that exact cache and calls the canonical builder.

The ISO build still needs network access for Fedora, RPM Fusion, VSCodium,
Flathub setup, reviewed vendor-key sources and any other canonical online
inputs. No successful ISO build with networking disabled is claimed or implied.

## Supported workflow

On a networked preparation host:

```bash
sudo CACHE_DIR=/var/cache/noid-build ./scripts/offline-prep.sh
```

The prep helper accepts no positional options. It downloads from the exact
pinned GitHub release URL without curl's automatic redirect following. Every
redirect is inspected before the next connection: the initial host must be
`github.com`, later hops must remain on
`release-assets.githubusercontent.com`, and HTTPS is mandatory throughout.

The downloaded file must match the repository-owned SHA-256 and byte-count
pins. It is published without replacing an existing path. `MANIFEST.txt` is
then written in the same directory, fsynced and atomically renamed into place.
The manifest binds schema, relative path, original URL, size and SHA-256.

On the canonical networked build host:

```bash
CACHE_DIR=/var/cache/noid-build ./scripts/build-offline.sh
```

The development-only no-virt option remains available inside a disposable,
UEFI-booted virtualized build host with SELinux Enforcing:

```bash
CACHE_DIR=/var/cache/noid-build ./scripts/build-offline.sh --no-virt
```

The wrapper compares the manifest byte-for-byte with its reviewed constants,
rechecks payload size and SHA-256, and requires the cache tree to contain
exactly two directories and two regular files:

```text
/var/cache/noid-build/
├── MANIFEST.txt
└── ubo/
    └── 1.73.0/
        └── uBlock0_1.73.0.firefox.signed.xpi
```

The canonical builder copies the verified XPI into its private staging tree.
Module 16 receives it from the builder's loopback-only payload server and again
checks the source pin and exact size before installation. The wrapper cannot
bypass canonical source, signing, candidate-publication or VM gates.

## Transfer

Preserve regular files, directory structure and permissions when moving the
cache. For example:

```bash
rsync -a /var/cache/noid-build/ /run/media/user/usb/noid-build/
CACHE_DIR=/run/media/user/usb/noid-build ./scripts/build-offline.sh
```

The wrapper rejects noncanonical or symlink-traversing cache paths, symlinked
artifacts/manifests, extra files, stale mirror trees, altered manifest fields,
wrong sizes and wrong hashes.

## Deliberately unsupported Fedora mirror

The former optional `reposync` mode was not connected to the canonical build.
It has been removed rather than leaving operators with a large, integrity-listed
directory that the build silently ignored. A local repository implementation
would require pinned complete metadata/package snapshots, every enabled source
and trust anchor, disposable kickstart rewriting with no remote fallback, and
packet-level proof under disabled external networking. That implementation is
not present.

## Reproducibility boundary

Caching the XPI removes one network and content-drift variable. It does not make
ISO images bit-identical: repository state, the Fedora compose, image tooling
and the build environment remain relevant. `SOURCE_DATE_EPOCH` reduces one
timestamp source but is not proof of reproducibility. See
[build-reproducibility.md](build-reproducibility.md).
