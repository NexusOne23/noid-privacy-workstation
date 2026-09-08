# Build-source failure and cache policy

NoID Privacy does not silently switch a pinned artifact to an unrelated mirror.
A failed download, signature, fingerprint, size or SHA-256 gate aborts the
canonical build. Availability is recovered by retrying the same reviewed input
or by deliberately reviewing and updating its pin.

## Current source classes

The canonical online builder uses several independently authenticated source
classes:

| Source class | Verification boundary | Failure result |
| --- | --- | --- |
| Fedora repositories | Fedora repository metadata and RPM signatures | build aborts |
| RPM Fusion release/key/package inputs | exact key fingerprint plus RPM/repository signatures | build aborts |
| VSCodium repository inputs | exact full signing-key fingerprint plus package/repository signatures | build aborts |
| Pinned extension/archive payloads | version-specific source URL plus repository-owned SHA-256 and exact size/type checks | build aborts |
| Flathub system-remote setup | byte-pinned local descriptor, exact key identity, remote-policy reconciliation and signed catalog gates | build aborts |
| LVFS metadata | not refreshed during image composition; user-triggered after install | no build-time dependency |

The exact URLs, versions, fingerprints and hashes live beside the consuming
code. This document intentionally does not duplicate them because a copied pin
can become stale while still looking authoritative.

## Reduced-dependency cache

[`offline-build.md`](offline-build.md) documents the only supported cache
workflow. Today it pre-stages and verifies the pinned uBlock Origin XPI; the
canonical builder still needs network access for repositories and the other
release inputs. `build-offline.sh` is therefore not an air-gapped builder and
does not bypass any canonical build gate.

If the uBlock release host is temporarily unavailable, prepare the cache on a
networked machine once the exact pinned file is reachable, transfer the cache,
verify its exact manifest against the repository-owned path, URL, size and
SHA-256 contract, and run the normal builder. Module 16 re-verifies the
source-owned hash and exact size before installation.

## Repository outages

For a temporary repository outage, preserve the configured repository identity
and retry later. Substituting a manually chosen base URL can change the metadata
snapshot and reproducibility context even when RPM signatures remain valid.
When an operational mirror override is unavoidable, record the override, retain
the fetched repodata and package list, and treat the result as a separately
reviewed build input rather than an invisible fallback.

## Adding a dependency

A new external build dependency must have:

1. an immutable content identity (a version/tag alone is insufficient);
2. an independent authenticity check appropriate to the format;
3. an explicit fatal failure path;
4. an offline/cache story or a documented reason it is unavailable;
5. structural tests that prevent removal of the verification gate.

No project-operated binary mirror is claimed. A complete air-gapped build would
need immutable local snapshots of every enabled repository and payload, all
trust anchors, rewritten build inputs with no network fallback, and packet-level
proof that composition made no external connection. That is not implemented in
the current source tree.
