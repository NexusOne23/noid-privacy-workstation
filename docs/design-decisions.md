# Platform choices

NoID Privacy Workstation combines Fedora's mutable package system with a
hardened desktop configuration. This page describes the resulting platform
and its limits.

## Firefox and memory allocation

The image uses Fedora's signed Firefox packages, the project's Firefox
configuration and full uBlock Origin. It does not globally preload
`hardened_malloc`: Firefox's `mozjemalloc` configuration has documented
incompatibilities with that combination. See
[Mozilla's allocator issue](https://bugzilla.mozilla.org/show_bug.cgi?id=1668674)
and [the upstream hardened_malloc discussion](https://github.com/GrapheneOS/hardened_malloc/issues/123).
This describes compatibility with the shipped browser, not a claim that one
browser or allocator is universally safer.

## Packages and recovery

DNF updates the mutable system directly. This supports normal Fedora package,
development-tool and driver workflows. Kernel and core-library updates can
still require a reboot.

Btrfs and Snapper provide root-subvolume rollback through the supported
`noid-snap-rollback` workflow. Snapshots are not backups or authenticated atomic
images; their coverage excludes separate data subvolumes such as `/home`.
See [updates and recovery](upgrade-path.md) and [disk encryption](22-disk-encryption.md).

## ISO builds

The release binds the ISO checksum, signature and published source tree.
Complete byte-for-byte ISO reproducibility is not established: Fedora package
repositories change, and image construction produces variable metadata.
See [build reproducibility](build-reproducibility.md) for the precise scope of
`SOURCE_DATE_EPOCH` and [release verification](release-process.md) for downloads.
