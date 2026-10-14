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

## SELinux scope

SELinux runs enforcing with Fedora's targeted policy. Desktop logins keep
Fedora's `unconfined_u` mapping, so SELinux confines system services rather
than programs that run as the logged-in user. Confined login roles such as
`staff_u` or `user_u` are not part of the image: they are not tested with the
shipped GNOME, Flatpak, rootless-container, gaming and sudo administration
workflows, and on this single-user design the daily account is also the
administrator. Keeping administrator credentials out of the daily session
requires a separate administrator account.

Three SELinux booleans keep Fedora's default:

- `deny_ptrace` would block debugging and tracing for every domain, including
  root (`gdb`, `strace`, crash diagnostics). `kernel.yama.ptrace_scope=2`
  already restricts ptrace to processes holding `CAP_SYS_PTRACE`.
- `secure_mode_insmod` would block module loading by every domain, including
  the udev and systemd hotplug paths that load drivers for newly attached USB,
  Thunderbolt or Bluetooth hardware. `module.sig_enforce=1`,
  `lockdown=integrity` and the Module 21 deny policy already restrict which
  modules can load.
- `deny_execmem` would break the JIT compilers in Firefox and Electron
  applications; `selinuxuser_execstack` and `selinuxuser_execmod` stay off.
  The opt-in Gaming Mode turns `selinuxuser_execmod` back on for Wine/Proton
  (see [Gaming Mode](gaming.md)).

## LibreOffice documents

Fedora's LibreOffice reads system settings from dconf, and Module 17 uses that
layer. Macro security is locked at Very High, so a document's macros run only
from a trusted file location, and legacy import formats that LibreOffice marks
exotic are refused by default. Saving removes personal metadata while keeping
comment and tracked-change authors. The policy follows BSI-CS 146 where
LibreOffice 26.2 still needs it and deviates where a recommendation no longer
fits:

- Disabling all macros, embedded objects or the Python runtime would break
  My Macros, charts, e-mail mail merge and Python extensions.
- LibreOffice 26.2 already asks before it loads linked content from a document
  outside a trusted location. Blocking such links outright would also hide
  linked images in the user's own documents.
- Disabling individual import filters would break common paths such as HTML
  paste, and the same content can still arrive embedded in a common format.
  LibreOffice's own exotic-format switch covers the legacy parsers.
- Extensions remain installable, as with Firefox add-ons.

## Package signatures

DNF verifies package signatures for every enabled repository. RPM itself also
requires a verified signature (`%_pkgverify_level all`), Fedora 45's accepted
default. Explicit DNF `--nogpgcheck` and `rpm --nosignature` remain
per-package decisions, which keeps akmods' locally built kernel-module packages
working.

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
