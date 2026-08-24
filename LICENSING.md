# NoID Privacy Workstation — Licensing Overview

This file is a human-readable summary of how the repository is licensed. The
canonical license for NoID Privacy's own code and machine-readable policy is
GNU General Public License v3 or later in the repository-root `COPYING`, except
for the exact file-level exceptions inventoried below.

This is a multi-license repository. Different categories of content are
released under different licenses, summarized below:

  1. NoID Privacy's own code/policy ........ GPL-3.0-or-later
  2. NoID Privacy documentation ............ CC-BY-SA-4.0
  3. Third-party/separate code ............. exact license listed below
  4. Branding assets ....................... license listed per asset below

Each third-party component retains its own upstream license. The full text
of the GNU General Public License v3 is in the `COPYING` file at the
repository root.

================================================================================
TRADEMARK NOTICE
================================================================================

"Fedora" is a registered trademark of Red Hat, Inc. NoID Privacy Workstation
is an independent derivative work built on top of Fedora Linux and is NOT
affiliated with, endorsed by, or sponsored by the Fedora Project or Red Hat,
Inc. Official, unmodified Fedora software is available at
https://fedoraproject.org/.

Other trademarks referenced in this project (GNOME, Red Hat, Flatpak, Firefox,
Thunderbird, etc.) are the property of their respective owners. See
`docs/trademark-notice.md` for full details on the rebranding strategy and
trademark attributions.

The "NoID Privacy" name and original NoID Privacy branding assets in `branding/`
(logo, plymouth theme, app icons, avatar) are the exclusive property of the
NoID Privacy project. ALL RIGHTS RESERVED. They are NOT covered by the GPL
or CC BY-SA licenses below. Redistribution of the branding assets — or use
of the "NoID Privacy" name — as part of a different or modified distribution
requires explicit written permission.

The default wallpaper (`branding/wallpaper.png` + `branding/wallpaper-dark.png`,
deployed to `/usr/share/backgrounds/noid-privacy/default{,-dark}.png`) is GNOME's
`drool-l` / `drool-d` artwork from the `gnome-backgrounds` package
(<https://gitlab.gnome.org/GNOME/gnome-backgrounds>), licensed under
**CC-BY-SA-3.0**. Attribution is required for redistribution; derivative
works must use the same license.

================================================================================
1. NoID Privacy's own code and machine-readable policy
================================================================================

GNU General Public License, version 3 or later (GPL-3.0-or-later)

Copyright (C) 2026 NoID Privacy contributors

This category includes:

  - `kickstart/`, `scripts/`, `manifests/`, and `tests/` except
    `tests/README.md`
  - NoID Privacy-owned non-Markdown repository/CI configuration (`.gitattributes`,
    `.gitignore`, `.github/*.yml`, `.github/workflows/*.yml`)
  - `branding/SHA256SUMS` and `branding/icons/regenerate-icons.sh`
  - `overrides/noid-lan-xdp/noid-lan-xdp.sh`
  - `thunderbird/autoconfig.js`, `thunderbird/local-settings.js` and
    `thunderbird/mozilla.cfg`
  - NoID Privacy override sections in
    `thunderbird/noid-thunderbird-hardening.js` (the embedded upstream base is
    MIT; see section 3)

It excludes the separately licensed Lorax patches, Anaconda Live-source
derivative, XDP BPF source/object, Firefox derivative, vendored upstream
subtree, upstream license texts, documentation and branding assets listed
below.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <https://www.gnu.org/licenses/>. The full license
text is also included in the `COPYING` file at the repository root.

================================================================================
2. NoID Privacy documentation
================================================================================

Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)

This category includes the NoID Privacy-owned root Markdown files (`README.md`,
`INDEX.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
`SECURITY.md`, `AGENTS.md`, `LICENSING.md`), `docs/`, `tests/README.md`,
`.github/ISSUE_TEMPLATE/*.md`, `.github/pull_request_template.md`,
`overrides/noid-lan-xdp/README.md`, and Markdown shipped as user-facing
documentation from a Kickstart heredoc. It does not relicense third-party
notices or source code merely because those files use Markdown.

You are free to:
  - Share — copy and redistribute the material in any medium or format
  - Adapt — remix, transform, and build upon the material for any purpose,
    even commercially.

Under the following terms:
  - Attribution — You must give appropriate credit, provide a link to the
    license, and indicate if changes were made.
  - ShareAlike — If you remix, transform, or build upon the material, you must
    distribute your contributions under the same license as the original.

Full legal code: https://creativecommons.org/licenses/by-sa/4.0/legalcode

================================================================================
3. Third-party and separately licensed source — exact licenses retained
================================================================================

NoID Privacy derives, bundles, or vendors the following third-party components. Each
retains its own upstream license; where content is embedded in a NoID Privacy file,
the upstream notice is retained in-file.

--- REPOSITORY SOURCE WITH A FILE-LEVEL LICENSE EXCEPTION ---

  - Lorax monitor shutdown-drain patch — GPL-2.0-or-later
    `overrides/lorax/0001-drain-monitor-before-shutdown.patch` modifies
    Fedora Lorax's `pylorax/monitor.py`, whose header grants GPL version 2 or
    any later version. The patch retains that license rather than inheriting
    NoID Privacy's GPL-3.0-or-later default.

  - Lorax Live required-space compose patch — GPL-2.0-or-later
    `overrides/lorax/0002-precompute-live-required-space.patch` modifies
    Fedora Lorax's `pylorax/creator.py`, whose header grants GPL version 2 or
    any later version. The patch retains that license rather than inheriting
    NoID Privacy's GPL-3.0-or-later default.

  - Lorax cancelled-process cleanup patch — GPL-2.0-or-later
    `overrides/lorax/0003-terminate-cancelled-process.patch` modifies Fedora
    Lorax's `pylorax/executils.py`, whose header grants GPL version 2 or any
    later version. The patch retains that license rather than inheriting the
    NoID Privacy GPL-3.0-or-later default.

  - Lorax Live boot-menu defaults patch — GPL-2.0-or-later
    `overrides/lorax/0004-live-menu-default.patch` modifies Fedora Lorax
    template files `live/config_files/x86/grub2-{bios,efi}.cfg`, distributed
    by `lorax-templates-generic` under GPL-2.0-or-later. The patch retains that
    license rather than inheriting the NoID Privacy GPL-3.0-or-later default.

  - Anaconda Live OS initialization derivative — GPL-2.0-or-later
    `overrides/anaconda/live-os-initialization.py` modifies Fedora Anaconda's
    `pyanaconda/modules/payloads/source/live_os/initialization.py`, whose
    retained header grants GPL version 2 or any later version. Its generated
    copy inside `kickstart/snippets/17-gnome-hardening.ks` retains the same
    notice; GPL-2.0-or-later permits that combined Kickstart payload to be
    distributed under this project's GPL-3.0-or-later choice.

  - NoID Privacy physical-link XDP BPF program — GPL-2.0-only
    `overrides/noid-lan-xdp/noid-lan-xdp.bpf.c` carries the exact SPDX
    identifier and is the corresponding source for the committed
    `noid-lan-xdp.bpf.o.b64` object. The controller shell script remains
    GPL-3.0-or-later and its README remains CC-BY-SA-4.0.

    The complete GNU GPL version 2 text used by these exceptions is retained
    at `licenses/GPL-2.0.txt`.

--- DERIVED (modified upstream sources, embedded in NoID Privacy's own files) ---

  - arkenfox user.js v144.0 — MIT
    https://github.com/arkenfox/user.js
    Basis of `firefox/noid-firefox-hardening.js` (NoID Privacy Firefox Hardening),
    embedded into M16 as a gzip+base64 blob via
    `scripts/regen-firefox-embed.sh`. The exact tag `144.0` notice (commit
    `bb45863be796d331717e2b5d6e490f0d3e3cf93f`, SHA-256
    `2bf289bdd22188ccff2bf34c9a20a75c45b84f42f887da7e177d9bfd1bac3c1a`)
    is retained in-file and at `licenses/arkenfox-user.js-MIT.txt`, then
    installed to `/usr/share/licenses/noid-privacy/`. The combined Firefox
    derivative carries both upstream and NoID Privacy copyright notices and is
    distributed under MIT so it has one unambiguous file-level license.

  - HorlogeSkynet thunderbird-user.js v140.2 — MIT
    https://github.com/HorlogeSkynet/thunderbird-user.js
    Basis of `thunderbird/noid-thunderbird-hardening.js` (NoID Privacy Thunderbird
    Hardening), embedded into M35 as a gzip+base64 blob via
    `scripts/regen-thunderbird-embed.sh`. The exact annotated tag `v140.2`
    notice (commit `556709d1a4beced21f9888fb9b55dd623b415008`, SHA-256
    `e0bfbe5467925aa73c30bb5d7e9e23fef1a2f6285b0c5dd62a5c7ab091fc5331`)
    is retained in-file and at
    `licenses/horlogeskynet-thunderbird-user.js-MIT.txt`, then installed to
    `/usr/share/licenses/noid-privacy/`. That combined file explicitly marks
    the HorlogeSkynet base as MIT and NoID Privacy override sections as
    GPL-3.0-or-later.

--- BUNDLED / FETCHED AT BUILD TIME (pinned release tag or reviewed source
    revision + SHA256 verified; installed into the built image, not stored in
    this repository) ---

  - uBlock Origin (XPI) — GPL-3.0-or-later
    https://github.com/gorhill/uBlock
  - DKIM Verifier v6.3.0 (XPI) — MIT/X11
    https://github.com/lieser/dkim_verifier
  - Just Perfection GNOME Shell extension v36 — GPL-3.0-only
    https://gitlab.com/l3nn4rt/just-perfection-gnome-shell-desktop
    M17 downloads the GNOME Extensions release archive by exact version,
    byte count and SHA-256, validates its closed tree, and installs the
    extension system-wide. Upstream declares the extension GPL-3.0-only;
    downstream redistribution must preserve the applicable license notices
    and corresponding-source obligations.
  - NoID Privacy for Linux (`noid-privacy-linux.sh`) — GPL-3.0-or-later
    https://github.com/NexusOne23/noid-privacy-linux
    A sibling NoID Privacy project, bundled by M40 as the `noid-audit` companion.

--- THIRD-PARTY RPM REPOSITORY PACKAGES ---

  - VSCodium (`codium` RPM) — MIT, with bundled third-party notices
    https://github.com/VSCodium/vscodium
    M08 installs the vendor-built RPM from VSCodium's separately configured
    repository after pinning its signing-key fingerprint. It is not a Fedora
    package. The installed RPM metadata and its shipped license/notice files
    remain the authority for the exact package version in an image.

--- DESIGN-TIME TOOLS (not vendored, not shipped) ---

  - kernel-hardening-checker (Alexander Popov) — GPL-3.0-only
    https://github.com/a13xp0p0v/kernel-hardening-checker
    A build-/design-time tool used to review kernel hardening configuration.
    It is run from its own upstream checkout. No part of it is stored in this
    repository or installed into the image, so it carries no NoID Privacy
    derivative and imposes no distribution obligation here. The attribution is
    kept because its findings informed M01/M02 hardening decisions.

--- LICENSE TEXTS AND NOTICES ---

  - `COPYING`, `licenses/GPL-2.0.txt`,
    `licenses/arkenfox-user.js-MIT.txt`, and
    `licenses/horlogeskynet-thunderbird-user.js-MIT.txt` retain exact license
    or notice text for the corresponding works. Including those texts does not
    relicense them as NoID Privacy documentation.

--- DISTRO PACKAGES ---

  Fedora packages installed via kickstart `%packages` (and shipped inside the
  built ISO) retain their respective upstream licenses (most commonly GPL,
  LGPL, MIT, BSD, Apache — see Fedora Package Licensing guidelines). The built
  ISO is an **independent derivative work based on Fedora 44** (not a Fedora
  Remix — see `docs/trademark-notice.md` for the canonical positioning per
  Fedora Trademark Guidelines). Redistributing the ISO carries the corresponding-
  source obligations of the GPL/copyleft packages it contains (Fedora mirrors
  provide the matching source).

================================================================================
4. Branding assets
================================================================================

The "NoID Privacy" name and original NoID Privacy artwork are not covered by
the software or documentation licenses above. The project reserves all rights
to these assets:

  - `branding/noid-privacy-logo.png`
  - `branding/noid-privacy-logo-512.png`
  - `branding/noid-privacy-avatar-*.png`
  - `branding/plymouth/*.png`
  - `branding/icons/noid-privacy-*.png`

The Firefox Playground launcher references the unmodified `firefox` icon
installed by Fedora's Firefox package through standard icon-theme lookup; this
repository does not ship a copy or modified derivative of Mozilla's Firefox
logo. The generator (`branding/icons/regenerate-icons.sh`) and integrity manifest
(`branding/SHA256SUMS`) are project code/policy under GPL-3.0-or-later as
listed in section 1, not proprietary artwork.

The default wallpapers are a separate upstream exception:

  - `branding/wallpaper.png`
  - `branding/wallpaper-dark.png`

They are GNOME's `drool-l` / `drool-d` artwork from `gnome-backgrounds`,
licensed under CC-BY-SA-3.0:
https://gitlab.gnome.org/GNOME/gnome-backgrounds

Attribution is required for redistribution; derivative wallpaper works must
use the same license. The asset integrity manifest records bytes only and does
not change the license of any listed asset.

================================================================================
ACKNOWLEDGMENTS (design inspiration — NOT copied code)
================================================================================

NoID Privacy's hardening surfaces are independent re-implementations, not verbatim
copies. The following projects and baselines were studied as references and
shaped NoID Privacy's design direction; we gratefully acknowledge their work:

  - secureblue            https://github.com/secureblue/secureblue
  - Kicksecure / security-misc   https://www.kicksecure.com/
  - Kernel Self-Protection Project (KSPP)   https://kspp.github.io/
  - CIS Benchmarks        https://www.cisecurity.org/
  - Mozilla Security / Firefox hardening guidance
  - The arkenfox and HorlogeSkynet user.js projects (also credited above as
    directly-derived sources)

Crediting these projects does not imply their endorsement of NoID Privacy.
