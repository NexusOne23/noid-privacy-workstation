# Trademark Notice

This repository notice and Module 32's shorter installed notice have different
audiences. Keep both aligned on three user-facing facts: NoID Privacy is an
independent derivative rather than a Fedora Remix; “Fedora” is a Red Hat
trademark used for upstream attribution; and `UPSTREAM_BASE` in
`/etc/os-release` records that attribution. This repository additionally
records the package-level `fedora-logos` to `generic-logos` replacement.

## Fedora Trademark

**"Fedora" is a registered trademark of Red Hat, Inc.**

NoID Privacy Workstation is an **independent derivative work** built on
top of Fedora Linux. This project is **NOT affiliated with, endorsed by,
or sponsored by** the Fedora Project or Red Hat, Inc.

The name "Fedora" appears in this project's documentation and code for
descriptive upstream attribution, without implying endorsement, to indicate:

- The upstream Linux distribution this project is derived from (Fedora
  Linux 44).
- Compatibility with Fedora package repositories and tooling (dnf5, rpm,
  livemedia-creator, Anaconda installer).

## Rebranding Strategy

In accordance with
[Fedora's Trademark Guidelines](https://docs.fedoraproject.org/en-US/legal/trademarks/)
and the
[Fedora Remix Guidelines](https://fedoraproject.org/wiki/Remix), NoID Privacy Workstation performs the following rebranding measures to avoid
confusion with official Fedora products:

### Current overlay/package strategy

**Package-level selection** (M26 `%packages`):

- `fedora-logos` → `generic-logos` (official Fedora-provided replacement)
- `generic-release-notes` added; Fedora 44 does not build a binary package
  named `fedora-release-notes`, so this is not described as a replacement
- `fedora-release` retained because its current preset/runtime payload is the
  validated image basis; text rebranding is applied in `%post`.

**Text-level rebranding** (M32 `%post`):

- `/etc/os-release` — NAME, PRETTY_NAME, ID, LOGO, HOME_URL,
  DOCUMENTATION_URL, SUPPORT_URL, plus `UPSTREAM_BASE="Fedora Linux 44"`
  as an explicit machine-readable attribution field.
- `/etc/issue` + `/etc/issue.net` — login banner rebranded to product
  name only (minimal, like Fedora upstream).
- `/etc/system-release` — overlay to "NoID Privacy Workstation release 44".

**Trademark notice surfaces**:

- Machine-readable: `/etc/os-release` UPSTREAM_BASE field
- Full disclosure: `/usr/share/doc/noid-privacy/trademark-notice.md` (the installed-image version)
- User-visible at first GNOME login: NoID Privacy Setup (M13)
- Repository-level: README, `LICENSING.md` and this file

**Asset-level rebranding** (M32 `%post` — verified from build-host
payload):

- Own logo (`/usr/share/icons/hicolor/{1024,512}x*/apps/noid-privacy-logo.png`,
  `/usr/share/pixmaps/noid-privacy-logo.png`).
- Default wallpaper (`/usr/share/backgrounds/noid-privacy/default.png` +
  `default-dark.png`) — GNOME's `drool-l` / `drool-d` artwork from the
  `gnome-backgrounds` package, redistributed under **CC-BY-SA-3.0** (not an
  original NoID Privacy asset).
- Stock Fedora `bgrt` Plymouth theme with the NoID Privacy watermark at
  `/usr/share/plymouth/themes/spinner/watermark.png`; no custom Plymouth
  theme is shipped.
- GNOME dconf default wallpaper override
  (`/etc/dconf/db/distro.d/40-noid-wallpaper`).

Assets are shipped from the `branding/` directory in the repository and
packed into the live ISO by `scripts/build-iso.sh`. The wrapper verifies the
source manifest, stages only the declared payload behind a loopback-bound HTTP
server, and Module 32 verifies every fetched asset before installation.

### Future packaging

Custom release/logo RPMs could replace the current overlays if the project
later adopts and verifies that packaging model. No version, hosting service or
claim that every upstream Fedora reference will disappear is promised here:
Fedora remains the base distribution and must continue to be attributed.

## Other Trademarks

- **GNOME** is a registered trademark of the GNOME Foundation.
- **Red Hat** and **Red Hat Enterprise Linux** are registered trademarks
  of Red Hat, Inc.
- **Flatpak**, **Flathub** are trademarks of their respective owners.
- **Firefox** is a registered trademark of the Mozilla Foundation.
- **arkenfox/user.js** and **HorlogeSkynet/thunderbird-user.js** identify the
  historical MIT-licensed source snapshots of NoID Privacy's local browser and
  mail derivatives.
- **uBlock Origin** identifies the separately bundled GPL-3.0-or-later
  extension.

All third-party trademarks referenced in this project are the property
of their respective owners. Use of these names is for descriptive
purposes only and does not imply any affiliation or endorsement.

## Licensing

- **NoID Privacy-owned code and machine-readable policy**: GPL-3.0-or-later except
  for the exact GPL-2.0 file-level exceptions inventoried in
  [`LICENSING.md`](../LICENSING.md) (license texts in
  [`COPYING`](../COPYING) and
  [`licenses/GPL-2.0.txt`](../licenses/GPL-2.0.txt))
- **Documentation** (this repository's `docs/`, `README.md`, etc.):
  CC BY-SA 4.0
- **Embedded NoID Privacy Firefox Hardening** (`firefox/noid-firefox-hardening.js`):
  derivative work distributed under MIT, based on arkenfox user.js v144.0
  (upstream attribution retained in-file).
- **Embedded NoID Privacy Thunderbird Hardening**
  (`thunderbird/noid-thunderbird-hardening.js`): HorlogeSkynet-derived MIT
  base with separately marked NoID Privacy override sections as inventoried in
  [`LICENSING.md`](../LICENSING.md).
- **Third-party downloads** (uBlock Origin XPI): upstream license
  (GPL-3.0-or-later)
- **original NoID Privacy branding assets** (logo, Plymouth watermark, app
  icons, avatar in `branding/`): All rights reserved by the NoID Privacy project
  maintainer. Not licensed for redistribution or derivative work as part of
  a different distribution.
- **Default wallpaper** (`branding/wallpaper.png` + `wallpaper-dark.png`):
  GNOME's `drool-l` / `drool-d` artwork from the `gnome-backgrounds` package
  (<https://gitlab.gnome.org/GNOME/gnome-backgrounds>), licensed under
  **CC-BY-SA-3.0**. Attribution required; derivative works must use the
  same license.

## Where to get unmodified Fedora

If you want unmodified Fedora Linux (without NoID Privacy Workstation's
hardening and rebranding), see:

- [Fedora Workstation](https://fedoraproject.org/workstation/) — the
  official GNOME-based Fedora desktop edition.
- [Fedora Spins](https://spins.fedoraproject.org/) — official
  alternative desktop editions (KDE Plasma, Xfce, MATE, etc.).

## Reporting Trademark Concerns

If you believe this project infringes on a trademark, please file an
issue at
[github.com/NexusOne23/noid-privacy-workstation/issues](https://github.com/NexusOne23/noid-privacy-workstation/issues).
