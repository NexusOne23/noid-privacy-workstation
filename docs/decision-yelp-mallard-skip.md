# Engineering Decision: Skip Yelp/Mallard Integration

**Status**: decided — SKIP for the current product line; revisit if user demand
surfaces.

## Context

Yelp is GNOME's help viewer and native Mallard viewer. Integrating NoID Privacy
would require a second, GNOME-specific documentation representation in
addition to the repository's canonical Markdown.

- A future integration would author or generate valid `.page` XML with stable
  page IDs and links, validate it with `yelp-check`, and install it under the
  freedesktop help hierarchy such as `/usr/share/help/C/noid/`. `yelp-build`
  can generate HTML/EPUB output and creates its Mallard cache automatically
  unless an explicit cache is supplied; a hand-maintained
  `mallard-cache.xml` is not a Yelp runtime-install requirement.

## Decision

**SKIP yelp/Mallard integration for the current product line.** Reasoning:

1. `noid-help`, the Setup app's documentation-folder action and the installed
   index already make every guide discoverable.
2. Markdown remains useful from the terminal, through `xdg-open`, and outside
   GNOME.
3. Generated Mallard would add a synchronization, validation, localization and
   rendering contract without demonstrated user demand.

## What we ship instead

- Canonical Markdown in `/usr/share/doc/noid-privacy/`
- `noid-help` list/search/open navigation
- Native folder opening from NoID Privacy Setup
- Task index, cheatsheet and troubleshooting guides

## Revisit criteria

Re-evaluate adding yelp integration if:

- Multiple users explicitly request F1-key / GNOME-Help integration
- We ship a GUI app (not just CLI tools) that would naturally ship
  help files via the GNOME Help spec
- A maintained Markdown-to-Mallard pipeline can eliminate source duplication
  and pass link, localization and install-layout validation

## References

- [GNOME Help (Yelp)](https://apps.gnome.org/Yelp/)
- [GNOME yelp-tools source](https://gitlab.gnome.org/GNOME/yelp-tools)
- [Archived GNOME yelp-build documentation](https://wiki.gnome.org/Apps%282f%29Yelp%282f%29Tools%282f%29yelp%282d%29build.html)
