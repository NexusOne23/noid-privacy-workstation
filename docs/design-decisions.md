# Design Decisions — Why NoID Privacy Workstation 44 uses neither global hardened_malloc nor an immutable base, and does not claim a reproducible ISO

These are the three decisions where NoID Privacy diverges from the closest peer projects (Kicksecure, secureblue). Each is a deliberate trade-off, documented with sources so you can audit the rationale and overrule it if your threat model differs.

---

## 1. No `hardened_malloc`

NoID Privacy does not activate `hardened_malloc` globally because the shipped
Fedora Firefox build uses `mozjemalloc`, and globally preloading a replacement
allocator has a documented crash/incompatibility history. A representative
failure is:

```
fatal allocator error: invalid uninitialized allocator usage
Redirecting call to abort() to mozalloc_abort
```

The incompatibility is tracked in [Mozilla Bugzilla #1668674](https://bugzilla.mozilla.org/show_bug.cgi?id=1668674), [hardened_malloc Issue #123](https://github.com/GrapheneOS/hardened_malloc/issues/123), and [Red Hat Bugzilla #2260766](https://bugzilla.redhat.com/show_bug.cgi?id=2260766). Rebuilding Firefox with a compatible allocator configuration would replace Fedora's reviewed binary with a project-maintained browser build and its associated update burden. That is outside the current release scope.

**secureblue takes a different browser path** through [Trivalent](https://github.com/secureblue/Trivalent), a Chromium-derived browser. NoID Privacy deliberately keeps **Firefox + its absorbed arkenfox-derived configuration + full uBlock Origin**, because:

- Anthropic reports that its Mozilla collaboration found 22 Firefox
  vulnerabilities, including 14 rated high severity, after scanning nearly
  6,000 C++ files. It says most were fixed in Firefox 148 and the remainder
  were scheduled for later releases; this document does not turn that into an
  “all fixed in 148” claim.
- Mozilla reports that Firefox 150 included fixes for 271 additional
  vulnerabilities identified with Claude Mythos Preview. Those 271 findings
  are not represented here as 271 independently assigned CVEs or as a proof
  that all Firefox vulnerability classes are exhausted.
- Full **uBlock Origin** [no longer runs in Chrome since July 24, 2025](https://developer.chrome.com/docs/extensions/develop/migrate/mv2-deprecation-timeline) (MV2 disabled in Chrome 138, completely removed in Chrome 139). Chromium users only get **uBO Lite** with the `declarativeNetRequest` API and pre-approved rule-sets. Firefox continues parallel MV2 + MV3 support with `webRequest` — full uBO stays functional.
- [`arkenfox/user.js`](https://github.com/arkenfox/user.js) is the historical
  basis of the absorbed Firefox preferences in this repository. That does not
  imply that no other serious browser-hardening project exists.
- The browser remains a major attack surface. Palo Alto Networks' 2026 Unit 42
  report says browser activity played a role in 48% of its investigations;
  this is that incident-response dataset, not a universal internet rate.

The decision is therefore a product trade-off: keep Fedora's signed Firefox
update path and full uBO support instead of globally preloading an allocator
known to conflict with that browser build. This does not claim that Firefox is
universally safer than Trivalent or that allocator hardening has no value.

---

## 2. No Immutable (no `ostree` / `rpm-ostree`)

NoID Privacy stays on mutable Fedora + btrfs + LUKS + Snapper because two workflow-core requirements collide with ostree-based atomic distros without justified friction:

**Developer- and admin-workflow.** Host package layering on an rpm-ostree
system normally creates a new deployment for the next boot; supported live-apply
paths and containers cover some use cases but do not turn it into ordinary
mutable-DNF administration. Layered packages also become part of rebase and
deployment management. Toolbox/Distrobox is a valid answer for most development
work, but adds a container boundary and makes some system-near operations less
direct. NoID Privacy chooses the mutable workflow as a product trade-off, not because
Atomic systems are incapable of developer work.

**NVIDIA proprietary + Local-AI.** NVIDIA drivers can work on Atomic Fedora
derivatives, and projects such as Universal Blue provide dedicated NVIDIA image
variants. Their signed image/driver workflow is a different operational model
from iterating directly on a mutable host. NoID Privacy accepts the mutable-host risk
and maintenance burden because direct DNF, akmods and CUDA/toolkit work are
core product workflows; this is not a claim that Atomic NVIDIA support is
broken.

Snapper on Btrfs provides an overlapping rollback function, but it is **not
structurally equivalent** to an authenticated, content-addressed atomic image.
The NoID Privacy workflow creates a pre-change snapshot when that operation succeeds,
runs cleanup timers, and exposes the checked `noid-snap-rollback` wrapper over
Snapper's maintained classic rollback. It provides:

- Root-subvolume rollback of captured system state
- A short-lived system-snapshot history (not tamper-proof evidence)
- Package transactions modify the current mutable root directly; kernel and
  core-library updates can still require or recommend a reboot before every
  updated component is in use
- No layering friction
- Direct `dnf` workflow

What we lose versus ostree: non-atomicity at file-tree level (Snapper-rollback is subvolume-level, not content-addressed), no image-mode boot. For our threat model (privacy + hardening + auditability on a single workstation, not server-fleet management or kiosk-lockdown), that's the right trade-off choice.

---

## 3. No established byte-reproducible ISO

The project has **not demonstrated byte-for-byte reproducibility of complete
ISOs**, even for two builds started close together. `SOURCE_DATE_EPOCH`, a fixed
volume ID, UTC, and fixed language-runtime hash seeds reduce variance; they do
not prove that Lorax, Anaconda, RPM scriptlets, filesystem creation, package
resolution, and signing are deterministic as a pipeline.

Cross-time equality is additionally prevented by the current input model:

1. Fedora metalinks and updates are moving inputs, and this repo does not pin a
   complete compose/repository snapshot.
2. There is no lockfile mapping every selected NEVRA and repository metadata
   object to immutable bytes.
3. Build and signing tools can introduce further nondeterministic data.

Release `SHA256SUMS`, an optional exact-key detached signature, package lists,
logs, and the source revision support investigation. They are not an
independently reproducible audit trail, and commit signatures are not claimed
without verifying the specific commit. The measurable procedure and current
limits are in [`build-reproducibility.md`](build-reproducibility.md).

---

## Sources

### `hardened_malloc`
- [Anthropic — Partnering with Mozilla to improve Firefox's security](https://www.anthropic.com/news/mozilla-firefox-security)
- [Mozilla Blog — Hardening Firefox with Anthropic's Red Team](https://blog.mozilla.org/en/firefox/hardening-firefox-anthropic-red-team/)
- [Red Team (red.anthropic.com) — Firefox audit deep-dive](https://red.anthropic.com/2026/firefox/)
- [Mozilla Hacks — Behind the Scenes Hardening Firefox with Claude Mythos Preview (April 2026, 271 bugs in FF150)](https://hacks.mozilla.org/2026/05/behind-the-scenes-hardening-firefox/)
- [Mozilla Blog — The zero-days are numbered (Claude Mythos defenders-can-finally-find-them-all)](https://blog.mozilla.org/en/privacy-security/ai-security-zero-day-vulnerabilities/)
- [Mozilla MFSA 2026-30 — Firefox 150 security advisory](https://www.mozilla.org/en-US/security/advisories/mfsa2026-30/)
- [Mozilla Bugzilla #1668674 — Tab crash: uninitialized allocator usage](https://bugzilla.mozilla.org/show_bug.cgi?id=1668674)
- [Red Hat Bugzilla #2260766 — Build Firefox with support for replacing the malloc](https://bugzilla.redhat.com/show_bug.cgi?id=2260766)
- [GrapheneOS hardened_malloc Issue #123 — upstream Firefox bug](https://github.com/GrapheneOS/hardened_malloc/issues/123)
- [secureblue Issue #1604 — Firefox/Flatseal LD_PRELOAD workaround](https://github.com/secureblue/secureblue/issues/1604)
- [Arch Wiki — hardened_malloc](https://wiki.archlinux.org/title/Security#Hardened_malloc)
- [Google Chrome for Developers — Manifest V2 deprecation timeline](https://developer.chrome.com/docs/extensions/develop/migrate/mv2-deprecation-timeline)
- [uBlock Origin — browser support matrix](https://github.com/gorhill/uBlock/wiki/uBlock-Origin-works-best-on-Firefox)
- [arkenfox/user.js](https://github.com/arkenfox/user.js)
- [2026 Unit 42 Global Incident Response Report — browser activity in its investigation set](https://www.paloaltonetworks.com/resources/research/unit-42-incident-response-report)

### Immutable / `rpm-ostree`
- [RPM Fusion HowTo NVIDIA + Silverblue/Atomic](https://rpmfusion.org/Howto/NVIDIA)
- [Universal Blue ublue-os/akmods](https://github.com/ublue-os/akmods)
- [Toolbox project](https://containertoolbx.org/)
- [Distrobox project](https://github.com/89luca89/distrobox)
- [Snapper documentation](http://snapper.io/)

### Reproducible builds
- [Fedora Wiki — Changes/Package_builds_are_expected_to_be_reproducible](https://fedoraproject.org/wiki/Changes/Package_builds_are_expected_to_be_reproducible)
- [Fedora Wiki — Changes/ReproducibleBuildsClampMtimes](https://fedoraproject.org/wiki/Changes/ReproducibleBuildsClampMtimes)
- [reproducible-builds.org — SOURCE_DATE_EPOCH specification](https://reproducible-builds.org/docs/source-date-epoch/)
- [reproducible-builds.org — Monthly report January 2026](https://reproducible-builds.org/reports/2026-01/)
- [rebuilderd](https://github.com/kpcyrd/rebuilderd)
- [Debian Wiki — ReproducibleBuilds (mandatory in Forky, May 2026)](https://wiki.debian.org/ReproducibleBuilds)
- [reproduce.debian.net](https://reproduce.debian.net/)
- [snapshot.debian.org](https://snapshot.debian.org/) (Debian's package-archive service; no Fedora equivalent)
