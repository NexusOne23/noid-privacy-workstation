# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` (v1.7 release line) | :white_check_mark: (active maintained line) |
| v1.7 | :white_check_mark: (current Fedora 44 release line) |
| v1.6 and older | :x: (upgrade to the supported line) |

Support is scoped to the v1.7/Fedora 44 release and the `main` release line
until a successor and its support window are explicitly recorded here. Do not
infer future versioning or end-of-life dates from Fedora's release number
alone.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately via one of:

1. **GitHub Security Advisory** (preferred):
   If this repository shows `Security → Advisories → Report a vulnerability`,
   submit the report there. GitHub documents this as private vulnerability
   reporting to repository maintainers; the reporter and explicitly added
   advisory collaborators can participate in the private discussion. This is
   not described here as end-to-end encryption. See GitHub's official
   [private-reporting documentation](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-a-vulnerability/privately-reporting-a-security-vulnerability).

2. **Email**: Use the address listed in the maintainer profile. Treat ordinary
   email as ordinary transport. Use PGP only after independently obtaining and
   verifying the maintainer's current fingerprint; this policy does not assert
   that a particular profile or key service is authoritative.

## What to include

- Affected version (git ref or release tag).
- Affected Module / file / line range.
- Exact reproduction steps: kickstart build command, any post-install
  actions, observed behavior.
- Expected vs actual security impact.
- Suggested mitigation (optional).

## Response time goals (not an SLA)

| Severity       | First response | Fix + advisory |
|----------------|----------------|----------------|
| Critical (RCE, key/secret leak) | within 72 h | within 14 days |
| High (privesc, sandbox escape)  | within 5 d  | within 30 days |
| Medium (info leak, DoS)         | within 10 d | within 60 days |
| Low (hardening gap)             | within 14 d | best-effort    |

## Scope

**In scope**: vulnerabilities in any repository-owned source, configuration,
build/release tooling, test gate, manifest, artwork integration or shipped
documentation, including integration defects that weaken advertised guarantees
in [`docs/threat-model.md`](docs/threat-model.md).

**Out of scope**:

- Bugs in upstream Fedora packages (report to the relevant Fedora package
  maintainer or upstream project directly).
- Defects confined to unchanged upstream arkenfox, HorlogeSkynet, uBlock
  Origin or DKIM Verifier releases (report those to the respective upstream).
  A defect in NoID Privacy's carried derivatives, selected release, integration,
  update logic or advertised configuration remains in scope here, even when
  the affected bytes originated upstream.
- Bugs in the Linux kernel, GNOME, KDE, firewalld, NetworkManager, systemd
  (report to their respective upstream security teams).
- Hardware-level issues (Intel ME firmware, UEFI/BIOS, AMD PSP) that the
  image can only partially mitigate (see [`docs/scope.md`](docs/scope.md)).

## Disclosure policy

Coordinated disclosure. After a fix is merged, a public security advisory is
filed with:

- CVE identifier (requested from MITRE via GitHub's CNA workflow if needed)
- CVSS vector score
- Affected + fixed versions
- Mitigations for users who cannot upgrade immediately
- Credits to the reporter (unless anonymity is requested)

## Supply-chain integrity

The image necessarily consumes precompiled RPMs and selected external
artifacts. Fedora/RPM Fusion/vendor repositories remain upstream trust
boundaries. Repository-owned external payloads are pinned and verified as
documented; that does not make their source or build process independently
reproducible.
NoID Privacy Firefox Hardening — derived from the reviewed arkenfox v144.0
snapshot under MIT — is
checked into the repository at `firefox/noid-firefox-hardening.js` and
embedded into M16 as a gzip+base64 blob regenerated via
`scripts/regen-firefox-embed.sh` (Thunderbird hardening analogously at
`thunderbird/noid-thunderbird-hardening.js` → M35).
Those generators only republish the reviewed local canonical files; they do
not contact or merge either upstream. Update All likewise reapplies the local
derivatives and updates authenticated browser add-on packages separately.

Repository-managed non-RPM payload inputs include the **uBlock Origin** and
**DKIM Verifier** XPIs, the **Just-Perfection** GNOME Shell extension archive
and the M40 **NoID Privacy for Linux** auditor payload. The browser XPIs and
Just-Perfection archive are selected by release version and required SHA-256;
Just-Perfection has no separate upstream artifact signature, so its reviewed
byte pin is the only artifact-authentication gate. The canonical ISO builder
stages the auditor byte-for-byte from a public raw URL containing its full,
immutable Git commit; controlled CI/offline paths may supply the same bytes
from an exact clean checkout. The commit-qualified source, byte count and
SHA-256 must all match, and no downstream patch stack is applied. Fedora, RPM Fusion and configured vendor repositories
remain separate signed-package trust boundaries.
A digest proves that the bytes match the reviewed selection; it is not
independent proof of upstream authorship or reproducible provenance. Any
selection/digest mismatch aborts before the payload is accepted into the image;
see M16, M35, M40 and `scripts/build-iso.sh`.

This repository vendors no upstream third-party source tree. Design-time
hardening review uses `kernel-hardening-checker` from its own upstream
checkout; nothing of it is stored here or shipped. Mutter is installed
unchanged from Fedora; NoID Privacy does not carry a local Mutter source or
RPM override. Full license + provenance accounting is in
[`LICENSING.md`](LICENSING.md).

To independently verify: compute SHA256 of the uBO upstream XPI at the
pinned release tag and compare to the constants in `16-firefox.ks`. For
the Firefox user.js, review `firefox/noid-firefox-hardening.js` directly
(the MIT attribution to arkenfox is retained in-file).

## Hardening guarantees and limitations

See [`docs/threat-model.md`](docs/threat-model.md) for the detailed threat
model, and [`docs/scope.md`](docs/scope.md) for explicit out-of-scope
attacker classes.
