# GPG + Repository Trust Chain

Documents every external cryptographic trust anchor the image relies on,
the attestation mechanism, and what happens if a trust anchor is
compromised.

## Trust anchors

### 1. Fedora 44 package signing

- **Key**: Fedora 44 RPM-GPG-KEY-fedora-44-x86_64
  (`/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-x86_64`)
- **Fingerprint**: `36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6`
  (verify against <https://fedoraproject.org/security/>)
- **Shipped**: via Fedora installer; present in base Fedora 44.
- **Enforcement**: `gpgcheck=1` in `/etc/yum.repos.d/fedora*.repo`.
- **Boundary**: signature verification authenticates the configured Fedora
  signing authority; it does not prove that a legitimately signed package is
  bug-free or non-malicious. AIDE detects later file drift, not malicious
  behavior in an accepted baseline; SELinux only constrains allowed actions.

### 2. RPM Fusion (free + nonfree)

- **Installed**: Module 08 downloads the Fedora 44 release RPMs once.
  - `https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-44.noarch.rpm`
  - `https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-44.noarch.rpm`
- **Pinned fingerprints**: free
  `E9A491A3DE247814E7E067EAE06F8ECDD651FF2E`; nonfree
  `79BDB88F9BBF73910FD4095B6A2AF96194843C65`.
- **Bootstrap**: Module 08 extracts each key, checks the full fingerprint,
  imports it, verifies the release RPM signature with `rpmkeys -Kv`, and
  installs those same verified RPM bytes. Any bootstrap failure aborts.
- **Repository enforcement**: payload `gpgcheck=1`; the locally stored,
  fingerprint-verified key is referenced by file URL.

### 3. VSCodium repository (paulcarroty GitLab raw)

- **Key URL**: `https://gitlab.com/paulcarroty/vscodium-deb-rpm-repo/-/raw/master/pub.gpg`
- **Pinned fingerprint**: `1302DE60231889FE1EBACADC54678CF75A278D9C`.
- **Imported in**: Module 08
- **Enforcement**: `gpgcheck=1` + `repo_gpgcheck=1` (stricter than most
  third-party Fedora repos — the repo metadata itself is signed).
- **Bootstrap**: the downloaded key must match the full fingerprint and is
  persisted locally. The repo references only that local file. A pre-staged
  RPM is explicitly signature-checked; remote DNF uses the same pinned key.
  Key rotation requires a reviewed source change and new release.
- **DNF5 metadata-key caches**: DNF5 stores `repo_gpgcheck` keys separately
  from RPM package-signing keys, separately per repository, and in different
  root and unprivileged-user caches. Importing the key into the RPM database
  therefore cannot suppress every metadata-key prompt by itself. Module 08's
  offline `noid-vscodium-repo-key-seed` helper validates the pinned local key
  again and reconciles it into the exact libdnf5 cache before metadata is
  loaded. A DNF actions hook covers the invoking CLI cache and GNOME Software's
  native `/var/cache/dnf5daemon-server` cache after cleanup; a sandboxed user
  unit prepares the normal user's cache. Neither path fetches a key or
  accepts trust on first use. Root actions keep their root-owned validation evidence
  under `/var/lib/noid-privacy`, not in `/root`, so package-install services
  retain `ProtectHome=yes`; unprivileged actions keep separate XDG user state.
  This separation and the possibility of repeated import prompts are documented in the
  [DNF5 configuration reference](https://dnf5.readthedocs.io/en/stable/dnf5.conf.5.html#repo-options).

### 4. Flathub

- **Descriptor**: `manifests/flathub.flatpakrepo`, reviewed at 4,040 bytes and
  SHA-256 `3371dd250e61d9e1633630073fefda153cd4426f72f4afa0c3373ae2e8fea03a`.
  Module 18 embeds those exact bytes and never accepts an existing remote name.
- **Key**: full fingerprint
  `6E5C05D979C76DAF93C081354184DD4D907A7CAE`; canonical public export is 2,844
  bytes with SHA-256
  `8bdc20abc4e19c0796460beb5bfe0e7aa4138716999e19c6f2dbdd78cc41aeaa`.
  Local GnuPG trust-cache packets are excluded from the identity comparison.
- **Imported**: both `flathub` and `flathub-verified` are recreated from the
  pinned local descriptor on the ref-free compose root. A hostile pre-existing
  name, extra remote, wrong URL/subset/priority or changed key fails closed.
- **Enforcement**: Flatpak GPG-verifies commits and summaries. Compose requires
  non-empty online catalogs and retains their cache as same-build evidence for
  its final local gate. The three lifecycle gates query both current signed
  catalogs online because Flatpak may legitimately evict cached summaries
  after ordinary transactions; cache presence is not durable trust state.
- **Boundary**: a trusted malicious app/commit remains possible. Flatpak
  permissions and portals reduce but do not eliminate impact; the image prefers
  the verified subset but deliberately keeps the full catalog available.

### 5. NoID Privacy Firefox Hardening (Module 16, arkenfox-derived)

- **Source**: `firefox/noid-firefox-hardening.js` checked into this
  repository (derivative of arkenfox v144.0, MIT — absorbed 2026-04-22).
- **Verification**: `scripts/regen-firefox-embed.sh --check` enforces
  that the M16 embedded gzip+base64 blob matches the source file. CI
  runs this on every push.
- **Trust mode**: in-repo git history. Neither the image build nor the runtime
  updater downloads or imports an upstream arkenfox `user.js`; upstream
  movement requires a deliberate review and repository change.
- **Failure mode**: malicious commit to this repo. Mitigation: review
  the diff to `firefox/noid-firefox-hardening.js` like any other code
  change; upstream arkenfox v144.0 is the reference snapshot.

### 6. NoID Privacy Thunderbird Hardening (Module 35, HorlogeSkynet-derived)

- **Source**: `thunderbird/noid-thunderbird-hardening.js` checked into this
  repository (reviewed derivative of tagged HorlogeSkynet v140.2, MIT base).
- **Verification**: `scripts/regen-thunderbird-embed.sh --check` enforces
  byte parity with M35; structural/runtime tests validate the NoID Privacy composition
  and post-v140.2 Thunderbird preferences.
- **Trust mode**: in-repo git history. Neither build nor Update All fetches an
  upstream Thunderbird `user.js`; upstream movement requires manual review.
- **Failure mode**: malicious or mistaken repository change. Review the
  canonical source diff, provenance and the complete affected preference
  contract; the generator authenticates local parity, not correctness.

### 7. uBlock Origin (Module 16)

- **Source**: GitHub release
  `gorhill/uBlock/releases/download/1.73.0/uBlock0_1.73.0.firefox.signed.xpi`
- **Verification**: SHA256 of the XPI verified against constant.
- **XPI internal signature**: Mozilla AMO signs the XPI (Raymond Hill
  is an AMO-approved publisher). Browser checks this on install.
- **Failure mode**: runtime upstream replacement cannot change the pinned image
  seed without a SHA mismatch. A user-started Update All run may advance later
  uBO versions through the fixed official release channel only after digest,
  identity, compatibility and Firefox native-signature validation. That channel
  remains upstream trust; the signature proves publisher authorization, not
  benign behavior.

### 8. ProtonVPN repository (user opt-in, Module 13 installer / Module 29 docs)

- **Key URL**: <https://repo.protonvpn.com/fedora-$releasever-stable/public_key.asc>
  (Fedora 44: <https://repo.protonvpn.com/fedora-44-stable/public_key.asc>)
- **Pinned fingerprint**: `6929133BDE1CE1CFA9EDB286D84176F6844830D4`
  (pinned in the `noid-protonvpn-install` helper,
  `kickstart/snippets/13-aide-welcome.ks`). Re-verify any announced or
  observed rotation against
  <https://protonvpn.com/support/official-linux-vpn-fedora> before changing it.
- **Bootstrap**: nothing is imported at build time — the image ships no
  third-party VPN trust root (provider-neutral by design; see
  `kickstart/master.ks`). When the user opts in via the setup app's
  "Install Proton VPN" row (`noid-protonvpn-install`), the installer fetches
  the key, verifies its full primary fingerprint against the pin **before**
  `rpmkeys --import`, stores it at `/etc/pki/rpm-gpg/RPM-GPG-KEY-protonvpn`,
  writes Proton's canonical repo definition, and aborts on fetch failure or
  fingerprint mismatch. `docs/protonvpn-installation-guide.md` Step 1 directs
  users through that same shipped helper instead of duplicating a weaker
  manual bootstrap. The `--uninstall` path removes the repo file (key left in
  the trust store).
- **Enforcement**: `gpgcheck=1` in the installed
  `protonvpn-fedora-stable.repo`; `repo_gpgcheck=0` matches Proton's own
  published repo definition (they publish no signed repodata) — every RPM is
  still signature-checked against the pinned key.

### 9. Secure Boot chain (runtime)

- Firmware `db`/`dbx`, the installed Fedora shim/GRUB/kernel signatures, and
  local MOK state together determine the effective chain. Firmware contents and
  revocations vary by machine and update state; the image does not claim one
  universal Microsoft-CA inventory.
- Module 01 requests `lockdown=integrity` and module-signature enforcement, but
  runtime verification (`mokutil`, kernel lockdown state, loaded-module signer)
  remains required.
- `rd.emergency=halt` removes one recovery-shell path; it does not repair or
  independently prove the firmware/shim trust chain.

### 10. NoID Privacy release-signing key (release ISO + SHA256SUMS)

- **Key**: NoID Privacy Workstation Release Signing Key (Ed25519 [SC]).
- **Fingerprint**: `1ACBFCE49687FEBB91010E52F8E3F11D6962256F`
  (cross-check through an independent public channel; see Trust mode below).
- **Published**: <https://noid-privacy.com/downloads/noid-privacy-release.asc>
  (also referenced from `.well-known/security.txt`).
- **Signs**: the detached `SHA256SUMS.asc` over the release ISO's `SHA256SUMS`.
  This is the anchor a user checks before booting an ISO:
  `gpg --import noid-privacy-release.asc` → `gpg --verify SHA256SUMS.asc
  SHA256SUMS` → `sha256sum -c SHA256SUMS`.
- **Trust mode**: sign-only (not an encryption key). First acquisition still
  needs an independent fingerprint channel; this repository alone is not that
  independent channel.
- **Failure mode**: loss of the secret key → revoke via the offline revocation
  certificate + cut a new key; compromise → an attacker could sign a malicious
  ISO. Offline key custody/revocation readiness is an operator procedure that
  source review cannot verify. `scripts/archive-build.sh` pins
  `RELEASE_SIGNING_FPR` and requires exactly one matching valid signature on
  both `SHA256SUMS.asc` and `vm-test-signoff.txt.asc`; `scripts/build-iso.sh`
  only produces unsigned candidates and rejects `NOID_REQUIRE_SIGNATURE`.

### 11. negativo17 Fedora Multimedia (DisplayLink, user opt-in)

- **Key URL**: <https://negativo17.org/repos/RPM-GPG-KEY-slaanesh>
- **Pinned fingerprint**: `0C5D0F470484AE2FC40A9B6597F3008993E8909B`
  (pinned in the `noid-install-displaylink` installer,
  `kickstart/snippets/14-usbguard.ks`).
- **Bootstrap**: nothing is imported at build time. When the user opts in via
  `sudo noid-install-displaylink`, the installer fetches the key, verifies the
  full fingerprint against the pin before `rpmkeys --import`, stores it at
  `/etc/pki/rpm-gpg/RPM-GPG-KEY-negativo17`, and aborts on fetch failure or
  fingerprint mismatch. The uninstall path removes the repo file and deletes
  the imported key when no other repository shares it (ownership ledger).
- **Enforcement**: `gpgcheck=1` in the restricted
  `noid-displaylink-negativo17.repo`; `repo_gpgcheck=0` because negativo17
  publishes no signed repodata — the closed `includepkgs` namespace bounds
  what unsigned metadata can offer, and every RPM is still signature-checked.

### 12. Mullvad VPN repository (user opt-in, Module 13 installer)

- **Key URL**: <https://repository.mullvad.net/rpm/mullvad-keyring.asc>
- **Pinned fingerprint**: `A1198702FC3E0A09A9AE5B75D5A1D4F266DE8DDF`
  (Mullvad code-signing key, pinned in the `noid-mullvad-install` helper,
  `kickstart/snippets/13-aide-welcome.ks`). The current keyring contains exactly
  one primary key; the installer rejects any different or additional primary
  key before trusting the keyring. Re-verify any rotation against
  <https://mullvad.net/en/help/verifying-signatures> before changing it.
- **Bootstrap**: nothing is imported at build time. When the user opts in via
  the setup app's "Install Mullvad VPN" row (`noid-mullvad-install`), the
  installer fetches the keyring, confirms that its sole primary key has the
  pinned code-signing fingerprint **before** `rpmkeys --import`, stores it at
  `/etc/pki/rpm-gpg/RPM-GPG-KEY-mullvad`, writes Mullvad's canonical repo
  definition, and aborts on fetch failure or a missing, different or additional
  primary key. The `--uninstall` path removes the repo file (key left in the
  trust store).
- **Enforcement**: `gpgcheck=1` in the installed `mullvad-stable.repo`
  (matching Mullvad's own published repo definition); every RPM is
  signature-checked against the imported keyring.

## What happens if a trust anchor is compromised?

| Anchor | Local detection/control | Response |
|--------|-------------------------|----------|
| Fedora | RPM signature verification | disable affected repo/package path; follow Fedora rotation/advisory procedure |
| RPM Fusion | full fingerprint + release-RPM signature gate | abort build; review and re-pin an announced rotation |
| VSCodium | full fingerprint, local-key repo, RPM signature | abort build/update; disable repo until reviewed |
| Flathub | OSTree verification + sandbox policy | disable remote; assess installed refs and upstream response |
| Firefox hardening | source/embed byte-identity CI gate | reject drift; review source change and regenerate |
| uBO | pinned SHA256 + size + XPI signature | abort build; review and pin a new release |
| ProtonVPN | full fingerprint verified before import by `noid-protonvpn-install` (plus optional manual comparison for hand installs) | do not import; abort install on mismatch; update the pin only after reviewing Proton's official rotation notice |
| negativo17 (DisplayLink) | full fingerprint verified before import by `noid-install-displaylink` | abort install; uninstall path removes repo + imported key; review announced rotation before re-pin |
| Mullvad VPN | sole primary key must equal the pinned code-signing fingerprint before import by `noid-mullvad-install` | abort install on a missing, different or additional primary key; review announced rotation before re-pin |
| Secure Boot authorities | firmware/shim/kernel runtime inspection | apply vendor/Fedora revocations and verify chain again |
| NoID Privacy release key | expected-secret-key fingerprint + detached signature | stop release; revoke/rotate according to operator procedure |

## Adding a new trust anchor (contributor guidance)

Every new external dependency MUST:

1. Bind the fetched bytes to an immutable content identity: for example, a
   commit/OSTree digest, an exact signed RPM NEVRA, or an exact file size plus
   SHA-256. A version label or release tag alone can move and is not an
   immutable content identity.
2. Verify authenticity with the format's maintained mechanism where one
   exists: an upstream signature/checksum, RPM repository/package signatures,
   or an OSTree commit signature. A locally calculated hash proves byte
   identity only when the expected value came through a trusted channel.
3. Document the trust anchor here (add row to table).
4. Add a test in `tests/33-config-validation.sh` or equivalent that
   fails if the verify step is missing.

Failure to meet these mandatory supply-chain pinning requirements rejects the
change.
