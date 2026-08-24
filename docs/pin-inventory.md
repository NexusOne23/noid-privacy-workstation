# Pin Inventory — every pinned artifact and how to refresh it

Every third-party artifact that enters the image is pinned at its source:
by exact version, SHA-256 and (for large binaries) byte count, fetched only
from its official channel. This page lists **where each pin lives and how to
refresh it** — it deliberately names no current versions, so it cannot drift
when a pin is bumped. The pinned values themselves live in the listed files;
the shipped image additionally records its full RPM set in
`/usr/share/doc/noid-privacy/package-manifest.txt`. Exact artifacts retained
only as reviewed opt-in installation guidance are inventoried too; they are not
downloaded, installed or cached by the image build.

## Inventory

| Artifact | Official channel | Pin locations |
|---|---|---|
| Claude Code CLI | downloads.claude.ai | `kickstart/snippets/13-aide-welcome.ks` (installer; consent-gated updates then follow the vendor channel) |
| Codex CLI (musl tarball) | github.com/openai/codex releases | `kickstart/snippets/13-aide-welcome.ks` (installer; consent-gated updates then follow the vendor channel) |
| Claude Code IDE extension (VSIX) | open-vsx.org | M13 installer opt-in (no image pre-stage; consent-gated updates) |
| ChatGPT/Codex IDE extension (VSIX) | open-vsx.org | M13 installer opt-in (consent-gated updates) |
| uBlock Origin XPI (signed) | github.com/gorhill/uBlock releases | `kickstart/snippets/16-firefox.ks` (three uses), `kickstart/snippets/99-finalize.ks`, `scripts/offline-prep.sh`, `scripts/build-offline.sh`, `scripts/build-iso.sh` |
| DKIM Verifier XPI | github.com/lieser/dkim_verifier releases | `kickstart/snippets/35-thunderbird.ks`, `kickstart/snippets/25-update-process.ks` |
| Just Perfection shell extension | extensions.gnome.org | `kickstart/snippets/17-gnome-hardening.ks`, `kickstart/snippets/25-update-process.ks` |
| arkenfox user.js base | github.com/arkenfox/user.js | canonical `firefox/noid-firefox-hardening.js` (version in header); `regen`-checked into M16 |
| thunderbird-user.js base | github.com/HorlogeSkynet/thunderbird-user.js | canonical `thunderbird/noid-thunderbird-hardening.js`; `regen`-checked into M35 |
| noid-privacy-linux audit tool | public GitHub source at an exact immutable commit | `kickstart/snippets/40-audit-bundle.ks`, `scripts/build-iso.sh`, `scripts/build-audit-support-media.sh`; parity-gated by `tests/40` against version/commit/bytes/size/SHA; the canonical ISO builder fetches the commit-qualified raw URL, while CI and offline support-media paths use a clean exact-commit checkout |
| actions/checkout | github.com/actions/checkout releases | `.github/workflows/ci.yml` (every use is pinned to one reviewed full commit; Dependabot monitors the release line) |
| Fedora base netinst ISO | Fedora mirrors + GPG-signed CHECKSUM | `scripts/verify-fedora-base-iso.sh` is the filename/release/size/SHA/fingerprint authority; `scripts/fedora-base/` retains the exact signed CHECKSUM |
| Fedora Firefox launcher payload | Fedora-signed `firefox` RPM | `kickstart/snippets/16-firefox.ks` binds the exact pristine `/usr/bin/firefox` payload digest before deriving the NoID Privacy-owned launcher; `tests/16-firefox-structural.sh` gates the hash and derivation contract |
| Fedora Thunderbird launcher payload | Fedora-signed `thunderbird` RPM | `kickstart/snippets/35-thunderbird.ks` binds the exact pristine `/usr/bin/thunderbird` payload digest before deriving the NoID Privacy-owned launcher; `tests/35-thunderbird-structural.sh` gates the hash and derivation contract |
| Canonical Anaconda log grammar | the authenticated Fedora base netinst above | `manifests/compose-log-policy-v1.json`; its closed bindings are machine-checked against policy ID, scope and exact version marker by `scripts/audit-compose-log.py` |
| Anaconda Live required-space overlay | Fedora-signed `anaconda-core` and `anaconda-live` RPMs | `kickstart/snippets/17-gnome-hardening.ks` binds both exact NEVRAs, RPM payload metadata and the two vendor source hashes; canonical derivative `overrides/anaconda/live-os-initialization.py`, `scripts/regen-liveinst-required-space-embed.sh`, Lorax patch `overrides/lorax/0002-precompute-live-required-space.patch`, and the M17/Lorax semantic tests keep the vendor base and generated overlay synchronized |
| Lorax compose overrides | Fedora-signed `lorax` and `lorax-templates-generic` RPMs installed on the build host | `scripts/stage-lorax-overrides.sh` (closed system RPM configuration, exact NEVRA, clean complete RPM verification/inventory and all three Python source SHA-256 values), `scripts/stage-lorax-templates.sh` (the same gates for both x86 GRUB sources and complete generic template inventory), `overrides/lorax/0001-drain-monitor-before-shutdown.patch` through `overrides/lorax/0004-live-menu-default.patch`, and the three Python semantic verifiers |
| TuneD PPD profile map | Fedora-signed `tuned-ppd` RPM | `kickstart/snippets/27-hardware-tuning.ks` binds the package-owned `/etc/tuned/ppd.conf` byte count and digest before replacing its complete semantic map with the reviewed NoID Privacy child-profile mapping; `tests/27-hardware-tuning-structural.sh` gates both contracts |
| Optional local-AI evaluation artifacts (Ollama archive, llama.cpp Vulkan archive, llama-vscode VSIX) | official GitHub releases and open-vsx.org | canonical `docs/28-local-ai.md`, generated `kickstart/snippets/28-local-ai-docs.ks`, and `tests/28-local-ai-structural.sh`; documentation-only review pins, never image downloads |
| Local-AI reference GGUFs (Gemma4 and Ornith) | immutable publisher revisions on huggingface.co | canonical `docs/28-local-ai.md`, generated `kickstart/snippets/28-local-ai-docs.ks`, and `tests/28-local-ai-structural.sh`; reproduced reference-host records pinned by revision, size and SHA-256, never image downloads |
| LAN-XDP BPF object | built from in-repo `overrides/noid-lan-xdp/*.bpf.c` | `.b64` blob + `OBJECT_SHA256` in `kickstart/snippets/03-firewalld.ks` (twice) and `overrides/noid-lan-xdp/noid-lan-xdp.sh` |
| Proton VPN signing key fingerprint | repo.protonvpn.com | `kickstart/snippets/13-aide-welcome.ks` (`noid-protonvpn-install`; fingerprint verified before import, repo install then follows the vendor channel) |
| Mullvad code-signing key fingerprint | repository.mullvad.net | `kickstart/snippets/13-aide-welcome.ks` (`noid-mullvad-install`; the sole primary key must equal the pinned fingerprint before import) |
| GPG key fingerprints | key owners (VSCodium, RPM Fusion ×2, Fedora 44, negativo17, Flathub, NoID Privacy release key, Proton VPN, Mullvad) | `08-service-minimization.ks`, `13-aide-welcome.ks`, `14-usbguard.ks`, `18-flatpak-sandboxing.ks`, `scripts/verify-fedora-base-iso.sh`, `scripts/build-audit-support-media.sh`, `scripts/archive-build.sh` |

## Browser hardening snapshot contract

The arkenfox and HorlogeSkynet rows are reviewed **source snapshots**, not
runtime dependencies or mutable vendor feeds. No build, first-login or Update
All path downloads either upstream `user.js`:

- `firefox/noid-firefox-hardening.js` and
  `thunderbird/noid-thunderbird-hardening.js` are the locally maintained
  canonical derivatives.
- `scripts/regen-firefox-embed.sh` and
  `scripts/regen-thunderbird-embed.sh` deterministically copy those local
  bytes into M16/M35. “Regenerate” never means “fetch upstream”.
- Update All enrolls eligible new profiles and reapplies those local bytes. Its
  networked browser work is limited to separately authenticated extension
  channels (for example uBlock Origin or DKIM Verifier); it never replaces a
  NoID Privacy derivative with an upstream `user.js`.
- Advancing a base is a reviewed source change: compare the complete tagged
  upstream release, classify every active addition/removal/change against the
  shipped Firefox/Thunderbird version and NoID Privacy's security/privacy/UX contract,
  update the canonical source and provenance header, regenerate its embed, and
  run the owning structural/runtime tests. Untagged upstream `master` movement
  is evidence to review, not authorization to import.

## Refresh procedure

1. **Fetch from the official channel only** (table above). Authenticate the
   artifact through the maintained upstream signature/checksum where one
   exists, then compute local `sha256sum` and `stat -c '%s'` values. A local
   hash identifies the reviewed bytes; by itself it does not authenticate
   their publisher.
2. **Sanity-check the artifact** before pinning: ELF header for binaries,
   `unzip -l` manifest for VSIX/XPI, `tar -tzf` layout for tarballs.
3. **Move every location in the same commit.** `git grep` for the old
   version string *and* the old hash; installer and updater identity pins
   must never split.
4. **Run the owning module tests + `ksflatten`/`ksvalidator`**, bump the
   module `# Status:` line, and state the old→new versions in the commit
   message.
5. Version bumps are build-cycle decisions: refresh deliberately, not
   because a newer upstream version merely exists.

### Fedora build-stack re-pin

Treat the base ISO, Anaconda grammar and Lorax override as three separate
reviewed boundaries; a newer Fedora package does not authorize advancing the
other two.

1. For a base-ISO refresh, download the new official CHECKSUM and ISO, verify
   the CHECKSUM signature directly with the intended Fedora primary key, then
   update the single `BASE_RELEASE`, expected byte count, SHA-256, fingerprint
   when applicable, and retained signed CHECKSUM used by
   `scripts/verify-fedora-base-iso.sh`. Its `--print-expected-name` output is
   the filename authority consumed by the builder and tests.
2. Build once without widening the log classifier. Record the exact Anaconda
   version line from the authenticated installer, review every new high-signal
   event, then update the closed `bindings` and only the specifically justified
   rules in `manifests/compose-log-policy-v1.json`. Binding drift from the
   policy ID, human scope or exact Anaconda marker is a parser error.
3. For Lorax, obtain both candidates only from Fedora's signed repositories and
   record `rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' lorax
   lorax-templates-generic`. Compute local SHA-256 values for the package-owned
   `pylorax/monitor.py`, `pylorax/creator.py`, `pylorax/executils.py` and both
   x86 Live GRUB sources. Confirm that the complete installed `pylorax` and
   generic-template trees each pass RPM verification and contain exactly their
   RPM-owned inventory. Review the complete old/new sources, rebase all private
   patches with zero fuzz, update both staging helpers' closed constants, and
   require all three Lorax semantic verifiers plus the final BIOS/UEFI menu
   contract to pass on the staged trees.
4. Run the owning source/compose fixtures and retain the new private build
   evidence. Never make the patch tolerant of an unreviewed NEVRA or source
   hash merely to get a build running.

### Other Fedora payload re-pins

- For the Firefox and Thunderbird launchers, query only Fedora's signed stable
  repositories, verify the selected RPM signature and inspect the complete
  package-owned launcher plus its RPM payload metadata. Update the owning
  module's digest only after reviewing the complete old/new script, rebasing
  the NoID Privacy-owned launcher derivation against its exact maintained
  anchors and running the M16 or M35 structural and browser parity gates.
- For the Anaconda Live required-space overlay, obtain `anaconda-core` and
  `anaconda-live` from Fedora's signed release/update repositories, verify both
  exact NEVRAs and RPM signatures, then compare the complete old/new
  `initialization.py` and `liveinst` payloads. Update M17's RPM metadata and
  hashes, rebase the canonical derivative rather than hand-editing its embed,
  regenerate it, and update the closed base hash in Lorax patch 0002. Require
  the M17 structural fixture and Lorax required-space semantic verifier to pass.
- For the TuneD PPD map, obtain `tuned-ppd` from Fedora's signed stable
  repository and inspect the complete package-owned `ppd.conf`. Update its
  byte-count/digest binding only after reconciling every semantic mapping with
  the complete NoID Privacy replacement and both Balanced child profiles; run
  the M27 structural test and runtime TuneD verification.

The reviewed pin covers the artifact as first installed. No mutable vendor
updater stays enabled in the background. Where this project owns a maintained,
user-started channel (Firefox/Thunderbird add-ons and opted-in Claude/Codex
components through Update All), the pin is a recovery seed and that explicit
transaction owns later versions with recorded version + SHA-256 evidence.
Artifacts without such a path remain authoritative at their reviewed pin until
the next source refresh.

For Claude/Codex specifically, this is a deliberate consent-gated exception
to repository-reviewed exact byte pins **after** first installation, not an
accidental mutable-latest fallback: the first install remains version/size/
SHA-256 pinned, background updaters remain disabled, and only an explicit
user-started Update All run may advance an already opted-in component through
its fixed vendor namespace while appending local evidence.
