# Build Reproducibility — honest posture

NoID Privacy Workstation makes several inputs deterministic, but the project has
not established byte-for-byte reproducibility of complete ISOs. This document
separates implemented variance reduction from a reproducibility result that must
be measured, never assumed.

For the higher-level rationale (why this trade-off makes sense for NoID Privacy's threat model), see [`design-decisions.md`](design-decisions.md) §3.

---

## What `scripts/build-iso.sh` already does

```bash
# VOLID = fixed ECMA-119 d-character label; ISO_NAME = version-derived output
# filename (only the filename — the ISO content + its SHA256 are unaffected)
VOLID="NOID_PRIVACY_F44"
ISO_NAME="noid-privacy-workstation-44-${NOID_VERSION}-x86_64.iso"

# SOURCE_DATE_EPOCH from git commit-time
: "${SOURCE_DATE_EPOCH:=$(git -C "$REPO_ROOT" log -1 --format=%ct 2>/dev/null || date +%s)}"
export SOURCE_DATE_EPOCH

# per reproducible-builds.org 2026 best practices
export TZ=UTC PYTHONHASHSEED=0 PERL_HASH_SEED=0
```

The wrapper also passes the release derived from Module 32's `NOID_VERSION` and
the canonical project issue URL through Lorax's `--release` and `--bugurl`
interfaces. It rejects a volume label outside `[A-Z0-9_]{1,32}`, the Lorax
placeholder bug URL, and xorriso's ISO-9660/ECMA-119 volume-ID warning before a
candidate can be checksummed. These are compose-identity and audit gates, not a
claim of byte-for-byte reproducibility.

These settings reduce timestamp and language-runtime variance. They do not prove
that Lorax, Anaconda, RPM scriptlets, filesystem creation, package selection,
and signing are deterministic as a complete pipeline.

The epoch is exported for build tools that honor `SOURCE_DATE_EPOCH`. The
repository does not patch or wrap every Lorax/Anaconda subtool, so it does not
claim that particular `mksquashfs`, `tar`, or `xorriso` flags are present in
every build invocation.

---

## What's structurally blocked (cross-time)

“Build today and build in three weeks must produce the same SHA256” is not a
property of the current input model:

### 1. Fedora repos are a moving target

`master.ks` pulls install-source + `updates-released-f44` via Metalink. Fedora continuously pushes package updates; each rebuild grabs a different snapshot — different RPM NVRs, different ISO hash.

### 2. The build does not pin a complete Fedora compose/repository snapshot

Fedora/Koji retains many build artifacts, and Fedora works on package-level
reproducibility, but this repository does not provide a lockfile mapping every
resolved NEVRA and repository metadata object to immutable content. Therefore a
later build can legitimately select different signed packages.

### 3. The complete image-construction pipeline has not been proven deterministic

Lorax, Anaconda, filesystem/image builders, RPM scriptlets and generated image
metadata have not been shown by a two-build experiment to produce identical
bytes here. MOK keys are **not** an ISO-build input: an akmods/DKMS key is only
generated later on the installed machine when a user opts into an out-of-tree
driver, so it is machine-local state and does not explain ISO differences.

---

## Update frequency is NOT the reason

Update cadence and reproducibility are separate concerns. NoID Privacy chooses
Fedora for its platform characteristics; that does not remove this project's
responsibility to document and, where practical, pin its own inputs.

---

## What we deliver as audit substitute

Release evidence is expected to include:

- **`SHA256SUMS`** — canonical hash file
- **`SHA256SUMS.asc`** — detached signature when the release builder has an
  explicitly available signing key; its trust still depends on obtaining the
  public key/fingerprint independently
- **Build log** — compose/package transaction evidence retained by the release
  process; verify that it is actually archived for the specific release
- **Source tree** — git-versioned kickstart, tests, and docs; commit signatures
  are not claimed unless verified for the specific commit

These artifacts support investigation but are not a complete, independently
reproducible audit trail. In particular, a checksum signed by the same release
operator proves origin/integrity relative to that key, not independent build
equivalence.

---

## Audited state that does not establish determinism

These controls or boundaries are useful, but none is proof that two ISO builds
will match:

| Source | Workaround |
|--------|------------|
| Selected third-party GPG identities | Exact fingerprints are checked in kickstart; Fedora package selection remains moving |
| Build-time host identities | The final Lorax mounted-root scrub empties `/etc/machine-id` and removes random-seed, BRLAPI and NVMe host identities immediately before SquashFS creation; the final-image gate and two-install uniqueness gate still verify the result instead of assuming it |
| LUKS headers | Generated at install, not in ISO; doesn't affect ISO hash |
| Build timestamps | `SOURCE_DATE_EPOCH`/UTC reduce variance only where downstream tools honor them |
| Installed-system MOK keys | Generated only after an opt-in driver workflow; not embedded in the ISO |

An identity copied from the compose root into the release image or reused by
independent installations is a privacy release blocker and must be fixed before
publishing. That finding alone is not evidence that an affected host was
compromised: it proves an image-lifecycle defect. Compromise assessment remains
a separate investigation based on provenance, unexpected changes and other
host evidence.

---

## Experimental two-build comparison

To test—without presuming—that two builds of the same revision and pinned input
set produce identical ISOs:

```bash
# Build 1
cd /path/to/noid-privacy-fedora && git rev-parse HEAD       # note SHA
sudo -v
./scripts/build-iso.sh
A_ISO='<exact first ISO path printed by the wrapper>'
test -f "$A_ISO" && test ! -L "$A_ISO"
read -r A_SHA256 _ < <(sha256sum -- "$A_ISO")

# Build 2 (same SHA, same toolchain)
./scripts/build-iso.sh
B_ISO='<exact second ISO path printed by the wrapper>'
test -f "$B_ISO" && test ! -L "$B_ISO"
read -r B_SHA256 _ < <(sha256sum -- "$B_ISO")

printf 'build 1: %s\nbuild 2: %s\n' "$A_SHA256" "$B_SHA256"
test "$A_SHA256" = "$B_SHA256"
```

One matching pair is evidence for those two environments, not a general proof.
A mismatch must be reported and investigated; do not rename it "expected" merely
to pass the release process.

---

## References

- [reproducible-builds.org](https://reproducible-builds.org/) — project hub
- [SOURCE_DATE_EPOCH spec](https://reproducible-builds.org/docs/source-date-epoch/)
- [GNU xorriso manual — ECMA-119 volume-ID rules](https://www.gnu.org/software/xorriso/man_1_xorriso.html)
- [Fedora Wiki — Changes/Package_builds_are_expected_to_be_reproducible](https://fedoraproject.org/wiki/Changes/Package_builds_are_expected_to_be_reproducible)
- [Fedora Wiki — Changes/ReproducibleBuildsClampMtimes](https://fedoraproject.org/wiki/Changes/ReproducibleBuildsClampMtimes)
- [`design-decisions.md`](design-decisions.md) §3 — higher-level rationale for cross-time-repro trade-off
