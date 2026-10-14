# Build reproducibility

NoID Privacy Workstation makes several inputs deterministic, but the project has
not established byte-for-byte reproducibility of complete ISOs. This document
separates implemented variance reduction from a reproducibility result that must
be measured, never assumed.

See also [platform choices](design-decisions.md).

---

## What `scripts/build-iso.sh` already does

Simplified excerpt (the script additionally validates each value):

```bash
# VOLID = fixed ECMA-119 d-character label; ISO_NAME = version-derived output
# filename (only the filename — the ISO content + its SHA256 are unaffected)
VOLID="NOID_PRIVACY_F44"
ISO_NAME="noid-privacy-workstation-44-${NOID_VERSION}-x86_64.iso"

# Canonical build epoch: the source commit time unless explicitly set
: "${SOURCE_DATE_EPOCH:=$(git -C "$REPO_ROOT" log -1 --format=%ct 2>/dev/null || date +%s)}"
export SOURCE_DATE_EPOCH

# Variance-reduction environment for the wrapper's own processes only
export TZ=UTC PYTHONHASHSEED=0 PERL_HASH_SEED=0
```

The wrapper also passes the release derived from Module 32's `NOID_VERSION` and
the canonical project issue URL through Lorax's `--release` and `--bugurl`
interfaces. It rejects a volume label outside `[A-Z0-9_]{1,32}`, the Lorax
placeholder bug URL, and xorriso's ISO-9660/ECMA-119 volume-ID warning before a
candidate can be checksummed. These are compose-identity and audit gates, not a
claim of byte-for-byte reproducibility.

What these values affect, precisely:

- `SOURCE_DATE_EPOCH` names the build ID (`<commit-12>-<epoch>`), becomes the
  build epoch injected into `/etc/noid-build-info`, and normalizes the
  timestamps of the Anaconda updates-image archive built by the wrapper.
- `TZ`, `PYTHONHASHSEED` and `PERL_HASH_SEED` stabilize the wrapper's own
  helpers.
- The privileged Lorax compose does **not** receive the epoch or the hash
  seeds. It runs through `sudo`, whose environment reset keeps only the
  explicitly passed `PYTHONPATH` and variables sudoers itself preserves (such
  as `TZ`). Forwarding the epoch is deliberately avoided: squashfs-tools would
  then set every inode mtime to it and break the image's RPM payload and mtime
  pristine checks. The compose itself — squashfs, ISO and installer-written
  files — is therefore not timestamp-normalized.

None of this proves that Lorax, Anaconda, RPM scriptlets, filesystem creation,
package selection and signing are deterministic as a complete pipeline.

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

The compose is deliberately not timestamp-normalized (see above), so file
timestamps written during installation and image creation already differ
between runs.

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

## Source and download verification

The release provides the source tree, `SHA256SUMS` and `SHA256SUMS.asc`.
Verify the signature and ISO using the [download instructions](../README.md#-download-the-iso).
These establish integrity relative to the release key; they do not prove that
an independent build produces the same ISO. The image records its build
revision in `/etc/noid-build-info`.

## Generated state

These controls or boundaries are useful, but none is proof that two ISO builds
will match:

| Source | Workaround |
|--------|------------|
| Selected third-party GPG identities | Exact fingerprints are checked in kickstart; Fedora package selection remains moving |
| Build-time host identities | The final Lorax mounted-root scrub empties `/etc/machine-id` and removes random-seed, BRLAPI and NVMe host identities immediately before SquashFS creation; the final-image gate and two-install uniqueness gate still verify the result instead of assuming it |
| LUKS headers | Generated at install, not in ISO; doesn't affect ISO hash |
| Build timestamps | `SOURCE_DATE_EPOCH` fixes the build ID, injected build epoch and updates-image archive only; the Lorax compose is not timestamp-normalized |
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
cd /path/to/noid-privacy-workstation && git rev-parse HEAD   # note SHA
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
With the compose not timestamp-normalized, the current pipeline is not expected
to produce a matching pair; record the observed result and its explanation
rather than presenting either outcome as a release property. The comparison is
an optional experiment, not a release gate.

---

## References

- [reproducible-builds.org](https://reproducible-builds.org/) — project hub
- [SOURCE_DATE_EPOCH spec](https://reproducible-builds.org/docs/source-date-epoch/)
- [GNU xorriso manual — ECMA-119 volume-ID rules](https://www.gnu.org/software/xorriso/man_1_xorriso.html)
- [Fedora Wiki — Changes/Package_builds_are_expected_to_be_reproducible](https://fedoraproject.org/wiki/Changes/Package_builds_are_expected_to_be_reproducible)
- [Fedora Wiki — Changes/ReproducibleBuildsClampMtimes](https://fedoraproject.org/wiki/Changes/ReproducibleBuildsClampMtimes)
- [Platform choices](design-decisions.md)
