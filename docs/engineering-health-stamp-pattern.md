# Engineering: Module Health Stamp Pattern

**Status**: deliberate mixed migration.
Fourteen modules implement the failure-atomic contract below; legacy modules
retain their finalizer-owned checks.

## Motivation

`99-finalize.ks` owns final cross-Module gates and the legacy per-artifact
checks for Modules that predate this pattern. Repeating an adopting Module's
complete artifact contract in both its own `%post` and the finalizer would
slow review and let the two copies drift.

The **health stamp pattern** keeps artifact-level verification with the owning
Module. After that verification passes, the Module failure-atomically
publishes a machine-parseable stamp; `99-finalize.ks` independently binds the
exact expected filename to its module/name identity and `status=ok`.

Goals:

- **DRY**: no duplicate existence checks between Module `%post` and finalizer
- **Locality**: artifact-level checks live in the Module that owns them
- **Observability**: stamps remain readable on the installed system
  (`/var/lib/noid-privacy/stamp-*.ok`), available to future status tooling or
  troubleshooting scripts as build-publication evidence
- **Incremental migration**: Modules migrate one at a time; pattern is
  opt-in

Non-goals:

- **Not** a replacement for truly cross-Module checks. `99-finalize`
  keeps checks that genuinely span multiple Modules (AIDE baseline
  integrity, compiled dconf database, cross-version mask-chain, etc.).
- **Not** a replacement for the CONTRIBUTING.md E2E gate. Stamps are
  build-time artifacts; they do not replace pre-LOCK semantic tests.

## Stamp format

Stamps live under `/var/lib/noid-privacy/stamp-<NN>-<short-name>.ok`.

```
# NoID Privacy — Module NN Health Stamp
# Written at end of %post verification when all checks pass.
# Format: shell-sourceable key=value.
module=NN
name=<short-name>
version=1
status=ok
timestamp=2026-04-17T12:34:56Z
checks_passed=5
checks_total=5
```

Fields:

| Key | Required | Meaning |
|-----|----------|---------|
| `module` | yes | Integer Module number (must match filename `stamp-NN-*`) |
| `name` | yes | Short human-readable name (e.g. `user-docs`, `luks-partitioning`) |
| `version` | recommended by the format | Stamp format version; currently `1` |
| `status` | yes | `ok` on success. Anything else = failure |
| `timestamp` | recommended | ISO-8601 UTC timestamp of write |
| `checks_passed` | optional | Integer count of passed `check()` calls |
| `checks_total` | optional | Integer count of total `check()` calls |

Release-critical parsing requires exactly one `module`, `name` and `status`
line with the expected values. Additional extension keys are permitted and
ignored by the finalizer. Keep keys lowercase, ASCII and value-simple (no
embedded newlines or shell-specials).

## Who writes a stamp

A Module MUST publish its stamp **only if** its own verification block recorded
zero failures. Merely placing a direct write after the verification guard is
not sufficient: on a rerun, a stamp from the previous successful run already
exists, and a failure after rename or while applying the final SELinux context
can otherwise leave plausible green evidence.

The failure-atomic contract is:

1. Define the exact state directory and stamp path before payload work.
2. Before the first owned payload mutation, validate that the shared state
   directory is a real, non-symlink directory with exact root ownership, mode
   and SELinux context. Create it only when absent; never normalize an existing
   drifted boundary.
3. Remove any prior stamp and sync the directory. A rerun has no green evidence
   while its payload is incomplete.
4. After every module verification passes, stage the exact stamp on the same
   filesystem. Set root ownership and `0644`, apply and verify its SELinux
   context, validate the complete schema and sync the candidate.
5. Atomically rename the candidate to the canonical path. Until final metadata,
   content, context, file and directory sync checks pass, an `EXIT` cleanup must
   remove both the candidate and any published final stamp.
6. Clear that cleanup guard only after every final postcondition passes.

Do not source a candidate to validate it. Validate fixed keys and values as
data, reject duplicates in the module's exact schema, and keep M99's independent
non-executing parser as the cross-module gate. See M28 for the current
doc-module reference implementation and its executed fault-injection tests.

## Who reads a stamp

`99-finalize.ks` iterates its closed `EXPECTED_STAMPS` array of 14 exact
`module:name` pairs and asserts:

1. The exact canonical pathname exists as a regular non-symlink file (M36 has
   its explicitly declared historical filename exception).
2. Metadata is root:root mode `0644`.
3. Exactly one `module=`, `name=` and `status=` line exists and equals the
   expected module, expected name and `ok`.
4. No unexpected `stamp-*.ok` file exists outside the canonical set.

The finalizer deliberately counts and matches fixed lines with `grep`; it
never `.`-sources a stamp. A corrupted or hostile stamp therefore remains
data and cannot clobber finalizer state.

Extending: `noid-status` (M13) should read stamps at runtime to show
per-Module health on the installed system (future work).

## Migration plan

Every new Module that ships artifacts starts with the failure-atomic stamp
contract. A legacy Module migrates only through one focused, reviewed change
with a concrete correctness or maintainability trigger:

1. Add the failure-atomic invalidation/publication boundary described above.
2. REMOVE the corresponding per-artifact block from `99-finalize.ks`
   in the cross-Module verification section. Keep only truly
   cross-Module contracts in 99-finalize.
3. Add executed failure-path coverage and update the exact
   `EXPECTED_STAMPS` identity.

The existing legacy checks remain authoritative until all parts of that paired
change land together. A broad migration campaign is not a release goal.

## Status (current mixed-state inventory)

| Module | Stamp? | 99-finalize duplicate check? |
|---|---|---|
| 01-15, 17-27 (+ M11b sub) | no | yes (legacy per-artifact checks) |
| 16 | **yes** | no (Firefox gates complete before publication) |
| 28 | **yes** | no (local-AI documentation) |
| 29 | **yes** | no (user documentation) |
| 30 | **yes** | no (user documentation tier B) |
| 31 | **yes** | no (user documentation tier C) |
| 32 | **yes** | no (branding) |
| 33 | **yes** | no (operational hygiene) |
| 34 | **yes** | no (Firefox playground) |
| 35 | **yes** | no (Thunderbird; schema follows its own failure counter) |
| 36 | **yes** | no (NoID Privacy Network app) |
| 37 | **yes** | no (NoID Privacy Tools app) |
| 40 | **yes** | no (auditor identity and payload digests) |
| 41 | **yes** | no (Anaconda cleanup and service state) |
| 42 | **yes** | no (forensic retention) |

**Currently 14 modules adopt the stamp pattern** (M16 + M28 +
M29-M37 + M40 + M41 + M42). `99-finalize.ks` ships an array containing the
exact `module:name` pairs for those adopters and binds filename, identity,
status and metadata while rejecting extras.

### Current migration policy

- **Not a shrink, a restructure.** The per-artifact checks currently in
  `99-finalize.ks` are real content assertions — not duplicates. They
  have to live *somewhere*. Migration moves them into the owning Module and
  adds failure-atomic publication plumbing; it does not inherently reduce code.
- **New Modules use the current contract.** Use M28's complete boundary and
  tests as the reference. Do not add a new artifact-only finalizer block.
- **Legacy migration is incident-driven and paired.** A concrete drift or
  ownership bug can justify migrating one Module. Never remove its finalizer
  checks before the Module publishes and tests its exact stamp in the same
  change.

## Design decisions

**Why `key=value` instead of JSON?** Avoids installing `jq` as a hard
dependency inside the kickstart chroot and keeps validation to fixed
line-oriented tools. Stamps are read by `99-finalize.ks` in the Anaconda
`%post` environment where Python or `jq` may not be available.

**Why `/var/lib/noid-privacy/` instead of `/var/run/`?** Persistence —
stamps survive reboot so troubleshooting and future status tooling can display
the image-cut publication state.

**Why not `.sh` + `source`?** Security. A malicious stamp file (if
somehow introduced) sourced by 99-finalize would execute arbitrary code.
Fixed-string and counted-line validation performs no shell evaluation.

**Why write stamps only on full success?** The exit status of the
Module's `%post` is already carried by Anaconda's `--erroronfail`
flag. If `%post` aborts, the whole image build aborts. Early invalidation also
prevents a failed rerun from presenting its earlier success as current. The
check for `status != ok` remains defense in depth against corruption or manual
editing.

**Why keep the existing 99-finalize checks during migration?** Risk
management. The mixed state has 14 failure-atomic stamp adopters while
legacy modules retain the established per-artifact finalizer checks. Removing
those legacy checks without a specific paired migration would reduce
defense-in-depth. The checks are mostly fast
(stat + grep); their cost is readability, not runtime.

## References

- `CONTRIBUTING.md` — Module lifecycle + pre-LOCK gate
- `kickstart/snippets/28-local-ai-docs.ks` — failure-atomic stamp invalidation
  and publication reference
- `kickstart/snippets/99-finalize.ks` — stamp-check reference
  implementation (inside cross-Module verification loop)
- `tests/28-local-ai-structural.sh` — executes the production health boundary
  under stale-evidence, metadata, label and rename failures
