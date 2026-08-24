# CONTRIBUTING (technical) — How to add a Module

Companion to [`../CONTRIBUTING.md`](../CONTRIBUTING.md). This doc
covers the technical mechanics of adding a new Module N, writing its
kickstart snippet, and wiring it into master.ks + tests + docs.

## File layout convention

```
noid-privacy-workstation/
├── kickstart/
│   ├── master.ks                    ← adds `%include snippets/NN-yourname.ks`
│   └── snippets/
│       └── NN-yourname.ks           ← your new Module (design rationale
│                                       lives in this file's header
│                                       comment block)
├── tests/
│   └── NN-yourname-structural.sh    ← regression test
└── docs/                              (project-level docs — not per-Module)
```

Per-Module user docs ship inside the image under
`/usr/share/doc/noid-privacy/NN-*.md`. The Module's `.ks` file always
materializes the installed payload as a heredoc. A short, single-owner document
may use that heredoc as its canonical source. A large or cross-surface document
may instead use an explicitly named file under `docs/` as the canonical source,
provided a deterministic `scripts/regen-*.sh` generator and a structural
byte-identity test prevent the source and heredoc from drifting. Never edit
both copies independently.

## 1. Research-first workflow

Before writing a line of the kickstart, gather data:

1. **Grep the existing codebase** — what similar Modules already do.
2. **Web research** — current maintained best practice; upstream project
   docs; recent CVEs relevant to the space.
3. **Peer-distro survey** — how Kicksecure, secureblue, Qubes, Tails
   handle the same concern (+ why).
4. **Write the decision rationale FIRST** in the Module's `.ks`
   header block. It should answer:
   - What problem does this Module solve?
   - What does the peer-distro consensus say?
   - What's our specific trade-off decision (with rationale)?
   - What's the rollback path?
   - Known failure modes (also surface them in `docs/known-failures.md`).

Only AFTER the rationale block is reviewed, start writing the
`%post` logic.

## 2. Kickstart snippet template

```bash
# ============================================================================
# Module NN — Short descriptive title
# Status: DRAFT 2026-MM-DD (v1) — terse scope summary.
# ============================================================================
#
# What this Module covers:
#   - File 1 shipped: /etc/foo/bar.conf
#   - File 2 shipped: /usr/local/bin/noid-yourtool.sh
#   - Systemd service: noid-yourservice.service
#
# Decisions (confirmed YYYY-MM-DD):
#   [Q1 A]  ... (full question + answer + rationale)
#   [Q2 B]  ...
#
# Trade-offs:
#   - What this hardens, what this might break, what the reversal is
#
# (Change-narrative goes in the commit message; full history lives in git.
#  Bump the Status line on every change — no per-change v-entry blocks.)
# ============================================================================

%post --erroronfail --log=/var/log/ks-NN-yourname.log
set -e
set -o pipefail

log() { echo "[$(date +%H:%M:%S)] $*"; }
log "=== Start Module NN: Short title ==="

# ... your logic ...

log "=== End Module NN ==="
%end
```

### Key rules

- **`--erroronfail`**: any `%post` failure aborts the build. No silent
  skip.
- **`set -e` + `set -o pipefail`**: fail the `%post` on command or pipeline
  failure. Add nounset only after reviewing every optional/environment-derived
  variable and edge case in that specific block.
- **`log()` helper**: consistent format; aids the health-stamp
  diagnostic pattern.
- **Idempotent**: each step should tolerate re-run (systemctl enable X
  is idempotent; `echo > file` is idempotent; `cat >> file` is NOT —
  use `cat >` or `sed -i` with a guard).
- **Heredoc markers**: use uppercase suffix `_EOF` (e.g. `NM_EOF`,
  `DBUS_EOF`). Unique per file.
- **File permissions**: always set explicitly (`chmod 644 /etc/foo/bar.conf`
  + `chown root:root`).
- **SELinux relabel**: if writing to directories with context rules,
  call `restorecon -F path` (guard with `command -v restorecon`).

## 3. Health stamp (end of snippet)

Every new Module ends with a stamp write (migration pattern; 14 modules
adopt it: M16, M28-M37, M40, M41 and M42 per `99-finalize.ks`
`EXPECTED_STAMPS`. Other modules still use per-artifact checks in
`99-finalize.ks`):

Do not use an abbreviated direct write to the final pathname. It can preserve
an earlier success across a failed rerun or leave newly published but
unverified evidence after an interruption. Copy and adapt all three exact
boundaries from `kickstart/snippets/28-local-ai-docs.ks`:

1. the stamp variables, candidate state and `EXIT` cleanup;
2. `M28_HEALTH_INVALIDATION_BEGIN` through
   `M28_HEALTH_INVALIDATION_END`, before the first owned payload mutation;
3. the exact schema validator and
   `M28_HEALTH_PUBLICATION_BEGIN` through
   `M28_HEALTH_PUBLICATION_END`, after every owned verification passes.

Replace the module number, short name, pathname and schema-specific counters
consistently. Keep the shared directory validation, stale-stamp invalidation,
same-filesystem private candidate, ownership/mode/link-count checks, SELinux
label verification, candidate and final schema checks, file and directory
syncs, atomic rename and cleanup guard intact. Tests must execute at least the
stale-evidence, label and rename failure paths; changing only the happy path is
insufficient.

`99-finalize.ks` requires the exact canonical filename and module/name/status
tuple, a regular non-symlink root-owned mode-0644 file, and rejects unexpected
stamp files. The owning Module's stronger publication contract also verifies
link count, exact schema and SELinux context. Missing, renamed, substituted or
extra stamps fail the finalizer.

See [`docs/engineering-health-stamp-pattern.md`](engineering-health-stamp-pattern.md).

## 4. Wire into master.ks

Add a `%include` line in master.ks, ordered by dependency:

```
%include snippets/NN-yourname.ks
```

Use the authoritative dependency list in `kickstart/master.ks` under
`Snippet order CRITICAL CONSTRAINTS`; do not reproduce a partial copy in a
new document. In particular, M99 is last, M13 precedes M14/M15, M11b follows
M11, M34 follows M16, M40 precedes M37, and M41/M42 precede M99. M13 and M99
must continue to reject build-time AIDE trust state: runtime changes remain
evidence until the user explicitly reviews and commits an exact candidate.

## 5. Tests

Add `tests/NN-yourname-structural.sh`:

```bash
#!/bin/bash
# NN-yourname-structural — Module NN regression test
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/NN-yourname.ks"

test_start "NN-yourname-structural"

assert_file_exists "$KS_FILE"
assert_cmd_success "bash -n $KS_FILE" bash -n "$KS_FILE"

# Required heredoc markers
assert_grep_fixed 'YOUR_MARKER_EOF' "$KS_FILE"

# Files shipped (with paths)
assert_grep_fixed '/etc/foo/bar.conf' "$KS_FILE"
assert_grep_fixed '/usr/local/bin/noid-yourtool.sh' "$KS_FILE"

# Systemd service if present
assert_grep_fixed 'noid-yourservice.service' "$KS_FILE"

# Permissions
assert_grep_extended 'chmod [0-9]+ /etc/foo/bar.conf' "$KS_FILE"

# Stamp written
assert_grep_fixed 'stamp-NN-<short-name>.ok' "$KS_FILE"

test_finish
```

## 6. User docs

For a short, single-owner document, add the canonical user-facing content
directly as a heredoc in the Module's `.ks`:

````bash
mkdir -p /usr/share/doc/noid-privacy
cat > /usr/share/doc/noid-privacy/NN-yourtopic.md <<'USER_DOC_EOF'
# Module NN: Short title

What this Module does, why, and how to undo it.

## What changes

- /etc/foo/bar.conf is written (with content).
- /usr/local/bin/noid-yourtool.sh is installed.

## Why

Rationale — keep this short and user-focused; the full engineering
rationale lives in the Module's `.ks` header comments.

## Verify

```bash
sudo /usr/local/bin/noid-yourtool.sh --verify
```

## Revert

```bash
# Undo steps here.
```

## Known failure modes

See `docs/known-failures.md` section for M-NN.
USER_DOC_EOF

chmod 644 /usr/share/doc/noid-privacy/NN-yourtopic.md
chown root:root /usr/share/doc/noid-privacy/NN-yourtopic.md
````

For a large document maintained under `docs/`, follow the existing
`regen-local-ai-doc.sh`, `regen-ai-workspace-doc.sh` or
`regen-wan-strict-doc.sh` pattern: use the shared source-generator library,
replace only the uniquely delimited heredoc atomically, expose `--check`, and
add a test that requires byte identity. The repository file is then the only
place maintainers edit; the `.ks` heredoc remains the installed transport.

## 7. Pre-LOCK checklist

Before marking a Module v1 "LOCKED":

- [ ] Decision rationale captured in the `.ks` header comments
- [ ] `kickstart/snippets/NN-yourname.ks` passes `bash -n`
- [ ] `pykickstart` validation passes
- [ ] `tests/NN-yourname-structural.sh` exists + passes
- [ ] `bash tests/run-all.sh` 84/84 pass
- [ ] User doc is shipped by the %post heredoc; any separate canonical source
      has a deterministic generator and byte-identity test
- [ ] master.ks `%include` added in correct dependency order
- [ ] 99-finalize.ks stamp cross-check extended to include NN
- [ ] `docs/known-failures.md` reviewed; update it only for a new or changed limitation
- [ ] `INDEX.md` updated (add Module reference)
- [ ] External download? → immutable version/identity pinned; upstream
      signature or checksum verified where available; exact byte size, local
      SHA-256 and payload type enforced as applicable; central pin locations
      and tests updated

Any checklist item missing → PR rejected.

## 8. Update existing Module

If you're modifying an existing Module:

1. **Never remove a health stamp** — existing installs rely on it for
   cross-check.
2. **Never change the path of a shipped file** without a migration
   script for running systems. Or document in
   `docs/upgrade-path.md`.
3. **Update the test first** to expect the new invariant, then update
   the snippet to match.
4. **Bump the Status line** at top of snippet:
   `# Status: LOCKED 2026-04-18 (v2) — terse change summary.`
5. **Add explanation in `CHANGELOG.md`** for users reading upgrade
   notes.

## Contributing tips

- Read an existing compact Module snippet first (M02, M11b or M24 are useful
  examples); use larger modules only when their specific trust boundary is
  relevant.
- Use `grep -n` to find similar patterns in other Modules before
  inventing new ones.
- Don't over-engineer. Split by ownership and trust boundary when that makes
  the result easier to review; raw line count alone is not the criterion.

## Q&A

**Q: Can a Module span multiple %post blocks?**
A: pykickstart allows it, but no current Module does — every snippet
carries exactly one `%post` block. Keep that convention unless a reviewed
design requires otherwise; the smoke harness extracts a snippet's first
`%post` block.

**Q: Can a Module modify another Module's file?**
A: Avoid if possible. If required, order the %include so your Module
comes AFTER the file's originator, and document the dependency in your
snippet header.

**Q: Can a Module use `dnf install` at %post?**
A: Yes, but pass `--setopt=install_weak_deps=False` explicitly (prevents
pulling weak dependencies not listed in the `%packages` block, which can
re-introduce services the image explicitly masks). The similarly named
`--exclude-weakdeps` belongs to Kickstart's `%packages` section, not the DNF5
`install` command. Prefer `%packages` for install-time package selection. See
the maintained [DNF5 configuration reference](https://dnf5.readthedocs.io/en/stable/dnf5.conf.5.html#main-options)
and [Pykickstart package-selection reference](https://pykickstart.readthedocs.io/en/latest/kickstart-docs.html#chapter-9-package-selection).

**Q: Can a Module auto-egress to the internet?**
A: Only if it's been accepted as a trade-off and documented as such.
See [Silent-Machine M08 revisit](../kickstart/snippets/08-service-minimization.ks)
for an example.
