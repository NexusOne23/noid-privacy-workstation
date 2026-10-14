# Contributing to NoID Privacy Workstation

This file documents the engineering process for authoring, modifying, and
locking Module snippets in this project. Review alone is not sufficient for
`LOCKED` status: a Module must also pass the end-to-end semantic tests below,
because a silent-fail defect can survive both review and `bash -n`.

The checks below are **mandatory** before a Module or Module-version
is eligible for `LOCKED` status.

## Module lifecycle

```
DRAFT    → under active design, things churn
REVIEW   → content stable, awaiting gate (see below)
LOCKED   → cleared the gate; safe to ship as part of a numbered image
ROLLED   → superseded by a later version; kept in git history
```

`LOCKED` does **not** mean "known-perfect". It means "the mandatory gate
has been passed and the Module is stable for the current image cut."

DRAFT and REVIEW are working states outside the committed tree:
`tests/00-status-metadata.sh` accepts only the dated, versioned `LOCKED`
Status form in committed snippets.

## Mandatory pre-LOCK gate

Before marking a Module (or v2+ revision) `LOCKED` in its header
`# Status:` line, ALL items below must be green.

### 1. `bash -n` syntax sweep

```bash
cd noid-privacy-workstation
for f in kickstart/master.ks kickstart/snippets/*.ks; do
    [ -f "$f" ] || continue
    bash -n "$f" 2>/dev/null || echo "SYNTAX FAIL: $f"
done
```

Expected: zero failures. `bash -n` is necessary but not sufficient —
it catches syntax errors but not logic errors such as a `sed` address that
silently matches nothing.

### 2. Self-verification in the Module's own `%post`

Every Module snippet MUST include a verification block inside its
`%post` that asserts its own key artifacts are in place. Pattern:

```bash
# ------------------------------------------------------------------------------
# Phase X — Verification
# ------------------------------------------------------------------------------
PHASE="PX-verify"
log "Running verification"

checks=0
fails=0

check() {
    checks=$((checks + 1))
    if eval "$1" >/dev/null 2>&1; then
        log "  [OK] $2"
    else
        fails=$((fails + 1))
        log "  [FAIL] $2"
    fi
}

check "[ -x /usr/local/bin/foo ]" "foo installed + executable"
check "[ -f /etc/systemd/system/foo.service ]" "service unit present"
# ... one check() per load-bearing artifact ...

log "Verification: $((checks - fails))/$checks passed"
if [ "$fails" -gt 0 ]; then
    die "$fails verification check(s) FAILED"
fi
```

- **Assert every artifact** the Module writes or modifies (file
  existence, exec permission, content-size floor, key-regex grep).
- **Every successful match** emits `[OK]`; every failure `[FAIL]` +
  `fails=$((fails+1))`. A non-zero `fails` count aborts the build
  with `--erroronfail`.
- Minimum size floors on doc files protect against empty / truncated
  writes (e.g. `[ "$(stat -c %s /path/to/doc.md)" -gt 4096 ]`).

### 3. Cross-Module check in `99-finalize.ks`

For any artifact that a **later** Module depends on (log output,
binary, service, compiled config), add a corresponding check block
to the cross-module verification section in `99-finalize.ks`. This makes
covered contract failures visible and fatal; it does not prove untested
behavior or every runtime/hardware path.

Keep these checks focused on **cross-Module contracts** (Module X
writes, Module Y reads), not a duplicate of the Module's own
verification — that duplicate adds no information and slows builds.

### 4. E2E mock-data semantic test

This is the gate that catches silent-fail `sed`/`awk` defects. For any
helper function or non-trivial `sed`/`awk`/`grep` pipeline, write a
minimal test that:

1. Creates a representative mock input file (e.g. a fake
   `/etc/fstab`, a fake NM profile directory, a fake SELinux policy)
2. Sources the Module's %post logic or invokes the helper directly
3. Asserts the **exact expected output**, not just "no error"
4. Re-runs the same logic a second time and asserts idempotency

Example (abridged from the shipped mount-option test):

```bash
#!/bin/bash
# tests/22-luks-partitioning-mount.sh (abridged)
set -euo pipefail

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# 1. Build a representative fstab (the exact line layout that
#    Anaconda writes)
cat > "$TMPDIR/fstab" <<EOF
UUID=aaaa / btrfs defaults,subvol=root 0 0
UUID=bbbb /home btrfs defaults,subvol=home 0 0
UUID=cccc /tmp ext4 defaults 0 0
UUID=dddd /dev/shm tmpfs defaults 0 0
EOF

# 2. Extract the helper and every function it calls from the kickstart
#    snippet, and stub the snippet's logger
extract_function() {
    awk -v n="$1" '
        $0 ~ "^" n "\\(\\) *\\{" { in_fn=1 }
        in_fn { print }
        in_fn && /^\}$/ { in_fn=0; exit }
    ' kickstart/snippets/22-luks-partitioning.ks
}
for fn in fstab_opt_present append_fstab_opt fstab_has_mountpoint \
    ensure_mount_options; do
    extract_function "$fn"
done > "$TMPDIR/helper.sh"
log() { :; }
. "$TMPDIR/helper.sh"

# 3. Exercise: /tmp must get nosuid + noexec + nodev
FSTAB="$TMPDIR/fstab"
CHANGED=0
ensure_mount_options /tmp nosuid,noexec,nodev

# 4. Assert each option is present exactly once in the /tmp line
for opt in nosuid noexec nodev; do
    if ! grep -E "^UUID=cccc /tmp ext4 [^ ]*${opt}" "$FSTAB" >/dev/null; then
        echo "FAIL: /tmp missing $opt after patch"; exit 1
    fi
done

# 5. Idempotency: second run must be a no-op (no duplicate ",nosuid,nosuid")
ensure_mount_options /tmp nosuid
if grep -Eq ',nosuid.*,nosuid' "$FSTAB"; then
    echo "FAIL: non-idempotent (duplicate nosuid)"; exit 1
fi

echo "PASS"
```

Place tests under `tests/`; a `tests/NN-*` prefix names the owning Module
(00 = source contracts, 99 = cross-module). Invoked via `tests/run-all.sh`
before marking anything `LOCKED`.

### 5. Heredoc content extraction for large docs

Module snippets that ship documentation via large heredocs should
extract the rendered content and size-check it before LOCK:

```bash
# Extract the doc that would be written at install time
awk '/^cat > \/usr\/share\/doc\/noid-privacy\/FOO\.md <<.FOO_EOF./,/^FOO_EOF$/' \
    kickstart/snippets/NN-name.ks \
    | sed -e '1d' -e '$d' > /var/tmp/FOO.md

# Size sanity — must match or exceed the 99-finalize floor
wc -c /var/tmp/FOO.md
```

This catches heredoc-marker typos and accidental content truncation
that would pass `bash -n` but produce an empty file at install time.

## Authoring a new Module

1. Inspect `kickstart/master.ks`, `kickstart/snippets/` and `INDEX.md`, then
   pick an unused number. M38-M39 are the current reserved free slots; M43+
   is also available. Renumber an existing Module only after a full-project
   audit.
2. Create `kickstart/snippets/NN-name.ks` following the template
   below. Match the tone and structure of an existing comparable
   Module (e.g. M28 for doc-only, M22 for config-modification, M03
   for service-install). Capture the decision rationale (why this
   Module exists, what threats it mitigates, what trade-offs were
   accepted) inline in the file header comment block — this
   is the canonical place for per-Module design notes.
3. Add `%include snippets/NN-name.ks` to `master.ks` in the correct
   position. Respect the snippet-order comment at the top of
   `master.ks` (constraints: 99-finalize last, AIDE before its
   dependents, etc.).
4. Run the mandatory gate (section above).
5. Update `CHANGELOG.md` and `INDEX.md` description if
   the new Module changes user-facing scope.

### Snippet template

```text
# ============================================================================
# Module NN — Short Title
# Status: LOCKED 2026-MM-DD (v1) — terse scope summary.
# Design rationale: captured inline in the header comment block below.
#
# Scope: One sentence on what this Module does.
#
# Cross-references:
#   - Module X: writes file Z that we read
#   - Module Y: depends on our output
#
# Package modifications: list packages added/removed, or "NONE"
# ============================================================================

%packages --exclude-weakdeps
# Required adds — keep minimal
# -exclude-me   # excluded packages with rationale inline
%end

%post --log=/var/log/ks-NN-name.log --erroronfail
set -e
set -o pipefail

PHASE=""
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [noid-NN-name] ${PHASE}: $*"; }
die() { log "FAIL: $*"; exit 1; }

log "=== Module NN Short Title start ==="

# Phase 1 — ...
PHASE="P1-..."
# ...

# Phase N — Verification (MANDATORY, see CONTRIBUTING.md section 2)
PHASE="PX-verify"
# (see template under "Self-verification" above)

log "=== Module NN Short Title complete ==="
%end
```

## Updating a locked Module (v2, v3, …)

1. Bump the `# Status:` line at the top of the snippet (`(v1)` → `(v2)`,
   with the new date and a terse one-line summary of the change).
2. Apply the change.
3. Re-run the **full** pre-LOCK gate from section above, not just
   the parts you think are affected. Cross-Module side-effects are
   often non-obvious.
4. If the change adds a new artifact that other Modules may depend
   on, add the corresponding check to the cross-module verification section
   in `99-finalize.ks`.
5. Update `CHANGELOG.md`, `INDEX.md` description (if scope changed),
   and bump the module's `# Status: LOCKED YYYY-MM-DD (vN)` line (date +
   version + terse summary); the detailed change-narrative goes in the
   commit message, not a separate in-file lock-history block (one
   Status line per snippet).

## Anti-patterns (do not do)

### Do not declare LOCKED without running the gate

If you haven't run items 1-5 of the gate, the Module is at most
`REVIEW`, not `LOCKED`. Treating `LOCKED` as a review state lets silent-fail
defects ship as "locked".

### Do not run the gate by hand once and assume it stays green

Any structural change to the project (new Module, cross-Module
refactor, `%include` reorder) may invalidate a gate that was green
yesterday. Re-run the full sweep.

### Do not use `set -eu` without thinking about edge cases

`grep -c` exits 1 when there are zero matches; under `set -e` that aborts the
script even in a plain assignment. Pattern:

```bash
count=$(grep -c 'foo' file 2>/dev/null || true)
count=${count:-0}
if [ "$count" -gt 0 ]; then ...
```

### Do not use backup-file patterns inside AIDE-tracked directories

`cp /etc/foo.conf /etc/foo.conf.bak-$(date +%F)` writes into `/etc/`
which is AIDE-tracked. Every build creates an "added file" alert.
Do not leave backup copies in the image at all: stage them in a
`mktemp -d` directory under `/var/tmp` and remove it before the `%post`
section ends (`/root` is AIDE-tracked by Fedora's policy, and Fedora has
no `/var/backups`).

### Do not write to AIDE-tracked paths with `touch` / metadata-only ops

AIDE tracks metadata (ctime, mtime). A `chown` or `touch` of a
tracked file — even with identical content — produces an alert on
the next daily check. Put such operations outside AIDE-tracked paths
or exclude the exact directory entry via `!/path$` in `aide.conf`
(regex `$` anchor matches only the directory entry itself, not its
children).

## Related references

- [`INDEX.md`](INDEX.md) — Module semantic navigation
- [`docs/CONTRIBUTING-technical.md`](docs/CONTRIBUTING-technical.md) — technical mechanics of adding a new Module
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — community guidelines
- [`CHANGELOG.md`](CHANGELOG.md) — user-visible release history

## License

NoID Privacy-owned code and machine-readable policy: GPL-3.0-or-later except for the
GPL-2.0 and MIT file-level exceptions inventoried in
[`LICENSING.md`](LICENSING.md) (license texts in [`COPYING`](COPYING),
[`licenses/GPL-2.0.txt`](licenses/GPL-2.0.txt) and the MIT notices under
[`licenses/`](licenses/)). Documentation: CC BY-SA 4.0
unless otherwise noted in-file. Branding assets and third-party components
retain the exact terms stated in the full breakdown:
[`LICENSING.md`](LICENSING.md).
