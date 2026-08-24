#!/usr/bin/env bash
# Historical filename retained for discovery compatibility. Verify the retired
# RPM-error bypass stays absent and the remaining inst.updates producer has an
# authenticated, deterministic, atomic profile/mask-only contract.
set -euo pipefail

. "$(dirname "$0")/lib.sh"
ROOT=$(find_project_root)
BUILDER="$ROOT/scripts/anaconda-patch/build-updates-img.sh"
BASE_VERIFIER="$ROOT/scripts/verify-fedora-base-iso.sh"
RETIRED_PATCH="$ROOT/scripts/anaconda-patch/apply-patch.py"
M32="$ROOT/kickstart/snippets/32-branding.ks"
M99="$ROOT/kickstart/snippets/99-finalize.ks"
BASE_ISO_NAME="$("$BASE_VERIFIER" --print-expected-name)"
REAL_ISO=
for candidate in \
        "/var/tmp/$BASE_ISO_NAME" \
        "${HOME:?}/Downloads/$BASE_ISO_NAME"; do
    if [ -f "$candidate" ] && [ ! -L "$candidate" ]; then
        REAL_ISO=$candidate
        break
    fi
done
TMPDIR=$(mktemp -d "${TMPDIR:-/var/tmp}/noid-updates-test.XXXXXX")
trap 'rm -rf -- "$TMPDIR"' EXIT HUP INT TERM

test_start "00-anaconda-patch-structured"
assert_cmd_failure "retired transaction-progress patch source is absent" \
    test -e "$RETIRED_PATCH"
assert_cmd_success "updates image builder has valid Bash syntax" \
    bash -n "$BUILDER"
assert_grep_fixed 'export PATH=/usr/sbin:/usr/bin' "$BUILDER" \
    "updates-image builder resolves only Fedora system tools"
assert_grep_fixed '[ "$#" -eq 2 ]' "$BUILDER" \
    "producer requires exactly the authenticated base and absolute output"
assert_grep_fixed '"$VERIFY_BASE" "$NETINST_ISO"' "$BUILDER" \
    "standalone producer authenticates its Fedora base"
profile_open="publish_root_file /etc/anaconda/profile.d/noid-privacy.conf 0644 <<'NOIDPROF_EOF'"
assert_grep_fixed "$profile_open" "$M32" \
    "Module 32 uses the failure-atomic profile publisher"
assert_grep_fixed 'PROFILE_HEREDOC_OPEN="publish_root_file /etc/anaconda/profile.d/noid-privacy.conf 0644 <<'\''NOIDPROF_EOF'\''"' \
    "$BUILDER" "updates producer follows the canonical profile publisher"
assert_not_grep 'cat > /etc/anaconda/profile.d/noid-privacy.conf' "$BUILDER" \
    "updates producer has no stale direct-write opening marker"
assert_grep_fixed 'LC_ALL=C find . -print0 | LC_ALL=C sort -z' "$BUILDER" \
    "archive member order is deterministic and NUL-safe"
assert_grep_fixed '--reproducible' "$BUILDER" \
    "GNU cpio device/inode variance is disabled"
assert_grep_fixed 'gzip -n -9' "$BUILDER" \
    "gzip header name and timestamp are suppressed"
assert_grep_fixed 'os.link(temporary, destination, follow_symlinks=False)' \
    "$BUILDER" "publication is atomic and no-replace"
for signal_contract in \
    "trap 'exit 129' HUP" \
    "trap 'exit 130' INT" \
    "trap 'exit 143' TERM"; do
    assert_grep_fixed "$signal_contract" "$BUILDER" \
        "updates-image builder preserves the signal-derived exit status"
done
assert_grep_fixed "if grep -Fq 'transaction_progress.py'" "$BUILDER" \
    "archive verification explicitly rejects an RPM-transaction override"
assert_not_grep 'self._queue.put' "$M99" \
    "Module 99 no longer rewrites Anaconda's callback producer"
assert_not_grep "token == 'script_error'" "$M99" \
    "Module 99 no longer admits a scriptlet-error token"
assert_grep_fixed "grep -qE 'NoID Privacy PATCH|_noid_safe_script_errors|_noid_safe_pkg'" \
    "$M99" "Module 99 fails if a retired bypass survives"

assert_cmd_failure "producer rejects a missing argument" bash "$BUILDER"
assert_cmd_failure "producer rejects surplus arguments" \
    bash "$BUILDER" missing.iso /var/tmp/out.img surplus
printf '%s\n' sentinel > "$TMPDIR/existing.img"
assert_cmd_failure "producer refuses an existing destination before base access" \
    bash "$BUILDER" missing.iso "$TMPDIR/existing.img"
assert_eq sentinel "$(cat "$TMPDIR/existing.img")" \
    "existing destination bytes remain unchanged"
printf '%s\n' symlink-target > "$TMPDIR/symlink-target"
ln -s "$TMPDIR/symlink-target" "$TMPDIR/output-link.img"
assert_cmd_failure "producer refuses a symlink destination" \
    bash "$BUILDER" missing.iso "$TMPDIR/output-link.img"
assert_eq symlink-target "$(cat "$TMPDIR/symlink-target")" \
    "symlink target bytes remain unchanged"

if [ -n "$REAL_ISO" ]; then
    epoch=1783900000
    first="$TMPDIR/first.img"
    second="$TMPDIR/second.img"
    assert_cmd_success "first authenticated updates image builds" \
        env SOURCE_DATE_EPOCH="$epoch" NOID_ANACONDA_PATCH_TMPDIR=/var/tmp \
        bash "$BUILDER" "$REAL_ISO" "$first"
    assert_cmd_success "second authenticated updates image builds" \
        env SOURCE_DATE_EPOCH="$epoch" NOID_ANACONDA_PATCH_TMPDIR=/var/tmp \
        bash "$BUILDER" "$REAL_ISO" "$second"
    assert_eq "$(sha256sum "$first" | awk '{print $1}')" \
        "$(sha256sum "$second" | awk '{print $1}')" \
        "same base/source/epoch produces byte-identical updates images"

    gzip -dc -- "$first" | cpio -it --quiet 2>/dev/null \
        > "$TMPDIR/members"
    printf '%s\n' \
        . \
        etc \
        etc/anaconda \
        etc/anaconda/profile.d \
        etc/anaconda/profile.d/noid-privacy.conf \
        etc/systemd \
        etc/systemd/system \
        etc/systemd/system/brltty.service \
        > "$TMPDIR/expected-members"
    assert_cmd_success "archive has exactly the declared eight members" \
        cmp -s "$TMPDIR/expected-members" "$TMPDIR/members"
    assert_not_grep 'transaction_progress.py' "$TMPDIR/members" \
        "runtime archive contains no RPM-transaction override"
    mkdir "$TMPDIR/extracted"
    (
        cd "$TMPDIR/extracted"
        gzip -dc -- "$first" | cpio -id --quiet 2>/dev/null
    )
    assert_grep_fixed 'id = noid-privacy-workstation' \
        "$TMPDIR/extracted/etc/anaconda/profile.d/noid-privacy.conf" \
        "extracted native profile is functional"
    assert_eq /dev/null \
        "$(readlink "$TMPDIR/extracted/etc/systemd/system/brltty.service")" \
        "extracted build-installer BRLTTY mask is exact"
else
    printf '  [SKIP] authenticated end-to-end image fixture: reviewed base ISO absent\n'
fi

test_finish
