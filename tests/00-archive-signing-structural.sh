#!/usr/bin/env bash
# Exact source authentication and fail-before-publish archive fixtures.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

ROOT=$(find_project_root)
SCRIPT="$ROOT/scripts/archive-build.sh"
RELEASE_DOC="$ROOT/docs/release-process.md"
TMPDIR=$(mktemp -d "${NOID_TEST_EXEC_TMPDIR:-/var/tmp}/noid-archive-test.XXXXXX")
trap 'rm -rf -- "$TMPDIR"' EXIT HUP INT TERM
FIXTURE_REPO="$TMPDIR/repo"
CANDIDATE_NAME=unsigned-candidate-0123456789ab-1783900000-AbCd12
CANDIDATE="$FIXTURE_REPO/build-output/candidates/$CANDIDATE_NAME"
FINAL_NAME=signed-release-0123456789ab-1783900000-AbCd12
FPR=1ACBFCE49687FEBB91010E52F8E3F11D6962256F
COMMIT=0123456789abcdef0123456789abcdef01234567
FINAL_APPROVAL='Final: 16/16 PASS + complete canonical pre-ship command ledger PASS + all three browser/kernel/BPF/Flatpak/hardware/Dracut/Snapper passes + Dracut hard-power-loss recovery + LAN-XDP + package freshness + ACL parity + enforcing AVC gates PASS — CLEAR FOR TAGGING/PUBLISHING'

test_start "00-archive-signing-structural"
assert_cmd_success "archive helper syntax" bash -n "$SCRIPT"
assert_grep_fixed 'export PATH=/usr/sbin:/usr/bin' "$SCRIPT" \
    "archive helper resolves only Fedora system tools"
assert_grep_fixed '[ "$#" -eq 1 ]' "$SCRIPT" \
    "archive helper requires exactly one candidate path"
assert_not_grep_extended 'BUILD_NUMBER|BUILD_NUM|build[0-9]+-' "$SCRIPT" \
    "archive identity has no retired manual build number"
assert_grep_fixed 'os.fsync(stream.fileno())' "$SCRIPT" \
    "archive files are flushed before publication"
assert_grep_fixed 'mv -T --update=none-fail -- "$TRANSACTION" "$FINAL_DIR"' "$SCRIPT" \
    "archive publication is one no-replace same-filesystem directory rename"
assert_grep_fixed '! -type d ! -type f' "$SCRIPT" \
    "archive input is closed to ordinary files and directories"
for signal_contract in \
    "trap 'exit 129' HUP" \
    "trap 'exit 130' INT" \
    "trap 'exit 143' TERM"; do
    assert_grep_fixed "$signal_contract" "$SCRIPT" \
        "archive helper preserves the signal-derived exit status"
done
assert_not_grep 'NOID_REQUIRE_SIGNATURE' "$SCRIPT" \
    "archive helper has no unsigned or key-availability branch"
assert_grep_fixed "$FINAL_APPROVAL" "$SCRIPT" \
    "archive helper requires the complete current release approval"
assert_grep_fixed "$FINAL_APPROVAL" "$RELEASE_DOC" \
    "release template and archive approval are byte-identical"
for new_release_gate in \
        'Neutral timezone live:                PASS' \
        'Selected timezone fresh-install:      PASS' \
        'Selected timezone reboot:             PASS' \
        'Final SquashFS image-hygiene gate: PASS' \
        'Two-install host-identity uniqueness gate: PASS'; do
    assert_grep_fixed "$new_release_gate" "$SCRIPT" \
        "archive helper requires $new_release_gate"
    assert_grep_fixed "${new_release_gate%PASS}[PASS|FAIL]" "$RELEASE_DOC" \
        "release template exposes ${new_release_gate%: PASS}"
done

mkdir -p "$FIXTURE_REPO/scripts" "$CANDIDATE/private-build-evidence" \
    "$FIXTURE_REPO/bin"
cp "$SCRIPT" "$FIXTURE_REPO/scripts/archive-build.sh"
sed -i "s#^export PATH=/usr/sbin:/usr/bin\$#export PATH=$FIXTURE_REPO/bin:/usr/sbin:/usr/bin#" \
    "$FIXTURE_REPO/scripts/archive-build.sh"
chmod 0755 "$FIXTURE_REPO/scripts/archive-build.sh"
printf '%s\n' candidate-iso-bytes > \
    "$CANDIDATE/noid-privacy-workstation-44-v1.7-x86_64.iso"
ISO_NAME=noid-privacy-workstation-44-v1.7-x86_64.iso
ISO_SHA=$(sha256sum "$CANDIDATE/$ISO_NAME" | awk '{print $1}')
printf '%s  %s\n' "$ISO_SHA" "$ISO_NAME" > "$CANDIDATE/SHA256SUMS"
printf '%s\n' signature > "$CANDIDATE/SHA256SUMS.asc"
printf '%s\n' private-evidence > \
    "$CANDIDATE/private-build-evidence/compose.log"
cat > "$CANDIDATE/vm-test-signoff.txt" <<EOF
VM-test sign-off
Git commit: $COMMIT
Candidate directory: $CANDIDATE_NAME
Candidate ISO SHA256: $ISO_SHA
Complete pre-ship command ledger:     PASS
Pre-ship executable inventory SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
$FINAL_APPROVAL
Dracut host-only gate live:           PASS
Dracut host-only gate fresh-install:  PASS
Dracut host-only gate reboot:         PASS
Dracut hard-power-loss recovery:      PASS
Neutral timezone live:                PASS
Selected timezone fresh-install:      PASS
Selected timezone reboot:             PASS
Final SquashFS image-hygiene gate: PASS
Two-install host-identity uniqueness gate: PASS
Package freshness gate: PASS
Raw/SquashFS/installed ACL parity gate: PASS
Installed enforcing-AVC gate: PASS
EOF
printf '%s\n' signoff-signature > "$CANDIDATE/vm-test-signoff.txt.asc"
# GnuPG status stub. The previous version emitted VALIDSIG unconditionally, so
# the fingerprint pin had no negative fixture at all and the release gate could
# not be shown to reject anything. GnuPG emits VALIDSIG for any
# cryptographically sound signature -- including one from an EXPIRED or REVOKED
# key, where it exits 0 and withholds GOODSIG -- so those are the cases the gate
# has to refuse. NOID_TEST_GPG_MODE selects the scenario.
cat > "$FIXTURE_REPO/bin/gpg" <<EOF
#!/bin/bash
case "\${NOID_TEST_GPG_MODE:-good}" in
    good)
        printf '%s\n' '[GNUPG:] GOODSIG $FPR NoID Privacy Release'
        printf '%s\n' '[GNUPG:] VALIDSIG $FPR 2026-07-13 0 4 0 1 10 00 $FPR'
        ;;
    expired)
        printf '%s\n' '[GNUPG:] EXPKEYSIG $FPR NoID Privacy Release'
        printf '%s\n' '[GNUPG:] VALIDSIG $FPR 2026-07-13 0 4 0 1 10 00 $FPR'
        ;;
    revoked)
        printf '%s\n' '[GNUPG:] REVKEYSIG $FPR NoID Privacy Release'
        printf '%s\n' '[GNUPG:] VALIDSIG $FPR 2026-07-13 0 4 0 1 10 00 $FPR'
        ;;
    foreign)
        printf '%s\n' '[GNUPG:] GOODSIG 0000000000000000000000000000000000000000 Other Signer'
        printf '%s\n' '[GNUPG:] VALIDSIG 0000000000000000000000000000000000000000 2026-07-13 0 4 0 1 10 00 0000000000000000000000000000000000000000'
        ;;
    double)
        printf '%s\n' '[GNUPG:] GOODSIG $FPR NoID Privacy Release'
        printf '%s\n' '[GNUPG:] VALIDSIG $FPR 2026-07-13 0 4 0 1 10 00 $FPR'
        printf '%s\n' '[GNUPG:] GOODSIG $FPR NoID Privacy Release'
        printf '%s\n' '[GNUPG:] VALIDSIG $FPR 2026-07-13 0 4 0 1 10 00 $FPR'
        ;;
    unsigned)
        ;;
esac
EOF
cat > "$FIXTURE_REPO/bin/mv" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${NOID_TEST_INJECT_MV_COLLISION:-0}" = 1 ]; then
    destination=${!#}
    mkdir -- "$destination"
    printf '%s\n' competing-publisher > "$destination/OWNER"
fi
exec /usr/bin/mv "$@"
EOF
chmod 0755 "$FIXTURE_REPO/bin/gpg" "$FIXTURE_REPO/bin/mv"
ARCHIVE=(env PATH="$FIXTURE_REPO/bin:/usr/bin:/bin" \
    "$FIXTURE_REPO/scripts/archive-build.sh")

assert_cmd_failure "archive helper rejects extra arguments" \
    "${ARCHIVE[@]}" "$CANDIDATE" surplus

cp "$CANDIDATE/$ISO_NAME" "$TMPDIR/iso.clean"
printf '%s\n' tampered >> "$CANDIDATE/$ISO_NAME"
assert_cmd_failure "tampered candidate ISO is rejected before publication" \
    "${ARCHIVE[@]}" "$CANDIDATE"
assert_cmd_failure "tampered candidate leaves no final archive" \
    test -e "$FIXTURE_REPO/build-archive/$FINAL_NAME"
cp "$TMPDIR/iso.clean" "$CANDIDATE/$ISO_NAME"

cp "$CANDIDATE/vm-test-signoff.txt" "$TMPDIR/signoff.clean"
grep -v '^Package freshness gate:' "$TMPDIR/signoff.clean" \
    > "$CANDIDATE/vm-test-signoff.txt"
assert_cmd_failure "incomplete signed VM approval is rejected" \
    "${ARCHIVE[@]}" "$CANDIDATE"
cp "$TMPDIR/signoff.clean" "$CANDIDATE/vm-test-signoff.txt"

grep -v '^Two-install host-identity uniqueness gate:' \
    "$TMPDIR/signoff.clean" > "$CANDIDATE/vm-test-signoff.txt"
assert_cmd_failure "missing two-install identity approval is rejected" \
    "${ARCHIVE[@]}" "$CANDIDATE"
cp "$TMPDIR/signoff.clean" "$CANDIDATE/vm-test-signoff.txt"

for missing_timezone_gate in \
        'Neutral timezone live:' \
        'Selected timezone fresh-install:' \
        'Selected timezone reboot:'; do
    grep -vF "$missing_timezone_gate" "$TMPDIR/signoff.clean" \
        > "$CANDIDATE/vm-test-signoff.txt"
    assert_cmd_failure \
        "missing ${missing_timezone_gate%:} approval is rejected" \
        "${ARCHIVE[@]}" "$CANDIDATE"
    cp "$TMPDIR/signoff.clean" "$CANDIDATE/vm-test-signoff.txt"
done
unset missing_timezone_gate

mv "$CANDIDATE/SHA256SUMS.asc" "$TMPDIR/checksum.asc"
assert_cmd_failure "unsigned checksum is rejected" \
    "${ARCHIVE[@]}" "$CANDIDATE"
mv "$TMPDIR/checksum.asc" "$CANDIDATE/SHA256SUMS.asc"

ln -s "$CANDIDATE" \
    "$FIXTURE_REPO/build-output/candidates/unsigned-candidate-link"
assert_cmd_failure "symlink candidate is rejected" \
    "${ARCHIVE[@]}" \
    "$FIXTURE_REPO/build-output/candidates/unsigned-candidate-link"

mkfifo "$CANDIDATE/unmanifested-fifo"
assert_cmd_failure "unmanifested special entries are rejected" \
    "${ARCHIVE[@]}" "$CANDIDATE"
rm -f -- "$CANDIDATE/unmanifested-fifo"

assert_cmd_failure "publication-time collision is rejected atomically" \
    env NOID_TEST_INJECT_MV_COLLISION=1 "${ARCHIVE[@]}" "$CANDIDATE"
assert_file_exists "$FIXTURE_REPO/build-archive/$FINAL_NAME/OWNER" \
    "publication-time collision preserves the competing destination"
assert_cmd_failure "publication-time collision exposes no candidate payload" \
    test -e "$FIXTURE_REPO/build-archive/$FINAL_NAME/candidate"
rm -rf -- "$FIXTURE_REPO/build-archive/$FINAL_NAME"

# Negative fixtures for the release-signature gate. Without these the pin was
# unfalsifiable: the stub always answered with the pinned VALIDSIG, so the
# assertions above proved only that a correct signature is accepted. An EXPIRED
# or REVOKED signing key still produces VALIDSIG and a zero gpg exit status, so
# a key that has been rotated out -- or revoked after a compromise -- would have
# authenticated a release. Each case must be refused before publication.
for signature_case in expired:"an expired signing key" \
        revoked:"a revoked signing key" \
        foreign:"a signature from an unpinned key" \
        double:"a doubly signed manifest" \
        unsigned:"a signature with no status output"; do
    signature_mode=${signature_case%%:*}
    signature_label=${signature_case#*:}
    assert_cmd_failure "release gate rejects ${signature_label}" \
        env NOID_TEST_GPG_MODE="$signature_mode" "${ARCHIVE[@]}" "$CANDIDATE"
    assert_cmd_failure "${signature_label} leaves no published archive" \
        test -e "$FIXTURE_REPO/build-archive/$FINAL_NAME"
done
unset signature_case signature_mode signature_label

assert_cmd_success "authenticated candidate archives transactionally" \
    "${ARCHIVE[@]}" "$CANDIDATE"
FINAL="$FIXTURE_REPO/build-archive/$FINAL_NAME"
assert_file_exists "$FINAL/candidate/$ISO_NAME" \
    "archive contains the exact candidate ISO"
assert_cmd_success "archived ISO is byte-identical to source" \
    cmp -s "$CANDIDATE/$ISO_NAME" "$FINAL/candidate/$ISO_NAME"
assert_file_exists "$FINAL/INPUT-SHA256SUMS" \
    "archive retains complete authenticated input manifest"
assert_file_exists "$FINAL/OUTPUT-SHA256SUMS" \
    "archive retains complete verified output manifest"
assert_cmd_success "input/output manifests are byte-identical" \
    cmp -s "$FINAL/INPUT-SHA256SUMS" "$FINAL/OUTPUT-SHA256SUMS"
assert_cmd_success "complete archive manifest verifies" \
    bash -c 'cd "$1" && sha256sum -c --strict --status ARCHIVE-SHA256SUMS' \
        _ "$FINAL"

before=$(find "$FINAL" -type f -print0 | sort -z | xargs -0 sha256sum)
assert_cmd_failure "existing archive destination is never replaced" \
    "${ARCHIVE[@]}" "$CANDIDATE"
after=$(find "$FINAL" -type f -print0 | sort -z | xargs -0 sha256sum)
assert_eq "$before" "$after" \
    "collision leaves the complete published archive byte-identical"

test_finish
