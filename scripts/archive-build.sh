#!/usr/bin/env bash
# Archive one exact, VM-approved, release-signed candidate transactionally.
set -euo pipefail
export LC_ALL=C.UTF-8
export PATH=/usr/sbin:/usr/bin

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_OUTPUT="$REPO_ROOT/build-output/candidates"
BUILD_ARCHIVE="$REPO_ROOT/build-archive"
RELEASE_SIGNING_FPR=1ACBFCE49687FEBB91010E52F8E3F11D6962256F

log() { echo "[archive-build] $*"; }
die() { log "ERROR: $*" >&2; exit 1; }

[ "$#" -eq 1 ] || die "usage: $0 CANDIDATE_DIRECTORY"
CANDIDATE_INPUT=$1
[ -d "$BUILD_OUTPUT" ] && [ ! -L "$BUILD_OUTPUT" ] \
    || die "canonical candidate parent is missing or symlinked"
CANDIDATE_PARENT=$(readlink -e -- "$BUILD_OUTPUT") \
    || die "cannot canonicalize candidate parent"
[ -d "$CANDIDATE_INPUT" ] && [ ! -L "$CANDIDATE_INPUT" ] \
    || die "candidate must be a non-symlink directory"
CANDIDATE_DIR=$(readlink -e -- "$CANDIDATE_INPUT") \
    || die "cannot canonicalize candidate"
[ "${CANDIDATE_DIR%/*}" = "$CANDIDATE_PARENT" ] \
    || die "candidate is not a direct child of build-output/candidates"
CANDIDATE_NAME=${CANDIDATE_DIR##*/}
if [[ ! $CANDIDATE_NAME =~ ^unsigned-candidate-([0-9a-f]{12})-([0-9]+)-([A-Za-z0-9]{6})$ ]]; then
    die "candidate directory name does not match the canonical transaction schema"
fi
COMMIT_PREFIX=${BASH_REMATCH[1]}

for tool in awk cat chmod cmp cp find gpg grep mkdir mktemp mv python3 \
        readlink rm sed sha256sum sort stat xargs; do
    command -v "$tool" >/dev/null 2>&1 || die "required tool missing: $tool"
done
unsupported_entry=$(find "$CANDIDATE_DIR" -mindepth 1 \
    ! -type d ! -type f -print -quit)
[ -z "$unsupported_entry" ] \
    || die "candidate archive input contains an unsupported entry: $unsupported_entry"
unreadable=$(find "$CANDIDATE_DIR" -type f ! -readable -print -quit)
[ -z "$unreadable" ] || die "unreadable candidate file: $unreadable"
newline_name=$(find "$CANDIDATE_DIR" -depth -print0 | \
    python3 -c 'import os,sys; p=sys.stdin.buffer.read().split(b"\0"); print(next((os.fsdecode(x) for x in p if b"\n" in x), ""))')
[ -z "$newline_name" ] || die "newline in candidate pathname"

mapfile -t ISO_FILES < <(find "$CANDIDATE_DIR" -maxdepth 1 -type f \
    -name 'noid-privacy-workstation-44-*-x86_64.iso' -print | LC_ALL=C sort)
[ "${#ISO_FILES[@]}" -eq 1 ] || die "candidate must contain exactly one release ISO"
ISO_PATH=${ISO_FILES[0]}
ISO_NAME=${ISO_PATH##*/}
PUBLIC_MANIFEST="$CANDIDATE_DIR/SHA256SUMS"
PUBLIC_SIGNATURE="$CANDIDATE_DIR/SHA256SUMS.asc"
SIGNOFF="$CANDIDATE_DIR/vm-test-signoff.txt"
SIGNOFF_SIGNATURE="$CANDIDATE_DIR/vm-test-signoff.txt.asc"
for path in "$PUBLIC_MANIFEST" "$PUBLIC_SIGNATURE" "$SIGNOFF" "$SIGNOFF_SIGNATURE"; do
    [ -f "$path" ] && [ ! -L "$path" ] || die "required approval artifact missing: ${path##*/}"
done

ISO_SHA256=$(sha256sum -- "$ISO_PATH" | awk '{print $1}')
EXPECTED_PUBLIC_LINE="$ISO_SHA256  $ISO_NAME"
[ "$(grep -Fxc "$EXPECTED_PUBLIC_LINE" "$PUBLIC_MANIFEST" || true)" -eq 1 ] \
    && [ "$(grep -cEv '^[[:space:]]*(#|$)' "$PUBLIC_MANIFEST" || true)" -eq 1 ] \
    || die "public checksum is not the exact one-ISO manifest"
(
    cd "$CANDIDATE_DIR"
    sha256sum --check --strict --status SHA256SUMS
) || die "candidate ISO checksum verification failed"

verify_release_signature() {
    local signature=$1 content=$2
    gpg --batch --no-options --status-fd=1 \
        --verify "$signature" "$content" 2>/dev/null \
        | awk -v fpr="$RELEASE_SIGNING_FPR" '
            # GnuPG emits VALIDSIG for any cryptographically sound signature,
            # including one made by an EXPIRED or REVOKED key, and exits 0 in
            # both cases -- so a VALIDSIG-and-fingerprint gate accepted a
            # release signed with a key that is no longer valid. Verified
            # locally against a throwaway key generated under
            # --faked-system-time with one-day validity: gpg printed EXPKEYSIG
            # plus VALIDSIG, exited 0, and the previous gate returned 0.
            # GOODSIG is the status GnuPG withholds in exactly those cases, so
            # require it and reject the unusable-key statuses explicitly.
            $1=="[GNUPG:]" && ($2=="EXPKEYSIG" || $2=="REVKEYSIG" \
                || $2=="EXPSIG" || $2=="ERRSIG" || $2=="BADSIG") {bad++}
            $1=="[GNUPG:]" && $2=="GOODSIG" {good++}
            $1=="[GNUPG:]" && $2=="VALIDSIG" {total++; if ($3==fpr) valid++}
            END {exit !(total==1 && valid==1 && good==1 && !bad)}
        '
}
verify_release_signature "$PUBLIC_SIGNATURE" "$PUBLIC_MANIFEST" \
    || die "public checksum is not signed exactly once by the release key"
verify_release_signature "$SIGNOFF_SIGNATURE" "$SIGNOFF" \
    || die "VM sign-off is not signed exactly once by the release key"

mapfile -t commits < <(sed -n 's/^Git commit: \([0-9a-f]\{40\}\)$/\1/p' "$SIGNOFF")
[ "${#commits[@]}" -eq 1 ] && [ "${commits[0]:0:12}" = "$COMMIT_PREFIX" ] \
    || die "VM sign-off commit does not match candidate build ID"
[ "$(grep -Fxc "Candidate directory: $CANDIDATE_NAME" "$SIGNOFF" || true)" -eq 1 ] \
    || die "VM sign-off does not name this exact candidate"
[ "$(grep -Fxc "Candidate ISO SHA256: $ISO_SHA256" "$SIGNOFF" || true)" -eq 1 ] \
    || die "VM sign-off does not bind this exact ISO digest"
for approval in \
    'Final: 16/16 PASS + complete canonical pre-ship command ledger PASS + all three browser/kernel/BPF/Flatpak/hardware/Dracut/Snapper passes + Dracut hard-power-loss recovery + LAN-XDP + package freshness + ACL parity + enforcing AVC gates PASS — CLEAR FOR TAGGING/PUBLISHING' \
    'Complete pre-ship command ledger:     PASS' \
    'Dracut host-only gate live:           PASS' \
    'Dracut host-only gate fresh-install:  PASS' \
    'Dracut host-only gate reboot:         PASS' \
    'Dracut hard-power-loss recovery:      PASS' \
    'Neutral timezone live:                PASS' \
    'Selected timezone fresh-install:      PASS' \
    'Selected timezone reboot:             PASS' \
    'Final SquashFS image-hygiene gate: PASS' \
    'Two-install host-identity uniqueness gate: PASS' \
    'Package freshness gate: PASS' \
    'Raw/SquashFS/installed ACL parity gate: PASS' \
    'Installed enforcing-AVC gate: PASS'; do
    [ "$(grep -Fxc "$approval" "$SIGNOFF" || true)" -eq 1 ] \
        || die "VM sign-off lacks exact approval: $approval"
done
[ "$(grep -Ec '^Pre-ship executable inventory SHA256: [0-9a-f]{64}$' \
        "$SIGNOFF" || true)" -eq 1 ] \
    || die "VM sign-off lacks one canonical pre-ship executable inventory digest"

[ ! -L "$BUILD_ARCHIVE" ] || die "archive root must not be a symlink"
if [ -e "$BUILD_ARCHIVE" ] && [ ! -d "$BUILD_ARCHIVE" ]; then
    die "archive root is not a directory"
fi
mkdir -p "$BUILD_ARCHIVE"
ARCHIVE_ROOT=$(readlink -e -- "$BUILD_ARCHIVE") \
    || die "cannot canonicalize archive root"
FINAL_NAME="signed-release-${CANDIDATE_NAME#unsigned-candidate-}"
FINAL_DIR="$ARCHIVE_ROOT/$FINAL_NAME"
[ ! -e "$FINAL_DIR" ] && [ ! -L "$FINAL_DIR" ] \
    || die "archive destination already exists: $FINAL_NAME"
TRANSACTION=$(mktemp -d "$ARCHIVE_ROOT/.transaction.signed-release.XXXXXX")
chmod 0700 "$TRANSACTION"
cleanup() { rm -rf -- "$TRANSACTION" 2>/dev/null || true; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

INPUT_MANIFEST="$TRANSACTION/INPUT-SHA256SUMS"
OUTPUT_MANIFEST="$TRANSACTION/OUTPUT-SHA256SUMS"
(
    cd "$CANDIDATE_DIR"
    find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum --
) > "$INPUT_MANIFEST"
mkdir "$TRANSACTION/candidate"
cp -a --reflink=auto "$CANDIDATE_DIR/." "$TRANSACTION/candidate/"
(
    cd "$TRANSACTION/candidate"
    find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum --
) > "$OUTPUT_MANIFEST"
cmp -s "$INPUT_MANIFEST" "$OUTPUT_MANIFEST" \
    || die "archived candidate bytes differ from authenticated input"

cat > "$TRANSACTION/ARCHIVE-METADATA" <<EOF
NOID_BUILD_ARCHIVE_V2
CANDIDATE_NAME=$CANDIDATE_NAME
SOURCE_COMMIT=${commits[0]}
ISO_NAME=$ISO_NAME
ISO_SHA256=$ISO_SHA256
RELEASE_SIGNING_FINGERPRINT=$RELEASE_SIGNING_FPR
EOF
(
    cd "$TRANSACTION"
    mapfile -d '' -t archive_files < <(
        find . -type f -print0 | LC_ALL=C sort -z
    )
    printf '%s\0' "${archive_files[@]}" | xargs -0 -r sha256sum -- \
        > ARCHIVE-SHA256SUMS
    sha256sum --check --strict --status ARCHIVE-SHA256SUMS
) || die "complete archive manifest verification failed"

# Flush every file, then directories from leaves to root. Publication is a
# same-filesystem rename and the archive-root fsync persists the new name.
python3 - "$TRANSACTION" <<'PY'
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
for path in sorted((p for p in root.rglob("*") if p.is_file())):
    with path.open("rb") as stream:
        os.fsync(stream.fileno())
directories = [root, *(p for p in root.rglob("*") if p.is_dir())]
for path in sorted(directories, key=lambda p: len(p.parts), reverse=True):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PY

mv -T --update=none-fail -- "$TRANSACTION" "$FINAL_DIR" \
    || die "archive publication collided: $FINAL_NAME"
TRANSACTION=""
archive_fd=$(python3 - "$ARCHIVE_ROOT" <<'PY'
import os, sys
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY)
os.fsync(fd)
os.close(fd)
print("ok")
PY
)
[ "$archive_fd" = ok ] || die "archive-root fsync failed"
trap - EXIT HUP INT TERM

log "OK: authenticated archive published atomically"
log "  $FINAL_DIR"
log "  Verify: (cd '$FINAL_DIR' && sha256sum -c --strict ARCHIVE-SHA256SUMS)"
