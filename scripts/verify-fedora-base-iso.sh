#!/usr/bin/env bash
# Verify the exact Fedora 44 netinst image used as the Anaconda build base.
# The reviewed checksum manifest is clear-signed by Fedora's pinned F44 key.

set -euo pipefail
export LC_ALL=C.UTF-8
export PATH=/usr/sbin:/usr/bin

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE_RELEASE="44-1.7"
FEDORA_RELEASE="${BASE_RELEASE%%-*}"
EXPECTED_NAME="Fedora-Server-netinst-x86_64-${BASE_RELEASE}.iso"
EXPECTED_SIZE=1228384256
EXPECTED_SHA256="ae20c06bea746913cadea7d80463e13f4bf55bee4df2918111c921c674b70283"
FEDORA_FPR="36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6"
FEDORA_KEY="/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-${FEDORA_RELEASE}-primary"
CHECKSUM_FILE="${REPO_ROOT}/scripts/fedora-base/Fedora-Server-${BASE_RELEASE}-x86_64-CHECKSUM"

die() {
    echo "[verify-fedora-base] ERROR: $*" >&2
    exit 1
}

if [ "$#" -eq 1 ] && [ "$1" = --print-expected-name ]; then
    printf '%s\n' "$EXPECTED_NAME"
    exit 0
fi
[ "$#" -eq 1 ] || die "usage: $0 /path/to/${EXPECTED_NAME}"
ISO_PATH="$1"
[ -f "$ISO_PATH" ] || die "base ISO is not a regular file: $ISO_PATH"
[ ! -L "$ISO_PATH" ] || die "base ISO must not be a symbolic link: $ISO_PATH"
[ "$(basename -- "$ISO_PATH")" = "$EXPECTED_NAME" ] \
    || die "unsupported base ISO filename: $(basename -- "$ISO_PATH")"
[ -r "$FEDORA_KEY" ] || die "Fedora ${FEDORA_RELEASE} signing key is missing: $FEDORA_KEY"
[ -r "$CHECKSUM_FILE" ] || die "reviewed Fedora checksum manifest is missing: $CHECKSUM_FILE"
command -v gpg >/dev/null 2>&1 || die "gpg is required to verify Fedora provenance"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"

mapfile -t key_fprs < <(
    gpg --batch --no-options --with-colons --show-keys "$FEDORA_KEY" 2>/dev/null \
        | awk -F: '$1=="fpr" {print toupper($10)}'
)
[ "${#key_fprs[@]}" -eq 1 ] \
    || die "Fedora key file must contain exactly one primary fingerprint"
[ "${key_fprs[0]}" = "$FEDORA_FPR" ] \
    || die "Fedora signing-key fingerprint mismatch"

tmp_dir="$(mktemp -d "${TMPDIR:-/var/tmp}/noid-fedora-base-verify.XXXXXX")"
chmod 0700 "$tmp_dir"
cleanup() { rm -rf -- "$tmp_dir"; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

gpg --batch --homedir "$tmp_dir" --import "$FEDORA_KEY" >/dev/null 2>&1 \
    || die "could not import the pinned Fedora 44 key"
if ! gpg --batch --homedir "$tmp_dir" --status-fd=3 \
        --output "$tmp_dir/checksums.txt" --decrypt "$CHECKSUM_FILE" \
        3>"$tmp_dir/gpg.status" 2>"$tmp_dir/gpg.stderr"; then
    die "Fedora checksum-manifest signature verification failed"
fi
awk -v fpr="$FEDORA_FPR" '
    # Same hardening as scripts/archive-build.sh: VALIDSIG alone is emitted for
    # a signature from an EXPIRED or REVOKED key and gpg still exits 0, so a
    # rotated-out or compromised-and-revoked Fedora signing key would still
    # authenticate the base-image manifest. GOODSIG is withheld in exactly
    # those cases; require it and reject the unusable-key statuses outright.
    $1=="[GNUPG:]" && ($2=="EXPKEYSIG" || $2=="REVKEYSIG" \
        || $2=="EXPSIG" || $2=="ERRSIG" || $2=="BADSIG") {bad++}
    $1=="[GNUPG:]" && $2=="GOODSIG" {good++}
    $1=="[GNUPG:]" && $2=="VALIDSIG" && toupper($3)==fpr {valid++}
    END {exit !(valid==1 && good==1 && !bad)}
' "$tmp_dir/gpg.status" || die "manifest was not signed exactly once by a currently valid pinned Fedora 44 key"

expected_line="SHA256 (${EXPECTED_NAME}) = ${EXPECTED_SHA256}"
[ "$(grep -Fxc "$expected_line" "$tmp_dir/checksums.txt" || true)" -eq 1 ] \
    || die "signed manifest does not contain the exact reviewed netinst checksum"
[ "$(grep -Fxc "# ${EXPECTED_NAME}: ${EXPECTED_SIZE} bytes" "$tmp_dir/checksums.txt" || true)" -eq 1 ] \
    || die "signed manifest does not contain the exact reviewed netinst size"

actual_size="$(stat -c '%s' -- "$ISO_PATH" 2>/dev/null || true)"
[ "$actual_size" = "$EXPECTED_SIZE" ] \
    || die "base ISO size mismatch (expected ${EXPECTED_SIZE}, got ${actual_size:-unknown})"
actual_sha256="$(sha256sum -- "$ISO_PATH" | awk '{print $1}')"
[ "$actual_sha256" = "$EXPECTED_SHA256" ] \
    || die "base ISO SHA256 mismatch"

echo "[verify-fedora-base] OK: Fedora 44 signed manifest, fingerprint, size and SHA256 verified"
