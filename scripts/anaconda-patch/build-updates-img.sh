#!/usr/bin/env bash
# Build the minimal authenticated inst.updates payload used by the canonical
# Fedora 44 KVM compose. It contains only native Anaconda profile data and a
# build-installer-local BRLTTY systemd mask; it never overrides RPM transaction
# handling.

set -euo pipefail
export LC_ALL=C.UTF-8
export PATH=/usr/sbin:/usr/bin

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VERIFY_BASE="$REPO_ROOT/scripts/verify-fedora-base-iso.sh"
M32_PATH="$REPO_ROOT/kickstart/snippets/32-branding.ks"

die() { echo "[build-updates-img] ERROR: $*" >&2; exit 1; }
log() { echo "[build-updates-img] $*"; }

[ "$#" -eq 2 ] \
    || die "usage: $0 /path/to/REVIEWED-FEDORA-NETINST.iso /absolute/output.img"
NETINST_ISO=$1
OUTPUT_IMG=$2
[[ $OUTPUT_IMG = /* ]] || die "output path must be absolute"
output_name=${OUTPUT_IMG##*/}
[[ $output_name =~ ^[A-Za-z0-9._-]+$ ]] || die "unsafe output filename"
output_parent=${OUTPUT_IMG%/*}
[ -n "$output_parent" ] || output_parent=/
[ -d "$output_parent" ] && [ ! -L "$output_parent" ] && [ -w "$output_parent" ] \
    || die "output parent must be a writable non-symlink directory"
output_parent=$(readlink -e -- "$output_parent") \
    || die "cannot canonicalize output parent"
OUTPUT_IMG="$output_parent/$output_name"
[ ! -e "$OUTPUT_IMG" ] && [ ! -L "$OUTPUT_IMG" ] \
    || die "output already exists; refusing to replace it"

[ -x "$VERIFY_BASE" ] || die "base-ISO verifier is missing or not executable"
[ -f "$M32_PATH" ] && [ ! -L "$M32_PATH" ] \
    || die "Module 32 profile source is missing or symlinked"
for tool in awk cmp cpio find git grep gzip install ln mktemp python3 \
        readlink sha256sum sort stat touch; do
    command -v "$tool" >/dev/null 2>&1 || die "required tool missing: $tool"
done

# Authenticate the exact base even though the minimal overlay no longer copies
# Python from it. This binds standalone invocations to the same reviewed
# installer runtime that will consume the profile and mask.
"$VERIFY_BASE" "$NETINST_ISO" \
    || die "Fedora base-ISO provenance/integrity verification failed"

PATCH_TMPDIR=${NOID_ANACONDA_PATCH_TMPDIR:-/var/tmp}
[[ $PATCH_TMPDIR = /* ]] || die "workdir must be an absolute path"
[ ! -L "$PATCH_TMPDIR" ] || die "workdir must not be a symlink"
PATCH_TMPDIR=$(readlink -e -- "$PATCH_TMPDIR" 2>/dev/null || true)
[ -n "$PATCH_TMPDIR" ] && [ -d "$PATCH_TMPDIR" ] \
    && [ ! -L "$PATCH_TMPDIR" ] && [ -w "$PATCH_TMPDIR" ] \
    || die "workdir must be a writable non-symlink directory"
work_fstype=$(stat -f -c %T -- "$PATCH_TMPDIR" 2>/dev/null || true)
case "$work_fstype" in
    tmpfs|ramfs) die "Anaconda updates workdir is memory-backed ($work_fstype)" ;;
    "") die "cannot determine Anaconda updates workdir filesystem" ;;
esac

: "${SOURCE_DATE_EPOCH:=$(git -C "$REPO_ROOT" log -1 --format=%ct 2>/dev/null || true)}"
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]] \
    || die "SOURCE_DATE_EPOCH must be an unsigned integer"

WORK_DIR=$(mktemp -d -p "$PATCH_TMPDIR" noid-anaconda-updates.XXXXXX)
OUTPUT_TMP=$(mktemp "$output_parent/.noid-anaconda-updates.XXXXXX")
cleanup() {
    rm -rf -- "$WORK_DIR" 2>/dev/null || true
    rm -f -- "$OUTPUT_TMP" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
chmod 0700 "$WORK_DIR"
chmod 0600 "$OUTPUT_TMP"
UPDATES_DIR="$WORK_DIR/updates"
PROFILE_DIR="$UPDATES_DIR/etc/anaconda/profile.d"
SYSTEMD_DIR="$UPDATES_DIR/etc/systemd/system"
install -d -m 0755 "$PROFILE_DIR" "$SYSTEMD_DIR"

log "Extracting the unique Module 32 Anaconda profile"
PROFILE_HEREDOC_OPEN="publish_root_file /etc/anaconda/profile.d/noid-privacy.conf 0644 <<'NOIDPROF_EOF'"
[ "$(grep -Fxc "$PROFILE_HEREDOC_OPEN" "$M32_PATH" || true)" -eq 1 ] \
    || die "profile heredoc opening marker is not unique"
[ "$(grep -Fxc 'NOIDPROF_EOF' "$M32_PATH" || true)" -eq 1 ] \
    || die "profile heredoc closing marker is not unique"
awk -v opening="$PROFILE_HEREDOC_OPEN" '
    $0 == opening {
        if (seen++) exit 2
        copy=1
        next
    }
    copy && $0 == "NOIDPROF_EOF" { copy=0; closed=1; next }
    copy { print }
    END { if (seen != 1 || !closed || copy) exit 3 }
' "$M32_PATH" > "$PROFILE_DIR/noid-privacy.conf" \
    || die "profile heredoc extraction failed"
[ -s "$PROFILE_DIR/noid-privacy.conf" ] || die "profile extraction is empty"
chmod 0644 "$PROFILE_DIR/noid-privacy.conf"

log "Staging the build-installer-only native BRLTTY mask"
ln -s /dev/null "$SYSTEMD_DIR/brltty.service"
[ "$(readlink -- "$SYSTEMD_DIR/brltty.service")" = /dev/null ] \
    || die "BRLTTY mask target mismatch"

# Normalize every archive timestamp, including the symlink. GNU cpio's
# reproducible mode also clears inode/device variance; sorted NUL input fixes
# pathname order and gzip -n removes header name/time fields.
find "$UPDATES_DIR" -exec touch -h -d "@$SOURCE_DATE_EPOCH" -- {} +
log "Building deterministic newc+gzip payload"
(
    cd "$UPDATES_DIR"
    LC_ALL=C find . -print0 | LC_ALL=C sort -z \
        | cpio --null --create --format=newc --owner=0:0 \
            --reproducible 2>/dev/null \
        | gzip -n -9
) > "$OUTPUT_TMP"
chmod 0644 "$OUTPUT_TMP"
gzip -t -- "$OUTPUT_TMP" || die "gzip integrity check failed"

ACTUAL_MANIFEST="$WORK_DIR/actual-manifest"
EXPECTED_MANIFEST="$WORK_DIR/expected-manifest"
gzip -dc -- "$OUTPUT_TMP" | cpio -it --quiet 2>/dev/null \
    > "$ACTUAL_MANIFEST" || die "cannot list updates archive"
printf '%s\n' \
    . \
    etc \
    etc/anaconda \
    etc/anaconda/profile.d \
    etc/anaconda/profile.d/noid-privacy.conf \
    etc/systemd \
    etc/systemd/system \
    etc/systemd/system/brltty.service \
    > "$EXPECTED_MANIFEST"
cmp -s "$EXPECTED_MANIFEST" "$ACTUAL_MANIFEST" \
    || die "updates archive member set/order drifted"
if grep -Fq 'transaction_progress.py' "$ACTUAL_MANIFEST"; then
    die "forbidden RPM-transaction override entered updates image"
fi

VERIFY_DIR="$WORK_DIR/verify"
install -d -m 0700 "$VERIFY_DIR"
(
    cd "$VERIFY_DIR"
    # --no-absolute-filenames even though this round-trips an archive this
    # script just created and whose member set was cmp-compared against the
    # pinned manifest above: GNU cpio writes absolute member names outside the
    # target directory by default, and a containment guarantee should not
    # depend on an earlier check still running first. Matches M17's extraction.
    gzip -dc -- "$OUTPUT_TMP" | cpio -id --quiet --no-absolute-filenames 2>/dev/null
) || die "updates archive extraction failed"
cmp -s "$PROFILE_DIR/noid-privacy.conf" \
    "$VERIFY_DIR/etc/anaconda/profile.d/noid-privacy.conf" \
    || die "profile bytes changed across the archive"
[ -L "$VERIFY_DIR/etc/systemd/system/brltty.service" ] \
    && [ "$(readlink -- "$VERIFY_DIR/etc/systemd/system/brltty.service")" = /dev/null ] \
    || die "BRLTTY mask did not survive archive extraction"

# fsync the complete inode, publish with an atomic no-replace hard link, fsync
# the directory entry, then remove the private temporary name. os.link fails
# atomically if a file or symlink appeared at OUTPUT_IMG.
python3 - "$OUTPUT_TMP" "$OUTPUT_IMG" "$output_parent" <<'PY'
import os
import sys

temporary, destination, parent = sys.argv[1:]
with open(temporary, "rb") as stream:
    os.fsync(stream.fileno())
os.link(temporary, destination, follow_symlinks=False)
directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory_fd)
    os.unlink(temporary)
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
OUTPUT_TMP=""

output_size=$(stat -c %s -- "$OUTPUT_IMG")
output_hash=$(sha256sum -- "$OUTPUT_IMG" | awk '{print $1}')
log "OK: authenticated deterministic updates image published"
log "  Output: $OUTPUT_IMG"
log "  Size:   $output_size bytes"
log "  SHA256: $output_hash"
