#!/usr/bin/env bash
# Build the complete offline source/test support ISO used by VM release audits.
set -euo pipefail
umask 077
export LC_ALL=C.UTF-8
export PATH=/usr/sbin:/usr/bin

FEDORA_RELEASE=44
FEDORA_KEY_FINGERPRINT='36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6'
AUDITOR_SOURCE_COMMIT='e204bb68a7ac3ce08acc685fb56356d460ba3710'
AUDITOR_SOURCE_SIZE='600495'
AUDITOR_SOURCE_SHA256='724213827287ed4d203bbd6c6d2706b7f60225bde5134c63a6c525bf6e46f0ac'
VOLUME_ID='NOID_AUDIT_SUPPORT'

usage() {
    echo "Usage: $0 /absolute/write-once-output.iso" >&2
}
die() {
    echo "ERROR: $*" >&2
    exit 1
}

case "$#" in
    1) ;;
    *) usage; exit 2 ;;
esac

OUTPUT=$1
[[ "$OUTPUT" = /* ]] || die 'output path must be absolute'
case "$OUTPUT" in *$'\n'*|*$'\r'*) die 'output path contains a line break' ;; esac
[ ! -e "$OUTPUT" ] && [ ! -L "$OUTPUT" ] || die 'output path already exists'
OUTPUT_PARENT=$(dirname "$OUTPUT")
[ -d "$OUTPUT_PARENT" ] && [ ! -L "$OUTPUT_PARENT" ] \
    || die 'output parent must be a real directory'
OUTPUT_PARENT=$(realpath -e "$OUTPUT_PARENT")
[ "$(dirname "$OUTPUT")" = "$OUTPUT_PARENT" ] \
    || die 'output parent must be canonical and contain no symlink component'

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AUDITOR_SOURCE=${NOID_AUDIT_SRC:-"${REPO_ROOT%/*}/noid-privacy-linux/noid-privacy-linux.sh"}
SIGNATURE_LIB="$REPO_ROOT/scripts/lib/verify-rpm-signatures.sh"
FEDORA_KEY=$(readlink -e "/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-${FEDORA_RELEASE}-x86_64")

for tool in cmp createrepo_c dnf git gpg patch rpm rpmkeys sha256sum sudo tar xorriso; do
    command -v "$tool" >/dev/null 2>&1 || die "required tool missing: $tool"
done
[ -f "$SIGNATURE_LIB" ] && [ ! -L "$SIGNATURE_LIB" ] \
    || die 'isolated RPM verification library is missing or symlinked'
[ -f "$AUDITOR_SOURCE" ] && [ ! -L "$AUDITOR_SOURCE" ] \
    || die 'reviewed noid-privacy-linux.sh source is missing or symlinked'
[ -f "$FEDORA_KEY" ] && [ ! -L "$FEDORA_KEY" ] \
    || die 'Fedora release key target is missing or symlinked'
[ "$(stat -c %s "$AUDITOR_SOURCE")" = "$AUDITOR_SOURCE_SIZE" ] \
    || die 'reviewed noid-privacy-linux.sh byte count drifted'
[ "$(sha256sum "$AUDITOR_SOURCE" | awk '{print $1}')" = "$AUDITOR_SOURCE_SHA256" ] \
    || die 'reviewed noid-privacy-linux.sh bytes drifted'

AUDITOR_REPO=$(git -C "$(dirname "$AUDITOR_SOURCE")" rev-parse --show-toplevel 2>/dev/null) \
    || die 'reviewed auditor source is not in its Git checkout'
[ "$(readlink -e "$AUDITOR_SOURCE")" = \
    "$(readlink -e "$AUDITOR_REPO/noid-privacy-linux.sh")" ] \
    || die 'auditor source is not the repository-root release script'
[ "$(git -C "$AUDITOR_REPO" rev-parse --verify HEAD)" = "$AUDITOR_SOURCE_COMMIT" ] \
    || die 'auditor checkout is not at the pinned commit'
[ -z "$(git -C "$AUDITOR_REPO" status --porcelain=v1 --untracked-files=all)" ] \
    || die 'auditor checkout is not clean at the pinned commit'
git -C "$AUDITOR_REPO" show "${AUDITOR_SOURCE_COMMIT}:noid-privacy-linux.sh" \
    | cmp -s - "$AUDITOR_SOURCE" \
    || die 'auditor working-tree bytes differ from the pinned commit object'

SOURCE_COMMIT=$(git -C "$REPO_ROOT" rev-parse --verify HEAD)
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || die 'source commit is invalid'
[ -z "$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ] \
    || die 'support media requires a clean committed source tree'

STAGE=$(mktemp -d /var/tmp/noid-audit-support-stage.XXXXXXXX)
EXTRACTED=$(mktemp -d /var/tmp/noid-audit-support-verify.XXXXXXXX)
BUNDLE_CHECKOUT=$(mktemp -d /var/tmp/noid-audit-support-bundle.XXXXXXXX)
AUDITOR_BUNDLE_CHECKOUT=$(mktemp -d /var/tmp/noid-audit-support-auditor-bundle.XXXXXXXX)
REPO_CHECK_ROOT=$(mktemp -d /var/tmp/noid-audit-support-repo-check.XXXXXXXX)
TEMP_ISO=$(mktemp --tmpdir="$OUTPUT_PARENT" .noid-audit-support.XXXXXXXX.iso)
MANIFEST_TEMP=$(mktemp /var/tmp/noid-audit-support-manifest.XXXXXXXX)
cleanup() {
    # xorriso restores ISO9660/Rock Ridge directory modes (typically 0555).
    # Re-open only our five mktemp trees before removing them; otherwise a
    # failed verification leaves an undeletable extracted tree behind.
    chmod -R u+w -- "$STAGE" "$EXTRACTED" "$BUNDLE_CHECKOUT" \
        "$AUDITOR_BUNDLE_CHECKOUT" "$REPO_CHECK_ROOT" 2>/dev/null || true
    rm -rf -- "$STAGE" "$EXTRACTED" "$BUNDLE_CHECKOUT" \
        "$AUDITOR_BUNDLE_CHECKOUT" "$REPO_CHECK_ROOT"
    rm -f -- "$MANIFEST_TEMP"
    [ ! -e "$TEMP_ISO" ] || rm -f -- "$TEMP_ISO"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$STAGE/noid-privacy-fedora" \
    "$STAGE/noid-privacy-linux" "$STAGE/fedora-rpms"
install -m 0644 "$FEDORA_KEY" \
    "$STAGE/RPM-GPG-KEY-fedora-${FEDORA_RELEASE}-x86_64"
git -C "$REPO_ROOT" archive --format=tar "$SOURCE_COMMIT" \
    | tar -x -C "$STAGE/noid-privacy-fedora"
printf '%s\n' "$SOURCE_COMMIT" > "$STAGE/noid-privacy-fedora/SOURCE-COMMIT"

# tests/00-status-metadata.sh intentionally binds every LOCKED marker to the
# file's real Git history. A git-archive tree alone cannot satisfy that gate,
# so the support medium carries a complete, exact-HEAD bundle next to the
# read-only reference export. The bundle is executable history, not merely a
# marker: validate its advertised ref now and clone/compare it after ISO
# extraction below.
git -C "$REPO_ROOT" bundle create \
    "$STAGE/noid-privacy-fedora.bundle" HEAD
chmod 0644 "$STAGE/noid-privacy-fedora.bundle"
git -C "$REPO_ROOT" bundle verify "$STAGE/noid-privacy-fedora.bundle" \
    >/dev/null
[ "$(git bundle list-heads "$STAGE/noid-privacy-fedora.bundle")" = \
    "$SOURCE_COMMIT HEAD" ] || die 'source bundle does not advertise exact HEAD'

# M40 verifies the auditor against its pinned Git object, so an exported script
# plus a text commit marker is not a complete offline test boundary. Carry a
# self-contained sibling bundle and prove its only advertised ref before the
# human-readable byte reference is staged beside it.
git -C "$AUDITOR_REPO" bundle create \
    "$STAGE/noid-privacy-linux.bundle" HEAD
chmod 0644 "$STAGE/noid-privacy-linux.bundle"
git -C "$AUDITOR_REPO" bundle verify \
    "$STAGE/noid-privacy-linux.bundle" >/dev/null
[ "$(git bundle list-heads "$STAGE/noid-privacy-linux.bundle")" = \
    "$AUDITOR_SOURCE_COMMIT HEAD" ] \
    || die 'auditor bundle does not advertise exact pinned HEAD'
install -m 0644 "$AUDITOR_SOURCE" \
    "$STAGE/noid-privacy-linux/noid-privacy-linux.sh"
printf '%s\n' "$AUDITOR_SOURCE_COMMIT" \
    > "$STAGE/noid-privacy-linux/SOURCE-COMMIT"

# Download the complete Fedora-signed dependency closure. --alldeps is
# load-bearing: the Live candidate may already have some dependencies, while
# the offline media must not silently depend on that ambient package set.
# Restrict the whole solver and metadata transaction, not only the named
# packages. DNF5 --from-repo limits package selection but still permits all
# enabled repositories for dependencies, which would contact unrelated vendor
# repos and make the support closure host-configuration-dependent.
# The hardened host keeps /etc/dnf/versionlock.toml root-readable. Use DNF as
# Root so the existing restriction is honored; do not disable the versionlock
# plugin merely to make an unprivileged download work. All later verification
# and output publication remain in the invoking user's private staging tree.
sudo -- dnf --repo=fedora,updates download --resolve --alldeps \
    --setopt=install_weak_deps=False \
    --arch=x86_64 --arch=noarch \
    --from-repo=fedora,updates \
    --destdir="$STAGE/fedora-rpms" ShellCheck pykickstart patch
mapfile -d '' -t rpms < <(find "$STAGE/fedora-rpms" -maxdepth 1 \
    -type f -name '*.rpm' -print0 | sort -z)
[ "${#rpms[@]}" -gt 0 ] || die 'DNF produced no offline dependency RPMs'

# DNF runs under the caller's restrictive umask but as Root so it can read the
# system version lock. Transfer only the closed, regular RPM list back to the
# invoking identity before unprivileged signature verification and ISO work.
build_uid=$(id -u)
build_gid=$(id -g)
sudo -- chown --no-dereference "$build_uid:$build_gid" -- "${rpms[@]}"
chmod 0600 -- "${rpms[@]}"
for rpm_file in "${rpms[@]}"; do
    [ -f "$rpm_file" ] && [ ! -L "$rpm_file" ] \
        && [ "$(stat -c '%u:%g:%a:%h' "$rpm_file")" = \
             "$build_uid:$build_gid:600:1" ] \
        || die "downloaded RPM ownership/type postcondition failed: $rpm_file"
done

# shellcheck disable=SC1090,SC1091 # absolute validated repository-owned library.
. "$SIGNATURE_LIB"
TMPDIR=/var/tmp noid_verify_rpms_with_isolated_key \
    "$FEDORA_KEY" "$FEDORA_KEY_FINGERPRINT" "${rpms[@]}"
createrepo_c --quiet --no-database --checksum sha256 \
    --revision "$SOURCE_COMMIT" "$STAGE/fedora-rpms"
[ -s "$STAGE/fedora-rpms/repodata/repomd.xml" ] \
    || die 'offline repository metadata was not generated'

cat > "$STAGE/README.txt" <<'README_EOF'
NOID AUDIT SUPPORT MEDIA V1

This medium contains the exact Fedora source snapshot, the exact committed
sibling auditor release in the required layout, and the Fedora-signed offline
dependency closure for ShellCheck, pykickstart, and GNU patch.

ISO9660 is read-only. Use the complete Git bundle for the writable test
checkout, and copy the reviewed sibling auditor beside it (replace /media with
the actual support-media mount point):

  commit=$(cat /media/noid-privacy-fedora/SOURCE-COMMIT)
  git clone /media/noid-privacy-fedora.bundle /writable/noid-privacy-fedora
  git -C /writable/noid-privacy-fedora checkout --detach "$commit"
  auditor_commit=$(cat /media/noid-privacy-linux/SOURCE-COMMIT)
  git clone /media/noid-privacy-linux.bundle /writable/noid-privacy-linux
  git -C /writable/noid-privacy-linux checkout --detach "$auditor_commit"

The exported noid-privacy-fedora directory is the byte reference for that
commit. Install the local RPM closure without enabling network repos:

  media=/media
  (cd "$media" && sha256sum -c MANIFEST.sha256)
  sudo dnf --repo=noid-audit-support \
    --repofrompath=noid-audit-support,"file://$media/fedora-rpms" \
    --setopt=noid-audit-support.pkg_gpgcheck=1 \
    --setopt=noid-audit-support.repo_gpgcheck=0 \
    --setopt=noid-audit-support.skip_if_unavailable=0 \
    --setopt=noid-audit-support.gpgkey="file://$media/RPM-GPG-KEY-fedora-44-x86_64" \
    --setopt=install_weak_deps=False \
    install ShellCheck pykickstart patch

First compare the support ISO SHA-256 with the retained build evidence.
The read-only ISO manifest then binds its repository metadata and copied
Fedora key. The metadata is not separately OpenPGP-signed; DNF verifies every
selected RPM against that fingerprint-checked Fedora 44 key.

Run the suite from the writable noid-privacy-fedora checkout. Module 40 uses
../noid-privacy-linux/noid-privacy-linux.sh automatically. Alternatively set
NOID_AUDIT_SRC to that exact file. Verify MANIFEST.sha256 before use.
README_EOF

(
    cd "$STAGE"
    find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
) > "$MANIFEST_TEMP"
install -m 0644 "$MANIFEST_TEMP" "$STAGE/MANIFEST.sha256"
xorriso -as mkisofs -quiet -r -J -V "$VOLUME_ID" -o "$TEMP_ISO" "$STAGE"

xorriso -osirrox on -indev "$TEMP_ISO" -extract / "$EXTRACTED" \
    >/dev/null 2>&1
actual_volume=$(LC_ALL=C xorriso -indev "$TEMP_ISO" -pvd_info 2>/dev/null \
    | sed -n 's/^Volume Id[[:space:]]*:[[:space:]]*//p')
[ "$actual_volume" = "$VOLUME_ID" ] || die 'support ISO volume identity drifted'
(cd "$EXTRACTED" && sha256sum -c MANIFEST.sha256 >/dev/null)
[ "$(cat "$EXTRACTED/noid-privacy-fedora/SOURCE-COMMIT")" = "$SOURCE_COMMIT" ] \
    || die 'extracted source commit evidence drifted'
[ "$(sha256sum "$EXTRACTED/noid-privacy-linux/noid-privacy-linux.sh" | awk '{print $1}')" \
    = "$AUDITOR_SOURCE_SHA256" ] || die 'extracted auditor source drifted'
[ "$(stat -c %s "$EXTRACTED/noid-privacy-linux/noid-privacy-linux.sh")" \
    = "$AUDITOR_SOURCE_SIZE" ] || die 'extracted auditor source size drifted'
[ "$(cat "$EXTRACTED/noid-privacy-linux/SOURCE-COMMIT")" \
    = "$AUDITOR_SOURCE_COMMIT" ] || die 'extracted auditor commit evidence drifted'
auditor_bundle="$EXTRACTED/noid-privacy-linux.bundle"
[ -f "$auditor_bundle" ] && [ ! -L "$auditor_bundle" ] \
    || die 'extracted auditor bundle is missing or symlinked'
git -C "$AUDITOR_REPO" bundle verify "$auditor_bundle" >/dev/null
[ "$(git bundle list-heads "$auditor_bundle")" = \
    "$AUDITOR_SOURCE_COMMIT HEAD" ] \
    || die 'extracted auditor bundle ref drifted'
git clone --no-hardlinks --quiet "$auditor_bundle" \
    "$AUDITOR_BUNDLE_CHECKOUT/repo"
[ "$(git -C "$AUDITOR_BUNDLE_CHECKOUT/repo" rev-parse --verify HEAD)" = \
    "$AUDITOR_SOURCE_COMMIT" ] || die 'auditor bundle checkout HEAD drifted'
[ -z "$(git -C "$AUDITOR_BUNDLE_CHECKOUT/repo" status \
    --porcelain=v1 --untracked-files=all)" ] \
    || die 'auditor bundle checkout is not clean'
cmp -s "$AUDITOR_BUNDLE_CHECKOUT/repo/noid-privacy-linux.sh" \
    "$EXTRACTED/noid-privacy-linux/noid-privacy-linux.sh" \
    || die 'auditor bundle source and exported byte reference differ'
cmp -s "$FEDORA_KEY" \
    "$EXTRACTED/RPM-GPG-KEY-fedora-${FEDORA_RELEASE}-x86_64" \
    || die 'extracted Fedora repository key drifted'
repomd="$EXTRACTED/fedora-rpms/repodata/repomd.xml"
[ -s "$repomd" ] || die 'extracted offline repository metadata is missing'
repomd_revision=$(sed -n \
    's:.*<revision>\([^<]*\)</revision>.*:\1:p' "$repomd")
[ "$repomd_revision" = "$SOURCE_COMMIT" ] \
    || die 'extracted offline repository revision drifted'

# Parse the extracted read-only repository through DNF5 itself. Querying only
# the media repo inside a private empty installroot proves repodata readability,
# exact package coverage and absence of an ambient/network repository fallback.
mapfile -t repo_locations < <(
    LC_ALL=C.UTF-8 dnf --quiet --no-plugins \
        --installroot="$REPO_CHECK_ROOT" --releasever="$FEDORA_RELEASE" \
        --setopt=reposdir=/dev/null \
        --repofrompath=noid-audit-support,"file://$EXTRACTED/fedora-rpms" \
        --setopt=noid-audit-support.pkg_gpgcheck=1 \
        --setopt=noid-audit-support.repo_gpgcheck=0 \
        --setopt=noid-audit-support.skip_if_unavailable=0 \
        --repo=noid-audit-support \
        repoquery --available '*' --location
)
[ "${#repo_locations[@]}" -eq "${#rpms[@]}" ] \
    || die 'extracted offline repository package count drifted'
declare -A repo_location_seen=()
for repo_location in "${repo_locations[@]}"; do
    case "$repo_location" in
        "file://$EXTRACTED/fedora-rpms/"*.rpm) ;;
        *) die "offline repository published an unexpected location: $repo_location" ;;
    esac
    rpm_path=${repo_location#file://}
    [ -f "$rpm_path" ] && [ ! -L "$rpm_path" ] \
        || die "offline repository location is unsafe: $repo_location"
    [ -z "${repo_location_seen[$rpm_path]+present}" ] \
        || die "offline repository duplicated a package location: $repo_location"
    repo_location_seen["$rpm_path"]=1
done
mapfile -d '' -t extracted_rpms < <(find "$EXTRACTED/fedora-rpms" -maxdepth 1 \
    -type f -name '*.rpm' -print0 | sort -z)
[ "${#extracted_rpms[@]}" -eq "${#rpms[@]}" ] \
    || die 'extracted offline RPM count drifted'
for rpm_path in "${extracted_rpms[@]}"; do
    [ -n "${repo_location_seen[$rpm_path]+present}" ] \
        || die "offline repository omitted an extracted RPM: $rpm_path"
done

# Prove the ISO-carried bundle is self-contained, checks out the exact source
# commit with a clean index, and reproduces every tracked byte plus Git's
# executable-bit contract in the read-only archive tree. Only SOURCE-COMMIT is
# permitted as an extra file in that reference export.
git -C "$REPO_ROOT" bundle verify \
    "$EXTRACTED/noid-privacy-fedora.bundle" >/dev/null
[ "$(git bundle list-heads "$EXTRACTED/noid-privacy-fedora.bundle")" = \
    "$SOURCE_COMMIT HEAD" ] || die 'extracted source bundle ref drifted'
git clone --no-hardlinks --quiet "$EXTRACTED/noid-privacy-fedora.bundle" \
    "$BUNDLE_CHECKOUT/repo"
[ "$(git -C "$BUNDLE_CHECKOUT/repo" rev-parse --verify HEAD)" = \
    "$SOURCE_COMMIT" ] || die 'bundle checkout HEAD drifted'
[ -z "$(git -C "$BUNDLE_CHECKOUT/repo" status \
    --porcelain=v1 --untracked-files=all)" ] \
    || die 'bundle checkout is not clean'

tracked_count=0
while IFS= read -r -d '' index_record; do
    index_meta=${index_record%%$'\t'*}
    relative_path=${index_record#*$'\t'}
    read -r index_mode _object_id index_stage <<< "$index_meta"
    [ "$index_stage" = 0 ] || die "non-stage-zero bundle entry: $relative_path"
    checkout_path="$BUNDLE_CHECKOUT/repo/$relative_path"
    exported_path="$EXTRACTED/noid-privacy-fedora/$relative_path"
    case "$index_mode" in
        100644)
            [ -f "$exported_path" ] && [ ! -L "$exported_path" ] \
                && [ ! -x "$exported_path" ] \
                || die "exported non-executable file contract drifted: $relative_path"
            cmp -s "$checkout_path" "$exported_path" \
                || die "exported file bytes drifted: $relative_path"
            ;;
        100755)
            [ -f "$exported_path" ] && [ ! -L "$exported_path" ] \
                && [ -x "$exported_path" ] \
                || die "exported executable file contract drifted: $relative_path"
            cmp -s "$checkout_path" "$exported_path" \
                || die "exported file bytes drifted: $relative_path"
            ;;
        120000)
            [ -L "$exported_path" ] \
                && [ "$(readlink "$checkout_path")" = "$(readlink "$exported_path")" ] \
                || die "exported symlink contract drifted: $relative_path"
            ;;
        *) die "unsupported Git mode in source bundle: $index_mode" ;;
    esac
    tracked_count=$((tracked_count + 1))
done < <(git -C "$BUNDLE_CHECKOUT/repo" ls-files --stage -z)
exported_count=$(find "$EXTRACTED/noid-privacy-fedora" -mindepth 1 \
    \( -type f -o -type l \) -printf x | wc -c)
[ "$exported_count" -eq "$((tracked_count + 1))" ] \
    || die 'exported source contains an entry outside Git plus SOURCE-COMMIT'

chmod 0600 "$TEMP_ISO"
sync -- "$TEMP_ISO"
ln -- "$TEMP_ISO" "$OUTPUT" || die 'write-once output publication collided'
rm -f -- "$TEMP_ISO"
sync -- "$OUTPUT"
sync -- "$OUTPUT_PARENT"
printf 'Audit support ISO: %s\n' "$OUTPUT"
printf 'Source commit: %s\n' "$SOURCE_COMMIT"
sha256sum "$OUTPUT"
