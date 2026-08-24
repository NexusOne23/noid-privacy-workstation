#!/usr/bin/env bash
# Historical filename: authenticated reduced-dependency cache wrapper.
# This is not an offline or air-gapped ISO builder. It removes one build-time
# network fetch; every other canonical build dependency remains unchanged.
set -euo pipefail
export LC_ALL=C.UTF-8
export PATH=/usr/sbin:/usr/bin

readonly UBO_VERSION="1.73.0"
readonly UBO_SHA256="bccc51a773150af4af6e1fd62c7bfdeb7238b79ff2381b998fa9f2e38f64786a"
readonly UBO_SIZE="4679419"
readonly UBO_FILENAME="uBlock0_${UBO_VERSION}.firefox.signed.xpi"
readonly UBO_RELATIVE_PATH="ubo/${UBO_VERSION}/${UBO_FILENAME}"
readonly UBO_URL="https://github.com/gorhill/uBlock/releases/download/${UBO_VERSION}/${UBO_FILENAME}"
readonly MANIFEST_HEADER="NOID_REDUCED_DEPENDENCY_CACHE_V1"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CACHE_DIR="${CACHE_DIR:-/var/cache/noid-build}"

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'USAGE_EOF'
Usage: CACHE_DIR=/absolute/cache/path scripts/build-offline.sh [BUILD OPTION]

Authenticated reduced-dependency wrapper (historical filename). The only
accepted build options are --no-virt and --with-assets; the latter is the
canonical builder's deprecated compatibility alias. This workflow still needs
network access and must not be described as offline or air-gapped.
USAGE_EOF
}

for argument in "$@"; do
    case "$argument" in
        -h|--help) usage; exit 0 ;;
    esac
done
for argument in "$@"; do
    case "$argument" in
        --no-virt|--with-assets) ;;
        *) printf 'ERROR: unknown option: %s\n' "$argument" >&2; exit 2 ;;
    esac
done

case "$CACHE_DIR" in
    /*) ;;
    *) die "CACHE_DIR must be an absolute path" ;;
esac
case "$CACHE_DIR" in
    *$'\n'*|*$'\r'*) die "CACHE_DIR must not contain line breaks" ;;
esac
[ "$CACHE_DIR" != / ] || die "CACHE_DIR must not be /"
[ -d "$CACHE_DIR" ] && [ ! -L "$CACHE_DIR" ] || die "cache directory is missing or symlinked: $CACHE_DIR"
[ "$(realpath -e -- "$CACHE_DIR")" = "$CACHE_DIR" ] || die "CACHE_DIR must be canonical and contain no symlink components"

PAYLOAD="$CACHE_DIR/$UBO_RELATIVE_PATH"
MANIFEST="$CACHE_DIR/MANIFEST.txt"
[ -f "$PAYLOAD" ] && [ ! -L "$PAYLOAD" ] || die "required cached uBO payload is missing or symlinked"
[ -f "$MANIFEST" ] && [ ! -L "$MANIFEST" ] || die "cache manifest is missing or symlinked"

# The repository pins are the trust root. A cache author cannot authorize
# arbitrary bytes merely by recomputing MANIFEST.txt.
TMP_EXPECTED=$(mktemp)
trap 'rm -f -- "$TMP_EXPECTED"' EXIT
printf '%s\n' \
    "$MANIFEST_HEADER" \
    "artifact=${UBO_RELATIVE_PATH}" \
    "source=${UBO_URL}" \
    "size=${UBO_SIZE}" \
    "sha256=${UBO_SHA256}" > "$TMP_EXPECTED"
cmp -s -- "$TMP_EXPECTED" "$MANIFEST" || die "manifest does not exactly match the repository-reviewed cache contract"

actual_size=$(stat -c '%s' -- "$PAYLOAD")
[ "$actual_size" = "$UBO_SIZE" ] || die "cached uBO size mismatch"
actual_sha=$(sha256sum -- "$PAYLOAD")
actual_sha=${actual_sha%% *}
[ "$actual_sha" = "$UBO_SHA256" ] || die "cached uBO SHA-256 mismatch"

actual_tree=$(mktemp)
trap 'rm -f -- "$TMP_EXPECTED" "$actual_tree"' EXIT
find "$CACHE_DIR" -mindepth 1 -printf '%y %P\n' | LC_ALL=C sort > "$actual_tree"
cat > "$TMP_EXPECTED" <<TREE_EOF
d ubo
d ubo/${UBO_VERSION}
f MANIFEST.txt
f ${UBO_RELATIVE_PATH}
TREE_EOF
LC_ALL=C sort -o "$TMP_EXPECTED" "$TMP_EXPECTED"
cmp -s -- "$TMP_EXPECTED" "$actual_tree" || die "cache tree contains missing, extra or non-regular entries"

log "Authenticated reduced-dependency cache verified (one pinned uBO XPI)"
log "This remains a networked canonical build; no air-gap claim is made."

cd "$REPO_ROOT"
if git rev-parse --verify HEAD >/dev/null 2>&1; then
    SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct HEAD)
else
    SOURCE_DATE_EPOCH=$(date +%s)
    log "WARNING: no Git commit epoch available; cross-run timestamp variance remains"
fi
export SOURCE_DATE_EPOCH
export NOID_BUILD_CACHE_DIR="$CACHE_DIR"

log "Invoking canonical builder: scripts/build-iso.sh $*"
"${REPO_ROOT}/scripts/build-iso.sh" "$@"
