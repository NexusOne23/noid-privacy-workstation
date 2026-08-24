#!/usr/bin/env bash
# Stage the one supported reduced-dependency cache artifact.
#
# Historical filename only: this does not prepare an offline ISO build. The
# canonical builder still needs its configured repositories and other reviewed
# network sources. This helper fetches only the pinned uBlock Origin XPI used by
# Module 16, validates its repository-owned size/SHA-256 pins, and publishes an
# exact manifest last.
set -euo pipefail
umask 022
export LC_ALL=C.UTF-8
export PATH=/usr/sbin:/usr/bin

readonly UBO_VERSION="1.73.0"
readonly UBO_SHA256="bccc51a773150af4af6e1fd62c7bfdeb7238b79ff2381b998fa9f2e38f64786a"
readonly UBO_SIZE="4679419"
readonly UBO_FILENAME="uBlock0_${UBO_VERSION}.firefox.signed.xpi"
readonly UBO_RELATIVE_PATH="ubo/${UBO_VERSION}/${UBO_FILENAME}"
readonly UBO_URL="https://github.com/gorhill/uBlock/releases/download/${UBO_VERSION}/${UBO_FILENAME}"
readonly MANIFEST_HEADER="NOID_REDUCED_DEPENDENCY_CACHE_V1"

CACHE_DIR="${CACHE_DIR:-/var/cache/noid-build}"
TMP_DOWNLOAD=""
TMP_HEADERS=""
TMP_MANIFEST=""

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'USAGE_EOF'
Usage: CACHE_DIR=/absolute/cache/path scripts/offline-prep.sh

Prepare the pinned uBlock Origin payload used by the reduced-dependency build
wrapper. No arguments are accepted. This is not an offline/air-gapped builder.
USAGE_EOF
}
cleanup() {
    [ -z "$TMP_DOWNLOAD" ] || rm -f -- "$TMP_DOWNLOAD"
    [ -z "$TMP_HEADERS" ] || rm -f -- "$TMP_HEADERS"
    [ -z "$TMP_MANIFEST" ] || rm -f -- "$TMP_MANIFEST"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

case "$#" in
    0) ;;
    1) case "$1" in -h|--help) usage; exit 0 ;; *) usage >&2; exit 2 ;; esac ;;
    *) usage >&2; exit 2 ;;
esac

case "$CACHE_DIR" in
    /*) ;;
    *) die "CACHE_DIR must be an absolute path" ;;
esac
case "$CACHE_DIR" in
    *$'\n'*|*$'\r'*) die "CACHE_DIR must not contain line breaks" ;;
esac
[ "$CACHE_DIR" != / ] || die "CACHE_DIR must not be /"

expected_manifest() {
    printf '%s\n' \
        "$MANIFEST_HEADER" \
        "artifact=${UBO_RELATIVE_PATH}" \
        "source=${UBO_URL}" \
        "size=${UBO_SIZE}" \
        "sha256=${UBO_SHA256}"
}

verify_payload() {
    local file="$1" actual_size actual_sha
    [ -f "$file" ] && [ ! -L "$file" ] || die "payload is missing, non-regular or symlinked: $file"
    actual_size=$(stat -c '%s' -- "$file")
    [ "$actual_size" = "$UBO_SIZE" ] || die "uBO size mismatch: expected ${UBO_SIZE}, got ${actual_size}"
    actual_sha=$(sha256sum -- "$file")
    actual_sha=${actual_sha%% *}
    [ "$actual_sha" = "$UBO_SHA256" ] || die "uBO SHA-256 mismatch: expected ${UBO_SHA256}, got ${actual_sha}"
}

url_host() {
    local url="$1"
    if [[ "$url" =~ ^https://([^/:?#]+)(/[^#]*)?$ ]]; then
        printf '%s\n' "${BASH_REMATCH[1],,}"
    else
        return 1
    fi
}

fetch_pinned_github_asset() {
    local destination="$1" current="$UBO_URL" host status location
    local -a locations=()
    local hop

    TMP_HEADERS=$(mktemp --tmpdir="$(dirname "$destination")" .noid-fetch-headers.XXXXXXXX)
    TMP_DOWNLOAD=$(mktemp --tmpdir="$(dirname "$destination")" .noid-ubo.XXXXXXXX)

    for hop in 0 1 2 3; do
        host=$(url_host "$current") || die "refusing malformed or non-HTTPS fetch URL"
        if [ "$hop" -eq 0 ]; then
            [ "$current" = "$UBO_URL" ] && [ "$host" = github.com ] \
                || die "initial uBO origin differs from the reviewed URL"
        else
            case "$host" in
                release-assets.githubusercontent.com) ;;
                *) die "refusing redirect to unreviewed host: $host" ;;
            esac
        fi

        : > "$TMP_HEADERS"
        : > "$TMP_DOWNLOAD"
        status=$(curl --silent --show-error \
            --proto '=https' --request GET --max-redirs 0 \
            --connect-timeout 30 --max-time 300 --retry 3 --retry-delay 2 \
            --dump-header "$TMP_HEADERS" --output "$TMP_DOWNLOAD" \
            --write-out '%{http_code}' -- "$current") \
            || die "uBO fetch failed at reviewed host: $host"

        case "$status" in
            200)
                verify_payload "$TMP_DOWNLOAD"
                chmod 0644 "$TMP_DOWNLOAD"
                sync -- "$TMP_DOWNLOAD"
                if ! ln -- "$TMP_DOWNLOAD" "$destination" 2>/dev/null; then
                    [ -e "$destination" ] || die "could not publish cached uBO payload"
                    verify_payload "$destination"
                fi
                rm -f -- "$TMP_DOWNLOAD"
                TMP_DOWNLOAD=""
                return 0
                ;;
            301|302|303|307|308)
                mapfile -t locations < <(
                    awk 'BEGIN { IGNORECASE=1 }
                         /^Location:[[:space:]]*/ {
                             sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); print
                         }' "$TMP_HEADERS"
                )
                [ "${#locations[@]}" -eq 1 ] || die "redirect response must contain exactly one Location header"
                location=${locations[0]}
                host=$(url_host "$location") || die "refusing malformed or non-HTTPS redirect"
                [ "$host" = release-assets.githubusercontent.com ] \
                    || die "refusing redirect to unreviewed host: $host"
                current=$location
                ;;
            *) die "unexpected HTTP status ${status} from reviewed host ${host}" ;;
        esac
    done
    die "uBO fetch exceeded the reviewed redirect limit"
}

# Reject non-canonical parents before creating anything. In particular, never
# let root-run preparation follow a pre-existing symlink and create a cache
# leaf at the link target before the later canonical-path check can reject it.
if [ -e "$CACHE_DIR" ] || [ -L "$CACHE_DIR" ]; then
    [ -d "$CACHE_DIR" ] && [ ! -L "$CACHE_DIR" ] \
        || die "CACHE_DIR must be a real directory"
else
    cache_parent=${CACHE_DIR%/*}
    cache_name=${CACHE_DIR##*/}
    [ -n "$cache_parent" ] || cache_parent=/
    [ -n "$cache_name" ] || die "CACHE_DIR must not end with a slash"
    [ -d "$cache_parent" ] && [ ! -L "$cache_parent" ] \
        || die "CACHE_DIR parent must be an existing non-symlink directory"
    canonical_parent=$(realpath -e -- "$cache_parent")
    [ "$canonical_parent" = "$cache_parent" ] \
        || die "CACHE_DIR parent must be canonical and contain no symlink components"
    mkdir -- "$CACHE_DIR"
fi
canonical_cache=$(realpath -e -- "$CACHE_DIR")
[ "$canonical_cache" = "$CACHE_DIR" ] || die "CACHE_DIR must be canonical and contain no symlink components"

ensure_cache_directory() {
    local directory="$1"
    if [ -e "$directory" ] || [ -L "$directory" ]; then
        [ -d "$directory" ] && [ ! -L "$directory" ] \
            || die "cache component must be a real directory: $directory"
    else
        # Create one leaf at a time. Unlike mkdir -p, mkdir cannot traverse a
        # pre-existing symlink in the leaf position before we reject it.
        mkdir -- "$directory"
    fi
    [ "$(realpath -e -- "$directory")" = "$directory" ] \
        || die "cache component contains or traverses a symlink: $directory"
}

UBO_ROOT="$CACHE_DIR/ubo"
UBO_DIR="$UBO_ROOT/$UBO_VERSION"
ensure_cache_directory "$UBO_ROOT"
ensure_cache_directory "$UBO_DIR"
PAYLOAD="$CACHE_DIR/$UBO_RELATIVE_PATH"
MANIFEST="$CACHE_DIR/MANIFEST.txt"

# Old mirror experiments and arbitrary extra files are not part of the
# supported cache contract. Reject them before adding or refreshing evidence.
while IFS= read -r -d '' entry; do
    relative=${entry#"$CACHE_DIR"/}
    case "$relative" in
        ubo|"ubo/$UBO_VERSION"|"$UBO_RELATIVE_PATH"|MANIFEST.txt) ;;
        *) die "unsupported extra cache entry: $relative" ;;
    esac
done < <(find "$CACHE_DIR" -mindepth 1 -print0)

if [ -e "$PAYLOAD" ] || [ -L "$PAYLOAD" ]; then
    verify_payload "$PAYLOAD"
    log "Pinned uBO payload already present and valid"
else
    log "Fetching pinned uBO ${UBO_VERSION} from constrained GitHub origins"
    fetch_pinned_github_asset "$PAYLOAD"
    verify_payload "$PAYLOAD"
fi

TMP_MANIFEST=$(mktemp --tmpdir="$CACHE_DIR" .MANIFEST.txt.XXXXXXXX)
expected_manifest > "$TMP_MANIFEST"
chmod 0644 "$TMP_MANIFEST"
sync -- "$TMP_MANIFEST"
if [ -e "$MANIFEST" ] || [ -L "$MANIFEST" ]; then
    [ -f "$MANIFEST" ] && [ ! -L "$MANIFEST" ] || die "existing manifest is non-regular or symlinked"
fi
mv -fT -- "$TMP_MANIFEST" "$MANIFEST"
TMP_MANIFEST=""
sync -- "$CACHE_DIR"

log "Reduced-dependency cache published: $CACHE_DIR"
log "Run: CACHE_DIR=$CACHE_DIR ./scripts/build-offline.sh"
