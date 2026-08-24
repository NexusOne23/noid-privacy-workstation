#!/usr/bin/env bash
# Verify repository -> image license inventory -> installed browser-source
# notice parity. Run in the source checkout against / or a mounted root.
set -euo pipefail
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin

TEST_NAME=18-browser-license-notices
fail() { echo "FAIL  $TEST_NAME: $*" >&2; exit 1; }

[ "$#" -le 1 ] || {
    echo "FAIL  $TEST_NAME: usage: $0 [INSTALLED_ROOT]" >&2
    exit 2
}
for required_command in awk cmp dirname mktemp readlink rm sha256sum stat; do
    command -v "$required_command" >/dev/null 2>&1 || \
        fail "required command missing: $required_command"
done
SCRIPT_PATH=$(readlink -e -- "$0") || fail "cannot canonicalize script path"
REPO_ROOT=$(cd "$(dirname -- "$SCRIPT_PATH")/../.." && pwd -P) || \
    fail "cannot resolve repository root"
INSTALLED_ROOT=${1:-/}
[ -d "$INSTALLED_ROOT" ] && [ ! -L "$INSTALLED_ROOT" ] || {
    echo "FAIL  $TEST_NAME: installed root is invalid: $INSTALLED_ROOT" >&2
    exit 2
}
INSTALLED_ROOT=$(readlink -e -- "$INSTALLED_ROOT") || \
    fail "cannot canonicalize installed root"

ARKENFOX_REPO="$REPO_ROOT/licenses/arkenfox-user.js-MIT.txt"
HORLOGE_REPO="$REPO_ROOT/licenses/horlogeskynet-thunderbird-user.js-MIT.txt"
root_path() {
    local suffix=$1
    if [ "$INSTALLED_ROOT" = / ]; then
        printf '/%s\n' "$suffix"
    else
        printf '%s/%s\n' "$INSTALLED_ROOT" "$suffix"
    fi
}
ARKENFOX_INSTALLED=$(root_path usr/share/licenses/noid-privacy/arkenfox-user.js-MIT.txt)
HORLOGE_INSTALLED=$(root_path usr/share/licenses/noid-privacy/horlogeskynet-thunderbird-user.js-MIT.txt)
FIREFOX_SOURCE=$(root_path usr/share/noid-firefox/user.js)
THUNDERBIRD_SOURCE=$(root_path usr/share/noid-thunderbird/user.js)

for regular in "$ARKENFOX_REPO" "$HORLOGE_REPO"; do
    [ -f "$regular" ] && [ ! -L "$regular" ] || {
        fail "repository notice is missing, non-regular or symlinked: $regular"
    }
done
for regular in "$ARKENFOX_INSTALLED" "$HORLOGE_INSTALLED" \
        "$FIREFOX_SOURCE" "$THUNDERBIRD_SOURCE"; do
    [ -f "$regular" ] && [ ! -L "$regular" ] || \
        fail "installed source/notice is missing, non-regular or symlinked: $regular"
    canonical=$(readlink -e -- "$regular") || \
        fail "cannot canonicalize installed source/notice: $regular"
    if [ "$INSTALLED_ROOT" != / ]; then
        case "$canonical" in
            "$INSTALLED_ROOT"/*) ;;
            *) fail "installed source/notice escapes candidate root: $regular" ;;
        esac
    fi
    [ "$(stat -c '%u:%g:%a:%h' "$regular")" = 0:0:644:1 ] || \
        fail "installed source/notice metadata differs: $regular"
done

verify_notice_hash() {
    local notice=$1 expected=$2 label=$3 actual
    actual=$(sha256sum -- "$notice") || fail "cannot hash $label notice"
    actual=${actual%% *}
    [ "$actual" = "$expected" ] || \
        fail "$label repository notice hash differs"
}
verify_notice_hash "$ARKENFOX_REPO" \
    2bf289bdd22188ccff2bf34c9a20a75c45b84f42f887da7e177d9bfd1bac3c1a \
    arkenfox
verify_notice_hash "$HORLOGE_REPO" \
    e0bfbe5467925aa73c30bb5d7e9e23fef1a2f6285b0c5dd62a5c7ab091fc5331 \
    HorlogeSkynet
cmp -s -- "$ARKENFOX_REPO" "$ARKENFOX_INSTALLED" || \
    fail "installed arkenfox notice differs from repository"
cmp -s -- "$HORLOGE_REPO" "$HORLOGE_INSTALLED" || \
    fail "installed HorlogeSkynet notice differs from repository"

extract_notice() {
    local source=$1 begin=$2 end=$3 output=$4
    awk -v begin="$begin" -v end="$end" '
        $0 == begin {
            found_begin++
            if (state != 0) invalid=1
            state=1
            next
        }
        $0 == end {
            found_end++
            if (state != 1) invalid=1
            state=2
            next
        }
        state == 1 { print }
        END {
            exit !(state == 2 && found_begin == 1 &&
                   found_end == 1 && !invalid)
        }
    ' "$source" > "$output"
}

test_tmp=$(mktemp -d /var/tmp/noid-browser-license.XXXXXXXX)
trap 'rm -rf -- "$test_tmp"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
extract_notice "$FIREFOX_SOURCE" '/* ARKENFOX MIT NOTICE BEGIN' \
    'ARKENFOX MIT NOTICE END */' "$test_tmp/arkenfox.txt" || \
    fail "Firefox source notice markers are missing, duplicated or out of order"
extract_notice "$THUNDERBIRD_SOURCE" '/* HORLOGESKYNET MIT NOTICE BEGIN' \
    'HORLOGESKYNET MIT NOTICE END */' "$test_tmp/horloge.txt" || \
    fail "Thunderbird source notice markers are missing, duplicated or out of order"
cmp -s -- "$test_tmp/arkenfox.txt" "$ARKENFOX_INSTALLED" || \
    fail "installed Firefox source and license notice differ"
cmp -s -- "$test_tmp/horloge.txt" "$HORLOGE_INSTALLED" || \
    fail "installed Thunderbird source and license notice differ"

echo "PASS  $TEST_NAME: repo=image=installed-browser-source notices"
