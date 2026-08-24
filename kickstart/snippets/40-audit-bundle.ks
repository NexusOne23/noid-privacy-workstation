# ============================================================================
# Module 40 — noid-audit Bundle Integration
# Status: LOCKED 2026-08-22 (v46) — pin the final reviewed v3.7.2 release.
#
# Bundles `noid-privacy-linux.sh` (NoID Privacy for Linux, GPLv3,
# https://github.com/NexusOne23/noid-privacy-linux) as the offline-capable
# Hardening Posture audit tool. Pinned version + SHA live in the %post pin
# block below. Adds:
#   /usr/local/bin/noid-privacy-linux.sh    — the audit script (SHA256-pinned)
#   /usr/local/bin/noid-audit               — wrapper (sudo + flags)
#   /etc/noid/audit-version                 — bundled version marker
#   + health stamp (extensions: audit_version, audit_commit, audit_size,
#     audit_sha256, version_marker_sha256, wrapper_sha256)
#
# User invokes: `noid-audit` → runs supplemental local posture inventory. It is
# not a release gate; UNKNOWN/NOT_TESTED remain incomplete evidence.
#
# Why bundle (vs curl-on-demand): offline-first (air-gapped install, pre-VPN
# diagnosis) + deterministic audit-payload selection (exact version/hash) + defense-
# in-depth (SHA256-verified at build-time AND post-install).
#
# Update philosophy: the bundled version is frozen at build time to a specific
# reviewed source commit, byte count and SHA-256. The wrapper deliberately has
# no network self-update: the reviewed source line exposes no project-signed
# checksum/manifest that could authenticate a newly downloaded root-executed
# script independently of GitHub TLS. A later ISO/source release must review
# and repin the complete identity tuple.
#
# Delivery: same HTTP staging as M32 branding (build-iso.sh stages, inner VM
# fetches from the build-host HTTP endpoint). SHA256-pinned both at build
# (build-iso.sh) and at install (this %post). Layered defense.
#
# Constraint notes (keep on future edits):
#   - PIN-SYNC INVARIANT (load-bearing): the version/commit/size/SHA tuple
#     here must match stage_noid_audit()'s version/source_commit/
#     expected_size/expected_sha in build-iso.sh. The commit/size/SHA subset
#     must also match AUDITOR_SOURCE_* in build-audit-support-media.sh.
#     tests/40 derives and compares every carrier dynamically; move all
#     carriers together in the same commit. A one-sided bump fails the suite
#     or aborts the image build at the STEP-1 identity gates.
#   - VERSION_EOF heredoc is UNQUOTED on purpose ($NOID_AUDIT_VERSION
#     substitution); backticks inside it must stay backslash-escaped or
#     build-time command substitution empties the comment lines (the
#     post-write grep is the anti-regression check).
#   - The wrapper reports both the image-owned bundle version and the
#     underlying auditor's own version. Commit, byte count and digest bind the
#     bundle to the reviewed public source revision without modifying bytes.
# ============================================================================

%post --erroronfail --log=/var/log/ks-40-audit-bundle.log
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

log() { echo "[$(date +%H:%M:%S)] $*"; }
fail() {
    log "[FAIL] $*"
    exit 1
}

ROOT_PUBLICATION_TMP=""

# Root-owned payloads are validated before publication, staged beside their
# destinations and renamed atomically. Every parent is canonical, root:root and
# non-writable by group/other before a target is touched.
ensure_root_dir() {
    local path=$1 mode=${2:-0755} current="" component metadata current_mode
    case "$path" in
        /*) ;;
        *) fail "directory path is not absolute: $path" ;;
    esac
    while IFS= read -r component; do
        [ -n "$component" ] || continue
        current="$current/$component"
        [ ! -L "$current" ] || fail "symlinked directory component: $current"
        if [ -e "$current" ]; then
            [ -d "$current" ] || fail "non-directory path component: $current"
        else
            install -d -m 0755 -o root -g root -- "$current" \
                || fail "cannot create directory: $current"
        fi
        [ "$(readlink -e -- "$current" 2>/dev/null)" = "$current" ] \
            || fail "non-canonical directory component: $current"
        metadata=$(stat -Lc '%u:%g:%a' -- "$current" 2>/dev/null) \
            || fail "cannot inspect directory: $current"
        case "$metadata" in
            0:0:*) current_mode=${metadata##*:} ;;
            *) fail "directory is not root:root: $current ($metadata)" ;;
        esac
        [[ "$current_mode" =~ ^[0-7]{3,4}$ ]] \
            || fail "directory mode is invalid: $current ($current_mode)"
        (( (8#$current_mode & 0022) == 0 )) \
            || fail "directory is group/other-writable: $current ($current_mode)"
    done < <(printf '%s\n' "${path#/}" | tr '/' '\n')
    chmod "$mode" -- "$path" || fail "cannot set directory mode: $path"
    chown root:root -- "$path" || fail "cannot set directory owner: $path"
    [ "$(stat -Lc '%u:%g:%a' -- "$path" 2>/dev/null)" = \
        "0:0:${mode#0}" ] || fail "directory postcondition failed: $path"
    restorecon -F -- "$path" || fail "cannot label directory: $path"
    matchpathcon -V "$path" >/dev/null \
        || fail "directory label differs from policy: $path"
    sync -- "$path" || fail "cannot sync directory: $path"
}

publish_root_file() {
    local source=$1 destination=$2 requested_mode=$3
    local parent temporary mode=${requested_mode#0} source_state parent_state
    local source_mode parent_mode
    parent=${destination%/*}
    [ -f "$source" ] && [ ! -L "$source" ] \
        || fail "publication source is missing, non-regular or symlinked: $source"
    [ "$(readlink -e -- "$source" 2>/dev/null)" = "$source" ] \
        || fail "publication source is non-canonical: $source"
    source_state=$(stat -Lc '%u:%g:%a:%h' -- "$source" 2>/dev/null) \
        || fail "cannot inspect publication source: $source"
    case "$source_state" in
        0:0:*:1)
            source_mode=${source_state#0:0:}
            source_mode=${source_mode%:1}
            ;;
        *) fail "publication source metadata is unsafe: $source ($source_state)" ;;
    esac
    [[ "$source_mode" =~ ^[0-7]{3,4}$ ]] \
        || fail "publication source mode is invalid: $source ($source_mode)"
    (( (8#$source_mode & 0022) == 0 )) \
        || fail "publication source is group/other-writable: $source ($source_mode)"
    [ -d "$parent" ] && [ ! -L "$parent" ] \
        || fail "publication parent is unsafe: $parent"
    [ "$(readlink -e -- "$parent" 2>/dev/null)" = "$parent" ] \
        || fail "publication parent is non-canonical: $parent"
    parent_state=$(stat -Lc '%u:%g:%a' -- "$parent" 2>/dev/null) \
        || fail "cannot inspect publication parent: $parent"
    case "$parent_state" in
        0:0:*) parent_mode=${parent_state##*:} ;;
        *) fail "publication parent is not root:root: $parent ($parent_state)" ;;
    esac
    [[ "$parent_mode" =~ ^[0-7]{3,4}$ ]] \
        || fail "publication parent mode is invalid: $parent ($parent_mode)"
    (( (8#$parent_mode & 0022) == 0 )) \
        || fail "publication parent is writable by group/other: $parent ($parent_mode)"
    [ ! -e "$destination" ] || [ -f "$destination" ] || [ -L "$destination" ] \
        || fail "publication target is neither a regular file nor symlink: $destination"
    temporary=$(mktemp "$parent/.noid-audit-publish.XXXXXXXX") \
        || fail "cannot stage: $destination"
    ROOT_PUBLICATION_TMP=$temporary
    if ! install -m "$requested_mode" -o root -g root -- "$source" "$temporary"; then
        rm -f -- "$temporary"
        ROOT_PUBLICATION_TMP=""
        fail "cannot stage: $destination"
    fi
    restorecon -F -- "$temporary" || {
        rm -f -- "$temporary"
        ROOT_PUBLICATION_TMP=""
        fail "cannot label staged file: $destination"
    }
    matchpathcon -V "$temporary" >/dev/null || {
        rm -f -- "$temporary"
        ROOT_PUBLICATION_TMP=""
        fail "staged-file label differs from policy: $destination"
    }
    sync -- "$temporary" || {
        rm -f -- "$temporary"
        ROOT_PUBLICATION_TMP=""
        fail "cannot sync staged file: $destination"
    }

    # Ignore ordinary termination signals only across the rename, final-label,
    # postcondition and durability window. Outside it, the module traps abort
    # and retire every registered staging path.
    trap '' HUP INT TERM
    if ! mv -fT -- "$temporary" "$destination"; then
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        rm -f -- "$temporary"
        ROOT_PUBLICATION_TMP=""
        fail "cannot publish: $destination"
    fi
    ROOT_PUBLICATION_TMP=""
    if ! restorecon -F -- "$destination" \
       || ! matchpathcon -V "$destination" >/dev/null; then
        rm -f -- "$destination" || true
        sync -- "$parent" >/dev/null 2>&1 || true
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        fail "published-file label differs from policy: $destination"
    fi
    if ! { [ -f "$destination" ] && [ ! -L "$destination" ] \
           && cmp -s -- "$source" "$destination" \
           && [ "$(stat -Lc '%u:%g:%a:%h' -- "$destination" 2>/dev/null)" = \
                "0:0:$mode:1" ] \
           && [ "$(readlink -e -- "$destination" 2>/dev/null)" = \
                "$destination" ]; }; then
        rm -f -- "$destination" || true
        sync -- "$parent" >/dev/null 2>&1 || true
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        fail "publication postcondition failed: $destination"
    fi
    if ! sync -- "$destination" || ! sync -- "$parent"; then
        rm -f -- "$destination" || true
        sync -- "$parent" >/dev/null 2>&1 || true
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        fail "cannot make publication durable: $destination"
    fi
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
}

log "=== Module 40 — noid-audit Bundle Integration ==="

# ============================================================================
# Pinned audit-tool version. PIN-SYNC: matches stage_noid_audit() in
# build-iso.sh and AUDITOR_SOURCE_* in build-audit-support-media.sh (see
# header constraint note). Pin history lives in git.
# ============================================================================
NOID_AUDIT_VERSION="v3.7.2"
NOID_AUDIT_COMMIT="e204bb68a7ac3ce08acc685fb56356d460ba3710"
NOID_AUDIT_SIZE="600495"
NOID_AUDIT_SHA256="724213827287ed4d203bbd6c6d2706b7f60225bde5134c63a6c525bf6e46f0ac"
NOID_AUDIT_URL="http://10.0.2.2:8000/branding/noid-privacy-linux.sh"
NOID_AUDIT_DEST="/usr/local/bin/noid-privacy-linux.sh"

AUDIT_CANDIDATE=""
VERSION_CANDIDATE=""
WRAPPER_CANDIDATE=""
STAMP_CANDIDATE=""
STAMP_DIR=/var/lib/noid-privacy
STAMP=/var/lib/noid-privacy/stamp-40-audit-bundle.ok
STAMP_PUBLICATION_ACTIVE=0
cleanup_candidates() {
    local saved_rc=$? candidate cleanup_failed=0
    trap - EXIT
    trap '' HUP INT TERM
    for candidate in \
        "${ROOT_PUBLICATION_TMP:-}" \
        "${AUDIT_CANDIDATE:-}" \
        "${VERSION_CANDIDATE:-}" \
        "${WRAPPER_CANDIDATE:-}" \
        "${STAMP_CANDIDATE:-}"; do
        [ -n "$candidate" ] || continue
        if ! rm -f -- "$candidate"; then
            log "[FAIL] could not retire staged Module 40 payload: $candidate"
            cleanup_failed=1
        fi
    done
    if [ "${STAMP_PUBLICATION_ACTIVE:-0}" -eq 1 ]; then
        if ! rm -f -- "$STAMP"; then
            log "[FAIL] could not retire incomplete Module 40 health stamp"
            cleanup_failed=1
        fi
        sync -- "$STAMP_DIR" >/dev/null 2>&1 || true
    fi
    if [ "$saved_rc" -eq 0 ] && [ "$cleanup_failed" -ne 0 ]; then
        exit 1
    fi
    return "$saved_rc"
}
trap cleanup_candidates EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# M40_HEALTH_INVALIDATION_BEGIN
# Validate shared state without normalizing drift, then retire any earlier
# success before the first directory, download or installed-payload mutation.
if { [ -e "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; } \
   && { [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; }; then
    fail "$STAMP_DIR exists but is not a real directory"
fi
if [ ! -e "$STAMP_DIR" ]; then
    install -d -m 0755 -o root -g root "$STAMP_DIR"
fi
if [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
        0:0:755 ]; then
    fail "$STAMP_DIR metadata is not root:root 0755"
fi
if [ ! -x /usr/sbin/restorecon ] || [ ! -x /usr/sbin/matchpathcon ] \
   || ! /usr/sbin/restorecon -F -- "$STAMP_DIR" \
   || ! /usr/sbin/matchpathcon -V "$STAMP_DIR" >/dev/null; then
    fail "$STAMP_DIR SELinux context is not canonical"
fi
if [ -e "$STAMP" ] || [ -L "$STAMP" ]; then
    if [ ! -f "$STAMP" ] && [ ! -L "$STAMP" ]; then
        fail "health-stamp target is not a file or symlink: $STAMP"
    fi
    rm -f -- "$STAMP" \
        || fail "cannot invalidate stale Module 40 health stamp"
    sync -- "$STAMP_DIR"
fi
log "  [OK] prior Module 40 health stamp is absent"
# M40_HEALTH_INVALIDATION_END

ensure_root_dir /usr/local/bin 0755
ensure_root_dir /etc/noid 0755
AUDIT_CANDIDATE=$(mktemp /var/tmp/noid-audit-payload.XXXXXXXX) \
    || fail "cannot create audit-payload candidate"
VERSION_CANDIDATE=$(mktemp /var/tmp/noid-audit-version.XXXXXXXX) \
    || fail "cannot create audit-version candidate"
WRAPPER_CANDIDATE=$(mktemp /var/tmp/noid-audit-wrapper.XXXXXXXX) \
    || fail "cannot create audit-wrapper candidate"

# ============================================================================
# STEP 1: Fetch + verify audit-script candidate
# ============================================================================
log "STEP 1: fetching $NOID_AUDIT_VERSION from $NOID_AUDIT_URL"

if curl --silent --show-error --fail --max-time 30 --proto '=http' \
        --max-filesize "$NOID_AUDIT_SIZE" \
        --output "$AUDIT_CANDIDATE" "$NOID_AUDIT_URL"; then
    log "  [OK] candidate downloaded ($(stat -c %s "$AUDIT_CANDIDATE") bytes)"
else
    log "  [FAIL] curl could not fetch $NOID_AUDIT_URL"
    log "  build-iso.sh staging may be missing — ensure the audit tool is staged to the build-host branding/ endpoint"
    exit 1
fi

# Verify exact byte count and SHA-256. The size is an independent truncation /
# wrong-object guard; the digest remains the byte-identity authority.
ACTUAL_SIZE=$(stat -c %s "$AUDIT_CANDIDATE")
if [ "$ACTUAL_SIZE" != "$NOID_AUDIT_SIZE" ]; then
    log "  [FAIL] byte-count mismatch — wrong or truncated audit payload"
    log "    expected: $NOID_AUDIT_SIZE"
    log "    actual:   $ACTUAL_SIZE"
    exit 1
fi

ACTUAL_SHA=$(sha256sum "$AUDIT_CANDIDATE" | awk '{print $1}')
if [ "$ACTUAL_SHA" != "$NOID_AUDIT_SHA256" ]; then
    log "  [FAIL] SHA256 mismatch — payload is not the reviewed selection"
    log "    expected: $NOID_AUDIT_SHA256"
    log "    actual:   $ACTUAL_SHA"
    exit 1
fi

if ! /usr/bin/bash -n "$AUDIT_CANDIDATE"; then
    fail "audit-script candidate has invalid Bash syntax"
fi
UNDERLYING_CANDIDATE_VERSION=$(
    /usr/bin/bash "$AUDIT_CANDIDATE" --version 2>/dev/null || true
)
if [ "$UNDERLYING_CANDIDATE_VERSION" != \
        "NoID Privacy for Linux ${NOID_AUDIT_VERSION#v}" ]; then
    fail "audit-script candidate reports an unexpected version: $UNDERLYING_CANDIDATE_VERSION"
fi
log "  [OK] audit-script candidate identity + syntax + version verified"

# ============================================================================
# STEP 2: Version marker
# ============================================================================
log "STEP 2: writing /etc/noid/audit-version"

# Backticks below stay backslash-escaped: VERSION_EOF is an UNQUOTED heredoc
# (substitutes $NOID_AUDIT_VERSION), so unescaped backticks would command-
# substitute at build time and empty the comment lines. The post-write grep
# is the anti-regression check.
cat > "$VERSION_CANDIDATE" <<VERSION_EOF
# NoID Privacy Audit Bundled Version
# This file is the source-of-truth for \`noid-audit --version\`.
# Updated only by a reviewed, SHA-256-pinned NoID Privacy image/source release.
# Upstream commit: $NOID_AUDIT_COMMIT
# Exact bytes: $NOID_AUDIT_SIZE; SHA-256: $NOID_AUDIT_SHA256
$NOID_AUDIT_VERSION
VERSION_EOF

# Verify template substitution worked (anti-regression check)
if grep -q "source-of-truth for \`noid-audit --version\`" \
        "$VERSION_CANDIDATE"; then
    log "  [OK] audit-version template substitution intact (verified)"
else
    log "  [FAIL] audit-version template substitution failed — comment lines empty (regression)"
    exit 1
fi

log "  [OK] audit-version candidate = $NOID_AUDIT_VERSION"

# ============================================================================
# STEP 3: noid-audit wrapper
# ============================================================================
log "STEP 3: preparing and publishing the closed noid-audit bundle"

cat > "$WRAPPER_CANDIDATE" <<'WRAPPER_EOF'
#!/bin/bash
# noid-audit — wrapper for /usr/local/bin/noid-privacy-linux.sh
#
# Usage:
#   noid-audit                    Offline inventory + score + AI prompt (sudo)
#   noid-audit --online [flags]   Explicitly permit upstream network checks
#   noid-audit --aide-live        Run a fresh AIDE check; never rebaseline
#   noid-audit --rpm-baseline-init|--rpm-baseline-update
#                                 Create/update RPM drift evidence only after
#                                 a separately reviewed policy is installed
#   noid-audit --version          Show bundled version
#   noid-audit --help             Show audit script's own --help
#   noid-audit <other-flags>      Passed through to underlying script
#
# Source: NoID Privacy for Linux (GPLv3)
#         https://github.com/NexusOne23/noid-privacy-linux

set -euo pipefail

readonly SCRIPT="/usr/local/bin/noid-privacy-linux.sh"
readonly SCRIPT_PARENT="/usr/local/bin"
readonly SCRIPT_PARENT_METADATA="0:0:755"
readonly SCRIPT_METADATA="0:0:755:1"
readonly SCRIPT_SIZE="600495"
readonly SCRIPT_SHA256="724213827287ed4d203bbd6c6d2706b7f60225bde5134c63a6c525bf6e46f0ac"
readonly VERSION_FILE="/etc/noid/audit-version"
readonly VERSION_PARENT="/etc/noid"
readonly VERSION_PARENT_METADATA="0:0:755"
readonly VERSION_METADATA="0:0:644:1"
readonly VERSION_MAX_BYTES="4096"
readonly BASH_BIN="/usr/bin/bash"
readonly ENV_BIN="/usr/bin/env"
readonly MATCHPATHCON="/usr/sbin/matchpathcon"
readonly READLINK="/usr/bin/readlink"
readonly SHA256SUM="/usr/bin/sha256sum"
readonly STAT="/usr/bin/stat"
readonly SUDO="/usr/bin/sudo"
NETWORK_MODE=offline
AIDE_LIVE=0
RPM_BASELINE_ACTION=""
RPM_POLICY_REFRESH=0
declare -a AUDIT_ARGS=()

trusted_root_dir() {
    local path=$1 metadata=$2
    [ -d "$path" ] && [ ! -L "$path" ] \
        && [ "$("$READLINK" -e -- "$path" 2>/dev/null)" = "$path" ] \
        && [ "$("$STAT" -Lc '%u:%g:%a' -- "$path" 2>/dev/null)" = \
            "$metadata" ] \
        && "$MATCHPATHCON" -V "$path" >/dev/null 2>&1
}

trusted_script() {
    local actual
    trusted_root_dir "$SCRIPT_PARENT" "$SCRIPT_PARENT_METADATA" \
        && [ -f "$SCRIPT" ] && [ ! -L "$SCRIPT" ] && [ -x "$SCRIPT" ] \
        && [ "$("$READLINK" -e -- "$SCRIPT" 2>/dev/null)" = "$SCRIPT" ] \
        && [ "$("$STAT" -Lc '%u:%g:%a:%h' -- "$SCRIPT" 2>/dev/null)" = \
            "$SCRIPT_METADATA" ] \
        && [ "$("$STAT" -Lc '%s' -- "$SCRIPT" 2>/dev/null)" = \
            "$SCRIPT_SIZE" ] \
        && "$MATCHPATHCON" -V "$SCRIPT" >/dev/null 2>&1 \
        || return 1
    actual=$("$SHA256SUM" -- "$SCRIPT" 2>/dev/null) || return 1
    [ "${actual%% *}" = "$SCRIPT_SHA256" ]
}

read_bundled_version() {
    local line size
    if ! trusted_root_dir "$VERSION_PARENT" "$VERSION_PARENT_METADATA" \
            || [ ! -f "$VERSION_FILE" ] || [ -L "$VERSION_FILE" ] \
            || [ "$("$READLINK" -e -- "$VERSION_FILE" 2>/dev/null)" != \
                "$VERSION_FILE" ] \
            || [ "$("$STAT" -Lc '%u:%g:%a:%h' -- "$VERSION_FILE" \
                    2>/dev/null)" != "$VERSION_METADATA" ] \
            || ! "$MATCHPATHCON" -V "$VERSION_FILE" >/dev/null 2>&1; then
        printf '%s\n' unknown
        return
    fi
    size=$("$STAT" -Lc '%s' -- "$VERSION_FILE" 2>/dev/null) || {
        printf '%s\n' unknown
        return
    }
    if [[ ! "$size" =~ ^[0-9]+$ ]] || [ "$size" -gt "$VERSION_MAX_BYTES" ]; then
        printf '%s\n' unknown
        return
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            ''|'#'*) continue ;;
        esac
        if [[ "$line" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            printf '%s\n' "$line"
        else
            printf '%s\n' unknown
        fi
        return
    done < "$VERSION_FILE"
    printf '%s\n' unknown
}

cmd_version() {
    local v upstream
    v=$(read_bundled_version)
    echo "noid-audit wrapper: $v (bundled)"
    if trusted_script; then
        upstream=$("$BASH_BIN" "$SCRIPT" --version 2>/dev/null || true)
        if [ -n "$upstream" ]; then
            printf 'noid-audit upstream: %s\n' "$upstream"
        fi
    fi
}

require_script() {
    if ! trusted_script; then
        echo "ERROR: $SCRIPT is missing or failed its pinned identity check" >&2
        echo "  This installation may be incomplete or modified." >&2
        exit 2
    fi
}

run_root_audit() {
    # Do not delegate the root-shell environment boundary to the ambient
    # sudoers policy. In particular, BASH_ENV and language/runtime loader
    # variables must never reach the root Bash even if a later administrator
    # changes env_reset/env_keep. Add only fixed execution identity/locale
    # values and the exact explicit evidence opt-ins below.
    local -a root_environment=(-i
        HOME=/root
        USER=root
        LOGNAME=root
        SHELL=/bin/bash
        PATH=/usr/sbin:/usr/bin:/sbin:/bin
        LANG=C
        LC_ALL=C)
    [ -x "$SUDO" ] || {
        echo "ERROR: required privilege broker is unavailable: $SUDO" >&2
        exit 2
    }
    [ "$AIDE_LIVE" -eq 0 ] || root_environment+=(NOID_AIDE_LIVE=1)
    case "$RPM_BASELINE_ACTION" in
        '') ;;
        init) root_environment+=(NOID_RPM_BASELINE_INIT=1) ;;
        update) root_environment+=(NOID_RPM_BASELINE_UPDATE=1) ;;
        *)
            echo "ERROR: internal RPM-baseline action is invalid" >&2
            exit 2
            ;;
    esac
    exec "$SUDO" -- "$ENV_BIN" "${root_environment[@]}" "$BASH_BIN" "$SCRIPT" "$@"
}

# Retired update, diagnostic and version modes are reserved in every argument
# position. The underlying auditor exits immediately when it encounters help
# or version, so allowing an earlier pass-through flag to hide trailing tokens
# would make malformed invocations look successful.
for argument in "$@"; do
    case "$argument" in
        --update)
            echo "ERROR: self-update is disabled; install only a reviewed, SHA-256-pinned NoID Privacy release." >&2
            exit 2
            ;;
        --help|-h)
            [ "$#" -eq 1 ] || {
                echo "ERROR: --help accepts no additional arguments" >&2
                exit 2
            }
            ;;
        --version|-V)
            [ "$#" -eq 1 ] || {
                echo "ERROR: --version accepts no additional arguments" >&2
                exit 2
            }
            ;;
    esac
done
unset argument

# Entry point
case "${1:-}" in
    --version|-V)
        [ "$#" -eq 1 ] || {
            echo "ERROR: --version accepts no additional arguments" >&2
            exit 2
        }
        cmd_version
        exit 0
        ;;
    --help|-h)
        [ "$#" -eq 1 ] || {
            echo "ERROR: --help accepts no additional arguments" >&2
            exit 2
        }
        if trusted_script; then
            echo "noid-audit wrapper defaults: --offline; with no flags also --ai"
            echo "Use --online [audit flags] to explicitly permit active network checks."
            echo "Stateful evidence capture requires one of these explicit wrapper flags:"
            echo "  --aide-live           fresh AIDE check only; never creates/replaces its baseline"
            echo "  --rpm-baseline-init   create RPM evidence; reviewed NoID Privacy policy required"
            echo "  --rpm-baseline-update replace RPM evidence; reviewed NoID Privacy policy required"
            echo "Ambient NOID_* evidence variables are deliberately ignored."
            echo ""
            exec "$BASH_BIN" "$SCRIPT" --help
        else
            echo "noid-audit — wrapper for noid-privacy-linux.sh"
            echo ""
            echo "Usage:"
            echo "  noid-audit               Run supplemental posture inventory (sudo)"
            echo "  noid-audit --online      Explicitly permit active network checks"
            echo "  noid-audit --aide-live   Explicitly run a fresh AIDE check"
            echo "  noid-audit --version     Show bundled version"
            echo "  noid-audit --help        Show this help"
        fi
        exit 0
        ;;
esac

# Wrapper-owned flags are removed before invoking the byte-identical upstream
# script. Ambient stateful variables are never authority: only these explicit
# tokens may add their exact value after sudo.
for argument in "$@"; do
    case "$argument" in
        --online)
            [ "$NETWORK_MODE" != explicit-offline ] || {
                echo "ERROR: --online conflicts with --offline" >&2
                exit 2
            }
            NETWORK_MODE=online
            ;;
        --offline)
            [ "$NETWORK_MODE" != online ] || {
                echo "ERROR: --offline conflicts with --online" >&2
                exit 2
            }
            NETWORK_MODE=explicit-offline
            ;;
        --aide-live)
            AIDE_LIVE=1
            ;;
        --rpm-baseline-init)
            [ "$RPM_BASELINE_ACTION" != update ] || {
                echo "ERROR: choose only one RPM-baseline action" >&2
                exit 2
            }
            RPM_BASELINE_ACTION=init
            ;;
        --rpm-baseline-update)
            [ "$RPM_BASELINE_ACTION" != init ] || {
                echo "ERROR: choose only one RPM-baseline action" >&2
                exit 2
            }
            RPM_BASELINE_ACTION=update
            ;;
        --refresh-noid-rpm-policy)
            RPM_POLICY_REFRESH=1
            AUDIT_ARGS+=("$argument")
            ;;
        *)
            AUDIT_ARGS+=("$argument")
            ;;
    esac
done
unset argument

if [ "$RPM_POLICY_REFRESH" -eq 1 ] \
   && { [ "$AIDE_LIVE" -eq 1 ] || [ -n "$RPM_BASELINE_ACTION" ]; }; then
    echo "ERROR: RPM-policy refresh cannot be combined with evidence-capture actions" >&2
    exit 2
fi

require_script
if [ "${#AUDIT_ARGS[@]}" -eq 0 ]; then
    AUDIT_ARGS=(--ai)
fi

if [ "$NETWORK_MODE" = online ]; then
    run_root_audit "${AUDIT_ARGS[@]}"
fi
# NoID Privacy's integration is offline by default. The exact upstream script
# remains unchanged; --online above is the explicit egress opt-in.
run_root_audit --offline "${AUDIT_ARGS[@]}"
WRAPPER_EOF

/usr/bin/bash -n "$WRAPPER_CANDIDATE" \
    || fail "noid-audit wrapper candidate has invalid Bash syntax"
grep -qxF "readonly SCRIPT_SIZE=\"$NOID_AUDIT_SIZE\"" "$WRAPPER_CANDIDATE" \
    || fail "wrapper candidate byte-count pin drifted"
grep -qxF "readonly SCRIPT_SHA256=\"$NOID_AUDIT_SHA256\"" \
        "$WRAPPER_CANDIDATE" \
    || fail "wrapper candidate digest pin drifted"
VERSION_MARKER_SHA256=$(sha256sum "$VERSION_CANDIDATE" | awk '{print $1}')
WRAPPER_SHA256=$(sha256sum "$WRAPPER_CANDIDATE" | awk '{print $1}')
[[ "$VERSION_MARKER_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || fail "version-marker candidate digest is invalid"
[[ "$WRAPPER_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || fail "wrapper candidate digest is invalid"

publish_root_file "$AUDIT_CANDIDATE" "$NOID_AUDIT_DEST" 0755
publish_root_file "$VERSION_CANDIDATE" /etc/noid/audit-version 0644
publish_root_file "$WRAPPER_CANDIDATE" /usr/local/bin/noid-audit 0755
log "  [OK] audit payload, version marker and wrapper atomically published"

# ============================================================================
# STEP 4: Verification (verify_fail counter pattern, analog M21/M22/M26)
# ============================================================================
log "STEP 4: verification"

verify_fail=0
checks_total=9

verify_owned_regular() {
    local path=$1 mode=$2
    [ -f "$path" ] && [ ! -L "$path" ] \
        && [ "$(readlink -e -- "$path" 2>/dev/null)" = "$path" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' "$path")" = "0:0:${mode}:1" ] \
        && /usr/sbin/matchpathcon -V "$path" >/dev/null
}

# Exact file identity metadata. These are root-executed or trust-bearing
# payloads; executable/existence-only checks would accept symlink, hardlink,
# owner and mode substitution.
if verify_owned_regular "$NOID_AUDIT_DEST" 755 \
        && [ -x "$NOID_AUDIT_DEST" ] \
        && cmp -s -- "$AUDIT_CANDIDATE" "$NOID_AUDIT_DEST"; then
    log "  [OK] audit script exact bytes, metadata and label"
else
    log "  [FAIL] $NOID_AUDIT_DEST metadata/executable contract invalid"
    verify_fail=$((verify_fail + 1))
fi

if verify_owned_regular /usr/local/bin/noid-audit 755 \
        && [ -x /usr/local/bin/noid-audit ] \
        && cmp -s -- "$WRAPPER_CANDIDATE" /usr/local/bin/noid-audit; then
    log "  [OK] wrapper exact bytes, metadata and label"
else
    log "  [FAIL] /usr/local/bin/noid-audit metadata/executable contract invalid"
    verify_fail=$((verify_fail + 1))
fi

if verify_owned_regular /etc/noid/audit-version 644 \
        && cmp -s -- "$VERSION_CANDIDATE" /etc/noid/audit-version; then
    BUNDLED=$(grep -vE "^\s*(#|$)" /etc/noid/audit-version \
        | head -1 | tr -d '[:space:]' || true)
    if [ "$BUNDLED" = "$NOID_AUDIT_VERSION" ]; then
        log "  [OK] /etc/noid/audit-version = $NOID_AUDIT_VERSION"
    else
        log "  [FAIL] /etc/noid/audit-version content unexpected: $BUNDLED"
        verify_fail=$((verify_fail + 1))
    fi
else
    log "  [FAIL] /etc/noid/audit-version identity/metadata contract invalid"
    verify_fail=$((verify_fail + 1))
fi

# Bash syntax check
if /usr/bin/bash -n "$NOID_AUDIT_DEST" 2>/dev/null; then
    log "  [OK] audit script bash -n clean"
else
    log "  [FAIL] audit script bash -n syntax error"
    verify_fail=$((verify_fail + 1))
fi

UNDERLYING_VERSION=$(
    /usr/bin/bash "$NOID_AUDIT_DEST" --version 2>/dev/null || true
)
if [ "$UNDERLYING_VERSION" = \
        "NoID Privacy for Linux ${NOID_AUDIT_VERSION#v}" ]; then
    log "  [OK] underlying auditor reports version ${NOID_AUDIT_VERSION#v}"
else
    log "  [FAIL] underlying auditor version unexpected: $UNDERLYING_VERSION"
    verify_fail=$((verify_fail + 1))
fi

if /usr/bin/bash -n /usr/local/bin/noid-audit 2>/dev/null; then
    log "  [OK] wrapper bash -n clean"
else
    log "  [FAIL] wrapper bash -n syntax error"
    verify_fail=$((verify_fail + 1))
fi

# SHA256 re-verify (paranoid drift-detection)
INSTALLED_SHA=$(sha256sum "$NOID_AUDIT_DEST" | awk '{print $1}')
if [ "$INSTALLED_SHA" = "$NOID_AUDIT_SHA256" ]; then
    log "  [OK] SHA256 matches pinned value"
else
    log "  [FAIL] SHA256 drift after install"
    log "    expected: $NOID_AUDIT_SHA256"
    log "    actual:   $INSTALLED_SHA"
    verify_fail=$((verify_fail + 1))
fi

EXPECTED_WRAPPER_VERSION=$(printf \
    'noid-audit wrapper: %s (bundled)\nnoid-audit upstream: NoID Privacy for Linux %s' \
    "$NOID_AUDIT_VERSION" "${NOID_AUDIT_VERSION#v}")
ACTUAL_WRAPPER_VERSION=$(
    /usr/local/bin/noid-audit --version 2>/dev/null || true
)
if [ "$ACTUAL_WRAPPER_VERSION" = "$EXPECTED_WRAPPER_VERSION" ]; then
    log "  [OK] wrapper reports the exact bundle + auditor versions"
else
    log "  [FAIL] wrapper version output is inconsistent"
    verify_fail=$((verify_fail + 1))
fi

set +e
/usr/local/bin/noid-audit --update >/dev/null 2>&1
UPDATE_RC=$?
set -e
if [ "$UPDATE_RC" -eq 2 ]; then
    log "  [OK] retired self-update token fails closed"
else
    log "  [FAIL] retired self-update token returned rc=$UPDATE_RC (expected 2)"
    verify_fail=$((verify_fail + 1))
fi

if [ "$verify_fail" -gt 0 ]; then
    log "[FAIL] $verify_fail of $checks_total verification check(s) failed — aborting build"
    exit 1
fi

log "  [OK] all $checks_total verification checks passed"

# ============================================================================
# STEP 5: Health Stamp (shared pattern; module-specific extensions
#         audit_version + audit_commit + audit_size + audit_sha256 +
#         version_marker_sha256 + wrapper_sha256)
# ============================================================================
log "STEP 5: writing health stamp"

# M40_HEALTH_PUBLICATION_BEGIN
if [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ] \
   || [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
        0:0:755 ] \
   || ! /usr/sbin/matchpathcon -V "$STAMP_DIR" >/dev/null; then
    fail "shared health-stamp directory drifted before Module 40 publication"
fi

verify_m40_health_stamp() {
    local path="$1"
    [ -f "$path" ] \
        && [ ! -L "$path" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' -- "$path" 2>/dev/null || true)" = \
            0:0:644:1 ] \
        && [ "$(wc -l < "$path")" -eq 16 ] \
        && [ "$(grep -c '^module=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^name=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^version=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^status=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^timestamp=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^checks_passed=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^checks_total=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^audit_version=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^audit_commit=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^audit_size=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^audit_sha256=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^version_marker_sha256=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^wrapper_sha256=' "$path" || true)" -eq 1 ] \
        && grep -qFx '# NoID Privacy — Module 40 Health Stamp' "$path" \
        && grep -qFx \
            '# Written at end of %post verification when all checks pass.' \
            "$path" \
        && grep -qFx \
            '# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.' \
            "$path" \
        && grep -qFx 'module=40' "$path" \
        && grep -qFx 'name=audit-bundle' "$path" \
        && grep -qFx 'version=1' "$path" \
        && grep -qFx 'status=ok' "$path" \
        && grep -Eq \
            '^timestamp=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' \
            "$path" \
        && grep -qFx "checks_passed=$((checks_total - verify_fail))" "$path" \
        && grep -qFx "checks_total=$checks_total" "$path" \
        && grep -qFx "audit_version=$NOID_AUDIT_VERSION" "$path" \
        && grep -qFx "audit_commit=$NOID_AUDIT_COMMIT" "$path" \
        && grep -qFx "audit_size=$NOID_AUDIT_SIZE" "$path" \
        && grep -qFx "audit_sha256=$NOID_AUDIT_SHA256" "$path" \
        && grep -qFx "version_marker_sha256=$VERSION_MARKER_SHA256" "$path" \
        && grep -qFx "wrapper_sha256=$WRAPPER_SHA256" "$path"
}

STAMP_CANDIDATE=$(mktemp \
    "$STAMP_DIR/.stamp-40-audit-bundle.ok.XXXXXXXX") \
    || fail "cannot create Module 40 health-stamp candidate"
cat > "$STAMP_CANDIDATE" <<STAMP_EOF
# NoID Privacy — Module 40 Health Stamp
# Written at end of %post verification when all checks pass.
# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.
module=40
name=audit-bundle
version=1
status=ok
timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
checks_passed=$((checks_total - verify_fail))
checks_total=$checks_total
audit_version=$NOID_AUDIT_VERSION
audit_commit=$NOID_AUDIT_COMMIT
audit_size=$NOID_AUDIT_SIZE
audit_sha256=$NOID_AUDIT_SHA256
version_marker_sha256=$VERSION_MARKER_SHA256
wrapper_sha256=$WRAPPER_SHA256
STAMP_EOF

chown root:root -- "$STAMP_CANDIDATE"
chmod 0644 -- "$STAMP_CANDIDATE"
/usr/sbin/restorecon -F -- "$STAMP_CANDIDATE" \
    || fail "cannot label Module 40 health-stamp candidate"
/usr/sbin/matchpathcon -V "$STAMP_CANDIDATE" >/dev/null \
    || fail "Module 40 health-stamp candidate label differs"
verify_m40_health_stamp "$STAMP_CANDIDATE" \
    || fail "staged Module 40 health-stamp contract is invalid"
sync -- "$STAMP_CANDIDATE" \
    || fail "cannot sync Module 40 health-stamp candidate"

STAMP_PUBLICATION_ACTIVE=1
publish_root_file "$STAMP_CANDIDATE" "$STAMP" 0644
/usr/sbin/matchpathcon -V "$STAMP" >/dev/null \
    || fail "published Module 40 health-stamp label differs"
sync -- "$STAMP" \
    || fail "cannot sync published Module 40 health stamp"
sync -- "$STAMP_DIR" \
    || fail "cannot sync Module 40 health-stamp directory"
verify_m40_health_stamp "$STAMP" \
    || fail "published Module 40 health-stamp contract is invalid"
rm -f -- "$STAMP_CANDIDATE"
STAMP_CANDIDATE=""
STAMP_PUBLICATION_ACTIVE=0
log "  [OK] exact Module 40 health stamp published atomically: $STAMP"
# M40_HEALTH_PUBLICATION_END

log "=== Module 40 noid-audit complete ==="
%end
