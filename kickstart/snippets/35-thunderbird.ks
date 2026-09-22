# ============================================================================
# Module 35 — Thunderbird Hardening
# Status: LOCKED 2026-09-21 (v67) — retain exact DKIM bytes with reviewed ATN compatibility and allow a valid newer recovery source.
#
# Canonical source-of-truth files:
#   - thunderbird/noid-thunderbird-hardening.js (user.js, gzip+base64-embedded)
#   - thunderbird/mozilla.cfg (defaultPref-only, AutoConfig Layer 2)
#   - thunderbird/autoconfig.js + local-settings.js (mozilla.cfg pointers)
#   - docs/35-thunderbird-smartcard.md (installed user guide)
#   Sync gates: scripts/regen-thunderbird-embed.sh --check +
#   scripts/regen-thunderbird-mozilla-cfg.sh --check +
#   scripts/regen-thunderbird-smartcard-doc.sh --check (all must stay IN SYNC).
#
# Architecture (5 deployment layers):
#   - Layer 1 = per-profile user.js (HorlogeSkynet base + NoID Privacy overrides)
#   - Layer 2 = AutoConfig mozilla.cfg (defaultPref ONLY, no lockPref —
#               User-Empowerment hard constraint)
#   - Layer 3 = system-pref-files (defaults/pref/noid-locale.js +
#               /etc/thunderbird/pref/ mirror — system-locale flow-through)
#   - Layer 4 = DKIM Verifier XPI (bundled, opt-out; SHA256-pinned)
#   - Layer 5 = policies.json restricted to the default search engine
# ============================================================================

%post --erroronfail --log=/var/log/ks-35-thunderbird.log
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

log() { echo "[noid-35-thunderbird] $*"; }
fail() {
    log "FAIL: $*"
    exit 1
}

ROOT_PUBLICATION_TMP=

# Root-owned payloads are always staged beside their destination and renamed
# atomically. Canonical parent checks reject symlink traversal before any write.
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
            *) fail "directory is not root-owned: $current ($metadata)" ;;
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
        *) fail "publication parent is not root-owned: $parent ($parent_state)" ;;
    esac
    [[ "$parent_mode" =~ ^[0-7]{3,4}$ ]] \
        || fail "publication parent mode is invalid: $parent ($parent_mode)"
    (( (8#$parent_mode & 0022) == 0 )) \
        || fail "publication parent is group/other-writable: $parent ($parent_mode)"
    [ ! -e "$destination" ] || [ -f "$destination" ] || [ -L "$destination" ] \
        || fail "publication target is neither a regular file nor a symlink: $destination"
    temporary=$(mktemp "$parent/.noid-thunderbird-publish.XXXXXXXX") \
        || fail "cannot stage: $destination"
    ROOT_PUBLICATION_TMP=$temporary
    if ! install -m "$requested_mode" -o root -g root -- "$source" "$temporary"; then
        rm -f -- "$temporary"
        ROOT_PUBLICATION_TMP=
        fail "cannot stage: $destination"
    fi
    restorecon -F -- "$temporary" || {
        rm -f -- "$temporary"
        ROOT_PUBLICATION_TMP=
        fail "cannot label staged file: $destination"
    }
    matchpathcon -V "$temporary" >/dev/null || {
        rm -f -- "$temporary"
        ROOT_PUBLICATION_TMP=
        fail "staged-file label differs from policy: $destination"
    }
    sync -- "$temporary" || {
        rm -f -- "$temporary"
        ROOT_PUBLICATION_TMP=
        fail "cannot sync staged file: $destination"
    }

    # Ignore ordinary termination signals only across the bounded rename,
    # final-label and durability window. Outside this window the module-level
    # traps abort and retire every registered staging path.
    trap '' HUP INT TERM
    if ! mv -fT -- "$temporary" "$destination"; then
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        rm -f -- "$temporary"
        ROOT_PUBLICATION_TMP=
        fail "cannot publish: $destination"
    fi
    ROOT_PUBLICATION_TMP=
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

verify_sha256() {
    local file="$1" expected_sha="$2" name="$3"
    local actual_sha
    actual_sha=$(sha256sum "$file" | cut -d' ' -f1)
    if [ "$actual_sha" != "$expected_sha" ]; then
        log "FAIL: SHA256 mismatch for $name"
        log "  expected: $expected_sha"
        log "  actual:   $actual_sha"
        exit 1
    fi
    log "  SHA256 OK: $name"
}

log "=== Module 35 post-install: Thunderbird hardening (replaces 16b) ==="

# ----------------------------------------------------------------------------
# STEP 0: Cleanup Module 16b legacy artefacts (idempotent)
# ----------------------------------------------------------------------------
# STEP 4c replaces any legacy policy with the audited minimal policy.
log "STEP 0: legacy policy replacement is handled transactionally in STEP 4c"

# ----------------------------------------------------------------------------
# STEP 1: Variables + Supply-Chain-Pin
# ----------------------------------------------------------------------------
NOID_TB_HARDENING_VERSION="1.3.1-horlogeskynet140.3"
DKIM_VERIFIER_VERSION="6.3.0"
DKIM_VERIFIER_URL="https://github.com/lieser/dkim_verifier/releases/download/v${DKIM_VERIFIER_VERSION}/dkim_verifier-${DKIM_VERIFIER_VERSION}.xpi"
DKIM_VERIFIER_SHA256="5ae95b4d560257b2e5722e1d3824a4031fb74d5d57b790dfc12f76a11dc1501a"
DKIM_VERIFIER_EXT_ID="dkim_verifier@pl"
SHARE_DIR="/usr/share/noid-thunderbird"
TB_INSTALL_DIR="/usr/lib64/thunderbird"
TB_DISTRIBUTION_DIR="${TB_INSTALL_DIR}/distribution"
TB_DISTRIBUTION_EXT_DIR="${TB_DISTRIBUTION_DIR}/extensions"
TB_DEFAULTS_PREF_DIR="${TB_INSTALL_DIR}/defaults/pref"
TB_SKEL_DIR="/etc/skel/.thunderbird"
TB_SKEL_PROFILE_DIR="${TB_SKEL_DIR}/default-release"
CACHE_DIR="/var/cache/noid-build/thunderbird"
STAMP_DIR=/var/lib/noid-privacy
STAMP="$STAMP_DIR/stamp-35-thunderbird.ok"
NOID_TB_REASSERT_CANDIDATE=
NOID_TB_ACTION_CANDIDATE=
USERJS_CANDIDATE=
HORLOGESKYNET_LICENSE_CANDIDATE=
MOZILLA_CFG_CANDIDATE=
AUTOCONFIG_JS_CANDIDATE=
LOCAL_SETTINGS_JS_CANDIDATE=
NOID_LOCALE_CANDIDATE=
POLICIES_CANDIDATE=
PROFILES_INI_CANDIDATE=
XPI_DOWNLOAD=
HARDEN_PROFILE_CANDIDATE=
SMARTCARD_DOC_CANDIDATE=
STAMP_TMP=
STAMP_PUBLICATION_ACTIVE=0

cleanup_m35_publication() {
    local saved_rc=$? candidate cleanup_failed=0
    trap - EXIT
    trap '' HUP INT TERM
    for candidate in \
        "${ROOT_PUBLICATION_TMP:-}" \
        "${NOID_TB_REASSERT_CANDIDATE:-}" \
        "${NOID_TB_ACTION_CANDIDATE:-}" \
        "${USERJS_CANDIDATE:-}" \
        "${HORLOGESKYNET_LICENSE_CANDIDATE:-}" \
        "${MOZILLA_CFG_CANDIDATE:-}" \
        "${AUTOCONFIG_JS_CANDIDATE:-}" \
        "${LOCAL_SETTINGS_JS_CANDIDATE:-}" \
        "${NOID_LOCALE_CANDIDATE:-}" \
        "${POLICIES_CANDIDATE:-}" \
        "${PROFILES_INI_CANDIDATE:-}" \
        "${XPI_DOWNLOAD:-}" \
        "${HARDEN_PROFILE_CANDIDATE:-}" \
        "${SMARTCARD_DOC_CANDIDATE:-}" \
        "${STAMP_TMP:-}"; do
        [ -n "$candidate" ] || continue
        if ! rm -f -- "$candidate"; then
            log "FAIL: could not retire staged Module 35 payload: $candidate"
            cleanup_failed=1
        fi
    done
    if [ "${STAMP_PUBLICATION_ACTIVE:-0}" -eq 1 ]; then
        if ! rm -f -- "$STAMP"; then
            log "FAIL: could not retire incomplete Module 35 health stamp"
            cleanup_failed=1
        fi
        sync -- "$STAMP_DIR" >/dev/null 2>&1 || true
    fi
    if [ "$saved_rc" -eq 0 ] && [ "$cleanup_failed" -ne 0 ]; then
        exit 1
    fi
    return "$saved_rc"
}
trap cleanup_m35_publication EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# ----------------------------------------------------------------------------
# STEP 2: Verify thunderbird is installed (sanity check)
# ----------------------------------------------------------------------------
log "STEP 2: Verify thunderbird is installed"
if ! rpm -q thunderbird >/dev/null 2>&1; then
    log "  FAIL: thunderbird RPM is required but not installed"
    exit 1
fi
TB_VERSION=$(rpm -q --qf '%{VERSION}-%{RELEASE}' thunderbird)
log "  thunderbird present: $TB_VERSION"

# The Fedora launcher is an RPM-owned input. Pin and preserve its exact bytes;
# the helper below derives a NoID Privacy-owned /usr/local launcher and XDG
# desktop overlay, so package updates never require vendor-file mutation.
TB_LAUNCHER=/usr/bin/thunderbird
TB_LAUNCHER_SOURCE_SHA256=12fd44963992a2cfafeaa5bca5f33b0c22c7ec9d1e0f1cc71a38d5bd5019e76e
verify_sha256 "$TB_LAUNCHER" "$TB_LAUNCHER_SOURCE_SHA256" \
    "pristine Fedora Thunderbird launcher"
if [ "$(grep -cF 'exec $MOZ_PROGRAM "$@"' "$TB_LAUNCHER")" -ne 1 ]; then
    log "  FAIL: Thunderbird launcher exec line is not the reviewed shape"
    exit 1
fi
bash -n "$TB_LAUNCHER"
log "  Thunderbird RPM launcher remains byte-pristine"

# M35_HEALTH_INVALIDATION_BEGIN
# A build-health stamp represents this complete Thunderbird publication, not
# merely a prior successful run. Validate the shared state boundary without
# normalizing drift, then retire old success before the first payload mutation.
if { [ -e "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; } \
   && { [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; }; then
    fail "$STAMP_DIR exists but is not a real directory"
fi
if [ ! -e "$STAMP_DIR" ]; then
    install -d -m 0755 -o root -g root "$STAMP_DIR"
fi
[ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" = \
    0:0:755 ] || fail "$STAMP_DIR metadata is not root:root 0755"
restorecon -F -- "$STAMP_DIR" \
    || fail "cannot label Thunderbird health-stamp directory"
matchpathcon -V "$STAMP_DIR" >/dev/null \
    || fail "Thunderbird health-stamp directory label differs"
if [ -e "$STAMP" ] || [ -L "$STAMP" ]; then
    [ -f "$STAMP" ] || [ -L "$STAMP" ] \
        || fail "health-stamp target is not a file or symlink: $STAMP"
    rm -f -- "$STAMP" \
        || fail "cannot invalidate stale Module 35 health stamp"
    sync -- "$STAMP_DIR"
fi
log "  Prior Module 35 health stamp is absent"
# M35_HEALTH_INVALIDATION_END

# Regenerate owned launcher/desktop overlays after Thunderbird updates. A future
# Fedora payload is accepted only when its RPM digest and reviewed anchors match.
NOID_TB_REASSERT_CANDIDATE=$(mktemp /var/tmp/noid-thunderbird-reassert.XXXXXXXX)
cat > "$NOID_TB_REASSERT_CANDIDATE" <<'NOID_TB_REASSERT_EOF'
#!/usr/bin/bash
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

if [ "$#" -ne 0 ]; then
    printf 'Usage: noid-thunderbird-reassert\n' >&2
    exit 2
fi

launcher_tmp=
desktop_tmp=
managed_tmp=
cleanup_reassert() {
    local saved_rc=$? temporary cleanup_failed=0
    trap - EXIT
    trap '' HUP INT TERM
    for temporary in \
        "${launcher_tmp:-}" "${desktop_tmp:-}" "${managed_tmp:-}"; do
        [ -n "$temporary" ] || continue
        rm -f -- "$temporary" || cleanup_failed=1
    done
    if [ "$saved_rc" -eq 0 ] && [ "$cleanup_failed" -ne 0 ]; then
        printf 'noid-thunderbird-reassert: failed to retire a staged file\n' >&2
        exit 1
    fi
    return "$saved_rc"
}
trap cleanup_reassert EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
    logger -t noid-thunderbird-reassert "FAILED: $*"
    printf 'noid-thunderbird-reassert: %s\n' "$*" >&2
    exit 1
}

vendor_digest() {
    local path=$1 digest actual
    [ "$(rpm -q --qf '%{FILEDIGESTALGO}' thunderbird 2>/dev/null)" = 8 ] \
        || fail "Thunderbird RPM does not declare SHA-256 file digests"
    # The reader must consume rpm's complete file list: an early-exit awk can
    # close the pipe while rpm is still writing, and under pipefail the
    # resulting SIGPIPE (exit 141) would abort this script without reaching
    # fail().
    digest=$(rpm -q --qf '[%{FILENAMES}\t%{FILEDIGESTS}\n]' thunderbird 2>/dev/null \
        | awk -F '\t' -v p="$path" '
            $1 == p { count++; digest=$2 }
            END { if (count != 1 || digest == "") exit 1; print digest }
        ') || fail "cannot obtain RPM digest for $path"
    [ "${#digest}" -eq 64 ] || fail "cannot obtain RPM digest for $path"
    actual=$(sha256sum "$path" | awk '{print $1}')
    [ "$actual" = "$digest" ] || fail "$path differs from its signed RPM payload"
}

verify_managed_dir() {
    local path=$1 state mode
    [ -d "$path" ] && [ ! -L "$path" ] \
        || fail "unsafe managed directory: $path"
    [ "$(readlink -e -- "$path" 2>/dev/null)" = "$path" ] \
        || fail "managed directory contains a symlink: $path"
    state=$(stat -Lc '%u:%g:%a' -- "$path" 2>/dev/null) \
        || fail "cannot inspect managed directory: $path"
    case "$state" in
        0:0:*) mode=${state##*:} ;;
        *) fail "managed directory is not root-owned: $path ($state)" ;;
    esac
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] \
        || fail "managed directory mode is invalid: $path ($mode)"
    (( (8#$mode & 0022) == 0 )) \
        || fail "managed directory is group/other-writable: $path ($mode)"
    restorecon -F -- "$path" || fail "cannot label managed directory: $path"
    matchpathcon -V "$path" >/dev/null \
        || fail "managed-directory label differs: $path"
}

ensure_managed_dir() {
    local path=$1 parent
    case "$path" in
        /*) ;;
        *) fail "managed directory is not absolute: $path" ;;
    esac
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        parent=${path%/*}
        verify_managed_dir "$parent"
        install -d -m 0755 -o root -g root -- "$path" \
            || fail "cannot create managed directory: $path"
    fi
    [ -d "$path" ] && [ ! -L "$path" ] \
        || fail "unsafe managed directory before metadata repair: $path"
    [ "$(readlink -e -- "$path" 2>/dev/null)" = "$path" ] \
        || fail "managed directory contains a symlink before metadata repair: $path"
    chown root:root -- "$path" \
        || fail "cannot set managed-directory owner: $path"
    chmod 0755 -- "$path" \
        || fail "cannot set managed-directory mode: $path"
    verify_managed_dir "$path"
    [ "$(stat -Lc '%u:%g:%a' -- "$path" 2>/dev/null)" = 0:0:755 ] \
        || fail "managed-directory postcondition failed: $path"
}

publish_staged_file() {
    local staged=$1 destination=$2 requested_mode=$3 parent mode expected_sha
    local state
    mode=${requested_mode#0}
    parent=${destination%/*}
    ensure_managed_dir "$parent"
    [ "$(dirname -- "$staged")" = "$parent" ] \
        || fail "staged file is outside its publication directory: $destination"
    [ -f "$staged" ] && [ ! -L "$staged" ] \
        && [ "$(readlink -e -- "$staged" 2>/dev/null)" = "$staged" ] \
        && [ "$(stat -Lc '%h' -- "$staged" 2>/dev/null)" = 1 ] \
        || fail "unsafe staged file for $destination"
    expected_sha=$(sha256sum "$staged" | awk '{print $1}')
    chmod "$requested_mode" -- "$staged" \
        || fail "cannot set staged mode for $destination"
    chown root:root -- "$staged" \
        || fail "cannot set staged owner for $destination"
    restorecon -F -- "$staged" \
        || fail "cannot label staged file for $destination"
    matchpathcon -V "$staged" >/dev/null \
        || fail "staged-file label differs for $destination"
    sync -- "$staged" || fail "cannot sync staged file for $destination"

    trap '' HUP INT TERM
    if ! mv -fT -- "$staged" "$destination"; then
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        fail "cannot publish $destination"
    fi
    if ! restorecon -F -- "$destination" \
       || ! matchpathcon -V "$destination" >/dev/null; then
        rm -f -- "$destination" || true
        sync -- "$parent" >/dev/null 2>&1 || true
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        fail "published-file label differs for $destination"
    fi
    state=$(stat -Lc '%u:%g:%a:%h' -- "$destination" 2>/dev/null) || state=
    if [ ! -f "$destination" ] || [ -L "$destination" ] \
       || [ "$(readlink -e -- "$destination" 2>/dev/null)" != "$destination" ] \
       || [ "$state" != "0:0:$mode:1" ] \
       || [ "$(sha256sum "$destination" | awk '{print $1}')" != "$expected_sha" ] \
       || ! sync -- "$destination" || ! sync -- "$parent"; then
        rm -f -- "$destination" || true
        sync -- "$parent" >/dev/null 2>&1 || true
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        fail "publication postcondition failed for $destination"
    fi
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
}

vendor_launcher=/usr/bin/thunderbird
owned_launcher=/usr/local/bin/thunderbird
vendor_desktop=/usr/share/applications/net.thunderbird.Thunderbird.desktop
owned_desktop=/usr/local/share/applications/net.thunderbird.Thunderbird.desktop
ensure_managed_dir /usr/local/bin
ensure_managed_dir /usr/local/share/applications
exec 9>/run/noid-thunderbird-overlay.lock
flock -w 300 9 || fail "timed out waiting for Thunderbird overlay regeneration"
vendor_digest "$vendor_launcher"
vendor_digest "$vendor_desktop"
[ "$(grep -cF 'exec $MOZ_PROGRAM "$@"' "$vendor_launcher")" -eq 1 ] \
    || fail "reviewed Thunderbird exec anchor changed"
[ "$(grep -Fxc "export MOZ_APP_LAUNCHER=\"$vendor_launcher\"" "$vendor_launcher")" -eq 1 ] \
    || fail "reviewed Thunderbird relaunch anchor changed"

launcher_tmp=$(mktemp /usr/local/bin/.thunderbird.XXXXXX)
desktop_tmp=$(mktemp --suffix=.desktop /usr/local/share/applications/.net.thunderbird.Thunderbird.XXXXXX)
cp -- "$vendor_launcher" "$launcher_tmp"
sed -i '\|exec $MOZ_PROGRAM "$@"|i\# NoID Privacy: ordinary invocations always use the hardened canonical profile.\n# Explicit profile-management, diagnostic and version/help invocations retain\n# their upstream argument semantics. Thunderbird flag matching is ASCII\n# case-insensitive, so normalize only for exact comparison; attached forms such\n# as -Pfoo and --profile=/path are not profile selectors.\nNOID_PROFILE_SELECTED=0\nfor arg in "$@"; do\n  case "${arg,,}" in\n    -p|-profile|--profile|-profilemanager|--profilemanager|-createprofile|--createprofile|--help|-h|--version|-v|--full-version)\n      NOID_PROFILE_SELECTED=1\n      break\n      ;;\n  esac\ndone\nif [ "$NOID_PROFILE_SELECTED" -eq 0 ]; then\n  set -- -P default-release "$@"\nfi\n' "$launcher_tmp"
sed -i "s|^export MOZ_APP_LAUNCHER=\"$vendor_launcher\"$|export MOZ_APP_LAUNCHER=\"$owned_launcher\"|" \
    "$launcher_tmp"
bash -n "$launcher_tmp" || fail "derived Thunderbird launcher is not valid Bash"
publish_staged_file "$launcher_tmp" "$owned_launcher" 0755
launcher_tmp=

cp -- "$vendor_desktop" "$desktop_tmp"
sed -i 's|^Exec=thunderbird %u$|Exec=/usr/local/bin/thunderbird %u|' "$desktop_tmp"
sed -i 's|^TryExec=thunderbird$|TryExec=/usr/local/bin/thunderbird|' "$desktop_tmp"
grep -qx 'Exec=/usr/local/bin/thunderbird %u' "$desktop_tmp" \
    || fail "derived Thunderbird desktop Exec is not canonical"
if command -v desktop-file-validate >/dev/null 2>&1; then
    desktop-file-validate "$desktop_tmp" || fail "derived Thunderbird desktop entry is invalid"
fi
publish_staged_file "$desktop_tmp" "$owned_desktop" 0644
desktop_tmp=

# Re-assert the AutoConfig/policy payload inside the thunderbird package tree.
# Preflight the complete cache before publishing any member; a partial cache
# must fail the DNF action visibly. Each changed file is staged beside its
# destination and atomically renamed so Thunderbird never reads a truncation.
autoconfig_changed=0
dkim_changed=0
autoconfig_pairs=(
    "/usr/share/noid-thunderbird/mozilla.cfg::/usr/lib64/thunderbird/mozilla.cfg" \
    "/usr/share/noid-thunderbird/autoconfig.js::/usr/lib64/thunderbird/defaults/pref/autoconfig.js" \
    "/usr/share/noid-thunderbird/local-settings.js::/usr/lib64/thunderbird/defaults/pref/local-settings.js" \
    "/usr/share/noid-thunderbird/noid-locale.js::/usr/lib64/thunderbird/defaults/pref/noid-locale.js" \
    "/usr/share/noid-thunderbird/policies.json::/usr/lib64/thunderbird/distribution/policies.json"
)
for src_dst in "${autoconfig_pairs[@]}"; do
    src="${src_dst%%::*}"
    if [ ! -f "$src" ] || [ -L "$src" ]; then
        fail "canonical Thunderbird source missing, non-regular or symlinked: $src"
    fi
done

publish_managed_file() {
    local src=$1 dst=$2 category=$3 parent source_state source_mode
    case "$category" in
        autoconfig|dkim) ;;
        *) fail "unknown managed Thunderbird payload category: $category" ;;
    esac
    parent=${dst%/*}
    [ -f "$src" ] && [ ! -L "$src" ] \
        && [ "$(readlink -e -- "$src" 2>/dev/null)" = "$src" ] \
        || fail "unsafe canonical source for $dst"
    source_state=$(stat -Lc '%u:%g:%a:%h' -- "$src" 2>/dev/null) \
        || fail "cannot inspect canonical source for $dst"
    case "$source_state" in
        0:0:*:1) source_mode=${source_state#0:0:}; source_mode=${source_mode%:1} ;;
        *) fail "canonical source metadata is unsafe for $dst ($source_state)" ;;
    esac
    if ! [[ "$source_mode" =~ ^[0-7]{3,4}$ ]] \
       || (( (8#$source_mode & 0022) != 0 )); then
        fail "canonical source is group/other-writable for $dst"
    fi
    ensure_managed_dir "$parent"
    if [ -f "$dst" ] && [ ! -L "$dst" ] && cmp -s "$src" "$dst" \
       && [ "$(readlink -e -- "$dst" 2>/dev/null)" = "$dst" ] \
       && [ "$(stat -Lc '%u:%g:%a:%h' "$dst" 2>/dev/null || true)" = \
            0:0:644:1 ] \
       && matchpathcon -V "$dst" >/dev/null; then
        return 0
    fi
    managed_tmp=$(mktemp "$parent/.noid-thunderbird-managed.XXXXXX") \
        || fail "cannot stage $dst"
    if ! install -m 0644 -o root -g root "$src" "$managed_tmp"; then
        rm -f -- "$managed_tmp"
        managed_tmp=
        fail "cannot stage canonical payload for $dst"
    fi
    publish_staged_file "$managed_tmp" "$dst" 0644
    managed_tmp=
    case "$category" in
        autoconfig) autoconfig_changed=1 ;;
        dkim) dkim_changed=1 ;;
    esac
}

for src_dst in "${autoconfig_pairs[@]}"; do
    src="${src_dst%%::*}"
    dst="${src_dst#*::}"
    publish_managed_file "$src" "$dst" autoconfig
done

# DKIM Verifier: restore from the exact reviewed seed or a structurally valid,
# non-older durable current slot. A valid destination newer than the available
# managed source is preserved; all other missing/invalid/stale states converge
# atomically without a downgrade.
dkim_validator=/usr/local/lib/noid-privacy/validate-webextension.py
dkim_seed=/usr/share/noid-thunderbird/dkim_verifier.xpi
dkim_seed_version=6.3.0
dkim_seed_sha256=5ae95b4d560257b2e5722e1d3824a4031fb74d5d57b790dfc12f76a11dc1501a
dkim_current=/var/lib/noid-privacy/managed-extensions/dkim_verifier@pl.xpi
dkim_seed_compat=/usr/share/noid-thunderbird/dkim-compatibility.json
dkim_current_compat=/var/lib/noid-privacy/managed-extensions/dkim-compatibility.json
[ -f "$dkim_current_compat" ] || dkim_current_compat=$dkim_seed_compat
for metadata in "$dkim_seed_compat" "$dkim_current_compat"; do
    [ -f "$metadata" ] && [ ! -L "$metadata" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' -- "$metadata")" = 0:0:644:1 ] \
        || fail "unsafe DKIM compatibility metadata"
done
dkim_dst=/usr/lib64/thunderbird/distribution/extensions/dkim_verifier@pl.xpi
[ -x "$dkim_validator" ] || fail "WebExtension validator missing"
tb_version=$(rpm -q --qf '%{VERSION}' thunderbird 2>/dev/null) \
    || fail "cannot determine Thunderbird version"
[ -f "$dkim_seed" ] && [ ! -L "$dkim_seed" ] \
    || fail "reviewed DKIM seed missing, non-regular or symlinked"
[ "$(sha256sum "$dkim_seed" | awk '{print $1}')" = "$dkim_seed_sha256" ] \
    || fail "reviewed DKIM seed differs from its exact SHA-256"
seed_version=$(
    "$dkim_validator" "$dkim_seed" dkim_verifier@pl \
        "$dkim_seed_version" 0 -
) || fail "reviewed DKIM seed fails identity/version validation"
[ "$seed_version" = "$dkim_seed_version" ] \
    || fail "reviewed DKIM seed validator returned an unexpected version"

version_at_least() {
    local candidate=$1 floor=$2 first
    first=$(printf '%s\n%s\n' "$floor" "$candidate" | sort -V | head -n 1)
    [ "$first" = "$floor" ]
}

dkim_src=
dkim_src_version=$dkim_seed_version
dkim_floor=$dkim_seed_version
if "$dkim_validator" "$dkim_seed" dkim_verifier@pl "$dkim_seed_version" \
        0 "$tb_version" 0 "$dkim_seed_compat" >/dev/null 2>&1; then
    dkim_src=$dkim_seed
fi
if [ -f "$dkim_current" ] && [ ! -L "$dkim_current" ]; then
    [ "$(stat -Lc '%u:%g:%a:%h' "$dkim_current")" = 0:0:644:1 ] \
        || fail "unsafe durable DKIM payload metadata"
    structural_version=$("$dkim_validator" "$dkim_current" dkim_verifier@pl - 0 - 2>/dev/null) \
        || structural_version=
    if [ -n "$structural_version" ] && version_at_least "$structural_version" "$dkim_floor"; then
        dkim_floor=$structural_version
    fi
    current_version=$(
        "$dkim_validator" "$dkim_current" dkim_verifier@pl - 0 "$tb_version" 0 "$dkim_current_compat" \
            2>/dev/null
    ) || current_version=
    if [ -n "$current_version" ] \
            && version_at_least "$current_version" "$dkim_seed_version"; then
        dkim_src=$dkim_current
        dkim_src_version=$current_version
    else
        logger -t noid-thunderbird-reassert \
            "WARNING: durable DKIM current slot is incompatible, invalid or older than reviewed seed"
    fi
fi

dst_version=
if [ -f "$dkim_dst" ] && [ ! -L "$dkim_dst" ]; then
    structural_version=$("$dkim_validator" "$dkim_dst" dkim_verifier@pl - 0 - 2>/dev/null) \
        || structural_version=
    if [ -n "$structural_version" ] && version_at_least "$structural_version" "$dkim_floor"; then
        dkim_floor=$structural_version
    fi
    dst_version=$(
        "$dkim_validator" "$dkim_dst" dkim_verifier@pl - 0 "$tb_version" 0 "$dkim_current_compat" \
            2>/dev/null
    ) || dst_version=
fi
if [ -n "$dst_version" ] && version_at_least "$dst_version" "$dkim_src_version" \
        && version_at_least "$dst_version" "$dkim_floor"; then
    if [ -n "$dkim_src" ] && [ "$dst_version" = "$dkim_src_version" ] && ! cmp -s "$dkim_src" "$dkim_dst"; then
        publish_managed_file "$dkim_src" "$dkim_dst" dkim
    fi
elif [ -n "$dkim_src" ] && version_at_least "$dkim_src_version" "$dkim_floor"; then
    publish_managed_file "$dkim_src" "$dkim_dst" dkim
else
    fail "no compatible DKIM payload is available; run NoID Privacy Update to refresh ATN compatibility"
fi
if [ "$autoconfig_changed" -eq 1 ]; then
    logger -t noid-thunderbird-reassert "re-asserted AutoConfig payload inside the thunderbird package tree"
fi
if [ "$dkim_changed" -eq 1 ]; then
    logger -t noid-thunderbird-reassert "re-asserted DKIM Verifier payload inside the thunderbird package tree"
fi
logger -t noid-thunderbird-reassert "regenerated owned Thunderbird launcher/XDG overlays"
NOID_TB_REASSERT_EOF
if ! bash -n "$NOID_TB_REASSERT_CANDIDATE"; then
    fail "Thunderbird reassert helper does not parse"
fi
ensure_root_dir /usr/local/bin 0755
publish_root_file "$NOID_TB_REASSERT_CANDIDATE" \
    /usr/local/bin/noid-thunderbird-reassert 0755
rm -f -- "$NOID_TB_REASSERT_CANDIDATE"
NOID_TB_REASSERT_CANDIDATE=

NOID_TB_ACTION_CANDIDATE=$(mktemp /var/tmp/noid-thunderbird-action.XXXXXXXX)
cat > "$NOID_TB_ACTION_CANDIDATE" <<'NOID_TB_ACTIONS_EOF'
# Regenerate owned launcher/XDG overlays from the newly installed signed RPM
# and re-assert the cached AutoConfig payload inside the package tree.
post_transaction:thunderbird:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-thunderbird-reassert\ >/dev/null
NOID_TB_ACTIONS_EOF
ensure_root_dir /etc/dnf/libdnf5-plugins/actions.d 0755
publish_root_file "$NOID_TB_ACTION_CANDIDATE" \
    /etc/dnf/libdnf5-plugins/actions.d/noid-thunderbird.actions 0644
rm -f -- "$NOID_TB_ACTION_CANDIDATE"
NOID_TB_ACTION_CANDIDATE=
log "  Thunderbird recovery helper/action installed (full run deferred until cache publication)"

# ----------------------------------------------------------------------------
# STEP 3: Decode embedded NoID Privacy Thunderbird hardening user.js
# ----------------------------------------------------------------------------
# Source: thunderbird/noid-thunderbird-hardening.js (HorlogeSkynet v140.3 base
# plus NoID Privacy overrides). Embedded gzip+base64; this decode step does not fetch.
# Regenerate: scripts/regen-thunderbird-embed.sh
log "STEP 3: Decode embedded NoID Privacy Thunderbird hardening v$NOID_TB_HARDENING_VERSION"
ensure_root_dir "$SHARE_DIR" 0755

# Generated from the canonical native worker and reviewed ATN compatibility
# record by scripts/regen-thunderbird-compatibility-embed.sh.
cat > /usr/local/lib/noid-privacy/noid-thunderbird-compatibility <<'TB_NATIVE_COMPAT_EOF'
#!/usr/bin/python3
"""Apply a digest-bound marketplace compatibility update through Thunderbird.

Usage: noid-thunderbird-compatibility ARCHIVE ID VERSION PRODUCT_VERSION METADATA [PROFILE]
Without PROFILE, verify in a disposable profile. With PROFILE, update only the
matching installed add-on's compatibility through Addon.findUpdates. The worker
has no network, session bus or writable system files. Its temporary AutoConfig
never changes the installed AutoConfig sandbox or the user's update preferences.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("expected one regular file")
    return info


def main():
    if len(sys.argv) not in {6, 7} or os.getuid() == 0:
        raise ValueError(__doc__.splitlines()[2])
    archive, identity, version, product_version, metadata = sys.argv[1:6]
    if not re.fullmatch(r"[A-Za-z0-9{][A-Za-z0-9._+@{}-]{0,254}", identity):
        raise ValueError("invalid extension identity")
    validator = "/usr/local/lib/noid-privacy/validate-webextension.py"
    subprocess.run([validator, archive, identity, version, "0", product_version,
                    "1", metadata], check=True, stdout=subprocess.DEVNULL)
    archive = Path(archive).resolve(strict=True)
    regular(archive)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    supplied = json.loads(Path(metadata).read_text())
    updates = supplied["addons"][identity]["updates"]
    matches = [entry for entry in updates if entry["version"] == version
               and entry.get("update_hash") == "sha256:" + digest]
    if len(matches) != 1:
        raise ValueError("compatibility record is not bound to the archive")
    # Exclude update_link: this worker may apply compatibility, never install
    # executable updates or contact an origin carried by marketplace metadata.
    update = {key: matches[0][key] for key in
              ("version", "update_hash", "applications")}
    with tempfile.TemporaryDirectory(prefix="noid-tb-compat.", dir="/var/tmp") as tmp:
        work = Path(tmp)
        for name in ("home", "config", "cache", "runtime", "profile"):
            (work / name).mkdir(mode=0o700)
        actual_profile = len(sys.argv) == 7
        if actual_profile:
            original = Path(sys.argv[6])
            profile = original.resolve(strict=True)
            if original != profile or profile.stat().st_uid != os.getuid() \
                    or not profile.is_dir():
                raise ValueError("unsafe profile directory")
            installed = profile / "extensions" / (identity + ".xpi")
            if regular(installed).st_uid != os.getuid() \
                    or hashlib.sha256(installed.read_bytes()).hexdigest() != digest:
                raise ValueError("profile extension differs from validated archive")
            database = profile / "extensions.json"
            if database.is_file() and not database.is_symlink():
                records = json.loads(database.read_text()).get("addons", [])
                matching = [item for item in records if item.get("id") == identity
                            and item.get("version") == version]
                bounds = update["applications"]["gecko"]
                if len(matching) == 1:
                    addon = matching[0]
                    applications = addon.get("targetApplications", [])
                    if addon.get("appDisabled") is False \
                            and (addon.get("userDisabled") is True or addon.get("active") is True) \
                            and addon.get("path") == str(installed) and any(
                            item.get("id") == "toolkit@mozilla.org"
                            and item.get("minVersion") == bounds["strict_min_version"]
                            and item.get("maxVersion") == bounds["strict_max_version"]
                            for item in applications):
                        print(version)
                        return
            # The native profile lock remains the final arbiter of concurrent
            # browser use; never remove or bypass it.
        else:
            profile = work / "profile"
            (profile / "extensions").mkdir(mode=0o700)
            shutil.copyfile(archive, profile / "extensions" / (identity + ".xpi"))
        (work / "updates.json").write_text(json.dumps({"addons": {
            identity: {"updates": [update]}}}))
        (work / "autoconfig.js").write_text(
            'pref("general.config.filename", "mozilla.cfg");\n'
            'pref("general.config.obscure_value", 0);\n'
            'pref("general.config.sandbox_enabled", false);\n')
        result = work / "result.json"
        values = json.dumps({"id": identity, "version": version,
                             "url": (work / "updates.json").as_uri(),
                             "result": str(result), "fresh": not actual_profile})
        base = Path("/usr/share/noid-thunderbird/mozilla.cfg").read_text()
        code = r'''
// One-shot worker, mounted only inside the network-isolated process.
(function () {
 const job = JOB_VALUES;
 function finish(value) {
  const file = Components.classes["@mozilla.org/file/local;1"].createInstance(Components.interfaces.nsIFile);
  file.initWithPath(job.result);
  const out = Components.classes["@mozilla.org/network/file-output-stream;1"].createInstance(Components.interfaces.nsIFileOutputStream);
  const text = JSON.stringify(value);
  out.init(file, 0x02|0x08|0x20, 384, 0); out.write(text, text.length); out.close();
  Services.startup.quit(Components.interfaces.nsIAppStartup.eForceQuit);
 }
 if (job.fresh) defaultPref("extensions.autoDisableScopes", 0);
 Services.obs.addObserver(function ready() {
  Services.obs.removeObserver(ready, "final-ui-startup");
  (async () => {
   try {
    const {AddonManager} = ChromeUtils.importESModule("resource://gre/modules/AddonManager.sys.mjs");
    const addon = await AddonManager.getAddonByID(job.id);
    if (!addon || addon.version !== job.version) throw new Error("native add-on identity mismatch");
    const disabled = addon.userDisabled;
    const key = "extensions.update.url";
    if (Services.prefs.prefIsLocked(key)) throw new Error("update URL is user-locked");
    const hadUser = Services.prefs.prefHasUserValue(key);
    const old = Services.prefs.getStringPref(key);
    let done;
    try {
     Services.prefs.setStringPref(key, job.url);
     done = new Promise((resolve, reject) => addon.findUpdates({
      onUpdateFinished(a, status) { status === 0 ? resolve() : reject(new Error("native update status " + status)); }
     }, AddonManager.UPDATE_WHEN_USER_REQUESTED));
    } finally {
     if (hadUser) Services.prefs.setStringPref(key, old); else Services.prefs.clearUserPref(key);
    }
    await done;
    if (!addon.isCompatible || addon.userDisabled !== disabled || (!disabled && !addon.isActive))
     throw new Error("native compatibility/activation postcondition failed");
    finish({ok: true, id: addon.id, version: addon.version});
   } catch (error) { finish({ok: false, error: String(error)}); }
  })();
 }, "final-ui-startup");
})();
'''.replace("JOB_VALUES", values)
        (work / "mozilla.cfg").write_text(base + code)
        command = ["/usr/bin/bwrap", "--unshare-all", "--die-with-parent",
                   "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
                   "--tmpfs", "/home", "--tmpfs", "/run",
                   "--bind", str(work), str(work)]
        if actual_profile:
            command += ["--bind", str(profile), str(profile)]
        for source, destination in [
            ("autoconfig.js", "/usr/lib64/thunderbird/defaults/pref/autoconfig.js"),
            ("mozilla.cfg", "/usr/lib64/thunderbird/mozilla.cfg")]:
            command += ["--ro-bind", str(work / source), destination]
        for key, directory in [("HOME", "home"), ("XDG_CONFIG_HOME", "config"),
                               ("XDG_CACHE_HOME", "cache"), ("XDG_RUNTIME_DIR", "runtime")]:
            command += ["--setenv", key, str(work / directory)]
        for key in ("DBUS_SESSION_BUS_ADDRESS", "DISPLAY", "WAYLAND_DISPLAY"):
            command += ["--unsetenv", key]
        command += ["/usr/lib64/thunderbird/thunderbird", "--headless", "--no-remote",
                    "--profile", str(profile)]
        # timeout kills the complete namespace if native shutdown stalls.
        run = subprocess.run(["/usr/bin/timeout", "-k", "3s", "30s", *command],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if run.returncode or not result.is_file():
            raise ValueError("isolated native compatibility worker failed or timed out")
        verdict = json.loads(result.read_text())
        if verdict != {"ok": True, "id": identity, "version": version}:
            raise ValueError(verdict.get("error", "invalid native verdict"))
        print(version)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f"Thunderbird compatibility: {exc}", file=sys.stderr)
        sys.exit(1)
TB_NATIVE_COMPAT_EOF
chmod 0755 /usr/local/lib/noid-privacy/noid-thunderbird-compatibility
chown root:root /usr/local/lib/noid-privacy/noid-thunderbird-compatibility
restorecon -F /usr/local/lib/noid-privacy/noid-thunderbird-compatibility
cat > "$SHARE_DIR/dkim-compatibility.json" <<'TB_SEED_COMPAT_EOF'
{
  "addons": {
    "dkim_verifier@pl": {
      "updates": [
        {
          "version": "6.3.0",
          "update_hash": "sha256:5ae95b4d560257b2e5722e1d3824a4031fb74d5d57b790dfc12f76a11dc1501a",
          "applications": {
            "gecko": {
              "strict_min_version": "128.0",
              "strict_max_version": "*"
            }
          }
        }
      ]
    }
  }
}
TB_SEED_COMPAT_EOF
chmod 0644 "$SHARE_DIR/dkim-compatibility.json"
chown root:root "$SHARE_DIR/dkim-compatibility.json"
restorecon -F "$SHARE_DIR/dkim-compatibility.json"
USERJS_CANDIDATE=$(mktemp /var/tmp/noid-thunderbird-userjs.XXXXXXXX)
base64 -d <<'TB_HARDENING_GZ_B64_EOF' | gunzip > "$USERJS_CANDIDATE"
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
TB_HARDENING_GZ_B64_EOF
USERJS_LINES=$(wc -l < "$USERJS_CANDIDATE")
USERJS_SIZE=$(stat -c%s "$USERJS_CANDIDATE")
if [ "$USERJS_SIZE" -lt 30000 ]; then
    fail "user.js too small (${USERJS_SIZE} bytes, expected >30KB after gunzip)"
fi
EXPECTED_USERJS_VERSION_MARKER="user_pref(\"_noid.thunderbird.hardening.version\", \"$NOID_TB_HARDENING_VERSION\");"
if [ "$(grep -Fxc "$EXPECTED_USERJS_VERSION_MARKER" "$USERJS_CANDIDATE")" -ne 1 ]; then
    fail "embedded user.js hardening version differs from NOID_TB_HARDENING_VERSION"
fi
publish_root_file "$USERJS_CANDIDATE" "$SHARE_DIR/user.js" 0644
rm -f -- "$USERJS_CANDIDATE"
USERJS_CANDIDATE=

# Retain the exact MIT notice from the embedded HorlogeSkynet-derived source in
# the image-wide license inventory. The digest is from annotated tag v140.3,
# commit 556709d1a4beced21f9888fb9b55dd623b415008.
LICENSE_DIR=/usr/share/licenses/noid-privacy
HORLOGESKYNET_LICENSE="$LICENSE_DIR/horlogeskynet-thunderbird-user.js-MIT.txt"
ensure_root_dir "$LICENSE_DIR" 0755
HORLOGESKYNET_LICENSE_CANDIDATE=$(mktemp \
    /var/tmp/noid-thunderbird-license.XXXXXXXX)
awk '/^\/\* HORLOGESKYNET MIT NOTICE BEGIN$/ { copy=1; next }
     /^HORLOGESKYNET MIT NOTICE END \*\/$/ { copy=0; found_end=1; next }
     copy { print }
     END { if (!found_end) exit 1 }' \
    "$SHARE_DIR/user.js" > "$HORLOGESKYNET_LICENSE_CANDIDATE"
printf '%s  %s\n' \
    e0bfbe5467925aa73c30bb5d7e9e23fef1a2f6285b0c5dd62a5c7ab091fc5331 \
    "$HORLOGESKYNET_LICENSE_CANDIDATE" | sha256sum -c -
publish_root_file "$HORLOGESKYNET_LICENSE_CANDIDATE" \
    "$HORLOGESKYNET_LICENSE" 0644
rm -f -- "$HORLOGESKYNET_LICENSE_CANDIDATE"
HORLOGESKYNET_LICENSE_CANDIDATE=
log "  Installed exact HorlogeSkynet v140.3 MIT notice: $HORLOGESKYNET_LICENSE"
log "  user.js: ${USERJS_LINES} lines, ${USERJS_SIZE} bytes"

# ----------------------------------------------------------------------------
# STEP 4: AutoConfig (Layer 2) — mozilla.cfg + autoconfig.js + local-settings.js
# ----------------------------------------------------------------------------
# defaultPref()-only (NO lockPref). An about:config user value overrides this
# layer unless the profile's user.js resets the same pref at startup.
log "STEP 4: Deploy AutoConfig (Layer 2: defaultPref-only)"
ensure_root_dir "$TB_DEFAULTS_PREF_DIR" 0755

MOZILLA_CFG_CANDIDATE=$(mktemp /var/tmp/noid-thunderbird-mozilla-cfg.XXXXXXXX)
cat > "$MOZILLA_CFG_CANDIDATE" <<'MOZILLA_CFG_EOF'
// !!! IMPORTANT: file MUST start with a comment line (Mozilla parses skipping line 1)
// NoID Privacy Workstation 44 — Thunderbird AutoConfig (Layer 2: defaultPref-only, NO Locks)
// Generated by Module 35. Unowned file inside the thunderbird package tree:
// plain RPM upgrades keep it in place; reinstall/tree-restructure paths drop
// it. Re-asserted by noid-thunderbird-reassert (dnf5 action on every
// thunderbird transaction) and by /usr/local/bin/noid-update-all.sh.
// An about:config user value overrides this default layer unless the profile's
// user.js resets the same pref at startup.
//
// mozilla.cfg is the system-wide, user-overridable default layer and covers
// every profile regardless of name. The separately maintained
// /etc/skel/.thunderbird/default-release/user.js adds profile-specific
// hardening and is re-read at startup.
//
// NoID Privacy's owned launcher selects `default-release` for ordinary starts,
// so the skel profile is authoritative there. Explicit profile-management and
// migration paths may use other registered names; AutoConfig remains the
// name-independent baseline for those profiles.
// Fedora's signed RPM and the user-started NoID Privacy update workflow own
// application updates. The pinned DKIM package is independently checked for
// identity, version and compatibility with the installed Thunderbird.

// === TELEMETRY OFF ===
defaultPref("toolkit.telemetry.enabled", false);
defaultPref("toolkit.telemetry.unified", false);
defaultPref("toolkit.telemetry.server", "data:,");
defaultPref("toolkit.telemetry.archive.enabled", false);
defaultPref("toolkit.telemetry.newProfilePing.enabled", false);
defaultPref("toolkit.telemetry.shutdownPingSender.enabled", false);
defaultPref("toolkit.telemetry.updatePing.enabled", false);
defaultPref("toolkit.telemetry.bhrPing.enabled", false);
defaultPref("toolkit.telemetry.firstShutdownPing.enabled", false);
defaultPref("toolkit.coverage.opt-out", true);
defaultPref("toolkit.coverage.endpoint.base", "");
defaultPref("datareporting.policy.dataSubmissionEnabled", false);
defaultPref("datareporting.healthreport.uploadEnabled", false);
defaultPref("datareporting.usage.uploadEnabled", false);
defaultPref("app.shield.optoutstudies.enabled", false);
defaultPref("app.normandy.api_url", "");
defaultPref("app.normandy.user_id", "");
defaultPref("breakpad.reportURL", "");
defaultPref("browser.crashReports.unsubmittedCheck.autoSubmit2", false);
defaultPref("captivedetect.canonicalURL", "");
defaultPref("network.captive-portal-service.enabled", false);
defaultPref("network.connectivity-service.enabled", false);
defaultPref("network.connectivity-service.IPv4.url", "");
defaultPref("network.connectivity-service.IPv6.url", "");
defaultPref("mail.rights.override", true);
defaultPref("captchadetection.actor.enabled", false);
defaultPref("nimbus.profileId", "");
defaultPref("dom.push.userAgentID", "");

// === AI/ML FEATURES OFF (TB 148+ — analog Firefox privacy/telemetry tightening) ===
defaultPref("browser.ml.enable", false);
defaultPref("browser.ai.control.default", "blocked");
defaultPref("browser.ai.control.sidebarChatbot", "blocked");
defaultPref("browser.ai.control.linkPreviewKeyPoints", "blocked");
defaultPref("browser.ai.control.smartTabGroups", "blocked");
defaultPref("browser.ai.control.translations", "blocked");
defaultPref("browser.ai.control.pdfjsAltText", "blocked");

// === DNS (provider-neutral OS/VPN resolver; user may enable Secure DNS) ===
// mode 5 means Firefox/Thunderbird DoH is off by explicit image default.
// defaultPref remains user-overridable and user.js deliberately carries no
// network.trr.* value, so the choice survives restarts and Update All.
defaultPref("network.trr.mode", 5);
// Do not disable IPv6 inside the application. Physical-WAN IPv6 remains an OS
// policy; VPN-internal IPv6 and IPv6-only/NAT64 networks remain usable.
defaultPref("network.dns.disableIPv6", false);
// TB 152 initializes both the Secure DNS controls and OpenPGP-keyserver list
// only after Gecko's region service resolves. Seed the packaged region
// locally and disable the unrelated Mozilla country/Wi-Fi lookup so blocked
// egress cannot leave those controls empty or unexpandable.
defaultPref("doh-rollout.home-region", "global");
defaultPref("browser.region.network.url", "");
defaultPref("browser.region.network.scan", false);
defaultPref("browser.region.update.enabled", false);
defaultPref("network.dns.disablePrefetch", true);
defaultPref("network.dns.disablePrefetchFromHTTPS", true);
defaultPref("network.prefetch-next", false);
// A failed user-configured proxy must not silently bypass to a direct
// connection. Accepted trade-off: while that proxy is unavailable, blocklist,
// Remote Settings and CRLite refreshes cannot update. Those refreshes are not
// content-signature verified in Thunderbird either — see the CRLite note in
// the profile user.js (REMOTE_SETTINGS_VERIFY_SIGNATURE = false).
defaultPref("network.proxy.failover_direct", false);
defaultPref("network.IDN_show_punycode", true);

// === TLS (TLS 1.2 minimum, TLS 1.3 maximum, no-deprecated-versions) ===
defaultPref("security.tls.version.min", 3);
defaultPref("security.tls.version.max", 4);
defaultPref("security.tls.version.enable-deprecated", false);
defaultPref("security.ssl.require_safe_negotiation", true);
defaultPref("security.tls.enable_0rtt_data", false);
// TLS 1.3 hybrid X25519MLKEM768 capability; peer negotiation is still required.
defaultPref("security.tls.enable_kyber", true);
defaultPref("security.ssl.treat_unsafe_negotiation_as_broken", true);
defaultPref("security.OCSP.enabled", 1);
// Keep Mozilla's soft-fail default. Hard-fail protects when a responder is
// available but blocked, yet turns responder outages into TLS/S/MIME failures
// and cannot replace revocation data for certificates without an OCSP URL.
// Let's Encrypt removed OCSP URLs on 2025-05-07 and shut its responders on
// 2025-08-06; OCSP fetching, stapling and the packaged OneCRL remain active.
// https://letsencrypt.org/2024/12/05/ending-ocsp.html
defaultPref("security.OCSP.require", false);
defaultPref("security.cert_pinning.enforcement_level", 2);
defaultPref("security.mixed_content.block_active_content", true);
defaultPref("security.mixed_content.block_display_content", true);
defaultPref("mail.external_protocol_requires_permission", true);
defaultPref("dom.security.https_only_mode", true);

// === EXTERNAL LINK CLICKS — DON'T PROMPT FOR REGISTERED PROTOCOLS ===
// https/http/mailto going to system default-handler should NOT prompt
// every click. Thunderbird already defaults these known protocols to false;
// keep the user-overridable values explicit.
defaultPref("network.protocol-handler.warn-external.http", false);
defaultPref("network.protocol-handler.warn-external.https", false);
defaultPref("network.protocol-handler.warn-external.mailto", false);

// === SAFEBROWSING COMPATIBILITY; REMOTE DOWNLOAD REPUTATION OFF ===
// Thunderbird 152 does not initialize Gecko's SafeBrowsing list service, so
// the four true values below are inert forward-compatibility defaults, not
// active local-list protection. Thunderbird's heuristic PhishingDetector is
// enabled separately; the false value suppresses per-download reputation POSTs.
defaultPref("browser.safebrowsing.downloads.remote.enabled", false);
defaultPref("browser.safebrowsing.malware.enabled", true);
defaultPref("browser.safebrowsing.phishing.enabled", true);
defaultPref("browser.safebrowsing.downloads.enabled", true);
defaultPref("browser.safebrowsing.blockedURIs.enabled", true);

// === THUNDERBIRD 152 SHUTDOWN SANITIZATION ===
// Thunderbird's sanitizer reads this three-pref namespace, not Firefox's
// privacy.clearOnShutdown_v2/privacy.clearSiteData/privacy.clearHistory keys.
// Remove cache and cookies on a clean exit; preserve message/history state.
defaultPref("privacy.sanitize.sanitizeOnShutdown", true);
defaultPref("privacy.clearOnShutdown.cache", true);
defaultPref("privacy.clearOnShutdown.cookies", true);
defaultPref("privacy.clearOnShutdown.history", false);
defaultPref("privacy.sanitize.timeSpan", 0);

// === MAIL DISPLAY — HTML mail readable, remote-images blocked ===
// Display ORIGINAL HTML (sanitized by TB built-in) with remote images
// blocked + JS off + media off. User can read formatted newsletters; these
// values are selected by default and remain user-overridable.
defaultPref("mailnews.message_display.disable_remote_image", true);  // KEEP — privacy critical
defaultPref("mailnews.display.html_as", 0);                          // RELAX (was 3) — show HTML
defaultPref("mailnews.display.disallow_mime_handlers", 0);           // RELAX (was 3) — sane defaults
defaultPref("mail.identity.default.compose_html", true);             // RELAX (was false) — HTML compose
defaultPref("mail.html_compose", true);                              // RELAX (was false) — allow HTML
defaultPref("mail.compose.default_to_paragraph", true);              // RELAX — paragraph mode
defaultPref("mail.inline_attachments", true);                        // RELAX (was false) — show inline images/PDFs
defaultPref("mail.html_sanitize.drop_conditional_css", true);        // KEEP — sanitize tracking-CSS
defaultPref("mail.compose.add_link_preview", false);                 // KEEP — no auto preview-fetch
defaultPref("permissions.default.image", 2);                         // KEEP — block external images by default
// Keep explicit sender/site exceptions durable while retaining the blocked
// default. A user can still choose memory-only permissions in about:config.
defaultPref("permissions.memory_only", false);
defaultPref("javascript.enabled", false);                            // KEEP — security critical
defaultPref("media.mediasource.enabled", false);                     // KEEP — privacy
defaultPref("media.eme.enabled", false);                             // KEEP — DRM off

// === COMPOSE — PUBLIC-RECIPIENT (BCC) WARNING ===
// Built-in warning is on by Mozilla-default (threshold 15). Harden: warn at
// fewer public To/CC recipients + re-warn on send if the first warning was
// dismissed — guards against accidental recipient-address disclosure (e.g. a
// mailing list pasted into CC instead of BCC). No master on/off pref exists;
// the threshold gates the warning, .aggressive adds the second send-time prompt.
defaultPref("mail.compose.warn_public_recipients.threshold", 5);
defaultPref("mail.compose.warn_public_recipients.aggressive", true);

// === MDN / READ-RECEIPT SUPPRESSION (critical Privacy) ===
defaultPref("mail.mdn.report.not_in_to_cc", 0);
defaultPref("mail.mdn.report.outside_domain", 0);
defaultPref("mail.mdn.report.other", 0);
defaultPref("mail.request.return_receipt", 0);

// === PHISHING DETECTION (local heuristics, ACTIVE) ===
defaultPref("mail.phishing.detection.enabled", true);
defaultPref("mail.phishing.detection.disallow_form_actions", true);

// === AUTO-CONFIG — OWN-DOMAIN FETCH + LOCAL GUESS ENABLED ===
// fetchFromISP contacts the user's own mail domain; sslOnly and
// sendEmailAddress=false govern only that path. guess.* controls local hostname
// probing, and requireGoodCert applies only there. The independent Thunderbird
// ISPDB request is controlled by mailnews.auto_config_url, is deliberately left
// at the vendor default here, and discloses the mail domain to that service.
// No Settings toggle exists. A complete opt-out requires guess/fetchFromISP
// false plus an empty auto_config_url in about:config; for the ordinary
// NoID Privacy profile, edit/remove the matching user.js lines so restart does
// not reapply them.
defaultPref("mailnews.auto_config.guess.enabled", true);             // RELAX (was false) — try TB-internal heuristics
defaultPref("mailnews.auto_config.fetchFromISP.enabled", true);      // RELAX (was false) — autodetect via ISP
defaultPref("mailnews.auto_config.fetchFromISP.sendEmailAddress", false);  // KEEP — don't leak full email
defaultPref("mailnews.auto_config.fetchFromISP.sslOnly", true);            // KEEP — TLS-only fetch
defaultPref("mailnews.auto_config.guess.sslOnly", true);                   // KEEP — TLS-only guess
defaultPref("mailnews.auto_config.guess.requireGoodCert", true);           // KEEP — strict cert verify
defaultPref("mailnews.start_page.enabled", false);                         // KEEP
defaultPref("mailnews.start_page.url", "about:blank");                     // KEEP

// === SMTP EHLO LOCAL-ADDRESS MINIMIZATION ===
// Avoid disclosing a private-LAN or VPN-internal local socket address. RFC 5321
// prefers an actual address literal but forbids rejection solely for failed
// EHLO identity verification; users can override this for a broken provider.
defaultPref("mail.smtpserver.default.hello_argument", "[127.0.0.1]");

// === ADDRESS BOOK + EMAIL COLLECTION + CLOUDFILES OFF ===
defaultPref("mail.collect_email_address_outgoing", false);
defaultPref("mail.cloud_files.enabled", false);

// === CHAT / IRC / XMPP / MATRIX (default off — User can enable) ===
defaultPref("mail.chat.enabled", false);
defaultPref("purple.logging.log_chats", false);
defaultPref("purple.logging.log_ims", false);
defaultPref("purple.conversations.im.send_typing", false);
defaultPref("mail.chat.notification_info", 2);

// === CALENDAR (system-tz default) ===
// TB uses system-locale TZ via useSystemTimezone=true (e.g. Europe/Paris on
// fr_FR system, America/New_York on en_US system). User can override via
// Calendar Settings.
defaultPref("calendar.timezone.useSystemTimezone", true);
defaultPref("calendar.alarms.playsound", false);
defaultPref("calendar.alarms.show", true);

// === RSS (no Webpage Auto-Load) ===
defaultPref("rss.show.content-base", 3);
defaultPref("rss.show.summary", 1);

// === OPENPGP / GNUPG ===
// Editable default: users can add/remove keyservers in Thunderbird and their
// profile value wins. Keep this out of user.js so a restart does not undo UI
// changes; the explicit default also survives an upstream-default change.
defaultPref("mail.openpgp.keyserver_list", "vks://keys.openpgp.org, hkps://keys.mailvelope.com");
defaultPref("mail.openpgp.separate_mime_layers", true);
defaultPref("mail.openpgp.allow_external_gnupg", true);

// === USER AGENT (minimal in outgoing headers + sendUserAgent off) ===
defaultPref("mailnews.headers.useMinimalUserAgent", true);
defaultPref("mailnews.headers.sendUserAgent", false);

// === PRIVACY/TRACKING ===
defaultPref("privacy.firstparty.isolate", false);
defaultPref("privacy.donottrackheader.enabled", false);
defaultPref("privacy.globalprivacycontrol.enabled", false);
defaultPref("privacy.resistFingerprinting", false);

// === LANGUAGE / LOCALE / SPELLCHECKER — system-locale flow-through ===
// No en-US forcing. Earlier approach forced en-US to "reduce
// fingerprinting", but TB is email (not browser) — Accept-Language privacy
// for SMTP is irrelevant. Forcing en-US on fr_FR-locale users (or any
// non-English locale) caused a language prompt on first start and made the
// en-US dictionary flag non-English text incorrectly.
// Specific drops:
//   * privacy.spoof_english=1 — means "do not spoof" and suppresses the
//     language prompt (only value 0 prompts). Layer 1 retains this value; it
//     is not mirrored here because system-locale flow-through is intended.
//   * intl.accept_languages="en-US, en" — let TB use system-locale default
//     (fr_FR → "fr-FR, en-US, en"; en_US → "en-US, en"; etc.).
//   * spellchecker.dictionary="en-US" — let TB use system-locale dictionary
//     (user installs hunspell-XX RPM via dnf if missing). M26 ships only
//     hunspell-en-US baseline; dictionary install via Settings → Composition.
// KEPT: mail.suppress_content_language=true (outgoing-only, no UX impact,
//       valid privacy hygiene — recipient doesn't know your TB language).
defaultPref("mail.suppress_content_language", true);      // No Content-Language leak (KEEP — outgoing-only)

// DKIM Verifier settings are WebExtension storage keys, not Gecko prefs.
// Its default JSDNS resolver reads the OS resolver configuration, preserving
// active VPN/private-link DNS policy. Do not add inert extensions.dkim_verifier.*
// Gecko preferences or force a provider through managed storage.

// === USER-STARTED UPDATE OWNERSHIP ===
// Fedora owns the application through DNF. NoID Privacy Update All owns DKIM
// and every additional profile extension through fixed official channels;
// Thunderbird itself performs no background executable/add-on update.
defaultPref("app.update.auto", false);
defaultPref("app.update.silent", false);
defaultPref("extensions.update.enabled", false);
defaultPref("extensions.update.autoUpdateDefault", false);
defaultPref("extensions.systemAddon.update.enabled", false);
// Keep Thunderbird's compiled Remote Settings endpoint. Release builds ignore
// unsupported endpoint overrides; telemetry/studies are controlled separately.
// Thunderbird 152's MailGlue initializes the
// security-state/cert-revocations client, which downloads and installs CRLite
// full filters and deltas. Mode 2 enforces both revoked and not-revoked results;
// the remaining revocation mechanisms cover validation until a usable filter is
// present.
defaultPref("security.remote_settings.crlite_filters.enabled", true);
defaultPref("security.pki.crlite_mode", 2);
defaultPref("extensions.blocklist.enabled", true);
defaultPref("extensions.getAddons.cache.enabled", false);

// === DISK-CACHE + HISTORY + FORM-AUTOFILL ===
// Cache stays off; history + form-autofill + downloadDir restored to sane
// defaults so URL completion in Address Book + autocomplete + auto-save
// to Downloads all work as expected.
defaultPref("browser.cache.disk.enable", false);                  // KEEP — no disk cache
defaultPref("browser.cache.disk_cache_ssl", false);               // KEEP — no SSL cache
defaultPref("browser.formfill.enable", true);                     // RELAX (was false) — autocomplete works
defaultPref("places.history.enabled", true);                      // RELAX (was false) — URL/contact completion
defaultPref("browser.download.useDownloadDir", true);             // RELAX (was false) — auto-save to Downloads
defaultPref("mail.shell.checkDefaultClient", false);              // KEEP — no "make default" annoyance

// === EMPTY-TRASH-ON-EXIT — DISABLED (was destructive) ===
// empty_trash_on_exit=true is destructive — user who accidentally moved
// important mail to trash loses it on next quit. LUKS encryption protects
// at-rest data, so the marginal privacy gain doesn't justify the data-loss
// risk.
defaultPref("mail.server.default.empty_trash_on_exit", false);    // RELAX (was true) — non-destructive

// === WEB-FORM ADDRESS/CARD AUTOFILL OFF ===
defaultPref("extensions.formautofill.creditCards.enabled", false);
defaultPref("extensions.formautofill.addresses.enabled", false);
defaultPref("signon.autofillForms", false);
defaultPref("signon.formlessCapture.enabled", false);

// === EXTENSIONS SCOPES (for the profile-installed DKIM-XPI + Mozilla langpacks) ===
// Bitmask: 1=profile + 2=user + 4=app + 8=system
// enabledScopes=5 (=profile+app) — load profile/extensions/ (where the
// distribution installer copies the DKIM XPI on first run) + the app-global
// /usr/lib64/thunderbird/extensions/ (Fedora langpacks)
// autoDisableScopes=11 (=profile+user+system, app-bit OFF):
//   App-bit OFF lets app-installed Mozilla langpacks (location=app-global)
//   stay enabled → matches user system-locale (fr_FR → langpack-fr auto-active
//   via Fedora's all-redhat.js matchOS=true + intl.locale.requested=""
//   defense-in-depth from noid-locale.js).
defaultPref("extensions.enabledScopes", 5);
defaultPref("extensions.autoDisableScopes", 11);

// === BUILT-IN ABOUT:WELCOME / ONBOARDING DISABLE ===
defaultPref("browser.aboutwelcome.enabled", false);

// === POST-v140.3 GECKO PRIVACY PREFS (FF/TB 145+, base review TB 152, WebSocket arm TB 153) ===
// Shared Gecko-engine prefs postdating the HorlogeSkynet v140.3 base, mirrored
// from the user.js trailing block. mozilla.cfg (AutoConfig) is the reliable
// system-wide layer; the per-profile user.js is fallback only.
// PPA ad-measurement: TB 152's shared Gecko service reads this submission gate;
// the retired dom.private-attribution.enabled name is deliberately omitted.
defaultPref("dom.private-attribution.submission.enabled", false);
// Local Network Access (Gecko 150) — block sites + 3rd-party trackers reaching
// localhost/LAN. The explicit defaults activate the gate without policy locks.
defaultPref("network.lna.enabled", true);
defaultPref("network.lna.blocking", true);
defaultPref("network.lna.block_trackers", true);
// WebSocket arm of the same gate. Bug 1996551 documents the temporary exemption
// and opt-in pref; Bug 2042339 enables the gate for Gecko 154. TB 153 carries
// the pref; the matching Firefox 153 build was measured with a false default,
// so setting it here covers ws:// reaching localhost/LAN and survives the
// upstream default flipping back.
defaultPref("network.lna.websocket.enabled", true);
// Disable Nimbus configuration rollouts independently of Normandy.
defaultPref("nimbus.rollouts.enabled", false);
// Keep QWAC handling disabled; ordinary WebPKI validation is unchanged.
defaultPref("security.qwacs.enabled", false);
MOZILLA_CFG_EOF
if grep -q '^lockPref' "$MOZILLA_CFG_CANDIDATE"; then
    fail "lockPref found in candidate mozilla.cfg"
fi
publish_root_file "$MOZILLA_CFG_CANDIDATE" "$TB_INSTALL_DIR/mozilla.cfg" 0644
publish_root_file "$MOZILLA_CFG_CANDIDATE" "$SHARE_DIR/mozilla.cfg" 0644
rm -f -- "$MOZILLA_CFG_CANDIDATE"
MOZILLA_CFG_CANDIDATE=

AUTOCONFIG_JS_CANDIDATE=$(mktemp /var/tmp/noid-thunderbird-autoconfig.XXXXXXXX)
cat > "$AUTOCONFIG_JS_CANDIDATE" <<'AUTOCONFIG_JS_EOF'
// NoID Privacy Workstation 44 — Thunderbird AutoConfig pointer
// sandbox_enabled=true: NoID Privacy's mozilla.cfg uses only defaultPref()
// calls, which work in sandbox-enabled mode. The sandbox prevents AutoConfig
// JavaScript from reading environment variables, files, the network or
// privileged Components APIs.
pref("general.config.filename", "mozilla.cfg");
pref("general.config.obscure_value", 0);
pref("general.config.sandbox_enabled", true);
AUTOCONFIG_JS_EOF
publish_root_file "$AUTOCONFIG_JS_CANDIDATE" \
    "$TB_DEFAULTS_PREF_DIR/autoconfig.js" 0644
publish_root_file "$AUTOCONFIG_JS_CANDIDATE" "$SHARE_DIR/autoconfig.js" 0644
rm -f -- "$AUTOCONFIG_JS_CANDIDATE"
AUTOCONFIG_JS_CANDIDATE=

LOCAL_SETTINGS_JS_CANDIDATE=$(mktemp \
    /var/tmp/noid-thunderbird-local-settings.XXXXXXXX)
cat > "$LOCAL_SETTINGS_JS_CANDIDATE" <<'LOCAL_SETTINGS_JS_EOF'
// NoID Privacy Workstation 44 — Thunderbird local-settings (mozilla.cfg pointer)
// Compatibility alias for autoconfig.js: Mozilla deployment guidance has used
// both conventional filenames. Their identical values keep behavior deterministic.
pref("general.config.filename", "mozilla.cfg");
pref("general.config.obscure_value", 0);
LOCAL_SETTINGS_JS_EOF
publish_root_file "$LOCAL_SETTINGS_JS_CANDIDATE" \
    "$TB_DEFAULTS_PREF_DIR/local-settings.js" 0644
publish_root_file "$LOCAL_SETTINGS_JS_CANDIDATE" \
    "$SHARE_DIR/local-settings.js" 0644
rm -f -- "$LOCAL_SETTINGS_JS_CANDIDATE"
LOCAL_SETTINGS_JS_CANDIDATE=

# Defense-check: NO lockPref in deployed mozilla.cfg
if grep -q '^lockPref' "$TB_INSTALL_DIR/mozilla.cfg"; then
    log "  FAIL: lockPref found in mozilla.cfg — must be defaultPref only"
    exit 1
fi
log "  AutoConfig deployed (defaultPref only, NO Locks)"

# ----------------------------------------------------------------------------
# STEP 4b: system-pref-files for system-locale flow-through
# ----------------------------------------------------------------------------
# Defense-in-depth on top of Fedora's all-redhat.js (ships intl.locale.
# matchOS=true + intl.locale.requested=""). System-pref-files are read
# BEFORE autoconfig.cfg by the TB pref-system, so locale-resolution is
# reliable. References: Mozilla Bug 1423532 + Debian Bug #997841.
# Two write-targets, both Mozilla-conventional: the RPM-tree file (survives
# RPM upgrade — filename is RPM-untracked and namespaced for NoID Privacy) + the
# /etc/thunderbird/pref/ sysadmin mirror (TB reads both automatically).
log "STEP 4b: Deploy noid-locale.js system-pref-files"

NOID_LOCALE_CANDIDATE=$(mktemp /var/tmp/noid-thunderbird-locale.XXXXXXXX)
cat > "$NOID_LOCALE_CANDIDATE" <<'NOID_LOCALE_JS_EOF'
// NoID Privacy Workstation 44 — system-locale flow-through (defense-in-depth)
// Empty intl.locale.requested triggers TB to read $LANG via libc setlocale.
// Reference: Mozilla Bug 1423532 + Debian Bug #997841.
// MUST be in system-pref-file (NOT user.js or mozilla.cfg) — TB Init-timing
// reads system-prefs BEFORE autoconfig.cfg, so empty here lets locale-init
// fall back to OS locale via gnu_get_libc_version() / setlocale().
// No JS, no sandbox-bypass, no env-var access from JS context.
pref("intl.locale.requested", "");
pref("intl.regional_prefs.use_os_locales", true);
NOID_LOCALE_JS_EOF
publish_root_file "$NOID_LOCALE_CANDIDATE" \
    "$TB_DEFAULTS_PREF_DIR/noid-locale.js" 0644

# Mirror in /etc/thunderbird/pref/ (sysadmin-override path)
ensure_root_dir /etc/thunderbird/pref 0755
publish_root_file "$NOID_LOCALE_CANDIDATE" \
    /etc/thunderbird/pref/noid-locale.js 0644

# Cache copy in /usr/share/noid-thunderbird/ for Module 25 re-deploy after RPM upgrade
publish_root_file "$NOID_LOCALE_CANDIDATE" "$SHARE_DIR/noid-locale.js" 0644
rm -f -- "$NOID_LOCALE_CANDIDATE"
NOID_LOCALE_CANDIDATE=

log "  noid-locale.js deployed to defaults/pref + /etc/thunderbird/pref + cache"

# ----------------------------------------------------------------------------
# STEP 4c: minimal policies.json (default search only)
# ----------------------------------------------------------------------------
# SearchEngines sets DuckDuckGo as the built-in default. DKIM Verifier keeps its
# provider-neutral JSDNS default, which reads the active OS/VPN resolver instead
# of bypassing it with a separately forced public DoH provider.
# CRITICAL: dir-permissions MUST be 755 — at 750 the TB process cannot open
# the dir and policies.json is silently ignored (verified: the DDG
# default only took effect after chmod 755).
log "STEP 4c: Deploy minimal Thunderbird policy (DuckDuckGo)"

ensure_root_dir /etc/thunderbird/policies 0755

POLICIES_CANDIDATE=$(mktemp /var/tmp/noid-thunderbird-policies.XXXXXXXX)
cat > "$POLICIES_CANDIDATE" <<'POLICIES_JSON_EOF'
{
  "policies": {
    "SearchEngines": {
      "Default": "DuckDuckGo"
    }
  }
}
POLICIES_JSON_EOF
if ! python3 -m json.tool "$POLICIES_CANDIDATE" >/dev/null; then
    fail "candidate Thunderbird policy is invalid JSON"
fi
publish_root_file "$POLICIES_CANDIDATE" \
    /etc/thunderbird/policies/policies.json 0644

# Mirror in /usr/lib64/thunderbird/distribution/policies.json (Mozilla-distribution path)
ensure_root_dir /usr/lib64/thunderbird/distribution 0755
publish_root_file "$POLICIES_CANDIDATE" \
    /usr/lib64/thunderbird/distribution/policies.json 0644

# Cache copy in /usr/share/noid-thunderbird/ for Module 25 re-deploy
publish_root_file "$POLICIES_CANDIDATE" "$SHARE_DIR/policies.json" 0644
rm -f -- "$POLICIES_CANDIDATE"
POLICIES_CANDIDATE=

log "  policies.json deployed (DuckDuckGo only, dir mode 755)"

# ----------------------------------------------------------------------------
# STEP 5: /etc/skel/.thunderbird/ profile template (default-release Profile)
# ----------------------------------------------------------------------------
# When a user is created (e.g. by GIS in firstboot), /etc/skel/ contents are
# copied to $HOME. This seeds the user's first Thunderbird profile with the
# NoID Privacy-hardened user.js immediately (no manual hardening step required).
log "STEP 5: Deploy /etc/skel/.thunderbird/ profile template"
ensure_root_dir "$TB_SKEL_DIR" 0700
ensure_root_dir "$TB_SKEL_PROFILE_DIR" 0700

PROFILES_INI_CANDIDATE=$(mktemp /var/tmp/noid-thunderbird-profiles.XXXXXXXX)
cat > "$PROFILES_INI_CANDIDATE" <<'PROFILES_INI_EOF'
[General]
StartWithLastProfile=1
Version=2

[Profile0]
Name=default-release
IsRelative=1
Path=default-release
Default=1
PROFILES_INI_EOF
publish_root_file "$PROFILES_INI_CANDIDATE" "$SHARE_DIR/profiles.ini" 0644
publish_root_file "$SHARE_DIR/profiles.ini" "$TB_SKEL_DIR/profiles.ini" 0644
rm -f -- "$PROFILES_INI_CANDIDATE"
PROFILES_INI_CANDIDATE=

# user.js for the default-release profile (copy from /usr/share)
publish_root_file "$SHARE_DIR/user.js" "$TB_SKEL_PROFILE_DIR/user.js" 0600
log "  /etc/skel/.thunderbird/ canonical profile template deployed"

# ----------------------------------------------------------------------------
# STEP 6: DKIM Verifier XPI (Layer 4 — bundled, opt-out)
# ----------------------------------------------------------------------------
# Distribution-bundled extensions live in /usr/lib64/thunderbird/distribution/
# extensions/. They are auto-installed when the user creates a new profile.
# User can disable via Tools > Add-ons > DKIM Verifier > Disable.
log "STEP 6: Deploy DKIM Verifier XPI v$DKIM_VERIFIER_VERSION (Layer 4)"
ensure_root_dir "$TB_DISTRIBUTION_EXT_DIR" 0755
ensure_root_dir "$CACHE_DIR" 0755

XPI_TARGET="$TB_DISTRIBUTION_EXT_DIR/${DKIM_VERIFIER_EXT_ID}.xpi"
XPI_CACHE="$CACHE_DIR/dkim_verifier-${DKIM_VERIFIER_VERSION}.xpi"

if [ -e "$XPI_CACHE" ] || [ -L "$XPI_CACHE" ]; then
    [ -f "$XPI_CACHE" ] && [ ! -L "$XPI_CACHE" ] \
        || fail "unsafe DKIM cache object: $XPI_CACHE"
    log "  CACHE HIT: $XPI_CACHE"
else
    log "  FETCHING: $DKIM_VERIFIER_URL"
    XPI_DOWNLOAD=$(mktemp "$CACHE_DIR/.dkim-verifier-download.XXXXXXXX")
    if ! curl --fail --silent --show-error --location \
            --proto '=https' --proto-redir '=https' --tlsv1.2 \
            --retry 3 --retry-delay 2 --max-redirs 3 \
            --output "$XPI_DOWNLOAD" "$DKIM_VERIFIER_URL"; then
        rm -f -- "$XPI_DOWNLOAD"
        XPI_DOWNLOAD=
        fail "curl failed for $DKIM_VERIFIER_URL"
    fi
    verify_sha256 "$XPI_DOWNLOAD" "$DKIM_VERIFIER_SHA256" \
        "downloaded DKIM Verifier XPI v$DKIM_VERIFIER_VERSION"
    publish_root_file "$XPI_DOWNLOAD" "$XPI_CACHE" 0644
    rm -f -- "$XPI_DOWNLOAD"
    XPI_DOWNLOAD=
fi

verify_sha256 "$XPI_CACHE" "$DKIM_VERIFIER_SHA256" \
    "cached DKIM Verifier XPI v$DKIM_VERIFIER_VERSION"
TB_APP_VERSION=$(rpm -q --qf '%{VERSION}' thunderbird)
XPI_VALIDATED_VERSION=$(
    /usr/local/lib/noid-privacy/validate-webextension.py \
        "$XPI_CACHE" "$DKIM_VERIFIER_EXT_ID" "$DKIM_VERIFIER_VERSION" \
        0 "$TB_APP_VERSION" 0 "$SHARE_DIR/dkim-compatibility.json"
) || fail "DKIM Verifier identity/version/compatibility validation failed"
[ "$XPI_VALIDATED_VERSION" = "$DKIM_VERIFIER_VERSION" ] \
    || fail "DKIM Verifier validator returned an unexpected version"
publish_root_file "$XPI_CACHE" "$XPI_TARGET" 0644

# Cache copy in /usr/share for Module 25 re-deploy
publish_root_file "$XPI_CACHE" "$SHARE_DIR/dkim_verifier.xpi" 0644
log "  DKIM Verifier XPI deployed: $XPI_TARGET"

# The helper's fail-closed cache preflight is valid only after every canonical
# AutoConfig/policy/DKIM source exists. This first full run also generates the
# owned launcher/XDG overlay; later runs are transaction-triggered.
/usr/local/sbin/noid-thunderbird-reassert
log "  Thunderbird launcher/XDG overlay + package-tree recovery verified"

# /etc/skel only affects accounts created later. The Live account already
# exists before this module runs, so mirror the complete canonical profile to
# every existing real user that has not initialized Thunderbird. Never replace
# an existing profile tree during composition.
log "  Mirroring canonical Thunderbird profile to pre-existing real users"
for profile_source in "$SHARE_DIR/profiles.ini" "$SHARE_DIR/user.js"; do
    [ -f "$profile_source" ] && [ ! -L "$profile_source" ] && \
    [ "$(readlink -e -- "$profile_source" 2>/dev/null)" = "$profile_source" ] && \
    [ "$(stat -Lc '%u:%g:%a:%h' -- "$profile_source" 2>/dev/null)" = \
        "0:0:644:1" ] || fail "unsafe existing-user profile source: $profile_source"
done
for user_home in /home/*; do
    [ -d "$user_home" ] && [ ! -L "$user_home" ] || continue
    [ "$(readlink -e -- "$user_home" 2>/dev/null)" = "$user_home" ] || continue
    user_name=$(basename "$user_home")
    user_uid=$(id -u "$user_name" 2>/dev/null) || continue
    [ "$user_uid" -ge 1000 ] || continue
    passwd_home=$(getent passwd "$user_name" | awk -F: 'NR == 1 {print $6}')
    [ "$passwd_home" = "$user_home" ] || {
        log "    Skipped non-canonical home mapping: $user_home"
        continue
    }
    [ "$(stat -Lc '%u' -- "$user_home" 2>/dev/null)" = "$user_uid" ] || {
        log "    Skipped home with unexpected owner: $user_home"
        continue
    }
    target_tb="$user_home/.thunderbird"
    if [ ! -e "$target_tb" ] && [ ! -L "$target_tb" ]; then
        if runuser -u "$user_name" -- \
                env HOME="$user_home" TB_PROFILE_SOURCE_DIR="$SHARE_DIR" \
                /usr/bin/bash -s <<'NOID_TB_USER_SEED_EOF'
set -euo pipefail
umask 077
target="$HOME/.thunderbird"
[ ! -e "$target" ] && [ ! -L "$target" ] || exit 3
temporary=$(mktemp -d "$HOME/.noid-thunderbird-seed.XXXXXXXX")
cleanup() {
    if [ -n "${temporary:-}" ]; then
        rm -rf -- "$temporary"
    fi
    return 0
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -m 0700 -- "$temporary/default-release"
cp -- "$TB_PROFILE_SOURCE_DIR/profiles.ini" "$temporary/profiles.ini"
cp -- "$TB_PROFILE_SOURCE_DIR/user.js" \
    "$temporary/default-release/user.js"
if find "$temporary" -type l -print -quit | grep -q .; then
    exit 4
fi
chmod 0700 "$temporary" "$temporary/default-release"
chmod 0644 "$temporary/profiles.ini"
chmod 0600 "$temporary/default-release/user.js"
sync -- "$temporary/profiles.ini" \
    "$temporary/default-release/user.js" \
    "$temporary/default-release" "$temporary"
trap '' HUP INT TERM
if ! mv -T --update=none-fail -- "$temporary" "$target"; then
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if [ -e "$target" ] || [ -L "$target" ]; then
        exit 3
    fi
    exit 4
fi
temporary=""
sync -- "$HOME"
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
NOID_TB_USER_SEED_EOF
        then
            log "    Mirrored canonical profile to $user_home as $user_name"
        else
            seed_status=$?
            if [ "$seed_status" -eq 3 ]; then
                log "    Preserved Thunderbird tree created concurrently in $user_home"
            else
                fail "cannot mirror canonical Thunderbird profile to $user_home"
            fi
        fi
    else
        log "    Preserved existing Thunderbird tree in $user_home"
    fi
done

# ----------------------------------------------------------------------------
# STEP 7: Profile-harden CLI (for migration scenarios + multi-profile users)
# ----------------------------------------------------------------------------
log "STEP 7: Install /usr/local/bin/noid-thunderbird-harden-profile"
HARDEN_PROFILE_CANDIDATE=$(mktemp \
    /var/tmp/noid-thunderbird-harden-profile.XXXXXXXX)
cat > "$HARDEN_PROFILE_CANDIDATE" <<'HARDEN_PROFILE_SH_EOF'
#!/usr/bin/bash
# noid-thunderbird-harden-profile — apply NoID Privacy user.js to a registered Thunderbird profile.
# Usage:
#   noid-thunderbird-harden-profile <profile-name>       Apply to one registered profile
#   noid-thunderbird-harden-profile --all                Apply to all registered profiles
#   noid-thunderbird-harden-profile --automatic          Reapply NoID Privacy-managed profiles and initialize new ones
#   noid-thunderbird-harden-profile --remove <name|--all>  Remove NoID Privacy user.js
#
# The script copies /usr/share/noid-thunderbird/user.js into the profile.
# A differing pre-existing user.js is backed up to a collision-safe timestamped
# file. Reapplying the exact canonical bytes is a no-op.
# `--automatic` is the updater-safe mode: an absent user.js authorizes first
# application and an existing NoID Privacy marker authorizes canonical refresh. A
# foreign user.js is reported but left untouched.
# Existing prefs.js is not edited, but an applied user.js can reset the same
# pref on the next startup. Remove or edit that user.js for a durable override.

set -euo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

ATOMIC_TEMP=
BACKUP_TEMP=
OPT_OUT_TEMP=
BACKUP_RESULT=
cleanup_profile_helper() {
    local saved_rc=$? temporary cleanup_failed=0
    trap - EXIT
    trap '' HUP INT TERM
    for temporary in \
        "${ATOMIC_TEMP:-}" "${BACKUP_TEMP:-}" "${OPT_OUT_TEMP:-}"; do
        [ -n "$temporary" ] || continue
        rm -f -- "$temporary" || cleanup_failed=1
    done
    if [ "$saved_rc" -eq 0 ] && [ "$cleanup_failed" -ne 0 ]; then
        printf 'ERROR: failed to retire a staged profile file\n' >&2
        exit 1
    fi
    return "$saved_rc"
}
trap cleanup_profile_helper EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — Thunderbird" \
    NOID_FMT_AUTO_SUBTITLE="Profile hardening" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

action="apply"
target=""
selection="single"
case "$#:${1:-}:${2:-}" in
    1:-h:|1:--help:)
        sed -n '2,11p' "$0" | sed 's/^# \?//'
        exit 0
        ;;
    1:--all:) selection="all" ;;
    1:--automatic:) selection="automatic" ;;
    1:--*:*) echo "ERROR: unknown or incomplete option" >&2; exit 2 ;;
    1:*:) target="$1" ;;
    2:--remove:--all) action="remove"; selection="all" ;;
    2:--remove:--automatic) echo "ERROR: --automatic is apply-only" >&2; exit 2 ;;
    2:--remove:*) action="remove"; target="$2" ;;
    *) echo "ERROR: use <profile-name>, --all, --automatic, or --remove <profile-name|--all>" >&2; exit 2 ;;
esac

NOID_USERJS="/usr/share/noid-thunderbird/user.js"
NOID_MARKER_REGEX='^user_pref\("_noid\.thunderbird\.hardening\.version",'
OPT_OUT_BASENAME=".noid-thunderbird-hardening-disabled"
OPT_OUT_CONTENT="NOID_THUNDERBIRD_HARDENING_DISABLED_V1"
[ "$(id -u)" -ne 0 ] || { echo "ERROR: run as the normal desktop user, never through sudo" >&2; exit 1; }
[ -f "$NOID_USERJS" ] && [ ! -L "$NOID_USERJS" ] || {
    echo "ERROR: $NOID_USERJS missing, non-regular or symlinked" >&2
    exit 2
}
if ! { [ "$(readlink -e -- "$NOID_USERJS" 2>/dev/null)" = "$NOID_USERJS" ] \
       && [ "$(stat -Lc '%u:%g:%a:%h' -- "$NOID_USERJS" 2>/dev/null)" = \
            "0:0:644:1" ] \
       && matchpathcon -V "$NOID_USERJS" >/dev/null; }; then
    echo "ERROR: $NOID_USERJS failed its root-owned canonical-file contract" >&2
    exit 2
fi
grep -qE -- "$NOID_MARKER_REGEX" "$NOID_USERJS" || {
    echo "ERROR: $NOID_USERJS lacks the NoID Privacy ownership marker" >&2
    exit 2
}

PASSWD_HOME=$(getent passwd "$(id -u)" | awk -F: 'NR == 1 {print $6}')
[ "$HOME" = "$PASSWD_HOME" ] && [ -d "$HOME" ] && [ ! -L "$HOME" ] && \
[ "$(readlink -e -- "$HOME" 2>/dev/null)" = "$HOME" ] || {
    echo "ERROR: HOME does not match the canonical account home" >&2
    exit 1
}
HOME_METADATA=$(stat -Lc '%u:%a' -- "$HOME" 2>/dev/null) || exit 1
[ "${HOME_METADATA%%:*}" = "$(id -u)" ] && \
[ $((8#${HOME_METADATA#*:} & 8#022)) -eq 0 ] || {
    echo "ERROR: unsafe HOME owner or permissions" >&2
    exit 1
}

TB_ROOT="$HOME/.thunderbird"
if [ -z "${XDG_STATE_HOME:-}" ]; then
    for state_component in "$HOME/.local" "$HOME/.local/state"; do
        [ ! -L "$state_component" ] || {
            echo "ERROR: symlinked default state path" >&2
            exit 1
        }
        if [ ! -e "$state_component" ]; then
            mkdir -m 0700 -- "$state_component"
        fi
        [ -d "$state_component" ] && \
        [ "$(readlink -e -- "$state_component" 2>/dev/null)" = \
            "$state_component" ] || {
            echo "ERROR: unsafe default state path" >&2
            exit 1
        }
        chmod 0700 "$state_component"
    done
    STATE_BASE="$HOME/.local/state"
else
    STATE_BASE="$XDG_STATE_HOME"
fi
case "$STATE_BASE" in
    /*) ;;
    *) echo "ERROR: state directory must be absolute" >&2; exit 1 ;;
esac
[ -d "$STATE_BASE" ] && [ ! -L "$STATE_BASE" ] && \
[ "$(readlink -e -- "$STATE_BASE" 2>/dev/null)" = "$STATE_BASE" ] || {
    echo "ERROR: unsafe state base directory" >&2
    exit 1
}
STATE_BASE_METADATA=$(stat -Lc '%u:%a' -- "$STATE_BASE" 2>/dev/null) || exit 1
[ "${STATE_BASE_METADATA%%:*}" = "$(id -u)" ] && \
[ $((8#${STATE_BASE_METADATA#*:} & 8#022)) -eq 0 ] || {
    echo "ERROR: unsafe state base owner or permissions" >&2
    exit 1
}
STATE_DIR="$STATE_BASE/noid-privacy"
[ ! -L "$STATE_DIR" ] || { echo "ERROR: unsafe state directory" >&2; exit 1; }
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
[ "$(readlink -e -- "$STATE_DIR" 2>/dev/null)" = "$STATE_DIR" ] && \
[ "$(stat -Lc '%u:%a' -- "$STATE_DIR" 2>/dev/null)" = "$(id -u):700" ] || {
    echo "ERROR: unsafe state directory metadata" >&2
    exit 1
}

# A failed process query is not evidence that Thunderbird has exited. Only
# successful no-match queries or positively observed dead tasks permit writes.
# A task exiting between pgrep and ps can cause a retry instead of a mutation.
thunderbird_process_active() {
    local process_name pid state process_uid candidates query_rc
    if ! process_uid=$(id -u) || [[ ! "$process_uid" =~ ^[0-9]+$ ]]; then
        echo "ERROR: cannot determine Thunderbird process owner; refusing profile changes" >&2
        return 0
    fi
    for process_name in thunderbird thunderbird-bin; do
        if candidates=$(pgrep -u "$process_uid" -x "$process_name" 2>/dev/null); then
            if [ -z "$candidates" ]; then
                echo "ERROR: empty successful Thunderbird process query; refusing profile changes" >&2
                return 0
            fi
        else
            query_rc=$?
            if [ "$query_rc" -eq 1 ] && [ -z "$candidates" ]; then
                continue
            fi
            echo "ERROR: Thunderbird process query failed; refusing profile changes" >&2
            return 0
        fi
        while IFS= read -r pid; do
            if [[ ! "$pid" =~ ^[1-9][0-9]*$ ]]; then
                echo "ERROR: invalid Thunderbird process evidence; refusing profile changes" >&2
                return 0
            fi
            if ! state=$(ps -o state= -p "$pid" 2>/dev/null); then
                echo "ERROR: Thunderbird process state query failed; refusing profile changes" >&2
                return 0
            fi
            # state= has one state character and optional horizontal padding.
            # Empty, malformed or multi-record results cannot prove inactivity.
            if [[ ! "$state" =~ ^[[:blank:]]*[ZXx][[:blank:]]*$ ]]; then
                return 0
            fi
        done <<< "$candidates"
    done
    return 1
}

if thunderbird_process_active; then
    echo "ERROR: Thunderbird must be closed and its process state verifiable before changing profile files" >&2
    exit 75
fi
LOCK_FILE="$STATE_DIR/thunderbird-profile-operations.lock"
[ ! -L "$LOCK_FILE" ] || { echo "ERROR: unsafe lock path" >&2; exit 1; }
exec 9>"$LOCK_FILE"
chmod 0600 "$LOCK_FILE"
[ -f "$LOCK_FILE" ] && [ ! -L "$LOCK_FILE" ] && \
[ "$(stat -Lc '%u:%a:%h' -- "$LOCK_FILE" 2>/dev/null)" = \
    "$(id -u):600:1" ] || {
    echo "ERROR: unsafe lock-file metadata" >&2
    exit 1
}
flock -n 9 || { echo "ERROR: another Thunderbird profile operation is active" >&2; exit 75; }
if thunderbird_process_active; then
    echo "ERROR: Thunderbird must be closed and its process state verifiable before changing profile files" >&2
    exit 75
fi

atomic_install() {
    local source="$1" destination="$2" mode="$3" parent
    parent=$(dirname "$destination")
    [ -f "$source" ] && [ ! -L "$source" ] || return 1
    [ -d "$parent" ] && [ ! -L "$parent" ] || return 1
    [ ! -L "$destination" ] || return 1
    if [ -e "$destination" ] && [ ! -f "$destination" ]; then return 1; fi
    ATOMIC_TEMP=$(mktemp "$parent/.$(basename "$destination").tmp.XXXXXXXX") \
        || return 1
    if ! install -m "$mode" -- "$source" "$ATOMIC_TEMP" || \
       ! sync -- "$ATOMIC_TEMP"; then
        rm -f -- "$ATOMIC_TEMP"
        ATOMIC_TEMP=
        return 1
    fi
    trap '' HUP INT TERM
    if ! mv -fT -- "$ATOMIC_TEMP" "$destination"; then
        rm -f -- "$ATOMIC_TEMP"
        ATOMIC_TEMP=
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        return 1
    fi
    ATOMIC_TEMP=
    if ! { [ -f "$destination" ] && [ ! -L "$destination" ] \
           && cmp -s -- "$source" "$destination" \
           && [ "$(stat -Lc '%u:%a:%h' -- "$destination" 2>/dev/null)" = \
                "$(id -u):${mode#0}:1" ] \
           && sync -- "$destination" && sync -- "$parent"; }; then
        rm -f -- "$destination" || true
        sync -- "$parent" >/dev/null 2>&1 || true
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        return 1
    fi
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
}

backup_userjs() {
    local source="$1"
    BACKUP_RESULT=
    [ -f "$source" ] && [ ! -L "$source" ] || return 1
    BACKUP_TEMP=$(mktemp \
        "$(dirname "$source")/user.js.bak-noid-$(date -u +%Y%m%dT%H%M%S)-XXXXXXXX") \
        || return 1
    if ! cp --preserve=timestamps -- "$source" "$BACKUP_TEMP" || \
       ! chmod 0600 "$BACKUP_TEMP" || \
       ! sync -- "$BACKUP_TEMP"; then
        rm -f -- "$BACKUP_TEMP"
        BACKUP_TEMP=
        return 1
    fi
    [ -f "$BACKUP_TEMP" ] && [ ! -L "$BACKUP_TEMP" ] && \
    [ "$(stat -Lc '%u:%a:%h' -- "$BACKUP_TEMP" 2>/dev/null)" = \
        "$(id -u):600:1" ] || {
        rm -f -- "$BACKUP_TEMP"
        BACKUP_TEMP=
        return 1
    }
    BACKUP_RESULT=$BACKUP_TEMP
    BACKUP_TEMP=
}

discover_profiles() {
    local discovery_mode=${1:-strict}
    python3 - "$TB_ROOT" "$discovery_mode" <<'TB_PROFILE_LIST_PYEOF'
import configparser
import os
import re
import stat
import sys

root = sys.argv[1]
automatic = sys.argv[2] == "automatic"
uid = os.geteuid()
if not os.path.isabs(root) or os.path.normpath(root) != root:
    raise SystemExit("unsafe Thunderbird root")
try:
    root_stat = os.lstat(root)
except FileNotFoundError:
    if automatic:
        raise SystemExit(0)
    raise SystemExit("Thunderbird root does not exist")
if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
    raise SystemExit("Thunderbird root is not a regular directory")
if root_stat.st_uid != uid or root_stat.st_mode & 0o022:
    raise SystemExit("Thunderbird root ownership/mode is unsafe")
ini = os.path.join(root, "profiles.ini")
try:
    ini_stat = os.lstat(ini)
except FileNotFoundError:
    if automatic:
        raise SystemExit(0)
    raise SystemExit("profiles.ini does not exist")
if not stat.S_ISREG(ini_stat.st_mode) or stat.S_ISLNK(ini_stat.st_mode):
    raise SystemExit("profiles.ini is not regular")
if ini_stat.st_uid != uid or ini_stat.st_mode & 0o022:
    raise SystemExit("profiles.ini ownership/mode is unsafe")
parser = configparser.ConfigParser(strict=True, interpolation=None)
parser.optionxform = str
with open(ini, encoding="utf-8") as handle:
    parser.read_file(handle)
seen_names = set()
seen_paths = set()
for section in parser.sections():
    if not re.fullmatch(r"Profile[0-9]+", section):
        continue
    name = parser.get(section, "Name", fallback="")
    path = parser.get(section, "Path", fallback="")
    relative = parser.get(section, "IsRelative", fallback="")
    if relative == "0" and automatic:
        continue
    if relative != "1":
        raise SystemExit(f"{section}: external/absolute profile is outside NoID Privacy management")
    if not name or any(ch in name for ch in "\t\r\n") or name in seen_names:
        raise SystemExit(f"{section}: invalid/duplicate name")
    if (not path or os.path.isabs(path) or any(ch in path for ch in "\t\r\n")
            or os.path.normpath(path) != path or ".." in path.split(os.sep)
            or path in seen_paths):
        raise SystemExit(f"{section}: unsafe/duplicate path")
    candidate = os.path.join(root, path)
    current = root
    for component in path.split(os.sep):
        current = os.path.join(current, component)
        try:
            component_stat = os.lstat(current)
        except FileNotFoundError:
            raise SystemExit(f"{section}: profile path does not exist")
        if stat.S_ISLNK(component_stat.st_mode):
            raise SystemExit(f"{section}: symlinked path component")
    profile_stat = os.lstat(candidate)
    if not stat.S_ISDIR(profile_stat.st_mode) or profile_stat.st_uid != uid or profile_stat.st_mode & 0o022:
        raise SystemExit(f"{section}: unsafe profile directory")
    seen_names.add(name)
    seen_paths.add(path)
    print(f"{name}\t{candidate}")
TB_PROFILE_LIST_PYEOF
}

resolve_profile() {
    local wanted="$1" records name path match=""
    records=$(discover_profiles) || return 1
    while IFS=$'\t' read -r name path; do
        [ "$name" = "$wanted" ] || continue
        [ -z "$match" ] || return 1
        match="$path"
    done <<< "$records"
    [ -n "$match" ] || return 1
    printf '%s\n' "$match"
}

CHANGES=0

profile_is_opted_out() {
    local profile="$1" marker metadata
    marker="$profile/$OPT_OUT_BASENAME"
    [ ! -L "$marker" ] || return 2
    if [ ! -e "$marker" ]; then
        return 1
    fi
    [ -f "$marker" ] || return 2
    metadata=$(stat -Lc '%u:%a:%h' -- "$marker" 2>/dev/null) || return 2
    [ "$metadata" = "$(id -u):600:1" ] || return 2
    cmp -s -- "$marker" <(printf '%s\n' "$OPT_OUT_CONTENT") || return 2
}

clear_profile_opt_out() {
    local profile="$1" marker
    marker="$profile/$OPT_OUT_BASENAME"
    [ ! -L "$marker" ] || return 1
    if [ ! -e "$marker" ]; then
        return 0
    fi
    profile_is_opted_out "$profile" || return 1
    rm -f -- "$marker" && sync -- "$profile"
}

publish_profile_opt_out() {
    local profile="$1" marker
    marker="$profile/$OPT_OUT_BASENAME"
    [ ! -L "$marker" ] || return 1
    if [ -e "$marker" ]; then
        profile_is_opted_out "$profile"
        return
    fi
    OPT_OUT_TEMP=$(mktemp "$profile/.noid-thunderbird-opt-out.XXXXXXXX") \
        || return 1
    if ! printf '%s\n' "$OPT_OUT_CONTENT" > "$OPT_OUT_TEMP" || \
       ! chmod 0600 "$OPT_OUT_TEMP" || \
       ! atomic_install "$OPT_OUT_TEMP" "$marker" 600; then
        rm -f -- "$OPT_OUT_TEMP"
        OPT_OUT_TEMP=
        return 1
    fi
    rm -f -- "$OPT_OUT_TEMP" || return 1
    OPT_OUT_TEMP=
}

profile_is_automatic_eligible() {
    local profile="$1" destination grep_rc opt_out_rc
    destination="$profile/user.js"
    if profile_is_opted_out "$profile"; then
        return 1
    else
        opt_out_rc=$?
    fi
    [ "$opt_out_rc" -eq 1 ] || return 2
    [ ! -L "$destination" ] || return 2
    if [ ! -e "$destination" ]; then
        return 0
    fi
    [ -f "$destination" ] || return 2
    if grep -qE -- "$NOID_MARKER_REGEX" "$destination"; then
        return 0
    else
        grep_rc=$?
    fi
    [ "$grep_rc" -eq 1 ] && return 1
    return 2
}

apply_to_profile() {
    local profile="$1" destination backup="" metadata
    [ -d "$profile" ] && [ ! -L "$profile" ] || return 1
    destination="$profile/user.js"
    [ ! -L "$destination" ] || return 1
    if [ -e "$destination" ] && [ ! -f "$destination" ]; then return 1; fi
    if [ -f "$destination" ] && cmp -s -- "$NOID_USERJS" "$destination"; then
        metadata=$(stat -Lc '%u:%a:%h' -- "$destination" 2>/dev/null) \
            || return 1
        if [ "$metadata" = "$(id -u):600:1" ]; then
            clear_profile_opt_out "$profile" || return 1
            echo "  NoID Privacy user.js already applied to $profile"
            return 0
        fi
        atomic_install "$NOID_USERJS" "$destination" 600 || return 1
        clear_profile_opt_out "$profile" || return 1
        CHANGES=$((CHANGES + 1))
        echo "  Repaired NoID Privacy user.js metadata in $profile"
        return 0
    fi
    if [ -f "$destination" ]; then
        backup_userjs "$destination" || return 1
        backup=$BACKUP_RESULT
        echo "  Backed up existing user.js -> $(basename "$backup")"
    fi
    atomic_install "$NOID_USERJS" "$destination" 600 || return 1
    clear_profile_opt_out "$profile" || return 1
    CHANGES=$((CHANGES + 1))
    echo "  Applied NoID Privacy user.js to $profile"
}

remove_from_profile() {
    local profile="$1" destination backup grep_rc
    [ -d "$profile" ] && [ ! -L "$profile" ] || return 1
    destination="$profile/user.js"
    [ ! -L "$destination" ] || return 1
    if [ -e "$destination" ] && [ ! -f "$destination" ]; then return 1; fi
    if [ -f "$destination" ]; then
        if grep -qE -- "$NOID_MARKER_REGEX" "$destination"; then
            backup_userjs "$destination" || return 1
            backup=$BACKUP_RESULT
            publish_profile_opt_out "$profile" || return 1
            rm -f -- "$destination"
            sync -- "$profile"
            echo "  Removed NoID Privacy user.js from $profile (backup: $(basename "$backup"))"
            return 0
        else
            grep_rc=$?
        fi
        [ "$grep_rc" -eq 1 ] || return 1
        publish_profile_opt_out "$profile" || return 1
        echo "  Preserved foreign user.js and disabled automatic NoID Privacy hardening for $profile"
    else
        publish_profile_opt_out "$profile" || return 1
        echo "  Disabled automatic NoID Privacy hardening for $profile"
    fi
}

PROFILE_RECORDS=$(discover_profiles "$selection") || exit 1

if [ "$selection" = "automatic" ]; then
    failures=0
    eligible_count=0
    protected_count=0
    while IFS=$'\t' read -r name profile; do
        [ -n "$name" ] || continue
        if profile_is_automatic_eligible "$profile"; then
            eligible_count=$((eligible_count + 1))
            apply_to_profile "$profile" || failures=$((failures + 1))
        else
            eligible_rc=$?
            if [ "$eligible_rc" -eq 1 ]; then
                protected_count=$((protected_count + 1))
                echo "  Preserved foreign user.js in registered profile: $name"
            else
                echo "ERROR: unsafe or unreadable user.js in registered profile: $name" >&2
                failures=$((failures + 1))
            fi
        fi
    done <<< "$PROFILE_RECORDS"
    [ "$failures" -eq 0 ] || exit 1
    printf 'NOID_RESULT eligible=%d changed=%d protected=%d\n' \
        "$eligible_count" "$CHANGES" "$protected_count"
elif [ "$selection" = "all" ]; then
    failures=0
    while IFS=$'\t' read -r name profile; do
        [ -n "$name" ] || continue
        if [ "$action" = "apply" ]; then
            apply_to_profile "$profile" || failures=$((failures + 1))
        else
            remove_from_profile "$profile" || failures=$((failures + 1))
        fi
    done <<< "$PROFILE_RECORDS"
    [ "$failures" -eq 0 ] || exit 1
else
    profile=$(resolve_profile "$target") || {
        echo "ERROR: registered profile name not found or unsafe: $target" >&2
        exit 1
    }
    if [ "$action" = "apply" ]; then apply_to_profile "$profile"
    else remove_from_profile "$profile"; fi
fi

echo "Done."
HARDEN_PROFILE_SH_EOF
if ! bash -n "$HARDEN_PROFILE_CANDIDATE"; then
    fail "noid-thunderbird-harden-profile syntax error"
fi
# Check the boolean process guard before publishing the profile-writing CLI.
if ! bash -s -- "$HARDEN_PROFILE_CANDIDATE" <<'TB_PROCESS_GUARD_CHECK_EOF'
set -euo pipefail
guard=$(sed -n '/^thunderbird_process_active() {$/,/^}$/p' "$1")
[ -n "$guard" ] || exit 1
# The candidate is this module's own syntax-checked shell payload. Evaluate
# only its process guard, with local producers; never run the profile helper.
eval "$guard"
pgrep() { return 1; }
if thunderbird_process_active >/dev/null 2>&1; then exit 1; fi
pgrep() { return 2; }
thunderbird_process_active >/dev/null 2>&1 || exit 1
pgrep() { printf '%s\n' "$$"; }
ps() { printf '%s\n' Z; return 1; }
thunderbird_process_active >/dev/null 2>&1 || exit 1
ps() { printf '%s\n' Z; }
if thunderbird_process_active >/dev/null 2>&1; then exit 1; fi
TB_PROCESS_GUARD_CHECK_EOF
then
    fail "Thunderbird profile process guard failed its query-error contract"
fi
ensure_root_dir /usr/local/bin 0755
publish_root_file "$HARDEN_PROFILE_CANDIDATE" \
    /usr/local/bin/noid-thunderbird-harden-profile 0755
rm -f -- "$HARDEN_PROFILE_CANDIDATE"
HARDEN_PROFILE_CANDIDATE=
log "  noid-thunderbird-harden-profile installed"

# ----------------------------------------------------------------------------
# STEP 7c: Install the canonical Thunderbird smartcard guide
# ----------------------------------------------------------------------------
log "STEP 7c: Install Thunderbird smartcard guide"
ensure_root_dir /usr/share/doc/noid-privacy 0755
# Generated from docs/35-thunderbird-smartcard.md by
# scripts/regen-thunderbird-smartcard-doc.sh.
# Shipped Markdown target: /usr/share/doc/noid-privacy/35-thunderbird-smartcard.md
# Shipped Markdown heredoc: NOID_TB_SMARTCARD_DOC_EOF
SMARTCARD_DOC_CANDIDATE=$(mktemp /var/tmp/noid-thunderbird-smartcard.XXXXXXXX)
cat > "$SMARTCARD_DOC_CANDIDATE" <<'NOID_TB_SMARTCARD_DOC_EOF'
# Thunderbird + YubiKey / OpenPGP Smartcard

NoID Privacy ships Thunderbird with `mail.openpgp.allow_external_gnupg=true`.
This enables Thunderbird's **experimental** external-GnuPG path for secret-key
operations: GnuPG can sign and decrypt with a secret key on a hardware token
(YubiKey 5, OpenPGP smartcard, Nitrokey). Thunderbird still uses its internal
RNP implementation for public-key encryption, signature verification,
public-key storage and trust decisions.

This preference only exposes the integration. It does not prove that a given
Thunderbird, GPGME, token and reader combination works. Verify signing and
decryption after installation and after major Thunderbird/GnuPG updates.

## Install Smartcard Stack

NoID Privacy ships GnuPG for repository verification, but the complete smartcard stack
is not a guaranteed image component and PC/SC is masked by default. Install the
packages, then explicitly unmask the socket-activated service:

```bash
sudo dnf install gnupg2 pcsc-lite pcsc-lite-ccid opensc
sudo systemctl unmask pcscd.socket pcscd.service
sudo systemctl enable --now pcscd.socket
systemctl is-active pcscd.socket
```

`pcscd` is the PC/SC daemon that talks to USB smartcards.
Enabling it adds a local PC/SC socket plus the daemon/reader/parser surface.
Fedora governs access through polkit, and this is not a network listener, but it
is still an intentional local attack-surface and privacy trade-off that should
remain enabled only while smartcard access is wanted.

To return to the NoID Privacy default:

```bash
sudo systemctl disable --now pcscd.socket
sudo systemctl stop pcscd.service
sudo systemctl mask pcscd.socket pcscd.service
systemctl is-enabled pcscd.socket pcscd.service
```

Both units should report `masked`; smartcard access through PC/SC then stops.

## Verify Smartcard Detection

Insert your YubiKey/smartcard, then:

```bash
gpg --card-status
```

You should see:

```
Reader ...........: <your reviewed reader>
Application ID ...: <redacted>
Version ..........: <device value>
Manufacturer .....: <device value>
Serial number ....: <redacted>
Name of cardholder: <redacted>
...
Signature key ....: ABCD 1234 ...
Encryption key ...: EF01 5678 ...
Authentication key: 9876 ABCD ...
```

If no output: check `journalctl -u pcscd` for permissions or detection errors.

## Configure Thunderbird

In Thunderbird:

1. Tools → OpenPGP Key Manager
2. File → Import Public Keys from File (or Server Key Search)
3. Import your **public key** (signing + encryption pubkey from your card)

For sending:

4. Tools → Account Settings → End-to-End Encryption
5. Select "Use external key configured in GnuPG" (NoID Privacy default `mail.openpgp.allow_external_gnupg=true` enables this option)
6. Enter the exact **16-character primary key ID** (the last 16 characters of
   the primary-key fingerprint), as required by Thunderbird. The field is not
   a full-fingerprint verifier, so compare the value carefully.

## Send Encrypted/Signed Mail

When composing:

- **Encrypt** = Thunderbird's internal RNP implementation encrypts with the
  recipients' imported public keys and also encrypts a copy to your configured
  public key; this is not a secret-key operation on the card.
- **Sign** = GnuPG can ask the card to perform the signing operation. The
  signing secret stays on the token when that is where GnuPG stores it.
- **Decrypt** = GnuPG can ask the card to decrypt messages addressed to its
  secret key.
- A PIN prompt depends on the token, reader, pinentry and agent-cache policy;
  it is not guaranteed for every operation.

## OpenPGP Pref Reference

| Pref | NoID Privacy Value | Reason |
|------|-----------|--------|
| `mail.openpgp.allow_external_gnupg` | `true` | Hardware-token secret-key operations through GnuPG/GPGME |
| `mail.openpgp.separate_mime_layers` | `true` | RFC 3156 PGP/MIME interoperability |

NoID Privacy leaves `mail.openpgp.load_untested_gpgme_version` unset. It is an escape
hatch for trying an additional GPGME shared-library filename suffix, not a
general compatibility or security switch. Current Thunderbird already probes
the common `.45`, `.11` and unsuffixed library names.

## GnuPG Smartcard-Only Setup

GnuPG 2 uses `gpg-agent` automatically; a `use-agent` line and custom cipher
preferences are not required for Thunderbird smartcard support. If you
deliberately want bounded agent caching, review and set values appropriate for
your token and threat model, for example:

```bash
install -d -m 0700 "$HOME/.gnupg"
${EDITOR:-vi} "$HOME/.gnupg/gpg-agent.conf"
```

Add or replace these keys once in the file:

```text
default-cache-ttl 600
max-cache-ttl 7200
```

Then reload the agent:

```bash
gpg-connect-agent reloadagent /bye
```

These are example GnuPG agent cache limits, but token/reader policy determines
whether a smartcard PIN is actually cached. NoID Privacy does not enforce them.

## Troubleshooting

- **"PIN required"**: use the device's documented user PIN and change any
  factory credential during provisioning; this guide does not publish or
  assume a universal default.
- **"Card not found"**: `pcscd` not running, or `dnf install pcsc-lite-ccid` missing.
- **"Permission denied" on card access**: on Fedora, pcscd access is
  governed by polkit (not a `plugdev` group — that is a Debian-ism).
  Check `journalctl -u polkit -u pcscd` for the denial; an active local
  session is normally sufficient (`org.debian.pcsc-lite.access_pcsc`).
- **"GPGME isn't working"**: confirm that the installed Thunderbird can load
  Fedora's GPGME shared library, then inspect Thunderbird's Error Console.
  Do not guess a `mail.openpgp.load_untested_gpgme_version` suffix: compare the
  installed library filenames with the current Thunderbird loader source and
  test the complete sign/decrypt path.

## See Also

- `docs/35-thunderbird-mail-setup.md` (source tree) — General setup
- Mozilla Smartcards Guide: <https://wiki.mozilla.org/Thunderbird:OpenPGP:Smartcards>
- Thunderbird GPGME loader source: <https://searchfox.org/comm-central/source/mail/extensions/openpgp/content/modules/GPGMELib.sys.mjs>
NOID_TB_SMARTCARD_DOC_EOF
publish_root_file "$SMARTCARD_DOC_CANDIDATE" \
    /usr/share/doc/noid-privacy/35-thunderbird-smartcard.md 0644
rm -f -- "$SMARTCARD_DOC_CANDIDATE"
SMARTCARD_DOC_CANDIDATE=

# ----------------------------------------------------------------------------
# STEP 8: Verify deployment (file-presence + defense-checks) + health stamp
# ----------------------------------------------------------------------------
log "STEP 8: Verify Module 35 deployment"
TB_FAIL=0
for contract in \
    "$TB_INSTALL_DIR/mozilla.cfg|644" \
    "$TB_DEFAULTS_PREF_DIR/autoconfig.js|644" \
    "$TB_DEFAULTS_PREF_DIR/local-settings.js|644" \
    "$TB_DEFAULTS_PREF_DIR/noid-locale.js|644" \
    "$TB_DISTRIBUTION_DIR/policies.json|644" \
    "$TB_SKEL_DIR/profiles.ini|644" \
    "$TB_SKEL_PROFILE_DIR/user.js|600" \
    "$SHARE_DIR/profiles.ini|644" \
    "$XPI_TARGET|644" \
    "$SHARE_DIR/user.js|644" \
    "$SHARE_DIR/mozilla.cfg|644" \
    "$SHARE_DIR/autoconfig.js|644" \
    "$SHARE_DIR/local-settings.js|644" \
    "$SHARE_DIR/noid-locale.js|644" \
    "$SHARE_DIR/policies.json|644" \
    "$SHARE_DIR/dkim_verifier.xpi|644" \
    "$SHARE_DIR/dkim-compatibility.json|644" \
    "/usr/local/lib/noid-privacy/noid-thunderbird-compatibility|755" \
    "/etc/thunderbird/pref/noid-locale.js|644" \
    "/etc/thunderbird/policies/policies.json|644" \
    "/usr/bin/thunderbird|755" \
    "/usr/share/applications/net.thunderbird.Thunderbird.desktop|644" \
    "/usr/local/bin/thunderbird|755" \
    "/usr/local/share/applications/net.thunderbird.Thunderbird.desktop|644" \
    "/usr/local/bin/noid-thunderbird-reassert|755" \
    "/etc/dnf/libdnf5-plugins/actions.d/noid-thunderbird.actions|644" \
    "/usr/local/bin/noid-thunderbird-harden-profile|755" \
    "/usr/share/doc/noid-privacy/35-thunderbird-smartcard.md|644" \
    "$HORLOGESKYNET_LICENSE|644"; do
    f=${contract%%|*}
    expected_mode=${contract#*|}
    if [ -s "$f" ] && [ -f "$f" ] && [ ! -L "$f" ] && \
       [ "$(readlink -e -- "$f" 2>/dev/null)" = "$f" ] && \
       [ "$(stat -Lc '%u:%g:%a:%h' -- "$f" 2>/dev/null)" = \
           "0:0:$expected_mode:1" ]; then
        log "  [OK] $f (root:root $expected_mode, regular, link-count=1)"
    else
        log "  FAIL: unsafe or incorrect file contract: $f"
        TB_FAIL=$((TB_FAIL + 1))
    fi
done
if [ -L /usr/local/sbin ] && \
   [ "$(readlink -- /usr/local/sbin 2>/dev/null)" = bin ] && \
   [ "$(stat -c '%u:%g:%a' -- /usr/local/sbin 2>/dev/null)" = "0:0:777" ] && \
   [ /usr/local/sbin/noid-thunderbird-reassert -ef \
       /usr/local/bin/noid-thunderbird-reassert ]; then
    log "  [OK] Fedora unified-sbin alias resolves to the canonical Thunderbird helper"
else
    log "  FAIL: Fedora unified-sbin alias does not resolve to the canonical Thunderbird helper"
    TB_FAIL=$((TB_FAIL + 1))
fi
if ! grep -qF '](35-thunderbird-smartcard.md)' \
        /usr/share/doc/noid-privacy/post-quantum-readiness.md 2>/dev/null || \
   ! PAGER=true /usr/local/bin/noid-help 35-thunderbird-smartcard \
        >/dev/null 2>&1; then
    log "  FAIL: installed PQ-to-Thunderbird documentation link is not closed"
    TB_FAIL=$((TB_FAIL + 1))
fi

# Exact copy graph: every maintained source copy must remain byte-identical.
for pair in \
    "$SHARE_DIR/profiles.ini|$TB_SKEL_DIR/profiles.ini" \
    "$SHARE_DIR/user.js|$TB_SKEL_PROFILE_DIR/user.js" \
    "$SHARE_DIR/mozilla.cfg|$TB_INSTALL_DIR/mozilla.cfg" \
    "$SHARE_DIR/autoconfig.js|$TB_DEFAULTS_PREF_DIR/autoconfig.js" \
    "$SHARE_DIR/local-settings.js|$TB_DEFAULTS_PREF_DIR/local-settings.js" \
    "$SHARE_DIR/noid-locale.js|$TB_DEFAULTS_PREF_DIR/noid-locale.js" \
    "$SHARE_DIR/noid-locale.js|/etc/thunderbird/pref/noid-locale.js" \
    "$SHARE_DIR/policies.json|/etc/thunderbird/policies/policies.json" \
    "$SHARE_DIR/policies.json|$TB_DISTRIBUTION_DIR/policies.json" \
    "$SHARE_DIR/dkim_verifier.xpi|$XPI_TARGET"; do
    left=${pair%%|*}
    right=${pair#*|}
    if ! cmp -s "$left" "$right"; then
        log "  FAIL: installed Thunderbird copies differ: $left != $right"
        TB_FAIL=$((TB_FAIL + 1))
    fi
done

if ! bash -n /usr/bin/thunderbird 2>/dev/null || \
   ! bash -n /usr/local/bin/thunderbird 2>/dev/null || \
   ! bash -n /usr/local/sbin/noid-thunderbird-reassert 2>/dev/null || \
   ! bash -n /usr/local/bin/noid-thunderbird-harden-profile 2>/dev/null; then
    log "  FAIL: one or more installed Thunderbird shell payloads do not parse"
    TB_FAIL=$((TB_FAIL + 1))
fi
if ! rpm -Vf /usr/bin/thunderbird >/dev/null 2>&1 || \
   ! rpm -Vf /usr/share/applications/net.thunderbird.Thunderbird.desktop >/dev/null 2>&1 || \
   ! grep -qF 'set -- -P default-release "$@"' /usr/local/bin/thunderbird || \
   ! grep -qx 'Exec=/usr/local/bin/thunderbird %u' \
       /usr/local/share/applications/net.thunderbird.Thunderbird.desktop; then
    log "  FAIL: Thunderbird owned-overlay/vendor-pristine profile contract differs"
    TB_FAIL=$((TB_FAIL + 1))
fi
if [ "$(sha256sum "$XPI_TARGET" 2>/dev/null | awk '{print $1}')" != "$DKIM_VERIFIER_SHA256" ]; then
    log "  FAIL: final DKIM Verifier XPI differs from its exact pin"
    TB_FAIL=$((TB_FAIL + 1))
fi
if ! python3 - "$TB_SKEL_DIR/profiles.ini" <<'TB_PROFILE_CONTRACT_PYEOF'
import configparser, sys
parser = configparser.ConfigParser(strict=True, interpolation=None)
parser.optionxform = str
with open(sys.argv[1], encoding="utf-8") as handle:
    parser.read_file(handle)
profiles = [section for section in parser.sections() if section.startswith("Profile")]
assert profiles == ["Profile0"]
assert dict(parser["Profile0"]) == {
    "Name": "default-release",
    "IsRelative": "1",
    "Path": "default-release",
    "Default": "1",
}
TB_PROFILE_CONTRACT_PYEOF
then
    log "  FAIL: Thunderbird skel profiles.ini differs from canonical contract"
    TB_FAIL=$((TB_FAIL + 1))
fi
if ! grep -qx 'pref("general.config.filename", "mozilla.cfg");' \
        "$TB_DEFAULTS_PREF_DIR/autoconfig.js" || \
   ! grep -qx 'pref("general.config.obscure_value", 0);' \
        "$TB_DEFAULTS_PREF_DIR/autoconfig.js" || \
   ! grep -qx 'pref("general.config.sandbox_enabled", true);' \
        "$TB_DEFAULTS_PREF_DIR/autoconfig.js" || \
   ! grep -qx 'pref("general.config.filename", "mozilla.cfg");' \
        "$TB_DEFAULTS_PREF_DIR/local-settings.js"; then
    log "  FAIL: Thunderbird AutoConfig pointer contract differs"
    TB_FAIL=$((TB_FAIL + 1))
fi

# Defense-check 1: policies.json MUST match the audited minimal policy exactly.
if [ ! -f /etc/thunderbird/policies/policies.json ]; then
    log "  FAIL: /etc/thunderbird/policies/policies.json missing"
    TB_FAIL=$((TB_FAIL + 1))
elif ! python3 -c '
import json, sys
data = json.load(open("/etc/thunderbird/policies/policies.json"))
expected = {"policies": {
    "SearchEngines": {"Default": "DuckDuckGo"},
}}
sys.exit(0 if data == expected else 1)
' 2>/dev/null; then
    log "  FAIL: policies.json differs from the audited DuckDuckGo-only policy"
    TB_FAIL=$((TB_FAIL + 1))
fi
# Plus: dir permissions MUST be 755 (750 silently breaks policies.json load)
if [ "$(stat -c '%a' /etc/thunderbird/policies 2>/dev/null)" != "755" ]; then
    log "  FAIL: /etc/thunderbird/policies/ dir-permissions != 755 (TB-process can't open dir → policies silently ignored)"
    TB_FAIL=$((TB_FAIL + 1))
fi

# Defense-check 2: NO lockPref in deployed mozilla.cfg (User-Empowerment)
if grep -q '^lockPref' "$TB_INSTALL_DIR/mozilla.cfg"; then
    log "  FAIL: lockPref found in mozilla.cfg (must be defaultPref only)"
    TB_FAIL=$((TB_FAIL + 1))
fi
if ! grep -qx 'defaultPref("network.trr.mode", 5);' \
        "$TB_INSTALL_DIR/mozilla.cfg" || \
   grep -Eq '^defaultPref\("network\.trr\.(uri|custom_uri|bootstrapAddr)"' \
        "$TB_INSTALL_DIR/mozilla.cfg"; then
    log "  FAIL: Thunderbird DNS default must be user-overridable mode=5 without a forced DoH provider"
    TB_FAIL=$((TB_FAIL + 1))
fi
if ! grep -qx 'defaultPref("browser.safebrowsing.downloads.remote.enabled", false);' \
        "$TB_INSTALL_DIR/mozilla.cfg" || \
   ! grep -qx 'defaultPref("browser.safebrowsing.malware.enabled", true);' \
        "$TB_INSTALL_DIR/mozilla.cfg" || \
   ! grep -qx 'defaultPref("browser.safebrowsing.phishing.enabled", true);' \
        "$TB_INSTALL_DIR/mozilla.cfg" || \
   ! grep -qx 'defaultPref("browser.safebrowsing.downloads.enabled", true);' \
        "$TB_INSTALL_DIR/mozilla.cfg" || \
   ! grep -qx 'defaultPref("browser.safebrowsing.blockedURIs.enabled", true);' \
        "$TB_INSTALL_DIR/mozilla.cfg" || \
   ! grep -qx 'defaultPref("mail.phishing.detection.enabled", true);' \
        "$TB_INSTALL_DIR/mozilla.cfg"; then
    log "  FAIL: heuristic phishing detection, Safe Browsing compatibility values, or remote-reputation suppression differs"
    TB_FAIL=$((TB_FAIL + 1))
fi

# Defense-check 2b: parse the complete allowed AutoConfig grammar. Grep-only
# presence checks accept malformed JavaScript; this validator rejects every
# active line that is not exactly defaultPref("key", JSON-like scalar); and
# rejects duplicate keys that would otherwise create hidden last-write-wins
# behavior. No external JS runtime is added to the image.
if ! python3 - "$TB_INSTALL_DIR/mozilla.cfg" <<'MOZILLA_SYNTAX_PY_EOF'
import json
import re
import sys

path = sys.argv[1]
call = re.compile(
    r'^\s*defaultPref\(\s*'
    r'("(?:\\.|[^"\\])*")\s*,\s*'
    r'(true|false|-?[0-9]+|"(?:\\.|[^"\\])*")'
    r'\s*\);\s*(?://.*)?$')
seen = set()
count = 0
with open(path, encoding='utf-8') as stream:
    for number, raw in enumerate(stream, 1):
        line = raw.rstrip('\n')
        if not line.strip() or line.lstrip().startswith('//'):
            continue
        match = call.fullmatch(line)
        if not match:
            print(f'{path}:{number}: invalid AutoConfig statement', file=sys.stderr)
            sys.exit(1)
        key = json.loads(match.group(1))
        value = match.group(2)
        if value.startswith('"'):
            json.loads(value)
        if key in seen:
            print(f'{path}:{number}: duplicate preference {key}', file=sys.stderr)
            sys.exit(1)
        seen.add(key)
        count += 1
if count == 0:
    print(f'{path}: no defaultPref statements', file=sys.stderr)
    sys.exit(1)
MOZILLA_SYNTAX_PY_EOF
then
    log "  FAIL: mozilla.cfg syntax/shape validation failed"
    TB_FAIL=$((TB_FAIL + 1))
fi

# Defense-check 3: privacy/tracking baseline prefs present in deployed mozilla.cfg
# Case-insensitive grep -qi for robustness across encoding quirks.
for chk in 'calendar.timezone.useSystemTimezone.*true' \
           'privacy.firstparty.isolate.*false' \
           'privacy.donottrackheader.enabled.*false' \
           'doh-rollout.home-region.*global' \
           'browser.region.network.url.*, ""' \
           'browser.region.network.scan.*false' \
           'browser.region.update.enabled.*false' \
           'mail.openpgp.keyserver_list.*vks://keys.openpgp.org, hkps://keys.mailvelope.com'; do
    if ! grep -qi "$chk" "$TB_INSTALL_DIR/mozilla.cfg"; then
        log "  FAIL: privacy/tracking baseline missing in mozilla.cfg: $chk"
        TB_FAIL=$((TB_FAIL + 1))
    fi
done

if [ "$TB_FAIL" -eq 0 ]; then
    log "  Verification: all file-presence + defense-checks OK"

    # M35's STEP 8 uses TB_FAIL rather than the check()/checks/fails helper, so
    # the optional checks_passed/checks_total fields remain omitted. Old
    # evidence was retired before mutation; the module-level exit trap also
    # removes a newly published stamp if a final metadata/content/context gate
    # fails.
    # M35_HEALTH_PUBLICATION_BEGIN
    if [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ] \
       || [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
            0:0:755 ] \
       || ! matchpathcon -V "$STAMP_DIR" >/dev/null; then
        fail "shared Thunderbird health-stamp directory drifted"
    fi

    verify_thunderbird_health_content() {
        local path="$1"
        [ -f "$path" ] \
            && [ ! -L "$path" ] \
            && [ "$(wc -l < "$path")" -eq 6 ] \
            && [ "$(grep -c '^module=' "$path" || true)" -eq 1 ] \
            && [ "$(grep -c '^name=' "$path" || true)" -eq 1 ] \
            && [ "$(grep -c '^version=' "$path" || true)" -eq 1 ] \
            && [ "$(grep -c '^status=' "$path" || true)" -eq 1 ] \
            && [ "$(grep -c '^timestamp=' "$path" || true)" -eq 1 ] \
            && grep -qFx '# NoID Privacy — Module 35 Health Stamp' "$path" \
            && grep -qFx 'module=35' "$path" \
            && grep -qFx 'name=thunderbird' "$path" \
            && grep -qFx 'version=1' "$path" \
            && grep -qFx 'status=ok' "$path" \
            && grep -Eq \
                '^timestamp=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' \
                "$path"
    }
    STAMP_TMP=$(mktemp "$STAMP_DIR/.stamp-35-thunderbird.ok.XXXXXXXX") \
        || fail "cannot create Module 35 health-stamp candidate"
    cat > "$STAMP_TMP" <<STAMP_EOF || \
        fail "cannot write Module 35 health-stamp candidate"
# NoID Privacy — Module 35 Health Stamp
module=35
name=thunderbird
version=1
status=ok
timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
STAMP_EOF
    verify_thunderbird_health_content "$STAMP_TMP" \
        || fail "staged Module 35 health-stamp content is invalid"
    STAMP_PUBLICATION_ACTIVE=1
    publish_root_file "$STAMP_TMP" "$STAMP" 0644
    if [ "$(stat -Lc '%u:%g:%a:%h' -- "$STAMP" 2>/dev/null || true)" != \
            0:0:644:1 ] \
       || ! verify_thunderbird_health_content "$STAMP" \
       || ! matchpathcon -V "$STAMP" >/dev/null; then
        fail "published Module 35 health-stamp contract is invalid"
    fi
    rm -f -- "$STAMP_TMP" \
        || fail "cannot remove Module 35 health-stamp candidate"
    STAMP_TMP=
    STAMP_PUBLICATION_ACTIVE=0
    log "  Exact Module 35 health stamp published atomically"
    # M35_HEALTH_PUBLICATION_END

    log "=== Module 35: Thunderbird hardening COMPLETE ==="
else
    log "  FAIL: Module 35 deployment incomplete ($TB_FAIL issues)"
    exit 1
fi

%end
