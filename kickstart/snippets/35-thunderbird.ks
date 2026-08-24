# ============================================================================
# Module 35 — Thunderbird Hardening
# Status: LOCKED 2026-08-20 (v63) — bind and test Gecko LNA WebSocket coverage.
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
NOID_TB_HARDENING_VERSION="1.3.1-horlogeskynet140.2"
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
        "$dkim_seed_version" 0 "$tb_version"
) || fail "reviewed DKIM seed fails identity/version/compatibility validation"
[ "$seed_version" = "$dkim_seed_version" ] \
    || fail "reviewed DKIM seed validator returned an unexpected version"

version_at_least() {
    local candidate=$1 floor=$2 first
    first=$(printf '%s\n%s\n' "$floor" "$candidate" | sort -V | head -n 1)
    [ "$first" = "$floor" ]
}

dkim_src=$dkim_seed
dkim_src_version=$dkim_seed_version
if [ -f "$dkim_current" ] && [ ! -L "$dkim_current" ]; then
    current_version=$(
        "$dkim_validator" "$dkim_current" dkim_verifier@pl - 0 "$tb_version" \
            2>/dev/null
    ) || current_version=
    if [ -n "$current_version" ] \
            && version_at_least "$current_version" "$dkim_seed_version"; then
        dkim_src=$dkim_current
        dkim_src_version=$current_version
    else
        logger -t noid-thunderbird-reassert \
            "WARNING: durable DKIM current slot invalid or older than reviewed seed; using seed"
    fi
fi

dst_version=
if [ -f "$dkim_dst" ] && [ ! -L "$dkim_dst" ]; then
    dst_version=$(
        "$dkim_validator" "$dkim_dst" dkim_verifier@pl - 0 "$tb_version" \
            2>/dev/null
    ) || dst_version=
fi
if [ -n "$dst_version" ] && version_at_least "$dst_version" "$dkim_src_version"; then
    if [ "$dst_version" = "$dkim_src_version" ] && ! cmp -s "$dkim_src" "$dkim_dst"; then
        publish_managed_file "$dkim_src" "$dkim_dst" dkim
    fi
else
    publish_managed_file "$dkim_src" "$dkim_dst" dkim
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
# Source: thunderbird/noid-thunderbird-hardening.js (HorlogeSkynet v140.2 base
# plus NoID Privacy overrides). Embedded gzip+base64; this decode step does not fetch.
# Regenerate: scripts/regen-thunderbird-embed.sh
log "STEP 3: Decode embedded NoID Privacy Thunderbird hardening v$NOID_TB_HARDENING_VERSION"
ensure_root_dir "$SHARE_DIR" 0755
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
# the image-wide license inventory. The digest is from annotated tag v140.2,
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
log "  Installed exact HorlogeSkynet v140.2 MIT notice: $HORLOGESKYNET_LICENSE"
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

// === EXTENSIONS SCOPES (for distribution-bundled DKIM-XPI + Mozilla langpacks) ===
// Bitmask: 1=profile + 2=user + 4=app + 8=system
// enabledScopes=5 (=profile+app) — load distribution/extensions/ + profile/extensions/
// autoDisableScopes=11 (=profile+user+system, app-bit OFF):
//   App-bit OFF lets app-installed Mozilla langpacks (location=app-global)
//   stay enabled → matches user system-locale (fr_FR → langpack-fr auto-active
//   via Fedora's all-redhat.js matchOS=true + intl.locale.requested=""
//   defense-in-depth from noid-locale.js).
defaultPref("extensions.enabledScopes", 5);
defaultPref("extensions.autoDisableScopes", 11);

// === BUILT-IN ABOUT:WELCOME / ONBOARDING DISABLE ===
defaultPref("browser.aboutwelcome.enabled", false);

// === POST-v140.2 GECKO PRIVACY PREFS (FF/TB 145+, base review TB 152, WebSocket arm TB 153) ===
// Shared Gecko-engine prefs postdating the HorlogeSkynet v140.2 base, mirrored
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
        0 "$TB_APP_VERSION"
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

thunderbird_process_active() {
    local process_name pid state
    for process_name in thunderbird thunderbird-bin; do
        while IFS= read -r pid; do
            [ -n "$pid" ] || continue
            state=$(ps -o stat= -p "$pid" 2>/dev/null | awk 'NR == 1 {print $1}')
            case "$state" in
                ""|Z*|X*) ;;
                *) return 0 ;;
            esac
        done < <(pgrep -u "$(id -u)" -x "$process_name" 2>/dev/null || true)
    done
    return 1
}

if thunderbird_process_active; then
    echo "ERROR: close Thunderbird before changing profile files" >&2
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
    echo "ERROR: close Thunderbird before changing profile files" >&2
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
