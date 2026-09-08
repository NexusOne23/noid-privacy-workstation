# ============================================================================
# Module 35 — Thunderbird Hardening
# Status: LOCKED 2026-09-06 (v65) — refuse profile mutation when process queries fail or return invalid evidence.
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
wPz/CTC+kxqWAQA=
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
