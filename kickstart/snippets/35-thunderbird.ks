# ============================================================================
# Module 35 — Thunderbird Hardening
# Status: LOCKED 2026-10-02 (v75) — append a profile's user-overrides.js after the canonical user.js on every apply, so owner overrides survive Update All.
#
# Canonical source-of-truth files:
#   - thunderbird/noid-thunderbird-hardening.js (user.js, gzip+base64-embedded)
#   - thunderbird/mozilla.cfg (defaultPref-only, AutoConfig Layer 2)
#   - thunderbird/autoconfig.js + local-settings.js (mozilla.cfg pointers)
#   - scripts/noid-thunderbird-compatibility.py (native compatibility worker)
#   - thunderbird/dkim-compatibility.json (reviewed DKIM compatibility seed)
#   - docs/35-thunderbird-smartcard.md (installed user guide)
#   Sync gates: scripts/regen-thunderbird-embed.sh --check +
#   scripts/regen-thunderbird-mozilla-cfg.sh --check +
#   scripts/regen-thunderbird-compatibility-embed.sh --check +
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

log "=== Module 35 post-install: Thunderbird hardening ==="

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
STAMP_DIR=/var/lib/noid-privacy
STAMP="$STAMP_DIR/stamp-35-thunderbird.ok"
NOID_TB_REASSERT_CANDIDATE=
NOID_TB_ACTION_CANDIDATE=
TB_COMPAT_CANDIDATE=
TB_SEED_COMPAT_CANDIDATE=
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
        "${TB_COMPAT_CANDIDATE:-}" \
        "${TB_SEED_COMPAT_CANDIDATE:-}" \
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
    # A converged destination keeps its inode; replacing identical bytes would
    # surface as AIDE drift after every Update All and DNF transaction.
    if [ -f "$destination" ] && [ ! -L "$destination" ] \
       && [ "$(readlink -e -- "$destination" 2>/dev/null)" = "$destination" ] \
       && [ "$(stat -Lc '%u:%g:%a:%h' -- "$destination" 2>/dev/null)" = "0:0:$mode:1" ] \
       && [ "$(sha256sum "$destination" | awk '{print $1}')" = "$expected_sha" ] \
       && matchpathcon -V "$destination" >/dev/null 2>&1; then
        rm -f -- "$staged" || fail "cannot retire converged staged file for $destination"
        return 0
    fi
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
# Apply the locally authenticated DKIM compatibility record before the first
# managed-profile launch; the system updater is deliberately not a prerequisite.
# A failed compatibility update must not prevent opening the mail client.
# Thunderbird retains its native compatibility and signature enforcement.
sed -i '\|exec $MOZ_PROGRAM "$@"|i\if ! /usr/local/lib/noid-privacy/noid-thunderbird-compatibility --startup "$@" >/dev/null; then\n  printf "%s\\n" "Thunderbird: compatibility preparation failed; DKIM may remain disabled." >&2\nfi' "$launcher_tmp"
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
# Every admin overlay shadows the vendor entry with the same desktop-file ID, so
# GIO resolves its MimeType only through this directory's cache. A cache older
# than any overlay hides that handler (fresh v1.9: no mailto: handler).
admin_apps=/usr/local/share/applications
if [ ! -f "$admin_apps/mimeinfo.cache" ] || [ -L "$admin_apps/mimeinfo.cache" ] \
   || [ "$(stat -c '%a' "$admin_apps/mimeinfo.cache")" != 644 ] \
   || [ -n "$(find "$admin_apps" -maxdepth 1 -name '*.desktop' \
              -newer "$admin_apps/mimeinfo.cache" -print -quit)" ]; then
    # The cache must stay world-readable whatever umask the DNF action or
    # Update All caller has (M10 sets 027 for login shells).
    (umask 022 && update-desktop-database "$admin_apps") \
        || fail "cannot refresh the admin desktop MIME cache"
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
ensure_root_dir /usr/local/lib/noid-privacy 0755
TB_COMPAT_CANDIDATE=$(mktemp /var/tmp/noid-thunderbird-compat.XXXXXXXX)
cat > "$TB_COMPAT_CANDIDATE" <<'TB_NATIVE_COMPAT_EOF'
#!/usr/bin/python3
"""Apply a digest-bound marketplace compatibility update through Thunderbird.

Usage: noid-thunderbird-compatibility ARCHIVE ID VERSION PRODUCT_VERSION METADATA [PROFILE]
Without PROFILE, verify in a disposable profile. With PROFILE, update only the
matching installed add-on's compatibility through Addon.findUpdates. The worker
has no network, session bus or writable system files. Its temporary AutoConfig
never changes the installed AutoConfig sandbox or the user's update preferences.
"""

import hashlib
import configparser
import json
import os
from pathlib import Path
import pwd
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


def main(arguments=None, *, initialize=False):
    arguments = sys.argv[1:] if arguments is None else arguments
    if len(arguments) not in {5, 6} or os.getuid() == 0:
        raise ValueError(__doc__.splitlines()[2])
    archive, identity, version, product_version, metadata = arguments[:5]
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
        actual_profile = len(arguments) == 6
        if actual_profile:
            original = Path(arguments[5])
            profile = original.resolve(strict=True)
            if original != profile or profile.stat().st_uid != os.getuid() \
                    or not profile.is_dir():
                raise ValueError("unsafe profile directory")
            installed = profile / "extensions" / (identity + ".xpi")
            database = profile / "extensions.json"
            if initialize:
                # Let Thunderbird's native distribution installer create the
                # first add-on record, including its native opt-out state.
                # Never reinstall an extension removed from an existing profile.
                if installed.exists() or installed.is_symlink() \
                        or database.exists() or database.is_symlink():
                    raise ValueError("initial profile acquired extension state")
            elif regular(installed).st_uid != os.getuid() \
                    or hashlib.sha256(installed.read_bytes()).hexdigest() != digest:
                raise ValueError("profile extension differs from validated archive")
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


def startup(arguments):
    """Prepare only the managed canonical profile selected by the launcher.

    This is an offline part of a user-requested browser launch. Profile manager,
    diagnostics, missing profiles, removed add-ons and foreign/newer payloads
    retain Thunderbird's normal behavior. No extension database is rewritten.
    """
    selected = []
    for index, argument in enumerate(arguments):
        flag = argument.lower()
        if flag in {"-profilemanager", "--profilemanager", "-createprofile",
                    "--createprofile", "--help", "-h", "--version", "-v",
                    "--full-version"}:
            return
        if flag in {"-p", "-profile", "--profile"}:
            if index + 1 == len(arguments):
                return
            selected.append((flag, arguments[index + 1]))
    if len(selected) != 1 or selected[0] != ("-p", "default-release"):
        return
    uid = os.getuid()
    if uid == 0:
        raise ValueError("launch Thunderbird as the desktop user")
    home = Path(pwd.getpwuid(uid).pw_dir)
    if os.environ.get("HOME") != str(home):
        raise ValueError("HOME differs from the account database")
    root = home / ".thunderbird"
    profile = root / "default-release"
    for directory in (home, root, profile):
        try:
            info = directory.lstat()
        except FileNotFoundError:
            if directory == home:
                raise
            return  # A user may reset the profile; let Thunderbird handle it.
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid \
                or info.st_mode & 0o022 or directory.resolve(strict=True) != directory:
            raise ValueError("unsafe managed profile directory")
    registry = root / "profiles.ini"
    try:
        info = regular(registry)
    except FileNotFoundError:
        return
    if info.st_uid != uid or info.st_mode & 0o022:
        raise ValueError("unsafe managed profile registry")
    config = configparser.ConfigParser(interpolation=None)
    config.read_string(registry.read_text())
    matches = [config[section] for section in config.sections()
               if section.startswith("Profile")
               and config[section].get("Name") == "default-release"]
    if len(matches) != 1 or matches[0].get("IsRelative") != "1" \
            or matches[0].get("Path") != "default-release":
        return
    identity = "dkim_verifier@pl"
    installed = profile / "extensions" / (identity + ".xpi")
    database = profile / "extensions.json"
    initial = not database.exists() and not database.is_symlink() \
        and not installed.exists() and not installed.is_symlink()
    if not initial and not installed.exists() and not installed.is_symlink():
        return  # Respect native removal from an initialized profile.
    archive = Path("/usr/lib64/thunderbird/distribution/extensions") / (identity + ".xpi")
    info = regular(archive)
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("unsafe distribution extension")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if not initial:
        info = regular(installed)
        if info.st_uid != uid or info.st_mode & 0o022:
            raise ValueError("unsafe profile extension")
        if hashlib.sha256(installed.read_bytes()).hexdigest() != digest:
            return  # Preserve a different user-owned or newer extension.
    # A second window must keep using an already running Thunderbird. Native
    # profile locking remains authoritative if a process starts after this probe.
    query = subprocess.run(["/usr/bin/pgrep", "-u", str(uid), "-x",
                            "thunderbird|thunderbird-bin"],
                           capture_output=True, text=True, timeout=10)
    if query.returncode == 0:
        if not query.stdout or any(not re.fullmatch(r"[1-9][0-9]*", line)
                                   for line in query.stdout.splitlines()):
            raise ValueError("invalid Thunderbird process inventory")
        for pid in query.stdout.splitlines():
            try:
                executable = Path(os.readlink(f"/proc/{pid}/exe"))
            except FileNotFoundError:
                continue  # Exited process or zombie; no profile owner remains.
            if executable in {Path("/usr/lib64/thunderbird/thunderbird"),
                              Path("/usr/lib64/thunderbird/thunderbird-bin")}:
                return
        # A shell launcher is itself named thunderbird. It must not make its
        # own child skip the first-launch preparation before the native exec.
    elif query.returncode != 1 or query.stdout:
        raise ValueError("cannot establish Thunderbird process absence")
    for metadata in (Path("/var/lib/noid-privacy/managed-extensions/dkim-compatibility.json"),
                     Path("/usr/share/noid-thunderbird/dkim-compatibility.json")):
        if not metadata.exists() and not metadata.is_symlink():
            continue
        info = regular(metadata)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("unsafe compatibility record")
        updates = json.loads(metadata.read_text())["addons"][identity]["updates"]
        candidates = [item for item in updates
                      if item.get("update_hash") == "sha256:" + digest]
        if len(candidates) != 1:
            continue
        version = candidates[0]["version"]
        product = subprocess.run(["/usr/bin/rpm", "-q", "--qf", "%{VERSION}",
                                  "thunderbird"], check=True, capture_output=True,
                                 text=True, timeout=10).stdout
        main([str(archive), identity, version, product, str(metadata), str(profile)],
             initialize=initial)
        return
    raise ValueError("no digest-bound compatibility record for the distribution extension")


if __name__ == "__main__":
    try:
        if sys.argv[1:2] == ["--startup"]:
            startup(sys.argv[2:])
        else:
            main()
    except (OSError, ValueError, KeyError, configparser.Error,
            subprocess.SubprocessError) as exc:
        print(f"Thunderbird compatibility: {exc}", file=sys.stderr)
        sys.exit(1)
TB_NATIVE_COMPAT_EOF
publish_root_file "$TB_COMPAT_CANDIDATE" \
    /usr/local/lib/noid-privacy/noid-thunderbird-compatibility 0755
rm -f -- "$TB_COMPAT_CANDIDATE"
TB_COMPAT_CANDIDATE=
TB_SEED_COMPAT_CANDIDATE=$(mktemp /var/tmp/noid-thunderbird-seed-compat.XXXXXXXX)
cat > "$TB_SEED_COMPAT_CANDIDATE" <<'TB_SEED_COMPAT_EOF'
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
publish_root_file "$TB_SEED_COMPAT_CANDIDATE" \
    "$SHARE_DIR/dkim-compatibility.json" 0644
rm -f -- "$TB_SEED_COMPAT_CANDIDATE"
TB_SEED_COMPAT_CANDIDATE=
USERJS_CANDIDATE=$(mktemp /var/tmp/noid-thunderbird-userjs.XXXXXXXX)
base64 -d <<'TB_HARDENING_GZ_B64_EOF' | gunzip > "$USERJS_CANDIDATE"
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
9eCZAQA=
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
# commit 78aaf2644d20f8f077a361a0370686e92c8cc942.
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
// Thunderbird initializes both the Secure DNS controls and OpenPGP-keyserver
// list only after Gecko's region service resolves. Seed the packaged region
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
// Thunderbird does not initialize Gecko's SafeBrowsing list service, so
// the four true values below are inert forward-compatibility defaults, not
// active local-list protection. Thunderbird's heuristic PhishingDetector is
// enabled separately; the false value suppresses per-download reputation POSTs.
defaultPref("browser.safebrowsing.downloads.remote.enabled", false);
defaultPref("browser.safebrowsing.malware.enabled", true);
defaultPref("browser.safebrowsing.phishing.enabled", true);
defaultPref("browser.safebrowsing.downloads.enabled", true);
defaultPref("browser.safebrowsing.blockedURIs.enabled", true);

// === THUNDERBIRD SHUTDOWN SANITIZATION ===
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

// === PHISHING DETECTION (local heuristics, ACTIVE) ===
defaultPref("mail.phishing.detection.enabled", true);
defaultPref("mail.phishing.detection.disallow_form_actions", true);

// === AUTO-CONFIG — OWN-DOMAIN FETCH + HOSTNAME GUESS ON, EXCHANGE AUTODISCOVER OFF ===
// Account setup has five discovery channels:
//   1. fetchFromISP contacts the user's own mail domain (autoconfig.<domain>
//      and <domain>/.well-known); sslOnly and sendEmailAddress=false govern
//      only that path.
//   2. The Thunderbird ISPDB request is controlled by
//      mailnews.auto_config_url, is deliberately left at the vendor default
//      here, and discloses the mail domain to that service.
//   3. An MX DNS lookup for the domain repeats channels 1 and 2 for the mail
//      provider's domain.
//   4. Microsoft Exchange AutoDiscover (fetchFromExchange) POSTs the full
//      e-mail address to autodiscover.<domain> and <domain>, once over plain
//      HTTP, and sends the entered password to the HTTPS endpoints. It is off
//      by default; Exchange/Microsoft 365 users can enable it for setup.
//   5. Hostname guessing (guess.*) probes imap., pop3., pop., mail. and
//      smtp.<domain> plus <domain> itself over the network; guess.sslOnly
//      keeps those probes TLS-only and requireGoodCert applies only there.
// No Settings toggle exists. A complete opt-out requires guess,
// fetchFromISP and fetchFromExchange false plus an empty auto_config_url in
// about:config; for the ordinary NoID Privacy profile, edit/remove the
// matching user.js lines so restart does not reapply them.
defaultPref("mailnews.auto_config.guess.enabled", true);             // RELAX (was false) — probe candidate mail hostnames
defaultPref("mailnews.auto_config.fetchFromISP.enabled", true);      // RELAX (was false) — autodetect via ISP
defaultPref("mailnews.auto_config.fetchFromISP.sendEmailAddress", false);  // KEEP — don't leak full email
defaultPref("mailnews.auto_config.fetchFromISP.sslOnly", true);            // KEEP — TLS-only fetch
defaultPref("mailnews.auto_config.guess.sslOnly", true);                   // KEEP — TLS-only guess
defaultPref("mailnews.auto_config.guess.requireGoodCert", true);           // KEEP — strict cert verify
defaultPref("mailnews.auto_config.fetchFromExchange.enabled", false);      // KEEP — no address/password AutoDiscover
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
// useSystemTimezone=true follows the operating-system timezone (timedatectl /
// /etc/localtime), independent of the UI locale. The profile user.js re-applies
// this value at startup; a durable manual timezone needs a user.js override.
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
// Thunderbird's MailGlue initializes the
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

// === POST-v140.3 GECKO PRIVACY PREFS (FF/TB 145+, LNA WebSocket arm Gecko 154) ===
// Shared Gecko-engine prefs postdating the HorlogeSkynet v140.3 base, mirrored
// from the user.js trailing block. mozilla.cfg (AutoConfig) is the reliable
// system-wide layer; the per-profile user.js is fallback only.
// Local Network Access (Gecko 150) — block sites + 3rd-party trackers reaching
// localhost/LAN. The explicit defaults activate the gate without policy locks.
defaultPref("network.lna.enabled", true);
defaultPref("network.lna.blocking", true);
defaultPref("network.lna.block_trackers", true);
// WebSocket arm of the same gate. Bug 1996551 documents the temporary exemption
// and opt-in pref; Bug 2042339 enables the gate for Gecko 154. Setting it here
// covers ws:// reaching localhost/LAN on builds whose default is still false
// and survives an upstream default change.
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
# before the AutoConfig file (mozilla.cfg) by the TB pref-system, so locale-resolution is
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
// reads system-prefs before the AutoConfig file (mozilla.cfg), so empty here
// lets Gecko fall back to the OS locale (LANG/LC_* via setlocale()).
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

XPI_TARGET="$TB_DISTRIBUTION_EXT_DIR/${DKIM_VERIFIER_EXT_ID}.xpi"

# Download into a private root-owned temporary file. Only the verified bytes are
# published (distribution directory + reassert cache); the download itself is
# removed, so the image keeps no build-time copy.
log "  FETCHING: $DKIM_VERIFIER_URL"
XPI_DOWNLOAD=$(mktemp /var/tmp/noid-thunderbird-dkim.XXXXXXXX)
if ! curl --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --retry 3 --retry-delay 2 --max-redirs 3 \
        --output "$XPI_DOWNLOAD" "$DKIM_VERIFIER_URL"; then
    fail "curl failed for $DKIM_VERIFIER_URL"
fi
verify_sha256 "$XPI_DOWNLOAD" "$DKIM_VERIFIER_SHA256" \
    "downloaded DKIM Verifier XPI v$DKIM_VERIFIER_VERSION"
TB_APP_VERSION=$(rpm -q --qf '%{VERSION}' thunderbird)
XPI_VALIDATED_VERSION=$(
    /usr/local/lib/noid-privacy/validate-webextension.py \
        "$XPI_DOWNLOAD" "$DKIM_VERIFIER_EXT_ID" "$DKIM_VERIFIER_VERSION" \
        0 "$TB_APP_VERSION" 0 "$SHARE_DIR/dkim-compatibility.json"
) || fail "DKIM Verifier identity/version/compatibility validation failed"
[ "$XPI_VALIDATED_VERSION" = "$DKIM_VERIFIER_VERSION" ] \
    || fail "DKIM Verifier validator returned an unexpected version"
publish_root_file "$XPI_DOWNLOAD" "$XPI_TARGET" 0644

# Cache copy in /usr/share for Module 25 re-deploy
publish_root_file "$XPI_DOWNLOAD" "$SHARE_DIR/dkim_verifier.xpi" 0644
rm -f -- "$XPI_DOWNLOAD"
XPI_DOWNLOAD=
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
# pref on the next startup. Durable per-profile overrides belong in the
# profile's user-overrides.js: every apply, including every Update All run,
# appends that file after the canonical values, so its user_pref lines win.

set -euo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

ATOMIC_TEMP=
BACKUP_TEMP=
OPT_OUT_TEMP=
COMPOSED_TEMP=
BACKUP_RESULT=
cleanup_profile_helper() {
    local saved_rc=$? temporary cleanup_failed=0
    trap - EXIT
    trap '' HUP INT TERM
    for temporary in \
        "${ATOMIC_TEMP:-}" "${BACKUP_TEMP:-}" "${OPT_OUT_TEMP:-}" \
        "${COMPOSED_TEMP:-}"; do
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
# Updater and single-profile operations must not be blocked by an unrelated
# registered profile whose directory was deleted; --all stays strict.
tolerant = sys.argv[2] in ("automatic", "single")
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
    missing = False
    for component in path.split(os.sep):
        current = os.path.join(current, component)
        try:
            component_stat = os.lstat(current)
        except FileNotFoundError:
            if not tolerant:
                raise SystemExit(f"{section}: profile path does not exist")
            missing = True
            break
        if stat.S_ISLNK(component_stat.st_mode):
            raise SystemExit(f"{section}: symlinked path component")
    if missing:
        print(f"  Skipped registered profile {name} whose directory is absent",
              file=sys.stderr)
        seen_names.add(name)
        seen_paths.add(path)
        continue
    profile_stat = os.lstat(candidate)
    if not stat.S_ISDIR(profile_stat.st_mode) or profile_stat.st_uid != uid or profile_stat.st_mode & 0o022:
        raise SystemExit(f"{section}: unsafe profile directory")
    seen_names.add(name)
    seen_paths.add(path)
    print(f"{name}\t{candidate}")
TB_PROFILE_LIST_PYEOF
}

resolve_profile() {
    local wanted="$1" name path match=""
    while IFS=$'\t' read -r name path; do
        [ "$name" = "$wanted" ] || continue
        [ -z "$match" ] || return 1
        match="$path"
    done <<< "$PROFILE_RECORDS"
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

# The owner's durable overrides: a regular, unlinked file of at most 64 KiB in
# the profile, owned by the invoking user. It is appended after the canonical
# values on every apply, so a later user_pref for the same name wins at the
# next Thunderbird start without editing the managed user.js.
OVERRIDES_NAME=user-overrides.js
OVERRIDES_MAX_BYTES=65536
COMPOSED_SOURCE=
compose_userjs() {
    local profile="$1" overrides metadata
    overrides="$profile/$OVERRIDES_NAME"
    COMPOSED_SOURCE=$NOID_USERJS
    if [ ! -e "$overrides" ] && [ ! -L "$overrides" ]; then
        return 0
    fi
    metadata=$(stat -c '%u:%h:%s' -- "$overrides" 2>/dev/null) || return 1
    if [ ! -f "$overrides" ] || [ -L "$overrides" ] || \
       [ "${metadata%:*}" != "$(id -u):1" ]; then
        printf 'ERROR: %s must be a regular, unlinked file you own\n' \
            "$overrides" >&2
        return 1
    fi
    if [ "${metadata##*:}" -gt "$OVERRIDES_MAX_BYTES" ]; then
        printf 'ERROR: %s exceeds %s bytes\n' "$overrides" \
            "$OVERRIDES_MAX_BYTES" >&2
        return 1
    fi
    COMPOSED_TEMP=$(mktemp "$profile/.user.js.compose.XXXXXXXX") || return 1
    if ! { cat -- "$NOID_USERJS" &&
           printf '\n// --- NoID Privacy: appended from %s ---\n' \
               "$OVERRIDES_NAME" &&
           cat -- "$overrides"; } > "$COMPOSED_TEMP"; then
        rm -f -- "$COMPOSED_TEMP"
        COMPOSED_TEMP=
        return 1
    fi
    COMPOSED_SOURCE=$COMPOSED_TEMP
}

retire_composed_userjs() {
    [ -n "$COMPOSED_TEMP" ] || return 0
    rm -f -- "$COMPOSED_TEMP" || return 1
    COMPOSED_TEMP=
}

apply_to_profile() {
    local profile="$1" destination rc=0
    [ -d "$profile" ] && [ ! -L "$profile" ] || return 1
    destination="$profile/user.js"
    [ ! -L "$destination" ] || return 1
    if [ -e "$destination" ] && [ ! -f "$destination" ]; then return 1; fi
    compose_userjs "$profile" || return 1
    apply_composed_userjs "$profile" "$destination" || rc=$?
    retire_composed_userjs || rc=1
    return "$rc"
}

apply_composed_userjs() {
    local profile="$1" destination="$2" backup="" metadata
    if [ -f "$destination" ] && cmp -s -- "$COMPOSED_SOURCE" "$destination"; then
        metadata=$(stat -Lc '%u:%a:%h' -- "$destination" 2>/dev/null) \
            || return 1
        if [ "$metadata" = "$(id -u):600:1" ]; then
            clear_profile_opt_out "$profile" || return 1
            echo "  NoID Privacy user.js already applied to $profile"
            return 0
        fi
        atomic_install "$COMPOSED_SOURCE" "$destination" 600 || return 1
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
    atomic_install "$COMPOSED_SOURCE" "$destination" 600 || return 1
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

4. ≡ → Account Settings (menu bar: Edit → Account Settings) → End-to-End Encryption
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
