# ============================================================================
# Module 41 — installed-target transition
# Status: LOCKED 2026-08-23 (v41) — converge GDM's native log-directory contract before first login.
#
# Why: Fedora's signed livesys-scripts and NoID Privacy M17 deliberately create
# ephemeral Live privileges: an unlocked root password field, the passwordless
# liveuser, M17's exact NOPASSWD rule, GNOME installer polkit authorization and
# GDM auto-login. A normal target installation must supersede that state. If
# the transfer or cleanup is incomplete (power loss, broken package or an
# upstream lifecycle change), the installed system could inherit a local
# privilege-escalation path.
#
# Defense: noid-anaconda-cleanup.service runs the short security mode once on
# the first persistent boot (idempotent; skipped on Live media). GDM and
# systemd-user-sessions are success-gated on its independently validated
# security marker. Once GDM is available, noid-anaconda-maintenance.service
# performs the slow RPM/DNF work and publishes anaconda-cleanup.done. Both
# units remain network-denied; incomplete evidence is retired and retried.
#
# Cleanup scope (detail in the CLEANUP_EOF script comments): local root-password
# lock + liveuser + recoverable quarantine of exact account remnants + exact
# M17 sudoers policy + exact signed
# Fedora Live-installer polkit rule + GDM log-directory label + auto-login + /var/lib/livesys +
# livesys unit symlinks + exact AccountsService liveuser state + GDM
# initial-setup policy (Sections 7–8) + digest-scoped compose-NM profile
# archiving + active restricted chronyd-provider reconciliation before login.
# Deferred scope: RPM-native metadata repair + installer-only RPM removal
# (including exact NoID Privacy Livesys .rpmsave retirement) + DNF5-native
# reason/autoremove cleanup + first-boot install-date evidence.
#
# Constraint notes (keep on future edits):
#   - Section 7 GIS policy requires BOTH conditions (HUMAN_USERS=0 AND
#     HOME_USERS=0) before enabling initial setup. A re-install over a
#     LUKS-preserved /home satisfies only the first, so the real GDM
#     InitialSetupEnable key is set false with a manual-recreation hint.
#   - The security unit keeps MemoryDenyWriteExecute=yes. Only the deferred
#     maintenance unit relaxes it for the general RPM/DNF scriptlet boundary.
#     ProtectSystem=strict + ProtectHome are skipped where parent-dir writes are
#     required (rationale in the unit comments).
#   - Fedora's Anaconda sysconfig file is an intentional input to unprivileged
#     post-install tools. The Live-image transfer can leave its parent 0750 and
#     the generated, non-RPM-owned file 0640, so a narrow metadata bridge runs
#     in the existing pre-login security unit. The broad RPM-owned tree repair
#     remains deferred; no duplicate package scan is added to the login path.
#   - The complete Anaconda/Lorax/live-install package set is removed in one
#     DNF5 transaction so package reasons/history remain coherent; removing
#     only individual leaves left the installer stack and caused meta-packages
#     to return via dependencies.
#   - Build-time stamp-41, pre-login security evidence and the final
#     anaconda-cleanup.done marker coexist by design and prove distinct stages.
# ============================================================================

%post --erroronfail --log=/var/log/ks-41-anaconda-cleanup.log
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

log() { echo "[$(date +%H:%M:%S)] $*"; }
fail() {
    log "  [FAIL] $*"
    exit 1
}

ROOT_PUBLICATION_TMP=""

# M41_ROOT_PUBLICATION_BEGIN
# Root-owned executable and unit payloads are staged beside their destination,
# relabeled, byte-checked and made durable before the build can claim success.
# Existing target symlinks are replaced by rename rather than followed.
publish_root_file() {
    local source=$1 destination=$2 requested_mode=$3
    local parent temporary mode=${requested_mode#0} parent_state parent_mode
    local source_state source_mode

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
        || fail "publication source is writable by group/other: $source"
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
        || fail "publication parent is writable by group/other: $parent"
    [ ! -e "$destination" ] || [ -f "$destination" ] || [ -L "$destination" ] \
        || fail "publication target is neither a regular file nor symlink: $destination"
    [ -x /usr/sbin/restorecon ] && [ -x /usr/sbin/matchpathcon ] \
        || fail "SELinux label tools are unavailable"

    temporary=$(mktemp "$parent/.noid-m41-publish.XXXXXXXX") \
        || fail "cannot stage publication: $destination"
    ROOT_PUBLICATION_TMP=$temporary
    if ! install -m "$requested_mode" -o root -g root -- "$source" "$temporary" \
       || ! /usr/sbin/restorecon -F -- "$temporary" \
       || ! /usr/sbin/matchpathcon -V "$temporary" >/dev/null \
       || ! sync -- "$temporary"; then
        rm -f -- "$temporary" || true
        ROOT_PUBLICATION_TMP=""
        fail "cannot prepare publication: $destination"
    fi

    # A signal may not land after rename but before the final path becomes
    # validated and removable by the outer cleanup trap.
    trap '' HUP INT TERM
    if ! mv -fT -- "$temporary" "$destination"; then
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        rm -f -- "$temporary" || true
        ROOT_PUBLICATION_TMP=""
        fail "cannot publish: $destination"
    fi
    ROOT_PUBLICATION_TMP=""
    if ! /usr/sbin/restorecon -F -- "$destination" \
       || ! /usr/sbin/matchpathcon -V "$destination" >/dev/null \
       || [ ! -f "$destination" ] || [ -L "$destination" ] \
       || ! cmp -s -- "$source" "$destination" \
       || [ "$(stat -Lc '%u:%g:%a:%h' -- "$destination" 2>/dev/null)" != \
            "0:0:$mode:1" ] \
       || [ "$(readlink -e -- "$destination" 2>/dev/null)" != "$destination" ] \
       || ! sync -- "$destination" \
       || ! sync -- "$parent"; then
        rm -f -- "$destination" || true
        sync -- "$parent" >/dev/null 2>&1 || true
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        fail "published-file postcondition failed: $destination"
    fi
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
}
candidate_sha256() {
    local path=$1 digest
    digest=$(/usr/bin/sha256sum -- "$path" 2>/dev/null) \
        || fail "cannot hash Module 41 publication candidate: $path"
    digest=${digest%% *}
    [[ "$digest" =~ ^[a-f0-9]{64}$ ]] \
        || fail "invalid Module 41 publication-candidate digest: $path"
    printf '%s\n' "$digest"
}
# M41_ROOT_PUBLICATION_END
log "=== Module 41 — anaconda-cleanup safety-net ==="

# M41_HEALTH_INVALIDATION_BEGIN
# The build-time stamp represents this complete publication. Validate the
# shared state boundary without normalizing drift, then remove any prior
# success before this run starts changing the cleanup payload and activation.
M41_STATE_DIR=/var/lib/noid-privacy
STAMP="$M41_STATE_DIR/stamp-41-anaconda-cleanup.ok"
# M41_BUILD_CLEANUP_BEGIN
CLEANUP_SOURCE=""
IDENTITY_SOURCE=""
IDENTITY_SERVICE_SOURCE=""
BUILD_NM_CANDIDATE=""
SERVICE_SOURCE=""
MAINTENANCE_SERVICE_SOURCE=""
GDM_GATE_SOURCE=""
USER_SESSIONS_GATE_SOURCE=""
CLEANUP_EXPECTED_SHA=""
IDENTITY_EXPECTED_SHA=""
IDENTITY_SERVICE_EXPECTED_SHA=""
SERVICE_EXPECTED_SHA=""
MAINTENANCE_SERVICE_EXPECTED_SHA=""
GDM_GATE_EXPECTED_SHA=""
USER_SESSIONS_GATE_EXPECTED_SHA=""
STAMP_CANDIDATE=""
STAMP_PUBLISHED=0
cleanup_m41_build_candidates() {
    local saved_rc=$? candidate cleanup_failed=0
    trap - EXIT
    trap '' HUP INT TERM
    for candidate in \
        "${ROOT_PUBLICATION_TMP:-}" \
        "${IDENTITY_SOURCE:-}" \
        "${IDENTITY_SERVICE_SOURCE:-}" \
        "${CLEANUP_SOURCE:-}" \
        "${BUILD_NM_CANDIDATE:-}" \
        "${SERVICE_SOURCE:-}" \
        "${MAINTENANCE_SERVICE_SOURCE:-}" \
        "${GDM_GATE_SOURCE:-}" \
        "${USER_SESSIONS_GATE_SOURCE:-}" \
        "${STAMP_CANDIDATE:-}"; do
        [ -n "$candidate" ] || continue
        if ! rm -f -- "$candidate"; then
            log "  [FAIL] could not retire staged Module 41 payload: $candidate"
            cleanup_failed=1
        fi
    done
    if [ "${STAMP_PUBLISHED:-0}" -eq 1 ]; then
        if ! rm -f -- "$STAMP"; then
            log "  [FAIL] could not retire incomplete Module 41 health stamp"
            cleanup_failed=1
        fi
        sync -- "$M41_STATE_DIR" >/dev/null 2>&1 || true
    fi
    if [ "$saved_rc" -eq 0 ] && [ "$cleanup_failed" -ne 0 ]; then
        exit 1
    fi
    return "$saved_rc"
}
trap cleanup_m41_build_candidates EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
# M41_BUILD_CLEANUP_END

if { [ -e "$M41_STATE_DIR" ] || [ -L "$M41_STATE_DIR" ]; } \
   && { [ ! -d "$M41_STATE_DIR" ] || [ -L "$M41_STATE_DIR" ]; }; then
    log "  [FAIL] $M41_STATE_DIR exists but is not a real directory"
    exit 1
fi
if [ ! -e "$M41_STATE_DIR" ]; then
    install -d -m 0755 -o root -g root "$M41_STATE_DIR"
fi
if [ "$(stat -Lc '%u:%g:%a' -- "$M41_STATE_DIR" 2>/dev/null || true)" != \
        0:0:755 ]; then
    log "  [FAIL] $M41_STATE_DIR metadata is not root:root 0755"
    exit 1
fi
if [ ! -x /usr/sbin/restorecon ] || [ ! -x /usr/sbin/matchpathcon ] \
   || ! /usr/sbin/restorecon -F -- "$M41_STATE_DIR" \
   || ! /usr/sbin/matchpathcon -V "$M41_STATE_DIR" >/dev/null; then
    log "  [FAIL] $M41_STATE_DIR SELinux context is not canonical"
    exit 1
fi
if [ -e "$STAMP" ] || [ -L "$STAMP" ]; then
    if [ ! -f "$STAMP" ] && [ ! -L "$STAMP" ]; then
        log "  [FAIL] health-stamp target is not a file or symlink: $STAMP"
        exit 1
    fi
    rm -f -- "$STAMP" || {
        log "  [FAIL] cannot invalidate stale Module 41 health stamp"
        exit 1
    }
    sync -- "$M41_STATE_DIR"
fi
log "  [OK] prior Module 41 health stamp is absent"
# M41_HEALTH_INVALIDATION_END

# ============================================================================
# STEP 0: Host-identity lifecycle helper
# ============================================================================
# The final Lorax tree deliberately contains none of the three compose-time
# identity files below. systemd already owns first-boot machine-id and random
# seed creation; BRLAPI's RPM scriptlet and the unowned libnvme files have no
# equivalent boot-time publisher. This helper closes only that remaining gap:
# Live media gets a fresh set in its writable overlay, and M41 rotates it once
# more before the first installed login. It never prints identifying values.
log "STEP 0: writing /usr/local/bin/noid-host-identity"

[ -d /usr/local/bin ] && [ ! -L /usr/local/bin ] \
    && [ "$(readlink -e -- /usr/local/bin 2>/dev/null)" = /usr/local/bin ] \
    && [ "$(stat -Lc '%u:%g:%a' -- /usr/local/bin 2>/dev/null)" = \
        0:0:755 ] \
    || fail "/usr/local/bin publication parent is not canonical root:root 0755"
IDENTITY_SOURCE=$(mktemp /var/tmp/.noid-host-identity.XXXXXXXX) \
    || fail "cannot stage host-identity helper source"
cat > "$IDENTITY_SOURCE" <<'HOST_IDENTITY_EOF'
#!/bin/bash
# noid-host-identity — generate or verify per-boot/per-install host identity
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C
umask 0077

BRLAPI_KEY=/etc/brlapi.key
NVME_DIR=/etc/nvme
NVME_HOSTID=$NVME_DIR/hostid
NVME_HOSTNQN=$NVME_DIR/hostnqn
STATE_DIR=/var/lib/noid-privacy
INSTALL_MARKER=$STATE_DIR/host-identity-installed.done
STAGED_FILE=""

log() { echo "[noid-host-identity] $*"; }
fail() { log "FAILED: $*" >&2; exit 1; }
cleanup() {
    local saved_rc=$?
    trap - EXIT HUP INT TERM
    [ -z "${STAGED_FILE:-}" ] || rm -f -- "$STAGED_FILE" || true
    return "$saved_rc"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
    cat <<'IDENTITY_USAGE_EOF'
Usage: noid-host-identity {--check|--repair|--ensure|--install-transition}

  --check               Verify metadata, labels and value relationships only.
  --repair              Rotate BRLAPI and NVMe host identities after checking
                        that no NVMe-over-Fabrics controller is active.
  --ensure              Internal boot mode: create missing identities or
                        resume an incomplete first-transition publication;
                        never rotate a validated identity.
  --install-transition  Internal M41 mode: rotate the Live identities once
                        before the first installed login.
IDENTITY_USAGE_EOF
}

require_root() {
    [ "$EUID" -eq 0 ] \
        || fail "operation requires root because the BRLAPI key is root-readable"
}

trusted_directory() {
    local path=$1 expected_mode=$2
    [ -d "$path" ] && [ ! -L "$path" ] \
        && [ "$(readlink -e -- "$path" 2>/dev/null)" = "$path" ] \
        && [ "$(stat -Lc '%u:%g:%a' -- "$path" 2>/dev/null)" = \
            "0:0:$expected_mode" ] \
        && /usr/sbin/matchpathcon -V "$path" >/dev/null
}

ensure_directories() {
    trusted_directory /etc 755 || fail "/etc boundary is unsafe"
    if [ ! -e "$NVME_DIR" ] && [ ! -L "$NVME_DIR" ]; then
        install -d -o root -g root -m 0755 -- "$NVME_DIR"
        /usr/sbin/restorecon -F -- "$NVME_DIR"
    fi
    trusted_directory "$NVME_DIR" 755 || fail "$NVME_DIR boundary is unsafe"
    trusted_directory /var/lib 755 || fail "/var/lib boundary is unsafe"
    if [ ! -e "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ]; then
        install -d -o root -g root -m 0755 -- "$STATE_DIR"
        /usr/sbin/restorecon -F -- "$STATE_DIR"
    fi
    trusted_directory "$STATE_DIR" 755 || fail "$STATE_DIR boundary is unsafe"
}

brlapi_gid() {
    local record
    record=$(getent -s files group brlapi) || return 1
    [ "$(grep -c . <<<"$record")" -eq 1 ] || return 1
    awk -F: '$1 == "brlapi" && $3 ~ /^[0-9]+$/ { print $3 }' <<<"$record"
}

validate_root_file() { # PATH GID MODE SIZE
    local path=$1 gid=$2 mode=$3 size=$4
    [ -f "$path" ] && [ ! -L "$path" ] \
        && [ "$(readlink -e -- "$path" 2>/dev/null)" = "$path" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h:%s' -- "$path" 2>/dev/null)" = \
            "0:$gid:$mode:1:$size" ] \
        && /usr/sbin/matchpathcon -V "$path" >/dev/null
}

validate_nvme_pair() {
    local hostid hostnqn
    validate_root_file "$NVME_HOSTID" 0 644 37 || return 1
    validate_root_file "$NVME_HOSTNQN" 0 644 69 || return 1
    [ "$(wc -l <"$NVME_HOSTID")" -eq 1 ] \
        && [ "$(wc -l <"$NVME_HOSTNQN")" -eq 1 ] || return 1
    IFS= read -r hostid <"$NVME_HOSTID" || return 1
    IFS= read -r hostnqn <"$NVME_HOSTNQN" || return 1
    [[ "$hostid" =~ ^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$ ]] \
        && [ "$hostnqn" = "nqn.2014-08.org.nvmexpress:uuid:$hostid" ]
}

validate_brlapi_key() {
    local gid key
    gid=$(brlapi_gid) && [[ "$gid" =~ ^[0-9]+$ ]] || return 1
    validate_root_file "$BRLAPI_KEY" "$gid" 640 33 || return 1
    [ "$(wc -l <"$BRLAPI_KEY")" -eq 1 ] || return 1
    IFS= read -r key <"$BRLAPI_KEY" || return 1
    [[ "$key" =~ ^[a-f0-9]{32}$ ]]
}

validate_install_marker() {
    local value
    validate_root_file "$INSTALL_MARKER" 0 644 45 || {
        # The active-fabric form is longer than the normal rotated form.
        validate_root_file "$INSTALL_MARKER" 0 644 66 || return 1
    }
    [ "$(wc -l <"$INSTALL_MARKER")" -eq 1 ] || return 1
    IFS= read -r value <"$INSTALL_MARKER" || return 1
    [[ "$value" =~ ^NOID_HOST_IDENTITY_INSTALLED_V1\ mode=(rotated|nvme-preserved-active-fabric)$ ]]
}

write_atomic() { # PATH GROUP MODE VALUE
    local path=$1 group=$2 mode=$3 value=$4 parent candidate
    parent=${path%/*}
    trusted_directory "$parent" 755 || fail "publication parent is unsafe: $parent"
    [ ! -e "$path" ] || [ -f "$path" ] || [ -L "$path" ] \
        || fail "publication target has an unsafe type: $path"
    candidate=$(mktemp "$parent/.noid-host-identity.XXXXXXXX") \
        || fail "cannot stage host identity"
    STAGED_FILE=$candidate
    printf '%s\n' "$value" >"$candidate"
    chown root:"$group" "$candidate"
    chmod "$mode" "$candidate"
    /usr/sbin/restorecon -F -- "$candidate"
    /usr/sbin/matchpathcon -V "$candidate" >/dev/null
    sync -- "$candidate"
    trap '' HUP INT TERM
    mv -fT -- "$candidate" "$path"
    STAGED_FILE=""
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    /usr/sbin/restorecon -F -- "$path"
    /usr/sbin/matchpathcon -V "$path" >/dev/null
    sync -- "$path"
    sync -- "$parent"
}

rotate_nvme_pair() {
    local hostid
    hostid=$(/usr/bin/uuidgen --random) || fail "uuidgen failed"
    [[ "$hostid" =~ ^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$ ]] \
        || fail "uuidgen returned an unexpected schema"
    write_atomic "$NVME_HOSTID" root 0644 "$hostid"
    write_atomic "$NVME_HOSTNQN" root 0644 \
        "nqn.2014-08.org.nvmexpress:uuid:$hostid"
    validate_nvme_pair || fail "published NVMe host identity is invalid"
}

rotate_brlapi_key() {
    local key
    getent -s files group brlapi >/dev/null \
        || fail "local brlapi group is unavailable"
    key=$(/usr/bin/mcookie) || fail "mcookie failed"
    [[ "$key" =~ ^[a-f0-9]{32}$ ]] \
        || fail "mcookie returned an unexpected schema"
    write_atomic "$BRLAPI_KEY" brlapi 0640 "$key"
    validate_brlapi_key || fail "published BRLAPI key is invalid"
}

active_nvme_fabric() {
    local transport_file transport
    for transport_file in /sys/class/nvme/nvme*/transport; do
        [ -f "$transport_file" ] || continue
        IFS= read -r transport <"$transport_file" || return 0
        case "$transport" in
            pcie) ;;
            *) return 0 ;;
        esac
    done
    return 1
}

check_all() {
    require_root
    validate_nvme_pair || fail "NVMe host identity contract failed"
    validate_brlapi_key || fail "BRLAPI key contract failed"
    log "PASS: host identity files are internally consistent"
}

ensure_missing() {
    require_root
    ensure_directories
    if { [ -e "$NVME_HOSTID" ] || [ -L "$NVME_HOSTID" ]; } \
       || { [ -e "$NVME_HOSTNQN" ] || [ -L "$NVME_HOSTNQN" ]; }; then
        if validate_nvme_pair; then
            :
        elif [ -e "$INSTALL_MARKER" ] || [ -L "$INSTALL_MARKER" ]; then
            fail "installed identity evidence exists; refusing automatic NVMe repair"
        elif active_nvme_fabric; then
            fail "incomplete NVMe identity with an active fabric requires manual recovery"
        else
            rotate_nvme_pair
            log "resumed incomplete pre-install NVMe identity publication"
        fi
    else
        rotate_nvme_pair
        log "generated missing per-boot NVMe host identity"
    fi
    if [ -e "$BRLAPI_KEY" ] || [ -L "$BRLAPI_KEY" ]; then
        if validate_brlapi_key; then
            :
        elif [ -e "$INSTALL_MARKER" ] || [ -L "$INSTALL_MARKER" ]; then
            fail "installed identity evidence exists; refusing automatic BRLAPI repair"
        else
            rotate_brlapi_key
            log "resumed incomplete pre-install BRLAPI key publication"
        fi
    else
        rotate_brlapi_key
        log "generated missing per-boot BRLAPI key"
    fi
    check_all
}

publish_install_marker() {
    local mode=$1
    write_atomic "$INSTALL_MARKER" root 0644 \
        "NOID_HOST_IDENTITY_INSTALLED_V1 mode=$mode"
    validate_install_marker || fail "installed-transition marker is invalid"
}

install_transition() {
    require_root
    ensure_directories
    if validate_install_marker; then
        check_all
        log "validated prior installed host-identity transition"
        return 0
    fi
    if [ -e "$INSTALL_MARKER" ] || [ -L "$INSTALL_MARKER" ]; then
        [ -f "$INSTALL_MARKER" ] || [ -L "$INSTALL_MARKER" ] \
            || fail "installed-transition marker has an unsafe type"
        rm -f -- "$INSTALL_MARKER"
        sync -- "$STATE_DIR"
    fi
    if active_nvme_fabric; then
        validate_nvme_pair \
            || fail "active NVMe-over-Fabrics requires an existing valid identity"
        rotate_brlapi_key
        publish_install_marker nvme-preserved-active-fabric
        log "preserved active NVMe-over-Fabrics identity; rotated BRLAPI key"
    else
        rotate_nvme_pair
        rotate_brlapi_key
        publish_install_marker rotated
        log "rotated installed NVMe host identity and BRLAPI key"
    fi
    check_all
}

repair_all() {
    require_root
    ensure_directories
    active_nvme_fabric \
        && fail "refusing repair while an NVMe-over-Fabrics controller is active"
    rotate_nvme_pair
    rotate_brlapi_key
    check_all
    log "repair completed"
}

if [ "$#" -ne 1 ]; then
    usage >&2
    exit 2
fi
case "$1" in
    --help|-h) usage ;;
    --check) check_all ;;
    --repair) repair_all ;;
    --ensure) ensure_missing ;;
    --install-transition) install_transition ;;
    *) usage >&2; exit 2 ;;
esac
HOST_IDENTITY_EOF

bash -n "$IDENTITY_SOURCE" \
    || fail "host-identity helper source has invalid shell syntax"
IDENTITY_EXPECTED_SHA=$(candidate_sha256 "$IDENTITY_SOURCE")
publish_root_file "$IDENTITY_SOURCE" \
    /usr/local/bin/noid-host-identity 0755
rm -f -- "$IDENTITY_SOURCE" \
    || fail "cannot retire host-identity helper source"
IDENTITY_SOURCE=""
log "  [OK] /usr/local/bin/noid-host-identity installed"

# ============================================================================
# STEP 1: Cleanup script
# ============================================================================
log "STEP 1: writing /usr/libexec/noid-anaconda-cleanup.sh"

[ -d /usr/libexec ] && [ ! -L /usr/libexec ] \
    && [ "$(readlink -e -- /usr/libexec 2>/dev/null)" = /usr/libexec ] \
    && [ "$(stat -Lc '%u:%g:%a' -- /usr/libexec 2>/dev/null)" = 0:0:755 ] \
    || fail "/usr/libexec publication parent is not canonical root:root 0755"
CLEANUP_SOURCE=$(mktemp /var/tmp/.noid-anaconda-cleanup.XXXXXXXX) \
    || fail "cannot stage the first-boot cleanup source"
cat > "$CLEANUP_SOURCE" <<'CLEANUP_EOF'
#!/bin/bash
# noid-anaconda-cleanup.sh — first-boot safety-net for Live-ISO remnants
#
# Retry-safe: state-changing operations converge behind explicit guards. The
# pre-login security transition and deferred package hygiene have independent
# durable markers. All actions are logged to the systemd journal.
#
# Activation flow:
#   1. GDM requires this script's --security mode
#   2. Security mode retires all Live authorization and publishes its marker
#   3. GDM becomes available
#   4. The separately ordered --maintenance service removes installer packages
#   5. Maintenance atomically publishes anaconda-cleanup.done on success

set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 {--security|--maintenance}" >&2
    exit 2
fi
MODE=$1
case "$MODE" in
    --security)
        MODE=security
        DONE_MARKER=/var/lib/noid-privacy/anaconda-cleanup-security.done
        ;;
    --maintenance)
        MODE=maintenance
        DONE_MARKER=/var/lib/noid-privacy/anaconda-cleanup.done
        ;;
    *)
        echo "Usage: $0 {--security|--maintenance}" >&2
        exit 2
        ;;
esac
SECURITY_MARKER=/var/lib/noid-privacy/anaconda-cleanup-security.done
BUILD_NM_MANIFEST=/usr/lib/noid-privacy/anaconda-build-nm-profile-sha256
LOG_TAG=noid-anaconda-cleanup

log() {
    logger -t "$LOG_TAG" "$*" 2>/dev/null || true
    echo "[$LOG_TAG] $*"
}

forward_log_tail() { # FILE PREFIX
    local path=$1 prefix=$2
    tail -50 "$path" 2>/dev/null \
        | while IFS= read -r line; do
            [ -n "$line" ] || continue
            logger -t "$LOG_TAG" "$prefix: $line" 2>/dev/null || true
        done || true
}

# M41_RUNTIME_MARKER_CLEANUP_BEGIN
RUNTIME_CANDIDATE=""
RPM_METADATA_CANDIDATE=""
DONE_CANDIDATE=""
DONE_PUBLISHED=0
cleanup_runtime_marker() {
    local saved_rc=$? cleanup_failed=0
    trap - EXIT
    trap '' HUP INT TERM
    if [ -n "${RUNTIME_CANDIDATE:-}" ]; then
        if ! rm -f -- "$RUNTIME_CANDIDATE"; then
            log "FAILED: could not retire staged runtime policy candidate"
            cleanup_failed=1
        fi
    fi
    if [ -n "${RPM_METADATA_CANDIDATE:-}" ]; then
        if ! rm -f -- "$RPM_METADATA_CANDIDATE"; then
            log "FAILED: could not retire staged RPM metadata manifest"
            cleanup_failed=1
        fi
    fi
    if [ -n "${DONE_CANDIDATE:-}" ]; then
        if ! rm -f -- "$DONE_CANDIDATE"; then
            log "FAILED: could not retire staged cleanup completion marker"
            cleanup_failed=1
        fi
    fi
    if [ "${DONE_PUBLISHED:-0}" -eq 1 ]; then
        if ! rm -f -- "$DONE_MARKER"; then
            log "FAILED: could not retire incomplete cleanup completion marker"
            cleanup_failed=1
        fi
        sync -- "${DONE_MARKER%/*}" >/dev/null 2>&1 || true
    fi
    if [ "$saved_rc" -eq 0 ] && [ "$cleanup_failed" -ne 0 ]; then
        exit 1
    fi
    return "$saved_rc"
}
verify_cleanup_done_marker() {
    local path=$1 expected=${2:-} value
    [ -f "$path" ] && [ ! -L "$path" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' -- "$path" 2>/dev/null)" = \
            0:0:644:1 ] \
        && [ "$(wc -l < "$path")" -eq 1 ] || return 1
    value=$(cat "$path") || return 1
    [[ "$value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\ cleanup_count=[0-9]+$ ]] \
        || return 1
    [ -z "$expected" ] || [ "$value" = "$expected" ]
}
trap cleanup_runtime_marker EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
# M41_RUNTIME_MARKER_CLEANUP_END

# Belt-and-suspenders: also check for Live-ISO via /run/livesys and overlayfs
# root. Service-level ConditionPathExists is primary, but if the service ever
# runs erroneously on Live-ISO, this script-level check is the fallback.
if [ -e /run/livesys ] || [ -d /run/initramfs/live ]; then
    log "Live-ISO mode detected (/run/livesys or /run/initramfs/live present) — skipping cleanup, exiting 0"
    exit 0
fi

# Filesystem-type check: Live-ISO root is overlay/squashfs; a persistent target
# can use Btrfs, ext4, XFS or another ordinary block-backed filesystem.
if ! ROOT_FS=$(findmnt -no FSTYPE / 2>/dev/null) || [ -z "$ROOT_FS" ]; then
    log "Cannot determine root filesystem type — refusing cleanup and retrying next boot"
    exit 1
fi
case "$ROOT_FS" in
    overlay|tmpfs|squashfs)
        log "Live-ISO root filesystem ($ROOT_FS) — skipping cleanup, exiting 0"
        exit 0
        ;;
esac

log "Installed persistent root detected ($ROOT_FS) — running cleanup"

STATE_DIR=${DONE_MARKER%/*}
if [ ! -d "$STATE_DIR" ] || [ -L "$STATE_DIR" ] \
   || [ "$(stat -Lc '%u:%g:%a' -- "$STATE_DIR" 2>/dev/null)" != \
      0:0:755 ]; then
    log "FAILED: NoID Privacy state directory contract is invalid: $STATE_DIR"
    exit 1
fi
if [ ! -x /usr/sbin/restorecon ] || [ ! -x /usr/sbin/matchpathcon ] \
   || ! /usr/sbin/restorecon -F -- "$STATE_DIR" \
   || ! /usr/sbin/matchpathcon -V "$STATE_DIR" >/dev/null; then
    log "FAILED: NoID Privacy state directory label is not canonical"
    exit 1
fi

installer_evidence_root_is_safe() {
    # Fedora 44's filesystem RPM owns /root as root:root 0550. Keep that
    # package-native boundary intact: requiring the historical 0700 shape
    # blocks every real installed transition, while chmodding it here would
    # create avoidable RPM metadata drift.
    [ -d /root ] && [ ! -L /root ] \
        && [ "$(readlink -e -- /root 2>/dev/null)" = /root ] \
        && [ "$(stat -Lc '%u:%g:%a' -- /root 2>/dev/null)" = 0:0:550 ]
}

CLEANUP_COUNT=0
retire_installer_evidence() {
    local path payload
    installer_evidence_root_is_safe \
        || { log "FAILED: /root evidence boundary is unsafe"; return 1; }
    [ -d /var/log ] && [ ! -L /var/log ] \
        && [ "$(readlink -e -- /var/log 2>/dev/null)" = /var/log ] \
        || { log "FAILED: /var/log evidence boundary is unsafe"; return 1; }

    for path in /root/anaconda-ks.cfg /root/original-ks.cfg; do
        if [ -e "$path" ] || [ -L "$path" ]; then
            [ -f "$path" ] || [ -L "$path" ] \
                || { log "FAILED: installer evidence has an unsafe type: $path"; return 1; }
            rm -f -- "$path" || return 1
            CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
        fi
    done
    for path in /var/log/ks-*.log; do
        [ -e "$path" ] || [ -L "$path" ] || continue
        [ -f "$path" ] || [ -L "$path" ] \
            || { log "FAILED: Kickstart evidence has an unsafe type: $path"; return 1; }
        rm -f -- "$path" || return 1
        CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
    done

    path=/var/log/anaconda
    if [ -e "$path" ] || [ -L "$path" ]; then
        [ -d "$path" ] && [ ! -L "$path" ] \
            && [ "$(readlink -e -- "$path" 2>/dev/null)" = "$path" ] \
            && ! mountpoint -q -- "$path" \
            || { log "FAILED: Anaconda evidence directory is unsafe"; return 1; }
        payload=$(find -P "$path" -xdev -mindepth 1 -print -quit) \
            || { log "FAILED: cannot enumerate Anaconda evidence"; return 1; }
        if [ -n "$payload" ]; then
            find -P "$path" -xdev -depth -mindepth 1 -delete \
                || { log "FAILED: cannot retire Anaconda evidence"; return 1; }
            CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
        fi
        payload=$(find -P "$path" -xdev -mindepth 1 -print -quit) \
            || { log "FAILED: cannot verify Anaconda evidence absence"; return 1; }
        [ -z "$payload" ] \
            || { log "FAILED: Anaconda evidence payload remains"; return 1; }
    fi
    sync -- /root /var/log
    log "retired exact installed Anaconda/Kickstart evidence paths"
}

if [ "$MODE" = security ]; then
    if ! /usr/local/bin/noid-host-identity --install-transition; then
        log "FAILED: installed host-identity transition did not converge"
        exit 1
    fi
fi

if [ "$MODE" = maintenance ]; then
    if ! verify_cleanup_done_marker "$SECURITY_MARKER" \
       || ! matchpathcon -V "$SECURITY_MARKER" >/dev/null; then
        log "FAILED: deferred maintenance requires validated pre-login security cleanup"
        exit 1
    fi
fi

# M41_RUNTIME_MARKER_RECONCILE_BEGIN
# A path-existence systemd condition cannot distinguish durable success from a
# power loss after rename but before final validation. Validate here instead:
# exact good evidence makes this boot a no-op; an incomplete regular/symlink
# marker is retired so the cleanup runs again; an unexpected directory blocks
# GDM for review.
if [ -e "$DONE_MARKER" ] || [ -L "$DONE_MARKER" ]; then
    if verify_cleanup_done_marker "$DONE_MARKER" \
       && matchpathcon -V "$DONE_MARKER" >/dev/null; then
        log "Validated prior cleanup completion marker — no mutation needed"
        exit 0
    fi
    if [ -f "$DONE_MARKER" ] || [ -L "$DONE_MARKER" ]; then
        rm -f -- "$DONE_MARKER"
        sync -- "$STATE_DIR"
        log "Retired incomplete cleanup marker — retrying full convergence"
    else
        log "FAILED: cleanup marker path is neither a regular file nor symlink"
        exit 1
    fi
fi
# M41_RUNTIME_MARKER_RECONCILE_END

# This exact installer-evidence retirement belongs to first convergence, not
# every later boot. A validated completion marker returned above; an absent or
# incomplete marker reaches this point and therefore retries the retirement.
if [ "$MODE" = security ]; then
    retire_installer_evidence || exit 1
fi

# ----- 1. liveuser account + /home/liveuser -----
verify_local_identity_databases_readable() {
    local identity_db
    for identity_db in passwd shadow group gshadow; do
        if ! getent -s files "$identity_db" >/dev/null; then
            log "FAILED: local $identity_db database is not enumerable"
            return 1
        fi
    done
}

trusted_nonwritable_directory() {
    local path=$1 expected_owner=${2:-0:0}
    local metadata mode
    [ -d "$path" ] && [ ! -L "$path" ] \
        && [ "$(readlink -e -- "$path" 2>/dev/null)" = "$path" ] \
        || return 1
    metadata=$(stat -Lc '%u:%g:%a' -- "$path" 2>/dev/null) || return 1
    [ "${metadata%:*}" = "$expected_owner" ] || return 1
    mode=${metadata##*:}
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$mode & 0022) == 0 ))
}

trusted_quarantine_source_parent() {
    local path=$1

    trusted_nonwritable_directory "$path" 0:0 && return 0
    # Fedora deliberately ships the mail-spool parent as root:mail 0775.
    # Accept only that exact native exception: no image-provisioned user is in
    # group mail, this transition runs before user sessions open, and the
    # root-private quarantine plus collision checks remain independent. The
    # recovery directory is not represented as immutable against software an
    # administrator later authorizes to run with the mail group.
    [ "$path" = /var/spool/mail ] \
        && [ -d "$path" ] \
        && [ ! -L "$path" ] \
        && [ "$(readlink -e -- "$path" 2>/dev/null)" = "$path" ] \
        && [ "$(stat -Lc '%U:%G:%a' -- "$path" 2>/dev/null)" = \
            root:mail:775 ]
}

# Fedora Anaconda's live-image payload copies /etc/sysconfig, /usr/lib/grub
# and /boot/grub2 in a second rsync pass with only -rx. The workaround avoids
# copying the lremovexattr capability that KIWI images can place on rsync, but
# it also omits -p/-o/-g/-l: regular files arrive as 0640, directories as
# 0750, and package symlinks are skipped. Restore only package-declared
# ownership/mode/link identity in the two trees whose RPM-native metadata
# remains authoritative. /boot/grub2 is deliberately excluded because NoID Privacy
# owns its stricter 0700 contract.
#
# This is retry-safe across STEP 9b: an installer config that becomes unowned
# after package removal is preserved on a retry, while every still-owned path
# converges again. Regular-file content and timestamps are never restored, so
# legitimate NoID Privacy/admin configuration bytes remain intact.
# M41_LIVE_IMAGE_RPM_METADATA_BEGIN
resolve_local_rpm_user() {
    local wanted=$1
    getent -s files passwd "$wanted" \
        | awk -F: -v wanted="$wanted" '
            $1 == wanted {
                count++
                value = $3
            }
            END {
                if (count == 1 && value ~ /^[0-9]+$/)
                    print value
                else
                    exit 1
            }
        '
}

resolve_local_rpm_group() {
    local wanted=$1
    getent -s files group "$wanted" \
        | awk -F: -v wanted="$wanted" '
            $1 == wanted {
                count++
                value = $3
            }
            END {
                if (count == 1 && value ~ /^[0-9]+$/)
                    print value
                else
                    exit 1
            }
        '
}

reconcile_live_image_rpm_metadata() {
    local scope_a=${1:-/etc/sysconfig}
    local scope_b=${2:-/usr/lib/grub}
    local manifest=""
    local path raw_mode rpm_user rpm_group raw_flags rpm_link extra
    local record prior_record file_type expected_mode flags_value
    local expected_uid expected_gid current_owner current_mode
    local canonical parent canonical_parent
    local changed_count=0
    local absent_count=0
    local key
    declare -A seen_record=()
    declare -A expected_type=()
    declare -A expected_permissions=()
    declare -A expected_owner=()
    declare -A expected_link=()
    declare -A create_link=()

    case "$scope_a:$scope_b" in
        *$'\n'*|*$'\r'*|*$'\t'*)
            log "FAILED: live-image RPM metadata scopes contain control characters"
            return 1
            ;;
    esac
    [[ "$scope_a" == /* && "$scope_b" == /* ]] \
        && [ "$scope_a" != / ] && [ "$scope_b" != / ] \
        && [ "$scope_a" != "$scope_b" ] \
        && [[ "$scope_a/" != "$scope_b/"* ]] \
        && [[ "$scope_b/" != "$scope_a/"* ]] || {
            log "FAILED: live-image RPM metadata scopes overlap or are unsafe"
            return 1
        }
    trusted_nonwritable_directory "$scope_a" \
        && trusted_nonwritable_directory "$scope_b" || {
            log "FAILED: live-image RPM metadata scope is not trusted"
            return 1
        }

    manifest=$(mktemp \
        /var/tmp/.noid-live-image-rpm-metadata.XXXXXXXX) || {
            log "FAILED: cannot stage installed RPM metadata"
            return 1
        }
    RPM_METADATA_CANDIDATE=$manifest
    if ! LC_ALL=C rpm -qa \
            --qf '[%{FILENAMES}\t%{FILEMODES:octal}\t%{FILEUSERNAME}\t%{FILEGROUPNAME}\t%{FILEFLAGS}\t%{FILELINKTOS}\n]' \
            > "$manifest"; then
        log "FAILED: cannot enumerate installed RPM metadata"
        return 1
    fi

    # Phase one validates the complete applicable manifest before any chmod or
    # chown. Identical co-owned directory records are accepted; conflicting
    # package metadata is a fail-closed review state.
    while IFS=$'\t' read -r \
            path raw_mode rpm_user rpm_group raw_flags rpm_link extra; do
        case "$path" in
            "$scope_a"|"$scope_a"/*|"$scope_b"|"$scope_b"/*) ;;
            *) continue ;;
        esac
        if [ -n "${extra:-}" ] \
           || [[ "$path" == *$'\n'* || "$path" == *$'\r'* ]] \
           || ! [[ "$raw_mode" =~ ^[0-7]{5,7}$ ]] \
           || ! [[ "$raw_flags" =~ ^[0-9]+$ ]] \
           || [[ "${rpm_link:-}" == *$'\n'* \
                || "${rpm_link:-}" == *$'\r'* \
                || "${rpm_link:-}" == *$'\t'* ]] \
           || [ -z "$rpm_user" ] || [ -z "$rpm_group" ]; then
            log "FAILED: malformed package metadata in live-image scope"
            return 1
        fi
        flags_value=$((10#$raw_flags))
        # An absent %ghost carries no installed metadata to reconcile.
        if (( (flags_value & 64) != 0 )); then
            continue
        fi

        record=$raw_mode$'\t'$rpm_user$'\t'$rpm_group$'\t'$raw_flags$'\t'${rpm_link:-}
        if [ -n "${seen_record[$path]+present}" ]; then
            prior_record=${seen_record[$path]}
            if [ "$record" != "$prior_record" ]; then
                log "FAILED: conflicting package metadata in live-image scope"
                return 1
            fi
            continue
        fi
        seen_record[$path]=$record

        file_type=$((8#$raw_mode & 0170000))
        case "$file_type" in
            32768) expected_type[$path]=regular ;;
            16384) expected_type[$path]=directory ;;
            40960) expected_type[$path]=symlink ;;
            *)
                log "FAILED: unsupported package object in live-image scope"
                return 1
                ;;
        esac
        printf -v expected_mode '%04o' "$((8#$raw_mode & 07777))"
        expected_permissions[$path]=$expected_mode
        expected_link[$path]=${rpm_link:-}
        if ! expected_uid=$(resolve_local_rpm_user "$rpm_user") \
           || ! expected_gid=$(resolve_local_rpm_group "$rpm_group"); then
            log "FAILED: package metadata names an unresolved local identity"
            return 1
        fi
        expected_owner[$path]=$expected_uid:$expected_gid

        if [ ! -e "$path" ] && [ ! -L "$path" ]; then
            if [ "${expected_type[$path]}" = symlink ]; then
                [ -n "${expected_link[$path]}" ] || {
                    log "FAILED: absent package symlink has no RPM link target"
                    return 1
                }
                parent=${path%/*}
                canonical_parent=$(readlink -e -- "$parent" 2>/dev/null) \
                    || {
                        log "FAILED: absent package symlink parent is not canonical"
                        return 1
                    }
                [ "$canonical_parent" = "$parent" ] || {
                    log "FAILED: absent package symlink parent traverses a link"
                    return 1
                }
                create_link[$path]=1
            else
                # Metadata reconciliation has no authority to recreate
                # regular-file/directory content. This includes valid
                # %missingok/%ghost-like lifecycle states and deliberately
                # retired configurations; the RPM payload audit owns review.
                unset 'seen_record[$path]' 'expected_type[$path]' \
                    'expected_permissions[$path]' 'expected_owner[$path]' \
                    'expected_link[$path]'
                absent_count=$((absent_count + 1))
                continue
            fi
        fi
        if [ -n "${create_link[$path]+present}" ]; then
            continue
        fi
        case "${expected_type[$path]}" in
            regular)
                [ -f "$path" ] && [ ! -L "$path" ] \
                    && canonical=$(readlink -e -- "$path" 2>/dev/null) \
                    && [ "$canonical" = "$path" ] \
                    && [ "$(stat -c '%h' -- "$path" 2>/dev/null)" = 1 ] || {
                        log "FAILED: package regular-file type/canonical path mismatch"
                        return 1
                    }
                ;;
            directory)
                [ -d "$path" ] && [ ! -L "$path" ] \
                    && canonical=$(readlink -e -- "$path" 2>/dev/null) \
                    && [ "$canonical" = "$path" ] || {
                        log "FAILED: package directory type/canonical path mismatch"
                        return 1
                    }
                ;;
            symlink)
                [ -L "$path" ] \
                    && [ "$(stat -c '%h' -- "$path" 2>/dev/null)" = 1 ] || {
                    log "FAILED: package symlink type mismatch"
                    return 1
                }
                [ -n "${expected_link[$path]}" ] \
                    && [ "$(readlink -- "$path")" = \
                        "${expected_link[$path]}" ] || {
                        log "FAILED: package symlink target disagrees with RPM metadata"
                        return 1
                    }
                parent=${path%/*}
                canonical_parent=$(readlink -e -- "$parent" 2>/dev/null) \
                    || {
                        log "FAILED: package symlink parent is not canonical"
                        return 1
                    }
                [ "$canonical_parent" = "$parent" ] || {
                    log "FAILED: package symlink parent traverses a link"
                    return 1
                }
                ;;
        esac
    done < "$manifest"

    [ "${#seen_record[@]}" -gt 0 ] || {
        log "FAILED: installed RPM database has no live-image scope metadata"
        return 1
    }
    if [ "$absent_count" -gt 0 ]; then
        log "Preserving $absent_count absent RPM path(s); metadata-only convergence does not recreate content"
    fi

    # Phase two changes only ownership and permission bits that disagree with
    # the validated package manifest, plus symlinks that Anaconda demonstrably
    # skipped. Symlink modes are not mutable on Linux.
    for key in "${!seen_record[@]}"; do
        if [ -n "${create_link[$key]+present}" ]; then
            ln -s -- "${expected_link[$key]}" "$key" || {
                log "FAILED: cannot restore skipped package symlink"
                return 1
            }
            changed_count=$((changed_count + 1))
        fi
        current_owner=$(stat -c '%u:%g' -- "$key" 2>/dev/null) || {
            log "FAILED: cannot inspect package ownership in live-image scope"
            return 1
        }
        if [ "$current_owner" != "${expected_owner[$key]}" ]; then
            chown -h -- "${expected_owner[$key]}" "$key" || {
                log "FAILED: cannot restore package ownership in live-image scope"
                return 1
            }
            changed_count=$((changed_count + 1))
        fi
        if [ "${expected_type[$key]}" != symlink ]; then
            current_mode=$(stat -c '%04a' -- "$key" 2>/dev/null) || {
                log "FAILED: cannot inspect package mode in live-image scope"
                return 1
            }
            if [ "$current_mode" != "${expected_permissions[$key]}" ]; then
                chmod -- "${expected_permissions[$key]}" "$key" || {
                    log "FAILED: cannot restore package mode in live-image scope"
                    return 1
                }
                changed_count=$((changed_count + 1))
            fi
        fi
    done

    for key in "${!seen_record[@]}"; do
        restorecon -F -- "$key" || {
            log "FAILED: cannot restore package path SELinux label"
            return 1
        }
        if [ "${expected_type[$key]}" != directory ] \
           && [ "$(stat -c '%h' -- "$key" 2>/dev/null)" != 1 ]; then
            log "FAILED: package path link-count postcondition did not converge"
            return 1
        fi
        current_owner=$(stat -c '%u:%g' -- "$key" 2>/dev/null) || return 1
        [ "$current_owner" = "${expected_owner[$key]}" ] || {
            log "FAILED: package ownership postcondition did not converge"
            return 1
        }
        if [ "${expected_type[$key]}" != symlink ]; then
            current_mode=$(stat -c '%04a' -- "$key" 2>/dev/null) || return 1
            [ "$current_mode" = "${expected_permissions[$key]}" ] || {
                log "FAILED: package mode postcondition did not converge"
                return 1
            }
        elif [ "$(readlink -- "$key")" != "${expected_link[$key]}" ]; then
            log "FAILED: package symlink postcondition did not converge"
            return 1
        fi
        matchpathcon -V "$key" >/dev/null || {
            log "FAILED: package path label postcondition did not converge"
            return 1
        }
    done
    sync -- "$scope_a" "$scope_b" || {
        log "FAILED: cannot durably synchronize live-image scope metadata"
        return 1
    }
    rm -f -- "$manifest" || {
        log "FAILED: cannot retire installed RPM metadata manifest"
        return 1
    }
    RPM_METADATA_CANDIDATE=""
    if [ "$changed_count" -gt 0 ]; then
        CLEANUP_COUNT=$((CLEANUP_COUNT + changed_count))
        log "Restored RPM-native metadata on $changed_count live-image path attribute(s)"
    else
        log "RPM-native live-image path metadata already converged"
    fi
}
# M41_LIVE_IMAGE_RPM_METADATA_END

# M41_ANACONDA_INTERACTION_ACCESS_BEGIN
# Anaconda documents /etc/sysconfig/anaconda as a communication file for
# post-install tools, including GNOME Initial Setup. Fedora's Live-image copy
# can independently leave the RPM-owned parent at 0750 and this generated,
# non-RPM-owned file at 0640. In that state GIS receives EACCES before the
# deferred whole-tree RPM metadata repair can run. Converge only this exact
# existing interface before GDM: no bytes are rewritten, no file is created,
# and unexpected owner/type/mode/schema state blocks rather than broadens
# access. The later RPM reconciler remains authoritative for every owned path.
reconcile_anaconda_interaction_config_access() {
    local interaction_path=${1:-/etc/sysconfig/anaconda}
    local interaction_expected_owner=${2:-0:0}
    local parent_expected_owner=${3:-0:0}
    local parent=${interaction_path%/*}
    local parent_state parent_mode path_state path_size
    local file_present=0 changed_count=0

    [[ "$interaction_path" == /* ]] && [ "$interaction_path" != / ] \
        && [ "$parent" != / ] || {
            log "FAILED: Anaconda interaction-config path is unsafe"
            return 1
        }
    [ -d "$parent" ] && [ ! -L "$parent" ] \
        && [ "$(readlink -e -- "$parent" 2>/dev/null)" = "$parent" ] || {
            log "FAILED: Anaconda interaction-config parent is not canonical"
            return 1
        }
    parent_state=$(stat -Lc '%u:%g:%a' -- "$parent" 2>/dev/null) || {
        log "FAILED: cannot inspect Anaconda interaction-config parent"
        return 1
    }
    [ "${parent_state%:*}" = "$parent_expected_owner" ] || {
        log "FAILED: Anaconda interaction-config parent owner differs"
        return 1
    }
    parent_mode=${parent_state##*:}
    case "$parent_mode" in
        750|755) ;;
        *)
            log "FAILED: Anaconda interaction-config parent mode is unexpected"
            return 1
            ;;
    esac

    if [ -e "$interaction_path" ] || [ -L "$interaction_path" ]; then
        [ -f "$interaction_path" ] && [ ! -L "$interaction_path" ] \
            && [ "$(readlink -e -- "$interaction_path" 2>/dev/null)" = \
                "$interaction_path" ] || {
                log "FAILED: Anaconda interaction config is not a canonical regular file"
                return 1
            }
        path_state=$(stat -Lc '%u:%g:%a:%h' -- \
            "$interaction_path" 2>/dev/null) || {
            log "FAILED: cannot inspect Anaconda interaction config"
            return 1
        }
        case "$path_state" in
            "$interaction_expected_owner":640:1|\
                "$interaction_expected_owner":644:1) ;;
            *)
                log "FAILED: Anaconda interaction-config metadata is unexpected"
                return 1
                ;;
        esac
        path_size=$(stat -Lc '%s' -- "$interaction_path" 2>/dev/null) \
            || return 1
        [ "$path_size" -gt 0 ] && [ "$path_size" -le 65536 ] || {
            log "FAILED: Anaconda interaction-config size is unexpected"
            return 1
        }
        if ! awk '
            /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
                section = $0
                gsub(/[[:space:]]/, "", section)
                next
            }
            section == "[General]" &&
                    /^[[:space:]]*post_install_tools_disabled[[:space:]]*=/ {
                value = $0
                sub(/^[^=]*=/, "", value)
                gsub(/[[:space:]]/, "", value)
                if (value !~ /^[01]$/)
                    bad = 1
                count++
            }
            END { exit !(count == 1 && !bad) }
        ' "$interaction_path"; then
            log "FAILED: Anaconda interaction-config control schema is unexpected"
            return 1
        fi
        file_present=1
    fi

    if [ "$parent_mode" != 755 ]; then
        chmod 0755 -- "$parent" || {
            log "FAILED: cannot publish Anaconda interaction-config parent"
            return 1
        }
        changed_count=$((changed_count + 1))
    fi
    if [ "$file_present" -eq 1 ] \
       && [ "$path_state" != "$interaction_expected_owner:644:1" ]; then
        chmod 0644 -- "$interaction_path" || {
            log "FAILED: cannot publish Anaconda interaction config"
            return 1
        }
        changed_count=$((changed_count + 1))
    fi

    restorecon -F -- "$parent" || {
        log "FAILED: cannot restore Anaconda interaction-config parent label"
        return 1
    }
    matchpathcon -V "$parent" >/dev/null || {
        log "FAILED: Anaconda interaction-config parent label differs"
        return 1
    }
    if [ "$file_present" -eq 1 ]; then
        restorecon -F -- "$interaction_path" || {
            log "FAILED: cannot restore Anaconda interaction-config label"
            return 1
        }
        matchpathcon -V "$interaction_path" >/dev/null || {
            log "FAILED: Anaconda interaction-config label differs"
            return 1
        }
        [ "$(stat -Lc '%u:%g:%a:%h' -- \
            "$interaction_path" 2>/dev/null)" = \
            "$interaction_expected_owner:644:1" ] || {
                log "FAILED: Anaconda interaction-config postcondition differs"
                return 1
            }
    fi
    [ "$(stat -Lc '%u:%g:%a' -- "$parent" 2>/dev/null)" = \
        "$parent_expected_owner:755" ] || {
            log "FAILED: Anaconda interaction-config parent postcondition differs"
            return 1
        }
    if [ "$file_present" -eq 1 ]; then
        sync -- "$interaction_path" || return 1
    fi
    sync -- "$parent" || return 1
    if [ "$changed_count" -gt 0 ]; then
        CLEANUP_COUNT=$((CLEANUP_COUNT + changed_count))
        log "Published Anaconda interaction config for unprivileged post-install consumers ($changed_count attribute(s))"
    else
        log "Anaconda interaction-config access already converged"
    fi
}
# M41_ANACONDA_INTERACTION_ACCESS_END

root_password_hash_is_locked() {
    case "$1" in
        '!'*|'*'*) return 0 ;;
        *) return 1 ;;
    esac
}

ensure_local_root_password_locked() {
    local root_passwd_count root_shadow_count
    local root_passwd_entry root_shadow_entry
    local root_name root_uid root_gid root_extra root_shadow_name root_hash

    root_passwd_count=$(awk -F: '$1 == "root" { count++ }
        END { print count + 0 }' /etc/passwd) || return 1
    root_shadow_count=$(awk -F: '$1 == "root" { count++ }
        END { print count + 0 }' /etc/shadow) || return 1
    if [ "$root_passwd_count" -ne 1 ] || [ "$root_shadow_count" -ne 1 ]; then
        log "FAILED: local root identity is missing or duplicated"
        return 1
    fi

    root_passwd_entry=$(getent -s files passwd root) || return 1
    IFS=: read -r root_name _ root_uid root_gid _ _ _ root_extra \
        <<< "$root_passwd_entry"
    if [ "$root_name" != root ] || [ "$root_uid" != 0 ] \
       || [ "$root_gid" != 0 ] || [ -n "$root_extra" ]; then
        log "FAILED: local root passwd entry is malformed"
        return 1
    fi

    root_shadow_entry=$(getent -s files shadow root) || return 1
    IFS=: read -r root_shadow_name root_hash _ _ _ _ _ _ _ root_extra \
        <<< "$root_shadow_entry"
    if [ "$root_shadow_name" != root ] || [ -n "$root_extra" ]; then
        log "FAILED: local root shadow entry is malformed"
        return 1
    fi
    if root_password_hash_is_locked "$root_hash"; then
        return 0
    fi

    log "Unlocked local root password field found — locking it natively"
    /usr/bin/passwd -l root >/dev/null
    root_shadow_entry=$(getent -s files shadow root) || return 1
    IFS=: read -r root_shadow_name root_hash _ \
        <<< "$root_shadow_entry"
    if [ "$root_shadow_name" != root ] \
       || ! root_password_hash_is_locked "$root_hash"; then
        log "FAILED: local root password field remains unlocked"
        return 1
    fi
    CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
}

retire_exact_noid_live_sudoers() {
    local target=$1
    local expected_metadata=${2:-0:0:440:1}
    local expected_parent_owner=${3:-0:0}
    local parent=${target%/*}

    [ -e "$target" ] || [ -L "$target" ] || return 0
    if ! trusted_nonwritable_directory "$parent" "$expected_parent_owner" \
       || [ ! -f "$target" ] || [ -L "$target" ] \
       || [ "$(stat -Lc '%u:%g:%a:%h' -- "$target" 2>/dev/null)" != \
            "$expected_metadata" ] \
       || ! cmp -s -- "$target" \
            <(printf '%s\n' \
                'Defaults:liveuser verifypw=any' \
                'liveuser ALL=(ALL) NOPASSWD: ALL') \
       || ! /usr/sbin/visudo -cf "$target" >/dev/null; then
        log "FAILED: preserving noncanonical M17 Live sudoers state: $target"
        return 1
    fi
    rm -f -- "$target"
    if [ -e "$target" ] || [ -L "$target" ]; then
        log "FAILED: exact M17 Live sudoers policy remains"
        return 1
    fi
    sync -- "$parent"
    CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
    log "Removed exact M17 Live sudoers policy"
}

emit_noid_usbguard_user_ipc_profile() {
    printf '%s\n' \
        'Devices=list,modify,listen' \
        'Policy=list' \
        'Parameters=list,listen' \
        'Exceptions=listen'
}

retire_exact_liveuser_usbguard_ipc() {
    local target=$1
    local expected_metadata=${2:-0:0:600:1}
    local expected_parent_owner=${3:-0:0}
    local parent=${target%/*}

    [ -e "$target" ] || [ -L "$target" ] || return 0
    if ! trusted_nonwritable_directory "$parent" "$expected_parent_owner" \
       || [ ! -f "$target" ] || [ -L "$target" ] \
       || [ "$(stat -Lc '%u:%g:%a:%h' -- "$target" 2>/dev/null)" != \
            "$expected_metadata" ] \
       || ! matchpathcon -V "$target" >/dev/null \
       || ! cmp -s -- "$target" \
            <(emit_noid_usbguard_user_ipc_profile); then
        log "FAILED: preserving noncanonical USBGuard Live-user IPC state"
        return 1
    fi
    rm -f -- "$target"
    if [ -e "$target" ] || [ -L "$target" ]; then
        log "FAILED: exact USBGuard Live-user IPC state remains"
        return 1
    fi
    sync -- "$parent"
    CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
    log "Removed exact USBGuard Live-user IPC state"
}

active_liveuser_sudoers_refs() {
    local sudoers_file=${1:-/etc/sudoers}
    local parse_output parse_line candidate
    local -a sudoers_inputs=()

    [ -f "$sudoers_file" ] && [ ! -L "$sudoers_file" ] \
        && [ -r "$sudoers_file" ] || return 2
    # Fedora's visudo check mode parses the policy in its entirety and reports
    # every file reached through nested @include/@includedir directives. Use
    # that native parse graph instead of assuming all active policy lives in
    # /etc/sudoers.d; an administrator-owned include elsewhere must not escape
    # the fail-closed liveuser postcondition.
    parse_output=$(LC_ALL=C /usr/sbin/visudo -cf "$sudoers_file" 2>&1) \
        || return 2
    while IFS= read -r parse_line; do
        case "$parse_line" in
            *': parsed OK') candidate=${parse_line%: parsed OK} ;;
            *) return 2 ;;
        esac
        [[ "$candidate" == /* ]] || return 2
        [ -f "$candidate" ] && [ ! -L "$candidate" ] \
            && [ -r "$candidate" ] \
            && [ "$(readlink -e -- "$candidate" 2>/dev/null)" = \
                "$candidate" ] || return 2
        sudoers_inputs+=("$candidate")
    done <<< "$parse_output"
    [ "${#sudoers_inputs[@]}" -gt 0 ] || return 2
    awk '
        {
            line = $0
            sub(/^[[:space:]]*/, "", line)
            if (line ~ /^#/)
                next
            sub(/[[:space:]]*#.*/, "", line)
            if (line ~ /(^|[^[:alnum:]_.-])liveuser([^[:alnum:]_.-]|$)/)
                found = 1
        }
        END { exit found ? 0 : 1 }
    ' "${sudoers_inputs[@]}"
}

retire_exact_fedora_live_polkit_rule() {
    local target=$1
    local expected_metadata=${2:-0:0:644:1}
    local expected_parent_owner=${3:-0:0}
    local parent=${target%/*}

    [ -e "$target" ] || [ -L "$target" ] || return 0
    if ! trusted_nonwritable_directory "$parent" "$expected_parent_owner" \
       || [ ! -f "$target" ] || [ -L "$target" ] \
       || [ "$(stat -Lc '%u:%g:%a:%h' -- "$target" 2>/dev/null)" != \
            "$expected_metadata" ] \
       || ! cmp -s -- "$target" <(cat <<'LIVE_POLKIT_EOF'
polkit.addRule(function(action, subject) {
    if (!subject.local)
        return undefined;
    if (subject.user !== 'liveuser')
        return undefined;
    if (action.id.indexOf('org.fedoraproject.pkexec.liveinst') !== 0)
        return undefined;
    return 'yes';
});
LIVE_POLKIT_EOF
); then
        log "FAILED: preserving noncanonical Fedora Live polkit state: $target"
        return 1
    fi
    rm -f -- "$target"
    if [ -e "$target" ] || [ -L "$target" ]; then
        log "FAILED: exact Fedora Live polkit rule remains"
        return 1
    fi
    sync -- "$parent"
    CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
    log "Removed exact signed-Fedora Live-installer polkit rule"
}

emit_noid_liveinst_umask_wrapper() {
    printf '%s\n' \
        '#!/usr/bin/bash' \
        'umask 022' \
        'exec /usr/bin/liveinst "$@"'
}

retire_exact_noid_liveinst_umask_wrapper() {
    local target=$1
    local expected_metadata=${2:-0:0:755:1}
    local expected_parent_owner=${3:-0:0}
    local parent=${target%/*}

    [ -e "$target" ] || [ -L "$target" ] || return 0
    if ! trusted_nonwritable_directory "$parent" "$expected_parent_owner" \
       || [ ! -f "$target" ] || [ -L "$target" ] \
       || [ "$(stat -Lc '%u:%g:%a:%h' -- "$target" 2>/dev/null)" != \
            "$expected_metadata" ] \
       || ! matchpathcon -V "$target" >/dev/null \
       || ! cmp -s -- "$target" \
            <(emit_noid_liveinst_umask_wrapper); then
        log "FAILED: preserving noncanonical M17 Live-installer wrapper"
        return 1
    fi
    rm -f -- "$target"
    if [ -e "$target" ] || [ -L "$target" ]; then
        log "FAILED: exact M17 Live-installer wrapper remains"
        return 1
    fi
    sync -- "$parent"
    CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
    log "Removed exact M17 Live-installer public-umask wrapper"
}

if [ "$MODE" = security ]; then
log "STEP 0: publishing Anaconda post-install interaction config before GDM"
reconcile_anaconda_interaction_config_access
verify_local_identity_databases_readable

local_liveuser_entry() {
    getent -s files passwd liveuser
}

LIVEUSER_ENTRY=$(local_liveuser_entry 2>/dev/null || true)
if [ -n "$LIVEUSER_ENTRY" ]; then
    IFS=: read -r liveuser_name _ liveuser_uid liveuser_gid _ \
        liveuser_home _ liveuser_extra <<< "$LIVEUSER_ENTRY"
    if [ "$liveuser_name" != liveuser ] \
       || ! [[ "$liveuser_uid" =~ ^[0-9]+$ ]] \
       || ! [[ "$liveuser_gid" =~ ^[0-9]+$ ]] \
       || [ "$liveuser_uid" -lt 1000 ] \
       || [ "$liveuser_uid" -ge 60000 ] \
       || [ "$liveuser_home" != /home/liveuser ] \
       || [ -n "$liveuser_extra" ] \
       || [ "$(awk -F: -v uid="$liveuser_uid" \
            '$3 == uid { count++ } END { print count + 0 }' /etc/passwd)" \
            -ne 1 ]; then
        log "FAILED: local liveuser passwd entry is malformed"
        exit 1
    fi
    log "liveuser found in /etc/passwd — removing"
    # Resolve the local numeric UID before deletion, then remove only the
    # account. `userdel -r` trusts the passwd home field and could recursively
    # delete an unexpected path if that field drifted; exact remnants are
    # removed separately below.
    if pgrep -u "$liveuser_uid" >/dev/null 2>&1; then
        pkill -KILL -u "$liveuser_uid" 2>/dev/null || {
            log "FAILED: could not signal every liveuser process"
            exit 1
        }
        for _ in {1..20}; do
            pgrep -u "$liveuser_uid" >/dev/null 2>&1 || break
            sleep 0.1
        done
        if pgrep -u "$liveuser_uid" >/dev/null 2>&1; then
            log "FAILED: liveuser processes remain after SIGKILL"
            exit 1
        fi
    fi
    if ! userdel liveuser 2>/dev/null; then
        if local_liveuser_entry >/dev/null 2>&1; then
            log "FAILED: userdel left the local liveuser account present"
            exit 1
        else
            log "userdel returned nonzero after removing the local account; continuing with exact remnant cleanup"
        fi
    fi
    if local_liveuser_entry >/dev/null 2>&1; then
        log "FAILED: liveuser still exists after userdel"
        exit 1
    fi
    CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
fi

# shadow-utils documents `pwconv` as the lock-aware reconciler that removes
# shadow entries without a matching passwd entry. This covers a power loss
# after passwd publication but before shadow publication without hand-editing
# either authentication database.
if getent -s files shadow liveuser >/dev/null 2>&1; then
    log "Stale local liveuser shadow entry found — reconciling with pwconv"
    pwconv
    if getent -s files shadow liveuser >/dev/null 2>&1; then
        log "FAILED: local liveuser shadow entry remains after pwconv"
        exit 1
    fi
    CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
fi

# USERGROUPS_ENAB normally lets userdel remove the matching private group.
# Recover an empty remnant explicitly, but fail closed on malformed, duplicate
# or member-bearing state rather than deleting another account's membership.
LIVEUSER_GROUP_ENTRY=$(getent -s files group liveuser 2>/dev/null || true)
if [ -n "$LIVEUSER_GROUP_ENTRY" ]; then
    if [[ "$LIVEUSER_GROUP_ENTRY" == *$'\n'* ]]; then
        log "FAILED: duplicate local liveuser group entries require review"
        exit 1
    fi
    IFS=: read -r liveuser_group_name _ liveuser_group_gid \
        liveuser_group_members liveuser_group_extra <<< "$LIVEUSER_GROUP_ENTRY"
    if [ "$liveuser_group_name" != liveuser ] \
       || ! [[ "$liveuser_group_gid" =~ ^[0-9]+$ ]] \
       || [ -n "$liveuser_group_members" ] \
       || [ -n "$liveuser_group_extra" ]; then
        log "FAILED: refusing to remove malformed or member-bearing liveuser group"
        exit 1
    fi
    log "Empty local liveuser group remnant found — removing"
    groupdel liveuser
    if getent -s files group liveuser >/dev/null 2>&1; then
        log "FAILED: local liveuser group remains after groupdel"
        exit 1
    fi
    CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
fi

# `grpconv` is the corresponding lock-aware gshadow reconciler. It is needed
# only for a crash-split orphan whose plain group entry is already absent.
if getent -s files gshadow liveuser >/dev/null 2>&1; then
    log "Stale local liveuser gshadow entry found — reconciling with grpconv"
    grpconv
    if getent -s files gshadow liveuser >/dev/null 2>&1; then
        log "FAILED: local liveuser gshadow entry remains after grpconv"
        exit 1
    fi
    CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
fi

# Fedora livesys-main and M17 intentionally clear root's password in the
# ephemeral Live environment. Anaconda's `rootpw --lock` normally supersedes
# that state on the target; this safety-net makes the password-field lock an
# explicit pre-login postcondition without deleting any underlying hash.
ensure_local_root_password_locked

# A preserved `/home` is a separate, non-Snapper data boundary. The name
# `liveuser` alone therefore is not deletion authority: a reinstall can retain
# a legitimate administrator-owned /home/liveuser even after Anaconda removed
# the passwd entry. Move either exact remnant to a root-private sibling on the
# same filesystem. This removes the account-facing path atomically without
# destroying bytes. A mount at or below the source, an unsafe parent, an
# existing quarantine target or a cross-filesystem rename fails closed and
# blocks GDM for review.
quarantine_exact_liveuser_remnant() {
    local source=$1 quarantine_dir=$2 quarantine_name=$3
    local expected_uid=${4:-0} expected_gid=${5:-0}
    local source_parent=${source%/*}
    local destination="$quarantine_dir/$quarantine_name"
    local expected_quarantine_owner="$expected_uid:$expected_gid"

    if [ ! -e "$source" ] && [ ! -L "$source" ]; then
        # A failed directory sync happens after the same-filesystem rename.
        # On retry, revalidate and sync the already-published recovery target
        # instead of mistaking an unconfirmed publication for a completed
        # no-op. If neither path exists there is genuinely nothing to do.
        if [ ! -e "$destination" ] && [ ! -L "$destination" ]; then
            return 0
        fi
        trusted_quarantine_source_parent "$source_parent" \
            || { log "FAILED: exact liveuser-remnant parent is unsafe: $source_parent"; return 1; }
        trusted_nonwritable_directory \
            "$quarantine_dir" "$expected_quarantine_owner" \
            && [ "$(stat -Lc '%a' -- "$quarantine_dir")" = 700 ] \
            && matchpathcon -V "$quarantine_dir" >/dev/null \
            || { log "FAILED: prior liveuser quarantine is unsafe: $quarantine_dir"; return 1; }
        sync -- "$quarantine_dir" "$source_parent" || {
            log "FAILED: prior liveuser quarantine is not durably published: $destination"
            return 1
        }
        log "Validated durable prior liveuser quarantine: $destination"
        return 0
    fi
    trusted_quarantine_source_parent "$source_parent" \
        || { log "FAILED: exact liveuser-remnant parent is unsafe: $source_parent"; return 1; }
    if findmnt -rn -o TARGET \
            | awk -v source="$source" '
                $0 == source || index($0, source "/") == 1 { found=1 }
                END { exit found ? 0 : 1 }
            '; then
        log "FAILED: preserving mounted liveuser remnant for review: $source"
        return 1
    fi
    if [ -e "$quarantine_dir" ] || [ -L "$quarantine_dir" ]; then
        trusted_nonwritable_directory \
            "$quarantine_dir" "$expected_quarantine_owner" \
            && [ "$(stat -Lc '%a' -- "$quarantine_dir")" = 700 ] \
            && matchpathcon -V "$quarantine_dir" >/dev/null \
            || { log "FAILED: liveuser quarantine is unsafe: $quarantine_dir"; return 1; }
    else
        mkdir -m 0700 -- "$quarantine_dir" \
            && chown "$expected_uid:$expected_gid" -- "$quarantine_dir" \
            && restorecon -F -- "$quarantine_dir" \
            && matchpathcon -V "$quarantine_dir" >/dev/null \
            && trusted_nonwritable_directory \
                "$quarantine_dir" "$expected_quarantine_owner" \
            && [ "$(stat -Lc '%a' -- "$quarantine_dir")" = 700 ] \
            || { log "FAILED: cannot create liveuser quarantine: $quarantine_dir"; return 1; }
        sync -- "$quarantine_dir" "${quarantine_dir%/*}" \
            || { log "FAILED: cannot make liveuser quarantine durable"; return 1; }
    fi
    if [ -e "$destination" ] || [ -L "$destination" ]; then
        log "FAILED: liveuser quarantine target already exists: $destination"
        return 1
    fi

    # none-fail prevents a target created after the check from being
    # overwritten and makes the skipped move itself fail, before the exact
    # postcondition supplies an independent second gate.
    if ! mv --update=none-fail -T -- "$source" "$destination" \
       || [ -e "$source" ] || [ -L "$source" ] \
       || { [ ! -e "$destination" ] && [ ! -L "$destination" ]; }; then
        log "FAILED: could not atomically quarantine liveuser remnant: $source"
        return 1
    fi
    # Directory fsync is sufficient for the same-filesystem rename and avoids
    # dereferencing a quarantined symlink or opening an unusual inode type.
    sync -- "$quarantine_dir" "$source_parent" || {
        log "FAILED: quarantined liveuser remnant is not durably published: $destination"
        return 1
    }
    CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
    log "Quarantined exact liveuser remnant for review: $source -> $destination"
}

quarantine_exact_liveuser_remnant \
    /home/liveuser /home/.noid-liveuser-quarantine home-entry
quarantine_exact_liveuser_remnant \
    /var/spool/mail/liveuser \
    /var/spool/mail/.noid-liveuser-quarantine mail-entry

# ----- 2. Exact Live authorization policies -----
# Anaconda copies the Live root into the target, including M14's named
# notifier ACL. Retire only the byte- and metadata-exact NoID Privacy user profile
# after the Live account has gone. This runs before M14's installed
# first-boot unit, so usbguard never starts with a stale installed identity.
USBGUARD_LIVEUSER_IPC=/etc/usbguard/IPCAccessControl.d/liveuser
retire_exact_liveuser_usbguard_ipc "$USBGUARD_LIVEUSER_IPC"

# Remove only M17's byte-exact rule. Any other active liveuser sudoers
# reference is administrator-owned or unexplained state: preserve it and block
# GDM for review instead of deleting an entire unrelated policy file.
retire_exact_noid_live_sudoers /etc/sudoers.d/liveuser-nopasswd
if active_liveuser_sudoers_refs; then
    log "FAILED: preserving unexplained active liveuser sudoers authorization"
    exit 1
else
    sudoers_scan_rc=$?
    if [ "$sudoers_scan_rc" -ne 1 ]; then
        log "FAILED: cannot parse or inspect the active sudoers policy"
        exit 1
    fi
fi

# Fedora's signed livesys-gnome 0.9.6 hook writes this exact runtime-only rule
# so liveuser can start Anaconda without authentication. It is not RPM-owned,
# so package removal cannot retire it. Preserve and fail closed on any byte or
# metadata drift rather than treating the filename alone as deletion authority.
LIVE_POLKIT_RULE=/usr/share/polkit-1/rules.d/20-livesys-gnome.rules
retire_exact_fedora_live_polkit_rule "$LIVE_POLKIT_RULE"

# M17 shadows the package-owned executable only in the Live PATH so both the
# desktop launcher and direct shell launches give Anaconda/Dracut public
# system-file modes. It is neither needed nor allowed on the installed target.
LIVEINST_UMASK_WRAPPER=/usr/local/bin/liveinst
retire_exact_noid_liveinst_umask_wrapper "$LIVEINST_UMASK_WRAPPER"

# ----- 3. GDM Live automatic/timed login -----
GDM_LOG_DIR=/var/log/gdm
GDM_LOG_GID=""

# Fedora GDM 50.2 owns this path as an RPM ghost and creates/reconciles it at
# daemon startup with gdm_ensure_dir(LOGDIR, 0, gdm_gid, 0711, FALSE). The
# transferred Live root does not contain the ghost directory, so the first
# installed GDM process would otherwise create it only after this pre-login
# transition. On an enforcing target that creation has been observed to
# inherit xdm_log_t even though Fedora's file-context policy requires
# xserver_log_t. Reproduce GDM's exact native metadata contract here, then
# make the SELinux postcondition part of the GDM success gate.
reconcile_gdm_log_directory() {
    local target=$1 parent=${1%/*}
    local expected_uid=0 gdm_group gdm_gid expected_metadata
    local before_metadata="" label_was_canonical=0 changed=0

    if [ ! -d "$parent" ] || [ -L "$parent" ] \
       || [ "$(readlink -e -- "$parent" 2>/dev/null)" != "$parent" ] \
       || [ "$(stat -Lc '%u:%g:%a' -- "$parent" 2>/dev/null)" != \
          0:0:755 ]; then
        log "FAILED: GDM log parent is not canonical root:root 0755: $parent"
        return 1
    fi

    gdm_group=$(getent -s files group gdm) || {
        log "FAILED: local GDM group is unavailable"
        return 1
    }
    if [ "$(printf '%s\n' "$gdm_group" | \
            awk -F: 'NF == 4 && $1 == "gdm" && $3 ~ /^[0-9]+$/ { count++ } END { print count + 0 }')" -ne 1 ]; then
        log "FAILED: local GDM group record is malformed or ambiguous"
        return 1
    fi
    gdm_gid=$(printf '%s\n' "$gdm_group" | \
        awk -F: 'NF == 4 && $1 == "gdm" && $3 ~ /^[0-9]+$/ { print $3 }')
    [[ "$gdm_gid" =~ ^[0-9]+$ ]] || {
        log "FAILED: local GDM group ID is invalid"
        return 1
    }
    GDM_LOG_GID=$gdm_gid
    expected_metadata=$expected_uid:$gdm_gid:711

    if [ -e "$target" ] || [ -L "$target" ]; then
        if [ ! -d "$target" ] || [ -L "$target" ] \
           || [ "$(readlink -e -- "$target" 2>/dev/null)" != "$target" ] \
           || mountpoint -q -- "$target"; then
            log "FAILED: GDM log path has an unsafe type or mount boundary: $target"
            return 1
        fi
        before_metadata=$(stat -Lc '%u:%g:%a' -- "$target" 2>/dev/null) || {
            log "FAILED: cannot inspect GDM log directory metadata"
            return 1
        }
        if matchpathcon -V "$target" >/dev/null 2>&1; then
            label_was_canonical=1
        fi
    else
        if ! mkdir -m 0711 -- "$target"; then
            log "FAILED: cannot create GDM log directory"
            return 1
        fi
        changed=1
    fi

    if ! chown "$expected_uid:$gdm_gid" -- "$target" \
       || ! chmod 0711 -- "$target" \
       || ! restorecon -F -- "$target" \
       || [ "$(stat -Lc '%u:%g:%a' -- "$target" 2>/dev/null)" != \
          "$expected_metadata" ] \
       || ! matchpathcon -V "$target" >/dev/null \
       || ! sync -- "$target" "$parent"; then
        log "FAILED: GDM log directory did not converge to its native metadata and SELinux contract"
        return 1
    fi

    if [ "$before_metadata" != "$expected_metadata" ] \
       || [ "$label_was_canonical" -ne 1 ]; then
        changed=1
    fi
    if [ "$changed" -eq 1 ]; then
        CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
        log "Converged GDM log directory metadata and SELinux label"
    fi
}

reconcile_gdm_log_directory "$GDM_LOG_DIR"

GDM_CUSTOM_CONF=/etc/gdm/custom.conf
if [ ! -f "$GDM_CUSTOM_CONF" ] || [ -L "$GDM_CUSTOM_CONF" ] \
   || [ "$(stat -Lc '%u:%g:%a:%h' -- "$GDM_CUSTOM_CONF" 2>/dev/null)" != \
      0:0:644:1 ]; then
    log "FAILED: GDM custom.conf metadata contract is invalid"
    exit 1
fi

gdm_daemon_key_value_count() {
    local target=$1 wanted_key=$2 wanted_value=$3
    awk -v wanted_key="$wanted_key" -v wanted_value="$wanted_value" '
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
            section = $0
            gsub(/[[:space:]]/, "", section)
            in_daemon = (section == "[daemon]")
            next
        }
        in_daemon && index($0, "=") {
            key = $0
            sub(/=.*/, "", key)
            sub(/^[[:space:]]+/, "", key)
            sub(/[[:space:]]+$/, "", key)
            value = $0
            sub(/^[^=]*=/, "", value)
            sub(/^[[:space:]]+/, "", value)
            sub(/[[:space:]\r]+$/, "", value)
            if (key == wanted_key && value == wanted_value)
                count++
        }
        END { print count + 0 }
    ' "$target"
}

retire_liveuser_gdm_login() {
    local target=$1
    local auto_count timed_count daemon_count candidate=""

    daemon_count=$(grep -cE \
        '^[[:space:]]*\[daemon\][[:space:]]*$' "$target" || true)
    if [ "$daemon_count" -gt 1 ]; then
        log "FAILED: multiple [daemon] sections in $target"
        return 1
    fi
    auto_count=$(gdm_daemon_key_value_count \
        "$target" AutomaticLogin liveuser)
    timed_count=$(gdm_daemon_key_value_count \
        "$target" TimedLogin liveuser)
    if [ "$auto_count" -eq 0 ] && [ "$timed_count" -eq 0 ]; then
        return 0
    fi

    candidate=$(mktemp "${target%/*}/.noid-gdm-login.XXXXXXXX") || {
        log "FAILED: cannot stage GDM Live-login retirement"
        return 1
    }
    RUNTIME_CANDIDATE=$candidate
    if ! cp --preserve=mode,ownership -- "$target" "$candidate"; then
        rm -f -- "$candidate"
        RUNTIME_CANDIDATE=""
        log "FAILED: cannot copy GDM configuration for Live-login retirement"
        return 1
    fi

    if [ "$auto_count" -gt 0 ]; then
        sed -i -E \
            '/^[[:space:]]*\[daemon\][[:space:]]*$/,/^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
                s/^([[:space:]]*)AutomaticLoginEnable[[:space:]]*=[[:space:]]*[Tt]rue[[:space:]]*$/\1AutomaticLoginEnable=False/
                s/^([[:space:]]*)AutomaticLogin[[:space:]]*=[[:space:]]*liveuser[[:space:]]*$/\1# AutomaticLogin=liveuser  ## removed by noid-anaconda-cleanup/
            }' "$candidate"
    fi
    if [ "$timed_count" -gt 0 ]; then
        sed -i -E \
            '/^[[:space:]]*\[daemon\][[:space:]]*$/,/^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
                s/^([[:space:]]*)TimedLoginEnable[[:space:]]*=[[:space:]]*[Tt]rue[[:space:]]*$/\1TimedLoginEnable=False/
                s/^([[:space:]]*)TimedLogin[[:space:]]*=[[:space:]]*liveuser[[:space:]]*$/\1# TimedLogin=liveuser  ## removed by noid-anaconda-cleanup/
                s/^([[:space:]]*)TimedLoginDelay[[:space:]]*=[[:space:]]*1[[:space:]]*$/\1# TimedLoginDelay=1  ## removed by noid-anaconda-cleanup/
            }' "$candidate"
    fi
    if [ "$(gdm_daemon_key_value_count \
            "$candidate" AutomaticLogin liveuser)" -ne 0 ] \
       || [ "$(gdm_daemon_key_value_count \
            "$candidate" TimedLogin liveuser)" -ne 0 ]; then
        rm -f -- "$candidate"
        RUNTIME_CANDIDATE=""
        log "FAILED: staged GDM configuration retains a Live-login target"
        return 1
    fi
    if [ "$(stat -Lc '%u:%g:%a:%h' -- "$candidate" 2>/dev/null)" != \
            0:0:644:1 ] \
       || ! restorecon -F -- "$candidate" \
       || ! matchpathcon -V "$candidate" >/dev/null \
       || ! sync -- "$candidate"; then
        rm -f -- "$candidate"
        RUNTIME_CANDIDATE=""
        log "FAILED: staged GDM Live-login policy failed metadata/label gates"
        return 1
    fi
    if ! mv -fT -- "$candidate" "$target"; then
        rm -f -- "$candidate"
        RUNTIME_CANDIDATE=""
        log "FAILED: cannot publish retired GDM Live-login policy"
        return 1
    fi
    candidate=""
    RUNTIME_CANDIDATE=""
    if ! restorecon -F -- "$target" \
       || ! matchpathcon -V "$target" >/dev/null; then
        log "FAILED: cannot validate published GDM Live-login policy label"
        return 1
    fi
    sync -- "$target" || return 1
    sync -- "${target%/*}" || return 1
    log "GDM Live automatic/timed login target retired atomically"
    CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
}

retire_liveuser_gdm_login "$GDM_CUSTOM_CONF"

# ----- 4. /var/lib/livesys -----
if [ -e /var/lib/livesys ] || [ -L /var/lib/livesys ]; then
    log "/var/lib/livesys present — removing"
    rm -rf -- /var/lib/livesys
    if [ -e /var/lib/livesys ] || [ -L /var/lib/livesys ]; then
        log "FAILED: /var/lib/livesys remains after exact-path cleanup"
        exit 1
    fi
    CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
fi

# ----- 5. livesys-scripts service drop-ins -----
for unit in livesys.service livesys-late.service livesys-gnome.service; do
    for unit_dir in /etc/systemd/system/multi-user.target.wants /etc/systemd/system/graphical.target.wants; do
        if [ -L "$unit_dir/$unit" ]; then
            log "Live-ISO unit symlink: $unit_dir/$unit — removing"
            rm -f "$unit_dir/$unit"
            CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
        elif [ -e "$unit_dir/$unit" ]; then
            log "FAILED: preserving unexpected non-symlink Live unit activation: $unit_dir/$unit"
            exit 1
        fi
    done
done

# ----- 6. Exact AccountsService liveuser cleanup -----
# GDM empty-username regression fix:
#
# Root cause: Anaconda copies liveuser from Live-ISO to installed system.
# noid-user-avatar-backfill.service (M32) ran at multi-user.target BEFORE
# this cleanup at graphical.target → wrote /var/lib/AccountsService/users/
# liveuser with Icon=NoID Privacy. userdel above removes liveuser from
# /etc/passwd but does NOT touch /var/lib/AccountsService/users/<name>
# (AccountsService manages those files; userdel is unaware).
# Net: orphan AccountsService entry → AccountsService daemon still
# enumerates `liveuser` → GDM thinks user exists → does NOT trigger
# gnome-initial-setup → user sees empty Username field instead of
# first-boot wizard.
#
# Defense: remove only the known `/var/lib/AccountsService/users/liveuser`
# remnant after the local account is gone. A generic "user absent right now"
# scan is not sufficient authority to delete unrelated identity state: remote
# identities and deliberately staged local-account recovery can both make a
# valid entry appear orphaned temporarily.
#
# M32 also orders noid-user-avatar-backfill.service to run
# AFTER this cleanup completes (After=noid-anaconda-cleanup.service +
# WantedBy=graphical.target → same target as M41, ordered after) so the
# orphan-creation race is closed at the source. This exact cleanup remains
# defense in depth if that ordering regresses.
ACCOUNTS_USERS_DIR=/var/lib/AccountsService/users
ACCOUNTS_LIVEUSER_ENTRY=$ACCOUNTS_USERS_DIR/liveuser
if [ -e "$ACCOUNTS_LIVEUSER_ENTRY" ] || [ -L "$ACCOUNTS_LIVEUSER_ENTRY" ]; then
    if local_liveuser_entry >/dev/null 2>&1; then
        log "FAILED: refusing AccountsService cleanup while local liveuser exists"
        exit 1
    fi
    trusted_nonwritable_directory "$ACCOUNTS_USERS_DIR" || {
        log "FAILED: AccountsService user-state directory is unsafe"
        exit 1
    }
    if [ ! -f "$ACCOUNTS_LIVEUSER_ENTRY" ] \
       && [ ! -L "$ACCOUNTS_LIVEUSER_ENTRY" ]; then
        log "FAILED: preserving unexpected AccountsService liveuser object"
        exit 1
    fi
    log "Exact AccountsService liveuser remnant found — removing"
    rm -f -- "$ACCOUNTS_LIVEUSER_ENTRY" || {
        log "FAILED: cannot remove exact AccountsService liveuser remnant"
        exit 1
    }
    if [ -e "$ACCOUNTS_LIVEUSER_ENTRY" ] \
       || [ -L "$ACCOUNTS_LIVEUSER_ENTRY" ]; then
        log "FAILED: AccountsService liveuser remnant remains"
        exit 1
    fi
    # Nudge accounts-daemon's inotify watcher only after an actual removal;
    # touching the directory cannot create a regular `users` path.
    touch -- "$ACCOUNTS_USERS_DIR"
    sync -- "$ACCOUNTS_USERS_DIR"
    CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
fi

# ----- 7. GDM initial-setup policy (re-install detection) -----
# GDM 50.1 does not read /etc/gdm/run-initial-setup. Its maintained decision
# is: local display + no AccountsService users + GIS session available +
# daemon/InitialSetupEnable=true. The kernel parameter gnome.initial-setup=
# can explicitly override that decision. Retire the obsolete marker and set
# the real GDM key from the target state:
#   - fresh install (no passwd users, no preserved home): true
#   - re-install (no passwd users, preserved home):       false
#   - normal installed target with passwd users:          true (harmless;
#     GDM's existing-user check prevents GIS)
#
# The preserved-home branch deliberately suppresses GIS because creating a
# second account can disconnect the preserved UID-owned data from its original
# identity. Recovery remains the documented manual recreation of the original
# account with the matching UID.
reconcile_gdm_initial_setup_policy() {
    local human_users=$1
    local home_users=$2
    local gdm_custom_conf=$3
    local legacy_gis_marker=$4
    local candidate=""
    local gis_initial_setup_enable
    local gis_daemon_key_count
    local gis_daemon_line
    local gis_daemon_section_count
    local gis_key_count

    if [ "$human_users" -gt 0 ]; then
        gis_initial_setup_enable=true
        log "User(s) in /etc/passwd ($human_users UID 1000+) — normal login; GIS remains enabled but GDM's existing-user gate suppresses it"
    elif [ "$home_users" -gt 0 ]; then
        gis_initial_setup_enable=false
        log "Re-install detected ($home_users preserved /home/* UID 1000+, 0 /etc/passwd users) — disabling GIS — manual user-recreation needed via root recovery (useradd matching preserved /home/<user> UID)"
    else
        gis_initial_setup_enable=true
        log "Fresh install (0 /etc/passwd users + 0 preserved /home/*) — enabling GDM initial setup"
    fi

    if [ ! -f "$gdm_custom_conf" ] || [ -L "$gdm_custom_conf" ]; then
        log "FAILED: GDM configuration is missing, non-regular or symlinked: $gdm_custom_conf"
        return 1
    fi

    # Reject malformed duplicate daemon groups before changing either the
    # configuration or the legacy marker. The edit itself is prepared beside
    # custom.conf, fully validated, then renamed atomically.
    gis_daemon_section_count=$(grep -cE \
        '^[[:space:]]*\[daemon\][[:space:]]*$' "$gdm_custom_conf" || true)
    if [ "$gis_daemon_section_count" -gt 1 ]; then
        log "FAILED: multiple [daemon] sections in $gdm_custom_conf"
        return 1
    fi
    gis_key_count=$(grep -ciE '^[[:space:]]*InitialSetupEnable[[:space:]]*=' \
        "$gdm_custom_conf" || true)
    gis_daemon_key_count=$(awk -v wanted="$gis_initial_setup_enable" '
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
            section = $0
            gsub(/[[:space:]]/, "", section)
            in_daemon = (section == "[daemon]")
            next
        }
        in_daemon && /^[[:space:]]*InitialSetupEnable[[:space:]]*=/ {
            value = $0
            sub(/^[^=]*=/, "", value)
            gsub(/[[:space:]]/, "", value)
            if (value == wanted)
                count++
        }
        END { print count + 0 }
    ' "$gdm_custom_conf")
    if [ "$gis_key_count" -ne 1 ] || [ "$gis_daemon_key_count" -ne 1 ]; then
        candidate=$(mktemp \
            "${gdm_custom_conf%/*}/.noid-gdm-custom.XXXXXXXX") || {
            log "FAILED: cannot stage GDM policy update"
            return 1
        }
        RUNTIME_CANDIDATE=$candidate
        if ! cp --preserve=mode,ownership -- "$gdm_custom_conf" "$candidate"; then
            rm -f -- "$candidate"
            RUNTIME_CANDIDATE=""
            log "FAILED: cannot copy GDM policy into its staging file"
            return 1
        fi
        sed -i '/^[[:space:]]*InitialSetupEnable[[:space:]]*=/Id' \
            "$candidate"
        if [ "$gis_daemon_section_count" -eq 1 ]; then
            gis_daemon_line=$(grep -nEm1 \
                '^[[:space:]]*\[daemon\][[:space:]]*$' "$candidate" \
                | cut -d: -f1)
            sed -i "${gis_daemon_line}a InitialSetupEnable=${gis_initial_setup_enable}" \
                "$candidate"
        else
            printf '\n[daemon]\nInitialSetupEnable=%s\n' \
                "$gis_initial_setup_enable" >> "$candidate"
        fi

        gis_key_count=$(grep -ciE \
            '^[[:space:]]*InitialSetupEnable[[:space:]]*=' \
            "$candidate" || true)
        gis_daemon_key_count=$(awk -v wanted="$gis_initial_setup_enable" '
            /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
                section = $0
                gsub(/[[:space:]]/, "", section)
                in_daemon = (section == "[daemon]")
                next
            }
            in_daemon && /^[[:space:]]*InitialSetupEnable[[:space:]]*=/ {
                value = $0
                sub(/^[^=]*=/, "", value)
                gsub(/[[:space:]]/, "", value)
                if (value == wanted)
                    count++
            }
            END { print count + 0 }
        ' "$candidate")
        if [ "$gis_key_count" -ne 1 ] \
           || [ "$gis_daemon_key_count" -ne 1 ]; then
            rm -f -- "$candidate"
            RUNTIME_CANDIDATE=""
            log "FAILED: staged GDM InitialSetupEnable policy is invalid"
            return 1
        fi
        if [ "$(stat -Lc '%u:%g:%a:%h' -- "$candidate" 2>/dev/null)" != \
                0:0:644:1 ] \
           || ! restorecon -F -- "$candidate" \
           || ! matchpathcon -V "$candidate" >/dev/null \
           || ! sync -- "$candidate"; then
            rm -f -- "$candidate"
            RUNTIME_CANDIDATE=""
            log "FAILED: staged GDM InitialSetupEnable policy failed metadata/label gates"
            return 1
        fi
        if ! mv -fT -- "$candidate" "$gdm_custom_conf"; then
            rm -f -- "$candidate"
            RUNTIME_CANDIDATE=""
            log "FAILED: cannot publish the staged GDM policy"
            return 1
        fi
        candidate=""
        RUNTIME_CANDIDATE=""
        if ! restorecon -F -- "$gdm_custom_conf" \
           || ! matchpathcon -V "$gdm_custom_conf" >/dev/null \
           || ! sync -- "$gdm_custom_conf" \
           || ! sync -- "${gdm_custom_conf%/*}"; then
            log "FAILED: published GDM InitialSetupEnable policy failed label/durability gates"
            return 1
        fi
        log "Set InitialSetupEnable=$gis_initial_setup_enable in $gdm_custom_conf"
        CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
    fi

    gis_key_count=$(grep -ciE \
        '^[[:space:]]*InitialSetupEnable[[:space:]]*=' \
        "$gdm_custom_conf" || true)
    gis_daemon_key_count=$(awk -v wanted="$gis_initial_setup_enable" '
            /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
                section = $0
                gsub(/[[:space:]]/, "", section)
                in_daemon = (section == "[daemon]")
                next
            }
            in_daemon && /^[[:space:]]*InitialSetupEnable[[:space:]]*=/ {
                value = $0
                sub(/^[^=]*=/, "", value)
                gsub(/[[:space:]]/, "", value)
                if (value == wanted)
                    count++
            }
            END { print count + 0 }
        ' "$gdm_custom_conf")
    if [ "$gis_key_count" -ne 1 ] || [ "$gis_daemon_key_count" -ne 1 ]; then
        log "FAILED: GDM InitialSetupEnable did not converge to $gis_initial_setup_enable"
        return 1
    fi

    if [ -e "$legacy_gis_marker" ] || [ -L "$legacy_gis_marker" ]; then
        rm -f -- "$legacy_gis_marker"
        if [ -e "$legacy_gis_marker" ] || [ -L "$legacy_gis_marker" ]; then
            log "FAILED: obsolete GDM initial-setup marker remains"
            return 1
        fi
        log "Removed obsolete GDM initial-setup marker: $legacy_gis_marker"
        CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
    fi
}

if ! HUMAN_USERS=$(getent -s files passwd \
    | awk -F: '$3 >= 1000 && $3 < 60000 && $1 != "nobody" && $1 != "nfsnobody"' \
    | wc -l); then
    log "FAILED: cannot count regular passwd users; refusing an uninformed GIS decision"
    exit 1
fi
# Re-install detection: any /home/* subdir owned by UID 1000-59999 indicates pre-existing user data
if ! HOME_USERS=$(find /home -mindepth 1 -maxdepth 1 -type d \
    -uid +999 -uid -60000 2>/dev/null | wc -l); then
    log "FAILED: cannot inspect preserved home directories; refusing an uninformed GIS decision"
    exit 1
fi

# ----- 8. Reconcile the actual GDM InitialSetupEnable control -----
reconcile_gdm_initial_setup_policy \
    "$HUMAN_USERS" "$HOME_USERS" \
    "$GDM_CUSTOM_CONF" /etc/gdm/run-initial-setup
if ! restorecon -F -- "$GDM_CUSTOM_CONF" \
   || ! matchpathcon -V "$GDM_CUSTOM_CONF" >/dev/null \
   || [ "$(stat -Lc '%u:%g:%a:%h' -- "$GDM_CUSTOM_CONF" 2>/dev/null)" != \
        0:0:644:1 ]; then
    log "FAILED: GDM custom.conf metadata/label changed during policy publication"
    exit 1
fi

# ----- 9. Exact compose-created NetworkManager profile cleanup -----
# The compose VM can create a persistent, unowned Ethernet profile that is
# copied into the ISO. Absence of its interface on the installed machine is
# not sufficient deletion authority: an unplugged USB/dock NIC or an inactive
# virtual device is also legitimately absent from /sys/class/net. During image
# construction M41 therefore records only the SHA-256 of an exact active,
# auto-generated compose profile. First boot archives a profile only when:
#   1. its complete bytes still match that build-owned digest; and
#   2. the bound interface is absent on the installed system.
# Changed/user-created profiles and every unrecorded profile are left alone.
log "STEP 9: exact compose-created NetworkManager profile cleanup"

nm_connection_value() {
    local profile=$1 wanted_key=$2
    awk -F= -v wanted_key="$wanted_key" '
        /^\[[^]]+\]$/ {
            in_connection = ($0 == "[connection]")
            next
        }
        in_connection {
            key = $1
            sub(/^[[:space:]]+/, "", key)
            sub(/[[:space:]]+$/, "", key)
            if (key == wanted_key) {
                value = substr($0, index($0, "=") + 1)
                sub(/^[[:space:]]+/, "", value)
                sub(/[[:space:]\r]+$/, "", value)
                print value
                exit
            }
        }
    ' "$profile"
}

if [ ! -f "$BUILD_NM_MANIFEST" ] || [ -L "$BUILD_NM_MANIFEST" ] \
   || [ "$(stat -Lc '%u:%g:%a:%h' -- "$BUILD_NM_MANIFEST" \
            2>/dev/null)" != 0:0:644:1 ] \
   || ! matchpathcon -V "$BUILD_NM_MANIFEST" >/dev/null; then
    log "FAILED: compose NetworkManager digest manifest contract is invalid"
    exit 1
fi
declare -A BUILD_NM_DIGEST_SEEN=()
while IFS= read -r build_nm_digest || [ -n "$build_nm_digest" ]; do
    [ -n "$build_nm_digest" ] || continue
    if ! [[ "$build_nm_digest" =~ ^[a-f0-9]{64}$ ]] \
       || [ -n "${BUILD_NM_DIGEST_SEEN[$build_nm_digest]:-}" ]; then
        log "FAILED: compose NetworkManager digest manifest is malformed"
        exit 1
    fi
    BUILD_NM_DIGEST_SEEN[$build_nm_digest]=1
done < "$BUILD_NM_MANIFEST"

NM_CONN_DIR=/etc/NetworkManager/system-connections
GHOST_ARCHIVE_DIR=/etc/NetworkManager/system-connections-removed
GHOST_COUNT=0
if trusted_nonwritable_directory "$NM_CONN_DIR"; then
    for conn in "$NM_CONN_DIR"/*.nmconnection; do
        [ -f "$conn" ] && [ ! -L "$conn" ] || continue
        [ "$(stat -Lc '%u:%g:%a:%h' -- "$conn" 2>/dev/null)" = \
            0:0:600:1 ] || continue
        matchpathcon -V "$conn" >/dev/null || {
            log "FAILED: NetworkManager profile label differs from policy: $conn"
            exit 1
        }
        actual_profile_sha=$(sha256sum -- "$conn" 2>/dev/null) || {
            log "FAILED: cannot hash NetworkManager profile: $conn"
            exit 1
        }
        actual_profile_sha=${actual_profile_sha%% *}
        [ -n "${BUILD_NM_DIGEST_SEEN[$actual_profile_sha]:-}" ] || continue

        ifname=$(nm_connection_value "$conn" interface-name)
        if ! [[ "$ifname" =~ ^[A-Za-z0-9_.:-]+$ ]]; then
            log "FAILED: digest-matched compose profile has an unsafe interface name"
            exit 1
        fi
        [ ! -e "/sys/class/net/$ifname" ] || {
            log "  Keeping digest-matched compose profile: bound interface exists"
            continue
        }

        if [ -e "$GHOST_ARCHIVE_DIR" ] || [ -L "$GHOST_ARCHIVE_DIR" ]; then
            [ -d "$GHOST_ARCHIVE_DIR" ] && [ ! -L "$GHOST_ARCHIVE_DIR" ] \
                || { log "FAILED: NetworkManager archive path is unsafe"; exit 1; }
        else
            install -d -o root -g root -m 0700 -- "$GHOST_ARCHIVE_DIR"
        fi
        [ "$(stat -Lc '%u:%g:%a' -- "$GHOST_ARCHIVE_DIR" \
                2>/dev/null)" = 0:0:700 ] \
            || { log "FAILED: NetworkManager archive metadata is unsafe"; exit 1; }
        if ! restorecon -F -- "$GHOST_ARCHIVE_DIR" \
           || ! matchpathcon -V "$GHOST_ARCHIVE_DIR" >/dev/null; then
            log "FAILED: NetworkManager archive directory label differs"
            exit 1
        fi

        base=${conn##*/}
        [ "$base" = "$ifname.nmconnection" ] || {
            log "FAILED: digest-matched compose profile name drifted"
            exit 1
        }
        archive_path="$GHOST_ARCHIVE_DIR/${base}.compose-ghost-${actual_profile_sha:0:16}"
        if [ -e "$archive_path" ] || [ -L "$archive_path" ]; then
            log "FAILED: NetworkManager compose-profile archive collision"
            exit 1
        fi
        log "  Archiving exact compose profile whose bound interface is absent"
        mv -T -- "$conn" "$archive_path"
        if ! restorecon -F -- "$archive_path" \
           || ! matchpathcon -V "$archive_path" >/dev/null \
           || [ ! -f "$archive_path" ] || [ -L "$archive_path" ] \
           || [ "$(stat -Lc '%u:%g:%a:%h' -- "$archive_path" \
                    2>/dev/null)" != 0:0:600:1 ] \
           || [ "$(sha256sum -- "$archive_path" | awk '{print $1}')" != \
                "$actual_profile_sha" ]; then
            log "FAILED: archived compose profile failed its postcondition"
            exit 1
        fi
        CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
        GHOST_COUNT=$((GHOST_COUNT + 1))
        sync -- "$archive_path"
        sync -- "$GHOST_ARCHIVE_DIR"
    done
elif [ -e "$NM_CONN_DIR" ] || [ -L "$NM_CONN_DIR" ]; then
    log "FAILED: NetworkManager system-connections path is unsafe"
    exit 1
fi

# Reload NM if a compose profile was archived so in-memory state matches disk.
#
# The archival itself is the durable, security-relevant step: the file is
# already gone from system-connections and verified in the root-private archive.
# The reload only shortens the window in which a still-running daemon keeps the
# retired profile in memory. NetworkManager re-reads system-connections on every
# start, so an inactive daemon needs no reload at all — and must not be treated
# as a failure. Without this gate the whole cleanup exits non-zero on any boot
# where NetworkManager did not come up, which propagates through the hard
# gdm.service drop-in and removes the graphical login entirely.
# A target reaches this branch on first boot when its interface name differs
# from the compose VM's. When the names coincide, the still-applicable profile
# is deliberately retained and GHOST_COUNT remains zero.
if [ "$GHOST_COUNT" -gt 0 ]; then
    if ! systemctl is-active --quiet NetworkManager.service; then
        log "NetworkManager inactive; the archived compose profile is already off disk and applies at its next start"
    elif command -v nmcli >/dev/null 2>&1; then
        if ! nmcli connection reload; then
            log "FAILED: nmcli could not reload after compose-profile archival"
            exit 1
        fi
    elif ! systemctl reload NetworkManager.service; then
        log "FAILED: compose profile archived and neither nmcli nor NetworkManager reload succeeded"
        exit 1
    else
        log "nmcli unavailable; NetworkManager.service reload synchronized the archive"
    fi
fi
fi

if [ "$MODE" = maintenance ]; then
# ----- 9a. Restore RPM-native metadata lost by Anaconda live-image rsync -----
log "STEP 9a: reconciling package metadata after live-image transfer"
reconcile_live_image_rpm_metadata

# ----- 9b. installer-only package cleanup -----
# The installed workstation does not need the Anaconda UI/core or the Lorax
# image-build tooling. Removing only four leaves was incomplete: the reference
# host still carried Anaconda core/GUI/TUI/widgets and Lorax, and
# anaconda-install-env-deps was required by lorax-lmc-novirt so it returned.
# The whole known installer set is therefore removed together; internal
# dependency cycles are valid when every member is in one transaction.
#
# Use DNF5 rather than calling rpm directly. DNF5 owns the installed-package
# reason/history database and its documentation requires that state to be
# changed through the CLI/API. `--no-autoremove` keeps this first transaction
# scoped to the named installer stack; Step 9c separately converges deliberate
# leaf reasons before resolving its former dependencies. Cache-only operation
# is sufficient for installed-package removal and preserves the service's
# network-denied boundary.
log "STEP 9b: removing the post-install Anaconda/Lorax/live-install package set"
INSTALLER_PKGS=()
for pkg in \
    anaconda anaconda-core anaconda-gui anaconda-tui anaconda-widgets \
    anaconda-widgets-devel anaconda-webui anaconda-live anaconda-dracut \
    anaconda-realmd anaconda-install-env-deps anaconda-install-img-deps \
    lorax lorax-lmc-novirt lorax-lmc-virt lorax-templates-generic \
    lorax-templates-rhel lorax-docs livesys-scripts; do
    if rpm -q "$pkg" >/dev/null 2>&1; then
        INSTALLER_PKGS+=("$pkg")
    fi
done
if [ "${#INSTALLER_PKGS[@]}" -gt 0 ]; then
    log "  Removing installer-only packages: ${INSTALLER_PKGS[*]}"
    INSTALLER_REMOVE_LOG=$(mktemp -t noid-installer-remove.XXXXXX)
    if ! ( umask 022; /usr/bin/dnf5 --cacheonly --assumeyes remove \
            --no-autoremove "${INSTALLER_PKGS[@]}" ) \
            > "$INSTALLER_REMOVE_LOG" 2>&1; then
        log "FAILED: DNF5 installer-package transaction failed"
        forward_log_tail "$INSTALLER_REMOVE_LOG" dnf-installer-remove
        rm -f -- "$INSTALLER_REMOVE_LOG"
        exit 1
    fi
    forward_log_tail "$INSTALLER_REMOVE_LOG" dnf-installer-remove
    rm -f -- "$INSTALLER_REMOVE_LOG"
    for pkg in "${INSTALLER_PKGS[@]}"; do
        if rpm -q "$pkg" >/dev/null 2>&1; then
            log "FAILED: $pkg remains installed after DNF5 transaction"
            exit 1
        fi
        CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
    done
fi

# M17 deliberately changes livesys-scripts' %config(noreplace)
# /etc/sysconfig/livesys so the Live ISO starts the GNOME session. A normal
# RPM erase correctly preserves that modified file as livesys.rpmsave, but
# carrying the known build-only value into the installed workstation creates
# false config-drift evidence forever. Remove only either exact byte shape
# that M17 can produce; preserve and report anything else as possible
# administrator-owned state.
LIVESYS_RPMSAVE=/etc/sysconfig/livesys.rpmsave
if [ -e "$LIVESYS_RPMSAVE" ] || [ -L "$LIVESYS_RPMSAVE" ]; then
    if [ -f "$LIVESYS_RPMSAVE" ] && [ ! -L "$LIVESYS_RPMSAVE" ] \
       && { cmp -s "$LIVESYS_RPMSAVE" \
                <(printf '%s\n' 'livesys_session=gnome') \
            || cmp -s "$LIVESYS_RPMSAVE" \
                <(printf '%s\n' \
                    '# Session type for desktop environment livesys setup' \
                    'livesys_session=gnome'); }; then
        rm -f -- "$LIVESYS_RPMSAVE"
        CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
        log "  Removed exact build-only Livesys .rpmsave"
    else
        log "  REVIEW: preserving noncanonical $LIVESYS_RPMSAVE"
    fi
fi

# ----- 9c. DNF reason convergence + orphan cleanup -----
# Fedora @workstation-product-environment + Anaconda installer pull in
# weak dependencies that can become orphans once STEP 9b removes the live-ISO
# installer/build stack and the post-install package set stabilizes. DNF
# autoremove uses DNF5's system-state reason tracking. Packages copied from the
# composed Live image retain dependency/external reasons on the installed
# target even when the Kickstart selected them explicitly. Therefore every
# intentional leaf below must first converge to the native `user` reason.
#
# Intentional leaves (12 workstation/runtime packages):
#   openssl                  — TLS CLI (cert-debug, openssl s_client, etc.)
#   gdb, gdb-headless        — debugger (reverse-eng + security research)
#   binutils                 — objdump/strings/readelf/ld (binary-audit)
#   ctags                    — code-navigation (editor/CLI)
#   source-highlight         — pager syntax-highlight (less/git diff)
#   smartmontools            — SMART-capable storage-health monitoring
#   smartmontools-selinux    — SELinux policy for smartmontools
#   kexec-tools              — kexec for kernel-debug / live-rescue
#   hfsplus-tools            — Mac HFS+ mount support (USB-stick recovery)
#   python3-libdnf5          — VSCodium metadata-key cache-path API (M08)
#   dbus-tools               — GTK session activation environment API (M19)
#
# `dnf5 mark user` is the maintained ownership mechanism. A transaction-local
# --exclude would hide the first-boot symptom but leave the same packages
# incorrectly eligible for the user's next ordinary `dnf autoremove`.
#
# Failure-atomic: lock contention, broken metadata or any other autoremove
# failure leaves maintenance without its done marker. The security transition
# and GDM remain available, while the separately ordered maintenance unit
# retries on the next boot instead of sealing incomplete package hygiene as
# success. M25 noid-update-all still reports any remaining orphan count.
log "STEP 9c: converging 12 intentional leaf-package reasons before autoremove"
PERSISTENT_LEAF_PKGS=(
    openssl
    gdb
    gdb-headless
    binutils
    ctags
    source-highlight
    smartmontools
    smartmontools-selinux
    kexec-tools
    hfsplus-tools
    python3-libdnf5
    dbus-tools
)

# M08's offline VSCodium trust helper imports libdnf5 at every graphical login
# and in the pre-metadata DNF action. Missing it would both fail the user unit
# and make ordinary DNF transactions fail before they could repair the package.
if ! rpm -q python3-libdnf5 >/dev/null 2>&1; then
    log "FAILED: required VSCodium trust runtime python3-libdnf5 is absent before autoremove"
    exit 1
fi

# M19's topology-gated post-Shell helper must update both the systemd user
# manager and D-Bus activation environment. The helper is not RPM-packaged, so
# bind its Fedora runtime explicitly before DNF can classify dependency reasons.
GSK_ACTIVATION_UPDATER=/usr/bin/dbus-update-activation-environment
# M41_GSK_RUNTIME_GATE_BEGIN
if ! rpm -q dbus-tools >/dev/null 2>&1 \
   || [ ! -x "$GSK_ACTIVATION_UPDATER" ] \
   || [ -L "$GSK_ACTIVATION_UPDATER" ] \
   || [ "$(rpm -qf --qf '%{NAME}' \
        "$GSK_ACTIVATION_UPDATER" 2>/dev/null || true)" != \
        dbus-tools ]; then
    log "FAILED: required GTK session activation runtime dbus-tools is absent or invalid before autoremove"
    exit 1
fi
# M41_GSK_RUNTIME_GATE_END

# rpmdb-WAL hygiene (F44 SQLite-WAL quirk)
sync

MARK_LOG=$(mktemp -t noid-mark-user.XXXXXX)
if ! ( umask 022; /usr/bin/dnf5 --cacheonly --assumeyes mark user \
        --skip-unavailable "${PERSISTENT_LEAF_PKGS[@]}" ) \
        > "$MARK_LOG" 2>&1; then
    log "FAILED: could not mark intentional leaf packages as user-installed"
    forward_log_tail "$MARK_LOG" dnf-mark
    rm -f "$MARK_LOG"
    exit 1
fi
rm -f "$MARK_LOG"

# M41_AUTOREMOVE_TRANSACTION_BEGIN
AUTOREMOVE_BEFORE=$(rpm -qa 2>/dev/null | wc -l)
TMPLOG=$(mktemp -t noid-autoremove.XXXXXX)
if ( umask 022; /usr/bin/dnf5 --cacheonly autoremove -y ) \
        > "$TMPLOG" 2>&1; then
    AUTOREMOVE_AFTER=$(rpm -qa 2>/dev/null | wc -l)
    AUTOREMOVE_COUNT=$((AUTOREMOVE_BEFORE - AUTOREMOVE_AFTER))
    log "  [OK] autoremove complete — $AUTOREMOVE_COUNT package(s) removed (before=$AUTOREMOVE_BEFORE after=$AUTOREMOVE_AFTER)"
    CLEANUP_COUNT=$((CLEANUP_COUNT + AUTOREMOVE_COUNT))
else
    log "FAILED: dnf autoremove failed — package hygiene remains retryable"
    forward_log_tail "$TMPLOG" dnf
    rm -f "$TMPLOG"
    exit 1
fi
# Append dnf output to journal (last 50 lines max — full output otherwise floods)
forward_log_tail "$TMPLOG" dnf
rm -f "$TMPLOG"
# M41_AUTOREMOVE_TRANSACTION_END

# ----- 9z. Record installed-system first-boot time in release metadata -----
# /etc/noid-privacy-release and /var/lib/noid-privacy/version are written at
# image BUILD time (Module 99 %post runs during squashfs construction, not at
# end-user install), so their INSTALL_DATE / install_date fields carry the BUILD
# date for every installed system. Re-stamp them once here with the system
# clock observed on the installed system's first boot. This is the closest
# image-owned installation-time evidence; it is not represented as a trusted
# timestamp or as the Anaconda transaction's exact completion time.
replace_exact_metadata_key() {
    local target=$1 key=$2 value=$3
    local parent=${target%/*} base=${target##*/}
    local candidate parent_metadata parent_mode

    [ -f "$target" ] && [ ! -L "$target" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' -- "$target" 2>/dev/null)" = \
            0:0:644:1 ] || {
        log "FAILED: release metadata target is unsafe: $target"
        return 1
    }
    [ "$(grep -cE "^${key}=" "$target" 2>/dev/null || true)" -eq 1 ] || {
        log "FAILED: release metadata key is missing or duplicated: $key"
        return 1
    }
    [ -d "$parent" ] && [ ! -L "$parent" ] || {
        log "FAILED: release metadata parent is unsafe: $parent"
        return 1
    }
    parent_metadata=$(stat -Lc '%u:%g:%a' -- "$parent" 2>/dev/null) || {
        log "FAILED: cannot inspect release metadata parent: $parent"
        return 1
    }
    case "$parent_metadata" in
        0:0:*) parent_mode=${parent_metadata##*:} ;;
        *)
            log "FAILED: release metadata parent is not root-owned: $parent"
            return 1
            ;;
    esac
    if ! [[ "$parent_mode" =~ ^[0-7]{3,4}$ ]] \
       || (( (8#$parent_mode & 0022) != 0 )); then
        log "FAILED: release metadata parent is group/world-writable: $parent"
        return 1
    fi

    candidate=$(mktemp "$parent/.${base}.XXXXXXXX") || {
        log "FAILED: cannot stage release metadata: $target"
        return 1
    }
    RUNTIME_CANDIDATE=$candidate
    if ! sed "s|^${key}=.*$|${key}=${value}|" "$target" > "$candidate"; then
        rm -f -- "$candidate"
        RUNTIME_CANDIDATE=""
        log "FAILED: cannot render release metadata: $target"
        return 1
    fi
    chmod 0644 "$candidate"
    chown root:root "$candidate"
    if ! restorecon -F -- "$candidate" \
       || ! matchpathcon -V "$candidate" >/dev/null; then
        rm -f -- "$candidate"
        RUNTIME_CANDIDATE=""
        log "FAILED: cannot validate staged release metadata label: $target"
        return 1
    fi
    if [ "$(grep -cFx "${key}=${value}" "$candidate" || true)" -ne 1 ]; then
        rm -f -- "$candidate"
        RUNTIME_CANDIDATE=""
        log "FAILED: staged release metadata did not converge: $target"
        return 1
    fi
    sync -- "$candidate"
    if ! mv -fT -- "$candidate" "$target"; then
        rm -f -- "$candidate"
        RUNTIME_CANDIDATE=""
        log "FAILED: cannot publish release metadata: $target"
        return 1
    fi
    candidate=""
    RUNTIME_CANDIDATE=""
    if ! restorecon -F -- "$target" \
       || ! matchpathcon -V "$target" >/dev/null; then
        log "FAILED: cannot validate published release metadata label: $target"
        return 1
    fi
    [ -f "$target" ] && [ ! -L "$target" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' -- "$target" 2>/dev/null)" = \
            0:0:644:1 ] \
        && [ "$(grep -cFx "${key}=${value}" "$target" || true)" -eq 1 ] || {
        log "FAILED: published release metadata postcondition failed: $target"
        return 1
    }
    sync -- "$target"
    sync -- "$parent"
}

NOID_INSTALL_NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
replace_exact_metadata_key \
    /etc/noid-privacy-release INSTALL_DATE "$NOID_INSTALL_NOW"
replace_exact_metadata_key \
    /var/lib/noid-privacy/version install_date "$NOID_INSTALL_NOW"
log "  [OK] installed-system first-boot time recorded (${NOID_INSTALL_NOW})"
if ! verify_cleanup_done_marker "$SECURITY_MARKER" \
   || ! matchpathcon -V "$SECURITY_MARKER" >/dev/null; then
    log "FAILED: pre-login security evidence changed during deferred maintenance"
    exit 1
fi
fi

if [ "$MODE" = security ]; then
# ----- 10. Security postconditions + done marker -----
# Never persist success if the privilege-bearing live account, a sudoers
# grant, the Live installer authorization, root-password unlock, or automatic
# login survived an earlier operation.
verify_local_identity_databases_readable
ensure_local_root_password_locked
if local_liveuser_entry >/dev/null 2>&1; then
    log "FAILED postcondition: liveuser account still exists"
    exit 1
fi
if getent -s files shadow liveuser >/dev/null 2>&1 \
   || getent -s files group liveuser >/dev/null 2>&1 \
   || getent -s files gshadow liveuser >/dev/null 2>&1; then
    log "FAILED postcondition: local liveuser authentication state still exists"
    exit 1
fi
for liveuser_remnant in /home/liveuser /var/spool/mail/liveuser; do
    if [ -e "$liveuser_remnant" ] || [ -L "$liveuser_remnant" ]; then
        log "FAILED postcondition: exact liveuser remnant still exists"
        exit 1
    fi
done
if [ -e /var/lib/livesys ] || [ -L /var/lib/livesys ]; then
    log "FAILED postcondition: /var/lib/livesys still exists"
    exit 1
fi
for unit in livesys.service livesys-late.service livesys-gnome.service; do
    for unit_dir in /etc/systemd/system/multi-user.target.wants \
        /etc/systemd/system/graphical.target.wants; do
        if [ -e "$unit_dir/$unit" ] || [ -L "$unit_dir/$unit" ]; then
            log "FAILED postcondition: Live unit activation still exists: $unit_dir/$unit"
            exit 1
        fi
    done
done
if active_liveuser_sudoers_refs; then
    log "FAILED postcondition: active sudoers entry still references liveuser"
    exit 1
else
    sudoers_postcondition_rc=$?
    if [ "$sudoers_postcondition_rc" -ne 1 ]; then
        log "FAILED postcondition: cannot parse or inspect active sudoers policy"
        exit 1
    fi
fi
if [ -e "$LIVE_POLKIT_RULE" ] || [ -L "$LIVE_POLKIT_RULE" ]; then
    log "FAILED postcondition: Fedora Live-installer polkit rule still exists"
    exit 1
fi
if [ -e "$LIVEINST_UMASK_WRAPPER" ] \
   || [ -L "$LIVEINST_UMASK_WRAPPER" ]; then
    log "FAILED postcondition: M17 Live-installer wrapper still exists"
    exit 1
fi
if [ -e "$USBGUARD_LIVEUSER_IPC" ] \
   || [ -L "$USBGUARD_LIVEUSER_IPC" ]; then
    log "FAILED postcondition: USBGuard Live-user IPC state still exists"
    exit 1
fi
if [ -e "$ACCOUNTS_LIVEUSER_ENTRY" ] \
   || [ -L "$ACCOUNTS_LIVEUSER_ENTRY" ]; then
    log "FAILED postcondition: AccountsService liveuser state still exists"
    exit 1
fi
if [ -e /etc/gdm/run-initial-setup ] \
   || [ -L /etc/gdm/run-initial-setup ]; then
    log "FAILED postcondition: obsolete GDM initial-setup marker still exists"
    exit 1
fi
if [ "$(gdm_daemon_key_value_count \
        "$GDM_CUSTOM_CONF" AutomaticLogin liveuser)" -ne 0 ] \
   || [ "$(gdm_daemon_key_value_count \
        "$GDM_CUSTOM_CONF" TimedLogin liveuser)" -ne 0 ]; then
    log "FAILED postcondition: GDM still targets liveuser for automatic/timed login"
    exit 1
fi
if [ -z "$GDM_LOG_GID" ] \
   || [ ! -d "$GDM_LOG_DIR" ] || [ -L "$GDM_LOG_DIR" ] \
   || [ "$(readlink -e -- "$GDM_LOG_DIR" 2>/dev/null)" != \
      "$GDM_LOG_DIR" ] \
   || [ "$(stat -Lc '%u:%g:%a' -- "$GDM_LOG_DIR" 2>/dev/null)" != \
      "0:$GDM_LOG_GID:711" ] \
   || ! matchpathcon -V "$GDM_LOG_DIR" >/dev/null; then
    log "FAILED postcondition: GDM log directory contract drifted before login"
    exit 1
fi

# M11's early system preset owns the Anaconda transaction outcome and prevents
# Fedora presets from selecting ordinary chronyd.service. Reconcile that native
# contract once more immediately before the completion marker as defense in
# depth. Enablement alone is insufficient for the current boot: stop the
# ordinary provider, start the restricted provider, and verify both persistent
# and active state. Failure leaves this first-boot unit retryable and continues
# to gate GDM.
if ! systemctl disable --now chronyd.service; then
    log "FAILED postcondition: could not disable/stop ordinary chronyd.service"
    exit 1
fi
if ! systemctl enable --now chronyd-restricted.service; then
    log "FAILED postcondition: could not enable/start chronyd-restricted.service"
    exit 1
fi
if systemctl is-enabled chronyd.service >/dev/null 2>&1 \
   || ! systemctl is-enabled chronyd-restricted.service >/dev/null 2>&1 \
   || systemctl is-active chronyd.service >/dev/null 2>&1 \
   || ! systemctl is-active chronyd-restricted.service >/dev/null 2>&1; then
    log "FAILED postcondition: restricted chronyd provider selection drifted"
    exit 1
fi
fi

# M41_RUNTIME_MARKER_PUBLICATION_BEGIN
# Publish the existence-gated marker atomically. Until final bytes, metadata,
# SELinux context and durability all pass, the EXIT/signal cleanup owns and
# removes either the candidate or the published path so a retry is never
# suppressed by incomplete success evidence.
DONE_VALUE=$(date -u +"%Y-%m-%dT%H:%M:%SZ cleanup_count=$CLEANUP_COUNT")
DONE_CANDIDATE=$(mktemp "$STATE_DIR/.anaconda-cleanup.done.XXXXXXXX") || {
    log "FAILED: cannot stage cleanup completion marker"
    exit 1
}
if ! printf '%s\n' "$DONE_VALUE" > "$DONE_CANDIDATE" \
   || ! chmod 0644 "$DONE_CANDIDATE" \
   || ! chown root:root "$DONE_CANDIDATE" \
   || ! restorecon -F -- "$DONE_CANDIDATE" \
   || ! matchpathcon -V "$DONE_CANDIDATE" >/dev/null \
   || ! verify_cleanup_done_marker "$DONE_CANDIDATE" "$DONE_VALUE" \
   || ! sync -- "$DONE_CANDIDATE"; then
    log "FAILED: staged cleanup completion marker failed its contract"
    exit 1
fi

# Ignore termination only across rename and registration of the final path.
# Once DONE_PUBLISHED=1, ordinary traps resume and remove that exact path on
# every incomplete exit.
trap '' HUP INT TERM
if ! mv -fT -- "$DONE_CANDIDATE" "$DONE_MARKER"; then
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    log "FAILED: cannot publish cleanup completion marker"
    exit 1
fi
DONE_CANDIDATE=""
DONE_PUBLISHED=1
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if ! restorecon -F -- "$DONE_MARKER" \
   || ! matchpathcon -V "$DONE_MARKER" >/dev/null \
   || ! verify_cleanup_done_marker "$DONE_MARKER" "$DONE_VALUE" \
   || ! sync -- "$DONE_MARKER" \
   || ! sync -- "$STATE_DIR"; then
    log "FAILED: published cleanup completion marker is invalid"
    exit 1
fi
DONE_PUBLISHED=0
trap - EXIT HUP INT TERM
# M41_RUNTIME_MARKER_PUBLICATION_END

log "Cleanup complete — $CLEANUP_COUNT counted item(s) processed"
exit 0
CLEANUP_EOF

CLEANUP_EXPECTED_SHA=$(candidate_sha256 "$CLEANUP_SOURCE")
publish_root_file "$CLEANUP_SOURCE" \
    /usr/libexec/noid-anaconda-cleanup.sh 0755
rm -f -- "$CLEANUP_SOURCE" \
    || fail "cannot retire the cleanup-script source candidate"
CLEANUP_SOURCE=""

log "  [OK] /usr/libexec/noid-anaconda-cleanup.sh installed"

# ============================================================================
# STEP 1b: Record exact compose-created NetworkManager profile bytes
# ============================================================================
log "STEP 1b: recording exact compose-created NetworkManager profile bytes"

compose_nm_connection_value() {
    local profile=$1 wanted_key=$2
    awk -F= -v wanted_key="$wanted_key" '
        /^\[[^]]+\]$/ {
            in_connection = ($0 == "[connection]")
            next
        }
        in_connection {
            key = $1
            sub(/^[[:space:]]+/, "", key)
            sub(/[[:space:]]+$/, "", key)
            if (key == wanted_key) {
                value = substr($0, index($0, "=") + 1)
                sub(/^[[:space:]]+/, "", value)
                sub(/[[:space:]]+$/, "", value)
                print value
                exit
            }
        }
    ' "$profile"
}

is_compose_nm_profile() {
    local profile=$1
    local sys_class_net=${2:-/sys/class/net}
    local expected_metadata=${3:-0:0:600:1}
    local base connection_id connection_type ifname

    [ -f "$profile" ] && [ ! -L "$profile" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' -- "$profile" 2>/dev/null)" = \
            "$expected_metadata" ] || return 1
    rpm -qf -- "$profile" >/dev/null 2>&1 && return 1
    base=${profile##*/}
    [[ "$base" =~ ^[A-Za-z0-9_.:-]+\.nmconnection$ ]] || return 1
    connection_id=$(compose_nm_connection_value "$profile" id)
    connection_type=$(compose_nm_connection_value "$profile" type)
    ifname=$(compose_nm_connection_value "$profile" interface-name)
    [ "$connection_type" = ethernet ] \
        && [[ "$ifname" =~ ^[A-Za-z0-9_.:-]+$ ]] \
        && [ "$connection_id" = "$ifname" ] \
        && [ "$base" = "$ifname.nmconnection" ] \
        && [ -e "$sys_class_net/$ifname" ]
}

[ -d /usr/lib ] && [ ! -L /usr/lib ] \
    && [ "$(readlink -e -- /usr/lib 2>/dev/null)" = /usr/lib ] \
    || fail "/usr/lib publication boundary is not a canonical real directory"
USR_LIB_METADATA=$(stat -Lc '%u:%g:%a' -- /usr/lib 2>/dev/null) \
    || fail "cannot inspect /usr/lib publication boundary"
case "$USR_LIB_METADATA" in
    0:0:*) USR_LIB_MODE=${USR_LIB_METADATA##*:} ;;
    *) fail "/usr/lib publication boundary is not root-owned" ;;
esac
[[ "$USR_LIB_MODE" =~ ^[0-7]{3,4}$ ]] \
    && (( (8#$USR_LIB_MODE & 0022) == 0 )) \
    || fail "/usr/lib publication boundary is group/other-writable"
if [ -e /usr/lib/noid-privacy ] || [ -L /usr/lib/noid-privacy ]; then
    [ -d /usr/lib/noid-privacy ] && [ ! -L /usr/lib/noid-privacy ] \
        || fail "/usr/lib/noid-privacy is not a real directory"
else
    install -d -o root -g root -m 0755 -- /usr/lib/noid-privacy \
        || fail "cannot create /usr/lib/noid-privacy"
fi
[ "$(readlink -e -- /usr/lib/noid-privacy 2>/dev/null)" = \
    /usr/lib/noid-privacy ] \
    && [ "$(stat -Lc '%u:%g:%a' -- /usr/lib/noid-privacy 2>/dev/null)" = \
        0:0:755 ] \
    && /usr/sbin/restorecon -F -- /usr/lib/noid-privacy \
    && /usr/sbin/matchpathcon -V /usr/lib/noid-privacy >/dev/null \
    || fail "/usr/lib/noid-privacy metadata/label contract is invalid"
BUILD_NM_MANIFEST=/usr/lib/noid-privacy/anaconda-build-nm-profile-sha256
BUILD_NM_CANDIDATE=$(mktemp \
    /var/tmp/.anaconda-build-nm-profile-sha256.XXXXXXXX) \
    || fail "cannot stage compose NetworkManager digest manifest"
: > "$BUILD_NM_CANDIDATE"
NM_CONN_DIR=/etc/NetworkManager/system-connections
if [ -d "$NM_CONN_DIR" ] && [ ! -L "$NM_CONN_DIR" ]; then
    NM_CONN_DIR_METADATA=$(stat -Lc '%u:%g:%a' -- "$NM_CONN_DIR" \
        2>/dev/null) || fail "cannot inspect NetworkManager profile directory"
    case "$NM_CONN_DIR_METADATA" in
        0:0:*) NM_CONN_DIR_MODE=${NM_CONN_DIR_METADATA##*:} ;;
        *) fail "NetworkManager profile directory is not root-owned" ;;
    esac
    [ "$(readlink -e -- "$NM_CONN_DIR" 2>/dev/null)" = "$NM_CONN_DIR" ] \
        && [[ "$NM_CONN_DIR_MODE" =~ ^[0-7]{3,4}$ ]] \
        && (( (8#$NM_CONN_DIR_MODE & 0022) == 0 )) \
        && /usr/sbin/restorecon -F -- "$NM_CONN_DIR" \
        && /usr/sbin/matchpathcon -V "$NM_CONN_DIR" >/dev/null \
        || fail "NetworkManager profile directory boundary is unsafe"
    for compose_profile in "$NM_CONN_DIR"/*.nmconnection; do
        [ -e "$compose_profile" ] || continue
        if is_compose_nm_profile "$compose_profile"; then
            /usr/sbin/matchpathcon -V "$compose_profile" >/dev/null \
                || fail "compose NetworkManager profile label differs: $compose_profile"
            sha256sum -- "$compose_profile" | awk '{print $1}' \
                >> "$BUILD_NM_CANDIDATE"
        fi
    done
elif [ -e "$NM_CONN_DIR" ] || [ -L "$NM_CONN_DIR" ]; then
    log "  [FAIL] NetworkManager system-connections path is unsafe"
    exit 1
fi
LC_ALL=C sort -u -o "$BUILD_NM_CANDIDATE" "$BUILD_NM_CANDIDATE"
chmod 0644 "$BUILD_NM_CANDIDATE"
chown root:root "$BUILD_NM_CANDIDATE"
while IFS= read -r compose_digest || [ -n "$compose_digest" ]; do
    [ -n "$compose_digest" ] || continue
    [[ "$compose_digest" =~ ^[a-f0-9]{64}$ ]] || {
        log "  [FAIL] generated compose NetworkManager digest is malformed"
        exit 1
    }
done < "$BUILD_NM_CANDIDATE"
publish_root_file "$BUILD_NM_CANDIDATE" "$BUILD_NM_MANIFEST" 0644
rm -f -- "$BUILD_NM_CANDIDATE" \
    || fail "cannot retire compose NetworkManager digest source"
BUILD_NM_CANDIDATE=""
if [ ! -f "$BUILD_NM_MANIFEST" ] || [ -L "$BUILD_NM_MANIFEST" ] \
   || [ "$(stat -Lc '%u:%g:%a:%h' -- "$BUILD_NM_MANIFEST")" != \
      0:0:644:1 ] \
   || ! /usr/sbin/matchpathcon -V "$BUILD_NM_MANIFEST" >/dev/null; then
    log "  [FAIL] compose NetworkManager digest manifest publication failed"
    exit 1
fi
sync -- "$BUILD_NM_MANIFEST"
sync -- /usr/lib/noid-privacy
log "  [OK] recorded $(grep -c . "$BUILD_NM_MANIFEST" || true) exact compose profile digest(s)"

# ============================================================================
# STEP 2: systemd service
# ============================================================================
log "STEP 2: writing /etc/systemd/system/noid-anaconda-cleanup.service"

[ -d /etc/systemd/system ] && [ ! -L /etc/systemd/system ] \
    && [ "$(readlink -e -- /etc/systemd/system 2>/dev/null)" = \
        /etc/systemd/system ] \
    && [ "$(stat -Lc '%u:%g:%a' -- /etc/systemd/system 2>/dev/null)" = \
        0:0:755 ] \
    || fail "/etc/systemd/system publication boundary is invalid"

IDENTITY_SERVICE_SOURCE=$(mktemp \
    /var/tmp/.noid-host-identity-service.XXXXXXXX) \
    || fail "cannot stage host-identity service source"
cat > "$IDENTITY_SERVICE_SOURCE" <<'HOST_IDENTITY_SERVICE_EOF'
[Unit]
Description=NoID Privacy — create fresh Live host identity
Documentation=https://github.com/NexusOne23/noid-privacy-workstation
DefaultDependencies=yes
Wants=systemd-random-seed.service
After=local-fs.target systemd-random-seed.service
Before=brltty.service noid-anaconda-cleanup.service systemd-user-sessions.service getty.target gdm.service display-manager.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/noid-host-identity --ensure
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal
TimeoutStartSec=30
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX
MemoryDenyWriteExecute=yes
IPAddressDeny=any
SystemCallArchitectures=native
ReadWritePaths=/etc /var/lib/noid-privacy
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FOWNER

[Install]
WantedBy=graphical.target
HOST_IDENTITY_SERVICE_EOF
IDENTITY_SERVICE_EXPECTED_SHA=$(candidate_sha256 \
    "$IDENTITY_SERVICE_SOURCE")
publish_root_file "$IDENTITY_SERVICE_SOURCE" \
    /etc/systemd/system/noid-host-identity.service 0644
rm -f -- "$IDENTITY_SERVICE_SOURCE" \
    || fail "cannot retire host-identity service source"
IDENTITY_SERVICE_SOURCE=""
log "  [OK] noid-host-identity.service installed"

SERVICE_SOURCE=$(mktemp /var/tmp/.noid-anaconda-cleanup-service.XXXXXXXX) \
    || fail "cannot stage cleanup service source"
cat > "$SERVICE_SOURCE" <<'SERVICE_EOF'
[Unit]
Description=NoID Privacy — retire Live authorization before first login
Documentation=https://github.com/NexusOne23/noid-privacy-workstation
DefaultDependencies=yes
# STEP 9 may archive an exact compose profile and reload NetworkManager. Keep
# that privacy transition inside the pre-login success boundary.
Requires=noid-host-identity.service
After=local-fs.target NetworkManager.service noid-host-identity.service
Before=systemd-user-sessions.service getty.target gdm.service display-manager.service
# Skip on Live-ISO (multiple detection layers)
ConditionPathExists=!/run/livesys
ConditionPathExists=!/run/initramfs/live

[Service]
Type=oneshot
ExecStart=/usr/libexec/noid-anaconda-cleanup.sh --security
RemainAfterExit=no
StandardOutput=journal
StandardError=journal
TimeoutStartSec=120
UMask=0077

# Hardening (M12 baseline upgrade — analog M14/M11b/M22 baseline).
#
# NoNewPrivileges stays off because native account tools may need SELinux
# transitions. Network denial and the remaining sandbox constrain the one-shot.
#
# M12 ADD (7 new): PrivateTmp + RestrictAddressFamilies=AF_UNIX +
# MemoryDenyWriteExecute + IPAddressDeny + CapabilityBoundingSet (limited
# set for userdel/rm/sed needs) + ProtectClock + ProtectHostname.
#
# M12 SKIPS (3, with explicit rationale — script's privesc-cleanup needs):
#   - ProtectSystem=strict: would block userdel rename of /etc/passwd.tmp →
#     /etc/passwd (parent dir /etc/ must be RW for unlink+create entry).
#     ReadWritePaths cannot whitelist a single file inside an RO directory
#     for rename operations (rename mutates the parent directory's entry list,
#     not just the file content).
#   - ProtectHome=read-only: would block the atomic rename of `/home/liveuser`
#     into its root-private sibling quarantine because that operation mutates
#     directory entries in `/home`, not merely content below the source path.
#   - ReadWritePaths: companion of ProtectSystem=strict, irrelevant without it.
NoNewPrivileges=no
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX
PrivateTmp=yes
MemoryDenyWriteExecute=yes
IPAddressDeny=any
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FOWNER CAP_KILL CAP_SETUID CAP_SETGID

[Install]
WantedBy=graphical.target
SERVICE_EOF

SERVICE_EXPECTED_SHA=$(candidate_sha256 "$SERVICE_SOURCE")
publish_root_file "$SERVICE_SOURCE" \
    /etc/systemd/system/noid-anaconda-cleanup.service 0644
rm -f -- "$SERVICE_SOURCE" \
    || fail "cannot retire cleanup service source"
SERVICE_SOURCE=""

log "  [OK] noid-anaconda-cleanup.service installed"

MAINTENANCE_SERVICE_SOURCE=$(mktemp \
    /var/tmp/.noid-anaconda-maintenance-service.XXXXXXXX) \
    || fail "cannot stage deferred-maintenance service source"
cat > "$MAINTENANCE_SERVICE_SOURCE" <<'MAINTENANCE_SERVICE_EOF'
[Unit]
Description=NoID Privacy — deferred post-install package hygiene
Documentation=https://github.com/NexusOne23/noid-privacy-workstation
DefaultDependencies=yes
Requires=noid-anaconda-cleanup.service
After=noid-anaconda-cleanup.service gdm.service display-manager.service
ConditionPathExists=!/run/livesys
ConditionPathExists=!/run/initramfs/live

[Service]
Type=oneshot
ExecStart=/usr/libexec/noid-anaconda-cleanup.sh --maintenance
RemainAfterExit=no
StandardOutput=journal
StandardError=journal
TimeoutStartSec=600
UMask=0077

# RPM erase/autoremove scriptlets require normal executable mappings and may
# require SELinux transitions. Keep those, but deny network access and every
# unrelated kernel mutation surface.
NoNewPrivileges=no
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX
PrivateTmp=yes
MemoryDenyWriteExecute=no
IPAddressDeny=any
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FOWNER CAP_KILL CAP_SETUID CAP_SETGID

[Install]
WantedBy=graphical.target
MAINTENANCE_SERVICE_EOF
MAINTENANCE_SERVICE_EXPECTED_SHA=$(candidate_sha256 \
    "$MAINTENANCE_SERVICE_SOURCE")
publish_root_file "$MAINTENANCE_SERVICE_SOURCE" \
    /etc/systemd/system/noid-anaconda-maintenance.service 0644
rm -f -- "$MAINTENANCE_SERVICE_SOURCE" \
    || fail "cannot retire deferred-maintenance service source"
MAINTENANCE_SERVICE_SOURCE=""
log "  [OK] noid-anaconda-maintenance.service installed"

# Ordering alone is not a success dependency: Before=gdm.service permits GDM
# to start after a failed cleanup. Require the oneshot from the real display
# manager so a privesc-critical cleanup failure blocks graphical login. A
# Condition-skipped cleanup on the Live ISO, or a script-confirmed prior
# completion marker on an installed target, is a successful no-op.
if [ -e /etc/systemd/system/gdm.service.d ] \
   || [ -L /etc/systemd/system/gdm.service.d ]; then
    [ -d /etc/systemd/system/gdm.service.d ] \
        && [ ! -L /etc/systemd/system/gdm.service.d ] \
        || fail "GDM drop-in directory is unsafe"
else
    install -d -o root -g root -m 0755 \
        /etc/systemd/system/gdm.service.d \
        || fail "cannot create GDM drop-in directory"
fi
[ "$(readlink -e -- /etc/systemd/system/gdm.service.d 2>/dev/null)" = \
    /etc/systemd/system/gdm.service.d ] \
    && [ "$(stat -Lc '%u:%g:%a' -- \
        /etc/systemd/system/gdm.service.d 2>/dev/null)" = 0:0:755 ] \
    && /usr/sbin/restorecon -F -- /etc/systemd/system/gdm.service.d \
    && /usr/sbin/matchpathcon -V \
        /etc/systemd/system/gdm.service.d >/dev/null \
    || fail "GDM drop-in directory metadata/label contract is invalid"
GDM_GATE_SOURCE=$(mktemp /var/tmp/.noid-gdm-cleanup-gate.XXXXXXXX) \
    || fail "cannot stage GDM cleanup gate source"
cat > "$GDM_GATE_SOURCE" <<'GDM_GATE_EOF'
[Unit]
Requires=noid-host-identity.service noid-anaconda-cleanup.service
After=noid-host-identity.service noid-anaconda-cleanup.service
GDM_GATE_EOF
GDM_GATE_EXPECTED_SHA=$(candidate_sha256 "$GDM_GATE_SOURCE")
publish_root_file "$GDM_GATE_SOURCE" /etc/systemd/system/gdm.service.d/40-noid-anaconda-cleanup.conf 0644
rm -f -- "$GDM_GATE_SOURCE" \
    || fail "cannot retire GDM cleanup gate source"
GDM_GATE_SOURCE=""

# Keep /run/nologin in force unless the same security transition succeeds.
# The cleanup unit's Before= edge supplies ordering; this Requires= drop-in is
# the failure dependency that prevents console/user-session admission.
if [ -e /etc/systemd/system/systemd-user-sessions.service.d ] \
   || [ -L /etc/systemd/system/systemd-user-sessions.service.d ]; then
    [ -d /etc/systemd/system/systemd-user-sessions.service.d ] \
        && [ ! -L /etc/systemd/system/systemd-user-sessions.service.d ] \
        || fail "systemd-user-sessions drop-in directory is unsafe"
else
    install -d -o root -g root -m 0755 \
        /etc/systemd/system/systemd-user-sessions.service.d \
        || fail "cannot create systemd-user-sessions drop-in directory"
fi
[ "$(readlink -e -- \
    /etc/systemd/system/systemd-user-sessions.service.d 2>/dev/null)" = \
    /etc/systemd/system/systemd-user-sessions.service.d ] \
    && [ "$(stat -Lc '%u:%g:%a' -- \
        /etc/systemd/system/systemd-user-sessions.service.d 2>/dev/null)" = \
        0:0:755 ] \
    && /usr/sbin/restorecon -F -- \
        /etc/systemd/system/systemd-user-sessions.service.d \
    && /usr/sbin/matchpathcon -V \
        /etc/systemd/system/systemd-user-sessions.service.d >/dev/null \
    || fail "systemd-user-sessions drop-in directory contract is invalid"
USER_SESSIONS_GATE_SOURCE=$(mktemp \
    /var/tmp/.noid-user-sessions-cleanup-gate.XXXXXXXX) \
    || fail "cannot stage systemd-user-sessions cleanup gate source"
cat > "$USER_SESSIONS_GATE_SOURCE" <<'USER_SESSIONS_GATE_EOF'
[Unit]
Requires=noid-host-identity.service noid-anaconda-cleanup.service
After=noid-host-identity.service noid-anaconda-cleanup.service
USER_SESSIONS_GATE_EOF
USER_SESSIONS_GATE_EXPECTED_SHA=$(candidate_sha256 \
    "$USER_SESSIONS_GATE_SOURCE")
publish_root_file "$USER_SESSIONS_GATE_SOURCE" /etc/systemd/system/systemd-user-sessions.service.d/40-noid-anaconda-cleanup.conf 0644
rm -f -- "$USER_SESSIONS_GATE_SOURCE" \
    || fail "cannot retire systemd-user-sessions cleanup gate source"
USER_SESSIONS_GATE_SOURCE=""

# ============================================================================
# STEP 3: Enable service (skipped on Live-ISO via Condition*=)
# ============================================================================
log "STEP 3: enabling host-identity, first-boot security and maintenance services"

systemctl daemon-reload
systemctl enable \
    noid-host-identity.service \
    noid-anaconda-cleanup.service \
    noid-anaconda-maintenance.service

log "  [OK] pre-login security and deferred-maintenance services enabled"

# ============================================================================
# STEP 4: Verification (verify_fail counter pattern, analog M21/M22/M26)
# ============================================================================
log "STEP 4: verification"

verify_fail=0
checks_total=15
IDENTITY_SERVICE_ENABLED=$(systemctl is-enabled \
    noid-host-identity.service 2>/dev/null || true)
SECURITY_SERVICE_ENABLED=$(systemctl is-enabled \
    noid-anaconda-cleanup.service 2>/dev/null || true)
MAINTENANCE_SERVICE_ENABLED=$(systemctl is-enabled \
    noid-anaconda-maintenance.service 2>/dev/null || true)
if [ "$IDENTITY_SERVICE_ENABLED" = enabled ] \
   && [ "$SECURITY_SERVICE_ENABLED" = enabled ] \
   && [ "$MAINTENANCE_SERVICE_ENABLED" = enabled ]; then
    SERVICE_ENABLED=enabled
else
    SERVICE_ENABLED="identity=${IDENTITY_SERVICE_ENABLED:-unknown},security=${SECURITY_SERVICE_ENABLED:-unknown},maintenance=${MAINTENANCE_SERVICE_ENABLED:-unknown}"
fi

verify_owned_regular() {
    local path=$1 mode=$2
    [ -f "$path" ] && [ ! -L "$path" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' "$path")" = "0:0:${mode}:1" ]
}

if verify_owned_regular /usr/local/bin/noid-host-identity 755 \
        && [ -x /usr/local/bin/noid-host-identity ] \
        && bash -n /usr/local/bin/noid-host-identity \
        && /usr/sbin/matchpathcon -V \
            /usr/local/bin/noid-host-identity >/dev/null; then
    log "  [OK] host-identity helper exact root-owned executable"
else
    log "  [FAIL] host-identity helper contract invalid"
    verify_fail=$((verify_fail + 1))
fi

if verify_owned_regular /usr/libexec/noid-anaconda-cleanup.sh 755 \
        && [ -x /usr/libexec/noid-anaconda-cleanup.sh ] \
        && /usr/sbin/matchpathcon -V \
            /usr/libexec/noid-anaconda-cleanup.sh >/dev/null; then
    log "  [OK] cleanup script exact root-owned executable"
else
    log "  [FAIL] cleanup script metadata/executable contract invalid"
    verify_fail=$((verify_fail + 1))
fi

if verify_owned_regular /etc/systemd/system/noid-host-identity.service 644 \
        && grep -qFx \
            'ExecStart=/usr/local/bin/noid-host-identity --ensure' \
            /etc/systemd/system/noid-host-identity.service \
        && /usr/sbin/matchpathcon -V \
            /etc/systemd/system/noid-host-identity.service >/dev/null; then
    log "  [OK] host-identity unit has exact metadata and ExecStart"
else
    log "  [FAIL] host-identity unit metadata/ExecStart contract invalid"
    verify_fail=$((verify_fail + 1))
fi

if verify_owned_regular /etc/systemd/system/noid-anaconda-cleanup.service 644 \
        && grep -qFx 'ExecStart=/usr/libexec/noid-anaconda-cleanup.sh --security' \
            /etc/systemd/system/noid-anaconda-cleanup.service \
        && /usr/sbin/matchpathcon -V \
            /etc/systemd/system/noid-anaconda-cleanup.service >/dev/null; then
    log "  [OK] service unit exact root-owned file with pinned ExecStart"
else
    log "  [FAIL] service unit metadata/ExecStart contract invalid"
    verify_fail=$((verify_fail + 1))
fi

if verify_owned_regular \
       /etc/systemd/system/noid-anaconda-maintenance.service 644 \
   && grep -qFx \
       'ExecStart=/usr/libexec/noid-anaconda-cleanup.sh --maintenance' \
       /etc/systemd/system/noid-anaconda-maintenance.service \
   && /usr/sbin/matchpathcon -V \
       /etc/systemd/system/noid-anaconda-maintenance.service >/dev/null; then
    log "  [OK] deferred-maintenance unit has exact metadata and ExecStart"
else
    log "  [FAIL] deferred-maintenance unit metadata/ExecStart contract invalid"
    verify_fail=$((verify_fail + 1))
fi

if verify_owned_regular \
       /etc/systemd/system/gdm.service.d/40-noid-anaconda-cleanup.conf 644 \
   && cmp -s /etc/systemd/system/gdm.service.d/40-noid-anaconda-cleanup.conf \
       <(printf '%s\n' '[Unit]' \
           'Requires=noid-host-identity.service noid-anaconda-cleanup.service' \
           'After=noid-host-identity.service noid-anaconda-cleanup.service') \
   && /usr/sbin/matchpathcon -V \
       /etc/systemd/system/gdm.service.d/40-noid-anaconda-cleanup.conf \
       >/dev/null; then
    log "  [OK] GDM is success-gated on anaconda cleanup"
else
    log "  [FAIL] GDM cleanup success dependency missing"
    verify_fail=$((verify_fail + 1))
fi

if verify_owned_regular \
       /etc/systemd/system/systemd-user-sessions.service.d/40-noid-anaconda-cleanup.conf \
       644 \
   && cmp -s /etc/systemd/system/systemd-user-sessions.service.d/40-noid-anaconda-cleanup.conf \
       <(printf '%s\n' '[Unit]' \
           'Requires=noid-host-identity.service noid-anaconda-cleanup.service' \
           'After=noid-host-identity.service noid-anaconda-cleanup.service') \
   && /usr/sbin/matchpathcon -V \
       /etc/systemd/system/systemd-user-sessions.service.d/40-noid-anaconda-cleanup.conf \
       >/dev/null; then
    log "  [OK] systemd user sessions are success-gated on cleanup"
else
    log "  [FAIL] systemd-user-sessions cleanup dependency missing"
    verify_fail=$((verify_fail + 1))
fi

manifest_valid=1
declare -A VERIFY_NM_DIGEST_SEEN=()
if ! verify_owned_regular \
        /usr/lib/noid-privacy/anaconda-build-nm-profile-sha256 644 \
   || ! /usr/sbin/matchpathcon -V \
        /usr/lib/noid-privacy/anaconda-build-nm-profile-sha256 >/dev/null; then
    manifest_valid=0
else
    while IFS= read -r verify_nm_digest || [ -n "$verify_nm_digest" ]; do
        [ -n "$verify_nm_digest" ] || continue
        if ! [[ "$verify_nm_digest" =~ ^[a-f0-9]{64}$ ]] \
           || [ -n "${VERIFY_NM_DIGEST_SEEN[$verify_nm_digest]:-}" ]; then
            manifest_valid=0
            break
        fi
        VERIFY_NM_DIGEST_SEEN[$verify_nm_digest]=1
    done < /usr/lib/noid-privacy/anaconda-build-nm-profile-sha256
fi
if [ "$manifest_valid" -eq 1 ]; then
    log "  [OK] compose NetworkManager digest manifest is exact and canonical"
else
    log "  [FAIL] compose NetworkManager digest manifest contract invalid"
    verify_fail=$((verify_fail + 1))
fi

if [ "$SERVICE_ENABLED" = enabled ]; then
    log "  [OK] service enabled"
else
    log "  [FAIL] service state is not exactly enabled: ${SERVICE_ENABLED:-unknown}"
    verify_fail=$((verify_fail + 1))
fi

# Bash syntax check
if bash -n /usr/libexec/noid-anaconda-cleanup.sh 2>/dev/null; then
    log "  [OK] cleanup script bash -n clean"
else
    log "  [FAIL] cleanup script bash -n syntax error"
    verify_fail=$((verify_fail + 1))
fi

# Blocking graphical.target.wants activation-symlink check for all first-boot
# services; this is the canonical path for WantedBy=graphical.target.
if [ -L /etc/systemd/system/graphical.target.wants/noid-host-identity.service ] \
   && [ "$(readlink -f \
       /etc/systemd/system/graphical.target.wants/noid-host-identity.service)" = \
       /etc/systemd/system/noid-host-identity.service ] \
   && [ -L /etc/systemd/system/graphical.target.wants/noid-anaconda-cleanup.service ] \
   && [ "$(readlink -f \
       /etc/systemd/system/graphical.target.wants/noid-anaconda-cleanup.service)" = \
       /etc/systemd/system/noid-anaconda-cleanup.service ] \
   && [ -L /etc/systemd/system/graphical.target.wants/noid-anaconda-maintenance.service ] \
   && [ "$(readlink -f \
       /etc/systemd/system/graphical.target.wants/noid-anaconda-maintenance.service)" = \
       /etc/systemd/system/noid-anaconda-maintenance.service ]; then
    log "  [OK] graphical target links all three exact first-boot services"
else
    log "  [FAIL] graphical target service links missing or misdirected"
    verify_fail=$((verify_fail + 1))
fi

if [ -d /var/lib/noid-privacy ] \
   && [ ! -L /var/lib/noid-privacy ] \
   && [ "$(stat -Lc '%u:%g:%a' -- /var/lib/noid-privacy)" = \
      0:0:755 ] \
   && /usr/sbin/matchpathcon -V /var/lib/noid-privacy >/dev/null; then
    log "  [OK] NoID Privacy state directory has exact metadata"
else
    log "  [FAIL] NoID Privacy state directory contract invalid"
    verify_fail=$((verify_fail + 1))
fi

if [ ! -e /var/lib/noid-privacy/anaconda-cleanup.done ] \
   && [ ! -L /var/lib/noid-privacy/anaconda-cleanup.done ] \
   && [ ! -e /var/lib/noid-privacy/anaconda-cleanup-security.done ] \
   && [ ! -L /var/lib/noid-privacy/anaconda-cleanup-security.done ] \
   && [ ! -e /var/lib/noid-privacy/host-identity-installed.done ] \
   && [ ! -L /var/lib/noid-privacy/host-identity-installed.done ]; then
    log "  [OK] composed image contains no run-time completion markers"
else
    log "  [FAIL] stale run-time completion marker would suppress first boot"
    verify_fail=$((verify_fail + 1))
fi

SYSTEMD_VERIFY_LOG=$(mktemp -t noid-m41-systemd-verify.XXXXXX)
if systemd-analyze verify \
        noid-host-identity.service \
        noid-anaconda-cleanup.service \
        noid-anaconda-maintenance.service gdm.service \
        systemd-user-sessions.service \
        > "$SYSTEMD_VERIFY_LOG" 2>&1; then
    log "  [OK] cleanup and login dependency graph verifies"
else
    log "  [FAIL] cleanup or login dependency graph is invalid"
    tail -50 "$SYSTEMD_VERIFY_LOG"
    verify_fail=$((verify_fail + 1))
fi
rm -f -- "$SYSTEMD_VERIFY_LOG"

if [ "$(/usr/bin/sha256sum -- /usr/local/bin/noid-host-identity \
        | awk '{print $1}')" = "$IDENTITY_EXPECTED_SHA" ] \
   && [ "$(/usr/bin/sha256sum -- \
        /etc/systemd/system/noid-host-identity.service \
        | awk '{print $1}')" = "$IDENTITY_SERVICE_EXPECTED_SHA" ] \
   && [ "$(/usr/bin/sha256sum -- /usr/libexec/noid-anaconda-cleanup.sh \
        | awk '{print $1}')" = "$CLEANUP_EXPECTED_SHA" ] \
   && [ "$(/usr/bin/sha256sum -- \
        /etc/systemd/system/noid-anaconda-cleanup.service \
        | awk '{print $1}')" = "$SERVICE_EXPECTED_SHA" ] \
   && [ "$(/usr/bin/sha256sum -- \
        /etc/systemd/system/noid-anaconda-maintenance.service \
        | awk '{print $1}')" = "$MAINTENANCE_SERVICE_EXPECTED_SHA" ] \
   && [ "$(/usr/bin/sha256sum -- \
        /etc/systemd/system/gdm.service.d/40-noid-anaconda-cleanup.conf \
        | awk '{print $1}')" = "$GDM_GATE_EXPECTED_SHA" ] \
   && [ "$(/usr/bin/sha256sum -- \
        /etc/systemd/system/systemd-user-sessions.service.d/40-noid-anaconda-cleanup.conf \
        | awk '{print $1}')" = "$USER_SESSIONS_GATE_EXPECTED_SHA" ]; then
    log "  [OK] all seven final M41 payloads match their publication candidates"
else
    log "  [FAIL] final M41 payload bytes differ from their publication candidates"
    verify_fail=$((verify_fail + 1))
fi

if [ "$verify_fail" -gt 0 ]; then
    log "[FAIL] $verify_fail of $checks_total verification check(s) failed — aborting build"
    exit 1
fi

log "  [OK] all $checks_total verification checks passed"

# ============================================================================
# STEP 5: Health Stamp (extension service_enabled). Build-time stamp —
#         distinct from the run-time anaconda-cleanup.done marker; both
#         coexist by design (see header constraint note).
# ============================================================================
log "STEP 5: writing health stamp"

# M41_HEALTH_PUBLICATION_BEGIN
if [ ! -d "$M41_STATE_DIR" ] || [ -L "$M41_STATE_DIR" ] \
   || [ "$(stat -Lc '%u:%g:%a' -- "$M41_STATE_DIR" 2>/dev/null || true)" != \
        0:0:755 ] \
   || ! /usr/sbin/matchpathcon -V "$M41_STATE_DIR" >/dev/null; then
    log "  [FAIL] shared health-stamp directory drifted before publication"
    exit 1
fi

verify_m41_health_stamp() {
    local path="$1"
    verify_owned_regular "$path" 644 \
        && [ "$(wc -l < "$path")" -eq 18 ] \
        && grep -qFx '# NoID Privacy — Module 41 Health Stamp' "$path" \
        && grep -qFx \
            '# Written at end of %post verification when all checks pass.' \
            "$path" \
        && grep -qFx \
            '# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.' \
            "$path" \
        && [ "$(grep -c '^module=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^name=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^version=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^status=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^timestamp=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^checks_passed=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^checks_total=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^service_enabled=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^identity_sha256=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^identity_service_sha256=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^cleanup_sha256=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^security_service_sha256=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^maintenance_service_sha256=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^gdm_gate_sha256=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^user_sessions_gate_sha256=' "$path" || true)" -eq 1 ] \
        && grep -qFx 'module=41' "$path" \
        && grep -qFx 'name=anaconda-cleanup' "$path" \
        && grep -qFx 'version=4' "$path" \
        && grep -qFx 'status=ok' "$path" \
        && grep -Eq \
            '^timestamp=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' \
            "$path" \
        && grep -qFx "checks_passed=$checks_total" "$path" \
        && grep -qFx "checks_total=$checks_total" "$path" \
        && grep -qFx 'service_enabled=enabled' "$path" \
        && grep -qFx "identity_sha256=$IDENTITY_EXPECTED_SHA" "$path" \
        && grep -qFx \
            "identity_service_sha256=$IDENTITY_SERVICE_EXPECTED_SHA" "$path" \
        && grep -qFx "cleanup_sha256=$CLEANUP_EXPECTED_SHA" "$path" \
        && grep -qFx \
            "security_service_sha256=$SERVICE_EXPECTED_SHA" "$path" \
        && grep -qFx \
            "maintenance_service_sha256=$MAINTENANCE_SERVICE_EXPECTED_SHA" "$path" \
        && grep -qFx "gdm_gate_sha256=$GDM_GATE_EXPECTED_SHA" "$path" \
        && grep -qFx \
            "user_sessions_gate_sha256=$USER_SESSIONS_GATE_EXPECTED_SHA" "$path"
}

STAMP_CANDIDATE=$(mktemp \
    "$M41_STATE_DIR/.stamp-41-anaconda-cleanup.XXXXXXXX") \
    || fail "cannot create Module 41 health-stamp candidate"
cat > "$STAMP_CANDIDATE" <<STAMP_EOF || \
    fail "cannot write Module 41 health-stamp candidate"
# NoID Privacy — Module 41 Health Stamp
# Written at end of %post verification when all checks pass.
# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.
module=41
name=anaconda-cleanup
version=4
status=ok
timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
checks_passed=$((checks_total - verify_fail))
checks_total=$checks_total
service_enabled=$SERVICE_ENABLED
identity_sha256=$IDENTITY_EXPECTED_SHA
identity_service_sha256=$IDENTITY_SERVICE_EXPECTED_SHA
cleanup_sha256=$CLEANUP_EXPECTED_SHA
security_service_sha256=$SERVICE_EXPECTED_SHA
maintenance_service_sha256=$MAINTENANCE_SERVICE_EXPECTED_SHA
gdm_gate_sha256=$GDM_GATE_EXPECTED_SHA
user_sessions_gate_sha256=$USER_SESSIONS_GATE_EXPECTED_SHA
STAMP_EOF
chmod 0644 "$STAMP_CANDIDATE" \
    || fail "cannot set Module 41 health-stamp mode"
chown root:root "$STAMP_CANDIDATE" \
    || fail "cannot set Module 41 health-stamp ownership"
/usr/sbin/restorecon -F -- "$STAMP_CANDIDATE" \
    || fail "cannot label Module 41 health-stamp candidate"
/usr/sbin/matchpathcon -V "$STAMP_CANDIDATE" >/dev/null \
    || fail "Module 41 health-stamp candidate label differs"
verify_m41_health_stamp "$STAMP_CANDIDATE" \
    || fail "staged Module 41 health-stamp contract is invalid"
sync -- "$STAMP_CANDIDATE" \
    || fail "cannot sync Module 41 health-stamp candidate"
STAMP_PUBLISHED=1
publish_root_file "$STAMP_CANDIDATE" "$STAMP" 0644
rm -f -- "$STAMP_CANDIDATE" \
    || fail "cannot retire Module 41 health-stamp source"
STAMP_CANDIDATE=""
/usr/sbin/matchpathcon -V "$STAMP" >/dev/null \
    || fail "published Module 41 health-stamp label differs"
sync -- "$STAMP" \
    || fail "cannot sync published Module 41 health stamp"
sync -- "$M41_STATE_DIR" \
    || fail "cannot sync Module 41 health-stamp directory"
verify_m41_health_stamp "$STAMP" \
    || fail "published Module 41 health-stamp contract is invalid"
STAMP_PUBLISHED=0
log "  [OK] $STAMP written atomically with exact metadata and context"
# M41_HEALTH_PUBLICATION_END

log "=== Module 41 anaconda-cleanup complete ==="
%end
