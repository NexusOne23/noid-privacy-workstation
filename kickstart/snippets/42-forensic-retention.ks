# ============================================================================
# Module 42 — Forensic Retention (30-day cap on NoID Privacy-managed traces)
# Status: LOCKED 2026-08-12 (v26) — retain removed-VM swtpm logs at Fedora's default label.
#
# Scope: every age-managed NoID Privacy forensic source listed here targets a
# 30-day maximum. This is not a 30-day completeness guarantee: source-owned
# size/count ceilings can evict high-volume records earlier, and the explicit
# daemon/session exceptions below use their documented safe lifecycle boundary.
# This includes active and rotated audit/install/AIDE/libvirt/swtpm/tuned/dnf5 logs
# and wtmp/btmp. NetworkManager's global WiFi-MAC/activation history has a
# separate honest session boundary: it is cleared before every NetworkManager
# start, because NetworkManager 1.56.1 loads both databases into RAM only at
# startup and exposes no maintained runtime-clear API. A daily profile pass
# strips only stale serialized generated keys without interrupting networking.
# A bootless session can therefore retain its in-memory/current on-disk NM
# history for longer than 30 days; M42 never hides that limit behind an
# ineffective live-daemon truncate or a disruptive daily network restart.
# UPower 1.91.3 independently keeps at most seven days of loaded-device records
# whenever its native writer saves them. It exposes no maintained file-prune API
# or lock, so M42 removes old whole history files only while no upowerd process
# exists, before every daemon start. The daily pass defers that scope while the
# daemon runs; a bootless session can therefore retain an untouched file beyond
# 30 days without racing UPower's atomic writer.
# Snapshots are owned by M20 and use the same 30-day eligibility target without
# an important=yes exception. Active/default roots are protected and clock
# discontinuities defer deletion. All age decisions use wall time: a backward
# or otherwise incorrect system clock can defer expiry until time catches up.
# User files/app profiles and storage remanence are explicitly outside this
# log-retention mechanism; docs state that boundary.
#
# Ships the daily prune + rotate machinery for sources without a usable
# native cap (detail per script heredoc):
#   - rotated audit.log.[0-9]+ (auditd is size-based, not time-based) +
#     daily native `auditctl --signal rotate` of the current audit.log
#   - install-time logs (/var/log/anaconda + ks-*.log + the exact authselect,
#     target-karg, firstboot and crypto-policy error artifacts) + Anaconda
#     kickstart replays in /root (anaconda-ks.cfg +
#     original-ks.cfg — full RPM list = strong install-fingerprint)
#   - exact AIDE per-run timestamped reports plus exact rotated archives of
#     the shared aide.log; user-owned AIDE databases never enter this scope
#   - active libvirt qemu + tuned + dnf5 logs (daily copytruncate), closed
#     per-VM swtpm logs after libvirt restores their `virt_log_t` label, plus
#     tss-owned removed-domain logs at Fedora's default `var_log_t` path label,
#     and only their rotated archives (age-pruned; active basenames are never
#     deleted). Running-VM swtpm logs retain their VM-specific `svirt_image_t`
#     MCS isolation and are reported as protected/deferred.
#   - UPower history files untouched for more than 30 days, but only at the
#     stopped-daemon pre-start boundary; the native writer independently culls
#     loaded-device records after seven days whenever it saves them
#   - NetworkManager generated history — global seen-bssids/timestamps files
#     are cleared while the daemon is stopped, before each daemon start; a
#     daily pass removes only legacy/imported `[wifi] seen-bssids=` and
#     `[connection] timestamp=` keys from exact system `.nmconnection` files.
#   + wtmp/btmp rewritten to daily+rotate30+maxage30; wtmp's stock minsize
#     gate is removed because it otherwise retains low-volume login history.
#
# Deliberate deviations (UX > absolute-privacy — keep on future edits):
#   - /var/lib/bluetooth pairing state NOT pruned (would force daily
#     re-pair). M08 deliberately leaves the D-Bus service unmasked so GNOME's
#     panel works; an rfkill soft block supplies the default-OFF state. Pairing
#     records begin accumulating after user opt-in and are retained by design.
#   - .nmconnection files NOT deleted whole (would drop saved WiFi
#     passwords every 30 days); only global generated state plus legacy/imported
#     generated keys in their exact native sections are stripped — user-set
#     `bssid=` pins, SSIDs, credentials and mac-address settings stay untouched.
#   - NetworkManager's private internal-*.lease files are NOT pruned. They can
#     expose a last assigned address and per-interface recency through mtime,
#     but are opaque daemon-owned lease-continuity state rather than a supported
#     history API; clearing them could force avoidable DHCP reacquisition.
#
# Out of scope (owned elsewhere): logrotate.d/snapper cap + strict snapshot
# time-prune → M20; update-time check-only AIDE evidence → M25; aide-check
# wrapper + user-owned candidate review/commit → M13; one-shot Live-ISO purge → M41;
# journald time/size retention → M08. M42 independently owns the ongoing cap
# on the listed install-time artifacts. M12 emits the rotated audit.log.*
# files this module prunes.
#
# Design constraints (keep on future edits):
#   - Daily timer windows are 00:00–02:00 and 07:25–08:05, plus systemd's
#     default timer accuracy. RandomizedDelaySec reduces synchronized wakeups;
#     Persistent=true catches suspended-overnight.
#   - File prunes use GNU find's exact relative cutoff
#     (`! -newermt "-30 days"`) — never count-based caps.
#   - Full systemd sandboxing on all 5 services. PrivateNetwork=yes on the
#     three file-only prunes. NetworkManager needs its host D-Bus socket;
#     auditctl needs the host's AF_NETLINK audit control plane. Their explicit
#     address-family allowlists still exclude IP and packet sockets. Nice=19
#     for the tiny prunes, Nice=10 for nm-privacy-prune + auditd-rotate
#     (responsiveness).
#     IOSchedulingClass=idle is context-correct here (sub-second night jobs).
#   - auditd rotation uses Fedora audit-userspace's native
#     `auditctl --signal rotate` interface. auditctl first obtains auditd's PID
#     with AUDIT_GET over AF_NETLINK and then signals it through pidfd:
#     CAP_AUDIT_CONTROL + CAP_KILL are both required. The helper asks auditd to
#     rotate without exposing/logging a PID.
# ============================================================================

# No %packages block — find, awk, grep, coreutils, logger, logrotate, systemctl,
# restorecon, matchpathcon, NetworkManager and auditctl are provided earlier.

%post --erroronfail --log=/var/log/ks-42-forensic-retention.log
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

log() { echo "[$(date +%H:%M:%S)] $*"; }
fail() {
    log "  [FAIL] $*"
    exit 1
}

ROOT_PUBLICATION_TMP=""
M42_SOURCE_TMP=""
STAMP_CANDIDATE=""
STAMP_PUBLISHED=0
PAYLOADS_BOUND=0
PAYLOAD_MANIFEST_SHA256=""
M42_PUBLISHED_PATHS=()
M42_PUBLISHED_SHA256=()

# M42_PAYLOAD_INVENTORY_BEGIN
# Exact publication order is part of the build-evidence contract. The canonical
# unified-sbin targets are the real /usr/local/bin files, not their sbin alias.
M42_EXPECTED_PAYLOAD_PATHS=(
    /usr/local/bin/noid-install-logs-prune.sh
    /usr/local/bin/noid-audit-prune.sh
    /usr/local/bin/noid-misc-logs-prune.sh
    /usr/local/bin/noid-nm-privacy-prune.sh
    /usr/local/bin/noid-auditd-rotate.sh
    /etc/systemd/system/noid-install-logs-prune.service
    /etc/systemd/system/noid-install-logs-prune.timer
    /etc/systemd/system/noid-audit-prune.service
    /etc/systemd/system/noid-audit-prune.timer
    /etc/systemd/system/noid-misc-logs-prune.service
    /etc/systemd/system/noid-misc-logs-prune.timer
    /etc/systemd/system/noid-nm-privacy-prune.service
    /etc/systemd/system/noid-nm-privacy-prune.timer
    /etc/systemd/system/NetworkManager.service.d/23-noid-history-boundary.conf
    /etc/systemd/system/upower.service.d/23-noid-history-boundary.conf
    /etc/systemd/system/noid-auditd-rotate.service
    /etc/systemd/system/noid-auditd-rotate.timer
    /etc/logrotate.d/noid-forensic-30day
    /etc/logrotate.d/libvirtd.qemu
    /etc/logrotate.d/aide
    /etc/logrotate.d/wtmp
    /etc/logrotate.d/btmp
)
# M42_PAYLOAD_INVENTORY_END

# Root-owned executables, units and policies are staged beside their final
# destination, labeled and byte-checked before an atomic rename. Existing
# symlink targets are replaced rather than followed. Final bytes and their
# containing directory are synced before success can be reported.
# M42_ROOT_PUBLICATION_BEGIN
publish_root_file() {
    local source=$1 destination=$2 requested_mode=$3
    local parent temporary mode=${requested_mode#0} parent_state parent_mode
    local source_state source_mode source_sha

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
    source_sha=$(/usr/bin/sha256sum -- "$source" 2>/dev/null \
        | /usr/bin/awk '{print $1}') \
        || fail "cannot hash publication source: $source"
    [[ "$source_sha" =~ ^[0-9a-f]{64}$ ]] \
        || fail "publication source digest is invalid: $source"
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

    temporary=$(mktemp "$parent/.noid-m42-publish.XXXXXXXX") \
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
    if [ "$destination" != "${STAMP:-}" ]; then
        M42_PUBLISHED_PATHS+=("$destination")
        M42_PUBLISHED_SHA256+=("$source_sha")
    fi
}
# M42_ROOT_PUBLICATION_END

stage_root_file() {
    local destination=$1 mode=$2

    M42_SOURCE_TMP=$(mktemp /var/tmp/noid-m42-source.XXXXXXXX) \
        || fail "cannot create source candidate for $destination"
    if ! cat > "$M42_SOURCE_TMP" \
       || ! chmod "$mode" "$M42_SOURCE_TMP" \
       || ! chown root:root "$M42_SOURCE_TMP"; then
        fail "cannot stage source bytes for $destination"
    fi
    publish_root_file "$M42_SOURCE_TMP" "$destination" "$mode"
    rm -f -- "$M42_SOURCE_TMP" \
        || fail "cannot retire source candidate for $destination"
    M42_SOURCE_TMP=""
}

# M42_BUILD_CLEANUP_BEGIN
cleanup_m42_build_candidates() {
    local saved_rc=$? candidate cleanup_failed=0
    trap - EXIT
    trap '' HUP INT TERM
    for candidate in \
        "${ROOT_PUBLICATION_TMP:-}" \
        "${M42_SOURCE_TMP:-}" \
        "${STAMP_CANDIDATE:-}"; do
        [ -n "$candidate" ] || continue
        if ! rm -f -- "$candidate"; then
            log "  [FAIL] could not retire staged Module 42 payload: $candidate"
            cleanup_failed=1
        fi
    done
    if [ "${STAMP_PUBLISHED:-0}" -eq 1 ]; then
        if ! rm -f -- "$STAMP"; then
            log "  [FAIL] could not retire incomplete Module 42 health stamp"
            cleanup_failed=1
        fi
        sync -- "$M42_STATE_DIR" >/dev/null 2>&1 || true
    fi
    if [ "$saved_rc" -eq 0 ] && [ "$cleanup_failed" -ne 0 ]; then
        exit 1
    fi
    return "$saved_rc"
}
trap cleanup_m42_build_candidates EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
# M42_BUILD_CLEANUP_END

log "=== Module 42 — Forensic Retention (30-day cap) — start ==="

# M42_HEALTH_INVALIDATION_BEGIN
# The build-time stamp describes this complete retention publication. Validate
# the shared state boundary without normalizing drift, then remove any prior
# success before this run changes scripts, policies, units or timer activation.
M42_STATE_DIR=/var/lib/noid-privacy
STAMP="$M42_STATE_DIR/stamp-42-forensic-retention.ok"
if { [ -e "$M42_STATE_DIR" ] || [ -L "$M42_STATE_DIR" ]; } \
   && { [ ! -d "$M42_STATE_DIR" ] || [ -L "$M42_STATE_DIR" ]; }; then
    log "  [FAIL] $M42_STATE_DIR exists but is not a real directory"
    exit 1
fi
if [ ! -e "$M42_STATE_DIR" ]; then
    install -d -m 0755 -o root -g root "$M42_STATE_DIR"
fi
if [ "$(stat -Lc '%u:%g:%a' -- "$M42_STATE_DIR" 2>/dev/null || true)" != \
        0:0:755 ]; then
    log "  [FAIL] $M42_STATE_DIR metadata is not root:root 0755"
    exit 1
fi
if ! restorecon -F -- "$M42_STATE_DIR" \
   || ! matchpathcon -V "$M42_STATE_DIR" >/dev/null; then
    log "  [FAIL] $M42_STATE_DIR SELinux context is not canonical"
    exit 1
fi
if [ -e "$STAMP" ] || [ -L "$STAMP" ]; then
    if [ ! -f "$STAMP" ] && [ ! -L "$STAMP" ]; then
        log "  [FAIL] health-stamp target is not a file or symlink: $STAMP"
        exit 1
    fi
    rm -f -- "$STAMP" || {
        log "  [FAIL] cannot invalidate stale Module 42 health stamp"
        exit 1
    }
    sync -- "$M42_STATE_DIR"
fi
log "  [OK] prior Module 42 health stamp is absent"
# M42_HEALTH_INVALIDATION_END

# ============================================================================
# Step 1: Install /usr/local/sbin/ prune + rotate scripts (5 scripts)
# ============================================================================
log "Step 1: writing prune + rotate scripts"

# Fedora's native unified-sbin layout owns /usr/local/sbin as the exact
# `bin` alias. Publish to the canonical real directory; the established
# /usr/local/sbin command paths continue to resolve to the same bytes.
[ -d /usr/local/bin ] && [ ! -L /usr/local/bin ] \
    && [ "$(readlink -e /usr/local/bin)" = /usr/local/bin ] \
    && [ "$(stat -Lc '%u:%g:%a' /usr/local/bin)" = 0:0:755 ] \
    && [ -L /usr/local/sbin ] \
    && [ "$(readlink -- /usr/local/sbin)" = bin ] \
    && [ "$(stat -c '%u:%g:%a' /usr/local/sbin)" = 0:0:777 ] \
    || fail "Fedora unified /usr/local bin/sbin boundary is unsafe"

# ----- 1a. noid-install-logs-prune.sh -----
stage_root_file /usr/local/bin/noid-install-logs-prune.sh 0755 \
    <<'INSTALL_LOGS_PRUNE_EOF'
#!/bin/bash
# NoID Privacy — prune install-time logs + artifacts after 30 days
#
# Anaconda + kickstart + first-boot logs + Anaconda-generated kickstart
# replays in /root/ are one-shot install artifacts. After 30 days they
# have served all forensic value (matches the 30-day forensic-retention
# policy). This script enforces the cap.
#
# Triggered: noid-install-logs-prune.timer daily. Any deletion failure makes
# the service fail visibly so the retention guarantee cannot silently drift.

set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 0077

if [ "$#" -ne 0 ]; then
    echo 'Usage: noid-install-logs-prune.sh' >&2
    exit 2
fi

CUTOFF_DAYS=30
LOG_TAG="noid-install-logs-prune"
FAILURES=0

# Print the number of deleted paths. A missing optional directory is handled
# by the caller; a real find/delete failure is returned to systemd.
delete_aged() {
    local deleted
    # Emit one fixed byte per deletion instead of pathnames: counting remains
    # exact even for unusual filenames, and private target names never enter
    # the journal or command-substitution output.
    if ! deleted=$(find "$@" ! -newermt "-${CUTOFF_DAYS} days" \
        -printf x -delete 2>/dev/null); then
        return 1
    fi
    printf '%s\n' "${#deleted}"
}

# Keep this filename contract narrow: all five are image-generated one-shot
# evidence. It must not become a broad /var/log/noid-* deletion rule.
delete_aged_install_logs() {
    local log_dir=$1
    delete_aged "$log_dir" -maxdepth 1 -type f \
        \( -name 'ks-*.log' \
           -o -name 'ks-10-authselect.err' \
           -o -name 'noid-anaconda-kernel-cmdline.log' \
           -o -name 'noid-firstboot-setup.log' \
           -o -name 'noid-crypto-policy.err' \)
}

logger -t "$LOG_TAG" "pruning install-time logs older than ${CUTOFF_DAYS} days"

# /var/log/anaconda/*  (anaconda.log dbus.log journal.log packaging.log storage.log lorax-packages.log)
ANACONDA_REMOVED=0
if [ -d /var/log/anaconda ]; then
    if ! ANACONDA_REMOVED=$(delete_aged /var/log/anaconda -maxdepth 1 -type f); then
        logger -t "$LOG_TAG" "FAILED to prune /var/log/anaconda"
        FAILURES=$((FAILURES + 1))
    fi
fi

# Per-module kickstart logs plus the exact one-shot logs written outside the
# ks-*.log convention by M01, M08 and M10.
INSTALL_LOG_REMOVED=0
if ! INSTALL_LOG_REMOVED=$(delete_aged_install_logs /var/log); then
    logger -t "$LOG_TAG" "FAILED to prune exact /var/log install artifacts"
    FAILURES=$((FAILURES + 1))
fi

# /root/anaconda-ks.cfg + /root/original-ks.cfg  (= Anaconda-generated kickstart
# replays revealing install date, partition layout, RPM list, hostname etc.)
ROOTKS_REMOVED=0
if ! ROOTKS_REMOVED=$(delete_aged /root -maxdepth 1 -type f \
    \( -name 'anaconda-ks.cfg' -o -name 'original-ks.cfg' \)); then
    logger -t "$LOG_TAG" "FAILED to prune Anaconda kickstart replays"
    FAILURES=$((FAILURES + 1))
fi

logger -t "$LOG_TAG" "removed: ${ANACONDA_REMOVED} anaconda, ${INSTALL_LOG_REMOVED} install-logs, ${ROOTKS_REMOVED} root-ks-cfg"
[ "$FAILURES" -eq 0 ] || exit 1
exit 0
INSTALL_LOGS_PRUNE_EOF

# ----- 1b. noid-audit-prune.sh -----
stage_root_file /usr/local/bin/noid-audit-prune.sh 0755 <<'AUDIT_PRUNE_EOF'
#!/bin/bash
# NoID Privacy — prune rotated audit logs after 30 days
#
# auditd has a 640-MiB count/size rolling ceiling but no native age cap.
# High-volume records can therefore leave the ring before 30 days; low-volume
# copies can otherwise span months. This script enforces only the maximum age
# by deleting rotated audit logs older than 30 days. The current audit.log is
# never touched — only rotated copies (audit.log.[0-9]+).
#
# Triggered by noid-audit-prune.timer daily. Any deletion failure makes the
# service fail visibly so the maximum-age boundary cannot silently drift.

set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 0077

if [ "$#" -ne 0 ]; then
    echo 'Usage: noid-audit-prune.sh' >&2
    exit 2
fi

CUTOFF_DAYS=30
LOG_TAG="noid-audit-prune"
AUDIT_DIR="/var/log/audit"

logger -t "$LOG_TAG" "pruning rotated audit logs older than ${CUTOFF_DAYS} days"

if [ ! -d "$AUDIT_DIR" ]; then
    logger -t "$LOG_TAG" "audit dir missing, skipping"
    exit 0
fi

# Find rotated logs (NEVER the current audit.log)
if ! deleted=$(find "$AUDIT_DIR" -regextype posix-extended -maxdepth 1 -type f \
    -regex '.*/audit\.log\.[0-9]+' ! -newermt "-${CUTOFF_DAYS} days" \
    -printf x -delete 2>/dev/null); then
    logger -t "$LOG_TAG" "FAILED to prune rotated audit logs"
    exit 1
fi
REMOVED=${#deleted}

logger -t "$LOG_TAG" "removed: ${REMOVED} rotated audit logs"
exit 0
AUDIT_PRUNE_EOF

# ----- 1c. noid-misc-logs-prune.sh -----
stage_root_file /usr/local/bin/noid-misc-logs-prune.sh 0755 \
    <<'MISC_LOGS_PRUNE_EOF'
#!/bin/bash
# NoID Privacy — prune miscellaneous logs older than 30 days
#
# Covers logs without their own logrotate config or with insufficient cap:
#   - exact NoID Privacy AIDE check/review reports and active aide.log archives
#                                     (small files may never trigger rotation)
#   - /var/log/libvirt/qemu/*.log.{N}[.gz] / *.log-YYYYMMDD[.gz]
#   - closed /var/log/swtpm/libvirt/qemu/*.log basenames after libvirt restores
#                                     `virt_log_t`, or removed-domain basenames
#                                     at Fedora's default `var_log_t` label when
#                                     exact tss ownership/mode/link checks pass
#                                     (daily copytruncate)
#   - /var/log/swtpm/libvirt/qemu/*.log.{N}[.gz] /
#                                     *.log-YYYYMMDD[.gz] (rotated vTPM history)
#   - /var/log/tuned/*.log.{N}[.gz] / *.log-YYYYMMDD[.gz]
#   - /var/log/dnf5.log.{N} + dateext archives (dnf5's own size rotation and
#                                     NoID Privacy's daily active-log rotation)
#   - inactive wtmp/btmp archives (logrotate's `maxage` is evaluated only
#                                     when the active basename rotates)
#   - /var/lib/upower/history-*.dat files whose mtime exceeds the cutoff, but
#                                     only while no upowerd process exists
#                                     (loaded-device records are culled natively
#                                     after seven days whenever UPower saves)
#
# Triggered: noid-misc-logs-prune.timer daily. Any pruning failure makes the
# service fail visibly so the retention guarantee cannot silently drift.

set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 0077

if [ "$#" -ne 0 ]; then
    echo 'Usage: noid-misc-logs-prune.sh' >&2
    exit 2
fi

CUTOFF_DAYS=30
LOG_TAG="noid-misc-logs-prune"
DELETE_FAILURES=0

quote_logrotate_path() {
    local path="$1"
    # logrotate accepts a double-quoted pathname token. Newlines cannot be
    # represented safely as one token, so fail instead of generating an
    # ambiguous policy. Backslashes and double quotes are escaped explicitly.
    case "$path" in
        *$'\n'*|*$'\r'*) return 1 ;;
    esac
    path=${path//\\/\\\\}
    path=${path//\"/\\\"}
    printf '"%s"' "$path"
}

delete_aged() {
    local deleted
    # Count with one fixed byte per deletion. This is pathname-safe and keeps
    # private VM/profile-derived basenames out of captured command output.
    if ! deleted=$(find "$@" ! -newermt "-${CUTOFF_DAYS} days" \
        -printf x -delete 2>/dev/null); then
        return 1
    fi
    printf '%s\n' "${#deleted}"
}

logger -t "$LOG_TAG" "pruning misc logs older than ${CUTOFF_DAYS} days"

# Exact NoID Privacy per-run AIDE reports and rotated shared aide.log archives.
# The active shared aide.log is never matched. Active and archived AIDE
# databases are user-owned trust evidence and never enter this script.
AIDE_REMOVED=0
if [ -d /var/log/aide ]; then
    if ! AIDE_REMOVED=$(delete_aged /var/log/aide -regextype posix-extended \
        -maxdepth 1 -type f \
        \( -regex '.*/aide-check-[0-9]{8}-[0-9]{6}\.[A-Za-z0-9]{6}\.log' \
           -o -regex '.*/aide-baseline-review-[0-9]{8}-[0-9]{6}\.[A-Za-z0-9]{6}\.log' \
           -o -regex '.*/aide\.log\.[0-9]+(\.gz)?' \
           -o -regex '.*/aide\.log-[0-9]{8}(\.gz)?' \)); then
        logger -t "$LOG_TAG" "FAILED to prune exact AIDE report/archive scope"
        DELETE_FAILURES=$((DELETE_FAILURES + 1))
    fi
fi

# Rotated libvirt per-VM logs. The active *.log basename is deliberately not
# matched: deleting an open/quiet current file makes the daemon continue
# writing to an unlinked inode. Numeric names cover Fedora/virtlogd history;
# dateext names cover the M42 logrotate policy.
LIBVIRT_REMOVED=0
if [ -d /var/log/libvirt/qemu ]; then
    if ! LIBVIRT_REMOVED=$(delete_aged /var/log/libvirt/qemu \
        -regextype posix-extended -maxdepth 1 -type f \
        \( -regex '.*/[^/]+\.log\.[0-9]+(\.gz)?' \
           -o -regex '.*/[^/]+\.log-[0-9]{8}(\.gz)?' \)); then
        logger -t "$LOG_TAG" "FAILED to prune libvirt qemu logs"
        DELETE_FAILURES=$((DELETE_FAILURES + 1))
    fi
fi

# libvirt deliberately relabels each running VM's swtpm process, state and log
# with the guest-specific svirt_image_t MCS category. The system logrotate_t
# domain must not bypass that VM boundary; doing so also aborts the unrelated
# global logrotate transaction. Once a registered VM stops, libvirt restores
# virt_log_t. A log left behind after domain removal can instead converge to
# Fedora's default var_log_t path label; accept that narrower orphan state only
# for a one-link, non-writable tss-owned regular file. Select only these
# closed/restored basenames into an exact-path, ephemeral config and force at
# most one rotation per calendar day. /dev/null is
# logrotate's documented state-free mode, avoiding a persistent domain-name
# history in logrotate.status. A start-after-selection race fails this isolated
# job safely and is retried later; it can no longer fail global log rotation.
SWTPM_ELIGIBLE=0
SWTPM_PROTECTED=0
SWTPM_ALREADY_ROTATED=0
SWTPM_ROTATE_FAILURES=0
SWTPM_SCANNED=0
SWTPM_DEFAULT_LABEL=0
SWTPM_CONFIG_TMP=""
SWTPM_LIST_TMP=""
SWTPM_LOG_DIR=/var/log/swtpm/libvirt/qemu
retire_swtpm_tmp() {
    local cleanup_failed=0

    [ -z "$SWTPM_CONFIG_TMP" ] \
        || rm -f -- "$SWTPM_CONFIG_TMP" || cleanup_failed=1
    [ -z "$SWTPM_LIST_TMP" ] \
        || rm -f -- "$SWTPM_LIST_TMP" || cleanup_failed=1
    SWTPM_CONFIG_TMP=""
    SWTPM_LIST_TMP=""
    return "$cleanup_failed"
}
cleanup_swtpm_tmp() {
    local saved_rc=$? cleanup_failed=0

    trap - EXIT
    trap '' HUP INT TERM
    retire_swtpm_tmp || cleanup_failed=1
    if [ "$saved_rc" -eq 0 ] && [ "$cleanup_failed" -ne 0 ]; then
        exit 1
    fi
    return "$saved_rc"
}
trap cleanup_swtpm_tmp EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -d "$SWTPM_LOG_DIR" ]; then
    SWTPM_TSS_UID=$(id -u tss 2>/dev/null || true)
    SWTPM_TSS_GID=$(id -g tss 2>/dev/null || true)
    # PrivateTmp + the host's tmpfs-backed /tmp keep VM-derived basenames out
    # of persistent logrotate state even across a crash or power loss.
    if ! SWTPM_CONFIG_TMP=$(mktemp /tmp/noid-swtpm.conf.XXXXXX) \
       || ! SWTPM_LIST_TMP=$(mktemp /tmp/noid-swtpm.list.XXXXXX); then
        logger -t "$LOG_TAG" "FAILED to create ephemeral swtpm rotation files"
        retire_swtpm_tmp || true
        SWTPM_ROTATE_FAILURES=$((SWTPM_ROTATE_FAILURES + 1))
    elif ! find "$SWTPM_LOG_DIR" -mindepth 1 -maxdepth 1 \
        -name '*.log' -print0 > "$SWTPM_LIST_TMP"; then
        logger -t "$LOG_TAG" "FAILED to enumerate swtpm qemu logs"
        SWTPM_ROTATE_FAILURES=$((SWTPM_ROTATE_FAILURES + 1))
    else
        SWTPM_TODAY=$(date +%Y%m%d)
        while IFS= read -r -d '' swtpm_log; do
            SWTPM_SCANNED=$((SWTPM_SCANNED + 1))
            if [ -L "$swtpm_log" ] || [ ! -f "$swtpm_log" ]; then
                logger -t "$LOG_TAG" \
                    "REFUSED non-regular/symlink swtpm log #$SWTPM_SCANNED"
                SWTPM_ROTATE_FAILURES=$((SWTPM_ROTATE_FAILURES + 1))
                continue
            fi
            if ! swtpm_context=$(stat -c '%C' -- "$swtpm_log"); then
                logger -t "$LOG_TAG" \
                    "FAILED to read swtpm log context #$SWTPM_SCANNED"
                SWTPM_ROTATE_FAILURES=$((SWTPM_ROTATE_FAILURES + 1))
                continue
            fi
            case "$swtpm_context" in
                *:svirt_image_t:*)
                    SWTPM_PROTECTED=$((SWTPM_PROTECTED + 1))
                    logger -t "$LOG_TAG" \
                        "PROTECTED active-VM swtpm log #$SWTPM_SCANNED; rotation deferred"
                    continue
                    ;;
                *:virt_log_t:*)
                    ;;
                *:var_log_t:*)
                    if [ -z "$SWTPM_TSS_UID" ] || [ -z "$SWTPM_TSS_GID" ] \
                       || ! swtpm_meta=$(stat -c '%u:%g:%a:%h' -- "$swtpm_log"); then
                        logger -t "$LOG_TAG" \
                            "REFUSED unverifiable default-label swtpm log #$SWTPM_SCANNED"
                        SWTPM_ROTATE_FAILURES=$((SWTPM_ROTATE_FAILURES + 1))
                        continue
                    fi
                    case "$swtpm_meta" in
                        "$SWTPM_TSS_UID:$SWTPM_TSS_GID:600:1"|\
                        "$SWTPM_TSS_UID:$SWTPM_TSS_GID:640:1"|\
                        "$SWTPM_TSS_UID:$SWTPM_TSS_GID:644:1")
                            SWTPM_DEFAULT_LABEL=$((SWTPM_DEFAULT_LABEL + 1))
                            ;;
                        *)
                            logger -t "$LOG_TAG" \
                                "REFUSED unsafe default-label swtpm log #$SWTPM_SCANNED"
                            SWTPM_ROTATE_FAILURES=$((SWTPM_ROTATE_FAILURES + 1))
                            continue
                            ;;
                    esac
                    ;;
                *)
                    logger -t "$LOG_TAG" \
                        "REFUSED unexpected swtpm log context #$SWTPM_SCANNED"
                    SWTPM_ROTATE_FAILURES=$((SWTPM_ROTATE_FAILURES + 1))
                    continue
                    ;;
            esac

            swtpm_archive="${swtpm_log}-${SWTPM_TODAY}"
            if [ -L "$swtpm_archive" ] || [ -L "${swtpm_archive}.gz" ]; then
                logger -t "$LOG_TAG" \
                    "REFUSED symlink at today's swtpm archive path #$SWTPM_SCANNED"
                SWTPM_ROTATE_FAILURES=$((SWTPM_ROTATE_FAILURES + 1))
                continue
            fi
            if { [ -e "$swtpm_archive" ] && [ ! -f "$swtpm_archive" ]; } \
               || { [ -e "${swtpm_archive}.gz" ] \
                    && [ ! -f "${swtpm_archive}.gz" ]; }; then
                logger -t "$LOG_TAG" \
                    "REFUSED non-regular swtpm archive path #$SWTPM_SCANNED"
                SWTPM_ROTATE_FAILURES=$((SWTPM_ROTATE_FAILURES + 1))
                continue
            fi
            if [ -e "$swtpm_archive" ] || [ -e "${swtpm_archive}.gz" ]; then
                SWTPM_ALREADY_ROTATED=$((SWTPM_ALREADY_ROTATED + 1))
                continue
            fi

            if ! quote_logrotate_path "$swtpm_log" >> "$SWTPM_CONFIG_TMP"; then
                logger -t "$LOG_TAG" \
                    "REFUSED unsafe swtpm log name #$SWTPM_SCANNED"
                SWTPM_ROTATE_FAILURES=$((SWTPM_ROTATE_FAILURES + 1))
                continue
            fi
            cat >> "$SWTPM_CONFIG_TMP" <<'SWTPM_LOGROTATE_STANZA_EOF'
 {
    su tss tss
    daily
    rotate 30
    maxage 30
    missingok
    notifempty
    compress
    delaycompress
    dateext
    dateformat -%Y%m%d
    copytruncate
}
SWTPM_LOGROTATE_STANZA_EOF
            SWTPM_ELIGIBLE=$((SWTPM_ELIGIBLE + 1))
        done < "$SWTPM_LIST_TMP"

        if [ "$SWTPM_ELIGIBLE" -gt 0 ] \
           && ! /usr/sbin/logrotate --force --state /dev/null "$SWTPM_CONFIG_TMP"; then
            logger -t "$LOG_TAG" \
                "FAILED isolated rotation of closed/restored swtpm logs"
            SWTPM_ROTATE_FAILURES=$((SWTPM_ROTATE_FAILURES + 1))
        fi
    fi
    if ! retire_swtpm_tmp; then
        logger -t "$LOG_TAG" "FAILED to retire ephemeral swtpm rotation files"
        SWTPM_ROTATE_FAILURES=$((SWTPM_ROTATE_FAILURES + 1))
    fi
fi

# Rotated archives are no longer VM-active inodes. Prune them independently
# even while a current basename remains protected by a running guest.
SWTPM_REMOVED=0
if [ -d /var/log/swtpm/libvirt/qemu ]; then
    if ! SWTPM_REMOVED=$(delete_aged /var/log/swtpm/libvirt/qemu \
        -regextype posix-extended -maxdepth 1 -type f \
        \( -regex '.*/[^/]+\.log\.[0-9]+(\.gz)?' \
           -o -regex '.*/[^/]+\.log-[0-9]{8}(\.gz)?' \)); then
        logger -t "$LOG_TAG" "FAILED to prune swtpm qemu logs"
        DELETE_FAILURES=$((DELETE_FAILURES + 1))
    fi
fi

# Rotated tuned logs only. As above, never unlink the active *.log basename.
TUNED_REMOVED=0
if [ -d /var/log/tuned ]; then
    if ! TUNED_REMOVED=$(delete_aged /var/log/tuned -regextype posix-extended \
        -maxdepth 1 -type f \
        \( -regex '.*/[^/]+\.log\.[0-9]+(\.gz)?' \
           -o -regex '.*/[^/]+\.log-[0-9]{8}(\.gz)?' \)); then
        logger -t "$LOG_TAG" "FAILED to prune tuned logs"
        DELETE_FAILURES=$((DELETE_FAILURES + 1))
    fi
fi

# dnf5 own numeric rotations + NoID Privacy logrotate dateext archives. The active
# dnf5.log is rotated daily by noid-forensic-30day and never deleted here.
DNF_REMOVED=0
if ! DNF_REMOVED=$(delete_aged /var/log -regextype posix-extended \
    -maxdepth 1 -type f \
    \( -regex '.*/dnf5\.log\.[0-9]+(\.gz)?' \
       -o -regex '.*/dnf5\.log-[0-9]{8}(\.gz)?' \)); then
    logger -t "$LOG_TAG" "FAILED to prune dnf5 archives"
    DELETE_FAILURES=$((DELETE_FAILURES + 1))
fi

# M42_UPOWER_LIFECYCLE_BEGIN
# UPower 1.91.3 culls records older than seven days whenever it saves a loaded
# device history. It uses atomic file replacement but exposes no maintained
# external-prune API or cooperating lock. A quiet loaded device can still have
# an old mtime, so mtime alone cannot prove that a file is inactive. Delete old
# whole files only when systemd proves that no upowerd process exists. The
# upower.service drop-in orders this helper before every daemon start; the
# daily timer honestly defers this scope while the daemon remains active.
UPOWER_FILES_REMOVED=0
UPOWER_FILES_DEFERRED=0
UPOWER_QUERY_OK=1
UPOWER_ACTIVE_STATE=""
UPOWER_MAIN_PID=""
if ! UPOWER_UNIT_PROPERTIES=$(/usr/bin/systemctl show upower.service \
    --property=ActiveState --property=MainPID 2>/dev/null); then
    logger -t "$LOG_TAG" "FAILED to inspect UPower process state"
    UPOWER_QUERY_OK=0
fi
if [ "$UPOWER_QUERY_OK" -eq 1 ]; then
    while IFS='=' read -r upower_key upower_value; do
        case "$upower_key" in
            ActiveState)
                [ -z "$UPOWER_ACTIVE_STATE" ] || UPOWER_QUERY_OK=0
                UPOWER_ACTIVE_STATE=$upower_value
                ;;
            MainPID)
                [ -z "$UPOWER_MAIN_PID" ] || UPOWER_QUERY_OK=0
                UPOWER_MAIN_PID=$upower_value
                ;;
            *) UPOWER_QUERY_OK=0 ;;
        esac
    done <<< "$UPOWER_UNIT_PROPERTIES"
fi
case "$UPOWER_MAIN_PID" in
    ''|*[!0-9]*) UPOWER_QUERY_OK=0 ;;
esac
case "$UPOWER_ACTIVE_STATE" in
    inactive|failed|activating|deactivating|active) ;;
    *) UPOWER_QUERY_OK=0 ;;
esac

if [ "$UPOWER_QUERY_OK" -ne 1 ]; then
    logger -t "$LOG_TAG" "REFUSED inconsistent UPower process state"
    DELETE_FAILURES=$((DELETE_FAILURES + 1))
elif [ "$UPOWER_MAIN_PID" -gt 0 ]; then
    case "$UPOWER_ACTIVE_STATE" in
        active|activating|deactivating)
            UPOWER_FILES_DEFERRED=1
            logger -t "$LOG_TAG" \
                "DEFERRED UPower history prune: daemon owns the writer boundary"
            ;;
        *)
            logger -t "$LOG_TAG" "REFUSED inconsistent UPower process identity"
            DELETE_FAILURES=$((DELETE_FAILURES + 1))
            ;;
    esac
elif [ "$UPOWER_ACTIVE_STATE" = active ]; then
    logger -t "$LOG_TAG" "REFUSED active UPower state without a main process"
    DELETE_FAILURES=$((DELETE_FAILURES + 1))
elif [ -d /var/lib/upower ]; then
    if ! UPOWER_FILES_REMOVED=$(delete_aged /var/lib/upower \
        -regextype posix-extended -maxdepth 1 -type f \
        -regex '.*/history-[^/]+\.dat'); then
        logger -t "$LOG_TAG" \
            "FAILED to prune stopped-daemon UPower history files"
        DELETE_FAILURES=$((DELETE_FAILURES + 1))
    fi
fi
# M42_UPOWER_LIFECYCLE_END

# `maxage` is considered by logrotate only while the active basename is being
# rotated. An empty active aide.log/wtmp/btmp can therefore leave an old archive
# untouched. Enforce the archive age independently without matching the active
# basenames.
ACCOUNTING_REMOVED=0
if ! ACCOUNTING_REMOVED=$(delete_aged /var/log -regextype posix-extended \
    -maxdepth 1 -type f \
    \( -regex '.*/(wtmp|btmp)\.[0-9]+(\.gz)?' \
       -o -regex '.*/(wtmp|btmp)-[0-9]{8}(\.gz)?' \)); then
    logger -t "$LOG_TAG" "FAILED to prune wtmp/btmp archives"
    DELETE_FAILURES=$((DELETE_FAILURES + 1))
fi

logger -t "$LOG_TAG" "removed: ${AIDE_REMOVED} aide reports/archives, ${LIBVIRT_REMOVED} libvirt-qemu, ${SWTPM_REMOVED} swtpm-qemu archives, ${TUNED_REMOVED} tuned, ${DNF_REMOVED} dnf5-rotated, ${UPOWER_FILES_REMOVED} upower histories (${UPOWER_FILES_DEFERRED} daemon-owned deferral), ${ACCOUNTING_REMOVED} wtmp/btmp archives; swtpm: ${SWTPM_ELIGIBLE} closed eligible (${SWTPM_DEFAULT_LABEL} Fedora-default orphan), ${SWTPM_ALREADY_ROTATED} already rotated today, ${SWTPM_PROTECTED} active protected"
[ "$DELETE_FAILURES" -eq 0 ] \
    && [ "$SWTPM_ROTATE_FAILURES" -eq 0 ] || exit 1
exit 0
MISC_LOGS_PRUNE_EOF

# ----- 1d. noid-nm-privacy-prune.sh -----
stage_root_file /usr/local/bin/noid-nm-privacy-prune.sh 0755 \
    <<'NM_PRIVACY_PRUNE_EOF'
#!/bin/bash
# NoID Privacy — clear NetworkManager generated connection history
#
# Layer A — global state files in /var/lib/NetworkManager/:
#   - seen-bssids: BSSIDs observed for saved Wi-Fi connections (= location history)
#   - timestamps:  per-connection last-active epoch (= temporal trail of connections)
# NetworkManager 1.56.1 loads both databases once at daemon startup and keeps
# the authoritative copy in RAM. Reloading configuration or profiles does not
# reload them, and daemon shutdown writes RAM back to disk. Therefore Layer A
# runs only while NetworkManager is inactive and is ordered before every daemon
# start. A daily run against an active daemon explicitly skips Layer A rather
# than claiming that a live truncate erased the in-memory history.
#
# Layer B — legacy/imported generated state inside exact system profiles:
#   - Current NetworkManager documents 802-11-wireless.seen-bssids and
#     connection.timestamp as read-only state that is not preserved as profile
#     configuration. Old/imported keyfiles can nevertheless carry those keys.
#     Remove `timestamp=` only from [connection], and `seen-bssids=` only from
#     [wifi]/[802-11-wireless]. Same-named VPN/plugin/custom keys survive.
#
# Trade-offs: clearing seen-bssids can add discovery latency for hidden SSIDs.
# Clearing timestamps removes NetworkManager's recency tie-break among otherwise
# equal autoconnect candidates. Explicit `autoconnect-priority` values avoid
# relying on that recency history. Manual `bssid=` pins remain untouched.
#
# Every changed candidate is parsed first by NetworkManager's native offline
# keyfile path. With a running daemon, the exact published file is then loaded
# through `nmcli connection load`; this updates it without a global reload or
# disconnect. An atomic exchange retains the original until native loading and
# all postconditions succeed, so a rejected edit rolls back byte-for-byte.

set -uo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 0077

if [ "$#" -ne 0 ]; then
    echo 'Usage: noid-nm-privacy-prune.sh' >&2
    exit 2
fi

LOG_TAG="noid-nm-privacy-prune"
FAILURES=0
ACTIVE_CANDIDATE=""
ACTIVE_PROFILE=""
ACTIVE_EXCHANGED=0

restore_signal_traps() {
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
}

rollback_active_profile() {
    local rollback_failed=0

    trap '' HUP INT TERM
    if [ "$ACTIVE_EXCHANGED" -eq 1 ]; then
        if /usr/bin/mv --exchange -T -- \
                "$ACTIVE_CANDIDATE" "$ACTIVE_PROFILE"; then
            ACTIVE_EXCHANGED=0
            sync -- "$ACTIVE_PROFILE" \
                "$NMCONN_DIR" >/dev/null 2>&1 || rollback_failed=1
        else
            rollback_failed=1
        fi
    fi
    if [ "$ACTIVE_EXCHANGED" -eq 0 ] && [ -n "$ACTIVE_CANDIDATE" ]; then
        rm -f -- "$ACTIVE_CANDIDATE" || rollback_failed=1
    fi
    ACTIVE_CANDIDATE=""
    ACTIVE_PROFILE=""
    restore_signal_traps
    return "$rollback_failed"
}

cleanup_nm_candidates() {
    local saved_rc=$? cleanup_failed=0

    trap - EXIT
    trap '' HUP INT TERM
    if [ "$ACTIVE_EXCHANGED" -eq 1 ]; then
        if ! /usr/bin/mv --exchange -T -- \
                "$ACTIVE_CANDIDATE" "$ACTIVE_PROFILE"; then
            logger -t "$LOG_TAG" \
                "FAILED to roll back an interrupted NetworkManager profile edit"
            cleanup_failed=1
        else
            ACTIVE_EXCHANGED=0
            sync -- "$ACTIVE_PROFILE" \
                "$NMCONN_DIR" >/dev/null 2>&1 || cleanup_failed=1
        fi
    fi
    if [ "$ACTIVE_EXCHANGED" -eq 0 ] && [ -n "$ACTIVE_CANDIDATE" ]; then
        rm -f -- "$ACTIVE_CANDIDATE" || cleanup_failed=1
    fi
    if [ "$saved_rc" -eq 0 ] && [ "$cleanup_failed" -ne 0 ]; then
        exit 1
    fi
    return "$saved_rc"
}
trap cleanup_nm_candidates EXIT
restore_signal_traps

verify_directory() {
    local path=$1 expected=$2

    # Directory st_nlink is filesystem-specific: the live SquashFS lower
    # layer reports 2 here, while the installed Btrfs and copied-up overlay
    # directories report 1. It is not a stable path-identity property.
    # Directory type, canonical path, owner/mode and SELinux label remain
    # independently fail-closed below.
    [ -d "$path" ] \
        && [ ! -L "$path" ] \
        && [ "$(readlink -e -- "$path" 2>/dev/null)" = "$path" ] \
        && [ "$(stat -Lc '%u:%g:%a' -- "$path" 2>/dev/null)" = \
            "$expected" ] \
        && /usr/sbin/matchpathcon -V "$path" >/dev/null
}

remove_stale_candidates() {
    local directory=$1 pattern=$2 candidate_class=$3 stale stale_meta

    for stale in "$directory"/$pattern; do
        if [ ! -e "$stale" ] && [ ! -L "$stale" ]; then
            continue
        fi
        stale_meta=$(stat -Lc '%u:%g:%a:%h' -- "$stale" 2>/dev/null || true)
        case "$candidate_class:$stale_meta" in
            state:0:0:600:1|state:0:0:644:1|profile:0:0:600:1) ;;
            *) return 1 ;;
        esac
        if [ -L "$stale" ] || [ ! -f "$stale" ] \
           || ! /usr/sbin/matchpathcon -V "$stale" >/dev/null \
           || ! rm -f -- "$stale"; then
            return 1
        fi
    done
    sync -- "$directory"
}

profile_has_generated_state() {
    /usr/bin/awk '
        /^[[:space:]]*\[[^][]+\][[:space:]]*$/ {
            section = $0
            sub(/^[[:space:]]*\[/, "", section)
            sub(/\][[:space:]]*$/, "", section)
            next
        }
        section == "connection" &&
            /^[[:space:]]*timestamp[[:space:]]*=/ { found = 1 }
        (section == "wifi" || section == "802-11-wireless") &&
            /^[[:space:]]*seen-bssids[[:space:]]*=/ { found = 1 }
        END { exit(found ? 0 : 1) }
    ' "$1"
}

sanitize_profile() {
    /usr/bin/awk '
        /^[[:space:]]*\[[^][]+\][[:space:]]*$/ {
            section = $0
            sub(/^[[:space:]]*\[/, "", section)
            sub(/\][[:space:]]*$/, "", section)
            print
            next
        }
        section == "connection" &&
            /^[[:space:]]*timestamp[[:space:]]*=/ { next }
        (section == "wifi" || section == "802-11-wireless") &&
            /^[[:space:]]*seen-bssids[[:space:]]*=/ { next }
        { print }
    ' "$1"
}

NM_STATE_DIR=/var/lib/NetworkManager
NMCONN_DIR=/etc/NetworkManager/system-connections
if ! verify_directory "$NM_STATE_DIR" "0:0:700"; then
    logger -t "$LOG_TAG" "REFUSED unsafe NetworkManager state directory"
    exit 1
fi
if ! verify_directory "$NMCONN_DIR" "0:0:755"; then
    logger -t "$LOG_TAG" "REFUSED unsafe NetworkManager profile directory"
    exit 1
fi
if ! remove_stale_candidates \
        "$NM_STATE_DIR" '.noid-nm-state.*' state \
   || ! remove_stale_candidates \
        "$NMCONN_DIR" '.noid-nm-profile.*' profile; then
    logger -t "$LOG_TAG" \
        "REFUSED unsafe or unremovable stale NetworkManager candidate"
    exit 1
fi

# A queued NetworkManager start can already report ActiveState=activating while
# this ordered prerequisite still runs. MainPID is the load-bearing boundary:
# PID 0 means no daemon can own or rewrite the RAM databases yet. A non-zero
# PID always defers Layer A, including stop/reload transitions. Reading both
# properties in one invocation also avoids a split-query classification race.
NM_UNIT_PROPERTIES=$(/usr/bin/systemctl show NetworkManager.service \
    --property=ActiveState --property=MainPID 2>/dev/null) || {
    logger -t "$LOG_TAG" \
        "DEFERRED: cannot inspect NetworkManager process state"
    exit 1
}
NM_ACTIVE_STATE=$(printf '%s\n' "$NM_UNIT_PROPERTIES" \
    | /usr/bin/awk -F= '$1 == "ActiveState" { print $2 }')
NM_MAIN_PID=$(printf '%s\n' "$NM_UNIT_PROPERTIES" \
    | /usr/bin/awk -F= '$1 == "MainPID" { print $2 }')
case "$NM_MAIN_PID" in
    0)
        case "$NM_ACTIVE_STATE" in
            inactive|failed|activating|deactivating) NM_RUNNING=0 ;;
            *)
                logger -t "$LOG_TAG" \
                    "DEFERRED: inconsistent NetworkManager process state"
                exit 1
                ;;
        esac
        ;;
    ''|*[!0-9]*)
        logger -t "$LOG_TAG" \
            "DEFERRED: invalid NetworkManager main-process identity"
        exit 1
        ;;
    *)
        case "$NM_ACTIVE_STATE" in
            active|reloading|activating|deactivating) NM_RUNNING=1 ;;
            *)
                logger -t "$LOG_TAG" \
                    "DEFERRED: inconsistent NetworkManager process state"
                exit 1
                ;;
        esac
        ;;
esac

# Layer A — global state files
CLEARED_GLOBAL=0
if [ "$NM_RUNNING" -eq 0 ]; then
    logger -t "$LOG_TAG" \
        "Layer A: clearing global NM history before daemon start"
    for f in "$NM_STATE_DIR/seen-bssids" "$NM_STATE_DIR/timestamps"; do
        if [ ! -e "$f" ] && [ ! -L "$f" ]; then
            continue
        fi
        if [ -L "$f" ] || [ ! -f "$f" ]; then
            logger -t "$LOG_TAG" \
                "REFUSED non-regular/symlink NetworkManager state file"
            FAILURES=$((FAILURES + 1))
            continue
        fi
        state_meta=$(stat -Lc '%u:%g:%a:%h' -- "$f" 2>/dev/null || true)
        case "$state_meta" in
            0:0:600:1|0:0:644:1) ;;
            *)
                logger -t "$LOG_TAG" \
                    "REFUSED unexpected NetworkManager state metadata"
                FAILURES=$((FAILURES + 1))
                continue
                ;;
        esac
        if ! /usr/sbin/matchpathcon -V "$f" >/dev/null; then
            logger -t "$LOG_TAG" \
                "REFUSED unexpected NetworkManager state label"
            FAILURES=$((FAILURES + 1))
            continue
        fi

        ACTIVE_CANDIDATE=$(mktemp "$NM_STATE_DIR/.noid-nm-state.XXXXXXXX") \
            || {
                logger -t "$LOG_TAG" \
                    "FAILED to stage empty NetworkManager state"
                FAILURES=$((FAILURES + 1))
                continue
            }
        if ! chmod 0600 "$ACTIVE_CANDIDATE" \
           || ! /usr/sbin/matchpathcon -V "$ACTIVE_CANDIDATE" >/dev/null \
           || ! sync -- "$ACTIVE_CANDIDATE"; then
            rm -f -- "$ACTIVE_CANDIDATE" || true
            ACTIVE_CANDIDATE=""
            logger -t "$LOG_TAG" \
                "FAILED to prepare empty NetworkManager state"
            FAILURES=$((FAILURES + 1))
            continue
        fi

        state_publish_ok=0
        state_exchanged=0
        trap '' HUP INT TERM
        if /usr/bin/mv --exchange -T -- "$ACTIVE_CANDIDATE" "$f"; then
            state_exchanged=1
        fi
        if [ "$state_exchanged" -eq 1 ] \
           && [ -f "$ACTIVE_CANDIDATE" ] \
           && [ ! -L "$ACTIVE_CANDIDATE" ] \
           && [ "$(stat -Lc '%u:%g:%a:%h' -- \
                    "$ACTIVE_CANDIDATE" 2>/dev/null)" = "$state_meta" ] \
           && /usr/sbin/matchpathcon -V "$ACTIVE_CANDIDATE" >/dev/null \
           && [ -f "$f" ] \
           && [ ! -L "$f" ] \
           && [ "$(stat -Lc '%u:%g:%a:%h:%s' -- "$f" 2>/dev/null)" = \
                "0:0:600:1:0" ] \
           && /usr/sbin/matchpathcon -V "$f" >/dev/null \
           && sync -- "$f" "$NM_STATE_DIR" \
           && rm -f -- "$ACTIVE_CANDIDATE" \
           && sync -- "$NM_STATE_DIR"; then
            state_publish_ok=1
            ACTIVE_CANDIDATE=""
        else
            # If the exchange happened, the old file remains at the candidate
            # name. Exchange it back before retiring our empty candidate.
            if [ "$state_exchanged" -eq 1 ] \
               && [ -e "$ACTIVE_CANDIDATE" ] \
               && [ -e "$f" ]; then
                /usr/bin/mv --exchange -T -- \
                    "$ACTIVE_CANDIDATE" "$f" >/dev/null 2>&1 || true
            fi
            rm -f -- "$ACTIVE_CANDIDATE" >/dev/null 2>&1 || true
            ACTIVE_CANDIDATE=""
            sync -- "$NM_STATE_DIR" >/dev/null 2>&1 || true
        fi
        restore_signal_traps
        if [ "$state_publish_ok" -eq 1 ]; then
            CLEARED_GLOBAL=$((CLEARED_GLOBAL + 1))
        else
            logger -t "$LOG_TAG" \
                "FAILED atomic NetworkManager state clearing"
            FAILURES=$((FAILURES + 1))
        fi
    done
else
    logger -t "$LOG_TAG" \
        "Layer A: active daemon owns RAM history; deferring clear until its next start"
fi

# Layer B — legacy generated keys in exact system .nmconnection files.
logger -t "$LOG_TAG" "Layer B: stripping legacy generated keys from system-connections"

CLEARED_PROFILE=0
TOUCHED_PROFILE=0
for prof in "$NMCONN_DIR"/*.nmconnection; do
    # The glob may not match when no system profile exists.
    if [ -L "$prof" ]; then
        logger -t "$LOG_TAG" "REFUSED symlink NetworkManager profile"
        FAILURES=$((FAILURES + 1))
        continue
    fi
    [ -f "$prof" ] || continue
    case "$prof" in
        *$'\n'*|*$'\r'*)
            logger -t "$LOG_TAG" \
                "REFUSED control character in NetworkManager profile path"
            FAILURES=$((FAILURES + 1))
            continue
            ;;
    esac
    TOUCHED_PROFILE=$((TOUCHED_PROFILE + 1))
    profile_meta=$(stat -Lc '%u:%g:%a:%h' -- "$prof" 2>/dev/null || true)
    if [ "$profile_meta" != "0:0:600:1" ] \
       || ! /usr/sbin/matchpathcon -V "$prof" >/dev/null; then
        logger -t "$LOG_TAG" \
            "REFUSED unexpected NetworkManager profile metadata/label"
        FAILURES=$((FAILURES + 1))
        continue
    fi

    if profile_has_generated_state "$prof"; then
        :
    else
        generated_rc=$?
        if [ "$generated_rc" -eq 1 ]; then
            continue
        fi
        logger -t "$LOG_TAG" "FAILED to inspect NetworkManager profile"
        FAILURES=$((FAILURES + 1))
        continue
    fi

    before_sha=$(sha256sum -- "$prof" 2>/dev/null | awk '{print $1}')
    ACTIVE_CANDIDATE=$(mktemp "$NMCONN_DIR/.noid-nm-profile.XXXXXXXX") \
        || {
            logger -t "$LOG_TAG" "FAILED to stage NetworkManager profile"
            FAILURES=$((FAILURES + 1))
            continue
        }
    if ! sanitize_profile "$prof" > "$ACTIVE_CANDIDATE" \
       || ! chmod 0600 "$ACTIVE_CANDIDATE" \
       || ! /usr/sbin/matchpathcon -V "$ACTIVE_CANDIDATE" >/dev/null \
       || profile_has_generated_state "$ACTIVE_CANDIDATE" \
       || ! /usr/bin/nmcli --offline connection modify \
            < "$ACTIVE_CANDIDATE" >/dev/null 2>&1 \
       || ! sync -- "$ACTIVE_CANDIDATE"; then
        rm -f -- "$ACTIVE_CANDIDATE" || true
        ACTIVE_CANDIDATE=""
        logger -t "$LOG_TAG" \
            "FAILED to sanitize or natively validate NetworkManager profile"
        FAILURES=$((FAILURES + 1))
        continue
    fi

    current_sha=$(sha256sum -- "$prof" 2>/dev/null | awk '{print $1}')
    if [ -z "$before_sha" ] || [ "$current_sha" != "$before_sha" ] \
       || [ "$(stat -Lc '%u:%g:%a:%h' -- "$prof" 2>/dev/null)" != \
            "$profile_meta" ] \
       || ! /usr/sbin/matchpathcon -V "$prof" >/dev/null; then
        rm -f -- "$ACTIVE_CANDIDATE" || true
        ACTIVE_CANDIDATE=""
        logger -t "$LOG_TAG" \
            "DEFERRED concurrently changed NetworkManager profile"
        FAILURES=$((FAILURES + 1))
        continue
    fi

    ACTIVE_PROFILE=$prof
    trap '' HUP INT TERM
    if /usr/bin/mv --exchange -T -- "$ACTIVE_CANDIDATE" "$ACTIVE_PROFILE"; then
        ACTIVE_EXCHANGED=1
    fi
    restore_signal_traps
    if [ "$ACTIVE_EXCHANGED" -ne 1 ]; then
        rm -f -- "$ACTIVE_CANDIDATE" || true
        ACTIVE_CANDIDATE=""
        ACTIVE_PROFILE=""
        logger -t "$LOG_TAG" \
            "FAILED to atomically exchange NetworkManager profile"
        FAILURES=$((FAILURES + 1))
        continue
    fi

    profile_publish_ok=1
    if [ -L "$ACTIVE_CANDIDATE" ] || [ ! -f "$ACTIVE_CANDIDATE" ] \
       || [ "$(stat -Lc '%u:%g:%a:%h' -- \
                "$ACTIVE_CANDIDATE" 2>/dev/null)" != "$profile_meta" ] \
       || [ "$(sha256sum -- "$ACTIVE_CANDIDATE" 2>/dev/null \
                | awk '{print $1}')" != "$before_sha" ] \
       || ! /usr/sbin/matchpathcon -V "$ACTIVE_CANDIDATE" >/dev/null \
       || [ -L "$ACTIVE_PROFILE" ] || [ ! -f "$ACTIVE_PROFILE" ] \
       || [ "$(stat -Lc '%u:%g:%a:%h' -- \
                "$ACTIVE_PROFILE" 2>/dev/null)" != "0:0:600:1" ] \
       || ! /usr/sbin/matchpathcon -V "$ACTIVE_PROFILE" >/dev/null \
       || profile_has_generated_state "$ACTIVE_PROFILE" \
       || ! sync -- "$ACTIVE_PROFILE" "$NMCONN_DIR"; then
        profile_publish_ok=0
    fi
    if [ "$profile_publish_ok" -eq 1 ] && [ "$NM_RUNNING" -eq 1 ] \
       && ! /usr/bin/nmcli connection load \
            "$ACTIVE_PROFILE" >/dev/null 2>&1; then
        profile_publish_ok=0
    fi

    if [ "$profile_publish_ok" -ne 1 ]; then
        if ! rollback_active_profile; then
            logger -t "$LOG_TAG" \
                "FAILED to roll back rejected NetworkManager profile"
            exit 1
        fi
        logger -t "$LOG_TAG" \
            "FAILED NetworkManager profile publication/load; original restored"
        FAILURES=$((FAILURES + 1))
        continue
    fi

    # Commit the exchange only after native validation/loading and all final
    # postconditions. Once the retained original has been removed, register
    # the sanitized profile as irrevocably committed before the final directory
    # sync. A sync failure is still visible, but can never trigger a rollback
    # through a source path that no longer exists.
    profile_commit_ok=0
    profile_commit_irrevocable=0
    trap '' HUP INT TERM
    if rm -f -- "$ACTIVE_CANDIDATE" \
       || { [ ! -e "$ACTIVE_CANDIDATE" ] \
            && [ ! -L "$ACTIVE_CANDIDATE" ]; }; then
        ACTIVE_CANDIDATE=""
        ACTIVE_EXCHANGED=0
        ACTIVE_PROFILE=""
        profile_commit_irrevocable=1
        if sync -- "$NMCONN_DIR"; then
            profile_commit_ok=1
        fi
    fi
    restore_signal_traps
    if [ "$profile_commit_ok" -ne 1 ]; then
        if [ "$profile_commit_irrevocable" -eq 1 ]; then
            logger -t "$LOG_TAG" \
                "FAILED to sync committed NetworkManager profile sanitation"
            FAILURES=$((FAILURES + 1))
            continue
        fi
        if ! rollback_active_profile; then
            logger -t "$LOG_TAG" \
                "FAILED to recover an uncommitted NetworkManager profile"
            exit 1
        fi
        logger -t "$LOG_TAG" \
            "FAILED to retire original NetworkManager profile after exchange"
        FAILURES=$((FAILURES + 1))
        continue
    fi
    CLEARED_PROFILE=$((CLEARED_PROFILE + 1))
done

logger -t "$LOG_TAG" \
    "completed: ${CLEARED_GLOBAL} stopped-daemon state files cleared, ${CLEARED_PROFILE}/${TOUCHED_PROFILE} profiles sanitized; daemon_state=${NM_ACTIVE_STATE}, main_pid_present=$((NM_MAIN_PID > 0))"
[ "$FAILURES" -eq 0 ] || exit 1
exit 0
NM_PRIVACY_PRUNE_EOF

# ----- 1e. noid-auditd-rotate.sh -----
stage_root_file /usr/local/bin/noid-auditd-rotate.sh 0755 \
    <<'AUDITD_ROTATE_EOF'
#!/bin/bash
# NoID Privacy — daily auditd log rotation
#
# auditd's native ring is size/count-based (64 MiB × 10). It can evict earlier
# under high load, while a quiet active file can span months. This script forces
# daily rotation through audit-userspace's native `auditctl --signal rotate`
# interface so the 30-day maximum-age prune can act on a closed file.
# Rotated audit.log.[0-9]+ files are pruned by noid-audit-prune.service
# after 30 days.
#
# Triggered: noid-auditd-rotate.timer daily. Failure is visible to systemd.
# Fedora's audit-rules package owns the auditctl helper and its documented
# `--signal rotate` interface.

set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 0077

if [ "$#" -ne 0 ]; then
    echo 'Usage: noid-auditd-rotate.sh' >&2
    exit 2
fi

LOG_TAG="noid-auditd-rotate"

logger -t "$LOG_TAG" "requesting auditd log rotation through auditctl"

if [ ! -x /usr/bin/auditctl ]; then
    logger -t "$LOG_TAG" "auditctl missing — required daily rotation failed"
    exit 1
fi

if /usr/bin/auditctl --signal rotate >/dev/null 2>&1; then
    logger -t "$LOG_TAG" "auditd accepted the native rotation request"
else
    logger -t "$LOG_TAG" "FAILED to request auditd log rotation"
    exit 1
fi

exit 0
AUDITD_ROTATE_EOF

log "  [OK] 5 prune + rotate scripts atomically installed in /usr/local/sbin/"

# ============================================================================
# Step 2: Install systemd service + timer units (5 pairs)
# ============================================================================
log "Step 2: writing systemd service + timer units"

[ -d /etc/systemd/system ] && [ ! -L /etc/systemd/system ] \
    && [ "$(readlink -e /etc/systemd/system)" = /etc/systemd/system ] \
    && [ "$(stat -Lc '%u:%g:%a' /etc/systemd/system)" = 0:0:755 ] \
    || fail "/etc/systemd/system boundary is unsafe"
if [ ! -e /etc/systemd/system/NetworkManager.service.d ]; then
    install -d -m 0755 -o root -g root \
        /etc/systemd/system/NetworkManager.service.d
fi
[ -d /etc/systemd/system/NetworkManager.service.d ] \
    && [ ! -L /etc/systemd/system/NetworkManager.service.d ] \
    && [ "$(readlink -e /etc/systemd/system/NetworkManager.service.d)" = \
        /etc/systemd/system/NetworkManager.service.d ] \
    && [ "$(stat -Lc '%u:%g:%a' \
        /etc/systemd/system/NetworkManager.service.d)" = 0:0:755 ] \
    || fail "NetworkManager drop-in boundary is unsafe"
if [ ! -e /etc/systemd/system/upower.service.d ]; then
    install -d -m 0755 -o root -g root \
        /etc/systemd/system/upower.service.d
fi
[ -d /etc/systemd/system/upower.service.d ] \
    && [ ! -L /etc/systemd/system/upower.service.d ] \
    && [ "$(readlink -e /etc/systemd/system/upower.service.d)" = \
        /etc/systemd/system/upower.service.d ] \
    && [ "$(stat -Lc '%u:%g:%a' \
        /etc/systemd/system/upower.service.d)" = 0:0:755 ] \
    || fail "UPower drop-in boundary is unsafe"
# M08 owns this parent as a private root boundary for the local FSS
# verification-key receipt. M21 and historical M42 builds could widen it to
# 0755 while publishing non-secret marker files. Admit only that known legacy
# mode, tighten it before adding the opt-out contract, and reject every other
# pre-existing boundary.
if [ ! -e /etc/noid-privacy ] && [ ! -L /etc/noid-privacy ]; then
    install -d -m 0700 -o root -g root /etc/noid-privacy
fi
[ -d /etc/noid-privacy ] && [ ! -L /etc/noid-privacy ] \
    && [ "$(readlink -e /etc/noid-privacy)" = /etc/noid-privacy ] \
    || fail "NetworkManager history opt-out boundary is unsafe"
noid_etc_meta=$(stat -Lc '%u:%g:%a' /etc/noid-privacy 2>/dev/null || true)
case "$noid_etc_meta" in
    0:0:700) ;;
    0:0:755)
        chmod 0700 /etc/noid-privacy \
            || fail "cannot tighten the legacy NetworkManager opt-out boundary"
        ;;
    *) fail "NetworkManager history opt-out boundary is unsafe: $noid_etc_meta" ;;
esac
[ "$(stat -Lc '%u:%g:%a' /etc/noid-privacy 2>/dev/null || true)" = 0:0:700 ] \
    || fail "NetworkManager history opt-out boundary did not converge to 0700"

# ----- 2a. noid-install-logs-prune.{service,timer} -----
stage_root_file /etc/systemd/system/noid-install-logs-prune.service 0644 \
    <<'INSTALL_LOGS_PRUNE_SERVICE_EOF'
[Unit]
Description=NoID Privacy prune install-time logs + Anaconda ks-cfg artifacts older than 30 days
Documentation=man:find(1)

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/noid-install-logs-prune.sh
UMask=0077

NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/log /root
# Do not set ProtectHome here: every ProtectHome mode creates a protected view
# of /root before this service's targeted write allowlist is applied. The unit
# needs the real /root namespace for exactly two filename-scoped prune targets.
# Preserve that narrow /root exception while making every user home inaccessible.
InaccessiblePaths=/home
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=CAP_DAC_OVERRIDE
PrivateNetwork=yes
Nice=19
IOSchedulingClass=idle
INSTALL_LOGS_PRUNE_SERVICE_EOF

stage_root_file /etc/systemd/system/noid-install-logs-prune.timer 0644 \
    <<'INSTALL_LOGS_PRUNE_TIMER_EOF'
[Unit]
Description=Daily prune NoID Privacy install-time logs (30-day forensic cap)
Documentation=man:systemd.timer(5)

[Timer]
# Daily at 07:30 with up to 30 minutes of jitter. This shares the morning
# maintenance window with AIDE but avoids a synchronized fixed wakeup.
OnCalendar=07:30:00
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
INSTALL_LOGS_PRUNE_TIMER_EOF

# ----- 2b. noid-audit-prune.{service,timer} -----
stage_root_file /etc/systemd/system/noid-audit-prune.service 0644 \
    <<'AUDIT_PRUNE_SERVICE_EOF'
[Unit]
Description=NoID Privacy prune rotated audit logs older than 30 days
Documentation=man:auditd.conf(5) man:find(1)
After=auditd.service
Wants=auditd.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/noid-audit-prune.sh
UMask=0077

# Sandbox
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/log/audit
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH
AmbientCapabilities=
PrivateNetwork=yes

# Low priority
Nice=19
IOSchedulingClass=idle
AUDIT_PRUNE_SERVICE_EOF

stage_root_file /etc/systemd/system/noid-audit-prune.timer 0644 \
    <<'AUDIT_PRUNE_TIMER_EOF'
[Unit]
Description=Daily prune NoID Privacy rotated audit logs (30-day forensic cap)
Documentation=man:systemd.timer(5)

[Timer]
# Daily at 07:35 with 25min jitter (stagger from install-logs-prune at 07:30)
OnCalendar=07:35:00
RandomizedDelaySec=25m
Persistent=true

[Install]
WantedBy=timers.target
AUDIT_PRUNE_TIMER_EOF

# ----- 2c. noid-misc-logs-prune.{service,timer} -----
stage_root_file /etc/systemd/system/noid-misc-logs-prune.service 0644 \
    <<'MISC_LOGS_PRUNE_SERVICE_EOF'
[Unit]
Description=NoID Privacy prune exact AIDE and miscellaneous log archives older than 30 days
Documentation=man:find(1)
Before=upower.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/noid-misc-logs-prune.sh
UMask=0077

NoNewPrivileges=yes
ProtectSystem=strict
# ReadWritePaths cover all prune-target dirs. AIDE trust databases and their
# archives are deliberately absent.
#   /var/log              — AIDE reports + dnf5 archives
#   /var/log/libvirt      — qemu/*.log* per-VM
#   /var/log/swtpm        — libvirt/qemu/*.log* per-vTPM
#   /var/log/tuned        — *.log* daemon history
#   /var/lib/upower       — old history files at the stopped-daemon boundary
ReadWritePaths=/var/log -/var/log/libvirt -/var/log/tuned -/var/lib/upower
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
# logrotate's recommended `su tss tss` boundary needs the two identity-switch
# capabilities; CAP_DAC_OVERRIDE permits traversal of tss's mode-0730 log dir.
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SETGID CAP_SETUID
PrivateNetwork=yes
Nice=19
IOSchedulingClass=idle
MISC_LOGS_PRUNE_SERVICE_EOF

stage_root_file /etc/systemd/system/noid-misc-logs-prune.timer 0644 \
    <<'MISC_LOGS_PRUNE_TIMER_EOF'
[Unit]
Description=Daily prune NoID Privacy-managed AIDE, VM, package, UPower and accounting history
Documentation=man:systemd.timer(5)

[Timer]
OnCalendar=07:45:00
RandomizedDelaySec=20m
Persistent=true

[Install]
WantedBy=timers.target
MISC_LOGS_PRUNE_TIMER_EOF

# ----- 2d. noid-nm-privacy-prune.{service,timer} -----
stage_root_file /etc/systemd/system/noid-nm-privacy-prune.service 0644 \
    <<'NM_PRIVACY_PRUNE_SERVICE_EOF'
[Unit]
Description=NoID Privacy clear generated NetworkManager history at its safe lifecycle boundary
Documentation=man:NetworkManager(8) man:nm-settings-nmcli(5)
After=local-fs.target
Before=NetworkManager.service
# This explicit root-owned marker is the supported complete opt-out. A skipped
# condition is not a failure and therefore does not block NetworkManager.
ConditionPathExists=!/etc/noid-privacy/disable-nm-history-prune

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/noid-nm-privacy-prune.sh
UMask=0077

NoNewPrivileges=yes
ProtectSystem=strict
# ReadWritePaths cover both layer-A + layer-B targets:
#   /var/lib/NetworkManager      — global seen-bssids + timestamps
#   /etc/NetworkManager/system-connections — per-profile seen-bssids
# Per-file `nmcli connection load` requires NM's D-Bus socket only on the daily
# active-daemon pass; the pre-start pass uses native offline parsing.
ReadWritePaths=/var/lib/NetworkManager /etc/NetworkManager/system-connections
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
# Every accepted target is root-owned and metadata-verified before mutation;
# no capability outside the service's root UID is required.
CapabilityBoundingSet=
# NOT PrivateNetwork=yes — active-daemon per-file load needs NM's D-Bus socket.
# Network access otherwise stays restricted to AF_UNIX.
Nice=10
IOSchedulingClass=idle
NM_PRIVACY_PRUNE_SERVICE_EOF

stage_root_file /etc/systemd/system/noid-nm-privacy-prune.timer 0644 \
    <<'NM_PRIVACY_PRUNE_TIMER_EOF'
[Unit]
Description=Daily sanitize legacy generated NetworkManager profile state
Documentation=man:systemd.timer(5)

[Timer]
OnCalendar=daily
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
NM_PRIVACY_PRUNE_TIMER_EOF

# NetworkManager owns both global databases in RAM. Ordering the sanitizer
# before every daemon start is the only maintained no-disconnect clearing
# boundary. Wants keeps a failed/privacy-degraded sanitizer visible without
# turning a metadata anomaly into forced loss of all networking.
stage_root_file \
    /etc/systemd/system/NetworkManager.service.d/23-noid-history-boundary.conf \
    0644 <<'NM_HISTORY_BOUNDARY_DROPIN_EOF'
[Unit]
Wants=noid-nm-privacy-prune.service
After=noid-nm-privacy-prune.service

[Service]
# Keep newly replaced NetworkManager state databases and profiles root-only.
UMask=0077
NM_HISTORY_BOUNDARY_DROPIN_EOF

# UPower's native history writer replaces files atomically and does not expose
# a cooperating external lock. Pull the misc helper into each daemon-start
# transaction so its UPower scope runs only before a process can own the writer.
# Wants keeps an anomaly visible without denying all desktop power reporting.
stage_root_file \
    /etc/systemd/system/upower.service.d/23-noid-history-boundary.conf \
    0644 <<'UPOWER_HISTORY_BOUNDARY_DROPIN_EOF'
[Unit]
Wants=noid-misc-logs-prune.service
After=noid-misc-logs-prune.service
UPOWER_HISTORY_BOUNDARY_DROPIN_EOF

# ----- 2e. noid-auditd-rotate.{service,timer} -----
stage_root_file /etc/systemd/system/noid-auditd-rotate.service 0644 \
    <<'AUDITD_ROTATE_SERVICE_EOF'
[Unit]
Description=NoID Privacy auditd daily native force-rotate for time-capping audit.log
Documentation=man:auditctl(8) man:auditd(8)
After=auditd.service
Requires=auditd.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/noid-auditd-rotate.sh
UMask=0077

# NOT NoNewPrivileges=yes: Fedora labels auditctl auditctl_exec_t and its
# maintained SELinux policy requires the init_t -> auditctl_t domain
# transition. NNP blocks that transition with 203/EXEC. The exact capability,
# address-family, syscall, namespace and filesystem bounds below remain active.
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
PrivateDevices=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service @signal
# Fedora's maintained auditctl opens NETLINK_AUDIT and sends AUDIT_GET to
# discover auditd's PID, then uses pidfd_open + pidfd_send_signal. Keep the
# host audit control plane reachable, while AF_INET, AF_INET6 and AF_PACKET
# remain denied.
RestrictAddressFamilies=AF_UNIX AF_NETLINK
# NOT PrivateNetwork=yes: audit netlink is a host control plane, not Internet
# access, and must remain in the host network namespace. The address-family
# allowlist above still prevents this unit from opening IP or packet sockets.
CapabilityBoundingSet=CAP_AUDIT_CONTROL CAP_KILL
Nice=10
IOSchedulingClass=idle
AUDITD_ROTATE_SERVICE_EOF

stage_root_file /etc/systemd/system/noid-auditd-rotate.timer 0644 \
    <<'AUDITD_ROTATE_TIMER_EOF'
[Unit]
Description=Daily auditd force-rotate
Documentation=man:systemd.timer(5)

[Timer]
OnCalendar=07:25:00
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
AUDITD_ROTATE_TIMER_EOF

log "  [OK] 10 units + 2 daemon lifecycle drop-ins atomically installed"

# ============================================================================
# Step 3: Daily rotation + strict 30-day cap for active forensic logs
# ============================================================================
# Size-based rotation alone cannot cap a quiet active log by age. Rotate the
# active libvirt/tuned/dnf5 files daily; maxage controls archives and the M42
# prune script independently handles closed/restored swtpm logs and removes
# archives whose mtimes exceed the cutoff.
# copytruncate is used because these daemons do not share one portable reopen
# signal. At most the small copy/truncate window can lose a few log records.
log "Step 3: installing daily rotation + strict 30-day log caps"

[ -d /etc/logrotate.d ] && [ ! -L /etc/logrotate.d ] \
    && [ "$(readlink -e /etc/logrotate.d)" = /etc/logrotate.d ] \
    && [ "$(stat -Lc '%u:%g:%a' /etc/logrotate.d)" = 0:0:755 ] \
    || fail "/etc/logrotate.d boundary is unsafe"

stage_root_file /etc/logrotate.d/noid-forensic-30day 0644 \
    <<'NOID_FORENSIC_LOGROTATE_EOF'
/var/log/tuned/*.log /var/log/dnf5.log {
    daily
    rotate 30
    maxage 30
    missingok
    notifempty
    compress
    delaycompress
    dateext
    dateformat -%Y%m%d
    copytruncate
}
NOID_FORENSIC_LOGROTATE_EOF

# libvirt already ships a stanza for the same qemu/*.log glob. Replace that
# stanza instead of duplicating the path in another file: logrotate rejects
# duplicate log entries and would otherwise abort the entire rotation run.
stage_root_file /etc/logrotate.d/libvirtd.qemu 0644 \
    <<'LIBVIRTD_QEMU_LOGROTATE_EOF'
/var/log/libvirt/qemu/*.log {
    daily
    rotate 30
    maxage 30
    missingok
    notifempty
    compress
    delaycompress
    dateext
    dateformat -%Y%m%d
    copytruncate
}

LIBVIRTD_QEMU_LOGROTATE_EOF

# Fedora's AIDE stanza matches every *.log, including immutable timestamped
# per-run reports. Rotating such a report refreshes the archive mtime and can
# extend retention far beyond its original creation time. Restrict logrotate
# to the shared active aide.log; M42 age-prunes per-run reports in place using
# their unchanged mtimes.
stage_root_file /etc/logrotate.d/aide 0644 <<'AIDE_LOGROTATE_EOF'
/var/log/aide/aide.log {
    daily
    rotate 30
    maxage 30
    missingok
    notifempty
    compress
    delaycompress
    dateext
    dateformat -%Y%m%d
    copytruncate
}
AIDE_LOGROTATE_EOF

# Replace the distribution stanzas instead of editing selected directives.
# The stock wtmp stanza may include `minsize`, which suppresses rotations on a
# low-activity host and therefore defeats a time cap. maxage alone only removes
# rotated files, so daily rotation is required as well.
stage_root_file /etc/logrotate.d/wtmp 0644 <<'WTMP_LOGROTATE_EOF'
/var/log/wtmp {
    daily
    rotate 30
    maxage 30
    missingok
    notifempty
    compress
    delaycompress
    dateext
    dateformat -%Y%m%d
    create 0664 root utmp
}
WTMP_LOGROTATE_EOF

stage_root_file /etc/logrotate.d/btmp 0644 <<'BTMP_LOGROTATE_EOF'
/var/log/btmp {
    daily
    rotate 30
    maxage 30
    missingok
    notifempty
    compress
    delaycompress
    dateext
    dateformat -%Y%m%d
    create 0660 root utmp
}
BTMP_LOGROTATE_EOF

log "  [OK] active-log and wtmp/btmp policies atomically published"

# ============================================================================
# Step 4: Reload systemd + enable all 5 timers
# ============================================================================
log "Step 4: systemd-daemon-reload + enable 5 timers"

if ! systemctl daemon-reload; then
    log "  [FAIL] systemd daemon-reload failed"
    exit 1
fi

# Enable timers. They actually fire at first reboot (Persistent=true catches
# any missed daily schedule). Enable is idempotent.
for t in noid-install-logs-prune.timer noid-audit-prune.timer \
         noid-misc-logs-prune.timer noid-nm-privacy-prune.timer \
         noid-auditd-rotate.timer; do
    if systemctl enable "$t" 2>/dev/null; then
        log "  [OK] $t enabled"
    else
        log "  [FAIL] $t could not be enabled"
        exit 1
    fi
done

# ============================================================================
# Step 5: Verification (verify_fail counter pattern, analog M41 + M22 + M26)
# ============================================================================
log "Step 5: verification"

verify_fail=0
checks_total=0
scripts_installed=0
timers_enabled=0

# 5.1: All 5 prune+rotate scripts present + executable
for s in noid-install-logs-prune.sh noid-audit-prune.sh \
         noid-misc-logs-prune.sh noid-nm-privacy-prune.sh \
        noid-auditd-rotate.sh; do
    checks_total=$((checks_total + 1))
    script_path="/usr/local/bin/$s"
    script_meta=$(stat -Lc '%u:%g:%a:%h' "$script_path" 2>/dev/null || true)
    if [ -f "$script_path" ] && [ ! -L "$script_path" ] \
       && [ -x "$script_path" ] && [ "$script_meta" = "0:0:755:1" ] \
       && /usr/sbin/matchpathcon -V "$script_path" >/dev/null; then
        scripts_installed=$((scripts_installed + 1))
        log "  [OK] $script_path installed as root:root 0755 regular file"
    else
        log "  [FAIL] $script_path missing or has unsafe metadata ($script_meta)"
        verify_fail=$((verify_fail + 1))
    fi
done

# 5.2: bash -n on all 5 scripts
for s in noid-install-logs-prune.sh noid-audit-prune.sh \
         noid-misc-logs-prune.sh noid-nm-privacy-prune.sh \
         noid-auditd-rotate.sh; do
    checks_total=$((checks_total + 1))
    if bash -n "/usr/local/sbin/$s" 2>/dev/null; then
        log "  [OK] /usr/local/sbin/$s bash -n clean"
    else
        log "  [FAIL] /usr/local/sbin/$s bash -n syntax error"
        verify_fail=$((verify_fail + 1))
    fi
done

# 5.3: All 10 systemd unit files have exact metadata and canonical labels.
for u in noid-install-logs-prune.service noid-install-logs-prune.timer \
         noid-audit-prune.service noid-audit-prune.timer \
         noid-misc-logs-prune.service noid-misc-logs-prune.timer \
         noid-nm-privacy-prune.service noid-nm-privacy-prune.timer \
         noid-auditd-rotate.service noid-auditd-rotate.timer; do
    checks_total=$((checks_total + 1))
    unit_path="/etc/systemd/system/$u"
    unit_meta=$(stat -Lc '%u:%g:%a:%h' -- "$unit_path" 2>/dev/null || true)
    if [ -f "$unit_path" ] && [ ! -L "$unit_path" ] \
       && [ "$unit_meta" = "0:0:644:1" ] \
       && /usr/sbin/matchpathcon -V "$unit_path" >/dev/null; then
        log "  [OK] $unit_path installed as root:root 0644 regular file"
    else
        log "  [FAIL] $unit_path missing or has unsafe metadata ($unit_meta)"
        verify_fail=$((verify_fail + 1))
    fi
done

# Bind the lifecycle drop-ins that make daemon-owned history pruning real
# stopped-daemon pre-start operations.
checks_total=$((checks_total + 1))
NM_HISTORY_DROPIN=/etc/systemd/system/NetworkManager.service.d/23-noid-history-boundary.conf
nm_dropin_meta=$(stat -Lc '%u:%g:%a:%h' -- \
    "$NM_HISTORY_DROPIN" 2>/dev/null || true)
if [ -d /etc/noid-privacy ] && [ ! -L /etc/noid-privacy ] \
   && [ "$(stat -Lc '%u:%g:%a' /etc/noid-privacy)" = "0:0:700" ] \
   && [ -f "$NM_HISTORY_DROPIN" ] && [ ! -L "$NM_HISTORY_DROPIN" ] \
   && [ "$nm_dropin_meta" = "0:0:644:1" ] \
   && /usr/sbin/matchpathcon -V "$NM_HISTORY_DROPIN" >/dev/null \
   && grep -qFx 'Wants=noid-nm-privacy-prune.service' "$NM_HISTORY_DROPIN" \
   && grep -qFx 'After=noid-nm-privacy-prune.service' "$NM_HISTORY_DROPIN" \
   && grep -qFx 'UMask=0077' "$NM_HISTORY_DROPIN"; then
    log "  [OK] NetworkManager lifecycle/UMask boundary is installed"
else
    log "  [FAIL] NetworkManager lifecycle/UMask boundary is incomplete"
    verify_fail=$((verify_fail + 1))
fi

checks_total=$((checks_total + 1))
UPOWER_HISTORY_DROPIN=/etc/systemd/system/upower.service.d/23-noid-history-boundary.conf
upower_dropin_meta=$(stat -Lc '%u:%g:%a:%h' -- \
    "$UPOWER_HISTORY_DROPIN" 2>/dev/null || true)
if [ -f "$UPOWER_HISTORY_DROPIN" ] && [ ! -L "$UPOWER_HISTORY_DROPIN" ] \
   && [ "$upower_dropin_meta" = "0:0:644:1" ] \
   && /usr/sbin/matchpathcon -V "$UPOWER_HISTORY_DROPIN" >/dev/null \
   && grep -qFx 'Wants=noid-misc-logs-prune.service' "$UPOWER_HISTORY_DROPIN" \
   && grep -qFx 'After=noid-misc-logs-prune.service' "$UPOWER_HISTORY_DROPIN"; then
    log "  [OK] UPower stopped-daemon history boundary is installed"
else
    log "  [FAIL] UPower history lifecycle boundary is incomplete"
    verify_fail=$((verify_fail + 1))
fi

# Every root job gets a private creation mask independently of its script.
checks_total=$((checks_total + 1))
service_umasks=0
for s in noid-install-logs-prune.service noid-audit-prune.service \
         noid-misc-logs-prune.service noid-nm-privacy-prune.service \
         noid-auditd-rotate.service; do
    if grep -qFx 'UMask=0077' "/etc/systemd/system/$s"; then
        service_umasks=$((service_umasks + 1))
    fi
done
if [ "$service_umasks" -eq 5 ]; then
    log "  [OK] all five M42 services enforce UMask=0077"
else
    log "  [FAIL] only $service_umasks of 5 M42 services enforce UMask=0077"
    verify_fail=$((verify_fail + 1))
fi

# Validate the complete service/timer dependency graph with systemd's parser.
checks_total=$((checks_total + 1))
SYSTEMD_VERIFY_LOG=$(mktemp -t noid-m42-systemd-verify.XXXXXX)
if systemd-analyze verify \
        NetworkManager.service \
        upower.service \
        /etc/systemd/system/noid-install-logs-prune.{service,timer} \
        /etc/systemd/system/noid-audit-prune.{service,timer} \
        /etc/systemd/system/noid-misc-logs-prune.{service,timer} \
        /etc/systemd/system/noid-nm-privacy-prune.{service,timer} \
        /etc/systemd/system/noid-auditd-rotate.{service,timer} \
        > "$SYSTEMD_VERIFY_LOG" 2>&1; then
    log "  [OK] all M42 service/timer units pass systemd-analyze verify"
else
    log "  [FAIL] M42 systemd unit verification failed"
    sed 's/^/         /' "$SYSTEMD_VERIFY_LOG"
    verify_fail=$((verify_fail + 1))
fi
rm -f -- "$SYSTEMD_VERIFY_LOG"

# 5.4: All 5 timers enabled (timers.target.wants symlinks)
for t in noid-install-logs-prune.timer noid-audit-prune.timer \
         noid-misc-logs-prune.timer noid-nm-privacy-prune.timer \
         noid-auditd-rotate.timer; do
    checks_total=$((checks_total + 1))
    timer_link="/etc/systemd/system/timers.target.wants/$t"
    timer_target=$(readlink -f -- "$timer_link" 2>/dev/null || true)
    if [ -L "$timer_link" ] \
       && [ "$timer_target" = "/etc/systemd/system/$t" ]; then
        timers_enabled=$((timers_enabled + 1))
        log "  [OK] $t enabled with exact timers.target.wants target"
    else
        log "  [FAIL] $t enablement link missing or targets '$timer_target'"
        verify_fail=$((verify_fail + 1))
    fi
done

# 5.5: Every logrotate policy has exact metadata and parses independently.
for f in /etc/logrotate.d/noid-forensic-30day \
         /etc/logrotate.d/libvirtd.qemu /etc/logrotate.d/aide \
         /etc/logrotate.d/wtmp /etc/logrotate.d/btmp; do
    checks_total=$((checks_total + 1))
    logrotate_meta=$(stat -Lc '%u:%g:%a:%h' -- "$f" 2>/dev/null || true)
    if [ -f "$f" ] && [ ! -L "$f" ] \
       && [ "$logrotate_meta" = "0:0:644:1" ] \
       && /usr/sbin/matchpathcon -V "$f" >/dev/null; then
        log "  [OK] $f installed as root:root 0644 regular file"
    else
        log "  [FAIL] $f missing or has unsafe metadata ($logrotate_meta)"
        verify_fail=$((verify_fail + 1))
    fi

    checks_total=$((checks_total + 1))
    if /usr/sbin/logrotate --debug --state /dev/null "$f" >/dev/null 2>&1; then
        log "  [OK] $f passes logrotate parser validation"
    else
        log "  [FAIL] $f does not parse as an independent logrotate policy"
        verify_fail=$((verify_fail + 1))
    fi
done

# 5.6: active logrotate policy installed with all three required time guards.
checks_total=$((checks_total + 1))
if [ -f /etc/logrotate.d/noid-forensic-30day ] \
   && grep -q '^[[:space:]]*daily' /etc/logrotate.d/noid-forensic-30day \
   && grep -q '^[[:space:]]*rotate[[:space:]]\+30' /etc/logrotate.d/noid-forensic-30day \
   && grep -q '^[[:space:]]*maxage[[:space:]]\+30' /etc/logrotate.d/noid-forensic-30day; then
    log "  [OK] active forensic logs rotate daily with rotate/maxage 30"
else
    log "  [FAIL] /etc/logrotate.d/noid-forensic-30day is missing required caps"
    verify_fail=$((verify_fail + 1))
fi

checks_total=$((checks_total + 1))
if [ -f /etc/logrotate.d/libvirtd.qemu ] \
   && grep -qF '/var/log/libvirt/qemu/*.log {' /etc/logrotate.d/libvirtd.qemu \
   && ! grep -qF '/var/log/swtpm/' /etc/logrotate.d/libvirtd.qemu \
   && grep -q '^[[:space:]]*daily' /etc/logrotate.d/libvirtd.qemu \
   && grep -q '^[[:space:]]*rotate[[:space:]]\+30' /etc/logrotate.d/libvirtd.qemu \
   && grep -q '^[[:space:]]*maxage[[:space:]]\+30' /etc/logrotate.d/libvirtd.qemu; then
    log "  [OK] global libvirt qemu rotation excludes SELinux-isolated swtpm logs"
else
    log "  [FAIL] /etc/logrotate.d/libvirtd.qemu has an unsafe/incomplete scope"
    verify_fail=$((verify_fail + 1))
fi

checks_total=$((checks_total + 1))
if grep -qF '*:svirt_image_t:*)' /usr/local/sbin/noid-misc-logs-prune.sh \
   && grep -qF '*:virt_log_t:*)' /usr/local/sbin/noid-misc-logs-prune.sh \
   && grep -qF '*:var_log_t:*)' /usr/local/sbin/noid-misc-logs-prune.sh \
   && grep -qF '"$SWTPM_TSS_UID:$SWTPM_TSS_GID:644:1")' \
        /usr/local/sbin/noid-misc-logs-prune.sh \
   && grep -qF '/usr/sbin/logrotate --force --state /dev/null' \
        /usr/local/sbin/noid-misc-logs-prune.sh; then
    log "  [OK] closed swtpm rotation preserves active-VM SELinux isolation"
else
    log "  [FAIL] closed swtpm rotation/isolation contract is incomplete"
    verify_fail=$((verify_fail + 1))
fi

checks_total=$((checks_total + 1))
if [ -f /etc/logrotate.d/aide ] \
   && grep -q '^/var/log/aide/aide\.log[[:space:]]*{' /etc/logrotate.d/aide \
   && ! grep -q '^/var/log/aide/\*\.log' /etc/logrotate.d/aide \
   && grep -q '^[[:space:]]*daily' /etc/logrotate.d/aide \
   && grep -q '^[[:space:]]*rotate[[:space:]]\+30' /etc/logrotate.d/aide \
   && grep -q '^[[:space:]]*maxage[[:space:]]\+30' /etc/logrotate.d/aide; then
    log "  [OK] active aide.log is capped without rotating per-run reports"
else
    log "  [FAIL] /etc/logrotate.d/aide does not isolate/cap active aide.log"
    verify_fail=$((verify_fail + 1))
fi

# wtmp/btmp must not retain the stock minsize gate: it can suppress daily
# rotation indefinitely on low-activity systems.
for f in /etc/logrotate.d/wtmp /etc/logrotate.d/btmp; do
    checks_total=$((checks_total + 1))
    if [ -f "$f" ] \
       && grep -q '^[[:space:]]*daily' "$f" \
       && grep -q '^[[:space:]]*rotate[[:space:]]\+30' "$f" \
       && grep -q '^[[:space:]]*maxage[[:space:]]\+30' "$f" \
       && ! grep -q '^[[:space:]]*minsize' "$f"; then
        log "  [OK] $f rotates daily with rotate/maxage 30 and no minsize gate"
    else
        log "  [FAIL] $f is missing the strict daily 30-day cap"
        verify_fail=$((verify_fail + 1))
    fi
done

# M42_FINAL_PAYLOAD_BINDING_FUNCTION_BEGIN
verify_m42_payload_binding() {
    local index expected_path published_path expected_sha live_sha
    local manifest=""

    PAYLOADS_BOUND=${#M42_EXPECTED_PAYLOAD_PATHS[@]}
    PAYLOAD_MANIFEST_SHA256=""
    [ "$PAYLOADS_BOUND" -eq 22 ] \
        && [ "${#M42_PUBLISHED_PATHS[@]}" -eq "$PAYLOADS_BOUND" ] \
        && [ "${#M42_PUBLISHED_SHA256[@]}" -eq "$PAYLOADS_BOUND" ] \
        || return 1

    for ((index = 0; index < PAYLOADS_BOUND; index++)); do
        expected_path=${M42_EXPECTED_PAYLOAD_PATHS[$index]}
        published_path=${M42_PUBLISHED_PATHS[$index]}
        expected_sha=${M42_PUBLISHED_SHA256[$index]}
        [ "$published_path" = "$expected_path" ] \
            && [[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]] \
            || return 1
        live_sha=$(/usr/bin/sha256sum -- "$expected_path" 2>/dev/null \
            | /usr/bin/awk '{print $1}') \
            || return 1
        [ "$live_sha" = "$expected_sha" ] || return 1
        manifest+="${expected_sha}  ${expected_path}"$'\n'
    done

    PAYLOAD_MANIFEST_SHA256=$(printf '%s' "$manifest" \
        | /usr/bin/sha256sum | /usr/bin/awk '{print $1}') \
        || return 1
    [[ "$PAYLOAD_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]]
}
# M42_FINAL_PAYLOAD_BINDING_FUNCTION_END

checks_total=$((checks_total + 1))
if verify_m42_payload_binding; then
    log "  [OK] all $PAYLOADS_BOUND final M42 payloads match their publication candidates"
else
    log "  [FAIL] final M42 payload bytes/order differ from their publication candidates"
    verify_fail=$((verify_fail + 1))
fi

if [ "$verify_fail" -gt 0 ]; then
    log "[FAIL] $verify_fail of $checks_total verification check(s) failed — aborting build"
    exit 1
fi

log "  [OK] all $checks_total verification checks passed"

# ============================================================================
# Step 6: Health Stamp
# ============================================================================
log "Step 6: writing health stamp"

# M42_HEALTH_PUBLICATION_BEGIN
if [ ! -d "$M42_STATE_DIR" ] || [ -L "$M42_STATE_DIR" ] \
   || [ "$(stat -Lc '%u:%g:%a' -- "$M42_STATE_DIR" 2>/dev/null || true)" != \
        0:0:755 ] \
   || ! /usr/sbin/matchpathcon -V "$M42_STATE_DIR" >/dev/null; then
    log "  [FAIL] shared health-stamp directory drifted before publication"
    exit 1
fi

verify_m42_health_stamp() {
    local path="$1"
    [ -f "$path" ] \
        && [ ! -L "$path" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' -- "$path" 2>/dev/null || true)" = \
            0:0:644:1 ] \
        && [ "$(wc -l < "$path")" -eq 14 ] \
        && grep -qFx '# NoID Privacy — Module 42 Health Stamp' "$path" \
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
        && [ "$(grep -c '^timers_enabled=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^scripts_installed=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^payloads_bound=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^payload_manifest_sha256=' "$path" || true)" -eq 1 ] \
        && grep -qFx 'module=42' "$path" \
        && grep -qFx 'name=forensic-retention' "$path" \
        && grep -qFx 'version=7' "$path" \
        && grep -qFx 'status=ok' "$path" \
        && grep -Eq \
            '^timestamp=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' \
            "$path" \
        && grep -qFx "checks_passed=$checks_total" "$path" \
        && grep -qFx "checks_total=$checks_total" "$path" \
        && grep -qFx "timers_enabled=$timers_enabled" "$path" \
        && grep -qFx "scripts_installed=$scripts_installed" "$path" \
        && grep -qFx "payloads_bound=$PAYLOADS_BOUND" "$path" \
        && grep -Eq '^payload_manifest_sha256=[0-9a-f]{64}$' "$path" \
        && grep -qFx \
            "payload_manifest_sha256=$PAYLOAD_MANIFEST_SHA256" "$path"
}

STAMP_CANDIDATE=$(mktemp \
    "$M42_STATE_DIR/.stamp-42-forensic-retention.XXXXXXXX") \
    || fail "cannot create Module 42 health-stamp candidate"
cat > "$STAMP_CANDIDATE" <<STAMP_EOF || \
    fail "cannot write Module 42 health-stamp candidate"
# NoID Privacy — Module 42 Health Stamp
# Written at end of %post verification when all checks pass.
# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.
module=42
name=forensic-retention
version=7
status=ok
timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
checks_passed=$((checks_total - verify_fail))
checks_total=$checks_total
timers_enabled=$timers_enabled
scripts_installed=$scripts_installed
payloads_bound=$PAYLOADS_BOUND
payload_manifest_sha256=$PAYLOAD_MANIFEST_SHA256
STAMP_EOF
chmod 0644 "$STAMP_CANDIDATE" \
    || fail "cannot set Module 42 health-stamp mode"
chown root:root "$STAMP_CANDIDATE" \
    || fail "cannot set Module 42 health-stamp ownership"
/usr/sbin/restorecon -F -- "$STAMP_CANDIDATE" \
    || fail "cannot label Module 42 health-stamp candidate"
/usr/sbin/matchpathcon -V "$STAMP_CANDIDATE" >/dev/null \
    || fail "Module 42 health-stamp candidate label differs"
verify_m42_health_stamp "$STAMP_CANDIDATE" \
    || fail "staged Module 42 health-stamp contract is invalid"
sync -- "$STAMP_CANDIDATE" \
    || fail "cannot sync Module 42 health-stamp candidate"
# Register the final stamp as removable before the publisher's atomic rename,
# closing the old rename-to-registration signal window.
STAMP_PUBLISHED=1
publish_root_file "$STAMP_CANDIDATE" "$STAMP" 0644
rm -f -- "$STAMP_CANDIDATE" \
    || fail "cannot retire Module 42 health-stamp source"
STAMP_CANDIDATE=""
/usr/sbin/matchpathcon -V "$STAMP" >/dev/null \
    || fail "published Module 42 health-stamp label differs"
sync -- "$STAMP" \
    || fail "cannot sync published Module 42 health stamp"
sync -- "$M42_STATE_DIR" \
    || fail "cannot sync Module 42 health-stamp directory"
verify_m42_health_stamp "$STAMP" \
    || fail "published Module 42 health-stamp contract is invalid"
STAMP_PUBLISHED=0
trap - EXIT
log "  [OK] $STAMP written atomically with exact metadata and context"
# M42_HEALTH_PUBLICATION_END

log "=== Module 42 forensic-retention complete ==="
%end
