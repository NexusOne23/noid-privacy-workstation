# ============================================================================
# Module 25 — Update Process (Manual Orchestrator + Weekly Reminder)
# Status: LOCKED 2026-08-23 (v131) — describe installation and update activation through one canonical reboot verdict and icon.
#
# Strategy: manual updates via the orchestrator + a weekly reminder timer.
# Why manual (not dnf-automatic): no background daemons (M08 philosophy),
# AIDE workflow integration (M13), NVIDIA akmod/dracut black-screen edge
# cases, snapper pre/post snapshots, firmware with user confirm, Firefox/
# Thunderbird hardening re-apply, user agency over reboot timing.
# Decisions: manual orchestrator · Mon 10:00 reminder (1h random delay) ·
# notify-send with copy-pasteable command · preset auto-enable for all
# users · English notification text.
#
# Covers:
#   - Step 1: /usr/local/bin/noid-update-all.sh (NOID_UPDATE_EOF — the
#     deployed orchestrator): 9 main steps + 4 sub-steps (5b Thunderbird
#     re-deploy, 6b GNOME extensions, 6c VSCodium extensions, 8b config-drift
#     evidence);
#     root-guard, sudo keep-alive, pre-summary post-snapshot with EXIT fallback, /run/
#     process-bound noid-update-running record, _emit_marker GUI side-channel
#   - Step 1b (retired): no VSCodium extension is image-staged. Both vendor
#     extensions are explicit M13 installer opt-ins behind their own informed
#     prompts; /etc/skel ships no third-party extension code.
#   - Step 2/3: noid-update-reminder.{service,timer} + user-preset
#   - Step 3b: login-time reboot notifier plus immediate `--status` CLI
#     (kernel-version-diff + NVIDIA running-vs-on-disk skew; marker-less)
#   - Step 3c: noid-update GTK4+libadwaita+Vte GUI + noid-askpass (zenity)
#     + launcher + .desktop (Exec=GUI, StartupWMClass=com.noidprivacy.Update)
#   - Step 3d: rejection/cleanup of obsolete automatic AIDE replacement paths
#   - Step 4: verification
#
# Deliberate deviations (do NOT re-litigate):
#   - Reboot detection is MARKER-LESS (kernel-version-diff `uname -r` vs
#     /lib/modules, world-readable + WAL-immune). NO state file, NO sudoers
#     helper — tests/25 enforces both as whole-file negatives.
#   - AIDE is check-only in the updater. Expected package drift is preserved
#     for review and is never absorbed into the active database.
#   - Step 2 uses M19's durable inhibited queue and exact verifier: main and
#     580xx branch, all four fresh modules, kmod/akmod/CUDA EVR, target kernel,
#     exact enrolled MOK certificate and atomically published initramfs hash.
#   - This workflow acquires no agent payload itself. The M13 opt-in helpers'
#     --update mode refreshes only components that user installed (consent
#     given at install time), re-validates identity/structure before
#     activation and records version + SHA-256 evidence in the per-user
#     agent-update ledger. uBO, DKIM Verifier and Just Perfection retain exact
#     image seeds but advance only in this user-started workflow: fixed upstream
#     identities, official product-marketplace stable selection,
#     compatibility/structure/digest checks, no downgrade, atomic publication
#     and a local SHA-256 evidence ledger. Every uBO candidate additionally
#     advertises the current
#     managed-storage schema and contains every selected filter-list token before
#     any profile copy changes. Their application-level background executable-
#     update checks stay disabled. RPM-managed extensions remain in the signed
#     DNF transaction; user-authorized marketplace extensions use validated,
#     non-downgrading paths with agent namespaces excluded. openh264 stays
#     --exclude'd until codec opt-in.
#   - fwupd step skips ONLY when fwupd.service is masked (is-enabled =
#     "masked"); `static` is the normal D-Bus-dormant state and falls
#     through to on-demand activation. Network-facing `fwupdmgr` calls stay in
#     the invoking user's client and use fwupd's fine-grained PolicyKit API;
#     only the networkless native quit request uses sudo. The synchronous
#     workflow finishes with bounded daemon observation and never signals the
#     daemon or disables hardware plugins.
#   - sudo keep-alive refreshes every 50s and drops the cache via `sudo -k`
#     on EXIT — the M10 timestamp_timeout=3 hardening stays untouched.
#
# Constraint notes (keep when editing):
#   - NOID_UPDATE_EOF is the deployed /usr/local/bin/noid-update-all.sh —
#     byte-parity discipline (heredoc-extract + diff after any edit);
#     tests/25 pins MANY fixed strings inside it (notification titles,
#     rollback command, rollback hint, the NVIDIA-gate comment).
#   - Locale-robust parsing: LC_ALL=C on all flatpak transaction calls +
#     fwupdmgr client calls; the fwupd progress
#     filter matches decimal-comma percents too. The dnf upgrade, fwupd
#     refresh and needs-restarting calls also run under LC_ALL=C. Reboot/service
#     decisions parse the documented DNF5 JSON schema plus its command rc.
#   - `dnf needs-restarting -s` runs as the INVOKING USER — sudo env_reset
#     strips the session D-Bus it needs (dies before stdout under sudo).
#   - F44 rpmdb is SQLite-WAL in a root-only dir → rpm queries via sudo.
#   - `dnf upgrade --refresh` owns metadata freshness; do not duplicate it
#     with an independent cache mutation.
#   - M32's canonical branding helper + GDM .session chmod + native
#     permission-policy blocks are re-asserts after dnf upgrade. Plymouth
#     causes an all-kernel rebuild only when its managed source bytes differ
#     from the pre-transaction state.
#
# Cross-reference:
#   - M08 (codec opt-in, VSCodium settings/default-GPU launcher, fwupd
#     live-skip), M10 (tmpfiles
#     permission policy + timestamp_timeout), M13 (AIDE conf + aide-check flock), M16/
#     M34 (Firefox profiles helper), M17 (GNOME extensions), M18 (flatpak),
#     M19 (nvidia hooks sibling), M20 (snapper), M24 (fwupd masks), M26
#     (vte291-gtk4 + libdnf5-plugin-actions), M32 (logo asset), M35
#     (Thunderbird re-deploy sources).
#   - M13 noid-status renders the add-on patch age from the
#     ~/.local/state/noid-privacy/extension-checks record written here. It is a
#     pure reader, so every authenticated marketplace check must publish its
#     outcome — including the runs that change nothing and the ones that fail —
#     or that surface reports an age no check established. M42 ages nothing
#     there (one overwritten line per component); M99 verifies both sides name
#     the identical path.
# ============================================================================

# No %packages block — all deps (snapper, flatpak, fwupdmgr, aide) come
# from other Modules. This snippet just ships the script + systemd units.
#
# HOWEVER: the script depends on these packages being present at runtime:
#   - snapper + snapper-plugins (Module 20)
#   - flatpak (base Fedora)
#   - fwupd (base Fedora)
#   - aide (Module 13)
# If any is missing, the script skips that step gracefully.

%post --erroronfail --log=/var/log/ks-25-update-process.log

set -euo pipefail
echo "=============================================================="
echo "[Module 25] Update Process orchestrator + reminder timer"
echo "=============================================================="

# ----------------------------------------------------------------------------
# Step 1: Install /usr/local/bin/noid-update-all.sh
# ----------------------------------------------------------------------------
# The script is a bash orchestrator: 9 main update steps + 4 nested
# sub-steps (5b Thunderbird re-deploy, 6b GNOME extensions, 6c VSCodium
# extensions, 8b config-drift evidence). STEPS=9 counts main steps only;
# sub-steps display as `[Nb/9]`. Steps: 1 snapper pre-snapshot · 2 DNF (+permission reconcile +
# NVIDIA rebuild) · 3 flatpak · 4 fwupd (manual confirm) · 5(+5b) Firefox/
# Thunderbird hardening re-apply · 6(+6b/6c) consent-gated agents/extensions ·
# 7 repo signature check · 8 AIDE check-only evidence · 8b config-drift
# evidence · 9 reboot check.
# Plus: root-guard, snapper post-snapshot before the Summary with an EXIT
# fallback for premature termination, /run/
# process/lock-bound noid-update-running record for narrow audit suppression.

echo ""
echo "[Step 1] Installing /usr/local/bin/noid-update-all.sh"

cat > /usr/local/bin/noid-update-all.sh <<'NOID_UPDATE_EOF'
#!/usr/bin/env bash
set -uo pipefail

# ============================================================================
# NoID Privacy — System Update Orchestrator
# Design rationale: see the kickstart module header.
# Shipped by: kickstart/snippets/25-update-process.ks
# ============================================================================
#
# USAGE: Call as NORMAL USER (not with sudo):
#   /usr/local/bin/noid-update-all.sh
# Script calls sudo only where needed.
#
# Weekly reminder timer fires every Monday 10:00 (randomized 1h delay)
# suggesting to run this script.
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

print_usage() {
    cat <<'USAGE_EOF'
Usage: noid-update-all.sh [--help]

Run the complete guided NoID Privacy update workflow. Invoke it as the normal
desktop user; the script requests sudo only for the individual privileged
steps.

Options:
  -h, --help  Show this help and exit without changing the system.
USAGE_EOF
}

# Parse the complete CLI before root checks, sudo, snapshots, marker files or
# any other state change. The workflow intentionally accepts no operational
# options; misspellings must never start an update.
if [ "$#" -gt 0 ]; then
    if [ "$#" -eq 1 ] && { [ "$1" = "--help" ] || [ "$1" = "-h" ]; }; then
        print_usage
        exit 0
    fi
    printf 'ERROR: unsupported argument:' >&2
    printf ' %q' "$@" >&2
    printf '\n' >&2
    print_usage >&2
    exit 2
fi

# Safety guard: this script MUST run as a normal user. Calling it via sudo
# would cause flatpak updates to install into /root/, Firefox profiles in
# /root/.config/mozilla to be scanned (or nothing if empty), and user-session
# notifications to go nowhere. The script invokes sudo internally only at
# privileged boundaries (DNF, Snapper, AIDE, boot/config publication and
# fwupd's networkless daemon-quit API).
if [ "$(id -u)" -eq 0 ]; then
    echo -e "${RED}ERROR${NC}: do not run this script as root or via sudo"
    echo -e "${YELLOW}→${NC} call it as your normal user; sudo is invoked internally where needed:"
    echo "    /usr/local/bin/noid-update-all.sh"
    exit 1
fi

# Serialize the complete workflow, not just DNF/AIDE internals. Package-manager
# locks cannot prevent two sessions from creating overlapping snapshots,
# reasserting policy concurrently or racing marker ownership.
UPDATE_LOCK=/run/lock/noid-update-all.lock
UPDATE_LOCK_GUARD_PID=
UPDATE_LOCK_READY=
UPDATE_MARKER_OWNED=0
_release_update_lock_guard() {
    if [ -n "${UPDATE_LOCK_GUARD_PID:-}" ]; then
        kill "$UPDATE_LOCK_GUARD_PID" 2>/dev/null || true
        wait "$UPDATE_LOCK_GUARD_PID" 2>/dev/null || true
        UPDATE_LOCK_GUARD_PID=
    fi
    rm -f -- "${UPDATE_LOCK_READY:-}"
    UPDATE_LOCK_READY=
}
if [ ! -e "$UPDATE_LOCK" ]; then
    echo -e "${RED}ERROR${NC}: update lock is missing ($UPDATE_LOCK); run systemd-tmpfiles --create"
    exit 1
fi
# Bind the lock to a live child PID instead of accepting the weaker statement
# "some process holds this inode". util-linux flock normally exits after
# locking an inherited FD, and the kernel may attribute that FLOCK to the
# process that originally opened the shared file description. Let flock open
# the path itself and use --no-fork so the exec'd guardian PID owns the exact
# kernel record. The guardian exits when this parent PID/start-time disappears.
update_proc_stat=$(<"/proc/$$/stat")
update_proc_tail=${update_proc_stat##*) }
[ "$update_proc_tail" != "$update_proc_stat" ] || {
    echo -e "${RED}ERROR${NC}: cannot parse updater process identity"
    exit 1
}
read -r -a update_proc_fields <<<"$update_proc_tail"
[ "${#update_proc_fields[@]}" -ge 20 ] || {
    echo -e "${RED}ERROR${NC}: updater process identity is incomplete"
    exit 1
}
UPDATE_MARKER_PID=$$
UPDATE_MARKER_START=${update_proc_fields[19]}
UPDATE_MARKER_UID=$(id -u)
UPDATE_LOCK_READY=$(mktemp "${XDG_RUNTIME_DIR:-/tmp}/.noid-update-lock-ready.XXXXXX")
chmod 0600 "$UPDATE_LOCK_READY"
/usr/bin/flock --nonblock --conflict-exit-code 75 --no-fork "$UPDATE_LOCK" \
    /usr/libexec/noid-update-lock-guardian \
    "$UPDATE_MARKER_PID" "$UPDATE_MARKER_START" "$UPDATE_LOCK_READY" &
UPDATE_LOCK_GUARD_PID=$!
trap _release_update_lock_guard EXIT
lock_ready=0
for _ in {1..100}; do
    if [ "$(cat "$UPDATE_LOCK_READY" 2>/dev/null || true)" = ready ]; then
        lock_ready=1
        break
    fi
    if ! kill -0 "$UPDATE_LOCK_GUARD_PID" 2>/dev/null; then
        break
    fi
    sleep 0.02
done
if [ "$lock_ready" -ne 1 ]; then
    if kill -0 "$UPDATE_LOCK_GUARD_PID" 2>/dev/null; then
        # A live guardian that did not acknowledge readiness must be stopped
        # before wait: it watches this parent and would otherwise deadlock with
        # the parent waiting for it to exit.
        kill "$UPDATE_LOCK_GUARD_PID" 2>/dev/null || true
        wait "$UPDATE_LOCK_GUARD_PID" 2>/dev/null || true
        UPDATE_LOCK_GUARD_PID=
        echo -e "${RED}ERROR${NC}: update lock guardian readiness timed out"
        exit 1
    fi
    wait "$UPDATE_LOCK_GUARD_PID" 2>/dev/null
    lock_rc=$?
    UPDATE_LOCK_GUARD_PID=
    [ "$lock_rc" -eq 75 ] \
        && echo -e "${YELLOW}INFO${NC}: another NoID Privacy update workflow is already running" \
        || echo -e "${RED}ERROR${NC}: update lock guardian failed (exit $lock_rc)"
    exit "$lock_rc"
fi
rm -f -- "$UPDATE_LOCK_READY"
UPDATE_LOCK_READY=
STEPS=9
ERRORS=0
WARNINGS=0
RPM_SIBLING_LIST=
CODIUM_INVENTORY_ERR=
# Per-step error attribution for the GUI marker channel (see _flush_step_errors)
_LAST_STEP=""
_LAST_STEP_ERRORS=0
DNF_SUCCEEDED=0
BOOT_IMAGE_GLOBAL_REBUILD=0
BOOT_IMAGE_REBUILD_REASON=
# SKIPPED_LIST tracks whole-step skips (tool not installed / Live-Boot /
# masked) so the Summary can say WHICH steps did not run next to the step
# counter. DEFERRED_LIST tracks incomplete sub-steps caused by normal,
# user-resolvable runtime state. WARNINGS is incremented at every step-level
# WARN echo, including every deferral.
SKIPPED_LIST=()
DEFERRED_LIST=()
FWUPD_REBOOT=0
REBOOT_BLOCKERS=()
REBOOT_STATE_WRITE_FAILED=0
PRIOR_REBOOT_BLOCKERS=
PRIOR_NVIDIA_BLOCK=0
prior_reboot_state=/run/noid-privacy/reboot-blocked
if [ -f "$prior_reboot_state" ] && [ ! -L "$prior_reboot_state" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' "$prior_reboot_state" 2>/dev/null)" = 0:0:644:1 ]; then
    mapfile -t prior_reboot_rows < "$prior_reboot_state" || prior_reboot_rows=()
    if [ "${#prior_reboot_rows[@]}" -eq 2 ] \
            && [ "${prior_reboot_rows[0]}" = schema=1 ] \
            && [[ "${prior_reboot_rows[1]}" =~ ^blockers=[a-z-]+(,[a-z-]+)*$ ]]; then
        PRIOR_REBOOT_BLOCKERS=${prior_reboot_rows[1]#blockers=}
    fi
fi
case ",$PRIOR_REBOOT_BLOCKERS," in
    *,initramfs,*)
        BOOT_IMAGE_GLOBAL_REBUILD=1
        BOOT_IMAGE_REBUILD_REASON=retained-initramfs-blocker
        ;;
esac
case ",$PRIOR_REBOOT_BLOCKERS," in
    *,nvidia,*) PRIOR_NVIDIA_BLOCK=1 ;;
esac
snap_num=""
START_TS=$(date +%s)

# visual helpers — single-line dividers, banner, summary box.
# Width fixed to 78 chars (fits 80-col terminal, leaves room for prompt char +
# avoids wrap on tight gnome-terminal). Uses Unicode box-drawing chars (U+2500
# range — universally supported in GNOME default fonts).
_W=78
_hr='══════════════════════════════════════════════════════════════════════════════'

# Step header: ── [N/STEPS] description ─────────────...
# Steps never abort — failures raise the ERRORS accumulator and the run
# continues. _flush_step_errors compares the accumulator against its value at
# the previous step's start and emits a per-step STEPFAIL marker, so the GUI
# checklist can attribute an error to the step that actually raised it
# instead of blaming whichever step ran last.
_flush_step_errors() {
    if [ -n "${_LAST_STEP:-}" ] && [ "${ERRORS:-0}" -gt "${_LAST_STEP_ERRORS:-0}" ]; then
        _emit_marker "STEPFAIL $_LAST_STEP"
    fi
}

step() {
    local n="$1" desc="$2"
    local prefix="── [$n/$STEPS] $desc "
    local fill=$(( _W - ${#prefix} ))
    [ "$fill" -lt 1 ] && fill=1
    echo ""
    printf '%b%s' "$BOLD" "$prefix"
    printf '─%.0s' $(seq 1 "$fill")
    printf '%b\n' "$NC"
    _flush_step_errors
    _LAST_STEP="$n"
    _LAST_STEP_ERRORS=${ERRORS:-0}
    _emit_marker "STEP $n $STEPS $desc"
}

# Optional machine-readable progress for a GUI frontend (env-guarded; the CLI is
# a no-op when NOID_UPDATE_MARKER_FILE is unset). Consumed by the noid-update GUI.
_emit_marker() {
    [ -n "${NOID_UPDATE_MARKER_FILE:-}" ] && printf '%s\n' "$*" >> "${NOID_UPDATE_MARKER_FILE}" 2>/dev/null || true
}

publish_reboot_blockers() {
    [ "${#REBOOT_BLOCKERS[@]}" -gt 0 ] || return 0
    sudo /usr/libexec/noid-reboot-block-state --publish \
        "${REBOOT_BLOCKERS[@]}"
}

register_reboot_blocker() {
    local reason=${1:-} existing
    case "$reason" in
        kernel-cmdline|initramfs|bls-identity|nvidia|boot-inventory) ;;
        *) return 2 ;;
    esac
    for existing in "${REBOOT_BLOCKERS[@]}"; do
        [ "$existing" = "$reason" ] && return 0
    done
    REBOOT_BLOCKERS+=("$reason")
    if ! publish_reboot_blockers; then
        REBOOT_STATE_WRITE_FAILED=1
        return 1
    fi
}

load_reboot_readiness() {
    local -a args=() record=()
    [ "${FWUPD_REBOOT:-0}" -eq 0 ] || args+=(--firmware-required)
    [ "${reboot_hint:-no}" != yes ] || args+=(--recommended)
    mapfile -t record < <(/usr/libexec/noid-reboot-readiness "${args[@]}") \
        || return 1
    [ "${#record[@]}" -eq 8 ] && [ "${record[0]}" = schema=1 ] \
        || return 1
    case "${record[1]}" in
        activation=required|activation=recommended|activation=none) ;;
        *) return 1 ;;
    esac
    case "${record[2]}" in safety=safe|safety=blocked) ;; *) return 1 ;; esac
    [[ "${record[3]}" =~ ^blockers=[a-z-]+(,[a-z-]+)*$ ]] || return 1
    [[ "${record[4]}" =~ ^running_kernel=[A-Za-z0-9._+-]+$ ]] || return 1
    [[ "${record[5]}" =~ ^latest_kernel=[A-Za-z0-9._+-]+$ ]] || return 1
    [[ "${record[6]}" =~ ^nvidia_running=[A-Za-z0-9._+-]+$ ]] || return 1
    [[ "${record[7]}" =~ ^nvidia_installed=[A-Za-z0-9._+-]+$ ]] || return 1
    REBOOT_ACTIVATION=${record[1]#activation=}
    REBOOT_SAFETY=${record[2]#safety=}
    REBOOT_BLOCKER_SUMMARY=${record[3]#blockers=}
    case "$REBOOT_SAFETY:$REBOOT_BLOCKER_SUMMARY" in
        safe:none) ;;
        blocked:none|safe:*) return 1 ;;
        blocked:*)
            local reason
            while IFS= read -r reason; do
                case "$reason" in
                    kernel-cmdline|initramfs|bls-identity|nvidia|boot-inventory|state-unsafe|nvidia-state) ;;
                    *) return 1 ;;
                esac
            done < <(tr ',' '\n' <<< "$REBOOT_BLOCKER_SUMMARY")
            ;;
        *) return 1 ;;
    esac
}

# Format duration in human readable: 423s -> 7m 03s, 12s -> 12s
human_duration() {
    local s=$1
    if [ "$s" -ge 60 ]; then
        printf "%dm %02ds" $((s / 60)) $((s % 60))
    else
        printf "%ds" "$s"
    fi
}

parse_dnf_reboot_hint() {
    python3 -c '
import json
import sys

try:
    result = json.load(sys.stdin)
except (OSError, UnicodeError, json.JSONDecodeError):
    raise SystemExit(1)
if not isinstance(result, list) or len(result) != 1:
    raise SystemExit(1)
record = result[0]
if not isinstance(record, dict) or record.get("type") != "reboot" \
        or type(record.get("reboot_required")) is not bool:
    raise SystemExit(1)
print("yes" if record["reboot_required"] else "no")
'
}

parse_dnf_service_units() {
    python3 -c '
import json
import re
import sys

try:
    result = json.load(sys.stdin)
except (OSError, UnicodeError, json.JSONDecodeError):
    raise SystemExit(1)
if not isinstance(result, list):
    raise SystemExit(1)
units = []
for record in result:
    if not isinstance(record, dict) or record.get("type") != "unit":
        raise SystemExit(1)
    unit = record.get("unit")
    if not isinstance(unit, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.@:\\-]{0,254}", unit):
        raise SystemExit(1)
    units.append(unit)
if len(units) != len(set(units)):
    raise SystemExit(1)
print("\n".join(sorted(units)))
'
}

read_aide_database_state() {
    local output
    local -a lines=()
    output=$(sudo -n /usr/libexec/noid-aide-status 2>/dev/null) || {
        printf '%s\n' unavailable
        return 0
    }
    mapfile -t lines <<< "$output"
    if [ "${#lines[@]}" -ne 2 ] \
       || [ "${lines[0]}" != NOID_AIDE_STATE_V1 ] \
       || [[ "${lines[1]}" != STATE=* ]]; then
        printf '%s\n' unavailable
        return 0
    fi
    case "${lines[1]#STATE=}" in
        active|absent|unsafe) printf '%s\n' "${lines[1]#STATE=}" ;;
        *) printf '%s\n' unavailable ;;
    esac
}

# Exact-file identity primitive used before and after every cached executable
# payload deployment. It rejects symlinks and malformed digests; callers add
# ownership/mode requirements appropriate to the source location.
payload_matches() {
    local path="${1:-}" expected="${2:-}" actual
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || return 2
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    actual=$(sha256sum -- "$path" 2>/dev/null | awk '{print $1}') || return 1
    [ "$actual" = "$expected" ]
}

WEBEXT_VALIDATOR=/usr/local/lib/noid-privacy/validate-webextension.py
FIREFOX_XPI_SIGNATURE_VERIFIER=/usr/local/lib/noid-privacy/verify-firefox-xpi-signature
UBO_POLICY_VALIDATOR=/usr/local/lib/noid-privacy/validate-ubo-policy.py
UBO_POLICY_SOURCE=/usr/share/noid-firefox/uBlock0@raymondhill.net.json
EXTENSION_UPDATE_LEDGER="${XDG_STATE_HOME:-$HOME/.local/state}/noid-privacy/extension-updates.log"
# Last-check state, deliberately NOT the append-only evidence ledger above.
# Firefox and Thunderbird background add-on updates are disabled by design
# (M16/M35), so the age of the newest authenticated marketplace check IS this
# machine's add-on patch latency — and nothing surfaced it. The ledger cannot:
# it only records actual version changes, so a component that has been current
# for a year is indistinguishable from one never checked at all.
# One overwritten line per component keeps this bounded, which is why M42 has
# nothing to age here and why noid-status can render it without any network
# request of its own.
EXTENSION_CHECK_STATE="${XDG_STATE_HOME:-$HOME/.local/state}/noid-privacy/extension-checks"

trusted_root_file() {
    local path="${1:-}" expected_mode="${2:-}"
    [[ "$expected_mode" =~ ^[0-7]{3,4}$ ]] || return 2
    [ -f "$path" ] && [ ! -L "$path" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' -- "$path" 2>/dev/null || true)" \
            = "0:0:${expected_mode}:1" ]
}

record_extension_update() {
    local component="$1" previous="$2" installed="$3" digest="$4" state_dir
    [[ "$component" =~ ^[A-Za-z0-9._+@{}-]+$ ]] || return 1
    [[ "$previous" =~ ^[0-9]+([.][0-9]+)*$ ]] || return 1
    [[ "$installed" =~ ^[0-9]+([.][0-9]+)*$ ]] || return 1
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
    state_dir=$(dirname "$EXTENSION_UPDATE_LEDGER") || return 1
    [ ! -L "$state_dir" ] || return 1
    mkdir -p "$state_dir" || return 1
    chmod 0700 "$state_dir" || return 1
    [ ! -L "$EXTENSION_UPDATE_LEDGER" ] || return 1
    if [ -e "$EXTENSION_UPDATE_LEDGER" ] && [ ! -f "$EXTENSION_UPDATE_LEDGER" ]; then
        return 1
    fi
    ( umask 077
      printf 'timestamp=%s component=%s previous=%s installed=%s sha256=%s\n' \
          "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$component" "$previous" \
          "$installed" "$digest" >>"$EXTENSION_UPDATE_LEDGER"
    ) || return 1
    chmod 0600 "$EXTENSION_UPDATE_LEDGER"
}

# Record that an authenticated marketplace check completed for one component,
# whatever its outcome. Exactly one line per component survives, so the file
# stays bounded no matter how often update-all runs. The rewrite is atomic:
# a torn write must never leave noid-status reading a half-line and reporting
# a patch age that was never measured.
record_extension_check() {
    local component="$1" result="$2" state_dir tmp timestamp
    [[ "$component" =~ ^[A-Za-z0-9._+@{}-]+$ ]] || return 1
    case "$result" in current|updated|failed) ;; *) return 1 ;; esac
    state_dir=$(dirname "$EXTENSION_CHECK_STATE") || return 1
    [ ! -L "$state_dir" ] || return 1
    mkdir -p "$state_dir" || return 1
    chmod 0700 "$state_dir" || return 1
    [ ! -L "$EXTENSION_CHECK_STATE" ] || return 1
    if [ -e "$EXTENSION_CHECK_STATE" ] && [ ! -f "$EXTENSION_CHECK_STATE" ]; then
        return 1
    fi
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ) || return 1
    tmp=$(mktemp "${EXTENSION_CHECK_STATE}.XXXXXX") || return 1
    if ! ( umask 077
           if [ -f "$EXTENSION_CHECK_STATE" ]; then
               grep -v "^component=${component} " -- "$EXTENSION_CHECK_STATE" || true
           fi
           printf 'component=%s checked=%s result=%s\n' \
               "$component" "$timestamp" "$result"
         ) > "$tmp"; then
        rm -f -- "$tmp"
        return 1
    fi
    if ! chmod 0600 "$tmp" || ! mv -fT -- "$tmp" "$EXTENSION_CHECK_STATE"; then
        rm -f -- "$tmp"
        return 1
    fi
}

numeric_version_is_newer() {
    python3 - "$1" "$2" <<'NUMERIC_VERSION_PY'
import re
import sys

def parse(value):
    if not re.fullmatch(r"[0-9]+(?:[.][0-9]+)*", value):
        raise SystemExit(2)
    return tuple(int(part) for part in value.split("."))

new, old = map(parse, sys.argv[1:])
width = max(len(new), len(old))
new += (0,) * (width - len(new))
old += (0,) * (width - len(old))
raise SystemExit(0 if new > old else 1)
NUMERIC_VERSION_PY
}

ubo_candidate_action() {
    local latest_version="$1" current_version="$2"
    local current_policy_valid="$3" current_digest_matches="$4"
    case "${current_policy_valid}:${current_digest_matches}" in
        0:0|0:1|1:0|1:1) ;;
        *) return 2 ;;
    esac
    if numeric_version_is_newer "$latest_version" "$current_version"; then
        printf '%s\n' advance
    elif numeric_version_is_newer "$current_version" "$latest_version"; then
        if [ "$current_policy_valid" -eq 1 ]; then
            printf '%s\n' keep
        else
            printf '%s\n' reject
        fi
    elif [ "$current_policy_valid" -eq 1 ] \
            && [ "$current_digest_matches" -eq 1 ]; then
        printf '%s\n' keep
    else
        # Numerically equal versions must converge to the authenticated release
        # bytes and its proven managed-policy compatibility.
        printf '%s\n' repair
    fi
}

# Resolve each fixed managed extension through its product's official
# marketplace. This deliberately shares the compatibility-filtered,
# origin-bounded metadata parser below instead of consuming GitHub's
# unauthenticated 60-request/hour REST quota. Preserve the existing private
# staging contract: the DKIM root publisher accepts only
# /var/tmp/noid-xpi-update.*/payload.xpi, so copy the already authenticated
# marketplace bytes into that slot and re-verify their exact SHA-256.
fetch_latest_xpi() {
    local component="$1" marketplace expected_id product_package marketplace_rc=0
    LATEST_XPI_WORK=
    LATEST_XPI_PATH=
    LATEST_XPI_VERSION=
    LATEST_XPI_SHA256=
    LATEST_XPI_SIZE=
    LATEST_XPI_PRODUCT_VERSION=
    LATEST_XPI_ERROR="managed marketplace request was not initialized"
    LATEST_XPI_ERROR_CLASS=validation
    case "$component" in
        ubo)
            marketplace=amo
            expected_id=uBlock0@raymondhill.net
            product_package=firefox
            LATEST_XPI_ERROR="root-managed uBO policy or validator is missing or unsafe"
            trusted_root_file "$UBO_POLICY_VALIDATOR" 755 || return 1
            trusted_root_file "$UBO_POLICY_SOURCE" 644 || return 1
            ;;
        dkim)
            marketplace=atn
            expected_id=dkim_verifier@pl
            product_package=thunderbird
            ;;
        *) return 2 ;;
    esac
    LATEST_XPI_PRODUCT_VERSION=$(sudo rpm -q --qf '%{VERSION}\n' \
        "$product_package" 2>/dev/null) || {
        LATEST_XPI_ERROR="installed ${product_package} version could not be queried"
        return 1
    }
    fetch_marketplace_xpi "$marketplace" "$expected_id" \
        "$LATEST_XPI_PRODUCT_VERSION" || marketplace_rc=$?
    if [ "$marketplace_rc" -ne 0 ]; then
        LATEST_XPI_ERROR=${MARKETPLACE_ERROR:-official marketplace validation failed}
        LATEST_XPI_ERROR_CLASS=${MARKETPLACE_ERROR_CLASS:-validation}
        cleanup_marketplace_xpi
        return "$marketplace_rc"
    fi

    LATEST_XPI_VERSION=$MARKETPLACE_VERSION
    LATEST_XPI_SHA256=$MARKETPLACE_SHA256
    LATEST_XPI_SIZE=$MARKETPLACE_SIZE
    LATEST_XPI_WORK=$(mktemp -d /var/tmp/noid-xpi-update.XXXXXX) || {
        LATEST_XPI_ERROR="private managed-XPI staging could not be created"
        cleanup_marketplace_xpi
        return 1
    }
    chmod 0700 "$LATEST_XPI_WORK" || {
        LATEST_XPI_ERROR="private managed-XPI staging permissions could not be set"
        cleanup_marketplace_xpi
        cleanup_latest_xpi
        return 1
    }
    LATEST_XPI_PATH="$LATEST_XPI_WORK/payload.xpi"
    if ! install -m 0600 -- "$MARKETPLACE_PATH" "$LATEST_XPI_PATH" \
            || [ "$(stat -c '%s' "$LATEST_XPI_PATH" 2>/dev/null || echo 0)" \
                != "$LATEST_XPI_SIZE" ] \
            || ! payload_matches "$LATEST_XPI_PATH" "$LATEST_XPI_SHA256"; then
        LATEST_XPI_ERROR="authenticated marketplace XPI could not enter private managed staging"
        cleanup_marketplace_xpi
        cleanup_latest_xpi
        return 1
    fi
    if [ "$component" = ubo ] \
       && ! "$UBO_POLICY_VALIDATOR" "$LATEST_XPI_PATH" \
            "$UBO_POLICY_SOURCE" >/dev/null; then
        LATEST_XPI_ERROR="marketplace uBO XPI is incompatible with the managed filter-list policy"
        cleanup_marketplace_xpi
        cleanup_latest_xpi
        return 1
    fi
    cleanup_marketplace_xpi
    LATEST_XPI_ERROR=
    LATEST_XPI_ERROR_CLASS=
    return 0
}

cleanup_latest_xpi() {
    if [ -n "${LATEST_XPI_WORK:-}" ] && [ -d "$LATEST_XPI_WORK" ] \
            && [ ! -L "$LATEST_XPI_WORK" ]; then
        rm -rf --one-file-system -- "$LATEST_XPI_WORK"
    fi
    LATEST_XPI_WORK=
    LATEST_XPI_PATH=
}

# Enumerate only profile-owned executable extensions. Built-in/system add-ons
# remain owned by the Firefox/Thunderbird RPM transaction; locale packs have a
# separate browser-major reconciliation path. Every emitted target is a
# canonical regular XPI below one registered profile inside the user home.
browser_extension_inventory() {
    local product="$1" output="$2"
    python3 - "$product" "$output" "${XDG_CONFIG_HOME:-$HOME/.config}" \
        "$HOME" <<'BROWSER_EXTENSION_INVENTORY_PY'
import configparser
import json
import os
from pathlib import Path
import re
import stat
import sys

product, output, xdg_config, home = sys.argv[1:]
home_root = Path(home).resolve()
if product == "firefox":
    root = Path(xdg_config) / "mozilla" / "firefox"
    excluded = {"uBlock0@raymondhill.net"}
elif product == "thunderbird":
    root = Path(home) / ".thunderbird"
    excluded = {"dkim_verifier@pl"}
else:
    raise SystemExit(2)

def regular(path):
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return False
    return stat.S_ISREG(mode) and not stat.S_ISLNK(mode)

if not root.exists():
    Path(output).write_text("", encoding="utf-8")
    raise SystemExit(0)
try:
    root = root.resolve(strict=True)
except OSError:
    raise SystemExit("profile root cannot be canonicalized")
if not root.is_dir() or os.path.commonpath((root, home_root)) != str(home_root) \
        or not regular(root / "profiles.ini"):
    raise SystemExit("profile root/profiles.ini is unsafe")
parser = configparser.ConfigParser(strict=True, interpolation=None)
parser.optionxform = str
parser.read(root / "profiles.ini", encoding="utf-8")
records = []
seen_targets = set()
for section in parser.sections():
    if not re.fullmatch(r"Profile[0-9]+", section):
        continue
    relative = parser.get(section, "Path", fallback="")
    is_relative = parser.get(section, "IsRelative", fallback="1")
    if is_relative == "1":
        parts = Path(relative).parts
        if not parts or any(part in {"", ".", ".."} for part in parts):
            raise SystemExit("unsafe registered relative profile path")
        profile_candidate = root.joinpath(*parts)
    elif is_relative == "0":
        profile_candidate = Path(relative)
        if not profile_candidate.is_absolute():
            raise SystemExit("registered absolute profile path is malformed")
    else:
        raise SystemExit("registered profile IsRelative value is invalid")
    try:
        profile = profile_candidate.resolve(strict=True)
        if not profile.is_dir() \
                or os.path.commonpath((profile, home_root)) != str(home_root):
            raise SystemExit("registered profile escapes the user home")
    except (OSError, ValueError):
        raise SystemExit("registered profile cannot be canonicalized")
    database_path = profile / "extensions.json"
    if not database_path.exists():
        continue
    if not regular(database_path):
        raise SystemExit("extensions.json is unsafe")
    with database_path.open(encoding="utf-8") as source:
        database = json.load(source)
    extensions_dir = profile / "extensions"
    profile_addons = [addon for addon in database.get("addons", [])
                      if addon.get("type") == "extension"
                      and addon.get("location") == "app-profile"
                      and addon.get("id") not in excluded]
    if profile_addons:
        try:
            extensions_dir = extensions_dir.resolve(strict=True)
            if not extensions_dir.is_dir() \
                    or os.path.commonpath((extensions_dir, profile)) != str(profile):
                raise SystemExit("profile extensions directory is unsafe")
        except (OSError, ValueError):
            raise SystemExit("profile extensions directory cannot be canonicalized")
    for addon in profile_addons:
        identity = addon.get("id")
        version = addon.get("version")
        if identity in excluded:
            continue
        if not isinstance(identity, str) or not re.fullmatch(
                r"(?:[A-Za-z0-9][A-Za-z0-9._+@-]{0,254}|[{][0-9A-Fa-f-]{1,64}[}])",
                identity):
            raise SystemExit("profile extension identity is unsafe")
        if not isinstance(version, str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", version):
            raise SystemExit("profile extension version is unsafe")
        target = extensions_dir / f"{identity}.xpi"
        if not regular(target):
            raise SystemExit(f"profile extension is not one regular XPI: {identity}")
        recorded = addon.get("path")
        if not isinstance(recorded, str) or os.path.realpath(recorded) != os.path.realpath(target):
            raise SystemExit(f"profile extension path identity mismatch: {identity}")
        target_text = str(target)
        if target_text in seen_targets:
            raise SystemExit("duplicate profile extension target")
        seen_targets.add(target_text)
        profile_name = parser.get(section, "Name", fallback=profile.name)
        if not re.fullmatch(r"[A-Za-z0-9._ -]{1,128}", profile_name):
            profile_name = profile.name
        records.append((identity, version, target_text, profile_name))

with open(output, "w", encoding="utf-8", newline="\n") as target:
    for record in sorted(records):
        if any("\t" in field or "\n" in field for field in record):
            raise SystemExit("inventory field framing violation")
        target.write("\t".join(record) + "\n")
BROWSER_EXTENSION_INVENTORY_PY
}

atomic_install_profile_xpi() {
    local source="$1" destination="$2" digest="$3" parent temporary
    payload_matches "$source" "$digest" || return 1
    parent=${destination%/*}
    [ -d "$parent" ] && [ ! -L "$parent" ] || return 1
    [ ! -L "$destination" ] || return 1
    if [ -e "$destination" ] && [ ! -f "$destination" ]; then return 1; fi
    temporary=$(mktemp "$parent/.noid-extension-update.XXXXXXXX") || return 1
    if ! install -m 0644 -- "$source" "$temporary" \
            || ! payload_matches "$temporary" "$digest" \
            || ! sync -- "$temporary" \
            || ! mv -fT -- "$temporary" "$destination" \
            || ! sync -- "$destination" "$parent" \
            || ! payload_matches "$destination" "$digest"; then
        rm -f -- "$temporary"
        return 1
    fi
}

# Resolve an arbitrary profile-owned extension through the product's official
# marketplace. The API response owns the latest stable compatible artifact;
# exact GUID, public state, file URL, byte count and SHA-256 are all bound
# before the shared archive validator sees the XPI.
fetch_marketplace_xpi() {
    local marketplace="$1" identity="$2" product_version="$3"
    local api_url metadata headers record parser_rc curl_rc http_status
    MARKETPLACE_WORK=
    MARKETPLACE_PATH=
    MARKETPLACE_VERSION=
    MARKETPLACE_SHA256=
    MARKETPLACE_SIZE=
    MARKETPLACE_ERROR="marketplace request was not initialized"
    MARKETPLACE_ERROR_CLASS=validation
    [[ "$identity" =~ ^[A-Za-z0-9{][A-Za-z0-9._+@{}-]{0,254}$ ]] || return 2
    case "$marketplace" in
        amo)
            api_url=$(python3 -c '
import sys, urllib.parse
print("https://addons.mozilla.org/api/v5/addons/search/?" +
      urllib.parse.urlencode({"guid": sys.argv[1], "app": "firefox",
                              "appversion": sys.argv[2], "type": "extension"}))
' "$identity" "$product_version") || return 1
            ;;
        atn)
            api_url=$(python3 -c '
import sys, urllib.parse
print("https://services.addons.thunderbird.net/api/v4/addons/search/?" +
      urllib.parse.urlencode({"guid": sys.argv[1], "app": "thunderbird",
                              "appversion": sys.argv[2], "type": "extension"}))
' "$identity" "$product_version") || return 1
            ;;
        *) return 2 ;;
    esac
    MARKETPLACE_WORK=$(mktemp -d /var/tmp/noid-marketplace-xpi.XXXXXX) || return 1
    chmod 0700 "$MARKETPLACE_WORK"
    metadata="$MARKETPLACE_WORK/metadata.json"
    headers="$MARKETPLACE_WORK/headers.txt"
    MARKETPLACE_ERROR="official ${marketplace^^} metadata network/TLS request failed (check VPN path and retry)"
    MARKETPLACE_ERROR_CLASS=availability
    curl_rc=0
    http_status=$(curl -sS --proto '=https' --tlsv1.2 --max-time 30 \
        --max-filesize 4194304 -D "$headers" -w '%{http_code}' \
        -H 'Accept: application/json' \
        -o "$metadata" "$api_url") || curl_rc=$?
    [ "$curl_rc" -eq 0 ] || return 1
    if [ "$http_status" = 403 ] || [ "$http_status" = 429 ]; then
        MARKETPLACE_ERROR="official ${marketplace^^} rate limit or shared VPN-exit throttling (HTTP ${http_status}; retry after changing endpoint/time)"
        return 1
    fi
    if [ "$http_status" != 200 ]; then
        MARKETPLACE_ERROR="official ${marketplace^^} metadata request returned HTTP ${http_status}"
        return 1
    fi
    MARKETPLACE_ERROR="official ${marketplace^^} metadata identity/digest is invalid"
    MARKETPLACE_ERROR_CLASS=validation
    parser_rc=0
    record=$(python3 - "$metadata" "$marketplace" "$identity" <<'MARKETPLACE_XPI_RELEASE_PY'
import json
import re
import sys
from urllib.parse import urlsplit

path, marketplace, expected_id = sys.argv[1:]
with open(path, encoding="utf-8") as source:
    response = json.load(source)
if response.get("count") != 1 or response.get("next") is not None \
        or response.get("previous") is not None \
        or not isinstance(response.get("results"), list) \
        or len(response["results"]) != 1:
    raise SystemExit("compatible marketplace search cardinality mismatch")
addon = response["results"][0]
if addon.get("guid") != expected_id or addon.get("type") != "extension" \
        or addon.get("is_disabled") is not False:
    raise SystemExit("marketplace add-on identity/state mismatch")
version_record = addon.get("current_version")
if not isinstance(version_record, dict):
    raise SystemExit("current stable version missing")
version = version_record.get("version")
if not isinstance(version, str) or not re.fullmatch(r"[0-9]+(?:[.][0-9]+)*", version):
    raise SystemExit(3)
if marketplace == "amo":
    compatibility = version_record.get("compatibility", {}).get("firefox")
    files = [version_record.get("file")]
    allowed_host = "addons.mozilla.org"
    url_pattern = r"/firefox/downloads/file/[1-9][0-9]*/[A-Za-z0-9._+-]+[.]xpi"
elif marketplace == "atn":
    compatibility = version_record.get("compatibility", {}).get("thunderbird")
    candidate_files = version_record.get("files", [])
    linux_files = [item for item in candidate_files if item.get("platform") == "linux"]
    all_files = [item for item in candidate_files if item.get("platform") == "all"]
    files = linux_files if linux_files else all_files
    allowed_host = "addons.thunderbird.net"
    url_pattern = r"/thunderbird/downloads/file/[1-9][0-9]*/[A-Za-z0-9._+-]+[.]xpi"
else:
    raise SystemExit(2)
if not isinstance(compatibility, dict) or len(files) != 1 or not isinstance(files[0], dict):
    raise SystemExit("compatible marketplace file cardinality mismatch")
artifact = files[0]
if artifact.get("status") != "public":
    raise SystemExit("marketplace file is not public")
digest = artifact.get("hash")
size = artifact.get("size")
url = artifact.get("url")
if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
    raise SystemExit("marketplace file lacks SHA-256")
if not isinstance(size, int) or not 0 < size <= 64 * 1024 * 1024:
    raise SystemExit("marketplace file size outside policy")
if not isinstance(url, str):
    raise SystemExit("marketplace file URL missing")
parsed = urlsplit(url)
if parsed.scheme != "https" or parsed.hostname != allowed_host \
        or not re.fullmatch(url_pattern, parsed.path):
    raise SystemExit("marketplace file URL outside fixed origin")
if marketplace == "amo" and (parsed.query or parsed.fragment):
    raise SystemExit("AMO file URL carries unexpected suffix")
if marketplace == "atn" and parsed.query not in {"", "src="}:
    raise SystemExit("ATN file URL carries unexpected query")
print(version, size, digest.removeprefix("sha256:"), url, sep="\t")
MARKETPLACE_XPI_RELEASE_PY
) || parser_rc=$?
    [ "$parser_rc" -ne 3 ] || { MARKETPLACE_ERROR="non-numeric marketplace version is not safely orderable"; return 3; }
    [ "$parser_rc" -eq 0 ] || return 1
    IFS=$'\t' read -r MARKETPLACE_VERSION MARKETPLACE_SIZE \
        MARKETPLACE_SHA256 MARKETPLACE_URL <<<"$record"
    [[ "$MARKETPLACE_VERSION" =~ ^[0-9]+([.][0-9]+)*$ ]] || return 1
    [[ "$MARKETPLACE_SIZE" =~ ^[1-9][0-9]*$ ]] || return 1
    [[ "$MARKETPLACE_SHA256" =~ ^[0-9a-f]{64}$ ]] || return 1
    MARKETPLACE_PATH="$MARKETPLACE_WORK/payload.xpi"
    MARKETPLACE_ERROR="marketplace XPI download failed"
    MARKETPLACE_ERROR_CLASS=availability
    curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --max-redirs 5 --max-time 90 --max-filesize 67108864 \
        -o "$MARKETPLACE_PATH" "$MARKETPLACE_URL" || return 1
    MARKETPLACE_ERROR="marketplace XPI private download staging failed"
    MARKETPLACE_ERROR_CLASS=validation
    chmod 0600 "$MARKETPLACE_PATH" || return 1
    MARKETPLACE_ERROR="marketplace XPI bytes differ from API size/SHA-256"
    MARKETPLACE_ERROR_CLASS=validation
    [ "$(stat -c '%s' "$MARKETPLACE_PATH" 2>/dev/null || echo 0)" = "$MARKETPLACE_SIZE" ] \
        && payload_matches "$MARKETPLACE_PATH" "$MARKETPLACE_SHA256" || return 1
    MARKETPLACE_ERROR="marketplace XPI structure, GUID or compatibility is invalid"
    if [ "$marketplace" = amo ]; then
        "$WEBEXT_VALIDATOR" "$MARKETPLACE_PATH" "$identity" \
            "$MARKETPLACE_VERSION" 1 "$product_version" 1 >/dev/null || return 1
        MARKETPLACE_ERROR="Firefox native signature verification rejected the AMO XPI"
        "$FIREFOX_XPI_SIGNATURE_VERIFIER" "$MARKETPLACE_PATH" \
            "$identity" "$MARKETPLACE_VERSION" || return 1
    else
        "$WEBEXT_VALIDATOR" "$MARKETPLACE_PATH" "$identity" \
            "$MARKETPLACE_VERSION" 0 "$product_version" 1 >/dev/null || return 1
    fi
    MARKETPLACE_ERROR=
    MARKETPLACE_ERROR_CLASS=
}

cleanup_marketplace_xpi() {
    if [ -n "${MARKETPLACE_WORK:-}" ] && [ -d "$MARKETPLACE_WORK" ] \
            && [ ! -L "$MARKETPLACE_WORK" ]; then
        rm -rf --one-file-system -- "$MARKETPLACE_WORK"
    fi
    MARKETPLACE_WORK=
    MARKETPLACE_PATH=
}

# Advance every profile-owned marketplace extension for one browser. Inventory
# is sorted by GUID, so one authenticated candidate is fetched once and reused
# byte-for-byte across every profile that carries that GUID. A marketplace or
# integrity failure is a run failure; channel availability and non-numeric
# ordering are visible retryable warnings that leave validated local bytes
# untouched.
update_marketplace_extensions() {
    local product="$1" marketplace="$2" product_package product_label
    local inventory product_version identity installed_version actual_version target profile_name
    local active_identity='' fetch_rc=0 updated=0 validator_signature component
    # Check accounting for the add-on patch-age surface. `checked` counts
    # identities whose marketplace answer authenticated, `failed` those whose
    # did not; a run that authenticated nothing must never look "current".
    local checked=0 failed=0 check_result
    case "$product:$marketplace" in
        firefox:amo)
            product_package=firefox
            product_label=Firefox
            validator_signature=1
            ;;
        thunderbird:atn)
            product_package=thunderbird
            product_label=Thunderbird
            validator_signature=0
            ;;
        *)
            echo -e "${RED}ERROR${NC}: internal marketplace ownership mapping is invalid"
            ERRORS=$((ERRORS + 1))
            return 0
            ;;
    esac
    inventory=$(mktemp "/var/tmp/noid-${product}-extension-inventory.XXXXXX") || {
        echo -e "${RED}ERROR${NC}: ${product_label} extension inventory could not be created"
        ERRORS=$((ERRORS + 1))
        return 0
    }
    chmod 0600 "$inventory"
    if ! browser_extension_inventory "$product" "$inventory"; then
        echo -e "${RED}ERROR${NC}: ${product_label} profile-owned extension inventory is unsafe or unreadable"
        ERRORS=$((ERRORS + 1))
        rm -f -- "$inventory"
        return 0
    fi
    if [ ! -s "$inventory" ]; then
        echo -e "${GREEN}OK${NC}: no additional profile-owned ${product_label} extensions require marketplace reconciliation"
        rm -f -- "$inventory"
        return 0
    fi
    product_version=$(sudo rpm -q --qf '%{VERSION}\n' "$product_package" 2>/dev/null) || {
        echo -e "${RED}ERROR${NC}: installed ${product_label} version is unavailable for extension compatibility selection"
        ERRORS=$((ERRORS + 1))
        record_extension_check "${product}-marketplace" failed || true
        rm -f -- "$inventory"
        return 0
    }
    [[ "$product_version" =~ ^[0-9]+([.][0-9A-Za-z+-]+)*$ ]] || {
        echo -e "${RED}ERROR${NC}: installed ${product_label} version cannot be safely sent to its fixed marketplace query"
        ERRORS=$((ERRORS + 1))
        record_extension_check "${product}-marketplace" failed || true
        rm -f -- "$inventory"
        return 0
    }

    while IFS=$'\t' read -r identity installed_version target profile_name; do
        [ -n "$identity" ] || continue
        if [ "$identity" != "$active_identity" ]; then
            cleanup_marketplace_xpi
            active_identity=$identity
            fetch_rc=0
            fetch_marketplace_xpi "$marketplace" "$identity" "$product_version" \
                || fetch_rc=$?
            if [ "$fetch_rc" -eq 3 ]; then
                echo -e "${YELLOW}WARN${NC}: ${product_label} extension ${identity} has a non-numeric marketplace version; left untouched because ordering is unprovable"
                WARNINGS=$((WARNINGS + 1))
                failed=$((failed + 1))
            elif [ "$fetch_rc" -ne 0 ] \
                    && [ "${MARKETPLACE_ERROR_CLASS:-validation}" = availability ]; then
                echo -e "${YELLOW}WARN${NC}: ${product_label} extension ${identity} marketplace check unavailable (${MARKETPLACE_ERROR:-retry later}); all profile copies left unchanged"
                WARNINGS=$((WARNINGS + 1))
                DEFERRED_LIST+=("${product_label}-extension-check")
                failed=$((failed + 1))
            elif [ "$fetch_rc" -ne 0 ]; then
                echo -e "${RED}ERROR${NC}: ${product_label} extension ${identity} could not be authenticated through the fixed ${marketplace^^} channel (${MARKETPLACE_ERROR:-unknown validation failure}); all profile copies left untouched"
                ERRORS=$((ERRORS + 1))
                failed=$((failed + 1))
            else
                checked=$((checked + 1))
            fi
        fi
        [ "$fetch_rc" -eq 0 ] || continue
        if ! [[ "$installed_version" =~ ^[0-9]+([.][0-9]+)*$ ]]; then
            echo -e "${YELLOW}WARN${NC}: ${product_label} extension ${identity} has non-numeric installed version ${installed_version} (${profile_name}); left untouched because ordering is unprovable"
            WARNINGS=$((WARNINGS + 1))
            continue
        fi
        actual_version=$("$WEBEXT_VALIDATOR" "$target" "$identity" - \
            "$validator_signature" "$product_version" 1 2>/dev/null) || {
            echo -e "${RED}ERROR${NC}: installed ${product_label} extension ${identity} fails structure/identity/compatibility validation (${profile_name}); left untouched for review"
            ERRORS=$((ERRORS + 1))
            continue
        }
        if [ "$product" = firefox ] \
                && ! "$FIREFOX_XPI_SIGNATURE_VERIFIER" "$target" \
                    "$identity" "$actual_version"; then
            echo -e "${RED}ERROR${NC}: installed Firefox extension ${identity} fails Firefox native signature verification (${profile_name}); left untouched for review"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        if [ "$installed_version" != "$actual_version" ]; then
            echo -e "${YELLOW}NOTE${NC}: ${product_label} extension state database reports ${installed_version}, exact XPI reports ${actual_version} (${profile_name}); using authenticated XPI bytes"
        fi
        installed_version=$actual_version
        if numeric_version_is_newer "$MARKETPLACE_VERSION" "$installed_version"; then
            if atomic_install_profile_xpi "$MARKETPLACE_PATH" "$target" \
                    "$MARKETPLACE_SHA256" \
                    && [ "$("$WEBEXT_VALIDATOR" "$target" "$identity" \
                        "$MARKETPLACE_VERSION" "$validator_signature" \
                        "$product_version" 1 2>/dev/null || true)" = "$MARKETPLACE_VERSION" ]; then
                echo -e "${GREEN}UPDATED${NC}: ${product_label} extension ${identity} ${installed_version} → ${MARKETPLACE_VERSION} (${profile_name}; restart ${product_label} to apply)"
                component="${product}-${identity}"
                if record_extension_update "$component" "$installed_version" \
                        "$MARKETPLACE_VERSION" "$MARKETPLACE_SHA256"; then
                    updated=$((updated + 1))
                else
                    echo -e "${RED}ERROR${NC}: ${product_label} extension ${identity} updated but SHA-256 evidence could not be recorded"
                    ERRORS=$((ERRORS + 1))
                fi
            else
                echo -e "${RED}ERROR${NC}: ${product_label} extension ${identity} ${installed_version} → ${MARKETPLACE_VERSION} atomic publication/postcondition failed (${profile_name})"
                ERRORS=$((ERRORS + 1))
            fi
        else
            echo -e "${GREEN}OK${NC}: ${product_label} extension ${identity} ${installed_version} is current or newer (${profile_name}; no downgrade)"
        fi
    done < "$inventory"
    cleanup_marketplace_xpi
    rm -f -- "$inventory"
    [ "$updated" -eq 0 ] || echo -e "${GREEN}OK${NC}: ${updated} profile-owned ${product_label} extension copy/copies advanced; SHA-256 evidence recorded"
    # A partially failed run reports `failed`: the patch-age surface must not
    # claim a completed check while one identity stayed unauthenticated.
    if [ "$failed" -gt 0 ]; then
        check_result=failed
    elif [ "$updated" -gt 0 ]; then
        check_result=updated
    elif [ "$checked" -gt 0 ]; then
        check_result=current
    else
        return 0
    fi
    record_extension_check "${product}-marketplace" "$check_result" || true
}

publish_managed_dkim_xpi() {
    local source="$1" destination="$2" digest="$3" version="$4"
    sudo /usr/bin/bash -s -- "$source" "$destination" "$digest" "$version" <<'DKIM_PUBLISH_EOF'
set -euo pipefail
PATH=/usr/sbin:/usr/bin
source_file=$1
destination=$2
expected_sha=$3
expected_version=$4
temporary=
cleanup() { [ -z "${temporary:-}" ] || rm -f -- "$temporary"; }
trap cleanup EXIT
# Each allow-listed destination carries the one grandparent it may sit under.
# Deriving it here keeps the pin bound to the destination it was written for; a
# single literal equality silently made the second destination unreachable.
case "$destination" in
    /var/lib/noid-privacy/managed-extensions/dkim_verifier@pl.xpi)
        allowed_grandparent=/var/lib/noid-privacy ;;
    /usr/lib64/thunderbird/distribution/extensions/dkim_verifier@pl.xpi)
        allowed_grandparent=/usr/lib64/thunderbird/distribution ;;
    *) exit 2 ;;
esac
[ "${SUDO_UID:-0}" -gt 0 ] 2>/dev/null \
    && case "$source_file" in /var/tmp/noid-xpi-update.*/payload.xpi) true ;; *) false ;; esac \
    && [ -f "$source_file" ] && [ ! -L "$source_file" ] \
    && [ "$(stat -c '%u:%a' "$source_file" 2>/dev/null || true)" = "${SUDO_UID}:600" ] \
    && [[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]] \
    && [[ "$expected_version" =~ ^[0-9]+([.][0-9]+)*$ ]] \
    || exit 2
[ "$(sha256sum "$source_file" | awk '{print $1}')" = "$expected_sha" ] || exit 2
parent=${destination%/*}
# No module provisions /var/lib/noid-privacy/managed-extensions at build time,
# so on a fresh installation this parent was simply absent and the publisher
# exited 2 on its very first call. That short-circuited the whole && chain in
# Step 5b, the run printed "atomic publication/postcondition failed", the
# orchestrator exited 1, and the DKIM Verifier update channel stayed dead on
# every subsequent run because nothing ever created the directory either.
# Create it here under the same shape publish_managed_thunderbird_config
# already uses: require the grandparent this destination is allowed to sit
# under, so a parent is still never created below an unchecked location, then
# re-assert the exact metadata afterwards. Both allow-listed trees are
# provisioned the same way, so a missing parent self-heals in either instead of
# failing closed forever -- which is the failure this whole block exists to end.
grandparent=${parent%/*}
[ "$grandparent" = "$allowed_grandparent" ] \
    && [ -d "$grandparent" ] && [ ! -L "$grandparent" ] \
    && [ "$(stat -c '%u:%g:%a' "$grandparent" 2>/dev/null || true)" = 0:0:755 ] \
    || exit 2
if [ ! -e "$parent" ] && [ ! -L "$parent" ]; then
    install -d -m 0755 -o root -g root "$parent"
fi
[ -d "$parent" ] && [ ! -L "$parent" ] \
    && [ "$(stat -c '%u:%g:%a' "$parent" 2>/dev/null || true)" = 0:0:755 ] \
    || exit 2
[ ! -L "$destination" ] || exit 2
if [ -e "$destination" ] && [ ! -f "$destination" ]; then exit 2; fi
temporary=$(mktemp "$parent/.dkim_verifier@pl.xpi.noid-new.XXXXXXXX")
install -m 0644 -- "$source_file" "$temporary"
[ "$(sha256sum "$temporary" | awk '{print $1}')" = "$expected_sha" ] || exit 2
chown root:root "$temporary"
command -v restorecon >/dev/null 2>&1 && restorecon -F "$temporary"
sync -- "$temporary"
mv -fT -- "$temporary" "$destination"
temporary=
sync -- "$destination" "$parent"
[ "$(stat -c '%U:%G:%a' "$destination")" = root:root:644 ]
[ "$(sha256sum "$destination" | awk '{print $1}')" = "$expected_sha" ]
DKIM_PUBLISH_EOF
}

publish_managed_thunderbird_config() {
    local source="$1" destination="$2"
    sudo /usr/bin/bash -s -- "$source" "$destination" <<'TB_CONFIG_PUBLISH_EOF'
set -euo pipefail
PATH=/usr/sbin:/usr/bin
source_file=$1
destination=$2
temporary=
cleanup() { [ -z "${temporary:-}" ] || rm -f -- "$temporary"; }
trap cleanup EXIT
case "${source_file}::${destination}" in
    /usr/share/noid-thunderbird/noid-locale.js::/etc/thunderbird/pref/noid-locale.js|\
    /usr/share/noid-thunderbird/policies.json::/etc/thunderbird/policies/policies.json) ;;
    *) exit 2 ;;
esac
[ -f "$source_file" ] && [ ! -L "$source_file" ] \
    && [ "$(stat -Lc '%u:%g:%a:%h' "$source_file" 2>/dev/null || true)" = 0:0:644:1 ] \
    || exit 2
parent=${destination%/*}
grandparent=${parent%/*}
[ "$grandparent" = /etc/thunderbird ] \
    && [ -d "$grandparent" ] && [ ! -L "$grandparent" ] \
    && [ "$(stat -c '%u:%g:%a' "$grandparent" 2>/dev/null || true)" = 0:0:755 ] \
    || exit 2
if [ ! -e "$parent" ] && [ ! -L "$parent" ]; then
    install -d -m 0755 -o root -g root "$parent"
fi
[ -d "$parent" ] && [ ! -L "$parent" ] \
    && [ "$(stat -c '%u:%g:%a' "$parent" 2>/dev/null || true)" = 0:0:755 ] \
    || exit 2
[ ! -L "$destination" ] || exit 2
if [ -e "$destination" ] && [ ! -f "$destination" ]; then exit 2; fi
temporary=$(mktemp "$parent/.noid-thunderbird-config.XXXXXXXX")
install -m 0644 -o root -g root -- "$source_file" "$temporary"
cmp -s -- "$source_file" "$temporary"
command -v restorecon >/dev/null 2>&1 && restorecon -F "$temporary"
sync -- "$temporary"
mv -fT -- "$temporary" "$destination"
temporary=
sync -- "$destination" "$parent"
[ "$(stat -Lc '%u:%g:%a:%h' "$destination")" = 0:0:644:1 ]
cmp -s -- "$source_file" "$destination"
TB_CONFIG_PUBLISH_EOF
}

finalize_post_snapshot() {
    [ -n "${snap_num:-}" ] || return 0
    if ! command -v snapper >/dev/null 2>&1 \
            || [ ! -x /usr/libexec/noid-snapper-create ]; then
        logger -t noid-update-all \
            "ERROR: post-snapshot helper unavailable for pre #${snap_num}"
        echo -e "${RED}ERROR${NC}: post-snapshot helper unavailable for pre #${snap_num}" >&2
        return 1
    fi
    if sudo /usr/libexec/noid-snapper-create post "${snap_num}" \
            "noid-update-all post" >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}: Post-snapshot for pre #${snap_num} created"
        snap_num=
        return 0
    fi
    logger -t noid-update-all \
        "ERROR: post-snapshot for pre #${snap_num} not created (pre left unpaired)"
    echo -e "${RED}ERROR${NC}: post-snapshot for pre #${snap_num} could not be created — run 'sudo snapper -c root list' to verify." >&2
    return 1
}

# Survive a terminal close (SIGHUP) mid-run. The normal path creates and
# verifies the post-snapshot before printing the Summary. The EXIT trap is the
# fallback for an earlier error or signal; a failed fallback changes the final
# process status so the GUI can never report an unpaired pre-snapshot as green.
trap '' HUP

cleanup() {
    local rc=$?
    trap - EXIT
    trap '' HUP INT TERM
    if [ -n "${CODIUM_INVENTORY_ERR:-}" ]; then
        rm -f -- "$CODIUM_INVENTORY_ERR"
        CODIUM_INVENTORY_ERR=
    fi
    if [ -n "${RPM_SIBLING_LIST:-}" ]; then
        rm -f -- "$RPM_SIBLING_LIST"
        RPM_SIBLING_LIST=
    fi
    # Remove only the process-bound update window published by this exclusive
    # workflow. A SIGKILL cannot run this trap, but the read-only validator then
    # rejects the stale PID/start-time/lock tuple instead of suppressing events.
    if [ "${UPDATE_MARKER_OWNED:-0}" -eq 1 ]; then
        sudo rm -f /run/noid-update-running 2>/dev/null || true
        sudo sync -- /run 2>/dev/null || true
    fi
    # A premature exit still receives one verified post attempt. Failure is a
    # real workflow error because it breaks Snapper pre/post pairing.
    if ! finalize_post_snapshot; then
        rc=1
    fi
    # Hold the cross-session lock through post-snapshot completion, then stop
    # the exact guardian. On SIGKILL the guardian notices the vanished parent
    # identity and releases the lock without relying on this trap.
    _release_update_lock_guard
    # Stop the sudo keep-alive refresher + drop the cached credential. The
    # extended cache must NOT outlive this deliberately-started run; the global
    # timestamp_timeout=3 hardening (M10) stays intact for everything else.
    [ -n "${SUDO_KEEPALIVE_PID:-}" ] && kill "${SUDO_KEEPALIVE_PID}" 2>/dev/null
    sudo -k 2>/dev/null || true
    exit "$rc"
}
trap cleanup EXIT

# sudo keep-alive — single auth-prompt for the whole run.
# This script runs as the normal user and calls sudo across all 9 steps, with
# long NON-sudo phases in between (flatpak --user, VSCodium-ext REST downloads,
# Firefox re-apply, Claude). NoID Privacy hardens timestamp_timeout=3 (M10 Step 7, CIS
# 4.3.6), so the sudo cache expires during those phases and the user gets
# re-prompted up to 3x per run. Prime the credential once here, then refresh it
# in the background (50s < 180s timeout) for the script's lifetime. cleanup()
# runs `sudo -k` on EXIT so the warm cache never outlives this run — the global
# timestamp_timeout=3 hardening is untouched. The refresher self-terminates via
# `kill -0 "$$"` when this script dies. With SUDO_ASKPASS set (the GUI launches
# with it) the prime uses a GRAPHICAL password dialog (sudo -A); otherwise a
# terminal prompt. A declined/failed prime exits before the update marker,
# snapshot or first step: silently falling through from a cancelled graphical
# prompt to a terminal sudo prompt strands the GUI in a false "running" state.
# NOID_UPDATE_NO_KEEPALIVE=1 remains the explicit per-step-prompt opt-out.
prime_sudo_credential() {
    if [ -n "${SUDO_ASKPASS:-}" ]; then
        sudo -A -v 2>/dev/null
    else
        sudo -v
    fi
}
if [ "${NOID_UPDATE_NO_KEEPALIVE:-0}" != "1" ]; then
    if ! prime_sudo_credential; then
        _emit_marker "CANCELLED authentication"
        echo -e "${YELLOW}CANCELLED${NC}: administrator authentication was declined; no update step or snapshot was started"
        exit 125
    fi
    ( while true; do sudo -n true 2>/dev/null; sleep 50; kill -0 "$$" 2>/dev/null || exit; done ) &
    SUDO_KEEPALIVE_PID=$!
fi

# Publish a durable, process-bound update window. Mere path existence is never
# authority: /usr/libexec/noid-update-window-active independently requires this
# exact process identity, argv, live guardian and its kernel FLOCK. Publication
# is same-filesystem atomic so readers see either the old complete record or the
# new complete record, never a partially written schema.
if ! sudo /usr/bin/bash -c '
    set -euo pipefail
    marker=/run/noid-update-running
    temporary=$(mktemp /run/.noid-update-running.XXXXXX)
    cleanup_marker() { rm -f -- "$temporary"; }
    trap cleanup_marker EXIT
    printf "pid=%s\nstart_time=%s\nuid=%s\nlock_pid=%s\n" \
        "$1" "$2" "$3" "$4" >"$temporary"
    chown root:root "$temporary"
    chmod 0600 "$temporary"
    if command -v restorecon >/dev/null 2>&1; then
        restorecon -F "$temporary"
    fi
    sync -- "$temporary"
    mv -fT -- "$temporary" "$marker"
    temporary=
    sync -- "$marker"
    sync -- /run
' _ "$UPDATE_MARKER_PID" "$UPDATE_MARKER_START" "$UPDATE_MARKER_UID" \
    "$UPDATE_LOCK_GUARD_PID"; then
    echo -e "${RED}ERROR${NC}: cannot publish the verified update window"
    exit 1
fi
UPDATE_MARKER_OWNED=1
if ! sudo /usr/libexec/noid-update-window-active; then
    echo -e "${RED}ERROR${NC}: published update window failed process/lock validation"
    exit 1
fi

echo ""
echo -e "${BOLD}${_hr}${NC}"
echo -e "${BOLD}  NoID Privacy — System Update Orchestrator${NC}"
echo -e "  $(date '+%Y-%m-%d %H:%M %Z')"
echo -e "${BOLD}${_hr}${NC}"
echo ""

# Dependency check
MISSING=()
for tool in snapper flatpak fwupdmgr aide; do
    command -v "${tool}" >/dev/null 2>&1 || MISSING+=("${tool}")
done

# Auto-detect hardened profiles, profiles owned by the orchestrator, and
# unhardened user-created profiles.
# Switched from `find -type d` to shared helper
# /usr/local/lib/noid-privacy/firefox-profiles.sh which parses profiles.ini.
# Old find-based discovery matched non-profile dirs (Crash Reports, Pending
# Pings, Profile Groups, firefox-mpris) and would silently install user.js
# into them.
#
# Tracks BOTH the registered profile name (for special-case dispatch in Step 5
# below — playground needs base+overrides) AND the on-disk path.  The M34
# playground ready marker is user-owned workflow evidence, not a security
# authority: it only opts that exact reserved profile into repair. Safely
# registered profiles with no user.js enter automatic first application;
# foreign user.js files and exact explicit exclusions remain untouched.
managed_firefox_playground_profile() {
    local name=$1 marker marker_state marker_content
    [ "$name" = playground ] || return 1
    marker="${XDG_CONFIG_HOME:-${HOME:?}/.config}/noid-privacy/firefox-playground-init.done"
    marker_content=NOID_FIREFOX_PLAYGROUND_READY_V1
    [ -f "$marker" ] && [ ! -L "$marker" ] || return 1
    marker_state=$(stat -c '%u:%a:%h' -- "$marker") || return 1
    [ "$marker_state" = "$(id -u):600:1" ] || return 1
    cmp -s -- "$marker" <(printf '%s\n' "$marker_content")
}

classify_firefox_profiles() {
    local profile_name profile_path pdir exclusion_rc
    HARDENED_PROFILES=()
    HARDENED_NAMES=()
    FIREFOX_RECONCILE_PROFILES=()
    FIREFOX_RECONCILE_NAMES=()
    UNHARDENED_PROFILES=()
    UNHARDENED_NAMES=()

    while IFS=$'\t' read -r profile_name profile_path _ _; do
        [[ -n "$profile_name" ]] || continue
        pdir=$(profile_dir_for "$profile_name") || continue
        [[ -d "$pdir" ]] || continue
        if profile_hardening_complete "$profile_name"; then
            HARDENED_PROFILES+=("${pdir}")
            HARDENED_NAMES+=("${profile_name}")
            FIREFOX_RECONCILE_PROFILES+=("${pdir}")
            FIREFOX_RECONCILE_NAMES+=("${profile_name}")
        else
            UNHARDENED_PROFILES+=("${pdir}")
            UNHARDENED_NAMES+=("${profile_name}")
            if profile_auto_hardening_excluded "${pdir}"; then
                continue
            else
                exclusion_rc=$?
            fi
            [ "$exclusion_rc" -eq 1 ] || continue
            if { [ ! -e "$pdir/user.js" ] && [ ! -L "$pdir/user.js" ]; } || \
               profile_userjs_noid_managed "${pdir}" || \
               managed_firefox_playground_profile "$profile_name"; then
                FIREFOX_RECONCILE_PROFILES+=("${pdir}")
                FIREFOX_RECONCILE_NAMES+=("${profile_name}")
            fi
        fi
    done < <(list_registered_profiles)
}

HARDENED_PROFILES=()
HARDENED_NAMES=()
FIREFOX_RECONCILE_PROFILES=()
FIREFOX_RECONCILE_NAMES=()
UNHARDENED_PROFILES=()
UNHARDENED_NAMES=()
if [[ -r /usr/local/lib/noid-privacy/firefox-profiles.sh ]]; then
    # shellcheck source=/dev/null
    . /usr/local/lib/noid-privacy/firefox-profiles.sh
    classify_firefox_profiles
fi

if [[ ${#FIREFOX_RECONCILE_PROFILES[@]} -eq 0 ]]; then
    MISSING+=("noid-firefox (no Firefox profile eligible for automatic hardening)")
fi

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo -e "${YELLOW}INFO${NC}: Optional tools/profiles not found: ${MISSING[*]}"
    echo -e "       → corresponding steps will be skipped"
    echo ""
fi

# [1] Snapper Pre-Snapshot (CLI rollback point)
step "1" "Snapper Pre-Snapshot"
if command -v snapper >/dev/null 2>&1 && \
   [ -x /usr/libexec/noid-snapper-create ] && \
   sudo snapper list-configs 2>/dev/null | grep -q "^root"; then
    snap_num=$(sudo /usr/libexec/noid-snapper-create pre \
        "noid-update-all pre" 2>/dev/null) || snap_num=""
    if [[ -n "${snap_num}" ]]; then
        echo -e "${GREEN}OK${NC}: Pre-snapshot #${snap_num} created"
    else
        echo -e "${YELLOW}WARN${NC}: snapper create failed"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo -e "${YELLOW}SKIP${NC}: snapper not configured (root config missing)"
    SKIPPED_LIST+=("Snapper")
fi

verify_dnf_completeness() {
    local output='' check_rc=0

    # DNF5 intentionally lets `upgrade` skip candidates whose dependencies do
    # not currently resolve and still return success. Keep that behavior so a
    # transient third-party repository skew cannot block unrelated Fedora
    # security updates, then use the command's documented postflight contract:
    # check-upgrade returns 0 for no remaining update, 100 when candidates
    # remain, and another value when completeness cannot be determined. The
    # just-refreshed cache avoids a second network round trip and the caller
    # supplies the same policy exclusions as the transaction.
    if output=$(sudo LC_ALL=C dnf --cacheonly check-upgrade "$@" 2>&1); then
        check_rc=0
    else
        check_rc=$?
    fi
    case "$check_rc" in
        0)
            echo -e "${GREEN}OK${NC}: no policy-eligible RPM updates remain"
            ;;
        100)
            [ -z "$output" ] || printf '%s\n' "$output" | sed 's/^/    /'
            echo -e "${YELLOW}WARN${NC}: DNF left update candidates unresolved; repository/version skew requires review"
            WARNINGS=$((WARNINGS + 1))
            ;;
        *)
            [ -z "$output" ] || printf '%s\n' "$output" | sed 's/^/    /'
            echo -e "${RED}ERROR${NC}: DNF update completeness check failed (exit ${check_rc})"
            ERRORS=$((ERRORS + 1))
            return 1
            ;;
    esac
    return 0
}

newest_installed_kernel_package() {
    local inventory candidate package count=0
    inventory=$(sudo LC_ALL=C rpm -q \
        --qf $'%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' \
        kernel 2>/dev/null) || return 1
    while IFS= read -r candidate; do
        [[ "$candidate" == kernel-?* ]] \
            && [[ "$candidate" != *[[:space:]]* ]] \
            || return 1
        count=$((count + 1))
    done <<< "$inventory"
    [ "$count" -gt 0 ] || return 1
    package=$(LC_ALL=C sort -V <<< "$inventory" | tail -n 1) || return 1
    printf '%s\n' "$package"
}

BRANDING_RESTORE_HELPER=/usr/local/sbin/noid-restore-branding
BGRT_PLY_UPGRADE=/usr/share/plymouth/themes/bgrt/bgrt.plymouth
# Track either maintained NVIDIA branch. The exact branch pair and its kmod are
# verified later by M19's shared verifier; this value is only a change trigger.
nvidia_branch_evr() {
    local rows name evr main_cuda_value legacy_cuda_value
    local main_akmod='' main_cuda='' legacy_akmod='' legacy_cuda=''
    # One successful complete rpmdb inventory distinguishes a normal missing
    # package from a database/read failure and binds both halves of each
    # supported branch. A CUDA-only change or partial branch must be a trigger,
    # not invisible state.
    rows=$(sudo rpm -qa --qf '%{NAME}\t%{EVR}.%{ARCH}\n' 2>/dev/null) \
        || return 1
    while IFS=$'\t' read -r name evr; do
        case "$name" in
            akmod-nvidia)
                [ -z "$main_akmod" ] || return 1
                main_akmod=$evr ;;
            xorg-x11-drv-nvidia-cuda)
                [ -z "$main_cuda" ] || return 1
                main_cuda=$evr ;;
            akmod-nvidia-580xx)
                [ -z "$legacy_akmod" ] || return 1
                legacy_akmod=$evr ;;
            xorg-x11-drv-nvidia-580xx-cuda)
                [ -z "$legacy_cuda" ] || return 1
                legacy_cuda=$evr ;;
        esac
    done <<< "$rows"
    main_cuda_value=${main_cuda:-missing}
    legacy_cuda_value=${legacy_cuda:-missing}
    if [[ -n "$main_akmod" && -n "$legacy_akmod" ]]; then
        printf 'mixed:main-akmod=%s:main-cuda=%s:580xx-akmod=%s:580xx-cuda=%s\n' \
            "$main_akmod" "$main_cuda_value" "$legacy_akmod" "$legacy_cuda_value"
    elif [[ -n "$main_akmod" && -n "$main_cuda" \
            && -z "$legacy_akmod" && -z "$legacy_cuda" ]]; then
        printf 'main:akmod=%s:cuda=%s\n' "$main_akmod" "$main_cuda"
    elif [[ -n "$legacy_akmod" && -n "$legacy_cuda" \
            && -z "$main_akmod" && -z "$main_cuda" ]]; then
        printf '580xx:akmod=%s:cuda=%s\n' "$legacy_akmod" "$legacy_cuda"
    elif [[ -z "$main_akmod" && -z "$main_cuda" \
            && -z "$legacy_akmod" && -z "$legacy_cuda" ]]; then
        printf 'none\n'
    else
        printf 'partial:main-akmod=%s:main-cuda=%s:580xx-akmod=%s:580xx-cuda=%s\n' \
            "${main_akmod:-missing}" "$main_cuda_value" \
            "${legacy_akmod:-missing}" "$legacy_cuda_value"
    fi
}

resume_retained_nvidia_queue() {
    local queue=/var/lib/noid-nvidia-integrity/queue probe deadline
    [ -d "$queue" ] && [ ! -L "$queue" ] || return 0
    if ! find "$queue" -mindepth 1 -maxdepth 1 -type f \
            \( -name '*.pending' -o -name '*.deferred' \) \
            -print -quit 2>/dev/null | grep -q .; then
        return 0
    fi
    [ -x /usr/libexec/noid-nvidia-initramfs-queue ] || return 1
    probe=$(mktemp "${XDG_RUNTIME_DIR:-/tmp}/.noid-nvidia-resume.XXXXXX") \
        || return 1
    if ! sudo /usr/libexec/noid-nvidia-initramfs-queue --resume; then
        rm -f -- "$probe"
        return 1
    fi
    deadline=$((SECONDS + 3600))
    while find "$queue" -mindepth 1 -maxdepth 1 -type f \
            \( -name '*.pending' -o -name '*.deferred' \) \
            -print -quit 2>/dev/null | grep -q .; do
        if find "$queue" -mindepth 1 -maxdepth 1 -type f -name '*.failed' \
                -newer "$probe" -print -quit 2>/dev/null | grep -q .; then
            rm -f -- "$probe"
            return 1
        fi
        if (( SECONDS >= deadline )); then
            rm -f -- "$probe"
            return 1
        fi
        sleep 2
    done
    rm -f -- "$probe"
}

# Resume power-loss/interrupted work before taking M25's boot-mutation lock;
# the M19 workers need that same lock and would otherwise deadlock behind us.
if find /var/lib/noid-nvidia-integrity/queue -mindepth 1 -maxdepth 1 \
        -type f \( -name '*.pending' -o -name '*.deferred' \) \
        -print -quit 2>/dev/null | grep -q .; then
    echo ""
    echo "  -> Resuming retained NVIDIA boot-image verification..."
    if resume_retained_nvidia_queue; then
        echo -e "${GREEN}OK${NC}: retained NVIDIA queue converged before DNF"
    else
        echo -e "${RED}ERROR${NC}: retained NVIDIA queue did not converge; do not reboot"
        ERRORS=$((ERRORS + 1))
        register_reboot_blocker nvidia || true
    fi
fi

# The DNF transaction may install kernels and execute kernel-install/dracut;
# keep that complete phase mutually exclusive with M21 and every supported
# NoID Privacy BLS/initramfs writer. M19's update hook sees the update-running
# marker and is handled by the durable queue after this lock is released.
BOOT_MUTATION_LOCK=/run/lock/noid-boot-mutation.lock
if [ ! -e "$BOOT_MUTATION_LOCK" ]; then
    echo -e "${RED}ERROR${NC}: shared boot-mutation lock is missing; repair Module 21 first."
    exit 1
fi
if ! exec 7>"$BOOT_MUTATION_LOCK"; then
    echo -e "${RED}ERROR${NC}: cannot open the shared boot-mutation lock."
    exit 1
fi
if ! flock -w 1800 7; then
    echo -e "${RED}ERROR${NC}: timed out waiting for another boot mutation."
    exit 1
fi
if ! sudo /usr/libexec/noid-boot-mutation-guard >/dev/null; then
    echo -e "${RED}ERROR${NC}: M21 boot recovery/reboot validation is incomplete; update refused."
    exit 1
fi
# [2] DNF
echo ""
step "2" "DNF (RPM packages)"
# Capture every change-detection baseline only after acquiring the shared boot
# lease. Reading these before a possibly long lock wait would compare DNF
# against stale state changed by the prior lock owner.
KERNEL_BEFORE_VALID=1
if ! kernel_before=$(newest_installed_kernel_package); then
    kernel_before=
    KERNEL_BEFORE_VALID=0
    echo -e "${RED}ERROR${NC}: cannot determine the newest installed kernel before DNF"
    ERRORS=$((ERRORS + 1))
fi
cmdline_before_sha=$(sudo sha256sum /etc/kernel/cmdline 2>/dev/null \
    | awk '{print $1}') || cmdline_before_sha=missing
plymouth_before_sha=$(sudo sha256sum "$BGRT_PLY_UPGRADE" 2>/dev/null \
    | awk '{print $1}') || plymouth_before_sha=missing
NVIDIA_BEFORE_VALID=1
if ! nvidia_before=$(nvidia_branch_evr); then
    nvidia_before=invalid
    NVIDIA_BEFORE_VALID=0
    echo -e "${RED}ERROR${NC}: cannot inventory the managed NVIDIA branch before DNF"
    ERRORS=$((ERRORS + 1))
    register_reboot_blocker nvidia || true
fi
# umask 022 subshell: defensive measure. M10 KEEPS Fedora's default
# UMASK=022 (intentionally not 027 per Kicksecure security-misc #185
# rationale — stricter umask breaks dnf5 system-state files, rpm-
# software-management/dnf5#1908). So the subshell is currently a no-op
# on a vanilla M10 image. Kept as belt+suspenders against:
#   (1) user who manually changed /etc/login.defs UMASK to stricter value
#   (2) root processes with inherited strict umask from a custom cron /
#       systemd service that invokes update-all.sh
#   (3) future M10 change that tightens UMASK
# The post-fix below (chmod 644 on any 640 .session files) is further
# belt+suspenders that catches GDM greeter breakage regardless of path.
# Silent-Machine fix: prevent automatic noopenh264
# obsolete-swap during routine updates. fedora-cisco-openh264.repo ships
# enabled=1 so manual `dnf install openh264` is one-step, BUT openh264
# carries Obsoletes: noopenh264 → unconditional `dnf upgrade` would
# silently swap in the patent-encumbered codec on every run. Conditional
# --exclude breaks the swap pre-opt-in; once user opts in via Welcome
# (codec packages installed), exclude is dropped so security updates flow
# normally.
# DNF5 documents --refresh as the single metadata-freshness control for the
# transaction. Do not mutate the cache independently immediately beforehand:
# that duplicates the same policy, adds another privileged failure surface and
# cannot make a successful --refresh transaction fresher.
# The repository wildcard setopt is a command-line-priority transaction guard:
# every downloaded repository package must pass its OpenPGP check even if
# persistent repository configuration drifted weaker. Step 7 independently
# reports that persistent drift instead of hiding it behind this one-run guard.
openh264_opted_in() {
    local codec_package
    # The NoID Privacy image starts with all three components absent. Any installed
    # component therefore means that this host has left that zero-payload
    # baseline. Requiring a particular pair would strand a valid partial/manual
    # state behind --exclude and withhold its ordinary security updates.
    for codec_package in \
        openh264 mozilla-openh264 gstreamer1-plugin-openh264; do
        if sudo rpm -q "$codec_package" >/dev/null 2>&1; then
            return 0
        fi
    done
    return 1
}

dnf_signature_setopt='--setopt=*.pkg_gpgcheck=True'
dnf_codec_exclude='--exclude=openh264,mozilla-openh264,gstreamer1-plugin-openh264'
dnf_postcheck_args=("$dnf_signature_setopt")
if openh264_opted_in; then
    # At least one codec component is present — let that state resolve and
    # receive updates normally.
    sudo sh -c 'umask 022; LC_ALL=C dnf "$1" upgrade --refresh -y' \
        _ "$dnf_signature_setopt" 2>&1 | sed 's/^/    /'
else
    # No codec component is installed — exclude prevents Obsoletes-driven
    # auto-swap before opt-in.
    dnf_postcheck_args+=("$dnf_codec_exclude")
    sudo sh -c 'umask 022; LC_ALL=C dnf "$1" upgrade --refresh -y "$2"' \
        _ "$dnf_signature_setopt" "$dnf_codec_exclude" 2>&1 | sed 's/^/    /'
fi
dnf_rc=${PIPESTATUS[0]}
if [[ ${dnf_rc} -eq 0 ]]; then
    DNF_SUCCEEDED=1
    echo -e "${GREEN}OK${NC}: DNF transaction completed"
    verify_dnf_completeness "${dnf_postcheck_args[@]}" || true
else
    echo -e "${RED}ERROR${NC}: DNF upgrade failed (exit ${dnf_rc})"
    ERRORS=$((ERRORS + 1))
fi

# M08's host-only DNF action already regenerates VSCodium's XDG admin overlays
# when the codium package changes. Repeat the idempotent publisher here as the
# supported full-update workflow's end-to-end postcondition: the signed RPM
# desktop payload must stay pristine, every translated/current vendor action
# must be preserved, and only VSCodium's Exec target may route through the
# native platform-default GPU selector. The publisher runs regardless of the
# DNF exit code: it is idempotent, and a committed transaction whose
# post_transaction action failed still needs its end-to-end postcondition.
echo ""
echo "  -> VSCodium native default-GPU launcher convergence..."
if [ ! -x /usr/local/sbin/noid-codium-launcher-sync ]; then
    echo -e "${RED}ERROR${NC}: VSCodium launcher synchronizer is missing"
    ERRORS=$((ERRORS + 1))
elif sudo /usr/local/sbin/noid-codium-launcher-sync >/dev/null; then
    echo -e "${GREEN}OK${NC}: VSCodium RPM payload pristine; native default-GPU launchers converged"
else
    echo -e "${RED}ERROR${NC}: VSCodium launcher convergence failed"
    ERRORS=$((ERRORS + 1))
fi

# Re-submit the pinned BPF object to the running kernel verifier and refresh
# both physical-link hooks after RPM/bpftool/driver userspace updates. A newly
# installed kernel is not running yet and is therefore verified by M03's hard
# NetworkManager boot path after reboot. The topology helper preserves the
# firewalld/nft/netdev layers and publishes a DEGRADED health state if XDP alone
# is incompatible; that keeps WAN repair access without silently claiming the
# raw-packet boundary is complete.
echo ""
echo "  -> Physical-link XDP/TC post-update verification..."
xdp_health=""
if [ ! -x /usr/local/sbin/noid-lan-topology-refresh.sh ] \
   || [ ! -x /usr/local/sbin/noid-lan-xdp ]; then
    echo -e "${RED}ERROR${NC}: physical-link boundary helper is missing"
    ERRORS=$((ERRORS + 1))
elif ! sudo /usr/local/sbin/noid-lan-topology-refresh.sh; then
    echo -e "${RED}ERROR${NC}: physical-link boundary refresh transaction failed"
    ERRORS=$((ERRORS + 1))
else
    xdp_health=$(sed -n 's/^STATE=//p' /run/noid-privacy/lan-xdp-health \
        2>/dev/null | head -n 1)
    case "$xdp_health" in
        ACTIVE)
            if sudo /usr/local/sbin/noid-lan-xdp status 2>&1 | sed 's/^/    /'; then
                echo -e "${GREEN}OK${NC}: physical-link XDP/TC boundary reloaded and verified"
            else
                echo -e "${RED}ERROR${NC}: XDP health claimed ACTIVE but live postconditions failed"
                ERRORS=$((ERRORS + 1))
            fi
            ;;
        DEGRADED)
            echo -e "${YELLOW}WARN${NC}: hardware/kernel lacks the qualified XDP path; firewalld/nft fallback remains active"
            WARNINGS=$((WARNINGS + 1))
            if [ -x /usr/local/bin/noid-lan-xdp-notify ]; then
                /usr/local/bin/noid-lan-xdp-notify --force 2>/dev/null || true
            fi
            ;;
        *)
            echo -e "${RED}ERROR${NC}: physical-link boundary published no recognized health state"
            ERRORS=$((ERRORS + 1))
            ;;
    esac
fi

orphan_out=
orphan_rc=0
# Use the root transaction state and the cache refreshed immediately above.
# An unprivileged DNF5 invocation uses a separate per-user cache that was not
# refreshed by the transaction. --cacheonly also makes this inventory egress-free.
# Keep diagnostics out of the package-name stream; the exit code below still
# exposes an unavailable inventory without miscounting a warning as an orphan.
orphan_out=$(sudo LC_ALL=C dnf -q --cacheonly repoquery --unneeded 2>/dev/null) \
    || orphan_rc=$?
if [ "$orphan_rc" -ne 0 ]; then
    echo -e "${YELLOW}INFO${NC}: optional orphan-dependency inventory unavailable (exit ${orphan_rc})"
elif [[ -n "${orphan_out}" ]]; then
    orphan_count=$(printf '%s\n' "${orphan_out}" | wc -l)
    echo -e "${YELLOW}INFO${NC}: ${orphan_count} orphan dependencies (manually: sudo dnf autoremove)"
fi

# GDM session permission guard
for f in /usr/share/gnome-session/sessions/*.session; do
    if [ -f "$f" ]; then
        perms=$(stat -c '%a' "$f")
        if [ "$perms" != "644" ]; then
            echo -e "${YELLOW}FIX${NC}: $f had $perms, correcting to 644"
            sudo chmod 644 "$f"
        fi
    fi
done

# Reconcile M10's declarative permission policy after the complete update.
# The dnf5 action already runs transaction-scoped for each owning package;
# this native tmpfiles call is the end-to-end postcondition, not a blind
# periodic chmod loop.
if [ -f /etc/tmpfiles.d/90-noid-permission-policy.conf ]; then
    echo ""
    echo "  → Native permission-policy reconciliation..."
    if sudo systemd-tmpfiles --create \
            /etc/tmpfiles.d/90-noid-permission-policy.conf; then
        echo -e "${GREEN}OK${NC}: M10 tmpfiles permission policy reconciled"
    else
        echo -e "${RED}ERROR${NC}: M10 tmpfiles permission policy failed"
        ERRORS=$((ERRORS + 1))
    fi
fi

# Normalize the two GRUB objects whose package-declared state is part of the
# clean NoID Privacy RPM posture. This is intentionally narrow: never run rpm --restore
# across whole packages because that could overwrite reviewed NoID Privacy-managed
# files elsewhere in the payload.
if [ -d /boot/grub2 ]; then
    sudo chmod 0700 /boot/grub2
    sudo chown root:root /boot/grub2
fi
if [ -f /etc/default/grub ] && [ ! -e /etc/sysconfig/grub ] \
   && [ ! -L /etc/sysconfig/grub ]; then
    sudo ln -s ../default/grub /etc/sysconfig/grub
fi
if [ "$(stat -c '%a:%U:%G' /boot/grub2 2>/dev/null)" != "700:root:root" ] \
   || [ "$(readlink /etc/sysconfig/grub 2>/dev/null)" != "../default/grub" ]; then
    echo -e "${RED}ERROR${NC}: GRUB RPM metadata normalization failed"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}OK${NC}: GRUB RPM metadata normalized"
fi

# Fedora's kernel-install 20-grub plugin can regenerate /etc/kernel/cmdline
# during a kernel transaction. On the NoID Privacy default-subvolume boot model,
# grub2-mkconfig observes the currently mounted Btrfs path and can resurrect
# Anaconda's obsolete rootflags=subvol= selector. Re-run M01's single native
# publisher while this process still owns BOOT_MUTATION_LOCK, before any
# initramfs is rebuilt from the durable command line.
# The publisher runs even when DNF exited nonzero: dnf5 reports exit 1 for a
# committed transaction whose post_transaction action failed, and by then
# kernel-install has already rewritten the durable sources. Skipping here left
# the boot contract degraded and blocked Snapper pre/post pairing; the
# publisher is idempotent, self-verifying, and a no-op when nothing drifted.
echo ""
echo "  -> Canonical post-DNF kernel command-line convergence..."
if ! sudo /usr/libexec/noid-canonicalize-kernel-cmdline --publish \
        >/dev/null; then
    echo -e "${RED}ERROR${NC}: canonical kernel command-line convergence failed; do not reboot"
    ERRORS=$((ERRORS + 1))
    register_reboot_blocker kernel-cmdline || true
elif sudo awk -F= '$1=="MODEL" && $2=="default-subvolume-v1" {found=1} END {exit !found}' \
        /.snapshots/.noid-state/boot-model.ready \
        && sudo grep -Eq '(^|[[:space:]])rootflags=[^[:space:]]*(subvol|subvolid)=' \
            /etc/kernel/cmdline; then
    echo -e "${RED}ERROR${NC}: obsolete Btrfs root selector survived canonical convergence; do not reboot"
    ERRORS=$((ERRORS + 1))
    register_reboot_blocker kernel-cmdline || true
else
    echo -e "${GREEN}OK${NC}: durable kernel command line and normal BLS entries converged"
    cmdline_after_sha=$(sudo sha256sum /etc/kernel/cmdline 2>/dev/null \
        | awk '{print $1}') || cmdline_after_sha=missing
    if [[ "$cmdline_after_sha" != "$cmdline_before_sha" ]]; then
        BOOT_IMAGE_GLOBAL_REBUILD=1
        BOOT_IMAGE_REBUILD_REASON="durable kernel command line changed"
    fi
fi

# M32 owns one value-independent recovery contract for every RPM-owned
# branding surface. Its host-only DNF action normally converges the files
# during post_transaction; this explicit invocation is the orchestrator's
# end-to-end postcondition and covers a disabled/missed action without
# duplicating the layout policy here.
#
# The bgrt source is embedded in each initramfs. Rebuild every image only when
# its final bytes differ from the bytes present before DNF. A normal Plymouth
# package update temporarily installs stock bytes and M32 restores the exact
# prior canonical bytes before this comparison, so the existing images remain
# valid and an expensive all-kernel rebuild would add no correctness.
# The convergence runs regardless of the DNF exit code: the helper is a
# value-independent recovery contract, and a transaction that stomped a
# branding surface before failing its post_transaction action still needs it.
reconcile_branding_after_dnf() {
    local plymouth_after_sha

    echo ""
    echo "  -> Canonical post-DNF branding convergence..."
    if [ ! -x "$BRANDING_RESTORE_HELPER" ]; then
        echo -e "${RED}ERROR${NC}: canonical M32 branding helper is missing"
        ERRORS=$((ERRORS + 1))
        return 0
    fi
    if ! sudo "$BRANDING_RESTORE_HELPER" >/dev/null; then
        echo -e "${RED}ERROR${NC}: canonical M32 branding convergence failed"
        ERRORS=$((ERRORS + 1))
        return 0
    fi
    if ! plymouth_after_sha=$(sudo sha256sum "$BGRT_PLY_UPGRADE" 2>/dev/null \
            | awk '{print $1}'); then
        echo -e "${RED}ERROR${NC}: managed Plymouth source is missing after branding convergence"
        ERRORS=$((ERRORS + 1))
        return 0
    fi
    if [[ "$plymouth_after_sha" != "$plymouth_before_sha" ]]; then
        BOOT_IMAGE_GLOBAL_REBUILD=1
        BOOT_IMAGE_REBUILD_REASON="${BOOT_IMAGE_REBUILD_REASON:+${BOOT_IMAGE_REBUILD_REASON}; }managed Plymouth source changed"
        echo -e "${GREEN}OK${NC}: branding converged; changed Plymouth bytes queued for atomic all-kernel rebuild"
    else
        echo -e "${GREEN}OK${NC}: branding converged; Plymouth bytes unchanged, existing boot images remain valid"
    fi
}

reconcile_branding_after_dnf

# Resolve the exact post-transaction kernel/driver delta before releasing the
# shared boot lease. Fedora's kernel RPM already invokes kernel-install/Dracut
# for a new kernel. NoID Privacy therefore rebuilds only a new non-NVIDIA target that
# may have consumed a transient pre-convergence command line, or every image
# when a genuinely global NoID Privacy-owned input changed after package triggers.
# M19 remains the sole exact writer for a managed NVIDIA target.
KERNEL_AFTER_DNF_VALID=1
if ! kernel_after_dnf=$(newest_installed_kernel_package); then
    kernel_after_dnf=
    KERNEL_AFTER_DNF_VALID=0
    echo -e "${RED}ERROR${NC}: cannot determine the newest installed kernel after DNF"
    ERRORS=$((ERRORS + 1))
    register_reboot_blocker boot-inventory || true
fi
nvidia_after=invalid
NVIDIA_AFTER_VALID=1
NVIDIA_TOPOLOGY_VALID=1
if ! nvidia_after=$(nvidia_branch_evr); then
    NVIDIA_AFTER_VALID=0
    echo -e "${RED}ERROR${NC}: cannot inventory the managed NVIDIA branch after DNF"
    ERRORS=$((ERRORS + 1))
    register_reboot_blocker nvidia || true
fi
case "$nvidia_after" in
    mixed:*|partial:*)
        NVIDIA_TOPOLOGY_VALID=0
        echo -e "${RED}ERROR${NC}: managed NVIDIA packages are partial or mixed after DNF; do not reboot"
        ERRORS=$((ERRORS + 1))
        register_reboot_blocker nvidia || true
        ;;
esac
new_kver=""
if [[ "$NVIDIA_AFTER_VALID" -eq 1 && "$NVIDIA_TOPOLOGY_VALID" -eq 1 \
        && "${nvidia_after}" != none \
        && "$KERNEL_AFTER_DNF_VALID" -eq 1 ]]; then
    # Always converge the kernel that the next reboot would select. This also
    # repairs a pending newer kernel from an earlier failed run even when the
    # current DNF transaction changed neither kernel nor driver packages.
    if [[ "$KERNEL_BEFORE_VALID" -ne 1 \
          || "${kernel_before}" != "${kernel_after_dnf}" \
          || "$NVIDIA_BEFORE_VALID" -ne 1 \
          || "${nvidia_before}" != "${nvidia_after}" \
          || "$PRIOR_NVIDIA_BLOCK" -eq 1 \
          || "${kernel_after_dnf#kernel-}" != "$(uname -r)" ]]; then
        new_kver="${kernel_after_dnf#kernel-}"
    fi
fi
non_nvidia_kernel_target=""
if [[ "$KERNEL_BEFORE_VALID" -eq 1 && "$KERNEL_AFTER_DNF_VALID" -eq 1 \
        && "${kernel_before}" != "${kernel_after_dnf}" \
        && "${nvidia_after}" == none ]]; then
    non_nvidia_kernel_target="${kernel_after_dnf#kernel-}"
fi

# The regeneration runs regardless of the DNF exit code: its inputs are
# change-scoped (queued global drift or an exact new kernel), so a failed
# transaction without such input remains a validated no-op.
regenerate_changed_boot_images() {
    local target_kernel="${1:-}" nvidia_target="${2:-}"

    echo ""
    echo "  -> Change-scoped atomic boot-image regeneration and validation..."
    if [[ "$BOOT_IMAGE_GLOBAL_REBUILD" -eq 1 ]]; then
        echo "    Global input: ${BOOT_IMAGE_REBUILD_REASON}"
        if sudo -C 8 /usr/libexec/noid-dracut-regenerate-all \
                --lock-held=7; then
            echo -e "${GREEN}OK${NC}: every installed initramfs atomically rebuilt and validated"
            return 0
        fi
        echo -e "${RED}ERROR${NC}: canonical all-kernel boot-image regeneration failed; do not reboot"
        ERRORS=$((ERRORS + 1))
        register_reboot_blocker initramfs || true
        return 1
    fi
    if [[ -n "$target_kernel" ]]; then
        if sudo -C 8 /usr/libexec/noid-dracut-regenerate-all \
                --lock-held=7 --kernel="$target_kernel"; then
            echo -e "${GREEN}OK${NC}: initramfs for ${target_kernel} atomically rebuilt and validated"
            return 0
        fi
        echo -e "${RED}ERROR${NC}: targeted boot-image regeneration failed for ${target_kernel}; do not reboot"
        ERRORS=$((ERRORS + 1))
        register_reboot_blocker initramfs || true
        return 1
    fi
    if [[ -n "$nvidia_target" ]]; then
        echo -e "${YELLOW}DEFER${NC}: ${nvidia_target} is owned by the exact NVIDIA module/initramfs worker below"
        return 0
    fi
    echo -e "${GREEN}SKIP${NC}: no boot-image input changed; native package hooks retained the existing images"
    return 0
}

regenerate_changed_boot_images "$non_nvidia_kernel_target" "$new_kver" || true
# M19's queue takes the same shared lock. Release the DNF/GRUB/Plymouth phase
# before entering that durable worker path; otherwise the parent would wait on
# its own lock through a separate process.
flock -u 7
exec 7>&-

# M32's fedora-release action restores identity files inside the DNF callback
# but only queues its BLS title convergence. Start that oneshot synchronously
# after releasing BOOT_MUTATION_LOCK, prove the durable marker was consumed,
# and only then enter M19's separate queue. Calling it while fd 7 was locked
# would make the updater wait on its own transaction through another process.
echo ""
echo "  -> Guarded BLS identity convergence..."
if ! sudo systemctl start noid-identity-bls-refresh.service; then
    echo -e "${RED}ERROR${NC}: queued BLS identity convergence failed; do not reboot"
    ERRORS=$((ERRORS + 1))
    register_reboot_blocker bls-identity || true
elif sudo test -e /var/lib/noid-privacy/identity-bls-refresh.pending \
        || sudo test -L /var/lib/noid-privacy/identity-bls-refresh.pending; then
    echo -e "${RED}ERROR${NC}: BLS identity request remained pending after service success; do not reboot"
    ERRORS=$((ERRORS + 1))
    register_reboot_blocker bls-identity || true
else
    echo -e "${GREEN}OK${NC}: BLS identity entries converged under the shared boot contract"
fi

# NVIDIA exact module-set + atomic initramfs verification after a kernel OR
# driver update. M19's dnf/kernel-install hooks deliberately skip only while
# M25's process/lock validator proves this exact orchestrator is active; this
# path then enters the same durable queue explicitly and waits for exact ready
# evidence before continuing.
if [[ -n "${new_kver}" ]]; then
    NVIDIA_OK=0
    echo ""
    echo "  -> Queueing exact NVIDIA module/initramfs verification for ${new_kver}..."
    queued_marker=''
    if [[ ! -x /usr/libexec/noid-nvidia-initramfs-queue \
          || ! -x /usr/libexec/noid-nvidia-verify ]]; then
        echo -e "${RED}ERROR${NC}: M19 NVIDIA integrity helpers are missing; run noid-nvidia-install.sh to repair the managed installation."
    elif queued_marker=$(sudo /usr/libexec/noid-nvidia-initramfs-queue \
            "${new_kver}" 2>/dev/null) \
            && [[ "$queued_marker" == /var/lib/noid-nvidia-integrity/queue/*.pending ]]; then
        failed_marker="${queued_marker%.pending}.failed"
        deadline=$((SECONDS + 3600))
        while sudo test -e "$queued_marker"; do
            if sudo test -s "$failed_marker"; then
                echo -e "${RED}ERROR${NC}: NVIDIA worker failed:"
                sudo sed 's/^/    /' "$failed_marker" || true
                break
            fi
            if (( SECONDS >= deadline )); then
                echo -e "${RED}ERROR${NC}: NVIDIA worker timed out; durable task and reboot inhibitor remain active."
                break
            fi
            sleep 2
        done
        ready_file="/var/lib/noid-nvidia-integrity/${new_kver}.ready"
        if ! sudo test -e "$queued_marker" \
                && sudo test -s "$ready_file" \
                && verify_output=$(sudo /usr/libexec/noid-nvidia-verify \
                    "$new_kver" --require-enrolled 2>&1); then
            expected_initramfs_hash=$(sudo sed -n \
                's/^initramfs_sha256=//p' "$ready_file" | tail -1)
            actual_initramfs_hash=$(sudo sha256sum \
                "/boot/initramfs-${new_kver}.img" 2>/dev/null | awk '{print $1}')
            if [[ -n "$expected_initramfs_hash" \
                  && "$actual_initramfs_hash" == "$expected_initramfs_hash" ]]; then
                NVIDIA_OK=1
                printf '%s\n' "$verify_output" | sed 's/^/    /'
                echo -e "${GREEN}OK${NC}: exact NVIDIA modules + enrolled MOK + initramfs verified for ${new_kver}"
            fi
        fi
    else
        echo -e "${RED}ERROR${NC}: could not enter the durable NVIDIA rebuild queue."
    fi
    if [[ "${NVIDIA_OK}" -eq 0 ]]; then
        ERRORS=$((ERRORS + 1))
        register_reboot_blocker nvidia || true
        echo -e "${RED}ERROR${NC}: NVIDIA update is not reboot-ready. The prior initramfs remains at the BLS path or the reboot inhibitor remains active."
        echo "  Recovery: sudo /usr/libexec/noid-nvidia-initramfs-queue --resume"
        echo "  Full rollback: noid-nvidia-install.sh --rollback"
    fi

    # On fail: critical notification to the invoking desktop session.
    if [[ "${NVIDIA_OK}" -eq 0 ]] && command -v notify-send >/dev/null 2>&1; then
        user_uid=$(id -u)
        if [[ -S "/run/user/${user_uid}/bus" ]]; then
            DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${user_uid}/bus" \
                notify-send --urgency=critical --icon=dialog-error \
                --app-name="NoID Privacy" \
                "NVIDIA integrity verification FAILED" \
                "Kernel ${new_kver} is not reboot-ready. The durable task/inhibitor remains; run: sudo /usr/libexec/noid-nvidia-initramfs-queue --resume" \
                2>/dev/null || true
        fi
    fi
fi

# [3] Flatpak — explicit System (sudo) + User (no auth) split
# Earlier versions ran `flatpak update --noninteractive -y` without scope flags.
# That tries to update both scopes, but in --noninteractive mode the polkit
# auth required for system-scope updates can fail silently (flatpak#4838).
# Splitting makes auth deterministic: sudo for system (cache valid from Step 2
# DNF), no auth for user.
# NOTE: --noninteractive -y can accept expanded app permissions. This is a
# deliberate user-operated update trade-off, not a claim that the five global
# M18 denials neutralize every broad app permission. Interactive confirmation
# would deadlock the orchestrator; transaction output remains visible, and M18
# documents both `flatpak info --show-permissions` and the optional verified
# Flatseal UI for per-app review. No background Flatpak updater is enabled.
echo ""
step "3" "Flatpak (System + User scope)"
if command -v flatpak >/dev/null 2>&1; then
    flatpak_rc=0
    # Flatpak 1.18 deliberately treats a failed optional/related-ref mutation
    # as non-fatal and can exit 0 after printing e.g.
    # `Warning: Failed to install org.freedesktop.Platform.GL...`. A GPU
    # driver extension can therefore remain absent while an exit-code-only
    # orchestrator reports green. Preserve Flatpak's native HTTP negotiation,
    # resume the content-addressed OSTree pull at most twice, and retain a third
    # exact mutation warning as a visible non-blocking updater warning. Flatpak
    # itself deliberately returned success for that related-ref condition; a
    # real non-zero process status remains a hard error. LC_ALL=C makes this
    # narrow vendor diagnostic stable; all other output remains informational.
    flatpak_related_incomplete=0
    run_flatpak_scope_update() {
        local scope=$1 label=$2 attempt=1 max_attempts=3 output
        local -a pipe_status

        output=$(mktemp "${XDG_RUNTIME_DIR:-/tmp}/.noid-flatpak-${label}.XXXXXX") || {
            echo -e "${RED}ERROR${NC}: cannot create ${label} Flatpak transaction evidence"
            return 70
        }
        if ! chmod 0600 "$output"; then
            rm -f -- "$output"
            echo -e "${RED}ERROR${NC}: cannot protect ${label} Flatpak transaction evidence"
            return 70
        fi

        while [[ $attempt -le $max_attempts ]]; do
            : > "$output" || {
                rm -f -- "$output"
                echo -e "${RED}ERROR${NC}: cannot reset ${label} Flatpak transaction evidence"
                return 70
            }
            if [[ $scope == system ]]; then
                sudo LC_ALL=C flatpak update --system --noninteractive -y 2>&1 \
                    | tee "$output" | sed 's/^/    /'
            else
                LC_ALL=C flatpak --user update --noninteractive -y 2>&1 \
                    | tee "$output" | sed 's/^/    /'
            fi
            pipe_status=("${PIPESTATUS[@]}")
            if [[ ${pipe_status[1]} -ne 0 || ${pipe_status[2]} -ne 0 ]]; then
                rm -f -- "$output"
                echo -e "${RED}ERROR${NC}: cannot preserve ${label} Flatpak transaction output"
                return 74
            fi
            if LC_ALL=C grep -Eq \
                    '^Warning: Failed to (install|update|uninstall) ' "$output"; then
                if [[ ${pipe_status[0]} -ne 0 ]]; then
                    rm -f -- "$output"
                    return "${pipe_status[0]}"
                fi
                if [[ $attempt -lt $max_attempts ]]; then
                    echo -e "    ${YELLOW}INFO${NC}: ${label} Flatpak related refs incomplete; resumable retry $((attempt + 1))/${max_attempts}"
                    attempt=$((attempt + 1))
                    sleep 2
                    continue
                fi
                rm -f -- "$output"
                flatpak_related_incomplete=$((flatpak_related_incomplete + 1))
                return 0
            fi
            rm -f -- "$output"
            return "${pipe_status[0]}"
        done
        rm -f -- "$output"
        return 70
    }

    system_refs=''
    user_refs=''
    system_list_rc=0
    user_list_rc=0
    system_has_refs=0
    user_has_refs=0
    # Per-scope hard status is captured from the actual Flatpak process. The
    # documented exit-0 mutation warning above is tracked separately so it can
    # remain visible without misclassifying the entire update as failed.

    # `flatpak update` also refreshes AppStream catalogs. On a fresh image with
    # no installed refs that downloads both the full and verified Flathub
    # catalogs without updating any software. Keep the explicit user-operated
    # catalog/search path demand-driven and skip only demonstrably empty local
    # installations. Query failures remain hard update errors.
    system_refs=$(sudo LC_ALL=C flatpak list --system --columns=ref 2>&1) \
        || system_list_rc=$?
    user_refs=$(LC_ALL=C flatpak --user list --columns=ref 2>&1) \
        || user_list_rc=$?
    if [[ ${system_list_rc} -ne 0 ]]; then
        printf '%s\n' "${system_refs}" | sed 's/^/    [system] /'
        echo -e "${RED}ERROR${NC}: cannot inventory system-scope Flatpak refs (exit ${system_list_rc})"
        flatpak_rc=${system_list_rc}
    elif [[ -n ${system_refs} ]]; then
        system_has_refs=1
    fi
    if [[ ${user_list_rc} -ne 0 ]]; then
        printf '%s\n' "${user_refs}" | sed 's/^/    [user] /'
        echo -e "${RED}ERROR${NC}: cannot inventory user-scope Flatpak refs (exit ${user_list_rc})"
        flatpak_rc=${user_list_rc}
    elif [[ -n ${user_refs} ]]; then
        user_has_refs=1
    fi

    # System scope: needs polkit auth in non-interactive mode → invoke via sudo
    # so it inherits the sudo timestamp from Step 2 DNF (no extra prompt).
    if [[ ${system_has_refs} -eq 1 ]]; then
        echo "  → Updating system-scope Flatpaks (admin-installed apps)"
        fp_t0=$(date +%s)
        run_flatpak_scope_update system system
        sys_rc=$?
        [[ ${sys_rc} -ne 0 ]] && flatpak_rc=${sys_rc}
        echo "    [system] duration: $(human_duration $(($(date +%s) - fp_t0)))"
    elif [[ ${system_list_rc} -eq 0 ]]; then
        echo -e "${GREEN}SKIP${NC}: no installed system-scope Flatpak refs"
    fi

    # User scope: runs as user, no auth needed. Covers apps the user
    # installed with `flatpak --user install` from flathub-verified.
    if [[ ${user_has_refs} -eq 1 ]]; then
        echo "  → Updating user-scope Flatpaks (user-installed apps)"
        fp_t0=$(date +%s)
        run_flatpak_scope_update user user
        user_rc=$?
        [[ ${user_rc} -ne 0 ]] && flatpak_rc=${user_rc}
        echo "    [user] duration: $(human_duration $(($(date +%s) - fp_t0)))"
    elif [[ ${user_list_rc} -eq 0 ]]; then
        echo -e "${GREEN}SKIP${NC}: no installed user-scope Flatpak refs"
    fi
    if [[ ${flatpak_related_incomplete} -gt 0 ]]; then
        echo -e "${YELLOW}WARN${NC}: Flatpak updates completed, but related refs remain incomplete in ${flatpak_related_incomplete} populated scope(s); retry later"
        WARNINGS=$((WARNINGS + 1))
    fi
    if [[ ${flatpak_rc} -eq 0 && ${flatpak_related_incomplete} -eq 0 ]]; then
        if [[ ${system_has_refs} -eq 0 && ${user_has_refs} -eq 0 ]]; then
            echo -e "${GREEN}OK${NC}: no installed Flatpak refs; catalog-only refresh not needed"
        else
            echo -e "${GREEN}OK${NC}: Flatpak update completed for every populated scope"
        fi
    elif [[ ${flatpak_rc} -ne 0 ]]; then
        echo -e "${RED}ERROR${NC}: Flatpak update failed (exit ${flatpak_rc})"
        ERRORS=$((ERRORS + 1))
    fi

    # Runtime cleanup in both scopes. A previous update, a manual uninstall, or
    # an interrupted cleanup can leave old runtimes even when this run changed
    # no apps, so update-output parsing is not a sound reason to skip cleanup.
    if [[ "${NOID_SKIP_FLATPAK_CLEANUP:-0}" == "1" ]]; then
        echo ""
        echo -e "${YELLOW}SKIP${NC}: flatpak uninstall --unused (NOID_SKIP_FLATPAK_CLEANUP=1)"
        echo "         Run manually: flatpak uninstall --unused"
    else
        echo ""
        echo "  → Cleaning unused system- and user-scope runtimes"
        fp_t0=$(date +%s)
        unused_fail=0
        if [[ ${system_has_refs} -eq 1 ]]; then
            if unused_system_out=$(sudo LC_ALL=C flatpak uninstall --system --unused -y --noninteractive 2>&1); then
                printf '%s\n' "${unused_system_out}" | sed 's/^/    [system] /'
            else
                unused_rc=$?
                printf '%s\n' "${unused_system_out}" | sed 's/^/    [system] /'
                echo -e "${RED}ERROR${NC}: system-scope unused-runtime cleanup failed (exit ${unused_rc})"
                unused_fail=1
            fi
        elif [[ ${system_list_rc} -eq 0 ]]; then
            echo "    [system] no installed refs; cleanup not needed"
        else
            echo "    [system] inventory unavailable; cleanup skipped after error"
        fi
        if [[ ${user_has_refs} -eq 1 ]]; then
            if unused_user_out=$(LC_ALL=C flatpak --user uninstall --unused -y --noninteractive 2>&1); then
                printf '%s\n' "${unused_user_out}" | sed 's/^/    [user] /'
            else
                unused_rc=$?
                printf '%s\n' "${unused_user_out}" | sed 's/^/    [user] /'
                echo -e "${RED}ERROR${NC}: user-scope unused-runtime cleanup failed (exit ${unused_rc})"
                unused_fail=1
            fi
        elif [[ ${user_list_rc} -eq 0 ]]; then
            echo "    [user] no installed refs; cleanup not needed"
        else
            echo "    [user] inventory unavailable; cleanup skipped after error"
        fi
        fp_unused_dt=$(($(date +%s) - fp_t0))
        if [ "$unused_fail" -eq 0 ]; then
            echo -e "${GREEN}OK${NC}: Unused-runtime cleanup completed in both scopes ($(human_duration ${fp_unused_dt}))"
        else
            ERRORS=$((ERRORS + 1))
        fi
    fi

    # Runtime sandbox-boundary postflight. Module 18 enforces the same
    # postconditions at image build, finalization and release-test time.
    # Keep this after DNF/Flatpak updates so a regressed package set cannot
    # receive a green Update Summary.
    fp_ver=$(flatpak --version 2>/dev/null | awk '{print $2}')
    fp_min="1.18.1"
    if [[ -n "${fp_ver}" ]]; then
        fp_lowest=$(printf '%s\n%s\n' "${fp_ver}" "${fp_min}" | sort -V | head -n 1)
        if [[ "${fp_lowest}" != "${fp_min}" ]]; then
            echo -e "${RED}ERROR${NC}: flatpak ${fp_ver} < ${fp_min} (security baseline)"
            echo -e "  ${YELLOW}→${NC} Verify that DNF step 2 installed the current Flatpak security update"
            ERRORS=$((ERRORS + 1))
        else
            echo -e "${GREEN}OK${NC}: flatpak ${fp_ver} >= ${fp_min} (security baseline)"
        fi
    else
        echo -e "${RED}ERROR${NC}: cannot determine flatpak version"
        ERRORS=$((ERRORS + 1))
    fi

    portal_ver=
    portal_query_rc=0
    portal_ver=$(sudo LC_ALL=C rpm -q --queryformat '%{VERSION}\n' \
        xdg-desktop-portal 2>/dev/null) || portal_query_rc=$?
    portal_min="1.22.1"
    if [ "$portal_query_rc" -ne 0 ]; then
        echo -e "${RED}ERROR${NC}: xdg-desktop-portal package/version query failed (exit ${portal_query_rc})"
        ERRORS=$((ERRORS + 1))
    elif [[ ! "$portal_ver" =~ ^[0-9]+([.][0-9A-Za-z+-]+)*$ ]]; then
        echo -e "${RED}ERROR${NC}: xdg-desktop-portal returned an invalid version value"
        ERRORS=$((ERRORS + 1))
    else
        portal_lowest=$(printf '%s\n%s\n' "${portal_ver}" "${portal_min}" | sort -V | head -n 1)
        if [[ "${portal_lowest}" != "${portal_min}" ]]; then
            echo -e "${RED}ERROR${NC}: xdg-desktop-portal ${portal_ver} < ${portal_min} (CVE-2026-55888/55889)"
            echo -e "  ${YELLOW}→${NC} Verify that DNF step 2 installed the portal security update"
            ERRORS=$((ERRORS + 1))
        else
            echo -e "${GREEN}OK${NC}: xdg-desktop-portal ${portal_ver} >= ${portal_min} (security baseline)"
        fi
    fi

    if [[ ! -x /usr/bin/bwrap ]]; then
        echo -e "${RED}ERROR${NC}: bubblewrap executable missing or not executable"
        ERRORS=$((ERRORS + 1))
    elif [[ -u /usr/bin/bwrap ]]; then
        echo -e "${RED}ERROR${NC}: bubblewrap is setuid (deprecated privileged mode; CVE-2026-41163)"
        ERRORS=$((ERRORS + 1))
    else
        echo -e "${GREEN}OK${NC}: bubblewrap uses the non-setuid user-namespace path"
    fi
else
    echo -e "${YELLOW}SKIP${NC}: flatpak not installed"
    SKIPPED_LIST+=("Flatpak")
fi

settle_fwupd_daemon() {
    local fw_quit_out fw_quit_rc=0 fw_quit_deadline

    if ! systemctl --quiet is-active fwupd.service; then
        echo -e "${GREEN}OK${NC}: fwupd daemon is already inactive"
        return 0
    fi

    # `fwupdmgr quit` is fwupd's native lifecycle API: upstream defers daemon
    # shutdown until any firmware update in progress has finished. Normally
    # the script-start keep-alive supplies this credential; the explicit
    # NOID_UPDATE_NO_KEEPALIVE mode may request the normal per-step password.
    fw_quit_out=$(sudo LC_ALL=C fwupdmgr quit 2>&1) || fw_quit_rc=$?
    if [ -n "$fw_quit_out" ]; then
        printf '%s\n' "$fw_quit_out" | sed 's/^/    /'
    fi
    if [ "$fw_quit_rc" -ne 0 ]; then
        echo -e "${RED}ERROR${NC}: fwupd safe quit request failed (exit ${fw_quit_rc})"
        ERRORS=$((ERRORS + 1))
        return 1
    fi

    # Bound only observation. Never signal or kill a firmware daemon: a plugin
    # may still be completing device cleanup after the synchronous client call.
    fw_quit_deadline=$((SECONDS + 30))
    while systemctl --quiet is-active fwupd.service; do
        if (( SECONDS >= fw_quit_deadline )); then
            echo -e "${RED}ERROR${NC}: fwupd remained active after its update-aware quit request"
            ERRORS=$((ERRORS + 1))
            return 1
        fi
        sleep 0.25
    done
    echo -e "${GREEN}OK${NC}: fwupd daemon returned to its on-demand inactive state"
}

# [4] Firmware (fwupd) — manual confirm
echo ""
step "4" "Firmware (fwupd)"
if ! command -v fwupdmgr >/dev/null 2>&1; then
    echo -e "${YELLOW}SKIP${NC}: fwupdmgr not installed"
    SKIPPED_LIST+=("Firmware")
elif [ "$(systemctl is-enabled fwupd.service 2>/dev/null)" = "masked" ]; then
    # Skip gracefully when
    # fwupd.service is REALLY masked. An earlier `is-active --quiet` check
    # returns rc=3 ("inactive") for static D-Bus-activated services on
    # installed-system → false-positive skip. Observed:
    # noid-update-all.sh skipped Step 4 (Firmware) despite working fwupdmgr (D-Bus
    # auto-activation works fine). Distinguish "masked" (Live-ISO + M24
    # belt+suspenders + admin-masked) from "static" (D-Bus-dormant, normal
    # Fedora 44 installed). Only masked → SKIP. Static → fall through →
    # fwupdmgr triggers D-Bus activation, fwupd starts on-demand.
    echo -e "${YELLOW}SKIP${NC}: fwupd.service masked (Live ISO mode or admin-masked)"
    SKIPPED_LIST+=("Firmware")
else
    # For formatting consistency, pipe fwupdmgr refresh output
    # through sed for uniform col-5 indent.
    # filter per-percent progress noise. fwupdmgr prints a
    # localized progress line for every 1% increment → 100+ lines of noise per
    # refresh. grep -vE drops any line ending in ": NN%" while preserving the
    # status messages (metadata-download + device-update notices). Locale-
    # agnostic — pattern matches by structure, not strings.
    # An earlier integer-only regex `[0-9]+%` matched only INTEGER percents.
    # French locale (and others using decimal-comma) emits e.g.
    # a localized line like `…: 27,4%` which is `[digits][comma][digits]%` — the
    # integer-only regex missed it → all decimal-percentage lines leaked
    # through → user-visible noise variance (progress lists sometimes short,
    # sometimes very long). Extended pattern to `[0-9]+([,.][0-9]+)?%` matches BOTH
    # `27%` (integer) AND `27,4%` (fr_FR) AND `27.4%` (en_US).
    LC_ALL=C fwupdmgr refresh --force 2>&1 \
        | grep -vE ':[[:space:]]+[0-9]+([,.][0-9]+)?%[[:space:]]*$' \
        | sed 's/^/    /'
    fw_refresh_rc=${PIPESTATUS[0]}
    if [ "$fw_refresh_rc" -ne 0 ]; then
        echo -e "${RED}ERROR${NC}: fwupdmgr refresh failed (exit ${fw_refresh_rc}); firmware current state cannot be proven from cached metadata alone"
        ERRORS=$((ERRORS + 1))
    fi
    fw_rc=0
    fw_updates=$(LC_ALL=C fwupdmgr get-updates 2>&1) || fw_rc=$?
    if [[ ${fw_rc} -eq 2 ]]; then
        echo -e "${GREEN}OK${NC}: No firmware updates available"
    elif [[ ${fw_rc} -eq 0 ]]; then
        echo "${fw_updates}" | sed 's/^/    /'
        echo ""
        # PROMPT marker with description + PROMPT_DONE sentinel.
        # GUI _poll_markers handler raises an Adw.Banner ("Input required — answer
        # in the terminal log below.") + auto-expands log + sets cur_lbl to the
        # description. PROMPT_DONE hides the banner. Without the description +
        # banner the only cue was a dim-label change behind a collapsed log —
        # users missed it and assumed the spinner had hung.
        _emit_marker "PROMPT fwupd Install firmware updates"
        read -rp "Install firmware updates now? [y/N] " fw_answer
        _emit_marker "PROMPT_DONE"
        # regex accepts y/Y/yes/Yes/YES (matches the M05 +
        # M15 prompt-accept pattern). Previous `^[yY]$` matched only single-char.
        if [[ "${fw_answer}" =~ ^[yY]([eE][sS])?$ ]]; then
            LC_ALL=C fwupdmgr update --no-reboot-check 2>&1 | sed 's/^/    /'
            fw_update_rc=${PIPESTATUS[0]}
            if [ "$fw_update_rc" -eq 0 ]; then
                echo -e "${GREEN}OK${NC}: Firmware update command completed"
                # The documented command returns 0 when a deployed update is
                # pending reboot and 2 when no reboot is necessary. JSON mode
                # disables interactive reboot prompts; all other states are
                # completeness errors rather than an assumed "no".
                fw_reboot_rc=0
                LC_ALL=C fwupdmgr check-reboot-needed --json \
                    >/dev/null 2>&1 || fw_reboot_rc=$?
                case "$fw_reboot_rc" in
                    0) FWUPD_REBOOT=1 ;;
                    2) FWUPD_REBOOT=0 ;;
                    *)
                        echo -e "${RED}ERROR${NC}: fwupd reboot-state query failed (exit ${fw_reboot_rc})"
                        ERRORS=$((ERRORS + 1))
                        ;;
                esac
            else
                echo -e "${RED}ERROR${NC}: fwupdmgr update failed (exit ${fw_update_rc})"
                ERRORS=$((ERRORS + 1))
            fi
        else
            echo "    Skipped."
        fi
    else
        echo -e "${RED}ERROR${NC}: fwupdmgr get-updates exit ${fw_rc}"
        ERRORS=$((ERRORS + 1))
        echo "${fw_updates}" | sed 's/^/    /'
    fi
    settle_fwupd_daemon
fi

# [5] NoID Privacy Firefox Hardening automatic enrollment + re-apply
#
# NoID Privacy ships consolidated /usr/share/noid-firefox/user.js (via
# M16 install). update-all enrolls every safely registered new profile that has
# no user.js and is not explicitly excluded, then maintains every NoID Privacy-owned
# profile. This serves three purposes:
#   1. Safe automatic coverage for profiles created since installation
#   2. Defensive re-sync: if a managed profile's user.js got corrupted/edited,
#      re-install canonical version
#   3. Package-update compatibility: if a future signed NoID Privacy package owns the
#      canonical user.js, update-all will propagate it to existing profiles.
# Foreign/manual user.js files, unsafe/external profiles and explicit exclusion
# markers remain untouched until the user reviews and opts in.
#
# The hardening payload re-apply itself has no external fetch. The explicit
# executable-extension transactions later in this step use fixed GitHub/AMO
# channels with their separate identity, digest and signature gates.
#
# reset_stale_langpack <profile-dir>: Firefox's OS-package-manager update path
# can retain an incompatible langpack database record and fall back to English
# (Mozilla bugs 1724360/1995824 remain the upstream tracking boundary for this
# scenario). Reset only the generated registration/startup state so Firefox
# discovers the matching RPM-owned distribution langpack on next launch.
# Delete only profile-local XPI bytes proven stale; preserve other current
# language packs. Returns 0 if reset, 1 if nothing safely actionable is stale.
reset_stale_langpack() {
    local pdir ej ffver ffmaj stale stale_identity
    pdir="$1"
    ej="$pdir/extensions.json"
    [ -f "$ej" ] || return 1
    # rpm writes its "package ... is not installed" diagnostic to stdout.
    # Bind the value to a successful privileged query before deriving a major;
    # otherwise that diagnostic could be mistaken for a version and trigger a
    # destructive false stale-langpack reset.
    ffver=$(sudo rpm -q --qf '%{VERSION}\n' firefox 2>/dev/null) || return 1
    ffmaj=${ffver%%.*}
    [[ "$ffmaj" =~ ^[0-9]+$ ]] || return 1
    stale=$(python3 - "$ej" "$ffmaj" <<'LPVER_PY' 2>/dev/null
import json,re,sys
try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        d=json.load(fh)
    ff=sys.argv[2]
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    print(f"langpack state unreadable: {exc}", file=sys.stderr)
    raise SystemExit(1)
stale=[]
for a in d.get("addons",[]):
    if a.get("type")=="locale":
        v=str(a.get("version","")).split(".")[0]
        if v and v!=ff:
            identity=str(a.get("id",""))
            if not re.fullmatch(r"langpack-[A-Za-z0-9_-]+@firefox[.]mozilla[.]org", identity):
                raise SystemExit("unsafe stale langpack identity")
            stale.append(identity)
print("\n".join(sorted(set(stale))))
LPVER_PY
) || return 1
    [ -n "$stale" ] || return 1
    while IFS= read -r stale_identity; do
        [ -n "$stale_identity" ] || continue
        rm -f -- "$pdir/extensions/${stale_identity}.xpi"
    done <<<"$stale"
    rm -f -- "$pdir/addonStartup.json.lz4" "$pdir/extensions.json"
    [ -f "$pdir/prefs.js" ] \
        && sed -i '/extensions\.installedDistroAddon\.langpack-/d' "$pdir/prefs.js"
    return 0
}

# pgrep matches process-table entries by name without distinguishing a live
# task from a terminated child that its parent has not reaped yet. A zombie
# (State Z) and the transient dead states (X/x) cannot execute or retain
# browser profile files, so they must not defer reconciliation. Keep the check
# fail-closed for every other state and for an extant process whose status
# cannot be parsed. The caller supplies only fixed Firefox/Thunderbird names.
browser_process_active() {
    local process_name browser_pid status_file browser_state
    for process_name in "$@"; do
        while IFS= read -r browser_pid; do
            [[ "$browser_pid" =~ ^[0-9]+$ ]] || continue
            status_file="/proc/${browser_pid}/status"
            if [ ! -r "$status_file" ]; then
                [ -e "/proc/${browser_pid}" ] && return 0
                continue
            fi
            browser_state=$(awk '$1 == "State:" { print $2; exit }' \
                "$status_file" 2>/dev/null || true)
            case "$browser_state" in
                Z|X|x) continue ;;
                "") [ -e "/proc/${browser_pid}" ] || continue ;;
            esac
            return 0
        done < <(pgrep -u "$(id -u)" -x "$process_name" 2>/dev/null || true)
    done
    return 1
}

# Accept exactly one bounded machine-readable result from M35's updater-safe
# Thunderbird profile helper. Human diagnostics may surround it, but duplicate,
# malformed or impossible counts never become updater success.
parse_thunderbird_automatic_result() {
    local output=$1 result_count result eligible changed protected
    result_count=$(grep -cE \
        '^NOID_RESULT eligible=[0-9]{1,9} changed=[0-9]{1,9} protected=[0-9]{1,9}$' \
        <<< "$output" || true)
    [ "$result_count" -eq 1 ] || return 1
    result=$(grep -E \
        '^NOID_RESULT eligible=[0-9]{1,9} changed=[0-9]{1,9} protected=[0-9]{1,9}$' \
        <<< "$output")
    if [[ "$result" =~ ^NOID_RESULT[[:space:]]eligible=([0-9]{1,9})[[:space:]]changed=([0-9]{1,9})[[:space:]]protected=([0-9]{1,9})$ ]]; then
        eligible=${BASH_REMATCH[1]}
        changed=${BASH_REMATCH[2]}
        protected=${BASH_REMATCH[3]}
    else
        return 1
    fi
    [ "$changed" -le "$eligible" ] || return 1
    printf '%s %s %s\n' "$eligible" "$changed" "$protected"
}

echo ""
step "5" "NoID Privacy Firefox Hardening (re-apply to user profiles)"
if [[ -x /usr/local/sbin/noid-firefox-reassert ]]; then
    if sudo /usr/local/sbin/noid-firefox-reassert; then
        echo -e "${GREEN}OK${NC}: Firefox owned launcher/XDG overlays regenerated; RPM payload pristine"
    else
        echo -e "${RED}ERROR${NC}: Firefox owned-overlay regeneration failed; review the package update before launching Firefox"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "${RED}ERROR${NC}: /usr/local/sbin/noid-firefox-reassert missing (image integrity bug)"
    ERRORS=$((ERRORS + 1))
fi
if browser_process_active firefox firefox-bin; then
    echo -e "${YELLOW}WARN${NC}: Firefox is running — profile hardening deferred; close it and re-run to update executable extension bytes"
    WARNINGS=$((WARNINGS + 1))
    DEFERRED_LIST+=("Firefox profile hardening")
elif [[ ! -f /usr/share/noid-firefox/user.js ]]; then
    echo -e "${RED}ERROR${NC}: /usr/share/noid-firefox/user.js missing (image integrity bug)"
    ERRORS=$((ERRORS + 1))
elif ! acquire_firefox_profile_lock; then
    echo -e "${YELLOW}WARN${NC}: another Firefox profile operation is active — profile hardening deferred until it completes"
    WARNINGS=$((WARNINGS + 1))
    DEFERRED_LIST+=("Firefox profile hardening")
else
    # Re-apply must use apply_userjs() from the
    # shared helper, NOT a blind `install` of base user.js. apply_userjs
    # special-cases playground (base + /usr/share/noid-firefox/user-playground-
    # overrides.js) so playground-specific prefs (PB autostart, clear-on-
    # shutdown, sessionstore amnesia) are not destroyed by every weekly run.
    firefox_resynced=0
    langpack_reset=0
    for i in "${!FIREFOX_RECONCILE_NAMES[@]}"; do
        profile_name="${FIREFOX_RECONCILE_NAMES[$i]}"
        profile_path="${FIREFOX_RECONCILE_PROFILES[$i]}"
        echo "  -> Profile: ${profile_name}"
        if apply_userjs "${profile_name}" && \
           install_ubo_profile_local "${profile_name}" && \
           patch_ubo_pb_permission "${profile_name}" && \
           profile_hardening_complete "${profile_name}"; then
            firefox_resynced=$((firefox_resynced + 1))
        else
            echo -e "     ${RED}ERROR${NC}: complete Firefox profile re-apply failed for ${profile_name}"
            ERRORS=$((ERRORS + 1))
        fi
    done
    if [[ ${firefox_resynced} -gt 0 ]]; then
        echo -e "${GREEN}OK${NC}: NoID Privacy Firefox Hardening re-applied (${firefox_resynced} profile(s))"
    fi
    # The pre-update classification is not durable truth: a managed playground
    # profile may have entered this step incomplete and just converged above.
    # Refresh every list before extension updates and the final warning so a
    # successful repair participates immediately and stale warnings disappear.
    classify_firefox_profiles

    # Executable-extension updates are explicit-only. Resolve AMO's latest
    # compatible Mozilla-signed uBO XPI once, prove that it still
    # supports the complete root-managed filter-list policy, then converge
    # every already-hardened profile atomically under the profile-operation
    # lock. A same-version copy with different bytes is repaired to the
    # authenticated marketplace release; a compatible manually newer copy is
    # never downgraded.
    ubo_check_result=none
    if [[ ${#HARDENED_PROFILES[@]} -eq 0 ]]; then
        echo -e "${GREEN}OK${NC}: no hardened Firefox profiles carry the NoID Privacy-managed uBlock Origin payload"
    elif fetch_latest_xpi ubo; then
        ubo_updated=0
        # Every per-profile failure below is an ERRORS increment followed by
        # `continue`, so a run in which each profile failed validation would
        # otherwise leave ubo_updated at 0 and publish a reassuring "current"
        # check. Compare the error delta instead of the update counter, which
        # also covers error paths added later.
        ubo_errors_before=$ERRORS
        for i in "${!HARDENED_NAMES[@]}"; do
            profile_name=${HARDENED_NAMES[$i]}
            profile_path=${HARDENED_PROFILES[$i]}
            ubo_target="$profile_path/extensions/uBlock0@raymondhill.net.xpi"
            current_ubo_version=$("$WEBEXT_VALIDATOR" "$ubo_target" \
                uBlock0@raymondhill.net - 1 \
                "$LATEST_XPI_PRODUCT_VERSION" 2>/dev/null) || {
                echo -e "${RED}ERROR${NC}: ${profile_name} uBO payload fails identity/signature/compatibility validation"
                ERRORS=$((ERRORS + 1))
                continue
            }
            if ! "$FIREFOX_XPI_SIGNATURE_VERIFIER" "$ubo_target" \
                    uBlock0@raymondhill.net "$current_ubo_version"; then
                echo -e "${RED}ERROR${NC}: ${profile_name} uBO payload fails Firefox native signature verification"
                ERRORS=$((ERRORS + 1))
                continue
            fi
            current_ubo_policy_valid=0
            if "$UBO_POLICY_VALIDATOR" "$ubo_target" \
                    "$UBO_POLICY_SOURCE" >/dev/null; then
                current_ubo_policy_valid=1
            fi
            current_ubo_digest_matches=0
            if payload_matches "$ubo_target" "$LATEST_XPI_SHA256"; then
                current_ubo_digest_matches=1
            fi
            ubo_change=$(ubo_candidate_action "$LATEST_XPI_VERSION" \
                "$current_ubo_version" "$current_ubo_policy_valid" \
                "$current_ubo_digest_matches") || {
                echo -e "${RED}ERROR${NC}: ${profile_name} uBO convergence state is invalid"
                ERRORS=$((ERRORS + 1))
                continue
            }
            if [ "$ubo_change" = advance ] || [ "$ubo_change" = repair ]; then
                if noid_atomic_install_file "$LATEST_XPI_PATH" "$ubo_target" 644 \
                        && payload_matches "$ubo_target" "$LATEST_XPI_SHA256" \
                        && [ "$("$WEBEXT_VALIDATOR" "$ubo_target" \
                            uBlock0@raymondhill.net "$LATEST_XPI_VERSION" 1 \
                            "$LATEST_XPI_PRODUCT_VERSION" 2>/dev/null)" = "$LATEST_XPI_VERSION" ] \
                        && "$UBO_POLICY_VALIDATOR" "$ubo_target" \
                            "$UBO_POLICY_SOURCE" >/dev/null; then
                    if [ "$ubo_change" = advance ]; then
                        echo -e "${GREEN}UPDATED${NC}: uBlock Origin ${current_ubo_version} → ${LATEST_XPI_VERSION} (${profile_name}; restart Firefox to apply)"
                    else
                        echo -e "${GREEN}REPAIRED${NC}: uBlock Origin ${LATEST_XPI_VERSION} restored to the authenticated policy-compatible release (${profile_name}; restart Firefox to apply)"
                    fi
                    ubo_updated=$((ubo_updated + 1))
                    if ! record_extension_update firefox-ubo "$current_ubo_version" \
                            "$LATEST_XPI_VERSION" "$LATEST_XPI_SHA256"; then
                        echo -e "${RED}ERROR${NC}: uBlock Origin changed but SHA-256 evidence could not be recorded"
                        ERRORS=$((ERRORS + 1))
                    fi
                else
                    echo -e "${RED}ERROR${NC}: uBlock Origin ${current_ubo_version} → ${LATEST_XPI_VERSION} atomic convergence/postcondition failed"
                    ERRORS=$((ERRORS + 1))
                fi
            elif [ "$ubo_change" = reject ]; then
                echo -e "${RED}ERROR${NC}: uBlock Origin ${current_ubo_version} is newer than the authenticated stable release but does not support the managed filter-list policy (${profile_name}; no implicit downgrade)"
                ERRORS=$((ERRORS + 1))
            else
                echo -e "${GREEN}OK${NC}: uBlock Origin ${current_ubo_version} is current or newer (${profile_name}; no downgrade)"
            fi
        done
        [ "$ubo_updated" -eq 0 ] || echo -e "${GREEN}OK${NC}: uBlock Origin converged in ${ubo_updated} profile(s); SHA-256 evidence recorded"
        if [ "$ERRORS" -ne "$ubo_errors_before" ]; then
            ubo_check_result=failed
        elif [ "$ubo_updated" -gt 0 ]; then
            ubo_check_result=updated
        else
            ubo_check_result=current
        fi
    else
        if [ "${LATEST_XPI_ERROR_CLASS:-validation}" = availability ]; then
            echo -e "${YELLOW}WARN${NC}: current stable uBlock Origin check unavailable (${LATEST_XPI_ERROR:-retry later}); validated profile payloads left unchanged"
            WARNINGS=$((WARNINGS + 1))
            DEFERRED_LIST+=("uBlock-Origin-check")
        else
            echo -e "${RED}ERROR${NC}: current stable uBlock Origin release could not be authenticated (${LATEST_XPI_ERROR:-unknown validation failure}); profile payloads left untouched"
            ERRORS=$((ERRORS + 1))
        fi
        ubo_check_result=failed
    fi
    # `none` means no hardened profile carries the managed payload, so there was
    # nothing to check and no patch age to claim.
    [ "$ubo_check_result" = none ] \
        || record_extension_check firefox-ubo "$ubo_check_result" || true
    cleanup_latest_xpi

    # User-installed AMO extensions are allowed, while every browser-owned
    # background update path is disabled. Reconcile all registered profiles
    # here under the same Firefox operation lock; uBO and locale packs remain
    # with their dedicated paths above.
    update_marketplace_extensions firefox amo

    # Reset stale generated langpack state only after the same-run extension
    # inventory has consumed extensions.json. Firefox rebuilds that database
    # on its next launch, so deleting it earlier would silently exclude the
    # profile from marketplace reconciliation in this run.
    for i in "${!FIREFOX_RECONCILE_NAMES[@]}"; do
        profile_name="${FIREFOX_RECONCILE_NAMES[$i]}"
        profile_path="${FIREFOX_RECONCILE_PROFILES[$i]}"
        if reset_stale_langpack "$profile_path"; then
            echo -e "     ${GREEN}OK${NC}: stale langpack reset for ${profile_name} (re-installs matched version on next Firefox launch)"
            langpack_reset=$((langpack_reset + 1))
        fi
    done
    if [[ ${langpack_reset} -gt 0 ]]; then
        echo -e "${GREEN}OK${NC}: Firefox langpack re-synced after extension reconciliation (${langpack_reset} profile(s))"
    fi
fi

# Warn only about profiles that remain outside NoID Privacy hardening after
# automatic first application and managed-state repair. They still receive
# global AutoConfig defaults, but a foreign/manually modified user.js, an exact
# `--exclude` marker or invalid exclusion metadata prevented profile-local
# convergence without implicit overwrite.
if [[ ${#UNHARDENED_NAMES[@]} -gt 0 ]]; then
    echo -e "${YELLOW}NOTE${NC}: ${#UNHARDENED_NAMES[@]} protected/excluded Firefox profile(s) remain outside complete NoID Privacy hardening:"
    for un in "${UNHARDENED_NAMES[@]}"; do
        echo "    - ${un}"
    done
    echo "  → Review first; opt in per profile: noid-firefox-harden-profile <profile-name>"
    echo "  → A foreign user.js requires an explicit reviewed --force."
    echo "  → Invalid exclusion metadata must be inspected and removed before opt-in."
fi

# [5b] NoID Privacy Thunderbird Hardening (re-deploy system-wide files post dnf upgrade)
#
# Module 35 ships AutoConfig (mozilla.cfg +
# autoconfig.js + local-settings.js) at /usr/lib64/thunderbird/ + DKIM Verifier
# XPI at /usr/lib64/thunderbird/distribution/extensions/. These are unowned
# files inside the thunderbird package tree: plain `dnf upgrade thunderbird`
# keeps them in place, but reinstall/obsoletes/tree-restructure paths drop
# them silently. First-line recovery is noid-thunderbird-reassert (runs on
# every thunderbird transaction via its dnf5 action); this step is the
# orchestrated belt+suspenders pass and additionally owns the validated
# DKIM seed/durable version channel below.
#
# Migration step: also auto-cleanup a legacy Module-16b policies.json if
# present (detected by its EnableTrackingProtection lock). M35 ships only the
# audited minimal DuckDuckGo-only policy, which this step re-deploys below.
echo ""
step "5b" "NoID Privacy Thunderbird Hardening (re-deploy + 16b-Migration)"
TB_DKIM_SEED_VERSION="6.3.0"
TB_DKIM_SEED_SHA256="5ae95b4d560257b2e5722e1d3824a4031fb74d5d57b790dfc12f76a11dc1501a"
TB_DKIM_SEED="/usr/share/noid-thunderbird/dkim_verifier.xpi"
TB_DKIM_CURRENT="/var/lib/noid-privacy/managed-extensions/dkim_verifier@pl.xpi"
TB_DKIM_SOURCE=
TB_DKIM_SOURCE_VERSION=
TB_DKIM_SOURCE_SHA256=
TB_DKIM_CURRENT_VALID=0
if ! sudo rpm -q thunderbird >/dev/null 2>&1; then
    echo -e "${RED}ERROR${NC}: thunderbird is not installed (required NoID Privacy component)"
    ERRORS=$((ERRORS + 1))
elif browser_process_active thunderbird thunderbird-bin; then
    echo -e "${YELLOW}WARN${NC}: Thunderbird is running — profile hardening deferred; close it and re-run to replace executable extension bytes"
    WARNINGS=$((WARNINGS + 1))
    DEFERRED_LIST+=("Thunderbird profile hardening")
elif ! payload_matches "$TB_DKIM_SEED" "$TB_DKIM_SEED_SHA256"; then
    echo -e "${RED}ERROR${NC}: canonical Thunderbird DKIM XPI is missing, symlinked or differs from the reviewed SHA-256"
    ERRORS=$((ERRORS + 1))
else
    tb_actions=0
    tb_errors_before=$ERRORS
    TB_VERSION=$(sudo rpm -q --qf '%{VERSION}\n' thunderbird 2>/dev/null) || TB_VERSION=
    if [ -z "$TB_VERSION" ] || \
       [ "$("$WEBEXT_VALIDATOR" "$TB_DKIM_SEED" dkim_verifier@pl \
           "$TB_DKIM_SEED_VERSION" 0 "$TB_VERSION" 2>/dev/null || true)" \
           != "$TB_DKIM_SEED_VERSION" ]; then
        echo -e "${RED}ERROR${NC}: reviewed DKIM seed fails structure/identity/Thunderbird-compatibility validation"
        ERRORS=$((ERRORS + 1))
    else
        TB_DKIM_SOURCE=$TB_DKIM_SEED
        TB_DKIM_SOURCE_VERSION=$TB_DKIM_SEED_VERSION
        TB_DKIM_SOURCE_SHA256=$TB_DKIM_SEED_SHA256
    fi
    if [ -e "$TB_DKIM_CURRENT" ] || [ -L "$TB_DKIM_CURRENT" ]; then
        current_dkim_version=$("$WEBEXT_VALIDATOR" "$TB_DKIM_CURRENT" \
            dkim_verifier@pl - 0 "$TB_VERSION" 2>/dev/null) || current_dkim_version=
        current_dkim_sha=$(sha256sum "$TB_DKIM_CURRENT" 2>/dev/null | awk '{print $1}')
        if [ -z "$current_dkim_version" ] \
                || ! [[ "$current_dkim_sha" =~ ^[0-9a-f]{64}$ ]] \
                || [ "$(stat -c '%U:%G:%a' "$TB_DKIM_CURRENT" 2>/dev/null || true)" != root:root:644 ]; then
            echo -e "${YELLOW}NOTE${NC}: durable DKIM current payload is invalid; the authenticated channel will repair it"
        elif numeric_version_is_newer "$TB_DKIM_SEED_VERSION" "$current_dkim_version"; then
            echo -e "${YELLOW}NOTE${NC}: durable DKIM current payload ${current_dkim_version} is older than seed ${TB_DKIM_SEED_VERSION}; the authenticated channel will repair it without downgrade"
        else
            TB_DKIM_CURRENT_VALID=1
            TB_DKIM_SOURCE=$TB_DKIM_CURRENT
            TB_DKIM_SOURCE_VERSION=$current_dkim_version
            TB_DKIM_SOURCE_SHA256=$current_dkim_sha
        fi
    fi

    if [[ -x /usr/local/sbin/noid-thunderbird-reassert ]]; then
        if sudo /usr/local/sbin/noid-thunderbird-reassert; then
            echo -e "${GREEN}OK${NC}: Thunderbird owned launcher/XDG overlays regenerated; RPM payload pristine"
        else
            echo -e "${RED}ERROR${NC}: Thunderbird owned-overlay regeneration failed; review the package update before launching Thunderbird"
            ERRORS=$((ERRORS + 1))
        fi
    else
        echo -e "${RED}ERROR${NC}: /usr/local/sbin/noid-thunderbird-reassert missing (image integrity bug)"
        ERRORS=$((ERRORS + 1))
    fi

    # Initialize safe registered profiles whose user.js is absent and refresh
    # profiles carrying M35's active NoID Privacy ownership marker. The helper reads
    # the reviewed local /usr/share/noid-thunderbird/user.js derivative; this
    # path never fetches or applies HorlogeSkynet upstream bytes. Foreign,
    # external and explicitly opted-out profiles remain untouched.
    if [[ -x /usr/local/bin/noid-thunderbird-harden-profile ]]; then
        tb_profile_output=
        if tb_profile_output=$(
            /usr/local/bin/noid-thunderbird-harden-profile --automatic 2>&1
        ); then
            if tb_profile_counts=$(
                parse_thunderbird_automatic_result "$tb_profile_output"
            ); then
                read -r tb_eligible_profiles tb_changed_profiles \
                    tb_protected_profiles \
                    <<< "$tb_profile_counts"
                tb_actions=$((tb_actions + tb_changed_profiles))
                echo -e "${GREEN}OK${NC}: Thunderbird automatic profile hardening reconciled (${tb_changed_profiles}/${tb_eligible_profiles} eligible changed; ${tb_protected_profiles} protected)"
            else
                echo -e "${RED}ERROR${NC}: Thunderbird profile helper returned an invalid automatic-result contract"
                ERRORS=$((ERRORS + 1))
            fi
        else
            echo -e "${RED}ERROR${NC}: Thunderbird automatic profile hardening failed; only safe new or marker-owned profiles were eligible"
            ERRORS=$((ERRORS + 1))
        fi
    else
        echo -e "${RED}ERROR${NC}: /usr/local/bin/noid-thunderbird-harden-profile missing (image integrity bug)"
        ERRORS=$((ERRORS + 1))
    fi

    # Migration: cleanup deprecated Module 16b artefacts (idempotent)
    if [[ -f /etc/thunderbird/policies/policies.json ]]; then
        if grep -q 'EnableTrackingProtection.*Locked' /etc/thunderbird/policies/policies.json 2>/dev/null; then
            echo "  -> Migrating away from deprecated Module 16b policies.json"
            sudo rm -f /etc/thunderbird/policies/policies.json
            sudo rmdir --ignore-fail-on-non-empty /etc/thunderbird/policies/ 2>/dev/null || true
            sudo rmdir --ignore-fail-on-non-empty /etc/thunderbird/ 2>/dev/null || true
            tb_actions=$((tb_actions + 1))
        fi
    fi

    # The reassert helper above already atomically owns all five files inside
    # the Thunderbird package tree. Publish only the two independent /etc
    # consumers here, through a fixed-pair root transaction with safe-parent,
    # metadata and byte-for-byte postconditions.
    for src_dst in \
        "/usr/share/noid-thunderbird/noid-locale.js::/etc/thunderbird/pref/noid-locale.js" \
        "/usr/share/noid-thunderbird/policies.json::/etc/thunderbird/policies/policies.json"; do
        src="${src_dst%::*}"
        dst="${src_dst#*::}"
        if ! trusted_root_file "$src" 644; then
            echo -e "${RED}ERROR${NC}: canonical Thunderbird source metadata is unsafe: ${src}"
            ERRORS=$((ERRORS + 1))
        elif ! trusted_root_file "$dst" 644 || ! cmp -s "$src" "$dst"; then
            if publish_managed_thunderbird_config "$src" "$dst"; then
                tb_actions=$((tb_actions + 1))
            else
                echo -e "${RED}ERROR${NC}: Thunderbird atomic config publication failed exact postcondition: ${dst}"
                ERRORS=$((ERRORS + 1))
            fi
        fi
    done

    # Re-deploy DKIM Verifier XPI (Layer 4)
    DKIM_DST="/usr/lib64/thunderbird/distribution/extensions/dkim_verifier@pl.xpi"
    if [ -n "$TB_DKIM_SOURCE" ] && \
       { ! payload_matches "$DKIM_DST" "$TB_DKIM_SOURCE_SHA256"; }; then
        dkim_redeploy_work=$(mktemp -d /var/tmp/noid-xpi-update.XXXXXX) || dkim_redeploy_work=
        if [ -n "$dkim_redeploy_work" ]; then
            chmod 0700 "$dkim_redeploy_work"
            cp -- "$TB_DKIM_SOURCE" "$dkim_redeploy_work/payload.xpi" 2>/dev/null || true
            chmod 0600 "$dkim_redeploy_work/payload.xpi" 2>/dev/null || true
        fi
        if [ -n "$dkim_redeploy_work" ] \
                && payload_matches "$dkim_redeploy_work/payload.xpi" "$TB_DKIM_SOURCE_SHA256" \
                && publish_managed_dkim_xpi "$dkim_redeploy_work/payload.xpi" \
                    "$DKIM_DST" "$TB_DKIM_SOURCE_SHA256" "$TB_DKIM_SOURCE_VERSION"; then
            tb_actions=$((tb_actions + 1))
        else
            echo -e "${RED}ERROR${NC}: Thunderbird DKIM XPI redeploy failed atomic SHA-256 postcondition"
            ERRORS=$((ERRORS + 1))
        fi
        [ -z "$dkim_redeploy_work" ] || rm -rf --one-file-system -- "$dkim_redeploy_work"
    fi
    if [ -z "$TB_DKIM_SOURCE" ] || \
       ! payload_matches "$DKIM_DST" "$TB_DKIM_SOURCE_SHA256" || \
       [ "$("$WEBEXT_VALIDATOR" "$DKIM_DST" dkim_verifier@pl \
           "$TB_DKIM_SOURCE_VERSION" 0 "$TB_VERSION" 2>/dev/null || true)" \
           != "$TB_DKIM_SOURCE_VERSION" ]; then
        echo -e "${RED}ERROR${NC}: installed Thunderbird DKIM XPI differs from the validated current source"
        ERRORS=$((ERRORS + 1))
    fi

    # Validate the complete policy rather than looking for one historic bad
    # key. This catches deletion and any unexpected policy-scope expansion.
    if ! python3 -c '
import json, sys
path = "/etc/thunderbird/policies/policies.json"
expected = {"policies": {
    "SearchEngines": {"Default": "DuckDuckGo"},
}}
try:
    actual = json.load(open(path))
except (OSError, ValueError):
    sys.exit(1)
sys.exit(0 if actual == expected else 1)
'; then
        echo -e "${RED}ERROR${NC}: Thunderbird policy is missing or differs from the audited DuckDuckGo-only policy"
        ERRORS=$((ERRORS + 1))
    fi

    # Advance the durable current slot and active distribution copy only from
    # ATN's official compatible stable channel. The immutable image seed in
    # /usr/share remains unchanged for recovery and reproducible build evidence.
    if [ -n "$TB_DKIM_SOURCE" ]; then
        dkim_check_result=none
        if fetch_latest_xpi dkim; then
            if numeric_version_is_newer "$LATEST_XPI_VERSION" "$TB_DKIM_SOURCE_VERSION" \
                    || { [ "$TB_DKIM_CURRENT_VALID" -eq 0 ] \
                        && ! numeric_version_is_newer "$TB_DKIM_SOURCE_VERSION" \
                            "$LATEST_XPI_VERSION"; }; then
                if publish_managed_dkim_xpi "$LATEST_XPI_PATH" "$TB_DKIM_CURRENT" \
                        "$LATEST_XPI_SHA256" "$LATEST_XPI_VERSION" \
                        && publish_managed_dkim_xpi "$LATEST_XPI_PATH" "$DKIM_DST" \
                            "$LATEST_XPI_SHA256" "$LATEST_XPI_VERSION" \
                        && payload_matches "$TB_DKIM_CURRENT" "$LATEST_XPI_SHA256" \
                        && payload_matches "$DKIM_DST" "$LATEST_XPI_SHA256" \
                        && [ "$("$WEBEXT_VALIDATOR" "$TB_DKIM_CURRENT" \
                            dkim_verifier@pl "$LATEST_XPI_VERSION" 0 \
                            "$LATEST_XPI_PRODUCT_VERSION" 2>/dev/null)" = "$LATEST_XPI_VERSION" ] \
                        && [ "$("$WEBEXT_VALIDATOR" "$DKIM_DST" \
                            dkim_verifier@pl "$LATEST_XPI_VERSION" 0 \
                            "$LATEST_XPI_PRODUCT_VERSION" 2>/dev/null)" = "$LATEST_XPI_VERSION" ]; then
                    if numeric_version_is_newer "$LATEST_XPI_VERSION" "$TB_DKIM_SOURCE_VERSION"; then
                        echo -e "${GREEN}UPDATED${NC}: DKIM Verifier ${TB_DKIM_SOURCE_VERSION} → ${LATEST_XPI_VERSION} (restart Thunderbird to apply)"
                    else
                        echo -e "${GREEN}REPAIRED${NC}: durable DKIM current slot restored at ${LATEST_XPI_VERSION} (restart Thunderbird to apply)"
                    fi
                    tb_actions=$((tb_actions + 1))
                    dkim_check_result=updated
                    if ! record_extension_update thunderbird-dkim \
                            "$TB_DKIM_SOURCE_VERSION" "$LATEST_XPI_VERSION" \
                            "$LATEST_XPI_SHA256"; then
                        echo -e "${RED}ERROR${NC}: DKIM Verifier updated but SHA-256 evidence could not be recorded"
                        ERRORS=$((ERRORS + 1))
                    fi
                else
                    echo -e "${RED}ERROR${NC}: DKIM Verifier ${TB_DKIM_SOURCE_VERSION} → ${LATEST_XPI_VERSION} atomic publication/postcondition failed"
                    ERRORS=$((ERRORS + 1))
                    dkim_check_result=failed
                fi
            elif [ "$TB_DKIM_CURRENT_VALID" -eq 0 ]; then
                echo -e "${RED}ERROR${NC}: authenticated DKIM channel ${LATEST_XPI_VERSION} is older than reviewed seed ${TB_DKIM_SOURCE_VERSION}; invalid current slot left untouched (no downgrade)"
                ERRORS=$((ERRORS + 1))
                dkim_check_result=failed
            else
                echo -e "${GREEN}OK${NC}: DKIM Verifier ${TB_DKIM_SOURCE_VERSION} is current or newer (no downgrade)"
                dkim_check_result=current
            fi
        else
            if [ "${LATEST_XPI_ERROR_CLASS:-validation}" = availability ]; then
                echo -e "${YELLOW}WARN${NC}: current stable DKIM Verifier check unavailable (${LATEST_XPI_ERROR:-retry later}); validated installed payload left unchanged"
                WARNINGS=$((WARNINGS + 1))
                DEFERRED_LIST+=("DKIM-Verifier-check")
            else
                echo -e "${RED}ERROR${NC}: current stable DKIM Verifier release could not be authenticated (${LATEST_XPI_ERROR:-unknown validation failure}); installed payload left untouched"
                ERRORS=$((ERRORS + 1))
            fi
            dkim_check_result=failed
        fi
        # `none` cannot occur here — every branch above assigns — but the guard
        # keeps a future branch from publishing an unmeasured patch age.
        [ "$dkim_check_result" = none ] \
            || record_extension_check thunderbird-dkim "$dkim_check_result" || true
        cleanup_latest_xpi
    fi

    # All additional profile-owned ATN extensions use the same explicit-only
    # update transaction. DKIM Verifier stays on its dedicated managed
    # distribution-level publication path above.
    update_marketplace_extensions thunderbird atn

    if [[ $ERRORS -ne $tb_errors_before ]]; then
        echo -e "${RED}ERROR${NC}: Thunderbird hardening is not in the complete reviewed state"
    elif [[ ${tb_actions} -gt 0 ]]; then
        echo -e "${GREEN}OK${NC}: Thunderbird hardening re-applied (${tb_actions} action(s))"
    else
        echo -e "${GREEN}OK${NC}: Thunderbird hardening already in sync"
    fi
fi

# [6] NoID Privacy-managed AI coding agents (opt-in, consent-gated updates)
#
# The opt-in installers in M13 authenticate exact reviewed artifacts at
# install time; accepting a component there is also the standing consent for
# vendor-channel refreshes. Update All acquires no agent payload itself: it
# invokes each helper's --update mode, which refreshes only components of its
# own product that are actually present — the CLI only when it resolves to
# the NoID Privacy-managed install (foreign CLI installs are left alone), and
# the editor extension when VSCodium has it installed. Every applied update
# validates identity and archive structure before activation and appends
# version + SHA-256 evidence to
# ~/.local/state/noid-privacy/agent-updates.log. Accounts with no component
# present are skipped untouched.
echo ""
step "6" "AI coding agents (opt-in consent-gated update)"
for agent_entry in \
    "/usr/local/bin/noid-claude-install:Claude-Code" \
    "/usr/local/bin/noid-codex-install:OpenAI-Codex"; do
    agent_helper=${agent_entry%%:*}
    agent_label=${agent_entry#*:}
    if [ ! -x "$agent_helper" ]; then
        echo -e "${RED}ERROR${NC}: $agent_label opt-in helper missing: $agent_helper"
        ERRORS=$((ERRORS + 1))
        continue
    fi
    agent_rc=0
    "$agent_helper" --update 2>&1 | sed 's/^/  /' || agent_rc=$?
    case "$agent_rc" in
        0) echo -e "${GREEN}OK${NC}: $agent_label opted-in components current (evidence recorded on change)" ;;
        3)
            echo -e "${YELLOW}SKIP${NC}: $agent_label not opted in on this account"
            SKIPPED_LIST+=("$agent_label")
            ;;
        *)
            echo -e "${RED}ERROR${NC}: $agent_label update incomplete (rc=$agent_rc); successful component changes remain applied and recorded"
            ERRORS=$((ERRORS + 1))
            ;;
    esac
done

# [6b] GNOME Shell extensions: transactional, explicit EGO updates.
#
# M17's exact Just-Perfection pin remains the reproducible first-install seed.
# Update All also advances that managed extension from its fixed EGO identity;
# this is the owner-selected exception to immutable runtime pins. EGO provides
# no artifact signature, so the deliberate trust boundary is HTTPS plus exact
# UUID/version/GNOME compatibility, archive safety, no-downgrade, atomic
# publication and local SHA-256 evidence. RPM-owned extensions update through
# DNF (Step 2). Other system-wide non-RPM extensions use the same transaction.
# The archive
# is downloaded and parsed unprivileged, path/type/size/identity checked,
# compiled unprivileged, copied to a root-owned sibling staging directory and
# atomically exchanged only after every postcondition succeeds. Egress is
# HTTPS-only; user-domain extensions in ~/.local/share/gnome-shell/extensions
# are deliberately left untouched.
echo ""
step "6b" "GNOME Shell Extensions (explicit EGO update)"
JP_UUID="just-perfection-desktop@just-perfection"
JP_SEED_VERSION="36"
JP_SEED_SHA256="4aef633af6345755d8982f14821d1c276b539faa10c2eddc596a27359ebe3281"
JP_PATH="/usr/share/gnome-shell/extensions/$JP_UUID"
JP_CACHE="/var/lib/noid-privacy/cache/just-perfection-v$JP_SEED_VERSION.shell-extension.zip"
if ! command -v gnome-shell >/dev/null 2>&1; then
    echo -e "${RED}ERROR${NC}: gnome-shell is not installed (required NoID Privacy component)"
    ERRORS=$((ERRORS + 1))
elif ! command -v jq >/dev/null 2>&1; then
    echo -e "${RED}ERROR${NC}: jq missing; cannot verify the managed GNOME extension"
    ERRORS=$((ERRORS + 1))
else
    if ! payload_matches "$JP_CACHE" "$JP_SEED_SHA256"; then
        echo -e "${RED}ERROR${NC}: cached Just-Perfection image seed differs from the reviewed SHA-256"
        ERRORS=$((ERRORS + 1))
    fi
    if [ ! -f "$JP_PATH/metadata.json" ] || [ -L "$JP_PATH" ] || \
            [ -L "$JP_PATH/metadata.json" ]; then
        echo -e "${RED}ERROR${NC}: managed Just-Perfection extension is missing or symlinked"
        ERRORS=$((ERRORS + 1))
    fi

    # Running GNOME major drives the EGO shell_version_map lookup below.
    GNOME_MAJOR=$(gnome-shell --version 2>/dev/null | awk '{print $NF}' | cut -d. -f1)
    for ext_path in /usr/share/gnome-shell/extensions/*; do
        [ -d "$ext_path" ] || continue
        ext_base=$(basename "$ext_path")
        if [ -L "$ext_path" ]; then
            echo -e "${RED}ERROR${NC}: ${ext_base} — symlinked extension root cannot be safely updated"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        # RPM-owned extensions update through DNF; never overwrite RPM-owned
        # files (would break rpm -V + SELinux contexts + the next dnf upgrade).
        if sudo rpm -qf "$ext_path" >/dev/null 2>&1; then
            echo -e "${GREEN}OK${NC}: ${ext_base} is RPM-managed (updated via DNF)"
            continue
        fi
        # Unmanaged non-RPM system extension → EGO update for the running GNOME
        # major. Identity must match the installed directory before its value is
        # used in an API request or privileged target transaction.
        if ! command -v curl >/dev/null 2>&1 \
                || ! command -v python3 >/dev/null 2>&1; then
            echo -e "${RED}ERROR${NC}: ${ext_base} — curl/python3 missing; explicit EGO update cannot run"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        if [ ! -f "$ext_path/metadata.json" ] || [ -L "$ext_path/metadata.json" ]; then
            echo -e "${RED}ERROR${NC}: ${ext_base} — metadata.json missing or symlinked; update state is unprovable"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        ego_uuid=$(jq -r '.uuid // empty' "$ext_path/metadata.json" 2>/dev/null)
        ego_installed=$(jq -r '.version // empty | tostring' "$ext_path/metadata.json" 2>/dev/null)
        if [[ "$ego_uuid" != "$ext_base" \
              || ! "$ego_uuid" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*@[A-Za-z0-9][A-Za-z0-9._+-]*$ ]]; then
            echo -e "${RED}ERROR${NC}: ${ext_base} — metadata UUID/path identity invalid; update state is unprovable"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        if ! [[ "$GNOME_MAJOR" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}ERROR${NC}: ${ext_base} — GNOME major undetected; compatible EGO update cannot be selected"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        if ! [[ "$ego_installed" =~ ^[1-9][0-9]{0,8}$ ]]; then
            echo -e "${RED}ERROR${NC}: ${ext_base} v${ego_installed:-none} — installed version is not safely orderable"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        ego_info_rc=0
        ego_info=$(curl -fsS --proto '=https' --tlsv1.2 --max-time 15 \
            --max-filesize 1048576 --get \
            --data-urlencode "uuid=${ego_uuid}" \
            'https://extensions.gnome.org/extension-info/' 2>/dev/null) \
            || ego_info_rc=$?
        if [ "$ego_info_rc" -ne 0 ]; then
            echo -e "${YELLOW}WARN${NC}: ${ego_uuid} v${ego_installed} — EGO update check unavailable; installed extension left unchanged (retry later)"
            WARNINGS=$((WARNINGS + 1))
            DEFERRED_LIST+=("GNOME-extension-check")
            continue
        fi
        if [ -z "$ego_info" ]; then
            echo -e "${RED}ERROR${NC}: ${ego_uuid} — EGO returned an empty successful response"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        ego_api_uuid=$(printf '%s' "$ego_info" | jq -r '.uuid // empty' 2>/dev/null)
        ego_available=$(printf '%s' "$ego_info" | jq -r --arg shell "$GNOME_MAJOR" \
            '.shell_version_map[$shell].version // empty | tostring' 2>/dev/null)
        if [ "$ego_api_uuid" != "$ego_uuid" ]; then
            echo -e "${RED}ERROR${NC}: ${ego_uuid} — EGO response identity mismatch"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        if ! [[ "$ego_available" =~ ^[1-9][0-9]{0,8}$ ]]; then
            echo -e "${RED}ERROR${NC}: ${ego_uuid} v${ego_installed} — no GNOME ${GNOME_MAJOR} build on EGO"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        if [ "$ego_available" -le "$ego_installed" ]; then
            echo -e "${GREEN}OK${NC}: ${ego_uuid} v${ego_installed} (latest for GNOME ${GNOME_MAJOR})"
            continue
        fi
        ego_work=$(mktemp -d /var/tmp/noid-ego-extension.XXXXXX) || {
            echo -e "${RED}ERROR${NC}: ${ego_uuid} — private staging failed"; ERRORS=$((ERRORS + 1)); continue; }
        chmod 0700 "$ego_work"
        ego_zip="$ego_work/extension.zip"
        ego_stage="$ego_work/staged"
        ego_download_rc=0
        curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 \
                --max-redirs 3 --max-time 60 --max-filesize 67108864 --get \
                --data-urlencode "shell_version=${GNOME_MAJOR}" \
                --data-urlencode "extension_version=${ego_available}" \
                -o "$ego_zip" \
                "https://extensions.gnome.org/download-extension/${ego_uuid}.shell-extension.zip" \
                2>/dev/null || ego_download_rc=$?
        if [ "$ego_download_rc" -ne 0 ]; then
            echo -e "${YELLOW}WARN${NC}: ${ego_uuid} v${ego_installed} → v${ego_available} download unavailable; installed extension left unchanged (retry later)"
            WARNINGS=$((WARNINGS + 1))
            DEFERRED_LIST+=("GNOME-extension-download")
            rm -rf --one-file-system -- "$ego_work"
            continue
        fi
        if [ ! -f "$ego_zip" ] || [ -L "$ego_zip" ] \
             || [ "$(stat -c %s "$ego_zip" 2>/dev/null || echo 0)" -le 0 ] \
             || [ "$(stat -c %s "$ego_zip" 2>/dev/null || echo 0)" -gt 67108864 ]; then
            echo -e "${RED}ERROR${NC}: ${ego_uuid} v${ego_available} downloaded artifact is missing or outside policy"
            ERRORS=$((ERRORS + 1))
            rm -rf --one-file-system -- "$ego_work"
            continue
        fi
        ego_tree_sha=
        if ! ego_tree_sha=$(python3 - "$ego_zip" "$ego_stage" "$ego_uuid" \
                "$ego_available" "$GNOME_MAJOR" <<'EGO_VALIDATE_PY'
import hashlib
import json
import os
from pathlib import PurePosixPath
import shutil
import stat
import subprocess
import sys
import zipfile

archive, output, expected_uuid, expected_version, shell_major = sys.argv[1:]
max_entries = 4096
max_file = 64 * 1024 * 1024
max_total = 256 * 1024 * 1024

def reject(message):
    raise ValueError(message)

with zipfile.ZipFile(archive) as bundle:
    entries = bundle.infolist()
    if not entries or len(entries) > max_entries:
        reject("entry count outside policy")
    seen = set()
    total = 0
    normalized = []
    for entry in entries:
        name = entry.filename
        if not name or len(name.encode("utf-8")) > 4096:
            reject("invalid entry name")
        if name.startswith("/") or "\\" in name:
            reject("non-relative POSIX entry")
        parts = PurePosixPath(name).parts
        if not parts or any(part in ("", ".", "..") for part in parts):
            reject("unsafe entry component")
        path = "/".join(parts)
        if path in seen:
            reject("duplicate entry")
        seen.add(path)
        if entry.flag_bits & 1:
            reject("encrypted entry")
        mode = (entry.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(mode)
        if entry.is_dir():
            if file_type not in (0, stat.S_IFDIR):
                reject("directory/type mismatch")
        else:
            if file_type not in (0, stat.S_IFREG):
                reject("non-regular entry")
            if entry.file_size < 0 or entry.file_size > max_file:
                reject("entry size outside policy")
            total += entry.file_size
            if total > max_total:
                reject("expanded bundle outside policy")
        normalized.append((entry, parts))
    if bundle.testzip() is not None:
        reject("bundle CRC failure")
    try:
        metadata_raw = bundle.read("metadata.json")
        if len(metadata_raw) > 1024 * 1024:
            reject("metadata too large")
        metadata = json.loads(metadata_raw.decode("utf-8"))
    except (KeyError, UnicodeError, json.JSONDecodeError) as exc:
        reject(f"metadata unreadable: {exc}")
    if metadata.get("uuid") != expected_uuid:
        reject("UUID mismatch")
    if str(metadata.get("version", "")) != expected_version:
        reject("version mismatch")
    shells = metadata.get("shell-version")
    if not isinstance(shells, list) or shell_major not in {str(v) for v in shells}:
        reject("GNOME compatibility mismatch")
    os.mkdir(output, 0o700)
    for entry, parts in normalized:
        destination = os.path.join(output, *parts)
        if entry.is_dir():
            os.makedirs(destination, mode=0o700, exist_ok=True)
            continue
        os.makedirs(os.path.dirname(destination), mode=0o700, exist_ok=True)
        with bundle.open(entry) as source, open(destination, "xb") as target:
            shutil.copyfileobj(source, target, length=1024 * 1024)
        os.chmod(destination, 0o600)

schemas = os.path.join(output, "schemas")
if os.path.isdir(schemas):
    subprocess.run(
        ["/usr/bin/glib-compile-schemas", "--strict", schemas],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def tree_digest(root):
    records = []
    entry_count = 0
    expanded = 0
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        filenames.sort()
        for name in dirnames:
            path = os.path.join(current, name)
            mode = os.lstat(path).st_mode
            if not stat.S_ISDIR(mode):
                reject("post-extraction non-directory")
            relative = os.path.relpath(path, root).replace(os.sep, "/")
            records.append(("D", relative, 0, ""))
            entry_count += 1
        for name in filenames:
            path = os.path.join(current, name)
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode):
                reject("post-extraction non-regular file")
            relative = os.path.relpath(path, root).replace(os.sep, "/")
            file_hash = hashlib.sha256()
            with open(path, "rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    file_hash.update(chunk)
            records.append(("F", relative, info.st_size, file_hash.hexdigest()))
            entry_count += 1
            expanded += info.st_size
    if entry_count < 1 or entry_count > max_entries + 1 or expanded > max_total + max_file:
        reject("final tree outside policy")
    result = hashlib.sha256()
    for kind, relative, size, file_hash in sorted(records):
        for value in (kind, relative, str(size), file_hash):
            encoded = value.encode("utf-8")
            result.update(len(encoded).to_bytes(8, "big"))
            result.update(encoded)
    return result.hexdigest()

print(tree_digest(output))
EGO_VALIDATE_PY
        ); then
            echo -e "${RED}ERROR${NC}: ${ego_uuid} v${ego_available} archive structure/identity invalid"
            ERRORS=$((ERRORS + 1))
            rm -rf --one-file-system -- "$ego_work"
            continue
        fi
        if ! [[ "$ego_tree_sha" =~ ^[0-9a-f]{64}$ ]]; then
            echo -e "${RED}ERROR${NC}: ${ego_uuid} v${ego_available} validated tree identity is malformed"
            ERRORS=$((ERRORS + 1))
            rm -rf --one-file-system -- "$ego_work"
            continue
        fi
        echo "  → ${ego_uuid} v${ego_installed} → v${ego_available} ($(stat -c %s "$ego_zip") bytes, sha256=$(sha256sum "$ego_zip" | cut -c1-16)…)"
        if sudo /usr/bin/bash -s -- "$ego_stage" "$ext_path" \
                "$ego_uuid" "$ego_available" "$ego_tree_sha" <<'EGO_PUBLISH_EOF'
set -euo pipefail
PATH=/usr/sbin:/usr/bin
source_dir=$1
target_dir=$2
expected_uuid=$3
expected_version=$4
expected_tree_sha=$5
parent=${target_dir%/*}
base=${target_dir##*/}
candidate=

cleanup() {
    if [ -n "${candidate:-}" ] && [ -d "$candidate" ] && [ ! -L "$candidate" ]; then
        rm -rf --one-file-system -- "$candidate"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

case "$target_dir" in
    /usr/share/gnome-shell/extensions/*) ;;
    *) exit 2 ;;
esac
[ "$parent" = /usr/share/gnome-shell/extensions ] \
    && [ -d "$parent" ] && [ ! -L "$parent" ] \
    && [ "$(stat -c '%u:%g:%a' "$parent" 2>/dev/null || true)" = 0:0:755 ] \
    || exit 2
[ "${SUDO_UID:-0}" -gt 0 ] 2>/dev/null \
    && case "$source_dir" in /var/tmp/noid-ego-extension.*/staged) true ;; *) false ;; esac \
    && [ "$(stat -c '%u:%a' "$source_dir" 2>/dev/null || true)" = "${SUDO_UID}:700" ] \
    || exit 2
[ "$base" = "$expected_uuid" ] \
    && [[ "$expected_uuid" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*@[A-Za-z0-9][A-Za-z0-9._+-]*$ ]] \
    && [[ "$expected_version" =~ ^[1-9][0-9]*$ ]] \
    && [[ "$expected_tree_sha" =~ ^[0-9a-f]{64}$ ]] \
    && [ -d "$source_dir" ] && [ ! -L "$source_dir" ] \
    && [ -d "$target_dir" ] && [ ! -L "$target_dir" ] \
    && [ "$(stat -c '%u:%g:%a' "$target_dir" 2>/dev/null || true)" = 0:0:755 ] \
    || exit 2

# The parent is root-owned; remove only exact root-owned leftovers from an
# interrupted prior transaction for this same UUID.
shopt -s nullglob
for stale in "$parent/.${base}.noid-new."*; do
    [ -d "$stale" ] && [ ! -L "$stale" ] \
        && [ "$(stat -c '%U:%G' "$stale" 2>/dev/null || true)" = root:root ] \
        && rm -rf --one-file-system -- "$stale"
done
candidate=$(mktemp -d "$parent/.${base}.noid-new.XXXXXX")
cp -R --no-preserve=all -- "$source_dir/." "$candidate/"
if find -P "$candidate" -xdev -mindepth 1 \
        \( -type l -o \( ! -type d ! -type f \) \) -print -quit | grep -q .; then
    exit 2
fi
actual_tree_sha=$(python3 - "$candidate" <<'EGO_TREE_DIGEST_PY'
import hashlib
import os
import stat
import sys

root = sys.argv[1]
records = []
entry_count = 0
expanded = 0
for current, dirnames, filenames in os.walk(root, followlinks=False):
    dirnames.sort()
    filenames.sort()
    for name in dirnames:
        path = os.path.join(current, name)
        mode = os.lstat(path).st_mode
        if not stat.S_ISDIR(mode):
            raise SystemExit(1)
        relative = os.path.relpath(path, root).replace(os.sep, "/")
        records.append(("D", relative, 0, ""))
        entry_count += 1
    for name in filenames:
        path = os.path.join(current, name)
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            raise SystemExit(1)
        relative = os.path.relpath(path, root).replace(os.sep, "/")
        file_hash = hashlib.sha256()
        with open(path, "rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                file_hash.update(chunk)
        records.append(("F", relative, info.st_size, file_hash.hexdigest()))
        entry_count += 1
        expanded += info.st_size
if entry_count < 1 or entry_count > 4097 \
        or expanded > 320 * 1024 * 1024:
    raise SystemExit(1)
result = hashlib.sha256()
for kind, relative, size, file_hash in sorted(records):
    for value in (kind, relative, str(size), file_hash):
        encoded = value.encode("utf-8")
        result.update(len(encoded).to_bytes(8, "big"))
        result.update(encoded)
print(result.hexdigest())
EGO_TREE_DIGEST_PY
)
[ "$actual_tree_sha" = "$expected_tree_sha" ] || exit 2
python3 - "$candidate/metadata.json" "$expected_uuid" "$expected_version" <<'EGO_METADATA_PY'
import json
import sys
path, expected_uuid, expected_version = sys.argv[1:]
with open(path, encoding="utf-8") as source:
    metadata = json.load(source)
if metadata.get("uuid") != expected_uuid or str(metadata.get("version", "")) != expected_version:
    raise SystemExit(1)
EGO_METADATA_PY
chown -R root:root "$candidate"
find -P "$candidate" -xdev -type d -exec chmod 0755 {} +
find -P "$candidate" -xdev -type f -exec chmod 0644 {} +
restorecon -RF "$candidate"
find -P "$candidate" -xdev -type f -exec sync -- {} +
sync -- "$candidate" "$parent"

# Both directories are siblings on one filesystem. RENAME_EXCHANGE makes the
# active-tree transition atomic: interruption leaves either the complete old
# tree or the complete validated new tree at the public path, never a mix.
python3 - "$target_dir" "$candidate" <<'EGO_EXCHANGE_PY'
import ctypes
import os
import sys

old, new = map(os.fsencode, sys.argv[1:])
libc = ctypes.CDLL(None, use_errno=True)
renameat2 = libc.renameat2
renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p,
                      ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
renameat2.restype = ctypes.c_int
if renameat2(-100, old, -100, new, 2) != 0:  # AT_FDCWD, RENAME_EXCHANGE
    error = ctypes.get_errno()
    raise OSError(error, os.strerror(error))
EGO_EXCHANGE_PY
sync -- "$target_dir" "$parent"
rm -rf --one-file-system -- "$candidate"
candidate=
trap - EXIT INT TERM
EGO_PUBLISH_EOF
        then
            echo -e "${GREEN}UPDATED${NC}: ${ego_uuid} v${ego_installed} → v${ego_available} (re-login to apply)"
            ego_digest=$(sha256sum "$ego_zip" | awk '{print $1}')
            if ! record_extension_update "gnome-${ego_uuid}" "$ego_installed" \
                    "$ego_available" "$ego_digest"; then
                echo -e "${RED}ERROR${NC}: ${ego_uuid} updated but SHA-256 evidence could not be recorded"
                ERRORS=$((ERRORS + 1))
            fi
        else
            echo -e "${RED}ERROR${NC}: ${ego_uuid} v${ego_installed} → v${ego_available} atomic publication failed"
            ERRORS=$((ERRORS + 1))
        fi
        rm -rf --one-file-system -- "$ego_work"
    done
fi

# [6c] VSCodium Extensions (Open-VSX opt-in update)
#
# M08 ships extensions.autoCheckUpdates=false + extensions.autoUpdate="off" (no
# background Open-VSX traffic). Running noid-update-all.sh IS the opt-in update
# path: this step refreshes every user-installed VSCodium extension via codium's
# own documented update/install commands, then works around gallery latency
# with an identity-checked REST `/latest` comparison. The global command has no
# exclude option: when either NoID Privacy-managed agent extension is present,
# every other extension is updated individually so those two namespaces truly
# remain owned by Step 6. REST results can only advance, never downgrade, an
# installed version. Egress is HTTPS-only; Codium owns VSIX acquisition and
# installation validation.
echo ""
step "6c" "VSCodium Extensions (Open-VSX opt-in update)"
if ! command -v codium >/dev/null 2>&1; then
    echo -e "${RED}ERROR${NC}: codium is not installed (required NoID Privacy component)"
    ERRORS=$((ERRORS + 1))
else
    _noid_vsx_is_agent() {
        case "${1,,}" in
            anthropic.claude-code|openai.chatgpt) return 0 ;;
            *) return 1 ;;
        esac
    }
    _noid_version_newer() {
        # REST is only an exact fallback for bounded numeric release versions.
        # Return 0 for candidate-newer, 1 for an ordered non-newer pair and 2
        # when either value is outside the bounded grammar.
        # Codium's native path remains authoritative for pre-release versions;
        # treating them with GNU sort -V would invert SemVer precedence (for
        # example, it orders 1.0.0-beta after 1.0.0). Segments accept up to 18
        # digits: Open-VSX ships date-stamped patch segments beyond 9 digits
        # (live example: redhat.vscode-yaml 1.25.2026071508).
        python3 - "$1" "$2" <<'VSX_VERSION_PY'
import re
import sys

pattern = re.compile(r"[0-9]{1,18}(?:\.[0-9]{1,18}){1,3}")
candidate, installed = sys.argv[1:]
if not pattern.fullmatch(candidate) or not pattern.fullmatch(installed):
    raise SystemExit(2)
candidate_parts = tuple(int(part) for part in candidate.split("."))
installed_parts = tuple(int(part) for part in installed.split("."))
width = max(len(candidate_parts), len(installed_parts))
candidate_parts += (0,) * (width - len(candidate_parts))
installed_parts += (0,) * (width - len(installed_parts))
raise SystemExit(0 if candidate_parts > installed_parts else 1)
VSX_VERSION_PY
    }
    capture_codium_inventory() {
        local inventory_rc=0
        CODIUM_INVENTORY=
        CODIUM_INVENTORY_ERR=$(mktemp \
            "${XDG_RUNTIME_DIR:-/tmp}/.noid-codium-inventory.XXXXXX") \
            || return 1
        chmod 0600 "$CODIUM_INVENTORY_ERR" || {
            rm -f -- "$CODIUM_INVENTORY_ERR"
            CODIUM_INVENTORY_ERR=
            return 1
        }
        CODIUM_INVENTORY=$(codium --list-extensions --show-versions \
            2>"$CODIUM_INVENTORY_ERR") || inventory_rc=$?
        if [ "$inventory_rc" -ne 0 ] && [ -s "$CODIUM_INVENTORY_ERR" ]; then
            sed 's/^/  /' "$CODIUM_INVENTORY_ERR"
        fi
        rm -f -- "$CODIUM_INVENTORY_ERR"
        CODIUM_INVENTORY_ERR=
        return "$inventory_rc"
    }
    # Query the platform build first and the universal build second. Accept a
    # response only when its namespace/name/platform and bounded version match
    # the requested identity.
    _vsx_latest() {  # $1=publisher $2=name -> prints version or empty
        local plat
        for plat in linux-x64 universal; do
            curl -fsS --proto '=https' --tlsv1.2 --max-time 10 \
                --max-filesize 1048576 \
                "https://open-vsx.org/api/$1/$2/${plat}/latest" 2>/dev/null \
            | python3 -c "import sys, json, re
try:
    data=json.load(sys.stdin)
    version=str(data.get('version', ''))
    valid=(str(data.get('namespace', '')).lower()==sys.argv[1].lower()
           and str(data.get('name', '')).lower()==sys.argv[2].lower()
           and data.get('targetPlatform')==sys.argv[3]
           and re.fullmatch(r'[0-9]{1,18}(?:\.[0-9]{1,18}){1,3}', version))
    if valid:
        print(version)
    else:
        raise SystemExit(1)
except Exception:
    raise SystemExit(1)" "$1" "$2" "$plat" 2>/dev/null && return 0
        done
        return 0
    }
    if ! capture_codium_inventory; then
        echo -e "${RED}ERROR${NC}: cannot enumerate VSCodium extensions; complete update state is unprovable"
        ERRORS=$((ERRORS + 1))
    else
        codium_list=$CODIUM_INVENTORY
        codium_has_agent=0
        codium_non_agent_count=0
        while IFS= read -r ext_line; do
            [ -n "$ext_line" ] || continue
            ext_id=${ext_line%@*}
            if [ "$ext_id" = "$ext_line" ]; then
                echo -e "${RED}ERROR${NC}: malformed VSCodium extension inventory row: ${ext_line}"
                ERRORS=$((ERRORS + 1))
                continue
            fi
            if _noid_vsx_is_agent "$ext_id"; then
                codium_has_agent=1
            else
                codium_non_agent_count=$((codium_non_agent_count + 1))
            fi
        done <<<"$codium_list"

        native_rc=0
        if [ "$codium_non_agent_count" -eq 0 ]; then
            echo -e "${YELLOW}INFO${NC}: no non-agent extensions are installed; Step 6 owns any managed agent extensions"
        elif [ "$codium_has_agent" -eq 0 ]; then
            native_out=$(codium --update-extensions 2>&1) || native_rc=$?
            printf '%s\n' "$native_out" | sed '/^$/d; s/^/  /'
        else
            echo -e "${YELLOW}INFO${NC}: managed agent extensions present; using per-extension native updates"
            while IFS= read -r ext_line; do
                [ -n "$ext_line" ] || continue
                ext_id=${ext_line%@*}
                ext_ver=${ext_line##*@}
                if ! [[ "$ext_id" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*\.[A-Za-z0-9][A-Za-z0-9._-]*$ \
                   && "$ext_ver" != "$ext_line" ]]; then
                    echo -e "${RED}ERROR${NC}: malformed VSCodium extension inventory row: ${ext_line}"
                    ERRORS=$((ERRORS + 1))
                    native_rc=1
                    continue
                fi
                _noid_vsx_is_agent "$ext_id" && continue
                if ! codium --install-extension "$ext_id" --force 2>&1 \
                        | sed "s/^/  [${ext_id}] /"; then
                    native_rc=1
                fi
            done <<<"$codium_list"
        fi
        if [ "$codium_non_agent_count" -eq 0 ]; then
            echo -e "${GREEN}OK${NC}: no additional VSCodium extensions require the native update path"
        elif [ "$native_rc" -eq 0 ]; then
            echo -e "${GREEN}OK${NC}: native VSCodium extension update completed"
        else
            echo -e "${RED}ERROR${NC}: native VSCodium extension update reported a failure"
            ERRORS=$((ERRORS + 1))
        fi

        rest_updated=0
        rest_skipped=0
        rest_blocked=0
        rest_unavailable=0
        rest_newer=0
        rest_unordered=0
        if command -v curl >/dev/null 2>&1 \
                && command -v python3 >/dev/null 2>&1; then
            if ! capture_codium_inventory; then
                echo -e "${RED}ERROR${NC}: post-update VSCodium extension enumeration failed"
                ERRORS=$((ERRORS + 1))
            else
                codium_after=$CODIUM_INVENTORY
                while IFS= read -r ext_line; do
                    [ -n "$ext_line" ] || continue
                    ext_id=${ext_line%@*}
                    ext_ver=${ext_line##*@}
                    if ! [[ "$ext_id" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*\.[A-Za-z0-9][A-Za-z0-9._-]*$ \
                       && "$ext_ver" != "$ext_line" ]]; then
                        echo -e "${RED}ERROR${NC}: malformed post-update VSCodium extension row: ${ext_line}"
                        ERRORS=$((ERRORS + 1))
                        rest_blocked=$((rest_blocked + 1))
                        continue
                    fi
                    _noid_vsx_is_agent "$ext_id" && continue
                    pub=${ext_id%%.*}
                    name=${ext_id#*.}
                    latest=$(_vsx_latest "$pub" "$name" | head -n 1)
                    if [ -z "$latest" ]; then
                        echo -e "${YELLOW}INFO${NC}: ${ext_id} Open-VSX latest response unavailable; native update result retained"
                        rest_unavailable=$((rest_unavailable + 1))
                        continue
                    fi
                    if [ "$latest" = "$ext_ver" ]; then
                        continue
                    fi
                    version_order_rc=0
                    _noid_version_newer "$latest" "$ext_ver" \
                        || version_order_rc=$?
                    case "$version_order_rc" in
                        0) ;;
                        1)
                            echo -e "${GREEN}OK${NC}: ${ext_id} installed ${ext_ver} is newer than registry ${latest}; no downgrade"
                            rest_newer=$((rest_newer + 1))
                            continue
                            ;;
                        2)
                            echo -e "${YELLOW}WARN${NC}: ${ext_id} version ordering is unprovable (${ext_ver} vs ${latest}); left to Codium's native update path"
                            WARNINGS=$((WARNINGS + 1))
                            rest_unordered=$((rest_unordered + 1))
                            continue
                            ;;
                        *)
                            echo -e "${RED}ERROR${NC}: ${ext_id} version comparator failed unexpectedly"
                            ERRORS=$((ERRORS + 1))
                            rest_blocked=$((rest_blocked + 1))
                            continue
                            ;;
                    esac
                    echo -e "${YELLOW}UPDATE${NC}: ${ext_id} ${ext_ver} → ${latest}"
                    install_rc=0
                    install_out=$(codium --install-extension \
                        "${ext_id}@${latest}" --force 2>&1) || install_rc=$?
                    printf '%s\n' "$install_out" | sed "s/^/  [${ext_id}] /"
                    installed_exact=$(codium --list-extensions --show-versions \
                        2>/dev/null | grep -iFx -- "${ext_id}@${latest}" || true)
                    if [ "$install_rc" -eq 0 ] && [ -n "$installed_exact" ]; then
                        echo -e "${GREEN}OK${NC}: ${ext_id} → ${latest}"
                        rest_updated=$((rest_updated + 1))
                    else
                        echo -e "${RED}ERROR${NC}: ${ext_id} → ${latest} install/postcondition failed"
                        ERRORS=$((ERRORS + 1))
                        rest_blocked=$((rest_blocked + 1))
                    fi
                done <<<"$codium_after"
            fi
        else
            echo -e "${RED}ERROR${NC}: curl/python3 missing; Open-VSX current-state verification cannot run"
            ERRORS=$((ERRORS + 1))
            rest_skipped=1
        fi
        if [ "$codium_non_agent_count" -eq 0 ]; then
            echo -e "${GREEN}OK${NC}: no additional VSCodium extensions require Open-VSX reconciliation"
        elif [ "$rest_blocked" -gt 0 ]; then
            echo -e "${RED}ERROR${NC}: REST cross-check completed with ${rest_blocked} unverified/failed extension state(s)"
        elif [ "$rest_skipped" -gt 0 ]; then
            echo -e "${RED}ERROR${NC}: REST cross-check unavailable; VSCodium extension current state is unprovable"
        elif [ "$rest_unavailable" -gt 0 ]; then
            echo -e "${YELLOW}WARN${NC}: Open-VSX REST channel unavailable for ${rest_unavailable} extension state(s); native update result retained, retry later"
            WARNINGS=$((WARNINGS + 1))
            DEFERRED_LIST+=("Open-VSX-cross-check")
        elif [ "$rest_unordered" -gt 0 ]; then
            echo -e "${YELLOW}WARN${NC}: REST cross-check left ${rest_unordered} unorderable version state(s) to Codium's native updater"
        elif [ "$rest_updated" -gt 0 ]; then
            echo -e "${GREEN}OK${NC}: ${rest_updated} extension(s) advanced by identity-checked Open-VSX REST fallback"
        elif [ "$rest_newer" -gt 0 ]; then
            echo -e "${GREEN}OK${NC}: VSCodium extension versions are current or newer (${rest_newer} no-downgrade state(s))"
        else
            echo -e "${GREEN}OK${NC}: VSCodium extension versions are current"
        fi
    fi
fi

# [7] Repo Signature + Reachability Safety Check
echo ""
step "7" "Repo Signature + Reachability Safety Check"
repo_security_inventory() {
    python3 -c '
import json
import re
import sys

try:
    repositories = json.load(sys.stdin)
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    raise SystemExit(f"invalid DNF repository JSON: {exc}")
if not isinstance(repositories, list) or not repositories:
    raise SystemExit("DNF returned no enabled repository records")

seen = set()
for repository in repositories:
    if not isinstance(repository, dict):
        raise SystemExit("DNF repository record is not an object")
    identity = repository.get("id")
    if not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]+", identity):
        raise SystemExit("DNF repository identity is missing or unsafe")
    if identity in seen:
        raise SystemExit(f"duplicate DNF repository identity: {identity}")
    seen.add(identity)
    if repository.get("is_enabled") is not True:
        raise SystemExit(f"DNF returned a non-enabled repository: {identity}")
    package_check = repository.get("pkg_gpgcheck")
    metadata_check = repository.get("repo_gpgcheck")
    if not isinstance(package_check, bool) or not isinstance(metadata_check, bool):
        raise SystemExit(f"DNF signature state is missing for: {identity}")
    if not package_check:
        print(f"PACKAGE\t{identity}")
    if not metadata_check:
        print(f"METADATA\t{identity}")
'
}

# Inspect DNF5's effective root transaction configuration, including inherited
# defaults and config-manager overrides. Grepping *.repo text cannot prove this
# state: an omitted key, [main] value or override may change the effective
# result. Step 2 already refreshed the root cache, so this postflight performs
# no independent repository egress.
repo_info_json=
repo_info_rc=0
repo_info_json=$(sudo LC_ALL=C dnf --cacheonly repo info --enabled --json \
    2> >(sed 's/^/    /' >&2)) \
    || repo_info_rc=$?
repo_security_rows=
repo_parse_rc=0
if [ "$repo_info_rc" -eq 0 ]; then
    repo_security_rows=$(printf '%s\n' "$repo_info_json" \
        | repo_security_inventory 2>&1) || repo_parse_rc=$?
fi

if [ "$repo_info_rc" -ne 0 ]; then
    [ -z "$repo_info_json" ] || printf '%s\n' "$repo_info_json" | sed 's/^/    /'
    echo -e "${RED}ERROR${NC}: effective enabled-repository state could not be queried (exit ${repo_info_rc})"
    ERRORS=$((ERRORS + 1))
elif [ "$repo_parse_rc" -ne 0 ]; then
    [ -z "$repo_security_rows" ] || printf '%s\n' "$repo_security_rows" | sed 's/^/    /'
    echo -e "${RED}ERROR${NC}: effective enabled-repository signature state is invalid or incomplete"
    ERRORS=$((ERRORS + 1))
else
    package_unsigned=$(printf '%s\n' "$repo_security_rows" \
        | awk -F '\t' '$1 == "PACKAGE" { print $2 }')
    metadata_unsigned=$(printf '%s\n' "$repo_security_rows" \
        | awk -F '\t' '$1 == "METADATA" { print $2 }')
    if [ -n "$package_unsigned" ]; then
        echo -e "${RED}${BOLD}ERROR${NC}${RED}: package signature verification is disabled for enabled repository/repositories:${NC}"
        printf '%s\n' "$package_unsigned" | sed 's/^/    /'
        ERRORS=$((ERRORS + 1))
    else
        echo -e "${GREEN}OK${NC}: every enabled repository enforces RPM package signature verification"
    fi
    if [ -n "$metadata_unsigned" ]; then
        metadata_relaxed_count=$(printf '%s\n' "$metadata_unsigned" \
            | awk 'NF { count++ } END { print count + 0 }')
        echo -e "${YELLOW}INFO${NC}: repository metadata signature verification is disabled for ${metadata_relaxed_count} enabled repository/repositories:"
        printf '%s\n' "$metadata_unsigned" | sed 's/^/    /'
        echo "  → RPM package signatures still gate installed package payloads"
        echo "  → Listed metadata lacks DNF repository-metadata OpenPGP verification"
    else
        echo -e "${GREEN}OK${NC}: every enabled repository also verifies repository metadata signatures"
    fi
fi

# OpenH264 repository-metalink reachability check — attribute a loud metadata
# failure without claiming that this probe reached a package-distribution host.
# Background: Module 08 pins skip_if_unavailable=False for
# fedora-cisco-openh264.repo, so a DNF metadata refresh fails loudly while
# the repository path is unreachable instead of silently dropping OpenH264.
# Fedora builds/signs the RPMs and Cisco distributes them, but this request
# checks only Fedora's public metalink. A package URL can still fail later.
probe_openh264_http() {
    local url=$1 status
    # Do not use --fail here: HTTP errors are the values this diagnostic must
    # distinguish. Transport failures still return non-zero and normalize to
    # 000 without concatenating curl's --write-out bytes with fallback output.
    if ! status=$(curl --proto '=https' --tlsv1.2 --max-time 10 \
            -sS -o /dev/null -w '%{http_code}' "$url" 2>/dev/null); then
        status=000
    fi
    case "$status" in
        [0-9][0-9][0-9]) printf '%s\n' "$status" ;;
        *) printf '000\n' ;;
    esac
}

if [[ -f /etc/yum.repos.d/fedora-cisco-openh264.repo ]] \
        && command -v curl >/dev/null 2>&1; then
    openh264_release=$(/usr/bin/rpm -E '%fedora' 2>/dev/null) \
        || openh264_release=
    openh264_arch=$(/usr/bin/rpm -E '%_arch' 2>/dev/null) \
        || openh264_arch=
    if ! [[ "$openh264_release" =~ ^[0-9]+$ \
            && "$openh264_arch" =~ ^[A-Za-z0-9_+-]+$ ]]; then
        echo -e "${YELLOW}INFO${NC}: fedora-cisco-openh264 metalink probe skipped; runtime release/architecture could not be derived"
    else
        openh264_metalink="https://mirrors.fedoraproject.org/metalink?repo=fedora-cisco-openh264-${openh264_release}&arch=${openh264_arch}"
        openh264_http=$(probe_openh264_http "$openh264_metalink")
        case "${openh264_http}" in
            200)
                echo -e "${GREEN}OK${NC}: fedora-cisco-openh264 metalink reachable (HTTP 200)"
                ;;
            403)
                echo -e "${YELLOW}INFO${NC}: fedora-cisco-openh264 metalink returned HTTP 403"
                echo "  → a DNF metadata refresh fails loudly while this persists (openh264 repo required)"
                echo "  → retry from another network/VPN exit or after the repository path recovers"
                ;;
            000)
                echo -e "${YELLOW}INFO${NC}: fedora-cisco-openh264 metalink check timed out (10s)"
                echo "  → Network/VPN issue? A DNF metadata refresh fails loudly while this persists"
                ;;
            *)
                echo -e "${YELLOW}INFO${NC}: fedora-cisco-openh264 metalink returned HTTP ${openh264_http}"
                echo "  → a DNF metadata refresh may fail loudly while this persists"
                ;;
        esac
    fi
fi

# [8] AIDE — check-only evidence; never replace the trust database
# Package updates are expected to create drift, but expected is not the same as
# trusted. Preserve the active database, run the ordinary check when one exists,
# and direct the user to the separate hash-confirmed review workflow.
echo ""
step "8" "AIDE Integrity Evidence"

if [ "$DNF_SUCCEEDED" -ne 1 ]; then
    echo -e "${YELLOW}SKIP${NC}: AIDE check skipped because the DNF transaction failed"
    SKIPPED_LIST+=("AIDE")
elif grep -qE 'rd\.live\.image|boot=live' /proc/cmdline 2>/dev/null; then
    echo -e "${YELLOW}SKIP${NC}: Live-Boot mode detected; no persistent trust database is used"
    SKIPPED_LIST+=("AIDE")
elif ! command -v aide >/dev/null 2>&1; then
    echo -e "${YELLOW}SKIP${NC}: aide not installed"
    SKIPPED_LIST+=("AIDE")
elif [ "${NOID_SKIP_AIDE_CHECK:-0}" = "1" ]; then
    echo -e "${YELLOW}SKIP${NC}: AIDE check skipped by explicit user choice"
    SKIPPED_LIST+=("AIDE")
else
    aide_database_state=$(read_aide_database_state)
    if [ "$aide_database_state" = absent ]; then
        echo -e "${YELLOW}INFO${NC}: no active AIDE baseline; updater did not create one"
        echo "  → User-owned workflow: sudo noid-aide-baseline-review prepare"
        SKIPPED_LIST+=("AIDE (baseline uninitialized)")
    elif [ "$aide_database_state" = unsafe ]; then
        echo -e "${RED}ERROR${NC}: AIDE baseline path has unsafe metadata; check-only evidence was not started"
        ERRORS=$((ERRORS + 1))
    elif [ "$aide_database_state" != active ]; then
        echo -e "${RED}ERROR${NC}: fixed AIDE baseline-state boundary is unavailable or malformed"
        ERRORS=$((ERRORS + 1))
    else
        echo "  → Running check-only AIDE evidence scan; active database will not change"
        # No shell-option toggling here: this orchestrator runs WITHOUT errexit
        # by design. Errors are counted and the Summary is always reached.
        aide_rc=0
        sudo /usr/local/sbin/noid-aide-check.sh >/dev/null 2>&1 || aide_rc=$?
        latest_aide_report=$(sudo find /var/log/aide -maxdepth 1 -type f \
            -name 'aide-check-*.log' -printf '%T@ %p\n' 2>/dev/null \
            | sort -nr | head -1 | cut -d' ' -f2-)
        if [ "$aide_rc" -eq 0 ]; then
            echo -e "${GREEN}OK${NC}: AIDE check found no differences"
        elif [ "$aide_rc" -ge 1 ] && [ "$aide_rc" -le 7 ]; then
            echo -e "${YELLOW}REVIEW${NC}: AIDE reports filesystem differences (rc=$aide_rc)"
            echo "  → Report: ${latest_aide_report:-/var/log/aide/}"
            echo "  → Inspect every unexpected path; the updater did NOT absorb the drift"
            echo "  → To prepare a separate candidate after review: sudo noid-aide-baseline-review prepare"
            WARNINGS=$((WARNINGS + 1))
        else
            echo -e "${RED}ERROR${NC}: AIDE check failed or was incomplete (rc=$aide_rc)"
            echo "  → Report: ${latest_aide_report:-/var/log/aide/}"
            ERRORS=$((ERRORS + 1))
        fi
    fi
fi

# [8b] Forked-config drift evidence (.rpmnew / .rpmsave)
# NoID Privacy deliberately forks a number of %config(noreplace) vendor files
# (chrony.conf, aide.conf, auditd.conf, usbguard configs, login.defs, ...).
# RPM protects those forks from silent replacement, but new upstream defaults
# then land as .rpmnew siblings — invisible unless someone looks. Surface
# them after every update run; merging stays a deliberate human decision.
echo ""
step "8b" "Config drift evidence (.rpmnew / .rpmsave)"
rpm_sibling_files=()
if ! RPM_SIBLING_LIST=$(mktemp \
        "${XDG_RUNTIME_DIR:-/tmp}/.noid-rpm-siblings.XXXXXX"); then
    echo -e "${RED}ERROR${NC}: cannot create private config-drift scan evidence"
    ERRORS=$((ERRORS + 1))
else
    chmod 0600 "$RPM_SIBLING_LIST"
    if sudo find /etc -xdev \
            \( -name '*.rpmnew' -o -name '*.rpmsave' -o -name '*.rpmorig' \) \
            -type f -print0 | LC_ALL=C sort -z >"$RPM_SIBLING_LIST"; then
        mapfile -d '' -t rpm_sibling_files <"$RPM_SIBLING_LIST"
        if [ "${#rpm_sibling_files[@]}" -eq 0 ]; then
            echo -e "${GREEN}OK${NC}: no .rpmnew/.rpmsave/.rpmorig files under /etc"
        else
            echo -e "${YELLOW}REVIEW${NC}: ${#rpm_sibling_files[@]} vendor-default sibling file(s) present:"
            for rpm_sibling in "${rpm_sibling_files[@]}"; do
                printf '  → %s\n' "$rpm_sibling"
            done
            echo "  → Diff each against its live twin, then merge or remove deliberately;"
            echo "    the updater never merges vendor defaults automatically."
            WARNINGS=$((WARNINGS + 1))
        fi
    else
        echo -e "${RED}ERROR${NC}: config-drift scan under /etc failed or was incomplete"
        ERRORS=$((ERRORS + 1))
    fi
    rm -f -- "$RPM_SIBLING_LIST"
    RPM_SIBLING_LIST=
fi

# [9] Reboot Check
echo ""
step "9" "Reboot check"
# DNF owns only its core-package recommendation. Kernel, NVIDIA, firmware and
# blocker state are deliberately not re-derived here: after the boot-scoped
# state transaction is published below, one canonical reader computes both
# activation need and reboot safety for the Summary and every other consumer.
reboot_info=$(sudo LC_ALL=C dnf needs-restarting --json 2>/dev/null)
reboot_rc=$?
reboot_hint=$(parse_dnf_reboot_hint \
    <<< "$reboot_info" 2>/dev/null) || reboot_hint=invalid
if [[ ${reboot_rc} -eq 0 && "$reboot_hint" = no ]]; then
    echo -e "${GREEN}OK${NC}: DNF reports no core-package restart recommendation; final canonical reboot verdict follows"
elif [[ ${reboot_rc} -eq 1 && "$reboot_hint" = yes ]]; then
    echo -e "${YELLOW}RESTART RECOMMENDED${NC}: updated reboot-relevant packages detected; final canonical reboot verdict follows"
else
    echo -e "${RED}ERROR${NC}: DNF reboot-hint query failed or returned inconsistent data (rc=${reboot_rc})"
    ERRORS=$((ERRORS + 1))
fi

# Run `needs-restarting -s` as the INVOKING USER, not via
# sudo. dnf5's -s mode also enumerates user-session units and needs the
# session D-Bus; sudo's env_reset strips DBUS_SESSION_BUS_ADDRESS +
# XDG_RUNTIME_DIR, so under sudo it died with
# [org.freedesktop.DBus.Error.FileNotFound] BEFORE printing anything to
# stdout (stderr swallowed here) — the "Services with outdated binaries"
# hint never fired. As the invoking user (the script's normal context, incl.
# the GUI path which spawns this script unprivileged) it works. Validate both
# the documented JSON records and their rc (0=no units, 1=units); an execution
# or schema failure is a visible warning instead of silently losing the hint.
# This installed-state query needs neither repository definitions nor plugins.
# Give it a private empty reposdir, an empty config and `--no-plugins`: otherwise
# an unrelated root-only third-party .repo file or a DNF transaction action can
# break the advisory. `-C` + `</dev/null` remain defense in depth against cache
# refreshes and prompts. Real package transactions retain their normal repo and
# repo_gpgcheck policy.
needs_svc_err=$(mktemp "${XDG_RUNTIME_DIR:-/tmp}/.noid-needs-restarting.XXXXXX") \
    || needs_svc_err=""
needs_svc_repos=$(mktemp -d \
    "${XDG_RUNTIME_DIR:-/tmp}/.noid-needs-restarting-repos.XXXXXX") \
    || needs_svc_repos=""
if [[ -n "$needs_svc_err" && -n "$needs_svc_repos" ]]; then
    needs_svc_json=$(timeout --signal=TERM --kill-after=5s 20s \
        env LC_ALL=C dnf --config=/dev/null \
        --setopt="reposdir=$needs_svc_repos" --no-plugins \
        needs-restarting -s -C --json \
        </dev/null 2>"$needs_svc_err")
    needs_svc_rc=$?
else
    needs_svc_json=""
    needs_svc_rc=125
    [[ -z "$needs_svc_err" ]] || \
        printf '%s\n' 'unable to create private DNF service-query state' \
            > "$needs_svc_err"
fi
# A local execution failure or bounded timeout loses only this advisory hint.
# Never retry with the system repositories: Step 2 already performed the
# authorized root DNF transaction, and this helper has no repository purpose.
needs_svc_parse_rc=0
needs_svc=$(parse_dnf_service_units \
    <<< "$needs_svc_json" 2>/dev/null) || needs_svc_parse_rc=$?
if [[ "$needs_svc_parse_rc" -eq 0 && "$needs_svc_rc" -eq 1 \
        && -n "$needs_svc" ]]; then
    echo -e "${YELLOW}Services with outdated binaries:${NC}"
    echo "${needs_svc}" | sed 's/^/  /'
elif [[ "$needs_svc_parse_rc" -ne 0 ]] \
        || { [[ "$needs_svc_rc" -eq 0 ]] && [[ -n "$needs_svc" ]]; } \
        || { [[ "$needs_svc_rc" -eq 1 ]] && [[ -z "$needs_svc" ]]; } \
        || [[ "$needs_svc_rc" -gt 1 ]]; then
    # Carry the query's own first stderr line. Without it this warning names
    # four different conditions — dead query, rejected schema, and both
    # rc/record mismatches — and discards the only evidence that separates
    # them, so a recurrence cannot be diagnosed after the fact.
    needs_svc_detail=""
    if [[ -n "$needs_svc_err" && -s "$needs_svc_err" ]]; then
        needs_svc_detail=$(head -1 "$needs_svc_err")
    fi
    echo -e "${YELLOW}WARN${NC}: DNF service-restart query failed or returned inconsistent data (rc=${needs_svc_rc})${needs_svc_detail:+ — ${needs_svc_detail}}"
    WARNINGS=$((WARNINGS + 1))
fi
[[ -z "$needs_svc_repos" ]] || rmdir -- "$needs_svc_repos"
[[ -z "$needs_svc_err" ]] || rm -f -- "$needs_svc_err"

# Close the Snapper transaction before the Summary so its result participates
# in both the GUI step attribution and the process exit status. The EXIT trap
# remains a fallback only for earlier termination.
if ! finalize_post_snapshot; then
    ERRORS=$((ERRORS + 1))
fi

END_TS=$(date +%s)
DURATION=$(human_duration $((END_TS - START_TS)))

# Complete the boot-scoped safety transaction, then obtain both independent
# axes from the same canonical reader used by every other presentation. A
# run retires a prior same-boot blocker only after every relevant boot
# convergence gate above has passed; an unrelated update error does not invent
# a boot blocker, while a failed/unsafe state publication itself blocks.
if [ "${#REBOOT_BLOCKERS[@]}" -eq 0 ] \
        && [ "$REBOOT_STATE_WRITE_FAILED" -eq 0 ]; then
    if ! sudo /usr/libexec/noid-reboot-block-state --clear; then
        REBOOT_STATE_WRITE_FAILED=1
        ERRORS=$((ERRORS + 1))
    fi
elif ! publish_reboot_blockers; then
    REBOOT_STATE_WRITE_FAILED=1
fi

REBOOT_ACTIVATION=none
REBOOT_SAFETY=blocked
REBOOT_BLOCKER_SUMMARY=state-unsafe
if ! load_reboot_readiness; then
    echo -e "${RED}ERROR${NC}: canonical reboot-readiness record is unavailable or malformed"
    ERRORS=$((ERRORS + 1))
elif [ "$REBOOT_STATE_WRITE_FAILED" -ne 0 ]; then
    REBOOT_SAFETY=blocked
    REBOOT_BLOCKER_SUMMARY=state-unsafe
    echo -e "${RED}ERROR${NC}: reboot-safety state could not be published reliably"
    ERRORS=$((ERRORS + 1))
fi
_emit_marker "WARNINGS $WARNINGS"
_emit_marker "REBOOT $REBOOT_ACTIVATION $REBOOT_SAFETY $REBOOT_BLOCKER_SUMMARY"

echo ""
echo -e "${BOLD}${_hr}${NC}"
echo -e "${BOLD}  Update Summary${NC}"
echo -e "  ──────────────"
printf "  %-18s %s\n" "Duration:" "$DURATION"
printf "  %-18s %s steps\n" "Steps:" "$STEPS"
if [[ ${#SKIPPED_LIST[@]} -gt 0 ]]; then
    printf "  %-18s ${YELLOW}%s${NC}\n" "Skipped:" "${SKIPPED_LIST[*]}"
fi
if [[ ${#DEFERRED_LIST[@]} -gt 0 ]]; then
    printf "  %-18s ${YELLOW}%s${NC}\n" "Deferred:" "${DEFERRED_LIST[*]}"
fi
if [[ ${ERRORS} -gt 0 ]]; then
    printf "  %-18s ${RED}%d${NC}\n" "Errors:" "$ERRORS"
else
    printf "  %-18s ${GREEN}%d${NC}\n" "Errors:" "$ERRORS"
fi
if [[ ${WARNINGS} -gt 0 ]]; then
    printf "  %-18s ${YELLOW}%d${NC}\n" "Warnings:" "$WARNINGS"
fi
if [[ "$REBOOT_SAFETY" = blocked ]]; then
    printf "  %-18s ${RED}blocked${NC} — repair first (%s)\n" \
        "Reboot:" "$REBOOT_BLOCKER_SUMMARY"
elif [[ "$REBOOT_ACTIVATION" = required ]]; then
    printf "  %-18s ${YELLOW}required + safe${NC} — reboot to activate\n" "Reboot:"
elif [[ "$REBOOT_ACTIVATION" = recommended ]]; then
    printf "  %-18s ${YELLOW}recommended + safe${NC} — core libraries/services updated\n" "Reboot:"
else
    printf "  %-18s ${GREEN}no${NC}\n" "Reboot:"
fi
echo -e "${BOLD}${_hr}${NC}"
# Flush the final step's error attribution before the terminal exit gate
# (steps 1..8 flush at the next step's header; step 9 has no successor).
_flush_step_errors
if [[ "$REBOOT_SAFETY" = blocked ]]; then
    echo -e "  ${RED}✗ Boot path is not reboot-safe${NC} — repair: ${REBOOT_BLOCKER_SUMMARY}"
    echo ""
    exit 1
elif [[ ${ERRORS} -gt 0 ]]; then
    echo -e "  ${RED}✗ ${ERRORS} error(s) — review output above${NC}"
    echo ""
    exit 1
elif [[ "$REBOOT_ACTIVATION" = required || "$REBOOT_ACTIVATION" = recommended ]]; then
    echo -e "  ${GREEN}✓ Updates applied${NC} — reboot to complete"
    echo ""
    exit 0
elif [[ ${WARNINGS} -gt 0 ]]; then
    echo -e "  ${YELLOW}✓ Updates applied with ${WARNINGS} warning(s)${NC} — review the named non-blocking conditions above"
    echo ""
    exit 0
else
    echo -e "  ${GREEN}✓ Checked update sources are current${NC}"
    echo ""
    exit 0
fi
NOID_UPDATE_EOF

chmod 755 /usr/local/bin/noid-update-all.sh
chown root:root /usr/local/bin/noid-update-all.sh
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/local/bin/noid-update-all.sh
fi
echo "  [OK] /usr/local/bin/noid-update-all.sh installed (755 root:root)"

# Boot activation need and boot safety are independent state axes. This root
# publisher owns only the small, boot-scoped safety record; activation remains
# a direct live comparison in the read-only helper below. The record contains
# closed reason codes only—no kernel release, hardware identity or log text.
cat > /usr/libexec/noid-reboot-block-state <<'REBOOT_BLOCK_STATE_EOF'
#!/usr/bin/bash
set -euo pipefail
PATH=/usr/sbin:/usr/bin
LC_ALL=C
export PATH LC_ALL

STATE_DIR=/run/noid-privacy
STATE=$STATE_DIR/reboot-blocked
candidate=

fail() {
    echo "noid-reboot-block-state: $*" >&2
    exit 1
}
cleanup() {
    [ -z "${candidate:-}" ] || rm -f -- "$candidate"
}
trap cleanup EXIT HUP INT TERM

[ "$(id -u)" -eq 0 ] || fail "must run as root"
if [ -e "$STATE_DIR" ] || [ -L "$STATE_DIR" ]; then
    [ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ] \
        && [ "$(stat -Lc '%u:%g:%a' "$STATE_DIR")" = 0:0:755 ] \
        || fail "runtime state directory metadata is unsafe"
else
    install -d -m 0755 -o root -g root "$STATE_DIR"
fi

case "${1:-}" in
    --clear)
        [ "$#" -eq 1 ] || fail "usage: noid-reboot-block-state --clear"
        if [ -e "$STATE" ] || [ -L "$STATE" ]; then
            [ -f "$STATE" ] && [ ! -L "$STATE" ] \
                && [ "$(stat -Lc '%u:%g:%a:%h' "$STATE")" = 0:0:644:1 ] \
                && [ "$(stat -Lc '%s' "$STATE")" -le 256 ] \
                || fail "existing reboot-block record is unsafe"
            rm -f -- "$STATE"
            sync -- "$STATE_DIR"
        fi
        ;;
    --publish)
        shift
        [ "$#" -ge 1 ] && [ "$#" -le 5 ] \
            || fail "publish requires one to five closed reason codes"
        kernel_cmdline=0
        initramfs=0
        bls_identity=0
        nvidia=0
        boot_inventory=0
        for reason in "$@"; do
            case "$reason" in
                kernel-cmdline) kernel_cmdline=1 ;;
                initramfs) initramfs=1 ;;
                bls-identity) bls_identity=1 ;;
                nvidia) nvidia=1 ;;
                boot-inventory) boot_inventory=1 ;;
                *) fail "unsupported reboot blocker: $reason" ;;
            esac
        done
        blockers=
        for entry in \
            "kernel-cmdline:$kernel_cmdline" \
            "initramfs:$initramfs" \
            "bls-identity:$bls_identity" \
            "nvidia:$nvidia" \
            "boot-inventory:$boot_inventory"; do
            [ "${entry##*:}" -eq 1 ] || continue
            reason=${entry%%:*}
            blockers=${blockers:+$blockers,}$reason
        done
        [ -n "$blockers" ] || fail "empty reboot blocker set"
        candidate=$(mktemp "$STATE_DIR/.reboot-blocked.XXXXXX")
        printf 'schema=1\nblockers=%s\n' "$blockers" > "$candidate"
        chown root:root "$candidate"
        chmod 0644 "$candidate"
        sync -- "$candidate"
        mv -fT -- "$candidate" "$STATE"
        candidate=
        sync -- "$STATE"
        sync -- "$STATE_DIR"
        ;;
    *)
        fail "usage: noid-reboot-block-state --clear | --publish <reason>..."
        ;;
esac
REBOOT_BLOCK_STATE_EOF
chmod 0755 /usr/libexec/noid-reboot-block-state
chown root:root /usr/libexec/noid-reboot-block-state

# Canonical, unprivileged reader used by the updater summary, GTK frontend,
# login notifier and NoID Privacy Tools. It reports two independent axes and fails
# closed on malformed safety evidence. Its pure resolver is exercised as a
# complete decision matrix by tests/25.
cat > /usr/libexec/noid-reboot-readiness <<'REBOOT_READINESS_EOF'
#!/usr/bin/bash
set -uo pipefail
PATH=/usr/sbin:/usr/bin
LC_ALL=C
export PATH LC_ALL

resolve_reboot_state() {
    local kernel_pending=${1:-} nvidia_pending=${2:-}
    local firmware_pending=${3:-} recommended=${4:-}
    local policy_pending=${5:-} blockers=${6:-}
    local flag
    for flag in "$kernel_pending" "$nvidia_pending" \
            "$firmware_pending" "$recommended" "$policy_pending"; do
        case "$flag" in 0|1) ;; *) return 2 ;; esac
    done
    case "$blockers" in
        '') return 2 ;;
        none) REBOOT_SAFETY=safe ;;
        *) REBOOT_SAFETY=blocked ;;
    esac
    if [ "$kernel_pending" -eq 1 ] || [ "$nvidia_pending" -eq 1 ] \
            || [ "$firmware_pending" -eq 1 ] \
            || [ "$policy_pending" -eq 1 ]; then
        REBOOT_ACTIVATION=required
    elif [ "$recommended" -eq 1 ]; then
        REBOOT_ACTIVATION=recommended
    else
        REBOOT_ACTIVATION=none
    fi
    REBOOT_BLOCKERS=$blockers
}

firmware_pending=0
recommended=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --firmware-required) firmware_pending=1 ;;
        --recommended) recommended=1 ;;
        --help|-h)
            echo "Usage: noid-reboot-readiness [--firmware-required] [--recommended]"
            exit 0
            ;;
        *) exit 2 ;;
    esac
    shift
done

kernel_cmdline=0
initramfs=0
bls_identity=0
nvidia=0
boot_inventory=0
state_unsafe=0
nvidia_state=0
add_blocker() {
    case "${1:-}" in
        kernel-cmdline) kernel_cmdline=1 ;;
        initramfs) initramfs=1 ;;
        bls-identity) bls_identity=1 ;;
        nvidia) nvidia=1 ;;
        boot-inventory) boot_inventory=1 ;;
        state-unsafe) state_unsafe=1 ;;
        nvidia-state) nvidia_state=1 ;;
        *) return 1 ;;
    esac
}

policy_pending=0
firstboot_marker=/var/lib/noid-privacy/.firstboot-cmdline-reboot-required
if [ -e "$firstboot_marker" ] || [ -L "$firstboot_marker" ]; then
    policy_pending=1
    [ -f "$firstboot_marker" ] && [ ! -L "$firstboot_marker" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' "$firstboot_marker" 2>/dev/null)" = 0:0:600:1 ] \
        && [ "$(stat -Lc '%s' "$firstboot_marker" 2>/dev/null || echo 0)" -eq 274 ] \
        || add_blocker state-unsafe
fi

block_state=/run/noid-privacy/reboot-blocked
if [ -e "$block_state" ] || [ -L "$block_state" ]; then
    if [ -f "$block_state" ] && [ ! -L "$block_state" ] \
            && [ "$(stat -Lc '%u:%g:%a:%h' "$block_state" 2>/dev/null)" = 0:0:644:1 ] \
            && [ "$(stat -Lc '%s' "$block_state" 2>/dev/null || echo 9999)" -le 256 ]; then
        mapfile -t state_rows < "$block_state" || state_rows=()
        if [ "${#state_rows[@]}" -eq 2 ] \
                && [ "${state_rows[0]}" = schema=1 ] \
                && [[ "${state_rows[1]}" == blockers=* ]]; then
            IFS=, read -r -a persisted_blockers \
                <<< "${state_rows[1]#blockers=}"
            [ "${#persisted_blockers[@]}" -ge 1 ] || add_blocker state-unsafe
            for reason in "${persisted_blockers[@]}"; do
                add_blocker "$reason" || add_blocker state-unsafe
            done
        else
            add_blocker state-unsafe
        fi
    else
        add_blocker state-unsafe
    fi
fi

nvidia_state_dir=/var/lib/noid-nvidia-integrity
nvidia_queue=$nvidia_state_dir/queue
nvidia_degraded=$nvidia_state_dir/degraded
nvidia_managed=0
if [ -e "$nvidia_state_dir" ] || [ -L "$nvidia_state_dir" ]; then
    if [ ! -d "$nvidia_state_dir" ] || [ -L "$nvidia_state_dir" ] \
            || [ "$(stat -Lc '%u:%g:%a' "$nvidia_state_dir" 2>/dev/null)" != 0:0:755 ]; then
        add_blocker nvidia-state
    else
        nvidia_managed=1
        # M19 publishes this durable record on interactive, queued-worker and
        # post-boot integrity failure. Its presence is independently
        # reboot-blocking even when no queue marker or live inhibitor remains.
        if [ -e "$nvidia_degraded" ] || [ -L "$nvidia_degraded" ]; then
            if [ -f "$nvidia_degraded" ] && [ ! -L "$nvidia_degraded" ] \
                    && [ "$(stat -Lc '%u:%g:%a:%h' "$nvidia_degraded" 2>/dev/null)" = 0:0:600:1 ]; then
                add_blocker nvidia
            else
                add_blocker nvidia-state
            fi
        fi
        if [ -e "$nvidia_queue" ] || [ -L "$nvidia_queue" ]; then
            if [ ! -d "$nvidia_queue" ] || [ -L "$nvidia_queue" ] \
                    || [ "$(stat -Lc '%u:%g:%a' "$nvidia_queue" 2>/dev/null)" != 0:0:755 ]; then
                add_blocker nvidia-state
            elif find "$nvidia_queue" -mindepth 1 -maxdepth 1 -type f \
                    \( -name '*.pending' -o -name '*.deferred' -o -name '*.failed' \) \
                    -print -quit 2>/dev/null | grep -q .; then
                add_blocker nvidia
            fi
        fi
    fi
fi
if [ "$nvidia_managed" -eq 1 ]; then
    guard_state=$(timeout 3 systemctl is-active \
        noid-nvidia-reboot-guard.service 2>/dev/null)
    guard_rc=$?
    case "$guard_rc:$guard_state" in
        0:active) add_blocker nvidia ;;
        3:inactive) ;;
        *) add_blocker nvidia-state ;;
    esac
fi

running_kernel=$(uname -r 2>/dev/null || true)
latest_kernel=$(find /lib/modules -mindepth 1 -maxdepth 1 -type d \
    -printf '%f\n' 2>/dev/null | sort -V | tail -1)
kernel_pending=0
if [ -z "$running_kernel" ] || [ -z "$latest_kernel" ]; then
    add_blocker boot-inventory
elif [ "$running_kernel" != "$latest_kernel" ]; then
    kernel_pending=1
fi

nvidia_version_file=/proc/driver/nvidia/version
nv_run=
if [ -e "$nvidia_version_file" ] || [ -L "$nvidia_version_file" ]; then
    if [ -f "$nvidia_version_file" ] && [ ! -L "$nvidia_version_file" ]; then
        nv_run=$(sed -n \
            -e 's/^NVRM version: NVIDIA UNIX [A-Za-z0-9_.+-]* Kernel Module  *\([0-9][0-9.]*\)  .*/\1/p' \
            -e 's/^NVRM version: NVIDIA UNIX Open Kernel Module for [A-Za-z0-9_.+-]*  *\([0-9][0-9.]*\)  .*/\1/p' \
            "$nvidia_version_file" 2>/dev/null | head -1)
        [[ "$nv_run" =~ ^[0-9]+(\.[0-9]+){1,3}$ ]] \
            || add_blocker nvidia-state
    else
        add_blocker nvidia-state
    fi
fi
nv_disk=$(modinfo -F version nvidia 2>/dev/null || true)
nvidia_pending=0
if [ -n "$nv_run" ] && [ -z "$nv_disk" ]; then
    add_blocker nvidia-state
elif [ -n "$nv_run" ] && [ -n "$nv_disk" ] && [ "$nv_run" != "$nv_disk" ]; then
    nvidia_pending=1
elif [ -z "$nv_run" ] && [ -n "$nv_disk" ] \
        && find "$nvidia_state_dir" -maxdepth 1 -type f -name '*.prepared' \
            -print -quit 2>/dev/null | grep -q .; then
    nvidia_pending=1
fi

blockers=
for entry in \
    "kernel-cmdline:$kernel_cmdline" \
    "initramfs:$initramfs" \
    "bls-identity:$bls_identity" \
    "nvidia:$nvidia" \
    "boot-inventory:$boot_inventory" \
    "state-unsafe:$state_unsafe" \
    "nvidia-state:$nvidia_state"; do
    [ "${entry##*:}" -eq 1 ] || continue
    reason=${entry%%:*}
    blockers=${blockers:+$blockers,}$reason
done
blockers=${blockers:-none}
resolve_reboot_state "$kernel_pending" "$nvidia_pending" \
    "$firmware_pending" "$recommended" "$policy_pending" "$blockers" \
    || exit 1
printf 'schema=1\nactivation=%s\nsafety=%s\nblockers=%s\n' \
    "$REBOOT_ACTIVATION" "$REBOOT_SAFETY" "$REBOOT_BLOCKERS"
printf 'running_kernel=%s\nlatest_kernel=%s\n' \
    "${running_kernel:-unavailable}" "${latest_kernel:-unavailable}"
printf 'nvidia_running=%s\nnvidia_installed=%s\n' \
    "${nv_run:-unavailable}" "${nv_disk:-unavailable}"
REBOOT_READINESS_EOF
chmod 0755 /usr/libexec/noid-reboot-readiness
chown root:root /usr/libexec/noid-reboot-readiness

# The guardian is deliberately tiny and unprivileged. flock(1) execs it with
# --no-fork only after opening and locking the canonical path, so its live PID
# is also the kernel lock
# owner recorded in /proc/locks. It exits when the exact updater identity dies.
cat > /usr/libexec/noid-update-lock-guardian <<'NOID_UPDATE_LOCK_GUARD_EOF'
#!/usr/bin/bash
set -euo pipefail

parent_pid=${1:-}
parent_start=${2:-}
ready_file=${3:-}
case "$parent_pid:$parent_start" in
    *[!0-9:]*|:*|*:) exit 1 ;;
esac
[ "$#" -eq 3 ] || exit 1
[ "$PPID" = "$parent_pid" ] || exit 1
[ -f "$ready_file" ] && [ ! -L "$ready_file" ] \
    && [ "$(stat -c '%u:%a:%h' "$ready_file")" = "$(id -u):600:1" ] \
    || exit 1

parent_matches() {
    local proc_stat proc_tail
    local -a proc_fields=()
    [ -r "/proc/$parent_pid/stat" ] || return 1
    proc_stat=$(<"/proc/$parent_pid/stat") || return 1
    proc_tail=${proc_stat##*) }
    [ "$proc_tail" != "$proc_stat" ] || return 1
    read -r -a proc_fields <<<"$proc_tail"
    [ "${#proc_fields[@]}" -ge 20 ] \
        && [ "${proc_fields[19]}" = "$parent_start" ]
}

parent_matches || exit 1
printf 'ready\n' >"$ready_file"
sync -- "$ready_file"
trap 'exit 0' HUP INT TERM
while parent_matches; do
    sleep 1
done
NOID_UPDATE_LOCK_GUARD_EOF
chmod 0755 /usr/libexec/noid-update-lock-guardian
chown root:root /usr/libexec/noid-update-lock-guardian

# A marker is not an authority. This read-only helper accepts an update window
# only when the exact non-root updater process is still alive, has the recorded
# start time and UID, names the canonical script in argv, and has a live child
# guardian that owns the exact kernel FLOCK. Stale files, PID reuse, malformed
# schemas, symlinks and unlocked lookalikes all fail shut.
cat > /usr/libexec/noid-update-window-active <<'NOID_UPDATE_WINDOW_EOF'
#!/usr/bin/bash
set -euo pipefail
PATH=/usr/sbin:/usr/bin

MARKER=/run/noid-update-running
LOCK=/run/lock/noid-update-all.lock
UPDATER=/usr/local/bin/noid-update-all.sh
GUARDIAN=/usr/libexec/noid-update-lock-guardian

inactive() { exit 1; }

process_matches() {
    local proc_stat proc_tail proc_uid
    local -a proc_fields=()
    [ -r "/proc/$pid/stat" ] && [ -r "/proc/$pid/status" ] \
        && [ -r "/proc/$pid/cmdline" ] || return 1
    proc_stat=$(<"/proc/$pid/stat") || return 1
    proc_tail=${proc_stat##*) }
    [ "$proc_tail" != "$proc_stat" ] || return 1
    read -r -a proc_fields <<<"$proc_tail"
    [ "${#proc_fields[@]}" -ge 20 ] \
        && [ "${proc_fields[19]}" = "$start_time" ] || return 1
    proc_uid=$(awk '/^Uid:/ { print $2; exit }' "/proc/$pid/status")
    [ "$proc_uid" = "$uid" ] || return 1
    tr '\0' '\n' <"/proc/$pid/cmdline" | grep -Fqx -- "$UPDATER" \
        || return 1
    return 0
}

guardian_matches() {
    local proc_uid proc_ppid fd target lock_inode found_argv=0 index
    local -a argv=()
    [ -r "/proc/$lock_pid/status" ] && [ -r "/proc/$lock_pid/cmdline" ] \
        || return 1
    proc_uid=$(awk '/^Uid:/ { print $2; exit }' "/proc/$lock_pid/status")
    proc_ppid=$(awk '/^PPid:/ { print $2; exit }' "/proc/$lock_pid/status")
    [ "$proc_uid" = "$uid" ] && [ "$proc_ppid" = "$pid" ] || return 1
    mapfile -d '' -t argv <"/proc/$lock_pid/cmdline" || return 1
    for ((index=0; index + 2 < ${#argv[@]}; index++)); do
        if [ "${argv[index]}" = "$GUARDIAN" ] \
                && [ "${argv[index + 1]}" = "$pid" ] \
                && [ "${argv[index + 2]}" = "$start_time" ]; then
            found_argv=1
        fi
    done
    [ "$found_argv" -eq 1 ] || return 1
    for fd in "/proc/$lock_pid/fd/"*; do
        target=$(readlink -f -- "$fd" 2>/dev/null || true)
        [ "$target" = "$LOCK" ] && break
        target=
    done
    [ "$target" = "$LOCK" ] || return 1
    lock_inode=$(stat -c '%i' "$LOCK")
    awk -v owner="$lock_pid" -v inode="$lock_inode" '
        $2 == "FLOCK" && $4 == "WRITE" && $5 == owner {
            split($6, identity, ":")
            if (identity[3] == inode) found=1
        }
        END { exit !found }
    ' /proc/locks
}

[ "$#" -eq 0 ] || inactive
[ "$(id -u)" -eq 0 ] || inactive
[ -f "$MARKER" ] && [ ! -L "$MARKER" ] \
    && [ "$(stat -c '%U:%G:%a:%h' "$MARKER" 2>/dev/null || true)" = root:root:600:1 ] \
    && [ "$(stat -c '%s' "$MARKER" 2>/dev/null || echo 9999)" -le 192 ] \
    || inactive
[ -f "$LOCK" ] && [ ! -L "$LOCK" ] \
    && [ "$(stat -c '%U:%G:%a' "$LOCK" 2>/dev/null || true)" = root:wheel:660 ] \
    || inactive

mapfile -t rows <"$MARKER" || inactive
[ "${#rows[@]}" -eq 4 ] || inactive
[[ "${rows[0]}" =~ ^pid=([1-9][0-9]*)$ ]] || inactive
pid=${BASH_REMATCH[1]}
[[ "${rows[1]}" =~ ^start_time=([1-9][0-9]*)$ ]] || inactive
start_time=${BASH_REMATCH[1]}
[[ "${rows[2]}" =~ ^uid=([1-9][0-9]*)$ ]] || inactive
uid=${BASH_REMATCH[1]}
[[ "${rows[3]}" =~ ^lock_pid=([1-9][0-9]*)$ ]] || inactive
lock_pid=${BASH_REMATCH[1]}
[ "$lock_pid" != "$pid" ] || inactive

process_matches || inactive
guardian_matches || inactive
exec 9<>"$LOCK" || inactive
if flock --nonblock 9; then
    flock -u 9
    inactive
fi
# Close the TOCTOU window in which the recorded owner could die after the
# first /proc check and a different process could acquire the same lock.
process_matches || inactive
guardian_matches || inactive
exit 0
NOID_UPDATE_WINDOW_EOF
chmod 0755 /usr/libexec/noid-update-lock-guardian \
    /usr/libexec/noid-update-window-active
chown root:root /usr/libexec/noid-update-lock-guardian \
    /usr/libexec/noid-update-window-active
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/libexec/noid-update-lock-guardian \
        /usr/libexec/noid-update-window-active
fi

# /run is tmpfs, so materialize the cross-session workflow lock both for this
# image build and on every installed-system boot. Anaconda's first user is in
# wheel; non-wheel accounts cannot run the privileged update workflow anyway.
mkdir -p /usr/lib/tmpfiles.d /run/lock
cat > /usr/lib/tmpfiles.d/noid-update-lock.conf <<'NOID_UPDATE_LOCK_EOF'
f /run/lock/noid-update-all.lock 0660 root wheel -
NOID_UPDATE_LOCK_EOF
chmod 0644 /usr/lib/tmpfiles.d/noid-update-lock.conf
chown root:root /usr/lib/tmpfiles.d/noid-update-lock.conf
install -m 0660 -o root -g wheel /dev/null /run/lock/noid-update-all.lock

# ----------------------------------------------------------------------------
# Step 1b (retired): no VSCodium extension is image-staged
# ----------------------------------------------------------------------------
# Neither vendor extension ships in /etc/skel. The M13 installers offer the
# Claude Code and Codex extensions behind their own informed opt-in prompts,
# so no third-party extension code activates before an explicit user choice.
# The noid-codex-install helper offers its VSIX behind a separate informed
# opt-in, and noid-claude-install now mirrors that structure exactly.
# ----------------------------------------------------------------------------
# Step 2: Install systemd user timer + service
# ----------------------------------------------------------------------------
# Path: /etc/systemd/user/noid-update-reminder.{service,timer}
# Auto-enable via: /etc/systemd/user-preset/50-noid-update.preset
#
# Every user who logs in will get the reminder.

echo ""
echo "[Step 2] Installing systemd user timer + service"

mkdir -p /etc/systemd/user /etc/systemd/user-preset

cat > /etc/systemd/user/noid-update-reminder.service <<'SERVICE_EOF'
[Unit]
Description=NoID Privacy — Weekly update reminder notification
Documentation=https://noid-privacy.com

[Service]
Type=oneshot
ExecStart=/usr/bin/notify-send \
    --urgency=normal \
    --icon=/usr/share/pixmaps/noid-privacy-logo.png \
    --app-name="NoID Privacy" \
    --expire-time=30000 \
    "Weekly system update due" \
    "Time for your update.\n\nClick the 'NoID Privacy Update' icon in the Dash, OR run from a terminal:\n\n    /usr/local/bin/noid-update-all.sh\n\nDuration: 5-15 min depending on number of updates."
SERVICE_EOF

cat > /etc/systemd/user/noid-update-reminder.timer <<'TIMER_EOF'
[Unit]
Description=NoID Privacy — Weekly update reminder trigger
Documentation=https://noid-privacy.com

[Timer]
# Every Monday at 10:00, with 1 hour random delay (fire between 10:00-11:00)
OnCalendar=Mon *-*-* 10:00:00
RandomizedDelaySec=1h
# AccuracySec=1min explicit (drift-proof against
# future systemd default change). Per ArchWiki systemd/Timers: default 1min
# is canonical for weekly-reminder pattern (sub-minute precision unnecessary,
# absolute precision wastes scheduler wakeups). RandomizedDelaySec=1h dominates
# anyway — actual fire window is 10:00:00 + [0..1h] + [0..1min].
AccuracySec=1min
# Persistent=true catches missed fires (e.g. machine was offline on Monday)
# and fires as soon as user logs in next.
Persistent=true

[Install]
WantedBy=timers.target
TIMER_EOF

chmod 644 /etc/systemd/user/noid-update-reminder.service
chmod 644 /etc/systemd/user/noid-update-reminder.timer

echo "  [OK] /etc/systemd/user/noid-update-reminder.service"
echo "  [OK] /etc/systemd/user/noid-update-reminder.timer"

# ----------------------------------------------------------------------------
# Step 3: Auto-enable timer for all users via preset
# ----------------------------------------------------------------------------
# Preset files are inert until systemctl applies them. M17's
# noid-user-firstrun runs `systemctl --user preset noid-update-reminder.timer`
# at first login and verifies that the timer became enabled.
# /etc/systemd/user-preset/ is local admin override of /usr/lib/systemd/user-preset/
# Format: one "enable <unit>" or "disable <unit>" line per file.

cat > /etc/systemd/user-preset/50-noid-update.preset <<'PRESET_EOF'
# NoID Privacy — auto-enable update reminder timer for all users
# Applied explicitly by M17's noid-user-firstrun at first login
enable noid-update-reminder.timer
PRESET_EOF

chmod 644 /etc/systemd/user-preset/50-noid-update.preset
echo "  [OK] /etc/systemd/user-preset/50-noid-update.preset"

# ----------------------------------------------------------------------------
# Step 3b: Login-time canonical reboot-readiness notifier
# ----------------------------------------------------------------------------
# xdg autostart on every GNOME login. Activation is a direct live comparison;
# safety consumes the closed boot-scoped record owned by the root publisher.
# Re-nags every session until activation completed or the blocker was repaired.

echo ""
echo "[Step 3b] Installing kernel-reboot-required login notifier"

cat > /usr/local/bin/noid-pending-reboot-check.sh <<'PENDING_REBOOT_EOF'
#!/bin/bash
# noid-pending-reboot-check.sh — present the canonical activation/safety state

set -u

MODE=notify
usage() {
    cat <<'USAGE_EOF'
Usage: noid-pending-reboot-check.sh [--status|--help]

  (no args)  Login notifier: wait for GNOME, notify only when action is needed
  --status   Print the current kernel/NVIDIA reboot state immediately
  --help     Show this help
USAGE_EOF
}

case "$#:${1:-}" in
    0:) ;;
    1:status|1:--status) MODE=status ;;
    1:-h|1:--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac

# Skip in live-ISO mode (no kernel updates can happen on tmpfs overlay)
if grep -qE 'rd\.live\.image|boot=live' /proc/cmdline 2>/dev/null; then
    if [ "$MODE" = status ]; then
        echo "NoID Privacy — Pending Reboot"
        echo "  Live image: no persistent kernel update can be activated here"
        echo "  Reboot required: no"
    fi
    exit 0
fi

# The autostart mode waits for GNOME's notification service. Interactive
# `--status` is deliberately independent of the graphical session and returns
# immediately, which makes it suitable for NoID Privacy Tools and terminals.
if [ "$MODE" = notify ]; then
    sleep 15
    [ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ] || exit 0
fi

# Audit-storage degradation re-nag (M12 owns the boot-scoped /run marker): its
# existence is user-visible even though its root-only content is not. M12's
# path unit covers the mid-session moment; this covers later logins in the same
# boot while the state persists.
audit_storage_degraded=0
[ -e /run/noid-privacy/audit-storage-degraded ] \
    && audit_storage_degraded=1
if [ "$MODE" = notify ] && [ "$audit_storage_degraded" -eq 1 ]; then
    notify-send \
        --urgency=critical \
        --icon=drive-harddisk \
        --app-name="NoID Privacy" \
        --expire-time=0 \
        "Audit storage degraded — action required" \
        "Free disk space, then check: noid-status\nIf audit logging was suspended, resume it: sudo auditctl --signal resume" \
        2>/dev/null || true
fi

# Read one exact record. A missing/malformed helper is itself a blocker: callers
# must never fall back to an activation-only heuristic that can offer reboot
# while a durable NVIDIA task or boot-contract failure remains active.
readiness=()
mapfile -t readiness < <(/usr/libexec/noid-reboot-readiness 2>/dev/null)
if [ "${#readiness[@]}" -eq 8 ] && [ "${readiness[0]}" = schema=1 ] \
        && [[ "${readiness[1]}" =~ ^activation=(required|recommended|none)$ ]] \
        && [[ "${readiness[2]}" =~ ^safety=(safe|blocked)$ ]] \
        && [[ "${readiness[3]}" =~ ^blockers=[a-z-]+(,[a-z-]+)*$ ]] \
        && [[ "${readiness[4]}" =~ ^running_kernel=[A-Za-z0-9._+-]+$ ]] \
        && [[ "${readiness[5]}" =~ ^latest_kernel=[A-Za-z0-9._+-]+$ ]] \
        && [[ "${readiness[6]}" =~ ^nvidia_running=[A-Za-z0-9._+-]+$ ]] \
        && [[ "${readiness[7]}" =~ ^nvidia_installed=[A-Za-z0-9._+-]+$ ]]; then
    activation=${readiness[1]#activation=}
    safety=${readiness[2]#safety=}
    blockers=${readiness[3]#blockers=}
    running_kernel=${readiness[4]#running_kernel=}
    latest_kernel=${readiness[5]#latest_kernel=}
    nv_run=${readiness[6]#nvidia_running=}
    nv_disk=${readiness[7]#nvidia_installed=}
    case "$safety:$blockers" in
        safe:none) ;;
        blocked:none|safe:*) safety=blocked; blockers=state-unsafe ;;
        blocked:*)
            IFS=, read -r -a blocker_rows <<< "$blockers"
            for blocker in "${blocker_rows[@]}"; do
                case "$blocker" in
                    kernel-cmdline|initramfs|bls-identity|nvidia|boot-inventory|state-unsafe|nvidia-state) ;;
                    *) safety=blocked; blockers=state-unsafe; break ;;
                esac
            done
            ;;
        *) safety=blocked; blockers=state-unsafe ;;
    esac
else
    activation=none
    safety=blocked
    blockers=state-unsafe
    running_kernel=unavailable
    latest_kernel=unavailable
    nv_run=unavailable
    nv_disk=unavailable
fi

# Human-readable immediate status. This path performs no notification, sleep,
# privileged operation or state write; a pending reboot is a state, not a CLI
# execution failure, so successful inspection always exits zero.
if [ "$MODE" = status ]; then
    FMT_LIB=/usr/local/lib/noid-privacy/agent-install-format.sh
    # shellcheck source=/dev/null
    if [ -r "$FMT_LIB" ]; then
        . "$FMT_LIB"
    else
        fmt_banner() { echo "$1"; [ -z "${2:-}" ] || echo "  $2"; }
        fmt_ok() { echo "  OK: $1"; }
        fmt_info() { echo "  - $1"; }
        fmt_warn() { echo "  ! $1" >&2; }
    fi
    fmt_banner "NoID Privacy — Pending Reboot" \
        "kernel and NVIDIA activation state"
    fmt_info "Running kernel: ${running_kernel}"
    if [ "$latest_kernel" != unavailable ]; then
        fmt_info "Newest installed kernel: ${latest_kernel}"
    else
        fmt_warn "No installed kernel directory could be determined"
    fi
    if [ "$nv_run" != unavailable ] || [ "$nv_disk" != unavailable ]; then
        fmt_info "NVIDIA module: running=${nv_run}, installed=${nv_disk}"
    else
        fmt_info "NVIDIA module: not loaded/installed"
    fi
    if [ "$audit_storage_degraded" -eq 1 ]; then
        fmt_warn "Audit storage is degraded; inspect noid-status"
    else
        fmt_ok "Audit storage degradation marker is absent"
    fi
    if [ "$safety" = blocked ]; then
        fmt_warn "Restart safety: BLOCKED — repair ${blockers} first"
        [ "$activation" = none ] \
            || fmt_info "Update activation remains ${activation} after repair"
    elif [ "$activation" = required ]; then
        fmt_warn "Reboot required and verified safe"
    elif [ "$activation" = recommended ]; then
        fmt_warn "Reboot recommended and verified safe"
    else
        fmt_ok "Reboot required: no"
    fi
    exit 0
fi

# A blocker is always actionable even without a version delta. Never place a
# reboot command in this notification.
if [ "$safety" = blocked ]; then
    recovery="Run NoID Privacy Update again and review its boot-repair step."
    case ",$blockers," in
        *,nvidia,*)
            recovery="Resume the verified NVIDIA queue:\n    sudo /usr/libexec/noid-nvidia-initramfs-queue --resume\nThen run NoID Privacy Update again."
            ;;
    esac
    notify-send \
        --urgency=critical \
        --icon=software-update-urgent \
        --app-name="NoID Privacy" \
        --expire-time=0 \
        "Restart blocked — boot repair required" \
        "Safety checks: ${blockers}\n\n${recovery}" \
        2>/dev/null || true
    exit 0
fi

# Nothing hard-pending → silent login path. The updater summary still presents
# a soft recommendation when DNF supplied one during that explicit run.
[ "$activation" = required ] || exit 0

notify-send \
    --urgency=critical \
    --icon=system-reboot-symbolic \
    --app-name="NoID Privacy" \
    --expire-time=0 \
    "Verified system changes — REBOOT REQUIRED" \
    "A verified boot-policy or update activation is pending.\n\nRunning kernel: ${running_kernel}\nNewest installed: ${latest_kernel}\nNVIDIA: running=${nv_run}, installed=${nv_disk}\n\nBoot safety is verified. Reboot to activate:\n    sudo reboot" \
    2>/dev/null || true

exit 0
PENDING_REBOOT_EOF

chmod 755 /usr/local/bin/noid-pending-reboot-check.sh
chown root:root /usr/local/bin/noid-pending-reboot-check.sh
echo "  [OK] /usr/local/bin/noid-pending-reboot-check.sh (755)"

# xdg autostart entry
cat > /etc/xdg/autostart/noid-pending-reboot.desktop <<'AUTOSTART_EOF'
[Desktop Entry]
Type=Application
Name=NoID Privacy Pending-Reboot Check
Comment=Check whether verified system changes require a reboot
Exec=/usr/local/bin/noid-pending-reboot-check.sh
NoDisplay=true
Terminal=false
X-GNOME-Autostart-enabled=true
# NOTE: X-GNOME-Autostart-Phase deliberately NOT set.
# GNOME 49+ (Fedora 44 ships GNOME 50) rejects this key. The script's
# own `sleep 15` + D-Bus-readiness check replaces the phase-control
# semantic — notification fires only once shell + notification daemon
# are both ready.
AUTOSTART_EOF
chmod 644 /etc/xdg/autostart/noid-pending-reboot.desktop
chown root:root /etc/xdg/autostart/noid-pending-reboot.desktop
echo "  [OK] /etc/xdg/autostart/noid-pending-reboot.desktop (644)"

# ----------------------------------------------------------------------------
# Step 3c: GTK4 update GUI + launcher + desktop entry
# ----------------------------------------------------------------------------
# Ships the NoID Privacy Update app — a GTK4 + libadwaita + Vte GUI that wraps
# noid-update-all.sh in a real pty (interactive prompts work natively; one
# graphical sudo prompt via the askpass below + the script's keep-alive). The
# .desktop launches the GUI directly (Icon noid-privacy-update from M32); the
# launcher script is kept as a robust GUI-or-terminal entry point. One of the
# four first-party GTK4 apps beside Setup, Network and Tools. Needs vte291-gtk4 (M26).
echo ""
echo "[Step 3c] Installing GTK4 update GUI + launcher + desktop entry"

cat > /usr/local/bin/noid-update <<'NOID_UPDATE_APP_EOF'
#!/usr/bin/python3
"""NoID Privacy Update — GTK4 + libadwaita + Vte system-update GUI.

Adw-native: a step checklist is the hero (green check / spinner / pending dot);
the real terminal (Vte) is a collapsible log. The single sudo password is asked
via a GRAPHICAL askpass dialog (sudo -A) instead of the terminal, so the log can
stay collapsed and nothing needs scrolling. fwupd's interactive [y/N] still uses
the terminal and auto-reveals the log on a PROMPT marker.

Wraps /usr/local/bin/noid-update-all.sh in a real pty. Runs UNPRIVILEGED.
English UI to match the other NoID Privacy first-party apps (noid-network, noid-welcome).
"""

import os
import sys
import subprocess
import tempfile

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
gi.require_version('Vte', '3.91')
from gi.repository import Gtk, Adw, Vte, GLib, Gio, Pango, Gdk
sys.path.insert(0, '/usr/lib/noid-privacy')
import noid_ui

APP_ID = 'com.noidprivacy.Update'
UPDATE_SCRIPT = '/usr/local/bin/noid-update-all.sh'
ASKPASS = '/usr/local/bin/noid-askpass'
TOTAL_STEPS = 10

# GUI checklist rows. Sub-steps 5b/6b/6c share their semantic parent row;
# config-drift evidence (8b) has its own row and shifts reboot to row 10.
STEP_LABELS = [
    ('Snapshot',          'Pre-snapshot (CLI rollback point)'),
    ('System packages',   'DNF (RPM) + kernel/NVIDIA if needed'),
    ('Flatpak',           'System + user apps'),
    ('Firmware',          'fwupd'),
    ('Firefox hardening', 'NoID Privacy user.js + Thunderbird'),
    ('Agents + extensions', 'Consent-gated agents + editor/GNOME updates'),
    ('Repo check',        'Signatures + reachability'),
    ('AIDE integrity',    'Check-only evidence (no baseline replacement)'),
    ('Config drift',      '.rpmnew / .rpmsave evidence'),
    ('Reboot check',      'Kernel/services'),
]

STEP_MARKER_ROWS = {
    '1': 1, '2': 2, '3': 3, '4': 4,
    '5': 5, '5b': 5,
    '6': 6, '6b': 6, '6c': 6,
    '7': 7, '8': 8, '8b': 9, '9': 10,
}


def _marker_row(token):
    return STEP_MARKER_ROWS.get(token)

UPDATE_CSS = b"""
.noid-hero-title { font-size: 1.4rem; font-weight: 800; }
.noid-step-num { opacity: 0.5; font-feature-settings: "tnum"; min-width: 1.5rem; }
.noid-count { font-size: 1.1rem; }
.noid-done { color: @success_color; }
.noid-error { color: @error_color; }
.noid-pending { opacity: 0.35; }
"""


def _completion_snapshot(current_step, status, error_steps=None):
    """Return per-step checklist states, completed count and progress fraction.

    error_steps carries the orchestrator's STEPFAIL attribution (steps whose
    ERRORS delta was non-zero). With it, exactly the failing steps show as
    errors and every other reached step stays done. Without it (crash before
    any attribution arrived), the last reached step takes the blame."""
    errors = set(error_steps or ())
    if status == 0:
        return ['done'] * TOTAL_STEPS, TOTAL_STEPS, 1.0
    current = max(0, min(current_step, TOTAL_STEPS))
    states = []
    for i in range(1, current + 1):
        if i in errors or (i == current and not errors):
            states.append('error')
        else:
            states.append('done')
    states.extend(['pending'] * (TOTAL_STEPS - len(states)))
    completed = states.count('done')
    return states, completed, completed / float(TOTAL_STEPS)


class UpdateWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app,
                         default_width=noid_ui.DEFAULT_WIDTH,
                         default_height=noid_ui.DEFAULT_HEIGHT)
        self.set_title('NoID Privacy Update')

        self.marker_path = None
        self.marker_offset = 0
        self.poll_id = 0
        self.running = False
        self.cancelled_before_start = False
        self.cur_step = 0
        self.step_errors = set()    # STEPFAIL attribution from the orchestrator
        self.warning_count = 0      # final non-blocking WARNINGS summary marker
        self.step_stacks = []
        self.step_images = []
        self.step_spinners = []
        self._reboot_activation = None
        self._reboot_safety = None
        self._reboot_blockers = None

        toolbar = Adw.ToolbarView()
        self.set_content(toolbar)

        header = noid_ui.app_header(
            'NoID Privacy Update', 'User-controlled system maintenance',
            'noid-privacy-update')
        toolbar.add_top_bar(header)

        self.toast_overlay = Adw.ToastOverlay()
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.toast_overlay.set_child(self.stack)
        toolbar.set_content(self.toast_overlay)
        self.stack.add_named(self._build_idle_page(), 'idle')
        self.stack.add_named(self._build_run_page(), 'run')
        self.stack.set_visible_child_name('idle')

        self.connect('close-request', self._on_close_request)

    # --- pages ---------------------------------------------------------------

    def _build_idle_page(self):
        status = Adw.StatusPage()
        status.set_icon_name('noid-privacy-update')
        status.set_title('Keep your system up to date')
        status.set_description(
            'Packages, Flatpaks, firmware, browser hardening and an integrity '
            'check in one run — you are asked for your password only once.')

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.set_halign(Gtk.Align.CENTER)
        box.set_size_request(500, -1)

        evidence_clamp = Adw.Clamp()
        evidence_clamp.set_maximum_size(420)
        evidence_clamp.set_tightening_threshold(340)
        evidence_clamp.set_margin_top(4)

        evidence = Adw.PreferencesGroup()
        evidence.set_title('After the update')
        self.aide_check = Adw.SwitchRow()
        self.aide_check.set_title('Verify files with AIDE')
        self.aide_check.set_subtitle(
            'Recommended — compare with your reviewed baseline; never replace it')
        self.aide_check.set_active(True)
        noid_ui.add_emoji_prefix(self.aide_check, '🛡️')
        evidence.add(self.aide_check)
        evidence_clamp.set_child(evidence)
        box.append(evidence_clamp)

        start = Gtk.Button(label='Start Update')
        start.add_css_class('suggested-action')
        start.add_css_class('pill')
        start.set_halign(Gtk.Align.CENTER)
        noid_ui.accessible(
            start, 'Start Update',
            'Begin the visible user-controlled system update workflow')
        start.connect('clicked', self._on_start)
        box.append(start)

        status.set_child(box)
        return status

    def _make_status_widget(self):
        """suffix = a Stack holding a state Image + a Spinner."""
        st = Gtk.Stack()
        img = Gtk.Image.new_from_icon_name('media-record-symbolic')
        img.add_css_class('noid-pending')
        img.set_accessible_role(Gtk.AccessibleRole.PRESENTATION)
        spin = Gtk.Spinner()
        spin.set_accessible_role(Gtk.AccessibleRole.PRESENTATION)
        st.add_named(img, 'icon')
        st.add_named(spin, 'spin')
        st.set_visible_child_name('icon')
        self.step_stacks.append(st)
        self.step_images.append(img)
        self.step_spinners.append(spin)
        return st

    def _build_run_page(self):
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)

        clamp = Adw.Clamp()
        clamp.set_maximum_size(620)
        clamp.set_margin_top(20)
        clamp.set_margin_bottom(12)
        clamp.set_margin_start(12)
        clamp.set_margin_end(12)
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(body)

        head = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.hero_title = Gtk.Label(label='Updating your system…', xalign=0)
        self.hero_title.add_css_class('noid-hero-title')
        self.hero_title.set_hexpand(True)
        self.hero_title.set_halign(Gtk.Align.START)
        row.append(self.hero_title)
        self.count_lbl = Gtk.Label(label='0 of %d complete' % TOTAL_STEPS)
        self.count_lbl.add_css_class('noid-count')
        row.append(self.count_lbl)
        head.append(row)
        self.progress = Gtk.ProgressBar()
        self.progress.set_fraction(0.0)
        head.append(self.progress)
        self.cur_lbl = Gtk.Label(label='', xalign=0)
        self.cur_lbl.add_css_class('dim-label')
        self.cur_lbl.set_halign(Gtk.Align.START)
        self.cur_lbl.set_wrap(True)
        head.append(self.cur_lbl)
        body.append(head)

        self.banner = Adw.Banner()
        self.banner.set_revealed(False)
        body.append(self.banner)

        self.done_btnbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.done_btnbox.set_halign(Gtk.Align.CENTER)
        self.done_btnbox.set_visible(False)
        body.append(self.done_btnbox)

        self.log_expander = Gtk.Expander(label='Show log')
        self.term = Vte.Terminal()
        self.term.set_scrollback_lines(200000)
        self.term.set_vexpand(True)
        try:
            self.term.set_font(Pango.FontDescription.from_string('Monospace 10'))
        except (TypeError, GLib.Error) as exc:
            print('Cannot set terminal font: %s' % exc, file=sys.stderr)
        self.term.connect('child-exited', self._on_child_exited)

        # Vte clipboard + context-menu (Ctrl+Shift+C/V/A + right-click).
        # Vte 0.78+ ships built-in shortcut-handling but an explicit
        # Gtk.ShortcutController guarantees consistent behavior across Vte
        # versions on Fedora 44+. Right-click via Gtk.GestureClick →
        # Gtk.PopoverMenu (GTK4 idiom; GTK3's TextView right-click context-
        # menu is gone). Action-group 'term' owns the three verbs.
        _term_ag = Gio.SimpleActionGroup()
        _ac_copy = Gio.SimpleAction.new('copy', None)
        _ac_copy.connect('activate',
                          lambda *a: self.term.copy_clipboard_format(Vte.Format.TEXT))
        _term_ag.add_action(_ac_copy)
        _ac_paste = Gio.SimpleAction.new('paste', None)
        _ac_paste.connect('activate', lambda *a: self.term.paste_clipboard())
        _term_ag.add_action(_ac_paste)
        _ac_selall = Gio.SimpleAction.new('select-all', None)
        _ac_selall.connect('activate', lambda *a: self.term.select_all())
        _term_ag.add_action(_ac_selall)
        self.term.insert_action_group('term', _term_ag)

        _sc = Gtk.ShortcutController()
        _sc.set_scope(Gtk.ShortcutScope.LOCAL)
        for _trigger, _action in (
            ('<Control><Shift>c', 'term.copy'),
            ('<Control><Shift>v', 'term.paste'),
            ('<Control><Shift>a', 'term.select-all'),
        ):
            _sc.add_shortcut(Gtk.Shortcut.new(
                Gtk.ShortcutTrigger.parse_string(_trigger),
                Gtk.NamedAction.new(_action),
            ))
        self.term.add_controller(_sc)

        _menu = Gio.Menu()
        _menu.append('Copy (Ctrl+Shift+C)', 'term.copy')
        _menu.append('Paste (Ctrl+Shift+V)', 'term.paste')
        _menu.append('Select All (Ctrl+Shift+A)', 'term.select-all')
        self._term_popover = Gtk.PopoverMenu.new_from_model(_menu)
        self._term_popover.set_parent(self.term)
        self._term_popover.set_has_arrow(False)

        _gc = Gtk.GestureClick.new()
        _gc.set_button(Gdk.BUTTON_SECONDARY)
        def _on_term_right_click(_gesture, _n_press, x, y):
            _r = Gdk.Rectangle()
            _r.x = int(x); _r.y = int(y); _r.width = 1; _r.height = 1
            self._term_popover.set_pointing_to(_r)
            self._term_popover.popup()
        _gc.connect('pressed', _on_term_right_click)
        self.term.add_controller(_gc)

        term_scroll = Gtk.ScrolledWindow()
        term_scroll.set_child(self.term)
        term_scroll.set_min_content_height(280)
        term_scroll.set_vexpand(True)
        self.log_expander.set_child(term_scroll)
        body.append(self.log_expander)

        self.steps_group = Adw.PreferencesGroup()
        for i, (label, sub) in enumerate(STEP_LABELS, start=1):
            r = Adw.ActionRow()
            r.set_title(label)
            r.set_subtitle(sub)
            num = Gtk.Label(label='%d' % i)
            num.add_css_class('noid-step-num')
            num.set_accessible_role(Gtk.AccessibleRole.PRESENTATION)
            r.add_prefix(num)
            r.add_suffix(self._make_status_widget())
            noid_ui.accessible_row(r)
            self.steps_group.add(r)
        body.append(self.steps_group)

        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_vexpand(True)
        scroller.set_child(clamp)
        outer.append(scroller)
        return outer

    # --- step state ----------------------------------------------------------

    def _mark(self, i, state):
        if i < 0 or i >= len(self.step_stacks):
            return
        img, spin, st = self.step_images[i], self.step_spinners[i], self.step_stacks[i]
        for c in ('noid-pending', 'noid-done', 'noid-error'):
            img.remove_css_class(c)
        if state == 'running':
            st.set_visible_child_name('spin')
            spin.start()
            return
        spin.stop()
        st.set_visible_child_name('icon')
        if state == 'done':
            img.set_from_icon_name('object-select-symbolic')
            img.add_css_class('noid-done')
        elif state == 'error':
            img.set_from_icon_name('dialog-error-symbolic')
            img.add_css_class('noid-error')
        else:  # pending
            img.set_from_icon_name('media-record-symbolic')
            img.add_css_class('noid-pending')

    def _set_step(self, n):
        n = max(1, min(n, TOTAL_STEPS))
        for i in range(n - 1):
            self._mark(i, 'error' if (i + 1) in self.step_errors else 'done')
        self._mark(n - 1, 'running')
        self.cur_step = n
        self.progress.set_fraction((n - 1) / float(TOTAL_STEPS))
        self.count_lbl.set_label('Step %d of %d' % (n, TOTAL_STEPS))
        self.hero_title.set_label('Updating your system…')

    # --- run -----------------------------------------------------------------

    def _on_start(self, _btn):
        if self.running:
            return
        if not os.path.isfile(UPDATE_SCRIPT) or not os.access(UPDATE_SCRIPT, os.X_OK):
            self._fail('Update script is missing or not executable: %s' % UPDATE_SCRIPT)
            return
        if not os.path.isfile(ASKPASS) or not os.access(ASKPASS, os.X_OK):
            self._fail('Graphical administrator-password helper is unavailable.')
            return

        self.stack.set_visible_child_name('run')
        self.banner.set_revealed(False)
        self.done_btnbox.set_visible(False)
        self._clear_done_btns()
        self.cur_step = 0
        self.step_errors = set()
        self.warning_count = 0
        self.cancelled_before_start = False
        self._reboot_activation = None
        self._reboot_safety = None
        self._reboot_blockers = None
        for i in range(len(self.step_stacks)):
            self._mark(i, 'pending')
        self.progress.set_fraction(0.0)
        self.count_lbl.set_visible(True)
        self.count_lbl.set_label('0 of %d complete' % TOTAL_STEPS)
        self.hero_title.set_label('Authenticating…')
        self.cur_lbl.set_label('A password dialog will appear — enter your password there.')
        self.log_expander.set_expanded(False)  # PW comes via graphical dialog

        rundir = GLib.get_user_runtime_dir() or '/tmp'
        try:
            marker_fd, self.marker_path = tempfile.mkstemp(
                prefix='noid-update-markers.', dir=rundir, text=True)
            os.close(marker_fd)
        except OSError as exc:
            print('noid-update: marker creation failed: %s' % exc,
                  file=sys.stderr)
            self.marker_path = None
            self._fail('Could not create private progress state; no update was started.')
            return
        self.marker_offset = 0

        child_env = dict(os.environ)
        child_env['NOID_UPDATE_MARKER_FILE'] = self.marker_path
        child_env['SUDO_ASKPASS'] = ASKPASS
        if not self.aide_check.get_active():
            child_env['NOID_SKIP_AIDE_CHECK'] = '1'
        else:
            child_env.pop('NOID_SKIP_AIDE_CHECK', None)
        envv = ['%s=%s' % item for item in child_env.items()]

        self.running = True
        try:
            self.term.spawn_async(
                pty_flags=Vte.PtyFlags.DEFAULT,
                working_directory=os.environ.get('HOME', '/'),
                argv=['/bin/bash', UPDATE_SCRIPT],
                envv=envv,
                spawn_flags=GLib.SpawnFlags.DEFAULT,
                child_setup=None,
                timeout=-1,
                cancellable=None,
                callback=self._spawn_done,
                user_data=0)
        except (OSError, TypeError, GLib.Error) as exc:
            self._fail('Could not start update: %s' % exc)
            return
        self.poll_id = GLib.timeout_add(250, self._poll_markers)

    def _spawn_done(self, terminal, pid, error=None, *rest):
        if error is not None:
            self._fail('Start failed: %s' % getattr(error, 'message', error))
            return
        self.term.grab_focus()

    def _poll_markers(self):
        if not self.marker_path:
            return False
        try:
            with open(self.marker_path, 'r') as fh:
                fh.seek(self.marker_offset)
                data = fh.read()
                self.marker_offset = fh.tell()
        except (OSError, UnicodeError) as exc:
            print('noid-update: marker read failed: %s' % exc,
                  file=sys.stderr)
            return self.running
        for line in data.splitlines():
            parts = line.split(None, 3)
            if not parts:
                continue
            if parts[0] == 'STEP' and len(parts) >= 3:
                desc = parts[3] if len(parts) >= 4 else ''
                n = _marker_row(parts[1])
                if n is None:
                    continue
                self._set_step(n)
                if desc:
                    self.cur_lbl.set_label(desc)
                # A new step started — any stale PROMPT banner
                # from the previous step is now obsolete. Defensive: matched
                # PROMPT marker should have emitted a PROMPT_DONE already, but
                # if the script crashed mid-prompt the banner would otherwise
                # stay revealed forever.
                if self.banner.get_revealed():
                    self.banner.set_revealed(False)
            elif parts[0] == 'PROMPT':
                # Interactive terminal input needed (e.g. fwupd
                # y/N) -> reveal log + raise Adw.Banner ("Input required") +
                # describe the prompt in cur_lbl. Banner is the visible cue;
                # log auto-expand + grab_focus prep the terminal for typing.
                # PROMPT marker format: "PROMPT <short-name> <description...>".
                # Falls back to "terminal" if no description present.
                desc = ' '.join(parts[1:]) if len(parts) > 1 else 'terminal'
                self.log_expander.set_expanded(True)
                self.term.grab_focus()
                self.banner.set_title(
                    'Input required — answer in the terminal log below.')
                self.banner.set_revealed(True)
                self.cur_lbl.set_label('Waiting for input: %s' % desc)
            elif parts[0] == 'STEPFAIL' and len(parts) >= 2:
                # Per-step error attribution: the named step raised the
                # orchestrator's ERRORS accumulator. Mark it immediately
                # (the following STEP marker would otherwise repaint it done).
                n = _marker_row(parts[1])
                if n is None:
                    continue
                if 1 <= n <= TOTAL_STEPS:
                    self.step_errors.add(n)
                    if n != self.cur_step:
                        self._mark(n - 1, 'error')
            elif parts[0] == 'PROMPT_DONE':
                # Interactive prompt resolved -> hide banner.
                # The step continues normally; the next STEP marker will update
                # cur_lbl to the new step description.
                self.banner.set_revealed(False)
            elif parts[0] == 'REBOOT' and len(parts) == 4:
                # Two-axis reboot result from the orchestrator's canonical
                # reader: activation need and boot safety never overwrite one
                # another. Closed reason codes contain no host identity.
                if (parts[1] in ('required', 'recommended', 'none')
                        and parts[2] in ('safe', 'blocked')
                        and all(token in {
                            'none', 'kernel-cmdline', 'initramfs',
                            'bls-identity', 'nvidia', 'boot-inventory',
                            'state-unsafe', 'nvidia-state'}
                            for token in parts[3].split(','))
                        and ((parts[2] == 'safe') ==
                             (parts[3] == 'none'))):
                    self._reboot_activation = parts[1]
                    self._reboot_safety = parts[2]
                    self._reboot_blockers = parts[3]
            elif parts[0] == 'WARNINGS' and len(parts) >= 2:
                # Count-only final summary state: no log content or machine
                # identity crosses the private marker channel.
                try:
                    count = int(parts[1], 10)
                except ValueError:
                    continue
                if 0 <= count <= 1000000:
                    self.warning_count = count
            elif parts[0] == 'CANCELLED' and len(parts) >= 2:
                self.cancelled_before_start = parts[1] == 'authentication'
        return self.running

    def _on_child_exited(self, _terminal, status):
        self.running = False
        if self.poll_id:
            GLib.source_remove(self.poll_id)
            self.poll_id = 0
        self._poll_markers()

        if self.cancelled_before_start:
            for i in range(TOTAL_STEPS):
                self._mark(i, 'pending')
            self.progress.set_fraction(0.0)
            self.count_lbl.set_label('0 of %d complete' % TOTAL_STEPS)
            self._finish_cancelled()
            self._cleanup_marker()
            return

        states, completed, fraction = _completion_snapshot(
            self.cur_step, status, self.step_errors)
        for i, state in enumerate(states):
            self._mark(i, state)
        self.progress.set_fraction(fraction)
        self.count_lbl.set_label('%d of %d complete' % (completed, TOTAL_STEPS))
        self.cur_lbl.set_label('')

        self._finish(status)

        self._cleanup_marker()

    # --- completion ----------------------------------------------------------

    def _clear_done_btns(self):
        child = self.done_btnbox.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self.done_btnbox.remove(child)
            child = nxt

    def _finish_cancelled(self):
        self._clear_done_btns()
        self.banner.set_revealed(False)
        self.hero_title.set_label('Update cancelled')
        self.cur_lbl.set_label(
            'Administrator authentication was cancelled. No update step or '
            'snapshot was started.')
        cb = Gtk.Button(label='Close')
        cb.add_css_class('suggested-action')
        cb.add_css_class('pill')
        noid_ui.accessible(cb, 'Close', 'Close NoID Privacy Update')
        cb.connect('clicked', lambda b: self.close())
        self.done_btnbox.append(cb)
        self.done_btnbox.set_visible(True)

    def _cleanup_marker(self):
        if not self.marker_path:
            return
        try:
            os.unlink(self.marker_path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            print('Cannot remove progress marker: %s' % exc, file=sys.stderr)
        self.marker_path = None

    @staticmethod
    def _reboot_readiness():
        """Return the canonical (activation, safety, blockers) record."""
        try:
            result = subprocess.run(
                ['/usr/libexec/noid-reboot-readiness'], capture_output=True,
                text=True, timeout=5, check=False)
        except (OSError, UnicodeError, subprocess.SubprocessError) as exc:
            print('Cannot inspect canonical reboot readiness: %s' % exc,
                  file=sys.stderr)
            return ('none', 'blocked', 'state-unsafe')
        if result.returncode != 0:
            print('Canonical reboot-readiness helper failed (exit %d)' %
                  result.returncode, file=sys.stderr)
            return ('none', 'blocked', 'state-unsafe')
        rows = result.stdout.splitlines()
        if len(rows) != 8 or rows[0] != 'schema=1':
            return ('none', 'blocked', 'state-unsafe')
        values = {}
        for row in rows[1:]:
            if '=' not in row:
                return ('none', 'blocked', 'state-unsafe')
            key, value = row.split('=', 1)
            if key in values:
                return ('none', 'blocked', 'state-unsafe')
            values[key] = value
        activation = values.get('activation')
        safety = values.get('safety')
        blockers = values.get('blockers')
        closed_blockers = {
            'none', 'kernel-cmdline', 'initramfs', 'bls-identity', 'nvidia',
            'boot-inventory', 'state-unsafe', 'nvidia-state'}
        blocker_set = blockers.split(',') if blockers else []
        if (activation not in ('required', 'recommended', 'none')
                or safety not in ('safe', 'blocked')
                or not blocker_set
                or any(item not in closed_blockers for item in blocker_set)
                or (safety == 'safe') != (blockers == 'none')):
            return ('none', 'blocked', 'state-unsafe')
        return (activation, safety, blockers)

    def _finish(self, status):
        self._clear_done_btns()
        self.cur_lbl.set_label('')
        warning_suffix = (
            ' %d non-blocking %s review in the log below.' %
            (self.warning_count,
             'warning needs' if self.warning_count == 1 else 'warnings need')
            if status == 0 and self.warning_count else '')
        # Prefer the orchestrator marker; an absent or malformed marker is
        # re-read through the same canonical helper, never a second heuristic.
        activation = self._reboot_activation
        safety = self._reboot_safety
        blockers = self._reboot_blockers
        if activation is None or safety is None or blockers is None:
            activation, safety, blockers = self._reboot_readiness()
        if safety == 'blocked':
            self.hero_title.set_label('Restart blocked — boot repair required')
            self.cur_lbl.set_label(
                'Do not restart yet. Boot-safety checks failed: %s. '
                'Review the log and complete the named recovery first.' %
                blockers.replace(',', ', '))
            self.log_expander.set_expanded(True)
            cb = Gtk.Button(label='Close')
            cb.add_css_class('suggested-action')
            cb.add_css_class('pill')
            noid_ui.accessible(
                cb, 'Close', 'Close Update without attempting an unsafe restart')
            cb.connect('clicked', lambda b: self.close())
            self.done_btnbox.append(cb)
        elif activation in ('required', 'recommended'):
            if activation == 'required':
                if status != 0:
                    title = 'Finished with errors — safe reboot required'
                elif self.warning_count:
                    title = 'Update complete with warnings — reboot required'
                else:
                    title = 'Update complete — reboot required'
                self.hero_title.set_label(title)
                reason = 'An update needs a reboot to take effect. Restart to activate it.'
            else:
                if status != 0:
                    title = 'Finished with errors — safe reboot recommended'
                elif self.warning_count:
                    title = 'Update complete with warnings — reboot recommended'
                else:
                    title = 'Update complete — reboot recommended'
                self.hero_title.set_label(title)
                reason = ('Updated core libraries/services keep running with the '
                          'old version until you restart.')
            if status == 0:
                self.cur_lbl.set_label(reason + warning_suffix)
                if self.warning_count:
                    self.log_expander.set_expanded(True)
            else:
                self.cur_lbl.set_label(
                    reason + ' Some steps reported errors — check the log below '
                    'before rebooting.')
                self.log_expander.set_expanded(True)
            rb = Gtk.Button(label='Restart now')
            rb.add_css_class('suggested-action')
            rb.add_css_class('pill')
            noid_ui.accessible(
                rb, 'Restart now', 'Restart to activate the installed updates')
            rb.connect('clicked', self._on_reboot)
            self.done_btnbox.append(rb)
            lt = Gtk.Button(label='Later')
            lt.add_css_class('pill')
            noid_ui.accessible(
                lt, 'Later', 'Close Update without restarting now')
            lt.connect('clicked', lambda b: self.close())
            self.done_btnbox.append(lt)
        elif status == 0:
            if self.warning_count:
                self.hero_title.set_label('Update complete with warnings')
                self.cur_lbl.set_label(
                    'The update workflow completed.' + warning_suffix)
                self.log_expander.set_expanded(True)
            else:
                self.hero_title.set_label('Update complete')
                self.cur_lbl.set_label('Everything is up to date.')
            cb = Gtk.Button(label='Close')
            cb.add_css_class('suggested-action')
            cb.add_css_class('pill')
            noid_ui.accessible(cb, 'Close', 'Close NoID Privacy Update')
            cb.connect('clicked', lambda b: self.close())
            self.done_btnbox.append(cb)
        else:
            self.hero_title.set_label('Finished with errors')
            self.cur_lbl.set_label(
                'Some steps reported errors — check the log below for details.')
            self.log_expander.set_expanded(True)
            cb = Gtk.Button(label='Close')
            cb.add_css_class('suggested-action')
            cb.add_css_class('pill')
            noid_ui.accessible(cb, 'Close', 'Close NoID Privacy Update')
            cb.connect('clicked', lambda b: self.close())
            self.done_btnbox.append(cb)
        self.done_btnbox.set_visible(True)

    # --- reboot / close ------------------------------------------------------

    def _on_reboot(self, _btn):
        dialog = Adw.AlertDialog.new(
            'Reboot now?',
            'The system will restart to activate the updates.')
        dialog.add_response('cancel', 'Cancel')
        dialog.add_response('reboot', 'Reboot')
        dialog.set_response_appearance('reboot', Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response('cancel')
        dialog.set_close_response('cancel')
        dialog.connect('response', self._reboot_response)
        dialog.present(self)

    def _reboot_response(self, _dialog, response):
        if response == 'reboot':
            try:
                subprocess.Popen(['systemctl', 'reboot'])
            except OSError as exc:
                noid_ui.toast(
                    self.toast_overlay, 'Reboot failed to start: %s' % exc, 5)
                print('Reboot failed to start: %s' % exc, file=sys.stderr)

    def _on_close_request(self, _win):
        if self.running:
            dialog = Adw.AlertDialog.new(
                'Update still running',
                'This window owns the interactive update terminal and must stay '
                'open until the run finishes. You can minimize it; closing is '
                'available again after completion.')
            dialog.add_response('keep-open', 'Keep window open')
            dialog.set_default_response('keep-open')
            dialog.set_close_response('keep-open')
            dialog.present(self)
            return True
        return False

    def _fail(self, msg):
        self.running = False
        if self.poll_id:
            GLib.source_remove(self.poll_id)
            self.poll_id = 0
        self._cleanup_marker()
        self.stack.set_visible_child_name('run')
        self.hero_title.set_label('Start failed')
        self.banner.set_title(msg)
        self.banner.set_revealed(True)


class UpdateApp(noid_ui.NoIDApplication):
    def __init__(self):
        super().__init__(APP_ID, 'noid-privacy-update', UPDATE_CSS)

    def do_activate(self):
        win = self.props.active_window
        if not win:
            win = UpdateWindow(self)
        win.present()


def main():
    return UpdateApp().run(sys.argv)


if __name__ == '__main__':
    sys.exit(main())
NOID_UPDATE_APP_EOF
chmod 0755 /usr/local/bin/noid-update
chown root:root /usr/local/bin/noid-update

cat > /usr/local/bin/noid-askpass <<'NOID_ASKPASS_EOF'
#!/bin/bash
# noid-askpass — graphical sudo askpass for the NoID Privacy Update GUI.
# sudo (-A / SUDO_ASKPASS) runs this to obtain the password via a GUI dialog
# instead of the terminal; the entered password is printed to stdout.
exec zenity --password --title="NoID Privacy Update — administrator password" 2>/dev/null
NOID_ASKPASS_EOF
chmod 0755 /usr/local/bin/noid-askpass
chown root:root /usr/local/bin/noid-askpass

cat > /usr/local/bin/noid-update-all-launcher.sh <<'LAUNCHER_EOF'
#!/bin/bash
# NoID Privacy Update — launcher.
# Opens the GTK4 Vte update app (noid-update). Kept as the launcher target so any
# cached GNOME app-info / .desktop still pointing here resolves to the GUI app.
# Falls back to a terminal run only if the GUI app is unavailable.
if [ -x /usr/local/bin/noid-update ]; then
    exec /usr/local/bin/noid-update "$@"
fi

TITLE="NoID Privacy System Update"
SCRIPT='/usr/local/bin/noid-update-all.sh; echo; echo "Press Enter to close..."; read _'
if command -v ptyxis >/dev/null 2>&1; then
    exec ptyxis --title="$TITLE" -- bash -c "$SCRIPT"
elif command -v kgx >/dev/null 2>&1; then
    exec kgx --title="$TITLE" -- bash -c "$SCRIPT"
elif command -v gnome-terminal >/dev/null 2>&1; then
    exec gnome-terminal --title="$TITLE" -- bash -c "$SCRIPT"
else
    exec /usr/local/bin/noid-update-all.sh
fi
LAUNCHER_EOF
chmod 0755 /usr/local/bin/noid-update-all-launcher.sh
chown root:root /usr/local/bin/noid-update-all-launcher.sh

cat > /usr/share/applications/noid-update-all.desktop <<'NOID_UPDATE_DESKTOP_EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=NoID Privacy Update
GenericName=NoID Privacy Update Tool
Comment=Run user-controlled system updates with integrity evidence
Exec=/usr/local/bin/noid-update
Icon=noid-privacy-update
Terminal=false
Categories=System;
Keywords=update;upgrade;dnf;flatpak;aide;system;noid;privacy;
StartupNotify=true
StartupWMClass=com.noidprivacy.Update
NOID_UPDATE_DESKTOP_EOF
chmod 644 /usr/share/applications/noid-update-all.desktop
chown root:root /usr/share/applications/noid-update-all.desktop

echo "  [OK] /usr/local/bin/noid-update (GTK4 GUI, 0755)"
echo "  [OK] /usr/local/bin/noid-askpass (0755)"
echo "  [OK] /usr/local/bin/noid-update-all-launcher.sh (0755)"
echo "  [OK] /usr/share/applications/noid-update-all.desktop (644)"

# ----------------------------------------------------------------------------
# Step 3d: reject superseded automatic AIDE trust replacement
# ----------------------------------------------------------------------------
echo "[Step 3d] Removing obsolete post-reboot AIDE rebaseline artifacts"
systemctl disable noid-aide-rebaseline-on-boot.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/multi-user.target.wants/noid-aide-rebaseline-on-boot.service
rm -f /etc/systemd/system/noid-aide-rebaseline-on-boot.service
rm -f /usr/local/sbin/noid-aide-rebaseline-on-boot.sh
rm -f /var/lib/noid-privacy/aide-rebaseline-after-kernel-reboot.marker
rm -f /var/lib/noid-privacy/aide-rebaseline-interrupted.marker
rm -f /var/lib/noid-privacy/aide-rebaseline-pending.txt
echo "  [OK] updater has no boot-time AIDE database replacement path"

# ----------------------------------------------------------------------------
# Step 4: Verification
# ----------------------------------------------------------------------------

echo ""
echo "[Step 4] Verification"

fail=0

# 4.1 — Script exists and is executable
if [ -x /usr/local/bin/noid-update-all.sh ]; then
    echo "  [OK] /usr/local/bin/noid-update-all.sh executable"
else
    echo "  [FAIL] /usr/local/bin/noid-update-all.sh missing or not executable"
    fail=$((fail + 1))
fi

# 4.2 — Script starts with shebang
if head -1 /usr/local/bin/noid-update-all.sh | grep -q "^#!/usr/bin/env bash"; then
    echo "  [OK] script has correct shebang"
else
    echo "  [FAIL] script missing shebang"
    fail=$((fail + 1))
fi

# 4.3 — systemd user units present
for unit in noid-update-reminder.service noid-update-reminder.timer; do
    if [ -f "/etc/systemd/user/$unit" ]; then
        echo "  [OK] /etc/systemd/user/$unit"
    else
        echo "  [FAIL] /etc/systemd/user/$unit missing"
        fail=$((fail + 1))
    fi
done

# 4.4 — Preset file for auto-enable
if [ -f /etc/systemd/user-preset/50-noid-update.preset ]; then
    echo "  [OK] /etc/systemd/user-preset/50-noid-update.preset"
else
    echo "  [FAIL] user-preset file missing"
    fail=$((fail + 1))
fi

# 4.5 — Timer syntax sanity check (one exact literal)
oncalendar_exact_count=$(grep -cFx 'OnCalendar=Mon *-*-* 10:00:00' \
    /etc/systemd/user/noid-update-reminder.timer || true)
oncalendar_total_count=$(grep -c '^OnCalendar=' \
    /etc/systemd/user/noid-update-reminder.timer || true)
if [ "$oncalendar_exact_count" -eq 1 ] && [ "$oncalendar_total_count" -eq 1 ]; then
    echo "  [OK] timer OnCalendar=Mon 10:00:00"
else
    echo "  [FAIL] timer OnCalendar incorrect"
    fail=$((fail + 1))
fi

# 4.5b — Semantically parse the exact value shipped in the timer, rather than
# re-parsing a second hardcoded copy that could not detect artifact drift.
if command -v systemd-analyze >/dev/null 2>&1; then
    oncalendar_value=$(sed -n 's/^OnCalendar=//p' \
        /etc/systemd/user/noid-update-reminder.timer)
    oncalendar_value_count=$(printf '%s\n' "$oncalendar_value" \
        | grep -c . || true)
    if [ "$oncalendar_value_count" -ne 1 ]; then
        echo "  [FAIL] timer must contain exactly one OnCalendar value"
        fail=$((fail + 1))
    elif systemd-analyze calendar --iterations=5 \
            "$oncalendar_value" >/dev/null 2>&1; then
        echo "  [OK] timer OnCalendar semantic verify (systemd-analyze --iterations=5)"
    else
        echo "  [FAIL] timer OnCalendar fails systemd-analyze semantic verify"
        fail=$((fail + 1))
    fi
fi

# 4.6 — Script passes basic shell syntax check
if bash -n /usr/local/bin/noid-update-all.sh 2>/dev/null; then
    echo "  [OK] script passes bash -n syntax check"
else
    echo "  [FAIL] script has bash syntax errors"
    fail=$((fail + 1))
fi

# 4.6b — M16's managed uBO policy must remain a safe, executable contract for
# both the image seed and every future candidate selected by this updater.
if [ -f /usr/local/lib/noid-privacy/validate-ubo-policy.py ] \
        && [ ! -L /usr/local/lib/noid-privacy/validate-ubo-policy.py ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' \
            /usr/local/lib/noid-privacy/validate-ubo-policy.py \
            2>/dev/null || true)" = '0:0:755:1' ] \
        && [ -f /usr/share/noid-firefox/uBlock0@raymondhill.net.json ] \
        && [ ! -L /usr/share/noid-firefox/uBlock0@raymondhill.net.json ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' \
            /usr/share/noid-firefox/uBlock0@raymondhill.net.json \
            2>/dev/null || true)" = '0:0:644:1' ] \
        && [ -f /usr/lib64/mozilla/managed-storage/uBlock0@raymondhill.net.json ] \
        && [ ! -L /usr/lib64/mozilla/managed-storage/uBlock0@raymondhill.net.json ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' \
            /usr/lib64/mozilla/managed-storage/uBlock0@raymondhill.net.json \
            2>/dev/null || true)" = '0:0:644:1' ] \
        && cmp -s -- /usr/share/noid-firefox/uBlock0@raymondhill.net.json \
            /usr/lib64/mozilla/managed-storage/uBlock0@raymondhill.net.json \
        && /usr/local/lib/noid-privacy/validate-ubo-policy.py \
            '/usr/lib64/mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/uBlock0@raymondhill.net.xpi' \
            /usr/share/noid-firefox/uBlock0@raymondhill.net.json \
            >/dev/null; then
    echo "  [OK] uBO seed supports the complete root-managed filter-list policy"
else
    echo "  [FAIL] uBO policy/validator/seed contract is missing, unsafe or incompatible"
    fail=$((fail + 1))
fi

# 4.7 — GNOME desktop launcher via wrapper script + simple Exec= path
# (an inline `bash -c '...'` in Exec= violates the Desktop Entry Spec —
# reserved chars — and fails desktop-file-validate → app missing from
# Activities). Verify both pieces.
if [ -f /usr/local/bin/noid-update-all-launcher.sh ] \
        && [ -x /usr/local/bin/noid-update-all-launcher.sh ]; then
    echo "  [OK] noid-update-all-launcher.sh wrapper present + executable"
else
    echo "  [FAIL] /usr/local/bin/noid-update-all-launcher.sh missing or not executable"
    fail=$((fail + 1))
fi
if [ -f /usr/share/applications/noid-update-all.desktop ]; then
    if grep -q '^Exec=/usr/local/bin/noid-update$' /usr/share/applications/noid-update-all.desktop \
            && ! grep -q '^Exec=.*pkexec' /usr/share/applications/noid-update-all.desktop \
            && grep -q '^Icon=noid-privacy-update' /usr/share/applications/noid-update-all.desktop \
            && grep -q '^StartupWMClass=com.noidprivacy.Update$' /usr/share/applications/noid-update-all.desktop \
            && grep -q '^Type=Application' /usr/share/applications/noid-update-all.desktop; then
        echo "  [OK] noid-update-all.desktop (GUI-Exec + WMClass + NoID Privacy icon)"
    else
        echo "  [FAIL] noid-update-all.desktop missing required keys or invalid Exec"
        fail=$((fail + 1))
    fi
    # Enforce desktop-file-validate cleanliness when the validator is available.
    if command -v desktop-file-validate >/dev/null 2>&1; then
        if desktop-file-validate /usr/share/applications/noid-update-all.desktop 2>/dev/null; then
            echo "  [OK] noid-update-all.desktop passes desktop-file-validate"
        else
            echo "  [FAIL] noid-update-all.desktop fails desktop-file-validate"
            fail=$((fail + 1))
        fi
    fi
else
    echo "  [FAIL] /usr/share/applications/noid-update-all.desktop missing"
    fail=$((fail + 1))
fi

# 4.7b — canonical two-axis reboot state + login notifier + XDG autostart.
# Installation success requires both safety helpers and every presentation
# consumer to retain the same fail-closed contract.
if [ -f /usr/libexec/noid-reboot-block-state ] \
        && [ ! -L /usr/libexec/noid-reboot-block-state ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' \
            /usr/libexec/noid-reboot-block-state 2>/dev/null)" = '0:0:755:1' ] \
        && bash -n /usr/libexec/noid-reboot-block-state 2>/dev/null \
        && grep -qF 'STATE_DIR=/run/noid-privacy' \
            /usr/libexec/noid-reboot-block-state \
        && grep -qF 'STATE=$STATE_DIR/reboot-blocked' \
            /usr/libexec/noid-reboot-block-state \
        && grep -qF 'unsupported reboot blocker:' \
            /usr/libexec/noid-reboot-block-state; then
    echo "  [OK] reboot-block publisher owned, executable + valid"
else
    echo "  [FAIL] reboot-block publisher missing, substituted or invalid"
    fail=$((fail + 1))
fi
if [ -f /usr/libexec/noid-reboot-readiness ] \
        && [ ! -L /usr/libexec/noid-reboot-readiness ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' \
            /usr/libexec/noid-reboot-readiness 2>/dev/null)" = '0:0:755:1' ] \
        && bash -n /usr/libexec/noid-reboot-readiness 2>/dev/null \
        && grep -qF 'resolve_reboot_state() {' \
            /usr/libexec/noid-reboot-readiness \
        && grep -qF 'block_state=/run/noid-privacy/reboot-blocked' \
            /usr/libexec/noid-reboot-readiness \
        && grep -qF 'firstboot_marker=/var/lib/noid-privacy/.firstboot-cmdline-reboot-required' \
            /usr/libexec/noid-reboot-readiness \
        && grep -qF 'nvidia_degraded=$nvidia_state_dir/degraded' \
            /usr/libexec/noid-reboot-readiness \
        && grep -qF 'case "$guard_rc:$guard_state" in' \
            /usr/libexec/noid-reboot-readiness; then
    echo "  [OK] canonical reboot-readiness reader owned, executable + valid"
else
    echo "  [FAIL] canonical reboot-readiness reader missing, substituted or invalid"
    fail=$((fail + 1))
fi
if [ -f /usr/local/bin/noid-pending-reboot-check.sh ] \
        && [ ! -L /usr/local/bin/noid-pending-reboot-check.sh ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' \
            /usr/local/bin/noid-pending-reboot-check.sh 2>/dev/null)" \
            = '0:0:755:1' ] \
        && bash -n /usr/local/bin/noid-pending-reboot-check.sh 2>/dev/null \
        && grep -qF '/usr/libexec/noid-reboot-readiness' \
            /usr/local/bin/noid-pending-reboot-check.sh \
        && grep -qF 'Restart blocked — boot repair required' \
            /usr/local/bin/noid-pending-reboot-check.sh; then
    echo "  [OK] pending-reboot notifier owned, executable + valid"
else
    echo "  [FAIL] pending-reboot notifier missing, substituted or invalid"
    fail=$((fail + 1))
fi

pending_reboot_desktop_valid=1
if command -v desktop-file-validate >/dev/null 2>&1 \
        && ! desktop-file-validate \
            /etc/xdg/autostart/noid-pending-reboot.desktop 2>/dev/null; then
    pending_reboot_desktop_valid=0
fi
if [ -f /etc/xdg/autostart/noid-pending-reboot.desktop ] \
        && [ ! -L /etc/xdg/autostart/noid-pending-reboot.desktop ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' \
            /etc/xdg/autostart/noid-pending-reboot.desktop 2>/dev/null)" \
            = '0:0:644:1' ] \
        && grep -qFx 'Type=Application' \
            /etc/xdg/autostart/noid-pending-reboot.desktop \
        && grep -qFx 'Exec=/usr/local/bin/noid-pending-reboot-check.sh' \
            /etc/xdg/autostart/noid-pending-reboot.desktop \
        && ! grep -qE '^[[:space:]]*X-GNOME-Autostart-Phase[[:space:]]*=' \
            /etc/xdg/autostart/noid-pending-reboot.desktop \
        && [ "$pending_reboot_desktop_valid" -eq 1 ]; then
    echo "  [OK] pending-reboot XDG autostart owned + valid"
else
    echo "  [FAIL] pending-reboot XDG autostart missing, substituted or invalid"
    fail=$((fail + 1))
fi

# 4.8 — GTK4 update GUI app present + executable + valid Python + Vte guard
if [ -x /usr/local/bin/noid-update ] \
        && python3 -c "import ast; ast.parse(open('/usr/local/bin/noid-update').read())" 2>/dev/null \
        && grep -q "APP_ID = 'com.noidprivacy.Update'" /usr/local/bin/noid-update \
        && grep -q "gi.require_version('Vte', '3.91')" /usr/local/bin/noid-update \
        && grep -q '^import noid_ui$' /usr/local/bin/noid-update \
        && [ -f /usr/lib/noid-privacy/noid_ui.py ]; then
    echo "  [OK] /usr/local/bin/noid-update (valid Python + shared UI + Vte guard)"
else
    echo "  [FAIL] /usr/local/bin/noid-update missing/not-executable/invalid"
    fail=$((fail + 1))
fi

# 4.9 — graphical sudo askpass present + executable
if [ -x /usr/local/bin/noid-askpass ] && grep -q 'zenity --password' /usr/local/bin/noid-askpass; then
    echo "  [OK] /usr/local/bin/noid-askpass (graphical sudo askpass)"
else
    echo "  [FAIL] /usr/local/bin/noid-askpass missing/not-executable/invalid"
    fail=$((fail + 1))
fi

# 4.10 — no updater-owned AIDE trust replacement survives.
aide_artifacts=0
for obsolete in /usr/local/sbin/noid-aide-rebaseline-on-boot.sh \
                /etc/systemd/system/noid-aide-rebaseline-on-boot.service \
                /etc/systemd/system/multi-user.target.wants/noid-aide-rebaseline-on-boot.service \
                /var/lib/noid-privacy/aide-rebaseline-after-kernel-reboot.marker \
                /var/lib/noid-privacy/aide-rebaseline-interrupted.marker \
                /var/lib/noid-privacy/aide-rebaseline-pending.txt; do
    if [ -e "$obsolete" ] || [ -L "$obsolete" ]; then
        echo "  [FAIL] obsolete automatic AIDE replacement artifact present: $obsolete"
        fail=$((fail + 1))
        aide_artifacts=$((aide_artifacts + 1))
    fi
done
if [ "$aide_artifacts" -eq 0 ]; then
    echo "  [OK] updater contains no automatic AIDE database replacement path"
fi

# 4.11 — whole-workflow lock and process-bound update-window validator
if [ -f /usr/lib/tmpfiles.d/noid-update-lock.conf ] \
        && grep -q '^f /run/lock/noid-update-all.lock 0660 root wheel -$' \
            /usr/lib/tmpfiles.d/noid-update-lock.conf \
        && [ -f /run/lock/noid-update-all.lock ] \
        && [ "$(stat -c '%U:%G:%a' /run/lock/noid-update-all.lock)" = 'root:wheel:660' ]; then
    echo "  [OK] system-wide update workflow lock installed + boot-persistent"
else
    echo "  [FAIL] noid-update-all workflow lock missing or has wrong ownership/mode"
    fail=$((fail + 1))
fi
if [ -x /usr/libexec/noid-update-lock-guardian ] \
        && [ ! -L /usr/libexec/noid-update-lock-guardian ] \
        && [ -x /usr/libexec/noid-update-window-active ] \
        && [ ! -L /usr/libexec/noid-update-window-active ] \
        && grep -qF 'process_matches || inactive' \
            /usr/libexec/noid-update-window-active \
        && grep -qF '/proc/locks' /usr/libexec/noid-update-window-active \
        && grep -qF 'flock --nonblock 9' \
            /usr/libexec/noid-update-window-active; then
    echo "  [OK] process/lock-bound update-window validator installed"
else
    echo "  [FAIL] update-window validator missing or incomplete"
    fail=$((fail + 1))
fi

if [ $fail -gt 0 ]; then
    echo ""
    echo "[Module 25] FAILED ($fail checks)"
    exit 1
fi

echo ""
echo "=============================================================="
echo "[Module 25] Done — all checks passed"
echo "=============================================================="
echo ""
echo "Post-boot expected behavior:"
echo "  - User logs in → M17 noid-user-firstrun applies preset → timer enabled"
echo "  - Every Monday 10:00-11:00 (randomized) → reminder notification"
echo "  - User runs: /usr/local/bin/noid-update-all.sh"
echo "  - Script performs 9 main update steps + 4 sub-steps (snapper, dnf,"
echo "    flatpak, fwupd, noid-firefox re-apply [+5b: noid-thunderbird re-deploy],"
echo "    consent-gated agents [+6b: GNOME pin/updates, +6c: VSCodium updates],"
echo "    gpg check, AIDE check-only evidence [+8b: config-drift evidence], reboot check)"

%end
