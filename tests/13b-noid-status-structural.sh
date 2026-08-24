#!/bin/bash
# 13b-noid-status-structural — verify /usr/local/bin/noid-status structural invariants
#
# noid-status is a user-runnable diagnostic CLI. It is safe to run
# as any user and must show clear "n/a (root only)" messages for privileged
# checks rather than silently failing to "unknown".
#
# Covered fixes:
#   - auditd field: explicit `[ "$(id -u)" -ne 0 ]` early-branch sets
#     "n/a (root only)" instead of leaving AUDITD_IMMUT="unknown"
#   - HSI field: never wakes boot-dormant fwupd; while an explicit firmware
#     operation already owns the daemon, sed-strip ANSI escapes from fwupdmgr
#     output, then awk sub() to remove "Host Security ID:" prefix (preserves
#     "HSI:N!" colon vs awk -F: which would truncate at second colon)
#   - Snapper field: fixed M20 root helper exposes only sanitized status
#     as wheel members → SNAP_COUNT is non-zero for non-root callers
#   - update-reminder field: derives the canonical same-user systemd bus after
#     metadata validation instead of depending on inherited desktop variables
#
# This test extracts the STATUS_EOF heredoc from M13 13-aide-welcome.ks
# and asserts the patched control-flow is present.

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/13-aide-welcome.ks"

test_start "13b-noid-status-structural"

assert_file_exists "$KS_FILE"
assert_cmd_success "bash -n $KS_FILE" bash -n "$KS_FILE"

TMPDIR="$(mktemp -d /var/tmp/noid-test13b.XXXXXX)"
DNS_FIXTURE=""
trap 'rm -rf "$TMPDIR"; [ -z "$DNS_FIXTURE" ] || rm -f "$DNS_FIXTURE"' EXIT

SCRIPT="$TMPDIR/noid-status"
extract_heredoc "$KS_FILE" "STATUS_EOF" "$SCRIPT" || _fail "STATUS_EOF extraction"
assert_file_min_size "$SCRIPT" 4096 "noid-status script >4KB (non-trivial scope)"

# --- bash syntax of the extracted heredoc -----------------------------------
if bash -n "$SCRIPT" 2>/dev/null; then
    _pass "noid-status: bash -n clean"
else
    _fail "noid-status: bash -n errors in extracted heredoc"
fi

# --- shebang + safety mode --------------------------------------------------
assert_grep_fixed '#!/bin/bash' "$SCRIPT" "bash shebang"
assert_grep_extended '^set -[^[:space:]]*u[^[:space:]]*[[:space:]]+pipefail$' \
    "$SCRIPT" "unset-variable protection is enabled in strict mode"

# --- fixed AIDE state privilege boundary -----------------------------------
AIDE_STATUS_HELPER="$TMPDIR/noid-aide-status"
extract_heredoc "$KS_FILE" "AIDE_STATUS_HELPER_EOF" "$AIDE_STATUS_HELPER" \
    || _fail "AIDE_STATUS_HELPER_EOF extraction"
assert_cmd_success "AIDE root status helper parses" bash -n "$AIDE_STATUS_HELPER"
assert_grep_fixed 'Cmnd_Alias NOID_AIDE_STATUS = /usr/libexec/noid-aide-status ""' \
    "$KS_FILE" "AIDE status sudo rule is exact and argument-free"
assert_grep_fixed 'f /run/lock/noid-aide.lock 0600 root root -' "$KS_FILE" \
    "AIDE shared lock is created by tmpfiles with root-only mode"
assert_grep_fixed 'ReadWritePaths=/var/log/aide /run/lock/noid-aide.lock' \
    "$KS_FILE" "AIDE service can write only its report directory and exact lock"
assert_grep_fixed 'UMask=0077' "$KS_FILE" \
    "AIDE service creates private files by default"
assert_grep_fixed 'AIDE_DATABASE_STATE=$(read_aide_database_state)' "$SCRIPT" \
    "noid-status consumes the root-published AIDE state"
assert_cmd_failure \
    "noid-status never mistakes an unreadable root database for absence" \
    grep -qF -- 'if [ ! -s /var/lib/aide/aide.db.gz ]' "$SCRIPT"
assert_grep_fixed "_aide_database_state() == 'active'" "$KS_FILE" \
    "Setup enables its AIDE switch only from the fixed state schema"

lan_xdp_reader="$TMPDIR/lan-xdp-health-reader.sh"
sed -n \
    '/^# BEGIN LAN_XDP_HEALTH_READER$/,/^# END LAN_XDP_HEALTH_READER$/p' \
    "$SCRIPT" > "$lan_xdp_reader"
# shellcheck source=/dev/null
. "$lan_xdp_reader"
LAN_XDP_FIXTURE_DIR="$TMPDIR/lan-xdp-health"
LAN_XDP_FIXTURE_FILE="$LAN_XDP_FIXTURE_DIR/state"
mkdir -m 0755 "$LAN_XDP_FIXTURE_DIR"
lan_xdp_owner=$(stat -c '%U:%G' "$LAN_XDP_FIXTURE_DIR")
lan_xdp_file_meta="$lan_xdp_owner:644:1"
lan_xdp_dir_meta="$lan_xdp_owner:755"
for lan_xdp_detail in controller-missing sync-or-postcheck-failed \
        unsupported-link-type no-ethernet-link physical-ipv6-unsupported; do
    printf 'STATE=DEGRADED\nDETAIL=%s\n' "$lan_xdp_detail" \
        > "$LAN_XDP_FIXTURE_FILE"
    chmod 0644 "$LAN_XDP_FIXTURE_FILE"
    assert_eq "$lan_xdp_detail" \
        "$(read_lan_xdp_degraded_detail "$LAN_XDP_FIXTURE_FILE" \
            "$lan_xdp_file_meta" "$lan_xdp_dir_meta")" \
        "noid-status exposes LAN-XDP reason: $lan_xdp_detail"
done
printf 'STATE=DEGRADED\nDETAIL=unknown-reason\n' > "$LAN_XDP_FIXTURE_FILE"
assert_cmd_failure "noid-status rejects an unknown LAN-XDP reason" \
    read_lan_xdp_degraded_detail "$LAN_XDP_FIXTURE_FILE" \
        "$lan_xdp_file_meta" "$lan_xdp_dir_meta"
printf 'STATE=DEGRADED\nDETAIL=controller-missing\nEXTRA=unsafe\n' \
    > "$LAN_XDP_FIXTURE_FILE"
assert_cmd_failure "noid-status rejects extra LAN-XDP health fields" \
    read_lan_xdp_degraded_detail "$LAN_XDP_FIXTURE_FILE" \
        "$lan_xdp_file_meta" "$lan_xdp_dir_meta"
assert_grep_fixed 'reason=$XDP_DETAIL' "$SCRIPT" \
    "noid-status includes the validated reason in human and JSON state"

aide_state_reader="$TMPDIR/aide-state-reader.sh"
sed -n '/^# BEGIN AIDE_STATE_READER$/,/^# END AIDE_STATE_READER$/p' \
    "$AIDE_STATUS_HELPER" > "$aide_state_reader"
# shellcheck disable=SC1090
. "$aide_state_reader"
AIDE_FIXTURE_DIR="$TMPDIR/aide-db"
AIDE_FIXTURE_DB="$AIDE_FIXTURE_DIR/aide.db.gz"
mkdir -m 0700 "$AIDE_FIXTURE_DIR"
aide_owner=$(stat -c '%u:%g' "$AIDE_FIXTURE_DIR")
assert_eq absent \
    "$(read_aide_state "$AIDE_FIXTURE_DIR" "$AIDE_FIXTURE_DB" \
        "$aide_owner:700" "$aide_owner:600:1")" \
    "safe AIDE directory without a database is absent"
printf '%s\n' candidate > "$AIDE_FIXTURE_DB"
chmod 0600 "$AIDE_FIXTURE_DB"
assert_eq active \
    "$(read_aide_state "$AIDE_FIXTURE_DIR" "$AIDE_FIXTURE_DB" \
        "$aide_owner:700" "$aide_owner:600:1")" \
    "safe nonempty root-private AIDE database is active"
ln "$AIDE_FIXTURE_DB" "$AIDE_FIXTURE_DB.hardlink"
assert_eq unsafe \
    "$(read_aide_state "$AIDE_FIXTURE_DIR" "$AIDE_FIXTURE_DB" \
        "$aide_owner:700" "$aide_owner:600:1")" \
    "hardlinked AIDE database is unsafe"
rm -f "$AIDE_FIXTURE_DB.hardlink"
mv "$AIDE_FIXTURE_DB" "$AIDE_FIXTURE_DB.target"
ln -s "$AIDE_FIXTURE_DB.target" "$AIDE_FIXTURE_DB"
assert_eq unsafe \
    "$(read_aide_state "$AIDE_FIXTURE_DIR" "$AIDE_FIXTURE_DB" \
        "$aide_owner:700" "$aide_owner:600:1")" \
    "symlinked AIDE database is unsafe"
rm -f "$AIDE_FIXTURE_DB" "$AIDE_FIXTURE_DB.target"
chmod 0755 "$AIDE_FIXTURE_DIR"
assert_eq unsafe \
    "$(read_aide_state "$AIDE_FIXTURE_DIR" "$AIDE_FIXTURE_DB" \
        "$aide_owner:700" "$aide_owner:600:1")" \
    "widened AIDE database directory is unsafe"

# --- auditd shows "n/a (root only)" for non-root ----------------
# Without the fix, `auditctl -s` fails silently for non-root and the field
# stays at its initial "unknown" value. The early-branch on id -u must come
# BEFORE the auditctl-call.
assert_grep_extended 'if \[ "\$\(id -u\)" -ne 0 \]; then' "$SCRIPT" \
    "auditd: non-root early-branch present"
assert_grep_fixed 'AUDITD_IMMUT="n/a (root only)"' "$SCRIPT" \
    "auditd: 'n/a (root only)' messaging string"
assert_grep_fixed 'elif command -v auditctl' "$SCRIPT" \
    "auditd: auditctl path is elif (only as root)"

# --- audit-storage boot-scoped degradation marker --------------------------
assert_grep_fixed 'read_audit_storage_state()' "$SCRIPT" \
    "audit storage has an explicit safe marker reader"
assert_grep_fixed 'audit-storage:DEGRADED' "$SCRIPT" \
    "brief mode makes a boot-scoped low-space event prominent"
assert_grep_fixed '"audit_storage": next(v)' "$SCRIPT" \
    "JSON integrity object exposes audit-storage degradation"
audit_storage_helper="$TMPDIR/audit-storage-helper.sh"
sed -n '/^# BEGIN AUDIT_STORAGE_STATUS_READER$/,/^# END AUDIT_STORAGE_STATUS_READER$/p' \
    "$SCRIPT" > "$audit_storage_helper"
# shellcheck source=/dev/null
. "$audit_storage_helper"
AUDIT_STORAGE_FIXTURE_DIR="$TMPDIR/audit-storage-state"
AUDIT_STORAGE_FIXTURE_FILE="$AUDIT_STORAGE_FIXTURE_DIR/audit-storage-degraded"
mkdir -m 0755 "$AUDIT_STORAGE_FIXTURE_DIR"
audit_storage_owner=$(stat -c '%U:%G' "$AUDIT_STORAGE_FIXTURE_DIR")
audit_storage_file_meta="$audit_storage_owner:600:1"
audit_storage_dir_meta="$audit_storage_owner:755"
assert_eq ok \
    "$(read_audit_storage_state "$AUDIT_STORAGE_FIXTURE_FILE" \
        "$audit_storage_file_meta" "$audit_storage_dir_meta")" \
    "missing marker is the exact healthy state"
printf '%s\n' status=degraded > "$AUDIT_STORAGE_FIXTURE_FILE"
chmod 0600 "$AUDIT_STORAGE_FIXTURE_FILE"
assert_eq 'DEGRADED (boot-scoped low-space marker; review required)' \
    "$(read_audit_storage_state "$AUDIT_STORAGE_FIXTURE_FILE" \
        "$audit_storage_file_meta" "$audit_storage_dir_meta")" \
    "safe root-private marker remains visible without reading its contents"
chmod 0644 "$AUDIT_STORAGE_FIXTURE_FILE"
assert_eq 'unknown (invalid audit-storage marker metadata)' \
    "$(read_audit_storage_state "$AUDIT_STORAGE_FIXTURE_FILE" \
        "$audit_storage_file_meta" "$audit_storage_dir_meta")" \
    "marker metadata drift cannot masquerade as a trusted event"
rm -f "$AUDIT_STORAGE_FIXTURE_FILE"
ln -s /dev/null "$AUDIT_STORAGE_FIXTURE_FILE"
assert_eq 'unknown (unsafe audit-storage marker type)' \
    "$(read_audit_storage_state "$AUDIT_STORAGE_FIXTURE_FILE" \
        "$audit_storage_file_meta" "$audit_storage_dir_meta")" \
    "audit-storage marker symlinks are rejected"

# --- LUKS backup evidence has a closed, metadata-bound schema ---------------
luks_backup_helper="$TMPDIR/luks-backup-helper.sh"
sed -n \
    '/^    # BEGIN LUKS_BACKUP_STATUS_READER$/,/^    # END LUKS_BACKUP_STATUS_READER$/p' \
    "$SCRIPT" | sed 's/^    //' > "$luks_backup_helper"
# shellcheck disable=SC1090
. "$luks_backup_helper"
LUKS_FIXTURE_DIR="$TMPDIR/luks-evidence"
LUKS_FIXTURE_LOG="$LUKS_FIXTURE_DIR/luks-backup.log"
mkdir -m 0755 "$LUKS_FIXTURE_DIR"
luks_owner=$(stat -c '%U:%G' "$LUKS_FIXTURE_DIR")
printf '%s\t%s\n' '2026-07-27T12:34:56+02:00' \
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
    > "$LUKS_FIXTURE_LOG"
chmod 0640 "$LUKS_FIXTURE_LOG"
assert_eq 'present (last 2026-07-27T12:34:56+02:00, sha256:0123456789ab…)' \
    "$(read_luks_backup_log "$LUKS_FIXTURE_LOG" \
        "$luks_owner:640:1" "$luks_owner:755")" \
    "valid privacy-minimized LUKS backup evidence is parsed"
printf '%s\n' 'hostile terminal text' >> "$LUKS_FIXTURE_LOG"
assert_cmd_failure "malformed LUKS backup evidence is rejected" \
    read_luks_backup_log "$LUKS_FIXTURE_LOG" \
        "$luks_owner:640:1" "$luks_owner:755"
sed -i '$d' "$LUKS_FIXTURE_LOG"
ln "$LUKS_FIXTURE_LOG" "$LUKS_FIXTURE_LOG.hardlink"
assert_cmd_failure "hardlinked LUKS backup evidence is rejected" \
    read_luks_backup_log "$LUKS_FIXTURE_LOG" \
        "$luks_owner:640:1" "$luks_owner:755"
rm -f "$LUKS_FIXTURE_LOG.hardlink"
chmod 0777 "$LUKS_FIXTURE_DIR"
assert_cmd_failure "writable LUKS evidence directory is rejected" \
    read_luks_backup_log "$LUKS_FIXTURE_LOG" \
        "$luks_owner:640:1" "$luks_owner:755"
assert_grep_fixed '/usr/libexec/noid-reboot-readiness' "$SCRIPT" \
    "noid-status consumes the canonical activation and reboot-safety reader"
assert_not_grep 'find -H /lib/modules' "$SCRIPT" \
    "noid-status has no second installed-kernel heuristic"
assert_grep_fixed 'BLOCKED*) BRIEF_PARTS+=("reboot:BLOCKED")' "$SCRIPT" \
    "brief status exposes a reboot-safety blocker distinctly"
reboot_status_reader="$TMPDIR/reboot-status-reader.sh"
sed -n '/^# BEGIN REBOOT_STATUS_READER$/,/^# END REBOOT_STATUS_READER$/p' \
    "$SCRIPT" > "$reboot_status_reader"
assert_cmd_success "noid-status reboot reader parses in isolation" \
    bash -n "$reboot_status_reader"
# shellcheck source=/dev/null
. "$reboot_status_reader"
reboot_status_fixture="$TMPDIR/reboot-status-fixture"
cat > "$reboot_status_fixture" <<'REBOOT_STATUS_FIXTURE_EOF'
#!/bin/bash
printf '%s\n' "$REBOOT_FIXTURE_OUTPUT"
exit "${REBOOT_FIXTURE_RC:-0}"
REBOOT_STATUS_FIXTURE_EOF
chmod 0755 "$reboot_status_fixture"
REBOOT_FIXTURE_OUTPUT=$'schema=1\nactivation=none\nsafety=safe\nblockers=none\nrunning_kernel=7.1.8-test\nlatest_kernel=7.1.8-test\nnvidia_running=unavailable\nnvidia_installed=unavailable'
REBOOT_FIXTURE_RC=0
export REBOOT_FIXTURE_OUTPUT REBOOT_FIXTURE_RC
assert_eq 'not required' "$(read_reboot_state "$reboot_status_fixture")" \
    "canonical safe/no-activation state is rendered cleanly"
REBOOT_FIXTURE_OUTPUT=$'schema=1\nactivation=required\nsafety=safe\nblockers=none\nrunning_kernel=7.1.8-test\nlatest_kernel=7.1.9-test\nnvidia_running=610.1\nnvidia_installed=610.2'
export REBOOT_FIXTURE_OUTPUT
assert_grep_fixed 'REQUIRED + SAFE' \
    <(read_reboot_state "$reboot_status_fixture") \
    "canonical activation requirement retains its verified-safe axis"
REBOOT_FIXTURE_OUTPUT=$'schema=1\nactivation=required\nsafety=blocked\nblockers=nvidia,state-unsafe\nrunning_kernel=7.1.8-test\nlatest_kernel=7.1.9-test\nnvidia_running=610.1\nnvidia_installed=610.2'
export REBOOT_FIXTURE_OUTPUT
assert_grep_fixed 'BLOCKED (activation=required; repair before restart: nvidia,state-unsafe)' \
    <(read_reboot_state "$reboot_status_fixture") \
    "canonical safety blocker wins over activation advice"
REBOOT_FIXTURE_OUTPUT=$'schema=1\nactivation=none\nsafety=safe\nblockers=nvidia\nrunning_kernel=7.1.8-test\nlatest_kernel=7.1.8-test\nnvidia_running=unavailable\nnvidia_installed=unavailable'
export REBOOT_FIXTURE_OUTPUT
assert_eq 'unknown (canonical reboot state inconsistent)' \
    "$(read_reboot_state "$reboot_status_fixture")" \
    "inconsistent canonical reboot axes never render as trusted"
REBOOT_FIXTURE_RC=1
export REBOOT_FIXTURE_RC
assert_eq 'unknown (canonical reboot reader failed)' \
    "$(read_reboot_state "$reboot_status_fixture")" \
    "canonical helper failure remains explicit"
unset REBOOT_FIXTURE_OUTPUT REBOOT_FIXTURE_RC

# --- HSI strips ANSI escapes + uses awk sub() -------------------
# fwupdmgr emits ANSI color codes even with NO_COLOR=1 (upstream issue
# #4959). Without the sed-strip, "[1m" leaks into the displayed value.
# Without the sub() replacement, awk -F: would truncate at the second colon
# and the HSI score-suffix is lost.
assert_grep_extended 'sed -e .s/\\x1b' "$SCRIPT" \
    "HSI: ANSI escape strip (sed pattern matching \\x1b)"
assert_grep_fixed 'sub(/^Host Security ID:[[:space:]]*/, "")' "$SCRIPT" \
    "HSI: awk sub() prefix-strip (preserves HSI:N! colon)"
assert_not_grep "awk -F: '/Host Security ID/ {print \$2; exit}'" "$SCRIPT" \
    "HSI: legacy awk -F: extraction (truncation bug) REMOVED"
assert_grep_fixed 'read_hsi()' "$SCRIPT" \
    "HSI: dedicated failure-safe reader"
assert_grep_fixed 'systemctl --quiet is-active fwupd.service' "$SCRIPT" \
    "HSI: status query preserves fwupd's boot-dormant state"
assert_grep_fixed 'lockdown_probe=$(awk' "$SCRIPT" \
    "missing lockdown file cannot abort the diagnostic"
assert_grep_fixed 'if SB_RAW=$(mokutil --sb-state' "$SCRIPT" \
    "non-EFI mokutil failure normalizes to unknown"

hsi_helper="$TMPDIR/hsi-helper.sh"
awk '
    /^read_hsi\(\) \{/ {copy=1}
    copy {print}
    copy && /^\}$/ {exit}
' "$SCRIPT" > "$hsi_helper"
# shellcheck disable=SC1090
. "$hsi_helper"
hsi_call_marker="$TMPDIR/hsi-fwupdmgr-called"
# shellcheck disable=SC2329 # invoked indirectly by the extracted read_hsi helper.
systemctl() { return 1; }
# shellcheck disable=SC2329 # invoked indirectly by the extracted read_hsi helper.
fwupdmgr() { : > "$hsi_call_marker"; return 9; }
assert_eq "unknown (fwupd dormant; explicit check required)" "$(read_hsi)" \
    "dormant fwupd stays dormant during a status query"
assert_cmd_failure "dormant HSI query never invokes fwupdmgr" \
    test -e "$hsi_call_marker"
# shellcheck disable=SC2329 # invoked indirectly by the extracted read_hsi helper.
systemctl() { return 0; }
# shellcheck disable=SC2329 # invoked indirectly by the extracted read_hsi helper.
fwupdmgr() { return 9; }
assert_eq "unknown" "$(read_hsi)" \
    "unsupported fwupdmgr platform renders unknown without aborting"
# shellcheck disable=SC2317,SC2329 # invoked indirectly by the extracted read_hsi helper.
fwupdmgr() {
    printf '\033[1mHost Security ID:\033[0m HSI:3!\n'
}
assert_eq "HSI:3!" "$(read_hsi)" \
    "valid colored HSI output is stripped and parsed intact"
# Put the match before more than one pipe buffer of trailing output. An awk
# `print; exit` makes the upstream printf lose SIGPIPE under pipefail.
# shellcheck disable=SC2317,SC2329 # invoked indirectly by the extracted read_hsi helper.
fwupdmgr() {
    local i
    printf 'Host Security ID: HSI:4\n'
    for ((i = 0; i < 12000; i++)); do
        printf 'Trailing fwupd detail %05d xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n' "$i"
    done
}
assert_eq "HSI:4" "$(read_hsi)" \
    "HSI parsing consumes long trailing output without a SIGPIPE race"
assert_not_grep 'print; exit' "$hsi_helper" \
    "HSI extraction does not terminate its upstream pipeline early"
unset -f fwupdmgr systemctl

# --- Snapper status is a fixed non-mutating privilege boundary ---------------
assert_grep_fixed 'sudo -n /usr/libexec/noid-snapper-status' "$SCRIPT" \
    "Snapper: exact argument-free status helper call"
assert_not_grep 'snapper -c root list' "$SCRIPT" \
    "Snapper: desktop status no longer receives arbitrary config access"
assert_grep_fixed 'boot=(ready|reboot-required|degraded)' "$SCRIPT" \
    "Snapper: helper output is schema-validated before display"
assert_not_grep 'FIRSTBOOT_REBOOT_MARKER=' "$SCRIPT" \
    "noid-status does not duplicate the firstboot marker reader"
assert_grep_fixed 'REBOOT_STATE=$(read_reboot_state)' "$SCRIPT" \
    "firstboot, kernel, NVIDIA and blockers converge through one status reader"

# --- Update reminder survives a shell without desktop environment -----------
assert_cmd_failure \
    "update reminder no longer depends on an inherited runtime variable" \
    grep -qF -- 'if [ -n "${XDG_RUNTIME_DIR:-}" ]' "$SCRIPT"
assert_grep_fixed 'runtime="/run/user/${uid}"' "$SCRIPT" \
    "update reminder derives the canonical systemd user runtime path"
assert_grep_fixed 'runtime_meta=$(stat -Lc' "$SCRIPT" \
    "update reminder binds the runtime directory to trusted metadata"
assert_grep_fixed 'bus_meta=$(stat -Lc' "$SCRIPT" \
    "update reminder binds the D-Bus socket to the same user"
assert_grep_fixed 'XDG_RUNTIME_DIR="$runtime"' "$SCRIPT" \
    "update reminder passes the verified runtime only to its bounded query"
assert_grep_fixed 'DBUS_SESSION_BUS_ADDRESS="unix:path=${bus}"' "$SCRIPT" \
    "update reminder passes the verified user-bus address explicitly"
assert_grep_fixed '/usr/bin/systemctl --user is-enabled' "$SCRIPT" \
    "update reminder uses systemd's native read-only timer query"

update_reminder_helper="$TMPDIR/update-reminder-helper.sh"
sed -n \
    '/^# BEGIN UPDATE_REMINDER_STATUS_READER$/,/^# END UPDATE_REMINDER_STATUS_READER$/p' \
    "$SCRIPT" > "$update_reminder_helper"
# shellcheck source=/dev/null
. "$update_reminder_helper"
assert_eq enabled "$(classify_update_reminder_state 0 enabled)" \
    "successful enabled timer state is accepted"
assert_eq disabled "$(classify_update_reminder_state 1 disabled)" \
    "systemctl's disabled timer result is accepted"
assert_eq 'unknown (user-session timer)' \
    "$(classify_update_reminder_state 0 generated)" \
    "unexpected successful unit states remain unknown"
assert_eq 'unknown (user-session timer)' \
    "$(classify_update_reminder_state 1 enabled)" \
    "contradictory systemctl status and output remain unknown"
assert_eq 'unknown (user-session timer)' \
    "$(classify_update_reminder_state 124 '')" \
    "a bounded-query timeout remains an honest unknown"

# --- Add-on patch age is read from local state and never probed -------------
# M16/M35 disable every browser-owned background extension update, so this is
# the only surface that tells a user their add-ons are stale. It must stay a
# pure reader: a status command that reached a marketplace would turn a
# diagnostic into the exact autonomous traffic the image suppresses.
assert_grep_fixed \
    'EXTENSION_CHECK_STATE_FILE="${XDG_STATE_HOME:-$HOME/.local/state}/noid-privacy/extension-checks"' \
    "$SCRIPT" "add-on check state path matches the M25 producer literally"
assert_grep_fixed 'EXTENSION_CHECK_STALE_DAYS=30' "$SCRIPT" \
    "add-on staleness threshold is an explicit named constant"
assert_grep_fixed 'fmt_kv_warn "Add-on updates"' "$SCRIPT" \
    "a stale or failed add-on check is rendered as a warning"
# An armed WAN-egress-strict boundary is the usual reason a tunnel this image
# cannot pin never connects, and the client only ever reports EPERM from its
# own socket. STRICT_EMPTY in particular reads as healthy in every other view.
assert_grep_fixed 'fmt_kv "WAN-egress-strict" "$WAN_STRICT"' "$SCRIPT" \
    "the WAN-egress-strict mode is reported next to the VPN row"
assert_grep_fixed 'MODE=STRICT_EMPTY)    WAN_STRICT="armed, nothing pinned' "$SCRIPT" \
    "the armed-but-unpinned mode names its consequence rather than reading healthy"
assert_grep_fixed 'MODE=ERROR)           WAN_STRICT="error (do not infer protection)"' \
    "$SCRIPT" "a failed boundary is never rendered as protection"
# Kernel WireGuard discovery is a `wg show` read. M26 ships wireguard-tools,
# so this row normally stays silent; on a host where it was removed an
# unmanaged provider tunnel is unpinnable and its handshake is dropped.
assert_grep_fixed 'command -v wg >/dev/null 2>&1' "$SCRIPT" \
    "an unreadable kernel tunnel is detected through the missing wg tool"
# A DOWN interface is not a VPN. Measured on the installed image: a leftover
# WireGuard device left behind by an earlier test read as "active (mullsim3)"
# while nothing carried traffic. Claiming protection that is absent is the one
# direction this row must never fail in, so both detection paths filter state.
assert_grep_fixed '$2 != "DOWN" {print $1}' "$SCRIPT" \
    "a WireGuard interface that is administratively down is not reported active"
assert_grep_fixed '/^(tun|tap|proton|wg)/ && $2 != "DOWN"' "$SCRIPT" \
    "the tun/tap fallback filters interface state the same way"
assert_not_grep_extended "show type wireguard 2>/dev/null \| awk '\{print \\\$1\}'" \
    "$SCRIPT" "no detection path accepts an interface on existence alone"
assert_grep_fixed 'kernel tunnel unreadable (install wireguard-tools to pin it)' \
    "$SCRIPT" "that condition names the package that fixes it"
assert_grep_fixed 'addon-updates:ok' "$SCRIPT" \
    "brief mode exposes the add-on check verdict"
assert_grep_fixed '"addon_check": next(v),' "$SCRIPT" \
    "json mode exposes the add-on check verdict"
assert_not_grep_extended 'curl|wget|addons\.mozilla\.org|addons\.thunderbird\.net' \
    "$SCRIPT" "status never contacts a marketplace to determine add-on age"

# --- DNS mode is visible without leaking connection identity ----------------
assert_grep_fixed 'DNS_MODE_CLI=/usr/local/sbin/noid-dns-mode' "$SCRIPT" \
    "DNS status consumes the canonical selector backend"
assert_grep_fixed '"$cli" --status-machine' "$SCRIPT" \
    "DNS status requests only the closed machine schema"
assert_grep_fixed 'dns:${DNS_BRIEF}' "$SCRIPT" \
    "brief status makes a persistent opportunistic selection visible"
assert_grep_fixed 'fmt_kv_warn "DNS policy"' "$SCRIPT" \
    "opportunistic, off, invalid or drifted DNS policy is prominent"
assert_grep_fixed 'fmt_kv "DNS active path" "$DNS_ACTIVE_PATH"' "$SCRIPT" \
    "full status distinguishes selected policy from active routing scope"
assert_not_grep 'GENERAL.CONNECTION\|connection.id\|ipv4.dns\|ipv6.dns' \
    "$SCRIPT" \
    "DNS status does not collect profile names or resolver addresses"

dns_status_helper="$TMPDIR/dns-status-helper.sh"
sed -n \
    '/^# BEGIN DNS_TRANSPORT_STATUS_READER$/,/^# END DNS_TRANSPORT_STATUS_READER$/p' \
    "$SCRIPT" > "$dns_status_helper"
assert_cmd_success "extracted DNS status reader parses" bash -n "$dns_status_helper"
# shellcheck source=/dev/null
. "$dns_status_helper"
DNS_FIXTURE=$(mktemp /var/tmp/noid-dns-mode-fixture.XXXXXX)
write_dns_fixture() {
    cat > "$DNS_FIXTURE" <<DNS_STATUS_EOF
#!/bin/bash
cat <<'DNS_STATE_EOF'
$1
DNS_STATE_EOF
DNS_STATUS_EOF
    chmod 0755 "$DNS_FIXTURE"
}
write_dns_fixture 'NOID-DNS-MODE-V2
selection=opportunistic
configured=opportunistic
runtime_global=opportunistic
physical_configured=opportunistic
physical_runtime=opportunistic
scope=link
link_mode=no'
read_dns_transport_state "$DNS_FIXTURE"
format_dns_transport_state
assert_eq yes "$DNS_STATE_VALID" \
    "DNS status accepts the exact versioned backend schema"
assert_eq opportunistic "$DNS_BRIEF" \
    "brief DNS status exposes a persistent opportunistic selection"
assert_eq 1 "$DNS_POLICY_WARN" \
    "opportunistic DNS remains a warning despite an active VPN path"
assert_eq \
    'VPN/private ~. link (DoT=no); selected global policy dormant' \
    "$DNS_ACTIVE_PATH" \
    "active tunnel DNS is separated from the dormant global policy"
write_dns_fixture 'NOID-DNS-MODE-V2
selection=default
configured=yes
runtime_global=yes
physical_configured=default
physical_runtime=yes
scope=global
link_mode=none'
read_dns_transport_state "$DNS_FIXTURE"
format_dns_transport_state
assert_eq strict "$DNS_BRIEF" \
    "image-default DNS renders as strict"
assert_eq 0 "$DNS_POLICY_WARN" \
    "converged strict DNS is not a warning"
assert_eq 'global resolver (DoT=yes)' "$DNS_ACTIVE_PATH" \
    "global DNS path reports its effective transport"
write_dns_fixture 'NOID-DNS-MODE-V2
selection=opportunistic
selection=strict
configured=yes
runtime_global=yes
physical_configured=yes
physical_runtime=yes
scope=global'
read_dns_transport_state "$DNS_FIXTURE"
format_dns_transport_state
assert_eq no "$DNS_STATE_VALID" \
    "DNS status rejects duplicate and incomplete fields"
assert_eq check "$DNS_BRIEF" \
    "invalid DNS status cannot be rendered as healthy"

extension_check_helper="$TMPDIR/extension-check-helper.sh"
sed -n \
    '/^# BEGIN EXTENSION_CHECK_STATUS_READER$/,/^# END EXTENSION_CHECK_STATUS_READER$/p' \
    "$SCRIPT" > "$extension_check_helper"
assert_cmd_success "extracted add-on check reader parses" \
    bash -n "$extension_check_helper"

ext_state_home="$TMPDIR/ext-state"
mkdir -p "$ext_state_home/noid-privacy"
ext_state_file="$ext_state_home/noid-privacy/extension-checks"

# read_extension_check_state assigns two globals instead of printing one of
# them, so drive it in a subshell and report both results on one line.
ext_probe() {
    XDG_STATE_HOME="$ext_state_home" HOME="$TMPDIR/ext-home" bash -c '
        set -uo pipefail
        . "$1"
        EXT_CHECK_STATE=""
        EXT_CHECK_WARN=1
        read_extension_check_state
        printf "%s|%s\n" "$EXT_CHECK_WARN" "$EXT_CHECK_STATE"
    ' _ "$extension_check_helper"
}

ext_stamp() { date -u -d "$1" +%Y-%m-%dT%H:%M:%SZ; }

rm -f "$ext_state_file"
assert_eq '1|never checked (run noid-update-all.sh)' "$(ext_probe)" \
    "a machine that never ran update-all is reported as never checked"

printf 'component=firefox-ubo checked=%s result=current\ncomponent=thunderbird-dkim checked=%s result=current\n' \
    "$(ext_stamp now)" "$(ext_stamp now)" > "$ext_state_file"
assert_eq '0|checked today (2 component(s))' "$(ext_probe)" \
    "a same-day check across two components is current"

printf 'component=firefox-ubo checked=%s result=current\n' \
    "$(ext_stamp '14 days ago')" > "$ext_state_file"
assert_eq '0|checked 14d ago (1 component(s))' "$(ext_probe)" \
    "a check inside the staleness window is not a warning"

printf 'component=firefox-ubo checked=%s result=current\n' \
    "$(ext_stamp '30 days ago')" > "$ext_state_file"
assert_eq '1|checked 30d ago (1 component(s))' "$(ext_probe)" \
    "the staleness threshold itself already warns"

printf 'component=firefox-ubo checked=%s result=current\ncomponent=firefox-marketplace checked=%s result=failed\n' \
    "$(ext_stamp now)" "$(ext_stamp now)" > "$ext_state_file"
assert_eq '1|checked today; 1 of 2 component(s) failed' "$(ext_probe)" \
    "one failed component warns even when the check ran today"

# The newest record decides the age; an old component must not hide a recent
# check, and a recent one must not hide that the rest is stale.
printf 'component=firefox-ubo checked=%s result=current\ncomponent=thunderbird-dkim checked=%s result=current\n' \
    "$(ext_stamp '400 days ago')" "$(ext_stamp now)" > "$ext_state_file"
assert_eq '0|checked today (2 component(s))' "$(ext_probe)" \
    "the newest record determines the reported age"

printf 'garbage\ncomponent=firefox-ubo checked=not-a-date result=current\n' \
    > "$ext_state_file"
assert_eq '1|unreadable (no valid check record)' "$(ext_probe)" \
    "a malformed state file is reported, never silently treated as current"

printf 'component=firefox-ubo checked=%s result=bogus\n' "$(ext_stamp now)" \
    > "$ext_state_file"
assert_eq '1|unreadable (no valid check record)' "$(ext_probe)" \
    "an unknown result token is rejected"

rm -f "$ext_state_file"
ln -s /dev/null "$ext_state_file"
assert_eq '1|never checked (run noid-update-all.sh)' "$(ext_probe)" \
    "a symlinked state file is never followed"
rm -f "$ext_state_file"

# --- Brief + JSON + Help modes still present --------------------------------
assert_grep_fixed '1:--brief) MODE="brief"' "$SCRIPT" "brief mode"
assert_grep_fixed '1:--json)  MODE="json"'  "$SCRIPT" "json mode"
assert_grep_fixed '1:--help|1:-h)'          "$SCRIPT" "help mode"
assert_grep_fixed 'SELinux        : enforcing/permissive state' "$SCRIPT" \
    "help describes the SELinux output actually rendered"
assert_grep_fixed 'VPN            : WireGuard/VPN interface presence' "$SCRIPT" \
    "help describes the VPN output actually rendered"
assert_grep_fixed 'DNS            : persistent global/physical policy and active routing scope' \
    "$SCRIPT" "help describes selected and effective DNS state"
assert_grep_fixed 'Updates        : update-reminder timer, add-on marketplace check age (read' \
    "$SCRIPT" "help describes the update outputs actually rendered"
assert_grep_fixed 'from local state only; no network request) and' "$SCRIPT" \
    "help states that the add-on age costs no network request"
assert_not_grep 'policy name' "$SCRIPT" \
    "help does not advertise an unrendered SELinux policy name"
assert_not_grep 'killswitch layers' "$SCRIPT" \
    "help does not advertise unrendered VPN kill-switch layers"
assert_not_grep 'last noid-update-all run' "$SCRIPT" \
    "help does not advertise an unrendered update timestamp"
assert_not_grep 'AIDE_NEXT\|AIDE_LAST' "$SCRIPT" \
    "status does not query unused AIDE timer timestamps"
assert_grep_fixed 'marker written by M99 and refreshed by M41' "$SCRIPT" \
    "release-file ownership is attributed to its real writers"
assert_grep_fixed 'case "$#:${1:-}" in' "$SCRIPT" \
    "CLI mode selection includes exact argument arity"
assert_grep_fixed 'FMT_LIB=/usr/local/lib/noid-privacy/agent-install-format.sh' \
    "$SCRIPT" "full status uses the shared NoID Privacy CLI presentation"
assert_grep_fixed 'fmt_banner "NoID Privacy — System Status"' "$SCRIPT" \
    "full status uses the common boxed identity"
assert_grep_fixed 'fmt_note "$(date -Iseconds)"' "$SCRIPT" \
    "full status retains its timestamp below the bounded banner"
for section in Kernel LSM Network Authentication 'Integrity monitoring' \
        Hardware Storage Updates; do
    assert_grep_fixed "fmt_section \"$section\"" "$SCRIPT" \
        "full status uses the shared section style: $section"
done
assert_grep_fixed 'fmt_kv_warn "LUKS backup"' "$SCRIPT" \
    "missing LUKS backup remains visually prominent"
assert_grep_fixed 'fmt_kv_warn "Reboot"' "$SCRIPT" \
    "pending reboot remains visually prominent"
assert_not_grep 'NoID Privacy — hardening status' "$SCRIPT" \
    "retired unboxed status header is absent"
assert_not_grep_extended 'printf .%sKernel|printf .%sNetwork' "$SCRIPT" \
    "retired per-command section rendering is absent"

# --- Faillock zero/one/failure semantics -----------------------------------
assert_grep_fixed 'count_faillock_records()' "$SCRIPT" \
    "faillock records use a dedicated total-count helper"
assert_not_grep 'faillock --user .*grep -c' "$SCRIPT" \
    "healthy zero-record state cannot trip grep/pipefail"

faillock_helper="$TMPDIR/faillock-helper.sh"
awk '
    /^count_faillock_records\(\) \{/ {copy=1}
    copy {print}
    copy && /^\}$/ {exit}
' "$SCRIPT" > "$faillock_helper"
# shellcheck disable=SC1090
. "$faillock_helper"
faillock_zero() { return 0; }
faillock_one() { printf '%s\n' '2026-07-11 01:02:03 TTY /dev/tty1 V' ; }
faillock_broken() { return 7; }
assert_eq "0" "$(count_faillock_records faillock_zero)" \
    "zero faillock records are a successful zero"
assert_eq "1" "$(count_faillock_records faillock_one)" \
    "one faillock record is counted"
assert_cmd_failure "failed faillock query remains distinguishable" \
    count_faillock_records faillock_broken

# --- JSON output contains the patched fields --------------------------------
assert_grep_fixed '"auditd": next(v)'              "$SCRIPT" "JSON: auditd key"
assert_grep_fixed '"hsi": next(v)'                 "$SCRIPT" "JSON: hsi key"
assert_grep_fixed '"platform_security": next(v)'   "$SCRIPT" "JSON: platform status key"
assert_grep_fixed '"wan_ipv6": next(v)'            "$SCRIPT" "JSON: WAN IPv6 postcondition key"
assert_grep_fixed '"dns": {'                       "$SCRIPT" "JSON: nested DNS state object"
assert_grep_fixed '"active_scope": next(v)'        "$SCRIPT" "JSON: DNS routing-scope key"
assert_grep_fixed '"snapper": next(v)'             "$SCRIPT" "JSON: snapper key"
assert_grep_fixed 'json.dump(document, sys.stdout' "$SCRIPT" \
    "JSON output uses one standards-compliant serializer"

STATUS_JSON="$TMPDIR/noid-status.json"
JSON_SERIALIZER="$TMPDIR/noid-status-json.py"
awk '
    /^JSON_PY$/ { copying=0; exit }
    copying { print }
    /<<.JSON_PY.$/ { copying=1 }
' "$SCRIPT" > "$JSON_SERIALIZER"
assert_file_min_size "$JSON_SERIALIZER" 512 \
    "noid-status JSON serializer is extractable"
json_values=(
    '2026-08-01T12:34:56+02:00'
    'lockdown-fixture' 'secure-boot-fixture' 'signature-fixture'
    'selinux-fixture'
    'firewall-fixture' 'zones-fixture' 'xdp-fixture' 'wan-ipv6-fixture'
    'vpn-fixture'
    'opportunistic' 'opportunistic' 'opportunistic'
    'opportunistic' 'opportunistic' 'link' 'no'
    'faillock-fixture' 'faillock-config-fixture'
    'aide-fixture' 'aide-popup-fixture' 'audit-notify-fixture'
    'auditd-fixture' 'audit-storage-fixture'
    'usbguard-fixture' 'hsi-fixture' 'platform-fixture'
    'luks-fixture' 'luks-backup-fixture' 'snapper-fixture'
    'reminder-fixture' 'addon-check-fixture' 'reboot-fixture'
)
if env -i PATH=/usr/bin:/bin HOME="$TMPDIR" \
        python3 -I "$JSON_SERIALIZER" "${json_values[@]}" > "$STATUS_JSON"; then
    _pass "noid-status JSON serializer runs only on synthetic source fixtures"
else
    _fail "noid-status JSON serializer runs only on synthetic source fixtures"
fi
assert_cmd_success "noid-status output parses as JSON" \
    python3 -m json.tool "$STATUS_JSON"
assert_cmd_success "noid-status JSON has the documented nested object schema" \
    python3 -c '
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
assert isinstance(d, dict)
assert set(d) == {"timestamp", "kernel", "lsm", "network", "auth", "integrity", "hardware", "storage", "updates"}
assert "platform_security" in d["hardware"] and "snapper" in d["storage"]
assert "wan_ipv6" in d["network"]
assert d["network"]["dns"] == {
    "selection": "opportunistic",
    "configured": "opportunistic",
    "runtime_global": "opportunistic",
    "physical_configured": "opportunistic",
    "physical_runtime": "opportunistic",
    "active_scope": "link",
    "active_link_mode": "no",
}
assert "audit_storage" in d["integrity"]
assert set(d["updates"]) == {"reminder_timer", "addon_check", "reboot_required"}
assert d["updates"]["addon_check"] == "addon-check-fixture"
' "$STATUS_JSON"
assert_cmd_failure "unknown noid-status option is rejected" \
    bash "$SCRIPT" --unknown
assert_cmd_failure "extra noid-status argument is rejected" \
    bash "$SCRIPT" --json extra
assert_cmd_failure "extra help argument is rejected" \
    bash "$SCRIPT" --help extra
assert_grep_fixed 'read_platform_status()'          "$SCRIPT" \
    "Module 15 status has a real consumer"
assert_grep_fixed 'usbguard-gnome-wildcard.status' "$SCRIPT" \
    "USBGuard cleanup degradation has a status consumer"
assert_grep_fixed 'MEI_KT_SOL_HOST_BINDING)'        "$SCRIPT" \
    "MEI KT/SOL result is parsed from the schema"
assert_not_grep '^ *\. "\$file"' "$SCRIPT" \
    "platform status data is never sourced as shell code"
assert_grep_fixed 'CHECKED_AT_KERNEL)' "$SCRIPT" \
    "platform reader parses the producer's kernel binding"
assert_grep_fixed 'CHECKED_POLICY_SHA256)' "$SCRIPT" \
    "platform reader parses the producer's policy binding"
assert_grep_fixed 'stale (MEI platform policy changed since check)' "$SCRIPT" \
    "platform reader exposes policy-stale evidence"
assert_grep_fixed 'stale (checked kernel %s; running %s)' "$SCRIPT" \
    "platform reader exposes kernel-stale evidence"

wan_ipv6_helper="$TMPDIR/wan-ipv6-helper.sh"
sed -n '/^# BEGIN WAN_IPV6_STATUS_READER$/,/^# END WAN_IPV6_STATUS_READER$/p' \
    "$SCRIPT" > "$wan_ipv6_helper"
# shellcheck source=/dev/null
. "$wan_ipv6_helper"
WAN_IPV6_FIXTURE_DIR="$TMPDIR/wan-ipv6-state"
WAN_IPV6_FIXTURE_FILE="$WAN_IPV6_FIXTURE_DIR/status"
mkdir -m 0755 "$WAN_IPV6_FIXTURE_DIR"
wan_ipv6_owner=$(stat -c '%U:%G' "$WAN_IPV6_FIXTURE_DIR")
wan_ipv6_file_meta="$wan_ipv6_owner:644:1"
wan_ipv6_dir_meta="$wan_ipv6_owner:755"
WAN_IPV6_LIVE_CMDLINE="$TMPDIR/wan-ipv6-live-cmdline"
WAN_IPV6_LIVE_SYS="$TMPDIR/wan-ipv6-live-sys"
WAN_IPV6_LIVE_PROC="$TMPDIR/wan-ipv6-live-proc"
printf '%s\n' 'quiet rd.live.image=1 test' > "$WAN_IPV6_LIVE_CMDLINE"
mkdir -p "$WAN_IPV6_LIVE_SYS/eth0/device" \
    "$WAN_IPV6_LIVE_PROC/eth0"
printf '%s\n' 1 > "$WAN_IPV6_LIVE_PROC/eth0/disable_ipv6"
assert_eq \
    'LIVE-OFF (eth0; runtime verified, non-persistent Live media)' \
    "$(read_live_wan_ipv6_status "$WAN_IPV6_LIVE_CMDLINE" \
        "$WAN_IPV6_LIVE_SYS" "$WAN_IPV6_LIVE_PROC")" \
    "noid-status reports verified Live-media physical IPv6 without a false warning"
printf '%s\n' 0 > "$WAN_IPV6_LIVE_PROC/eth0/disable_ipv6"
assert_eq 'ERROR (eth0; Live physical IPv6 not disabled)' \
    "$(read_live_wan_ipv6_status "$WAN_IPV6_LIVE_CMDLINE" \
        "$WAN_IPV6_LIVE_SYS" "$WAN_IPV6_LIVE_PROC")" \
    "noid-status exposes a real Live-media physical IPv6 failure"
rm -rf "$WAN_IPV6_LIVE_SYS/eth0" "$WAN_IPV6_LIVE_PROC/eth0"
assert_eq 'LIVE-DEFERRED (no physical NIC; default-disable remains)' \
    "$(read_live_wan_ipv6_status "$WAN_IPV6_LIVE_CMDLINE" \
        "$WAN_IPV6_LIVE_SYS" "$WAN_IPV6_LIVE_PROC")" \
    "noid-status distinguishes a Live environment without a physical NIC"
printf '%s\n' 'rd.live.imagefoo foo=rd.live.image' \
    > "$WAN_IPV6_LIVE_CMDLINE"
assert_cmd_failure "near-match Live tokens do not mask installed status" \
    read_live_wan_ipv6_status "$WAN_IPV6_LIVE_CMDLINE" \
        "$WAN_IPV6_LIVE_SYS" "$WAN_IPV6_LIVE_PROC"
printf '%s\n' NOID_WAN_IPV6_STATUS_V1 MODE=ENFORCED IFACE=eth0 \
    > "$WAN_IPV6_FIXTURE_FILE"
chmod 0644 "$WAN_IPV6_FIXTURE_FILE"
assert_eq 'ENFORCED (eth0)' \
    "$(read_wan_ipv6_status "$WAN_IPV6_FIXTURE_FILE" \
        "$wan_ipv6_file_meta" "$wan_ipv6_dir_meta")" \
    "noid-status accepts the exact enforced IPv6-off contract"
printf '%s\n' NOID_WAN_IPV6_STATUS_V1 MODE=DEFERRED IFACE=- \
    > "$WAN_IPV6_FIXTURE_FILE"
assert_eq 'DEFERRED (no physical NIC; default-disable remains)' \
    "$(read_wan_ipv6_status "$WAN_IPV6_FIXTURE_FILE" \
        "$wan_ipv6_file_meta" "$wan_ipv6_dir_meta")" \
    "noid-status distinguishes deferred from enforced"
printf '%s\n' NOID_WAN_IPV6_STATUS_V1 MODE=ERROR IFACE=wlan0 \
    > "$WAN_IPV6_FIXTURE_FILE"
assert_eq 'ERROR (wlan0; physical IPv6 enforcement degraded)' \
    "$(read_wan_ipv6_status "$WAN_IPV6_FIXTURE_FILE" \
        "$wan_ipv6_file_meta" "$wan_ipv6_dir_meta")" \
    "noid-status makes IPv6 enforcement failure prominent"
printf '%s\n' EXTRA=field >> "$WAN_IPV6_FIXTURE_FILE"
assert_eq 'unknown (invalid status-file schema)' \
    "$(read_wan_ipv6_status "$WAN_IPV6_FIXTURE_FILE" \
        "$wan_ipv6_file_meta" "$wan_ipv6_dir_meta")" \
    "noid-status rejects extra IPv6 status fields"

platform_helper="$TMPDIR/platform-helper.sh"
sed -n '/^# BEGIN PLATFORM_STATUS_READER$/,/^# END PLATFORM_STATUS_READER$/p' \
    "$SCRIPT" > "$platform_helper"
# shellcheck source=/dev/null
. "$platform_helper"
PLATFORM_FIXTURE_DIR="$TMPDIR/platform-state"
PLATFORM_FIXTURE_FILE="$PLATFORM_FIXTURE_DIR/mei-status.txt"
mkdir -m 0755 "$PLATFORM_FIXTURE_DIR"
platform_owner=$(stat -c '%U:%G' "$PLATFORM_FIXTURE_DIR")
platform_file_meta="$platform_owner:644"
platform_dir_meta="$platform_owner:755"
policy_a=$(printf 'a%.0s' {1..64})
policy_b=$(printf 'b%.0s' {1..64})
write_staged_platform_fixture() {
    case "$1" in
        intel)
            cat > "$PLATFORM_FIXTURE_FILE" <<'PLATFORM_STATUS_EOF'
CPU_VENDOR=intel
STATUS_LIFECYCLE=build-time-placeholder
MEI_STATE=build-time-unknown
MEI_SUBMODULES_BLOCKED=none
MEI_KT_SOL_HOST_BINDING=configured-not-runtime-verified
MEI_FWUPD_VISIBILITY=runtime-check-required
PLATFORM_STATUS_EOF
            ;;
        amd)
            cat > "$PLATFORM_FIXTURE_FILE" <<'PLATFORM_STATUS_EOF'
CPU_VENDOR=amd
STATUS_LIFECYCLE=build-time-placeholder
MEI_STATE=n/a-on-amd
PSP_STATE=runtime-check-required
CCP_POLICY=not-blacklisted
PSP_FWUPD_VISIBILITY=runtime-check-required
PSB_STATE=see-fwupdmgr-security
HARDWARE_LAYER_DOC=/usr/share/doc/noid-privacy/15-amd-psp-hardware-layer.md
PLATFORM_STATUS_EOF
            ;;
        unknown)
            cat > "$PLATFORM_FIXTURE_FILE" <<'PLATFORM_STATUS_EOF'
CPU_VENDOR=unknown
STATUS_LIFECYCLE=build-time-placeholder
MEI_STATE=n/a
PSP_STATE=n/a
NOTE=vendor-specific firmware status unavailable; generic hardening still applies
PLATFORM_STATUS_EOF
            ;;
    esac
    chmod 0644 "$PLATFORM_FIXTURE_FILE"
}
for staged_vendor in intel amd unknown; do
    write_staged_platform_fixture "$staged_vendor"
    assert_eq 'pending (Live/build-time placeholder; target-boot refresh not run)' \
        "$(read_platform_status "$PLATFORM_FIXTURE_FILE" "$platform_file_meta" \
            "$platform_dir_meta" 6.99.1-test "$policy_a")" \
        "exact $staged_vendor build placeholder is explicit pending state"
done
write_staged_platform_fixture intel
sed -i '/^MEI_SUBMODULES_BLOCKED=/d' "$PLATFORM_FIXTURE_FILE"
assert_eq 'unknown (invalid platform-status schema)' \
    "$(read_platform_status "$PLATFORM_FIXTURE_FILE" "$platform_file_meta" \
        "$platform_dir_meta" 6.99.1-test "$policy_a")" \
    "partial staged schema is rejected"
write_staged_platform_fixture intel
printf '%s\n' 'EXTRA=unreviewed' >> "$PLATFORM_FIXTURE_FILE"
assert_eq 'unknown (invalid platform-status schema)' \
    "$(read_platform_status "$PLATFORM_FIXTURE_FILE" "$platform_file_meta" \
        "$platform_dir_meta" 6.99.1-test "$policy_a")" \
    "extra staged field is rejected"
write_staged_platform_fixture intel
sed -i 's/^STATUS_LIFECYCLE=.*/STATUS_LIFECYCLE=runtime-check-required/' \
    "$PLATFORM_FIXTURE_FILE"
assert_eq 'unknown (invalid platform-status schema)' \
    "$(read_platform_status "$PLATFORM_FIXTURE_FILE" "$platform_file_meta" \
        "$platform_dir_meta" 6.99.1-test "$policy_a")" \
    "unrecognized lifecycle cannot relabel an incomplete record"
write_valid_platform_fixture() {
    cat > "$PLATFORM_FIXTURE_FILE" <<PLATFORM_STATUS_EOF
CPU_VENDOR=intel
MEI_STATE=mei-me-bound
MEI_CORE_POLICY=loadable
MEI_KERNEL_REGRESSION=no
MEI_SUBMODULES_BLOCKED=none
MEI_KT_SOL_HOST_BINDING=enforced
MEI_FWUPD_VISIBILITY=available-platform-results-vary
CHECKED_AT_KERNEL=6.99.1-test
CHECKED_AT=2026-07-13T12:34:56Z
CHECKED_POLICY_SHA256=$policy_a
PLATFORM_STATUS_EOF
    chmod 0644 "$PLATFORM_FIXTURE_FILE"
}
write_valid_platform_fixture
assert_eq 'Intel MEI=mei-me-bound; core-policy=loadable; submodules=none; KT/SOL=enforced; fwupd=available-platform-results-vary' \
    "$(read_platform_status "$PLATFORM_FIXTURE_FILE" "$platform_file_meta" \
        "$platform_dir_meta" 6.99.1-test "$policy_a")" \
    "current kernel/policy-bound platform status is accepted"
sed -i 's/^MEI_KT_SOL_HOST_BINDING=.*/MEI_KT_SOL_HOST_BINDING=no-device-present/' \
    "$PLATFORM_FIXTURE_FILE"
assert_eq 'Intel MEI=mei-me-bound; core-policy=loadable; submodules=none; KT/SOL=no-device-present; fwupd=available-platform-results-vary' \
    "$(read_platform_status "$PLATFORM_FIXTURE_FILE" "$platform_file_meta" \
        "$platform_dir_meta" 6.99.1-test "$policy_a")" \
    "absent KT/SOL hardware is accepted without an enforcement claim"
sed -i 's/^MEI_KT_SOL_HOST_BINDING=.*/MEI_KT_SOL_HOST_BINDING=enforced/' \
    "$PLATFORM_FIXTURE_FILE"
sed -i 's/^MEI_SUBMODULES_BLOCKED=.*/MEI_SUBMODULES_BLOCKED=hdcp,wdt/' \
    "$PLATFORM_FIXTURE_FILE"
assert_eq 'Intel MEI=mei-me-bound; core-policy=loadable; submodules=hdcp,wdt; KT/SOL=enforced; fwupd=available-platform-results-vary' \
    "$(read_platform_status "$PLATFORM_FIXTURE_FILE" "$platform_file_meta" \
        "$platform_dir_meta" 6.99.1-test "$policy_a")" \
    "canonical opt-in MEI submodule state is accepted and displayed"
sed -i 's/^MEI_SUBMODULES_BLOCKED=.*/MEI_SUBMODULES_BLOCKED=wdt,hdcp/' \
    "$PLATFORM_FIXTURE_FILE"
assert_eq 'unknown (invalid platform-status schema)' \
    "$(read_platform_status "$PLATFORM_FIXTURE_FILE" "$platform_file_meta" \
        "$platform_dir_meta" 6.99.1-test "$policy_a")" \
    "non-canonical MEI submodule ordering is rejected"
write_valid_platform_fixture
sed -i \
    -e 's/^MEI_STATE=.*/MEI_STATE=blocked-by-policy/' \
    -e 's/^MEI_CORE_POLICY=.*/MEI_CORE_POLICY=blacklisted/' \
    -e 's/^MEI_FWUPD_VISIBILITY=.*/MEI_FWUPD_VISIBILITY=unavailable-by-policy/' \
    "$PLATFORM_FIXTURE_FILE"
assert_eq 'Intel MEI=blocked-by-policy; core-policy=blacklisted; submodules=none; KT/SOL=enforced; fwupd=unavailable-by-policy' \
    "$(read_platform_status "$PLATFORM_FIXTURE_FILE" "$platform_file_meta" \
        "$platform_dir_meta" 6.99.1-test "$policy_a")" \
    "complete MEI core-lockdown state is accepted and displayed"
write_valid_platform_fixture
assert_eq 'stale (checked kernel 6.99.1-test; running 7.0.0-new)' \
    "$(read_platform_status "$PLATFORM_FIXTURE_FILE" "$platform_file_meta" \
        "$platform_dir_meta" 7.0.0-new "$policy_a")" \
    "kernel change makes old platform evidence explicitly stale"
assert_eq 'stale (MEI platform policy changed since check)' \
    "$(read_platform_status "$PLATFORM_FIXTURE_FILE" "$platform_file_meta" \
        "$platform_dir_meta" 6.99.1-test "$policy_b")" \
    "policy change makes old platform evidence explicitly stale"
cat > "$PLATFORM_FIXTURE_FILE" <<PLATFORM_STATUS_EOF
CPU_VENDOR=amd
MEI_STATE=n/a-on-amd
PSP_STATE=firmware-managed
CCP_STATE=loaded
CCP_POLICY=not-blacklisted
PSP_FWUPD_VISIBILITY=available-platform-results-vary
PSB_STATE=see-fwupdmgr-security
HARDWARE_LAYER_DOC=/usr/share/doc/noid-privacy/15-amd-psp-hardware-layer.md
CHECKED_AT_KERNEL=6.99.1-test
CHECKED_AT=2026-07-13T12:34:56Z
CHECKED_POLICY_SHA256=$policy_a
PLATFORM_STATUS_EOF
assert_eq 'AMD PSP=firmware-managed; CCP=loaded; PSB=see-fwupdmgr-security' \
    "$(read_platform_status "$PLATFORM_FIXTURE_FILE" "$platform_file_meta" \
        "$platform_dir_meta" 6.99.1-test "$policy_a")" \
    "complete AMD runtime schema is accepted"
cat > "$PLATFORM_FIXTURE_FILE" <<PLATFORM_STATUS_EOF
CPU_VENDOR=unknown
MEI_STATE=n/a
PSP_STATE=n/a
NOTE=vendor-specific firmware status unavailable; generic hardening still applies
CHECKED_AT_KERNEL=6.99.1-test
CHECKED_AT=2026-07-13T12:34:56Z
CHECKED_POLICY_SHA256=$policy_a
PLATFORM_STATUS_EOF
assert_eq 'platform=unknown; MEI=n/a' \
    "$(read_platform_status "$PLATFORM_FIXTURE_FILE" "$platform_file_meta" \
        "$platform_dir_meta" 6.99.1-test "$policy_a")" \
    "complete unknown-vendor runtime schema is accepted"
write_valid_platform_fixture
printf '%s\n' 'CPU_VENDOR=intel' >> "$PLATFORM_FIXTURE_FILE"
assert_eq 'unknown (invalid platform-status schema)' \
    "$(read_platform_status "$PLATFORM_FIXTURE_FILE" "$platform_file_meta" \
        "$platform_dir_meta" 6.99.1-test "$policy_a")" \
    "duplicate platform-status fields are rejected"
write_valid_platform_fixture
chmod 0775 "$PLATFORM_FIXTURE_DIR"
assert_eq 'unknown (invalid status-directory metadata)' \
    "$(read_platform_status "$PLATFORM_FIXTURE_FILE" "$platform_file_meta" \
        "$platform_dir_meta" 6.99.1-test "$policy_a")" \
    "writable platform-status directory metadata is rejected"
chmod 0755 "$PLATFORM_FIXTURE_DIR"
ln -s "$PLATFORM_FIXTURE_FILE" "$PLATFORM_FIXTURE_DIR/status-link"
assert_eq unknown \
    "$(read_platform_status "$PLATFORM_FIXTURE_DIR/status-link" \
        "$platform_file_meta" "$platform_dir_meta" 6.99.1-test "$policy_a")" \
    "platform-status symlink is rejected"
assert_not_grep '\. "\$UG_STATE_FILE"' "$SCRIPT" \
    "USBGuard status data is never sourced as shell code"
assert_grep_fixed 'read_usbguard_state()' "$SCRIPT" \
    "USBGuard status uses a closed data parser"

usbguard_helper="$TMPDIR/usbguard-helper.sh"
awk '
    /^read_usbguard_state\(\) \{/ {copy=1}
    copy {print}
    copy && /^\}$/ {exit}
' "$SCRIPT" > "$usbguard_helper"
# shellcheck disable=SC1090
. "$usbguard_helper"
USB_FIXTURE_DIR="$TMPDIR/usbguard-state"
USB_FIXTURE_FILE="$USB_FIXTURE_DIR/usbguard-status.txt"
mkdir -m 0755 "$USB_FIXTURE_DIR"
file_owner=$(stat -c '%U:%G' "$USB_FIXTURE_DIR")
valid_file_meta="$file_owner:644"
valid_dir_meta="$file_owner:755"
write_valid_usbguard_fixture() {
    cat > "$USB_FIXTURE_FILE" <<'USB_STATUS_EOF'
STATE=real
DEVICE_COUNT=2
FALLBACK_ACTIVE=no
LAST_RUN=2026-07-13T12:34:56+02:00
USB_STATUS_EOF
    chmod 0644 "$USB_FIXTURE_FILE"
}
write_valid_usbguard_fixture
assert_eq real "$(read_usbguard_state "$USB_FIXTURE_FILE" \
    "$valid_file_meta" "$valid_dir_meta")" \
    "valid USBGuard status data is parsed"

usbguard_brief_helper="$TMPDIR/usbguard-brief-helper.sh"
awk '
    /^classify_usbguard_brief\(\) \{/ {copy=1}
    copy {print}
    copy && /^\}$/ {exit}
' "$SCRIPT" > "$usbguard_brief_helper"
# shellcheck disable=SC1090
. "$usbguard_brief_helper"
assert_eq ok "$(classify_usbguard_brief 'active (first-boot state: real)')" \
    "brief USBGuard status accepts only the exact healthy state"
assert_eq check \
    "$(classify_usbguard_brief 'active (first-boot state: emergency)')" \
    "emergency USBGuard policy is prominent in brief mode"
assert_eq check \
    "$(classify_usbguard_brief 'active (first-boot state: unknown (invalid status-file content))')" \
    "unparseable USBGuard state is not reported healthy"
assert_eq check \
    "$(classify_usbguard_brief 'active (first-boot state: real); GNOME wildcard cleanup DEGRADED')" \
    "USBGuard cleanup degradation is not reported healthy"
assert_eq inactive "$(classify_usbguard_brief inactive)" \
    "inactive USBGuard retains its distinct brief state"

HOSTILE_MARKER="$TMPDIR/usbguard-hostile-executed"
cat > "$USB_FIXTURE_FILE" <<USB_STATUS_EOF
STATE=\$(touch "$HOSTILE_MARKER")
DEVICE_COUNT=2
FALLBACK_ACTIVE=no
LAST_RUN=2026-07-13T12:34:56+02:00
USB_STATUS_EOF
chmod 0644 "$USB_FIXTURE_FILE"
assert_eq 'unknown (invalid status-file content)' \
    "$(read_usbguard_state "$USB_FIXTURE_FILE" "$valid_file_meta" "$valid_dir_meta")" \
    "hostile USBGuard value is rejected as data"
[ ! -e "$HOSTILE_MARKER" ] \
    && _pass "hostile USBGuard value was not executed" \
    || _fail "hostile USBGuard value executed"

write_valid_usbguard_fixture
printf '%s\n' 'STATE=emergency' >> "$USB_FIXTURE_FILE"
assert_eq 'unknown (invalid status-file content)' \
    "$(read_usbguard_state "$USB_FIXTURE_FILE" "$valid_file_meta" "$valid_dir_meta")" \
    "duplicate USBGuard key is rejected"

write_valid_usbguard_fixture
mv "$USB_FIXTURE_FILE" "$USB_FIXTURE_FILE.target"
ln -s "$USB_FIXTURE_FILE.target" "$USB_FIXTURE_FILE"
assert_eq 'unknown (missing or unsafe status file)' \
    "$(read_usbguard_state "$USB_FIXTURE_FILE" "$valid_file_meta" "$valid_dir_meta")" \
    "USBGuard status symlink is rejected"
rm -f "$USB_FIXTURE_FILE" "$USB_FIXTURE_FILE.target"

write_valid_usbguard_fixture
chmod 0666 "$USB_FIXTURE_FILE"
assert_eq 'unknown (invalid status-file metadata)' \
    "$(read_usbguard_state "$USB_FIXTURE_FILE" "$valid_file_meta" "$valid_dir_meta")" \
    "writable USBGuard status mode is rejected"
chmod 0644 "$USB_FIXTURE_FILE"
assert_eq 'unknown (invalid status-file metadata)' \
    "$(read_usbguard_state "$USB_FIXTURE_FILE" 'invalid:invalid:644' "$valid_dir_meta")" \
    "unexpected USBGuard status ownership is rejected"
chmod 0700 "$USB_FIXTURE_DIR"
assert_eq 'unknown (invalid status-directory metadata)' \
    "$(read_usbguard_state "$USB_FIXTURE_FILE" "$valid_file_meta" "$valid_dir_meta")" \
    "unsafe USBGuard status-directory metadata is rejected"

# --- M13 header status line present in the .ks itself -----------------------
assert_grep_extended '^# Status: LOCKED [0-9]{4}-[0-9]{2}-[0-9]{2} \(v[0-9]+(\.[0-9]+)*\)' \
    "$KS_FILE" "M13 has dated, versioned LOCKED status metadata"

test_finish
