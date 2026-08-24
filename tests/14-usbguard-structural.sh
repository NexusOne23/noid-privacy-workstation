#!/bin/bash
# 14-usbguard-structural — verify Module 14 USBGuard daemon.conf + firstboot + escape-hatches
#
# Checks:
#   - daemon.conf has ImplicitPolicyTarget=block + HidePII=true + AuditBackend=LinuxAudit
#   - daemon.conf has no broad group/user IPC grants
#   - named ACLs keep notifier device actions while reserving policy/parameters
#     for root and retiring legacy supplementary usbguard membership
#   - firstboot script has generate-policy + emergency-HID-fallback state machine
#   - usbguard.service MUST be MASKED (firstboot unmasks after generate-policy)
#   - unified noid-usbguard-devices inventory/revoke manager, its specialized
#     noid-usbguard-allow-device admission backend, and noid-install-displaylink
#   - graphical-session.target owns usbguard-notifier for each real login
#   - a one-shot graphical-login catch-up reports pre-login blocked devices

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/14-usbguard.ks"
M08_FILE="$PROJECT_ROOT/kickstart/snippets/08-service-minimization.ks"
M05_FILE="$PROJECT_ROOT/kickstart/snippets/05-lan-isolation.ks"
M13_FILE="$PROJECT_ROOT/kickstart/snippets/13-aide-welcome.ks"
M29_FILE="$PROJECT_ROOT/kickstart/snippets/29-user-docs.ks"
M41_FILE="$PROJECT_ROOT/kickstart/snippets/41-anaconda-cleanup.ks"
AIDE_SECURE_MANIFEST="$PROJECT_ROOT/manifests/aide-secure-paths.tsv"
GREETER_RUNTIME="$PROJECT_ROOT/tests/pre-ship/17-greeter-identity-runtime.sh"
USBGUARD_RUNTIME="$PROJECT_ROOT/tests/pre-ship/14-usbguard-runtime.sh"

test_start "14-usbguard-structural"

assert_file_exists "$KS_FILE"

TMPDIR="$(mktemp -d /var/tmp/noid-test14.XXXXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

extract_heredoc "$KS_FILE" "DAEMON_EOF"   "$TMPDIR/usbguard-daemon.conf" || _fail "daemon.conf extraction"
extract_heredoc "$KS_FILE" "FIRSTBOOT_EOF" "$TMPDIR/firstboot.sh" || _fail "firstboot extraction"
extract_heredoc "$KS_FILE" "ADD_USER_EOF" "$TMPDIR/add-user.sh" || _fail "add-user extraction"
extract_heredoc "$KS_FILE" "ALLOW_DEV_EOF" "$TMPDIR/allow-device.sh" || _fail "allow-device extraction"
extract_heredoc "$KS_FILE" "USB_MANAGER_EOF" "$TMPDIR/usbguard-devices.py" \
    || _fail "USBGuard manager extraction"
extract_heredoc "$KS_FILE" "USBG_DOC_EOF" "$TMPDIR/14-usbguard.md" || _fail "USBGuard documentation extraction"
extract_heredoc "$KS_FILE" "DOCK_DOC_EOF" "$TMPDIR/docking-stations.md" \
    || _fail "docking documentation extraction"
extract_heredoc "$M29_FILE" "GETSTART_EOF" "$TMPDIR/getting-started.md" \
    || _fail "getting-started documentation extraction"
extract_heredoc "$KS_FILE" "DISPLAYLINK_EOF" "$TMPDIR/displaylink.sh" || _fail "DisplayLink installer extraction"
extract_heredoc "$KS_FILE" "PRESET_EOF"    "$TMPDIR/50-noid-usbguard.preset" || _fail "preset extraction"
extract_heredoc "$KS_FILE" "NOTIFIER_DROPIN_EOF" "$TMPDIR/usbguard-notifier.conf" \
    || _fail "notifier drop-in extraction"
extract_heredoc "$KS_FILE" "USBGUARD_LOGIN_CATCHUP_EOF" \
    "$TMPDIR/noid-usbguard-login-catchup" \
    || _fail "pre-login USB block catch-up extraction"
extract_heredoc "$KS_FILE" "USBGUARD_LOGIN_CATCHUP_SERVICE_EOF" \
    "$TMPDIR/noid-usbguard-login-catchup.service" \
    || _fail "pre-login USB block catch-up service extraction"
extract_heredoc "$M08_FILE" "ELIGIBLE_USER_EOF" "$TMPDIR/noid-eligible-user" \
    || _fail "shared eligibility helper extraction"
extract_heredoc "$M05_FILE" "RUNTIME_TMPFILES_EOF" "$TMPDIR/noid-runtime.conf" \
    || _fail "shared runtime tmpfiles extraction"
extract_heredoc "$KS_FILE" "REMOVE_GNOME_WILDCARD_EOF" "$TMPDIR/remove-gnome-wildcard.sh" || _fail "wildcard cleanup extraction"
extract_heredoc "$KS_FILE" "USB_LIVE_SERVICE_EOF" "$TMPDIR/noid-usbguard-live-init.service" \
    || _fail "USBGuard live service extraction"
extract_heredoc "$KS_FILE" "FIRSTBOOT_SERVICE_EOF" "$TMPDIR/noid-usbguard-firstboot.service" \
    || _fail "USBGuard firstboot service extraction"
extract_heredoc "$KS_FILE" "SERVICE_EOF" "$TMPDIR/noid-usbguard-add-user.service" \
    || _fail "USBGuard add-user service extraction"
extract_heredoc "$M41_FILE" "SERVICE_EOF" "$TMPDIR/noid-anaconda-cleanup.service" \
    || _fail "Anaconda cleanup service extraction"
extract_heredoc "$M41_FILE" "HOST_IDENTITY_SERVICE_EOF" \
    "$TMPDIR/noid-host-identity.service" \
    || _fail "host-identity service extraction"
sed -i \
    's|^ExecStart=/usr/local/bin/noid-host-identity --ensure$|ExecStart=/usr/bin/true --ensure|' \
    "$TMPDIR/noid-host-identity.service"
extract_heredoc "$KS_FILE" "REJECT_GNOME_WILDCARD_SERVICE_EOF" \
    "$TMPDIR/noid-usbguard-remove-gnome-wildcard.service" \
    || _fail "USBGuard wildcard-cleanup service extraction"
extract_heredoc "$M13_FILE" "STATUS_EOF" "$TMPDIR/noid-status" \
    || _fail "Module 13 noid-status extraction"

if bash -n "$TMPDIR/firstboot.sh"; then
    _pass "firstboot script: bash -n clean"
else
    _fail "firstboot script: bash -n"
fi
assert_cmd_success "USBGuard add-user helper is valid bash" bash -n "$TMPDIR/add-user.sh"
assert_cmd_success "USBGuard device manager parses as Python" \
    python3 -c 'import ast, pathlib, sys; ast.parse(pathlib.Path(sys.argv[1]).read_text())' \
    "$TMPDIR/usbguard-devices.py"
assert_cmd_success "USBGuard device manager help is side-effect-free" \
    python3 "$TMPDIR/usbguard-devices.py" --help
assert_cmd_success "USBGuard allow-device helper is valid bash" \
    bash -n "$TMPDIR/allow-device.sh"
assert_grep_fixed 'for path in (USBGUARD, RULE_PARSER):' \
    "$TMPDIR/usbguard-devices.py" \
    "USBGuard read-only inventory depends only on its native inspection tools"
assert_grep_fixed 'require_safe_executable(ALLOW_HELPER)' \
    "$TMPDIR/usbguard-devices.py" \
    "USBGuard manager validates its admission backend only at the allow boundary"
assert_grep_fixed 'require_safe_executable(SNAP_PRE)' \
    "$TMPDIR/usbguard-devices.py" \
    "USBGuard manager validates its rollback helper only at the revoke boundary"
assert_not_grep 'for path in (USBGUARD, RULE_PARSER, ALLOW_HELPER, SNAP_PRE):' \
    "$TMPDIR/usbguard-devices.py" \
    "damaged mutation helpers cannot suppress the read-only USBGuard inventory"
assert_cmd_success "GNOME wildcard cleanup helper is valid bash" bash -n "$TMPDIR/remove-gnome-wildcard.sh"
assert_cmd_success "pre-login USB block catch-up is valid bash" \
    bash -n "$TMPDIR/noid-usbguard-login-catchup"
if bash -n "$TMPDIR/displaylink.sh"; then
    _pass "DisplayLink installer: bash -n clean"
else
    _fail "DisplayLink installer: bash -n"
fi
assert_cmd_success "USBGuard system-unit graph parses with the candidate definitions" \
    env -i PATH=/usr/sbin:/usr/bin LC_ALL=C \
    SYSTEMD_UNIT_PATH="$TMPDIR:/etc/systemd/system:/usr/lib/systemd/system" \
    systemd-analyze verify noid-host-identity.service \
        noid-usbguard-firstboot.service \
        noid-usbguard-live-init.service \
        noid-usbguard-add-user.service \
        noid-usbguard-remove-gnome-wildcard.service

# --- daemon.conf hardened settings ------------------------------------------
assert_grep_extended '^ImplicitPolicyTarget=block$' "$TMPDIR/usbguard-daemon.conf"
assert_grep_extended '^AuthorizedDefault=none$' "$TMPDIR/usbguard-daemon.conf"
assert_grep_extended '^InsertedDevicePolicy=apply-policy$' "$TMPDIR/usbguard-daemon.conf"
assert_grep_extended '^PresentDevicePolicy=apply-policy$' "$TMPDIR/usbguard-daemon.conf"
assert_grep_extended '^PresentControllerPolicy=keep$' "$TMPDIR/usbguard-daemon.conf"
assert_grep_extended '^RestoreControllerDeviceState=false$' "$TMPDIR/usbguard-daemon.conf"
assert_grep_extended '^IPCAccessControlFiles=/etc/usbguard/IPCAccessControl\.d/$' \
    "$TMPDIR/usbguard-daemon.conf"
assert_grep_extended '^HidePII=true$' "$TMPDIR/usbguard-daemon.conf"
assert_grep_extended '^AuditBackend=LinuxAudit$' "$TMPDIR/usbguard-daemon.conf"
assert_grep_extended '^DeviceRulesWithPort=false$' "$TMPDIR/usbguard-daemon.conf"
assert_not_grep 'hash-based identification is portable' "$KS_FILE" \
    "DeviceRulesWithPort=false is not misrepresented as removing parent topology"

# --- Named ACLs are the sole IPC authorization surface ----------------------
assert_not_grep '^IPCAllowedUsers=' "$TMPDIR/usbguard-daemon.conf"
assert_not_grep '^IPCAllowedGroups=' "$TMPDIR/usbguard-daemon.conf"

# --- firstboot state machine ------------------------------------------------
assert_grep_fixed 'usbguard generate-policy' "$TMPDIR/firstboot.sh"
assert_grep_fixed 'allow with-interface 03:*:*' "$TMPDIR/firstboot.sh"
assert_grep_fixed 'uninitialized -> emergency' "$TMPDIR/firstboot.sh"
assert_grep_fixed "systemctl --no-reload unmask \\" "$TMPDIR/firstboot.sh" \
    "firstboot batches masked-unit removal without an intermediate reload"
assert_grep_fixed 'usbguard.service usbguard-dbus.service' "$TMPDIR/firstboot.sh" \
    "daemon and D-Bus surfaces share one unit-file transaction"
assert_grep_fixed "systemctl --no-reload enable \\" "$TMPDIR/firstboot.sh" \
    "firstboot batches enablement before publishing either unit"
assert_eq "1" "$(grep -cF 'systemctl daemon-reload' "$TMPDIR/firstboot.sh")" \
    "firstboot publishes its complete USBGuard unit-file transaction exactly once"
assert_grep_fixed 'refusing automatic re-learning' "$TMPDIR/firstboot.sh" \
    "real state never re-learns attached devices"
assert_grep_fixed 'PENDING_REAL=1' "$TMPDIR/firstboot.sh" \
    "real-state commit is explicitly deferred"
assert_grep_fixed 'ensure_root_directory "$STATE_DIR" 755' \
    "$TMPDIR/firstboot.sh" "USBGuard status directory metadata is enforced"
assert_grep_fixed 'mktemp "${STATUS_FILE}.tmp.XXXXXX"' \
    "$TMPDIR/firstboot.sh" "USBGuard status candidate is created beside its target"
assert_grep_fixed 'mv -fT -- "$tmp" "$STATUS_FILE"' \
    "$TMPDIR/firstboot.sh" "USBGuard status publication is an atomic replacement"
assert_grep_fixed 'refusing invalid USBGuard status state' \
    "$TMPDIR/firstboot.sh" "USBGuard producer enforces its state grammar"
assert_grep_fixed 'STATE=real|emergency|initializing' "$KS_FILE" \
    "USBGuard source documentation matches the producer state grammar"
assert_grep_fixed '`initializing`). The file contains exactly these four keys.' \
    "$TMPDIR/14-usbguard.md" \
    "USBGuard user documentation names the transient initializing state"
assert_not_grep 'STATE=real.*unknown' "$TMPDIR/14-usbguard.md" \
    "USBGuard documentation does not invent an unwritable unknown state"
assert_grep_fixed 'The read-only `noid-status` command (Module 13) parses this file' \
    "$TMPDIR/14-usbguard.md" "USBGuard documentation names the real state consumer"
assert_not_grep_extended 'welcome.*reads.*usbguard-status|welcome notification.*reads this file' \
    "$KS_FILE" "USBGuard source has no retired Welcome state consumer"
assert_grep_fixed 'trap cleanup_tmp_rules EXIT HUP INT TERM' "$TMPDIR/firstboot.sh" \
    "temporary device-policy data is cleaned on interruption"
assert_not_grep 'systemctl unmask usbguard.*|| true' "$TMPDIR/firstboot.sh" \
    "USBGuard unmask errors are not swallowed"
assert_not_grep 'systemctl enable usbguard.*|| true' "$TMPDIR/firstboot.sh" \
    "USBGuard enable errors are not swallowed"
assert_grep_fixed 'set -euo pipefail' "$TMPDIR/firstboot.sh" \
    "USBGuard firstboot propagates unhandled failures"
assert_grep_fixed 'write_state "initializing"' "$TMPDIR/firstboot.sh" \
    "published policy enters a durable transient state before service activation"
assert_not_grep_extended '>[[:space:]]*"\$STATE_FILE"' "$TMPDIR/firstboot.sh" \
    "durable USBGuard state is never overwritten in place"
assert_grep_fixed 'CURRENT_STATE" = "initializing"' "$TMPDIR/firstboot.sh" \
    "interrupted activation resumes without re-learning attached devices"
assert_grep_fixed 'publish_policy_candidate "$TMPRULES"' "$TMPDIR/firstboot.sh" \
    "generated policy uses the atomic policy publisher"
assert_grep_fixed 'mv -fT -- "$candidate" "$RULES_FILE"' "$TMPDIR/firstboot.sh" \
    "policy publication is a same-directory atomic replacement"
assert_grep_fixed 'usbguard-rule-parser -f "$candidate"' "$TMPDIR/firstboot.sh" \
    "policy candidate grammar is validated before activation"
assert_grep_fixed 'sync -f /etc/usbguard' "$TMPDIR/firstboot.sh" \
    "policy rename is made durable before service activation"
assert_not_grep '/tmp/noid-usbguard-rules' "$TMPDIR/firstboot.sh" \
    "device-descriptor policy candidates never use the global temporary directory"
assert_not_grep 'usbguard add-user' "$TMPDIR/firstboot.sh" \
    "USBGuard firstboot cannot reintroduce full generated ACLs or group membership"
assert_grep_fixed 'broad USBGuard IPC authorization is present' "$TMPDIR/firstboot.sh" \
    "USBGuard firstboot fails closed on group/user-wide IPC authorization"
assert_grep_fixed "'Policy=list'" "$TMPDIR/firstboot.sh" \
    "normal-user IPC profile cannot change policy"
assert_grep_fixed "'Parameters=list,listen'" "$TMPDIR/firstboot.sh" \
    "normal-user IPC profile cannot change daemon parameters"
assert_grep_fixed "'Policy=list,modify'" "$TMPDIR/firstboot.sh" \
    "root IPC profile retains policy administration"
assert_grep_fixed "'Parameters=list,modify,listen'" "$TMPDIR/firstboot.sh" \
    "root IPC profile retains parameter administration"
assert_grep_fixed 'mv -fT -- "$tmp" "$target"' "$TMPDIR/firstboot.sh" \
    "firstboot publishes IPC profiles by same-filesystem atomic replacement"
assert_grep_fixed "stat -Lc '%u:%g:%a:%h'" "$TMPDIR/firstboot.sh" \
    "firstboot requires exact IPC owner, mode and single-link identity"

unit_unmask_line=$(grep -nF "systemctl --no-reload unmask \\" \
    "$TMPDIR/firstboot.sh" | tail -1 | cut -d: -f1 || true)
unit_enable_line=$(grep -nF "systemctl --no-reload enable \\" \
    "$TMPDIR/firstboot.sh" | tail -1 | cut -d: -f1 || true)
unit_reload_line=$(grep -nF 'systemctl daemon-reload' \
    "$TMPDIR/firstboot.sh" | tail -1 | cut -d: -f1 || true)
daemon_start_line=$(grep -nF 'systemctl start usbguard.service' \
    "$TMPDIR/firstboot.sh" | tail -1 | cut -d: -f1 || true)
dbus_start_line=$(grep -nF 'systemctl start usbguard-dbus.service' \
    "$TMPDIR/firstboot.sh" | tail -1 | cut -d: -f1 || true)
if [ -n "$unit_unmask_line" ] && [ -n "$unit_enable_line" ] && \
   [ -n "$unit_reload_line" ] && [ -n "$daemon_start_line" ] && \
   [ -n "$dbus_start_line" ] && \
   [ "$unit_enable_line" -gt "$unit_unmask_line" ] && \
   [ "$unit_reload_line" -gt "$unit_enable_line" ] && \
   [ "$daemon_start_line" -gt "$unit_reload_line" ] && \
   [ "$dbus_start_line" -gt "$daemon_start_line" ]; then
    _pass "both USBGuard unit surfaces reach PID 1 before either service starts"
else
    _fail "USBGuard unit publication/start ordering"
fi

assert_grep_fixed 'ConditionKernelCommandLine=rd.live.image' "$TMPDIR/noid-usbguard-live-init.service" \
    "live initializer is strictly live-media scoped"
assert_grep_fixed 'Before=multi-user.target graphical.target' "$TMPDIR/noid-usbguard-live-init.service" \
    "USBGuard implicit block is established before the graphical session"
assert_grep_fixed 'ExecStart=/usr/local/bin/noid-usbguard-firstboot.sh' \
    "$TMPDIR/noid-usbguard-live-init.service" \
    "live initializer reuses the verified present-device policy state machine"
assert_grep_fixed 'systemctl enable noid-usbguard-firstboot.service noid-usbguard-live-init.service' \
    "$KS_FILE" "installed and live initializers are both enabled"

assert_grep_fixed 'set -euo pipefail' "$TMPDIR/add-user.sh" \
    "USBGuard add-user helper propagates failures"
assert_not_grep 'groupadd -r usbguard' "$TMPDIR/add-user.sh" \
    "USBGuard reconciliation does not recreate a broad group path"
assert_not_grep 'usermod -aG usbguard' "$TMPDIR/add-user.sh" \
    "USBGuard reconciliation never grants supplementary group access"
assert_not_grep 'usbguard add-user' "$TMPDIR/add-user.sh" \
    "USBGuard reconciliation never generates full ACLs through the CLI"
assert_grep_fixed '/usr/bin/gpasswd -d "$username" usbguard' "$TMPDIR/add-user.sh" \
    "legacy distro-managed usbguard membership is removed explicitly"
assert_grep_fixed 'write_ipc_file root root' "$TMPDIR/add-user.sh" \
    "late reconciliation preserves the root administrative profile"
assert_grep_fixed 'write_ipc_file "$username" user' "$TMPDIR/add-user.sh" \
    "every eligible user receives the least-privilege profile"
assert_grep_fixed 'mv -fT -- "$tmp" "$target"' "$TMPDIR/add-user.sh" \
    "late IPC convergence uses atomic replacement"
assert_not_grep 'reload-or-restart usbguard.service.*|| true' "$TMPDIR/add-user.sh" \
    "USBGuard add-user does not hide daemon reload failure"
assert_not_grep 'log .*\$username' "$TMPDIR/add-user.sh" \
    "USBGuard add-user does not write local usernames to journal"
assert_grep_fixed 'exit 75' "$TMPDIR/add-user.sh" \
    "too-early USBGuard reconciliation is retryable, not reported successful"
assert_grep_fixed \
    'After=usbguard.service noid-usbguard-firstboot.service noid-usbguard-live-init.service' \
    "$TMPDIR/noid-usbguard-add-user.service" \
    "passwd reconciliation waits behind both installed and Live initializers"
assert_grep_fixed 'SuccessExitStatus=75' \
    "$TMPDIR/noid-usbguard-add-user.service" \
    "intentional daemon-not-ready deferral is not a red systemd failure"
assert_grep_fixed 'flock -w 30 9' "$TMPDIR/add-user.sh" \
    "concurrent passwd/direct reconciliation is serialized"
assert_grep_fixed "stat -Lc '%u:%g:%a:%h' \"\$LOCK_FILE\"" "$TMPDIR/add-user.sh" \
    "reconciliation lock requires root ownership, closed mode and one link"
assert_grep_fixed 'LOCK_FILE=/run/noid-privacy/usbguard-add-user.lock' \
    "$TMPDIR/add-user.sh" \
    "reconciliation lock uses the shared labelled runtime namespace"
assert_grep_fixed 'f /run/noid-privacy/usbguard-add-user.lock 0600 root root -' \
    "$TMPDIR/noid-runtime.conf" \
    "reconciliation lock is created before services start"
assert_grep_fixed 'z /run/noid-privacy/usbguard-add-user.lock 0600 root root -' \
    "$TMPDIR/noid-runtime.conf" \
    "reconciliation lock has an explicit SELinux relabel contract"
assert_grep_fixed 'restore_and_verify_label "$target"' "$TMPDIR/add-user.sh" \
    "late IPC publication verifies the final SELinux label"
assert_grep_fixed 'sync -f "$IPC_DIR"' "$TMPDIR/add-user.sh" \
    "late IPC rename is durable before daemon reload"
assert_not_grep_extended 'not active.*exit 0|skipping \(firstboot will run \+ retry\)' \
    "$TMPDIR/add-user.sh" \
    "daemon-not-ready path cannot consume its only trigger as success"
assert_grep_fixed 'declare -A expected_ipc_profiles=([root]=root)' \
    "$TMPDIR/add-user.sh" \
    "late reconciliation builds a closed root-plus-eligible identity set"
assert_grep_fixed 'expected_ipc_profiles["$username"]=user' \
    "$TMPDIR/add-user.sh" \
    "eligible identities enter the closed USBGuard IPC set explicitly"
assert_grep_fixed 'prune_stale_ipc_files' "$TMPDIR/add-user.sh" \
    "account deletion converges the named USBGuard IPC set"
assert_grep_fixed 'if ! ipc_file_matches "$target" user; then' \
    "$TMPDIR/add-user.sh" \
    "stale IPC retirement is gated by exact NoID Privacy user-profile bytes"
assert_grep_fixed 'Preserving unexplained USBGuard IPC state for review' \
    "$TMPDIR/add-user.sh" \
    "unknown IPC state is preserved and fails closed"
assert_not_grep_extended 'rm[[:space:]]+-rf.*IPCAccessControl|rm[[:space:]]+-rf.*\$target' \
    "$TMPDIR/add-user.sh" \
    "late IPC convergence never recursively deletes authorization state"
assert_grep_fixed '[ "$username" = liveuser ] && ! live_identity_is_expected' \
    "$TMPDIR/add-user.sh" \
    "liveuser IPC is eligible only while the machine is actual Live media"

# Exercise the exact stale-profile state transition in an isolated directory.
# The production predicate hard-codes root ownership; this unprivileged fixture
# replaces only the metadata/SELinux observations while retaining byte, inode,
# enumeration and deletion behavior.
extract_usbguard_function() {
    local name=$1 source=$2
    awk -v wanted="$name" '
        $0 ~ "^" wanted "\\(\\) *\\{" { in_function=1 }
        in_function { print }
        in_function && /^\}$/ { exit }
    ' "$source"
}
{
    extract_usbguard_function emit_ipc_profile "$TMPDIR/add-user.sh"
    extract_usbguard_function ipc_file_matches "$TMPDIR/add-user.sh"
    extract_usbguard_function prune_stale_ipc_files "$TMPDIR/add-user.sh"
} > "$TMPDIR/ipc-prune-functions.sh"
assert_cmd_success "isolated USBGuard IPC pruning functions are valid bash" \
    bash -n "$TMPDIR/ipc-prune-functions.sh"
(
    # shellcheck source=/dev/null
    . "$TMPDIR/ipc-prune-functions.sh"
    IPC_DIR="$TMPDIR/ipc-prune"
    mkdir -p "$IPC_DIR"
    chmod 0755 "$IPC_DIR"
    emit_ipc_profile root > "$IPC_DIR/root"
    emit_ipc_profile user > "$IPC_DIR/alice"
    emit_ipc_profile user > "$IPC_DIR/stale"
    chmod 0600 "$IPC_DIR"/*
    # The sourced pruning function consumes this associative array dynamically.
    # shellcheck disable=SC2034
    declare -A expected_ipc_profiles=([root]=root [alice]=user)
    ipc_changed=0
    # The sourced pruning function invokes these fixture-local replacements.
    # shellcheck disable=SC2317,SC2329
    ensure_ipc_directory() { :; }
    # shellcheck disable=SC2317,SC2329
    selinux_label_ok() { :; }
    # shellcheck disable=SC2317,SC2329
    stat() { printf '%s\n' 0:0:600:1; }
    # shellcheck disable=SC2317,SC2329
    sync() { :; }
    # shellcheck disable=SC2317,SC2329
    log() { :; }
    prune_stale_ipc_files
    [ ! -e "$IPC_DIR/stale" ] && [ -f "$IPC_DIR/root" ] \
        && [ -f "$IPC_DIR/alice" ] && [ "$ipc_changed" -eq 1 ]
) && _pass "exact stale user IPC is removed while expected profiles survive" \
  || _fail "exact stale user IPC reconciliation"
(
    # shellcheck source=/dev/null
    . "$TMPDIR/ipc-prune-functions.sh"
    IPC_DIR="$TMPDIR/ipc-unknown"
    mkdir -p "$IPC_DIR"
    chmod 0755 "$IPC_DIR"
    emit_ipc_profile root > "$IPC_DIR/root"
    printf '%s\n' 'administrator-owned bytes' > "$IPC_DIR/unknown"
    chmod 0600 "$IPC_DIR"/*
    # The sourced pruning function consumes this associative array dynamically.
    # shellcheck disable=SC2034
    declare -A expected_ipc_profiles=([root]=root)
    ipc_changed=0
    # The sourced pruning function invokes these fixture-local replacements.
    # shellcheck disable=SC2317,SC2329
    ensure_ipc_directory() { :; }
    # shellcheck disable=SC2317,SC2329
    selinux_label_ok() { :; }
    # shellcheck disable=SC2317,SC2329
    stat() { printf '%s\n' 0:0:600:1; }
    # shellcheck disable=SC2317,SC2329
    sync() { :; }
    # shellcheck disable=SC2317,SC2329
    log() { :; }
    ! prune_stale_ipc_files && \
        grep -qxF 'administrator-owned bytes' "$IPC_DIR/unknown"
) && _pass "unknown stale IPC bytes are preserved and block convergence" \
  || _fail "unknown stale IPC fail-closed behavior"

daemon_ready_line=$(grep -nF 'systemctl is-active --quiet usbguard.service' \
    "$TMPDIR/firstboot.sh" | tail -1 | cut -d: -f1 || true)
reconcile_line=$(grep -nF '/usr/local/bin/noid-usbguard-add-user.sh' \
    "$TMPDIR/firstboot.sh" | tail -1 | cut -d: -f1 || true)
real_commit_line=$(grep -nF 'write_state "real"' \
    "$TMPDIR/firstboot.sh" | tail -1 | cut -d: -f1 || true)
if [ -n "$daemon_ready_line" ] && [ -n "$reconcile_line" ] && \
   [ -n "$real_commit_line" ] && [ "$reconcile_line" -gt "$daemon_ready_line" ] && \
   [ "$real_commit_line" -gt "$reconcile_line" ]; then
    _pass "firstboot reconciles every current user after daemon readiness and before real-state commit"
else
    _fail "firstboot daemon-ready user reconciliation ordering"
fi

service_verify_line=$(grep -nF 'systemctl is-enabled --quiet usbguard.service' \
    "$TMPDIR/firstboot.sh" | tail -1 | cut -d: -f1 || true)
if [ -n "$service_verify_line" ] && [ -n "$real_commit_line" ] && \
   [ "$real_commit_line" -gt "$service_verify_line" ]; then
    _pass "STATE=real is committed only after service verification"
else
    _fail "STATE=real ordering (service verification must precede commit)"
fi

assert_grep_fixed 'Requires=noid-anaconda-cleanup.service' \
    "$TMPDIR/noid-usbguard-firstboot.service" \
    "installed USBGuard initialization requires successful Live-state cleanup"
assert_grep_fixed 'After=local-fs.target noid-anaconda-cleanup.service' \
    "$TMPDIR/noid-usbguard-firstboot.service" \
    "installed USBGuard initialization runs after Live-state cleanup"
assert_grep_fixed 'Before=multi-user.target graphical.target' \
    "$TMPDIR/noid-usbguard-firstboot.service" \
    "installed USB admission control is active before login targets"
assert_not_grep_extended '^After=.*(^|[[:space:]])multi-user\.target([[:space:]]|$)' \
    "$TMPDIR/noid-usbguard-firstboot.service" \
    "installed firstboot cannot run after the login target it protects"

# --- KS source: usbguard.service mask directive -----------------------------
assert_grep_fixed 'systemctl mask usbguard.service' "$KS_FILE"
# Symmetric build-time mask of usbguard-dbus.service.
assert_grep_fixed 'systemctl mask usbguard-dbus.service' "$KS_FILE"

# --- allow-device escape-hatch ---------------------------------------------
assert_grep_fixed 'ALLOW_ARGS=(allow-device --permanent "$DEV_ID")' \
    "$TMPDIR/allow-device.sh" \
    "ordinary devices retain USBGuard's topology-bound permanent decision"
assert_grep_fixed 'noid-snap-pre --embedded "usbguard allow blocked device"' \
    "$TMPDIR/allow-device.sh" \
    "USBGuard uses the concise nested rollback-point presentation"
assert_grep_fixed 'sub(/:$/, "", candidate)' "$TMPDIR/allow-device.sh" \
    "USBGuard list IDs normalize the rendered terminal colon"
assert_grep_fixed '[ "$#" -gt 1 ]' "$TMPDIR/allow-device.sh" \
    "USBGuard allow wrapper rejects surplus arguments"
assert_grep_fixed '[ "$CURRENT_LINE" != "$DEV_LINE" ]' "$TMPDIR/allow-device.sh" \
    "USBGuard allow wrapper rejects a recycled runtime device ID"
assert_grep_fixed '[ "$FINAL_LINE" != "$DEV_LINE" ]' "$TMPDIR/allow-device.sh" \
    "ordinary USB admission repeats the exact blocked-row check after snapshot work"
assert_grep_fixed 'same_runtime_device "$DEV_LINE" "$FINAL_LINE"' \
    "$TMPDIR/allow-device.sh" \
    "ModeSwitch precursor revalidates its descriptor at the final runtime-allow boundary"
assert_grep_fixed 'same_runtime_device "$current_target_line" "$final_target_line"' \
    "$TMPDIR/allow-device.sh" \
    "ModeSwitch target revalidates its descriptor after portable-rule persistence"
assert_grep_fixed 'Enter menu number [1-$MENU_COUNT]' "$TMPDIR/allow-device.sh" \
    "interactive USBGuard prompt requests only the displayed menu number"
assert_grep_fixed 'DEV_LINE=$(menu_device_line "$MENU_INDEX" "$BLOCKED")' \
    "$TMPDIR/allow-device.sh" \
    "interactive menu selection is mapped to its exact blocked-device row"
assert_grep_fixed 'gsub(/[[:cntrl:]]/, "", device_name)' \
    "$TMPDIR/allow-device.sh" \
    "device-supplied menu names cannot inject terminal control characters"
assert_grep_fixed 'if (length(device_name) > 64)' "$TMPDIR/allow-device.sh" \
    "device-supplied menu names have a bounded display width"
assert_grep_fixed 'could not query USBGuard'\''s blocked-device list' \
    "$TMPDIR/allow-device.sh" \
    "blocked-list IPC failure cannot masquerade as an empty result"
assert_grep_fixed 'MODE_SWITCH_DATA_DIR=/usr/share/usb_modeswitch' \
    "$TMPDIR/allow-device.sh" \
    "ModeSwitch recognition is bound to the package-owned native data directory"
assert_grep_fixed 'modeswitch_target_line()' "$TMPDIR/allow-device.sh" \
    "ModeSwitch verification correlates a second identity on the same physical port"
assert_grep_fixed 'parent == source_parent' "$TMPDIR/allow-device.sh" \
    "ModeSwitch verification also binds the re-enumeration to the same USB parent"
assert_grep_fixed 'portable_modeswitch_rule()' \
    "$TMPDIR/allow-device.sh" \
    "ModeSwitch persistence has a dedicated topology-independent rule builder"
assert_grep_fixed 'MODE_SWITCH_RULE_LABEL=noid-modeswitch-portable-v1' \
    "$TMPDIR/allow-device.sh" \
    "portable ModeSwitch rules carry an unambiguous helper ownership label"
assert_grep_fixed 'rule="allow id $vidpid hash \"$hash\" with-interface $interfaces label \"$MODE_SWITCH_RULE_LABEL\""' \
    "$TMPDIR/allow-device.sh" \
    "portable ModeSwitch rules bind descriptor identity and interfaces without topology"
assert_grep_fixed 'usbguard-rule-parser "$rule"' "$TMPDIR/allow-device.sh" \
    "portable ModeSwitch candidates pass the native rule parser"
portable_roundtrip='allow id 1234:5678 hash "YWJjZA==" with-interface { 08:06:50 ff:ff:ff } label "noid-modeswitch-portable-v1"'
portable_parser_output=$(usbguard-rule-parser "$portable_roundtrip" 2>/dev/null) || \
    _fail "native USBGuard parser accepts the portable multi-interface rule shape"
portable_parser_canonical=$(sed -n 's/^OUTPUT: //p' <<< "$portable_parser_output")
assert_eq "$portable_roundtrip" "$portable_parser_canonical" \
    "native USBGuard serialization preserves the exact portable rule bytes"
assert_cmd_failure "native USBGuard parser positive control rejects malformed policy" \
    usbguard-rule-parser 'allow id definitely-not-a-usb-id'
assert_grep_fixed 'usbguard append-rule "$portable"' "$TMPDIR/allow-device.sh" \
    "portable ModeSwitch persistence uses the native policy API"
assert_grep_fixed 'usbguard remove-rule "$rule_id"' "$TMPDIR/allow-device.sh" \
    "old topology-bound rules are retired through the native policy API"
assert_grep_fixed 'grep -Eq '\'' (label|if) '\'' <<< "$body" && return 1' \
    "$TMPDIR/allow-device.sh" \
    "labelled or conditional operator policy is never auto-removed"
assert_grep_fixed 'grep -Fq '\'' serial "'\'' <<< "$body" || return 1' \
    "$TMPDIR/allow-device.sh" \
    "reduced unlabeled operator policy is not mistaken for a generated device rule"
assert_grep_fixed 'portable_rule_is_unique()' "$TMPDIR/allow-device.sh" \
    "ModeSwitch success requires exactly one helper-owned portable rule"
assert_grep_fixed 'RULES_FILE = "/etc/usbguard/rules.conf"' \
    "$TMPDIR/usbguard-devices.py" \
    "USBGuard manager compares runtime policy with the durable native source"
assert_grep_fixed 'os.O_NOFOLLOW' "$TMPDIR/usbguard-devices.py" \
    "USBGuard manager opens durable policy without following a final symlink"
assert_grep_fixed 'pass_fds=(descriptor,)' "$TMPDIR/usbguard-devices.py" \
    "native rule validation reads the already-verified policy descriptor"
assert_grep_fixed 'runtime-only rules are loaded; refusing a save that could persist them' \
    "$TMPDIR/usbguard-devices.py" \
    "revoke refuses to persist transient runtime policy as a side effect"
assert_grep_fixed 'ordered_parity = [rule.body for rule in rules] == durable_bodies' \
    "$TMPDIR/usbguard-devices.py" \
    "revoke requires exact daemon/file rule ordering before a full-policy save"
assert_grep_fixed 'run_usbguard("list-rules", "-d")' \
    "$TMPDIR/usbguard-devices.py" \
    "manager uses USBGuard 1.1.4's supported affected-device inventory"
assert_not_grep 'run_usbguard("list-devices", match_query)' \
    "$TMPDIR/usbguard-devices.py" \
    "manager does not invent an unsupported positional list-devices query"
assert_grep_fixed 'exact_rule_matches_device(rule, device)' \
    "$TMPDIR/usbguard-devices.py" \
    "opposite runtime/durable targets use only the closed exact-device selector"
assert_grep_fixed 'rule.raw == selected.raw' "$TMPDIR/usbguard-devices.py" \
    "revoke revalidates the exact selected policy row after confirmation"
assert_grep_fixed 'run_usbguard("remove-rule", str(selected.rule_id))' \
    "$TMPDIR/usbguard-devices.py" \
    "revoke removes the durable allow through USBGuard's native policy API"
assert_grep_fixed 'run_usbguard("block-device", str(same.device_id))' \
    "$TMPDIR/usbguard-devices.py" \
    "revoke separately deauthorizes unchanged connected instances"
assert_grep_fixed 'USB controller — protected' "$TMPDIR/usbguard-devices.py" \
    "manager refuses controller-rule revocation through its guided path"

# Exercise the manager against a hermetic daemon/policy model. The durable
# policy deliberately differs from live device state in both directions and
# includes one offline ModeSwitch identity. The mock remove-rule implements
# USBGuard 1.1.4's save-on-policy-mutation behavior so the runtime-only guard
# and remove-then-block sequence are load-bearing.
mkdir -p "$TMPDIR/manager-bin"
cp /usr/bin/usbguard-rule-parser "$TMPDIR/manager-bin/usbguard-rule-parser"
cat > "$TMPDIR/manager-bin/systemctl" <<'USB_MANAGER_SYSTEMCTL_EOF'
#!/bin/sh
[ "$1" = is-active ] && exit 0
exit 1
USB_MANAGER_SYSTEMCTL_EOF
cat > "$TMPDIR/manager-bin/noid-usbguard-allow-device" <<'USB_MANAGER_ALLOW_EOF'
#!/bin/sh
printf '%s\n' "$*" > "$NOID_USB_MANAGER_ALLOW_CALL"
USB_MANAGER_ALLOW_EOF
cat > "$TMPDIR/manager-bin/noid-snap-pre" <<'USB_MANAGER_SNAP_EOF'
#!/bin/sh
printf '%s\n' "$*" > "$NOID_USB_MANAGER_SNAPSHOT_CALL"
printf 'Rollback snapshot #91 created.\n'
USB_MANAGER_SNAP_EOF
cat > "$TMPDIR/manager-bin/usbguard" <<'USB_MANAGER_CLI_EOF'
#!/bin/sh
set -eu

list_all_devices() {
    cat "$NOID_USB_MANAGER_DEVICES"
}

case "$1" in
    list-rules)
        if [ "$#" -eq 1 ]; then
            cat "$NOID_USB_MANAGER_RUNTIME"
        elif [ "$#" -eq 2 ] && [ "$2" = -d ]; then
            while IFS= read -r rule; do
                printf '%s\n' "$rule"
                case "$rule" in
                    *'id 1d6b:0002'*)
                        grep -F ' id 1d6b:0002 ' "$NOID_USB_MANAGER_DEVICES" \
                            | sed 's/^/\t/'
                        ;;
                    *'id 1234:0001'*)
                        grep -F ' id 1234:0001 ' \
                            "$NOID_USB_MANAGER_DEVICES" \
                            | sed 's/^/\t/' || true
                        ;;
                    *) : ;;
                esac
            done < "$NOID_USB_MANAGER_RUNTIME"
        else
            exit 1
        fi
        ;;
    list-devices)
        [ "$#" -eq 1 ] || exit 64
        list_all_devices
        ;;
    remove-rule)
        remove_id=$2
        awk -F: -v remove_id="$remove_id" '$1 != remove_id' \
            "$NOID_USB_MANAGER_RUNTIME" > "$NOID_USB_MANAGER_RUNTIME.next"
        mv -f "$NOID_USB_MANAGER_RUNTIME.next" "$NOID_USB_MANAGER_RUNTIME"
        sed -n 's/^[0-9][0-9]*: //p' "$NOID_USB_MANAGER_RUNTIME" \
            > "$NOID_USB_MANAGER_RULES.next"
        chmod 0600 "$NOID_USB_MANAGER_RULES.next"
        mv -f "$NOID_USB_MANAGER_RULES.next" "$NOID_USB_MANAGER_RULES"
        ;;
    block-device)
        device_id=$2
        awk -v device_id="$device_id" '
            $1 == device_id ":" { sub(/^[0-9]+: allow /, device_id ": block ") }
            { print }
        ' "$NOID_USB_MANAGER_DEVICES" > "$NOID_USB_MANAGER_DEVICES.next"
        mv -f "$NOID_USB_MANAGER_DEVICES.next" "$NOID_USB_MANAGER_DEVICES"
        ;;
    *)
        exit 1
        ;;
esac
USB_MANAGER_CLI_EOF
chmod 0755 "$TMPDIR/manager-bin/usbguard-rule-parser" \
    "$TMPDIR/manager-bin/systemctl" \
    "$TMPDIR/manager-bin/noid-usbguard-allow-device" \
    "$TMPDIR/manager-bin/noid-snap-pre" \
    "$TMPDIR/manager-bin/usbguard"

cat > "$TMPDIR/manager.rules" <<'USB_MANAGER_RULES_EOF'
allow id 1d6b:0002 serial "controller" name "xHCI Host Controller" hash "Y29udHJvbGxlcg==" with-interface 09:00:00 with-connect-type "hardwired"
allow id 1234:0001 serial "permanent" name "Permanent Device" hash "cGVybWFuZW50" parent-hash "Y29udHJvbGxlcg==" with-interface 08:06:50 with-connect-type "hotplug"
allow id 0bda:1a2b hash "cHJlY3Vyc29y" with-interface 08:06:50 label "noid-modeswitch-portable-v1"
block id 9999:0001 serial "blocked" name "Durably Blocked" hash "YmxvY2tlZA==" parent-hash "Y29udHJvbGxlcg==" with-interface ff:ff:ff with-connect-type "hotplug"
allow id 7777:0001 serial "runtime-blocked" name "Runtime Blocked" hash "cnVudGltZS1ibG9ja2Vk" parent-hash "Y29udHJvbGxlcg==" with-interface ff:ff:ff with-connect-type "hotplug"
USB_MANAGER_RULES_EOF
chmod 0600 "$TMPDIR/manager.rules"
awk '{ print NR ": " $0 }' "$TMPDIR/manager.rules" > "$TMPDIR/manager.runtime"
cat > "$TMPDIR/manager.devices" <<'USB_MANAGER_DEVICES_EOF'
7: allow id 1234:0001 serial "permanent" name "Permanent Device" hash "cGVybWFuZW50" parent-hash "Y29udHJvbGxlcg==" via-port "1-1" with-interface 08:06:50 with-connect-type "hotplug"
8: allow id 2222:0001 serial "session" name "Session Device" hash "c2Vzc2lvbg==" parent-hash "Y29udHJvbGxlcg==" via-port "1-2" with-interface ff:ff:ff with-connect-type "hotplug"
9: allow id 9999:0001 serial "blocked" name "Durably Blocked" hash "YmxvY2tlZA==" parent-hash "Y29udHJvbGxlcg==" via-port "1-3" with-interface ff:ff:ff with-connect-type "hotplug"
10: block id 7777:0001 serial "runtime-blocked" name "Runtime Blocked" hash "cnVudGltZS1ibG9ja2Vk" parent-hash "Y29udHJvbGxlcg==" via-port "1-4" with-interface ff:ff:ff with-connect-type "hotplug"
11: allow id 1d6b:0002 serial "controller" name "xHCI Host Controller" hash "Y29udHJvbGxlcg==" parent-hash "cm9vdA==" with-interface 09:00:00 with-connect-type "hardwired"
USB_MANAGER_DEVICES_EOF

cp "$TMPDIR/usbguard-devices.py" "$TMPDIR/manager.py"
manager_uid=$(id -u)
manager_gid=$(id -g)
sed -i \
    -e "s|USBGUARD = \"/usr/bin/usbguard\"|USBGUARD = \"$TMPDIR/manager-bin/usbguard\"|" \
    -e "s|RULE_PARSER = \"/usr/bin/usbguard-rule-parser\"|RULE_PARSER = \"$TMPDIR/manager-bin/usbguard-rule-parser\"|" \
    -e "s|RULES_FILE = \"/etc/usbguard/rules.conf\"|RULES_FILE = \"$TMPDIR/manager.rules\"|" \
    -e "s|ALLOW_HELPER = \"/usr/local/bin/noid-usbguard-allow-device\"|ALLOW_HELPER = \"$TMPDIR/manager-bin/noid-usbguard-allow-device\"|" \
    -e "s|SNAP_PRE = \"/usr/local/bin/noid-snap-pre\"|SNAP_PRE = \"$TMPDIR/manager-bin/noid-snap-pre\"|" \
    -e "s|\[\"/usr/bin/systemctl\"|[\"$TMPDIR/manager-bin/systemctl\"|" \
    -e 's/if os.geteuid() != 0:/if False:/' \
    -e "s/!= (0, 0, 0o600, 1):/!= ($manager_uid, $manager_gid, 0o600, 1):/" \
    -e "s/metadata.st_uid != 0/metadata.st_uid != $manager_uid/" \
    -e "s/metadata.st_gid != 0/metadata.st_gid != $manager_gid/" \
    "$TMPDIR/manager.py"

manager_env=(
    NOID_USB_MANAGER_RUNTIME="$TMPDIR/manager.runtime"
    NOID_USB_MANAGER_RULES="$TMPDIR/manager.rules"
    NOID_USB_MANAGER_DEVICES="$TMPDIR/manager.devices"
    NOID_USB_MANAGER_ALLOW_CALL="$TMPDIR/manager.allow-call"
    NOID_USB_MANAGER_SNAPSHOT_CALL="$TMPDIR/manager.snapshot-call"
)
assert_cmd_success "USBGuard manager classifies real runtime/durable combinations" \
    env "${manager_env[@]}" python3 "$TMPDIR/manager.py" status
env "${manager_env[@]}" python3 "$TMPDIR/manager.py" status \
    > "$TMPDIR/manager.status"
cp "$TMPDIR/manager.devices" "$TMPDIR/manager.devices.with-block"
sed -i 's/^10: block /10: allow /' "$TMPDIR/manager.devices"
env "${manager_env[@]}" python3 "$TMPDIR/manager.py" status \
    > "$TMPDIR/manager.no-blocked.status"
mv -f "$TMPDIR/manager.devices.with-block" "$TMPDIR/manager.devices"
assert_grep_fixed 'No USB devices are currently blocked or rejected.' \
    "$TMPDIR/manager.no-blocked.status" \
    "an empty blocked-device inventory is stated explicitly"
chmod 0644 "$TMPDIR/manager-bin/noid-usbguard-allow-device" \
    "$TMPDIR/manager-bin/noid-snap-pre"
assert_cmd_success "USBGuard read-only status survives unavailable mutation helpers" \
    env "${manager_env[@]}" python3 "$TMPDIR/manager.py" status
if env "${manager_env[@]}" python3 "$TMPDIR/manager.py" allow 7 \
        > "$TMPDIR/manager.unsafe-allow.output" 2>&1; then
    _fail "USBGuard allow rejects an unsafe admission backend"
else
    _pass "USBGuard allow rejects an unsafe admission backend"
fi
assert_grep_fixed 'required executable is missing or unsafe' \
    "$TMPDIR/manager.unsafe-allow.output" \
    "allow validates its additional executable at the action boundary"
if printf '2\n' | env "${manager_env[@]}" \
        python3 "$TMPDIR/manager.py" revoke 2 \
        > "$TMPDIR/manager.unsafe-snapshot.output" 2>&1; then
    _fail "USBGuard revoke rejects an unsafe snapshot helper"
else
    _pass "USBGuard revoke rejects an unsafe snapshot helper"
fi
assert_grep_fixed 'required executable is missing or unsafe' \
    "$TMPDIR/manager.unsafe-snapshot.output" \
    "revoke validates its rollback executable at the action boundary"
assert_grep_fixed '2: allow id 1234:0001' "$TMPDIR/manager.runtime" \
    "unsafe rollback helper aborts before USBGuard policy mutation"
chmod 0755 "$TMPDIR/manager-bin/noid-usbguard-allow-device" \
    "$TMPDIR/manager-bin/noid-snap-pre"
assert_grep_fixed 'permanent allow (rule 2)' "$TMPDIR/manager.status" \
    "connected durable authorization is identified by the matching persistent rule"
assert_grep_fixed 'session-only allow' "$TMPDIR/manager.status" \
    "runtime authorization without a durable match is identified"
assert_grep_fixed 'session allow; durable block rule 4 remains' \
    "$TMPDIR/manager.status" \
    "temporary allow cannot be mistaken for persistent authorization"
assert_grep_fixed 'runtime block; permanent allow rule 5 remains' \
    "$TMPDIR/manager.status" \
    "runtime deauthorization cannot be mistaken for durable revocation"
assert_grep_fixed '0bda:1a2b  ModeSwitch storage identity  offline' \
    "$TMPDIR/manager.status" \
    "offline ModeSwitch precursor has an honest functional inventory name"
assert_grep_fixed 'Blocked USB devices' "$TMPDIR/manager.status" \
    "manager exposes a dedicated blocked-device inventory"
assert_grep_fixed '10   block   7777:0001' "$TMPDIR/manager.status" \
    "blocked runtime devices are listed explicitly"
assert_grep_fixed 'runtime block; permanent allow rule 5 remains' \
    "$TMPDIR/manager.status" \
    "blocked inventory keeps durable-versus-runtime authorization explicit"
assert_grep_fixed 'Persistent block/reject rules' "$TMPDIR/manager.status" \
    "manager separates current blocks from explicit durable deny policy"
assert_grep_fixed '4    block   9999:0001  Durably Blocked' \
    "$TMPDIR/manager.status" \
    "durable deny inventory includes stored rules even while runtime-allowed"
assert_grep_fixed 'USB controller — protected' \
    "$TMPDIR/manager.status" \
    "controller policy is explicitly protected in the overview"

cp "$TMPDIR/manager.runtime" "$TMPDIR/manager.runtime.clean"
printf '%s\n' \
    '6: allow id 3333:0001 hash "cnVudGltZQ==" with-interface ff:ff:ff' \
    >> "$TMPDIR/manager.runtime"
if printf '2\n' | env "${manager_env[@]}" \
        python3 "$TMPDIR/manager.py" revoke 2 \
        > "$TMPDIR/manager.runtime-only.output" 2>&1; then
    _fail "USBGuard manager refuses revoke while runtime-only policy is loaded"
else
    _pass "USBGuard manager refuses revoke while runtime-only policy is loaded"
fi
assert_grep_fixed 'runtime-only rules are loaded; refusing a save' \
    "$TMPDIR/manager.runtime-only.output" \
    "runtime-only policy cannot become durable as a revoke side effect"
if [ ! -e "$TMPDIR/manager.snapshot-call" ]; then
    _pass "runtime-policy drift aborts before the rollback point or mutation"
else
    _fail "runtime-policy drift aborts before the rollback point or mutation"
fi
assert_grep_fixed '2: allow id 1234:0001' "$TMPDIR/manager.runtime" \
    "runtime-policy drift leaves the selected allow rule untouched"

cp "$TMPDIR/manager.runtime.clean" "$TMPDIR/manager.runtime"
awk 'NR == 1 { first=$0; next } NR == 2 { print; print first; next } { print }' \
    "$TMPDIR/manager.runtime" > "$TMPDIR/manager.runtime.reordered"
mv -f "$TMPDIR/manager.runtime.reordered" "$TMPDIR/manager.runtime"
if printf '2\n' | env "${manager_env[@]}" \
        python3 "$TMPDIR/manager.py" revoke 2 \
        > "$TMPDIR/manager.reordered.output" 2>&1; then
    _fail "USBGuard manager refuses a reordered daemon policy"
else
    _pass "USBGuard manager refuses a reordered daemon policy"
fi
assert_grep_fixed 'daemon/rules.conf policy drift blocks safe revocation' \
    "$TMPDIR/manager.reordered.output" \
    "policy-order drift cannot be persisted by a revoke side effect"
assert_grep_fixed '2: allow id 1234:0001' "$TMPDIR/manager.runtime" \
    "policy-order drift leaves the selected rule untouched"

cp "$TMPDIR/manager.runtime.clean" "$TMPDIR/manager.runtime"
if printf '2\n' | env "${manager_env[@]}" \
        python3 "$TMPDIR/manager.py" revoke 2 \
        > "$TMPDIR/manager.revoke.output" 2>&1; then
    _pass "USBGuard manager removes durable allow then blocks its live instance"
else
    _fail "USBGuard manager removes durable allow then blocks its live instance"
fi
assert_grep_fixed '--embedded usbguard revoke persistent allow rule' \
    "$TMPDIR/manager.snapshot-call" \
    "persistent revoke creates its dedicated rollback point before mutation"
assert_not_grep 'id 1234:0001' "$TMPDIR/manager.rules" \
    "persistent revoke removes the exact durable allow body"
assert_not_grep '2: allow id 1234:0001' "$TMPDIR/manager.runtime" \
    "persistent revoke removes the exact daemon policy row"
assert_grep_fixed '7: block id 1234:0001' "$TMPDIR/manager.devices" \
    "persistent revoke separately deauthorizes the unchanged live device"
assert_grep_fixed 'Persistent allow rule removed and connected instances deauthorized.' \
    "$TMPDIR/manager.revoke.output" \
    "revoke reports success only after durable and runtime postconditions"

assert_grep_fixed 'if [ "$target_state" = allow ]' "$TMPDIR/allow-device.sh" \
    "ModeSwitch success requires the re-enumerated identity to be allowed"
assert_grep_fixed 'Permanently allow this re-enumerated USB identity? [y/N]' \
    "$TMPDIR/allow-device.sh" \
    "a post-switch identity requires a second explicit trust decision"
assert_grep_fixed '[ "$current_target_line" != "$target_line" ]' \
    "$TMPDIR/allow-device.sh" \
    "the second decision rejects a changed or recycled runtime identity"
assert_not_grep 'usbguard allow-device --permanent "$target_id"' \
    "$TMPDIR/allow-device.sh" \
    "the second identity never receives USBGuard's parent-hash-bound generated rule"
assert_grep_fixed 'sudo noid-usbguard-devices status' \
    "$TMPDIR/allow-device.sh" \
    "admission success points to the unified persistent-policy overview"
assert_grep_fixed 'sudo noid-usbguard-devices revoke' \
    "$TMPDIR/allow-device.sh" \
    "admission success points to the verified persistent-revoke workflow"
assert_not_grep 'echo "  sudo usbguard remove-rule' \
    "$TMPDIR/allow-device.sh" \
    "admission success does not bypass the verified manager with manual rule removal"
mkdir -p "$TMPDIR/mock-bin"
cat > "$TMPDIR/mock-bin/id" <<'USB_ID_MOCK_EOF'
#!/bin/sh
[ "$1" = -u ] && printf '0\n'
USB_ID_MOCK_EOF
cat > "$TMPDIR/mock-bin/systemctl" <<'USB_SYSTEMCTL_MOCK_EOF'
#!/bin/sh
exit 0
USB_SYSTEMCTL_MOCK_EOF
cat > "$TMPDIR/mock-bin/usbguard" <<'USB_CLI_MOCK_EOF'
#!/bin/sh
case "$1" in
    list-devices)
        first_hash=abc
        if [ "${NOID_USB_STALE_AFTER_SNAPSHOT:-no}" = yes ] && \
           [ -f "${NOID_USB_SNAPSHOT_DONE:-/nonexistent}" ]; then
            first_hash=recycled
        fi
        printf '%s\n' \
            "9: block id 1234:5678 serial \"fixture-one\" name \"Fixture One\" hash \"$first_hash\" parent-hash \"def\" via-port \"1-1\" with-interface { 08:06:50 }" \
            '15: block id 9876:5432 serial "fixture-two" name "Fixture Two" hash "ghi" parent-hash "jkl" via-port "1-2" with-interface { 08:06:50 }'
        ;;
    allow-device)
        printf '%s\n' "$*" > "$NOID_USB_MOCK_CALLS"
        ;;
    *) exit 1 ;;
esac
USB_CLI_MOCK_EOF
cat > "$TMPDIR/mock-bin/noid-snap-pre" <<'USB_SNAPSHOT_MOCK_EOF'
#!/bin/sh
[ "${1:-}" = --embedded ] && shift
printf '%s\n' "$1" > "$NOID_USB_SNAPSHOT_DESC"
[ -z "${NOID_USB_SNAPSHOT_DONE:-}" ] || : > "$NOID_USB_SNAPSHOT_DONE"
printf 'Rollback snapshot #73 created.\n'
USB_SNAPSHOT_MOCK_EOF
chmod 0755 "$TMPDIR/mock-bin/id" "$TMPDIR/mock-bin/systemctl" \
    "$TMPDIR/mock-bin/usbguard" "$TMPDIR/mock-bin/noid-snap-pre"
assert_cmd_success "USBGuard rendered 9: ID reaches allow-device as numeric 9" \
    env PATH="$TMPDIR/mock-bin:$PATH" NOID_USB_MOCK_CALLS="$TMPDIR/usb.calls" \
    NOID_USB_SNAPSHOT_DESC="$TMPDIR/usb.snapshot" \
    bash "$TMPDIR/allow-device.sh" 9
assert_eq 'allow-device --permanent 9' "$(cat "$TMPDIR/usb.calls")" \
    "USBGuard CLI receives the normalized numeric list ID"
assert_eq 'usbguard allow blocked device' "$(cat "$TMPDIR/usb.snapshot")" \
    "USBGuard snapshot description contains no serial, hash, name or descriptor"

: > "$TMPDIR/usb-snapshot-race.calls"
if env PATH="$TMPDIR/mock-bin:$PATH" \
        NOID_USB_MOCK_CALLS="$TMPDIR/usb-snapshot-race.calls" \
        NOID_USB_SNAPSHOT_DESC="$TMPDIR/usb-snapshot-race.snapshot" \
        NOID_USB_SNAPSHOT_DONE="$TMPDIR/usb-snapshot-race.done" \
        NOID_USB_STALE_AFTER_SNAPSHOT=yes \
        bash "$TMPDIR/allow-device.sh" 9 \
        > "$TMPDIR/usb-snapshot-race.output" 2>&1; then
    _fail "runtime ID recycled during snapshot is rejected"
else
    _pass "runtime ID recycled during snapshot is rejected"
fi
assert_eq 0 "$(wc -l < "$TMPDIR/usb-snapshot-race.calls")" \
    "snapshot-window ID recycling cannot reach allow-device"
assert_grep_fixed 'blocked USB identity changed after the snapshot' \
    "$TMPDIR/usb-snapshot-race.output" \
    "snapshot-window failure identifies the final fail-closed boundary"

# A dual-identity adapter gets two independently approved, descriptor-bound
# rules. Same-port observation correlates the transition but never substitutes
# for the second decision, and neither persistent rule retains topology.
cp "$TMPDIR/allow-device.sh" "$TMPDIR/allow-device-modeswitch.sh"
sed -i \
    -e "s|MODE_SWITCH_DATA_DIR=/usr/share/usb_modeswitch|MODE_SWITCH_DATA_DIR=$TMPDIR/modeswitch-data|" \
    -e 's/\[ "$metadata" = 0:0:644:1 \]/return 0/' \
    "$TMPDIR/allow-device-modeswitch.sh"
mkdir -p "$TMPDIR/modeswitch-data" "$TMPDIR/modeswitch-bin"
printf '%s\n' 'StandardEject=1' > "$TMPDIR/modeswitch-data/0bda:1a2b"
cp "$TMPDIR/mock-bin/id" "$TMPDIR/mock-bin/systemctl" \
    "$TMPDIR/mock-bin/noid-snap-pre" "$TMPDIR/modeswitch-bin/"
cat > "$TMPDIR/modeswitch-bin/sleep" <<'USB_MODE_SLEEP_EOF'
#!/bin/sh
exit 0
USB_MODE_SLEEP_EOF
cat > "$TMPDIR/modeswitch-bin/usbguard" <<'USB_MODE_CLI_EOF'
#!/bin/sh
case "$1" in
    list-devices)
        if [ -f "$NOID_USB_MODE_STATE" ] && [ "${2:-}" != -b ]; then
            count=0
            [ ! -f "$NOID_USB_MODE_LIST_COUNT" ] || count=$(cat "$NOID_USB_MODE_LIST_COUNT")
            count=$((count + 1))
            printf '%s\n' "$count" > "$NOID_USB_MODE_LIST_COUNT"
            target_hash=target
            if [ "${NOID_USB_MODE_STALE_TARGET:-no}" = yes ] && [ "$count" -ge 2 ]; then
                target_hash=changed
            fi
            if [ "${NOID_USB_MODE_STALE_TARGET_AFTER_RULE:-no}" = yes ] && \
               grep -q 'allow id 35bc:0108 .*noid-modeswitch-portable-v1' \
                    "$NOID_USB_MODE_POLICY" 2>/dev/null; then
                target_hash=changed-after-rule
            fi
            target_state=${NOID_USB_MODE_TARGET_STATE:-allow}
            [ ! -f "$NOID_USB_MODE_TARGET_ALLOWED" ] || target_state=allow
            printf '22: %s id 35bc:0108 serial "fixture-target" name "802.11ac WLAN Adapter" hash "%s" parent-hash "controller" via-port "1-1" with-interface ff:ff:ff with-connect-type "hotplug"\n' \
                "$target_state" "$target_hash"
        else
            source_hash=source
            if [ "${NOID_USB_MODE_STALE_SOURCE_AFTER_RULE:-no}" = yes ] && \
               grep -q 'allow id 0bda:1a2b .*noid-modeswitch-portable-v1' \
                    "$NOID_USB_MODE_POLICY" 2>/dev/null; then
                source_hash=changed-after-rule
            fi
            printf '%s\n' \
                "9: block id 0bda:1a2b serial \"\" name \"DISK\" hash \"$source_hash\" parent-hash \"controller\" via-port \"1-1\" with-interface 08:06:50 with-connect-type \"hotplug\""
        fi
        ;;
    list-rules)
        [ ! -s "$NOID_USB_MODE_POLICY" ] || cat "$NOID_USB_MODE_POLICY"
        ;;
    append-rule)
        printf '%s\n' "$*" >> "$NOID_USB_MOCK_CALLS"
        next_id=$(awk -F: 'BEGIN { max=0 } $1 ~ /^[0-9]+$/ && $1 > max { max=$1 } END { print max + 1 }' \
            "$NOID_USB_MODE_POLICY")
        printf '%s: %s\n' "$next_id" "$2" >> "$NOID_USB_MODE_POLICY"
        ;;
    remove-rule)
        printf '%s\n' "$*" >> "$NOID_USB_MOCK_CALLS"
        awk -F: -v remove_id="$2" '$1 != remove_id' \
            "$NOID_USB_MODE_POLICY" > "$NOID_USB_MODE_POLICY.next"
        mv -f "$NOID_USB_MODE_POLICY.next" "$NOID_USB_MODE_POLICY"
        ;;
    allow-device)
        printf '%s\n' "$*" >> "$NOID_USB_MOCK_CALLS"
        case "${2:-}" in
            9) : > "$NOID_USB_MODE_STATE" ;;
            22) : > "$NOID_USB_MODE_TARGET_ALLOWED" ;;
            *) exit 1 ;;
        esac
        ;;
    *) exit 1 ;;
esac
USB_MODE_CLI_EOF
chmod 0755 "$TMPDIR/modeswitch-bin/sleep" \
    "$TMPDIR/modeswitch-bin/usbguard"

# Existing portable target: source enrollment is enough and no second prompt
# or target mutation occurs.
printf '%s\n' \
    '3: allow id 35bc:0108 hash "target" with-interface ff:ff:ff label "noid-modeswitch-portable-v1"' \
    > "$TMPDIR/usb-mode.policy"
if env PATH="$TMPDIR/modeswitch-bin:$PATH" \
        NOID_USB_MOCK_CALLS="$TMPDIR/usb-mode.calls" \
        NOID_USB_MODE_STATE="$TMPDIR/usb-mode.state" \
        NOID_USB_MODE_TARGET_ALLOWED="$TMPDIR/usb-mode.target-allowed" \
        NOID_USB_MODE_LIST_COUNT="$TMPDIR/usb-mode.list-count" \
        NOID_USB_MODE_POLICY="$TMPDIR/usb-mode.policy" \
        NOID_USB_SNAPSHOT_DESC="$TMPDIR/usb-mode.snapshot" \
        bash "$TMPDIR/allow-device-modeswitch.sh" 9 \
        > "$TMPDIR/usb-mode.output" 2>&1; then
    _pass "ModeSwitch precursor reaches an already-allowed target"
else
    _fail "ModeSwitch precursor reaches an already-allowed target"
fi
assert_grep_fixed 'append-rule allow id 0bda:1a2b hash "source" with-interface 08:06:50 label "noid-modeswitch-portable-v1"' \
    "$TMPDIR/usb-mode.calls" \
    "ModeSwitch precursor receives an identity-bound portable policy rule"
assert_grep_fixed 'allow-device 9' "$TMPDIR/usb-mode.calls" \
    "ModeSwitch precursor runtime authorization triggers the native transition"
assert_not_grep 'allow-device --permanent' "$TMPDIR/usb-mode.calls" \
    "ModeSwitch path never asks USBGuard to generate parent-bound allow policy"
assert_not_grep 'allow-device 22' "$TMPDIR/usb-mode.calls" \
    "an already portable target is not modified"
assert_grep_fixed 'ModeSwitch transition verified: both identities have topology-independent device-specific persistent allow rules.' \
    "$TMPDIR/usb-mode.output" \
    "ModeSwitch helper verifies portable policy for both identities"

# Rule persistence is deliberately between the first identity check and its
# runtime authorization. Recycle the same numeric handle in that exact window;
# the newly descriptor-bound rule is harmless, and the stale handle must never
# reach allow-device.
: > "$TMPDIR/usb-mode-source-race.policy"
: > "$TMPDIR/usb-mode-source-race.calls"
if env PATH="$TMPDIR/modeswitch-bin:$PATH" \
        NOID_USB_MOCK_CALLS="$TMPDIR/usb-mode-source-race.calls" \
        NOID_USB_MODE_STATE="$TMPDIR/usb-mode-source-race.state" \
        NOID_USB_MODE_TARGET_ALLOWED="$TMPDIR/usb-mode-source-race.target-allowed" \
        NOID_USB_MODE_LIST_COUNT="$TMPDIR/usb-mode-source-race.list-count" \
        NOID_USB_MODE_POLICY="$TMPDIR/usb-mode-source-race.policy" \
        NOID_USB_MODE_STALE_SOURCE_AFTER_RULE=yes \
        NOID_USB_SNAPSHOT_DESC="$TMPDIR/usb-mode-source-race.snapshot" \
        bash "$TMPDIR/allow-device-modeswitch.sh" 9 \
        > "$TMPDIR/usb-mode-source-race.output" 2>&1; then
    _fail "ModeSwitch precursor recycled during policy persistence is rejected"
else
    _pass "ModeSwitch precursor recycled during policy persistence is rejected"
fi
assert_not_grep '^allow-device 9$' "$TMPDIR/usb-mode-source-race.calls" \
    "stale precursor runtime handle cannot reach allow-device"
assert_grep_fixed 'USB identity changed during policy persistence' \
    "$TMPDIR/usb-mode-source-race.output" \
    "precursor persistence-window race fails at the final identity boundary"

# Typical post-install state: the target has USBGuard's generated parent-bound
# rule. A second yes migrates it to the helper-owned portable form.
printf '%s\n' \
    '2: allow id 0bda:1a2b serial "" name "DISK" hash "source" parent-hash "old-controller" with-interface 08:06:50 with-connect-type "hotplug"' \
    '3: allow id 35bc:0108 serial "fixture-target" name "802.11ac WLAN Adapter" hash "target" parent-hash "controller" with-interface ff:ff:ff with-connect-type "hotplug"' \
    '4: allow id 0bda:1a2b hash "source" parent-hash "operator-controller"' \
    > "$TMPDIR/usb-mode-migrate.policy"
if printf 'y\n' | env PATH="$TMPDIR/modeswitch-bin:$PATH" \
        NOID_USB_MOCK_CALLS="$TMPDIR/usb-mode-migrate.calls" \
        NOID_USB_MODE_STATE="$TMPDIR/usb-mode-migrate.state" \
        NOID_USB_MODE_TARGET_ALLOWED="$TMPDIR/usb-mode-migrate.target-allowed" \
        NOID_USB_MODE_LIST_COUNT="$TMPDIR/usb-mode-migrate.list-count" \
        NOID_USB_MODE_POLICY="$TMPDIR/usb-mode-migrate.policy" \
        NOID_USB_SNAPSHOT_DESC="$TMPDIR/usb-mode-migrate.snapshot" \
        bash "$TMPDIR/allow-device-modeswitch.sh" 9 \
        > "$TMPDIR/usb-mode-migrate.output" 2>&1; then
    _pass "ModeSwitch target topology rule migrates after a second explicit yes"
else
    _fail "ModeSwitch target topology rule migrates after a second explicit yes"
fi
assert_grep_fixed 'append-rule allow id 35bc:0108 hash "target" with-interface ff:ff:ff label "noid-modeswitch-portable-v1"' \
    "$TMPDIR/usb-mode-migrate.calls" \
    "second explicit decision appends the exact portable target rule"
assert_grep_fixed 'remove-rule 2' "$TMPDIR/usb-mode-migrate.calls" \
    "legacy precursor rule is retired even when it names an old USB parent"
assert_grep_fixed 'remove-rule 3' "$TMPDIR/usb-mode-migrate.calls" \
    "known generated target topology rule is retired through USBGuard"
assert_grep_fixed '4: allow id 0bda:1a2b hash "source" parent-hash "operator-controller"' \
    "$TMPDIR/usb-mode-migrate.policy" \
    "reduced unlabeled operator topology policy survives helper migration"
grep -F 'label "noid-modeswitch-portable-v1"' \
    "$TMPDIR/usb-mode-migrate.policy" > "$TMPDIR/usb-mode-migrate.portable"
assert_eq 2 "$(wc -l < "$TMPDIR/usb-mode-migrate.portable")" \
    "ModeSwitch migration persists exactly two helper-owned portable rules"
assert_not_grep_extended 'parent-hash|via-port|with-connect-type' \
    "$TMPDIR/usb-mode-migrate.portable" \
    "both helper-owned ModeSwitch rules are topology-independent"
assert_eq 3 "$(wc -l < "$TMPDIR/usb-mode-migrate.policy")" \
    "ModeSwitch migration leaves two portable identities plus independent operator policy"

# Refusing the second decision keeps only the explicitly approved precursor.
: > "$TMPDIR/usb-mode-decline.policy"
if printf 'n\n' | env PATH="$TMPDIR/modeswitch-bin:$PATH" \
        NOID_USB_MOCK_CALLS="$TMPDIR/usb-mode-decline.calls" \
        NOID_USB_MODE_STATE="$TMPDIR/usb-mode-decline.state" \
        NOID_USB_MODE_TARGET_ALLOWED="$TMPDIR/usb-mode-decline.target-allowed" \
        NOID_USB_MODE_LIST_COUNT="$TMPDIR/usb-mode-decline.list-count" \
        NOID_USB_MODE_POLICY="$TMPDIR/usb-mode-decline.policy" \
        NOID_USB_MODE_TARGET_STATE=block \
        NOID_USB_SNAPSHOT_DESC="$TMPDIR/usb-mode-decline.snapshot" \
        bash "$TMPDIR/allow-device-modeswitch.sh" 9 \
        > "$TMPDIR/usb-mode-decline.output" 2>&1; then
    _pass "ModeSwitch second identity remains blocked after explicit refusal"
else
    _fail "ModeSwitch second identity remains blocked after explicit refusal"
fi
assert_not_grep 'id 35bc:0108' "$TMPDIR/usb-mode-decline.policy" \
    "refusal adds no persistent target identity"
assert_not_grep 'allow-device 22' "$TMPDIR/usb-mode-decline.calls" \
    "refusal adds no runtime target authorization"
assert_grep_fixed 'Second identity not authorized' "$TMPDIR/usb-mode-decline.output" \
    "refusal is reported without a false complete verdict"
assert_grep_fixed 'can therefore still be blocked after a USB port, hub or controller change' \
    "$TMPDIR/usb-mode-decline.output" \
    "refusal states the adapter remains topology-sensitive"

# A blocked second identity becomes both portable and effectively allowed only
# after the second yes.
: > "$TMPDIR/usb-mode-blocked.policy"
if printf 'y\n' | env PATH="$TMPDIR/modeswitch-bin:$PATH" \
        NOID_USB_MOCK_CALLS="$TMPDIR/usb-mode-blocked.calls" \
        NOID_USB_MODE_STATE="$TMPDIR/usb-mode-blocked.state" \
        NOID_USB_MODE_TARGET_ALLOWED="$TMPDIR/usb-mode-blocked.target-allowed" \
        NOID_USB_MODE_LIST_COUNT="$TMPDIR/usb-mode-blocked.list-count" \
        NOID_USB_MODE_POLICY="$TMPDIR/usb-mode-blocked.policy" \
        NOID_USB_MODE_TARGET_STATE=block \
        NOID_USB_SNAPSHOT_DESC="$TMPDIR/usb-mode-blocked.snapshot" \
        bash "$TMPDIR/allow-device-modeswitch.sh" 9 \
        > "$TMPDIR/usb-mode-blocked.output" 2>&1; then
    _pass "blocked ModeSwitch target requires and honors the second explicit yes"
else
    _fail "blocked ModeSwitch target requires and honors the second explicit yes"
fi
assert_grep_fixed 'allow-device 22' "$TMPDIR/usb-mode-blocked.calls" \
    "approved blocked target receives a separate runtime authorization"
assert_not_grep_extended 'parent-hash|via-port|with-connect-type' \
    "$TMPDIR/usb-mode-blocked.policy" \
    "new precursor and target rules contain no topology attributes"

# The second runtime ID is re-read after the prompt. A changed descriptor row
# aborts before any target policy or runtime mutation.
: > "$TMPDIR/usb-mode-stale.policy"
if printf 'y\n' | env PATH="$TMPDIR/modeswitch-bin:$PATH" \
        NOID_USB_MOCK_CALLS="$TMPDIR/usb-mode-stale.calls" \
        NOID_USB_MODE_STATE="$TMPDIR/usb-mode-stale.state" \
        NOID_USB_MODE_TARGET_ALLOWED="$TMPDIR/usb-mode-stale.target-allowed" \
        NOID_USB_MODE_LIST_COUNT="$TMPDIR/usb-mode-stale.list-count" \
        NOID_USB_MODE_POLICY="$TMPDIR/usb-mode-stale.policy" \
        NOID_USB_MODE_TARGET_STATE=block \
        NOID_USB_MODE_STALE_TARGET=yes \
        NOID_USB_SNAPSHOT_DESC="$TMPDIR/usb-mode-stale.snapshot" \
        bash "$TMPDIR/allow-device-modeswitch.sh" 9 \
        > "$TMPDIR/usb-mode-stale.output" 2>&1; then
    _fail "changed ModeSwitch target row is rejected before second mutation"
else
    _pass "changed ModeSwitch target row is rejected before second mutation"
fi
assert_not_grep 'id 35bc:0108' "$TMPDIR/usb-mode-stale.policy" \
    "stale target race cannot append a target rule"
assert_not_grep 'allow-device 22' "$TMPDIR/usb-mode-stale.calls" \
    "stale target race cannot authorize a recycled runtime ID"

# A descriptor can also change after the second explicit decision while its
# portable rule is being persisted. The final re-resolution must prevent a
# stale runtime allow even though the old descriptor's exact rule is durable.
: > "$TMPDIR/usb-mode-target-rule-race.policy"
: > "$TMPDIR/usb-mode-target-rule-race.calls"
if printf 'y\n' | env PATH="$TMPDIR/modeswitch-bin:$PATH" \
        NOID_USB_MOCK_CALLS="$TMPDIR/usb-mode-target-rule-race.calls" \
        NOID_USB_MODE_STATE="$TMPDIR/usb-mode-target-rule-race.state" \
        NOID_USB_MODE_TARGET_ALLOWED="$TMPDIR/usb-mode-target-rule-race.target-allowed" \
        NOID_USB_MODE_LIST_COUNT="$TMPDIR/usb-mode-target-rule-race.list-count" \
        NOID_USB_MODE_POLICY="$TMPDIR/usb-mode-target-rule-race.policy" \
        NOID_USB_MODE_TARGET_STATE=block \
        NOID_USB_MODE_STALE_TARGET_AFTER_RULE=yes \
        NOID_USB_SNAPSHOT_DESC="$TMPDIR/usb-mode-target-rule-race.snapshot" \
        bash "$TMPDIR/allow-device-modeswitch.sh" 9 \
        > "$TMPDIR/usb-mode-target-rule-race.output" 2>&1; then
    _fail "ModeSwitch target recycled during policy persistence is rejected"
else
    _pass "ModeSwitch target recycled during policy persistence is rejected"
fi
assert_not_grep '^allow-device 22$' "$TMPDIR/usb-mode-target-rule-race.calls" \
    "stale target runtime handle cannot reach allow-device after rule persistence"
assert_grep_fixed 'identity changed during policy persistence' \
    "$TMPDIR/usb-mode-target-rule-race.output" \
    "target persistence-window race fails at the final identity boundary"
assert_cmd_success "interactive menu number 2 maps to sparse USBGuard ID 15" \
    sh -c 'printf "2\ny\n" | env PATH="$1" NOID_USB_MOCK_CALLS="$2" \
        NOID_USB_SNAPSHOT_DESC="$3" bash "$4" >"$5"' sh \
    "$TMPDIR/mock-bin:$PATH" "$TMPDIR/usb-interactive.calls" \
    "$TMPDIR/usb-interactive.snapshot" "$TMPDIR/allow-device.sh" \
    "$TMPDIR/usb-interactive.output"
assert_eq 'allow-device --permanent 15' \
    "$(cat "$TMPDIR/usb-interactive.calls")" \
    "interactive USBGuard menu never requires the separately displayed runtime ID"
assert_grep_fixed '[2] Fixture Two' "$TMPDIR/usb-interactive.output" \
    "USBGuard picker places the recognizable device name first"
assert_grep_fixed \
    'Vendor/Product: 9876:5432 | Interface: 08:06:50 | USBGuard ID: 15' \
    "$TMPDIR/usb-interactive.output" \
    "USBGuard picker labels its compact technical identifiers"
assert_not_grep_extended 'serial |hash |parent-hash|via-port' \
    "$TMPDIR/usb-interactive.output" \
    "USBGuard picker hides long descriptor internals from normal output"
assert_cmd_failure "USBGuard allow wrapper rejects an extra argument before mutation" \
    env PATH="$TMPDIR/mock-bin:$PATH" NOID_USB_MOCK_CALLS="$TMPDIR/usb-extra.calls" \
    NOID_USB_SNAPSHOT_DESC="$TMPDIR/usb-extra.snapshot" \
    bash "$TMPDIR/allow-device.sh" 9 extra
assert_not_grep 'noid-snap-pre "usbguard allow device: ${DEV_DESC}"' \
    "$TMPDIR/allow-device.sh" \
    "USBGuard HidePII fields never enter persistent snapshot descriptions"
assert_grep_fixed 'Stopping or disabling only `usbguard.service` is **not** an opt-out.' \
    "$TMPDIR/14-usbguard.md" \
    "USBGuard opt-out documentation explains the live kernel state"
assert_grep_fixed 'noid-usbguard-firstboot.service noid-usbguard-live-init.service' \
    "$TMPDIR/14-usbguard.md" \
    "USBGuard persistent opt-out masks the automatic reconciler"
assert_grep_fixed 'Its upstream action is' "$TMPDIR/14-usbguard.md" \
    "notification workflow is distinguished from permanent authorization"
assert_grep_fixed 'temporary: it authorizes the current device instance' \
    "$TMPDIR/14-usbguard.md" \
    "notification Allow is documented as temporary"
assert_grep_fixed 'USBGuard does not expose' "$TMPDIR/14-usbguard.md" \
    "native temporary/permanent device-privilege coupling is disclosed"
assert_grep_fixed 'not a claim that the wrapper is the only technically possible command' \
    "$TMPDIR/14-usbguard.md" \
    "persistent wrapper documentation makes no false exclusivity claim"
assert_grep_fixed 'Enter that bracketed menu number' "$TMPDIR/14-usbguard.md" \
    "persistent wrapper documentation distinguishes menu numbers from device IDs"
assert_grep_fixed 'long serial and descriptor hashes stay out' \
    "$TMPDIR/14-usbguard.md" \
    "persistent wrapper documentation describes the compact recognition view"
assert_grep_fixed 'USB ModeSwitch / dual-identity adapters' \
    "$TMPDIR/14-usbguard.md" \
    "USBGuard documentation names the cold-start dual-identity boundary"
assert_grep_fixed 'does not ship broad vendor/product or mass-storage allow rules' \
    "$TMPDIR/14-usbguard.md" \
    "ModeSwitch recovery does not weaken default-deny USB admission"
assert_grep_fixed 'auto-allows a second identity.' \
    "$TMPDIR/14-usbguard.md" \
    "ModeSwitch documentation preserves explicit trust for both identities"
assert_grep_fixed "Ordinary devices" "$TMPDIR/14-usbguard.md" \
    "ordinary persistent USB decisions retain their topology boundary"
assert_grep_fixed "stored USB parent/topology" "$TMPDIR/docking-stations.md" \
    "dock guidance does not promise portability for generated USBGuard rules"
assert_not_grep 'trusted on every future plug-in' "$TMPDIR/14-usbguard.md" \
    "USBGuard documentation makes no false universal reconnect guarantee"
assert_not_grep 'allow id \*:\*" | sudo tee' "$TMPDIR/14-usbguard.md" \
    "USBGuard documentation provides no blanket allow copy-paste path"
assert_grep_fixed 'does **not**' "$TMPDIR/14-usbguard.md" \
    "USBGuard documentation states its physical and trusted-device limits"
assert_not_grep 'USBKill hardware, juice-jacking' "$TMPDIR/14-usbguard.md" \
    "USB authorization is not misrepresented as electrical protection"
assert_not_grep 'immutable audit log' "$TMPDIR/14-usbguard.md" \
    "audit-rule immutability is not misrepresented as tamper-proof storage"
assert_not_grep 'auto-enabled via systemd user-preset' "$TMPDIR/14-usbguard.md" \
    "notifier documentation matches static graphical-session ownership"
assert_not_grep 'enable --now usbguard-notifier' "$TMPDIR/14-usbguard.md" \
    "troubleshooting does not create obsolete default-target ownership"
assert_grep_fixed 'sudo usbguard block-device --permanent <device-id>' \
    "$TMPDIR/14-usbguard.md" \
    "revocation documentation persists an exact device-specific block"
assert_grep_fixed 'sudo usbguard remove-rule <rule-id>' "$TMPDIR/14-usbguard.md" \
    "policy-rule removal uses the native USBGuard interface"
assert_not_grep 'sudo nano /etc/usbguard/rules.conf' "$TMPDIR/14-usbguard.md" \
    "documentation does not recommend unsafe in-place policy editing"
assert_grep_fixed 'sudo usbguard-rule-parser -f "$candidate"' \
    "$TMPDIR/14-usbguard.md" \
    "keyboard recovery validates one captured candidate instead of rerunning discovery"
assert_grep_fixed 'sudo mktemp /etc/usbguard/.keyboard-rule.XXXXXX' \
    "$TMPDIR/14-usbguard.md" \
    "keyboard recovery keeps device descriptors out of a shared temporary directory"
assert_not_grep 'remembered permanently' "$TMPDIR/getting-started.md" \
    "getting-started guide cannot misstate notifier Allow as persistent"
assert_grep_fixed 'temporary authorization of the' "$TMPDIR/getting-started.md" \
    "getting-started guide states notifier Allow lifetime"
assert_not_grep 'Works out-of-the-box. No drivers needed.' "$TMPDIR/docking-stations.md" \
    "dock guide cannot collapse USB/DP and Thunderbolt PCIe authorization"
assert_grep_fixed 'USBGuard controls USB children only' "$TMPDIR/docking-stations.md" \
    "dock guide states the USBGuard/Thunderbolt boundary"
assert_grep_fixed 'does **not**' "$TMPDIR/docking-stations.md" \
    "dock guide states that boltd is intentionally absent"
assert_grep_fixed 'install `boltd`' "$TMPDIR/docking-stations.md" \
    "dock guide names the absent Thunderbolt authorization daemon"
assert_grep_fixed 'image cannot force this firmware property' \
    "$TMPDIR/docking-stations.md" \
    "dock guide requires per-device firmware authorization verification"

# --- DisplayLink opt-in supply chain + postconditions ----------------------
assert_grep_fixed 'set -euo pipefail' "$TMPDIR/displaylink.sh"
assert_grep_fixed '0C5D0F470484AE2FC40A9B6597F3008993E8909B' "$TMPDIR/displaylink.sh" \
    "negativo17 full signing-key fingerprint is pinned"
assert_grep_fixed 'gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-negativo17' "$TMPDIR/displaylink.sh" \
    "negativo17 repo uses only the locally pinned key"
assert_not_grep 'rpmkeys --import.*[|][|][[:space:]]*true' "$TMPDIR/displaylink.sh" \
    "negativo17 key import failure is not swallowed"
assert_grep_fixed 'trap cleanup_displaylink_install EXIT' "$TMPDIR/displaylink.sh" \
    "failed install uses the transaction cleanup path"
assert_grep_fixed "trap 'exit 129' HUP" "$TMPDIR/displaylink.sh" \
    "DisplayLink SIGHUP reaches transactional rollback with a failing status"
assert_grep_fixed "trap 'exit 130' INT" "$TMPDIR/displaylink.sh" \
    "DisplayLink SIGINT reaches transactional rollback with a failing status"
assert_grep_fixed "trap 'exit 143' TERM" "$TMPDIR/displaylink.sh" \
    "DisplayLink SIGTERM reaches transactional rollback with a failing status"
assert_grep_fixed 'run_system_dnf -y history undo "$CURRENT_TX_ID"' "$TMPDIR/displaylink.sh" \
    "failed package/build path undoes the exact captured DNF transaction"
assert_grep_fixed 'run_system_dnf history info --json "$tx_id"' "$TMPDIR/displaylink.sh" \
    "captured DNF transaction identity is validated before rollback ownership"
assert_grep_fixed 'for (( tx_id = after_id; tx_id > before_id; tx_id-- )); do' \
    "$TMPDIR/displaylink.sh" \
    "ownership scan covers every transaction recorded during the install"
assert_grep_fixed 'no recorded DNF transaction carries the requested DisplayLink packages' \
    "$TMPDIR/displaylink.sh" \
    "unowned package state stops the installer instead of a variant fallback"
assert_grep_fixed 'install-state.tsv' "$TMPDIR/displaylink.sh" \
    "successful install publishes a closed ownership ledger"
assert_grep_fixed "[ \"\$(wc -l < \"\$STATE_FILE\")\" -eq 8 ]" \
    "$TMPDIR/displaylink.sh" "DisplayLink ownership ledger has an exact schema size"
assert_grep_fixed '[ "$(state_value schema)" = 2 ]' "$TMPDIR/displaylink.sh" \
    "DisplayLink ownership ledger carries the current schema"
assert_grep_fixed 'repo_sha256' "$TMPDIR/displaylink.sh" \
    "DisplayLink ledger pins its restricted repository bytes"
assert_grep_fixed 'key_file_sha256' "$TMPDIR/displaylink.sh" \
    "DisplayLink ledger pins a helper-owned key file"
assert_grep_fixed "[ \"\$(stat -c '%u:%g:%a' \"\$STATE_DIR\" 2>/dev/null)\" = 0:0:700 ]" \
    "$TMPDIR/displaylink.sh" "DisplayLink ownership directory metadata is closed"
assert_grep_fixed "[ \"\$(stat -Lc '%u:%g:%a:%h' \"\$STATE_FILE\" 2>/dev/null)\" = 0:0:600:1 ]" \
    "$TMPDIR/displaylink.sh" "DisplayLink ownership ledger metadata is closed"
assert_grep_fixed 'rpmkeys --delete "$NEGATIVO17_FPR_EXPECTED"' \
    "$TMPDIR/displaylink.sh" "NoID Privacy-owned RPM trust is removed on rollback/uninstall"
assert_grep_fixed 'key_file_owned' "$TMPDIR/displaylink.sh" \
    "local key-file ownership is persisted and parsed"
assert_grep_fixed 'rpm_key_owned' "$TMPDIR/displaylink.sh" \
    "RPM keyring ownership is persisted and parsed"
assert_grep_fixed 'noid-displaylink-negativo17.repo' "$TMPDIR/displaylink.sh" \
    "DisplayLink uses a uniquely owned repository file"
assert_grep_fixed 'primary_key_fingerprints()' "$TMPDIR/displaylink.sh" \
    "DisplayLink key parser distinguishes primary keys from subkeys"
assert_grep_fixed '[ "${#DOWNLOADED_FPRS[@]}" -ne 1 ]' "$TMPDIR/displaylink.sh" \
    "DisplayLink download accepts exactly one pinned primary key"
assert_grep_fixed "--proto '=https' --proto-redir '=https' --tlsv1.2 --max-redirs 3" \
    "$TMPDIR/displaylink.sh" \
    "DisplayLink key retrieval and bounded redirects are HTTPS-only with a TLS floor"
assert_grep_fixed "stat -Lc '%u:%g:%a:%h' \"\$LOCK_FILE\"" \
    "$TMPDIR/displaylink.sh" \
    "DisplayLink transaction lock rejects unsafe metadata and hard links"
assert_grep_fixed 'LOCK_FILE=/run/noid-privacy/displaylink.lock' \
    "$TMPDIR/displaylink.sh" \
    "DisplayLink lock uses a path with a defined SELinux default context"
assert_grep_fixed 'f /run/noid-privacy/displaylink.lock 0600 root root -' \
    "$TMPDIR/noid-runtime.conf" \
    "DisplayLink lock is created before an opt-in transaction"
assert_grep_fixed 'z /run/noid-privacy/displaylink.lock 0600 root root -' \
    "$TMPDIR/noid-runtime.conf" \
    "DisplayLink lock has an explicit SELinux relabel contract"
assert_grep_fixed 'validate_owned_artifacts' "$TMPDIR/displaylink.sh" \
    "DisplayLink uninstall refuses modified helper-owned trust artifacts"
assert_not_grep 'rm -rf -- "$TX_DIR"' "$TMPDIR/displaylink.sh" \
    "DisplayLink rollback cleanup is mount-bounded and prefix-checked"
assert_grep_fixed 'includepkgs=displaylink,xorg-x11-displaylink,libevdi*,akmod-evdi,kmod-evdi,dkms-evdi,evdi-kmod-common' \
    "$TMPDIR/displaylink.sh" "third-party repository is restricted to DisplayLink/EVDI names"
assert_grep_fixed 'DNF=/usr/bin/dnf' "$TMPDIR/displaylink.sh" \
    "DisplayLink package work binds to Fedora's native DNF path"
assert_grep_fixed '( umask 022; "$DNF" "$@" )' "$TMPDIR/displaylink.sh" \
    "DisplayLink scopes public package metadata permissions to DNF work"
assert_grep_fixed 'run_system_dnf --repo=fedora,updates,fedora-multimedia -y install "$@"' \
    "$TMPDIR/displaylink.sh" "install transaction excludes unrelated enabled repositories"
displaylink_dnf_calls=$(grep -Ec 'run_system_dnf([[:space:]]|$)' "$TMPDIR/displaylink.sh" || true)
[ "$displaylink_dnf_calls" -eq 6 ] \
    && _pass "all six DisplayLink DNF paths use the scoped wrapper" \
    || _fail "DisplayLink scoped DNF path count differs (expected 6, got $displaylink_dnf_calls)"
assert_not_grep_extended '^[[:space:]]*(if ![[:space:]]+|[!][[:space:]]+)?dnf([[:space:]]|$)' \
    "$TMPDIR/displaylink.sh" \
    "DisplayLink has no DNF invocation outside the scoped wrapper"

DISPLAYLINK_DNF_HARNESS="$TMPDIR/displaylink-dnf-umask.sh"
awk '
    /^DNF=\/usr\/bin\/dnf$/ { print; next }
    /^run_system_dnf\(\) \{$/ { copy=1 }
    copy { print }
    copy && /^}$/ { exit }
' "$TMPDIR/displaylink.sh" > "$DISPLAYLINK_DNF_HARNESS"
displaylink_dnf_umask=$(env DISPLAYLINK_DNF_HARNESS="$DISPLAYLINK_DNF_HARNESS" bash -c '
    dnf() { umask; }
    export -f dnf
    # shellcheck source=/dev/null
    . "$DISPLAYLINK_DNF_HARNESS"
    DNF=dnf
    umask 077
    run_system_dnf history list --json
')
[ "$displaylink_dnf_umask" = 0022 ] \
    && _pass "DisplayLink gives every DNF child only the public metadata umask" \
    || _fail "DisplayLink DNF wrapper inherited umask $displaylink_dnf_umask"
assert_not_grep 'REPO_FILE=/etc/yum.repos.d/fedora-multimedia.repo' \
    "$TMPDIR/displaylink.sh" "generic administrator repo path is not overwritten"
assert_not_grep 'run_system_dnf -y remove akmod-evdi' "$TMPDIR/displaylink.sh" \
    "akmod-to-DKMS fallback cannot leave dependency/package residue"
assert_grep_fixed 'Synaptics publishes an Ubuntu' "$TMPDIR/displaylink.sh" \
    "DisplayLink helper identifies the Fedora packaging boundary"
assert_grep_fixed 'NoID Privacy makes no telemetry/privacy promise' "$TMPDIR/displaylink.sh" \
    "DisplayLink proprietary screen-processing boundary is disclosed"
assert_grep_fixed 'modinfo -k "$(uname -r)" evdi' "$TMPDIR/displaylink.sh" \
    "evdi is verified for the running kernel"
assert_grep_fixed 'systemctl is-enabled displaylink.service' "$TMPDIR/displaylink.sh" \
    "DisplayLink enablement has a postcondition"
assert_not_grep 'systemctl enable displaylink.service.*[|][|][[:space:]]*true' "$TMPDIR/displaylink.sh" \
    "DisplayLink enable failure is not swallowed"
assert_grep_fixed 'pre-uninstall snapshot failed; no packages were removed' "$TMPDIR/displaylink.sh" \
    "uninstall refuses mutation without rollback point"
assert_cmd_success "DisplayLink --help is side-effect-free and context-independent" \
    bash "$TMPDIR/displaylink.sh" --help
assert_cmd_success "DisplayLink -h is side-effect-free and context-independent" \
    bash "$TMPDIR/displaylink.sh" -h
displaylink_extra_rc=0
bash "$TMPDIR/displaylink.sh" --akmod extra \
    >"$TMPDIR/displaylink-extra.out" 2>&1 || displaylink_extra_rc=$?
assert_eq 1 "$displaylink_extra_rc" \
    "DisplayLink rejects extra arguments with its parser exit code"
assert_grep_fixed 'ERROR: Unknown option or extra argument: --akmod' \
    "$TMPDIR/displaylink-extra.out" \
    "DisplayLink rejects extra arguments before its root or mutation gates"

# --- systemd graphical-session lifecycle owns notifier ----------------------
assert_grep_extended '^ignore usbguard-notifier\.service$' "$TMPDIR/50-noid-usbguard.preset" \
    "preset passes cannot recreate the upstream default-target ownership"
assert_grep_fixed 'ConditionUser=!@system' "$TMPDIR/usbguard-notifier.conf" \
    "notifier retains systemd's system-identity defense in depth"
assert_not_grep 'ConditionEnvironment=XDG_SESSION_CLASS=user' \
    "$TMPDIR/usbguard-notifier.conf" \
    "notifier cannot race a late user-manager environment import"
assert_grep_fixed 'PartOf=graphical-session.target' \
    "$TMPDIR/usbguard-notifier.conf" \
    "notifier stops with the graphical session"
assert_grep_fixed 'After=graphical-session.target' \
    "$TMPDIR/usbguard-notifier.conf" \
    "notifier is ordered within the graphical-session transaction"
assert_grep_fixed 'ExecCondition=/usr/bin/systemctl --user --quiet is-active graphical-session.target' \
    "$TMPDIR/usbguard-notifier.conf" \
    "obsolete early enablement can only skip until the real session starts"
assert_grep_fixed 'ExecCondition=/usr/libexec/noid-eligible-user graphical' \
    "$TMPDIR/usbguard-notifier.conf" \
    "notifier requires a persistent account and exact local logind session"
assert_grep_fixed 'ExecStart=/usr/bin/usbguard-notifier --wait' \
    "$TMPDIR/usbguard-notifier.conf" "normal-user notifier waits for IPC"
assert_grep_fixed '/usr/lib/systemd/user/graphical-session.target.wants/usbguard-notifier.service' \
    "$KS_FILE" "distro static target link owns every graphical login"
assert_grep_fixed '/usr/lib/systemd/user/graphical-session.target.wants/noid-usbguard-login-catchup.service' \
    "$KS_FILE" "pre-login block catch-up is owned once per graphical login"
assert_grep_fixed 'PartOf=graphical-session.target' \
    "$TMPDIR/noid-usbguard-login-catchup.service" \
    "pre-login block catch-up stops with the graphical session"
assert_grep_fixed 'After=graphical-session.target usbguard-notifier.service' \
    "$TMPDIR/noid-usbguard-login-catchup.service" \
    "pre-login block catch-up runs after graphical notifier startup"
assert_grep_fixed 'Type=oneshot' "$TMPDIR/noid-usbguard-login-catchup.service" \
    "pre-login block inventory runs once per graphical session"
assert_grep_fixed 'RemainAfterExit=yes' "$TMPDIR/noid-usbguard-login-catchup.service" \
    "pre-login block catch-up cannot repeat inside one graphical session"
assert_grep_fixed 'ProtectHome=read-only' \
    "$TMPDIR/noid-usbguard-login-catchup.service" \
    "graphical identity gate can validate the user's canonical home"
assert_not_grep '^Restart=' "$TMPDIR/noid-usbguard-login-catchup.service" \
    "pre-login block catch-up has no notification restart loop"
assert_grep_fixed '/usr/bin/usbguard list-devices --blocked' \
    "$TMPDIR/noid-usbguard-login-catchup" \
    "login catch-up reads the current blocked inventory"
assert_grep_fixed '--action=review="Open USBGuard Devices"' \
    "$TMPDIR/noid-usbguard-login-catchup" \
    "login catch-up names the exact manager it opens"
assert_eq 1 "$(grep -c -- '--action=' "$TMPDIR/noid-usbguard-login-catchup")" \
    "login catch-up offers one unambiguous action"
assert_grep_fixed '/usr/bin/systemd-run --user --collect --wait --quiet' \
    "$TMPDIR/noid-usbguard-login-catchup" \
    "login catch-up escapes inherited NoNewPrivileges through the user manager"
assert_grep_fixed '--expand-environment=no' \
    "$TMPDIR/noid-usbguard-login-catchup" \
    "transient launch preserves the terminal shell command byte semantics"
assert_grep_fixed '/usr/bin/sudo -- /usr/local/bin/noid-usbguard-devices' \
    "$TMPDIR/noid-usbguard-login-catchup" \
    "login catch-up opens the interactive USBGuard manager directly"
assert_not_grep 'noid-tools\|gtk-launch\|Keep blocked' \
    "$TMPDIR/noid-usbguard-login-catchup" \
    "login catch-up has no broad app detour or redundant keep action"
assert_not_grep '^IPAddressDeny=' \
    "$TMPDIR/noid-usbguard-login-catchup.service" \
    "user unit makes no unenforceable IP firewall claim"
assert_not_grep_extended 'usbguard[[:space:]]+(allow-device|append-rule)' \
    "$TMPDIR/noid-usbguard-login-catchup" \
    "login catch-up can never authorize or persist a USB device"

# Exercise the three load-bearing outcomes against fixed-path test doubles:
# current blocks notify once and open only the reviewed manager directly;
# an empty inventory stays silent; IPC failure warns once and fails visible.
for mock in usbguard notify-send systemd-run ptyxis manager sleep; do
    cat >"$TMPDIR/mock-$mock" <<'USBGUARD_CATCHUP_MOCK_EOF'
#!/bin/bash
case "${0##*/}" in
    mock-usbguard)
        case "${NOID_CATCHUP_FIXTURE_MODE:-blocked}" in
            blocked) printf '%s\n' '14: block id 0781:5591 with-interface 08:06:50' ;;
            empty) : ;;
            error) exit 1 ;;
        esac
        ;;
    mock-notify-send)
        printf '%s\n' "$*" >> "${NOID_CATCHUP_NOTIFY_LOG:?}"
        [ "${NOID_CATCHUP_NOTIFY_ACTION:-dismissed}" = review ] && printf '%s\n' review
        ;;
    mock-systemd-run)
        printf '%s\n' "$*" >> "${NOID_CATCHUP_LAUNCH_LOG:?}"
        ;;
    mock-ptyxis|mock-manager) : ;;
    mock-sleep) : ;;
esac
USBGUARD_CATCHUP_MOCK_EOF
    chmod 0755 "$TMPDIR/mock-$mock"
done
sed \
    -e "s|/usr/bin/usbguard|$TMPDIR/mock-usbguard|g" \
    -e "s|/usr/bin/notify-send|$TMPDIR/mock-notify-send|g" \
    -e "s|/usr/bin/systemd-run|$TMPDIR/mock-systemd-run|g" \
    -e "s|/usr/bin/ptyxis|$TMPDIR/mock-ptyxis|g" \
    -e "s|/usr/local/bin/noid-usbguard-devices|$TMPDIR/mock-manager|g" \
    -e "s|/usr/bin/sleep|$TMPDIR/mock-sleep|g" \
    "$TMPDIR/noid-usbguard-login-catchup" \
    >"$TMPDIR/noid-usbguard-login-catchup.fixture"
chmod 0755 "$TMPDIR/noid-usbguard-login-catchup.fixture"

: >"$TMPDIR/catchup-notify.log"
: >"$TMPDIR/catchup-launch.log"
assert_cmd_success "one pre-login block produces one review notification" \
    env NOID_CATCHUP_FIXTURE_MODE=blocked NOID_CATCHUP_NOTIFY_ACTION=review \
        NOID_CATCHUP_NOTIFY_LOG="$TMPDIR/catchup-notify.log" \
        NOID_CATCHUP_LAUNCH_LOG="$TMPDIR/catchup-launch.log" \
        "$TMPDIR/noid-usbguard-login-catchup.fixture"
assert_eq 1 "$(wc -l < "$TMPDIR/catchup-notify.log")" \
    "one blocked-inventory catch-up emits one notification"
assert_eq 1 "$(wc -l < "$TMPDIR/catchup-launch.log")" \
    "review action opens the direct USBGuard manager once"
assert_grep_fixed "$TMPDIR/mock-manager" "$TMPDIR/catchup-launch.log" \
    "transient terminal receives the interactive manager command"
assert_grep_fixed '--expand-environment=no' "$TMPDIR/catchup-launch.log" \
    "transient launch disables systemd's second dollar expansion"

: >"$TMPDIR/catchup-notify.log"
: >"$TMPDIR/catchup-launch.log"
assert_cmd_success "empty pre-login block inventory stays silent" \
    env NOID_CATCHUP_FIXTURE_MODE=empty \
        NOID_CATCHUP_NOTIFY_LOG="$TMPDIR/catchup-notify.log" \
        NOID_CATCHUP_LAUNCH_LOG="$TMPDIR/catchup-launch.log" \
        "$TMPDIR/noid-usbguard-login-catchup.fixture"
assert_eq 0 "$(wc -l < "$TMPDIR/catchup-notify.log")" \
    "empty catch-up emits no notification"

: >"$TMPDIR/catchup-notify.log"
: >"$TMPDIR/catchup-launch.log"
assert_cmd_failure "unreadable USBGuard state fails visible without retry loop" \
    env NOID_CATCHUP_FIXTURE_MODE=error \
        NOID_CATCHUP_NOTIFY_LOG="$TMPDIR/catchup-notify.log" \
        NOID_CATCHUP_LAUNCH_LOG="$TMPDIR/catchup-launch.log" \
        "$TMPDIR/noid-usbguard-login-catchup.fixture"
assert_eq 1 "$(wc -l < "$TMPDIR/catchup-notify.log")" \
    "unreadable state emits one truthful notification"
assert_grep_fixed 'USB protection status unavailable' "$TMPDIR/catchup-notify.log" \
    "unreadable state never claims that blocking remains active"

# Verify the exact merged unit and every absolute executable inside a
# hermetic candidate root. The source host intentionally does not have M08's
# new helper installed yet, so its user-manager parser uses a second copy with
# only that already-exactly-asserted command replaced by /usr/bin/true.
install -d "$TMPDIR/systemd-root/etc/systemd/system/usbguard-notifier.service.d" \
    "$TMPDIR/systemd-root/usr/lib/systemd/system" \
    "$TMPDIR/systemd-root/usr/libexec" "$TMPDIR/systemd-root/usr/bin"
install -m 0644 /usr/lib/systemd/user/usbguard-notifier.service \
    "$TMPDIR/systemd-root/usr/lib/systemd/system/usbguard-notifier.service"
install -m 0644 "$TMPDIR/usbguard-notifier.conf" \
    "$TMPDIR/systemd-root/etc/systemd/system/usbguard-notifier.service.d/10-noid-wait.conf"
install -m 0644 "$TMPDIR/noid-usbguard-login-catchup.service" \
    "$TMPDIR/systemd-root/usr/lib/systemd/system/noid-usbguard-login-catchup.service"
install -m 0755 "$TMPDIR/noid-eligible-user" \
    "$TMPDIR/systemd-root/usr/libexec/noid-eligible-user"
install -m 0755 "$TMPDIR/noid-usbguard-login-catchup" \
    "$TMPDIR/systemd-root/usr/libexec/noid-usbguard-login-catchup"
install -m 0755 /usr/bin/systemctl "$TMPDIR/systemd-root/usr/bin/systemctl"
install -m 0755 /usr/bin/usbguard-notifier \
    "$TMPDIR/systemd-root/usr/bin/usbguard-notifier"
assert_cmd_success "exact notifier graph and M08 helper verify in a hermetic candidate root" \
    env -i PATH=/usr/sbin:/usr/bin HOME=/root LC_ALL=C \
    SYSTEMD_UNIT_PATH=/etc/systemd/system:/usr/lib/systemd/system \
    systemd-analyze --root="$TMPDIR/systemd-root" --recursive-errors=no \
        verify usbguard-notifier.service noid-usbguard-login-catchup.service

install -d "$TMPDIR/systemd-user/usbguard-notifier.service.d"
install -m 0644 /usr/lib/systemd/user/usbguard-notifier.service \
    "$TMPDIR/systemd-user/usbguard-notifier.service"
install -m 0644 "$TMPDIR/usbguard-notifier.conf" \
    "$TMPDIR/systemd-user/usbguard-notifier.service.d/10-noid-wait.conf"
install -m 0644 "$TMPDIR/noid-usbguard-login-catchup.service" \
    "$TMPDIR/systemd-user/noid-usbguard-login-catchup.service"
sed -i 's|^ExecCondition=/usr/libexec/noid-eligible-user graphical$|ExecCondition=/usr/bin/true|' \
    "$TMPDIR/systemd-user/usbguard-notifier.service.d/10-noid-wait.conf"
sed -i \
    -e 's|^ExecCondition=/usr/libexec/noid-eligible-user graphical$|ExecCondition=/usr/bin/true|' \
    -e 's|^ExecStart=/usr/libexec/noid-usbguard-login-catchup$|ExecStart=/usr/bin/true|' \
    "$TMPDIR/systemd-user/noid-usbguard-login-catchup.service"
install -d -m 0700 "$TMPDIR/systemd-runtime" "$TMPDIR/systemd-home"
assert_cmd_failure "user-unit verifier rejects an absent runtime in a clean build environment" \
    env -i PATH=/usr/sbin:/usr/bin \
    SYSTEMD_UNIT_PATH="$TMPDIR/systemd-user:/usr/lib/systemd/user" \
    systemd-analyze --user --recursive-errors=no verify usbguard-notifier.service
assert_cmd_success "candidate notifier user-unit graph parses in a real user manager" \
    env -i PATH=/usr/sbin:/usr/bin HOME="$TMPDIR/systemd-home" LC_ALL=C \
    XDG_RUNTIME_DIR="$TMPDIR/systemd-runtime" \
    SYSTEMD_UNIT_PATH="$TMPDIR/systemd-user:/usr/lib/systemd/user" \
    systemd-analyze --user verify \
        usbguard-notifier.service noid-usbguard-login-catchup.service
assert_cmd_success "compose-scoped user-manager parser accepts the merged definition" \
    env -i PATH=/usr/sbin:/usr/bin HOME="$TMPDIR/systemd-home" LC_ALL=C \
    XDG_RUNTIME_DIR="$TMPDIR/systemd-runtime" \
    SYSTEMD_UNIT_PATH="$TMPDIR/systemd-user:/usr/lib/systemd/user" \
    systemd-analyze --user --recursive-errors=no verify \
        usbguard-notifier.service noid-usbguard-login-catchup.service
install -d -m 0700 "$TMPDIR/systemd-runtime-cleanup"
assert_cmd_success "compose-scoped user-manager verifier executes before cleanup" \
    env -i PATH=/usr/sbin:/usr/bin HOME="$TMPDIR/systemd-home" LC_ALL=C \
    XDG_RUNTIME_DIR="$TMPDIR/systemd-runtime-cleanup" \
    SYSTEMD_UNIT_PATH="$TMPDIR/systemd-user:/usr/lib/systemd/user" \
    systemd-analyze --user --recursive-errors=no verify \
        usbguard-notifier.service noid-usbguard-login-catchup.service
if [ -d "$TMPDIR/systemd-runtime-cleanup/systemd" ]; then
    _pass "compose-scoped verifier creates its expected runtime child"
else
    _fail "compose-scoped verifier did not create its expected runtime child"
fi
assert_cmd_success "verifier runtime children are removed mount-boundedly" \
    find "$TMPDIR/systemd-runtime-cleanup" -xdev -mindepth 1 -delete
assert_cmd_success "emptied private verifier runtime is removable" \
    rmdir -- "$TMPDIR/systemd-runtime-cleanup"
if [ ! -e "$TMPDIR/systemd-runtime-cleanup" ]; then
    _pass "private verifier runtime is absent after cleanup"
else
    _fail "private verifier runtime remains after cleanup"
fi
assert_grep_fixed '/usr/bin/systemd-analyze --user --recursive-errors=no' \
    "$KS_FILE" "compose limits recursive errors to its owned merged-unit definition"
assert_grep_fixed 'XDG_RUNTIME_DIR="$unit_verify_runtime"' "$KS_FILE" \
    "compose supplies the private runtime required by offline user-unit verification"
assert_grep_fixed 'chmod 0700 "$unit_verify_runtime"' "$KS_FILE" \
    "compose closes the private user-unit verification runtime mode"
assert_grep_fixed '/usr/bin/env -i' "$KS_FILE" \
    "compose user-unit verification cannot inherit a misleading login environment"
assert_grep_fixed 'find "$unit_verify_runtime" -xdev -mindepth 1 -delete' \
    "$KS_FILE" "compose removes verifier-created runtime children without crossing mounts"
assert_not_grep 'rmdir "$unit_verify_runtime"' "$KS_FILE" \
    "compose does not assume systemd-analyze leaves its runtime directory empty"
assert_eq 3 "$(grep -cF '/usr/libexec/noid-eligible-user account-uid' "$KS_FILE")" \
    "first-user IPC, passwd reconciliation and failure notifications share one account gate"
assert_grep_fixed 'account_uid_is_eligible "$2" "" no' \
    "$TMPDIR/noid-eligible-user" \
    "root account classification retains ProtectHome without weakening identity records"
assert_grep_fixed '/usr/libexec/noid-eligible-user account-uid "$candidate_uid"' \
    "$TMPDIR/firstboot.sh" \
    "firstboot cannot select a numeric-only pseudo-user for USBGuard IPC"
assert_grep_fixed '/usr/libexec/noid-eligible-user account-uid "$uid" || continue' \
    "$TMPDIR/add-user.sh" \
    "passwd reconciliation excludes GDM/GIS/transient identities"
assert_grep_fixed '/usr/libexec/noid-eligible-user account-uid "$uid" || continue' \
    "$TMPDIR/remove-gnome-wildcard.sh" \
    "degraded-state notifications exclude non-human session buses"
assert_not_grep '"$uid" -lt 65000' "$TMPDIR/add-user.sh" \
    "numeric-only USBGuard account classification cannot return"
assert_file_executable "$USBGUARD_RUNTIME" \
    "USBGuard named-ACL runtime gate is executable"
assert_cmd_success "USBGuard named-ACL runtime gate parses" \
    bash -n "$USBGUARD_RUNTIME"
assert_grep_fixed 'live|fresh-install|reboot) ;;' "$USBGUARD_RUNTIME" \
    "USBGuard runtime gate accepts the exact three lifecycle identities"
assert_not_grep 'ImplicitPolicyTarget allow' "$USBGUARD_RUNTIME" \
    "runtime gate never opens the implicit policy during a denial probe"
assert_grep_fixed 'ImplicitPolicyTarget "$original_parameter"' \
    "$USBGUARD_RUNTIME" \
    "runtime gate proves parameter denial using the already-safe value"
assert_grep_fixed "root:root:755:1" "$USBGUARD_RUNTIME" \
    "runtime gate authenticates the root-executed eligible-user classifier"
assert_grep_fixed 'matchpathcon -V "$ELIGIBLE"' "$USBGUARD_RUNTIME" \
    "runtime gate verifies the classifier SELinux execution boundary"
assert_grep_fixed 'NOID_RUNTIME_IPC_PROBE' "$USBGUARD_RUNTIME" \
    "runtime gate attempts and rejects an unprivileged policy append"
assert_grep_fixed 'rules.conf changed during denied IPC probes' "$USBGUARD_RUNTIME" \
    "runtime gate proves denied probes leave durable policy unchanged"
assert_grep_fixed 'root:root:600:1' "$USBGUARD_RUNTIME" \
    "runtime gate rejects unsafe daemon-config or policy metadata"
assert_grep_fixed 'allow-device "$allowed_id"' "$USBGUARD_RUNTIME" \
    "runtime gate proves the notifier-compatible device-modify path"
assert_file_executable "$GREETER_RUNTIME" \
    "GDM/GIS/transient candidate runtime gate is executable"
assert_cmd_success "greeter identity runtime gate parses" \
    bash -n "$GREETER_RUNTIME"
for unit in usbguard-notifier.service noid-agent-policy-adapters.service; do
    assert_grep_fixed "$unit" "$GREETER_RUNTIME" \
        "greeter runtime gate covers $unit"
done
assert_grep_fixed 'IPCAccessControl.d/$name' "$GREETER_RUNTIME" \
    "greeter runtime gate rejects a per-identity USBGuard IPC grant"
assert_grep_fixed 'getent group usbguard >/dev/null 2>&1' "$GREETER_RUNTIME" \
    "greeter runtime gate checks legacy group membership only when the group exists"
assert_not_grep 'usbguard group is missing' "$GREETER_RUNTIME" \
    "absence of the retired broad USBGuard group is accepted as safe"
assert_grep_fixed '-p LoadState -p ActiveState -p Result' "$GREETER_RUNTIME" \
    "greeter runtime gate takes one atomic user-unit property snapshot"
assert_grep_fixed 'setpriv --reuid="$uid" --regid="$gid" --clear-groups' \
    "$GREETER_RUNTIME" \
    "greeter runtime gate queries with the already-validated NSS identity"
assert_grep_fixed 'DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus"' \
    "$GREETER_RUNTIME" \
    "greeter runtime gate uses the existing user bus without a PAM bridge"
assert_not_grep '--machine=' "$GREETER_RUNTIME" \
    "greeter runtime gate cannot synthesize a PAM login for the pseudo-user"
assert_grep_fixed 'success|exec-condition)' "$GREETER_RUNTIME" \
    "greeter runtime gate accepts only systemd's two clean skip results"
assert_grep_fixed 'capture_active_greeter_snapshots' "$GREETER_RUNTIME" \
    "greeter runtime gate owns the foreground-session wait"
assert_grep_fixed 'for _ in {1..600}; do' "$GREETER_RUNTIME" \
    "greeter runtime gate bounds its foreground wait to 30 seconds"
assert_grep_fixed 'greeter_snapshots+=("$properties")' "$GREETER_RUNTIME" \
    "greeter runtime gate freezes the active property set before Live auto-login"
assert_grep_fixed 'if session_is_active_greeter "$session"; then' "$GREETER_RUNTIME" \
    "a bus failure remains fatal while the greeter is foreground"
assert_grep_fixed 'manager_retired_cleanly "$uid"' "$GREETER_RUNTIME" \
    "a short-lived Live greeter is accepted only after clean manager retirement"
assert_grep_fixed '[[ $active == inactive && $result == success ]]' \
    "$GREETER_RUNTIME" \
    "retired greeter manager must have an exact successful terminal state"
assert_grep_fixed 'root:root:755:1' "$GREETER_RUNTIME" \
    "greeter gate authenticates the root-executed identity classifier"
assert_grep_fixed 'matchpathcon -V "$gate"' "$GREETER_RUNTIME" \
    "greeter gate verifies the classifier SELinux execution boundary"

# GNOME must never neutralize implicit block with a global allow.
assert_grep_fixed 'usbguard list-rules --label "$label"' "$TMPDIR/remove-gnome-wildcard.sh"
assert_grep_fixed 'usbguard remove-rule "$rule_id"' "$TMPDIR/remove-gnome-wildcard.sh"
assert_grep_fixed 'GNOME USBGuard wildcard remains after cleanup' "$TMPDIR/remove-gnome-wildcard.sh"
assert_grep_fixed 'Unable to verify USBGuard rules after cleanup' \
    "$TMPDIR/remove-gnome-wildcard.sh" \
    "a failed final rule query cannot be reported as wildcard absence"
assert_not_grep 'ExecStartPost=/usr/local/sbin/noid-usbguard-remove-gnome-wildcard' "$KS_FILE" \
    "wildcard cleanup failure cannot terminate usbguard.service"
assert_grep_fixed 'Wants=noid-usbguard-remove-gnome-wildcard.service' "$KS_FILE" \
    "every USBGuard start pulls in independent cleanup"
assert_grep_fixed 'Restart=on-failure' "$KS_FILE" \
    "wildcard cleanup retries independently"
assert_grep_fixed 'StartLimitBurst=3' "$TMPDIR/noid-usbguard-remove-gnome-wildcard.service" \
    "wildcard cleanup retry burst is bounded"
assert_grep_fixed 'RestartSec=10s' "$TMPDIR/noid-usbguard-remove-gnome-wildcard.service" \
    "wildcard cleanup retries are spaced"
assert_grep_fixed 'STATE=%s' "$TMPDIR/remove-gnome-wildcard.sh" \
    "wildcard cleanup publishes a durable state"
assert_grep_fixed 'mv -fT -- "$tmp" "$status_file"' \
    "$TMPDIR/remove-gnome-wildcard.sh" \
    "wildcard cleanup status uses an atomic same-directory replacement"
assert_grep_fixed 'sync -f /var/lib/noid-privacy' \
    "$TMPDIR/remove-gnome-wildcard.sh" \
    "wildcard cleanup status rename is durable"
assert_grep_fixed 'retire_status()' "$TMPDIR/remove-gnome-wildcard.sh" \
    "wildcard cleanup can retire stale status through a trusted parent"
assert_not_grep 'publish_status DEGRADED cleanup-unverified || true' \
    "$TMPDIR/remove-gnome-wildcard.sh" \
    "wildcard cleanup status failures are never silently swallowed"

# A persistent failure may be retried, but it must notify only on the first
# transition into DEGRADED. Exercise the EXIT handler twice against one shared
# status marker so this is behavior, not merely a source-string assertion.
awk '/^on_exit\(\)/,/^}/' "$TMPDIR/remove-gnome-wildcard.sh" \
    >"$TMPDIR/wildcard-on-exit.function"
cat >"$TMPDIR/wildcard-notify-once.fixture" <<'USBGUARD_NOTIFY_ONCE_EOF'
#!/bin/bash
set -euo pipefail
marker=${NOID_WILDCARD_DEGRADED_MARKER:?}
notify_log=${NOID_WILDCARD_NOTIFY_LOG:?}
degraded_status_is_current() { [ -f "$marker" ]; }
publish_status() { : > "$marker"; }
logger() { :; }
notify_active_users() { printf 'notified\n' >> "$notify_log"; }
# shellcheck source=/dev/null
. "${NOID_WILDCARD_ON_EXIT_FUNCTION:?}"
false || on_exit
USBGUARD_NOTIFY_ONCE_EOF
chmod 0755 "$TMPDIR/wildcard-notify-once.fixture"
for _attempt in 1 2; do
    NOID_WILDCARD_DEGRADED_MARKER="$TMPDIR/wildcard-degraded.marker" \
    NOID_WILDCARD_NOTIFY_LOG="$TMPDIR/wildcard-notify.log" \
    NOID_WILDCARD_ON_EXIT_FUNCTION="$TMPDIR/wildcard-on-exit.function" \
        "$TMPDIR/wildcard-notify-once.fixture" || true
done
assert_eq 1 "$(wc -l < "$TMPDIR/wildcard-notify.log")" \
    "one persistent wildcard-cleanup fault emits one desktop notification"

# Reproduce the EXIT-trap call context with a failing atomic rename. The old
# implementation inherited disabled errexit from `|| true`, continued after
# mv failed and left the prior OK file in place. The publisher must now retire
# that stale evidence even in the same OR-list context.
wildcard_status_root="$TMPDIR/wildcard-status-root"
wildcard_fail_bin="$TMPDIR/wildcard-fail-bin"
mkdir -p "$wildcard_status_root" "$wildcard_fail_bin"
chmod 0755 "$wildcard_status_root"
printf 'STATE=OK\nMESSAGE=wildcard-absent\nCHECKED_AT=old\n' \
    >"$wildcard_status_root/usbguard-gnome-wildcard.status"
chmod 0644 "$wildcard_status_root/usbguard-gnome-wildcard.status"
cat >"$wildcard_fail_bin/mv" <<'USBGUARD_STATUS_MV_FAIL_EOF'
#!/bin/bash
printf 'invoked\n' >>"${NOID_USBGUARD_MV_LOG:?}"
exit 70
USBGUARD_STATUS_MV_FAIL_EOF
chmod 0755 "$wildcard_fail_bin/mv"
wildcard_publish_fixture="$TMPDIR/wildcard-publish-failure.fixture"
awk '/^notify_active_users\(\)/ { exit } { print }' \
    "$TMPDIR/remove-gnome-wildcard.sh" \
    | sed \
        -e "s|status_file=/var/lib/noid-privacy/usbguard-gnome-wildcard.status|status_file=$wildcard_status_root/usbguard-gnome-wildcard.status|" \
        -e "s|/var/lib/noid-privacy|$wildcard_status_root|g" \
        -e "s|0:0:755|$(id -u):$(id -g):755|g" \
        -e "s|0:0:644:1|$(id -u):$(id -g):644:1|g" \
        -e "s|-o root -g root|-o $(id -un) -g $(id -gn)|g" \
        -e "s|chown root:root|chown $(id -un):$(id -gn)|g" \
        -e "s|/sys/fs/selinux/enforce|$wildcard_status_root/selinux-disabled|g" \
        -e "s|export PATH=/usr/sbin:/usr/bin|export PATH=$wildcard_fail_bin:/usr/sbin:/usr/bin|" \
        >"$wildcard_publish_fixture"
printf '\npublish_status DEGRADED cleanup-unverified || true\n' \
    >>"$wildcard_publish_fixture"
chmod 0755 "$wildcard_publish_fixture"
assert_cmd_success "wildcard degraded-status failure fixture executes" \
    env NOID_USBGUARD_MV_LOG="$TMPDIR/wildcard-mv.log" \
        "$wildcard_publish_fixture"
assert_file_exists "$TMPDIR/wildcard-mv.log" \
    "wildcard fixture reaches the injected failed rename"
if [ ! -e "$wildcard_status_root/usbguard-gnome-wildcard.status" ] \
   && [ ! -L "$wildcard_status_root/usbguard-gnome-wildcard.status" ]; then
    _pass "failed wildcard DEGRADED publication retires stale OK evidence"
else
    _fail "failed wildcard DEGRADED publication retires stale OK evidence"
fi

assert_grep_fixed 'loginctl list-sessions --json=short' \
    "$TMPDIR/remove-gnome-wildcard.sh" \
    "cleanup alerts start from a bounded logind session snapshot"
assert_grep_fixed '[ "$remote" = no ]' "$TMPDIR/remove-gnome-wildcard.sh" \
    "cleanup alerts exclude remote sessions"
assert_grep_fixed '[ "$locked" = no ]' "$TMPDIR/remove-gnome-wildcard.sh" \
    "cleanup alerts exclude locked sessions"
assert_grep_fixed 'setpriv --reuid="$uid" --regid="$gid" --init-groups' \
    "$TMPDIR/remove-gnome-wildcard.sh" \
    "cleanup alerts drop privilege without a PAM-capable sudo bridge"
assert_not_grep 'sudo -u' "$TMPDIR/remove-gnome-wildcard.sh" \
    "cleanup alerts never synthesize a sudo/PAM login"
assert_grep_fixed 'ProtectSystem=strict' "$TMPDIR/noid-usbguard-remove-gnome-wildcard.service" \
    "wildcard cleanup service has a read-only system image"
assert_grep_fixed 'ReadWritePaths=/var/lib/noid-privacy' \
    "$TMPDIR/noid-usbguard-remove-gnome-wildcard.service" \
    "wildcard cleanup service can write only its owned state directory"
assert_grep_fixed 'ProtectHome=read-only' \
    "$TMPDIR/noid-usbguard-remove-gnome-wildcard.service" \
    "wildcard cleanup service retains visibility of active session buses"
assert_grep_fixed 'InaccessiblePaths=/home /root' \
    "$TMPDIR/noid-usbguard-remove-gnome-wildcard.service" \
    "wildcard cleanup keeps user data hidden while exposing /run/user"
assert_grep_fixed 'RestrictAddressFamilies=AF_UNIX' \
    "$TMPDIR/noid-usbguard-remove-gnome-wildcard.service" \
    "wildcard cleanup service is limited to local IPC"
assert_grep_fixed 'IPAddressDeny=any' "$TMPDIR/noid-usbguard-remove-gnome-wildcard.service" \
    "wildcard cleanup service cannot emit IP traffic"
assert_grep_fixed 'degraded_status_is_current' "$TMPDIR/remove-gnome-wildcard.sh" \
    "persistent wildcard-cleanup failure is detected before desktop notification"
assert_grep_fixed 'if [ "$notify_needed" -eq 1 ]; then' \
    "$TMPDIR/remove-gnome-wildcard.sh" \
    "only a transition into degraded state emits a desktop notification"
assert_grep_fixed 'USBGuard protection state is unverified' \
    "$TMPDIR/remove-gnome-wildcard.sh" \
    "degraded cleanup does not claim the daemon remains active"
assert_not_grep 'USBGuard daemon remains active' "$TMPDIR/remove-gnome-wildcard.sh" \
    "retired false daemon-active claim cannot return"
assert_not_grep 'USBGuard is still blocking unknown devices' \
    "$TMPDIR/remove-gnome-wildcard.sh" \
    "cleanup failure does not claim that enforcement is active"
assert_grep_fixed 'regular_root_file_ok "$DAEMON_CONF" 600' \
    "$TMPDIR/firstboot.sh" \
    "firstboot fails explicitly on unsafe daemon-config metadata"
assert_grep_fixed 'daemon.conf metadata must be root:root 600 nlink=1' "$KS_FILE" \
    "Module 14 verifies the daemon-config startup mode"
assert_grep_fixed 'write_emergency_policy' "$TMPDIR/firstboot.sh" \
    "emergency retries rebuild the bounded policy"
assert_grep_fixed 'generated emergency USB policy failed its bounded-policy postcondition' \
    "$TMPDIR/firstboot.sh" "emergency policy is verified before activation"
assert_not_grep 'polkit.addRule(function(action, subject)' "$KS_FILE" \
    "obsolete broad gsd-usb-protection Polkit grant is absent"

# Cross-module consumer: system USBGuard state belongs to the read-only
# noid-status CLI, not to a dead variable name in the graphical Welcome app.
assert_grep_fixed '/var/lib/noid-privacy/usbguard-status.txt' "$TMPDIR/noid-status" \
    "Module 13 noid-status consumes the USBGuard state contract"
assert_grep_fixed 'read_usbguard_state()' "$TMPDIR/noid-status" \
    "Module 13 parses USBGuard status as closed data"
assert_not_grep '\. "\$UG_STATE_FILE"' "$TMPDIR/noid-status" \
    "Module 13 never sources USBGuard status"
mapfile -t usbguard_aide_rows < <(awk -F'|' \
    '$3 == "/etc/usbguard/.noid-aide-coverage-probe" { print $0 }' \
    "$AIDE_SECURE_MANIFEST")
assert_eq 1 "${#usbguard_aide_rows[@]}" \
    "canonical manifest has one USBGuard AIDE contract"
IFS='|' read -r usbguard_aide_rule _ _ <<<"${usbguard_aide_rows[0]}"
assert_grep_fixed "grep -qxF '$usbguard_aide_rule SECURE'" "$KS_FILE" \
    "Module 14 requires AIDE content tracking for all USBGuard controls"
assert_grep_fixed "--path-check='f:/etc/usbguard/rules.conf'" "$KS_FILE" \
    "Module 14 evaluates effective AIDE rule-tree coverage"
assert_grep_fixed 'grep -qF sha256 <<<"$aide_usbguard_match"' "$KS_FILE" \
    "Module 14 requires the effective SHA-256 attribute"
assert_grep_fixed 'grep -qF sha512 <<<"$aide_usbguard_match"' "$KS_FILE" \
    "Module 14 requires the effective SHA-512 attribute"
assert_grep_fixed "! grep -qxF '!/etc/usbguard/rules\\.conf\$'" "$KS_FILE" \
    "Module 14 rejects a rules.conf AIDE blind spot"
assert_grep_fixed 'grep -qF '\''/var/lib/noid-privacy/usbguard-status.txt'\''' "$KS_FILE" \
    "Module 14 verifies the stable USBGuard state path"
assert_grep_fixed '/usr/local/bin/noid-status' "$KS_FILE" \
    "Module 14 verifies the actual Module 13 status consumer"
assert_not_grep 'USBGUARD_STATUS_FILE.*noid-welcome' "$KS_FILE" \
    "Module 14 does not retain the obsolete Welcome variable contract"

# --- KS package list --------------------------------------------------------
awk '/^%packages([[:space:]]|$)/,/^%end$/' "$KS_FILE" > "$TMPDIR/packages.txt"
assert_grep_extended '^usbguard$' "$TMPDIR/packages.txt"
assert_grep_extended '^usbguard-selinux$' "$TMPDIR/packages.txt"
assert_grep_extended '^usbguard-tools$' "$TMPDIR/packages.txt"
assert_grep_extended '^usbguard-notifier$' "$TMPDIR/packages.txt"
# usbguard-dbus subpackage for the org.usbguard.Devices1 D-Bus name.
assert_grep_extended '^usbguard-dbus$' "$TMPDIR/packages.txt"

# --- M14 low/info audit regressions ----------------------------------------
awk '/^write_state\(\)/,/^}/' "$TMPDIR/firstboot.sh" > "$TMPDIR/write-state.sh"
awk '/^write_status\(\)/,/^}/' "$TMPDIR/firstboot.sh" > "$TMPDIR/write-status.sh"
for publisher in "$TMPDIR/write-state.sh" "$TMPDIR/write-status.sh"; do
    for guarded_step in \
        'chmod 0644 "$tmp" &&' \
        'chown root:root "$tmp" &&' \
        'restore_and_verify_label "$tmp" &&' \
        'sync -- "$tmp" &&'; do
        assert_grep_fixed "$guarded_step" "$publisher" \
            "USBGuard atomic publisher propagates: $guarded_step"
    done
done
assert_grep_fixed 'mv -fT -- "$tmp" "$STATE_FILE" &&' "$TMPDIR/write-state.sh" \
    "durable-state rename failure reaches the publisher error path"
assert_grep_fixed 'regular_root_file_ok "$STATE_FILE" 644 &&' \
    "$TMPDIR/write-state.sh" \
    "durable-state metadata postcondition gates the byte comparison"
assert_grep_fixed 'mv -fT -- "$tmp" "$STATUS_FILE" &&' "$TMPDIR/write-status.sh" \
    "status rename failure reaches the publisher error path"
assert_grep_fixed 'regular_root_file_ok "$STATUS_FILE" 644 &&' \
    "$TMPDIR/write-status.sh" \
    "status metadata postcondition gates the byte comparison"

publisher_postcondition_fixture() (
    local publisher=$1
    STATE_DIR="$TMPDIR/publisher-state"
    # Consumed by the function body sourced below.
    # shellcheck disable=SC2034
    STATE_FILE="$STATE_DIR/usbguard-policy-state"
    # Consumed by the function body sourced below.
    # shellcheck disable=SC2034
    STATUS_FILE="$STATE_DIR/usbguard-status.txt"
    command mkdir -p "$STATE_DIR"
    # These mocks isolate the publisher's control flow. In particular, cmp is
    # deliberately successful so an ignored metadata failure would reproduce
    # the audited false-success path.
    # shellcheck disable=SC2317,SC2329
    ensure_root_directory() { command mkdir -p "$1"; }
    # shellcheck disable=SC2317,SC2329
    chmod() { :; }
    # shellcheck disable=SC2317,SC2329
    chown() { :; }
    # shellcheck disable=SC2317,SC2329
    restore_and_verify_label() { :; }
    # shellcheck disable=SC2317,SC2329
    sync() { :; }
    # shellcheck disable=SC2317,SC2329
    regular_root_file_ok() { return 1; }
    # shellcheck disable=SC2317,SC2329
    cmp() { return 0; }
    # shellcheck disable=SC2317,SC2329
    log() { :; }
    # shellcheck source=/dev/null
    . "$publisher"
    case "${publisher##*/}" in
        write-state.sh) write_state real ;;
        write-status.sh) write_status real 1 no ;;
        *) return 2 ;;
    esac
)
assert_cmd_failure "durable-state publisher fails a metadata postcondition" \
    publisher_postcondition_fixture "$TMPDIR/write-state.sh"
assert_cmd_failure "status publisher fails a metadata postcondition" \
    publisher_postcondition_fixture "$TMPDIR/write-status.sh"

assert_not_grep 'ExecStartPost removes' "$KS_FILE" \
    "module header describes the independent wildcard-cleanup unit"
assert_grep_fixed "if id -nG \"\$username\" 2>/dev/null | tr ' ' '\\n' | grep -qx usbguard; then" \
    "$TMPDIR/add-user.sh" \
    "legacy USBGuard group removal has an explicit postcondition"
assert_not_grep_extended '^[[:space:]]*! id -nG.*grep -qx usbguard' \
    "$TMPDIR/add-user.sh" \
    "legacy group verification is not an inert inverted command"

for published_path in \
    /etc/systemd/system/noid-usbguard-firstboot.service \
    /etc/systemd/user-preset/50-noid-usbguard.preset \
    /usr/local/bin/noid-usbguard-add-user.sh \
    /etc/systemd/system/noid-usbguard-add-user.service \
    /etc/systemd/system/noid-usbguard-add-user.path \
    /usr/local/sbin/noid-usbguard-remove-gnome-wildcard \
    /etc/systemd/system/usbguard.service.d/20-noid-reject-gnome-wildcard.conf \
    /etc/systemd/system/noid-usbguard-remove-gnome-wildcard.service; do
    assert_grep_fixed "restorecon -F $published_path" "$KS_FILE" \
        "published USBGuard root path is relabelled: $published_path"
done

assert_grep_fixed 'Before reboot: complete MOK enrollment when prompted' \
    "$TMPDIR/displaylink.sh" \
    "optional MOK prerequisite does not consume a numbered DisplayLink step"
assert_grep_fixed '  1. Reboot: sudo reboot' "$TMPDIR/displaylink.sh" \
    "DisplayLink next steps start at one in every Secure Boot state"
assert_not_grep '  4. Verify:' "$TMPDIR/displaylink.sh" \
    "DisplayLink next steps remain consecutively numbered"
assert_grep_fixed 'systemd.mask=noid-usbguard-firstboot.service systemd.mask=usbguard.service' \
    "$TMPDIR/14-usbguard.md" \
    "one-boot keyboard recovery masks the otherwise failing firstboot unit"
assert_grep_fixed 'notification includes an **Allow** button' \
    "$TMPDIR/14-usbguard.md" \
    "USBGuard documentation uses the notifier's actual Allow label"
assert_grep_fixed 'with **Allow** and **Reject** actions' "$TMPDIR/docking-stations.md" \
    "dock documentation uses the notifier's actual action labels"
assert_not_grep_extended 'Allow this device|Block / Allow|Allow once|Allow/Block' \
    "$KS_FILE" \
    "USBGuard source contains no invented notifier button labels"
assert_grep_fixed 'SECURE-tracks /etc/usbguard and forbids both former control' \
    "$KS_FILE" \
    "retired USBGuard AIDE excludes are described accurately"
assert_not_grep 'IPCAccessControl.d exclude.*Moved' "$KS_FILE" \
    "retired USBGuard AIDE exclude is not described as moved"
assert_grep_fixed 'system-bus API and is masked symmetrically because it Requires=usbguard.service' \
    "$KS_FILE" \
    "usbguard-dbus package verification records its real rationale"
assert_grep_fixed 'if grep -qxF "$setting" /etc/usbguard/usbguard-daemon.conf; then' \
    "$KS_FILE" \
    "daemon verification cannot be satisfied by explanatory comments"

test_finish
