# ============================================================================
# Module 14 — USBGuard
# Status: LOCKED 2026-08-08 (v55) — revalidate recyclable runtime IDs at the final allow boundary.
#
# Covers:
#   - 5 packages: usbguard + -selinux + -tools + -notifier + -dbus (the
#     notifier uses USBGuard's native IPC; -dbus is the separately hardened
#     system D-Bus integration surface)
#   - /etc/usbguard/usbguard-daemon.conf hardened replacement (block
#     default, AuthorizedDefault=none pinned, PresentControllerPolicy=keep,
#     HidePII=true, AuditBackend=LinuxAudit, NO IPCAllowedGroups/Users;
#     named root/user ACLs are the only IPC authorization surface)
#   - rules.conf placeholder (replaced at first boot by generate-policy)
#   - noid-usbguard-firstboot.{sh,service}: state machine uninitialized ->
#     (emergency|initializing|real) -> real; emergency =
#     `allow with-interface 03:*:*`
#     HID-only fallback, auto-replaced when generate-policy succeeds;
#     registers the first user with the minimum notifier-compatible ACL and
#     root with the full administrative ACL; atomically publishes and
#     durably records policy/state before unmasking + enabling
#     usbguard.service and usbguard-dbus.service
#   - noid-usbguard-add-user.{sh,service,path}: /etc/passwd watcher for
#     late-arriving users (gnome-initial-setup creates the user AFTER
#     multi-user.target — the firstboot service alone would miss it);
#     atomically converges named ACLs and removes legacy supplementary
#     usbguard-group membership
#   - usbguard-notifier: static graphical-session ownership + resilience
#     drop-in (`ConditionUser=!@system`, shared persistent-account + exact
#     local `Class=user` logind gate, `PartOf`/`After` graphical-session,
#     active-target `ExecCondition`, `--wait` + Restart=on-failure), plus one
#     graphical-login catch-up that inventories devices blocked before the
#     notifier connected. The static target links supply every login
#     transaction; GDM/GIS/transient managers and obsolete default-target
#     starts condition-skip without notifier IPC.
#   - noid-usbguard-devices manager (durable/runtime inventory, guarded
#     revocation and delegation to the specialized allow workflow) plus the
#     noid-usbguard-allow-device escape-hatch (interactive
#     allow-device --permanent with snapper pre-snapshot; recognized
#     ModeSwitch pairs instead receive two explicitly approved, descriptor-
#     hashed rules without port, parent or connect-type topology) +
#     noid-install-displaylink opt-in installer (negativo17 repo, GPG
#     fingerprint pinned match-or-abort, restricted package namespace,
#     exact DNF rollback/ownership ledger, akmod -> dkms fallback, MOK
#     enrollment guidance)
#   - usbguard.service independently Wants= a bounded-retry cleanup service that
#     removes and rejects GNOME's global wildcard rule after daemon start;
#     M17 masks both gsd-usb-protection activation units
#   - user docs: 14-usbguard.md + docking-stations.md
#
# Deliberate deviations (do NOT re-litigate):
#   - usbguard.service + usbguard-dbus.service are MASKED at build time
#     (not disabled): preset re-evaluation can silently re-enable a
#     disabled unit -> boot-before-policy = full keyboard lockout. The
#     firstboot service unmasks both only after rules.conf is valid;
#     usbguard-dbus is masked symmetrically (Requires=usbguard.service —
#     left unmasked alone it would land in failed state at boot).
#   - firstboot/add-user services keep NNP=false + ProtectSystem=true (not
#     strict): the scripts call systemctl, reconcile /etc/usbguard and may
#     remove legacy distro-managed membership from /etc/group.
#   - The add-user PATH unit carries NO After= ordering: ordering it
#     against usbguard.service created a paths.target <-> basic.target
#     cycle; ordering lives in the triggered .service. A too-early direct
#     helper invocation returns EX_TEMPFAIL, while the firstboot service
#     invokes the same reconciliation after both USBGuard units are verified.
#   - The add-user .service uses Wants= (not Requires=): Requires= on the
#     masked usbguard.service fails the unit at queue time.
#   - AuditFilePath stays in daemon.conf (ignored under LinuxAudit) as a
#     reference for users switching backends.
#
# Constraint notes (keep when editing):
#   - The firstboot device count matches ALL `^allow ` rules — not only
#     `allow id VID:PID` (some hardware yields with-interface or
#     with-connect rules; a narrow regex caused false emergency-mode).
#   - An EMPTY IPCAccessControl.d/<user> file = explicit DENY. Always publish
#     one of the two exact, non-empty ACL profiles by atomic replacement.
#   - `Devices=modify` is required for the upstream notifier's temporary
#     Allow action. USBGuard cannot split temporary from permanent per-device
#     modification, so the supported persistent path remains the audited
#     sudo wrapper while the native CLI limitation is documented honestly.
#   - Root needs its own IPCAccessControl.d entry (root is not in
#     wheel/usbguard) or sudo-based wrappers get IPC-denied.
#   - M13 content-tracks all of /etc/usbguard; legitimate policy/user changes
#     remain visible AIDE drift for the user to review.
#   - M13 ships THE noid-status CLI; M14 only writes usbguard-status.txt
#     (key=value contract: STATE/DEVICE_COUNT/FALLBACK_ACTIVE/LAST_RUN) —
#     order-independent by design.
#
# Cross-reference:
#   - M12: usbguard_config audit watch + LinuxAudit evidence pipeline (verify
#     11.10 hard-checks the rule). Device popups remain M14 notifier-owned;
#     M13: noid-status reads the status file and SECURE-tracks USBGuard controls
#     while forbidding the retired AIDE excludes. M17 masks gsd-usb-protection
#     (Dconf false alone did
#     not prevent its `allow id *:*` injection). M28:
#     the optional M12 popup plugin does not replace USBGuard's own notifier.
# ============================================================================

%packages --exclude-weakdeps
usbguard
usbguard-selinux
usbguard-tools
usbguard-notifier
# usbguard-notifier uses the daemon's native IPC socket. usbguard-dbus is the
# separate, hardened org.usbguard1 system-bus API for explicit D-Bus tooling.
# GNOME's unsafe USB-protection plugin is masked by M17. The service is masked
# at build time; firstboot enables it only after a valid policy is durable.
usbguard-dbus
%end

%post --erroronfail --log=/var/log/ks-14-usbguard.log

set -euo pipefail
echo "=============================================================="
echo "[Module 14] USBGuard"
echo "=============================================================="

# ----------------------------------------------------------------------------
# Step 1: Write hardened /etc/usbguard/usbguard-daemon.conf
# ----------------------------------------------------------------------------
# Complete replacement of Fedora default with host 1:1 + 4 upgrades:
#   - Remove both legacy group/user-wide IPC grants
#   - Use exact named ACLs written by firstboot/user reconciliation
#   - HidePII=true (research: Red Hat + NIST 800-53)
#   - AuditBackend=LinuxAudit (integrate with auditd/Module 12)
#
echo ""
echo "[Step 1] Writing /etc/usbguard/usbguard-daemon.conf"

cat > /etc/usbguard/usbguard-daemon.conf <<'DAEMON_EOF'
# NoID Privacy — USBGuard daemon configuration
# Design rationale captured inline below.
# This file replaces the Fedora default completely.
#
# Based on: Fedora 44 configuration testing + documented upstream behavior (Red Hat RHEL 8.3+,
# NIST 800-53, SCAP Security Guide, Fedora 2025 how-to).

# ----------------------------------------------------------------------------
# Rule files
# ----------------------------------------------------------------------------
RuleFile=/etc/usbguard/rules.conf
RuleFolder=/etc/usbguard/rules.d/

# ----------------------------------------------------------------------------
# Policy enforcement
# ----------------------------------------------------------------------------

# Unknown devices (no matching rule) are BLOCKED.
# Research consensus: `block` is the most secure option.
ImplicitPolicyTarget=block

# At daemon start, apply rules to already-connected devices.
# This ensures policy is enforced even after daemon restart.
PresentDevicePolicy=apply-policy

# USB controllers at daemon start: KEEP existing state (do not deauthorize).
# CRITICAL: `apply-policy` here would deauth controllers on daemon restart,
# killing all downstream devices including keyboard/mouse. `keep` preserves
# the controller authorization state across daemon restarts.
PresentControllerPolicy=keep

# New device insertions after daemon start: apply rules.
InsertedDevicePolicy=apply-policy

# Kernel-side default authorization for NEW devices: deauthorized until a
# rule allows them. `none` is the upstream default in the shipped usbguard
# (1.1.4, man 5 usbguard-daemon.conf) — pinned explicitly so a future
# upstream default change cannot silently widen the insertion window.
AuthorizedDefault=none

# Do NOT restore permissive state on daemon shutdown.
# If true, an attacker could exploit daemon shutdown to bypass policy.
RestoreControllerDeviceState=false

# uevent backend (Fedora default, kernel netlink-based)
DeviceManagerBackend=uevent

# ----------------------------------------------------------------------------
# IPC access control
# ----------------------------------------------------------------------------
# Named files are the sole authorization source. Do not add IPCAllowedGroups
# or IPCAllowedUsers: either would bypass the least-privilege per-user profile.
# Firstboot grants root full administration and normal users only the
# notifier-compatible Devices modify plus list/listen privileges.
IPCAccessControlFiles=/etc/usbguard/IPCAccessControl.d/

# ----------------------------------------------------------------------------
# Rule generation behavior
# ----------------------------------------------------------------------------
# Generated rules do NOT include port numbers (via-port attribute).
# Port numbers are unstable across reboots. Generated rules still retain their
# descriptor hash and USB parent binding; only the separately approved
# ModeSwitch workflow below deliberately removes all topology attributes.
DeviceRulesWithPort=false

# ----------------------------------------------------------------------------
# Audit logging
# ----------------------------------------------------------------------------
# LinuxAudit: integrate with systemd-audit subsystem (/var/log/audit/audit.log)
# instead of separate /var/log/usbguard/usbguard-audit.log.
# This keeps USBGuard records in the same forensic audit stream. M14's
# usbguard-notifier remains the separate user-facing device-notification path.
# Research: Red Hat RHEL hardening guide recommends LinuxAudit.
AuditBackend=LinuxAudit

# AuditFilePath is ignored when AuditBackend=LinuxAudit.
# Kept for reference in case user switches backend.
AuditFilePath=/var/log/usbguard/usbguard-audit.log

# ----------------------------------------------------------------------------
# Privacy
# ----------------------------------------------------------------------------
# HIDE device serial numbers and descriptor hashes from audit entries.
# Research: Red Hat RHEL 8.3+ privacy enhancement, NIST 800-53 compliance,
# SCAP Security Guide for Fedora recommends HidePII=true.
# Default is false — explicitly enabled for privacy-freak target.
HidePII=true
DAEMON_EOF

chmod 600 /etc/usbguard/usbguard-daemon.conf
chown root:root /etc/usbguard/usbguard-daemon.conf
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /etc/usbguard/usbguard-daemon.conf 2>/dev/null || true
fi
echo "  [OK] /etc/usbguard/usbguard-daemon.conf written (600 root:root)"

# ----------------------------------------------------------------------------
# Step 2: Write placeholder /etc/usbguard/rules.conf
# ----------------------------------------------------------------------------
# First-boot service will REPLACE this with generate-policy output
# (or emergency HID fallback if generate-policy fails).
# Empty placeholder prevents usbguard.service from failing if it starts
# before first-boot service runs.
#
echo ""
echo "[Step 2] Writing placeholder /etc/usbguard/rules.conf"

cat > /etc/usbguard/rules.conf <<'RULES_EOF'
# NoID Privacy — Placeholder rules file
# This file will be REPLACED at first boot by noid-usbguard-firstboot.service
# using `usbguard generate-policy` to capture currently connected devices.
#
# Until first-boot initialization completes, this file is empty which means
# (combined with ImplicitPolicyTarget=block) that ALL USB devices will be
# blocked. That's safe because usbguard.service is NOT enabled in this %post
# — only first-boot service enables it after generate-policy writes real rules.
RULES_EOF

chmod 600 /etc/usbguard/rules.conf
chown root:root /etc/usbguard/rules.conf
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /etc/usbguard/rules.conf 2>/dev/null || true
fi
echo "  [OK] placeholder /etc/usbguard/rules.conf written"

# ----------------------------------------------------------------------------
# Step 3: Install noid-usbguard-firstboot.sh
# ----------------------------------------------------------------------------
echo ""
echo "[Step 3] Installing /usr/local/bin/noid-usbguard-firstboot.sh"

cat > /usr/local/bin/noid-usbguard-firstboot.sh <<'FIRSTBOOT_EOF'
#!/bin/bash
# NoID Privacy — USBGuard First-Boot Initialization
# Ships as part of image Module 14.
# Triggered by noid-usbguard-firstboot.service (systemd oneshot).
# State machine: uninitialized → (emergency|initializing|real) → real

set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin

STATE_DIR=/var/lib/noid-privacy
STATE_FILE="${STATE_DIR}/usbguard-state"
STATUS_FILE="${STATE_DIR}/usbguard-status.txt"
RULES_FILE=/etc/usbguard/rules.conf
DAEMON_CONF=/etc/usbguard/usbguard-daemon.conf
IPC_DIR=/etc/usbguard/IPCAccessControl.d
LOG_TAG="noid-usbguard-firstboot"

log() {
    logger -t "$LOG_TAG" "$*"
    echo "[$(date -Iseconds)] $*"
}

selinux_label_ok() {
    local path=$1
    [ ! -f /sys/fs/selinux/enforce ] || \
        matchpathcon -V "$path" >/dev/null 2>&1
}

restore_and_verify_label() {
    local path=$1
    [ ! -f /sys/fs/selinux/enforce ] && return 0
    command -v restorecon >/dev/null 2>&1 && \
        command -v matchpathcon >/dev/null 2>&1 || {
        log "ERROR: SELinux is active but labeling tools are unavailable"
        return 1
    }
    restorecon -F "$path" >/dev/null
    matchpathcon -V "$path" >/dev/null
}

ensure_root_directory() {
    local path=$1 mode=$2
    if [ -L "$path" ] || { [ -e "$path" ] && [ ! -d "$path" ]; }; then
        log "ERROR: $path is not a real directory"
        return 1
    fi
    install -d -m "$mode" -o root -g root "$path"
    [ "$(stat -Lc '%u:%g:%a' "$path" 2>/dev/null || true)" = "0:0:$mode" ] && \
        restore_and_verify_label "$path" || {
        log "ERROR: $path metadata or SELinux label is invalid"
        return 1
    }
}

regular_root_file_ok() {
    local path=$1 mode=$2
    [ -f "$path" ] && [ ! -L "$path" ] && \
        [ "$(stat -Lc '%u:%g:%a:%h' "$path" 2>/dev/null || true)" = "0:0:$mode:1" ] && \
        selinux_label_ok "$path"
}

write_state() {
    local state=$1 tmp
    case "$state" in
        emergency|initializing|real) ;;
        *) log "ERROR: refusing invalid USBGuard durable state"; return 1 ;;
    esac
    ensure_root_directory "$STATE_DIR" 755
    tmp=$(mktemp "${STATE_FILE}.tmp.XXXXXX")
    if ! {
        printf '%s\n' "$state" > "$tmp" &&
        chmod 0644 "$tmp" &&
        chown root:root "$tmp" &&
        restore_and_verify_label "$tmp" &&
        sync -- "$tmp" &&
        mv -fT -- "$tmp" "$STATE_FILE" &&
        restore_and_verify_label "$STATE_FILE" &&
        sync -- "$STATE_FILE" &&
        sync -f "$STATE_DIR" &&
        regular_root_file_ok "$STATE_FILE" 644 &&
        cmp -s "$STATE_FILE" <(printf '%s\n' "$state")
    }; then
        rm -f -- "$tmp"
        log "ERROR: failed to publish USBGuard durable state atomically"
        return 1
    fi
}

write_status() {
    local state="$1"
    local count="$2"
    local fallback="$3"
    local timestamp tmp
    case "$state" in
        real|emergency|initializing) ;;
        *) log "ERROR: refusing invalid USBGuard status state"; return 1 ;;
    esac
    case "$count" in
        ''|*[!0-9]*) log "ERROR: refusing invalid USBGuard device count"; return 1 ;;
    esac
    case "$fallback" in
        yes|no) ;;
        *) log "ERROR: refusing invalid USBGuard fallback state"; return 1 ;;
    esac
    timestamp=$(date -Iseconds)
    ensure_root_directory "$STATE_DIR" 755
    tmp=$(mktemp "${STATUS_FILE}.tmp.XXXXXX")
    if ! {
        printf 'STATE=%s\nDEVICE_COUNT=%s\nFALLBACK_ACTIVE=%s\nLAST_RUN=%s\n' \
            "$state" "$count" "$fallback" "$timestamp" > "$tmp" &&
        chmod 0644 "$tmp" &&
        chown root:root "$tmp" &&
        restore_and_verify_label "$tmp" &&
        sync -- "$tmp" &&
        mv -fT -- "$tmp" "$STATUS_FILE" &&
        restore_and_verify_label "$STATUS_FILE" &&
        sync -- "$STATUS_FILE" &&
        sync -f "$STATE_DIR" &&
        regular_root_file_ok "$STATUS_FILE" 644 &&
        cmp -s "$STATUS_FILE" <(
            printf 'STATE=%s\nDEVICE_COUNT=%s\nFALLBACK_ACTIVE=%s\nLAST_RUN=%s\n' \
                "$state" "$count" "$fallback" "$timestamp"
        )
    }; then
        rm -f -- "$tmp"
        log "ERROR: failed to publish USBGuard status atomically"
        return 1
    fi
}

policy_rule_count() {
    grep -cE '^[[:space:]]*(allow|block|reject|match)[[:space:]]' "$1" \
        2>/dev/null || true
}

policy_allow_count() {
    grep -cE '^[[:space:]]*allow[[:space:]]' "$1" 2>/dev/null || true
}

policy_file_ok() {
    local path=$1
    regular_root_file_ok "$path" 600 && \
        [ "$(policy_rule_count "$path")" -gt 0 ] && \
        timeout --signal=TERM --kill-after=1s 10s \
            usbguard-rule-parser -f "$path" >/dev/null 2>&1
}

publish_policy_candidate() {
    local candidate=$1
    chmod 0600 "$candidate"
    chown root:root "$candidate"
    restore_and_verify_label "$candidate"
    [ "$(policy_rule_count "$candidate")" -gt 0 ] && \
        timeout --signal=TERM --kill-after=1s 10s \
            usbguard-rule-parser -f "$candidate" >/dev/null 2>&1 || {
        log "ERROR: refusing invalid USBGuard policy candidate"
        return 1
    }
    sync -- "$candidate"
    mv -fT -- "$candidate" "$RULES_FILE"
    restore_and_verify_label "$RULES_FILE"
    sync -- "$RULES_FILE"
    sync -f /etc/usbguard
    policy_file_ok "$RULES_FILE" || {
        log "ERROR: published USBGuard policy failed its postcondition"
        return 1
    }
}

write_emergency_policy() {
    local tmp_policy noncomment_count
    tmp_policy=$(mktemp /etc/usbguard/.rules.conf.emergency.XXXXXX)
    cat > "$tmp_policy" <<'EMERGENCY_RULES'
# NoID Privacy — Emergency HID Fallback (auto-generated)
# This file is replaced when full present-device policy generation succeeds.
allow with-interface 03:*:*
EMERGENCY_RULES
    noncomment_count=$(grep -cEv '^[[:space:]]*(#|$)' "$tmp_policy" 2>/dev/null || true)
    if [ "$noncomment_count" != "1" ] || \
       ! grep -qxF 'allow with-interface 03:*:*' "$tmp_policy"; then
        rm -f -- "$tmp_policy"
        log "ERROR: generated emergency USB policy failed its bounded-policy postcondition"
        return 1
    fi
    if ! publish_policy_candidate "$tmp_policy"; then
        rm -f -- "$tmp_policy"
        return 1
    fi
}

# Step 1: Check current state
ensure_root_directory "$STATE_DIR" 755

# usbguard-daemon refuses a configuration that is readable outside root. Keep
# this as a validation boundary, not an automatic chmod: metadata drift can
# accompany content drift and must not be silently promoted into trusted
# daemon input. The image writer and finalizer both enforce the same contract.
if ! regular_root_file_ok "$DAEMON_CONF" 600; then
    log "ERROR: USBGuard daemon configuration is not root:root 0600 with a valid SELinux label"
    exit 1
fi

CURRENT_STATE="uninitialized"
if [ -e "$STATE_FILE" ] || [ -L "$STATE_FILE" ]; then
    if ! regular_root_file_ok "$STATE_FILE" 644 || \
       [ "$(wc -l < "$STATE_FILE")" -ne 1 ]; then
        log "ERROR: USBGuard durable state has unsafe metadata or schema"
        exit 1
    fi
    CURRENT_STATE=$(<"$STATE_FILE")
    case "$CURRENT_STATE" in
        emergency|initializing|real) ;;
        *)
            log "ERROR: refusing unknown USBGuard durable state"
            exit 1
            ;;
    esac
fi

SKIP_POLICY_REFRESH=0
PENDING_REAL=0
REAL_DEVICES_FOUND=0

log "Current state: $CURRENT_STATE"

if [ "$CURRENT_STATE" = "real" ] || [ "$CURRENT_STATE" = "initializing" ]; then
    # Never re-learn a completed allowlist on later boots: an attacker could
    # otherwise have a newly attached device absorbed into the trusted policy.
    # Continue through service enforcement so a failed/disabled daemon is
    # repaired instead of being hidden behind the state marker.
    if ! policy_file_ok "$RULES_FILE"; then
        log "ERROR: committed USBGuard state has no valid policy; refusing automatic re-learning"
        exit 1
    fi
    SKIP_POLICY_REFRESH=1
    REAL_DEVICES_FOUND=$(policy_allow_count "$RULES_FILE")
    if [ "$CURRENT_STATE" = "initializing" ]; then
        PENDING_REAL=1
        log "Resuming activation of the already-published policy without re-learning devices"
    else
        log "Real allowlist already initialized — retaining policy and re-enforcing service state"
    fi
fi

# Step 2: Ensure directories with correct SELinux context
ensure_root_directory /etc/usbguard 755
ensure_root_directory /var/log/usbguard 755

# Step 3: Try usbguard generate-policy
GENERATE_SUCCESS=0
TMPRULES=""

cleanup_tmp_rules() {
    if [ -n "$TMPRULES" ]; then
        rm -f -- "$TMPRULES"
    fi
}
trap cleanup_tmp_rules EXIT HUP INT TERM

if [ "$SKIP_POLICY_REFRESH" -eq 0 ]; then
    log "Running usbguard generate-policy"
    TMPRULES=$(mktemp /etc/usbguard/.rules.conf.generated.XXXXXX)

    if timeout --signal=TERM --kill-after=1s 30s \
            usbguard generate-policy > "$TMPRULES" 2>/dev/null; then
        if [ -s "$TMPRULES" ]; then
            # Count ALL allow rules, not just the strict
            # `allow id <VID>:<PID>` form. usbguard generate-policy may output
            # `allow with-interface ...` or `allow with-connect-type ...` for some
            # hardware (e.g. devices without VID:PID descriptors); previous regex
            # missed those and triggered emergency-mode unnecessarily.
            # grep -c prints 0 while returning 1 on no match; the fallback is
            # explicit and the value is validated below.
            DEVICE_COUNT=$(grep -cE '^allow[[:space:]]' "$TMPRULES" 2>/dev/null) || DEVICE_COUNT=0
            if [ "$DEVICE_COUNT" -gt 0 ]; then
                GENERATE_SUCCESS=1
                REAL_DEVICES_FOUND=$DEVICE_COUNT
                log "generate-policy success: $DEVICE_COUNT device rules generated"
            else
                log "generate-policy produced output but no device rules — treating as failure"
            fi
        else
            log "generate-policy produced empty output — treating as failure"
        fi
    else
        log "generate-policy command failed"
    fi
fi

# Step 4: Write rules.conf based on result
if [ "$SKIP_POLICY_REFRESH" -eq 1 ]; then
    log "Keeping existing real rules.conf unchanged"
elif [ "$GENERATE_SUCCESS" = "1" ]; then
    publish_policy_candidate "$TMPRULES"
    TMPRULES=""
    # Record the durable transient commit marker immediately after policy
    # publication. Once this marker is durable, any interruption before
    # service verification resumes the exact policy without re-learning.
    write_state "initializing"
    PENDING_REAL=1
    write_status "initializing" "$REAL_DEVICES_FOUND" "no"
    log "Real policy ready; state commit deferred until service verification"
else
    log "Rebuilding bounded emergency HID fallback policy"
    write_emergency_policy
    write_state "emergency"
    write_status "emergency" "0" "yes"
    if [ "$CURRENT_STATE" = "uninitialized" ]; then
        log "State transition: uninitialized -> emergency (HID fallback active)"
    else
        log "Emergency policy integrity restored -- full generation retries next boot"
    fi
fi

if [ -n "$TMPRULES" ]; then
    rm -f -- "$TMPRULES"
    TMPRULES=""
fi

# Step 5: Group/user-wide IPC authorization must stay absent. Named files are
# the only accepted authorization source; continuing with either legacy line
# would silently bypass the least-privilege profiles below.
if grep -Eq '^[[:space:]]*(IPCAllowedGroups|IPCAllowedUsers)[[:space:]]*=' \
        "$DAEMON_CONF"; then
    log "ERROR: broad USBGuard IPC authorization is present"
    exit 1
fi
log "Named USBGuard IPC authorization verified as the sole access path"

# Step 6: Publish the first normal-user ACL and root administrative ACL.
# `Devices=modify` is the smallest upstream privilege that preserves the
# notifier's temporary Allow button. Policy and parameter modification remain
# root-only. USBGuard has no separate temporary/permanent device privilege, so
# the native CLI limitation is documented and the recommended persistent path
# remains `sudo noid-usbguard-devices allow` (which delegates to the reviewed
# noid-usbguard-allow-device admission backend).
emit_ipc_profile() {
    case "$1" in
        user)
            printf '%s\n' \
                'Devices=list,modify,listen' \
                'Policy=list' \
                'Parameters=list,listen' \
                'Exceptions=listen'
            ;;
        root)
            printf '%s\n' \
                'Devices=list,modify,listen' \
                'Policy=list,modify' \
                'Parameters=list,modify,listen' \
                'Exceptions=listen'
            ;;
        *)
            return 1
            ;;
    esac
}

ipc_file_matches() {
    local target="$1"
    local profile="$2"
    [ -f "$target" ] && [ ! -L "$target" ] && \
        [ "$(stat -Lc '%u:%g:%a:%h' "$target" 2>/dev/null || true)" = 0:0:600:1 ] && \
        selinux_label_ok "$target" && \
        cmp -s "$target" <(emit_ipc_profile "$profile")
}

write_ipc_file() {
    local user="$1"
    local profile="$2"
    local target tmp

    [[ $user =~ ^[A-Za-z0-9._-]+$ ]] || {
        log "ERROR: refusing unsafe USBGuard IPC identity"
        return 1
    }
    ensure_root_directory "$IPC_DIR" 755

    target="$IPC_DIR/$user"
    if ipc_file_matches "$target" "$profile"; then
        return 0
    fi

    tmp=$(mktemp "$IPC_DIR/.noid-ipc.XXXXXX") || return 1
    if ! emit_ipc_profile "$profile" > "$tmp" || \
       ! chmod 0600 "$tmp" || ! chown root:root "$tmp"; then
        rm -f -- "$tmp"
        return 1
    fi
    if ! restore_and_verify_label "$tmp"; then
        rm -f -- "$tmp"
        return 1
    fi
    if ! sync -- "$tmp" || ! mv -fT -- "$tmp" "$target" || \
       ! restore_and_verify_label "$target" || ! sync -- "$target" || \
       ! sync -f "$IPC_DIR" || ! ipc_file_matches "$target" "$profile"; then
        rm -f -- "$tmp"
        return 1
    fi
}

FIRST_USER=""
while IFS=: read -r candidate_user _ candidate_uid _ _ _ _; do
    if /usr/libexec/noid-eligible-user account-uid "$candidate_uid"; then
        FIRST_USER=$candidate_user
        break
    fi
done < <(getent passwd)

if [ -n "$FIRST_USER" ]; then
    # NOTE: HidePII=true (daemon config) only hides device serials +
    # descriptor hashes from audit-log, NOT user identifiers in
    # IPCAccessControl.d/<user>. The log line just avoids leaking the
    # username to journal — defense-in-depth, not parity.
    log "Found first non-system user for usbguard IPC registration"
    write_ipc_file "$FIRST_USER" user
    log "Installed minimum notifier-compatible IPC profile for one user"
else
    log "No non-system user found yet -- deferring named IPC registration"
fi

# Step 6b: Root IPC file — required for `sudo noid-usbguard-devices`, its
# noid-usbguard-allow-device admission backend, and daemon administration.
# Root gets the full profile; normal users never do.
log "Granting root full IPC access for sudo-based USBGuard management"
write_ipc_file root root
log "Installed full root-only USBGuard IPC profile"

# Step 7: Publish both USBGuard units to PID 1, then start them
# Module 14 kickstart masks usbguard.service to prevent boot-before-policy
# race (placeholder rules.conf → keyboard lockout). Here at first-boot,
# generate-policy has run successfully (state=real) or emergency fallback
# is in place (state=emergency) — either way rules.conf is now valid, so
# we can safely unmask and enable both service surfaces. Keep the unit-file
# transaction together and explicitly reload PID 1 once before either start:
# on Live media usbguard.service can wait for basic.target while this early
# oneshot is running. Unmasking usbguard-dbus.service only after that wait
# races the already-running target transaction and leaves `systemctl start`
# observing a stale loaded unit even after enable's implicit reload.
if ! systemctl --no-reload unmask \
        usbguard.service usbguard-dbus.service; then
    log "ERROR: failed to unmask USBGuard service units"
    exit 1
fi
if ! systemctl --no-reload enable \
        usbguard.service usbguard-dbus.service; then
    log "ERROR: failed to enable USBGuard service units"
    exit 1
fi
if ! systemctl daemon-reload; then
    log "ERROR: failed to publish USBGuard service units to systemd"
    exit 1
fi

if ! systemctl is-active --quiet usbguard.service; then
    log "Starting usbguard.service"
    if ! systemctl start usbguard.service; then
        log "ERROR: failed to start usbguard.service"
        exit 1
    fi
else
    log "usbguard.service already running -- restarting"
    if ! systemctl restart usbguard.service; then
        log "ERROR: failed to restart usbguard.service"
        exit 1
    fi
fi

# Start the separately hardened system D-Bus front-end for
# explicit integration clients. usbguard-notifier uses the daemon's native IPC
# and does not depend on this service; M17 masks GNOME's unsafe wildcard-rule
# producer. The D-Bus unit is nevertheless masked at build time alongside the
# daemon to avoid a boot-before-policy dependency failure. It was published
# together with usbguard.service above, before the first daemon start could
# block on basic.target.
if ! systemctl is-active --quiet usbguard-dbus.service; then
    log "Starting usbguard-dbus.service"
    if ! systemctl start usbguard-dbus.service; then
        log "ERROR: failed to start usbguard-dbus.service"
        exit 1
    fi
else
    log "usbguard-dbus.service already running -- restarting"
    if ! systemctl restart usbguard-dbus.service; then
        log "ERROR: failed to restart usbguard-dbus.service"
        exit 1
    fi
fi

if ! systemctl is-enabled --quiet usbguard.service || \
   ! systemctl is-active --quiet usbguard.service || \
   ! systemctl is-enabled --quiet usbguard-dbus.service || \
   ! systemctl is-active --quiet usbguard-dbus.service; then
    log "ERROR: USBGuard service verification failed; state remains retryable"
    exit 1
fi

# Close the passwd-watcher readiness race. A path event can be consumed while
# firstboot is still establishing the daemon. The path-triggered service is
# ordered after this unit, but a failed firstboot must remain retryable; once
# the daemon is confirmed, reconcile every current regular user here as the
# authoritative daemon-ready trigger. Future /etc/passwd changes remain owned
# by noid-usbguard-add-user.path.
if [ ! -x /usr/local/bin/noid-usbguard-add-user.sh ] || \
   ! /usr/local/bin/noid-usbguard-add-user.sh; then
    log "ERROR: daemon-ready USBGuard user/IPC reconciliation failed"
    exit 1
fi

if [ "$PENDING_REAL" -eq 1 ]; then
    write_state "real"
    write_status "real" "$REAL_DEVICES_FOUND" "no"
    log "State transition: $CURRENT_STATE -> real ($REAL_DEVICES_FOUND devices)"
elif [ "$CURRENT_STATE" = "real" ]; then
    write_status "real" "$REAL_DEVICES_FOUND" "no"
fi

FINAL_STATE=$(<"$STATE_FILE")
log "First-boot initialization complete (state: $FINAL_STATE)"
exit 0
FIRSTBOOT_EOF

chmod 755 /usr/local/bin/noid-usbguard-firstboot.sh
chown root:root /usr/local/bin/noid-usbguard-firstboot.sh
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/local/bin/noid-usbguard-firstboot.sh 2>/dev/null || true
fi
echo "  [OK] /usr/local/bin/noid-usbguard-firstboot.sh installed (755)"

# ----------------------------------------------------------------------------
# Step 4: Install noid-usbguard-firstboot.service systemd unit
# ----------------------------------------------------------------------------
echo ""
echo "[Step 4] Installing noid-usbguard-firstboot.service"

cat > /etc/systemd/system/noid-usbguard-firstboot.service <<'FIRSTBOOT_SERVICE_EOF'
[Unit]
Description=NoID Privacy USBGuard first-boot initialization
Documentation=file:///usr/share/doc/noid-privacy/14-usbguard.md
Requires=noid-anaconda-cleanup.service
After=local-fs.target noid-anaconda-cleanup.service
Before=multi-user.target graphical.target
ConditionFileIsExecutable=/usr/local/bin/noid-usbguard-firstboot.sh
# Skip in live-ISO mode. USBGuard rule learning and persistent
# named per-user ACL publication are meaningful only on the installed system.
ConditionKernelCommandLine=!rd.live.image
# usbguard.service is not enabled at install time (Module 14 Step 6 ensures
# this); this service explicitly enables and starts it. Ordering this oneshot
# before both login targets closes the installed-system admission window while
# devices enumerated later are still fail-closed by AuthorizedDefault=none.
# Runs on every boot; once the state file contains `initializing` or `real`,
# policy generation is skipped — SELinux/IPC/user reconciliation and unit
# enablement still run against the already-published policy.

[Service]
Type=oneshot
RemainAfterExit=no
ExecStart=/usr/local/bin/noid-usbguard-firstboot.sh
StandardOutput=journal
StandardError=journal

# Security hardening — 2026 baseline.
# NOTE: ProtectSystem=true (not strict) — script needs to write to:
#   /etc/usbguard/*                                   — daemon config + rules
#   /etc/usbguard/IPCAccessControl.d/*                — per-user IPC access
#   /etc/systemd/system/multi-user.target.wants/*     — systemctl enable symlink
#   /etc/group, /etc/gshadow, /etc/group-, /etc/gshadow- — legacy group cleanup
# ProtectSystem=strict would make /etc read-only → all these writes fail.
# ProtectSystem=true leaves /etc writable, only /usr /boot /efi are RO which
# we don't touch. /var/lib/noid-privacy + /var/log/usbguard are writable too.
ProtectSystem=true
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=false
# NoNewPrivileges=false because script calls systemctl + usbguard (privileged)
#
# Service-specific sandbox expansion (+10 directives):
# All 10 directives are orthogonal to NNP=false + ProtectSystem=true intent
# and don't affect the script's privileged operations (systemctl, USBGuard
# IPC-file reconciliation, getent, install and legacy group cleanup). Service
# runs once per boot until state=real.
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
# MemoryDenyWriteExecute: bash + usbguard binary, no JIT compilers — safe.
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
# IPAddressDeny=any — script doesn't network (all local: write_status,
# generate-policy, named ACL publication, systemctl, local file operations).
IPAddressDeny=any

[Install]
WantedBy=multi-user.target
FIRSTBOOT_SERVICE_EOF

chmod 644 /etc/systemd/system/noid-usbguard-firstboot.service
chown root:root /etc/systemd/system/noid-usbguard-firstboot.service
restorecon -F /etc/systemd/system/noid-usbguard-firstboot.service 2>/dev/null || true
echo "  [OK] /etc/systemd/system/noid-usbguard-firstboot.service installed (644)"

# Live-media initializer: learn only devices already present at boot, then
# start implicit-block before the graphical session. The live overlay is
# intentionally disposable; installed systems use the separate firstboot unit
# above. This closes the hotplug window without persisting live-device IDs.
cat > /etc/systemd/system/noid-usbguard-live-init.service <<'USB_LIVE_SERVICE_EOF'
[Unit]
Description=NoID Privacy USBGuard live-media pre-session initialization
Documentation=file:///usr/share/doc/noid-privacy/14-usbguard.md
DefaultDependencies=no
# systemd-udev-settle is deprecated (freedesktop) and, because Wants= pulls a
# dependency into the transaction regardless of the requesting unit's own
# Condition* result, it runs even on installed systems where this unit's
# rd.live.image condition is unmet — a ~5s boot penalty for a service that is
# skipped there. USBGuard's daemon handles hotplug (implicit-block = fail-closed),
# so devices not yet enumerated at learn-time are blocked, not allowed; a full
# coldplug settle is unnecessary.
After=local-fs.target
Before=multi-user.target graphical.target
Wants=local-fs.target
ConditionKernelCommandLine=rd.live.image
ConditionFileIsExecutable=/usr/local/bin/noid-usbguard-firstboot.sh

[Service]
Type=oneshot
ExecStart=/usr/local/bin/noid-usbguard-firstboot.sh
RemainAfterExit=yes
ProtectSystem=true
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=false
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
IPAddressDeny=any

[Install]
WantedBy=multi-user.target
USB_LIVE_SERVICE_EOF
chmod 0644 /etc/systemd/system/noid-usbguard-live-init.service
chown root:root /etc/systemd/system/noid-usbguard-live-init.service
restorecon -F /etc/systemd/system/noid-usbguard-live-init.service 2>/dev/null || true
echo "  [OK] live-media pre-session USBGuard initializer installed"

# ----------------------------------------------------------------------------
# Step 5: Enable noid-usbguard-firstboot.service
# ----------------------------------------------------------------------------
# Enable via wantedby symlink in multi-user.target.wants.
# The service runs on every boot; once state is `initializing` or `real`, only
# policy generation is skipped (the rest of the sequence still runs).
echo ""
echo "[Step 5] Enabling noid-usbguard-firstboot.service"

systemctl enable noid-usbguard-firstboot.service noid-usbguard-live-init.service

if [ -L /etc/systemd/system/multi-user.target.wants/noid-usbguard-firstboot.service ]; then
    echo "  [OK] noid-usbguard-firstboot.service enabled"
else
    echo "  [FAIL] Service not enabled (symlink missing)"
    exit 1
fi
if [ ! -L /etc/systemd/system/multi-user.target.wants/noid-usbguard-live-init.service ]; then
    echo "  [FAIL] Live USBGuard initializer not enabled"
    exit 1
fi

# ----------------------------------------------------------------------------
# Step 6: MASK usbguard.service (first-boot service unmasks + enables)
# ----------------------------------------------------------------------------
# IMPORTANT: usbguard.service must NOT auto-start before first-boot service
# runs generate-policy. If it starts with placeholder rules.conf + no user
# IPC access, it would block ALL USB devices including keyboard → LOCKOUT.
#
# We MASK instead of disable because:
#   - disable is REVERSIBLE by systemctl preset re-evaluation (daemon-reload
#     after preset change, dnf upgrade usbguard, etc.) → dangerous race
#   - mask is IRREVERSIBLE except via explicit systemctl unmask
#   - first-boot service explicitly unmasks before enable+start in Step 7
#     (after generate-policy has written real rules.conf)
#
# If upstream Fedora package ships usbguard.service enabled by default, mask
# creates symlink /etc/systemd/system/usbguard.service → /dev/null which
# OVERRIDES the package-level enable. Preset re-evaluation cannot undo a mask.
echo ""
echo "[Step 6] Masking usbguard.service (first-boot service will unmask + start)"

if ! systemctl mask usbguard.service; then
    echo "  [WARN] systemctl mask failed; verifying/falling back to explicit symlink"
fi

if [ -L /etc/systemd/system/usbguard.service ] && \
   [ "$(readlink /etc/systemd/system/usbguard.service)" = "/dev/null" ]; then
    echo "  [OK] usbguard.service masked"
else
    echo "  [WARN] usbguard.service mask symlink not found (chroot fallback)"
    # Defensive fallback: manually create the mask symlink
    ln -sf /dev/null /etc/systemd/system/usbguard.service
    echo "  [OK] usbguard.service manually masked via ln -sf"
fi

# INVEST-2 fix: also mask usbguard-dbus.service symmetrically.
# usbguard-dbus.service has Requires=usbguard.service (per upstream unit).
# If left unmasked while usbguard.service is masked, systemd would try to
# start it at boot, fail because of the masked dep, and leave it in
# failed state. The firstboot script unmasks BOTH together after policy
# is in place.
if ! systemctl mask usbguard-dbus.service; then
    echo "  [WARN] systemctl mask failed; verifying/falling back to explicit symlink"
fi
if [ -L /etc/systemd/system/usbguard-dbus.service ] && \
   [ "$(readlink /etc/systemd/system/usbguard-dbus.service)" = "/dev/null" ]; then
    echo "  [OK] usbguard-dbus.service masked"
else
    ln -sf /dev/null /etc/systemd/system/usbguard-dbus.service
    echo "  [OK] usbguard-dbus.service manually masked via ln -sf"
fi

# ----------------------------------------------------------------------------
# Step 7: Install systemd-user-preset for usbguard-notifier
# ----------------------------------------------------------------------------
# The notifier is a static dependency of graphical-session.target below. Mark
# it `ignore` in preset policy so package/user-manager preset passes neither
# create the upstream default.target link nor remove the distro-owned static
# graphical link. Existing default-target links remain harmless: the active-
# graphical-target ExecCondition skips the early attempt, then the static
# graphical-session dependency starts the unit when the session is real.
# Eligible users receive an exact named, notifier-compatible IPC file from
# firstboot/passwd reconciliation; no broad supplementary group is required.
echo ""
echo "[Step 7] Installing systemd user preset for usbguard-notifier"

mkdir -p /etc/systemd/user-preset

cat > /etc/systemd/user-preset/50-noid-usbguard.preset <<'PRESET_EOF'
# NoID Privacy — USBGuard desktop notifier has static graphical ownership
# Notifier displays interactive Allow/Reject notifications when USB devices
# are connected and blocked. Named IPC access is reconciled by
# noid-usbguard-firstboot.service.
ignore usbguard-notifier.service
PRESET_EOF

chmod 644 /etc/systemd/user-preset/50-noid-usbguard.preset
chown root:root /etc/systemd/user-preset/50-noid-usbguard.preset
restorecon -F /etc/systemd/user-preset/50-noid-usbguard.preset 2>/dev/null || true
echo "  [OK] /etc/systemd/user-preset/50-noid-usbguard.preset installed"

# ----------------------------------------------------------------------------
# Step 7b: /etc/passwd watcher → exact named USBGuard IPC
# ----------------------------------------------------------------------------
# gnome-initial-setup creates the user AFTER multi-user.target, so the
# firstboot service alone can miss it (no named ACL → notifier IPC denied).
# The path-unit watches /etc/passwd and triggers an idempotent oneshot that
# atomically converges exact ACLs and removes legacy supplementary usbguard
# membership before reloading the daemon when ACL bytes changed.
echo ""
echo "[Step 7b] Installing /etc/passwd watcher → usbguard-add-user"

cat > /usr/local/bin/noid-usbguard-add-user.sh <<'ADD_USER_EOF'
#!/bin/bash
# NoID Privacy — reconcile least-privilege named USBGuard IPC.
# Triggered by noid-usbguard-add-user.path on /etc/passwd change.
# Idempotent: exact files and already-clean group membership are no-op.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin

LOG_TAG="noid-usbguard-add-user"
log() { logger -t "$LOG_TAG" "$*"; echo "[$(date -Iseconds)] $*"; }

LOCK_FILE=/run/noid-privacy/usbguard-add-user.lock
if [ -L "$LOCK_FILE" ] || { [ -e "$LOCK_FILE" ] && [ ! -f "$LOCK_FILE" ]; }; then
    log "USBGuard reconciliation lock path is unsafe"
    exit 1
fi
if [ ! -e "$LOCK_FILE" ]; then
    install -m 0600 -o root -g root /dev/null "$LOCK_FILE"
fi
if [ "$(stat -Lc '%u:%g:%a:%h' "$LOCK_FILE" 2>/dev/null || true)" != 0:0:600:1 ]; then
    log "USBGuard reconciliation lock metadata is unsafe"
    exit 1
fi
if [ -f /sys/fs/selinux/enforce ]; then
    restorecon -F "$LOCK_FILE" >/dev/null && \
        matchpathcon -V "$LOCK_FILE" >/dev/null || {
        log "USBGuard reconciliation lock SELinux label is unsafe"
        exit 1
    }
fi
exec 9<>"$LOCK_FILE"
if ! flock -w 30 9; then
    log "another USBGuard reconciliation did not finish within 30 seconds"
    exit 75
fi

# A direct/path invocation before daemon readiness is not a successful
# reconciliation. Firstboot invokes this helper again after verifying both
# USBGuard units, so return EX_TEMPFAIL and leave the state honestly retryable.
if ! systemctl is-active --quiet usbguard.service; then
    log "usbguard.service not active — reconciliation deferred to firstboot"
    exit 75
fi

IPC_DIR=/etc/usbguard/IPCAccessControl.d
ipc_changed=0
declare -A expected_ipc_profiles=([root]=root)

selinux_label_ok() {
    local path=$1
    [ ! -f /sys/fs/selinux/enforce ] || \
        matchpathcon -V "$path" >/dev/null 2>&1
}

restore_and_verify_label() {
    local path=$1
    [ ! -f /sys/fs/selinux/enforce ] && return 0
    command -v restorecon >/dev/null 2>&1 && \
        command -v matchpathcon >/dev/null 2>&1 && \
        restorecon -F "$path" >/dev/null && \
        matchpathcon -V "$path" >/dev/null
}

ensure_ipc_directory() {
    if [ -L "$IPC_DIR" ] || { [ -e "$IPC_DIR" ] && [ ! -d "$IPC_DIR" ]; }; then
        log "USBGuard IPC directory is not a real directory"
        return 1
    fi
    install -d -o root -g root -m 0755 "$IPC_DIR"
    [ "$(stat -Lc '%u:%g:%a' "$IPC_DIR" 2>/dev/null || true)" = 0:0:755 ] && \
        restore_and_verify_label "$IPC_DIR" || {
        log "USBGuard IPC directory metadata or label is invalid"
        return 1
    }
}

emit_ipc_profile() {
    case "$1" in
        user)
            printf '%s\n' \
                'Devices=list,modify,listen' \
                'Policy=list' \
                'Parameters=list,listen' \
                'Exceptions=listen'
            ;;
        root)
            printf '%s\n' \
                'Devices=list,modify,listen' \
                'Policy=list,modify' \
                'Parameters=list,modify,listen' \
                'Exceptions=listen'
            ;;
        *)
            return 1
            ;;
    esac
}

ipc_file_matches() {
    local target="$1"
    local profile="$2"
    [ -f "$target" ] && [ ! -L "$target" ] && \
        [ "$(stat -Lc '%u:%g:%a:%h' "$target" 2>/dev/null || true)" = 0:0:600:1 ] && \
        selinux_label_ok "$target" && \
        cmp -s "$target" <(emit_ipc_profile "$profile")
}

write_ipc_file() {
    local username="$1"
    local profile="$2"
    local target tmp

    [[ $username =~ ^[A-Za-z0-9._-]+$ ]] || {
        log "Refusing unsafe USBGuard IPC identity"
        return 1
    }
    ensure_ipc_directory

    target="$IPC_DIR/$username"
    if ipc_file_matches "$target" "$profile"; then
        return 0
    fi

    tmp=$(mktemp "$IPC_DIR/.noid-ipc.XXXXXX") || return 1
    if ! emit_ipc_profile "$profile" > "$tmp" || \
       ! chmod 0600 "$tmp" || ! chown root:root "$tmp"; then
        rm -f -- "$tmp"
        return 1
    fi
    if ! restore_and_verify_label "$tmp"; then
        rm -f -- "$tmp"
        return 1
    fi
    if ! sync -- "$tmp" || ! mv -fT -- "$tmp" "$target" || \
       ! restore_and_verify_label "$target" || ! sync -- "$target" || \
       ! sync -f "$IPC_DIR" || ! ipc_file_matches "$target" "$profile"; then
        rm -f -- "$tmp"
        return 1
    fi
    ipc_changed=1
    log "Reconciled one named USBGuard IPC profile"
}

live_identity_is_expected() {
    [ -e /run/livesys ] || [ -e /run/initramfs/live ] || \
        grep -Eq '(^|[[:space:]])rd\.live\.image(=1)?([[:space:]]|$)' \
            /proc/cmdline
}

prune_stale_ipc_files() {
    local target identity

    ensure_ipc_directory
    while IFS= read -r -d '' target; do
        identity=${target##*/}
        if [[ ${expected_ipc_profiles[$identity]+present} ]]; then
            ipc_file_matches "$target" \
                "${expected_ipc_profiles[$identity]}" || {
                log "Expected USBGuard IPC profile failed final validation"
                return 1
            }
            continue
        fi

        # Delete only the exact least-privilege profile emitted by this
        # module. Unknown bytes, links, unusual inodes, labels or metadata may
        # be administrator-owned or tampered state and therefore fail closed.
        if ! ipc_file_matches "$target" user; then
            log "Preserving unexplained USBGuard IPC state for review"
            return 1
        fi
        rm -f -- "$target"
        if [ -e "$target" ] || [ -L "$target" ]; then
            log "Stale USBGuard IPC profile remains after exact cleanup"
            return 1
        fi
        ipc_changed=1
        log "Retired one stale named USBGuard IPC profile"
    done < <(find -P "$IPC_DIR" -xdev -mindepth 1 -maxdepth 1 -print0)
    sync -f "$IPC_DIR"
}

# Root owns policy/parameter administration and the supported permanent wrapper.
write_ipc_file root root

while IFS=: read -r username _ uid _ _ home shell; do
    # M08's root-owned account gate uses login.defs UID_MIN/UID_MAX plus the
    # canonical /home/<name> NSS record and a usable shell. This excludes
    # gdm-greeter, GNOME Initial Setup, DynamicUser and transient identities
    # even when their UID is numerically high, while this root service retains
    # ProtectHome=true instead of opening user data merely to classify it.
    /usr/libexec/noid-eligible-user account-uid "$uid" || continue
    # `liveuser` is eligible only on actual Live media. M41 removes it and its
    # exact ACL from an installed target before this service is allowed to run.
    if [ "$username" = liveuser ] && ! live_identity_is_expected; then
        continue
    fi
    [[ $username =~ ^[A-Za-z0-9._-]+$ ]] || {
        log "Refusing unsafe eligible USBGuard IPC identity"
        exit 1
    }
    expected_ipc_profiles["$username"]=user

    # Broad group authorization was retired. Remove only legacy
    # distro-managed supplementary membership; the package-owned group itself
    # remains intact for compatibility.
    if getent group usbguard >/dev/null 2>&1 && \
       id -nG "$username" 2>/dev/null | tr ' ' '\n' | grep -qx usbguard; then
        /usr/bin/gpasswd -d "$username" usbguard >/dev/null
        if id -nG "$username" 2>/dev/null | tr ' ' '\n' | grep -qx usbguard; then
            log "ERROR: legacy broad USBGuard group grant remains after removal"
            exit 1
        fi
        log "Removed one legacy broad USBGuard group grant"
    fi

    write_ipc_file "$username" user
done < /etc/passwd

# Account deletion is also a reconciliation event: remove exact NoID Privacy user
# profiles whose identities are no longer eligible. This keeps the daemon's
# authorization set equal to root plus the current eligible account set.
prune_stale_ipc_files

# Reload USBGuard only when the named ACL bytes or metadata changed.
if [ "$ipc_changed" -eq 1 ]; then
    systemctl reload-or-restart usbguard.service
    systemctl is-active --quiet usbguard.service
    log "usbguard.service reload-or-restart verified (named IPC state applied)"
fi

exit 0
ADD_USER_EOF
chmod 755 /usr/local/bin/noid-usbguard-add-user.sh
chown root:root /usr/local/bin/noid-usbguard-add-user.sh
restorecon -F /usr/local/bin/noid-usbguard-add-user.sh 2>/dev/null || true
echo "  [OK] /usr/local/bin/noid-usbguard-add-user.sh installed"

cat > /etc/systemd/system/noid-usbguard-add-user.service <<'SERVICE_EOF'
[Unit]
Description=NoID Privacy — Reconcile named USBGuard IPC (triggered by passwd change)
Documentation=file:///usr/share/doc/noid-privacy/14-usbguard.md
# Removed `Requires=usbguard.service`
# because usbguard.service is MASKED in Live-Boot squashfs (Module 14 Step 6
# masks it; noid-usbguard-firstboot.service unmasks + starts it later). systemd
# enforces Requires= at queue-time → if dependency is masked, the unit fails
# with `Result: resources`. The VM audit showed
# `noid-usbguard-add-user.path`
# in failed state from boot due to this exact race. Replaced with:
#   - Wants= (soft, no fail if missing)
#   - After= both installed and Live initializers (order after unmask happens)
# The helper returns EX_TEMPFAIL if usbguard.service is not active; successful
# firstboot invokes it directly after daemon verification, so an early path
# event cannot consume the only reconciliation opportunity. Treat that explicit
# deferral as a non-red systemd result; it is not a reconciliation success.
After=usbguard.service noid-usbguard-firstboot.service noid-usbguard-live-init.service
Wants=usbguard.service
ConditionFileIsExecutable=/usr/local/bin/noid-usbguard-add-user.sh

[Service]
Type=oneshot
RemainAfterExit=no
ExecStart=/usr/local/bin/noid-usbguard-add-user.sh
SuccessExitStatus=75
StandardOutput=journal
StandardError=journal

# 2026 baseline hardening (mirrors noid-usbguard-firstboot.service)
ProtectSystem=true
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=false
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
IPAddressDeny=any
SERVICE_EOF
chmod 644 /etc/systemd/system/noid-usbguard-add-user.service
chown root:root /etc/systemd/system/noid-usbguard-add-user.service
restorecon -F /etc/systemd/system/noid-usbguard-add-user.service 2>/dev/null || true

cat > /etc/systemd/system/noid-usbguard-add-user.path <<'PATH_EOF'
[Unit]
Description=NoID Privacy — Watch /etc/passwd for named USBGuard IPC
Documentation=file:///usr/share/doc/noid-privacy/14-usbguard.md
# Removed After= entirely.
# `After=noid-usbguard-firstboot.service usbguard.service` created a systemd
# ordering CYCLE detected at boot:
#   paths.target → noid-usbguard-add-user.path → usbguard.service
#                → basic.target → paths.target (CYCLE!)
# Path-units belong to paths.target which basic.target requires; but
# usbguard.service is `After=basic.target` (system default) → cycle. systemd
# breaks the cycle by removing one edge → unit silently fails to activate.
# Fix: remove After= from .path. The path-unit only watches /etc/passwd —
# no boot-ordering needed. Ordering matters in the TRIGGERED .service which
# already orders behind both initializers and `usbguard.service`, and has
# `Wants=usbguard.service`. Defense-in-depth: script checks
# `is-active usbguard.service || exit 75`; successful firstboot invokes the
# same helper after daemon verification, so a too-early trigger is retryable.

[Path]
PathChanged=/etc/passwd
TriggerLimitBurst=10
TriggerLimitIntervalSec=60s
Unit=noid-usbguard-add-user.service

[Install]
WantedBy=multi-user.target
PATH_EOF
chmod 644 /etc/systemd/system/noid-usbguard-add-user.path
chown root:root /etc/systemd/system/noid-usbguard-add-user.path
restorecon -F /etc/systemd/system/noid-usbguard-add-user.path 2>/dev/null || true

# Enable the path-unit so it activates at multi-user.target
ln -sf /etc/systemd/system/noid-usbguard-add-user.path \
    /etc/systemd/system/multi-user.target.wants/noid-usbguard-add-user.path
echo "  [OK] noid-usbguard-add-user.{path,service} installed + enabled"

# ----------------------------------------------------------------------------
# Step 7c (v6): usbguard-notifier graphical-session lifecycle + identity gate
# ----------------------------------------------------------------------------
# The upstream notifier user-unit is enabled at default.target, which can run
# before GNOME imports its session environment and is not stopped by graphical
# logout. A static graphical-session target link plus PartOf/After and an
# active-target ExecCondition makes every eligible graphical login a fresh
# owner. M08's common gate separately requires a persistent human account and
# an exact active local logind `Class=user`, Wayland/X11 session. It therefore
# excludes GDM, GNOME Initial Setup, remote and transient user managers without
# relying on late-imported XDG environment variables.
# The drop-in also re-sets ExecStart with the native `--wait` flag and retains
# Restart=on-failure. Companion: M17 keeps GNOME
# usb-protection off — the GSD `allow id *:*` injection would otherwise
# silently bypass USBGuard and leave the notifier nothing to show.

echo ""
echo "[Step 7c] Installing graphical-session-owned usbguard-notifier"

mkdir -p /etc/systemd/user/usbguard-notifier.service.d

cat > /etc/systemd/user/usbguard-notifier.service.d/10-noid-wait.conf <<'NOTIFIER_DROPIN_EOF'
# NoID Privacy — usbguard-notifier resilience drop-in (Module 14 Step 7c)
#
# Bug:        upstream default.target ownership evaluates too early and does
#             not bind the notifier's stop/start lifecycle to GNOME logout.
# Fix:        graphical-session target ownership, persistent-user + exact
#             local logind session identity, native --wait IPC mode and
#             restart recovery.
# Revoke:     remove this drop-in and the distro-owned graphical-session link.

[Unit]
ConditionUser=!@system
PartOf=graphical-session.target
After=graphical-session.target

[Service]
ExecCondition=/usr/libexec/noid-eligible-user graphical
ExecCondition=/usr/bin/systemctl --user --quiet is-active graphical-session.target
ExecStart=
ExecStart=/usr/bin/usbguard-notifier --wait
Restart=on-failure
RestartSec=2s
NOTIFIER_DROPIN_EOF

chmod 644 /etc/systemd/user/usbguard-notifier.service.d/10-noid-wait.conf
chown root:root /etc/systemd/user/usbguard-notifier.service.d/10-noid-wait.conf
echo "  [OK] /etc/systemd/user/usbguard-notifier.service.d/10-noid-wait.conf installed"

# A vendor unit cannot express desktop-session ownership while retaining its
# upstream default.target Install section. The distro-owned static wants link
# is the maintained systemd mechanism and survives preset `ignore` unchanged.
install -d -m 0755 -o root -g root \
    /usr/lib/systemd/user/graphical-session.target.wants
ln -sfn /usr/lib/systemd/user/usbguard-notifier.service \
    /usr/lib/systemd/user/graphical-session.target.wants/usbguard-notifier.service

# SELinux context restore for the drop-in (defensive, install path is
# under /etc which is fine but consistent with M27 STEP 4 pattern)
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /etc/systemd/user/usbguard-notifier.service.d/10-noid-wait.conf 2>/dev/null || true
fi

# usbguard-notifier listens only after the graphical session exists and does
# not replay device events emitted earlier in the boot. Query current daemon
# state once per graphical login so a blocked ModeSwitch precursor (or any
# other pre-login insertion) is visible without weakening authorization.
# The helper reports only a count, never device-provided names or identifiers,
# and offers one direct route to the existing reviewed manager; it never
# authorizes. The terminal is started as a fresh user-manager transient unit:
# this oneshot deliberately has NoNewPrivileges=yes, which a direct child
# would inherit and which would prevent the manager's ordinary sudo boundary.
cat > /usr/libexec/noid-usbguard-login-catchup <<'USBGUARD_LOGIN_CATCHUP_EOF'
#!/bin/bash
# NoID Privacy — surface USBGuard blocks that happened before graphical login.
set -u -o pipefail
umask 077
export PATH=/usr/sbin:/usr/bin

for required in /usr/bin/usbguard /usr/bin/notify-send /usr/bin/systemd-run \
                /usr/bin/ptyxis /usr/bin/bash /usr/bin/sudo \
                /usr/local/bin/noid-usbguard-devices; do
    [ -x "$required" ] || exit 1
done

blocked=
query_ok=0
for _attempt in 1 2 3 4 5; do
    if blocked=$(/usr/bin/usbguard list-devices --blocked 2>/dev/null); then
        query_ok=1
        break
    fi
    /usr/bin/sleep 1
done

if [ "$query_ok" -ne 1 ]; then
    /usr/bin/notify-send --urgency=critical --icon=dialog-warning \
        --app-name="NoID Privacy" -- \
        "USB protection status unavailable" \
        "The USBGuard device list could not be read after sign-in. Run: sudo noid-usbguard-devices" \
        </dev/null >/dev/null 2>&1 || true
    exit 1
fi

blocked_count=$(printf '%s\n' "$blocked" \
    | /usr/bin/awk 'NF { count++ } END { print count + 0 }')
unset blocked
[ "$blocked_count" -gt 0 ] || exit 0

if [ "$blocked_count" -eq 1 ]; then
    summary="USB device blocked before sign-in"
    body="1 USB device is currently blocked. Review it before allowing anything; nothing was authorized automatically."
else
    summary="USB devices blocked before sign-in"
    body="$blocked_count USB devices are currently blocked. Review them before allowing anything; nothing was authorized automatically."
fi

action=$(/usr/bin/notify-send --urgency=critical --icon=dialog-warning \
    --app-name="NoID Privacy" \
    --action=review="Open USBGuard Devices" -- \
    "$summary" "$body" 2>/dev/null || true)

if [ "$action" = review ]; then
    terminal_command='NOID_WELCOME_SPAWN=1 /usr/bin/sudo -- /usr/local/bin/noid-usbguard-devices; rc=$?; echo; [ $rc -ne 0 ] && echo "Command exited with error (rc=$rc)"; read -r -p "Press ENTER to close..." || :; exit 0'
    /usr/bin/systemd-run --user --collect --wait --quiet \
        --expand-environment=no \
        --property=Type=exec \
        /usr/bin/ptyxis -- /usr/bin/bash -c "$terminal_command" \
        >/dev/null 2>&1 || {
        /usr/bin/notify-send --urgency=normal --icon=dialog-warning \
            --app-name="NoID Privacy" -- \
            "USB manager could not be opened" \
            "Run: sudo noid-usbguard-devices" \
            </dev/null >/dev/null 2>&1 || true
        exit 1
    }
fi

exit 0
USBGUARD_LOGIN_CATCHUP_EOF
chmod 0755 /usr/libexec/noid-usbguard-login-catchup
chown root:root /usr/libexec/noid-usbguard-login-catchup
restorecon -F /usr/libexec/noid-usbguard-login-catchup 2>/dev/null || true

cat > /usr/lib/systemd/user/noid-usbguard-login-catchup.service <<'USBGUARD_LOGIN_CATCHUP_SERVICE_EOF'
[Unit]
Description=NoID Privacy — Report USB devices blocked before graphical login
Documentation=file:///usr/share/doc/noid-privacy/14-usbguard.md
ConditionUser=!@system
PartOf=graphical-session.target
After=graphical-session.target usbguard-notifier.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecCondition=/usr/libexec/noid-eligible-user graphical
ExecCondition=/usr/bin/systemctl --user --quiet is-active graphical-session.target
ExecStart=/usr/libexec/noid-usbguard-login-catchup
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX
# A per-user manager cannot attach the IPAddressDeny= BPF firewall and logs a
# warning instead. AF_UNIX is the effective, native local-only boundary here.
USBGUARD_LOGIN_CATCHUP_SERVICE_EOF
chmod 0644 /usr/lib/systemd/user/noid-usbguard-login-catchup.service
chown root:root /usr/lib/systemd/user/noid-usbguard-login-catchup.service
restorecon -F /usr/lib/systemd/user/noid-usbguard-login-catchup.service 2>/dev/null || true

ln -sfn /usr/lib/systemd/user/noid-usbguard-login-catchup.service \
    /usr/lib/systemd/user/graphical-session.target.wants/noid-usbguard-login-catchup.service

echo "  [OK] pre-login USB block catch-up is owned once per graphical session"

# ----------------------------------------------------------------------------
# Step 7d: Reject GNOME's USBGuard wildcard after every daemon start
# ----------------------------------------------------------------------------
# Runtime evidence showed GNOME adding:
#   allow id *:* label "GNOME_SETTINGS_DAEMON_RULE"
# which authorizes every later hotplug and defeats ImplicitPolicyTarget=block.
# M17 masks the producer. This lifecycle hook also removes any pre-existing
# residue after upgrades/races and verifies the postcondition.
echo ""
echo "[Step 7d] Installing USBGuard GNOME-wildcard rejection hook"

cat > /usr/local/sbin/noid-usbguard-remove-gnome-wildcard <<'REMOVE_GNOME_WILDCARD_EOF'
#!/bin/bash
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin
# `stat -c %F` is translated; this helper compares it against English literals.
# systemd hands services the installation's LANG, so pin the parse locale.
LC_ALL=C.UTF-8
export LC_ALL

label=GNOME_SETTINGS_DAEMON_RULE
status_file=/var/lib/noid-privacy/usbguard-gnome-wildcard.status
rules=""
query_ok=0

property_value() {
    local property=$1 data=$2 values
    values=$(printf '%s\n' "$data" | sed -n "s/^${property}=//p")
    [ "$(printf '%s\n' "$values" | grep -c . || true)" -eq 1 ] || return 1
    printf '%s\n' "$values"
}

status_file_ok() {
    local expected=$1
    [ -f "$status_file" ] && [ ! -L "$status_file" ] && \
        [ "$(stat -Lc '%u:%g:%a:%h' "$status_file" 2>/dev/null || true)" = 0:0:644:1 ] && \
        { [ ! -f /sys/fs/selinux/enforce ] || \
          matchpathcon -V "$status_file" >/dev/null 2>&1; } && \
        cmp -s "$status_file" <(printf '%s' "$expected")
}

degraded_status_is_current() {
    [ -f "$status_file" ] && [ ! -L "$status_file" ] && \
        [ "$(stat -Lc '%u:%g:%a:%h' "$status_file" 2>/dev/null || true)" = \
            0:0:644:1 ] && \
        { [ ! -f /sys/fs/selinux/enforce ] || \
          matchpathcon -V "$status_file" >/dev/null 2>&1; } && \
        [ "$(wc -l < "$status_file" 2>/dev/null || true)" = 3 ] && \
        [ "$(grep -cxF 'STATE=DEGRADED' "$status_file" 2>/dev/null || true)" = 1 ] && \
        [ "$(grep -cxF 'MESSAGE=cleanup-unverified' "$status_file" \
            2>/dev/null || true)" = 1 ] && \
        [ "$(grep -cE '^CHECKED_AT=.+$' "$status_file" 2>/dev/null || true)" = 1 ]
}

retire_status() {
    [ -d /var/lib/noid-privacy ] && [ ! -L /var/lib/noid-privacy ] && \
        [ "$(stat -Lc '%u:%g:%a' /var/lib/noid-privacy 2>/dev/null || true)" = \
            0:0:755 ] || return 1
    rm -f -- "$status_file"
}

restore_status_label() {
    local path=$1
    [ ! -f /sys/fs/selinux/enforce ] || {
        restorecon -F "$path" >/dev/null && \
            matchpathcon -V "$path" >/dev/null
    }
}

publish_status() {
    local state="$1" message="$2" checked_at expected tmp
    case "$state:$message" in
        OK:wildcard-absent|DEGRADED:cleanup-unverified) ;;
        *) return 1 ;;
    esac
    if [ -L /var/lib/noid-privacy ] || \
       { [ -e /var/lib/noid-privacy ] && [ ! -d /var/lib/noid-privacy ]; }; then
        return 1
    fi
    install -d -m 0755 -o root -g root /var/lib/noid-privacy || return 1
    [ "$(stat -Lc '%u:%g:%a' /var/lib/noid-privacy 2>/dev/null || true)" = 0:0:755 ] \
        || return 1
    restore_status_label /var/lib/noid-privacy || {
        retire_status || true
        return 1
    }
    checked_at=$(date -Iseconds) || {
        retire_status || true
        return 1
    }
    printf -v expected 'STATE=%s\nMESSAGE=%s\nCHECKED_AT=%s\n' \
        "$state" "$message" "$checked_at" || {
        retire_status || true
        return 1
    }
    tmp=$(mktemp /var/lib/noid-privacy/.usbguard-gnome-wildcard.XXXXXX) || {
        retire_status || true
        return 1
    }
    if ! printf '%s' "$expected" > "$tmp" \
       || ! chmod 0644 "$tmp" \
       || ! chown root:root "$tmp" \
       || ! restore_status_label "$tmp" \
       || ! sync -- "$tmp" \
       || ! mv -fT -- "$tmp" "$status_file" \
       || ! restore_status_label "$status_file" \
       || ! sync -- "$status_file" \
       || ! sync -f /var/lib/noid-privacy \
       || ! status_file_ok "$expected"; then
        rm -f -- "$tmp"
        retire_status || true
        return 1
    fi
}

notify_active_users() {
    command -v notify-send >/dev/null 2>&1 || return 0

    local sessions_json session_rows
    local session uid extra properties session_user seat remote session_class
    local session_type session_state session_active locked active_session
    local passwd_record user account_uid gid home shell runtime dbus_sock bus_status
    declare -A notified_uids=()

    sessions_json=$(
        timeout --signal=TERM --kill-after=1s 3s \
            loginctl list-sessions --json=short 2>/dev/null
    ) || return 0
    session_rows=$(
        python3 -c '
import json
import sys
rows = json.load(sys.stdin)
if not isinstance(rows, list):
    raise SystemExit(1)
for row in rows:
    if not isinstance(row, dict):
        continue
    session = row.get("session")
    uid = row.get("uid")
    if isinstance(session, (str, int)) and isinstance(uid, int):
        print(f"{session}\t{uid}")
' <<<"$sessions_json"
    ) || return 0

    while IFS=$'\t' read -r session uid extra; do
        [ -z "${extra:-}" ] || continue
        [[ "$session" =~ ^[[:alnum:]_.-]{1,128}$ ]] || continue
        [[ "$uid" =~ ^[0-9]+$ ]] && \
            [ "$uid" -ge 1000 ] && [ "$uid" -le 4294967294 ] || continue
        [ -z "${notified_uids[$uid]:-}" ] || continue
        /usr/libexec/noid-eligible-user account-uid "$uid" || continue

        properties=$(
            timeout --signal=TERM --kill-after=1s 3s \
                loginctl show-session "$session" \
                --property=User --property=Seat --property=Remote \
                --property=Class --property=Type --property=State \
                --property=Active --property=LockedHint 2>/dev/null
        ) || continue
        session_user=$(property_value User "$properties") || continue
        seat=$(property_value Seat "$properties") || continue
        remote=$(property_value Remote "$properties") || continue
        session_class=$(property_value Class "$properties") || continue
        session_type=$(property_value Type "$properties") || continue
        session_state=$(property_value State "$properties") || continue
        session_active=$(property_value Active "$properties") || continue
        locked=$(property_value LockedHint "$properties") || continue
        [ "$session_user" = "$uid" ] && \
            [[ "$seat" =~ ^[[:alnum:]_.-]{1,128}$ ]] && \
            [ "$remote" = no ] && [ "$session_class" = user ] && \
            [[ "$session_type" =~ ^(wayland|x11)$ ]] && \
            [ "$session_state" = active ] && [ "$session_active" = yes ] && \
            [ "$locked" = no ] || continue

        active_session=$(
            timeout --signal=TERM --kill-after=1s 3s \
                loginctl show-seat "$seat" \
                --property=ActiveSession --value 2>/dev/null
        ) || continue
        [ "$active_session" = "$session" ] || continue

        passwd_record=$(
            timeout --signal=TERM --kill-after=1s 3s \
                getent passwd "$uid" 2>/dev/null
        ) || continue
        [ "$(printf '%s\n' "$passwd_record" | grep -c . || true)" -eq 1 ] \
            || continue
        IFS=: read -r user _ account_uid gid _ home shell extra \
            <<<"$passwd_record"
        [ -z "${extra:-}" ] && [ "$user" != root ] && \
            [ "$account_uid" = "$uid" ] && [[ "$gid" =~ ^[0-9]+$ ]] && \
            [[ "$home" == /* ]] && [ -n "$shell" ] || continue

        runtime="/run/user/$uid"
        dbus_sock="$runtime/bus"
        bus_status=$(
            setpriv --reuid="$uid" --regid="$gid" --init-groups \
                --reset-env timeout --signal=TERM --kill-after=1s 3s \
                stat -c '%F:%u' "$dbus_sock" 2>/dev/null
        ) || continue
        [ "$bus_status" = "socket:$uid" ] || continue

        setpriv --reuid="$uid" --regid="$gid" --init-groups --reset-env \
            timeout --signal=TERM --kill-after=1s 5s \
            env HOME="$home" XDG_RUNTIME_DIR="$runtime" \
                DBUS_SESSION_BUS_ADDRESS="unix:path=$dbus_sock" \
            notify-send --urgency=critical --icon=dialog-warning \
                --app-name="NoID Privacy" -- \
                "USB protection needs attention" \
                "The GNOME USBGuard wildcard cleanup could not be verified. USB protection may be unavailable or incomplete. Check: sudo systemctl status noid-usbguard-remove-gnome-wildcard.service" \
                </dev/null >/dev/null 2>&1 \
            && notified_uids["$uid"]=1 || true
    done <<<"$session_rows"
}

on_exit() {
    local rc=$? notify_needed=1
    if [ "$rc" -ne 0 ]; then
        # Restart=on-failure is intentionally retained for bounded recovery,
        # but one persistent fault must produce one desktop warning, not one
        # warning per retry. A later successful run publishes OK and thereby
        # arms notification for the next distinct degraded transition.
        if degraded_status_is_current; then
            notify_needed=0
        fi
        if ! publish_status DEGRADED cleanup-unverified; then
            logger -p daemon.err -t noid-usbguard \
                "GNOME wildcard cleanup status publication failed; prior status is untrusted" || true
        fi
        logger -p daemon.err -t noid-usbguard \
            "GNOME wildcard cleanup unverified; USBGuard protection state is unverified" || true
        if [ "$notify_needed" -eq 1 ]; then
            notify_active_users
        fi
    fi
    exit "$rc"
}
trap on_exit EXIT

for _attempt in {1..20}; do
    if rules="$(timeout --signal=TERM --kill-after=1s 3s \
            usbguard list-rules --label "$label" 2>/dev/null)"; then
        query_ok=1
        break
    fi
    sleep 0.25
done
if [ "$query_ok" -ne 1 ]; then
    echo "Unable to query USBGuard rules after daemon start" >&2
    exit 1
fi

while IFS=: read -r rule_id _rule; do
    [ -n "$rule_id" ] || continue
    case "$rule_id" in
        *[!0-9]*)
            echo "Refusing malformed USBGuard rule id: $rule_id" >&2
            exit 1
            ;;
    esac
    timeout --signal=TERM --kill-after=1s 5s \
        usbguard remove-rule "$rule_id"
done <<< "$rules"

if ! remaining_rules=$(timeout --signal=TERM --kill-after=1s 3s \
        usbguard list-rules --label "$label" 2>/dev/null); then
    echo "Unable to verify USBGuard rules after cleanup" >&2
    exit 1
fi
if [ -n "$remaining_rules" ]; then
    echo "GNOME USBGuard wildcard remains after cleanup" >&2
    exit 1
fi
publish_status OK wildcard-absent
REMOVE_GNOME_WILDCARD_EOF
chmod 0755 /usr/local/sbin/noid-usbguard-remove-gnome-wildcard
chown root:root /usr/local/sbin/noid-usbguard-remove-gnome-wildcard
restorecon -F /usr/local/sbin/noid-usbguard-remove-gnome-wildcard 2>/dev/null || true

mkdir -p /etc/systemd/system/usbguard.service.d
cat > /etc/systemd/system/usbguard.service.d/20-noid-reject-gnome-wildcard.conf <<'REJECT_GNOME_WILDCARD_UNIT_EOF'
[Unit]
Wants=noid-usbguard-remove-gnome-wildcard.service
REJECT_GNOME_WILDCARD_UNIT_EOF
chmod 0644 /etc/systemd/system/usbguard.service.d/20-noid-reject-gnome-wildcard.conf
chown root:root /etc/systemd/system/usbguard.service.d/20-noid-reject-gnome-wildcard.conf
restorecon -F /etc/systemd/system/usbguard.service.d/20-noid-reject-gnome-wildcard.conf 2>/dev/null || true

cat > /etc/systemd/system/noid-usbguard-remove-gnome-wildcard.service <<'REJECT_GNOME_WILDCARD_SERVICE_EOF'
[Unit]
Description=Verify removal of GNOME's broad USBGuard wildcard
After=usbguard.service
StartLimitIntervalSec=5min
StartLimitBurst=3

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/noid-usbguard-remove-gnome-wildcard
Restart=on-failure
RestartSec=10s
TimeoutStartSec=45s
UMask=0077
CapabilityBoundingSet=CAP_SETGID CAP_SETUID
AmbientCapabilities=
NoNewPrivileges=yes
PrivateDevices=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
InaccessiblePaths=/home /root
ReadWritePaths=/var/lib/noid-privacy
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
IPAddressDeny=any
REJECT_GNOME_WILDCARD_SERVICE_EOF
chmod 0644 /etc/systemd/system/noid-usbguard-remove-gnome-wildcard.service
chown root:root /etc/systemd/system/noid-usbguard-remove-gnome-wildcard.service
restorecon -F /etc/systemd/system/noid-usbguard-remove-gnome-wildcard.service 2>/dev/null || true
echo "  [OK] USBGuard wildcard cleanup is independently bounded and transition-notified"

# ----------------------------------------------------------------------------
# Step 8: Create /var/lib/noid-privacy directory (state dir)
# ----------------------------------------------------------------------------
echo ""
echo "[Step 8] Ensuring /var/lib/noid-privacy state directory exists"

mkdir -p /var/lib/noid-privacy
chmod 755 /var/lib/noid-privacy
chown root:root /var/lib/noid-privacy
echo "  [OK] /var/lib/noid-privacy exists (755 root:root)"

# ----------------------------------------------------------------------------
# Step 9: (REMOVED 2026-04-15)
# ----------------------------------------------------------------------------
# Previously: overwrote /usr/local/bin/noid-welcome.sh with a USBGuard-aware
# version. This created a cross-Module order dependency (13 → 14 → 15 hard-
# coded overwrite cascade). Refactored: Module 13 now ships the read-only
# noid-status CLI, which parses /var/lib/noid-privacy/usbguard-status.txt as
# closed data at runtime. Module 14 only writes the status file via the
# firstboot script's write_status() function. Order-independent.
#
# Status file contract (written by firstboot script Step 4):
#   STATE=real|emergency|initializing
#   DEVICE_COUNT=<int>
#   FALLBACK_ACTIVE=yes|no
#   LAST_RUN=<iso8601>

# ----------------------------------------------------------------------------
# Step 10: (REMOVED 2026-04-15)
# ----------------------------------------------------------------------------
# Previously: appended an IPCAccessControl.d exclude to aide.conf. RETIRED —
# Module 13 now SECURE-tracks /etc/usbguard and forbids both former control
# excludes; verify 11.8 below independently asserts their absence.

# ----------------------------------------------------------------------------
# Step 10b: Install noid-usbguard-allow-device escape-hatch
# ----------------------------------------------------------------------------
# User-facing escape-hatch for devices plugged AFTER first-boot policy
# generation (docks, audio interfaces, printers): interactive picker around
# `allow-device --permanent` with snapper pre-snapshot. No baseline
# weakening — explicit per-device allow only. Usage doc in the heredoc.
echo ""
echo "[Step 10b] Installing /usr/local/bin/noid-usbguard-allow-device"

cat > /usr/local/bin/noid-usbguard-allow-device <<'ALLOW_DEV_EOF'
#!/bin/bash
# noid-usbguard-allow-device — permanently allow a blocked USB device
#
# Convenience wrapper around `usbguard list-devices` + `allow-device --permanent`.
# Creates a snapper pre-snapshot first so the change is rollback-able.
#
# Usage:  sudo noid-usbguard-allow-device       (interactive menu number)
#         sudo noid-usbguard-allow-device <N>   (allow by USBGuard device ID)
#
# Argument-mode "N" is the first column from `usbguard list-devices`.

set -euo pipefail

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — USBGuard" \
    NOID_FMT_AUTO_SUBTITLE="Explicit device authorization" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

if [ "$#" -gt 1 ]; then
    echo "Usage: noid-usbguard-allow-device [numeric-device-id]" >&2
    exit 2
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "This helper must be run as root (use sudo)." >&2
    exit 1
fi

if ! command -v usbguard >/dev/null 2>&1; then
    echo "Error: usbguard not installed." >&2
    exit 1
fi

if ! systemctl is-active usbguard >/dev/null 2>&1; then
    echo "Error: usbguard.service is not active. Check first-boot initialization:" >&2
    echo "  sudo journalctl -u noid-usbguard-firstboot.service" >&2
    exit 1
fi

MODE_SWITCH_DATA_DIR=/usr/share/usb_modeswitch
MODE_SWITCH_RULE_LABEL=noid-modeswitch-portable-v1

# List all devices with state 'block' (blocked, not yet allowed). A daemon/IPC
# error is not the same as an empty blocked set and must remain visible.
if ! BLOCKED=$(timeout --signal=TERM --kill-after=1s 5s \
        usbguard list-devices -b 2>/dev/null); then
    echo "Error: could not query USBGuard's blocked-device list." >&2
    exit 1
fi

if [ -z "$BLOCKED" ]; then
    echo "No blocked devices detected."
    echo ""
    echo "To see ALL devices (allowed + blocked):"
    echo "  sudo usbguard list-devices"
    exit 0
fi

# usbguard 1.1.x renders the list identifier as `N:` in the first column,
# while allow-device accepts the bare numeric N. Normalize only that terminal
# colon and require exactly one matching row; do not parse descriptions.
blocked_device_line() {
    local wanted=$1
    local device_rows=$2
    awk -v wanted="$wanted" '
        {
            candidate=$1
            sub(/:$/, "", candidate)
            if (candidate == wanted) { matches++; line=$0 }
        }
        END {
            if (matches != 1) exit 1
            print line
        }
    ' <<< "$device_rows"
}

# Return exactly one row by runtime handle from the complete device inventory.
# Unlike blocked_device_line(), this also admits an identity whose freshly
# persisted policy has already changed its effective state to allow.
device_line() {
    local wanted=$1
    local device_rows=$2
    awk -v wanted="$wanted" '
        {
            candidate=$1
            sub(/:$/, "", candidate)
            if (candidate == wanted) { matches++; line=$0 }
        }
        END {
            if (matches != 1) exit 1
            print line
        }
    ' <<< "$device_rows"
}

# Runtime state is the second field. Compare the numeric runtime handle and
# every remaining USBGuard descriptor field after normalizing field separators,
# so a block -> allow transition caused by the just-persisted exact rule is
# harmless while a recycled handle, descriptor change or ambiguous row remains
# fail-closed.
device_line_without_state() {
    awk '{
        first=$1
        $1=""
        $2=""
        sub(/^[[:space:]]+/, "")
        print first " " $0
    }' <<< "$1"
}

same_runtime_device() {
    [ "$(device_line_without_state "$1")" = \
      "$(device_line_without_state "$2")" ]
}

# Return one exact row by the one-based number shown in the interactive menu.
# This is intentionally separate from USBGuard's sparse runtime device ID.
menu_device_line() {
    local wanted=$1
    local device_rows=$2
    awk -v wanted="$wanted" '
        NR == wanted { line=$0; matches++ }
        END {
            if (matches != 1) exit 1
            print line
        }
    ' <<< "$device_rows"
}

# Render only recognition-relevant fields. The complete rule remains in memory
# for the byte-identical pre-authorization race check, but serial/hash material
# adds noise here and device-supplied names must not inject terminal controls.
render_device_rows() {
    local display_mode=$1
    local selected_index=${2:-}
    awk -v display_mode="$display_mode" -v selected_index="$selected_index" '
        {
            runtime_id=$1
            sub(/:$/, "", runtime_id)

            product_id="unknown"
            if (match($0, / id [[:xdigit:]]{4}:[[:xdigit:]]{4}/)) {
                product_id=substr($0, RSTART + 4, RLENGTH - 4)
            }

            device_name="Unnamed USB device"
            if (match($0, / name "[^"]*"/)) {
                device_name=substr($0, RSTART + 7, RLENGTH - 8)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", device_name)
            }
            gsub(/[[:cntrl:]]/, "", device_name)
            if (device_name == "") device_name="Unnamed USB device"
            if (length(device_name) > 64) {
                device_name=substr(device_name, 1, 61) "..."
            }

            interface_id="unknown"
            if (match($0, / with-interface (\{ )?[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}/)) {
                interface_id=substr($0, RSTART, RLENGTH)
                sub(/^ with-interface (\{ )?/, "", interface_id)
            }

            row_index=(display_mode == "menu" ? NR : selected_index)
            if (row_index != "") {
                printf "  [%s] %s\n", row_index, device_name
            } else {
                printf "  %s\n", device_name
            }
            printf "      Vendor/Product: %s | Interface: %s | USBGuard ID: %s\n",
                   product_id, interface_id, runtime_id
        }
    '
}

device_vidpid() {
    awk '
        match($0, / id [[:xdigit:]]{4}:[[:xdigit:]]{4}/) {
            print substr($0, RSTART + 4, RLENGTH - 4)
        }
    ' <<< "$1"
}

device_via_port() {
    awk '
        match($0, / via-port "[^"]+"/) {
            print substr($0, RSTART + 11, RLENGTH - 12)
        }
    ' <<< "$1"
}

device_hash() {
    awk '
        match($0, / hash "[^"]+"/) {
            value=substr($0, RSTART, RLENGTH)
            sub(/^ hash "/, "", value)
            sub(/"$/, "", value)
            print value
        }
    ' <<< "$1"
}

device_parent_hash() {
    awk '
        match($0, / parent-hash "[^"]+"/) {
            value=substr($0, RSTART, RLENGTH)
            sub(/^ parent-hash "/, "", value)
            sub(/"$/, "", value)
            print value
        }
    ' <<< "$1"
}

device_interfaces() {
    sed -nE 's/^.* with-interface (.*) with-connect-type "[^"]*"$/\1/p' \
        <<< "$1"
}

# USBGuard intentionally generates every permanent allow-device decision with
# parent-hash, even when DeviceRulesWithPort=false. That default is useful for
# ordinary peripherals but breaks a dual-identity network adapter when either
# identity later appears below another controller or external hub. For this
# explicitly recognized device class, construct a native rule from USBGuard's
# descriptor hash and complete interface set while omitting every topology
# attribute. The label makes helper-owned portable rules unambiguous without
# participating in matching.
portable_modeswitch_rule() {
    local line=$1 vidpid hash interfaces rule
    vidpid=$(device_vidpid "$line")
    hash=$(device_hash "$line")
    interfaces=$(device_interfaces "$line")
    [[ "$vidpid" =~ ^[[:xdigit:]]{4}:[[:xdigit:]]{4}$ ]] || return 1
    [[ "$hash" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || return 1
    if ! [[ "$interfaces" =~ ^[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}$|^\{[[:space:]]+[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}([[:space:]]+[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2})*[[:space:]]+\}$ ]]; then
        return 1
    fi
    rule="allow id $vidpid hash \"$hash\" with-interface $interfaces label \"$MODE_SWITCH_RULE_LABEL\""
    usbguard-rule-parser "$rule" >/dev/null 2>&1 || return 1
    printf '%s\n' "$rule"
}

rule_body() {
    local line=$1
    printf '%s\n' "${line#* }"
}

exact_policy_rule_ids() {
    local wanted=$1 rules=$2
    awk -v wanted="$wanted" '
        {
            rule_id=$1
            sub(/:$/, "", rule_id)
            body=substr($0, index($0, " ") + 1)
            if (body == wanted && rule_id ~ /^[0-9]+$/) print rule_id
        }
    ' <<< "$rules"
}

policy_rule_line() {
    local wanted=$1 rules=$2
    awk -v wanted="$wanted" '
        {
            rule_id=$1
            sub(/:$/, "", rule_id)
            if (rule_id == wanted) { matches++; line=$0 }
        }
        END {
            if (matches != 1) exit 1
            print line
        }
    ' <<< "$rules"
}

# Recognize only USBGuard's complete canonical full-device allow shape for the
# same exact descriptor hash. A reduced rule can be a deliberate operator
# policy even when it is unlabeled, so absence of a label alone never makes a
# rule helper-owned. Generated allows contain the complete serial/name/hash/
# parent/interface/connect-type inventory in canonical list-rules output;
# labels, conditions, or a missing inventory field make cleanup fail closed.
is_generated_topology_allow_rule() {
    local device_line=$1 policy_line=$2 body source_id source_hash rule_id rule_hash
    body=$(rule_body "$policy_line")
    [[ "$body" == allow\ * ]] || return 1
    grep -Eq ' (label|if) ' <<< "$body" && return 1
    grep -Fq ' serial "' <<< "$body" || return 1
    grep -Fq ' name "' <<< "$body" || return 1
    grep -Fq ' hash "' <<< "$body" || return 1
    grep -Fq ' parent-hash "' <<< "$body" || return 1
    grep -Fq ' with-interface ' <<< "$body" || return 1
    grep -Fq ' with-connect-type "' <<< "$body" || return 1
    source_id=$(device_vidpid "$device_line")
    source_hash=$(device_hash "$device_line")
    rule_id=$(device_vidpid "$policy_line")
    rule_hash=$(device_hash "$policy_line")
    [ -n "$source_id" ] && [ "$rule_id" = "$source_id" ] && \
        [ -n "$source_hash" ] && [ "$rule_hash" = "$source_hash" ]
}

portable_rule_is_unique() {
    local device_line=$1 rules=$2 portable ids
    portable=$(portable_modeswitch_rule "$device_line") || return 1
    ids=$(exact_policy_rule_ids "$portable" "$rules")
    [ "$(awk 'NF { count++ } END { print count + 0 }' <<< "$ids")" -eq 1 ]
}

persist_portable_modeswitch_rule() {
    local device_line=$1 portable rules ids count rule_id current_rules current_line
    local topology_ids=
    portable=$(portable_modeswitch_rule "$device_line") || {
        echo "Error: could not construct a safe topology-independent USBGuard rule." >&2
        return 1
    }
    if ! rules=$(timeout --signal=TERM --kill-after=1s 5s \
            usbguard list-rules 2>/dev/null); then
        echo "Error: could not read USBGuard policy before the portable rule change." >&2
        return 1
    fi
    ids=$(exact_policy_rule_ids "$portable" "$rules")
    count=$(awk 'NF { count++ } END { print count + 0 }' <<< "$ids")
    if [ "$count" -gt 1 ]; then
        echo "Error: duplicate helper-owned portable USBGuard rules require review." >&2
        return 1
    fi
    if [ "$count" -eq 0 ]; then
        if ! timeout --signal=TERM --kill-after=1s 15s \
                usbguard append-rule "$portable" >/dev/null; then
            echo "Error: failed to append the portable USBGuard rule." >&2
            return 1
        fi
    fi

    if ! rules=$(timeout --signal=TERM --kill-after=1s 5s \
            usbguard list-rules 2>/dev/null) || \
       ! portable_rule_is_unique "$device_line" "$rules"; then
        echo "Error: the portable USBGuard rule was not uniquely persisted." >&2
        return 1
    fi

    # Once the broader, identity-bound rule is durable, retire only old
    # unconditional device-specific allow rules for the same descriptor hash.
    # Revalidate every numeric rule ID immediately before deletion so a
    # concurrent policy edit cannot redirect cleanup to another rule.
    while IFS= read -r current_line; do
        [ -n "$current_line" ] || continue
        if is_generated_topology_allow_rule "$device_line" "$current_line"; then
            rule_id=${current_line%%:*}
            topology_ids="${topology_ids}${topology_ids:+ }$rule_id"
        fi
    done <<< "$rules"
    for rule_id in $topology_ids; do
        if ! current_rules=$(timeout --signal=TERM --kill-after=1s 5s \
                usbguard list-rules 2>/dev/null) || \
           ! current_line=$(policy_rule_line "$rule_id" "$current_rules") || \
           ! is_generated_topology_allow_rule "$device_line" "$current_line"; then
            echo "Error: USBGuard policy changed during topology-rule cleanup." >&2
            return 1
        fi
        if ! timeout --signal=TERM --kill-after=1s 15s \
                usbguard remove-rule "$rule_id" >/dev/null; then
            echo "Error: failed to retire an old topology-bound USBGuard rule." >&2
            return 1
        fi
    done

    if ! rules=$(timeout --signal=TERM --kill-after=1s 5s \
            usbguard list-rules 2>/dev/null) || \
       ! portable_rule_is_unique "$device_line" "$rules"; then
        echo "Error: final portable USBGuard policy verification failed." >&2
        return 1
    fi
    while IFS= read -r current_line; do
        [ -n "$current_line" ] || continue
        if is_generated_topology_allow_rule "$device_line" "$current_line"; then
            echo "Error: an old topology-bound USBGuard rule remains." >&2
            return 1
        fi
    done <<< "$rules"
}

# A flip-flop USB network adapter can enumerate first as a storage device so
# usb_modeswitch can eject its bundled driver image, then return with a second
# network identity. Never auto-authorize that precursor: USB IDs and interface
# classes are spoofable, and the kernel authorization API would expose the
# storage interface while probing it. Recognition here changes only the guided
# post-approval verification; the user's exact permanent USBGuard decision is
# still the authorization boundary.
is_modeswitch_precursor() {
    local line=$1 vidpid config metadata
    vidpid=$(device_vidpid "$line")
    [[ "$vidpid" =~ ^[[:xdigit:]]{4}:[[:xdigit:]]{4}$ ]] || return 1
    grep -Eq ' with-interface (\{ )?08:06:50([[:space:]}]|$)' \
        <<< "$line" || return 1
    config="$MODE_SWITCH_DATA_DIR/$vidpid"
    [ -f "$config" ] && [ ! -L "$config" ] || return 1
    metadata=$(stat -c '%u:%g:%a:%h' "$config" 2>/dev/null) || return 1
    [ "$metadata" = 0:0:644:1 ]
}

# Return exactly one re-enumerated identity on the same physical port and USB
# parent. The source VID:PID is excluded so a slow disconnect cannot be
# mistaken for a successful mode switch.
modeswitch_target_line() {
    local source_line=$1 device_rows=$2 source_id source_port source_parent
    source_id=$(device_vidpid "$source_line")
    source_port=$(device_via_port "$source_line")
    source_parent=$(device_parent_hash "$source_line")
    [ -n "$source_id" ] && [ -n "$source_port" ] && \
        [ -n "$source_parent" ] || return 1
    awk -v source_id="$source_id" -v source_port="$source_port" \
            -v source_parent="$source_parent" '
        {
            id=""
            port=""
            parent=""
            if (match($0, / id [[:xdigit:]]{4}:[[:xdigit:]]{4}/)) {
                id=substr($0, RSTART + 4, RLENGTH - 4)
            }
            if (match($0, / via-port "[^"]+"/)) {
                port=substr($0, RSTART + 11, RLENGTH - 12)
            }
            if (match($0, / parent-hash "[^"]+"/)) {
                parent=substr($0, RSTART, RLENGTH)
                sub(/^ parent-hash "/, "", parent)
                sub(/"$/, "", parent)
            }
            if (id != "" && id != source_id && port == source_port &&
                    parent == source_parent) {
                matches++
                line=$0
            }
        }
        END {
            if (matches != 1) exit 1
            print line
        }
    ' <<< "$device_rows"
}

verify_modeswitch_transition() {
    local source_line=$1 rows rules target_line target_state
    local target_confirm current_rows current_target_line final_rows final_target_line
    local final_target_id final_target_state post_rows post_target_line post_target_state
    echo "ModeSwitch precursor enrolled; waiting for its network identity..."
    for _ in {1..32}; do
        sleep 0.25
        if ! rows=$(timeout --signal=TERM --kill-after=1s 5s \
                usbguard list-devices 2>/dev/null); then
            echo "Warning: could not verify the post-switch USBGuard state." >&2
            return 0
        fi
        if target_line=$(modeswitch_target_line "$source_line" "$rows"); then
            target_state=$(awk '{ print $2 }' <<< "$target_line")
            echo "Re-enumerated USB identity:"
            render_device_rows selected <<< "$target_line"
            if [ "$target_state" = allow ]; then
                if ! rules=$(timeout --signal=TERM --kill-after=1s 5s \
                        usbguard list-rules 2>/dev/null); then
                    echo "The new identity is currently allowed, but persistent policy could not be verified." >&2
                elif portable_rule_is_unique "$target_line" "$rules"; then
                    echo "ModeSwitch transition verified: both identities have topology-independent device-specific persistent allow rules."
                    return 0
                fi
            else
                echo "The re-enumerated identity is currently blocked."
            fi

            echo "A topology-independent permanent rule for this second identity was not verified."
            echo "This is a new trust decision; same-port correlation is not authorization."
            echo "If approved, the exact descriptor identity will be trusted across USB ports and hubs."
            target_confirm=
            if ! read -rp "Permanently allow this re-enumerated USB identity? [y/N] " \
                    target_confirm; then
                echo ""
            fi
            if ! [[ "$target_confirm" =~ ^[yY]$ ]]; then
                echo "Second identity not authorized; no topology-independent persistent rule was added for it."
                echo "The adapter can therefore still be blocked after a USB port, hub or controller change."
                return 0
            fi

            # The runtime ID is recyclable and the prompt can remain open for
            # an arbitrary time. Re-read the complete device set and require
            # the exact same row, physical port and USB parent immediately
            # before applying the second explicit decision.
            if ! current_rows=$(timeout --signal=TERM --kill-after=1s 5s \
                    usbguard list-devices 2>/dev/null) || \
               ! current_target_line=$(modeswitch_target_line \
                    "$source_line" "$current_rows") || \
               [ "$current_target_line" != "$target_line" ]; then
                echo "Error: the re-enumerated USB identity changed; the second identity was not authorized." >&2
                return 1
            fi

            if ! persist_portable_modeswitch_rule "$current_target_line"; then
                echo "Error: portable authorization of the second identity failed." >&2
                return 1
            fi

            # Rule persistence can take multiple IPC round trips. Resolve the
            # correlated device again at the final runtime-allow boundary and
            # permit only an unchanged descriptor whose state is block/allow.
            # Never send a stale, recyclable ID to allow-device.
            if ! final_rows=$(timeout --signal=TERM --kill-after=1s 5s \
                    usbguard list-devices 2>/dev/null) || \
               ! final_target_line=$(modeswitch_target_line \
                    "$source_line" "$final_rows") || \
               ! same_runtime_device "$current_target_line" "$final_target_line"; then
                echo "Error: the re-enumerated USB identity changed during policy persistence; runtime authorization was not attempted." >&2
                return 1
            fi
            final_target_id=$(awk '{ candidate=$1; sub(/:$/, "", candidate); print candidate }' \
                <<< "$final_target_line")
            final_target_state=$(awk '{ print $2 }' <<< "$final_target_line")
            case "$final_target_state" in
                allow) ;;
                block)
                    if ! timeout --signal=TERM --kill-after=1s 15s \
                            usbguard allow-device "$final_target_id"; then
                        echo "Error: runtime authorization of the second identity failed." >&2
                        return 1
                    fi
                    ;;
                *)
                    echo "Error: the re-enumerated USB identity is neither blocked nor allowed; runtime authorization was not attempted." >&2
                    return 1
                    ;;
            esac

            # CLI success is not the final verdict. Re-resolve the correlated
            # device and require both effective authorization and exactly one
            # topology-independent persistent rule for its descriptor hash.
            if ! post_rows=$(timeout --signal=TERM --kill-after=1s 5s \
                    usbguard list-devices 2>/dev/null) || \
               ! post_target_line=$(modeswitch_target_line \
                    "$source_line" "$post_rows"); then
                echo "Error: could not verify the second identity after authorization." >&2
                return 1
            fi
            post_target_state=$(awk '{ print $2 }' <<< "$post_target_line")
            if [ "$post_target_state" != allow ]; then
                echo "Error: the second identity is not effectively allowed after authorization." >&2
                return 1
            fi
            if ! rules=$(timeout --signal=TERM --kill-after=1s 5s \
                    usbguard list-rules 2>/dev/null) || \
               ! portable_rule_is_unique "$post_target_line" "$rules"; then
                echo "Error: no unique topology-independent persistent rule was verified for the second identity." >&2
                return 1
            fi
            echo "ModeSwitch transition verified: both identities have topology-independent device-specific persistent allow rules."
            return 0
        fi
    done
    echo "The precursor rule is persistent, but no second identity appeared within 8 seconds." >&2
    echo "Unplug/replug the device once; approve any newly blocked identity explicitly." >&2
}

# Argument mode: allow by USBGuard runtime device ID.
if [ "$#" -eq 1 ]; then
    DEV_ID="$1"
    # Validate: must be numeric, must appear in BLOCKED list
    if ! [[ "$DEV_ID" =~ ^[0-9]+$ ]]; then
        echo "Error: device id must be numeric (first column of list-devices output)." >&2
        exit 1
    fi
    if ! DEV_LINE=$(blocked_device_line "$DEV_ID" "$BLOCKED"); then
        echo "Error: device $DEV_ID is not in the blocked list:" >&2
        echo "$BLOCKED" >&2
        exit 1
    fi
else
    # Interactive menu
    echo "Currently blocked USB devices:"
    echo ""
    render_device_rows menu <<< "$BLOCKED"
    echo ""
    MENU_COUNT=$(awk 'END { print NR + 0 }' <<< "$BLOCKED")
    read -rp "Enter menu number [1-$MENU_COUNT], or 'q' to quit: " MENU_INDEX
    [[ "$MENU_INDEX" =~ ^[qQ]$ ]] && exit 0
    if ! [[ "$MENU_INDEX" =~ ^[1-9][0-9]*$ ]]; then
        echo "Invalid menu number. Aborted." >&2
        exit 1
    fi
    if ! DEV_LINE=$(menu_device_line "$MENU_INDEX" "$BLOCKED"); then
        echo "Menu number must be between 1 and $MENU_COUNT. Aborted." >&2
        exit 1
    fi
    DEV_ID=$(awk '{
        candidate=$1
        sub(/:$/, "", candidate)
        print candidate
    }' <<< "$DEV_LINE")
    if ! [[ "$DEV_ID" =~ ^[0-9]+$ ]] || \
       ! blocked_device_line "$DEV_ID" "$BLOCKED" >/dev/null; then
        echo "Error: selected row has no unique numeric USBGuard device ID." >&2
        exit 1
    fi
fi

MODE_SWITCH_PRECURSOR=no
if is_modeswitch_precursor "$DEV_LINE"; then
    MODE_SWITCH_PRECURSOR=yes
fi

echo ""
echo "About to PERMANENTLY ALLOW:"
render_device_rows selected "${MENU_INDEX:-}" <<< "$DEV_LINE"
if [ "$MODE_SWITCH_PRECURSOR" = yes ]; then
    echo ""
    echo "Detected a USB ModeSwitch precursor (temporary storage identity)."
    echo "Its exact descriptor identity will be trusted across USB ports and hubs."
    echo "No vendor-wide, product-wide or mass-storage exception will be added."
fi
if [ "$#" -eq 0 ]; then
    echo ""
    read -rp "Continue? [y/N] " CONFIRM
    [[ "$CONFIRM" =~ ^[yY]$ ]] || { echo "Aborted."; exit 0; }
fi

# Device list IDs are runtime handles and can be recycled after hot-unplug.
# Re-query immediately before mutation and require that the selected row is
# byte-identical; never authorize a different device through a stale ID.
if ! CURRENT_BLOCKED=$(timeout --signal=TERM --kill-after=1s 5s \
        usbguard list-devices -b 2>/dev/null) || \
   ! CURRENT_LINE=$(blocked_device_line "$DEV_ID" "$CURRENT_BLOCKED") || \
   [ "$CURRENT_LINE" != "$DEV_LINE" ]; then
    echo "Error: the blocked-device list changed; no device was authorized." >&2
    exit 1
fi

# A snapshot is useful but this single USBGuard rule remains directly revocable.
# Keep its persistent description generic: the complete selected row contains
# serial and descriptor hashes hidden from LinuxAudit by HidePII=true. Report
# snapshot failure explicitly instead of hiding it.
if command -v noid-snap-pre >/dev/null 2>&1; then
    if ! noid-snap-pre --embedded "usbguard allow blocked device"; then
        echo "Warning: pre-change snapshot failed; continuing with the revocable USBGuard rule only." >&2
    fi
fi

# Apply. Ordinary devices retain USBGuard's topology-bound permanent decision.
# A recognized ModeSwitch precursor uses a helper-owned identity rule first,
# then a runtime allow to trigger the native mode transition without asking
# USBGuard to generate a parent-hash-bound permanent rule.
if [ "$MODE_SWITCH_PRECURSOR" = yes ]; then
    if ! persist_portable_modeswitch_rule "$DEV_LINE"; then
        exit 1
    fi
    # Persisting the identity rule can itself take several IPC operations.
    # Re-resolve the complete inventory immediately before runtime allow. A
    # rule-induced block -> allow transition needs no mutation; every identity
    # change or other state aborts without using the recyclable handle.
    if ! FINAL_DEVICES=$(timeout --signal=TERM --kill-after=1s 5s \
            usbguard list-devices 2>/dev/null) || \
       ! FINAL_LINE=$(device_line "$DEV_ID" "$FINAL_DEVICES") || \
       ! same_runtime_device "$DEV_LINE" "$FINAL_LINE"; then
        echo "Error: the USB identity changed during policy persistence; runtime authorization was not attempted." >&2
        exit 1
    fi
    FINAL_STATE=$(awk '{ print $2 }' <<< "$FINAL_LINE")
    case "$FINAL_STATE" in
        allow) ALLOW_ARGS=() ;;
        block) ALLOW_ARGS=(allow-device "$DEV_ID") ;;
        *)
            echo "Error: the USB identity is neither blocked nor allowed; runtime authorization was not attempted." >&2
            exit 1
            ;;
    esac
else
    # The snapshot helper runs outside USBGuard and may take time. Repeat the
    # byte-identical blocked-row check after it, at the final mutation boundary.
    if ! FINAL_BLOCKED=$(timeout --signal=TERM --kill-after=1s 5s \
            usbguard list-devices -b 2>/dev/null) || \
       ! FINAL_LINE=$(blocked_device_line "$DEV_ID" "$FINAL_BLOCKED") || \
       [ "$FINAL_LINE" != "$DEV_LINE" ]; then
        echo "Error: the blocked USB identity changed after the snapshot; no device was authorized." >&2
        exit 1
    fi
    ALLOW_ARGS=(allow-device --permanent "$DEV_ID")
fi
if [ "${#ALLOW_ARGS[@]}" -eq 0 ] || \
   timeout --signal=TERM --kill-after=1s 15s usbguard "${ALLOW_ARGS[@]}"; then
    echo ""
    echo "Device permanently allowed:"
    render_device_rows selected <<< "$DEV_LINE"
    if [ "$MODE_SWITCH_PRECURSOR" = yes ]; then
        echo "Topology-independent rule persisted to /etc/usbguard/rules.conf"
    else
        echo "Rule persisted to /etc/usbguard/rules.conf"
    fi
    if [ "$MODE_SWITCH_PRECURSOR" = yes ]; then
        verify_modeswitch_transition "$DEV_LINE"
    fi
    echo ""
    echo "To revoke later:"
    echo "  sudo noid-usbguard-devices status"
    echo "  sudo noid-usbguard-devices revoke"
else
    echo "Error: usbguard allow-device failed." >&2
    exit 1
fi
ALLOW_DEV_EOF

chmod 755 /usr/local/bin/noid-usbguard-allow-device
chown root:root /usr/local/bin/noid-usbguard-allow-device
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/local/bin/noid-usbguard-allow-device 2>/dev/null || true
fi
echo "  [OK] /usr/local/bin/noid-usbguard-allow-device installed (755)"

# ----------------------------------------------------------------------------
# Step 10b.1: Install unified USBGuard inventory / allow / revoke manager
# ----------------------------------------------------------------------------
# The admission helper above owns the difficult ModeSwitch trust boundary.
# This manager composes that reviewed workflow with a root-readable durable
# policy inventory and exact-rule revocation. It never edits rules.conf:
# USBGuard's native IPC remains the sole policy mutation surface.
echo "[Step 10b.1] Installing /usr/local/bin/noid-usbguard-devices"

cat > /usr/local/bin/noid-usbguard-devices <<'USB_MANAGER_EOF'
#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""NoID Privacy USBGuard device and durable-policy manager."""

from __future__ import annotations

import collections
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass, field

USBGUARD = "/usr/bin/usbguard"
RULE_PARSER = "/usr/bin/usbguard-rule-parser"
RULES_FILE = "/etc/usbguard/rules.conf"
ALLOW_HELPER = "/usr/local/bin/noid-usbguard-allow-device"
SNAP_PRE = "/usr/local/bin/noid-snap-pre"
MODE_SWITCH_LABEL_PREFIX = "noid-modeswitch-portable-v1"
TIMEOUT = 8

RULE_LINE_RE = re.compile(r"^(\d+): (allow|block|reject) (.*)$")
DEVICE_LINE_RE = re.compile(r"^(\d+): (allow|block|reject) (.*)$")
VIDPID_RE = re.compile(r"(?:^| )id ([0-9A-Fa-f]{4}:[0-9A-Fa-f]{4})(?: |$)")
HASH_RE = re.compile(r'(?:^| )hash "((?:\\.|[^"\\])*)"(?: |$)')
NAME_RE = re.compile(r'(?:^| )name "((?:\\.|[^"\\])*)"(?: |$)')
LABEL_RE = re.compile(r'(?:^| )label "((?:\\.|[^"\\])*)"(?: |$)')
INTERFACE_RE = re.compile(
    r"(?:^| )with-interface (.+?)(?= if | with-connect-type | label |$)"
)
EXACT_DEVICE_SELECTOR_RE = re.compile(
    r"^id (?P<id>[0-9A-Fa-f]{4}:[0-9A-Fa-f]{4})"
    r'(?: serial "(?P<serial>(?:\\.|[^"\\])*)")?'
    r'(?: name "(?P<name>(?:\\.|[^"\\])*)")?'
    r' hash "(?P<hash>(?:\\.|[^"\\])*)"'
    r'(?: parent-hash "(?P<parent_hash>(?:\\.|[^"\\])*)")?'
    r'(?: via-port "(?P<via_port>(?:\\.|[^"\\])*)")?'
    r" with-interface (?P<interfaces>"
    r"(?:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}|"
    r"\{ [0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}"
    r"(?: [0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})* \})"
    r')'
    r'(?: with-connect-type "(?P<connect_type>(?:\\.|[^"\\])*)")?'
    r'(?: label "(?P<label>(?:\\.|[^"\\])*)")?$'
)

# Keep the Python manager visually byte-for-byte aligned with the shared Bash
# presentation contract from agent-install-format.sh. The implementation is
# local because importing executable Python from /usr/local through an ad-hoc
# sys.path extension would create a new privileged code-loading boundary.
_FMT_TTY = sys.stdout.isatty()
_FMT_COLOR = (
    _FMT_TTY
    and not os.environ.get("NO_COLOR")
    and os.environ.get("TERM", "dumb") != "dumb"
)
_F_RST = "\033[0m" if _FMT_COLOR else ""
_F_B = "\033[1m" if _FMT_COLOR else ""
_F_BLUE = "\033[38;5;39m" if _FMT_COLOR else ""
_F_GREEN = "\033[38;5;42m" if _FMT_COLOR else ""
_F_YEL = "\033[38;5;214m" if _FMT_COLOR else ""
_F_RED = "\033[38;5;203m" if _FMT_COLOR else ""


def fmt_tty_banner(title: str, subtitle: str = "") -> None:
    if not _FMT_TTY:
        return
    bar = "─" * 52
    print(f"{_F_BLUE}╭{bar}╮{_F_RST}")
    print(
        f"{_F_BLUE}│{_F_RST} {_F_B}{title}{_F_RST}"
        f"{' ' * max(0, 50 - len(title))} {_F_BLUE}│{_F_RST}"
    )
    if subtitle:
        grey = "\033[38;5;245m" if _FMT_COLOR else ""
        print(
            f"{_F_BLUE}│{_F_RST} {grey}{subtitle}{_F_RST}"
            f"{' ' * max(0, 50 - len(subtitle))} {_F_BLUE}│{_F_RST}"
        )
    print(f"{_F_BLUE}╰{bar}╯{_F_RST}")


def fmt_section(title: str) -> None:
    print(f"\n{_F_BLUE}{_F_B}── {title}{_F_RST}")


def fmt_done(message: str) -> None:
    print(f"\n{_F_GREEN}{_F_B}✓ {message}{_F_RST}")


def fmt_ok(message: str) -> None:
    print(f"  {_F_GREEN}✓{_F_RST} {message}")


def fmt_error(message: str) -> str:
    return f"  {_F_RED}✗ {message}{_F_RST}"


def fmt_warning(message: str) -> str:
    return f"  {_F_YEL}!{_F_RST} {message}"


def fmt_action(key: str, label_text: str) -> None:
    print(f"  {_F_BLUE}[{key}]{_F_RST} {label_text}")


def prompt(message: str) -> str:
    return input(f"{_F_BLUE}{_F_B}{message}{_F_RST}")


class ManagerError(RuntimeError):
    """A checked USBGuard contract could not be established."""


@dataclass
class Device:
    device_id: int
    state: str
    attributes: str
    raw: str

    @property
    def body(self) -> str:
        return f"{self.state} {self.attributes}"


@dataclass
class Rule:
    rule_id: int
    target: str
    attributes: str
    raw: str
    durable: bool = False
    matching_devices: list[int] = field(default_factory=list)

    @property
    def body(self) -> str:
        return f"{self.target} {self.attributes}"

    @property
    def conditional(self) -> bool:
        return " if " in f" {self.body} "


@dataclass
class PolicyState:
    rules: list[Rule]
    devices: list[Device]
    durable_missing: list[str]
    durable_order_matches: bool

    @property
    def runtime_only_rules(self) -> list[Rule]:
        return [rule for rule in self.rules if not rule.durable]

    @property
    def clean_durable_mapping(self) -> bool:
        return not self.durable_missing and self.durable_order_matches


def usage(stream=sys.stdout) -> None:
    print(
        """Usage:
  sudo noid-usbguard-devices
  sudo noid-usbguard-devices status
  sudo noid-usbguard-devices allow [device-id]
  sudo noid-usbguard-devices revoke [rule-id]

No arguments opens the complete overview and an action menu.
status is read-only. allow delegates to the specialized permanent admission
helper. revoke removes one exact persistent allow rule and deauthorizes each
unchanged connected device instance matched by that rule.
""",
        file=stream,
    )


def clean_text(value: str, limit: int = 42) -> str:
    value = "".join(ch for ch in value if ch.isprintable())
    value = value.replace(r'\"', '"').replace(r"\\", "\\").strip()
    if not value:
        value = "Unnamed USB device"
    if len(value) > limit:
        value = value[: limit - 3] + "..."
    return value


def attribute(pattern: re.Pattern[str], body: str) -> str:
    match = pattern.search(body)
    return match.group(1) if match else ""


def vidpid(body: str) -> str:
    return attribute(VIDPID_RE, body) or "unknown"


def device_name(body: str) -> str:
    return clean_text(attribute(NAME_RE, body))


def interfaces(body: str) -> str:
    value = attribute(INTERFACE_RE, body)
    return clean_text(value, 34) if value else "unknown"


def label(body: str) -> str:
    return clean_text(attribute(LABEL_RE, body), 48) if LABEL_RE.search(body) else ""


def run_command(argv: list[str], *, timeout: int = TIMEOUT) -> str:
    try:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ManagerError(f"could not execute {argv[0]}: {exc}") from exc
    if result.returncode != 0:
        detail = clean_text(result.stderr or result.stdout, 160)
        raise ManagerError(
            f"{os.path.basename(argv[0])} failed (rc={result.returncode}): {detail}"
        )
    return result.stdout


def run_usbguard(*arguments: str) -> str:
    return run_command([USBGUARD, *arguments])


def parse_rules(output: str) -> list[Rule]:
    rules: list[Rule] = []
    for line in output.splitlines():
        match = RULE_LINE_RE.fullmatch(line)
        if not match:
            raise ManagerError("USBGuard returned an unparseable policy row")
        rules.append(
            Rule(int(match.group(1)), match.group(2), match.group(3), line)
        )
    return rules


def parse_devices(output: str) -> list[Device]:
    devices: list[Device] = []
    for line in output.splitlines():
        if not line:
            continue
        match = DEVICE_LINE_RE.fullmatch(line)
        if not match:
            raise ManagerError("USBGuard returned an unparseable device row")
        devices.append(
            Device(int(match.group(1)), match.group(2), match.group(3), line)
        )
    return devices


def exact_selector(attributes: str) -> dict[str, str | None] | None:
    """Return the closed exact-device subset this manager can compare."""
    match = EXACT_DEVICE_SELECTOR_RE.fullmatch(attributes)
    return match.groupdict() if match else None


def exact_rule_matches_device(rule: Rule, device: Device) -> bool:
    """Match exact descriptor rules without widening USBGuard semantics."""
    rule_selector = exact_selector(rule.attributes)
    device_selector = exact_selector(device.attributes)
    if rule_selector is None or device_selector is None:
        return False
    for key, value in rule_selector.items():
        if key == "label" or value is None:
            continue
        if device_selector.get(key) != value:
            return False
    return True


def bind_native_rule_devices(
    output: str, rules: list[Rule], devices: list[Device]
) -> None:
    """Parse USBGuard 1.1.4 list-rules -d without inventing a query API."""
    known = {device.device_id: device for device in devices}
    rule_index = -1
    for line in output.splitlines():
        if not line:
            continue
        if line[0].isspace():
            if rule_index < 0:
                raise ManagerError("USBGuard returned a device before its policy row")
            affected = parse_devices(line.lstrip())
            if len(affected) != 1:
                raise ManagerError("USBGuard returned an invalid affected-device row")
            device = affected[0]
            if (
                device.device_id not in known
                or known[device.device_id].raw != device.raw
            ):
                raise ManagerError(
                    "USBGuard device state changed during policy inspection"
                )
            rules[rule_index].matching_devices.append(device.device_id)
            continue

        rule_index += 1
        if rule_index >= len(rules) or line != rules[rule_index].raw:
            raise ManagerError("USBGuard policy changed during affected-device inspection")
    if rule_index + 1 != len(rules):
        raise ManagerError("USBGuard omitted policy rows from list-rules -d")


def durable_rule_bodies() -> list[str]:
    """Parse the root policy through one verified, no-follow file descriptor."""
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(RULES_FILE, flags)
    except OSError as exc:
        raise ManagerError(f"cannot open durable USBGuard policy: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ManagerError("durable USBGuard policy is not a regular file")
        if (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode),
                metadata.st_nlink) != (0, 0, 0o600, 1):
            raise ManagerError(
                "durable USBGuard policy metadata is not root:root 0600 nlink=1"
            )
        try:
            result = subprocess.run(
                [RULE_PARSER, "-f", f"/proc/self/fd/{descriptor}"],
                check=False,
                capture_output=True,
                text=True,
                timeout=TIMEOUT,
                pass_fds=(descriptor,),
                env={**os.environ, "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ManagerError(f"could not validate durable USBGuard policy: {exc}") from exc
    finally:
        os.close(descriptor)
    if result.returncode != 0:
        raise ManagerError("durable USBGuard policy failed native parser validation")
    bodies = [
        line[len("OUTPUT: "):]
        for line in result.stdout.splitlines()
        if line.startswith("OUTPUT: ")
    ]
    if not bodies:
        raise ManagerError("durable USBGuard policy contains no parsed rules")
    return bodies


def load_state() -> PolicyState:
    rules = parse_rules(run_usbguard("list-rules"))
    devices = parse_devices(run_usbguard("list-devices"))
    durable_bodies = durable_rule_bodies()
    durable = collections.Counter(durable_bodies)
    for rule in rules:
        if durable[rule.body] > 0:
            rule.durable = True
            durable[rule.body] -= 1
    missing = list(durable.elements())

    bind_native_rule_devices(run_usbguard("list-rules", "-d"), rules, devices)

    # USBGuard 1.1.4's -d view lists affected devices only when the rule target
    # equals their current target. For an exact descriptor rule, compare the
    # closed canonical selector locally as well so a temporary runtime block
    # cannot hide a durable allow (or vice versa). Broad, wildcarded,
    # conditional or otherwise non-canonical rules are never widened here.
    for rule in rules:
        for device in devices:
            if (
                device.device_id not in rule.matching_devices
                and exact_rule_matches_device(rule, device)
            ):
                rule.matching_devices.append(device.device_id)
    ordered_parity = [rule.body for rule in rules] == durable_bodies
    return PolicyState(rules, devices, missing, ordered_parity)


def rules_for_device(state: PolicyState, device_id: int) -> list[Rule]:
    return [rule for rule in state.rules if device_id in rule.matching_devices]


def authorization_text(state: PolicyState, device: Device) -> str:
    matching = rules_for_device(state, device.device_id)
    durable_matching = [rule for rule in matching if rule.durable]
    if any(rule.conditional for rule in durable_matching):
        return "conditional durable policy — inspect rules"
    durable_first = durable_matching[0] if durable_matching else None
    if device.state == "allow":
        if durable_first and durable_first.target == "allow":
            return f"permanent allow (rule {durable_first.rule_id})"
        if durable_first:
            return (
                f"session allow; durable {durable_first.target} "
                f"rule {durable_first.rule_id} remains"
            )
        return "session-only allow"
    if durable_first and durable_first.target == device.state:
        return f"permanent {device.state} (rule {durable_first.rule_id})"
    if durable_first and durable_first.target == "allow":
        return f"runtime {device.state}; permanent allow rule {durable_first.rule_id} remains"
    return "implicit/runtime block"


def rule_kind(rule: Rule) -> str:
    if " if " in f" {rule.body} ":
        return "conditional — manual review"
    if not VIDPID_RE.search(rule.body) or not HASH_RE.search(rule.body):
        return "broad/non-device rule — manual only"
    iface = attribute(INTERFACE_RE, rule.body)
    if re.search(r"(?:^|[ {])09:[0-9A-Fa-f*]{2}:[0-9A-Fa-f*]{2}(?:[ }]|$)", iface):
        return "USB controller — protected"
    marker = label(rule.body)
    if marker.startswith(MODE_SWITCH_LABEL_PREFIX):
        return "ModeSwitch identity"
    if re.search(r"(?:^|[ {])03:[0-9A-Fa-f*]{2}:[0-9A-Fa-f*]{2}(?:[ }]|$)", iface):
        return "HID/input — lockout risk"
    return "device-specific"


def rule_display_name(rule: Rule, device_map: dict[int, Device]) -> str:
    """Prefer a matching live name without adding it to durable trust."""
    stored = device_name(rule.body)
    if stored != "Unnamed USB device":
        return stored
    for device_id in rule.matching_devices:
        device = device_map.get(device_id)
        if device is not None:
            live = device_name(device.body)
            if live != "Unnamed USB device":
                return live
    if rule_kind(rule) == "ModeSwitch identity":
        iface = attribute(INTERFACE_RE, rule.body)
        if re.search(r"(?:^|[ {])08:06:50(?:[ }]|$)", iface):
            return "ModeSwitch storage identity"
        return "ModeSwitch device identity"
    return stored


def is_managed_revoke_candidate(rule: Rule) -> bool:
    return (
        rule.durable
        and rule.target == "allow"
        and not rule.conditional
        and bool(VIDPID_RE.search(rule.body))
        and bool(HASH_RE.search(rule.body))
        and rule_kind(rule) != "USB controller — protected"
    )


def print_overview(state: PolicyState) -> None:
    fmt_tty_banner(
        "NoID Privacy — USBGuard Devices",
        "Runtime and persistent authorization",
    )
    fmt_section("Current USB devices")
    print(f"{_F_B}DEV  STATE   ID         NAME                         AUTHORIZATION{_F_RST}")
    if not state.devices:
        print("-    -       -          no devices reported")
    for device in state.devices:
        state_field = f"{device.state:<7}"
        if device.state == "allow":
            state_field = f"{_F_GREEN}{state_field}{_F_RST}"
        elif device.state in ("block", "reject"):
            state_field = f"{_F_YEL}{state_field}{_F_RST}"
        print(
            f"{device.device_id:<4} {state_field} {vidpid(device.body):<10} "
            f"{device_name(device.body):<28} {authorization_text(state, device)}"
        )

    fmt_section("Blocked USB devices")
    blocked = [device for device in state.devices if device.state != "allow"]
    if not blocked:
        fmt_ok("No USB devices are currently blocked or rejected.")
    else:
        print(f"{_F_B}DEV  STATE   ID         NAME                         INTERFACES  AUTHORIZATION{_F_RST}")
        for device in blocked:
            print(
                f"{device.device_id:<4} {_F_YEL}{device.state:<7}{_F_RST} "
                f"{vidpid(device.body):<10} {device_name(device.body):<28} "
                f"{interfaces(device.body):<11} {authorization_text(state, device)}"
            )

    fmt_section("Persistent allow rules")
    print(f"{_F_B}RULE ID         NAME                         CONNECTED  TYPE{_F_RST}")
    durable_allows = [
        rule for rule in state.rules if rule.durable and rule.target == "allow"
    ]
    if not durable_allows:
        print("-    -          no persistent allow rules")
    device_map = {device.device_id: device for device in state.devices}
    for rule in durable_allows:
        connected = ",".join(
            str(device_id)
            for device_id in rule.matching_devices
            if device_id in device_map
        ) or "offline"
        print(
            f"{rule.rule_id:<4} {vidpid(rule.body):<10} "
            f"{rule_display_name(rule, device_map):<28} "
            f"{connected:<10} {rule_kind(rule)}"
        )

    fmt_section("Persistent block/reject rules")
    durable_denies = [
        rule
        for rule in state.rules
        if rule.durable and rule.target in ("block", "reject")
    ]
    if not durable_denies:
        fmt_ok("No explicit persistent block or reject rules are stored.")
    else:
        print(f"{_F_B}RULE TARGET  ID         NAME                         CONNECTED  TYPE{_F_RST}")
        for rule in durable_denies:
            connected = ",".join(
                str(device_id)
                for device_id in rule.matching_devices
                if device_id in device_map
            ) or "offline"
            print(
                f"{rule.rule_id:<4} {rule.target:<7} {vidpid(rule.body):<10} "
                f"{rule_display_name(rule, device_map):<28} "
                f"{connected:<10} {rule_kind(rule)}"
            )

    if state.runtime_only_rules:
        ids = ", ".join(str(rule.rule_id) for rule in state.runtime_only_rules)
        print("\n" + fmt_warning(
            "Runtime-only policy rule(s) are loaded: " + ids
        ))
        print(
            "Revocation is disabled because USBGuard remove-rule would save "
            "the complete runtime policy."
        )
    if state.durable_missing:
        print("\n" + fmt_error(
            "rules.conf contains durable rule(s) not present in the daemon "
            "policy; permanence is not fully assessable."
        ))
    elif not state.durable_order_matches:
        print("\n" + fmt_error(
            "Daemon policy order differs from rules.conf; guided revocation "
            "is disabled."
        ))


def require_clean_revoke_state(state: PolicyState) -> None:
    if state.runtime_only_rules:
        raise ManagerError(
            "runtime-only rules are loaded; refusing a save that could persist them"
        )
    if not state.clean_durable_mapping:
        raise ManagerError(
            "daemon/rules.conf policy drift blocks safe revocation"
        )


def choose_revoke_rule(state: PolicyState, requested: str | None) -> Rule:
    candidates = [rule for rule in state.rules if is_managed_revoke_candidate(rule)]
    if not candidates:
        raise ManagerError("no safely revocable persistent device allow rules found")
    if requested is not None:
        if not requested.isdecimal():
            raise ManagerError("rule-id must be numeric")
        matches = [rule for rule in candidates if rule.rule_id == int(requested)]
        if len(matches) != 1:
            raise ManagerError("rule-id is not one safely revocable persistent allow rule")
        return matches[0]

    fmt_section("Persistent device allow rules")
    device_map = {device.device_id: device for device in state.devices}
    for index, rule in enumerate(candidates, 1):
        connected = ",".join(map(str, rule.matching_devices)) or "offline"
        print(
            f"  [{index}] rule {rule.rule_id}: {rule_display_name(rule, device_map)} "
            f"({vidpid(rule.body)}; connected: {connected}; {rule_kind(rule)})"
        )
    try:
        answer = prompt(
            f"Select menu number [1-{len(candidates)}], or q: "
        ).strip()
    except EOFError as exc:
        raise ManagerError("no selection received; nothing changed") from exc
    if answer.lower() == "q":
        raise SystemExit(0)
    if not answer.isdecimal() or not (1 <= int(answer) <= len(candidates)):
        raise ManagerError("invalid revoke menu number")
    return candidates[int(answer) - 1]


def snapshot_before_revoke() -> None:
    require_safe_executable(SNAP_PRE)
    run_command(
        [SNAP_PRE, "--embedded", "usbguard revoke persistent allow rule"],
        timeout=90,
    )


def find_same_device(devices: list[Device], original: Device) -> Device | None:
    wanted_vidpid = vidpid(original.body)
    wanted_hash = attribute(HASH_RE, original.body)
    for device in devices:
        if (
            device.device_id == original.device_id
            and vidpid(device.body) == wanted_vidpid
            and attribute(HASH_RE, device.body) == wanted_hash
        ):
            return device
    return None


def revoke(requested: str | None, *, show_banner: bool = True) -> None:
    if show_banner:
        fmt_tty_banner(
            "NoID Privacy — USBGuard Devices",
            "Verified persistent authorization removal",
        )
    initial = load_state()
    require_clean_revoke_state(initial)
    selected = choose_revoke_rule(initial, requested)
    kind = rule_kind(selected)
    initial_device_map = {device.device_id: device for device in initial.devices}

    fmt_section("About to revoke one persistent USB allow rule")
    print(f"  Rule:       {selected.rule_id}")
    print(f"  Device:     {rule_display_name(selected, initial_device_map)}")
    print(f"  Vendor/ID:  {vidpid(selected.body)}")
    print(f"  Interfaces: {interfaces(selected.body)}")
    print(f"  Type:       {kind}")
    if kind == "HID/input — lockout risk":
        print("  WARNING: this can immediately disable a keyboard or mouse.")
    if kind == "ModeSwitch identity":
        print(
            "  NOTE: a dual-identity adapter can have a second persistent "
            "ModeSwitch rule; review the overview again afterward."
        )
    try:
        confirmation = prompt(
            f"Type the persistent rule ID {selected.rule_id} to revoke it: "
        ).strip()
    except EOFError as exc:
        raise ManagerError("no confirmation received; nothing changed") from exc
    if confirmation != str(selected.rule_id):
        print("Aborted; nothing changed.")
        return

    current = load_state()
    require_clean_revoke_state(current)
    current_matches = [
        rule
        for rule in current.rules
        if rule.rule_id == selected.rule_id
        and rule.raw == selected.raw
        and is_managed_revoke_candidate(rule)
    ]
    if len(current_matches) != 1:
        raise ManagerError("policy changed after confirmation; nothing was revoked")
    selected = current_matches[0]
    device_map = {device.device_id: device for device in current.devices}
    affected = [
        device_map[device_id]
        for device_id in selected.matching_devices
        if device_id in device_map
    ]

    snapshot_before_revoke()
    run_usbguard("remove-rule", str(selected.rule_id))

    block_failures: list[int] = []
    for original in affected:
        devices_now = parse_devices(run_usbguard("list-devices"))
        same = find_same_device(devices_now, original)
        if same is None or same.state != "allow":
            continue
        try:
            run_usbguard("block-device", str(same.device_id))
        except ManagerError:
            block_failures.append(same.device_id)

    final = load_state()
    if any(rule.raw == selected.raw for rule in final.rules) or any(
        body == selected.body for body in durable_rule_bodies()
    ):
        raise ManagerError("selected allow rule still exists after revocation")

    still_allowed: list[int] = []
    for original in affected:
        same = find_same_device(final.devices, original)
        if same is not None and same.state == "allow":
            still_allowed.append(same.device_id)
    if block_failures or still_allowed:
        ids = sorted(set(block_failures + still_allowed))
        raise ManagerError(
            "persistent rule was removed, but connected device ID(s) remain "
            "authorized until disconnect/daemon reset: "
            + ",".join(map(str, ids))
        )

    fmt_done("Persistent allow rule removed and connected instances deauthorized.")
    remaining = [
        rule
        for rule in final.rules
        if rule.durable and rule.target == "allow"
        and any(
            vidpid(device.body) == vidpid(selected.body)
            and attribute(HASH_RE, device.body) == attribute(HASH_RE, selected.body)
            for device in final.devices
            if device.device_id in rule.matching_devices
        )
    ]
    if remaining:
        print(
            "WARNING: another persistent allow rule still matches this "
            "connected descriptor; review status before treating it as fully revoked."
        )
    if kind == "ModeSwitch identity":
        print("Review the overview and revoke the adapter's other identity if listed.")


def require_safe_executable(path: str) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise ManagerError(f"required executable is unavailable: {path}: {exc}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or stat.S_IMODE(metadata.st_mode) & 0o111 == 0
    ):
        raise ManagerError(f"required executable is missing or unsafe: {path}")


def ensure_runtime() -> None:
    if os.geteuid() != 0:
        raise ManagerError("run this manager as root (use sudo)")
    # Keep the read-only inventory available even if an optional mutation
    # helper is missing or damaged. Each action validates its own additional
    # executable immediately before that trust boundary is crossed.
    for path in (USBGUARD, RULE_PARSER):
        require_safe_executable(path)
    try:
        result = subprocess.run(
            ["/usr/bin/systemctl", "is-active", "--quiet", "usbguard.service"],
            check=False,
            timeout=TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ManagerError(f"could not query usbguard.service: {exc}") from exc
    if result.returncode != 0:
        raise ManagerError("usbguard.service is not active")


def main(argv: list[str]) -> int:
    if argv and argv[0] in ("-h", "--help", "help"):
        usage()
        return 0
    if len(argv) > 2 or (len(argv) == 2 and argv[0] not in ("allow", "revoke")):
        usage(sys.stderr)
        return 2
    command = argv[0] if argv else "manage"
    if command not in ("manage", "status", "list", "allow", "revoke"):
        usage(sys.stderr)
        return 2

    ensure_runtime()
    if command in ("status", "list"):
        print_overview(load_state())
        return 0
    if command == "allow":
        require_safe_executable(ALLOW_HELPER)
        os.execv(ALLOW_HELPER, [ALLOW_HELPER, *argv[1:]])
    if command == "revoke":
        revoke(argv[1] if len(argv) == 2 else None)
        return 0

    state = load_state()
    print_overview(state)
    fmt_section("Actions")
    fmt_action("a", "Allow a blocked device")
    fmt_action("r", "Revoke a persistent allow rule")
    fmt_action("q", "Quit")
    print()
    try:
        action = prompt("Select action: ").strip().lower()
    except EOFError:
        action = "q"
    if action == "a":
        require_safe_executable(ALLOW_HELPER)
        os.execv(ALLOW_HELPER, [ALLOW_HELPER])
    if action == "r":
        revoke(None, show_banner=False)
        return 0
    if action in ("q", ""):
        return 0
    raise ManagerError("unknown action; nothing changed")


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except ManagerError as exc:
        print(fmt_error(str(exc)), file=sys.stderr)
        raise SystemExit(1)
USB_MANAGER_EOF

chmod 755 /usr/local/bin/noid-usbguard-devices
chown root:root /usr/local/bin/noid-usbguard-devices
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/local/bin/noid-usbguard-devices 2>/dev/null || true
fi
python3 -m py_compile /usr/local/bin/noid-usbguard-devices
rm -rf /usr/local/bin/__pycache__
echo "  [OK] /usr/local/bin/noid-usbguard-devices installed (755)"

# ----------------------------------------------------------------------------
# Step 10c: Install /usr/local/bin/noid-install-displaylink (opt-in)
# ----------------------------------------------------------------------------
# DisplayLink USB video adapters (NOT Thunderbolt/USB4 DP Alt-Mode — those
# work out-of-the-box) need the proprietary daemon + evdi kernel module;
# neither ships with Fedora. Opt-in installer: EULA warning + snapper
# pre-snapshot + restricted negativo17 repo (GPG fingerprint pinned) + exact
# package/trust ownership ledger + akmod->dkms fallback + MOK enrollment
# guidance. User-confirmed with an explicit recovery boundary — full flow in
# the DISPLAYLINK_EOF heredoc.
echo ""
echo "[Step 10c] Installing /usr/local/bin/noid-install-displaylink"

cat > /usr/local/bin/noid-install-displaylink <<'DISPLAYLINK_EOF'
#!/bin/bash
# noid-install-displaylink — opt-in DisplayLink (USB video) driver installer.
#
# Installs the evdi kernel module + displaylink proprietary userspace daemon
# from the negativo17.org Fedora Multimedia third-party repository.
#
# DisplayLink = USB-attached video adapters (not to be confused with Thunder-
# bolt/USB4 docks that use native DisplayPort Alt-Mode — those work out-of-
# the-box without any driver install).
#
# Two-path installation strategy:
#   1. Try akmod-evdi first (Fedora-standard, auto-rebuild on kernel update)
#   2. Roll the exact failed DNF transaction back before trying dkms-evdi.
# Fedora packages are community-maintained: Synaptics publishes an Ubuntu
# reference driver, not a Fedora build. The repository is restricted to the
# DisplayLink/EVDI package family so its broader multimedia/NVIDIA inventory
# cannot replace Fedora or RPM Fusion packages.
#
# Secure Boot: MOK enrollment path differs by installed variant:
#   - akmod: /etc/pki/akmods/certs/public_key.der
#   - dkms : /var/lib/dkms/mok.pub
#
# Usage:
#   sudo noid-install-displaylink              # auto (akmod → dkms fallback)
#   sudo noid-install-displaylink --akmod      # force akmod path
#   sudo noid-install-displaylink --dkms       # force dkms path
#   sudo noid-install-displaylink --uninstall  # remove NoID Privacy-managed payload

set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — DisplayLink" \
    NOID_FMT_AUTO_SUBTITLE="Third-party driver workflow" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

usage() {
    cat <<'USAGE'
Usage: noid-install-displaylink [--akmod|--dkms|--uninstall|--help]

With no option, install DisplayLink using akmod with a DKMS fallback.
  --akmod      require the akmod path
  --dkms       require the DKMS path
  --uninstall  remove the NoID Privacy-managed DisplayLink/evdi payload and trust state
  -h, --help   show this help without requiring root or changing the system
USAGE
}

case "$#:${1:-}" in
    0:) ACTION=install ;;
    1:-h|1:--help) usage; exit 0 ;;
    1:--akmod|1:akmod) ACTION=--akmod ;;
    1:--dkms|1:dkms) ACTION=--dkms ;;
    1:--uninstall|1:uninstall) ACTION=--uninstall ;;
    *) echo "ERROR: Unknown option or extra argument: ${1:-}" >&2; usage >&2; exit 1 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    echo "This installer must be run as root (use sudo)." >&2
    exit 1
fi

REPO_FILE=/etc/yum.repos.d/noid-displaylink-negativo17.repo
NEGATIVO17_FPR_EXPECTED="0C5D0F470484AE2FC40A9B6597F3008993E8909B"
NEGATIVO17_KEY_URL="https://negativo17.org/repos/RPM-GPG-KEY-slaanesh"
NEGATIVO17_KEY_LOCAL="/etc/pki/rpm-gpg/RPM-GPG-KEY-negativo17"
DNF=/usr/bin/dnf
STATE_DIR=/var/lib/noid-privacy/displaylink
STATE_FILE="$STATE_DIR/install-state.tsv"
LOCK_FILE=/run/noid-privacy/displaylink.lock
MANAGED_PACKAGES=(
    displaylink xorg-x11-displaylink libevdi
    akmod-evdi kmod-evdi dkms-evdi evdi-kmod-common
)

for required_command in awk curl dnf flock gpg python3 rpm rpmkeys \
        sha256sum stat sync systemctl; do
    command -v "$required_command" >/dev/null 2>&1 || {
        echo "ERROR: required command is unavailable: $required_command" >&2
        exit 1
    }
done

run_system_dnf() {
    # DNF5 atomically rewrites its public package-reason/group inventory.
    # Keep the helper's trust ledger and scratch private under 0077, but give
    # every DNF cache, history and transaction path Fedora's normal 0022.
    ( umask 022; "$DNF" "$@" )
}

if [ -f /sys/fs/selinux/enforce ]; then
    for required_command in matchpathcon restorecon; do
        command -v "$required_command" >/dev/null 2>&1 || {
            echo "ERROR: SELinux is active but $required_command is unavailable." >&2
            exit 1
        }
    done
fi

if [ -L "$LOCK_FILE" ] || { [ -e "$LOCK_FILE" ] && [ ! -f "$LOCK_FILE" ]; }; then
    echo "ERROR: DisplayLink lock path is not a regular file." >&2
    exit 1
fi
if [ ! -e "$LOCK_FILE" ]; then
    install -m 0600 -o root -g root /dev/null "$LOCK_FILE"
fi
if [ "$(stat -Lc '%u:%g:%a:%h' "$LOCK_FILE" 2>/dev/null || true)" != 0:0:600:1 ]; then
    echo "ERROR: DisplayLink lock metadata is unsafe." >&2
    exit 1
fi
if [ -f /sys/fs/selinux/enforce ]; then
    restorecon -F "$LOCK_FILE" >/dev/null
    matchpathcon -V "$LOCK_FILE" >/dev/null || {
        echo "ERROR: DisplayLink lock SELinux label is unsafe." >&2
        exit 1
    }
fi
exec 9<>"$LOCK_FILE"
if ! flock -n 9; then
    echo "ERROR: another DisplayLink transaction is active." >&2
    exit 75
fi

selinux_label_ok() {
    local path=$1
    [ ! -f /sys/fs/selinux/enforce ] || \
        matchpathcon -V "$path" >/dev/null 2>&1
}

restore_and_verify_label() {
    local path=$1
    [ ! -f /sys/fs/selinux/enforce ] && return 0
    restorecon -F "$path" >/dev/null
    matchpathcon -V "$path" >/dev/null
}

primary_key_fingerprints() {
    gpg --batch --show-keys --with-colons "$1" 2>/dev/null | awk -F: '
        $1 == "pub" { want_fingerprint=1; next }
        $1 == "fpr" && want_fingerprint {
            print toupper($10)
            want_fingerprint=0
        }
    '
}

key_file_matches_identity() {
    local path=$1
    local -a fingerprints=()
    [ -f "$path" ] && [ ! -L "$path" ] && \
        [ "$(stat -Lc '%u:%g:%a:%h' "$path" 2>/dev/null || true)" = 0:0:644:1 ] && \
        selinux_label_ok "$path" || return 1
    mapfile -t fingerprints < <(primary_key_fingerprints "$path")
    [ "${#fingerprints[@]}" -eq 1 ] && \
        [ "${fingerprints[0]}" = "$NEGATIVO17_FPR_EXPECTED" ]
}

rpm_key_present() {
    rpmkeys --list 2>/dev/null | awk -v fpr="$NEGATIVO17_FPR_EXPECTED" \
        'toupper($1) == fpr { found=1 } END { exit !found }'
}

state_value() {
    local key=$1
    awk -F '\t' -v key="$key" '
        $1 == key { if (++seen > 1) exit 2; value=$2 }
        END { if (seen != 1) exit 1; print value }
    ' "$STATE_FILE"
}

validate_state() {
    [ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ] || return 1
    [ -f "$STATE_FILE" ] && [ ! -L "$STATE_FILE" ] || return 1
    [ "$(stat -c '%u:%g:%a' "$STATE_DIR" 2>/dev/null)" = 0:0:700 ] || return 1
    [ "$(stat -Lc '%u:%g:%a:%h' "$STATE_FILE" 2>/dev/null)" = 0:0:600:1 ] || return 1
    selinux_label_ok "$STATE_DIR" && selinux_label_ok "$STATE_FILE" || return 1
    [ "$(wc -l < "$STATE_FILE")" -eq 8 ] || return 1
    [ "$(state_value schema)" = 2 ] || return 1
    case "$(state_value variant)" in akmod|dkms) ;; *) return 1 ;; esac
    case "$(state_value repo_owned)" in yes|no) ;; *) return 1 ;; esac
    case "$(state_value key_file_owned)" in yes|no) ;; *) return 1 ;; esac
    case "$(state_value rpm_key_owned)" in yes|no) ;; *) return 1 ;; esac
    state_value install_transaction_id | grep -Eq '^[1-9][0-9]*$' || return 1
    state_value repo_sha256 | grep -Eq '^[0-9a-f]{64}$' || return 1
    state_value key_file_sha256 | grep -Eq '^([0-9a-f]{64}|external)$'
}

validate_owned_artifacts() {
    local repo_owned key_file_owned expected actual
    repo_owned=$(state_value repo_owned)
    key_file_owned=$(state_value key_file_owned)
    if [ "$repo_owned" = yes ]; then
        [ -f "$REPO_FILE" ] && [ ! -L "$REPO_FILE" ] && \
            [ "$(stat -Lc '%u:%g:%a:%h' "$REPO_FILE" 2>/dev/null || true)" = 0:0:644:1 ] && \
            selinux_label_ok "$REPO_FILE" || return 1
        expected=$(state_value repo_sha256)
        actual=$(sha256sum "$REPO_FILE" | awk '{print $1}')
        [ "$actual" = "$expected" ] || return 1
    fi
    if [ "$key_file_owned" = yes ]; then
        key_file_matches_identity "$NEGATIVO17_KEY_LOCAL" || return 1
        expected=$(state_value key_file_sha256)
        actual=$(sha256sum "$NEGATIVO17_KEY_LOCAL" | awk '{print $1}')
        [ "$actual" = "$expected" ] || return 1
    fi
}

# --- UNINSTALL path ---------------------------------------------------
if [ "$ACTION" = "--uninstall" ] || [ "$ACTION" = "uninstall" ]; then
    echo "Uninstalling the NoID Privacy-managed DisplayLink payload..."
    if ! validate_state; then
        echo "ERROR: no valid NoID Privacy DisplayLink ownership ledger exists." >&2
        echo "Refusing to remove packages, repositories or keys that may be administrator-owned." >&2
        exit 1
    fi
    if ! validate_owned_artifacts; then
        echo "ERROR: a NoID Privacy-owned DisplayLink trust artifact changed." >&2
        echo "Refusing package removal until the repository/key drift is reviewed." >&2
        exit 1
    fi
    if ! command -v noid-snap-pre >/dev/null 2>&1; then
        echo "ERROR: noid-snap-pre is required for this system-changing operation." >&2
        exit 1
    fi
    if ! noid-snap-pre "DisplayLink uninstall"; then
        echo "ERROR: pre-uninstall snapshot failed; no packages were removed." >&2
        exit 1
    fi
    if systemctl list-unit-files displaylink.service --no-legend 2>/dev/null | grep -q '^displaylink\.service'; then
        if ! systemctl disable --now displaylink.service; then
            echo "ERROR: could not disable/stop displaylink.service." >&2
            exit 1
        fi
    fi
    installed_managed=()
    for pkg in "${MANAGED_PACKAGES[@]}"; do
        rpm -q "$pkg" >/dev/null 2>&1 && installed_managed+=("$pkg")
    done
    if [ "${#installed_managed[@]}" -gt 0 ] && \
       ! run_system_dnf -y remove "${installed_managed[@]}"; then
        echo "ERROR: DisplayLink package removal failed; use the snapshot to roll back if needed." >&2
        exit 1
    fi
    for pkg in "${MANAGED_PACKAGES[@]}"; do
        if rpm -q "$pkg" >/dev/null 2>&1; then
            echo "ERROR: managed DisplayLink package remains installed: $pkg" >&2
            exit 1
        fi
    done

    repo_owned=$(state_value repo_owned)
    key_file_owned=$(state_value key_file_owned)
    rpm_key_owned=$(state_value rpm_key_owned)
    if [ "$repo_owned" = yes ]; then
        rm -f -- "$REPO_FILE"
        [ ! -e "$REPO_FILE" ] && [ ! -L "$REPO_FILE" ] || {
            echo "ERROR: managed DisplayLink repository file remains." >&2
            exit 1
        }
        sync -f /etc/yum.repos.d
    fi

    # A user may have added another negativo17 repository after installation.
    # In that case ownership transfers to that repository and the shared key is
    # preserved rather than breaking an unrelated explicit opt-in.
    shared_key_use=0
    if grep -RqsF -- "$NEGATIVO17_KEY_LOCAL" /etc/yum.repos.d 2>/dev/null; then
        shared_key_use=1
        echo "NOTICE: preserving the negativo17 key because another repository references it."
    fi
    if [ "$shared_key_use" -eq 0 ]; then
        if [ "$key_file_owned" = yes ]; then
            rm -f -- "$NEGATIVO17_KEY_LOCAL"
            [ ! -e "$NEGATIVO17_KEY_LOCAL" ] && \
                [ ! -L "$NEGATIVO17_KEY_LOCAL" ] || {
                echo "ERROR: managed negativo17 key file remains." >&2
                exit 1
            }
            sync -f /etc/pki/rpm-gpg
        fi
        if [ "$rpm_key_owned" = yes ] && rpm_key_present; then
            rpmkeys --delete "$NEGATIVO17_FPR_EXPECTED"
        fi
    fi
    if [ "$rpm_key_owned" = yes ] && [ "$shared_key_use" -eq 0 ] && rpm_key_present; then
        echo "ERROR: NoID Privacy-owned negativo17 RPM key remains after uninstall." >&2
        exit 1
    fi
    rm -f -- "$STATE_FILE"
    sync -f "$STATE_DIR"
    rmdir -- "$STATE_DIR"
    sync -f /var/lib/noid-privacy
    echo "Done. Shared dependencies are preserved; reboot to fully unload evdi."
    exit 0
fi

cat <<'WARNING'

 ┌────────────────────────────────────────────────────────────────────┐
 │ DisplayLink installation                                           │
 │                                                                    │
 │ This will:                                                         │
 │   1. Add third-party repo: negativo17.org (Fedora Multimedia)      │
 │   2. Install evdi kernel module (GPL, via akmod or DKMS fallback)  │
 │   3. Install displaylink (PROPRIETARY DisplayLink daemon)          │
 │   4. Guide MOK enrollment if Secure Boot is active                 │
 │                                                                    │
 │ DisplayLink Corp EULA applies to the proprietary daemon.           │
 │ The third-party repository has unsigned metadata; package          │
 │ signatures are fingerprint-pinned and its package namespace is     │
 │ restricted to DisplayLink/EVDI. The display daemon processes       │
 │ screen content; NoID Privacy makes no telemetry/privacy promise.   │
 │                                                                    │
 │ If you only use Thunderbolt/USB4 docks with DP Alt-Mode, CANCEL —  │
 │ those work out-of-the-box without DisplayLink software.            │
 │                                                                    │
 │ Uninstall later: sudo noid-install-displaylink --uninstall         │
 └────────────────────────────────────────────────────────────────────┘

WARNING

# Decide variant
VARIANT="auto"
case "$ACTION" in
    --akmod) VARIANT="akmod" ;;
    --dkms)  VARIANT="dkms"  ;;
    install) VARIANT="auto"  ;;
esac

read -rp "Continue? [y/N] " CONFIRM
[[ "$CONFIRM" =~ ^[yY]$ ]] || { echo "Aborted."; exit 0; }

if [ -e "$STATE_DIR" ] || [ -L "$STATE_DIR" ]; then
    echo "ERROR: DisplayLink state already exists at $STATE_DIR." >&2
    echo "Use --uninstall for a valid managed install; otherwise inspect/recover the retained transaction." >&2
    exit 1
fi
if find /var/lib/noid-privacy -maxdepth 1 -type d -name '.displaylink-txn.*' \
        -print -quit 2>/dev/null | grep -q .; then
    echo "ERROR: an interrupted DisplayLink transaction ledger remains." >&2
    echo "Inspect it and the pre-install snapshot before retrying; no automatic trust absorption is performed." >&2
    exit 1
fi
if [ -e "$REPO_FILE" ] || [ -L "$REPO_FILE" ]; then
    echo "ERROR: $REPO_FILE already exists without a NoID Privacy ownership ledger." >&2
    exit 1
fi
for pkg in "${MANAGED_PACKAGES[@]}"; do
    if rpm -q "$pkg" >/dev/null 2>&1; then
        echo "ERROR: $pkg is already installed outside the NoID Privacy ownership ledger." >&2
        echo "Refusing to claim or later remove administrator-owned package state." >&2
        exit 1
    fi
done

# System-changing package/repository operations require the promised rollback
# point. Do not begin if the snapshot mechanism is unavailable or unhealthy.
if ! command -v noid-snap-pre >/dev/null 2>&1; then
    echo "ERROR: noid-snap-pre is required for DisplayLink installation." >&2
    exit 1
fi
if ! noid-snap-pre "DisplayLink install ($VARIANT)"; then
    echo "ERROR: pre-install snapshot failed; no repository was added." >&2
    exit 1
fi

# ---------------------------------------------------------------------
# Step 1: Add negativo17 repo (GPG-verified, fingerprint-pinned)
# ---------------------------------------------------------------------
#
# GPG TRUST EXCEPTION:
#   `repo_gpgcheck=0` is set below. negativo17.org does not publish signed
#   repository metadata. Package PAYLOAD signatures remain mandatory
#   (`gpgcheck=1`). HTTPS protects transport, not a compromised publisher;
#   the closed `includepkgs` namespace limits what unsigned metadata can offer.
#
# GPG KEY FINGERPRINT PIN (matches VSCodium pattern in Module 08):
#   Verified against the publisher's current key repository and live URL.
#   Source: https://github.com/negativo17/gpg-keys
#
#     pub   rsa4096 2024-09-01 [SC] [expires: 2029-08-31]
#           0C5D 0F47 0484 AE2F C40A  9B65 97F3 0089 93E8 909B
# Without this pin, `dnf install` would TOFU any key served at the URL —
# a compromised negativo17.org host or MITM (despite TLS) could substitute
# a malicious key and signed-package check would still pass against the
# adversary's key. The pin verifies the downloaded key's primary fingerprint
# matches the expected value before import.
# One retained ledger owns every mutation made by this helper. The DNF5
# transaction ID is captured and validated so a post-package akmod/DKMS or
# service failure can undo the exact package transaction before trust files are
# removed. Power loss leaves the pending directory visible and fail-closed.
INSTALL_COMMITTED=0
KEY_TMP=""
KEY_CANDIDATE=""
REPO_CANDIDATE=""
CURRENT_TX_ID=""
KEY_FILE_OWNED=no
RPM_KEY_OWNED=no
REPO_OWNED=no
REPO_SHA256=""
KEY_FILE_SHA256=external
TX_DIR=""

latest_history_id() {
    run_system_dnf history list --json | python3 -c '
import json, sys
rows = json.load(sys.stdin)
print(max((int(row["id"]) for row in rows), default=0))
'
}

transaction_contains() {
    local tx_id=$1 required=$2
    run_system_dnf history info --json "$tx_id" | python3 -c '
import json, re, sys
required = set(sys.argv[1].split(","))
rows = json.load(sys.stdin)
if len(rows) != 1:
    raise SystemExit(1)
names = set()
for item in rows[0].get("packages", []):
    if item.get("action") not in {"Install", "Upgrade", "Reinstall", "Downgrade"}:
        continue
    nevra = item.get("nevra", "")
    # Remove arch, release/version and epoch while retaining hyphens in name.
    match = re.match(r"^(.*?)-(?:[0-9]+:)?[0-9][^-]*-", nevra)
    if match:
        names.add(match.group(1))
raise SystemExit(0 if required <= names else 1)
' "$required"
}

rollback_current_transaction() {
    [ -n "$CURRENT_TX_ID" ] || return 0
    echo "  Rolling back exact DNF transaction $CURRENT_TX_ID..." >&2
    if ! run_system_dnf -y history undo "$CURRENT_TX_ID"; then
        echo "ERROR: DNF transaction $CURRENT_TX_ID could not be undone." >&2
        return 1
    fi
    for pkg in "${MANAGED_PACKAGES[@]}"; do
        if rpm -q "$pkg" >/dev/null 2>&1; then
            echo "ERROR: $pkg remains after DNF transaction rollback." >&2
            return 1
        fi
    done
    CURRENT_TX_ID=""
}

cleanup_displaylink_install() {
    rc=$?
    cleanup_failed=0
    [ -z "$KEY_TMP" ] || rm -f -- "$KEY_TMP" || cleanup_failed=1
    [ -z "$KEY_CANDIDATE" ] || rm -f -- "$KEY_CANDIDATE" || cleanup_failed=1
    [ -z "$REPO_CANDIDATE" ] || rm -f -- "$REPO_CANDIDATE" || cleanup_failed=1
    if [ "$rc" -ne 0 ] && [ "$INSTALL_COMMITTED" -eq 0 ]; then
        if systemctl list-unit-files displaylink.service --no-legend 2>/dev/null \
                | grep -q '^displaylink\.service'; then
            systemctl disable --now displaylink.service >/dev/null 2>&1 || true
        fi
        rollback_current_transaction || cleanup_failed=1
        [ "$REPO_OWNED" = no ] || rm -f -- "$REPO_FILE" || cleanup_failed=1
        if systemctl is-active --quiet displaylink.service 2>/dev/null || \
           systemctl is-enabled --quiet displaylink.service 2>/dev/null; then
            cleanup_failed=1
        fi
        shared_key_use=0
        if grep -RqsF -- "$NEGATIVO17_KEY_LOCAL" /etc/yum.repos.d 2>/dev/null; then
            shared_key_use=1
            echo "NOTICE: preserving the negativo17 key now referenced by another repository." >&2
        fi
        if [ "$shared_key_use" -eq 0 ]; then
            [ "$KEY_FILE_OWNED" = no ] || rm -f -- "$NEGATIVO17_KEY_LOCAL" || cleanup_failed=1
            if [ "$RPM_KEY_OWNED" = yes ] && rpm_key_present; then
                rpmkeys --delete "$NEGATIVO17_FPR_EXPECTED" || cleanup_failed=1
            fi
            if [ "$RPM_KEY_OWNED" = yes ] && rpm_key_present; then
                cleanup_failed=1
            fi
        fi
        if [ "$cleanup_failed" -eq 0 ]; then
            if [ -n "$TX_DIR" ]; then
                case "$TX_DIR" in
                    /var/lib/noid-privacy/.displaylink-txn.*)
                        find "$TX_DIR" -xdev -mindepth 1 -delete && \
                            rmdir -- "$TX_DIR" || cleanup_failed=1
                        ;;
                    *)
                        cleanup_failed=1
                        ;;
                esac
            fi
        fi
        if [ "$cleanup_failed" -eq 0 ]; then
            echo "DisplayLink installation failed; package, repository and owned key state were rolled back." >&2
        else
            echo "ERROR: DisplayLink rollback is incomplete; retained ledger: ${TX_DIR:-none}" >&2
            echo "Use the pre-install snapshot and inspect DNF history before retrying." >&2
            rc=1
        fi
    fi
    trap - EXIT
    exit "$rc"
}
trap cleanup_displaylink_install EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -L /var/lib/noid-privacy ] || \
   { [ -e /var/lib/noid-privacy ] && [ ! -d /var/lib/noid-privacy ]; }; then
    echo "ERROR: /var/lib/noid-privacy is not a real directory." >&2
    exit 1
fi
install -d -m 0755 -o root -g root /var/lib/noid-privacy
[ "$(stat -Lc '%u:%g:%a' /var/lib/noid-privacy 2>/dev/null || true)" = 0:0:755 ] && \
    restore_and_verify_label /var/lib/noid-privacy || {
    echo "ERROR: /var/lib/noid-privacy metadata or label is invalid." >&2
    exit 1
}
TX_DIR=$(mktemp -d /var/lib/noid-privacy/.displaylink-txn.XXXXXX)
chmod 0700 "$TX_DIR"
chown root:root "$TX_DIR"
restore_and_verify_label "$TX_DIR"
printf 'schema\t1\nstatus\tpending\n' > "$TX_DIR/transaction.tsv"
chmod 0600 "$TX_DIR/transaction.tsv"
chown root:root "$TX_DIR/transaction.tsv"
restore_and_verify_label "$TX_DIR/transaction.tsv"
sync -- "$TX_DIR/transaction.tsv"
sync -f "$TX_DIR"

echo ""
echo "[1/5] Adding negativo17.org Fedora Multimedia repo..."

# Pre-import + fingerprint-pin gate (refuses install on mismatch)
KEY_TMP=$(mktemp /tmp/negativo17-key.XXXXXX.gpg)
if ! curl --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' --tlsv1.2 --max-redirs 3 \
        --connect-timeout 10 --max-time 30 \
        --output "$KEY_TMP" "$NEGATIVO17_KEY_URL"; then
    echo "ERROR: failed to fetch negativo17 GPG key from $NEGATIVO17_KEY_URL" >&2
    exit 1
fi
mapfile -t DOWNLOADED_FPRS < <(primary_key_fingerprints "$KEY_TMP")
if [ "${#DOWNLOADED_FPRS[@]}" -ne 1 ] || \
   [ "${DOWNLOADED_FPRS[0]:-}" != "$NEGATIVO17_FPR_EXPECTED" ]; then
    echo "ERROR: negativo17 GPG key fingerprint mismatch (possible MITM/key-rotation)" >&2
    echo "  expected: $NEGATIVO17_FPR_EXPECTED" >&2
    echo "  actual primary keys: ${DOWNLOADED_FPRS[*]:-none}" >&2
    echo "  Aborting DisplayLink install. If negativo17 has rotated the key intentionally," >&2
    echo "  update NEGATIVO17_FPR_EXPECTED in /usr/local/bin/noid-install-displaylink." >&2
    exit 1
fi
echo "  [OK] negativo17 GPG key fingerprint verified: ${DOWNLOADED_FPRS[0]}"
if [ -e "$NEGATIVO17_KEY_LOCAL" ] || [ -L "$NEGATIVO17_KEY_LOCAL" ]; then
    if ! key_file_matches_identity "$NEGATIVO17_KEY_LOCAL"; then
        echo "ERROR: existing negativo17 key file has unsafe metadata, label or identity." >&2
        exit 1
    fi
else
    KEY_CANDIDATE=$(mktemp /etc/pki/rpm-gpg/.noid-negativo17.XXXXXX)
    install -m 0644 -o root -g root "$KEY_TMP" "$KEY_CANDIDATE"
    restore_and_verify_label "$KEY_CANDIDATE"
    sync -- "$KEY_CANDIDATE"
    mv -fT -- "$KEY_CANDIDATE" "$NEGATIVO17_KEY_LOCAL"
    KEY_CANDIDATE=""
    restore_and_verify_label "$NEGATIVO17_KEY_LOCAL"
    sync -- "$NEGATIVO17_KEY_LOCAL"
    sync -f /etc/pki/rpm-gpg
    key_file_matches_identity "$NEGATIVO17_KEY_LOCAL" || {
        echo "ERROR: installed negativo17 key failed its postcondition." >&2
        exit 1
    }
    KEY_FILE_OWNED=yes
fi
if [ "$KEY_FILE_OWNED" = yes ]; then
    KEY_FILE_SHA256=$(sha256sum "$NEGATIVO17_KEY_LOCAL" | awk '{print $1}')
else
    KEY_FILE_SHA256=external
fi
if ! rpm_key_present; then
    if ! rpmkeys --import "$NEGATIVO17_KEY_LOCAL"; then
        echo "ERROR: negativo17 key import failed." >&2
        exit 1
    fi
    RPM_KEY_OWNED=yes
fi
rm -f "$KEY_TMP"
KEY_TMP=""

REPO_CANDIDATE=$(mktemp /etc/yum.repos.d/.noid-displaylink.XXXXXX)
cat > "$REPO_CANDIDATE" <<REPO
# Managed by noid-install-displaylink; do not broaden includepkgs.
[fedora-multimedia]
name=NoID Privacy restricted DisplayLink packages from negativo17 - \$basearch
baseurl=https://negativo17.org/repos/multimedia/fedora-\$releasever/\$basearch/
enabled=1
gpgcheck=1
repo_gpgcheck=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-negativo17
skip_if_unavailable=False
includepkgs=displaylink,xorg-x11-displaylink,libevdi*,akmod-evdi,kmod-evdi,dkms-evdi,evdi-kmod-common
REPO
chmod 0644 "$REPO_CANDIDATE"
chown root:root "$REPO_CANDIDATE"
restore_and_verify_label "$REPO_CANDIDATE"
sync -- "$REPO_CANDIDATE"
mv -fT -- "$REPO_CANDIDATE" "$REPO_FILE"
REPO_CANDIDATE=""
restore_and_verify_label "$REPO_FILE"
sync -- "$REPO_FILE"
sync -f /etc/yum.repos.d
if [ ! -f "$REPO_FILE" ] || [ -L "$REPO_FILE" ] || \
   [ "$(stat -Lc '%u:%g:%a:%h' "$REPO_FILE" 2>/dev/null || true)" != 0:0:644:1 ] || \
   ! selinux_label_ok "$REPO_FILE"; then
    echo "ERROR: restricted DisplayLink repository failed its postcondition." >&2
    exit 1
fi
REPO_SHA256=$(sha256sum "$REPO_FILE" | awk '{print $1}')
REPO_OWNED=yes

# ---------------------------------------------------------------------
# Step 2: Refresh metadata
# ---------------------------------------------------------------------
echo "[2/5] Refreshing DNF metadata..."
run_system_dnf --repo=fedora,updates,fedora-multimedia -y --refresh makecache

# ---------------------------------------------------------------------
# Step 3: Install with variant selection + fallback
# ---------------------------------------------------------------------
INSTALLED_VARIANT=""

run_install_transaction() {
    local required_csv=$1 before_id after_id tx_id dnf_rc=0
    shift
    before_id=$(latest_history_id)
    run_system_dnf --repo=fedora,updates,fedora-multimedia -y install "$@" || dnf_rc=$?
    after_id=$(latest_history_id)
    if [ "$after_id" -gt "$before_id" ]; then
        # An unrelated DNF transaction can land between the install and this
        # inspection. Claim exactly the newest recorded transaction that
        # carries the requested packages, so rollback ownership never binds
        # to foreign package state.
        for (( tx_id = after_id; tx_id > before_id; tx_id-- )); do
            if transaction_contains "$tx_id" "$required_csv"; then
                CURRENT_TX_ID=$tx_id
                printf 'dnf_transaction\t%s\n' "$CURRENT_TX_ID" >> "$TX_DIR/transaction.tsv"
                sync -- "$TX_DIR/transaction.tsv"
                break
            fi
        done
        if [ -z "$CURRENT_TX_ID" ]; then
            # New transactions exist but none carries the requested packages,
            # so rollback ownership cannot be established. Stop the whole
            # installer: a variant fallback on top of unowned package state
            # is refused, and the EXIT trap keeps trust-artifact cleanup.
            echo "ERROR: no recorded DNF transaction carries the requested DisplayLink packages." >&2
            echo "Review transactions $((before_id + 1))-$after_id manually with: dnf history info <id>" >&2
            exit 4
        fi
    fi
    if [ "$dnf_rc" -ne 0 ]; then
        echo "ERROR: DisplayLink DNF transaction returned rc=$dnf_rc." >&2
        return "$dnf_rc"
    fi
    if [ -z "$CURRENT_TX_ID" ]; then
        echo "ERROR: successful install produced no auditable DNF transaction ID." >&2
        return 1
    fi
}

try_akmod() {
    echo "[3/5] Attempting akmod-evdi install (Fedora-standard path)..."
    if ! run_install_transaction 'akmod-evdi,displaylink' akmod-evdi displaylink; then
        return 1
    fi
    # akmod needs a kernel build trigger. akmods is automatic on kernel
    # update but must be prodded for the CURRENT running kernel.
    echo "  Building evdi module for running kernel: $(uname -r)"
    if akmods --force --kernels "$(uname -r)" 2>&1 | tail -3; then
        if modinfo -k "$(uname -r)" evdi >/dev/null 2>&1; then
            INSTALLED_VARIANT="akmod"
            return 0
        fi
    fi
    echo "  akmods build did NOT produce evdi.ko — akmod path failed."
    return 1
}

try_dkms() {
    echo "[3/5] Attempting dkms-evdi install (community fallback)..."
    if ! run_install_transaction 'dkms-evdi,displaylink' \
            dkms kernel-devel displaylink dkms-evdi; then
        return 1
    fi
    # dkms autoinstall builds for all installed kernels
    if dkms autoinstall 2>&1 | tail -3; then
        if dkms status 2>/dev/null | grep -qE "^evdi.*installed"; then
            INSTALLED_VARIANT="dkms"
            return 0
        fi
    fi
    echo "  dkms build failed — investigate with: dkms status"
    return 1
}

case "$VARIANT" in
    akmod)
        try_akmod || { echo "akmod install failed. Try --dkms." >&2; exit 1; }
        ;;
    dkms)
        try_dkms  || { echo "dkms install failed. Check 'dkms status'." >&2; exit 1; }
        ;;
    auto)
        if ! try_akmod; then
            echo ""
            echo "  akmod failed — undoing its exact package transaction before DKMS..."
            echo ""
            if ! rollback_current_transaction; then
                echo "Could not restore the pre-akmod package state; DKMS fallback refused." >&2
                exit 1
            fi
            try_dkms || { echo "Both akmod AND dkms failed. File an issue." >&2; exit 1; }
        fi
        ;;
esac

echo "  evdi module installed via: $INSTALLED_VARIANT"

# ---------------------------------------------------------------------
# Step 4: Secure Boot / MOK enrollment guidance (variant-specific paths)
# ---------------------------------------------------------------------
SB_STATE="disabled"
if command -v mokutil >/dev/null 2>&1; then
    if mokutil --sb-state 2>/dev/null | grep -qi "enabled"; then
        SB_STATE="enabled"
    fi
fi

echo ""
echo "[4/5] Secure Boot / MOK status..."
if [ "$SB_STATE" = "enabled" ]; then
    case "$INSTALLED_VARIANT" in
        akmod)
            MOK_PUB="/etc/pki/akmods/certs/public_key.der"
            ;;
        dkms)
            MOK_PUB="/var/lib/dkms/mok.pub"
            ;;
    esac

    if [ ! -f "$MOK_PUB" ]; then
        echo "ERROR: Secure Boot is enabled but the MOK public key is absent: $MOK_PUB" >&2
        echo "Refusing to report a driver that cannot be enrolled and loaded." >&2
        exit 1
    else
        echo ""
        echo "  Secure Boot is ENABLED. The evdi kernel module must be signed"
        echo "  with a Machine Owner Key (MOK) enrolled in UEFI. Steps:"
        echo ""
        echo "   1. Import the MOK (sets a password for MOK Manager):"
        echo "        sudo mokutil --import $MOK_PUB"
        echo ""
        echo "   2. Reboot. At the blue MOK Manager screen:"
        echo "        Enroll MOK → Continue → Yes → enter the password you just set"
        echo ""
        echo "   3. After boot, verify evdi is loaded:"
        echo "        lsmod | grep evdi"
        echo ""
        echo "  Without MOK enrollment, evdi will NOT load under Secure Boot."
        echo "  Full walkthrough: /usr/share/doc/noid-privacy/19-secure-boot-mok.md"
    fi
else
    echo "  Secure Boot appears disabled — evdi should load directly."
fi

# ---------------------------------------------------------------------
# Step 5: Enable displaylink service
# ---------------------------------------------------------------------
echo ""
echo "[5/5] Enabling displaylink.service..."
if ! systemctl enable displaylink.service; then
    echo "ERROR: displaylink.service could not be enabled." >&2
    exit 1
fi
if [ "$(systemctl is-enabled displaylink.service 2>/dev/null)" != "enabled" ]; then
    echo "ERROR: displaylink.service did not reach the enabled state." >&2
    exit 1
fi
if ! rpm -q displaylink >/dev/null 2>&1 || ! modinfo -k "$(uname -r)" evdi >/dev/null 2>&1; then
    echo "ERROR: final DisplayLink package/module postcondition failed." >&2
    exit 1
fi

state_tmp="$TX_DIR/install-state.tsv.tmp"
{
    printf 'schema\t2\n'
    printf 'variant\t%s\n' "$INSTALLED_VARIANT"
    printf 'repo_owned\t%s\n' "$REPO_OWNED"
    printf 'key_file_owned\t%s\n' "$KEY_FILE_OWNED"
    printf 'rpm_key_owned\t%s\n' "$RPM_KEY_OWNED"
    printf 'install_transaction_id\t%s\n' "$CURRENT_TX_ID"
    printf 'repo_sha256\t%s\n' "$REPO_SHA256"
    printf 'key_file_sha256\t%s\n' "$KEY_FILE_SHA256"
} > "$state_tmp"
chmod 0600 "$state_tmp"
chown root:root "$state_tmp"
restore_and_verify_label "$state_tmp"
sync -- "$state_tmp"
mv -fT -- "$state_tmp" "$TX_DIR/install-state.tsv"
restore_and_verify_label "$TX_DIR/install-state.tsv"
sync -- "$TX_DIR/install-state.tsv"
rm -f -- "$TX_DIR/transaction.tsv"
sync -- "$TX_DIR"
mv -T -- "$TX_DIR" "$STATE_DIR"
TX_DIR="$STATE_DIR"
restore_and_verify_label "$STATE_DIR"
restore_and_verify_label "$STATE_FILE"
sync -- "$STATE_FILE"
sync -f /var/lib/noid-privacy
validate_state || {
    echo "ERROR: committed DisplayLink ownership ledger failed validation." >&2
    exit 1
}
INSTALL_COMMITTED=1

echo ""
echo "DisplayLink install finished (variant: $INSTALLED_VARIANT)."
echo ""
echo "Next steps:"
if [ "$SB_STATE" = "enabled" ]; then
    echo "  Before reboot: complete MOK enrollment when prompted (see above)."
fi
echo "  1. Reboot: sudo reboot"
echo "  2. Plug your DisplayLink dock. If USBGuard blocks it:"
echo "       sudo noid-usbguard-devices allow"
echo "  3. Verify: lsmod | grep evdi && systemctl status displaylink"
echo ""
echo "Uninstall later with: sudo noid-install-displaylink --uninstall"
DISPLAYLINK_EOF

chmod 755 /usr/local/bin/noid-install-displaylink
chown root:root /usr/local/bin/noid-install-displaylink
echo "  [OK] /usr/local/bin/noid-install-displaylink installed (755)"

# ----------------------------------------------------------------------------
# Step 10ca: Install /usr/share/doc/noid-privacy/14-usbguard.md
# ----------------------------------------------------------------------------
# General user-facing USBGuard doc — the "how do I allow a USB device?"
# workflow. Cross-referenced from 00-README.md, 01-getting-started.md,
# 00-cheatsheet.md, and 08-masked-services.md.
# Authoritative for the allow-device flow; docking-stations.md (step 10d)
# covers Thunderbolt/USB4/DisplayLink-specific edge cases.

mkdir -p /usr/share/doc/noid-privacy

cat > /usr/share/doc/noid-privacy/14-usbguard.md <<'USBG_DOC_EOF'
# USBGuard — USB Device Whitelisting

USBGuard is a device-level firewall for USB. By default, every USB
device that gets plugged in is **blocked** until you explicitly
allow it. This reduces the rogue-device/BadUSB attack surface, including
devices that impersonate keyboards or network adapters. It does **not**
protect against destructive electrical "USB killer" hardware, malicious
charger power behavior, compromised firmware in an already-allowed device,
or every data-exfiltration path. Use a charge-only cable/data blocker when
you need a physical charging-only boundary.

## How it works

The USBGuard daemon (`usbguard-daemon`, config
`/etc/usbguard/usbguard-daemon.conf`) reads rules from
`/etc/usbguard/rules.conf` + `/etc/usbguard/rules.d/` at startup.
When a USB device is inserted, its descriptors are matched against
the rules. If no rule matches → blocked. On allow with `--permanent`,
a device-specific rule is appended to or updated in `rules.conf` so
the decision survives reboots.

## First-boot state machine

This image initializes USBGuard through
`noid-usbguard-firstboot.service`:

1. **Emergency mode** (initial policy generation failed or produced no
   usable device rules):
   HID devices (keyboard + mouse) are temporarily allowed so you can
   type. Everything else stays blocked.
2. **Initializing** is a transient commit state: a real policy has been
   written, but the daemon and D-Bus service have not both passed their
   post-start checks yet. A successful firstboot run replaces it with
   `real`; an interrupted run remains retryable.
3. **Real mode** (after firstboot service runs — first successful
   boot with devices plugged in):
   The firstboot service enumerates every currently-connected device
   via `usbguard generate-policy` and writes a permanent rule for
   each. After this, only devices present at first boot are allowed
   — ANY new device requires explicit allow.

Current state is reported in
`/var/lib/noid-privacy/usbguard-status.txt` (key=value):

```
STATE=real
DEVICE_COUNT=5
FALLBACK_ACTIVE=no
LAST_RUN=2026-07-27T12:34:56+02:00
```

The read-only `noid-status` command (Module 13) parses this file and
reports the closed state vocabulary (`real`, `emergency`, or transient
`initializing`). The file contains exactly these four keys.

### USB ModeSwitch / dual-identity adapters

Some USB Wi-Fi and mobile-network adapters are “flip-flop” devices. After a
real USB power loss they first enumerate as a small mass-storage device so
`usb_modeswitch` can eject the bundled driver image; they then disconnect and
return with a different network-device identity. Warm reboots can retain the
second identity, so the precursor may first appear only after a later cold
start.

`usbguard generate-policy` can bind only identities that exist when it runs.
It cannot safely predict a future precursor from the already-switched device,
and NoID Privacy does not ship broad vendor/product or mass-storage allow rules:
those identifiers and interface classes can be spoofed. The first time
the precursor appears, approve that exact blocked row once with the supported
manager (which delegates admission to the specialized wrapper):

```bash
sudo noid-usbguard-devices allow
```

For a precursor recognized by a root-owned native `usb_modeswitch` data entry,
the wrapper persists a native USBGuard rule containing the exact vendor/product
ID, USBGuard descriptor hash and complete interface set. It deliberately omits
`via-port`, `parent-hash` and `with-connect-type`: those values describe USB
topology, so retaining them would break the pair after moving it below another
controller or external hub. The rule remains device-specific and carries the
`noid-modeswitch-portable-v1` ownership label.

The admission wrapper then waits for the same physical port and USB parent to
re-enumerate. That correlation identifies the immediate transition but never
authorizes it. If the resulting identity already has the same helper-owned,
topology-independent rule, the wrapper verifies both identities and finishes.
Otherwise it displays the second identity and requires a **second, separate
confirmation** before persisting that identity's exact portable rule.
Immediately before the second change it re-reads the device set and rejects a
changed or recycled runtime identity. Old unconditional rules for the same
exact descriptor hash are removed only when they carry topology attributes;
labelled or conditional operator policy is preserved. The wrapper never
auto-allows a second identity.

If the second confirmation is refused or closed, no topology-independent rule
is added for that identity. The precursor remains portable, but the adapter can
still be blocked after a port, hub or controller change until the second exact
identity is separately approved.

This portability has an explicit trade-off: a device that reproduces the same
descriptor hash and interfaces can match on any USB topology instead of only
below one parent. USBGuard documents `hash` as its most specific device
identifier; it is still descriptor identity, not cryptographic hardware
authentication. A successful first authorization normally triggers the native
udev/`usb_modeswitch` transition without another replug. If the hardware does
not re-enumerate within the bounded wait, unplug and reconnect it once.

## Device overview and management

The supported front door is:

```bash
sudo noid-usbguard-devices
```

It shows two related inventories without printing descriptor hashes or serial
numbers:

- every currently known USB device and whether its observed state is backed by
  durable policy, is only a session decision, or conflicts with the durable
  rule that will apply after reconnect;
- every persistent allow rule, including rules whose device is currently
  offline (for example a ModeSwitch storage precursor).

The manager parses the root-only `rules.conf` through
`usbguard-rule-parser` and compares those canonical bytes with the daemon's
ordered runtime policy. `list-devices` alone has no persistent marker, while
`list-rules -d` reports matching current targets and cannot by itself prove
durability or effective precedence. If daemon/file drift, conditional policy,
or runtime-only policy rules prevent an exact conclusion, the manager says so
and disables guided revocation rather than guessing.

Direct modes are:

```bash
sudo noid-usbguard-devices status
sudo noid-usbguard-devices allow [device-id]
sudo noid-usbguard-devices revoke [rule-id]
```

`noid-usbguard-allow-device` remains the compatibility and specialized
admission backend; the manager's `allow` action executes those same reviewed
bytes.

## Allowing a new USB device — normal workflow

### Step 1 — Plug the device in

It's blocked. During an active graphical session, `usbguard-notifier` shows
the native Allow/Reject notification. A device blocked earlier in boot cannot
be replayed by that event listener, so the separate graphical-login catch-up
queries the current blocked set once and offers **Open USBGuard Devices**. No
`/dev/sdN`, no kernel keyboard mapping, and no automatic authorization occurs.

### Step 2 — Run the wrapper

```bash
sudo noid-usbguard-devices allow
```

Wraps `usbguard list-devices -b` (blocked devices) and gives every row one
explicit menu number such as `[1]`. The device-provided name comes first,
followed by the vendor/product ID, interface class and separately labelled
informational `USBGuard ID`; long serial and descriptor hashes stay out of the
selection display. Enter that bracketed menu number. The wrapper safely maps
the menu choice to the current device ID. Ordinary devices use
`usbguard allow-device --permanent <device-id>`. Recognized ModeSwitch
precursors use the separately documented portable-rule path above.

When the selected row is a recognized ModeSwitch storage precursor, the same
wrapper also observes the bounded re-enumeration. An already-portable second
identity is verified without another change. A topology-bound legacy rule does
not receive that verdict. The wrapper instead shows the identity and asks
separately before replacing the old binding with its exact portable rule.
Refusing or closing the second prompt adds no portable rule for that identity.
Same-port correlation never replaces either user decision, and no vendor-wide
exception is added.

For non-interactive use, the optional command-line argument remains the
USBGuard device ID rather than the menu number:

```bash
sudo noid-usbguard-devices allow <device-id>
```

### Step 3 — Verify

```bash
lsblk                          # for storage devices
lsusb                          # general listing
usbguard list-devices          # rows begin with numeric ID and allow/block state
```

The rule is now persistent in `/etc/usbguard/rules.conf`. Ordinary devices
remain authorized on reconnect only while USBGuard's stored descriptor and
topology attributes match. Only the separately confirmed ModeSwitch path above
deliberately omits port, parent and connection-topology attributes.

## Alternative — click-to-allow from the notification

For a device inserted while the graphical session is already active, the
GNOME-integrated `usbguard-notifier` notification includes an **Allow** button.
Its upstream action is temporary: it authorizes the current device instance
without appending a durable rule. Reconnect or reboot can therefore prompt
again.

For a device blocked before login, the one-shot catch-up notification offers
one **Open USBGuard Devices** action. Closing the notification keeps every
device blocked. The action opens the interactive manager directly in a
terminal; it still authorizes nothing until the user selects **Allow** and
confirms the exact device. The catch-up reports only a count and never copies
device-provided names, identifiers, serials or hashes into the desktop
notification.

Normal users receive the minimum notifier-compatible named IPC profile:

```
Devices=list,modify,listen
Policy=list
Parameters=list,listen
Exceptions=listen
```

This prevents policy and daemon-parameter changes. USBGuard does not expose
separate privileges for temporary and permanent per-device modification,
however, so `Devices=modify` also lets that same user invoke the native
`usbguard allow-device --permanent` command directly. The supported persistent
workflow remains `sudo noid-usbguard-devices allow`: it creates rollback
evidence and guides selection, while root's separate ACL owns policy and
parameter administration. This is an upstream authorization-granularity limit,
not a claim that the wrapper is the only technically possible command.

## One-shot allow (this session only)

For a USB stick you only need once:

```bash
usbguard list-devices          # find the numeric N
usbguard allow-device <N>      # no --permanent → current device instance
# Authorization ends on disconnect/daemon reset; no durable rule is appended
```

## Revoking a persistent device allow

Use the manager so the durable rule and any unchanged connected runtime
instance are handled as two separate postconditions:

```bash
sudo noid-usbguard-devices revoke
```

The menu contains only exact persistent device allow rules. Broad rules,
conditional policy and USB-controller rules are never removed by the guided
path. HID/input rules carry an explicit immediate-lockout warning. The selected
rule is re-read byte-for-byte after confirmation, a pre-change snapshot is
required, the rule is removed through `usbguard remove-rule`, and unchanged
connected instances are then deauthorized with a non-permanent
`usbguard block-device`. ModeSwitch adapters can have two persistent identity
rules; review the overview again and revoke both when retiring the physical
adapter.

The manager refuses guided revocation while runtime-only policy rules are
loaded. USBGuard saves the complete current policy after `remove-rule`; without
that guard, an unrelated temporary policy rule could become durable as a side
effect.

The native alternative for one currently present ordinary device is:

```bash
sudo usbguard list-devices
sudo usbguard block-device --permanent <device-id>
```

USBGuard 1.1.4 upserts a matching device-specific rule at its existing rule ID
and appends only when no matching rule exists. Its older installed man-page
wording says “appended”; the current CLI help and daemon implementation say
“appended to or updated”. The manager uses remove-then-runtime-block instead so
the result is absence of durable trust, not a retained durable deny rule.

For expert manual removal of one policy rule:

```bash
sudo usbguard list-rules
sudo usbguard remove-rule <rule-id>
```

Device IDs and rule IDs are different namespaces: the first identifies a
currently known device, while the second identifies a persistent policy rule.
Review the exact row immediately before either state-changing command. Removing
a policy rule does not automatically deauthorize an already connected device;
blocking only the current instance does not remove a durable allow. That is why
the manager verifies both layers.

## Disabling USBGuard entirely (NOT recommended)

Stopping or disabling only `usbguard.service` is **not** an opt-out.
`AuthorizedDefault=none` remains active in the running kernel, so newly
inserted devices stay deauthorized; additionally, the enabled NoID Privacy
firstboot reconciler would enable the daemon again on the next boot.

For a bounded one-boot recovery, use path C under **Replacement keyboard**
below. A deliberate persistent opt-out must mask the reconcilers and both
daemon surfaces, then reboot so the USB controllers return to their kernel
defaults:

```bash
sudo systemctl mask --now \
  noid-usbguard-firstboot.service noid-usbguard-live-init.service \
  noid-usbguard-add-user.path noid-usbguard-add-user.service \
  usbguard.service usbguard-dbus.service
systemctl --user mask --now usbguard-notifier.service
sudo reboot
```

This removes USB device admission control after the reboot. Do not replace
the policy with a blanket `allow id *:*` rule: that keeps a misleading
"USBGuard active" surface while permanently reopening the BadUSB class.

To reverse an explicit persistent opt-out:

```bash
sudo systemctl unmask \
  noid-usbguard-firstboot.service noid-usbguard-live-init.service \
  noid-usbguard-add-user.path noid-usbguard-add-user.service \
  usbguard.service usbguard-dbus.service
sudo systemctl enable \
  noid-usbguard-firstboot.service noid-usbguard-live-init.service \
  noid-usbguard-add-user.path
sudo systemctl start noid-usbguard-firstboot.service
systemctl --user unmask usbguard-notifier.service
systemctl --user start usbguard-notifier.service
```

The firstboot service reuses the existing device policy; it does not relearn
devices when `STATE=real`.

## Auditd integration

USBGuard rule-file changes trigger audit events via the
`usbguard_config` watch in M12's rules. This means:

```bash
# Every rule-file change recorded
sudo ausearch -k usbguard_config -ts today
```

A USB-keyboard-based attacker who managed to allow a malicious device cannot
silently rewrite your rules: the change is recorded in auditd while M12's
immutable audit **configuration** is active. This is evidence, not a claim
that the log file itself is cryptographically immutable or tamper-proof
against an attacker who gains sufficient privilege.
USB device popups come from M14's `usbguard-notifier`, not M12's optional
keyed-integrity popup plugin.

## Dock-specific edge cases

- **USB-C / USB4 DisplayPort Alt-Mode and USB functions** can work without a
  Thunderbolt PCIe authorization daemon. Thunderbolt/USB4 PCIe functions are a
  separate firmware/kernel authorization boundary; see `docking-stations.md`.
- **DisplayLink / UGreen** USB-3 display-bridge docks: need the
  opt-in proprietary DisplayLink userspace driver plus EVDI (via
  `noid-install-displaylink` — also see `docking-stations.md`).

## Troubleshooting

### Replacement keyboard / "my keyboard is blocked and I can't log in"

On an established system the policy knows only the devices captured at
first boot plus your explicit allows — a NEW keyboard (replacement after
a defect, borrowed unit) is blocked like any other unknown device, and
the login screen shows no allow-notification (the notifier runs inside
your user session).

Two approaches that do NOT work here, so you don't waste time on them:
`systemd.unit=rescue.target`/`emergency.target` provide no maintenance
shell on this image (the root account is locked — see
99-troubleshooting.md "Boot-level problems"), and stopping the running
daemon does not unblock anything: the USB controllers stay in
deauthorize-by-default (`AuthorizedDefault=none` +
`RestoreControllerDeviceState=false`), so a device plugged in after
`systemctl stop usbguard` remains blocked.

Pick the first path that matches your situation:

**A — You are logged in (any allowed input device still works):**
click **Allow** on the usbguard-notifier notification, or run
`sudo noid-usbguard-devices allow`.

**B — You are at the login screen with a working (allowed) mouse:**
open the accessibility menu (the person icon in the login screen's top
bar), enable **Screen Keyboard**, enter your password with the on-screen
keyboard, log in, then continue with path A.

**C — No usable input device at all:** disable USBGuard for ONE boot
from the GRUB editor, then allow the new keyboard properly:

1. Reboot. At the GRUB menu press `e` on the default entry (reveal the
   hidden menu with ESC/F8 during POST — firmware keyboard handling is
   independent of USBGuard).
2. Append ` systemd.mask=noid-usbguard-firstboot.service systemd.mask=usbguard.service systemd.mask=usbguard-dbus.service`
   to the `linux ...` line, press Ctrl-X. All three units are masked for this
   one boot only and return automatically on the next boot. USB
   implicit-blocking is OFF for this single boot — that is the bounded,
   deliberate trade-off of this recovery path.
3. Log in normally (the new keyboard works this boot) and append ONLY
   the new keyboard's own reviewed rule. Do not pipe a fresh, changing
   `generate-policy` result straight into the active policy, do not relearn
   every attached device, and do not add a blanket
   `allow with-interface 03:*:*` rule.

```bash
# Capture one private candidate in USBGuard's root-owned configuration
# directory (generate-policy needs no daemon).
candidate=$(sudo mktemp /etc/usbguard/.keyboard-rule.XXXXXX)
sudo usbguard generate-policy | sudo tee "$candidate" >/dev/null
sudo chmod 0600 "$candidate"

# Edit the candidate until it contains exactly the one reviewed keyboard
# rule, then validate its grammar.
sudoedit "$candidate"
sudo usbguard-rule-parser -f "$candidate"

# Build and validate a same-directory replacement for the complete policy.
policy=$(sudo mktemp /etc/usbguard/.rules.conf.recovery.XXXXXX)
sudo cp /etc/usbguard/rules.conf "$policy"
printf '\n' | sudo tee -a "$policy" >/dev/null
sudo cat "$candidate" | sudo tee -a "$policy" >/dev/null
sudo usbguard-rule-parser -f "$policy"
sudo chown root:root "$policy"
sudo chmod 0600 "$policy"
sudo restorecon -F "$policy"
sudo sync -- "$policy"
sudo mv -fT "$policy" /etc/usbguard/rules.conf
sudo restorecon -F /etc/usbguard/rules.conf
sudo sync -- /etc/usbguard/rules.conf
sudo sync -f /etc/usbguard
sudo rm -f "$candidate"
```

4. `sudo reboot`. The daemon starts normally again and the new keyboard
   is allowed by its own device-specific rule. The rules.conf change is
   ordinary AIDE-visible drift — review it like any policy edit.

### "usbguard-daemon won't start"

```bash
sudo systemctl status usbguard -l
sudo ausearch -m avc -ts recent | grep usbguard
```

SELinux context corruption in `/etc/usbguard/` is the most common
cause. Fix:

```bash
sudo restorecon -Rv /etc/usbguard/
sudo systemctl start usbguard
```

### "GNOME notification for blocked device doesn't appear"

First distinguish a new in-session insertion from a device that was already
blocked during boot. The event notifier handles only the former; the login
catch-up inventories the latter. Check both user-level services:

```bash
systemctl --user status \
  usbguard-notifier.service \
  noid-usbguard-login-catchup.service
```

If the live-event notifier is not running:

```bash
systemctl --user unmask usbguard-notifier
systemctl --user start usbguard-notifier
```

Its next graphical-login start is owned by the distro's static
`graphical-session.target` dependency; do not create a separate
`default.target` enablement link.

The catch-up is also a static graphical-session dependency and runs once per
login. It never enables a device. To inspect the current truth directly:

```bash
sudo noid-usbguard-devices status
```

## References

- Module 14 source: `kickstart/snippets/14-usbguard.ks` —
  authoritative for firstboot state machine, daemon config, wrapper
  script logic
- `docking-stations.md` in this directory — dock-specific workflow
- [USBGuard upstream docs](https://usbguard.github.io/)
- `man 8 usbguard-daemon` — daemon configuration reference
- `man 1 usbguard` — CLI reference

USBG_DOC_EOF

chmod 644 /usr/share/doc/noid-privacy/14-usbguard.md
chown root:root /usr/share/doc/noid-privacy/14-usbguard.md
echo "  [OK] /usr/share/doc/noid-privacy/14-usbguard.md written"

# ----------------------------------------------------------------------------
# Step 10d: Install /usr/share/doc/noid-privacy/docking-stations.md
# ----------------------------------------------------------------------------
# User-facing doc that distinguishes USB/DP Alt-Mode functions, explicitly
# authorized Thunderbolt PCIe functions and DisplayLink opt-in drivers.
# Also covers the USBGuard runtime-allow workflow.

mkdir -p /usr/share/doc/noid-privacy

cat > /usr/share/doc/noid-privacy/docking-stations.md <<'DOCK_DOC_EOF'
# NoID Privacy — USB-C / Thunderbolt Docking Station Guide

USB-C docks can expose several independent functions: DisplayPort Alt-Mode,
ordinary USB devices, Thunderbolt/USB4 PCIe tunneling, or DisplayLink video.
Do not treat those authorization boundaries as interchangeable.

## Type 1: USB-C / USB4 DisplayPort Alt-Mode and ordinary USB functions

DisplayPort Alt-Mode uses the GPU's native DRM/KMS path and needs no
DisplayLink driver. Ordinary USB children remain controlled by USBGuard.

Examples:
- a Thunderbolt 4 dock
- CalDigit TS3 Plus, TS4
- Dell WD22TB4, WD19TBS
- HP Thunderbolt Dock G4
- OWC Thunderbolt Hub / Dock
- Any dock sold as "Thunderbolt" or "USB4"

Video path: DisplayPort signals travel through the USB-C connector directly
to the GPU. The kernel sees the external display natively via DRM/KMS.

**First-plug workflow**:
1. Plug the dock. USBGuard may briefly block it.
2. During an active session GNOME shows USBGuard **Allow** and **Reject**
   actions. If the block happened before login, the one-shot catch-up instead
   offers **Open USBGuard Devices**; dismissing it keeps every device blocked.
3. Review the exact device, then click the live notification's temporary
   **Allow** action or run `sudo noid-usbguard-devices allow` to
   write a persistent rule. Ordinary USBGuard-generated rules can remain tied
   to the stored USB parent/topology, so moving the dock can require another
   explicit decision.

External-monitor success still depends on the dock's actual topology, cable,
firmware and GPU. USBGuard controls USB children only; it does not authorize
Thunderbolt PCIe tunneling.

## Thunderbolt / USB4 PCIe functions

NoID Privacy keeps the kernel `thunderbolt` driver available and enables
strict IOMMU/early-DMA protection. The domain authorization level is owned by
firmware and the kernel; verify that the actual device reports `user` or
`secure` because the image cannot force this firmware property:

```bash
grep -H . /sys/bus/thunderbolt/devices/domain*/security
```

It deliberately does **not** install `boltd`: upstream boltd automatically
enrolls and authorizes unknown devices with its IOMMU policy when an IOMMU is
active, which is not an explicit-per-device approval default.

Therefore a dock's USB and DisplayPort functions may work while tunneled PCIe
functions (for example an eGPU or PCIe NIC) remain unavailable. Enabling those
functions requires a deliberate, separately reviewed authorization workflow;
NoID Privacy does not silently add one. USBGuard approval covers only USB
children and must not be described as Thunderbolt PCIe approval.

## Type 2: DisplayLink (USB-attached video)

**Requires opt-in proprietary driver install.**

Examples:
- Most "universal" USB-to-HDMI/DP adapters (StarTech, Plugable basic, HP)
- Some Targus docks (non-Thunderbolt lineup)
- Some Kensington docks (non-Thunderbolt lineup)
- Some Dell non-Thunderbolt docks (D3100, D6000)
- Any dock sold as "DisplayLink" or "DL-*" chipset

Video path: USB data → DisplayLink chip → proprietary compression →
userspace daemon → kernel evdi module → GPU framebuffer. Neither the
kernel module (evdi) nor the daemon (displaylink) ship with Fedora.
Synaptics publishes an Ubuntu reference driver; the Fedora RPMs used by this
opt-in are community packages. EVDI's own upstream documentation notes that
its userspace/kernel communication is not access-controlled or authenticated.
The proprietary daemon necessarily processes screen content; NoID Privacy
makes no telemetry or privacy guarantee for it.

**Install workflow**:
1. Run: `sudo noid-install-displaylink`
   (asks for confirmation, creates a pre-change snapshot, verifies the current
   negativo17 signing-key fingerprint, and adds a repository restricted to
   DisplayLink/EVDI package names). The repository's metadata is not signed;
   package signatures remain mandatory. The restricted package namespace
   prevents its broader multimedia/NVIDIA inventory from replacing Fedora or
   RPM Fusion packages.

2. If Secure Boot is enabled in your firmware, complete MOK enrollment
   at the next reboot's blue MokManager screen.
   Full walkthrough: see `/usr/share/doc/noid-privacy/19-secure-boot-mok.md`.

3. Reboot.

4. Plug the dock. Handle USBGuard popup as above.

5. Verify: `lsmod | grep evdi && systemctl status displaylink`.

**To uninstall**: `sudo noid-install-displaylink --uninstall`. The helper
requires its closed ownership ledger, removes only the managed DisplayLink/
EVDI packages and trust files, preserves shared dependencies, and preserves a
signing key if another explicit repository now references it.

## How to tell which type you have

```bash
# Thunderbolt / USB4 domain indicator (not proof of authorization):
ls /sys/bus/thunderbolt/devices/   # if entries appear when plugged = TB/USB4

# DisplayLink indicator:
lsusb | grep -iE "displaylink|17e9:"   # if matches = DisplayLink chip
```

Or check the product page. Search for "Thunderbolt" — present = Type 1.

## USBGuard workflow (both types)

USBGuard blocks any USB device plugged AFTER first-boot policy generation.
Two ways to allow:

**Interactive (GNOME)**:
- Popup appears on plug-in with **Allow** and **Reject** actions.

**CLI (persistent)**:
```bash
sudo noid-usbguard-devices             # overview + allow/revoke menu
sudo noid-usbguard-devices allow       # blocked-device picker directly
```

The helper attempts a pre-change snapshot before persisting the allow rule and
reports if that attempt fails. If it succeeded, use `noid-snap-rollback` from
working/rescue userspace; GRUB does not list snapshots. The narrower recovery
is to revoke the exact durable rule with `noid-usbguard-devices revoke`.

## Hardware selection

For the least complex path, prefer a USB-C dock whose display outputs use
DisplayPort Alt-Mode and whose remaining functions are ordinary USB devices.
Thunderbolt/USB4 PCIe and DisplayLink add separate trust and software
boundaries as described above.
DOCK_DOC_EOF

chmod 644 /usr/share/doc/noid-privacy/docking-stations.md
echo "  [OK] /usr/share/doc/noid-privacy/docking-stations.md installed (644)"

# The former broad wheel-user Polkit grant for gsd-usb-protection is
# intentionally absent. M17 disables that unsafe integration; explicit device
# approval remains available through noid-usbguard-devices with sudo.
rm -f /etc/polkit-1/rules.d/50-noid-usbguard.rules

# ----------------------------------------------------------------------------
# Step 11: Verification
# ----------------------------------------------------------------------------
echo ""
echo "[Step 11] Verification"

fail=0

# 11.1 — Packages installed (5 packages — usbguard-dbus provides the hardened
# system-bus API and is masked symmetrically because it Requires=usbguard.service)
for pkg in usbguard usbguard-selinux usbguard-tools usbguard-notifier usbguard-dbus; do
    if rpm -q "$pkg" >/dev/null 2>&1; then
        echo "  [OK] Package $pkg installed"
    else
        echo "  [FAIL] Package $pkg missing"
        fail=$((fail + 1))
    fi
done

# 11.2 — daemon.conf identity + content
if [ -f /etc/usbguard/usbguard-daemon.conf ] && \
   [ ! -L /etc/usbguard/usbguard-daemon.conf ] && \
   [ "$(stat -Lc '%u:%g:%a:%h' /etc/usbguard/usbguard-daemon.conf \
        2>/dev/null || true)" = 0:0:600:1 ]; then
    echo "  [OK] daemon.conf: root:root 600 nlink=1"
else
    echo "  [FAIL] daemon.conf metadata must be root:root 600 nlink=1"
    fail=$((fail + 1))
fi
for setting in \
    "ImplicitPolicyTarget=block" \
    "PresentDevicePolicy=apply-policy" \
    "PresentControllerPolicy=keep" \
    "InsertedDevicePolicy=apply-policy" \
    "AuthorizedDefault=none" \
    "RestoreControllerDeviceState=false" \
    "IPCAccessControlFiles=/etc/usbguard/IPCAccessControl.d/" \
    "HidePII=true" \
    "AuditBackend=LinuxAudit" \
    "DeviceRulesWithPort=false"; do
    if grep -qxF "$setting" /etc/usbguard/usbguard-daemon.conf; then
        echo "  [OK] daemon.conf: $setting"
    else
        echo "  [FAIL] daemon.conf missing: $setting"
        fail=$((fail + 1))
    fi
done

# 11.3 — Named ACLs are the sole IPC authorization surface.
if grep -Eq '^[[:space:]]*(IPCAllowedGroups|IPCAllowedUsers)[[:space:]]*=' \
        /etc/usbguard/usbguard-daemon.conf; then
    echo "  [FAIL] daemon.conf has a broad group/user IPC grant"
    fail=$((fail + 1))
elif grep -qF "'Policy=list'" /usr/local/bin/noid-usbguard-firstboot.sh && \
     grep -qF "'Parameters=list,listen'" /usr/local/bin/noid-usbguard-firstboot.sh && \
     grep -qF "'Policy=list,modify'" /usr/local/bin/noid-usbguard-firstboot.sh && \
     grep -qF '/usr/bin/gpasswd -d "$username" usbguard' \
         /usr/local/bin/noid-usbguard-add-user.sh; then
    echo "  [OK] Named least-privilege user and full root IPC profiles installed"
else
    echo "  [FAIL] named USBGuard IPC reconciliation contract is incomplete"
    fail=$((fail + 1))
fi

# 11.4 — Scripts + service installed
for f in \
    /usr/local/bin/noid-usbguard-firstboot.sh \
    /usr/libexec/noid-eligible-user \
    /usr/libexec/noid-usbguard-login-catchup \
    /etc/systemd/system/noid-usbguard-firstboot.service \
    /etc/systemd/user-preset/50-noid-usbguard.preset \
    /etc/systemd/user/usbguard-notifier.service.d/10-noid-wait.conf \
    /usr/lib/systemd/user/noid-usbguard-login-catchup.service \
    /usr/lib/systemd/user/graphical-session.target.wants/usbguard-notifier.service \
    /usr/lib/systemd/user/graphical-session.target.wants/noid-usbguard-login-catchup.service; do
    if [ -f "$f" ]; then
        echo "  [OK] $f installed"
    else
        echo "  [FAIL] $f missing"
        fail=$((fail + 1))
    fi
done

if grep -qxF 'ConditionUser=!@system' \
        /etc/systemd/user/usbguard-notifier.service.d/10-noid-wait.conf && \
   grep -qxF 'PartOf=graphical-session.target' \
        /etc/systemd/user/usbguard-notifier.service.d/10-noid-wait.conf && \
   grep -qxF 'ExecCondition=/usr/libexec/noid-eligible-user graphical' \
        /etc/systemd/user/usbguard-notifier.service.d/10-noid-wait.conf && \
   grep -qxF 'ExecCondition=/usr/bin/systemctl --user --quiet is-active graphical-session.target' \
        /etc/systemd/user/usbguard-notifier.service.d/10-noid-wait.conf && \
   [ "$(readlink /usr/lib/systemd/user/graphical-session.target.wants/usbguard-notifier.service 2>/dev/null || true)" = \
        /usr/lib/systemd/user/usbguard-notifier.service ] && \
   [ "$(readlink /usr/lib/systemd/user/graphical-session.target.wants/noid-usbguard-login-catchup.service 2>/dev/null || true)" = \
        /usr/lib/systemd/user/noid-usbguard-login-catchup.service ] && \
   grep -qxF 'PartOf=graphical-session.target' \
        /usr/lib/systemd/user/noid-usbguard-login-catchup.service && \
   grep -qxF 'ExecStart=/usr/libexec/noid-usbguard-login-catchup' \
        /usr/lib/systemd/user/noid-usbguard-login-catchup.service && \
   bash -n /usr/libexec/noid-usbguard-login-catchup && \
   ! grep -Eq 'usbguard[[:space:]]+(allow-device|append-rule)' \
        /usr/libexec/noid-usbguard-login-catchup; then
    echo "  [OK] USBGuard live events and pre-login catch-up are graphical-session owned"
else
    echo "  [FAIL] USBGuard graphical notification lifecycle invalid"
    fail=$((fail + 1))
fi
unit_verify_runtime=$(mktemp -d /run/noid-systemd-user-verify.XXXXXX 2>/dev/null || true)
unit_verify_output=
if [ -z "$unit_verify_runtime" ]; then
    echo "  [FAIL] private runtime directory for user-unit verification could not be created"
    fail=$((fail + 1))
elif ! chmod 0700 "$unit_verify_runtime"; then
    echo "  [FAIL] private runtime directory for user-unit verification could not be secured"
    fail=$((fail + 1))
elif unit_verify_output=$(/usr/bin/env -i \
        PATH=/usr/sbin:/usr/bin HOME=/root LC_ALL=C \
        XDG_RUNTIME_DIR="$unit_verify_runtime" \
        SYSTEMD_UNIT_PATH=/etc/systemd/user:/usr/lib/systemd/user \
        /usr/bin/systemd-analyze --user --recursive-errors=no \
        verify usbguard-notifier.service \
            noid-usbguard-login-catchup.service 2>&1); then
    # Validate the shipped unit plus its merged drop-ins here. Recursively
    # judging Fedora/systemd-owned manager units is intentionally left to the
    # source-suite graph check and the real-session pre-ship gate: Anaconda's
    # root offline manager cannot construct app.slice's start transaction even
    # though that Fedora/systemd-owned unit is outside M14's ownership boundary.
    # Treating its offline job error as M14's result creates a false failure.
    echo "  [OK] USBGuard graphical user-unit definitions verify hermetically"
else
    echo "  [FAIL] USBGuard graphical user-unit definitions are invalid"
    [ -z "$unit_verify_output" ] || printf '%s\n' "$unit_verify_output" | sed 's/^/    /'
    fail=$((fail + 1))
fi
if [ -n "$unit_verify_runtime" ]; then
    # systemd-analyze creates XDG_RUNTIME_DIR/systemd even for offline verify.
    # Stay on the private runtime filesystem and require complete cleanup.
    if ! find "$unit_verify_runtime" -xdev -mindepth 1 -delete 2>/dev/null || \
       ! rmdir -- "$unit_verify_runtime" 2>/dev/null; then
        echo "  [FAIL] private user-unit verification runtime could not be removed"
        fail=$((fail + 1))
    fi
fi

# 11.5 — First-boot service enabled
if [ -L /etc/systemd/system/multi-user.target.wants/noid-usbguard-firstboot.service ]; then
    echo "  [OK] noid-usbguard-firstboot.service enabled"
else
    echo "  [FAIL] noid-usbguard-firstboot.service not enabled"
    fail=$((fail + 1))
fi

# 11.6 — usbguard.service + usbguard-dbus.service MASKED (Step 6 — first-boot
# service unmasks + enables both after policy is in place)
for masked_svc in usbguard.service usbguard-dbus.service; do
    if [ -L /etc/systemd/system/$masked_svc ] && \
       [ "$(readlink /etc/systemd/system/$masked_svc)" = "/dev/null" ]; then
        echo "  [OK] $masked_svc masked (first-boot service will unmask + enable)"
    else
        echo "  [FAIL] $masked_svc mask symlink missing"
        fail=$((fail + 1))
    fi
done

# 11.7 — Module 13 noid-status reads USBGuard status file (cross-ref)
# Module 13 intentionally exposes system USBGuard state through its read-only
# diagnostic CLI rather than a stale constant in the graphical Welcome app.
# Verify the actual consumer and stable state-file contract.
if [ -x /usr/local/bin/noid-status ] && \
   grep -qF '/var/lib/noid-privacy/usbguard-status.txt' \
       /usr/local/bin/noid-status && \
   grep -qF 'read_usbguard_state()' /usr/local/bin/noid-status && \
   ! grep -qF '. "$UG_STATE_FILE"' /usr/local/bin/noid-status; then
    echo "  [OK] noid-status parses USBGuard status as data (Module 13 cross-ref)"
else
    echo "  [FAIL] noid-status USBGuard data-parser contract missing — check Module 13"
    fail=$((fail + 1))
fi

# 11.8 — AIDE evidence cross-ref. Device rules and per-user IPC grants are
# security controls: the parent must be SECURE-tracked and legacy broad
# exclusions must be absent. The config line alone is insufficient because an
# earlier Fedora rule can win AIDE's deepest-node/first-match resolution.
aide_usbguard_match=$(LC_ALL=C aide --config=/etc/aide.conf \
    --path-check='f:/etc/usbguard/rules.conf' 2>&1) || aide_usbguard_match=
if grep -qxF '/etc/usbguard/ SECURE' /etc/aide.conf && \
   grep -qF sha256 <<<"$aide_usbguard_match" && \
   grep -qF sha512 <<<"$aide_usbguard_match" && \
   ! grep -qxF '!/etc/usbguard/rules\.conf$' /etc/aide.conf && \
   ! grep -qxF '!/etc/usbguard/IPCAccessControl\.d(/.*)?$' /etc/aide.conf; then
    echo "  [OK] AIDE content-tracks USBGuard policy and IPC grants"
else
    echo "  [FAIL] AIDE USBGuard evidence contract incomplete — check Module 13"
    fail=$((fail + 1))
fi

# 11.9 — State directory exists
if [ -d /var/lib/noid-privacy ]; then
    echo "  [OK] /var/lib/noid-privacy state directory exists"
else
    echo "  [FAIL] /var/lib/noid-privacy missing"
    fail=$((fail + 1))
fi

# 11.10 — Cross-ref Module 12 (audit rules MUST cover /etc/usbguard)
# Module 12 ships the usbguard_config rule; this is a hard dependency check.
if grep -q "\-k usbguard_config\b" /etc/audit/rules.d/99-hardening.rules 2>/dev/null; then
    echo "  [OK] Module 12 usbguard_config audit rule present (cross-ref)"
else
    echo "  [FAIL] Module 12 usbguard_config audit rule missing — check Module 12 kickstart"
    fail=$((fail + 1))
fi

# 11.11 — GNOME wildcard rejection hook and obsolete-Polkit-grant removal
if [ ! -x /usr/local/sbin/noid-usbguard-remove-gnome-wildcard ] || \
   [ ! -f /etc/systemd/system/usbguard.service.d/20-noid-reject-gnome-wildcard.conf ]; then
    echo "  [FAIL] GNOME USBGuard wildcard rejection hook missing"
    fail=$((fail + 1))
elif [ -e /etc/polkit-1/rules.d/50-noid-usbguard.rules ]; then
    echo "  [FAIL] obsolete gsd-usb-protection Polkit grant remains"
    fail=$((fail + 1))
else
    echo "  [OK] GNOME wildcard rejected; obsolete Polkit grant absent"
fi

if [ $fail -gt 0 ]; then
    echo ""
    echo "[Module 14] FAILED ($fail checks)"
    exit 1
fi

echo ""
echo "=============================================================="
echo "[Module 14] Done — all checks passed"
echo ""
echo "IMPORTANT: usbguard.service will be enabled + started by"
echo "           noid-usbguard-firstboot.service on first boot."
echo "           First boot will either:"
echo "             (a) generate-policy from connected devices -> real state"
echo "             (b) emergency HID fallback -> retry next boot"
echo "=============================================================="

%end
