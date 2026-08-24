# ============================================================================
# Module 07 — IPv6 / Network Privacy Bundle
# Status: LOCKED 2026-08-22 (v25) — name the v1.7 physical IPv6 support boundary.
#
# Covers:
#   1. /etc/gai.conf — complete RFC 6724 address-selection policy + the
#      Section 10.3 administrative override ::ffff:0:0/96 precedence 100.
#      This sorts IPv4 destinations first when both families are otherwise
#      equally suitable; it does not alter A/AAAA DNS query scheduling.
#   2. /etc/sysctl.d/98-privacy-network.conf — net.ipv4.ip_forward=0 (boot
#      default; libvirt may override at runtime while VMs are active).
#      It deliberately sorts before M02's 99-hardening.conf: if a full policy
#      reload changes forwarding from 1 to 0, Linux resets IPv4 host/router
#      defaults and M02 must reassert accept_redirects=0 afterwards.
#      TCP timestamps are not overridden: maintained Linux value 1 uses a
#      random per-connection offset while preserving RTTM/PAWS.
#   3. noid-wan-ipv6-disable.sh + firstboot service — one locked authority;
#      /etc/sysctl.d/99-wan-ipv6-off.conf is the sole durable source and a
#      root-published runtime status records ENFORCED/DEFERRED/ERROR.
#   4. STEP 4b NM dispatcher 55-wan-ipv6-refresh — awaited physical pre-up
#      enforcement plus locked up-event reconciliation (WAN-change handler).
#   5. User-doc 07-physical-ipv6-boundary.md — v1.7 support boundary; no
#      partial/broken reactivation recipe.
#
# Design constraints (incident-verified; keep when editing):
#   - The firstboot service makes one quiescent attempt. Missing NIC is a
#     successful published DEFERRED state; the dispatcher retriggers on
#     physical-link activation. Explicit pre-up interface selection avoids
#     depending on a default route that does not exist yet.
#   - The generated sysctl file is the only durable policy state. It is staged,
#     validated, fsynced and renamed only after the live sysctl is verified.
#     All boot/dispatcher events share the hardened flock. Do not reintroduce a
#     second durable marker that can disagree after interruption.
#   - NetworkManager 1.56 waits for ordinary pre-up dispatchers but does not
#     use their exit status as an activation veto. The helper therefore applies
#     and verifies the live hard constraint before it validates or changes the
#     durable file. M02's default-disable and M23's connection method remain
#     independent layers; a dispatcher failure is explicit evidence, not a
#     falsely advertised veto.
#   - Physical classification is topology-based: a kernel-safe interface name
#     must have /sys/class/net/<iface>/device. Interface names are
#     administrator-controlled and therefore must never be used as a device
#     type authority or deny-list.
#   - gai.conf: one label or precedence directive makes glibc replace that
#     entire built-in table. Keep both explicit RFC 6724 tables complete.
#   - Service sandbox: ProtectKernelTunables=no (script writes /proc/sys
#     via sysctl -w); @chown must come AFTER ~@privileged in the
#     SystemCallFilter lines (order-sensitive — same rule as Module 04).
#   - Early-boot systemd-sysctl may log "Couldn't write ... ignoring" for
#     the per-WAN key when the NIC driver registers later — benign:
#     sysctl.d(5) re-applies net.ipv6.conf.* keys per-interface as each
#     interface appears, M02's default.disable_ipv6=1 covers the gap, and
#     the generated file carries the "-" prefix (failures log at debug).
#   - Linux documents ip_forward as special: changing it resets IPv4
#     configuration to host/router defaults. On Fedora 44, a 1 -> 0 transition
#     reproducibly resets all.accept_redirects from 0 to 1. A complete
#     systemd-sysctl reload previously applied M02's 99-hardening.conf first,
#     then M07's equally prefixed 99-privacy-network.conf changed forwarding
#     and undid the redirect policy. The 98 prefix fixes the dependency using
#     sysctl.d's native lexical order: forwarding first, hardening second.
#     Do not add a runtime watcher, libvirt hook or broad sysctl reload.
#
# Cross-reference:
#   - Module 02: net.ipv6.conf.default.disable_ipv6=1 (new interfaces start
#     v6 off) and IPv4 accept_redirects=0 — this module adds the explicit
#     per-WAN IPv6 layer and reset-safe forwarding order.
#   - VPN software or an imported profile may configure tunnel IPv6
#     independently; that does not conflict with this physical-link policy.
#   - Module 04: same event-driven firstboot-service pattern (oneshot +
#     ConditionPathExists + dispatcher), but a deliberately broader aggregate
#     interface classifier for ARP learning.
#
# Decisions:
#   [1] gai.conf ships the complete RFC 6724 policy (glibc all-or-nothing rule)
#   [2] ::ffff:0:0/96 precedence 100 — RFC 6724 Section 10.3 IPv4 preference
#   [3] no tcp_timestamps override — Linux's maintained default value 1 uses
#       the RFC 7323 per-connection random offset for the uptime privacy issue
#       while retaining RTT measurement and PAWS. A future deviation requires
#       reproducible leakage and performance/reliability evidence.
#   [4] ip_forward=0 as boot default, with lexical application before M02's
#       accept_redirects=0 policy
#   [5] WAN detection is generic (no hardcoded interface names)
# ============================================================================

%post --erroronfail --log=/var/log/ks-07-ipv6-privacy.log
set -euo pipefail

log() { echo "[noid-07-ipv6]" "$@"; }
log "=== Module 07 post-install: IPv6 / Network Privacy Bundle ==="

# ====================================================================
# STEP 1: /etc/gai.conf — explicit RFC 6724 policy, IPv4 precedence 100
# ====================================================================
# Sorts getaddrinfo() destination results; it does not control DNS queries.
# Ships complete label/precedence tables because glibc replaces each built-in
# table as soon as one directive of that kind is configured.
cat > /etc/gai.conf << 'GAI_EOF'
# NoID Privacy — glibc getaddrinfo() destination-address ordering
# Module 07 — design rationale in the module header (source tree).
#
# Sorts IPv4-mapped destinations (::ffff:0:0/96) before otherwise equally
# suitable IPv6 destinations. This does not control A/AAAA DNS query
# scheduling and does not override an application's own connection racing.
#
# CRITICAL: one label or precedence directive makes glibc replace the whole
# built-in table of that kind. Keep both RFC 6724 tables complete.

# Label definitions (RFC 6724 default)
label ::1/128       0
label ::/0          1
label 2002::/16     2
label ::/96         3
label ::ffff:0:0/96 4
label 2001:0::/32   5
label fc00::/7      13
label fec0::/10     11
label 3ffe::/16     12

# Precedence definitions (RFC 6724 policy)
# CRITICAL: glibc REPLACES the default precedence table entirely as soon as
# ANY precedence line is present. We therefore ship the eight unchanged
# RFC 6724 rows plus the Section 10.3 administrative override row. Missing any
# RFC row would make that prefix class fall back to the ::/0 catch-all.
precedence  ::1/128       50
precedence  ::/0          40
precedence  2002::/16     30
precedence ::/96           1
# NoID Privacy policy (Decision [2] in the module header):
# IPv4-mapped precedence 100 (RFC 6724 default 35). This is the RFC's
# documented administrator setting for preferring IPv4 destination addresses.
precedence ::ffff:0:0/96 100
precedence fec0::/10       1
precedence 3ffe::/16       1
precedence fc00::/7        3
precedence 2001:0::/32     5

# Scope definitions for IPv4-mapped addresses
scopev4 ::ffff:169.254.0.0/112  2
scopev4 ::ffff:127.0.0.0/104    2
scopev4 ::ffff:0.0.0.0/96       14
GAI_EOF
chmod 644 /etc/gai.conf
chown root:root /etc/gai.conf
log "STEP 1: /etc/gai.conf written (complete RFC 6724 policy + IPv4 precedence 100)"

# ====================================================================
# STEP 2: /etc/sysctl.d/98-privacy-network.conf
# ====================================================================
# ip_forward=0: boot default; libvirt writes /proc/sys/net/ipv4/ip_forward=1 at
# runtime when its NAT network comes up — expected, no conflict (runtime write
# supersedes the boot value). TCP timestamps intentionally remain at the
# maintained Linux default; NoID Privacy has no evidence supporting a global override.
# Retire the previous filename before publishing its reset-safe replacement.
# Keeping both would apply ip_forward twice and recreate the ordering defect.
rm -f /etc/sysctl.d/99-privacy-network.conf
cat > /etc/sysctl.d/98-privacy-network.conf << 'SYSCTL_EOF'
# NoID Privacy — Network Privacy sysctls
# Module 07 — design rationale in the module header (source tree).

# TCP timestamps are intentionally not overridden. Linux default value 1 uses
# a random offset per connection and retains RFC 7323 RTTM/PAWS machinery.

# Disable IP forwarding — we are a desktop, not a router.
# libvirt will override at runtime when VMs are active (expected behavior).
net.ipv4.ip_forward = 0
SYSCTL_EOF
chmod 640 /etc/sysctl.d/98-privacy-network.conf
chown root:root /etc/sysctl.d/98-privacy-network.conf
log "STEP 2: /etc/sysctl.d/98-privacy-network.conf written before M02 hardening (ip_forward=0; TCP timestamp default preserved)"

# ====================================================================
# STEP 3: WAN IPv6 disable first-boot detection script
# ====================================================================
# Detects a sysfs hardware-backed physical interface at first boot (preferring
# the IPv4 default-route device) and writes the per-WAN sysctl file. Interface
# names are never treated as device-type evidence. Retry via dispatcher.
cat > /usr/local/sbin/noid-wan-ipv6-disable.sh << 'SCRIPT_EOF'
#!/bin/bash
#
# NoID Privacy — WAN IPv6 disable first-boot detection
# Module 07 — design rationale in the module header (source tree).
#
# Detects the primary WAN interface and writes an explicit
# /etc/sysctl.d/99-wan-ipv6-off.conf file with
# net/ipv6/conf/<wan-iface>/disable_ipv6=1. The slash-first spelling preserves
# dots in valid kernel interface names. Applies runtime via sysctl -w.
#
# This is defense-in-depth on top of Module 02's
# net.ipv6.conf.default.disable_ipv6=1 (which already causes new
# interfaces to start v6 off). Adds explicit per-WAN hardening +
# audit trail (matches the supported Fedora 44 configuration pattern).
#

set -euo pipefail

TEST_MODE="${NOID_WAN_IPV6_TEST_MODE:-0}"
if [ "$TEST_MODE" = 1 ]; then
    SYSCTL_FILE="${NOID_WAN_IPV6_SYSCTL_FILE:-/etc/sysctl.d/99-wan-ipv6-off.conf}"
    STATUS_FILE="${NOID_WAN_IPV6_STATUS_FILE:-/run/noid-privacy/wan-ipv6-status}"
    LOCK_FILE="${NOID_WAN_IPV6_LOCK_FILE:-/run/lock/noid-wan-ipv6.lock}"
    SYS_CLASS_NET="${NOID_SYS_CLASS_NET:-/sys/class/net}"
    PROC_IPV6_ROOT="${NOID_PROC_IPV6_ROOT:-/proc/sys/net/ipv6/conf}"
    SYSCTL_BIN="${NOID_SYSCTL_BIN:-/usr/sbin/sysctl}"
    IP_BIN="${NOID_IP_BIN:-/usr/sbin/ip}"
    DEFER_MISSING_NETWORK="${NOID_WAN_IPV6_DEFER_MISSING_NETWORK:-0}"
else
    SYSCTL_FILE=/etc/sysctl.d/99-wan-ipv6-off.conf
    STATUS_FILE=/run/noid-privacy/wan-ipv6-status
    LOCK_FILE=/run/lock/noid-wan-ipv6.lock
    SYS_CLASS_NET=/sys/class/net
    PROC_IPV6_ROOT=/proc/sys/net/ipv6/conf
    SYSCTL_BIN=/usr/sbin/sysctl
    IP_BIN=/usr/sbin/ip
    DEFER_MISSING_NETWORK=0
fi
SYSCTL_CMD=("$SYSCTL_BIN")
IP_CMD=("$IP_BIN")
if [ "$TEST_MODE" = 1 ]; then
    read -r -a SYSCTL_CMD <<< "$SYSCTL_BIN"
    read -r -a IP_CMD <<< "$IP_BIN"
fi
CURRENT_IFACE=-
STAGED_FILE=
COMMITTED=0

log() { echo "[noid-wan-v6] $*"; }
err() { echo "[noid-wan-v6] ERROR: $*" >&2; }

expected_ids() {
    if [ "$TEST_MODE" = 1 ]; then
        printf '%s:%s\n' "$(id -u)" "$(id -g)"
    else
        echo 0:0
    fi
}

ensure_owned_directory() {
    local directory=$1 expected
    if [ ! -e "$directory" ]; then
        if [ "$TEST_MODE" = 1 ]; then
            mkdir -p "$directory"
            chmod 0755 "$directory"
        else
            install -d -m 0755 -o root -g root "$directory"
        fi
    fi
    expected=$(expected_ids)
    [ -d "$directory" ] && [ ! -L "$directory" ] && \
        [ "$(stat -c '%u:%g:%a' "$directory")" = "$expected:755" ]
}

validate_existing_policy() {
    local expected old_iface assignment_iface active_count assignment_re
    [ -e "$SYSCTL_FILE" ] || return 0
    expected=$(expected_ids)
    [ -f "$SYSCTL_FILE" ] && [ ! -L "$SYSCTL_FILE" ] && \
        [ "$(stat -c '%u:%g:%a:%h' "$SYSCTL_FILE")" = "$expected:640:1" ] || {
        err "existing sysctl policy metadata mismatch"
        return 1
    }
    # Accept the preceding dot-form only for identities without a dot. That
    # syntax was lossless for those deployed names; a successful transaction
    # immediately republishes the slash-form and completes the migration.
    assignment_re='^(-net/ipv6/conf/[A-Za-z0-9_.-]{1,15}/disable_ipv6|-net\.ipv6\.conf\.[A-Za-z0-9_-]{1,15}\.disable_ipv6) = 1$'
    [ "$(grep -Ec "$assignment_re" "$SYSCTL_FILE")" = 1 ] || {
        err "existing sysctl assignment contract mismatch"
        return 1
    }
    active_count=$(awk \
        '!/^[[:space:]]*($|#)/ { count++ } END { print count + 0 }' \
        "$SYSCTL_FILE")
    [ "$active_count" = 1 ] || {
        err "existing sysctl policy contains unexpected active directives"
        return 1
    }
    if grep -q '^# NOID_WAN_IPV6_POLICY_V1 IFACE=' "$SYSCTL_FILE"; then
        [ "$(grep -c '^# NOID_WAN_IPV6_POLICY_V1 IFACE=' "$SYSCTL_FILE")" = 1 ] || return 1
        old_iface=$(sed -n 's/^# NOID_WAN_IPV6_POLICY_V1 IFACE=\([A-Za-z0-9_.-]\{1,15\}\)$/\1/p' "$SYSCTL_FILE")
        assignment_iface=$(sed -n \
            -e 's|^-net/ipv6/conf/\([A-Za-z0-9_.-]\{1,15\}\)/disable_ipv6 = 1$|\1|p' \
            -e 's|^-net\.ipv6\.conf\.\([A-Za-z0-9_-]\{1,15\}\)\.disable_ipv6 = 1$|\1|p' \
            "$SYSCTL_FILE")
        [ -n "$old_iface" ] && [ "$old_iface" = "$assignment_iface" ] || {
            err "existing sysctl policy identity mismatch"
            return 1
        }
    fi
}

failpoint() {
    local stage=$1
    if [ "$TEST_MODE" = 1 ] && [ "${NOID_TEST_FAIL_STAGE:-}" = "$stage" ]; then
        err "test failpoint: $stage"
        return 99
    fi
}

publish_status() {
    local mode=$1 iface=$2 status_dir staged expected
    case "$mode" in ENFORCED|DEFERRED|ERROR) ;; *) return 1 ;; esac
    [[ "$iface" =~ ^(-|[A-Za-z0-9_.-]{1,15})$ ]] || return 1
    status_dir=$(dirname "$STATUS_FILE")
    ensure_owned_directory "$status_dir" || return 1
    staged=$(mktemp "$status_dir/.wan-ipv6-status.XXXXXX")
    printf 'NOID_WAN_IPV6_STATUS_V1\nMODE=%s\nIFACE=%s\n' \
        "$mode" "$iface" > "$staged"
    chmod 0644 "$staged"
    if [ "$TEST_MODE" != 1 ]; then chown root:root "$staged"; fi
    expected=$(expected_ids)
    [ "$(stat -c '%u:%g:%a:%h' "$staged")" = "$expected:644:1" ] || {
        rm -f "$staged"
        return 1
    }
    sync -- "$staged"
    mv -fT "$staged" "$STATUS_FILE"
    sync -- "$status_dir"
}

on_exit() {
    local rc=$?
    set +e
    [ -z "$STAGED_FILE" ] || rm -f "$STAGED_FILE"
    if [ "$rc" -ne 0 ] && [ "$COMMITTED" -ne 1 ]; then
        if ! publish_status ERROR "$CURRENT_IFACE"; then
            rm -f "$STATUS_FILE"
        fi
    fi
    exit "$rc"
}

if [ "$TEST_MODE" != 1 ] && [ "$(id -u)" -ne 0 ]; then
    err "must run as root"
    exit 1
fi

EXPLICIT_IFACE=
case "$#" in
    0) ;;
    1)
        [ "$1" = "--defer-missing-network" ] || {
            err "unknown argument"
            exit 2
        }
        DEFER_MISSING_NETWORK=1
        ;;
    2)
        [ "$1" = "--interface" ] || { err "unknown argument"; exit 2; }
        EXPLICIT_IFACE=$2
        ;;
    *) err "usage: $0 [--defer-missing-network | --interface IFACE]"; exit 2 ;;
esac

prepare_lock() {
    local lock_dir expected path_id fd_id
    lock_dir=$(dirname "$LOCK_FILE")
    ensure_owned_directory "$lock_dir" || { err "unsafe lock directory"; return 1; }
    [ ! -L "$LOCK_FILE" ] || { err "lock symlink rejected"; return 1; }
    if [ ! -e "$LOCK_FILE" ]; then
        ( umask 077; : > "$LOCK_FILE" )
        if [ "$TEST_MODE" != 1 ]; then chown root:root "$LOCK_FILE"; fi
    fi
    expected=$(expected_ids)
    [ -f "$LOCK_FILE" ] && [ ! -L "$LOCK_FILE" ] && \
        [ "$(stat -c '%u:%g:%a:%h' "$LOCK_FILE")" = "$expected:600:1" ] || {
        err "lock metadata mismatch"
        return 1
    }
    exec 9<> "$LOCK_FILE"
    path_id=$(stat -Lc '%d:%i' "$LOCK_FILE")
    fd_id=$(stat -Lc '%d:%i' "/proc/$$/fd/9")
    [ "$path_id" = "$fd_id" ] || { err "lock path changed during open"; return 1; }
    flock -x 9
}

# Detect a physical carrier. Prefer a default-route interface, then fall back
# to an alphabetical topology scan before NetworkManager has a route. Kernel
# interface names are administrator-controlled and are never a type authority:
# /sys/class/net/<iface>/device is the sole physical-device criterion.
detect_wan_interface() {
    local iface path
    while IFS= read -r iface; do
        if valid_physical_iface "$iface"; then
            echo "$iface"
            return 0
        fi
    done < <("${IP_CMD[@]}" -4 route show default 2>/dev/null | \
        awk '/^default/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')

    # Fallback: alphabetical scan
    for path in "$SYS_CLASS_NET"/*; do
        [ -e "$path" ] || continue
        iface=${path##*/}
        if valid_physical_iface "$iface"; then
            echo "$iface"
            return 0
        fi
    done
    return 1
}

valid_physical_iface() {
    local iface=${1:-}
    [[ "$iface" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || return 1
    [ -d "$SYS_CLASS_NET/$iface/device" ]
}

prepare_lock
trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

IFACE=$EXPLICIT_IFACE
if [ -n "$IFACE" ]; then
    valid_physical_iface "$IFACE" || { err "invalid/non-physical interface: $IFACE"; exit 1; }
else
    IFACE=$(detect_wan_interface || true)
fi
if [ -z "$IFACE" ]; then
    if [ "$DEFER_MISSING_NETWORK" = "1" ]; then
        publish_status DEFERRED -
        COMMITTED=1
        log "no primary physical interface; deferred (default IPv6 disable remains active)"
        exit 0
    fi
    err "no primary physical interface detected"
    exit 1
fi
CURRENT_IFACE=$IFACE

log "primary WAN interface: $IFACE"

# NetworkManager waits for pre-up dispatchers but proceeds after an ordinary
# script failure. Apply and verify the live hard constraint before touching or
# even validating durable policy, so malformed persistent evidence cannot
# prevent enforcement on the current physical link.
if ! "${SYSCTL_CMD[@]}" -w "net/ipv6/conf/$IFACE/disable_ipv6=1" >/dev/null 2>&1; then
    err "runtime IPv6 disable apply failed for $IFACE"
    exit 1
fi
if [ ! -f "$PROC_IPV6_ROOT/$IFACE/disable_ipv6" ] || \
   [ "$(cat "$PROC_IPV6_ROOT/$IFACE/disable_ipv6")" != 1 ]; then
    err "runtime IPv6 disable verification failed for $IFACE"
    exit 1
fi
failpoint after-live || exit $?

# The sysctl file is the sole durable state. Stage and validate it before any
# publication so there is no second state file that can disagree after a crash.
sysctl_dir=$(dirname "$SYSCTL_FILE")
ensure_owned_directory "$sysctl_dir" || { err "unsafe sysctl directory"; exit 1; }
validate_existing_policy || exit 1
STAGED_FILE=$(mktemp "$sysctl_dir/.99-wan-ipv6-off.XXXXXX")
cat > "$STAGED_FILE" << SYSCTL_INNER_EOF
# NoID Privacy — Per-WAN IPv6 disable
# Module 07 — generated transactionally by noid-wan-ipv6-disable.sh
# NOID_WAN_IPV6_POLICY_V1 IFACE=$IFACE
#
# Defense in depth on top of net.ipv6.conf.default.disable_ipv6=1
# (Module 02). Physical IPv6 is not a release-qualified v1.7 mode.

-net/ipv6/conf/$IFACE/disable_ipv6 = 1
SYSCTL_INNER_EOF
chmod 0640 "$STAGED_FILE"
if [ "$TEST_MODE" != 1 ]; then chown root:root "$STAGED_FILE"; fi
expected=$(expected_ids)
[ "$(stat -c '%u:%g:%a:%h' "$STAGED_FILE")" = "$expected:640:1" ] || {
    err "staged sysctl metadata mismatch"
    exit 1
}
grep -qxF "# NOID_WAN_IPV6_POLICY_V1 IFACE=$IFACE" "$STAGED_FILE" || {
    err "staged policy identity mismatch"
    exit 1
}
[ "$(grep -Ec '^-net/ipv6/conf/[A-Za-z0-9_.-]{1,15}/disable_ipv6 = 1$' "$STAGED_FILE")" = 1 ] || {
    err "staged sysctl assignment contract mismatch"
    exit 1
}

sync -- "$STAGED_FILE"
mv -fT "$STAGED_FILE" "$SYSCTL_FILE"
STAGED_FILE=
sync -- "$sysctl_dir"
failpoint after-policy-rename || exit $?
publish_status ENFORCED "$IFACE"
COMMITTED=1
log "committed + verified: net/ipv6/conf/$IFACE/disable_ipv6=1"
if ! logger -t noid-wan-v6 "WAN IPv6 disabled on $IFACE"; then
    log "journal publication unavailable; enforcement remains committed"
fi
SCRIPT_EOF

chmod 755 /usr/local/sbin/noid-wan-ipv6-disable.sh
chown root:root /usr/local/sbin/noid-wan-ipv6-disable.sh
rm -f /var/lib/noid-privacy/wan-ipv6-off.state
log "STEP 3: /usr/local/sbin/noid-wan-ipv6-disable.sh installed"

# The sandboxed firstboot unit receives write access to this exact lock path,
# not to all of /run/lock. Pre-create it through systemd's native volatile-file
# mechanism so namespace setup cannot fail before the helper starts.
mkdir -p /etc/tmpfiles.d
cat > /etc/tmpfiles.d/noid-wan-ipv6.conf <<'WAN_IPV6_TMPFILES_EOF'
# NoID Privacy — Module 07 WAN IPv6 transaction lock
f /run/lock/noid-wan-ipv6.lock 0600 root root -
WAN_IPV6_TMPFILES_EOF
chmod 0644 /etc/tmpfiles.d/noid-wan-ipv6.conf
chown root:root /etc/tmpfiles.d/noid-wan-ipv6.conf
systemd-tmpfiles --create /etc/tmpfiles.d/noid-wan-ipv6.conf
log "STEP 3b: exact WAN IPv6 transaction lock registered + created"

# ====================================================================
# STEP 4: First-boot service
# ====================================================================
# Same event-driven pattern as the Module 04 ARP learner: do not wait for
# connectivity. Missing NIC exits cleanly; the dispatcher retries on link-up.
cat > /etc/systemd/system/noid-wan-ipv6-disable-firstboot.service << 'SVC_EOF'
[Unit]
Description=NoID Privacy: first-boot WAN IPv6 disable
Documentation=file:///usr/local/sbin/noid-wan-ipv6-disable.sh
Requires=systemd-tmpfiles-setup.service
After=NetworkManager.service systemd-tmpfiles-setup.service
Wants=NetworkManager.service
ConditionPathExists=!/etc/sysctl.d/99-wan-ipv6-off.conf
# Skip in live-ISO mode: the generated /etc/sysctl.d policy would live only in
# the disposable overlay. M02's default.disable_ipv6=1 covers new Live links;
# M23 owns the separate NetworkManager profile policy.
ConditionKernelCommandLine=!rd.live.image

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/noid-wan-ipv6-disable.sh --defer-missing-network
RemainAfterExit=no
StandardOutput=journal
StandardError=journal
UMask=0077

# baseline sandbox: universally-safe directives.
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ProtectKernelLogs=yes
ProtectHostname=yes
ProtectClock=yes
SystemCallArchitectures=native

# 2026 systemd-baseline hardening:
ProtectSystem=strict
ReadWritePaths=/etc/sysctl.d /run/noid-privacy /run/lock/noid-wan-ipv6.lock
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
# ProtectKernelTunables=no — script writes /proc/sys via sysctl -w (legitimate)
ProtectKernelTunables=no
ProtectKernelModules=yes
ProtectProc=invisible
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
RestrictNamespaces=yes
MemoryDenyWriteExecute=yes
IPAddressDeny=any
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
# SystemCallFilter ORDER constraint (same as M04): systemd
# processes filter lines in order; ~@privileged removes chown (chown is in
# the @privileged set), so @chown MUST come AFTER ~@privileged to re-add
# it. The reverse order makes the @chown line a no-op (~@privileged nukes
# chown again — EPERM because SystemCallErrorNumber=EPERM is set below).
SystemCallFilter=@chown
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
SVC_EOF
chmod 644 /etc/systemd/system/noid-wan-ipv6-disable-firstboot.service
chown root:root /etc/systemd/system/noid-wan-ipv6-disable-firstboot.service
log "STEP 4: /etc/systemd/system/noid-wan-ipv6-disable-firstboot.service installed"

# ====================================================================
# STEP 4b: NM dispatcher 55-wan-ipv6-refresh
# ====================================================================
# WAN-change handler — the firstboot service runs only once, so a later
# primary-WAN change needs this dispatcher to re-invoke the script. The
# helper re-runs its full stage/apply/verify/rename pipeline on every
# invocation; that pipeline is idempotent (same iface → same policy file),
# so unchanged-WAN invocations are harmless, just not skipped. See header
# Design constraints. Same dispatcher architecture as the M06 dispatchers.
cat > /etc/NetworkManager/dispatcher.d/55-wan-ipv6-refresh <<'REFRESH_EOF'
#!/bin/bash
#
# NoID Privacy — WAN-iface change handler (Module 07)
#
# Every physical pre-up attempts and verifies the kernel IPv6-disable
# postcondition before NetworkManager marks the link fully active. NetworkManager
# records but does not veto activation on an ordinary dispatcher error, so the
# helper enforces live state before durable-policy validation and publishes any
# failure explicitly. The later up event reconciles the same policy again.

set -euo pipefail
umask 077

IFACE="${1:-}"
ACTION="${2:-}"
case "$#" in
    0) exit 0 ;;
    2) ;;
    *) echo "noid-wan-ipv6-refresh: expected exactly INTERFACE ACTION" >&2; exit 2 ;;
esac

TEST_MODE="${NOID_WAN_IPV6_TEST_MODE:-0}"
if [ "$TEST_MODE" = 1 ]; then
    HELPER="${NOID_WAN_IPV6_HELPER:-/usr/local/sbin/noid-wan-ipv6-disable.sh}"
    SYS_CLASS_NET="${NOID_SYS_CLASS_NET:-/sys/class/net}"
    CMDLINE_FILE="${NOID_CMDLINE_FILE:-/proc/cmdline}"
    REFRESH_TMPDIR="${NOID_WAN_IPV6_REFRESH_TMPDIR:-/run}"
else
    HELPER=/usr/local/sbin/noid-wan-ipv6-disable.sh
    SYS_CLASS_NET=/sys/class/net
    CMDLINE_FILE=/proc/cmdline
    REFRESH_TMPDIR=/run
fi
HELPER_CMD=("$HELPER")
if [ "$TEST_MODE" = 1 ]; then
    read -r -a HELPER_CMD <<< "$HELPER"
fi

# Only pre-up/up events
case "$ACTION" in pre-up|up) ;; *) exit 0 ;; esac

# Skip only the exact live-ISO kernel-command-line key, with or without a value.
grep -Eq '(^|[[:space:]])rd\.live\.image(=[^[:space:]]*)?([[:space:]]|$)' \
    "$CMDLINE_FILE" 2>/dev/null && exit 0

# A kernel-safe name plus sysfs device backing is the complete classifier.
# Names are administrator-controlled, so prefixes cannot prove device type.
[[ "$IFACE" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || exit 0
[ -d "$SYS_CLASS_NET/$IFACE/device" ] || exit 0

# The helper return code is authoritative. Logger availability is not: a
# journal transport failure cannot convert enforcement success to failure or
# enforcement failure to success.
output_file=
cleanup_refresh() {
    local rc=$?
    trap - EXIT
    [ -z "$output_file" ] || rm -f "$output_file"
    exit "$rc"
}
trap cleanup_refresh EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
output_file=$(mktemp "$REFRESH_TMPDIR/noid-wan-ipv6-refresh.XXXXXX")
if "${HELPER_CMD[@]}" --interface "$IFACE" \
        >"$output_file" 2>&1; then
    if ! logger -t noid-wan-ipv6-refresh < "$output_file"; then
        sed 's/^/[noid-wan-ipv6-refresh] /' "$output_file" >&2
    fi
    exit 0
else
    rc=$?
fi
if ! logger -t noid-wan-ipv6-refresh < "$output_file"; then
    sed 's/^/[noid-wan-ipv6-refresh] /' "$output_file" >&2
fi
echo "noid-wan-ipv6-refresh: $ACTION enforcement failed for $IFACE; NetworkManager records but does not veto ordinary dispatcher failures" >&2
exit "$rc"
REFRESH_EOF
chmod 700 /etc/NetworkManager/dispatcher.d/55-wan-ipv6-refresh
chown root:root /etc/NetworkManager/dispatcher.d/55-wan-ipv6-refresh
mkdir -p /etc/NetworkManager/dispatcher.d/pre-up.d
ln -sfn ../55-wan-ipv6-refresh \
    /etc/NetworkManager/dispatcher.d/pre-up.d/55-wan-ipv6-refresh
log "STEP 4b: /etc/NetworkManager/dispatcher.d/55-wan-ipv6-refresh installed (WAN-change handler)"

# ====================================================================
# STEP 5: Enable service
# ====================================================================
systemctl enable noid-wan-ipv6-disable-firstboot.service
log "STEP 5: noid-wan-ipv6-disable-firstboot.service enabled"

# ====================================================================
# STEP 6: Verification
# ====================================================================
log "STEP 6: verification ==="
fail=0

if [ -f /etc/gai.conf ] && [ ! -L /etc/gai.conf ] && \
   [ "$(stat -c '%u:%g:%a:%h' /etc/gai.conf)" = 0:0:644:1 ]; then
    if grep -q "precedence ::ffff:0:0/96 100" /etc/gai.conf; then
        log "  ✓ /etc/gai.conf present with IPv4 precedence 100"
    else
        log "  ✗ /etc/gai.conf present but precedence 100 MISSING"
        fail=$((fail + 1))
    fi
else
    log "  ✗ /etc/gai.conf missing or unsafe metadata"
    fail=$((fail + 1))
fi

if [ -f /etc/sysctl.d/98-privacy-network.conf ] && \
   [ ! -L /etc/sysctl.d/98-privacy-network.conf ] && \
   [ "$(stat -c '%u:%g:%a:%h' /etc/sysctl.d/98-privacy-network.conf)" = \
     0:0:640:1 ]; then
    if ! grep -Eq '^[[:space:]]*net\.ipv4\.tcp_timestamps[[:space:]]*=' \
           /etc/sysctl.d/98-privacy-network.conf && \
       grep -q "ip_forward = 0" /etc/sysctl.d/98-privacy-network.conf && \
       [ ! -e /etc/sysctl.d/99-privacy-network.conf ]; then
        log "  ✓ 98-privacy-network.conf precedes hardening and pins ip_forward=0"
    else
        log "  ✗ M07 sysctl order/content is not reset-safe"
        fail=$((fail + 1))
    fi
else
    log "  ✗ 98-privacy-network.conf missing or unsafe metadata"
    fail=$((fail + 1))
fi

if [ -f /usr/local/sbin/noid-wan-ipv6-disable.sh ] && \
   [ ! -L /usr/local/sbin/noid-wan-ipv6-disable.sh ] && \
   [ "$(stat -c '%u:%g:%a:%h' /usr/local/sbin/noid-wan-ipv6-disable.sh)" = \
     0:0:755:1 ]; then
    log "  ✓ noid-wan-ipv6-disable.sh exact metadata present"
else
    log "  ✗ noid-wan-ipv6-disable.sh missing or unsafe metadata"
    fail=$((fail + 1))
fi

if bash -n /usr/local/sbin/noid-wan-ipv6-disable.sh 2>/dev/null; then
    log "  ✓ noid-wan-ipv6-disable.sh bash -n clean"
else
    log "  ✗ noid-wan-ipv6-disable.sh bash -n FAILED"
    fail=$((fail + 1))
fi

if grep -qxF 'scopev4 ::ffff:0.0.0.0/96       14' /etc/gai.conf 2>/dev/null \
   && ! grep -Eq '^[[:space:]]*scopev4[[:space:]]+::/96[[:space:]]+14([[:space:]]*(#.*)?)?$' \
        /etc/gai.conf 2>/dev/null; then
    log "  ✓ gai.conf IPv4-mapped default scope is valid"
else
    log "  ✗ gai.conf IPv4-mapped default scope missing or invalid"
    fail=$((fail + 1))
fi

if [ -f /etc/tmpfiles.d/noid-wan-ipv6.conf ] && \
   [ ! -L /etc/tmpfiles.d/noid-wan-ipv6.conf ] && \
   [ "$(stat -c '%u:%g:%a:%h' /etc/tmpfiles.d/noid-wan-ipv6.conf)" = 0:0:644:1 ] && \
   grep -qxF 'f /run/lock/noid-wan-ipv6.lock 0600 root root -' \
       /etc/tmpfiles.d/noid-wan-ipv6.conf; then
    log "  ✓ exact tmpfiles transaction-lock contract present"
else
    log "  ✗ tmpfiles transaction-lock contract missing or unsafe"
    fail=$((fail + 1))
fi

wan_ipv6_unit=/etc/systemd/system/noid-wan-ipv6-disable-firstboot.service
if [ -f "$wan_ipv6_unit" ] && [ ! -L "$wan_ipv6_unit" ] && \
   [ "$(stat -c '%u:%g:%a:%h' "$wan_ipv6_unit")" = 0:0:644:1 ] && \
   grep -qxF 'CapabilityBoundingSet=CAP_NET_ADMIN' "$wan_ipv6_unit" && \
   grep -qxF 'UMask=0077' "$wan_ipv6_unit" && \
   grep -qxF \
       'ReadWritePaths=/etc/sysctl.d /run/noid-privacy /run/lock/noid-wan-ipv6.lock' \
       "$wan_ipv6_unit" && \
   grep -qxF \
       'ExecStart=/usr/local/sbin/noid-wan-ipv6-disable.sh --defer-missing-network' \
       "$wan_ipv6_unit" && \
   grep -qxF 'ProtectKernelModules=yes' "$wan_ipv6_unit"; then
    log "  ✓ firstboot service exact least-privilege contract present"
else
    log "  ✗ firstboot service missing, unsafe or over-privileged"
    fail=$((fail + 1))
fi

if systemctl is-enabled noid-wan-ipv6-disable-firstboot.service >/dev/null 2>&1; then
    log "  ✓ firstboot service enabled"
else
    log "  ✗ firstboot service NOT enabled"
    fail=$((fail + 1))
fi

# NM dispatcher 55-wan-ipv6-refresh (WAN-change handler)
wan_ipv6_dispatcher=/etc/NetworkManager/dispatcher.d/55-wan-ipv6-refresh
wan_ipv6_preup=/etc/NetworkManager/dispatcher.d/pre-up.d/55-wan-ipv6-refresh
if [ -f "$wan_ipv6_dispatcher" ] && [ ! -L "$wan_ipv6_dispatcher" ] && \
   [ "$(stat -c '%u:%g:%a:%h' "$wan_ipv6_dispatcher")" = 0:0:700:1 ] && \
   [ -L "$wan_ipv6_preup" ] && \
   [ "$(readlink "$wan_ipv6_preup")" = ../55-wan-ipv6-refresh ]; then
    log "  ✓ 55-wan-ipv6-refresh exact dispatcher + pre-up link present"
else
    log "  ✗ 55-wan-ipv6-refresh missing or unsafe metadata/link"
    fail=$((fail + 1))
fi

if bash -n "$wan_ipv6_dispatcher" 2>/dev/null; then
    log "  ✓ 55-wan-ipv6-refresh bash -n clean"
else
    log "  ✗ 55-wan-ipv6-refresh bash -n FAILED"
    fail=$((fail + 1))
fi

if [ "$fail" -gt 0 ]; then
    log "STEP 6: verification FAILED ($fail check(s) failed)"
    exit 1
fi
log "STEP 6: verification passed"

# ====================================================================
# STEP 7: User-doc — exact physical-IPv6 support boundary
# ====================================================================
# Physical IPv6 is disabled at multiple independent layers. v1.7 does not have
# an IPv6-aware XDP/NDP/RA/return-flow design, so a command recipe that flips
# only sysctl/NM state would advertise an end state the image cannot enforce.
log "STEP 7: writing /usr/share/doc/noid-privacy/07-physical-ipv6-boundary.md"
mkdir -p /usr/share/doc/noid-privacy
rm -f /usr/share/doc/noid-privacy/07-ipv6-reactivate.md
cat > /usr/share/doc/noid-privacy/07-physical-ipv6-boundary.md <<'IPV6_DOC_EOF'
# Physical IPv6 support boundary

NoID Privacy v1.7 does not support physical-WAN IPv6 as one coherent,
release-qualified mode. Physical Ethernet/Wi-Fi IPv6 remains disabled by
default. This is a product boundary, not a claim that IPv6 itself is insecure.

Two operational facts reinforce that boundary. Unconfigured IPv6 is not inert:
a host that never uses it still answers Router Advertisements and DHCPv6, which
the `mitm6` attack class turns into DNS takeover on an otherwise IPv4-only
network. And VPN clients have historically carried IPv4 inside the tunnel while
letting IPv6 leave beside it. Neither fact makes IPv6 insecure; both make an
unqualified IPv6 mode a worse trade than no IPv6 mode. VPN-internal IPv6 stays
supported — only the physical carrier remains IPv4.

## Where IPv6 is disabled

| Layer | Mechanism | Source |
|---|---|---|
| 1. Kernel default | `net.ipv6.conf.default.disable_ipv6=1` | Module 02 |
| 2. Kernel current physical link | `net/ipv6/conf/<link>/disable_ipv6=1` before activation | Module 07 firstboot/dispatcher |
| 3. NM connection | `ipv6.method=disabled` | Module 23 dispatcher |
| 4. Host firewall | Router Advertisement and Redirect are not admitted | Module 03 |
| 5. Physical ingress | Mandatory LAN XDP has no IPv6/NDP peer or return-flow implementation | Modules 03/05 |

Layer 2 deliberately keeps one durable assignment for the most recently
processed sysfs hardware-backed link. The classifier validates the kernel
interface name and `/sys/class/net/<link>/device`; interface-name prefixes are
not device-type evidence. On every such `pre-up`, the M07 dispatcher first sets
and verifies that link's live kernel value, then rotates the durable assignment
to it. A previously processed, inactive link can therefore show
`disable_ipv6=0` until its next `pre-up`; that is not a claim that every existing
interface node carries a permanent per-interface assignment.

NetworkManager waits for `pre-up` scripts before marking a profile fully active,
but an ordinary dispatcher script's nonzero result is logged rather than used
as an activation veto. M07 therefore applies and verifies the live sysctl before
it validates the durable file. M02's new-interface default and M23's
`ipv6.method=disabled` are independent layers; an M07 `ERROR` status remains a
real degraded-state signal and must not be described as a blocked activation.

Module 06 can classify IPv6 VPN endpoint tuples for physical transport, but
that does not create a complete physical-WAN IPv6 host mode. VPN-internal IPv6
on a tunnel is a separate supported path: the physical carrier may remain IPv4
while the provider routes IPv6 inside the authenticated tunnel.

## Why there is no reactivation command

The former guide removed one generated sysctl file, disabled only the firstboot
unit and set one NetworkManager profile to `ipv6.method=auto`. The next physical
link-up invoked the still-active M07 dispatcher and disabled IPv6 again. M23
also restored `ipv6.method=disabled`; M03 withheld the Router Advertisement
path used by common SLAAC/default-route setups; and mandatory XDP rejected
physical IPv6 ingress. A successful address or ping was therefore not a
supported postcondition.

NoID Privacy now ships no partial “re-enable” recipe. Explicit user intent still
overrides the default, but enabling physical IPv6 currently means maintaining a
custom fork of all affected modules and accepting that it is outside the v1.7
release contract. Do not disable one layer and infer that the others agree.

## Qualification required for future support

A supported implementation needs one durable policy source consumed by M02,
M03, M07, M23, M06, status and documentation, plus an IPv6-aware physical
ingress design. Its release matrix must cover:

- enable/disable across reboot and Ethernet/Wi-Fi hotplug;
- SLAAC, DHCPv6 and reviewed static addressing;
- Neighbor Discovery, Router Advertisement and Redirect validation;
- exact IPv6 peer/return-flow behavior in XDP/TC and firewalld;
- VPN-internal IPv6, physical no-VPN IPv6 and WAN-strict interactions; and
- one machine-readable mode that every user interface reports without
  inference.

Until that design and three-pass evidence exist, `ipv6.method=disabled` plus
the kernel/dispatcher/XDP layers are the only release-qualified physical mode.

## Diagnostics

```bash
cat /run/noid-privacy/wan-ipv6-status
sudo cat /etc/sysctl.d/99-wan-ipv6-off.conf
nmcli -f GENERAL.DEVICE,IP6 device show
sudo journalctl -b -t noid-wan-ipv6-refresh
sudo journalctl -b -t noid-wan-v6
sudo journalctl -b -u noid-wan-ipv6-disable-firstboot.service
```

## Related

- Module 02 sysctl hardening: 99-hardening.conf
- Module 07 firstboot script: /usr/local/sbin/noid-wan-ipv6-disable.sh
- Module 23 dispatcher: /etc/NetworkManager/dispatcher.d/40-noid-connection-defaults
- Module 03 firewalld policy: /etc/firewalld/policies/allow-host-ipv6.xml
IPV6_DOC_EOF
chmod 644 /usr/share/doc/noid-privacy/07-physical-ipv6-boundary.md
log "  [OK] /usr/share/doc/noid-privacy/07-physical-ipv6-boundary.md installed"

log "=== Module 07 complete ==="
%end
