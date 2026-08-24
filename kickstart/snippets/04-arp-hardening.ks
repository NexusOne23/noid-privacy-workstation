# ============================================================================
# Module 04 — Holistic Network State + ARP Hardening
# Status: LOCKED 2026-08-23 (v2.50) — preserve global readiness on gatewayless physical-link activation.
#
# Covers:
#   - noid-arp-hardening.sh tool (learn/status/disable/refresh)
#   - root-validated state guard before NetworkManager
#   - generated awaited pre-up + parallel post-activation dispatcher copies
#   - First-boot systemd service auto-activates ARP hardening (always-on
#     defense stack, not opt-in; the CLI stays for admin management)
#   - awaited NM pre-up dispatcher plus DHCP-complete fail-visible retry
#
# Architecture (6 components):
#   1. /usr/local/sbin/noid-arp-hardening.sh            (CLI tool)
#   2. /usr/local/sbin/noid-arp-state-guard.sh          (closed state gate)
#   3. /usr/share/noid-privacy/arp-hardening/90-arp-hardening.template
#      + firstboot/state-guard services
#   4. /usr/local/libexec/noid-network-readiness        (gateway/XDP marker
#      publisher and M11 chrony online/offline transition owner)
#   5. /etc/NetworkManager/dispatcher.d/25-noid-arp-initial-learn
#      + awaited pre-up.d symlink
#   6. Runtime-generated at 'learn' time:
#      - exact pre-up.d + no-wait.d/90-arp-hardening copies and root symlink
#      - /var/lib/noid-privacy/arp-hardening.state
#
# Activation flow: the state guard rejects malformed, symlinked, unowned or
# internally inconsistent state before NetworkManager starts. No ARP packet
# hook is installed: RFC 5227 IPv4 Address Conflict Detection needs ARP Probes,
# Announcements, incoming conflict packets and ordinary replies throughout link
# activation and operation. The learner then makes one non-blocking attempt; if
# no NIC or gateway exists, it exits cleanly and the awaited NetworkManager
# pre-up hook retriggers it on a later physical activation. If DHCP has not
# exported a gateway at pre-up, the ordinary up/dhcp4-change dispatcher event
# retries immediately after address configuration and disconnects that exact
# interface if trust establishment fails. A connected attempt runs `learn`
# (detect WAN iface + gateway IP + MAC, generate the dispatcher and publish the
# closed state file). Subsequent boots: the dispatcher re-applies the permanent
# neighbour pin at pre-up and revalidates the gateway identity after address
# configuration. For a same-IP/new-MAC transition it removes only its exact
# stale managed pin, then accepts only two time-separated matching raw
# observations with no conflicting kernel-neighbour identity. Ambiguity fails
# closed. Ethernet MACs are not authenticated, so this is bounded TOFU rather
# than proof of gateway ownership. Offline state stays quiescent instead of
# holding the boot transaction or restarting forever.
#
# Constraint notes (keep when editing):
#   - arping is used only for bounded explicit trust establishment. Standard
#     ARP remains available for RFC 5227 ACD; accepting ARP frames is not the
#     gateway trust decision. The permanent neighbour entry is.
#   - SystemCallFilter order in the firstboot unit: @chown must come AFTER
#     ~@privileged (systemd applies filter lines in order).
#   - Firewalld `FlushAllOnReload=yes` deliberately flushes external runtime
#     nftables state. M04 therefore owns no redundant nft mirror and no false
#     `ExecStartPost` reload hook; M03/M05 rebuild enforcement from durable
#     closed-schema state.
#
# Decisions:
#   [Q1] First-boot retry: ConditionPathExists=!state-file → retries each
#        boot until learn succeeds (eventually consistent)
#   [Q2] NM dispatcher: awaited pre-up refresh; active-link failure disconnects
#   [Q3] No mode toggle — always-on
#   [Q4] Learner service is a fallback; activation ordering belongs to the
#        pre-up/post-DHCP NetworkManager dispatcher transaction
#   [Q5] First-boot logging errors only, to the journal
#
# Cross-reference: M03 consumes the validated gateway identity for its XDP
# return-path gate; M05 owns approved-peer state and exact neighbour pins;
# M06 killswitch tables are a separate enforcement layer, but their hostname
# endpoint resolver also consumes the readiness marker M04 publishes; M11's
# chrony online path is conditioned on the same marker.
# ============================================================================

%packages --exclude-weakdeps
# iputils provides arping for initial/explicit gateway-MAC learning.
# Hard-dep of @workstation-product-environment; explicit listing is
# drift-proof.
iputils
# Closed-schema IPv4 validation in the boot guard and controller.
python3
# cmp binds the generated dispatcher bytes to the validated identity/template.
diffutils
%end

%post --erroronfail --log=/var/log/ks-04-arp-hardening.log
set -euo pipefail
LC_ALL=C
export LC_ALL

log() { echo "[noid-04-arp]" "$@"; }
log "=== Module 04 post-install: ARP hardening + firstboot service ==="

# ====================================================================
# STEP 1: Install the state guard and awaited initial learner
# ====================================================================
mkdir -p /usr/share/noid-privacy/arp-hardening \
    /usr/local/sbin /usr/local/libexec /etc/systemd/system
install -d -m 0755 -o root -g root /var/lib/noid-privacy

cat > /usr/local/libexec/noid-network-readiness <<'NETWORK_READINESS_EOF'
#!/bin/bash
# Publish the exact post-DHCP gateway/XDP boundary and keep chrony sources
# offline until that postcondition exists.
set -euo pipefail
umask 077
LC_ALL=C
export LC_ALL

READY_DIR=/run/noid-privacy
READY_FILE=$READY_DIR/gateway-xdp.ready
READY_CONTENT=NOID_GATEWAY_XDP_READY_V1
XDP_HEALTH=/run/noid-privacy/lan-xdp-health
STATE_GUARD=/usr/local/sbin/noid-arp-state-guard.sh
CHRONY_ONLINE_UNIT=noid-chrony-network-online.service
CHRONY_OFFLINE_UNIT=noid-chrony-network-offline.service
CHRONY_TRANSITION_LOCK=/run/chrony/noid-network-readiness.lock
WAN_SCAN_PATH=noid-wan-strict-scan-profiles.path
WAN_SCAN_UNIT=noid-wan-strict-scan-profiles.service
CHRONY_MIN_ONLINE=3
CHRONY_ONLINE_ATTEMPTS=600
CHRONY_ACTIVITY_LOG_EVERY=25

require_ready_parent() {
    if [ ! -e "$READY_DIR" ]; then
        install -d -m 0755 -o root -g root "$READY_DIR"
    fi
    [ -d "$READY_DIR" ] && [ ! -L "$READY_DIR" ] \
        && [ "$(stat -Lc '%u:%g:%a' "$READY_DIR")" = 0:0:755 ]
}

retire_ready() {
    require_ready_parent
    rm -f -- "$READY_FILE"
}

valid_ready() {
    require_ready_parent
    [ -f "$READY_FILE" ] && [ ! -L "$READY_FILE" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' "$READY_FILE")" = 0:0:644:1 ] \
        && [ "$(cat "$READY_FILE")" = "$READY_CONTENT" ] \
        && [ "$(wc -l < "$READY_FILE")" -eq 1 ]
}

runtime_boundary_verified() {
    local state detail actual_size expected_size
    [ -f "$XDP_HEALTH" ] && [ ! -L "$XDP_HEALTH" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' "$XDP_HEALTH")" = 0:0:644:1 ] \
        && [ "$(wc -l < "$XDP_HEALTH")" -eq 2 ] || return 1
    actual_size=$(stat -Lc '%s' "$XDP_HEALTH") || return 1
    { IFS= read -r state && IFS= read -r detail; } < "$XDP_HEALTH" || return 1
    expected_size=$(( ${#state} + ${#detail} + 2 ))
    [ "$actual_size" -eq "$expected_size" ] || return 1
    case "$state:$detail" in
        'STATE=ACTIVE:DETAIL=verified')
            return 0
            ;;
        # M03 owns this six-value vocabulary and fails its topology transaction
        # whenever the current LAN state actually requires XDP. Only after that
        # owner has returned success may this helper accept a DEGRADED health
        # value. Refusing one here cannot restore XDP; it only suppresses the
        # shared readiness marker after M03 has already decided the system may
        # proceed behind its L3/firewalld/WAN-strict fallback layers.
        'STATE=DEGRADED:DETAIL=no-ethernet-link'|\
        'STATE=DEGRADED:DETAIL=unsupported-link-type'|\
        'STATE=DEGRADED:DETAIL=physical-ipv6-unsupported'|\
        'STATE=DEGRADED:DETAIL=controller-missing'|\
        'STATE=DEGRADED:DETAIL=sync-or-postcheck-failed')
            # The marker has two consumers: it lets M11 bring chrony's NTS
            # sources online and lets M06 resolve a configured VPN endpoint and
            # queue WAN-strict reconciliation. The latter still requires the
            # validated ARP state and the OS resolver; XDP is not part of that
            # DNS trust chain. Accepting M03's successful owner decision keeps
            # both consumers available without weakening M03's fail-closed LAN
            # transaction. Operational versus hardware degradation remains
            # explicit in the journal, noid-status and the login notifier.
            return 0
            ;;
        # Anything else fails closed, including an unknown DETAIL: a state this
        # module has not been taught is not a state it may wave through.
        # tests/00-degradation-contract.py proves this set still equals what
        # M03 can publish, so a new reason cannot slip past unnoticed.
        *)
            return 1
            ;;
    esac
}

boundary_verified() {
    [ -x "$STATE_GUARD" ] && "$STATE_GUARD" \
        && runtime_boundary_verified
}

publish_ready() {
    local staged
    boundary_verified
    require_ready_parent
    staged=$(mktemp "$READY_DIR/.gateway-xdp.ready.XXXXXX")
    trap 'rm -f -- "${staged:-}"' EXIT
    printf '%s\n' "$READY_CONTENT" > "$staged"
    chmod 0644 "$staged"
    chown root:root "$staged"
    mv -fT -- "$staged" "$READY_FILE"
    staged=
    trap - EXIT
    valid_ready
}

chrony_offline() {
    if systemctl is-active --quiet chronyd-restricted.service; then
        # ARP first-boot runs with NoNewPrivileges and NetworkManager
        # dispatchers run in NetworkManager_dispatcher_custom_t. Neither
        # caller can receive chronyd_restricted_t's reply directly: the first
        # blocks Fedora's chronyc_t transition and the second has no matching
        # transition. PID 1 starts this synchronous, chrony-owned one-shot in
        # its own SELinux domain instead.
        #
        # Not fatal, and loud instead. This helper runs under `set -e` from
        # NetworkManager dispatchers, so an unguarded failure here aborted the
        # whole dispatcher -- and the load-bearing half, retiring the readiness
        # marker, has already happened by the time this runs. Failing the
        # dispatcher additionally skipped gateway learning, which is a
        # subsystem this transition does not own. Keeping the NTS sources
        # online is not a boundary violation either: what protects WAN egress
        # is firewalld and WAN-strict, both unaffected.
        if ! systemctl start "$CHRONY_OFFLINE_UNIT"; then
            logger -p daemon.warning -t noid-network-readiness \
                "could not hold NTS sources offline via $CHRONY_OFFLINE_UNIT"
        fi
    fi
}

lock_chrony_transition() {
    local chrony_uid chrony_gid parent_metadata lock_metadata
    chrony_uid=$(id -u chrony)
    chrony_gid=$(id -g chrony)
    [ -d /run/chrony ] && [ ! -L /run/chrony ]
    parent_metadata=$(stat -Lc '%u:%g:%a' /run/chrony)
    [ "$parent_metadata" = "$chrony_uid:$chrony_gid:750" ]
    if [ -e "$CHRONY_TRANSITION_LOCK" ] || \
       [ -L "$CHRONY_TRANSITION_LOCK" ]; then
        # Two statements, deliberately not one `&&` list. errexit exempts every
        # command of an AND-OR list except the last, so `[ -f x ] && [ ! -L x ]`
        # written as a bare statement falls straight through when the path is a
        # dangling symlink -- and `exec 9>` below would then create the target.
        # As separate simple commands each one aborts on its own.
        [ -f "$CHRONY_TRANSITION_LOCK" ]
        [ ! -L "$CHRONY_TRANSITION_LOCK" ]
    fi
    exec 9>"$CHRONY_TRANSITION_LOCK"
    lock_metadata=$(stat -Lc '%u:%g:%a:%h' "$CHRONY_TRANSITION_LOCK")
    [ "$lock_metadata" = "$chrony_uid:$chrony_gid:600:1" ]
    /usr/bin/flock --exclusive 9
}

case "${1:-}" in
    offline)
        [ "$#" -eq 1 ] || exit 2
        retire_ready
        chrony_offline
        ;;
    ready)
        [ "$#" -eq 1 ] || exit 2
        publish_ready
        # Separate statements for the same reason as the transition lock above:
        # as one `&&` list a missing unit file is exempt from errexit and the
        # start below would run against an unverified path.
        [ -f "/etc/systemd/system/$CHRONY_ONLINE_UNIT" ]
        [ ! -L "/etc/systemd/system/$CHRONY_ONLINE_UNIT" ]
        systemctl start --no-block "$CHRONY_ONLINE_UNIT"
        if systemctl is-active --quiet "$WAN_SCAN_PATH"; then
            systemctl start --no-block "$WAN_SCAN_UNIT"
        fi
        ;;
    consumer-precheck)
        [ "$#" -eq 1 ] || exit 2
        # A queued online job can legitimately become stale after the next
        # physical-link event retires readiness. Treat that as cancellation,
        # but keep a still-published invalid boundary fail-visible.
        valid_ready || exit 0
        if ! boundary_verified || \
           ! systemctl is-active --quiet chronyd-restricted.service; then
            valid_ready || exit 0
            exit 1
        fi
        ;;
    offline-consumer)
        [ "$#" -eq 1 ] || exit 2
        systemctl is-active --quiet chronyd-restricted.service
        lock_chrony_transition
        /usr/bin/chronyc -u chrony offline >/dev/null
        /usr/bin/chronyc -u chrony activity \
            | grep -qx '0 sources online'
        ;;
    online-consumer)
        [ "$#" -eq 1 ] || exit 2
        systemctl is-active --quiet chronyd-restricted.service
        lock_chrony_transition
        if ! valid_ready; then
            /usr/bin/chronyc -u chrony offline >/dev/null
            exit 0
        fi
        if ! runtime_boundary_verified; then
            /usr/bin/chronyc -u chrony offline >/dev/null
            exit 1
        fi
        /usr/bin/chronyc -u chrony online >/dev/null
        # `chronyc online` returns before asynchronous hostname resolution has
        # necessarily published an online source. The configured selection
        # policy requires `minsources 3`, so one resolved source is not a usable
        # postcondition. Wait up to two minutes for three online sources while
        # keeping the release signal and public XDP health live in every
        # iteration. Log only aggregate activity counters: they explain a slow
        # resolver path without recording server or network identities.
        attempt=0
        while [ "$attempt" -lt "$CHRONY_ONLINE_ATTEMPTS" ]; do
            if ! valid_ready; then
                /usr/bin/chronyc -u chrony offline >/dev/null || true
                exit 0
            fi
            if ! runtime_boundary_verified; then
                /usr/bin/chronyc -u chrony offline >/dev/null || true
                exit 1
            fi
            activity=''
            counts=''
            activity_ok=0
            if activity=$(/usr/bin/chronyc -u chrony activity 2>/dev/null) &&
               counts=$(printf '%s\n' "$activity" | /usr/bin/awk '
                    $2 == "sources" && $3 == "online" { online = $1 }
                    $2 == "sources" && $3 == "doing" && $4 == "burst" &&
                        $7 == "online)" { burst = $1 }
                    $2 == "sources" && $3 == "with" && $4 == "unknown" {
                        unknown = $1
                    }
                    END { printf "%d %d %d\n", online + 0, burst + 0,
                          unknown + 0 }
                '); then
                read -r online burst unknown <<<"$counts"
                activity_ok=1
            else
                online=0
                burst=0
                unknown=0
            fi
            if [ "$online" -ge "$CHRONY_MIN_ONLINE" ]; then
                /usr/bin/logger -t noid-network-readiness -- \
                    "chrony resolver readiness reached: online=$online burst=$burst unknown=$unknown activity_ok=$activity_ok"
                exit 0
            fi
            if [ $((attempt % CHRONY_ACTIVITY_LOG_EVERY)) -eq 0 ]; then
                /usr/bin/logger -t noid-network-readiness -- \
                    "waiting for chrony resolver readiness: online=$online burst=$burst unknown=$unknown activity_ok=$activity_ok required=$CHRONY_MIN_ONLINE elapsed_s=$((attempt / 5))"
            fi
            attempt=$((attempt + 1))
            /usr/bin/sleep 0.2
        done
        /usr/bin/logger -p daemon.warning -t noid-network-readiness -- \
            "chrony resolver readiness timed out: online=$online burst=$burst unknown=$unknown activity_ok=$activity_ok required=$CHRONY_MIN_ONLINE elapsed_s=$((CHRONY_ONLINE_ATTEMPTS / 5))"
        /usr/bin/chronyc -u chrony offline >/dev/null || true
        exit 1
        ;;
    status)
        [ "$#" -eq 1 ] || exit 2
        if valid_ready && boundary_verified; then
            printf '%s\n' READY
        else
            printf '%s\n' NOT_READY
            exit 1
        fi
        ;;
    *)
        echo "Usage: noid-network-readiness {offline|ready|consumer-precheck|offline-consumer|online-consumer|status}" >&2
        exit 2
        ;;
esac
NETWORK_READINESS_EOF
chmod 0755 /usr/local/libexec/noid-network-readiness
chown root:root /usr/local/libexec/noid-network-readiness

# The retired arp-family table carried no packet hook and therefore enforced
# nothing. firewalld's maintained FlushAllOnReload=yes contract also removed it
# on every D-Bus reload, which ExecStartPost cannot observe. Remove the mirror
# and its obsolete restoration machinery; M03/M05 consume their durable state
# directly.
#
# Live migration ordering is load-bearing: NetworkManager may still have the
# retired guard in Requires=. Stopping that guard first also stops
# NetworkManager and every active tunnel. Remove the dependency, make PID 1
# forget it, and only then stop the retired unit. In an installer chroot where
# daemon-reload is unavailable, disable boot activation but leave any
# hypothetical running unit alone.
rm -f /etc/systemd/system/NetworkManager.service.d/21-noid-arp-bootstrap.conf
if systemctl daemon-reload >/dev/null 2>&1; then
    systemctl disable --now noid-arp-bootstrap.service >/dev/null 2>&1 || true
else
    systemctl disable noid-arp-bootstrap.service >/dev/null 2>&1 || true
fi
rm -f \
    /usr/share/noid-privacy/arp-hardening/arp-hardening.nft.template \
    /usr/share/noid-privacy/arp-hardening/arp-bootstrap.nft \
    /usr/share/noid-privacy/arp-hardening/arp-hardening-firewalld-reload.conf.template \
    /etc/nftables/arp-hardening.nft \
    /etc/systemd/system/firewalld.service.d/arp-hardening-firewalld-reload.conf \
    /usr/local/sbin/noid-arp-bootstrap.sh \
    /etc/systemd/system/noid-arp-bootstrap.service \
    /etc/NetworkManager/dispatcher.d/25-noid-arp-bootstrap-learn \
    /etc/NetworkManager/dispatcher.d/pre-up.d/25-noid-arp-bootstrap-learn

cat > /usr/local/sbin/noid-arp-state-guard.sh <<'ARP_STATE_GUARD_EOF'
#!/bin/bash
set -euo pipefail
umask 077
LC_ALL=C
export LC_ALL

STATE=/var/lib/noid-privacy/arp-hardening.state
STATE_DIR=/var/lib/noid-privacy
DISABLED=/var/lib/noid-privacy/arp-hardening.disabled
DISPATCHER_DIR=/etc/NetworkManager/dispatcher.d
PREUP_DIR=/etc/NetworkManager/dispatcher.d/pre-up.d
NOWAIT_DIR=/etc/NetworkManager/dispatcher.d/no-wait.d
DISPATCHER=/etc/NetworkManager/dispatcher.d/90-arp-hardening
PREUP=/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening
NOWAIT=/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening
TEMPLATE=/usr/share/noid-privacy/arp-hardening/90-arp-hardening.template

fail() {
    echo "noid-arp-state-guard: $*" >&2
    exit 1
}
present() { [ -e "$1" ] || [ -L "$1" ]; }
require_regular() {
    local path=$1 mode=$2 metadata
    [ -f "$path" ] && [ ! -L "$path" ] \
        || fail "$path is not a regular non-symlink file"
    metadata=$(stat -Lc '%u:%g:%a:%h' -- "$path") \
        || fail "cannot inspect $path"
    [ "$metadata" = "0:0:$mode:1" ] \
        || fail "$path metadata is $metadata, expected 0:0:$mode:1"
}
require_directory() {
    local path=$1 metadata
    [ -d "$path" ] && [ ! -L "$path" ] \
        || fail "$path is not a non-symlink directory"
    metadata=$(stat -Lc '%u:%g:%a' -- "$path") \
        || fail "cannot inspect $path"
    [ "$metadata" = 0:0:755 ] \
        || fail "$path metadata is $metadata, expected 0:0:755"
}

require_directory "$STATE_DIR"
require_directory "$DISPATCHER_DIR"
require_directory "$PREUP_DIR"
require_directory "$NOWAIT_DIR"
require_regular "$TEMPLATE" 644
marker=0
if present "$DISABLED"; then
    require_regular "$DISABLED" 600
    [ ! -s "$DISABLED" ] || fail "disabled marker is not empty"
    marker=1
fi

if ! present "$STATE"; then
    [ "$marker" -eq 0 ] || fail "disabled marker exists without gateway identity state"
    ! present "$DISPATCHER" && ! present "$PREUP" && ! present "$NOWAIT" \
        || fail "generated dispatcher exists without gateway state"
    exit 0
fi

require_regular "$STATE" 644
parsed=$(python3 - "$STATE" <<'STATE_PY'
import ipaddress
import re
import sys

expected = {"ENABLED", "WAN_IFACE", "GATEWAY_IP", "GATEWAY_MAC", "LEARNED_AT"}
state = {}
try:
    with open(sys.argv[1], "r", encoding="ascii") as stream:
        for raw in stream:
            line = raw.rstrip("\n")
            if not line or "=" not in line:
                raise ValueError
            key, value = line.split("=", 1)
            if key not in expected or key in state or not value:
                raise ValueError
            state[key] = value
    if set(state) != expected or state["ENABLED"] not in {"0", "1"}:
        raise ValueError
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", state["WAN_IFACE"]):
        raise ValueError
    gateway = ipaddress.IPv4Address(state["GATEWAY_IP"])
    if gateway.is_unspecified or str(gateway) != state["GATEWAY_IP"]:
        raise ValueError
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", state["GATEWAY_MAC"]):
        raise ValueError
    if not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        state["LEARNED_AT"],
    ):
        raise ValueError
except (OSError, UnicodeError, ValueError):
    raise SystemExit(1)
print("\t".join((
    state["ENABLED"],
    state["WAN_IFACE"],
    state["GATEWAY_IP"],
    state["GATEWAY_MAC"],
)))
STATE_PY
) || fail "gateway state failed closed-schema validation"
IFS=$'\t' read -r enabled state_iface state_ip state_mac extra <<<"$parsed"
[ -n "$enabled" ] && [ -n "$state_iface" ] && [ -n "$state_ip" ] \
    && [ -n "$state_mac" ] && [ -z "${extra:-}" ] \
    || fail "gateway state parser returned an invalid record"

if [ "$enabled" = 1 ]; then
    [ "$marker" -eq 0 ] || fail "enabled state conflicts with disabled marker"
    [ -L "$DISPATCHER" ] \
        && [ "$(readlink "$DISPATCHER")" = no-wait.d/90-arp-hardening ] \
        || fail "normal dispatcher symlink is missing or wrong"
    require_regular "$PREUP" 700
    require_regular "$NOWAIT" 700
    bash -n "$PREUP" || fail "awaited dispatcher has invalid Bash syntax"
    bash -n "$NOWAIT" || fail "no-wait dispatcher has invalid Bash syntax"
    sed -e "s|@@WAN_IFACE@@|$state_iface|g" \
        -e "s|@@GATEWAY_IP@@|$state_ip|g" \
        -e "s|@@GATEWAY_MAC@@|$state_mac|g" \
        "$TEMPLATE" | cmp -s - "$PREUP" \
        || fail "awaited dispatcher does not match gateway identity state"
    cmp -s -- "$PREUP" "$NOWAIT" \
        || fail "awaited and no-wait dispatcher copies differ"
else
    [ "$marker" -eq 1 ] || fail "disabled identity state lacks its explicit marker"
    ! present "$DISPATCHER" && ! present "$PREUP" && ! present "$NOWAIT" \
        || fail "disabled state retains an active generated dispatcher"
fi
ARP_STATE_GUARD_EOF
chmod 0755 /usr/local/sbin/noid-arp-state-guard.sh
chown root:root /usr/local/sbin/noid-arp-state-guard.sh

cat > /etc/systemd/system/noid-arp-state-guard.service <<'ARP_STATE_GUARD_SERVICE_EOF'
[Unit]
Description=NoID Privacy validate gateway identity state before networking
DefaultDependencies=no
After=local-fs.target
Before=NetworkManager.service network-pre.target
Wants=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/noid-arp-state-guard.sh
RemainAfterExit=yes
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
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
ARP_STATE_GUARD_SERVICE_EOF
chmod 0644 /etc/systemd/system/noid-arp-state-guard.service
chown root:root /etc/systemd/system/noid-arp-state-guard.service

mkdir -p /etc/systemd/system/NetworkManager.service.d
cat > /etc/systemd/system/NetworkManager.service.d/21-noid-arp-state-guard.conf <<'ARP_NM_REQUIRE_EOF'
[Unit]
Requires=noid-arp-state-guard.service
After=noid-arp-state-guard.service
ARP_NM_REQUIRE_EOF
chmod 0644 /etc/systemd/system/NetworkManager.service.d/21-noid-arp-state-guard.conf
chown root:root /etc/systemd/system/NetworkManager.service.d/21-noid-arp-state-guard.conf

# Learn synchronously before a physical connection becomes fully active when
# NetworkManager has already exported IP4_GATEWAY. Some DHCP backends do not
# expose that value until the connection is active, so the same canonical
# script also handles up/dhcp4-change from dispatcher.d. A failed post-DHCP
# attempt disconnects only that physical interface rather than leaving an
# unpinned active link.
install -d -m 0755 -o root -g root \
    /etc/NetworkManager/dispatcher.d \
    /etc/NetworkManager/dispatcher.d/pre-up.d \
    /etc/NetworkManager/dispatcher.d/no-wait.d
cat > /etc/NetworkManager/dispatcher.d/25-noid-arp-initial-learn <<'ARP_INITIAL_DISPATCHER_EOF'
#!/bin/bash
set -euo pipefail
umask 077
LC_ALL=C
export LC_ALL
iface=${1:-}
event=${2:-}
ARP_TOOL=/usr/local/sbin/noid-arp-hardening.sh
STATE_GUARD=/usr/local/sbin/noid-arp-state-guard.sh
NETWORK_READINESS=/usr/local/libexec/noid-network-readiness
STATE=/var/lib/noid-privacy/arp-hardening.state
DISABLED=/var/lib/noid-privacy/arp-hardening.disabled
SYS_CLASS_NET=${NOID_SYS_CLASS_NET:-/sys/class/net}
case "$event" in
    pre-down|down)
        [[ "$iface" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || exit 1
        [ -d "$SYS_CLASS_NET/$iface/device" ] || exit 0
        # Retire the single global readiness marker only for the link that owns
        # the pinned identity. It is global, but a `down` is not: taking it away
        # for an unrelated NIC strands a still-active pinned WAN link with no
        # event to re-arm it. Readiness is republished only by a later
        # up/dhcp4-change on some physical link, so on a docked laptop whose
        # pinned WAN is Ethernet, switching Wi-Fi off in GNOME stopped time
        # synchronisation until the next DHCP renewal -- half a lease, i.e.
        # hours. The marker is not chrony-only either: M06's WAN-strict
        # endpoint controller refuses to resolve a VPN endpoint hostname
        # without it (06-vpn-killswitch.ks NETWORK_READY).
        #
        # No pinned identity yet, or an unreadable/implausible one, still
        # retires: before initial learning there is no link to protect, and
        # fail-closed is the right default for an unusable state file.
        pinned_iface=""
        if [ -f "$STATE" ] && [ ! -L "$STATE" ]; then
            pinned_iface=$(sed -n 's/^WAN_IFACE=//p' "$STATE" | head -1)
            [[ "$pinned_iface" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || pinned_iface=""
        fi
        if [ -z "$pinned_iface" ] || [ "$iface" = "$pinned_iface" ]; then
            "$NETWORK_READINESS" offline
        fi
        exit 0
        ;;
    pre-up|up|dhcp4-change) ;;
    *) exit 0 ;;
esac
[[ "$iface" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || exit 1
[ -d "$SYS_CLASS_NET/$iface/device" ] || exit 0
if ! "$STATE_GUARD"; then
    "$NETWORK_READINESS" offline || true
    exit 1
fi
# Once a complete identity contract exists, the generated priority-90
# dispatcher owns gateway/XDP transitions. Retiring readiness here as well
# would duplicate every pre-up/up/DHCP event and let an obsolete queued
# initial-learner action cancel the generated dispatcher's online consumer.
#
# That ownership claim does NOT hold for the durably disabled state. cmd_disable
# removes both generated dispatchers while deliberately keeping the state file
# (ENABLED=0), so from the next boot on no path recreates
# /run/noid-privacy/gateway-xdp.ready: the firstboot unit is skipped by its
# ConditionPathExists on the state file, the priority-90 dispatcher no longer
# exists, and this one used to return right here. All six chrony sources are
# declared `offline` in /etc/chrony.conf and only
# noid-chrony-network-online.service brings them up, gated on exactly that
# file, while Fedora's 20-chrony-onoffline dispatcher was replaced with an
# exit-0 shadow. The clock would therefore free-run silently after a documented
# `noid-arp-hardening.sh disable`, until NTS-KE validity broke and only the
# console-only noid-time-recovery path remained. Publish readiness for that
# case; publish_ready still refuses unless the retained M03 boundary verifies.
if [ -e "$STATE" ]; then
    if [ -e "$DISABLED" ]; then
        "$NETWORK_READINESS" ready || exit 1
    fi
    exit 0
fi
"$NETWORK_READINESS" offline
[ ! -e "$DISABLED" ] || exit 0
gateway=${IP4_GATEWAY:-}
if [ "$gateway" = 0.0.0.0 ]; then
    logger -t noid-arp-dispatcher \
        "no IPv4 gateway for $iface at $event; NetworkManager exported its no-gateway sentinel"
    exit 0
fi
if [ -z "$gateway" ] && [ "$event" != pre-up ]; then
    gateway=$(ip -4 route show default dev "$iface" 2>/dev/null \
        | awk '/^default/ {
            for (i=1; i<NF; i++) if ($i=="via") {print $(i+1); exit}
        }')
fi
if [ -z "$gateway" ]; then
    logger -t noid-arp-dispatcher \
        "no IPv4 gateway for $iface at $event; bootstrap policy retained for post-DHCP retry"
    exit 0
fi
learn_rc=0
NOID_ARP_IFACE="$iface" NOID_ARP_GATEWAY_IP="$gateway" \
    "$ARP_TOOL" --silent learn || learn_rc=$?
if [ "$learn_rc" -ne 0 ]; then
    logger -t noid-arp-dispatcher "FAILED: $event gateway learning on $iface"
    # Exit code 2 is the only outcome that means two bounded observations
    # disagree about who owns the gateway address. Then the boundary really is
    # open and taking the link down is the fail-closed answer.
    #
    # Every other failure -- no gateway yet, no arping reply, a helper that
    # could not run -- only means this control has not established itself. The
    # firewalld DROP default, block-lan-out, the M03 XDP/TC boundary and
    # WAN-strict all keep enforcing regardless, so disconnecting bought no
    # protection and instead stranded the owner on an ordinary DHCP race. That
    # also contradicted docs/hardware-network-compatibility.md, which promises
    # the owner is not left without WAN repair access.
    if [ "$learn_rc" -eq 2 ] && [ "$event" != pre-up ]; then
        logger -t noid-arp-dispatcher \
            "gateway identity is contested on $iface; disconnecting"
        /usr/bin/nmcli device disconnect "$iface" >/dev/null 2>&1 || true
    fi
    exit 1
fi
ARP_INITIAL_DISPATCHER_EOF
chmod 0700 /etc/NetworkManager/dispatcher.d/25-noid-arp-initial-learn
chown root:root /etc/NetworkManager/dispatcher.d/25-noid-arp-initial-learn
ln -sfnT ../25-noid-arp-initial-learn \
    /etc/NetworkManager/dispatcher.d/pre-up.d/25-noid-arp-initial-learn

# --- Generated NetworkManager dispatcher template (fail-closed refresh) ---
# On interface-up: every usable gateway identity is revalidated through the
# bounded TOFU primitive before normal consumers continue. Pre-up restores the
# last validated exact pin, while up/dhcp4-change can safely rebind a legitimate
# same-IP/new-MAC gateway only after two matching raw observations when no
# independent kernel neighbour exists.
cat > /usr/share/noid-privacy/arp-hardening/90-arp-hardening.template <<'NM_TEMPLATE_EOF'
#!/bin/bash
#
# NoID Privacy — ARP Hardening NetworkManager dispatcher
# Auto-generated by: noid-arp-hardening.sh learn
#
# Features:
#   - awaited pre-up protection when DHCP state is available
#   - immediate up/dhcp4-change retry when pre-up has no gateway
#   - exact event-interface/gateway selection
#   - active-link failure disconnects only the affected interface
#

set -euo pipefail
umask 077

IFACE="$1"
ACTION="$2"

GATEWAY_IP="@@GATEWAY_IP@@"
GATEWAY_MAC="@@GATEWAY_MAC@@"
WAN_IFACE="@@WAN_IFACE@@"
ARP_TOOL="/usr/local/sbin/noid-arp-hardening.sh"
STATE_GUARD="/usr/local/sbin/noid-arp-state-guard.sh"
NETWORK_READINESS="/usr/local/libexec/noid-network-readiness"
DISABLED="/var/lib/noid-privacy/arp-hardening.disabled"
ACTIVATION_MARKER_PREFIX="/run/noid-privacy/arp-activation-ready"
ACTIVATION_MARKER_CONTENT="NOID_ARP_ACTIVATION_READY_V1"
EVENT_UUID="${CONNECTION_UUID:-}"

valid_event_uuid() {
    [[ "$EVENT_UUID" =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ ]]
}

activation_marker_path() {
    printf '%s.%s\n' "$ACTIVATION_MARKER_PREFIX" "$IFACE"
}

require_activation_parent() {
    [ -d /run/noid-privacy ] && [ ! -L /run/noid-privacy ] \
        && [ "$(stat -Lc '%u:%g:%a' /run/noid-privacy)" = 0:0:755 ]
}

clear_activation_marker() {
    local marker
    require_activation_parent
    marker=$(activation_marker_path)
    if [ -d "$marker" ] && [ ! -L "$marker" ]; then
        return 1
    fi
    rm -f -- "$marker"
}

activation_marker_matches() {
    local marker expected
    valid_event_uuid || return 1
    require_activation_parent
    marker=$(activation_marker_path)
    expected="$ACTIVATION_MARKER_CONTENT $EVENT_UUID"
    [ -f "$marker" ] && [ ! -L "$marker" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' "$marker")" = 0:0:600:1 ] \
        && [ "$(cat "$marker")" = "$expected" ] \
        && [ "$(wc -l < "$marker")" -eq 1 ]
}

publish_activation_marker() {
    local marker staged expected
    valid_event_uuid
    require_activation_parent
    marker=$(activation_marker_path)
    staged=$(mktemp "/run/noid-privacy/.arp-activation-ready.${IFACE}.XXXXXX")
    trap 'rm -f -- "${staged:-}"' RETURN
    expected="$ACTIVATION_MARKER_CONTENT $EVENT_UUID"
    printf '%s\n' "$expected" > "$staged"
    chmod 0600 "$staged"
    chown root:root "$staged"
    mv -fT -- "$staged" "$marker"
    staged=
    trap - RETURN
    activation_marker_matches
}

apply_existing_config() {
    if ! pin_recorded_identity_on_event_iface; then
        logger -t noid-arp-dispatcher \
            "FAILED: cannot restore and verify pinned gateway neighbour"
        return 1
    fi
}

pin_recorded_identity_on_event_iface() {
    local records observed
    if ! ip neigh replace "$GATEWAY_IP" lladdr "$GATEWAY_MAC" \
            dev "$IFACE" nud permanent; then
        return 1
    fi
    records=$(ip -4 neigh show to "$GATEWAY_IP" dev "$IFACE") || return 1
    [ "$(grep -c . <<<"$records")" -eq 1 ] || return 1
    observed=$(awk -v ip="$GATEWAY_IP" '
        NR == 1 && $1 == ip {
            mac=""
            for (i=1; i<=NF; i++) {
                if ($i=="lladdr") mac=tolower($(i+1))
            }
            if (mac != "" && tolower($NF) == "permanent") print mac
        }
    ' <<<"$records")
    [ "$observed" = "$GATEWAY_MAC" ]
}

event_gateway_ip() {
    if [ -n "${IP4_GATEWAY:-}" ]; then
        [ "$IP4_GATEWAY" = 0.0.0.0 ] || printf '%s\n' "$IP4_GATEWAY"
    elif [ "$ACTION" != pre-up ]; then
        ip -4 route show default dev "$IFACE" 2>/dev/null \
            | awk '/^default/ {
                for (i=1; i<NF; i++) if ($i=="via") {print $(i+1); exit}
            }'
    fi
}

canonical_gateway_ip() {
    python3 -c \
        'import ipaddress,sys; print(ipaddress.IPv4Address(sys.argv[1]))' \
        "$1" 2>/dev/null
}

trigger_refresh() {
    local reason="$1" rc=0
    logger -t noid-arp-dispatcher "refresh triggered: $reason"
    if [ ! -x "$ARP_TOOL" ]; then
        logger -t noid-arp-dispatcher "ARP tool missing at $ARP_TOOL"
        return 1
    fi
    NOID_ARP_IFACE="$IFACE" NOID_ARP_GATEWAY_IP="$CURRENT_GW" \
        "$ARP_TOOL" refresh >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then
        logger -t noid-arp-dispatcher "refresh successful"
        return 0
    fi
    logger -t noid-arp-dispatcher "refresh FAILED"
    # Propagate verbatim: 2 means two bounded observations disagree about who
    # owns the gateway address, anything else means the control has not
    # established itself yet. Swallowing the code made those indistinguishable.
    return "$rc"
}

fail_event() {
    local reason="$1" severity="${2:-transient}"
    logger -t noid-arp-dispatcher "FAILED: $reason"
    # Only a contested gateway identity leaves a boundary open that this layer
    # cannot close, and only then is taking the link down the fail-closed
    # answer. For every other failure the firewalld DROP default, block-lan-out,
    # the M03 XDP/TC boundary and WAN-strict all keep enforcing, so a
    # disconnect bought no protection and stranded the owner on an ordinary
    # DHCP race -- against docs/hardware-network-compatibility.md's promise
    # that WAN repair access survives.
    if [ "$severity" = contested ] && [ "$ACTION" != pre-up ]; then
        logger -t noid-arp-dispatcher \
            "gateway identity is contested on $IFACE; disconnecting"
        /usr/bin/nmcli device disconnect "$IFACE" >/dev/null 2>&1 || true
    fi
    return 1
}

case "$ACTION" in
    pre-down|down)
        [[ "$IFACE" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || exit 1
        [ -d "/sys/class/net/$IFACE/device" ] || exit 0
        # Same rule as the initial-learn dispatcher: the readiness marker is
        # global, a link going down is not. WAN_IFACE is substituted at
        # generation time from the already validated state file, so this
        # dispatcher always knows which link owns the pin -- the pre-up fast
        # path below makes exactly this comparison. Retiring readiness for an
        # unrelated NIC left the pinned link without it and with no event to
        # re-arm, which stops NTS synchronisation and M06 WAN-strict endpoint
        # resolution until the next DHCP renewal on the pinned link.
        #
        # The activation marker stays unconditional: clearing it only forces
        # the next DHCP event to run a full transaction instead of the
        # coalescing shortcut, which is more work rather than less.
        if [ "$IFACE" = "$WAN_IFACE" ]; then
            "$NETWORK_READINESS" offline
        fi
        clear_activation_marker
        ;;
    pre-up|up|dhcp4-change)
        [[ "$IFACE" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || exit 1
        [ -d "/sys/class/net/$IFACE/device" ] || exit 0
        if [ "$ACTION" = pre-up ] || [ "$ACTION" = up ]; then
            clear_activation_marker
        fi
        if ! "$STATE_GUARD"; then
            "$NETWORK_READINESS" offline || true
            exit 1
        fi
        [ ! -e "$DISABLED" ] || exit 0
        CURRENT_GW=$(event_gateway_ip)
        if [ -z "$CURRENT_GW" ]; then
            # A gatewayless physical LAN/dock that does not own the recorded
            # pin cannot retire the single global WAN readiness marker. Doing
            # so strands a still-active pinned WAN until that unrelated link
            # changes again or the WAN renews DHCP; M11 then holds NTS offline
            # and M06 cannot resolve a configured WAN-strict hostname. The
            # down path already applies this same ownership rule. Conversely,
            # no gateway on the pinned interface may represent a real loss or
            # same-interface transition and must remain fail-closed.
            if [ "$IFACE" = "$WAN_IFACE" ]; then
                "$NETWORK_READINESS" offline
                logger -t noid-arp-dispatcher \
                    "no IPv4 gateway for pinned $IFACE; readiness retired"
            else
                logger -t noid-arp-dispatcher \
                    "no IPv4 gateway for unpinned $IFACE; preserving global readiness"
            fi
            exit 0
        fi
        # From the first actual gateway candidate onward, consumers remain
        # offline until the complete ARP/XDP topology transaction republishes
        # the marker. Invalid gateway syntax and every refresh failure therefore
        # stay fail-closed.
        "$NETWORK_READINESS" offline
        if ! CURRENT_GW=$(canonical_gateway_ip "$CURRENT_GW"); then
            fail_event "invalid non-canonical event gateway"
            exit 1
        fi

        if [ "$ACTION" = pre-up ] && [ "$IFACE" = "$WAN_IFACE" ] \
                && [ "$CURRENT_GW" = "$GATEWAY_IP" ]; then
            if ! apply_existing_config; then
                fail_event "pre-up protection restore"
                exit 1
            fi
            logger -t noid-arp-dispatcher \
                "restored validated gateway pin before activation"
            exit 0
        fi

        # NetworkManager queues DHCP actions before activation is complete and
        # guarantees that queued actions still run when later events supersede
        # them. Coalesce those early actions until this activation's `up`
        # action has completed one full refresh. A marker from another profile
        # never authorizes the shortcut. Once `up` publishes this exact UUID,
        # every later DHCP renewal still performs the complete raw observation
        # and topology transaction.
        if [ "$ACTION" = dhcp4-change ] && valid_event_uuid \
           && ! activation_marker_matches; then
            logger -t noid-arp-dispatcher \
                "gateway revalidation deferred until activation up event"
            exit 0
        fi

        refresh_rc=0
        trigger_refresh "revalidate interface=$IFACE" \
            || refresh_rc=$?
        if [ "$refresh_rc" -ne 0 ]; then
            if [ "$refresh_rc" -eq 2 ]; then
                fail_event "gateway identity is contested" contested
            else
                fail_event "transactional gateway refresh failed"
            fi
            exit 1
        fi
        if [ "$ACTION" = up ] && valid_event_uuid \
           && ! publish_activation_marker; then
            "$NETWORK_READINESS" offline || true
            fail_event "activation-generation publication failed"
            exit 1
        fi
        logger -t noid-arp-dispatcher \
            "gateway identity revalidated and boundary postchecked"
        ;;
esac
NM_TEMPLATE_EOF
chmod 644 /usr/share/noid-privacy/arp-hardening/90-arp-hardening.template

log "STEP 1: state guard + awaited learner + dispatcher template installed"

# ====================================================================
# STEP 2: Install noid-arp-hardening.sh tool
# ====================================================================
cat > /usr/local/sbin/noid-arp-hardening.sh <<'ARP_TOOL_EOF'
#!/bin/bash
#
# NoID Privacy — ARP Hardening Tool
#
# Detects the primary WAN interface and its default gateway MAC, then installs
# an exact permanent kernel neighbour entry. This prevents ordinary ARP cache
# replacement for the gateway while preserving standard ARP and RFC 5227 IPv4
# Address Conflict Detection. Ethernet source MACs are not authentication.
# Gateway changes use bounded TOFU: one non-conflicting kernel/raw identity, or
# two time-separated matching raw observations when the cache is empty.
#
# Architecture (2 runtime contracts generated by 'learn'):
#   1. awaited pre-up plus no-wait post-activation dispatcher copies
#   2. /var/lib/noid-privacy/arp-hardening.state (closed identity state)
#
# ARP hardening is activated automatically by
# noid-arp-hardening-firstboot.service on the first successful boot
# with network connectivity. No user action required.
#
# Usage (for admin management):
#   sudo noid-arp-hardening.sh learn       # detect + activate (auto on first boot)
#   sudo noid-arp-hardening.sh status      # show current state + MAC match
#   sudo noid-arp-hardening.sh disable     # remove kernel pin; retain XDP identity
#   sudo noid-arp-hardening.sh refresh     # re-learn (after router/network change)
#   sudo noid-arp-hardening.sh help
#
# Flags:
#   --silent    Minimal output (for scripted / non-interactive use)
#

set -euo pipefail
umask 077
LC_ALL=C
export LC_ALL

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — Gateway ARP Pin" \
    NOID_FMT_AUTO_SUBTITLE="Pinned gateway identity" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

TEMPLATE_DIR="/usr/share/noid-privacy/arp-hardening"
NM_DISPATCHER="/etc/NetworkManager/dispatcher.d/90-arp-hardening"
NM_DISPATCHER_PREUP="/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening"
NM_DISPATCHER_NOWAIT="/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening"
STATE_DIR="/var/lib/noid-privacy"
STATE_FILE="$STATE_DIR/arp-hardening.state"
DISABLED_FILE="$STATE_DIR/arp-hardening.disabled"
STATE_GUARD="/usr/local/sbin/noid-arp-state-guard.sh"
NETWORK_READINESS="/usr/local/libexec/noid-network-readiness"
SYS_CLASS_NET="${NOID_SYS_CLASS_NET:-/sys/class/net}"
# Test fixtures replace these two literals in their private extracted copy.
# The installed tool never accepts ownership expectations from its environment.
EXPECTED_OWNER=0
EXPECTED_GROUP=0
TX_ACTIVE=0
TX_DIR=""
TX_IFACE=""
TX_GATEWAY_IP=""
TX_OLD_ENABLED=""
TX_OLD_IFACE=""
TX_OLD_GATEWAY_IP=""
TX_OLD_GATEWAY_MAC=""
TX_OLD_LEARNED_AT=""
TX_TARGET_OLD_MAC=""
TX_TARGET_OLD_NUD=""
TX_LOCK_FD=""
declare -a TX_PATHS TX_BACKUPS

rollback_transaction() {
    local failed=0 index path backup parent
    [ "$TX_ACTIVE" = "1" ] || return 0

    for index in "${!TX_PATHS[@]}"; do
        path=${TX_PATHS[$index]}
        backup=${TX_BACKUPS[$index]}
        rm -f -- "$path" || failed=1
        if [ "$backup" != "ABSENT" ]; then
            parent=${path%/*}
            install -d -m 0755 -o root -g root "$parent" || failed=1
            cp -a -- "$backup" "$path" || failed=1
        fi
    done

    if [ -n "$TX_GATEWAY_IP" ] && [ -n "$TX_IFACE" ]; then
        ip neigh del "$TX_GATEWAY_IP" dev "$TX_IFACE" >/dev/null 2>&1 || true
        if [ -n "$TX_TARGET_OLD_MAC" ] && [ -n "$TX_TARGET_OLD_NUD" ]; then
            ip neigh replace "$TX_GATEWAY_IP" lladdr "$TX_TARGET_OLD_MAC" \
                dev "$TX_IFACE" nud "$TX_TARGET_OLD_NUD" || failed=1
        fi
    fi
    if [ "$TX_OLD_ENABLED" = 1 ] \
       && [ -n "$TX_OLD_IFACE" ] && [ -n "$TX_OLD_GATEWAY_IP" ] \
       && [ -n "$TX_OLD_GATEWAY_MAC" ]; then
        ip neigh replace "$TX_OLD_GATEWAY_IP" lladdr "$TX_OLD_GATEWAY_MAC" \
            dev "$TX_OLD_IFACE" nud permanent || failed=1
    fi
    [ "$failed" -eq 0 ]
}

cleanup_transaction() {
    local rc=$?
    trap - EXIT HUP INT TERM
    if [ "$TX_ACTIVE" = "1" ] && ! rollback_transaction; then
        err "transaction rollback failed; disconnecting NetworkManager"
        systemctl --no-block stop NetworkManager.service >/dev/null 2>&1 || true
        rc=1
    fi
    [ -z "$TX_DIR" ] || rm -rf -- "$TX_DIR"
    exit "$rc"
}
trap cleanup_transaction EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

SILENT=0
DEFER_MISSING_NETWORK="${NOID_ARP_DEFER_MISSING_NETWORK:-0}"

usage() {
    cat <<'USAGE_EOF'
Usage: noid-arp-hardening.sh [--silent] <command>

Commands:
  learn        Detect gateway + MAC, publish state, enable the permanent pin
  status       Show current state + MAC match check
  disable      Remove the kernel pin while retaining M03's XDP identity
  refresh      Re-detect gateway MAC (after router firmware update etc.)
  help         Show this help

Description:
  Pins the current IPv4 gateway to one permanent kernel neighbour entry.
  Standard ARP remains enabled for IPv4 Address Conflict Detection and normal
  link operation; this tool does not claim to authenticate Ethernet frames.

  Auto-activates on first boot via noid-arp-hardening-firstboot.service.
  NM dispatcher revalidates physical-link gateway identity after address
  configuration. A same-IP MAC change replaces only the exact stale managed
  pin, requires two time-separated matching raw observations with no
  conflicting kernel-neighbour identity, and fails closed on ambiguity.
  `disable` affects the kernel neighbour pin only. M03's default-drop XDP/TC
  boundary retains the last validated gateway identity so LAN isolation is not
  silently weakened.

Caveats:
  - Ethernet MAC addresses are not authenticated. An unexpected gateway change
    should be verified with the network operator even when bounded re-learning
    succeeds.
  - If an expected change remains fail-closed, inspect the network, then run `refresh` explicitly.
  - If automatic refresh fails (network change during boot), run 'refresh'
    manually.
  - If an approved M05 LAN-peer exception targets the gateway itself, revoke
    that peer before `disable`; its independent binding owns the same kernel
    neighbour entry.
USAGE_EOF
}

log() { [ "$SILENT" = "1" ] && return 0; echo "[noid-arp] $*"; }
err() { echo "[noid-arp] ERROR: $*" >&2; }

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        err "must run as root (use sudo)"
        exit 1
    fi
}

parse_existing_state() {
    local key value extra canonical metadata
    local -A seen=()
    TX_OLD_ENABLED=""
    TX_OLD_IFACE=""
    TX_OLD_GATEWAY_IP=""
    TX_OLD_GATEWAY_MAC=""
    TX_OLD_LEARNED_AT=""
    if [ ! -e "$STATE_FILE" ] && [ ! -L "$STATE_FILE" ]; then
        return 0
    fi
    [ -f "$STATE_FILE" ] && [ ! -L "$STATE_FILE" ] || {
        err "existing state is non-regular or symlinked"
        return 1
    }
    metadata=$(stat -Lc '%u:%g:%a:%h' -- "$STATE_FILE") || return 1
    [ "$metadata" = \
      "$EXPECTED_OWNER:$EXPECTED_GROUP:644:1" ] || {
        err "existing state has unsafe metadata: $metadata"
        return 1
    }
    while IFS='=' read -r key value extra; do
        [ -n "$key" ] && [ -z "$extra" ] || return 1
        [[ -z ${seen[$key]+present} ]] || return 1
        seen["$key"]=1
        case "$key" in
            ENABLED)
                [[ "$value" =~ ^[01]$ ]] || return 1
                TX_OLD_ENABLED=$value
                ;;
            WAN_IFACE)
                [[ "$value" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || return 1
                TX_OLD_IFACE=$value
                ;;
            GATEWAY_IP)
                canonical=$(python3 -c \
                    'import ipaddress,sys; print(ipaddress.IPv4Address(sys.argv[1]))' \
                    "$value" 2>/dev/null) || return 1
                [ "$canonical" = "$value" ] || return 1
                TX_OLD_GATEWAY_IP=$value
                ;;
            GATEWAY_MAC)
                [[ "$value" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || return 1
                TX_OLD_GATEWAY_MAC=$value
                ;;
            LEARNED_AT)
                [[ "$value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] \
                    || return 1
                TX_OLD_LEARNED_AT=$value
                ;;
            *) return 1 ;;
        esac
    done < "$STATE_FILE"
    [ "${#seen[@]}" -eq 5 ]
}

exact_permanent_neighbour_mac() {
    local ip=$1 iface=$2 records
    records=$(ip -4 neigh show to "$ip" dev "$iface" 2>/dev/null) || return 1
    [ "$(grep -c . <<<"$records")" -eq 1 ] || return 1
    awk -v ip="$ip" '
        NR == 1 && $1 == ip {
            mac=""
            for (i=1; i<=NF; i++) {
                if ($i=="lladdr") mac=tolower($(i+1))
            }
            if (mac != "" && tolower($NF) == "permanent") print mac
        }
    ' <<<"$records"
}

begin_transaction() {
    local path index backup target_before target_state metadata lock_path
    TX_IFACE=$1
    TX_GATEWAY_IP=$2
    if [ -e "$STATE_DIR" ] || [ -L "$STATE_DIR" ]; then
        [ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ] || {
            err "state directory is non-directory or symlinked"
            return 1
        }
        metadata=$(stat -Lc '%u:%g:%a' -- "$STATE_DIR") || return 1
        [ "$metadata" = \
          "$EXPECTED_OWNER:$EXPECTED_GROUP:755" ] || {
            err "state directory has unsafe metadata: $metadata"
            return 1
        }
    else
        install -d -m 0755 -o "$EXPECTED_OWNER" -g "$EXPECTED_GROUP" "$STATE_DIR"
    fi
    lock_path="$STATE_DIR/.arp-hardening.lock"
    if [ -e "$lock_path" ] || [ -L "$lock_path" ]; then
        [ -f "$lock_path" ] && [ ! -L "$lock_path" ] || {
            err "transaction lock is non-regular or symlinked"
            return 1
        }
        metadata=$(stat -Lc '%u:%g:%a:%h' -- "$lock_path") || return 1
        [ "$metadata" = \
          "$EXPECTED_OWNER:$EXPECTED_GROUP:600:1" ] || {
            err "transaction lock has unsafe metadata: $metadata"
            return 1
        }
    else
        install -m 0600 -o "$EXPECTED_OWNER" -g "$EXPECTED_GROUP" \
            /dev/null "$lock_path"
    fi
    exec {TX_LOCK_FD}<>"$lock_path"
    flock -x "$TX_LOCK_FD"
    metadata=$(stat -Lc '%u:%g:%a:%h' -- "/proc/self/fd/$TX_LOCK_FD") \
        || return 1
    [ "$metadata" = \
      "$EXPECTED_OWNER:$EXPECTED_GROUP:600:1" ] || {
        err "opened transaction lock has unsafe metadata: $metadata"
        return 1
    }
    TX_DIR=$(mktemp -d "$STATE_DIR/.arp-transaction.XXXXXX")
    chmod 0700 "$TX_DIR"
    "$STATE_GUARD" || {
        err "gateway state contract changed or failed while acquiring the transaction"
        return 1
    }
    if ! parse_existing_state; then
        err "existing state failed closed parsing"
        return 1
    fi
    if [ -z "$TX_IFACE" ] && [ -n "$TX_OLD_IFACE" ]; then
        TX_IFACE=$TX_OLD_IFACE
        TX_GATEWAY_IP=$TX_OLD_GATEWAY_IP
    fi

    TX_TARGET_OLD_MAC=""
    TX_TARGET_OLD_NUD=""
    if [ -n "$TX_IFACE" ] && [ -n "$TX_GATEWAY_IP" ]; then
        target_before=$(ip -4 neigh show to "$TX_GATEWAY_IP" dev "$TX_IFACE")
        if [ -n "$target_before" ]; then
            TX_TARGET_OLD_MAC=$(awk '
                NR == 1 { for (i=1; i<=NF; i++) if ($i=="lladdr") print tolower($(i+1)) }
            ' <<<"$target_before")
            target_state=$(awk 'NR == 1 { print tolower($NF) }' <<<"$target_before")
            [[ "$TX_TARGET_OLD_MAC" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] \
                || TX_TARGET_OLD_MAC=""
            case "$target_state" in
                permanent|noarp|reachable|stale) TX_TARGET_OLD_NUD=$target_state ;;
                *) [ -z "$TX_TARGET_OLD_MAC" ] || TX_TARGET_OLD_NUD=stale ;;
            esac
        fi
    fi

    TX_PATHS=("$NM_DISPATCHER" "$NM_DISPATCHER_PREUP" \
              "$NM_DISPATCHER_NOWAIT" \
              "$STATE_FILE" "$DISABLED_FILE")
    TX_BACKUPS=()
    for index in "${!TX_PATHS[@]}"; do
        path=${TX_PATHS[$index]}
        if [ -d "$path" ] && [ ! -L "$path" ]; then
            err "managed path is unexpectedly a directory: $path"
            return 1
        fi
        if [ -e "$path" ] || [ -L "$path" ]; then
            backup="$TX_DIR/path.$index"
            cp -a -- "$path" "$backup"
            TX_BACKUPS+=("$backup")
        else
            TX_BACKUPS+=("ABSENT")
        fi
    done
    TX_ACTIVE=1
}

atomic_publish() {
    local source=$1 destination=$2 mode=$3 parent temporary
    [ -f "$source" ] && [ ! -L "$source" ] || return 1
    parent=${destination%/*}
    install -d -m 0755 -o root -g root "$parent"
    temporary=$(mktemp "$parent/.${destination##*/}.new.XXXXXX")
    if ! install -m "$mode" -o root -g root -- "$source" "$temporary"; then
        rm -f -- "$temporary"
        return 1
    fi
    if ! mv -fT -- "$temporary" "$destination"; then
        rm -f -- "$temporary"
        return 1
    fi
}

atomic_symlink_publish() {
    local target=$1 destination=$2 parent temporary_dir temporary
    parent=${destination%/*}
    install -d -m 0755 -o root -g root "$parent"
    temporary_dir=$(mktemp -d "$parent/.${destination##*/}.new.XXXXXX")
    chmod 0700 "$temporary_dir"
    temporary="$temporary_dir/link"
    if ! ln -s -- "$target" "$temporary"; then
        rmdir -- "$temporary_dir"
        return 1
    fi
    if ! mv -fT -- "$temporary" "$destination"; then
        rm -f -- "$temporary"
        rmdir -- "$temporary_dir"
        return 1
    fi
    rmdir -- "$temporary_dir"
}

commit_transaction() {
    rm -rf -- "$TX_DIR"
    TX_ACTIVE=0
    TX_DIR=""
}

# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

detect_wan_interface() {
    # Prefer interface with active default route (multi-iface support).
    # Handles scenarios:
    #  - Laptop with WiFi + Ethernet both connected → picks active default
    # A sysfs `device` backing is the provider-neutral physical-link
    # discriminator. No VPN brand or interface-name denylist is needed.
    # Returns the first hardware-backed interface with a default route, then
    # falls back to the hardware-backed sysfs inventory before DHCP completes.
    local iface net_path
    if [ -n "${NOID_ARP_IFACE:-}" ]; then
        [[ "$NOID_ARP_IFACE" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] \
            && [ -d "$SYS_CLASS_NET/$NOID_ARP_IFACE/device" ] || return 1
        printf '%s\n' "$NOID_ARP_IFACE"
        return 0
    fi
    while IFS= read -r iface; do
        [ -z "$iface" ] && continue
        [[ "$iface" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || continue
        if [ -d "$SYS_CLASS_NET/$iface/device" ]; then
            echo "$iface"
            return 0
        fi
    done < <(ip -4 route show default 2>/dev/null | awk '/^default/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')

    # Shell pathname expansion is locale-sorted and preserves interface names;
    # unlike parsing `ls`, it cannot reinterpret whitespace or display escapes.
    for net_path in "$SYS_CLASS_NET"/*; do
        [ -e "$net_path" ] || continue
        iface=${net_path##*/}
        [ "$iface" = "lo" ] && continue
        [[ "$iface" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || continue
        [ -d "$net_path/device" ] || continue
        echo "$iface"
        return 0
    done
    return 1
}

detect_gateway_ip() {
    local iface="$1" candidate
    if [ -n "${NOID_ARP_GATEWAY_IP:-}" ]; then
        candidate=$NOID_ARP_GATEWAY_IP
    else
        candidate=$(ip -4 route show default dev "$iface" 2>/dev/null \
            | awk '/^default/ {
                for (i=1; i<NF; i++) if ($i=="via") {print $(i+1); exit}
            }')
    fi
    [ -n "$candidate" ] && [ "$candidate" != 0.0.0.0 ] || return 1
    python3 -c '
import ipaddress, sys
address = ipaddress.IPv4Address(sys.argv[1])
if address.is_unspecified:
    raise SystemExit(1)
print(address)
' "$candidate" 2>/dev/null
}

detect_gateway_mac() {
    local gateway_ip="$1"
    local iface="$2"
    local first_output first_macs second_output second_macs
    local neighbor_output neighbor_macs neighbor_count
    local neighbor_mac_count first_count second_count

    # Exit codes are load-bearing for the caller, so keep them distinct:
    #   1  the gateway identity could not be determined -- no reply yet, DHCP
    #      still settling, or a probe tool failed. That is the normal state of
    #      a link that is still joining and says nothing about an attacker.
    #   2  two bounded observations disagree about who owns the gateway
    #      address. That is the raw signature of an ARP identity conflict, and
    #      it is the only case where the boundary is genuinely open.
    # Collapsing both into 1 is what made a DHCP race indistinguishable from
    # an attack and let a routine transient tear down the user's link.

    # A permanent entry would make an explicit same-IP refresh rediscover its
    # own stale pin. Remove only the exact M04-managed identity on its recorded
    # interface. A separate dynamic/admin neighbour remains independent
    # evidence and must agree with the raw observation.
    if [ "$TX_OLD_IFACE" = "$iface" ] \
            && [ "$TX_OLD_GATEWAY_IP" = "$gateway_ip" ] \
            && [ "$TX_TARGET_OLD_NUD" = permanent ] \
            && [ "$TX_TARGET_OLD_MAC" = "$TX_OLD_GATEWAY_MAC" ]; then
        ip neigh del "$gateway_ip" dev "$iface"
    fi

    neighbor_output=$(ip -4 neigh show to "$gateway_ip" dev "$iface") \
        || return 1
    neighbor_count=$(grep -c . <<<"$neighbor_output" || true)
    # More than one neighbour entry for one address on one interface means two
    # stations answer for the gateway. That is a conflict, not a missing
    # answer.
    [ "$neighbor_count" -le 1 ] || return 2
    neighbor_macs=$(awk -v ip="$gateway_ip" '
        NR == 1 && $1 == ip {
            for (i=1; i<=NF; i++) {
                if ($i == "lladdr") mac=tolower($(i+1))
            }
            if (mac != "") print mac
        }
    ' <<<"$neighbor_output" | sort -u)
    if [ "$neighbor_count" -eq 1 ]; then
        neighbor_mac_count=$(grep -c . <<<"$neighbor_macs" || true)
        [ "$neighbor_mac_count" -eq 1 ] \
            || { [ "$neighbor_mac_count" -gt 1 ] && return 2; return 1; }
    else
        [ -z "$neighbor_macs" ] || return 1
    fi

    first_output=$(arping -c3 -w5 -I "$iface" "$gateway_ip" 2>&1) \
        || return 1
    first_macs=$(awk -F'[][]' '/reply from/ {print tolower($2)}' \
        <<<"$first_output" | grep -E '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' \
        | sort -u)
    first_count=$(grep -c . <<<"$first_macs" || true)
    # Zero replies is a link that is not ready yet; two or more distinct
    # replies is the raw signature of an ARP identity conflict.
    [ "$first_count" -eq 1 ] \
        || { [ "$first_count" -gt 1 ] && return 2; return 1; }

    if [ "$neighbor_count" -eq 1 ]; then
        [ "$first_macs" = "$neighbor_macs" ] || return 2
        printf '%s\n' "$first_macs"
        return 0
    fi

    # Fedora's AF_PACKET arping does not populate an empty kernel neighbour
    # cache. In that normal state, require a second separately bounded raw
    # observation after a real time gap, and accept only the same single MAC.
    sleep 1
    second_output=$(arping -c3 -w5 -I "$iface" "$gateway_ip" 2>&1) \
        || return 1
    second_macs=$(awk -F'[][]' '/reply from/ {print tolower($2)}' \
        <<<"$second_output" | grep -E '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' \
        | sort -u)
    second_count=$(grep -c . <<<"$second_macs" || true)
    [ "$second_count" -eq 1 ] \
        || { [ "$second_count" -gt 1 ] && return 2; return 1; }
    [ "$first_macs" = "$second_macs" ] || return 2
    printf '%s\n' "$first_macs"
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_learn() {
    require_root

    local iface gateway_ip gateway_mac parse_candidate_state

    [ -x "$STATE_GUARD" ] || {
        err "state guard missing or not executable: $STATE_GUARD"
        return 1
    }
    "$STATE_GUARD" || {
        err "gateway state contract is inconsistent"
        return 1
    }
    [ -x "$NETWORK_READINESS" ] && "$NETWORK_READINESS" offline || {
        err "could not hold WAN consumers offline before gateway learning"
        return 1
    }

    # Missing network is normal on an offline installation/live boot. The
    # system service requests deferred semantics: retain native ARP/ACD and the
    # M03 fail-closed topology boundary, then let the awaited physical-link
    # hook retry. Interactive `learn` still reports a non-zero error so an
    # administrator is never given a false success.
    iface=$(detect_wan_interface || true)
    if [ -z "${iface:-}" ]; then
        if [ "$DEFER_MISSING_NETWORK" = "1" ]; then
            log "no primary physical interface; deferred with native ARP/ACD and fail-closed topology active"
            return 0
        fi
        err "no primary physical interface detected"
        return 1
    fi
    log "primary WAN interface: $iface"

    gateway_ip=$(detect_gateway_ip "$iface" || true)
    if [ -z "${gateway_ip:-}" ]; then
        if [ "$DEFER_MISSING_NETWORK" = "1" ]; then
            log "no default IPv4 gateway on $iface; deferred with native ARP/ACD and fail-closed topology active"
            return 0
        fi
        err "no default IPv4 gateway on $iface"
        return 1
    fi
    log "default gateway IP: $gateway_ip"

    # From this point onward every mutation is serialized and covered by the
    # exact prior-file and prior-neighbour snapshot. The commit is
    # delayed until generated files, runtime state and durable LAN peers have
    # all passed their postconditions.
    begin_transaction "$iface" "$gateway_ip"

    # Standard ARP reaches the kernel even when XDP/TC is active. The bounded
    # probe below scopes trust establishment by exact interface/IP and rejects
    # multiple or kernel/raw-observation-disagreeing MACs.
    local detect_rc=0
    gateway_mac=$(detect_gateway_mac "$gateway_ip" "$iface") || detect_rc=$?
    if [ "$detect_rc" -eq 2 ]; then
        # Propagated verbatim: only this outcome means the gateway identity is
        # actively contested, and only this outcome justifies a caller taking
        # the link down. Every other failure below returns 1 and leaves the
        # link alone.
        err "conflicting MAC observations for $gateway_ip on $iface"
        return 2
    fi
    if [ "$detect_rc" -ne 0 ]; then
        err "could not resolve one unambiguous MAC for $gateway_ip on $iface"
        return 1
    fi
    if [ -z "$gateway_mac" ]; then
        err "could not resolve MAC of $gateway_ip via arping on $iface (is the network up?)"
        return 1
    fi
    if ! [[ "$gateway_mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
        err "gateway neighbor entry returned an invalid MAC address"
        return 1
    fi
    gateway_mac=${gateway_mac,,}
    log "gateway MAC: $gateway_mac"

    [ -f "$TEMPLATE_DIR/90-arp-hardening.template" ] \
        && [ ! -L "$TEMPLATE_DIR/90-arp-hardening.template" ] || {
        err "template missing or symlinked: $TEMPLATE_DIR/90-arp-hardening.template"
        return 1
    }

    # Generate all durable artifacts inside the private transaction directory.
    # Nothing under /etc or /var is published until every parser accepts the
    # complete candidate set.
    sed -e "s|@@WAN_IFACE@@|$iface|g" \
        -e "s|@@GATEWAY_IP@@|$gateway_ip|g" \
        -e "s|@@GATEWAY_MAC@@|$gateway_mac|g" \
        "$TEMPLATE_DIR/90-arp-hardening.template" > "$TX_DIR/90-arp-hardening"

    cat > "$TX_DIR/arp-hardening.state" <<STATE_EOF
ENABLED=1
WAN_IFACE=$iface
GATEWAY_IP=$gateway_ip
GATEWAY_MAC=$gateway_mac
LEARNED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
STATE_EOF

    bash -n "$TX_DIR/90-arp-hardening"
    if grep -q '@@[A-Z_][A-Z_]*@@' "$TX_DIR/90-arp-hardening"; then
        err "generated policy retains an unsubstituted placeholder"
        return 1
    fi
    parse_candidate_state=$(python3 - "$TX_DIR/arp-hardening.state" <<'STATE_PY'
import ipaddress
import re
import sys

expected = {"ENABLED", "WAN_IFACE", "GATEWAY_IP", "GATEWAY_MAC", "LEARNED_AT"}
state = {}
try:
    with open(sys.argv[1], "r", encoding="ascii") as stream:
        for raw in stream:
            line = raw.rstrip("\n")
            if not line or "=" not in line:
                raise ValueError
            key, value = line.split("=", 1)
            if key not in expected or key in state or not value:
                raise ValueError
            state[key] = value
    if set(state) != expected or state["ENABLED"] != "1":
        raise ValueError
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", state["WAN_IFACE"]):
        raise ValueError
    gateway = ipaddress.IPv4Address(state["GATEWAY_IP"])
    if gateway.is_unspecified or str(gateway) != state["GATEWAY_IP"]:
        raise ValueError
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", state["GATEWAY_MAC"]):
        raise ValueError
    if not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        state["LEARNED_AT"],
    ):
        raise ValueError
except (OSError, UnicodeError, ValueError):
    raise SystemExit(1)
print("valid")
STATE_PY
)
    [ "$parse_candidate_state" = valid ] || {
        err "generated state failed closed-schema validation"
        return 1
    }

    # Activate the validated pin before publishing its dispatcher and state.
    # Any later failure restores the exact prior neighbour and files.
    ip neigh replace "$gateway_ip" lladdr "$gateway_mac" dev "$iface" nud permanent

    atomic_publish "$TX_DIR/90-arp-hardening" "$NM_DISPATCHER_PREUP" 0700
    atomic_publish "$TX_DIR/90-arp-hardening" "$NM_DISPATCHER_NOWAIT" 0700
    atomic_symlink_publish no-wait.d/90-arp-hardening "$NM_DISPATCHER"
    atomic_publish "$TX_DIR/arp-hardening.state" "$STATE_FILE" 0644
    rm -f "$DISABLED_FILE"
    if ! "$STATE_GUARD"; then
        err "published gateway identity contract failed validation"
        return 1
    fi

    # Mode 0644 (not 0600): the noid-network GUI reads this file + `ip neigh`
    # directly (non-privileged) for its gateway-ARP status display. Content
    # (WAN iface / gateway IP / gateway MAC / learn-timestamp) is non-secret —
    # the gateway MAC is broadcast on the LAN and readable via `ip neigh` by
    # any local process anyway. Matches the 0644 wan-strict-endpoints.txt pattern.
    # Rebuild M03's authenticated XDP/TC topology from the newly published
    # identity and restore every durable M05 peer binding. This is the actual
    # enforcement path; no hookless shadow table is involved.
    if [ ! -x /usr/local/sbin/noid-lan-topology-refresh.sh ] \
       || ! /usr/local/sbin/noid-lan-topology-refresh.sh; then
        err "gateway learned but durable LAN peer bindings could not be restored"
        return 1
    fi
    if [ "$(exact_permanent_neighbour_mac "$gateway_ip" "$iface" || true)" \
         != "$gateway_mac" ]; then
        err "topology refresh changed or removed the validated permanent gateway pin"
        return 1
    fi
    if ! "$NETWORK_READINESS" ready; then
        err "gateway/XDP postcondition passed but readiness publication failed"
        return 1
    fi

    commit_transaction

    log "ARP hardening ENABLED"
    log "  interface:    $iface"
    log "  gateway IP:   $gateway_ip"
    log "  gateway MAC:  $gateway_mac"
    # NoID Privacy journal records carry no gateway IP or MAC. Scripted callers
    # use --silent, and the generated dispatcher logs only the interface reason
    # code. Keep the exact current identity in the published state file and in
    # this interactive output instead of building a timestamped join history.
    logger -t noid-arp "ENABLED (gateway pinned on $iface)" || true
}

cmd_status() {
    require_root

    [ -x "$STATE_GUARD" ] && "$STATE_GUARD" || {
        echo "ARP hardening: ERROR (gateway state contract is inconsistent)"
        return 1
    }
    if [ ! -e "$STATE_FILE" ] && [ ! -L "$STATE_FILE" ]; then
        echo "ARP hardening: LEARNING (native ARP/ACD available; gateway identity not yet pinned)"
        return 0
    fi

    if ! parse_existing_state; then
        echo "ARP hardening: ERROR (state failed closed-schema validation)"
        return 1
    fi

    local ENABLED="$TX_OLD_ENABLED"
    local WAN_IFACE="$TX_OLD_IFACE"
    local GATEWAY_IP="$TX_OLD_GATEWAY_IP"
    local GATEWAY_MAC="$TX_OLD_GATEWAY_MAC"
    local LEARNED_AT="$TX_OLD_LEARNED_AT"

    echo "ARP hardening: $([ "${ENABLED:-0}" = "1" ] && echo ENABLED || echo DISABLED)"
    echo "  learned at:  ${LEARNED_AT:-unknown}"
    echo "  interface:   ${WAN_IFACE:-unknown}"
    echo "  gateway IP:  ${GATEWAY_IP:-unknown}"
    echo "  gateway MAC: ${GATEWAY_MAC:-unknown}"

    # Require one exact permanent entry while enabled, and no permanent entry
    # after the explicit kernel-pin opt-out.
    local current_record="" current_mac="" current_nud=""
    local interface_present=1 status_failed=0
    if [ ! -d "$SYS_CLASS_NET/$WAN_IFACE" ]; then
        echo "  kernel pin:   unavailable [interface not present]"
        interface_present=0
        status_failed=1
    else
        current_record=$(ip -4 neigh show to "$GATEWAY_IP" \
            dev "$WAN_IFACE" 2>/dev/null || true)
        current_mac=$(awk 'NR == 1 { for (i=1; i<=NF; i++) if ($i=="lladdr") print tolower($(i+1)) }' \
            <<<"$current_record")
        current_nud=$(awk 'NR == 1 { print tolower($NF) }' <<<"$current_record")
    fi
    if [ "$interface_present" -eq 0 ]; then
        :
    elif [ "$ENABLED" = 0 ]; then
        if [ "$current_nud" = permanent ]; then
            echo "  kernel pin:   PRESENT [ERROR: disabled state]"
            status_failed=1
        else
            echo "  kernel pin:   absent [OK: explicit opt-out]"
        fi
        echo "  XDP identity: retained for fail-closed M03 gateway return gate"
    elif [ "$(grep -c . <<<"$current_record")" -ne 1 ]; then
        echo "  kernel pin:   MISSING OR AMBIGUOUS"
        status_failed=1
    elif [ "$current_mac" = "$GATEWAY_MAC" ] && [ "$current_nud" = permanent ]; then
        echo "  kernel pin:   $current_mac permanent [OK MATCH]"
    else
        echo "  kernel pin:   ${current_mac:-unknown} ${current_nud:-unknown} [MISMATCH - run 'refresh']"
        status_failed=1
    fi

    if [ "$ENABLED" = 1 ]; then
        echo "  NM dispatch:  installed + state-guard validated"
    else
        echo "  NM dispatch:  absent [OK: explicit opt-out]"
    fi
    return "$status_failed"
}

cmd_disable() {
    require_root

    [ -x "$STATE_GUARD" ] && "$STATE_GUARD" || {
        err "gateway state contract is inconsistent"
        return 1
    }
    [ -x "$NETWORK_READINESS" ] && "$NETWORK_READINESS" offline || {
        err "could not hold WAN consumers offline before gateway-pin transition"
        return 1
    }
    begin_transaction "" ""
    [ -n "$TX_OLD_ENABLED" ] || {
        err "no validated gateway identity exists; nothing to disable"
        return 1
    }
    if [ "$TX_OLD_ENABLED" = 0 ]; then
        "$NETWORK_READINESS" ready
        commit_transaction
        log "ARP kernel pin already DISABLED; M03 XDP identity retained"
        return 0
    fi

    cat > "$TX_DIR/arp-hardening.disabled.state" <<STATE_EOF
ENABLED=0
WAN_IFACE=$TX_OLD_IFACE
GATEWAY_IP=$TX_OLD_GATEWAY_IP
GATEWAY_MAC=$TX_OLD_GATEWAY_MAC
LEARNED_AT=$TX_OLD_LEARNED_AT
STATE_EOF

    # A durable opt-out must remove the pin as well as its metadata. Otherwise
    # a later legitimate same-IP gateway-MAC change would remain unreachable
    # even though the CLI reported the feature disabled. Failure is covered by
    # the same transaction and restores the prior pin/configuration.
    # Publish the opt-out marker first, so any concurrent dispatcher attempt
    # fails closed during the short multi-file transition.
    install -m 0600 -o root -g root /dev/null "$TX_DIR/disabled"
    atomic_publish "$TX_DIR/disabled" "$DISABLED_FILE" 0600

    atomic_publish "$TX_DIR/arp-hardening.disabled.state" "$STATE_FILE" 0644
    rm -f "$NM_DISPATCHER"
    rm -f "$NM_DISPATCHER_PREUP"
    rm -f "$NM_DISPATCHER_NOWAIT"
    if ! "$STATE_GUARD"; then
        err "published kernel-pin opt-out contract failed validation"
        return 1
    fi

    if ip -4 neigh show to "$TX_OLD_GATEWAY_IP" dev "$TX_OLD_IFACE" \
            | grep -q .; then
        ip neigh del "$TX_OLD_GATEWAY_IP" dev "$TX_OLD_IFACE"
    fi

    # Re-seed M03 from the retained identity and prove that the explicit
    # kernel-pin opt-out did not open the default-drop LAN boundary.
    if [ ! -x /usr/local/sbin/noid-lan-topology-refresh.sh ] \
       || ! /usr/local/sbin/noid-lan-topology-refresh.sh; then
        err "kernel pin removed but M03 gateway identity could not be revalidated"
        return 1
    fi
    if [ -n "$(exact_permanent_neighbour_mac \
            "$TX_OLD_GATEWAY_IP" "$TX_OLD_IFACE" || true)" ]; then
        err "an approved M05 peer policy restored the gateway pin; revoke that peer before disabling M04"
        return 1
    fi
    if ! "$NETWORK_READINESS" ready; then
        err "retained XDP identity passed but readiness publication failed"
        return 1
    fi

    commit_transaction

    log "ARP kernel pin DISABLED; M03 XDP gateway identity retained"
    logger -t noid-arp "kernel pin DISABLED; fail-closed XDP identity retained" || true
}

cmd_refresh() {
    require_root
    if [ ! -f "$STATE_FILE" ]; then
        err "not currently active - use 'learn' first"
        exit 1
    fi
    log "re-learning gateway MAC..."
    # `cmd_learn` snapshots the current permanent pin and state; any failed or
    # interrupted re-observation restores both exactly.
    cmd_learn
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Parse --silent flag
while [ $# -gt 0 ]; do
    case "${1:-}" in
        --silent) SILENT=1; shift ;;
        *) break ;;
    esac
done

cmd="${1:-help}"
case "$cmd" in
    learn)   cmd_learn ;;
    status)  cmd_status ;;
    disable) cmd_disable ;;
    refresh) cmd_refresh ;;
    help|-h|--help) usage ;;
    *) err "unknown command: $cmd"; usage; exit 1 ;;
esac
ARP_TOOL_EOF

chmod 755 /usr/local/sbin/noid-arp-hardening.sh
chown root:root /usr/local/sbin/noid-arp-hardening.sh
log "STEP 2: /usr/local/sbin/noid-arp-hardening.sh installed (multi-iface detection + event-driven offline deferral, cross-ref M03 block-lan-out + M06 VPN killswitch)"

# ====================================================================
# STEP 3: First-boot service — auto-activate on install
# ====================================================================
# Makes one learner attempt without waiting for online state. Missing NIC or
# gateway exits successfully with native ARP/ACD and M03's fail-closed topology
# intact; the dispatcher retriggers at pre-up and, when DHCP has not exposed a
# gateway there, again at up/dhcp4-change. Once learning creates the state
# file, both the service conditions and initial dispatcher make future calls
# no-ops.
#
# Verbose output (stdout + logger) for first-boot visibility in `systemctl
# status noid-arp-hardening-firstboot.service` and journalctl.
#
cat > /etc/systemd/system/noid-arp-hardening-firstboot.service << 'SVC_EOF'
[Unit]
Description=NoID Privacy: first-boot ARP hardening (learn gateway MAC)
Documentation=file:///usr/local/sbin/noid-arp-hardening.sh
Requires=noid-arp-state-guard.service
After=noid-arp-state-guard.service NetworkManager.service
Wants=NetworkManager.service
ConditionPathExists=!/var/lib/noid-privacy/arp-hardening.state
ConditionPathExists=!/var/lib/noid-privacy/arp-hardening.disabled

[Service]
Type=oneshot
Environment=NOID_ARP_DEFER_MISSING_NETWORK=1
ExecStart=/usr/local/sbin/noid-arp-hardening.sh --silent learn
RemainAfterExit=no
StandardOutput=journal
StandardError=journal
Restart=no

# Full 2026-baseline sandbox. Service runs
# noid-arp-hardening.sh learn calls ip neigh (AF_NETLINK), arping (AF_PACKET
# raw L2), followed by M03's topology/XDP generation refresh. The latter writes
# bpffs below /sys; ProtectKernelTunables=yes remounts that hierarchy read-only
# even when ReadWritePaths names it. Keep the same narrow bpffs exception and
# kernel-tunable posture as M03's dedicated topology service.
# CAP_NET_RAW is required for arping AF_PACKET. CAP_PERFMON pairs with
# CAP_BPF for privileged verifier treatment while the final topology refresh
# loads the audited XDP object (the same minimal pair used by M03).
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ProtectKernelLogs=yes
ProtectHostname=yes
ProtectClock=yes
ProtectKernelTunables=no
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/etc/NetworkManager/dispatcher.d /var/lib/noid-privacy /run -/sys/fs/bpf
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK AF_PACKET
RestrictNamespaces=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
# SystemCallFilter ORDER constraint:
# systemd processes SystemCallFilter lines IN ORDER. Previous attempt put
# @chown BEFORE ~@privileged — but ~@privileged then REMOVED @chown again
# because chown is in the @privileged set. The intermediate version still
# failed with SIGSYS.
# Fix: @chown line moved AFTER ~@privileged so it re-adds chown to the
# filtered allow-list. Per systemd.exec(5): later directives extend earlier
# ones; ~ removes from current set, no-prefix adds to current set.
# This restores file-ownership syscalls plus the one BPF syscall required by
# noid-lan-xdp's authenticated pinned learning-map update. All other
# @privileged calls remain blocked.
SystemCallFilter=@chown
SystemCallFilter=bpf
SystemCallFilter=capset setuid
CapabilityBoundingSet=CAP_CHOWN CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_PERFMON

[Install]
WantedBy=multi-user.target
SVC_EOF
chmod 644 /etc/systemd/system/noid-arp-hardening-firstboot.service
chown root:root /etc/systemd/system/noid-arp-hardening-firstboot.service
log "STEP 3: /etc/systemd/system/noid-arp-hardening-firstboot.service installed"

# ====================================================================
# STEP 4: Enable first-boot service
# ====================================================================
systemctl enable noid-arp-state-guard.service noid-arp-hardening-firstboot.service
log "STEP 4: pre-network state guard + firstboot gateway learner enabled"

# ====================================================================
# STEP 5: Verification (logged to /var/log/ks-04-arp-hardening.log)
# ====================================================================
restorecon -RF \
    /usr/local/libexec/noid-network-readiness \
    /usr/local/sbin/noid-arp-hardening.sh \
    /usr/local/sbin/noid-arp-state-guard.sh \
    /usr/share/noid-privacy/arp-hardening \
    /etc/NetworkManager/dispatcher.d \
    /etc/systemd/system/noid-arp-state-guard.service \
    /etc/systemd/system/noid-arp-hardening-firstboot.service \
    /etc/systemd/system/NetworkManager.service.d/21-noid-arp-state-guard.conf

log "STEP 5: verification ==="
verify_failed=0

if [ -d /var/lib/noid-privacy ] && [ ! -L /var/lib/noid-privacy ] \
   && [ "$(stat -Lc '%u:%g:%a' /var/lib/noid-privacy)" = 0:0:755 ]; then
    log "  ✓ shared state root has strict metadata"
else
    log "  ✗ shared state root missing, symlinked or unsafe"
    verify_failed=1
fi

for spec in \
    /usr/local/libexec/noid-network-readiness:755 \
    /usr/local/sbin/noid-arp-hardening.sh:755 \
    /usr/local/sbin/noid-arp-state-guard.sh:755 \
    /etc/NetworkManager/dispatcher.d/25-noid-arp-initial-learn:700 \
    /usr/share/noid-privacy/arp-hardening/90-arp-hardening.template:644 \
    /etc/systemd/system/noid-arp-state-guard.service:644 \
    /etc/systemd/system/noid-arp-hardening-firstboot.service:644 \
    /etc/systemd/system/NetworkManager.service.d/21-noid-arp-state-guard.conf:644; do
    path=${spec%:*}
    mode=${spec##*:}
    if [ -f "$path" ] && [ ! -L "$path" ] \
       && [ "$(stat -Lc '%u:%g:%a:%h' -- "$path")" = \
            "0:0:$mode:1" ]; then
        log "  ✓ $path has strict metadata"
    else
        log "  ✗ $path missing or has unsafe metadata"
        verify_failed=1
    fi
done

if [ -L /etc/NetworkManager/dispatcher.d/pre-up.d/25-noid-arp-initial-learn ] \
   && [ "$(readlink /etc/NetworkManager/dispatcher.d/pre-up.d/25-noid-arp-initial-learn)" = \
        ../25-noid-arp-initial-learn ]; then
    log "  ✓ initial learner has the exact awaited pre-up symlink"
else
    log "  ✗ initial learner pre-up symlink is missing or wrong"
    verify_failed=1
fi

for retired in \
    /usr/share/noid-privacy/arp-hardening/arp-hardening.nft.template \
    /usr/share/noid-privacy/arp-hardening/arp-bootstrap.nft \
    /usr/share/noid-privacy/arp-hardening/arp-hardening-firewalld-reload.conf.template \
    /etc/nftables/arp-hardening.nft \
    /etc/systemd/system/firewalld.service.d/arp-hardening-firewalld-reload.conf \
    /usr/local/sbin/noid-arp-bootstrap.sh \
    /etc/systemd/system/noid-arp-bootstrap.service \
    /etc/systemd/system/NetworkManager.service.d/21-noid-arp-bootstrap.conf \
    /etc/NetworkManager/dispatcher.d/25-noid-arp-bootstrap-learn \
    /etc/NetworkManager/dispatcher.d/pre-up.d/25-noid-arp-bootstrap-learn; do
    if [ -e "$retired" ] || [ -L "$retired" ]; then
        log "  ✗ retired non-enforcing artifact remains: $retired"
        verify_failed=1
    fi
done

for script in \
    /usr/local/libexec/noid-network-readiness \
    /usr/local/sbin/noid-arp-hardening.sh \
    /usr/local/sbin/noid-arp-state-guard.sh \
    /etc/NetworkManager/dispatcher.d/25-noid-arp-initial-learn \
    /usr/share/noid-privacy/arp-hardening/90-arp-hardening.template; do
    if bash -n "$script"; then
        log "  ✓ Bash syntax: $script"
    else
        log "  ✗ Bash syntax: $script"
        verify_failed=1
    fi
done

if /usr/local/sbin/noid-arp-state-guard.sh; then
    log "  ✓ empty pre-learning identity lifecycle validates"
else
    log "  ✗ empty pre-learning identity lifecycle is inconsistent"
    verify_failed=1
fi

if systemd-analyze verify \
        /etc/systemd/system/noid-arp-state-guard.service \
        /etc/systemd/system/noid-arp-hardening-firstboot.service; then
    log "  ✓ systemd units verify"
else
    log "  ✗ systemd unit verification failed"
    verify_failed=1
fi

for unit in noid-arp-state-guard.service noid-arp-hardening-firstboot.service; do
    if systemctl is-enabled "$unit" >/dev/null 2>&1; then
        log "  ✓ $unit enabled"
    else
        log "  ✗ $unit NOT enabled"
        verify_failed=1
    fi
done

# Verify the actual installed awaited/revalidation contract. Keep these probes
# bound to executable template bytes, not an outer source comment.
dispatcher_template=/usr/share/noid-privacy/arp-hardening/90-arp-hardening.template
if grep -Fq 'pre-up|up|dhcp4-change)' "$dispatcher_template" && \
   grep -Fq '"$NETWORK_READINESS" offline' "$dispatcher_template" && \
   grep -Fq 'NOID_ARP_ACTIVATION_READY_V1' "$dispatcher_template" && \
   grep -Fq 'gateway revalidation deferred until activation up event' \
       "$dispatcher_template" && \
   grep -Fq 'publish_activation_marker' "$dispatcher_template" && \
   grep -Fq 'NOID_ARP_IFACE="$IFACE" NOID_ARP_GATEWAY_IP="$CURRENT_GW"' \
       "$dispatcher_template" && \
   grep -Fq 'gateway identity revalidated and boundary postchecked' \
       "$dispatcher_template"; then
    log "  ✓ NM dispatcher has awaited transactional gateway revalidation"
else
    log "  ✗ NM dispatcher template missing awaited gateway-revalidation features"
    verify_failed=1
fi

# RFC 5227 ACD requires ARP probes, announcements and conflict packets. M04
# installs no ARP-family packet hook at all.
if ! grep -qE 'nft (add|delete|list|flush)|table arp|hook (input|output)' \
        /usr/local/sbin/noid-arp-hardening.sh \
        /usr/local/sbin/noid-arp-state-guard.sh \
        /usr/share/noid-privacy/arp-hardening/90-arp-hardening.template; then
    log "  ✓ M04 preserves native IPv4 ACD and owns no nft mirror"
else
    log "  ✗ M04 unexpectedly retains nft/ARP packet-table logic"
    verify_failed=1
fi

[ "$verify_failed" -eq 0 ] || {
    log "FATAL: Module 04 post-install verification failed"
    exit 1
}

log "=== Module 04 complete ==="
%end
