#!/bin/bash
# NoID Privacy -- reconcile an active WireGuard link with its real outer MTU.
# This changes only the live kernel link. It never edits or persists an owning
# NetworkManager, provider, wg-quick, Mullvad, Proton, or OpenVPN profile.

set -euo pipefail
set -f
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
unset BASH_ENV CDPATH ENV GLOBIGNORE PYTHONPATH PYTHONHOME
umask 077

IP=/usr/bin/ip
WG=/usr/bin/wg
FLOCK=/usr/bin/flock
LOGGER=/usr/bin/logger
CAT=/usr/bin/cat
AWK=/usr/bin/awk
GREP=/usr/bin/grep
HEAD=/usr/bin/head
LOCK=/run/lock/noid-wireguard-mtu.lock
SYS_CLASS_NET=/sys/class/net
WG_PAD=16
WG_TRAILER=32

log_info() {
    "$LOGGER" -t noid-wireguard-mtu -- "$*"
}

log_warn() {
    "$LOGGER" -p user.warning -t noid-wireguard-mtu -- "$*"
}

valid_uint() {
    case "${1:-}" in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

valid_iface() {
    case "${1:-}" in
        ''|-*|*[!A-Za-z0-9_.:-]*) return 1 ;;
    esac
    [ "${#1}" -le 15 ] && [ -e "$SYS_CLASS_NET/$1" ]
}

wireguard_iface() {
    local iface=$1 item
    for item in $("$WG" show interfaces 2>/dev/null); do
        [ "$item" != "$iface" ] || return 0
    done
    return 1
}

read_link_mtu() {
    local value
    value=$("$CAT" "$SYS_CLASS_NET/$1/mtu" 2>/dev/null) || return 1
    valid_uint "$value" || return 1
    [ "$value" -gt 0 ] || return 1
    printf '%s' "$value"
}

endpoint_family() {
    case "$1" in
        \[*\]:*|*:*:*) printf 'inet6' ;;
        *)             printf 'inet' ;;
    esac
}

endpoint_host() {
    local endpoint=$1
    case "$endpoint" in
        \[*\]:*) endpoint=${endpoint#[}; printf '%s' "${endpoint%%]*}" ;;
        *)       printf '%s' "${endpoint%:*}" ;;
    esac
}

wireguard_fwmark() {
    local mark
    mark=$("$WG" show "$1" fwmark 2>/dev/null) || return 1
    case "$mark" in
        ''|off|none) return 1 ;;
        *) printf '%s' "$mark" ;;
    esac
}

# Emit "<outer-interface> <route-mtu-or-zero>". Return 2 if an unmarked
# full-tunnel lookup loops back into the tunnel instead of revealing its outer
# path. A route-scoped/PMTU-cached MTU is stricter than the device MTU.
route_lookup() {
    local host=$1 mark=$2 tunnel=$3 output first flattened
    local dev='' route_mtu=0 i j
    local -a fields

    if [ -n "$mark" ]; then
        output=$("$IP" route get "$host" mark "$mark" 2>/dev/null) || return 1
    else
        output=$("$IP" route get "$host" 2>/dev/null) || return 1
    fi
    [ -n "$output" ] || return 1
    first=$(printf '%s\n' "$output" | "$HEAD" -1)
    read -ra fields <<<"$first"
    for ((i = 0; i < ${#fields[@]}; i++)); do
        [ "${fields[i]}" = dev ] || continue
        [ $((i + 1)) -lt ${#fields[@]} ] || return 1
        dev=${fields[i + 1]}
        break
    done
    [ -n "$dev" ] || return 1
    [ "$dev" != "$tunnel" ] || return 2

    flattened=${output//$'\n'/ }
    read -ra fields <<<"$flattened"
    for ((i = 0; i < ${#fields[@]}; i++)); do
        [ "${fields[i]}" = mtu ] || continue
        j=$((i + 1))
        [ "$j" -lt ${#fields[@]} ] || continue
        if [ "${fields[j]}" = lock ]; then
            j=$((j + 1))
            [ "$j" -lt ${#fields[@]} ] || continue
        fi
        valid_uint "${fields[j]}" || continue
        route_mtu=${fields[j]}
        break
    done
    printf '%s %s' "$dev" "$route_mtu"
}

safe_inner_mtu() {
    local outer=$1 family=$2 overhead usable
    case "$family" in
        inet6) overhead=$((40 + 8 + WG_TRAILER)) ;;
        inet)  overhead=$((20 + 8 + WG_TRAILER)) ;;
        *) return 1 ;;
    esac
    usable=$((outer - overhead))
    [ "$usable" -ge "$WG_PAD" ] || return 1
    printf '%s' $((usable / WG_PAD * WG_PAD))
}

# Return success when the tunnel carries, or is configured to carry, usable
# IPv6. Link-local-only state is not treated as user IPv6 traffic, matching the
# read-only NoID Privacy MTU audit.
tunnel_has_usable_ipv6() {
    local addresses allowed
    addresses=$("$IP" -6 addr show dev "$1" 2>/dev/null) || return 2
    if printf '%s\n' "$addresses" | "$GREP" -qE 'inet6 .* scope global'; then
        return 0
    fi
    allowed=$("$WG" show "$1" allowed-ips 2>/dev/null) || return 2
    if printf '%s\n' "$allowed" | "$GREP" -q ':'; then
        return 0
    fi
    return 1
}

reconcile_one() {
    local iface=$1 current endpoints endpoint family host mark lookup lookup_rc
    local outer_dev route_mtu outer_mtu candidate worst_safe='' worst_detail=''
    local peers=0 unresolved=0 ipv6_rc applied

    valid_iface "$iface" || {
        log_warn "refused invalid or absent interface name"
        return 1
    }
    wireguard_iface "$iface" || return 0
    current=$(read_link_mtu "$iface") || {
        log_warn "$iface has an unreadable live MTU; left unchanged"
        return 1
    }
    endpoints=$("$WG" show "$iface" endpoints 2>/dev/null | "$AWK" '{print $2}') || {
        log_warn "$iface peer endpoints are unreadable; live MTU $current retained"
        return 1
    }
    [ -n "$endpoints" ] || {
        log_warn "$iface has no peer endpoints; live MTU $current retained"
        return 1
    }
    mark=$(wireguard_fwmark "$iface") || mark=''

    while IFS= read -r endpoint; do
        [ -n "$endpoint" ] || continue
        peers=$((peers + 1))
        if [ "$endpoint" = '(none)' ]; then
            unresolved=$((unresolved + 1))
            continue
        fi
        family=$(endpoint_family "$endpoint")
        host=$(endpoint_host "$endpoint")
        if lookup=$(route_lookup "$host" "$mark" "$iface"); then
            lookup_rc=0
        else
            lookup_rc=$?
        fi
        if [ "$lookup_rc" -ne 0 ]; then
            unresolved=$((unresolved + 1))
            continue
        fi
        outer_dev=${lookup%% *}
        route_mtu=${lookup##* }
        valid_iface "$outer_dev" || {
            unresolved=$((unresolved + 1))
            continue
        }
        outer_mtu=$(read_link_mtu "$outer_dev") || {
            unresolved=$((unresolved + 1))
            continue
        }
        if [ "$route_mtu" -gt 0 ] && [ "$route_mtu" -lt "$outer_mtu" ]; then
            outer_mtu=$route_mtu
        fi
        candidate=$(safe_inner_mtu "$outer_mtu" "$family") || {
            unresolved=$((unresolved + 1))
            continue
        }
        if [ -z "$worst_safe" ] || [ "$candidate" -lt "$worst_safe" ]; then
            worst_safe=$candidate
            worst_detail="$outer_dev/$outer_mtu/$family"
        fi
    done <<<"$endpoints"

    if [ "$peers" -eq 0 ] || [ "$unresolved" -ne 0 ] || [ -z "$worst_safe" ]; then
        log_warn "$iface outer route incomplete ($unresolved/$peers peers); live MTU $current retained"
        return 1
    fi
    [ "$current" -gt "$worst_safe" ] || return 0

    if [ "$worst_safe" -lt 1280 ]; then
        if tunnel_has_usable_ipv6 "$iface"; then
            ipv6_rc=0
        else
            ipv6_rc=$?
        fi
        case "$ipv6_rc" in
            0)
                log_warn "$iface needs MTU $worst_safe below the IPv6 minimum; live MTU $current retained"
                return 1
                ;;
            1) ;;
            *)
                log_warn "$iface IPv6 state is unreadable; live MTU $current retained"
                return 1
                ;;
        esac
    fi

    if ! "$IP" link set dev "$iface" mtu "$worst_safe"; then
        log_warn "$iface MTU correction $current->$worst_safe failed; profile was not modified"
        return 1
    fi
    applied=$(read_link_mtu "$iface") || applied='unreadable'
    if [ "$applied" != "$worst_safe" ]; then
        log_warn "$iface MTU postcondition failed (expected $worst_safe, got $applied)"
        return 1
    fi
    log_info "lowered $iface live MTU $current->$worst_safe for outer $worst_detail; owning profile unchanged"
    printf '%s\n' "$iface: live MTU $current -> $worst_safe (outer $worst_detail)"
}

reconcile_all() {
    local interfaces iface failures=0
    interfaces=$("$WG" show interfaces 2>/dev/null) || return 1
    [ -n "$interfaces" ] || return 0
    for iface in $interfaces; do
        reconcile_one "$iface" || failures=$((failures + 1))
    done
    [ "$failures" -eq 0 ]
}

[ "$EUID" -eq 0 ] || {
    echo "noid-wireguard-mtu-reconcile: root required" >&2
    exit 1
}
[ "$#" -eq 1 ] || {
    echo "Usage: noid-wireguard-mtu-reconcile --all|INTERFACE" >&2
    exit 2
}

lock_state=$(stat -Lc '%u:%g:%a:%h' "$LOCK" 2>/dev/null || true)
[ -f "$LOCK" ] && [ ! -L "$LOCK" ] && [ "$lock_state" = '0:0:600:1' ] || {
    log_warn "lock file is absent or untrusted; no MTU was changed"
    exit 1
}
exec 9<>"$LOCK"
"$FLOCK" -w 3 9 || {
    log_warn "another MTU reconciliation is still active; this event was skipped"
    exit 1
}

case "$1" in
    --all) reconcile_all ;;
    --*)
        echo "Usage: noid-wireguard-mtu-reconcile --all|INTERFACE" >&2
        exit 2
        ;;
    *) reconcile_one "$1" ;;
esac
