#!/usr/bin/env bash
# M36 tunnel-MTU audit fixture: behavioural coverage for the cases where a
# text-only assertion cannot tell a correct verdict from a plausible one.
#
# Every command the audit touches (ip, wg, sysfs) is replaced by a scripted
# stub, so each case exercises the real decision logic against a synthetic
# topology instead of this host's live network. Covered:
#   - oversized and correctly sized IPv4 tunnels
#   - full-tunnel peer whose endpoint routes back through the tunnel itself
#   - peer without a known endpoint (alone and beside a healthy peer)
#   - multiple peers whose endpoints use different outer links
#   - ordinary and locked route MTUs stricter than the outer device MTU
#   - global, AllowedIP-only, link-local-only and unreadable IPv6 state
#   - persistent NM, runtime/provider NM, wg-quick and unknown ownership advice
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/36-noid-network-app.ks"
test_start "36-mtu-audit-fixture"

TMPDIR="$(mktemp -d /var/tmp/noid-test-36-mtu.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

extract_heredoc "$KS_FILE" NOID_NETWORK_AUDIT_EOF "$TMPDIR/audit.sh" || \
    _fail "M36 audit heredoc extraction"

# Isolate the MTU helpers and audit_mtu from the surrounding privileged
# plumbing; the extracted range must stay non-empty if the module is edited.
python3 - "$TMPDIR/audit.sh" "$TMPDIR/unit.sh" <<'PY'
import sys
src = open(sys.argv[1]).read()
start = src.index('WG_PAD=16')
end = src.index('audit_wan()')
body = src[start:end]
assert 'audit_mtu()' in body, 'audit_mtu is outside the extracted range'
open(sys.argv[2], 'w').write(body)
PY

make_harness() {
    local iface=$1 tun_mtu=$2 fwmark=$3 endpoints=$4 route_out=$5 \
          dev_mtu=$6 ipv6=$7 allowed_ips=${8:-} alt_host=${9:-} \
          alt_route=${10:-} alt_dev=${11:-} alt_mtu=${12:-}
    rm -rf "${TMPDIR:?}/bin" "${TMPDIR:?}/sys"
    mkdir -p "$TMPDIR/bin" "$TMPDIR/sys/class/net/$iface" \
             "$TMPDIR/sys/class/net/outer0"
    printf '%s\n' "$tun_mtu" > "$TMPDIR/sys/class/net/$iface/mtu"
    printf '%s\n' "$dev_mtu" > "$TMPDIR/sys/class/net/outer0/mtu"
    if [ -n "$alt_dev" ]; then
        mkdir -p "$TMPDIR/sys/class/net/$alt_dev"
        printf '%s\n' "$alt_mtu" > "$TMPDIR/sys/class/net/$alt_dev/mtu"
    fi

    cat > "$TMPDIR/bin/wg" <<EOF
#!/bin/bash
case "\$3" in
  fwmark)    printf '%s\n' '$fwmark' ;;
  endpoints) printf '%s\n' '$endpoints' ;;
  allowed-ips) printf '%s\n' '$allowed_ips' ;;
esac
EOF
    cat > "$TMPDIR/bin/ip" <<EOF
#!/bin/bash
if [ "\$1" = "-d" ]; then printf '1: %s: <POINTOPOINT>\n' '$iface'; exit 0; fi
if [ "\$1" = "-6" ]; then
  case '$ipv6' in
    yes)  printf '    inet6 2001:db8::1/128 scope global\n' ;;
    link) printf '    inet6 fe80::1/64 scope link\n' ;;
    fail) exit 1 ;;
  esac
  exit 0
fi
if [ "\$1" = route ]; then
  case '$fwmark' in
    off|none|'') [ "\$#" -eq 3 ] || exit 9 ;;
    *) [ "\${4:-}" = mark ] && [ "\${5:-}" = '$fwmark' ] || exit 9 ;;
  esac
  if [ -n '$alt_host' ] && [ "\$3" = '$alt_host' ]; then
    printf '%s\n' '$alt_route'
  else
    printf '%s\n' '$route_out'
  fi
  exit 0
fi
EOF
    cat > "$TMPDIR/bin/nmcli" <<'EOF'
#!/bin/bash
exit 1
EOF
    cat > "$TMPDIR/bin/busctl" <<'EOF'
#!/bin/bash
exit 1
EOF
    chmod +x "$TMPDIR/bin/wg" "$TMPDIR/bin/ip" \
        "$TMPDIR/bin/nmcli" "$TMPDIR/bin/busctl"
    mkdir -p "$TMPDIR/wgquick"

    cat > "$TMPDIR/harness.sh" <<EOF
set -uo pipefail
IP="$TMPDIR/bin/ip"; WG="$TMPDIR/bin/wg"
NMCLI="$TMPDIR/bin/nmcli"; BUSCTL="$TMPDIR/bin/busctl"
WG_QUICK_DIR="$TMPDIR/wgquick"
CAT=/usr/bin/cat; HEAD=/usr/bin/head; AWK=/usr/bin/awk
GREP=/usr/bin/grep; WC=/usr/bin/wc
overall=0
fmt_banner(){ :; }; fmt_note(){ :; }; fmt_step(){ :; }
fmt_ok(){ printf 'OK: %s\n' "\$1"; }
fmt_info(){ printf ' - %s\n' "\$1"; }
fmt_err(){ printf 'ERR: %s\n' "\$1"; }
. "$TMPDIR/unit.sh"
# Only the sysfs read is redirected into the fixture tree; every verdict
# below is produced by the module's own code.
mtu_read_link(){
    local v
    v=\$(/usr/bin/cat "$TMPDIR/sys/class/net/\$1/mtu" 2>/dev/null) || return 1
    case "\$v" in ''|*[!0-9]*) return 1 ;; esac
    printf '%s' "\$v"
}
audit_mtu
exit "\$overall"
EOF
}

set_nm_profile() {
    local iface=$1 flags=$2
    local uuid=11111111-2222-3333-4444-555555555555
    cat > "$TMPDIR/bin/nmcli" <<EOF
#!/bin/bash
if [ "\$1 \$2 \$3 \$4 \$5" = "-g GENERAL.CON-UUID device show $iface" ]; then
    printf '%s\n' '$uuid'
    exit 0
fi
if [ "\$1 \$2 \$3 \$4 \$5" = "-t -f UUID,DBUS-PATH connection show" ]; then
    printf '%s:%s\n' '$uuid' '/org/freedesktop/NetworkManager/Settings/7'
    exit 0
fi
exit 1
EOF
    cat > "$TMPDIR/bin/busctl" <<EOF
#!/bin/bash
printf 'u %s\n' '$flags'
EOF
    chmod +x "$TMPDIR/bin/nmcli" "$TMPDIR/bin/busctl"
}

set_wgquick_profile() {
    local iface=$1
    printf '[Interface]\n' > "$TMPDIR/wgquick/$iface.conf"
}

# run_case <name> <expected rc> [pattern|!absent-pattern ...]
run_case() {
    local name=$1 expect_rc=$2 out rc ok=1 pattern
    shift 2
    set +e
    out=$(bash "$TMPDIR/harness.sh" 2>&1)
    rc=$?
    set -e
    [ "$rc" -eq "$expect_rc" ] || ok=0
    for pattern in "$@"; do
        case "$pattern" in
            '!'*)
                ! printf '%s' "$out" | grep -qF -- "${pattern#!}" || ok=0
                ;;
            *)
                printf '%s' "$out" | grep -qF -- "$pattern" || ok=0
                ;;
        esac
    done
    if [ "$ok" -eq 1 ]; then
        _pass "$name"
    else
        printf '%s\n' "$out" | sed 's/^/      | /' >&2
        _fail "$name (rc=$rc, expected $expect_rc)"
    fi
}

# --- baseline: the real 1456 -> 1392 case this audit was written for --------
make_harness wg0 1420 0x1234 "PEER 203.0.113.9:51820" \
    "203.0.113.9 via 10.0.0.1 dev outer0 src 10.0.0.2 mark 0x1234" 1456 no
run_case "oversized IPv4 tunnel reports the computed maximum and the command" 1 \
    "Locally fragmentation-free maximum: 1392" \
    "exceeds the local maximum by 28 bytes" \
    "ip link set dev wg0 mtu 1392"

make_harness wg0 1420 0x1234 "PEER 203.0.113.9:51820" \
    "203.0.113.9 via 10.0.0.1 dev outer0 src 10.0.0.2 mark 0x1234" 1456 no
set_nm_profile wg0 0
run_case "persistent NetworkManager profile gets an exact durable command" 1 \
    "Durable owner: persistent NetworkManager WireGuard profile" \
    "nmcli connection modify uuid 11111111-2222-3333-4444-555555555555 wireguard.mtu 1392" \
    '!runtime/provider-managed NetworkManager profile'

make_harness wg0 1420 0x1234 "PEER 203.0.113.9:51820" \
    "203.0.113.9 via 10.0.0.1 dev outer0 src 10.0.0.2 mark 0x1234" 1456 no
set_nm_profile wg0 1
run_case "unsaved NetworkManager profile stays with its provider" 1 \
    "runtime/provider-managed NetworkManager profile" \
    "Set WireGuard MTU 1392 in the owning VPN app" \
    '!nmcli connection modify'

make_harness wg0 1420 0x1234 "PEER 203.0.113.9:51820" \
    "203.0.113.9 via 10.0.0.1 dev outer0 src 10.0.0.2 mark 0x1234" 1456 no
set_wgquick_profile wg0
run_case "canonical wg-quick owner gets a configuration-line repair" 1 \
    "Durable owner: canonical wg-quick configuration" \
    "$TMPDIR/wgquick/wg0.conf" \
    "MTU = 1392" \
    '!nmcli connection modify'

make_harness wg0 1392 0x1234 "PEER 203.0.113.9:51820" \
    "203.0.113.9 via 10.0.0.1 dev outer0 src 10.0.0.2 mark 0x1234" 1456 no
run_case "correctly sized tunnel passes and prints no command" 0 \
    "fits its outer link without local fragmentation" \
    '!ip link set'

# --- full tunnel: the endpoint must not be measured through the tunnel -----
make_harness wg0 1420 off "PEER 203.0.113.9:51820" \
    "203.0.113.9 dev wg0 src 10.2.0.2" 1456 no
run_case "endpoint routing back through the tunnel is refused, not measured" 1 \
    "routes back through wg0 itself" \
    "indeterminate" \
    '!ip link set'

# --- unevaluable peers must never produce a green verdict ------------------
make_harness wg0 1420 0x1234 "PEER (none)" \
    "203.0.113.9 via 10.0.0.1 dev outer0" 1456 no
run_case "a peer without an endpoint fails instead of passing" 1 \
    "has no known endpoint" \
    '!OK:'

make_harness wg0 1380 0x1234 \
    "PEER1 203.0.113.9:51820
PEER2 (none)" \
    "203.0.113.9 via 10.0.0.1 dev outer0 src 10.0.0.2" 1456 no
run_case "one unevaluable peer blocks a pass earned by a healthy peer" 1 \
    "1 of 2 peer endpoints could not be evaluated" \
    '!OK:'

# Different peers may leave through different physical links. The strictest
# locally observable ceiling must govern the one tunnel MTU shared by both.
make_harness wg0 1400 0x1234 \
    "PEER1 203.0.113.9:51820
PEER2 198.51.100.9:51820" \
    "203.0.113.9 via 10.0.0.1 dev outer0 src 10.0.0.2" 1500 no '' \
    198.51.100.9 \
    "198.51.100.9 via 10.1.0.1 dev outer1 src 10.1.0.2" outer1 1456
run_case "multiple outer links select the strictest peer ceiling" 1 \
    "Locally fragmentation-free maximum: 1392" \
    "outer outer1" \
    "exceeds the local maximum by 8 bytes"

# --- a route-scoped MTU is a stricter ceiling than the device --------------
make_harness wg0 1420 0x1234 "PEER 203.0.113.9:51820" \
    "203.0.113.9 via 10.0.0.1 dev outer0 src 10.0.0.2 mtu 1400" 1500 no
run_case "route MTU overrides a larger device MTU" 1 \
    "Locally fragmentation-free maximum: 1328" \
    "route-mtu"

make_harness wg0 1420 0x1234 "PEER 203.0.113.9:51820" \
    "203.0.113.9 via 10.0.0.1 dev outer0 src 10.0.0.2 mtu lock 1400" \
    1500 no
run_case "locked route MTU retains its numeric ceiling" 1 \
    "Locally fragmentation-free maximum: 1328" \
    "route-mtu"

# --- RFC 8200 section 5: 1280 is a floor, not a suggestion -----------------
make_harness wg0 1420 0x1234 "PEER [2001:db8::9]:51820" \
    "2001:db8::9 via fe80::1 dev outer0 src 2001:db8::2" 1280 yes
run_case "an IPv6-carrying tunnel is never pushed below 1280" 1 \
    "No safe correction exists" \
    "minimum IPv6 link MTU of 1280" \
    '!ip link set'

make_harness wg0 1420 0x1234 "PEER [2001:db8::9]:51820" \
    "2001:db8::9 via fe80::1 dev outer0 src 2001:db8::2" 1280 no \
    "PEER ::/0"
run_case "IPv6 AllowedIPs block a sub-1280 correction before address assignment" 1 \
    "No safe correction exists" \
    '!ip link set'

make_harness wg0 1420 0x1234 "PEER [2001:db8::9]:51820" \
    "2001:db8::9 via fe80::1 dev outer0 src 2001:db8::2" 1280 link
run_case "link-local-only IPv6 reports the trade-off but keeps IPv4 repair" 1 \
    "Only IPv6 link-local state is present" \
    "ip link set dev wg0 mtu 1200"

make_harness wg0 1420 0x1234 "PEER [2001:db8::9]:51820" \
    "2001:db8::9 via fe80::1 dev outer0 src 2001:db8::2" 1280 no
run_case "an IPv4-only tunnel on the same path may be lowered" 1 \
    "ip link set dev wg0 mtu 1200"

make_harness wg0 1420 0x1234 "PEER [2001:db8::9]:51820" \
    "2001:db8::9 via fe80::1 dev outer0 src 2001:db8::2" 1280 fail
run_case "unreadable IPv6 state never authorizes a sub-1280 correction" 1 \
    "No correction printed: IPv6 state" \
    '!ip link set'

test_finish
