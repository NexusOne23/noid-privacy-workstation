#!/bin/bash
# M23 NetworkManager smoke test: conf.d drop-ins
set -euo pipefail
. "$(dirname "$0")/lib.sh"

smoke_start "M23-networkmanager"

PROJECT_ROOT="$(project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/23-networkmanager.ks"

TMP_POST=$(mktemp --tmpdir smoke-m23-post-XXXXXX.sh)
smoke_register_temp_file "$TMP_POST"

extract_post "$KS_FILE" "$TMP_POST"

# M23's verification cross-checks Fedora and earlier M03/M05/M07 artefacts.
# Seed only those prerequisites so the isolated smoke matches real include
# order without weakening any M23 assertion.
install -d -m 0755 \
    "$SANDBOX_DIR/usr/local/sbin" \
    "$SANDBOX_DIR/usr/lib/NetworkManager/conf.d" \
    "$SANDBOX_DIR/etc/NetworkManager/conf.d"
touch "$SANDBOX_DIR/usr/lib/NetworkManager/conf.d/22-wifi-mac-addr.conf"
touch "$SANDBOX_DIR/etc/NetworkManager/conf.d/99-privacy.conf"
touch "$SANDBOX_DIR/etc/NetworkManager/conf.d/03-vpn-zone.conf"
printf '%s\n' 'precedence ::ffff:0:0/96 100' > "$SANDBOX_DIR/etc/gai.conf"

# No active NetworkManager command runs in the outer %post. The nmcli calls
# are payload inside the generated dispatcher and must remain byte-intact;
# the former broad sed replacement corrupted both shell conditionals and the
# artifact this test was supposed to inspect.

if run_in_sandbox "$TMP_POST"; then
    _pass "M23 %post executed without error"
else
    _fail "M23 %post returned non-zero"
fi

# Three drop-ins (00-/01-/02- priority order)
assert_in_sandbox '[ -f /etc/NetworkManager/conf.d/00-noid-mac-randomization.conf ]' \
    "00-noid-mac-randomization.conf"
assert_in_sandbox '[ -f /etc/NetworkManager/conf.d/01-noid-ipv6.conf ]' \
    "01-noid-ipv6.conf"
assert_in_sandbox '[ -f /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf ]' \
    "02-noid-connection-defaults.conf"

# Content checks (post-NM-1.54 architecture)
# WiFi MAC randomization: Fedora vendor default at /usr/lib/NetworkManager/conf.d/22-wifi-mac-addr.conf
# is NOT overridden by NoID Privacy — see Module 23 STEP 1 comment. Our file only sets
# wifi.scan-rand-mac-address and ethernet.cloned-mac-address.
assert_in_sandbox 'grep -q "wifi.scan-rand-mac-address=yes" /etc/NetworkManager/conf.d/00-noid-mac-randomization.conf' \
    "wifi.scan-rand-mac-address=yes (probe-MAC randomization)"
assert_in_sandbox 'grep -q "ethernet.cloned-mac-address=stable" /etc/NetworkManager/conf.d/00-noid-mac-randomization.conf' \
    "ethernet.cloned-mac-address=stable"
assert_in_sandbox 'grep -qx "ethernet.wake-on-lan=32768" /etc/NetworkManager/conf.d/00-noid-mac-randomization.conf' \
    "ethernet.wake-on-lan=32768 (numeric NM ignore flag; M27 device policy unchanged)"

# IPv6: NM 1.54+ rejected ipv6.method as connection-default — properties moved
# to dispatcher /etc/NetworkManager/dispatcher.d/40-noid-connection-defaults.
# 01-noid-ipv6.conf only carries ip6-privacy=2 + numeric addr-gen-mode=1
# (stable-privacy) defaults, which are accepted as connection defaults.
assert_in_sandbox 'grep -q "ipv6.ip6-privacy=2" /etc/NetworkManager/conf.d/01-noid-ipv6.conf' \
    "ipv6.ip6-privacy=2 default (RFC 4941)"
assert_in_sandbox 'grep -qx "ipv6.addr-gen-mode=1" /etc/NetworkManager/conf.d/01-noid-ipv6.conf' \
    "ipv6.addr-gen-mode=1 (stable-privacy; RFC 7217)"

# LLDP off via 02-noid-connection-defaults.conf
assert_in_sandbox '[ -f /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf ]' \
    "02-noid-connection-defaults.conf"
assert_in_sandbox 'grep -q "connection.lldp=0" /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf' \
    "connection.lldp=0 default"
assert_in_sandbox 'grep -q "ipv4.link-local=2" /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf' \
    "IPv4 link-local fallback disabled before profile activation"
assert_in_sandbox 'grep -q "ipv4.dad-timeout=200" /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf' \
    "IPv4 duplicate-address detection remains explicitly enabled"

# Per-connection hardening dispatcher (TunnelVision + ipv6.method + mdns/llmnr)
assert_in_sandbox '[ -x /etc/NetworkManager/dispatcher.d/40-noid-connection-defaults ]' \
    "Module 23 dispatcher 40-noid-connection-defaults executable"
assert_in_sandbox 'grep -q "ipv4.ignore-auto-routes" /etc/NetworkManager/dispatcher.d/40-noid-connection-defaults' \
    "dispatcher applies ipv4.ignore-auto-routes (TunnelVision CVE-2024-3661 mitigation)"
assert_in_sandbox 'grep -q "ipv6.method disabled" /etc/NetworkManager/dispatcher.d/40-noid-connection-defaults' \
    "dispatcher applies ipv6.method=disabled per-connection"

# Permissions
assert_in_sandbox '[ "$(stat -c %a /etc/NetworkManager/conf.d/00-noid-mac-randomization.conf)" = "644" ]' \
    "mode 644 on MAC randomization"

smoke_finish
