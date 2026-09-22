#!/usr/bin/env bash
# F306 gate: strict-default global/physical Quad9 DoT plus VPN compatibility.
set -euo pipefail

TEST_NAME=05-resolved-dot-runtime
PASS_ID=${1:-}
PHASE=${2:-}
case "$PASS_ID:$PHASE" in
    live:config|fresh-install:config|reboot:config|fresh-install:quad9-query|live:vpn-query|live:vpn-dot-query|fresh-install:vpn-query|fresh-install:vpn-dot-query|reboot:vpn-query|reboot:vpn-dot-query) ;;
    *)
        echo "Usage: bash $0 {live|fresh-install|reboot} config" >&2
        echo "       bash $0 fresh-install quad9-query" >&2
        echo "       bash $0 {live|fresh-install|reboot} {vpn-query|vpn-dot-query}" >&2
        exit 2
        ;;
esac

fail() { echo "FAIL  $TEST_NAME [$PASS_ID/$PHASE]: $*" >&2; exit 1; }
pass() { echo "PASS  $TEST_NAME [$PASS_ID/$PHASE]: $*"; }

grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
for command_name in grep NetworkManager nmcli python3 resolvectl noid-dns-mode; do
    command -v "$command_name" >/dev/null 2>&1 || fail "required command missing: $command_name"
done

status_json=$(resolvectl status --json=short 2>/dev/null) || fail "cannot read resolved status JSON"
[[ -n $status_json ]] || fail "resolved status JSON is empty"
mode_status=$(noid-dns-mode --status-machine 2>/dev/null) || \
    fail "cannot read the closed NoID Privacy DNS-mode state"
nm_config=$(NetworkManager --print-config 2>/dev/null) || \
    fail "cannot read NetworkManager's merged connection defaults"

python3 - "$PHASE" "$status_json" "$mode_status" "$nm_config" <<'PY' || \
    fail "effective resolver topology violates the global/per-link DoT contract"
import json
import subprocess
import sys

phase = sys.argv[1]
rows = json.loads(sys.argv[2])
status_lines = sys.argv[3].splitlines()
nm_lines = sys.argv[4].splitlines()
if not isinstance(rows, list):
    raise SystemExit("status root is not a list")
if len(status_lines) != 8 or status_lines[0] != "NOID-DNS-MODE-V2":
    raise SystemExit("DNS-mode status schema is not V2")
mode_state = {}
for line in status_lines[1:]:
    if line.count("=") != 1:
        raise SystemExit("malformed DNS-mode state")
    key, value = line.split("=", 1)
    if not key or not value or key in mode_state:
        raise SystemExit("malformed DNS-mode key/value set")
    mode_state[key] = value
if set(mode_state) != {
        "selection", "configured", "runtime_global",
        "physical_configured", "physical_runtime", "scope", "link_mode",
}:
    raise SystemExit("DNS-mode state field set is not exact")

expected_mode = "yes"
if mode_state["configured"] != expected_mode:
    raise SystemExit(
        f"selected merged mode is {mode_state['configured']!r}, "
        f"expected {expected_mode!r} for {phase}")
if mode_state["runtime_global"] != expected_mode:
    raise SystemExit("global runtime does not match the selected mode")
if mode_state["physical_configured"] not in {
        "none", "default", expected_mode}:
    raise SystemExit("active physical profile does not match the selected mode")
if mode_state["physical_runtime"] not in {"none", expected_mode}:
    raise SystemExit("physical runtime does not match the selected mode")

sections = {}
current = None
for raw_line in nm_lines:
    line = raw_line.strip()
    if line.startswith("[") and line.endswith("]"):
        current = line[1:-1]
        sections.setdefault(current, {})
    elif current and line and not line.startswith("#") and "=" in line:
        key, value = line.split("=", 1)
        sections[current][key] = value
required = {
    "connection-noid-ethernet-dns": "type:ethernet",
    "connection-noid-wifi-dns": "type:wifi",
}
for section, device_match in required.items():
    values = sections.get(section, {})
    if values.get("match-device") != device_match:
        raise SystemExit(f"{section} does not match {device_match}")
    if values.get("connection.dns-over-tls") != "2":
        raise SystemExit(f"{section} is not fail-closed Strict DoT")
if sections.get("connection", {}).get("connection.dns-over-tls") != "1":
    raise SystemExit(
        "generic unset-profile DNS transport is not opportunistic (numeric 1)")

if mode_state["physical_configured"] == "default":
    if expected_mode != "yes":
        raise SystemExit(
            "a profile default is valid only for the strict image mode")
    if mode_state["physical_runtime"] != "none":
        raise SystemExit(
            "an active physical profile has not explicitly converged")
    if mode_state["scope"] != "global" or mode_state["link_mode"] != "none":
        raise SystemExit(
            "link-down profile-default state has an unexpected DNS scope")

global_rows = [row for row in rows if isinstance(row, dict) and "ifname" not in row]
if len(global_rows) != 1:
    raise SystemExit(f"expected one global resolver row, found {len(global_rows)}")
global_row = global_rows[0]
if global_row.get("dnsOverTLS") != expected_mode:
    raise SystemExit(
        f"global DNSOverTLS is {global_row.get('dnsOverTLS')!r}, "
        f"not {expected_mode!r}")

expected_servers = {
    ("9.9.9.9", "dns.quad9.net"),
    ("149.112.112.112", "dns.quad9.net"),
    ("2620:fe::fe", "dns.quad9.net"),
    ("2620:fe::9", "dns.quad9.net"),
}
expected_fallback = {
    ("9.9.9.9", "dns.quad9.net"),
    ("149.112.112.112", "dns.quad9.net"),
}

def server_set(row, field):
    servers = row.get(field, [])
    if not isinstance(servers, list):
        raise SystemExit(f"{field} is not a list")
    return {(str(server.get("addressString", "")), str(server.get("name", "")))
            for server in servers if isinstance(server, dict)}

if server_set(global_row, "servers") != expected_servers:
    raise SystemExit("global DNS server/name set is not exact Quad9")
if server_set(global_row, "fallbackServers") != expected_fallback:
    raise SystemExit("fallback DNS server/name set is not exact Quad9")

link_rows = [row for row in rows if isinstance(row, dict) and "ifname" in row]
for row in link_rows:
    servers = row.get("servers", [])
    if not servers:
        continue
    if row.get("dnsOverTLS") not in {"no", "opportunistic", "yes"}:
        raise SystemExit(
            f"per-link DNS on {row.get('ifname')} has an unknown DoT mode"
        )

if phase == "quad9-query":
    for row in link_rows:
        scopes = row.get("scopes", [])
        has_dns_scope = any(isinstance(scope, dict) and scope.get("protocol") == "dns"
                            for scope in scopes)
        if has_dns_scope and server_set(row, "servers") != expected_servers:
            raise SystemExit(f"non-Quad9 per-link DNS scope is active on {row.get('ifname')}")

if phase in {"vpn-query", "vpn-dot-query"}:
    candidates = []
    for row in link_rows:
        domains = row.get("searchDomains", [])
        root_route = any(isinstance(domain, dict)
                         and domain.get("name") == "."
                         and domain.get("routeOnly") is True
                         for domain in domains)
        if (root_route and row.get("servers")
                and row.get("dnsOverTLS") == "opportunistic"):
            candidates.append(row)
    if len(candidates) != 1 or not candidates[0]:
        raise SystemExit(
            "expected one active ~. VPN/private DNS scope with "
            f"opportunistic DoT, found {len(candidates)}"
        )
    candidate = candidates[0]
    ifname = str(candidate.get("ifname", ""))
    active = subprocess.run(
        ["nmcli", "-t", "-e", "no", "-f", "UUID,DEVICE",
         "connection", "show", "--active"],
        check=False, capture_output=True, text=True, timeout=10)
    if active.returncode != 0:
        raise SystemExit("cannot enumerate active NetworkManager profiles")
    profile_uuids = []
    for line in active.stdout.splitlines():
        fields = line.split(":", 1)
        if len(fields) == 2 and fields[1] == ifname:
            profile_uuids.append(fields[0])
    if len(profile_uuids) != 1:
        raise SystemExit(
            f"active ~. link {ifname!r} does not map to one profile")
    profile_mode = subprocess.run(
        ["nmcli", "-e", "no", "-g", "connection.dns-over-tls",
         "connection", "show", profile_uuids[0]],
        check=False, capture_output=True, text=True, timeout=10)
    if profile_mode.returncode != 0 or profile_mode.stdout.strip() not in {
            "-1", "default"}:
        raise SystemExit(
            "active ~. profile does not leave connection.dns-over-tls unset")
    if phase == "vpn-dot-query":
        server_addresses = {
            str(server.get("addressString", ""))
            for server in candidate.get("servers", [])
            if isinstance(server, dict)
        }
        quad9_addresses = {
            "9.9.9.9", "149.112.112.112",
            "2620:fe::fe", "2620:fe::9",
        }
        if (not server_addresses
                or not server_addresses.issubset(quad9_addresses)):
            raise SystemExit(
                "vpn-dot-query requires an exclusively Quad9 tunnel DNS "
                "server set; use a disposable test profile, not a mixed "
                "provider-owned resolver scope")
        current = candidate.get("currentServer")
        current_address = (
            str(current.get("addressString", ""))
            if isinstance(current, dict) else "")
        if current_address not in quad9_addresses:
            raise SystemExit(
                "vpn-dot-query requires Quad9 as the active tunnel resolver")
PY

case "$PHASE" in
    config)
        pass "global/physical Quad9 is strict; unset non-physical profiles default to best-effort opportunistic DoT"
        ;;
    quad9-query)
        # Explicit controlled egress: Quad9 documents this TXT response as the
        # transport probe. Strict mode must negotiate authenticated DoT.
        query_json=$(resolvectl query --cache=no --stale-data=no --type=TXT \
            --json=short proto.on.quad9.net. 2>&1) || {
            printf '%s\n' "$query_json" >&2
            fail "controlled Quad9 transport query failed"
        }
        python3 - "$query_json" <<'PY' || {
import json
import sys

record = json.loads(sys.argv[1])
if not isinstance(record, dict) or record.get("items") != ["dot"]:
    raise SystemExit(f"unexpected Quad9 protocol response: {record!r}")
PY
            printf '%s\n' "$query_json" >&2
            fail "Quad9 did not report DNS-over-TLS transport"
        }
        pass "controlled Quad9 query succeeded through the DoT transport"
        ;;
    vpn-query)
        # Explicit controlled egress through the active ~. tunnel DNS scope.
        query_output=$(resolvectl query --cache=no --stale-data=no example.com 2>&1) || {
            printf '%s\n' "$query_output" >&2
            fail "controlled VPN/private-resolver compatibility query failed"
        }
        pass "active unset VPN/private ~. resolver remains usable under opportunistic DoT with DNS/53 fallback"
        ;;
    vpn-dot-query)
        # Explicit diagnostic mutation plus controlled egress: forget cached
        # server features, then require Quad9 to report DoT for the next probe.
        # This proves the best-effort path can use TLS; it does not turn the
        # opportunistic policy into a fail-closed or downgrade-resistant one.
        resolvectl reset-server-features || \
            fail "cannot reset cached resolver feature state"
        query_json=$(resolvectl query --cache=no --stale-data=no --type=TXT \
            --json=short proto.on.quad9.net. 2>&1) || {
            printf '%s\n' "$query_json" >&2
            fail "controlled in-tunnel Quad9 transport query failed"
        }
        python3 - "$query_json" <<'PY' || {
import json
import sys

record = json.loads(sys.argv[1])
if not isinstance(record, dict) or record.get("items") != ["dot"]:
    raise SystemExit(f"unexpected Quad9 protocol response: {record!r}")
PY
            printf '%s\n' "$query_json" >&2
            fail "in-tunnel Quad9 did not report DNS-over-TLS transport"
        }
        pass "unset VPN/private profile inherited opportunistic DoT and used TLS for the controlled Quad9 probe"
        ;;
esac
