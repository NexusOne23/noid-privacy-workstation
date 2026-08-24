#!/usr/bin/env python3
"""Bind M29 tunnel-down claims to the actual M03/M06 policy semantics."""

from __future__ import annotations

import ipaddress
import pathlib
import sys
import xml.etree.ElementTree as ET


def fail(message: str) -> None:
    raise SystemExit(f"fixture failure: {message}")


if len(sys.argv) != 4:
    raise SystemExit("usage: fixture BLOCK_LAN_OUT_XML WAN_STRICT_NFT VPN_GUIDE")

policy_path = pathlib.Path(sys.argv[1])
strict_path = pathlib.Path(sys.argv[2])
guide_path = pathlib.Path(sys.argv[3])
root = ET.parse(policy_path).getroot()
if root.tag != "policy" or root.get("target") != "CONTINUE":
    fail("block-lan-out must continue traffic that matches no LAN rule")
if root.find("./ingress-zone[@name='HOST']") is None:
    fail("block-lan-out host ingress is missing")
if root.find("./egress-zone[@name='drop']") is None:
    fail("block-lan-out physical-zone egress is missing")

# A generic HTTPS flow to a routable public documentation fixture must not
# match a destination or discovery-port drop. That proves M03 is a LAN boundary,
# not a public-WAN kill switch.
probe_ip = ipaddress.ip_address("93.184.216.34")
probe_port = 443
for rule in root.findall("rule"):
    destination = rule.find("destination")
    if destination is not None:
        network = ipaddress.ip_network(destination.attrib["address"], strict=False)
        if probe_ip.version == network.version and probe_ip in network:
            fail(f"public fixture unexpectedly matches LAN destination {network}")
    port = rule.find("port")
    if port is not None:
        bounds = [int(value) for value in port.attrib["port"].split("-", 1)]
        low, high = (bounds[0], bounds[0]) if len(bounds) == 1 else bounds
        if low <= probe_port <= high:
            fail("public HTTPS fixture unexpectedly matches a discovery-port drop")

strict = strict_path.read_text(encoding="utf-8")
required_in_order = [
    "oifname @physical_ifaces ip daddr @bypass_grace_v4 accept",
    "ip daddr . meta l4proto . th dport @vpn_endpoints_v4",
    "oifname @physical_ifaces meta nfproto ipv4",
    "counter name wan_blocked_v4 drop",
]
positions = []
for fragment in required_in_order:
    position = strict.find(fragment)
    if position < 0:
        fail(f"WAN-strict fragment missing: {fragment}")
    positions.append(position)
if positions != sorted(positions):
    fail("WAN-strict grace/endpoint/final-drop order changed")

# Parse the closed decision table out of the shipped guide so the behavioural
# model and its documentation cannot drift independently.
documented_rows = {}
for line in guide_path.read_text(encoding="utf-8").splitlines():
    if not line.startswith("|") or line.startswith("|---"):
        continue
    cells = [cell.strip() for cell in line.strip("|").split("|")]
    if len(cells) == 3 and cells[0] != "Enforcing state":
        documented_rows[cells[0]] = (cells[1], cells[2])

expected_rows = {
    "Only NoID Privacy inbound `drop` + block-lan-out":
        ("direct WAN allowed", "direct WAN allowed"),
    "Proton CLI `standard`": ("direct WAN allowed by design", "blocked"),
    "Proton GUI Advanced": ("blocked", "blocked"),
    "NoID Privacy WAN-strict `STRICT`":
        ("blocked except exact VPN endpoint tuples",
         "blocked except exact VPN endpoint tuples"),
}
if documented_rows != expected_rows:
    fail(f"VPN tunnel-down decision table differs: {documented_rows!r}")

print("PASS: base public-WAN fallback and strict/provider blocking states are distinct")
