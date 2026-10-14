#!/usr/bin/env python3
"""A consumer may not be stricter about a boundary than the layer that owns it.

M03 owns the XDP/TC boundary and publishes a closed health vocabulary. Whenever
no LAN peer requires XDP it exits 0 for every DEGRADED reason. The
no-ethernet-link branch additionally records in the journal that
"L3/firewalld/WAN-strict remain active". That is M03 deciding the system may
proceed on this hardware.

M04 consumes that health file to decide whether the shared readiness marker may
be published. The marker lets chrony bring its NTS sources online and lets M06
resolve a configured VPN endpoint before queuing WAN-strict reconciliation.
M04 does not own the XDP boundary, so it must not apply a harsher policy than
the owner after M03's topology transaction has succeeded. When it did, a
machine M03 had declared survivable never got a clock and could not reconcile a
hostname-based VPN endpoint: gateway-xdp.ready stayed absent and chrony stayed
offline until a free-running clock eventually invalidated NTS-KE TLS itself.

This contract extracts the producer's published vocabulary and the consumer's
accepted set and requires them to match exactly. Both stay written out
explicitly in their own module -- that is what makes them auditable -- and this
check moves the agreement between them to build time, where it costs nothing at
runtime. A new DEGRADED reason in M03 now fails the build instead of silently
stopping the clock on whatever hardware triggers it.
"""

from __future__ import annotations

import pathlib
import re
import sys

# `publish_xdp_health DEGRADED no-ethernet-link`. Keep the state generic: the
# producer's case arm below, not this test, owns the closed state vocabulary.
PUBLISH = re.compile(
    r"^\s*publish_xdp_health\s+([A-Z][A-Z0-9-]*)\s+([a-z0-9-]+)\s*$",
    re.M,
)
# One or more accepted case arms before the wildcard rejection arm. Restrict
# extraction to pattern positions ending in `) ;;`; comments and case bodies
# can never become phantom vocabulary entries.
ARM = re.compile(
    r"(?:^|[;\n])\s*"
    r"(?P<patterns>[A-Za-z0-9-]+(?:\s*\|\s*(?:\\\s*)?[A-Za-z0-9-]+)*)"
    r"\s*\)\s*;;",
    re.M,
)
PUBLISHER_BODY = re.compile(
    r"^publish_xdp_health\(\)\s*\{(?P<body>.*?)^\s*state_dir=",
    re.M | re.S,
)
# `'STATE=DEGRADED:DETAIL=no-ethernet-link'|\`
ACCEPT = re.compile(r"'STATE=(ACTIVE|DEGRADED):DETAIL=([a-z0-9-]+)'")
CONSUMER_BODY = re.compile(
    r"^runtime_boundary_verified\(\)\s*\{(?P<body>.*?)^\}",
    re.M | re.S,
)
CONSUMER_CASE = re.compile(
    r'^\s*case\s+"\$state:\$detail"\s+in(?P<body>.*?)^\s*esac\s*$',
    re.M | re.S,
)
CONSUMER_ARM = re.compile(
    r"(?P<patterns>"
    r"\s*'STATE=(?:ACTIVE|DEGRADED):DETAIL=[a-z0-9-]+'"
    r"(?:\s*\|\s*(?:\\\s*)?'STATE=(?:ACTIVE|DEGRADED):DETAIL=[a-z0-9-]+')*"
    r")\)\s*(?P<body>.*?)^\s*;;",
    re.M | re.S,
)
SUCCESS_BODY = re.compile(r"^\s*return\s+0\s*;?\s*$", re.S)

PRODUCER = "kickstart/snippets/03-firewalld.ks"
CONSUMER = "kickstart/snippets/04-arp-hardening.ks"


def declared_values(text: str, variable: str) -> set[str]:
    vocabulary = re.search(
        rf'case\s+"\${re.escape(variable)}"\s+in(?P<body>.*?)\*\)',
        text,
        re.S,
    )
    if not vocabulary:
        raise SystemExit(
            f"{PRODUCER}: closed {variable} vocabulary not found"
        )
    body = re.sub(r"(?m)#.*$", "", vocabulary.group("body"))
    declared: set[str] = set()
    for arm in ARM.finditer(body):
        declared.update(
            value
            for value in re.split(r"\s*\|\s*\\?\s*", arm.group("patterns"))
            if value
        )
    if not declared:
        raise SystemExit(
            f"{PRODUCER}: closed {variable} vocabulary has no accepted arm"
        )
    return declared


def published(text: str) -> set[str]:
    states = {f"{state}:{detail}" for state, detail in PUBLISH.findall(text)}
    publisher = PUBLISHER_BODY.search(text)
    if not publisher:
        raise SystemExit(f"{PRODUCER}: publish_xdp_health body not found")
    declared_states = declared_values(publisher.group("body"), "state")
    declared_details = declared_values(publisher.group("body"), "detail")
    emitted_states = {entry.split(":", 1)[0] for entry in states}
    emitted_details = {entry.split(":", 1)[1] for entry in states}
    missing_states = declared_states - emitted_states
    missing_details = declared_details - emitted_details
    if missing_states or missing_details:
        raise SystemExit(
            f"{PRODUCER}: declared but never published: "
            f"states={sorted(missing_states)}, details={sorted(missing_details)}"
        )
    unknown_states = emitted_states - declared_states
    unknown_details = emitted_details - declared_details
    if unknown_states or unknown_details:
        raise SystemExit(
            f"{PRODUCER}: published outside the closed vocabulary: "
            f"states={sorted(unknown_states)}, details={sorted(unknown_details)}"
        )
    return states


def accepted(text: str) -> set[str]:
    consumer = CONSUMER_BODY.search(text)
    if not consumer:
        raise SystemExit(f"{CONSUMER}: runtime_boundary_verified body not found")
    boundary_case = CONSUMER_CASE.search(consumer.group("body"))
    if not boundary_case:
        raise SystemExit(f"{CONSUMER}: state/detail case not found")

    # Labels are policy only when their own branch succeeds.  Searching the
    # whole file for label text would keep counting an arm after its outcome
    # changed to `return 1`, and would also let comments masquerade as policy.
    case_body = re.sub(r"(?m)^\s*#.*(?:\n|$)", "", boundary_case.group("body"))
    states: set[str] = set()
    for arm in CONSUMER_ARM.finditer(case_body):
        if not SUCCESS_BODY.fullmatch(arm.group("body")):
            continue
        states.update(
            f"{state}:{detail}"
            for state, detail in ACCEPT.findall(arm.group("patterns"))
        )
    return states


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    producer = (root / PRODUCER).read_text(encoding="utf-8")
    consumer = (root / CONSUMER).read_text(encoding="utf-8")

    owner_states = published(producer)
    reader_states = accepted(consumer)

    if not owner_states or not reader_states:
        print("degradation contract: no states extracted", file=sys.stderr)
        return 1

    unhandled = owner_states - reader_states
    invented = reader_states - owner_states
    if unhandled:
        print(
            "degradation contract: the boundary owner publishes states its "
            f"consumer refuses: {sorted(unhandled)}\n"
            "  M03 exits 0 for every DEGRADED reason when no LAN peer requires "
            "XDP, so M04 refusing one only withholds the shared readiness "
            "consumers.",
            file=sys.stderr,
        )
    if invented:
        print(
            "degradation contract: the consumer accepts states the owner "
            f"never publishes: {sorted(invented)}",
            file=sys.stderr,
        )
    if unhandled or invented:
        return 1
    print(
        f"degradation contract: {len(owner_states)} published boundary states, "
        "all handled by the consumer"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
