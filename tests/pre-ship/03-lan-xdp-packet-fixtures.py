#!/usr/bin/env python3
"""Send deterministic raw frames for the isolated LAN-XDP runtime gate."""

from __future__ import annotations

import argparse
import socket
import struct
import time


SRC_MAC = bytes.fromhex("020000000001")
DST_MAC = bytes.fromhex("020000000002")
OTHER_MAC = bytes.fromhex("020000000003")
ROTATED_MAC = bytes.fromhex("020000000010")
BROADCAST = b"\xff" * 6
SRC_IP = socket.inet_aton("192.0.2.1")
DST_IP = socket.inet_aton("192.0.2.2")
GATEWAY_IP = socket.inet_aton("198.51.100.1")
DHCP_XID = 0x12345678
ROTATED_DHCP_XID = 0x87654321


def checksum(payload: bytes) -> int:
    if len(payload) % 2:
        payload += b"\0"
    total = sum(struct.unpack(f"!{len(payload) // 2}H", payload))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(payload: bytes, ethertype: int = 0x0800,
             destination: bytes = DST_MAC, source: bytes = SRC_MAC) -> bytes:
    return destination + source + struct.pack("!H", ethertype) + payload


def ipv4(payload: bytes, protocol: int, *, total_length: int | None = None,
         fragment: int = 0, ttl: int = 64, bad_checksum: bool = False,
         source: bytes = SRC_IP, destination: bytes = DST_IP) -> bytes:
    declared = 20 + len(payload) if total_length is None else total_length
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, declared, 0x4242, fragment, ttl,
        protocol, 0, source, destination,
    )
    header_sum = checksum(header)
    if bad_checksum:
        header_sum ^= 0x0001
    header = header[:10] + struct.pack("!H", header_sum) + header[12:]
    return header + payload


def udp(data: bytes = b"fixture", *, source_port: int = 40000,
        destination_port: int = 40001, length: int | None = None,
        checksum_mode: str = "valid", source: bytes = SRC_IP,
        destination: bytes = DST_IP) -> bytes:
    declared = 8 + len(data) if length is None else length
    header = struct.pack("!HHHH", source_port, destination_port, declared, 0)
    pseudo = source + destination + struct.pack("!BBH", 0, 17, declared)
    value = checksum(pseudo + header + data)
    if value == 0:
        value = 0xFFFF
    if checksum_mode == "zero":
        value = 0
    elif checksum_mode == "bad":
        value ^= 0x0001
    return struct.pack("!HHHH", source_port, destination_port, declared, value) + data


def tcp(*, data_offset: int = 5, checksum_mode: str = "valid",
        source_port: int = 40000, destination_port: int = 443,
        source: bytes = SRC_IP, destination: bytes = DST_IP) -> bytes:
    offset_flags = (data_offset << 12) | 0x002
    header = struct.pack("!HHIIHHHH", source_port, destination_port,
                         1, 0, offset_flags,
                         65535, 0, 0)
    pseudo = source + destination + struct.pack("!BBH", 0, 6, len(header))
    value = checksum(pseudo + header)
    if checksum_mode == "bad":
        value ^= 0x0001
    return header[:16] + struct.pack("!H", value) + header[18:]


def icmp(*, checksum_mode: str = "valid", kind: int = 8,
         identifier: int = 0xCAFE) -> bytes:
    packet = struct.pack("!BBHHH", kind, 0, 0, identifier, 1)
    value = checksum(packet)
    if checksum_mode == "bad":
        value ^= 0x0001
    return packet[:2] + struct.pack("!H", value) + packet[4:]


def icmp_error(*, inner_bad_checksum: bool = False, inner_fragment: int = 0,
               inner_total_length: int = 40,
               checksum_mode: str = "valid") -> bytes:
    quoted_tcp = struct.pack("!HHI", 50000, 443, 1)
    inner = ipv4(
        quoted_tcp, 6, total_length=inner_total_length,
        fragment=inner_fragment, bad_checksum=inner_bad_checksum,
        source=DST_IP, destination=GATEWAY_IP,
    )
    packet = struct.pack("!BBHI", 3, 3, 0, 0) + inner
    value = checksum(packet)
    if checksum_mode == "bad":
        value ^= 0x0001
    return packet[:2] + struct.pack("!H", value) + packet[4:]


def gateway_icmp_error(**kwargs) -> bytes:
    return ethernet(ipv4(icmp_error(**kwargs), 1,
                         source=GATEWAY_IP, destination=DST_IP))


def arp_packet(*, operation: int, ethernet_source: bytes = SRC_MAC,
               ethernet_destination: bytes = DST_MAC,
               sender_mac: bytes = SRC_MAC, sender_ip: bytes = SRC_IP,
               target_mac: bytes = DST_MAC, target_ip: bytes = DST_IP) -> bytes:
    payload = (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, operation)
        + sender_mac + sender_ip + target_mac + target_ip
    )
    return ethernet(payload, 0x0806, ethernet_destination, ethernet_source)


def arp_reply(**kwargs: bytes | int) -> bytes:
    return arp_packet(operation=2, **kwargs)


def arp_request(**kwargs: bytes | int) -> bytes:
    return arp_packet(operation=1, ethernet_destination=BROADCAST,
                      target_mac=b"\0" * 6, **kwargs)


def dhcp_reply(*, destination_mac: bytes = BROADCAST,
               client_mac: bytes = DST_MAC, xid: int = DHCP_XID,
               checksum_mode: str = "valid", truncated: bool = False) -> bytes:
    bootp = struct.pack(
        "!BBBBIHHIIII16s64s128sI",
        2, 1, 6, 0, xid, 0, 0,
        0, int.from_bytes(DST_IP, "big"), int.from_bytes(SRC_IP, "big"), 0,
        client_mac + b"\0" * 10, b"\0" * 64, b"\0" * 128, 0x63825363,
    )
    if truncated:
        bootp = bootp[:-1]
    datagram = udp(
        bootp, source_port=67, destination_port=68,
        checksum_mode=checksum_mode,
        source=SRC_IP, destination=socket.inet_aton("255.255.255.255"),
    )
    packet = ipv4(
        datagram, 17, source=SRC_IP,
        destination=socket.inet_aton("255.255.255.255"),
    )
    return ethernet(packet, destination=destination_mac)


def dhcp_request(*, client_mac: bytes = ROTATED_MAC,
                 xid: int = ROTATED_DHCP_XID) -> bytes:
    zero_ip = b"\0" * 4
    broadcast_ip = socket.inet_aton("255.255.255.255")
    bootp = struct.pack(
        "!BBBBIHHIIII16s64s128sI",
        1, 1, 6, 0, xid, 0, 0x8000,
        0, 0, 0, 0,
        client_mac + b"\0" * 10, b"\0" * 64, b"\0" * 128, 0x63825363,
    )
    datagram = udp(
        bootp, source_port=68, destination_port=67,
        source=zero_ip, destination=broadcast_ip,
    )
    packet = ipv4(datagram, 17, source=zero_ip, destination=broadcast_ip)
    return ethernet(packet, destination=BROADCAST, source=client_mac)


def invalid_frames() -> list[tuple[str, bytes, str]]:
    good_udp = udp()
    good_udp_ip = ipv4(good_udp, 17)
    frames: list[tuple[str, bytes, str]] = [
        ("vlan-truncated", ethernet(b"\0\0", 0x8100), "default"),
        ("ipv4-header-truncated", ethernet(b"\x45" + b"\0" * 9), "default"),
        ("ipv4-total-shorter-than-header", ethernet(ipv4(b"", 17, total_length=19)), "default"),
        ("ipv4-total-longer-than-frame", ethernet(ipv4(b"\0" * 8, 17, total_length=60)), "default"),
        ("ipv4-bad-checksum", ethernet(ipv4(good_udp, 17, bad_checksum=True)), "default"),
        ("ipv4-zero-ttl", ethernet(ipv4(good_udp, 17, ttl=0)), "default"),
        ("udp-header-truncated", ethernet(ipv4(b"\0" * 7, 17)), "default"),
        ("udp-length-below-header", ethernet(ipv4(udp(b"", length=7), 17)), "default"),
        ("udp-length-mismatch", ethernet(ipv4(udp(b"abcd", length=8), 17)), "default"),
        ("udp-zero-checksum", ethernet(ipv4(udp(checksum_mode="zero"), 17)), "default"),
        ("udp-bad-checksum", ethernet(ipv4(udp(checksum_mode="bad"), 17)), "default"),
        ("tcp-header-truncated", ethernet(ipv4(b"\0" * 19, 6)), "default"),
        ("tcp-data-offset-short", ethernet(ipv4(tcp(data_offset=4), 6)), "default"),
        ("tcp-bad-checksum", ethernet(ipv4(tcp(checksum_mode="bad"), 6)), "default"),
        ("icmp-header-truncated", ethernet(ipv4(b"\x08" + b"\0" * 6, 1)), "default"),
        ("icmp-bad-checksum", ethernet(ipv4(icmp(checksum_mode="bad"), 1)), "default"),
        ("ethernet-destination-mismatch", ethernet(good_udp_ip, destination=OTHER_MAC), "default"),
        ("triple-vlan", ethernet(struct.pack("!HHHHHH", 0, 0x8100, 0, 0x8100, 0, 0x0800) + good_udp_ip, 0x8100), "default"),
        ("pppoe-discovery-unsupported", ethernet(b"", 0x8863), "default"),
        ("pppoe-session-unsupported", ethernet(b"", 0x8864), "default"),
        ("eapol-truncated-body", ethernet(b"\x02\x00\x00\x04", 0x888E,
                                           bytes.fromhex("0180c2000003")), "default"),
        ("arp-ethernet-sender-mismatch", arp_reply(ethernet_source=OTHER_MAC), "default"),
        ("arp-ethernet-target-mismatch", arp_reply(ethernet_destination=OTHER_MAC), "default"),
        ("arp-reply-target-mismatch", arp_reply(target_mac=OTHER_MAC), "default"),
        ("arp-request-sender-mismatch", arp_request(ethernet_source=OTHER_MAC), "default"),
        ("arp-unsupported-operation", arp_packet(operation=3), "default"),
        ("dhcp-payload-truncated", dhcp_reply(truncated=True), "default"),
        ("dhcp-ethernet-destination-mismatch", dhcp_reply(destination_mac=OTHER_MAC), "default"),
        ("dhcp-zero-checksum", dhcp_reply(checksum_mode="zero"), "default"),
        ("icmp-error-inner-bad-checksum", gateway_icmp_error(inner_bad_checksum=True), "default"),
        ("icmp-error-inner-fragment", gateway_icmp_error(inner_fragment=1), "default"),
        ("icmp-error-inner-total-short", gateway_icmp_error(inner_total_length=27), "default"),
        ("icmp-error-outer-bad-checksum", gateway_icmp_error(checksum_mode="bad"), "default"),
        ("ipv4-more-fragments", ethernet(ipv4(good_udp, 17, fragment=0x2000)), "fragment"),
        ("ipv4-nonzero-fragment-offset", ethernet(ipv4(good_udp, 17, fragment=1)), "fragment"),
        ("ipv4-reserved-fragment-flag", ethernet(ipv4(good_udp, 17, fragment=0x8000)), "fragment"),
    ]
    assert sum(kind == "default" for _, _, kind in frames) == 33
    assert sum(kind == "fragment" for _, _, kind in frames) == 3
    return frames


def valid_frames() -> list[tuple[str, bytes]]:
    eapol = ethernet(b"\x02\x00\x00\x00", 0x888E,
                      bytes.fromhex("0180c2000003"))
    return [
        ("eapol", eapol),
        ("arp-unicast-reply", arp_reply()),
        ("arp-request", arp_request()),
        ("arp-acd-probe", arp_request(sender_ip=b"\0" * 4)),
        ("arp-announcement", arp_request(target_ip=SRC_IP)),
        ("dhcp", dhcp_reply()),
        ("related-icmp-error", gateway_icmp_error()),
    ]


def peer_unsolicited_frames(offset: int = 0) -> list[tuple[str, bytes]]:
    """Valid peer frames with tuples distinct from the correlated-flow suite."""
    return [
        ("peer-tcp-selected", ethernet(ipv4(
            tcp(source_port=41000 + offset, destination_port=443), 6))),
        ("peer-tcp-adjacent", ethernet(ipv4(
            tcp(source_port=41001 + offset, destination_port=444), 6))),
        ("peer-udp-range-start", ethernet(ipv4(udp(
            source_port=42000 + offset, destination_port=5300), 17))),
        ("peer-udp-range-end", ethernet(ipv4(udp(
            source_port=42001 + offset, destination_port=5301), 17))),
        ("peer-udp-adjacent", ethernet(ipv4(udp(
            source_port=42002 + offset, destination_port=5302), 17))),
        ("peer-icmp-echo", ethernet(ipv4(
            icmp(identifier=0xBEEF + offset), 1))),
    ]


def peer_flow_open_frames() -> list[tuple[str, bytes]]:
    """Locally emitted packets observed by TC to open three reverse flows."""
    outgoing_udp = udp(
        source_port=40001, destination_port=40000,
        source=DST_IP, destination=SRC_IP)
    outgoing_tcp = tcp(
        source_port=443, destination_port=40000,
        source=DST_IP, destination=SRC_IP)
    return [
        ("open-udp", ethernet(
            ipv4(outgoing_udp, 17, source=DST_IP, destination=SRC_IP),
            destination=SRC_MAC, source=DST_MAC)),
        ("open-tcp", ethernet(
            ipv4(outgoing_tcp, 6, source=DST_IP, destination=SRC_IP),
            destination=SRC_MAC, source=DST_MAC)),
        ("open-icmp", ethernet(
            ipv4(icmp(), 1, source=DST_IP, destination=SRC_IP),
            destination=SRC_MAC, source=DST_MAC)),
    ]


def peer_flow_reply_frames() -> list[tuple[str, bytes]]:
    """Exact reverse tuples for peer_flow_open_frames()."""
    return [
        ("reply-udp", ethernet(ipv4(udp(), 17))),
        ("reply-tcp", ethernet(ipv4(tcp(), 6))),
        ("reply-icmp", ethernet(ipv4(icmp(kind=0), 1))),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", required=True)
    parser.add_argument(
        "--suite", required=True,
        choices=(
            "invalid", "valid", "peer-unsolicited", "peer-unsolicited-alt1",
            "peer-unsolicited-alt2", "peer-unsolicited-alt3", "peer-flow-open",
            "peer-flow-replies", "dhcp-reply", "dhcp-request-rotated",
            "dhcp-reply-rotated",
        ),
    )
    args = parser.parse_args()
    if args.suite == "invalid":
        frames = invalid_frames()
    elif args.suite == "valid":
        frames = valid_frames()
    elif args.suite == "peer-unsolicited":
        frames = peer_unsolicited_frames()
    elif args.suite == "peer-unsolicited-alt1":
        frames = peer_unsolicited_frames(100)
    elif args.suite == "peer-unsolicited-alt2":
        frames = peer_unsolicited_frames(200)
    elif args.suite == "peer-unsolicited-alt3":
        frames = peer_unsolicited_frames(300)
    elif args.suite == "peer-flow-open":
        frames = peer_flow_open_frames()
    elif args.suite == "peer-flow-replies":
        frames = peer_flow_reply_frames()
    elif args.suite == "dhcp-reply":
        frames = [("dhcp-reply", dhcp_reply())]
    elif args.suite == "dhcp-request-rotated":
        frames = [("dhcp-request-rotated", dhcp_request())]
    else:
        frames = [(
            "dhcp-reply-rotated",
            dhcp_reply(client_mac=ROTATED_MAC, xid=ROTATED_DHCP_XID),
        )]
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                       socket.htons(0x0003)) as raw:
        raw.bind((args.interface, 0))
        for name, frame, *_ in frames:
            try:
                sent = raw.send(frame)
            except OSError as exc:
                raise RuntimeError(f"raw send failed for {name}: {exc}") from exc
            if sent != len(frame):
                raise RuntimeError(f"short raw send for {name}: {sent}/{len(frame)}")
            time.sleep(0.01)
    print(f"sent {len(frames)} {args.suite} fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
