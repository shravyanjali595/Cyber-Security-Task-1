#!/usr/bin/env python3
"""Audit classic Ethernet PCAP files without capturing live network traffic."""

from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO


PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
}
ETHERNET = 1
VLAN_TYPES = {0x8100, 0x88A8, 0x9100}
IP_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}
PLAINTEXT_PORTS = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
}
TCP_FLAG_NAMES = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
)
HTTP_PREFIXES = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"HTTP/1.",
)
FTP_COMMAND_PREFIXES = (
    b"USER ",
    b"PASS ",
    b"QUIT",
    b"RETR ",
    b"STOR ",
    b"220 ",
    b"230 ",
)


class PcapError(ValueError):
    """Raised when a PCAP file is invalid or unsupported."""


class PacketDecodeError(ValueError):
    """Raised when an individual captured frame is malformed."""


@dataclass
class PacketRecord:
    number: int
    timestamp: str
    source_mac: str
    destination_mac: str
    source_ip: str
    destination_ip: str
    ttl: int
    protocol: str
    source_port: int | None = None
    destination_port: int | None = None
    tcp_sequence: int | None = None
    tcp_flags: list[str] | None = None
    plaintext_indicators: list[str] | None = None
    cleartext_signature: str | None = None


@dataclass
class AuditReport:
    capture_file: str
    total_packets: int
    ipv4_packets: int
    protocol_counts: dict[str, int]
    malformed_packets: list[str]
    packets: list[PacketRecord]

    def to_dict(self) -> dict[str, object]:
        return {
            "capture_file": self.capture_file,
            "total_packets": self.total_packets,
            "ipv4_packets": self.ipv4_packets,
            "protocol_counts": self.protocol_counts,
            "malformed_packets": self.malformed_packets,
            "packets": [asdict(packet) for packet in self.packets],
        }


def _mac(raw: bytes) -> str:
    return ":".join(f"{part:02x}" for part in raw)


def _ipv4(raw: bytes) -> str:
    return ".".join(str(part) for part in raw)


def _payload_signature(payload: bytes) -> str | None:
    sample = payload.lstrip()
    upper = sample[:16].upper()
    if any(upper.startswith(prefix) for prefix in HTTP_PREFIXES):
        return "HTTP message bytes"
    if any(upper.startswith(prefix) for prefix in FTP_COMMAND_PREFIXES):
        return "FTP control-message bytes"
    return None


def decode_frame(frame: bytes, number: int, timestamp: str) -> PacketRecord | None:
    """Decode an Ethernet/IPv4 frame. Non-IPv4 frames return None."""
    if len(frame) < 14:
        raise PacketDecodeError("truncated Ethernet header")

    destination_mac = _mac(frame[0:6])
    source_mac = _mac(frame[6:12])
    ether_type = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    while ether_type in VLAN_TYPES:
        if len(frame) < offset + 4:
            raise PacketDecodeError("truncated VLAN header")
        ether_type = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    if ether_type != 0x0800:
        return None
    if len(frame) < offset + 20:
        raise PacketDecodeError("truncated IPv4 header")

    version_ihl = frame[offset]
    version = version_ihl >> 4
    header_length = (version_ihl & 0x0F) * 4
    if version != 4 or header_length < 20:
        raise PacketDecodeError("invalid IPv4 version or header length")
    if len(frame) < offset + header_length:
        raise PacketDecodeError("truncated IPv4 options")

    total_length = struct.unpack_from("!H", frame, offset + 2)[0]
    if total_length < header_length:
        raise PacketDecodeError("invalid IPv4 total length")
    ip_end = min(offset + total_length, len(frame))
    protocol_id = frame[offset + 9]
    ttl = frame[offset + 8]
    source_ip = _ipv4(frame[offset + 12 : offset + 16])
    destination_ip = _ipv4(frame[offset + 16 : offset + 20])
    fragment_field = struct.unpack_from("!H", frame, offset + 6)[0]
    fragment_offset = fragment_field & 0x1FFF
    transport_offset = offset + header_length
    protocol = IP_PROTOCOLS.get(protocol_id, f"IP-{protocol_id}")

    record = PacketRecord(
        number=number,
        timestamp=timestamp,
        source_mac=source_mac,
        destination_mac=destination_mac,
        source_ip=source_ip,
        destination_ip=destination_ip,
        ttl=ttl,
        protocol=protocol,
    )
    if fragment_offset != 0:
        return record

    if protocol_id == 6:
        if ip_end < transport_offset + 20:
            raise PacketDecodeError("truncated TCP header")
        source_port, destination_port, sequence = struct.unpack_from(
            "!HHI", frame, transport_offset
        )
        tcp_header_length = (frame[transport_offset + 12] >> 4) * 4
        if tcp_header_length < 20 or ip_end < transport_offset + tcp_header_length:
            raise PacketDecodeError("invalid or truncated TCP header")
        flags_byte = frame[transport_offset + 13]
        flags = [name for mask, name in TCP_FLAG_NAMES if flags_byte & mask]
        payload = frame[transport_offset + tcp_header_length : ip_end]
        record.source_port = source_port
        record.destination_port = destination_port
        record.tcp_sequence = sequence
        record.tcp_flags = flags
        ports = {source_port, destination_port}
        services = sorted({PLAINTEXT_PORTS[port] for port in ports if port in PLAINTEXT_PORTS})
        record.plaintext_indicators = services
        if source_port == 80 or destination_port == 80:
            record.cleartext_signature = _payload_signature(payload)
        elif source_port == 21 or destination_port == 21:
            signature = _payload_signature(payload)
            if signature == "FTP control-message bytes":
                record.cleartext_signature = signature
    elif protocol_id == 17:
        if ip_end < transport_offset + 8:
            raise PacketDecodeError("truncated UDP header")
        source_port, destination_port = struct.unpack_from("!HH", frame, transport_offset)
        record.source_port = source_port
        record.destination_port = destination_port
        record.plaintext_indicators = sorted(
            {
                PLAINTEXT_PORTS[port]
                for port in {source_port, destination_port}
                if port in PLAINTEXT_PORTS
            }
        )

    return record


def _read_pcap_header(stream: BinaryIO) -> tuple[str, int, int]:
    header = stream.read(24)
    if len(header) != 24:
        raise PcapError("file is shorter than a classic PCAP header")
    magic = header[:4]
    if magic not in PCAP_MAGICS:
        raise PcapError("unsupported PCAP magic; expected classic PCAP")
    endian, precision = PCAP_MAGICS[magic]
    major, minor, _, _, snaplen, network = struct.unpack(endian + "HHIIII", header[4:])
    if (major, minor) != (2, 4):
        raise PcapError(f"unsupported PCAP version {major}.{minor}")
    if network != ETHERNET:
        raise PcapError(f"unsupported link type {network}; expected Ethernet (1)")
    return endian, precision, snaplen


def analyze_pcap(path: Path) -> AuditReport:
    records: list[PacketRecord] = []
    malformed: list[str] = []
    protocols: Counter[str] = Counter()
    total_packets = 0

    with path.open("rb") as stream:
        endian, precision, snaplen = _read_pcap_header(stream)
        while True:
            packet_header = stream.read(16)
            if not packet_header:
                break
            total_packets += 1
            if len(packet_header) != 16:
                malformed.append(f"packet {total_packets}: truncated packet header")
                break
            seconds, fraction, captured_length, original_length = struct.unpack(
                endian + "IIII", packet_header
            )
            if captured_length > snaplen:
                malformed.append(
                    f"packet {total_packets}: captured length {captured_length} exceeds snaplen {snaplen}"
                )
                break
            frame = stream.read(captured_length)
            if len(frame) != captured_length:
                malformed.append(f"packet {total_packets}: truncated frame data")
                break
            if fraction >= precision:
                malformed.append(f"packet {total_packets}: invalid timestamp fraction")
                continue
            timestamp = datetime.fromtimestamp(
                seconds + fraction / precision, tz=timezone.utc
            ).isoformat()
            try:
                record = decode_frame(frame, total_packets, timestamp)
            except PacketDecodeError as error:
                malformed.append(f"packet {total_packets}: {error}")
                continue
            if record is not None:
                records.append(record)
                protocols[record.protocol] += 1

    return AuditReport(
        capture_file=path.name,
        total_packets=total_packets,
        ipv4_packets=len(records),
        protocol_counts=dict(sorted(protocols.items())),
        malformed_packets=malformed,
        packets=records,
    )


def format_text(report: AuditReport) -> str:
    lines = [
        f"Capture: {report.capture_file}",
        f"Packets: {report.total_packets} total, {report.ipv4_packets} IPv4",
        "IPv4 protocols: "
        + (", ".join(f"{name}={count}" for name, count in report.protocol_counts.items()) or "none"),
        f"Malformed packets: {len(report.malformed_packets)}",
        "Plaintext exposure indicators:",
    ]
    findings = 0
    for packet in report.packets:
        if not packet.plaintext_indicators:
            continue
        findings += 1
        services = ", ".join(packet.plaintext_indicators)
        evidence = packet.cleartext_signature or "service-port indicator only; payload not verified"
        lines.append(
            f"  packet {packet.number}: {packet.source_ip}:{packet.source_port} -> "
            f"{packet.destination_ip}:{packet.destination_port} [{services}; {evidence}]"
        )
    if not findings:
        lines.append("  none")
    for error in report.malformed_packets:
        lines.append(f"Malformed: {error}")
    lines.append(
        "Note: port matches indicate potential exposure; only listed payload signatures "
        "confirm recognizable plaintext protocol bytes in that packet."
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit an authorized classic Ethernet PCAP file (offline only)."
    )
    parser.add_argument("capture", type=Path, help="classic Ethernet PCAP file to analyze")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", type=Path, help="write the report to this file")
    args = parser.parse_args(argv)

    try:
        report = analyze_pcap(args.capture)
    except (OSError, PcapError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    output = (
        json.dumps(report.to_dict(), indent=2)
        if args.format == "json"
        else format_text(report)
    )
    if args.output:
        try:
            args.output.write_text(output + "\n", encoding="utf-8")
        except OSError as error:
            print(f"error writing report: {error}", file=sys.stderr)
            return 2
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
