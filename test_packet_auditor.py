import struct
import tempfile
import unittest
from pathlib import Path

from packet_auditor import PacketDecodeError, analyze_pcap, decode_frame, format_text


def ethernet_ipv4_tcp(payload=b"", destination_port=80, flags=0x18):
    destination_mac = bytes.fromhex("001122334455")
    source_mac = bytes.fromhex("66778899aabb")
    tcp = struct.pack(
        "!HHIIHHHH",
        49152,
        destination_port,
        123456,
        0,
        (5 << 12) | flags,
        65535,
        0,
        0,
    )
    ip_length = 20 + len(tcp) + len(payload)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_length,
        7,
        0,
        64,
        6,
        0,
        bytes((192, 0, 2, 10)),
        bytes((198, 51, 100, 20)),
    )
    return destination_mac + source_mac + struct.pack("!H", 0x0800) + ip + tcp + payload


def make_pcap(frames):
    header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    records = []
    for frame in frames:
        records.append(struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame)
    return header + b"".join(records)


class PacketAuditorTests(unittest.TestCase):
    def test_decodes_headers_and_http_plaintext_signature(self):
        frame = ethernet_ipv4_tcp(b"GET /demo HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
        packet = decode_frame(frame, 1, "1970-01-01T00:00:01+00:00")

        self.assertIsNotNone(packet)
        self.assertEqual(packet.source_mac, "66:77:88:99:aa:bb")
        self.assertEqual(packet.destination_mac, "00:11:22:33:44:55")
        self.assertEqual(packet.source_ip, "192.0.2.10")
        self.assertEqual(packet.destination_ip, "198.51.100.20")
        self.assertEqual(packet.ttl, 64)
        self.assertEqual(packet.tcp_sequence, 123456)
        self.assertEqual(packet.tcp_flags, ["PSH", "ACK"])
        self.assertEqual(packet.plaintext_indicators, ["HTTP"])
        self.assertEqual(packet.cleartext_signature, "HTTP message bytes")

    def test_audits_pcap_and_text_report_without_dumping_payload(self):
        frame = ethernet_ipv4_tcp(b"GET /demo HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "authorized-test.pcap"
            capture.write_bytes(make_pcap([frame]))
            report = analyze_pcap(capture)

        rendered = format_text(report)
        self.assertEqual(report.total_packets, 1)
        self.assertEqual(report.ipv4_packets, 1)
        self.assertEqual(report.protocol_counts, {"TCP": 1})
        self.assertIn("HTTP message bytes", rendered)
        self.assertNotIn("GET /demo", rendered)

    def test_rejects_truncated_ethernet_frame(self):
        with self.assertRaisesRegex(PacketDecodeError, "truncated Ethernet"):
            decode_frame(b"\x00" * 10, 1, "timestamp")

    def test_non_ipv4_frame_is_ignored(self):
        frame = bytes.fromhex("00112233445566778899aabb0806") + b"\x00" * 28
        self.assertIsNone(decode_frame(frame, 1, "timestamp"))


if __name__ == "__main__":
    unittest.main()
