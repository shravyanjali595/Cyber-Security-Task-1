"""Create a synthetic PCAP for demonstrating the offline packet auditor."""

import struct
from pathlib import Path


def demo_frame():
    payload = b"GET /demo HTTP/1.1\r\nHost: example.invalid\r\n\r\n"
    tcp = struct.pack(
        "!HHIIHHHH",
        49152,
        80,
        1000,
        0,
        (5 << 12) | 0x18,
        4096,
        0,
        0,
    )
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp) + len(payload),
        1,
        0,
        64,
        6,
        0,
        bytes((192, 0, 2, 10)),
        bytes((198, 51, 100, 20)),
    )
    ethernet = (
        bytes.fromhex("00112233445566778899aabb")
        + struct.pack("!H", 0x0800)
    )
    return ethernet + ip + tcp + payload


def main():
    frame = demo_frame()
    global_header = b"\xd4\xc3\xb2\xa1" + struct.pack(
        "<HHIIII", 2, 4, 0, 0, 65535, 1
    )
    record_header = struct.pack("<IIII", 1, 0, len(frame), len(frame))
    destination = Path(__file__).with_name("demo.pcap")
    destination.write_bytes(global_header + record_header + frame)
    print(f"Wrote synthetic capture: {destination}")


if __name__ == "__main__":
    main()
