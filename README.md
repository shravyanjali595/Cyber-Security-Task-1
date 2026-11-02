# TRAINLYZE — Project 01: Network Packet Analyzer

An offline packet auditor for **authorized classic Ethernet PCAP files**. It uses
only the Python standard library and does not open raw sockets, capture live
traffic, or print application payloads.

## Features

- Decodes Ethernet MAC addresses, optional VLAN tags, IPv4 addresses, TTL, and
  protocol IDs.
- Decodes TCP ports, sequence numbers, and FIN/SYN/RST/PSH/ACK/URG flags; also
  recognizes UDP ports and ICMP protocol packets.
- Reports possible plaintext-service exposure on FTP, Telnet, SMTP, HTTP, POP3,
  and IMAP ports.
- Recognizes HTTP message and FTP control-message byte signatures in matching
  packets without displaying or saving payload contents.
- Emits human-readable or JSON reports; malformed packet records are reported.

Port numbers alone are **indicators, not proof** that a connection is unencrypted.
A recognized protocol signature is evidence of readable protocol bytes in that
packet. This tool does not reassemble TCP streams, decrypt TLS, or establish
whether a service is safe based only on its port.

## Requirements and usage

Python 3.10 or later; no third-party packages are needed.

```powershell
python packet_auditor.py path\to\authorized-capture.pcap
python packet_auditor.py path\to\authorized-capture.pcap --format json --output audit.json
```

The reader supports classic PCAP files with Ethernet link type. It intentionally
does not support live capture or PCAPNG.

## Synthetic demonstration and audit result

Create and analyze a harmless synthetic capture containing one HTTP request
between documentation-only IP addresses:

```powershell
python examples\create_demo_capture.py
python packet_auditor.py examples\demo.pcap --output examples\demo-audit.txt
```

Recorded output from the synthetic capture:

```text
Capture: demo.pcap
Packets: 1 total, 1 IPv4
IPv4 protocols: TCP=1
Malformed packets: 0
Plaintext exposure indicators:
  packet 1: 192.0.2.10:49152 -> 198.51.100.20:80 [HTTP; HTTP message bytes]
Note: port matches indicate potential exposure; only listed payload signatures confirm recognizable plaintext protocol bytes in that packet.
```

The sample shows a recognizable HTTP request in packet bytes and is a controlled
test fixture, not evidence collected from a real network. No real capture has
been audited in this repository.

## Tests

```powershell
python -m unittest discover -s tests -v
```
