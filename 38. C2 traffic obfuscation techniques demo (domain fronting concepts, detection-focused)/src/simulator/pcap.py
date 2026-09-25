"""Byte-accurate PCAP writer for synthetic flows — offline file output only.

Frames follow Ethernet II / IPv4 / UDP|TCP with minimal DNS and HTTP payloads so
Wireshark can open the artifact on an isolated lab host. No packet is ever sent
anywhere: ``write_pcap`` merely serializes bytes to a local file.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path

from src.simulator.flows import FlowRecord

PCAP_MAGIC = 0xA1B2C3D4  # little-endian timestamps
VERSION_MAJOR, VERSION_MINOR = 2, 4
SNAPLEN = 65535
LINKTYPE_ETHERNET = 1

ETH_HDR = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02"  # dst, src (locally administered)
ETHERTYPE_IPV4 = 0x0800
PROTO_ICMP, PROTO_TCP, PROTO_UDP = 1, 6, 17


@dataclass
class PcapInfo:
    path: str
    frames: int
    size_bytes: int
    sha256: str


def _ipv4_bytes(ip: str) -> bytes:
    return bytes(int(p) for p in ip.split("."))


def _inet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ipv4_header(src: str, dst: str, proto: int, ttl: int, ip_id: int, payload_len: int) -> bytes:
    total_len = 20 + payload_len
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,            # version 4, IHL 5
        0x00,            # DSCP
        total_len,
        ip_id & 0xFFFF,
        0x4000,          # DF
        ttl,
        proto,
        0x0000,          # checksum placeholder
        _ipv4_bytes(src),
        _ipv4_bytes(dst),
    )
    csum = _inet_checksum(hdr)
    return hdr[:10] + struct.pack("!H", csum) + hdr[12:]


def _udp_header(sport: int, dport: int, payload_len: int) -> bytes:
    sport, dport = sport & 0xFFFF, dport & 0xFFFF   # synthetic ports may overflow
    return struct.pack("!HHHH", sport, dport, 8 + payload_len, 0x0000)  # csum 0 (IPv4-legal)


def _tcp_header(sport: int, dport: int, seq: int, ack: int, flags: int, payload_len: int) -> bytes:
    sport, dport = sport & 0xFFFF, dport & 0xFFFF   # synthetic ports may overflow
    return struct.pack(
        "!HHIIBBHHH",
        sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
        0x50, flags, 8192, 0x0000, 0x0000,  # data offset 5, csum/urg 0
    )


def _dns_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _dns_query(txid: int, name: str) -> bytes:
    return (
        struct.pack("!HHHHHH", txid & 0xFFFF, 0x0100, 1, 0, 0, 0)
        + _dns_name(name)
        + struct.pack("!HH", 1, 1)  # QTYPE=A QCLASS=IN
    )


def _dns_response(txid: int, name: str, addr: str) -> bytes:
    return (
        struct.pack("!HHHHHH", txid & 0xFFFF, 0x8180, 1, 1, 0, 0)
        + _dns_name(name)
        + struct.pack("!HH", 1, 1)
        + b"\xc0\x0c"                       # pointer to qname
        + struct.pack("!HHIH", 1, 1, 300, 4)
        + _ipv4_bytes(addr)
    )


def _http_request(flow: FlowRecord) -> bytes:
    host = flow.host or flow.sni or "example.invalid"
    return (
        f"{flow.method} {flow.uri} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: demo-agent/1.0\r\n"
        f"Accept: */*\r\n"
        f"\r\n"
    ).encode()


def _http_response(flow: FlowRecord) -> bytes:
    body = flow.body or b"ok"
    return (
        f"HTTP/1.1 {flow.status} OK\r\n"
        f"Server: demo-origin\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    ).encode() + body


def packets_for_flow(flow: FlowRecord) -> list[tuple[float, bytes]]:
    """Expand a FlowRecord into (timestamp, raw_frame) tuples."""
    ts = flow.ts
    out: list[tuple[float, bytes]] = []

    def emit(t: float, ip_payload: bytes, proto: int, ttl: int, ip_id: int) -> None:
        ip_hdr = _ipv4_header(flow.src, flow.dst, proto, ttl, ip_id, len(ip_payload))
        out.append((t, ETH_HDR + struct.pack("!H", ETHERTYPE_IPV4) + ip_hdr + ip_payload))

    if flow.app == "dns":
        q = _dns_query(int(flow.ip_id) & 0xFFFF, flow.host or flow.sni or "example.invalid")
        emit(ts, _udp_header(flow.sport, flow.dport, len(q)) + q, PROTO_UDP, flow.ttl, flow.ip_id)
        r = _dns_response(int(flow.ip_id) & 0xFFFF, flow.host or flow.sni or "example.invalid", flow.dst)
        emit(ts + 0.004, _udp_header(flow.dport, flow.sport, len(r)) + r, PROTO_UDP, 64, flow.ip_id + 1)
        return out

    if flow.app == "ntp":
        payload = b"\x1b" + b"\x00" * 47  # LI/VN/Mode client, zeroed body
        emit(ts, _udp_header(flow.sport, flow.dport, len(payload)) + payload, PROTO_UDP, flow.ttl, flow.ip_id)
        emit(ts + 0.05, _udp_header(flow.dport, flow.sport, len(payload)) + payload, PROTO_UDP, 64, flow.ip_id + 1)
        return out

    # HTTP over TCP with a 3-way handshake
    seq_c, seq_s = flow.ip_id * 100, 5000
    req = _http_request(flow)
    resp = _http_response(flow)

    emit(ts, _tcp_header(flow.sport, flow.dport, seq_c, 0, 0x02, 0), PROTO_TCP, flow.ttl, flow.ip_id)              # SYN
    emit(ts + 0.01, _tcp_header(flow.dport, flow.sport, seq_s, seq_c + 1, 0x12, 0), PROTO_TCP, 64, flow.ip_id)     # SYN-ACK
    emit(ts + 0.02, _tcp_header(flow.sport, flow.dport, seq_c + 1, seq_s + 1, 0x10, 0), PROTO_TCP, flow.ttl, flow.ip_id)  # ACK
    emit(ts + 0.03, _tcp_header(flow.sport, flow.dport, seq_c + 1, seq_s + 1, 0x18, len(req)) + req, PROTO_TCP, flow.ttl, flow.ip_id + 1)  # PSH req
    emit(ts + 0.06, _tcp_header(flow.dport, flow.sport, seq_s + 1, seq_c + 1 + len(req), 0x18, len(resp)) + resp, PROTO_TCP, 64, flow.ip_id + 2)  # PSH resp
    emit(ts + 0.08, _tcp_header(flow.sport, flow.dport, seq_c + 1 + len(req), seq_s + 1 + len(resp), 0x11, 0), PROTO_TCP, flow.ttl, flow.ip_id + 3)  # FIN
    return out


def write_pcap(path: str | Path, flows: list[FlowRecord]) -> PcapInfo:
    """Serialize all flows' packets to a classic libpcap file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    frames = 0
    with path.open("wb") as fh:
        glob = struct.pack("<IHHiIII", PCAP_MAGIC, VERSION_MAJOR, VERSION_MINOR, 0, 0, SNAPLEN, LINKTYPE_ETHERNET)
        fh.write(glob)
        h.update(glob)
        for flow in flows:
            for ts, frame in packets_for_flow(flow):
                sec = int(ts)
                usec = int(round((ts - sec) * 1_000_000)) % 1_000_000
                rec = struct.pack("<IIII", sec, usec, len(frame), len(frame))
                fh.write(rec)
                fh.write(frame)
                h.update(rec)
                h.update(frame)
                frames += 1
    return PcapInfo(path=str(path), frames=frames, size_bytes=path.stat().st_size, sha256=h.hexdigest())
