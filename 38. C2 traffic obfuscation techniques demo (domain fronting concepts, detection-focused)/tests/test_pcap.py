"""PCAP writer structure tests — self-parse and field checks."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.simulator.flows import App, FlowRecord
from src.simulator.pcap import PCAP_MAGIC, packets_for_flow, write_pcap


def _flow(**kw) -> FlowRecord:
    base = dict(ts=1000.0, src="192.0.2.11", dst="198.51.100.10", sport=45001,
                dport=443, proto="tcp", app=App.HTTP, ttl=57, ip_id=1005,
                sni="cdn.example", host="203.0.113.10", uri="/x", method="GET",
                status=200, body=b"ok", ja3="browser-chrome-stable",
                family="campaign", note="test")
    base.update(kw)
    return FlowRecord(**base)


def test_pcap_header_and_packet_count(tmp_path):
    flows = [_flow(), _flow(ts=1001.0, app=App.DNS, proto="udp", dport=53,
                            dst="198.51.100.53", sni="", host="portal.example")]
    info = write_pcap(tmp_path / "t.pcap", flows)
    raw = (tmp_path / "t.pcap").read_bytes()
    magic, maj, minr, _tz, _sf, snap, link = struct.unpack("<IHHiIII", raw[:24])
    assert magic == PCAP_MAGIC and (maj, minr) == (2, 4) and link == 1
    # count records
    off, frames = 24, 0
    while off < len(raw):
        ts_s, ts_u, incl, orig = struct.unpack("<IIII", raw[off:off + 16])
        assert incl == orig and incl > 0
        off += 16 + incl
        frames += 1
    assert frames == info.frames > 0
    assert info.size_bytes == len(raw)


def test_ethernet_type_and_ipv4_ttl_written():
    frames = packets_for_flow(_flow(ttl=57))
    # Frame layout: eth(14) then IPv4; verify ethertype and TTL survive.
    ethertype = struct.unpack("!H", frames[0][1][12:14])[0]
    assert ethertype == 0x0800
    assert frames[0][1][14 + 8] == 57          # IPv4 TTL byte
    assert frames[0][1][14 + 12:14 + 16] == bytes([192, 0, 2, 11])  # src IP


def test_dns_and_tcp_flows_produce_frames():
    assert len(packets_for_flow(_flow(app=App.DNS, proto="udp", dport=53))) >= 2
    assert len(packets_for_flow(_flow(app=App.HTTP))) >= 6     # handshake + req/resp + FIN
