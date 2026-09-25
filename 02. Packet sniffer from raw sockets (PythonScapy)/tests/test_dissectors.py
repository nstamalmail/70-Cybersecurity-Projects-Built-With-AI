"""Unit tests for protocol dissectors using hand-built synthetic frames."""

import socket
import struct
import unittest

from sniffer.dissectors import dissect
from sniffer.models import Packet


def mkpkt(raw: bytes, number: int = 1) -> Packet:
    return dissect(Packet(number=number, timestamp=1_700_000_000.123456, raw=raw, orig_len=len(raw)),
                   link_layer=True)


def eth(payload: bytes, ethertype: int) -> bytes:
    return (b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66"
            + struct.pack("!H", ethertype) + payload)


def ipv4(payload: bytes, proto: int, src="192.168.1.10", dst="93.184.216.34") -> bytes:
    total = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s",
                         0x45, 0, total, 0x1234, 0x4000, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    s = 0
    for i in range(0, 20, 2):
        s += struct.unpack("!H", header[i:i + 2])[0]
    s = (s & 0xFFFF) + (s >> 16)
    cksum = (~s) & 0xFFFF
    header = header[:10] + struct.pack("!H", cksum) + header[12:]
    return header + payload


def tcp_seg(sport, dport, flags=0x02, payload=b"") -> bytes:
    return struct.pack("!HHIIHHHH",
                       sport, dport, 1000, 0, (5 << 12) | flags, 8192, 0, 0) + payload


def udp_seg(sport, dport, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


class TestEthernetIpTcp(unittest.TestCase):
    def test_ethernet_ipv4_tcp_syn(self):
        raw = eth(ipv4(tcp_seg(51000, 443, flags=0x02), 6), 0x0800)
        pkt = mkpkt(raw)
        self.assertFalse(pkt.malformed)
        eth_l = pkt.layer("Ethernet")
        self.assertEqual(eth_l.fields["ethertype"], 0x0800)
        self.assertEqual(eth_l.fields["src"], "11:22:33:44:55:66")
        ip = pkt.layer("IPv4")
        self.assertEqual(ip.fields["src"], "192.168.1.10")
        self.assertEqual(ip.fields["dst"], "93.184.216.34")
        self.assertTrue(ip.fields["checksum_ok"])
        tcp = pkt.layer("TCP")
        self.assertEqual(tcp.fields["sport"], 51000)
        self.assertEqual(tcp.fields["dport"], 443)
        self.assertTrue(tcp.fields["flags.syn"])
        self.assertEqual(pkt.protocol, "TCP")
        self.assertIn("443", pkt.info)

    def test_truncated_tcp_is_flagged_not_crash(self):
        raw = eth(ipv4(tcp_seg(1, 2)[:8], 6), 0x0800)          # cut TCP header
        pkt = mkpkt(raw)
        self.assertTrue(pkt.malformed)

    def test_tcp_payload_len_recorded(self):
        payload = b"X" * 11
        pkt = mkpkt(eth(ipv4(tcp_seg(1, 2, flags=0x18, payload=payload), 6), 0x0800))
        self.assertEqual(pkt.layer("TCP").fields["payload_len"], 11)


class TestArp(unittest.TestCase):
    def test_arp_request(self):
        arp = (struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
               + b"\x01\x02\x03\x04\x05\x06" + socket.inet_aton("10.0.0.1")
               + b"\x00\x00\x00\x00\x00\x00" + socket.inet_aton("10.0.0.2"))
        pkt = mkpkt(eth(arp, 0x0806))
        arp_l = pkt.layer("ARP")
        self.assertIsNotNone(arp_l)
        self.assertEqual(arp_l.fields["opcode"], 1)
        self.assertEqual(arp_l.fields["spa"], "10.0.0.1")
        self.assertEqual(arp_l.fields["tpa"], "10.0.0.2")
        self.assertIn("request", pkt.info)


class TestDns(unittest.TestCase):
    def test_dns_query_and_response(self):
        qname = b"\x03www\x07example\x03com\x00"
        query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
        pkt = mkpkt(eth(ipv4(udp_seg(51001, 53, query), 17), 0x0800))
        dns = pkt.layer("DNS")
        self.assertIsNotNone(dns)
        self.assertEqual(dns.fields["qr"], "query")
        self.assertEqual(dns.fields["question"], "www.example.com")
        self.assertEqual(dns.fields["qtype"], "A")

        # question section includes qtype/qclass; answer RR owner uses a
        # compression pointer (0xC00C) back to the question name
        question = qname + struct.pack("!HH", 1, 1)
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([93, 184, 216, 34])
        resp = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + question + rr
        pkt2 = mkpkt(eth(ipv4(udp_seg(53, 51001, resp), 17), 0x0800))
        dns2 = pkt2.layer("DNS")
        self.assertEqual(dns2.fields["qr"], "response")
        answers = dns2.fields.get("answers", [])
        self.assertTrue(any("93.184.216.34" in a for a in answers))


class TestHttp(unittest.TestCase):
    def test_http_request(self):
        req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t\r\n\r\n"
        pkt = mkpkt(eth(ipv4(tcp_seg(51002, 80, flags=0x18, payload=req), 6), 0x0800))
        http = pkt.layer("HTTP")
        self.assertIsNotNone(http)
        self.assertEqual(http.fields["request.method"], "GET")
        self.assertEqual(http.fields["request.uri"], "/index.html")
        self.assertEqual(http.fields["header.host"], "example.com")

    def test_http_response(self):
        resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        pkt = mkpkt(eth(ipv4(tcp_seg(80, 51002, flags=0x18, payload=resp), 6), 0x0800))
        http = pkt.layer("HTTP")
        self.assertEqual(http.fields["response.code"], "200")
        self.assertEqual(http.fields["response.reason"], "OK")


class TestTls(unittest.TestCase):
    def test_tls_client_hello_sni(self):
        sni = b"www.example.com"
        ext_data = (struct.pack("!H", len(sni) + 3) + b"\x00"
                    + struct.pack("!H", len(sni)) + sni)
        ext = struct.pack("!HH", 0x0000, len(ext_data)) + ext_data
        session_id = b""
        cipher_suites = struct.pack("!H", 2) + b"\x00\x2f"
        compression = b"\x01\x00"
        handshake_body = (b"\x03\x03" + b"\x11" * 32
                          + bytes([len(session_id)]) + session_id
                          + cipher_suites + compression
                          + struct.pack("!H", len(ext)) + ext)
        handshake = b"\x01" + struct.pack("!I", len(handshake_body))[1:] + handshake_body
        record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake

        pkt = mkpkt(eth(ipv4(tcp_seg(51003, 443, flags=0x18, payload=record), 6), 0x0800))
        tls = pkt.layer("TLS")
        self.assertIsNotNone(tls)
        self.assertEqual(tls.fields["handshake_type"], "ClientHello")
        self.assertEqual(tls.fields["sni"], "www.example.com")


class TestIpv6AndEdge(unittest.TestCase):
    def test_ipv6_udp(self):
        udp = udp_seg(50000, 53, struct.pack("!HHHHHH", 1, 0, 0, 0, 0, 0))
        src = socket.inet_pton(socket.AF_INET6, "fe80::1")
        dst = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        ip6 = struct.pack("!IHBB", 0x60000000, len(udp), 17, 64) + src + dst + udp
        pkt = mkpkt(eth(ip6, 0x86DD))
        ip6_l = pkt.layer("IPv6")
        self.assertEqual(ip6_l.fields["src"], "fe80::1")
        self.assertEqual(ip6_l.fields["dst"], "2001:db8::1")
        self.assertIsNotNone(pkt.layer("UDP"))

    def test_vlan_tagged_frame(self):
        inner = eth(ipv4(tcp_seg(1, 2), 6), 0x0800)[14:]       # payload after outer eth header
        outer = (b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66"
                 + struct.pack("!HHH", 0x8100, 0x0064, 0x0800)  # TPID, TCI(VID 100), inner type
                 + inner)
        pkt = mkpkt(outer)
        eth_l = pkt.layer("Ethernet")
        self.assertEqual(eth_l.fields["vlan.vid"], 100)
        self.assertEqual(eth_l.fields["ethertype"], 0x0800)
        self.assertIsNotNone(pkt.layer("IPv4"))

    def test_unknown_ethertype_keeps_ethernet_layer(self):
        pkt = mkpkt(b"\x00" * 14 + b"\xff" * 40)
        self.assertIsNotNone(pkt.layer("Ethernet"))

    def test_short_frame_malformed(self):
        pkt = mkpkt(b"\x45\x00\x00\x28")
        self.assertTrue(pkt.malformed or pkt.layer("IPv4") is not None)


if __name__ == "__main__":
    unittest.main()
