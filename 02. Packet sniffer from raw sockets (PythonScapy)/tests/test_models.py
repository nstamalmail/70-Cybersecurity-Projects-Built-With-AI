"""Tests for Packet display helpers and statistics aggregation (stdlib unittest)."""

import unittest

from sniffer.capture.stats import StatisticsAggregator
from sniffer.models import Packet, ProtocolLayer

from test_dissectors import eth, ipv4, mkpkt, tcp_seg


class TestPacketHelpers(unittest.TestCase):
    def test_packet_summary_row_columns(self):
        pkt = mkpkt(eth(ipv4(tcp_seg(51000, 443, flags=0x02), 6), 0x0800))
        row = pkt.summary_row()
        self.assertEqual(len(row), 7)
        self.assertEqual(row[0], "1")
        self.assertEqual(row[4], "TCP")
        self.assertEqual(row[2], "192.168.1.10")
        self.assertIn("443", row[6])

    def test_packet_layer_lookup_case_insensitive(self):
        pkt = mkpkt(eth(ipv4(tcp_seg(1, 2), 6), 0x0800))
        self.assertIsNotNone(pkt.layer("tcp"))
        self.assertEqual(pkt.field("ipv4", "ttl"), 64)

    def test_layer_summary_and_color(self):
        lay = ProtocolLayer("TCP", {"sport": 1, "dport": 2}, 34, 20)
        self.assertIn("sport=1", lay.summary())
        pkt = mkpkt(eth(ipv4(tcp_seg(1, 2), 6), 0x0800))
        self.assertIn(pkt.color_class(), ("TCP", "OTHER"))

    def test_info_tcp(self):
        pkt = mkpkt(eth(ipv4(tcp_seg(40000, 80, flags=0x18), 6), 0x0800))
        self.assertIn("40000", pkt.info)
        self.assertIn("80", pkt.info)
        self.assertIn("ACK", pkt.info)


class TestStats(unittest.TestCase):
    def test_stats_aggregator_counts(self):
        agg = StatisticsAggregator()
        agg.start_session()
        for i in range(5):
            pkt = mkpkt(eth(ipv4(tcp_seg(1000 + i, 80), 6), 0x0800), number=i + 1)
            agg.update(pkt, matched=(i % 2 == 0))
        snap = agg.snapshot()
        self.assertEqual(snap.total, 5)
        self.assertEqual(snap.matched, 3)
        self.assertEqual(snap.protocol_counts.get("TCP"), 5)
        hosts = dict(snap.top_talkers)
        self.assertEqual(hosts.get("192.168.1.10"), 5)           # once per packet (src)
        self.assertEqual(hosts.get("93.184.216.34"), 5)          # once per packet (dst)


if __name__ == "__main__":
    unittest.main()
