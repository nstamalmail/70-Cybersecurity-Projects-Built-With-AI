"""Tests for the pcap writer/reader round-trip (stdlib unittest)."""

import os
import struct
import tempfile
import unittest

from sniffer.capture.pcap_file import PcapFormatError, PcapReader, PcapWriter


class TestPcapRoundTrip(unittest.TestCase):
    def test_round_trip_micro(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.pcap")
            w = PcapWriter(path)
            pkts = [(1700000000.100000, b"\x01\x02\x03\x04" * 20),
                    (1700000000.200000, b"\xff" * 60),
                    (1700000000.300000, b"")]
            for ts, data in pkts:
                w.write_packet(ts, data)
            w.close()

            r = PcapReader(path)
            self.assertEqual(r.version, (2, 4))
            self.assertEqual(r.linktype, 1)
            recs = r.read_all()
            self.assertEqual(len(recs), 3)
            self.assertEqual(recs[0].data, pkts[0][1])
            self.assertLess(abs(recs[0].ts - 1700000000.100000), 1e-6)
            self.assertEqual(recs[2].orig_len, 0)
            r.close()

    def test_read_big_endian_nanosecond_magic(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "be.pcap")
            with open(path, "wb") as fh:
                fh.write(struct.pack(">IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1))
                fh.write(struct.pack(">IIII", 1700000000, 500_000_000, 4, 4))
                fh.write(b"\xde\xad\xbe\xef")
            r = PcapReader(path)
            recs = r.read_all()
            self.assertEqual(len(recs), 1)
            self.assertLess(abs(recs[0].ts - 1700000000.5), 1e-6)
            r.close()

    def test_bad_magic_raises(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bad.pcap")
            with open(path, "wb") as fh:
                fh.write(b"NOTPCAP1234567890123456")
            with self.assertRaises(PcapFormatError):
                PcapReader(path)

    def test_truncated_tail_is_tolerated(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "trunc.pcap")
            w = PcapWriter(path)
            w.write_packet(1700000000.0, b"A" * 32)
            w.close()
            with open(path, "r+b") as fh:
                fh.truncate(24 + 16 + 10)                  # cut inside packet data
            r = PcapReader(path)
            self.assertEqual(len(r.read_all()), 0)         # incomplete record dropped
            r.close()


if __name__ == "__main__":
    unittest.main()
