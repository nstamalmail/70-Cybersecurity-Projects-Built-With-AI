"""Tests for src/domain/calculator.py — known-answer vectors and edge cases."""

import unittest

from src.domain.calculator import (
    calculate_subnet,
    calculate_subnet_from_mask,
    divide_network,
    netmask_from_prefix,
    network_from_string,
    prefix_from_mask,
    usable_host_count,
)
from src.domain.models import PlannerError


class TestCalculateSubnet(unittest.TestCase):
    def test_classic_24(self):
        info = calculate_subnet("192.168.1.25", "24")
        self.assertEqual(info.network, "192.168.1.0/24")
        self.assertEqual(info.prefix, 24)
        self.assertEqual(info.netmask, "255.255.255.0")
        self.assertEqual(info.wildcard, "0.0.0.255")
        self.assertEqual(info.network_address, "192.168.1.0")
        self.assertEqual(info.broadcast_address, "192.168.1.255")
        self.assertEqual(info.first_host, "192.168.1.1")
        self.assertEqual(info.last_host, "192.168.1.254")
        self.assertEqual(info.total_hosts, 256)
        self.assertEqual(info.usable_hosts, 254)
        self.assertEqual(
            info.binary_network, "11000000.10101000.00000001.00000000"
        )
        self.assertEqual(info.binary_mask, "11111111.11111111.11111111.00000000")

    def test_host_bits_are_ignored(self):
        info = calculate_subnet("10.20.30.99", "16")
        self.assertEqual(info.network_address, "10.20.0.0")
        self.assertEqual(info.broadcast_address, "10.20.255.255")

    def test_rfc3021_slash31(self):
        info = calculate_subnet("10.0.0.0", "31")
        self.assertEqual(info.usable_hosts, 2)
        self.assertEqual(info.first_host, "10.0.0.0")
        self.assertEqual(info.last_host, "10.0.0.1")

    def test_rfc3021_slash32(self):
        info = calculate_subnet("10.0.0.5", "32")
        self.assertEqual(info.usable_hosts, 1)
        self.assertEqual(info.first_host, "10.0.0.5")
        self.assertEqual(info.last_host, "10.0.0.5")

    def test_slash0(self):
        info = calculate_subnet("0.0.0.0", "0")
        self.assertEqual(info.network_address, "0.0.0.0")
        self.assertEqual(info.broadcast_address, "255.255.255.255")
        self.assertEqual(info.usable_hosts, 2 ** 32 - 2)
        self.assertEqual(info.wildcard, "255.255.255.255")

    def test_mask_based_calculation(self):
        via_mask = calculate_subnet_from_mask("192.168.1.25", "255.255.255.0")
        via_prefix = calculate_subnet("192.168.1.25", "24")
        self.assertEqual(via_mask, via_prefix)

    def test_invalid_ips(self):
        for bad in ("999.1.1.1", "1.2.3", "1.2.3.4.5", "a.b.c.d", "01.2.3.4", ""):
            with self.subTest(bad=bad):
                with self.assertRaises(PlannerError):
                    calculate_subnet(bad, "24")

    def test_invalid_prefixes(self):
        for bad in ("33", "-1", "abc", ""):
            with self.subTest(bad=bad):
                with self.assertRaises(PlannerError):
                    calculate_subnet("10.0.0.1", bad)

    def test_usable_host_count(self):
        self.assertEqual(usable_host_count(24), 254)
        self.assertEqual(usable_host_count(31), 2)
        self.assertEqual(usable_host_count(32), 1)
        self.assertEqual(usable_host_count(30), 2)
        self.assertEqual(usable_host_count(0), 2 ** 32 - 2)


class TestPrefixFromMask(unittest.TestCase):
    def test_valid_masks(self):
        cases = {
            "255.255.255.255": 32,
            "255.255.255.0": 24,
            "255.255.0.0": 16,
            "255.0.0.0": 8,
            "0.0.0.0": 0,
            "255.255.255.252": 30,
        }
        for mask, expected in cases.items():
            with self.subTest(mask=mask):
                self.assertEqual(prefix_from_mask(mask), expected)

    def test_non_contiguous_mask_rejected(self):
        with self.assertRaises(PlannerError):
            prefix_from_mask("255.0.255.0")

    def test_garbage_rejected(self):
        for bad in ("banana", "255.255.255", "999.1.1.1", ""):
            with self.subTest(bad=bad):
                with self.assertRaises(PlannerError):
                    prefix_from_mask(bad)


class TestDivideNetwork(unittest.TestCase):
    def test_divide_24_into_4(self):
        subnets = divide_network("192.168.1.0/24", 4)
        self.assertEqual(len(subnets), 4)
        self.assertEqual(
            [s.network_address for s in subnets],
            ["192.168.1.0", "192.168.1.64", "192.168.1.128", "192.168.1.192"],
        )
        self.assertTrue(all(s.prefix == 26 for s in subnets))
        self.assertTrue(all(s.usable_hosts == 62 for s in subnets))

    def test_divide_into_8(self):
        subnets = divide_network("10.0.0.0/24", 8)
        self.assertEqual(len(subnets), 8)
        self.assertTrue(all(s.prefix == 27 for s in subnets))

    def test_host_bits_in_base_accepted(self):
        subnets = divide_network("10.0.0.37/24", 2)
        self.assertEqual([s.network_address for s in subnets],
                         ["10.0.0.0", "10.0.0.128"])

    def test_invalid_parts(self):
        with self.assertRaises(PlannerError):
            divide_network("10.0.0.0/24", 3)
        with self.assertRaises(PlannerError):
            divide_network("10.0.0.0/24", 0)

    def test_division_too_fine(self):
        with self.assertRaises(PlannerError):
            divide_network("10.0.0.0/32", 2)

    def test_invalid_base(self):
        with self.assertRaises(PlannerError):
            divide_network("nonsense", 2)


class TestNetmaskFromPrefix(unittest.TestCase):
    def test_known_masks(self):
        cases = {
            0: "0.0.0.0",
            8: "255.0.0.0",
            16: "255.255.0.0",
            24: "255.255.255.0",
            25: "255.255.255.128",
            30: "255.255.255.252",
            31: "255.255.255.254",
            32: "255.255.255.255",
        }
        for prefix, expected in cases.items():
            with self.subTest(prefix=prefix):
                self.assertEqual(netmask_from_prefix(prefix), expected)

    def test_invalid_prefix(self):
        for bad in (-1, 33):
            with self.subTest(bad=bad):
                with self.assertRaises(PlannerError):
                    netmask_from_prefix(bad)


class TestNetworkFromString(unittest.TestCase):
    def test_parses(self):
        net = network_from_string("192.168.1.0/24")
        self.assertEqual(str(net), "192.168.1.0/24")

    def test_rejects_garbage(self):
        for bad in ("10.0.0.0", "10.0.0.0/", "10.0.0.0/33", "10.0.0.999/24"):
            with self.subTest(bad=bad):
                with self.assertRaises(PlannerError):
                    network_from_string(bad)


if __name__ == "__main__":
    unittest.main()