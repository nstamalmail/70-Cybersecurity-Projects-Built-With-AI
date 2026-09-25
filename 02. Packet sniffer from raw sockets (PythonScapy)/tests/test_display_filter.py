"""Tests for the display filter engine (stdlib unittest)."""

import unittest

from sniffer.display_filter import FilterError, compile_filter, tokenize, validate_filter

from test_dissectors import eth, ipv4, mkpkt, tcp_seg, udp_seg


class TestGrammar(unittest.TestCase):
    def test_tokenize_basic(self):
        toks = tokenize("ip.src == 10.0.0.1 and tcp.port == 443")
        kinds = [k for k, _ in toks]
        self.assertEqual(kinds, ["field", "op", "value", "and", "field", "op", "value"])

    def test_tokenize_quoted_strings(self):
        toks = tokenize('http.host == "example.com"')
        self.assertIn(("value", "example.com"), toks)

    def test_unknown_field_raises(self):
        with self.assertRaises(FilterError):
            compile_filter("bogus.field == 1")

    def test_syntax_error_raises(self):
        with self.assertRaises(FilterError):
            compile_filter("ip.src == ")
        with self.assertRaises(FilterError):
            compile_filter("and tcp.port == 80")

    def test_validate_filter_returns_message(self):
        self.assertIsNone(validate_filter("tcp.port == 80"))
        self.assertIsNotNone(validate_filter("nope !!!"))


class TestEvaluation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tcp_pkt = mkpkt(eth(ipv4(tcp_seg(51000, 443, flags=0x02), 6), 0x0800))
        cls.udp_pkt = mkpkt(eth(ipv4(udp_seg(51001, 53, b"\x00" * 12), 17), 0x0800))
        cls.http_pkt = mkpkt(eth(ipv4(tcp_seg(
            51002, 80, flags=0x18,
            payload=b"GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n"), 6), 0x0800))

    def test_eq_port(self):
        self.assertTrue(compile_filter("tcp.port == 443")(self.tcp_pkt))
        self.assertFalse(compile_filter("tcp.port == 80")(self.tcp_pkt))

    def test_udp_port(self):
        self.assertTrue(compile_filter("udp.port == 53")(self.udp_pkt))
        self.assertFalse(compile_filter("udp.port == 53")(self.tcp_pkt))

    def test_and_or_not(self):
        f = compile_filter("tcp.port == 443 and ip.src == 192.168.1.10")
        self.assertTrue(f(self.tcp_pkt))
        g = compile_filter("tcp.port == 443 or udp.port == 53")
        self.assertTrue(g(self.tcp_pkt))
        self.assertTrue(g(self.udp_pkt))
        h = compile_filter("not udp")
        self.assertTrue(h(self.tcp_pkt))
        self.assertFalse(compile_filter("not tcp")(self.tcp_pkt))

    def test_precedence_and_over_or(self):
        # 'and' binds tighter than 'or'
        f = compile_filter("tcp.port == 80 or tcp.port == 443 and ip.src == 192.168.1.10")
        self.assertTrue(f(self.tcp_pkt))
        self.assertFalse(f(self.udp_pkt))

    def test_parentheses(self):
        f = compile_filter("(tcp.port == 80 or tcp.port == 443) and frame.len > 0")
        self.assertTrue(f(self.tcp_pkt))

    def test_flags_and_numeric_compare(self):
        self.assertTrue(compile_filter("tcp.flags.syn == true")(self.tcp_pkt))
        self.assertFalse(compile_filter("tcp.flags.fin == true")(self.tcp_pkt))
        self.assertTrue(compile_filter("frame.len >= 54")(self.tcp_pkt))
        self.assertTrue(compile_filter("ip.ttl == 64")(self.tcp_pkt))
        self.assertFalse(compile_filter("ip.ttl > 64")(self.tcp_pkt))

    def test_contains(self):
        self.assertFalse(compile_filter('frame contains "GET"')(self.tcp_pkt))
        self.assertTrue(compile_filter('frame contains "get /x"')(self.http_pkt))
        self.assertTrue(compile_filter('http.request.method == GET')(self.http_pkt))

    def test_http_host(self):
        self.assertTrue(compile_filter('http.host == "example.com"')(self.http_pkt))

    def test_ip_host_matches_either_side(self):
        pkt = mkpkt(eth(ipv4(tcp_seg(1, 2), 6, src="10.0.0.5", dst="10.0.0.6"), 0x0800))
        self.assertTrue(compile_filter("ip.host == 10.0.0.5")(pkt))
        self.assertTrue(compile_filter("ip.host == 10.0.0.6")(pkt))

    def test_absent_field_is_false(self):
        self.assertFalse(compile_filter("udp.port == 53")(self.tcp_pkt))
        self.assertFalse(compile_filter('http.host == "x"')(self.tcp_pkt))


if __name__ == "__main__":
    unittest.main()
