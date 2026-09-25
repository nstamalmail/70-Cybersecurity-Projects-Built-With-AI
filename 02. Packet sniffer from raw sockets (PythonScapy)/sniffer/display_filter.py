"""Display filter engine — Wireshark-like mini-language.

Grammar (recursive descent, compiled once to a closure tree):

    expr    := or_expr
    or_expr := and_expr ( "or"  and_expr )*
    and_expr:= not_expr ( "and" not_expr )*
    not_expr:= "not" not_expr | comparison | "(" expr ")"
    comparison := field op value
    op      := == != < <= > >= contains
    field   := dotted identifier
    value   := quoted string | bareword | number

Evaluation is O(fields touched) per packet. Unknown fields or syntax errors
raise FilterError which the GUI surfaces inline (red filter bar) — never a
crash. ``contains`` is case-insensitive over the raw frame bytes.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from .models import Packet


class FilterError(ValueError):
    """Raised for syntax errors or unknown fields."""


# ---------------------------------------------------------------------------
# field registry — friendly name -> accessor over Packet
# ---------------------------------------------------------------------------

def _tcp_flag_getter(flag: str) -> Callable[[Packet], Any]:
    def get(pkt: Packet) -> Any:
        tcp = pkt.layer("TCP")
        if not tcp:
            return None
        return bool(tcp.fields.get(f"flags.{flag}"))
    return get


def _layer_field(layer: str, key: str) -> Callable[[Packet], Any]:
    def get(pkt: Packet) -> Any:
        lay = pkt.layer(layer)
        return lay.fields.get(key) if lay else None
    return get


def _ip_host(pkt: Packet) -> Tuple[Optional[str], Optional[str]]:
    v4 = pkt.layer("IPv4")
    if v4:
        return v4.fields.get("src"), v4.fields.get("dst")
    v6 = pkt.layer("IPv6")
    if v6:
        return v6.fields.get("src"), v6.fields.get("dst")
    return None, None


def _arp_src(pkt: Packet) -> Any:
    arp = pkt.layer("ARP")
    return arp.fields.get("spa") if arp else None


def _arp_dst(pkt: Packet) -> Any:
    arp = pkt.layer("ARP")
    return arp.fields.get("tpa") if arp else None


def _raw(pkt: Packet) -> Any:
    return pkt.raw


def _layer_presence(layer: str) -> Callable[[Packet], Any]:
    def get(pkt: Packet) -> Any:
        return pkt.layer(layer)          # None → absent; layer object → present
    return get


# protocol-name presence tests: "udp", "not tcp", "http and tls" …
_PROTOCOL_PRESENCE = {
    "ip": "IPv4", "ipv4": "IPv4", "ipv6": "IPv6", "ip6": "IPv6",
    "tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "icmpv6": "ICMPv6",
    "arp": "ARP", "dns": "DNS", "http": "HTTP", "tls": "TLS",
    "quic": "QUIC", "dhcp": "DHCP", "ethernet": "Ethernet", "eth": "Ethernet",
}


FIELD_ACCESSORS: Dict[str, Callable[[Packet], Any]] = {
    # frame
    "frame": _raw,                      # enables: frame contains "password"
    "frame.len": lambda p: p.frame_len,
    "frame.number": lambda p: p.number,
    "frame.malformed": lambda p: p.malformed,
    # IPv4
    "ip.src": _layer_field("IPv4", "src"),
    "ip.dst": _layer_field("IPv4", "dst"),
    "ip.ttl": _layer_field("IPv4", "ttl"),
    "ip.id": _layer_field("IPv4", "id"),
    "ip.proto": _layer_field("IPv4", "proto"),
    "ip.host": _ip_host,
    # IPv6
    "ipv6.src": _layer_field("IPv6", "src"),
    "ipv6.dst": _layer_field("IPv6", "dst"),
    "ip6.src": _layer_field("IPv6", "src"),
    "ip6.dst": _layer_field("IPv6", "dst"),
    "ip6.host": _ip_host,
    # ARP
    "arp.src.proto": _arp_src,
    "arp.dst.proto": _arp_dst,
    "arp.opcode": _layer_field("ARP", "opcode"),
    # TCP
    "tcp.port": lambda p: (p.src_port, p.dst_port) if p.layer("TCP") else None,
    "tcp.srcport": lambda p: p.src_port if p.layer("TCP") else None,
    "tcp.dstport": lambda p: p.dst_port if p.layer("TCP") else None,
    "tcp.seq": _layer_field("TCP", "seq"),
    "tcp.window": _layer_field("TCP", "win"),
    "tcp.flags.syn": _tcp_flag_getter("syn"),
    "tcp.flags.ack": _tcp_flag_getter("ack"),
    "tcp.flags.fin": _tcp_flag_getter("fin"),
    "tcp.flags.rst": _tcp_flag_getter("rst"),
    "tcp.flags.psh": _tcp_flag_getter("psh"),
    "tcp.flags.urg": _tcp_flag_getter("urg"),
    # UDP
    "udp.port": lambda p: (p.src_port, p.dst_port) if p.layer("UDP") else None,
    "udp.srcport": lambda p: p.src_port if p.layer("UDP") else None,
    "udp.dstport": lambda p: p.dst_port if p.layer("UDP") else None,
    # DNS
    "dns.qname": _layer_field("DNS", "question"),
    "dns.qtype": _layer_field("DNS", "qtype"),
    "dns.flags.response": lambda p: bool(
        (pkt_layer_field(p, "DNS", "qr") or "") == "response"),
    # HTTP
    "http.host": lambda p: pkt_layer_field(p, "HTTP", "header.host"),
    "http.request.method": lambda p: pkt_layer_field(p, "HTTP", "request.method"),
    "http.request.uri": lambda p: pkt_layer_field(p, "HTTP", "request.uri"),
    "http.response.code": lambda p: pkt_layer_field(p, "HTTP", "response.code"),
    # TLS
    "tls.handshake.type": lambda p: pkt_layer_field(p, "TLS", "handshake_type"),
    "tls.sni": lambda p: pkt_layer_field(p, "TLS", "sni"),
}

# register protocol-name presence fields (after the dict literal so names
# like "tcp.port" win over bare "tcp" — presence keys have no dots)
for _pname, _lname in _PROTOCOL_PRESENCE.items():
    FIELD_ACCESSORS[_pname] = _layer_presence(_lname)


def pkt_layer_field(pkt: Packet, layer: str, key: str) -> Any:
    lay = pkt.layer(layer)
    return lay.fields.get(key) if lay else None


# ---------------------------------------------------------------------------
# tokenizer
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"""\s*(?:
        (?P<lparen>\() |
        (?P<rparen>\)) |
        (?P<op>==|!=|<=|>=|<|>) |
        (?P<contains>contains\b) |
        (?P<and>and\b) |
        (?P<or>or\b) |
        (?P<not>not\b) |
        (?P<dqstr>"[^"]*") |
        (?P<sqstr>'[^']*') |
        (?P<number>-?\d+(?:\.\d+)*) |          # dotted quads stay one token (10.0.0.1)
        (?P<field>[A-Za-z_][A-Za-z0-9_.]*) |
        (?P<bare>[^\s()]+)
    )""",
    re.VERBOSE | re.IGNORECASE,
)


def tokenize(text: str) -> List[Tuple[str, str]]:
    """Return a list of (kind, value) tokens. Raises FilterError on garbage."""
    tokens: List[Tuple[str, str]] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            rest = text[pos:].strip()
            if not rest:
                break
            raise FilterError(f"unexpected input near: {rest[:20]!r}")
        pos = m.end()
        kind = m.lastgroup
        value = m.group(kind)
        if kind in ("dqstr", "sqstr"):
            value = value[1:-1]                # strip quotes
            kind = "value"
        elif kind in ("number", "bare"):
            kind = "value"                     # every literal is a value token
        tokens.append((kind, value))
    return tokens


# ---------------------------------------------------------------------------
# parser (recursive descent) — produces a predicate closure
# ---------------------------------------------------------------------------

_OPS = {"==", "!=", "<", "<=", ">", ">="}


class _Parser:
    def __init__(self, tokens: List[Tuple[str, str]]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Optional[Tuple[str, str]]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self) -> Tuple[str, str]:
        tok = self.peek()
        if tok is None:
            raise FilterError("unexpected end of filter expression")
        self.pos += 1
        return tok

    def expect_kind(self, kind: str) -> Tuple[str, str]:
        tok = self.next()
        if tok[0] != kind:
            raise FilterError(f"expected {kind}, got {tok[1]!r}")
        return tok

    # expr := or_expr
    def parse(self) -> Callable[[Packet], bool]:
        fn = self.parse_or()
        if self.peek() is not None:
            raise FilterError(f"trailing input near {self.peek()!r}")
        return fn

    def parse_or(self) -> Callable[[Packet], bool]:
        left = self.parse_and()
        parts = [left]
        while self.peek() and self.peek()[0] == "or":
            self.next()
            parts.append(self.parse_and())

        if len(parts) == 1:
            return left

        def or_fn(pkt: Packet) -> bool:
            return any(part(pkt) for part in parts)
        return or_fn

    def parse_and(self) -> Callable[[Packet], bool]:
        left = self.parse_not()
        parts = [left]
        while self.peek() and self.peek()[0] == "and":
            self.next()
            parts.append(self.parse_not())

        if len(parts) == 1:
            return left

        def and_fn(pkt: Packet) -> bool:
            return all(part(pkt) for part in parts)
        return and_fn

    def parse_not(self) -> Callable[[Packet], bool]:
        tok = self.peek()
        if tok and tok[0] == "not":
            self.next()
            inner = self.parse_not()

            def not_fn(pkt: Packet) -> bool:
                return not inner(pkt)
            return not_fn
        if tok and tok[0] == "lparen":
            self.next()
            inner = self.parse_or()
            self.expect_kind("rparen")
            return inner
        return self.parse_comparison()

    def parse_comparison(self) -> Callable[[Packet], bool]:
        tok = self.next()
        if tok[0] not in ("field", "bare"):
            raise FilterError(f"expected field name, got {tok[1]!r}")
        field_name = tok[1]
        accessor = FIELD_ACCESSORS.get(field_name.lower())
        if accessor is None:
            raise FilterError(
                f"unknown field {field_name!r} — try ip.src, tcp.port, frame.len, …")

        op_tok = self.peek()
        if op_tok is None:
            # bare field = presence test (e.g. "tcp", "http")
            def presence(pkt: Packet) -> bool:
                try:
                    return accessor(pkt) is not None
                except Exception:
                    return False
            return presence
        if op_tok[0] != "op":
            if op_tok[0] == "contains":
                self.next()
                value = self.expect_value()[1]
                return self._contains_fn(accessor, value)
            raise FilterError(f"expected operator after {field_name!r}, got {op_tok[1]!r}")
        self.next()
        op = op_tok[1]
        value = self.expect_value()[1]
        return self._compare_fn(field_name, accessor, op, value)

    def expect_value(self) -> Tuple[str, str]:
        """Value positions accept quoted strings, numbers and barewords
        (e.g. GET, true, https) — anything except keywords/parens."""
        tok = self.next()
        if tok[0] in ("value", "field", "bare"):
            return tok
        raise FilterError(f"expected value, got {tok[1]!r}")

    @staticmethod
    def _coerce(value: str, current: Any) -> Union[int, float, str, bool]:
        if isinstance(current, bool):
            return value.lower() in ("true", "1", "yes")
        if isinstance(current, (int, float)):
            try:
                return int(value)
            except ValueError:
                try:
                    return float(value)
                except ValueError:
                    raise FilterError(f"{value!r} is not numeric for this field")
        return value

    def _compare_fn(self, field_name: str, accessor: Callable[[Packet], Any],
                    op: str, raw_value: str) -> Callable[[Packet], bool]:
        def cmp_fn(pkt: Packet) -> bool:
            current = accessor(pkt)
            if current is None:
                return False
            values = current if isinstance(current, tuple) else (current,)
            for cur in values:
                if cur is None:
                    continue
                try:
                    want = self._coerce(raw_value, cur)
                except FilterError:
                    return False
                try:
                    if op == "==" and cur == want:
                        return True          # tuple fields (ip.host) match either endpoint
                    if op == "!=" and cur != want:
                        return True
                    if isinstance(cur, (int, float)) and isinstance(want, (int, float)):
                        if op == "<" and cur < want:
                            return True
                        if op == "<=" and cur <= want:
                            return True
                        if op == ">" and cur > want:
                            return True
                        if op == ">=" and cur >= want:
                            return True
                    elif op in ("<", "<=", ">", ">="):
                        s_cur, s_want = str(cur), str(want)
                        if op == "<" and s_cur < s_want:
                            return True
                        if op == "<=" and s_cur <= s_want:
                            return True
                        if op == ">" and s_cur > s_want:
                            return True
                        if op == ">=" and s_cur >= s_want:
                            return True
                except TypeError:
                    continue
            return False
        return cmp_fn

    @staticmethod
    def _contains_fn(accessor: Callable[[Packet], Any], value: str) -> Callable[[Packet], bool]:
        needle = value.lower().encode("utf-8", "ignore")

        def contains_fn(pkt: Packet) -> bool:
            current = accessor(pkt)
            if current is None:
                return False
            if isinstance(current, bytes):
                return needle in current.lower()
            return needle in str(current).lower().encode("utf-8", "ignore")
        return contains_fn


def compile_filter(text: str) -> Callable[[Packet], bool]:
    """Compile a display filter expression into a predicate(Packet) -> bool."""
    text = (text or "").strip()
    if not text:
        return lambda pkt: True
    return _Parser(tokenize(text)).parse()


def validate_filter(text: str) -> Optional[str]:
    """Return an error message if invalid, else None."""
    try:
        compile_filter(text)
        return None
    except FilterError as exc:
        return str(exc)
