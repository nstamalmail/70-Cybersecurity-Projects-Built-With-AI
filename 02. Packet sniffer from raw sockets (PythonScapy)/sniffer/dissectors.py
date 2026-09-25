"""Protocol dissectors — pure functions over byte buffers.

Every dissector appends a ProtocolLayer to the packet and returns nothing.
Robustness contract (see architecture.md §7):
  * never trust lengths — use ``need()`` for bounds checks
  * malformed input raises TruncatedPacketError, handled by ``dissect()``
  * no I/O, no global state — trivially unit-testable
"""

from __future__ import annotations

import struct
from typing import Callable, Dict, List, Optional

from .models import (
    IPPROTO_ICMP,
    IPPROTO_ICMPV6,
    IPPROTO_TCP,
    IPPROTO_UDP,
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    ETHERTYPE_VLAN,
    Packet,
    ProtocolLayer,
    TruncatedPacketError,
)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def need(buf: bytes, off: int, n: int) -> None:
    """Raise TruncatedPacketError if ``buf[off:off+n]`` is not fully available."""
    if off < 0 or n < 0 or off + n > len(buf):
        raise TruncatedPacketError(f"need {n} bytes at offset {off}, have {max(len(buf) - off, 0)}")


def mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def ipv4(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def ipv6(b: bytes) -> str:
    import ipaddress
    return str(ipaddress.IPv6Address(b))


def _fmt_tcp_flags(f: int) -> List[str]:
    out = []
    for bit, name in ((0x01, "fin"), (0x02, "syn"), (0x04, "rst"), (0x08, "psh"),
                      (0x10, "ack"), (0x20, "urg"), (0x40, "ece"), (0x80, "cwr")):
        if f & bit:
            out.append(name)
    return out


def _safe_ascii(data: bytes, limit: int = 60) -> str:
    out = ""
    for ch in data[:limit]:
        out += chr(ch) if 32 <= ch < 127 else "."
    return out


# ---------------------------------------------------------------------------
# link layer
# ---------------------------------------------------------------------------

def dissect_ethernet(pkt: Packet) -> None:
    buf = pkt.raw
    need(buf, 0, 14)
    dst, src, etype = struct.unpack_from("!6s6sH", buf, 0)
    fields = {"dst": mac(dst), "src": mac(src), "ethertype": etype}
    offset = 14
    inner_type = etype

    # 802.1Q VLAN tag(s) — up to two stacked tags
    vlan_seen = False
    while inner_type == ETHERTYPE_VLAN and offset + 4 <= len(buf):
        tci, inner_type = struct.unpack_from("!HH", buf, offset)
        fields["vlan.vid"] = tci & 0x0FFF
        fields["vlan.pcp"] = (tci >> 13) & 0x07
        vlan_seen = True
        offset += 4
    if vlan_seen:
        fields["ethertype"] = inner_type

    pkt.layers.append(ProtocolLayer("Ethernet", fields, 0, offset))

    payload = buf[offset:]
    if inner_type == ETHERTYPE_IPV4:
        dissect_ipv4(pkt, payload, offset)
    elif inner_type == ETHERTYPE_IPV6:
        dissect_ipv6(pkt, payload, offset)
    elif inner_type == ETHERTYPE_ARP:
        dissect_arp(pkt, payload, offset)
    # unknown ethertype: Ethernet layer alone still renders


def dissect_arp(pkt: Packet, buf: bytes, base: int) -> None:
    need(buf, 0, 28)
    htype, ptype, hlen, plen, oper = struct.unpack_from("!HHBBH", buf, 0)
    sha, spa, tha, tpa = struct.unpack_from("!6s4s6s4s", buf, 8)
    pkt.layers.append(ProtocolLayer("ARP", {
        "htype": htype,
        "ptype": f"0x{ptype:04x}",
        "opcode": oper,
        "sha": mac(sha),
        "spa": ipv4(spa),
        "tha": mac(tha),
        "tpa": ipv4(tpa),
        "src": ipv4(spa),
        "dst": ipv4(tpa),
    }, base, 28))


# ---------------------------------------------------------------------------
# internet layer
# ---------------------------------------------------------------------------

IP_PROTO_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE",
    50: "ESP", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",
}


def dissect_ipv4(pkt: Packet, buf: bytes, base: int) -> None:
    need(buf, 0, 20)
    v_ihl, tos, total_len, ident, flags_frag, ttl, proto, cksum = struct.unpack_from("!BBHHHBBH", buf, 0)
    version = v_ihl >> 4
    ihl = (v_ihl & 0x0F) * 4
    if version != 4 or ihl < 20:
        raise TruncatedPacketError(f"bad IPv4 version/ihl {version}/{ihl}")
    need(buf, 0, ihl)
    src, dst = struct.unpack_from("!4s4s", buf, 12)

    flags = (flags_frag >> 13) & 0x07
    frag_off = flags_frag & 0x1FFF
    fields = {
        "version": version, "ihl": ihl // 4, "tos": tos, "len": total_len,
        "id": ident, "flags": flags, "frag_offset": frag_off,
        "ttl": ttl, "proto": proto, "proto_name": IP_PROTO_NAMES.get(proto, str(proto)),
        "src": ipv4(src), "dst": ipv4(dst),
    }
    # header checksum (lazy validation — cheap, in-header only)
    s = 0
    for i in range(0, ihl, 2):
        s += struct.unpack_from("!H", buf, i)[0]
    s = (s & 0xFFFF) + (s >> 16)
    fields["checksum_ok"] = ((~s) & 0xFFFF) == 0
    if frag_off:
        fields["fragmented"] = True
    if flags & 0x02:
        fields["dont_fragment"] = True

    hdr_len = total_len if total_len else len(buf)
    pkt.layers.append(ProtocolLayer("IPv4", fields, base, min(ihl, len(buf))))

    if proto == IPPROTO_TCP:
        dissect_tcp(pkt, buf[ihl:hdr_len] if hdr_len <= len(buf) else buf[ihl:], base + ihl)
    elif proto == IPPROTO_UDP:
        dissect_udp(pkt, buf[ihl:hdr_len] if hdr_len <= len(buf) else buf[ihl:], base + ihl)
    elif proto == IPPROTO_ICMP:
        dissect_icmp(pkt, buf[ihl:], base + ihl)
    # else: leave IP layer as top; unknown proto still displayed


def dissect_ipv6(pkt: Packet, buf: bytes, base: int) -> None:
    need(buf, 0, 40)
    vtcfl, payload_len, nh, hop = struct.unpack_from("!IHBB", buf, 0)
    version = vtcfl >> 28
    if version != 6:
        raise TruncatedPacketError(f"bad IPv6 version {version}")
    src, dst = struct.unpack_from("!16s16s", buf, 8)
    tc = (vtcfl >> 20) & 0xFF
    flow = vtcfl & 0xFFFFF
    pkt.layers.append(ProtocolLayer("IPv6", {
        "version": version, "traffic_class": tc, "flow_label": flow,
        "payload_len": payload_len, "hop_limit": hop,
        "next_header": nh, "proto_name": IP_PROTO_NAMES.get(nh, str(nh)),
        "src": ipv6(src), "dst": ipv6(dst),
    }, base, 40))

    body = buf[40:40 + payload_len] if payload_len else buf[40:]
    if nh == IPPROTO_TCP:
        dissect_tcp(pkt, body, base + 40)
    elif nh == IPPROTO_UDP:
        dissect_udp(pkt, body, base + 40)
    elif nh == IPPROTO_ICMPV6:
        dissect_icmpv6(pkt, body, base + 40)


def dissect_icmp(pkt: Packet, buf: bytes, base: int) -> None:
    need(buf, 0, 8)
    typ, code, cksum, ident, seq = struct.unpack_from("!BBHHH", buf, 0)
    fields = {"type": typ, "code": code, "id": ident, "seq": seq}
    if typ == 8:
        fields["kind"] = "echo request"
    elif typ == 0:
        fields["kind"] = "echo reply"
    elif typ == 3:
        fields["kind"] = "destination unreachable"
    elif typ == 11:
        fields["kind"] = "time exceeded"
    pkt.layers.append(ProtocolLayer("ICMP", fields, base, 8))


def dissect_icmpv6(pkt: Packet, buf: bytes, base: int) -> None:
    need(buf, 0, 8)
    typ, code, cksum = struct.unpack_from("!BBH", buf, 0)
    ident, seq = struct.unpack_from("!HH", buf, 4)
    fields = {"type": typ, "code": code, "id": ident, "seq": seq}
    if typ == 128:
        fields["kind"] = "echo request"
    elif typ == 129:
        fields["kind"] = "echo reply"
    elif typ == 135:
        fields["kind"] = "neighbor solicitation"
    elif typ == 136:
        fields["kind"] = "neighbor advertisement"
    pkt.layers.append(ProtocolLayer("ICMPv6", fields, base, 8))


# ---------------------------------------------------------------------------
# transport layer
# ---------------------------------------------------------------------------

def dissect_tcp(pkt: Packet, buf: bytes, base: int) -> None:
    need(buf, 0, 20)
    sport, dport, seq, ack, doff_flags, win, cksum, urg = struct.unpack_from("!HHIIHHHH", buf, 0)
    doff = (doff_flags >> 12) * 4
    if doff < 20:
        raise TruncatedPacketError(f"bad TCP data offset {doff}")
    need(buf, 0, doff)
    flags = doff_flags & 0x01FF

    fields: Dict = {
        "sport": sport, "dport": dport, "seq": seq, "ack": ack,
        "win": win, "checksum": cksum, "urgent": urg,
        "payload_len": max(len(buf) - doff, 0),
    }
    for name in _fmt_tcp_flags(flags):
        fields[f"flags.{name}"] = True

    # simple options walk (MSS, window scale, SACK OK, timestamps)
    opt = 20
    while opt < doff:
        kind = buf[opt]
        if kind == 0:
            break
        if kind == 1:
            opt += 1
            continue
        need(buf, opt, 2)
        olen = buf[opt + 1]
        if olen < 2 or opt + olen > doff:
            break
        if kind == 2 and olen == 4:
            fields["options.mss"] = struct.unpack_from("!H", buf, opt + 2)[0]
        elif kind == 3 and olen == 3:
            fields["options.winscale"] = buf[opt + 2]
        elif kind == 4:
            fields["options.sackok"] = True
        elif kind == 8 and olen == 10:
            fields["options.ts"] = True
        opt += olen

    pkt.layers.append(ProtocolLayer("TCP", fields, base, doff))
    payload = buf[doff:]
    if payload:
        _dispatch_port(payload, sport, dport, pkt, base + doff)


def dissect_udp(pkt: Packet, buf: bytes, base: int) -> None:
    need(buf, 0, 8)
    sport, dport, ulen, cksum = struct.unpack_from("!HHHH", buf, 0)
    pkt.layers.append(ProtocolLayer("UDP", {
        "sport": sport, "dport": dport, "len": ulen, "checksum": cksum,
        "payload_len": max(len(buf) - 8, 0),
    }, base, 8))
    payload = buf[8:ulen] if 8 < ulen <= len(buf) else buf[8:]
    if payload:
        if sport == 53 or dport == 53:
            dissect_dns(pkt, payload, base + 8)
        elif sport == 67 or dport == 67 or sport == 68 or dport == 68:
            _note_dhcp(pkt, payload, base + 8)


def _dispatch_port(payload: bytes, sport: int, dport: int, pkt: Packet, base: int) -> None:
    if sport in (80, 8080, 8000) or dport in (80, 8080, 8000):
        dissect_http(pkt, payload, base)
    elif sport == 443 or dport == 443 or sport == 853 or dport == 853:
        dissect_tls(pkt, payload, base)


# ---------------------------------------------------------------------------
# application layer
# ---------------------------------------------------------------------------

DNS_TYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 65: "HTTPS", 33: "SRV"}


def _read_dns_name(buf: bytes, off: int) -> "tuple[str, int]":
    """Read a (possibly compressed) DNS name; returns (name, next_offset)."""
    labels: List[str] = []
    jumps = 0
    pos = off
    end = -1
    while True:
        need(buf, pos, 1)
        l = buf[pos]
        if l == 0:
            pos += 1
            break
        if l & 0xC0 == 0xC0:                      # compression pointer
            need(buf, pos, 2)
            ptr = ((l & 0x3F) << 8) | buf[pos + 1]
            if end < 0:
                end = pos + 2
            jumps += 1
            if jumps > 32 or ptr >= len(buf):
                raise TruncatedPacketError("bad DNS compression pointer")
            pos = ptr
            continue
        if l & 0xC0:
            raise TruncatedPacketError("bad DNS label type")
        need(buf, pos + 1, l)
        labels.append(buf[pos + 1:pos + 1 + l].decode("ascii", "replace"))
        pos += 1 + l
    name = ".".join(labels) if labels else "<root>"
    return name, (end if end >= 0 else pos)


def dissect_dns(pkt: Packet, buf: bytes, base: int) -> None:
    need(buf, 0, 12)
    ident, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", buf, 0)
    fields: Dict = {
        "id": ident,
        "qr": "response" if flags & 0x8000 else "query",
        "opcode": (flags >> 11) & 0x0F,
        "rcode": flags & 0x0F,
        "qdcount": qd, "ancount": an,
    }
    off = 12
    if qd:
        try:
            name, off = _read_dns_name(buf, off)
            need(buf, off, 4)
            qtype, qclass = struct.unpack_from("!HH", buf, off)
            fields["question"] = name
            fields["qtype"] = DNS_TYPE_NAMES.get(qtype, str(qtype))
            fields["qclass"] = "IN" if qclass == 1 else str(qclass)
            off += 4
        except TruncatedPacketError:
            pass
    answers = []
    for _ in range(min(an, 32)):                   # cap work per packet
        try:
            name, off = _read_dns_name(buf, off)
            need(buf, off, 10)
            rtype, _rclass, _ttl, rdlen = struct.unpack_from("!HHIH", buf, off)
            off += 10
            need(buf, off, rdlen)
            rdata = buf[off:off + rdlen]
            if rtype == 1 and rdlen == 4:
                answers.append(f"{name} A {ipv4(rdata)}")
            elif rtype == 28 and rdlen == 16:
                answers.append(f"{name} AAAA {ipv6(rdata)}")
            elif rtype in (2, 5, 12):
                cname, _ = _read_dns_name(buf, off)
                answers.append(f"{name} {DNS_TYPE_NAMES.get(rtype, rtype)} {cname}")
            else:
                answers.append(f"{name} {DNS_TYPE_NAMES.get(rtype, rtype)} ({rdlen} bytes)")
            off += rdlen
        except TruncatedPacketError:
            break
    if answers:
        fields["answers"] = answers
    pkt.layers.append(ProtocolLayer("DNS", fields, base, min(off, len(buf)) - base))


DHCP_OPTIONS = {53: "msg-type", 12: "hostname", 55: "param-list", 1: "subnet-mask", 3: "router", 6: "dns"}


def _note_dhcp(pkt: Packet, buf: bytes, base: int) -> None:
    """Minimal DHCP: option 53 message type + hostname when present."""
    try:
        need(buf, 0, 240)
    except TruncatedPacketError:
        return
    if buf[0:1] != b"\x01":
        return                                    # not a BOOTREQUEST
    magic = buf[236:240]
    if magic != b"\x63\x82\x53\x63":
        return
    msg_type = buf[242] if len(buf) > 242 else None
    fields = {"protocol": "DHCP/BOOTP"}
    if msg_type:
        fields["msg-type"] = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 5: "ACK"}.get(msg_type, str(msg_type))
    pkt.layers.append(ProtocolLayer("DHCP", fields, base, min(len(buf), 300) - base))


def dissect_http(pkt: Packet, buf: bytes, base: int) -> None:
    text = buf[:4096].decode("iso-8859-1", "replace")
    fields: Dict = {}
    lines = text.split("\r\n")
    first = lines[0] if lines else ""
    if first.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ")):
        parts = first.split(" ")
        fields["request.method"] = parts[0]
        fields["request.uri"] = parts[1] if len(parts) > 1 else ""
        fields["request.version"] = parts[2] if len(parts) > 2 else ""
        fields["line"] = first
    elif first.startswith("HTTP/"):
        parts = first.split(" ", 2)
        fields["response.version"] = parts[0]
        fields["response.code"] = parts[1] if len(parts) > 1 else ""
        fields["response.reason"] = parts[2] if len(parts) > 2 else ""
        fields["line"] = first
    else:
        return                                    # not HTTP-looking; keep TCP only
    for line in lines[1:]:
        if not line:
            break
        if ":" in line:
            k, _, v = line.partition(":")
            fields[f"header.{k.strip().lower()}"] = v.strip()
    pkt.layers.append(ProtocolLayer("HTTP", fields, base, min(len(buf), 4096)))


TLS_CONTENT_TYPES = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData"}


def _read_tls_server_name(buf: bytes, ext_off: int, ext_end: int) -> Optional[str]:
    pos = ext_off
    while pos + 4 <= ext_end:
        etype, elen = struct.unpack_from("!HH", buf, pos)
        pos += 4
        if etype == 0 and pos + elen <= ext_end:  # server_name
            try:
                # extension_data: list_len(2) name_type(1) name_len(2) name
                name_type = buf[pos + 2]
                if name_type == 0:
                    nlen = struct.unpack_from("!H", buf, pos + 3)[0]
                    if pos + 5 + nlen <= ext_end:
                        return buf[pos + 5:pos + 5 + nlen].decode("ascii", "replace")
            except (struct.error, IndexError):
                return None
        pos += elen
    return None


def dissect_tls(pkt: Packet, buf: bytes, base: int) -> None:
    need(buf, 0, 5)
    ctype = buf[0]
    ver_major, ver_minor = buf[1], buf[2]
    rec_len = struct.unpack_from("!H", buf, 3)[0]
    fields: Dict = {
        "content_type": TLS_CONTENT_TYPES.get(ctype, str(ctype)),
        "version": f"{ver_major}.{ver_minor}",
        "record_len": rec_len,
    }
    if ctype == 22 and len(buf) >= 9:
        htype = buf[5]
        hnames = {0: "HelloRequest", 1: "ClientHello", 2: "ServerHello",
                  11: "Certificate", 12: "ServerKeyExchange", 16: "ClientKeyExchange"}
        fields["handshake_type"] = hnames.get(htype, str(htype))
        try:
            if htype == 1:                        # ClientHello → SNI
                # body layout from buf[9]: version(2) random(32) sid_len(1)…
                sid_len = buf[43]
                pos = 44 + sid_len
                need(buf, pos, 2)
                cs_len = struct.unpack_from("!H", buf, pos)[0]
                pos += 2 + cs_len
                need(buf, pos, 1)
                cm_len = buf[pos]
                pos += 1 + cm_len
                need(buf, pos, 2)
                ext_len = struct.unpack_from("!H", buf, pos)[0]
                sni = _read_tls_server_name(buf, pos + 2, pos + 2 + ext_len)
                if sni:
                    fields["sni"] = sni
                    fields["line"] = f"ClientHello SNI={sni}"
            elif htype == 2:
                fields["line"] = "ServerHello"
        except (TruncatedPacketError, struct.error, IndexError):
            pass
    elif ctype == 23:
        fields["line"] = "ApplicationData (encrypted)"
    if "line" not in fields:
        fields["line"] = fields["content_type"]
    pkt.layers.append(ProtocolLayer("TLS", fields, base, min(len(buf), rec_len + 5)))


def dissect_quic_header(pkt: Packet, buf: bytes, base: int) -> None:
    """Header-only QUIC note (no decryption)."""
    if not buf:
        return
    b0 = buf[0]
    is_long = bool(b0 & 0x80)
    fields: Dict = {"long_header": is_long}
    if is_long and len(buf) >= 6:
        fields["version"] = "0x" + buf[1:5].hex()
        fields["line"] = f"QUIC long header v={fields['version']}"
    else:
        fields["line"] = "QUIC short header"
    pkt.layers.append(ProtocolLayer("QUIC", fields, base, min(len(buf), 32)))


# ---------------------------------------------------------------------------
# registry & top-level entry
# ---------------------------------------------------------------------------

# dissector registry keyed by name — extension point for plugins
DISSECTORS: Dict[str, Callable] = {
    "ethernet": dissect_ethernet,
    "arp": dissect_arp,
    "ipv4": dissect_ipv4,
    "ipv6": dissect_ipv6,
    "icmp": dissect_icmp,
    "icmpv6": dissect_icmpv6,
    "tcp": dissect_tcp,
    "udp": dissect_udp,
    "dns": dissect_dns,
    "http": dissect_http,
    "tls": dissect_tls,
    "quic": dissect_quic_header,
}

L3_IPPROTO_DISPATCH = {
    IPPROTO_TCP: dissect_tcp,
    IPPROTO_UDP: dissect_udp,
    IPPROTO_ICMP: dissect_icmp,
    IPPROTO_ICMPV6: dissect_icmpv6,
}


def dissect(pkt: Packet, link_layer: bool = True) -> Packet:
    """Dissect ``pkt.raw`` and return the packet.

    ``link_layer=True`` → frame starts with an Ethernet header.
    ``False`` → raw IPv4/IPv6 datagram (Windows SIO_RCVALL path before
    the engine prepends a synthetic Ethernet header — kept for completeness).
    Never raises: malformed packets are flagged, not propagated.

    The packet is frozen, so dissection runs against a temporary mutable
    layer list which is re-frozen into a tuple at the end.
    """
    buf = pkt.raw
    layers: List[ProtocolLayer] = []
    object.__setattr__(pkt, "layers", layers)     # mutable during dissection
    try:
        if link_layer and len(buf) >= 14:
            # full L2 frame — Ethernet dissector dispatches on ethertype and
            # leaves unknown ethertypes as Ethernet-only (never dropped)
            dissect_ethernet(pkt)
        elif buf:
            version = buf[0] >> 4
            if version == 4:
                dissect_ipv4(pkt, buf, 0)
            elif version == 6:
                dissect_ipv6(pkt, buf, 0)
            else:
                raise TruncatedPacketError("unrecognized datagram")
    except TruncatedPacketError:
        object.__setattr__(pkt, "malformed", True)
    except Exception:
        # defense in depth: a bug in a dissector must never kill the capture
        object.__setattr__(pkt, "malformed", True)
    object.__setattr__(pkt, "layers", tuple(layers))
    return pkt
