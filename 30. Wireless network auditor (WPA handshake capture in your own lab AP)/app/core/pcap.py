"""Minimal pcap / pcapng reader + 802.11 EAPOL extraction for WNA.

Pure stdlib (architecture.md asks for tshark/pyshark; those are optional
external accelerators — the built-in parser works offline and inside the exe,
which is the point of the verification gate).

Handles:
- classic libpcap (little/big endian, microsecond/nanosecond)
- pcapng (section/streaming parsing of EPB blocks)
- link types: 105 (radiotap), 127 (radiotap 802.11), 1 (Ethernet),
  113 (Linux SLL), 119 (PRISM)
- data frames carrying 802.1X (EAPOL) packets, plus beacons for ESSID/BSSID
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple

LINKTYPE_RADIOTAP = 105
LINKTYPE_RADIOTAP_80211 = 127
LINKTYPE_ETHERNET = 1
LINKTYPE_SLL = 113
LINKTYPE_PRISM = 119

DOT11_TYPE_DATA = 0x2
EAPOL_ETHERTYPE = 0x888E


@dataclass
class Packet:
    linktype: int
    data: bytes
    ts_sec: int = 0
    ts_usec: int = 0


@dataclass
class EapolFrame:
    """A parsed 802.1X EAPOL frame with WPA key-info decomposition."""

    src: str                     # client MAC (station)
    dst: str                     # AP MAC (BSSID) as seen in the 802.11 header
    bssid: str = ""
    version: int = 0
    packet_type: int = 0         # 3 = EAPOL-Key
    key_info: int = 0
    key_length: int = 0
    replay_counter: int = 0
    nonce: bytes = b""
    mic: bytes = b""
    has_pmkid: bool = False
    pmkid: bytes = b""
    message: str = ""            # M1..M4 classification
    ts_sec: int = 0

    @property
    def is_key_frame(self) -> bool:
        return self.packet_type == 3

    def key_info_flags(self) -> List[str]:
        flags = []
        ki = self.key_info
        if ki & 0x0001:
            flags.append("ACK")
        if ki & 0x0002:
            flags.append("MIC")
        if ki & 0x0004:
            flags.append("Secure")
        if ki & 0x0008:
            flags.append("Error")
        if ki & 0x0010:
            flags.append("Request")
        if ki & 0x0040:
            flags.append("KeyRSC")
        return flags


def iter_pcap_packets(path: str) -> Iterator[Packet]:
    """Yield packets from a .cap (libpcap) or .pcapng file."""
    with open(path, "rb") as fh:
        data = fh.read()

    if data.startswith(b"\x0a\x0d\x0d\x0a"):
        yield from _iter_pcapng(data)
        return
    if len(data) < 24:
        return

    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, ts_div = "<", 1e6
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, ts_div = ">", 1e6
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, ts_div = "<", 1e9
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, ts_div = ">", 1e9
    else:
        return

    vmajor, vminor, _tz, _sig, _snap, linktype = struct.unpack_from(
        endian + "HHiIII", data, 4)
    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack_from(
            endian + "IIII", data, off)
        off += 16
        if incl_len > len(data) - off or incl_len > 262144:
            break
        yield Packet(linktype=linktype, data=data[off:off + incl_len],
                     ts_sec=ts_sec, ts_usec=int(ts_frac / (ts_div / 1e6)))
        off += incl_len


def _iter_pcapng(data: bytes) -> Iterator[Packet]:
    off = 0
    linktype = LINKTYPE_ETHERNET
    endian = "<"
    while off + 12 <= len(data):
        block_type, block_len = struct.unpack_from(endian + "II", data, off)
        if block_type == 0x0A0D0D0A:  # SHB
            bom = struct.unpack_from(endian + "I", data, off + 8)[0]
            if bom == 0x1A2B3C4D:
                endian = "<"
            elif bom == 0x4D3C2B1A:
                endian = ">"
            if off + 28 <= len(data):
                linktype = struct.unpack_from(endian + "I", data, off + 20)[0]
        elif block_type == 0x00000001:  # IDB
            if off + 20 <= len(data):
                linktype = struct.unpack_from(endian + "H", data, off + 8)[0]
        elif block_type == 0x00000006:  # EPB
            iface, ts_high, ts_low, cap_len = struct.unpack_from(
                endian + "IIII", data, off + 8)
            if off + 28 + cap_len <= len(data):
                pkt = data[off + 28: off + 28 + cap_len]
                ts_sec = int(((ts_high << 32) | ts_low) / 1e6)
                yield Packet(linktype=linktype, data=pkt, ts_sec=ts_sec)
        elif block_type == 0x00000003:  # SPB
            if off + 16 <= len(data):
                cap_len = struct.unpack_from(endian + "I", data, off + 8)[0]
                pkt = data[off + 16: off + 16 + cap_len]
                yield Packet(linktype=linktype, data=pkt)
        if block_len < 12 or off + block_len > len(data):
            break
        off += block_len


# ------------------------------------------------------------------ 802.11
def _strip_radiotap(data: bytes) -> Tuple[int, bytes]:
    if len(data) < 4:
        return 0, data
    header_len = struct.unpack_from("<H", data, 2)[0]
    return 0, data[header_len:]


def _strip_prism(data: bytes) -> Tuple[int, bytes]:
    if len(data) < 144:
        return 0, data
    return 0, data[144:]


def parse_dot11_frame(data: bytes) -> Optional[dict]:
    """Parse an 802.11 frame header (data/beacon) → dict with addresses."""
    if not data:
        return None
    fc = struct.unpack_from("<H", data, 0)[0]
    version = fc & 0x0003
    ftype = (fc >> 2) & 0x0003
    subtype = (fc >> 4) & 0x000F
    to_ds = bool(fc & 0x0100)
    from_ds = bool(fc & 0x0200)
    if version != 0:
        return None

    addr1 = data[4:10]   # RA / DA
    addr2 = data[10:16]  # TA / SA
    addr3 = data[16:22]  # DA / BSSID

    def mac(b: bytes) -> str:
        return ":".join(f"{x:02x}" for x in b)

    if ftype == 0:  # management (beacon/probe): BSSID = addr3, SSID tag follows
        ssid = ""
        if len(data) > 36:
            i = 36
            while i + 2 <= len(data):
                tag_id, tag_len = data[i], data[i + 1]
                if tag_id == 0:
                    ssid = data[i + 2:i + 2 + tag_len].decode("utf-8", "replace")
                    break
                i += 2 + tag_len
        return {"type": "mgmt", "subtype": subtype, "bssid": mac(addr3),
                "ssid": ssid}

    if ftype == DOT11_TYPE_DATA:
        if to_ds and from_ds:      # WDS — 4 addresses
            if len(data) < 30:
                return None
            bssid = mac(addr1)
            src = mac(data[24:30])
            dst = mac(addr3)
            payload_off = 30
        elif to_ds:                # station → AP: BSSID = addr1
            bssid, src, dst = mac(addr1), mac(addr2), mac(addr3)
            payload_off = 24
        else:                      # AP → station: BSSID = addr2
            bssid, src, dst = mac(addr2), mac(addr3), mac(addr1)
            payload_off = 24
        return {"type": "data", "bssid": bssid, "src": src, "dst": dst,
                "payload_off": payload_off}
    return None


def _parse_eapol(src: str, dst: str, bssid: str, eapol: bytes,
                 ts_sec: int = 0) -> Optional[EapolFrame]:
    """Parse an EAPOL packet (after the 802.1X header start)."""
    # EAPOL: version(1) type(1) length(2) [body]
    if len(eapol) < 4:
        return None
    version = eapol[0]
    packet_type = eapol[1]
    body = eapol[4:]
    frame = EapolFrame(src=src, dst=dst, bssid=bssid, version=version,
                       packet_type=packet_type, ts_sec=ts_sec)
    if packet_type != 3 or len(body) < 95:   # EAPOL-Key body minimum
        frame.message = "EAPOL-nonkey"
        return frame
    # Key descriptor (RSN): nonce@13(32), IV@45, RSC@61, KeyID@69,
    # MIC@77(16), data length@93, key data@95
    frame.key_info = struct.unpack_from(">H", body, 1)[0]
    frame.key_length = struct.unpack_from(">H", body, 3)[0]
    frame.replay_counter = struct.unpack_from(">Q", body, 5)[0]
    frame.nonce = body[13:45]
    frame.mic = body[77:93]
    key_data_len = struct.unpack_from(">H", body, 93)[0] if len(body) >= 95 else 0
    key_data = body[95:95 + key_data_len]

    # IEEE 802.11i Key Information layout:
    #   bits 0-2  Key Descriptor Version
    #   bit  3    Key Type (0x0008 = Pairwise)
    #   bit  7    ACK      (0x0080)
    #   bit  8    MIC      (0x0100)
    #   bit  9    Secure   (0x0200)
    #   bit 10    Error    (0x0400)
    #   bit 11    Request  (0x0800)
    ack = bool(frame.key_info & 0x0080)
    mic_set = bool(frame.key_info & 0x0100)
    secure = bool(frame.key_info & 0x0200)

    if frame.nonce != b"\x00" * 32 and not mic_set and ack:
        frame.message = "M1"
    elif mic_set and not ack and frame.nonce != b"\x00" * 32:
        frame.message = "M2"
    elif mic_set and ack:
        frame.message = "M3"          # ANonce repeated, Secure usually set
    elif mic_set and not ack and frame.nonce == b"\x00" * 32:
        frame.message = "M4"
    else:
        frame.message = "M?"

    # PMKID KDE: dd 14 00 0f ac 04 <8 bytes...>  (16 bytes total pmkid)
    if key_data:
        i = 0
        while i + 2 <= len(key_data):
            kde_id = key_data[i]
            kde_len = key_data[i + 1]
            kde = key_data[i + 2:i + 2 + kde_len]
            if kde_id == 0xdd and len(kde) >= 20 and kde[:6] == b"\x00\x0f\xac\x04" \
                    and kde[6:8] == b"\x00" * 2 or \
                    (kde_id == 0xdd and len(kde) >= 16 and b"\x00\x0f\xac" in kde[:4]):
                # PMKID KDE: OUI type 4; pmkid is the 16 bytes after the OUI
                if len(kde) >= 20 and kde[:4] == b"\x00\x0f\xac\x04":
                    frame.pmkid = kde[8:24] if len(kde) >= 24 else kde[6:22]
                    frame.has_pmkid = True
                    break
            i += 2 + kde_len
    return frame


def extract_eapol_frames(path: str) -> Tuple[List[EapolFrame], List[dict], int]:
    """Parse a capture file → (eapol_frames, aps[{bssid,essid}], total)."""
    eapols: List[EapolFrame] = []
    aps: List[dict] = []
    total = 0
    for pkt in iter_pcap_packets(path):
        total += 1
        data = pkt.data
        linktype = pkt.linktype
        if linktype in (LINKTYPE_RADIOTAP, LINKTYPE_RADIOTAP_80211):
            _, data = _strip_radiotap(data)
        elif linktype == LINKTYPE_PRISM:
            _, data = _strip_prism(data)

        if not data:
            continue
        fc = struct.unpack_from("<H", data, 0)[0] if len(data) >= 2 else 0
        ftype = (fc >> 2) & 0x0003

        if ftype == 0:  # management frame: collect AP/ESSID
            mg = parse_dot11_frame(data)
            if mg and mg.get("bssid") and mg.get("ssid"):
                if not any(a["bssid"] == mg["bssid"] for a in aps):
                    aps.append({"bssid": mg["bssid"], "essid": mg["ssid"]})
            continue

        if ftype != DOT11_TYPE_DATA:
            continue

        frame = parse_dot11_frame(data)
        if not frame:
            continue
        payload = data[frame["payload_off"]:]
        # strip LLC/SNAP: AA AA 03 00 00 00 + ethertype
        if len(payload) < 8:
            continue
        if payload[:3] == b"\xaa\xaa\x03":
            ethertype = struct.unpack_from(">H", payload, 6)[0]
            eapol = payload[8:]
        elif struct.unpack_from(">H", payload, 0)[0] == EAPOL_ETHERTYPE \
                if len(payload) >= 2 else False:
            ethertype = EAPOL_ETHERTYPE
            eapol = payload[2:]
        else:
            continue
        if ethertype != EAPOL_ETHERTYPE:
            continue
        ef = _parse_eapol(frame["src"], frame["dst"], frame["bssid"],
                          eapol, pkt.ts_sec)
        if ef:
            eapols.append(ef)
    return eapols, aps, total
