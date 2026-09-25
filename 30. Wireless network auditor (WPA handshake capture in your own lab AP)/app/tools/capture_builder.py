"""Synthetic .cap builder for WNA testing: writes a valid libpcap file with a
beacon frame and a complete WPA2 4-way handshake (M1–M4) computed from a real
PSK, so the verifier and the internal cracker have authentic material.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import List, Tuple

AP_MAC = "02:11:22:33:44:55"
STA_MAC = "02:aa:bb:cc:dd:ee"
DEFAULT_SSID = "WNA-Lab-AP"
DEFAULT_PSK = "hunter2-but-longer"


def _mac_bytes(m: str) -> bytes:
    return bytes.fromhex(m.replace(":", ""))


def _mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _beacon(bssid: str, ssid: str) -> bytes:
    # radiotap header (8 bytes, minimal)
    radiotap = struct.pack("<BBHBBBB", 0, 0, 8, 0x0000, 0, 0, 0)
    fc = 0x0080                       # beacon
    dur = 0
    addr_b = _mac_bytes(bssid)
    header = struct.pack("<HH6s6s6sH", fc, dur, addr_b, addr_b, addr_b, 0)
    # fixed params: timestamp(8) beacon interval(2) capability(2)
    fixed = struct.pack("<QHH", 0, 100, 0x0411)
    # tagged params: SSID + supported rates
    ssid_ie = bytes([0, len(ssid)]) + ssid.encode()
    rates_ie = bytes([1, 4, 0x82, 0x84, 0x0b, 0x96])
    return radiotap + header + fixed + ssid_ie + rates_ie


def _eapol_key_frame(version: int, key_info: int, key_len: int,
                     replay: int, nonce: bytes, mic: bytes,
                     key_data: bytes = b"") -> bytes:
    """Build an EAPOL-Key packet (802.1X header + RSN key descriptor).

    Body layout (IEEE 802.11i, key descriptor type at 0):
      0      key descriptor type
      1-2    key information (flags)
      3-4    key length
      5-12   key replay counter
      13-44  key nonce (32)
      45-60  key IV (16)
      61-68  key RSC (8)
      69-76  key ID (8, reserved)
      77-92  key MIC (16)
      93-94  key data length
      95+    key data
    """
    body_len = 95 + len(key_data)
    body = bytearray(body_len)
    body[0] = 2                      # descriptor type: RSN (802.11i)
    struct.pack_into(">H", body, 1, key_info)
    struct.pack_into(">H", body, 3, key_len)
    struct.pack_into(">Q", body, 5, replay)
    body[13:45] = nonce[:32]
    # IV / RSC / KeyID remain zero
    body[77:93] = mic[:16]
    struct.pack_into(">H", body, 93, len(key_data))
    body[95:95 + len(key_data)] = key_data
    eapol = bytes([version, 3]) + struct.pack(">H", body_len) + bytes(body)
    return eapol


def _data_frame(src: str, dst: str, bssid: str, payload: bytes) -> bytes:
    radiotap = struct.pack("<BBHBBBB", 0, 0, 8, 0x0000, 0, 0, 0)
    # to_ds=1 (station → AP): addr1=BSSID(rev path M1 handled separately)
    fc = 0x0108                       # data frame, to DS
    header = struct.pack("<HH6s6s6sH", fc, 0, _mac_bytes(dst),
                         _mac_bytes(src), _mac_bytes(bssid), 0)
    llc = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
    return radiotap + header + llc + payload


def _data_frame_ap(src: str, dst: str, bssid: str, payload: bytes) -> bytes:
    radiotap = struct.pack("<BBHBBBB", 0, 0, 8, 0x0000, 0, 0, 0)
    fc = 0x0208                       # data frame, from DS (AP → station)
    header = struct.pack("<HH6s6s6sH", fc, 0, _mac_bytes(dst),
                         _mac_bytes(src), _mac_bytes(bssid), 0)
    llc = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
    return radiotap + header + llc + payload


def compute_ptk(psk: str, ssid: str, ap: str, sta: str,
                ap_nonce: bytes, sta_nonce: bytes) -> bytes:
    """PRF-512 PTK — same canonical order as the verifier:
    min(MAC)||max(MAC)||ANonce||SNonce."""
    pmk = hashlib.pbkdf2_hmac("sha1", psk.encode(), ssid.encode(), 4096, 32)
    apb, stb = _mac_bytes(ap), _mac_bytes(sta)
    if apb > stb:
        apb, stb = stb, apb
    A = (b"Pairwise key expansion" + b"\x00" + apb + stb
         + ap_nonce + sta_nonce)
    out = b""
    for i in range(4):
        out += hmac.new(pmk, A + bytes([i]), hashlib.sha1).digest()
    return out[:64]


def build_mic(kck: bytes, eapol_packet: bytes) -> bytes:
    """MIC over the EAPOL packet with MIC field zeroed (already zeroed in
    the input)."""
    return hmac.new(kck, eapol_packet, hashlib.md5).digest()[:16]


def build_handshake_cap(path: str, ssid: str = DEFAULT_SSID,
                        psk: str = DEFAULT_PSK,
                        include_m3_m4: bool = True,
                        include_pmkid: bool = True) -> dict:
    """Write a .cap with beacon + M1..M4 (MICs computed from the real PSK)."""
    ap, sta = AP_MAC, STA_MAC
    ap_nonce = bytes(range(32))
    sta_nonce = bytes(range(32, 64))
    anonce = ap_nonce
    snonce = sta_nonce

    # global packet counter for replay counters
    frames: List[bytes] = []
    frames.append(_beacon(ap, ssid))

    # M1: AP → STA, ACK set, no MIC, ANonce
    replay1 = 1
    key_data = b""
    if include_pmkid:
        # PMKID KDE: dd 14 00 0f ac 04 <pmkid(16)>
        pmk = hashlib.pbkdf2_hmac("sha1", psk.encode(), ssid.encode(), 4096, 32)
        pmkid = hmac.new(pmk, b"PMK Name" + _mac_bytes(ap) + _mac_bytes(sta),
                         hashlib.sha1).digest()
        key_data = bytes([0xdd, 20]) + b"\x00\x0f\xac\x04" + b"\x00\x00" + pmkid
    m1_eapol = _eapol_key_frame(2, 0x008A, 16, replay1, anonce,
                                b"\x00" * 16, key_data)
    frames.append(_data_frame_ap(ap, sta, ap, m1_eapol))

    # M2: STA → AP, MIC set, SNonce
    replay2 = 1
    m2_eapol = _eapol_key_frame(2, 0x010A, 16, replay2, snonce,
                                b"\x00" * 16)
    ptk = compute_ptk(psk, ssid, ap, sta, anonce, snonce)
    kck = ptk[:16]
    mic = build_mic(kck, m2_eapol)
    # rebuild M2 with MIC filled
    m2_eapol = _eapol_key_frame(2, 0x010A, 16, replay2, snonce, mic)
    frames.append(_data_frame(sta, ap, ap, m2_eapol))

    if include_m3_m4:
        # M3: AP → STA, ACK+MIC+Secure, ANonce
        replay3 = replay1 + 1
        m3_eapol = _eapol_key_frame(2, 0x13CA, 16, replay3, anonce,
                                    b"\x00" * 16)
        mic3 = build_mic(kck, m3_eapol)
        m3_eapol = _eapol_key_frame(2, 0x13CA, 16, replay3, anonce, mic3)
        frames.append(_data_frame_ap(ap, sta, ap, m3_eapol))

        # M4: STA → AP, MIC+Secure, zero nonce
        replay4 = replay2 + 1
        m4_eapol = _eapol_key_frame(2, 0x030A, 16, replay4, b"\x00" * 32,
                                    b"\x00" * 16)
        mic4 = build_mic(kck, m4_eapol)
        m4_eapol = _eapol_key_frame(2, 0x030A, 16, replay4, b"\x00" * 32, mic4)
        frames.append(_data_frame(sta, ap, ap, m4_eapol))

    # write libpcap (linktype radiotap = 105)
    out = bytearray()
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 105)
    ts = 1727000000
    for i, fr in enumerate(frames):
        out += struct.pack("<IIII", ts + i, 0, len(fr), len(fr))
        out += fr

    with open(path, "wb") as fh:
        fh.write(bytes(out))

    return {
        "path": path, "ssid": ssid, "psk": psk, "ap": ap, "sta": sta,
        "frames": len(frames),
    }
