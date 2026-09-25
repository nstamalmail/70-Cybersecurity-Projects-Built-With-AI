"""Handshake/PMKID verification + hashcat 22000 conversion for WNA
(architecture.md §3.3 Handshake/PMKID Verifier + Hash Converter).

Verification gate: cracking is only offered after a complete M1–M4 exchange
between the same AP/client pair, or a valid PMKID in EAPOL M1.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from typing import Dict, List, Optional, Tuple

from app.core.models import VerificationResult
from app.core.pcap import EapolFrame, extract_eapol_frames


def _pair_key(f: EapolFrame) -> Tuple[str, str]:
    """Identity of the AP/client pair (order-independent on MACs)."""
    return tuple(sorted([f.src, f.dst]))  # type: ignore[return-value]


def verify_capture(path: str) -> VerificationResult:
    """Analyze a .cap/.pcapng capture and assess handshake completeness."""
    result = VerificationResult(capture_path=path)
    if not os.path.exists(path):
        result.notes = "file not found"
        return result

    eapols, aps, total = extract_eapol_frames(path)
    result.total_packets = total
    result.aps_seen = aps
    result.eapol_frames = len(eapols)

    key_frames = [f for f in eapols if f.is_key_frame]

    # group M1..M4 by AP/client pair
    best_pair: Tuple[str, Tuple[int, int, int, int]] = ("", (0, 0, 0, 0))
    best_pair_frames: List[EapolFrame] = []
    pairs: Dict[str, List[EapolFrame]] = {}
    for f in key_frames:
        pairs.setdefault(_pair_key(f), []).append(f)
    for pair, frames in pairs.items():
        msgs = {"M1": 0, "M2": 0, "M3": 0, "M4": 0}
        for fr in frames:
            if fr.message in msgs:
                msgs[fr.message] += 1
        counts = (msgs["M1"], msgs["M2"], msgs["M3"], msgs["M4"])
        score = sum(1 for c in counts if c > 0)
        if score > sum(1 for c in best_pair[1] if c > 0):
            best_pair = (pair, counts)
            best_pair_frames = frames

    counts = best_pair[1]
    msgs_present = [name for name, c in zip(("M1", "M2", "M3", "M4"), counts) if c > 0]
    result.messages_present = msgs_present
    result.handshake_captured = all(c > 0 for c in counts) and len(msgs_present) == 4
    if result.handshake_captured:
        result.handshake_completeness = "complete"
    elif msgs_present:
        result.handshake_completeness = "partial"

    # BSSID/ESSID from the best pair or beacons
    if best_pair_frames:
        f0 = best_pair_frames[0]
        # BSSID is whichever end is the AP: M1's receiver is the client.
        m1 = next((fr for fr in best_pair_frames if fr.message == "M1"), None)
        if m1:
            result.bssid = m1.src      # M1 sender = AP
        else:
            result.bssid = f0.bssid or f0.dst
    for ap in aps:
        if result.bssid and ap["bssid"] == result.bssid:
            result.essid = ap["essid"]
            break
    if not result.essid and aps:
        result.essid = aps[0]["essid"]

    # PMKID: usually in M1 key data
    for fr in key_frames:
        if fr.has_pmkid and fr.pmkid:
            result.pmkid_captured = True
            if not result.bssid and fr.src:
                result.bssid = fr.src
            break

    if not key_frames:
        result.notes = ("no EAPOL-Key frames in capture — was the capture taken "
                        "on the right channel? did a client (re)connect?")
    elif result.handshake_completeness == "partial":
        result.notes = ("partial handshake: capture longer or force a client "
                        "re-authentication in your lab (deauth is opt-in)")
    return result


# ------------------------------------------------------------------ hash conversion
def _hexs(b: bytes) -> str:
    return b.hex()


def convert_to_22000(path: str) -> List[str]:
    """Convert a capture to hashcat mode 22000 lines (WPA-PBKDF2-PMKID+EAPOL).

    Line format: WPA*01*pmkid*mac_ap*mac_sta*essid*password_hex*… simplified
    to the EAPOL variant hashcat accepts for verification tooling:
    WPA*01*<pmkid or ''>*<ap_mac>*<sta_mac>*<essid>*<eapol_b64_hex>*<eapol_len>
    Note: this produces the message-pair line used by the audit report; full
    cracking with hashcat/aircrack-ng uses the original capture.
    """
    lines: List[str] = []
    eapols, _aps, _total = extract_eapol_frames(path)
    key_frames = [f for f in eapols if f.is_key_frame]

    pairs: Dict[str, List[EapolFrame]] = {}
    for f in key_frames:
        pairs.setdefault(_pair_key(f), []).append(f)

    for pair, frames in pairs.items():
        m1 = next((fr for fr in frames if fr.message == "M1"), None)
        m2 = next((fr for fr in frames if fr.message == "M2"), None)
        if not (m1 and m2):
            continue
        ap_mac = m1.src.replace(":", "")
        sta_mac = m1.dst.replace(":", "")
        essid = ""
        for fr in frames:
            if fr.bssid:
                break
        # EAPOL bytes for M2 (full EAPOL packet incl. header, no FCS)
        m2_eapol = bytes([2, m2.packet_type]) + struct.pack(
            ">H", 0)  # placeholder; real length from capture parse below
        # rebuild full EAPOL header from parsed fields
        eapol_body = bytearray(97 + 0)
        eapol_body[0] = 2  # key descriptor version (placeholder)
        struct.pack_into(">H", eapol_body, 1, m2.key_info)
        struct.pack_into(">H", eapol_body, 3, m2.key_length)
        struct.pack_into(">Q", eapol_body, 5, m2.replay_counter)
        eapol_body[13:77] = m2.nonce
        eapol_body[77:94] = m2.mic
        eapol_full = bytes([m2.version, 3]) + len(eapol_body).to_bytes(2, "big") \
            + bytes(eapol_body)
        pmkid_hex = _hexs(m1.pmkid) if m1.has_pmkid else ""
        lines.append(
            f"WPA*01*{pmkid_hex}*{ap_mac}*{sta_mac}*{essid or 'ESSID_UNKNOWN'}*"
            f"{_hexs(eapol_full)}*{len(eapol_full)}")
    return lines


# ------------------------------------------------------------------ PSK math
def compute_pmk(passphrase: str, essid: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", passphrase.encode("utf-8"),
                               essid.encode("utf-8"), 4096, 32)


def compute_ptk(pmk: bytes, ap_mac: str, sta_mac: str, ap_nonce: bytes,
                sta_nonce: bytes) -> bytes:
    """PRF-512 (IEEE 802.11i / hostapd) PTK derivation.

    A = "Pairwise key expansion" || 0x00 ||
        min(AA,SPA) || max(AA,SPA) || ANonce || SNonce
    (MACs sorted ascending; nonces in ANonce-then-SNonce order.)
    """
    def mac_bytes(m: str) -> bytes:
        return bytes.fromhex(m.replace(":", ""))

    apb, stb = mac_bytes(ap_mac), mac_bytes(sta_mac)
    if apb > stb:
        apb, stb = stb, apb            # apb = min, stb = max
    label = b"Pairwise key expansion"
    A = label + b"\x00" + apb + stb + ap_nonce + sta_nonce
    out = b""
    for i in range(4):
        out += hmac.new(pmk, A + bytes([i]), hashlib.sha1).digest()
    return out[:64]


def verify_psk(passphrase: str, essid: str, ap_mac: str, sta_mac: str,
               m1: EapolFrame, m2: EapolFrame) -> bool:
    """Verify a candidate PSK against a captured M1/M2 pair (MIC check)."""
    pmk = compute_pmk(passphrase, essid)
    ptk = compute_ptk(pmk, ap_mac, sta_mac, m1.nonce, m2.nonce)
    kck = ptk[:16]
    mic = hmac.new(kck, _mic_frame(m2), hashlib.md5).digest()
    return hmac.compare_digest(mic, m2.mic[:16])


def _mic_frame(m2: EapolFrame) -> bytes:
    """Reconstruct the 802.1X frame with MIC zeroed for MIC computation.

    Layout matches the RSN key descriptor: type@0, info@1, len@3,
    replay@5, nonce@13(32), IV@45(16), RSC@61(8), KeyID@69(8), MIC@77
    (zeroed), data length@93 (=0).
    """
    body = bytearray(95)
    body[0] = 2
    struct.pack_into(">H", body, 1, m2.key_info)
    struct.pack_into(">H", body, 3, m2.key_length)
    struct.pack_into(">Q", body, 5, m2.replay_counter)
    body[13:45] = m2.nonce[:32]
    # IV / RSC / KeyID remain zero, MIC field zeroed, data length 0
    return bytes([m2.version, 3]) + len(body).to_bytes(2, "big") + bytes(body)
