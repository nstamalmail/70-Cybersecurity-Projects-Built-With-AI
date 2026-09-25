"""Embedded OUI vendor database + lookup.

The embedded dict is a curated snapshot of common consumer/enterprise
prefixes so the exe stays self-contained (architecture.md §4.4). If a
full IEEE dataset is placed next to the exe/app as ``oui.txt``
(IEEE OUI format: "00-00-0C   (hex)\t\tCisco Systems, Inc"), it is
loaded and merged at startup.

Locally-administered / randomized MACs (2nd hex digit in {2,6,A,E})
are reported as "Randomized (locally administered)" when no OUI match
exists — typical for modern phones using privacy MACs.
"""

from __future__ import annotations

import os
import re

# ------------------------------------------------------------------ data

OUI_DB: dict[str, str] = {
    # --- Virtualization / cloud (very common in scans) ---
    "00:05:69": "VMware",
    "00:0C:29": "VMware",
    "00:1C:14": "VMware",
    "00:50:56": "VMware",
    "00:15:5D": "Microsoft (Hyper-V)",
    "00:03:FF": "Microsoft",
    "00:0D:3A": "Microsoft (Azure)",
    "00:25:AE": "Microsoft",
    "00:50:F2": "Microsoft",
    "00:1C:42": "Parallels",
    "08:00:27": "VirtualBox",
    "00:16:3E": "Xen",
    "52:54:00": "QEMU/KVM",
    "00:02:C9": "Mellanox",

    # --- Apple ---
    "00:03:93": "Apple", "00:05:02": "Apple", "00:0A:27": "Apple",
    "00:0A:95": "Apple", "00:0D:93": "Apple", "00:10:FA": "Apple",
    "00:11:24": "Apple", "00:14:51": "Apple", "00:16:CB": "Apple",
    "00:17:F2": "Apple", "00:19:E3": "Apple", "00:1B:63": "Apple",
    "00:1C:B3": "Apple", "00:1E:52": "Apple", "00:1E:C2": "Apple",
    "00:1F:5B": "Apple", "00:1F:F3": "Apple", "00:21:E9": "Apple",
    "00:22:41": "Apple", "00:23:6C": "Apple", "00:23:DF": "Apple",
    "00:24:36": "Apple", "00:25:00": "Apple", "00:25:4B": "Apple",
    "00:25:BC": "Apple", "00:26:08": "Apple", "00:26:4A": "Apple",
    "00:26:B0": "Apple", "00:26:BB": "Apple", "28:6A:BA": "Apple",
    "28:CF:E9": "Apple", "2C:B0:5D": "Apple", "30:A1:39": "Apple",
    "34:C0:59": "Apple", "38:C9:86": "Apple", "3C:07:54": "Apple",
    "40:33:1A": "Apple", "48:74:6E": "Apple", "4C:7C:5F": "Apple",
    "50:EA:D6": "Apple", "54:26:96": "Apple", "58:1F:28": "Apple",
    "58:55:CA": "Apple", "5C:59:F5": "Apple", "60:FA:CD": "Apple",
    "64:A3:CB": "Apple", "68:A8:6D": "Apple", "6C:40:08": "Apple",
    "70:56:81": "Apple", "74:E1:B6": "Apple", "78:31:C1": "Apple",
    "7C:6D:62": "Apple", "80:E6:50": "Apple", "84:38:35": "Apple",
    "88:66:A5": "Apple", "8C:29:37": "Apple", "90:B2:1F": "Apple",
    "94:94:26": "Apple", "98:01:A7": "Apple", "9C:20:7B": "Apple",
    "A0:99:9B": "Apple", "A4:B1:C1": "Apple", "A8:88:08": "Apple",
    "AC:87:A3": "Apple", "B0:34:95": "Apple", "B4:18:D1": "Apple",
    "BC:52:B7": "Apple", "C0:63:94": "Apple", "C4:2C:03": "Apple",
    "C8:69:CD": "Apple", "CC:08:E0": "Apple", "D0:03:4B": "Apple",
    "D4:9A:20": "Apple", "D8:00:4D": "Apple", "D8:96:95": "Apple",
    "DC:2B:61": "Apple", "E0:F8:47": "Apple", "F0:18:98": "Apple",
    "F0:B4:79": "Apple", "F4:F1:5A": "Apple", "FC:25:3F": "Apple",

    # --- Cisco (representative subset) ---
    "00:00:0C": "Cisco", "00:06:2A": "Cisco", "00:06:28": "Cisco",
    "00:07:0D": "Cisco", "00:07:4F": "Cisco", "00:0A:42": "Cisco",
    "00:0B:46": "Cisco", "00:0B:BE": "Cisco", "00:0D:28": "Cisco",
    "00:0E:08": "Cisco", "00:0E:38": "Cisco", "00:11:20": "Cisco",
    "00:11:5C": "Cisco", "00:11:92": "Cisco", "00:12:00": "Cisco",
    "00:12:13": "Cisco", "00:12:7F": "Cisco", "00:12:D9": "Cisco",
    "00:13:19": "Cisco", "00:13:5F": "Cisco", "00:13:C4": "Cisco",
    "00:14:1B": "Cisco", "00:14:69": "Cisco", "00:14:A8": "Cisco",
    "00:15:2B": "Cisco", "00:16:46": "Cisco", "00:17:0E": "Cisco",
    "00:17:5A": "Cisco", "00:17:94": "Cisco", "00:18:18": "Cisco",
    "00:18:39": "Cisco", "00:18:73": "Cisco", "00:19:06": "Cisco",
    "00:1A:2F": "Cisco", "00:1A:70": "Cisco", "00:1B:0C": "Cisco",
    "00:1B:2A": "Cisco", "00:1B:54": "Cisco", "00:1B:8F": "Cisco",
    "00:1C:B0": "Cisco", "00:1D:45": "Cisco", "00:1E:14": "Cisco",
    "00:1E:49": "Cisco", "00:1E:7A": "Cisco", "00:1E:F7": "Cisco",
    "00:1F:6C": "Cisco", "00:1F:9E": "Cisco", "00:1F:CA": "Cisco",

    # --- Hewlett-Packard ---
    "00:10:83": "Hewlett-Packard", "00:1E:0B": "Hewlett-Packard",
    "00:23:7D": "Hewlett-Packard", "00:24:81": "Hewlett-Packard",
    "00:26:55": "Hewlett-Packard",

    # --- Dell ---
    "00:14:22": "Dell", "00:1A:A0": "Dell", "00:1D:09": "Dell",
    "00:21:70": "Dell", "00:23:AE": "Dell", "00:25:64": "Dell",
    "00:26:B9": "Dell", "18:03:73": "Dell", "B8:CA:3A": "Dell",
    "D4:BE:D9": "Dell", "F0:1F:AF": "Dell",

    # --- Lenovo / IBM ---
    "00:04:AC": "IBM", "00:06:29": "IBM", "00:09:6B": "IBM",
    "00:0D:60": "IBM", "00:11:25": "IBM", "54:E1:AD": "Lenovo",

    # --- Intel ---
    "00:1B:21": "Intel", "00:1C:BF": "Intel", "00:1D:E0": "Intel",
    "00:1E:64": "Intel", "00:1F:3B": "Intel", "00:22:FA": "Intel",
    "00:24:D6": "Intel", "00:27:10": "Intel", "3C:A9:F4": "Intel",
    "58:6D:8F": "Intel", "5C:C5:D4": "Intel", "84:3A:4B": "Intel",
    "A0:A8:CD": "Intel",

    # --- Realtek / NIC vendors ---
    "00:E0:4C": "Realtek", "00:10:18": "Broadcom", "00:90:4C": "Broadcom",
    "00:04:4B": "NVIDIA",

    # --- ASUS ---
    "00:0C:6E": "ASUSTek", "00:0E:A6": "ASUSTek", "00:15:F2": "ASUSTek",
    "00:17:31": "ASUSTek", "00:18:F3": "ASUSTek", "00:1A:92": "ASUSTek",
    "00:1D:60": "ASUSTek", "00:1F:C6": "ASUSTek", "00:22:15": "ASUSTek",
    "00:23:54": "ASUSTek", "00:24:8C": "ASUSTek", "00:26:18": "ASUSTek",
    "04:D9:F5": "ASUSTek", "08:60:6E": "ASUSTek", "10:BF:48": "ASUSTek",
    "14:DA:E9": "ASUSTek", "1C:87:2C": "ASUSTek", "20:CF:30": "ASUSTek",
    "2C:4D:54": "ASUSTek", "30:5A:3A": "ASUSTek", "30:85:A9": "ASUSTek",

    # --- D-Link ---
    "00:05:5D": "D-Link", "00:0D:88": "D-Link", "00:0F:3D": "D-Link",
    "00:11:95": "D-Link", "00:13:46": "D-Link", "00:15:E9": "D-Link",
    "00:17:9A": "D-Link", "00:18:E7": "D-Link", "00:19:5B": "D-Link",
    "00:1B:11": "D-Link", "00:1C:F0": "D-Link", "00:1D:7E": "D-Link",
    "00:1E:58": "D-Link", "00:22:B0": "D-Link", "00:24:01": "D-Link",
    "00:26:5A": "D-Link", "1C:7E:E5": "D-Link", "34:08:04": "D-Link",
    "C8:D3:A3": "D-Link",

    # --- TP-Link ---
    "00:27:19": "TP-Link", "14:CC:20": "TP-Link", "50:C2:E8": "TP-Link",
    "94:0C:6D": "TP-Link", "AC:84:C6": "TP-Link", "C0:25:E9": "TP-Link",
    "30:B5:C2": "TP-Link", "A4:2B:B0": "TP-Link", "D8:07:B6": "TP-Link",
    "54:C8:0F": "TP-Link", "24:69:68": "TP-Link", "98:DA:C4": "TP-Link",
    "60:32:B1": "TP-Link", "84:16:F9": "TP-Link", "14:75:90": "TP-Link",

    # --- Netgear ---
    "00:09:5B": "Netgear", "00:0F:B5": "Netgear", "00:1B:2F": "Netgear",
    "00:1E:2A": "Netgear", "00:1F:33": "Netgear", "00:22:3F": "Netgear",
    "00:24:B2": "Netgear", "00:26:F2": "Netgear", "00:18:4D": "Netgear",
    "00:1A:23": "Netgear", "20:4E:7F": "Netgear", "9C:3D:CF": "Netgear",
    "A0:40:A0": "Netgear", "B0:48:7A": "Netgear", "C0:3F:0E": "Netgear",
    "CC:40:85": "Netgear", "E0:46:9A": "Netgear", "E4:F4:C6": "Netgear",

    # --- Huawei ---
    "00:18:82": "Huawei", "00:1E:10": "Huawei", "00:25:9E": "Huawei",
    "00:9A:CD": "Huawei", "04:F9:38": "Huawei", "08:19:A6": "Huawei",
    "08:63:61": "Huawei", "0C:37:DC": "Huawei", "10:1B:54": "Huawei",
    "14:B9:68": "Huawei", "18:C5:8A": "Huawei", "20:08:ED": "Huawei",
    "24:09:95": "Huawei", "28:6E:D4": "Huawei", "30:74:96": "Huawei",
    "34:6B:D3": "Huawei", "40:4E:36": "Huawei", "44:6D:6C": "Huawei",
    "48:46:FB": "Huawei", "4C:1F:CC": "Huawei", "50:01:BB": "Huawei",
    "54:A5:1B": "Huawei", "58:60:5F": "Huawei", "5C:B3:95": "Huawei",
    "64:16:F0": "Huawei", "68:A0:F6": "Huawei", "6C:B7:49": "Huawei",
    "70:72:3C": "Huawei", "78:1D:BA": "Huawei", "7C:A2:3E": "Huawei",
    "80:FB:06": "Huawei", "84:46:FE": "Huawei", "88:40:B3": "Huawei",
    "8C:BE:BE": "Huawei", "90:17:AC": "Huawei", "94:04:9C": "Huawei",
    "98:E7:F5": "Huawei", "9C:28:EF": "Huawei", "A4:99:47": "Huawei",
    "B4:30:52": "Huawei", "E8:BD:D1": "Huawei", "F4:63:1F": "Huawei",
    "F8:01:13": "Huawei", "FC:48:EF": "Huawei",

    # --- Xiaomi ---
    "00:9E:C8": "Xiaomi", "04:CF:8C": "Xiaomi", "10:2A:B3": "Xiaomi",
    "18:59:36": "Xiaomi", "28:6C:07": "Xiaomi", "34:CE:00": "Xiaomi",
    "38:A4:ED": "Xiaomi", "3C:BD:D8": "Xiaomi", "40:31:3C": "Xiaomi",
    "44:23:7C": "Xiaomi", "4C:49:E3": "Xiaomi", "50:8F:4C": "Xiaomi",
    "58:44:98": "Xiaomi", "64:09:80": "Xiaomi", "74:23:44": "Xiaomi",
    "78:02:F8": "Xiaomi", "7C:1D:D9": "Xiaomi", "84:F3:EB": "Xiaomi",
    "88:C3:97": "Xiaomi", "98:FA:E3": "Xiaomi", "9C:99:A0": "Xiaomi",
    "A4:77:33": "Xiaomi", "AC:C1:EE": "Xiaomi", "B0:E2:35": "Xiaomi",
    "D4:97:0B": "Xiaomi", "E4:46:DA": "Xiaomi", "EC:D0:9F": "Xiaomi",
    "F0:B4:29": "Xiaomi", "F4:F5:D8": "Xiaomi", "F8:A4:5F": "Xiaomi",
    "FC:64:BA": "Xiaomi",

    # --- Samsung (representative subset) ---
    "00:12:47": "Samsung", "00:16:32": "Samsung", "00:1B:98": "Samsung",
    "00:1D:25": "Samsung", "00:1E:E2": "Samsung", "00:21:19": "Samsung",
    "00:21:4C": "Samsung", "00:23:39": "Samsung", "00:23:99": "Samsung",
    "00:24:54": "Samsung", "00:26:37": "Samsung", "10:68:3F": "Samsung",
    "14:49:E0": "Samsung", "1C:62:0C": "Samsung", "24:DB:ED": "Samsung",
    "28:98:13": "Samsung", "2C:AE:2B": "Samsung", "30:96:FB": "Samsung",
    "34:23:BA": "Samsung", "38:01:67": "Samsung", "3C:5A:B4": "Samsung",
    "40:0E:85": "Samsung", "4C:BC:A5": "Samsung", "50:CC:F8": "Samsung",
    "54:92:BE": "Samsung", "5C:0A:5B": "Samsung", "6C:F3:73": "Samsung",
    "70:F9:27": "Samsung", "78:25:AD": "Samsung", "84:55:A5": "Samsung",
    "8C:77:12": "Samsung", "90:18:7C": "Samsung", "94:35:0A": "Samsung",
    "98:0C:82": "Samsung", "9C:02:98": "Samsung", "A4:07:B6": "Samsung",
    "A8:06:00": "Samsung", "AC:36:13": "Samsung", "B0:72:BF": "Samsung",
    "B4:3A:28": "Samsung", "BC:72:B1": "Samsung", "C4:42:02": "Samsung",
    "C8:BA:94": "Samsung", "D0:22:BE": "Samsung", "D8:90:E8": "Samsung",
    "DC:71:44": "Samsung", "E8:50:8B": "Samsung", "F0:25:B7": "Samsung",
    "F4:7B:5E": "Samsung", "F8:04:2E": "Samsung", "FC:A1:3E": "Samsung",

    # --- Ubiquiti / MikroTik / Aruba / Fortinet / Zyxel ---
    "00:27:22": "Ubiquiti", "04:18:D6": "Ubiquiti", "24:5A:4C": "Ubiquiti",
    "24:A4:3C": "Ubiquiti", "44:D9:E7": "Ubiquiti", "68:D7:9A": "Ubiquiti",
    "74:AC:B9": "Ubiquiti", "78:8A:20": "Ubiquiti", "80:2A:A8": "Ubiquiti",
    "DC:9F:DB": "Ubiquiti", "E0:63:DA": "Ubiquiti", "F0:9F:C2": "Ubiquiti",
    "00:0C:42": "MikroTik", "2C:C8:1B": "MikroTik", "48:8F:5A": "MikroTik",
    "64:D1:54": "MikroTik", "B8:69:F4": "MikroTik", "CC:2D:E0": "MikroTik",
    "D4:CA:6D": "MikroTik", "E4:8D:8C": "MikroTik",
    "00:0B:86": "Aruba", "00:1A:1E": "Aruba", "24:DE:C6": "Aruba",
    "00:09:0F": "Fortinet", "70:4C:A5": "Fortinet",
    "00:19:CB": "Zyxel", "5C:F4:AB": "Zyxel",

    # --- Linksys / APC ---
    "00:06:25": "Linksys", "00:0C:41": "Linksys", "00:14:BF": "Linksys",
    "00:16:B6": "Linksys", "00:21:29": "Linksys", "00:C0:B7": "APC/Schneider",

    # --- NAS / servers ---
    "90:09:D0": "Synology", "24:5E:BE": "QNAP",
    "00:25:90": "Supermicro", "0C:C4:7A": "Supermicro",

    # --- Printers / office ---
    "00:11:32": "Brother", "00:1B:A9": "Brother", "00:80:77": "Brother",
    "00:00:85": "Canon", "00:00:48": "Xerox", "00:80:91": "Xerox",

    # --- Smart home / IoT / streaming ---
    "40:B4:CD": "Amazon", "44:65:0D": "Amazon", "6C:56:97": "Amazon",
    "74:C2:46": "Amazon", "78:E1:03": "Amazon", "84:D6:D0": "Amazon",
    "A0:02:DC": "Amazon", "AC:63:BE": "Amazon",
    "00:1A:11": "Google", "54:60:09": "Google", "F4:F5:E8": "Google",
    "CC:6D:A0": "Roku",
    "24:0A:C4": "Espressif (ESP32/8266)", "24:6F:28": "Espressif (ESP32/8266)",
    "30:AE:A4": "Espressif (ESP32/8266)", "5C:CF:7F": "Espressif (ESP32/8266)",
    "A4:CF:12": "Espressif (ESP32/8266)", "BC:DD:C2": "Espressif (ESP32/8266)",
    "EC:FA:BC": "Espressif (ESP32/8266)", "3C:71:BF": "Espressif (ESP32/8266)",
    "84:CC:A8": "Espressif (ESP32/8266)",

    # --- Raspberry Pi ---
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi", "D8:3A:DD": "Raspberry Pi",
    "2C:CF:67": "Raspberry Pi",

    # --- Sony / LG ---
    "00:01:4A": "Sony", "00:04:1F": "Sony", "00:13:A9": "Sony",
    "00:19:63": "Sony", "00:1A:80": "Sony", "00:1D:BA": "Sony",
    "30:F9:ED": "Sony", "00:1E:75": "LG", "C4:54:44": "LG",

    # --- Atheros / Qualcomm ---
    "00:0B:6B": "Atheros",

    # --- MediaTek / Ralink (Wi-Fi NICs, routers) ---
    "00:0C:E7": "MediaTek", "4C:23:38": "MediaTek", "40:3F:8C": "TP-Link",
    "0C:F2:D6": "MediaTek", "A8:5E:45": "MediaTek", "C0:25:5D": "Ralink",

    # --- IP cameras ---
    "44:19:B6": "Hikvision", "44:47:CC": "Hikvision", "4C:BD:8F": "Hikvision",
    "C0:56:E3": "Hikvision", "BC:AD:28": "Hikvision",
    "3C:EF:8C": "Dahua", "90:02:A9": "Dahua",

    # --- Gigabyte ---
    "50:E5:49": "Gigabyte", "94:DE:80": "Gigabyte",
}

RANDOMIZED_VENDOR = "Randomized (locally administered)"

_OUI_RE = re.compile(r"^([0-9A-Fa-f]{2})[:\-.\s]?([0-9A-Fa-f]{2})[:\-.\s]?([0-9A-Fa-f]{2})")

_oui_txt_loaded = False


def _try_load_oui_txt() -> None:
    """Optionally merge a full IEEE oui.txt placed next to the app.

    Never fatal: if the file is missing or malformed we just keep the
    embedded DB.
    """
    global _oui_txt_loaded
    if _oui_txt_loaded:
        return
    _oui_txt_loaded = True
    here = os.path.dirname(os.path.abspath(__file__))
    for base in (os.path.dirname(here), here, os.getcwd()):
        path = os.path.join(base, "oui.txt")
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = re.match(r"^\s*([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$", line)
                    if m:
                        prefix = f"{m.group(1)}:{m.group(2)}:{m.group(3)}".upper()
                        vendor = m.group(4).strip()
                        if vendor:
                            OUI_DB.setdefault(prefix, vendor)
        except OSError:
            pass
        break


def normalize_mac(mac: str) -> str:
    """Any common MAC format -> uppercase colon-separated."""
    if not mac:
        return ""
    hexdigits = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(hexdigits) != 12:
        return mac.strip().upper()
    return ":".join(hexdigits[i : i + 2] for i in range(0, 12, 2)).upper()


def _is_locally_administered(mac: str) -> bool:
    """IEEE: bit 1 of first octet set => locally administered."""
    try:
        first_octet = int(mac[:2], 16)
        return bool(first_octet & 0b10)
    except ValueError:
        return False


def lookup_vendor(mac: str) -> str:
    """MAC -> vendor string ('' if unknown and not locally administered)."""
    if not mac:
        return ""
    _try_load_oui_txt()
    norm = normalize_mac(mac)
    prefix = norm[:8].upper()
    vendor = OUI_DB.get(prefix)
    if vendor:
        return vendor
    if _is_locally_administered(prefix):
        return RANDOMIZED_VENDOR
    return ""
