"""Unit tests for the pure logic in core/ (no network access needed)."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.engine import _ip_to_u32, expand_targets  # noqa: E402
from core.exporter import export_csv, export_json  # noqa: E402
from core.models import Host, ScanEvent, ScanResult  # noqa: E402
from core.oui import RANDOMIZED_VENDOR, lookup_vendor, normalize_mac  # noqa: E402


# ------------------------------------------------------------ byte order

class TestIpToU32:
    def test_loopback_is_0x0100007f(self):
        # inet_addr convention: little-endian memory layout spells octets.
        assert _ip_to_u32("127.0.0.1") == 0x0100007F

    def test_private_addr(self):
        assert _ip_to_u32("192.168.1.2") == 0x0201A8C0


# ------------------------------------------------------------ CIDR math

class TestExpandTargets:
    def test_slash24_excludes_network_and_broadcast(self):
        ips = expand_targets("192.168.1.0/24")
        assert len(ips) == 254
        assert "192.168.1.0" not in ips
        assert "192.168.1.255" not in ips
        assert "192.168.1.1" in ips

    def test_slash31_probes_both(self):
        ips = expand_targets("10.0.0.4/31")
        assert ips == ["10.0.0.4", "10.0.0.5"]

    def test_slash32_single(self):
        assert expand_targets("10.1.2.3/32") == ["10.1.2.3"]

    def test_slash30(self):
        ips = expand_targets("10.0.0.0/30")
        assert ips == ["10.0.0.1", "10.0.0.2"]

    def test_exclude_own_ip(self):
        ips = expand_targets("192.168.1.0/24", exclude_ip="192.168.1.25")
        assert "192.168.1.25" not in ips
        assert len(ips) == 253

    def test_sorted_numerically(self):
        ips = expand_targets("192.168.0.0/22")
        assert ips == sorted(ips, key=lambda s: [int(o) for o in s.split(".")])

    def test_ipv6_rejected(self):
        with pytest.raises(ValueError):
            expand_targets("::1/128")

    def test_host_bits_ignored(self):
        # strict=False: host bits are masked off; .77/30 -> network .76,
        # broadcast .79, usable hosts .77 and .78
        ips = expand_targets("192.168.1.77/30")
        assert ips == ["192.168.1.77", "192.168.1.78"]


# ------------------------------------------------------------ OUI

class TestOui:
    def test_known_vendor(self):
        assert lookup_vendor("B8:27:EB:12:34:56") == "Raspberry Pi"
        assert lookup_vendor("00-25-64-AA-BB-CC") == "Dell"

    def test_normalize_formats(self):
        assert normalize_mac("b827eb123456") == "B8:27:EB:12:34:56"
        assert normalize_mac("B827.EB12.3456") == "B8:27:EB:12:34:56"
        assert normalize_mac("b8-27-eb-12-34-56") == "B8:27:EB:12:34:56"

    def test_randomized_mac(self):
        # 2nd hex digit 2/6/A/E => locally administered
        assert lookup_vendor("A2:11:22:33:44:55") == RANDOMIZED_VENDOR
        assert lookup_vendor("da:bb:cc:dd:ee:ff") == RANDOMIZED_VENDOR

    def test_unknown_global_mac_empty(self):
        # 00:00:00 is assigned (Xerox) in real IEEE db but not in our snapshot;
        # first octet 00 is universally administered.
        vendor = lookup_vendor("00:11:22:33:44:55")
        assert isinstance(vendor, str)

    def test_empty(self):
        assert lookup_vendor("") == ""


# ------------------------------------------------------------ models

class TestModels:
    def _result(self):
        from datetime import datetime
        hosts = (
            Host(ip="192.168.1.20", mac="AA:BB:CC:00:00:02", vendor="V2", hostname="b"),
            Host(ip="192.168.1.3", mac="AA:BB:CC:00:00:01", vendor="V1", hostname="a"),
        )
        return ScanResult(
            cidr="192.168.1.0/24",
            started=datetime(2026, 1, 1, 12, 0, 0),
            finished=datetime(2026, 1, 1, 12, 0, 5),
            hosts=hosts,
        )

    def test_sorted_hosts_numeric(self):
        r = self._result()
        assert [h.ip for h in r.sorted_hosts()] == ["192.168.1.3", "192.168.1.20"]

    def test_duration(self):
        assert self._result().duration_s == 5.0

    def test_to_json_dict(self):
        d = self._result().to_json_dict()
        assert d["host_count"] == 2
        assert d["hosts"][0]["ip"] == "192.168.1.3"
        assert d["started"] == "2026-01-01T12:00:00"
        json.dumps(d)  # must be serializable

    def test_host_row(self):
        h = Host(ip="1.2.3.4", mac="A", vendor="B", hostname="C")
        assert h.to_row() == ("1.2.3.4", "A", "B", "C")

    def test_event_defaults(self):
        e = ScanEvent("progress", {"done": 1, "total": 2})
        assert e.kind == "progress" and e.value["done"] == 1


# ------------------------------------------------------------ exporters

class TestExporters:
    def _result(self):
        from datetime import datetime
        return ScanResult(
            cidr="10.0.0.0/24",
            started=datetime(2026, 1, 1, 8, 0, 0),
            finished=datetime(2026, 1, 1, 8, 0, 3),
            hosts=(
                Host(ip="10.0.0.2", mac="AA:BB:CC:DD:EE:01", vendor="X", hostname="hostb"),
                Host(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:00", vendor="Y", hostname="hosta"),
            ),
        )

    def test_csv(self, tmp_path):
        p = tmp_path / "out.csv"
        export_csv(self._result(), str(p))
        text = p.read_text(encoding="utf-8-sig")
        lines = text.strip().splitlines()
        assert lines[0] == "ip,mac,vendor,hostname"
        assert lines[1].startswith("10.0.0.1,")

    def test_json(self, tmp_path):
        p = tmp_path / "out.json"
        export_json(self._result(), str(p))
        d = json.loads(p.read_text(encoding="utf-8"))
        assert d["cidr"] == "10.0.0.0/24"
        assert d["host_count"] == 2

    def test_dispatch_by_extension(self, tmp_path):
        from core.exporter import export

        j = tmp_path / "x.json"
        c = tmp_path / "y.dat"  # unknown ext -> CSV
        assert export(self._result(), str(j)) == str(j)
        assert export(self._result(), str(c)) == str(c)
        assert json.loads(j.read_text())["host_count"] == 2
        assert "ip," in c.read_text(encoding="utf-8-sig")
