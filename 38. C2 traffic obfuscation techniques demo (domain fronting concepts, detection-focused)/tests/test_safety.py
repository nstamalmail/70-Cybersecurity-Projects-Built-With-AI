"""Safety guard: the project must contain zero network-capable imports (S1)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.safety import scan_for_network_imports
from src.simulator.scenario import (
    CLIENT_IPS, CDN_EDGES, ORIGIN_IPS, RESOLVER_IP,
    BENIGN_DOMAINS, C2_DOMAINS, DGA_SEED_DOMAINS, FRONT_DOMAINS,
    NTP_DOMAINS, RANSOMWARE_DOMAINS,
    is_documentation_ip, is_reserved_domain,
)


def test_no_network_imports_anywhere():
    violations = scan_for_network_imports()
    assert violations == [], f"network-capable imports found: {violations}"


def test_every_hardcoded_ip_is_documentation_range():
    ips = [*CLIENT_IPS, *CDN_EDGES, *ORIGIN_IPS, RESOLVER_IP]
    assert ips, "IP pools must not be empty"
    for ip in ips:
        assert is_documentation_ip(ip), f"{ip} is outside RFC 5737 ranges (S4)"


def test_every_hardcoded_domain_is_reserved():
    domains = [*FRONT_DOMAINS, *C2_DOMAINS, *BENIGN_DOMAINS,
               *NTP_DOMAINS, *RANSOMWARE_DOMAINS, *DGA_SEED_DOMAINS]
    assert domains, "domain pools must not be empty"
    for d in domains:
        assert is_reserved_domain(d), f"{d} is not a reserved/example domain (S5)"


def test_public_ips_and_domains_rejected():
    assert not is_documentation_ip("8.8.8.8")
    assert not is_documentation_ip("93.184.216.34")
    assert not is_reserved_domain("evil.com")
    assert not is_reserved_domain("malware-download.net")
