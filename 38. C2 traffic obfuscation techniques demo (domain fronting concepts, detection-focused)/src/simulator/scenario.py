"""Scenario registry: named, seedable simulation profiles.

All addresses and domains come from the reserved pools below (architecture §0.1,
constraints S4/S5). Nothing here can reach the internet: documentation-only IP
ranges and reserved-TLD domains are hard-coded.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------- S4: IPs ----
# RFC 5737 documentation ranges only.
CLIENT_POOL = "192.0.2.0/24"      # office clients
INFRA_POOL = "198.51.100.0/24"    # CDN edges + DNS resolver
ORIGIN_POOL = "203.0.113.0/24"    # concealed origins (never contacted directly)

RESOLVER_IP = "198.51.100.53"
CDN_EDGES = ["198.51.100.10", "198.51.100.11", "198.51.100.12", "198.51.100.13"]
ORIGIN_IPS = [                    # concealed origins — never contacted directly
    "203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13", "203.0.113.14",
]
CLIENT_IPS = [f"192.0.2.{n}" for n in range(11, 31)]   # 20 office clients

DOC_IP_RE = re.compile(
    r"^(192\.0\.2\.\d{1,3}|198\.51\.100\.\d{1,3}|203\.0\.113\.\d{1,3})$"
)


def is_documentation_ip(ip: str) -> bool:
    """True if ip is inside an RFC 5737 documentation range (S4)."""
    return bool(DOC_IP_RE.match(ip))


# ------------------------------------------------------------- S5: domains ----
FRONT_DOMAINS = [
    "assets.example",
    "cdn.example",
    "static.example",
    "updates.example",
    "api.example",
]
C2_DOMAINS = [
    "q7x2k9p4v1m3.example",
    "z8w3j2n5b6c1.example",
    "m4p8r2t7x5k0.example",
    "v1n6c4h9s3d7.example",
]
BENIGN_DOMAINS = [
    "portal.example",
    "mail.example",
    "docs.example",
    "intranet.example",
    "search.example",
    "news.invalid",
    "wiki.example",
]
NTP_DOMAINS = ["time.example", "ntp.example"]
RANSOMWARE_DOMAINS = ["checkin.example", "gatekeeper.example"]

# The allow-listed workstation TLS fingerprint (single source of truth for the
# generator and the detection engine's D3/D8 baseline).
BROWSER_JA3 = "browser-chrome-stable"
DGA_SEED_DOMAINS = [                  # 20-24 char labels — Conficker-style length
    "bv7xk2qmzp41tn9w3jfx8c2d.invalid",
    "k4pr82tmxq50z1n6hc4vs3d7.invalid",
    "p9q2wk5m8zx1j3f7dx4nb6c2h5t.invalid",
    "w2r6y3u8o1e5q0s4a7d9g2h5j.invalid",
]

RESERVED_DOMAIN_RE = re.compile(
    r"^([a-z0-9-]+\.)*(example|invalid|test|example\.com|example\.net|example\.org)$"
)


def is_reserved_domain(domain: str) -> bool:
    """True if domain uses a reserved TLD / example name (S5)."""
    return bool(RESERVED_DOMAIN_RE.match(domain))


# ------------------------------------------------------------- scenarios ------
@dataclass(frozen=True)
class ScenarioConfig:
    name: str
    label: str
    description: str
    duration_seconds: int = 8 * 3600
    beacon_period: float = 60.0          # seconds between callbacks
    jitter_sigma: float = 3.0            # std-dev of jitter (tight beacon)
    encoding_layers: tuple[str, ...] = ("base64",)
    n_campaign_clients: int = 3
    n_callbacks_per_client: int = 30
    exfil_every_n: int = 7               # every Nth callback carries a long encoded URI (D7)
    include_benign: bool = True
    include_ntp: bool = True
    include_ransomware: bool = False
    include_dga_decoy: bool = False
    campaign_ja3: str = "c2-fronting-fingerprint-1"


SCENARIOS: dict[str, ScenarioConfig] = {
    "c2_domain_fronting": ScenarioConfig(
        name="c2_domain_fronting",
        label="C2 — Domain Fronting (core demo)",
        description=(
            "Clients beacon to CDN edges with SNI=front domain but Host=concealed "
            "origin. Benign browsing and NTP decoys included for contrast."
        ),
    ),
    "c2_dga": ScenarioConfig(
        name="c2_dga",
        label="C2 — DGA + Fronting mix",
        description=(
            "Fronting callbacks mixed with algorithmic .invalid domains and a "
            "DGA noise burst — stresses D5/D6 and shows decoy discrimination."
        ),
        include_dga_decoy=True,
        beacon_period=45.0,
        jitter_sigma=6.0,
        encoding_layers=("base64", "xor"),
    ),
    "ransomware_checkin": ScenarioConfig(
        name="ransomware_checkin",
        label="Ransomware check-in (decoy stress)",
        description=(
            "No fronting: a periodic high-entropy check-in plus benign traffic. "
            "Separates D2/D4/D9 — periodicity alone is not enough."
        ),
        include_ransomware=True,
        n_campaign_clients=0,
        beacon_period=120.0,
        jitter_sigma=1.0,
        encoding_layers=("xor",),
    ),
    "benign_only": ScenarioConfig(
        name="benign_only",
        label="Benign only (negative control)",
        description=(
            "Office browsing plus NTP sync. Every detector should stay quiet — "
            "use this to validate thresholds."
        ),
        n_campaign_clients=0,
    ),
}


def get_scenario(name: str) -> ScenarioConfig:
    return SCENARIOS[name]
