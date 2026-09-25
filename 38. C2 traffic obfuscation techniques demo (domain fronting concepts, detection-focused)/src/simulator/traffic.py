"""TrafficGen — fabricates the full synthetic traffic picture for a scenario.

Everything is generated from a seeded PRNG (deterministic across runs). No
packets are sent; the output is a list of FlowRecords plus a written PCAP.

Cohort design (matters for detector quality):
- Each client gets an IP-layer cohort (TTL + IP-ID stride) — feeds D8.
- Each client role gets a TLS fingerprint: workstations share the allow-listed
  browser JA3, implants/ransomware carry their own family JA3 — feeds D2/D3/D8
  scoping so benign rhythm never trips per-host detectors.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from src.simulator import encoders
from src.simulator.flows import App, FlowRecord
from src.simulator.pcap import PcapInfo, write_pcap
from src.simulator.scenario import (
    BENIGN_DOMAINS,
    CDN_EDGES,
    CLIENT_IPS,
    DGA_SEED_DOMAINS,
    FRONT_DOMAINS,
    NTP_DOMAINS,
    ORIGIN_IPS,
    RANSOMWARE_DOMAINS,
    RESOLVER_IP,
    BROWSER_JA3,
    ScenarioConfig,
)

BENIGN_PATHS = ["/", "/index.html", "/assets/app.css", "/api/v1/me", "/search?q=meeting+notes"]
C2_URI_BASE = "/api/v1/telemetry"
EXFIL_MARKER = "X47"          # didactic placeholder payload marker (S2)
NTP_PERIOD = 1024.0           # classic NTP polling cadence — a benign rhythm decoy

JA3_BROWSER = BROWSER_JA3  # allow-listed in the detection engine (single source)
JA3_RANSOM = "ransom-family-tls"


@dataclass
class SimulationResult:
    flows: list[FlowRecord]
    pcap: PcapInfo
    scenario: ScenarioConfig
    seed: int


def _cohort(rng: random.Random) -> dict:
    """Per-client IP-layer fingerprint (same generator ⇒ same TTL/id stride — D8)."""
    return {"ttl": 126 + rng.choice([0, 1, 2]), "id_stride": rng.choice([3, 5, 7])}


class TrafficGen:
    def __init__(self, cfg: ScenarioConfig, seed: int = 1337):
        self.cfg = cfg
        self.rng = random.Random(seed)
        self.seed = seed
        self._ip_id = 1000

    # ------------------------------------------------------------------ utils
    def _next_ip_id(self, stride: int) -> int:
        self._ip_id += stride
        return self._ip_id & 0xFFFF

    def _dns_flow(self, ts: float, src: str, qname: str, answer: str, cohort: dict) -> FlowRecord:
        return FlowRecord(
            ts=ts, src=src, dst=RESOLVER_IP, sport=40000 + self.rng.randint(0, 20000),
            dport=53, proto="udp", app=App.DNS,
            ttl=cohort["ttl"], ip_id=self._next_ip_id(cohort["id_stride"]),
            host=qname, family="dns", note=f"DNS A {qname} -> {answer}",
        )

    # ------------------------------------------------------------- campaigns
    def _campaign_callback(self, ts: float, src: str, cohort: dict, i: int) -> FlowRecord:
        """Domain-fronting style callback: SNI=front (benign-looking), Host=origin."""
        rng = self.rng
        front = rng.choice(FRONT_DOMAINS)
        origin = rng.choice(ORIGIN_IPS)
        edge = rng.choice(CDN_EDGES)

        uri = C2_URI_BASE
        layers: list[str] = []
        method = "GET"
        if i % self.cfg.exfil_every_n == 0:
            # Long, layered-encoded "exfil" query → D7 fires; shape lesson for D4.
            payload = (EXFIL_MARKER * 40).encode() + bytes(rng.randrange(256) for _ in range(160))
            encoded, layers = encoders.layered_encode(payload, list(self.cfg.encoding_layers))
            uri = f"{C2_URI_BASE}/up?d={encoded.decode('latin-1')}"
            method = "POST"

        return FlowRecord(
            ts=ts, src=src, dst=edge, sport=45000 + rng.randint(0, 20000), dport=443,
            proto="tcp", app=App.HTTP,
            ttl=57, ip_id=self._next_ip_id(cohort["id_stride"]),   # implant stack TTL → D8 cohort
            sni=front,                 # sensor-visible: benign front domain
            host=origin,               # CDN-visible: concealed origin (the disjunction)
            uri=uri, method=method, status=200, body=b"ok" if method == "GET" else b"accepted",
            ja3=self.cfg.campaign_ja3, ja3s="c2-origin-tls",
            encoding_layers=layers, family="campaign",
            note=f"fronting: SNI={front} Host={origin}",
        )

    def _ransomware_checkin(self, ts: float, src: str, cohort: dict) -> FlowRecord:
        """Periodic high-entropy check-in — NO fronting (separates D2/D4 from D1)."""
        rng = self.rng
        dom = rng.choice(RANSOMWARE_DOMAINS)
        payload = bytes(rng.randrange(256) for _ in range(1024))  # high-entropy body (D4) — 1KiB keeps sample entropy ≈7.8, safely over threshold
        return FlowRecord(
            ts=ts, src=src, dst=rng.choice(CDN_EDGES), sport=46000 + rng.randint(0, 20000),
            dport=443, proto="tcp", app=App.HTTP,
            ttl=59, ip_id=self._next_ip_id(cohort["id_stride"]),   # ransom stack TTL → D8 cohort
            sni=dom, host=dom, uri=f"/gate?id={rng.randrange(10**9):09d}",
            method="POST", status=200, body=payload,
            ja3=JA3_RANSOM, ja3s="ransom-origin-tls",
            encoding_layers=[], family="ransomware",
            note="periodic high-entropy check-in (no fronting)",
        )

    # ---------------------------------------------------------------- decoys
    def _benign_flow(self, ts: float, src: str, cohort: dict) -> FlowRecord:
        rng = self.rng
        dom = rng.choice(BENIGN_DOMAINS)
        return FlowRecord(
            ts=ts, src=src, dst=rng.choice(CDN_EDGES), sport=47000 + rng.randint(0, 20000),
            dport=443, proto="tcp", app=App.HTTP,
            ttl=cohort["ttl"], ip_id=self._next_ip_id(cohort["id_stride"]),
            sni=dom, host=dom, uri=rng.choice(BENIGN_PATHS),
            method="GET", status=200, body=b"<html>fine</html>",
            ja3=JA3_BROWSER, ja3s="cdn-default-tls",
            encoding_layers=[], family="benign",
            note="normal user browsing (SNI == Host)",
        )

    def _ntp_flow(self, ts: float, src: str, cohort: dict) -> FlowRecord:
        return FlowRecord(
            ts=ts, src=src, dst=RESOLVER_IP, sport=123, dport=123, proto="udp", app=App.NTP,
            ttl=cohort["ttl"], ip_id=self._next_ip_id(cohort["id_stride"]),
            host=self.rng.choice(NTP_DOMAINS), family="ntp",
            note="benign periodic NTP sync (rhythm decoy for D2/D9)",
        )

    def _dga_decoy_flow(self, ts: float, src: str, cohort: dict) -> FlowRecord:
        return FlowRecord(
            ts=ts, src=src, dst=RESOLVER_IP, sport=41000 + self.rng.randint(0, 20000),
            dport=53, proto="udp", app=App.DNS,
            ttl=cohort["ttl"], ip_id=self._next_ip_id(cohort["id_stride"]),
            host=self.rng.choice(DGA_SEED_DOMAINS), family="dga_decoy",
            note="DGA-like NXDOMAIN probe decoy (noise, not the campaign)",
        )

    # ------------------------------------------------------------------ main
    def run(self) -> SimulationResult:
        cfg, rng = self.cfg, self.rng
        flows: list[FlowRecord] = []
        end = cfg.duration_seconds

        clients = rng.sample(CLIENT_IPS, k=min(8, len(CLIENT_IPS)))
        cohorts = {c: _cohort(rng) for c in clients}
        implants = set(clients[: cfg.n_campaign_clients])
        ransom_hosts = set(clients[:2]) if cfg.include_ransomware else set()
        dga_client = clients[-1] if cfg.include_dga_decoy and clients[-1] not in implants else None

        events: list[tuple[float, FlowRecord]] = []

        # Campaign callbacks with jittered beacon cadence.
        for client in sorted(implants):
            t = rng.uniform(0, 30)
            i = 0
            while t < end and i < cfg.n_callbacks_per_client:
                events.append((t, self._campaign_callback(t, client, cohorts[client], i)))
                t += max(1.0, rng.gauss(cfg.beacon_period, cfg.jitter_sigma))
                i += 1

        # Ransomware check-ins (no fronting) from their own hosts.
        for client in sorted(ransom_hosts):
            t = rng.uniform(0, 60)
            n = 0
            while t < end and n < 60:   # bounded: enough for periodicity stats
                events.append((t, self._ransomware_checkin(t, client, cohorts[client])))
                t += max(5.0, rng.gauss(cfg.beacon_period, cfg.jitter_sigma))
                n += 1

        # Benign browsing: every client every ~2–6 min.
        if cfg.include_benign:
            for client in clients:
                t = rng.uniform(0, 60)
                while t < end:
                    events.append((t, self._benign_flow(t, client, cohorts[client])))
                    t += max(10.0, rng.gauss(240, 90))

        # Benign NTP: strict periodicity — the "rhythm is not proof" decoy (D9).
        if cfg.include_ntp:
            for client in clients:
                t = rng.uniform(0, NTP_PERIOD)
                while t < end:
                    events.append((t, self._ntp_flow(t, client, cohorts[client])))
                    t += NTP_PERIOD

        # DGA noise burst from a workstation (never from an implant).
        if dga_client:
            t0 = rng.uniform(0, end / 2)
            for _ in range(40):
                events.append((t0, self._dga_decoy_flow(t0, dga_client, cohorts[dga_client])))
                t0 += rng.uniform(0.4, 2.0)

        # One DNS resolution per distinct hostname, before the traffic.
        seen: dict[str, str] = {}
        for _, fl in events:
            host = fl.host or fl.sni
            if host and host not in seen:
                seen[host] = fl.dst
        for n, (host, dst) in enumerate(sorted(seen.items())):
            src = clients[n % len(clients)]
            flows.append(self._dns_flow(0.5 + n * 0.05, src, host, dst, cohorts[src]))

        flows.extend(fl for _, fl in events)
        flows.sort(key=lambda f: f.ts)

        pcap = write_pcap(f"artifacts/c2_demo_{cfg.name}_{self.seed}.pcap", flows)
        return SimulationResult(flows=flows, pcap=pcap, scenario=cfg, seed=self.seed)
