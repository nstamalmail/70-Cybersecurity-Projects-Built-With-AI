# Architecture — C2 Traffic Obfuscation Techniques Demo (Detection-Focused)

**Version:** 1.0 · **Date:** 2026-09-09
**Type:** Off-Network, Synthetic-Data Training Workbench (Blue-Team)
**Owners:** Security Engineering Guild

---

## 0. Scope, Positioning, and Safety

This is a **detection-engineering training workbench**, not a C2 framework. It models how
campaigns *appear* to network sensors — including the shape of domain-fronting style traffic —
**entirely from synthetic data**, so defenders can build, tune, and validate detections safely.

### 0.1 Hard Safety Constraints (enforced in code)

| # | Constraint | Enforcement |
|---|------------|-------------|
| S1 | No outbound network I/O of any kind | No `socket`, `http`, `requests` imports anywhere in `src/` |
| S2 | No real C2 infrastructure or payloads | Only didactic placeholder strings (`X47`, `Qm9ubmll…`) |
| S3 | No real DNS/HTTP/ARP packet emission | PCAP records are bytes written straight to a local file |
| S4 | IPs must use documentation ranges | `RFC 5737` (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) + `RFC 3849` (2001:db8::/32) |
| S5 | Domains must use reserved TLDs / example names | `.example`, `.invalid`, plus canonical example.com/net/org |
| S6 | Big-picture integrity | Model *why defenders can see through* obfuscation — never improve offensive tradecraft |

The PCAP is a **byte-accurate frame layout** (Ethernet/IPv4/UDP/TCP + minimal DNS/HTTP headers)
suitable for Wireshark inspection on an isolated lab host. It is emitted to a local file only.

### 0.2 Legal / Ethical Framing

- Runs **fully offline** on the analyst's machine. Nothing is captured, sniffed, or transmitted.
- All traffic is *fabricated* from scenario definitions — no live interface is ever touched.
- Intended audience: detection engineers, SOC analysts, purple-team facilitators, students.

---

## 1. Goals and Non-Goals

### Goals
1. **Explain domain fronting concepts** — SNI/Host disjunction, TLS fingerprint normalization, camouflage trade-offs — via interactive simulation.
2. **Generate safe synthetic evidence**: PCAP, Zeek-style `conn.log`, Suricata-style `eve.json`, CSV flows.
3. **Ship 9 high-signal detections** (D1–D9) with transparent, inspectable logic and tunable thresholds.
4. **Visualize** both attacker-side encoding/layering and defender-side scoring/analytics.
5. **Distribute as a portable Windows `.exe`** (no Python install required) via PyInstaller.

### Non-Goals
- ❌ Operating, configuring, or connecting to real C2 channels.
- ❌ Emulating malware families, EDR evasion, or process injection.
- ❌ Live packet capture from any network interface.
- ❌ Guidance that materially improves offensive operational security.

---

## 2. System Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                            app.py (entrypoint)                           │
│            argparse: --self-test · --smoke · --version · --windowed      │
└───────────────┬──────────────────────────────────────────────────────────┘
                │
                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                       SIMULATOR ENGINE (pure Python)                     │
│                                                                          │
│  Scenario ──► TrafficGen ──► PcapWriter ──► artifacts/                   │
│                  │                                                       │
│                  ├──► FlowBuilder ──► ZeekLog · EveJSON · CSV            │
│                  └──► DecoyPool (noise/DGA/beacon/Ransomware)            │
│                                                                          │
│  Encoders: XOR · ROT13 · Base64 · multi-layer (layered ring markers)     │
│  Jitter:   deterministic PRNG (seeded) + jitter profile per scenario     │
│  Beacon:   periodic / jittered / dga-mixed                               │
└───────────────┬──────────────────────────────────────────────────────────┘
                │ artifacts (in-memory flow objects + written files)
                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                        DETECTION ENGINE (pure Python)                    │
│                                                                          │
│  D1 SNI/Host mismatch        (domain-fronting core signal)               │
│  D2 Beacon periodicity       (arrival-time variance scoring)             │
│  D3 JA3-style TLS fingerprint cluster (client-hello byte hash)           │
│  D4 High-entropy egress body (per-window Shannon entropy)                │
│  D5 Long-domain / DGA heuristic (char-class entropy + length)            │
│  D6 Rare-SNI pivoting        (single-SNI to many destination IPs)        │
│  D7 Suspicious URI patterns  (long, encoded, odd extensions)             │
│  D8 TTL / IP-ID anomalies    (cohort fingerprint)                        │
│  D9 Decoy discriminators     (goodware vs malware bifurcation)           │
│                                                                          │
│  Verdicts: clean / suspicious / malicious + rule-hit explanation strings │
└───────────────┬──────────────────────────────────────────────────────────┘
                │
                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                          ZTN MODULE (pure Python)                        │
│  Verdicts: allow · verify · deny (safe state transitions, no network)    │
└───────────────┬──────────────────────────────────────────────────────────┘
                │
                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                        GUI LAYER (tkinter / ttk)                         │
│                                                                          │
│  Dashboard · Flows · TLS · Beacon · Detections · PCAP · ZTN · About      │
│  Matplotlib backend: TkAgg (stubbed gracefully if unavailable)           │
│  All long work dispatched to background threads; UI stays responsive.    │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Technology Choices

| Layer      | Choice | Rationale |
|------------|--------|-----------|
| Runtime    | Python ≥ 3.10 (target 3.12) | Stdlib tkinter ships with Windows python.org builds |
| GUI        | tkinter + ttk | Zero extra deps for the portable exe; native widgets |
| Charts     | matplotlib (TkAgg) **optional** | Graceful fallback to native canvas if missing |
| Crypto-ish | `hashlib`, `hmac`, `random` | Fingerprint hashing, deterministic simulation PRNG |
| PCAP       | Hand-rolled writer (`struct.pack`) | Exact control over frame bytes; no scapy dependency |
| Packaging  | PyInstaller `--onefile --windowed` | Single portable `.exe`, no console flash |
| Tests      | pytest (stdlib `unittest` fallback) | Fast CI + local verification |

**Determinism:** all randomness flows through `random.Random(seed)`; the same scenario +
seed always produces byte-identical artifacts and identical detection verdicts.

---

## 4. Module Design

### 4.1 `simulator/pcap.py` — PCAP Writer
- Global header: magic `0xa1b2c3d4`, version 2.4, snaplen 65535, LINKTYPE_ETHERNET.
- Per-packet: ts_sec/ts_usec/incl_len/orig_len then Ethernet II + IPv4 + (UDP|TCP).
- DNS-over-UDP/53 and minimal HTTP-over-TCP/80 request/response frames.
- Layered encoding simulation: payloads may be wrapped N times; wrapper count recorded
  per flow and surfaced as a detection hint (see D7).

### 4.2 `simulator/traffic.py` — TrafficGen + FlowBuilder
- `FlowRecord` dataclass: ts, src, dst, sport, dport, proto, sni, host, uri, method,
  status, bytes_up/down, duration, ttl, ip_id, ja3, ja3s, encoding_layers, family, verdict.
- Domains drawn **only** from the reserved pool (see §0.1 S5).
- Beacon cadence modeled with jitter profiles: `tight` (σ≈1s), `loose` (σ≈30s), `dga`.

### 4.3 `simulator/encoders.py` — Encoding Layers
- `xor_round(data, key)` · `rot13(s)` · `b64(data)` · `layered(data, rounds)`.
- Round-trip property tests: `decode(encode(x)) == x` for all codecs.

### 4.4 `simulator/decoys.py` — DecoyPool
- Injects benign background: normal browsing (example.com/news.invalid), CDN-ish flows,
  OS-update-like polling, plus adversarial decoys: DGA bursts, periodic-but-benign NTP,
  and a "ransomware-checkin" decoy to force D9 discrimination.

### 4.5 `detections/` — Rule Modules
Each rule is a pure function: `list[FlowRecord] -> list[Finding]`.

| ID  | Name | Core metric | Threshold default |
|-----|------|-------------|-------------------|
| D1  | SNI/Host mismatch | `sni != host` on same flow | any occurrence |
| D2  | Beacon periodicity | stdev(inter-arrival) / mean ≤ 0.15 | ≥ 8 flows/group |
| D3  | JA3 cluster | identical ja3 across > 3 dsts | > 3 destinations |
| D4  | High-entropy body | windowed Shannon entropy > 7.2 bits/byte | ≥ 2 windows |
| D5  | DGA heuristic | length ≥ 21 AND digit/letter entropy > 3.3 | score ≥ 3 |
| D6  | Rare-SNI pivot | one SNI → ≥ 4 distinct dst IPs | ≥ 4 |
| D7  | URI anomaly | len(uri) > 120 or layered encoders | any |
| D8  | TTL cohort | identical ttl+ip_id stride across dsts | ≥ 3 |
| D9  | Decoy discriminator | ransomware-checkin vs benign NTP bifurcation | verdict-level |

### 4.6 `ztn.py` — Zero-Trust Policy Stub
Maps aggregated findings → `allow | verify | deny` with a safe, offline state machine.
Produces an audit trail (JSON) demonstrating identity/device-aware gating concepts.

### 4.7 `scenario.py` — Scenario Registry
Named, seedable scenarios: `c2_domain_fronting`, `c2_dga`, `ransomware_checkin`,
`benign_only`. Each returns (TrafficGen config, DecoyPool config, label).

---

## 5. GUI Design (tkinter)

```
┌─────────────────────────────────────────────────────────────┐
│ C2 Obfuscation Detection Workbench                  [─][□][×]│
├──────────────┬──────────────────────────────────────────────┤
│ ▶ Run        │  [Dashboard][Flows][TLS][Beacon]             │
│ Scenario ▼   │  [Detections][PCAP][ZTN][About]              │
│ Seed  [1337] │──────────────────────────────────────────────│
│ ☑ Decoys     │  ┌ Notebook page content ─────────────────┐  │
│ Thresholds…  │  │ (tables, charts, verdict panels)       │  │
│              │  └────────────────────────────────────────┘  │
│ Status bar:  │                                              │
│ ● ready      ├──────────────────────────────────────────────┤
└──────────────┴──────────────────────────────────────────────┘
```

- **Left rail:** scenario selector, seed, decoy toggle, threshold editor, Run button,
  artifact export buttons, progress bar.
- **Dashboard:** verdict pie (malicious/suspicious/clean), top talkers, finding counts,
  scenario timeline strip.
- **Flows:** virtualized Treeview (10k+ rows via chunked insert), column sort, filter box.
- **TLS:** JA3/JA3S cluster table + client-hello hex preview (synthetic).
- **Beacon:** inter-arrival scatter + periodicity score per host.
- **Detections:** finding list with rule ID, severity, evidence string, "explain" pane.
- **PCAP:** export path, size, SHA-256, "open folder" button, frame count summary.
- **ZTN:** policy verdict table (allow/verify/deny) + audit JSON export.
- **Threading:** engine runs in a `threading.Thread`; UI updates via `queue` + `after()` polling.

---

## 6. Data Flow (one run)

1. User selects scenario + seed → clicks **Run**.
2. `TrafficGen` builds flows (campaign + decoys), all RFC5737/reserved-TLD.
3. `PcapWriter` writes `artifacts/c2_demo_<scenario>_<seed>.pcap`.
4. `FlowBuilder` emits zeek `conn.log`, suricata `eve.json`, `flows.csv`.
5. Detection rules score flows → `Finding` list.
6. `ZTN` maps findings → allow/verify/deny + audit JSON.
7. GUI notebook populates all tabs; status bar shows counts and artifact paths.

---

## 7. Testing Strategy

- **Unit:** encoder round-trips, PCAP header bytes, each D-rule with crafted flows
  (positive + negative cases), D9 decoy bifurcation.
- **Property:** encode/decode identity; pcap reader re-parses its own output.
- **Smoke:** `--smoke` runs the full pipeline headless and prints a summary (exit 0/1).
- **GUI:** instantiation test + tab-switch test on CI with Xvfb/xvfb-run where needed.

---

## 8. Packaging (Portable EXE)

```bash
pyinstaller --onefile --windowed --name C2DetectionWorkbench \
  --add-data "README.md;." \
  --collect-submodules matplotlib.backends.backend_tkagg \
  app.py
```

- `--windowed` suppresses console; `--onefile` gives a single portable binary.
- Windows Defender/SmartScreen may warn on unsigned exes — expected for demos.
- Verify: run `C2DetectionWorkbench.exe --smoke` → exit 0, artifacts generated.

---

## 9. Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Misuse as offensive tooling | Safety constraints S1–S6 enforced in code + review gate; no network imports |
| matplotlib unavailable in exe | Native-canvas fallback path; matplotlib optional extra |
| Very large flow tables freeze UI | Chunked Treeview insert + background thread |
| Threshold mis-tuning teaches wrong lesson | Defaults tuned to clearly separate decoys from campaigns; explainable findings |

---

## 10. Future Extensions
- More decoy families (DNS tunneling decoys, QUIC-shaped flows).
- Detection-explanation NLP pane (local, offline).
- Optional Zeek/Suricata "import mode" for user-supplied logs (still offline).
