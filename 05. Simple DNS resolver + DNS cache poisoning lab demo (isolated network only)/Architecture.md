# Architecture: Simple DNS Resolver + DNS Cache Poisoning Lab Demo (GUI-Based Solution)

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS) — **Isolated Lab Network Only**
**Core Capability:** Educational DNS resolver implementation with controlled cache poisoning demonstration in a sandboxed network
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **DNS Resolver & Cache Poisoning Lab Demo (DRCP)** is a GUI-driven desktop application for cybersecurity educators, students, and lab researchers who need to **demonstrate how DNS cache poisoning works** in a controlled, isolated environment. It provides both a functional DNS resolver implementation and a guided attack simulation that shows how forged DNS responses can corrupt a resolver's cache.

DNS cache poisoning remains one of the most consequential classes of network attacks. The fundamental weakness is architectural: DNS queries and responses over UDP rely on only a 16-bit transaction ID (65,536 possible values) plus the source port to match responses to queries . Dan Kaminsky's 2008 discovery showed that by flooding a resolver with forged responses, an attacker could guess the transaction ID and inject false records before the legitimate authoritative server responds . While source port randomization raised the difficulty from ~65,000 attempts to over a billion, side-channel attacks like SAD DNS (2020) demonstrated that even this mitigation could be defeated by leaking the ephemeral port through ICMP rate limiting .

The tool is designed around four principles:

1. **Isolated lab only** — all demonstrations occur on a closed network (host-only VMs or localhost); the tool refuses to operate against real DNS infrastructure.
2. **Educational transparency** — every packet, transaction ID, and cache entry is visible and inspectable; the attack is shown step-by-step, not hidden behind a "run exploit" button.
3. **Defensive framing** — the demonstration concludes with DNSSEC validation and the mitigations that make the attack infeasible in production .
4. **Report generation** — every lab session produces an exportable report documenting the attack timeline, evidence, and defensive recommendations.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Lab Setup │ │ Resolver  │ │ Attack    │ │ Cache     │ │ Report  │ │
│  │ Wizard    │ │ Console   │ │ Simulator │ │ Inspector │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Packet    │ │ Transaction│ │ Poisoning │ │ Defense   │ │ Console │ │
│  │ Viewer    │ │ ID Monitor│ │ Timeline  │ │ Demo      │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Lab        │ │ Attack     │ │ Cache      │ │ Event Bus / Log    │ │
│  │ Controller │ │ Engine     │ │ Manager    │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     DNS Core Layer                                   │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ DNS Resolver   │ │ DNS Cache      │ │ DNS Packet               │  │
│  │ (recursive)    │ │ (LRU + TTL)    │ │ Encoder/Decoder          │  │
│  │                │ │                │ │ (dnslib)                 │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Fake Authoritative Server (for isolated lab)                   │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Attack Simulation Layer                          │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Forged Packet  │ │ Transaction ID │ │ Poisoning Verifier       │  │
│  │ Generator      │ │ Guesser        │ │ (cache state checker)    │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Lab Config │ │ Cache Dump │ │ Attack Log │ │ Report Store       │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `LabSetupWizard` | Guided setup: verify isolated network, configure resolver IP/port, configure fake authoritative server, confirm "no real DNS" acknowledgment. **Blocks operation if a public DNS server is detected.** |
| `ResolverConsoleView` | Interactive DNS query console: send a query (`dig`-like), see the resolver's processing steps, view the response. Shows cache hit vs. miss. |
| `AttackSimulatorView` | **Primary attack view.** Step-by-step attack: (1) trigger resolver to send query, (2) observe transaction ID and source port, (3) flood forged responses, (4) observe cache poisoning. Manual and automated modes. |
| `CacheInspectorView` | Live view of the resolver's cache: domain, record type, value, TTL remaining, poisoned flag. Before/after comparison. |
| `PacketViewerView` | Raw DNS packet inspection: hex view, decoded header (transaction ID, flags), question, answer sections. Side-by-side legitimate vs. forged packets . |
| `TransactionIdMonitor` | Live visualization of transaction IDs: query ID, source port, guessed IDs attempted, success/failure. Demonstrates the 16-bit search space . |
| `PoisoningTimelineView` | Chronological timeline of the attack: query sent → forged responses sent → legitimate response arrives too late → cache poisoned. |
| `DefenseDemoView` | Demonstrates mitigations: (1) source port randomization, (2) DNSSEC validation rejects forged answers . |
| `ReportBuilderView` | Export lab report (HTML/PDF/JSON) with attack timeline, packet captures, cache state, and defensive recommendations. |
| `ConsoleView` | Live log: resolver operations, packet send/receive, errors. |

**Key UI Patterns:**
- **Step-by-step attack flow**: numbered steps with "Execute" buttons; each step shows what happened and why.
- **Before/after cache comparison**: side-by-side view showing cache state before and after poisoning.
- **Color-coded packet states**: Legitimate (green), Forged (red), Failed (gray).
- **Safety banner**: prominent "ISOLATED LAB ONLY" indicator; red warning if public DNS detected.

### 3.2 Orchestration Layer

**Lab Controller**
- Manages lab lifecycle: setup → resolver start → attack simulation → cleanup.
- Enforces isolation: resolves target IP; if it matches a public DNS server (8.8.8.8, 1.1.1.1, etc.), refuses to proceed.
- Coordinates between resolver, attack engine, and cache manager.

**Attack Engine**
- Orchestrates the cache poisoning simulation.
- Steps: (1) send query to trigger resolver's outbound query, (2) capture transaction ID and source port, (3) generate forged responses, (4) flood, (5) verify cache state.
- Manual mode: each step requires user confirmation.
- Automated mode: runs the full attack with configurable delay.

**Cache Manager**
- Implements LRU cache with TTL expiration.
- Tracks cache entries: domain, record type, value, TTL, insertion time, source (legitimate/forged).
- Provides cache dump and flush operations .

### 3.3 DNS Core Layer

**DNS Resolver**
- Recursive resolver implementation using `dnslib` .
- Receives queries on configured port; checks cache; if miss, sends query to upstream (fake authoritative server).
- Validates response: transaction ID match, source IP match, source port match .
- Caches valid responses with TTL.

```python
class SimpleResolver:
    def __init__(self, cache, upstream):
        self.cache = cache
        self.upstream = upstream

    def resolve(self, query):
        # Check cache
        cached = self.cache.get(query.qname, query.qtype)
        if cached:
            return cached

        # Forward to upstream
        txn_id = random.randint(0, 65535)
        src_port = random.randint(1024, 65535)
        response = self.send_query(query, txn_id, src_port)

        # Validate response
        if not self.validate(response, txn_id, src_port):
            return None  # Reject forged response

        self.cache.put(query.qname, query.qtype, response, ttl)
        return response
```

**DNS Cache**
- LRU cache with TTL-based expiration.
- Keyed by `(qname, qtype)`.
- Stores: rdata, TTL, insertion timestamp, source flag (legitimate/forged).
- Supports dump (for GUI inspection) and flush .

**DNS Packet Encoder/Decoder**
- Uses `dnslib` for encoding/decoding DNS wire-format packets .
- Classes: `DNSRecord`, `DNSHeader`, `DNSQuestion`, `RR`, `A`, `CNAME` .
- Validates transaction ID on response .

**Fake Authoritative Server**
- Runs on localhost (or lab VM) to simulate an authoritative DNS server.
- Responds to A/CNAME queries for configured test domains.
- **Only operates on isolated network**; no real DNS resolution.

### 3.4 Attack Simulation Layer

**Forged Packet Generator**
- Creates DNS responses with forged answers.
- Configurable: transaction ID (manual or brute-force range), source port, forged IP address.
- Uses `dnslib` to construct packets; `scapy` or raw sockets to send .

**Transaction ID Guesser**
- Simulates the brute-force search of the 16-bit transaction ID space .
- Modes:
  - **Manual**: user specifies transaction ID.
  - **Sequential**: try IDs in order (simulates old BIND behavior) .
  - **Random**: random ID attempts (realistic attacker behavior).
- Displays progress: attempts made, time elapsed, success/failure.

**Poisoning Verifier**
- After attack, queries the resolver for the target domain.
- Checks if the response matches the forged record (poisoned) or the legitimate record (not poisoned).
- Displays before/after cache state.

### 3.5 Defense Demonstration Layer

**Source Port Randomization Demo**
- Shows how randomizing the source port increases the search space .
- Before: fixed source port (e.g., 53) → attack succeeds quickly.
- After: random source port → attack requires >1 billion attempts .

**DNSSEC Validation Demo**
- Shows DNSSEC signatures on legitimate responses.
- Forged responses lack valid signatures → rejected .
- Demonstrates the "only definitive solution" to cache poisoning .

### 3.6 Storage Layer

**Data directory:**
```
~/.drcp/
├── labs/
│   └── <lab_id>/
│       ├── config.json
│       ├── cache_before.json
│       ├── cache_after.json
│       ├── attack_log.jsonl
│       └── packets/
│           ├── query.pcap
│           └── forged.pcap
├── reports/
│   └── <lab_id>_report.pdf
└── logs/
    └── drcp.log
```

**Lab session model:**
```python
@dataclass
class LabSession:
    lab_id: str
    timestamp: datetime
    resolver_ip: str
    resolver_port: int
    target_domain: str
    legitimate_answer: str
    forged_answer: str
    attack_steps: list[AttackStep]
    cache_before: list[CacheEntry]
    cache_after: list[CacheEntry]
    poisoning_successful: bool

@dataclass
class AttackStep:
    step_number: int
    action: str
    timestamp: datetime
    details: str
    success: bool

@dataclass
class CacheEntry:
    domain: str
    record_type: str
    value: str
    ttl: int
    source: str  # 'legitimate', 'forged'
```

### 3.7 Canonical Data Model

See `LabSession`, `AttackStep`, and `CacheEntry` above.

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, packet view, cache inspector
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Resolver Thread (single)
  ├── Listen for DNS queries on UDP socket
  ├── Process queries (cache check, upstream forward)
  └── Validate responses

Attack Thread (single)
  ├── Send forged packets
  ├── Track transaction ID attempts
  └── Emit progress signals

Upstream Thread (single)
  └── Fake authoritative server
```

**Rules:**
- Resolver runs in its own thread; GUI never blocks on socket operations.
- Attack simulation runs in worker thread; progress emitted via signals.
- All key material (cache entries) protected by lock for thread-safe access.
- Cancellation: `threading.Event` checked between attack attempts.

---

## 5. Workflow: End-to-End User Journey

1. **Lab Setup** → verify isolated network; configure resolver IP/port; configure fake authoritative server; acknowledge "no real DNS" warning .
2. **Start Resolver** → resolver begins listening; cache empty.
3. **Trigger Query** → send a query for `test.lab` to the resolver; observe cache miss and upstream query .
4. **Observe Transaction ID** → monitor shows the transaction ID and source port used for the outbound query.
5. **Send Forged Response** → attack simulator sends a forged response with the guessed transaction ID and a malicious IP.
6. **Legitimate Response Arrives** → if forged response arrived first, the resolver accepts it; legitimate response is discarded.
7. **Verify Poisoning** → query the resolver again; it returns the forged IP from cache .
8. **Inspect Cache** → cache inspector shows the poisoned entry with source "forged."
9. **Defense Demo** → enable source port randomization or DNSSEC validation; repeat attack; observe rejection .
10. **Export Report** → generate PDF/JSON with attack timeline, packets, cache state, and findings.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Real-world attack** | Tool refuses to operate against public DNS (8.8.8.8, 1.1.1.1, etc.); requires isolated network acknowledgment. |
| **Accidental poisoning** | Resolver only caches responses from configured fake authoritative server; no real upstream. |
| **Network leakage** | All traffic on localhost or host-only VM network; no external routing. |
| **Educational misuse** | Prominent disclaimer; tool logs all sessions; lab-only design. |
| **Packet injection** | Raw sockets require root; tool uses `dnslib` + UDP sockets for lab simplicity. |
| **Cache persistence** | Cache stored in memory only; dump files are for inspection, not used for resolution. |

---

## 7. Extensibility Points

1. **New attack technique** — implement `AttackTechnique` ABC (Kaminsky, SAD DNS simulation) .
2. **New defense** — implement `DefenseMechanism` ABC (port randomization, DNSSEC, 0x20 encoding) .
3. **New record type** — add support for AAAA, MX, TXT via `dnslib` .
4. **New export format** — `Exporter` ABC (PDF, JSON, HTML, PCAP).
5. **Real BIND integration** — optional: use BIND9 as resolver instead of custom implementation .

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 2 s |
| Resolver query processing | < 10 ms |
| Attack simulation (1000 attempts) | < 5 s |
| Cache dump/restore | < 100 ms |
| Report generation | < 3 s |
| Memory footprint | < 200 MB RSS |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly |
| DNS packets | `dnslib` | Encode/decode DNS wire-format  |
| Raw packets | `scapy` (optional) | Forged packet generation  |
| Sockets | `socket` (stdlib) | UDP resolver |
| DB | JSON + SQLite | Lab session storage |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
drcp/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── drcp/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── lab_setup.py
│       │   │   ├── resolver_console.py
│       │   │   ├── attack_simulator.py
│       │   │   ├── cache_inspector.py
│       │   │   ├── packet_viewer.py
│       │   │   ├── txn_id_monitor.py
│       │   │   ├── poisoning_timeline.py
│       │   │   ├── defense_demo.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── cache_table_model.py
│       │   │   └── attack_log_model.py
│       │   └── widgets/
│       │       ├── packet_hex_view.py
│       │       ├── cache_entry_card.py
│       │       └── safety_banner.py
│       ├── core/
│       │   ├── resolver/
│       │   │   ├── resolver.py
│       │   │   ├── cache.py
│       │   │   └── validator.py
│       │   ├── packets/
│       │   │   ├── encoder.py
│       │   │   ├── decoder.py
│       │   │   └── forger.py
│       │   ├── attack/
│       │   │   ├── engine.py
│       │   │   ├── txn_id_guesser.py
│       │   │   └── verifier.py
│       │   ├── defense/
│       │   │   ├── port_randomization.py
│       │   │   └── dnssec_demo.py
│       │   └── upstream/
│       │       └── fake_authoritative.py
│       ├── storage/
│       │   ├── lab_store.py
│       │   └── cache_store.py
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── html_exporter.py
│       │   │   ├── pdf_exporter.py
│       │   │   └── json_exporter.py
│       │   └── templates/
│       └── utils/
│           ├── isolation.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── gui/
├── resources/
│   ├── icons/
│   └── zone_files/
└── docs/
    ├── architecture.md
    └── lab_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, lab setup wizard, isolation check, resolver stub | 2 weeks |
| **P1 — DNS Resolver** | Recursive resolver, cache, `dnslib` integration, resolver console | 2 weeks |
| **P2 — Fake Authoritative** | Fake upstream server, zone file support | 1 week |
| **P3 — Attack Simulator** | Forged packet generation, transaction ID guessing, step-by-step UI | 3 weeks |
| **P4 — Cache Inspector** | Cache dump, before/after comparison, poisoned flag | 1 week |
| **P5 — Packet Viewer** | Hex view, decoded fields, side-by-side comparison | 1 week |
| **P6 — Defense Demo** | Port randomization, DNSSEC validation demonstration | 2 weeks |
| **P7 — Reporting** | HTML/PDF/JSON export, attack timeline | 2 weeks |
| **P8 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~17 weeks (single senior dev) / ~9 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: DNS packet encoding/decoding, cache TTL expiration, transaction ID validation, forged packet construction.
- **Integration**: full attack simulation against fake authoritative server on localhost.
- **GUI**: `pytest-qt` for resolver console, attack steps, cache inspector.
- **Safety**: verify isolation check rejects public DNS; verify no external packets sent.
- **Cross-validation**: compare resolver behavior against BIND9 in isolated lab .

---

## 13. Open Questions / Decisions Pending

1. **BIND vs custom resolver** — BIND9 is production-grade but heavyweight; custom resolver is simpler for education . Recommend: custom resolver for v1; BIND integration optional.
2. **Raw sockets vs UDP** — Scapy raw sockets are realistic but require root; UDP sockets are simpler. Recommend: UDP for v1; Scapy optional .
3. **SAD DNS simulation** — complex (ICMP rate limiting side-channel) . Recommend: document as advanced topic; not in v1.
4. **DNSSEC implementation** — full DNSSEC is complex. Recommend: simplified validation demo (signature presence check) .
5. **Isolation enforcement** — how to reliably detect "isolated network"? Recommend: blocklist of known public DNS IPs + user acknowledgment.

---

## 14. Glossary

- **DNS Cache Poisoning** — Injecting false DNS records into a resolver's cache .
- **Transaction ID** — 16-bit field matching DNS queries to responses .
- **Kaminsky Attack** — 2008 cache poisoning technique exploiting insufficient transaction ID randomness .
- **Source Port Randomization** — Mitigation that randomizes the UDP source port for DNS queries .
- **SAD DNS** — Side-channel attack that leaks the ephemeral port, defeating randomization .
- **DNSSEC** — DNS Security Extensions; cryptographic validation of DNS responses .
- **dnslib** — Python library for encoding/decoding DNS packets .
- **Fake Authoritative Server** — Lab-only DNS server simulating upstream responses.
- **In-Bailiwick** — Records within the scope of an authoritative server's zone .

---

*End of document.*