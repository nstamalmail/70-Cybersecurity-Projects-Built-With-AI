# Architecture: Windows Event Log Correlation Tool for Intrusion Timeline (GUI-Based Solution)

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows primary, Linux/macOS for offline analysis)
**Core Capability:** Ingest, normalize, correlate, and visualize Windows Event Logs (EVTX) into an intrusion timeline
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Windows Event Log Correlation Tool (WELCT)** is a GUI-driven desktop application for DFIR analysts, SOC investigators, and threat hunters who need to reconstruct an intrusion timeline from Windows Event Logs. It ingests native `.evtx` files (live or offline), Security, System, Application, Sysmon, PowerShell, TerminalServices, WMI, Defender, Firewall, and Task Scheduler channels, plus third-party provider logs (CrowdStrike, SentinelOne, Sysmon variants).

The tool's distinguishing feature is **correlation** — the ability to chain events into attack narratives using built-in and user-defined rules mapped to MITRE ATT&CK techniques, then present the result as a filterable, zoomable timeline.

Core capabilities:
- **Multi-source ingestion** — one or many `.evtx` files, live channels, EVTXtract output, Velociraptor/Chainsaw/KAPE exports.
- **Normalization** — every event mapped to a unified schema (ECS-inspired) with canonical fields.
- **Correlation engine** — rule-based (Sigma-compatible) + stateful sequence detection (e.g., "4624 → 4672 → 4688 with `mimikatz`").
- **Attack timeline** — unified, multi-lane timeline with drill-down.
- **Entity graph** — users, hosts, processes, IPs, and their relationships.
- **Reporting** — HTML/PDF/JSON/CSV/STIX 2.1/MISP with attack narrative.

The tool is designed around four principles:

1. **Read-only by default** — source `.evtx` files opened read-only; live channels accessed via `wevtapi` in read-only mode.
2. **Evidence integrity** — every source file hashed; every correlation logged; chain-of-custody.
3. **MITRE-mapped** — every correlation rule tagged with ATT&CK technique IDs.
4. **Analyst-first UI** — correlation is a *hypothesis generator*, not a verdict; all rules show supporting events.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Case Mgmt │ │ Source    │ │ Rule      │ │ Timeline  │ │ Report  │ │
│  │  View     │ │ Manager   │ │ Manager   │ │  View     │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Events    │ │ Correla-  │ │ Entity    │ │ MITRE     │ │ Console │ │
│  │ Table     │ │ tion View │ │ Graph     │ │ Heatmap   │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots (async)
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Ingest     │ │ Pipeline   │ │ Scheduler  │ │ Event Bus / Log    │ │
│  │ Queue      │ │ Engine     │ │ (QThread   │ │ (structlog)        │ │
│  │ (priority) │ │ (staged)   │ │  Pool)     │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Event Processing Layer                           │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ EVTX Parser    │ │ Normalizer     │ │ Correlation Engine       │  │
│  │ (BinXML,       │ │ (ECS schema,   │ │ (Sigma rules, stateful   │  │
│  │  chunked)      │ │  TZ, providers)│ │  sequences, scoring)     │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Enrichment: IP geo, hash lookup, Sigma rule pack, ATT&CK map  │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Case DB    │ │ Event      │ │ Correla-   │ │ Rule / ATT&CK      │ │
│  │ (SQLite)   │ │ Store      │ │ tion Store │ │ Cache              │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     OS / Runtime Abstraction Layer                   │
│  File I/O (read-only) · wevtapi (live) · TZ / locale · Config store  │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `CaseManagerView` | Create/open cases; analyst metadata; chain-of-custody; case directory selection. |
| `SourceManagerView` | Add `.evtx` files, folders, live channels, or third-party exports. Auto-detect channel from EVTX `Channel` element. Show source hash, event count, time range, provider list. |
| `IngestProgressView` | Per-source progress: chunks parsed, events/s, malformed records, errors. |
| `RuleManagerView` | Browse/import Sigma rules, built-in rules, custom rules. Filter by ATT&CK technique, severity, log source. Enable/disable. Show rule YAML + test against loaded events. |
| `EventsTableView` | Master event table: timestamp, host, channel, provider, EventID, user, process, command line, IP, correlated flags. Virtualized for 100M+ rows. |
| `TimelineView` | Unified chronological view; swim lanes per host/user/technique; zoomable; brush-select to filter. |
| `CorrelationView` | List of correlated incidents: rule name, severity, ATT&CK mapping, entities involved, first/last seen, supporting events (clickable to drill down). |
| `EntityGraphView` | Interactive graph of users/hosts/processes/IPs/domains with relationship edges derived from events. |
| `MitreHeatmapView` | ATT&CK matrix heatmap: cells colored by hit count / severity; click → filtered timeline. |
| `PivotPanel` | Right-click any event → pivot: "all events for this user", "all events for this host", "all processes spawned by this PID", "all logons from this IP". |
| `SearchFilterBar` | Full-text search (FTS5) + field filters + saved queries + regex. |
| `ReportBuilderView` | Export HTML/PDF/JSON/CSV/STIX/MISP; attack narrative template; hash manifest. |
| `ConsoleView` | Live log tail; parser warnings; rule engine stats; debug toggle. |

**Key UI Patterns**
- Model/View with `QAbstractTableModel` — virtualization mandatory (Security.evtx alone can have millions of events).
- Worker threads via `QThreadPool` + `QRunnable`; UI never blocks.
- Streaming results: parser emits events incrementally; UI batches appends (500 rows/tick).
- Timeline rendering uses a custom `QGraphicsScene` with level-of-detail (LOD) — aggregate when zoomed out, individual events when zoomed in.
- Entity graph uses `pyqtgraph` or `networkx` + custom Qt item rendering.

### 3.2 Orchestration Layer

**Ingest Queue**
- Priority queue (`queue.PriorityQueue`) with worker pool.
- Job = `(job_id, source_path, channel_hint, filters, case_id)`.
- Persisted to SQLite `ingestions` table for crash recovery.

**Pipeline Engine (staged)**
```
[Source Reader] → [EVTX Parser] → [Normalizer] → [Enricher]
       → [Dedup + Hash] → [Writer] → [Correlation Engine] → [Indexer]
```
- Stages connected by bounded queues (back-pressure aware).
- Each stage independently testable and replaceable.
- Correlation runs after ingest completes (batch) OR incrementally (streaming mode).

**Scheduler**
- Parallelism: `min(4, cpu_count-1)` for CPU-bound stages; per-source EVTX parsing parallelized.
- Correlation is stateful per rule and per entity — serialized per rule, parallel across rules.
- Writer serialized (SQLite WAL single writer).

### 3.3 EVTX Parser Layer

**File format**
- EVTX header: `ElfFile\0` magic, chunk count, next record ID, header size (4096).
- Chunks: 64 KB each; `ElfChnk\0` magic; record offsets table (last 64 records cached).
- Records: `\x2a\x2a\x00\x00` magic; size; record ID; timestamp (FILETIME); BinXML payload.
- BinXML: binary XML with template instances, name/value substitutions, nested elements, substitution arrays.
- CRC32 checksums per chunk and per header.

**Parser features**
- **Chunked streaming**: parse one 64 KB chunk at a time; never load the whole file.
- **Corruption tolerance**: skip bad chunks, continue; report recovered record count.
- **Template caching**: BinXML templates reused heavily — cache decoded templates keyed by template ID to speed up parsing 10–100×.
- **Time zone handling**: EVTX stores timestamps in UTC (FILETIME); display in analyst-selected TZ.
- **Provider detection**: System, Security, Application, Sysmon (Microsoft-Windows-Sysmon/Operational), PowerShell (Operational/Classic), WMI-Activity, TerminalServices-LocalSessionManager, TerminalServices-RemoteConnectionManager, TaskScheduler, Windows Defender, Firewall, AppLocker, CodeIntegrity, DNS Client, BITS, RemoteDesktopServices, etc.
- **Live channels** (Windows only): read via `wevtapi` (`EvtQuery`, `EvtNext`, `EvtRender`) in read-only mode; supports `.evtx` export too.

**Third-party sources**
- **EVTXtract**: raw carved EVTX records → reassembled into pseudo-chunks.
- **Velociraptor / Chainsaw / Hayabusa / KAPE**: JSON/JSONL exports → mapped to unified schema.
- **Sysmon for Linux** (`.evtx` from Windows, or JSON): same schema.
- **Windows Event Forwarding (WEF)** and **WinRM** collected logs: same as native EVTX.

### 3.4 Normalization Layer

**Unified schema (ECS-inspired)**

```python
@dataclass
class NormalizedEvent:
    event_id: str                  # ULID
    case_id: str
    source_id: str
    source_path: str

    # Time
    ts: datetime                   # UTC
    ts_raw: int                    # FILETIME
    ts_source: str                 # 'evtx_record', 'system_time'

    # Identity
    host: str | None               # Computer
    channel: str | None            # Security, System, ...
    provider: str | None           # Microsoft-Windows-Security-Auditing
    provider_guid: str | None
    event_code: int | None         # 4624, 1, 4104, ...
    record_id: int | None
    task: int | None
    opcode: int | None
    level: int | None              # 0-5 (Critical..Verbose)
    keywords: str | None

    # Actors
    user: str | None               # TargetUserName / SubjectUserName
    user_sid: str | None
    subject_user: str | None
    subject_sid: str | None
    logon_type: int | None         # 2,3,10,...
    logon_id: str | None

    # Process
    process_name: str | None
    process_id: int | None
    parent_process_name: str | None
    parent_process_id: int | None
    command_line: str | None
    image_path: str | None
    hashes: dict[str, str] | None  # Sysmon hashes

    # Network
    src_ip: str | None
    src_port: int | None
    dst_ip: str | None
    dst_port: int | None
    protocol: str | None
    dns_query: str | None

    # File / Registry
    target_filename: str | None
    registry_key: str | None
    registry_value: str | None

    # Service / Task / Scheduled
    service_name: str | None
    task_name: str | None

    # PowerShell
    script_block: str | None

    # Raw
    message: str | None            # rendered message
    xml: str                       # original XML
    extra: dict                    # all other named fields

    # Correlation
    techniques: list[str]          # MITRE ATT&CK IDs
    tags: list[str]                # sigma rule IDs, analyst tags
    severity: str | None           # informational..critical
```

**Provider-specific normalizers**
- One `Normalizer` per provider family (Security, Sysmon, PowerShell, etc.).
- Extracts well-known fields into canonical slots; everything else goes to `extra`.
- Handles event-specific structures (e.g., 4624 has `TargetUserName`, `LogonType`, `IpAddress`; Sysmon EID 1 has `Image`, `CommandLine`, `Hashes`; PowerShell 4104 has `ScriptBlockText`).
- Uses a declarative mapping table (`normalizers/security.yaml`, `normalizers/sysmon.yaml`) so new event IDs can be added without code.

**Message rendering**
- Render BinXML substitution arrays into human-readable message using provider message tables (`%SystemRoot%\System32\wevtapi.dll` message resources) OR a bundled message DB.
- Fallback: leave `message` null and expose structured `extra`.

### 3.5 Correlation Layer

**Rule engine (Sigma-compatible)**

Sigma rules define detection logic in YAML:

```yaml
title: Suspicious LSASS Access
id: 0f8b1e2a-...
status: stable
description: Detects access to LSASS memory
references:
  - https://attack.mitre.org/techniques/T1003/001/
author: WELCT
date: 2025/01/01
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4656
    ObjectName|endswith: '\lsass.exe'
    AccessMask|contains: '0x1010'
  condition: selection
falsepositives:
  - Legitimate AV/EDR
level: high
```

- **Compiler**: Sigma → internal query AST (SQL or in-memory predicate).
- **Backends**: 
  - SQL backend for loaded events (SQLite FTS5 + generated WHERE clauses).
  - Streaming backend for live ingestion (Python predicates).
- **Bundled rule packs**: SigmaHQ core + Windows-specific community rules (~3000+).
- **Custom rules**: user can add/import; validated against schema; tested against loaded events.
- **Rule versioning**: rule ID + version stored with each correlation hit.

**Stateful correlation (sequences)**

Beyond single-event rules, the engine supports **temporal sequences** with a DSL:

```yaml
title: Credential Dumping Sequence
id: welct-seq-001
sequence:
  - rule: 'sigma:4624'                 # logon
    within: 5m
  - rule: 'sigma:4672'                 # special privileges
    within: 1m
  - rule: 'sigma:sysmon-10'            # process access to lsass
    within: 2m
    where: "TargetImage endswith 'lsass.exe'"
group_by: [host, user]
severity: critical
techniques: [T1003.001, T1078]
```

- **Engine**: sliding-window state machine per `group_by` key.
- **Out-of-order events**: handled via event-time windowing (not arrival-time).
- **Bounded state**: per-key state evicted after max window; configurable memory cap.

**Correlation scoring**
- Each hit assigned a **confidence** (0.0–1.0) from:
  - Rule `level` (Sigma level → base score).
  - Rule specificity (number of field constraints).
  - Entity rarity (rare users/hosts/IPs score higher).
  - Sequence depth (longer sequences → higher confidence).
  - False-positive suppressions (allow-list per rule/entity).
- Optional **risk score** aggregating per-entity (user/host) totals.

**False-positive suppression**
- Per-rule allow-lists (users, hosts, processes, paths, IPs).
- Global allow-lists (e.g., known service accounts, `NT AUTHORITY\SYSTEM` for certain rules).
- Time-based (e.g., exclude known maintenance windows).

**ATT&CK mapping**
- Rule tags `attack.tNNNN` → technique IDs.
- Sub-techniques (`attack.t1003.001`) → parent rollup for heatmap.
- Tactics derived from technique (`attack.credential_access` → TA0006).
- Bundled ATT&CK STIX data used for tactic/technique names and descriptions.

### 3.6 Enrichment Layer

**IP enrichment**
- Optional local GeoIP (MaxMind GeoLite2) — offline, no external calls by default.
- ASN lookup (GeoLite2 ASN).
- Private/reserved IP detection.
- Optional external lookups (VirusTotal, AbuseIPDB) — **disabled by default**, opt-in per case, all lookups logged in custody.

**Hash enrichment**
- Optional local hash DB (NSRL, custom IOC list).
- Optional external lookups (VT) — opt-in only.

**Process tree enrichment**
- Reconstruct process lineage from Sysmon EID 1 (`ProcessCreate`) and 4688.
- Handle PID reuse (match by `ProcessGuid` where available).
- Orphan processes marked as such.

**Logon session enrichment**
- Track logon IDs from 4624 → correlate with 4648, 4672, 4634/4647 (logoff).
- Identify interactive vs network vs service logons.

**Entity enrichment**
- Build canonical entity list: users (SID), hosts, processes (image + hash), IPs, domains, files, registry keys, services, scheduled tasks.

### 3.7 Storage Layer

**Case Directory Layout**
```
cases/<case_id>/
├── case.db                      # SQLite: cases, sources, events, correlations, custody
├── manifest.json                # Case metadata
├── source_ref.txt               # Paths + hashes of source EVTX files
├── sources/                     # Optional copies (if user requests)
├── rules/
│   ├── bundled/                 # SigmaHQ + built-in
│   ├── imported/                # User-imported
│   └── custom/                  # User-authored
├── enrich/
│   ├── geoip/                   # GeoLite2 DB (if provided)
│   └── ioc/                     # IOC lists
├── reports/
│   ├── report.html
│   ├── report.pdf
│   ├── timeline.csv
│   ├── correlations.json
│   ├── stix.json
│   ├── misp.json
│   └── custody.json
└── logs/
    └── session.log
```

**SQLite Schema (abridged)**
```sql
CREATE TABLE cases (
  id TEXT PRIMARY KEY, name TEXT, analyst TEXT,
  host_count INTEGER, event_count INTEGER,
  created_at TIMESTAMP
);
CREATE TABLE sources (
  id TEXT PRIMARY KEY, case_id TEXT,
  path TEXT, sha256 TEXT, size INTEGER,
  channel TEXT, provider_list_json TEXT,
  first_event_ts TIMESTAMP, last_event_ts TIMESTAMP,
  event_count INTEGER, malformed_count INTEGER,
  FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE TABLE events (
  id INTEGER PRIMARY KEY, case_id TEXT, source_id TEXT,
  ts TIMESTAMP, ts_raw INTEGER,
  host TEXT, channel TEXT, provider TEXT, provider_guid TEXT,
  event_code INTEGER, record_id INTEGER,
  level INTEGER, task INTEGER, opcode INTEGER, keywords TEXT,
  user TEXT, user_sid TEXT, subject_user TEXT, subject_sid TEXT,
  logon_type INTEGER, logon_id TEXT,
  process_name TEXT, process_id INTEGER,
  parent_process_name TEXT, parent_process_id INTEGER,
  command_line TEXT, image_path TEXT, hashes_json TEXT,
  src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER,
  protocol TEXT, dns_query TEXT,
  target_filename TEXT, registry_key TEXT, registry_value TEXT,
  service_name TEXT, task_name TEXT, script_block TEXT,
  message TEXT, xml TEXT, extra_json TEXT,
  FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE INDEX idx_events_ts ON events(ts);
CREATE INDEX idx_events_code ON events(event_code);
CREATE INDEX idx_events_user ON events(user_sid);
CREATE INDEX idx_events_host ON events(host);
CREATE INDEX idx_events_proc ON events(process_id);
CREATE INDEX idx_events_srcip ON events(src_ip);
CREATE VIRTUAL TABLE events_fts USING fts5(
  message, command_line, script_block, extra_json,
  content='events', content_rowid='id'
);
CREATE TABLE correlations (
  id INTEGER PRIMARY KEY, case_id TEXT,
  rule_id TEXT, rule_title TEXT, rule_level TEXT,
  severity TEXT, confidence REAL, risk_score REAL,
  first_ts TIMESTAMP, last_ts TIMESTAMP,
  group_key TEXT,              -- JSON: {host, user, ...}
  techniques_json TEXT,        -- ["T1003.001","T1078"]
  tactics_json TEXT,
  supporting_event_ids_json TEXT,
  status TEXT,                 -- 'new','triage','confirmed','false_positive'
  analyst_notes TEXT
);
CREATE INDEX idx_corr_rule ON correlations(rule_id);
CREATE INDEX idx_corr_sev ON correlations(severity);
CREATE TABLE entities (
  id INTEGER PRIMARY KEY, case_id TEXT,
  kind TEXT,                   -- 'user','host','process','ip','domain','file',...
  key TEXT,                    -- SID, hostname, hash, IP, path
  display TEXT,
  first_ts TIMESTAMP, last_ts TIMESTAMP,
  risk_score REAL,
  tags_json TEXT
);
CREATE TABLE custody (
  id INTEGER PRIMARY KEY, case_id TEXT,
  ts TIMESTAMP, actor TEXT, action TEXT, detail_json TEXT
);
```

**Performance considerations**
- Partitioning: SQLite supports one DB per case; for very large cases (>500M events), shard by month or host.
- Indexes tuned for the common pivots (ts, event_code, user_sid, host, process_id, src_ip).
- FTS5 on message + command_line + script_block; configurable (can be disabled for speed).
- WAL mode; single writer thread.
- Vacuum/analyze on case close.

### 3.8 Canonical Data Model

See `NormalizedEvent` in §3.4. Additional types:

```python
@dataclass
class Correlation:
    correlation_id: str
    case_id: str
    rule_id: str
    rule_title: str
    rule_level: str              # Sigma level
    severity: str                # normalized: informational..critical
    confidence: float
    risk_score: float
    first_ts: datetime
    last_ts: datetime
    group_key: dict              # {host: ..., user: ...}
    techniques: list[str]        # ["T1003.001"]
    tactics: list[str]           # ["credential_access"]
    supporting_event_ids: list[int]
    status: str                  # new/triage/confirmed/false_positive
    analyst_notes: str | None

@dataclass
class Entity:
    entity_id: str
    case_id: str
    kind: str                    # user/host/process/ip/domain/file/registry/service/task
    key: str                     # canonical ID (SID, hostname, hash, IP, path)
    display: str
    first_ts: datetime
    last_ts: datetime
    risk_score: float
    tags: list[str]
```

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, model updates
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Ingest Pool (QThreadPool, N workers)
  ├── EVTX reader threads      (parallel per source file)
  ├── Normalizer threads       (parallel per chunk)
  ├── Enricher thread          (serial; may call external APIs if enabled)
  ├── Hasher + dedup thread    (serial)
  └── Writer thread            (serial, SQLite WAL)

Correlation Pool (QThreadPool, M workers)
  ├── Rule compiler thread     (serial; compiles Sigma → AST)
  ├── Rule evaluator threads   (parallel across rules)
  └── Sequence engine thread   (serial per group_by key; parallel across keys)
       │
       └── Bounded queues between stages (back-pressure)
```

**Rules**
- Source EVTX files opened read-only; never modified.
- Live channels: one `wevtapi` reader thread per channel; read-only query.
- SQLite in WAL mode; single writer, many readers.
- Cancellation: cooperative `threading.Event` checked every N events.
- Memory bounds: correlation state capped (default 1 GB); LRU eviction per rule.
- Out-of-order events: correlation uses **event time** windows, not arrival order.

---

## 5. Workflow: End-to-End User Journey

1. **Create Case** → analyst name, host(s), evidence description.
2. **Add Sources** → drag/drop `.evtx` files or folders; add live channels (Windows); import third-party exports (Chainsaw, Hayabusa, Velociraptor JSON).
3. **Auto-Detect** → parse EVTX headers; extract channel, provider list, time range, event count. Hash each source.
4. **Ingest** → pipeline runs; events appear in table as parsed; progress per source.
5. **Select Rules** → enable bundled Sigma packs (default: core + Windows + ATT&CK-mapped); import custom rules; disable noisy rules.
6. **Correlate** → engine evaluates all enabled rules (single-event + sequences); correlations appear in `CorrelationView` with ATT&CK tags.
7. **Triage** → sort by severity/confidence; drill into supporting events; mark confirmed/false-positive; add notes; tags propagate to entities.
8. **Investigate** → pivot by entity (user/host/process/IP); timeline view; entity graph; MITRE heatmap.
9. **Report** → HTML/PDF attack narrative; JSON/CSV for SIEM; STIX/MISP for sharing; redaction profile.
10. **Archive** → zip case dir; sign with case HMAC; chain-of-custody log.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| Writing to source EVTX | All opens read-only; live channels via read-only `wevtapi` queries. |
| Malicious EVTX (parser exploit) | Parsers run in subprocess with resource limits; fuzz-tested; no `eval`; recursion depth caps; BinXML depth limit. |
| Malicious command-line content | Never executed; displayed as text; rendering in Qt with HTML escaping. |
| External enrichment leakage | External lookups (VT, AbuseIPDB) **disabled by default**; opt-in per case; all lookups logged. |
| Sensitive data in reports | Redaction profile: hash/redact usernames, IPs, paths, command lines; audit-logged. |
| Evidence tampering | Append-only HMAC hash chain on `custody`; source hashes recorded at ingest; manifest signed. |
| Rule supply-chain | Bundled rules from SigmaHQ pinned by commit; imported rules validated against schema; no code execution from YAML. |
| DoS via huge logs | Configurable caps; streaming; memory-bounded queues; FTS optional. |
| Live-channel privilege | Read-only query; may require `Event Log Readers` group; documented. |
| Time-zone confusion | All internal timestamps UTC; TZ displayed; export includes both. |
| PID reuse | Match by `ProcessGuid` where available (Sysmon); flag ambiguity. |

---

## 7. Extensibility Points

1. **New provider normalizer** — YAML mapping in `normalizers/`; no code needed.
2. **New Sigma rule** — drop YAML in `rules/custom/`.
3. **New sequence rule** — YAML in `rules/sequences/`.
4. **New correlation backend** — implement `RuleBackend` ABC (SQL, streaming, external SIEM).
5. **New enrichment** — implement `Enricher` ABC (GeoIP, VT, custom IOC).
6. **New exporter** — `Exporter` ABC; HTML/PDF/JSON/CSV/STIX/MISP shipped.
7. **New UI view** — plug into `MainWindow` tab registry.
8. **Live channel collector** — implement `ChannelReader` ABC (wevtapi, WEF, WinRM).

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time (cold) | < 3 s |
| UI responsiveness | < 100 ms for any user action |
| EVTX ingest throughput | ≥ 100k events/s (SSD, warm template cache) |
| Correlation throughput | ≥ 500k events/s per rule (SQL backend) |
| Memory footprint | < 3 GB RSS for 100M-event case |
| Case size support | Up to 500M events (sharded) |
| Timeline render | 60 fps at 1M visible events (LOD aggregation) |
| Concurrency | Up to 8 ingest workers, 8 correlation workers |
| Crash recovery | Resume ingest/correlation from last committed batch within 5 s |
| Localization | i18n-ready (Qt Linguist `.ts`) |
| Accessibility | Keyboard-navigable, screen-reader labels |
| Timestamp accuracy | 100 ns precision (FILETIME); UTC internal; TZ-aware display |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Rich ecosystem (`python-evtx`, `lxml`, `pySigma`) |
| GUI | PySide6 (LGPL) | Commercial-friendly; mature Model/View |
| EVTX parsing | `python-evtx` (vendored + patched) + custom streaming parser | Battle-tested; patch for speed |
| Sigma | `pySigma` + `pySigma-backend-sqlite` | Standard rule format |
| XML | `lxml` (fast) | BinXML rendering |
| DB | SQLite (WAL + FTS5) | Embedded, ACID, FTS |
| GeoIP | `geoip2` + MaxMind GeoLite2 (user-provided) | Offline |
| STIX/MISP | `stix2`, `pymisp` | Standard sharing |
| ATT&CK | `mitreattack-python` (bundled STIX) | Technique metadata |
| Serialization | JSON Lines + MessagePack | Streaming + compact |
| Hashing | `hashlib` (SHA-256), `blake3` (fast dedup) | Speed + standard |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller + Briefcase | Cross-platform binaries |
| Testing | pytest + pytest-qt + Hypothesis | Unit, GUI, property-based |
| Fuzzing | Atheris / AFL++ | Parser hardening |
| CI | GitHub Actions | Matrix: Win/Linux/macOS × py3.10–3.12 |

---

## 10. Directory Structure (Source Tree)

```
welct/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── welct/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── case_manager.py
│       │   │   ├── source_manager.py
│       │   │   ├── ingest_progress.py
│       │   │   ├── rule_manager.py
│       │   │   ├── events_table.py
│       │   │   ├── timeline.py
│       │   │   ├── correlation.py
│       │   │   ├── entity_graph.py
│       │   │   ├── mitre_heatmap.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── events_table_model.py
│       │   │   ├── correlations_table_model.py
│       │   │   ├── timeline_model.py
│       │   │   └── entity_model.py
│       │   └── widgets/
│       │       ├── pivot_panel.py
│       │       ├── filter_bar.py
│       │       ├── hex_viewer.py
│       │       ├── xml_viewer.py
│       │       └── timeline_canvas.py
│       ├── core/
│       │   ├── ingest/
│       │   │   ├── evtx_reader.py
│       │   │   ├── evtx_parser.py
│       │   │   ├── binxml.py
│       │   │   ├── template_cache.py
│       │   │   ├── live_channels.py     # wevtapi
│       │   │   ├── third_party.py       # Chainsaw, Hayabusa, Velociraptor
│       │   │   └── chunked_reader.py
│       │   ├── normalize/
│       │   │   ├── schema.py
│       │   │   ├── normalizer.py
│       │   │   ├── provider_map.py
│       │   │   ├── message_renderer.py
│       │   │   └── mappings/
│       │   │       ├── security.yaml
│       │   │       ├── system.yaml
│       │   │       ├── sysmon.yaml
│       │   │       ├── powershell.yaml
│       │   │       ├── terminal_services.yaml
│       │   │       ├── defender.yaml
│       │   │       ├── firewall.yaml
│       │   │       ├── applocker.yaml
│       │   │       └── taskscheduler.yaml
│       │   ├── enrich/
│       │   │   ├── geoip.py
│       │   │   ├── ioc.py
│       │   │   ├── process_tree.py
│       │   │   ├── logon_session.py
│       │   │   └── external.py          # opt-in VT/AbuseIPDB
│       │   ├── correlation/
│       │   │   ├── engine.py
│       │   │   ├── sigma_loader.py
│       │   │   ├── sigma_compiler.py
│       │   │   ├── backends/
│       │   │   │   ├── sql_backend.py
│       │   │   │   └── streaming_backend.py
│       │   │   ├── sequences.py
│       │   │   ├── scoring.py
│       │   │   ├── allowlist.py
│       │   │   └── attack_map.py
│       │   ├── pipeline/
│       │   │   ├── stages.py
│       │   │   ├── queue.py
│       │   │   └── scheduler.py
│       │   └── dedup/
│       │       ├── fastcdc.py
│       │       └── hash_index.py
│       ├── storage/
│       │   ├── case_db.py
│       │   ├── event_store.py
│       │   ├── correlation_store.py
│       │   ├── entity_store.py
│       │   ├── fts_index.py
│       │   ├── cache.py
│       │   └── migrations/
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── html_exporter.py
│       │   │   ├── pdf_exporter.py
│       │   │   ├── json_exporter.py
│       │   │   ├── csv_exporter.py
│       │   │   ├── stix_exporter.py
│       │   │   └── misp_exporter.py
│       │   └── templates/
│       ├── security/
│       │   ├── read_only.py
│       │   ├── filename_sanitizer.py
│       │   ├── sandbox.py
│       │   ├── redaction.py
│       │   └── custody.py
│       └── utils/
│           ├── hashing.py
│           ├── timeconv.py             # FILETIME, TZ
│           ├── units.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/
│   │   ├── evtx_samples/              # public EVTX samples
│   │   ├── sigma_rules/
│   │   └── third_party_exports/
│   └── gui/
├── resources/
│   ├── icons/
│   ├── rules/
│   │   ├── bundled/                   # SigmaHQ + built-in
│   │   ├── sequences/                 # stateful rules
│   │   └── allowlists/
│   ├── attack/
│   │   └── enterprise-attack.json     # STIX bundle
│   ├── geoip/
│   │   └── README.md                  # user provides GeoLite2
│   └── themes/
└── docs/
    ├── architecture.md
    ├── evtx_notes.md
    ├── sigma_notes.md
    ├── attack_notes.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, case mgmt, EVTX reader, events table, basic ingestion | 3 weeks |
| **P1 — Normalization** | Provider mappings (Security, System, Sysmon, PowerShell), message rendering, FTS index | 4 weeks |
| **P2 — Correlation Core** | Sigma loader + compiler, SQL backend, correlation view, ATT&CK mapping | 5 weeks |
| **P3 — Timeline & Pivots** | Timeline view (LOD), pivot panel, saved filters | 3 weeks |
| **P4 — Sequences** | Stateful sequence engine, sequence rule DSL, memory bounds | 4 weeks |
| **P5 — Enrichment** | GeoIP, IOC, process tree, logon session, opt-in external | 3 weeks |
| **P6 — Entity Graph & Heatmap** | Entity store, graph view, MITRE heatmap | 4 weeks |
| **P7 — Rule Manager** | Import/browse/test Sigma rules, allowlists, false-positive suppression | 3 weeks |
| **P8 — Third-Party Ingest** | Chainsaw, Hayabusa, Velociraptor JSON importers | 2 weeks |
| **P9 — Live Channels** | wevtapi reader, live collection, incremental correlation | 3 weeks |
| **P10 — Reporting** | HTML/PDF attack narrative, JSON/CSV/STIX/MISP, redaction | 3 weeks |
| **P11 — Hardening** | Parser fuzzing, sandboxing, read-only enforcement, packaging | 4 weeks |
| **P12 — Polish** | Performance (sharding, FTS tuning), i18n, docs, accessibility | 3 weeks |

**Total:** ~43 weeks (single senior dev) / ~22 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: FILETIME conversion, BinXML template decode, provider field mapping, Sigma compilation, sequence state machine, scoring, allowlist matching.
- **Integration**: run against public EVTX samples (EVTX-ATTACK-SAMPLES, Mordor, OTRF Security-Datasets, Sysmon samples) with known ground truth; validate correlation hits.
- **GUI**: `pytest-qt` for wizard flows, table filtering, timeline zoom, graph interaction.
- **Property-based**: Hypothesis for timestamp round-trips, Sigma predicate equivalence, sequence window boundaries.
- **Performance**: benchmark on 10 GB EVTX (100M+ events); regression CI if ingest throughput drops > 15%.
- **Security**: fuzz EVTX parser (chunk headers, BinXML, substitution arrays) with AFL++ / Atheris; malformed chunks, cyclic templates, huge substitution arrays.
- **Correlation correctness**: golden-rule tests — known malicious dataset → expected correlation set; known benign dataset → no false positives (or documented ones).
- **Cross-validation**: compare Sigma hits against `chainsaw` and `hayabusa` on the same EVTX.

---

## 13. Open Questions / Decisions Pending

1. **`python-evtx` vs custom parser** — `python-evtx` is mature but slow. Recommend: vendor + patch for speed; custom streaming parser for hot paths.
2. **Message rendering** — full provider message tables are large (~200 MB). Recommend: bundle common providers; fetch others from host on Windows; fallback to structured fields.
3. **Live channel support on Linux/macOS** — not available (no `wevtapi`). Recommend: Windows-only; document.
4. **External enrichment default** — off. Recommend: explicit opt-in per case with audit log; document legal implications.
5. **Very large cases (>500M events)** — SQLite per-case may hit limits. Recommend: sharding by month/host; document; v2 explores DuckDB/Parquet.
6. **Sigma backend** — `pySigma-backend-sqlite` is young. Recommend: custom SQL backend tuned for our schema; fall back to streaming for unsupported features.
7. **Sequence DSL** — standardize on Sigma correlation rules (Sigma v2 spec) where possible; extend only if needed.
8. **STIX/MISP mapping** — define mapping for events, correlations, entities; recommend: v1 minimal (correlations + indicators), v2 richer.
9. **License** — `python-evtx` (Apache 2.0); SigmaHQ rules (Detection Rule License); GeoLite2 (CC BY-SA 4.0 with attribution); verify redistribution.

---

## 14. Glossary

- **EVTX** — Windows XML Event Log file format.
- **BinXML** — Binary XML encoding used inside EVTX records.
- **Channel** — Logical log stream (Security, System, Sysmon/Operational, ...).
- **Provider** — Component that writes events (Microsoft-Windows-Security-Auditing, ...).
- **EventID** — Numeric event code within a provider.
- **FILETIME** — 100-ns intervals since 1601-01-01 UTC.
- **Sysmon** — Microsoft Sysinternals system monitoring driver; rich telemetry.
- **Sigma** — Vendor-neutral detection rule format.
- **ATT&CK** — MITRE Adversarial Tactics, Techniques & Common Knowledge.
- **Tactic / Technique / Sub-technique** — ATT&CK hierarchy (TA0006 / T1003 / T1003.001).
- **ECS** — Elastic Common Schema (inspiration for our unified schema).
- **FTS5** — SQLite full-text search extension.
- **WEF** — Windows Event Forwarding.
- **wevtapi** — Windows Event Log API.
- **LOD** — Level of Detail (rendering optimization).
- **Chain of custody** — Audit trail proving evidence integrity.
- **IOC** — Indicator of Compromise.
- **MISP** — Malware Information Sharing Platform.
- **STIX** — Structured Threat Information Expression.

---

*End of document.*