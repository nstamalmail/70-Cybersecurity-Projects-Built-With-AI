# Architecture: Network Forensics — PCAP-to-Story Tool (GUI-Based Solution)

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** PCAP/PCAPNG ingestion, session reconstruction, and narrative timeline generation
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **PCAP-to-Story Tool (P2S)** is a GUI-driven desktop application for network forensics analysts who need to transform raw packet captures into a coherent, human-readable narrative of network activity. It ingests `.pcap` and `.pcapng` files, reconstructs TCP/UDP sessions, decodes application-layer protocols (HTTP, DNS, TLS, SMB, SMTP, FTP), extracts transferred files, and produces a chronological "story" timeline that links events across flows.

The tool is designed around four principles:

1. **Read-only ingestion** — source captures never modified; all analysis in a case directory.
2. **Story-first output** — the primary deliverable is a narrative timeline, not a raw packet list.
3. **Session-aware correlation** — events are grouped by TCP stream / UDP conversation, then linked by IP, host, user-agent, and timestamp.
4. **Optional TLS decryption** — supports `SSLKEYLOGFILE` integration for decrypting TLS 1.3 traffic where keys are available .

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Case Mgmt │ │ Capture   │ │ Story     │ │ Session   │ │ Report  │ │
│  │  View     │ │ Loader    │ │ Timeline  │ │ Browser   │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Protocol  │ │ File      │ │ Flow      │ │ DNS       │ │ Console │ │
│  │ Explorer  │ │ Carver    │ │ Graph     │ │ Timeline  │ │         │ │
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
│                     Analysis / Reconstruction Layer                  │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Packet Parser  │ │ Session        │ │ Protocol Decoders        │  │
│  │ (dpkt/scapy)   │ │ Reassembler    │ │ (HTTP, DNS, TLS, SMB,    │  │
│  │ PCAP/PCAPNG    │ │ (TCP/UDP)      │ │  SMTP, FTP, HTTP/2)      │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ File Carver (HTTP, SMB, FTP, TFTP) + Magic-byte extraction    │  │
│  └────────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Story Engine: event correlation, dedup, timeline construction │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Case DB    │ │ Carved     │ │ Session    │ │ Story Timeline     │ │
│  │ (SQLite)   │ │ Files      │ │ Index      │ │ Store              │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     OS / Runtime Abstraction Layer                   │
│  File I/O (read-only) · TLS keylog integration · TZ handling         │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `CaseManagerView` | Create/open cases; analyst metadata; chain-of-custody; case directory selection. |
| `CaptureLoaderView` | Drag-and-drop `.pcap`/`.pcapng`; auto-detect format via magic bytes (PCAP: `0xA1B2C3D4`; PCAPNG: `0x0A0D0D0A`) . Display packet count, time range, link types, interfaces (PCAPNG). |
| `StoryTimelineView` | **Primary view.** Chronological narrative: each event (HTTP request, DNS query, TLS handshake, file transfer) shown as a card with timestamp, source/destination, protocol, and summary. Filterable by protocol, host, or keyword. |
| `SessionBrowserView` | List of TCP/UDP conversations with byte counts, duration, state (established/closed/reset). Click to drill into stream contents. |
| `ProtocolExplorerView` | Tree of decoded protocol layers; click a node to filter the story timeline to related events. |
| `FileCarverView` | Extracted files from HTTP, SMB, FTP, TFTP; preview images/text; hash on carve. |
| `FlowGraphView` | Interactive graph of IP-to-IP communication; edge thickness = bytes, color = protocol mix. |
| `DnsTimelineView` | Dedicated DNS query timeline: query name, type, response, TTL, resolver. |
| `SearchFilterBar` | Full-text search (FTS5) across story events, HTTP URIs, DNS names, file contents. |
| `TlsKeysPanel` | Load `SSLKEYLOGFILE`; show decryption status per session; flag sessions where keys are missing . |
| `ReportBuilderView` | Export story as HTML/PDF/JSON/CSV; include carved files manifest with SHA-256. |
| `ConsoleView` | Live log tail; parser warnings; decryption stats. |

**Key UI Patterns**
- Story timeline uses a virtualized list (Qt `QListView` with custom delegate); each "card" renders protocol-specific summary.
- Session browser uses `QAbstractTableModel` — virtualized for millions of packets.
- TLS decryption status badge per session: 🔓 decrypted, 🔒 encrypted (no keys), ⚠️ partial.
- Right-click pivots: "Show all traffic from this host", "Show all HTTP to this domain", "Extract files from this session", "Find DNS queries for this name".

### 3.2 Orchestration Layer

**Ingest Queue**
- Priority queue with worker pool.
- Job = `(job_id, capture_path, filters, tls_keylog_path, case_id)`.
- Persisted to SQLite for crash recovery.

**Pipeline Engine (staged)**
```
[Capture Reader] → [Packet Parser] → [Session Reassembler] → [Protocol Decoder]
       → [File Carver] → [Story Engine] → [Writer] → [Indexer]
```
- Stages connected by bounded queues (back-pressure aware).
- Capture reader streams packets; never loads entire file into memory.

**Scheduler**
- Packet parsing parallelized across capture chunks (if capture is split).
- Session reassembly serialized per TCP stream (stateful); parallel across streams.
- Protocol decoding parallelized after reassembly.

### 3.3 Capture Reader Layer

**Format support**
- **PCAP**: magic numbers `0xA1B2C3D4` (microsecond, native), `0xD4C3B2A1` (microsecond, swapped), `0xA1B23C4D` (nanosecond, native), `0x4D3CB2A1` (nanosecond, swapped) .
- **PCAPNG**: magic `0x0A0D0D0A`; supports multiple interfaces, per-interface metadata (name, description, OS), comments, nanosecond precision .
- **Auto-detection**: never trust file extension; inspect magic bytes .

**Streaming**
- Read packet-by-packet using `dpkt.pcap.Reader` / `dpkt.pcapng.Reader` or `pyshark` for complex dissectors .
- For very large captures (>10 GB), optional BPF pre-filtering to reduce scope.

**Link-layer handling**
- Ethernet (LINKTYPE 1), Linux SLL, raw IP, 802.11 (with radiotap).
- PCAPNG per-interface link type honored.

### 3.4 Session Reassembly Layer

**TCP Reassembly**
- Bidirectional stream reconstruction per `tcp.stream`.
- Handle retransmissions, out-of-order packets, missing segments.
- Buffer management: bounded per-stream buffer (default 64 MB); eviction on overflow with warning.
- Use a robust reassembler (e.g., `pcapkit` or custom) — do not naively concatenate payloads .

**UDP "Sessions"**
- Conversation grouping by 5-tuple; no reassembly (UDP is message-oriented), but per-conversation packet ordering preserved.

**Connection lifecycle**
- Detect SYN, SYN-ACK, FIN, RST.
- Track connection start/end timestamps, byte counts, duration.
- Handle mid-stream capture start (no SYN observed).

**Output: `Session` objects**
```python
@dataclass
class Session:
    session_id: str
    protocol: str          # 'tcp' or 'udp'
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    start_ts: datetime
    end_ts: datetime
    client_bytes: int
    server_bytes: int
    state: str             # 'established', 'closed', 'reset', 'partial'
    client_stream: bytes   # reassembled
    server_stream: bytes
```

### 3.5 Protocol Decoder Layer

| Protocol | Decoder | Events Extracted |
|---|---|---|
| **HTTP/1.1** | Parse request line, headers, body | Method, URI, Host, User-Agent, Status, Content-Type, Content-Length, body  |
| **HTTP/2** | HPACK decompression, frame parsing | Headers, stream IDs, data frames  |
| **DNS** | Parse query/response | Query name, type, response IPs, TTL, rcode  |
| **TLS** | Handshake parsing (SNI, JA3), optional decryption | SNI, cipher suites, certificate subjects, decrypted HTTP  |
| **SMB/SMB2** | Parse negotiate, tree connect, read/write | File paths, share names, transferred files  |
| **SMTP** | Parse commands, DATA | MAIL FROM, RCPT TO, subject, attachments |
| **FTP** | Parse commands | USER, PASS, RETR, STOR, file transfers |
| **TFTP** | Parse opcodes | Read/write requests, filenames |
| **ICMP** | Parse type/code | Echo request/reply, unreachable messages |

**Decoder interface**
```python
class ProtocolDecoder(ABC):
    name: str
    def detect(self, session: Session) -> float:
        """Return confidence 0.0-1.0 that this protocol is present."""
    def decode(self, session: Session) -> Iterator[StoryEvent]:
        """Yield story events extracted from the session."""
```

**Dynamic Protocol Detection (DPD)**
- Try decoders in priority order; accept if confidence > threshold.
- Fallback: heuristic content matching (e.g., `GET `, `POST `, `HTTP/`).

### 3.6 File Carver Layer

**HTTP file extraction**
- `tshark --export-objects http,DIR` equivalent: reassemble chunked transfer-encoding, decompress gzip/deflate, join multipart bodies, write one file per request/response .
- HTTP/2 uses separate dispatcher: `http2` .

**SMB file extraction**
- Parse SMB/SMB2 read/write operations; reassemble file from chunks.

**FTP file extraction**
- Parse RETR/STOR commands; reassemble data channel.

**TFTP file extraction**
- Parse WRQ/RRQ; reassemble blocks.

**Magic-byte carving**
- Scan reassembled stream buffers for known file headers (JPEG, PNG, PDF, ZIP, PE, ELF) .
- Extract from stream start to known footer or size.

**Output**
- Carved files written to case directory `carved/` with SHA-256 hash.
- File metadata stored in SQLite: `session_id`, `protocol`, `original_name`, `content_type`, `size`, `sha256`.

### 3.7 Story Engine

**Purpose**: Transform decoded protocol events into a coherent narrative timeline.

**Event types**
```python
@dataclass
class StoryEvent:
    event_id: str
    case_id: str
    session_id: str
    ts: datetime
    protocol: str          # 'http', 'dns', 'tls', 'smb', ...
    event_type: str        # 'request', 'response', 'query', 'handshake', 'file_transfer'
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    summary: str           # human-readable, e.g., "GET /index.html from example.com"
    host: str | None
    uri: str | None
    user_agent: str | None
    content_type: str | None
    status_code: int | None
    bytes_sent: int
    bytes_received: int
    carved_file_path: str | None
    tags: list[str]
```

**Correlation**
- Link DNS queries to subsequent HTTP/TLS connections by resolved IP + timestamp proximity.
- Link HTTP requests to TLS handshakes (same session).
- Group events by "activity session" (gap threshold, e.g., 30 s of inactivity starts a new activity).

**Dedup**
- Hash event content; skip duplicates (e.g., retransmitted HTTP responses).

**Timeline construction**
- Sort all events by `ts`.
- Optional "compression" of repetitive events (e.g., 100 DNS queries to same domain → one summary event with count).

### 3.8 TLS Decryption Layer

**Key sources**
- `SSLKEYLOGFILE` from browser or proxy .
- User-provided keylog file.

**Decryption**
- Use `tshark` with `-o tls.keylog_file:/path/to/keys.log` .
- Alternative: `pyshark` with keylog option.

**Limitations**
- TLS 1.3 with ephemeral keys requires keylog.
- QUIC/HTTP3 decryption not supported (different key log format) .
- Sessions without keys remain encrypted and are marked as such.

### 3.9 Storage Layer

**Case Directory Layout**
```
cases/<case_id>/
├── case.db                      # SQLite: cases, captures, sessions, events, carved files
├── manifest.json                # Case metadata
├── source_ref.txt               # Path + hash of source PCAP(s)
├── carved/
│   ├── http/
│   ├── smb/
│   ├── ftp/
│   └── magic/
├── reports/
│   ├── story.html
│   ├── story.pdf
│   ├── story.json
│   ├── timeline.csv
│   └── manifest.csv             # SHA-256 of carved files
└── logs/
    └── session.log
```

**SQLite Schema (abridged)**
```sql
CREATE TABLE cases (
  id TEXT PRIMARY KEY, name TEXT, analyst TEXT,
  created_at TIMESTAMP
);
CREATE TABLE captures (
  id TEXT PRIMARY KEY, case_id TEXT,
  path TEXT, sha256 TEXT, size INTEGER,
  format TEXT,             -- 'pcap' or 'pcapng'
  packet_count INTEGER,
  first_ts TIMESTAMP, last_ts TIMESTAMP,
  link_types_json TEXT,
  FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE TABLE sessions (
  id TEXT PRIMARY KEY, case_id TEXT, capture_id TEXT,
  protocol TEXT, src_ip TEXT, src_port INTEGER,
  dst_ip TEXT, dst_port INTEGER,
  start_ts TIMESTAMP, end_ts TIMESTAMP,
  client_bytes INTEGER, server_bytes INTEGER,
  state TEXT,
  tls_decrypted INTEGER DEFAULT 0,
  FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE TABLE story_events (
  id INTEGER PRIMARY KEY, case_id TEXT, session_id TEXT,
  ts TIMESTAMP, protocol TEXT, event_type TEXT,
  src_ip TEXT, dst_ip TEXT,
  host TEXT, uri TEXT, user_agent TEXT,
  status_code INTEGER, content_type TEXT,
  summary TEXT, bytes_sent INTEGER, bytes_received INTEGER,
  carved_file_id INTEGER,
  tags_json TEXT,
  FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE INDEX idx_events_ts ON story_events(ts);
CREATE INDEX idx_events_proto ON story_events(protocol);
CREATE INDEX idx_events_host ON story_events(host);
CREATE VIRTUAL TABLE events_fts USING fts5(
  summary, uri, user_agent, tags_json,
  content='story_events', content_rowid='id'
);
CREATE TABLE carved_files (
  id INTEGER PRIMARY KEY, case_id TEXT, session_id TEXT,
  protocol TEXT, original_name TEXT, content_type TEXT,
  size INTEGER, sha256 TEXT, local_path TEXT
);
```

### 3.10 Canonical Data Model

See `Session` (§3.4), `StoryEvent` (§3.7), and `CarvedFile` (§3.6).

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, model updates
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Ingest Pool (QThreadPool, N workers)
  ├── Capture reader thread      (streaming, sequential per file)
  ├── Packet parser threads      (parallel across chunks if split)
  ├── Session reassembler        (stateful per stream; parallel across streams)
  ├── Protocol decoder threads   (parallel after reassembly)
  ├── File carver thread         (parallel across sessions)
  └── Story engine thread        (serial; correlation is global)
       │
       └── Bounded queues between stages (back-pressure)
```

**Rules**
- Capture reader is single-threaded per file (sequential packet order).
- Session reassembly is stateful per stream; parallelize across streams, serialize within a stream.
- TLS decryption runs before protocol decoding (or is integrated into `tshark` invocation).
- SQLite in WAL mode; single writer.
- Cancellation: cooperative `threading.Event` checked every N packets.
- Memory bounds: session buffers capped; LRU eviction with warning.

---

## 5. Workflow: End-to-End User Journey

1. **Create Case** → name, analyst, evidence description.
2. **Load Capture** → drag/drop `.pcap`/`.pcapng`; auto-detect format; display packet count, time range, link types .
3. **Load TLS Keys** (optional) → select `SSLKEYLOGFILE`; flag which sessions can be decrypted .
4. **Ingest** → pipeline runs; sessions reassembled; protocols decoded; files carved.
5. **Explore Story** → primary timeline view; filter by protocol/host; drill into sessions.
6. **Pivot** → click host → all events for that host; click DNS query → subsequent connections to resolved IP.
7. **Inspect Carved Files** → preview images/text; verify SHA-256; export.
8. **Report** → generate HTML/PDF/JSON story report with timeline, session summaries, carved files manifest.
9. **Archive** → zip case dir; sign with case HMAC.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| Malicious PCAP (parser exploit) | Parser runs in subprocess with resource limits; fuzz-tested; no `eval`; depth caps on protocol nesting. |
| Malicious carved files (malware) | Carved files never auto-executed; previews rendered in sandbox; written with `.carved` extension by default. |
| Path traversal from HTTP filenames | Sanitize filenames; reject `..`, `/`, `\`, NUL; reserved-name mangling on Windows . |
| TLS keylog sensitive | Keys used in-memory only; never logged; decrypted content redacted in exports by default. |
| Sensitive data in captures | Redaction profile for exports (usernames, passwords, credit cards). |
| Evidence tampering | SHA-256 of source capture; manifest signed; append-only custody log. |
| Large capture DoS | Configurable caps; streaming; memory-bounded queues; optional BPF pre-filter. |
| Decompression bombs (gzip in HTTP) | Max decompressed size limit; abort on overflow. |

---

## 7. Extensibility Points

1. **New protocol decoder** — implement `ProtocolDecoder` ABC; register in `decoders/registry.py`.
2. **New file carver** — implement `FileCarver` ABC.
3. **New TLS key source** — implement `TlsKeyProvider` ABC (keylog, NSS, custom).
4. **New exporter** — `Exporter` ABC; HTML/PDF/JSON/CSV shipped.
5. **Custom correlation rule** — Python plugin with access to case DB.
6. **Custom story template** — Jinja2 for report narrative.

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time (cold) | < 2 s |
| UI responsiveness | < 100 ms for any user action |
| Packet parse throughput | ≥ 1M packets/s (simple parse) |
| Session reassembly throughput | ≥ 100 MB/s |
| Protocol decode throughput | ≥ 500k events/s |
| Memory footprint | < 2 GB RSS regardless of capture size |
| Capture size support | Up to 100 GB (streaming) |
| Session count support | Up to 10M sessions |
| Story event count | Up to 100M events (FTS optional) |
| Concurrency | Up to 8 workers (configurable) |
| Crash recovery | Resume ingest from last committed packet within 5 s |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable, screen-reader labels |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Rich ecosystem (`dpkt`, `scapy`, `pyshark`) |
| GUI | PySide6 (LGPL) | Commercial-friendly; mature Model/View |
| Packet parsing | `dpkt` (fast) + `pyshark` (complex dissectors) | dpkt is lightweight; pyshark wraps tshark for TLS decryption  |
| TLS decryption | `tshark` with `tls.keylog_file` | Robust, standard  |
| Session reassembly | Custom + `pcapkit` for reference | Full control over memory bounds |
| HTTP/2 | `h2` library for HPACK | Mature |
| DNS | `dnspython` | Parsing and validation |
| SMB | `impacket` (optional) | SMB/SMB2 parsing |
| DB | SQLite (WAL + FTS5) | Embedded, ACID, FTS |
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
p2s/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── p2s/
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
│       │   │   ├── capture_loader.py
│       │   │   ├── story_timeline.py
│       │   │   ├── session_browser.py
│       │   │   ├── protocol_explorer.py
│       │   │   ├── file_carver.py
│       │   │   ├── flow_graph.py
│       │   │   ├── dns_timeline.py
│       │   │   ├── tls_keys.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── story_events_model.py
│       │   │   ├── sessions_table_model.py
│       │   │   └── carved_files_model.py
│       │   └── widgets/
│       │       ├── event_card.py
│       │       ├── hex_viewer.py
│       │       ├── preview_pane.py
│       │       └── filter_bar.py
│       ├── core/
│       │   ├── ingest/
│       │   │   ├── capture_reader.py
│       │   │   ├── format_detect.py
│       │   │   └── chunker.py
│       │   ├── parse/
│       │   │   ├── packet_parser.py
│       │   │   └── link_layer.py
│       │   ├── session/
│       │   │   ├── tcp_reassembly.py
│       │   │   ├── udp_grouping.py
│       │   │   └── lifecycle.py
│       │   ├── decoders/
│       │   │   ├── base.py
│       │   │   ├── registry.py
│       │   │   ├── http1.py
│       │   │   ├── http2.py
│       │   │   ├── dns.py
│       │   │   ├── tls.py
│       │   │   ├── smb.py
│       │   │   ├── smtp.py
│       │   │   ├── ftp.py
│       │   │   ├── tftp.py
│       │   │   └── icmp.py
│       │   ├── carve/
│       │   │   ├── http_carver.py
│       │   │   ├── smb_carver.py
│       │   │   ├── ftp_carver.py
│       │   │   ├── magic_carver.py
│       │   │   └── sanitize.py
│       │   ├── story/
│       │   │   ├── engine.py
│       │   │   ├── correlation.py
│       │   │   ├── dedup.py
│       │   │   └── timeline.py
│       │   ├── tls/
│       │   │   ├── keylog.py
│       │   │   └── decryptor.py
│       │   ├── pipeline/
│       │   │   ├── stages.py
│       │   │   ├── queue.py
│       │   │   └── scheduler.py
│       │   └── dedup/
│       │       ├── fastcdc.py
│       │       └── hash_index.py
│       ├── storage/
│       │   ├── case_db.py
│       │   ├── session_store.py
│       │   ├── event_store.py
│       │   ├── carved_store.py
│       │   ├── fts_index.py
│       │   └── migrations/
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── html_exporter.py
│       │   │   ├── pdf_exporter.py
│       │   │   ├── json_exporter.py
│       │   │   └── csv_exporter.py
│       │   └── templates/
│       ├── security/
│       │   ├── filename_sanitizer.py
│       │   ├── sandbox.py
│       │   ├── redaction.py
│       │   └── custody.py
│       └── utils/
│           ├── hashing.py
│           ├── timeconv.py
│           ├── units.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/
│   │   ├── pcaps/
│   │   │   ├── http.pcap
│   │   │   ├── dns.pcap
│   │   │   ├── tls.pcap
│   │   │   └── smb.pcap
│   │   └── keylogs/
│   └── gui/
├── resources/
│   ├── icons/
│   ├── redaction_profiles/
│   │   ├── default.yaml
│   │   └── pii_strict.yaml
│   └── themes/
└── docs/
    ├── architecture.md
    ├── pcap_notes.md
    ├── tls_notes.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, case mgmt, capture loader, format detection, story timeline stub | 2 weeks |
| **P1 — Packet & Session** | Packet parser, TCP/UDP session reassembly, session browser | 3 weeks |
| **P2 — HTTP + DNS** | HTTP/1.1 decoder, DNS decoder, story engine v1 | 3 weeks |
| **P3 — File Carving** | HTTP file extraction, magic-byte carving, carved files view | 2 weeks |
| **P4 — TLS** | Keylog integration, decryption via tshark, decrypted HTTP parsing | 2 weeks |
| **P5 — More Protocols** | SMB, SMTP, FTP, TFTP, ICMP decoders | 4 weeks |
| **P6 — Story Engine v2** | Correlation (DNS → connection → HTTP), dedup, activity sessions | 3 weeks |
| **P7 — Flow Graph & DNS Timeline** | Visualization views | 2 weeks |
| **P8 — HTTP/2** | HPACK decompression, HTTP/2 decoder | 2 weeks |
| **P9 — Reporting** | HTML/PDF/JSON story report, manifest, redaction | 3 weeks |
| **P10 — Hardening** | Parser fuzzing, sandboxing, memory bounds, packaging | 4 weeks |
| **P11 — Polish** | Performance (streaming, FTS tuning), i18n, docs, accessibility | 3 weeks |

**Total:** ~33 weeks (single senior dev) / ~17 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: PCAP/PCAPNG magic detection, TCP reassembly (retransmission, out-of-order), HTTP parsing, DNS parsing, file carving, story correlation.
- **Integration**: run against public PCAP corpora (Wireshark SampleCaptures, Malware-Traffic-Analysis, pcaps from DFIR challenges) with known ground truth.
- **GUI**: `pytest-qt` for timeline rendering, session drill-down, carved file preview.
- **Property-based**: Hypothesis for reassembly edge cases, timestamp ordering.
- **Performance**: benchmark on 10 GB PCAP; regression CI if throughput drops > 15%.
- **Security**: fuzz PCAP parser (malformed headers, truncated packets, huge lengths) with AFL++ / Atheris; fuzz protocol decoders.
- **Cross-validation**: compare session reassembly against `tshark -z follow,tcp,raw,N`; compare HTTP extraction against `tshark --export-objects` .

---

## 13. Open Questions / Decisions Pending

1. **dpkt vs pyshark vs scapy** — dpkt is fast but lacks complex dissectors; pyshark wraps tshark (handles TLS decryption but slower). Recommend: dpkt for fast path, pyshark for TLS/complex protocols .
2. **TLS decryption** — rely on `tshark` subprocess or implement in-process? Recommend: subprocess for v1 (robust); evaluate `pyshark` integration.
3. **HTTP/2 priority** — defer to v2 unless captures show significant HTTP/2 traffic.
4. **SMB parsing** — `impacket` is powerful but GPL-adjacent; verify license for commercial redistribution.
5. **QUIC/HTTP3** — not supported in v1; document limitation.
6. **Very large captures (>100 GB)** — streaming with bounded memory; consider capture splitting or BPF pre-filter.
7. **Story narrative generation** — rule-based v1; consider LLM-assisted summarization in v2 (with privacy safeguards).

---

## 14. Glossary

- **PCAP** — Packet CAPture format (libpcap).
- **PCAPNG** — PCAP Next Generation format; supports multiple interfaces .
- **TCP reassembly** — reconstructing a byte stream from out-of-order/retransmitted segments .
- **Session** — a TCP connection or UDP conversation (5-tuple).
- **SSLKEYLOGFILE** — file containing TLS master secrets for decryption .
- **HPACK** — HTTP/2 header compression.
- **SNI** — Server Name Indication (TLS extension).
- **JA3** — TLS client fingerprint.
- **Carving** — extracting files from raw bytes by signature .
- **DPD** — Dynamic Protocol Detection.
- **FTS5** — SQLite full-text search extension.
- **Chain of custody** — audit trail proving evidence integrity.

---

*End of document.*