# Architecture: Custom Proxy Server (HTTP/SOCKS5) — GUI-Based Solution

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** Multi-protocol proxy server (HTTP CONNECT + SOCKS5) with traffic logging, filtering, and report generation
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Custom Proxy Server (CPS)** is a GUI-driven desktop application for security professionals, developers, and network administrators who need a **controllable, inspectable proxy server** supporting both HTTP CONNECT tunneling and SOCKS5 protocols. It provides real-time traffic visibility, configurable filtering, and multi-format report export.

Proxy servers are foundational network infrastructure. HTTP CONNECT establishes tunnels for HTTPS traffic through explicit proxies, while SOCKS5 provides a lower-level framework for TCP and UDP relaying with built-in authentication support . Production tools like `pproxy2` and `wsocks-core` demonstrate that Python can deliver high-performance proxy implementations using asyncio and uvloop .

The tool is designed around four principles:

1. **Dual-protocol support** — HTTP CONNECT for browser/HTTPS tunneling; SOCKS5 for application-level relaying and UDP support.
2. **Observable by default** — every request is logged with timestamp, source, destination, method, status, and byte counts, enabling traffic analysis and troubleshooting .
3. **Controllable** — domain/IP blocklists, authentication, and connection rules configurable via GUI.
4. **Report-ready** — structured export (JSON, CSV, HTML, PDF) of traffic logs and proxy statistics.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Server    │ │ Live      │ │ Filter    │ │ Auth      │ │ Report  │ │
│  │ Config    │ │ Traffic   │ │ Rules     │ │ Manager   │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Stats     │ │ Connection│ │ Domain    │ │ Log       │ │ Console │ │
│  │ Dashboard │ │ Detail    │ │ Blocklist │ │ Viewer    │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Proxy      │ │ Traffic    │ │ Filter     │ │ Event Bus / Log    │ │
│  │ Controller │ │ Logger     │ │ Engine     │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Proxy Core Layer                                 │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ HTTP CONNECT   │ │ SOCKS5         │ │ Protocol Auto-           │  │
│  │ Handler        │ │ Handler        │ │ Detection                │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Async TCP Relay (asyncio) + Connection Pool                    │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Traffic    │ │ Config     │ │ Auth       │ │ Report Store       │ │
│  │ Log Store  │ │ Store      │ │ Store      │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `ServerConfigView` | Configure listen address/port, protocol mode (HTTP only, SOCKS5 only, both on same port with auto-detection ), worker count, TLS settings. |
| `LiveTrafficView` | **Primary view.** Real-time table of proxied connections: timestamp, client IP, destination host/port, protocol, bytes up/down, duration, status. Virtualized for high volume. |
| `FilterRulesView` | Domain/IP blocklist management. Support exact match, wildcard, regex. Import/export rules. |
| `AuthManagerView` | User/password authentication for SOCKS5 and HTTP proxies. Per-user access rules. |
| `StatsDashboardView` | Aggregate metrics: total connections, active connections, bytes transferred, top destinations, error rate. |
| `ConnectionDetailView` | Drill-down for a selected connection: full request/response metadata (for HTTP), byte counts, timing breakdown. |
| `DomainBlocklistView` | Manage blocked domains with reason tags; preview impact. |
| `LogViewerView` | Browse historical traffic logs with search/filter by date, destination, client. |
| `ReportBuilderView` | **Export interface.** Select date range, metrics to include, format (JSON/CSV/HTML/PDF). |
| `ConsoleView` | Live server log: connections accepted, errors, auth failures. |

**Key UI Patterns:**
- **Live streaming**: connections appear in the table as they complete (or while active).
- **Protocol badges**: HTTP (blue), SOCKS5 (green), both (purple).
- **Status color coding**: success (green), blocked (red), error (orange).
- **Click-to-drill**: click connection → show full metadata and timing.
- **Server start/stop**: prominent control with status indicator (running/stopped/error).

### 3.2 Orchestration Layer

**Proxy Controller**
- Manages server lifecycle: start, stop, restart, reload config.
- Spawns asyncio event loop in background thread.
- Enforces listen address/port binding.

**Traffic Logger**
- Records every connection: start time, end time, client address, destination, protocol, bytes sent/received, status.
- Buffers writes to avoid blocking proxy traffic .
- Rotates log files by date/size.

**Filter Engine**
- Evaluates destination against blocklist rules before allowing connection.
- Supports exact hostname, wildcard (`*.example.com`), IP/CIDR, regex.
- Returns block reason for logging.

### 3.3 Proxy Core Layer

**HTTP CONNECT Handler**
- Parses HTTP CONNECT request: `CONNECT host:port HTTP/1.1` .
- Establishes TCP connection to target.
- Returns `HTTP/1.1 200 Connection Established`.
- Relays bytes bidirectionally until either side closes.

**SOCKS5 Handler**
- Implements RFC 1928 handshake: version negotiation, auth method selection, CONNECT request .
- Supports username/password authentication (RFC 1929).
- Establishes TCP connection to target.
- Relays bytes bidirectionally.
- UDP ASSOCIATE support (optional; complex, v2).

**Protocol Auto-Detection**
- Peek first byte of client connection:
  - `0x05` → SOCKS5 handshake.
  - `C` (0x43, 'C' from "CONNECT") → HTTP CONNECT.
- Enables single-port operation .

**Async TCP Relay**
- Uses `asyncio.open_connection()` for target connections.
- Uses `asyncio.StreamReader/StreamWriter` for bidirectional relay.
- Connection pooling for repeated destinations (optional performance optimization ).

```python
async def relay(reader, writer):
    while True:
        data = await reader.read(65536)
        if not data:
            break
        writer.write(data)
        await writer.drain()
    writer.close()
```

### 3.4 Storage Layer

**Data directory:**
```
~/.cps/
├── config.json                 # Server configuration
├── logs/
│   └── traffic_YYYYMMDD.jsonl  # Traffic log (JSON Lines)
├── blocklists/
│   └── *.txt                   # Domain/IP blocklists
├── auth/
│   └── users.json              # User credentials (hashed)
├── reports/
│   └── <report_id>.pdf
└── logs/
    └── cps.log
```

**Traffic log schema (JSON Lines):**
```json
{"timestamp":"2026-09-20T14:23:11Z","client_ip":"192.168.1.100","dest_host":"api.example.com","dest_port":443,"protocol":"HTTP_CONNECT","bytes_up":1240,"bytes_down":45678,"duration_ms":234,"status":"ALLOWED"}
```

**Configuration model:**
```python
@dataclass
class ProxyConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    protocol_mode: str = "auto"       # 'http', 'socks5', 'auto'
    auth_required: bool = False
    auth_users: dict[str, str] = field(default_factory=dict)
    blocklist_enabled: bool = True
    blocklist_paths: list[str] = field(default_factory=list)
    log_enabled: bool = True
    max_connections: int = 1000
```

### 3.5 Report Generation & Export

**Export formats:**

| Format | Use Case | Library |
|---|---|---|
| **JSON** | Machine-readable, SIEM ingestion | `json` |
| **CSV** | Spreadsheet analysis | `csv` |
| **HTML** | Shareable, formatted report | Jinja2 |
| **PDF** | Formal deliverable | WeasyPrint |

**Report sections:**
1. **Header**: Server config, report period, generation timestamp.
2. **Executive Summary**: Total connections, unique destinations, bytes transferred, blocked count.
3. **Top Destinations**: Top 20 by connection count and by bytes.
4. **Top Clients**: Top clients by connection count.
5. **Blocked Connections**: List with block reason.
6. **Error Summary**: Connection failures, auth failures.
7. **Full Traffic Log**: Filterable table (optional, for CSV/JSON).

**Structured output (inspired by proxy logging patterns ):**
```
[PROXY REPORT] 2026-09-20 00:00 - 2026-09-20 23:59
Server: 127.0.0.1:8080 (auto-detect)

[SUMMARY]
Total connections: 1,247
Bytes up: 2.3 MB | Bytes down: 145.7 MB
Blocked: 23 | Errors: 5

[TOP DESTINATIONS]
api.example.com:443     | 456 connections | 89.2 MB
cdn.static.com:443      | 234 connections | 45.1 MB

[BLOCKED]
malware-c2.com          | 12 connections | rule: blocklist_1
```

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, traffic table updates, report builder
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Proxy Event Loop Thread (single, asyncio)
  ├── Accept client connections
  ├── Handle protocol handshake
  ├── Relay data
  └── Emit connection events via thread-safe queue

Logger Thread (single)
  └── Drain queue → write to disk (buffered)
```

**Rules:**
- Proxy runs in dedicated thread with its own asyncio event loop.
- UI updates marshalled via Qt signals (queued connection).
- Traffic log writes buffered to avoid blocking relay.
- Cancellation: graceful shutdown closes listener, drains connections.

---

## 5. Workflow: End-to-End User Journey

1. **Configure Server** → set listen address/port, protocol mode (HTTP/SOCKS5/auto).
2. **Set Authentication** (optional) → add users for SOCKS5/HTTP auth.
3. **Configure Blocklist** → import domain/IP blocklist.
4. **Start Server** → server binds and begins accepting connections.
5. **Configure Client** → point browser/app to proxy (`http://127.0.0.1:8080` or `socks5://127.0.0.1:8080`).
6. **Observe Traffic** → live table populates with connections.
7. **Drill into Connection** → view full metadata for a specific connection.
8. **Review Blocked** → see blocked connection attempts with reasons.
9. **Export Report** → generate JSON/CSV/HTML/PDF for the session.
10. **Stop Server** → graceful shutdown.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Open proxy abuse** | Default bind to `127.0.0.1`; warn if binding to `0.0.0.0`; authentication strongly recommended for public binds. |
| **Authentication bypass** | SOCKS5 username/password per RFC 1929; HTTP `Proxy-Authorization` header. |
| **Credential storage** | Passwords hashed (bcrypt/scrypt); never stored plaintext. |
| **Traffic log sensitivity** | Logs contain destination hostnames; local storage; optional encryption at rest. |
| **TLS interception** | **Not implemented** — this tool tunnels TLS, does not intercept it. Document clearly. |
| **Resource exhaustion** | Max connection limit; idle timeout; backpressure via asyncio. |

---

## 7. Extensibility Points

1. **New protocol** — implement `ProxyProtocol` ABC (HTTP, SOCKS5, SOCKS4, Shadowsocks).
2. **New filter rule type** — extend `FilterRule` (exact, wildcard, regex, CIDR).
3. **New export format** — `Exporter` ABC (JSON, CSV, HTML, PDF, SARIF).
4. **Upstream chaining** — forward to another proxy (ChainRouter pattern ).
5. **TLS fingerprinting** — optional; requires `curl_cffi` .

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 1 s |
| Connection acceptance | < 10 ms |
| Relay throughput | > 100 MB/s (loopback) |
| Concurrent connections | 1,000+ |
| Memory footprint | < 200 MB RSS |
| Log write throughput | > 10,000 events/s (buffered) |
| Report generation | < 5 s |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly |
| Async I/O | `asyncio` (stdlib) | Standard, no deps |
| SOCKS5 | Custom (RFC 1928) or `python-socks` | Protocol correctness |
| HTTP CONNECT | Custom parser | Lightweight |
| Report export | `json`, `csv`, `Jinja2`, `WeasyPrint` | Multi-format |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
cps/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── cps/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── server_config.py
│       │   │   ├── live_traffic.py
│       │   │   ├── filter_rules.py
│       │   │   ├── auth_manager.py
│       │   │   ├── stats_dashboard.py
│       │   │   ├── connection_detail.py
│       │   │   ├── domain_blocklist.py
│       │   │   ├── log_viewer.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── traffic_table_model.py
│       │   │   └── blocklist_table_model.py
│       │   └── widgets/
│       │       ├── protocol_badge.py
│       │       ├── status_indicator.py
│       │       └── server_control.py
│       ├── core/
│       │   ├── proxy/
│       │   │   ├── server.py
│       │   │   ├── http_connect.py
│       │   │   ├── socks5.py
│       │   │   ├── auto_detect.py
│       │   │   └── relay.py
│       │   ├── filter/
│       │   │   ├── engine.py
│       │   │   └── rules.py
│       │   ├── auth/
│       │   │   └── users.py
│       │   └── logging/
│       │       └── traffic_logger.py
│       ├── storage/
│       │   ├── config_store.py
│       │   ├── log_store.py
│       │   └── blocklist_store.py
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── json_exporter.py
│       │   │   ├── csv_exporter.py
│       │   │   ├── html_exporter.py
│       │   │   └── pdf_exporter.py
│       │   └── templates/
│       └── utils/
│           ├── net.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── gui/
├── resources/
│   ├── icons/
│   └── default_blocklists/
└── docs/
    ├── architecture.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, server config, HTTP CONNECT handler, basic relay | 2 weeks |
| **P1 — SOCKS5** | RFC 1928 handshake, auth, CONNECT command | 2 weeks |
| **P2 — Auto-Detect** | Single-port protocol detection, unified listener | 1 week |
| **P3 — Live Traffic** | Traffic table, streaming updates, connection detail | 2 weeks |
| **P4 — Filtering** | Blocklist engine, rules UI, import/export | 1 week |
| **P5 — Auth** | User management, password hashing, per-user rules | 1 week |
| **P6 — Reporting** | JSON/CSV/HTML/PDF export, report templates | 2 weeks |
| **P7 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~14 weeks (single senior dev) / ~7 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: SOCKS5 handshake parsing, HTTP CONNECT parsing, filter rule evaluation, auth verification.
- **Integration**: full proxy flow with `curl --proxy` (HTTP) and `curl --socks5` (SOCKS5).
- **GUI**: `pytest-qt` for traffic table streaming, config changes, report builder.
- **Performance**: benchmark relay throughput; verify no blocking under load.
- **Security**: verify auth bypass prevention; verify blocklist enforcement; verify no credential leakage in logs.

---

## 13. Open Questions / Decisions Pending

1. **asyncio vs threads** — asyncio provides better scalability ; threads are simpler. Recommend: asyncio for v1.
2. **UDP support** — SOCKS5 UDP ASSOCIATE is complex; HTTP has no UDP. Recommend: v2 feature.
3. **TLS interception** — **explicitly out of scope**; this is a tunneling proxy, not a MITM proxy. Document clearly.
4. **Upstream chaining** — forward to another proxy. Recommend: v2; ChainRouter pattern available .
5. **Log rotation** — implement size/date-based rotation; default: daily.

---

## 14. Glossary

- **HTTP CONNECT** — HTTP method establishing a TCP tunnel through a proxy .
- **SOCKS5** — Socket Secure version 5; framework for TCP/UDP relaying with authentication .
- **Auto-Detect** — Single port accepting both HTTP and SOCKS5 by inspecting first bytes .
- **RFC 1928** — SOCKS5 protocol specification.
- **RFC 1929** — SOCKS5 username/password authentication.
- **Relay** — Bidirectional byte forwarding between client and target.
- **Blocklist** — Rules denying connections to specified destinations.
- **Tunneling** — Encapsulating traffic through a proxy without inspection.

---

*End of document.*