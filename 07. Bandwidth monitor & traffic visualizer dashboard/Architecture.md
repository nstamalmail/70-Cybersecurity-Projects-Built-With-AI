# Architecture: Bandwidth Monitor & Traffic Visualizer Dashboard (GUI-Based Solution)

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows primary, Linux/macOS with platform-specific providers)
**Core Capability:** Real-time per-process and per-interface bandwidth monitoring with historical visualization and multi-format report export
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Bandwidth Monitor & Traffic Visualizer Dashboard (BMTVD)** is a GUI-driven desktop application for network administrators, security analysts, and power users who need to understand exactly **where their bandwidth is going**. It provides real-time per-process attribution, per-interface monitoring, historical trend visualization, and comprehensive report generation.

The tool addresses a persistent visibility gap: system-wide bandwidth monitors tell you "the network is busy" without answering "which application is responsible" or "is this normal for this hour?" Production tools like LibreNMS and Akvorado provide interface-level and flow-level visibility, but they require server infrastructure and don't answer the desktop-level question of per-process attribution . Meanwhile, Python's `psutil` library exposes both system-wide network counters (`net_io_counters(pernic=True)`) and per-process connection data (`net_connections()`), enabling a desktop tool to bridge this gap .

The tool is designed around four principles:

1. **Attribution-first** — every byte is attributed to a specific process, interface, or connection; no unattributed "system" traffic unless it genuinely cannot be resolved.
2. **Visualization as insight** — data is worthless without context; the dashboard provides time-series graphs, top-consumer rankings, and anomaly highlighting .
3. **Report-ready** — structured export (JSON, CSV, HTML, PDF) of bandwidth statistics, top consumers, and trends for capacity planning and incident documentation .
4. **Platform-aware accuracy** — uses native APIs where available (`psutil` for cross-platform, Windows-specific APIs for enhanced accuracy) .

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Live      │ │ Process   │ │ Interface │ │ History   │ │ Report  │ │
│  │ Dashboard │ │ Breakdown │ │ Monitor   │ │ Charts    │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Top       │ │ Connection│ │ Alerts /  │ │ Tray      │ │ Console │ │
│  │ Consumers │ │ Detail    │ │ Thresholds│ │ Widget    │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Poll       │ │ Data       │ │ Alert      │ │ Event Bus / Log    │ │
│  │ Scheduler  │ │ Aggregator │ │ Engine     │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Data Collection Layer                            │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ psutil         │ │ Platform       │ │ Connection               │  │
│  │ Collector      │ │ Enhancer       │ │ Tracker                  │  │
│  │ (cross-plat)   │ │ (Windows APIs) │ │ (PID→socket mapping)     │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Time-Series│ │ Config     │ │ Alert      │ │ Report Store       │ │
│  │ Store      │ │ Store      │ │ Log        │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `LiveDashboardView` | **Primary view.** Real-time summary: total upload/download rate, active connections, top 5 consumers, per-interface rates. Auto-refreshing cards. |
| `ProcessBreakdownView` | Table of processes with network activity: PID, name, upload rate, download rate, total bytes, connection count. Sortable, filterable . |
| `InterfaceMonitorView` | Per-interface statistics: interface name, bytes sent/received, packets, errors, drops. Uses `psutil.net_io_counters(pernic=True)` . |
| `HistoryChartsView` | Time-series graphs: total bandwidth over time, per-process trend lines, per-interface traffic. Zoomable, pan-able. |
| `TopConsumersView` | Ranked lists: top processes by bandwidth, top destinations by connection count, top interfaces by traffic volume. |
| `ConnectionDetailView` | Drill-down for a selected process: active TCP/UDP connections with remote addresses, states, and per-connection byte estimates . |
| `AlertsThresholdsView` | Configure per-process or per-interface bandwidth thresholds (e.g., "alert if chrome.exe exceeds 10 MB/s"). |
| `TrayWidget` | Minimize to system tray; tooltip shows current total rate; quick pause/resume monitoring. |
| `ReportBuilderView` | **Export interface.** Date range selection, format (JSON/CSV/HTML/PDF), sections to include (summary, top consumers, trends, raw data). |
| `ConsoleView` | Live log: collection errors, permission warnings, provider status. |

**Key UI Patterns:**
- **Real-time streaming**: rates update every N seconds (default: 2s) without UI blocking.
- **Color-coded rates**: green (low), yellow (medium), red (high) based on configurable thresholds.
- **Click-to-drill**: click a process → show its connections; click an interface → filter history to that interface.
- **Sparkline previews**: miniature trend lines in the top-consumers view.
- **Responsive tables**: `QAbstractTableModel` with sorting and filtering.

### 3.2 Orchestration Layer

**Poll Scheduler**
- `QTimer` fires every `poll_interval` seconds.
- Each tick: (1) snapshot `psutil` network counters, (2) snapshot process connections, (3) compute deltas, (4) update models, (5) evaluate alerts.
- Runs in worker thread to avoid UI blocking.

**Data Aggregator**
- Merges system-wide counters with per-process connection data.
- Computes per-process bandwidth deltas using cumulative counters .
- Handles process exit (attribute last known traffic to a "terminated" bucket).

**Alert Engine**
- Per-process/interface rules: `{target_pattern, direction, threshold_bytes_per_sec, action}`.
- Evaluated after each tick; cooldown to prevent alert storms.
- Alerts logged to JSONL for report inclusion.

### 3.3 Data Collection Layer

**psutil Collector (cross-platform)**

Uses `psutil` for core data collection :
```python
import psutil

# System-wide per-interface
net_io = psutil.net_io_counters(pernic=True)
# {'eth0': netio(bytes_sent=..., bytes_recv=...), ...}

# Per-process connections
conns = psutil.net_connections(kind='tcp')
# [sconn(laddr=..., raddr=..., status='ESTABLISHED', pid=1254), ...]

# Process I/O (note: this is disk I/O, not network)
proc = psutil.Process(pid)
io = proc.io_counters()  # bytes_sent/recv are DISK, not network
```

**Critical accuracy note:** `psutil.Process.io_counters()` reports **disk I/O**, not network I/O. Per-process network bandwidth requires mapping connections to processes and estimating per-connection bytes, or using platform-specific APIs .

**Platform Enhancer (Windows)**

For Windows, optional use of `GetPerTcpConnectionEStats` via `ctypes` for per-connection byte counts, improving attribution accuracy beyond connection-count-based estimates .

**Connection Tracker**
- Maps `(local_addr, local_port, remote_addr, remote_port)` → PID using `psutil.net_connections()`.
- Associates cumulative per-process byte estimates with connection lifetime.
- Tracks connection start/end times for duration analysis.

### 3.4 Storage Layer

**Data directory:**
```
~/.bmtvd/
├── config.json                 # Settings
├── logs/
│   ├── bandwidth_YYYYMMDD.jsonl  # Time-series snapshots
│   └── alerts.jsonl              # Alert events
├── history/
│   └── bmtvd.db                # SQLite for long-term storage
├── reports/
│   └── <report_id>_report.pdf
└── logs/
    └── bmtvd.log
```

**Time-series record:**
```python
@dataclass
class BandwidthSnapshot:
    timestamp: datetime
    total_upload_bps: float
    total_download_bps: float
    interfaces: dict[str, InterfaceStats]
    processes: list[ProcessBandwidth]
    connection_count: int

@dataclass
class ProcessBandwidth:
    pid: int
    name: str
    exe: str | None
    upload_bps: float
    download_bps: float
    bytes_sent: int
    bytes_recv: int
    connection_count: int

@dataclass
class InterfaceStats:
    name: str
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    errors_in: int
    errors_out: int
    drops_in: int
    drops_out: int
```

### 3.5 Canonical Data Model

See `BandwidthSnapshot`, `ProcessBandwidth`, and `InterfaceStats` above.

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, dashboard updates, charts
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Collection Worker (single thread)
  ├── psutil.net_io_counters()
  ├── psutil.net_connections()
  ├── psutil.process_iter() for metadata
  └── Emit BandwidthSnapshot via signal

History Writer (single thread)
  └── Append snapshot to JSONL (buffered)
```

**Rules:**
- Collection runs off main thread; `psutil` calls can be slow with many processes.
- UI updates marshalled via Qt signals.
- History writes buffered; flush every N snapshots or on interval.
- Cancellation: `threading.Event` checked between process iterations.

---

## 5. Report Generation & Export

**Export formats:**

| Format | Use Case | Library |
|---|---|---|
| **JSON** | Machine-readable, SIEM ingestion | `json` |
| **CSV** | Spreadsheet analysis, long-term storage | `csv` |
| **HTML** | Shareable, formatted report | Jinja2 |
| **PDF** | Formal deliverable, capacity planning | WeasyPrint / ReportLab  |

**Report sections:**
1. **Header**: Report period, generation timestamp, system info.
2. **Executive Summary**: Total bytes transferred, average rates, peak rates, top consumer.
3. **Interface Statistics**: Per-interface bytes, packets, errors, drops.
4. **Top Processes**: Ranked by total bandwidth, with upload/download breakdown.
5. **Trend Analysis**: Hourly/daily bandwidth patterns (if historical data available).
6. **Alert Summary**: Threshold breaches during period.
7. **Appendix**: Raw data export (optional).

**Structured output example (inspired by production monitoring dashboards):**
```
[BANDWIDTH REPORT] 2026-09-20 00:00 - 2026-09-20 23:59
Interface: eth0

[SUMMARY]
Total transferred: 14.7 GB (↑2.3 GB / ↓12.4 GB)
Average rate: 1.36 Mbps
Peak rate: 45.2 Mbps (14:23:11)
Active connections: 127

[TOP PROCESSES]
chrome.exe (PID 1234)   | ↑ 456 MB  | ↓ 8.2 GB  | 45 conns
firefox.exe (PID 5678)  | ↑ 123 MB  | ↓ 3.1 GB  | 23 conns
discord.exe (PID 9012)  | ↑ 89 MB   | ↓ 1.2 GB  | 12 conns

[ALERTS]
14:23:11 - chrome.exe exceeded 40 Mbps threshold (45.2 Mbps)
```

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Permission requirements** | `psutil` may require admin/root for full process visibility; document clearly. |
| **Data sensitivity** | Connection logs reveal browsing/communication patterns; local-only storage; optional encryption at rest. |
| **Accuracy limitations** | Per-process network attribution via `psutil` is connection-count-based, not byte-accurate; document limitation . |
| **Resource consumption** | Poll interval configurable; default 2s; CPU overhead < 2%. |
| **Process name spoofing** | Malware can name itself `svchost.exe`; process path and hash shown for verification. |

---

## 7. Extensibility Points

1. **New data source** — implement `Collector` ABC (psutil, Windows ETW, eBPF).
2. **New alert action** — implement `AlertAction` ABC (log, notify, tray, script).
3. **New export format** — `Exporter` ABC (JSON, CSV, HTML, PDF, XLSX) .
4. **Remote monitoring** — optional: send snapshots to remote dashboard.

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 2 s |
| Poll interval | 1–10 s (default 2 s) |
| CPU overhead | < 2% at 2s interval |
| Memory footprint | < 200 MB RSS |
| Process count support | Up to 1,000 processes |
| History retention | 30 days (configurable) |
| Report generation | < 5 s |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly; QThreadPool for workers  |
| Data collection | `psutil` | Cross-platform, standard  |
| Time-series storage | JSONL + optional SQLite | Lightweight; SQLite for long-term |
| Charts | `pyqtgraph` or `matplotlib` | Real-time performance |
| Report export | `json`, `csv`, `Jinja2`, `WeasyPrint` | Multi-format  |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
bmtvd/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── bmtvd/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── live_dashboard.py
│       │   │   ├── process_breakdown.py
│       │   │   ├── interface_monitor.py
│       │   │   ├── history_charts.py
│       │   │   ├── top_consumers.py
│       │   │   ├── connection_detail.py
│       │   │   ├── alerts_thresholds.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── processes_table_model.py
│       │   │   └── interfaces_table_model.py
│       │   └── widgets/
│       │       ├── rate_card.py
│       │       ├── sparkline.py
│       │       └── tray_widget.py
│       ├── core/
│       │   ├── collection/
│       │   │   ├── psutil_collector.py
│       │   │   ├── windows_enhancer.py
│       │   │   └── connection_tracker.py
│       │   ├── aggregation/
│       │   │   └── aggregator.py
│       │   ├── alerts/
│       │   │   └── engine.py
│       │   └── scheduler/
│       │       └── poller.py
│       ├── storage/
│       │   ├── timeseries_store.py
│       │   ├── config_store.py
│       │   └── alert_store.py
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── json_exporter.py
│       │   │   ├── csv_exporter.py
│       │   │   ├── html_exporter.py
│       │   │   └── pdf_exporter.py
│       │   └── templates/
│       └── utils/
│           ├── units.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── gui/
├── resources/
│   ├── icons/
│   └── themes/
└── docs/
    ├── architecture.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, psutil collection, interface monitor, basic process table | 2 weeks |
| **P1 — Dashboard** | Live dashboard, rate cards, top consumers | 1 week |
| **P2 — History & Charts** | Time-series storage, history charts, sparklines | 2 weeks |
| **P3 — Connection Detail** | PID→socket mapping, connection detail view | 1 week |
| **P4 — Alerts** | Threshold configuration, alert engine, tray notifications | 1 week |
| **P5 — Reporting** | JSON/CSV/HTML/PDF export, report templates | 2 weeks |
| **P6 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~12 weeks (single senior dev) / ~6 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: rate computation (delta/interval), unit formatting, alert rule evaluation.
- **Integration**: full collection cycle on known workloads (e.g., `curl` loop, browser streaming).
- **GUI**: `pytest-qt` for dashboard updates, chart rendering, report builder.
- **Cross-validation**: compare `psutil.net_io_counters()` against OS-native tools (`ifconfig`, `netstat`) .
- **Performance**: benchmark with 500+ processes; verify poll interval accuracy.

---

## 13. Open Questions / Decisions Pending

1. **Per-process byte accuracy** — `psutil` gives connection counts, not byte counts per process. Recommend: document limitation; Windows enhancer optional .
2. **Charts library** — `pyqtgraph` (fast, Qt-native) vs `matplotlib` (feature-rich). Recommend: `pyqtgraph` for real-time.
3. **SQLite vs JSONL** — JSONL for simplicity, SQLite for queries. Recommend: JSONL for v1; SQLite for long-term history.
4. **Elevated privileges** — required for full process visibility on Windows. Document; graceful degradation.

---

## 14. Glossary

- **Bandwidth** — Rate of data transfer, typically measured in bits or bytes per second.
- **psutil** — Python cross-platform library for system and process utilities .
- **net_io_counters** — `psutil` function returning cumulative bytes sent/received per interface.
- **net_connections** — `psutil` function returning active connections with owning PID.
- **Per-process attribution** — Associating network traffic with a specific application.
- **Time-series** — Sequence of data points indexed in time order.
- **Sparkline** — Small, word-sized chart showing trend.
- **Top consumer** — Process or interface with highest bandwidth usage.

---

*End of document.*