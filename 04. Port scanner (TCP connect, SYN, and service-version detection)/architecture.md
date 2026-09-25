# Architecture: Port Scanner (TCP Connect, SYN, Service-Version Detection) — GUI-Based Solution

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** Multi-mode port scanning (TCP Connect, SYN) with service/version detection and multi-format report export
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Multi-Mode Port Scanner (MMPS)** is a GUI-driven desktop application for security professionals, penetration testers, and network administrators who need to perform authorized network reconnaissance with both **TCP Connect** and **SYN (half-open)** scan techniques, enriched with **service and version detection** capabilities.

Port scanning remains the foundational reconnaissance technique in offensive and defensive security. The choice of scan technique matters: **TCP Connect scans** complete the full three-way handshake, are reliable and require no special privileges, but are trivially logged by the target. **SYN scans** send only the initial SYN packet, never completing the handshake — making them faster, stealthier, and less likely to be logged by application-layer systems, but requiring raw socket privileges (root/admin) and Npcap on Windows.

Service-version detection elevates a port scanner from "which doors are open" to "what is running behind them." Tools like `python-nmap` wrap Nmap's powerful `-sV` probe engine to identify service names and version strings. This capability is essential for vulnerability assessment: knowing port 22 is open is useful; knowing it runs OpenSSH 7.2p1 is actionable.

The tool is designed around four principles:

1. **Technique-appropriate scanning** — TCP Connect for unprivileged/quiet reliability; SYN for speed and stealth when privileges permit.
2. **Service intelligence** — banner grabbing and Nmap-based version detection to enrich raw port state.
3. **Structured reporting** — multi-format export (TXT, JSON, CSV, HTML/PDF) with findings grouped by severity and actionable next steps.
4. **Responsive GUI** — threaded scanning with live progress, results streaming, and cancellation support so the UI never blocks.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Target    │ │ Scan      │ │ Results   │ │ Service   │ │ Report  │ │
│  │ Config    │ │ Progress  │ │ Table     │ │ Detail    │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Port      │ │ Scan Mode │ │ Host      │ │ Risk      │ │ Console │ │
│  │ Range     │ │ Selector  │ │ Summary   │ │ Indicators│ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Scan       │ │ Result     │ │ Service    │ │ Event Bus / Log    │ │
│  │ Scheduler  │ │ Aggregator │ │ Enricher   │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Scanning Engine Layer                            │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ TCP Connect    │ │ SYN Scanner    │ │ Service/Version          │  │
│  │ Scanner        │ │ (Scapy)        │ │ Detection (Nmap)         │  │
│  │ (socket)       │ │                │ │                          │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Thread Pool (concurrent.futures) + Progress Callbacks          │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Scan       │ │ Result     │ │ Profile    │ │ Report Store       │ │
│  │ History    │ │ Cache      │ │ Store      │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `TargetConfigView` | Configure scan target: hostname/IP, CIDR range, or multiple targets. Resolve hostname to IP. Display resolved address. |
| `ScanModeSelector` | Choose scan technique: TCP Connect (default, no privileges), SYN (requires root/admin + Npcap on Windows), or both for comparison. |
| `PortRangeView` | Port specification: top 1000, full range (1-65535), custom range (`1-1024`, `22,80,443`), or specific list. |
| `ScanProgressView` | **Primary status view.** Progress bar, ports scanned/total, open ports found, elapsed time, ETA. Cancel button. Live scan log. |
| `ResultsTableView` | **Primary results view.** Sortable table: port, state (open/closed/filtered), service name, version, banner snippet. Color-coded by state (green=open, gray=closed, yellow=filtered). |
| `ServiceDetailView` | Drill-down for selected port: full banner, service version, CVE hints (if enabled), recommended enumeration commands. |
| `HostSummaryView` | Per-host summary: total open ports, critical services, OS fingerprint (if available), risk score. |
| `RiskIndicatorsView` | Flagged risky services: outdated versions, commonly vulnerable services (RDP, SMB, Telnet), unexpected ports. |
| `ReportBuilderView` | **Export interface.** Format selection (TXT, JSON, CSV, HTML, PDF), include/exclude sections, template selection. |
| `ConsoleView` | Live backend log: scan progress messages, errors, privilege warnings. |

**Key UI Patterns:**
- **Live results streaming**: ports appear in the results table as they are scanned, not batched at the end.
- **State color coding**: Open (green), Closed (gray), Filtered (yellow/orange).
- **Service badges**: Icon or label indicating service type (HTTP, SSH, RDP, SMB, etc.).
- **Click-to-drill**: click a port row → show banner, version, recommended commands.
- **Responsive cancellation**: Cancel button halts scan gracefully and preserves partial results.

### 3.2 Orchestration Layer

**Scan Scheduler**
- Manages the scan lifecycle: configuration → target resolution → port iteration → enrichment → aggregation.
- Spawns worker threads from a `ThreadPoolExecutor` (default: 100-200 workers).
- Progress callbacks emitted via Qt signals to update the GUI without blocking.

**Result Aggregator**
- Collects port results as they complete.
- Deduplicates (if scanning multiple targets).
- Groups by host, sorts by port state and number.

**Service Enricher**
- For open ports, triggers banner grabbing or Nmap `-sV` probe.
- Parses version strings from banners (SSH, FTP, SMTP, HTTP Server headers).
- Maps known services to CVEs and recommended enumeration commands.

### 3.3 Scanning Engine Layer

**TCP Connect Scanner**

Uses Python's `socket` module. For each port:
1. Create TCP socket.
2. Set timeout (default: 1.0s).
3. Call `sock.connect_ex((host, port))`.
4. `result == 0` → **OPEN**.
5. `result != 0` → **CLOSED** or **FILTERED** (cannot distinguish reliably).
6. On open, optionally send `\r\n` and read up to 1024 bytes for banner.

**Advantages:** No special privileges required; reliable; works everywhere.
**Disadvantages:** Full handshake completes (logged by target); slower due to OS TCP stack overhead and TIME_WAIT states.

```python
def scan_port_connect(host, port, timeout=1.0):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            banner = grab_banner(sock)
            return (port, "OPEN", banner)
        return (port, "CLOSED", None)
```

**SYN Scanner (Stealth)**

Uses Scapy raw sockets. For each port:
1. Craft TCP SYN packet: `IP(dst=host)/TCP(dport=port, flags="S")`.
2. Send and await response (`sr1` with timeout).
3. **SYN-ACK received** (flags `0x12`) → **OPEN**; send RST to clean up.
4. **RST received** (flags `0x14`) → **CLOSED**.
5. **No response** → **FILTERED**.

**Advantages:** Faster (no OS TCP overhead); stealthier (handshake never completes); full range feasible.
**Disadvantages:** Requires root/admin; requires Npcap on Windows.

```python
def scan_port_syn(host, port, timeout=1):
    pkt = IP(dst=host)/TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None:
        return (port, "FILTERED", None)
    if resp.haslayer(TCP):
        if resp[TCP].flags == 0x12:  # SYN-ACK
            send(IP(dst=host)/TCP(dport=port, flags="R"), verbose=0)
            return (port, "OPEN", None)
        elif resp[TCP].flags == 0x14:  # RST
            return (port, "CLOSED", None)
    return (port, "FILTERED", None)
```

**Service/Version Detection**

Two complementary approaches:

1. **Banner Grabbing (built-in)**: For open TCP ports, connect and read the service banner. Parse common patterns (SSH, FTP, SMTP, HTTP Server headers).
2. **Nmap Integration (`python-nmap`)**: Wrap Nmap's `-sV` probe engine for comprehensive version detection.

```python
import nmap
scanner = nmap.PortScanner()
scanner.scan(target_ip, arguments='-sV')
# Access: scanner[host]['tcp'][port]['name'], ['product'], ['version']
```

**Note:** Nmap version detection relies on what the service reports and may be inaccurate. Banner grabbing provides the raw data for manual verification.

### 3.4 Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, results table updates, progress bar
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Scan Worker Pool (ThreadPoolExecutor, 100-200 workers)
  ├── Each worker scans one port
  ├── Emits (port, state, banner) via callback
  └── Callback marshals to GUI thread via Qt signal

Enrichment Worker (single thread or small pool)
  └── Runs Nmap -sV on open ports after scan completes
```

**Critical threading rule:** GUI updates must happen on the main thread. Worker threads emit signals; Qt's `QueuedConnection` marshals them safely. Never call `widget.setText()` directly from a worker.

**Progress updates:** Use `QThreadPool` + `QRunnable` with signals, or `concurrent.futures` with a callback that emits Qt signals.

**Cancellation:** A shared `threading.Event` checked by each worker. On cancel, workers stop, partial results are preserved, and the progress bar halts.

### 3.5 Storage Layer

**Data directory:**
```
~/.mmps/
├── scans/
│   └── <scan_id>.json          # Full scan result
├── profiles/
│   └── *.yaml                  # Scan profiles (target, ports, mode)
├── reports/
│   └── <scan_id>_report.pdf
└── logs/
    └── mmps.log
```

**Scan result model:**
```python
@dataclass
class PortResult:
    port: int
    state: str                    # 'OPEN', 'CLOSED', 'FILTERED'
    service: str | None           # 'ssh', 'http', 'rdp', ...
    version: str | None           # 'OpenSSH 7.2p1'
    banner: str | None
    cves: list[str]
    risk_level: str               # 'critical', 'high', 'medium', 'low', 'info'

@dataclass
class ScanResult:
    scan_id: str
    target: str
    resolved_ip: str
    scan_mode: str                # 'tcp_connect', 'syn'
    timestamp: datetime
    ports: list[PortResult]
    os_fingerprint: str | None
    total_scanned: int
    open_count: int
    duration_seconds: float
```

### 3.6 Report Generation & Export

**Export formats and purpose:**

| Format | Use Case | Library |
|---|---|---|
| **TXT** | Human-readable, quick review | stdlib |
| **JSON** | Machine-readable, API integration | `json` |
| **CSV** | Spreadsheet analysis, SOC ingestion | `csv` |
| **HTML** | Shareable, formatted report | Jinja2 |
| **PDF** | Formal deliverable, archival | WeasyPrint |

**Report sections:**
1. **Header**: Target, scan date, scan mode, operator, authorization note.
2. **Executive Summary**: Total open ports, critical services, risk score.
3. **Open Ports Table**: Port, state, service, version.
4. **Service Details**: Banner, version, CVE hints, next-step commands.
5. **Risk Findings**: Flagged services with severity.
6. **Methodology**: Scan technique used, limitations (e.g., filtered ports ambiguous).
7. **Appendix**: Full port list, raw scan log.

**Structured output example (inspired by portscanner.py v3):**
```
[HOST] 10.10.10.1
[OS] Linux (TTL-based fingerprint)

[OPEN PORTS]
22/tcp   open    ssh      OpenSSH 7.2p1
80/tcp   open    http     Apache httpd 2.4.18

[CRITICAL FINDINGS]
- Port 22: OpenSSH 7.2p1 — CVE-2016-6210 (medium)

[NEXT STEPS]
- ssh: ssh-audit 10.10.10.1
- http: gobuster dir -u http://10.10.10.1 -w /usr/share/wordlists/dirb/common.txt
```

---

## 4. Security Considerations

| Concern | Mitigation |
|---|---|
| **Authorization** | Prominent disclaimer on first launch; operator must confirm authorized target. Tool logs authorization acknowledgment. |
| **Privilege escalation (SYN)** | SYN scan requires root/admin; document clearly. On Windows, requires Npcap. |
| **Rate limiting** | Configurable packets-per-second throttle for SYN scan to avoid overwhelming targets. |
| **Scan legality** | Document that scanning systems without authorization is illegal in many jurisdictions. |
| **Data sensitivity** | Scan results may reveal internal network topology; local-only storage; optional encryption at rest. |
| **False positives** | Filtered ports are ambiguous (firewall drop vs no response); document limitation. |

---

## 5. Extensibility Points

1. **New scan technique** — implement `ScanTechnique` ABC (Connect, SYN, FIN, XMAS, NULL, UDP).
2. **New service probe** — add banner pattern to `service_patterns.yaml`.
3. **New export format** — `Exporter` ABC (TXT, JSON, CSV, HTML, PDF, SARIF).
4. **CVE enrichment** — integrate NVD API or Vulners for live CVE lookup.
5. **OS fingerprinting** — add ICMP TTL-based fingerprinting.

---

## 6. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 2 s |
| TCP Connect scan (1000 ports) | < 10 s (100 workers, 1s timeout) |
| SYN scan (1000 ports) | < 5 s (with throttle) |
| Full range (65535 ports) | < 5 min |
| Service version detection | < 30 s per host |
| Report generation | < 5 s |
| Memory footprint | < 300 MB RSS |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 7. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly; QThreadPool for workers |
| TCP Connect | `socket` (stdlib) | No dependencies |
| SYN Scan | `scapy` | Standard raw packet crafting |
| Version Detection | `python-nmap` | Wraps Nmap -sV |
| Banner Grabbing | `socket` + regex | Lightweight fallback |
| Concurrency | `concurrent.futures.ThreadPoolExecutor` | Simple, bounded |
| Export | `json`, `csv`, `Jinja2`, `WeasyPrint` | Multi-format |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 8. Directory Structure (Source Tree)

```
mmps/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── mmps/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── target_config.py
│       │   │   ├── scan_progress.py
│       │   │   ├── results_table.py
│       │   │   ├── service_detail.py
│       │   │   ├── host_summary.py
│       │   │   ├── risk_indicators.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   └── ports_table_model.py
│       │   └── widgets/
│       │       ├── state_badge.py
│       │       ├── progress_panel.py
│       │       └── scan_mode_selector.py
│       ├── core/
│       │   ├── scanners/
│       │   │   ├── base.py
│       │   │   ├── tcp_connect.py
│       │   │   ├── syn_scanner.py
│       │   │   └── banner_grabber.py
│       │   ├── enrichment/
│       │   │   ├── nmap_service.py
│       │   │   ├── cve_lookup.py
│       │   │   └── service_patterns.yaml
│       │   ├── scheduler/
│       │   │   └── scan_controller.py
│       │   └── aggregation/
│       │       └── aggregator.py
│       ├── storage/
│       │   ├── scan_store.py
│       │   └── profile_store.py
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── txt_exporter.py
│       │   │   ├── json_exporter.py
│       │   │   ├── csv_exporter.py
│       │   │   ├── html_exporter.py
│       │   │   └── pdf_exporter.py
│       │   └── templates/
│       └── utils/
│           ├── ports.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── gui/
├── resources/
│   ├── icons/
│   └── wordlists/
└── docs/
    ├── architecture.md
    └── user_guide.md
```

---

## 9. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, target config, TCP Connect scanner, basic results table | 2 weeks |
| **P1 — Progress & Threading** | ThreadPoolExecutor, live progress, cancellation | 1 week |
| **P2 — SYN Scanner** | Scapy integration, privilege detection, state mapping | 2 weeks |
| **P3 — Service Detection** | Banner grabbing, python-nmap integration | 2 weeks |
| **P4 — Results & Detail** | Service detail view, host summary, risk indicators | 1 week |
| **P5 — Reporting** | TXT/JSON/CSV/HTML/PDF export, report templates | 2 weeks |
| **P6 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~13 weeks (single senior dev) / ~7 weeks (2 devs).

---

## 10. Testing Strategy

- **Unit**: port parsing, state mapping, banner parsing, export format generation.
- **Integration**: full scan against `scanme.nmap.org` (authorized test target) and local `127.0.0.1` with known listeners.
- **GUI**: `pytest-qt` for progress updates, results table sorting, cancellation.
- **Threading**: verify no UI blocking during scan; verify progress callbacks arrive on main thread.
- **Cross-validation**: compare TCP Connect and SYN results against each other and against `nmap` CLI on the same target.

---

## 11. Open Questions / Decisions Pending

1. **Nmap dependency** — require Nmap installation for version detection, or make optional? Recommend: optional; banner grabbing works without it; Nmap enriches when available.
2. **Windows SYN support** — requires Npcap; document installation. Fallback to TCP Connect if unavailable.
3. **UDP scanning** — out of scope v1; add in v2 with UDP probes.
4. **OS fingerprinting** — ICMP TTL-based is lightweight; Nmap `-O` is more accurate but requires privileges. Recommend: TTL-based for v1.
5. **CVE database** — static mapping vs live NVD API. Recommend: static for v1; API optional.

---

## 12. Glossary

- **TCP Connect Scan** — Full three-way handshake; reliable, logged, no privileges needed.
- **SYN Scan** — Half-open scan; sends SYN, reads SYN-ACK/RST; stealthy, fast, requires raw sockets.
- **Filtered** — No response received; firewall likely dropping packets; state ambiguous.
- **Banner Grabbing** — Reading the initial data a service sends on connection.
- **Service/Version Detection** — Probing open ports to identify software name and version.
- **ThreadPoolExecutor** — Python concurrency primitive for bounded parallel execution.
- **Raw Socket** — Socket that bypasses OS TCP stack; required for SYN scan.
- **Npcap** — Windows packet capture library required by Scapy for raw sockets.
- **Top 1000 Ports** — Most commonly used TCP ports, derived from Nmap frequency data.

---

*End of document.*