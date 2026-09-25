# Architecture: Dynamic Analysis Sandbox — Isolated VM + Behavior Logging (GUI-Based Solution)

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS) for GUI; requires virtualization host
**Core Capability:** Automated dynamic analysis of suspicious executables in isolated VMs with comprehensive behavior logging
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Dynamic Analysis Sandbox (DAS)** is a GUI-driven desktop application that orchestrates the execution of suspicious Windows executables in isolated virtual machines while capturing comprehensive behavioral telemetry. It addresses the gap between manual VM-based analysis (slow, error-prone) and full platform solutions like Cuckoo/CAPE (complex, CLI-centric) by providing a focused, analyst-friendly interface for **dynamic triage** .

The tool automates the complete analysis lifecycle: sample submission, VM orchestration from clean snapshots, sample execution with monitoring, behavior collection (API calls, file system, registry, network), and report generation with extracted IOCs .

The tool is designed around four principles:

1. **Isolation first** — analysis VMs use hypervisor-level network isolation (`--nic1 null`), no shared folders, no clipboard/drag-drop, and revert-to-clean-baseline before every run .
2. **Behavior over verdicts** — the output is comprehensive behavioral data, not just a malicious/clean verdict; every API call, file write, and network connection is logged .
3. **Reproducibility** — every analysis runs from the same clean snapshot; results are deterministic and comparable .
4. **Analyst-first UI** — behavior logs are presented as navigable timelines, process trees, and network graphs, not raw JSON dumps.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Sample    │ │ Analysis  │ │ Behavior  │ │ Process   │ │ Report  │ │
│  │ Queue     │ │ Progress  │ │ Timeline  │ │ Tree      │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Network   │ │ File System│ │ Registry  │ │ API Call  │ │ IOC     │ │
│  │ Graph     │ │ Changes   │ │ Changes   │ │ Log       │ │ Summary │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots (async)
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Analysis   │ │ VM Manager │ │ Task Queue │ │ Event Bus / Log    │ │
│  │ Scheduler  │ │ (snapshots)│ │ (priority) │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Guest VM Control Layer                            │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Guest Agent    │ │ Analyzer       │ │ Monitoring Hooks         │  │
│  │ (REST API)     │ │ (execution)    │ │ (API, FS, Registry, Net) │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Hypervisor Abstraction Layer                     │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ VirtualBox     │ │ KVM/QEMU       │ │ VMware (optional)        │  │
│  │ Adapter        │ │ Adapter        │ │ Adapter                  │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Network Simulation (INetSim / FakeNet-NG)                      │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Case DB    │ │ PCAP Store │ │ Dropped    │ │ Report / IOC       │ │
│  │ (SQLite)   │ │            │ │ Files      │ │ Store              │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `SampleQueueView` | Queue of samples pending analysis. Drag-drop submission. Sample metadata (hash, size, type). Queue status: pending/running/completed/failed. |
| `AnalysisProgressView` | Live progress: VM boot, sample execution, behavior collection, teardown. Per-phase timers. Real-time log tail. |
| `BehaviorTimelineView` | **Primary view.** Chronological event stream: process start, file write, registry change, network connection, API call. Filterable by type, process, or keyword. |
| `ProcessTreeView` | Hierarchical process tree from initial sample to all spawned children. Click process to filter timeline to that process. |
| `NetworkGraphView` | Visual graph of network connections: source process → destination IP/port, protocol, bytes. |
| `FileSystemChangesView` | Table of file operations: created, modified, deleted. Path, operation, process, timestamp. |
| `RegistryChangesView` | Table of registry operations: key, value, operation (set/delete), process, timestamp. |
| `ApiCallLogView` | Raw API call sequence: timestamp, process, DLL, function, arguments (truncated), return value. |
| `IOCSummaryView` | Extracted IOCs: URLs, IPs, domains, file paths, registry keys, mutexes, user-agents. Exportable. |
| `ReportBuilderView` | Generate JSON/HTML/PDF behavioral report. Include timeline, process tree, network graph, IOCs. |
| `ConsoleView` | Live host/guest communication log; agent messages; errors. |

**Key UI Patterns**
- Timeline uses virtualized list with protocol-specific event cards.
- Process tree uses `QTreeView` with expand/collapse; color-coded by suspicious API usage.
- Network graph uses `pyqtgraph` or custom Qt item rendering.
- Click-to-pivot: click process → filter timeline; click network connection → filter PCAP; click file write → show file.
- Real-time updates: behavior events appear as they are collected from the guest.

### 3.2 Orchestration Layer

**Analysis Scheduler**
- Manages analysis task lifecycle: queued → VM provisioning → execution → collection → teardown → report.
- One analysis per VM at a time; supports multiple VMs for parallel analysis (configurable) .
- Persisted to SQLite for crash recovery.

**VM Manager**
- Hypervisor abstraction: VirtualBox, KVM/QEMU, VMware .
- Snapshot management: revert to `clean-baseline` before every analysis (non-negotiable) .
- Network isolation: `--nic1 null` (VirtualBox) or no `-netdev` (QEMU) — hypervisor-level, guest cannot override .
- Boot monitoring: wait for guest agent to be ready before sample execution.

**Task Queue**
- Priority queue for sample submission.
- Task = `(task_id, sample_path, analysis_timeout, options, case_id)`.

**Pipeline Engine (staged)**
```
[Sample Intake] → [Hash & Static Preview] → [VM Provision] → [Agent Upload]
       → [Sample Execute] → [Behavior Collect] → [PCAP Capture]
       → [Memory Dump (optional)] → [VM Teardown] → [Report Generate]
```

### 3.3 Guest VM Control Layer

**Guest Agent**
- Python script running inside the VM as a service (auto-start on boot) .
- Provides REST API for:
  - File upload (analyzer, sample)
  - Command execution (start sample)
  - Status reporting
- Communicates with host via isolated network (host-only adapter) .

**Analyzer**
- Python script uploaded to guest at analysis start .
- Executes sample using appropriate **package** (e.g., `exe` → direct execution, `doc` → Office process, `url` → browser) .
- Prepares environment: hides analysis artifacts, disables UAC prompts, sets up monitoring .

**Monitoring Hooks**
- **API Hooking**: Intercept Windows API calls (CreateFile, RegSetValue, CreateProcess, InternetConnect, etc.) .
- **File System Monitoring**: Track file creates, writes, deletes, renames.
- **Registry Monitoring**: Track registry key/value operations.
- **Network Capture**: PCAP capture on host side (virtual adapter) .
- **Process Monitoring**: Track process creation, termination, parent-child relationships.
- **Memory Dump** (optional): Full or targeted memory dump for Volatility analysis .

### 3.4 Network Simulation Layer

**Purpose**: Let malware "call home" safely without real internet access .

**INetSim / FakeNet-NG**
- DNS: Answer all queries with fake IP.
- HTTP/HTTPS/FTP/SMTP: Return canned responses.
- Purpose: Trigger network-dependent behavior (droppers, C2, exfiltration) without real egress .

**Network Configuration**
- Host-only adapter: VM ↔ Host communication only .
- No NAT, no bridged — hypervisor-level isolation .
- Host-side PCAP capture on the virtual interface.

### 3.5 Behavior Collection Layer

**Data captured**

| Category | Fields | Source |
|---|---|---|
| **API Calls** | timestamp, process, DLL, function, args, return | Hook  |
| **File System** | operation, path, size, process, timestamp | Monitor |
| **Registry** | operation, key, value, process, timestamp | Monitor |
| **Network** | src_process, dst_ip, dst_port, protocol, bytes | PCAP  |
| **Process** | pid, ppid, name, path, command_line, start/end | Monitor |
| **Dropped Files** | path, hash, size, source process | Monitor |
| **Screenshots** | timestamped desktop captures | Auxiliary  |

**Behavior event normalization**
```python
@dataclass
class BehaviorEvent:
    event_id: str
    analysis_id: str
    ts: datetime
    event_type: str              # 'api_call', 'file_write', 'registry_set', 'network', 'process_create'
    process_id: int
    process_name: str
    parent_pid: int | None
    dll: str | None              # for api_call
    function: str | None         # for api_call
    arguments: dict | None       # for api_call
    path: str | None             # for file/registry
    operation: str | None        # 'create', 'write', 'delete', 'set'
    src_ip: str | None           # for network
    dst_ip: str | None
    dst_port: int | None
    protocol: str | None
    bytes_sent: int | None
    bytes_received: int | None
    raw: dict
```

### 3.6 Storage Layer

**Case Directory Layout**
```
cases/<case_id>/
├── case.db                      # SQLite: analyses, behavior_events, iocs, dropped_files
├── manifest.json                # Case metadata
├── samples/
│   └── <sha256>.exe             # Reference to original sample (not copied)
├── analyses/
│   └── <analysis_id>/
│       ├── behavior.jsonl       # Append-only behavior log
│       ├── process_tree.json
│       ├── network.pcap
│       ├── dropped_files/
│       ├── memory_dump.raw      # optional
│       ├── screenshots/
│       └── report.json
├── reports/
│   ├── <analysis_id>.html
│   ├── <analysis_id>.pdf
│   └── iocs.csv
└── logs/
    └── session.log
```

**SQLite Schema (abridged)**
```sql
CREATE TABLE analyses (
  id TEXT PRIMARY KEY, case_id TEXT, sha256 TEXT,
  status TEXT, started_at TIMESTAMP, finished_at TIMESTAMP,
  vm_name TEXT, vm_snapshot TEXT,
  error TEXT, FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE TABLE behavior_events (
  id INTEGER PRIMARY KEY, analysis_id TEXT,
  ts TIMESTAMP, event_type TEXT,
  process_id INTEGER, process_name TEXT, parent_pid INTEGER,
  dll TEXT, function TEXT, arguments_json TEXT,
  path TEXT, operation TEXT,
  src_ip TEXT, dst_ip TEXT, dst_port INTEGER, protocol TEXT,
  bytes_sent INTEGER, bytes_received INTEGER,
  raw_json TEXT
);
CREATE INDEX idx_events_analysis ON behavior_events(analysis_id);
CREATE INDEX idx_events_type ON behavior_events(event_type);
CREATE INDEX idx_events_process ON behavior_events(process_id);
CREATE INDEX idx_events_ts ON behavior_events(ts);
CREATE TABLE dropped_files (
  id INTEGER PRIMARY KEY, analysis_id TEXT,
  path TEXT, sha256 TEXT, size INTEGER,
  source_process TEXT, timestamp TIMESTAMP
);
CREATE TABLE iocs (
  id INTEGER PRIMARY KEY, analysis_id TEXT,
  ioc_type TEXT, value TEXT, context_json TEXT
);
```

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, model updates, timeline rendering
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Analysis Worker (single thread per analysis)
  ├── VM provisioning (blocking, but in worker)
  ├── Agent communication (async)
  ├── Sample execution orchestration
  └── Behavior collection (streaming from guest)

Host Monitor Thread (per analysis)
  ├── PCAP capture on virtual adapter
  ├── Behavior event ingestion from guest agent
  └── Writes to SQLite (serialized)
```

**Rules**
- One analysis worker per VM; multiple VMs = multiple workers .
- Guest agent communication is HTTP/REST over isolated network .
- Behavior events stream from guest to host during execution (not batch at end).
- SQLite in WAL mode; single writer per analysis.
- Cancellation: cooperative `threading.Event`; graceful VM teardown on abort.

---

## 5. Workflow: End-to-End User Journey

1. **Prepare Analysis VM** (one-time setup):
   - Install clean Windows VM (Windows 10/11 recommended) .
   - Install guest agent (auto-start) .
   - Install common software (Office, browsers, PDF readers) for realistic environment .
   - Configure network: host-only adapter, no internet .
   - Disable UAC prompts, Windows Defender (or configure to log) .
   - Take snapshot named `clean-baseline` .

2. **Submit Sample**:
   - Drag/drop suspicious executable.
   - Compute hashes (MD5/SHA-1/SHA-256).
   - Optional static preview (PE header, strings) .
   - Select analysis timeout (default: 120s) and options.

3. **Analysis Execution**:
   - Revert VM to `clean-baseline` .
   - Boot VM; wait for agent readiness.
   - Upload analyzer and sample via agent .
   - Start network simulation (INetSim/FakeNet-NG) .
   - Execute sample using appropriate package .
   - Monitor behavior in real-time (API calls, FS, registry, network).
   - Capture PCAP on host side.
   - Optional: memory dump at analysis end .

4. **Review Results**:
   - Timeline view: chronological behavior events.
   - Process tree: parent-child relationships, suspicious API usage.
   - Network graph: connections to external IPs.
   - File system: dropped files, modified system files.
   - Registry: persistence mechanisms.
   - IOC summary: all extracted indicators.

5. **Export**:
   - Behavioral report (JSON/HTML/PDF).
   - IOC export (CSV/JSON/STIX).
   - Dropped files (hashed, quarantined).
   - PCAP for further analysis.

6. **Teardown**:
   - Revert VM to `clean-baseline` (ready for next analysis) .
   - Archive analysis artifacts to case directory.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Malware escape** | Hypervisor-level network isolation (`--nic1 null`); no shared folders; no clipboard/drag-drop; no USB passthrough . |
| **VM reuse** | Never reuse a VM after sample execution; always revert to clean-baseline snapshot . |
| **Sample handling** | Defang at rest: rename `.exe.SAMPLE`, store in password-protected ZIP; never double-click; hash before/after transfer . |
| **Guest agent compromise** | Agent runs with limited privileges; only accepts authenticated requests; host validates all inputs. |
| **Host compromise via guest** | Guest-to-host communication only via agent REST API on isolated network; no file sharing. |
| **Analysis escape via hypervisor** | Keep hypervisor updated; use hardware virtualization (VT-x/AMD-V); disable nested virtualization if not needed. |
| **Data exfiltration from guest** | Network simulation ensures no real egress; PCAP capture on host side only . |
| **Sensitive sample content** | Case directories encrypted at rest (optional); access logged. |
| **Malicious dropped files** | Quarantined in case directory; never executed; hashed; previews sandboxed. |

---

## 7. Extensibility Points

1. **New hypervisor** — implement `HypervisorAdapter` ABC (VirtualBox, KVM, VMware, Azure) .
2. **New guest OS** — implement `GuestProfile` (Windows 7/10/11, Linux, Android) .
3. **New analysis package** — implement `Package` ABC (exe, doc, pdf, url, dll) .
4. **New monitor** — implement `Monitor` ABC (API hook, ETW, syscall) .
5. **New signature** — YARA rules, behavioral signatures .
6. **New export format** — `Exporter` ABC; JSON/HTML/PDF/CSV/STIX shipped.

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time (cold) | < 3 s |
| VM boot time | < 60 s (from snapshot) |
| Sample execution timeout | 120 s (configurable) |
| Behavior event ingestion | ≥ 10k events/s |
| Memory footprint (host) | < 2 GB RSS + VM memory |
| Concurrent analyses | 2-4 (configurable, depends on resources) |
| Analysis artifacts per run | < 5 GB (excluding memory dump) |
| Report generation | < 30 s |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable, screen-reader labels |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Rich ecosystem, hypervisor bindings |
| GUI | PySide6 (LGPL) | Commercial-friendly; mature Model/View |
| Hypervisor | VirtualBox (primary), KVM/QEMU, VMware  | Cross-platform, free |
| Hypervisor bindings | `pyvbox` (VBox), `libvirt` (KVM), `pyvmomi` (VMware) | Python APIs |
| Guest agent | Python REST (Flask/FastAPI) | Simple, cross-platform  |
| API hooking | Custom (Windows API hooks via `ctypes`/`detours`) | CAPE/Cuckoo approach  |
| Network sim | INetSim / FakeNet-NG | Industry standard  |
| PCAP capture | `pyshark` / `dpkt` | Host-side capture |
| DB | SQLite (WAL) | Embedded, ACID |
| Serialization | JSON Lines | Streaming behavior logs |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller + Briefcase | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |
| CI | GitHub Actions | Matrix: Win/Linux/macOS |

---

## 10. Directory Structure (Source Tree)

```
das/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── das/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── sample_queue.py
│       │   │   ├── analysis_progress.py
│       │   │   ├── behavior_timeline.py
│       │   │   ├── process_tree.py
│       │   │   ├── network_graph.py
│       │   │   ├── file_changes.py
│       │   │   ├── registry_changes.py
│       │   │   ├── api_call_log.py
│       │   │   ├── ioc_summary.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── events_table_model.py
│       │   │   ├── process_tree_model.py
│       │   │   └── network_model.py
│       │   └── widgets/
│       │       ├── event_card.py
│       │       ├── process_node.py
│       │       └── filter_bar.py
│       ├── core/
│       │   ├── orchestrator/
│       │   │   ├── scheduler.py
│       │   │   ├── vm_manager.py
│       │   │   └── pipeline.py
│       │   ├── hypervisor/
│       │   │   ├── base.py
│       │   │   ├── registry.py
│       │   │   ├── virtualbox.py
│       │   │   ├── kvm.py
│       │   │   └── vmware.py
│       │   ├── guest/
│       │   │   ├── agent_client.py
│       │   │   ├── analyzer.py
│       │   │   └── packages/
│       │   │       ├── base.py
│       │   │       ├── exe.py
│       │   │       ├── doc.py
│       │   │       └── url.py
│       │   ├── monitor/
│       │   │   ├── api_hook.py
│       │   │   ├── file_monitor.py
│       │   │   ├── registry_monitor.py
│       │   │   ├── process_monitor.py
│       │   │   └── network_capture.py
│       │   ├── network_sim/
│       │   │   ├── inetsim.py
│       │   │   └── fakenet.py
│       │   └── behavior/
│       │       ├── collector.py
│       │       ├── normalizer.py
│       │       └── ioc_extractor.py
│       ├── storage/
│       │   ├── case_db.py
│       │   ├── event_store.py
│       │   ├── artifact_store.py
│       │   └── migrations/
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── json_exporter.py
│       │   │   ├── html_exporter.py
│       │   │   ├── pdf_exporter.py
│       │   │   └── csv_exporter.py
│       │   └── templates/
│       ├── security/
│       │   ├── isolation.py
│       │   ├── defang.py
│       │   └── custody.py
│       └── utils/
│           ├── hashing.py
│           ├── units.py
│           └── logging.py
├── guest_agent/                 # Runs inside VM
│   ├── agent.py
│   └── requirements.txt
├── tests/
│   ├── unit/
│   ├── integration/
│   └── gui/
├── resources/
│   ├── icons/
│   ├── packages/                # Analysis package definitions
│   └── themes/
└── docs/
    ├── architecture.md
    ├── vm_setup.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, sample queue, hypervisor adapter (VirtualBox), VM provisioning | 3 weeks |
| **P1 — Guest Agent** | Agent REST API, file upload, command execution, status reporting | 2 weeks |
| **P2 — Execution** | Analyzer upload, sample execution, package framework (exe) | 3 weeks |
| **P3 — Network Capture** | Host-side PCAP capture, network graph view | 2 weeks |
| **P4 — Behavior Monitoring** | API hooking, FS/registry/process monitors, event streaming | 4 weeks |
| **P5 — Network Simulation** | INetSim/FakeNet-NG integration | 2 weeks |
| **P6 — Timeline & Views** | Behavior timeline, process tree, FS/registry views | 3 weeks |
| **P7 — IOC Extraction** | IOC extraction from behavior + network, summary view | 2 weeks |
| **P8 — Reporting** | JSON/HTML/PDF reports | 2 weeks |
| **P9 — Memory Dump** | Optional memory dump, Volatility integration | 2 weeks |
| **P10 — Hardening** | Isolation verification, defanging, custody | 2 weeks |
| **P11 — Polish** | Performance, i18n, docs, accessibility, packaging | 3 weeks |

**Total:** ~30 weeks (single senior dev) / ~15 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: hypervisor adapter operations, agent client, behavior event normalization, IOC extraction.
- **Integration**: full analysis lifecycle on benign sample (e.g., notepad.exe), then on controlled malicious sample (e.g., EICAR-like test file).
- **GUI**: `pytest-qt` for timeline filtering, process tree navigation, report generation.
- **Security**: verify VM isolation (network, shared folders, clipboard), test sample defanging, verify no host file system access from guest.
- **Performance**: benchmark on 100 MB sample; ensure event ingestion keeps up.
- **Cross-validation**: compare behavior logs against Cuckoo/CAPE output on same sample.

---

## 13. Open Questions / Decisions Pending

1. **Hypervisor priority** — VirtualBox is cross-platform but slower; KVM is faster but Linux-only. Recommend: VirtualBox primary, KVM optional.
2. **API hooking method** — Detours (CAPE approach) vs ETW vs syscall hooks. Recommend: Detours for v1 .
3. **Memory dump** — full dump is large (GBs) and slow. Recommend: optional, off by default; targeted dumps for specific processes.
4. **Windows Defender** — disable for analysis (avoids sample being quarantined), or enable with logging? Recommend: disable, document.
5. **Multi-VM parallel** — resource-intensive. Recommend: configurable, default 2 VMs.
6. **Guest OS support** — Windows 7/10/11 primary; Linux optional. Recommend: Windows 10/11 for v1.
7. **Sample upload to VirusTotal** — never by default; optional "upload" button with warning.
8. **License** — VirtualBox (GPL), INetSim (GPL), FakeNet-NG (GPL); verify redistribution.

---

## 14. Glossary

- **Dynamic analysis** — executing a sample and observing behavior .
- **Guest VM** — the isolated virtual machine where the sample runs .
- **Host** — the machine running the orchestration software.
- **Guest agent** — Python service running in the guest for host communication .
- **Analyzer** — Python script in guest that executes the sample and monitors .
- **Package** — defines how to execute a specific file type (exe, doc, url) .
- **Snapshot** — saved VM state; revert to `clean-baseline` before every run .
- **INetSim** — network simulation tool that answers DNS/HTTP/etc. .
- **API hooking** — intercepting Windows API calls for monitoring .
- **PCAP** — Packet CAPture file format.
- **IOC** — Indicator of Compromise.
- **Dropped file** — file written by the sample during execution.

---

*End of document.*