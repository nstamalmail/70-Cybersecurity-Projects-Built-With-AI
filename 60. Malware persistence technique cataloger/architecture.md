# Architecture: Malware Persistence Technique Cataloger — Auto-Extract IOCs from a Sample (GUI-Based Solution)

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** Automated persistence mechanism detection, cataloging, and IOC extraction from malware samples using static, dynamic, and registry-based analysis
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Malware Persistence Technique Cataloger (MPTC)** is a GUI-driven desktop application for malware analysts, DFIR investigators, and SOC analysts who need to systematically identify and catalog persistence mechanisms used by suspicious samples. It addresses the critical gap in post-analysis triage: automated sandboxes produce behavioral reports but rarely **catalog persistence techniques in a structured, MITRE ATT&CK-mapped format** suitable for remediation and threat hunting.

Persistence is consistently one of the most important tactics in the adversary lifecycle — it represents the phase where attackers "maintain their foothold" across restarts, credential changes, and other disruptions . Research shows **55.2% of malware samples** employ at least one persistence technique, and **5.5% employ four or more** . Common techniques include Registry Run keys, scheduled tasks, WMI subscriptions, services, and COM hijacking .

The tool is designed around four principles:

1. **Catalog, don't just detect** — every identified persistence mechanism is mapped to MITRE ATT&CK technique IDs, documented with evidence, and cataloged for reporting.
2. **Multi-source extraction** — analyze registry hives, dynamic behavior logs (CAPE/Cuckoo), and static artifacts (YARA matches) to build a complete picture.
3. **IOC-centric output** — every persistence mechanism yields actionable IOCs: registry keys, file paths, service names, scheduled task names, WMI queries.
4. **Remediation-ready** — the output includes not just what was found, but the exact steps to remove each persistence mechanism.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Sample    │ │ Persistence│ │ Registry │ │ Behavior  │ │ IOC     │ │
│  │ Loader    │ │ Catalog   │ │ Explorer │ │ Log       │ │ Summary │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ ATT&CK    │ │ Remediation│ │ YARA      │ │ Report    │ │ Console │ │
│  │ Heatmap   │ │ Checklist │ │ Matches   │ │ Builder   │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots (async)
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Analysis   │ │ Persistence│ │ IOC        │ │ Event Bus / Log    │ │
│  │ Queue      │ │ Engine     │ │ Compiler   │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Detection Modules Layer                          │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Registry       │ │ Behavior Log   │ │ Static Artifact          │  │
│  │ Analyzer       │ │ Parser (CAPE/  │ │ Analyzer (YARA, strings, │  │
│  │ (hives)        │ │  Cuckoo JSON)  │ │  PE imports)             │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Persistence Technique Catalog: T1547, T1543, T1053, T1546,     │  │
│  │ T1197, T1137, T1542, T1112, T1574, ... (MITRE TA0003)          │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Case DB    │ │ Persistence│ │ IOC Store  │ │ Report Store       │ │
│  │ (SQLite)   │ │ Catalog    │ │            │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `SampleLoaderView` | Load sample + analysis artifacts: sample file, CAPE/Cuckoo report, registry hives, memory dump. Auto-detect available artifacts. |
| `PersistenceCatalogView` | **Primary view.** Table of identified persistence mechanisms: technique name, MITRE ID, severity, evidence, source (registry/behavior/static), confidence. |
| `RegistryExplorerView` | Browse registry hives with persistence-relevant keys highlighted: Run/RunOnce, Services, Winlogon, AppInit_DLLs, Image File Execution Options. |
| `BehaviorLogView` | Filtered view of CAPE/Cuckoo behavior logs showing persistence-related API calls (RegSetValueEx, CreateService, etc.). |
| `YaraMatchesView` | YARA matches from bundled persistence-detection rules. |
| `AttackHeatmapView` | MITRE ATT&CK persistence tactic heatmap: techniques detected, techniques NOT detected (coverage gap). |
| `RemediationChecklistView` | Generated remediation steps per persistence mechanism: exact registry key to delete, service to stop, task to disable. |
| `IOCSummaryView` | Consolidated IOCs: registry paths, file paths, service names, task names, WMI queries, mutexes. |
| `ReportBuilderView` | Export persistence catalog report (HTML/PDF/JSON/CSV) with ATT&CK mapping and remediation steps. |
| `ConsoleView` | Live log tail; analysis warnings; errors. |

**Key UI Patterns**
- **Catalog-first layout**: persistence techniques as rows, evidence as expandable detail, remediation as inline actions.
- **Color coding by severity**: critical (ransomware persistence), high (C2 persistence), medium (generic), low (benign autoruns).
- **ATT&CK mapping**: every technique clickable to MITRE documentation.
- **Remediation actions**: checkbox per mechanism; "Generate remediation script" button produces PowerShell/reg commands.

### 3.2 Orchestration Layer

**Analysis Queue**
- Priority queue for sample analysis tasks.
- Task = `(task_id, sample_path, artifacts, case_id)`.
- Persisted to SQLite for crash recovery.

**Persistence Engine**
- Runs all detection modules in parallel.
- Aggregates results into unified catalog.
- Deduplicates across sources (e.g., same Run key found in registry + behavior log).

**IOC Compiler**
- Extracts actionable IOCs from catalog.
- Normalizes paths, keys, and names.

**Scheduler**
- Registry analysis: parallelized across hives.
- Behavior log parsing: parallelized across processes.
- YARA scanning: parallelized across rules.

### 3.3 Registry Analyzer Module

**Purpose**: Extract persistence mechanisms directly from registry hives .

**Supported hives**
| Hive | Path | Persistence Keys |
|---|---|---|
| **SOFTWARE** | `Windows\System32\config\SOFTWARE` | Run, RunOnce, RunServices, Policies\Explorer\Run, Wow6432Node\Run |
| **SYSTEM** | `Windows\System32\config\SYSTEM` | Services, ControlSet\Services, Winlogon, AppInit_DLLs, Image File Execution Options |
| **NTUSER.DAT** | `Users\<user>\NTUSER.DAT` | Run, RunOnce, Explorer\StartupApproved\Run |
| **UsrClass.dat** | `Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` | COM hijacking, Shell extensions |

**Persistence keys scanned** 
```python
PERSISTENCE_KEYS = {
    "SOFTWARE": [
        "Microsoft\\Windows\\CurrentVersion\\Run",
        "Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Microsoft\\Windows\\CurrentVersion\\RunServices",
        "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "Microsoft\\Windows NT\\CurrentVersion\\Windows",  # AppInit_DLLs
    ],
    "SYSTEM": [
        "ControlSet001\\Services",
        "ControlSet002\\Services",
        "CurrentControlSet\\Services",
        "ControlSet001\\Control\\Session Manager\\Image File Execution Options",
    ],
    "NTUSER.DAT": [
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run",
    ],
}
```

**Extraction logic**
- Use `python-registry` library for cross-platform hive parsing .
- For each key, enumerate values; flag suspicious entries:
  - Path in `ProgramData`, `Temp`, `AppData` (unusual locations)
  - `powershell.exe`, `cmd.exe`, `mshta.exe`, `rundll32.exe` launch strings
  - Base64-encoded arguments
  - Unsigned executables 
  - Recently modified keys (timestamp analysis)

**Output**: `PersistenceArtifact` records with technique ID, evidence, confidence.

### 3.4 Behavior Log Parser Module

**Purpose**: Extract persistence mechanisms from dynamic analysis reports (CAPE/Cuckoo JSON) .

**Relevant API calls**
| API Call | Category | Persistence Technique |
|---|---|---|
| `RegSetValueExW` | Registry | T1547.001 (Run keys), T1543.003 (Services) |
| `RegCreateKeyExW` | Registry | T1547.001 |
| `CreateServiceW` | Service | T1543.003 |
| `ChangeServiceConfigW` | Service | T1543.003 |
| `SchRpcRegisterTask` | Scheduled Task | T1053.005 |
| `CoCreateInstance` (COM) | COM Hijack | T1546.015 |
| `SetWindowsHookEx` | Hook | T1546.004 |

**Parsing strategy**
- Iterate `behavior.processes[].calls[]`.
- Filter for persistence-relevant API calls.
- Extract arguments: registry key path, value name, value data, service name, binary path.
- Cross-reference with registry analyzer results for corroboration.

**Evidence extraction**
```python
@dataclass
class PersistenceEvidence:
    source: str                    # 'registry', 'behavior', 'static', 'memory'
    technique_id: str              # 'T1547.001'
    technique_name: str            # 'Registry Run Keys / Startup Folder'
    evidence_type: str             # 'registry_key', 'service', 'scheduled_task', 'wmi'
    key_path: str | None           # 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
    value_name: str | None         # 'WindowsUpdate'
    value_data: str | None         # 'C:\ProgramData\svc\update.exe'
    service_name: str | None
    task_name: str | None
    binary_path: str | None
    process_id: int | None
    timestamp: datetime | None
    raw: dict
```

### 3.5 Static Artifact Analyzer Module

**Purpose**: Detect persistence indicators from static analysis of the sample .

**YARA rules (bundled)**
- `Persistence_RegistryRunKey` — detects Run key strings and `reg add` commands .
- `Persistence_Service` — detects `CreateService`, `sc create` patterns.
- `Persistence_ScheduledTask` — detects `schtasks` patterns.
- `Persistence_WMI` — detects WMI subscription strings.

**String analysis**
- Extract strings from sample; classify for persistence keywords:
  - Registry paths: `Software\Microsoft\Windows\CurrentVersion\Run`
  - Service names: `sc.exe create`, `CreateService`
  - Task names: `schtasks /create`
  - WMI: `__EventFilter`, `CommandLineEventConsumer`

**PE import analysis**
- Flag imports: `RegSetValueEx`, `CreateService`, `SchRpcRegisterTask`, `CoCreateInstance`.

### 3.6 Persistence Technique Catalog

**Built-in technique mappings (MITRE TA0003)**

| Technique ID | Name | Detection Sources |
|---|---|---|
| T1547.001 | Registry Run Keys / Startup Folder | Registry, Behavior, Static  |
| T1543.003 | Windows Service | Registry, Behavior |
| T1053.005 | Scheduled Task | Behavior, Static |
| T1546.003 | WMI Event Subscription | Behavior, Static  |
| T1546.015 | Component Object Model Hijacking | Registry, Behavior |
| T1542.003 | Bootkit | Registry, Static |
| T1112 | Modify Registry | Behavior |
| T1197 | BITS Jobs | Behavior, Static |
| T1137 | Office Application Startup | Registry, Static |
| T1574.001 | DLL Search Order Hijacking | Registry, Static |

**Technique catalog entry**
```python
@dataclass
class PersistenceTechnique:
    technique_id: str              # 'T1547.001'
    name: str                      # 'Registry Run Keys / Startup Folder'
    tactic: str                    # 'Persistence'
    description: str
    severity: str                  # 'critical', 'high', 'medium', 'low'
    detection_hints: list[str]     # What to look for
    remediation_steps: list[str]   # How to remove
    references: list[str]          # MITRE URL, blog posts
```

### 3.7 Remediation Engine

**Purpose**: Generate actionable removal instructions per persistence mechanism.

**Remediation templates**
| Technique | Remediation |
|---|---|
| Run Key | `reg delete "HKLM\...\Run" /v <name> /f` |
| Service | `sc stop <name> && sc delete <name>` |
| Scheduled Task | `schtasks /delete /tn <name> /f` |
| WMI Subscription | PowerShell: `Get-WmiObject -Namespace root\subscription -Class __EventFilter | Remove-WmiObject` |
| COM Hijack | `reg delete "HKCR\CLSID\{...}" /f` |

**Output**: PowerShell/reg script + manual steps + verification commands.

### 3.8 Storage Layer

**Case Directory Layout**
```
cases/<case_id>/
├── case.db                      # SQLite: samples, persistence, iocs
├── manifest.json                # Case metadata
├── artifacts/
│   ├── sample.exe
│   ├── cape_report.json
│   ├── registry/
│   │   ├── SOFTWARE
│   │   ├── SYSTEM
│   │   └── NTUSER.DAT
│   └── yara_matches.json
├── catalog/
│   └── persistence_catalog.json
├── remediation/
│   └── remediation.ps1
├── reports/
│   ├── persistence_report.html
│   ├── persistence_report.pdf
│   └── iocs.csv
└── logs/
    └── session.log
```

**SQLite Schema (abridged)**
```sql
CREATE TABLE persistence (
  id INTEGER PRIMARY KEY, case_id TEXT,
  technique_id TEXT, technique_name TEXT,
  severity TEXT, source TEXT,
  evidence_json TEXT,
  confidence REAL,
  remediated INTEGER DEFAULT 0
);
CREATE TABLE iocs (
  id INTEGER PRIMARY KEY, case_id TEXT,
  ioc_type TEXT, value TEXT,
  technique_id TEXT, context_json TEXT
);
CREATE INDEX idx_persistence_tech ON persistence(technique_id);
CREATE INDEX idx_iocs_type ON iocs(ioc_type);
```

### 3.9 Canonical Data Model

See `PersistenceEvidence` (§3.4) and `PersistenceTechnique` (§3.6).

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, catalog rendering, remediation generation
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Analysis Pool (QThreadPool, N workers)
  ├── Registry analyzer threads   (parallel across hives)
  ├── Behavior parser threads     (parallel across processes)
  ├── YARA scanner                (parallel across rules)
  └── IOC compiler                (after all inputs)

Writer Thread (serial)
  └── SQLite WAL writes
```

**Rules**
- Registry hive parsing is CPU-bound; parallelize across hives.
- Behavior log parsing is memory-bound; stream process-by-process.
- SQLite in WAL mode; single writer.
- Cancellation: cooperative `threading.Event` checked between hives/processes.

---

## 5. Workflow: End-to-End User Journey

1. **Load Artifacts** → select sample file, CAPE/Cuckoo report, registry hives, YARA matches.
2. **Auto-Detect** → identify available artifacts; suggest missing ones for better coverage.
3. **Analyze Registry** → scan persistence keys in SOFTWARE, SYSTEM, NTUSER.DAT.
4. **Parse Behavior Log** → filter persistence-related API calls from CAPE/Cuckoo report.
5. **Scan Static Artifacts** → run YARA persistence rules; extract strings.
6. **Aggregate Catalog** → merge evidence from all sources; deduplicate; score confidence.
7. **Review Catalog** → table of persistence techniques with evidence, severity, ATT&CK mapping.
8. **Drill into Evidence** → click technique → show supporting registry keys, API calls, strings.
9. **Review Remediation** → per-technique removal steps; generate remediation script.
10. **Export** → persistence report (HTML/PDF/JSON), IOC list (CSV/STIX), remediation script.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| Malicious registry hive (parser exploit) | `python-registry` runs in subprocess with resource limits; fuzz-tested. |
| Malicious behavior log (parser exploit) | JSON/BSON parsing with schema validation; no `eval`. |
| Malicious YARA rule (injection) | YARA rules are data, not code; sandboxed compilation. |
| Sample handling | Sample never executed; only static analysis + artifact parsing. |
| Sensitive IOCs in reports | Redaction profile for external sharing; audit export actions. |
| Path traversal | Sanitize paths from registry/behavior logs; never use as file paths. |

---

## 7. Extensibility Points

1. **New persistence technique** — add YAML to `techniques/` with detection hints and remediation.
2. **New artifact source** — implement `ArtifactAnalyzer` ABC (Volatility malfind output, Autoruns CSV).
3. **New YARA rule** — add to `rules/persistence/`.
4. **New remediation template** — add to `remediation/templates/`.
5. **New export format** — `Exporter` ABC.

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time (cold) | < 2 s |
| Registry hive parse | < 10 s (typical) |
| Behavior log parse (10k calls) | < 5 s |
| YARA scan | < 2 s |
| Catalog generation | < 1 s |
| Memory footprint | < 500 MB RSS |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Rich ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly |
| Registry parsing | `python-registry` | Cross-platform, mature  |
| Behavior parsing | `orjson` | Fast JSON parsing |
| YARA | `yara-python` | Standard bindings |
| DB | SQLite (WAL) | Embedded, ACID |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
mptc/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── mptc/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── sample_loader.py
│       │   │   ├── persistence_catalog.py
│       │   │   ├── registry_explorer.py
│       │   │   ├── behavior_log.py
│       │   │   ├── yara_matches.py
│       │   │   ├── attack_heatmap.py
│       │   │   ├── remediation_checklist.py
│       │   │   ├── ioc_summary.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── persistence_table_model.py
│       │   │   └── iocs_table_model.py
│       │   └── widgets/
│       │       ├── technique_badge.py
│       │       ├── evidence_pane.py
│       │       └── remediation_actions.py
│       ├── core/
│       │   ├── registry/
│       │   │   ├── analyzer.py
│       │   │   ├── keys.py
│       │   │   └── suspicious.py
│       │   ├── behavior/
│       │   │   ├── parser.py
│       │   │   └── api_filter.py
│       │   ├── static/
│       │   │   ├── yara_scanner.py
│       │   │   └── string_analyzer.py
│       │   ├── catalog/
│       │   │   ├── aggregator.py
│       │   │   └── techniques/
│       │   │       ├── t1547_001.yaml
│       │   │       ├── t1543_003.yaml
│       │   │       ├── t1053_005.yaml
│       │   │       ├── t1546_003.yaml
│       │   │       └── t1546_015.yaml
│       │   ├── remediation/
│       │   │   ├── generator.py
│       │   │   └── templates/
│       │   ├── ioc/
│       │   │   └── compiler.py
│       │   └── pipeline/
│       │       └── engine.py
│       ├── storage/
│       │   ├── case_db.py
│       │   └── migrations/
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── html_exporter.py
│       │   │   ├── pdf_exporter.py
│       │   │   └── csv_exporter.py
│       │   └── templates/
│       └── utils/
│           ├── hashing.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
│       ├── registry_hives/
│       ├── cape_reports/
│       └── yara_matches/
├── resources/
│   ├── icons/
│   ├── rules/
│   │   └── persistence/
│   └── themes/
└── docs/
    ├── architecture.md
    ├── technique_authoring.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, sample loader, artifact auto-detect | 2 weeks |
| **P1 — Registry Analyzer** | Hive parsing, persistence key scanning, registry explorer | 3 weeks |
| **P2 — Behavior Parser** | CAPE/Cuckoo JSON parsing, API filtering, evidence extraction | 2 weeks |
| **P3 — Static Analyzer** | YARA persistence rules, string analysis, PE imports | 2 weeks |
| **P4 — Catalog Engine** | Aggregation, dedup, confidence scoring, ATT&CK mapping | 2 weeks |
| **P5 — Remediation Engine** | Per-technique remediation, script generation | 2 weeks |
| **P6 — IOC Compiler** | Consolidated IOC extraction, export | 2 weeks |
| **P7 — Reporting** | HTML/PDF/JSON/CSV reports | 2 weeks |
| **P8 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~20 weeks (single senior dev) / ~10 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: registry key parsing, suspicious entry detection, behavior log filtering, YARA matching, catalog aggregation.
- **Integration**: full pipeline on known malware samples with documented persistence (e.g., Emotet Run keys, TrickBot services).
- **GUI**: `pytest-qt` for catalog navigation, evidence drilling, remediation checklist.
- **Fixtures**: registry hives from infected VMs (controlled environment), CAPE reports from MalwareBazaar samples.
- **Cross-validation**: compare detected persistence against Autoruns output  and CAPE signatures .

---

## 13. Open Questions / Decisions Pending

1. **Registry hive acquisition** — tool analyzes existing hives (from forensic image or live system). No live registry access by default.
2. **Volatility integration** — optional: use `windows.malfind` output to detect in-memory persistence . Recommend: v2 feature.
3. **WMI subscription parsing** — complex; requires parsing `OBJECTS.DATA` in WMI repository. Recommend: v1 detects via behavior logs; v2 parses repository.
4. **Autoruns CSV import** — allow importing Autoruns output for comparison. Recommend: v1 feature.
5. **Remediation script safety** — generated scripts must be reviewed before execution; include dry-run mode.
6. **License** — `python-registry` (Apache 2.0); YARA persistence rules (various); verify redistribution.

---

## 14. Glossary

- **Persistence** — techniques adversaries use to maintain foothold (MITRE TA0003) .
- **Run Key** — Registry key executing programs at logon (`HKLM\...\Run`).
- **Service** — Windows service that auto-starts with system (T1543.003).
- **Scheduled Task** — Windows Task Scheduler entry (T1053.005).
- **WMI Subscription** — Event-triggered WMI consumer (T1546.003).
- **COM Hijacking** — Redirecting COM object loading (T1546.015).
- **Autoruns** — Sysinternals tool enumerating autostart locations .
- **RegRipper** — Registry artifact extraction tool .
- **CAPE** — Cuckoo successor sandbox with enhanced config extraction .
- **ATT&CK** — MITRE Adversarial Tactics, Techniques & Common Knowledge.
- **TA0003** — Persistence tactic ID.

---

*End of document.*