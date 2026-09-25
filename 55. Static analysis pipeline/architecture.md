# Architecture: Static Analysis Pipeline — Strings, PE Header Parsing, Hash Lookups (GUI-Based Solution)

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** Automated static triage of suspicious Windows executables via hashing, PE header parsing, string extraction, and multi-source threat intelligence lookups
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Static Analysis Pipeline (SAP)** is a GUI-driven desktop application for SOC analysts, malware triage specialists, and DFIR investigators who need to perform **first-pass static analysis** on suspicious Windows executables without executing them. It consolidates four core static analysis capabilities into a single, automated pipeline:

1. **Hash computation** — MD5, SHA-1, SHA-256 for identification and reputation lookup .
2. **PE header parsing** — extraction of compile timestamp, section table, imports, exports, and anomaly detection .
3. **String extraction** — ASCII and Unicode string extraction with suspicious pattern classification (URLs, IPs, registry keys, commands) .
4. **Hash lookups** — automated querying of multiple threat intelligence sources (VirusTotal, MalwareBazaar, AlienVault OTX) by hash only, without uploading the sample .

The tool is designed around four principles:

1. **Never execute** — all analysis is strictly read-only; samples are never run .
2. **Triage-first** — produce a defensible verdict (LIKELY CLEAN / SUSPICIOUS / MALICIOUS) quickly to decide whether deeper dynamic analysis is warranted.
3. **Multi-source enrichment** — leverage external threat intelligence for reputation without uploading samples.
4. **Analyst-first UI** — every finding is clickable, drillable, and exportable for reporting.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Sample    │ │ Analysis  │ │ String    │ │ PE Header │ │ Report  │ │
│  │ Loader    │ │ Progress  │ │ Explorer  │ │ Inspector │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Hash      │ │ Threat    │ │ Verdict   │ │ IOC       │ │ Console │ │
│  │ Panel     │ │ Intel     │ │ Dashboard │ │ Summary   │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots (async)
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Task Queue │ │ Pipeline   │ │ Scheduler  │ │ Event Bus / Log    │ │
│  │ (priority) │ │ Engine     │ │ (QThread   │ │ (structlog)        │ │
│  │            │ │ (staged)   │ │  Pool)     │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Analysis Modules Layer                           │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Hash Engine    │ │ PE Parser      │ │ String Extractor         │  │
│  │ (MD5/SHA1/     │ │ (pefile-based) │ │ (ASCII/Unicode +         │  │
│  │  SHA256)       │ │                │ │  pattern classification) │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Threat Intel Aggregator (VT, MalwareBazaar, OTX)              │  │
│  └────────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Verdict Engine: weighted scoring → CLEAN/SUSPICIOUS/MALICIOUS │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Case DB    │ │ Report     │ │ API Key    │ │ Cache              │ │
│  │ (SQLite)   │ │ Store      │ │ Store      │ │ (Lookup Results)   │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     OS / Runtime Abstraction Layer                   │
│  File I/O (read-only) · HTTP client · Config store                   │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `SampleLoaderView` | Drag-and-drop or browse for suspicious files (.exe, .dll, .sys, .scr). Validates file type via magic bytes. Displays file size, type, and initial hash preview. |
| `AnalysisProgressView` | Per-module progress bars (Hash, PE Parse, Strings, Intel Lookups). Live status updates. Error surfacing. |
| `HashPanelView` | Displays MD5, SHA-1, SHA-256 with copy-to-clipboard. One-click "Lookup" button to query threat intel sources. |
| `PEHeaderInspectorView` | Tree/table view of PE structure: DOS header, NT headers, File Header (machine, timestamp, characteristics), Optional Header (entry point, image base, subsystem), Section Table (name, virtual size, raw size, entropy), Import Directory (DLLs and functions), Export Directory, Debug Directory, Resource Directory . |
| `StringExplorerView` | Table of extracted strings with filter/search. Columns: offset, type (ASCII/Unicode), length, string value, classification (URL/IP/Registry/Command/Suspicious API/Other). |
| `ThreatIntelView` | Results matrix from threat intel sources: source name, detection ratio, family/tags, first seen, last seen . Click to open source URL. |
| `VerdictDashboardView` | Overall verdict with color coding (CLEAN/SUSPICIOUS/MALICIOUS). Weighted risk score. Breakdown of contributing indicators. |
| `IOCSummaryView` | Consolidated IOCs extracted from all modules: hashes, URLs, IPs, registry keys, file paths, mutexes, user-agents, PDB paths. Exportable as CSV/JSON/STIX. |
| `ReportBuilderView` | Export full analysis report as JSON, HTML, PDF, or Markdown. Include hash manifest, IOC summary, and verdict rationale. |
| `ConsoleView` | Live log tail; module warnings; API errors; debug toggle. |

**Key UI Patterns**
- Model/View with `QAbstractTableModel` for string tables and PE sections.
- Worker threads via `QThreadPool` + `QRunnable`; UI never blocks on hashing or network lookups.
- Streaming results: string extraction emits batches; UI appends incrementally.
- Click-to-pivot: clicking an import in PE view filters strings to related patterns; clicking a URL in strings opens threat intel lookup.
- Color coding: red for high-risk indicators, yellow for suspicious, green for benign.

### 3.2 Orchestration Layer

**Task Queue**
- Priority queue with worker pool.
- Task = `(task_id, module, sample_path, options, case_id)`.
- Persisted to SQLite for crash recovery.

**Pipeline Engine (staged)**
```
[Sample Load] → [Hash] → [PE Parse] → [String Extract] → [Intel Lookups]
       → [IOC Compile] → [Verdict] → [Report]
```
- Modules run in dependency order; hash must complete before lookups.
- String extraction and PE parsing can run in parallel.
- Intel lookups run after hash is computed.

**Scheduler**
- Hash: single-threaded per file (I/O bound).
- PE parsing: single-threaded (pefile is not thread-safe per instance).
- String extraction: parallelizable across file chunks.
- Intel lookups: parallel across sources, rate-limited per API terms.

### 3.3 Hash Engine

**Computation**
- MD5, SHA-1, SHA-256 computed simultaneously in a single pass.
- Streaming: read file in chunks (default 1 MB) to bound memory.
- Output: hex digest strings with copy buttons.

**Hash type auto-detection** (for lookup input)
- 32 hex chars → MD5
- 40 hex chars → SHA-1
- 64 hex chars → SHA-256 

### 3.4 PE Parser Layer

**Library: `pefile`**
- Multi-platform Python module; no dependencies; endianness-independent .
- Used in VirusTotal and other production pipelines .

**Extracted data**

| Field | Source | Significance |
|---|---|---|
| Machine | File Header | Architecture (x86/x64/ARM) |
| TimeDateStamp | File Header | Compile time; anomalies suggest tampering |
| Characteristics | File Header | Executable, DLL, system file flags |
| AddressOfEntryPoint | Optional Header | Entry point; suspicious if in last section |
| ImageBase | Optional Header | Preferred load address |
| Subsystem | Optional Header | GUI, console, driver |
| Section names | Section Table | `.text`, `.data`, unusual names |
| Section entropy | Computed | High entropy (>7.0) suggests packing/encryption |
| Imports | Import Directory | DLLs and functions; suspicious APIs flag capabilities |
| Exports | Export Directory | Exported functions (for DLLs) |
| Debug path | Debug Directory | PDB path may reveal developer path |
| Resources | Resource Directory | Embedded icons, manifests, version info |

**Suspicious import detection**
- Flag APIs commonly abused by malware: `CreateRemoteThread`, `VirtualAllocEx`, `WriteProcessMemory`, `WinExec`, `ShellExecute`, `RegSetValueEx`, `InternetOpen`, `URLDownloadToFile`, `CryptEncrypt` .
- Group by capability: process injection, persistence, network, crypto, evasion.

**Anomaly detection**
- Entry point outside `.text` section.
- Sections with `W+X` characteristics (writable + executable).
- Section names not matching standard names.
- Timestamp in the future or far past.
- Missing or malformed imports.

### 3.5 String Extractor Layer

**Extraction**
- ASCII strings: regex `[ -~]{4,}` (configurable minimum length) .
- Unicode strings: UTF-16 LE; detect via `\x00` interleaving pattern.
- Batch extraction from directories supported .

**Pattern classification**

| Category | Pattern | Example |
|---|---|---|
| URL | `https?://[^\s]+` | `http://c2.example.com/gate.php` |
| IP Address | `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` | `192.168.1.100:4444` |
| Domain | `[a-z0-9-]+\.[a-z]{2,}` | `evil.com` |
| Registry Key | `HKLM|HKCU|...` | `Software\Microsoft\Windows\CurrentVersion\Run` |
| File Path | `[A-Z]:\\...` | `C:\Users\Public\payload.exe` |
| Command | `cmd\.exe|powershell|wscript` | `cmd.exe /c vssadmin delete shadows` |
| Suspicious API | Known API names | `CreateRemoteThread`, `VirtualAllocEx` |
| Credential | `password|passwd|login|token|key` | `password=admin123` |
| Base64 | Long alphanumeric strings | Encoded payloads |
| PDB Path | `*.pdb` | `C:\dev\project\Release\rat.pdb` |
| Mutex | `Global\...` | `Global\MutexName123` |
| User-Agent | `Mozilla/5.0...` | Malware HTTP user-agent |

**Suspicious keyword flagging**
- Keywords suggesting ransomware: `encrypt`, `decrypt`, `bitcoin`, `ransom`, `vssadmin`, `bcdedit` .
- Keywords suggesting credential theft: `password`, `credential`, `lsass`, `sam`, `ntds`.
- Keywords suggesting persistence: `Run`, `RunOnce`, `Services`, `Schedule`.

### 3.6 Threat Intel Aggregator

**Sources**

| Source | Method | Rate Limit | Notes |
|---|---|---|---|
| **VirusTotal** | API v3 hash lookup | 4 req/min (free tier) | Detection ratio, family names, tags, first/last seen  |
| **MalwareBazaar** | API hash lookup | Generous | Sample metadata, family, file type  |
| **AlienVault OTX** | API hash lookup | Generous | Pulses, tags, related indicators  |

**Lookup strategy**
- Query by hash only — **never upload the sample** .
- Parallel queries with per-source rate limiting.
- Cache results (by hash) to avoid redundant queries.
- Graceful degradation: if a source is unavailable, continue with others.

**Result normalization**
```python
@dataclass
class IntelResult:
    source: str              # 'virustotal', 'malwarebazaar', 'otx'
    hash_queried: str
    hash_type: str           # 'md5', 'sha1', 'sha256'
    found: bool
    detection_ratio: str | None   # e.g., '45/71'
    positives: int | None
    family: str | None            # e.g., 'RedLineStealer'
    tags: list[str]
    first_seen: datetime | None
    last_seen: datetime | None
    source_url: str | None
    raw_response: dict
```

### 3.7 Verdict Engine

**Weighted scoring**

| Indicator | Weight | Source |
|---|---|---|
| VT detection ratio > 10 | +40 | Threat Intel |
| VT detection ratio 1-10 | +20 | Threat Intel |
| Known malware family in VT/MB/OTX | +30 | Threat Intel |
| High section entropy (>7.0) | +15 | PE Parser |
| Suspicious imports (injection, crypto) | +15 | PE Parser |
| Suspicious strings (C2 URLs, commands) | +10 | String Extractor |
| W+X sections | +10 | PE Parser |
| Entry point outside `.text` | +10 | PE Parser |
| Packer detected | +5 | PE Parser |
| No VT detections | -30 | Threat Intel |
| Signed by trusted publisher | -20 | PE Parser |

**Verdict thresholds**
- Score ≥ 60: **MALICIOUS**
- Score 25–59: **SUSPICIOUS**
- Score < 25: **LIKELY CLEAN**

**Verdict rationale**
- Every contributing indicator is listed with its weight and source.
- Analyst can override verdict with justification (audit-logged).

### 3.8 IOC Compilation

**Compiled IOC types**
- Hashes: MD5, SHA-1, SHA-256
- URLs (from strings)
- IP addresses (from strings)
- Domains (from strings)
- Registry keys (from strings)
- File paths (from strings)
- Mutexes (from strings)
- User-agents (from strings)
- PDB paths (from PE debug directory)
- Family names (from threat intel)

**Export formats**
- CSV
- JSON
- STIX 2.1
- MISP

### 3.9 Storage Layer

**Case Directory Layout**
```
cases/<case_id>/
├── case.db                      # SQLite: samples, analyses, iocs, verdicts
├── manifest.json                # Case metadata
├── samples/
│   └── <sha256>.exe             # Reference to original sample (not copied by default)
├── reports/
│   ├── <sha256>.json            # Full analysis report
│   ├── <sha256>.html
│   └── iocs.csv
├── cache/
│   └── intel/                   # Cached threat intel responses
└── logs/
    └── session.log
```

**SQLite Schema (abridged)**
```sql
CREATE TABLE samples (
  sha256 TEXT PRIMARY KEY,
  md5 TEXT, sha1 TEXT,
  size INTEGER, file_type TEXT,
  first_seen TIMESTAMP, path TEXT
);
CREATE TABLE analyses (
  id TEXT PRIMARY KEY, sha256 TEXT,
  verdict TEXT, risk_score INTEGER,
  pe_data_json TEXT, strings_json TEXT,
  intel_json TEXT, iocs_json TEXT,
  analyzed_at TIMESTAMP
);
CREATE TABLE intel_cache (
  hash TEXT, source TEXT,
  response_json TEXT, cached_at TIMESTAMP,
  PRIMARY KEY (hash, source)
);
CREATE TABLE verdict_overrides (
  id INTEGER PRIMARY KEY, analysis_id TEXT,
  original_verdict TEXT, new_verdict TEXT,
  justification TEXT, analyst TEXT, ts TIMESTAMP
);
```

### 3.10 Canonical Data Model

```python
@dataclass
class Sample:
    sha256: str
    md5: str
    sha1: str
    size: int
    file_type: str
    path: str

@dataclass
class PEInfo:
    machine: str
    timestamp: datetime
    entry_point: int
    image_base: int
    subsystem: str
    sections: list[PESection]
    imports: dict[str, list[str]]       # dll -> [functions]
    exports: list[str]
    debug_path: str | None
    anomalies: list[str]

@dataclass
class PESection:
    name: str
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: str

@dataclass
class ExtractedString:
    offset: int
    type: str            # 'ascii', 'unicode'
    value: str
    classification: str  # 'url', 'ip', 'registry', ...
    length: int

@dataclass
class AnalysisResult:
    sample: Sample
    pe_info: PEInfo | None
    strings: list[ExtractedString]
    intel_results: list[IntelResult]
    iocs: dict[str, list[str]]
    verdict: str
    risk_score: int
    rationale: list[dict]
```

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, model updates
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Analysis Pool (QThreadPool, N workers)
  ├── Hash worker           (single per file)
  ├── PE parser worker      (single per file)
  ├── String extractor      (parallel across chunks)
  ├── Intel lookup worker   (parallel across sources, rate-limited)
  └── Verdict worker        (after all inputs ready)
```

**Rules**
- Sample file opened read-only; never executed.
- `pefile.PE` instance is not thread-safe — one instance per worker.
- HTTP lookups respect per-source rate limits; use a token-bucket or sleep.
- SQLite in WAL mode; single writer.
- Cancellation: cooperative `threading.Event` checked between strings/chunks.

---

## 5. Workflow: End-to-End User Journey

1. **Load Sample** → drag/drop or browse for suspicious file; validate PE magic (`MZ`).
2. **Hash** → compute MD5/SHA-1/SHA-256; display immediately.
3. **Threat Intel Lookup** → query VT, MalwareBazaar, OTX by hash; show results matrix .
4. **PE Parse** → extract headers, sections, imports, anomalies; display in inspector.
5. **String Extract** → extract ASCII/Unicode; classify patterns; display in explorer.
6. **IOC Compile** → aggregate IOCs from all modules.
7. **Verdict** → weighted scoring; display verdict with rationale.
8. **Review** → drill into any indicator; filter strings by classification; click imports.
9. **Override** (optional) → analyst can override verdict with justification.
10. **Export** → JSON/HTML/PDF report + IOC export (CSV/JSON/STIX).

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| Malicious sample (parser exploit) | `pefile` is robust but run in subprocess with resource limits; fuzz-tested. |
| Accidental execution | Sample never passed to `os.system`, `subprocess`, or `exec`; only read as bytes. |
| API key leakage | Keys stored in OS keychain or encrypted config; never logged. |
| Rate limit violation | Token-bucket per source; respect free-tier limits (VT: 4 req/min) . |
| Intel source outage | Graceful degradation; continue with available sources. |
| Sensitive IOCs in reports | Redaction profile for external sharing; audit export actions. |
| Path traversal from sample names | Sanitize filenames; never use sample-provided names for file paths. |
| Large file DoS | Configurable max file size (default 500 MB); streaming hash. |

---

## 7. Extensibility Points

1. **New analysis module** — implement `Analyzer` ABC; register in `modules/registry.py`.
2. **New threat intel source** — implement `IntelSource` ABC; register; add rate limit config .
3. **New string classification rule** — YAML pattern file in `patterns/`.
4. **New verdict indicator** — add to weight table in `verdict/scorer.py`.
5. **New export format** — `Exporter` ABC; JSON/HTML/PDF/CSV/STIX shipped.
6. **YARA rule integration** — add YARA scanning as optional module .

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time (cold) | < 2 s |
| Hash computation (100 MB) | < 1 s |
| PE parse (typical exe) | < 2 s |
| String extraction (100 MB) | < 5 s |
| Intel lookup (per source) | < 3 s (network bound) |
| Full pipeline (100 MB) | < 15 s (without network) |
| Memory footprint | < 500 MB RSS |
| File size support | Up to 500 MB (configurable) |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable, screen-reader labels |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Rich ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly; mature Model/View |
| PE parsing | `pefile` | Industry standard, no deps, used by VT  |
| Hashing | `hashlib` (stdlib) | Fast, standard |
| HTTP | `requests` | Standard, well-understood |
| String extraction | Custom regex + `strings`-style | Full control |
| Threat intel | VT API v3, MalwareBazaar API, OTX API | Free tiers available  |
| DB | SQLite (WAL) | Embedded, ACID |
| Serialization | JSON Lines | Streaming |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller + Briefcase | Cross-platform binaries |
| Testing | pytest + pytest-qt + Hypothesis | Unit, GUI, property-based |
| CI | GitHub Actions | Matrix: Win/Linux/macOS × py3.10–3.12 |

---

## 10. Directory Structure (Source Tree)

```
sap/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── sap/
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
│       │   │   ├── analysis_progress.py
│       │   │   ├── hash_panel.py
│       │   │   ├── pe_inspector.py
│       │   │   ├── string_explorer.py
│       │   │   ├── threat_intel.py
│       │   │   ├── verdict_dashboard.py
│       │   │   ├── ioc_summary.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── strings_table_model.py
│       │   │   ├── sections_table_model.py
│       │   │   └── intel_table_model.py
│       │   └── widgets/
│       │       ├── hash_display.py
│       │       ├── verdict_badge.py
│       │       └── filter_bar.py
│       ├── core/
│       │   ├── hash/
│       │   │   └── engine.py
│       │   ├── pe/
│       │   │   ├── parser.py
│       │   │   ├── anomalies.py
│       │   │   └── suspicious_imports.py
│       │   ├── strings/
│       │   │   ├── extractor.py
│       │   │   └── classifier.py
│       │   ├── intel/
│       │   │   ├── base.py
│       │   │   ├── registry.py
│       │   │   ├── virustotal.py
│       │   │   ├── malwarebazaar.py
│       │   │   └── otx.py
│       │   ├── verdict/
│       │   │   ├── scorer.py
│       │   │   └── rationale.py
│       │   ├── ioc/
│       │   │   └── compiler.py
│       │   └── pipeline/
│       │       ├── stages.py
│       │       ├── queue.py
│       │       └── scheduler.py
│       ├── storage/
│       │   ├── case_db.py
│       │   ├── intel_cache.py
│       │   └── migrations/
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── json_exporter.py
│       │   │   ├── html_exporter.py
│       │   │   ├── pdf_exporter.py
│       │   │   ├── csv_exporter.py
│       │   │   └── stix_exporter.py
│       │   └── templates/
│       ├── security/
│       │   ├── sandbox.py
│       │   ├── key_store.py
│       │   └── redaction.py
│       └── utils/
│           ├── hashing.py
│           ├── units.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/
│   │   ├── pe_samples/          # benign + test PEs
│   │   └── string_samples/
│   └── gui/
├── resources/
│   ├── icons/
│   ├── patterns/
│   │   ├── urls.yaml
│   │   ├── ips.yaml
│   │   ├── registry.yaml
│   │   └── suspicious_apis.yaml
│   └── themes/
└── docs/
    ├── architecture.md
    ├── pe_notes.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, sample loader, hash panel, basic file type detection | 2 weeks |
| **P1 — PE Parser** | pefile integration, header inspector, section table, imports, anomalies | 3 weeks |
| **P2 — String Extractor** | ASCII/Unicode extraction, pattern classification, explorer UI | 2 weeks |
| **P3 — Threat Intel** | VT, MalwareBazaar, OTX integrations, results matrix, caching | 3 weeks |
| **P4 — Verdict Engine** | Weighted scoring, rationale display, override workflow | 2 weeks |
| **P5 — IOC Compilation** | Aggregate IOCs, export CSV/JSON/STIX | 2 weeks |
| **P6 — Reporting** | JSON/HTML/PDF reports, manifest | 2 weeks |
| **P7 — Polish** | Performance, i18n, docs, accessibility, packaging | 3 weeks |

**Total:** ~19 weeks (single senior dev) / ~10 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: hash computation, PE field extraction, string classification, verdict scoring, intel result normalization.
- **Integration**: full pipeline on known PE samples (benign: notepad.exe; malicious: EICAR-like test files, public malware samples in isolated env).
- **GUI**: `pytest-qt` for sample loading, PE tree navigation, string filtering, verdict display.
- **Property-based**: Hypothesis for string extraction regex, hash round-trips.
- **Security**: fuzz PE parser (malformed headers, truncated files) with Atheris; test with packed samples.
- **Cross-validation**: compare PE field extraction against `pecheck` or `pestudio` output; compare hashes against `sha256sum`.
- **Network**: mock HTTP responses for intel lookups; test rate limiting and error handling.

---

## 13. Open Questions / Decisions Pending

1. **Sample upload to VT** — never by default; optional "upload" button with explicit warning .
2. **YARA integration** — optional module v2; adds `yara-python` dependency .
3. **Entropy calculation** — Shannon entropy per section; threshold for packing detection (default 7.0).
4. **FLOSS integration** — for obfuscated strings; optional module (requires FLOSS binary) .
5. **API key storage** — OS keychain preferred; encrypted config file fallback.
6. **Multi-file batch mode** — v2 feature; design pipeline for batch queue.
7. **Packer detection** — integrate `DIE` (Detect It Easy) or PEiD signatures via pefile .
8. **License** — `pefile` is public domain; `requests` is Apache 2.0; VT/MB/OTX APIs have terms of use; verify compliance.

---

## 14. Glossary

- **PE** — Portable Executable; Windows binary format (.exe, .dll, .sys).
- **DOS Header** — Legacy `MZ` header at start of PE.
- **NT Headers** — `PE\0\0` signature + File Header + Optional Header.
- **Section** — `.text` (code), `.data` (data), `.rdata` (read-only), `.rsrc` (resources).
- **Entropy** — Measure of randomness; high entropy suggests packing/encryption.
- **Import** — Function referenced from an external DLL.
- **Export** — Function made available to other modules (for DLLs).
- **PDB** — Program Database; debug symbols path.
- **VT** — VirusTotal; multi-engine malware scanning service.
- **MalwareBazaar** — abuse.ch malware sample repository.
- **OTX** — AlienVault Open Threat Exchange.
- **IOC** — Indicator of Compromise.
- **STIX** — Structured Threat Information Expression.
- **Verdict** — Overall assessment: CLEAN/SUSPICIOUS/MALICIOUS.
- **FLOSS** — FireEye Labs Obfuscated String Solver.

---

*End of document.*