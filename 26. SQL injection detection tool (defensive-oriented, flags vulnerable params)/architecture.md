# Architecture: SQL Injection Detection Tool — Defensive-Oriented (GUI-Based Solution)

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** Defensive-oriented SQL injection detection with parameter flagging, evidence capture, remediation guidance, and multi-format report export
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **SQL Injection Detection Tool (SIDT)** is a GUI-driven desktop application for application security engineers, developers, and authorized penetration testers who need to **identify SQL injection vulnerabilities in web applications they own or are authorized to test**. It provides a defensive-oriented workflow: detection is paired with evidence capture, severity assessment, remediation guidance, and reporting suitable for handing to development teams.

SQL injection remains one of the most critical and persistent web vulnerabilities, consistently appearing in the OWASP Top 10 . The industry-standard approach is well-established: inject crafted payloads into parameters and observe response differences — error-based, boolean-based blind, time-based blind, and union-based techniques each produce distinct signals . Frameworks like sqlmap automate this, but they are CLI-centric, aggressive by default, and oriented toward exploitation rather than remediation.

The tool is designed around four principles:

1. **Defensive by design** — no data extraction, no shell upload, no destructive payloads; detection only, with explicit "safe mode" default.
2. **Evidence-first findings** — every flagged parameter is backed by the exact request, response, and signal that triggered the detection.
3. **Remediation-oriented output** — each finding includes parameterized query guidance, ORM recommendations, and WAF rule suggestions .
4. **Report-ready** — export findings in JSON, CSV, HTML, and PDF with severity, evidence, and remediation for developer handoff.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Target    │ │ Discovery │ │ Scan      │ │ Finding   │ │ Report  │ │
│  │ Config    │ │ Console   │ │ Dashboard │ │ Inspector │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Parameter │ │ Technique │ │ Evidence  │ │ Remediation│ │ Console│ │
│  │ Inventory │ │ Selector  │ │ Viewer    │ │ Guide     │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Scan       │ │ Injection  │ │ Finding    │ │ Event Bus / Log    │ │
│  │ Controller │ │ Engine     │ │ Analyzer   │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Detection Engine Layer                           │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ HTTP Client    │ │ Payload        │ │ Detection Techniques     │  │
│  │ (session,      │ │ Generator      │ │ (error, boolean, time,   │  │
│  │  rate limit)   │ │ (technique-    │ │  union)                  │  │
│  │                │ │  specific)     │ │                          │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Response       │ │ DBMS           │ │ WAF Detection            │  │
│  │ Analyzer       │ │ Fingerprinter  │ │ (evasion awareness)      │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Scan       │ │ Finding    │ │ Evidence   │ │ Report Store       │ │
│  │ Store      │ │ Store      │ │ Store      │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `TargetConfigView` | Configure target URL, authentication (cookies, headers, bearer tokens), scope (allowed domains), rate limiting, safe-mode toggle. |
| `DiscoveryConsoleView` | Live discovery progress: URLs crawled, parameters found (query, POST body, headers, cookies). Manual parameter addition. |
| `ParameterInventoryView` | Table of discovered parameters: URL, method, parameter name, location (query/body/header/cookie), sample value, scan status. |
| `TechniqueSelectorView` | Choose detection techniques: error-based, boolean-based blind, time-based blind, union-based. Safe mode restricts to error-based and boolean-based (no time delays, no union). |
| `ScanDashboardView` | **Primary scanning view.** Real-time stats: requests sent, payloads per parameter, responses by status code, vulnerabilities flagged. Progress bar. |
| `FindingsInspectorView` | **Primary findings view.** Table of flagged parameters: URL, parameter, technique, confidence, severity, DBMS hint. Click → show evidence. |
| `EvidenceViewer` | Side-by-side request/response comparison: baseline request vs. injected request; baseline response vs. injected response. Highlight the signal (error, boolean difference, time delta). |
| `RemediationGuideView` | Per-finding remediation: parameterized query examples (Python, Java, Node, PHP), ORM guidance, WAF rule suggestions. |
| `ReportBuilderView` | **Export interface.** Format selection (JSON, CSV, HTML, PDF), include sections (findings, evidence, remediation, coverage). |
| `ConsoleView` | Live log: HTTP errors, rate limits, analyzer decisions, WAF detection events. |

**Key UI Patterns:**
- **Defensive-first posture**: safe mode enabled by default; destructive techniques require explicit opt-in with a warning.
- **Evidence-linked findings**: every finding links to baseline and injected request/response pairs.
- **Severity color coding**: Critical (red), High (orange), Medium (yellow), Low (blue).
- **Confidence indicators**: high confidence (multiple techniques agree), medium (single technique), low (ambiguous).
- **Remediation-first detail view**: the first thing shown for a finding is how to fix it, not how to exploit it.

### 3.2 Orchestration Layer

**Scan Controller**
- Manages scan lifecycle: discovery → parameter selection → baseline capture → injection → analysis → reporting.
- Coordinates rate limiting, concurrency, and cancellation.
- Tracks scan progress and findings.

**Injection Engine**
- For each parameter, applies technique-specific payloads.
- Captures baseline response before injection.
- Injects payloads and captures responses.
- Manages session state (cookies, tokens) across requests.

**Finding Analyzer**
- Compares injected response against baseline to determine if the payload triggered a vulnerability.
- Aggregates signals across techniques to compute confidence.
- Flags parameters as vulnerable, suspicious, or clean.

### 3.3 Detection Engine Layer

**HTTP Client**
- Wraps `requests` with session management, rate limiting, retry, and timeout.
- Supports authenticated sessions (cookies, headers, bearer tokens, CSRF token extraction).
- Configurable user-agent, proxy support for authorized testing through Burp/ZAP .

**Payload Generator**

Technique-specific payload sets:

| Technique | Detection Method | Sample Payload | Signal |
|---|---|---|---|
| **Error-based** | Inject payloads that trigger DBMS errors | `'` , `"` , `')` , `';--` | Error message containing SQL keywords |
| **Boolean-based blind** | Inject true/false conditions, compare responses | `' AND '1'='1` vs `' AND '1'='2` | Response difference (content length, status, hash) |
| **Time-based blind** | Inject delays, measure response time | `'; WAITFOR DELAY '0:0:5'--` | Response time delta > threshold |
| **Union-based** | Inject UNION SELECT, look for injected content | `' UNION SELECT NULL--` | Injected data appears in response |

**Safe mode payloads**: error-based and boolean-based only (no time delays, no UNION, no destructive operations).

**Response Analyzer**
- **Error detection**: signature matching against DBMS error messages (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) .
- **Boolean difference**: compares baseline vs. injected response using content length, status code, response hash, and fuzzy similarity.
- **Time delta**: measures response time; flags if injected request exceeds baseline by configurable threshold (default: 5 seconds).
- **Union detection**: looks for injected markers in response.

**DBMS Fingerprinter**
- Attempts to identify backend DBMS from error messages, version-specific behaviors, and response patterns.
- Enables technique selection and remediation specificity.

**WAF Detection**
- Detects presence of WAF via response headers (e.g., `Server: cloudflare`, `X-Sucuri-ID`), block pages, and response codes.
- Reports WAF presence without attempting evasion (defensive tool).

### 3.4 Storage Layer

**Data directory:**
```
~/.sidt/
├── scans/
│   └── <scan_id>/
│       ├── scan.json             # Full scan record
│       ├── findings.jsonl        # Per-parameter findings
│       ├── evidence/             # Request/response captures
│       └── report.html
├── payloads/
│   └── *.yaml                    # Payload definitions per technique
├── reports/
│   └── <scan_id>_report.pdf
└── logs/
    └── sidt.log
```

**Scan record model:**
```python
@dataclass
class SqlInjectionScan:
    scan_id: str
    timestamp: datetime
    target_url: str
    safe_mode: bool
    techniques_used: list[str]
    parameters_tested: int
    requests_sent: int
    findings: list[SqlInjectionFinding]

@dataclass
class SqlInjectionFinding:
    finding_id: str
    url: str
    method: str
    parameter_name: str
    parameter_location: str         # 'query', 'body', 'header', 'cookie'
    technique: str                  # 'error', 'boolean', 'time', 'union'
    confidence: str                 # 'high', 'medium', 'low'
    severity: str                   # 'critical', 'high', 'medium', 'low'
    dbms_hint: str | None           # 'mysql', 'postgresql', 'mssql', ...
    signal: str                     # human-readable signal description
    baseline_request: str
    injected_request: str
    baseline_response_snippet: str
    injected_response_snippet: str
    response_delta: dict            # length delta, time delta, status change
    remediation: str
    references: list[str]
```

### 3.5 Canonical Data Model

See `SqlInjectionScan` and `SqlInjectionFinding` above.

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, dashboard updates, findings display
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Scan Worker Pool (QThreadPool, N workers)
  ├── Parameter scanning threads (parallel across parameters)
  ├── HTTP requests (rate-limited)
  └── Response analysis

Writer Thread (serial)
  └── SQLite/JSON writes for findings and evidence
```

**Rules:**
- Parameters scanned in parallel (default: 5 concurrent).
- Rate limiting enforced globally (default: 10 req/s) to avoid overwhelming target.
- Time-based technique serialized (timing-sensitive).
- SQLite in WAL mode; batch inserts.
- Cancellation: `threading.Event` checked between requests.

---

## 5. Workflow: End-to-End User Journey

1. **Configure Target** → enter URL, authentication, scope, safe mode.
2. **Discover Parameters** → crawl site or import from OpenAPI; list parameters.
3. **Select Techniques** → choose error-based, boolean-based, time-based, union-based (safe mode limits).
4. **Capture Baseline** → send benign request per parameter; record baseline response.
5. **Inject Payloads** → send technique-specific payloads; record responses.
6. **Analyze Responses** → detect signals; flag vulnerable parameters.
7. **Review Findings** → table of flagged parameters with severity and confidence.
8. **Inspect Evidence** → side-by-side baseline vs. injected request/response.
9. **Read Remediation** → parameterized query guidance for each finding.
10. **Export Report** → JSON/CSV/HTML/PDF for developer handoff.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Destructive payloads** | Safe mode default; no `DROP`, `DELETE`, `UPDATE`, `INSERT` payloads ever; detection-only . |
| **Authorization** | Explicit authorization acknowledgment required before scanning; scope restricted to configured domains. |
| **Rate limiting** | Configurable rate limit (default 10 req/s); avoids DoS. |
| **Data extraction** | No data extraction; UNION-based detection uses markers, not real data. |
| **Time-based delays** | Disabled in safe mode; when enabled, capped at 5 seconds. |
| **Credential handling** | Auth tokens stored encrypted; never logged. |
| **WAF evasion** | Not implemented — defensive tool detects but does not evade . |
| **Report sensitivity** | Reports contain URLs and payloads; redaction profile for external sharing. |

---

## 7. Extensibility Points

1. **New detection technique** — implement `DetectionTechnique` ABC (error, boolean, time, union, out-of-band).
2. **New DBMS signature** — YAML in `dbms_signatures/` for error messages.
3. **New payload set** — YAML in `payloads/` per technique.
4. **New export format** — `Exporter` ABC (JSON, CSV, HTML, PDF, SARIF).
5. **CI/CD integration** — CLI mode for pipeline scanning with SARIF output.

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 2 s |
| Parameter discovery (100 URLs) | < 60 s |
| Baseline capture (per parameter) | < 500 ms |
| Injection requests (per parameter per technique) | < 30 requests |
| Full scan (100 parameters, safe mode) | < 15 min |
| Report generation | < 5 s |
| Memory footprint | < 300 MB RSS |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly |
| HTTP client | `requests` + `httpx` (async optional) | Standard |
| HTML parsing | `BeautifulSoup` | Parameter and form discovery |
| OpenAPI parsing | `openapi-spec-validator`, `prance` | Spec import |
| Fuzzy comparison | `difflib`, `rapidfuzz` | Boolean difference detection |
| DB | SQLite (WAL) | Embedded, ACID |
| Report export | `json`, `csv`, `Jinja2`, `WeasyPrint` | Multi-format |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
sidt/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── sidt/
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
│       │   │   ├── discovery_console.py
│       │   │   ├── parameter_inventory.py
│       │   │   ├── technique_selector.py
│       │   │   ├── scan_dashboard.py
│       │   │   ├── findings_inspector.py
│       │   │   ├── evidence_viewer.py
│       │   │   ├── remediation_guide.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── parameters_table_model.py
│       │   │   └── findings_table_model.py
│       │   └── widgets/
│       │       ├── severity_badge.py
│       │       ├── confidence_indicator.py
│       │       └── request_response_diff.py
│       ├── core/
│       │   ├── discovery/
│       │   │   ├── crawler.py
│       │   │   └── openapi_parser.py
│       │   ├── http/
│       │   │   └── client.py
│       │   ├── payloads/
│       │   │   ├── generator.py
│       │   │   └── sets/
│       │   │       ├── error.yaml
│       │   │       ├── boolean.yaml
│       │   │       ├── time.yaml
│       │   │       └── union.yaml
│       │   ├── techniques/
│       │   │   ├── base.py
│       │   │   ├── error_based.py
│       │   │   ├── boolean_blind.py
│       │   │   ├── time_blind.py
│       │   │   └── union_based.py
│       │   ├── analysis/
│       │   │   ├── response_analyzer.py
│       │   │   ├── dbms_fingerprint.py
│       │   │   └── waf_detect.py
│       │   └── remediation/
│       │       └── generator.py
│       ├── storage/
│       │   ├── scan_store.py
│       │   ├── finding_store.py
│       │   └── evidence_store.py
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── json_exporter.py
│       │   │   ├── csv_exporter.py
│       │   │   ├── html_exporter.py
│       │   │   └── pdf_exporter.py
│       │   └── templates/
│       └── utils/
│           ├── sanitize.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── gui/
├── resources/
│   ├── icons/
│   ├── dbms_signatures/
│   └── themes/
└── docs/
    ├── architecture.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, target config, HTTP client, crawler | 2 weeks |
| **P1 — Parameter Discovery** | Crawler, form extraction, OpenAPI import, inventory | 2 weeks |
| **P2 — Error-Based** | Error payloads, DBMS error signatures, finding display | 2 weeks |
| **P3 — Boolean-Based** | Boolean payloads, response diff, confidence scoring | 2 weeks |
| **P4 — Evidence Viewer** | Baseline vs. injected request/response diff | 1 week |
| **P5 — Remediation** | Parameterized query examples, ORM guidance | 1 week |
| **P6 — Time/Union (Opt-in)** | Time-based and union-based techniques (safe mode off) | 2 weeks |
| **P7 — DBMS/WAF Detection** | Fingerprinting, WAF detection | 1 week |
| **P8 — Reporting** | JSON/CSV/HTML/PDF export | 2 weeks |
| **P9 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~18 weeks (single senior dev) / ~9 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: payload generation, error signature matching, response diff, confidence scoring.
- **Integration**: full scan against intentionally vulnerable test apps (DVWA, OWASP Juice Shop, WebGoat).
- **GUI**: `pytest-qt` for dashboard, findings inspector, evidence viewer.
- **Cross-validation**: compare findings against sqlmap on the same target (defensive mode).
- **Safety**: verify no destructive payloads; verify rate limiting; verify safe mode restrictions.

---

## 13. Open Questions / Decisions Pending

1. **sqlmap integration** — optional: use sqlmap backend for detection . Recommend: custom engine for v1; sqlmap wrapper optional.
2. **Time-based delays** — disabled in safe mode; enable only with explicit opt-in and cap. Recommend: opt-in with 5s cap.
3. **Out-of-band detection** — DNS/HTTP callback for blind detection. Recommend: v2 feature.
4. **WAF evasion** — explicitly out of scope (defensive tool). Document clearly .

---

## 14. Glossary

- **SQLi** — SQL Injection; injection of SQL code into application queries.
- **Error-based** — Detection via DBMS error messages in response.
- **Boolean-based blind** — Detection via true/false response differences.
- **Time-based blind** — Detection via response time delays.
- **Union-based** — Detection via UNION SELECT injection.
- **Safe mode** — Restricted technique set; no destructive or slow payloads.
- **Parameterized query** — Primary remediation; separates SQL code from data .
- **WAF** — Web Application Firewall; may block or rate-limit injection attempts.
- **DBMS** — Database Management System (MySQL, PostgreSQL, MSSQL, Oracle, SQLite).

---

*End of document.*