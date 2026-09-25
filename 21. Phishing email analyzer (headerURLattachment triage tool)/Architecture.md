# Architecture: Phishing Email Analyzer (Header/URL/Attachment Triage Tool) — GUI-Based Solution

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** Multi-vector phishing email triage covering header authentication analysis, URL/domain risk assessment, attachment static analysis, and multi-format report export
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Phishing Email Analyzer (PEA)** is a GUI-driven desktop application for SOC analysts and incident responders who need to **rapidly triage suspicious emails** without switching between multiple tools. It consolidates the three pillars of email investigation into a single workflow: **header authentication analysis** (SPF/DKIM/DMARC results, sender spoofing indicators, routing chain inspection), **URL and domain risk assessment** (defanging, redirect chain analysis, domain reputation), and **attachment static analysis** (file type validation, hash computation, macro detection) .

Phishing remains the dominant initial access vector, accounting for a significant majority of malware delivery . The triage workflow is well-established: extract observables, enrich them, decide on action, and document findings . Yet analysts still juggle multiple tools — one for header analysis, another for URL scanning, a third for attachment inspection. This tool unifies the workflow.

The tool is designed around four principles:

1. **Header-first triage** — authentication results (SPF/DKIM/DMARC) are the strongest technical indicators of spoofing and are checked immediately .
2. **Defang by default** — extracted URLs, IPs, and domains are displayed and exported in defanged format (`hxxp://`, `[.]`) for safe sharing .
3. **Attachment safety** — attachments are statically analyzed only; never executed; hashes computed for reputation lookup .
4. **Report-ready** — export triage findings in JSON, CSV, HTML, and PDF formats with defanged indicators, risk scores, and MITRE ATT&CK mapping.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Email     │ │ Header    │ │ URL       │ │ Attachment│ │ Report  │ │
│  │ Loader    │ │ Analyzer  │ │ Analyzer  │ │ Analyzer  │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Risk      │ │ IOC       │ │ Routing   │ │ Defang    │ │ Console │ │
│  │ Dashboard │ │ Summary   │ │ Chain     │ │ Preview   │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Triage     │ │ Enrichment │ │ IOC        │ │ Event Bus / Log    │ │
│  │ Controller │ │ Pipeline   │ │ Extractor  │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Analysis Engine Layer                            │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ MIME Parser    │ │ Header Auth    │ │ URL Analyzer             │  │
│  │ (mail-parser)  │ │ Analyzer       │ │ (defang, redirect,       │  │
│  │                │ │ (SPF/DKIM/     │ │  reputation)             │  │
│  │                │ │  DMARC)        │ │                          │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Attachment     │ │ IOC Extractor  │ │ Risk Scorer              │  │
│  │ Analyzer       │ │ (iocflow)      │ │ (weighted signals)       │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Triage     │ │ IOC Store  │ │ Attachment │ │ Report Store       │ │
│  │ Store      │ │            │ │ Store      │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `EmailLoaderView` | Load `.eml` or `.msg` files via drag/drop or file browser. Display basic metadata (subject, from, date, size) . |
| `HeaderAnalyzerView` | **Primary header view.** Display SPF/DKIM/DMARC results (pass/fail/softfail/neutral) with color coding . Show From vs Return-Path vs Reply-To discrepancies. Display Received header chain (bottom-to-top routing) . |
| `UrlAnalyzerView` | Table of extracted URLs: defanged form, domain, redirect chain (if followed), reputation status, risk indicator . Click URL → show full analysis (domain age, IP, registration). |
| `AttachmentAnalyzerView` | Table of attachments: filename, MIME type, size, hash (MD5/SHA1/SHA256), file type validation, macro presence (for Office docs), embedded objects . Click attachment → show detailed analysis. |
| `RoutingChainView` | Visual representation of the Received header chain: originating IP → intermediate hops → destination. Highlight anomalous hops, mismatched domains, private IPs . |
| `RiskDashboardView` | **Primary triage verdict view.** Overall risk score (0-100), verdict (Safe / Suspicious / Likely Phishing), contributing signals breakdown . |
| `IocSummaryView` | Consolidated IOCs: defanged IPs, domains, URLs, email addresses, attachment hashes. Exportable as JSON, CSV, STIX . |
| `DefangPreviewView` | Toggle between raw and defanged views of all indicators. Defang by default for safe sharing . |
| `ReportBuilderView` | **Export interface.** Format selection (JSON, CSV, HTML, PDF), sections to include (header analysis, URLs, attachments, IOCs, verdict), template selection. |
| `ConsoleView` | Live log: parser warnings, enrichment errors, API rate limits. |

**Key UI Patterns:**
- **Verdict-first dashboard**: large risk score with color gradient (red → yellow → green) and clear verdict label .
- **Authentication color coding**: SPF/DKIM/DMARC results in green (pass), yellow (softfail/neutral), red (fail) .
- **Defang by default**: all indicators shown in defanged form; toggle to reveal raw for authorized analysis .
- **Click-to-drill**: click a URL → show redirect chain and reputation; click attachment → show full static analysis.
- **Safety banner**: "Attachments are analyzed statically and never executed."

### 3.2 Orchestration Layer

**Triage Controller**
- Manages the triage lifecycle: load → parse → analyze headers → extract URLs → analyze URLs → analyze attachments → score → report.
- Coordinates between parsers and analyzers.
- Tracks progress and handles errors.

**Enrichment Pipeline**
- Optional enrichment of URLs and IPs with reputation data (VirusTotal, URLScan.io, AbuseIPDB).
- Domain age lookup (WHOIS) for newly registered domains .
- Graceful degradation if APIs unavailable.

**IOC Extractor**
- Extracts indicators from email body, headers, and attachments using `iocflow` patterns .
- Deduplicates across sources.
- Applies false-positive filters (public suffix validation, benign domain allowlist) .

### 3.3 Analysis Engine Layer

**MIME Parser**
- Uses `mail-parser` for robust MIME parsing with defect detection .
- Extracts headers, body (plain/HTML), attachments, nested messages.
- Handles malformed MIME boundaries that may conceal malicious content .

**Header Auth Analyzer**
- Parses `Authentication-Results` header for SPF, DKIM, DMARC outcomes .
- Extracts `Received` header chain for routing analysis .
- Compares From, Return-Path, Reply-To, and Message-ID domains for mismatches .
- Flags `X-Originating-IP` and `X-Sender-IP` for sender identification .

**URL Analyzer**
- Extracts URLs from plain text and HTML body .
- Defangs URLs (`http://` → `hxxp://`, `.` → `[.]`) .
- Optionally follows redirect chains (configurable; disabled by default for safety) .
- Enriches with reputation data: VirusTotal, URLScan.io .

**Attachment Analyzer**
- Extracts and identifies attachment types (executable, Office, PDF, archive, script) .
- Computes MD5, SHA1, SHA256 hashes for reputation lookup .
- **Office documents**: Detects VBA macros, auto-execution triggers, embedded objects, external template references .
- **PDFs**: Detects JavaScript, embedded files, suspicious actions.
- **Archives**: Lists contents without extraction (path traversal, nested executables) .
- **Never executes attachments** — static analysis only.

**IOC Extractor**
- Uses `iocflow` for extraction of IPs, domains, URLs, hashes, emails from unstructured text .
- Defangs all extracted indicators by default .
- Filters private IPs, benign domains, and version-number false positives .

**Risk Scorer**
- Computes risk score (0-100) from weighted signals :
  - SPF/DKIM/DMARC failure: +30
  - Reply-To mismatch: +15
  - URL shortener or IP-based URL: +15
  - Newly registered domain (< 30 days): +20
  - Attachment with macro or executable: +25
  - Urgency/credential-harvesting language: +10
- Verdict thresholds: 0-20 Safe, 21-55 Suspicious, 56-100 Likely Phishing .

### 3.4 Storage Layer

**Data directory:**
```
~/.pea/
├── triages/
│   └── <triage_id>/
│       ├── triage.json           # Full analysis record
│       ├── iocs.json             # Extracted indicators
│       ├── attachments/          # Extracted attachments (hashed)
│       └── report.html
├── enrichment/
│   └── cache.json                # Cached reputation lookups
├── reports/
│   └── <triage_id>_report.pdf
└── logs/
    └── pea.log
```

**Triage record model:**
```python
@dataclass
class PhishingTriage:
    triage_id: str
    timestamp: datetime
    subject: str
    from_address: str
    return_path: str | None
    reply_to: str | None
    spf_result: str | None          # 'pass', 'fail', 'softfail', 'neutral'
    dkim_result: str | None
    dmarc_result: str | None
    received_chain: list[str]
    risk_score: int                 # 0-100
    verdict: str                    # 'safe', 'suspicious', 'likely_phishing'
    urls: list[UrlAnalysis]
    attachments: list[AttachmentAnalysis]
    iocs: dict[str, list[str]]      # {'ipv4': [], 'domain': [], 'url': [], ...}
    signals: list[RiskSignal]

@dataclass
class UrlAnalysis:
    url_defanged: str
    domain: str
    redirect_chain: list[str]
    reputation: str | None          # 'malicious', 'suspicious', 'clean', 'unknown'
    vt_detections: int | None
    is_shortener: bool
    is_ip_based: bool

@dataclass
class AttachmentAnalysis:
    filename: str
    mime_type: str
    size: int
    md5: str
    sha1: str
    sha256: str
    is_executable: bool
    has_macro: bool
    embedded_objects: list[str]
```

### 3.5 Canonical Data Model

See `PhishingTriage`, `UrlAnalysis`, and `AttachmentAnalysis` above.

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, dashboard, tables, preview
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Parsing Worker (single thread)
  ├── MIME parsing
  ├── Header extraction
  └── Body extraction

Analysis Pool (QThreadPool, N workers)
  ├── Header auth analysis
  ├── URL extraction and defanging
  ├── Attachment analysis (parallel per attachment)
  └── IOC extraction

Enrichment Pool (QThreadPool, 4 workers)
  ├── VirusTotal lookups
  ├── URLScan.io lookups
  └── WHOIS domain age
```

**Rules:**
- MIME parsing is fast; runs in worker to avoid blocking on large emails.
- Attachment analysis parallelized across attachments.
- Enrichment lookups parallelized and rate-limited.
- Cancellation: `threading.Event` checked between analysis stages.

---

## 5. Workflow: End-to-End User Journey

1. **Load Email** → drag/drop `.eml` or `.msg` file .
2. **Parse MIME** → extract headers, body, attachments .
3. **Analyze Headers** → SPF/DKIM/DMARC results, From/Return-Path/Reply-To comparison, routing chain .
4. **Extract URLs** → from body; defang; optionally follow redirects .
5. **Enrich URLs** → reputation lookup (VT, URLScan) .
6. **Analyze Attachments** → hashes, file type, macros, embedded objects .
7. **Extract IOCs** → IPs, domains, URLs, hashes, emails; defang .
8. **Compute Risk Score** → weighted signals; verdict .
9. **Review Dashboard** → verdict, contributing signals, drill into details.
10. **Export Report** → JSON/CSV/HTML/PDF with defanged IOCs and verdict.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Malicious attachment** | Static analysis only; never executed; hashes computed for lookup . |
| **Malicious URL** | Never fetched by default; redirect following disabled; reputation lookup only . |
| **MIME parser exploit** | `mail-parser` is robust with defect detection ; runs in worker with resource limits. |
| **API key exposure** | Enrichment API keys in OS keychain; never logged. |
| **Email data sensitivity** | Local-only storage; optional encryption at rest; defang by default. |
| **Accidental click** | All URLs displayed defanged; copy button provides defanged version . |

---

## 7. Extensibility Points

1. **New attachment analyzer** — implement `AttachmentAnalyzer` ABC (Office, PDF, archive, script).
2. **New URL enrichment source** — implement `UrlEnricher` ABC (VirusTotal, URLScan, Google Safe Browsing).
3. **New risk signal** — add to `RiskScorer` weight table.
4. **New export format** — `Exporter` ABC (JSON, CSV, HTML, PDF, STIX 2.1).
5. **Sandbox integration** — optional: submit attachments to sandbox for dynamic analysis .

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 2 s |
| Email parse (10 MB) | < 2 s |
| Header analysis | < 500 ms |
| URL extraction and defang | < 1 s |
| Attachment static analysis (per file) | < 3 s |
| Report generation | < 3 s |
| Memory footprint | < 300 MB RSS |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly |
| MIME parsing | `mail-parser` | Robust, defect-aware  |
| MSG parsing | `parse-emails` or `aspose-email` | `.msg` support  |
| IOC extraction | `iocflow` | Defang/refang, false-positive filters  |
| URL enrichment | `requests` (VT, URLScan, AbuseIPDB) | Standard APIs  |
| WHOIS | `python-whois` | Domain age lookup |
| Report export | `json`, `csv`, `Jinja2`, `WeasyPrint` | Multi-format |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
pea/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── pea/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── email_loader.py
│       │   │   ├── header_analyzer.py
│       │   │   ├── url_analyzer.py
│       │   │   ├── attachment_analyzer.py
│       │   │   ├── routing_chain.py
│       │   │   ├── risk_dashboard.py
│       │   │   ├── ioc_summary.py
│       │   │   ├── defang_preview.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── urls_table_model.py
│       │   │   └── attachments_table_model.py
│       │   └── widgets/
│       │       ├── risk_gauge.py
│       │       ├── auth_badge.py
│       │       └── defang_toggle.py
│       ├── core/
│       │   ├── parser/
│       │   │   ├── mime_parser.py
│       │   │   └── msg_parser.py
│       │   ├── analysis/
│       │   │   ├── header_auth.py
│       │   │   ├── url_analyzer.py
│       │   │   ├── attachment_analyzer.py
│       │   │   └── ioc_extractor.py
│       │   ├── enrichment/
│       │   │   ├── virustotal.py
│       │   │   ├── urlscan.py
│       │   │   └── whois.py
│       │   ├── scoring/
│       │   │   └── risk_scorer.py
│       │   └── defang/
│       │       └── defanger.py
│       ├── storage/
│       │   ├── triage_store.py
│       │   └── ioc_store.py
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── json_exporter.py
│       │   │   ├── csv_exporter.py
│       │   │   ├── html_exporter.py
│       │   │   └── pdf_exporter.py
│       │   └── templates/
│       └── utils/
│           ├── hashing.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── gui/
├── resources/
│   ├── icons/
│   └── templates/
└── docs/
    ├── architecture.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, email loader, MIME parser | 2 weeks |
| **P1 — Header Analysis** | SPF/DKIM/DMARC parsing, From/Return-Path comparison  | 2 weeks |
| **P2 — URL Analysis** | URL extraction, defanging, redirect chain  | 2 weeks |
| **P3 — Attachment Analysis** | Hash computation, file type, macro detection  | 2 weeks |
| **P4 — IOC Extraction** | iocflow integration, defanged IOC summary  | 1 week |
| **P5 — Risk Scoring** | Weighted signals, verdict dashboard  | 1 week |
| **P6 — Enrichment** | VirusTotal, URLScan, WHOIS integration  | 2 weeks |
| **P7 — Reporting** | JSON/CSV/HTML/PDF export | 2 weeks |
| **P8 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~17 weeks (single senior dev) / ~9 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: header parsing, URL defanging, attachment hash computation, risk scoring.
- **Integration**: full pipeline on synthetic phishing emails with known IOCs.
- **GUI**: `pytest-qt` for dashboard, tables, defang toggle.
- **Cross-validation**: compare SPF/DKIM/DMARC parsing against manual header inspection .
- **Safety**: verify attachments never executed; URLs never fetched by default.

---

## 13. Open Questions / Decisions Pending

1. **URL redirect following** — disabled by default for safety; enable per-case with warning . Recommend: disabled by default.
2. **Sandbox integration** — optional submission to sandbox for dynamic attachment analysis . Recommend: v2 feature.
3. **MSG format** — `.msg` support via `parse-emails` or `aspose-email` . Recommend: `parse-emails` for simplicity.
4. **IOC extraction library** — `iocflow` provides defang/refang and false-positive filters . Recommend: `iocflow` for v1.

---

## 14. Glossary

- **SPF** — Sender Policy Framework; verifies sending IP is authorized .
- **DKIM** — DomainKeys Identified Mail; cryptographic signature verification .
- **DMARC** — Domain-based Message Authentication; combines SPF/DKIM .
- **Defang** — Converting live indicators to safe form (`hxxp://`, `[.]`) .
- **MIME** — Multipurpose Internet Mail Extensions; email structure format .
- **Verdict** — Overall assessment: Safe / Suspicious / Likely Phishing .
- **IOC** — Indicator of Compromise .
- **Reply-To mismatch** — Reply-To domain differs from From domain .
- **Newly registered domain** — Domain < 30 days old; strong phishing indicator .

---

*End of document.*