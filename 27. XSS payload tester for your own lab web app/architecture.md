# Architecture: XSS Payload Tester for Lab Web Apps (GUI-Based Solution)

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** Controlled XSS detection against authorized lab web applications with reflected/stored/DOM-aware payload injection, browser-based confirmation, and multi-format report export
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **XSS Payload Tester (XPT)** is a GUI-driven desktop application for application security engineers, developers, and students who need to **test their own lab web applications for cross-site scripting vulnerabilities** in a controlled, browser-confirmed manner. It provides a defensive-oriented workflow: payloads are injected, reflections are detected, and confirmations are produced via an embedded headless browser — with clear evidence, severity scoring, and remediation guidance.

Cross-site scripting remains one of the most prevalent web vulnerabilities. The four canonical types — reflected, stored, DOM-based, and mutation (mXSS) — each have distinct detection requirements . Reflected XSS requires observing payload reflection in the immediate response; stored XSS requires the payload to persist and execute on a subsequent page load; DOM-based XSS requires observing sink execution in the browser's runtime, not just server responses. Automated tools that rely purely on HTTP reflection miss DOM-based XSS entirely, and tools that rely purely on browser alerts miss server-side encoding nuances.

The tool is designed around four principles:

1. **Browser-confirmed, not reflection-guessed** — a finding is only confirmed when the payload actually executes (alert fired, DOM mutated, callback received) in the embedded headless browser.
2. **Multi-type coverage** — reflected, stored, and DOM-based detection in one workflow.
3. **Lab-scoped by design** — explicit authorization acknowledgment, domain allowlist enforcement, no scanning of third-party sites.
4. **Report-ready** — export findings in JSON, CSV, HTML, and PDF with PoC payloads, evidence screenshots, and remediation guidance.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Target    │ │ Discovery │ │ Payload   │ │ Findings  │ │ Report  │ │
│  │ Config    │ │ Console   │ │ Library   │ │ Inspector │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Scan      │ │ Browser   │ │ Evidence  │ │ Remediation│ │ Console│ │
│  │ Dashboard │ │ Preview   │ │ Viewer    │ │ Guide     │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Scan       │ │ Injection  │ │ Confirm    │ │ Event Bus / Log    │ │
│  │ Controller │ │ Engine     │ │ Engine     │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Detection Engine Layer                           │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ HTTP Client    │ │ Payload        │ │ Reflection               │  │
│  │ (session,      │ │ Generator      │ │ Analyzer                 │  │
│  │  CSRF tokens)  │ │ (context-aware)│ │ (encoding, context)      │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Headless       │ │ DOM Sink       │ │ Stored XSS               │  │
│  │ Browser        │ │ Monitor        │ │ Confirmer                │  │
│  │ (Playwright)   │ │                │ │                          │  │
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
| `TargetConfigView` | Configure target URL, authentication (cookies, headers, tokens), CSRF token handling, scope allowlist (required), authorization acknowledgment checkbox. |
| `DiscoveryConsoleView` | Live discovery progress: URLs crawled, forms identified, parameters and input fields found, DOM sinks in JavaScript. |
| `PayloadLibraryView` | Browse and edit payload sets per context: HTML body, HTML attribute, JavaScript string, URL parameter, CSS context. Preview generated payloads. |
| `ScanDashboardView` | **Primary scanning view.** Real-time stats: requests sent, payloads injected, reflections detected, browser confirmations, findings. Progress bar. |
| `FindingsInspectorView` | **Primary findings view.** Table of findings: URL, parameter, XSS type (reflected/stored/DOM), context, severity, confidence, confirmation method. Click → show evidence. |
| `EvidenceViewer` | For each finding: injected payload, reflection snippet (with encoding shown), browser screenshot, console log, DOM mutation trace. |
| `BrowserPreviewView` | Embedded headless browser view showing the payload executing in real time (screenshot or live render). |
| `RemediationGuideView` | Per-finding remediation: output encoding guidance (context-specific), CSP recommendations, framework-specific escaping (React, Angular, Django, Rails) . |
| `ReportBuilderView` | **Export interface.** Format selection (JSON, CSV, HTML, PDF), include sections (findings, PoC payloads, screenshots, remediation, coverage). |
| `ConsoleView` | Live log: HTTP errors, browser console output, analyzer decisions. |

**Key UI Patterns:**
- **Browser-confirmed badge**: findings confirmed via browser execution show a distinct badge (higher confidence than reflection-only).
- **Context visualization**: shows exactly where the payload landed (HTML body, attribute, script) and how it was encoded.
- **Screenshot evidence**: every confirmed finding includes a browser screenshot.
- **Severity color coding**: Critical (stored XSS), High (reflected/DOM XSS), Medium (partial encoding), Low (suspicious reflection).
- **Safety banner**: "Lab-only tool. Authorized targets only."

### 3.2 Orchestration Layer

**Scan Controller**
- Manages scan lifecycle: discovery → payload injection → reflection analysis → browser confirmation → reporting.
- Coordinates HTTP client, browser engine, and analyzer.
- Tracks scan progress and findings.

**Injection Engine**
- Injects context-appropriate payloads into discovered parameters.
- Handles CSRF token refresh, session management, multi-step forms.
- For stored XSS: submits payload, then navigates to the page where it would render.

**Confirm Engine**
- Uses headless browser (Playwright) to load pages containing reflected/stored payloads.
- Monitors for execution signals: `alert()` fired, DOM mutation, `console.log`, network callback (XSS Hunter-style out-of-band).
- Captures screenshot and DOM snapshot as evidence.

### 3.3 Detection Engine Layer

**HTTP Client**
- Session management with cookies, headers, bearer tokens.
- CSRF token extraction and refresh per request.
- Rate limiting and retry.

**Payload Generator**

Context-aware payload sets:

| Context | Detection Focus | Sample Payload |
|---|---|---|
| **HTML body** | `<script>`, `<img onerror>`, `<svg onload>` | `<script>alert(1)</script>` |
| **HTML attribute** | Break-out from quotes | `" onmouseover="alert(1)` |
| **JavaScript string** | Break-out from string, `</script>` | `';alert(1);//` , `</script><script>alert(1)</script>` |
| **URL parameter** | `javascript:` scheme, DOM injection | `javascript:alert(1)` |
| **CSS context** | `expression()`, `url()` | `background:url(javascript:alert(1))` |
| **Template literals** | Backtick break-out | `` `+alert(1)+` `` |

**Reflection Analyzer**
- Locates injected payload in response.
- Determines encoding applied (raw, HTML-encoded, URL-encoded, JS-escaped, no encoding).
- Classifies context (inside `<script>`, inside attribute, inside HTML body).
- Flags "suspicious reflection" when payload appears unencoded or partially encoded.

**Headless Browser (Playwright)**
- Launches Chromium in headless mode with isolated context.
- Loads pages with injected payloads.
- Injects `alert`/`confirm`/`prompt` overrides to detect execution.
- Captures `console.log` output.
- Records screenshots and DOM snapshots on execution.

**DOM Sink Monitor**
- Statically analyzes JavaScript for dangerous sinks: `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout`, `location.href` .
- Instruments source-to-sink flows in the headless browser to detect DOM XSS.
- Uses taint-style tracking where feasible (browser-level, not full AST analysis).

**Stored XSS Confirmer**
- Submits payload via form or API.
- Navigates to the page(s) where the payload would render (profile, comment section, admin panel).
- Uses headless browser to confirm execution.
- Handles multi-step workflows (login → post → view).

### 3.4 Storage Layer

**Data directory:**
```
~/.xpt/
├── scans/
│   └── <scan_id>/
│       ├── scan.json             # Full scan record
│       ├── findings.jsonl        # Per-finding details
│       ├── evidence/
│       │   ├── <finding_id>_screenshot.png
│       │   ├── <finding_id>_dom.html
│       │   └── <finding_id>_console.log
│       └── report.html
├── payloads/
│   └── *.yaml                    # Payload sets per context
├── reports/
│   └── <scan_id>_report.pdf
└── logs/
    └── xpt.log
```

**Scan record model:**
```python
@dataclass
class XssScan:
    scan_id: str
    timestamp: datetime
    target_url: str
    authorized: bool
    parameters_tested: int
    payloads_injected: int
    findings: list[XssFinding]

@dataclass
class XssFinding:
    finding_id: str
    url: str
    method: str
    parameter_name: str
    parameter_location: str         # 'query', 'body', 'header', 'cookie'
    xss_type: str                   # 'reflected', 'stored', 'dom'
    context: str                    # 'html_body', 'html_attribute', 'js_string', ...
    payload: str
    encoded_in_response: bool
    encoding_applied: str | None    # 'html_encoded', 'url_encoded', 'none'
    browser_confirmed: bool
    confirmation_method: str        # 'alert', 'dom_mutation', 'console', 'out_of_band'
    severity: str                   # 'critical', 'high', 'medium', 'low'
    confidence: str                 # 'high', 'medium', 'low'
    screenshot_path: str | None
    dom_snapshot_path: str | None
    remediation: str
    references: list[str]
```

### 3.5 Canonical Data Model

See `XssScan` and `XssFinding` above.

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, dashboard, findings display, browser preview
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Scan Worker Pool (QThreadPool, N workers)
  ├── HTTP injection threads (parallel across parameters)
  ├── Reflection analysis (fast, in-line)
  └── Browser confirmation queue (serialized, browser is stateful)

Browser Worker (single thread)
  ├── Playwright Chromium instance
  ├── Page navigation and payload execution
  └── Evidence capture (screenshots, DOM, console)
```

**Rules:**
- HTTP injection parallelized across parameters (default: 5 concurrent).
- Browser confirmation serialized (one page at a time) to avoid resource contention.
- Screenshots captured on execution; saved to evidence directory.
- SQLite in WAL mode; batch inserts.
- Cancellation: `threading.Event` checked between requests.

---

## 5. Workflow: End-to-End User Journey

1. **Configure Target** → enter URL, auth, scope allowlist, acknowledge authorization.
2. **Discover** → crawl site, identify forms, parameters, DOM sinks.
3. **Select Payloads** → choose payload set per context (or use defaults).
4. **Inject & Analyze** → inject payloads, detect reflections, classify encoding.
5. **Confirm in Browser** → load pages with reflected/stored payloads in headless browser; confirm execution.
6. **Review Findings** → table of confirmed findings with type, severity, confidence.
7. **Inspect Evidence** → view payload, reflection, screenshot, DOM snapshot.
8. **Read Remediation** → context-specific output encoding guidance.
9. **Export Report** → JSON/CSV/HTML/PDF with PoCs and screenshots.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Unauthorized scanning** | Explicit authorization checkbox; domain allowlist required; scope enforcement. |
| **Lab-only design** | Documented; target must be lab/localhost; third-party scanning blocked. |
| **Payload harm** | Payloads trigger `alert(1)` or harmless DOM mutations; no data exfiltration payloads . |
| **Out-of-band callbacks** | Optional; disabled by default; when enabled, only to analyst-controlled endpoints. |
| **Headless browser isolation** | Playwright browser runs with isolated context; no persistent cookies; no file access. |
| **Credential handling** | Auth tokens in encrypted store; never logged. |
| **CSP interference** | CSP may block execution; tool reports CSP presence and notes that findings may be mitigated . |
| **Rate limiting** | Configurable; default 5 req/s. |

---

## 7. Extensibility Points

1. **New payload set** — YAML in `payloads/` per context.
2. **New confirmation method** — extend `ConfirmEngine` (alert, DOM mutation, out-of-band).
3. **New DOM sink pattern** — YAML in `dom_sinks/`.
4. **New export format** — `Exporter` ABC (JSON, CSV, HTML, PDF, SARIF).
5. **CI/CD integration** — CLI mode with SARIF output for pipeline scanning.
6. **CSP analysis module** — analyze CSP headers for mitigation assessment .

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 3 s (includes Playwright init) |
| Discovery (100 URLs) | < 60 s |
| Injection (per parameter) | < 500 ms |
| Browser confirmation (per finding) | < 5 s |
| Full scan (50 parameters) | < 10 min |
| Report generation | < 5 s |
| Memory footprint | < 800 MB RSS (browser) |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly |
| HTTP client | `requests` / `httpx` | Standard |
| HTML parsing | `BeautifulSoup`, `lxml` | Parameter and form discovery |
| Headless browser | `playwright` (Chromium) | Reliable browser automation |
| JS parsing | `esprima` or `pyjsparser` | DOM sink static analysis |
| Fuzzy diff | `difflib` | Reflection comparison |
| DB | SQLite (WAL) | Embedded, ACID |
| Report export | `json`, `csv`, `Jinja2`, `WeasyPrint` | Multi-format |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
xpt/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── xpt/
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
│       │   │   ├── payload_library.py
│       │   │   ├── scan_dashboard.py
│       │   │   ├── findings_inspector.py
│       │   │   ├── evidence_viewer.py
│       │   │   ├── browser_preview.py
│       │   │   ├── remediation_guide.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── parameters_table_model.py
│       │   │   └── findings_table_model.py
│       │   └── widgets/
│       │       ├── severity_badge.py
│       │       ├── confirmation_badge.py
│       │       └── context_indicator.py
│       ├── core/
│       │   ├── discovery/
│       │   │   ├── crawler.py
│       │   │   └── dom_sink_scanner.py
│       │   ├── http/
│       │   │   └── client.py
│       │   ├── payloads/
│       │   │   ├── generator.py
│       │   │   └── sets/
│       │   │       ├── html_body.yaml
│       │   │       ├── html_attribute.yaml
│       │   │       ├── js_string.yaml
│       │   │       ├── url_param.yaml
│       │   │       └── css_context.yaml
│       │   ├── analysis/
│       │   │   ├── reflection.py
│       │   │   ├── context_classifier.py
│       │   │   └── encoding_detector.py
│       │   ├── browser/
│       │   │   ├── playwright_driver.py
│       │   │   ├── xss_confirmer.py
│       │   │   └── evidence_capture.py
│       │   ├── stored/
│       │   │   └── stored_confirmer.py
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
│   ├── payloads/
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
| **P1 — Discovery** | Form extraction, parameter inventory, DOM sink scanner | 2 weeks |
| **P2 — Reflected XSS** | Payload injection, reflection analysis, context classification | 2 weeks |
| **P3 — Browser Confirmation** | Playwright integration, alert detection, screenshot capture | 2 weeks |
| **P4 — Encoding Analysis** | Encoding detection, context-aware payloads | 1 week |
| **P5 — Stored XSS** | Multi-step submission, stored confirmation workflow | 2 weeks |
| **P6 — DOM XSS** | Source-to-sink instrumentation, DOM mutation detection | 2 weeks |
| **P7 — Remediation** | Context-specific encoding guidance | 1 week |
| **P8 — Reporting** | JSON/CSV/HTML/PDF export with screenshots | 2 weeks |
| **P9 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~19 weeks (single senior dev) / ~10 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: payload generation, reflection detection, encoding classification, context classification.
- **Integration**: full scan against intentionally vulnerable lab apps (DVWA, OWASP Juice Shop, WebGoat, XSS Game).
- **GUI**: `pytest-qt` for dashboard, findings inspector, evidence viewer.
- **Cross-validation**: compare findings against manual browser testing on the same lab app.
- **Safety**: verify allowlist enforcement; verify no payloads contain data exfiltration.
- **Browser**: verify headless browser isolation; verify screenshots captured on execution.

---

## 13. Open Questions / Decisions Pending

1. **Playwright vs Selenium** — Playwright is faster and more reliable for headless . Recommend: Playwright for v1.
2. **DOM XSS detection depth** — full taint tracking is complex; browser-level instrumentation is pragmatic . Recommend: source-to-sink instrumentation for v1; AST-based taint analysis for v2.
3. **Out-of-band confirmation** — needed for blind XSS (payload fires in admin panel). Recommend: optional, disabled by default; analyst provides callback endpoint.
4. **CSP interaction** — CSP may block execution; tool should report CSP presence and note mitigation . Recommend: report CSP, do not attempt bypass.

---

## 14. Glossary

- **XSS** — Cross-Site Scripting; injection of client-side scripts into web pages.
- **Reflected XSS** — Payload reflected in immediate response.
- **Stored XSS** — Payload persisted and rendered on subsequent page loads.
- **DOM XSS** — Payload executed via client-side JavaScript sinks.
- **mXSS** — Mutation XSS; payload mutates during browser parsing.
- **CSP** — Content Security Policy; browser-level mitigation.
- **Sink** — Dangerous JavaScript function (`innerHTML`, `eval`, `document.write`).
- **Source** — Attacker-controlled input (`location.hash`, `document.URL`) .
- **Headless Browser** — Browser without visible UI, used for automated testing.
- **Reflection** — Payload appearing in response; not always exploitable.
- **Output Encoding** — Primary remediation; context-specific escaping.

---

*End of document.*