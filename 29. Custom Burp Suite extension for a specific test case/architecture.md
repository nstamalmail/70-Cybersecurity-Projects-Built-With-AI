# Architecture: Custom Burp Suite Extension for a Specific Test Case — GUI-Based Solution

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** A specialized Burp Suite extension framework — with an optional companion Python GUI — for automating a specific, repeatable web application test case, with finding capture and multi-format report export
**GUI Stack:** Python 3.10+ / PySide6 (Qt6) for companion GUI; Jython/Java for in-Burp extension
**Status:** Design Specification

---

## 1. Executive Summary

The **Custom Burp Suite Extension Framework (CBSEF)** is a design for building a **purpose-built Burp Suite extension** targeting one specific, well-defined web security test case (for example: mass-assignment detection, JWT algorithm-confusion testing, OAuth redirect-URI validation, GraphQL introspection abuse, or HTTP request smuggling). It combines an in-Burp extension (Java/Kotlin via the Montoya API, or Python via Jython for legacy Burp) with an **optional Python desktop companion GUI** for configuration, passive monitoring, and report generation.

Burp Suite's extension ecosystem is powerful but generic — the built-in scanner covers common vulnerability classes, but organizations with a **specific recurring test case** (an internal API convention, a custom auth flow, a proprietary parameter pattern) need tailored automation. The Burp **Montoya API** provides the modern extension surface: `HttpHandler` for intercepting and modifying requests/responses, `ScannerCheck` for custom scan checks, `ContextMenuItemsProvider` for UI integration, and `ExtensionStateListener` for lifecycle management .

The tool is designed around four principles:

1. **Single-test-case focus** — the extension does one thing exceptionally well; it is not a general-purpose scanner.
2. **Passive-first detection** — wherever possible, detect from naturally occurring traffic (`HttpHandler`) rather than generating additional requests, minimizing impact on the target .
3. **Human-confirmed findings** — the extension flags candidates; the analyst confirms; only confirmed findings appear in reports.
4. **Report-ready** — export findings in JSON, CSV, HTML, and PDF with request/response evidence, severity, and remediation.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│              Python Companion GUI (PySide6) [optional]               │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Test Case │ │ Live      │ │ Finding   │ │ Report    │ │ Console │ │
│  │ Config    │ │ Findings  │ │ Inspector │ │ Builder   │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Local REST / WebSocket
┌───────────────────────────────▼──────────────────────────────────────┐
│                  Burp Suite (Montoya API host)                       │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Custom Extension (Java/Kotlin or Jython)                       │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │  │
│  │  │ Http     │ │ Scanner  │ │ Context  │ │ Extension State  │   │  │
│  │  │ Handler  │ │ Check    │ │ Menu     │ │ Listener         │   │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘   │  │
│  │  ┌──────────────────────────────────────────────────────────┐  │  │
│  │  │ Test-Case Engine (detection logic specific to the case)  │  │  │
│  │  └──────────────────────────────────────────────────────────┘  │  │
│  │  ┌──────────────────────────────────────────────────────────┐  │  │
│  │  │ Findings Store + Local HTTP Bridge to Companion GUI      │  │  │
│  │  └──────────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Burp Extension Component (Montoya API)

**HttpHandler**
- Intercepts every proxied request/response pair.
- For the specific test case, inspects requests for the trigger pattern (e.g., a specific header, parameter, or endpoint).
- Passively records candidate findings without modifying traffic.
- Optionally injects test payloads when active scanning is enabled (analyst opt-in).
- Registered via `api.registerHttpHandler(handler)` .

**ScannerCheck**
- Implements a custom active scan check for the specific test case.
- Receives `HttpRequestResponse` and `AuditInsertionPoint` from Burp's scanner.
- Performs the case-specific probe and reports issues via `auditIssue` .
- Used only when the analyst runs an active scan against an authorized target.

**ContextMenuItemsProvider**
- Adds a right-click menu item in Burp's Proxy/Repeater/Target context menus: **"Send to [Extension Name]"** .
- Lets the analyst manually submit a request for case-specific analysis without waiting for passive detection.

**ExtensionStateListener**
- Handles extension unload/reload; flushes findings to disk; closes bridge connections .

**Test-Case Engine**
- The core logic specific to the chosen test case. Examples:
  - **Mass-assignment detection**: compares API responses when extra fields are added to JSON bodies; flags when server accepts and returns undocumented fields.
  - **JWT algorithm confusion**: parses JWTs, attempts `none` algorithm and HMAC-with-public-key variants; flags acceptance.
  - **OAuth redirect-URI validation**: mutates `redirect_uri` parameters with bypass patterns (subdomain tricks, path traversal, open redirects); flags acceptance.
  - **GraphQL introspection abuse**: sends introspection queries; flags when enabled on production endpoints.
  - **HTTP request smuggling**: sends CL.TE / TE.CL probes with timing and differential analysis.
- Emits `CandidateFinding` objects to the Findings Store.

**Findings Store**
- In-memory list of candidate and confirmed findings.
- Each finding holds: request, response, evidence, timestamp, confidence, status (candidate/confirmed/false-positive).

**Local Bridge**
- Small HTTP or WebSocket server exposed on `127.0.0.1` for the companion GUI.
- Endpoints: `GET /findings`, `POST /findings/{id}/confirm`, `GET /config`, `POST /config`.
- No external network exposure; bound to loopback only.

### 3.2 Python Companion GUI (PySide6)

| Widget | Responsibility |
|---|---|
| `TestConfigView` | Configure the test case: trigger pattern, payload set, detection thresholds, active vs. passive mode. |
| `LiveFindingsView` | **Primary view.** Real-time table of candidate findings: timestamp, URL, endpoint, parameter, confidence, evidence summary. Sorted by time; filtered by confidence. |
| `FindingInspectorView` | Drill-down: request, response, evidence (differential, timing, error), confidence explanation. Confirm / Mark False Positive buttons. |
| `ReportBuilderView` | **Export interface.** Format selection (JSON, CSV, HTML, PDF), include sections (findings, evidence, remediation, coverage). |
| `ConsoleView` | Live log: bridge messages, extension status, errors. |

**Key UI Patterns:**
- **Live streaming**: candidate findings appear as the proxy processes traffic.
- **Confirm/Reject workflow**: candidates require analyst confirmation before appearing in reports.
- **Confidence indicators**: high (multiple signals agree), medium (single strong signal), low (ambiguous).
- **Evidence-first detail**: the request/response pair is the primary artifact; the interpretation is secondary.

### 3.3 Analysis Flow (Example: Mass-Assignment Detection)

1. **Passive**: `HttpHandler` observes a POST/PUT request with a JSON body.
2. **Baseline capture**: records the response.
3. **Active probe** (opt-in): re-sends the request with one additional field (e.g., `"is_admin": true`) appended to the JSON body.
4. **Differential analysis**: compares baseline and probe responses.
5. **Signal detection**: flags if the probe response differs (new field echoed, different status, different body size).
6. **Finding emission**: creates a `CandidateFinding` with both requests and responses.
7. **Analyst confirmation**: analyst reviews and confirms.
8. **Report**: confirmed finding is exported.

### 3.4 Storage Layer

**Data directory (companion GUI):**
```
~/.cbsef/
├── config/
│   └── test_case_config.yaml
├── findings/
│   └── <session_id>/
│       ├── findings.jsonl
│       ├── evidence/
│       │   ├── <finding_id>_request.txt
│       │   └── <finding_id>_response.txt
│       └── report.html
├── reports/
│   └── <session_id>_report.pdf
└── logs/
    └── cbsef.log
```

**Finding model:**
```python
@dataclass
class CandidateFinding:
    finding_id: str
    test_case: str                 # 'mass_assignment', 'jwt_confusion', ...
    timestamp: datetime
    url: str
    method: str
    endpoint: str
    parameter: str | None
    confidence: str                # 'high', 'medium', 'low'
    status: str                    # 'candidate', 'confirmed', 'false_positive'
    signal_description: str
    baseline_request: str
    baseline_response: str
    probe_request: str | None
    probe_response: str | None
    differential: dict | None      # length delta, status delta, field echo
    remediation: str
```

### 3.5 Canonical Data Model

See `CandidateFinding` above.

---

## 4. Threading & Concurrency Model

**Burp Extension (Java/Jython):**
```
Burp Main Thread
  └── Extension event handlers (HttpHandler, ScannerCheck)

Worker Pool
  ├── Active probe threads (parallel probes)
  └── Differential analysis threads
```

**Companion GUI (Python):**
```
Main Thread (Qt)
  ├── UI events, findings table, inspector
  └── Bridge client polling / WebSocket receive

Bridge Listener Thread
  └── Receives findings, updates model
```

**Rules:**
- Burp's `HttpHandler` must return quickly; heavy analysis is deferred to worker threads.
- Passive detection is lightweight (in-line); active probing is queued.
- Companion GUI polls the bridge or subscribes to WebSocket; UI updates marshalled via Qt signals.
- No blocking of Burp's proxy pipeline.

---

## 5. Workflow: End-to-End User Journey

1. **Install Extension** → load JAR (or `.py` for Jython) into Burp; verify loaded in Extender tab.
2. **Configure Test Case** → via Burp UI panel or companion GUI: trigger pattern, payload set, mode (passive/active).
3. **Browse Target** → proxy traffic through Burp; extension passively observes.
4. **Candidate Findings Appear** → companion GUI shows live candidates.
5. **Review Candidate** → inspect request/response and evidence; confirm or reject.
6. **Active Probe (Optional)** → analyst triggers active scan on authorized target; scanner check runs.
7. **Confirm Findings** → analyst marks confirmed.
8. **Export Report** → JSON/CSV/HTML/PDF with confirmed findings and evidence.
9. **Remediate** → share remediation guidance with development team.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Unauthorized scanning** | Active mode requires explicit analyst action; passive mode observes only traffic the analyst is already proxying. |
| **Target impact** | Passive mode generates zero extra requests; active probes are rate-limited and non-destructive. |
| **False positives** | Analyst confirmation required before report inclusion. |
| **Credential exposure** | Request/response evidence may contain credentials; redaction in exports. |
| **Loopback bridge security** | Bridge bound to `127.0.0.1`; random token required; no external exposure. |
| **Extension sandbox** | Burp's extension model is in-process; the extension is trusted code — audit before installing. |
| **Evidence sensitivity** | Local-only storage; optional encryption at rest. |

---

## 7. Extensibility Points

1. **New test case** — implement `TestCase` ABC with `detect()` and `probe()` methods.
2. **New signal detector** — extend `SignalDetector` (differential, timing, error, reflection).
3. **New export format** — `Exporter` ABC (JSON, CSV, HTML, PDF, SARIF).
4. **Jython vs Montoya** — Jython for legacy Burp; Montoya API (Java/Kotlin) for modern Burp .
5. **Multi-test-case mode** — optional: bundle multiple test cases with per-case enable/disable.

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Extension load time | < 2 s |
| Passive detection latency | < 50 ms per request |
| Active probe rate | 5 req/s (configurable) |
| Bridge latency | < 100 ms |
| Companion GUI startup | < 2 s |
| Report generation | < 5 s |
| Memory footprint (GUI) | < 200 MB RSS |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Burp Extension | Java/Kotlin (Montoya API) | Modern, supported |
| Burp Extension (legacy) | Jython 2.7 | Legacy Burp compatibility |
| Build | Gradle | Standard for Burp extensions |
| Companion GUI | Python 3.10+ / PySide6 | Commercial-friendly |
| Bridge | `websockets` or Flask (loopback only) | Lightweight IPC |
| Report export | `json`, `csv`, `Jinja2`, `WeasyPrint` | Multi-format |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller (GUI), Gradle JAR (extension) | Cross-platform |
| Testing | pytest + pytest-qt (GUI), JUnit (extension) | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
cbsef/
├── extension/                     # Burp extension (Java/Kotlin)
│   ├── build.gradle
│   ├── src/main/java/.../
│   │   ├── CbsefExtension.java
│   │   ├── HttpHandlerImpl.java
│   │   ├── ScannerCheckImpl.java
│   │   ├── ContextMenuImpl.java
│   │   ├── TestCaseEngine.java
│   │   ├── FindingsStore.java
│   │   └── LocalBridge.java
│   └── resources/
│       └── test_cases/
├── gui/                           # Python companion GUI
│   ├── pyproject.toml
│   ├── src/cbsef_gui/
│   │   ├── main.py
│   │   ├── views/
│   │   │   ├── test_config.py
│   │   │   ├── live_findings.py
│   │   │   ├── finding_inspector.py
│   │   │   ├── report_builder.py
│   │   │   └── console.py
│   │   ├── models/
│   │   │   └── findings_table_model.py
│   │   ├── bridge/
│   │   │   └── client.py
│   │   ├── reporting/
│   │   │   ├── json_exporter.py
│   │   │   ├── csv_exporter.py
│   │   │   ├── html_exporter.py
│   │   │   └── pdf_exporter.py
│   │   └── storage/
│   │       └── finding_store.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── gui/
├── docs/
│   ├── architecture.md
│   ├── test_case_authoring.md
│   └── user_guide.md
└── resources/
    └── icons/
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Extension Skeleton** | Montoya API extension, HttpHandler, context menu, bridge stub | 2 weeks |
| **P1 — Test Case Engine** | Specific test-case detection logic, signal detectors | 3 weeks |
| **P2 — Passive Detection** | In-line detection, candidate emission, findings store | 2 weeks |
| **P3 — Companion GUI** | PySide6 shell, live findings table, inspector | 2 weeks |
| **P4 — Bridge** | Loopback HTTP/WebSocket, secure token, finding sync | 1 week |
| **P5 — Active Scanning** | ScannerCheck implementation, rate-limited probes | 2 weeks |
| **P6 — Confirm/Reject** | Analyst workflow, false-positive tracking | 1 week |
| **P7 — Reporting** | JSON/CSV/HTML/PDF export with evidence | 2 weeks |
| **P8 — Polish** | Performance, i18n, docs, packaging (JAR + EXE) | 3 weeks |

**Total:** ~18 weeks (single senior dev) / ~9 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit (extension)**: test-case detection logic, differential analysis, signal detection, JUnit.
- **Unit (GUI)**: bridge client, finding store, export generation.
- **Integration**: full workflow on intentionally vulnerable lab apps (DVWA, WebGoat) through Burp.
- **GUI**: `pytest-qt` for live findings, inspector, report builder.
- **Cross-validation**: compare findings against manual testing on the same target.
- **Safety**: verify passive mode generates no extra requests; verify active mode rate limiting.

---

## 13. Open Questions / Decisions Pending

1. **Montoya vs Jython** — Jython is deprecated for new Burp versions . Recommend: Montoya (Java/Kotlin) for v1; Jython only if legacy Burp support is required.
2. **Companion GUI necessity** — Burp has its own UI; the companion GUI adds cross-session reporting and richer evidence view. Recommend: optional; extension works standalone.
3. **Bridge security** — loopback + token; no TLS needed on loopback. Recommend: random token per session.
4. **Specific test case selection** — the framework is generic but must ship with one concrete test case. Recommend: mass-assignment detection as the reference implementation.

---

## 14. Glossary

- **Burp Suite** — Web application security testing platform.
- **Montoya API** — Modern Burp extension API (replaces legacy Extender API) .
- **HttpHandler** — Burp API interface for intercepting HTTP traffic .
- **ScannerCheck** — Burp API interface for custom active scan checks .
- **ContextMenuItemsProvider** — Burp API interface for adding context menu items .
- **ExtensionStateListener** — Burp API interface for extension lifecycle events .
- **Jython** — Python 2.7 implementation for JVM; legacy Burp extension language.
- **Candidate Finding** — Detected signal awaiting analyst confirmation.
- **Loopback Bridge** — Local-only IPC between extension and companion GUI.

---

*End of document.*