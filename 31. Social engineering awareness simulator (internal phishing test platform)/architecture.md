# Architecture: Social Engineering Awareness Simulator (Internal Phishing Test Platform) — GUI-Based Solution

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS) for administration console; internal web server for landing pages
**Core Capability:** Internal phishing simulation campaigns with email delivery, landing page tracking, training delivery, and multi-format report export
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Social Engineering Awareness Simulator (SEAS)** is a GUI-driven desktop application for security awareness teams and internal red teams who need to **run authorized, ethical phishing simulation campaigns** to measure and improve employee resilience. It consolidates campaign creation, target management, email delivery, landing page tracking, and training delivery into a single administrative console.

Phishing simulations are now a core component of mature security awareness programs. Industry data shows that trained employees report phishing attempts at **4× the rate of untrained employees** , and organizations running simulations at least twice monthly generate significantly better behavioral data than quarterly cadence . The critical design principle is **psychological safety**: punishing users who fail simulations creates fear, suppresses reporting, and drives incidents underground . The winning metric is **reporting rate**, not click rate .

The tool is designed around four principles:

1. **Ethics-first** — no panic-inducing lures (layoffs, medical results, personal finances); professional, relevant pretexts only .
2. **Training, not punishment** — immediate post-click training; no PII visible in dashboards; positive reinforcement for reporting .
3. **Reporting-first metrics** — track reporting rate and time-to-report as primary KPIs; click rate is diagnostic, not the goal .
4. **Report-ready** — export campaign reports in JSON, CSV, HTML, and PDF with behavioral metrics and trend analysis.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    Admin Console (Qt6/PySide6)                       │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Campaign  │ │ Target    │ │ Template  │ │ Live      │ │ Report  │ │
│  │ Manager   │ │ Manager   │ │ Editor    │ │ Dashboard │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Training  │ │ Consent   │ │ Metrics   │ │ Audit     │ │ Console │ │
│  │ Manager   │ │ Manager   │ │ Explorer  │ │ Log       │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Local API
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Campaign Engine (Python/Flask)                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Email      │ │ Landing    │ │ Tracking   │ │ Training           │ │
│  │ Sender     │ │ Page Server│ │ Engine     │ │ Dispatcher         │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Data Layer                                       │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ SQLite     │ │ Template   │ │ Consent    │ │ Audit              │ │
│  │ Store      │ │ Store      │ │ Store      │ │ Log                │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Admin Console (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `CampaignManagerView` | Create/schedule campaigns: name, send window, target groups, template selection, difficulty level. Randomize send windows (up to 4 hours) to avoid batch patterns . |
| `TargetManagerView` | Import targets via CSV; assign to groups; track consent status. **Never display names/emails in dashboards** — use anonymous participant IDs (P-XXXXX) . |
| `TemplateEditorView` | Create/edit email templates with variable substitution ({{first_name}}, {{department}}); preview rendering; select landing page. |
| `LandingPageBuilderView` | Choose from cloned templates (Google, Microsoft 365, DocuSign, IT Helpdesk) or create custom; configure two-stage flows if needed . |
| `LiveDashboardView` | **Primary monitoring view.** Live event feed: sent → opened → clicked → submitted → reported → trained. Campaign funnel visualization . |
| `MetricsExplorerView` | Drill-down metrics: reporting rate, click rate, time-to-report, repeat-clicker reduction, risk distribution charts . |
| `TrainingManagerView` | Configure post-click training: immediate landing page, microlearning emails, LMS integration . |
| `ConsentManagerView` | Informed consent flows; consent-withdrawal; GDPR compliance documentation . |
| `ReportBuilderView` | **Export interface.** Format selection (JSON, CSV, HTML, PDF), date range, anonymization settings. |
| `ConsoleView` | Live log: email delivery, tracking events, errors. |

**Key UI Patterns:**
- **Anonymized by default**: dashboards show P-XXXXX IDs, never names or emails .
- **Funnel visualization**: sent → opened → clicked → submitted → trained .
- **Reporting-rate prominence**: reporting rate and time-to-report shown as primary KPIs .
- **Risk band coloring**: low (green), medium (yellow), high (red) based on weighted scoring .
- **Consent indicators**: targets without consent are excluded from campaigns.

### 3.2 Campaign Engine

**Email Sender**
- Uses `aiosmtplib` for async email delivery .
- Randomizes send windows to avoid batch detection .
- Embeds tracking pixel (1×1 PNG) for open detection .
- Personalized templates with variable substitution.

**Landing Page Server**
- Flask-based local server serving cloned landing pages .
- Intercepts form submissions via capture-phase event listeners (`stopImmediatePropagation()`) to prevent original page JS from interfering .
- **Never persists submitted credentials** — only records the fact of submission .
- Redirects to training page immediately after submission.

**Tracking Engine**
- **Open tracking**: 1×1 pixel load .
- **Click tracking**: landing page visit .
- **Submission tracking**: form interception .
- **Report tracking**: report-phish button click in email client .

**Training Dispatcher**
- Immediate post-submission training page highlighting missed red flags .
- Optional microlearning emails (3–5 minutes) sent days after failure .
- LMS integration via API/SCORM for enrollment .

### 3.3 Data Layer

**SQLite Schema (abridged):**
```sql
CREATE TABLE campaigns (
  id TEXT PRIMARY KEY, name TEXT, template_id TEXT,
  schedule_start TIMESTAMP, schedule_end TIMESTAMP,
  status TEXT, created_at TIMESTAMP
);
CREATE TABLE targets (
  id TEXT PRIMARY KEY, participant_id TEXT UNIQUE, -- P-XXXXX
  email_encrypted BLOB, group_id TEXT,
  consent_status TEXT, consent_date TIMESTAMP
);
CREATE TABLE campaign_events (
  id INTEGER PRIMARY KEY, campaign_id TEXT, target_id TEXT,
  event_type TEXT, -- 'sent','opened','clicked','submitted','reported','trained'
  event_ts TIMESTAMP, device_info_json TEXT
);
CREATE TABLE training_modules (
  id TEXT PRIMARY KEY, name TEXT, content_html TEXT,
  trigger_condition TEXT -- 'click','submit','repeat_click'
);
```

**Consent model:**
```python
@dataclass
class Consent:
    target_id: str
    status: str  # 'granted', 'withdrawn', 'pending'
    granted_at: datetime | None
    withdrawn_at: datetime | None
    method: str  # 'email_link', 'portal', 'paper'
```

### 3.4 Canonical Data Model

**Campaign event:**
```python
@dataclass
class CampaignEvent:
    event_id: str
    campaign_id: str
    participant_id: str  # P-XXXXX (anonymized)
    event_type: str  # 'sent','opened','clicked','submitted','reported','trained'
    timestamp: datetime
    device_info: dict | None  # OS, browser, mobile/desktop
```

**Campaign metrics:**
```python
@dataclass
class CampaignMetrics:
    campaign_id: str
    total_targets: int
    sent: int
    opened: int
    clicked: int
    submitted: int
    reported: int
    trained: int
    click_rate: float       # clicked / sent
    reporting_rate: float   # reported / sent
    submission_rate: float  # submitted / sent
    median_time_to_report_minutes: float | None
```

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, dashboard updates, live feed
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Campaign Worker (async)
  ├── Email delivery (aiosmtplib)
  ├── Random send windows
  └── Tracking event collection

Flask Server (separate thread)
  └── Landing page serving, form capture

Metrics Worker (single thread)
  └── Aggregation, report generation
```

**Rules:**
- Email delivery is async; no blocking on SMTP .
- Flask server runs in dedicated thread; campaigns isolated by session.
- Metrics aggregation runs on demand; cached for dashboard.
- SQLite in WAL mode; batch inserts.

---

## 5. Workflow: End-to-End User Journey

1. **Configure Consent** → import targets; collect consent; exclude non-consented.
2. **Create Campaign** → name, schedule, select template, assign groups.
3. **Select Landing Page** → choose cloned template or custom.
4. **Launch** → emails sent with randomized windows; tracking pixel embedded.
5. **Monitor Live** → dashboard shows funnel: sent → opened → clicked → submitted → reported.
6. **Deliver Training** → post-click training page; microlearning emails.
7. **Review Metrics** → reporting rate, click rate, time-to-report, risk bands.
8. **Export Report** → JSON/CSV/HTML/PDF with anonymized metrics.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Unauthorized use** | Explicit authorization acknowledgment; local-only by default. |
| **Credential persistence** | **Never store submitted credentials** — only the fact of submission . |
| **PII exposure** | Anonymized participant IDs (P-XXXXX); no names/emails in dashboards . |
| **Consent compliance** | Informed consent; withdrawal flow; GDPR documentation . |
| **Psychological harm** | Avoid panic-inducing lures; professional pretexts only . |
| **Punitive culture** | Training, not punishment; positive reinforcement for reporting . |
| **Email delivery** | SMTP credentials in OS keychain; TLS enforced. |

---

## 7. Extensibility Points

1. **New channel** — implement `DeliveryChannel` ABC (email, SMS, voice) .
2. **New landing template** — HTML template with capture-phase injection .
3. **New training module** — YAML/HTML with trigger condition .
4. **New export format** — `Exporter` ABC (JSON, CSV, HTML, PDF).
5. **LMS integration** — SCORM/API connector .

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 2 s |
| Email delivery (1000 targets) | < 5 min |
| Landing page response | < 200 ms |
| Dashboard update | < 1 s |
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
| Email | `aiosmtplib` | Async SMTP  |
| Web server | `Flask` | Lightweight landing pages  |
| HTML parsing | `BeautifulSoup` | Template processing  |
| DB | SQLite (WAL) | Embedded, ACID |
| Encryption | `cryptography` (Fernet) | Consent records  |
| Report export | `json`, `csv`, `Jinja2`, `WeasyPrint` | Multi-format |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
seas/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── seas/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── campaign_manager.py
│       │   │   ├── target_manager.py
│       │   │   ├── template_editor.py
│       │   │   ├── landing_builder.py
│       │   │   ├── live_dashboard.py
│       │   │   ├── metrics_explorer.py
│       │   │   ├── training_manager.py
│       │   │   ├── consent_manager.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── campaigns_table_model.py
│       │   │   └── targets_table_model.py
│       │   └── widgets/
│       │       ├── funnel_chart.py
│       │       ├── risk_badge.py
│       │       └── consent_indicator.py
│       ├── core/
│       │   ├── campaign/
│       │   │   ├── engine.py
│       │   │   ├── scheduler.py
│       │   │   └── sender.py
│       │   ├── landing/
│       │   │   ├── server.py
│       │   │   ├── templates/
│       │   │   └── capture.py
│       │   ├── tracking/
│       │   │   └── engine.py
│       │   ├── training/
│       │   │   └── dispatcher.py
│       │   └── consent/
│       │       └── manager.py
│       ├── storage/
│       │   ├── campaign_store.py
│       │   ├── target_store.py
│       │   └── event_store.py
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── json_exporter.py
│       │   │   ├── csv_exporter.py
│       │   │   ├── html_exporter.py
│       │   │   └── pdf_exporter.py
│       │   └── templates/
│       └── utils/
│           ├── anonymize.py
│           └── logging.py
├── templates/
│   ├── emails/
│   └── landing/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── gui/
├── resources/
│   └── icons/
└── docs/
    ├── architecture.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, campaign manager, target manager | 2 weeks |
| **P1 — Email Delivery** | aiosmtplib integration, template rendering, send windows  | 2 weeks |
| **P2 — Landing Pages** | Flask server, cloned templates, capture-phase injection  | 2 weeks |
| **P3 — Tracking** | Open pixel, click tracking, submission tracking  | 1 week |
| **P4 — Training** | Post-click training page, microlearning dispatcher  | 2 weeks |
| **P5 — Dashboard** | Live event feed, funnel chart, metrics explorer | 2 weeks |
| **P6 — Consent** | Informed consent flow, withdrawal, GDPR documentation  | 1 week |
| **P7 — Reporting** | JSON/CSV/HTML/PDF export with anonymization | 2 weeks |
| **P8 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~17 weeks (single senior dev) / ~9 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: template rendering, event tracking, consent logic, anonymization.
- **Integration**: full campaign with mock SMTP; verify funnel metrics.
- **GUI**: `pytest-qt` for dashboard, metrics explorer, report builder.
- **Ethics**: verify no panic-inducing lures; verify no credential persistence.
- **Consent**: verify non-consented targets excluded.

---

## 13. Open Questions / Decisions Pending

1. **SMTP provider** — internal relay vs. external (SendGrid, Mailgun)? Recommend: internal relay for privacy.
2. **LMS integration** — API vs. SCORM? Recommend: API for modern LMS (Moodle, Canvas) .
3. **Multi-channel scope** — email-only for v1; SMS/vishing for v2 .
4. **Risk scoring weights** — click 50%, time-to-click 15%, difficulty 15%, reporting 20% . Recommend: configurable.

---

## 14. Glossary

- **Phishing Simulation** — Authorized test of employee susceptibility to phishing .
- **Reporting Rate** — % of simulated phish reported by employees; primary KPI .
- **Time-to-Report** — Median time from delivery to employee report .
- **Psychological Safety** — Non-punitive culture where reporting is rewarded .
- **Consent** — Informed agreement to participate; GDPR requirement .
- **Anonymized Participant ID** — P-XXXXX identifier; no PII in dashboards .
- **Capture-Phase Injection** — Event interception before page JS sees submission .
- **Tracking Pixel** — 1×1 PNG for open detection .

---

*End of document.*