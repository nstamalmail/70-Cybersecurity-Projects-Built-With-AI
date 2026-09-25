# Architecture: Ransomware Incident Tabletop Simulator + IR Runbook Builder (GUI-Based Solution)

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** Facilitate ransomware tabletop exercises and auto-generate/validate IR runbooks aligned with NIST SP 800-61r3 and CISA StopRansomware
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Ransomware Tabletop Simulator & IR Runbook Builder (RTS-IRB)** is a dual-purpose GUI application for security teams conducting ransomware preparedness exercises and building/maintaining incident response runbooks. It addresses two persistent gaps in organizational ransomware readiness: (1) tabletop exercises that surface real decision-making gaps, and (2) runbooks that are actionable under pressure rather than theoretical documents .

The tool provides two integrated modes:

**Simulator Mode** — A facilitator-driven tabletop exercise engine that walks participants through a ransomware incident in phases (Detection, Escalation, Decision, Recovery), injects realistic complications, captures decisions and rationale, and produces a findings report with prioritized remediation actions.

**Runbook Builder Mode** — A structured authoring environment for ransomware IR playbooks, with built-in templates aligned to NIST SP 800-61r3 and CISA StopRansomware, decision-tree logic, validation checks, and export to Markdown/PDF/HTML.

The two modes are linked: exercise findings feed directly into runbook gap analysis, and runbook validation can be run during exercises to test whether documented procedures actually work.

The tool is designed around four principles:

1. **Facilitator-first** — exercises are led by a dedicated facilitator (not a participant), with tooling that supports injection timing, note capture, and time-boxing .
2. **Runbooks that survive contact** — generated runbooks are actionable checklists, not narratives; every step is verifiable and assigned .
3. **Framework-aligned** — built-in alignment with NIST SP 800-61r3 (CSF 2.0 integration: Govern, Identify, Protect, Detect, Respond, Recover) and CISA guidance .
4. **Evidence-based improvement** — exercise outputs are structured findings with owners, deadlines, and linkage to specific runbook sections that need updating.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Exercise  │ │ Scenario  │ │ Live      │ │ Runbook   │ │ Findings│ │
│  │ Manager   │ │ Builder   │ │ Session   │ │ Editor    │ │ & Gaps  │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Decision  │ │ Inject    │ │ Runbook   │ │ Framework │ │ Report  │ │
│  │ Capture   │ │ Library   │ │ Validator │ │ Mapper    │ │ Export  │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots (async)
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Session    │ │ Phase      │ │ Injection  │ │ Event Bus / Log    │ │
│  │ Engine     │ │ Controller │ │ Scheduler  │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Core Processing Layer                            │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Scenario       │ │ Runbook        │ │ Framework Mapping        │  │
│  │ Engine         │ │ Template       │ │ (NIST CSF 2.0, CISA,     │  │
│  │ (phases,       │ │ Engine         │ │  ISO 27037, SWGDE)       │  │
│  │  injects)      │ │ (YAML→MD/PDF)  │ │                          │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Gap Analysis Engine: exercise findings ↔ runbook sections      │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Exercise   │ │ Runbook    │ │ Scenario   │ │ Finding / Gap      │ │
│  │ DB         │ │ Store      │ │ Library    │ │ Store              │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     OS / Runtime Abstraction Layer                   │
│  File I/O · TZ handling · Export (MD/PDF/HTML/DOCX) · Config store   │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `ExerciseManagerView` | Create/open exercises; metadata (organization, date, facilitator, participants, scope); select scenario template. |
| `ScenarioBuilderView` | Author/edit scenarios: phases, injects, decision points, timing. YAML-backed with GUI editor. |
| `LiveSessionView` | **Primary simulator view.** Phase navigation, timer, inject display, decision capture forms, participant roster, notes pane. |
| `DecisionCaptureView` | Structured forms for recording decisions: decision point, options considered, chosen path, rationale, owner, timestamp. |
| `InjectLibraryView` | Browse/edit reusable inject cards (e.g., "IR retainer not responding", "Journalist calls", "Backups take 72h") . |
| `RunbookEditorView` | Author/edit IR runbooks: sections, steps, checklists, decision trees, escalation matrix, communication templates. |
| `RunbookValidatorView` | Validate runbook against NIST/CISA checklists; flag missing sections, unclear owners, untestable steps. |
| `FrameworkMapperView` | Map runbook sections and exercise findings to NIST CSF 2.0 functions (Govern/Identify/Protect/Detect/Respond/Recover) and CISA phases . |
| `GapAnalysisView` | Cross-reference exercise findings with runbook sections; highlight gaps; suggest updates. |
| `ReportBuilderView` | Export exercise report (findings + action items) and/or runbook (MD/PDF/HTML/DOCX). |
| `ConsoleView` | Live log tail; session events; export errors. |

**Key UI Patterns**
- Two-mode layout: **Simulator** and **Builder** modes, switchable via a top-level tab or mode selector.
- Live session uses a **phase timeline** with a current-phase indicator, inject timer, and decision capture side panel.
- Runbook editor uses a **tree + detail** layout: sections in a tree, editable steps/checklists in the detail pane.
- Validation results shown inline (red/yellow/green badges on sections) plus a summary panel.
- Gap analysis uses a **two-column diff** view: exercise findings on left, runbook sections on right, with connector lines.

### 3.2 Orchestration Layer

**Session Engine**
- Manages exercise lifecycle: setup → phases → injects → decisions → wrap-up → report.
- Phase controller: sequential phase advancement with facilitator override.
- Injection scheduler: timed or manual inject delivery; tracks which injects have been used.
- Decision recorder: timestamped, immutable log of decisions and rationale.
- Time-boxing: per-phase timers with configurable duration (default: 30–45 min per phase) .

**Runbook Engine**
- Template loader: built-in templates (Court Report, Incident Response, Ransomware Playbook).
- Section resolver: evaluates conditional sections (e.g., "if data exfiltration suspected, include breach notification section").
- Validation engine: runs checklist against runbook structure and content.
- Export pipeline: render to MD → HTML → PDF/DOCX.

**Gap Analysis Engine**
- Compares exercise findings (structured) against runbook section coverage.
- Identifies: (1) findings with no corresponding runbook section, (2) runbook sections that failed during exercise, (3) decisions made without documented procedure.

**Scheduler**
- Injection delivery: timer-based, facilitator-triggered, or conditional (e.g., "if participant asks about backups, deliver backup inject").
- Report generation: async, with progress.

### 3.3 Scenario Engine

**Scenario model**
```python
@dataclass
class Scenario:
    scenario_id: str
    name: str
    description: str
    sector: str                    # 'retail', 'healthcare', 'finance', 'government', 'generic'
    threat_actor: str              # e.g., 'LockBit affiliate', 'state-linked'
    initial_access: str            # e.g., 'phishing', 'RDP', 'VPN exploit'
    data_at_risk: list[str]        # ['PII', 'PHI', 'financial', 'trade_secrets']
    phases: list[Phase]
    injects: list[Inject]
    decision_points: list[DecisionPoint]

@dataclass
class Phase:
    phase_id: str
    name: str                      # 'Detection', 'Escalation', 'Decision', 'Recovery'
    duration_minutes: int
    situation_report: str          # Markdown
    objectives: list[str]
    required_decisions: list[str]  # decision_point_ids

@dataclass
class Inject:
    inject_id: str
    phase_id: str
    title: str
    content: str                   # Markdown
    trigger: str                   # 'timed', 'manual', 'conditional'
    trigger_condition: str | None  # e.g., "participant mentions backups"
    order: int

@dataclass
class DecisionPoint:
    decision_id: str
    phase_id: str
    question: str
    options: list[DecisionOption]
    authority: str                 # who should decide
    criteria: list[str]            # decision criteria
    expected_outcome: str | None   # for facilitation guidance

@dataclass
class DecisionOption:
    option_id: str
    label: str
    consequences: list[str]
    is_preferred: bool             # facilitator guidance only
```

**Built-in scenario templates**
- **Retail Ransomware** (based on the "Enter the War Room" scenario): AI supply chain compromise, loyalty data theft, reputational attack .
- **Healthcare Ransomware**: PHI at risk, patient safety, HIPAA notification.
- **Municipal Ransomware**: public services disruption, citizen data, media pressure.
- **Manufacturing Ransomware**: OT/IT convergence, production halt, supply chain.
- **Generic Enterprise**: configurable sector, data types, threat actor.

**Scenario customization**
- All fields editable via GUI.
- Import/export scenarios as YAML.
- Scenario library shared across exercises.

### 3.4 Injection Library

**Inject categories**
- **Communication**: journalist calls, customer threats contract termination, employee leak to social media, deepfake of executive .
- **Technical**: backups partially encrypted, immutable backups intact but recovery slow (72h), second threat actor detected, C2 beacon discovered post-containment.
- **Legal/Regulatory**: regulator inquiry, breach notification deadline, law enforcement requests evidence preservation.
- **Business**: board meeting Monday, payroll disrupted, key vendor cannot deliver.
- **Ransom Decision**: attacker contacts executive directly, ransom demand increases, decryptor available but untrusted.

**Inject card format**
```yaml
inject:
  id: "inj-communic-001"
  phase: "escalation"
  title: "Journalist Makes Contact"
  category: "communication"
  content: |
    A journalist from a major outlet calls the main office number.
    They claim to have received data samples from the attackers
    and are preparing a story. They ask for comment by 5 PM today.
  trigger: "timed"
  trigger_minutes: 45
  probing_questions:
    - "Who handles media inquiries? Is that documented?"
    - "What is our approved messaging at this stage?"
    - "Do we have external counsel/PR on retainer?"
  linked_runbook_sections:
    - "communication.external"
    - "communication.media"
```

### 3.5 Runbook Engine

**Runbook model**
```python
@dataclass
class Runbook:
    runbook_id: str
    name: str
    version: str
    organization: str
    framework: str                 # 'NIST SP 800-61r3', 'CISA', 'custom'
    sections: list[RunbookSection]
    last_validated: datetime | None
    owner: str

@dataclass
class RunbookSection:
    section_id: str
    title: str
    phase: str                     # 'Preparation', 'Detection', 'Containment', 'Eradication', 'Recovery', 'Post-Incident'
    framework_refs: list[str]      # ['CSF.RS.MA-01', 'CISA.Containment.1']
    steps: list[RunbookStep]
    decision_tree: DecisionTree | None
    escalation: EscalationMatrix | None

@dataclass
class RunbookStep:
    step_id: str
    action: str                    # imperative, verifiable
    owner: str                     # role responsible
    verification: str              # how to confirm completion
    estimated_minutes: int | None
    dependencies: list[str]        # step_ids that must complete first
    references: list[str]          # links to tools, docs
```

**Built-in runbook templates**
- **Ransomware Playbook (CISA-aligned)**: Preparation, Detection & Analysis, Containment, Eradication & Recovery, Post-Incident .
- **NIST SP 800-61r3 Playbook**: CSF 2.0 functions with ransomware-specific outcomes .
- **Generic IR Playbook**: Service-agnostic IR runbook structure .

**Runbook structure template** (from runbook best practices) :
1. Overview & Impact
2. Detection & Alerts
3. Initial Triage
4. Mitigation Steps
5. Root Cause Investigation
6. Resolution Procedures
7. Verification & Rollback
8. Communication Templates
9. Escalation Matrix

**Decision trees**
- Visual decision-tree builder for complex decisions (e.g., "Pay ransom?" → conditions → outcomes).
- Rendered as interactive flowchart in runbook export.

**Escalation matrix**
- Table: severity, condition, escalate to, within, method, backup contact.

**Communication templates**
- Pre-written messages for: employees, customers, regulators, media, law enforcement.
- Variables substituted at export time (org name, incident ID, contact).

### 3.6 Validation Engine

**Validation against frameworks**
- **NIST CSF 2.0**: checks that each of the six functions (Govern, Identify, Protect, Detect, Respond, Recover) has coverage .
- **CISA StopRansomware**: checks that preparation, detection, containment, eradication, recovery, and post-incident phases are present .
- **Internal checklist**: configurable; defaults from runbook best practices .

**Validation checks**

| Check | Severity |
|---|---|
| Section has an owner | Required |
| Steps are imperative and verifiable | Required |
| Escalation matrix has backup contacts | Required |
| Communication templates include all stakeholder groups | Required |
| Decision trees have defined criteria | Recommended |
| Estimated times provided | Recommended |
| References to tools/docs present | Optional |
| Last validated within 12 months | Recommended |

**Validation output**
- Per-section badges: ✅ pass, ⚠️ warning, ❌ fail.
- Summary report with fix suggestions.
- Blocking failures prevent "final" status.

### 3.7 Gap Analysis Engine

**Inputs**
- Exercise findings (structured: decisions made, gaps identified, injects where response was inadequate).
- Runbook structure and content.

**Analysis**
- For each exercise finding, determine:
  - Is there a runbook section that addresses this?
  - Did the runbook section fail during exercise (e.g., owner unavailable, step unclear)?
  - Is there a decision that was made without documented procedure?

**Output**
```python
@dataclass
class GapFinding:
    gap_id: str
    exercise_id: str
    severity: str                  # 'critical', 'high', 'medium', 'low'
    category: str                  # 'missing_section', 'failed_procedure', 'undocumented_decision'
    description: str
    evidence: str                  # what happened during exercise
    affected_runbook_section: str | None
    remediation: str               # suggested action
    owner: str | None
    deadline: date | None
    status: str                    # 'open', 'in_progress', 'resolved'
```

**Gap-to-runbook linkage**
- Each gap is linked to a runbook section (existing or proposed).
- Runbook editor shows gap indicators on sections with open gaps.

### 3.8 Report Generation

**Exercise Report**
- Executive summary (non-technical).
- Scenario description.
- Phase-by-phase narrative.
- Decisions made (table with rationale).
- Findings and gaps (prioritized).
- Action items with owners and deadlines.
- Appendix: participant list, inject log, raw notes.

**Runbook Export**
- Markdown (source).
- HTML (web viewing).
- PDF/A (archival).
- DOCX (editable).
- JSON (machine-readable for CI/CD validation).

**Framework mapping report**
- Matrix: runbook sections × NIST CSF functions × CISA phases.
- Coverage heatmap.

### 3.9 Storage Layer

**Exercise Directory Layout**
```
exercises/<exercise_id>/
├── exercise.db                  # SQLite: metadata, decisions, findings, injects
├── scenario.yaml                # Scenario definition (snapshot)
├── decisions/
│   └── decision_log.jsonl       # Append-only decision log
├── injects/
│   └── inject_log.jsonl         # Inject delivery log
├── findings/
│   └── gaps.jsonl               # Gap findings
├── notes/
│   └── facilitator_notes.md
├── reports/
│   ├── exercise_report.html
│   ├── exercise_report.pdf
│   └── action_items.csv
└── logs/
    └── session.log
```

**Runbook Directory Layout**
```
runbooks/<runbook_id>/
├── runbook.yaml                 # Source definition
├── version_history/
│   ├── v1.0.yaml
│   └── v1.1.yaml
├── exports/
│   ├── runbook.md
│   ├── runbook.html
│   ├── runbook.pdf
│   └── runbook.docx
├── validation/
│   └── validation_report.json
└── gaps/
    └── linked_gaps.json
```

**SQLite Schema (abridged)**
```sql
CREATE TABLE exercises (
  id TEXT PRIMARY KEY, name TEXT, organization TEXT,
  facilitator TEXT, participants_json TEXT,
  scenario_id TEXT, started_at TIMESTAMP, finished_at TIMESTAMP,
  status TEXT
);
CREATE TABLE decisions (
  id TEXT PRIMARY KEY, exercise_id TEXT, decision_point_id TEXT,
  phase TEXT, ts TIMESTAMP, question TEXT,
  options_considered_json TEXT, chosen_option TEXT,
  rationale TEXT, decided_by TEXT, evidence_json TEXT
);
CREATE TABLE injects_delivered (
  id INTEGER PRIMARY KEY, exercise_id TEXT, inject_id TEXT,
  phase TEXT, delivered_at TIMESTAMP, trigger TEXT,
  participant_response TEXT
);
CREATE TABLE gaps (
  id TEXT PRIMARY KEY, exercise_id TEXT,
  severity TEXT, category TEXT, description TEXT,
  evidence TEXT, affected_section TEXT,
  remediation TEXT, owner TEXT, deadline DATE, status TEXT
);
CREATE TABLE runbooks (
  id TEXT PRIMARY KEY, name TEXT, version TEXT,
  organization TEXT, framework TEXT,
  owner TEXT, last_validated TIMESTAMP, status TEXT
);
CREATE TABLE runbook_sections (
  id TEXT PRIMARY KEY, runbook_id TEXT,
  title TEXT, phase TEXT, framework_refs_json TEXT,
  content_yaml TEXT
);
CREATE TABLE validation_results (
  id INTEGER PRIMARY KEY, runbook_id TEXT,
  validated_at TIMESTAMP, check_id TEXT,
  severity TEXT, passed INTEGER, message TEXT
);
```

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, live session display, decision capture
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Session Worker (single thread)
  ├── Injection scheduler (timers)
  ├── Decision log writer (append-only)
  └── Phase controller

Export Worker (QThreadPool)
  ├── Markdown renderer
  ├── HTML renderer
  ├── PDF renderer (WeasyPrint)
  └── DOCX renderer

Validation Worker (single thread, on-demand)
  └── Framework checks + report generation
```

**Rules**
- Live session UI must never block; injection delivery and logging are async.
- Decision log is append-only (never mutated); written from single thread.
- PDF/DOCX export is CPU/IO-bound; run in worker threads with progress signals.
- Runbook validation is fast enough to run on-demand; no background worker needed unless runbook is very large.

---

## 5. Workflow: End-to-End User Journey

### Simulator Workflow

1. **Create Exercise** → organization, date, facilitator, participants, select scenario.
2. **Prepare** → review scenario, customize injects, set phase timers, brief participants (outside tool).
3. **Run Session** → facilitator advances phases; tool displays situation reports; injects delivered per trigger; participants discuss; facilitator captures decisions and rationale.
4. **Capture Findings** → during/after each phase, facilitator records gaps and observations.
5. **Wrap-Up** → review decision log, inject log, findings; prioritize action items; assign owners and deadlines.
6. **Report** → generate exercise report (HTML/PDF); export action items (CSV).
7. **Feed into Runbook** → findings linked to runbook sections; gaps create runbook update tasks.

### Runbook Builder Workflow

1. **Create Runbook** → name, organization, framework (NIST/CISA/custom), template.
2. **Author Sections** → use template sections; edit steps, owners, verification, references.
3. **Build Decision Trees** → for complex decisions (ransom payment, notification).
4. **Configure Escalation** → matrix with contacts and backup contacts.
5. **Write Communication Templates** → for each stakeholder group.
6. **Validate** → run validation engine; fix failures.
7. **Export** → Markdown, HTML, PDF/A, DOCX, JSON.
8. **Review Cycle** → set review reminder (default: 12 months).

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| Sensitive exercise data | Exercise data may contain org-specific gaps; case directories can be encrypted at rest. |
| Runbook confidentiality | Runbooks reveal IR procedures; access controlled; no external transmission. |
| Decision log integrity | Append-only log with hash chain; timestamps; immutable. |
| Participant privacy | Participants recorded by role (not necessarily name); configurable. |
| Export leakage | Redaction profile for external sharing; preview before export. |
| Framework data currency | NIST/CISA mappings versioned; update mechanism. |
| Template injection | Runbook templates are YAML (data, not code); no code execution. |
| Path traversal in exports | Sanitize filenames; reject `..`, `/`, `\`. |

---

## 7. Extensibility Points

1. **New scenario template** — YAML in `scenarios/`; auto-discovered.
2. **New inject** — YAML in `injects/`; reusable across scenarios.
3. **New runbook template** — YAML + Markdown sections in `templates/`.
4. **New framework mapping** — YAML mapping file (e.g., `frameworks/iso27037.yaml`).
5. **New export format** — `Exporter` ABC; MD/HTML/PDF/DOCX/JSON shipped.
6. **Custom validation rule** — Python plugin with access to runbook model.
7. **Custom decision tree node** — plugin for specialized decision logic.

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time (cold) | < 2 s |
| UI responsiveness | < 100 ms for any user action |
| Injection delivery latency | < 1 s |
| Decision log write | < 50 ms |
| Runbook validation | < 2 s for typical runbook |
| PDF export | < 10 s |
| Memory footprint | < 500 MB RSS |
| Concurrent exercises | 1 per instance (single-facilitator design) |
| Runbook size support | Up to 500 sections, 5,000 steps |
| Localization | i18n-ready (Qt Linguist `.ts`) |
| Accessibility | Keyboard-navigable, screen-reader labels |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Rich ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly; mature Model/View |
| YAML | `ruamel.yaml` | Preserves comments/formatting for templates |
| Templating | Jinja2 | Report/export rendering |
| Markdown | `markdown-it-py` | CommonMark + extensions |
| PDF | `WeasyPrint` | HTML→PDF/A |
| DOCX | `python-docx` | Editable export |
| DB | SQLite (WAL) | Embedded, ACID |
| Serialization | JSON Lines | Append-only logs |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller + Briefcase | Cross-platform binaries |
| Testing | pytest + pytest-qt + Hypothesis | Unit, GUI, property-based |
| CI | GitHub Actions | Matrix: Win/Linux/macOS × py3.10–3.12 |

---

## 10. Directory Structure (Source Tree)

```
rts-irb/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── rts_irb/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── exercise_manager.py
│       │   │   ├── scenario_builder.py
│       │   │   ├── live_session.py
│       │   │   ├── decision_capture.py
│       │   │   ├── inject_library.py
│       │   │   ├── runbook_editor.py
│       │   │   ├── runbook_validator.py
│       │   │   ├── framework_mapper.py
│       │   │   ├── gap_analysis.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── decisions_table_model.py
│       │   │   ├── injects_table_model.py
│       │   │   └── gaps_table_model.py
│       │   └── widgets/
│       │       ├── phase_timeline.py
│       │       ├── decision_form.py
│       │       ├── inject_card.py
│       │       ├── runbook_tree.py
│       │       ├── validation_badge.py
│       │       └── gap_indicator.py
│       ├── core/
│       │   ├── session/
│       │   │   ├── engine.py
│       │   │   ├── phase_controller.py
│       │   │   ├── injection_scheduler.py
│       │   │   └── decision_recorder.py
│       │   ├── scenario/
│       │   │   ├── model.py
│       │   │   ├── loader.py
│       │   │   └── templates/
│       │   │       ├── retail_ransomware.yaml
│       │   │       ├── healthcare_ransomware.yaml
│       │   │       ├── municipal_ransomware.yaml
│       │   │       ├── manufacturing_ransomware.yaml
│       │   │       └── generic_enterprise.yaml
│       │   ├── injects/
│       │   │   ├── model.py
│       │   │   ├── loader.py
│       │   │   └── library/
│       │   │       ├── communication.yaml
│       │   │       ├── technical.yaml
│       │   │       ├── legal.yaml
│       │   │       ├── business.yaml
│       │   │       └── ransom_decision.yaml
│       │   ├── runbook/
│       │   │   ├── model.py
│       │   │   ├── loader.py
│       │   │   ├── validator.py
│       │   │   └── templates/
│       │   │       ├── ransomware_cisa.yaml
│       │   │       ├── nist_800_61r3.yaml
│       │   │       └── generic_ir.yaml
│       │   ├── framework/
│       │   │   ├── mapper.py
│       │   │   └── mappings/
│       │   │       ├── nist_csf_2.0.yaml
│       │   │       ├── cisa_stopransomware.yaml
│       │   │       └── internal_best_practices.yaml
│       │   ├── gap/
│       │   │   ├── analyzer.py
│       │   │   └── linker.py
│       │   └── export/
│       │       ├── markdown.py
│       │       ├── html.py
│       │       ├── pdf.py
│       │       ├── docx.py
│       │       └── json.py
│       ├── storage/
│       │   ├── exercise_db.py
│       │   ├── runbook_store.py
│       │   ├── scenario_store.py
│       │   ├── gap_store.py
│       │   └── migrations/
│       ├── security/
│       │   ├── redaction.py
│       │   └── crypto.py
│       └── utils/
│           ├── timeconv.py
│           ├── units.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/
│   │   ├── scenarios/
│   │   ├── injects/
│   │   └── runbooks/
│   └── gui/
├── resources/
│   ├── icons/
│   ├── themes/
│   └── checklists/
│       ├── cisa_ransomware_checklist.yaml
│       └── nist_csf_checklist.yaml
└── docs/
    ├── architecture.md
    ├── scenario_authoring.md
    ├── runbook_authoring.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, exercise manager, scenario model, basic live session view | 2 weeks |
| **P1 — Scenario & Injects** | Scenario loader, inject library, phase controller, injection scheduler | 3 weeks |
| **P2 — Decision Capture** | Decision forms, decision log, participant management | 2 weeks |
| **P3 — Runbook Editor** | Runbook model, section editor, step editor, decision trees | 4 weeks |
| **P4 — Validation Engine** | Framework mappings (NIST/CISA), validation checks, badges | 3 weeks |
| **P5 — Gap Analysis** | Finding capture, runbook linkage, gap report | 2 weeks |
| **P6 — Report Generation** | Exercise report, runbook export (MD/HTML/PDF/DOCX) | 3 weeks |
| **P7 — Built-in Content** | Scenario templates (retail, healthcare, municipal, manufacturing), inject library, runbook templates | 3 weeks |
| **P8 — Framework Mapping** | NIST CSF 2.0 mapper, CISA mapper, coverage heatmap | 2 weeks |
| **P9 — Polish** | Performance, i18n, docs, accessibility, packaging | 3 weeks |

**Total:** ~27 weeks (single senior dev) / ~14 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: scenario phase logic, inject trigger evaluation, decision log append, runbook section resolution, validation checks, gap analysis matching.
- **Integration**: full exercise flow (create → run → capture → report); full runbook flow (create → validate → export).
- **GUI**: `pytest-qt` for live session phase navigation, inject delivery, decision form validation, runbook editor.
- **Property-based**: Hypothesis for phase timing, inject ordering, validation coverage.
- **Content validation**: all built-in scenarios/injects/runbooks parsed and validated on CI.
- **Export validation**: DOCX/PDF structure validated with `python-docx` and `pypdf`.
- **Framework currency**: mappings checked against current NIST/CISA versions on release.

---

## 13. Open Questions / Decisions Pending

1. **Exercise data sensitivity** — exercises reveal organizational gaps. Recommend: encrypted-at-rest option; access controls.
2. **NIST SP 800-61r3 adoption** — r3 is new (April 2025). Recommend: support both r2 and r3 mappings; default to r3 .
3. **CISA StopRansomware currency** — guidance evolves. Recommend: versioned mappings with update mechanism .
4. **Multi-facilitator support** — out of scope v1; single facilitator per instance.
5. **Integration with external GRC tools** — out of scope; export JSON for import.
6. **LLM-assisted scenario generation** — out of scope v1; design scenario model to allow future AI-generated drafts (with human review).
7. **Framework licensing** — NIST/CISA publications are public domain; internal best-practice templates are clean-room.
8. **Runbook "living document" sync** — version control integration (Git) out of scope v1; manual export/import.

---

## 14. Glossary

- **Tabletop Exercise (TTX)** — Discussion-based simulation of an incident scenario to test decision-making and procedures .
- **Runbook** — Step-by-step operational guide for handling a specific incident type .
- **Playbook** — Broader than a runbook; may include strategy, roles, and multi-team coordination.
- **Injection** — Pre-planned information introduced during an exercise to test response .
- **SITREP** — Situation Report; phase-specific briefing in a TTX .
- **Facilitator** — Independent person leading the exercise, not a participant .
- **NIST SP 800-61r3** — Incident Response Recommendations and Considerations for Cybersecurity Risk Management (CSF 2.0 Community Profile) .
- **CISA StopRansomware** — CISA's ransomware guidance and checklist .
- **CSF 2.0** — NIST Cybersecurity Framework version 2.0: Govern, Identify, Protect, Detect, Respond, Recover .
- **Gap Analysis** — Comparing exercise findings against documented procedures to identify missing or ineffective controls.
- **Decision Tree** — Visual representation of a decision process with conditions and outcomes.

---

*End of document.*