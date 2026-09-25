# Architecture: Red Team Engagement Report Generator (Findings → CVSS → Executive Summary) — GUI-Based Solution

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** Structured red team findings capture, CVSS 3.1/4.0 scoring, attack narrative assembly, executive summary generation, and multi-format report export
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Red Team Engagement Report Generator (RTERG)** is a GUI-driven desktop application for red team leads, offensive security consultants, and engagement managers who need to transform raw engagement findings into **client-ready reports** — complete with CVSS-scored vulnerabilities, an attack narrative, an executive summary, and a remediation roadmap. It addresses the persistent gap between the technical work of a red team engagement and the deliverable that clients, executives, and regulators actually read.

Red team reporting is a distinct discipline from vulnerability scanning. A scanner produces a list of CVEs with CVSS scores; a red team report must explain **how an adversary chained multiple findings into a coherent attack path**, what business impact that chain had, and what the client should fix first. The industry-standard structure is well-established: executive summary (non-technical, business risk), methodology, findings (each with CVSS score, evidence, and remediation), attack narrative (chronological story), and appendices . CVSS provides the standardized severity scoring that makes findings comparable and auditable, with CVSS 4.0 now supplementing CVSS 3.1 for new engagements .

The tool is designed around four principles:

1. **Findings-first workflow** — analysts capture findings during the engagement; the report is assembled from structured data, not rewritten from scratch at the end.
2. **CVSS-native scoring** — built-in CVSS 3.1 and 4.0 calculators with vector string parsing and score computation, no external tool required.
3. **Narrative over enumeration** — findings are linked into attack chains; the attack narrative is a first-class artifact, not an afterthought.
4. **Report-ready** — export in DOCX, PDF, HTML, Markdown, and JSON with executive summary, findings, attack narrative, and remediation roadmap.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Engagement│ │ Findings  │ │ CVSS      │ │ Attack    │ │ Executive│ │
│  │ Manager   │ │ Editor    │ │ Calculator│ │ Narrative │ │ Summary │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Evidence  │ │ Remediation│ │ Roadmap   │ │ Report    │ │ Console │ │
│  │ Manager   │ │ Editor    │ │ Builder   │ │ Composer  │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Engagement │ │ Finding    │ │ Narrative  │ │ Event Bus / Log    │ │
│  │ Controller │ │ Aggregator │ │ Assembler  │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Report Engine Layer                              │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ CVSS Engine    │ │ Chain Analyzer │ │ Executive Summary        │  │
│  │ (3.1 + 4.0)    │ │ (attack paths) │ │ Generator                │  │
│  └────────────────┘ └────────────────────┘ └──────────────────────┘  │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Remediation    │ │ Roadmap        │ │ Template Engine          │  │
│  │ Prioritizer    │ │ Builder        │ │ (DOCX/PDF/HTML/MD)       │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Engagement │ │ Finding    │ │ Evidence   │ │ Report Store       │ │
│  │ Store      │ │ Store      │ │ Store      │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `EngagementManagerView` | Create/manage engagement: client name, engagement type (red team, pentest, adversary simulation), scope, timeline, rules of engagement, team members, target environments. |
| `FindingsEditorView` | **Primary authoring view.** Create/edit findings: title, description, affected assets, category, CWE/OWASP mapping, technical details, evidence links, remediation. Rich Markdown editor with live preview. |
| `CvssCalculatorView` | **CVSS scoring view.** Interactive CVSS 3.1 and 4.0 calculators: select metrics (AV, AC, PR, UI, S, C, I, A for 3.1; AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA for 4.0), compute base score, parse/display vector string, preview severity . |
| `AttackNarrativeView` | **Primary narrative view.** Assemble the attack narrative from findings: chronological chain of steps, each linked to a finding; add narrative text, screenshots, and timestamps. Drag-and-drop step reordering. |
| `ExecutiveSummaryView` | Generate and edit the executive summary: business impact, risk rating, key themes, strategic recommendations. AI-assisted draft (optional) with human review. |
| `EvidenceManagerView` | Attach evidence to findings: screenshots, command output, PCAP snippets, files. Auto-hash evidence; embed in report. |
| `RemediationEditorView` | Per-finding remediation: short-term mitigation, long-term fix, references, effort estimate. |
| `RoadmapBuilderView` | Prioritized remediation roadmap: findings grouped by severity, effort, and dependency; timeline (immediate / 30-day / 90-day / strategic). |
| `ReportComposerView` | **Export interface.** Select sections, order, include/exclude findings, choose template (executive brief, full technical, regulatory). Format selection (DOCX, PDF, HTML, Markdown, JSON). |
| `ConsoleView` | Live log: CVSS computation, template rendering, export errors. |

**Key UI Patterns:**
- **Findings-first layout**: the findings editor dominates; CVSS and evidence are side panels.
- **Severity color coding**: Critical (red), High (orange), Medium (yellow), Low (blue), Info (gray) .
- **Chain visualization**: attack narrative shows findings as connected steps; each step clickable to the finding detail.
- **Live CVSS score**: score and severity update instantly as metrics change.
- **Report preview**: rendered report preview beside the composer.

### 3.2 Orchestration Layer

**Engagement Controller**
- Manages engagement lifecycle: setup → findings capture → scoring → narrative → report.
- Tracks engagement metadata and team members.

**Finding Aggregator**
- Collects findings from all sources (manual entry, imported from tools).
- Deduplicates and groups related findings.
- Computes aggregate severity distribution.

**Narrative Assembler**
- Links findings into attack chain steps.
- Generates the chronological narrative structure.
- Provides narrative templates per engagement type.

### 3.3 Report Engine Layer

**CVSS Engine**

Full CVSS 3.1 and 4.0 calculator with vector string parsing.

**CVSS 3.1 base metrics** :
- Attack Vector (AV): Network, Adjacent, Local, Physical
- Attack Complexity (AC): Low, High
- Privileges Required (PR): None, Low, High
- User Interaction (UI): None, Required
- Scope (S): Unchanged, Changed
- Confidentiality (C), Integrity (I), Availability (A): None, Low, High

**CVSS 4.0 base metrics** :
- Attack Vector (AV), Attack Complexity (AC), Attack Requirements (AT), Privileges Required (PR), User Interaction (UI)
- Vulnerable System (VC, VI, VA) and Subsequent System (SC, SI, SA) impact metrics

**Engine capabilities**:
- Parse existing vector strings (from scanner output, CVE databases).
- Compute base score from metric selections.
- Compute temporal and environmental scores (3.1).
- Convert between 3.1 and 4.0 where feasible (documented as approximate).
- Suggest severity rating from score (None/Low/Medium/High/Critical).

**Chain Analyzer**
- Identifies attack chains: sequences of findings that, combined, achieve a higher-impact objective.
- Scores chain severity based on cumulative impact (e.g., initial access + privilege escalation + data exfiltration = Critical).
- Produces a chain diagram for the report.

**Executive Summary Generator**
- Aggregates findings into business-impact themes.
- Computes overall engagement risk rating.
- Generates strategic recommendations.
- Optional LLM-assisted drafting with mandatory human review .

**Remediation Prioritizer**
- Ranks remediation actions by: severity, exploitability, business impact, effort, dependency.
- Groups into roadmap tiers (immediate, 30-day, 90-day, strategic).

**Template Engine**
- Jinja2 templates for report structure.
- DOCX reference for styles (via `python-docx`/`docxtpl`).
- Section-level control: include/exclude, order, custom content.

### 3.4 Storage Layer

**Data directory:**
```
~/.rterg/
├── engagements/
│   └── <engagement_id>/
│       ├── engagement.json       # Engagement metadata
│       ├── findings/
│       │   ├── <finding_id>.json
│       │   └── ...
│       ├── evidence/
│       │   ├── <finding_id>/
│       │   │   ├── screenshot_01.png
│       │   │   └── output.txt
│       ├── narrative/
│       │   └── attack_narrative.md
│       ├── summary/
│       │   └── executive_summary.md
│       └── report/
│           ├── report.docx
│           ├── report.pdf
│           └── report.html
├── templates/
│   ├── executive_brief.yaml
│   ├── full_technical.yaml
│   └── regulatory.yaml
└── logs/
    └── rterg.log
```

**Finding model:**
```python
@dataclass
class Finding:
    finding_id: str
    engagement_id: str
    title: str
    description: str
    affected_assets: list[str]
    category: str                     # 'initial_access', 'privilege_escalation', ...
    cwe_id: str | None
    owasp_ref: str | None
    cvss_version: str                 # '3.1', '4.0'
    cvss_vector: str
    cvss_score: float
    severity: str                     # 'critical', 'high', 'medium', 'low', 'info'
    technical_details: str
    evidence_ids: list[str]
    remediation_short: str
    remediation_long: str
    remediation_effort: str           # 'low', 'medium', 'high'
    references: list[str]
    mitre_technique: str | None
    status: str                       # 'draft', 'reviewed', 'final'
    created_at: datetime
    updated_at: datetime
```

**Attack chain model:**
```python
@dataclass
class AttackChain:
    chain_id: str
    title: str
    steps: list[ChainStep]
    cumulative_severity: str
    objective: str                    # 'domain_admin', 'data_exfiltration', ...

@dataclass
class ChainStep:
    step_order: int
    finding_id: str
    action: str
    timestamp: datetime | None
    notes: str
```

**Engagement model:**
```python
@dataclass
class Engagement:
    engagement_id: str
    client_name: str
    engagement_type: str              # 'red_team', 'pentest', 'adversary_sim'
    scope: list[str]
    timeline_start: datetime
    timeline_end: datetime
    team_members: list[str]
    rules_of_engagement: str
    findings: list[Finding]
    attack_chains: list[AttackChain]
    executive_summary: str
    created_at: datetime
```

### 3.5 Canonical Data Model

See `Finding`, `AttackChain`, and `Engagement` above.

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, findings editor, CVSS calculator
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Export Worker (single thread)
  ├── DOCX rendering (python-docx/docxtpl)
  ├── PDF rendering (WeasyPrint)
  ├── HTML rendering (Jinja2)
  └── JSON export

Analysis Worker (QThreadPool)
  ├── CVSS computation (fast, in-line)
  ├── Chain analysis
  └── Roadmap prioritization
```

**Rules:**
- CVSS computation is instant; runs on main thread.
- Report rendering is CPU/I/O-bound; runs in worker with progress.
- LLM-assisted summary drafting (optional) runs async.
- SQLite/JSON writes serialized.
- Cancellation: `threading.Event` checked between render stages.

---

## 5. Workflow: End-to-End User Journey

1. **Create Engagement** → client, type, scope, timeline, rules of engagement.
2. **Capture Findings** → as engagement progresses, add findings with technical details and evidence.
3. **Score with CVSS** → for each finding, select metrics; compute score; validate vector string .
4. **Attach Evidence** → screenshots, command output, files; auto-hashed.
5. **Build Attack Narrative** → link findings into a chronological attack chain .
6. **Write Remediation** → short-term mitigation and long-term fix per finding.
7. **Build Roadmap** → prioritize remediation into tiers.
8. **Generate Executive Summary** → business impact, risk rating, strategic recommendations.
9. **Compose Report** → select template (executive brief, full technical, regulatory); order sections.
10. **Export Report** → DOCX/PDF/HTML/Markdown/JSON.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Client data sensitivity** | Engagement data may contain client IPs, credentials, evidence; local-only storage; optional encryption at rest. |
| **Evidence leakage** | Evidence may contain PII or credentials; redaction profile for external sharing. |
| **LLM assistance (optional)** | Disabled by default; when enabled, only anonymized summaries sent; client approval required. |
| **Report integrity** | Report hash recorded; optional digital signature. |
| **Access control** | Optional case-level password; audit log of edits. |
| **Legal sensitivity** | Rules of engagement captured; disclaimers included in report. |

---

## 7. Extensibility Points

1. **New finding source** — implement `FindingImporter` ABC (manual, Nessus, Burp, Cobalt Strike, BloodHound).
2. **New CVSS version** — extend `CvssEngine` (future CVSS versions).
3. **New template** — YAML + Jinja2 in `templates/`.
4. **New export format** — `Exporter` ABC (DOCX, PDF, HTML, Markdown, JSON, STIX).
5. **New roadmap strategy** — implement `RoadmapStrategy` ABC (severity-first, effort-first, dependency-aware).
6. **LLM summary provider** — pluggable (OpenAI, local Ollama, Azure OpenAI).

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 2 s |
| Finding creation | < 200 ms |
| CVSS computation | < 50 ms |
| Report rendering (100 findings) | < 30 s |
| PDF export | < 60 s |
| Memory footprint | < 500 MB RSS |
| Finding capacity | Up to 1,000 per engagement |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly |
| CVSS | Custom implementation (3.1 + 4.0 formulas) | No dependency, full control |
| DOCX | `python-docx` + `docxtpl` | Mature, template-driven |
| PDF | `WeasyPrint` (HTML → PDF) | Good typography, PDF/A support |
| HTML/Markdown | `Jinja2` + `markdown` | Standard |
| Screenshots | Qt built-in capture | Native |
| Hashing | `hashlib` (SHA-256) | Evidence integrity |
| DB | SQLite (WAL) + JSON | Embedded, ACID |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
rterg/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── rterg/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── engagement_manager.py
│       │   │   ├── findings_editor.py
│       │   │   ├── cvss_calculator.py
│       │   │   ├── attack_narrative.py
│       │   │   ├── executive_summary.py
│       │   │   ├── evidence_manager.py
│       │   │   ├── remediation_editor.py
│       │   │   ├── roadmap_builder.py
│       │   │   ├── report_composer.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── findings_table_model.py
│       │   │   └── roadmap_table_model.py
│       │   └── widgets/
│       │       ├── severity_badge.py
│       │       ├── cvss_metric_selector.py
│       │       ├── chain_diagram.py
│       │       └── markdown_editor.py
│       ├── core/
│       │   ├── cvss/
│       │   │   ├── cvss31.py
│       │   │   ├── cvss40.py
│       │   │   └── vector_parser.py
│       │   ├── findings/
│       │   │   ├── model.py
│       │   │   ├── importer.py
│       │   │   └── aggregator.py
│       │   ├── narrative/
│       │   │   ├── assembler.py
│       │   │   └── chain_analyzer.py
│       │   ├── summary/
│       │   │   └── generator.py
│       │   ├── remediation/
│       │   │   ├── prioritizer.py
│       │   │   └── roadmap.py
│       │   └── template/
│       │       ├── engine.py
│       │       └── context.py
│       ├── storage/
│       │   ├── engagement_store.py
│       │   ├── finding_store.py
│       │   └── evidence_store.py
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── docx_exporter.py
│       │   │   ├── pdf_exporter.py
│       │   │   ├── html_exporter.py
│       │   │   ├── markdown_exporter.py
│       │   │   └── json_exporter.py
│       │   └── templates/
│       │       ├── executive_brief.yaml
│       │       ├── full_technical.yaml
│       │       └── regulatory.yaml
│       └── utils/
│           ├── hashing.py
│           └── logging.py
├── templates/
│   └── sections/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── gui/
├── resources/
│   ├── icons/
│   └── themes/
└── docs/
    ├── architecture.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, engagement manager, findings editor | 2 weeks |
| **P1 — CVSS 3.1** | CVSS 3.1 calculator, vector parsing, severity mapping  | 2 weeks |
| **P2 — CVSS 4.0** | CVSS 4.0 calculator and metrics  | 2 weeks |
| **P3 — Evidence** | Evidence attachment, hashing, embedding in report | 1 week |
| **P4 — Attack Narrative** | Chain assembly, chain diagram, narrative editor  | 2 weeks |
| **P5 — Remediation & Roadmap** | Remediation editor, prioritization, roadmap tiers  | 2 weeks |
| **P6 — Executive Summary** | Summary generator, optional LLM assistance  | 2 weeks |
| **P7 — Report Templates** | DOCX/PDF/HTML templates, section control | 3 weeks |
| **P8 — Export** | DOCX/PDF/HTML/Markdown/JSON export | 2 weeks |
| **P9 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~21 weeks (single senior dev) / ~11 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: CVSS 3.1 and 4.0 score computation (against official examples), vector parsing, chain scoring.
- **Integration**: full workflow from engagement creation to report export; validate DOCX/PDF structure.
- **GUI**: `pytest-qt` for findings editor, CVSS calculator, narrative editor.
- **Cross-validation**: compare CVSS scores against FIRST's official calculator and `cvss` Python library.
- **Content validation**: reports rendered from fixed inputs match expected structure.

---

## 13. Open Questions / Decisions Pending

1. **CVSS 3.1 vs 4.0 default** — CVSS 4.0 is newer but adoption is still growing; many clients still expect 3.1 . Recommend: 3.1 default; 4.0 available per finding.
2. **LLM-assisted summary** — adds value but raises confidentiality concerns. Recommend: disabled by default; opt-in with client approval; local model preferred.
3. **Attack narrative format** — linear chain vs. graph. Recommend: linear chain for v1; graph visualization in v2.
4. **Regulatory templates** — PCI DSS, HIPAA, GDPR-specific report structures. Recommend: v2 feature; generic templates for v1.
5. **Import from scanners** — Nessus, Burp, Cobalt Strike import. Recommend: v2 feature; manual entry for v1.

---

## 14. Glossary

- **Red Team Engagement** — Authorized adversary simulation against an organization.
- **Finding** — A discovered vulnerability or weakness.
- **CVSS** — Common Vulnerability Scoring System; standardized severity metric .
- **CVSS 3.1** — Current widely-adopted CVSS version.
- **CVSS 4.0** — Newer CVSS version with revised metrics .
- **Vector String** — Compact representation of CVSS metrics (e.g., `CVSS:3.1/AV:N/AC:L/...`).
- **Base Score** — CVSS score derived from intrinsic vulnerability characteristics.
- **Attack Chain** — Sequence of findings combined to achieve an objective.
- **Executive Summary** — Non-technical report section for business stakeholders.
- **Roadmap** — Prioritized remediation plan across time tiers.
- **CWE** — Common Weakness Enumeration.
- **OWASP** — Open Web Application Security Project.

---

*End of document.*