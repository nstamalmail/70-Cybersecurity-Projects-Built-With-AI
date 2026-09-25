# Architecture: Forensic Report Generator — Findings, Evidence Log, Exhibit Index (GUI-Based Solution)

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** Author, assemble, and export court-ready forensic reports with findings, evidence logs, and exhibit indexes
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Forensic Report Generator (FRG)** is a GUI-driven desktop application for digital forensic examiners, incident responders, and expert witnesses who must produce court-admissible reports. It consolidates findings, evidence logs, and exhibit indexes into a single, consistent, verifiable document set — with chain-of-custody intact, hashes verified, and formatting aligned with legal standards (e.g., ISO/IEC 27037, SWGDE, ENFSI, NIST SP 800-86, ACPO Good Practice Guide).

The tool is **not** an analysis engine. It is a **report-authoring and evidence-management workspace** that ingests outputs from other forensic tools (Autopsy, Volatility, ALEAPP, X-Ways, Cellebrite, custom scripts) alongside manually authored findings, then produces:

- **Executive Summary** — non-technical, plain-language findings and conclusions.
- **Technical Findings** — per-finding narrative with methodology, observations, and interpretation.
- **Evidence Log** — every item of evidence with provenance, hash, storage location, and custody events.
- **Exhibit Index** — numbered exhibits (screenshots, files, logs, artifacts) with references, SHA-256, and location.
- **Appendices** — tool versions, methodology, limitations, glossary, references.
- **Chain-of-Custody Report** — full audit trail from seizure to courtroom.

The tool is designed around four principles:

1. **Court-admissibility first** — every claim traceable to evidence; every exhibit hashable; every finding citable.
2. **Reproducibility** — report content generated from a case database; identical inputs → identical outputs.
3. **Multi-format export** — DOCX, PDF/A (archival), HTML, Markdown, JSON, and STIX/MISP (for sharing).
4. **Separation of concerns** — evidence store, findings store, and report templates are independent.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Case Mgmt │ │ Findings  │ │ Evidence  │ │ Exhibit   │ │ Report  │ │
│  │  View     │ │ Editor    │ │ Log       │ │ Index     │ │ Composer│ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Custody   │ │ Ingest    │ │ Verify /  │ │ Preview   │ │ Console │ │
│  │ Timeline  │ │ Wizard    │ │ Hash Panel│ │ Pane      │ │         │ │
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
│                Report & Evidence Processing Layer                    │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Ingest Adapters│ │ Template       │ │ Render Pipeline          │  │
│  │ (Autopsy,      │ │ Engine         │ │ (Jinja2 → DOCX/PDF/HTML) │  │
│  │  Volatility,   │ │ (YAML + Jinja) │ │                          │  │
│  │  ALEAPP, CSV)  │ │                │ │                          │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Evidence Store + Hash Verification + Chain-of-Custody Engine   │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Case DB    │ │ Evidence   │ │ Exhibit    │ │ Template /         │ │
│  │ (SQLite)   │ │ Vault      │ │ Store      │ │ Asset Cache        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     OS / Runtime Abstraction Layer                   │
│  File I/O · Hashing · TZ / locale · Signing (PGP/X.509) · Config     │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `CaseManagerView` | Create/open cases; case metadata (case number, court, jurisdiction, examiner, retaining party); case template selection. |
| `FindingsEditorView` | Author/edit findings: title, severity, category, narrative, methodology, observations, interpretation, references to exhibits/evidence. Rich text (Markdown) with live preview. |
| `EvidenceLogView` | Master evidence table: evidence ID, description, source, hash (MD5/SHA-1/SHA-256), size, acquisition date, storage location, custody status. |
| `ExhibitIndexView` | Master exhibit table: exhibit number, description, type, source finding(s), file path, hash, page/figure reference. |
| `CustodyTimelineView` | Chronological view of every custody event across all evidence: seizure, transfer, analysis, storage, return. |
| `IngestWizardView` | Import findings/evidence from external tools: Autopsy CSV/XML, Volatility JSON, ALEAPP HTML/JSON, Cellebrite UFED, X-Ways, generic CSV/JSON, custom scripts. |
| `VerifyHashPanelView` | Re-hash selected evidence/exhibits; compare to stored hashes; flag mismatches; produce verification report. |
| `ReportComposerView` | Assemble report: select sections, order, include/exclude findings/exhibits, apply template, preview, export. |
| `TemplateManagerView` | Browse/manage report templates (YAML + Jinja2 + DOCX reference); import/export; preview. |
| `PreviewPane` | Live report preview (rendered HTML or DOCX-derived); click to jump to source finding/exhibit. |
| `SignaturePanelView` | Apply digital signature (PGP or X.509) to exported PDF/DOCX; verify existing signatures. |
| `RedactionView` | Configure redaction rules (PII, legal privileged, classified); preview redacted output; audit redaction actions. |
| `ConsoleView` | Live log tail; render warnings; template errors; debug toggle. |

**Key UI Patterns**
- Model/View with `QAbstractTableModel` for evidence/exhibit tables.
- Rich text editing via `QTextEdit` with Markdown source + HTML preview, or a dedicated Markdown editor widget.
- Cross-linking: findings ↔ exhibits ↔ evidence ↔ custody events are hyperlinked; clicking a reference jumps to the target.
- Live preview: as the analyst edits findings, the preview pane re-renders (debounced).
- Templates: WYSIWYG for structure, Markdown/Jinja for content.
- Undo/redo stack for all edits (findings, evidence, exhibits).

### 3.2 Orchestration Layer

**Task Queue**
- Priority queue with worker pool.
- Task = `(task_id, task_type, params, case_id)`.
- Task types: ingest, hash-verify, render, export, sign, redact.
- Persisted to SQLite for crash recovery.

**Pipeline Engine (staged)**
```
[Ingest Adapter] → [Normalizer] → [Evidence Store] → [Dedup + Hash]
       → [Finding/Exhibit Mapper] → [Template Engine] → [Renderer]
       → [Signer] → [Exporter]
```
- Stages connected by bounded queues.
- Each stage independently testable.

**Scheduler**
- Rendering and hashing parallelized.
- Signing serialized (crypto operations).
- Export serialized per output file.

### 3.3 Ingest Adapter Layer

**Supported sources**

| Source | Format | Adapter |
|---|---|---|
| Autopsy | CSV / XML / JSON export | `AutopsyAdapter` |
| Volatility 3 | JSON output | `VolatilityAdapter` |
| ALEAPP | HTML / JSON | `AleappAdapter` |
| Cellebrite UFED | XML / Excel report | `CellebriteAdapter` |
| X-Ways | CSV / XML | `XWaysAdapter` |
| Magnet AXIOM | CSV / XML | `AxiomAdapter` |
| EnCase | CSV / LEF | `EnCaseAdapter` |
| Custom scripts | JSON / CSV (documented schema) | `GenericAdapter` |
| Manual entry | GUI forms | (built-in) |

**Adapter interface**
```python
class IngestAdapter(ABC):
    name: str
    supported_formats: list[str]

    def detect(self, path: Path) -> float:
        """Return confidence 0.0-1.0 that this adapter can parse the file."""

    def ingest(self, path: Path, case_id: str) -> Iterator[IngestRecord]:
        """Yield normalized records (findings, evidence, exhibits)."""
```

**Normalized ingest record**
```python
@dataclass
class IngestRecord:
    record_type: Literal["finding", "evidence", "exhibit"]
    title: str
    description: str
    severity: str | None            # for findings
    category: str | None            # for findings
    source_tool: str                # 'autopsy', 'volatility', ...
    source_ref: str                 # original ID in source tool
    hash_sha256: str | None         # for evidence/exhibits
    file_path: str | None           # for exhibits
    extra: dict                     # original fields
```

**Mapping wizard**
- After ingest, user maps source fields to FRG schema (or accept defaults).
- Mapping saved per source tool for reuse.

### 3.4 Evidence Store Layer

**Evidence item model**
```python
@dataclass
class EvidenceItem:
    evidence_id: str                # e.g., "E-001"
    case_id: str
    description: str
    source: str                     # 'seized from', 'provided by', ...
    acquisition_date: datetime
    acquisition_method: str         # 'physical', 'logical', 'live'
    acquisition_tool: str
    hash_md5: str | None
    hash_sha1: str | None
    hash_sha256: str | None
    size_bytes: int | None
    storage_location: str           # physical or digital location
    storage_handler: str            # who holds it
    custody_status: str             # 'in_custody', 'transferred', 'returned', 'destroyed'
    notes: str | None
    tags: list[str]
```

**Evidence vault**
- Evidence files are **not copied** into the case by default (avoid duplicate storage); only references + hashes stored.
- Optional "sealed copy" mode: copy evidence into case vault with additional hash.
- Evidence file paths stored as absolute or case-relative.

**Hash verification**
- Re-hash on demand; compare to stored.
- Verification report: pass/fail per item, timestamp, verifier.
- Hash algorithm configurable (MD5/SHA-1/SHA-256/SHA-512).

### 3.5 Exhibit Store Layer

**Exhibit model**
```python
@dataclass
class Exhibit:
    exhibit_id: str                 # e.g., "EX-001"
    case_id: str
    description: str
    exhibit_type: str               # 'screenshot', 'file', 'log', 'image', 'database', 'report'
    source_evidence_id: str | None  # link to evidence item
    source_finding_ids: list[str]   # links to findings that cite this exhibit
    file_path: str                  # path to exhibit file in case dir
    hash_sha256: str
    page_ref: str | None            # page/figure reference in report
    notes: str | None
    redacted: bool
```

**Exhibit generation**
- Manual: attach files, screenshots, logs.
- Auto: from analysis tools (e.g., a Volatility `malfind` output → exhibit).
- Screenshot capture: built-in tool to capture screen region with timestamp and case ID watermark (useful for live analysis).

**Exhibit referencing**
- Every finding can cite exhibits by ID (`[EX-001]`).
- Report renderer resolves references to hyperlinks and page numbers.

### 3.6 Findings Editor Layer

**Finding model**
```python
@dataclass
class Finding:
    finding_id: str                 # e.g., "F-001"
    case_id: str
    title: str
    severity: str                   # 'critical', 'high', 'medium', 'low', 'informational'
    category: str                   # 'malware', 'data_exfiltration', 'unauthorized_access', ...
    summary: str                    # 1-2 sentences
    narrative: str                  # full Markdown narrative
    methodology: str                # tools, commands, procedures used
    observations: str               # factual observations
    interpretation: str             # analyst's interpretation / opinion
    limitations: str | None         # caveats
    evidence_ids: list[str]         # linked evidence
    exhibit_ids: list[str]          # linked exhibits
    references: list[str]           # external references, standards
    tags: list[str]
    author: str
    created_at: datetime
    modified_at: datetime
    status: str                     # 'draft', 'peer_reviewed', 'final'
```

**Finding categories** (default taxonomy, configurable)
- Unauthorized access
- Data exfiltration
- Malware / persistence
- Credential compromise
- Lateral movement
- Timeline reconstruction
- Data recovery
- System configuration
- Chain-of-custody issues
- Other

**Peer review workflow**
- Findings have status: draft → peer_reviewed → final.
- Reviewer can add comments (stored separately).
- Report export warns if any finding is not `final`.

### 3.7 Chain-of-Custody Layer

**Custody event model**
```python
@dataclass
class CustodyEvent:
    event_id: str
    case_id: str
    evidence_id: str | None         # null for case-level events
    ts: datetime
    actor: str                      # who performed the action
    action: str                     # 'seized', 'transferred', 'analyzed', 'stored', ...
    from_party: str | None
    to_party: str | None
    location: str | None
    detail: str | None
    prev_hash: str | None           # previous entry hash
    entry_hash: str                 # HMAC of this entry
```

**Append-only log**
- Hash-chained: each entry includes HMAC of previous entry.
- Tamper-evident: verification recomputes chain.
- Exportable as PDF/CSV for court.

**Custody report generation**
- Per-evidence timeline: seizure → transfer → analysis → storage → return.
- Case-level timeline: all events.
- Includes actor signatures (if digital signature available).

### 3.8 Template & Rendering Layer

**Template model**
- A report template is a directory with:
  - `template.yaml` — metadata, section order, conditional inclusion.
  - `reference.docx` — DOCX reference for styles (fonts, headings, numbering).
  - `sections/*.jinja2` — per-section Jinja2 templates.
  - `assets/` — logos, headers, footers.
  - `styles.css` — for HTML/PDF output.

**Built-in templates**
- **Court Report (Default)** — full formal report with all sections.
- **Executive Brief** — non-technical summary only.
- **Incident Response Report** — findings + timeline + IOCs.
- **Civil Litigation Report** — evidence + exhibits + custody.
- **Law Enforcement Report** — chain-of-custody emphasis.
- **Internal Investigation Report** — flexible structure.

**Rendering pipeline**
```
[Template] + [Case DB] → [Jinja2 Context Builder] → [Renderer]
    → [DOCX (python-docx) | PDF/A (WeasyPrint) | HTML | Markdown | JSON]
```

**Cross-references**
- Exhibit references (`[EX-001]`) resolved to numbered references with page links.
- Finding references resolved to section numbers.
- Evidence references resolved to evidence log rows.
- Automatic table of contents.
- Automatic list of figures/tables.
- Automatic exhibit index.

**Numbering**
- Findings: `F-001`, `F-002`, ...
- Evidence: `E-001`, `E-002`, ...
- Exhibits: `EX-001`, `EX-002`, ...
- Sections: hierarchical (1, 1.1, 1.1.1).
- Configurable schemes per template.

### 3.9 Export Layer

**Export formats**

| Format | Use case | Library |
|---|---|---|
| **DOCX** | Editable court submission | `python-docx` |
| **PDF/A** | Archival, immutable | `WeasyPrint` (HTML→PDF) |
| **HTML** | Web viewing, email | Jinja2 |
| **Markdown** | Source control, lightweight | Jinja2 |
| **JSON** | Machine-readable, STIX/MISP | Custom |
| **CSV** | Exhibit index, evidence log | stdlib `csv` |
| **STIX 2.1** | Threat intel sharing | `stix2` |
| **MISP** | Threat intel sharing | `pymisp` |

**PDF/A compliance**
- Use `WeasyPrint` with PDF/A output profile.
- Embed all fonts; no external references.
- Validate with `verapdf` (optional).

**Digital signature**
- PGP: sign exported PDF/DOCX with examiner's PGP key.
- X.509: sign PDF with X.509 certificate (via `pyhanko`).
- Timestamping: optional RFC 3161 timestamp.

### 3.10 Redaction Layer

**Redaction rules**
- PII: names, emails, phone numbers, addresses, SSNs, credit cards.
- Legal privileged: attorney-client communications.
- Classified: user-defined patterns.
- Per-finding, per-exhibit, per-export-profile.

**Redaction application**
- Text: regex-based replacement with `[REDACTED]` or black-box.
- Images: black-box regions (manual annotation).
- PDF: true redaction (remove underlying text, not just overlay).

**Audit**
- Every redaction logged: who, what, when, rule applied.
- Redacted and unredacted versions both stored (access-controlled).

### 3.11 Storage Layer

**Case Directory Layout**
```
cases/<case_id>/
├── case.db                      # SQLite: cases, findings, evidence, exhibits, custody
├── manifest.json                # Case metadata
├── source_ref.txt               # Paths + hashes of source material
├── evidence/
│   ├── refs.json                # Evidence references (paths, hashes)
│   └── sealed/                  # Optional sealed copies
├── exhibits/
│   ├── EX-001_screenshot.png
│   ├── EX-002_malfind_output.txt
│   └── ...
├── findings/
│   └── (stored in DB; Markdown snapshots optional)
├── custody/
│   └── custody.jsonl            # Append-only custody log
├── templates/
│   └── (case-specific templates if any)
├── reports/
│   ├── report.docx
│   ├── report.pdf
│   ├── report.html
│   ├── report.md
│   ├── report.json
│   ├── exhibit_index.csv
│   ├── evidence_log.csv
│   ├── custody_report.pdf
│   └── manifest.csv             # SHA-256 of all exports
├── redaction/
│   ├── profiles/
│   └── audit.jsonl
└── logs/
    └── session.log
```

**SQLite Schema (abridged)**
```sql
CREATE TABLE cases (
  id TEXT PRIMARY KEY, name TEXT, case_number TEXT,
  court TEXT, jurisdiction TEXT, examiner TEXT,
  retaining_party TEXT, created_at TIMESTAMP
);
CREATE TABLE findings (
  id TEXT PRIMARY KEY, case_id TEXT,
  title TEXT, severity TEXT, category TEXT,
  summary TEXT, narrative TEXT, methodology TEXT,
  observations TEXT, interpretation TEXT, limitations TEXT,
  evidence_ids_json TEXT, exhibit_ids_json TEXT,
  references_json TEXT, tags_json TEXT,
  author TEXT, status TEXT,
  created_at TIMESTAMP, modified_at TIMESTAMP,
  FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE TABLE evidence (
  id TEXT PRIMARY KEY, case_id TEXT,
  description TEXT, source TEXT,
  acquisition_date TIMESTAMP, acquisition_method TEXT, acquisition_tool TEXT,
  hash_md5 TEXT, hash_sha1 TEXT, hash_sha256 TEXT,
  size_bytes INTEGER, storage_location TEXT, storage_handler TEXT,
  custody_status TEXT, notes TEXT, tags_json TEXT,
  FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE TABLE exhibits (
  id TEXT PRIMARY KEY, case_id TEXT,
  description TEXT, exhibit_type TEXT,
  source_evidence_id TEXT, source_finding_ids_json TEXT,
  file_path TEXT, hash_sha256 TEXT,
  page_ref TEXT, notes TEXT, redacted INTEGER DEFAULT 0,
  FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE TABLE custody_events (
  id TEXT PRIMARY KEY, case_id TEXT, evidence_id TEXT,
  ts TIMESTAMP, actor TEXT, action TEXT,
  from_party TEXT, to_party TEXT, location TEXT,
  detail TEXT, prev_hash TEXT, entry_hash TEXT,
  FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE TABLE report_exports (
  id TEXT PRIMARY KEY, case_id TEXT,
  format TEXT, template TEXT,
  output_path TEXT, hash_sha256 TEXT,
  exported_at TIMESTAMP, signed INTEGER DEFAULT 0,
  FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE VIRTUAL TABLE findings_fts USING fts5(
  title, summary, narrative, tags_json,
  content='findings', content_rowid='id'
);
```

### 3.12 Canonical Data Model

See `Finding` (§3.6), `EvidenceItem` (§3.4), `Exhibit` (§3.5), `CustodyEvent` (§3.7).

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, model updates, rich text editing
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Task Pool (QThreadPool, N workers)
  ├── Ingest threads         (parallel per source file)
  ├── Hash threads           (parallel per evidence/exhibit)
  ├── Render threads         (parallel per output format)
  ├── Sign threads           (serial; crypto)
  └── Export writer          (serial per output file)
```

**Rules**
- Rich text editing on main thread only.
- Live preview rendering debounced (300 ms) and off-thread (HTML render).
- SQLite in WAL mode; single writer.
- Cancellation: cooperative `threading.Event` for long render/export tasks.
- Memory bounds: large evidence/exhibit previews loaded on demand.

---

## 5. Workflow: End-to-End User Journey

1. **Create Case** → case number, court, jurisdiction, examiner, retaining party, template.
2. **Ingest Findings/Evidence** → import from Autopsy, Volatility, ALEAPP, Cellebrite, etc., or enter manually.
3. **Register Evidence** → for each evidence item: description, source, acquisition method, hash, storage location.
4. **Verify Hashes** → re-hash evidence/exhibits; produce verification report.
5. **Author Findings** → narrative, methodology, observations, interpretation; link to evidence and exhibits.
6. **Create Exhibits** → attach screenshots, logs, files; number sequentially; link to findings.
7. **Record Custody** → log seizure, transfers, analysis, storage.
8. **Peer Review** → reviewer comments; findings move to `final`.
9. **Compose Report** → select template; order sections; include/exclude findings/exhibits.
10. **Preview** → live preview; click cross-references to jump.
11. **Redact** (if needed) → apply profile; audit.
12. **Export** → DOCX, PDF/A, HTML, Markdown, JSON, CSV; sign; timestamp.
13. **Archive** → zip case dir; sign with case HMAC; record export hashes.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| Evidence tampering | SHA-256 of every evidence/exhibit; HMAC-signed manifest; append-only custody log with hash chain. |
| Unauthorized case access | Optional case encryption at rest; access logged. |
| Sensitive data leakage in exports | Redaction profiles; preview redacted output; audit trail. |
| Digital signature key compromise | Support HSM/OS keystore; require passphrase per session; never store keys unencrypted. |
| Malicious ingest files (parser exploit) | Adapters run in subprocess with resource limits; fuzz-tested; no `eval`. |
| Path traversal from exhibit filenames | Sanitize filenames; reject `..`, `/`, `\`, NUL; reserved-name mangling. |
| Template injection (Jinja2) | Sandboxed Jinja2 environment; no arbitrary Python; whitelist filters. |
| Report forgery | Digital signature (PGP/X.509) on exports; RFC 3161 timestamp optional. |
| Chain-of-custody disputes | Hash-chained custody log; exportable verification report. |
| Legal privilege exposure | Redaction of privileged content; separate access controls. |

---

## 7. Extensibility Points

1. **New ingest adapter** — implement `IngestAdapter` ABC; register in `adapters/registry.py`.
2. **New template** — YAML + Jinja2 + reference DOCX; drop in `templates/`.
3. **New exporter** — `Exporter` ABC; DOCX/PDF/HTML/MD/JSON/CSV/STIX/MISP shipped.
4. **New redaction rule** — YAML profile.
5. **New signature backend** — implement `Signer` ABC (PGP, X.509, HSM).
6. **Custom numbering scheme** — plugin for `NumberingScheme`.
7. **Custom finding taxonomy** — YAML config.

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time (cold) | < 2 s |
| UI responsiveness | < 100 ms for any user action |
| Live preview render | < 500 ms (debounced) |
| Full report render (100 findings, 500 exhibits) | < 30 s |
| PDF/A export | < 60 s |
| Hash computation | ≥ 500 MB/s |
| Memory footprint | < 1 GB RSS |
| Case size support | Up to 10,000 findings, 100,000 evidence items, 500,000 exhibits |
| Report length support | Up to 5,000 pages |
| Crash recovery | Resume from last committed edit within 5 s |
| Localization | i18n-ready (Qt Linguist `.ts`) |
| Accessibility | Keyboard-navigable, screen-reader labels |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Rich ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly; mature Model/View |
| Markdown | `markdown-it-py` + `mdit-py-plugins` | CommonMark + extensions |
| Templating | Jinja2 (sandboxed) | Standard, safe |
| DOCX | `python-docx` + `docxtpl` | Mature |
| PDF | `WeasyPrint` (HTML→PDF/A) | Good typography; PDF/A support |
| PDF signing | `pyhanko` | X.509 signing |
| PGP | `python-gnupg` | GPG integration |
| Timestamp | `rfc3161ng` | RFC 3161 timestamps |
| STIX | `stix2` | Threat intel sharing |
| MISP | `pymisp` | Threat intel sharing |
| DB | SQLite (WAL + FTS5) | Embedded, ACID, FTS |
| Serialization | JSON Lines + MessagePack | Streaming + compact |
| Hashing | `hashlib` (SHA-256), `blake3` (fast dedup) | Speed + standard |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller + Briefcase | Cross-platform binaries |
| Testing | pytest + pytest-qt + Hypothesis | Unit, GUI, property-based |
| CI | GitHub Actions | Matrix: Win/Linux/macOS × py3.10–3.12 |

---

## 10. Directory Structure (Source Tree)

```
frg/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── frg/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── case_manager.py
│       │   │   ├── findings_editor.py
│       │   │   ├── evidence_log.py
│       │   │   ├── exhibit_index.py
│       │   │   ├── custody_timeline.py
│       │   │   ├── ingest_wizard.py
│       │   │   ├── verify_hash.py
│       │   │   ├── report_composer.py
│       │   │   ├── template_manager.py
│       │   │   ├── signature_panel.py
│       │   │   ├── redaction_view.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── findings_table_model.py
│       │   │   ├── evidence_table_model.py
│       │   │   ├── exhibits_table_model.py
│       │   │   └── custody_table_model.py
│       │   └── widgets/
│       │       ├── markdown_editor.py
│       │       ├── preview_pane.py
│       │       ├── cross_link.py
│       │       ├── screenshot_capture.py
│       │       └── filter_bar.py
│       ├── core/
│       │   ├── ingest/
│       │   │   ├── base.py
│       │   │   ├── registry.py
│       │   │   ├── autopsy.py
│       │   │   ├── volatility.py
│       │   │   ├── aleapp.py
│       │   │   ├── cellebrite.py
│       │   │   ├── xways.py
│       │   │   ├── axiom.py
│       │   │   ├── encase.py
│       │   │   └── generic.py
│       │   ├── findings/
│       │   │   ├── model.py
│       │   │   ├── taxonomy.py
│       │   │   └── review.py
│       │   ├── evidence/
│       │   │   ├── model.py
│       │   │   ├── vault.py
│       │   │   └── verify.py
│       │   ├── exhibits/
│       │   │   ├── model.py
│       │   │   ├── numbering.py
│       │   │   └── capture.py
│       │   ├── custody/
│       │   │   ├── model.py
│       │   │   ├── log.py
│       │   │   └── verify.py
│       │   ├── template/
│       │   │   ├── loader.py
│       │   │   ├── context.py
│       │   │   └── numbering.py
│       │   ├── render/
│       │   │   ├── docx_renderer.py
│       │   │   ├── pdf_renderer.py
│       │   │   ├── html_renderer.py
│       │   │   ├── markdown_renderer.py
│       │   │   ├── json_renderer.py
│       │   │   └── csv_renderer.py
│       │   ├── export/
│       │   │   ├── base.py
│       │   │   ├── registry.py
│       │   │   ├── stix_exporter.py
│       │   │   └── misp_exporter.py
│       │   ├── sign/
│       │   │   ├── base.py
│       │   │   ├── pgp_signer.py
│       │   │   ├── x509_signer.py
│       │   │   └── timestamp.py
│       │   ├── redact/
│       │   │   ├── rules.py
│       │   │   ├── apply.py
│       │   │   └── audit.py
│       │   └── pipeline/
│       │       ├── stages.py
│       │       ├── queue.py
│       │       └── scheduler.py
│       ├── storage/
│       │   ├── case_db.py
│       │   ├── findings_store.py
│       │   ├── evidence_store.py
│       │   ├── exhibit_store.py
│       │   ├── custody_store.py
│       │   ├── fts_index.py
│       │   └── migrations/
│       ├── templates/
│       │   ├── court_report/
│       │   ├── executive_brief/
│       │   ├── incident_response/
│       │   ├── civil_litigation/
│       │   ├── law_enforcement/
│       │   └── internal_investigation/
│       ├── security/
│       │   ├── filename_sanitizer.py
│       │   ├── sandbox.py
│       │   ├── custody.py
│       │   └── signature.py
│       └── utils/
│           ├── hashing.py
│           ├── timeconv.py
│           ├── units.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/
│   │   ├── ingest_samples/
│   │   ├── findings_samples/
│   │   └── template_samples/
│   └── gui/
├── resources/
│   ├── icons/
│   ├── redaction_profiles/
│   │   ├── default.yaml
│   │   ├── pii_strict.yaml
│   │   └── legal_privilege.yaml
│   ├── styles/
│   └── themes/
└── docs/
    ├── architecture.md
    ├── template_authoring.md
    ├── legal_notes.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, case mgmt, findings editor (Markdown), evidence log, basic DOCX export | 3 weeks |
| **P1 — Evidence & Exhibits** | Evidence store, exhibit store, hash verification, cross-linking | 3 weeks |
| **P2 — Chain of Custody** | Custody log, hash-chained entries, custody report | 2 weeks |
| **P3 — Templates** | Template loader, Jinja2 context builder, DOCX/HTML renderers, built-in templates | 4 weeks |
| **P4 — PDF & PDF/A** | WeasyPrint integration, PDF/A output, validation | 2 weeks |
| **P5 — Ingest Adapters** | Autopsy, Volatility, ALEAPP, Cellebrite, generic CSV/JSON | 4 weeks |
| **P6 — Report Composer** | Section ordering, include/exclude, live preview, TOC, lists of figures/tables | 3 weeks |
| **P7 — Signing & Timestamp** | PGP, X.509, RFC 3161 | 2 weeks |
| **P8 — Redaction** | Rules, application, audit, image redaction | 3 weeks |
| **P9 — STIX/MISP** | Threat intel export | 2 weeks |
| **P10 — Peer Review** | Review workflow, comments, status transitions | 2 weeks |
| **P11 — Hardening** | Parser fuzzing, template sandboxing, packaging | 3 weeks |
| **P12 — Polish** | Performance, i18n, docs, accessibility | 3 weeks |

**Total:** ~36 weeks (single senior dev) / ~18 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: hash verification, custody hash chain, template context builder, numbering scheme, cross-reference resolution, redaction rules.
- **Integration**: full workflow from ingest → findings → exhibits → report → export; validate DOCX/PDF structure with `python-docx` and `pypdf`.
- **GUI**: `pytest-qt` for editor flows, live preview, cross-link navigation, template manager.
- **Property-based**: Hypothesis for numbering, cross-reference resolution, hash chain integrity.
- **Performance**: benchmark on 1,000 findings, 10,000 evidence items, 50,000 exhibits; regression CI if render time increases > 20%.
- **Security**: fuzz ingest adapters (malicious CSV/XML/JSON) with Atheris; template injection tests; path traversal tests.
- **Legal correctness**: golden-report tests — fixed inputs → expected DOCX/PDF; validate with `docx` and `pdf` diff tools.
- **Cross-validation**: compare exhibit index and evidence log against source tools.

---

## 13. Open Questions / Decisions Pending

1. **PDF/A vs PDF** — PDF/A is archival; PDF is more flexible. Recommend: both, with PDF/A default for court.
2. **DOCX vs ODT** — DOCX is dominant in legal; ODT is open. Recommend: DOCX primary; ODT optional.
3. **Jinja2 sandboxing** — use `jinja2.sandbox.SandboxedEnvironment`; disable dangerous filters.
4. **Redaction of images** — manual annotation v1; ML-assisted v2 (with audit).
5. **Digital signature default** — PGP or X.509? Recommend: both; PGP for internal, X.509 for court.
6. **Timestamp authority** — RFC 3161 requires TSA URL; make configurable; optional.
7. **Multi-examiner collaboration** — out of scope v1; design DB schema to allow future merge.
8. **Cloud export** — out of scope; local export only.
9. **Template licensing** — ensure built-in templates are clean-room and not copied from proprietary sources.
10. **Accessibility of redacted content** — redacted PDFs must remove underlying text, not just overlay; test with text extraction.

---

## 14. Glossary

- **ACPO** — Association of Chief Police Officers (UK); Good Practice Guide for Digital Evidence.
- **Chain of custody** — audit trail proving evidence integrity from seizure to court.
- **Exhibit** — a numbered item presented as evidence in court.
- **Finding** — a conclusion drawn by the examiner from analysis.
- **ISO/IEC 27037** — international standard for digital evidence handling.
- **NIST SP 800-86** — Guide to Integrating Forensic Techniques into Incident Response.
- **PDF/A** — ISO-standardized PDF for long-term archival.
- **PGP** — Pretty Good Privacy; encryption and signing.
- **RFC 3161** — Time-Stamp Protocol.
- **STIX** — Structured Threat Information Expression.
- **SWGDE** — Scientific Working Group on Digital Evidence.
- **X.509** — Public key certificate standard.
- **PDF/A** — Archival PDF profile.
- **FTS5** — SQLite full-text search extension.

---

*End of document.*