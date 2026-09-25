# Architecture: Log Anonymizer/Redactor for Safe Log Sharing (GUI-Based Solution)

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** Local, deterministic log redaction with configurable PII/secret detection, tokenization-based anonymization, and multi-format report export
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Log Anonymizer & Redactor (LAR)** is a GUI-driven desktop application for developers, support engineers, and security analysts who need to **safely share log files** without exposing credentials, personally identifiable information (PII), or internal infrastructure details. It addresses the operational reality that logs are routinely shared in bug reports, support tickets, and incident channels — and that automated redaction reduces accidental disclosure but cannot be trusted blindly .

The tool consolidates proven redaction techniques: **regex-driven detection** of common PII and secrets, **deterministic tokenization** that preserves log structure and enables correlation across redacted files without revealing originals, and **configurable policy profiles** aligned to GDPR, HIPAA, and PCI DSS requirements . It deliberately **runs locally with no network calls**, because the entire purpose is to prevent sensitive data from leaving the user's machine .

The tool is designed around four principles:

1. **Local-only by default** — no network requests, no telemetry, no API calls; redaction happens entirely on the user's machine .
2. **Deterministic, not random** — the same input with the same salt always produces the same redacted token, preserving correlation across files for troubleshooting .
3. **Configurable, not opaque** — every pattern, profile, and replacement strategy is visible and editable; users can add custom detectors for their environment.
4. **Report-ready** — export redaction summaries in JSON, CSV, HTML, and PDF formats documenting what was redacted (counts and types, not values) for audit trails.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Input     │ │ Redaction │ │ Preview   │ │ Detector  │ │ Report  │ │
│  │ Selector  │ │ Progress  │ │ / Diff    │ │ Config    │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Profile   │ │ Summary   │ │ Salt      │ │ Policy    │ │ Console │ │
│  │ Selector  │ │ Stats     │ │ Manager   │ │ Profiles  │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Redaction  │ │ Detector   │ │ Tokenizer  │ │ Event Bus / Log    │ │
│  │ Controller │ │ Registry   │ │ Engine     │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Redaction Core Layer                             │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Regex Detector │ │ Pattern        │ │ Replacement              │  │
│  │ (PII, secrets) │ │ Validators     │ │ Strategies               │  │
│  │                │ │                │ │ (tokenize, mask, redact) │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Presidio Integration (optional) + Custom Detector Plugins      │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Policy     │ │ Salt Store │ │ Redaction  │ │ Report Store       │ │
│  │ Profiles   │ │ (encrypted)│ │ History    │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `InputSelectorView` | Select input: single file, directory (recursive), or stdin pipe. Auto-detect log format (plaintext, JSON, JSONL, Syslog RFC 5424, Nginx/Apache access logs) . Display file size and line count. |
| `ProfileSelectorView` | Choose redaction profile: **GDPR (EU)**, **HIPAA (US)**, **PCI DSS**, **Basic**, **Strict**, or **Custom** . Profile determines which detectors are active. |
| `DetectorConfigView` | **Primary configuration view.** Enable/disable individual detectors: email, IP, UUID, API keys, Bearer tokens, AWS keys, private key headers, password assignments, SSN, credit card, phone, hostname, custom patterns . |
| `SaltManagerView` | Generate, load, or save redaction salt. Salt enables deterministic tokenization — same input + same salt = same output token, enabling correlation across redacted files . Salt is encrypted at rest. |
| `RedactionProgressView` | Live progress: lines processed, detections found, detections by type. Cancel button for large files. |
| `PreviewDiffView` | **Critical safety view.** Side-by-side original vs. redacted preview (first N lines). Highlight redactions. Critical because automated redaction cannot guarantee complete coverage — users must review before sharing . |
| `SummaryStatsView` | Post-redaction summary: total detections, by type, by file, redaction ratio. No original values shown — only counts. |
| `ReportBuilderView` | **Export interface.** Format selection (JSON, CSV, HTML, PDF), sections to include (summary, per-file stats, detector breakdown), redaction of the report itself (recommended). |
| `ConsoleView` | Live log: detector matches, regex warnings, file I/O errors, malformed line handling (JSONL fallback) . |

**Key UI Patterns:**
- **Preview-before-write**: redacted output is written to a separate directory; original files are never overwritten by default .
- **Color-coded detections**: Email (blue), IP (green), Secret (red), PII (orange).
- **Safety banner**: persistent reminder that "automated redaction reduces exposure but cannot guarantee complete coverage."
- **Review gate**: before export, user must acknowledge preview review.
- **Stream-friendly processing**: line-by-line processing means memory footprint does not grow with file size .

### 3.2 Orchestration Layer

**Redaction Controller**
- Manages redaction lifecycle: input → detection → replacement → output → report.
- Enforces preview-before-write workflow.
- Tracks progress and handles cancellation.

**Detector Registry**
- Holds all active detectors (built-in + custom).
- Applies detectors in priority order (specific patterns before generic ones to avoid mis-detection).
- Supports per-profile detector selection.

**Tokenizer Engine**
- Implements deterministic tokenization: `HMAC-SHA256(salt, original_value)` → truncated → formatted token .
- Ensures same input always produces same token with same salt.
- Tokens preserve type indication (e.g., `<EMAIL_1>`, `<IP_2>`).
- Supports multiple replacement strategies: tokenize (reversible correlation), mask (asterisks), redact (remove), label (type name only) .

### 3.3 Redaction Core Layer

**Regex Detector**

Built-in detection patterns:

| Category | Pattern | Example Match |
|---|---|---|
| **Email** | RFC 5322-compliant | `user@example.com` |
| **IPv4** | `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b` | `192.168.1.100` |
| **IPv6** | Standard IPv6 regex | `2001:db8::1` |
| **UUID** | `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-...` | `550e8400-e29b-41d4-a716-446655440000` |
| **Bearer Token** | `Bearer\s+[A-Za-z0-9\-._~+/]+=*` | `Bearer eyJhbGci...` |
| **GitHub Token** | `gh[pousr]_[A-Za-z0-9]{36,}` | `ghp_xxxxxxxxxxxx` |
| **OpenAI Key** | `sk-[A-Za-z0-9]{20,}` | `sk-xxxxxxxx` |
| **AWS Access Key** | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` |
| **Private Key Header** | `-----BEGIN (RSA |EC|OPENSSH )?PRIVATE KEY-----` | PEM headers |
| **Password Assignment** | `(password |passwd|pwd|secret|token|api_key)\s*[=:]\s*\S+` | `password=secret123` |
| **SSN (US)** | `\d{3}-\d{2}-\d{4}` | `123-45-6789`  |
| **Credit Card** | Luhn-validated PAN patterns | `4111-1111-1111-1111`  |
| **Hostname in URL** | `https?://[^/\s]+` | `https://internal.corp.local`  |

**Presidio Integration (Optional)**

For NLP-based PII detection beyond regex (names, addresses, organizations), integrate Microsoft Presidio :
- Presidio `AnalyzerEngine` detects entities.
- Presidio `AnonymizerEngine` applies replacement operators.
- Optional: Faker-based replacement for realistic anonymization .

**Replacement Strategies**

| Strategy | Behavior | Use Case |
|---|---|---|
| **Tokenize** | `HMAC(salt, value)` → `<TYPE_N>` | Correlation across files  |
| **Mask** | Replace characters with `*` (preserve length) | Visual indication of length |
| **Redact** | Remove entirely | Minimal output |
| **Label** | Replace with `<TYPE>` | Type indication only  |
| **Faker** | Replace with fake realistic value | Testing/demo data  |

**Custom Detector Plugins**

Users can add custom regex patterns for environment-specific sensitive data (e.g., internal project codes, custom token formats) .

### 3.4 Storage Layer

**Data directory:**
```
~/.lar/
├── profiles/
│   └── *.yaml                 # Policy profiles (GDPR, HIPAA, custom)
├── salts/
│   └── <salt_id>.enc          # Encrypted salt store
├── history/
│   └── redaction_log.jsonl    # Redaction history (counts only, no values)
├── reports/
│   └── <report_id>.pdf
└── logs/
    └── lar.log
```

**Policy Profile Model:**
```python
@dataclass
class RedactionProfile:
    profile_id: str
    name: str                    # 'GDPR EU', 'HIPAA US', 'PCI DSS', 'Strict'
    enabled_detectors: list[str] # detector IDs
    replacement_strategy: str    # 'tokenize', 'mask', 'redact', 'label'
    salt_required: bool
    custom_patterns: list[CustomPattern]
    compliance_refs: list[str]   # ['GDPR Art. 32', 'HIPAA §164.312']
```

**Redaction Summary Model:**
```python
@dataclass
class RedactionSummary:
    summary_id: str
    timestamp: datetime
    input_files: list[str]
    profile_used: str
    total_lines: int
    total_detections: int
    detections_by_type: dict[str, int]  # {'email': 12, 'ipv4': 45, ...}
    files_processed: int
    output_directory: str
    salt_id: str | None
```

### 3.5 Canonical Data Model

See `RedactionProfile` and `RedactionSummary` above.

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, preview rendering, progress updates
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Redaction Worker (single thread)
  ├── Stream input line-by-line
  ├── Apply detectors
  ├── Apply replacement strategy
  ├── Write to output file
  └── Emit progress/detections

Report Worker (single thread)
  └── Generate HTML/PDF/JSON/CSV report
```

**Rules:**
- Redaction is streaming: line-by-line, memory-bounded .
- Preview generation uses a limited sample (first 100 lines) for responsiveness.
- Cancellation: `threading.Event` checked between lines.
- Output written to separate directory; originals never modified by default .

---

## 5. Workflow: End-to-End User Journey

1. **Select Input** → choose file(s), directory (recursive), or stdin pipe.
2. **Choose Profile** → select GDPR, HIPAA, PCI DSS, Basic, Strict, or Custom .
3. **Configure Detectors** → enable/disable specific detectors; add custom patterns .
4. **Manage Salt** (optional) → generate/load salt for deterministic tokenization .
5. **Preview** → view first N lines with redactions highlighted; **review required** before proceeding.
6. **Run Redaction** → stream-process input, write redacted output to separate directory.
7. **Review Summary** → detection counts by type, redaction ratio, files processed.
8. **Export Report** → JSON/CSV/HTML/PDF redaction summary (counts only, no values).
9. **Share Safely** → redacted logs + summary report ready for sharing.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Network leakage** | No network calls by default; local-only processing . |
| **Salt compromise** | Salt encrypted at rest; deterministic tokens become reversible if salt leaks — document risk . |
| **Incomplete redaction** | Preview-before-write enforced; safety banner warns that automated redaction cannot guarantee complete coverage . |
| **Original file retention** | Originals never overwritten by default; user must explicitly enable `--delete-original` . |
| **Redaction report leakage** | Reports contain counts only, never original values; report itself can be redacted. |
| **Malicious regex (ReDoS)** | Custom patterns validated for catastrophic backtracking; timeouts on regex execution. |
| **Unicode/homoglyph evasion** | Normalization before matching where applicable; documented limitation. |
| **Deterministic token correlation** | Tokens enable correlation across files — this is a feature, not a bug; document that same salt should not be shared publicly. |

---

## 7. Extensibility Points

1. **New detector** — YAML pattern in `detectors/` or Python plugin .
2. **New profile** — YAML profile in `profiles/` selecting detectors and strategy.
3. **New replacement strategy** — implement `ReplacementStrategy` ABC (tokenize, mask, redact, label, faker).
4. **Presidio integration** — optional NLP-based PII detection .
5. **New export format** — `Exporter` ABC (JSON, CSV, HTML, PDF, SARIF).
6. **CI/CD integration** — CLI mode for pipeline redaction.

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 2 s |
| Redaction throughput | > 10 MB/s (regex) |
| Memory footprint | < 200 MB RSS (streaming) |
| File size support | Up to 10 GB (streaming) |
| Preview latency | < 500 ms (first 100 lines) |
| Report generation | < 3 s |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly |
| Regex | `re` (stdlib) | Standard |
| Tokenization | `hmac` + `hashlib` (stdlib) | Deterministic  |
| Presidio (optional) | `presidio-analyzer`, `presidio-anonymizer` | NLP PII detection  |
| Salt encryption | `cryptography` (Fernet) | Standard |
| Report export | `json`, `csv`, `Jinja2`, `WeasyPrint` | Multi-format |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
lar/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── lar/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── input_selector.py
│       │   │   ├── profile_selector.py
│       │   │   ├── detector_config.py
│       │   │   ├── salt_manager.py
│       │   │   ├── redaction_progress.py
│       │   │   ├── preview_diff.py
│       │   │   ├── summary_stats.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   └── detectors_table_model.py
│       │   └── widgets/
│       │       ├── detection_badge.py
│       │       ├── diff_highlighter.py
│       │       └── safety_banner.py
│       ├── core/
│       │   ├── detectors/
│       │   │   ├── base.py
│       │   │   ├── email.py
│       │   │   ├── ipv4.py
│       │   │   ├── secrets.py
│       │   │   ├── pii.py
│       │   │   └── custom.py
│       │   ├── replacement/
│       │   │   ├── base.py
│       │   │   ├── tokenizer.py
│       │   │   ├── masker.py
│       │   │   └── redactor.py
│       │   ├── profiles/
│       │   │   └── loader.py
│       │   └── salt/
│       │       └── manager.py
│       ├── storage/
│       │   ├── profile_store.py
│       │   ├── salt_store.py
│       │   └── history_store.py
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── json_exporter.py
│       │   │   ├── csv_exporter.py
│       │   │   ├── html_exporter.py
│       │   │   └── pdf_exporter.py
│       │   └── templates/
│       └── utils/
│           ├── streaming.py
│           └── logging.py
├── detectors/
│   └── *.yaml                 # Built-in detector patterns
├── profiles/
│   ├── gdpr_eu.yaml
│   ├── hipaa_us.yaml
│   ├── pci_dss.yaml
│   └── strict.yaml
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
| **P0 — Skeleton** | Qt shell, input selector, basic email/IP regex, streaming redaction | 2 weeks |
| **P1 — Detector Suite** | Full built-in detector set (secrets, PII, UUIDs, tokens)  | 2 weeks |
| **P2 — Tokenization** | Deterministic HMAC tokenization, salt management  | 1 week |
| **P3 — Profiles** | GDPR, HIPAA, PCI DSS, Strict profiles  | 1 week |
| **P4 — Preview & Diff** | Preview-before-write, side-by-side diff, review gate | 2 weeks |
| **P5 — Summary & Report** | Detection summary, JSON/CSV/HTML/PDF export | 2 weeks |
| **P6 — Presidio (Optional)** | NLP-based PII detection integration  | 2 weeks |
| **P7 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~15 weeks (single senior dev) / ~8 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: regex detection, tokenization determinism, replacement strategies, profile loading.
- **Integration**: full pipeline on synthetic logs with known PII; verify detection counts.
- **GUI**: `pytest-qt` for preview diff, progress, summary.
- **Determinism**: same input + same salt produces identical output across runs .
- **Cross-validation**: compare detection against manual review of synthetic test logs.

---

## 13. Open Questions / Decisions Pending

1. **Presidio dependency** — Presidio is heavy (spaCy models); regex-first for v1; Presidio optional for v2 .
2. **Salt sharing** — salts enable correlation; should teams share salts? Recommend: document clearly; per-team salts recommended.
3. **Irreversible redaction** — tokenization is reversible with salt; true irreversible redaction requires hashing without salt or removal. Recommend: offer both modes .
4. **Format-specific parsing** — JSONL/JSON-aware redaction preserves structure; malformed lines fall back to plaintext .

---

## 14. Glossary

- **PII** — Personally Identifiable Information.
- **PHI** — Protected Health Information (HIPAA) .
- **PAN** — Primary Account Number (PCI DSS) .
- **Deterministic Tokenization** — Same input + same salt = same output token .
- **Salt** — Secret value making tokenization deterministic but non-guessable .
- **Presidio** — Microsoft's PII detection/anonymization framework .
- **Reversible Masking** — CloudWatch-style masking that can be unmasked with permission .
- **Irreversible Redaction** — Permanent removal; no permission can recover .
- **Streaming Redaction** — Line-by-line processing; memory-bounded .

---

*End of document.*