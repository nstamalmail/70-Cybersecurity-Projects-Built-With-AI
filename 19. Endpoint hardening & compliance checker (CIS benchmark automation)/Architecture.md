# Architecture: Endpoint Hardening & Compliance Checker (CIS Benchmark Automation) — GUI-Based Solution

**Document Version:** 1.0  
**Author:** Senior Security Developer  
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)  
**Core Capability:** Automated assessment of endpoint configurations against CIS Benchmarks, with compliance scoring, remediation guidance, and multi-format report export  
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)  
**Status:** Design Specification

---

## 1. Executive Summary

The **Endpoint Hardening & Compliance Checker (EHCC)** is a GUI-driven desktop application for system administrators, compliance officers, and security engineers who need to **automate endpoint configuration assessment against CIS Benchmarks**. It bridges the gap between manual checklist review and full CIS-CAT Pro deployment by providing a focused, GUI-based assessment tool that runs locally or remotely against Windows and Linux endpoints.

CIS Benchmarks are the globally recognized standard for secure system configuration, with over 100 community-developed benchmarks covering more than 25 vendor product families . CIS-CAT Pro Assessor automates the evaluation of a system's cybersecurity posture against these benchmarks, saving hours of manual configuration review that is also prone to human error . The tool produces a compliance score between 1 and 100, with HTML reports that include remediation steps for non-compliant settings .

The tool is designed around four principles:

1. **Benchmark-native assessment** — directly consumes CIS Benchmark definitions (XML/OVAL) and evaluates them against live system state.
2. **Cross-platform coverage** — supports Windows 10/11, Windows Server 2016-2025, and major Linux distributions (RHEL, Ubuntu, Rocky, Alma) .
3. **Actionable remediation** — every finding includes the specific setting, current value, expected value, and remediation command/script.
4. **Report-ready** — export assessment results in HTML, PDF, JSON, and CSV formats with compliance scores, per-control findings, and remediation guidance.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Target    │ │ Benchmark │ │ Assessment│ │ Finding   │ │ Report  │ │
│  │ Manager   │ │ Selector  │ │ Dashboard │ │ Detail    │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Compliance│ │ Remediation│ │ History   │ │ Exceptions│ │ Console │ │
│  │ Charts    │ │ Guide     │ │ / Trends  │ │ Manager   │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Assessment │ │ Benchmark  │ │ Finding    │ │ Event Bus / Log    │ │
│  │ Controller │ │ Engine     │ │ Aggregator │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Assessment Engine Layer                          │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ CIS Benchmark  │ │ OVAL           │ │ System State             │  │
│  │ Parser         │ │ Evaluator      │ │ Collector                │  │
│  │ (XML/OVAL)     │ │                │ │ (Windows/Linux)          │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Scoring Engine + Exception Handler + Remediation Generator     │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Platform Collector Layer                         │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Windows        │ │ Linux          │ │ Remote                   │  │
│  │ Collector      │ │ Collector      │ │ Collector (WinRM/SSH)    │  │
│  │ (Registry, GPO)│ │ (SSH, /etc)    │ │                          │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Assessment │ │ Benchmark  │ │ Exception  │ │ Report Store       │ │
│  │ Store      │ │ Store      │ │ Store      │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `TargetManagerView` | Configure assessment targets: local system, remote Windows (WinRM), remote Linux (SSH). Store credentials in OS keychain. Support bulk target lists. |
| `BenchmarkSelectorView` | Browse and select CIS Benchmarks: Windows 11 Enterprise (5.1.0), Windows Server 2022 (4.0.0), RHEL 9 (2.0.0), Ubuntu 22.04 LTS, etc. Filter by platform, version, profile level (L1/L2) . |
| `AssessmentDashboardView` | **Primary view.** Overall compliance score (1-100), pass/fail counts, category breakdown (Account Policies, Local Policies, Security Options, etc.), assessment duration. |
| `FindingDetailView` | Drill-down for a selected control: control ID, title, description, current value, expected value, severity, remediation command, CIS reference . |
| `ComplianceChartsView` | Visual breakdown: compliance by category (pie/bar chart), trend over time (line chart), per-target comparison. |
| `RemediationGuideView` | Generated remediation script (PowerShell/bash) for selected findings. Preview, copy, or export. |
| `HistoryTrendsView` | Historical assessment results: compliance score over time, recurring failures, drift detection. |
| `ExceptionsManagerView` | Documented exceptions: controls that are intentionally non-compliant, with justification, approval, and expiration date . |
| `ReportBuilderView` | **Export interface.** Format selection (HTML, PDF, JSON, CSV), sections to include (summary, findings, remediation, exceptions), template selection. |
| `ConsoleView` | Live log: collection progress, OVAL evaluation, errors, permission warnings. |

**Key UI Patterns:**
- **Score-first dashboard**: large compliance score with color gradient (red → yellow → green).
- **Category heatmap**: grid showing compliance status by CIS category.
- **Click-to-drill**: click a finding → show current vs expected value, remediation.
- **Exception indicators**: controls with documented exceptions shown in gray with a badge.
- **Real-time progress**: assessment runs with live progress per control.

### 3.2 Orchestration Layer

**Assessment Controller**
- Manages assessment lifecycle: target connection → system state collection → benchmark evaluation → scoring → reporting.
- Coordinates between platform collectors and the benchmark engine.
- Handles cancellation and partial results.

**Benchmark Engine**
- Parses CIS Benchmark definitions (XML/OVAL format).
- Evaluates OVAL definitions against collected system state.
- Maps results to benchmark controls (passed, failed, not applicable, error).

**Finding Aggregator**
- Collects findings from benchmark evaluation.
- Groups by category (Account Policies, Local Policies, Security Options, etc.).
- Computes per-category and overall compliance scores.

### 3.3 Assessment Engine Layer

**CIS Benchmark Parser**
- Parses CIS Benchmark XML (XCCDF) and OVAL definitions.
- Extracts control metadata: ID, title, description, severity, remediation, references.
- Maps controls to OVAL checks.

**OVAL Evaluator**
- Evaluates OVAL definitions against collected system state.
- Determines pass/fail/error for each control.
- Handles platform-specific OVAL schemas (Windows Registry, Linux file content).

**System State Collector**
- Collects the specific system state required by OVAL checks:
  - **Windows**: Registry keys/values, Group Policy settings, account policies, audit policies, user rights, service configurations.
  - **Linux**: File permissions, content of `/etc/` configuration files, service states, kernel parameters, SSH configuration.
- Uses platform-native APIs: `winreg` on Windows, file reads and command execution on Linux.

**Scoring Engine**
- Computes compliance score: `(passed_controls / total_applicable_controls) × 100`.
- Applies profile level filtering (L1 vs L2) .
- Handles exceptions (excluded from scoring).

**Exception Handler**
- Manages documented exceptions: controls intentionally non-compliant with justification .
- Exceptions excluded from compliance score.
- Expiration tracking and approval workflow.

**Remediation Generator**
- Generates platform-specific remediation commands for failed controls.
- Windows: PowerShell scripts (e.g., `Set-ItemProperty`, `secedit`).
- Linux: bash commands (e.g., `chmod`, `sed`, `sysctl`).
- Commands sourced from CIS Benchmark remediation text.

### 3.4 Platform Collector Layer

**Windows Collector**
- Reads registry keys and values via `winreg`.
- Executes `secedit /export` for security policy analysis.
- Queries `Get-LocalUser`, `Get-Service`, `Get-NetFirewallProfile` via PowerShell.
- Collects audit policy via `auditpol /get /category:*`.

**Linux Collector**
- Reads `/etc/` configuration files (`sshd_config`, `passwd`, `shadow`, `sysctl.conf`, etc.).
- Executes `sysctl -a`, `systemctl list-unit-files`, `ufw status`.
- Checks file permissions via `os.stat()`.
- Collects package versions for software-specific benchmarks.

**Remote Collector**
- **Windows**: WinRM via `pywinrm` for remote registry and PowerShell execution.
- **Linux**: SSH via `paramiko` for remote file reads and command execution.
- Credentials stored in OS keychain; never logged.

### 3.5 Storage Layer

**Data directory:**
```
~/.ehcc/
├── assessments/
│   └── <assessment_id>/
│       ├── assessment.json       # Full result
│       ├── findings.jsonl        # Per-control findings
│       └── remediation.ps1|sh    # Generated remediation
├── benchmarks/
│   └── <benchmark_name>/         # Parsed benchmark definitions
├── exceptions/
│   └── exceptions.yaml           # Documented exceptions
├── reports/
│   └── <assessment_id>_report.pdf
└── logs/
    └── ehcc.log
```

**Assessment record model:**
```python
@dataclass
class ComplianceAssessment:
    assessment_id: str
    target_name: str
    target_os: str                  # 'windows', 'linux'
    target_version: str
    benchmark_name: str             # 'CIS Windows 11 Enterprise v5.1.0'
    profile_level: str              # 'L1', 'L2'
    timestamp: datetime
    compliance_score: int           # 1-100
    total_controls: int
    passed: int
    failed: int
    not_applicable: int
    errors: int
    exceptions: int
    findings: list[ControlFinding]

@dataclass
class ControlFinding:
    control_id: str                 # '1.1.1'
    title: str
    category: str                   # 'Account Policies'
    severity: str                   # 'high', 'medium', 'low'
    status: str                     # 'pass', 'fail', 'not_applicable', 'error', 'exception'
    current_value: str | None
    expected_value: str | None
    remediation: str | None
    cis_reference: str | None
```

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, dashboard updates, findings display
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Collection Worker (single thread per target)
  ├── System state collection (registry/file reads)
  ├── Remote command execution
  └── Emit collected state

Evaluation Worker (single thread)
  ├── OVAL evaluation per control
  ├── Scoring computation
  └── Emit findings

Report Worker (single thread)
  └── Generate HTML/PDF/JSON/CSV
```

**Rules:**
- Collection is I/O-bound; remote collection may be slow, runs in worker.
- OVAL evaluation is CPU-bound; parallelized across controls.
- SQLite/JSON writes serialized.
- Cancellation: `threading.Event` checked between controls.

---

## 5. Workflow: End-to-End User Journey

1. **Configure Target** → local system, remote Windows (WinRM), or remote Linux (SSH).
2. **Select Benchmark** → choose CIS Benchmark matching target OS/version (e.g., "CIS Windows 11 Enterprise v5.1.0") .
3. **Configure Profile** → L1 (baseline) or L2 (defense-in-depth) .
4. **Run Assessment** → system state collected, OVAL evaluated, findings aggregated.
5. **Review Dashboard** → compliance score, pass/fail counts, category breakdown .
6. **Drill into Findings** → current vs expected values, remediation commands.
7. **Manage Exceptions** → document intentional non-compliance with justification .
8. **Generate Remediation** → PowerShell/bash script for failed controls.
9. **Export Report** → HTML/PDF/JSON/CSV with score, findings, remediation.
10. **Track Trends** → historical scores, recurring failures, drift over time.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Credential storage** | Remote credentials stored in OS keychain; never logged. |
| **Read-only assessment** | Tool collects state and reports; does not modify system unless remediation script is explicitly executed by user. |
| **Benchmark integrity** | Downloaded benchmarks validated against CIS signatures; local cache integrity-checked. |
| **Sensitive data in findings** | Some controls may reveal security-relevant configuration (e.g., password policy); local-only storage. |
| **Remediation safety** | Generated scripts are previewed before execution; user must explicitly run them. |
| **Remote connection security** | WinRM over HTTPS; SSH with key-based auth preferred. |

---

## 7. Extensibility Points

1. **New platform collector** — implement `PlatformCollector` ABC (Windows, Linux, macOS).
2. **New benchmark format** — implement `BenchmarkParser` ABC (CIS XML/OVAL, STIG XCCDF).
3. **New OVAL check type** — extend `OvalEvaluator` (registry, file, command, package).
4. **New export format** — `Exporter` ABC (HTML, PDF, JSON, CSV, XCCDF ARF).
5. **Ansible integration** — export remediation as Ansible playbooks .

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 2 s |
| Assessment (Windows, 300 controls) | < 5 min |
| Assessment (Linux, 200 controls) | < 3 min |
| Remote collection latency | < 10 s |
| Report generation | < 10 s |
| Memory footprint | < 500 MB RSS |
| Concurrent targets | Up to 10 |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly |
| Benchmark parsing | `lxml` (XML), custom OVAL parser | CIS benchmarks are XML/OVAL |
| Windows collection | `winreg`, `subprocess` (PowerShell) | Native APIs |
| Linux collection | `subprocess` (sysctl, systemctl), file reads | Native tools |
| Remote Windows | `pywinrm` | WinRM client |
| Remote Linux | `paramiko` | SSH client |
| Scoring | Custom | Simple pass/fail computation |
| Report export | `json`, `csv`, `Jinja2`, `WeasyPrint` | Multi-format |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
ehcc/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── ehcc/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── target_manager.py
│       │   │   ├── benchmark_selector.py
│       │   │   ├── assessment_dashboard.py
│       │   │   ├── finding_detail.py
│       │   │   ├── compliance_charts.py
│       │   │   ├── remediation_guide.py
│       │   │   ├── history_trends.py
│       │   │   ├── exceptions_manager.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── findings_table_model.py
│       │   │   └── targets_table_model.py
│       │   └── widgets/
│       │       ├── score_gauge.py
│       │       ├── category_heatmap.py
│       │       └── severity_badge.py
│       ├── core/
│       │   ├── benchmark/
│       │   │   ├── parser.py
│       │   │   ├── oval_evaluator.py
│       │   │   └── model.py
│       │   ├── collectors/
│       │   │   ├── base.py
│       │   │   ├── windows.py
│       │   │   ├── linux.py
│       │   │   └── remote.py
│       │   ├── scoring/
│       │   │   └── engine.py
│       │   ├── remediation/
│       │   │   └── generator.py
│       │   └── exceptions/
│       │       └── manager.py
│       ├── storage/
│       │   ├── assessment_store.py
│       │   ├── benchmark_store.py
│       │   └── exception_store.py
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── html_exporter.py
│       │   │   ├── pdf_exporter.py
│       │   │   ├── json_exporter.py
│       │   │   └── csv_exporter.py
│       │   └── templates/
│       └── utils/
│           ├── win_registry.py
│           └── logging.py
├── benchmarks/
│   └── (downloaded CIS benchmark XML/OVAL files)
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
| **P0 — Skeleton** | Qt shell, target manager, benchmark selector, local Windows collection | 2 weeks |
| **P1 — CIS Parser** | XML/XCCDF parser, control metadata extraction | 2 weeks |
| **P2 — OVAL Evaluator** | OVAL parsing, evaluation engine, Windows registry checks | 3 weeks |
| **P3 — Scoring & Dashboard** | Compliance score, category breakdown, dashboard UI | 2 weeks |
| **P4 — Linux Collector** | Linux system state collection, OVAL evaluation | 2 weeks |
| **P5 — Remote Collection** | WinRM and SSH remote collectors | 2 weeks |
| **P6 — Remediation** | Remediation script generation, preview, export | 2 weeks |
| **P7 — Exceptions & Trends** | Exception management, history tracking, trend charts | 2 weeks |
| **P8 — Reporting** | HTML/PDF/JSON/CSV export | 2 weeks |
| **P9 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~22 weeks (single senior dev) / ~11 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: XML parsing, OVAL evaluation, scoring, remediation generation.
- **Integration**: full assessment on known non-compliant Windows/Linux VMs; validate score against CIS-CAT benchmark .
- **GUI**: `pytest-qt` for dashboard, finding detail, remediation preview.
- **Cross-validation**: compare findings against manual CIS Benchmark review for a subset of controls.
- **Exception testing**: verify exceptions excluded from scoring.

---

## 13. Open Questions / Decisions Pending

1. **CIS-CAT Lite vs custom** — CIS-CAT Lite is free but limited to internal non-commercial use . A custom tool avoids license restrictions. Recommend: custom implementation for commercial use; CIS-CAT Lite for non-commercial reference.
2. **Benchmark acquisition** — CIS Benchmarks require CIS SecureSuite membership for full XML/OVAL files. Recommend: support user-provided benchmark files; bundle community STIG profiles .
3. **Remediation automation** — full automated remediation is risky; CIS-CAT Pro offers it but with approval gates. Recommend: generate scripts for manual review/execution .
4. **macOS support** — CIS publishes macOS benchmarks . Recommend: v2 feature.

---

## 14. Glossary

- **CIS Benchmarks** — Consensus-developed secure configuration recommendations .
- **CIS-CAT Pro** — CIS Configuration Assessment Tool; commercial tool for automated benchmark assessment .
- **CIS-CAT Lite** — Free version of CIS-CAT; limited benchmarks and functionality .
- **OVAL** — Open Vulnerability and Assessment Language; standard for configuration assessment .
- **XCCDF** — Extensible Configuration Checklist Description Format; benchmark structure.
- **L1/L2** — CIS profile levels: L1 (baseline), L2 (defense-in-depth) .
- **Exception** — Documented, approved deviation from a control requirement .
- **Compliance Score** — Percentage of applicable controls that pass.
- **WinRM** — Windows Remote Management; protocol for remote Windows access.
- **ARF** — Assessment Result Format; OVAL result container.

---

*End of document.*