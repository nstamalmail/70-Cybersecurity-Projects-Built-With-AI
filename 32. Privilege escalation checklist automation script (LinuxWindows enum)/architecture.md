# Architecture: Privilege Escalation Checklist Automation Script (Linux/Windows Enum) — GUI-Based Solution

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** Automated privilege escalation enumeration for Linux and Windows hosts with consolidated findings, prioritization, remediation guidance, and multi-format report export
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Privilege Escalation Checklist Automation Tool (PECAT)** is a GUI-driven desktop application for authorized penetration testers, red teamers, and defensive security engineers who need to **systematically enumerate privilege escalation vectors** on Linux and Windows hosts. It consolidates the enumeration logic found in tools like LinPEAS and WinPEAS into a single, cross-platform workflow that produces structured, prioritized, and exportable reports.

Privilege escalation is fundamentally an enumeration problem: after gaining initial foothold, the attacker (or authorized tester) must identify the one misconfiguration that grants elevated access. On Linux, this means SUID/SGID binaries, sudo misconfigurations, dangerous capabilities, writable cron jobs, and kernel exploits . On Windows, it means token privileges, weak service permissions, unquoted service paths, AlwaysInstallElevated, and DLL hijacking . Existing tools like LinPEAS and WinPEAS automate this sweep but are CLI-centric, produce unstructured output, and require manual triage of color-highlighted findings .

The tool is designed around four principles:

1. **Cross-platform enumeration** — one tool, one workflow, both Linux and Windows targets.
2. **Structured output** — every finding is categorized (SUID, sudo, cron, services, registry, etc.), prioritized (critical/high/medium/low), and linked to exploitation references (GTFOBins, MITRE ATT&CK) .
3. **Defensive-oriented reporting** — findings include remediation guidance suitable for system hardening, not just exploitation commands.
4. **Report-ready** — export enumeration results in JSON, CSV, HTML, and PDF formats for engagement documentation or hardening audits.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Target    │ │ Enum      │ │ Findings  │ │ Remediation│ │ Report  │ │
│  │ Manager   │ │ Progress  │ │ Dashboard │ │ Guide     │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Checklist │ │ Exploit   │ │ Kernel    │ │ Credential│ │ Console │ │
│  │ View      │ │ Refs      │ │ Suggester │ │ Hunter    │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Enum       │ │ Finding    │ │ Risk       │ │ Event Bus / Log    │ │
│  │ Controller │ │ Normalizer │ │ Scorer     │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Enumeration Engine Layer                         │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Linux          │ │ Windows        │ │ Remote Execution         │  │
│  │ Enumerator     │ │ Enumerator     │ │ (SSH / WinRM / SMB)      │  │
│  │ (SUID, sudo,   │ │ (tokens,       │ │                          │  │
│  │  cron, caps)   │ │  services,     │ │                          │  │
│  │                │ │  registry)     │ │                          │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Checklist Registry (per-platform, per-category checks)         │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Enum       │ │ Finding    │ │ Checklist  │ │ Report Store       │ │
│  │ Store      │ │ Store      │ │ Definitions│ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `TargetManagerView` | Configure enumeration targets: local host or remote (SSH for Linux, WinRM/SMB for Windows). Store credentials in OS keychain. Support bulk target lists. |
| `EnumProgressView` | **Primary progress view.** Live enumeration progress per category (SUID, sudo, cron, services, registry). Show checks completed, findings so far, elapsed time. |
| `FindingsDashboardView` | **Primary findings view.** Aggregated findings table: category, finding, severity, confidence, exploitation reference. Sortable, filterable. Color-coded by severity. |
| `ChecklistView` | Per-category checklist view: SUID/SGID, sudo rules, capabilities, cron, writable files, credentials (Linux); token privileges, services, unquoted paths, AlwaysInstallElevated, registry ACLs, credentials (Windows) . |
| `FindingDetailView` | Drill-down: finding description, raw evidence, exploitation reference (GTFOBins link, MITRE ATT&CK), remediation guidance. |
| `ExploitRefsView` | Cross-reference with GTFOBins (Linux) and known Windows escalation techniques. Click to open reference. |
| `KernelSuggesterView` | Kernel version → known exploit mapping (DirtyCow, DirtyPipe, PwnKit, etc.) . |
| `CredentialHunterView` | Findings related to exposed credentials: bash history, config files, SSH keys, registry autologon, browser data . |
| `RemediationGuideView` | Per-finding remediation: remove SUID bit, restrict sudo rules, fix service permissions, harden registry . |
| `ReportBuilderView` | **Export interface.** Format selection (JSON, CSV, HTML, PDF), sections to include (findings, evidence, remediation, checklist coverage). |
| `ConsoleView` | Live log: command execution, errors, permission warnings. |

**Key UI Patterns:**
- **Category-based layout**: findings grouped by escalation category; categories collapsible.
- **Severity color coding**: Critical (red), High (orange), Medium (yellow), Low (blue), Info (gray).
- **Exploitation reference badges**: GTFOBins link for Linux SUID; technique ID for Windows.
- **Evidence-linked findings**: every finding links to the raw command output that produced it.
- **Remediation-first detail**: the first thing shown for a finding is how to fix it, not how to exploit it.

### 3.2 Orchestration Layer

**Enum Controller**
- Manages enumeration lifecycle: target connection → category selection → check execution → aggregation → reporting.
- Coordinates local and remote enumerators.
- Tracks progress and findings.

**Finding Normalizer**
- Converts platform-specific check results to a unified finding model.
- Assigns category, severity, and confidence based on check metadata.

**Risk Scorer**
- Prioritizes findings based on exploitability, prevalence, and impact.
- Known-exploitable SUID binaries (GTFOBins) scored higher than custom binaries .
- AlwaysInstallElevated and unquoted service paths scored high on Windows .

### 3.3 Enumeration Engine Layer

**Linux Enumerator**

Checks based on established methodology :

| Category | Check | Command |
|---|---|---|
| **System** | Kernel version, distro, patch level | `uname -a`, `cat /etc/os-release` |
| **SUID/SGID** | Find SUID/SGID binaries | `find / -perm -4000 -type f 2>/dev/null` |
| **Sudo** | Sudo rules and NOPASSWD | `sudo -l` |
| **Capabilities** | Files with capabilities | `getcap -r / 2>/dev/null` |
| **Cron** | Scheduled tasks and writable scripts | `cat /etc/crontab`, `ls -la /etc/cron.*` |
| **Writable Files** | World-writable dirs and files | `find / -writable -type f 2>/dev/null` |
| **Credentials** | History files, config files, SSH keys | `cat ~/.bash_history`, find `id_rsa` |
| **Network** | Listening services, NFS exports | `ss -tlnp`, `showmount -e` |

**Windows Enumerator**

Checks based on established methodology :

| Category | Check | Command |
|---|---|---|
| **System** | OS version, patch level, architecture | `systeminfo`, `wmic qfe list` |
| **Privileges** | Token privileges | `whoami /priv` |
| **Groups** | Group membership | `whoami /groups` |
| **Services** | Unquoted paths, weak permissions | `wmic service get name,pathname` |
| **AlwaysInstallElevated** | Registry policy check | `reg query HKLM\...\Installer` |
| **Registry ACLs** | Weak registry permissions | `accesschk.exe` or PowerShell |
| **Credentials** | Autologon, config files, history | Registry, `cmdkey`, config files |
| **DLL Hijacking** | Writable directories in service paths | `icacls` |

**Remote Execution**
- **Linux**: SSH via `paramiko` for remote command execution.
- **Windows**: WinRM via `pywinrm` or SMB via `impacket`.
- Credentials stored in OS keychain; never logged.

### 3.4 Storage Layer

**Data directory:**
```
~/.pecat/
├── enumerations/
│   └── <enum_id>/
│       ├── enum.json             # Full enumeration record
│       ├── findings.jsonl        # Per-finding details
│       ├── evidence/             # Raw command output
│       └── report.html
├── checklists/
│   ├── linux.yaml                # Linux check definitions
│   └── windows.yaml              # Windows check definitions
├── reports/
│   └── <enum_id>_report.pdf
└── logs/
    └── pecat.log
```

**Enumeration record model:**
```python
@dataclass
class PrivilegeEnumeration:
    enum_id: str
    timestamp: datetime
    target_host: str
    target_os: str                  # 'linux', 'windows'
    os_version: str
    checks_executed: int
    findings: list[PrivEscFinding]

@dataclass
class PrivEscFinding:
    finding_id: str
    category: str                   # 'suid', 'sudo', 'service', 'registry', ...
    title: str
    description: str
    severity: str                   # 'critical', 'high', 'medium', 'low', 'info'
    confidence: str                 # 'high', 'medium', 'low'
    evidence: str                   # Raw command output
    exploitation_ref: str | None    # GTFOBins URL, MITRE ATT&CK ID
    remediation: str
    mitre_technique: str | None     # 'T1548.001', 'T1574.009'
```

### 3.5 Canonical Data Model

See `PrivilegeEnumeration` and `PrivEscFinding` above.

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, findings table, detail views
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Enumeration Worker Pool (QThreadPool, N workers)
  ├── Linux check threads (parallel across categories)
  ├── Windows check threads
  └── Remote command execution

Risk Scoring Worker (single thread)
  └── Prioritize findings, compute risk scores

Writer Thread (serial)
  └── SQLite/JSON writes for findings and evidence
```

**Rules:**
- Checks parallelized across categories (default: 5 concurrent).
- Remote execution serialized per host (connection stateful).
- Risk scoring runs after all checks complete.
- SQLite in WAL mode; batch inserts.
- Cancellation: `threading.Event` checked between checks.

---

## 5. Workflow: End-to-End User Journey

1. **Configure Target** → local host or remote (SSH/WinRM); provide credentials.
2. **Select Checks** → choose categories (SUID, sudo, cron, services, etc.) or run all.
3. **Execute Enumeration** → checks run in parallel; findings appear live.
4. **Review Findings** → dashboard shows prioritized findings by severity and category.
5. **Inspect Evidence** → click finding → show raw command output and exploitation reference.
6. **Read Remediation** → hardening guidance for each finding .
7. **Review Kernel Exploits** → version mapping to known CVEs .
8. **Export Report** → JSON/CSV/HTML/PDF for engagement documentation.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Authorization** | Explicit authorization acknowledgment required; tool for authorized testing only. |
| **Remote credentials** | Stored in OS keychain; never logged; transmitted over SSH/WinRM only. |
| **Read-only enumeration** | Checks are read-only; no modification of target system. |
| **Evidence sensitivity** | Evidence may contain credentials; local-only storage; redaction in exports. |
| **Exploitation references** | Links to GTFOBins/ATT&CK provided for context; tool does not execute exploits. |
| **Rate limiting** | Configurable; avoids overwhelming target during enumeration. |

---

## 7. Extensibility Points

1. **New check** — YAML check definition in `checklists/` (command, parser, severity, remediation).
2. **New platform** — implement `PlatformEnumerator` ABC (Linux, Windows, macOS).
3. **New exploitation reference source** — extend `ExploitRefs` (GTFOBins, LOLBAS, ATT&CK).
4. **New export format** — `Exporter` ABC (JSON, CSV, HTML, PDF, SARIF).
5. **CI/CD integration** — CLI mode for automated hardening audits.

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 2 s |
| Local enumeration (Linux, all checks) | < 60 s |
| Local enumeration (Windows, all checks) | < 90 s |
| Remote enumeration latency | < 5 s per check |
| Report generation | < 5 s |
| Memory footprint | < 300 MB RSS |
| Concurrent targets | Up to 5 |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly |
| Linux enumeration | `subprocess` (shell commands) | Standard |
| Windows enumeration | `subprocess` (PowerShell, wmic), `pywin32`  | Native APIs |
| Remote Linux | `paramiko` | SSH client |
| Remote Windows | `pywinrm` | WinRM client |
| DB | SQLite (WAL) | Embedded, ACID |
| Report export | `json`, `csv`, `Jinja2`, `WeasyPrint` | Multi-format |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
pecat/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── pecat/
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
│       │   │   ├── enum_progress.py
│       │   │   ├── findings_dashboard.py
│       │   │   ├── checklist_view.py
│       │   │   ├── finding_detail.py
│       │   │   ├── exploit_refs.py
│       │   │   ├── kernel_suggester.py
│       │   │   ├── credential_hunter.py
│       │   │   ├── remediation_guide.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   └── findings_table_model.py
│       │   └── widgets/
│       │       ├── severity_badge.py
│       │       ├── category_tree.py
│       │       └── evidence_pane.py
│       ├── core/
│       │   ├── enumerators/
│       │   │   ├── base.py
│       │   │   ├── linux.py
│       │   │   ├── windows.py
│       │   │   └── remote.py
│       │   ├── checks/
│       │   │   ├── registry.py
│       │   │   └── checklists/
│       │   │       ├── linux.yaml
│       │   │       └── windows.yaml
│       │   ├── scoring/
│       │   │   └── risk_scorer.py
│       │   ├── references/
│       │   │   ├── gtfobins.py
│       │   │   └── mitre_attack.py
│       │   └── kernel/
│       │       └── exploit_suggester.py
│       ├── storage/
│       │   ├── enum_store.py
│       │   └── finding_store.py
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── json_exporter.py
│       │   │   ├── csv_exporter.py
│       │   │   ├── html_exporter.py
│       │   │   └── pdf_exporter.py
│       │   └── templates/
│       └── utils/
│           ├── subprocess_runner.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── gui/
├── resources/
│   ├── icons/
│   └── checklists/
└── docs/
    ├── architecture.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, target manager, Linux system info checks | 2 weeks |
| **P1 — Linux Core** | SUID/SGID, sudo, capabilities, cron checks  | 3 weeks |
| **P2 — Windows Core** | Token privileges, services, AlwaysInstallElevated  | 3 weeks |
| **P3 — Finding Normalization** | Unified finding model, severity scoring, dashboard | 2 weeks |
| **P4 — Exploitation References** | GTFOBins integration, MITRE ATT&CK mapping | 1 week |
| **P5 — Kernel Suggester** | Version → CVE mapping (DirtyCow, DirtyPipe, PwnKit)  | 1 week |
| **P6 — Remote Execution** | SSH and WinRM remote enumerators | 2 weeks |
| **P7 — Credential Hunter** | History files, config files, registry autologon  | 1 week |
| **P8 — Reporting** | JSON/CSV/HTML/PDF export with remediation | 2 weeks |
| **P9 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~20 weeks (single senior dev) / ~10 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: check execution, output parsing, severity scoring, remediation lookup.
- **Integration**: full enumeration on vulnerable Linux/Windows VMs (e.g., HackTheBox, TryHackMe labs).
- **GUI**: `pytest-qt` for dashboard, findings table, detail views.
- **Cross-validation**: compare findings against LinPEAS/WinPEAS output on same host .
- **Safety**: verify read-only enumeration; verify no exploit execution.

---

## 13. Open Questions / Decisions Pending

1. **LinPEAS/WinPEAS integration** — wrap existing tools vs. custom implementation? Recommend: custom checks for structured output; optional integration for coverage .
2. **Kernel exploit database** — static mapping vs. `searchsploit` integration? Recommend: static curated list of high-impact CVEs for v1.
3. **Windows enumeration depth** — PowerShell vs. native binaries? Recommend: PowerShell where available; `wmic` fallback.
4. **Remote execution scope** — SSH/WinRM only, or also SMB? Recommend: SSH/WinRM for v1.

---

## 14. Glossary

- **Privilege Escalation** — Gaining elevated access (root/SYSTEM) from a low-privilege foothold.
- **SUID** — Set User ID; binary runs as its owner (often root) .
- **sudo** — Allows users to run commands as another user .
- **Capabilities** — Fine-grained Linux privileges (e.g., `cap_setuid`) .
- **AlwaysInstallElevated** — Windows policy allowing MSI installation as SYSTEM .
- **Unquoted Service Path** — Windows service path with spaces allowing binary planting .
- **Token Impersonation** — Windows technique abusing `SeImpersonatePrivilege` .
- **GTFOBins** — Curated list of Unix binaries exploitable for privilege escalation .
- **MITRE ATT&CK** — Adversary tactics and techniques framework.
- **LinPEAS/WinPEAS** — Automated privilege escalation enumeration scripts .

---

*End of document.*