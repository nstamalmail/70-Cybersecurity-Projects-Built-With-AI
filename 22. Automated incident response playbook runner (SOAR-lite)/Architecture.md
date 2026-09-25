# Architecture: Automated Incident Response Playbook Runner (SOAR-lite) — GUI-Based Solution

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** DAG-based playbook execution engine with action integrations (EDR, firewall, ticketing, notification), approval gates, rollback, and multi-format report export
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **SOAR-lite Playbook Runner (SLPR)** is a GUI-driven desktop application for SOC analysts and incident responders who need **automated, auditable incident response** without deploying a full enterprise SOAR platform. It executes declarative playbooks against live security tooling — isolating endpoints, blocking IPs, disabling accounts, opening tickets, notifying on-call — while enforcing approval gates for high-impact actions and producing complete execution reports.

Full SOAR platforms (Splunk SOAR, Palo Alto Cortex XSOAR, Swimlane, Tines) are comprehensive but costly and complex to operate. Many SOC teams — especially small and mid-sized ones, MSSPs, and lab environments — need **80% of the value at 20% of the complexity**. The SLPR delivers a focused runner: declarative playbooks in YAML, a DAG execution engine, a library of common action integrations, human-in-the-loop approval for destructive actions, and exportable execution reports for audit and post-incident review.

The tool is designed around four principles:

1. **Playbooks as code** — YAML-defined DAGs with typed inputs/outputs, version-controlled and reviewable.
2. **Safe by default** — destructive actions (isolate host, disable account, block IP) require explicit approval unless the playbook and environment explicitly opt into automatic execution.
3. **Idempotent and reversible** — every action declares whether it is reversible and provides a rollback command; the runner tracks state to enable rollback.
4. **Report-ready** — every execution produces a structured report with timeline, per-step inputs/outputs, approvals, errors, and exported artifacts (JSON, CSV, HTML, PDF).

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Playbook  │ │ Execution │ │ DAG       │ │ Approval  │ │ Report  │ │
│  │ Library   │ │ Console   │ │ Viewer    │ │ Dialog    │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Incident  │ │ Action    │ │ Rollback  │ │ Metrics   │ │ Console │ │
│  │ Context   │ │ Log       │ │ Viewer    │ │ Dashboard │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Execution  │ │ DAG        │ │ Approval   │ │ Event Bus / Log    │ │
│  │ Controller │ │ Scheduler  │ │ Manager    │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Playbook Engine Layer                            │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Playbook       │ │ Condition      │ │ State / Context          │  │
│  │ Parser         │ │ Evaluator      │ │ Manager                  │  │
│  │ (YAML → DAG)   │ │ (Jinja2)       │ │                          │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Rollback Engine + Idempotency Tracker + Audit Logger           │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Action Integration Layer                         │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ EDR            │ │ Firewall /     │ │ Identity / IAM           │  │
│  │ (CrowdStrike,  │ │ Proxy (Palo    │ │ (Entra ID, Okta,         │  │
│  │  Defender)     │ │  Alto, CF)     │ │  AD)                     │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Ticketing      │ │ Notification   │ │ Custom Script /          │  │
│  │ (Jira,         │ │ (Slack, Teams, │ │ Webhook                  │  │
│  │  ServiceNow)   │ │  Email, Pager) │ │                          │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Playbook   │ │ Execution  │ │ Credential │ │ Report Store       │ │
│  │ Store      │ │ History    │ │ Store      │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `PlaybookLibraryView` | Browse installed playbooks: name, description, version, author, tags, required integrations. Import/export playbooks. Preview YAML source. |
| `IncidentContextView` | Define incident context for execution: incident ID, affected entities (hostnames, IPs, users, hashes), severity, source alert, analyst notes. Context is passed as variables to the playbook. |
| `ExecutionConsoleView` | **Primary execution view.** Live execution log: step name, status (pending/running/success/failed/skipped/awaiting approval), start/end time, output summary. Click step → show full input/output. |
| `DagViewerView` | Visual DAG of the playbook: nodes = steps, edges = dependencies. Live status coloring (green=success, red=failed, yellow=awaiting, gray=pending). |
| `ApprovalDialogView` | Modal dialog when a step requires approval: shows action, target, impact, and reversal procedure. Approve / Reject / Defer buttons. |
| `ActionLogView` | Detailed log per action: API request/response (redacted), HTTP status, execution time, retry attempts, error messages. |
| `RollbackViewerView` | List of completed actions with reversal capability: shows rollback status per action, "Rollback" button, "Rollback All" option. |
| `MetricsDashboardView` | Aggregate metrics: playbook execution count, success rate, mean time to respond, MTTR, most-used playbooks, most-failed steps. |
| `ReportBuilderView` | **Export interface.** Format selection (JSON, CSV, HTML, PDF), sections to include (timeline, step details, approvals, artifacts, rollback status). |
| `ConsoleView` | Live backend log: DAG scheduling, condition evaluation, integration errors. |

**Key UI Patterns:**
- **DAG-first execution view**: the visual DAG and the execution log are shown side-by-side; step status updates in real time.
- **Approval prominence**: when a step requires approval, the dialog blocks progress and clearly shows impact and reversal.
- **Rollback visibility**: every completed action has a rollback affordance; state tracked in the execution log.
- **Status color coding**: Green (success), Red (failed), Yellow (awaiting approval), Orange (partial), Gray (pending/skipped).
- **Click-to-drill**: click any step → full input/output/error details and API call log.

### 3.2 Orchestration Layer

**Execution Controller**
- Manages playbook execution lifecycle: load → validate → schedule → execute → complete → report.
- Handles pause/resume/cancel.
- Manages variable resolution from incident context.

**DAG Scheduler**
- Topological execution of playbook steps respecting dependencies.
- Parallel execution where dependencies permit.
- Conditional branching (`if`/`else`), loops (`for_each`), and error handling (`try`/`catch`/`finally`).
- Retry policy per step (max attempts, backoff).

**Approval Manager**
- Blocks execution of steps flagged `requires_approval: true` until an analyst approves.
- Records approver identity, timestamp, and justification.
- Supports approval policies (e.g., "require 2 approvers for critical actions").

### 3.3 Playbook Engine Layer

**Playbook Parser**
- Parses YAML playbook definitions into an internal DAG model.
- Validates: cycles, missing dependencies, undefined variables, unregistered actions.
- Supports includes and templates for reusable sub-playbooks.

**Condition Evaluator**
- Evaluates Jinja2 expressions over the execution context.
- Supports conditions on step outputs, incident context, and environmental variables.
- Sandboxed Jinja2 environment (no arbitrary code execution).

**State / Context Manager**
- Maintains execution state: variables, step outputs, incident context.
- Provides variable resolution for step inputs.
- Supports namespaced outputs (e.g., `steps.isolate_host.output.endpoint_id`).

**Rollback Engine**
- Tracks reversible actions and their rollback commands.
- Executes rollback in reverse order on failure or manual trigger.
- Handles partial rollback (some steps irreversible — logged and reported).

**Idempotency Tracker**
- Records action keys to prevent duplicate execution on retry or replay.
- Supports dry-run mode where actions are logged but not executed.

**Audit Logger**
- Append-only hash-chained execution log.
- Records every action, approval, error, and state change.
- Exports for audit and compliance.

### 3.4 Action Integration Layer

Every action implements a common interface:

```python
class Action(ABC):
    name: str
    description: str
    reversible: bool
    destructive: bool
    required_credentials: list[str]

    @abstractmethod
    def execute(self, params: dict, context: ExecutionContext) -> ActionResult: ...

    @abstractmethod
    def rollback(self, result: ActionResult, context: ExecutionContext) -> RollbackResult: ...
```

**Built-in action integrations:**

| Category | Integration | Actions |
|---|---|---|
| **EDR** | CrowdStrike Falcon | `isolate_host`, `lift_isolation`, `quarantine_file`, `kill_process`, `get_device_details` |
| **EDR** | Microsoft Defender | `isolate_device`, `release_device`, `run_antivirus_scan`, `get_device_info` |
| **Firewall** | Palo Alto PAN-OS | `block_ip`, `unblock_ip`, `block_domain`, `commit_config` |
| **Firewall** | Cloudflare | `block_ip`, `unblock_ip`, `add_to_waf_rule` |
| **Identity** | Microsoft Entra ID | `disable_user`, `enable_user`, `revoke_sessions`, `reset_password` |
| **Identity** | Okta | `suspend_user`, `unsuspend_user`, `clear_sessions` |
| **Ticketing** | Jira | `create_issue`, `update_issue`, `add_comment` |
| **Ticketing** | ServiceNow | `create_incident`, `update_incident`, `close_incident` |
| **Notification** | Slack | `post_message`, `create_channel`, `send_dm` |
| **Notification** | Microsoft Teams | `post_message`, `create_chat` |
| **Notification** | Email (SMTP) | `send_email` |
| **Notification** | PagerDuty | `trigger_incident`, `resolve_incident` |
| **Enrichment** | VirusTotal | `lookup_hash`, `lookup_ip`, `lookup_domain`, `lookup_url` |
| **Enrichment** | AbuseIPDB | `lookup_ip` |
| **Script** | Local / Remote | `run_powershell`, `run_bash`, `run_python` |
| **Webhook** | Generic | `post_json`, `get_json` |

### 3.5 Playbook Definition Format

Playbooks are YAML DAGs:

```yaml
name: "Phishing Email Response"
version: "1.0"
description: "Automated triage and containment for reported phishing emails"
author: "SOC Team"
tags: ["phishing", "email", "containment"]
required_integrations: ["virustotal", "crowdstrike", "entra_id", "slack"]

inputs:
  - name: reported_email_hash
    type: sha256
    required: true
  - name: reporter_email
    type: email
    required: true
  - name: affected_user
    type: email
    required: false

steps:
  - id: enrich_hash
    action: virustotal.lookup_hash
    params:
      hash: "{{ inputs.reported_email_hash }}"
    outputs: [vt_result]

  - id: check_reputation
    type: condition
    condition: "{{ steps.enrich_hash.vt_result.positives > 3 }}"
    on_true: isolate_sender
    on_false: notify_benign

  - id: isolate_sender
    action: crowdstrike.isolate_host
    params:
      hostname: "{{ inputs.affected_user }}"
    requires_approval: true
    reversible: true
    outputs: [endpoint_id]

  - id: disable_account
    action: entra_id.disable_user
    params:
      user_principal_name: "{{ inputs.affected_user }}"
    requires_approval: true
    reversible: true

  - id: notify_security
    action: slack.post_message
    params:
      channel: "#soc-alerts"
      message: "Phishing response executed for {{ inputs.reporter_email }}"

  - id: notify_benign
    action: slack.post_message
    params:
      channel: "#soc-alerts"
      message: "Reported email benign, no action taken"

on_failure:
  rollback: true
  notify: "#soc-alerts"
```

### 3.6 Storage Layer

**Data directory:**
```
~/.slpr/
├── playbooks/
│   └── <playbook_id>/
│       ├── playbook.yaml
│       └── metadata.json
├── executions/
│   └── <execution_id>/
│       ├── execution.json
│       ├── audit.jsonl          # Hash-chained audit log
│       ├── step_outputs/
│       └── report.html
├── credentials/
│   └── credentials.enc          # Encrypted credential store
├── reports/
│   └── <execution_id>_report.pdf
└── logs/
    └── slpr.log
```

**Execution record model:**
```python
@dataclass
class PlaybookExecution:
    execution_id: str
    playbook_id: str
    playbook_version: str
    incident_id: str
    started_at: datetime
    finished_at: datetime | None
    status: str                    # 'running', 'success', 'failed', 'cancelled', 'rolled_back'
    inputs: dict
    steps: list[StepExecution]
    approvals: list[ApprovalRecord]
    rollback_status: str | None

@dataclass
class StepExecution:
    step_id: str
    action: str
    status: str                    # 'pending', 'running', 'success', 'failed', 'skipped', 'awaiting_approval'
    started_at: datetime | None
    finished_at: datetime | None
    inputs: dict
    outputs: dict | None
    error: str | None
    retry_count: int
    reversible: bool
    rolled_back: bool

@dataclass
class ApprovalRecord:
    step_id: str
    approver: str
    timestamp: datetime
    decision: str                  # 'approved', 'rejected', 'deferred'
    justification: str | None
```

### 3.7 Canonical Data Model

See `PlaybookExecution`, `StepExecution`, and `ApprovalRecord` above.

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, DAG rendering, execution log
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

DAG Scheduler (single thread)
  ├── Topological ordering
  ├── Parallel step dispatch (asyncio or thread pool)
  └── State transitions

Action Execution Pool (QThreadPool, N workers)
  ├── API calls to EDR, firewall, identity, ticketing
  ├── Script execution
  └── Result marshalling

Approval Thread (main thread, via Qt signal)
  └── Blocks on user decision (modal dialog)

Audit Writer (single thread)
  └── Append-only hash-chained log
```

**Rules:**
- DAG scheduler runs in dedicated thread; UI marshalled via signals.
- Actions execute in parallel where dependencies permit.
- Approval gates block execution until user decision (async).
- Credentials accessed via encrypted store, decrypted per-action in memory only.
- Cancellation: `threading.Event` checked between steps.

---

## 5. Workflow: End-to-End User Journey

1. **Select Playbook** → browse library, choose playbook matching incident type.
2. **Provide Incident Context** → incident ID, affected entities, severity, notes.
3. **Pre-Flight Validation** → check required integrations, credentials, permissions.
4. **Execute** → DAG scheduler begins; steps execute in order; live status updates.
5. **Approval Gates** → destructive steps pause for analyst approval; impact and reversal shown.
6. **Monitor** → live execution log and DAG status; drill into any step.
7. **Handle Failure** → on failure, playbook-defined `on_failure` policy triggers (rollback, notify).
8. **Rollback** (if needed) → manual or automatic rollback of reversible actions.
9. **Export Report** → JSON/CSV/HTML/PDF with timeline, step details, approvals, artifacts.
10. **Review Metrics** → update SOC metrics dashboard.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Destructive actions** | Require approval by default; policy-configurable; impact and reversal shown before approval. |
| **Credential exposure** | Encrypted credential store; decrypted per-action in memory; zeroized after use. |
| **API key leakage** | Never logged; redacted in audit logs. |
| **Playbook injection** | YAML parsed with safe loader; Jinja2 sandboxed; no `eval`. |
| **Action scope** | Playbooks declare required integrations; credentials scoped per action. |
| **Rollback safety** | Rollback commands tested; irreversible actions clearly flagged. |
| **Audit integrity** | Hash-chained append-only audit log; exportable verification. |
| **Blast radius** | Dry-run mode; max-target limits; approval for bulk actions. |

---

## 7. Extensibility Points

1. **New action** — implement `Action` ABC; register in `actions/registry.py`.
2. **New integration** — implement `IntegrationAdapter` ABC (EDR, firewall, IAM, ticketing).
3. **New condition operator** — extend `ConditionEvaluator`.
4. **New export format** — `Exporter` ABC (JSON, CSV, HTML, PDF, STIX).
5. **Webhook event trigger** — optional: trigger playbook on incoming alert webhook.

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 2 s |
| Playbook parse and validate | < 500 ms |
| Action execution (API call) | < 5 s typical |
| Approval prompt latency | < 100 ms |
| Rollback latency | < 10 s |
| Report generation | < 5 s |
| Memory footprint | < 300 MB RSS |
| Concurrent executions | 1 per instance (single-analyst design) |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly |
| Playbook format | YAML (`ruamel.yaml`) | Human-readable, version-controllable |
| Condition evaluation | `jinja2` (sandboxed) | Standard templating |
| HTTP client | `requests` + `httpx` (async) | Integration APIs |
| EDR | `falconpy` (CrowdStrike), MS Graph | Official SDKs |
| Firewall | `pan-python`, Cloudflare API | Vendor SDKs |
| IAM | MS Graph, Okta SDK | Official SDKs |
| Ticketing | `jira`, ServiceNow REST | Standard libraries |
| Notification | `slack-sdk`, Teams webhook | Official SDKs |
| Encryption | `cryptography` (Fernet) | Credential store |
| Report export | `json`, `csv`, `Jinja2`, `WeasyPrint` | Multi-format |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
slpr/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── slpr/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── playbook_library.py
│       │   │   ├── incident_context.py
│       │   │   ├── execution_console.py
│       │   │   ├── dag_viewer.py
│       │   │   ├── approval_dialog.py
│       │   │   ├── action_log.py
│       │   │   ├── rollback_viewer.py
│       │   │   ├── metrics_dashboard.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── steps_table_model.py
│       │   │   └── playbooks_table_model.py
│       │   └── widgets/
│       │       ├── dag_canvas.py
│       │       ├── status_badge.py
│       │       └── approval_banner.py
│       ├── core/
│       │   ├── engine/
│       │   │   ├── parser.py
│       │   │   ├── scheduler.py
│       │   │   ├── condition.py
│       │   │   ├── context.py
│       │   │   └── rollback.py
│       │   ├── actions/
│       │   │   ├── base.py
│       │   │   ├── registry.py
│       │   │   ├── edr/
│       │   │   ├── firewall/
│       │   │   ├── identity/
│       │   │   ├── ticketing/
│       │   │   ├── notification/
│       │   │   ├── enrichment/
│       │   │   ├── script/
│       │   │   └── webhook/
│       │   ├── approval/
│       │   │   └── manager.py
│       │   └── audit/
│       │       └── logger.py
│       ├── storage/
│       │   ├── playbook_store.py
│       │   ├── execution_store.py
│       │   └── credential_store.py
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── json_exporter.py
│       │   │   ├── csv_exporter.py
│       │   │   ├── html_exporter.py
│       │   │   └── pdf_exporter.py
│       │   └── templates/
│       └── utils/
│           ├── redaction.py
│           └── logging.py
├── playbooks/
│   ├── phishing_response.yaml
│   ├── ransomware_containment.yaml
│   ├── suspicious_login.yaml
│   └── malware_detonation.yaml
├── tests/
│   ├── unit/
│   ├── integration/
│   └── gui/
├── resources/
│   ├── icons/
│   └── themes/
└── docs/
    ├── architecture.md
    ├── playbook_authoring.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, playbook parser, DAG model, basic scheduler | 2 weeks |
| **P1 — Core Actions** | Notification (Slack/Email), enrichment (VT) actions | 2 weeks |
| **P2 — Execution Console** | Live execution log, DAG viewer, status updates | 2 weeks |
| **P3 — Approval System** | Approval dialog, policy engine, audit of approvals | 1 week |
| **P4 — EDR Integration** | CrowdStrike, Defender isolate/release actions | 2 weeks |
| **P5 — Firewall/IAM** | Palo Alto block, Entra ID disable, rollback | 2 weeks |
| **P6 — Ticketing** | Jira, ServiceNow actions | 1 week |
| **P7 — Rollback Engine** | Reversal tracking, rollback execution | 2 weeks |
| **P8 — Reporting** | JSON/CSV/HTML/PDF execution reports | 2 weeks |
| **P9 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~19 weeks (single senior dev) / ~10 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: playbook parsing, DAG scheduling, condition evaluation, action execution, rollback logic.
- **Integration**: full playbook execution against mock APIs; verify approval flow and rollback.
- **GUI**: `pytest-qt` for DAG viewer, execution console, approval dialog.
- **Safety**: verify dry-run mode; verify approval gate blocks destructive actions.
- **Audit**: verify hash-chained log integrity.

---

## 13. Open Questions / Decisions Pending

1. **Approval default** — should all destructive actions require approval, or only "critical"? Recommend: all destructive require approval by default; policy-configurable.
2. **Parallel execution** — parallel steps can complicate rollback ordering. Recommend: allow parallelism but roll back in reverse topological order.
3. **Credential scoping** — per-action credentials vs per-playbook. Recommend: per-action with playbook-declared requirements.
4. **Webhook triggers** — inbound webhook to auto-start playbooks. Recommend: v2 feature.

---

## 14. Glossary

- **SOAR** — Security Orchestration, Automation, and Response.
- **Playbook** — Declarative workflow of response actions.
- **DAG** — Directed Acyclic Graph; playbook execution model.
- **Action** — Single integration operation (isolate host, block IP).
- **Rollback** — Reversing a completed action.
- **Approval Gate** — Human-in-the-loop checkpoint before destructive action.
- **Idempotency** — Repeating an action produces the same result.
- **Audit Log** — Append-only, tamper-evident record of execution.
- **MTTR** — Mean Time to Respond/Resolve.

---

*End of document.*