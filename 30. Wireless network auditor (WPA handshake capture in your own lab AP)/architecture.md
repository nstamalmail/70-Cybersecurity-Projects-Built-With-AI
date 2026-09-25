# Architecture: Wireless Network Auditor (WPA Handshake Capture in Your Own Lab AP) — GUI-Based Solution

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Linux primary (Kali/Ubuntu with monitor-mode-capable adapter); Windows/macOS companion GUI with remote sensor support
**Core Capability:** Lab-scoped WPA/WPA2 handshake and PMKID capture with passive/active modes, integrity verification, offline cracking handoff, and multi-format audit report export
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Wireless Network Auditor (WNA)** is a GUI-driven desktop application for security engineers and wireless auditors who need to **validate the security posture of their own lab access points** by capturing the WPA/WPA2 4-way handshake and PMKID material, then producing a professional audit report. It wraps the two dominant capture workflows — the classic **aircrack-ng** suite (active deauth-assisted) and the modern **hcxtools/hcxdumptool** suite (passive PMKID/clientless) — behind a unified, safe, lab-scoped interface .

The core value proposition is twofold. First, it **democratizes the workflow**: monitor mode setup, channel locking, BSSID targeting, handshake completeness verification, and hash format conversion are all error-prone CLI operations that the GUI sequences correctly and validates at each step . Second, it **enforces lab scope**: an allowlist of BSSIDs is mandatory, active deauthentication requires explicit opt-in per target, and the tool refuses to operate against unauthorized networks — because deauth and rogue AP techniques disrupt production and can affect systems outside the intended scope .

The tool is designed around four principles:

1. **Lab-scoped by design** — BSSID allowlist enforced; deauth requires per-target opt-in; no operation against unauthorized networks.
2. **Capture verification before cracking** — the tool confirms a complete 4-message EAPOL handshake (M1–M4) or valid PMKID before declaring success, avoiding wasted cracking cycles .
3. **Modern and classic workflows** — supports both passive PMKID capture (no client needed, no deauth) and classic deauth-assisted handshake capture .
4. **Report-ready** — export a complete audit report with RF inventory, capture evidence (hashes, timestamps), crack result, and remediation in JSON, CSV, HTML, and PDF.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Adapter   │ │ Target    │ │ Capture   │ │ Crack     │ │ Report  │ │
│  │ Manager   │ │ Allowlist │ │ Console   │ │ Console   │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ RF        │ │ Handshake │ │ PMKID     │ │ Hash      │ │ Console │ │
│  │ Inventory │ │ Verifier  │ │ Viewer    │ │ Converter │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Capture    │ │ Tool       │ │ Crack      │ │ Event Bus / Log    │ │
│  │ Controller │ │ Orchestr.  │ │ Dispatcher │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Wireless Engine Layer                            │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Monitor Mode   │ │ Capture        │ │ Handshake/PMKID          │  │
│  │ Manager        │ │ Engines        │ │ Verifier                 │  │
│  │ (airmon-ng/iw) │ │ (airodump/     │ │ (tshark/pyshark)         │  │
│  │                │ │  hcxdumptool)  │ │                          │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Deauth Engine  │ │ Hash Converter │ │ Crack Engine             │  │
│  │ (aireplay-ng)  │ │ (hcxpcapngtool)│ │ (aircrack-ng/hashcat)    │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Audit      │ │ Capture    │ │ Hash       │ │ Report Store       │ │
│  │ Store      │ │ Artifacts  │ │ Store      │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `AdapterManagerView` | Enumerate wireless interfaces; verify monitor mode and injection support; enable/disable monitor mode; detect adapter chipset and capabilities . |
| `TargetAllowlistView` | **Mandatory scope control.** Enter BSSIDs and ESSIDs of lab APs. Only allowlisted BSSIDs can be targeted for capture or deauth. Import/export allowlist. |
| `RfInventoryView` | **Primary reconnaissance view.** Live airodump-ng-style table: BSSID, ESSID, channel, encryption (WPA2/WPA3/WEP/Open), signal strength (RSSI), connected clients. Filter to allowlisted targets . |
| `CaptureConsoleView` | **Primary capture view.** Real-time capture status: packets captured, EAPOL frames observed, PMKID received, handshake completeness indicator. Live airodump-ng/hcxdumptool output tail. |
| `HandshakeVerifierView` | Post-capture verification: shows whether a complete 4-message EAPOL handshake (M1–M4) was captured, or a valid PMKID. Displays which messages are present . |
| `PmkidViewerView` | For PMKID captures: displays the PMKID hash line, source AP, timestamp, and hashcat mode compatibility . |
| `HashConverterView` | Convert captured `.cap`/`.pcapng` to hashcat mode 22000 format via hcxpcapngtool. Preview the converted hash line. |
| `CrackConsoleView` | **Cracking handoff view.** Configure aircrack-ng (CPU, quick check) or hashcat (GPU, bulk). Select wordlist, rules, masks. Live cracking progress and result . |
| `ReportBuilderView` | **Export interface.** Format selection (JSON, CSV, HTML, PDF), sections to include (RF inventory, capture evidence, handshake verification, crack result, remediation). |
| `ConsoleView` | Live log: monitor mode changes, capture events, tool invocations, errors. |

**Key UI Patterns:**
- **Scope-first layout**: the allowlist must be configured before any capture controls become active.
- **Capture verification gate**: cracking controls remain disabled until the handshake verifier confirms a complete M1–M4 or PMKID.
- **Passive vs. active indicator**: passive capture (PMKID/hcxdumptool) shown in blue; active deauth-assisted capture shown in orange with a warning.
- **Evidence-linked results**: every finding links to the raw capture file, the hash line, and the cracking command used.
- **Remediation-first reporting**: the report frames results as posture validation with hardening recommendations, not as an exploit demonstration.

### 3.2 Orchestration Layer

**Capture Controller**
- Manages the capture lifecycle: adapter prep → scope setup → reconnaissance → target selection → capture → verification.
- Coordinates between airodump-ng (classic) and hcxdumptool (passive) backends.
- Enforces allowlist: refuses to target BSSIDs not in the allowlist .

**Tool Orchestrator**
- Wraps external tools (`airmon-ng`, `airodump-ng`, `aireplay-ng`, `hcxdumptool`, `hcxpcapngtool`, `aircrack-ng`, `hashcat`, `tshark`) as subprocesses .
- Parses tool output for live status updates.
- Handles version detection (hcxdumptool CLI changed between v5/v6/v6.3+) and adapts flags accordingly .

**Crack Dispatcher**
- Hands off the captured hash to aircrack-ng (CPU) or hashcat (GPU, mode 22000) .
- Tracks cracking progress, keys tested per second, and result.
- Supports wordlist, rules, and hybrid mask attacks .

### 3.3 Wireless Engine Layer

**Monitor Mode Manager**
- Enables monitor mode via `airmon-ng start <iface>` or `iw dev <iface> set type monitor` .
- Kills conflicting services (`NetworkManager`, `wpa_supplicant`) before mode change .
- Validates injection support (`aireplay-ng -9`) before active techniques .
- Handles interface renaming (`wlan0` → `wlan0mon`).

**Capture Engines**

| Engine | Tool | Mode | Characteristics |
|---|---|---|---|
| **Classic capture** | `airodump-ng` | Active/Passive | Channel-locked to target BSSID; waits for client handshake; optional deauth assist . |
| **Passive PMKID** | `hcxdumptool` | Passive | Clientless; solicits PMKID in M1; no deauth sent; writes `.pcapng` . |
| **Deauth assist** | `aireplay-ng` | Active | Sends deauth frames to force client re-auth; requires allowlist opt-in . |

**Handshake/PMKID Verifier**
- Parses captured `.cap`/`.pcapng` using `tshark` or `pyshark` with `eapol` display filter .
- Confirms presence of EAPOL messages M1–M4 between the same AP/client pair .
- For PMKID: confirms valid PMKID element in EAPOL M1.
- Reports completeness: "complete 4-way handshake" / "partial (M1,M2 only)" / "PMKID present" .

**Hash Converter**
- Converts `.cap`/`.pcapng` to hashcat mode 22000 via `hcxpcapngtool -o hash.hc22000` .
- Extracts ESSID list for targeted cracking (`-E` flag) .
- Validates converted hash line (format, message pair field).

**Crack Engine**
- **aircrack-ng**: CPU-based quick check against wordlist .
- **hashcat**: GPU-based bulk cracking; mode 22000 unified format .
- Supports dictionary, rules, hybrid mask, and mask attacks .
- Reports cracking speed (keys/s) and result .

### 3.4 Storage Layer

**Data directory:**
```
~/.wna/
├── audits/
│   └── <audit_id>/
│       ├── audit.json            # Full audit record
│       ├── captures/
│       │   ├── <bssid>_handshake.cap
│       │   └── <bssid>_pmkid.pcapng
│       ├── hashes/
│       │   └── <bssid>.hc22000
│       ├── evidence/
│       │   ├── airodump_output.txt
│       │   └── verification.txt
│       └── report.html
├── allowlist.yaml                # Lab scope allowlist
├── wordlists/                    # User-provided wordlists
├── reports/
│   └── <audit_id>_report.pdf
└── logs/
    └── wna.log
```

**Audit record model:**
```python
@dataclass
class WirelessAudit:
    audit_id: str
    timestamp: datetime
    adapter: str
    monitor_interface: str
    allowlist: list[str]              # BSSIDs
    targets: list[AuditTarget]
    capture_method: str               # 'classic', 'pmkid', 'hybrid'

@dataclass
class AuditTarget:
    bssid: str
    essid: str
    channel: int
    encryption: str                   # 'WPA2-PSK', 'WPA3-SAE', 'WPA2-Enterprise'
    handshake_captured: bool
    handshake_completeness: str       # 'complete', 'partial', 'none'
    pmkid_captured: bool
    hash_file: str | None
    crack_attempted: bool
    crack_tool: str | None            # 'aircrack-ng', 'hashcat'
    crack_result: str | None          # password if cracked, None otherwise
    crack_duration_seconds: float | None
    evidence_hashes: dict             # sha256 of capture files
```

### 3.5 Canonical Data Model

See `WirelessAudit` and `AuditTarget` above.

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, RF inventory table, capture console
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Capture Worker (single thread per capture session)
  ├── airodump-ng or hcxdumptool subprocess
  ├── Output parsing and status emission
  └── File writing

Verification Worker (single thread)
  ├── tshark/pyshark parsing of capture
  └── Completeness assessment

Crack Worker (single thread)
  ├── aircrack-ng or hashcat subprocess
  ├── Progress parsing
  └── Result emission
```

**Rules:**
- Capture runs as subprocess; output tailed for live status.
- Verification is post-capture; runs once when capture is stopped.
- Cracking is CPU/GPU-bound; runs in dedicated worker.
- SQLite in WAL mode; batch inserts.
- Cancellation: `threading.Event` checked between tool invocations.

---

## 5. Workflow: End-to-End User Journey

1. **Configure Allowlist** → enter BSSIDs/ESSIDs of lab APs; this is mandatory scope control .
2. **Prepare Adapter** → select wireless interface; enable monitor mode; verify injection support .
3. **Reconnaissance** → scan nearby networks; filter to allowlisted targets .
4. **Select Target** → choose allowlisted AP; lock channel.
5. **Choose Capture Method**:
   - **Passive PMKID** (recommended): clientless, no deauth .
   - **Classic handshake** (with optional deauth): requires client present; deauth opt-in per target .
6. **Capture** → monitor live status; stop when handshake or PMKID confirmed.
7. **Verify** → confirm complete 4-message EAPOL or valid PMKID .
8. **Convert** → convert to hashcat mode 22000 format .
9. **Crack** → aircrack-ng quick check or hashcat GPU bulk .
10. **Report** → export JSON/CSV/HTML/PDF with RF inventory, capture evidence, verification, crack result, and remediation .

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Unauthorized target** | BSSID allowlist mandatory; capture/deauth refuse non-allowlisted targets . |
| **Deauth disruption** | Deauth disabled by default; requires per-target opt-in with warning; rate-limited . |
| **Rogue AP** | Out of scope for v1; no evil-twin functionality. |
| **Capture artifacts** | Hashes and captures stored locally; optional encryption at rest. |
| **Cracked password exposure** | Displayed only after explicit crack completion; not logged in plaintext by default. |
| **Monitor mode conflicts** | Kill NetworkManager/wpa_supplicant before mode change; restore on exit . |
| **Adapter capability** | Validate monitor mode and injection before promising workflows . |
| **Legal compliance** | Explicit lab-only acknowledgement; tool refuses public BSSIDs. |

---

## 7. Extensibility Points

1. **New capture backend** — implement `CaptureEngine` ABC (airodump-ng, hcxdumptool, Kismet).
2. **New crack backend** — implement `CrackBackend` ABC (aircrack-ng, hashcat, cowpatty).
3. **New verification method** — extend `HandshakeVerifier` (tshark, pyshark, scapy).
4. **New export format** — `Exporter` ABC (JSON, CSV, HTML, PDF).
5. **Remote sensor support** — optional: capture on Raspberry Pi, crack on GPU host (PiStorm-style distributed model) .

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 2 s |
| Monitor mode enable | < 5 s |
| RF scan (per channel) | < 2 s |
| PMKID capture (typical) | < 60 s |
| Handshake verification | < 3 s |
| Hash conversion | < 2 s |
| Crack (aircrack-ng, 1M words) | < 5 min |
| Memory footprint | < 300 MB RSS |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly |
| Monitor mode | `airmon-ng` / `iw` | Standard tools  |
| Classic capture | `airodump-ng` / `aireplay-ng` | aircrack-ng suite  |
| Passive capture | `hcxdumptool` / `hcxpcapngtool` | Modern PMKID workflow  |
| Verification | `tshark` / `pyshark` | EAPOL parsing  |
| Cracking | `aircrack-ng` (CPU), `hashcat` (GPU mode 22000) | Industry standard  |
| DB | SQLite (WAL) | Embedded, ACID |
| Report export | `json`, `csv`, `Jinja2`, `WeasyPrint` | Multi-format |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
wna/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── wna/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── adapter_manager.py
│       │   │   ├── target_allowlist.py
│       │   │   ├── rf_inventory.py
│       │   │   ├── capture_console.py
│       │   │   ├── handshake_verifier.py
│       │   │   ├── pmkid_viewer.py
│       │   │   ├── hash_converter.py
│       │   │   ├── crack_console.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── rf_inventory_model.py
│       │   │   └── audit_targets_model.py
│       │   └── widgets/
│       │       ├── scope_banner.py
│       │       ├── capture_status.py
│       │       └── verification_badge.py
│       ├── core/
│       │   ├── adapter/
│       │   │   └── monitor_mode.py
│       │   ├── capture/
│       │   │   ├── base.py
│       │   │   ├── airodump_engine.py
│       │   │   ├── hcxdumptool_engine.py
│       │   │   └── deauth_engine.py
│       │   ├── verify/
│       │   │   ├── handshake_verifier.py
│       │   │   └── pmkid_verifier.py
│       │   ├── convert/
│       │   │   └── hcxpcapngtool.py
│       │   ├── crack/
│       │   │   ├── base.py
│       │   │   ├── aircrack_backend.py
│       │   │   └── hashcat_backend.py
│       │   └── scope/
│       │       └── allowlist.py
│       ├── storage/
│       │   ├── audit_store.py
│       │   └── artifact_store.py
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
│   └── wordlists/
└── docs/
    ├── architecture.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, adapter manager, monitor mode, RF inventory | 2 weeks |
| **P1 — Classic Capture** | airodump-ng integration, channel lock, BSSID target | 2 weeks |
| **P2 — Handshake Verification** | tshark/pyshark EAPOL parsing, completeness check  | 1 week |
| **P3 — Hash Conversion** | hcxpcapngtool integration, mode 22000 output  | 1 week |
| **P4 — Crack Handoff** | aircrack-ng and hashcat integration, progress display  | 2 weeks |
| **P5 — Passive PMKID** | hcxdumptool integration, clientless capture  | 2 weeks |
| **P6 — Deauth Assist** | aireplay-ng integration, per-target opt-in  | 1 week |
| **P7 — Reporting** | JSON/CSV/HTML/PDF export with evidence  | 2 weeks |
| **P8 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~16 weeks (single senior dev) / ~8 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: allowlist enforcement, hash conversion parsing, EAPOL verification logic, crack progress parsing.
- **Integration**: full workflow against a lab AP (own router) with known PSK; verify capture, conversion, crack.
- **GUI**: `pytest-qt` for RF inventory, capture console, verifier display.
- **Cross-validation**: compare handshake verification against manual Wireshark EAPOL filter .
- **Safety**: verify allowlist blocks non-allowlisted targets; verify deauth requires opt-in.

---

## 13. Open Questions / Decisions Pending

1. **Monitor mode on Windows/macOS** — monitor mode and injection are Linux-centric; Windows requires Npcap and specific adapters . Recommend: Linux primary; Windows/macOS companion GUI with remote sensor support.
2. **hcxdumptool version churn** — CLI flags changed between v5, v6, and v6.3+ . Recommend: version detection and flag adaptation.
3. **PMKID vs. handshake priority** — PMKID is clientless and faster; handshake requires client presence . Recommend: default to PMKID; offer handshake as alternative.
4. **WPA3 support** — SAE handshakes are not crackable by this workflow. Recommend: detect and report WPA3; document limitation.

---

## 14. Glossary

- **Monitor Mode** — Wireless adapter mode capturing all 802.11 frames without association .
- **4-Way Handshake** — WPA/WPA2 EAPOL M1–M4 exchange; contains material for offline PSK verification .
- **PMKID** — Pairwise Master Key Identifier; clientless capture technique from EAPOL M1 .
- **EAPOL** — Extensible Authentication Protocol over LAN; carries the handshake .
- **BSSID** — MAC address of an access point.
- **ESSID** — Network name (SSID).
- **PSK** — Pre-Shared Key; the Wi-Fi password.
- **Hashcat Mode 22000** — Unified WPA/WPA2/WPA3 hash format .
- **Deauthentication** — Forcing a client to disconnect, prompting re-auth (active technique) .
- **aircrack-ng** — Classic wireless auditing suite .
- **hcxtools** — Modern passive capture toolkit (hcxdumptool, hcxpcapngtool) .

---

*End of document.*