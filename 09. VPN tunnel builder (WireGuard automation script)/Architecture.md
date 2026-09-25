# Architecture: VPN Tunnel Builder (WireGuard Automation Script) — GUI-Based Solution

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** Automated WireGuard tunnel provisioning (server + peer key generation, config generation, interface control, QR code export) with multi-format report export
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **WireGuard Tunnel Builder (WGTB)** is a GUI-driven desktop application for system administrators, DevOps engineers, and security professionals who need to **rapidly provision and manage WireGuard VPN tunnels** without manually editing configuration files or running a sequence of shell commands. It automates the entire lifecycle: key generation, server configuration, peer provisioning, interface control, and status monitoring — with report generation and export options.

WireGuard is a modern, kernel-native VPN protocol that has seen rapid adoption since its stable release in 2020. It uses state-of-the-art cryptography via the Noise Protocol Framework, operates over UDP only, and is significantly simpler than IPSec or OpenVPN . Its peer-to-peer architecture means every participant is technically a peer, though in practice one side acts as the "server" with a static endpoint . The complexity lies not in the protocol itself but in the operational overhead: generating keys, managing configs, handling platform-specific quirks (especially Windows tunnel services), and keeping the running state in sync with configuration files.

The tool is designed around four principles:

1. **Zero-touch provisioning** — from a single screen, generate a full server + peer setup with keys, addresses, and configs ready to export.
2. **Platform-aware automation** — on Linux/macOS, use `wg-quick` and `wg` utilities; on Windows, use `wireguard.exe /installtunnelservice` for proper service integration .
3. **Stateless where possible** — generate configs and export them; the tool does not need to maintain a daemon, though it can manage live interfaces where permitted.
4. **Report-first** — every provisioning session produces an exportable report documenting the tunnel topology, keys (public only), peer assignments, and handshake status.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Server    │ │ Peer      │ │ Interface │ │ Status    │ │ Report  │ │
│  │ Config    │ │ Manager   │ │ Control   │ │ Monitor   │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Key       │ │ QR Code   │ │ Config    │ │ Topology  │ │ Console │ │
│  │ Generator │ │ Export    │ │ Preview   │ │ View      │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Tunnel     │ │ Platform   │ │ State      │ │ Event Bus / Log    │ │
│  │ Controller │ │ Adapter    │ │ Tracker    │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     WireGuard Core Layer                             │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Key Management │ │ Config         │ │ Interface Control        │  │
│  │ (wg genkey /   │ │ Generator      │ │ (wg-quick / wireguard.exe│  │
│  │  wg pubkey)    │ │ (INI format)   │ │  / wg set)               │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Status Parser (wg show) + Peer Stats                           │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Config     │ │ Key Store  │ │ Report     │ │ Session            │ │
│  │ Store      │ │ (encrypted)│ │ Store      │ │ State              │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `ServerConfigView` | Configure the "server" side: interface name (e.g., `wg0`), private IP/network address, listen port (default 51820), DNS, MTU, NAT forwarding rules, PostUp/PostDown commands . |
| `PeerManagerView` | Manage peer list: add/remove peers, auto-assign IP addresses, set `AllowedIPs`, `PersistentKeepalive`, `PresharedKey` . |
| `KeyGeneratorView` | Generate key pairs via `wg genkey` and `wg pubkey`; display public keys; export private keys to secure files . |
| `InterfaceControlView` | Start/stop interfaces: `wg-quick up/down` (Linux/macOS), `wireguard.exe /installtunnelservice` (Windows) . |
| `StatusMonitorView` | **Primary status view.** Live peer status: latest handshake, bytes transferred (rx/tx), endpoint, allowed IPs . |
| `ConfigPreviewView` | Preview generated `.conf` files (server and peer) with syntax highlighting; copy to clipboard; save to file. |
| `QRCodeExportView` | Generate QR codes for peer configs; export as PNG; print/save for mobile client import . |
| `TopologyView` | Visual representation: server node with peer nodes; link status (handshake age); click peer → show details. |
| `ReportBuilderView` | **Export interface.** Format selection (JSON, CSV, HTML, PDF, TEXT), include sections (server config, peer list, status, key fingerprints). |
| `ConsoleView` | Live log: command execution, errors, permission prompts. |

**Key UI Patterns:**
- **Wizard-style flow**: Server Setup → Add Peers → Generate Configs → Start Tunnel → Monitor.
- **Inline config editing**: generated configs are editable before export.
- **Status color coding**: Green (handshake < 2 min ago), Yellow (handshake > 2 min), Red (no handshake).
- **One-click copy**: public keys, configs, and commands copyable with a single click.
- **Safety indicators**: private keys never displayed in full; masked with reveal option requiring confirmation.

### 3.2 Orchestration Layer

**Tunnel Controller**
- Manages the tunnel lifecycle: configure → generate → start → monitor → stop.
- Coordinates between key generation, config generation, and interface control.
- Handles platform-specific differences via the Platform Adapter.

**Platform Adapter**
- Abstracts the platform-specific WireGuard tooling:

| Platform | Key Gen | Config Apply | Interface Control | Status Query |
|---|---|---|---|---|
| **Linux** | `wg genkey` / `wg pubkey` | `wg-quick up/down` | `ip link` / `wg` | `wg show`  |
| **macOS** | `wg genkey` / `wg pubkey` | `wg-quick up/down` | `wg` | `wg show` |
| **Windows** | `wg genkey` / `wg pubkey` | `wireguard.exe /installtunnelservice` | `sc start/stop` | `wg show`  |

**State Tracker**
- Tracks the current tunnel state: interface name, peer list, running status.
- Syncs running state with config files (detects drift).
- Persists session state for recovery.

### 3.3 WireGuard Core Layer

**Key Management**
- Uses `wg genkey` to generate private keys and `wg pubkey` to derive public keys .
- Optional `wg genpsk` for preshared keys (adds symmetric layer of security) .
- Private keys stored with restrictive permissions (`umask 077`) .

**Config Generator**
- Produces standard `wg-quick` INI-format configs.
- **Server config template** (based on ):
```ini
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = <server_private_key>
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = <client_public_key>
AllowedIPs = 10.0.0.2/32
```
- **Peer config template** (based on ):
```ini
[Interface]
PrivateKey = <client_private_key>
Address = 10.0.0.2/24
DNS = 10.0.0.1

[Peer]
PublicKey = <server_public_key>
Endpoint = <server_ip>:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

**Interface Control**
- **Linux/macOS**: `wg-quick up <interface>` / `wg-quick down <interface>` .
- **Windows**: `wireguard.exe /installtunnelservice <config_path>` creates a Windows service named `WireGuardTunnel$<interface>` .
- The service can be controlled via `sc start/stop WireGuardTunnel$<interface>`.

**Status Parser**
- Parses `wg show <interface>` output for peer stats :
  - Public key
  - Endpoint
  - Allowed IPs
  - Latest handshake
  - Transfer (rx/tx bytes)
- Formats handshake age for GUI display.

### 3.4 Storage Layer

**Data directory:**
```
~/.wgtb/
├── sessions/
│   └── <session_id>/
│       ├── server.conf
│       ├── peers/
│       │   ├── peer1.conf
│       │   └── peer2.conf
│       ├── keys.enc           # Encrypted key storage
│       └── report.json
├── reports/
│   └── <session_id>_report.pdf
└── logs/
    └── wgtb.log
```

**Session model:**
```python
@dataclass
class TunnelSession:
    session_id: str
    interface_name: str
    server_private_key: str      # Encrypted at rest
    server_public_key: str
    server_ip: str
    listen_port: int
    peers: list[PeerConfig]
    created_at: datetime
    status: str                  # 'configured', 'running', 'stopped'

@dataclass
class PeerConfig:
    peer_id: str
    name: str
    private_key: str             # Encrypted at rest
    public_key: str
    preshared_key: str | None
    assigned_ip: str
    allowed_ips: str
    endpoint: str | None
    persistent_keepalive: int | None
```

### 3.5 Canonical Data Model

See `TunnelSession` and `PeerConfig` above.

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, config preview, status display
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Command Worker (QThread)
  ├── Execute wg/wg-quick/wireguard.exe commands
  ├── Capture output
  └── Emit results via signal

Status Poller (QTimer)
  └── Periodic `wg show` query (default: 10s)
```

**Rules:**
- All external commands run in worker thread; GUI never blocks.
- Status polling is non-blocking; results update the status monitor.
- Key generation is fast (<100ms) but still runs in worker to be safe.
- Cancellation: `threading.Event` checked between command executions.

---

## 5. Workflow: End-to-End User Journey

1. **Launch** → select "New Tunnel" or load existing session.
2. **Configure Server** → interface name, IP range, port, DNS, NAT options.
3. **Generate Server Keys** → `wg genkey` / `wg pubkey`; private key stored encrypted.
4. **Add Peers** → one or more peers; each gets auto-assigned IP, keys generated.
5. **Generate Configs** → server and peer `.conf` files previewed.
6. **Export Configs** → download peer configs; generate QR codes for mobile.
7. **Start Tunnel** → `wg-quick up` (Linux/macOS) or `wireguard.exe /installtunnelservice` (Windows).
8. **Monitor Status** → live peer handshake, transfer stats.
9. **Export Report** → JSON/CSV/HTML/PDF with tunnel topology, peer assignments, public key fingerprints.
10. **Stop Tunnel** → `wg-quick down` or `wireguard.exe /uninstalltunnelservice`.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Private key exposure** | Private keys stored encrypted at rest; never displayed in full in GUI; restrictive file permissions (`umask 077`) . |
| **Command injection** | All commands executed with fixed arguments; no shell interpolation of user input. |
| **Config file permissions** | Generated configs written with `0600` permissions on Unix; Windows ACLs restricted to owner . |
| **Elevated privileges** | Interface control requires admin/root; document clearly. Windows uses service installation which handles privilege separation . |
| **Endpoint exposure** | Server public IP visible in peer configs; expected behavior; document. |
| **Report sensitivity** | Reports contain public keys and IPs only; private keys excluded by default; option to include key fingerprints. |

---

## 7. Extensibility Points

1. **New platform** — implement `PlatformAdapter` ABC (Linux, macOS, Windows, Android) .
2. **New export format** — `Exporter` ABC (JSON, CSV, HTML, PDF, TEXT, QR).
3. **Site-to-site topology** — extend to multi-gateway mesh .
4. **Mesh networking** — integrate with mesh generators (e.g., wireguard-mesh) .
5. **API integration** — REST API for headless provisioning .

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 2 s |
| Key generation | < 100 ms |
| Config generation | < 50 ms |
| Interface start | < 3 s |
| Status poll interval | 10 s (configurable) |
| Report generation | < 3 s |
| Memory footprint | < 150 MB RSS |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly |
| WireGuard CLI | `wg`, `wg-quick`, `wireguard.exe` | Official tools  |
| Config format | INI (custom parser) | Standard `wg-quick` format |
| QR codes | `qrcode` + `Pillow` | Mobile export  |
| Report export | `json`, `csv`, `Jinja2`, `WeasyPrint` | Multi-format |
| Encryption | `cryptography` (Fernet) | Key store protection |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
wgtb/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── wgtb/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── server_config.py
│       │   │   ├── peer_manager.py
│       │   │   ├── key_generator.py
│       │   │   ├── interface_control.py
│       │   │   ├── status_monitor.py
│       │   │   ├── config_preview.py
│       │   │   ├── qr_export.py
│       │   │   ├── topology_view.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   └── peers_table_model.py
│       │   └── widgets/
│       │       ├── config_editor.py
│       │       ├── status_badge.py
│       │       └── qr_display.py
│       ├── core/
│       │   ├── keys/
│       │   │   └── generator.py
│       │   ├── config/
│       │   │   ├── generator.py
│       │   │   └── parser.py
│       │   ├── platform/
│       │   │   ├── base.py
│       │   │   ├── linux.py
│       │   │   ├── macos.py
│       │   │   └── windows.py
│       │   ├── control/
│       │   │   └── tunnel_controller.py
│       │   └── status/
│       │       └── parser.py
│       ├── storage/
│       │   ├── session_store.py
│       │   ├── key_store.py
│       │   └── config_store.py
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── json_exporter.py
│       │   │   ├── csv_exporter.py
│       │   │   ├── html_exporter.py
│       │   │   └── pdf_exporter.py
│       │   └── templates/
│       └── utils/
│           ├── net.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── gui/
├── resources/
│   ├── icons/
│   └── templates/
└── docs/
    ├── architecture.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, server config view, key generation | 2 weeks |
| **P1 — Peer Management** | Peer table, IP allocation, key generation per peer | 2 weeks |
| **P2 — Config Generation** | Server + peer config generation, preview, export | 2 weeks |
| **P3 — Platform Adapters** | Linux/macOS (`wg-quick`), Windows (`wireguard.exe`)  | 2 weeks |
| **P4 — Interface Control** | Start/stop tunnel, service installation | 2 weeks |
| **P5 — Status Monitoring** | `wg show` parsing, peer handshake/transfer display | 1 week |
| **P6 — QR & Reporting** | QR code export, JSON/CSV/HTML/PDF report  | 2 weeks |
| **P7 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~16 weeks (single senior dev) / ~8 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: key generation, config parsing/generation, platform adapter selection, status output parsing.
- **Integration**: full tunnel provisioning on Linux (using `wg-quick`) and Windows (using `wireguard.exe`) .
- **GUI**: `pytest-qt` for config preview, peer table, status updates.
- **Cross-platform**: verify Windows service creation and Linux interface control.
- **Security**: verify private key encryption, file permissions, no command injection.

---

## 13. Open Questions / Decisions Pending

1. **Windows service vs userspace** — `wireguard.exe /installtunnelservice` integrates with Windows service manager ; userspace mode is simpler but less robust. Recommend: service mode for production, userspace for testing.
2. **Preshared keys** — add `PresharedKey` by default for post-quantum resistance . Recommend: optional, enabled by default.
3. **NAT configuration** — `PostUp`/`PostDown` iptables rules are Linux-specific; Windows/macOS need different approaches. Recommend: platform-specific templates.
4. **Multi-hop/mesh** — out of scope v1; design for site-to-site in v2 .
5. **Android client** — QR code export supports official WireGuard app . No custom app needed.

---

## 14. Glossary

- **WireGuard** — Modern, kernel-native VPN protocol using Noise Protocol Framework .
- **`wg`** — Command-line utility for WireGuard interface control and status .
- **`wg-quick`** — Script for bringing WireGuard interfaces up/down from config files .
- **`wg genkey` / `wg pubkey`** — Commands for key generation .
- **Interface** — Virtual network interface (e.g., `wg0`) representing a tunnel.
- **Peer** — Remote endpoint; WireGuard is peer-to-peer, though one side often acts as server .
- **`AllowedIPs`** — CIDR ranges routed through a peer .
- **`PersistentKeepalive`** — Keepalive interval to maintain NAT mappings .
- **`PresharedKey`** — Symmetric key adding post-quantum resistance .
- **`Endpoint`** — Remote peer's IP:port .
- **Tunnel service** — Windows service (`WireGuardTunnel$<name>`) managing a tunnel .

---

*End of document.*