# Packet Sniffer — Raw Sockets, GUI-based (Python)

**Version:** 1.0
**Date:** 2026-09-07
**Author:** Architecture design (senior security development)
**Status:** Implemented in this repository (`sniffer/` package, `main.py`, packaged via PyInstaller)

---

## 1. Purpose & Scope

A desktop application that captures live network traffic directly from the OS at **Layer 2 / Layer 3** using raw sockets, decodes protocol headers, and presents packets in an interactive, Wireshark-like three-pane GUI. It supports offline analysis of saved captures and export in the industry-standard libpcap format.

### In scope
- Live capture on **Windows** (raw socket + `SIO_RCVALL`), **Linux** (AF_PACKET / raw IP socket).
- Live decoding of Ethernet II, IEEE 802.1Q VLAN, ARP, IPv4, IPv6, ICMP(v4/v6), TCP, UDP, DNS, HTTP (request/response line + headers), TLS ClientHello/ServerHello (SNI extraction).
- Reassembly-free per-packet display (stream reassembly is explicitly out of scope — see §10).
- Three-pane GUI (packet list / protocol detail tree / hex dump), live statistics, display filters, save/load/export (`pcap`, JSON, CSV).
- Portable Windows executable via PyInstaller.

### Out of scope (v1)
- TCP stream reassembly and HTTP body reassembly (skeleton APIs provided: `ReassemblyEngine`).
- WPA-encrypted Wi-Fi (monitor-mode capture, radiotap parsing).
- Defragmentation of IPv4 fragments (fragments are flagged, not reassembled).
- Packet injection / editing (passive capture only — deliberate security posture).

---

## 2. Legal & Ethical Constraints (must be enforced in the product)

Capturing traffic that is not yours may be **illegal** (e.g., wiretapping statutes, CFAA, GDPR). The product therefore:

1. Shows an **elevation/legal notice dialog on first run** (unless `--yes` / `SNIFFER_SKIP_NOTICE=1`).
2. Is **passive-only** by design — no injection code paths exist.
3. Never logs payload contents to disk automatically; export is an explicit user action.

This document and the README repeat the constraint: **use only on networks you own or are explicitly authorized to test.**

---

## 3. High-Level Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                            Presentation Layer                          │
│  main.py → gui/app.py → Tk MainWindow                                 │
│  ┌────────────┐  ┌──────────────┐  ┌──────────┐  ┌────────────────┐   │
│  │ Toolbar /  │  │ Packet List  │  │  Detail  │  │  Hex Dump /    │   │
│  │ StatusBar  │  │ (Treeview)   │  │  Tree    │  │  Stats Tabs    │   │
│  └────────────┘  └──────────────┘  └──────────┘  └────────────────┘   │
│        │                 ▲                ▲                ▲           │
│        │ queue.Queue    event-loop poll (polling, never cross-thread    │
│        ▼                 Tk calls)                                     │
├────────────────────────────────────────────────────────────────────────┤
│                          Application / Control Layer                    │
│  CaptureController  (start/stop/pause, session state machine)          │
│  DisplayFilter      (compile-once expression engine)                   │
│  StatisticsAggregator (counters, top-talkers)                          │
├────────────────────────────────────────────────────────────────────────┤
│                              Core Domain Layer                         │
│  Packet, PacketInfo (immutable value objects)                          │
│  Dissectors (strategy registry): Ethernet, VLAN, ARP, IPv4, IPv6,      │
│  ICMP, TCP, UDP, DNS, HTTP, TLS, QUIC-header                           │
│  NameResolver (LRU-cached reverse DNS — off by default)                │
├────────────────────────────────────────────────────────────────────────┤
│                            Capture / I/O Layer                         │
│  CaptureEngine (abstract) ──┬─ RawSocketEngine (AF_PACKET / SIO_RCVALL)│
│                             ├─ PcapFileEngine (offline .pcap replay)   │
│                             └─ (extensible: libpcap/npf, dpdk, ...)    │
│  PcapWriter / PcapReader (libpcap file format v2.4, little-endian)     │
│  Platform utils: admin detection & elevation, interface discovery      │
├────────────────────────────────────────────────────────────────────────┤
│                              Platform / OS                             │
│  Windows: ws2_32 raw IP socket + SIO_RCVALL (L3)                       │
│  Linux:   AF_PACKET SOCK_RAW (L2, promoted) / raw IP socket fallback   │
└────────────────────────────────────────────────────────────────────────┘
```

### Design principles
| Principle | How it is realized |
|---|---|
| **UI never blocks** | Capture runs in a daemon thread; GUI polls a bounded `queue.Queue` at 60–100 ms intervals. |
| **Backpressure over data loss** | Bounded queue (`maxsize=5000`); when full the engine drops newest packets and increments a dropped counter — the GUI thread can never be swamped. |
| **Immutability** | `Packet`/`PacketInfo` are frozen dataclasses; dissectors never mutate raw bytes. |
| **Open/closed** | New protocol = register a new `Dissector` class in `DISSECTORS` — no core changes. |
| **Graceful degradation** | Every dissector is wrapped in a try/except; a malformed packet renders as "malformed" rather than crashing the capture thread. |
| **No third-party runtime deps** | Pure standard library (`socket`, `struct`, `tkinter`, `threading`) → trivially portable exe, minimal AV friction. |

---

## 4. Module Map

```
main.py                    CLI entrypoint (--list-interfaces, --interface, --headless, --bpf)
sniffer/
  __init__.py              package metadata + elevate-if-needed hook
  __main__.py              `python -m sniffer` support
  models.py                Packet, PacketInfo, ProtocolLayer, capture statistics models
  dissectors.py            strategy registry + all protocol parsers (pure functions)
  display_filter.py        display-filter lexer/parser/evaluator (recursive descent)
  capture/
    __init__.py            exports, CaptureEngine ABC, CaptureController
    engine.py              RawSocketEngine, PcapFileEngine, SnifferConfig
    pcap_file.py           PcapWriter / PcapReader (libpcap v2.4)
    platform_win.py        SIO_RCVALL setup, interface GUID→name mapping, admin check/elevation
    platform_posix.py      AF_PACKET socket setup, interface enumeration, admin check
  gui/
    __init__.py
    app.py                 MainWindow: layout, event loop, menu, toolbar, statusbar
    panels.py              PacketListPanel, DetailTreePanel, HexPanel
    stats_panel.py         StatisticsPanel (counters, top talkers, protocol pie)
    dialogs.py             notice/elevation dialog, about
  utils/
    __init__.py
    platform.py            os detection, is_admin(), run_as_admin(), local IPs
    name_resolver.py       async-ish reverse DNS with LRU cache (thread pool of 1)
tests/
  test_dissectors.py       synthetic frame → expected field values
  test_display_filter.py   grammar/eval tests incl. operator precedence, errors
  test_pcap_file.py        write→read round-trip, magic variants
  test_models.py          Packet immutability & summary formatting
build_exe.bat / build_exe.sh   one-shot PyInstaller packaging scripts
sniffer.spec              PyInstaller spec (windowed, no console, admin manifest)
```

---

## 5. Data Flow (live capture)

```
NIC ──► OS raw socket ──► CaptureEngine.capture_loop()   [worker thread]
                              │ parse bytes ──► Dissector chain
                              │ Packet immutable object
                              ▼
                     queue.Queue(maxsize=5000)          [thread boundary]
                              │
        MainWindow._poll_queue() every ~80 ms [Tk main thread]
                              │ display-filter match?
                              ├─ yes ► PacketListPanel.append (Treeview, capped 200k rows*)
                              ├─      ► StatisticsAggregator.update
                              └─      ► PcapWriter.write (if recording enabled)
```

\* The packet list uses a **fixed-capacity ring behavior**: beyond `--max-rows` (default 200,000) the oldest rows are removed. Memory per row ≈ 1 KB → ~200 MB ceiling, keeping the 32/64-bit exe safe.

### Thread model
| Thread | Responsibility | Ends when |
|---|---|---|
| Tk main thread | All UI, polling queue, user actions | Window closed |
| Capture thread (1, daemon) | Blocking `recvfrom`, dissection, enqueue, stats, pcap write | `stop_event` set |
| DNS resolver thread (optional, 1) | Reverse lookups with 5 s timeout, LRU 4096 | Process exit |

No locks are shared between capture and UI except the queue itself and one `threading.Lock` guarding the statistics snapshot — both cheap.

### Backpressure & drops
- Queue full → engine increments `dropped` counter, **drops the newest packet** (simplest, avoids blocking the NIC read loop).
- StatusBar shows live counters: `pkts / matched / dropped / iface / bps`.

---

## 6. Capture Layer Details

### 6.1 Windows (`platform_win.py`)
- `socket.socket(AF_INET, SOCK_RAW, IPPROTO_IP)` bound to a specific local IPv4 address.
- `setsockopt(IPPROTO_IP, IP_HDRINCL, 1)` then `ioctl(SIO_RCVALL, RCVALL_ON)` — promiscuous-for-the-host mode on that interface. Requires **Administrator**.
- The socket receives complete IP packets (L3). Ethernet/802.1Q headers are **not** available on this path; a synthetic loopback Ethernet header is prepended internally so downstream dissectors see a uniform L2 frame.
- Interface enumeration via `GetAdaptersAddresses` (ctypes) → friendly name + IP + GUID; the bound IP identifies the interface.
- Elevation: `ctypes.windll.shell32.ShellExecuteW(None, "runas", ...)` re-launch with `SNIFFER_ELEVATED=1` env marker to avoid infinite loops.

### 6.2 Linux/BSD (`platform_posix.py`)
- Preferred: `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` bound via `sockaddr_ll` → full **L2** frames incl. VLAN tags. Requires root or `CAP_NET_RAW`.
- Fallback (macOS, restricted envs): `AF_INET/SOCK_RAW` per-protocol sockets marked with a synthetic Ethernet header.
- Interface list: `socket.if_nameindex()` + `SIOCGIFCONF`; non-loopback filter applied for AF_PACKET (loopback seen twice via ETH_P_ALL).

### 6.3 Offline engine (`PcapFileEngine`)
- Reads libpcap v2.4 (magic `d4c3b2a1`/`a1b2c3d4`, nanosecond variant `4d3cb2a1`).
- Replays records into the same queue pipeline with a "file" interface name — identical UI code path, so GUI tests can be driven from fixtures.

### 6.4 pcap export (`PcapWriter`)
- Writes global header with the link type actually captured (1 = Ethernet, 101/228 fallback for raw IP), per-packet `ts_sec/ts_usec/incl_len/orig_len`. Round-trip tested.

---

## 7. Protocol Dissection (strategy registry)

Each dissector is a pure function `(bytes, PacketInfo) -> None` that appends a `ProtocolLayer(name, fields, payload_offset)` to the packet. Payload chaining: each layer hands `pkt.payload[l.offset : ]` to the next.

```
Frame
 └─ Ethernet II (dst, src, ethertype)            [L2, POSIX path]
     └─ 802.1Q VLAN (pcp, dei, vid, inner type)  [optional]
         └─ IPv4 (ver, ihl, tos, len, id, flags, frag, ttl, proto, cksum, src, dst)
         └─ IPv6 (ver, tc, flow, len, nh, hop, src, dst)
             ├─ ICMPv4 / ICMPv6 (type, code, echo id/seq)
             ├─ TCP  (sport, dport, seq, ack, doff, flags, win, cksum, urg, options)
             │    ├─ HTTP  (method/URI/version | status, headers…) [ports 80/8080/8000]
             │    ├─ TLS   (ver, type, ClientHello SNI, ServerHello) [port 443/853…]
             │    └─ QUIC  (version, cid) — header only
             ├─ UDP  (sport, dport, len, cksum)
             │    ├─ DNS  (id, flags, qdcount, questions: name/type/class, answers)
             │    └─ DHCP/QUIC sniff — minimal
             └─ ARP  (htype, ptype, op, sha, spa, tha, tpa)  [from Ethernet]
```

### Robustness rules (senior-dev contract)
1. **Never trust lengths.** Every read is bounds-checked via a helper `need(buf, off, n)`; violations raise `TruncatedPacketError` → layer is dropped, packet marked malformed.
2. **Checksums are validated lazily** (IPv4 header cksum on decode; TCP/UDP off by default — CPU).
3. Unknown ethertype/IP-proto/ports still render with raw hex — **no packet is ever silently dropped**.
4. All dissectors are **pure** (no I/O) → trivially unit-testable with byte fixtures (see `tests/test_dissectors.py`).

---

## 8. Display Filter Engine

Wireshark-like mini-language, recursive-descent parser:

```
expr    := or_expr
or_expr := and_expr ( "or" and_expr )*
and_expr:= not_expr ( "and" not_expr )*
not_expr:= "not" not_expr | comparison | "(" expr ")"
comparison := field op value
op      := == != < <= > >= contains
field   := dotted identifier (e.g. ip.src, tcp.port, http.host, tcp.flags.syn)
value   := quoted string | bareword | number
```

- Compiled **once** to a closure AST; evaluated per-packet in O(fields touched).
- Field registry maps friendly names (`ip.src`, `tcp.flags.syn`, `dns.qname`, `http.host`, `frame.len`, …) to `PacketInfo` accessors; unknown field → inline error in the filter bar (red background), never a crash.
- Examples: `tcp.port == 443`, `ip.addr == 10.0.0.5 and not udp`, `http.request.method == GET`, `tcp contains "password"` (case-insensitive contains).

---

## 9. GUI Layout (tkinter — chosen deliberately)

**Why tkinter:** ships in CPython, zero extra binary deps → the portable exe is ~10–12 MB instead of 60+ MB with Qt, and avoids GPL/LGPL packaging questions. `ttk.Treeview` provides sortable virtualized tables adequate for 10⁵ rows.

```
┌ Toolbar: Start ▶ / Stop ■ / Pause ⏸ │ iface ▼ │ filter [_______] │ Clear │ Save │ ┐
├ Main PanedWindow (vertical) ─────────────────────────────────────────────┤
│ │ Packet List (columns: No, Time, Source, Dest, Protocol, Length, Info) │
│ ├────────────────────────────────────────────────────────────────────────│
│ │ Detail Tree (protocol layers, expandable fields, decoded values)      │
│ ├────────────────────────────────────────────────────────────────────────│
│ │ Hex Dump (offsets 16 bytes/row, ASCII gutter, selection-linked)       │
├ Bottom Notebook ─────────────────────────────────────────────────────────┤
│ │ Statistics: totals, protocol %, top talkers   │ [Status bar]          │
└──────────────────────────────────────────────────────────────────────────┘
```

UX details:
- **Live-follow:** list auto-scrolls to newest while user is at bottom; jumps pause auto-follow.
- **Row coloring** by protocol class (TCP=light blue, UDP=green, DNS=yellow, HTTP=orange, TLS=purple, ARP=pink, errors=red).
- **Detail/Hex selection sync:** clicking a row repopulates both lower panes; hex panel highlights selected field byte ranges (layer offsets stored on `ProtocolLayer`).
- Filter bar validates on Enter; compile errors shown inline.
- Menu: File (Save pcap, Export JSON/CSV, Open pcap), Capture (Start/Stop/Pause, Options: resolve names, promiscuous, max rows), Help (About, legal notice).

---

## 10. Performance & Memory Budget

| Concern | Mitigation |
|---|---|
| 100 Mbps+ line rate bursts | Bounded queue + drop-newest backpressure; dissection is O(bytes) with `struct.unpack_from`, zero copies of payload except hex view (on demand). |
| Long sessions | Row cap 200k; pcap writer streams to disk (no buffering). |
| Tk redraw cost | Batch insert per poll cycle (up to 200 rows/tick), disable per-row tags beyond threshold. |
| Reverse DNS | Off by default; LRU 4096; 1 worker thread; never blocks capture. |
| GIL contention | Dissection (~µs/packet) and Tk poll are short slices; blocking `recvfrom` releases GIL. |

**Explicit non-goal:** TCP stream reassembly — recorded in `memory.md` as v2 candidate.

---

## 11. Security & Hardening Review (threat model)

| Threat | Mitigation |
|---|---|
| Malformed/hostile packets crashing parser | Bounds-checked dissectors, top-level try/except per packet, fuzz-style unit tests with truncations. |
| Privilege abuse | App is passive-only; no send/inject paths; elevation only when user starts a live capture. |
| Secrets in captured payloads (passwords, tokens) | Payloads shown in GUI only; no automatic disk persistence; export is explicit; docs warn to redact before sharing. |
| CVE surface from third-party deps | None at runtime (stdlib-only). |
| EXE tampering | Build script prints SHA256 of artifact; instructions to distribute signed. |
| DLL/PyInstaller hijack | `--onefile` with PyInstaller ≥ 6 defaults; advise signing. |

---

## 12. Packaging — Portable Windows EXE

- **PyInstaller `--onefile --windowed --noconfirm`** via `sniffer.spec`:
  - `console=False` (GUI), hidden imports for `sniffer.gui`, `tkinter` bits auto-detected.
  - UAC manifest `requireAdministrator` is **avoided** deliberately: the exe must open for offline .pcap analysis without elevation; elevation is requested only when starting a live capture (re-launch with "runas").
  - Icon: optional `.ico`; version-info block embedded.
- `build_exe.bat` (Windows) / `build_exe.sh` (cross-check only) run `pip install pyinstaller` then the spec; output in `dist/PacketSniffer.exe` (single portable file) plus SHA256.
- Smoke test: launch exe → open bundled `tests/fixtures/sample.pcap` → verify rows render (no NIC needed).

### Build targets
| Artifact | Command |
|---|---|
| Portable exe | `build_exe.bat` → `dist\PacketSniffer.exe` |
| Onedir build (faster AV scan) | `pyinstaller sniffer.spec -- --onedir` |
| Source run | `python main.py` / `python -m sniffer` |

---

## 13. Testing Strategy

| Level | What | How |
|---|---|---|
| Unit | Dissector correctness | Synthetic frames (hand-built `struct.pack` fixtures) assert field values, incl. truncated/malformed inputs. |
| Unit | Display filter grammar & eval | Precedence, `not/and/or`, parens, `contains`, error cases. |
| Unit | pcap round-trip | Write N packets → read → byte-equal timestamps/lengths; magic variants. |
| Unit | Models | Immutability, summary strings. |
| Integration | GUI | `PcapFileEngine` drives the same pipeline; panel assertions run under Tk test mode (skipped in headless CI). |
| Smoke | Packaged exe | Manual: run exe, open sample.pcap. |

Run: `python -m pytest tests/ -v` (or `python -m unittest discover tests`).

---

## 14. Extensibility Roadmap (recorded in memory.md)

1. TCP stream reassembly + HTTP body/chunked parsing (`ReassemblyEngine` stub exists).
2. IPv4 defragmentation.
3. scapy/libpcap backend selection for monitor-mode Wi-Fi & 802.11 parsing.
4. GeoIP enrichment of external IPs (offline mmdb).
5. Plugin API: drop a `.py` into `plugins/` → auto-registered dissector.

---

## 15. Known Limitations

- Windows raw socket path is IPv4-only (SIO_RCVALL limitation); IPv6 needs NPF/npf packet.sys (scapy path) — v2.
- No 802.11 (Wi-Fi radio) parsing; capture happens at OS-provided layer.
- HTTP over TLS is invisible (by design — no MITM).
- High-rate captures (>50k pps) will drop packets on the GUI path; use headless mode (`--headless`) for those.
