# Memory — PacketSniffer (Raw Socket GUI)

> **What this file is:** durable technical knowledge that must survive across
> sessions — decisions with reasons, platform gotchas, protocol-format facts,
> and pitfalls already hit once (with their fixes). Read when touching the
> related code. For current status see `state.md`; for design see
> `architecture.md`.

---

## 1. Core Architectural Decisions (do not casually reverse)

| Decision | Why |
|---|---|
| **Stdlib-only runtime** (socket, struct, threading, tkinter, ctypes) | Portable 11 MB exe, no pip install on targets, small AV/CVE surface. Any new dependency needs a very good reason. |
| **Tkinter over Qt** | Ships with CPython → onefile exe feasible; Qt would balloon to 60+ MB and add GPL/LGPL packaging questions. ttk.Treeview is adequate up to ~200k rows. |
| **Bounded queue (5000) + drop-newest backpressure** | Never block the capture thread, never swamp the GUI thread. Dropped counter is surfaced in stats. |
| **Frozen dataclass `Packet` + `object.__setattr__` during `dissect()`** | Immutability for consumers; the layer list is mutable *only* inside dissection, re-frozen to tuple at the end. Do not replace with mutation of `layers` after `dissect()` returns. |
| **Engines are ABCs** (`CaptureEngine`) | Live raw-socket and offline pcap replay share one pipeline and one GUI code path; new backends (scapy/npf, dpdk) plug in without touching UI. |
| **Windows path is L3 (SIO_RCVALL), synthetic Ethernet prepended** | SIO_RCVALL yields IP datagrams only. Uniform L2 view downstream. On Linux AF_PACKET gives real L2 incl. VLAN. |
| **Dissectors are pure functions + `need()` bounds checks** | Malformed input raises `TruncatedPacketError` → flagged, never crashes; trivially unit-testable with hand-built frames. |
| **No `requireAdministrator` manifest in the exe** | The exe must open for offline pcap analysis without UAC. Elevation is requested only when starting a live capture (ShellExecuteW "runas" re-launch). |
| **Passive-only tool** | No packet injection code paths anywhere — deliberate security/legal posture. |

---

## 2. Platform Gotchas (Windows)

1. **Raw sockets need Administrator.** Unelevated: `socket(AF_INET, SOCK_RAW)`
   raises PermissionError; `SIO_RCVALL` ioctl raises OSError even when socket
   creation succeeded. Elevation re-launch uses env marker `SNIFFER_ELEVATED=1`
   to prevent infinite UAC loops.
2. **SIO_RCVALL is IPv4-only.** No IPv6 capture on the raw-socket path (needs
   NPF/WinPcap packet.sys → scapy backend, roadmap v2).
3. **SIO_RCVALL is per-IP-bound.** Bind to a specific adapter IP; enum adapters
   via `GetAdaptersAddresses` (iphlpapi). The x64 struct offsets used in
   `platform_win.py` (FriendlyName 96, Description 104, FirstUnicastAddress 24)
   were validated against Python 3.12 / Windows 11 — re-verify if Windows layout
   changes or on ARM64.
4. **IP_HDRINCL must be set before SIO_RCVALL** on some stacks, else ioctl fails.
5. `socket.if_nameindex()` does not exist on Windows — POSIX-only code path.
6. **Project directory contains non-ASCII characters** (the folder name has a
   mangled `–` in this workspace). Keep terminal output ASCII-safe; avoid
   embedding the absolute path in generated files.

## 3. Platform Gotchas (POSIX)

1. `AF_PACKET + SOCK_RAW + htons(ETH_P_ALL)` → full L2 frames, needs
   `CAP_NET_RAW`/root. Bind to interface name to scope capture.
2. Loopback appears twice via ETH_P_ALL; `platform_posix.py` de-prioritizes it.
3. macOS: AF_PACKET does not exist → falls back to BPF-less raw IP sockets
   (L3, synthetic Ethernet). Monitor-mode Wi-Fi is out of scope.

---

## 4. Protocol-Format Facts (verified in tests)

| Fact | Detail |
|---|---|
| TCP header unpack | `!HHIIHHHH` (sport, dport, seq, ack, doff<<12|flags, win, cksum, urg) — data offset is a **nibble** in the high byte of the 8th halfword pair. |
| IPv4 header checksum | Sum 16-bit words incl. checksum, fold, `(~s) & 0xFFFF == 0` → valid. Only the header, only IPv4. |
| pcap magic | Read first 4 bytes **little-endian**: `0xA1B2C3D4` → file is big-endian; `0xD4C3B2A1` → little-endian. Nano variants: `0xA1B23C4D` (BE file) / `0x4D3CB2A1` (LE file). Getting this backwards silently mis-parses everything. |
| pcap global header | 24 bytes: magic, vmaj, vmin, tz, sig, snaplen, linktype. Records: ts_sec, ts_sub, incl_len, orig_len (16 bytes) + data. |
| DNS compression pointer | `0xC0xx`; max 32 hops. A DNS **response** needs the full question section (name + qtype + qclass) before the answer RRs — omitting it desynchronizes parsing. |
| TLS ClientHello SNI | Record header 5 bytes; handshake body at buf[9]: version(2)+random(32) → sid_len is **one byte at buf[43]**; then cipher_suites(2+cs_len), compression(1+cm_len), extensions_len(2). server_name ext (type 0): name_type at +2, name_len at +3 (u16), name at +5. |
| HTTP detection | First line method or `HTTP/` prefix only; cap decode at 4096 bytes. |
| 802.1Q | TPID 0x8100 + TCI (3 bits PCP, 1 DEI, 12 VID) + **inner ethertype** as two more bytes. |

---

## 5. Pitfalls Hit Once (fixed — don't re-introduce)

1. **Tokenizer split IPs into number tokens** (`10.0.0.1` → `10`, `.`, ...).
   Fix: number regex `(\d+(?:\.\d+)*)` and normalize number/bare/quoted to a
   single `value` kind. Also: **strip quotes before reassigning the kind**, or
   quoted strings keep their quotes.
2. **Value positions must accept barewords** (`tcp.flags.syn == true`,
   `http.request.method == GET`) — `expect_value()` accepts kind
   `value|field|bare`, not just `value`.
3. **Bare protocol names need presence accessors** — `not udp`, `tcp or http`
   work because `_PROTOCOL_PRESENCE` registers `tcp/udp/...` → layer lookup.
4. **Never assign attributes on the frozen Packet outside `dissect()`'s
   sanctioned pattern** — `dataclasses.FrozenInstanceError` otherwise.
5. **TCP/UDP/DNS layers must not set `src`/`dst` string fields** — `Packet.src`
   prefers the topmost layer with `src`, so port-bearing `ip:port` strings leak
   into the packet-list Source/Destination columns. IP layers own `src`/`dst`.
6. **`struct.pack("!HHIIBBHHH", 8 values)`** — format has 9 items; correct TCP
   fixture format is `!HHIIHHHH`.
7. **Ethernet unknown ethertype** → keep Ethernet layer only; the old probe in
   `dissect()` mis-detected 0x0806 (ARP = 0x0806 ≠ 0x0608) and dropped frames.
8. **Close the pcap reader handle on bad magic** — leaked file handles broke
   temp-dir cleanup on Windows (WinError 32).

---

## 6. Roadmap (v2 candidates, with entry points)

| Feature | Entry point / notes |
|---|---|
| TCP stream reassembly + HTTP body/chunked | stub concept `ReassemblyEngine`; key by (src,sport,dst,dport); handle seq wraparound. |
| IPv4 defragmentation | `IPv4` layer already flags `fragmented`; reassemble in engine before dissection. |
| scapy / NPF backend | new `CaptureEngine` subclass; enables IPv6 + monitor-mode Wi-Fi on Windows. |
| Kernel BPF filtering | `SnifferConfig.bpf` accepted but inert; wire to AF_PACKET SO_ATTACH_FILTER; Windows needs NPF. |
| GeoIP enrichment | offline mmdb lookup in stats panel. |
| Plugin dissectors | `DISSECTORS` registry is the extension point; load `plugins/*.py` and register. |
| Wire NameResolver into GUI | checkbox exists (`resolve_var` in app.py); hook `utils/name_resolver.py` into `PacketListPanel.append`. |

---

## 7. Style & Conventions Observed

- Docstring-first modules; "why" comments at tricky lines (struct offsets).
- Tests double as protocol-format documentation — keep fixtures hand-built and
  commented, no captured real traffic in the repo (privacy).
- Build order that works: `python -m unittest discover -s tests` →
  `python -m PyInstaller sniffer.spec --noconfirm` → `dist/PacketSniffer.exe`.
- `build_exe.bat` is the Windows one-shot (installs pyinstaller if missing,
  runs tests, builds, prints SHA256).
