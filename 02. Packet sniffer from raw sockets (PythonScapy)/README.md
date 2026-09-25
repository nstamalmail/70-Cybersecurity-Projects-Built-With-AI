# PacketSniffer — GUI Packet Sniffer on Raw Sockets

A desktop packet analyzer built in pure Python (standard library only) that
captures live traffic through **raw sockets** — Windows `SIO_RCVALL`, Linux
`AF_PACKET` — decodes protocol headers, and displays them in a
Wireshark-style three-pane GUI. Includes a **portable Windows EXE** build.

> ⚠️ **Legal / ethical use** — packet sniffing can expose passwords, tokens and
> personal data. Capturing traffic on networks you do not own or are not
> explicitly authorized to test may be **illegal**. This tool is strictly
> passive (no injection) and shows an ethics notice on first run. Redact
> payloads before sharing captures.

---

## Features

- **Live capture** — Windows (raw IP socket + `SIO_RCVALL`, requires
  Administrator) and Linux/macOS (`AF_PACKET` or raw IP, requires root /
  `CAP_NET_RAW`).
- **Offline analysis** — open and dissect `.pcap` files; replay them in the GUI.
- **Protocol decoding** — Ethernet II, 802.1Q VLAN, ARP, IPv4, IPv6, ICMP,
  ICMPv6, TCP (+options), UDP, DNS (incl. compression pointers), HTTP
  (request/response + headers), TLS ClientHello (**SNI extraction**),
  QUIC header, DHCP (minimal).
- **Wireshark-like GUI** — packet list with protocol coloring, expandable
  per-layer detail tree, hex+ASCII dump, live statistics
  (protocol %, top talkers, pps/bps).
- **Display filters** — `tcp.port == 443 and not udp`,
  `ip.host == 10.0.0.5`, `http.request.method == GET`,
  `frame contains "password"`, `tls.sni == "example.com"`, `not arp`, …
- **Export** — save to libpcap `.pcap`, export JSON / CSV.
- **Portable exe** — single 11 MB `PacketSniffer.exe`, no Python required.

## Quick start

### Source (any OS)

```bash
python main.py                       # GUI
python main.py tests/fixtures/sample.pcap   # open sample capture
python main.py --list-interfaces     # enumerate capture interfaces
python main.py --headless --duration 30 --out cap.pcap --yes   # CLI capture
python -m unittest discover -s tests # run the test suite
```

Live capture privileges:

```text
Windows:  run from an elevated prompt, or let the app relaunch elevated (UAC).
Linux:    sudo python main.py  (or setcap cap_net_raw+ep $(which python))
```

### Portable Windows exe

```bat
build_exe.bat
:: → dist\PacketSniffer.exe  (single portable file; SHA256 printed)
dist\PacketSniffer.exe
```

The exe opens without elevation for pcap analysis; choosing *Start capture*
prompts a UAC relaunch (raw sockets need Administrator).

## The GUI

```
┌ Toolbar: ▶ Start │ ■ Stop │ Interface ▼ │ Filter [____________] │ Clear │ Save ┐
├ Packet list:  No │ Time │ Source │ Destination │ Protocol │ Length │ Info     ┤
├ Detail tree:  expandable protocol layers and fields                           ┤
├ Hex dump:     offset │ hex bytes │ ASCII (linked to selection)                ┤
└ Tabs: Statistics (counters, protocol %, top talkers)          [status bar]    ┘
```

- Rows are colored by protocol class; the list auto-follows new packets.
- Click a row → detail tree and hex view update; malformed packets are red.
- Filter bar validates live (red = syntax error) and applies on Enter.

## Filter cheat-sheet

| Expression | Meaning |
|---|---|
| `tcp.port == 443` | TCP to/from port 443 |
| `ip.host == 10.0.0.5` | either endpoint is 10.0.0.5 |
| `tcp.flags.syn == true and tcp.flags.ack == false` | connection attempts |
| `udp.port == 53` | DNS traffic |
| `http.request.method == GET` | HTTP GET requests |
| `tls.sni contains "example"` | TLS ClientHello with SNI match |
| `frame contains "password"` | case-insensitive bytes search |
| `not arp and not icmp` | exclude noise |
| `(tcp.port == 80 or tcp.port == 443) and frame.len > 200` | grouping |

## Project layout & documentation

- `architecture.md` — full design: layers, data flow, thread model, threat
  model, packaging, test strategy.
- `state.md` — current project status, verified items, next actions.
- `memory.md` — durable technical knowledge: decisions, platform gotchas,
  protocol format facts, pitfalls already fixed.
- `sniffer/` — package (`models`, `dissectors`, `display_filter`, `capture/`,
  `gui/`, `utils/`); `main.py` — CLI entry.

## Known limitations

- Windows capture is IPv4-only (`SIO_RCVALL` limitation); IPv6 needs the
  planned scapy/NPF backend.
- No TCP stream reassembly / HTTP body reassembly (v2 roadmap in memory.md).
- No Wi-Fi monitor-mode / 802.11 parsing; no packet injection (by design).
- Very high packet rates (>~50k pps) drop packets on the GUI path — use
  `--headless` for those.

## Build & test

```bash
python -m unittest discover -s tests   # 36 tests, stdlib unittest
build_exe.bat                          # Windows portable exe
./build_exe.sh                         # Linux/macOS build (sanity)
```

See `architecture.md` §12–13 for packaging and testing details.
