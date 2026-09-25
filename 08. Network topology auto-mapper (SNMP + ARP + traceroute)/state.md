# NTAM - Network Topology Auto-Mapper: State

## Status: COMPLETE (discovery, graph view, import, reports verified)

## What this is
Topology mapper per `architecture.md`: host discovery (TCP ping sweep), ARP lookup,
traceroute path building, SNMP sysName/sysDescr collection where agents respond, an
interactive graph view (node/link model + canvas rendering), DOT export, and reports
in TXT/JSON/CSV/HTML/PDF.

## Components
- `src/ntam/engine.py`     - DiscoveryEngine: ping sweep (per-OS args), ARP table parse
  (Windows `arp -a`), traceroute (ICMP/UDP fallback + TTL parsing), SNMP GET via
  best-effort UDP, node/link model with NetworkNode/NetworkLink dataclasses,
  topology JSON serialize/restore, DOT export.
- `src/ntam/reporting.py`  - topology report dict -> TXT/JSON/CSV/HTML/PDF (handles
  both dataclass and dict links when rendering).
- `src/ntam/theme.py`      - dark QSS theme.
- `src/ntam/main.py`       - PySide6 GUI: discovery controls (CIDR, SNMP community),
  graph canvas with node drag, node/link tables, File > Import Topology (JSON),
  File > Export Report, File > Export DOT.
- `sample_data/topology_small_office.json` - importable 12-node office topology.
- `tests/smoke_gui.py`     - model + reports + DOT + import + GUI (offscreen Qt).

## How to run
```
cd "08. Network topology auto-mapper (SNMP + ARP + traceroute)"
python src/ntam/main.py          # GUI
python tests/smoke_gui.py        # smoke test
```

## Verified
- Ping sweep / ARP parse / traceroute run against loopback without crashing; ping arg
  handling fixed for Windows vs Linux flags.
- 5 report formats written from both live discovery and imported topology; DOT export
  parses as a graph file (nodes/edges present).
- Import of topology_small_office.json renders the graph and node tables.
- GUI boots offscreen; canvas draws nodes/links from the model.

## Notes
- SNMP is best-effort: if no agent answers (typical on desktops), nodes still appear
  from ping/ARP with vendor guess left empty; sysName/sysDescr fill in when available.
- Link inference: same-subnet nodes attach to the default gateway; traceroute hops
  chain into router links.
