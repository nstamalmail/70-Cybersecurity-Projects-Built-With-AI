# NTAM Memory: decisions & lessons

- Cross-platform subprocess flags: Windows ping is `ping -n 1 -w <ms> <host>` while
  Linux is `ping -c 1 -W <sec> <host>`; mixing them (e.g. `-w` with `-W`) exits with
  usage errors. Always branch on os.name before building the command.
- Dataclass field ordering bit us once: NetworkLink initially had a default field
  before required ones (TypeError). Rule: required fields first, defaults after.
- reporting.to_dot must accept BOTH dict and dataclass links because imported
  topologies are plain dicts while live discovery yields dataclasses; normalize early.
- arp -a on Windows emits localized text; parsing keys on the IP-in-lines regex rather
  than on interface headers so it survives locale differences.
- SNMP via raw UDP get (no pysnmp) keeps the exe small; a single GET for sysDescr.0 /
  sysName.0 with a short timeout is enough for labeling in an educational tool.
- Graph rendering: positions are stored ON the node model so import -> render needs no
  layout pass, and dragging just writes back to the model (persisted on export).
