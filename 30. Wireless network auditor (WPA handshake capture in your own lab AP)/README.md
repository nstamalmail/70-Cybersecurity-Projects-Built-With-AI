# WNA — Wireless Network Auditor (lab AP, WPA handshake)

Lab-scoped WPA/WPA2 posture validation: **verify** captured handshakes/PMKIDs
from your own access points, convert them to hashcat 22000 format, run a
gated wordlist PSK check, and export a full audit report. The capture/parse/
verify/crack core is pure stdlib — it works offline and inside the portable
exe. Monitor-mode capture (airmon-ng/airodump-ng/hcxdumptool) happens on your
own Linux capture host; this tool consumes the resulting `.cap`/`.pcapng`.

## Run from source

```
pip install -r requirements.txt
python main.py
```

## Run the portable exe

Copy `dist/WNA.exe` anywhere and double-click.

## Workflow

1. **1. Scope** — the BSSID allowlist is **mandatory**; imports/exports as
   text or JSON. Only allowlisted APs can be assessed.
2. **2. Capture & verify** — upload a `.cap`/`.pcapng` captured in your lab
   (e.g. with airodump-ng/hcxdumptool). The verifier parses radiotap/802.11,
   extracts EAPOL frames, classifies M1–M4 and PMKID, and reports
   completeness: *complete / partial / none*.
3. **Verification gate** — cracking stays disabled until a complete M1–M4
   exchange or a valid PMKID is verified (architecture.md principle:
   verification before cracking).
4. **🧬 Convert to hashcat 22000** — hash line(s) previewed and saved.
5. **3. Crack (gated)** — internal PBKDF2/MIC wordlist verification against
   your own handshake (multi-threaded, cancellable), plus exact
   aircrack-ng/hashcat handoff commands.
6. **4. Targets** — save each verified capture as an audit target.
7. **5. Reports** — **⬆ Import audit file…** for report-only workflows, or
   **💾 Export audit report (HTML/CSV/JSON)…** — results are framed as
   posture validation with hardening recommendations.

## Sample data (samples/)

- `sample_allowlist.txt` — scope allowlist
- `make_sample_capture.py` — generates a synthetic WPA2 capture (known PSK
  `hunter2-but-longer`) so the whole flow works without radio hardware
- `sample_audit.json` — report generation from pre-collected targets

## Self-test

```
python main.py --selftest      # 18 checks: parser, M1-M4/PMKID, gate, 22000, cracker, reports
```

## Scope & legality

- Deauth/active capture tooling is out of scope here; the tool records your
  declared allowlist in the report.
- Handshake capture and PSK recovery are permitted **only** for networks you
  own. Cracking is refused without a verified handshake and a scope allowlist.

## Files

- `state.md` — live snapshot maintained by the app
- `memory.md` — append-only audit history
