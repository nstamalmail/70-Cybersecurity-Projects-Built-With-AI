# XPT — XSS Payload Tester (for your own lab web apps)

GUI desktop app that tests **your own lab web apps** for cross-site scripting.
Payloads are lab-safe (`alert(1)` / DOM markers only — no exfiltration, no
keyloggers, no network callbacks).

## Run from source

```
pip install -r requirements.txt
python main.py
```

## Run the portable exe

Copy `dist/XPT.exe` anywhere and double-click. Optional: install
`playwright` (and `playwright install chromium`) to enable browser-based
execution confirmation; without it findings are reflection-based.

## Workflow

1. **1. Target** — lab app URL, method, headers, cookies, body.
2. **2. Parameters** — auto-discovered, manual, or **⬆ Import parameters JSON**.
3. **3. Payloads** — pick contexts (HTML body / attribute / JS string / URL /
   CSS), add custom payloads or **⬆ Load payloads from file…**.
4. **4. Scan** — confirm authorization and start; live console + stats.
5. **5. Findings** — click a row for payload, reflection snippet with encoding
   classification, context, and context-specific remediation.
6. **6. Reports** — load scans, **Import findings file…** for report-only
   workflows, or **Export HTML/CSV/JSON…**.

## Generate a report from sample data (no scanning)

1. Start XPT → **6. Reports**
2. **⬆ Import findings file…** → `samples/sample_findings.json`
3. Confirm the export prompt and choose a folder.

## Demo target

```
python samples/demo_target.py      # serves http://127.0.0.1:8765
```

Endpoints: `/search?q=hello` (reflected), `/profile?name=guest` (attribute
break-out), `/script?q=world` (JS string), `/safe?q=hello` (properly encoded —
should NOT be flagged), `/comment` (stored-style POST).

## Self-test

```
python main.py --selftest
```

## Safety

- Lab-scoped: authorization checkbox required; third-party scanning is on you.
- Payloads trigger `alert(1)` or harmless DOM mutations only.
- CSP presence is reported and remediation notes it — the tool does not attempt
  CSP bypass.
- Encoded (mitigated) reflections are not reported as exploitable findings.

## Files

- `state.md` — live snapshot maintained by the app
- `memory.md` — append-only session/scan history
- `samples/` — sample config, parameters, payloads, findings + demo target
