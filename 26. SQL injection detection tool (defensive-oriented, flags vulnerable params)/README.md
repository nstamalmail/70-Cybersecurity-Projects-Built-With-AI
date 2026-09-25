# SIDT — SQL Injection Detection Tool (defensive-oriented)

GUI desktop app that detects SQL injection in web apps **you own or are
authorized to test**. Defensive by design: detection only — no data
extraction, no destructive payloads.

## Run from source

```
pip install -r requirements.txt
python main.py
```

## Run the portable exe

Copy `dist/SIDT.exe` anywhere (USB stick is fine) and double-click. First run
unpacks to a temp dir and may take a few seconds.

## Workflow

1. **1. Target** — URL, method, headers, cookies, body. "Load demo target URL"
   or point at your own authorized app.
2. **2. Parameters** — auto-discovered from the request; toggle, add manually,
   or **⬆ Import parameters JSON** (see `samples/sample_parameters.json`).
3. **3. Scan** — choose techniques. Safe mode (default) allows only
   error-based + boolean-based. Time-based/union require unchecking safe mode.
   Confirm the authorization checkbox and start.
4. **4. Findings** — click a row to see baseline vs injected evidence and the
   remediation guide (parameterized queries in Python/Java/Node/PHP, ORM
   guidance, WAF rule suggestions).
5. **5. Reports** — load any scan, **Import findings file…** to build a report
   from manually prepared data, or **Export HTML/CSV/JSON…** to save a report
   anywhere.

## Generate a report from sample data (no scanning)

1. Start SIDT → **5. Reports**
2. **⬆ Import findings file…** → choose `samples/sample_findings.json`
3. Confirm the export prompt and choose a folder — HTML/CSV/JSON are written.

## Demo target

```
python samples/demo_target.py      # serves http://127.0.0.1:8765
```

Endpoints: `/search?user=admin` (error), `/item?id=5` (boolean),
`/list?cat=books` (union), `/sleep?q=1` (time, needs safe mode off).

## Self-test

```
python main.py --selftest          # headless engine verification
```

## Safety

- Safe mode ON by default; time/union techniques are opt-in with caps.
- No `DROP/DELETE/UPDATE/INSERT/TRUNCATE/ALTER/CREATE` tokens in any payload.
- UNION detection uses inert markers only — never extracts data.
- Rate limiting (delay between requests), optional proxy, TLS verification.
- Authorization acknowledgment required before every scan.

## Files

- `state.md` — live snapshot maintained by the app
- `memory.md` — append-only session/scan history
- `samples/` — sample config, parameters, findings + demo target
