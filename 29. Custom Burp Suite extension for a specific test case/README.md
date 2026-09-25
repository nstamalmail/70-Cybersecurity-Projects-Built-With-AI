# CBSEF — Custom Burp Suite Extension Framework (companion GUI)

A purpose-built Burp Suite extension framework for **one specific, repeatable
test case** — the reference implementation is **mass-assignment detection** —
plus this Python desktop companion GUI for configuration, live findings,
analyst confirmation, and report export.

The repo contains both halves:

- `extension/cbsef_burp_extension.py` — the in-Burp side (Montoya API
  reference / JSON bridge contract) that posts candidate findings to the GUI.
- `app/` — the companion GUI: loopback bridge, live findings table with a
  **confirm / mark-false-positive** workflow, a passive analyzer + active
  probe builder for pasted requests, and multi-format reporting.

## Run from source

```
pip install -r requirements.txt
python main.py
```

## Run the portable exe

Copy `dist/CBSEF.exe` anywhere and double-click.

## Passive-first workflow

1. **1. Config** → ▶ Start loopback bridge (port 8737, optional token).
2. Let the Burp extension post findings to
   `http://127.0.0.1:<port>/findings` — candidates appear live in
   **2. Live findings**.
3. No Burp? Paste a raw request in **3. Inspector** → the selected analyzers
   run passively; the mass-assignment engine can also **build active probes**
   (canary fields such as `is_admin`, `role`) for you to send via Repeater.
4. Analyst confirms or rejects each candidate — only confirmed findings
   belong in a report.
5. **4. Reports** → import a findings file or pick a session →
   **Export session (HTML/CSV/JSON)…**

## Test cases included

| Test case | Mode | Signal |
|---|---|---|
| Mass assignment | passive + probe builder | authorization-like fields bound in JSON bodies; canary echo / status / length delta |
| JWT algorithm confusion | passive | `alg=none` tokens, external `kid`, HS/RS confusion notes |
| OAuth redirect_uri | probe | mutated redirect_uri accepted (302 to off-allowlist origin) |
| GraphQL introspection | probe | `__schema` returns data |

## Sample data (samples/)

- `sample_findings.json` — report generation without any traffic
- `sample_request.txt` — paste into the Inspector to try the analyzers
- `README.md` — includes a curl one-liner to test the bridge end-to-end

## Self-test

```
python main.py --selftest      # 16 checks: engines, bridge round-trip, token, reports
```

## Security notes

- The bridge binds to `127.0.0.1` only; set a token to require
  `X-CBSEF-Token` on every call.
- Passive mode generates zero extra requests; active probes are built for you
  to send manually (rate-limited, non-destructive).
- Findings require human confirmation before they are treated as confirmed.

## Files

- `state.md` — live snapshot maintained by the app
- `memory.md` — append-only session/finding history
