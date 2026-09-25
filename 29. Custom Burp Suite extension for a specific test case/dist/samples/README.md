# CBSEF sample data

| File | What it is | Where to load it |
|---|---|---|
| `sample_findings.json` | Three pre-collected findings (confirmed + candidates) for a lab API. | Reports tab → **⬆ Import findings file…** → then **Export session…** |
| `sample_request.txt` | Raw HTTP request with a JSON body. | Inspector tab → paste → **🔎 Analyze** / **🧪 Build probes** |
| `../extension/cbsef_burp_extension.py` | Reference Burp extension source posting to the loopback bridge. | See header of that file |

## Report from sample data (no Burp required)

1. Start CBSEF → **4. Reports**
2. **⬆ Import findings file…** → `samples/sample_findings.json`
3. Confirm the export prompt and pick a folder — HTML/CSV/JSON are written.

## Bridge quick check (no Burp required)

1. **1. Config** → ▶ Start bridge (token optional)
2. In another terminal:

```
curl -X POST http://127.0.0.1:8737/findings \
  -H "Content-Type: application/json" \
  -d '{"test_case":"mass_assignment","url":"/api/x","method":"POST",
       "parameter":"is_admin","confidence":"high",
       "signal_description":"manual curl test"}'
```

3. Watch **2. Live findings** — the candidate appears; confirm or reject it.
