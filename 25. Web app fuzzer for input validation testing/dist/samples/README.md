# WebFuzzer sample data

Manual input files you can load into the GUI instead of (or alongside) a live scan.

| File | What it is | Where to load it |
|---|---|---|
| `sample_config.json` | Full scan configuration (target, injection points, payload categories, scan options). | Toolbar → **📂 Import config** |
| `sample_payloads.txt` | Custom payload list (one per line, `#` comments allowed). | Payloads tab → **⬆ Load payloads from file…** |
| `sample_findings.json` | Pre-collected findings; generates a full report without running a scan. | Reports tab → **⬆ Import findings file…** |
| `demo_target.py` | Deliberately vulnerable local web app to scan safely. | `python samples/demo_target.py` (serves http://127.0.0.1:8765) |

## Quick start with the demo target

1. `python samples/demo_target.py`
2. Start WebFuzzer, then in **1. Target** enter `http://127.0.0.1:8765/sqli?user=admin`
3. Confirm the authorization checkbox in **3. Scan**, press **▶ Start scan**
4. Findings appear in **4. Findings**; export from **5. Reports** (HTML/CSV/JSON)

## Generate a report from the sample findings (no scanning needed)

1. Start WebFuzzer → **5. Reports**
2. Click **⬆ Import findings file…** and choose `samples/sample_findings.json`
3. Click **💾 Export HTML/CSV/JSON…** — a report is generated from the imported data
   and can be saved anywhere (exported/downloaded).

## Sample URLs for the demo target

```
http://127.0.0.1:8765/sqli?user=admin
http://127.0.0.1:8765/xss?q=hello
http://127.0.0.1:8765/file?name=readme.txt
http://127.0.0.1:8765/ssti?name=world
http://127.0.0.1:8765/redirect?url=/home
http://127.0.0.1:8765/cmd?host=localhost
http://127.0.0.1:8765/sleep?q=1
http://127.0.0.1:8765/crlf?lang=en
```

Replace targets/payloads with your own data — all import files are plain JSON/text
and meant to be edited. Authorized testing only.
