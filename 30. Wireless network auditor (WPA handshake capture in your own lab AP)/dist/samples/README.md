# WNA sample data

| File | What it is | Where to load it |
|---|---|---|
| `sample_allowlist.txt` | Scope allowlist (BSSID=ESSID lines). | Scope tab → **⬆ Import allowlist…** |
| `make_sample_capture.py` | Generates `sample_lab_capture.cap` — a synthetic WPA2 handshake from a known PSK. | `python samples/make_sample_capture.py [out.cap] [psk]` |
| `sample_audit.json` | Two assessed targets (one complete + cracked, one partial). | Reports tab → **⬆ Import audit file…** |

## End-to-end with the sample capture (no radio hardware needed)

```
python samples/make_sample_capture.py        # writes sample_lab_capture.cap
python main.py
```

1. **1. Scope** → **⬆ Import allowlist…** → `samples/sample_allowlist.txt`
2. **2. Capture & verify** → Browse → `samples/sample_lab_capture.cap` →
   **🔎 Verify handshake** — the gate shows *complete 4-way handshake*
3. **🧬 Convert to hashcat 22000** → hash line shown (saved to `data/`)
4. **3. Crack (gated)** → wordlist: the generated capture's PSK is
   `hunter2-but-longer`; make a wordlist containing it → **▶ Start**
5. **4. Targets** → **💾 Save verified capture as target**
6. **5. Reports** → **💾 Export audit report (HTML/CSV/JSON)…**

## Report from sample data (no capture needed)

**5. Reports → ⬆ Import audit file… → `sample_audit.json`** — a full report
is generated from the imported targets and can be saved anywhere.

## Legal

Captures, handshakes and PSK recovery are permitted **only** for networks you
own (your lab AP). The tool enforces a scope allowlist and records it in the
report.
