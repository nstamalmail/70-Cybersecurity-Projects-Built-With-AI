"""Report exporters: HTML (self-contained), CSV, JSON. All fields escaped."""
from __future__ import annotations

import csv
import html
import json
import os
import time
from typing import Dict, List, Optional

from .parser import HashRecord
from .policy import summarize

WATERMARK = ("Generated for hashes the operator owns or is explicitly "
             "authorized to test — HashArmor v1.0.0")


def _esc(s) -> str:
    return html.escape(str(s))


def export_html(path: str, records: List[HashRecord],
                meta: Optional[Dict] = None) -> str:
    meta = meta or {}
    summary = summarize(records)
    rows = []
    order = {"CRITICAL": 0, "WEAK": 1, "FAIR": 2, "UNTESTED": 3, "STRONG": 4}
    for r in sorted(records, key=lambda x: (order.get(x.verdict or "UNTESTED", 9),
                                            x.digest_hex)):
        cls = {"CRITICAL": "crit", "WEAK": "weak", "FAIR": "fair",
               "STRONG": "strong", "UNTESTED": "untested"}.get(
                   r.verdict or "UNTESTED", "untested")
        pw = r.plaintext if r.plaintext else "—"
        findings = "<br>".join(_esc(f) for f in r.findings) or "—"
        rows.append(
            f"<tr class='{cls}'>"
            f"<td>{_esc(r.display_name())}</td>"
            f"<td class='mono'>{_esc(r.algo or '?')}</td>"
            f"<td class='mono'>{_esc(r.digest_hex[:24]) + ('…' if len(r.digest_hex) > 24 else '')}</td>"
            f"<td class='mono'>{_esc(pw)}</td>"
            f"<td><span class='pill {cls}'>{_esc(r.verdict or 'UNTESTED')}</span></td>"
            f"<td>{r.entropy_bits:.1f}</td>"
            f"<td class='small'>{findings}</td></tr>"
        )
    chips = "".join(
        f"<span class='chip'>{_esc(k)}: <b>{v}</b></span>" for k, v in summary.items())
    doc = f"""<!doctype html><html><head><meta charset='utf-8'>
<title>HashArmor Audit Report</title><style>
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0f1216;color:#d7dde6;margin:0;padding:24px}}
h1{{font-size:20px;margin:0 0 4px}} .sub{{color:#8a93a3;font-size:12px;margin-bottom:16px}}
.chip{{background:#1a1f26;border:1px solid #2a313c;border-radius:12px;padding:3px 10px;margin-right:6px;font-size:12px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
th{{text-align:left;background:#1a1f26;color:#9fb3c8;padding:8px;border-bottom:1px solid #2a313c}}
td{{padding:8px;border-bottom:1px solid #1d232b;vertical-align:top}}
.mono{{font-family:Consolas,monospace;font-size:12px}}
.small{{font-size:11px;color:#8a93a3}}
.pill{{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}}
.pill.crit{{background:#3a1520;color:#ff5370}} .pill.weak{{background:#3a2c12;color:#f7b83d}}
.pill.fair{{background:#12303a;color:#4dd0e1}} .pill.strong{{background:#12321f;color:#3ddc84}}
.pill.untested{{background:#1c222b;color:#8a93a3}}
tr.crit td:first-child{{border-left:3px solid #ff5370}}
tr.weak td:first-child{{border-left:3px solid #f7b83d}}
tr.strong td:first-child{{border-left:3px solid #3ddc84}}
</style></head><body>
<h1>HashArmor Audit Report</h1>
<div class='sub'>{_esc(WATERMARK)} · {_esc(time.strftime('%Y-%m-%d %H:%M:%S'))}</div>
<div style='margin-bottom:12px'>{chips}</div>
<table><thead><tr><th>Label</th><th>Algorithm</th><th>Digest</th><th>Plaintext</th>
<th>Verdict</th><th>Entropy</th><th>Findings</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
</body></html>"""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path


def export_csv(path: str, records: List[HashRecord]) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["label", "algorithm", "digest_hex", "plaintext",
                    "verdict", "entropy_bits", "findings", "watermark"])
        for r in sorted(records, key=lambda x: x.digest_hex):
            w.writerow([r.display_name(), r.algo or "?", r.digest_hex,
                        r.plaintext or "", r.verdict or "UNTESTED",
                        f"{r.entropy_bits:.1f}", "; ".join(r.findings),
                        WATERMARK])
    return path


def export_json(path: str, records: List[HashRecord],
                meta: Optional[Dict] = None) -> str:
    payload = {
        "watermark": WATERMARK,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "summary": summarize(records),
        "records": [
            {"label": r.display_name(), "algo": r.algo,
             "digest_hex": r.digest_hex, "plaintext": r.plaintext,
             "verdict": r.verdict, "entropy_bits": round(r.entropy_bits, 1),
             "findings": r.findings}
            for r in sorted(records, key=lambda x: x.digest_hex)
        ],
    }
    if meta:
        payload["meta"] = meta
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=1)
    return path
