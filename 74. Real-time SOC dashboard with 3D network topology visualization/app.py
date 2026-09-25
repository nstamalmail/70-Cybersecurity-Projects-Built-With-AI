import os
import json
from datetime import datetime
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="SOC Dashboard Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


def load_json(filename: str):
    with open(os.path.join(DATA_DIR, filename), "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(filename: str, data):
    with open(os.path.join(DATA_DIR, filename), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None


@app.get("/", response_class=HTMLResponse)
async def root():
    return FileResponse(os.path.join(BASE_DIR, "static", "index.html"))


@app.get("/api/alerts")
async def get_alerts(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
):
    alerts = load_json("sample_alerts.json")
    if severity:
        alerts = [a for a in alerts if a["severity"] == severity]
    if status:
        alerts = [a for a in alerts if a["status"] == status]
    if category:
        alerts = [a for a in alerts if a["category"] == category]
    if search:
        s = search.lower()
        alerts = [a for a in alerts if s in a["type"].lower() or s in a["message"].lower() or s in a.get("ip", "").lower()]
    return alerts


@app.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: int):
    alerts = load_json("sample_alerts.json")
    for a in alerts:
        if a["id"] == alert_id:
            return a
    raise HTTPException(status_code=404, detail="Alert not found")


@app.put("/api/alerts/{alert_id}")
async def update_alert(alert_id: int, update: IncidentUpdate):
    alerts = load_json("sample_alerts.json")
    for a in alerts:
        if a["id"] == alert_id:
            if update.status is not None:
                a["status"] = update.status
            if update.severity is not None:
                a["severity"] = update.severity
            save_json("sample_alerts.json", alerts)
            return a
    raise HTTPException(status_code=404, detail="Alert not found")


@app.get("/api/network")
async def get_network_topology():
    return load_json("sample_network.json")


@app.get("/api/network/{node_id}")
async def get_node(node_id: int):
    data = load_json("sample_network.json")
    for n in data["nodes"]:
        if n["id"] == node_id:
            return n
    raise HTTPException(status_code=404, detail="Node not found")


@app.get("/api/metrics")
async def get_metrics():
    return load_json("sample_metrics.json")


@app.get("/api/report/security")
async def generate_security_report():
    alerts = load_json("sample_alerts.json")
    network = load_json("sample_network.json")
    metrics = load_json("sample_metrics.json")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    status_counts = {"active": 0, "investigating": 0, "resolved": 0, "acknowledged": 0, "open": 0}
    for a in alerts:
        severity_counts[a["severity"]] = severity_counts.get(a["severity"], 0) + 1
        status_counts[a["status"]] = status_counts.get(a["status"], 0) + 1

    node_status = {"healthy": 0, "warning": 0, "critical": 0, "offline": 0}
    for n in network["nodes"]:
        node_status[n["status"]] = node_status.get(n["status"], 0) + 1

    critical_alerts = [a for a in alerts if a["severity"] == "critical"]

    alert_rows = ""
    for a in alerts[:20]:
        sev_color = {"critical": "#ff4444", "high": "#ff8800", "medium": "#ffcc00", "low": "#44aa44"}.get(a["severity"], "#888")
        alert_rows += f"""<tr>
            <td><span style="color:{sev_color};font-weight:bold;">{a['severity'].upper()}</span></td>
            <td>{a['type']}</td>
            <td>{a['source']}</td>
            <td>{a['ip']}</td>
            <td>{a['message']}</td>
            <td>{a['status']}</td>
            <td>{a['timestamp']}</td>
        </tr>"""

    node_rows = ""
    for n in network["nodes"]:
        status_color = {"healthy": "#44aa44", "warning": "#ffcc00", "critical": "#ff4444", "offline": "#888"}.get(n["status"], "#888")
        node_rows += f"""<tr>
            <td>{n['label']}</td>
            <td>{n['type']}</td>
            <td><span style="color:{status_color};font-weight:bold;">{n['status'].upper()}</span></td>
            <td>{n['ip']}</td>
            <td>{n['location']}</td>
            <td>{n['cpu']}%</td>
            <td>{n['memory']}%</td>
            <td>{n['uptime']}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Security Report - {timestamp}</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; max-width: 1100px; margin: 0 auto; padding: 20px; background: #0a0e17; color: #c9d1d9; }}
h1 {{ color: #00ff88; border-bottom: 2px solid #00ff88; padding-bottom: 10px; }}
h2 {{ color: #8b949e; margin-top: 30px; }}
.stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 20px 0; }}
.stat-card {{ background: #161b22; padding: 18px; border-radius: 8px; text-align: center; border: 1px solid #30363d; }}
.stat-card .value {{ font-size: 28px; font-weight: bold; }}
.stat-card .label {{ font-size: 11px; color: #8b949e; margin-top: 5px; }}
.critical {{ color: #ff4444; }}
.high {{ color: #ff8800; }}
.medium {{ color: #ffcc00; }}
.low {{ color: #44aa44; }}
.healthy {{ color: #44aa44; }}
.warning {{ color: #ffcc00; }}
table {{ width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 13px; }}
th, td {{ padding: 8px 10px; text-align: left; border-bottom: 1px solid #30363d; }}
th {{ background: #161b22; color: #00ff88; }}
tr:hover {{ background: #161b2244; }}
footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #30363d; color: #8b949e; font-size: 12px; text-align: center; }}
</style>
</head>
<body>
<h1>SOC Security Operations Report</h1>
<p style="color:#8b949e">Generated: {timestamp}</p>

<h2>Alert Overview</h2>
<div class="stats-grid">
    <div class="stat-card"><div class="value critical">{severity_counts['critical']}</div><div class="label">Critical Alerts</div></div>
    <div class="stat-card"><div class="value high">{severity_counts['high']}</div><div class="label">High Alerts</div></div>
    <div class="stat-card"><div class="value medium">{severity_counts['medium']}</div><div class="label">Medium Alerts</div></div>
    <div class="stat-card"><div class="value low">{severity_counts['low']}</div><div class="label">Low Alerts</div></div>
</div>

<div class="stats-grid">
    <div class="stat-card"><div class="value" style="color:#ff4444;">{status_counts.get('active', 0)}</div><div class="label">Active Incidents</div></div>
    <div class="stat-card"><div class="value" style="color:#ff8800;">{status_counts.get('investigating', 0)}</div><div class="label">Investigating</div></div>
    <div class="stat-card"><div class="value" style="color:#44aa44;">{status_counts.get('resolved', 0)}</div><div class="label">Resolved</div></div>
    <div class="stat-card"><div class="value" style="color:#00ff88;">{metrics['overview']['mttd_minutes']}min</div><div class="label">MTTD</div></div>
</div>

<h2>Critical Alerts Requiring Immediate Attention</h2>
<table>
<tr><th>Severity</th><th>Type</th><th>Source</th><th>IP</th><th>Message</th><th>Status</th><th>Time</th></tr>
{''.join(f"""<tr>
    <td><span class="critical">CRITICAL</span></td>
    <td>{a['type']}</td><td>{a['source']}</td><td>{a['ip']}</td>
    <td>{a['message']}</td><td>{a['status']}</td><td>{a['timestamp']}</td>
</tr>""" for a in critical_alerts)}
</table>

<h2>Recent Alerts (Top 20)</h2>
<table>
<tr><th>Severity</th><th>Type</th><th>Source</th><th>IP</th><th>Message</th><th>Status</th><th>Time</th></tr>
{alert_rows}
</table>

<h2>Network Topology Status ({len(network['nodes'])} nodes, {len(network['edges'])} connections)</h2>
<div class="stats-grid">
    <div class="stat-card"><div class="value healthy">{node_status.get('healthy', 0)}</div><div class="label">Healthy</div></div>
    <div class="stat-card"><div class="value warning">{node_status.get('warning', 0)}</div><div class="label">Warning</div></div>
    <div class="stat-card"><div class="value critical">{node_status.get('critical', 0)}</div><div class="label">Critical</div></div>
    <div class="stat-card"><div class="value" style="color:#888;">{node_status.get('offline', 0)}</div><div class="label">Offline</div></div>
</div>
<table>
<tr><th>Node</th><th>Type</th><th>Status</th><th>IP</th><th>Location</th><th>CPU</th><th>Memory</th><th>Uptime</th></tr>
{node_rows}
</table>

<h2>Key Metrics</h2>
<div class="stats-grid">
    <div class="stat-card"><div class="value" style="color:#00ff88;">{metrics['overview']['uptime_percentage']}%</div><div class="label">Uptime</div></div>
    <div class="stat-card"><div class="value" style="color:#00ff88;">{metrics['overview']['mttr_minutes']}min</div><div class="label">MTTR</div></div>
    <div class="stat-card"><div class="value" style="color:#00ff88;">{metrics['overview']['total_alerts']}</div><div class="label">Total Alerts</div></div>
    <div class="stat-card"><div class="value" style="color:#00ff88;">{metrics['overview']['active_incidents']}</div><div class="label">Open Incidents</div></div>
</div>

<footer>SOC Security Report &bull; Confidential &bull; {timestamp}</footer>
</body>
</html>"""

    report_path = os.path.join(REPORTS_DIR, f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    return HTMLResponse(content=html, headers={
        "Content-Disposition": f'attachment; filename="security_report.html"'
    })


app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
