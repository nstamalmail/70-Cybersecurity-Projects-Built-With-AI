import json
import os
import math
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="3D Attack Path Visualizer", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


def load_json(filename: str):
    with open(DATA_DIR / filename, "r") as f:
        return json.load(f)


@app.get("/", response_class=HTMLResponse)
async def root():
    with open(BASE_DIR / "static" / "index.html", "r") as f:
        return HTMLResponse(content=f.read())


@app.get("/api/graph")
async def get_graph():
    graph = load_json("sample_graph.json")
    return graph


@app.get("/api/nodes")
async def get_nodes(node_type: Optional[str] = Query(None)):
    graph = load_json("sample_graph.json")
    nodes = graph["nodes"]
    if node_type:
        nodes = [n for n in nodes if n["type"] == node_type]
    return nodes


@app.get("/api/nodes/{node_id}")
async def get_node(node_id: str):
    graph = load_json("sample_graph.json")
    node = next((n for n in graph["nodes"] if n["id"] == node_id), None)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    edges = graph["edges"]
    connected_edges = [e for e in edges if e["source"] == node_id or e["target"] == node_id]
    connected_nodes = set()
    for e in connected_edges:
        connected_nodes.add(e["source"])
        connected_nodes.add(e["target"])
    connected_nodes.discard(node_id)
    connected_node_list = [n for n in graph["nodes"] if n["id"] in connected_nodes]
    return {
        **node,
        "connected_edges": connected_edges,
        "connected_nodes": connected_node_list,
    }


@app.get("/api/edges")
async def get_edges(edge_type: Optional[str] = Query(None)):
    graph = load_json("sample_graph.json")
    edges = graph["edges"]
    if edge_type:
        edges = [e for e in edges if e["type"] == edge_type]
    return edges


@app.get("/api/paths")
async def get_paths():
    return load_json("sample_paths.json")


@app.get("/api/paths/{path_id}")
async def get_path(path_id: int):
    paths = load_json("sample_paths.json")
    path = next((p for p in paths if p["id"] == path_id), None)
    if not path:
        raise HTTPException(status_code=404, detail="Path not found")
    graph = load_json("sample_graph.json")
    path_nodes = []
    for nid in path["path"]:
        node = next((n for n in graph["nodes"] if n["id"] == nid), None)
        if node:
            path_nodes.append(node)
    return {**path, "node_details": path_nodes}


@app.get("/api/search")
async def search_nodes(q: str = Query(..., min_length=1)):
    graph = load_json("sample_graph.json")
    query_lower = q.lower()
    results = [
        n for n in graph["nodes"]
        if query_lower in n["name"].lower()
        or query_lower in n.get("properties", {}).get("display_name", "").lower()
        or query_lower in n.get("properties", {}).get("hostname", "").lower()
        or query_lower in n.get("properties", {}).get("ip", "").lower()
    ]
    return results


@app.get("/api/pathfind")
async def find_path(source: str = Query(...), target: str = Query(...)):
    graph = load_json("sample_graph.json")
    nodes = {n["id"]: n for n in graph["nodes"]}
    adj = {}
    for e in graph["edges"]:
        if e["source"] not in adj:
            adj[e["source"]] = []
        if e["target"] not in adj:
            adj[e["target"]] = []
        adj[e["source"]].append((e["target"], e["type"]))
        adj[e["target"]].append((e["source"], e["type"]))

    if source not in nodes or target not in nodes:
        raise HTTPException(status_code=404, detail="Source or target node not found")

    queue = [(source, [source], [])]
    visited = {source}

    while queue:
        current, path, edges_used = queue.pop(0)
        if current == target:
            path_nodes = [nodes[nid] for nid in path]
            risk = calculate_risk_score(path_nodes, edges_used)
            return {
                "found": True,
                "path": path,
                "edges": edges_used,
                "node_details": path_nodes,
                "risk_score": risk,
                "hops": len(path) - 1,
            }
        for neighbor, edge_type in adj.get(current, []):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, path + [neighbor], edges_used + [edge_type]))

    return {"found": False, "path": [], "edges": [], "risk_score": 0, "hops": 0}


def calculate_risk_score(path_nodes, edges):
    score = 50
    node_types = [n["type"] for n in path_nodes]
    if "domain" in node_types:
        score += 20
    admin_count = sum(1 for n in path_nodes if n.get("properties", {}).get("admin_count", 0) > 0)
    score += admin_count * 5
    high_priv = ["DCSync", "GenericAll", "AdminTo"]
    for e in edges:
        if e in high_priv:
            score += 10
    score += len(path_nodes) * 2
    return min(score, 100)


@app.get("/api/stats")
async def get_stats():
    graph = load_json("sample_graph.json")
    paths = load_json("sample_paths.json")
    node_types = {}
    edge_types = {}
    for n in graph["nodes"]:
        t = n["type"]
        node_types[t] = node_types.get(t, 0) + 1
    for e in graph["edges"]:
        t = e["type"]
        edge_types[t] = edge_types.get(t, 0) + 1
    return {
        "total_nodes": len(graph["nodes"]),
        "total_edges": len(graph["edges"]),
        "node_types": node_types,
        "edge_types": edge_types,
        "pre_computed_paths": len(paths),
        "avg_risk_score": round(sum(p["risk_score"] for p in paths) / len(paths)) if paths else 0,
    }


@app.get("/api/report")
async def generate_report():
    graph = load_json("sample_graph.json")
    paths = load_json("sample_paths.json")

    node_types = {}
    edge_types = {}
    for n in graph["nodes"]:
        t = n["type"]
        node_types[t] = node_types.get(t, 0) + 1
    for e in graph["edges"]:
        t = e["type"]
        edge_types[t] = edge_types.get(t, 0) + 1

    paths_sorted = sorted(paths, key=lambda x: x["risk_score"], reverse=True)

    high_risk_nodes = set()
    for p in paths:
        if p["risk_score"] >= 85:
            for nid in p["path"]:
                high_risk_nodes.add(nid)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Attack Path Analysis Report</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ font-size: 2.2em; margin-bottom: 8px; color: #ff4444; }}
h2 {{ color: #58a6ff; margin: 25px 0 12px; border-bottom: 1px solid #21262d; padding-bottom: 6px; }}
.subtitle {{ color: #8b949e; margin-bottom: 30px; }}
.stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 30px; }}
.stat-card {{ background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 16px; text-align: center; }}
.stat-value {{ font-size: 2em; font-weight: bold; color: #ff4444; }}
.stat-label {{ color: #8b949e; font-size: 0.85em; margin-top: 4px; }}
table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #21262d; }}
th {{ background: #161b22; color: #58a6ff; font-size: 0.85em; letter-spacing: 0.5px; }}
tr:hover {{ background: rgba(88,166,255,0.05); }}
.risk-high {{ color: #ff4444; font-weight: bold; }}
.risk-medium {{ color: #f0883e; font-weight: bold; }}
.risk-low {{ color: #3fb950; font-weight: bold; }}
.node-type {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }}
.type-user {{ background: rgba(56,139,253,0.2); color: #58a6ff; }}
.type-group {{ background: rgba(255,68,68,0.2); color: #ff4444; }}
.type-computer {{ background: rgba(63,185,80,0.2); color: #3fb950; }}
.type-domain {{ background: rgba(240,136,62,0.2); color: #f0883e; }}
.edge-type {{ color: #8b949e; font-size: 0.85em; }}
.path-chain {{ display: flex; align-items: center; flex-wrap: wrap; gap: 4px; margin: 8px 0; }}
.path-node {{ background: #161b22; border: 1px solid #21262d; padding: 3px 8px; border-radius: 4px; font-size: 0.8em; }}
.path-arrow {{ color: #58a6ff; font-size: 0.8em; }}
.recommendations {{ background: #161b22; border-left: 3px solid #ff4444; padding: 15px; border-radius: 0 8px 8px 0; margin: 15px 0; }}
.recommendations li {{ margin: 6px 0; margin-left: 20px; }}
.footer {{ text-align: center; margin-top: 30px; color: #484f58; border-top: 1px solid #21262d; padding-top: 15px; }}
</style>
</head>
<body>
<div class="container">
<h1>Attack Path Analysis Report</h1>
<p class="subtitle">Active Directory Security Assessment - Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<div class="stats-grid">
<div class="stat-card"><div class="stat-value">{len(graph['nodes'])}</div><div class="stat-label">Total Nodes</div></div>
<div class="stat-card"><div class="stat-value">{len(graph['edges'])}</div><div class="stat-label">Total Edges</div></div>
<div class="stat-card"><div class="stat-value">{len(paths)}</div><div class="stat-label">Attack Paths</div></div>
<div class="stat-card"><div class="stat-value">{round(sum(p['risk_score'] for p in paths) / len(paths))}</div><div class="stat-label">Avg Risk Score</div></div>
<div class="stat-card"><div class="stat-value">{len([p for p in paths if p['risk_score'] >= 85])}</div><div class="stat-label">Critical Paths</div></div>
<div class="stat-card"><div class="stat-value">{len(high_risk_nodes)}</div><div class="stat-label">High-Risk Nodes</div></div>
</div>

<div class="section">
<h2>Network Overview</h2>
<table>
<thead><tr><th>Node Type</th><th>Count</th></tr></thead>
<tbody>
"""
    for ntype, count in sorted(node_types.items()):
        html += f'<tr><td><span class="node-type type-{ntype}">{ntype.upper()}</span></td><td>{count}</td></tr>\n'

    html += """</tbody></table>
<h2>Edge Types</h2>
<table>
<thead><tr><th>Edge Type</th><th>Count</th></tr></thead>
<tbody>
"""
    for etype, count in sorted(edge_types.items(), key=lambda x: -x[1]):
        html += f'<tr><td class="edge-type">{etype}</td><td>{count}</td></tr>\n'

    html += """</tbody></table></div>

<div class="section">
<h2>Attack Paths (Ranked by Risk)</h2>
<table>
<thead><tr><th>#</th><th>Path Name</th><th>Hops</th><th>Risk</th><th>Description</th></tr></thead>
<tbody>
"""
    for i, p in enumerate(paths_sorted):
        risk_class = "risk-high" if p["risk_score"] >= 85 else "risk-medium" if p["risk_score"] >= 70 else "risk-low"
        html += f'<tr><td>{i+1}</td><td>{p["name"]}</td><td>{len(p["path"])-1}</td><td class="{risk_class}">{p["risk_score"]}/100</td><td style="font-size:0.85em">{p["description"]}</td></tr>\n'

    html += """</tbody></table></div>

<div class="section">
<h2>Detailed Path Breakdown</h2>
"""
    for p in paths_sorted:
        risk_class = "risk-high" if p["risk_score"] >= 85 else "risk-medium" if p["risk_score"] >= 70 else "risk-low"
        html += f"""<div style="margin-bottom:20px;padding:15px;background:#161b22;border-radius:8px;border-left:3px solid {'#ff4444' if p['risk_score']>=85 else '#f0883e' if p['risk_score']>=70 else '#3fb950'}">
<h3 style="color:#c9d1d9;margin-bottom:8px">{p['name']} <span class="{risk_class}">[{p['risk_score']}/100]</span></h3>
<div class="path-chain">
"""
        graph = load_json("sample_graph.json")
        nodes_map = {n["id"]: n for n in graph["nodes"]}
        for j, nid in enumerate(p["path"]):
            node = nodes_map.get(nid, {})
            ntype = node.get("type", "unknown")
            html += f'<span class="path-node"><span class="node-type type-{ntype}">{ntype}</span> {node.get("name", nid)}</span>'
            if j < len(p["path"]) - 1:
                edge_type = p["edges"][j] if j < len(p["edges"]) else "?"
                html += f'<span class="path-arrow">--{edge_type}--></span>'
        html += f"""</div>
<p style="color:#8b949e;font-size:0.9em;margin-top:8px">{p['description']}</p>
</div>"""

    html += """
<div class="recommendations">
<h2 style="color:#ff4444;margin-bottom:10px;border:none">Recommendations</h2>
<ul>
<li>Implement least privilege access - remove unnecessary admin rights</li>
<li>Audit service accounts and enforce strong password policies</li>
<li>Monitor DCSync privileges - restrict to dedicated Domain Admin accounts only</li>
<li>Implement tiered administration model for admin accounts</li>
<li>Deploy LAPS for local administrator password management</li>
<li>Enable advanced audit policies for privileged group changes</li>
<li>Regular access reviews for IT-Admins and Domain Admins groups</li>
<li>Network segmentation to limit lateral movement between VLANs</li>
</ul>
</div>

<div class="footer">
<p>Attack Path Analysis Report | 3D Network Visualizer | Generated with BloodHound-style analysis</p>
</div>
</div>
</body></html>"""

    report_path = REPORTS_DIR / "attack_path_report.html"
    with open(report_path, "w") as f:
        f.write(html)

    return HTMLResponse(content=html, headers={
        "Content-Disposition": f'attachment; filename="attack_path_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html"'
    })


@app.get("/api/report/download")
async def download_report():
    report_path = REPORTS_DIR / "attack_path_report.html"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="No report available. Generate one first.")
    return FileResponse(str(report_path), filename="attack_path_report.html", media_type="text/html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
