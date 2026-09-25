from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import httpx
import asyncio
from contextlib import asynccontextmanager
from dotenv import load_dotenv

load_dotenv()

MISP_URL = os.getenv("MISP_URL", "https://localhost")
MISP_KEY = os.getenv("MISP_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")

threat_cache = {"misp": [], "otx": [], "last_updated": None}

@asynccontextmanager
async def lifespan(app: FastAPI):
    asyncio.create_task(periodic_threat_feed_update())
    yield

app = FastAPI(title="3D Incident Response Training Platform", version="2.0.0", lifespan=lifespan)

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

def load_json(filename: str) -> dict:
    filepath = DATA_DIR / filename
    if filepath.exists():
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_json(filename: str, data: dict):
    filepath = DATA_DIR / filename
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

async def fetch_misp_events(limit: int = 50) -> List[Dict]:
    if not MISP_KEY:
        return load_json("misp_sample_events.json").get("events", [])[:limit]
    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            headers = {"Authorization": MISP_KEY, "Accept": "application/json", "Content-Type": "application/json"}
            resp = await client.get(f"{MISP_URL}/events", headers=headers, params={"limit": limit, "enforceWarninglist": True})
            resp.raise_for_status()
            data = resp.json()
            events = []
            for event in data.get("response", []):
                e = event.get("Event", event)
                events.append({
                    "id": e.get("id"),
                    "info": e.get("info", ""),
                    "date": e.get("date", ""),
                    "threat_level_id": e.get("threat_level_id"),
                    "analysis": e.get("analysis"),
                    "timestamp": e.get("timestamp"),
                    "tag": [t.get("name", "") for t in e.get("Tag", [])],
                    "attribute_count": len(e.get("Attribute", [])),
                    "source": "MISP"
                })
            return events
    except Exception as e:
        print(f"MISP fetch error: {e}")
        return load_json("misp_sample_events.json").get("events", [])[:limit]

async def fetch_otx_pulses(limit: int = 50) -> List[Dict]:
    if not OTX_API_KEY:
        return load_json("otx_sample_pulses.json").get("pulses", [])[:limit]
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            headers = {"X-OTX-API-KEY": OTX_API_KEY, "Accept": "application/json"}
            resp = await client.get("https://otx.alienvault.com/api/v1/pulses/subscribed", headers=headers, params={"limit": limit, "modified_since": (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()})
            resp.raise_for_status()
            data = resp.json()
            pulses = []
            for p in data.get("results", []):
                pulses.append({
                    "id": p.get("id"),
                    "name": p.get("name", ""),
                    "description": p.get("description", "")[:200],
                    "created": p.get("created", ""),
                    "modified": p.get("modified", ""),
                    "tags": p.get("tags", []),
                    "adversary": p.get("adversary", ""),
                    "malware_families": [m.get("name", "") for m in p.get("malware", [])],
                    "industries": p.get("industries", []),
                    "references": p.get("references", []),
                    "indicators_count": len(p.get("indicators", [])),
                    "source": "OTX"
                })
            return pulses
    except Exception as e:
        print(f"OTX fetch error: {e}")
        return load_json("otx_sample_pulses.json").get("pulses", [])[:limit]

async def periodic_threat_feed_update():
    while True:
        try:
            threat_cache["misp"] = await fetch_misp_events()
            threat_cache["otx"] = await fetch_otx_pulses()
            threat_cache["last_updated"] = datetime.now(timezone.utc).isoformat()
            save_json("live_threats.json", threat_cache)
        except Exception as e:
            print(f"Feed update error: {e}")
        await asyncio.sleep(300)

class SessionCreate(BaseModel):
    scenario_id: str
    trainee: str
    department: str

class DecisionRecord(BaseModel):
    decision_point: str
    chosen: str

class ProgressUpdate(BaseModel):
    session_id: str
    evidence_collected: List[str] = []
    rooms_visited: List[str] = []

@app.get("/", response_class=HTMLResponse)
async def root():
    index_path = BASE_DIR / "static" / "index.html"
    if index_path.exists():
        return FileResponse(index_path, media_type="text/html")
    return HTMLResponse("<h1>3D Incident Response Training Platform</h1>")

@app.get("/api/scenarios")
async def get_scenarios():
    data = load_json("sample_scenarios.json")
    return {"scenarios": data.get("scenarios", [])}

@app.get("/api/scenarios/{scenario_id}")
async def get_scenario(scenario_id: str):
    data = load_json("sample_scenarios.json")
    scenarios = data.get("scenarios", [])
    scenario = next((s for s in scenarios if s["id"] == scenario_id), None)
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return scenario

@app.get("/api/threats")
async def get_threats(source: Optional[str] = None, refresh: bool = False):
    if refresh or not threat_cache["last_updated"]:
        threat_cache["misp"] = await fetch_misp_events()
        threat_cache["otx"] = await fetch_otx_pulses()
        threat_cache["last_updated"] = datetime.now(timezone.utc).isoformat()
    threats = []
    if source is None or source.lower() == "misp":
        threats.extend(threat_cache["misp"])
    if source is None or source.lower() == "otx":
        threats.extend(threat_cache["otx"])
    return {"threats": threats, "count": len(threats), "last_updated": threat_cache["last_updated"], "sources": {"misp": len(threat_cache["misp"]), "otx": len(threat_cache["otx"])}}

@app.get("/api/threats/misp")
async def get_misp_events(refresh: bool = False):
    if refresh or not threat_cache["misp"]:
        threat_cache["misp"] = await fetch_misp_events()
    return {"events": threat_cache["misp"], "count": len(threat_cache["misp"])}

@app.get("/api/threats/otx")
async def get_otx_pulses(refresh: bool = False):
    if refresh or not threat_cache["otx"]:
        threat_cache["otx"] = await fetch_otx_pulses()
    return {"pulses": threat_cache["otx"], "count": len(threat_cache["otx"])}

@app.get("/api/threats/stats")
async def get_threat_stats():
    misp = threat_cache["misp"]
    otx = threat_cache["otx"]
    all_threats = misp + otx
    industries = {}
    for t in otx:
        for ind in t.get("industries", []):
            industries[ind] = industries.get(ind, 0) + 1
    return {
        "total_threats": len(all_threats),
        "misp_events": len(misp),
        "otx_pulses": len(otx),
        "top_industries": sorted(industries.items(), key=lambda x: x[1], reverse=True)[:10],
        "last_updated": threat_cache["last_updated"]
    }

@app.post("/api/sessions")
async def create_session(session: SessionCreate):
    data = load_json("sample_scenarios.json")
    scenarios = data.get("scenarios", [])
    scenario = next((s for s in scenarios if s["id"] == session.scenario_id), None)
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")
    
    sessions_data = load_json("sample_sessions.json")
    sessions = sessions_data.get("sessions", [])
    
    new_session = {
        "id": f"session_{len(sessions) + 1:03d}",
        "scenario_id": session.scenario_id,
        "trainee": session.trainee,
        "department": session.department,
        "start_time": datetime.now(timezone.utc).isoformat() + "Z",
        "end_time": None,
        "completion_time_seconds": 0,
        "status": "in_progress",
        "score": 0,
        "max_score": 100,
        "decisions": [],
        "evidence_collected": [],
        "rooms_visited": [],
        "completed": False
    }
    
    sessions.append(new_session)
    sessions_data["sessions"] = sessions
    save_json("sample_sessions.json", sessions_data)
    
    return new_session

@app.get("/api/sessions")
async def get_sessions(limit: int = 20, offset: int = 0):
    data = load_json("sample_sessions.json")
    sessions = data.get("sessions", [])
    return {
        "sessions": sessions[offset:offset + limit],
        "total": len(sessions)
    }

@app.get("/api/sessions/{session_id}")
async def get_session(session_id: str):
    data = load_json("sample_sessions.json")
    sessions = data.get("sessions", [])
    session = next((s for s in sessions if s["id"] == session_id), None)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session

@app.post("/api/sessions/{session_id}/decisions")
async def record_decision(session_id: str, decision: DecisionRecord):
    data = load_json("sample_sessions.json")
    sessions = data.get("sessions", [])
    session_idx = next((i for i, s in enumerate(sessions) if s["id"] == session_id), None)
    
    if session_idx is None:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = sessions[session_idx]
    
    scenario_data = load_json("sample_scenarios.json")
    scenarios = scenario_data.get("scenarios", [])
    scenario = next((s for s in scenarios if s["id"] == session["scenario_id"]), None)
    
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")
    
    score = 0
    feedback = ""
    for room in scenario.get("rooms", []):
        for dp in room.get("decision_points", []):
            if dp["id"] == decision.decision_point:
                for opt in dp["options"]:
                    if opt["id"] == decision.chosen:
                        score = opt["score"]
                        feedback = opt["feedback"]
                        break
    
    decision_record = {
        "decision_point": decision.decision_point,
        "chosen": decision.chosen,
        "score": score,
        "feedback": feedback,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z"
    }
    
    session["decisions"].append(decision_record)
    session["score"] = sum(d["score"] for d in session["decisions"])
    sessions[session_idx] = session
    
    data["sessions"] = sessions
    save_json("sample_sessions.json", data)
    
    return {"decision": decision_record, "total_score": session["score"]}

@app.put("/api/sessions/{session_id}/progress")
async def update_progress(session_id: str, progress: ProgressUpdate):
    data = load_json("sample_sessions.json")
    sessions = data.get("sessions", [])
    session_idx = next((i for i, s in enumerate(sessions) if s["id"] == session_id), None)
    
    if session_idx is None:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = sessions[session_idx]
    
    for evidence in progress.evidence_collected:
        if evidence not in session["evidence_collected"]:
            session["evidence_collected"].append(evidence)
    
    for room in progress.rooms_visited:
        if room not in session["rooms_visited"]:
            session["rooms_visited"].append(room)
    
    sessions[session_idx] = session
    data["sessions"] = sessions
    save_json("sample_sessions.json", data)
    
    return session

@app.post("/api/sessions/{session_id}/complete")
async def complete_session(session_id: str):
    data = load_json("sample_sessions.json")
    sessions = data.get("sessions", [])
    session_idx = next((i for i, s in enumerate(sessions) if s["id"] == session_id), None)
    
    if session_idx is None:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = sessions[session_idx]
    session["end_time"] = datetime.now(timezone.utc).isoformat() + "Z"
    session["status"] = "completed"
    session["completed"] = True
    
    if session["start_time"]:
        start = datetime.fromisoformat(session["start_time"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(session["end_time"].replace("Z", "+00:00"))
        session["completion_time_seconds"] = int((end - start).total_seconds())
    
    sessions[session_idx] = session
    data["sessions"] = sessions
    save_json("sample_sessions.json", data)
    
    return session

@app.get("/api/progress")
async def get_progress():
    data = load_json("sample_sessions.json")
    sessions = data.get("sessions", [])
    
    completed = [s for s in sessions if s.get("completed")]
    in_progress = [s for s in sessions if not s.get("completed")]
    
    scores = [s["score"] for s in completed]
    avg_score = sum(scores) / len(scores) if scores else 0
    
    return {
        "total_sessions": len(sessions),
        "completed": len(completed),
        "in_progress": len(in_progress),
        "average_score": round(avg_score, 1),
        "high_score": max(scores) if scores else 0,
        "low_score": min(scores) if scores else 0
    }

@app.get("/api/reports/{session_id}")
async def generate_report(session_id: str):
    data = load_json("sample_sessions.json")
    sessions = data.get("sessions", [])
    session = next((s for s in sessions if s["id"] == session_id), None)
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    scenario_data = load_json("sample_scenarios.json")
    scenarios = scenario_data.get("scenarios", [])
    scenario = next((s for s in scenarios if s["id"] == session["scenario_id"]), None)
    
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")
    
    score_percentage = (session["score"] / scenario.get("completion_criteria", {}).get("minimum_score", 100)) * 100 if scenario.get("completion_criteria", {}).get("minimum_score", 100) > 0 else 0
    passed = session["score"] >= scenario.get("completion_criteria", {}).get("minimum_score", 100)
    
    decisions_html = ""
    for decision in session.get("decisions", []):
        decisions_html += f"""
        <tr>
            <td>{decision['decision_point'].replace('_', ' ').title()}</td>
            <td>{decision['chosen'].upper()}</td>
            <td>{decision['score']}/10</td>
            <td>{decision.get('feedback', 'N/A')}</td>
        </tr>
        """
    
    evidence_html = ""
    for evidence in session.get("evidence_collected", []):
        evidence_html += f"<li>{evidence.replace('_', ' ').title()}</li>"
    
    rooms_html = ""
    for room in session.get("rooms_visited", []):
        rooms_html += f"<li>{room.replace('_', ' ').title()}</li>"
    
    minutes = session.get("completion_time_seconds", 0) // 60
    seconds = session.get("completion_time_seconds", 0) % 60
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Training Report - {session_id}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a2e; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 900px; margin: 0 auto; background: #16213e; padding: 40px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
        .header {{ text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 2px solid #0f3460; }}
        .header h1 {{ color: #00d9ff; font-size: 28px; margin-bottom: 10px; }}
        .header p {{ color: #888; font-size: 14px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-box {{ background: #0f3460; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-box h3 {{ color: #00d9ff; font-size: 32px; margin-bottom: 5px; }}
        .stat-box p {{ color: #888; font-size: 12px; text-transform: uppercase; }}
        .passed {{ color: #00ff88; }}
        .failed {{ color: #ff4444; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #0f3460; }}
        th {{ background: #0f3460; color: #00d9ff; font-weight: 600; }}
        tr:hover {{ background: rgba(0, 217, 255, 0.05); }}
        .section {{ margin: 30px 0; }}
        .section h2 {{ color: #00d9ff; font-size: 20px; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 1px solid #0f3460; }}
        ul {{ list-style: none; padding: 0; }}
        ul li {{ padding: 8px 0; border-bottom: 1px solid #0f3460; }}
        ul li:before {{ content: "•"; color: #00d9ff; margin-right: 10px; }}
        .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 2px solid #0f3460; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Cybersecurity Training Report</h1>
            <p>Incident Response Scenario Completion Certificate</p>
        </div>
        
        <div class="summary">
            <div class="stat-box">
                <h3>{session['score']}/100</h3>
                <p>Total Score</p>
            </div>
            <div class="stat-box">
                <h3 class="{'passed' if passed else 'failed'}">{'PASSED' if passed else 'FAILED'}</h3>
                <p>Status</p>
            </div>
            <div class="stat-box">
                <h3>{minutes}m {seconds}s</h3>
                <p>Completion Time</p>
            </div>
            <div class="stat-box">
                <h3>{len(session.get('evidence_collected', []))}</h3>
                <p>Evidence Found</p>
            </div>
        </div>
        
        <div class="section">
            <h2>Trainee Information</h2>
            <table>
                <tr><td><strong>Name:</strong></td><td>{session['trainee']}</td></tr>
                <tr><td><strong>Department:</strong></td><td>{session['department']}</td></tr>
                <tr><td><strong>Scenario:</strong></td><td>{scenario['title']}</td></tr>
                <tr><td><strong>Date:</strong></td><td>{session['start_time'][:10]}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Decision Breakdown</h2>
            <table>
                <thead>
                    <tr>
                        <th>Decision Point</th>
                        <th>Choice</th>
                        <th>Score</th>
                        <th>Feedback</th>
                    </tr>
                </thead>
                <tbody>
                    {decisions_html}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Evidence Collected</h2>
            <ul>{evidence_html if evidence_html else '<li>No evidence collected</li>'}</ul>
        </div>
        
        <div class="section">
            <h2>Rooms Visited</h2>
            <ul>{rooms_html if rooms_html else '<li>No rooms visited</li>'}</ul>
        </div>
        
        <div class="footer">
            <p>Generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC | 3D Incident Response Training Platform</p>
            <p>This report is for training purposes only.</p>
        </div>
    </div>
</body>
</html>"""
    
    report_filename = f"report_{session_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.html"
    report_path = REPORTS_DIR / report_filename
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    return HTMLResponse(content=html_content, media_type="text/html")

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
