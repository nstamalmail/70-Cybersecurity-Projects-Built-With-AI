import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="3D CTF Scoreboard", version="1.0.0")

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
    filepath = DATA_DIR / filename
    with open(filepath, "r") as f:
        return json.load(f)


@app.get("/", response_class=HTMLResponse)
async def root():
    html_path = BASE_DIR / "static" / "index.html"
    with open(html_path, "r") as f:
        return HTMLResponse(content=f.read())


@app.get("/api/teams")
async def get_teams():
    return load_json("sample_teams.json")


@app.get("/api/teams/{team_id}")
async def get_team(team_id: int):
    teams = load_json("sample_teams.json")
    team = next((t for t in teams if t["id"] == team_id), None)
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    solves = load_json("sample_solves.json")
    team_solves = [s for s in solves if s["team_id"] == team_id]
    challenges = load_json("sample_challenges.json")
    solved_challenge_ids = {s["challenge_id"] for s in team_solves}
    solved_challenges = [c for c in challenges if c["id"] in solved_challenge_ids]
    category_breakdown = {}
    for s in team_solves:
        ch = next((c for c in challenges if c["id"] == s["challenge_id"]), None)
        if ch:
            cat = ch["category"]
            category_breakdown[cat] = category_breakdown.get(cat, 0) + s["points"]
    return {
        **team,
        "solves": team_solves,
        "solved_challenges": solved_challenges,
        "category_breakdown": category_breakdown,
        "solve_count": len(team_solves),
    }


@app.get("/api/challenges")
async def get_challenges(category: Optional[str] = Query(None)):
    challenges = load_json("sample_challenges.json")
    if category:
        challenges = [c for c in challenges if c["category"] == category]
    return challenges


@app.get("/api/challenges/{challenge_id}")
async def get_challenge(challenge_id: int):
    challenges = load_json("sample_challenges.json")
    challenge = next((c for c in challenges if c["id"] == challenge_id), None)
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    solves = load_json("sample_solves.json")
    challenge_solves = [s for s in solves if s["challenge_id"] == challenge_id]
    teams = load_json("sample_teams.json")
    solvers = []
    for s in challenge_solves:
        team = next((t for t in teams if t["id"] == s["team_id"]), None)
        if team:
            solvers.append({"team_name": team["name"], "timestamp": s["timestamp"]})
    return {**challenge, "solvers": solvers}


@app.get("/api/solves")
async def get_solves(
    team_id: Optional[int] = Query(None),
    challenge_id: Optional[int] = Query(None),
    limit: int = Query(100),
):
    solves = load_json("sample_solves.json")
    if team_id:
        solves = [s for s in solves if s["team_id"] == team_id]
    if challenge_id:
        solves = [s for s in solves if s["challenge_id"] == challenge_id]
    solves.sort(key=lambda x: x["timestamp"])
    return solves[-limit:]


@app.get("/api/solves/feed")
async def get_solve_feed(limit: int = Query(20)):
    solves = load_json("sample_solves.json")
    teams = load_json("sample_teams.json")
    challenges = load_json("sample_challenges.json")
    solves.sort(key=lambda x: x["timestamp"], reverse=True)
    feed = []
    for s in solves[:limit]:
        team = next((t for t in teams if t["id"] == s["team_id"]), None)
        challenge = next((c for c in challenges if c["id"] == s["challenge_id"]), None)
        if team and challenge:
            feed.append({
                "id": s["id"],
                "team_name": team["name"],
                "team_id": team["id"],
                "challenge_name": challenge["name"],
                "challenge_id": challenge["id"],
                "category": challenge["category"],
                "points": s["points"],
                "timestamp": s["timestamp"],
            })
    return feed


@app.get("/api/leaderboard")
async def get_leaderboard():
    teams = load_json("sample_teams.json")
    solves = load_json("sample_solves.json")
    challenges = load_json("sample_challenges.json")
    leaderboard = []
    for team in teams:
        team_solves = [s for s in solves if s["team_id"] == team["id"]]
        category_scores = {}
        for s in team_solves:
            ch = next((c for c in challenges if c["id"] == s["challenge_id"]), None)
            if ch:
                cat = ch["category"]
                category_scores[cat] = category_scores.get(cat, 0) + s["points"]
        leaderboard.append({
            **team,
            "solve_count": len(team_solves),
            "category_scores": category_scores,
        })
    leaderboard.sort(key=lambda x: x["total_score"], reverse=True)
    for i, entry in enumerate(leaderboard):
        entry["rank"] = i + 1
    return leaderboard


@app.get("/api/scoreboard/timeline")
async def get_scoreboard_timeline():
    solves = load_json("sample_solves.json")
    teams = load_json("sample_teams.json")
    solves.sort(key=lambda x: x["timestamp"])
    timeline = []
    cumulative_scores = {t["id"]: 0 for t in teams}
    for s in solves:
        cumulative_scores[s["team_id"]] += s["points"]
        scores_snapshot = dict(cumulative_scores)
        timeline.append({
            "timestamp": s["timestamp"],
            "solve_id": s["id"],
            "team_id": s["team_id"],
            "challenge_id": s["challenge_id"],
            "points": s["points"],
            "scores_after": scores_snapshot,
        })
    return timeline


@app.get("/api/stats")
async def get_stats():
    teams = load_json("sample_teams.json")
    challenges = load_json("sample_challenges.json")
    solves = load_json("sample_solves.json")
    categories = {}
    for c in challenges:
        cat = c["category"]
        if cat not in categories:
            categories[cat] = {"count": 0, "total_points": 0, "total_solves": 0}
        categories[cat]["count"] += 1
        categories[cat]["total_points"] += c["points"]
        cat_solves = [s for s in solves if s["challenge_id"] == c["id"]]
        categories[cat]["total_solves"] += len(cat_solves)
    return {
        "total_teams": len(teams),
        "total_challenges": len(challenges),
        "total_solves": len(solves),
        "categories": categories,
        "total_points_possible": sum(c["points"] for c in challenges),
        "avg_solves_per_challenge": round(len(solves) / len(challenges), 1),
    }


@app.get("/api/report")
async def generate_report(format: str = Query("html")):
    teams = load_json("sample_teams.json")
    challenges = load_json("sample_challenges.json")
    solves = load_json("sample_solves.json")

    teams.sort(key=lambda x: x["total_score"], reverse=True)
    for i, t in enumerate(teams):
        t["rank"] = i + 1

    categories = {}
    for c in challenges:
        cat = c["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(c)

    solve_timeline = sorted(solves, key=lambda x: x["timestamp"])
    top_solves = []
    for s in solve_timeline[-20:]:
        team = next((t for t in teams if t["id"] == s["team_id"]), None)
        ch = next((c for c in challenges if c["id"] == s["challenge_id"]), None)
        if team and ch:
            top_solves.append({
                "team": team["name"],
                "challenge": ch["name"],
                "category": ch["category"],
                "points": s["points"],
                "time": s["timestamp"],
            })

    cat_stats = {}
    for cat, chals in categories.items():
        cat_solves = [s for s in solves if any(c["id"] == s["challenge_id"] for c in chals)]
        cat_stats[cat] = {
            "count": len(chals),
            "total_points": sum(c["points"] for c in chals),
            "solve_count": len(cat_solves),
            "avg_difficulty": round(sum(c["points"] for c in chals) / len(chals)),
        }

    podium = teams[:3] if len(teams) >= 3 else teams

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CTF Competition Report</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0a1a; color: #e0e0e0; padding: 20px; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ text-align: center; font-size: 2.5em; margin-bottom: 10px; background: linear-gradient(135deg, #00ff88, #00ccff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
.subtitle {{ text-align: center; color: #888; margin-bottom: 40px; font-size: 1.1em; }}
.podium {{ display: flex; justify-content: center; align-items: flex-end; gap: 20px; margin-bottom: 40px; }}
.podium-place {{ text-align: center; padding: 20px; border-radius: 10px; background: rgba(255,255,255,0.05); }}
.podium-place.first {{ order: 2; border: 2px solid #ffd700; transform: scale(1.1); }}
.podium-place.second {{ order: 1; border: 2px solid #c0c0c0; }}
.podium-place.third {{ order: 3; border: 2px solid #cd7f32; }}
.podium-rank {{ font-size: 2em; font-weight: bold; }}
.podium-name {{ font-size: 1.3em; margin: 5px 0; color: #fff; }}
.podium-score {{ font-size: 1.1em; color: #00ff88; }}
.section {{ margin-bottom: 30px; background: rgba(255,255,255,0.03); border-radius: 10px; padding: 20px; }}
.section h2 {{ color: #00ccff; margin-bottom: 15px; border-bottom: 1px solid rgba(0,204,255,0.3); padding-bottom: 8px; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 10px 15px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1); }}
th {{ background: rgba(0,204,255,0.1); color: #00ccff; }}
tr:hover {{ background: rgba(0,255,136,0.05); }}
.rank-1 {{ color: #ffd700; font-weight: bold; }}
.rank-2 {{ color: #c0c0c0; font-weight: bold; }}
.rank-3 {{ color: #cd7f32; font-weight: bold; }}
.category-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }}
.cat-web {{ background: rgba(0,150,255,0.3); color: #4db8ff; }}
.cat-crypto {{ background: rgba(255,165,0,0.3); color: #ffaa44; }}
.cat-forensics {{ background: rgba(0,255,136,0.3); color: #00ff88; }}
.cat-reversing {{ background: rgba(200,100,255,0.3); color: #cc88ff; }}
.cat-pwn {{ background: rgba(255,50,50,0.3); color: #ff6666; }}
.stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
.stat-card {{ background: rgba(0,204,255,0.1); border-radius: 8px; padding: 15px; text-align: center; }}
.stat-value {{ font-size: 2em; font-weight: bold; color: #00ff88; }}
.stat-label {{ color: #aaa; font-size: 0.9em; }}
.footer {{ text-align: center; margin-top: 40px; color: #666; font-size: 0.9em; padding: 20px; border-top: 1px solid rgba(255,255,255,0.1); }}
</style>
</head>
<body>
<div class="container">
<h1>CTF Competition Report</h1>
<p class="subtitle">Competition Results &amp; Analytics</p>

<div class="stats-grid">
<div class="stat-card"><div class="stat-value">{len(teams)}</div><div class="stat-label">Teams</div></div>
<div class="stat-card"><div class="stat-value">{len(challenges)}</div><div class="stat-label">Challenges</div></div>
<div class="stat-card"><div class="stat-value">{len(solves)}</div><div class="stat-label">Total Solves</div></div>
<div class="stat-card"><div class="stat-value">{sum(c['points'] for c in challenges)}</div><div class="stat-label">Total Points</div></div>
</div>

<div class="section">
<h2>Podium</h2>
<div class="podium">
<div class="podium-place second">
<div class="podium-rank" style="color:#c0c0c0">2nd</div>
<div class="podium-name">{podium[1]['name']}</div>
<div class="podium-score">{podium[1]['total_score']} pts</div>
<div style="color:#888;font-size:0.85em">{podium[1]['affiliation']}</div>
</div>
<div class="podium-place first">
<div class="podium-rank" style="color:#ffd700">1st</div>
<div class="podium-name">{podium[0]['name']}</div>
<div class="podium-score">{podium[0]['total_score']} pts</div>
<div style="color:#888;font-size:0.85em">{podium[0]['affiliation']}</div>
</div>
<div class="podium-place third">
<div class="podium-rank" style="color:#cd7f32">3rd</div>
<div class="podium-name">{podium[2]['name']}</div>
<div class="podium-score">{podium[2]['total_score']} pts</div>
<div style="color:#888;font-size:0.85em">{podium[2]['affiliation']}</div>
</div>
</div>
</div>

<div class="section">
<h2>Full Rankings</h2>
<table>
<thead><tr><th>Rank</th><th>Team</th><th>Affiliation</th><th>Solves</th><th>Score</th></tr></thead>
<tbody>
"""

    for t in teams:
        rank_class = f"rank-{t['rank']}" if t['rank'] <= 3 else ""
        html += f'<tr><td class="{rank_class}">#{t["rank"]}</td><td>{t["name"]}</td><td>{t["affiliation"]}</td><td>{t.get("solve_count", 0)}</td><td>{t["total_score"]}</td></tr>\n'

    html += """</tbody></table></div>

<div class="section">
<h2>Challenge Statistics by Category</h2>
<table>
<thead><tr><th>Category</th><th>Challenges</th><th>Total Points</th><th>Solves</th><th>Avg Points</th></tr></thead>
<tbody>
"""

    for cat, stats in cat_stats.items():
        html += f'<tr><td><span class="category-badge cat-{cat}">{cat.upper()}</span></td><td>{stats["count"]}</td><td>{stats["total_points"]}</td><td>{stats["solve_count"]}</td><td>{stats["avg_difficulty"]}</td></tr>\n'

    html += """</tbody></table></div>

<div class="section">
<h2>Recent Solves</h2>
<table>
<thead><tr><th>Time</th><th>Team</th><th>Challenge</th><th>Category</th><th>Points</th></tr></thead>
<tbody>
"""

    for s in top_solves:
        html += f'<tr><td>{s["time"]}</td><td>{s["team"]}</td><td>{s["challenge"]}</td><td><span class="category-badge cat-{s["category"]}">{s["category"].upper()}</span></td><td>{s["points"]}</td></tr>\n'

    html += f"""</tbody></table></div>

<div class="footer">
<p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 3D CTF Scoreboard System</p>
</div>
</div>
</body></html>"""

    report_path = REPORTS_DIR / "ctf_report.html"
    with open(report_path, "w") as f:
        f.write(html)

    return HTMLResponse(content=html, headers={
        "Content-Disposition": f'attachment; filename="ctf_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html"'
    })


@app.get("/api/report/download")
async def download_report():
    report_path = REPORTS_DIR / "ctf_report.html"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="No report available. Generate one first via /api/report")
    return FileResponse(str(report_path), filename="ctf_report.html", media_type="text/html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
