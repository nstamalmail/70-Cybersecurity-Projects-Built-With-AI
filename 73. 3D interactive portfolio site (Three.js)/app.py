import os
import json
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, HTTPException, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="3D Portfolio Backend", version="1.0.0")

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
    filepath = os.path.join(DATA_DIR, filename)
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(filename: str, data):
    filepath = os.path.join(DATA_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


class ContactForm(BaseModel):
    name: str
    email: str
    subject: str
    message: str


class ProjectUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    tech_stack: Optional[list] = None
    category: Optional[str] = None


@app.get("/", response_class=HTMLResponse)
async def root():
    return FileResponse(os.path.join(BASE_DIR, "static", "index.html"))


@app.get("/api/projects")
async def get_projects():
    return load_json("sample_projects.json")


@app.get("/api/projects/{project_id}")
async def get_project(project_id: int):
    projects = load_json("sample_projects.json")
    for p in projects:
        if p["id"] == project_id:
            return p
    raise HTTPException(status_code=404, detail="Project not found")


@app.post("/api/projects")
async def create_project(
    title: str = Form(...),
    description: str = Form(...),
    tech_stack: str = Form(...),
    category: str = Form("General"),
    link: str = Form(""),
):
    projects = load_json("sample_projects.json")
    new_id = max(p["id"] for p in projects) + 1 if projects else 1
    new_project = {
        "id": new_id,
        "title": title,
        "description": description,
        "tech_stack": [t.strip() for t in tech_stack.split(",")],
        "image": "default.png",
        "category": category,
        "year": datetime.now().year,
        "link": link,
        "featured": False,
    }
    projects.append(new_project)
    save_json("sample_projects.json", projects)
    return new_project


@app.put("/api/projects/{project_id}")
async def update_project(project_id: int, update: ProjectUpdate):
    projects = load_json("sample_projects.json")
    for p in projects:
        if p["id"] == project_id:
            if update.title is not None:
                p["title"] = update.title
            if update.description is not None:
                p["description"] = update.description
            if update.tech_stack is not None:
                p["tech_stack"] = update.tech_stack
            if update.category is not None:
                p["category"] = update.category
            save_json("sample_projects.json", projects)
            return p
    raise HTTPException(status_code=404, detail="Project not found")


@app.delete("/api/projects/{project_id}")
async def delete_project(project_id: int):
    projects = load_json("sample_projects.json")
    projects = [p for p in projects if p["id"] != project_id]
    save_json("sample_projects.json", projects)
    return {"message": "Project deleted"}


@app.get("/api/analytics")
async def get_analytics():
    return load_json("sample_analytics.json")


@app.post("/api/contact")
async def contact_form(form: ContactForm):
    contacts_file = os.path.join(DATA_DIR, "contacts.json")
    contacts = []
    if os.path.exists(contacts_file):
        with open(contacts_file, "r", encoding="utf-8") as f:
            contacts = json.load(f)
    entry = {
        "id": len(contacts) + 1,
        "name": form.name,
        "email": form.email,
        "subject": form.subject,
        "message": form.message,
        "timestamp": datetime.now().isoformat(),
        "read": False,
    }
    contacts.append(entry)
    with open(contacts_file, "w", encoding="utf-8") as f:
        json.dump(contacts, f, indent=2, ensure_ascii=False)
    return {"message": "Contact form submitted successfully", "id": entry["id"]}


@app.get("/api/report/portfolio")
async def generate_portfolio_report():
    projects = load_json("sample_projects.json")
    analytics = load_json("sample_analytics.json")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    featured = [p for p in projects if p.get("featured")]
    categories = {}
    for p in projects:
        cat = p.get("category", "General")
        categories[cat] = categories.get(cat, 0) + 1

    all_tech = []
    for p in projects:
        all_tech.extend(p.get("tech_stack", []))
    tech_counts = {}
    for t in all_tech:
        tech_counts[t] = tech_counts.get(t, 0) + 1
    top_tech = sorted(tech_counts.items(), key=lambda x: -x[1])[:10]

    projects_html = ""
    for p in projects:
        tech_badges = "".join(
            f'<span class="badge">{t}</span>' for t in p.get("tech_stack", [])
        )
        featured_class = "featured" if p.get("featured") else ""
        projects_html += f"""
        <div class="project-card {featured_class}">
            <h3>{p['title']}</h3>
            <p class="category">{p.get('category', 'General')} &bull; {p.get('year', '')}</p>
            <p>{p['description']}</p>
            <div class="tech-stack">{tech_badges}</div>
        </div>
        """

    source_rows = ""
    for s in analytics.get("visitor_sources", []):
        source_rows += f"<tr><td>{s['source']}</td><td>{s['count']}</td><td>{s['percentage']}%</td></tr>"

    tech_chart_data = json.dumps([t[0] for t in top_tech])
    tech_chart_values = json.dumps([t[1] for t in top_tech])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Portfolio Report - {timestamp}</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; background: #0a0a0f; color: #e0e0e0; }}
h1 {{ color: #64ffda; border-bottom: 2px solid #64ffda; padding-bottom: 10px; }}
h2 {{ color: #8892b0; margin-top: 30px; }}
.stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
.stat-card {{ background: #1a1a2e; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #2a2a4a; }}
.stat-card .value {{ font-size: 28px; font-weight: bold; color: #64ffda; }}
.stat-card .label {{ font-size: 12px; color: #8892b0; margin-top: 5px; }}
.project-card {{ background: #1a1a2e; padding: 20px; margin: 15px 0; border-radius: 8px; border-left: 4px solid #64ffda; }}
.project-card.featured {{ border-left-color: #ffd700; }}
.project-card h3 {{ margin: 0 0 8px 0; color: #ccd6f6; }}
.project-card .category {{ color: #64ffda; font-size: 13px; margin: 0 0 8px 0; }}
.project-card p {{ margin: 5px 0; color: #8892b0; font-size: 14px; }}
.tech-stack {{ margin-top: 10px; }}
.badge {{ display: inline-block; background: #233554; color: #64ffda; padding: 3px 10px; border-radius: 12px; font-size: 12px; margin: 3px 4px 3px 0; }}
table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
th, td {{ padding: 10px 15px; text-align: left; border-bottom: 1px solid #2a2a4a; }}
th {{ background: #1a1a2e; color: #64ffda; }}
footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #2a2a4a; color: #8892b0; font-size: 12px; text-align: center; }}
</style>
</head>
<body>
<h1>Portfolio Analytics Report</h1>
<p style="color:#8892b0">Generated: {timestamp}</p>

<h2>Overview</h2>
<div class="stats-grid">
    <div class="stat-card"><div class="value">{analytics['total_visitors']:,}</div><div class="label">Total Visitors</div></div>
    <div class="stat-card"><div class="value">{analytics['unique_visitors']:,}</div><div class="label">Unique Visitors</div></div>
    <div class="stat-card"><div class="value">{analytics['page_views']:,}</div><div class="label">Page Views</div></div>
    <div class="stat-card"><div class="value">{analytics['bounce_rate']}%</div><div class="label">Bounce Rate</div></div>
</div>

<h2>Traffic Sources</h2>
<table>
<tr><th>Source</th><th>Visits</th><th>Share</th></tr>
{source_rows}
</table>

<h2>Projects ({len(projects)} total, {len(featured)} featured)</h2>
<div class="categories">
{''.join(f'<span class="badge">{cat}: {cnt}</span>' for cat, cnt in categories.items())}
</div>
{projects_html}

<h2>Top Technologies</h2>
<table>
<tr><th>Technology</th><th>Projects Using It</th></tr>
{''.join(f"<tr><td>{t}</td><td>{c}</td></tr>" for t, c in top_tech)}
</table>

<footer>3D Portfolio Report &bull; {timestamp}</footer>
</body>
</html>"""

    report_path = os.path.join(REPORTS_DIR, f"portfolio_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    return HTMLResponse(content=html, headers={
        "Content-Disposition": f'attachment; filename="portfolio_report.html"'
    })


app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
