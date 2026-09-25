from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import json
import os
from pathlib import Path

app = FastAPI(title="WebXR Security Awareness Training Module", version="1.0.0")

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

class ModuleComplete(BaseModel):
    module_id: str
    quiz_score: int
    time_spent_minutes: int

class EmployeeCreate(BaseModel):
    name: str
    department: str

@app.get("/", response_class=HTMLResponse)
async def root():
    index_path = BASE_DIR / "static" / "index.html"
    if index_path.exists():
        return FileResponse(index_path, media_type="text/html")
    return HTMLResponse("<h1>WebXR Security Awareness Training Module</h1>")

@app.get("/api/modules")
async def get_modules():
    data = load_json("sample_modules.json")
    return {"modules": data.get("modules", [])}

@app.get("/api/modules/{module_id}")
async def get_module(module_id: str):
    data = load_json("sample_modules.json")
    modules = data.get("modules", [])
    module = next((m for m in modules if m["id"] == module_id), None)
    if not module:
        raise HTTPException(status_code=404, detail="Module not found")
    return module

@app.get("/api/progress")
async def get_all_progress():
    data = load_json("sample_progress.json")
    employees = data.get("employees", [])
    
    total_employees = len(employees)
    completed_all = sum(1 for e in employees if len(e.get("modules_completed", [])) == 5)
    in_progress = total_employees - completed_all
    
    all_scores = []
    for emp in employees:
        all_scores.extend(emp.get("quiz_scores", {}).values())
    
    avg_score = sum(all_scores) / len(all_scores) if all_scores else 0
    certificates = sum(1 for e in employees if e.get("certificate_earned"))
    
    return {
        "total_employees": total_employees,
        "completed_all_modules": completed_all,
        "in_progress": in_progress,
        "average_quiz_score": round(avg_score, 1),
        "certificates_earned": certificates,
        "completion_rate": round((completed_all / total_employees * 100) if total_employees > 0 else 0, 1)
    }

@app.get("/api/progress/{employee_id}")
async def get_employee_progress(employee_id: str):
    data = load_json("sample_progress.json")
    employees = data.get("employees", [])
    employee = next((e for e in employees if e["id"] == employee_id), None)
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    return employee

@app.get("/api/progress/list")
async def list_employees(limit: int = 20, offset: int = 0):
    data = load_json("sample_progress.json")
    employees = data.get("employees", [])
    return {
        "employees": employees[offset:offset + limit],
        "total": len(employees)
    }

@app.post("/api/progress/{employee_id}/complete")
async def complete_module(employee_id: str, completion: ModuleComplete):
    data = load_json("sample_progress.json")
    employees = data.get("employees", [])
    emp_idx = next((i for i, e in enumerate(employees) if e["id"] == employee_id), None)
    
    if emp_idx is None:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    employee = employees[emp_idx]
    
    if completion.module_id not in employee.get("modules_completed", []):
        employee.setdefault("modules_completed", []).append(completion.module_id)
    
    employee.setdefault("quiz_scores", {})[completion.module_id] = completion.quiz_score
    employee["last_activity"] = datetime.utcnow().isoformat() + "Z"
    employee["total_training_minutes"] = employee.get("total_training_minutes", 0) + completion.time_spent_minutes
    
    if len(employee.get("modules_completed", [])) >= 5:
        all_scores = list(employee.get("quiz_scores", {}).values())
        if all(score >= 70 for score in all_scores):
            employee["certificate_earned"] = True
    
    employees[emp_idx] = employee
    data["employees"] = employees
    save_json("sample_progress.json", data)
    
    return employee

@app.post("/api/employees")
async def create_employee(employee: EmployeeCreate):
    data = load_json("sample_progress.json")
    employees = data.get("employees", [])
    
    new_employee = {
        "id": f"emp_{len(employees) + 1:03d}",
        "name": employee.name,
        "department": employee.department,
        "modules_completed": [],
        "quiz_scores": {},
        "last_activity": datetime.utcnow().isoformat() + "Z",
        "total_training_minutes": 0,
        "certificate_earned": False
    }
    
    employees.append(new_employee)
    data["employees"] = employees
    save_json("sample_progress.json", data)
    
    return new_employee

@app.get("/api/reports/compliance")
async def generate_compliance_report():
    data = load_json("sample_progress.json")
    employees = data.get("employees", [])
    modules_data = load_json("sample_modules.json")
    modules = modules_data.get("modules", [])
    
    total_employees = len(employees)
    completed_all = sum(1 for e in employees if len(e.get("modules_completed", [])) == 5)
    compliance_rate = round((completed_all / total_employees * 100) if total_employees > 0 else 0, 1)
    
    department_stats = {}
    for emp in employees:
        dept = emp.get("department", "Unknown")
        if dept not in department_stats:
            department_stats[dept] = {"total": 0, "completed": 0, "avg_score": 0, "scores": []}
        department_stats[dept]["total"] += 1
        if len(emp.get("modules_completed", [])) == 5:
            department_stats[dept]["completed"] += 1
        scores = list(emp.get("quiz_scores", {}).values())
        department_stats[dept]["scores"].extend(scores)
    
    for dept in department_stats:
        scores = department_stats[dept]["scores"]
        department_stats[dept]["avg_score"] = round(sum(scores) / len(scores), 1) if scores else 0
        department_stats[dept]["completion_rate"] = round(
            (department_stats[dept]["completed"] / department_stats[dept]["total"] * 100) 
            if department_stats[dept]["total"] > 0 else 0, 1
        )
        del department_stats[dept]["scores"]
    
    module_stats = {}
    for module in modules:
        module_id = module["id"]
        completed_by = sum(1 for e in employees if module_id in e.get("modules_completed", []))
        scores = [e.get("quiz_scores", {}).get(module_id, 0) for e in employees if module_id in e.get("quiz_scores", {})]
        module_stats[module_id] = {
            "title": module["title"],
            "completed_by": completed_by,
            "completion_rate": round((completed_by / total_employees * 100) if total_employees > 0 else 0, 1),
            "avg_score": round(sum(scores) / len(scores), 1) if scores else 0
        }
    
    dept_rows = ""
    for dept, stats in sorted(department_stats.items()):
        dept_rows += f"""
        <tr>
            <td>{dept}</td>
            <td>{stats['total']}</td>
            <td>{stats['completed']}</td>
            <td>{stats['completion_rate']}%</td>
            <td>{stats['avg_score']}%</td>
        </tr>
        """
    
    module_rows = ""
    for module_id, stats in module_stats.items():
        module_rows += f"""
        <tr>
            <td>{stats['title']}</td>
            <td>{stats['completed_by']}/{total_employees}</td>
            <td>{stats['completion_rate']}%</td>
            <td>{stats['avg_score']}%</td>
        </tr>
        """
    
    employee_rows = ""
    for emp in employees:
        completed = len(emp.get("modules_completed", []))
        avg_score = round(sum(emp.get("quiz_scores", {}).values()) / len(emp.get("quiz_scores", {})), 1) if emp.get("quiz_scores") else 0
        status = "Complete" if emp.get("certificate_earned") else f"{completed}/5 Modules"
        employee_rows += f"""
        <tr>
            <td>{emp['name']}</td>
            <td>{emp.get('department', 'N/A')}</td>
            <td>{completed}/5</td>
            <td>{avg_score}%</td>
            <td>{status}</td>
            <td>{'Yes' if emp.get('certificate_earned') else 'No'}</td>
        </tr>
        """
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Training Compliance Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f7fa; color: #333; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 40px; padding-bottom: 20px; border-bottom: 3px solid #0066cc; }}
        .header h1 {{ color: #0066cc; font-size: 32px; margin-bottom: 10px; }}
        .header p {{ color: #666; font-size: 14px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 40px; }}
        .stat-box {{ background: linear-gradient(135deg, #0066cc 0%, #004499 100%); padding: 25px; border-radius: 12px; text-align: center; color: #fff; }}
        .stat-box h3 {{ font-size: 36px; margin-bottom: 8px; }}
        .stat-box p {{ font-size: 12px; text-transform: uppercase; letter-spacing: 1px; opacity: 0.9; }}
        .section {{ margin: 30px 0; }}
        .section h2 {{ color: #0066cc; font-size: 22px; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #e0e0e0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 14px 16px; text-align: left; border-bottom: 1px solid #e0e0e0; }}
        th {{ background: #f8f9fa; color: #0066cc; font-weight: 600; text-transform: uppercase; font-size: 12px; letter-spacing: 0.5px; }}
        tr:hover {{ background: #f8f9fa; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }}
        .badge-success {{ background: #d4edda; color: #155724; }}
        .badge-warning {{ background: #fff3cd; color: #856404; }}
        .badge-danger {{ background: #f8d7da; color: #721c24; }}
        .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 2px solid #e0e0e0; color: #999; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Awareness Training Compliance Report</h1>
            <p>Generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
        </div>
        
        <div class="summary">
            <div class="stat-box">
                <h3>{total_employees}</h3>
                <p>Total Employees</p>
            </div>
            <div class="stat-box">
                <h3>{completed_all}</h3>
                <p>Completed All Modules</p>
            </div>
            <div class="stat-box">
                <h3>{compliance_rate}%</h3>
                <p>Compliance Rate</p>
            </div>
            <div class="stat-box">
                <h3>{sum(1 for e in employees if e.get('certificate_earned'))}</h3>
                <p>Certificates Earned</p>
            </div>
        </div>
        
        <div class="section">
            <h2>Department Compliance</h2>
            <table>
                <thead>
                    <tr>
                        <th>Department</th>
                        <th>Total Employees</th>
                        <th>Completed</th>
                        <th>Completion Rate</th>
                        <th>Average Score</th>
                    </tr>
                </thead>
                <tbody>
                    {dept_rows}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Module Statistics</h2>
            <table>
                <thead>
                    <tr>
                        <th>Module</th>
                        <th>Completed By</th>
                        <th>Completion Rate</th>
                        <th>Average Score</th>
                    </tr>
                </thead>
                <tbody>
                    {module_rows}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Employee Progress</h2>
            <table>
                <thead>
                    <tr>
                        <th>Employee</th>
                        <th>Department</th>
                        <th>Modules</th>
                        <th>Avg Score</th>
                        <th>Status</th>
                        <th>Certificate</th>
                    </tr>
                </thead>
                <tbody>
                    {employee_rows}
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>WebXR Security Awareness Training Module | Confidential</p>
        </div>
    </div>
</body>
</html>"""
    
    report_filename = f"compliance_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
    report_path = REPORTS_DIR / report_filename
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    return HTMLResponse(content=html_content, media_type="text/html")

@app.get("/api/reports/{employee_id}")
async def generate_employee_report(employee_id: str):
    data = load_json("sample_progress.json")
    employees = data.get("employees", [])
    employee = next((e for e in employees if e["id"] == employee_id), None)
    
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    modules_data = load_json("sample_modules.json")
    modules = modules_data.get("modules", [])
    
    completed = len(employee.get("modules_completed", []))
    avg_score = round(sum(employee.get("quiz_scores", {}).values()) / len(employee.get("quiz_scores", {})), 1) if employee.get("quiz_scores") else 0
    
    module_rows = ""
    for module in modules:
        module_id = module["id"]
        status = "Completed" if module_id in employee.get("modules_completed", []) else "Not Started"
        score = employee.get("quiz_scores", {}).get(module_id, "N/A")
        module_rows += f"""
        <tr>
            <td>{module['title']}</td>
            <td>{module['category']}</td>
            <td>{status}</td>
            <td>{score if score != 'N/A' else '-'}</td>
        </tr>
        """
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Employee Training Report - {employee['name']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f7fa; color: #333; padding: 20px; }}
        .container {{ max-width: 900px; margin: 0 auto; background: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 40px; padding-bottom: 20px; border-bottom: 3px solid #0066cc; }}
        .header h1 {{ color: #0066cc; font-size: 28px; margin-bottom: 10px; }}
        .header p {{ color: #666; font-size: 14px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin-bottom: 40px; }}
        .stat-box {{ background: linear-gradient(135deg, #0066cc 0%, #004499 100%); padding: 20px; border-radius: 12px; text-align: center; color: #fff; }}
        .stat-box h3 {{ font-size: 32px; margin-bottom: 5px; }}
        .stat-box p {{ font-size: 11px; text-transform: uppercase; letter-spacing: 1px; opacity: 0.9; }}
        .section {{ margin: 30px 0; }}
        .section h2 {{ color: #0066cc; font-size: 20px; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #e0e0e0; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #e0e0e0; }}
        th {{ background: #f8f9fa; color: #0066cc; font-weight: 600; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }}
        .badge-success {{ background: #d4edda; color: #155724; }}
        .badge-warning {{ background: #fff3cd; color: #856404; }}
        .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 2px solid #e0e0e0; color: #999; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Employee Training Report</h1>
            <p>{employee['name']} | {employee.get('department', 'N/A')}</p>
        </div>
        
        <div class="summary">
            <div class="stat-box">
                <h3>{completed}/5</h3>
                <p>Modules Completed</p>
            </div>
            <div class="stat-box">
                <h3>{avg_score}%</h3>
                <p>Average Score</p>
            </div>
            <div class="stat-box">
                <h3>{employee.get('total_training_minutes', 0)}</h3>
                <p>Training Minutes</p>
            </div>
            <div class="stat-box">
                <h3>{'Yes' if employee.get('certificate_earned') else 'No'}</h3>
                <p>Certificate</p>
            </div>
        </div>
        
        <div class="section">
            <h2>Module Progress</h2>
            <table>
                <thead>
                    <tr>
                        <th>Module</th>
                        <th>Category</th>
                        <th>Status</th>
                        <th>Score</th>
                    </tr>
                </thead>
                <tbody>
                    {module_rows}
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC | WebXR Security Awareness Training</p>
        </div>
    </div>
</body>
</html>"""
    
    return HTMLResponse(content=html_content, media_type="text/html")

@app.get("/api/certificates/{employee_id}")
async def generate_certificate(employee_id: str):
    data = load_json("sample_progress.json")
    employees = data.get("employees", [])
    employee = next((e for e in employees if e["id"] == employee_id), None)
    
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    if not employee.get("certificate_earned"):
        raise HTTPException(status_code=400, detail="Employee has not earned certificate")
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Certificate - {employee['name']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Georgia', serif; 
            background: #f5f5f5; 
            display: flex; 
            justify-content: center; 
            align-items: center; 
            min-height: 100vh;
            padding: 20px;
        }}
        .certificate {{
            width: 800px;
            height: 600px;
            background: linear-gradient(135deg, #fff 0%, #f8f9fa 100%);
            border: 8px double #0066cc;
            border-radius: 8px;
            padding: 60px;
            text-align: center;
            position: relative;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }}
        .certificate::before {{
            content: '';
            position: absolute;
            top: 20px;
            left: 20px;
            right: 20px;
            bottom: 20px;
            border: 2px solid #c0c0c0;
            border-radius: 4px;
        }}
        .logo {{ font-size: 24px; color: #0066cc; font-weight: bold; margin-bottom: 20px; }}
        .title {{ font-size: 36px; color: #0066cc; margin-bottom: 30px; text-transform: uppercase; letter-spacing: 3px; }}
        .subtitle {{ font-size: 18px; color: #666; margin-bottom: 40px; }}
        .name {{ font-size: 42px; color: #333; margin-bottom: 20px; font-style: italic; }}
        .course {{ font-size: 20px; color: #0066cc; margin-bottom: 40px; }}
        .date {{ font-size: 16px; color: #666; margin-bottom: 40px; }}
        .signature {{ font-size: 14px; color: #999; margin-top: 40px; }}
        .seal {{ 
            position: absolute;
            bottom: 40px;
            right: 60px;
            width: 100px;
            height: 100px;
            background: #0066cc;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
            font-size: 12px;
            font-weight: bold;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="certificate">
        <div class="logo">SECURITY TRAINING INSTITUTE</div>
        <div class="title">Certificate of Completion</div>
        <div class="subtitle">This certifies that</div>
        <div class="name">{employee['name']}</div>
        <div class="course">has successfully completed all 5 modules of the<br>WebXR Security Awareness Training Program</div>
        <div class="date">Awarded on {datetime.utcnow().strftime('%B %d, %Y')}</div>
        <div class="signature">_____________________________<br>Training Director</div>
        <div class="seal">CERTIFIED<br>COMPLETE</div>
    </div>
</body>
</html>"""
    
    return HTMLResponse(content=html_content, media_type="text/html")

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
