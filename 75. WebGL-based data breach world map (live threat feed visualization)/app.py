from fastapi import FastAPI, Query, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, date, timedelta
import json
import os
import socket
import httpx
import asyncio
from pathlib import Path
import uuid
from collections import defaultdict

app = FastAPI(title="Data Breach World Map API - Live Threat Intelligence")

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
CACHE_DIR = BASE_DIR / "cache"
REPORTS_DIR.mkdir(exist_ok=True)
CACHE_DIR.mkdir(exist_ok=True)

live_cache = {
    "breaches": [],
    "threats": [],
    "last_updated": None,
    "sources": [],
    "source_details": {}
}


def load_json(filename: str) -> list:
    filepath = DATA_DIR / filename
    if filepath.exists():
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def save_cache():
    cache_file = CACHE_DIR / "live_data.json"
    with open(cache_file, "w", encoding="utf-8") as f:
        json.dump(live_cache, f, indent=2, ensure_ascii=False)


def load_cache():
    cache_file = CACHE_DIR / "live_data.json"
    if cache_file.exists():
        with open(cache_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            live_cache.update(data)


COUNTRY_COORDS = {
    "US": {"lat": 39.8283, "lng": -98.5795}, "CN": {"lat": 35.8617, "lng": 104.1954},
    "RU": {"lat": 61.5240, "lng": 105.3188}, "DE": {"lat": 51.1657, "lng": 10.4515},
    "NL": {"lat": 52.1326, "lng": 5.2913}, "GB": {"lat": 55.3781, "lng": -3.4360},
    "FR": {"lat": 46.2276, "lng": 2.2137}, "BR": {"lat": -14.2350, "lng": -51.9253},
    "IN": {"lat": 20.5937, "lng": 78.9629}, "JP": {"lat": 36.2048, "lng": 138.2529},
    "KR": {"lat": 35.9078, "lng": 127.7669}, "AU": {"lat": -25.2744, "lng": 133.7751},
    "CA": {"lat": 56.1304, "lng": -106.3468}, "PL": {"lat": 51.9194, "lng": 19.1451},
    "UA": {"lat": 48.3794, "lng": 31.1656}, "IR": {"lat": 32.4279, "lng": 53.6880},
    "VN": {"lat": 14.0583, "lng": 108.2772}, "ID": {"lat": -0.7893, "lng": 113.9213},
    "TH": {"lat": 15.8700, "lng": 100.9925}, "MY": {"lat": 4.2105, "lng": 101.9758},
    "SG": {"lat": 1.3521, "lng": 103.8198}, "ZA": {"lat": -30.5595, "lng": 22.9375},
    "NG": {"lat": 9.0820, "lng": 8.6753}, "EG": {"lat": 26.8206, "lng": 30.8025},
    "SA": {"lat": 23.8859, "lng": 45.0792}, "AE": {"lat": 23.4241, "lng": 53.8478},
    "IL": {"lat": 31.0461, "lng": 34.8516}, "TR": {"lat": 38.9637, "lng": 35.2433},
    "IT": {"lat": 41.8719, "lng": 12.5674}, "ES": {"lat": 40.4637, "lng": -3.7492},
    "SE": {"lat": 60.1282, "lng": 18.6435}, "NO": {"lat": 60.4720, "lng": 8.4689},
    "FI": {"lat": 61.9241, "lng": 25.7482}, "DK": {"lat": 56.2639, "lng": 9.5018},
    "CH": {"lat": 46.8182, "lng": 8.2275}, "AT": {"lat": 47.5162, "lng": 14.5501},
    "BE": {"lat": 50.5039, "lng": 4.4699}, "CZ": {"lat": 49.8175, "lng": 15.4730},
    "RO": {"lat": 45.9432, "lng": 24.9668}, "BG": {"lat": 42.7339, "lng": 25.4858},
    "GR": {"lat": 39.0742, "lng": 21.8243}, "PT": {"lat": 39.3999, "lng": -8.2245},
    "IE": {"lat": 53.1424, "lng": -7.6921}, "NZ": {"lat": -40.9006, "lng": 174.8860},
    "PH": {"lat": 12.8797, "lng": 121.7740}, "BD": {"lat": 23.6850, "lng": 90.3563},
    "PK": {"lat": 30.3753, "lng": 69.3451},
}


async def fetch_cisa_kev():
    """Fetch CISA Known Exploited Vulnerabilities catalog"""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                vendor_locations = {
                    "Microsoft": {"lat": 47.6062, "lng": -122.3321, "country": "USA"},
                    "Google": {"lat": 37.4220, "lng": -122.0841, "country": "USA"},
                    "Apple": {"lat": 37.3861, "lng": -122.0839, "country": "USA"},
                    "Adobe": {"lat": 37.3915, "lng": -121.9616, "country": "USA"},
                    "Cisco": {"lat": 37.3893, "lng": -121.9777, "country": "USA"},
                    "Fortinet": {"lat": 37.3875, "lng": -122.0880, "country": "USA"},
                    "Citrix": {"lat": 33.7490, "lng": -84.3880, "country": "USA"},
                    "VMware": {"lat": 37.4220, "lng": -122.0841, "country": "USA"},
                    "SAP": {"lat": 50.9430, "lng": 6.9430, "country": "Germany"},
                    "Oracle": {"lat": 37.5062, "lng": -121.9617, "country": "USA"},
                    "Atlassian": {"lat": -33.8688, "lng": 151.2093, "country": "Australia"},
                }
                
                breaches = []
                for i, vuln in enumerate(vulnerabilities[:100]):
                    vendor = vuln.get("vendorProject", "Unknown")
                    location = vendor_locations.get(vendor, {"lat": 40.7128, "lng": -74.0060, "country": "USA"})
                    
                    days_old = (datetime.now() - datetime.strptime(vuln.get("dateAdded", "2024-01-01"), "%Y-%m-%d")).days
                    if days_old < 30:
                        severity = "critical"
                    elif days_old < 90:
                        severity = "high"
                    elif days_old < 180:
                        severity = "medium"
                    else:
                        severity = "low"
                    
                    breaches.append({
                        "id": 1000 + i,
                        "name": f"CVE-{vuln.get('cveID', 'UNKNOWN')}",
                        "severity": severity,
                        "records": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                        "date": vuln.get("dateAdded", "2024-01-01"),
                        "source": vendor,
                        "description": vuln.get("shortDescription", "No description available"),
                        "lat": location["lat"] + (i % 5 - 2) * 0.5,
                        "lng": location["lng"] + (i % 3 - 1) * 0.5,
                        "country": location["country"],
                        "cve": vuln.get("cveID"),
                        "action": vuln.get("action", "Apply updates"),
                        "dueDate": vuln.get("dueDate", "2024-01-01"),
                        "source_type": "CISA KEV"
                    })
                
                return breaches, f"CISA KEV ({len(breaches)} CVEs)"
    except Exception as e:
        print(f"Error fetching CISA KEV: {e}")
    return [], "CISA KEV (failed)"


async def fetch_urlhaus():
    """Fetch abuse.ch URLhaus - malware distribution URLs"""
    url = "https://urlhaus.abuse.ch/downloads/json_recent/"
    threats = []
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                
                for i, (entry_id, entries) in enumerate(data.items()):
                    if i >= 40:
                        break
                    for entry in entries[:1]:
                        cc = "US"
                        location = COUNTRY_COORDS.get(cc, {"lat": 0, "lng": 0})
                        
                        tags = entry.get("tags", [])
                        threat_type = "malware" if any(t in str(tags).lower() for t in ["malware", "exe", "elf"]) else "phishing"
                        
                        threats.append({
                            "id": 2000 + i,
                            "source_ip": entry.get("url", "unknown")[:50],
                            "source_country": cc,
                            "target_country": "US",
                            "attack_type": threat_type,
                            "severity": "high" if threat_type == "malware" else "medium",
                            "status": entry.get("url_status", "unknown"),
                            "timestamp": entry.get("dateadded", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                            "lat": location["lat"] + (i % 5 - 2) * 3,
                            "lng": location["lng"] + (i % 3 - 1) * 3,
                            "target_lat": 39.8283 + (i % 3 - 1),
                            "target_lng": -98.5795 + (i % 5 - 2),
                            "source_type": "Abuse.ch URLhaus",
                            "tags": tags
                        })
    except Exception as e:
        print(f"Error fetching URLhaus: {e}")
    
    return threats, f"Abuse.ch URLhaus ({len(threats)} URLs)"


async def fetch_otx_alienvault():
    """Fetch OTX AlienVault - public pulses"""
    url = "https://otx.alienvault.com/otxapi/pulses?sort=-created&limit=20"
    threats = []
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                pulses = data.get("results", [])
                
                for i, pulse in enumerate(pulses):
                    indicators = pulse.get("indicators", [])
                    for j, indicator in enumerate(indicators[:5]):
                        ind_type = indicator.get("type", "")
                        ind_value = indicator.get("indicator", "")
                        
                        if ind_type in ["IPv4", "domain", "hostname", "URL"]:
                            cc = indicator.get("country", "US") or "US"
                            location = COUNTRY_COORDS.get(cc, {"lat": 0, "lng": 0})
                            
                            threats.append({
                                "id": 3000 + i * 10 + j,
                                "source_ip": ind_value[:50],
                                "source_country": cc,
                                "target_country": "US",
                                "attack_type": pulse.get("name", "Unknown")[:30],
                                "severity": "high",
                                "status": "active",
                                "timestamp": pulse.get("created", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                                "lat": location["lat"] + (i % 5 - 2) * 2,
                                "lng": location["lng"] + (i % 3 - 1) * 2,
                                "target_lat": 39.8283,
                                "target_lng": -98.5795,
                                "source_type": "OTX AlienVault",
                                "pulse_name": pulse.get("name", "Unknown"),
                                "indicator_type": ind_type
                            })
    except Exception as e:
        print(f"Error fetching OTX: {e}")
    
    return threats, f"OTX AlienVault ({len(threats)} indicators)"


async def fetch_cybercrime_tracker():
    """Fetch Cybercrime Tracker - C2 servers"""
    url = "https://cybercrime-tracker.net/all.json"
    threats = []
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                
                for i, entry in enumerate(data[:30]):
                    cc = entry.get("cc", "US")
                    location = COUNTRY_COORDS.get(cc, {"lat": 0, "lng": 0})
                    
                    threats.append({
                        "id": 4000 + i,
                        "source_ip": entry.get("ip", "unknown"),
                        "source_country": cc,
                        "target_country": "US",
                        "attack_type": entry.get("type", "c2"),
                        "severity": "critical",
                        "status": "active",
                        "timestamp": entry.get("date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                        "lat": location["lat"] + (i % 5 - 2) * 2,
                        "lng": location["lng"] + (i % 3 - 1) * 2,
                        "target_lat": 39.8283,
                        "target_lng": -98.5795,
                        "source_type": "Cybercrime Tracker",
                        "c2_domain": entry.get("domain", "")
                    })
    except Exception as e:
        print(f"Error fetching Cybercrime Tracker: {e}")
    
    return threats, f"Cybercrime Tracker ({len(threats)} C2 servers)"


async def fetch_inleak():
    """Fetch InLeak - data leak monitoring"""
    url = "https://inleak.com/api/v1/leaks/recent"
    threats = []
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                leaks = data.get("data", []) if isinstance(data, dict) else data
                
                for i, leak in enumerate(leaks[:20]):
                    cc = leak.get("country", "US")
                    location = COUNTRY_COORDS.get(cc, {"lat": 0, "lng": 0})
                    
                    threats.append({
                        "id": 5000 + i,
                        "source_ip": leak.get("domain", "unknown")[:50],
                        "source_country": cc,
                        "target_country": "US",
                        "attack_type": "data_leak",
                        "severity": "high",
                        "status": "active",
                        "timestamp": leak.get("date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                        "lat": location["lat"] + (i % 5 - 2) * 2,
                        "lng": location["lng"] + (i % 3 - 1) * 2,
                        "target_lat": 39.8283,
                        "target_lng": -98.5795,
                        "source_type": "InLeak",
                        "leak_type": leak.get("type", "unknown")
                    })
    except Exception as e:
        print(f"Error fetching InLeak: {e}")
    
    return threats, f"InLeak ({len(threats)} leaks)"


async def fetch_all_live_data():
    """Fetch from all sources concurrently"""
    tasks = [
        fetch_cisa_kev(),
        fetch_urlhaus(),
        fetch_otx_alienvault(),
        fetch_cybercrime_tracker(),
    ]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    all_breaches = []
    all_threats = []
    source_names = []
    source_details = {}
    
    for result in results:
        if isinstance(result, Exception):
            print(f"Error in fetch: {result}")
            continue
        
        data, status = result
        source_names.append(status)
        
        if "CISA" in status:
            all_breaches.extend(data)
            source_details["CISA KEV"] = {"count": len(data), "status": status}
        else:
            all_threats.extend(data)
            source_name = status.split(" (")[0]
            source_details[source_name] = {"count": len(data), "status": status}
    
    if not all_threats:
        all_threats = load_json("sample_threats.json")
    if not all_breaches:
        all_breaches = load_json("sample_breaches.json")
    
    live_cache["breaches"] = all_breaches
    live_cache["threats"] = all_threats
    live_cache["last_updated"] = datetime.now().isoformat()
    live_cache["sources"] = source_names
    live_cache["source_details"] = source_details
    
    save_cache()
    
    return {
        "breaches_count": len(all_breaches),
        "threats_count": len(all_threats),
        "sources": source_names,
        "source_details": source_details,
        "last_updated": live_cache["last_updated"]
    }


@app.on_event("startup")
async def startup_event():
    load_cache()
    # Load cached data immediately, fetch live in background
    if not live_cache.get("breaches"):
        live_cache["breaches"] = load_json("sample_breaches.json")
    if not live_cache.get("threats"):
        live_cache["threats"] = load_json("sample_threats.json")


@app.get("/", response_class=HTMLResponse)
async def root():
    html_path = BASE_DIR / "static" / "index.html"
    if html_path.exists():
        with open(html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Data Breach World Map</h1>")


@app.post("/api/live/refresh")
async def refresh_live_data():
    result = await fetch_all_live_data()
    return {"status": "refreshed", **result}


@app.get("/api/live/status")
async def live_status():
    return {
        "last_updated": live_cache.get("last_updated"),
        "sources": live_cache.get("sources", []),
        "source_details": live_cache.get("source_details", {}),
        "breaches_count": len(live_cache.get("breaches", [])),
        "threats_count": len(live_cache.get("threats", []))
    }


@app.get("/api/breaches")
async def get_breaches(
    severity: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    live: bool = Query(True)
):
    if live and live_cache.get("breaches"):
        breaches = live_cache["breaches"]
    else:
        breaches = load_json("sample_breaches.json")
    
    if severity:
        breaches = [b for b in breaches if b["severity"].lower() == severity.lower()]
    if source:
        breaches = [b for b in breaches if source.lower() in b.get("source", "").lower()]
    if start_date:
        breaches = [b for b in breaches if b.get("date", "") >= start_date]
    if end_date:
        breaches = [b for b in breaches if b.get("date", "") <= end_date]
    if region:
        region_filters = {
            "north_america": lambda b: 15 <= b.get("lat", 0) <= 72 and -170 <= b.get("lng", 0) <= -50,
            "south_america": lambda b: -60 <= b.get("lat", 0) <= 15 and -85 <= b.get("lng", 0) <= -30,
            "europe": lambda b: 35 <= b.get("lat", 0) <= 72 and -25 <= b.get("lng", 0) <= 45,
            "asia": lambda b: -10 <= b.get("lat", 0) <= 75 and 45 <= b.get("lng", 0) <= 180,
            "africa": lambda b: -35 <= b.get("lat", 0) <= 37 and -20 <= b.get("lng", 0) <= 55,
            "oceania": lambda b: -50 <= b.get("lat", 0) <= -10 and 110 <= b.get("lng", 0) <= 180
        }
        if region.lower() in region_filters:
            breaches = [b for b in breaches if region_filters[region.lower()](b)]
    
    return {"breaches": breaches, "total": len(breaches), "live": live_cache.get("last_updated") is not None}


@app.get("/api/breaches/{breach_id}")
async def get_breach(breach_id: int):
    all_breaches = live_cache.get("breaches", []) + load_json("sample_breaches.json")
    for breach in all_breaches:
        if breach.get("id") == breach_id:
            return breach
    raise HTTPException(status_code=404, detail="Breach not found")


@app.get("/api/threats")
async def get_threats(
    severity: Optional[str] = Query(None),
    attack_type: Optional[str] = Query(None),
    source_country: Optional[str] = Query(None),
    source_type: Optional[str] = Query(None),
    live: bool = Query(True)
):
    if live and live_cache.get("threats"):
        threats = live_cache["threats"]
    else:
        threats = load_json("sample_threats.json")
    
    if severity:
        threats = [t for t in threats if t["severity"].lower() == severity.lower()]
    if attack_type:
        threats = [t for t in threats if attack_type.lower() in t.get("attack_type", "").lower()]
    if source_country:
        threats = [t for t in threats if source_country.upper() in t.get("source_country", "").upper()]
    if source_type:
        threats = [t for t in threats if source_type.lower() in t.get("source_type", "").lower()]
    
    return {"threats": threats, "total": len(threats), "live": live_cache.get("last_updated") is not None}


@app.get("/api/stats")
async def get_statistics():
    breaches = live_cache.get("breaches", []) or load_json("sample_breaches.json")
    threats = live_cache.get("threats", []) or load_json("sample_threats.json")
    
    severity_counts = defaultdict(int)
    source_type_counts = defaultdict(int)
    country_counts = defaultdict(int)
    
    for b in breaches:
        severity_counts[b["severity"]] += 1
        country_counts[b.get("country", "Unknown")] += 1
    
    for t in threats:
        source_type_counts[t.get("source_type", "Unknown")] += 1
    
    return {
        "total_breaches": len(breaches),
        "total_threats": len(threats),
        "severity_breakdown": dict(severity_counts),
        "top_countries": dict(sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
        "source_type_breakdown": dict(source_type_counts),
        "live_data": live_cache.get("last_updated") is not None,
        "last_updated": live_cache.get("last_updated"),
        "data_sources": live_cache.get("sources", []),
        "source_details": live_cache.get("source_details", {})
    }


@app.get("/api/geographic_data")
async def get_geographic_data():
    breaches = live_cache.get("breaches", []) or load_json("sample_breaches.json")
    threats = live_cache.get("threats", []) or load_json("sample_threats.json")
    
    return {
        "breach_locations": [
            {
                "lat": b.get("lat", 0), "lng": b.get("lng", 0),
                "severity": b["severity"], "name": b.get("name", "Unknown"),
                "source": b.get("source", "Unknown"), "country": b.get("country", "Unknown"),
                "source_type": b.get("source_type", "Unknown")
            } for b in breaches
        ],
        "threat_arcs": [
            {
                "source": {"lat": t.get("lat", 0), "lng": t.get("lng", 0)},
                "target": {"lat": t.get("target_lat", 39.8283), "lng": t.get("target_lng", -98.5795)},
                "severity": t["severity"], "attack_type": t.get("attack_type", "unknown"),
                "source_type": t.get("source_type", "Unknown")
            } for t in threats
        ]
    }


class ReportRequest(BaseModel):
    title: Optional[str] = "Threat Intelligence Report"
    include_breaches: bool = True
    include_threats: bool = True
    severity_filter: Optional[str] = None


@app.post("/api/reports/generate")
async def generate_report(request: ReportRequest):
    breaches = live_cache.get("breaches", []) or load_json("sample_breaches.json")
    threats = live_cache.get("threats", []) or load_json("sample_threats.json")
    
    if request.severity_filter:
        breaches = [b for b in breaches if b["severity"] == request.severity_filter]
        threats = [t for t in threats if t["severity"] == request.severity_filter]
    
    severity_colors = {"critical": "#ff0040", "high": "#ff6600", "medium": "#ffcc00", "low": "#00cc44"}
    
    breach_rows = ""
    for b in breaches[:100]:
        color = severity_colors.get(b["severity"], "#999")
        breach_rows += f"""<tr>
            <td>{b.get('id', 'N/A')}</td><td>{b.get('name', 'Unknown')}</td>
            <td><span style="color:{color};font-weight:bold;">{b['severity'].upper()}</span></td>
            <td>{b.get('source', 'Unknown')}</td><td>{b.get('date', 'N/A')}</td>
            <td>{b.get('country', 'N/A')}</td><td>{b.get('source_type', 'N/A')}</td>
        </tr>"""
    
    threat_rows = ""
    for t in threats[:100]:
        color = severity_colors.get(t["severity"], "#999")
        threat_rows += f"""<tr>
            <td>{t.get('source_ip', 'N/A')[:30]}</td><td>{t.get('source_country', 'N/A')}</td>
            <td>{t.get('attack_type', 'N/A')}</td>
            <td><span style="color:{color};font-weight:bold;">{t['severity'].upper()}</span></td>
            <td>{t.get('source_type', 'N/A')}</td><td>{t.get('timestamp', 'N/A')}</td>
        </tr>"""
    
    severity_stats = defaultdict(int)
    source_type_stats = defaultdict(int)
    for b in breaches:
        severity_stats[b["severity"]] += 1
    for t in threats:
        source_type_stats[t.get("source_type", "Unknown")] += 1
    
    source_list = "\n".join([f"<li>{k}: {v['count']} items</li>" for k, v in live_cache.get("source_details", {}).items()])
    
    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{request.title}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #0a0e17; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        h1 {{ color: #00ff88; font-size: 2.5em; border-bottom: 2px solid #00ff88; padding-bottom: 10px; }}
        h2 {{ color: #00aaff; margin: 20px 0; }}
        .live-badge {{ background: #ff0040; color: white; padding: 5px 15px; border-radius: 20px; animation: pulse 2s infinite; }}
        @keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.5; }} }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: linear-gradient(135deg, #1a1f2e, #0d1117); border: 1px solid #30363d; border-radius: 10px; padding: 15px; text-align: center; }}
        .stat-value {{ font-size: 1.8em; font-weight: bold; color: #00ff88; }}
        .stat-label {{ color: #8b949e; margin-top: 5px; }}
        .sources-list {{ background: #161b22; border-radius: 10px; padding: 20px; margin: 20px 0; }}
        .sources-list ul {{ list-style: none; }}
        .sources-list li {{ padding: 8px 0; border-bottom: 1px solid #30363d; color: #00ff88; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; background: #161b22; border-radius: 8px; overflow: hidden; font-size: 0.9em; }}
        th {{ background: #21262d; color: #00ff88; padding: 10px; text-align: left; }}
        td {{ padding: 8px 10px; border-bottom: 1px solid #30363d; }}
        tr:hover {{ background: #1c2128; }}
        .charts-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0; }}
        .chart-container {{ background: #161b22; border-radius: 10px; padding: 20px; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #30363d; color: #8b949e; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ {request.title} <span class="live-badge">LIVE DATA</span></h1>
        <p style="color: #8b949e;">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="stats-grid">
            <div class="stat-card"><div class="stat-value">{len(breaches)}</div><div class="stat-label">Vulnerabilities</div></div>
            <div class="stat-card"><div class="stat-value">{len(threats)}</div><div class="stat-label">Threat Indicators</div></div>
            <div class="stat-card"><div class="stat-value">{severity_stats.get('critical', 0)}</div><div class="stat-label">Critical</div></div>
            <div class="stat-card"><div class="stat-value">{severity_stats.get('high', 0)}</div><div class="stat-label">High</div></div>
            <div class="stat-card"><div class="stat-value">{len(live_cache.get('sources', []))}</div><div class="stat-label">Live Sources</div></div>
        </div>
        
        <div class="sources-list">
            <h2>📡 Live Data Sources</h2>
            <ul>{source_list}</ul>
        </div>
        
        <div class="charts-grid">
            <div class="chart-container"><h2>Severity Distribution</h2><canvas id="severityChart" height="200"></canvas></div>
            <div class="chart-container"><h2>Threat Sources</h2><canvas id="sourceChart" height="200"></canvas></div>
        </div>
        
        <h2>Data Breach Events & Vulnerabilities</h2>
        <table>
            <thead><tr><th>ID</th><th>Name/CVE</th><th>Severity</th><th>Vendor</th><th>Date</th><th>Country</th><th>Source</th></tr></thead>
            <tbody>{breach_rows}</tbody>
        </table>
        
        <h2>Threat Indicators</h2>
        <table>
            <thead><tr><th>Indicator</th><th>Country</th><th>Type</th><th>Severity</th><th>Source</th><th>Timestamp</th></tr></thead>
            <tbody>{threat_rows}</tbody>
        </table>
        
        <div class="footer">
            <p>LIVE Threat Intelligence Report | {len(live_cache.get('sources', []))} Live Sources Active</p>
            <p>Report ID: {uuid.uuid4().hex[:8].upper()} | Classification: Internal Use Only</p>
        </div>
    </div>
    
    <script>
        new Chart(document.getElementById('severityChart').getContext('2d'), {{
            type: 'doughnut',
            data: {{ labels: ['Critical', 'High', 'Medium', 'Low'], datasets: [{{ data: [{severity_stats.get('critical', 0)}, {severity_stats.get('high', 0)}, {severity_stats.get('medium', 0)}, {severity_stats.get('low', 0)}], backgroundColor: ['#ff0040', '#ff6600', '#ffcc00', '#00cc44'] }}] }},
            options: {{ responsive: true, plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#e0e0e0' }} }} }} }}
        }});
        new Chart(document.getElementById('sourceChart').getContext('2d'), {{
            type: 'bar',
            data: {{ labels: {json.dumps(list(source_type_stats.keys())[:8])}, datasets: [{{ label: 'Threats', data: {json.dumps(list(source_type_stats.values())[:8])}, backgroundColor: '#00ff88' }}] }},
            options: {{ responsive: true, plugins: {{ legend: {{ display: false }} }}, scales: {{ x: {{ ticks: {{ color: '#8b949e' }} }}, y: {{ ticks: {{ color: '#8b949e' }} }} }} }}
        }});
    </script>
</body>
</html>"""
    
    filename = f"report_{uuid.uuid4().hex[:8]}.html"
    filepath = REPORTS_DIR / filename
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report_html)
    
    return FileResponse(path=str(filepath), filename=request.title.replace(" ", "_") + ".html", media_type="text/html")


app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

DEFAULT_PORT = 8003


def find_free_port(start_port: int = DEFAULT_PORT, max_attempts: int = 50) -> int:
    """Return the first available port starting at start_port, checking sequentially."""
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("0.0.0.0", port))
                return port
        except OSError:
            continue
    raise RuntimeError(
        f"No free port found in range {start_port}-{start_port + max_attempts - 1}"
    )


if __name__ == "__main__":
    import uvicorn

    port = find_free_port(DEFAULT_PORT)
    if port != DEFAULT_PORT:
        print(f"Port {DEFAULT_PORT} busy, falling back to port {port}")
    print(f"Starting server at http://localhost:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
