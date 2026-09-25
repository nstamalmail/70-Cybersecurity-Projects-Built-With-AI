import asyncio
import httpx

async def test_sources():
    print("Testing CISA KEV...")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            print(f"  Status: {r.status_code}")
            if r.status_code == 200:
                data = r.json()
                vulns = data.get("vulnerabilities", [])
                print(f"  Vulnerabilities: {len(vulns)}")
    except Exception as e:
        print(f"  Error: {e}")

    print("\nTesting URLhaus...")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get("https://urlhaus.abuse.ch/downloads/json_recent/")
            print(f"  Status: {r.status_code}")
            if r.status_code == 200:
                data = r.json()
                urls = data.get("urls", [])
                print(f"  URLs: {len(urls)}")
    except Exception as e:
        print(f"  Error: {e}")

    print("\nTesting ThreatFox...")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "get_iocs", "days": 7})
            print(f"  Status: {r.status_code}")
            if r.status_code == 200:
                data = r.json()
                iocs = data.get("data", [])
                print(f"  IOCs: {len(iocs)}")
    except Exception as e:
        print(f"  Error: {e}")

    print("\nTesting MalwareBazaar...")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_recent", "time": "24h"})
            print(f"  Status: {r.status_code}")
            if r.status_code == 200:
                data = r.json()
                samples = data.get("data", [])
                print(f"  Samples: {len(samples)}")
    except Exception as e:
        print(f"  Error: {e}")

    print("\nTesting OTX AlienVault...")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get("https://otx.alienvault.com/otxapi/pulses?sort=-created&limit=5")
            print(f"  Status: {r.status_code}")
            if r.status_code == 200:
                data = r.json()
                pulses = data.get("results", [])
                print(f"  Pulses: {len(pulses)}")
    except Exception as e:
        print(f"  Error: {e}")

    print("\nTesting Ransomware Tracker...")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get("https://ransomwaretracker.abuse.ch/downloads/csv_recent.txt")
            print(f"  Status: {r.status_code}")
            if r.status_code == 200:
                lines = r.text.strip().split("\n")
                print(f"  Entries: {len(lines) - 1}")
    except Exception as e:
        print(f"  Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_sources())
