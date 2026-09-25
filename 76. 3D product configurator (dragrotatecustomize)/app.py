from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, List, Any
from datetime import datetime
import json
import uuid
from pathlib import Path

app = FastAPI(title="3D Product Configurator API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

def load_json(filename):
    filepath = DATA_DIR / filename
    if filepath.exists():
        with open(filepath, "r") as f:
            return json.load(f)
    return []

def save_json(filename, data):
    with open(DATA_DIR / filename, "w") as f:
        json.dump(data, f, indent=2)

@app.get("/", response_class=HTMLResponse)
async def root():
    html_path = BASE_DIR / "static" / "index.html"
    if html_path.exists():
        with open(html_path, "r") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>3D Product Configurator</h1>")

@app.get("/api/products")
async def get_products():
    return {"products": load_json("sample_products.json")}

@app.get("/api/products/{product_id}")
async def get_product(product_id: str):
    for p in load_json("sample_products.json"):
        if p["id"] == product_id:
            return p
    raise HTTPException(status_code=404, detail="Product not found")

@app.get("/api/configurations")
async def get_configurations():
    return {"configurations": load_json("sample_configurations.json")}

class ConfigurationRequest(BaseModel):
    product_id: str
    name: Optional[str] = "My Configuration"
    selections: Dict[str, Any]

@app.post("/api/configurations")
async def create_configuration(request: ConfigurationRequest):
    products = load_json("sample_products.json")
    product = next((p for p in products if p["id"] == request.product_id), None)
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    total_price = product["base_price"]
    for option_key, choice_id in request.selections.items():
        if option_key in product["options"]:
            option = product["options"][option_key]
            if option.get("multiple") and isinstance(choice_id, list):
                for cid in choice_id:
                    for choice in option["choices"]:
                        if choice["id"] == cid:
                            total_price += choice["price"]
            else:
                for choice in option["choices"]:
                    if choice["id"] == choice_id:
                        total_price += choice["price"]
                        break

    config = {
        "id": f"config-{uuid.uuid4().hex[:6]}",
        "product_id": request.product_id,
        "product_name": product["name"],
        "name": request.name,
        "selections": request.selections,
        "total_price": round(total_price, 2),
        "created_at": datetime.now().isoformat()
    }
    configs = load_json("sample_configurations.json")
    configs.append(config)
    save_json("sample_configurations.json", configs)
    return config

@app.delete("/api/configurations/{config_id}")
async def delete_configuration(config_id: str):
    configs = load_json("sample_configurations.json")
    configs = [c for c in configs if c["id"] != config_id]
    save_json("sample_configurations.json", configs)
    return {"message": "Configuration deleted"}

class CartItem(BaseModel):
    configuration_id: str
    quantity: int = 1

class CartRequest(BaseModel):
    items: List[CartItem]

@app.post("/api/cart/calculate")
async def calculate_cart(request: CartRequest):
    configs = load_json("sample_configurations.json")
    items = []
    subtotal = 0
    for cart_item in request.items:
        config = next((c for c in configs if c["id"] == cart_item.configuration_id), None)
        if config:
            item_total = config["total_price"] * cart_item.quantity
            items.append({"configuration": config, "quantity": cart_item.quantity, "line_total": round(item_total, 2)})
            subtotal += item_total
    tax = round(subtotal * 0.08, 2)
    return {"items": items, "subtotal": round(subtotal, 2), "tax": tax, "total": round(subtotal + tax, 2)}

class ReportRequest(BaseModel):
    configuration_ids: List[str]
    customer_name: Optional[str] = "Customer"
    customer_email: Optional[str] = "customer@example.com"

@app.post("/api/reports/generate")
async def generate_report(request: ReportRequest):
    configs = load_json("sample_configurations.json")
    products = load_json("sample_products.json")
    selected_configs = [c for c in configs if c["id"] in request.configuration_ids]
    if not selected_configs:
        raise HTTPException(status_code=404, detail="No configurations found")

    product_map = {p["id"]: p for p in products}
    subtotal = sum(c["total_price"] for c in selected_configs)
    tax = round(subtotal * 0.08, 2)
    total = round(subtotal + tax, 2)

    items_html = ""
    for config in selected_configs:
        options_html = "".join(
            f"<tr><td>{k.replace('_',' ').title()}</td><td>{', '.join(v) if isinstance(v, list) else v.replace('_',' ').title()}</td></tr>"
            for k, v in config["selections"].items()
        )
        items_html += f'<div class="product-card"><h3>{config["product_name"]}</h3><p class="config-name">Config: {config["name"]}</p><table class="options-table"><thead><tr><th>Option</th><th>Selection</th></tr></thead><tbody>{options_html}</tbody></table><p class="price">${config["total_price"]:,.2f}</p></div>'

    report_html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Order Summary</title><style>*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:'Segoe UI',system-ui,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;padding:40px 20px}}.container{{max-width:800px;margin:0 auto;background:white;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,0.3);overflow:hidden}}.header{{background:linear-gradient(135deg,#1a1a2e,#16213e);color:white;padding:30px 40px}}.header h1{{font-size:2em;margin-bottom:10px}}.header p{{opacity:0.8}}.content{{padding:30px 40px}}.customer-info{{background:#f8f9fa;padding:15px 20px;border-radius:8px;margin-bottom:25px}}.customer-info p{{margin:5px 0;color:#555}}.product-card{{border:1px solid #e0e0e0;border-radius:12px;padding:20px;margin:15px 0}}.product-card h3{{color:#1a1a2e;margin-bottom:5px}}.config-name{{color:#666;font-size:0.9em;margin-bottom:10px}}.options-table{{width:100%;border-collapse:collapse;margin:10px 0}}.options-table th{{background:#1a1a2e;color:white;padding:8px 12px;text-align:left}}.options-table td{{padding:8px 12px;border-bottom:1px solid #eee}}.price{{font-size:1.3em;font-weight:bold;color:#667eea;margin-top:10px}}.summary{{background:#f8f9fa;padding:20px;border-radius:8px;margin-top:25px}}.summary-row{{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #e0e0e0}}.summary-row:last-child{{border-bottom:none}}.total-row{{font-size:1.3em;font-weight:bold;color:#1a1a2e;border-top:2px solid #667eea;padding-top:12px;margin-top:8px}}.footer{{text-align:center;padding:20px;color:#999;font-size:0.85em}}</style></head><body><div class="container"><div class="header"><h1>Order Summary</h1><p>Thank you for your configuration</p></div><div class="content"><div class="customer-info"><p><strong>Customer:</strong> {request.customer_name}</p><p><strong>Email:</strong> {request.customer_email}</p><p><strong>Date:</strong> {datetime.now().strftime('%B %d, %Y')}</p><p><strong>Quote ID:</strong> {uuid.uuid4().hex[:8].upper()}</p></div>{items_html}<div class="summary"><div class="summary-row"><span>Subtotal</span><span>${subtotal:,.2f}</span></div><div class="summary-row"><span>Tax (8%)</span><span>${tax:,.2f}</span></div><div class="summary-row total-row"><span>Total</span><span>${total:,.2f}</span></div></div></div><div class="footer"><p>This quote is valid for 30 days</p><p>3D Product Configurator | Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}</p></div></div></body></html>"""

    filename = f"order_{uuid.uuid4().hex[:8]}.html"
    filepath = REPORTS_DIR / filename
    with open(filepath, "w") as f:
        f.write(report_html)
    return FileResponse(path=str(filepath), filename="Order_Summary.html", media_type="text/html")

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
