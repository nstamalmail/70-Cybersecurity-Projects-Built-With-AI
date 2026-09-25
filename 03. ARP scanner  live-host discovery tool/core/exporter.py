"""CSV / JSON exporters (pure functions, caller owns the destination)."""

from __future__ import annotations

import csv
import json

from core.models import ScanResult


def export_csv(result: ScanResult, path: str) -> str:
    """Write hosts to CSV (UTF-8 with BOM so Excel renders it cleanly)."""
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ip", "mac", "vendor", "hostname"])
        for host in result.sorted_hosts():
            writer.writerow(host.to_row())
    return path


def export_json(result: ScanResult, path: str) -> str:
    """Write the full scan result (metadata + hosts) as JSON."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result.to_json_dict(), fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return path


def export(result: ScanResult, path: str) -> str:
    """Dispatch on extension; unknown extension falls back to CSV."""
    lower = path.lower()
    if lower.endswith(".json"):
        return export_json(result, path)
    return export_csv(result, path)
