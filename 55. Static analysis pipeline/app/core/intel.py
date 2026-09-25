"""Threat intelligence aggregation (hash-only lookups, never sample upload).

Design rules from the architecture:
  * query by hash only - the sample is never uploaded;
  * per-source rate limiting and on-disk caching;
  * graceful degradation - a missing key, disabled toggle or network error
    yields an explicit ``disabled`` / ``error`` row instead of an exception;
  * an optional **simulated** source is available for demos and is always
    labelled as simulated so it can never be mistaken for real intel.
"""
from __future__ import annotations

import datetime as _dt
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from app.config import cache_dir

USER_AGENT = "SAP-Workbench/1.0 (malware-triage; hash lookup only)"

SOURCES = ("virustotal", "malwarebazaar", "otx")
SOURCE_LABELS = {
    "virustotal": "VirusTotal",
    "malwarebazaar": "MalwareBazaar",
    "otx": "AlienVault OTX",
    "simulated": "Simulated (demo)",
}
SOURCE_URLS = {
    "virustotal": "https://www.virustotal.com/gui/file/{hash}",
    "malwarebazaar": "https://bazaar.abuse.ch/sample/{hash}/",
    "otx": "https://otx.alienvault.com/indicator/file/{hash}",
}


@dataclass
class IntelResult:
    source: str
    hash_queried: str = ""
    hash_type: str = "sha256"
    status: str = "ok"  # ok | not_found | disabled | error | cached | simulated
    found: bool = False
    detection_ratio: str = ""
    positives: int = 0
    total_engines: int = 0
    family: str = ""
    tags: list[str] = field(default_factory=list)
    file_type: str = ""
    first_seen: str = ""
    last_seen: str = ""
    source_url: str = ""
    error: str = ""
    raw: dict = field(default_factory=dict)

    def to_row(self) -> list:
        return [
            SOURCE_LABELS.get(self.source, self.source),
            self.status,
            self.detection_ratio or ("-" if not self.found else "n/a"),
            self.family or "-",
            ", ".join(self.tags[:6]) if self.tags else "-",
            self.first_seen or "-",
            self.source_url or "",
        ]


class IntelAggregator:
    """Hash lookups across the configured sources, with cache + rate limiting."""

    MIN_INTERVAL = {"virustotal": 15.0, "malwarebazaar": 2.0, "otx": 1.5}

    def __init__(self, settings, bus=None, cache_root: Path | None = None) -> None:
        self.settings = settings
        self.bus = bus
        self.cache_root = (cache_root or cache_dir()) / "intel"
        self.cache_root.mkdir(parents=True, exist_ok=True)
        self._last_call: dict[str, float] = {}

    # ------------------------------------------------------------- plumbing
    def _log(self, message: str, level: str = "info") -> None:
        if self.bus:
            self.bus.log(message, level)

    def enabled(self) -> bool:
        return bool(self.settings.get("enable_network_lookups"))

    def configured_sources(self) -> list[str]:
        keys = {
            "virustotal": self.settings.get("virustotal_api_key"),
            "malwarebazaar": self.settings.get("malwarebazaar_api_key"),
            "otx": self.settings.get("otx_api_key"),
        }
        return [s for s in SOURCES if str(keys.get(s) or "").strip()]

    def _cache_path(self, source: str, digest: str) -> Path:
        return self.cache_root / f"{source}_{digest[:32]}.json"

    def _cache_get(self, source: str, digest: str) -> dict | None:
        path = self._cache_path(source, digest)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None
        cached_at = payload.get("_cached_at")
        if cached_at:
            try:
                age = _dt.datetime.now() - _dt.datetime.fromisoformat(cached_at)
                if age.days > 7:
                    return None
            except Exception:
                pass
        return payload

    def _cache_put(self, source: str, digest: str, payload: dict) -> None:
        payload = dict(payload)
        payload["_cached_at"] = _dt.datetime.now().isoformat(timespec="seconds")
        try:
            self._cache_path(source, digest).write_text(
                json.dumps(payload, indent=2), encoding="utf-8"
            )
        except Exception:
            pass

    def _throttle(self, source: str) -> None:
        interval = self.MIN_INTERVAL.get(source, 1.0)
        last = self._last_call.get(source, 0.0)
        wait = interval - (time.monotonic() - last)
        if wait > 0:
            self._log(f"Rate limiting {source}: waiting {wait:.1f}s", "debug")
            time.sleep(wait)
        self._last_call[source] = time.monotonic()

    # ---------------------------------------------------------------- public
    def lookup(self, hashes: dict, simulate: bool = False) -> list[IntelResult]:
        """Look up a hash set.  ``hashes`` is the dict from the hash engine."""
        sha256 = hashes.get("sha256", "")
        results: list[IntelResult] = []

        if simulate:
            results.extend(self._simulated_results(hashes))
            return results

        if not self.enabled():
            for source in SOURCES:
                results.append(
                    IntelResult(
                        source=source,
                        hash_queried=sha256,
                        status="disabled",
                        error="Network lookups are disabled in Settings (offline mode).",
                        source_url=SOURCE_URLS[source].format(hash=sha256),
                    )
                )
            self._log(
                "Threat intel lookups skipped - offline mode (Settings \u2192 Network lookups).",
                "warn",
            )
            return results

        configured = self.configured_sources()
        if not configured:
            self._log(
                "Network lookups enabled but no API keys configured - nothing to query.",
                "warn",
            )
        for source in SOURCES:
            if source not in configured:
                results.append(
                    IntelResult(
                        source=source,
                        hash_queried=sha256,
                        status="disabled",
                        error="No API key configured for this source.",
                        source_url=SOURCE_URLS[source].format(hash=sha256),
                    )
                )
                continue
            try:
                results.append(self._query(source, hashes))
            except Exception as exc:  # keep going with the other sources
                self._log(f"{source} lookup failed: {exc}", "error")
                results.append(
                    IntelResult(
                        source=source,
                        hash_queried=sha256,
                        status="error",
                        error=str(exc),
                        source_url=SOURCE_URLS[source].format(hash=sha256),
                    )
                )
        return results

    def _query(self, source: str, hashes: dict) -> IntelResult:
        sha256 = hashes.get("sha256", "")
        cached = self._cache_get(source, sha256)
        if cached:
            self._log(f"{source}: cache hit for {sha256[:16]}\u2026", "debug")
            return self._from_payload(source, sha256, cached, status="cached")

        self._throttle(source)
        self._log(f"Querying {SOURCE_LABELS[source]} for {sha256[:16]}\u2026", "info")
        if source == "virustotal":
            payload = self._virustotal(sha256)
        elif source == "malwarebazaar":
            payload = self._malwarebazaar(sha256)
        else:
            payload = self._otx(sha256)
        self._cache_put(source, sha256, payload)
        return self._from_payload(source, sha256, payload)

    # -------------------------------------------------------------- sources
    def _virustotal(self, sha256: str) -> dict:
        import requests

        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {
            "x-apikey": str(self.settings.get("virustotal_api_key")),
            "User-Agent": USER_AGENT,
        }
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 404:
            return {"found": False, "status": "not_found"}
        if resp.status_code == 429:
            return {"found": False, "status": "rate_limited", "error": "HTTP 429 rate limited"}
        resp.raise_for_status()
        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        positives = int(stats.get("malicious", 0) or 0) + int(stats.get("suspicious", 0) or 0)
        total = sum(int(v or 0) for v in stats.values()) or 0
        family = ""
        popular = attrs.get("popular_threat_classification", {}) or {}
        if popular.get("suggested_threat_label"):
            family = str(popular["suggested_threat_label"])
        elif popular.get("popular_threat_name"):
            names = popular["popular_threat_name"]
            if names:
                family = str(names[0].get("value", ""))
        return {
            "found": True,
            "status": "ok",
            "positives": positives,
            "total_engines": total,
            "family": family,
            "tags": list(attrs.get("tags", []) or []),
            "file_type": str(attrs.get("type_description", "")),
            "first_seen": _ts(attrs.get("first_submission_date")),
            "last_seen": _ts(attrs.get("last_analysis_date")),
            "raw": {"stats": stats, "reputation": attrs.get("reputation")},
        }

    def _malwarebazaar(self, sha256: str) -> dict:
        import requests

        headers = {
            "API-KEY": str(self.settings.get("malwarebazaar_api_key")),
            "User-Agent": USER_AGENT,
        }
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": sha256},
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("query_status") != "ok" or not payload.get("data"):
            return {"found": False, "status": "not_found", "raw": payload}
        item = payload["data"][0]
        vendor = item.get("vendor_intel") or {}
        tags = list(item.get("tags") or [])
        for key, value in vendor.items():
            if isinstance(value, dict):
                tags.append(str(key))
        return {
            "found": True,
            "status": "ok",
            "family": str(item.get("signature") or ""),
            "tags": tags,
            "file_type": str(item.get("file_type") or ""),
            "first_seen": str(item.get("first_seen") or ""),
            "last_seen": str(item.get("last_seen") or ""),
            "raw": {
                "file_name": item.get("file_name"),
                "imphash": item.get("imphash"),
                "tlsh": item.get("tlsh"),
                "delivery_method": item.get("delivery_method"),
            },
        }

    def _otx(self, sha256: str) -> dict:
        import requests

        url = f"https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general"
        headers = {
            "X-OTX-API-KEY": str(self.settings.get("otx_api_key")),
            "User-Agent": USER_AGENT,
        }
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 404:
            return {"found": False, "status": "not_found"}
        resp.raise_for_status()
        payload = resp.json()
        pulses = payload.get("pulse_info", {}).get("pulses", []) or []
        return {
            "found": bool(pulses),
            "status": "ok" if pulses else "not_found",
            "family": str((pulses[0].get("name") if pulses else "") or ""),
            "tags": [t for p in pulses[:5] for t in (p.get("tags") or [])][:12],
            "first_seen": str(payload.get("pulse_info", {}).get("modified", "") or ""),
            "raw": {"pulse_count": len(pulses)},
        }

    # ------------------------------------------------------------- simulated
    def _simulated_results(self, hashes: dict) -> list[IntelResult]:
        """Clearly-labelled synthetic intel used by the demo fixture only."""
        sha256 = hashes.get("sha256", "")
        estimated = int(sha256[:4], 16) % 55 + 12 if sha256 else 30
        return [
            IntelResult(
                source="simulated",
                hash_queried=sha256,
                status="simulated",
                found=True,
                detection_ratio=f"{estimated}/72",
                positives=estimated,
                total_engines=72,
                family="Demo.Trojan.Loader",
                tags=["demo", "loader", "simulated", "c2"],
                file_type="Win32 EXE",
                first_seen="2026-02-11 09:14:00",
                last_seen="2026-08-30 17:02:00",
                source_url="",
                raw={"note": "SYNTHETIC demo data - not real threat intelligence."},
            ),
            IntelResult(
                source="simulated",
                hash_queried=sha256,
                status="simulated",
                found=True,
                detection_ratio="-",
                family="Demo.Trojan.Loader",
                tags=["demo", "win32", "simulated"],
                file_type="exe",
                first_seen="2026-02-11 09:14:00",
                last_seen="2026-08-31 06:40:00",
                raw={"note": "SYNTHETIC demo data - not real threat intelligence."},
            ),
        ]

    # -------------------------------------------------------------- mapping
    def _from_payload(
        self, source: str, sha256: str, payload: dict, status: str = ""
    ) -> IntelResult:
        found = bool(payload.get("found"))
        return IntelResult(
            source=source,
            hash_queried=sha256,
            status=status or payload.get("status", "ok"),
            found=found,
            detection_ratio=(
                f"{payload.get('positives', 0)}/{payload.get('total_engines', 0)}"
                if source == "virustotal" and found
                else ""
            ),
            positives=int(payload.get("positives", 0) or 0),
            total_engines=int(payload.get("total_engines", 0) or 0),
            family=str(payload.get("family") or ""),
            tags=list(payload.get("tags") or []),
            file_type=str(payload.get("file_type") or ""),
            first_seen=str(payload.get("first_seen") or ""),
            last_seen=str(payload.get("last_seen") or ""),
            error=str(payload.get("error") or ""),
            source_url=SOURCE_URLS.get(source, "").format(hash=sha256),
            raw=payload.get("raw") or {},
        )


def _ts(value) -> str:
    if not value:
        return ""
    try:
        if isinstance(value, (int, float)) or str(value).isdigit():
            return _dt.datetime.utcfromtimestamp(int(value)).strftime("%Y-%m-%d %H:%M")
        return str(value)[:16]
    except Exception:
        return str(value)


def intel_summary(results: list[IntelResult]) -> dict:
    """Aggregate intel for the verdict engine and the report header."""
    positives = max((r.positives for r in results), default=0)
    total = max((r.total_engines for r in results), default=0)
    families = sorted({r.family for r in results if r.family})
    tags = sorted({t for r in results for t in r.tags})
    queried = sum(1 for r in results if r.status in ("ok", "cached", "simulated"))
    return {
        "positives": positives,
        "total_engines": total,
        "detection_ratio": f"{positives}/{total}" if total else "",
        "families": families,
        "tags": tags,
        "sources_queried": queried,
        "sources_total": len(results),
        "status": (
            "simulated"
            if any(r.status == "simulated" for r in results)
            else "disabled"
            if all(r.status == "disabled" for r in results) and results
            else "ok"
        ),
    }
