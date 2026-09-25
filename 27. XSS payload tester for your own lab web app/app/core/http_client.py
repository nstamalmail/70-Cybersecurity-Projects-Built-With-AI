"""HTTP client + parameter discovery for XPT (mirrors SIDT house style)."""

from __future__ import annotations

import json
from typing import Dict, List, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from app.core.models import Parameter, ScanConfig

USER_AGENT = "XPT/1.0 (lab XSS tester; authorized targets only)"


def parse_headers_text(text: str) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, _, v = line.partition(":")
        headers[k.strip()] = v.strip()
    return headers


def parse_cookies_text(text: str) -> Dict[str, str]:
    cookies: Dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if ":" in line:
            line = line.split(":", 1)[1].strip()
        for pair in line.split(";"):
            if "=" in pair:
                k, _, v = pair.partition("=")
                cookies[k.strip()] = v.strip()
    return cookies


def parse_body_params(body: str, body_type: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if not body or body_type == "none":
        return out
    if body_type == "json":
        try:
            doc = json.loads(body)
        except Exception:
            return out
        if isinstance(doc, dict):
            for k, v in doc.items():
                out.append((str(k), "" if v is None else str(v)))
        return out
    for pair in body.replace("\n", "&").split("&"):
        if "=" in pair:
            k, _, v = pair.partition("=")
            if k.strip():
                out.append((k.strip(), v))
    return out


def discover_parameters(cfg: ScanConfig) -> List[Parameter]:
    params: List[Parameter] = []
    split = urlsplit(cfg.target_url)
    for k, v in parse_qsl(split.query, keep_blank_values=True):
        params.append(Parameter("query", k, v))
    for k, v in parse_body_params(cfg.body, cfg.body_type):
        params.append(Parameter("body", k, v))
    for k, v in cfg.cookies.items():
        params.append(Parameter("cookie", k, v))
    return params


def build_request(cfg: ScanConfig, param: Parameter, value: str) -> Tuple[str, Dict, Dict, str]:
    """Return (url, headers, cookies, body) with `param` set to `value`."""
    headers = dict(cfg.headers)
    cookies = dict(cfg.cookies)
    body = cfg.body

    if param.location == "query":
        split = urlsplit(cfg.target_url)
        qs = parse_qsl(split.query, keep_blank_values=True)
        replaced = False
        new_qs = []
        for k, v in qs:
            if k == param.name and not replaced:
                new_qs.append((k, value))
                replaced = True
            else:
                new_qs.append((k, v))
        if not replaced:
            new_qs.append((param.name, value))
        url = urlunsplit((split.scheme, split.netloc, split.path,
                          urlencode(new_qs), split.fragment))
        return url, headers, cookies, body

    if param.location == "cookie":
        cookies[param.name] = value
        return cfg.target_url, headers, cookies, body

    # body
    if cfg.body_type == "json":
        try:
            doc = json.loads(cfg.body)
        except Exception:
            doc = {}
        if isinstance(doc, dict):
            doc[param.name] = value
        else:
            doc = {param.name: value}
        body = json.dumps(doc)
    else:
        pairs = parse_body_params(cfg.body, cfg.body_type)
        new_pairs = []
        replaced = False
        for k, v in pairs:
            if k == param.name and not replaced:
                new_pairs.append((k, value))
                replaced = True
            else:
                new_pairs.append((k, v))
        if not replaced:
            new_pairs.append((param.name, value))
        body = urlencode(new_pairs)
    return cfg.target_url, headers, cookies, body


def request_preview(method: str, url: str, headers: Dict[str, str],
                    cookies: Dict[str, str], body: str = "") -> str:
    lines = [f"{method} {url}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    if cookies:
        lines.append("Cookie: " + "; ".join(f"{k}={v}" for k, v in cookies.items()))
    lines.append("")
    if body:
        lines.append(body)
    return "\n".join(lines)


class HttpClient:
    def __init__(self, cfg: ScanConfig):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.proxies = {"http": cfg.proxy, "https": cfg.proxy} if cfg.proxy else None

    def send(self, method: str, url: str, headers: Dict[str, str],
             cookies: Dict[str, str], body: str = "") -> requests.Response:
        import time
        if self.cfg.delay_ms:
            time.sleep(self.cfg.delay_ms / 1000.0)
        data = body.encode("utf-8") if body else None
        if data is not None and "Content-Type" not in {k.title() for k in headers}:
            headers = dict(headers)
            headers["Content-Type"] = ("application/json" if self.cfg.body_type == "json"
                                       else "application/x-www-form-urlencoded")
        return self.session.request(
            method, url, headers=headers, cookies=cookies, data=data,
            timeout=self.cfg.timeout, allow_redirects=self.cfg.follow_redirects,
            verify=self.cfg.verify_ssl, proxies=self.proxies,
        )
