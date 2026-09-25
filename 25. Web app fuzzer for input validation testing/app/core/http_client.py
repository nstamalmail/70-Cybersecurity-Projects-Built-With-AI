"""Thread-safe HTTP client wrapper around `requests`.

One session per thread is created lazily (thread-local) to avoid cookie races.
"""

from __future__ import annotations

import threading
import time
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests import RequestException, Timeout

from app.core.models import RequestSpec

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 WebFuzzer/1.0"
)


class RateLimiter:
    """Global minimum-interval limiter shared by all workers."""

    def __init__(self, min_interval_ms: int = 0):
        self._lock = threading.Lock()
        self._last = 0.0
        self.set_delay(min_interval_ms)

    def set_delay(self, min_interval_ms: int) -> None:
        with self._lock:
            self._interval = max(0.0, min_interval_ms / 1000.0)

    def wait(self) -> None:
        if self._interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            diff = self._last + self._interval - now
            if diff > 0:
                self._last = now + diff
                time.sleep(diff)
            else:
                self._last = now


class HttpClient:
    """Throttled, thread-safe HTTP client."""

    def __init__(self, timeout: float = 10.0, verify: bool = True,
                 follow_redirects: bool = True, proxy: str = "", delay_ms: int = 0):
        self.timeout = timeout
        self.verify = verify
        self.follow_redirects = follow_redirects
        self.proxy = proxy
        self.rate_limiter = RateLimiter(delay_ms)
        self._local = threading.local()

    def set_config(self, timeout: float, verify: bool, follow_redirects: bool,
                   proxy: str, delay_ms: int) -> None:
        self.timeout = timeout
        self.verify = verify
        self.follow_redirects = follow_redirects
        self.proxy = proxy
        self.rate_limiter.set_delay(delay_ms)

    def _session(self) -> requests.Session:
        s = getattr(self._local, "session", None)
        if s is None:
            s = requests.Session()
            s.headers.update({"User-Agent": UA, "Accept": "*/*"})
            self._local.session = s
        return s

    def send(self, spec: RequestSpec) -> Tuple[requests.Response, float]:
        """Send a request, respecting the global rate limiter.

        Returns (response, elapsed_seconds). Raises RequestException on failure.
        """
        self.rate_limiter.wait()
        session = self._session()
        proxies: Optional[Dict[str, str]] = None
        if self.proxy:
            proxies = {"http": self.proxy, "https": self.proxy}

        start = time.monotonic()
        resp = session.request(
            method=spec.method,
            url=spec.url,
            headers=spec.headers or None,
            cookies=spec.cookies or None,
            data=spec.body if spec.body_type in ("form", "raw") else None,
            json=spec.body if spec.body_type == "json" else None,
            timeout=(self.timeout, self.timeout + 15),
            allow_redirects=spec.allow_redirects,
            verify=self.verify,
            proxies=proxies,
        )
        elapsed = time.monotonic() - start
        return resp, elapsed


def error_label(exc: BaseException) -> str:
    if isinstance(exc, Timeout):
        return "timeout"
    if isinstance(exc, requests.exceptions.SSLError):
        return "ssl-error"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "connection-error"
    if isinstance(exc, requests.exceptions.InvalidURL):
        return "invalid-url"
    if isinstance(exc, RequestException):
        return "http-error"
    return type(exc).__name__


def same_host(url_a: str, url_b: str) -> bool:
    a, b = urlparse(url_a), urlparse(url_b)
    return a.netloc == b.netloc and a.scheme == b.scheme