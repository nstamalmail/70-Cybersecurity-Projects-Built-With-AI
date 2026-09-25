"""Outbound alert notifiers.

Each notifier is a small, independent worker that receives an ``Alert`` and
tries to deliver it somewhere (webhook, email, remote syslog, stdout). A
notifier must never raise into the pipeline: every public ``notify`` is
wrapped by the caller, and internal send errors are logged and swallowed so
one misconfigured notifier cannot suppress an alert or kill the pipeline.

Built-in kinds (all stdlib):

* ``webhook``  — HTTPS/HTTP POST (or configurable method) with a JSON body.
* ``email``    — SMTP plaintext alert. TLS and auth are optional.
* ``syslog``   — sends a single-line syslog-like message (UDP or TCP) so this
                 app can forward alerts into another SIEM.
* ``echo``     — prints the notification payload to stdout (dev / tests).

Configuration lives in ``config.json`` under the ``notifiers`` key, e.g.::

    { "notifiers": [
        { "type": "webhook", "url": "https://example.com/ingest",
          "method": "POST", "timeout": 10,
          "headers": {"Authorization": "Bearer ..."},
          "body_template": "default" },
        { "type": "email", "smtp_host": "smtp.example.com", "from": "siem@...",
          "to": ["ops@example.com"], "subject_template": "default",
          "port": 587, "tls": true, "login": "user:pass" },
        { "type": "syslog", "host": "10.0.0.5", "port": 514,
          "transport": "udp" },
        { "type": "echo" }
      ]
    }

Payload templates
-----------------

Templates select which keys from the alert are included and how the subject
or body is rendered. ``"default"`` is the only built-in template; it is
intentionally stable so existing configs keep working. The keys exposed to a
template are drawn from the ``Alert`` dataclass plus a small helper envelope.

A future template can be added by extending ``_TEMPLATES`` without touching
the notifier implementations.
"""
from __future__ import annotations

import email.message
import json
import logging
import queue
import socket
import smtplib
import ssl
import sys
import time
import urllib.parse
import urllib.request
from typing import Any, Optional

log = logging.getLogger("siem.notifiers")

# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------

def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))


def _envelope(alert: Any) -> dict[str, Any]:
    """Render an alert into a stable JSON-friendly envelope for templates.

    ``event_sample`` is a best-effort one-line human-readable hint about the
    triggering event. It is intentionally plain ASCII so webhook/email bodies
    stay clean on cp1252 consoles too.
    """
    event_sample = ""
    fields = getattr(alert, "fields", None) or {}
    ev_id = fields.get("EventID") or fields.get("event_id")
    if ev_id:
        event_sample = f"EventID={ev_id}"
    host = getattr(alert, "host", None)
    if not host:
        host = fields.get("host") or fields.get("Computer") or ""
    src_ip = fields.get("src_ip")
    pieces: list[str] = []
    if host:
        pieces.append(f"host={host}")
    if src_ip:
        pieces.append(f"src_ip={src_ip}")
    if not pieces:
        pieces.append(f"rule={alert.rule_id}")
    if not event_sample:
        event_sample = ", ".join(pieces)
    elif pieces:
        event_sample = f"{event_sample}, {', '.join(pieces)}"
    return {
        "ts_iso": _iso(alert.ts),
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "severity": alert.severity,
        "summary": alert.summary,
        "group_key": alert.group_key,
        "count": alert.count,
        "status": alert.status,
        "event_sample": event_sample,
        "fields": fields,
        "id": alert.id,
    }


def _render_template(template: str, alert: Any, *, body: bool = False) -> str:
    """Render a named template to a string.

    Only the built-in ``"default"`` template exists today.
    """
    env = _envelope(alert)
    if template != "default":
        raise ValueError(f"unknown template: {template!r}")
    if body:
        return (
            f"Rule      : {env['rule_name']} ({env['rule_id']})\n"
            f"Time      : {env['ts_iso']}\n"
            f"Severity  : {env['severity']}\n"
            f"Group key : {env['group_key']}\n"
            f"Count     : {env['count']}\n"
            f"Status    : {env['status']}\n"
            f"Event     : {env['event_sample']}\n"
            f"Summary   : {env['summary']}\n"
        )
    return (
        f"{env['rule_name']} [{env['severity'].upper()}] "
        f"({env['group_key']}, x{env['count']}): {env['summary']}"
    )


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class Notifier:
    """Single-delivery alert notifier.

    Subclasses override ``_send``. The public API is ``notify`` — callers
    should wrap it in their own ``try/except`` if they want pipeline safety
    (the pipeline does this).
    """

    kind: str = ""

    def __init__(self, cfg: dict[str, Any]) -> None:
        self.cfg = cfg

    def notify(self, alert: Any) -> None:
        self._send(alert)

    def _send(self, alert: Any) -> None:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------

class WebhookNotifier(Notifier):
    kind = "webhook"

    def __init__(self, cfg: dict[str, Any]) -> None:
        super().__init__(cfg)
        self.url = str(cfg.get("url", "")).strip()
        if not self.url:
            raise ValueError("webhook notifier requires url")
        self.method = str(cfg.get("method", "POST")).upper()
        self.timeout = float(cfg.get("timeout", 10) or 10)
        headers: dict[str, str] = {}
        raw_headers = cfg.get("headers")
        if isinstance(raw_headers, dict):
            for k, v in raw_headers.items():
                if k and v is not None:
                    headers[str(k)] = str(v)
        self.headers = headers
        self.body_template = str(cfg.get("body_template", "default"))

    def _send(self, alert: Any) -> None:
        payload = _envelope(alert)
        body = json.dumps(payload, default=str, separators=(",", ":"))
        req = urllib.request.Request(
            self.url,
            data=body.encode("utf-8"),
            method=self.method,
            headers={**self.headers, "Content-Type": "application/json",
                     "Accept": "application/json, text/plain"},
        )
        # Some servers reject requests without a User-Agent.
        if "User-Agent" not in self.headers:
            req.add_header("User-Agent", "SIEMCorrelator/0.3")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.status
                _maybe_read_body(resp)
        except urllib.error.HTTPError as exc:
            # HTTPError still gives us a status + body; log it.
            status = exc.code
            _maybe_read_body(exc)
            raise NotificationError(f"webhook {self.method} {self.url} -> {status}") from exc
        except Exception as exc:
            raise NotificationError(f"webhook {self.method} {self.url}: {exc}") from exc
        log.info("webhook notify %s -> %s (%s)", self.kind, self.url, status)

    def __repr__(self) -> str:
        return f"WebhookNotifier({self.url!r})"


def _maybe_read_body(resp):
    try:
        # Best-effort: consume the body so the connection can be reused / closed.
        if hasattr(resp, "read"):
            resp.read(4096)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

class EmailNotifier(Notifier):
    kind = "email"

    def __init__(self, cfg: dict[str, Any]) -> None:
        super().__init__(cfg)
        self.smtp_host = str(cfg.get("smtp_host", "")).strip()
        if not self.smtp_host:
            raise ValueError("email notifier requires smtp_host")
        self.port = int(cfg.get("port", 587) or 587)
        self.from_addr = str(cfg.get("from", "")).strip()
        if not self.from_addr:
            raise ValueError("email notifier requires from")
        raw_to = cfg.get("to")
        if not raw_to:
            raise ValueError("email notifier requires to")
        if isinstance(raw_to, str):
            self.to_addrs = [a.strip() for a in raw_to.split(",") if a.strip()]
        elif isinstance(raw_to, list):
            self.to_addrs = [str(a).strip() for a in raw_to if str(a).strip()]
        else:
            self.to_addrs = []
        if not self.to_addrs:
            raise ValueError("email notifier requires at least one to address")
        self.tls = bool(cfg.get("tls", self.port == 465))
        self.login = cfg.get("login")
        self.subject_template = str(cfg.get("subject_template", "default"))

    def _send(self, alert: Any) -> None:
        msg = email.message.EmailMessage()
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.to_addrs)
        msg["Subject"] = _render_template(self.subject_template, alert, body=False)
        msg["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S %z", time.localtime(alert.ts))
        msg.set_content_type("text/plain")
        msg.set_content(_render_template(self.subject_template, alert, body=True))

        login_user = login_pass = None
        if self.login:
            if isinstance(self.login, str) and ":" in self.login:
                user, _, pw = self.login.partition(":")
                login_user, login_pass = user, pw
            else:
                login_user = str(self.login)

        client: Optional[object] = None
        try:
            client_class = smtplib.SMTP
            client = client_class(self.smtp_host, self.port, timeout=15)
            if self.tls:
                if self.port == 465:
                    client = smtplib.SMTP_SSL(self.smtp_host, self.port, timeout=15)
                else:
                    context: Optional[ssl.SSLContext] = None
                    ctx_cfg = self.cfg.get("tls_context")
                    if isinstance(ctx_cfg, dict):
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        verify = ctx_cfg.get("verify", True)
                        if not verify:
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                    client.starttls(context=context)
            if login_user is not None:
                client.login(login_user, login_pass or "")
            code, msg_resp = client.send_message(msg)
        except Exception as exc:
            raise NotificationError(f"email notify via {self.smtp_host}:{self.port}: {exc}") from exc
        finally:
            if client is not None:
                try:
                    client.quit()
                except Exception:
                    pass
        log.info("email notify -> %s (%s)", ", ".join(self.to_addrs), code or "ok")


# ---------------------------------------------------------------------------
# Syslog replay (forward alerts into another SIEM as a single log line)
# ---------------------------------------------------------------------------

class SyslogNotifier(Notifier):
    kind = "syslog"

    def __init__(self, cfg: dict[str, Any]) -> None:
        super().__init__(cfg)
        self.host = str(cfg.get("host", "127.0.0.1")).strip()
        if not self.host:
            raise ValueError("syslog notifier requires host")
        self.port = int(cfg.get("port", 514) or 514)
        self.transport = str(cfg.get("transport", "udp")).lower()
        if self.transport not in ("udp", "tcp", "tls"):
            raise ValueError(f"syslog transport must be udp/tcp/tls, got {self.transport!r}")
        self.facility = int(cfg.get("facility", 16) or 16)  # local0
        self.level_map = {
            "critical": 2,  # LOG_CRIT
            "high": 3,      # LOG_ERR
            "medium": 4,    # LOG_WARNING
            "low": 6,       # LOG_INFO
        }
        self._tcp_sock: Optional[socket.socket] = None
        self._tls_sock: Optional[object] = None
        self._tls_context: Optional[ssl.SSLContext] = None
        raw_tls = cfg.get("tls")
        if self.transport == "tls":
            self._tls_context = ssl.create_default_context()
            if isinstance(raw_tls, dict):
                verify = raw_tls.get("verify", True)
                if not verify:
                    self._tls_context.check_hostname = False
                    self._tls_context.verify_mode = ssl.CERT_NONE

    def _send(self, alert: Any) -> None:
        prio = (self.facility << 3) | self.level_map.get(alert.severity, 6)
        line = f"<{prio}>{time.strftime('%b %d %H:%M:%S', time.localtime(alert.ts))} "
        line += (
            f"SIEMCorrelator[{alert.rule_id}]: "
            f"{alert.rule_name} [{alert.severity.upper()}] "
            f"{alert.summary} (key={alert.group_key}, x{alert.count})"
        )
        data = line.encode("utf-8")

        if self.transport == "udp":
            self._send_udp(data)
        elif self.transport == "tls":
            self._send_tls(data)
        else:
            self._send_tcp(data)

    def _send_udp(self, data: bytes) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(5)
            sock.sendto(data, (self.host, self.port))
        except Exception as exc:
            raise NotificationError(f"syslog udp {self.host}:{self.port}: {exc}") from exc
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _send_tcp(self, data: bytes) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(5)
            sock.connect((self.host, self.port))
            sock.sendall(data)
        except Exception as exc:
            raise NotificationError(f"syslog tcp {self.host}:{self.port}: {exc}") from exc
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _send_tls(self, data: bytes) -> None:
        if self._tls_context is None:
            self._tls_context = ssl.create_default_context()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(5)
            sock.connect((self.host, self.port))
            tls = self._tls_context.wrap_socket(sock, server_hostname=self.host)
            tls.sendall(data)
        except Exception as exc:
            raise NotificationError(f"syslog tls {self.host}:{self.port}: {exc}") from exc
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def __repr__(self) -> str:
        return f"SyslogNotifier({self.transport}://{self.host}:{self.port})"


# ---------------------------------------------------------------------------
# Echo (dev / test)
# ---------------------------------------------------------------------------

class EchoNotifier(Notifier):
    kind = "echo"

    def __init__(self, cfg: dict[str, Any], *, sink: Any = None) -> None:
        super().__init__(cfg)
        self._sink = sink

    def _send(self, alert: Any) -> None:
        env = _envelope(alert)
        payload = json.dumps(env, default=str, sort_keys=True, indent=2)
        line = f"[NOTIFIER:echo] {payload}"
        try:
            print(line, file=sys.stdout, flush=True)
        except Exception as exc:
            log.warning("echo notifier stdout write failed: %s", exc)
        if self._sink is not None:
            try:
                if isinstance(self._sink, queue.Queue):
                    self._sink.put(line, timeout=1)
                else:
                    self._sink.append(line)
            except Exception as exc:
                log.warning("echo notifier sink write failed: %s", exc)


# ---------------------------------------------------------------------------
# Factory + errors
# ---------------------------------------------------------------------------

_NOTIFIER_BY_KIND: dict[str, type[Notifier]] = {
    "webhook": WebhookNotifier,
    "email": EmailNotifier,
    "syslog": SyslogNotifier,
    "echo": EchoNotifier,
}


def build_notifier(raw: Any) -> Notifier:
    """Build a notifier from a config dict; raises on bad config."""
    if not isinstance(raw, dict):
        raise ValueError(f"notifier config must be a dict, got {type(raw)!r}")
    kind = str(raw.get("type", "")).strip()
    if not kind:
        raise ValueError("notifier config requires a type")
    cls = _NOTIFIER_BY_KIND.get(kind)
    if cls is None:
        raise ValueError(f"unknown notifier type: {kind!r}")
    return cls(raw)


def build_notifiers(cfg: dict[str, Any]) -> list[Notifier]:
    """Build all configured notifiers; invalid entries are silently dropped and
    logged so a single bad entry cannot prevent the rest from being used."""
    raw_list = cfg.get("notifiers")
    if not isinstance(raw_list, list):
        return []
    out: list[Notifier] = []
    for entry in raw_list:
        try:
            out.append(build_notifier(entry))
        except Exception as exc:
            log.warning("skipping invalid notifier config: %s (%s)", exc, entry)
    return out


class NotificationError(Exception):
    """A notifier failed to deliver. Handled by the pipeline; never raised into
    the rest of the app uncaught."""
    pass
