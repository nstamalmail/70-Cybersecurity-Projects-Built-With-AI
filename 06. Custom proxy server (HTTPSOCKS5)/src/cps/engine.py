"""Proxy core for CPS: asyncio HTTP CONNECT + SOCKS5 server with auto-detect,
filter engine, traffic logging and session report building."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime


# ------------------------------------------------------------------- config
@dataclass
class ProxyConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    protocol_mode: str = "auto"           # http | socks5 | auto
    auth_required: bool = False
    auth_users: dict = field(default_factory=dict)     # user -> sha256 hex
    blocklist_enabled: bool = True
    blocklist_rules: list = field(default_factory=list)  # list[str]
    log_enabled: bool = True
    max_connections: int = 1000

    def to_dict(self):
        return {
            "listen_host": self.listen_host, "listen_port": self.listen_port,
            "protocol_mode": self.protocol_mode, "auth_required": self.auth_required,
            "blocklist_enabled": self.blocklist_enabled,
            "blocklist_rules": list(self.blocklist_rules),
            "log_enabled": self.log_enabled, "max_connections": self.max_connections,
        }


# ------------------------------------------------------------ filter engine
class FilterEngine:
    """Destination filter: exact host, wildcard *.example.com, CIDR, regex."""

    def __init__(self, rules: list[str]):
        import ipaddress
        import re as _re
        self._ip = ipaddress
        self._re = _re
        self.exact: set[str] = set()
        self.wildcards: list[tuple[str, str]] = []     # (suffix, original)
        self.cidrs: list = []
        self.regexes: list = []
        self.invalid: list[str] = []
        for raw in rules or []:
            rule = raw.strip()
            if not rule or rule.startswith("#"):
                continue
            low = rule.lower()
            if low.startswith("re:"):
                try:
                    self.regexes.append(_re.compile(rule[3:], _re.I))
                except _re.error:
                    self.invalid.append(rule)
                continue
            try:
                self.cidrs.append(self._ip.ip_network(rule, strict=False))
                continue
            except ValueError:
                pass
            if low.startswith("*."):
                self.wildcards.append((low[1:], rule))   # '.example.com'
                continue
            if "/" in rule or low.count(".") == 3 and low.replace(".", "").isdigit():
                try:
                    self.cidrs.append(self._ip.ip_network(rule, strict=False))
                    continue
                except ValueError:
                    pass
            self.exact.add(low.rstrip("."))

    def check(self, host: str) -> str | None:
        """Return block reason if host is blocked, else None."""
        h = (host or "").lower().rstrip(".")
        if h in self.exact:
            return "exact match"
        for suffix, original in self.wildcards:
            if h.endswith(suffix):
                return f"wildcard {original}"
        try:
            ip = self._ip.ip_address(h.split(":")[0])
            for cidr in self.cidrs:
                if ip in cidr:
                    return f"CIDR {cidr}"
        except ValueError:
            pass
        for pattern in self.regexes:
            if pattern.search(h):
                return f"regex {pattern.pattern}"
        return None


# ------------------------------------------------------------ auth (hashes)
def hash_password(password: str) -> str:
    import hashlib
    return hashlib.sha256(("cps-salt:" + password).encode()).hexdigest()


def verify_password(password: str, stored_hash: str) -> bool:
    import hmac
    return hmac.compare_digest(hash_password(password), stored_hash or "")


# ----------------------------------------------------------------- the server
class ProxyServer:
    """Runs an asyncio loop in a background thread; emits events via callback."""

    def __init__(self, config: ProxyConfig, on_event=None):
        self.config = config
        self.on_event = on_event or (lambda rec: None)
        self.filter = FilterEngine(config.blocklist_rules if config.blocklist_enabled else [])
        self.loop: asyncio.AbstractEventLoop | None = None
        self.server: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self.running = False
        self.active_connections = 0
        self.total_connections = 0

    # ---------------------------------------------------------- lifecycle
    def start(self):
        if self.running:
            return
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        # wait for bind
        for _ in range(50):
            if self.running:
                break
            time.sleep(0.1)

    def stop(self):
        if not self.running:
            return
        if self.loop and self.server:
            self.loop.call_soon_threadsafe(self.server.close)
        self.running = False

    def _run_loop(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.server = self.loop.run_until_complete(
                asyncio.start_server(self._client_connected,
                                     self.config.listen_host, self.config.listen_port))
            self.running = True
            self.loop.run_until_complete(self.server.serve_forever())
        except asyncio.CancelledError:
            pass  # normal stop() shutdown path
        except OSError as exc:
            self.on_event({"type": "error", "detail": f"bind failed: {exc}"})
        finally:
            self.running = False
            try:
                self.loop.close()
            except Exception:                              # noqa: BLE001
                pass

    # ------------------------------------------------------ connection I/O
    async def _client_connected(self, reader: asyncio.StreamReader,
                                writer: asyncio.StreamWriter):
        self.total_connections += 1
        self.active_connections += 1
        try:
            if self.config.protocol_mode == "socks5":
                await self._handle_socks5(reader, writer)
            elif self.config.protocol_mode == "http":
                await self._handle_http(reader, writer)
            else:
                # auto-detect by first byte
                first = await reader.read(1)
                if not first:
                    return
                if first == b"\x05":
                    await self._handle_socks5(reader, writer, first_byte=first)
                else:
                    await self._handle_http(reader, writer, first_byte=first)
        except (ConnectionError, asyncio.IncompleteReadError, TimeoutError):
            pass
        except Exception as exc:                           # noqa: BLE001
            self.on_event({"type": "error", "detail": f"handler error: {exc}"})
        finally:
            self.active_connections -= 1
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:                              # noqa: BLE001
                pass

    def _emit(self, **kw):
        rec = {"timestamp": datetime.now().isoformat(timespec="seconds"),
               "client_ip": kw.get("client_ip", ""), "dest_host": kw.get("dest_host", ""),
               "dest_port": kw.get("dest_port", 0), "protocol": kw.get("protocol", ""),
               "bytes_up": kw.get("bytes_up", 0), "bytes_down": kw.get("bytes_down", 0),
               "duration_ms": kw.get("duration_ms", 0), "status": kw.get("status", ""),
               "detail": kw.get("detail", "")}
        self.on_event(rec)

    async def _relay(self, r1, w1, r2, w2, counters, direction):
        try:
            while True:
                data = await r1.read(65536)
                if not data:
                    break
                counters[direction] += len(data)
                w2.write(data)
                await w2.drain()
        except (ConnectionError, TimeoutError):
            pass

    async def _tunnel(self, client_reader, client_writer, target_reader, target_writer,
                      client_ip, host, port, protocol, status="ALLOWED"):
        counters = {"up": 0, "down": 0}
        started = time.monotonic()
        t1 = asyncio.create_task(self._relay(client_reader, client_writer,
                                             target_reader, target_writer, counters, "up"))
        t2 = asyncio.create_task(self._relay(target_reader, target_writer,
                                             client_reader, client_writer, counters, "down"))
        try:
            await asyncio.gather(t1, t2)
        finally:
            for task in (t1, t2):
                task.cancel()
            duration_ms = int((time.monotonic() - started) * 1000)
            self._emit(client_ip=client_ip, dest_host=host, dest_port=port,
                       protocol=protocol, bytes_up=counters["up"],
                       bytes_down=counters["down"], duration_ms=duration_ms,
                       status=status)

    async def _check_filter(self, host) -> tuple[bool, str]:
        if not self.config.blocklist_enabled:
            return True, ""
        reason = self.filter.check(host)
        if reason:
            return False, reason
        return True, ""

    # ------------------------------------------------------- HTTP CONNECT
    async def _handle_http(self, reader, writer, first_byte: bytes | None = None):
        peer = writer.get_extra_info("peername") or ("?", 0)
        client_ip = peer[0]
        # read the request line (we may already have 1 byte)
        line = await reader.readline()
        if first_byte:
            line = first_byte + line
        try:
            method, target, _version = line.decode("latin1").strip().split(" ", 2)
        except ValueError:
            self._emit(client_ip=client_ip, dest_host="?", protocol="HTTP",
                       status="ERROR", detail="malformed request line")
            return
        # Drain the remaining CONNECT request headers before tunneling so
        # they are not forwarded to the target as tunnel payload.
        while True:
            header = await reader.readline()
            if not header or header in (b"\r\n", b"\n"):
                break
        if method.upper() != "CONNECT":
            body = b"HTTP/1.1 405 Method Not Allowed\r\n\r\n"
            self._emit(client_ip=client_ip, dest_host=target or "?", protocol="HTTP",
                       status="ERROR", detail="only CONNECT supported")
            writer.write(body)
            await writer.drain()
            return
        host, _, port_s = target.rpartition(":")
        port = int(port_s) if port_s.isdigit() else 443
        if self.config.auth_required:
            auth_line = ""
            while True:
                header = await reader.readline()
                if not header or header in (b"\r\n", b"\n"):
                    break
                if header.lower().startswith(b"proxy-authorization:"):
                    auth_line = header.decode("latin1").split(":", 1)[1].strip()
            user, ok = self._check_http_auth(auth_line)
            if not ok:
                writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                             b"Proxy-Authenticate: Basic realm=\"CPS\"\r\n\r\n")
                await writer.drain()
                self._emit(client_ip=client_ip, dest_host=target, protocol="HTTP",
                           status="AUTH_FAIL", detail=f"user={user}")
                return
        allowed, reason = await self._check_filter(host)
        if not allowed:
            writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            await writer.drain()
            self._emit(client_ip=client_ip, dest_host=host, dest_port=port,
                       protocol="HTTP", status="BLOCKED", detail=reason)
            return
        try:
            t_reader, t_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10)
        except (OSError, asyncio.TimeoutError) as exc:
            self._emit(client_ip=client_ip, dest_host=host, dest_port=port,
                       protocol="HTTP", status="ERROR", detail=str(exc))
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            return
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await self._tunnel(reader, writer, t_reader, t_writer, client_ip, host, port, "HTTP")

    def _check_http_auth(self, auth_line: str) -> tuple[str, bool]:
        import base64
        try:
            scheme, _, b64 = auth_line.partition(" ")
            if scheme.lower() != "basic":
                return "", False
            userpass = base64.b64decode(b64).decode("utf-8")
            user, _, password = userpass.partition(":")
        except Exception:                                  # noqa: BLE001
            return "", False
        stored = self.config.auth_users.get(user)
        if stored and verify_password(password, stored):
            return user, True
        return user, False

    # ------------------------------------------------------------- SOCKS5
    async def _handle_socks5(self, reader, writer, first_byte: bytes | None = None):
        peer = writer.get_extra_info("peername") or ("?", 0)
        client_ip = peer[0]
        ver = first_byte or await reader.readexactly(1)
        if ver != b"\x05":
            self._emit(client_ip=client_ip, protocol="SOCKS5", status="ERROR",
                       detail="bad version")
            return
        nmethods = (await reader.readexactly(1))[0]
        methods = await reader.readexactly(nmethods)
        if self.config.auth_required and 0x02 in methods:
            writer.write(b"\x05\x02")
            await writer.drain()
            # RFC 1929 username/password subnegotiation
            await reader.readexactly(1)                    # version byte
            ulen = (await reader.readexactly(1))[0]
            username = (await reader.readexactly(ulen)).decode("utf-8", "replace")
            plen = (await reader.readexactly(1))[0]
            password = (await reader.readexactly(plen)).decode("utf-8", "replace")
            stored = self.config.auth_users.get(username)
            if not stored or not verify_password(password, stored):
                writer.write(b"\x01\x01")
                await writer.drain()
                self._emit(client_ip=client_ip, protocol="SOCKS5", status="AUTH_FAIL",
                           detail=f"user={username}")
                return
            writer.write(b"\x01\x00")
            await writer.drain()
        elif self.config.auth_required:
            writer.write(b"\x05\xFF")                      # no acceptable method
            await writer.drain()
            self._emit(client_ip=client_ip, protocol="SOCKS5", status="AUTH_FAIL",
                       detail="no auth method offered")
            return
        else:
            writer.write(b"\x05\x00")
            await writer.drain()
        # request
        hdr = await reader.readexactly(4)
        if hdr[0] != 5 or hdr[1] != 1:                     # CONNECT only
            writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
            await writer.drain()
            self._emit(client_ip=client_ip, protocol="SOCKS5", status="ERROR",
                       detail="unsupported command")
            return
        atyp = hdr[3]
        if atyp == 1:                                      # IPv4
            raw = await reader.readexactly(4)
            host = ".".join(str(b) for b in raw)
        elif atyp == 3:                                    # domain
            alen = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(alen)).decode("utf-8", "replace")
        elif atyp == 4:                                    # IPv6
            raw = await reader.readexactly(16)
            import ipaddress
            host = str(ipaddress.IPv6Address(raw))
        else:
            writer.write(b"\x05\x08\x00\x01" + b"\x00" * 6)
            await writer.drain()
            return
        port_hi, port_lo = await reader.readexactly(2)
        port = (port_hi << 8) | port_lo
        allowed, reason = await self._check_filter(host)
        if not allowed:
            writer.write(b"\x05\x02\x00\x01" + b"\x00" * 6)   # connection not allowed
            await writer.drain()
            self._emit(client_ip=client_ip, dest_host=host, dest_port=port,
                       protocol="SOCKS5", status="BLOCKED", detail=reason)
            return
        try:
            t_reader, t_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10)
        except (OSError, asyncio.TimeoutError) as exc:
            self._emit(client_ip=client_ip, dest_host=host, dest_port=port,
                       protocol="SOCKS5", status="ERROR", detail=str(exc))
            writer.write(b"\x05\x01\x00\x01" + b"\x00" * 6)   # general failure
            await writer.drain()
            return
        writer.write(b"\x05\x00\x00\x01" + b"\x00" * 4 + (1080).to_bytes(2, "big"))
        await writer.drain()
        await self._tunnel(reader, writer, t_reader, t_writer, client_ip, host, port, "SOCKS5")


# --------------------------------------------------------------- session model
@dataclass
class ProxySession:
    session_id: str
    timestamp: datetime
    config: dict
    total_connections: int = 0
    total_bytes_up: int = 0
    total_bytes_down: int = 0
    blocked_count: int = 0
    error_count: int = 0
    auth_fail_count: int = 0
    unique_destinations: int = 0
    top_destinations: list = field(default_factory=list)
    top_clients: list = field(default_factory=list)
    blocked: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    traffic: list = field(default_factory=list)


def session_from_traffic(session_id: str, config: dict, records: list) -> ProxySession:
    """Aggregate raw traffic records (dicts from log or import) into a session."""
    dests: dict = {}
    clients: dict = {}
    blocked = []
    errors = []
    total_up = total_down = 0
    for r in records:
        total_up += r.get("bytes_up", 0) or 0
        total_down += r.get("bytes_down", 0) or 0
        key = f"{r.get('dest_host', '?')}:{r.get('dest_port', 0)}"
        entry = dests.setdefault(key, {"dest": key, "count": 0, "bytes": 0})
        entry["count"] += 1
        entry["bytes"] += (r.get("bytes_up", 0) or 0) + (r.get("bytes_down", 0) or 0)
        ckey = r.get("client_ip", "?")
        clients[ckey] = clients.get(ckey, 0) + 1
        status = r.get("status", "")
        if status == "BLOCKED":
            blocked.append(r)
        elif status in ("ERROR", "AUTH_FAIL"):
            errors.append(r)
    top_dests = sorted(dests.values(), key=lambda d: -d["count"])[:20]
    top_clients = sorted(({"client": c, "count": n} for c, n in clients.items()),
                         key=lambda d: -d["count"])[:10]
    return ProxySession(
        session_id=session_id,
        timestamp=datetime.now(),
        config=config,
        total_connections=len(records),
        total_bytes_up=total_up,
        total_bytes_down=total_down,
        blocked_count=len(blocked),
        error_count=sum(1 for r in errors if r.get("status") == "ERROR"),
        auth_fail_count=sum(1 for r in errors if r.get("status") == "AUTH_FAIL"),
        unique_destinations=len(dests),
        top_destinations=top_dests,
        top_clients=top_clients,
        blocked=blocked,
        errors=errors,
        traffic=records,
    )
