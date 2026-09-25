"""DNS lab core for DRCP: cache, resolver, fake authoritative, attack engine, verifier.

Educational lab only - all traffic stays on localhost / isolated networks.
The isolation guard refuses to aim at public DNS resolvers.
"""
from __future__ import annotations

import random
import socket
import socketserver
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime

import dnslib

# Public resolver IPs the lab refuses to target.
PUBLIC_DNS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "64.6.64.6", "77.88.8.8",
}


def check_isolation(resolver_ip: str) -> tuple[bool, str]:
    """Return (ok, reason). Refuses public DNS targets."""
    ip = (resolver_ip or "").strip()
    if not ip:
        return False, "resolver IP is empty"
    if ip in PUBLIC_DNS:
        return False, f"{ip} is a PUBLIC resolver - isolated lab only"
    if not (ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.")
            or ip.startswith("172.16.") or ip.startswith("172.17.")
            or ip.startswith("172.18.") or ip.startswith("172.19.")
            or ip.startswith("172.2") or ip.startswith("172.30.") or ip.startswith("172.31.")):
        return False, f"{ip} does not look like a private/lab address"
    return True, "isolated lab address accepted"


# --------------------------------------------------------------------- cache
@dataclass
class CacheEntry:
    domain: str
    record_type: str
    value: str
    ttl: int
    inserted_at: float = field(default_factory=time.time)
    source: str = "legitimate"          # legitimate | forged

    def expires_in(self) -> int:
        return max(0, int(self.ttl - (time.time() - self.inserted_at)))


class DNSCache:
    """Thread-safe LRU cache with TTL expiry and poison-source tracking."""

    def __init__(self, max_entries: int = 512):
        self._data: OrderedDict[tuple[str, str], CacheEntry] = OrderedDict()
        self._lock = threading.Lock()
        self._max = max_entries

    def get(self, qname: str, qtype: str) -> CacheEntry | None:
        key = (qname.rstrip(".").lower(), qtype.upper())
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            if entry.expires_in() <= 0:
                del self._data[key]
                return None
            self._data.move_to_end(key)
            return entry

    def put(self, entry: CacheEntry) -> None:
        key = (entry.domain.rstrip(".").lower(), entry.record_type.upper())
        with self._lock:
            self._data[key] = entry
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    def dump(self) -> list[CacheEntry]:
        with self._lock:
            live = [e for e in self._data.values() if e.expires_in() > 0]
            return [CacheEntry(e.domain, e.record_type, e.value, e.expires_in(),
                               e.inserted_at, e.source) for e in live]

    def flush(self) -> None:
        with self._lock:
            self._data.clear()

    def poisoned_count(self) -> int:
        return sum(1 for e in self.dump() if e.source == "forged")


# ------------------------------------------------------- fake authoritative
def _norm(name: str) -> str:
    """Normalize a DNS name: lowercase, strip trailing dot."""
    return str(name).rstrip(".").lower()


class _FakeAuthHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try:
            query = dnslib.DNSRecord.parse(data)
        except Exception:                                   # noqa: BLE001
            return
        qname = _norm(query.q.qname)
        qtype = query.q.qtype
        zone: dict = self.server.zone
        answer_ip = zone.get(qname)
        if answer_ip is None:
            reply = query.reply()
            reply.header.rcode = getattr(dnslib.RCODE, "NXDOMAIN")
            sock.sendto(reply.pack(), self.client_address)
            return
        reply = query.reply()
        reply.add_answer(dnslib.RR(query.q.qname, qtype, rdata=dnslib.A(answer_ip),
                                   ttl=self.server.default_ttl))
        packet = bytearray(reply.pack())
        if self.server.dnssec_enabled:
            # Educational stand-in for an RRSIG: only the genuine zone owner
            # can produce this marker, and it is only trusted on the real
            # upstream channel (see resolver validation).
            packet += b"LABSIG"
        sock.sendto(bytes(packet), self.client_address)


class FakeAuthoritativeServer(threading.Thread):
    """Lab-only DNS server serving a static zone on 127.0.0.1:5301 (default)."""

    def __init__(self, zone: dict[str, str], listen_port: int = 5301, default_ttl: int = 60):
        super().__init__(daemon=True)
        self.zone = {k.rstrip(".").lower(): v for k, v in zone.items()}
        self.listen_port = listen_port
        self.default_ttl = default_ttl
        self._srv = None
        self.running = False

    def run(self):
        self._srv = socketserver.UDPServer(("127.0.0.1", self.listen_port), _FakeAuthHandler)
        self._srv.zone = self.zone
        self._srv.default_ttl = self.default_ttl
        self._srv.dnssec_enabled = True
        self.running = True
        self._srv.serve_forever(poll_interval=0.1)

    def stop(self):
        if self._srv:
            self._srv.shutdown()
            self._srv.server_close()
        self.running = False


# ------------------------------------------------------------------ resolver
class SimpleResolver(threading.Thread):
    """Recursive-ish lab resolver on UDP. Validates txn id + source port."""

    def __init__(self, listen_port: int, upstream_port: int, cache: DNSCache,
                 randomize_port: bool = True, dnssec_mode: bool = False):
        super().__init__(daemon=True)
        self.listen_port = listen_port
        self.upstream_port = upstream_port
        self.cache = cache
        self.randomize_port = randomize_port
        self.dnssec_mode = dnssec_mode
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", listen_port))
        self.sock.settimeout(0.2)
        # Windows: disable ICMP-induced connection reset reporting on UDP
        # sockets (SIO_UDP_CONNRESET) so stray resets do not kill the loop.
        SIO_UDP_CONNRESET = 0x9800000C          # IOC_IN | IOC_VENDOR | 12
        try:
            self.sock.ioctl(SIO_UDP_CONNRESET, 0)
        except (AttributeError, OSError, ValueError):
            try:
                import ctypes
                flag = ctypes.c_ulong(0)         # FALSE = disable reporting
                returned = ctypes.c_ulong()
                ctypes.windll.ws2_32.WSAIoctl(
                    self.sock.fileno(), SIO_UDP_CONNRESET,
                    ctypes.byref(flag), ctypes.sizeof(flag),
                    None, 0, ctypes.byref(returned), None, None)
            except Exception:                              # noqa: BLE001
                pass
        self.running = False
        self.pending: dict[tuple[int, int], dict] = {}     # (txn_id, src_port) -> query ctx
        self.race_hold_ms: float = 0.0   # >0 simulates upstream latency (race window)
        self.events: list[dict] = []
        self._ev_lock = threading.Lock()
        self._pending_lock = threading.Lock()

    # ---- event log
    def log_event(self, kind: str, detail: str, color: str = "gray"):
        with self._ev_lock:
            self.events.append({"ts": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                                "kind": kind, "detail": detail, "color": color})

    def drain_events(self) -> list[dict]:
        with self._ev_lock:
            out = self.events[:]
            self.events = []
            return out

    # ---- thread body
    def run(self):
        self.running = True
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except ConnectionResetError:
                # Windows: an earlier send to a closed port surfaces here.
                # Flush the error and keep serving.
                try:
                    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                except OSError:
                    pass
                continue
            except OSError:
                break
            self._handle_client_query(data, addr)
        try:
            self.sock.close()
        except OSError:
            pass

    def stop(self):
        self.running = False

    # ---- inbound query from the "stub client"
    def _handle_client_query(self, data: bytes, addr):
        try:
            query = dnslib.DNSRecord.parse(data)
        except Exception:                                   # noqa: BLE001
            return
        qname = _norm(query.q.qname)
        qtype = dnslib.QTYPE[query.q.qtype]
        self.log_event("query", f"stub {addr[0]}:{addr[1]} asks {qname} {qtype}", "blue")

        cached = self.cache.get(qname, qtype)
        if cached:
            self.log_event("cache-hit", f"{qname} -> {cached.value} (TTL {cached.expires_in()}, "
                                       f"source={cached.source})", "green" if cached.source == "legitimate" else "red")
            reply = query.reply()
            reply.add_answer(dnslib.RR(qname, getattr(dnslib.QTYPE, qtype),
                                       rdata=dnslib.A(cached.value), ttl=cached.expires_in()))
            if cached.source == "forged":
                reply.set_header_ra(False)
            self.sock.sendto(reply.pack(), addr)
            return

        # cache miss -> forward to fake authoritative
        txn_id = random.randint(0, 65535)
        src_port = random.randint(1024, 65535) if self.randomize_port else 53153
        ctx = {"qname": qname, "qtype": qtype, "client": addr, "query": query, "dnssec": self.dnssec_mode}
        with self._pending_lock:
            self.pending[(txn_id, src_port)] = ctx
        self.log_event("forward", f"cache MISS -> upstream 127.0.0.1:{self.upstream_port} "
                                  f"txn=0x{txn_id:04x} sport={src_port}", "orange")
        out_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            out_sock.bind(("127.0.0.1", src_port if self.randomize_port else 0))
        except OSError:
            src_port = 0
        out_sock.settimeout(2.0)
        # Re-encode the outbound query with OUR transaction id (0xb6c5-style);
        # the upstream echoes it back and validation compares against txn_id.
        out_pkt = _stub_query(qname, txn_id=txn_id)
        out_sock.sendto(out_pkt, ("127.0.0.1", self.upstream_port))
        try:
            resp, upstream = out_sock.recvfrom(4096)
        except socket.timeout:
            with self._pending_lock:
                self.pending.pop((txn_id, src_port), None)
            self.log_event("timeout", f"upstream did not answer {qname}", "gray")
            out_sock.close()
            return
        out_sock.close()
        # Simulate upstream latency: hold the response so the attacker has a
        # realistic race window (models WAN propagation delay).
        if self.race_hold_ms > 0:
            time.sleep(self.race_hold_ms / 1000.0)
        self._validate_and_cache(resp, upstream, txn_id, src_port, ctx)

    # ---- response validation (the heart of the lesson)
    def _validate_and_cache(self, resp: bytes, upstream, txn_id: int, src_port: int, ctx):
        # First VALID response consumes the query slot (RFC 5452 behavior):
        # the winner of the race caches the record, the loser is a late
        # duplicate and is discarded.
        if ctx.get("resolved"):
            self.log_event("late", "late/duplicate response discarded (query already answered)", "gray")
            return
        try:
            parsed = dnslib.DNSRecord.parse(resp)
        except Exception:                                   # noqa: BLE001
            self.log_event("reject", "unparseable upstream response", "red")
            return
        rid = parsed.header.id
        # VALIDATION 1: transaction id must match the outstanding query.
        if rid != txn_id:
            self.log_event("reject", f"txn ID mismatch (got 0x{rid:04x} expected 0x{txn_id:04x}) "
                                     f"- forged response REJECTED", "red")
            return
        # VALIDATION 2 (defense): with source port randomization, a spoofed
        # response must present the ephemeral source port our outgoing query
        # used - the attacker has to guess it (~1/64512 per attempt).
        from_upstream = upstream[1] == self.upstream_port
        if not from_upstream:
            if self.randomize_port and upstream[1] != src_port:
                self.log_event("reject", f"spoofed source port {upstream[1]} != ephemeral {src_port} "
                                         f"(port randomization defense) - REJECTED", "red")
                return
            if self.dnssec_mode:
                # Only the real authoritative server holds the signing key; a
                # forged RRSIG is impossible, so off-channel LABSIG is fake.
                self.log_event("reject", "DNSSEC: forged response carries no valid zone "
                                         "signature (off-channel) - REJECTED", "red")
                return
        # DNSSEC demo: fake signature check - forged packets lack a signature
        if ctx.get("dnssec"):
            has_sig = resp.find(b"LABSIG") != -1
            if not has_sig:
                self.log_event("reject", "DNSSEC: no valid RRSIG - forged response REJECTED", "red")
                return
            self.log_event("dnssec", "DNSSEC signature validated", "green")
        qname = ctx["qname"]
        qtype = ctx["qtype"]
        value = None
        for rr in parsed.rr:
            if dnslib.QTYPE[rr.rtype] == "A":
                value = str(rr.rdata)
                break
        if value is None:
            self.log_event("reject", "no A record in upstream response", "gray")
            return
        ttl = parsed.rr[0].ttl if parsed.rr else 60
        with self._pending_lock:
            self.pending.pop((txn_id, src_port), None)
        ctx["resolved"] = True
        # Attribute the record: replies from the real upstream port are
        # legitimate; anything else is attacker spoofing (educational model).
        source = "legitimate" if from_upstream else "forged"
        self.cache.put(CacheEntry(qname, qtype, value, ttl, source=source))
        if source == "forged":
            self.log_event("cache-put", f"{qname} -> {value} cached (TTL {ttl}) - "
                                        f"** CACHE POISONED by forged response **", "red")
        else:
            self.log_event("cache-put", f"{qname} -> {value} cached (TTL {ttl}, legitimate)", "green")
        # answer the original stub client (may be gone - ignore send errors)
        try:
            reply = ctx["query"].reply()
            reply.add_answer(dnslib.RR(qname, getattr(dnslib.QTYPE, qtype),
                                       rdata=dnslib.A(value), ttl=ttl))
            self.sock.sendto(reply.pack(), ctx["client"])
        except OSError:
            pass


# ------------------------------------------------------------ attack engine
@dataclass
class AttackStep:
    step_number: int
    action: str
    timestamp: datetime
    details: str
    success: bool


class AttackEngine(threading.Thread):
    """Kaminsky-style forgery demo: guess txn id and race the legitimate reply.

    Because both resolver and upstream are local, the attacker observes the
    resolver's outbound query (via the resolver event log) and races forged
    responses with guessed transaction IDs - exactly the classroom scenario.
    """

    def __init__(self, resolver, target_domain: str, forged_ip: str,
                 strategy: str = "random", max_attempts: int = 65536,
                 forged_src_port: int = 44444):
        super().__init__(daemon=True)
        self.resolver = resolver
        self.target_domain = target_domain
        self.forged_ip = forged_ip
        self.strategy = strategy
        self.max_attempts = max_attempts
        self.forged_src_port = forged_src_port
        self.cancel_event = threading.Event()
        self.attempts = 0
        self.success = False
        self.guessed_id: int | None = None
        self.cache_snapshot: list | None = None
        self._pending_sock = None
        self.log: list[dict] = []

    def _log(self, msg: str, color: str = "gray"):
        self.log.append({"ts": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                         "msg": msg, "color": color})

    def run(self):
        self._log(f"attack started: target={self.target_domain} "
                  f"forged-ip={self.forged_ip} strategy={self.strategy}", "red")
        next_id = 0
        last_trigger = 0.0
        # Flush cache so the resolver must forward a fresh upstream query.
        self.resolver.cache.flush()
        # Give the attacker a realistic race window: hold the resolver's
        # upstream reply for 120ms (models WAN propagation delay).
        self.resolver.race_hold_ms = 120.0
        try:
            while not self.cancel_event.is_set() and self.attempts < self.max_attempts:
                # discover an in-flight query: (txn, sport) pending at resolver
                with self.resolver._pending_lock:
                    pending = list(self.resolver.pending.items())
                if not pending:
                    if time.monotonic() - last_trigger > 0.08:
                        # Flush any healed legit entry so the next stub query
                        # forces a fresh upstream forward we can race against.
                        self.resolver.cache.flush()
                        if self._pending_sock:
                            try:
                                self._pending_sock.close()
                            except OSError:
                                pass
                        self._pending_sock = self._trigger_stub_query()
                        last_trigger = time.monotonic()
                    time.sleep(0.001)
                    continue
                # Freeze the race window: detach the pending ctx so only we
                # race it; the resolver's own reply will arrive after the
                # race_hold delay and be discarded if our forgery lands first.
                (txn_id, sport), ctx = pending[0]
                with self.resolver._pending_lock:
                    self.resolver.pending.pop((txn_id, sport), None)
                # guess id
                if self.strategy == "sequential":
                    guess = next_id
                    next_id = (next_id + 1) % 65536
                elif self.strategy == "known":
                    guess = txn_id                   # educational omniscience
                else:
                    guess = random.randint(0, 65535)
                # The forged packet must spoof the source port our resolver
                # queried from. When the resolver randomizes it, the attacker
                # has to guess (~1/64512 chance) - that is the defense.
                if self.resolver.randomize_port:
                    spoof_port = random.randint(1024, 65535)
                else:
                    spoof_port = sport               # predictable fixed port
                self.attempts += 1
                pkt = self._forge(ctx, guess)
                # deliver forged response to the resolver's validation
                self.resolver._validate_and_cache(
                    pkt, ("127.0.0.1", spoof_port), txn_id, sport, ctx)
                if guess == txn_id:
                    self.guessed_id = guess
                    self._log(f"guess MATCHED txn=0x{guess:04x} on attempt {self.attempts} "
                              f"- waiting for resolver verdict", "orange")
                # Success = the resolver actually cached the forged record
                # (guess alone is not enough - defenses may still reject it).
                entry = self.resolver.cache.get(self.target_domain, "A")
                if entry and entry.source == "forged":
                    self.success = True
                    # Snapshot the poisoned cache NOW: later legitimate
                    # re-resolutions may heal the cache (TTL expiry), but the
                    # verdict documents the moment of compromise.
                    self.cache_snapshot = self.resolver.cache.dump()
                    self._log(f"SUCCESS after {self.attempts} attempts: txn=0x{guess:04x} "
                              f"spoofed sport={spoof_port} - cache POISONED", "red")
                    break
                if self.attempts % 5000 == 0:
                    self._log(f"...{self.attempts} forged attempts, still guessing", "gray")
                time.sleep(0.001)
        finally:
            # Let the resolver finish validating the forged response before
            # the verdict is read (race_hold sleep may still be running).
            time.sleep(0.3)
            self.resolver.race_hold_ms = 0.0
            if self._pending_sock:
                try:
                    self._pending_sock.close()
                except OSError:
                    pass
            if self.success and not self.cache_snapshot:
                self.cache_snapshot = self.resolver.cache.dump()
        if not self.success:
            self._log(f"attack finished WITHOUT success after {self.attempts} attempts "
                      f"(defenses held)", "green")

    def _trigger_stub_query(self):
        """Fire a stub query; returns (sock, packet) so the attacker can race
        while the resolver waits on the upstream reply."""
        q = _stub_query(self.target_domain, txn_id=random.randint(0, 65535))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.5)
        try:
            sock.sendto(q, ("127.0.0.1", self.resolver.listen_port))
        except OSError:
            sock.close()
            return None
        return sock

    def _forge(self, ctx, guess: int) -> bytes:
        q = dnslib.DNSRecord(dnslib.DNSHeader(id=guess, qr=1, aa=1, ra=0),
                             q=dnslib.DNSQuestion(self.target_domain, dnslib.QTYPE.A))
        q.add_answer(dnslib.RR(self.target_domain, dnslib.QTYPE.A,
                               rdata=dnslib.A(self.forged_ip), ttl=300))
        if ctx.get("dnssec"):
            # pretend we can sign - the demo validator looks for LABSIG
            q.add_ar(dnslib.RR("labsig", dnslib.QTYPE.TXT, rdata=dnslib.TXT("LABSIG"), ttl=0))
        return q.pack()

    def stop(self):
        self.cancel_event.set()


# ----------------------------------------------------------------- verifier
def _stub_query(domain: str, txn_id: int = 0) -> bytes:
    """Build a proper stub-client DNS query packet (with header)."""
    q = dnslib.DNSRecord(dnslib.DNSHeader(id=txn_id, rd=1),
                         q=dnslib.DNSQuestion(domain, dnslib.QTYPE.A))
    return q.pack()


def verify_poisoning(resolver_port: int, domain: str) -> tuple[str | None, bool]:
    """Query the resolver for domain; returns (answer, got_answer)."""
    q = dnslib.DNSRecord(dnslib.DNSHeader(id=0x1234, rd=1),
                         q=dnslib.DNSQuestion(domain, dnslib.QTYPE.A))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    try:
        sock.sendto(q.pack(), ("127.0.0.1", resolver_port))
        data, _ = sock.recvfrom(4096)
    except socket.timeout:
        return None, False
    finally:
        sock.close()
    parsed = dnslib.DNSRecord.parse(data)
    for rr in parsed.rr:
        if dnslib.QTYPE[rr.rtype] == "A":
            return str(rr.rdata), True
    return None, False


@dataclass
class LabSession:
    lab_id: str
    timestamp: datetime
    resolver_port: int
    upstream_port: int
    target_domain: str
    legitimate_answer: str
    forged_answer: str
    port_randomization: bool
    dnssec_mode: bool
    strategy: str
    attempts: int
    poisoning_successful: bool
    cache_before: list
    cache_after: list
    steps: list
    resolver_log: list
    attack_log: list


class LabController:
    """Orchestrates one lab run: setup -> query -> attack -> verify -> teardown."""

    def __init__(self):
        self.resolver = None
        self.upstream = None
        self.attacker = None
        self.session: LabSession | None = None

    def start_lab(self, resolver_port=5311, upstream_port=5301, zone=None,
                  randomize_port=True, dnssec=False) -> tuple[bool, str]:
        ok, reason = check_isolation("127.0.0.1")
        if not ok:
            return False, reason
        self.stop_lab()
        zone = zone or {"test.lab": "203.0.113.10", "www.test.lab": "203.0.113.11",
                        "bank.test.lab": "203.0.113.12"}
        self.upstream = FakeAuthoritativeServer(zone, listen_port=upstream_port)
        self.upstream.start()
        self.resolver = SimpleResolver(resolver_port, upstream_port, DNSCache(),
                                       randomize_port=randomize_port, dnssec_mode=dnssec)
        self.resolver.start()
        time.sleep(0.2)
        return True, f"lab up: resolver :{resolver_port} upstream :{upstream_port}"

    def stop_lab(self):
        if self.resolver:
            self.resolver.stop()
            self.resolver = None
        if self.upstream:
            self.upstream.stop()
            self.upstream = None
        if self.attacker:
            self.attacker.stop()
            self.attacker = None

    def trigger_query(self, domain: str) -> tuple[str | None, str]:
        """Stub-client query through the resolver; returns (answer, status)."""
        if not self.resolver:
            return None, "lab not running"
        q = _stub_query(domain, txn_id=random.randint(0, 65535))
        # Windows can raise ConnectionResetError on UDP sockets after an
        # earlier ICMP port-unreachable; retry with a fresh socket.
        for attempt in range(3):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(4.0)
            try:
                sock.sendto(q, ("127.0.0.1", self.resolver.listen_port))
                data, _ = sock.recvfrom(4096)
                break
            except ConnectionResetError:
                if attempt == 2:
                    return None, "connection reset"
                time.sleep(0.2)
                continue
            except socket.timeout:
                return None, "timeout"
            finally:
                sock.close()
        else:
            return None, "no answer"
        parsed = dnslib.DNSRecord.parse(data)
        for rr in parsed.rr:
            if dnslib.QTYPE[rr.rtype] == "A":
                return str(rr.rdata), "ok"
        return None, "no answer"

    def run_attack(self, domain: str, forged_ip: str, strategy: str, attempts: int):
        if not self.resolver:
            return None
        self.attacker = AttackEngine(self.resolver, domain, forged_ip,
                                     strategy=strategy, max_attempts=attempts)
        self.attacker.start()
        return self.attacker


def session_from_dict(d: dict) -> LabSession:
    """Rebuild a LabSession from imported JSON (sample data or saved file)."""
    return LabSession(
        lab_id=d.get("lab_id", "imported"),
        timestamp=datetime.fromisoformat(d.get("timestamp")) if d.get("timestamp") else datetime.now(),
        resolver_port=d.get("resolver_port", 5311),
        upstream_port=d.get("upstream_port", 5301),
        target_domain=d.get("target_domain", "?"),
        legitimate_answer=d.get("legitimate_answer", ""),
        forged_answer=d.get("forged_answer", ""),
        port_randomization=d.get("port_randomization", True),
        dnssec_mode=d.get("dnssec_mode", False),
        strategy=d.get("strategy", "?"),
        attempts=int(d.get("attempts", 0)),
        poisoning_successful=bool(d.get("poisoning_successful")),
        cache_before=list(d.get("cache_before", [])),
        cache_after=list(d.get("cache_after", [])),
        steps=list(d.get("steps", [])),
        resolver_log=list(d.get("resolver_log", [])),
        attack_log=list(d.get("attack_log", [])),
    )
