"""Load balancer simulation core for LBSim: algorithms, health checks, traffic.

Simulation-only: backends are in-process mock objects; no packets are sent.
"""
from __future__ import annotations

import hashlib
import random
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime


# ---------------------------------------------------------------- health cfg
@dataclass
class HealthCheckConfig:
    check_type: str = "tcp"               # tcp | http
    interval_seconds: float = 5.0
    timeout_seconds: float = 1.0
    fall_threshold: int = 3
    rise_threshold: int = 2
    http_path: str = "/"
    expected_status: list = field(default_factory=lambda: [200])

    def to_dict(self):
        return vars(self).copy()


# ---------------------------------------------------------------- backends
class SimulatedBackend:
    """Mock backend with configurable health behavior."""

    MODES = ("healthy", "http_500", "conn_refused", "slow")

    def __init__(self, backend_id: str, name: str, address: str, weight: int = 1,
                 mode: str = "healthy"):
        self.backend_id = backend_id
        self.name = name
        self.address = address
        self.weight = max(1, int(weight))
        self.mode = mode
        self.health = "UP"
        self.consecutive_failures = 0
        self.consecutive_successes = 0
        self.active_connections = 0
        self.total_requests = 0
        self.last_check: str | None = None
        self.last_latency_ms: float | None = None

    # ---- the "probe" target: simulates L4/L7 behavior
    def probe(self, cfg: HealthCheckConfig) -> tuple[bool, float, str]:
        """Returns (passed, latency_ms, detail)."""
        started = time.monotonic()
        if self.mode == "conn_refused":
            return False, 0.0, "connection refused (simulated)"
        if self.mode == "slow":
            time.sleep(min(0.05, cfg.timeout_seconds / 10))
            latency = (time.monotonic() - started) * 1000
            if cfg.check_type == "http":
                return False, latency, "timeout (slow backend)"
            return True, latency, "tcp ok (slow)"
        if self.mode == "http_500" and cfg.check_type == "http":
            latency = (time.monotonic() - started) * 1000
            return False, latency, f"HTTP 500 (expected {cfg.expected_status})"
        latency = (time.monotonic() - started) * 1000
        return True, latency, "ok"

    def to_dict(self):
        return {
            "backend_id": self.backend_id, "name": self.name, "address": self.address,
            "weight": self.weight, "mode": self.mode, "health": self.health,
            "consecutive_failures": self.consecutive_failures,
            "consecutive_successes": self.consecutive_successes,
            "active_connections": self.active_connections,
            "total_requests": self.total_requests,
            "last_check": self.last_check,
        }


# ------------------------------------------------------------- algorithms
class RoundRobin:
    name = "round_robin"

    def __init__(self, pool):
        self.pool = pool
        self._idx = 0

    def pick(self, client_ip: str | None = None):
        healthy = self.pool.healthy()
        if not healthy:
            return None
        backend = healthy[self._idx % len(healthy)]
        self._idx += 1
        return backend


class WeightedRoundRobin:
    """Smooth WRR (nginx-style): effective weight decays as it is used."""

    name = "weighted_round_robin"

    def __init__(self, pool):
        self.pool = pool
        self._current: dict[str, int] = {}

    def pick(self, client_ip: str | None = None):
        healthy = self.pool.healthy()
        if not healthy:
            return None
        total = sum(b.weight for b in healthy)
        for b in healthy:
            self._current.setdefault(b.backend_id, 0)
        best = None
        for b in healthy:
            self._current[b.backend_id] += b.weight
            if best is None or self._current[b.backend_id] > self._current[best.backend_id]:
                best = b
        if best:
            self._current[best.backend_id] -= total
        return best


class LeastConnections:
    name = "least_connections"

    def __init__(self, pool):
        self.pool = pool

    def pick(self, client_ip: str | None = None):
        healthy = self.pool.healthy()
        if not healthy:
            return None
        return min(healthy, key=lambda b: (b.active_connections, b.total_requests))


class IPHash:
    name = "ip_hash"

    def __init__(self, pool):
        self.pool = pool

    def pick(self, client_ip: str | None = None):
        healthy = self.pool.healthy()
        if not healthy:
            return None
        if not client_ip:
            client_ip = "0.0.0.0"
        digest = hashlib.sha1(client_ip.encode()).digest()
        idx = int.from_bytes(digest[:4], "big") % len(healthy)
        return healthy[idx]


ALGORITHMS = {cls.name: cls for cls in (RoundRobin, WeightedRoundRobin, LeastConnections, IPHash)}


class BackendPool:
    def __init__(self):
        self.backends: list[SimulatedBackend] = []

    def healthy(self) -> list[SimulatedBackend]:
        return [b for b in self.backends if b.health == "UP"]

    def add(self, backend: SimulatedBackend):
        self.backends.append(backend)

    def remove(self, backend_id: str):
        self.backends = [b for b in self.backends if b.backend_id != backend_id]

    def get(self, backend_id: str) -> SimulatedBackend | None:
        for b in self.backends:
            if b.backend_id == backend_id:
                return b
        return None


# ---------------------------------------------------------- health checker
class HealthChecker(threading.Thread):
    """Periodically probes each backend and drives the fall/rise state machine."""

    def __init__(self, pool: BackendPool, cfg: HealthCheckConfig, on_event=None):
        super().__init__(daemon=True)
        self.pool = pool
        self.cfg = cfg
        self.on_event = on_event or (lambda rec: None)
        self.cancel_event = threading.Event()
        self.log: list[dict] = []

    def stop(self):
        self.cancel_event.set()

    def run(self):
        while not self.cancel_event.is_set():
            for backend in list(self.pool.backends):
                if self.cancel_event.is_set():
                    return
                passed, latency, detail = backend.probe(self.cfg)
                prev = backend.health
                if passed:
                    backend.consecutive_successes += 1
                    backend.consecutive_failures = 0
                    if prev == "DOWN" and backend.consecutive_successes >= self.cfg.rise_threshold:
                        backend.health = "UP"
                        self._record(backend, prev, "rise_threshold",
                                     f"back UP after {backend.consecutive_successes} passes")
                else:
                    backend.consecutive_failures += 1
                    backend.consecutive_successes = 0
                    if prev == "UP" and backend.consecutive_failures >= self.cfg.fall_threshold:
                        backend.health = "DOWN"
                        self._record(backend, prev, "fall_threshold",
                                     f"marked DOWN after {backend.consecutive_failures} failures")
                backend.last_check = datetime.now().strftime("%H:%M:%S")
                backend.last_latency_ms = latency
                self.log.append({
                    "ts": datetime.now().isoformat(timespec="seconds"),
                    "backend": backend.name, "passed": passed,
                    "latency_ms": round(latency, 2), "detail": detail,
                    "health": backend.health,
                })
                self.on_event(self.log[-1])
                del self.log[:-1000]
            self.cancel_event.wait(max(0.2, self.cfg.interval_seconds))

    def _record(self, backend, prev, reason, detail):
        self.on_event({"ts": datetime.now().isoformat(timespec="seconds"),
                       "backend": backend.name, "passed": None,
                       "latency_ms": 0, "detail": f"STATE {prev}->{backend.health}: {detail}",
                       "health": backend.health, "transition": True})


# -------------------------------------------------------- traffic generator
class TrafficGenerator(threading.Thread):
    """Generates simulated requests at a configured rate via the algorithm."""

    def __init__(self, pool, algorithm_name: str, rate_rps: float, on_event=None,
                 client_ips: list | None = None):
        super().__init__(daemon=True)
        self.pool = pool
        self.rate = max(0.5, float(rate_rps))
        self.on_event = on_event or (lambda rec: None)
        self.cancel_event = threading.Event()
        self.algorithm = ALGORITHMS.get(algorithm_name, RoundRobin)(pool)
        self.total_sent = 0
        self.total_failed = 0
        self.client_ips = client_ips or ["203.0.113.50", "198.51.100.20",
                                         "192.0.2.77", "203.0.113.99"]
        self.log: list[dict] = []

    def stop(self):
        self.cancel_event.set()

    def run(self):
        interval = 1.0 / self.rate
        while not self.cancel_event.is_set():
            started = time.monotonic()
            backend = self.algorithm.pick(random.choice(self.client_ips))
            if backend is None:
                self.total_failed += 1
                self.log.append({"ts": datetime.now().isoformat(timespec="seconds"),
                                 "msg": "request DROPPED - no healthy backends"})
                self.on_event(self.log[-1])
            else:
                backend.active_connections += 1
                backend.total_requests += 1
                self.total_sent += 1
                self.on_event({"backend": backend.name,
                               "total_requests": backend.total_requests,
                               "active": backend.active_connections})
                # hold the connection briefly to model request duration
                hold = 0.02 if backend.mode != "slow" else 0.08
                self.cancel_event.wait(hold)
                backend.active_connections = max(0, backend.active_connections - 1)
            # pace to the requested rate
            elapsed = time.monotonic() - started
            if elapsed < interval:
                self.cancel_event.wait(interval - elapsed)
            del self.log[:-1000]


# ------------------------------------------------------------ session model
@dataclass
class StateTransition:
    timestamp: datetime
    backend: str
    from_state: str
    to_state: str
    reason: str


@dataclass
class SimulationResult:
    simulation_id: str
    timestamp: datetime
    algorithm: str
    health_check_config: dict
    backends: list
    total_requests: int
    state_transitions: list
    health_check_log: list
    duration_seconds: float = 0.0

    def to_dict(self):
        return {
            "simulation_id": self.simulation_id,
            "timestamp": self.timestamp.isoformat(timespec="seconds"),
            "algorithm": self.algorithm,
            "health_check_config": self.health_check_config,
            "backends": self.backends,
            "total_requests": self.total_requests,
            "state_transitions": self.state_transitions,
            "health_check_log": self.health_check_log[-200:],
            "duration_seconds": self.duration_seconds,
        }


def simulation_from_dict(d: dict) -> SimulationResult:
    return SimulationResult(
        simulation_id=d.get("simulation_id", "imported"),
        timestamp=datetime.fromisoformat(d["timestamp"]) if d.get("timestamp") else datetime.now(),
        algorithm=d.get("algorithm", "?"),
        health_check_config=d.get("health_check_config", {}),
        backends=list(d.get("backends", [])),
        total_requests=int(d.get("total_requests", 0)),
        state_transitions=list(d.get("state_transitions", [])),
        health_check_log=list(d.get("health_check_log", [])),
        duration_seconds=float(d.get("duration_seconds", 0.0)),
    )
