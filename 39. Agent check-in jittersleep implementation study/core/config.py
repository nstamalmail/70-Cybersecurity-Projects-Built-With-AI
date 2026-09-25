"""Core configuration dataclasses for the Agent Check-in Jitter/Sleep Study.

Pure data + (de)serialization. No GUI, no I/O beyond JSON helpers.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List

STRATEGIES = ("fixed", "uniform", "decorrelated", "equal")

STRATEGY_LABELS = {
    "fixed": "Fixed (deterministic)",
    "uniform": "Uniform jitter",
    "decorrelated": "Decorrelated (AWS)",
    "equal": "Equal/Full jitter",
}


@dataclass
class CheckinProfile:
    """One homogeneous group of agents sharing a scheduling strategy."""
    name: str = "profile-1"
    strategy: str = "uniform"
    base_delay_s: float = 30.0
    jitter_s: float = 10.0
    cap_s: float = 300.0
    multiplier: float = 3.0
    startup_spread_s: float = 0.0
    agent_count: int = 5
    seed: int = 42

    def validate(self) -> List[str]:
        errs: List[str] = []
        if not self.name or not self.name.strip():
            errs.append("Profile name must not be empty")
        if self.strategy not in STRATEGIES:
            errs.append(f"Unknown strategy: {self.strategy!r}")
        if self.base_delay_s <= 0:
            errs.append("base_delay_s must be > 0")
        if self.jitter_s < 0:
            errs.append("jitter_s must be >= 0")
        if self.cap_s < self.base_delay_s:
            errs.append("cap_s must be >= base_delay_s")
        if self.multiplier <= 1.0:
            errs.append("multiplier must be > 1.0")
        if self.startup_spread_s < 0:
            errs.append("startup_spread_s must be >= 0")
        if self.agent_count < 1:
            errs.append("agent_count must be >= 1")
        return errs

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CheckinProfile":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class ServerConfig:
    """Simulated target server: latency, failures, lockout."""
    failure_rate: float = 0.0
    latency_min_ms: int = 20
    latency_max_ms: int = 120
    lockout_after_failures: int = 0   # 0 disables lockouts
    lockout_duration_s: float = 30.0
    bucket_s: float = 10.0            # load-bucket size for the arrival histogram

    def validate(self) -> List[str]:
        errs: List[str] = []
        if not (0.0 <= self.failure_rate <= 1.0):
            errs.append("failure_rate must be in [0, 1]")
        if self.latency_min_ms < 0 or self.latency_max_ms < self.latency_min_ms:
            errs.append("latency range invalid")
        if self.lockout_after_failures < 0:
            errs.append("lockout_after_failures must be >= 0")
        if self.lockout_duration_s < 0:
            errs.append("lockout_duration_s must be >= 0")
        if self.bucket_s <= 0:
            errs.append("bucket_s must be > 0")
        return errs

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ServerConfig":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class AppConfig:
    """Whole-run configuration."""
    profiles: List[CheckinProfile] = field(default_factory=lambda: [CheckinProfile()])
    server: ServerConfig = field(default_factory=ServerConfig)
    seed: int = 1234
    duration_s: float = 0.0            # 0 = run until stopped
    speed: float = 1.0                 # 1x real time ... 100x accelerated

    def validate(self) -> List[str]:
        errs: List[str] = []
        if not self.profiles:
            errs.append("At least one profile is required")
        if self.seed < 0:
            errs.append("seed must be >= 0")
        if self.duration_s < 0:
            errs.append("duration_s must be >= 0")
        if not (0.1 <= self.speed <= 100.0):
            errs.append("speed must be in [0.1, 100]")
        names = [p.name for p in self.profiles]
        if len(names) != len(set(names)):
            errs.append("Profile names must be unique")
        for p in self.profiles:
            for e in p.validate():
                errs.append(f"[{p.name}] {e}")
        errs.extend(self.server.validate())
        return errs

    def fingerprint(self) -> str:
        payload = json.dumps(self.to_dict(), sort_keys=True).encode()
        return hashlib.sha256(payload).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profiles": [p.to_dict() for p in self.profiles],
            "server": self.server.to_dict(),
            "seed": self.seed,
            "duration_s": self.duration_s,
            "speed": self.speed,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AppConfig":
        return cls(
            profiles=[CheckinProfile.from_dict(p) for p in d.get("profiles", [])],
            server=ServerConfig.from_dict(d.get("server", {})),
            seed=d.get("seed", 1234),
            duration_s=d.get("duration_s", 0.0),
            speed=d.get("speed", 1.0),
        )
