"""WireGuard tunnel core for WGTB: key generation (curve25519), config
generation, platform adapter, QR export and session model.

Keys are generated in-process with the `cryptography` package (same
curve25519 algorithm as `wg genkey`), so the tool works without the WireGuard
CLI for provisioning. Applying interfaces still requires wg/wg-quick.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime


# ----------------------------------------------------------------- key gen
def generate_keypair() -> tuple[str, str]:
    """Generate a WireGuard keypair (base64-encoded curve25519 clamped)."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    private = X25519PrivateKey.generate()
    priv_bytes = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # WireGuard clamps private keys (wg genkey behavior)
    clamped = bytearray(priv_bytes)
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    priv_b64 = base64.b64encode(bytes(clamped)).decode()
    pub_b64 = base64.b64encode(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode()
    return priv_b64, pub_b64


def generate_psk() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def key_fingerprint(pub_key: str) -> str:
    return hashlib.sha256(pub_key.encode()).hexdigest()[:16]


# -------------------------------------------------------------- data model
@dataclass
class PeerConfig:
    peer_id: str
    name: str
    private_key: str
    public_key: str
    preshared_key: str | None
    assigned_ip: str
    allowed_ips: str
    endpoint: str | None = None
    persistent_keepalive: int | None = 25
    dns: str | None = None

    def to_dict(self, include_private: bool = False):
        d = {
            "peer_id": self.peer_id, "name": self.name,
            "public_key": self.public_key,
            "fingerprint": key_fingerprint(self.public_key),
            "preshared_key": "***" if self.preshared_key else None,
            "assigned_ip": self.assigned_ip, "allowed_ips": self.allowed_ips,
            "endpoint": self.endpoint,
            "persistent_keepalive": self.persistent_keepalive, "dns": self.dns,
        }
        if include_private:
            d["private_key"] = self.private_key
            if self.preshared_key:
                d["preshared_key"] = self.preshared_key
        return d


@dataclass
class TunnelSession:
    session_id: str
    interface_name: str
    server_private_key: str
    server_public_key: str
    server_ip: str
    server_network: str
    listen_port: int
    dns: str
    peers: list = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    status: str = "configured"

    def to_dict(self, include_private: bool = False):
        return {
            "session_id": self.session_id,
            "interface_name": self.interface_name,
            "server_public_key": self.server_public_key,
            "server_key_fingerprint": key_fingerprint(self.server_public_key),
            "server_private_key": self.server_private_key if include_private else None,
            "server_ip": self.server_ip, "server_network": self.server_network,
            "listen_port": self.listen_port, "dns": self.dns,
            "peers": [p.to_dict(include_private) for p in self.peers],
            "created_at": self.created_at.isoformat(timespec="seconds"),
            "status": self.status,
        }


def session_from_dict(d: dict) -> TunnelSession:
    peers = []
    for p in d.get("peers", []):
        peers.append(PeerConfig(
            peer_id=p.get("peer_id", uuid.uuid4().hex[:8]),
            name=p.get("name", "peer"),
            private_key=p.get("private_key", ""),
            public_key=p.get("public_key", ""),
            preshared_key=p.get("preshared_key") if p.get("preshared_key") not in (None, "***") else None,
            assigned_ip=p.get("assigned_ip", ""),
            allowed_ips=p.get("allowed_ips", ""),
            endpoint=p.get("endpoint"),
            persistent_keepalive=p.get("persistent_keepalive", 25),
            dns=p.get("dns"),
        ))
    created = d.get("created_at")
    return TunnelSession(
        session_id=d.get("session_id", "imported"),
        interface_name=d.get("interface_name", "wg0"),
        server_private_key=d.get("server_private_key", ""),
        server_public_key=d.get("server_public_key", ""),
        server_ip=d.get("server_ip", "10.0.0.1"),
        server_network=d.get("server_network", "10.0.0.0/24"),
        listen_port=int(d.get("listen_port", 51820)),
        dns=d.get("dns", "10.0.0.1"),
        peers=peers,
        created_at=datetime.fromisoformat(created) if created else datetime.now(),
        status=d.get("status", "imported"),
    )


# ------------------------------------------------------------ config generation
def generate_server_conf(sess: TunnelSession) -> str:
    lines = [
        "[Interface]",
        f"Address = {sess.server_ip}/{sess.server_network.split('/')[-1]}",
        f"ListenPort = {sess.listen_port}",
        f"PrivateKey = {sess.server_private_key}",
    ]
    if platform.system() == "Linux":
        lines += [
            "PostUp = iptables -A FORWARD -i %i -j ACCEPT; "
            "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
            "PostDown = iptables -D FORWARD -i %i -j ACCEPT; "
            "iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE",
        ]
    for p in sess.peers:
        lines += ["", "[Peer]",
                  f"# {p.name}",
                  f"PublicKey = {p.public_key}"]
        if p.preshared_key:
            lines.append(f"PresharedKey = {p.preshared_key}")
        lines.append(f"AllowedIPs = {p.assigned_ip}")
    return "\n".join(lines) + "\n"


def generate_peer_conf(sess: TunnelSession, peer: PeerConfig) -> str:
    server_endpoint = peer.endpoint or f"<SERVER_PUBLIC_IP>:{sess.listen_port}"
    lines = [
        "[Interface]",
        f"PrivateKey = {peer.private_key}",
        f"Address = {peer.assigned_ip}/{sess.server_network.split('/')[-1]}",
    ]
    if peer.dns:
        lines.append(f"DNS = {peer.dns}")
    lines += ["", "[Peer]",
              f"PublicKey = {sess.server_public_key}",
              f"Endpoint = {server_endpoint}",
              f"AllowedIPs = {peer.allowed_ips}"]
    if peer.preshared_key:
        lines.append(f"PresharedKey = {peer.preshared_key}")
    if peer.persistent_keepalive:
        lines.append(f"PersistentKeepalive = {peer.persistent_keepalive}")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------ platform adapter
def platform_info() -> dict:
    system = platform.system()
    info = {"system": system, "wg_available": False, "wg_path": None}
    candidates = ["wg"] if system != "Windows" else [
        r"C:\Program Files\WireGuard\wg.exe", "wg"]
    for cand in candidates:
        try:
            res = subprocess.run([cand, "--version"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                info["wg_available"] = True
                info["wg_path"] = cand
                break
        except (OSError, subprocess.TimeoutExpired):
            continue
    return info


def wg_show(interface: str | None = None) -> str:
    """Run `wg show` if available; raises FileNotFoundError if not installed."""
    system = platform.system()
    candidates = ([r"C:\Program Files\WireGuard\wg.exe", "wg"] if system == "Windows"
                  else ["wg"])
    for cand in candidates:
        try:
            cmd = [cand, "show"] + ([interface] if interface else [])
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                return res.stdout
        except FileNotFoundError:
            continue
        except (OSError, subprocess.TimeoutExpired):
            continue
    raise FileNotFoundError("wg CLI not found - install WireGuard to query live status")


def parse_wg_show(output: str) -> list[dict]:
    """Parse `wg show` output into peer status dicts."""
    peers: list[dict] = []
    current: dict | None = None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("peer:"):
            if current:
                peers.append(current)
            current = {"public_key": line.split(":", 1)[1].strip(), "handshake": None,
                       "transfer_rx": None, "transfer_tx": None, "endpoint": None,
                       "allowed_ips": None}
        elif current:
            if line.startswith("endpoint:"):
                current["endpoint"] = line.split(":", 1)[1].strip()
            elif line.startswith("allowed ips:"):
                current["allowed_ips"] = line.split(":", 1)[1].strip()
            elif line.startswith("latest handshake:"):
                current["handshake"] = line.split(":", 1)[1].strip()
            elif line.startswith("transfer:"):
                part = line.split(":", 1)[1].strip()
                rx, _, tx = part.partition("received, ")
                current["transfer_rx"] = rx.replace("received", "").strip()
                current["transfer_tx"] = tx.replace("sent", "").strip()
    if current:
        peers.append(current)
    return peers


# ---------------------------------------------------------------- QR export
def qr_png_path(content: str, path: str) -> str:
    """Render a QR code PNG for a peer config (for mobile import)."""
    import qrcode
    img = qrcode.make(content)
    img.save(path)
    return path


# ----------------------------------------------------------------- creation
def create_session(interface_name: str, server_network: str, listen_port: int,
                   dns: str, server_ip: str | None = None) -> TunnelSession:
    priv, pub = generate_keypair()
    network = server_network.split("/")[0]
    if server_ip is None:
        server_ip = ".".join(network.split(".")[:3]) + ".1"
    return TunnelSession(
        session_id=uuid.uuid4().hex[:10],
        interface_name=interface_name or "wg0",
        server_private_key=priv,
        server_public_key=pub,
        server_ip=server_ip,
        server_network=server_network,
        listen_port=listen_port,
        dns=dns or server_ip,
    )


def add_peer(sess: TunnelSession, name: str, with_psk: bool = True,
             allowed_ips: str = "0.0.0.0/0") -> PeerConfig:
    used = {int(p.assigned_ip.split(".")[3].split("/")[0])
            for p in sess.peers if p.assigned_ip}
    base = ".".join(sess.server_network.split("/")[0].split(".")[:3])
    next_host = 2
    while next_host in used:
        next_host += 1
    priv, pub = generate_keypair()
    peer = PeerConfig(
        peer_id=uuid.uuid4().hex[:8],
        name=name or f"peer{next_host}",
        private_key=priv, public_key=pub,
        preshared_key=generate_psk() if with_psk else None,
        assigned_ip=f"{base}.{next_host}",
        allowed_ips=allowed_ips,
        dns=sess.dns,
    )
    sess.peers.append(peer)
    return peer
