"""Notebook tab views. Each has ``frame`` and ``update_result(res)``."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from src import __version__
from src.gui.panels import (chunked_insert, draw_pie, draw_timeline, fmt_bytes,
                            make_text, make_tree, set_text, style_verdict_tags)
from src.simulator.scenario import BROWSER_JA3


class FlowsView:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent)
        bar = ttk.Frame(self.frame)
        bar.pack(fill="x", padx=6, pady=(6, 0))
        ttk.Label(bar, text="Filter contains:").pack(side="left")
        self.filter_var = tk.StringVar()
        ent = ttk.Entry(bar, textvariable=self.filter_var, width=32)
        ent.pack(side="left", padx=6)
        ent.bind("<KeyRelease>", lambda _e: self._refresh())
        self.count_var = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.count_var).pack(side="left", padx=12)
        cols = ("ts", "src", "dst", "dport", "proto", "app", "sni", "host", "uri", "ja3", "family", "verdict")
        heads = ("Time", "Source", "Destination", "DPort", "Proto", "App",
                 "SNI", "Host", "URI", "JA3", "Family", "Verdict")
        outer, self.tree = make_tree(self.frame, cols, heads,
                                     (70, 90, 100, 50, 50, 50, 110, 110, 220, 110, 80, 80))
        style_verdict_tags(self.tree)
        outer.pack(fill="both", expand=True, padx=6, pady=6)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.all_rows: list[tuple[tuple, str]] = []
        self.detail_frame, self.detail = make_text(self.frame, height=6)
        self.detail_frame.pack(fill="x", padx=6, pady=(0, 6))

    def _refresh(self):
        needle = self.filter_var.get().lower()
        rows = [r for r in self.all_rows
                if not needle or any(needle in str(v).lower() for v in r[0])]
        self.count_var.set(f"{len(rows)} / {len(self.all_rows)} flows")
        chunked_insert(self.tree, rows)

    _FIELDS = ("time", "src", "dst", "dport", "proto", "app",
               "sni", "host", "uri", "ja3", "family", "verdict")

    def _on_select(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        values = self.tree.item(sel[0], "values")
        set_text(self.detail, "\n".join(f"{c:8s}: {v}" for c, v in zip(self._FIELDS, values)))

    def update_result(self, res):
        self.all_rows = [(f.to_row(), f.verdict) for f in res.flows]
        self._refresh()


class TLSView:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent)
        ttk.Label(self.frame, text="TLS fingerprint clusters (JA3-style, synthetic)",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=6, pady=(6, 2))
        cols = ("ja3", "dsts", "flows", "sample_sni", "sample_host")
        outer, self.tree = make_tree(self.frame, cols,
                                     ("Fingerprint", "Distinct destinations", "Flows",
                                      "Sample SNI", "Sample Host"),
                                     (180, 130, 70, 160, 160))
        outer.pack(fill="both", expand=True, padx=6, pady=6)
        self.detail_frame, self.detail = make_text(self.frame, height=8)
        self.detail_frame.pack(fill="x", padx=6, pady=(0, 6))
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

    def _on_select(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        ja3, dsts, flows, sni, host = self.tree.item(sel[0], "values")
        set_text(self.detail,
                 f"fingerprint : {ja3}\ndestinations : {dsts}\nflows        : {flows}\n"
                 f"sample SNI   : {sni}\nsample Host  : {host}\n\n"
                 "One ClientHello shape reused across many destinations is tooling,\n"
                 "not users. Compare against the allow-listed browser cluster.")

    def update_result(self, res):
        clusters: dict[str, dict] = {}
        for f in res.flows:
            if f.app != "http" or not f.ja3:
                continue
            c = clusters.setdefault(f.ja3, {"dsts": set(), "n": 0, "sni": f.sni, "host": f.host})
            c["dsts"].add(f.dst)
            c["n"] += 1
        rows = [((ja3, str(len(c["dsts"])), c["n"], c["sni"] or "-", c["host"] or "-"),
                 "malicious" if ja3 != BROWSER_JA3 else "clean")
                for ja3, c in sorted(clusters.items(), key=lambda kv: -len(kv[1]["dsts"]))]
        chunked_insert(self.tree, rows)


class BeaconView:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent)
        ttk.Label(self.frame, text="Inter-arrival rhythm per (source → destination, fingerprint)",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=6, pady=(6, 2))
        cols = ("group", "n", "mean", "stddev", "cv", "verdict")
        outer, self.tree = make_tree(self.frame, cols,
                                     ("Group", "Flows", "Mean IAT (s)", "StdDev (s)", "CV", "Assessment"),
                                     (220, 60, 90, 90, 70, 200))
        style_verdict_tags(self.tree)
        outer.pack(fill="both", expand=True, padx=6, pady=6)
        self.detail_frame, self.detail = make_text(self.frame, height=7)
        self.detail_frame.pack(fill="x", padx=6, pady=(0, 6))
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.cv_max = 0.15

    def _on_select(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        group, n, mu, sd, cv, _v = self.tree.item(sel[0], "values")
        verdict = "BEACON-LIKE" if float(cv) <= self.cv_max else "human-ish / too sparse"
        set_text(self.detail,
                 f"group     : {group}\nflows     : {n}\nmean IAT  : {mu}s\n"
                 f"stddev    : {sd}s\ncv        : {cv}  →  {verdict}\n\n"
                 "CV = stddev / mean. Low CV = machine rhythm. NTP is perfectly\n"
                 "periodic too — which is why context (D3/D6/D8) must corroborate.")

    def update_result(self, res):
        from statistics import mean, pstdev
        groups: dict[tuple, list[float]] = {}
        for f in res.flows:
            if f.app == "http":
                groups.setdefault((f.src, f.ja3 or "?"), []).append(f.ts)
        rows = []
        for (src, ja3), ts in sorted(groups.items()):
            if len(ts) < 3:
                continue
            ts = sorted(ts)
            iats = [b - a for a, b in zip(ts, ts[1:])]
            mu = mean(iats)
            cv = pstdev(iats) / mu if mu > 0 else 1.0
            beacon = cv <= self.cv_max
            tag = "malicious" if beacon and ja3 != BROWSER_JA3 else "clean"
            rows.append(((f"{src}  [{ja3[:24]}]", str(len(ts)),
                          f"{mu:.1f}", f"{pstdev(iats):.1f}", f"{cv:.3f}",
                          "beacon-like" if beacon else "irregular"), tag))
        chunked_insert(self.tree, rows)


class DetectionsView:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent)
        cols = ("rule", "sev", "score", "group", "evidence")
        outer, self.tree = make_tree(self.frame, cols,
                                     ("Rule", "Severity", "Score", "Group", "Evidence"),
                                     (60, 90, 60, 180, 480))
        outer.pack(fill="both", expand=True, padx=6, pady=6)
        self.detail_frame, self.detail = make_text(self.frame, height=9)
        self.detail_frame.pack(fill="x", padx=6, pady=(0, 6))
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

    def _on_select(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        rule, sev, score, group, evidence = self.tree.item(sel[0], "values")
        full = next((f for f in self._findings if f.rule_id == rule and f.group_key == group), None)
        if full:
            set_text(self.detail,
                     f"{full.rule_id} — {full.title}   [{full.severity}, score {full.score}]\n"
                     f"{'-' * 70}\nEVIDENCE:\n  {full.evidence}\n\nWHY IT MATTERS:\n  {full.explanation}")

    def update_result(self, res):
        self._findings = res.findings
        rows = [(f.to_row(), "malicious" if f.severity in ("critical", "high") else
                 ("suspicious" if f.severity == "medium" else "clean"))
                for f in res.findings]
        chunked_insert(self.tree, rows)


class PcapView:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent)
        top = ttk.Frame(self.frame)
        top.pack(fill="x", padx=6, pady=6)
        self.info = tk.StringVar(value="Run a scenario to generate artifacts.")
        ttk.Label(self.frame, textvariable=self.info, justify="left",
                  font=("Consolas", 10)).pack(anchor="w", padx=6)
        self.paths = tk.Text(self.frame, height=10, state="disabled",
                             font=("Consolas", 9), background="#fafafa")
        self.paths.pack(fill="both", expand=True, padx=6, pady=6)
        btns = ttk.Frame(self.frame)
        btns.pack(fill="x", padx=6, pady=(0, 6))
        ttk.Button(btns, text="Open artifacts folder",
                   command=self._open_folder).pack(side="left")
        ttk.Label(self.frame, foreground="#616161", wraplength=860, justify="left",
                  text=("Frames are synthetic Ethernet/IPv4/UDP/TCP written locally. Open the PCAP in "
                        "Wireshark on an isolated lab host to inspect the SNI/Host disjunction, "
                        "beacon cadence and TTL cohorts yourself.")).pack(anchor="w", padx=6)

    def _open_folder(self):
        import subprocess
        from pathlib import Path
        p = Path("artifacts").resolve()
        p.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.Popen(["explorer", str(p)])
        except OSError:
            pass

    def update_result(self, res):
        info = res.pcap_info
        self.info.set(f"PCAP: {info.path}\nframes: {info.frames}   size: {fmt_bytes(info.size_bytes)}   "
                      f"sha256: {info.sha256[:32]}…")
        lines = "\n".join(f"{k:10s} {v}" for k, v in sorted(res.artifact_paths.items()))
        set_text(self.paths, lines)


class ZtnView:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent)
        cols = ("src", "verdict", "score", "rules", "reasons")
        outer, self.tree = make_tree(self.frame, cols,
                                     ("Source host", "Policy verdict", "Score", "Triggered rules", "Reasons"),
                                     (100, 100, 60, 140, 420))
        style_verdict_tags(self.tree)
        outer.pack(fill="both", expand=True, padx=6, pady=6)
        self.detail_frame, self.detail = make_text(self.frame, height=6)
        self.detail_frame.pack(fill="x", padx=6, pady=(0, 6))
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

    def _on_select(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        src, verdict, score, rules, reasons = self.tree.item(sel[0], "values")
        set_text(self.detail,
                 f"{src} → {verdict.upper()} (score {score}, rules: {rules})\n{reasons}")

    def update_result(self, res):
        rows = []
        for d in res.ztn.decisions:
            tag = "malicious" if d.verdict == "deny" else ("suspicious" if d.verdict == "verify" else "clean")
            rows.append((d.to_row(), tag))
        chunked_insert(self.tree, rows)
        counts = res.ztn.counts
        set_text(self.detail, f"policy outcome: {counts['allow']} allow · "
                              f"{counts['verify']} verify · {counts['deny']} deny")


class AboutView:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent)
        txt = (
            "C2 TRAFFIC OBFUSCATION — DETECTION-FOCUSED TRAINING WORKBENCH\n"
            f"version {__version__}\n"
            "\n"
            "WHAT THIS IS\n"
            "  An offline, synthetic-traffic lab for blue teams. It fabricates the\n"
            "  network *appearance* of domain-fronting style C2 (plus decoys) and\n"
            "  runs nine transparent detections over it. Every packet is generated\n"
            "  locally; nothing is captured, sent, or resolved.\n"
            "\n"
            "SAFETY CONTRACT\n"
            "  • No network I/O — enforced by a static AST guard (src/safety.py).\n"
            "  • IPs restricted to RFC 5737 documentation ranges (192.0.2.0/24,\n"
            "    198.51.100.0/24, 203.0.113.0/24); domains to .example/.invalid.\n"
            "  • No real payloads — didactic placeholder markers only.\n"
            "  • Purpose: teach defenders why obfuscation leaks signals.\n"
            "\n"
            "THE NINE DETECTIONS\n"
            "  D1 SNI/Host disjunction — the fronting signature itself\n"
            "  D2 Beacon periodicity — machine rhythm in arrival times\n"
            "  D3 TLS fingerprint clusters — one tool, many destinations\n"
            "  D4 High-entropy bodies — layered/encrypted content shape\n"
            "  D5 DGA-like hostnames — algorithmic naming statistics\n"
            "  D6 Rare-SNI pivoting — fan-out geometry of tunnel setup\n"
            "  D7 URI anomalies — the bulk cost of encoding layers\n"
            "  D8 TTL cohorts — shared generator artifacts\n"
            "  D9 Decoy discrimination — benign NTP rhythm must stay quiet\n"
            "\n"
            "WORKFLOW\n"
            "  1. Pick a scenario (try 'C2 — Domain Fronting' first).\n"
            "  2. Click Run — simulation, detection and zero-trust policy run.\n"
            "  3. Explore tabs; select table rows for explanations.\n"
            "  4. Export artifacts and open the PCAP in Wireshark to verify.\n"
            "\n"
            "  Deterministic: same scenario + seed ⇒ byte-identical PCAP.\n"
        )
        detail_frame, self.text = make_text(self.frame, height=10)
        detail_frame.pack(fill="both", expand=True, padx=6, pady=6)
        set_text(self.text, txt)


class DashboardView:
    title = "Dashboard"

    def __init__(self, parent):
        self.frame = ttk.Frame(parent)
        top = ttk.Frame(self.frame)
        top.pack(fill="x", padx=6, pady=6)

        # Verdict pie (left) + scenario description (right)
        self.pie = tk.Canvas(top, width=330, height=180, highlightthickness=0,
                             background="#ffffff")
        self.pie.pack(side="left")
        self.summary = tk.StringVar(value="Run a scenario to populate the dashboard.")
        ttk.Label(top, textvariable=self.summary, justify="left",
                  font=("Segoe UI", 10), wraplength=560).pack(side="left", padx=12)

        self.timeline = tk.Canvas(self.frame, height=95, highlightthickness=0,
                                  background="#ffffff")
        self.timeline.pack(fill="x", padx=6)
        ttk.Label(self.frame, text="Top talkers",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=6)
        cols = ("src", "flows", "malicious", "suspicious", "dsts")
        outer, self.tree = make_tree(self.frame, cols,
                                     ("Source", "Flows", "Malicious", "Suspicious", "Distinct destinations"),
                                     (110, 70, 90, 90, 160))
        style_verdict_tags(self.tree)
        outer.pack(fill="both", expand=True, padx=6, pady=6)

    def update_result(self, res):
        from src.simulator.scenario import get_scenario
        cfg = get_scenario(res.scenario)
        c = res.verdict_counts
        draw_pie(self.pie, c, size=150)
        draw_timeline(self.timeline, res.flows, res.findings)
        rules = sorted({f.rule_id for f in res.findings})
        self.summary.set(
            f"{cfg.label}\n{cfg.description}\n\n"
            f"seed {res.seed} · {len(res.flows)} flows · findings: {', '.join(rules) or 'none'}\n"
            f"verdicts — {c['malicious']} malicious · {c['suspicious']} suspicious · {c['clean']} clean")
        # top talkers
        stats: dict[str, dict] = {}
        for f in res.flows:
            s = stats.setdefault(f.src, {"n": 0, "m": 0, "s": 0, "dsts": set()})
            s["n"] += 1
            s["dsts"].add(f.dst)
            if f.verdict == "malicious":
                s["m"] += 1
            elif f.verdict == "suspicious":
                s["s"] += 1
        rows = [((src, str(s["n"]), str(s["m"]), str(s["s"]), str(len(s["dsts"]))),
                 "malicious" if s["m"] else ("suspicious" if s["s"] else "clean"))
                for src, s in sorted(stats.items(), key=lambda kv: (-kv[1]["m"], -kv[1]["s"]))]
        chunked_insert(self.tree, rows)
