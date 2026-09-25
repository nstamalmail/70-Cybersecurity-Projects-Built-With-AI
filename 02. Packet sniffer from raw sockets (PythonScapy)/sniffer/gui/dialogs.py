"""Dialogs: first-run legal/elevation notice, about box."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

NOTICE_TEXT = """\
ETHICAL USE NOTICE

Packet sniffing can expose sensitive data (passwords, tokens, personal
information). Capturing traffic on networks you do not own or are not
explicitly authorized to test may be ILLEGAL (e.g. wiretapping laws,
the Computer Fraud and Abuse Act, GDPR).

By continuing you confirm that:
  * you own the network you will capture on, or
  * you have written authorization to test it, and
  * you will not share captured payloads without redaction.

This tool is strictly passive: it never injects or modifies packets.

Run headless jobs with --yes to accept this notice non-interactively.
"""

ABOUT_TEXT = """\
PacketSniffer {version}

A GUI packet sniffer built on raw sockets (Windows SIO_RCVALL /
Linux AF_PACKET). Passive analysis only.

Layers decoded: Ethernet, VLAN, ARP, IPv4, IPv6, ICMP, ICMPv6,
TCP, UDP, DNS, HTTP, TLS (SNI), QUIC (header).

Use responsibly. See architecture.md for the full design document.
"""


def show_notice(parent) -> bool:
    """Show the first-run notice. Returns True if accepted."""
    dlg = tk.Toplevel(parent)
    dlg.title("Ethical use notice")
    dlg.transient(parent)
    dlg.grab_set()
    dlg.resizable(False, False)

    txt = tk.Text(dlg, width=68, height=14, wrap=tk.WORD, relief=tk.FLAT,
                  background="#fdf6e3", foreground="#333333")
    txt.insert("1.0", NOTICE_TEXT)
    txt.configure(state=tk.DISABLED)
    txt.pack(padx=12, pady=(12, 6))

    accepted = {"ok": False}

    def on_ok():
        accepted["ok"] = True
        dlg.destroy()

    btns = ttk.Frame(dlg)
    btns.pack(pady=(0, 12))
    ttk.Button(btns, text="I understand and accept", command=on_ok).pack(side=tk.LEFT, padx=6)
    ttk.Button(btns, text="Quit", command=dlg.destroy).pack(side=tk.LEFT, padx=6)

    dlg.protocol("WM_DELETE_WINDOW", dlg.destroy)
    parent.wait_window(dlg)
    return accepted["ok"]


def show_about(parent, version: str) -> None:
    messagebox.showinfo("About PacketSniffer", ABOUT_TEXT.format(version=version), parent=parent)


def show_error(parent, title: str, message: str) -> None:
    messagebox.showerror(title, message, parent=parent)
