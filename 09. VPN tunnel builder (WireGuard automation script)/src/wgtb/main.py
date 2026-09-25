"""WGTB - WireGuard Tunnel Builder. Main Qt application."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PySide6.QtCore import Qt, Slot                                # noqa: E402
from PySide6.QtGui import QAction, QPixmap                          # noqa: E402
from PySide6.QtWidgets import (                                     # noqa: E402
    QApplication, QCheckBox, QFileDialog, QFormLayout, QGroupBox,
    QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit, QMainWindow,
    QMessageBox, QPlainTextEdit, QPushButton, QSpinBox, QSplitter,
    QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget,
)

import theme                                                        # noqa: E402
import reporting                                                    # noqa: E402
import engine                                                       # noqa: E402
from engine import (                                                # noqa: E402
    add_peer, create_session, generate_peer_conf, generate_server_conf,
    key_fingerprint, parse_wg_show, platform_info, qr_png_path,
    session_from_dict, wg_show,
)

APP_NAME = "WGTB - WireGuard Tunnel Builder"
VERSION = "1.0.0"


def _data_dir():
    base = os.environ.get("WGTB_DATA", os.path.expanduser("~/.wgtb"))
    os.makedirs(base, exist_ok=True)
    return base


def _samples_dir():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    d = os.path.join(here, "sample_data")
    return d if os.path.isdir(d) else here


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{VERSION}")
        self.resize(1180, 790)
        self.session = None
        central = QWidget()
        root = QVBoxLayout(central)
        self._build_menu()

        head = QHBoxLayout()
        t = QLabel("WGTB - WireGuard Tunnel Builder")
        t.setObjectName("banner")
        head.addWidget(t)
        head.addStretch(1)
        pf = platform_info()
        wg_state = "wg CLI available" if pf["wg_available"] else "wg CLI not found (provisioning only)"
        lab = QLabel(wg_state)
        lab.setObjectName("dim")
        head.addWidget(lab)
        root.addLayout(head)

        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        # ---------------- Setup tab
        setup_tab = QWidget()
        tabs.addTab(setup_tab, "Tunnel Setup")
        sv = QVBoxLayout(setup_tab)

        cfg = QGroupBox("Server Configuration")
        form = QFormLayout(cfg)
        self.iface_edit = QLineEdit("wg0")
        self.network_edit = QLineEdit("10.0.0.0/24")
        self.port_spin = QSpinBox(); self.port_spin.setRange(1, 65535); self.port_spin.setValue(51820)
        self.dns_edit = QLineEdit("10.0.0.1")
        self.endpoint_edit = QLineEdit()
        self.endpoint_edit.setPlaceholderText("server public IP or hostname (used in peer configs)")
        self.psk_check = QCheckBox("Use preshared keys (post-quantum resistance)")
        self.psk_check.setChecked(True)
        self.fulltunnel_check = QCheckBox("Peer AllowedIPs = 0.0.0.0/0 (full-tunnel)")
        self.fulltunnel_check.setChecked(True)
        form.addRow("Interface name:", self.iface_edit)
        form.addRow("Tunnel network:", self.network_edit)
        form.addRow("Listen port:", self.port_spin)
        form.addRow("DNS:", self.dns_edit)
        form.addRow("Server endpoint:", self.endpoint_edit)
        form.addRow("", self.psk_check)
        form.addRow("", self.fulltunnel_check)
        sv.addWidget(cfg)

        row = QHBoxLayout()
        self.new_btn = QPushButton("New Tunnel / Generate Keys")
        self.new_btn.setObjectName("primary")
        self.add_peer_btn = QPushButton("Add Peer")
        self.add_peer_btn.setEnabled(False)
        self.remove_peer_btn = QPushButton("Remove Selected Peer")
        self.remove_peer_btn.setEnabled(False)
        self.import_btn = QPushButton("Import Session...")
        self.export_btn = QPushButton("Export Report...")
        self.export_btn.setEnabled(False)
        row.addWidget(self.new_btn)
        row.addWidget(self.add_peer_btn)
        row.addWidget(self.remove_peer_btn)
        row.addStretch(1)
        row.addWidget(self.import_btn)
        row.addWidget(self.export_btn)
        sv.addLayout(row)

        self.peer_tbl = QTableWidget(0, 5)
        self.peer_tbl.setHorizontalHeaderLabels(
            ["Name", "Tunnel IP", "Allowed IPs", "Key Fingerprint", "PSK"])
        self.peer_tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.peer_tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.peer_tbl.setSelectionBehavior(QTableWidget.SelectRows)
        sv.addWidget(self.peer_tbl, 1)

        # ---------------- Configs tab
        conf_tab = QWidget()
        tabs.addTab(conf_tab, "Configs & QR")
        cv = QVBoxLayout(conf_tab)
        split = QSplitter(Qt.Horizontal)
        left = QWidget(); self._left = left
        lv = QVBoxLayout(left); lv.setContentsMargins(0, 0, 0, 0)
        lv.addWidget(QLabel("Generated configs"))
        self.conf_view = QPlainTextEdit()
        self.conf_view.setObjectName("conf")
        self.conf_view.setReadOnly(True)
        lv.addWidget(self.conf_view)
        split.addWidget(left)
        right = QWidget(); self._right = right
        rv = QVBoxLayout(right); rv.setContentsMargins(0, 0, 0, 0)
        rv.addWidget(QLabel("Peer QR code (mobile import)"))
        self.qr_label = QLabel("select a peer")
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.qr_label.setMinimumSize(240, 240)
        self.qr_label.setStyleSheet(f"background:{theme.PANEL}; border:1px solid {theme.BORDER};")
        rv.addWidget(self.qr_label, 1)
        qr_row = QHBoxLayout()
        self.save_qr_btn = QPushButton("Save QR PNG...")
        self.save_qr_btn.setEnabled(False)
        self.save_conf_btn = QPushButton("Save Peer .conf...")
        self.save_conf_btn.setEnabled(False)
        qr_row.addWidget(self.save_qr_btn)
        qr_row.addWidget(self.save_conf_btn)
        qr_row.addStretch(1)
        rv.addLayout(qr_row)
        split.addWidget(right)
        split.setSizes([3, 2])
        cv.addWidget(split, 1)

        # ---------------- Status tab
        status_tab = QWidget()
        tabs.addTab(status_tab, "Live Status")
        stv = QVBoxLayout(status_tab)
        srow = QHBoxLayout()
        self.status_btn = QPushButton("Query wg show")
        self.status_out = QPlainTextEdit()
        self.status_out.setObjectName("console")
        self.status_out.setReadOnly(True)
        srow.addWidget(self.status_btn)
        srow.addStretch(1)
        stv.addLayout(srow)
        stv.addWidget(self.status_out, 1)

        # ---------------- About
        about_tab = QWidget()
        tabs.addTab(about_tab, "About / Security")
        av = QVBoxLayout(about_tab)
        about = QLabel(
            "<h2>WGTB</h2>"
            "<p>Zero-touch WireGuard provisioning: generates a server + peer setup with "
            "curve25519 keys (same algorithm as <code>wg genkey</code>), produces "
            "<code>wg-quick</code> INI configs and QR codes for mobile clients.</p>"
            "<p><b>Workflow:</b> configure server &rarr; generate keys &rarr; add peers "
            "(auto-assigned tunnel IPs) &rarr; export server .conf &amp; peer configs/QRs "
            "&rarr; apply with <code>wg-quick up</code> (Linux/macOS) or the WireGuard app "
            "(Windows service install) &rarr; verify with <code>wg show</code>.</p>"
            "<p><b>Security:</b> private keys are never shown in full or included in "
            "reports; distribute peer configs only over secure channels. Applying an "
            "interface requires admin/root.</p>")
        about.setWordWrap(True)
        about.setAlignment(Qt.AlignTop)
        av.addWidget(about)

        self._wire()
        self.setCentralWidget(central)

    def _build_menu(self):
        bar = self.menuBar()
        m_file = bar.addMenu("&File")
        act_import = QAction("Import Session (JSON)...", self)
        act_import.setShortcut("Ctrl+I")
        act_import.triggered.connect(self.import_session)
        act_quit = QAction("Exit", self)
        act_quit.triggered.connect(self.close)
        m_file.addAction(act_import)
        m_file.addSeparator()
        m_file.addAction(act_quit)

    def _wire(self):
        self.new_btn.clicked.connect(self.new_tunnel)
        self.add_peer_btn.clicked.connect(self.add_peer_action)
        self.remove_peer_btn.clicked.connect(self.remove_peer_action)
        self.import_btn.clicked.connect(self.import_session)
        self.export_btn.clicked.connect(self.export_report)
        self.peer_tbl.doubleClicked.connect(self.show_peer_config)
        self.save_qr_btn.clicked.connect(self.save_qr)
        self.save_conf_btn.clicked.connect(self.save_peer_conf)
        self.status_btn.clicked.connect(self.query_status)

    # ------------------------------------------------------------ sessions
    @Slot()
    def new_tunnel(self):
        try:
            sess = create_session(self.iface_edit.text().strip(),
                                  self.network_edit.text().strip() or "10.0.0.0/24",
                                  self.port_spin.value(),
                                  self.dns_edit.text().strip())
        except Exception as exc:                              # noqa: BLE001
            QMessageBox.critical(self, APP_NAME, f"Key generation failed: {exc}")
            return
        self.session = sess
        self._log(f"session {sess.session_id} created; server key "
                  f"{key_fingerprint(sess.server_public_key)}")
        self._refresh()

    @Slot()
    def add_peer_action(self):
        if not self.session:
            return
        name, ok = QInputDialog.getText(self, "Add Peer", "Peer name:")
        if not ok:
            return
        allowed = "0.0.0.0/0" if self.fulltunnel_check.isChecked() else \
            self.session.server_network
        endpoint = self.endpoint_edit.text().strip() or None
        peer = add_peer(self.session, name.strip(),
                        with_psk=self.psk_check.isChecked(), allowed_ips=allowed)
        if endpoint:
            peer.endpoint = f"{endpoint}:{self.session.listen_port}"
        self._log(f"peer '{peer.name}' added: {peer.assigned_ip} "
                  f"key {key_fingerprint(peer.public_key)}")
        self._refresh()

    @Slot()
    def remove_peer_action(self):
        if not self.session:
            return
        row = self.peer_tbl.currentRow()
        if 0 <= row < len(self.session.peers):
            peer = self.session.peers.pop(row)
            self._log(f"peer '{peer.name}' removed")
            self._refresh()

    def _refresh(self):
        self.peer_tbl.setRowCount(0)
        if not self.session:
            return
        for p in self.session.peers:
            row = self.peer_tbl.rowCount()
            self.peer_tbl.insertRow(row)
            for col, v in enumerate([p.name, p.assigned_ip, p.allowed_ips,
                                     key_fingerprint(p.public_key),
                                     "yes" if p.preshared_key else "no"]):
                self.peer_tbl.setItem(row, col, QTableWidgetItem(v))
        self.add_peer_btn.setEnabled(True)
        self.remove_peer_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        # select the first peer so the QR/config panes populate
        if self.session.peers:
            self.peer_tbl.selectRow(0)
        # show server config by default
        self.conf_view.setPlainText(generate_server_conf(self.session))
        self._render_selected_qr()

    def _selected_peer(self):
        row = self.peer_tbl.currentRow()
        if self.session and 0 <= row < len(self.session.peers):
            return self.session.peers[row]
        return None

    def _render_selected_qr(self):
        peer = self._selected_peer()
        if not peer:
            self.qr_label.setText("select a peer")
            self.qr_label.setPixmap(QPixmap())
            self.save_qr_btn.setEnabled(False)
            self.save_conf_btn.setEnabled(False)
            return
        conf = generate_peer_conf(self.session, peer)
        try:
            import io
            import qrcode
            img = qrcode.make(conf)
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            from PySide6.QtCore import QBuffer
            pixmap = QPixmap()
            pixmap.loadFromData(buf.getvalue(), "PNG")
            scaled = pixmap.scaled(220, 220, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.qr_label.setPixmap(scaled)
        except Exception as exc:                              # noqa: BLE001
            self.qr_label.setText(f"QR failed: {exc}")
        self.save_qr_btn.setEnabled(True)
        self.save_conf_btn.setEnabled(True)

    @Slot()
    def show_peer_config(self, index):
        peer = self._selected_peer()
        if peer and self.session:
            self.conf_view.setPlainText(generate_peer_conf(self.session, peer))

    @Slot()
    def save_qr(self):
        peer = self._selected_peer()
        if not peer or not self.session:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save QR Code", os.path.join(_data_dir(), f"{peer.name}_qr.png"),
            "PNG (*.png)")
        if not path:
            return
        try:
            qr_png_path(generate_peer_conf(self.session, peer), path)
        except Exception as exc:                              # noqa: BLE001
            QMessageBox.critical(self, APP_NAME, f"QR export failed: {exc}")
            return
        self._log(f"QR -> {path}")
        QMessageBox.information(self, APP_NAME, f"QR code saved:\n{path}")

    @Slot()
    def save_peer_conf(self):
        peer = self._selected_peer()
        if not peer or not self.session:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Peer Config", os.path.join(_data_dir(), f"{peer.name}.conf"),
            "WireGuard config (*.conf)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(generate_peer_conf(self.session, peer))
        self._log(f"peer config -> {path}")

    # -------------------------------------------------------------- status
    @Slot()
    def query_status(self):
        try:
            out = wg_show()
            self.status_out.setPlainText(out)
            peers = parse_wg_show(out)
            self._log(f"wg show: {len(peers)} peer(s) reported")
        except FileNotFoundError as exc:
            self.status_out.setPlainText(str(exc))
            self._log("wg CLI not available on this machine", "orange")
        except OSError as exc:
            self.status_out.setPlainText(f"error: {exc}")

    # -------------------------------------------------------------- import
    @Slot()
    def import_session(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Session (JSON)", _samples_dir(),
            "Session (*.json);;All files (*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            self.session = session_from_dict(raw)
        except Exception as exc:                              # noqa: BLE001
            QMessageBox.critical(self, APP_NAME, f"Import failed: {exc}")
            return
        self.iface_edit.setText(self.session.interface_name)
        self.network_edit.setText(self.session.server_network)
        self.port_spin.setValue(self.session.listen_port)
        self.dns_edit.setText(self.session.dns or "")
        self._log(f"imported session {self.session.session_id} with "
                  f"{len(self.session.peers)} peers")
        self.statusBar().showMessage(f"Imported session {self.session.session_id}")
        self._refresh()

    # -------------------------------------------------------------- report
    @Slot()
    def export_report(self):
        if not self.session:
            QMessageBox.information(self, APP_NAME, "Create or import a tunnel session first.")
            return
        fmt, ok = QInputDialog.getItem(self, "Export Report", "Format:",
                                       ["pdf", "html", "json", "csv", "txt"], 0, False)
        if not ok:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Report",
            os.path.join(_data_dir(), "reports", f"tunnel_{self.session.session_id}.{fmt}"),
            f"{fmt.upper()} (*.{fmt})")
        if not path:
            return
        try:
            out = reporting.export(self.session, fmt, path)
        except Exception as exc:                              # noqa: BLE001
            QMessageBox.critical(self, APP_NAME, f"Export failed: {exc}")
            return
        self._log(f"report -> {out}")
        QMessageBox.information(self, APP_NAME, f"Report written:\n{out}")

    def _log(self, msg, color="gray"):
        hexc = {"red": theme.RED, "green": theme.GREEN, "orange": theme.ORANGE,
                "gray": theme.TEXT_DIM}.get(color, theme.TEXT_DIM)
        self.statusBar().showMessage(msg)


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setStyleSheet(theme.STYLESHEET)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
