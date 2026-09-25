# MMPS Memory: decisions & lessons

- Pure stdlib for scanning (socket, struct) + PySide6 for GUI; scapy deliberately NOT
  used so the exe stays small and SYN mode degrades gracefully without admin rights.
- Report model is a single dict built by `reporting.build_report(scan)`; all 5 exporters
  consume it so TXT/HTML/PDF always agree with JSON/CSV.
- Import path reuses `engine.scan_result_from_dict` (same schema as sample_data) so an
  imported scan is indistinguishable from a live one in the UI and reports.
- Windows quirk: probing closed UDP-ish ports raises ConnectionResetError; the scan
  loop treats WSAECONNRESET as "closed/filtered" rather than crashing the worker.
- PyInstaller entry is `src/mmps/main.py` with `--path src/mmps` so local modules
  (engine, reporting, theme) resolve as top-level imports in the frozen exe.
- Educational scoping: CVE list is a small static hint map (banner -> CVE ids), clearly
  labelled "possible" in reports; not a vulnerability scanner replacement.
