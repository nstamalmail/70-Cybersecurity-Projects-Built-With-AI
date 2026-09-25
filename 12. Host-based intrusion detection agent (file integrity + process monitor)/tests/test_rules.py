from hids.core.models import ProcessInfo
from hids.engines.rules import evaluate_process


def _proc(name="notepad.exe", exe=r"C:\Windows\System32\notepad.exe",
          cmdline=None, parent=None):
    return ProcessInfo(pid=100, ppid=1, name=name, exe=exe,
                       cmdline=cmdline or [name], user="user",
                       parent_name=parent)


def test_benign_process_no_hits():
    hits = evaluate_process(_proc(), [])
    assert hits == []


def test_blacklisted_tool():
    hits = evaluate_process(_proc(name="mimikatz.exe",
                                  exe=r"C:\Users\x\AppData\mimikatz.exe"),
                            ["mimikatz.exe"])
    ids = [h[0] for h in hits]
    assert "BLACKLISTED_PROCESS" in ids
    sev = dict((h[0], h[1]) for h in hits)["BLACKLISTED_PROCESS"]
    assert sev == "CRITICAL"


def test_suspicious_powershell_encoded():
    cmdline = ["powershell.exe", "-nop", "-w", "hidden", "-enc", "SQBFAFgA"]
    hits = evaluate_process(_proc(name="powershell.exe",
                                  exe=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                  cmdline=cmdline), [])
    ids = [h[0] for h in hits]
    assert "SUSPICIOUS_POWERSHELL" in ids


def test_powershell_benign_no_hits():
    hits = evaluate_process(_proc(name="powershell.exe",
                                  exe=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                  cmdline=["powershell.exe", "-Command", "Get-ChildItem"]), [])
    assert hits == []


def test_office_spawned_shell():
    hits = evaluate_process(_proc(name="cmd.exe", parent="winword.exe"), [])
    assert ("OFFICE_SPAWNED_SHELL", "HIGH", hits[0][2]) in hits


def test_executable_in_temp():
    exe = r"C:\Users\victim\AppData\Local\Temp\update.exe"
    hits = evaluate_process(_proc(name="update.exe", exe=exe), [])
    ids = [h[0] for h in hits]
    assert "EXECUTABLE_IN_TEMP" in ids


def test_system_process_impersonation():
    hits = evaluate_process(_proc(name="svchost.exe", exe=r"D:\mal\svchost.exe"), [])
    ids = [h[0] for h in hits]
    assert "SYSTEM_PROCESS_IMPERSONATION" in ids


def test_legit_svchost_no_impersonation_hit():
    hits = evaluate_process(_proc(name="svchost.exe",
                                  exe=r"C:\Windows\System32\svchost.exe"), [])
    ids = [h[0] for h in hits]
    assert "SYSTEM_PROCESS_IMPERSONATION" not in ids


def test_persistence_attempt():
    cmdline = ["reg", "add", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
               "/v", "updater", "/d", "C:\\x.exe"]
    hits = evaluate_process(_proc(name="reg.exe", cmdline=cmdline), [])
    ids = [h[0] for h in hits]
    assert "PERSISTENCE_ATTEMPT" in ids
