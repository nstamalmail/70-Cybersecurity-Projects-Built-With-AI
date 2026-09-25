"""Built-in, expert-authored attack chains (MITRE ATT&CK mapped).

Each preset is a complete RulePackProject so a user can load one and
immediately validate/export. Content is written from a detection-engineering
perspective: one technique per chain phase, 1-2 rules each, realistic
patterns that work with Wazuh's decoders.
"""

from __future__ import annotations

from .models import (
    AttackChain,
    AttackStep,
    AttackTechnique,
    ConditionType,
    CustomDecoder,
    DetectionRule,
    PackOptions,
    RulePackProject,
)


def _rule(
    rid: int,
    level: int,
    desc: str,
    decoder: str,
    cond: ConditionType,
    pattern: str,
    *,
    groups: str = "attack_chain",
    field_name: str = "",
    frequency: int = 0,
    timeframe: int = 0,
    mitre_id: str = "",
    mitre_tactic: str = "",
) -> DetectionRule:
    rule = DetectionRule(
        rule_id=rid,
        level=level,
        description=desc,
        decoder=decoder,
        condition=cond,
        pattern=pattern,
        field_name=field_name,
        frequency=frequency,
        timeframe=timeframe,
        mitre_id=mitre_id,
        mitre_tactic=mitre_tactic,
    )
    rule.set_groups(groups)
    return rule


def _tech(tid: str, name: str, tactic: str, desc: str, *rules: DetectionRule) -> AttackTechnique:
    return AttackTechnique(
        technique_id=tid, name=name, tactic=tactic, description=desc, rules=list(rules)
    )


def _step(name: str, desc: str, *techs: AttackTechnique) -> AttackStep:
    return AttackStep(name=name, description=desc, techniques=list(techs))


# ---------------------------------------------------------------------------
# Preset 1 — Ransomware kill chain
# ---------------------------------------------------------------------------

def ransomware_preset() -> RulePackProject:
    chain = AttackChain(
        name="Ransomware Kill Chain",
        description=(
            "End-to-end detection for a modern ransomware operation: initial access "
            "via phishing, execution through living-off-the-land binaries, persistence, "
            "UAC bypass, shadow-copy deletion, credential harvesting, discovery, SMB "
            "lateral movement, C2 and the encryption impact phase."
        ),
        steps=[
            _step("Initial Access", "How the attacker gets in.",
                _tech("T1566.001", "Phishing Attachment", "Initial Access",
                      "Office/script attachment delivered via email.",
                      _rule(100101, 8, "Suspicious attachment dropped and executed",
                            "syslog", ConditionType.REGEX,
                            r"(?:rundll32|wscript|mshta|cscript)\s+.*\.(?:docm|xlsm|js|vbs|hta)",
                            mitre_id="T1566.001", mitre_tactic="Initial Access"),
                      _rule(100102, 5, "New executable created in user Downloads or Temp",
                            "syslog", ConditionType.REGEX,
                            r"(?:Downloads|AppData\\Local\\Temp)\\[^\\]+\.(exe|scr|pif|bat|cmd)",
                            mitre_id="T1204.002", mitre_tactic="Execution")),
                _tech("T1190", "Exploit Public-Facing Application", "Initial Access",
                      "RDP/webserver exploitation.",
                      _rule(100103, 9, "Suspicious brute force on RDP or web service",
                            "syslog", ConditionType.FREQUENCY,
                            r"(?:Failed password|invalid user|401)",
                            frequency=10, timeframe=60,
                            mitre_id="T1110", mitre_tactic="Credential Access"))),
            _step("Execution", "Running attacker code.",
                _tech("T1059.003", "PowerShell", "Execution",
                      "Obfuscated or encoded PowerShell.",
                      _rule(100110, 9, "Encoded PowerShell command (Base64)",
                            "syslog", ConditionType.REGEX,
                            r"powershell[^\n]*-enc(odedcommand)?\s+[A-Za-z0-9+/]{40,}={0,2}",
                            mitre_id="T1059.003", mitre_tactic="Execution"),
                      _rule(100111, 10, "PowerShell downloads and executes payload",
                            "syslog", ConditionType.REGEX,
                            r"powershell[^\n]*(?:IEX|Invoke-Expression|DownloadString|DownloadFile)",
                            mitre_id="T1059.003", mitre_tactic="Execution")),
                _tech("T1059.001", "Cmd / Batch", "Execution",
                      "Batch-driven lateral or impact activity.",
                      _rule(100112, 6, "Cmd launched with unusual switches",
                            "syslog", ConditionType.REGEX,
                            r"(?:/c\s+(?:copy|move|del|wmic|vssadmin)|cmd\.exe\s+/(?:c|k))",
                            mitre_id="T1059.001", mitre_tactic="Execution"))),
            _step("Persistence", "Staying on the host.",
                _tech("T1547.001", "Registry Run Keys", "Persistence",
                      "Autorun entries added to HKCU/HKLM.",
                      _rule(100120, 8, "Run key modified under CurrentVersion\\Run",
                            "eventchannel", ConditionType.REGEX,
                            r"HK(?:CU|LM)\\.*CurrentVersion\\Run(Once)?",
                            mitre_id="T1547.001", mitre_tactic="Persistence")),
                _tech("T1543.003", "Windows Service", "Persistence",
                      "New or modified service on the host.",
                      _rule(100121, 8, "Service binary installed outside System32",
                            "syslog", ConditionType.REGEX,
                            r"(?:sc\s+create|New-Service|create service).{0,120}(?:Temp|Users|ProgramData)",
                            mitre_id="T1543.003", mitre_tactic="Persistence"))),
            _step("Privilege Escalation", "Getting admin rights.",
                _tech("T1548.002", "Bypass User Account Control", "Privilege Escalation",
                      "UAC bypass patterns (fodhelper, eventvwr, ms-settings).",
                      _rule(100130, 9, "UAC bypass via fodhelper/eventvwr registry",
                            "eventchannel", ConditionType.REGEX,
                            r"(?:fodhelper|eventvwr\.exe|ms-settings:)",
                            mitre_id="T1548.002", mitre_tactic="Privilege Escalation"))),
            _step("Defense Evasion", "Avoiding detection.",
                _tech("T1490", "Inhibit System Recovery", "Impact",
                      "Shadow copies deleted ahead of encryption.",
                      _rule(100140, 12, "Shadow copy deletion (vssadmin)",
                            "syslog", ConditionType.REGEX,
                            r"vssadmin[^\n]*delete[^\n]*shadows",
                            mitre_id="T1490", mitre_tactic="Impact"),
                      _rule(100141, 12, "wmic shadowcopy delete",
                            "syslog", ConditionType.REGEX,
                            r"wmic[^\n]*shadowcopy[^\n]*delete",
                            mitre_id="T1490", mitre_tactic="Impact")),
                _tech("T1070.004", "File Deletion", "Defense Evasion",
                      "Log or tool cleanup.",
                      _rule(100142, 5, "Bulk deletion of log files",
                            "syslog", ConditionType.REGEX,
                            r"del\s+/q?\s+.*\.(?:log|evtx)",
                            mitre_id="T1070.004", mitre_tactic="Defense Evasion"))),
            _step("Credential Access", "Stealing secrets.",
                _tech("T1003.001", "LSASS Memory", "Credential Access",
                      "Mimikatz or procdump against lsass.",
                      _rule(100150, 12, "Mimikatz sekurlsa on the command line",
                            "syslog", ConditionType.REGEX,
                            r"sekurlsa|mimikatz|Invoke-Mimikatz",
                            mitre_id="T1003.001", mitre_tactic="Credential Access"),
                      _rule(100151, 11, "LSASS process dumped (procdump/comsvcs)",
                            "syslog", ConditionType.REGEX,
                            r"(?:procdump.{0,80}lsass|comsvcs\.dll.{0,80}MiniDump)",
                            mitre_id="T1003.001", mitre_tactic="Credential Access")),
                _tech("T1003.002", "SAM Registry Hive", "Credential Access",
                      "Reading local SAM.",
                      _rule(100152, 10, "Registry query targeting SAM hive",
                            "syslog", ConditionType.REGEX,
                            r"reg\s+save\s+.*\\(?:SAM|SYSTEM)|HKLM\\SAM",
                            mitre_id="T1003.002", mitre_tactic="Credential Access"))),
            _step("Discovery", "Mapping the environment.",
                _tech("T1082", "System Information Discovery", "Discovery",
                      "Host/domain enumeration.",
                      _rule(100160, 4, "Domain enumeration with net commands",
                            "syslog", ConditionType.REGEX,
                            r"net\s+(?:user|group|localgroup|view|share)\s+[/\\]?domain",
                            mitre_id="T1082", mitre_tactic="Discovery"))),
            _step("Lateral Movement", "Spreading.",
                _tech("T1021.002", "SMB/Admin Shares", "Lateral Movement",
                      "Write to ADMIN$/C$ and scheduled task push.",
                      _rule(100170, 10, "Write to admin share followed by task creation",
                            "syslog", ConditionType.FREQUENCY,
                            r"\\\\(?:ADMIN\$|C\$)\\",
                            frequency=3, timeframe=300,
                            mitre_id="T1021.002", mitre_tactic="Lateral Movement"),
                      _rule(100171, 9, "Scheduled task created remotely (schtasks /s)",
                            "syslog", ConditionType.REGEX,
                            r"schtasks\s+/create\s+/s\s+\S+",
                            mitre_id="T1053.005", mitre_tactic="Persistence"))),
            _step("Command and Control", "Phoning home.",
                _tech("T1071.001", "Web Protocols", "Command and Control",
                      "Beaconing over HTTP(S).",
                      _rule(100180, 8, "Repeated beaconing to single external host",
                            "syslog", ConditionType.FREQUENCY,
                            r"(?:GET|POST)\s+/[a-z0-9/]{8,}",
                            frequency=15, timeframe=300,
                            mitre_id="T1071.001", mitre_tactic="Command and Control"))),
            _step("Impact", "The payload lands.",
                _tech("T1486", "Data Encrypted for Impact", "Impact",
                      "Ransomware-style bulk renames and encryption flags.",
                      _rule(100190, 15, "Bulk file rename to encrypted extension",
                            "syslog", ConditionType.FREQUENCY,
                            r"\.(?:lockbit|encrypted|_enc|wasted|crypt)",
                            frequency=5, timeframe=60,
                            mitre_id="T1486", mitre_tactic="Impact"),
                      _rule(100191, 12, "Ransom note dropped to disk",
                            "syslog", ConditionType.REGEX,
                            r"(?:HOW_TO|README|RECOVER).*(?:txt|html)|[Rr]ansom(?:ware)?[ _-]?note",
                            mitre_id="T1486", mitre_tactic="Impact"))),
        ],
    )

    decoders = [
        CustomDecoder(
            name="win_event_security",
            prematch=r"EventID: (?:4624|4648|4672|4688|4697|4740|4720)",
            regex=r"Account Name:\s+(\S+)\s+.*?EventID: (\d+)\s+.*?Process Name:\s+(\S*)",
            order="user, event_id, process",
            parent="eventchannel",
        ),
    ]

    return RulePackProject(
        chain=chain,
        decoders=decoders,
        options=PackOptions(base_rule_id=100000, group_name="ransomware_chain"),
    )


# ---------------------------------------------------------------------------
# Preset 2 — Webshell & RCE
# ---------------------------------------------------------------------------

def webshell_preset() -> RulePackProject:
    chain = AttackChain(
        name="Webshell & RCE",
        description=(
            "Detects web application compromise: suspicious file uploads, execution of "
            "shell binaries from the web user, encoded web payloads, webshell creation "
            "and reverse-shell beaconing."
        ),
        steps=[
            _step("Initial Access", "Web-facing entry.",
                _tech("T1190", "Exploit Public-Facing App", "Initial Access",
                      "Scanner/exploit traffic.",
                      _rule(100201, 6, "Directory traversal attempt",
                            "web-accesslog", ConditionType.REGEX,
                            r"\.\./\.\./|%2e%2e%2f",
                            mitre_id="T1190", mitre_tactic="Initial Access"),
                      _rule(100202, 8, "SQL injection probe on parameter",
                            "web-accesslog", ConditionType.REGEX,
                            r"(?:union\s+select|'\s+or\s+'1'='1|sleep\s*\()",
                            mitre_id="T1190", mitre_tactic="Initial Access"))),
            _step("Execution", "Code runs on the server.",
                _tech("T1505.003", "Web Shell", "Persistence",
                      "Webshell uploaded and executed.",
                      _rule(100210, 12, "Suspicious file upload (.php/.aspx/.jsp)",
                            "web-accesslog", ConditionType.REGEX,
                            r"POST\s+[^\s]*\.(?:php|aspx|jsp|asp|ashx)\s",
                            mitre_id="T1505.003", mitre_tactic="Persistence"),
                      _rule(100211, 12, "Command executed by web server user",
                            "syslog", ConditionType.REGEX,
                            r"(?:www-data|apache|nobody|IUSR)[^\n]*(?:cmd\.exe|/bin/sh|bash\s+-c|/bin/bash)",
                            mitre_id="T1059", mitre_tactic="Execution")),
                _tech("T1059", "Command and Scripting", "Execution",
                      "One-liner payloads.",
                      _rule(100212, 10, "Encoded web payload (base64 in query)",
                            "web-accesslog", ConditionType.REGEX,
                            r"(?:cmd|exec|eval|system|passthru)=[A-Za-z0-9+/]{50,}={0,2}",
                            mitre_id="T1059", mitre_tactic="Execution"))),
            _step("Persistence", "Keeping the door open.",
                _tech("T1505.003", "Web Shell Files", "Persistence",
                      "Webshell dropped to webroot.",
                      _rule(100220, 11, "Webshell-style file created in webroot",
                            "syslog", ConditionType.REGEX,
                            r"(?:var/www|inetpub|htdocs).*(?:c99|r57|cmd|shell|backdoor)\.(php|aspx|jsp)",
                            mitre_id="T1505.003", mitre_tactic="Persistence"))),
            _step("Command and Control", "Outbound channel.",
                _tech("T1105", "Ingress Tool Transfer", "Command and Control",
                      "Server pulls a second-stage tool.",
                      _rule(100230, 9, "wget/curl download from web user",
                            "syslog", ConditionType.REGEX,
                            r"(?:wget|curl)[^\n]*(-o|--output|-O)[^\n]*\.(exe|sh|py|pl)",
                            mitre_id="T1105", mitre_tactic="Command and Control")),
                _tech("T1071.001", "Web Protocols", "Command and Control",
                      "Reverse shell beaconing.",
                      _rule(100231, 9, "Reverse shell connection from web host",
                            "firewall", ConditionType.FREQUENCY,
                            r"(?:ESTABLISHED|ALLOW).*(?:src|dst)",
                            frequency=20, timeframe=300,
                            mitre_id="T1071.001", mitre_tactic="Command and Control"))),
        ],
    )

    return RulePackProject(
        chain=chain,
        decoders=[
            CustomDecoder(
                name="apache_combined",
                prematch=r'" (?:GET|POST|HEAD|PUT|DELETE) ',
                regex=r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\w+) (\S+) [^"]+" (\d{3}) (\d+) "([^"]*)" "([^"]*)"',
                order="srcip, timestamp, method, url, statuscode, size, referer, useragent",
                parent="web-accesslog",
            ),
        ],
        options=PackOptions(base_rule_id=100200, group_name="webshell_rce"),
    )


# ---------------------------------------------------------------------------
# Preset 3 — Credential dumping
# ---------------------------------------------------------------------------

def credential_dump_preset() -> RulePackProject:
    chain = AttackChain(
        name="Credential Dumping",
        description=(
            "Detection of in-memory and on-disk credential theft: Mimikatz, LSASS "
            "dumps, registry hive copies, and NTDS extraction."
        ),
        steps=[
            _step("Credential Access", "Stealing credentials.",
                _tech("T1003.001", "LSASS Memory", "Credential Access",
                      "Tools reaching into LSASS.",
                      _rule(100301, 13, "Mimikatz detected on command line",
                            "syslog", ConditionType.REGEX,
                            r"(?i)(mimikatz|sekurlsa|lsadump|kerberos::)",
                            mitre_id="T1003.001", mitre_tactic="Credential Access"),
                      _rule(100302, 12, "LSASS opened for read by non-system process",
                            "eventchannel", ConditionType.REGEX,
                            r"(?:lsass\.exe).{0,200}(?:OpenProcess|PROCESS_VM_READ)",
                            mitre_id="T1003.001", mitre_tactic="Credential Access"),
                      _rule(100303, 11, "procdump or comsvcs dump of lsass",
                            "syslog", ConditionType.REGEX,
                            r"(?:procdump|comsvcs)[^\n]*lsass",
                            mitre_id="T1003.001", mitre_tactic="Credential Access")),
                _tech("T1003.002", "Security Account Manager", "Credential Access",
                      "SAM/SYSTEM hive copies.",
                      _rule(100304, 11, "Registry hive save of SAM",
                            "syslog", ConditionType.REGEX,
                            r"reg\s+save\s+\S+\s+\S*\\(SAM|SYSTEM)\b",
                            mitre_id="T1003.002", mitre_tactic="Credential Access")),
                _tech("T1003.003", "NTDS", "Credential Access",
                      "Domain database extraction.",
                      _rule(100305, 13, "ntds.dit access or vssadmin copy",
                            "syslog", ConditionType.REGEX,
                            r"(?:ntds\.dit|ntdsutil.{0,80}(?:snapshot|activate))",
                            mitre_id="T1003.003", mitre_tactic="Credential Access")),
                _tech("T1003.008", "/etc/passwd & shadow", "Credential Access",
                      "Unix credential files.",
                      _rule(100306, 9, "Read of /etc/shadow or /etc/passwd by non-root",
                            "syslog", ConditionType.REGEX,
                            r"(?:cat|tail|less|more)\s+/(?:etc/(?:shadow|passwd)|etc\b.*shadow)",
                            mitre_id="T1003.008", mitre_tactic="Credential Access")),
                _tech("T1555", "Credentials from Web Browsers", "Credential Access",
                      "Browser credential stores.",
                      _rule(100307, 10, "Browser credential file access (Login Data / Cookies)",
                            "syslog", ConditionType.REGEX,
                            r"(?:Login\sData|Cookies|Local\sState).{0,80}(?:chrome|firefox|edge|opera)",
                            mitre_id="T1555.003", mitre_tactic="Credential Access"))),
        ],
    )

    return RulePackProject(
        chain=chain,
        decoders=[],
        options=PackOptions(base_rule_id=100300, group_name="credential_dump"),
    )


# ---------------------------------------------------------------------------
# Preset 4 — Lateral movement
# ---------------------------------------------------------------------------

def lateral_movement_preset() -> RulePackProject:
    chain = AttackChain(
        name="Lateral Movement",
        description=(
            "Detection of host-to-host movement: SMB admin-share abuse, PsExec/WMI "
            "remote process creation, RDP logons and service installation on remote hosts."
        ),
        steps=[
            _step("Discovery", "Finding targets.",
                _tech("T1018", "Remote System Discovery", "Discovery",
                      "Network/domain enumeration.",
                      _rule(100401, 5, "Enumerating hosts with net view / adfind",
                            "syslog", ConditionType.REGEX,
                            r"(?:net\s+view\s+/domain|adfind\s+-h|nltest\s+/dclist)",
                            mitre_id="T1018", mitre_tactic="Discovery"))),
            _step("Lateral Movement", "Moving between hosts.",
                _tech("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement",
                      "Admin share access and file drop.",
                      _rule(100410, 10, "Admin share opened for write",
                            "syslog", ConditionType.FREQUENCY,
                            r"\\\\(?:ADMIN\$|C\$|IPC\$)\\",
                            frequency=3, timeframe=120,
                            mitre_id="T1021.002", mitre_tactic="Lateral Movement"),
                      _rule(100411, 10, "Suspicious binary dropped to admin share",
                            "syslog", ConditionType.REGEX,
                            r"\\\\[^\s]+\\ADMIN\$.+\.(?:exe|dll|bat|ps1)",
                            mitre_id="T1021.002", mitre_tactic="Lateral Movement")),
                _tech("T1021.001", "Remote Desktop Protocol", "Lateral Movement",
                      "Interactive remote logons.",
                      _rule(100412, 7, "RDP logon from multiple sources",
                            "eventchannel", ConditionType.FREQUENCY,
                            r"Logon Type:\s+10",
                            frequency=5, timeframe=300,
                            mitre_id="T1021.001", mitre_tactic="Lateral Movement")),
                _tech("T1569.002", "Service Execution", "Execution",
                      "PsExec-style service execution.",
                      _rule(100413, 12, "PsExec service binary created",
                            "syslog", ConditionType.REGEX,
                            r"(?:PSEXESVC|psexec|PAExec|remcom)",
                            mitre_id="T1569.002", mitre_tactic="Execution"),
                      _rule(100414, 11, "WMI remote process creation (win32_process)",
                            "syslog", ConditionType.REGEX,
                            r"wmic[^\n]*process\s+call\s+create|Invoke-WmiMethod\s+-ComputerName",
                            mitre_id="T1047", mitre_tactic="Execution")),
                _tech("T1053.005", "Scheduled Task", "Persistence",
                      "Task created on remote host.",
                      _rule(100415, 9, "Scheduled task created against remote host",
                            "syslog", ConditionType.REGEX,
                            r"schtasks\s+/create\s+/s\s+\S+",
                            mitre_id="T1053.005", mitre_tactic="Persistence"))),
            _step("Impact", "Payload delivered.",
                _tech("T1486", "Data Encrypted for Impact", "Impact",
                      "Ransomware stage on the new host.",
                      _rule(100420, 15, "Bulk rename to encrypted extension",
                            "syslog", ConditionType.FREQUENCY,
                            r"\.(?:lockbit|encrypted|crypt|_enc)\b",
                            frequency=5, timeframe=60,
                            mitre_id="T1486", mitre_tactic="Impact"))),
        ],
    )

    return RulePackProject(
        chain=chain,
        decoders=[
            CustomDecoder(
                name="wmi_process_create",
                prematch=r"Win32_Process\.Create",
                regex=r"CommandLine:\s*(\S.*)\s+ProcessId:\s*(\d+)",
                order="command_line, pid",
                parent="eventchannel",
            ),
        ],
        options=PackOptions(base_rule_id=100400, group_name="lateral_movement"),
    )


PRESETS: dict[str, RulePackProject] = {
    "Ransomware Kill Chain": ransomware_preset,
    "Webshell & RCE": webshell_preset,
    "Credential Dumping": credential_dump_preset,
    "Lateral Movement": lateral_movement_preset,
}


def list_presets() -> list[str]:
    return list(PRESETS.keys())


def load_preset(name: str) -> RulePackProject:
    factory = PRESETS.get(name)
    if factory is None:
        raise KeyError(f"Unknown preset: {name}")
    return factory()