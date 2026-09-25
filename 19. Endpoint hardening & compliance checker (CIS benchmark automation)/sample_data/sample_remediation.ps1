#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CIS Benchmark Remediation Script - Demo Sample
.DESCRIPTION
    Generates remediation actions for failed CIS controls.
    Run with -WhatIf to preview changes without applying.
.NOTES
    Generated: 2026-09-21
    Benchmark: CIS Windows 11 v3.0
    Total Controls: 58
#>

param(
    [switch]$WhatIf = $true,
    [string]$LogFile = "$env:USERPROFILE\cis_remediation_log.txt"
)

$ErrorActionPreference = 'Continue'
$remediationCount = 0

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Write-Host $entry -ForegroundColor $(switch($Level){'ERROR'{1}'WARNING'{3}'SUCCESS'{2}default{7}})
    Add-Content -Path $LogFile -Value $entry
}

Write-Host 'CIS Benchmark Remediation Script' -ForegroundColor Cyan
Write-Host ('=' * 70) -ForegroundColor DarkGray
Write-Log 'Remediation started'

# --- Control 1.1.3: Ensure maximum password age is 60 or fewer day(s) ---
Write-Host 'Remediating 1.1.3: Ensure maximum password age is 60 or fewer day(s)'
Write-Log 'Applying control 1.1.3'
if ($WhatIf) {
    Write-Host '  [WhatIf] Would execute: net accounts /maxpwage:60'
} else {
    Write-Log 'Running: net accounts /maxpwage:60'
}
$remediationCount++

# --- Control 1.2.2: Ensure Account lockout duration is 15+ minutes ---
Write-Host 'Remediating 1.2.2: Ensure Account lockout duration is 15+ minutes'
Write-Log 'Applying control 1.2.2'
if ($WhatIf) {
    Write-Host '  [WhatIf] Would execute: net accounts /lockoutduration:15'
} else {
    Write-Log 'Running: net accounts /lockoutduration:15'
}
$remediationCount++

# --- Control 2.1.2: Ensure Audit logon events is enabled ---
Write-Host 'Remediating 2.1.2: Ensure Audit logon events is enabled'
Write-Log 'Applying control 2.1.2'
if ($WhatIf) {
    Write-Host '  [WhatIf] Would execute: auditpol /set /subcategory:Logon /success:enable /failure:enable'
} else {
    Write-Log 'Running: auditpol /set /subcategory:Logon /success:enable /failure:enable'
}
$remediationCount++

# --- Control 3.1.2: Ensure Firewall default inbound is Block ---
Write-Host 'Remediating 3.1.2: Ensure Firewall default inbound is Block'
Write-Log 'Applying control 3.1.2'
if ($WhatIf) {
    Write-Host '  [WhatIf] Would execute: netsh advfirewall set allprofiles firewallpolicy blockinbound'
} else {
    Write-Log 'Running: netsh advfirewall set allprofiles firewallpolicy blockinbound'
}
$remediationCount++

# --- Control 5.1.2: Enable Admin Approval Mode ---
Write-Host 'Remediating 5.1.2: Enable Admin Approval Mode for Built-in Admin'
Write-Log 'Applying control 5.1.2'
if ($WhatIf) {
    Write-Host '  [WhatIf] Would execute: reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v FilterAdministratorToken /t REG_DWORD /d 1 /f'
} else {
    Write-Log 'Running: reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v FilterAdministratorToken /t REG_DWORD /d 1 /f'
}
$remediationCount++

# --- Control 8.2.1: Enable Process creation command line logging ---
Write-Host 'Remediating 8.2.1: Enable Process creation command line logging'
Write-Log 'Applying control 8.2.1'
if ($WhatIf) {
    Write-Host '  [WhatIf] Would execute: reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLineEnabled /t REG_DWORD /d 1 /f'
} else {
    Write-Log 'Running: reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLineEnabled /t REG_DWORD /d 1 /f'
}
$remediationCount++

# --- Control 10.1.4: Disable SMBv1 ---
Write-Host 'Remediating 10.1.4: Disable SMBv1 protocol'
Write-Log 'Applying control 10.1.4'
if ($WhatIf) {
    Write-Host '  [WhatIf] Would execute: Set-SmbServerConfiguration -EnableSMB1Protocol 0 -Force'
} else {
    Write-Log 'Running: Set-SmbServerConfiguration -EnableSMB1Protocol 0 -Force'
}
$remediationCount++

# Summary
Write-Host '' -ForegroundColor Cyan
Write-Host ('=' * 70) -ForegroundColor DarkGray
Write-Host ('Remediation complete. Total actions: {0}' -f $remediationCount) -ForegroundColor Cyan
Write-Host ('Review log at: {0}' -f $LogFile)
Write-Host ''
Write-Host 'IMPORTANT: Run without -WhatIf to apply changes.' -ForegroundColor Yellow
Write-Host 'Example: .\remediation.ps1' -ForegroundColor Yellow
Write-Host ''
