<#
.SYNOPSIS
    Windows Security Log Triage Tool
.DESCRIPTION
    Pulls common authentication, RDP, account lockout, and suspicious PowerShell events
    from Windows Event Logs, assigns a simple severity score, and exports results to CSV and JSON.
.NOTES
    Run PowerShell as Administrator for best results.
#>

param(
    [int]$HoursBack = 24,
    [string]$OutputDirectory = ".\TriageOutput"
)

$ErrorActionPreference = "SilentlyContinue"

if (-not (Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
}

$StartTime = (Get-Date).AddHours(-$HoursBack)
$Results = @()

function Get-Severity {
    param([string]$Category)

    switch ($Category) {
        "Account Lockout"       { return @{ Score = 90; Severity = "Critical" } }
        "Suspicious PowerShell" { return @{ Score = 85; Severity = "High" } }
        "RDP Logon"             { return @{ Score = 65; Severity = "Medium" } }
        "Failed Logon"          { return @{ Score = 55; Severity = "Medium" } }
        default                 { return @{ Score = 25; Severity = "Low" } }
    }
}

function Add-TriageEvent {
    param(
        [string]$Category,
        [int]$EventId,
        [datetime]$TimeCreated,
        [string]$User,
        [string]$SourceIp,
        [string]$Computer,
        [string]$Message
    )

    $sev = Get-Severity -Category $Category

    $script:Results += [PSCustomObject]@{
        TimeCreated = $TimeCreated
        Category    = $Category
        EventId     = $EventId
        Severity    = $sev.Severity
        Score       = $sev.Score
        User        = $User
        SourceIp    = $SourceIp
        Computer    = $Computer
        Message     = ($Message -replace "`r`n", " " -replace "\s{2,}", " ").Trim()
    }
}

# 4625 = Failed logon
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4625
    StartTime = $StartTime
} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

    Add-TriageEvent -Category "Failed Logon" -EventId 4625 -TimeCreated $_.TimeCreated `
        -User $data["TargetUserName"] -SourceIp $data["IpAddress"] -Computer $_.MachineName -Message $_.Message
}

# 4740 = Account locked out
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4740
    StartTime = $StartTime
} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

    Add-TriageEvent -Category "Account Lockout" -EventId 4740 -TimeCreated $_.TimeCreated `
        -User $data["TargetUserName"] -SourceIp $data["CallerComputerName"] -Computer $_.MachineName -Message $_.Message
}

# 4624 + LogonType 10 = successful RDP login
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4624
    StartTime = $StartTime
} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

    if ($data["LogonType"] -eq "10") {
        Add-TriageEvent -Category "RDP Logon" -EventId 4624 -TimeCreated $_.TimeCreated `
            -User $data["TargetUserName"] -SourceIp $data["IpAddress"] -Computer $_.MachineName -Message $_.Message
    }
}

# 4104 = PowerShell Script Block Logging
$SuspiciousPatterns = @(
    "Invoke-Expression",
    "IEX",
    "DownloadString",
    "FromBase64String",
    "EncodedCommand",
    "Invoke-WebRequest",
    "Net.WebClient",
    "Start-BitsTransfer",
    "Add-MpPreference",
    "Set-MpPreference",
    "ExecutionPolicy Bypass",
    "-WindowStyle Hidden"
)

Get-WinEvent -FilterHashtable @{
    LogName   = "Microsoft-Windows-PowerShell/Operational"
    Id        = 4104
    StartTime = $StartTime
} | ForEach-Object {
    $msg = $_.Message
    $matched = $false

    foreach ($pattern in $SuspiciousPatterns) {
        if ($msg -match [regex]::Escape($pattern)) {
            $matched = $true
            break
        }
    }

    if ($matched) {
        Add-TriageEvent -Category "Suspicious PowerShell" -EventId 4104 -TimeCreated $_.TimeCreated `
            -User $env:USERNAME -SourceIp "" -Computer $_.MachineName -Message $msg
    }
}

$Results = $Results | Sort-Object Score -Descending, TimeCreated -Descending

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$CsvPath = Join-Path $OutputDirectory "Windows_Triage_$Timestamp.csv"
$JsonPath = Join-Path $OutputDirectory "Windows_Triage_$Timestamp.json"

$Results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
$Results | ConvertTo-Json -Depth 4 | Out-File -FilePath $JsonPath -Encoding UTF8

Write-Host ""
Write-Host "Windows Security Log Triage Complete"
Write-Host "Lookback Window: $HoursBack hour(s)"
Write-Host "Events Found: $($Results.Count)"
Write-Host "CSV Output: $CsvPath"
Write-Host "JSON Output: $JsonPath"
Write-Host ""

if ($Results.Count -gt 0) {
    $Results | Select-Object TimeCreated, Category, EventId, Severity, Score, User, SourceIp | Format-Table -AutoSize
} else {
    Write-Host "No matching events found."
}
