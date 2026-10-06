# Windows Security Log Triage Tool

A lightweight PowerShell blue-team utility for triaging common Windows authentication and endpoint security events.

## What it does

The script collects:

- Failed logons (`4625`)
- Account lockouts (`4740`)
- RDP logons (`4624`, Logon Type 10)
- Suspicious PowerShell activity (`4104`)

It then assigns a simple severity score and exports results to both CSV and JSON.

## Severity model

| Category | Severity | Score |
|---|---|---:|
| Account Lockout | Critical | 90 |
| Suspicious PowerShell | High | 85 |
| RDP Logon | Medium | 65 |
| Failed Logon | Medium | 55 |

The scoring model is intentionally simple so it can be explained, adjusted, and extended.

## Usage

Run PowerShell as Administrator:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Windows-Security-Triage.ps1
```

Change the lookback window:

```powershell
.\Windows-Security-Triage.ps1 -HoursBack 48
```

Use a custom output directory:

```powershell
.\Windows-Security-Triage.ps1 -HoursBack 24 -OutputDirectory C:\Triage
```

## Output

The script creates:

- `Windows_Triage_<timestamp>.csv`
- `Windows_Triage_<timestamp>.json`

## Skills demonstrated

- PowerShell
- Windows Event Logs
- Security event analysis
- Authentication monitoring
- RDP monitoring
- PowerShell Script Block Logging
- Incident triage
- CSV/JSON export
- Basic severity scoring
- Security documentation

## Future improvements

- Frequency-based scoring for repeated failed logons
- Username/IP allowlists
- Correlation between failed logons and successful RDP sessions
- HTML summary reporting
- MITRE ATT&CK mapping
- Host/IP reputation enrichment
