# Active Roles Environment Assessment Report

A PowerShell script that connects to a One Identity Active Roles installation, collects environment data across multiple categories, and produces a self-contained interactive HTML report.

> **Important — no support.** This script is published as an open-source utility. **One Identity LLC does not provide support, updates, or guarantees of any kind.** See `LICENSE.txt` for full terms.

---

## What the report contains

- Active Roles version and build
- Operating system information
- Managed domains (with optional managed user counts, including a stacked **Enabled vs Disabled** breakdown per domain)
- Replication partners (Publisher / Subscribers) — Configuration DB and Management History DB
- Dynamic Groups
  - Optional broken-rules check
  - **Distribution across Active Roles servers**, with a warning when groups are not evenly balanced
  - **Top 10 expensive LDAP queries** (by `accountNameHistory` length), flagging any group with `>= 1000` cached entries as *Expensive*
- Managed Units (with optional broken-rules check)
- Workflows
- Virtual Attributes
- Script Modules and Policy Objects (including orphan policy links)
- Access Templates (including orphan AT links)
- Microsoft Entra (Azure AD) tenants configured in Active Roles
- Microsoft Exchange presence and `PerformanceFlag` / `Disable500VA` registry checks
- SQL Server **Auto Shrink** status on the AR Configuration database
- SQL Server **AlwaysOn / MultiSubnetFailoverSupport** check
- SQL Server **Parallelism Settings** check — Cost Threshold for Parallelism and MaxDOP compared against One Identity recommendations ([KB 4383609](https://support.oneidentity.com/kb/4383609))

The output is a single self-contained `.html` file with KPI cards, charts, and searchable/sortable tables. Chart.js is loaded from CDN.

---

## Requirements

| Requirement | Notes |
|---|---|
| Active Roles Server | The script must run **on the AR server itself** — it reads version information from the local registry. |
| Active Roles Management Shell | Must be installed on the AR server. |
| Windows PowerShell 5.1 | The script targets Windows PowerShell 5.1 (the version shipped with Windows Server). |
| Network access | Outbound HTTPS to `cdn.jsdelivr.net` is needed only on the host **viewing** the HTML, to load Chart.js. The script itself does not need internet. |
| SQL read access | Read access to the AR Configuration database (for the Auto Shrink, AlwaysOn, and Parallelism checks). |

---

## Critical execution requirements

The script **must** be executed under the following conditions, otherwise data collection will fail or be incomplete:

### 1. Run as Administrator

Open PowerShell with **Run as administrator**. Elevation is required for:
- Registry reads used to detect the Active Roles version
- Reading service-account-level data

### 2. Run under the Active Roles service account

The script connects to the Active Roles Configuration database (SQL Server) to verify **Auto Shrink**, **AlwaysOn / MultiSubnetFailoverSupport**, and **Parallelism settings** (Cost Threshold and MaxDOP). By default this connection uses **Windows Authentication (Integrated Security)**, which means the user running the script must have read access to `sys.databases` and `sys.configurations` on that SQL Server.

The Active Roles **service account** already has the required SQL permissions, so the simplest and recommended way to run the script is **as that service account**.

If you cannot log on as the service account, see [Alternative: SQL Server Authentication](#alternative-sql-server-authentication) below.

#### How to run as the service account

Option A — log on interactively as the service account (RDP or console), then open an elevated PowerShell.

Option B — start an elevated PowerShell as the service account from your own session:

```powershell
Start-Process powershell.exe -Verb RunAs -Credential (Get-Credential "DOMAIN\ARSvcAccount")
```

You can verify the running identity:

```powershell
whoami
```

---

## Quick start

1. Log on to the Active Roles server as the **AR service account**.
2. Open **PowerShell as Administrator**.
3. (First run only) Allow script execution for the current session:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
4. Change to the folder containing the script:
   ```powershell
   cd C:\Tools\ARAssessment
   ```
5. Run the script:
   ```powershell
   .\Get-ARAssessmentReport.ps1
   ```
6. Open the generated `AR_Assessment_<timestamp>.html` in a browser.

---

## Parameters

| Parameter | Type | Description |
|---|---|---|
| `-ARServer` | `string` | Active Roles server name or IP. Defaults to local auto-connect. |
| `-OutputPath` | `string` | Full path for the HTML report. Defaults to `.\AR_Assessment_<yyyyMMdd_HHmmss>.html`. |
| `-SkipBrokenRulesCheck` | `switch` | Skip GUID validation for Dynamic Groups and Managed Units membership rules. Recommended for large environments. |
| `-SkipUserCounts` | `switch` | Skip the managed user count per domain. Recommended for environments with many users. |
| `-SqlCredential` | `PSCredential` | SQL Server credential used by the Auto Shrink, AlwaysOn, and Parallelism checks when the AR Configuration database uses SQL Authentication. If omitted, Windows Authentication is used. |

---

## Examples

### Default run
```powershell
.\Get-ARAssessmentReport.ps1
```
Connects locally, collects everything, writes the report to the current directory.

### Specify server and output path
```powershell
.\Get-ARAssessmentReport.ps1 `
    -ARServer "arsserver.domain.com" `
    -OutputPath "C:\Reports\AR_Assessment.html"
```

### Skip slow checks (large environments)
```powershell
.\Get-ARAssessmentReport.ps1 -SkipBrokenRulesCheck -SkipUserCounts
```

### Alternative: SQL Server Authentication
Use this only if the AR Configuration database is configured for SQL Server Authentication, or if you cannot run the script as the AR service account.
```powershell
.\Get-ARAssessmentReport.ps1 -SqlCredential (Get-Credential)
```

---

## Output files

| File | Location |
|---|---|
| HTML report | `-OutputPath` (default: `.\AR_Assessment_<timestamp>.html`) |
| Log file | `.\logs\Get-ARAssessmentReport_<timestamp>.log` |

---

## Troubleshooting

| Symptom | Likely cause | Resolution |
|---|---|---|
| `Failed to load Active Roles Management Shell` | Module not installed on this host | Install the Active Roles Management Shell, or run on the AR server. |
| `Failed to connect to Active Roles Service` | AR service stopped or unreachable | Check the service: `Get-ARServiceStatus`. |
| SQL checks (Auto Shrink / AlwaysOn / Parallelism) return `Access denied` or `Login failed` | The current user is not the AR service account and has no SQL access | Re-run under the AR service account, or use `-SqlCredential`. |
| Parallelism section shows `Action Required` | `Cost Threshold for Parallelism` is below 50 or `MaxDOP` is not 4 | Engage your DBA and review against [KB 4383609](https://support.oneidentity.com/kb/4383609). |
| Dynamic Groups distribution warning is shown | Groups are concentrated on a single AR server in a multi-server environment | Verify whether this is intentional (dedicated Dynamic Group server). If not, rebalance Dynamic Group ownership. |
| Many Dynamic Groups flagged as `Expensive` | Membership queries return very large result sets (`accountNameHistory >= 1000`) | Review the group membership rules; narrow scope or filters where possible to reduce AR and DC load. |
| Script appears to hang | Broken-rules check iterating over many Dynamic Groups / Managed Units | Re-run with `-SkipBrokenRulesCheck`. |
| Charts are blank in the HTML | Host viewing the report has no internet access to the Chart.js CDN | Open the report on a machine with outbound internet. |
| Version shows `Unknown` | Script is not running on the AR server, or not running elevated | Run on the AR server as Administrator. |

---

## License

Copyright 2026 One Identity LLC. Licensed under the One Identity Permissive Software License. See `LICENSE.txt` for full terms.
