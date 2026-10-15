# PowerShell Threat Hunting & Command-Line Audit Visibility — SOC Lab Exercise 3

**Date:** October 15, 2026  
**Technology:** Microsoft Sentinel · Azure Monitor Agent · Windows Security Events · KQL  
**Scope:** Authorized Windows Server lab; defensive validation only

## Goal

Investigate process creation events, examine PowerShell activity, identify gaps in telemetry, and confirm that Windows process command lines are ingested into Microsoft Sentinel.

## Investigation and findings

### 1. Baseline security event volume

Queried the `SecurityEvent` table for counts by Windows Event ID over 24 hours:

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| summarize TotalEventos=count() by EventID
| order by TotalEventos desc
```

**Observed:** 940 Event ID 4688 (process creation) records during the queried window. This count indicates process creations logged, **not** attacks.

### 2. Process execution review

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| where isnotempty(NewProcessName)
| summarize TotalExecucoes=count() by NewProcessName
| order by TotalExecucoes desc
| take 15
```

Frequently recorded programs included legitimate Windows components such as `conhost.exe`, `backgroundTaskHost.exe`, and `svchost.exe`. Executable names and paths alone cannot prove a file's integrity or safety.

### 3. PowerShell investigation

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| where NewProcessName endswith @"\powershell.exe"
    or NewProcessName endswith @"\pwsh.exe"
| project TimeGenerated, Account, NewProcessName, CommandLine, ParentProcessName
| order by TimeGenerated desc
```

Two PowerShell process creation events were associated with the lab administrator account, and both showed `explorer.exe` as the parent process. This is **consistent with**, but does not conclusively prove, interactive user launch.

An initial command-line indicator search for patterns such as `-EncodedCommand`, `-ExecutionPolicy Bypass`, `DownloadString`, and `-NoProfile` returned no matches. **Important limitation:** the historical `CommandLine` values were empty, so the absence of matches was *not* meaningful evidence that such options were absent.

### 4. Discovered telemetry gap

Checked the registry setting that controls including command-line arguments in Security Event 4688:

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled
```

The system reported that the specified key or value was not found. In Sentinel, both previously observed PowerShell creation records had empty `CommandLine` fields.

### 5. Enable richer process auditing

In an elevated PowerShell console on the authorized lab VM, configured:

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

Windows returned `The operation completed successfully.`

**Operational caution:** process command-line auditing may record credentials or secrets if applications pass them as arguments. Protect access to Windows Security logs and downstream SIEM data. Domain policy could override local configuration in managed environments.

### 6. Controlled validation

Generated a benign test process:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'SOC-LAB-TEST-CMDLINE'"
```

Queried Microsoft Sentinel:

```kusto
SecurityEvent
| where TimeGenerated > ago(2h)
| where EventID == 4688
| where CommandLine contains "SOC-LAB-TEST-CMDLINE"
| project TimeGenerated, Account, NewProcessName, CommandLine, ParentProcessName
| order by TimeGenerated desc
```

**Confirmed:** Sentinel returned an Event ID 4688 record showing the **full test command line**. The new PowerShell process had `powershell.exe` as its parent, matching its launch from an existing PowerShell console.

## Results

| Control | Initial observation | Validated result |
|---|---|---|
| Event ID 4688 collection | Working | Working |
| New process name | Present | Present |
| User and parent process | Present | Present |
| Process command line | Empty in historical test events | Full command captured in new test event |
| Sentinel KQL visibility | Partial | Improved |

This exercise demonstrates improved telemetry, **not** detection of an actual compromise. Historical 4688 events are not retroactively enriched by the setting.

## Key SOC lessons

- Check data quality before interpreting the absence of suspicious command-line strings.
- Parent process information adds context, but does not independently establish benign or malicious intent.
- Windows Audit Process Creation (4688) and the separate setting for including command-line arguments are distinct controls.
- Validate end to end: configuration change → safe process execution → Windows audit event → AMA/Log Analytics ingestion → Sentinel KQL query.
- Avoid publishing sensitive logs, identities, network addresses, or raw incident exports.

## Next investigation

Build hunting queries for PowerShell execution trends and investigate unusual process-parent relationships, with the richer telemetry now available.

---
*Documented from a hands-on, authorized SOC lab; no claim of production incident response.*
