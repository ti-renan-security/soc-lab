# Parent–Child Process Analysis and Behavioral Baseline — SOC Lab Exercise 4

**Date:** 2026-10-15  
**Tools:** Microsoft Sentinel, Azure Log Analytics, KQL, Windows Security Event 4688  
**Scope:** Authorized Azure Windows Server laboratory

## Objective

Investigate parent–child process relationships, evaluate whether specific PowerShell process ancestry warrants further attention, and establish a baseline for repetitive Azure Guest Agent process activity.

## Method and observed evidence

### 1. PowerShell process ancestry

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| where NewProcessName endswith @"\powershell.exe"
   or NewProcessName endswith @"\pwsh.exe"
| summarize TotalExecucoes=count() by ParentProcessName, NewProcessName
| order by TotalExecucoes desc
```

**Observed**: 3 `explorer.exe → powershell.exe` executions and 1 `powershell.exe → powershell.exe` execution. The latter matched the previously performed authorized command-line audit test; these relationships are consistent with lab administration, but process ancestry alone does not verify intent.

### 2. Hunt for selected potentially unusual combinations

Queried process creations in which a parent executable matched `winword.exe`, `excel.exe`, `outlook.exe`, `chrome.exe`, `msedge.exe`, `wscript.exe`, or `cscript.exe`, and the child matched `powershell.exe`, `pwsh.exe`, or `cmd.exe`. **No results** appeared in the queried window. This does not rule out other attack paths or malicious activity.

### 3. Discover the most frequent process pairs

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| where isnotempty(ParentProcessName) and isnotempty(NewProcessName)
| summarize TotalExecucoes=count() by ParentProcessName, NewProcessName
| order by TotalExecucoes desc
| take 15
```

Common pairs included `svchost.exe → backgroundTaskHost.exe`, `services.exe → svchost.exe`, `svchost.exe → WmiPrvSE.exe` and Azure Guest Agent components starting `conhost.exe`. Because the agent paths were truncated in the UI, an additional query extracted the executable name.

### 4. Agent-related process names and counts

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| where ParentProcessName contains "GuestAgent"
| where NewProcessName endswith @"\conhost.exe"
| extend ParentExecutable = extract(@"[^\\]+$", 0, ParentProcessName)
| summarize Executions=count() by ParentExecutable
| order by Executions desc
```

| Parent executable | Executions |
|---|---:|
| `BfeToolWin8.exe` | 74 |
| `FindVolume.exe` | 18 |
| `CollectGuestLogs.exe` | 18 |
| **Total** | **110** |

The observed paths pointed to the Azure Guest Agent directory. These names are contextual clues, **not** verification of signed binaries or integrity.

### 5. Temporal baseline

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| where ParentProcessName contains "GuestAgent"
| where NewProcessName endswith @"\conhost.exe"
| summarize Executions=count() by Hour=bin(TimeGenerated, 1h)
| order by Hour asc
```

The observed timeline showed 6 executions per hour from 02:00 through 19:00 UTC, and 2 in the 20:00 hour (a potentially incomplete bucket). A 10-minute bin query revealed a repeated within-hour pattern in the visible sample: 1 at :00, 1 at :10, 3 at :30, and 1 at :40.

**Interpretation:** strong evidence of periodic activity, plausibly from scheduled or automated guest management. Regularity is not itself proof of benignness.

### 6. Command-line completeness

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| where NewProcessName endswith @"\conhost.exe"
| where ParentProcessName contains "GuestAgent"
| extend ParentExecutable = extract(@"[^\\]+$", 0, ParentProcessName)
| summarize Executions=count() by ParentExecutable, CommandLine
| order by Executions desc
```

| Parent executable | Empty CommandLine | Populated CommandLine | Total |
|---|---:|---:|---:|
| `BfeToolWin8.exe` | 67 | 7 | 74 |
| `FindVolume.exe` | 17 | 1 | 18 |
| `CollectGuestLogs.exe` | 17 | 1 | 18 |
| **Total** | **101** | **9** | **110** |

The populated command-line entries showed the same `conhost.exe` command pattern with `-ForceV1` (legacy console compatibility behavior). This suggests a relatively stable activity pattern. Many older entries were blank, consistent with the command-line auditing visibility gap fixed during [Exercise 3](../azure-sentinel-powershell-threat-hunting/). The query did not establish the exact timing of all missing arguments.

## Assessment

**Disposition: likely expected automated lab behavior; no clear malicious process relationship identified in this limited dataset.**

This is an analyst assessment of a bounded time window, not a signed-binary integrity check, malware verdict, or guarantee of system safety. Further verification could include checking file signatures, Windows service configuration, Azure extension status, and longer baseline windows if warranted.

## Lessons learned

- Process ancestry is useful for hunting but must be interpreted in context.
- Aggregating across time bins reveals stable operational patterns.
- Drill down from long process paths to executable names without discarding the raw underlying records.
- Telemetry completeness matters: process creation logs may lack command-line arguments until relevant auditing is enabled.
- In a public portfolio, record findings without exposing private network details, accounts, or raw sensitive logs.

---
*Defensive training in a controlled, authorized environment.*
