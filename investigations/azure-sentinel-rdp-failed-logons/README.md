# Azure Microsoft Sentinel — Failed RDP Authentication Detection

> **Hands-on SOC / Blue Team lab** · Azure · Windows Security Events · KQL · Microsoft Sentinel · Microsoft Defender

## Summary

This project documents an **authorized laboratory simulation** of failed Remote Desktop authentication attempts against a Windows Server virtual machine hosted in Microsoft Azure. The goal was to validate log collection, build a custom Microsoft Sentinel scheduled analytics rule, investigate the resulting alert and incident, and document the final disposition.

**Outcome:** Two intentionally generated Windows Security Event ID 4625 records were received by Log Analytics, a temporary test rule generated an alert and incident, and the incident was classified as **Benign Positive — Security testing** and resolved.

The production-style detection configuration was restored after testing.

## Architecture

```text
Azure Windows Server VM (Windows Security log)
        |
        v
Azure Monitor Agent (AMA) + Data Collection Rule (DCR)
        |
        v
Log Analytics Workspace (SecurityEvent table)
        |
        v
Microsoft Sentinel (KQL + Scheduled Analytics Rule)
        |
        v
Microsoft Defender (Alert -> Incident -> Investigation -> Resolution)
```

## Scope and tools

- Microsoft Azure virtual machine running Windows Server
- Windows audit policy: logon success and failure
- Azure Monitor Agent and Windows Security Events DCR
- Log Analytics workspace
- Microsoft Sentinel scheduled analytics rule and KQL
- Microsoft Defender incident investigation
- MITRE ATT&CK context: **Credential Access / T1110 Brute Force**

## Investigation workflow

1. Confirmed incoming Windows Security Events using KQL.
2. Reviewed Event ID **4624** and established that successful RDP sessions appeared with **LogonType 10**, while service logons appeared with **LogonType 5**.
3. Verified the local Windows audit policy with `auditpol /get /subcategory:"Logon"`.
4. Performed one authorized authentication-failure test and found **Event ID 4625, LogonType 3**. This highlighted that failed RDP authentication can be represented as a network logon.
5. Created an unprivileged, dedicated test account for further controlled validation.
6. Confirmed two Event ID 4625 records from the test account, with the failure status **0xC000006D**; verified the same records in the Log Analytics `SecurityEvent` table.
7. Temporarily changed the detection threshold and lookback for a controlled historical-data validation. The alert query returned **FailedAttempts = 2** and generated an incident.
8. Investigated and documented the incident; classified it as **Benign Positive — Security testing**, then resolved it.
9. Restored the normal detection rule threshold to **five failures in ten minutes** and disabled the temporary suppression setting.

**Important distinction:** The alert generated during this exercise used a deliberately reduced test threshold. It does **not** establish that a five-failure attack occurred. The exercise does not demonstrate a real intrusion.

## Detection query — restored configuration

```kusto
SecurityEvent
| where TimeGenerated >= ago(10m)
| where EventID == 4625
| where LogonType in (3, 10)
| where isnotempty(IpAddress)
| where IpAddress != "-"
| summarize
    FailedAttempts=count(),
    FirstAttempt=min(TimeGenerated),
    LastAttempt=max(TimeGenerated)
    by Computer, IpAddress
| where FailedAttempts >= 5
```

**Scheduling:** Every 10 minutes, looking back 10 minutes. Alert condition: number of query results greater than zero.

### Detection limitations

- **LogonType 3 is broader than RDP**; the rule detects repeated network-authentication failures as well as remote-interactive failures. The rule title is descriptive of the lab scenario, not a definitive attribution of every alert to RDP.
- This is a threshold-based detection, not definitive proof of malicious activity.
- Grouping by source IP and computer can aggregate failures across multiple accounts.
- A 10-minute scheduling frequency may not identify every possible 10-minute rolling window; overlapping lookback windows and entity mappings are planned improvements.
- The first lab rule did not map account, host and IP entities into the Defender incident graph.

## Supporting hunting queries

**Successful and failed logons by type**

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4624, 4625)
| summarize Events=count() by EventID, LogonType
| order by Events desc
```

**Inspect failed logons**

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| project TimeGenerated, Computer, Account, LogonType, IpAddress, Status
| order by TimeGenerated desc
```

## Incident disposition

| Field | Result |
|---|---|
| Incident | SOC-LAB - Multiple Failed RDP Logins |
| Severity | Medium |
| Test findings | Two failed authentications, Event ID 4625 / LogonType 3 |
| Alert detection | Custom scheduled analytics rule |
| Classification | Benign Positive — Security testing |
| Final status | Resolved |
| Containment | Not required for authorized test activity |

The original Defender export was reviewed, but **is intentionally not uploaded** here: it contains user details and environment identifiers. All sensitive account names, IP addresses and subscription-specific identifiers have been omitted from this public write-up.

## Next improvements

- Configure Sentinel entity mapping for IP, host and account
- Enrich alert details and strengthen investigative context
- Reduce duplicate alerts and test detection window edge cases
- Build SOC workbooks for authentication monitoring
- Add more controlled threat-detection scenarios

## Ethics and scope

All authentication tests were performed against an explicitly authorized, self-managed laboratory VM. No production systems or third-party accounts were targeted. This is **hands-on laboratory experience**, not an assertion of commercial SOC employment.
