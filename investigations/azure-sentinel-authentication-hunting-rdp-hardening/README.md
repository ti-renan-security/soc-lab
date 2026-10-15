# Authentication Threat Hunting & RDP Network Hardening — SOC Lab Exercise 5

**Date:** 2026-10-15  
**Environment:** Azure Windows Server VM, Microsoft Sentinel, Log Analytics, Windows Security Events, Network Security Group (NSG)  
**Scope:** Authorized defensive training lab

## Objectives

1. Analyze failed and successful Windows authentication events with KQL.
2. Investigate failure reasons and possible authentication from multiple external sources.
3. Correlate suspect source addresses with any successful sign-ins in the logged window.
4. Reduce unnecessary exposure of the VM's Remote Desktop Protocol (RDP) port while preserving administrative access.

## 1. Authentication baseline

```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4624, 4625)
| summarize
    TotalEvents=count(),
    FirstEvent=min(TimeGenerated),
    LastEvent=max(TimeGenerated)
    by EventID
| order by EventID asc
```

**Observed:** 144 successful logon events (4624) and 8 failed logon events (4625) returned by this query. These are event counts, not necessarily unique people or sessions.

## 2. Failed logon analysis

```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| summarize
    Attempts=count(),
    FirstAttempt=min(TimeGenerated),
    LastAttempt=max(TimeGenerated)
    by Account, LogonType, IpAddress
| order by Attempts desc
```

Observed failed events included:
- 3 events for a known controlled lab test user, from the administrator's connection IP;
- 1 event for the lab administrator account, from the same IP;
- 4 events targeting the account name **`Test`** from **3 distinct public source IPs**.

For the `Test` failures, all four events showed **LogonType 3** (network logon), and **SubStatus `0xC0000064`** (account not found). This does **not** prove the events were RDP logons; LogonType 10 is commonly associated with RemoteInteractive/RDP logons.

## 3. Focused account investigation

```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| where Account endswith @"\Test"
| project TimeGenerated, Account, IpAddress, LogonType, Status, SubStatus, Computer
| order by TimeGenerated asc
```

The four events occurred at separate points in the day, including two closely spaced failures from one source. They could be compatible with automated login attempts or misconfigured software; attribution was not established.

Looked for successful logon events for the same account name:

```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624
| where Account endswith @"\Test"
| project TimeGenerated, Account, IpAddress, LogonType, Computer
| order by TimeGenerated desc
```

**Result:** No matching successful logons in the available queried records.

## 4. Source-IP correlation

```kusto
let SuspectIPs =
    SecurityEvent
    | where TimeGenerated > ago(7d)
    | where EventID == 4625
    | where Account endswith @"\Test"
    | where isnotempty(IpAddress)
    | distinct IpAddress;
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4624, 4625)
| where IpAddress in (SuspectIPs)
| summarize
    TotalEvents=count(),
    Successes=countif(EventID == 4624),
    Failures=countif(EventID == 4625)
    by IpAddress, Account, LogonType
| order by Failures desc, Successes desc
```

**Observed:** the suspect addresses collectively had **4 failed events, 0 successful events**, all associated with the `Test` account in the queried set. Actual IP values are intentionally omitted from this public report.

## 5. Network exposure discovery

Inspected the VM's effective inbound NSG rules in the Azure portal.

**Initial state:**
- `default-allow-rdp`: priority 1000, TCP port 3389, **Source = Any**, Allow.
- Built-in `DenyAllInBound`: priority 65500.

An Any-source NSG rule makes RDP reachable from arbitrary source addresses **when the VM also has a publicly reachable network path and no other control blocks it**. The observed network-logon failures and this rule do not prove the failures occurred over RDP.

## 6. RDP hardening

Applied a staged change to reduce lockout risk:

1. Identified the administrator's current public IPv4 address on the client computer.
2. Created `Allow-RDP-MyIP`, priority **100**, inbound TCP **3389**, source set to that single IPv4 **/32**, action **Allow**.
3. Confirmed the client could open an RDP connection while the old allow-all rule was still present. This was a connectivity check, not proof of the new rule's isolation.
4. Removed `default-allow-rdp` (source Any).
5. Reviewed the NSG and verified the specific-IP rule remained alongside the built-in default rules, without the previous broad inbound RDP rule.
6. **Opened a fresh RDP connection after the broad rule was removed; the authorized administrator successfully connected.**

**Validated outcome:** the host remained reachable by RDP from the administrator's authorized source after the NSG restriction. Based on the reviewed rules, other internet sources are not authorized for inbound RDP through that NSG. A separate unauthorized-origin reachability test was **not** performed, and effective access also depends on other network controls.

**Operational caution:** a changing residential/public IP may require updating the /32 rule; the public IP, VM public IP, credentials, screenshots containing sensitive metadata, and raw logs are not included in this publication.

## Assessment and lessons

- A failed logon indicates an authentication failure, not successful compromise.
- `0xC0000064` identifies an account that was not found; interpreting status and substatus helps triage failures.
- Network logons (type 3) should not automatically be labeled RDP attempts.
- Correlation should be bounded by the data/time window and should not be presented as a global guarantee.
- Reducing exposed management ports is an effective *attack surface reduction* control.
- Validate administrative connectivity **after** removing an overly permissive rule.

**Disposition:** suspicious-looking authentication attempts identified and investigated; no successful logon found for the tested account or sources in the queried data; overly broad RDP ingress removed; authorized RDP access retested successfully.

---
*Authorized hands-on defensive lab. No evidence presented here establishes a real-world compromise or production SOC incident.*
