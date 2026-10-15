# Microsoft Sentinel Entity Mapping Validation — SOC Lab Exercise 2

> Hands-on defensive security exercise • Microsoft Azure • Microsoft Sentinel • Microsoft Defender

## Objective

Validate that a scheduled analytics rule in Microsoft Sentinel can map **IP** and **Host** entities from Windows Security Event data into a Defender incident, enabling a more useful investigation graph and supporting evidence.

This exercise builds upon [Exercise 1 — Failed RDP Authentication Detection](../azure-sentinel-rdp-failed-logons/).

## Environment

- Azure Windows Server VM with Windows Security Event auditing
- Azure Monitor Agent (AMA) and Data Collection Rule (DCR)
- Log Analytics Workspace (LAW), `SecurityEvent` table
- Microsoft Sentinel scheduled analytics rules
- Microsoft Defender incident investigation

## Method

1. Confirmed that failed authentication records (Event ID **4625**) included `Computer` and `IpAddress` fields in Log Analytics.
2. Configured entity mapping in the main rule:
   - **IP** → **Address** → `IpAddress`
   - **Host** → **FullName** → `Computer`
3. Saved the principal rule with its original detection threshold (five failed logons within ten minutes).
4. Created a **temporary test rule** to validate entity mapping against existing, authorized laboratory authentication events, rather than producing additional failed logins.
5. Used **Group all events into a single alert**, and configured temporary suppression to avoid repeated test alerts.
6. Confirmed a new alert and incident in Microsoft Defender.
7. Verified that the incident investigation graph displayed a **host** and an associated **source IP**, unlike the previous exercise, where no entities appeared.
8. Disabled the temporary test rule, leaving the main detection rule enabled.
9. Classified the test incident as **Benign Positive — Security testing** and resolved it.

## Temporary validation KQL

```kusto
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4625
| where Account contains "soc-test-user"
| where LogonType in (3, 10)
| where isnotempty(IpAddress)
| where IpAddress != "-"
| summarize
    FailedAttempts=count(),
    FirstAttempt=min(TimeGenerated),
    LastAttempt=max(TimeGenerated)
    by Computer, IpAddress
| where FailedAttempts >= 1
```

This is **test-only** logic, not a recommended production detection rule. The temporary rule was disabled after validation.

## Outcome

| Field | Recorded result |
|---|---|
| Incident | SOC-LAB-TEST - Entity Mapping Validation |
| Defender Incident ID | 2 |
| Severity | Low |
| Alerts | 1 |
| Detected affected devices | 1 |
| Supporting IP evidence | 1 |
| Classification | Benign Positive — Security testing |
| Resolution | Resolved |
| Temporary rule | Disabled |
| Main detection rule | Enabled |

The official incident export contained the host and IP in the attack-story investigation graph and separate impacted-device and IP-evidence sections. The source report is intentionally **not published**, because it includes environment-specific values. This public write-up omits public IP addresses, personal emails, and identifiers.

**Interpretation:** Entity mapping was validated, not an actual compromise. The platform's “Suspicious” evidence label in the report is an automatic alert artifact in the authorized simulation, not independent proof of malicious activity.

## Lessons learned

- Entity mapping enriches an alert with structured investigation context. It is different from simply displaying an IP in KQL results.
- The KQL output must include fields used by the entity identifiers.
- A simulation returning results does not itself prove incident creation; the Defender incident and graph need to be verified.
- A temporary test rule is useful for reusing known events without re-running potentially account-locking authentication tests.
- Grouping and suppression control alert volume, but suppression can also create blind spots and should be used deliberately.
- Mapping the host and IP does not automatically map the account; account entity mapping remains an enhancement.

## Next steps

- Add safe account entity mapping and richer alert details.
- Investigate events proactively using KQL threat-hunting queries.
- Evaluate duplicate-alert controls and detection coverage.
- Create Sentinel workbooks for authentication activity trends.

## Ethical scope

All activity was carried out in a controlled, authorized lab. This case study demonstrates practical learning and is not a claim of production SOC employment or a real-world intrusion.
