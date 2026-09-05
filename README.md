# SOC Lab — Blue Team & Security Monitoring

Hands-on cybersecurity lab focused on Security Operations Center (SOC) activities, log analysis, network monitoring, incident detection and defensive security.

## Objectives

This lab is designed to develop practical skills in:

- Security monitoring
- SIEM
- Log analysis
- Incident detection
- Incident response
- Network security
- Threat investigation
- Windows event analysis
- Defensive security
- Detection engineering
- MITRE ATT&CK mapping

## SOC Investigations

### Windows Failed Logon — Event ID 4625

Investigation of failed Windows logon attempts collected by Wazuh from `CLIENT01`.

The exercise covered:

- Windows Security Event ID 4625
- Failed interactive logon analysis
- Wazuh Rule ID 60122
- Authentication failure status codes
- Repeated failed logon detection
- SOC triage and event interpretation

[View investigation](investigations/failed-logon-event-4625/)

---

### Domain Credential Validation Failure — Event ID 4776

Investigation of failed Active Directory credential validation attempts generated from `CLIENT01` and processed by the Domain Controller `NTS-YTO-AD01`.

The exercise covered:

- Windows Security Event ID 4776
- Active Directory credential validation
- Status code `0xC000006A`
- Windows Advanced Audit Policy
- Wazuh EventChannel collection
- Analysis of Wazuh default Rule ID 60104
- Creation of custom Wazuh Rule ID 100100
- Level 7 SIEM alert
- Wazuh Threat Hunting validation
- MITRE ATT&CK T1110 contextual mapping
- SOC authentication-event analysis

[View investigation](investigations/domain-credential-validation-4776/)

---

### Brute Force Followed by Successful Logon — Correlated Detection

Custom Wazuh detection engineering use case that correlates repeated Windows authentication failures for the same account with a later successful logon.

The exercise covered:

- Windows Security Event IDs `4625` and `4624`
- Windows Logon Types `2`, `7`, and `11`
- Custom Wazuh Rules `100102`, `100103`, and `100104`
- Same-user correlation with `same_field`
- Time-based correlation using `frequency` and `timeframe`
- Level 10 possible brute-force alert
- Level 12 successful-logon-after-brute-force alert
- Identity normalization between UPN and NetBIOS username formats
- Alert-noise reduction and duplicate suppression by refining Logon Types
- MITRE ATT&CK `T1110 — Brute Force`
- MITRE ATT&CK `T1078 — Valid Accounts`
- SOC Tier 1 triage workflow

[View investigation](investigations/brute-force-successful-logon/)

---

### Sysmon Event ID 3 — PowerShell Network Connection Investigation

Detection-engineering and troubleshooting exercise focused on outbound network connections initiated by PowerShell and collected through Sysmon Event ID 3.

The exercise covered:

- Enabling Sysmon NetworkConnect telemetry
- Filtering Event ID 3 for `powershell.exe`
- Generating controlled HTTPS traffic with PowerShell
- Validating source IP, destination IP, protocol and destination port
- Confirming raw ingestion in Wazuh `archives.json`
- Reviewing native Wazuh rule `61605` and group `sysmon_event3`
- Building and troubleshooting custom rule `100202`
- Separating telemetry collection from alert generation
- Documenting a detection that did not trigger despite healthy raw-event ingestion
- MITRE ATT&CK `T1059.001 — PowerShell` context

[View investigation](investigations/sysmon-event3-powershell-network/)

---

### PowerShell File Creation and Execution — Correlated Detection

Behavioral detection engineering use case that correlates suspicious file creation with later PowerShell script execution using `ExecutionPolicy Bypass`.

The exercise covered:

- Enabling and validating Sysmon Event ID `11 — File Create`
- Correlating Sysmon Event IDs `11` and `1`
- Native Wazuh rules `61613` and `92028`
- Custom Wazuh Rules `100203`, `100204`, `100205`, `100206`, and `100207`
- File-extension-based detection enrichment
- Safe file triage using SHA256, file size, content inspection, and PE `MZ` header validation
- Same-user correlation with `same_field`
- Time-based correlation using `frequency` and `timeframe`
- Detection of `ExecutionPolicy Bypass`
- High-confidence execution from a temporary directory
- Progressive severity from Level 8 to Level 14
- MITRE ATT&CK `T1059.001 — PowerShell`
- SOC investigation and benign true-positive disposition

[View investigation](investigations/powershell-file-creation-execution-correlation/)

## Lab Environment

The environment includes:

- Windows endpoint (`CLIENT01`)
- Active Directory Domain Controller (`NTS-YTO-AD01`)
- Wazuh SIEM / security monitoring (`sec-wazuh01`)
- pfSense firewall
- Segmented virtual network
- Network traffic monitoring
- Security logs and alerts

## Activities

The lab includes practical exercises such as:

- Monitoring Windows authentication events
- Investigating failed login attempts
- Analyzing security alerts
- Creating and validating custom Wazuh rules
- Correlating events into higher-confidence detections
- Reviewing firewall and network logs
- Simulating controlled suspicious activity
- Identifying Indicators of Compromise (IOCs)
- Mapping detections to MITRE ATT&CK
- Performing SOC Tier 1 triage
- Reducing false positives and alert fatigue
- Documenting incident investigation steps

## Tools

- Wazuh
- Sysmon
- pfSense
- Windows Event Viewer
- Active Directory
- Wireshark
- VMware virtualization
- Windows Terminal / SSH
- TCP/IP
- Security logs

## Project Roadmap

- [x] Build initial lab architecture
- [x] Configure Wazuh monitoring
- [x] Connect Windows endpoint to Wazuh
- [x] Configure pfSense network segmentation
- [x] Generate and analyze Windows authentication events
- [x] Investigate Event ID 4625 failed logons
- [x] Investigate Event ID 4776 domain credential validation failures
- [x] Create custom Wazuh authentication rules
- [x] Build brute-force correlation for the same user
- [x] Correlate brute force with a subsequent successful logon
- [x] Map detections to MITRE ATT&CK T1110 and T1078
- [x] Validate detections in Wazuh Threat Hunting
- [x] Enable and validate Sysmon Event ID 3 network telemetry
- [x] Document PowerShell network-connection troubleshooting in Wazuh
- [x] Enable and investigate Sysmon Event ID 11 file creation
- [x] Build PowerShell suspicious-file creation detection
- [x] Correlate suspicious file creation with PowerShell script execution
- [x] Add same-user and temporary-path enrichment to correlated detections
- [x] Validate Level 14 high-confidence PowerShell alert in Wazuh Threat Hunting
- [ ] Analyze network traffic with Wireshark
- [ ] Add pfSense firewall-focused detection use cases
- [ ] Build additional SOC investigation playbooks
- [ ] Expand incident-response documentation

## Disclaimer

This lab is used exclusively for educational and defensive cybersecurity purposes in a controlled environment.
