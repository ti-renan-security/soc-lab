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

## Lab Environment

The environment includes:

- Windows endpoint
- Wazuh SIEM / security monitoring
- pfSense firewall
- Virtualized lab environment
- Network traffic monitoring
- Security logs and alerts

## Activities

The lab will include practical exercises such as:

- Monitoring Windows authentication events
- Investigating failed login attempts
- Analyzing security alerts
- Reviewing firewall and network logs
- Simulating controlled suspicious activity
- Identifying Indicators of Compromise (IOCs)
- Documenting incident investigation steps
- Creating basic incident response reports

## Tools

- Wazuh
- pfSense
- Windows Event Viewer
- Wireshark
- Virtualization
- TCP/IP
- Security logs

## Project Roadmap

- [ ] Build and document lab architecture
- [ ] Configure Wazuh monitoring
- [ ] Connect Windows endpoint to Wazuh
- [ ] Configure pfSense firewall
- [ ] Generate and analyze authentication events
- [ ] Investigate suspicious login activity
- [ ] Analyze network traffic with Wireshark
- [ ] Document first security incident investigation
- [ ] Map detections to MITRE ATT&CK techniques

## Disclaimer

This lab is used exclusively for educational and defensive cybersecurity purposes in a controlled environment.
