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

Investigation of repeated failed Windows authentication attempts detected using Wazuh.

**Topics covered:**

- Windows Security Event ID 4625
- Wazuh Rule 60122
- Interactive logon analysis
- Authentication Status and SubStatus
- Repeated failed authentication correlation
- Basic SOC triage
- MITRE ATT&CK context

➡️ [View the full investigation](investigations/failed-logon-event-4625/)

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
