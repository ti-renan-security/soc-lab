# Domain Credential Validation Failure — Event ID 4776

## Overview

This investigation demonstrates the detection and analysis of failed domain credential validation attempts in a Windows Active Directory environment.

The activity was intentionally generated in a controlled SOC lab by submitting incorrect credentials for a valid domain account from a Windows workstation.

The Domain Controller recorded Windows Security Event ID 4776, and Wazuh detected the authentication failure using a custom detection rule.

---

## Lab Environment

| System | Role | IP Address |
|---|---|---|
| SEC-WAZUH01 | Wazuh SIEM Server | 10.100.10.10 |
| NTS-YTO-AD01 | Active Directory Domain Controller / DNS | 10.100.10.5 |
| CLIENT01 | Windows 11 Domain Workstation | 10.100.10.20 |
| FW01-pfSense | Firewall / Gateway | 10.100.10.1 |

Domain:

```text
northtech.corp
