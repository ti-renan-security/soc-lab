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

**Domain:** `northtech.corp`

---

## Investigation Objective

The objective of this exercise was to:

- Generate failed domain authentication attempts.
- Identify Windows Event ID 4776 on the Domain Controller.
- Analyze the authentication failure status code.
- Confirm that Wazuh receives the Windows Security event.
- Create a custom SIEM detection rule.
- Validate the detection in Wazuh Threat Hunting.
- Correlate the activity with MITRE ATT&CK.

---

## Event Generation

A controlled authentication test was performed from `CLIENT01`.

The workstation attempted to authenticate to the Domain Controller using the domain account:

`NORTHTECH\renan.lab`

The SMB IPC connection was first removed:

```powershell
net use \\10.100.10.5\IPC$ /delete
```

A new authentication attempt was then initiated:

```powershell
net use \\10.100.10.5\IPC$ /user:NORTHTECH\renan.lab *
```

Incorrect passwords were intentionally entered multiple times.

---

## Windows Event Detection

The Domain Controller generated Windows Security Event ID 4776.

Relevant information:

```text
Event ID: 4776
Source: Microsoft-Windows-Security-Auditing
Task Category: Credential Validation
TargetUserName: renan.lab
Workstation: CLIENT01
Status: 0xC000006A
```

The status code `0xC000006A` indicates that the username is valid but the supplied password is incorrect.

This confirms that the Domain Controller attempted to validate credentials for an existing domain account, but authentication failed because of an incorrect password.

---

## Advanced Audit Policy

During the investigation, the Domain Controller was initially configured to audit successful credential validation events only.

The audit policy was reviewed using:

```powershell
auditpol /get /category:*
```

Credential Validation was then configured to audit both successful and failed authentication attempts.

This allowed failed Event ID 4776 events to be recorded in the Windows Security log.

---

## Wazuh Event Collection

The Wazuh agent installed on `NTS-YTO-AD01` was configured to monitor the Windows Security event channel.

Example configuration:

```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
```

The Wazuh agent successfully forwarded Event ID 4776 to the Wazuh Manager.

The original event matched the default Wazuh rule:

```text
Rule ID: 60104
Rule Description: Windows audit failure event
Rule Level: 5
```

---

## Custom Detection Rule

A custom Wazuh rule was created to specifically detect failed domain credential validation attempts where:

```text
Event ID = 4776
Status = 0xC000006A
```

Custom rule:

```xml
<group name="windows,">
  <rule id="100100" level="7">
    <if_sid>60104</if_sid>
    <field name="win.system.eventID">4776</field>
    <field name="win.eventdata.status">0xc000006a</field>
    <description>Domain credential validation failed</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

The rule inherits from Wazuh rule `60104` and adds conditions for Windows Event ID 4776 and the incorrect-password status code.

---

## Detection Result

After generating additional failed authentication attempts, Wazuh successfully triggered the custom detection.

Detection details:

```text
Rule ID: 100100
Rule Level: 7
Description: Domain credential validation failed
Agent: NTS-YTO-AD01
Event ID: 4776
Target User: renan.lab
Source Workstation: CLIENT01
Status: 0xC000006A
```

Multiple authentication failures were observed in Wazuh Threat Hunting.

---

## SOC Analysis

Repeated credential validation failures can have several possible explanations:

- User typing an incorrect password.
- Cached or outdated credentials.
- Misconfigured services or scheduled tasks.
- Password guessing.
- Brute-force activity.
- Attempted credential misuse.

In a production SOC environment, the analyst should correlate the event with additional telemetry such as:

- Event ID 4625 — Failed Logon
- Event ID 4624 — Successful Logon
- Event ID 4771 — Kerberos Pre-Authentication Failure
- Event ID 4740 — Account Lockout
- Source workstation
- Target username
- Authentication frequency
- Successful authentication following multiple failures

A sequence of repeated failures followed by a successful authentication could warrant further investigation.

---

## MITRE ATT&CK Context

The custom detection rule includes:

`T1110 — Brute Force`

MITRE ATT&CK T1110 covers techniques where adversaries attempt to gain access by guessing passwords or credentials.

A single Event ID 4776 failure does not by itself confirm malicious brute-force activity.

The MITRE mapping becomes more relevant when multiple repeated authentication failures or other suspicious behavior are observed.

---

## Detection Flow

```text
CLIENT01
   |
   | Incorrect domain password
   v
NTS-YTO-AD01
   |
   | Windows Security Event ID 4776
   v
Wazuh Agent
   |
   | Windows Security EventChannel
   v
Wazuh Manager
   |
   | Base Rule 60104
   v
Custom Rule 100100
   |
   | Level 7 Alert
   v
Wazuh Threat Hunting
```

---

## Evidence

### Windows Event Viewer — Event ID 4776

The Domain Controller recorded a credential validation failure for the domain user `renan.lab` originating from `CLIENT01`.

![Event Viewer — Event ID 4776](Event%20Viewer%20%E2%80%94%20Event%20ID%204776.png)

Relevant fields:

```text
Event ID: 4776
TargetUserName: renan.lab
Workstation: CLIENT01
Status: 0xC000006A
```

---

### Wazuh Threat Hunting — Custom Rule 100100

Wazuh detected multiple failed domain credential validation attempts using the custom rule.

![Wazuh Threat Hunting — Custom Rule 100100](Wazuh%20Threat%20Hunting%20%E2%80%94%20regra%20customizada%20100100.png)

Detection details:

```text
Rule ID: 100100
Rule Level: 7
Description: Domain credential validation failed
```

---

### Wazuh Event Details

The detailed Wazuh event confirmed the source workstation, target account, event ID, and authentication status.

![Wazuh Document Details](Wazuh%20Document%20Details%20%E2%80%94%20detalhes%20t%C3%A9cnicos%20do%20evento.png)

Relevant fields:

```text
Agent: NTS-YTO-AD01
Agent IP: 10.100.10.5
Event ID: 4776
Target User: renan.lab
Workstation: CLIENT01
Status: 0xC000006A
Channel: Security
```

---

## Conclusion

This investigation demonstrated the complete detection workflow for failed Active Directory credential validation.

The lab successfully covered:

- Windows authentication auditing.
- Active Directory credential validation.
- Windows Security Event ID 4776.
- Wazuh EventChannel collection.
- Analysis of Wazuh default rules.
- Creation of a custom SIEM detection rule.
- Alert validation in Threat Hunting.
- MITRE ATT&CK contextual mapping.
- SOC authentication-event analysis.

This exercise demonstrates how a SOC analyst can move from raw Windows authentication telemetry to a customized and actionable SIEM detection.
