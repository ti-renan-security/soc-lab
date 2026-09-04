# Sysmon Event ID 3 — PowerShell Network Connection Investigation

## Overview

This investigation documents a controlled SOC lab exercise focused on detecting and analyzing outbound network connections initiated by PowerShell using Sysmon Event ID 3 and Wazuh.

The objective was to validate the complete telemetry path from the Windows endpoint to the SIEM and then test a custom alert rule for PowerShell network activity.

## Lab Environment

- Endpoint: `CLIENT01`
- Endpoint IP: `10.100.10.20`
- Domain: `northtech.corp`
- SIEM Manager: `sec-wazuh01`
- Data source: `Microsoft-Windows-Sysmon/Operational`
- Sysmon Event ID: `3 — Network connection`
- Wazuh Agent ID: `001`

## Objective

Validate the following detection pipeline:

```text
PowerShell
   ↓
Outbound network connection
   ↓
Sysmon Event ID 3
   ↓
Wazuh Agent
   ↓
Wazuh Manager
   ↓
Custom detection / SOC investigation
```

## Sysmon Configuration

Sysmon was initially installed with network connection monitoring disabled.

A dedicated configuration was added to collect network connections initiated by PowerShell:

```xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256</HashAlgorithms>

  <EventFiltering>
    <ProcessCreate onmatch="exclude">
    </ProcessCreate>

    <NetworkConnect onmatch="include">
      <Image condition="end with">powershell.exe</Image>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```

After loading the configuration, `sysmon64 -c` confirmed:

```text
Network connection: enabled
NetworkConnect: include
Image filter: end with powershell.exe
```

## Test Activity

A benign HTTPS request was generated from PowerShell:

```powershell
Invoke-WebRequest https://example.com -UseBasicParsing
```

The request returned HTTP status `200 OK`.

## Endpoint Evidence

Sysmon generated Event ID 3 with the following relevant fields:

```text
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: NORTHTECH\Administrator
Protocol: tcp
Initiated: true
SourceIp: 10.100.10.20
DestinationIp: 104.20.23.154
DestinationPort: 443
DestinationPortName: https
```

### SOC Interpretation

The event confirms that PowerShell on `CLIENT01` initiated an outbound TCP connection over HTTPS.

The field `Initiated: true` is especially useful because it confirms that the endpoint initiated the connection rather than receiving it.

## Wazuh Collection Validation

The event was successfully received by the Wazuh Manager and stored in:

```text
/var/ossec/logs/archives/archives.json
```

A filtered query confirmed structured Event ID 3 data including:

```text
AGENT=CLIENT01
IMAGE=...\powershell.exe
SRC=10.100.10.20:<dynamic-port>
DST=104.20.23.154:443
```

This proved that the collection pipeline was functioning correctly:

```text
CLIENT01
   ↓
Sysmon Event ID 3
   ↓
Wazuh Agent
   ↓
Wazuh Manager
   ↓
archives.json
```

## Native Wazuh Rule Investigation

The Wazuh native ruleset was inspected to understand how Sysmon Event ID 3 is categorized.

The base rule identified was:

```xml
<rule id="61605" level="0">
  <if_sid>61600</if_sid>
  <field name="win.system.eventID">^3$</field>
  <description>Sysmon - Event 3: Network connection ...</description>
  <options>no_full_log</options>
  <group>sysmon_event3,</group>
</rule>
```

This confirms that Sysmon Event ID 3 is categorized under the Wazuh group:

```text
sysmon_event3
```

Additional native rules were found in:

```text
/var/ossec/ruleset/rules/0810-sysmon_id_3.xml
```

## Custom Detection Attempt

The custom rule ID `100202` was created to alert on network connections initiated by PowerShell.

Initial version:

```xml
<rule id="100202" level="8">
  <if_group>sysmon_event3</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe$</field>
  <description>PowerShell initiated a network connection</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```

Multiple troubleshooting approaches were tested:

- `if_group` with `sysmon_event3`
- `if_sid` with native rule `61605`
- direct matching on `win.system.eventID = 3`
- direct decoder and provider matching
- temporary removal of the PowerShell image filter
- syntax validation with `wazuh-analysisd -t`
- Wazuh Manager restart after rule changes
- full search of `alerts.json` for rule `100202`

## Troubleshooting Result

The raw Sysmon Event ID 3 continued to arrive correctly in `archives.json`, but rule `100202` did not generate an entry in `alerts.json` during this exercise.

No syntax error related to rule `100202` was observed during rule validation or Wazuh Manager startup.

Therefore, the final lab finding was:

```text
Sysmon Event ID 3 generated          ✅
Wazuh Agent forwarding               ✅
Wazuh Manager receiving              ✅
Structured event in archives.json    ✅
Custom rule syntax valid             ✅
Custom alert 100202 generated        ❌
```

This case was intentionally documented rather than hidden because troubleshooting failed detections is part of real detection engineering work.

## MITRE ATT&CK Context

The PowerShell process itself maps to:

```text
T1059.001 — Command and Scripting Interpreter: PowerShell
Tactic: Execution
```

The Event ID 3 telemetry provides network context that can be correlated with PowerShell execution to increase confidence during SOC investigation.

## SOC Lessons Learned

This investigation reinforced several practical SOC and detection-engineering concepts:

- Raw event ingestion must be validated separately from alert generation.
- `archives.json` and `alerts.json` serve different purposes.
- A detection rule can fail even when telemetry collection is healthy.
- Troubleshooting should isolate the pipeline step by step rather than changing multiple conditions at once.
- Native rule inheritance, groups and decoded fields must be verified against actual event structure.
- Network telemetry provides important context for suspicious scripting activity.
- Documenting unsuccessful detection attempts is valuable because it demonstrates analytical methodology and engineering discipline.

## Final Status

```text
Telemetry collection: SUCCESS
Event ID 3 visibility: SUCCESS
PowerShell network evidence: SUCCESS
Custom alert 100202: NOT TRIGGERED
Investigation status: DOCUMENTED FOR FURTHER RESEARCH
```

## Next Step

Continue the SOC lab with Sysmon Event ID 11 — File Create, focusing on file creation initiated by PowerShell and correlation with process execution activity.

## Disclaimer

This exercise was performed exclusively in a controlled cybersecurity laboratory for educational and defensive security purposes.
