# PowerShell File Creation and Execution — Correlated Detection

## Overview

This investigation documents a behavioral detection engineering use case built in a controlled SOC lab using Sysmon and Wazuh.

The objective was to move beyond isolated alerts and correlate a sequence of PowerShell behaviors:

1. PowerShell creates a potentially suspicious file.
2. PowerShell executes a script using `-ExecutionPolicy Bypass`.
3. Both activities are associated with the same user and endpoint within a short time window.
4. The executed script is located in a temporary directory.

The result is a higher-confidence correlated alert that represents a suspicious behavior chain rather than a single event.

## Lab Environment

- Endpoint: `CLIENT01`
- Endpoint IP: `10.100.10.20`
- Domain: `northtech.corp`
- User used during the controlled test: `NORTHTECH\Administrator`
- SIEM: Wazuh
- Wazuh Manager: `sec-wazuh01`
- Telemetry source: Microsoft Sysmon
- Event channel: `Microsoft-Windows-Sysmon/Operational`

## Sysmon Telemetry

Two Sysmon event types were used.

### Event ID 11 — File Create

Sysmon Event ID 11 records file creation activity.

A controlled PowerShell test created files such as:

```text
C:\Temp\soc-test-4.txt
C:\Temp\exec-test.ps1
C:\Temp\correlation-test.ps1
C:\Temp\same-user-test.ps1
C:\Temp\temp-regex-test.ps1
```

The Event ID 11 telemetry included fields such as:

```text
Image
ProcessId
TargetFilename
User
CreationUtcTime
```

Example process:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

### Event ID 1 — Process Create

Sysmon Event ID 1 records process creation.

A controlled script execution was generated with:

```powershell
powershell.exe -ExecutionPolicy Bypass -File C:\Temp\temp-regex-test.ps1
```

The event contained:

```text
Image: powershell.exe
CommandLine: powershell.exe -ExecutionPolicy Bypass -File C:\Temp\temp-regex-test.ps1
User: NORTHTECH\Administrator
IntegrityLevel: High
ParentImage: powershell.exe
```

## Wazuh Ingestion Validation

Before creating detections, raw telemetry was validated in:

```text
/var/ossec/logs/archives/archives.json
```

This confirmed that:

- Sysmon generated the events.
- The Wazuh Agent collected them.
- The Wazuh Manager received them.
- Fields such as `image`, `targetFilename`, `commandLine`, and `user` were available for rule evaluation.

A key lesson from the exercise was the distinction between:

```text
archives.json = raw events received by Wazuh
alerts.json   = events that matched alerting rules
```

## Native Wazuh Rules Used

The investigation reviewed native Wazuh Sysmon rules before building custom detections.

### Sysmon Event ID 11 base rule

Native Wazuh rule:

```text
61613
```

It assigns Sysmon Event ID 11 events to the group:

```text
sysmon_event_11
```

### PowerShell script execution rule

Native Wazuh rule:

```text
92028
```

Description:

```text
PowerShell executed script
```

This rule detects PowerShell command lines containing script extensions such as `.ps1`.

Using native Wazuh logic as a foundation made the custom rules more reliable and reduced unnecessary duplication.

## Custom Detection Rules

### Rule 100203 — PowerShell created a file

```xml
<rule id="100203" level="8">
  <if_group>sysmon_event_11</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe$</field>
  <description>PowerShell created a file</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```

Purpose:

- Detect any file creation performed by PowerShell.
- Provide baseline visibility.
- Generate a Level 8 alert.

### Rule 100204 — PowerShell created a potentially suspicious file

```xml
<rule id="100204" level="10">
  <if_sid>100203</if_sid>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i)\.(ps1|exe|dll|bat|cmd|vbs|js|hta)$</field>
  <description>PowerShell created a potentially suspicious file</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```

Purpose:

- Increase severity when PowerShell creates script or executable-like file extensions.
- Generate a Level 10 alert.

This rule intentionally identifies potentially suspicious file types rather than declaring them malicious.

## File Triage Example

A controlled file named:

```text
C:\Temp\virus.exe
```

triggered Rule `100204`.

The file was then investigated instead of assuming it was malware.

The following checks were performed:

```powershell
Get-FileHash C:\Temp\virus.exe -Algorithm SHA256
Get-Item C:\Temp\virus.exe | Format-List Name,Length,CreationTime,LastWriteTime
Get-Content C:\Temp\virus.exe
Format-Hex C:\Temp\virus.exe
```

Findings:

- File size: 52 bytes.
- Content: plain PowerShell text.
- The file did not begin with the Windows PE `MZ` header.
- The `.exe` extension did not represent the real file type.

This reinforced an important SOC principle:

> A suspicious filename or extension is an indicator for investigation, not proof of malware.

## Rule 100205 — PowerShell script execution with ExecutionPolicy Bypass

The initial custom logic was refined after reviewing Wazuh native rule `92028`.

Final rule:

```xml
<rule id="100205" level="11">
  <if_sid>92028</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)-executionpolicy\s+bypass</field>
  <description>PowerShell executed script with ExecutionPolicy Bypass</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```

Purpose:

- Reuse Wazuh's native PowerShell script-execution detection.
- Increase severity when the script is executed with `ExecutionPolicy Bypass`.
- Generate a Level 11 alert.

Example command:

```text
powershell.exe -ExecutionPolicy Bypass -File C:\Temp\exec-test.ps1
```

## Rule 100206 — Correlated creation and execution by the same user

Rule `100206` correlates the file-creation and script-execution behaviors.

```xml
<rule id="100206" level="13" frequency="2" timeframe="300">
  <if_matched_sid>100204</if_matched_sid>
  <if_sid>100205</if_sid>
  <same_field>win.eventdata.user</same_field>
  <description>PowerShell created a suspicious file and then executed a script with ExecutionPolicy Bypass by the same user</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```

Correlation logic:

```text
100204 — suspicious file created
        +
100205 — script executed with ExecutionPolicy Bypass
        +
same user
        +
same Wazuh agent context
        +
within 300 seconds
        =
100206 — Level 13
```

This represents a more meaningful behavioral chain than either event alone.

## Rule 100207 — High-confidence Temp directory execution

The final refinement increased severity when the correlated execution involved a temporary path.

A simpler regular expression was intentionally used after testing showed that an over-specific path expression failed to match the real command line format.

```xml
<rule id="100207" level="14" frequency="2" timeframe="300">
  <if_matched_sid>100204</if_matched_sid>
  <if_sid>100205</if_sid>
  <same_field>win.eventdata.user</same_field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)Temp.*\.ps1</field>
  <description>High-confidence PowerShell execution from Temp after suspicious file creation by the same user</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```

Validated test command:

```text
powershell.exe -ExecutionPolicy Bypass -File C:\Temp\temp-regex-test.ps1
```

Result:

```text
RULE=100207
LEVEL=14
USER=NORTHTECH\Administrator
```

## Final Detection Chain

```text
PowerShell creates a suspicious file
        ↓
Sysmon Event ID 11
        ↓
100203 — Level 8
PowerShell created a file
        ↓
100204 — Level 10
Potentially suspicious extension
        ↓
PowerShell executes a script
with ExecutionPolicy Bypass
        ↓
Sysmon Event ID 1
        ↓
Native 92028
PowerShell executed script
        ↓
100205 — Level 11
Script + ExecutionPolicy Bypass
        ↓
100206 — Level 13
Creation + execution correlated
same user / same endpoint context
        ↓
100207 — Level 14
Execution from Temp path
```

## MITRE ATT&CK Mapping

The detection chain is mapped to:

```text
Tactic: Execution
Technique: Command and Scripting Interpreter
Sub-technique: T1059.001 — PowerShell
```

The mapping describes the execution mechanism observed in the lab. It does not by itself establish malicious intent.

## SOC Analysis of Rule 100207

The validated Level 14 event contained:

```text
Endpoint: CLIENT01.northtech.corp
IP: 10.100.10.20
User: NORTHTECH\Administrator
Process: powershell.exe
Process ID: 4124
Parent Process: powershell.exe
Integrity Level: High
CommandLine: powershell.exe -ExecutionPolicy Bypass -File C:\Temp\temp-regex-test.ps1
Rule ID: 100207
Rule Level: 14
MITRE: T1059.001
```

From a SOC perspective, the combined indicators justify high-priority investigation because they include:

- PowerShell execution.
- Script execution.
- `ExecutionPolicy Bypass`.
- Temporary-directory execution.
- Elevated integrity level.
- PowerShell parent process.
- Prior suspicious file creation.
- Same-user correlation.
- Same endpoint context.
- Short correlation window.

However, even a Level 14 alert does not automatically prove malware.

In production, additional investigation would include:

- Reviewing the script content.
- Calculating the script SHA256.
- Checking file reputation and threat intelligence.
- Reviewing digital signatures where applicable.
- Looking for network connections.
- Reviewing child processes.
- Searching for persistence.
- Hunting for the same indicators on other endpoints.
- Confirming whether the activity was authorized.

## Final Lab Disposition

```text
Status: Closed
Detection: True Positive
Threat classification: Benign
Disposition: Benign True Positive
Reason: Authorized controlled SOC lab activity
```

The detection was correct because the observed behaviors really occurred. The activity was benign because it was intentionally generated as part of the controlled lab.

## Key Lessons Learned

- Sysmon Event ID 11 provides useful file-creation telemetry.
- Sysmon Event ID 1 provides process and command-line context.
- Raw telemetry must be validated before troubleshooting detection rules.
- `archives.json` and `alerts.json` serve different purposes.
- Native Wazuh rules can be reused as reliable parents for custom detections.
- More specific detections should build on previously validated behavior.
- A suspicious extension does not prove a file is malware.
- SHA256 is useful as a file identifier and IOC, but unknown reputation does not prove a file is safe.
- Parent process, command line, integrity level, file path, user, network activity, persistence, and reputation should be combined during triage.
- Behavioral correlation produces higher-confidence alerts than isolated indicators.
- `same_field` can reduce false positives by tying events to the same user.
- Overly restrictive regular expressions can prevent otherwise-correct detections from firing.
- Detection engineering requires iterative testing and troubleshooting.

## Disclaimer

All activity described in this investigation was performed in a controlled lab for educational and defensive-security purposes only.
