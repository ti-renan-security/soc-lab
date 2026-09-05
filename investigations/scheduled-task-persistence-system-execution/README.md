# Scheduled Task Persistence and SYSTEM Execution — Correlated Detection

## Overview

This investigation documents a Windows persistence detection use case built in a controlled SOC lab using Windows Task Scheduler telemetry, Sysmon, and Wazuh.

The goal was to detect a newly created scheduled task, correlate it with later execution of the same task, and then identify a process launched by the Task Scheduler service under the `NT AUTHORITY\SYSTEM` security context.

The final detection chain combines Windows Task Scheduler events with Sysmon process telemetry and maps the behavior to MITRE ATT&CK `T1053.005 — Scheduled Task`.

## Lab Environment

- Endpoint: `CLIENT01.northtech.corp`
- Endpoint IP: `10.100.10.20`
- Wazuh agent ID: `001`
- Wazuh manager: `sec-wazuh01`
- Windows Task Scheduler Operational log enabled
- Sysmon Event ID `1 — Process Create` enabled

## Detection Objective

Build a progressive detection chain for the following behavior:

```text
Scheduled task created
        ↓
Same task executed
        ↓
Task Scheduler launches process
        ↓
Process runs as NT AUTHORITY\SYSTEM
        ↓
High-severity persistence alert
```

## Telemetry Collection

The Wazuh agent was configured to collect:

```xml
<localfile>
  <location>Microsoft-Windows-TaskScheduler/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

This allowed Task Scheduler Operational events to be ingested into Wazuh and validated in `archives.json`.

## Relevant Windows Events

### Event ID 106 — Scheduled Task Registered

A newly created task generated Event ID `106`.

Observed fields included:

```text
taskName
userContext
```

Example:

```text
taskName: \SOC-Lab-Persistence-4
userContext: NORTHTECH\Administrator
```

Wazuh native rule `67014` detected this event and mapped it to:

```text
MITRE ATT&CK: T1053.005 — Scheduled Task
Tactics: Execution, Persistence, Privilege Escalation
```

### Event ID 129 — Scheduled Task Launched a Process

When the task executed, Event ID `129` identified the process launched by the task.

Example:

```text
taskName: \SOC-Lab-Persistence-4
path: cmd.exe
processID: 9552
```

This event was successfully collected by Wazuh but initially had no native alert rule associated with it.

### Additional Task Scheduler Events Observed

The successful execution sequence also generated:

```text
106 — task registered
140 — task updated
325 — task instance queued
110 — task launched
129 — process launched
100 — task execution started
200 — action started
201 — action completed
102 — task completed successfully
```

These events helped reconstruct the complete scheduled-task execution timeline.

## Controlled Test

A benign scheduled task was created to run as `SYSTEM` and write a text file:

```powershell
schtasks /create /tn "SOC-Lab-Persistence-4" /tr "cmd.exe /c echo Persistence Correlation 4 > C:\Temp\persistence-correlation-4.txt" /sc once /st 23:59 /ru SYSTEM /f
```

The task was then manually started:

```powershell
schtasks /run /tn "SOC-Lab-Persistence-4"
```

Successful execution was confirmed by reading:

```text
C:\Temp\persistence-correlation-4.txt
```

## Custom Detection Rules

### Rule 100300 — Scheduled Task Created

```xml
<rule id="100300" level="8">
  <if_sid>67014</if_sid>
  <description>Scheduled task created</description>
  <mitre>
    <id>T1053.005</id>
  </mitre>
</rule>
```

Purpose:

- promote Task Scheduler creation telemetry into a custom Level 8 detection;
- use Wazuh native rule `67014` as the parent rule.

## Rule 100302 — Scheduled Task Launched a Process

The Event ID `129` telemetry did not generate a native alert, so a custom rule was added using the same Windows event-channel base used by Task Scheduler rules:

```xml
<rule id="100302" level="7">
  <if_sid>60009</if_sid>
  <field name="win.system.providerName">Microsoft-Windows-TaskScheduler</field>
  <field name="win.system.eventID">^129$</field>
  <description>Scheduled task launched a process</description>
  <mitre>
    <id>T1053.005</id>
  </mitre>
</rule>
```

## Rule 100301 — Same Scheduled Task Created and Executed

The creation and execution events were correlated by task name:

```xml
<rule id="100301" level="12" frequency="2" timeframe="300">
  <if_matched_sid>100300</if_matched_sid>
  <if_sid>100302</if_sid>
  <same_field>win.eventdata.taskName</same_field>
  <description>Scheduled task created and then executed</description>
  <mitre>
    <id>T1053.005</id>
  </mitre>
</rule>
```

This correlation significantly improves confidence because the alert is generated only when the same `taskName` was recently created and later executed on the endpoint.

### Validated Result

```text
RULE=100300 | LEVEL=8
TASK=\SOC-Lab-Persistence-4
Scheduled task created

RULE=100301 | LEVEL=12
TASK=\SOC-Lab-Persistence-4
PATH=cmd.exe
Scheduled task created and then executed
```

## PID Correlation with Sysmon

Task Scheduler Event ID `129` identified:

```text
path: cmd.exe
processID: 9552
```

The same PID was then searched in Sysmon Event ID `1`.

The matching process event showed:

```text
ProcessId: 9552
Image: C:\Windows\System32\cmd.exe
CommandLine: "cmd.exe" /c echo Persistence Correlation 4 > C:\Temp\persistence-correlation-4.txt
User: NT AUTHORITY\SYSTEM
IntegrityLevel: System
ParentImage: C:\Windows\System32\svchost.exe
ParentCommandLine: C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s Schedule
```

This proved that the process identified by Task Scheduler telemetry was the same process observed by Sysmon.

## Rule 100303 — Task Scheduler Process Execution as SYSTEM

A high-severity behavioral rule was created to detect a process launched by the Windows Task Scheduler service under the `SYSTEM` account.

Final validated rule:

```xml
<rule id="100303" level="14">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.parentCommandLine" type="pcre2">(?i)-s\s+Schedule</field>
  <field name="win.eventdata.user" type="pcre2">(?i)^NT AUTHORITY.*SYSTEM$</field>
  <description>Scheduled Task launched a process as SYSTEM</description>
  <mitre>
    <id>T1053.005</id>
  </mitre>
</rule>
```

### Validated Alert

```text
RULE=100303
LEVEL=14
IMAGE=C:\Windows\System32\cmd.exe
USER=NT AUTHORITY\SYSTEM
PARENTCMD=C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule
```

The corresponding Wazuh alert showed:

```text
Process: C:\Windows\System32\cmd.exe
PID: 10120
User: NT AUTHORITY\SYSTEM
IntegrityLevel: System
Parent: C:\Windows\System32\svchost.exe
ParentCommandLine: svchost.exe -k netsvcs -p -s Schedule
```

## Detection Chain

```text
Task created
   ↓
Event ID 106
   ↓
Rule 100300 — Level 8
   ↓
Same task launches process
   ↓
Event ID 129
   ↓
Rule 100302 — Level 7
   ↓
same_field(taskName)
   ↓
Rule 100301 — Level 12
   ↓
Sysmon Event ID 1
   ↓
Task Scheduler service launches process as SYSTEM
   ↓
Rule 100303 — Level 14
```

## SOC Analysis

In a production environment, a newly created scheduled task followed by execution of the same task should be investigated, especially when the launched process runs as `SYSTEM`.

The following evidence increases confidence:

- newly registered task;
- same task executed shortly afterward;
- process launch confirmed by Task Scheduler Event ID `129`;
- PID linked to Sysmon Event ID `1`;
- `svchost.exe -s Schedule` identified as the parent service;
- process executed as `NT AUTHORITY\SYSTEM`;
- `IntegrityLevel: System` observed in telemetry.

A scheduled task running as `SYSTEM` can be legitimate, so the behavior alone does not prove malicious activity. The full command line, task configuration, child processes, network activity, created files, and surrounding endpoint activity should be reviewed.

## Lab Disposition

```text
Status: Closed
Detection: True Positive
Threat: Benign
Disposition: Benign True Positive
Reason: Authorized controlled persistence simulation
```

## Troubleshooting Lessons

Several useful detection-engineering lessons came from this exercise:

- Event ID `129` was present in `archives.json` but initially had no native alert rule.
- Creating an intermediate alert rule for Event ID `129` allowed reliable correlation.
- Rule dependency order matters: parent rules must appear before rules that reference them.
- `same_field` using `win.eventdata.taskName` produced a much more precise correlation than generic timing alone.
- A field can be valuable during investigation even when it is not ideal as a rule condition.
- The original exact regex for `NT AUTHORITY\SYSTEM` did not match reliably; the more resilient expression `^NT AUTHORITY.*SYSTEM$` worked with the decoded field representation.
- Progressive testing one condition at a time helped isolate rule-matching issues without breaking working detections.

## MITRE ATT&CK Mapping

- `T1053.005 — Scheduled Task`
- Tactics:
  - Execution
  - Persistence
  - Privilege Escalation

## Key Takeaway

This investigation demonstrates how multiple telemetry sources can be combined to move from a simple scheduled-task event to a high-confidence behavioral detection:

> A scheduled task was created, the same task was executed, the resulting process was identified by PID, and Sysmon confirmed that the Task Scheduler service launched the process as `SYSTEM`.

This is more valuable than relying on a single event because it reconstructs the behavior as a sequence rather than treating each alert in isolation.

## Disclaimer

This activity was performed exclusively in an isolated lab environment for defensive security education and detection-engineering practice.
