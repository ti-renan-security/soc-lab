# PowerShell EncodedCommand and File Creation — Correlated Investigation

## Overview

This investigation documents a controlled SOC lab exercise in which a PowerShell process launched another PowerShell process with a Base64-encoded command. Wazuh detected the encoded execution, and Sysmon telemetry was then correlated with the file created by the same process.

The objective was to practice a complete analyst workflow:

1. Generate a benign encoded PowerShell command.
2. Detect the execution in Wazuh.
3. Review Sysmon process-creation telemetry.
4. Extract and decode the Base64 payload.
5. Correlate the execution with Sysmon file-creation telemetry.
6. Validate the relationship using both `ProcessGuid` and `ProcessId`.
7. Map the observed behavior to MITRE ATT&CK.
8. Assign a final SOC disposition.

## Lab Environment

- Endpoint: `CLIENT01.northtech.corp`
- Endpoint IP: `10.100.10.20`
- Wazuh agent ID: `001`
- User: `NORTHTECH\renan.lab`
- Wazuh Manager: `sec-wazuh01`
- Telemetry source: Microsoft Sysmon
- Event channel: `Microsoft-Windows-Sysmon/Operational`
- SIEM: Wazuh

## Detection Objective

Identify and investigate this behavior chain:

```text
PowerShell
    ↓
PowerShell launched with -EncodedCommand
    ↓
Sysmon Event ID 1 — Process Create
    ↓
Wazuh Rule 92057 — Level 12
    ↓
Decode Base64 payload
    ↓
PowerShell creates a file
    ↓
Sysmon Event ID 11 — File Create
    ↓
Wazuh Rule 100203 — Level 8
    ↓
Correlate by ProcessGuid + ProcessId
```

## Controlled Test

A benign PowerShell command was prepared:

```powershell
$command = "Write-Output 'SOC-LAB-ENCODED-TEST' | Out-File C:\Users\Public\soc_lab_encoded_test.txt"
```

The command was converted to the UTF-16LE Base64 format expected by Windows PowerShell:

```powershell
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [Convert]::ToBase64String($bytes)
```

It was then executed with:

```powershell
powershell.exe -NoProfile -EncodedCommand $encoded
```

Successful execution was validated with:

```powershell
Get-Content C:\Users\Public\soc_lab_encoded_test.txt
```

Expected content:

```text
SOC-LAB-ENCODED-TEST
```

All activity was intentionally generated in an isolated lab.

## Detection 1 — Encoded PowerShell Execution

Wazuh detected the execution using native Rule `92057`.

### Alert

```text
Rule ID: 92057
Level: 12
Description: Powershell.exe spawned a powershell process which executed a base64 encoded command
MITRE ATT&CK: T1059.001 — PowerShell
Tactic: Execution
```

### Sysmon Event ID 1

The underlying Sysmon Process Create event contained:

```text
Computer: CLIENT01.northtech.corp
User: NORTHTECH\renan.lab
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ProcessId: 12260
ParentProcessId: 3556
ProcessGuid: {e9c1a367-8064-6aca-d406-000000001400}
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
IntegrityLevel: Medium
UtcTime: 2026-10-10 18:13:56.185
```

Observed command line:

```text
"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -EncodedCommand <Base64>
```

The process chain was therefore:

```text
powershell.exe
    └── powershell.exe -NoProfile -EncodedCommand <Base64>
```

## Base64 Analysis

The encoded value from the command line was decoded as UTF-16LE.

Decoded payload:

```powershell
Write-Output 'SOC-LAB-ENCODED-TEST' | Out-File C:\Users\Public\soc_lab_encoded_test.txt
```

This step was important because the use of `-EncodedCommand` is a behavioral indicator, but the encoding itself does not establish malicious intent.

The decoded command showed that the payload only wrote a known test string to a file in `C:\Users\Public`.

## Detection 2 — PowerShell File Creation

The resulting file activity was detected by custom Wazuh Rule `100203`.

### Alert

```text
Rule ID: 100203
Level: 8
Description: PowerShell created a file
```

The underlying Sysmon File Create event contained:

```text
Event ID: 11
Computer: CLIENT01.northtech.corp
User: NORTHTECH\renan.lab
Image: C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe
ProcessId: 12260
ProcessGuid: {e9c1a367-8064-6aca-d406-000000001400}
TargetFilename: C:\Users\Public\soc_lab_encoded_test.txt
UtcTime: 2026-10-10 18:13:56.405
```

## Process Correlation

The strongest evidence in this investigation was not simply temporal proximity.

Both the process-creation event and the file-creation event contained the same process identifiers:

```text
ProcessId:   12260
ProcessGuid: {e9c1a367-8064-6aca-d406-000000001400}
```

This directly links the PowerShell process that executed the encoded command to the PowerShell process that created:

```text
C:\Users\Public\soc_lab_encoded_test.txt
```

### Correlated Timeline

```text
NORTHTECH\renan.lab
        │
        ▼
powershell.exe
        │
        ▼
powershell.exe -NoProfile -EncodedCommand <Base64>
        │
        ├── Sysmon Event ID 1
        ├── PID 12260
        ├── ProcessGuid {e9c1a367-8064-6aca-d406-000000001400}
        ├── Wazuh Rule 92057
        └── Level 12
                │
                ▼
        Base64 decoded
                │
                ▼
Write-Output ... | Out-File C:\Users\Public\soc_lab_encoded_test.txt
                │
                ▼
        Sysmon Event ID 11
        PID 12260
        Same ProcessGuid
                │
                ▼
        Rule 100203 — Level 8
        PowerShell created a file
```

## MITRE ATT&CK Mapping

The encoded PowerShell execution was mapped by Wazuh to:

- Tactic: `Execution`
- Technique: `Command and Scripting Interpreter`
- Sub-technique: `T1059.001 — PowerShell`

This mapping describes the observed execution mechanism. It does not by itself prove malicious intent.

## SOC Triage

The initial alert justified investigation because it contained several relevant indicators:

- PowerShell launched PowerShell.
- The child process used `-EncodedCommand`.
- The command content was obscured with Base64.
- Wazuh assigned the detection Level 12.
- Sysmon provided full process and command-line context.

The analyst workflow then reduced uncertainty:

1. Extract the encoded value.
2. Decode it using the correct PowerShell character encoding.
3. Review the recovered command.
4. Identify the expected output file.
5. Search for corresponding file-creation telemetry.
6. Correlate Event ID 1 and Event ID 11 using `ProcessGuid` and `ProcessId`.
7. Confirm the activity was part of an authorized lab test.

## Final Disposition

```text
Status: Closed
Detection: True Positive
Threat classification: Benign
Disposition: Benign True Positive
Reason: Authorized controlled SOC lab activity
```

The alert is a true positive because the behavior detected by Wazuh genuinely occurred: PowerShell executed a Base64-encoded command.

The activity is benign because analysis of the decoded payload and correlated file creation confirmed that it was the authorized SOC lab test.

This distinction is important:

> A true-positive detection does not automatically mean the underlying activity is malicious.

## Key Lessons Learned

- PowerShell `-EncodedCommand` is an investigation signal, not proof of malicious activity.
- Base64 should be decoded before making a threat determination.
- Windows PowerShell `-EncodedCommand` uses Unicode/UTF-16LE encoding.
- Sysmon Event ID 1 provides process, parent-process, user, hash, integrity-level, and command-line context.
- Sysmon Event ID 11 provides evidence of files created by a process.
- `ProcessGuid` is especially valuable for correlating Sysmon events.
- `ProcessId` provides additional supporting correlation context.
- Behavioral detection should be followed by payload and consequence analysis.
- Wazuh native detections can be correlated with custom lab rules to reconstruct a complete activity chain.
- Severity represents detection priority and context; it does not replace analyst investigation.
- Benign true positives are useful for validating telemetry, detection logic, and analyst workflow.

## Analyst Takeaway

This exercise demonstrates a practical SOC workflow from alert to disposition:

```text
Detect → Triage → Decode → Correlate → Validate → Classify → Document
```

Rather than stopping at a high-severity encoded-PowerShell alert, the investigation used endpoint telemetry to determine exactly what the process executed and what artifact it created.

## Disclaimer

All activity described in this investigation was performed in a controlled lab for educational and defensive-security purposes only.
