# Brute Force Followed by Successful Logon — Wazuh Correlation Use Case

## Overview

This investigation documents a custom Wazuh detection use case for repeated Windows authentication failures followed by a successful logon for the same account.

The goal is to move beyond isolated failed-logon alerts and correlate a sequence that may indicate credential compromise:

```text
Repeated failed logons
        ↓
Possible brute force
        ↓
Successful logon by the same account
        ↓
High-priority correlated alert
```

> A successful logon after multiple failures does not prove compromise. It raises the priority of the investigation and requires contextual validation.

## Lab Environment

- **Wazuh Manager:** `sec-wazuh01` — `10.100.10.10`
- **Windows endpoint:** `CLIENT01` — `10.100.10.20`
- **Domain Controller:** `NTS-YTO-AD01` — `10.100.10.5`
- **Firewall:** pfSense
- **AD DNS domain:** `northtech.corp`
- **NetBIOS domain:** `NORTHTECH`

## Windows Events Used

### Event ID 4625 — Failed Logon

The initial detection focuses on failed interactive logons:

- Event ID: `4625`
- Logon Type: `2` — Interactive
- Wazuh base rule: `60122`

### Event ID 4624 — Successful Logon

Successful authentication events are used for the post-brute-force correlation.

Observed logon types during testing included:

- `2` — Interactive
- `7` — Unlock
- `11` — CachedInteractive

The final high-priority rule accepts Types `2` and `11`. Type `7` was intentionally excluded because Windows generated both Type 11 and Type 7 during the same authentication flow, creating duplicate Level 12 alerts.

## Detection Logic

### Rule 100102 — Interactive Logon Failure

```xml
<rule id="100102" level="7">
  <if_sid>60122</if_sid>
  <field name="win.system.eventID">4625</field>
  <field name="win.eventdata.logonType">2</field>
  <description>Interactive Windows logon failure</description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```

This rule identifies each failed interactive Windows logon.

### Rule 100103 — Possible Brute Force

```xml
<rule id="100103" level="10" frequency="5" timeframe="180">
  <if_matched_sid>100102</if_matched_sid>
  <same_field>win.eventdata.targetUserName</same_field>
  <description>Possible brute force - multiple interactive Windows logon failures</description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```

This rule correlates five failed logons for the same account within 180 seconds.

### Rule 100104 — Successful Logon After Possible Brute Force

```xml
<rule id="100104" level="12" frequency="2" timeframe="600">
  <if_sid>60118,67022</if_sid>
  <if_matched_sid>100103</if_matched_sid>
  <same_field>win.eventdata.targetUserName</same_field>
  <field name="win.system.eventID">4624</field>
  <field name="win.eventdata.logonType" type="pcre2">^(2|11)$</field>
  <description>Successful Windows logon after possible brute force activity</description>
  <mitre>
    <id>T1110</id>
    <id>T1078</id>
  </mitre>
</rule>
```

This rule raises a Level 12 alert when the same account successfully authenticates after the brute-force pattern.

## Validation

### Test 1 — Multiple Failures for the Same User

Five incorrect password attempts were generated for:

```text
NORTHTECH\renan.lab
```

Observed sequence:

```text
100102 | Level 7
100102 | Level 7
100102 | Level 7
100102 | Level 7
100103 | Level 10
```

Result: **Passed**.

### Test 2 — Different Users

Authentication failures were generated for different usernames.

Observed result:

- Rule `100102` fired for each individual failure.
- Rule `100103` did not correlate the failures into a brute-force alert.

This validated the use of:

```xml
<same_field>win.eventdata.targetUserName</same_field>
```

Result: **Passed**.

### Test 3 — Successful Authentication After Brute Force

After Rule `100103` fired, a valid password was supplied for the same account.

Observed sequence:

```text
100103 | Level 10 | renan.lab
100104 | Level 12 | renan.lab | Logon Type 11
```

Result: **Passed**.

### Test 4 — Alert Noise Reduction

The initial version accepted Logon Types `2`, `7`, and `11`, which produced two Level 12 alerts for one authentication flow.

The final rule was refined to accept only:

```text
2 | 11
```

Result: one high-priority correlated alert instead of duplicate alerts.

Result: **Passed**.

## Identity Normalization Finding

During early testing, failed and successful events represented the same identity differently:

```text
Failure: renan.lab@northtech.corp
Success: renan.lab
```

Using the NetBIOS format during authentication testing:

```text
NORTHTECH\renan.lab
```

produced consistent fields:

```text
USER=renan.lab
DOMAIN=NORTHTECH
```

This allowed `same_field` correlation to reliably match the identity.

## MITRE ATT&CK Mapping

- **T1110 — Brute Force**
- **T1078 — Valid Accounts**

The detection models a sequence where repeated authentication failures are followed by successful use of a valid account.

## SOC Tier 1 Triage

When Rule `100104` fires, an analyst should validate:

- Affected endpoint
- Target username and domain
- Number and timing of failed attempts
- Logon Type
- Source address and workstation
- Whether the successful authentication belongs to the same account
- Whether the user confirms the activity
- Whether suspicious activity occurred after authentication

Example lab context:

```text
Endpoint: CLIENT01
User: renan.lab
Domain: NORTHTECH
Failed-logon pattern: 5 attempts
Initial Logon Type: 2
Successful Logon Type: 11
MITRE: T1110, T1078
```

## Key Lessons

- A single authentication failure is an event; correlated failures can become a detection.
- Temporal correlation provides behavioral context.
- Identity-aware correlation reduces false positives.
- Windows Logon Type materially changes SOC interpretation.
- Authentication logs may represent the same identity in different formats.
- Successful authentication after repeated failures deserves higher-priority investigation.
- Deduplication and noise reduction are important to prevent alert fatigue.

## Defensive Use Only

This exercise was performed in an isolated lab for defensive security training and SOC detection engineering practice.
