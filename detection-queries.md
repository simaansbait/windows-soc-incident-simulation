# Detection Engineering – Splunk Queries
## Windows SOC Incident Simulation – Multi-Stage Intrusion

Author: Simaan Sbait  
Project Type: Internal SOC Incident Simulation  
Platform: Splunk Enterprise  
Telemetry Sources: Windows Security Logs, PowerShell Logging, Sysmon  

---

# Overview

This document contains all Splunk Search Processing Language (SPL) queries used to detect, correlate, and reconstruct a simulated multi-stage Windows intrusion in a controlled lab environment.

The attack chain includes:

- RDP brute-force authentication
- Privileged logon assignment
- Persistence via local account creation
- Encoded PowerShell execution
- Security log tampering
- SMB-based lateral movement

All detections were validated using:

```
index=lab_windows
```

---

# 1. Initial Access – RDP Brute Force (Event ID 4625)

## Raw Failed Logons

```spl
index=lab_windows EventCode=4625
| table _time Computer Account_Name Source_Network_Address Logon_Type Failure_Reason
| sort _time
```

## Failed Logon Count by Source IP

```spl
index=lab_windows EventCode=4625
| stats count as Failed_Attempts by Source_Network_Address
| sort - Failed_Attempts
```

## Brute Force Threshold Detection (5 Attempts Within 5 Minutes)

```spl
index=lab_windows EventCode=4625
| bucket _time span=5m
| stats count by _time Source_Network_Address
| where count > 5
| sort - count
```

Detection Logic:
Threshold-based authentication monitoring to identify brute-force activity.

---

# 2. Successful Network Logon (Event ID 4624 – Logon Type 3)

```spl
index=lab_windows EventCode=4624 Logon_Type=3
| table _time Computer Account_Name Source_Network_Address Logon_Type
| sort _time
```

## Correlation – Failed to Successful Authentication

```spl
index=lab_windows (EventCode=4625 OR EventCode=4624)
| stats values(EventCode) as Events count by Source_Network_Address Account_Name
| where mvcount(Events) > 1
```

Detection Logic:
Correlates repeated failed attempts followed by successful authentication from the same source IP.

---

# 3. Privilege Escalation – Special Privileges Assigned (Event ID 4672)

```spl
index=lab_windows EventCode=4672
| table _time Computer Account_Name Privileges
| sort _time
```

Detection Logic:
Monitors assignment of administrative-level privileges to newly authenticated sessions.

---

# 4. Persistence – New User Account Creation (Event ID 4720)

```spl
index=lab_windows EventCode=4720
| table _time Computer TargetUserName SubjectUserName
| sort _time
```

Detection Logic:
Detects creation of new local accounts for persistence.

---

# 5. Persistence – User Added to Local Administrators (Event ID 4732)

```spl
index=lab_windows EventCode=4732
| table _time Computer TargetUserName SubjectUserName
| sort _time
```

Detection Logic:
Identifies modification of local group membership granting administrative privileges.

---

# 6. Execution – Process Creation Monitoring (Event ID 4688)

## All Process Creation Events

```spl
index=lab_windows EventCode=4688
| table _time Computer New_Process_Name Process_Command_Line
| sort _time
```

## Encoded PowerShell Execution Detection

```spl
index=lab_windows EventCode=4688
(New_Process_Name="*powershell.exe*" AND Process_Command_Line="*EncodedCommand*")
| table _time Computer Process_Command_Line
| sort _time
```

Detection Logic:
Identifies potentially obfuscated PowerShell execution using encoded command arguments.

---

# 7. PowerShell Script Block Logging (Event ID 4104)

```spl
index=lab_windows EventCode=4104
| table _time Computer ScriptBlockText
| sort _time
```

Detection Logic:
Provides visibility into executed PowerShell script content when logging is enabled.

---

# 8. Defense Evasion – Security Log Clearing (Event ID 1102)

```spl
index=lab_windows EventCode=1102
| table _time Computer SubjectUserName
| sort _time
```

## High-Severity Alert Version

```spl
index=lab_windows EventCode=1102
| stats count by Computer SubjectUserName
```

Detection Logic:
Security log clearing is a high-confidence malicious indicator and should trigger immediate high-severity alerting.

---

# 9. Lateral Movement – SMB Network Logon (Event ID 4624 – Logon Type 3)

```spl
index=lab_windows EventCode=4624 Logon_Type=3
| table _time Computer Source_Network_Address Account_Name Logon_Type
| sort _time
```

Detection Logic:
Identifies network authentication events consistent with SMB administrative share access.

---

# 10. Logon Activity Timeline Visualization

```spl
index=lab_windows (EventCode=4624 OR EventCode=4625)
| timechart span=1m count by EventCode
```

Detection Logic:
Provides temporal visibility of authentication patterns during attack progression.

---

# 11. Full Attack Chain Reconstruction

```spl
index=lab_windows (EventCode=4625 OR EventCode=4624 OR EventCode=4672 OR EventCode=4720 OR EventCode=4732 OR EventCode=4688 OR EventCode=1102)
| sort _time
| table _time Computer EventCode Account_Name TargetUserName Source_Network_Address
```

Detection Logic:
Enables structured timeline reconstruction of multi-stage attack activity across hosts.

---

# Detection Engineering Methodology

The detection strategy in this project emphasizes:

- Multi-event correlation
- Behavioral detection over signature-only logic
- Privilege monitoring
- Persistence tracking
- Command-line execution visibility
- Defense evasion detection
- Lateral movement identification
- Timeline-based incident reconstruction

This approach reflects SOC Tier 1 / Tier 2 investigative methodology and structured incident response analysis using Splunk and Windows telemetry.

---

## MITRE ATT&CK Techniques Observed

- T1110 – Brute Force
- T1078 – Valid Accounts
- T1098 – Account Manipulation
- T1059.001 – PowerShell
- T1070.001 – Indicator Removal on Host
- T1021.002 – SMB/Windows Admin Shares

---

End of Document