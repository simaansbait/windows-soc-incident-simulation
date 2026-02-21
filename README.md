# Windows SOC Incident Simulation – Multi-Stage Intrusion

## Overview

This project simulates a full multi-stage Windows endpoint intrusion in a controlled lab environment and demonstrates Security Operations Center (SOC) detection, correlation, and investigative workflow capabilities.

The simulated adversary performed:

- RDP brute-force authentication
- Privileged administrative logon
- Persistence via local account creation
- Encoded PowerShell execution
- Security log tampering
- SMB-based lateral movement

All activity was reconstructed using Windows Security Logs, PowerShell logging, and Splunk-based detection analytics.

---

## Lab Architecture

**Environment Components:**

- Kali Linux attacker machine  
- WIN-LAB (Primary compromised host)  
- WIN-LAB-02 (Secondary lateral movement target)  
- Splunk Enterprise SIEM  
- Isolated VirtualBox lab  
- Windows Advanced Audit Policy enabled  
- Sysmon deployed  
- PowerShell Script Block Logging enabled  

---

## Attack Phases

### Phase 1 – Initial Access
- Event ID 4625 – Failed RDP authentication attempts
- Event ID 4624 – Successful network logon (Logon Type 3)
- Brute-force detection via threshold-based monitoring

### Phase 2 – Privilege Escalation
- Event ID 4672 – Special privileges assigned to new logon
- Confirmation of administrative token assignment

### Phase 3 – Persistence
- Event ID 4720 – New local account creation
- Event ID 4732 – User added to local Administrators group
- Detection of unauthorized privileged account establishment

### Phase 4 – Execution
- Event ID 4688 – Process creation telemetry
- Detection of encoded PowerShell command execution
- Command-line auditing analysis

### Phase 5 – Defense Evasion
- Event ID 1102 – Security log cleared
- High-confidence malicious indicator
- Log tampering detection logic

### Phase 6 – Lateral Movement
- Event ID 4624 – Logon Type 3 on secondary host
- SMB administrative share access
- Credential reuse detection

---

## Detection Engineering Approach

Detection logic was implemented using Splunk Search Processing Language (SPL) and focused on:

- Threshold-based brute-force detection
- Multi-event correlation (4625 → 4624 → 4672)
- Privilege monitoring
- Account persistence tracking
- Encoded PowerShell detection
- Security log tampering alerting
- Lateral movement detection
- Timeline reconstruction using timechart visualization

Full SPL queries are documented in:

**detection_queries.md**

---

## MITRE ATT&CK Mapping

| Phase | Technique | ID |
|-------|-----------|----|
| Initial Access | Brute Force | T1110 |
| Privilege Escalation | Valid Accounts | T1078 |
| Persistence | Account Manipulation | T1098 |
| Execution | PowerShell | T1059.001 |
| Defense Evasion | Indicator Removal on Host | T1070.001 |
| Lateral Movement | SMB/Windows Admin Shares | T1021.002 |

---

## Tools Used

- Windows 10 Pro
- Splunk Enterprise
- Sysmon
- Kali Linux
- MITRE ATT&CK Framework

---

## Full Enterprise Incident Report

See complete structured incident response report:

**Security Incident Report.pdf**

---

## Author

Simaan Sbait  
SOC Analyst Portfolio Project  
LinkedIn: https://www.linkedin.com/in/simaan-sbait-02a3a2323/
