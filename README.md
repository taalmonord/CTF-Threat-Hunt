# Microsoft Defender XDR Incident Investigation and Response

## Project Overview

This project documents a simulated multi-stage endpoint compromise investigated through Microsoft Defender XDR Advanced Hunting. The investigation began after a Finance user reported repeated overnight login prompts on `npt-ws01`.

The hunt identified:

- Unauthorized use of the `helpdesk` account from an external IP address
- WMI-based remote execution
- Execution of a malicious implant from `C:\Windows\Temp`
- Command-and-control communication
- Registry, scheduled-task, and service-based persistence
- Creation of a privileged local backdoor account
- Lateral-movement activity involving `npt-srv01`

The response plan is organized around the NIST SP 800-61 incident-response lifecycle: preparation, detection and analysis, containment, eradication, recovery, and post-incident improvement.

---

## Table of Contents

- [Scenario](#scenario)
- [Environment and Tools](#environment-and-tools)
- [Executive Summary](#executive-summary)
- [Incident Scope](#incident-scope)
- [Investigation Methodology](#investigation-methodology)
- [Reconstructed Attack Sequence](#reconstructed-attack-sequence)
- [Technical Findings](#technical-findings)
- [Indicators of Compromise](#indicators-of-compromise)
- [NIST SP 800-61 Response Plan](#nist-sp-800-61-response-plan)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [KQL Queries](#kql-queries)
- [Detection Engineering Opportunities](#detection-engineering-opportunities)
- [Lessons Learned](#lessons-learned)
- [Skills Demonstrated](#skills-demonstrated)
- [Disclaimer](#disclaimer)

---

## Scenario

**Help Desk Ticket:** `#4451`  
**Reported:** April 22, 2026 at 09:14 UTC  
**Reporter:** Mark Smith, Finance  
**Primary endpoint:** `npt-ws01`  
**Investigation window:** April 22, 2026 from 02:00–08:00 UTC  
**Primary focus window:** 04:30–06:00 UTC  

The user reported that the workstation displayed repeated login prompts overnight. Although the system appeared normal the next morning, Microsoft Defender telemetry confirmed that the activity represented a real compromise.

---

## Environment and Tools

- Microsoft Defender XDR
- Microsoft Defender Advanced Hunting
- Kusto Query Language
- Endpoint authentication telemetry
- Process creation telemetry
- Network connection telemetry
- File creation telemetry
- Registry telemetry
- Alert evidence and device scoping
- NIST SP 800-61 incident-response guidance
- MITRE ATT&CK

---

## Executive Summary

The investigation confirmed that an attacker authenticated to `npt-ws01` with the `helpdesk` account from external IP address `20.110.92.50`.

After obtaining access, the attacker used WMI-based remote execution. The process chain showed `wmiprvse.exe` spawning `cmd.exe`, which launched a malicious executable named `WindowsUpdate.exe` from `C:\Windows\Temp`.

The implant communicated with the command-and-control domain `updates.abordasync.website`. The attacker then established multiple persistence mechanisms:

1. Registry Run-key value: `WindowsHealthCheck`
2. Scheduled task: `GoogleUpdaterTask`
3. Windows service: `WindowsHealthSvc`
4. Local administrative backdoor account: `nexus_admin`

The attacker also generated lateral-movement activity toward a second internal endpoint, `npt-srv01`.

The incident was assessed as **High severity** because it involved credential compromise, malware execution, command-and-control traffic, multiple persistence mechanisms, unauthorized administrative access, and attempted or successful movement toward another internal host.

No confirmed data exfiltration or destructive activity was present in the supplied evidence. Those impacts therefore remain **unconfirmed**, not ruled out.

---

## Incident Scope

| Category | Finding |
|---|---|
| Primary compromised endpoint | `npt-ws01` |
| Secondary endpoint in scope | `npt-srv01` |
| Compromised account | `helpdesk` |
| Backdoor account | `nexus_admin` |
| External source/C2 IP | `20.110.92.50` |
| Internal lateral-movement destination | `10.3.0.10` |
| C2 domain | `updates.abordasync.website` |
| Implant | `C:\Windows\Temp\WindowsUpdate.exe` |
| Implant SHA-256 | `20cef6a013953890f9d38605d25d60dd63b42b09946bbb18ddb4a456da306e77` |
| Registry persistence | `WindowsHealthCheck` |
| Scheduled-task persistence | `GoogleUpdaterTask` |
| Service persistence | `WindowsHealthSvc` |
| Command-output artifact | `C:\Windows\Temp\uYgvso` |

---

## Investigation Methodology

The investigation used a pivot-based approach:

```text
User report
    ↓
Successful external logon
    ↓
Compromised account activity
    ↓
Parent-child process analysis
    ↓
Malware file identification
    ↓
Command-and-control traffic
    ↓
Persistence discovery
    ↓
Backdoor-account discovery
    ↓
Lateral-movement scoping
```

The earliest high-confidence detection point was the successful network logon by the `helpdesk` account from public IP address `20.110.92.50`.

This event was selected because it provided four strong pivot fields:

- Account
- Source IP address
- Device name
- Timestamp

Those fields led directly to process, file, network, registry, scheduled-task, service, account, and lateral-movement evidence.

---

## Reconstructed Attack Sequence

> The supplied evidence establishes the sequence of activity but does not provide every individual timestamp. This section should be treated as an evidence-based reconstruction rather than a second-by-second timeline.

### 1. Initial Access

The attacker successfully authenticated to `npt-ws01` with the `helpdesk` account from external IP address `20.110.92.50`.

<img width="1908" height="719" alt="Screenshot 2026-07-28 205541" src="https://github.com/user-attachments/assets/2d9c6b44-055e-45d0-b2db-20e5dcf0ba4f" />

**Evidence caption:** Microsoft Defender recorded a successful logon to `npt-ws01` using the `helpdesk` account from external IP address `20.110.92.50`.

### 2. WMI-Based Remote Execution

The process tree showed `wmiprvse.exe` spawning `cmd.exe`. The command shell then launched the malicious implant:

```text
cmd.exe /Q /c start "" "C:\Windows\Temp\WindowsUpdate.exe" 1> \Windows\Temp\uYgvso 2>&1
```

<img width="1913" height="775" alt="Screenshot 2026-07-28 205739" src="https://github.com/user-attachments/assets/bf142221-8a17-4710-8def-376314136547" />

**Evidence caption:** The `wmiprvse.exe → cmd.exe → WindowsUpdate.exe` relationship supports remote WMI execution rather than normal local-user activity.

### 3. Malware Execution

The attacker executed `WindowsUpdate.exe` from `C:\Windows\Temp`.

The file’s SHA-256 hash was:

```text
20cef6a013953890f9d38605d25d60dd63b42b09946bbb18ddb4a456da306e77
```

<img width="1912" height="856" alt="image" src="https://github.com/user-attachments/assets/83b8b39c-ce17-41e7-a475-e6fe15149cdc" />

**Evidence caption:** The executable was staged in a temporary Windows directory and identified by its full SHA-256 hash.

### 4. Command and Control

The compromised workstation communicated with:

```text
updates.abordasync.website
```

<img width="1918" height="857" alt="image" src="https://github.com/user-attachments/assets/10be9dd3-8dbc-4ee9-8e18-f40cfbdf3a1b" />

**Evidence caption:** The host established outbound communication with a suspicious non-Microsoft domain associated with the malicious process activity.

### 5. Registry Persistence

The attacker created a Registry Run-key value named:

```text
WindowsHealthCheck
```

<img width="1912" height="858" alt="image" src="https://github.com/user-attachments/assets/87b38255-7b38-49f3-8c7e-114287ab55ce" />

**Evidence caption:** The `WindowsHealthCheck` value provided automatic execution through a Windows Run key.

### 6. Scheduled-Task Persistence

The attacker created a scheduled task named:

```text
GoogleUpdaterTask
```

<img width="1501" height="856" alt="image" src="https://github.com/user-attachments/assets/d159b767-17c3-4ab9-bbce-1ac81f7773d5" />

**Evidence caption:** The task name imitated a legitimate software updater while providing persistence for the implant.

### 7. Service-Based Persistence

The attacker created a Windows service named:

```text
WindowsHealthSvc
```

<img width="1896" height="860" alt="image" src="https://github.com/user-attachments/assets/e502ca5f-0b43-4e81-b1d6-ad6c64e9da1e" />

**Evidence caption:** The malicious service provided an additional mechanism for restarting the implant.

### 8. Backdoor Account and Privilege Establishment

The attacker created the local account:

```text
nexus_admin
```

The account was then added to the local Administrators group.

<img width="1903" height="916" alt="image" src="https://github.com/user-attachments/assets/9a2e225f-4cab-42f7-9378-9b5dd7960a93" />

**Evidence caption:** The attacker established a privileged access path independent of the initially compromised `helpdesk` account.

### 9. Lateral Movement

Alert and device evidence identified `npt-srv01` as the second endpoint involved in lateral-movement activity.

**Evidence caption:** Alert evidence expanded the incident scope from `npt-ws01` to `npt-srv01`.

Supporting network evidence showed communication from `npt-ws01` toward internal IP address `10.3.0.10`.

<img width="1901" height="857" alt="image" src="https://github.com/user-attachments/assets/45d6cabd-c507-439a-8b63-c014f370499a" />

**Evidence caption:** The network event confirms communication from the compromised workstation toward the internal target. The hostname association should be established through alert or device evidence, not this connection alone.

---

## Technical Findings

### Authentication

A successful logon by the `helpdesk` account from `20.110.92.50` was inconsistent with expected support-account behavior and established unauthorized access to the endpoint.

### Execution

The process relationship:

```text
wmiprvse.exe
    └── cmd.exe
          └── C:\Windows\Temp\WindowsUpdate.exe
```

linked the suspicious authentication activity to remote execution and malware launch.

### Network

The implant communicated with `updates.abordasync.website`, establishing command-and-control behavior.

### File Activity

The implant was staged in `C:\Windows\Temp`, a temporary path that should not normally contain an executable impersonating a Windows update component.

### Persistence

The attacker created multiple independent persistence mechanisms:

- Registry Run key
- Scheduled task
- Windows service
- Privileged local account

The use of multiple persistence paths increased the likelihood that access would survive a reboot, logoff, or partial cleanup.

### Lateral Movement

The incident was not limited to a single workstation. `npt-srv01` remained in containment scope until investigators could determine whether malicious execution, persistence, or unauthorized logons occurred on that server.

---

## Indicators of Compromise

| Type | Value |
|---|---|
| Compromised account | `helpdesk` |
| Source/C2 IP | `20.110.92.50` |
| C2 domain | `updates.abordasync.website` |
| Implant filename | `WindowsUpdate.exe` |
| Implant path | `C:\Windows\Temp\WindowsUpdate.exe` |
| SHA-256 | `20cef6a013953890f9d38605d25d60dd63b42b09946bbb18ddb4a456da306e77` |
| Parent process | `wmiprvse.exe` |
| Registry value | `WindowsHealthCheck` |
| Scheduled task | `GoogleUpdaterTask` |
| Windows service | `WindowsHealthSvc` |
| Backdoor account | `nexus_admin` |
| Primary endpoint | `npt-ws01` |
| Secondary endpoint | `npt-srv01` |
| Internal target IP | `10.3.0.10` |
| Output artifact | `C:\Windows\Temp\uYgvso` |

---

# NIST SP 800-61 Response Plan

## 1. Preparation

- Declare a confirmed security incident and assign response ownership.
- Preserve Microsoft Defender alerts and Advanced Hunting results.
- Collect endpoint investigation packages before deleting artifacts.
- Record all response actions with UTC timestamps.
- Preserve evidence hashes and chain-of-custody information where required.
- Avoid powering off affected systems unless continued operation creates unacceptable risk.
- Coordinate with the Finance business owner before disruptive remediation.

## 2. Detection and Analysis

- Confirm the successful `helpdesk` logon from `20.110.92.50`.
- Correlate authentication with the `wmiprvse.exe → cmd.exe → WindowsUpdate.exe` process chain.
- Confirm communication with `updates.abordasync.website`.
- Hunt across the environment for:
  - The implant hash
  - The implant path
  - The C2 IP and domain
  - The malicious registry value
  - The scheduled task
  - The Windows service
  - The `nexus_admin` account
  - Use of the `helpdesk` account
  - WMI-based remote execution
- Investigate `npt-srv01` for malicious logons, processes, files, services, tasks, registry changes, and account activity.

## 3. Containment

### Endpoint Containment

- Immediately isolate `npt-ws01` through Microsoft Defender.
- Isolate `npt-srv01` or place it in a restricted containment VLAN until triage is complete.
- Prevent both systems from communicating with other production endpoints except approved response infrastructure.

### Identity Containment

- Disable the `helpdesk` account.
- Revoke active sessions and authentication tokens.
- Reset the account password.
- Investigate where and how the credentials were exposed.
- Disable `nexus_admin`.
- Reset other privileged or service accounts that authenticated to either affected endpoint.

### Network Containment

Block the following indicators in endpoint, DNS, proxy, and firewall controls:

```text
20.110.92.50
updates.abordasync.website
20cef6a013953890f9d38605d25d60dd63b42b09946bbb18ddb4a456da306e77
C:\Windows\Temp\WindowsUpdate.exe
```

Temporarily restrict unnecessary:

- WMI
- SMB
- RDP
- WinRM
- Remote service creation

## 4. Eradication

- Quarantine or delete `C:\Windows\Temp\WindowsUpdate.exe` after evidence collection.
- Verify the executable hash before removal.
- Remove the `WindowsHealthCheck` Run-key value.
- Delete `GoogleUpdaterTask`.
- Stop and delete `WindowsHealthSvc`.
- Delete the `nexus_admin` account and remove it from the Administrators group.
- Collect and remove `C:\Windows\Temp\uYgvso` if present.
- Search for equivalent persistence in:
  - Run and RunOnce keys
  - Startup folders
  - Scheduled tasks
  - Services
  - WMI event subscriptions
  - Local users and groups
- Rebuild `npt-ws01` from a known-good image.
- Rebuild or restore `npt-srv01` if compromise is confirmed.
- Patch or remove the exposed access path that permitted the original intrusion.

## 5. Recovery

- Restore systems from known-good images or verified clean backups.
- Confirm that backups predate the incident.
- Scan and validate backups before restoration.
- Reset affected credentials before reconnecting systems.
- Enforce least privilege and MFA for administrative access.
- Confirm that all known malicious files, accounts, tasks, services, registry entries, hashes, domains, and IP connections are absent.
- Reconnect systems in stages:
  1. Response network
  2. Restricted production segment
  3. Normal production
- Apply heightened monitoring for at least 72 hours.
- Continue targeted hunting for at least 14 days.
- Obtain business-owner validation before closing recovery.

## 6. Post-Incident Activity

- Conduct a lessons-learned meeting.
- Determine why the external logon was permitted.
- Determine why WMI remote execution succeeded.
- Determine why multiple persistence mechanisms were not detected earlier.
- Replace shared support accounts with named administrative accounts.
- Enforce MFA, privileged access management, and just-in-time elevation.
- Restrict administrative protocols between workstations and servers.
- Update incident-response playbooks with the indicators and response procedures from this case.
- Create or tune detections for the behaviors observed in this incident.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access / Persistence | Valid Accounts | Compromised `helpdesk` credentials |
| Execution | Windows Management Instrumentation | `wmiprvse.exe` spawning `cmd.exe` |
| Execution | Windows Command Shell | `cmd.exe /Q /c start` |
| Command and Control | Application Layer Protocol: Web Protocols | Outbound connection to `updates.abordasync.website` |
| Persistence | Registry Run Keys / Startup Folder | `WindowsHealthCheck` |
| Persistence | Scheduled Task/Job: Scheduled Task | `GoogleUpdaterTask` |
| Persistence | Create or Modify System Process: Windows Service | `WindowsHealthSvc` |
| Persistence | Create Account: Local Account | `nexus_admin` |
| Privilege Escalation | Account manipulation / local group modification | `nexus_admin` added to Administrators |
| Lateral Movement | Remote Services / WMI-based movement | Activity from `npt-ws01` toward `npt-srv01` |

---

# KQL Queries

> Microsoft Defender Advanced Hunting normally uses `Timestamp`. Some connected environments may expose `TimeGenerated`. Use the field available in the target workspace.

## 1. Suspicious Successful Logon

```kql
let start_time = datetime(2026-04-22T02:00:00Z);
let end_time = datetime(2026-04-22T08:00:00Z);
let HostInQuestion = "npt-ws01";

DeviceLogonEvents
| where Timestamp between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where ActionType == "LogonSuccess"
| project
    Timestamp,
    DeviceName,
    ActionType,
    LogonType,
    AccountName,
    RemoteIP
| order by Timestamp asc
```

## 2. WMI Remote Execution

```kql
let start_time = datetime(2026-04-22T02:00:00Z);
let end_time = datetime(2026-04-22T08:00:00Z);
let HostInQuestion = "npt-ws01";

DeviceProcessEvents
| where Timestamp between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where AccountName == "helpdesk"
| where ProcessCommandLine contains "WindowsUpdate.exe"
    or InitiatingProcessFileName =~ "wmiprvse.exe"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp asc
```

## 3. Command-and-Control Communication

```kql
let start_time = datetime(2026-04-22T02:00:00Z);
let end_time = datetime(2026-04-22T08:00:00Z);
let HostInQuestion = "npt-ws01";

DeviceNetworkEvents
| where Timestamp between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where InitiatingProcessAccountName == "helpdesk"
| where isnotempty(RemoteUrl)
| project
    Timestamp,
    DeviceName,
    ActionType,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp asc
```

## 4. Malicious File and SHA-256

```kql
let start_time = datetime(2026-04-22T02:00:00Z);
let end_time = datetime(2026-04-22T08:00:00Z);
let HostInQuestion = "npt-ws01";

DeviceFileEvents
| where Timestamp between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where FileName =~ "WindowsUpdate.exe"
    or FolderPath =~ @"C:\Windows\Temp\WindowsUpdate.exe"
| project
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp asc
```

## 5. Registry Run-Key Persistence

```kql
let start_time = datetime(2026-04-22T02:00:00Z);
let end_time = datetime(2026-04-22T08:00:00Z);
let HostInQuestion = "npt-ws01";

DeviceRegistryEvents
| where Timestamp between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where RegistryKey contains @"CurrentVersion\Run"
| where RegistryValueName == "WindowsHealthCheck"
| project
    Timestamp,
    DeviceName,
    ActionType,
    RegistryKey,
    RegistryValueName,
    RegistryValueData,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp asc
```

## 6. Scheduled-Task Persistence

```kql
let start_time = datetime(2026-04-22T02:00:00Z);
let end_time = datetime(2026-04-22T08:00:00Z);
let HostInQuestion = "npt-ws01";

DeviceProcessEvents
| where Timestamp between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName
| order by Timestamp asc
```

## 7. Service-Based Persistence

```kql
let start_time = datetime(2026-04-22T02:00:00Z);
let end_time = datetime(2026-04-22T08:00:00Z);
let HostInQuestion = "npt-ws01";

DeviceProcessEvents
| where Timestamp between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where FileName =~ "sc.exe"
| where ProcessCommandLine contains "create"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName
| order by Timestamp asc
```

## 8. Backdoor Administrator Account

```kql
let start_time = datetime(2026-04-22T02:00:00Z);
let end_time = datetime(2026-04-22T08:00:00Z);
let HostInQuestion = "npt-ws01";

DeviceProcessEvents
| where Timestamp between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where FileName in~ ("net.exe", "net1.exe")
| where ProcessCommandLine contains "nexus_admin"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName
| order by Timestamp asc
```

## 9. Lateral-Movement Alert Evidence

```kql
let start_time = datetime(2026-04-22T02:00:00Z);
let end_time = datetime(2026-04-22T08:00:00Z);

AlertEvidence
| where Timestamp between (start_time .. end_time)
| where DeviceName startswith "npt-"
| where Title contains "lateral"
    or Title contains "remote location"
| project
    Timestamp,
    Title,
    DeviceName,
    LocalIP,
    RemoteIP,
    EvidenceRole,
    EvidenceDirection,
    AlertId
| order by Timestamp asc
```

## 10. Supporting Internal Network Evidence

```kql
let start_time = datetime(2026-04-22T02:00:00Z);
let end_time = datetime(2026-04-22T08:00:00Z);

DeviceNetworkEvents
| where Timestamp between (start_time .. end_time)
| where DeviceName == "npt-ws01"
| where LocalIP == "10.3.0.10"
    or RemoteIP == "10.3.0.10"
| project
    Timestamp,
    DeviceName,
    LocalIP,
    LocalPort,
    RemoteIP,
    RemotePort,
    ActionType,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp asc
```

---

## Detection Engineering Opportunities

Potential Microsoft Defender detections include:

### External Logon by Support or Privileged Accounts

Alert when a support or administrative account successfully authenticates from an unexpected public IP address.

### WMI Provider Spawning a Command Shell

Detect:

```text
wmiprvse.exe → cmd.exe
wmiprvse.exe → powershell.exe
```

especially when the child process launches an executable from a temporary directory.

### Executable Launch from Windows Temp

Alert on unsigned or uncommon executables created or launched from:

```text
C:\Windows\Temp
C:\Users\*\AppData\Local\Temp
C:\Users\Public
```

### Suspicious Persistence Creation

Monitor for:

- `schtasks.exe /create`
- `sc.exe create`
- Registry writes to `CurrentVersion\Run`
- `net user /add`
- `net localgroup Administrators ... /add`

### Unusual Outbound Domains

Alert when unsigned or uncommon processes communicate with newly observed external domains.

---

## Lessons Learned

1. A system appearing normal to the user does not mean the incident has ended.
2. Authentication telemetry can reveal the earliest high-confidence point of compromise.
3. Parent-child process relationships are critical for distinguishing remote execution from local activity.
4. Multiple persistence mechanisms require full-scope eradication rather than removing only the first artifact found.
5. Shared support accounts weaken attribution and increase risk.
6. Lateral-movement investigations must include both alert evidence and device/network scoping.
7. An internal destination IP alone does not prove the hostname that owns that address.
8. Rebuilding a confirmed compromised endpoint is more reliable than relying exclusively on manual cleanup.

---

## Skills Demonstrated

- Microsoft Defender XDR
- Advanced Hunting
- Kusto Query Language
- Authentication analysis
- Process-tree analysis
- Malware triage
- Command-and-control analysis
- Persistence hunting
- Account and privilege analysis
- Lateral-movement scoping
- Incident containment
- Eradication planning
- Recovery planning
- NIST SP 800-61
- MITRE ATT&CK
- Technical documentation

---

## Disclaimer

This project was completed in a controlled training environment. Hostnames, user accounts, IP addresses, domains, hashes, and other indicators are part of the lab scenario and are documented for educational and portfolio purposes.
