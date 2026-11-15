# Hosts file modified

Idea from THM Investigating Windows - the attacker edited the hosts file and pointed google.com to his C2 (76.32.97.132). He also pointed www.virustotal.com and dci.sophosupd.com to 127.0.0.1 so the server couldn't reach VirusTotal or get Sophos updates.

**MITRE:** T1562.001 (Disable or Modify Tools), T1071.001 (C2 over web)
**Data source:** Sysmon EventID 11 (FileCreate)
**Severity:** Medium

## Search (SPL)

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 TargetFilename="*\\drivers\\etc\\hosts"
| table _time, host, User, Image, TargetFilename
```

## Sigma

```yaml
title: Hosts File Modified
id: 3d7b011d-79b4-4672-96e1-e0929c6ef3a1
status: experimental
author: Hashim
date: 2026-11-15
tags:
  - attack.defense-evasion
  - attack.t1562.001
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith: '\Windows\System32\drivers\etc\hosts'
  filter_trusted:
    Image|endswith:
      - '\TrustedInstaller.exe'
      - '\svchost.exe'
  condition: selection and not filter_trusted
level: medium
```

## How to test

Not tested in my lab yet. Plan: open Notepad as admin, add a line like `127.0.0.1 test.local` to the hosts file and save. Should show up as EventID 11.

## What I check when it fires

1. Open the hosts file and look at what was added
2. Real domains (google.com, update.microsoft.com) pointing to strange IPs = DNS poisoning / C2
3. Security vendor domains pointing to 127.0.0.1 = attacker blocking AV
4. Who changed it (Image, User) - notepad by an admin is different from powershell or an unknown exe
5. Check the IPs in VirusTotal / AbuseIPDB and escalate if they're bad

## False positives

- Admin or developer adding entries on purpose
- Some VPN or ad-blocking software
