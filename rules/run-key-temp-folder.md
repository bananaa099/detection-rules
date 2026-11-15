# Run key starting something from a temp folder

Idea from THM Investigating Windows - HKLM Run key started `C:\TMP\p.exe` (renamed PsExec) on every boot and connected to 10.34.2.3. Normal software almost never starts from TMP, Temp or Users\Public.

**MITRE:** T1547.001 (Registry Run Keys)
**Data source:** Sysmon EventID 13 (Registry value set)
**Severity:** High

## Search (SPL)

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 TargetObject="*\\CurrentVersion\\Run*"
  (Details="*\\TMP\\*" OR Details="*\\Temp\\*" OR Details="*\\Users\\Public\\*")
| table _time, host, User, Image, TargetObject, Details
```

## Sigma

```yaml
title: Run Key Points to Temp or Unusual Folder
id: 41bb415a-e450-4dba-9bdb-cf4a6dd8d27c
status: experimental
author: Hashim
date: 2026-11-15
tags:
  - attack.persistence
  - attack.t1547.001
logsource:
  product: windows
  category: registry_set
detection:
  selection_key:
    TargetObject|contains:
      - '\Software\Microsoft\Windows\CurrentVersion\Run\'
      - '\Software\Microsoft\Windows\CurrentVersion\RunOnce\'
  selection_path:
    Details|contains:
      - ':\TMP\'
      - ':\Temp\'
      - '\AppData\Local\Temp\'
      - ':\Users\Public\'
  condition: all of selection_*
level: high
```

## How to test

Not tested in my lab yet. Plan:

```cmd
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v test /d "C:\TMP\test.exe"
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v test /f
```

## What I check when it fires

1. What file the Run key points to, does it exist, hash it and check VirusTotal
2. Is the name trying to look normal (p.exe, update.exe, svchost in a wrong folder)
3. What process wrote the key (Image)
4. Other persistence on the same host - scheduled tasks, services, new accounts

## False positives

- Some installers put a one-time cleanup in RunOnce from Temp
