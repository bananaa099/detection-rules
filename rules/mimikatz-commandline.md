# Mimikatz on the command line

Idea from THM Investigating Windows (Mimikatz in C:\TMP) and THM Disk Analysis & Autopsy (mimikatz_trunk.zip in Downloads). Looking for the module names works even if the exe is renamed.

**MITRE:** T1003.001 (LSASS Memory)
**Data source:** Sysmon EventID 1 (process creation) or Security 4688 with command line logging
**Severity:** Critical

## Search (SPL)

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (CommandLine="*sekurlsa::*" OR CommandLine="*lsadump::*" OR CommandLine="*privilege::debug*" OR CommandLine="*kerberos::*")
| table _time, host, User, ParentImage, Image, CommandLine
```

## Sigma

```yaml
title: Mimikatz Keywords in Command Line
id: 2f445de0-b10e-4c26-bf22-9e72766795b5
status: experimental
author: Hashim
date: 2026-11-15
tags:
  - attack.credential-access
  - attack.t1003.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'sekurlsa::'
      - 'lsadump::'
      - 'privilege::debug'
      - 'kerberos::'
  condition: selection
level: critical
```

## How to test

Not tested yet. I don't want to run real Mimikatz on my VM, and Defender would block it anyway. Plan: run `cmd /c echo sekurlsa::logonpasswords` - the text ends up in the CommandLine field, so the rule should fire without running anything dangerous.

## What I check when it fires

1. This is not a "check later" alert - isolate the host
2. Which user ran it and from where (ParentImage)
3. Who logged in to this host recently - all those passwords should be treated as stolen
4. Escalate to L2 right away, they'll need to reset passwords

## False positives

- Authorized pentest
