# Encoded PowerShell Execution

I made a rule to catch PowerShell running with `-enc`. Attackers use it to hide the real command, so it is worth watching.

## Data source
Sysmon EventID 1 (process creation). I checked it in Splunk and the fields are there (CommandLine, ParentImage, User).

## Search
```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 "powershell" "-enc"
| table _time, host, User, Image, CommandLine, ParentImage
```

## Alert settings
- Real-time
- Trigger when results > 0, for each result
- Action: Add to Triggered Alerts

## How I tested it
Ran `powershell -NoProfile -enc` with a harmless command in my lab VM. The event showed up in Splunk in about a minute.

## What I check when it fires
1. Decode the Base64 after `-enc`.
2. Look at ParentImage. Is it an installer, an agent, or someone running it by hand?
3. Check the User. Is it SYSTEM or a normal user?
4. See if the same process made a network connection (EventID 3).
5. If the command is strange or talks to an unknown domain, escalate to L2.

## Known false positives
- Software installers and updaters
- Management tools like SCCM or Intune

If a trusted tool keeps triggering it, I would exclude that parent process instead of turning the rule off.