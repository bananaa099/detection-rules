# New Admin Account Created

**Detects:** a new user account that gets added to the Administrators group
**MITRE:** T1136 (Create Account), T1098 (Account Manipulation)
**Data source:** Windows Security logs (EventCode 4720 and 4732)
**Severity:** High

## Search (SPL)

```spl
index=* (EventCode=4720 OR EventCode=4732)
| transaction host maxspan=2m
| search EventCode=4720 EventCode=4732
| table _time, host, Account_Name, EventCode
```

Simple version to just see the events:

```spl
index=* (EventCode=4720 OR EventCode=4732)
| table _time, host, EventCode, Account_Name
```

## How I tested it

In my Windows VM I created a user and added it to Administrators:

```powershell
net user testadmin P@ssw0rd123 /add
net localgroup administrators testadmin /add
```

Both events (4720 then 4732) showed up in Splunk a few seconds apart.

## False positives

- IT creating a real admin account on purpose
- New employee setup

Before closing, I would check if the change was planned and who ran it.

## Triage

1. Who created the account (the Subject user in the event)
2. Was it expected / a ticket for it
3. What the new account did after it was created
4. If it wasn't planned - disable the account and escalate
