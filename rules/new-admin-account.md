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

## Seen in a case

In THM Investigating Windows the attacker added the built-in **Guest** account to Administrators. Guest already exists, so there was no 4720, only 4732. The first search above would miss it. The simple search catches it, so I'd also alert on 4732 alone when the group is Administrators:

```spl
index=* EventCode=4732 Group_Name="Administrators"
| table _time, host, src_user, MemberName
```
