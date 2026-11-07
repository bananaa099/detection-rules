# Credential stuffing on login page

Idea from HTB Meerkat - one IP sent 118 logins with different emails/passwords, got 401 every time and then 204 when one worked.

MITRE: T1110.004

```spl
index=web method=POST uri_path="*login*"
| bin _time span=10m
| stats count(eval(status=401)) as failed count(eval(status=200 OR status=204)) as success by _time, clientip
| where failed > 20 AND success > 0
```

Need to change uri_path for the app (Meerkat was `/bonita/loginservice`).

What to check:
- which account logged in after the fails
- IP reputation (VirusTotal / AbuseIPDB)
- user agent - in Meerkat it was python-requests
- what the IP did after login

Can be false positive if lots of users are behind one IP (office NAT) or a health check hits the login page.

Only checked against the Meerkat pcap, didn't test in my lab yet.
