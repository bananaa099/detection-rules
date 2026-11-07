# Detection Rules

Detection rules written for SIEM (Splunk SPL and Sigma format). Each rule has a short explanation of what it detects and how it was tested.

## Rules

**Windows**
- encoded-powershell
- new-admin-account-alert

**Web**
- credential-stuffing-login - many failed logins then a success from one IP (from HTB Meerkat)
- bonita-cve-2022-25237 - Bonitasoft auth bypass and RCE (from HTB Meerkat)

**Linux**
- ssh-authorized-keys-modified - attacker adds SSH key for persistence (from HTB Meerkat)

## Each rule includes
- Detection goal and MITRE ATT&CK technique
- Query (SPL or Sigma)
- Test data or log example that triggers it
- Known false positives