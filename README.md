# Quick-AD-Scan — PowerShell Edition

> A modular, zero-dependency PowerShell toolkit for enumerating and auditing
> Active Directory environments over LDAP.  
> **For authorised testing only.**

---

## What Is This?

This is a full PowerShell rewrite of
[Quick-AD-Scan-Script](https://github.com/anirudhataliyan/Quick-AD-Scan-Script)
originally written in Python. It performs the same core LDAP enumeration but
uses only built-in .NET classes — no pip, no virtual environment, no extra
install step. Results are exported to **CSV**, **JSON**, and a self-contained
**HTML report**.

---

## Features

Quick-AD-Scan provides both enumeration and security-auditing features:

- User, group and computer enumeration
- OU and domain trust mapping
- SPN discovery and Kerberos exposure checks (Kerberoast / AS-REP)
- Password policy auditing
- LDAP vulnerability checks (signing / LDAPS)
- Kerbrute integration (optional)
- Dangerous ACL / privileged membership detection (new)
- GPO security auditing (new)
- Finding engine, risk scoring, and privilege graph export (new)

---

## Project Structure

```
Quick-AD-Scan-PS/
├── main.ps1                         Entry point — run this
├── requirements.psd1                Dependency manifest (pip-equivalent)
├── README.md                        This file
└── src/
    ├── Enum-Users.ps1               User account enumeration
    ├── Enum-Groups.ps1              Group & membership enumeration
    ├── Enum-Computers.ps1           Computer / workstation enumeration
    ├── Enum-OUs.ps1                 Organisational Unit mapping
    ├── Enum-Trusts.ps1              Domain trust enumeration
    ├── Enum-SPNs.ps1                Kerberoastable SPN discovery
    ├── Invoke-KerberoastAudit.ps1   Kerberoast exposure audit
    ├── Invoke-ASREPRoastAudit.ps1   AS-REP roasting exposure audit
    ├── Invoke-PasswordPolicyAudit.ps1 Password policy audit
    ├── Invoke-VulnScan.ps1          LDAP vulnerability checks
    ├── Invoke-Kerbrute.ps1          Kerbrute wrapper (optional)
    ├── Invoke-DangerousACLAudit.ps1 Dangerous ACL / privileged membership audit
    ├── Invoke-GPOSecurityAudit.ps1  GPO security audit
    ├── Find-SecurityFindings.ps1    Finding engine (normalizes findings)
    ├── Invoke-RiskScoring.ps1       Risk scoring engine
    ├── Build-PrivilegeGraph.ps1     Privilege graph exporter
    └── Export-Results.ps1           CSV / JSON / HTML export
```

---

## Usage

Run the normal `main.ps1` entry point — the new modules are loaded and
executed as part of the standard scan. Use `-OutputFormat` to include HTML
export so findings, scores and the privilege graph are exported into the
output directory.

---

## Notes

- All new modules are read-only and perform LDAP enumeration only. They do not
  request Kerberos tickets, perform credential attacks, or modify Active
  Directory objects.

- The dangerous ACL detector is a heuristic that flags suspicious members of
  high-privilege groups. Full ACL parsing requires additional privileges and
  deeper analysis; consider extending with nTSecurityDescriptor parsing if
  needed.

---


