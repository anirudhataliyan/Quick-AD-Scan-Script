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
**HTML report** (new).

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
    ├── Enum-OUs.ps1                 Organisational Unit mapping     [NEW]
    ├── Enum-Trusts.ps1              Domain trust enumeration        [NEW]
    ├── Enum-SPNs.ps1                Kerberoastable SPN discovery    [NEW]
    ├── Invoke-PasswordPolicyAudit.ps1  Password policy audit        [NEW]
    ├── Invoke-VulnScan.ps1          LDAP relay vulnerability checks
    ├── Invoke-Kerbrute.ps1          Kerbrute binary wrapper
    └── Export-Results.ps1           CSV / JSON / HTML export        [NEW]
```

---

## Requirements

- **PowerShell 5.1** or later (PowerShell 7+ recommended)
- A **domain user account** — read-only access is enough for all enumeration
- No external PowerShell modules required
- *(Optional)* [Kerbrute](https://github.com/ropnop/kerbrute/releases) binary
  for Kerberos-based username enumeration / password spraying

Check `requirements.psd1` for the full dependency manifest (the PowerShell
equivalent of `requirements.txt`).

---

## Quick Start

```powershell
# Interactive mode — prompts for all inputs
.\main.ps1

# Fully CLI mode
.\main.ps1 -Server domain.com -Username "DOM\admin" -SearchBase "DC=domain,DC=com"

# Export CSV + JSON + HTML
.\main.ps1 -Server domain.com -Username "DOM\admin" -SearchBase "DC=domain,DC=com" `
           -OutputFormat "csv,json,html"

# Stealth mode (adds random delays between queries)
.\main.ps1 -Server domain.com -Username "DOM\admin" -SearchBase "DC=domain,DC=com" -Stealth
```

---

## Kerbrute Integration

Place the Kerbrute binary at `.\src\kerbrute\kerbrute.exe` (Windows) or
`.\src\kerbrute\kerbrute` (Linux/macOS) and it will be auto-detected.
Alternatively supply `-KerbrutePath`.

```powershell
# Username enumeration (auto-detects kerbrute from .\src\kerbrute\)
.\main.ps1 --kerbrute-cmd userenum --domain example.com --userlist users.txt

# Password spray with account lockout protection
.\main.ps1 -KerbruteCmd passwordspray `
           -Domain example.com `
           -UserList usernames.txt `
           -KerbrutePassword 'Summer2025' `
           -KerbruteSafe

# Supply explicit binary path
.\main.ps1 -KerbrutePath C:\tools\kerbrute.exe `
           -KerbruteCmd userenum `
           -Domain example.com `
           -UserList users.txt
```

Kerbrute results (valid usernames / logins) are parsed from stdout and saved
to a separate `kerbrute_results_<timestamp>.csv` in the output directory.

---

## Output

All results are saved to `.\output\` by default.  
Override with `-OutputDir`.

| File | Description |
|---|---|
| `Users_<ts>.csv` | All user accounts with flags |
| `Groups_<ts>.csv` | Groups and their members |
| `Computers_<ts>.csv` | Domain computers |
| `OUs_<ts>.csv` | Organisational unit tree |
| `Trusts_<ts>.csv` | Domain trusts |
| `SPNs_<ts>.csv` | Kerberoastable SPN accounts |
| `PasswordPolicy_<ts>.csv` | Domain password policy |
| `report_<ts>.html` | Single-file HTML summary report |
| `kerbrute_results_<ts>.csv` | Valid Kerbrute results (if run) |

---

## New Features Explained

### Kerberoastable SPN Discovery
Identifies enabled user accounts that have a `servicePrincipalName` attribute.
These can be targeted for offline ticket cracking. Accounts with `adminCount=1`
are highlighted in red as high-value targets.

### Password Policy Audit
Reads the Default Domain Policy and flags weak settings:
- Minimum password length < 12
- Complexity disabled
- No account lockout
- Password max age > 365 days

### Domain Trust Enumeration
Maps all `trustedDomain` objects and classifies each by direction
(Inbound / Outbound / Bidirectional) and type. Bidirectional trusts are
flagged for manual review.

### OU Enumeration
Walks the entire OU tree, notes depth and hierarchy, and flags OUs that have
Group Policy Objects (GPOs) linked.

### HTML Report
A single self-contained dark-themed HTML file summarising all scan results
in sortable tables. Enable with `-OutputFormat "csv,json,html"`.

---

## Execution Policy

If PowerShell blocks the script, temporarily bypass for the current session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\main.ps1
```

Or run directly:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\main.ps1
```

---

## Optional: RSAT Module

If the `ActiveDirectory` RSAT module is available on a domain-joined machine,
you can also use native AD cmdlets alongside this toolkit:

```powershell
# Install RSAT (Windows 10/11, requires elevation)
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

# Then use native cmdlets
Get-ADUser -Filter * -Properties *
```

This script does **not** require RSAT — it talks to LDAP directly via .NET.

---

## Disclaimer

This tool is intended for **authorised security assessments only**.  
Do not run against networks or systems you do not have explicit permission to test.  
The author and contributors accept no liability for misuse.

---

## Credits

- Original Python script: [@anirudhataliyan](https://github.com/anirudhataliyan/Quick-AD-Scan-Script)
- LDAP relay scanner inspiration: [@GoSecure](https://github.com/timb-machine-mirrors/GoSecure-ldap-scanner)
- Kerbrute: [@ropnop](https://github.com/ropnop/kerbrute)
