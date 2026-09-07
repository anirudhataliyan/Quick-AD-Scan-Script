# Quick-AD-Scan

A modular PowerShell toolkit for Active Directory enumeration and security auditing over LDAP.

Quick-AD-Scan is designed to help security students, administrators, and authorized security testers identify potentially dangerous Active Directory configurations.

> For authorized testing and defensive security assessment only.

## Features

### Active Directory Enumeration

- User enumeration
- Group and group-membership enumeration
- Computer enumeration
- Organizational Unit enumeration
- Domain trust enumeration
- Service Principal Name (SPN) discovery

### Security Auditing

- Password policy auditing
- LDAP security checks
- Kerberoasting exposure detection
- AS-REP roasting exposure detection
- Privileged account identification
- Password-never-expires detection
- Account configuration analysis

### Output

Results can be exported as:

- CSV
- JSON
- HTML

The HTML report provides a single self-contained report containing the collected scan results.

## Kerberos Security Auditing

Quick-AD-Scan currently performs two Kerberos-related exposure checks.

### Kerberoasting Exposure

The scanner identifies enabled user accounts with registered Service Principal Names (SPNs).

Accounts with SPNs can be relevant to Kerberoasting assessments because Kerberos service authentication can expose password-derived material that may be subjected to offline password auditing.

Quick-AD-Scan does not request service tickets or perform password cracking. It identifies potentially exposed account configurations.

The scanner gives additional attention to:

- Privileged accounts
- Accounts with `adminCount=1`
- Accounts configured with passwords that never expire
- Accounts with passwords that have not been changed recently

Example:

```text
[CRITICAL] svc_sql

Finding:
    Kerberoasting Exposure

SPNs:
    MSSQLSvc/sql01.example.local

Privileged:
    YES

Password never expires:
    YES
```

### AS-REP Roasting Exposure

The scanner identifies enabled user accounts where Kerberos pre-authentication is disabled.

This configuration can expose the account to AS-REP roasting techniques.

Quick-AD-Scan only detects the configuration. It does not request AS-REP responses or attempt password cracking.

Example:

```text
[HIGH] legacy_user

Finding:
    AS-REP Roasting Exposure

Kerberos pre-authentication:
    DISABLED

Privileged:
    NO
```

## Project Structure

```text
Quick-AD-Scan-Script/
│
├── main.ps1
├── README.md
├── requirements.psd1
│
├── src/
│   ├── Enum-Users.ps1
│   ├── Enum-Groups.ps1
│   ├── Enum-Computers.ps1
│   ├── Enum-OUs.ps1
│   ├── Enum-SPNs.ps1
│   ├── Enum-Trusts.ps1
│   │
│   ├── Invoke-KerberoastAudit.ps1
│   ├── Invoke-ASREPRoastAudit.ps1
│   │
│   ├── Invoke-PasswordPolicyAudit.ps1
│   ├── Invoke-VulnScan.ps1
│   ├── Invoke-Kerbrute.ps1
│   └── Export-Results.ps1
│
└── output/
```

## Requirements

- PowerShell 5.1 or later
- Windows Active Directory environment
- A domain account with sufficient read access
- No external PowerShell modules are required for the LDAP enumeration and auditing modules

PowerShell 7+ is recommended where available.

## Usage

### Interactive

```powershell
.\main.ps1
```

The script will prompt for the LDAP server, credentials, and search base.

### Command line

```powershell
.\main.ps1 \
    -Server "dc01.example.local" \
    -Username "EXAMPLE\administrator" \
    -SearchBase "DC=example,DC=local"
```

### Export CSV, JSON and HTML

```powershell
.\main.ps1 \
    -Server "dc01.example.local" \
    -Username "EXAMPLE\administrator" \
    -SearchBase "DC=example,DC=local" \
    -OutputFormat "csv,json,html"
```

### Custom output directory

```powershell
.\main.ps1 \
    -Server "dc01.example.local" \
    -Username "EXAMPLE\administrator" \
    -SearchBase "DC=example,DC=local" \
    -OutputDir ".\results"
```

## Example Findings

A security assessment may produce results similar to:

```text
SECURITY FINDINGS
=================

[CRITICAL] AD-KERB-001
Kerberoasting Exposure

Account:
    svc_sql

Indicators:
    Privileged account
    Password never expires
    Registered SPN


[HIGH] AD-KERB-002
AS-REP Roasting Exposure

Account:
    legacy_user

Indicators:
    Kerberos pre-authentication disabled
```

Actual results depend on the Active Directory environment being assessed.

## Security Model

Quick-AD-Scan is intended primarily as a read-only enumeration and security-auditing tool.

The Kerberoasting and AS-REP roasting modules implemented in this project detect vulnerable directory configurations but intentionally do not:

- Request Kerberos service tickets
- Request AS-REP responses
- Crack passwords
- Dump credentials
- Modify Active Directory objects

This allows the scanner to identify exposure without performing credential attacks.

## Existing Modules

| Module | Purpose |
|---|---|
| `Enum-Users.ps1` | Enumerates user accounts |
| `Enum-Groups.ps1` | Enumerates groups and memberships |
| `Enum-Computers.ps1` | Enumerates domain computers |
| `Enum-OUs.ps1` | Maps organizational units |
| `Enum-SPNs.ps1` | Discovers user accounts with SPNs |
| `Enum-Trusts.ps1` | Enumerates domain trusts |
| `Invoke-KerberoastAudit.ps1` | Detects Kerberoasting exposure |
| `Invoke-ASREPRoastAudit.ps1` | Detects AS-REP roasting exposure |
| `Invoke-PasswordPolicyAudit.ps1` | Audits password policy |
| `Invoke-VulnScan.ps1` | Performs LDAP security checks |
| `Invoke-Kerbrute.ps1` | Optional Kerbrute integration |
| `Export-Results.ps1` | Exports scan results |

## Roadmap

Planned security-auditing features include:

- Dangerous Active Directory ACL detection
- Delegation auditing
- LAPS auditing
- Privileged group analysis
- GPO security analysis
- LDAP signing and channel-binding analysis
- Active Directory Certificate Services auditing
- Risk scoring
- Security finding correlation
- Scan-to-scan comparison
- Privilege relationship graphs
- Improved HTML security dashboard

## Legal / Ethical Use

This project is intended for:

- Your own Active Directory lab
- Systems you administer
- Authorized penetration tests
- Security assessments where you have explicit permission

Do not run the scanner against networks or systems without authorization.

The author and contributors are not responsible for misuse of this software.

## License

Add your preferred open-source license to the repository before publishing a release.
