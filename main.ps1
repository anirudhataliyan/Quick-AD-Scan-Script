#Requires -Version 5.1
<#
.SYNOPSIS
    Quick-AD-Scan — PowerShell Active Directory Enumeration Tool

.DESCRIPTION
    A modular PowerShell toolkit for enumerating and auditing Active Directory
    environments over LDAP. Outputs results to CSV, JSON, and optionally HTML.
    Supports Kerbrute integration for Kerberos-based username enumeration and
    password spraying.

    Features:
      • User enumeration (with locked/disabled/never-expiring flags)
      • Group enumeration & membership
      • Computer enumeration (OS, last logon)
      • Organisational Unit (OU) enumeration         [NEW]
      • Domain trust enumeration                      [NEW]
      • Kerberoastable SPN account discovery          [NEW]
      • Password policy audit                         [NEW]
      • LDAP relay vulnerability check
      • Kerbrute integration (userenum / passwordspray)
      • Export to CSV, JSON, and HTML report          [NEW]

.PARAMETER Server
    LDAP server address, e.g. ldap://domain.com or just domain.com

.PARAMETER Username
    Bind username, e.g. DOMAIN\User or user@domain.com

.PARAMETER Password
    Bind password (prompted securely if omitted)

.PARAMETER SearchBase
    LDAP search base, e.g. DC=domain,DC=com

.PARAMETER KerbruteCmd
    Kerbrute sub-command: userenum | passwordspray

.PARAMETER KerbrутеPath
    Path to kerbrute binary (auto-detected if placed in .\src\kerbrute\)

.PARAMETER UserList
    Path to wordlist/username list for Kerbrute operations

.PARAMETER Domain
    DNS domain name used for Kerbrute (e.g. example.com)

.PARAMETER Password
    Single password for Kerbrute passwordspray

.PARAMETER KerbrутеSafe
    Pass --safe to kerbrute to avoid locking accounts

.PARAMETER OutputDir
    Directory for output files (default: .\output)

.PARAMETER OutputFormat
    Comma-separated list of output formats: csv,json,html (default: csv,json)

.PARAMETER Stealth
    Add randomised delays between queries to reduce detection noise

.EXAMPLE
    .\main.ps1
    # Interactive mode — prompts for all required inputs

.EXAMPLE
    .\main.ps1 -Server domain.com -Username "DOM\admin" -SearchBase "DC=domain,DC=com"

.EXAMPLE
    .\main.ps1 --kerbrute-cmd userenum --domain example.com --userlist users.txt

.NOTES
    For educational and authorised testing purposes only.
    Author  : converted & extended to PowerShell
    Original: https://github.com/anirudhataliyan/Quick-AD-Scan-Script
    Requires: No external modules — uses .NET DirectoryServices directly.
              Optionally benefits from the ActiveDirectory RSAT module.
#>

[CmdletBinding()]
param(
    [string]$Server,
    [string]$Username,
    [string]$Password,
    [string]$SearchBase,

    # Kerbrute integration
    [string]$KerbrутеPath,
    [ValidateSet('userenum','passwordspray')]
    [string]$KerbruteCmd,
    [string]$UserList,
    [string]$Domain,
    [string]$KerbrutePassword,
    [switch]$KerbrутеSafe,

    # Output
    [string]$OutputDir    = ".\output",
    [string]$OutputFormat = "csv,json",

    # Behaviour
    [switch]$Stealth
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Resolve script root so dot-sourcing works from any working directory ──────
$ScriptRoot = $PSScriptRoot
if (-not $ScriptRoot) { $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }

# ── Load feature modules ──────────────────────────────────────────────────────
$modules = @(
    'Enum-Users',
    'Enum-Groups',
    'Enum-Computers',
    'Enum-OUs',
    'Enum-Trusts',
    'Enum-SPNs',
    'Invoke-PasswordPolicyAudit',
    'Invoke-VulnScan',
    'Invoke-Kerbrute',
    'Export-Results'
)

foreach ($mod in $modules) {
    $modPath = Join-Path $ScriptRoot "src\$mod.ps1"
    if (Test-Path $modPath) {
        . $modPath
    } else {
        Write-Warning "Module not found: $modPath"
    }
}

# ── Banner ────────────────────────────────────────────────────────────────────
function Show-Banner {
    $banner = @"

  ██████╗ ██╗   ██╗██╗ ██████╗██╗  ██╗      █████╗ ██████╗
 ██╔═══██╗██║   ██║██║██╔════╝██║ ██╔╝     ██╔══██╗██╔══██╗
 ██║   ██║██║   ██║██║██║     █████╔╝      ███████║██║  ██║
 ██║▄▄ ██║██║   ██║██║██║     ██╔═██╗      ██╔══██║██║  ██║
 ╚██████╔╝╚██████╔╝██║╚██████╗██║  ██╗     ██║  ██║██████╔╝
  ╚══▀▀═╝  ╚═════╝ ╚═╝ ╚═════╝╚═╝  ╚═╝     ╚═╝  ╚═╝╚═════╝
        ███████╗ ██████╗ █████╗ ███╗  ██╗
        ██╔════╝██╔════╝██╔══██╗████╗ ██║
        ███████╗██║     ███████║██╔██╗██║
        ╚════██║██║     ██╔══██║██║╚████║
        ███████║╚██████╗██║  ██║██║ ╚███║
        ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝

  Quick-AD-Scan  |  PowerShell Edition
  For authorised testing only
"@
    Write-Host $banner -ForegroundColor Cyan
}

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Info  ([string]$msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-OK    ([string]$msg) { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn  ([string]$msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Fail  ([string]$msg) { Write-Host "[-] $msg" -ForegroundColor Red }
function Write-Section([string]$t)  {
    Write-Host "`n$('─' * 60)" -ForegroundColor DarkGray
    Write-Host "  $t" -ForegroundColor White
    Write-Host "$('─' * 60)" -ForegroundColor DarkGray
}

function Maybe-Sleep {
    if ($Stealth) {
        $delay = Get-Random -Minimum 500 -Maximum 3000
        Start-Sleep -Milliseconds $delay
    }
}

# ── Establish LDAP connection ─────────────────────────────────────────────────
function Connect-LDAP {
    param(
        [string]$Server,
        [string]$Username,
        [string]$Password,
        [string]$SearchBase
    )

    # Normalise server — strip ldap:// prefix for DirectoryEntry
    $host_ = $Server -replace '^ldaps?://', ''

    Write-Info "Connecting to $host_ ..."

    try {
        $path  = "LDAP://$host_/$SearchBase"
        $entry = New-Object System.DirectoryServices.DirectoryEntry($path, $Username, $Password)

        # Trigger bind by reading a property
        $null = $entry.distinguishedName

        Write-OK "Connection successful!"
        return $entry
    }
    catch {
        Write-Fail "Connection failed: $_"
        exit 1
    }
}

# ── Main ──────────────────────────────────────────────────────────────────────
Show-Banner

# ── Kerbrute-only mode ────────────────────────────────────────────────────────
if ($KerbruteCmd) {
    Write-Section "Kerbrute Mode"
    $kbPath = Resolve-KerbrутеPath -UserSuppliedPath $KerbrутеPath
    if (-not $kbPath) { Write-Fail "Kerbrute binary not found. See README for setup."; exit 1 }

    Invoke-KerbruteOperation `
        -BinaryPath    $kbPath `
        -SubCommand    $KerbruteCmd `
        -Domain        $Domain `
        -UserList      $UserList `
        -Password      $KerbrutePassword `
        -Safe:$KerbrутеSafe `
        -OutputDir     $OutputDir
    exit 0
}

# ── Interactive prompts for missing params ────────────────────────────────────
Write-Host ""
Write-Host "  Welcome to Quick-AD-Scan (PowerShell Edition)" -ForegroundColor White
Write-Host ""

if (-not $Server) {
    $Server = Read-Host "  Enter the AD server address (e.g. ldap://domain.com)"
}
if (-not $Username) {
    $Username = Read-Host "  Enter username (e.g. DOMAIN\User)"
}
if (-not $Password) {
    $secPwd  = Read-Host "  Enter password" -AsSecureString
    $bstr    = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPwd)
    $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
}
if (-not $SearchBase) {
    $SearchBase = Read-Host "  Enter search base (e.g. DC=domain,DC=com)"
}

# ── Connect ───────────────────────────────────────────────────────────────────
$ldap = Connect-LDAP -Server $Server -Username $Username -Password $Password -SearchBase $SearchBase

# ── Prepare output directory ──────────────────────────────────────────────────
$null = New-Item -ItemType Directory -Force -Path $OutputDir
$timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$formats    = $OutputFormat -split ',' | ForEach-Object { $_.Trim().ToLower() }

$allResults = @{}

# ── Run enumeration modules ───────────────────────────────────────────────────
Write-Section "1 / 7  User Enumeration"
Maybe-Sleep
$allResults['Users'] = Get-ADUsers -LdapEntry $ldap -SearchBase $SearchBase

Write-Section "2 / 7  Group Enumeration"
Maybe-Sleep
$allResults['Groups'] = Get-ADGroups -LdapEntry $ldap -SearchBase $SearchBase

Write-Section "3 / 7  Computer Enumeration"
Maybe-Sleep
$allResults['Computers'] = Get-ADComputers -LdapEntry $ldap -SearchBase $SearchBase

Write-Section "4 / 7  Organisational Unit Enumeration"
Maybe-Sleep
$allResults['OUs'] = Get-ADOUs -LdapEntry $ldap -SearchBase $SearchBase

Write-Section "5 / 7  Domain Trust Enumeration"
Maybe-Sleep
$allResults['Trusts'] = Get-ADTrusts -LdapEntry $ldap -SearchBase $SearchBase

Write-Section "6 / 7  Kerberoastable SPN Accounts"
Maybe-Sleep
$allResults['SPNs'] = Get-KerberoastableAccounts -LdapEntry $ldap -SearchBase $SearchBase

Write-Section "7 / 7  Password Policy Audit"
Maybe-Sleep
$allResults['PasswordPolicy'] = Get-PasswordPolicy -LdapEntry $ldap -SearchBase $SearchBase

# ── Vulnerability scan ────────────────────────────────────────────────────────
Write-Section "Vulnerability Scan — LDAP Relay Checks"
$server_ = $Server -replace '^ldaps?://', ''
Invoke-VulnScan -Server $server_ -SearchBase $SearchBase -Username $Username -Password $Password

# ── Optional Kerbrute ─────────────────────────────────────────────────────────
$kbPath = Resolve-KerbrутеPath -UserSuppliedPath $KerbrутеPath
if ($kbPath) {
    Write-Section "Kerbrute — Username Enumeration"
    $usernames = $allResults['Users'] | ForEach-Object { $_.SamAccountName } | Where-Object { $_ }
    $tmpList   = Join-Path $OutputDir "usernames_$timestamp.txt"
    $usernames | Set-Content $tmpList
    Write-OK "Username list written to $tmpList"

    Invoke-KerbruteOperation `
        -BinaryPath  $kbPath `
        -SubCommand  'userenum' `
        -Domain      ($Server -replace '^ldaps?://' -replace '/$') `
        -UserList    $tmpList `
        -Safe:$KerbrутеSafe `
        -OutputDir   $OutputDir
} else {
    Write-Warn "Kerbrute not found — skipping Kerberos enumeration."
    Write-Warn "Place binary at .\src\kerbrute\kerbrute[.exe] or pass -KerbrутеPath."
}

# ── Export ────────────────────────────────────────────────────────────────────
Write-Section "Exporting Results"
Export-ScanResults `
    -Results    $allResults `
    -OutputDir  $OutputDir `
    -Timestamp  $timestamp `
    -Formats    $formats

Write-Host ""
Write-OK "Scan complete. Results saved to: $OutputDir"
Write-Host ""
