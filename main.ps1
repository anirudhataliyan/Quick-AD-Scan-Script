#Requires -Version 5.1
<## .SYNOPSIS
    Quick-AD-Scan - PowerShell Active Directory Enumeration Tool

.DESCRIPTION
    Enumerates and audits Active Directory over LDAP.
    Outputs results to CSV and/or JSON files.

.PARAMETER Server
    LDAP server address, e.g. ldap://domain.com or domain.com

.PARAMETER Username
    Bind username, e.g. DOMAIN\User or user@domain.com

.PARAMETER Password
    Bind password (prompted if omitted)

.PARAMETER SearchBase
    LDAP search base, e.g. DC=domain,DC=com

.PARAMETER KerbruteCmd
    Kerbrute sub-command: userenum | passwordspray

.PARAMETER KerbrutePath
    Path to kerbrute binary (auto-detected if placed in .\src\kerbrute\)

.PARAMETER UserList
    Path to username list for Kerbrute

.PARAMETER Domain
    DNS domain name for Kerbrute (e.g. example.com)

.PARAMETER KerbrutePassword
    Password for Kerbrute passwordspray

.PARAMETER KerbruteSafe
    Pass --safe to kerbrute to avoid locking accounts

.PARAMETER OutputDir
    Output directory (default: .\output)

.PARAMETER OutputFormat
    Comma-separated output formats: csv,json,html (default: csv,json)

.PARAMETER Stealth
    Add random delays between queries

.EXAMPLE
    .\main.ps1

.EXAMPLE
    .\main.ps1 -Server domain.com -Username "DOM\admin" -SearchBase "DC=domain,DC=com"

.EXAMPLE
    .\main.ps1 -KerbruteCmd userenum -Domain example.com -UserList users.txt

.NOTES
    For authorised testing only.
    Original: https://github.com/anirudhataliyan/Quick-AD-Scan-Script
#>

[CmdletBinding()]
param(
    [string]$Server,
    [string]$Username,
    [string]$Password,
    [string]$SearchBase,

    [string]$KerbrutePath,
    [ValidateSet('userenum','passwordspray')]
    [string]$KerbruteCmd,
    [string]$UserList,
    [string]$Domain,
    [string]$KerbrutePassword,
    [switch]$KerbruteSafe,

    [string]$OutputDir    = ".\output",
    [string]$OutputFormat = "csv,json",

    [switch]$Stealth
)

# Use Continue so non-terminating errors stay non-terminating and don't abort the script
$ErrorActionPreference = 'Continue'

$ScriptRoot = $PSScriptRoot
if (-not $ScriptRoot) { $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }

$modules = @(
    'Enum-Users',
    'Enum-Groups',
    'Enum-Computers',
    'Enum-OUs',
    'Enum-Trusts',
    'Enum-SPNs',
    'Invoke-KerberoastAudit',
    'Invoke-ASREPRoastAudit',
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

function Maybe-Sleep {
    if ($Stealth) {
        Start-Sleep -Milliseconds (Get-Random -Minimum 500 -Maximum 3000)
    }
}

function Connect-LDAP {
    param(
        [string]$Server,
        [string]$Username,
        [string]$Password,
        [string]$SearchBase
    )

    $host_ = $Server -replace '^ldaps?://', ''
    Write-Host "[*] Connecting to $host_ ..."

    try {
        $entry = New-Object System.DirectoryServices.DirectoryEntry(
            "LDAP://$host_/$SearchBase", $Username, $Password
        )
        $null = $entry.distinguishedName
        Write-Host "[+] Connected."
        return $entry
    }
    catch {
        Write-Host "[-] Connection failed: $($_.Exception.Message)"
        exit 1
    }
}

# Kerbrute-only mode
if ($KerbruteCmd) {
    $kbPath = Resolve-KerbrutePath -UserSuppliedPath $KerbrutePath
    if (-not $kbPath) { Write-Host "[-] Kerbrute binary not found. See README."; exit 1 }

    Invoke-KerbruteOperation `
        -BinaryPath      $kbPath `
        -SubCommand      $KerbruteCmd `
        -Domain          $Domain `
        -UserList        $UserList `
        -Password        $KerbrutePassword `
        -Safe:$KerbruteSafe `
        -OutputDir       $OutputDir
    exit 0
}

# Interactive prompts for missing params
if (-not $Server)     { $Server     = Read-Host "AD server address (e.g. ldap://domain.com)" }
if (-not $Username)   { $Username   = Read-Host "Username (e.g. DOMAIN\User)" }
if (-not $Password) {
    $secPwd   = Read-Host "Password" -AsSecureString
    $bstr     = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPwd)
    $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
}
if (-not $SearchBase) { $SearchBase = Read-Host "Search base (e.g. DC=domain,DC=com)" }

$ldap = Connect-LDAP -Server $Server -Username $Username -Password $Password -SearchBase $SearchBase

$null      = New-Item -ItemType Directory -Force -Path $OutputDir
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$formats   = $OutputFormat -split ',' | ForEach-Object { $_.Trim().ToLower() }
$results   = @{}

Write-Host "[*] Starting enumeration..."

Maybe-Sleep
try   { $results['Users'] = Get-ADUsers -LdapEntry $ldap -SearchBase $SearchBase }
catch { Write-Host "[-] Users failed: $($_.Exception.Message)" }

Maybe-Sleep
try   { $results['Groups'] = Get-ADGroups -LdapEntry $ldap -SearchBase $SearchBase }
catch { Write-Host "[-] Groups failed: $($_.Exception.Message)" }

Maybe-Sleep
try   { $results['Computers'] = Get-ADComputers -LdapEntry $ldap -SearchBase $SearchBase }
catch { Write-Host "[-] Computers failed: $($_.Exception.Message)" }

Maybe-Sleep
try   { $results['OUs'] = Get-ADOUs -LdapEntry $ldap -SearchBase $SearchBase }
catch { Write-Host "[-] OUs failed: $($_.Exception.Message)" }

Maybe-Sleep
try   { $results['Trusts'] = Get-ADTrusts -LdapEntry $ldap -SearchBase $SearchBase }
catch { Write-Host "[-] Trusts failed: $($_.Exception.Message)" }

Maybe-Sleep
try {
    $results['SPNs'] = Get-KerberoastableAccounts `
        -LdapEntry $ldap `
        -SearchBase $SearchBase
}
catch {
    Write-Host "[-] SPNs failed: $($_.Exception.Message)"
}

Maybe-Sleep
try {
    $results['KerberoastAudit'] = Invoke-KerberoastAudit `
        -LdapEntry $ldap `
        -SearchBase $SearchBase
}
catch {
    Write-Host "[-] Kerberoast audit failed: $($_.Exception.Message)"
}

Maybe-Sleep
try {
    $results['ASREPRoastAudit'] = Invoke-ASREPRoastAudit `
        -LdapEntry $ldap `
        -SearchBase $SearchBase
}
catch {
    Write-Host "[-] AS-REP audit failed: $($_.Exception.Message)"
}

Maybe-Sleep
try {
    $results['PasswordPolicy'] = Get-PasswordPolicy `
        -LdapEntry $ldap `
        -SearchBase $SearchBase
}
catch {
    Write-Host "[-] Password policy failed: $($_.Exception.Message)"
}

Write-Host "[*] Running LDAP vulnerability checks..."
try {
    $server_ = $Server -replace '^ldaps?://', ''
    $results['VulnScan'] = Invoke-VulnScan -Server $server_ -SearchBase $SearchBase -Username $Username -Password $Password
}
catch { Write-Host "[-] VulnScan failed: $($_.Exception.Message)" }

# Optional Kerbrute
try {
    $kbPath = Resolve-KerbrutePath -UserSuppliedPath $KerbrutePath
    if ($kbPath) {
        Write-Host "[*] Running Kerbrute username enumeration..."
        $usernames = $results['Users'] | ForEach-Object { $_.SamAccountName } | Where-Object { $_ }
        $tmpList   = Join-Path $OutputDir "usernames_$timestamp.txt"
        $usernames | Set-Content $tmpList

        Invoke-KerbruteOperation `
            -BinaryPath  $kbPath `
            -SubCommand  'userenum' `
            -Domain      ($Server -replace '^ldaps?://' -replace '/$') `
            -UserList    $tmpList `
            -Safe:$KerbruteSafe `
            -OutputDir   $OutputDir
    } else {
        Write-Host "[!] Kerbrute not found - skipping. Place binary at .\src\kerbrute\kerbrute[.exe] or use -KerbrutePath."
    }
}
catch { Write-Host "[-] Kerbrute failed: $($_.Exception.Message)" }

Write-Host "[*] Results summary:"
foreach ($key in $results.Keys) {
    $count = if ($results[$key]) { $results[$key].Count } else { 0 }
    Write-Host "    $key : $count item(s)"
}
Write-Host "[*] Exporting results..."
try {
    Export-ScanResults `
        -Results   $results `
        -OutputDir $OutputDir `
        -Timestamp $timestamp `
        -Formats   $formats
}
catch { Write-Host "[-] Export failed: $($_.Exception.Message)" }

Write-Host "[+] Done. Results saved to: $OutputDir"
