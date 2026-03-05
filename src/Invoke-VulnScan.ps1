<#
.SYNOPSIS
    Check for LDAP relay / signing vulnerabilities on a domain controller.

.DESCRIPTION
    Attempts to detect whether LDAP signing is enforced and whether
    LDAPS channel binding is required. A missing signing requirement
    makes the DC susceptible to LDAP relay attacks (e.g. NTLM relay).

    Mirrors the original Python script's GoSecure ldap-scanner integration
    but implemented natively in PowerShell via .NET DirectoryServices.

.NOTES
    Checks performed:
      1. Anonymous LDAP bind attempt
      2. Plain (non-SSL) bind with credentials — detects if signing is negotiated
      3. LDAPS availability check
      4. LdapServerIntegrity registry key hint (if accessible)
#>

function Invoke-VulnScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$SearchBase,
        [string]$Username,
        [string]$Password
    )

    Write-Host "[*] Running LDAP vulnerability checks on $Server ..." -ForegroundColor Cyan

    $findings = @()

    # ── Check 1: Anonymous bind ───────────────────────────────────────────────
    Write-Host "  [CHECK 1] Anonymous LDAP bind..." -ForegroundColor Gray
    try {
        $anonEntry = New-Object System.DirectoryServices.DirectoryEntry(
            "LDAP://$Server/$SearchBase", "", "",
            [System.DirectoryServices.AuthenticationTypes]::Anonymous
        )
        $null = $anonEntry.distinguishedName
        Write-Host "  [!] VULNERABLE: Anonymous LDAP bind succeeded — disable null sessions!" -ForegroundColor Red
        $findings += [PSCustomObject]@{ Check='AnonymousBind'; Result='VULNERABLE'; Detail='Anonymous bind accepted' }
    }
    catch {
        Write-Host "  [+] Anonymous bind rejected (OK)" -ForegroundColor Green
        $findings += [PSCustomObject]@{ Check='AnonymousBind'; Result='OK'; Detail='Anonymous bind rejected' }
    }

    # ── Check 2: Signing requirement (via AuthenticationTypes) ────────────────
    Write-Host "  [CHECK 2] LDAP signing requirement..." -ForegroundColor Gray
    try {
        # Try connecting WITHOUT signing requested — if it succeeds, signing is NOT enforced
        $unsignedEntry = New-Object System.DirectoryServices.DirectoryEntry(
            "LDAP://$Server/$SearchBase", $Username, $Password,
            [System.DirectoryServices.AuthenticationTypes]::None
        )
        $null = $unsignedEntry.distinguishedName
        Write-Host "  [!] POTENTIALLY VULNERABLE: Server accepted unsigned bind — LDAP signing may not be enforced." -ForegroundColor Yellow
        $findings += [PSCustomObject]@{ Check='LDAPSigning'; Result='POTENTIALLY_VULNERABLE'; Detail='Unsigned bind accepted' }
    }
    catch {
        if ($_.Exception.Message -match 'StrongerAuthRequired|strong authentication') {
            Write-Host "  [+] LDAP signing is enforced (OK)" -ForegroundColor Green
            $findings += [PSCustomObject]@{ Check='LDAPSigning'; Result='OK'; Detail='StrongerAuthRequired returned' }
        }
        else {
            Write-Host "  [i] Signing check inconclusive: $($_.Exception.Message)" -ForegroundColor DarkGray
            $findings += [PSCustomObject]@{ Check='LDAPSigning'; Result='INCONCLUSIVE'; Detail=$_.Exception.Message }
        }
    }

    # ── Check 3: LDAPS availability ───────────────────────────────────────────
    Write-Host "  [CHECK 3] LDAPS (SSL/TLS) availability on port 636..." -ForegroundColor Gray
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connect   = $tcpClient.BeginConnect($Server, 636, $null, $null)
        $success   = $connect.AsyncWaitHandle.WaitOne(3000)
        $tcpClient.Close()

        if ($success) {
            Write-Host "  [+] LDAPS port 636 is open." -ForegroundColor Green
            $findings += [PSCustomObject]@{ Check='LDAPS'; Result='OK'; Detail='Port 636 open' }
        }
        else {
            Write-Host "  [!] LDAPS port 636 is NOT reachable — only plain LDAP available." -ForegroundColor Yellow
            $findings += [PSCustomObject]@{ Check='LDAPS'; Result='WARNING'; Detail='Port 636 unreachable' }
        }
    }
    catch {
        Write-Host "  [!] LDAPS check failed: $_" -ForegroundColor Yellow
        $findings += [PSCustomObject]@{ Check='LDAPS'; Result='ERROR'; Detail=$_.Exception.Message }
    }

    # ── Check 4: LDAP channel binding hint ───────────────────────────────────
    Write-Host "  [CHECK 4] Checking for LDAP channel binding (remote hint)..." -ForegroundColor Gray
    # We can't read the remote DC's registry, so we flag this as a manual check
    Write-Host "  [i] Channel binding (CVE-2017-8563) cannot be tested remotely without a Kerberos token." -ForegroundColor DarkGray
    Write-Host "      Verify LdapEnforceChannelBinding = 2 on the DC via Group Policy." -ForegroundColor DarkGray
    $findings += [PSCustomObject]@{ Check='ChannelBinding'; Result='MANUAL_CHECK'; Detail='Cannot be verified remotely' }

    Write-Host "[+] Vulnerability scan complete." -ForegroundColor Green
    return $findings
}
