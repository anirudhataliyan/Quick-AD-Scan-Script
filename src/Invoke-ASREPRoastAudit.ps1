#Requires -Version 5.1

<#
.SYNOPSIS
    Audits Active Directory for AS-REP roasting exposure.

.DESCRIPTION
    Identifies enabled user accounts for which Kerberos
    pre-authentication is not required.

    This module performs LDAP enumeration only.
    It does NOT request AS-REP responses or attempt
    password cracking.

.NOTES
    For authorized Active Directory security assessments only.
#>

function Invoke-ASREPRoastAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.DirectoryEntry]$LdapEntry,

        [Parameter(Mandatory)]
        [string]$SearchBase
    )

    Write-Host ""
    Write-Host "[*] Running AS-REP roasting exposure audit..."

    $searcher = New-Object System.DirectoryServices.DirectorySearcher($LdapEntry)

    # UAC bit 0x400000 = DONT_REQ_PREAUTH
    #
    # LDAP matching rule:
    # 1.2.840.113556.1.4.803 = LDAP_MATCHING_RULE_BIT_AND
    #
    # Also exclude disabled accounts.
    $searcher.Filter =
        "(&(objectCategory=person)(objectClass=user)" +
        "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" +
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

    $searcher.PageSize = 1000

    $properties = @(
        'sAMAccountName',
        'displayName',
        'userAccountControl',
        'adminCount',
        'pwdLastSet',
        'lastLogonTimestamp',
        'distinguishedName'
    )

    foreach ($property in $properties) {
        [void]$searcher.PropertiesToLoad.Add($property)
    }

    $results = @()
    $found = $null

    try {
        $found = $searcher.FindAll()

        foreach ($entry in $found) {
            $props = $entry.Properties

            $sam = $props['samaccountname'] |
                Select-Object -First 1

            if (-not $sam) {
                continue
            }

            $uac = 0

            if ($props['useraccountcontrol'].Count -gt 0) {
                $uac = [int]$props['useraccountcontrol'][0]
            }

            $adminCount = 0

            if ($props['admincount'].Count -gt 0) {
                $adminCount = [int]$props['admincount'][0]
            }

            $isPrivileged = ($adminCount -eq 1)

            $pwdLastSet = $null

            if ($props['pwdlastset'].Count -gt 0) {
                $fileTime = [int64]$props['pwdlastset'][0]

                if ($fileTime -gt 0) {
                    $pwdLastSet = [DateTime]::FromFileTime($fileTime)
                }
            }

            $severity = if ($isPrivileged) {
                "Critical"
            }
            else {
                "High"
            }

            $indicators = @(
                "Kerberos pre-authentication disabled"
            )

            if ($isPrivileged) {
                $indicators += "Privileged account (adminCount=1)"
            }

            $results += [PSCustomObject]@{
                FindingID            = "AD-KERB-002"
                FindingType          = "AS-REP Roasting Exposure"
                Severity             = $severity
                SamAccountName       = $sam
                DisplayName          = ($props['displayname'] | Select-Object -First 1)
                Privileged           = $isPrivileged
                KerberosPreAuth      = $false
                UserAccountControl   = $uac
                PasswordLastSet      = if ($pwdLastSet) {
                    $pwdLastSet.ToString("yyyy-MM-dd HH:mm:ss")
                } else {
                    $null
                }
                DistinguishedName    = ($props['distinguishedname'] | Select-Object -First 1)
                Indicators           = ($indicators -join "; ")
                Recommendation       = "Require Kerberos pre-authentication unless the exception is explicitly required and documented."
            }
        }

        if ($results.Count -eq 0) {
            Write-Host "[+] No enabled accounts with disabled Kerberos pre-authentication detected."
        }
        else {
            Write-Host "[!] $($results.Count) AS-REP roasting-exposed account(s) detected."

            foreach ($finding in $results) {
                Write-Host ""
                Write-Host "    [$($finding.Severity)] $($finding.SamAccountName)"

                if ($finding.Privileged) {
                    Write-Host "    [!] Privileged account"
                }

                Write-Host "    [!] Kerberos pre-authentication disabled"
            }
        }
    }
    catch {
        Write-Host "[-] AS-REP audit failed: $($_.Exception.Message)"
    }
    finally {
        if ($found) {
            $found.Dispose()
        }

        $searcher.Dispose()
    }

    return $results
}
