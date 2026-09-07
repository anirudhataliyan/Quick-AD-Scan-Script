#Requires -Version 5.1

<#
.SYNOPSIS
    Audits Active Directory for Kerberoasting exposure.

.DESCRIPTION
    Identifies enabled user accounts with registered SPNs.
    Highlights accounts that are privileged or have weak
    credential-lifecycle characteristics.

    This module performs LDAP enumeration only.
    It does NOT request Kerberos service tickets or crack passwords.

.NOTES
    For authorized Active Directory security assessments only.
#>

function Invoke-KerberoastAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.DirectoryEntry]$LdapEntry,

        [Parameter(Mandatory)]
        [string]$SearchBase
    )

    Write-Host ""
    Write-Host "[*] Running Kerberoasting exposure audit..."

    $searcher = New-Object System.DirectoryServices.DirectorySearcher($LdapEntry)

    # Enabled user accounts with at least one SPN.
    $searcher.Filter = @"
(&(objectCategory=person)
  (objectClass=user)
  (servicePrincipalName=*)
  (!(userAccountControl:1.2.840.113556.1.4.803:=2)))
"@ -replace '\s+', ''

    $searcher.PageSize = 1000

    $properties = @(
        'sAMAccountName',
        'displayName',
        'servicePrincipalName',
        'adminCount',
        'userAccountControl',
        'pwdLastSet',
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

            $spns = @($props['serviceprincipalname'])

            $adminCount = 0

            if ($props['admincount'].Count -gt 0) {
                $adminCount = [int]$props['admincount'][0]
            }

            $isPrivileged = ($adminCount -eq 1)

            $passwordNeverExpires = $false

            if ($props['useraccountcontrol'].Count -gt 0) {
                $uac = [int]$props['useraccountcontrol'][0]

                # UF_DONT_EXPIRE_PASSWD = 0x10000
                $passwordNeverExpires = (($uac -band 0x10000) -ne 0)
            }

            $pwdLastSet = $null

            if ($props['pwdlastset'].Count -gt 0) {
                $fileTime = [int64]$props['pwdlastset'][0]

                if ($fileTime -gt 0) {
                    $pwdLastSet = [DateTime]::FromFileTime($fileTime)
                }
            }

            $daysSincePasswordChange = $null

            if ($pwdLastSet) {
                $daysSincePasswordChange =
                    [int]((Get-Date) - $pwdLastSet).TotalDays
            }

            # Risk classification.
            $severity = "Medium"

            if ($isPrivileged -and $passwordNeverExpires) {
                $severity = "Critical"
            }
            elseif ($isPrivileged) {
                $severity = "High"
            }
            elseif ($passwordNeverExpires) {
                $severity = "High"
            }

            $findings = @()

            if ($isPrivileged) {
                $findings += "Privileged account (adminCount=1)"
            }

            if ($passwordNeverExpires) {
                $findings += "Password never expires"
            }

            if ($daysSincePasswordChange -ne $null -and
                $daysSincePasswordChange -gt 365) {
                $findings += "Password unchanged for more than 365 days"
            }

            $results += [PSCustomObject]@{
                FindingID               = "AD-KERB-001"
                FindingType             = "Kerberoasting Exposure"
                Severity                = $severity
                SamAccountName          = $sam
                DisplayName             = ($props['displayname'] | Select-Object -First 1)
                SPNCount                = $spns.Count
                SPNs                    = ($spns -join "; ")
                Privileged              = $isPrivileged
                PasswordNeverExpires    = $passwordNeverExpires
                PasswordLastSet         = if ($pwdLastSet) {
                    $pwdLastSet.ToString("yyyy-MM-dd HH:mm:ss")
                } else {
                    $null
                }
                DaysSincePasswordChange = $daysSincePasswordChange
                DistinguishedName       = ($props['distinguishedname'] | Select-Object -First 1)
                Indicators              = ($findings -join "; ")
                Recommendation          = "Review whether the SPN is required, minimize privileges, and use an appropriate managed service identity or credential lifecycle."
            }
        }

        if ($results.Count -eq 0) {
            Write-Host "[+] No enabled user accounts with SPNs detected."
        }
        else {
            Write-Host "[!] $($results.Count) Kerberoasting-exposed account(s) detected."

            foreach ($finding in $results) {
                Write-Host ""
                Write-Host "    [$($finding.Severity)] $($finding.SamAccountName)"
                Write-Host "    SPNs: $($finding.SPNCount)"

                if ($finding.Privileged) {
                    Write-Host "    [!] Privileged account"
                }

                if ($finding.PasswordNeverExpires) {
                    Write-Host "    [!] Password never expires"
                }
            }
        }
    }
    catch {
        Write-Host "[-] Kerberoast audit failed: $($_.Exception.Message)"
    }
    finally {
        if ($found) {
            $found.Dispose()
        }

        $searcher.Dispose()
    }

    return $results
}
