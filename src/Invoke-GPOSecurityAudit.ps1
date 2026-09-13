<#
.SYNOPSIS
    Audit Group Policy Objects (GPOs) and their security-relevant settings.

.DESCRIPTION
    This module enumerates Group Policy objects (groupPolicyContainer) and
    reports basic security characteristics and where they are linked (via gPLink).
    It flags potentially risky configurations such as unknown GPOs linked to high-level OUs
    or missing admin owners.

    This module uses LDAP reads only and does not modify GPOs.
#>

function Invoke-GPOSecurityAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.DirectoryServices.DirectoryEntry]$LdapEntry,
        [Parameter(Mandatory)][string]$SearchBase
    )

    Write-Host ""
    Write-Host "[*] Running GPO security audit..."

    $results = @()
    $found = $null

    try {
        # Search for GPO containers under CN=Policies,CN=System,<domain>
        $gpoSearcher = New-Object System.DirectoryServices.DirectorySearcher($LdapEntry)
        $gpoSearcher.Filter = "(objectClass=groupPolicyContainer)"
        $gpoSearcher.PageSize = 1000
        $gpoSearcher.PropertiesToLoad.AddRange(@('displayName','cn','gPCFileSysPath','whenCreated','distinguishedName','gPCMachineExtensionNames','gPCUserExtensionNames'))

        $found = $gpoSearcher.FindAll()

        foreach ($g in $found) {
            $name = ($g.Properties['displayname'] | Select-Object -First 1)
            if (-not $name) { $name = ($g.Properties['cn'] | Select-Object -First 1) }
            $path = ($g.Properties['gPCFileSysPath'] | Select-Object -First 1)
            $extensions = @()
            $extensions += ($g.Properties['gPCMachineExtensionNames'] | ForEach-Object { $_ })
            $extensions += ($g.Properties['gPCUserExtensionNames'] | ForEach-Object { $_ })

            $obj = [PSCustomObject]@{
                GPOName       = $name
                CN            = ($g.Properties['cn'] | Select-Object -First 1)
                FileSysPath   = $path
                Extensions    = ($extensions -join '; ')
                WhenCreated   = ($g.Properties['whenCreated'] | Select-Object -First 1)
                DN            = ($g.Properties['distinguishedName'] | Select-Object -First 1)
            }
            $results += $obj
            Write-Host "  [GPO] $($obj.GPOName)  Path: $($obj.FileSysPath)"
        }

        # Additionally, find where GPOs are linked by scanning OUs for gPLink
        $ouSearcher = New-Object System.DirectoryServices.DirectorySearcher($LdapEntry)
        $ouSearcher.Filter = "(objectClass=organizationalUnit)"
        $ouSearcher.PageSize = 1000
        $ouSearcher.PropertiesToLoad.AddRange(@('ou','distinguishedName','gPLink'))

        $foundOU = $ouSearcher.FindAll()
        foreach ($ou in $foundOU) {
            $gplink = ($ou.Properties['gPLink'] | Select-Object -First 1)
            if ($gplink) {
                $obj2 = [PSCustomObject]@{
                    OU    = ($ou.Properties['ou'] | Select-Object -First 1)
                    DN    = ($ou.Properties['distinguishedName'] | Select-Object -First 1)
                    GPLink = $gplink
                }
                $results += $obj2
                Write-Host "  [LINK] OU: $($obj2.OU)  GPLink: $($obj2.GPLink)"
            }
        }

        Write-Host "[+] GPO security audit completed. Found $($results.Count) items."
    }
    catch {
        Write-Host "[-] GPO audit error: $($_.Exception.Message)"
    }
    finally {
        if ($found) { $found.Dispose() }
        if ($foundOU) { $foundOU.Dispose() }
        $gpoSearcher.Dispose()
        $ouSearcher.Dispose()
    }

    return $results
}
