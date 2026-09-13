<#
.SYNOPSIS
    Audit Active Directory for potentially dangerous ACL memberships.

.DESCRIPTION
    This module performs a lightweight, read-only heuristic check for dangerous
    privilege exposures by inspecting membership of well-known privileged groups
    (Domain Admins, Enterprise Admins, Schema Admins, Administrators) and
    reporting any non-standard accounts or groups that are members.

    NOTE: This is a heuristic scan. Full ACL evaluation requires reading
    nTSecurityDescriptor and parsing ACEs which may need elevated privileges
    or additional controls. This module intentionally avoids destructive
    operations and only reads membership attributes.
#>

function Invoke-DangerousACLAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.DirectoryServices.DirectoryEntry]$LdapEntry,
        [Parameter(Mandatory)][string]$SearchBase
    )

    Write-Host ""
    Write-Host "[*] Running dangerous ACL / privileged membership audit..."

    $privileged = @(
        'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators'
    )

    $searcher = New-Object System.DirectoryServices.DirectorySearcher($LdapEntry)
    $searcher.PageSize = 1000
    $searcher.Filter = "(objectClass=group)"
    $searcher.PropertiesToLoad.AddRange(@('cn','member','distinguishedName'))

    $results = @()
    $found = $null

    try {
        $found = $searcher.FindAll()
        foreach ($g in $found) {
            $cn = ($g.Properties['cn'] | Select-Object -First 1)
            if ($privileged -notcontains $cn) { continue }

            $members = @()
            foreach ($m in $g.Properties['member']) {
                # Extract CN if present
                if ($m -match 'CN=([^,]+)') { $members += $Matches[1] } else { $members += $m }
            }

            $unusual = @()
            foreach ($mem in $members) {
                # Heuristic: flag any members that are users (not computer$) and not service accounts like 'krbtgt'
                if ($mem -and ($mem -notmatch '\$$') -and ($mem -notmatch '^krbtgt$')) {
                    $unusual += $mem
                }
            }

            $obj = [PSCustomObject]@{
                Group        = $cn
                MemberCount  = ($members.Count)
                Members      = ($members -join '; ')
                FlaggedItems = ($unusual -join '; ')
                DN           = ($g.Properties['distinguishedName'] | Select-Object -First 1)
            }
            $results += $obj

            Write-Host "  [PRIV] $cn  Members: $($obj.MemberCount)  Flagged: $($unusual.Count)"
        }

        if ($results.Count -gt 0) {
            Write-Host "[+] Dangerous ACL / privileged membership audit completed."
        } else {
            Write-Host "[i] No privileged groups found or no members detected."
        }
    }
    catch {
        Write-Host "[-] Dangerous ACL audit error: $($_.Exception.Message)"
    }
    finally {
        if ($found) { $found.Dispose() }
        $searcher.Dispose()
    }

    return $results
}
