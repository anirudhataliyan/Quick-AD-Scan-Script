<#
.SYNOPSIS
    Build a privilege graph (users <-> groups) as an adjacency list.

.DESCRIPTION
    Enumerates group membership relationships and emits a simple CSV-style
    adjacency list (Source,Target,Type) suitable for import into graph tools.

    This module reads group 'member' attributes and user objects; it is read-only.
#>

function Build-PrivilegeGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.DirectoryServices.DirectoryEntry]$LdapEntry,
        [Parameter(Mandatory)][string]$SearchBase
    )

    Write-Host ""
    Write-Host "[*] Building privilege graph..."

    $searcher = New-Object System.DirectoryServices.DirectorySearcher($LdapEntry)
    $searcher.Filter = "(objectClass=group)"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@('cn','member'))

    $edges = @()
    $found = $null

    try {
        $found = $searcher.FindAll()
        foreach ($g in $found) {
            $groupName = ($g.Properties['cn'] | Select-Object -First 1)
            foreach ($m in $g.Properties['member']) {
                $target = $m
                if ($m -match 'CN=([^,]+)') { $target = $Matches[1] }
                $edges += [PSCustomObject]@{
                    Source = $groupName
                    Target = $target
                    Type   = 'memberOf'
                }
            }
        }

        Write-Host "[+] Privilege graph nodes: $($edges.Count) edges gathered."
    }
    catch {
        Write-Host "[-] Privilege graph error: $($_.Exception.Message)"
    }
    finally {
        if ($found) { $found.Dispose() }
        $searcher.Dispose()
    }

    return $edges
}
