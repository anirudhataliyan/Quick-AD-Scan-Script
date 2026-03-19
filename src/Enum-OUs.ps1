<#
.SYNOPSIS
    Enumerate Organisational Units (OUs) in Active Directory.

.DESCRIPTION
    Maps the OU hierarchy and highlights whether each OU has GPOs linked,
    providing a high-level picture of how the domain is structured.
    This is a NEW feature not present in the original Python script.
#>

function Get-ADOUs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.DirectoryServices.DirectoryEntry]$LdapEntry,
        [Parameter(Mandatory)][string]$SearchBase
    )

    Write-Host "[*] Enumerating Organisational Units..."

    $searcher = New-Object System.DirectoryServices.DirectorySearcher($LdapEntry)
    $searcher.Filter   = "(objectClass=organizationalUnit)"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@(
        'ou','distinguishedName','description','gPLink','whenCreated','managedBy'
    ))

    $results = @()
    $found = $null

    try {
        $found = $searcher.FindAll()
        foreach ($r in $found) {
            $gpLink   = ($r.Properties['gPLink'] | Select-Object -First 1)
            $hasGPO   = -not [string]::IsNullOrWhiteSpace($gpLink)

            # Depth = number of OU= segments above root
            $dn    = ($r.Properties['distinguishedName'] | Select-Object -First 1)
            $depth = ([regex]::Matches($dn, 'OU=')).Count

            $obj = [PSCustomObject]@{
                Name        = ($r.Properties['ou']                 | Select-Object -First 1)
                Description = ($r.Properties['description']        | Select-Object -First 1)
                HasGPO      = $hasGPO
                GPOLink     = $gpLink
                ManagedBy   = ($r.Properties['managedBy']          | Select-Object -First 1)
                Depth       = $depth
                DN          = $dn
                WhenCreated = ($r.Properties['whenCreated']        | Select-Object -First 1)
            }
            $results += $obj

            $indent = '  ' * ($depth - 1)
            $gpoStr = if ($hasGPO) { ' [GPO LINKED]' } else { '' }
            Write-Host "  $indent[OU] $($obj.Name)$gpoStr"
        }
        Write-Host "[+] Found $($results.Count) OU(s)"
    }
    catch {
        Write-Host "[-] OU enumeration error: $_"
    }
    finally {
        if ($found) { $found.Dispose() }
        $searcher.Dispose()
    }

    return $results
}
