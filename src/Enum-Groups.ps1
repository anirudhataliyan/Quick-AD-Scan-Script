<#
.SYNOPSIS
    Enumerate Active Directory groups and their membership via LDAP.

.DESCRIPTION
    Queries for all group objects and resolves member CNs into readable names.
    Highlights privileged built-in groups (Domain Admins, Enterprise Admins, etc.)
#>

function Get-ADGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.DirectoryServices.DirectoryEntry]$LdapEntry,
        [Parameter(Mandatory)][string]$SearchBase
    )

    Write-Host "[*] Enumerating groups..." -ForegroundColor Cyan

    # Well-known privileged groups (lower-cased for comparison)
    $privilegedGroups = @(
        'domain admins', 'enterprise admins', 'schema admins',
        'administrators', 'account operators', 'backup operators',
        'print operators', 'server operators', 'group policy creator owners'
    )

    $searcher = New-Object System.DirectoryServices.DirectorySearcher($LdapEntry)
    $searcher.Filter   = "(objectClass=group)"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@(
        'cn','sAMAccountName','description','member',
        'groupType','distinguishedName','whenCreated'
    ))

    $results = @()

    try {
        $found = $searcher.FindAll()
        foreach ($r in $found) {
            $name    = ($r.Properties['cn']            | Select-Object -First 1)
            $sam     = ($r.Properties['sAMAccountName'] | Select-Object -First 1)
            $desc    = ($r.Properties['description']   | Select-Object -First 1)
            $dn      = ($r.Properties['distinguishedName'] | Select-Object -First 1)
            $created = ($r.Properties['whenCreated']   | Select-Object -First 1)

            # Decode group type
            $gType = [int]($r.Properties['groupType'] | Select-Object -First 1)
            $scope = switch ($gType -band 0xF) {
                2  { 'Global' }
                4  { 'DomainLocal' }
                8  { 'Universal' }
                default { 'Unknown' }
            }
            $isSecurity = [bool]($gType -band 0x80000000)

            $members = ($r.Properties['member'] | ForEach-Object {
                if ($_ -match 'CN=([^,]+)') { $Matches[1] }
            }) -join '; '

            $isPrivileged = $privilegedGroups -contains $name.ToLower()

            $obj = [PSCustomObject]@{
                Name        = $name
                SamAccount  = $sam
                Description = $desc
                Scope       = $scope
                IsSecurity  = $isSecurity
                IsPrivileged= $isPrivileged
                MemberCount = ($r.Properties['member'].Count)
                Members     = $members
                DN          = $dn
                WhenCreated = $created
            }
            $results += $obj

            $color = if ($isPrivileged) { 'Red' } else { 'White' }
            $priv  = if ($isPrivileged) { ' *** PRIVILEGED ***' } else { '' }
            Write-Host "  [GROUP] $name ($scope)  Members: $($obj.MemberCount)$priv" -ForegroundColor $color
        }
        Write-Host "[+] Found $($results.Count) group(s)" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Group enumeration error: $_" -ForegroundColor Red
    }
    finally {
        $found.Dispose()
        $searcher.Dispose()
    }

    return $results
}
