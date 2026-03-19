<#
.SYNOPSIS
    Enumerate Active Directory computer objects via LDAP.

.DESCRIPTION
    Returns all computer accounts with OS version, last logon timestamp,
    and stale-account flag (no logon in 90+ days).
#>

function Get-ADComputers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.DirectoryServices.DirectoryEntry]$LdapEntry,
        [Parameter(Mandatory)][string]$SearchBase
    )

    Write-Host "[*] Enumerating computers..."

    $searcher = New-Object System.DirectoryServices.DirectorySearcher($LdapEntry)
    $searcher.Filter   = "(objectClass=computer)"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@(
        'cn','dNSHostName','operatingSystem','operatingSystemVersion',
        'operatingSystemServicePack','lastLogonTimestamp',
        'userAccountControl','distinguishedName','description','whenCreated'
    ))

    $staleThreshold = (Get-Date).AddDays(-90)
    $results        = @()

    $found = $null
    try {
        $found = $searcher.FindAll()
        foreach ($r in $found) {
            $uac      = [int]($r.Properties['userAccountControl'] | Select-Object -First 1)
            $disabled = [bool]($uac -band 0x0002)

            $lastLogon = $null
            $isStale   = $false
            if ($r.Properties['lastLogonTimestamp'].Count -gt 0) {
                $ll = [long]$r.Properties['lastLogonTimestamp'][0]
                if ($ll -gt 0) {
                    $dt        = [datetime]::FromFileTime($ll)
                    $lastLogon = $dt.ToString('yyyy-MM-dd HH:mm:ss')
                    $isStale   = $dt -lt $staleThreshold
                }
            }

            $obj = [PSCustomObject]@{
                Name              = ($r.Properties['cn']                        | Select-Object -First 1)
                DNSHostName       = ($r.Properties['dNSHostName']               | Select-Object -First 1)
                OS                = ($r.Properties['operatingSystem']           | Select-Object -First 1)
                OSVersion         = ($r.Properties['operatingSystemVersion']    | Select-Object -First 1)
                ServicePack       = ($r.Properties['operatingSystemServicePack']| Select-Object -First 1)
                LastLogon         = $lastLogon
                IsDisabled        = $disabled
                IsStale           = $isStale
                Description       = ($r.Properties['description']              | Select-Object -First 1)
                DN                = ($r.Properties['distinguishedName']         | Select-Object -First 1)
                WhenCreated       = ($r.Properties['whenCreated']               | Select-Object -First 1)
            }
            $results += $obj

            $flags = @()
            if ($disabled) { $flags += 'DISABLED' }
            if ($isStale)  { $flags += 'STALE(90d)' }
            $flagStr = if ($flags) { " [$($flags -join '|')]" } else { '' }

            Write-Host "  [PC] $($obj.Name)  OS: $($obj.OS)$flagStr"
        }
        Write-Host "[+] Found $($results.Count) computer(s)"
    }
    catch {
        Write-Host "[-] Computer enumeration error: $_"
    }
    finally {
        if ($found) { $found.Dispose() }
        $searcher.Dispose()
    }

    return $results
}
