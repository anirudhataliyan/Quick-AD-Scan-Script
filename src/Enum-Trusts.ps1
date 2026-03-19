<#
.SYNOPSIS
    Enumerate Active Directory domain trusts.

.DESCRIPTION
    Queries trustedDomain objects from the directory and classifies each trust
    by direction, type, and transitivity.
    This is a NEW feature not present in the original Python script.
#>

function Get-ADTrusts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.DirectoryServices.DirectoryEntry]$LdapEntry,
        [Parameter(Mandatory)][string]$SearchBase
    )

    Write-Host "[*] Enumerating domain trusts..."

    $searcher = New-Object System.DirectoryServices.DirectorySearcher($LdapEntry)
    $searcher.Filter   = "(objectClass=trustedDomain)"
    $searcher.PageSize = 200
    $searcher.PropertiesToLoad.AddRange(@(
        'cn','trustDirection','trustType','trustAttributes',
        'flatName','distinguishedName','whenCreated','securityIdentifier'
    ))

    $results = @()
    $found = $null

    try {
        $found = $searcher.FindAll()

        if ($found.Count -eq 0) {
            Write-Host "  [i] No domain trusts found."
        }

        foreach ($r in $found) {
            $dir   = [int]($r.Properties['trustDirection']  | Select-Object -First 1)
            $type  = [int]($r.Properties['trustType']       | Select-Object -First 1)
            $attrs = [int]($r.Properties['trustAttributes'] | Select-Object -First 1)

            $dirStr = switch ($dir) {
                0 { 'Disabled' }
                1 { 'Inbound' }
                2 { 'Outbound' }
                3 { 'Bidirectional' }
                default { "Unknown ($dir)" }
            }

            $typeStr = switch ($type) {
                1 { 'Windows NT (DownLevel)' }
                2 { 'Windows Active Directory (Kerberos)' }
                3 { 'MIT (Non-Windows Kerberos)' }
                4 { 'DCE' }
                default { "Unknown ($type)" }
            }

            $transitive = [bool]($attrs -band 0x01)
            $ssoEnabled = [bool]($attrs -band 0x200)

            $obj = [PSCustomObject]@{
                TrustedDomain = ($r.Properties['cn']       | Select-Object -First 1)
                FlatName      = ($r.Properties['flatName'] | Select-Object -First 1)
                Direction     = $dirStr
                Type          = $typeStr
                Transitive    = $transitive
                SSOEnabled    = $ssoEnabled
                WhenCreated   = ($r.Properties['whenCreated'] | Select-Object -First 1)
                DN            = ($r.Properties['distinguishedName'] | Select-Object -First 1)
            }
            $results += $obj

            Write-Host "  [TRUST] $($obj.TrustedDomain)  Dir: $($obj.Direction)  Type: $($obj.Type)"
        }
        Write-Host "[+] Found $($results.Count) trust(s)"
    }
    catch {
        Write-Host "[-] Trust enumeration error: $_"
    }
    finally {
        if ($found) { $found.Dispose() }
        $searcher.Dispose()
    }

    return $results
}
