<#
.SYNOPSIS
    Discover Kerberoastable accounts — user accounts with SPNs set.

.DESCRIPTION
    Queries for enabled user accounts that have a servicePrincipalName attribute.
    These accounts can be targeted for Kerberoasting (requesting TGS tickets
    offline for cracking).

    This is a NEW feature not present in the original Python script.

.NOTES
    Output should be treated as sensitive. Only use on networks you are
    authorised to test.
#>

function Get-KerberoastableAccounts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.DirectoryServices.DirectoryEntry]$LdapEntry,
        [Parameter(Mandatory)][string]$SearchBase
    )

    Write-Host "[*] Hunting Kerberoastable accounts (user SPNs)..." -ForegroundColor Cyan

    # Filter: enabled users that have at least one SPN
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($LdapEntry)
    $searcher.Filter = "(&(objectClass=user)(objectCategory=person)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@(
        'sAMAccountName','servicePrincipalName','pwdLastSet',
        'adminCount','distinguishedName','lastLogonTimestamp'
    ))

    $results = @()

    try {
        $found = $searcher.FindAll()

        if ($found.Count -eq 0) {
            Write-Host "  [i] No Kerberoastable accounts found." -ForegroundColor Green
        }

        foreach ($r in $found) {
            $spns = $r.Properties['servicePrincipalName'] -join '; '

            $pwdLastSet = $null
            if ($r.Properties['pwdLastSet'].Count -gt 0) {
                $pl = [long]$r.Properties['pwdLastSet'][0]
                if ($pl -gt 0) { $pwdLastSet = [datetime]::FromFileTime($pl).ToString('yyyy-MM-dd HH:mm:ss') }
            }

            $isAdmin = [int]($r.Properties['adminCount'] | Select-Object -First 1) -eq 1

            $obj = [PSCustomObject]@{
                SamAccountName = ($r.Properties['sAMAccountName'] | Select-Object -First 1)
                SPNs           = $spns
                PasswordLastSet= $pwdLastSet
                IsAdminAccount = $isAdmin
                DN             = ($r.Properties['distinguishedName'] | Select-Object -First 1)
            }
            $results += $obj

            $color  = if ($isAdmin) { 'Red' } else { 'Yellow' }
            $marker = if ($isAdmin) { ' *** HIGH VALUE — adminCount=1 ***' } else { '' }
            Write-Host "  [SPN] $($obj.SamAccountName)  [$spns]$marker" -ForegroundColor $color
        }

        if ($results.Count -gt 0) {
            Write-Host "[!] $($results.Count) Kerberoastable account(s) found — consider auditing service account passwords!" -ForegroundColor Yellow
        } else {
            Write-Host "[+] No Kerberoastable accounts detected." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[-] SPN enumeration error: $_" -ForegroundColor Red
    }
    finally {
        $found.Dispose()
        $searcher.Dispose()
    }

    return $results
}
