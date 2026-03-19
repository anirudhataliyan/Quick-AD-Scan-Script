<#
.SYNOPSIS
    Discover Kerberoastable accounts - user accounts with SPNs set.

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

    Write-Host "[*] Checking for Kerberoastable accounts (user SPNs)..."

    $searcher = New-Object System.DirectoryServices.DirectorySearcher($LdapEntry)
    $searcher.Filter = "(&(objectClass=user)(objectCategory=person)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@(
        'sAMAccountName','servicePrincipalName','pwdLastSet',
        'adminCount','distinguishedName','lastLogonTimestamp'
    ))

    $results = @()
    $found = $null

    try {
        $found = $searcher.FindAll()

        if ($found.Count -eq 0) {
            Write-Host "  [i] No Kerberoastable accounts found."
        }

        foreach ($r in $found) {
            $spns = $r.Properties['servicePrincipalName'] -join '; '

            $pwdLastSet = $null
            if ($r.Properties['pwdLastSet'].Count -gt 0) {
                $pl = [long]$r.Properties['pwdLastSet'][0]
                if ($pl -gt 0) {
                    $pwdLastSet = [datetime]::FromFileTime($pl).ToString('yyyy-MM-dd HH:mm:ss')
                }
            }

            $isAdmin = [int]($r.Properties['adminCount'] | Select-Object -First 1) -eq 1

            $obj = [PSCustomObject]@{
                SamAccountName  = ($r.Properties['sAMAccountName']     | Select-Object -First 1)
                SPNs            = $spns
                PasswordLastSet = $pwdLastSet
                IsAdminAccount  = $isAdmin
                DN              = ($r.Properties['distinguishedName']   | Select-Object -First 1)
            }
            $results += $obj

            if ($isAdmin) {
                Write-Host "  [SPN] $($obj.SamAccountName)  [$spns] *** HIGH VALUE - adminCount=1 ***"
            } else {
                Write-Host "  [SPN] $($obj.SamAccountName)  [$spns]"
            }
        }

        if ($results.Count -gt 0) {
            Write-Host "[!] $($results.Count) Kerberoastable account(s) found."
        } else {
            Write-Host "[+] No Kerberoastable accounts detected."
        }
    }
    catch {
        Write-Host "[-] SPN enumeration error: $($_.Exception.Message)"
    }
    finally {
        if ($found) { $found.Dispose() }
        $searcher.Dispose()
    }

    return $results
}
