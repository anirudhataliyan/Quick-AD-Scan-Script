<#
.SYNOPSIS
    Enumerate Active Directory user accounts via LDAP.

.DESCRIPTION
    Queries the directory for all user objects and returns structured objects
    containing key account attributes including locked, disabled, and
    password-never-expires flags.
#>

function Get-ADUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.DirectoryServices.DirectoryEntry]$LdapEntry,
        [Parameter(Mandatory)][string]$SearchBase
    )

    Write-Host "[*] Enumerating users..."

    $searcher = New-Object System.DirectoryServices.DirectorySearcher($LdapEntry)
    $searcher.Filter   = "(&(objectClass=user)(objectCategory=person))"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@(
        'sAMAccountName','displayName','mail','department','title',
        'userAccountControl','lastLogonTimestamp','pwdLastSet',
        'memberOf','distinguishedName','description','whenCreated',
        'lockoutTime'
    ))

    $results = @()
    $found = $null

    try {
        $found = $searcher.FindAll()
        foreach ($r in $found) {
            $uac        = [int]($r.Properties['userAccountControl'] | Select-Object -First 1)
            $disabled   = [bool]($uac -band 0x0002)
            $pwdNeverEx = [bool]($uac -band 0x10000)
            $locked     = [bool]($uac -band 0x0010)

            $lastLogon = $null
            if ($r.Properties['lastLogonTimestamp'].Count -gt 0) {
                $ll = [long]$r.Properties['lastLogonTimestamp'][0]
                if ($ll -gt 0) { $lastLogon = [datetime]::FromFileTime($ll).ToString('yyyy-MM-dd HH:mm:ss') }
            }

            $pwdLastSet = $null
            if ($r.Properties['pwdLastSet'].Count -gt 0) {
                $pl = [long]$r.Properties['pwdLastSet'][0]
                if ($pl -gt 0) { $pwdLastSet = [datetime]::FromFileTime($pl).ToString('yyyy-MM-dd HH:mm:ss') }
            }

            $groups = ($r.Properties['memberOf'] | ForEach-Object {
                if ($_ -match 'CN=([^,]+)') { $Matches[1] }
            }) -join '; '

            $obj = [PSCustomObject]@{
                SamAccountName   = ($r.Properties['sAMAccountName']    | Select-Object -First 1)
                DisplayName      = ($r.Properties['displayName']        | Select-Object -First 1)
                Email            = ($r.Properties['mail']               | Select-Object -First 1)
                Department       = ($r.Properties['department']         | Select-Object -First 1)
                Title            = ($r.Properties['title']              | Select-Object -First 1)
                Description      = ($r.Properties['description']        | Select-Object -First 1)
                Disabled         = $disabled
                Locked           = $locked
                PasswordNeverExp = $pwdNeverEx
                LastLogon        = $lastLogon
                PasswordLastSet  = $pwdLastSet
                MemberOf         = $groups
                DN               = ($r.Properties['distinguishedName']  | Select-Object -First 1)
                WhenCreated      = ($r.Properties['whenCreated']        | Select-Object -First 1)
            }
            $results += $obj

            $flags = @()
            if ($disabled)   { $flags += 'DISABLED' }
            if ($locked)     { $flags += 'LOCKED' }
            if ($pwdNeverEx) { $flags += 'PWD_NEVER_EXP' }
            $flagStr = if ($flags) { " [$($flags -join '|')]" } else { '' }

            Write-Host "  [USER] $($obj.SamAccountName)$flagStr"
        }
        Write-Host "[+] Found $($results.Count) user(s)"
    }
    catch {
        Write-Host "[-] User enumeration error: $_"
    }
    finally {
        if ($found) { $found.Dispose() }
        $searcher.Dispose()
    }

    return $results
}
