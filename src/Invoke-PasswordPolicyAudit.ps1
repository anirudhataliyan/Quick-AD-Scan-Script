<#
.SYNOPSIS
    Retrieve and audit the domain password policy.

.DESCRIPTION
    Reads the Default Domain Policy password settings from the domain root
    object and reports on key attributes: minimum length, complexity, lockout,
    and maximum age.

    This is a NEW feature not present in the original Python script.
#>

function Get-PasswordPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.DirectoryServices.DirectoryEntry]$LdapEntry,
        [Parameter(Mandatory)][string]$SearchBase
    )

    Write-Host "[*] Reading domain password policy..."

    $results = @()
    $found = $null

    try {
        # The password policy lives on the domain root object
        $domainEntry = $LdapEntry
        $domainEntry.RefreshCache(@(
            'minPwdLength','maxPwdAge','minPwdAge','pwdHistoryLength',
            'pwdProperties','lockoutThreshold','lockoutDuration','lockoutObservationWindow'
        ))

        # Helper: convert 100-ns intervals to days
        function ConvertTo-Days ([long]$interval) {
            if ($interval -eq 0) { return 0 }
            $ticks = [Math]::Abs($interval)
            return [Math]::Round($ticks / 864000000000, 1)
        }

        $minLen      = [int]$domainEntry.Properties['minPwdLength'].Value
        $maxAgeDays  = ConvertTo-Days ([long]$domainEntry.Properties['maxPwdAge'].Value)
        $minAgeDays  = ConvertTo-Days ([long]$domainEntry.Properties['minPwdAge'].Value)
        $histLen     = [int]$domainEntry.Properties['pwdHistoryLength'].Value
        $complexity  = [int]$domainEntry.Properties['pwdProperties'].Value -band 1  # bit 0 = complexity
        $lockoutThrs = [int]$domainEntry.Properties['lockoutThreshold'].Value
        $lockoutDur  = ConvertTo-Days ([long]$domainEntry.Properties['lockoutDuration'].Value)

        $obj = [PSCustomObject]@{
            MinPasswordLength     = $minLen
            MaxPasswordAgeDays    = $maxAgeDays
            MinPasswordAgeDays    = $minAgeDays
            PasswordHistoryLength = $histLen
            ComplexityEnabled     = [bool]$complexity
            LockoutThreshold      = $lockoutThrs
            LockoutDurationDays   = $lockoutDur
        }
        $results += $obj

        # Print & flag weak settings
        Write-Host "  Minimum Password Length : $minLen $(if ($minLen -lt 12) { '[WEAK - recommend >= 12]' } else { '[OK]' })" 

        Write-Host "  Password Complexity     : $(if ($complexity) { 'Enabled [OK]' } else { 'DISABLED [WEAK]' })" 

        Write-Host "  Max Password Age (days) : $maxAgeDays $(if ($maxAgeDays -gt 365 -or $maxAgeDays -eq 0) { '[WEAK]' } else { '[OK]' })" 

        Write-Host "  Password History Length : $histLen $(if ($histLen -lt 10) { '[WEAK - recommend >= 10]' } else { '[OK]' })" 

        Write-Host "  Lockout Threshold       : $lockoutThrs $(if ($lockoutThrs -eq 0) { '[NO LOCKOUT - WEAK]' } else { '[OK]' })" 

        Write-Host "[+] Password policy retrieved."
    }
    catch {
        Write-Host "[-] Password policy read error: $_"
    }

    return $results
}
