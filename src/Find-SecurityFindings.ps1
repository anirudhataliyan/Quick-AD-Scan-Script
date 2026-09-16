<#
.SYNOPSIS
    Consolidate findings across modules into a normalized finding list.

.DESCRIPTION
    This lightweight engine ingests the results hashtable produced by main.ps1
    and converts module-specific outputs into a common finding format with:
      - ID
      - Title
      - Severity
      - Module
      - AffectedObject
      - Details

    The engine is intentionally read-only and does not perform new LDAP queries
    — it operates on already-collected results.
#>

function Find-SecurityFindings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Results
    )

    $findings = @()
    $idCounter = 1000

    # Helper to add finding
    function Add-Finding($title,$severity,$module,$obj,$details) {
        $idCounter++ | Out-Null
        $findings += [PSCustomObject]@{
            FindingID      = "F-" + $idCounter
            Title          = $title
            Severity       = $severity
            Module         = $module
            AffectedObject = $obj
            Details        = $details
        }
    }

    # Kerberoast findings
    if ($Results.ContainsKey('KerberoastAudit')) {
        foreach ($r in @($Results['KerberoastAudit'])) {
            $sev = if ($r.Severity) { $r.Severity } else { 'Medium' }
            Add-Finding "Kerberoast exposure: $($r.SamAccountName)" $sev 'KerberoastAudit' $r.SamAccountName ($r | ConvertTo-Json -Depth 3)
        }
    }

    # AS-REP findings
    if ($Results.ContainsKey('ASREPRoastAudit')) {
        foreach ($r in @($Results['ASREPRoastAudit'])) {
            $sev = if ($r.Severity) { $r.Severity } else { 'High' }
            Add-Finding "AS-REP exposure: $($r.SamAccountName)" $sev 'ASREPRoastAudit' $r.SamAccountName ($r | ConvertTo-Json -Depth 3)
        }
    }

    # SPNs
    if ($Results.ContainsKey('SPNs')) {
        foreach ($r in @($Results['SPNs'])) {
            Add-Finding "Kerberoastable account: $($r.SamAccountName)" 'Medium' 'SPNs' $r.SamAccountName ($r | ConvertTo-Json -Depth 3)
        }
    }

    # Password policy
    if ($Results.ContainsKey('PasswordPolicy')) {
        foreach ($r in @($Results['PasswordPolicy'])) {
            # check weak settings
            $weak = @()
            if ($r.MinPasswordLength -lt 12) { $weak += 'MinLen<' + $r.MinPasswordLength }
            if (-not $r.ComplexityEnabled) { $weak += 'ComplexityDisabled' }
            if ($r.MaxPasswordAgeDays -gt 365 -or $r.MaxPasswordAgeDays -eq 0) { $weak += 'MaxAgeWeak' }
            if ($weak.Count -gt 0) {
                Add-Finding "Weak password policy" 'Medium' 'PasswordPolicy' 'Domain' ($weak -join ', ')
            }
        }
    }

    # Vulnerability scan findings
    if ($Results.ContainsKey('VulnScan')) {
        foreach ($r in @($Results['VulnScan'])) {
            $title = "LDAP check: $($r.Check)"
            $sev = if ($r.Result -match 'VULNERABLE|POTENTIALLY') { 'High' } else { 'Low' }
            Add-Finding $title $sev 'VulnScan' $r.Check ($r.Detail)
        }
    }

    # Dangerous ACLs
    if ($Results.ContainsKey('DangerousACLs')) {
        foreach ($r in @($Results['DangerousACLs'])) {
            if ($r.FlaggedItems) {
                Add-Finding "Privileged group contains flagged members: $($r.Group)" 'High' 'DangerousACLs' $r.Group ($r.FlaggedItems)
            }
        }
    }

    # GPO findings
    if ($Results.ContainsKey('GPOAudit')) {
        foreach ($r in @($Results['GPOAudit'])) {
            Add-Finding "GPO / OU Link: $([string]$r.GPOName -or $r.OU)" 'Low' 'GPOAudit' ($r.GPOName -or $r.OU) ($r | ConvertTo-Json -Depth 3)
        }
    }

    return $findings
}
