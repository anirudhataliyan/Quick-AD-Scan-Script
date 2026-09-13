<#
.SYNOPSIS
    Assign numeric risk scores to findings.

.DESCRIPTION
    Simple scoring engine that maps severity levels to numeric values,
    factors in contextual attributes (privileged, age, password policies) and
    produces a combined risk score between 0 and 100.

    This module operates on findings produced by Find-SecurityFindings.
#>

function Invoke-RiskScoring {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$Findings
    )

    $scored = @()
    foreach ($f in $Findings) {
        $base = switch ($f.Severity.ToLower()) {
            'critical' { 90 }
            'high'     { 70 }
            'medium'   { 50 }
            'low'      { 25 }
            default    { 40 }
        }

        # Apply simple modifiers based on content
        $mod = 0
        if ($f.Title -match 'Kerberoast|SPN') { $mod += 10 }
        if ($f.Title -match 'AS-REP') { $mod += 15 }
        if ($f.Details -and ($f.Details -match 'Password never expires|NeverExpires')) { $mod += 10 }

        $score = [int]([Math]::Min(100, $base + $mod))

        $scored += [PSCustomObject]@{
            FindingID = $f.FindingID
            Title     = $f.Title
            Severity  = $f.Severity
            Module    = $f.Module
            Score     = $score
            Affected  = $f.AffectedObject
            Details   = $f.Details
        }
    }

    return $scored
}
