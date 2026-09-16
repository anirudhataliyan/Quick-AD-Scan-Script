<#
.SYNOPSIS
    Export scan results to an HTML report.

.DESCRIPTION
    Takes the consolidated results and generates a formatted HTML report
    with sections for each result type, special formatting for findings/risk scores.
#>

function Export-Results {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Results,
        [Parameter(Mandatory)][string]$OutputPath
    )

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <title>AD Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        section { background: white; padding: 20px; margin: 15px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h2 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        .badge { background: #007bff; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.85em; }
        .table-wrap { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: bold; color: #333; }
        tr:hover { background: #f9f9f9; }
        pre { background: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 0.9em; }
        .empty { color: #999; font-style: italic; }
    </style>
</head>
<body>
    <h1>Active Directory Scan Report</h1>
    <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
"@

    $sectionsHtml = ""

    foreach ($cat in $Results.Keys) {
        $data = @($Results[$cat])
        if ($data.Count -eq 0) {
            $sectionsHtml += "<section><h2>$cat</h2><p class='empty'>No results found.</p></section>`n"
            continue
        }

        # Special handling for Findings and RiskScores to make nicer tables
        if ($cat -eq 'Findings') {
            $sectionsHtml += "<section><h2>Findings <span class='badge'>$($data.Count)</span></h2><div class='table-wrap'><table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Module</th><th>Affected</th><th>Details</th></tr></thead><tbody>`n"
            foreach ($f in $data) {
                $details = [System.Web.HttpUtility]::HtmlEncode(($f.Details | ConvertTo-Json -Depth 4))
                $sectionsHtml += "<tr><td>$($f.FindingID)</td><td>$([System.Web.HttpUtility]::HtmlEncode($f.Title))</td><td>$([System.Web.HttpUtility]::HtmlEncode($f.Severity))</td><td>$([System.Web.HttpUtility]::HtmlEncode($f.Module))</td><td>$([System.Web.HttpUtility]::HtmlEncode($f.AffectedObject))</td><td><pre style='white-space:pre-wrap;max-width:600px;'>$details</pre></td></tr>`n"
            }
            $sectionsHtml += "</tbody></table></div></section>`n"
            continue
        }

        if ($cat -eq 'RiskScores') {
            $sectionsHtml += "<section><h2>Risk Scores <span class='badge'>$($data.Count)</span></h2><div class='table-wrap'><table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Score</th><th>Affected</th></tr></thead><tbody>`n"
            foreach ($s in $data) {
                $sectionsHtml += "<tr><td>$($s.FindingID)</td><td>$([System.Web.HttpUtility]::HtmlEncode($s.Title))</td><td>$([System.Web.HttpUtility]::HtmlEncode($s.Severity))</td><td>$($s.Score)</td><td>$([System.Web.HttpUtility]::HtmlEncode($s.Affected))</td></tr>`n"
            }
            $sectionsHtml += "</tbody></table></div></section>`n"
            continue
        }

        if ($cat -eq 'PrivilegeGraph') {
            # Offer a compact CSV-style table and a downloadable CSV blob
            $csvBlob = ($data | ConvertTo-Csv -NoTypeInformation) -join "`n"
            $csvEncoded = [System.Web.HttpUtility]::HtmlEncode($csvBlob)
            $sectionsHtml += "<section><h2>Privilege Graph <span class='badge'>$($data.Count)</span></h2><div class='table-wrap'><pre style='white-space:pre-wrap;max-width:100%;'>$csvEncoded</pre></div></section>`n"
            continue
        }

        # Generic table for other categories
        $props  = $data[0].PSObject.Properties.Name
        $header = ($props | ForEach-Object { "<th>$_</th>" }) -join ''
        $rows   = @()
        foreach ($item in $data) {
            $cells = @()
            foreach ($prop in $props) {
                $val = $item.$prop
                $encoded = [System.Web.HttpUtility]::HtmlEncode($val)
                $cells += "<td>$encoded</td>"
            }
            $rows += "<tr>" + ($cells -join '') + "</tr>`n"
        }
        
        $sectionsHtml += "<section><h2>$cat <span class='badge'>$($data.Count)</span></h2><div class='table-wrap'><table><thead><tr>$header</tr></thead><tbody>`n$($rows -join '')</tbody></table></div></section>`n"
    }

    $html += $sectionsHtml
    $html += @"
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Report exported to: $OutputPath"
}
