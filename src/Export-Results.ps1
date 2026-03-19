<#
.SYNOPSIS
    Export scan results to CSV, JSON, and/or HTML formats.
#>

function Export-ScanResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Results,
        [Parameter(Mandatory)][string]$OutputDir,
        [Parameter(Mandatory)][string]$Timestamp,
        [string[]]$Formats = @('csv','json')
    )

    $null = New-Item -ItemType Directory -Force -Path $OutputDir
    $written = 0

    foreach ($category in $Results.Keys) {
        $data = $Results[$category]

        # Skip truly null entries
        if ($null -eq $data) { continue }

        # Convert to array if single object
        if ($data -isnot [System.Array] -and $data -isnot [System.Collections.IEnumerable]) {
            $data = @($data)
        }

        $base = Join-Path $OutputDir "${category}_${Timestamp}"

        if ('csv' -in $Formats) {
            try {
                $csvPath = "$base.csv"
                if (@($data).Count -gt 0) {
                    @($data) | Export-Csv -Path $csvPath -NoTypeInformation -Force
                } else {
                    # Write empty CSV with just a note
                    "No data returned for $category" | Set-Content -Path $csvPath -Encoding UTF8
                }
                Write-Host "[+] CSV  -> $csvPath"
                $written++
            }
            catch { Write-Host "[-] CSV export failed for ${category}: $($_.Exception.Message)" }
        }

        if ('json' -in $Formats) {
            try {
                $jsonPath = "$base.json"
                @($data) | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8
                Write-Host "[+] JSON -> $jsonPath"
                $written++
            }
            catch { Write-Host "[-] JSON export failed for ${category}: $($_.Exception.Message)" }
        }
    }

    if ('html' -in $Formats) {
        try {
            $htmlPath = Join-Path $OutputDir "report_${Timestamp}.html"
            $html = Build-HtmlReport -Results $Results -Timestamp $Timestamp
            $html | Set-Content -Path $htmlPath -Encoding UTF8
            Write-Host "[+] HTML -> $htmlPath"
            $written++
        }
        catch { Write-Host "[-] HTML export failed: $($_.Exception.Message)" }
    }

    if ($written -eq 0) {
        Write-Host "[!] No files were written - all result sets were null."
    } else {
        Write-Host "[+] $written file(s) written to $OutputDir"
    }
}

function Build-HtmlReport {
    param(
        [hashtable]$Results,
        [string]$Timestamp
    )

    $scanDate = [datetime]::ParseExact($Timestamp,'yyyyMMdd_HHmmss',$null).ToString('yyyy-MM-dd HH:mm:ss')

    $sectionsHtml = ""
    foreach ($cat in $Results.Keys) {
        $data = @($Results[$cat])
        if ($data.Count -eq 0) {
            $sectionsHtml += "<section><h2>$cat</h2><p class='empty'>No results found.</p></section>`n"
            continue
        }

        $props  = $data[0].PSObject.Properties.Name
        $header = ($props | ForEach-Object { "<th>$_</th>" }) -join ''

        $rows = ($data | ForEach-Object {
            $row = $_
            $cells = ($props | ForEach-Object {
                $val = $row.$_
                "<td>$([System.Web.HttpUtility]::HtmlEncode("$val"))</td>"
            }) -join ''
            "<tr>$cells</tr>"
        }) -join "`n"

        $badge = "<span class='badge'>$($data.Count)</span>"
        $sectionsHtml += "<section><h2>$cat $badge</h2><div class='table-wrap'><table><thead><tr>$header</tr></thead><tbody>$rows</tbody></table></div></section>`n"
    }

    return @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Quick-AD-Scan Report - $scanDate</title>
  <style>
    body { background:#0f1117; color:#e0e0e0; font-family:'Segoe UI',sans-serif; padding:2rem; }
    h1 { color:#00b4d8; }
    h2 { color:#00b4d8; font-size:1rem; margin:1.5rem 0 .5rem; }
    .badge { background:#00b4d8; color:#000; border-radius:999px; padding:.1rem .5rem; font-size:.75rem; }
    .table-wrap { overflow-x:auto; }
    table { width:100%; border-collapse:collapse; font-size:.82rem; }
    th { padding:.5rem; text-align:left; border-bottom:1px solid #2c2f3e; }
    td { padding:.45rem .5rem; border-bottom:1px solid #2c2f3e; word-break:break-word; max-width:300px; }
    .empty { color:#888; font-style:italic; }
    p.ts { color:#888; font-size:.85rem; }
  </style>
</head>
<body>
  <h1>Quick-AD-Scan - Report</h1>
  <p class="ts">Generated: $scanDate</p>
  $sectionsHtml
  <footer style="margin-top:2rem;color:#888;font-size:.8rem;">For authorised testing only.</footer>
</body>
</html>
"@
}
