<#
.SYNOPSIS
    Export scan results to CSV, JSON, and/or HTML formats.

.DESCRIPTION
    Takes the hashtable of scan results produced by main.ps1 and writes
    per-category files plus an HTML summary report.

    NEW feature: HTML report output is not present in the original Python script.
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

    foreach ($category in $Results.Keys) {
        $data = $Results[$category]
        if (-not $data -or $data.Count -eq 0) { continue }

        $base = Join-Path $OutputDir "${category}_${Timestamp}"

        if ('csv' -in $Formats) {
            $csvPath = "$base.csv"
            $data | Export-Csv -Path $csvPath -NoTypeInformation
            Write-Host "[+] CSV  -> $csvPath" -ForegroundColor Green
        }

        if ('json' -in $Formats) {
            $jsonPath = "$base.json"
            $data | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8
            Write-Host "[+] JSON -> $jsonPath" -ForegroundColor Green
        }
    }

    if ('html' -in $Formats) {
        $htmlPath = Join-Path $OutputDir "report_${Timestamp}.html"
        $html = Build-HtmlReport -Results $Results -Timestamp $Timestamp
        $html | Set-Content -Path $htmlPath -Encoding UTF8
        Write-Host "[+] HTML -> $htmlPath" -ForegroundColor Green
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
        $data = $Results[$cat]
        if (-not $data -or $data.Count -eq 0) {
            $sectionsHtml += "<h2>$cat</h2><p class='empty'>No results found.</p>`n"
            continue
        }

        # Build table header from first object's properties
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
        $sectionsHtml += @"
<section>
  <h2>$cat $badge</h2>
  <div class='table-wrap'>
    <table>
      <thead><tr>$header</tr></thead>
      <tbody>$rows</tbody>
    </table>
  </div>
</section>
"@
    }

    return @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Quick-AD-Scan Report — $scanDate</title>
  <style>
    :root { --accent:#00b4d8; --bg:#0f1117; --surface:#1a1d27; --border:#2c2f3e; --text:#e0e0e0; --muted:#888; }
    * { box-sizing:border-box; margin:0; padding:0; }
    body { background:var(--bg); color:var(--text); font-family:'Segoe UI',system-ui,sans-serif; padding:2rem; }
    header { border-bottom:2px solid var(--accent); padding-bottom:1rem; margin-bottom:2rem; }
    header h1 { font-size:1.8rem; color:var(--accent); }
    header p  { color:var(--muted); font-size:.9rem; margin-top:.3rem; }
    section   { margin-bottom:2.5rem; }
    h2 { font-size:1.1rem; margin-bottom:.75rem; display:flex; align-items:center; gap:.5rem; }
    .badge { background:var(--accent); color:#000; border-radius:999px; padding:.1rem .5rem; font-size:.75rem; font-weight:700; }
    .table-wrap { overflow-x:auto; border-radius:6px; border:1px solid var(--border); }
    table { width:100%; border-collapse:collapse; font-size:.82rem; }
    thead tr { background:var(--surface); }
    th { padding:.55rem .75rem; text-align:left; color:var(--accent); font-weight:600; border-bottom:1px solid var(--border); white-space:nowrap; }
    td { padding:.5rem .75rem; border-bottom:1px solid var(--border); vertical-align:top; word-break:break-word; max-width:300px; }
    tr:last-child td { border-bottom:none; }
    tr:hover td { background:rgba(0,180,216,.05); }
    .empty { color:var(--muted); font-style:italic; }
    footer { margin-top:3rem; color:var(--muted); font-size:.8rem; border-top:1px solid var(--border); padding-top:1rem; }
  </style>
</head>
<body>
  <header>
    <h1>&#x1F6E1;&#xFE0F; Quick-AD-Scan — Report</h1>
    <p>Generated: $scanDate &nbsp;|&nbsp; PowerShell Edition</p>
  </header>
  $sectionsHtml
  <footer>For authorised testing only. Original project: github.com/anirudhataliyan/Quick-AD-Scan-Script</footer>
</body>
</html>
"@
}
