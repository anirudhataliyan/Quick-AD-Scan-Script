*** Begin Patch
*** Update File: src/Export-Results.ps1
@@
     foreach ($cat in $Results.Keys) {
         $data = @($Results[$cat])
         if ($data.Count -eq 0) {
             $sectionsHtml += "<section><h2>$cat</h2><p class='empty'>No results found.</p></section>`n"
             continue
         }
 
+        # Special handling for Findings and RiskScores to make nicer tables
+        if ($cat -eq 'Findings') {
+            $sectionsHtml += "<section><h2>Findings <span class='badge'>$($data.Count)</span></h2><div class='table-wrap'><table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Module</th><th>Affected</th><th>Details</th></tr></thead><tbody>"
+            foreach ($f in $data) {
+                $details = [System.Web.HttpUtility]::HtmlEncode(($f.Details | ConvertTo-Json -Depth 4))
+                $sectionsHtml += "<tr><td>$($f.FindingID)</td><td>$([System.Web.HttpUtility]::HtmlEncode($f.Title))</td><td>$([System.Web.HttpUtility]::HtmlEncode($f.Severity))</td><td>$([System.Web.HttpUtility]::HtmlEncode($f.Module))</td><td>$([System.Web.HttpUtility]::HtmlEncode($f.AffectedObject))</td><td><pre style='white-space:pre-wrap;max-width:600px;'>$details</pre></td></tr>`n"
+            }
+            $sectionsHtml += "</tbody></table></div></section>`n"
+            continue
+        }
+
+        if ($cat -eq 'RiskScores') {
+            $sectionsHtml += "<section><h2>Risk Scores <span class='badge'>$($data.Count)</span></h2><div class='table-wrap'><table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Score</th><th>Affected</th></tr></thead><tbody>"
+            foreach ($s in $data) {
+                $sectionsHtml += "<tr><td>$($s.FindingID)</td><td>$([System.Web.HttpUtility]::HtmlEncode($s.Title))</td><td>$([System.Web.HttpUtility]::HtmlEncode($s.Severity))</td><td>$($s.Score)</td><td>$([System.Web.HttpUtility]::HtmlEncode($s.Affected))</td></tr>`n"
+            }
+            $sectionsHtml += "</tbody></table></div></section>`n"
+            continue
+        }
+
+        if ($cat -eq 'PrivilegeGraph') {
+            # Offer a compact CSV-style table and a downloadable CSV blob
+            $csvBlob = ($data | ConvertTo-Csv -NoTypeInformation) -join "`n"
+            $csvEncoded = [System.Web.HttpUtility]::HtmlEncode($csvBlob)
+            $sectionsHtml += "<section><h2>Privilege Graph <span class='badge'>$($data.Count)</span></h2><div class='table-wrap'><pre style='white-space:pre-wrap;max-width:100%;'>" + $csvEncoded + "</pre></div></section>`n"
+            continue
+        }
+
         $props  = $data[0].PSObject.Properties.Name
         $header = ($props | ForEach-Object { "<th>$_</th>" }) -join ''
*** End Patch
