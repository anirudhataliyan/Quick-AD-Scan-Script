# Set execution policy first
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# Setup
$adServer = "ldap://WIN-A4EILT2H9KP.quickad.local"
$username = "QUICKAD\Administrator"
$password = "Qwertyuiop@123"

# Create connection
try {
    $LdapEntry = New-Object System.DirectoryServices.DirectoryEntry($adServer, $username, $password)
    $null = $LdapEntry.NativeObject
    $SearchBase = $LdapEntry.DistinguishedName
    
    Write-Host "Connected to: $adServer" -ForegroundColor Green
    Write-Host "Search Base: $SearchBase" -ForegroundColor Green
    Write-Host ""
}
catch {
    Write-Host "Connection failed: $_" -ForegroundColor Red
    exit
}

# Load all modules
Write-Host "[*] Loading modules..." -ForegroundColor Yellow
. .\src\Enum-Users.ps1
. .\src\Enum-Computers.ps1
. .\src\Enum-Groups.ps1
. .\src\Enum-OUs.ps1
. .\src\Enum-SPNs.ps1
. .\src\Enum-Trusts.ps1
. .\src\Invoke-KerberoastAudit.ps1
. .\src\Invoke-ASREPRoastAudit.ps1
. .\src\Invoke-PasswordPolicyAudit.ps1
. .\src\Invoke-DangerousACLAudit.ps1
. .\src\Invoke-GPOSecurityAudit.ps1
. .\src\Invoke-VulnScan.ps1
. .\src\Find-SecurityFindings.ps1
. .\src\Build-PrivilegeGraph.ps1
. .\src\Invoke-RiskScoring.ps1
. .\src\Export-Results.ps1
Write-Host "All modules loaded" -ForegroundColor Green
Write-Host ""

# Run all tests
Write-Host "[1/12] Enumerating Users..." -ForegroundColor Yellow
$users = Get-ADUsers -LdapEntry $LdapEntry -SearchBase $SearchBase
Write-Host "Found $($users.Count) users" -ForegroundColor Green
Write-Host ""

Write-Host "[2/12] Enumerating Computers..." -ForegroundColor Yellow
$computers = Get-ADComputers -LdapEntry $LdapEntry -SearchBase $SearchBase
Write-Host "Found $($computers.Count) computers" -ForegroundColor Green
Write-Host ""

Write-Host "[3/12] Enumerating Groups..." -ForegroundColor Yellow
$groups = Get-ADGroups -LdapEntry $LdapEntry -SearchBase $SearchBase
Write-Host "Found $($groups.Count) groups" -ForegroundColor Green
Write-Host ""

Write-Host "[4/12] Enumerating OUs..." -ForegroundColor Yellow
$ous = Get-ADOUs -LdapEntry $LdapEntry -SearchBase $SearchBase
Write-Host "Found $($ous.Count) OUs" -ForegroundColor Green
Write-Host ""

Write-Host "[5/12] Enumerating SPNs..." -ForegroundColor Yellow
$spns = Get-KerberoastableAccounts -LdapEntry $LdapEntry -SearchBase $SearchBase
Write-Host "Found $($spns.Count) SPNs" -ForegroundColor Green
Write-Host ""

Write-Host "[6/12] Enumerating Trusts..." -ForegroundColor Yellow
$trusts = Get-ADTrusts -LdapEntry $LdapEntry -SearchBase $SearchBase
Write-Host "Found $($trusts.Count) trusts" -ForegroundColor Green
Write-Host ""

Write-Host "[7/12] Kerberoast Audit..." -ForegroundColor Yellow
$kerberoast = Invoke-KerberoastAudit -LdapEntry $LdapEntry -SearchBase $SearchBase
Write-Host "Found $($kerberoast.Count) kerberoastable accounts" -ForegroundColor Green
Write-Host ""

Write-Host "[8/12] AS-REP Roast Audit..." -ForegroundColor Yellow
$asrep = Invoke-ASREPRoastAudit -LdapEntry $LdapEntry -SearchBase $SearchBase
Write-Host "Found $($asrep.Count) AS-REP roastable accounts" -ForegroundColor Green
Write-Host ""

Write-Host "[9/12] Password Policy Audit..." -ForegroundColor Yellow
$pwPolicy = Get-PasswordPolicy -LdapEntry $LdapEntry -SearchBase $SearchBase
Write-Host "Completed" -ForegroundColor Green
Write-Host ""

Write-Host "[10/12] Dangerous ACL Audit..." -ForegroundColor Yellow
$dangerousACLs = Invoke-DangerousACLAudit -LdapEntry $LdapEntry -SearchBase $SearchBase
Write-Host "Found $($dangerousACLs.Count) issues" -ForegroundColor Green
Write-Host ""

Write-Host "[11/12] GPO Security Audit..." -ForegroundColor Yellow
$gpoAudit = Invoke-GPOSecurityAudit -LdapEntry $LdapEntry -SearchBase $SearchBase
Write-Host "Found $($gpoAudit.Count) GPO issues" -ForegroundColor Green
Write-Host ""

Write-Host "[12/12] Vulnerability Scan..." -ForegroundColor Yellow
$vulnScan = Invoke-VulnScan -LdapEntry $LdapEntry -SearchBase $SearchBase
Write-Host "Found $($vulnScan.Count) vulnerabilities" -ForegroundColor Green
Write-Host ""

# Consolidate results
$results = @{
    'Users' = $users
    'Computers' = $computers
    'Groups' = $groups
    'OUs' = $ous
    'SPNs' = $spns
    'Trusts' = $trusts
    'KerberoastAudit' = $kerberoast
    'ASREPRoastAudit' = $asrep
    'PasswordPolicy' = $pwPolicy
    'DangerousACLs' = $dangerousACLs
    'GPOAudit' = $gpoAudit
    'VulnScan' = $vulnScan
}

# Generate findings and report
Write-Host "[+] Generating Security Findings..." -ForegroundColor Yellow
$findings = Find-SecurityFindings -Results $results
Write-Host "Found $($findings.Count) security findings" -ForegroundColor Green
Write-Host ""

Write-Host "[+] Building Privilege Graph..." -ForegroundColor Yellow
$privGraph = Build-PrivilegeGraph -LdapEntry $LdapEntry -SearchBase $SearchBase
Write-Host "Generated privilege graph" -ForegroundColor Green
Write-Host ""

Write-Host "[+] Calculating Risk Scores..." -ForegroundColor Yellow
$riskScores = Invoke-RiskScoring -Findings $findings
Write-Host "Risk scores calculated" -ForegroundColor Green
Write-Host ""

# Export to HTML
$results['Findings'] = $findings
$results['RiskScores'] = $riskScores
$results['PrivilegeGraph'] = $privGraph

Write-Host "[+] Exporting HTML Report..." -ForegroundColor Yellow
Export-Results -Results $results -OutputPath ".\AD_Scan_Report.html"
Write-Host "Report saved to: AD_Scan_Report.html" -ForegroundColor Green
Write-Host ""

Write-Host "=== SCAN COMPLETE ===" -ForegroundColor Cyan
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Users: $($users.Count)" -ForegroundColor White
Write-Host "  Computers: $($computers.Count)" -ForegroundColor White
Write-Host "  Groups: $($groups.Count)" -ForegroundColor White
Write-Host "  Security Findings: $($findings.Count)" -ForegroundColor White
Write-Host "  Risk Score Issues: $($riskScores.Count)" -ForegroundColor White
