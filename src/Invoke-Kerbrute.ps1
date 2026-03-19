<#
.SYNOPSIS
    Wrap the Kerbrute binary for Kerberos-based username enumeration and
    password spraying.

.DESCRIPTION
    Mirrors the original Python script's Kerbrute integration.
    Auto-detects the binary from:
      1. -KerbrutePath parameter (user-supplied)
      2. .\src\kerbrute\kerbrute[.exe]  (bundled)
      3. PATH

    Parses Kerbrute stdout for VALID USERNAME / VALID LOGIN tokens and
    appends results to the scan's output files.
#>

function Resolve-KerbrutePath {
    param([string]$UserSuppliedPath = '')

    if ($UserSuppliedPath -and (Test-Path $UserSuppliedPath)) {
        return $UserSuppliedPath
    }

    # Check bundled location
    $ext       = if ($env:OS -match 'Windows' -or [System.Environment]::OSVersion.Platform -eq 'Win32NT') { '.exe' } else { '' }
    $bundled   = Join-Path $PSScriptRoot "..\src\kerbrute\kerbrute$ext"
    if (Test-Path $bundled) { return (Resolve-Path $bundled).Path }

    # Check PATH
    $onPath = Get-Command kerbrute -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }

    return $null
}

function Invoke-KerbruteOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BinaryPath,
        [Parameter(Mandatory)][ValidateSet('userenum','passwordspray')][string]$SubCommand,
        [string]$Domain,
        [string]$UserList,
        [string]$Password,
        [switch]$Safe,
        [string]$OutputDir = '.\output'
    )

    if (-not (Test-Path $BinaryPath)) {
        Write-Host "[-] Kerbrute binary not found at: $BinaryPath"
        return
    }

    $null = New-Item -ItemType Directory -Force -Path $OutputDir

    $args_ = @($SubCommand, '--domain', $Domain)

    switch ($SubCommand) {
        'userenum' {
            if (-not $UserList) { Write-Host "[-] -UserList required for userenum"; return }
            $args_ += '--users', $UserList
        }
        'passwordspray' {
            if (-not $UserList -or -not $Password) {
                Write-Host "[-] -UserList and -KerbrutePassword required for passwordspray"
                return
            }
            $args_ += '--users', $UserList, '--password', $Password
        }
    }

    if ($Safe) { $args_ += '--safe' }

    Write-Host "[*] Launching: $BinaryPath $($args_ -join ' ')"

    $validResults = @()

    $found = $null
    try {
        & $BinaryPath @args_ 2>&1 | ForEach-Object {
            $line = "$_"
            Write-Host "    $line"

            # Parse known Kerbrute output tokens
            if ($line -match 'VALID USERNAME:\s*(\S+)') {
                $validResults += [PSCustomObject]@{
                    Source   = 'kerbrute'
                    Type     = 'ValidUsername'
                    Value    = $Matches[1]
                    Detail   = $line.Trim()
                }
                Write-Host "  [+] VALID: $($Matches[1])"
            }
            elseif ($line -match 'VALID LOGIN:\s*(\S+)') {
                $validResults += [PSCustomObject]@{
                    Source   = 'kerbrute'
                    Type     = 'ValidLogin'
                    Value    = $Matches[1]
                    Detail   = $line.Trim()
                }
                Write-Host "  [!!!] VALID LOGIN: $($Matches[1])"
            }
        }
    }
    catch {
        Write-Host "[-] Kerbrute execution error: $_"
    }

    if ($validResults.Count -gt 0) {
        $outCsv = Join-Path $OutputDir "kerbrute_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $validResults | Export-Csv -Path $outCsv -NoTypeInformation
        Write-Host "[+] Kerbrute results saved to: $outCsv"
    }
    else {
        Write-Host "[i] No valid usernames/logins found by Kerbrute."
    }

    return $validResults
}
