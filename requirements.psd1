#Requires -Version 5.1
<#
================================================================================
  requirements.psd1 - PowerShell Dependency Manifest
  Quick-AD-Scan (PowerShell Edition)
================================================================================

  PowerShell equivalent of Python's requirements.txt.

  BUILT-IN (.NET / PowerShell standard - no installation needed):
    - System.DirectoryServices          - LDAP queries, DirectoryEntry/Searcher
    - System.DirectoryServices.AccountManagement - optional (not used by default)
    - System.Net.Sockets                - TCP port checks in VulnScan
    - System.Web.HttpUtility            - HTML encoding in report
    - Microsoft.PowerShell.Utility      - ConvertTo-Json, Export-Csv, etc.

  OPTIONAL RSAT MODULE (enables richer AD cmdlets if available):
    - ActiveDirectory  (part of Windows RSAT)
    - Install via:  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory*
    - Or Group Policy / DISM on domain-joined machines.

  THIRD-PARTY BINARY (optional, for Kerbrute integration):
    - kerbrute  - https://github.com/ropnop/kerbrute/releases
    - Place at:  .\src\kerbrute\kerbrute.exe  (Windows)
                 .\src\kerbrute\kerbrute      (Linux / macOS)
    - Or pass:   -KerbrutePath <full-path>

  POWERSHELL VERSION:
    - Minimum : Windows PowerShell 5.1
    - Recommended : PowerShell 7+ (cross-platform, faster, better JSON support)

  PERMISSIONS:
    - Domain user (read-only) is sufficient for all enumeration features.
    - No elevation or special privileges required.
    - Some password policy fields may require Domain Admin to fully read.

================================================================================
  QUICK SETUP
================================================================================

  1. Run PowerShell as any domain user (no admin needed for enumeration).
  2. Optional - install RSAT for richer output:
        Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
  3. Optional - place kerbrute binary:
        .\src\kerbrute\kerbrute.exe
  4. Run the scan:
        .\main.ps1

================================================================================
#>

@{
    # Minimum PowerShell version required
    PowerShellVersion = '5.1'

    # All functionality works without these - they are purely optional enhancements
    OptionalModules = @(
        @{
            ModuleName    = 'ActiveDirectory'
            Description   = 'Windows RSAT module for richer AD cmdlets'
            InstallHint   = 'Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
            Required      = $false
        }
    )

    # .NET assemblies - always available, listed for documentation
    RequiredAssemblies = @(
        'System.DirectoryServices'
        'System.DirectoryServices.AccountManagement'
        'System.Net.Sockets'
        'System.Web'
    )

    # External binaries (optional)
    OptionalBinaries = @(
        @{
            Name        = 'kerbrute'
            Description = 'Kerberos username enumeration and password spraying'
            URL         = 'https://github.com/ropnop/kerbrute/releases'
            PlacedAt    = '.\src\kerbrute\kerbrute[.exe]'
            Required    = $false
        }
    )
}
