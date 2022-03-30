<#
.SYNOPSIS
Uninstall the CrowdStrike Falcon Sensor for Windows
.DESCRIPTION
Uninstalls the CrowdStrike Falcon Sensor for Windows. By default, once complete, the script
deletes itself and the downloaded uninstaller package (if necessary). The individual steps and any related error messages
are logged to 'Windows\Temp\csfalcon_uninstall.log' unless otherwise specified.

Script options can be passed as parameters or defined in the param() block. Default values are listed in
the parameter descriptions.

The script must be run as an administrator on the local machine in order for the Falcon Sensor to
uninstall.
.PARAMETER MaintenanceToken
Sensor uninstall maintenance token ['https://api.crowdstrike.com' if left undefined]
.PARAMETER UninstallParams
Sensor uninstall parameters ['/uninstall /quiet' if left undefined]
.PARAMETER UninstallTool
Sensor uninstall tool, local installation cache or CS standalone uninstaller ['installcache' if left undefined]
.PARAMETER LogPath
Script log location ['Windows\Temp\csfalcon_uninstall.log' if left undefined]
.PARAMETER DeleteUninstaller
Delete sensor uninstaller package when complete [default: $true]
.PARAMETER DeleteScript
Delete script when complete [default: $true]
.EXAMPLE
PS>.\falcon_windows_uninstall.ps1 -MaintenanceToken <string>

All parameters will use their default values.
.EXAMPLE
PS>.\falcon_windows_uninstall.ps1

Run the script and use all values that were previously defined within the script.
#>
[CmdletBinding()]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'DeleteUninstaller')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'DeleteScript')]
param(
    [Parameter(Position = 1)]
    [string] $MaintenanceToken,

    [Parameter(Position = 2)]
    [string] $UninstallParams = '/uninstall /quiet',

    [Parameter(Position = 3)]
    [ValidateSet('installcache', 'standalone')]
    [string] $UninstallTool = 'cache',

    [Parameter(Position = 4)]
    [string] $LogPath,

    [Parameter(Position = 5)]
    [bool] $DeleteUninstaller = $true,

    [Parameter(Position = 6)]
    [bool] $DeleteScript = $true
)
begin {
    $ScriptName = $MyInvocation.MyCommand.Name
    $ScriptPath = if (!$PSScriptRoot) {
        Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
    } else {
        $PSScriptRoot
    }

    if ($MaintenanceToken) {
        $UninstallParams += " MAINTENANCE_TOKEN=$MaintenanceToken"
    }

    if ($UninstallTool -match "installcache") {
        $UninstallerName = 'WindowsSensor*.exe'
        $UninstallerCachePath = "C:\ProgramData\Package Cache"
        $UninstallerPath = Get-ChildItem -Include $UninstallerName -Path $UninstallerCachePath -Recurse | ForEach-Object{$_.FullName}
    }

    if ($UninstallTool -match "standalone") {
        $UninstallerName = 'CsUninstallTool.exe'
        $UninstallerPath = Join-Path -Path $PSScriptRoot -ChildPath $UninstallerName
    }

    $WinSystem = [Environment]::GetFolderPath('System')
    $WinTemp = $WinSystem -replace 'system32','Temp'
    if (!$LogPath) {
        $LogPath = Join-Path -Path $WinTemp -ChildPath 'csfalcon_uninstall.log'
    }

    function Write-FalconLog ([string] $Source, [string] $Message) {
        $Content = @(Get-Date -Format 'yyyy-MM-dd hh:MM:ss')
        "$(@($Content + $Source) -join ' '): $Message" >> $LogPath
    }
}
process {
    if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) {
        $Message = 'Unable to proceed without administrative privileges'
        throw $Message
    }

    $AgentService = Get-Service -Name CSAgent -ErrorAction SilentlyContinue
    if (!$AgentService) {
        $Message = "'CSFalconService' is not installed"
        Write-FalconLog 'CheckService' $Message
        throw $Message
    }

    if (-not (Test-Path -Path $UninstallerPath))
    {
        $Message = "${UninstallerName} not found."
        Write-FalconLog 'CheckUninstaller' $Message
        throw $Message
    }

    $Message = 'Uninstalling Falcon Sensor...'
    Write-FalconLog 'Uninstaller' $Message
    Write-Output $Message

    $UninstallerProcess = Start-Process -FilePath "$UninstallerPath" -ArgumentList $UninstallParams -PassThru -Wait
    $UninstallerProcessId = $UninstallerProcess.Id
    Write-FalconLog 'StartProcess' "Started '$UninstallerPath' ($UninstallerProcessId)"
    if ($UninstallerProcess.ExitCode -ne 0)
    {
        $Message = "Uninstaller returned exit code $($UninstallerProcess.ExitCode)"
        Write-FalconLog "UninstallError" $Message
        throw $Message
    }

    $AgentService = Get-Service -Name CSAgent -ErrorAction SilentlyContinue
    if ($AgentService -and $AgentService.Status -eq 'Running')
    {
        $Message = 'Service uninstall failed...'
        Write-FalconLog "ServiceError" $Message
        throw $Message
    }

    if (Test-Path -Path HKLM:\System\Crowdstrike)
    {
        $Message = 'Registry key removal failed...'
        Write-FalconLog "RegistryError" $Message
        throw $Message
    }

    if (Test-Path -Path"${env:SYSTEMROOT}\System32\drivers\CrowdStrike")
    {
        $Message = 'Driver removal failed...'
        Write-FalconLog "DriverError" $Message
        throw $Message
    }

    @('DeleteUninstaller', 'DeleteScript') | ForEach-Object {
        if ((Get-Variable $_).Value -eq $true) {
            $FilePath = if ($_ -eq 'DeleteUninstaller') {
                "$UninstallerPath"
            } else {
                Join-Path -Path $ScriptPath -ChildPath $ScriptName
            }
            if (Test-Path $FilePath) {
                Remove-Item -Path $FilePath -Force
            }
            if (Test-Path $FilePath) {
                Write-FalconLog $_ "Failed to delete '$FilePath'"
            } else {
                Write-FalconLog $_ "Deleted '$FilePath'"
            }
        }
    }

    $Message = 'Successfully finished uninstall...'
    Write-FalconLog 'Uninstaller' $Message
    Write-Output $Message
}
