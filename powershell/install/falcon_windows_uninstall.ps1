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
.PARAMETER RemoveHost
Remove host from CrowdStrike Falcon [default: $false]
.PARAMETER FalconCloud
CrowdStrike Falcon OAuth2 API Hostname [default: autodiscover]
.PARAMETER FalconClientId
CrowdStrike Falcon OAuth2 API Client Id [Required if RemoveHost is $true]
.PARAMETER FalconClientSecret
CrowdStrike Falcon OAuth2 API Client Secret [Required if RemoveHost is $true]
.PARAMETER MemberCid
Member CID, used only in multi-CID ("Falcon Flight Control") configurations and with a parent management CID.
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
    [string] $UninstallTool = 'installcache',

    [Parameter(Position = 4)]
    [string] $LogPath,

    [Parameter(Position = 5)]
    [bool] $DeleteUninstaller = $true,

    [Parameter(Position = 6)]
    [bool] $DeleteScript = $true,

    [Parameter(Position = 7)]
    [bool] $RemoveHost = $false,

    [Parameter(Position = 8)]
    [ValidateSet('autodiscover', 'us-1', 'us-2', 'eu-1', 'us-gov-1')]
    [string] $FalconCloud = 'autodiscover',

    [Parameter(Position = 9)]
    [string] $FalconClientId,

    [Parameter(Position = 10)]
    [string] $FalconClientSecret,

    [Parameter(Position = 11)]
    [string] $MemberCid

)
begin {
    $ScriptName = $MyInvocation.MyCommand.Name
    $ScriptPath = if (!$PSScriptRoot) {
        Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
    }
    else {
        $PSScriptRoot
    }

    function Write-FalconLog ([string] $Source, [string] $Message) {
        $Content = @(Get-Date -Format 'yyyy-MM-dd hh:MM:ss')
        "$(@($Content + $Source) -join ' '): $Message" >> $LogPath
    }

    function Get-FalconCloud ([string] $xCsRegion) {
        $Output = switch ($xCsRegion) {
            'autodiscover' { 'https://api.crowdstrike.com'; break }
            'us-1' { 'https://api.crowdstrike.com'; break }
            'us-2' { 'https://api.us-2.crowdstrike.com'; break }
            'eu-1' { 'https://api.eu-1.crowdstrike.com'; break }
            'us-gov-1' { 'https://api.laggar.gcw.crowdstrike.com'; break }
            default { throw "Provided region $xCsRegion is invalid. Please set FalconCloud to a valid region or 'autodiscover'"; break }
        }
        return $Output
    }

    function Invoke-FalconAuth([string] $BaseUrl, [hashtable] $Body, [string] $FalconCloud) {
        $Headers = @{'Accept' = 'application/json'; 'Content-Type' = 'application/x-www-form-urlencoded'; 'charset' = 'utf-8' }

        try {
            $response = Invoke-WebRequest -Uri "$($BaseUrl)/oauth2/token" -UseBasicParsing -Method 'POST' -Headers $Headers -Body $Body -MaximumRedirection 0
            $content = ConvertFrom-Json -InputObject $response.Content
            $Headers.Add('Authorization', "bearer $($content.access_token)")
        }
        catch {
            # Handle redirects
            $response = $_.Exception.Response

            if (!$response) {
                $Message = "Unhandled error occurred while authenticating to the CrowdStrike Falcon API. Error: $($_.Exception.Message)"
                throw $Message
            }

            if ($response.StatusCode -in @(301, 302, 303, 307, 308)) {
                # If autodiscover is enabled, try to get the correct cloud
                if ($FalconCloud -eq 'autodiscover') {
                    if ($response.Headers.Contains('X-Cs-Region')) {
                        $region = $response.Headers.GetValues('X-Cs-Region')[0]
                    }
                    else {
                        $Message = "Received a redirect but no X-Cs-Region header was provided. Unable to autodiscover the FalconCloud. Please set FalconCloud to the correct region."
                        throw $Message
                    }

                    $BaseUrl = Get-FalconCloud($region)
                    $BaseUrl, $Headers = Invoke-FalconAuth $BaseUrl $Body $FalconCloud
                }
                else {
                    $Message = "Received a redirect. Please set FalconCloud to 'autodiscover' or the correct region."
                    throw $Message
                }
            }
            else {
                $Message = "Received a $($response.StatusCode) response from $($BaseUrl)oauth2/token. Please check your credentials and try again. Error: $($response.StatusDescription)"
                throw $Message
            }
        }

        return $BaseUrl, $Headers
    }

    function Test-FalconCredentials([string] $FalconClientId , [string] $FalconClientSecret ) {
        if ($FalconClientId -and $FalconClientSecret) {
            return $true
        }
        else {
            return $false
        }
    }

    function Get-AID {
        $reg_paths = 'HKLM:\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default', 'HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim'
        $aid = $null
        foreach ($path in $reg_paths) {
            try {
                $agItemProperty = Get-ItemProperty -Path $path -Name AG -ErrorAction Stop
                $aid = [System.BitConverter]::ToString( ($agItemProperty.AG)).ToLower() -replace '-', ''
                break
            }
            catch {
                $Message = "Unable to find AID in registry path: $path"
                Write-FalconLog 'AID' $Message
            }
        }
        if (!$aid) {
            $Message = "Unable to find AID in registry"
        }
        else {
            $Message = "Found AID: $aid"
        }

        Write-FalconLog 'AID' $Message
        return $aid
    }

    if ($MaintenanceToken) {
        $UninstallParams += " MAINTENANCE_TOKEN=$MaintenanceToken"
    }

    if ($UninstallTool -match "installcache") {
        $UninstallerName = 'WindowsSensor*.exe'
        $UninstallerCachePath = "C:\ProgramData\Package Cache"
        $UninstallerPath = Get-ChildItem -Include $UninstallerName -Path $UninstallerCachePath -Recurse | ForEach-Object { $_.FullName }
    }

    if ($UninstallTool -match "standalone") {
        $UninstallerName = 'CsUninstallTool.exe'
        $UninstallerPath = Join-Path -Path $PSScriptRoot -ChildPath $UninstallerName
    }

    $WinSystem = [Environment]::GetFolderPath('System')
    $WinTemp = $WinSystem -replace 'system32', 'Temp'
    if (!$LogPath) {
        $LogPath = Join-Path -Path $WinTemp -ChildPath 'csfalcon_uninstall.log'
    }
}
process {
    if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) {
        $Message = 'Unable to proceed without administrative privileges'
        throw $Message
    }

    # Verify creds are provided if using the API
    $credsProvided = Test-FalconCredentials $FalconClientId $FalconClientSecret
    if (!$credsProvided) {
        if ($RemoveHost) {
            $Message = 'Unable to remove host without credentials, please provide FalconClientId and FalconClientSecret'
            throw $Message
        }
    } else {
        # Grab AID before uninstalling
        $aid = Get-AID
    }


    if ($credsProvided) {
        $Headers = @{'Accept' = 'application/json'; 'Content-Type' = 'application/x-www-form-urlencoded'; 'charset' = 'utf-8' }
        $BaseUrl = Get-FalconCloud $FalconCloud


        $Body = @{}
        $Body["client_id"] = $FalconClientId
        $Body["client_secret"] = $FalconClientSecret

        if ($MemberCid) {
            $Body["&member_cid"] = $MemberCid
        }

        $BaseUrl, $Headers = Invoke-FalconAuth $BaseUrl $Body $FalconCloud
        $Headers['Content-Type'] = 'application/json'
    }
    


    $AgentService = Get-Service -Name CSAgent -ErrorAction SilentlyContinue
    if (!$AgentService) {
        $Message = "'CSFalconService' is not installed"
        Write-FalconLog 'CheckService' $Message
        throw $Message
    }

    if (-not (Test-Path -Path $UninstallerPath)) {
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
    if ($UninstallerProcess.ExitCode -ne 0) {
        if ($UninstallerProcess.ExitCode -eq 106) {
            $Message = 'Unable to uninstall, Falcon Sensor is protected with a maintenance token. Provide a valid maintenance token and try again.'
        }
        else {
            $Message = "Uninstaller returned exit code $($UninstallerProcess.ExitCode)"
        }
        Write-FalconLog "UninstallError" $Message
        throw $Message
    }

    $AgentService = Get-Service -Name CSAgent -ErrorAction SilentlyContinue
    if ($AgentService -and $AgentService.Status -eq 'Running') {
        $Message = 'Service uninstall failed...'
        Write-FalconLog "ServiceError" $Message
        throw $Message
    }

    if (Test-Path -Path HKLM:\System\Crowdstrike) {
        $Message = 'Registry key removal failed...'
        Write-FalconLog "RegistryError" $Message
        throw $Message
    }

    if (Test-Path -Path"${env:SYSTEMROOT}\System32\drivers\CrowdStrike") {
        $Message = 'Driver removal failed...'
        Write-FalconLog "DriverError" $Message
        throw $Message
    }

    @('DeleteUninstaller', 'DeleteScript') | ForEach-Object {
        if ((Get-Variable $_).Value -eq $true) {
            $FilePath = if ($_ -eq 'DeleteUninstaller') {
                "$UninstallerPath"
            }
            else {
                Join-Path -Path $ScriptPath -ChildPath $ScriptName
            }
            if (Test-Path $FilePath) {
                Remove-Item -Path $FilePath -Force
            }
            if (Test-Path $FilePath) {
                Write-FalconLog $_ "Failed to delete '$FilePath'"
            }
            else {
                Write-FalconLog $_ "Deleted '$FilePath'"
            }
        }
    }

    $Message = 'Successfully finished uninstall...'
    Write-FalconLog 'Uninstaller' $Message
    Write-Output $Message
}
end {
    Write-Output 'Script complete'
}
