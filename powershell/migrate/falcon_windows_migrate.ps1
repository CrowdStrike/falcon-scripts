<#
.SYNOPSIS
Migrate a sensor to another falcon cloud tenant.
.DESCRIPTION
Removes and installs the sensor using the new cloud and CID.

Falcon and Sensor tags are migrated to the new installation.
.PARAMETER NewFalconClientId
CrowdStrike Falcon OAuth2 API Client Id for the new Cloud [Required]
.PARAMETER NewFalconClientSecret
CrowdStrike Falcon OAuth2 API Client Secret for the new Cloud [Required]
.PARAMETER OldFalconClientId
CrowdStrike Falcon OAuth2 API Client Id for the old cloud [Required]
.PARAMETER OldFalconClientSecret
CrowdStrike Falcon OAuth2 API Client Secret for the old cloud [Required]
.PARAMETER NewFalconCloud
CrowdStrike Falcon OAuth2 API Hostname for the new cloud [default: 'autodiscover']
.PARAMETER OldFalconCloud
CrowdStrike Falcon OAuth2 API Hostname for the old cloud [default: 'autodiscover']
.PARAMETER NewFalconCid
Manually specify CrowdStrike Customer ID (CID) for the new cloud [default: $null]
.PARAMETER NewMemberCid
Member CID, used only in multi-CID ("Falcon Flight Control") configurations and with a parent management CID for the new cloud.
.PARAMETER OldMemberCid
Member CID, used only in multi-CID ("Falcon Flight Control") configurations and with a parent management CID for the old cloud.
.PARAMETER SensorUpdatePolicyName
Sensor Update Policy name to check for assigned sensor version [default: 'platform_default']
.PARAMETER InstallParams
Sensor installation parameters, without your CID value ['/install /quiet /noreboot' if left undefined]
.PARAMETER LogPath
Script log location ['Windows\Temp\csfalcon_migration_yyyy-MM-dd_HH-mm-ss.log' if left undefined]
.PARAMETER DeleteInstaller
Delete sensor installer package when complete [default: $true]
.PARAMETER DeleteUninstaller
Delete sensor uninstaller package when complete [default: $true]
.PARAMETER DeleteScript
Delete script when complete [default: $false]
.PARAMETER ProvToken
Provisioning token to use for sensor installation [default: $null]
.PARAMETER ProvWaitTime
Time to wait, in seconds, for sensor to provision [default: 1200]
.PARAMETER Tags
A comma-separated list of sensor grouping tags to apply to the host in addition to any pre-existing tags [default: $null]
.PARAMETER FalconTags
A comma-separated list of falcon grouping tags to apply to the host in addition to any pre-existing tags [default: $null]
.PARAMETER MaintenanceToken
Sensor uninstall maintenance token. If left undefined, the script will attempt to retrieve the token from the API assuming the FalconClientId|FalconClientSecret are defined.
.PARAMETER UninstallParams
Sensor uninstall parameters ['/uninstall /quiet' if left undefined]
.PARAMETER UninstallTool
Sensor uninstall tool, local installation cache or CS standalone uninstaller ['installcache' if left undefined]
.PARAMETER RemoveHost
Remove host from CrowdStrike Falcon
.PARAMETER SkipTags
Opt in/out of migrating tags. Tags passed to the Tags flag will still be added.
.PARAMETER Verbose
Enable verbose logging
#>
#Requires -Version 3.0

[CmdletBinding()]
param(
    [Parameter(Position = 1)]
    [ValidatePattern('\w{32}')]
    [string] $NewFalconClientId,
    [Parameter(Position = 2)]
    [ValidatePattern('\w{40}')]
    [string] $NewFalconClientSecret,
    [Parameter(Position = 3)]
    [ValidateSet('autodiscover', 'us-1', 'us-2', 'eu-1', 'us-gov-1')]
    [string] $NewFalconCloud = 'autodiscover',
    [Parameter(Position = 4)]
    [string] $NewMemberCid,
    [Parameter(Position = 5)]
    [ValidatePattern('\w{32}')]
    [string] $OldFalconClientId,
    [Parameter(Position = 6)]
    [ValidatePattern('\w{40}')]
    [string] $OldFalconClientSecret,
    [Parameter(Position = 7)]
    [ValidateSet('autodiscover', 'us-1', 'us-2', 'eu-1', 'us-gov-1')]
    [string] $OldFalconCloud = 'autodiscover',
    [Parameter(Position = 8)]
    [string] $OldMemberCid,
    [Parameter(Position = 9 )]
    [string] $SensorUpdatePolicyName,
    [Parameter(Position = 10)]
    [string] $InstallParams,
    [Parameter(Position = 11)]
    [string] $LogPath,
    [Parameter(Position = 12)]
    [string] $ProvToken,
    [Parameter(Position = 13)]
    [int] $ProvWaitTime = 1200,
    [Parameter(Position = 14)]
    [string] $Tags = '',
    [Parameter(Position = 15)]
    [string] $FalconTags = '',
    [Parameter(Position = 16)]
    [string] $MaintenanceToken,
    [Parameter(Position = 17)]
    [switch] $RemoveHost,
    [Parameter(Position = 18)]
    [string] $UninstallParams = '/uninstall /quiet',
    [Parameter(Position = 19)]
    [ValidateSet('installcache', 'standalone')]
    [string] $UninstallTool = 'installcache',
    [Parameter(Position = 20)]
    [switch] $SkipTags,
    [Parameter(Position = 21)]
    [bool] $DeleteUninstaller = $true,
    [Parameter(Position = 22)]
    [bool] $DeleteInstaller = $true,
    [Parameter(Position = 23)]
    [bool] $DeleteScript = $false,
    [Parameter(Position = 24)]
    [ValidatePattern('\w{32}-\w{2}')]
    [string] $NewFalconCid
)


function Write-RecoveryCsv {
    param (
        [array] $SensorGroupingTags,
        [array] $FalconGroupingTags,
        [string] $OldAid,
        [string] $Path
    )

    $directory = Split-Path -Parent $Path
    if (!(Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }

    $data = @()
    $dataRow = [PSCustomObject]@{
        'OldAid'             = $OldAid
        'SensorGroupingTags' = ($SensorGroupingTags -join ',')
        'FalconGroupingTags' = ($FalconGroupingTags -join ',')
    }
    $data += $dataRow
    $data = $data | Select-Object * -ExcludeProperty PS*
    $data | Export-Csv -Path $Path -NoTypeInformation -Force

    if (Test-Path $Path) {
        Write-MigrateLog "Recovery CSV file successfully created at $Path"
    }
    else {
        Write-MigrateLog 'Error: Recovery CSV file could not be created'
    }
}


function Read-RecoveryCsv {
    param (
        [string] $Path
    )

    if (!(Test-Path $Path)) {
        Write-MigrateLog "Recovery CSV file not found at $Path"
        throw "Recovery CSV does not exist at path $Path"
    }

    $data = Import-Csv -Path $Path
    $data = $data | Select-Object * -ExcludeProperty PS*
    $data = $data | ConvertTo-Json -Compress
    $data = ConvertFrom-Json -InputObject $data

    $data.SensorGroupingTags = (Format-TagArray -Tags $data.SensorGroupingTags)
    $data.FalconGroupingTags = (Format-TagArray -Tags $data.FalconGroupingTags)

    return $data
}


function Compare-TagsDiff {
    param (
        [array] $Tags,
        [array] $TagList
    )

    $Tags = $Tags -split ','

    if ($null -eq $TagList -or $TagList.Length -eq 0) {
        return $Tags
    }

    $tagsDiff = $Tags | Where-Object { $TagList -notcontains $_ }
    return $tagsDiff
}


function Format-TagArray {
    param (
        [string] $Tags,
        [string] $Seperator = ','
    )

    if ($Tags -eq '') {
        return @()
    }

    return $Tags -split $Seperator
}


function Write-MigrateLog {
    param (
        [string] $Message,
        [bool] $Stdout = $true
    )

    $logTimeStamp = @(Get-Date -Format 'yyyy-MM-dd hh:MM:ss')

    "$($logTimeStamp): $Message" | Out-File -FilePath $LogPath -Append -Encoding utf8

    if ($Stdout) {
        Write-Output $Message
    }
}

function Write-VerboseLog ([psobject] $VerboseInput, [string] $PreMessage) {

    # Determine if the input is a string or an object
    if ($VerboseInput -is [string]) {
        $message = $VerboseInput
    }
    else {
        $message = $VerboseInput | ConvertTo-Json -Depth 10
    }

    # If a pre message is provided, add it to the beginning of the message
    if ($PreMessage) {
        $message = "$PreMessage`r`n$message"
    }

    # Write Verbose
    Write-Verbose $message

    # Write to log file, but not Stdout
    Write-MigrateLog -Message $message -Stdout $false
}


# Uninstall Falcon Sensor
function Invoke-FalconUninstall ([string] $UninstallParams, [switch] $RemoveHost, [bool] $DeleteUninstaller, [string] $MaintenanceToken, [string] $UninstallTool) {
    try {
        $AgentService = Get-Service -Name CSAgent -ErrorAction SilentlyContinue
        if (!$AgentService) {
            $Message = "'CSFalconService' service not found, already uninstalled"
            Write-MigrateLog $Message
            return
        }

        $UninstallerPath = $null
        switch ($UninstallTool) {
            'installcache' {
                $UninstallerName = 'WindowsSensor*.exe'
                $UninstallerPathDir = 'C:\ProgramData\Package Cache'

                if (Test-Path -Path $UninstallerPathDir) {
                    $UninstallerPath = Get-ChildItem -Include $UninstallerName -Path $UninstallerPathDir -Recurse | ForEach-Object { $_.FullName } | Sort-Object -Descending | Select-Object -First 1
                }
                else {
                    $UninstallerPath = $null
                }
            }
            Default {
                $UninstallerName = 'CsUninstallTool.exe'
                $UninstallerPath = Join-Path -Path $PSScriptRoot -ChildPath $UninstallerName
            }
        }

        if (!$UninstallerPath -or (-not (Test-Path -Path $UninstallerPath))) {
            $Message = "${UninstallerName} not found. Unable to uninstall without the cached uninstaller or the standalone uninstaller."
            Write-MigrateLog $Message
            throw $Message
        }

        # If $oldBaseUrl and $oldCloudHeaders are null, then call the Get-HeadersAndUrl function again. Could be due to recovery mode.
        if (!$oldBaseUrl -or !$oldCloudHeaders) {
            $oldBaseUrl, $oldCloudHeaders = Get-HeadersAndUrl -FalconClientId $OldFalconClientId -FalconClientSecret $OldFalconClientSecret -FalconCloud $OldFalconCloud -MemberCid $OldMemberCid
        }

        if ($RemoveHost) {
            Write-MigrateLog 'Removing host from Falcon console'
            Invoke-HostVisibility -Aid $oldAid -action 'hide'
        }

        if ($MaintenanceToken) {
            # Assume the maintenance token is a valid Token and skip API calls
            $UninstallParams += " MAINTENANCE_TOKEN=$MaintenanceToken"
        }
        else {
            if ($oldAid) {
                # Assume user wants to use API to retrieve token
                # Build request body for retrieving maintenance token
                Write-MigrateLog 'Retrieving maintenance token from the CrowdStrike Falcon API.'
                $Body = @{
                    'device_id'     = $oldAid
                    'audit_message' = 'CrowdStrike Falcon Uninstall Powershell Script'
                }

                $bodyJson = $Body | ConvertTo-Json

                try {
                    $url = "${oldBaseUrl}/policy/combined/reveal-uninstall-token/v1"

                    $oldCloudHeaders['Content-Type'] = 'application/json'
                    $response = Invoke-WebRequest -Uri $url -UseBasicParsing -Method 'POST' -Headers $oldCloudHeaders -Body $bodyJson -MaximumRedirection 0
                    $content = ConvertFrom-Json -InputObject $response.Content
                    Write-VerboseLog -VerboseInput $content -PreMessage 'GetToken - $content:'

                    if ($content.errors) {
                        $Message = 'Failed to retrieve maintenance token: '
                        $Message += Format-FalconResponseError -errors $content.errors
                        Write-MigrateLog $Message
                        throw $Message
                    }
                    else {
                        $MaintenanceToken = $content.resources[0].uninstall_token
                        Write-MigrateLog "Retrieved maintenance token: $MaintenanceToken"
                        $UninstallParams += " MAINTENANCE_TOKEN=$MaintenanceToken"
                    }
                }
                catch {
                    Write-VerboseLog -VerboseInput $_.Exception -PreMessage 'GetToken - CAUGHT EXCEPTION - $_.Exception:'
                    $response = $_.Exception.Response

                    if (!$response) {
                        $Message = "Unhandled error occurred while retrieving maintenance token from the CrowdStrike Falcon API. Error: $($_.Exception.Message)"
                        Write-MigrateLog $Message
                        throw $Message
                    }

                    if ($response.StatusCode -eq 403) {
                        $scope = @{
                            'Sensor update policies' = @('Write')
                        }

                        $Message = Format-403Error -url $url -scope $scope

                        Write-MigrateLog $Message
                        throw $Message
                    }
                    else {
                        $Message = "Received a $($response.StatusCode) response from $($baseUrl)$($url) Error: $($response.StatusDescription)"
                        Write-MigrateLog $Message
                        throw $Message
                    }
                }
            }
        }

        # Begin uninstallation
        Write-MigrateLog 'Uninstalling Falcon Sensor...'
        Write-MigrateLog "Starting uninstaller with parameters: '$UninstallParams'"
        $UninstallerProcess = Start-Process -FilePath "$UninstallerPath" -ArgumentList $UninstallParams -PassThru -Wait
        $UninstallerProcessId = $UninstallerProcess.Id
        Write-MigrateLog "Started '$UninstallerPath' ($UninstallerProcessId)"
        if ($UninstallerProcess.ExitCode -ne 0) {
            Write-VerboseLog -VerboseInput $UninstallerProcess -PreMessage 'PROCESS EXIT CODE ERROR - $UninstallerProcess:'
            if ($UninstallerProcess.ExitCode -eq 106) {
                $Message = 'Unable to uninstall, Falcon Sensor is protected with a maintenance token. Provide a valid maintenance token and try again.'
            }
            else {
                $Message = "Uninstaller returned exit code $($UninstallerProcess.ExitCode)"
            }
            Write-MigrateLog $Message

            if ($RemoveHost) {
                $Message = 'Uninstall failed, attempting to restore host visibility...'
                Write-MigrateLog $Message
                Invoke-HostVisibility -Aid $oldAid -action 'show'
            }
            throw $Message
        }

        $AgentService = Get-Service -Name CSAgent -ErrorAction SilentlyContinue
        if ($AgentService -and $AgentService.Status -eq 'Running') {
            $Message = 'Service uninstall failed...'
            Write-MigrateLog $Message
            throw $Message
        }

        if (Test-Path -Path HKLM:\System\Crowdstrike) {
            $Message = 'Registry key removal failed...'
            Write-MigrateLog $Message
            throw $Message
        }

        if (Test-Path -Path"${env:SYSTEMROOT}\System32\drivers\CrowdStrike") {
            $Message = 'Driver removal failed...'
            Write-MigrateLog $Message
            throw $Message
        }

        # Delete the uninstaller
        if ($DeleteUninstaller) {
            if (Test-Path $UninstallerPath) {
                Remove-Item -Path $UninstallerPath -Force
            }
            if (Test-Path $UninstallerPath) {
                $Message = "Failed to delete '$UninstallerPath'"
                Write-MigrateLog $Message
                throw $Message
            }
            else {
                Write-MigrateLog "Deleted '$UninstallerPath'"
            }
        } else {
            Write-MigrateLog "Skipping deletion of '$UninstallerPath'"
        }

        Write-MigrateLog 'Falcon Sensor successfully uninstalled.'
    }
    catch {
        Write-VerboseLog -VerboseInput $_.Exception -PreMessage 'Invoke-FalconUninstall - CAUGHT EXCEPTION - $_.Exception:'
        $message = "Error uninstalling Falcon Sensor: $($_.Exception.Message)"
        throw $message
    }
}


# Install Falcon Sensor
function Invoke-FalconInstall ([string] $InstallParams, [string] $Tags, [bool] $DeleteInstaller, [string] $SensorUpdatePolicyName, [string] $ProvToken, [int] $ProvWaitTime, [string] $NewFalconCid) {
    $newBaseUrl, $newCloudHeaders = Get-HeadersAndUrl -FalconClientId $NewFalconClientId -FalconClientSecret $NewFalconClientSecret -FalconCloud $NewFalconCloud -MemberCid $NewMemberCid
    $Falcon = New-Object System.Net.WebClient
    $Falcon.Encoding = [System.Text.Encoding]::UTF8
    $Falcon.BaseAddress = $newBaseUrl
    $newCloudHeaders.Keys | ForEach-Object {
        $Falcon.Headers.Add($_, $newCloudHeaders[$_])
    }

    $Patterns = @{
        access_token = '"(?<name>access_token)": "(?<access_token>.*)",'
        build        = '"(?<name>build)": "(?<version>.+)",'
        ccid         = '(?<ccid>\w{32}-\w{2})'
        csregion     = '(?<name>X-Cs-Region): ([a-z0-9\-]+)'
        major_minor  = '"(?<name>sensor_version)": "(?<version>\d{1,}\.\d{1,})\.\d+",'
        policy_id    = '"(?<name>id)": "(?<id>\w{32})",'
        version      = '"(?<name>sensor_version)": "(?<version>.+)",'
    }
    try {
        if (!$SensorUpdatePolicyName) {
            $SensorUpdatePolicyName = 'platform_default'
        }
        if (!$InstallParams) {
            $InstallParams = '/install /quiet /noreboot'
        }

        # Main install logic
        if (Get-Service | Where-Object { $_.Name -eq 'CSFalconService' }) {
            $Message = "'CSFalconService' running. Falcon sensor is already installed."
            Write-MigrateLog $Message
            break
        }
        else {
            if ([Net.ServicePointManager]::SecurityProtocol -notmatch 'Tls12') {
                try {
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                }
                catch {
                    $Message = $_
                    Write-MigrateLog $Message
                    throw $Message
                }
            }
            if (!($PSVersionTable.CLRVersion.ToString() -ge 3.5)) {
                $Message = '.NET Framework 3.5 or newer is required'
                Write-MigrateLog $Message
                throw $Message
            }
        }

        # If NewFalconCid is not provided, get it from the API
        if (!$NewFalconCid) {
            $Response = Invoke-FalconGet '/sensors/queries/installers/ccid/v1'
            if ($Response -match $Patterns.ccid) {
                $Ccid = [regex]::Matches($Response, $Patterns.ccid)[0].Groups['ccid'].Value
                $Message = "Retrieved CCID: $Ccid"
                Write-MigrateLog $Message
                $InstallParams += " CID=$Ccid"
            }
            else {
                $Message = 'Failed to retrieve CCID'
                Write-MigrateLog $Message
                throw $Message
            }
        } else {
            $Message = "Using provided CCID: $NewFalconCid"
            Write-MigrateLog $Message
            $InstallParams += " CID=$NewFalconCid"
        }

        # Get sensor version from policy
        $message = "Retrieving sensor policy details for '$($SensorUpdatePolicyName)'"
        Write-MigrateLog $message
        $Response = Invoke-FalconGet ("/policy/combined/sensor-update/v2?filter=platform_name:" +
            "'Windows'%2Bname:'$($SensorUpdatePolicyName.ToLower())'")
        $PolicyId = if ($Response -match $Patterns.policy_id) {
            [regex]::Matches($Response, $Patterns.policy_id)[0].Groups['id'].Value
        }

        if ($Response -match $Patterns.build -or $Response -match $Patterns.version) {
            $Build = [regex]::Matches($Response, $Patterns.build)[0].Groups['version'].Value
            $Version = [regex]::Matches($Response, $Patterns.version)[0].Groups['version'].Value
            $MajorMinor = if ($Version) {
                [regex]::Matches($Response, $Patterns.major_minor)[0].Groups['version'].Value
            }
            $Patch = if ($Build) {
            ($Build).Split('|')[0]
            }
            elseif ($Version) {
            ($Version).Split('.')[-1]
            }
            if ($Patch) {
                Write-MigrateLog "Policy '$PolicyId' has build '$Patch' assigned"
            }
            else {
                $Message = "Failed to determine sensor version for policy '$PolicyId'"
                Write-MigrateLog $Message
                throw $Message
            }
        }
        else {
            $Message = "Failed to match policy name '$($SensorUpdatePolicyName.ToLower())'"
            Write-MigrateLog $Message
            throw $Message
        }

        $message = "Retrieved sensor policy details: Policy ID: $policyId, Build: $build, Version: $version"
        Write-MigrateLog $message

        # Get installer details based on policy version
        $message = "Retrieving installer details for sensor version: '$($version)'"
        $Response = Invoke-FalconGet "/sensors/combined/installers/v1?filter=platform:'windows'"
        if ($Response) {
            $BuildMatch = '\d{1,}?\.\d{1,}\.' + $Patch
            if ($MajorMinor) {
                $BuildMatch = "($BuildMatch|$([regex]::Escape($MajorMinor))\.\d+)"
            }
            $Installer = '"name": "(?<filename>(\w+\.){1,}?exe)",\n\s+"description": "(.*)?Falcon(.*)",(\n.*){1,}"sh' +
            'a256": "(?<hash>\w{64})",(\n.*){1,}"version": "' + $BuildMatch + '"'
            $Match = $Response.Split('}') | Where-Object { $_ -match $Installer }
            if ($Match) {
                $CloudHash = [regex]::Matches($Match, $Installer)[0].Groups['hash'].Value
                $CloudFile = [regex]::Matches($Match, $Installer)[0].Groups['filename'].Value
                $message = "Found installer: ($CloudFile) with sha256: '$CloudHash'"
                Write-MigrateLog $message
            }
            else {
                $MatchValue = "'$Patch'"
                if ($MajorMinor) {
                    $MatchValue += " or '$MajorMinor'"
                }
                $Message = "Unable to match installer using $MatchValue"
                Write-MigrateLog $Message
                throw $Message
            }
        }
        else {
            $Message = 'Failed to retrieve available installer list'
            Write-MigrateLog $Message
            throw $Message
        }

        if ($CloudHash -and $CloudFile) {
            $LocalFile = Join-Path -Path $WinTemp -ChildPath $CloudFile
            Write-MigrateLog "Downloading installer to: '$LocalFile'"
            Invoke-FalconDownload "/sensors/entities/download-installer/v1?id=$CloudHash" $LocalFile
            if (Test-Path $LocalFile) {
                Write-MigrateLog "Created '$LocalFile'"
                $LocalHash = Get-InstallerHash $LocalFile
            }
        }

        if ($CloudHash -ne $LocalHash) {
            $Message = "Hash mismatch on download (Local: $LocalHash, Cloud: $CloudHash)"
            Write-MigrateLog $Message
            throw $Message
        }

        if ($ProvToken) {
            $InstallParams += " ProvToken=$ProvToken"
        }

        if ($Tags) {
            $InstallParams += " GROUPING_TAGS=$Tags"
        }

        $InstallParams += " ProvWaitTime=$ProvWaitTime"

        Write-MigrateLog "Installing Falcon Sensor..."
        Write-MigrateLog "Starting installer '$LocalFile' with parameters '$InstallParams'"

        $process = (Start-Process -FilePath $LocalFile -ArgumentList $InstallParams -PassThru -ErrorAction SilentlyContinue)
        Write-MigrateLog "Started '$LocalFile' ($($process.Id))"
        Write-MigrateLog "Waiting for the installer process to complete with PID ($($process.Id))"
        Wait-Process -Id $process.Id
        Write-MigrateLog "Installer process with PID ($($process.Id)) has completed"

        if ($process.ExitCode -eq 1244) {
            $Message = "Exit code 1244: Falcon was unable to communicate with the CrowdStrike cloud. Please check your installation token and try again."
            Write-MigrateLog $Message
            throw $Message
        }
        elseif ($process.ExitCode -ne 0) {
            $errOut = $process.StandardError.ReadToEnd()
            $Message = "Falcon installer exited with code $($process.ExitCode). Error: $errOut"
            Write-MigrateLog $Message
            throw $Message
        }
        else {
            $Message = "Falcon installer exited with code $($process.ExitCode)"
        }

        Write-MigrateLog $Message

        # Delete the installer
        if ($DeleteInstaller) {
            if (Test-Path $LocalFile) {
                Remove-Item -Path $LocalFile -Force
            }
            if (Test-Path $LocalFile) {
                $Message = "Failed to delete '$LocalFile'"
                Write-MigrateLog $Message
                throw $Message
            }
            else {
                Write-MigrateLog "Deleted '$LocalFile'"
            }
        }

        $Message = 'Successfully finished install...'
        Write-MigrateLog $Message
    }
    catch {
        $message = "Error installing Falcon Sensor: $($_.Exception.Message)"
        throw $message
    }
}


function Get-HeadersAndUrl([string] $FalconClientId, [string] $FalconClientSecret, [string] $MemberCid, [string] $FalconCloud) {
    $headers = @{'Accept' = 'application/json'; 'Content-Type' = 'application/x-www-form-urlencoded'; 'charset' = 'utf-8' }
    $baseUrl = Get-FalconCloud $FalconCloud

    $body = @{}
    $body['client_id'] = $FalconClientId
    $body['client_secret'] = $FalconClientSecret

    if ($MemberCid) {
        $body['member_cid'] = $MemberCid
    }

    $baseUrl, $headers = Invoke-FalconAuth -BaseUrl $BaseUrl -Body $Body -FalconCloud $FalconCloud
    $headers['Content-Type'] = 'application/json'
    return $baseUrl, $headers
}


function Test-FalconCredential ([string] $FalconClientId, [string] $FalconClientSecret ) {
    if ($FalconClientId -and $FalconClientSecret) {
        return $true
    }
    else {
        return $false
    }
}


function Format-FalconResponseError($errors) {
    $message = ''
    foreach ($error in $errors) {
        $message += "`r`n`t $($error.message)"
    }
    return $message
}


function Format-403Error([string] $url, [hashtable] $scope) {
    $message = "Insufficient permission error when calling $($url). Verify the following scopes are included in the API key:"
    foreach ($key in $scope.Keys) {
        $message += "`r`n`t '$($key)' with: $($scope[$key])"
    }
    return $message
}


function Get-AID {
    $reg_paths = 'HKLM:\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default', 'HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim'
    $aid = $null
    foreach ($path in $reg_paths) {
        try {
            $agItemProperty = Get-ItemProperty -Path $path -Name AG -ErrorAction SilentlyContinue

            if ($null -eq $agItemProperty) {
                continue
            }

            $aid = [System.BitConverter]::ToString( ($agItemProperty.AG)).ToLower() -replace '-', ''
            break
        }
        catch {
            return $null
        }
    }
    return $aid
}


# Changes the host visibility status in the CrowdStrike Falcon console
# an action of $hide will hide the host, anything else will unhide the host
# should only be called to hide/unhide a host that is already in the console
function Invoke-HostVisibility ([string] $Aid, [string] $action) {
    if ($action -eq 'hide') {
        $action = 'hide_host'
    }
    else {
        $action = 'unhide_host'
    }

    if ($null -eq $Aid) {
        $Message = "AID not found on machine. Unable to ${action} host without AID, this may be due to the sensor not being installed or being partially installed."
        Write-MigrateLog $Message
        throw $Message
    }

    $Body = @{
        'ids' = @($Aid)
    }

    $bodyJson = $Body | ConvertTo-Json
    try {
        $url = "${oldBaseUrl}/devices/entities/devices-actions/v2?action_name=${action}"

        $oldCloudHeaders['Content-Type'] = 'application/json'
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -Method 'POST' -Headers $oldCloudHeaders -Body $bodyJson -MaximumRedirection 0
        $content = ConvertFrom-Json -InputObject $response.Content
        Write-VerboseLog -VerboseInput $content -PreMessage 'Invoke-HostVisibility - $content:'

        if ($content.errors) {
            $Message = "Error when calling ${action} on host: "
            $Message += Format-FalconResponseError -errors $content.errors
            Write-MigrateLog $Message
            throw $Message
        }
        else {
            $Message = "Action ${action} executed successfully on host"
            Write-MigrateLog $Message
        }
    }
    catch {
        Write-VerboseLog -VerboseInput $_.Exception -PreMessage 'Invoke-HostVisibility - CAUGHT EXCEPTION - $_.Exception:'
        $response = $_.Exception.Response

        if (!$response) {
            $Message = "Unhandled error occurred while performing action '${action}' on host from the CrowdStrike Falcon API. Error: $($_.Exception.Message)"
            Write-MigrateLog $Message
            throw $Message
        }

        if ($response.StatusCode -eq 409) {
            $Message = "Received a $($response.StatusCode) response from ${url} Error: $($response.StatusDescription)"
            Write-MigrateLog $Message
            Write-MigrateLog 'Host already removed from CrowdStrike Falcon'
        }
        elseif ($response.StatusCode -eq 403) {
            $scope = @{
                'host' = @('Write')
            }
            $Message = Format-403Error -url $url -scope $scope
            Write-MigrateLog $Message
            throw $Message
        }
        else {
            $Message = "Received a $($response.StatusCode) response from ${url}. Error: $($response.StatusDescription)"
            Write-MigrateLog $Message
            throw $Message
        }
    }
}


function Get-InstallerHash ([string] $Path) {
    $Output = if (Test-Path $Path) {
        $Algorithm = [System.Security.Cryptography.HashAlgorithm]::Create("SHA256")
        $Hash = [System.BitConverter]::ToString(
            $Algorithm.ComputeHash([System.IO.File]::ReadAllBytes($Path)))
        if ($Hash) {
            $Hash.Replace('-', '')
        }
        else {
            $null
        }
    }
    return $Output
}


function Invoke-FalconDownload ([string] $Path, [string] $Outfile) {
    $Falcon.Headers.Add('Accept', 'application/octet-stream')
    $Falcon.DownloadFile($Path, $Outfile)
}


function Invoke-FalconGet ([string] $Path) {
    # $Falcon.Headers.Add('Accept', 'application/json')
    $Request = $Falcon.OpenRead($Path)
    $Stream = New-Object System.IO.StreamReader $Request
    $Output = $Stream.ReadToEnd()
    @($Request, $Stream) | ForEach-Object {
        if ($null -ne $_) {
            $_.Dispose()
        }
    }
    return $Output
}


# Sets falcon tags
#psbinding
function Set-Tag ([string] $Aid, [array] $Tags, [string] $BaseUrl, $Headers) {
    try {
        $url = "${BaseUrl}/devices/entities/devices/tags/v1"
        $errorMessage = ''
        $tagsSet = $false

        $body = @{
            'action'     = 'append'
            'device_ids' = @($aid)
            'tags'       = $Tags
        }
        $body = ConvertTo-Json -InputObject $body
        $Headers['Content-Type'] = 'application/json'
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -Method 'PATCH' -Body $body -Headers $Headers -MaximumRedirection 0
        $content = ConvertFrom-Json -InputObject $response.Content
        Write-VerboseLog -VerboseInput $content -PreMessage 'Set-Tag - $content:'

        if ($content.resources) {
            if ($content.resources[0].updated) {
                $tagsSet = $true
            }
            elseif ($content.resources[0].code -eq 404) {
                $errorMessage = $deviceNotFoundError
            }
            else {
                $errorMessage = "Unable to set tags from the CrowdStrike Falcon API. Error: $($content.resources[0].error)"
            }
        }
        else {
            $errorMessage = "Unable to set tags from the CrowdStrike Falcon API. No host with AID: ${aid} If you want to skip transferring tags set the parameter -SkipTags to $true."
        }

        return $tagsSet, $errorMessage
    }
    catch {
        Write-VerboseLog -VerboseInput $_.Exception -PreMessage 'Set-Tag - CAUGHT EXCEPTION - $_.Exception:'
        $response = $_.Exception.Response

        if (!$response) {
            $errorMessage = "Unhandled error occurred while settings tags with the CrowdStrike Falcon API. Error: $($_.Exception.Message)"
        }

        if ($response.StatusCode -eq 403) {
            $scope = @{
                'host' = @('Write')
            }
            $errorMessage = Format-403Error -url $url -scope $scope
        }
        else {
            $errorMessage = "Received a $($response.StatusCode) response from ${url}. Error: $($response.StatusDescription)"
        }

        return $false, $errorMessage
    }
}

# Gets sensor and falcon tags
function Get-Tag ([string] $Aid, [string] $BaseUrl, $Headers) {
    try {
        Write-MigrateLog "Getting tags for host with AID: ${aid}"
        $url = "${BaseUrl}/devices/entities/devices/v2?ids=${aid}"


        Write-MigrateLog "Calling ${url}"
        $Headers['Content-Type'] = 'application/json'
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -Method 'GET' -Headers $Headers -MaximumRedirection 0
        $content = ConvertFrom-Json -InputObject $response.Content
        Write-VerboseLog -VerboseInput $content -PreMessage 'Get-Tag - $content:'

        if ($content.errors) {
            $message = 'Error when calling getting tags on host: '
            $message += Format-FalconResponseError -errors $content.errors
        }

        if ($content.resources) {
            return $content.resources[0].tags
        }
        else {
            $message = "Unable to grab tags from the CrowdStrike Falcon API. No host with AID: ${aid} If you want to skip transferring tags set the parameter -SkipTags to $true."
            throw $message
        }
    }
    catch {
        Write-VerboseLog -VerboseInput $_.Exception -PreMessage 'Get-Tag - CAUGHT EXCEPTION - $_.Exception:'
        $response = $_.Exception.Response

        Write-MigrateLog $_.Exception

        if (!$response) {
            $message = "Unhandled error occurred while grabbing tags from the CrowdStrike Falcon API. Error: $($_.Exception.Message)"
            throw $message
        }

        if ($response.StatusCode -eq 403) {
            $scope = @{
                'host' = @('Read')
            }
            $message = Format-403Error -url $url -scope $scope
            throw $message
        }
        else {
            $message = "Received a $($response.StatusCode) response from ${url}. Error: $($response.StatusDescription)"
            throw $message
        }
    }
}


function Split-Tag($tags) {
    $sensorGroupingTags = @()
    $falconGroupingTags = @()

    $tagsArray = $tags -split ' '

    foreach ($tag in $tagsArray) {
        if ($tag -like 'SensorGroupingTags/*') {
            $sensorGroupingTags += $tag.Split('/')[1]
        }
        elseif ($tag -like 'FalconGroupingTags/*') {
            $falconGroupingTags += $tag.Split('/')[1]
        }
    }

    return $sensorGroupingTags, $falconGroupingTags
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
    $Headers.Add('User-Agent', 'crowdstrike-falcon-scripts/1.1.5')
    try {
        $response = Invoke-WebRequest -Uri "$($BaseUrl)/oauth2/token" -UseBasicParsing -Method 'POST' -Headers $Headers -Body $Body
        $content = ConvertFrom-Json -InputObject $response.Content
        Write-VerboseLog -VerboseInput $content -PreMessage 'Invoke-FalconAuth - $content:'

        if ([string]::IsNullOrEmpty($content.access_token)) {
            $message = 'Unable to authenticate to the CrowdStrike Falcon API. Please check your credentials and try again.'
            throw $message
        }

        $Headers.Add('Authorization', "bearer $($content.access_token)")
    }
    catch {
        # Handle redirects
        Write-Verbose "Invoke-FalconAuth - CAUGHT EXCEPTION - `$_.Exception.Message`r`n$($_.Exception.Message)"
        $response = $_.Exception.Response

        if (!$response) {
            $message = "Unhandled error occurred while authenticating to the CrowdStrike Falcon API. Error: $($_.Exception.Message)"
            Write-FalconLog -Source 'Invoke-FalconAuth' -Message $message
            throw $message
        }

        if ($response.StatusCode -in @(301, 302, 303, 307, 308)) {
            # If autodiscover is enabled, try to get the correct cloud
            if ($FalconCloud -eq 'autodiscover') {
                if ($response.Headers.Contains('X-Cs-Region')) {
                    $region = $response.Headers.GetValues('X-Cs-Region')[0]
                    Write-Verbose "Received a redirect to $region. Setting FalconCloud to $region"
                }
                else {
                    $message = 'Received a redirect but no X-Cs-Region header was provided. Unable to autodiscover the FalconCloud. Please set FalconCloud to the correct region.'
                    Write-FalconLog -Source 'Invoke-FalconAuth' -Message $message
                    throw $message
                }

                $BaseUrl = Get-FalconCloud($region)
                $BaseUrl, $Headers = Invoke-FalconAuth -BaseUrl $BaseUrl -Body $Body -FalconCloud $FalconCloud

            }
            else {
                $message = "Received a redirect. Please set FalconCloud to 'autodiscover' or the correct region."
                Write-FalconLog -Source 'Invoke-FalconAuth' -Message $message
                throw $message
            }
        }
        else {
            $message = "Received a $($response.StatusCode) response from $($BaseUrl)oauth2/token. Please check your credentials and try again. Error: $($response.StatusDescription)"
            Write-FalconLog -Source 'Invoke-FalconAuth' -Message $message
            throw $message
        }
    }

    return $BaseUrl, $Headers
}

### Start of Migration Script ###

if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) {
    $message = 'Unable to proceed without administrative privileges'
    throw $message
}

$winSystem = [Environment]::GetFolderPath('System')
$winTemp = $winSystem -replace 'system32', 'Temp'
if (!$LogPath) {
    $LogPath = Join-Path -Path $winTemp -ChildPath "MigrateFalcon_$(Get-Date -Format yyyy-MM-dd_HH-mm-ss).log"
}
Write-VerboseLog -VerboseInput $LogPath -PreMessage 'LogPath:'
$recoveryCsvPath = Join-Path -Path $winTemp -ChildPath 'falcon_recovery.csv'
Write-VerboseLog -VerboseInput $recoveryCsvPath -PreMessage 'recoveryCsvPath:'

if (!(Test-FalconCredential $NewFalconClientId $NewFalconClientSecret)) {
    $message = 'API Credentials for the new cloud are required'
    Write-MigrateLog $message
    throw $message
}

if (!(Test-FalconCredential $OldFalconClientId $OldFalconClientSecret)) {
    $message = 'API Credentials for the old cloud are required'
    Write-MigrateLog $message
    throw $message
}

$sensorGroupingTags = @()
$falconGroupingTags = @()
$oldAid = Get-AID
$recoveryMode = (Test-Path $recoveryCsvPath)

if ($recoveryMode) {
    Write-MigrateLog 'Recovery mode detected. Attempting to recover from previous migration attempt.'
    $recoveryData = Read-RecoveryCsv -Path $recoveryCsvPath
    $sensorGroupingTags = $recoveryData.SensorGroupingTags
    $falconGroupingTags = $recoveryData.FalconGroupingTags
    $oldAid = $recoveryData.OldAid
}
else {
    # Get current tags
    if (!$SkipTags) {
        if ($null -eq $oldAid) {
            $message = "Unable to retrieve AID. Can't migrate tags without AID. Use -SkipTags to skip tag migration."
            Write-MigrateLog $message
            throw $message
        }
        $oldBaseUrl, $oldCloudHeaders = Get-HeadersAndUrl -FalconClientId $OldFalconClientId -FalconClientSecret $OldFalconClientSecret -FalconCloud $OldFalconCloud -MemberCid $OldMemberCid

        $apiTags = Get-Tag -Aid $oldAid -Headers $oldCloudHeaders -BaseUrl $oldBaseUrl
        Write-MigrateLog 'Successfully retrieved tags'
        $sensorGroupingTags, $falconGroupingTags = Split-Tag -Tags $apiTags
        Write-VerboseLog -VerboseInput $sensorGroupingTags -PreMessage 'sensorGroupingTags pre-diff:'
        Write-VerboseLog -VerboseInput $falconGroupingTags -PreMessage 'falconGroupingTags pre-diff:'
    }

}

$sensorGroupingTagsDiff = Compare-TagsDiff -Tags $Tags -TagList $sensorGroupingTags
Write-VerboseLog -VerboseInput $sensorGroupingTagsDiff -PreMessage 'sensorGroupingTagsDiff:'
$falconGroupingTagsDiff = Compare-TagsDiff -Tags $FalconTags -TagList $falconGroupingTags
Write-VerboseLog -VerboseInput $falconGroupingTagsDiff -PreMessage 'falconGroupingTagsDiff:'

$sensorGroupingTags += $sensorGroupingTagsDiff | Where-Object { $_ -ne "" }
$falconGroupingTags += $falconGroupingTagsDiff | Where-Object { $_ -ne "" }

Write-MigrateLog "Sensor Grouping tags: $sensorGroupingTags"
Write-MigrateLog "Falcon Grouping tags: $falconGroupingTags"

Write-MigrateLog 'Creating recovery csv to keep track of tags...'
Write-RecoveryCsv -SensorGroupingTags $sensorGroupingTags -FalconGroupingTags $falconGroupingTags -OldAid $oldAid -Path $recoveryCsvPath

Invoke-FalconUninstall -UninstallParams $UninstallParams -RemoveHost $RemoveHost -DeleteUninstaller $DeleteUninstaller -MaintenanceToken $MaintenanceToken -UninstallTool $UninstallTool
Invoke-FalconInstall -InstallParams $InstallParams -Tags ($SensorGroupingTags -join ',') -DeleteInstaller $DeleteInstaller -SensorUpdatePolicyName $SensorUpdatePolicyName -ProvToken $ProvToken -ProvWaitTime $ProvWaitTime -NewFalconCid $NewFalconCid

$timeout = Get-Date
$timeout = $timeout.AddSeconds(120)
$newAid = Get-AID

while ($null -eq $newAid -and (Get-Date) -lt $timeout) {
    $message = 'Waiting for new AID...'
    Write-MigrateLog $message
    Start-Sleep -Seconds 5
    $newAid = Get-AID
}

if ($null -eq $newAid) {
    $message = 'Unable to retrieve new AID. Please check the logs for more information.'
    Write-MigrateLog $message
    throw $message
}
else {
    Write-MigrateLog "Successfully retrieved new AID: $newAid"
}

# Set falcon sensor tags
if (!$SkipTags) {
    if ($falconGroupingTags.Count -gt 0) {
        Write-MigrateLog 'Migrating Falcon Grouping tags...'
        if (!$newBaseUrl -or !$newCloudHeaders) {
            $newBaseUrl, $newCloudHeaders = Get-HeadersAndUrl -FalconClientId $NewFalconClientId -FalconClientSecret $NewFalconClientSecret -FalconCloud $NewFalconCloud -MemberCid $NewMemberCid
        }
        $timeout = Get-Date
        $timeout = $timeout.AddSeconds(120)
        $deviceNotFoundError = 'Device not found.'
        $groupingTags = @()

        foreach ($tag in $falconGroupingTags) {
            $groupingTags += "FalconGroupingTags/$tag"
        }

        $tagsMigrated, $errorMessage = Set-Tag -Aid $newAid -Tags $groupingTags -BaseUrl $newBaseUrl -Headers $newCloudHeaders

        while ($tagsMigrated -eq $false -and (Get-Date) -lt $timeout) {
            # fail if error is not device not found
            if ($errorMessage -ne $deviceNotFoundError) {
                throw $errorMessage
            }

            Write-MigrateLog 'Waiting for new AID to be registered...'
            Start-Sleep -Seconds 5
            $tagsMigrated, $errorMessage = Set-Tag -Aid $newAid -Tags $groupingTags -BaseUrl $newBaseUrl -Headers $newCloudHeaders
        }

        if ($tagsMigrated -eq $false) {
            $message = "Unable to set Falcon Grouping tags. Please check the logs for more information. Error: $errorMessage"
            Write-MigrateLog $message
            throw $message
        }
        else {
            $message = "Successfully set Falcon Grouping tags: $groupingTags"
            Write-MigrateLog $message
        }
    }
    else {
        Write-MigrateLog 'No tags to migrate...'
    }
}
else {
    Write-MigrateLog 'SkipTags is set to true... skipping tag migration'
}
if (Test-Path $recoveryCsvPath) {
    Write-MigrateLog "Cleaning up Recovery CSV: $recoveryCsvPath"
    Remove-Item -Path $recoveryCsvPath -Force
}

# Delete migration script if requested
if ($DeleteScript) {
    $ScriptName = $MyInvocation.MyCommand.Name
    $ScriptPath = if (!$PSScriptRoot) {
        Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
    }
    else {
        $PSScriptRoot
    }
    $FilePath = Join-Path -Path $ScriptPath -ChildPath $ScriptName
    Remove-Item -Path $FilePath -Force
    if (Test-Path $FilePath) {
        Write-MigrateLog "Failed to delete '$FilePath'"
    }
    else {
        Write-MigrateLog "Deleted '$FilePath'"
    }
}

Write-MigrateLog 'Migration complete!'
#Stop-Transcript
Write-Output "`r`nSee the full log contents at: $LogPath"
