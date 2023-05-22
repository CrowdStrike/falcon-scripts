<#
.SYNOPSIS
Download and install the CrowdStrike Falcon Sensor for Windows
.DESCRIPTION
Uses the CrowdStrike Falcon APIs to check the sensor version assigned to a Windows Sensor Update policy,
downloads that version, then installs it on the local machine. By default, once complete, the script
deletes itself and the downloaded installer package. The individual steps and any related error messages
are logged to 'Windows\Temp\InstallFalcon.log' unless otherwise specified.

Script options can be passed as parameters or defined in the param() block. Default values are listed in
the parameter descriptions.

The script must be run as an administrator on the local machine in order for the Falcon Sensor installation
to complete, and the OAuth2 API Client being used requires 'sensor-update-policies:read' and
'sensor-download:read' permissions.
.PARAMETER FalconCloud
CrowdStrike Falcon OAuth2 API Hostname [default: autodiscover]
.PARAMETER FalconClientId
CrowdStrike Falcon OAuth2 API Client Id [Required]
.PARAMETER FalconClientSecret
CrowdStrike Falcon OAuth2 API Client Secret [Required]
.PARAMETER FalconCid
Manually specify CrowdStrike Customer ID (CID) [default: $null]
.PARAMETER MemberCid
Member CID, used only in multi-CID ("Falcon Flight Control") configurations and with a parent management CID.
.PARAMETER SensorUpdatePolicyName
Sensor Update Policy name to check for assigned sensor version ['platform_default' if left undefined]
.PARAMETER InstallParams
Sensor installation parameters, without your CID value ['/install /quiet /noreboot' if left undefined]
.PARAMETER LogPath
Script log location ['Windows\Temp\InstallFalcon.log' if left undefined]
.PARAMETER DeleteInstaller
Delete sensor installer package when complete [default: $true]
.PARAMETER DeleteScript
Delete script when complete [default: $false]
.PARAMETER ProvToken
Provisioning token to use for sensor installation [default: $null]
.PARAMETER ProvWaitTime
Time to wait, in seconds, for sensor to provision [default: 1200]
.PARAMETER Tags
A comma-separated list of tags to apply to the host after sensor installation [default: $null]
.EXAMPLE
PS>.\falcon_windows_install.ps1 -FalconClientId <string> -FalconClientSecret <string>

Run the script and define 'FalconClientId' and 'FalconClientSecret' during runtime. All other
parameters will use their default values.
.EXAMPLE
PS>.\falcon_windows_install.ps1

Run the script and use all values that were previously defined within the script.
.NOTES
Updated 2021-10-22 to include 'sensor_version' property when matching policy to sensor installer package.

#>
#Requires -Version 3.0

[CmdletBinding()]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'DeleteInstaller')]
param(
    [Parameter(Position = 1)]
    [ValidateSet('autodiscover', 'us-1', 'us-2', 'eu-1', 'us-gov-1')]
    [string] $FalconCloud = 'autodiscover',

    [Parameter(Position = 2)]
    [string] $FalconClientId,

    [Parameter(Position = 3)]
    [string] $FalconClientSecret,

    [Parameter(Position = 4)]
    [string] $MemberCid,

    [Parameter(Position = 5)]
    [string] $SensorUpdatePolicyName,

    [Parameter(Position = 6)]
    [string] $InstallParams,

    [Parameter(Position = 7)]
    [string] $LogPath,

    [Parameter(Position = 8)]
    [bool] $DeleteInstaller = $true,

    [Parameter(Position = 9)]
    [bool] $DeleteScript = $false,

    [Parameter(Position = 10)]
    [string] $ProvToken,

    [Parameter(Position = 11)]
    [int] $ProvWaitTime = 1200,

    [Parameter(Position = 12)]
    [string] $Tags,

    [Parameter(Position = 13)]
    [ValidatePattern('\w{32}-\w{2}')]
    [string] $FalconCid
)
begin {
    if ($PSVersionTable.PSVersion -lt '3.0')
    { throw "This script requires a miniumum PowerShell 3.0" }

    $ScriptName = $MyInvocation.MyCommand.Name
    $ScriptPath = if (!$PSScriptRoot) {
        Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
    }
    else {
        $PSScriptRoot
    }

    function Write-FalconLog ([string] $Source, [string] $Message) {
        $Content = @(Get-Date -Format 'yyyy-MM-dd hh:MM:ss')
        if ($Source -notmatch '^(StartProcess|Delete(Installer|Script))$' -and
            $Falcon.ResponseHeaders.Keys -contains 'X-Cs-TraceId') {
            $Content += , "[$($Falcon.ResponseHeaders.Get('X-Cs-TraceId'))]"
        }

        "$(@($Content + $Source) -join ' '): $Message" | Out-File -FilePath $LogPath -Append -Encoding utf8

        if ([string]::IsNullOrEmpty($Source)) {
            if ($FalconClientId.Length -gt 0) {
                Write-Output $Message.replace($FalconClientId, '***')
            }
            else {
                Write-Output $Message
            }
        }
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
            $response = Invoke-WebRequest -Uri "$($BaseUrl)/oauth2/token" -UseBasicParsing -Method 'POST' -Headers $Headers -Body $Body
            $content = ConvertFrom-Json -InputObject $response.Content

            if ([string]::IsNullOrEmpty($content.access_token)) {
                $Message = 'Unable to authenticate to the CrowdStrike Falcon API. Please check your credentials and try again.'
                throw $Message
            }

            $Headers.Add('Authorization', "bearer $($content.access_token)")
        }
        catch {
            # Handle redirects
            $response = $_.Exception.Response

            if (!$response) {
                $Message = "Unhandled error occurred while authenticating to the CrowdStrike Falcon API. Error: $($_.Exception.Message)"
                Write-FalconLog -Source 'Invoke-FalconAuth' -Message $Message
                throw $Message
            }

            if ($response.StatusCode -in @(301, 302, 303, 307, 308)) {
                # If autodiscover is enabled, try to get the correct cloud
                if ($FalconCloud -eq 'autodiscover') {
                    if ($response.Headers.Contains('X-Cs-Region')) {
                        $region = $response.Headers.GetValues('X-Cs-Region')[0]
                    }
                    else {
                        $Message = 'Received a redirect but no X-Cs-Region header was provided. Unable to autodiscover the FalconCloud. Please set FalconCloud to the correct region.'
                        Write-FalconLog -Source 'Invoke-FalconAuth' -Message $Message
                        throw $Message
                    }

                    $BaseUrl = Get-FalconCloud($region)
                    $BaseUrl, $Headers = Invoke-FalconAuth -BaseUrl $BaseUrl -Body $Body -FalconCloud $FalconCloud

                }
                else {
                    $Message = "Received a redirect. Please set FalconCloud to 'autodiscover' or the correct region."
                    Write-FalconLog -Source 'Invoke-FalconAuth' -Message $Message
                    throw $Message
                }
            }
            else {
                $Message = "Received a $($response.StatusCode) response from $($BaseUrl)oauth2/token. Please check your credentials and try again. Error: $($response.StatusDescription)"
                Write-FalconLog -Source 'Invoke-FalconAuth' -Message $Message
                throw $Message
            }
        }

        return $BaseUrl, $Headers
    }

    function Test-FalconCredential([string] $FalconClientId , [string] $FalconClientSecret ) {
        if ($FalconClientId -and $FalconClientSecret) {
            return $true
        }
        else {
            return $false
        }
    }

    $WinSystem = [Environment]::GetFolderPath('System')
    $WinTemp = $WinSystem -replace 'system32', 'Temp'
    if (!$LogPath) {
        $LogPath = Join-Path -Path $WinTemp -ChildPath 'InstallFalcon.log'
    }

    function Format-403Error([string] $url, [hashtable] $scope) {
        $Message = "Insufficient permission error when calling $($url). Verify the following scopes are included in the API key:"
        foreach ($key in $scope.Keys) {
            $Message += "`r`n`t '$($key)' with: $($scope[$key])"
        }
        return $Message
    }

    function Format-FalconResponseError($errors) {
        $Message = ''
        foreach ($error in $errors) {
            $Message += "`r`n`t $($error.message)"
        }
        return $Message
    }

    function Get-ResourceContent([string] $url, [string] $logKey, [hashtable] $scope, [string] $errorMessage) {
        try {
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -Method 'GET' -Headers $Headers -MaximumRedirection 0
            $content = ConvertFrom-Json -InputObject $response.Content

            if ($content.errors) {
                $message = "Error when getting content: "
                $message += Format-FalconResponseError -errors $content.errors
                Write-FalconLog $logKey $message
                throw $Message
            }

            if ($content.resources) {
                return $content.resources
            }
            else {
                $message = $errorMessage
                throw $message
            }
        }
        catch {
            $response = $_.Exception.Response

            Write-FalconLog $_.Exception

            if (!$response) {
                $message = "Unhandled error occurred. Error: $($_.Exception.Message)"
                throw $message
            }

            if ($response.StatusCode -eq 403) {
                $message = Format-403Error -url $url -scope $scope
                Write-FalconLog $logKey $message
                throw $message
            }
            else {
                $message = "Received a $($response.StatusCode) response from ${url}. Error: $($response.StatusDescription)"
                Write-FalconLog $logKey $message
                Write-Host $message
                throw $message
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

    function Invoke-FalconDownload ([string] $url, [string] $Outfile) {
        try {
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -Method 'GET' -Headers $Headers -OutFile $Outfile
        }
        catch {
            $response = $_.Exception.Response
            if (!$response) {
                $Message = "Unhandled error occurred. Error: $($_.Exception.Message)"
                Write-FalconLog 'DownloadFile' $Message
                throw $Message
            }
            if ($response.StatusCode -eq 403) {
                $scope = @{
                    'Sensor Download' = @('Read')
                }
                $message = Format-403Error -url $url -scope $scope
                Write-FalconLog 'Permissions' $message
                throw $message
            }
            else {
                $Message = "Received a $($response.StatusCode) response from ${url}. Error: $($response.StatusDescription)"
                Write-FalconLog 'DownloadFile' $Message
                throw $Message
            }
        }
    }

    if (!$SensorUpdatePolicyName) {
        $SensorUpdatePolicyName = 'platform_default'
    }
    if (!$InstallParams) {
        $InstallParams = '/install /quiet /noreboot'
    }
}
process {
    if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) {
        $Message = 'Unable to proceed without administrative privileges'
        Write-FalconLog 'CheckAdmin' $Message
        throw $Message
    }
    elseif (Get-Service | Where-Object { $_.Name -eq 'CSFalconService' }) {
        $Message = "'CSFalconService' running. Falcon sensor is already installed."
        Write-FalconLog 'CheckService' $Message
        exit 0
    }
    else {
        $credsProvided = Test-FalconCredential $FalconClientId $FalconClientSecret
        if ([Net.ServicePointManager]::SecurityProtocol -notmatch 'Tls12') {
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            }
            catch {
                $Message = $_
                Write-FalconLog 'TlsCheck' $Message
                throw $Message
            }
        }
        if (!($PSVersionTable.CLRVersion.ToString() -ge 3.5)) {
            $Message = '.NET Framework 3.5 or newer is required'
            Write-FalconLog 'NetCheck' $Message
            throw $Message
        }
    }

    # Configure OAuth2 authentication
    if ($credsProvided) {
        $Headers = @{'Accept' = 'application/json'; 'Content-Type' = 'application/x-www-form-urlencoded'; 'charset' = 'utf-8' }
        $BaseUrl = Get-FalconCloud $FalconCloud

        $Body = @{}
        $Body['client_id'] = $FalconClientId
        $Body['client_secret'] = $FalconClientSecret

        if ($MemberCid) {
            $Body['member_cid'] = $MemberCid
        }

        $BaseUrl, $Headers = Invoke-FalconAuth -BaseUrl $BaseUrl -Body $Body -FalconCloud $FalconCloud
        $Headers['Content-Type'] = 'application/json'
    }
    else {
        $Message = 'Unable to proceed without valid API credentials. Ensure you pass the required parameters or define them in the script.'
        Write-FalconLog 'CheckCredentials' $Message
        throw $Message
    }

    # Get CCID from API if not provided
    if (!$FalconCid) {
        $url = "${BaseUrl}/sensors/queries/installers/ccid/v1"
        $ccid_scope = @{
            'Sensor Download' = @('Read')
        }
        $ccid = Get-ResourceContent -url $url -logKey 'GetCcid' -scope $ccid_scope -errorMessage "Unable to grab CCID from the CrowdStrike Falcon API."

        $message = "Retrieved CCID: $ccid"
        Write-FalconLog 'GetCcid' $message
        Write-Host $message
        $InstallParams += " CID=$ccid"
    }
    else {
        $InstallParams += " CID=$FalconCid"
    }

    # Get sensor version from policy
    $filter = "platform_name:'Windows'+name:'$($SensorUpdatePolicyName.ToLower())'"
    $url = "${BaseUrl}/policy/combined/sensor-update/v2?filter=$([System.Web.HttpUtility]::UrlEncode($filter)))"
    $policy_scope = @{
        'Sensor update policies' = @('Read')
    }
    $policyDetails = Get-ResourceContent -url $url -logKey 'GetPolicy' -scope $policy_scope -errorMessage "Unable to fetch policy details from the CrowdStrike Falcon API."
    $policyId = $policyDetails.id
    $build = $policyDetails[0].settings.build
    $version = $policyDetails[0].settings.sensor_version
    $message = "Retrieved policy details: Policy ID: $policyId, Build: $build, Version: $version"
    Write-FalconLog 'GetPolicy' $Message
    Write-Host $Message

    # Get installer details based on policy version
    $encodedFilter = [System.Web.HttpUtility]::UrlEncode("platform:'windows'+version:'$($version)'")
    $url = "${BaseUrl}/sensors/combined/installers/v1?filter=${encodedFilter}"
    $installer_scope = @{
        'Sensor Download' = @('Read')
    }
    $installerDetails = Get-ResourceContent -url $url -logKey 'GetInstaller' -scope $installer_scope -errorMessage "Unable to fetch installer details from the CrowdStrike Falcon API."

    if ( $installerDetails.sha256 -and $installerDetails.name ) {
        $cloudHash = $installerDetails.sha256
        $cloudFile = $installerDetails.name
        $message = "Matched installer '$cloudHash' ($cloudFile)"
        Write-FalconLog 'GetInstaller' $Message
        Write-Host $Message
    }
    else {
        $message = "Failed to retrieve installer details."
        Write-FalconLog 'GetInstaller' $Message
        throw $Message
    }

    # Download the installer
    $localFile = Join-Path -Path $WinTemp -ChildPath $cloudFile
    $url = "${BaseUrl}/sensors/entities/download-installer/v1?id=$cloudHash"
    Invoke-FalconDownload -url $url -Outfile $localFile

    if (Test-Path $localFile) {
        $localHash = Get-InstallerHash -Path $localFile
        $message = "Downloaded '$localFile' ($localHash)"
        Write-FalconLog 'DownloadFile' $Message
        Write-Host $Message
    }
    else {
        $message = "Failed to download installer."
        Write-FalconLog 'DownloadFile' $Message
        throw $Message
    }

    # Compare the hashes prior to installation
    if ($cloudHash -ne $localHash) {
        $message = "Hash mismatch on download (Local: $localHash, Cloud: $cloudHash)"
        Write-FalconLog 'CheckHash' $Message
        throw $Message
    }

    # Additional parameters
    if ($ProvToken) {
        $InstallParams += " ProvToken=$ProvToken"
    }

    if ($Tags) {
        $InstallParams += " GROUPING_TAGS=$Tags"
    }

    $InstallParams += " ProvWaitTime=$ProvWaitTime"

    # Begin installation
    $process = (Start-Process -FilePath $LocalFile -ArgumentList $InstallParams -PassThru -ErrorAction SilentlyContinue)
    Write-FalconLog 'StartProcess' "Started '$LocalFile' ($($process.Id))"
    Write-FalconLog $null "Waiting for the installer process to complete with PID ($($process.Id))"
    Wait-Process -Id $process.Id
    Write-FalconLog $null "Installer process with PID ($($process.Id)) has completed"

    if ($process.ExitCode -eq 1244) {
        $Message = "Exit code 1244: Falcon was unable to communicate with the CrowdStrike cloud. Please check your installation token and try again."
        Write-FalconLog 'InstallerProcess' $Message
        throw $Message
    }
    elseif ($process.ExitCode -ne 0) {
        $errOut = $process.StandardError.ReadToEnd()
        $Message = "Falcon installer exited with code $($process.ExitCode). Error: $errOut"
        Write-FalconLog 'InstallerProcess' $Message
        throw $Message
    }
    else {
        $Message = "Falcon installer exited with code $($process.ExitCode)"
    }

    Write-FalconLog $null $Message


    @('DeleteInstaller', 'DeleteScript') | ForEach-Object {
        if ((Get-Variable $_).Value -eq $true) {
            $FilePath = if ($_ -eq 'DeleteInstaller') {
                $LocalFile
            }
            else {
                Join-Path -Path $ScriptPath -ChildPath $ScriptName
            }
            Remove-Item -Path $FilePath -Force
            if (Test-Path $FilePath) {
                Write-FalconLog $_ "Failed to delete '$FilePath'"
            }
            else {
                Write-FalconLog $_ "Deleted '$FilePath'"
            }
        }
    }
}
end {
    Write-FalconLog $null "Script complete"
}
