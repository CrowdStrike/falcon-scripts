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
CrowdStrike Falcon OAuth2 API Client Id [Required if FalconAccessToken is not provided]
.PARAMETER FalconClientSecret
CrowdStrike Falcon OAuth2 API Client Secret [Required if FalconAccessToken is not provided]
.PARAMETER FalconCid
Manually specify CrowdStrike Customer ID (CID) [default: $null]
.PARAMETER FalconAccessToken
Manually set the access token for the Falcon API. Used to bypass the OAuth2 authentication process to cut down on rate limiting. [default: $null]
.PARAMETER GetAccessToken
Returns an access token from the API credentials provided. Used to manually set the FalconAccessToken parameter.
.PARAMETER MemberCid
Member CID, used only in multi-CID ("Falcon Flight Control") configurations and with a parent management CID [default: $null]
.PARAMETER SensorUpdatePolicyName
Sensor Update Policy name to check for assigned sensor version [default: 'platform_default']
.PARAMETER InstallParams
Additional Sensor installation parameters. Script parameters should be used instead when supported. [default: '/install /quiet /norestart' ]
.PARAMETER LogPath
Script log location [default: 'Windows\Temp\InstallFalcon.log']
.PARAMETER DeleteInstaller
Delete sensor installer package when complete [default: $true]
.PARAMETER DeleteScript
Delete script when complete [default: $false]
.PARAMETER ProvToken
Provisioning token to use for sensor installation [default: $null]
.PARAMETER ProvWaitTime
Time to wait, in milliseconds, for sensor to provision [default: 1200000]
.PARAMETER Tags
A comma-separated list of tags to apply to the host after sensor installation [default: $null]
.PARAMETER ProxyHost
The proxy host for the sensor to use when communicating with CrowdStrike [default: $null]
.PARAMETER ProxyPort
The proxy port for the sensor to use when communicating with CrowdStrike [default: $null]
.PARAMETER ProxyDisable
By default, the Falcon sensor for Windows automatically attempts to use any available proxy connections when it connects to the CrowdStrike cloud.
This parameter forces the sensor to skip those attempts and ignore any proxy configuration, including Windows Proxy Auto Detection.
.PARAMETER UserAgent
User agent string to append to the User-Agent header when making requests to the CrowdStrike API.
.PARAMETER Verbose
Enable verbose logging

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
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'DeleteScript')]
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
    [int] $ProvWaitTime = 1200000,

    [Parameter(Position = 12)]
    [string[]] $Tags,

    [Parameter(Position = 13)]
    [ValidatePattern('\w{32}-\w{2}')]
    [string] $FalconCid,

    [Parameter(Position = 14)]
    [string] $ProxyHost,

    [Parameter(Position = 15)]
    [int] $ProxyPort,

    [Parameter(Position = 16)]
    [switch] $ProxyDisable,

    [Parameter(Position = 17)]
    [switch] $GetAccessToken,

    [Parameter(Position = 18)]
    [string] $FalconAccessToken,

    [Parameter(Position = 19)]
    [string] $UserAgent
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

    $ScriptVersion = "1.8.0"
    $BaseUserAgent = "crowdstrike-falcon-scripts/$ScriptVersion"
    $FullUserAgent = if ($UserAgent) {
        "$BaseUserAgent $UserAgent"
    } else {
        $BaseUserAgent
    }

    function Write-FalconLog ([string] $Source, [string] $Message, [bool] $stdout = $true) {
        $Content = @(Get-Date -Format 'yyyy-MM-dd hh:MM:ss')
        if ($Source -notmatch '^(StartProcess|Delete(Installer|Script))$' -and
            $Falcon.ResponseHeaders.Keys -contains 'X-Cs-TraceId') {
            $Content += , "[$($Falcon.ResponseHeaders.Get('X-Cs-TraceId'))]"
        }

        "$(@($Content + $Source) -join ' '): $Message" | Out-File -FilePath $LogPath -Append -Encoding utf8

        if ($stdout) {
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

        # If a pre-message is provided, add it to the beginning of the message
        if ($PreMessage) {
            $message = "$PreMessage`r`n$message"
        }

        # Write Verbose
        Write-Verbose $message

        # Write to log file, but not stdout
        Write-FalconLog -Source 'VERBOSE' -Message $message -stdout $false
    }

    function Get-FalconCloud ([string] $xCsRegion) {
        $Output = switch ($xCsRegion) {
            'autodiscover' { 'https://api.crowdstrike.com'; break }
            'us-1' { 'https://api.crowdstrike.com'; break }
            'us-2' { 'https://api.us-2.crowdstrike.com'; break }
            'eu-1' { 'https://api.eu-1.crowdstrike.com'; break }
            'us-gov-1' { 'https://api.laggar.gcw.crowdstrike.com'; break }
            'us-gov-2' { 'https://api.us-gov-2.crowdstrike.mil'; break }
            default { throw "Provided region $xCsRegion is invalid. Please set FalconCloud to a valid region or 'autodiscover'"; break }
        }
        return $Output
    }

    function Invoke-FalconAuth([hashtable] $WebRequestParams, [string] $BaseUrl, [hashtable] $Body, [string] $FalconCloud) {
        $Headers = @{'Accept' = 'application/json'; 'Content-Type' = 'application/x-www-form-urlencoded'; 'charset' = 'utf-8' }
        $Headers.Add('User-Agent', $FullUserAgent)
        if ($FalconAccessToken) {
            $Headers.Add('Authorization', "bearer $($FalconAccessToken)")
        }
        else {
            try {
                $response = Invoke-WebRequest @WebRequestParams -Uri "$($BaseUrl)/oauth2/token" -UseBasicParsing -Method 'POST' -Headers $Headers -Body $Body
                $content = ConvertFrom-Json -InputObject $response.Content
                Write-VerboseLog -VerboseInput $content -PreMessage 'Invoke-FalconAuth - $content:'

                if ([string]::IsNullOrEmpty($content.access_token)) {
                    $message = 'Unable to authenticate to the CrowdStrike Falcon API. Please check your credentials and try again.'
                    throw $message
                }

                if ($GetAccessToken -eq $true) {
                    Write-Output $content.access_token | out-host
                    exit 0
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
                        $BaseUrl, $Headers = Invoke-FalconAuth -WebRequestParams $WebRequestParams -BaseUrl $BaseUrl -Body $Body -FalconCloud $FalconCloud

                    }
                    else {
                        $message = "Received a redirect. Please set FalconCloud to 'autodiscover' or the correct region."
                        Write-FalconLog -Source 'Invoke-FalconAuth' -Message $message
                        throw $message
                    }
                }
                else {
                    $message = "Received a $($response.StatusCode) response from $($BaseUrl)/oauth2/token. Please check your credentials and try again. Error: $($response.StatusDescription)"
                    Write-FalconLog -Source 'Invoke-FalconAuth' -Message $message
                    throw $message
                }
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
        $message = "Insufficient permission error when calling $($url). Verify the following scopes are included in the API key:"
        foreach ($key in $scope.Keys) {
            $message += "`r`n`t '$($key)' with: $($scope[$key])"
        }
        return $message
    }

    function Format-FalconResponseError($errors) {
        $message = ''
        foreach ($error in $errors) {
            $message += "`r`n`t $($error.message)"
        }
        return $message
    }

    function Get-ResourceContent([hashtable] $WebRequestParams, [string] $url, [string] $logKey, [hashtable] $scope, [string] $errorMessage) {
        try {
            $response = Invoke-WebRequest @WebRequestParams -Uri $url -UseBasicParsing -Method 'GET' -MaximumRedirection 0
            $content = ConvertFrom-Json -InputObject $response.Content
            Write-VerboseLog -VerboseInput $content -PreMessage 'Get-ResourceContent - $content:'

            if ($content.errors) {
                $message = "Error when getting content: "
                $message += Format-FalconResponseError -errors $content.errors
                Write-FalconLog $logKey $message
                throw $message
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
            Write-VerboseLog -VerboseInput $_.Exception.Message -PreMessage 'Get-ResourceContent - CAUGHT EXCEPTION - $_.Exception.Message:'
            $response = $_.Exception.Response

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

    function Invoke-FalconDownload ([hashtable] $WebRequestParams, [string] $url, [string] $Outfile) {
        try {
            $ProgressPreference = 'SilentlyContinue'
            $response = Invoke-WebRequest @WebRequestParams -Uri $url -UseBasicParsing -Method 'GET' -OutFile $Outfile
        }
        catch {
            $response = $_.Exception.Response
            if (!$response) {
                $message = "Unhandled error occurred. Error: $($_.Exception.Message)"
                Write-FalconLog 'DownloadFile' $message
                throw $message
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
                $message = "Received a $($response.StatusCode) response from ${url}. Error: $($response.StatusDescription)"
                Write-FalconLog 'DownloadFile' $message
                throw $message
            }
        }
    }

    if (!$SensorUpdatePolicyName) {
        $SensorUpdatePolicyName = 'platform_default'
    }
    if (!$InstallParams) {
        $InstallParams = '/install /quiet /norestart'
    }
}
process {
    # TLS check should be first since it's needed for all HTTPS communication
    if ([Net.ServicePointManager]::SecurityProtocol -notmatch 'Tls12') {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }
        catch {
            $message = $_
            Write-FalconLog 'TlsCheck' $message
            throw $message
        }
    }

    if (!$GetAccessToken) {
        if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) {
            $message = 'Unable to proceed without administrative privileges'
            Write-FalconLog 'CheckAdmin' $message
            throw $message
        }
        if (Get-Service | Where-Object { $_.Name -eq 'CSFalconService' }) {
            $message = "'CSFalconService' running. Falcon sensor is already installed."
            Write-FalconLog 'CheckService' $message
            exit 0
        }
    }

    # Check if credentials were provided
    $AuthProvided = (Test-FalconCredential $FalconClientId $FalconClientSecret) -or $FalconAccessToken

    # Hashtable for common Invoke-WebRequest parameters
    $WebRequestParams = @{}

    # Configure proxy based on arguments
    $proxy = ""
    if ($ProxyHost) {
        Write-Output "Proxy settings detected in arguments, using proxy settings to communicate with the CrowdStrike api"

        if ($ProxyHost) {
            $proxy_host = $ProxyHost.Replace("http://", "").Replace("https://", "")
            Write-FalconLog -Source "Proxy" -Message "Proxy host ${proxy_host} found in arguments" -stdout $true
        }

        if ($ProxyPort) {
            Write-FalconLog -Source "Proxy" -Message "Proxy port ${ProxyPort} found in arguments" -stdout $true
            $proxy = "http://${proxy_host}:${ProxyPort}"
        }
        else {
            $proxy = "http://${proxy_host}"
        }

        $proxy = $proxy.Replace("'", "").Replace("`"", "")
        Write-FalconLog -Source "Proxy" -Message "Using proxy ${proxy} to communicate with the CrowdStrike Apis" -stdout $true
    }

    if ($proxy) {
        $WebRequestParams.Add('Proxy', $proxy)
    }

    # Configure OAuth2 authentication
    if ($AuthProvided) {
        $BaseUrl = Get-FalconCloud $FalconCloud

        $Body = @{}
        $Body['client_id'] = $FalconClientId
        $Body['client_secret'] = $FalconClientSecret

        if ($MemberCid) {
            $Body['member_cid'] = $MemberCid
        }

        $BaseUrl, $Headers = Invoke-FalconAuth -WebRequestParams $WebRequestParams -BaseUrl $BaseUrl -Body $Body -FalconCloud $FalconCloud
        $Headers['Content-Type'] = 'application/json'
        $WebRequestParams.Add('Headers', $Headers)
    }
    else {
        $message = 'Unable to proceed without valid API credentials. Ensure you pass the required parameters or define them in the script.'
        Write-FalconLog 'CheckCredentials' $message
        throw $message
    }

    # Get CCID from API if not provided
    if (!$FalconCid) {
        Write-FalconLog 'GetCcid' 'No CCID provided. Attempting to retrieve from the CrowdStrike Falcon API.'
        $url = "${BaseUrl}/sensors/queries/installers/ccid/v1"
        $ccid_scope = @{
            'Sensor Download' = @('Read')
        }
        $ccid = Get-ResourceContent -WebRequestParams $WebRequestParams -url $url -logKey 'GetCcid' -scope $ccid_scope -errorMessage "Unable to grab CCID from the CrowdStrike Falcon API."

        $message = "Retrieved CCID: $ccid"
        Write-FalconLog 'GetCcid' $message
        $InstallParams += " CID=$ccid"
    }
    else {
        $message = "Using provided CCID: $FalconCid"
        Write-FalconLog 'GetCcid' $message
        $InstallParams += " CID=$FalconCid"
    }

    # Get sensor version from policy
    $message = "Retrieving sensor policy details for '$($SensorUpdatePolicyName)'"
    Write-FalconLog 'GetPolicy' $message
    $filter = "platform_name:'Windows'+name.raw:'$($SensorUpdatePolicyName)'"
    $url = "${BaseUrl}/policy/combined/sensor-update/v2?filter=$([System.Web.HttpUtility]::UrlEncode($filter)))"
    $policy_scope = @{
        'Sensor update policies' = @('Read')
    }
    $policyDetails = Get-ResourceContent -WebRequestParams $WebRequestParams -url $url -logKey 'GetPolicy' -scope $policy_scope -errorMessage "Unable to fetch policy details from the CrowdStrike Falcon API."
    $policyId = $policyDetails.id
    $build = $policyDetails[0].settings.build
    $version = $policyDetails[0].settings.sensor_version

    # Make sure we got a version from the policy
    if (!$version) {
        $message = "Unable to retrieve sensor version from policy '$($SensorUpdatePolicyName)'. Please check the policy and try again."
        Write-FalconLog 'GetPolicy' $message
        throw $message
    }

    $message = "Retrieved sensor policy details: Policy ID: $policyId, Build: $build, Version: $version"
    Write-FalconLog 'GetPolicy' $message

    # Get installer details based on policy version
    $message = "Retrieving installer details for sensor version: '$($version)'"
    Write-FalconLog 'GetInstaller' $message
    $encodedFilter = [System.Web.HttpUtility]::UrlEncode("platform:'windows'+version:'$($version)'")
    $url = "${BaseUrl}/sensors/combined/installers/v1?filter=${encodedFilter}"
    $installer_scope = @{
        'Sensor Download' = @('Read')
    }
    $installerDetails = Get-ResourceContent -WebRequestParams $WebRequestParams -url $url -logKey 'GetInstaller' -scope $installer_scope -errorMessage "Unable to fetch installer details from the CrowdStrike Falcon API."

    if ( $installerDetails.sha256 -and $installerDetails.name ) {
        $cloudHash = $installerDetails.sha256
        $cloudFile = $installerDetails.name
        $message = "Found installer: ($cloudFile) with sha256: '$cloudHash'"
        Write-FalconLog 'GetInstaller' $message
    }
    else {
        $message = "Failed to retrieve installer details."
        Write-FalconLog 'GetInstaller' $message
        throw $message
    }

    # Download the installer
    $localFile = Join-Path -Path $WinTemp -ChildPath $cloudFile
    Write-FalconLog 'DownloadFile' "Downloading installer to: '$localFile'"
    $url = "${BaseUrl}/sensors/entities/download-installer/v1?id=$cloudHash"
    Invoke-FalconDownload -WebRequestParams $WebRequestParams -url $url -Outfile $localFile

    if (Test-Path $localFile) {
        $localHash = Get-InstallerHash -Path $localFile
        $message = "Successfull downloaded installer '$localFile' ($localHash)"
        Write-FalconLog 'DownloadFile' $message
    }
    else {
        $message = "Failed to download installer."
        Write-FalconLog 'DownloadFile' $message
        throw $message
    }

    # Compare the hashes prior to installation
    if ($cloudHash -ne $localHash) {
        $message = "Hash mismatch on download (Local: $localHash, Cloud: $cloudHash)"
        Write-FalconLog 'CheckHash' $message
        throw $message
    }

    # Additional parameters
    if ($ProvToken) {
        $InstallParams += " ProvToken=$ProvToken"
    }

    if ($Tags) {
        $InstallParams += " GROUPING_TAGS=$($Tags -join ',')"
    }

    if ($ProxyHost) {
        $InstallParams += " APP_PROXYNAME=$ProxyHost"
    }

    if ($ProxyPort) {
        $InstallParams += " APP_PROXYPORT=$ProxyPort"
    }

    # Disable proxy when switch is used
    if ($ProxyDisable) {
        $InstallParams += " PROXYDISABLE=0"
    }

    $InstallParams += " ProvWaitTime=$ProvWaitTime"

    # Begin installation
    Write-FalconLog 'Installer' 'Installing Falcon Sensor...'
    Write-FalconLog 'StartProcess' "Starting installer with parameters: '$InstallParams'"
    try {
        $process = (Start-Process -FilePath $LocalFile -ArgumentList $InstallParams -PassThru -ErrorAction SilentlyContinue)
        Write-FalconLog 'StartProcess' "Started '$LocalFile' ($($process.Id))"
        Write-FalconLog 'StartProcess' "Waiting for the installer process to complete with PID ($($process.Id))"
        Wait-Process -Id $process.Id
        Write-FalconLog 'StartProcess' "Installer process with PID ($($process.Id)) has completed"

        # Check the exit code
        if ($process.ExitCode -ne 0) {
            Write-VerboseLog -VerboseInput $process -PreMessage 'PROCESS EXIT CODE ERROR - $process:'
            if ($process.ExitCode -eq 1244) {
                $message = "Exit code 1244: Falcon was unable to communicate with the CrowdStrike cloud. Please check your installation token and try again."
                Write-FalconLog 'InstallerProcess' $message
                throw $message
            }
            else {
                if ($process.StandardError) {
                    $errOut = $process.StandardError.ReadToEnd()
                }
                else {
                    $errOut = "No error output was provided by the process."
                }
                $message = "Falcon installer exited with code $($process.ExitCode). Error: $errOut"
                Write-FalconLog 'InstallerProcess' $message
                throw $message
            }
        }
    }
    catch {
        Write-FalconLog 'InstallerProcess' "Caught exception: $_"
        throw $_
    }

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

    Write-FalconLog 'InstallerProcess' 'Falcon sensor installed successfully.'
}
end {
    Write-FalconLog 'EndScript' 'Script completed.'
    $message = "`r`nSee the full log contents at: '$($LogPath)'"
    Write-Output $message
}
