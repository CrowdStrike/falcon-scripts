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
uninstall and the OAuth2 API Client being used requires 'sensor-update-policies:write' and
'host:write' permissions.

.PARAMETER MaintenanceToken
Sensor uninstall maintenance token. If left undefined, the script will attempt to retrieve the token from the API assuming the FalconClientId|FalconClientSecret are defined.
.PARAMETER UninstallParams
Sensor uninstall parameters ['/uninstall /quiet' if left undefined]
.PARAMETER UninstallTool
Sensor uninstall tool, local installation cache or CS standalone uninstaller ['installcache' if left undefined]
.PARAMETER LogPath
Script log location ['Windows\Temp\csfalcon_uninstall.log' if left undefined]
.PARAMETER DeleteUninstaller
Delete sensor uninstaller package when complete [default: $true]
.PARAMETER DeleteScript
Delete script when complete [default: $false]
.PARAMETER RemoveHost
Remove host from CrowdStrike Falcon [requires either FalconClientId|FalconClientSecret or FalconAccessToken]. It is recommended to use Host Retention Policies to remove hosts from the Falcon console instead of this parameter.
.PARAMETER FalconCloud
CrowdStrike Falcon OAuth2 API Hostname [default: autodiscover]
.PARAMETER FalconClientId
CrowdStrike Falcon OAuth2 API Client Id
.PARAMETER FalconClientSecret
CrowdStrike Falcon OAuth2 API Client Secret
.PARAMETER FalconAccessToken
Manually set the access token for the Falcon API. Used to bypass the OAuth2 authentication process to cut down on rate limiting. [default: $null]
.PARAMETER GetAccessToken
Returns an access token from the API credentials provided. Used to manually set the FalconAccessToken parameter.
.PARAMETER MemberCid
Member CID, used only in multi-CID ("Falcon Flight Control") configurations and with a parent management CID.
.PARAMETER ProxyHost
The proxy host for the sensor to use when communicating with CrowdStrike [default: $null]
.PARAMETER ProxyPort
The proxy port for the sensor to use when communicating with CrowdStrike [default: $null]
.PARAMETER Verbose
Enable verbose logging

.EXAMPLE
PS>.\falcon_windows_uninstall.ps1 -MaintenanceToken <string>

Uninstall the Falcon sensor with the provided MaintenanceToken.
.EXAMPLE
PS>.\falcon_windows_uninstall.ps1 -FalconClientId <string> -FalconClientSecret <string> -RemoveHost

Use the Falcon API to retrieve the maintenance token and remove the host from the Falcon console
after uninstalling.
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
    [bool] $DeleteScript = $false,

    [Parameter(Position = 7)]
    [switch] $RemoveHost,

    [Parameter(Position = 8)]
    [ValidateSet('autodiscover', 'us-1', 'us-2', 'eu-1', 'us-gov-1')]
    [string] $FalconCloud = 'autodiscover',

    [Parameter(Position = 9)]
    [ValidatePattern('\w{32}')]
    [string] $FalconClientId,

    [Parameter(Position = 10)]
    [ValidatePattern('\w{40}')]
    [string] $FalconClientSecret,

    [Parameter(Position = 11)]
    [string] $MemberCid,

    [Parameter(Position = 12)]
    [string] $ProxyHost,

    [Parameter(Position = 13)]
    [int] $ProxyPort,

    [Parameter(Position = 14)]
    [switch] $GetAccessToken,

    [Parameter(Position = 15)]
    [string] $FalconAccessToken
)
begin {

    if ($FalconAccessToken) {
        if ($FalconCloud -eq "autodiscover") {
            $Message = 'Unable to auto discover Falcon region using access token, please provide FalconCloud'
            throw $Message
        }

    }

    $ScriptName = $MyInvocation.MyCommand.Name
    $ScriptPath = if (!$PSScriptRoot) {
        Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
    }
    else {
        $PSScriptRoot
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
            default { throw "Provided region $xCsRegion is invalid. Please set FalconCloud to a valid region or 'autodiscover'"; break }
        }
        return $Output
    }

    function Invoke-FalconAuth([hashtable] $WebRequestParams, [string] $BaseUrl, [hashtable] $Body, [string] $FalconCloud) {
        $Headers = @{'Accept' = 'application/json'; 'Content-Type' = 'application/x-www-form-urlencoded'; 'charset' = 'utf-8' }
        $Headers.Add('User-Agent', 'crowdstrike-falcon-scripts/1.7.4')
        if ($FalconAccessToken) {
            $Headers.Add('Authorization', "bearer $($FalconAccessToken)")
        }
        else {
            try {
                $response = Invoke-WebRequest @WebRequestParams -Uri "$($BaseUrl)/oauth2/token" -UseBasicParsing -Method 'POST' -Headers $Headers -Body $Body
                $content = ConvertFrom-Json -InputObject $response.Content
                Write-VerboseLog -VerboseInput $content -PreMessage 'Invoke-FalconAuth - $content:'

                if ([string]::IsNullOrEmpty($content.access_token)) {
                    $Message = 'Unable to authenticate to the CrowdStrike Falcon API. Please check your credentials and try again.'
                    throw $Message
                }

                if ($GetAccessToken -eq $true) {
                    Write-Output $content.access_token | out-host
                    exit
                }

                $Headers.Add('Authorization', "bearer $($content.access_token)")
            }
            catch {
                # Handle redirects
                Write-Verbose "Invoke-FalconAuth - CAUGHT EXCEPTION - `$_.Exception.Message`r`n$($_.Exception.Message)"
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
                            Write-Verbose "Received a redirect to $region. Setting FalconCloud to $region"
                        }
                        else {
                            $Message = 'Received a redirect but no X-Cs-Region header was provided. Unable to autodiscover the FalconCloud. Please set FalconCloud to the correct region.'
                            Write-FalconLog -Source 'Invoke-FalconAuth' -Message $Message
                            throw $Message
                        }

                        $BaseUrl = Get-FalconCloud($region)
                        $BaseUrl, $Headers = Invoke-FalconAuth -WebRequestParams $WebRequestParams -BaseUrl $BaseUrl -Body $Body -FalconCloud $FalconCloud

                    }
                    else {
                        $Message = "Received a redirect. Please set FalconCloud to 'autodiscover' or the correct region."
                        Write-FalconLog -Source 'Invoke-FalconAuth' -Message $Message
                        throw $Message
                    }
                }
                else {
                    $Message = "Received a $($response.StatusCode) response from $($BaseUrl)/oauth2/token. Please check your credentials and try again. Error: $($response.StatusDescription)"
                    Write-FalconLog -Source 'Invoke-FalconAuth' -Message $Message
                    throw $Message
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

        return $aid
    }

    $WinSystem = [Environment]::GetFolderPath('System')
    $WinTemp = $WinSystem -replace 'system32', 'Temp'
    if (!$LogPath) {
        $LogPath = Join-Path -Path $WinTemp -ChildPath 'csfalcon_uninstall.log'
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

    # Changes the host visibility status in the CrowdStrike Falcon console
    # an action of $hide will hide the host, anything else will unhide the host
    # should only be called to hide/unhide a host that is already in the console
    function Invoke-HostVisibility ([hashtable] $WebRequestParams, [string] $action) {
        if ($action -eq 'hide') {
            $action = 'hide_host'
        }
        else {
            $action = 'unhide_host'
        }

        if (!$aid) {
            $Message = "AID not found on machine. Unable to ${action} host without AID, this may be due to the sensor not being installed or being partially installed."
            Write-FalconLog 'HostVisibilityError' $Message
            throw $Message
        }

        $Body = @{
            'ids' = @($aid)
        }

        $bodyJson = $Body | ConvertTo-Json
        $url = "${BaseUrl}/devices/entities/devices-actions/v2?action_name=${action}"

        try {
            $response = Invoke-WebRequest @WebRequestParams -Uri $url -UseBasicParsing -Method 'POST' -Body $bodyJson -MaximumRedirection 0
            $content = ConvertFrom-Json -InputObject $response.Content
            Write-VerboseLog -VerboseInput $content -PreMessage 'Invoke-HostVisibility - $content:'

            if ($content.errors) {
                $Message = "Error when calling ${action} on host: "
                $Message += Format-FalconResponseError -errors $content.errors
                Write-FalconLog 'HostVisibilityError' $Message
                throw $Message
            }
            else {
                $Message = "Action ${action} executed successfully on host"
                Write-FalconLog 'HostVisibility' $Message
            }
        }
        catch {
            Write-VerboseLog -VerboseInput $_.Exception.Message -PreMessage 'Invoke-HostVisibility - CAUGHT EXCEPTION - $_.Exception.Message:'
            $response = $_.Exception.Response

            if (!$response) {
                $Message = "Unhandled error occurred while performing action '${action}' on host from the CrowdStrike Falcon API. Error: $($_.Exception.Message)"
                Write-FalconLog 'HostVisibilityError' $Message
                throw $Message
            }

            if ($response.StatusCode -eq 409) {
                $Message = "Received a $($response.StatusCode) response from ${url} Error: $($response.StatusDescription)"
                Write-FalconLog 'HostVisibilityError' $Message
                Write-FalconLog 'HostVisibilityError' 'Host already removed from CrowdStrike Falcon'
                # TBD: Should we throw an error here?
            }
            elseif ($response.StatusCode -eq 403) {
                $scope = @{
                    'host' = @('Write')
                }
                $Message = Format-403Error -url $url -scope $scope
                Write-FalconLog 'HostVisibilityError' $Message
                throw $Message
            }
            else {
                $Message = "Received a $($response.StatusCode) response from ${url}. Error: $($response.StatusDescription)"
                Write-FalconLog 'HostVisibilityError' $Message
                throw $Message
            }
        }
    }
}
process {
    if (!$GetAccessToken) {
        if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) {
            $Message = 'Unable to proceed without administrative privileges'
            throw $Message
        }

        $AgentService = Get-Service -Name CSAgent -ErrorAction SilentlyContinue
        if (!$AgentService) {
            $Message = "'CSFalconService' service not found, already uninstalled"
            Write-FalconLog 'CheckService' $Message
            break
        }
    }
    # Check if credentials were provided
    $AuthProvided = (Test-FalconCredential $FalconClientId $FalconClientSecret) -or $FalconAccessToken

    if ($AuthProvided) {
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
    elseif ($RemoveHost) {
        $Message = 'Unable to remove host without credentials, please provide FalconClientId and FalconClientSecret or FalconAccessToken'
        throw $Message
    }
    elseif ($GetAccessToken) {
        $Message = 'Unable to get access token without credentials, please provide FalconClientId and FalconClientSecret'
        throw $Message
    }

    $UninstallerPath = $null
    switch ($UninstallTool) {
        'installcache' {
            $UninstallerName = '^((WindowsSensor|FalconSensor_Windows).*\.)(exe)$'
            $UninstallerPathDir = 'C:\ProgramData\Package Cache'

            if (Test-Path -Path $UninstallerPathDir) {
                $UninstallerPath = Get-ChildItem -Path $UninstallerPathDir -Recurse | Where-Object { $_.Name -match $UninstallerName } | ForEach-Object { $_.FullName } | Sort-Object -Descending | Select-Object -First 1
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
        Write-FalconLog 'CheckUninstaller' $Message
        throw $Message
    }

    # Grab AID before uninstalling. Only relevant if $RemoveHost or if $AuthProvided and !$MaintenanceToken
    if ($RemoveHost -or ($AuthProvided -and !$MaintenanceToken)) {
        Write-FalconLog 'GetAID' 'Getting AID before uninstalling'
        $aid = Get-AID
        if (!$aid) {
            $Message = 'AID not found in registry. This could be due to the agent not being installed or being partially installed.'
        }
        else {
            $Message = "Found AID: $aid"
        }
        Write-FalconLog 'GetAID' $Message
    }

    if ($RemoveHost) {
        # Remove host from CrowdStrike Falcon
        Write-FalconLog 'RemoveHost' 'Removing host from Falcon console'
        Invoke-HostVisibility -WebRequestParams $WebRequestParams -action 'hide'
    }

    if ($MaintenanceToken) {
        # Assume the maintenance token is a valid Token and skip API calls
        $UninstallParams += " MAINTENANCE_TOKEN=$MaintenanceToken"
    }
    else {
        if ($aid) {
            # Assume user wants to use API to retrieve token
            # Build request body for retrieving maintenance token
            Write-FalconLog 'GetToken' 'Retrieving maintenance token from the CrowdStrike Falcon API.'
            $Body = @{
                'device_id'     = $aid
                'audit_message' = 'CrowdStrike Falcon Uninstall Powershell Script'
            }

            $bodyJson = $Body | ConvertTo-Json
            $url = "${BaseUrl}/policy/combined/reveal-uninstall-token/v1"

            try {
                $response = Invoke-WebRequest @WebRequestParams -Uri $url -UseBasicParsing -Method 'POST' -Body $bodyJson -MaximumRedirection 0
                $content = ConvertFrom-Json -InputObject $response.Content
                Write-VerboseLog -VerboseInput $content -PreMessage 'GetToken - $content:'

                if ($content.errors) {
                    $Message = 'Failed to retrieve maintenance token: '
                    $Message += Format-FalconResponseError -errors $content.errors
                    Write-FalconLog 'GetTokenError' $Message
                    throw $Message
                }
                else {
                    $MaintenanceToken = $content.resources[0].uninstall_token
                    Write-FalconLog 'GetToken' "Retrieved maintenance token: $MaintenanceToken"
                    $UninstallParams += " MAINTENANCE_TOKEN=$MaintenanceToken"
                }
            }
            catch {
                Write-VerboseLog -VerboseInput $_.Exception.Message -PreMessage 'GetToken - CAUGHT EXCEPTION - $_.Exception.Message:'
                $response = $_.Exception.Response

                if (!$response) {
                    $Message = "Unhandled error occurred while retrieving maintenance token from the CrowdStrike Falcon API. Error: $($_.Exception.Message)"
                    Write-FalconLog 'GetTokenError' $Message
                    throw $Message
                }

                if ($response.StatusCode -eq 403) {
                    $scope = @{
                        'Sensor update policies' = @('Write')
                    }

                    $Message = Format-403Error -url $url -scope $scope

                    Write-FalconLog 'GetTokenError' $Message
                    throw $Message
                }
                else {
                    $Message = "Received a $($response.StatusCode) response from $($BaseUrl)$($url) Error: $($response.StatusDescription)"
                    Write-FalconLog 'GetTokenError' $Message
                    throw $Message
                }
            }
        }
    }

    # Begin uninstallation
    Write-FalconLog 'Uninstaller' 'Uninstalling the Falcon Sensor...'
    Write-FalconLog 'StartProcess' "Starting uninstaller with parameters: '$UninstallParams'"
    $UninstallerProcess = Start-Process -FilePath "$UninstallerPath" -ArgumentList $UninstallParams -PassThru -Wait
    $UninstallerProcessId = $UninstallerProcess.Id
    Write-FalconLog 'StartProcess' "Started '$UninstallerPath' ($UninstallerProcessId)"
    if ($UninstallerProcess.ExitCode -ne 0) {
        Write-VerboseLog -VerboseInput $UninstallerProcess -PreMessage 'PROCESS EXIT CODE ERROR - $UninstallerProcess:'
        if ($UninstallerProcess.ExitCode -eq 106) {
            $Message = 'Unable to uninstall, Falcon Sensor is protected with a maintenance token. Provide a valid maintenance token and try again.'
        }
        else {
            $Message = "Uninstaller returned exit code $($UninstallerProcess.ExitCode)"
        }
        Write-FalconLog 'UninstallError' $Message

        if ($RemoveHost) {
            Write-FalconLog 'UninstallError' 'Uninstall failed, attempting to restore host visibility...'
            Invoke-HostVisibility -WebRequestParams $WebRequestParams -action 'show'
        }
        throw $Message
    }

    $AgentService = Get-Service -Name CSAgent -ErrorAction SilentlyContinue
    if ($AgentService -and $AgentService.Status -eq 'Running') {
        $Message = 'Service uninstall failed...'
        Write-FalconLog 'ServiceError' $Message
        throw $Message
    }

    if (Test-Path -Path HKLM:\System\Crowdstrike) {
        $Message = 'Registry key removal failed...'
        Write-FalconLog 'RegistryError' $Message
        throw $Message
    }

    if (Test-Path -Path"${env:SYSTEMROOT}\System32\drivers\CrowdStrike") {
        $Message = 'Driver removal failed...'
        Write-FalconLog 'DriverError' $Message
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

    Write-FalconLog 'Uninstaller' 'Falcon Sensor was successfully uninstalled.'
}
end {
    Write-FalconLog 'EndScript' 'Script completed.'
    $message = "`r`nSee the full log contents at '$($LogPath)'"
    Write-Output $message
}
