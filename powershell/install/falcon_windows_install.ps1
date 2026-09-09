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
.PARAMETER FalconDebug
Print redacted progress markers: detected OS and PowerShell version, the exact sensor
query filter, how many installers matched and which was chosen, the API route and HTTP
status for every call, and the sensor version installed plus the AID (that version is the one resolved from
the policy or query, not re-read from the binary). Values are dropped
unless the key is on a fixed allow-list, so secrets cannot appear. Also honors `$env:FALCON_DEBUG=1`.
Do not use `Set-PSDebug -Trace` or the common `-Debug` parameter for support; they print credentials.

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
# Read inside Test-FalconDebugEnabled, which the rule does not follow.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'FalconDebug')]
# Debug markers must stay out of the pipeline and out of the on-disk log.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
param(
    [Parameter(Position = 1)]
    [ValidateSet('autodiscover', 'us-1', 'us-2', 'us-3', 'eu-1', 'us-gov-1', 'us-gov-2')]
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
    [string] $UserAgent,

    [Parameter(Position = 20)]
    [switch] $FalconDebug
)
begin {
    Set-PSDebug -Off

    if ($PSVersionTable.PSVersion -lt '3.0')
    { throw "This script requires a miniumum PowerShell 3.0" }

    $ScriptName = $MyInvocation.MyCommand.Name
    $ScriptPath = if (!$PSScriptRoot) {
        Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
    }
    else {
        $PSScriptRoot
    }

    $ScriptVersion = "1.13.0"
    $BaseUserAgent = "crowdstrike-falcon-scripts/$ScriptVersion"
    $FullUserAgent = if ($UserAgent) {
        "$BaseUserAgent $UserAgent"
    } else {
        $BaseUserAgent
    }
    # PSEdition is absent on PowerShell 3/4; Desktop is the only edition they had.
    $PSEditionValue = if ($PSVersionTable.PSEdition) { $PSVersionTable.PSEdition } else { 'Desktop' }

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

    function Test-FalconDebugEnabled {
        if ($FalconDebug) { return $true }
        if ($env:FALCON_DEBUG -match '^(1|true)\z') { return $true }
        return $false
    }

    # Allow-list, the single decision point for both marker paths. Only known-safe
    # keys keep their value; everything else is dropped, so a future debug line
    # cannot leak a secret by accident.
    function Protect-FalconDebugPair([string] $Key, [string] $Value) {
        $SafeKeys = @(
            'step', 'source', 'error', 'stage',
            'cloud', 'old_cloud', 'new_cloud', 'region', 'region_hint', 'sensor_cloud',
            'http_status', 'curl_exit', 'exit_code', 'path', 'filter', 'sort',
            'os', 'os_version', 'os_arch', 'os_family', 'kernel', 'pkg_manager', 'distro_id', 'run_as',
            'count', 'index', 'decrement', 'version', 'sensor_version', 'policy_version', 'file_type', 'sha',
            'installer', 'bytes', 'sha_verify', 'billing', 'backend', 'apd', 'aid', 'cid_source',
            'tags_count', 'grouping_tags_count', 'sensor_type', 'param', 'registry', 'repository', 'tag',
            'client_id_set', 'client_secret_set', 'access_token_set', 'member_cid_set',
            'provisioning_token_set', 'maintenance_token_set', 'proxy_set', 'policy_name_set',
            'tags_set', 'grouping_tags_set'
        )
        if ($SafeKeys -ccontains $Key) { return "$Key=$Value" }
        return "$Key=[DROPPED]"
    }

    function Protect-FalconDebugMessage([string] $Message) {
        $Filtered = @()
        foreach ($Token in ($Message -split '\s+')) {
            if ([string]::IsNullOrEmpty($Token)) { continue }
            $Split = $Token.IndexOf('=')
            if ($Split -lt 1) { continue }
            $Filtered += Protect-FalconDebugPair $Token.Substring(0, $Split) $Token.Substring($Split + 1)
        }
        return ($Filtered -join ' ')
    }

    # Write-Host on purpose: keeps markers out of the pipeline and out of the log file.
    function Write-FalconDebug {
        param(
            [Parameter(Mandatory = $true)][string] $Step,
            [string] $Message,
            [System.Collections.IDictionary] $Pairs
        )
        if (-not (Test-FalconDebugEnabled)) { return }
        $Parts = @()
        if ($Message) { $Parts += Protect-FalconDebugMessage $Message }
        # -Pairs is required for any value that can contain a space, such as an FQL
        # filter holding a multi-word policy name. Splitting a joined string cannot
        # carry those safely: a bare word would be glued onto the previous value.
        if ($Pairs) {
            foreach ($Key in $Pairs.Keys) {
                $Parts += Protect-FalconDebugPair ([string]$Key) ([string]$Pairs[$Key])
            }
        }
        $Filtered = ($Parts | Where-Object { $_ }) -join ' '
        if ($Filtered) {
            Write-Host "FALCON_DEBUG: $Step $Filtered"
        }
        else {
            Write-Host "FALCON_DEBUG: $Step"
        }
    }

    function Get-FalconCloud ([string] $xCsRegion) {
        $Output = switch ($xCsRegion) {
            'autodiscover' { 'https://api.crowdstrike.com'; break }
            'us-1' { 'https://api.crowdstrike.com'; break }
            'us-2' { 'https://api.us-2.crowdstrike.com'; break }
            'us-3' { 'https://api.us-3.crowdstrike.com'; break }
            'eu-1' { 'https://api.eu-1.crowdstrike.com'; break }
            'us-gov-1' { 'https://api.laggar.gcw.crowdstrike.com'; break }
            'us-gov-2' { 'https://api.us-gov-2.crowdstrike.mil'; break }
            default { throw "Provided region $xCsRegion is invalid. Please set FalconCloud to a valid region or 'autodiscover'"; break }
        }
        return $Output
    }

    function Get-FalconRegionHeader($Response) {
        # Reads X-Cs-Region. The header collection type differs by platform and
        # by which code path produced it (HttpResponseHeaders vs
        # WebHeaderCollection vs a Dictionary), so probe by type/method instead
        # of assuming one shape.
        if (!$Response) {
            return $null
        }
        $ResponseHeaders = $Response.Headers
        if (!$ResponseHeaders) {
            return $null
        }
        if ($ResponseHeaders -is [System.Net.WebHeaderCollection]) {
            return $ResponseHeaders['X-Cs-Region']
        }
        $HeaderMethods = @($ResponseHeaders.PSObject.Methods.Name)
        # ContainsKey first: HttpResponseHeaders lacks it, so this can't misfire
        # on PowerShell 7.
        if ($HeaderMethods -contains 'ContainsKey') {
            if ($ResponseHeaders.ContainsKey('X-Cs-Region')) {
                return @($ResponseHeaders['X-Cs-Region'])[0]
            }
            return $null
        }
        if ($HeaderMethods -contains 'Contains') {
            if ($ResponseHeaders.Contains('X-Cs-Region')) {
                return @($ResponseHeaders.GetValues('X-Cs-Region'))[0]
            }
            return $null
        }
        return $null
    }

    function Invoke-FalconAuth([hashtable] $WebRequestParams, [string] $BaseUrl, [hashtable] $Body, [string] $FalconCloud) {
        $Headers = @{'Accept' = 'application/json'; 'Content-Type' = 'application/x-www-form-urlencoded'; 'charset' = 'utf-8' }
        $Headers.Add('User-Agent', $FullUserAgent)
        if ($FalconAccessToken) {
            Write-FalconDebug -Step 'Invoke-FalconAuth' -Message "source=access_token cloud=${FalconCloud}"
            $Headers.Add('Authorization', "bearer $($FalconAccessToken)")
        }
        else {
            # A 3xx here is the region auto-discovery hint (X-Cs-Region), not an
            # error. -MaximumRedirection 0 blocks it because 307/308 replay the
            # secret in the body. PowerShell 7 throws it; Windows PowerShell 5.1
            # returns it, and both funnel into $RedirectResponse and are handled once
            # below.
            $RedirectResponse = $null
            try {
                Write-FalconDebug -Step 'Invoke-FalconAuth' -Message "step=request cloud=${FalconCloud}"
                $response = Invoke-WebRequest @WebRequestParams -Uri "$($BaseUrl)/oauth2/token" -UseBasicParsing -Method 'POST' -Headers $Headers -Body $Body -MaximumRedirection 0
                # Status marker before ConvertFrom-Json: on Windows PowerShell 5.1 a
                # 308 is returned, not thrown, and parsing it would fail first.
                Write-FalconDebug -Step 'Invoke-FalconAuth' -Message "step=response http_status=$([int]$response.StatusCode) cloud=${FalconCloud}"

                if ([int]$response.StatusCode -in @(301, 302, 303, 307, 308)) {
                    $RedirectResponse = $response
                }
                else {
                    $content = ConvertFrom-Json -InputObject $response.Content

                    if ([string]::IsNullOrEmpty($content.access_token)) {
                        $message = 'Unable to authenticate to the CrowdStrike Falcon API. Please check your credentials and try again.'
                        throw $message
                    }

                    $Headers.Add('Authorization', "bearer $($content.access_token)")
                }
            }
            catch {
                # Status only. Never log the exception, its message, or the response:
                # they can carry the request body and the Authorization header.
                $debugStatus = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 'none' }
                Write-FalconDebug -Step 'Invoke-FalconAuth' -Message "http_status=$debugStatus error=oauth_request_failed"
                $response = $_.Exception.Response

                if (!$response) {
                    $message = "Unhandled error occurred while authenticating to the CrowdStrike Falcon API. Error: $($_.Exception.Message)"
                    Write-FalconLog -Source 'Invoke-FalconAuth' -Message $message
                    throw $message
                }

                if ([int]$response.StatusCode -in @(301, 302, 303, 307, 308)) {
                    $RedirectResponse = $response
                }
                else {
                    $message = "Received a $($response.StatusCode) response from $($BaseUrl)/oauth2/token. Please check your credentials and try again. Error: $($response.StatusDescription)"
                    Write-FalconLog -Source 'Invoke-FalconAuth' -Message $message
                    throw $message
                }
            }

            if ($RedirectResponse) {
                if ($FalconCloud -ne 'autodiscover') {
                    $message = "Received a redirect. Please set FalconCloud to 'autodiscover' or the correct region."
                    Write-FalconLog -Source 'Invoke-FalconAuth' -Message $message
                    throw $message
                }

                $region = Get-FalconRegionHeader -Response $RedirectResponse

                if ([string]::IsNullOrEmpty($region)) {
                    $message = 'Received a redirect but no X-Cs-Region header was provided. Unable to autodiscover the FalconCloud. Please set FalconCloud to the correct region.'
                    Write-FalconLog -Source 'Invoke-FalconAuth' -Message $message
                    throw $message
                }

                Write-Verbose "Received a redirect to $region. Setting FalconCloud to $region"
                # Get-FalconCloud validates the region against its own allowlist,
                # not the Location header.
                $BaseUrl = Get-FalconCloud($region)
                # Printed only after validation, so a hostile header cannot inject
                # arbitrary text into the console.
                Write-FalconDebug -Step 'Invoke-FalconAuth' -Message "step=region_retry region=$region"
                $BaseUrl, $Headers = Invoke-FalconAuth -WebRequestParams $WebRequestParams -BaseUrl $BaseUrl -Body $Body -FalconCloud $FalconCloud
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

    # Reads the AID for the debug marker only; registration is asynchronous, so
    # a missing AID right after install is normal.
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
                continue
            }
        }
        return $aid
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
        foreach ($err in $errors) {
            $message += "`r`n`t $($err.message)"
        }
        return $message
    }

    function Get-ResourceContent([hashtable] $WebRequestParams, [string] $url, [string] $logKey, [hashtable] $scope, [string] $errorMessage) {
        try {
            Write-FalconDebug -Step 'Get-ResourceContent' -Message "step=request path=$(([Uri]$url).AbsolutePath)"
            $response = Invoke-WebRequest @WebRequestParams -Uri $url -UseBasicParsing -Method 'GET' -MaximumRedirection 0
            Write-FalconDebug -Step 'Get-ResourceContent' -Message "step=response http_status=$([int]$response.StatusCode)"
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
            $debugStatus = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 'none' }
            Write-FalconDebug -Step 'Get-ResourceContent' -Message "http_status=$debugStatus error=request_failed"
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
            Write-FalconDebug -Step 'Invoke-FalconDownload' -Message "step=request path=$(([Uri]$url).AbsolutePath)"
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
    Write-FalconDebug -Step 'start' -Pairs ([ordered]@{
            version           = "$ScriptVersion (PowerShell $($PSVersionTable.PSVersion) $PSEditionValue)"
            cloud             = $FalconCloud
            client_id_set     = if ($FalconClientId) { 'yes' } else { 'no' }
            client_secret_set = if ($FalconClientSecret) { 'yes' } else { 'no' }
            access_token_set  = if ($FalconAccessToken) { 'yes' } else { 'no' }
            member_cid_set    = if ($MemberCid) { 'yes' } else { 'no' }
            proxy_set         = if ($ProxyHost) { 'yes' } else { 'no' }
            policy_name_set   = if ($SensorUpdatePolicyName -ne 'platform_default') { 'yes' } else { 'no' }
        })
    Write-FalconDebug -Step 'environment' -Pairs ([ordered]@{
            os         = 'windows'
            os_version = [System.Environment]::OSVersion.Version.ToString()
            os_arch    = $env:PROCESSOR_ARCHITECTURE
            run_as     = if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { 'admin' } else { 'user' }
        })
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

        # Check if we just need the token
        if ($GetAccessToken -eq $true) {
            $token = $Headers['Authorization'] -replace '^bearer\s+', ''
            Write-Output $token
            exit 0
        }
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
    Write-FalconDebug -Step 'GetPolicy' -Pairs ([ordered]@{ step = 'query'; path = '/policy/combined/sensor-update/v2'; filter = $filter })
    $url = "${BaseUrl}/policy/combined/sensor-update/v2?filter=$([System.Web.HttpUtility]::UrlEncode($filter)))"
    $policy_scope = @{
        'Sensor update policies' = @('Read')
    }
    $policyDetails = Get-ResourceContent -WebRequestParams $WebRequestParams -url $url -logKey 'GetPolicy' -scope $policy_scope -errorMessage "Unable to fetch policy details from the CrowdStrike Falcon API."
    $policyId = $policyDetails.id
    $build = $policyDetails[0].settings.build
    $rawVersion = $policyDetails[0].settings.sensor_version

    # Make sure we got a version from the policy
    if (!$rawVersion) {
        $message = "Unable to retrieve sensor version from policy '$($SensorUpdatePolicyName)'. Please check the policy and try again."
        Write-FalconLog 'GetPolicy' $message
        throw $message
    }

    # Normalize version to remove LTS suffixes for API compatibility
    $version = ($rawVersion -split '\s+')[0].Trim()

    $message = "Retrieved sensor policy details: Policy ID: $policyId, Build: $build, Version: $version"
    Write-FalconLog 'GetPolicy' $message
    Write-FalconDebug -Step 'GetPolicy' -Pairs ([ordered]@{ step = 'resolved'; policy_version = $version })

    # Get installer details based on normalized policy version
    $message = "Retrieving installer details for sensor version: '$($version)'"
    Write-FalconLog 'GetInstaller' $message
    $installerFilter = "platform:'windows'+version:'$($version)'"
    Write-FalconDebug -Step 'GetInstaller' -Pairs ([ordered]@{ step = 'query'; path = '/sensors/combined/installers/v3'; filter = $installerFilter; sort = 'none' })
    $encodedFilter = [System.Web.HttpUtility]::UrlEncode($installerFilter)
    $url = "${BaseUrl}/sensors/combined/installers/v3?filter=${encodedFilter}"
    $installer_scope = @{
        'Sensor Download' = @('Read')
    }
    $installerDetails = Get-ResourceContent -WebRequestParams $WebRequestParams -url $url -logKey 'GetInstaller' -scope $installer_scope -errorMessage "Unable to fetch installer details from the CrowdStrike Falcon API."
    Write-FalconDebug -Step 'GetInstaller' -Pairs ([ordered]@{ step = 'matched'; count = @($installerDetails).Count })

    if ( $installerDetails.sha256 -and $installerDetails.name ) {
        $cloudHash = $installerDetails.sha256
        $cloudFile = $installerDetails.name
        $message = "Found installer: ($cloudFile) with sha256: '$cloudHash'"
        Write-FalconLog 'GetInstaller' $message
        $shaString = [string]$cloudHash
        Write-FalconDebug -Step 'GetInstaller' -Pairs ([ordered]@{
                step      = 'selected'
                index     = 0
                file_type = "$($installerDetails.file_type)"
                sha       = $shaString.Substring(0, [Math]::Min(12, $shaString.Length))
            })
    }
    else {
        $message = "Failed to retrieve installer details."
        Write-FalconLog 'GetInstaller' $message
        throw $message
    }

    # Download the installer
    $localFile = Join-Path -Path $WinTemp -ChildPath $cloudFile
    Write-FalconLog 'DownloadFile' "Downloading installer to: '$localFile'"
    $url = "${BaseUrl}/sensors/entities/download-installer/v3?id=$cloudHash"
    Invoke-FalconDownload -WebRequestParams $WebRequestParams -url $url -Outfile $localFile

    if (Test-Path $localFile) {
        $localHash = Get-InstallerHash -Path $localFile
        $message = "Successfull downloaded installer '$localFile' ($localHash)"
        Write-FalconLog 'DownloadFile' $message
        Write-FalconDebug -Step 'DownloadFile' -Pairs ([ordered]@{ step = 'downloaded'; installer = $localFile; bytes = (Get-Item $localFile).Length })
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
    Write-FalconDebug -Step 'Installer' -Pairs ([ordered]@{
            step                   = 'configure'
            cid_source             = if ($FalconCid) { 'param' } else { 'api' }
            provisioning_token_set = if ($ProvToken) { 'yes' } else { 'no' }
            tags_count             = if ($Tags) { $Tags.Count } else { 0 }
            proxy_set              = if ($ProxyHost) { 'yes' } else { 'no' }
        })
    Write-FalconLog 'Installer' 'Installing Falcon Sensor...'
    Write-FalconLog 'StartProcess' 'Starting installer; command-line parameters omitted from the log because they may contain sensitive values'
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
    # Authoritative install-time version; aid=none is normal here since
    # registration completes asynchronously once the sensor reaches the cloud.
    $InstalledAid = Get-AID
    Write-FalconDebug -Step 'InstallerProcess' -Pairs ([ordered]@{ step = 'installed'; version = $version; aid = if ($InstalledAid) { $InstalledAid } else { 'none' } })
}
end {
    Write-FalconLog 'EndScript' 'Script completed.'
    $message = "`r`nSee the full log contents at: '$($LogPath)'"
    Write-Output $message
}
