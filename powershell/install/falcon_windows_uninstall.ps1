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
Sensor uninstall parameters ['/uninstall /quiet' if left undefined]. Note: '/uninstall' parameter is automatically removed when UninstallTool='standalone' as it's incompatible with CsUninstallTool.exe.
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
# Read inside Test-FalconDebugEnabled, which the rule does not follow.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'FalconDebug')]
# Debug markers must stay out of the pipeline and out of the on-disk log.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
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
    [ValidateSet('autodiscover', 'us-1', 'us-2', 'us-3', 'eu-1', 'us-gov-1', 'us-gov-2')]
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
    [string] $FalconAccessToken,

    [Parameter(Position = 16)]
    [string] $UserAgent,

    [Parameter(Position = 17)]
    [switch] $FalconDebug
)
begin {
    Set-PSDebug -Off


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
                        $Message = 'Unable to authenticate to the CrowdStrike Falcon API. Please check your credentials and try again.'
                        throw $Message
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
                    $Message = "Unhandled error occurred while authenticating to the CrowdStrike Falcon API. Error: $($_.Exception.Message)"
                    Write-FalconLog -Source 'Invoke-FalconAuth' -Message $Message
                    throw $Message
                }

                if ([int]$response.StatusCode -in @(301, 302, 303, 307, 308)) {
                    $RedirectResponse = $response
                }
                else {
                    $Message = "Received a $($response.StatusCode) response from $($BaseUrl)/oauth2/token. Please check your credentials and try again. Error: $($response.StatusDescription)"
                    Write-FalconLog -Source 'Invoke-FalconAuth' -Message $Message
                    throw $Message
                }
            }

            if ($RedirectResponse) {
                if ($FalconCloud -ne 'autodiscover') {
                    $Message = "Received a redirect. Please set FalconCloud to 'autodiscover' or the correct region."
                    Write-FalconLog -Source 'Invoke-FalconAuth' -Message $Message
                    throw $Message
                }

                $region = Get-FalconRegionHeader -Response $RedirectResponse

                if ([string]::IsNullOrEmpty($region)) {
                    $Message = 'Received a redirect but no X-Cs-Region header was provided. Unable to autodiscover the FalconCloud. Please set FalconCloud to the correct region.'
                    Write-FalconLog -Source 'Invoke-FalconAuth' -Message $Message
                    throw $Message
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
        foreach ($err in $errors) {
            $Message += "`r`n`t $($err.message)"
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
            Write-FalconDebug -Step 'Invoke-HostVisibility' -Message 'step=request path=/devices/entities/devices-actions/v2'
            $response = Invoke-WebRequest @WebRequestParams -Uri $url -UseBasicParsing -Method 'POST' -Body $bodyJson -MaximumRedirection 0
            Write-FalconDebug -Step 'Invoke-HostVisibility' -Message "step=response http_status=$([int]$response.StatusCode)"
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
            $debugStatus = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 'none' }
            Write-FalconDebug -Step 'Invoke-HostVisibility' -Message "http_status=$debugStatus error=request_failed"
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
    Write-FalconDebug -Step 'start' -Pairs ([ordered]@{
            version                = "$ScriptVersion (PowerShell $($PSVersionTable.PSVersion) $PSEditionValue)"
            cloud                  = $FalconCloud
            client_id_set          = if ($FalconClientId) { 'yes' } else { 'no' }
            client_secret_set      = if ($FalconClientSecret) { 'yes' } else { 'no' }
            access_token_set       = if ($FalconAccessToken) { 'yes' } else { 'no' }
            member_cid_set         = if ($MemberCid) { 'yes' } else { 'no' }
            maintenance_token_set  = if ($MaintenanceToken) { 'yes' } else { 'no' }
            proxy_set              = if ($ProxyHost) { 'yes' } else { 'no' }
        })
    Write-FalconDebug -Step 'environment' -Pairs ([ordered]@{
            os         = 'windows'
            os_version = [System.Environment]::OSVersion.Version.ToString()
            os_arch    = $env:PROCESSOR_ARCHITECTURE
            run_as     = if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { 'admin' } else { 'user' }
        })
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

        # Check if we just need the token
        if ($GetAccessToken -eq $true) {
            $token = $Headers['Authorization'] -replace '^bearer\s+', ''
            Write-Output $token
            exit 0
        }
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
        Write-FalconDebug -Step 'GetAID' -Pairs ([ordered]@{ aid = if ($aid) { $aid } else { 'none' } })
    }

    if ($RemoveHost) {
        # Remove host from CrowdStrike Falcon
        Write-FalconLog 'RemoveHost' 'Removing host from Falcon console'
        Invoke-HostVisibility -WebRequestParams $WebRequestParams -action 'hide'
    }

    if ($MaintenanceToken) {
        # Assume the maintenance token is a valid Token and skip API calls
        $UninstallParams += " MAINTENANCE_TOKEN=$MaintenanceToken"
        Write-FalconDebug -Step 'GetToken' -Pairs ([ordered]@{ source = 'param'; maintenance_token_set = 'yes' })
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
                Write-FalconDebug -Step 'GetToken' -Message 'step=request path=/policy/combined/reveal-uninstall-token/v1'
                $response = Invoke-WebRequest @WebRequestParams -Uri $url -UseBasicParsing -Method 'POST' -Body $bodyJson -MaximumRedirection 0
                Write-FalconDebug -Step 'GetToken' -Message "step=response http_status=$([int]$response.StatusCode)"
                $content = ConvertFrom-Json -InputObject $response.Content

                if ($content.errors) {
                    $Message = 'Failed to retrieve maintenance token: '
                    $Message += Format-FalconResponseError -errors $content.errors
                    Write-FalconLog 'GetTokenError' $Message
                    throw $Message
                }
                else {
                    $MaintenanceToken = $content.resources[0].uninstall_token
                    Write-FalconLog 'GetToken' 'Retrieved maintenance token'
                    $UninstallParams += " MAINTENANCE_TOKEN=$MaintenanceToken"
                    Write-FalconDebug -Step 'GetToken' -Pairs ([ordered]@{ source = 'api'; maintenance_token_set = 'yes' })
                }
            }
            catch {
                $debugStatus = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 'none' }
                Write-FalconDebug -Step 'GetToken' -Message "http_status=$debugStatus error=request_failed"
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

    # Process UninstallParams based on UninstallTool selection
    if ($UninstallTool -eq 'standalone') {
        # Check if /uninstall parameter is present
        if ($UninstallParams -match '/?uninstall') {
            $UninstallParams = $UninstallParams -replace '/?uninstall\s*', '' -replace '^\s+|\s+$', ''
            Write-FalconLog 'ParamValidation' "Removed '/uninstall' parameter for standalone uninstaller; parameter values omitted from the log"
        }

        # Ensure we have at least /quiet parameter
        if ([string]::IsNullOrWhiteSpace($UninstallParams)) {
            $UninstallParams = '/quiet'
            Write-FalconLog 'ParamValidation' "Applied default '/quiet' parameter for standalone uninstaller"
        }
    }

    # Begin uninstallation
    Write-FalconLog 'Uninstaller' 'Uninstalling the Falcon Sensor...'
    Write-FalconLog 'StartProcess' 'Starting uninstaller; command-line parameters omitted from the log because they may contain sensitive values'
    $UninstallerProcess = Start-Process -FilePath "$UninstallerPath" -ArgumentList $UninstallParams -PassThru -Wait
    $UninstallerProcessId = $UninstallerProcess.Id
    Write-FalconLog 'StartProcess' "Started '$UninstallerPath' ($UninstallerProcessId)"
    Write-FalconDebug -Step 'StartProcess' -Pairs ([ordered]@{ step = 'result'; exit_code = $UninstallerProcess.ExitCode })
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
