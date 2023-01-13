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
.PARAMETER OldNewFalconClientId
CrowdStrike Falcon OAuth2 API Client Id for the old cloud [Required]
.PARAMETER OldFalconClientSecret
CrowdStrike Falcon OAuth2 API Client Secret for the old cloud [Required]
.PARAMETER NewFalconCloud
CrowdStrike Falcon OAuth2 API Hostname for the new cloud [default: 'autodiscover']
.PARAMETER OldFalconCloud
CrowdStrike Falcon OAuth2 API Hostname for the old cloud [default: 'autodiscover']
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
.PARAMETER DeleteScript
Delete script when complete [default: $false]
.PARAMETER ProvToken
Provisioning token to use for sensor installation [default: $null]
.PARAMETER ProvWaitTime
Time to wait, in seconds, for sensor to provision [default: 1200]
.PARAMETER Tags
A comma-separated list of tags to apply to the host after sensor installation [default: $null]
.PARAMETER MaintenanceToken
Sensor uninstall maintenance token. If left undefined, the script will attempt to retrieve the token from the API assuming the FalconClientId|FalconClientSecret are defined.
.PARAMETER UninstallParams
Sensor uninstall parameters ['/uninstall /quiet' if left undefined]
.PARAMETER UninstallTool
Sensor uninstall tool, local installation cache or CS standalone uninstaller ['installcache' if left undefined]
.PARAMETER DeleteUninstaller
Delete sensor uninstaller package when complete [default: $true]
.PARAMETER DeleteScript
Delete script when complete [default: $true]
.PARAMETER RemoveHost
Remove host from CrowdStrike Falcon [default: $false]
.PARAMETER SkipTags
Opt in/out of migrating tags. Tags passed to the Tags flag will still be added. [default: $false]
.PARAMETER ScriptVersion
Branch or Tag of the install/uninstall scripts to use [default: 'v1.0.0']
#>
#Requires -Version 3.0

[CmdletBinding()]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'DeleteInstaller')]
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
  [Parameter(Position = 9)]
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
  [string] $MaintenanceToken,
  [Parameter(Position = 16)]
  [bool] $RemoveHost = $false,
  [Parameter(Position = 17)]
  [string] $UninstallParams = '/uninstall /quiet',
  [Parameter(Position = 18)]
  [ValidateSet('installcache', 'standalone')]
  [string] $UninstallTool = 'installcache',
  [Parameter(Position = 19)]
  [bool] $DeleteInstaller = $true,
  [Parameter(Position = 20)]
  [bool] $DeleteScript = $false,
  [Parameter(Position = 21)]
  [bool] $DeleteUninstaller = $true,
  [Parameter(Position = 22)]
  [bool] $SkipTags = $false
)

function Write-Log {
  param(
    [Parameter(ValueFromPipeline = $true)]
    [string] $Message
  )

  $Message >> $LogPath
  Write-Output $Message
}

function Invoke-SetupEnvironment ($Version, $FalconInstallScriptPath, $FalconUninstallScriptPath) {
  if (!(Test-Path $FalconInstallScriptPath)) {
    Write-Log "falcon_windows_install.ps1 not found, downloading github version: ${Version}"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/CrowdStrike/falcon-scripts/${Version}/powershell/install/falcon_windows_install.ps1" -OutFile $FalconInstallScriptPath
  }

  if (!(Test-Path $FalconUninstallScriptPath)) {
    Write-Log "falcon_windows_uninstall.ps1 not found, downloading github version: ${Version}"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/CrowdStrike/falcon-scripts/${Version}/powershell/install/falcon_windows_uninstall.ps1" -OutFile $FalconUninstallScriptPath
  }
}

# Uninstall Falcon Sensor
function Invoke-FalconUninstall {
  $uninstallArgs = @{
    'FalconCloud'        = $OldFalconCloud
    'FalconClientId'     = $OldFalconClientId
    'FalconClientSecret' = $OldFalconClientSecret
    'MemberCid'          = $OldMemberCid
    'RemoveHost'         = $RemoveHost
    'MaintenanceToken'   = $MaintenanceToken
    'UninstallParams'    = $UninstallParams
    'UninstallTool'      = $UninstallTool
    'LogPath'            = $LogPath
    #'DeleteUninstaller'  = $DeleteUninstaller
    #'DeleteScript'       = $DeleteScript
  }
  $argsList = @()

  foreach ($key in $uninstallArgs.Keys) {
    if (![string]::IsNullOrEmpty($uninstallArgs[$key])) {
      $argsList += "-$key $($uninstallArgs[$key])"
    }
  }

  Write-Log "Uninstalling Falcon Sensor..."

  $uninstallerProcess = Start-Process -FilePath $falconUninstallScriptPath -ArgumentList $argsList -Wait -PassThru
  $uninstallerProcessId = $uninstallerProcess.Id
  Write-Log "Uninstaller process ID: $uninstallerProcessId"
  if ($uninstallerProcess.ExitCode -ne 0) {
    $message = "Uninstaller process exited with code $($uninstallerProcess.ExitCode)"
    throw $message
  }
}

# Install Falcon Sensor
function Invoke-FalconInstall {
  
  $installArgs = @{
    'FalconCloud'        = $newBaseUrl
    'FalconClientId'     = $NewFalconClientId
    'FalconClientSecret' = $NewFalconClientSecret
    'MemberCid'          = $NewMemberCid
    'InstallParams'      = $InstallParams
    'LogPath'            = $LogPath
    'DeleteInstaller'    = $DeleteInstaller
    'DeleteScript'       = $DeleteScript
    'ProvToken'          = $ProvToken
    'ProvWaitTime'       = $ProvWaitTime
    'Tags'               = $sensorGroupingTags
  }

  $argsList = @()
  foreach ($key in $installArgs.Keys) {
      if (![string]::IsNullOrEmpty($installArgs[$key])) {
          $value = $installArgs[$key]
          if ($value -is [string]) {
              if ($value -ieq 'false') {
                  $value = $False
              }
              elseif ($value -ieq 'true') {
                  $value = $True
              }
          }
          $argsList += "-$key $value"
      }
  }

  Invoke-Expression "& `"$falconInstallScriptPath`" @installArgs"

  Write-Log "Install output: $stdOutput"
  Write-Log "Install error: $stdError"
}

function Get-HeadersAndUrl([string] $FalconClientId, [string] $FalconClientSecret, [string] $MemberCid, [string] $FalconCloud) {
  $headers = @{'Accept' = 'application/json'; 'Content-Type' = 'application/x-www-form-urlencoded'; 'charset' = 'utf-8' }
  $baseUrl = Get-FalconCloud $FalconCloud
  
  $body = @{}
  $body["client_id"] = $FalconClientId
  $body["client_secret"] = $FalconClientSecret
  
  if ($MemberCid) {
    $body["&member_cid"] = $MemberCid
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
  $message = ""
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

# Sets falcon tags
function Set-Tags ([string] $Aid, [array] $Tags, [string] $BaseUrl, $Headers) {
  try {
    $url = "${baseUrl}/devices/entities/devices/tags/v1"
    $errorMessage = ""
    $tagsSet = $false

    $body = @{
      "action"     = "append"
      "device_ids" = @($aid)
      "tags"       = $Tags
    }
    $body = ConvertTo-Json -InputObject $body

    $Headers['Content-Type'] = 'application/json'
    $response = Invoke-WebRequest -Uri $url -UseBasicParsing -Method 'PATCH' -Body $body -Headers $Headers -MaximumRedirection 0
    $content = ConvertFrom-Json -InputObject $response.Content

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
    $response = $_.Exception.Response

    if (!$response) {
      $errorMessage = "Unhandled error occurred while settings tags with the CrowdStrike Falcon API. Error: $($_.Exception.Message)"
    }

    if ($response.StatusCode -eq 403) {
      # TODO: implement real scopes
      $scope = @{
        "host" = @("Write")
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
function Get-Tags ([string] $Aid, [string] $BaseUrl, $Headers) {
  try {
    $url = "${baseUrl}/devices/entities/devices/v2?ids=${aid}"

    $Headers['Content-Type'] = 'application/json'
    $response = Invoke-WebRequest -Uri $url -UseBasicParsing -Method 'GET' -Headers $Headers -MaximumRedirection 0
    $content = ConvertFrom-Json -InputObject $response.Content

    if ($content.errors) {
      $message = "Error when calling getting tags on host: "
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
    $response = $_.Exception.Response

    if (!$response) {
      $message = "Unhandled error occurred while grabbing tags from the CrowdStrike Falcon API. Error: $($_.Exception.Message)"
      throw $message
    }

    if ($response.StatusCode -eq 403) {
      # TODO: implement real scopes
      $scope = @{
        "host" = @("Write")
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

function Split-Tags($tags) {
  $sensorGroupingTags = @()
  $falconGroupingTags = @()

  $tagsArray = $tags -split ' '

  foreach ($tag in $tagsArray) {
    if ($tag -like "SensorGroupingTags/*") {
      $sensorGroupingTags += $tag.Split("/")[1]
    }
    elseif ($tag -like "FalconGroupingTags/*") {
      $falconGroupingTags += $tag
    }
  }

  $sensorGroupingTags = $sensorGroupingTags -join ','

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
  try {
    $response = Invoke-WebRequest -Uri "$($BaseUrl)/oauth2/token" -UseBasicParsing -Method 'POST' -Headers $Headers -Body $Body
    $content = ConvertFrom-Json -InputObject $response.Content

    if ([string]::IsNullOrEmpty($content.access_token)) {
      $message = "Unable to authenticate to the CrowdStrike Falcon API. Please check your credentials and try again."
      throw $message
    }

    $Headers.Add('Authorization', "bearer $($content.access_token)")
  }
  catch {
    # Handle redirects
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
        }
        else {
          $message = "Received a redirect but no X-Cs-Region header was provided. Unable to autodiscover the FalconCloud. Please set FalconCloud to the correct region."
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

if (!(Test-FalconCredential $NewFalconClientId $NewFalconClientSecret)) {
  $message = 'API Credentials for the new cloud are required'
  $message >> $LogPath
  throw $message
}

if (!(Test-FalconCredential $OldFalconClientId $OldFalconClientSecret)) {
  $message = 'API Credentials for the old cloud are required'
  $message >> $LogPath
  throw $message
}

$SCRIPT_VERSION = "v1.0.0"

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$falconInstallScriptPath = Join-Path $scriptPath 'falcon_windows_install.ps1'
$falconUninstallScriptPath = Join-Path $scriptPath 'falcon_windows_uninstall.ps1'
$scriptPath >> $LogPath
$falconInstallScriptPath >> $LogPath
$falconUninstallScriptPath >> $LogPath
$sensorGroupingTags = ""
$falconGroupingTags = @()
$oldAid = Get-AID

Invoke-SetupEnvironment -Version $SCRIPT_VERSION -FalconInstallScriptPath $falconInstallScriptPath -FalconUninstallScriptPath $falconUninstallScriptPath

# Get current tags
if (!$SkipTags) {
  $oldBaseUrl, $oldCloudHeaders = Get-HeadersAndUrl -FalconClientId $OldFalconClientId -FalconClientSecret $OldFalconClientSecret -FalconCloud $OldFalconCloud -MemberCid $OldMemberCid
  $newBaseUrl, $newCloudHeaders = Get-HeadersAndUrl -FalconClientId $NewFalconClientId -FalconClientSecret $NewFalconClientSecret -FalconCloud $NewFalconCloud -MemberCid $NewMemberCid
  
  $tags = Get-Tags -Aid $oldAid -Headers $oldCloudHeaders -BaseUrl $oldCloudHeaders
  "Successfully retrieved tags" >> $LogPath
  $sensorGroupingTags, $falconGroupingTags = Split-Tags -Tags $tags
}

$sensorGroupingTags += $Tags

#Invoke-FalconUninstall
Invoke-FalconInstall

# TODO: Get new AID & wait for it/timeout
$timeout = Get-Date
$timeout = $timeout.AddSeconds(120)
$newAid = Get-AID

while ($null -eq $newAid -and (Get-Date) -lt $timeout) {
  "Waiting for new AID..." >> $LogPath
  Start-Sleep -Seconds 5
  $newAid = Get-AID
}


# Set falcon sensor tags
if (!$SkipTags) {
  if ($falconGroupingTags.Count -gt 0) {
    $timeout = Get-Date
    $timeout = $timeout.AddSeconds(120)
    $deviceNotFoundError = "Device not found."

    $tagsMigrated, $errorMessage = Set-Tags -Aid $newAid -Tags $falconGroupingTags -BaseUrl $newBaseUrl -Headers $newCloudHeaders

    while ($tagsMigrated -eq $false -and (Get-Date) -lt $timeout) {
      # fail if error is not device not found
      if ($errorMessage -ne $deviceNotFoundError) {
        throw $errorMessage
      }

      "Waiting for new AID to be registered..." >> $LogPath
      Start-Sleep -Seconds 5
      $tagsMigratedm, $errorMessage = Set-Tags -Aid $newAid -Tags $falconGroupingTags -BaseUrl $newBaseUrl -Headers $newCloudHeaders
    }
  }
  else {
    "No tags to migrate..." >> $LogPath
  }
}
else {
  "SkipTags is set to true... skipping tag migration" >> $LogPath
}

Write-Log "Migration complete!"
#Stop-Transcript

# Debugging DELETE
$logContent = Get-Content -Path $LogPath
Write-Output $logContent