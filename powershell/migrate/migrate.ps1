<#
.SYNOPSIS
Migrate a sensor to another falcon cloud tenant.
.DESCRIPTION
Removes and installs the sensor using the new cloud and CID.

Falcon and Sensor tags are migrated to the new installation.
.PARAMETER FalconClientId
CrowdStrike Falcon OAuth2 API Client Id [Required]
.PARAMETER FalconClientSecret
CrowdStrike Falcon OAuth2 API Client Secret [Required]
.PARAMETER FalconCloud
CrowdStrike Falcon OAuth2 API Hostname [default: 'autodiscover']
.PARAMETER MemberCid
Member CID, used only in multi-CID ("Falcon Flight Control") configurations and with a parent management CID.
.PARAMETER SensorUpdatePolicyName
Sensor Update Policy name to check for assigned sensor version [default: 'platform_default']
.PARAMETER InstallParams
Sensor installation parameters, without your CID value ['/install /quiet /noreboot' if left undefined]
.PARAMETER LogPath
Script log location ['Windows\Temp\csfalcon_install.log' if left undefined]
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
#>
#Requires -Version 3.0

[CmdletBinding()]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'DeleteInstaller')]
param(
  
  [Parameter(Position = 1)]
  [ValidatePattern('\w{32}')]
  [string] $FalconClientId,

  [Parameter(Position = 2)]
  [ValidatePattern('\w{40}')]
  [string] $FalconClientSecret,
  
  [Parameter(Position = 3)]
  [ValidateSet('autodiscover', 'us-1', 'us-2', 'eu-1', 'us-gov-1')]
  [string] $FalconCloud = 'autodiscover',

  [Parameter(Position = 4)]
  [string] $MemberCid,

  [Parameter(Position = 5)]
  [string] $SensorUpdatePolicyName,

  [Parameter(Position = 6)]
  [string] $InstallParams,

  [Parameter(Position = 7)]
  [string] $LogPath,

  [Parameter(Position = 8)]
  [string] $ProvToken,

  [Parameter(Position = 9)]
  [int] $ProvWaitTime = 1200,

  [Parameter(Position = 10)]
  [string] $Tags,

  [Parameter(Position = 11)]
  [string] $MaintenanceToken,

  [Parameter(Position = 12)]
  [bool] $RemoveHost = $false,

  [Parameter(Position = 13)]
  [string] $UninstallParams = '/uninstall /quiet',

  [Parameter(Position = 14)]
  [ValidateSet('installcache', 'standalone')]
  [string] $UninstallTool = 'installcache',

  [Parameter(Position = 15)]
  [bool] $DeleteInstaller = $true,

  [Parameter(Position = 16)]
  [bool] $DeleteScript = $false,
  
  [Parameter(Position = 17)]
  [bool] $DeleteUninstaller = $true
)