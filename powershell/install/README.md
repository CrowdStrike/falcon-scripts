# Falcon Powershell Installation Scripts

Powershell scripts to install/uninstall Falcon Sensor through the Falcon APIs on a Windows endpoint.

## Falcon API Permissions

API clients are granted one or more API scopes. Scopes allow access to specific CrowdStrike APIs and describe the actions that an API client can perform.

Ensure the following API scopes are enabled:
- Install:
  * **Sensor Download** [read]
  * **Sensor update policies** [read]
- Uninstall:
  * **Host** [write]
  * **Sensor update policies** [write]

## Configuration

### Install

Uses the CrowdStrike Falcon APIs to check the sensor version assigned to a ***Windows Sensor Update policy***,
downloads that version, then installs it on the local machine. By default, once complete, the script
deletes itself and the downloaded installer package. The individual steps and any related error messages
are logged to `'Windows\Temp\csfalcon_install.log'` unless otherwise specified.

The script must be run as an administrator on the local machine in order for the Falcon Sensor installation
to complete.

Script options can be passed as parameters or defined in the param() block. Default values are listed in
the parameter descriptions:

```pwsh
.PARAMETER FalconCloud
CrowdStrike Falcon OAuth2 API Hostname ['https://api.crowdstrike.com' if left undefined]
.PARAMETER FalconClientId
CrowdStrike Falcon OAuth2 API Client Id [Required]
.PARAMETER FalconClientSecret
CrowdStrike Falcon OAuth2 API Client Secret [Required]
.PARAMETER MemberCid
Member CID, used only in multi-CID ("Falcon Flight Control") configurations and with a parent management CID.
.PARAMETER SensorUpdatePolicyName
Sensor Update Policy name to check for assigned sensor version ['platform_default' if left undefined]
.PARAMETER InstallParams
Sensor installation parameters, without your CID value ['/install /quiet /noreboot' if left undefined]
.PARAMETER LogPath
Script log location ['Windows\Temp\csfalcon_install.log' if left undefined]
.PARAMETER DeleteInstaller
Delete sensor installer package when complete [default: $true]
.PARAMETER DeleteScript
Delete script when complete [default: $false]
.PARAMETER Uninstall
Uninstall the sensor from the host [default: $false]
.PARAMETER ProvToken
Provisioning token to use for sensor installation [default: $null]
.PARAMETER ProvWaitTime
Time to wait, in seconds, for sensor to provision [default: 1200]
.PARAMETER Tags
A comma-separated list of tags to apply to the host after sensor installation [default: $null]
```

Example:
```pwsh
PS>.\falcon_windows_install.ps1 -FalconClientId <string> -FalconClientSecret <string>
```

### Uninstall

Uninstalls the CrowdStrike Falcon Sensor for Windows. By default, once complete, the script
deletes itself and the downloaded uninstaller package (if necessary). The individual steps and any related error messages are logged to `'Windows\Temp\csfalcon_uninstall.log'` unless otherwise specified.

The script must be run as an administrator on the local machine in order for the Falcon Sensor installation
to complete.

Script options can be passed as parameters or defined in the param() block. Default values are listed in
the parameter descriptions:

```pwsh
.PARAMETER MaintenanceToken
Sensor uninstall maintenance token. If left undefined, the script will attempt to retrieve the
token from the API assuming the FalconClientId|FalconClientSecret are defined.
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
```

Examples:

Basic example that will uninstall the sensor with the provided maintenance token
```pwsh
PS>.\falcon_windows_uninstall.ps1 -MaintenanceToken <string>
```

An example using the Falcon API to retrieve the maintenance token and remove the host from the Falcon console
after uninstalling.
```pwsh
PS>.\falcon_windows_uninstall.ps1 -FalconClientId <string> -FalconClientSecret <string> -RemoveHost $true
```
