# Falcon Powershell Installation Scripts

Powershell scripts to install/uninstall Falcon Sensor through the Falcon APIs on a Windows endpoint.

## Table of Contents

- [Falcon API Permissions](#falcon-api-permissions)
- [Auto-Discovery of Falcon Cloud Region](#auto-discovery-of-falcon-cloud-region)
- [Configuration](#configuration)
- [Install Sensor](#install-sensor)
- [Uninstall Sensor](#uninstall-sensor)
- [Troubleshooting](#troubleshooting)

## Falcon API Permissions

API clients are granted one or more API scopes. Scopes allow access to specific CrowdStrike APIs and describe the actions that an API client can perform.

Ensure the following API scopes are enabled:

- Install:
  - **Sensor Download** [read]
  - **Sensor update policies** [read]
- Uninstall:
  - **Host** [write]
  - **Sensor update policies** [write]

## Auto-Discovery of Falcon Cloud Region

> [!IMPORTANT]
> Auto-discovery is only available for [us-1, us-2, us-3, eu-1] regions.

The scripts support auto-discovery of the Falcon cloud region. If the `FalconCloud` parameter is not set, the script will attempt to auto-discover the cloud region. If you want to set the cloud region manually, or if your region does not support auto-discovery, you can set the `FalconCloud` parameter.

## Configuration

### Setting up Authentication

#### Using Client ID and Client Secret

Provide the required parameters:

```powershell
.\falcon_windows_install.ps1 -FalconClientId <string> -FalconClientSecret <string>
```

#### Using an Access Token

You can also specify a Falcon access token if doing a batch install across multiple machines to prevent the need to call the token endpoint multiple times. If using an access token to authenticate, you ***MUST*** also provide `FALCON_CLOUD`:

```powershell
.\falcon_windows_install.ps1 -FalconCloud us-2 -FalconAccessToken <string>
```

> [!NOTE]
> If you need to retrieve an access token, run the script with the `GET_ACCESS_TOKEN` parameter set. The Falcon sensor will NOT be installed while this parameter is provided.
>
> ```powershell
> .\falcon_windows_install.ps1 -FalconClientId <string> -FalconClientSecret <string> -GetAccessToken
> ```
>
> The script will output the access token to the console.

## Install Sensor

Uses the CrowdStrike Falcon APIs to check the sensor version assigned to a ***Windows Sensor Update policy***,
downloads that version, then installs it on the local machine. By default, once complete, the script
deletes itself and the downloaded installer package. The individual steps and any related error messages
are logged to `'Windows\Temp\InstallFalcon.log'` unless otherwise specified.

The script must be run as an administrator on the local machine in order for the Falcon Sensor installation
to complete.

Script options can be passed as parameters or defined in the param() block. Default values are listed in
the parameter descriptions:

```pwsh
<#
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
Time to wait, in seconds, for sensor to provision [default: 1200]
.PARAMETER Tags
A comma-separated list of tags to apply to the host after sensor installation [default: $null]
.PARAMETER ProxyHost
The proxy host for the sensor to use when communicating with CrowdStrike [default: $null]
.PARAMETER ProxyPort
The proxy port for the sensor to use when communicating with CrowdStrike [default: $null]
.PARAMETER ProxyDisable
By default, the Falcon sensor for Windows automatically attempts to use any available proxy connections when it connects to the CrowdStrike cloud.
This parameter forces the sensor to skip those attempts and ignore any proxy configuration, including Windows Proxy Auto Detection.
.PARAMETER Verbose
Enable verbose logging
.PARAMETER FalconDebug
Print redacted progress markers: detected OS and PowerShell version, the exact sensor
query filter, how many installers matched and which was chosen, the API route and HTTP
status for every call, and the sensor version installed plus the AID (that version is the one resolved from
the policy or query, not re-read from the binary). Values are dropped
unless the key is on a fixed allow-list, so secrets cannot appear. Also honors `$env:FALCON_DEBUG=1`.
Do not use `Set-PSDebug -Trace` or the common `-Debug` parameter for support; they print credentials.
#>
```

### Usage

To download the script:

```pwsh
Invoke-WebRequest -Uri https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.13.0/powershell/install/falcon_windows_install.ps1 -OutFile falcon_windows_install.ps1
```

Basic example that will install the sensor with the provided provisioning token

```pwsh
.\falcon_windows_install.ps1 -FalconClientId <string> -FalconClientSecret <string> -ProvToken <string>
```

## Uninstall Sensor

Uninstalls the CrowdStrike Falcon Sensor for Windows. By default, once complete, the script
deletes itself and the downloaded uninstaller package (if necessary). The individual steps and any related error messages are logged to `'Windows\Temp\csfalcon_uninstall.log'` unless otherwise specified.

The script must be run as an administrator on the local machine in order for the Falcon Sensor installation
to complete.

Script options can be passed as parameters or defined in the param() block. Default values are listed in
the parameter descriptions:

```pwsh
<#
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
.PARAMETER Verbose
Enable verbose logging
.PARAMETER FalconDebug
Print redacted progress markers: detected OS and PowerShell version, the exact sensor
query filter, how many installers matched and which was chosen, the API route and HTTP
status for every call, and the sensor version installed plus the AID (that version is the one resolved from
the policy or query, not re-read from the binary). Values are dropped
unless the key is on a fixed allow-list, so secrets cannot appear. Also honors `$env:FALCON_DEBUG=1`.
Do not use `Set-PSDebug -Trace` or the common `-Debug` parameter for support; they print credentials.
#>
```

### Usage

To download the script:

```pwsh
Invoke-WebRequest -Uri https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.13.0/powershell/install/falcon_windows_uninstall.ps1 -OutFile falcon_windows_uninstall.ps1
```

Basic example that will uninstall the sensor with the provided maintenance token

```pwsh
.\falcon_windows_uninstall.ps1 -MaintenanceToken <string>
```

## Troubleshooting

Use the redacted debug mode. It prints the detected OS and PowerShell version, the
exact sensor query filter, how many installers matched and which was chosen, the API
route and HTTP status for every call, and the sensor version installed plus the AID
(the version is the one resolved from the policy or query, not re-read from the binary).
Values are dropped unless the key is on a fixed allow-list, so credentials cannot
appear in the output you send to support.

```pwsh
.\falcon_windows_install.ps1 -FalconDebug -FalconClientId <string> -FalconClientSecret <string> -ProvToken <string>
```

Sample output from a real install on Windows PowerShell 5.1 (values from a live run,
credentials never appear):

```
FALCON_DEBUG: start version=1.13.0 (PowerShell 5.1.20348.5499 Desktop) cloud=us-2 client_id_set=yes client_secret_set=yes access_token_set=no member_cid_set=no proxy_set=no policy_name_set=no
FALCON_DEBUG: environment os=windows os_version=10.0.20348.0 os_arch=AMD64 run_as=admin
FALCON_DEBUG: Invoke-FalconAuth step=response http_status=201 cloud=us-2
FALCON_DEBUG: GetPolicy step=query path=/policy/combined/sensor-update/v2 filter=platform_name:'Windows'+name.raw:'platform_default'
FALCON_DEBUG: GetPolicy step=resolved policy_version=8.10.21405
FALCON_DEBUG: GetInstaller step=query path=/sensors/combined/installers/v3 filter=platform:'windows'+version:'8.10.21405' sort=none
FALCON_DEBUG: GetInstaller step=matched count=1
FALCON_DEBUG: GetInstaller step=selected index=0 file_type=exe sha=338d1b7f2508
FALCON_DEBUG: DownloadFile step=downloaded installer=C:\Windows\Temp\FalconSensor_Windows.exe bytes=131724104
FALCON_DEBUG: Installer step=configure cid_source=api provisioning_token_set=no tags_count=0 proxy_set=no
FALCON_DEBUG: InstallerProcess step=installed version=8.10.21405 aid=61c06e35b3104b99a371be2d6943d2e7
```


`$env:FALCON_DEBUG = '1'` does the same thing, which is useful when the script runs
from a job where you cannot add a parameter.

`-Verbose` still enables the script's own operational logging in the console and the
log file. It is not a replacement for `-FalconDebug`.

> Note: debug markers go to the console via `Write-Host`, so they are not written to
> the script's log file. A `Start-Transcript` session does capture them, so stop any
> transcript first if you do not want the markers on disk.

Do **not** use `Set-PSDebug -Trace` or the common `-Debug` parameter for support.
Tracing prints every statement with its arguments, including `FalconClientSecret`,
`ProvToken`, access tokens, `Authorization` headers and the OAuth request body. These
scripts call `Set-PSDebug -Off` on entry, but that runs after PowerShell binds the
parameters, so a trace started beforehand can still expose the values you passed in.
