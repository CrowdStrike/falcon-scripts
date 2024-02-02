# Falcon Powershell Installation Scripts

Powershell scripts to install/uninstall Falcon Sensor through the Falcon APIs on a Windows endpoint.

## Falcon API Permissions

API clients are granted one or more API scopes. Scopes allow access to specific CrowdStrike APIs and describe the actions that an API client can perform.

Ensure the following API scopes are enabled:

- Install:
  - **Sensor Download** [read]
  - **Sensor update policies** [read]
- Uninstall:
  - **Host** [write]
  - **Sensor update policies** [write]

## Configuration

### Install

Uses the CrowdStrike Falcon APIs to check the sensor version assigned to a ***Windows Sensor Update policy***,
downloads that version, then installs it on the local machine. By default, once complete, the script
deletes itself and the downloaded installer package. The individual steps and any related error messages
are logged to `'Windows\Temp\InstallFalcon.log'` unless otherwise specified.

The script must be run as an administrator on the local machine in order for the Falcon Sensor installation
to complete.

Script options can be passed as parameters or defined in the param() block. Default values are listed in
the parameter descriptions:

```terminal
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
.PARAMETER Verbose
Enable verbose logging
```

***Examples***:

To download the script:

```pwsh
Invoke-WebRequest -Uri https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.3.1/powershell/install/falcon_windows_install.ps1 -OutFile falcon_windows_install.ps1
```

Basic example that will install the sensor with the provided provisioning token

```pwsh
.\falcon_windows_install.ps1 -FalconClientId <string> -FalconClientSecret <string> -ProvToken <string>
```

### Uninstall

Uninstalls the CrowdStrike Falcon Sensor for Windows. By default, once complete, the script
deletes itself and the downloaded uninstaller package (if necessary). The individual steps and any related error messages are logged to `'Windows\Temp\csfalcon_uninstall.log'` unless otherwise specified.

The script must be run as an administrator on the local machine in order for the Falcon Sensor installation
to complete.

Script options can be passed as parameters or defined in the param() block. Default values are listed in
the parameter descriptions:

```terminal
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
Remove host from CrowdStrike Falcon
.PARAMETER FalconCloud
CrowdStrike Falcon OAuth2 API Hostname [default: autodiscover]
.PARAMETER FalconClientId
CrowdStrike Falcon OAuth2 API Client Id [Required if RemoveHost is $true]
.PARAMETER FalconClientSecret
CrowdStrike Falcon OAuth2 API Client Secret [Required if RemoveHost is $true]
.PARAMETER MemberCid
Member CID, used only in multi-CID ("Falcon Flight Control") configurations and with a parent management CID.
.PARAMETER Verbose
Enable verbose logging
```

***Examples***:

To download the script:

```pwsh
Invoke-WebRequest -Uri https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.3.1/powershell/install/falcon_windows_uninstall.ps1 -OutFile falcon_windows_uninstall.ps1
```

Basic example that will uninstall the sensor with the provided maintenance token

```pwsh
.\falcon_windows_uninstall.ps1 -MaintenanceToken <string>
```

An example using the Falcon API to retrieve the maintenance token and remove the host from the Falcon console
after uninstalling.

```pwsh
.\falcon_windows_uninstall.ps1 -FalconClientId <string> -FalconClientSecret <string> -RemoveHost $true
```

## Troubleshooting

To assist in troubleshooting the installation scripts, you can try the following:

- Use the `-Verbose` parameter to enable verbose logging.

  > Note: This will display additional logging in the console, as well as in the log file.

  Example:

    ```pwsh
    .\falcon_windows_install.ps1 -Verbose -FalconClientId <string> -FalconClientSecret <string> -ProvToken <string>
    ```

- For a more detailed approach, you can use `Set-PSDebug -Trace`. This cmdlet offers three trace levels (0-2):

  - 0 : Turn script block logging off. (Equivalent to -Off)
  - 1 : Turn script block logging on. (Equivalent to -On)
  - 2 : Turn script block logging on and generate a trace of all commands in a script block and the arguments they were used with.
    > Similar to the output of `set -x` in bash. Very noisy but contains a lot of useful information.

  Example:

    ```pwsh
    Set-PSDebug -Trace 2
    .\falcon_windows_install.ps1 -FalconClientId <string> -FalconClientSecret <string> -ProvToken <string>
    # To turn off tracing
    Set-PSDebug -Trace 0
    ```
