# Falcon Powershell Sensor Migration Script

A versatile PowerShell script for host migration between Falcon cloud tenants, such as transitioning from US-1 to EU-1.

> Can also be used to migrate a sensor from one CID to another within the same cloud.

## Requirements

- PowerShell 3.0 or higher

The following **API scopes** are required:

- **Sensor Download** [read]
- **Host** [read,write]
- **Sensor update policies** [read,write]

## Auto-Discovery of Falcon Cloud Region

> [!IMPORTANT]
> Auto-discovery is only available for [us-1, us-2, eu-1] regions.

The script supports auto-discovery of the Falcon cloud region. If the `[New|Old]FalconCloud` parameter is not set, the script will attempt to auto-discover the cloud region. If you want to set the cloud region manually, or if your region does not support auto-discovery, you can set the `[New|Old]FalconCloud` parameter.

## What Does It Do?

This script streamlines the process of migrating a sensor from one CrowdStrike Falcon cloud tenant to another, such as transitioning from US-1 to US-2. It handles the removal and installation of the sensor in the new cloud while maintaining Falcon and Sensor tags throughout the migration. If an error arises during the migration, a recovery log is available to track the process and facilitate resumption of the migration.

The migration script effectively transfers the following settings:

- Sensor Tags (locally added tags on the sensor)
- Falcon Tags (tags assigned to the sensor in the Falcon console)

Additionally, it can assign new tags to the sensor during migration as well as give you the option to remove the old host from the UI after uninstallation.

Throughout the migration, errors and modifications are logged to a default location, which can be altered as needed: `Windows\Temp\csfalcon_migration_yyyy-MM-dd_HH-mm-ss.log`.

## Usage

The script must be run as an administrator on the target machine in order for the migration to complete
successfully.

Script options can be passed as parameters or defined in the param() block. Default values are listed in
the parameter descriptions:

```terminal
Falcon and Sensor tags are migrated to the new installation.
.PARAMETER NewFalconClientId
CrowdStrike Falcon OAuth2 API Client Id for the new Cloud [Required]
.PARAMETER NewFalconClientSecret
CrowdStrike Falcon OAuth2 API Client Secret for the new Cloud [Required]
.PARAMETER OldFalconClientId
CrowdStrike Falcon OAuth2 API Client Id for the old cloud [Required]
.PARAMETER OldFalconClientSecret
CrowdStrike Falcon OAuth2 API Client Secret for the old cloud [Required]
.PARAMETER NewFalconCloud
CrowdStrike Falcon OAuth2 API Hostname for the new cloud [default: 'autodiscover']
.PARAMETER OldFalconCloud
CrowdStrike Falcon OAuth2 API Hostname for the old cloud [default: 'autodiscover']
.PARAMETER NewFalconCid
Manually specify CrowdStrike Customer ID (CID) for the new cloud [default: $null]
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
.PARAMETER DeleteUninstaller
Delete sensor uninstaller package when complete [default: $true]
.PARAMETER DeleteScript
Delete script when complete [default: $false]
.PARAMETER ProvToken
Provisioning token to use for sensor installation [default: $null]
.PARAMETER ProvWaitTime
Time to wait, in seconds, for sensor to provision [default: 1200]
.PARAMETER Tags
A comma-separated list of sensor grouping tags to apply to the host in addition to any pre-existing tags [default: $null]
.PARAMETER FalconTags
A comma-separated list of falcon grouping tags to apply to the host in addition to any pre-existing tags [default: $null]
.PARAMETER MaintenanceToken
Sensor uninstall maintenance token. If left undefined, the script will attempt to retrieve the token from the API assuming the FalconClientId|FalconClientSecret are defined.
.PARAMETER UninstallParams
Sensor uninstall parameters ['/uninstall /quiet' if left undefined]
.PARAMETER UninstallTool
Sensor uninstall tool, local installation cache or CS standalone uninstaller ['installcache' if left undefined]
.PARAMETER RemoveHost
Remove host from CrowdStrike Falcon
.PARAMETER SkipTags
Opt in/out of migrating tags. Tags passed to the Tags flag will still be added.
.PARAMETER Verbose
Enable verbose logging
```

----------

To download the script, run the following command:

```pwsh
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.4.0/powershell/migrate/falcon_windows_migrate.ps1" -OutFile "falcon_windows_migrate.ps1"
```

### Example 1

A simple migration from US-1 to US-2 including existing sensor and falcon tags:

```pwsh
.\falcon_windows_migrate.ps1 `
    -NewFalconClientId 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
    -NewFalconClientSecret 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
    -OldFalconClientId 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
    -OldFalconClientSecret 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
    -NewFalconCloud "us-2" `
    -OldFalconCloud "us-1"
```

### Example 2

Migrate from US-1 to EU-1, remove the old host from the UI and add a new sensor tag:

```pwsh
.\falcon_windows_migrate.ps1 `
    -NewFalconClientId 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
    -NewFalconClientSecret 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
    -OldFalconClientId 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
    -OldFalconClientSecret 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
    -NewFalconCloud "eu-1" `
    -OldFalconCloud "us-1" `
    -RemoveHost `
    -Tags "NewTag,NewTag2"
```

### Example 3

Migrate from US-2 to EU-1, use a provisioning token and add a new falcon tag:

```pwsh
.\falcon_windows_migrate.ps1 `
    -NewFalconClientId 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
    -NewFalconClientSecret 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
    -OldFalconClientId 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
    -OldFalconClientSecret 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
    -NewFalconCloud "eu-1" `
    -OldFalconCloud "us-2" `
    -ProvToken 'xxxxxxxx' `
    -FalconTags "NewFalconTag"
```

### Example 4

Migrate from one CID to another within the same cloud:

```pwsh
.\falcon_windows_migrate.ps1 `
    -NewFalconClientId 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
    -NewFalconClientSecret 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
    -OldFalconClientId 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
    -OldFalconClientSecret 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
    -NewFalconCloud "eu-1" `
    -OldFalconCloud "eu-1" `
```

## Troubleshooting

To assist in troubleshooting the migration script, you can try the following:

- Use the `-Verbose` parameter to enable verbose logging.

  > Note: This will display additional logging in the console, as well as in the log file.

  Example:

    ```pwsh
    .\falcon_windows_migrate.ps1 `
        -Verbose `
        -NewFalconClientId 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
        -NewFalconClientSecret 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
        -OldFalconClientId 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
        -OldFalconClientSecret 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
        -NewFalconCloud "us-2" `
        -OldFalconCloud "us-1"
    ```

- For a more detailed approach, you can use `Set-PSDebug -Trace`. This cmdlet offers three trace levels (0-2):

  - 0 : Turn script block logging off. (Equivalent to -Off)
  - 1 : Turn script block logging on. (Equivalent to -On)
  - 2 : Turn script block logging on and generate a trace of all commands in a script block and the arguments they were used with.
    > Similar to the output of `set -x` in bash. Very noisy but contains a lot of useful information.

  Example:

    ```pwsh
    Set-PSDebug -Trace 2
    .\falcon_windows_migrate.ps1 `
        -NewFalconClientId 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
        -NewFalconClientSecret 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
        -OldFalconClientId 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
        -OldFalconClientSecret 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' `
        -NewFalconCloud "us-2" `
        -OldFalconCloud "us-1"
    # To turn off tracing
    Set-PSDebug -Trace 0
    ```
