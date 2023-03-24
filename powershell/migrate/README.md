# Falcon Powershell Sensor Migration Script

A versatile PowerShell script for host migration between Falcon cloud tenants, such as transitioning from US-1 to EU-1.

> Can also be used to migrate a sensor from one CID to another within the same cloud.

## Requirements

- PowerShell 3.0 or higher

The following **API scopes** are required:

- **Sensor Download** [read]
- **Host** [read,write]
- **Sensor update policies** [write]

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
```

### Example 1

A simple migration from US-1 to US-2 including sensor tags and falcon tags:

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

Migrate from US-2 to EU-1, use a provisioning token and add a new falcon tag to the sensor:

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
