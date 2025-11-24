# Falcon Linux Migration Script

Bash script to migrate Falcon sensor from one CID to another through the Falcon APIs on a Linux endpoint. By default, this script will uninstall the sensor from the old CID, install it in the new CID, and migrate any existing sensor and Falcon grouping tags. The script also creates a recovery file to facilitate resuming the migration in case of failure.

## Security Recommendations

### Use cURL version 7.55.0 or newer

We have identified a security concern related to cURL versions prior to 7.55, which required request headers to be set using the `-H` option, thus allowing potential secrets to be exposed via the command line. In newer versions of cURL, you can pass headers from stdin using the `@-` syntax, which addresses this security concern. Although our script offers compatibility with the older method by allowing you to set the environment variable `ALLOW_LEGACY_CURL=true`, we strongly urge you to upgrade cURL if your environment permits.

To check your version of cURL, run the following command: `curl --version`

## Table of Contents

- [Falcon API Permissions](#falcon-api-permissions)
- [Configuration](#configuration)
  - [Setting up Authentication](#setting-up-authentication)
- [Usage](#usage)
  - [Examples](#examples)
- [Troubleshooting](#troubleshooting)

## Falcon API Permissions

API clients are granted one or more API scopes. Scopes allow access to specific CrowdStrike APIs and describe the actions that an API client can perform.

Ensure the following API scopes are enabled for both the old and new CIDs:

- **Sensor Download** [read]
  > Required for downloading the Falcon Sensor installation package.

- **Installation Tokens** [read]
  > Required if your environment enforces installation tokens for Falcon Sensor installation.

- **Sensor update policies** [read]
  > Required when using the `FALCON_SENSOR_UPDATE_POLICY_NAME` environment variable to specify a sensor update policy.

- **Sensor update policies** [write]
  > Required if you want the script to automatically retrieve a maintenance token from the API.
  > Not needed if you directly provide the maintenance token via the `FALCON_MAINTENANCE_TOKEN` environment variable.
  > Maintenance tokens are required to uninstall sensors that have uninstall protection enabled.

- **Hosts** [read]
  > Required for retrieving sensor and Falcon grouping tags.

- **Hosts** [write]
  > Required for setting Falcon grouping tags and when using the `FALCON_REMOVE_HOST=true` environment variable.
  >
  > :warning:
  > It is recommended to use Host Retention Policies in the Falcon console instead.

## Configuration

### Setting up Authentication

You must provide API credentials for both the old and new CIDs:

```bash
# Old CID credentials
export OLD_FALCON_CLIENT_ID="XXXXXXX"
export OLD_FALCON_CLIENT_SECRET="YYYYYYYYY"
export OLD_FALCON_CLOUD="us-1"  # Optional, defaults to us-1

# New CID credentials
export NEW_FALCON_CLIENT_ID="ZZZZZZZ"
export NEW_FALCON_CLIENT_SECRET="WWWWWWW"
export NEW_FALCON_CLOUD="us-2"  # Optional, defaults to us-1
export NEW_FALCON_CID="AAAAAAAAAAA"  # Optional, will be auto-detected if not provided
```

#### Auto-Discovery of Falcon Cloud Region

> [!IMPORTANT]
> Auto-discovery is only available for [us-1, us-2, eu-1] regions.

The scripts support auto-discovery of the Falcon cloud region. If the `[OLD|NEW]FALCON_CLOUD` environment variable is not set, the script will attempt to auto-discover it. If you want to set the cloud region manually, or if your region does not support auto-discovery, you can set the `[OLD|NEW]FALCON_CLOUD` environment variable:

```bash
export [OLD|NEW]FALCON_CLOUD="us-gov-1"
```

## Usage

```terminal
Usage: falcon-linux-migrate.sh [-h|--help]

Migrates the Falcon sensor to another Falcon CID.
Version: 1.9.0

This script recognizes the following environmental variables:

Old CID Authentication:
    - OLD_FALCON_CLIENT_ID              (default: unset) [Required]
        Your CrowdStrike Falcon API client ID for the old CID.

    - OLD_FALCON_CLIENT_SECRET          (default: unset) [Required]
        Your CrowdStrike Falcon API client secret for the old CID.

    - OLD_FALCON_MEMBER_CID              (default: unset)
        Member CID, used only in multi-CID ("Falcon Flight Control") configurations and
        with a parent management CID for the old CID.

    - OLD_FALCON_CLOUD                  (default: 'us-1')
        The cloud region where your old CrowdStrike Falcon instance is hosted.
        Accepted values are ['us-1', 'us-2', 'eu-1', 'us-gov-1', 'us-gov-2'].

New CID Authentication:
    - NEW_FALCON_CLIENT_ID              (default: unset) [Required]
        Your CrowdStrike Falcon API client ID for the new CID.

    - NEW_FALCON_CLIENT_SECRET          (default: unset) [Required]
        Your CrowdStrike Falcon API client secret for the new CID.

    - NEW_FALCON_MEMBER_CID              (default: unset)
        Member CID, used only in multi-CID ("Falcon Flight Control") configurations and
        with a parent management CID for the new CID.

    - NEW_FALCON_CLOUD                  (default: 'us-1')
        The cloud region where your new CrowdStrike Falcon instance is hosted.
        Accepted values are ['us-1', 'us-2', 'eu-1', 'us-gov-1', 'us-gov-2'].

    - NEW_FALCON_CID                    (default: unset)
        Your CrowdStrike Falcon customer ID (CID) for the new CID.
        If not specified, will be detected automatically via API.

Migration Options:
    - MIGRATE_TAGS                      (default: true)
        Migrate the host's existing tags to the target CID.
        Accepted values are ['true', 'false'].

    - LOG_PATH                          (default: /tmp)
        Location for the log and recovery files.

Other Options
    - FALCON_MAINTENANCE_TOKEN          (default: unset)
        Sensor uninstall maintenance token used to unlock sensor uninstallation.
        If not provided the script will try to retrieve the token from the API.

    - FALCON_PROVISIONING_TOKEN         (default: unset)
        The provisioning token to use for installing the sensor.
        If the provisioning token is unset, the script will attempt to retrieve it from
        the API using your authentication credentials and token requirements.

    - FALCON_REMOVE_HOST                (default: unset)
        Determines whether the host should be removed from the Falcon console after uninstalling the sensor.
        Requires API Authentication.
        NOTE: It is recommended to use Host Retention Policies in the Falcon console instead.
        Accepted values are ['true', 'false'].

    - FALCON_SENSOR_VERSION_DECREMENT   (default: 0 [latest])
        The number of versions prior to the latest release to install.
        For example, 1 would install version N-1.

    - FALCON_SENSOR_UPDATE_POLICY_NAME  (default: unset)
        The name of the sensor update policy to use for installing the sensor.

    - FALCON_TAGS                       (default: unset)
        A comma-separated list of sensor grouping tags to apply to the host.
        If MIGRATE_TAGS=true these tags will be appended to any existing sensor tags.

    - FALCON_GROUPING_TAGS              (default: unset)
        A comma-separated list of Falcon grouping tags to apply to the host.
        If MIGRATE_TAGS=true these tags will be appended to any existing grouping tags.

    - FALCON_APD                        (default: unset)
        Configures if the proxy should be enabled or disabled.

    - FALCON_APH                        (default: unset)
        The proxy host for the sensor to use when communicating with CrowdStrike.

    - FALCON_APP                        (default: unset)
        The proxy port for the sensor to use when communicating with CrowdStrike.

    - FALCON_BILLING                    (default: default)
        To configure the sensor billing type.
        Accepted values are [default|metered].

    - FALCON_BACKEND                    (default: auto)
        For sensor backend.
        Accepted values are values: [auto|bpf|kernel].

    - FALCON_SENSOR_CLOUD               (default: unset)
        To pin the cloud region for unified sensor installations.
        This allows specifying the cloud region for unified sensors at installation time.
        Accepted values are [us-1|us-2|eu-1|us-gov-1|us-gov-2].

    - ALLOW_LEGACY_CURL                 (default: false)
        To use the legacy version of curl; version < 7.55.0.

    - USER_AGENT                        (default: unset)
        User agent string to append to the User-Agent header when making
        requests to the CrowdStrike API.

This script recognizes the following argument:
    -h, --help
        Print this help message and exit.
```

### Examples

#### Migrate a sensor from US-1 to US-2 with tag migration

```bash
export OLD_FALCON_CLIENT_ID="XXXXXXX"
export OLD_FALCON_CLIENT_SECRET="YYYYYYYYY"
export OLD_FALCON_CLOUD="us-1"
export NEW_FALCON_CLIENT_ID="ZZZZZZZ"
export NEW_FALCON_CLIENT_SECRET="WWWWWWW"
export NEW_FALCON_CLOUD="us-2"
curl -L https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.9.0/bash/migrate/falcon-linux-migrate.sh | sudo bash
```

#### Migrate a sensor to EU-1 with removal from old console

```bash
export OLD_FALCON_CLIENT_ID="XXXXXXX"
export OLD_FALCON_CLIENT_SECRET="YYYYYYYYY"
export OLD_FALCON_CLOUD="us-1"
export NEW_FALCON_CLIENT_ID="ZZZZZZZ"
export NEW_FALCON_CLIENT_SECRET="WWWWWWW"
export NEW_FALCON_CLOUD="eu-1"
export FALCON_REMOVE_HOST="true"
curl -L https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.9.0/bash/migrate/falcon-linux-migrate.sh | sudo bash
```

#### Migrate a sensor with custom tags

```bash
export OLD_FALCON_CLIENT_ID="XXXXXXX"
export OLD_FALCON_CLIENT_SECRET="YYYYYYYYY"
export NEW_FALCON_CLIENT_ID="ZZZZZZZ"
export NEW_FALCON_CLIENT_SECRET="WWWWWWW"
export FALCON_TAGS="department/it,location/hq"
export FALCON_GROUPING_TAGS="environment/production,criticality/high"
curl -L https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.9.0/bash/migrate/falcon-linux-migrate.sh | sudo bash
```

#### Migrate a sensor from one CID to another within the same cloud

```bash
export OLD_FALCON_CLIENT_ID="XXXXXXX"
export OLD_FALCON_CLIENT_SECRET="YYYYYYYYY"
export OLD_FALCON_CLOUD="us-1"
export NEW_FALCON_CLIENT_ID="ZZZZZZZ"
export NEW_FALCON_CLIENT_SECRET="WWWWWWW"
export NEW_FALCON_CLOUD="us-1"
curl -L https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.9.0/bash/migrate/falcon-linux-migrate.sh | sudo bash
```

## Troubleshooting

To troubleshoot migration issues, you can run the script with `bash -x` for detailed output:

```bash
bash -x falcon-linux-migrate.sh
```

or

```bash
curl -L https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.9.0/bash/migrate/falcon-linux-migrate.sh | bash -x
```

The script creates a log file at the location specified by `LOG_PATH` (defaults to `/tmp`) with the name format `falcon_migration_YYYYMMDD_HHMMSS.log`. This log contains detailed information about each step of the migration process.

If the migration process is interrupted, the script creates a recovery file at `$LOG_PATH/falcon_migration_recovery.csv` that contains information about the previous sensor's AID and tags. When rerunning the script, it will detect this file and attempt to continue the migration process.
