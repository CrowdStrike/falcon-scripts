# Falcon Linux Bash Installation Scripts

Bash script to install Falcon Sensor through the Falcon APIs on a Linux endpoint. By default,
this script will install, register the sensor, and start the service. If you would like to simply
install the sensor without any additional configurations, configure the `FALCON_INSTALL_ONLY`
environment variable. Consult the Environment Variables for each script for more information.

## Security Recommendations

### Use cURL version 7.55.0 or newer

We have identified a security concern related to cURL versions prior to 7.55, which required request headers to be set using the `-H` option, thus allowing potential secrets to be exposed via the command line. In newer versions of cURL, you can pass headers from stdin using the `@-` syntax, which addresses this security concern. Although our script offers compatibility with the older method by allowing you to set the environment variable `ALLOW_LEGACY_CURL=true`, we strongly urge you to upgrade cURL if your environment permits.

To check your version of cURL, run the following command: `curl --version`

## Table of Contents

- [Falcon API Permissions](#falcon-api-permissions)
- [Configuration](#configuration)
  - [Setting up Authentication](#setting-up-authentication)
- [Install Script](#install-script)
  - [Usage](#usage)
  - [Examples](#examples)
- [Uninstall Script](#uninstall-script)
  - [Usage](#usage-1)
  - [Examples](#examples-1)
- [Troubleshooting](#troubleshooting)

## Falcon API Permissions

API clients are granted one or more API scopes. Scopes allow access to specific CrowdStrike APIs and describe the actions that an API client can perform.

Ensure the following API scopes are enabled:

- **Sensor Download** [read]
  > Required for downloading the Falcon Sensor installation package.

- **Installation Tokens** [read]
  > Required if your environment enforces installation tokens for Falcon Sensor installation.

- **Sensor update policies** [read]
  > Required when using the `FALCON_SENSOR_UPDATE_POLICY_NAME` environment variable to specify a sensor update policy.

- **Sensor update policies** [write]
  > Required if you want the uninstall script to automatically retrieve a maintenance token from the API.
  > Not needed if you directly provide the maintenance token via the `FALCON_MAINTENANCE_TOKEN` environment variable.
  > Maintenance tokens are required to uninstall sensors that have uninstall protection enabled.

- **Hosts** [write]
  > Required when using the `FALCON_REMOVE_HOST=true` environment variable with the uninstall script.
  >
  > :warning:
  > It is recommended to use Host Retention Policies in the Falcon console instead.

## Configuration

### Setting up Authentication

#### Using Client ID and Client Secret

Export the required environment variables:

```bash
export FALCON_CLIENT_ID="XXXXXXX"
export FALCON_CLIENT_SECRET="YYYYYYYYY"
```

#### Auto-Discovery of Falcon Cloud Region

> [!IMPORTANT]
> Auto-discovery is only available for [us-1, us-2, eu-1] regions.

The scripts support auto-discovery of the Falcon cloud region. If the `FALCON_CLOUD` environment variable is not set, the script will attempt to auto-discover it. If you want to set the cloud region manually, or if your region does not support auto-discovery, you can set the `FALCON_CLOUD` environment variable:

```bash
export FALCON_CLOUD="us-gov-1"
```

#### Using an Access Token

You can also specify a Falcon access token if doing a batch install across multiple machines to prevent the need to call the token endpoint multiple times. If using an access token to authenticate, you ***MUST*** also provide `FALCON_CLOUD`:

```bash
export FALCON_ACCESS_TOKEN="XXXXXXXX"
export FALCON_CLOUD="us-1"
```

> [!NOTE]
> If you need to retrieve an access token, run the script with the `GET_ACCESS_TOKEN` environment variable set to `true`. The Falcon sensor will NOT be installed while this variable is set.
>
> ```bash
> export FALCON_CLIENT_ID="XXXXXXX"
> export FALCON_CLIENT_SECRET="YYYYYYYYY"
> export GET_ACCESS_TOKEN="true"
> ```
>
> The script will output the access token to the console.

#### Using AWS SSM

The installer is AWS SSM aware, if `FALCON_CLIENT_ID` and `FALCON_CLIENT_SECRET` are not provided AND the script is running on an AWS instance, the script will try to get API credentials from the SSM store of the region.

## Install Script

```terminal
Usage: falcon-linux-install.sh [-h|--help]

Installs and configures the CrowdStrike Falcon Sensor for Linux.
Version: 1.10.1

This script recognizes the following environmental variables:

Authentication:
    - FALCON_CLIENT_ID                  (default: unset)
        Your CrowdStrike Falcon API client ID.

    - FALCON_CLIENT_SECRET              (default: unset)
        Your CrowdStrike Falcon API client secret.

    - FALCON_ACCESS_TOKEN               (default: unset)
        Your CrowdStrike Falcon API access token.
        If used, FALCON_CLOUD must also be set.

    - FALCON_CLOUD                      (default: unset)
        The cloud region where your CrowdStrike Falcon instance is hosted.
        Required if using FALCON_ACCESS_TOKEN.
        Accepted values are ['us-1', 'us-2', 'eu-1', 'us-gov-1', 'us-gov-2'].

Other Options
    - FALCON_CID                        (default: auto)
        The customer ID that should be associated with the sensor.
        By default, the CID is automatically determined by your authentication credentials.

    - FALCON_SENSOR_VERSION_DECREMENT   (default: 0 [latest])
        The number of versions prior to the latest release to install.
        For example, 1 would install version N-1.

    - FALCON_PROVISIONING_TOKEN         (default: unset)
        The provisioning token to use for installing the sensor.
        If the provisioning token is unset, the script will attempt to retrieve it from
        the API using your authentication credentials and token requirements.

    - FALCON_SENSOR_UPDATE_POLICY_NAME  (default: unset)
        The name of the sensor update policy to use for installing the sensor.

    - FALCON_TAGS                       (default: unset)
        A comma seperated list of tags for sensor grouping.

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

    - FALCON_UNINSTALL                  (default: false)
        To uninstall the falcon sensor.
        **LEGACY** Please use the falcon-linux-uninstall.sh script instead.

    - FALCON_INSTALL_ONLY               (default: false)
        To install the falcon sensor without registering it with CrowdStrike.

    - FALCON_DOWNLOAD_ONLY              (default: false)
        To download the falcon sensor without installing it.

    - FALCON_DOWNLOAD_PATH              (default: $PWD)
        The path to download the falcon sensor to.

    - ALLOW_LEGACY_CURL                 (default: false)
        To use the legacy version of curl; version < 7.55.0.

    - GET_ACCESS_TOKEN                  (default: false)
        Prints an access token and exits.
        Requires FALCON_CLIENT_ID and FALCON_CLIENT_SECRET.
        Accepted values are ['true', 'false'].

    - PREP_GOLDEN_IMAGE                 (default: false)
        To prepare the sensor to be used in a golden image.
        Accepted values are ['true', 'false'].

    - USER_AGENT                        (default: unset)
        User agent string to append to the User-Agent header when making
        requests to the CrowdStrike API.

This script recognizes the following argument:
    -h, --help
        Print this help message and exit.
```

### Usage

To download and run the script directly:

```bash
export FALCON_CLIENT_ID="XXXXXXX"
export FALCON_CLIENT_SECRET="YYYYYYYYY"
curl -L https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.10.1/bash/install/falcon-linux-install.sh | bash
```

Alternatively, download the script and run it locally:

```bash
export FALCON_CLIENT_ID="XXXXXXX"
export FALCON_CLIENT_SECRET="YYYYYYYYY"
curl -O https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.10.1/bash/install/falcon-linux-install.sh
bash falcon-linux-install.sh
```

Or pass the environment variables directly to the script:

```bash
FALCON_CLIENT_ID="XXXXXXX" FALCON_CLIENT_SECRET="YYYYYYYYY" bash falcon-linux-install.sh
```

### Examples

#### Install the latest Falcon Sensor with the default settings

```bash
export FALCON_CLIENT_ID="XXXXXXX"
export FALCON_CLIENT_SECRET="YYYYYYYYY"
curl -L https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.10.1/bash/install/falcon-linux-install.sh | bash
```

#### Install the Falcon Sensor with the previous version (n-1)

```bash
export FALCON_CLIENT_ID="XXXXXXX"
export FALCON_CLIENT_SECRET="YYYYYYYYY"
export FALCON_SENSOR_VERSION_DECREMENT=1
curl -L https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.10.1/bash/install/falcon-linux-install.sh | bash
```

#### Create a Golden Image

```bash
export FALCON_CLIENT_ID="XXXXXXX"
export FALCON_CLIENT_SECRET="YYYYYYYYY"
export PREP_GOLDEN_IMAGE="true"
curl -L https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.10.1/bash/install/falcon-linux-install.sh | bash
```

## Uninstall Script

```terminal
Usage: falcon-linux-uninstall.sh [-h|--help]

Uninstalls the CrowdStrike Falcon Sensor from Linux operating systems.
Version: 1.10.1

This script recognizes the following environmental variables:

Authentication:
    - FALCON_CLIENT_ID                  (default: unset)
        Your CrowdStrike Falcon API client ID.

    - FALCON_CLIENT_SECRET              (default: unset)
        Your CrowdStrike Falcon API client secret.

    - FALCON_ACCESS_TOKEN               (default: unset)
        Your CrowdStrike Falcon API access token.
        If used, FALCON_CLOUD must also be set.

    - FALCON_CLOUD                      (default: unset)
        The cloud region where your CrowdStrike Falcon instance is hosted.
        Required if using FALCON_ACCESS_TOKEN.
        Accepted values are ['us-1', 'us-2', 'eu-1', 'us-gov-1', 'us-gov-2'].

Other Options:
    - FALCON_MAINTENANCE_TOKEN          (default: unset)
        Sensor uninstall maintenance token used to unlock sensor uninstallation.
        If not provided but FALCON_CLIENT_ID and FALCON_CLIENT_SECRET are set,
        the script will try to retrieve the token from the API.

    - FALCON_REMOVE_HOST                (default: unset)
        Determines whether the host should be removed from the Falcon console after uninstalling the sensor.
        Requires API Authentication.
        NOTE: It is recommended to use Host Retention Policies in the Falcon console instead.
        Accepted values are ['true', 'false'].

    - GET_ACCESS_TOKEN                  (default: unset)
        Prints an access token and exits.
        Requires FALCON_CLIENT_ID and FALCON_CLIENT_SECRET.
        Accepted values are ['true', 'false'].

    - FALCON_APH                        (default: unset)
        The proxy host for the sensor to use when communicating with CrowdStrike.

    - FALCON_APP                        (default: unset)
        The proxy port for the sensor to use when communicating with CrowdStrike.

    - USER_AGENT                        (default: unset)
        User agent string to append to the User-Agent header when making
        requests to the CrowdStrike API.

This script recognizes the following argument:
    -h, --help
        Print this help message and exit.
```

### Usage

To download and run the script directly

```bash
curl -L https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.10.1/bash/install/falcon-linux-uninstall.sh | bash
```

Alternatively, download the script and run it locally

```bash
curl -O https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.10.1/bash/install/falcon-linux-uninstall.sh
bash falcon-linux-uninstall.sh
```

### Examples

#### Uninstall the Falcon Sensor

```bash
curl -L https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.10.1/bash/install/falcon-linux-uninstall.sh | bash
```

## Troubleshooting

To troubleshoot installation issues, run the script by using `bash -x`:

```bash
bash -x falcon-linux-install.sh
```

or

```bash
curl -L https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.10.1/bash/install/falcon-linux-install.sh | bash -x
```
