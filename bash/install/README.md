# Falcon Linux Bash Installation Script

Bash script to install Falcon Sensor through the Falcon APIs on a Linux endpoint. By default,
this script will install, register the sensor, and start the service. If you would like to simply
install the sensor without any additional configurations, configure the `FALCON_INSTALL_ONLY`
environment variable.

## Security Recommendations

### Use cURL version 7.55.0 or newer

We have identified a security concern related to cURL versions prior to 7.55, which required request headers to be set using the `-H` option, thus allowing potential secrets to be exposed via the command line. In newer versions of cURL, you can pass headers from stdin using the `@-` syntax, which addresses this security concern. Although our script offers compatibility with the older method by allowing you to set the environment variable `ALLOW_LEGACY_CURL=true`, we strongly urge you to upgrade cURL if your environment permits.

To check your version of cURL, run the following command: `curl --version`

## Falcon API Permissions

API clients are granted one or more API scopes. Scopes allow access to specific CrowdStrike APIs and describe the actions that an API client can perform.

Ensure the following API scopes are enabled:

- **Sensor Download** [read]
- (optional) **Sensor update policies** [read]
  > Use this scope when configuring the `FALCON_SENSOR_UPDATE_POLICY_NAME` environment variable.

## Configuration

### Setting up Authentication

#### Using Client ID and Client Secret

Export the required environment variables:

```bash
export FALCON_CLIENT_ID="XXXXXXX"
export FALCON_CLIENT_SECRET="YYYYYYYYY"
```

#### Auto-Discovery of Falcon Cloud Region

The scripts support auto-discovery of the Falcon cloud region. If the `FALCON_CLOUD` environment variable is not set, the script will attempt to auto-discover it. If you want to set the cloud region manually, or if your region does not support auto-discovery, you can set the `FALCON_CLOUD` environment variable:

```bash
export FALCON_CLOUD="us-gov-1"
```

> [!IMPORTANT]
> Auto-discovery is only available for [us-1, us-2, eu-1] regions.

#### Using AWS SSM

The installer is AWS SSM aware, if `FALCON_CLIENT_ID` and `FALCON_CLIENT_SECRET` are not provided AND the script is running on an AWS instance, the script will try to get API credentials from the SSM store of the region.

### Install

```terminal
FALCON_CID                        (default: auto)
FALCON_CLOUD                      (default: us-1)
FALCON_SENSOR_VERSION_DECREMENT   (default: 0 [latest])
FALCON_PROVISIONING_TOKEN         (default: unset)
FALCON_SENSOR_UPDATE_POLICY_NAME  (default: unset)
FALCON_INSTALL_ONLY               (default: false)
FALCON_TAGS                       (default: unset)
FALCON_APD                        (default: unset)
FALCON_APH                        (default: unset)
FALCON_APP                        (default: unset)
FALCON_BILLING                    (default: default) possible values: [default|metered]
FALCON_BACKEND                    (default: auto)    possible values: [auto|bpf|kernel]
FALCON_TRACE                      (default: none)    possible values: [none|err|warn|info|debug]
ALLOW_LEGACY_CURL                 (default: false)
GET_ACCESS_TOKEN                  (default: false)   possible values: [true|false]
FALCON_REMOVE_HOST                (default: true)
```

***Examples***:

To download and run the script:

```bash
curl -L https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.3.4/bash/install/falcon-linux-install.sh | bash
```

Alternatively, you can run the script by cloning the repo:

```bash
git clone https://github.com/crowdstrike/falcon-scripts
```

Then, run the following command:

```bash
./falcon-linux-install.sh
```

or

```bash
bash falcon-linux-install.sh
```

### Uninstall

```terminal
Uninstalls the CrowdStrike Falcon Sensor from Linux operating systems.

The script recognizes the following environmental variables:

    - FALCON_CLIENT_ID                  (default: unset)
        Your CrowdStrike Falcon API client ID. Required if FALCON_REMOVE_HOST is 'true'.

    - FALCON_CLIENT_SECRET              (default: unset)
        Your CrowdStrike Falcon API client secret. Required if FALCON_REMOVE_HOST is 'true'.

    - FALCON_CLOUD                      (default: 'us-1')
        The CrowdStrike cloud region to use.
        Accepted values are ['us-1', 'us-2', 'eu-1', 'us-gov-1'].

    - FALCON_REMOVE_HOST                (default: unset)
        Determines whether the host should be removed from the Falcon console after uninstalling the sensor.
        Accepted values are ['true', 'false'].

    - FALCON_APH                        (default: unset)
        The proxy host for the sensor to use when communicating with CrowdStrike.

    - FALCON_APP                        (default: unset)
        The proxy port for the sensor to use when communicating with CrowdStrike.
```

***Examples***:

To download and run the script:

```bash
curl -L https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.3.4/bash/install/falcon-linux-uninstall.sh | bash
```

Uninstall and remove the host from the Falcon console:

```bash
export FALCON_CLIENT_ID="XXXXXXX"
export FALCON_CLIENT_SECRET="YYYYYYYYY"
export FALCON_REMOVE_HOST="true"
curl -L https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.3.4/bash/install/falcon-linux-uninstall.sh | bash
```

## Troubleshooting

To troubleshoot installation issues, run the script by using `bash -x`:

```bash
bash -x falcon-linux-install.sh
```

or

```bash
curl -L https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.3.4/bash/install/falcon-linux-install.sh | bash -x
```
