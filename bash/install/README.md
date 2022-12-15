# Falcon Linux Bash Installation Script

Bash script to install Falcon Sensor through the Falcon APIs on a Linux endpoint. By default,
this script will install, register the sensor, and start the service. If you would like to simply
install the sensor without any additional configurations, configure the `FALCON_INSTALL_ONLY`
environment variable.

## Configuration

1. Get sensor download API credentials from the cloud where your account has been configured:

  - https://falcon.crowdstrike.com/support/api-clients-and-keys
  - or https://falcon.us-2.crowdstrike.com/support/api-clients-and-keys
  - or https://falcon.eu-1.crowdstrike.com/support/api-clients-and-keys

Configure environment variables with your API credentials. Make sure that scope **Sensor Download** [read] is enabled.

Export the required environment variables:
```bash
export FALCON_CLIENT_ID="XXXXXXX"
export FALCON_CLIENT_SECRET="YYYYYYYYY"
```

The installer is AWS SSM aware, if `FALCON_CLIENT_ID` and `FALCON_CLIENT_SECRET` are not provided AND the script is running on an AWS instance, the script will try to get API credentials from the SSM store of the region.

Optional environment variables that can be exported:
```bash
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
```
The `FALCON_SENSOR_UPDATE_POLICY_NAME` variable requires to have additional API access. Make sure that scope **Sensor update policies** [read] is enabled.

2. Run the script:

```bash
curl -L https://raw.githubusercontent.com/crowdstrike/falcon-scripts/main/bash/install/falcon-linux-install.sh | bash
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
