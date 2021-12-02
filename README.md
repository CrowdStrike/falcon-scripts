# Falcon Linux Bash Installation Script

Bash script to install Falcon Sensor through the Falcon APIs on a Linux endpoint.

## Configuration

1. Get sensor download API credentials from the cloud where your account has been configured:

  - https://falcon.crowdstrike.com/support/api-clients-and-keys
  - or https://falcon.us-2.crowdstrike.com/support/api-clients-and-keys
  - or https://falcon.eu-1.crowdstrike.com/support/api-clients-and-keys

Configure environment variables with your API credentials. Make sure that scope Sensor Download [read] is enabled.

Export the required environment variables:
```bash
export FALCON_CLIENT_ID="XXXXXXX"
export FALCON_CLIENT_SECRET="YYYYYYYYY"
```

Optional environment variables that can be exported:
```bash
FALCON_CID                        (default: auto)
FALCON_CLOUD                      (default: us-1)
FALCON_SENSOR_VERSION_DECREMENT   (default: 0 [latest])
FALCON_PROVISIONING_TOKEN         (default: unset)
FALCON_SENSOR_UPDATE_POLICY_NAME  (default: unset)
```
The `FALCON_SENSOR_UPDATE_POLICY_NAME` variable requires to have additional API access. Make sure that scope Sensor update policies [read] is enabled.

2. Run the script:

```bash
curl -L https://raw.githubusercontent.com/crowdstrike/falcon-linux-install-bash/main/falcon-linux-deploy.sh | bash
```

Alternatively, you can run the script by cloning the repo:

```bash
git clone https://github.com/crowdstrike/falcon-linux-install-bash
```

Then, run the following command:

```bash
./falcon-linux-deploy.sh
```
or
```bash
bash falcon-linux-deploy.sh
```
