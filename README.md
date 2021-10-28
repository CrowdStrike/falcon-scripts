# Falcon Linux Bash Installation Script

Bash script to install Falcon Sensor through the Falcon APIs on a Linux endpoint.

## Configuration

1. Get sensor download API credentials from the cloud where your account has been configured:

  - https://falcon.crowdstrike.com/support/api-clients-and-keys
  - or https://falcon.us-2.crowdstrike.com/support/api-clients-and-keys
  - or https://falcon.eu-1.crowdstrike.com/support/api-clients-and-keys

Configure environment variables with your API credentials (scope Sensor Download [read]):

```shell
export FALCON_CLIENT_ID="XXXXXXX"
export FALCON_CLIENT_SECRET="YYYYYYYYY"
```

2. Run the script:

```shell
./falcon-linux-deploy.sh
```
