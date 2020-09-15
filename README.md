# Falcon Linux Bash installation script

Bash script to install Falcon Sensor, through the Falcon APIs, on a Linux endpoint.

## Configuration

- Step 1 : Get sensor download API credentials here : 
  - https://falcon.crowdstrike.com/support/api-clients-and-keys
  - or https://falcon.eu-1.crowdstrike.com/support/api-clients-and-keys

  Configure in the script or set environment variable with those credentials.

  - `export CS_API_CLIENT_ID="XXXXXXX"`
  - `export CS_API_CLIENT_SECRET="YYYYYYYYY"`

- Step 2 : Configure the target OS and the target path

- Step 3 : run the script

## Usage

run the script :

- `chmod 755 falcon-linux-deploy.sh`
- `./falcon-linux-deploy.sh`