# falcon-container-sensor-pull
## Bash script to pull latest Falcon Container or Node Kernel Mode DaemonSet Sensor from the CrowdStrike Container Registry to your local docker images

### Prerequisite: 
Script requires the following packages to be available: `curl`, `jq`, `docker`

CrowdStrike API Client created with `Falcon Images Download` scope assigned.
### Usage:
Make the script file executable `chmod +x ./falcon-container-sensor-pull.sh`

Ensure docker is running locally.

Execute the script with the relevant input arguments, GovCloud customers can omit the region flag and simply use the `--gov` flag to correctly set the endpoint.

### Example usage to download DaemonSet Sensor from Falcon US-2:
```
./falcon-container-sensor-pull.sh \
--cid <ABCDEFGHIJKLMN> \
--clientid <ABCDEFG123456> \
--clientsecret <ABCDEFG123456> \
--region US-2 \
--node
```
### Full list of variables available:
Variables can be passed to the script either via Arguments or via EnvVars:

| Short Form         | Long Form                      | EnvVar             | Default           |Description                                                                             | 
|:-------------------|--------------------------------|--------------------|-------------------|----------------------------------------------------------------------------------------|
| `-f <CID>`         | `--cid <CID>`                  | `$CID`             | `None` (Required) |CrowdStrike Customer ID (CID)                                                           | 
| `-u <CLIENT_ID>`   | `--clientid <CLIENT_ID>`       | `$CS_CLIENT_ID`    | `None` (Required) |CrowdStrike API Client ID                                                               | 
| `-s <CLIENTSECRET>`| `--clientsecret <CLIENTSECRET>`| `$CS_CLIENT_SECRET`| `None` (Required) |CrowdStrike API Client Secret                                                           | 
| `-r <REGION>`      | `--region <REGION>`            | `$REGION`          | `US-1` (Optional) |CrowdStrike Region                                                                      | 
| `-g`               | `--gov`                        | `$GOV`            | `false` (Optional)|Flag to set falcon API endpoints and registry to falcon gov cloud|
| `-n`               | `--node`                       | `$NODE`            | `false` (Optional)|Flag to download Node Sensor, if not set script defaults to downloading container sensor| 
| `-h`               | `--help`                       | N/A                | `None`            |Display help message                                                                    | 



