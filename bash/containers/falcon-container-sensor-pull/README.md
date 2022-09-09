# falcon-container-sensor-pull
Bash script to pull latest Falcon Container or Node Kernel Mode DaemonSet Sensor from the CrowdStrike Container Registry to your local docker registry or remote registry with Skopeo

## Prerequisite:

- Script requires the following commands to be installed:
  - `curl`
  - `docker`, `podman`, or `skopeo`
- CrowdStrike API Client created with `Falcon Images Download` scope assigned.
- If you are using docker, make sure that docker is running locally.

## Usage:

```
usage: ./falcon-container-sensor-pull.sh

Required Flags:
    -u, --client-id <FALCON_CLIENT_ID>             Falcon API OAUTH Client ID
    -s, --client-secret <FALCON_CLIENT_SECRET>     Falcon API OAUTH Client Secret

Optional Flags:
    -f, --cid <FALCON_CID>            Falcon Customer ID
    -r, --region <FALCON_REGION>      Falcon Cloud
    -c, --copy <REGISTRY/NAMESPACE>   registry to copy image e.g. myregistry.com/mynamespace
    -v, --version <SENSOR_VERSION>    specify sensor version to retrieve from the registry

    -n, --node          download node sensor instead of container sensor
    --runtime           use a different container runtime [docker, podman, skopeo]. Default is docker.
    --dump-credentials  print registry credentials to stdout to copy/paste into container tools.

Help Options:
    -h, --help display this help message
```

Execute the script with the relevant input arguments.

### Example usage to download DaemonSet Sensor

#### Example using `autodiscover`:
./falcon-container-sensor-pull.sh \
--client-id <ABCDEFG123456> \
--client-secret <ABCDEFG123456> \
--node

#### Example without using `autodiscover`:

```
./falcon-container-sensor-pull.sh \
--cid <ABCDEFG123456> \
--client-id <ABCDEFG123456> \
--client-secret <ABCDEFG123456> \
--region us-2 \
--node
```

### Full list of variables available:
Settings can be passed to the script through CLI Flags or environment variables:

| Flags                                          | Environment Variables   | Default                    | Description                                                                              |
|:-----------------------------------------------|-------------------------|----------------------------|------------------------------------------------------------------------------------------|
| `-f`, `--cid <FALCON_CID>`                     | `$FALCON_CID            | `None` (Optional)          | CrowdStrike Customer ID (CID)                                                            |
| `-u`, `--client-id <FALCON_CLIENT_ID>`         | `$FALCON_CLIENT_ID`     | `None` (Required)          | CrowdStrike API Client ID                                                                |
| `-s`, `--client-secret <FALCON_CLIENT_SECRET>` | `$FALCON_CLIENT_SECRET` | `None` (Required)          | CrowdStrike API Client Secret                                                            |
| `-r`, `--region <FALCON_CLOUD>`                | `$FALCON_CLOUD`         | `us-1` (Optional)          | CrowdStrike Region                                                                       |
| `-c`, `--copy <REGISTRY/NAMESPACE>`            | `$COPY`                 | `None` (Optional)          | Registry to copy image e.g. myregistry.com/mynamespace to                                |
| `-v`, `--version <SENSOR_VERSION>`             | `$SENSOR_VERSION`       | `None` (Optional)          | Specify sensor version to retrieve from the registry                                     |
| `-n`, `--node`                                 | `$SENSORTYPE`           | `falcon-sensor` (Optional) | Flag to download Node Sensor, if not set script defaults to downloading container sensor |
| `--runtime`                                    | `$CONTAINER_TOOL`       | `docker` (Optional)        | Use a different container runtime [docker, podman, skopeo]. Default is docker.           |
| `--dump-credentials`                           | `$CREDS`                | `False` (Optional)         | Print registry credentials to stdout to copy/paste into container tools.                 |
| `-h`, `--help`                                 | N/A                     | `None`                     | Display help message                                                                     |
