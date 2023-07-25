# Falcon Container Sensor pull script

Use this bash script to pull the latest **Falcon Container** sensor, **Node Kernel Mode DaemonSet** sensor, or **Kubernetes Admission Controller** from the CrowdStrike container registry and push it to your local Docker registry or remote registries.

## Security recommendations

### Use cURL version 7.55.0 or later

We've identified a security concern related to cURL versions 7.54.1 and earlier. In these versions, request headers were set using the `-H` option, which allowed potential secrets to be exposed via the command line. In newer versions of cURL, versions 7.55.0 and later, you can pass headers from stdin using the `@-` syntax, which addresses this security concern. **We recommend that you to upgrade cURL to version 7.55.0 or later**. If this is not possible, this script offers compatibility with the older method through the use of the `--allow-legacy-curl` optional command line flag.

To check your version of cURL, run the following command: `curl --version`

## Prerequisites

- Script requires the following commands to be installed:
  - `curl`
  - `docker`, `podman`, or `skopeo`
- CrowdStrike API Client created with these scopes:
    - `Falcon Images Download (read)`
    - `Sensor Download (read)`
- If you are using Docker, make sure that Docker is running locally.

## Usage

```terminal
usage: falcon-container-sensor-pull.sh

Required Flags:
    -u, --client-id <FALCON_CLIENT_ID>             Falcon API OAUTH Client ID
    -s, --client-secret <FALCON_CLIENT_SECRET>     Falcon API OAUTH Client Secret

Optional Flags:
    -f, --cid <FALCON_CID>            Falcon Customer ID
    -r, --region <FALCON_REGION>      Falcon Cloud
    -c, --copy <REGISTRY/NAMESPACE>   registry to copy image e.g. myregistry.com/mynamespace
    -v, --version <SENSOR_VERSION>    specify sensor version to retrieve from the registry
    -p, --platform <SENSOR_PLATFORM>  specify sensor platform to retrieve e.g x86_64, aarch64

    -n, --node                        download node sensor instead of container sensor
    --kubernetes-admission-controller download kubernetes admission controller instead of falcon sensor
    --runtime                         use a different container runtime [docker, podman, skopeo]. Default is docker.
    --dump-credentials                print registry credentials to stdout to copy/paste into container tools.
    --list-tags                       list all tags available for the selected sensor
    --allow-legacy-curl               allow the script to run with an older version of curl

Help Options:
    -h, --help display this help message
```

### Full list of variables available

> **Note**: **Settings can be passed to the script via CLI flags or environment variables:**

| Flags                                          | Environment Variables   | Default                    | Description                                                                              |
|:-----------------------------------------------|-------------------------|----------------------------|------------------------------------------------------------------------------------------|
| `-f`, `--cid <FALCON_CID>`                     | `$FALCON_CID`           | `None` (Optional)          | CrowdStrike Customer ID (CID)                                                            |
| `-u`, `--client-id <FALCON_CLIENT_ID>`         | `$FALCON_CLIENT_ID`     | `None` (Required)          | CrowdStrike API Client ID                                                                |
| `-s`, `--client-secret <FALCON_CLIENT_SECRET>` | `$FALCON_CLIENT_SECRET` | `None` (Required)          | CrowdStrike API Client Secret                                                            |
| `-r`, `--region <FALCON_CLOUD>`                | `$FALCON_CLOUD`         | `us-1` (Optional)          | CrowdStrike Region                                                                       |
| `-c`, `--copy <REGISTRY/NAMESPACE>`            | `$COPY`                 | `None` (Optional)          | Registry you want to copy the sensor image to. Example: `myregistry.com/mynamespace`                               |
| `-v`, `--version <SENSOR_VERSION>`             | `$SENSOR_VERSION`       | `None` (Optional)          | Specify sensor version to retrieve from the registry                                     |
| `-p`, `--platform <SENSOR_PLATFORM>`           | `$SENSOR_PLATFORM`      | `None` (Optional)          | Specify sensor platform to retrieve from the registry                                    |
| `-n`, `--node`                                 | `$SENSORTYPE`           | `falcon-sensor` (Optional) | Flag to download Node Sensor. **Default is Container Sensor**. |
| `--kubernetes-admission-controller`            | `$SENSORTYPE`           | `falcon-kac` (Optional)    | Flag to download Kubernetes Admission Controller. **Default is Container Sensor**. |
| `--runtime`                                    | `$CONTAINER_TOOL`       | `docker` (Optional)        | Use a different container runtime [docker, podman, skopeo]. **Default is Docker**.           |
| `--dump-credentials`                           | `$CREDS`                | `False` (Optional)         | Print registry credentials to stdout to copy/paste into container tools                 |
| `--list-tags`                                  | `$LISTTAGS`             | `False` (Optional)         | List all tags available for the selected sensor                                          |
| `--allow-legacy-curl`                          | `$ALLOW_LEGACY_CURL`    | `False` (Optional)         | Allow the script to run with an older version of cURL                                          |
| `-h`, `--help`                                 | N/A                     | `None`                     | Display help message                                                                     |

### Example usage to download DaemonSet sensor

#### Example using `autodiscover`

```
./falcon-container-sensor-pull.sh \
--client-id <ABCDEFG123456> \
--client-secret <ABCDEFG123456> \
--node
```

#### Example without using `autodiscover`

```
./falcon-container-sensor-pull.sh \
--cid <ABCDEFG123456> \
--client-id <ABCDEFG123456> \
--client-secret <ABCDEFG123456> \
--region us-2 \
--node
```
