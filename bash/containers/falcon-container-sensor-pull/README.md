# Falcon Container Sensor Pull Script

This bash script pulls the latest **Falcon Container** or **Node Kernel Mode DaemonSet** sensor from the CrowdStrike container registry to your local Docker registry or remote registries.

## Security Recommendations

### Use cURL version 7.55.0 or newer

We have identified a security concern related to cURL versions prior to 7.55, which required request headers to be set using the `-H` option, thus allowing potential secrets to be exposed via the command line. In newer versions of cURL, you can pass headers from stdin using the `@-` syntax, which addresses this security concern. Although our script offers compatibility with the older method through the use of the `--allow-legacy-curl` optional command line flag, we strongly urge you to upgrade cURL if your environment permits.

To check your version of cURL, run the following command: `curl --version`

## Prerequisites

- Script requires the following commands to be installed:
  - `curl`
  - `docker`, `podman`, or `skopeo`
- CrowdStrike API Client created with `Falcon Images Download (read)` AND `Sensor Download (read)` scope assigned.
- If you are using docker, make sure that docker is running locally.

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

    -n, --node              download node sensor instead of container sensor
    --runtime               use a different container runtime [docker, podman, skopeo]. Default is docker.
    --dump-credentials      print registry credentials to stdout to copy/paste into container tools.
    --list-tags             list all tags available for the selected sensor
    --allow-legacy-curl     allow the script to run with an older version of curl

Help Options:
    -h, --help display this help message
```

### Full list of variables available

> **Settings can be passed to the script via CLI flags or environment variables:**

| Flags                                          | Environment Variables   | Default                    | Description                                                                              |
|:-----------------------------------------------|-------------------------|----------------------------|------------------------------------------------------------------------------------------|
| `-f`, `--cid <FALCON_CID>`                     | `$FALCON_CID            | `None` (Optional)          | CrowdStrike Customer ID (CID)                                                            |
| `-u`, `--client-id <FALCON_CLIENT_ID>`         | `$FALCON_CLIENT_ID`     | `None` (Required)          | CrowdStrike API Client ID                                                                |
| `-s`, `--client-secret <FALCON_CLIENT_SECRET>` | `$FALCON_CLIENT_SECRET` | `None` (Required)          | CrowdStrike API Client Secret                                                            |
| `-r`, `--region <FALCON_CLOUD>`                | `$FALCON_CLOUD`         | `us-1` (Optional)          | CrowdStrike Region                                                                       |
| `-c`, `--copy <REGISTRY/NAMESPACE>`            | `$COPY`                 | `None` (Optional)          | Registry to copy image e.g. myregistry.com/mynamespace to                                |
| `-v`, `--version <SENSOR_VERSION>`             | `$SENSOR_VERSION`       | `None` (Optional)          | Specify sensor version to retrieve from the registry                                     |
| `-p`, `--platform <SENSOR_PLATFORM>`           | `$SENSOR_PLATFORM`      | `None` (Optional)          | Specify sensor platform to retrieve from the registry                                    |
| `-n`, `--node`                                 | `$SENSORTYPE`           | `falcon-sensor` (Optional) | Flag to download Node Sensor, if not set script defaults to downloading container sensor |
| `--runtime`                                    | `$CONTAINER_TOOL`       | `docker` (Optional)        | Use a different container runtime [docker, podman, skopeo]. Default is docker.           |
| `--dump-credentials`                           | `$CREDS`                | `False` (Optional)         | Print registry credentials to stdout to copy/paste into container tools.                 |
| `--list-tags`                                  | `$LISTTAGS`             | `False` (Optional)         | List all tags available for the selected sensor                                          |
| `--allow-legacy-curl`                          | `$ALLOW_LEGACY_CURL`    | `False` (Optional)         | Allow the script to run with an older version of curl                                          |
| `-h`, `--help`                                 | N/A                     | `None`                     | Display help message                                                                     |

### Example usage to download DaemonSet sensor

#### Example using `autodiscover`

``` bash
./falcon-container-sensor-pull.sh \
--client-id <ABCDEFG123456> \
--client-secret <ABCDEFG123456> \
--node
```

#### Example without using `autodiscover`

``` bash
./falcon-container-sensor-pull.sh \
--cid <ABCDEFG123456> \
--client-id <ABCDEFG123456> \
--client-secret <ABCDEFG123456> \
--region us-2 \
--node
```
