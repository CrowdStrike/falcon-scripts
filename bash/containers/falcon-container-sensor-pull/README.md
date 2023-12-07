# Falcon Container Sensor pull script

Use this bash script to pull the latest **Falcon Container** sensor, **Node Kernel Mode DaemonSet** sensor, **Kubernetes Admission Controller** or **Kubernetes Protection Agent** from the CrowdStrike container registry and push it to your local Docker registry or remote registries.

## Deprecation Warning :warning:

1. **Default Sensor Type Change** : The default sensor type will be changed from `falcon-container` to `falcon-sensor`. This change is based off of feedback from our customers and is intended to simplify the usage of this script.

1. **Environment Variable Deprecation** : The `SENSORTYPE` environment variable will be deprecated and replaced by `SENSOR_TYPE`. This update is intended to increase readability and maintain consistency in our environment variable naming convention.

1. **Command Option Deprecation** : The command line options `-n, --node`, `--kubernetes-admission-controller`, and `--kubernetes-protection-agent` will be deprecated and replaced by a single option `-t, --type`. The new `-t, --type` option will allow you to specify the sensor type in a more straightforward and simplified manner.

While these changes will be officially introduced in version 2.0.0, we will continue to support the deprecated environment variable and command options until that release. We strongly encourage you to adapt your usage to include the new `SENSOR_TYPE` environment variable and `-t, --type` command option to ensure a smooth transition when version 2.0.0 is released.

Please refer to the updated usage instructions and examples in the [Usage](#usage) section of this README. Feel free to reach out with any questions or concerns.

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
  - `Kubernetes Protection (read)`
    - For `kpagent` only
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
    -t, --type <SENSOR_TYPE>          specify which sensor to download [falcon-container|falcon-sensor|falcon-kac|kpagent]
                                      Default is falcon-container.

    --runtime                         use a different container runtime [docker, podman, skopeo]. Default is docker.
    --dump-credentials                print registry credentials to stdout to copy/paste into container tools.
    --get-pull-token                  get the pull token of the selected SENSOR_TYPE for Kubernetes.
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
| `-c`, `--copy <REGISTRY/NAMESPACE>`            | `$COPY`                 | `None` (Optional)          | Registry you want to copy the sensor image to. Example: `myregistry.com/mynamespace`     |
| `-v`, `--version <SENSOR_VERSION>`             | `$SENSOR_VERSION`       | `None` (Optional)          | Specify sensor version to retrieve from the registry                                     |
| `-p`, `--platform <SENSOR_PLATFORM>`           | `$SENSOR_PLATFORM`      | `None` (Optional)          | Specify sensor platform to retrieve from the registry                                    |
| `-t`, `--type <SENSOR_TYPE>`                   | `$SENSOR_TYPE`         | `falcon-container` (Optional) | Specify which sensor to download [`falcon-container`, `falcon-sensor`, `falcon-kac`, `kpagent`] ([see more details below](#sensor-types)) |
| `--runtime`                                    | `$CONTAINER_TOOL`       | `docker` (Optional)        | Use a different container runtime [docker, podman, skopeo]. **Default is Docker**.       |
| `--dump-credentials`                           | `$CREDS`                | `False` (Optional)         | Print registry credentials to stdout to copy/paste into container tools                  |
| `--get-pull-token`                             | N/A                     | `None`                     | Get the pull token of the selected SENSOR_TYPE for Kubernetes.                           |
| `--list-tags`                                  | `$LISTTAGS`             | `False` (Optional)         | List all tags available for the selected sensor                                          |
| `--allow-legacy-curl`                          | `$ALLOW_LEGACY_CURL`    | `False` (Optional)         | Allow the script to run with an older version of cURL                                    |
| `-h`, `--help`                                 | N/A                     | `None`                     | Display help message                                                                     |

### Sensor Types

The following sensor types are available to download:

| Sensor Image Name | Description |
|:-------------|:------------|
| `falcon-sensor` | The Falcon sensor for Linux as a DaemonSet deployment |
| `falcon-container` **(default)** | The Falcon Container sensor for Linux |
| `falcon-kac` | The Falcon Kubernetes Admission Controller |
| `kpagent` | The Falcon Kubernetes Protection Agent |

### Examples

#### Example downloading the Falcon Kubernetes Admission Controller

The following example will attempt to autodiscover the region and download the latest version of the Falcon Kubernetes Admission Controller container image.

```shell
./falcon-container-sensor-pull.sh \
--client-id <FALCON_CLIENT_ID> \
--client-secret <FALCON_CLIENT_SECRET> \
--type falcon-kac
```

#### Example downloading the Falcon DaemonSet sensor

The following example will download the latest version of the Falcon DaemonSet sensor container image and copy it to another registry.

```shell
./falcon-container-sensor-pull.sh \
--client-id <FALCON_CLIENT_ID> \
--client-secret <FALCON_CLIENT_SECRET> \
--region us-2 \
--type falcon-sensor \
--copy myregistry.com/mynamespace
```

#### Example dumping credentials

The following example will dump the credentials to stdout to copy/paste into container tools.

```shell
./falcon-container-sensor-pull.sh \
--client-id <FALCON_CLIENT_ID> \
--client-secret <FALCON_CLIENT_SECRET> \
--dump-credentials
```
