# Falcon Container Sensor pull script

Use this bash script to pull the latest **Falcon Container** sensor, **Node DaemonSet** sensor, **Kubernetes Admission Controller** or **Kubernetes Protection Agent** from the CrowdStrike container registry and push it to your local Docker registry or remote registries.

## Deprecation Warning :warning:

Please refer to the [Deprecation](DEPRECATION.md) document for more information pertaining to deprecated features and upcoming changes in version 2.0.0.

## Multi-Architecture Support :rocket:

The Falcon Container Sensor Pull script now supports multi-arch images. However, there are some limitations to be aware of:

- Currently only the `falcon-sensor` container image supports multi-arch as of 7.15.X.
  - The `falcon-sensor` image supports the following platforms:
    - `x86_64`
    - `aaarch64`
- `--list-tags` will list all tags for a selected platform **and** multi-arch images.
  - This is because multi-arch images support multiple platforms with the same tag.
- ***Pulling the full multi-arch image locally is not supported***
  - Because pulling mutilple images with the same tag locally will overwrite the previous image, the script will allow:
    - Pulling the image for a specific platform with the `-p, --platform` flag.
    - Or copying the multi-arch image to a different registry with the `-c, --copy` flag.

Refer to the [examples](#examples) section for more information on how to use the script with multi-arch images.

> [!NOTE]
> While we do support copying the multi-arch image to a different registry using Podman, Docker, or Skopeo, we recommend using Skopeo for this purpose. Skopeo is a tool specifically designed for copying container images between registries and supports multi-arch images.

## Security recommendations

### Use cURL version 7.55.0 or later

We've identified a security concern related to cURL versions 7.54.1 and earlier. In these versions, request headers were set using the `-H` option, which allowed potential secrets to be exposed via the command line. In newer versions of cURL, versions 7.55.0 and later, you can pass headers from stdin using the `@-` syntax, which addresses this security concern. **We recommend that you to upgrade cURL to version 7.55.0 or later**. If this is not possible, this script offers compatibility with the older method through the use of the `--allow-legacy-curl` optional command line flag.

To check your version of cURL, run the following command: `curl --version`

## Prerequisites

**Ensure the following are installed:**

- `curl`
- `docker`, `podman`, or `skopeo`
  > If using Docker, make sure it is running locally.

**Create a CrowdStrike API Client with the appropriate scopes based on the sensor type:**
> [!IMPORTANT]
> The following API scopes are the minimum required to retrieve the images. If you need to perform other operations post-retrieval, please refer to the CrowdStrike documentation to identify any additional scopes that may be required.

- **falcon-sensor | falcon-container | falcon-kac | falcon-imageanalyzer**
  - `Sensor Download (read)`
  - `Falcon Images Download (read)`
- **kpagent**
  - `Sensor Download (read)`
  - `Falcon Images Download (read)`
  - `Kubernetes Protection (read)`
- **falcon-snapshot**
  - `Sensor Download (read)`
  - `Snapshot Scanner Image Download (read)`
- **fcs**
  - `Sensor Download (read)`
  - `Infrastructure as Code (read)`

## Auto-Discovery of Falcon Cloud Region

> [!IMPORTANT]
> Auto-discovery is only available for [us-1, us-2, eu-1] regions.

The script supports auto-discovery of the Falcon cloud region. If the cloud region is not provided, the script will attempt to auto-discover it. If you want to set the cloud region manually, or if your region does not support auto-discovery, you set the `FALCON_CLOUD` environment variable or use the `-r, --region` flag.

## Usage

```terminal
Usage: falcon-container-sensor-pull.sh [options]
Version: 1.5.3

Required Flags:
    -u, --client-id <FALCON_CLIENT_ID>             Falcon API OAUTH Client ID
    -s, --client-secret <FALCON_CLIENT_SECRET>     Falcon API OAUTH Client Secret

Optional Flags:
    -f, --cid <FALCON_CID>                         Falcon Customer ID
    -r, --region <FALCON_CLOUD>                    Falcon Cloud Region [us-1|us-2|eu-1|us-gov-1] (Default: us-1)
    -c, --copy <REGISTRY/NAMESPACE>                Registry to copy the image to, e.g., myregistry.com/mynamespace
    -v, --version <SENSOR_VERSION>                 Specify sensor version to retrieve from the registry
    -p, --platform <SENSOR_PLATFORM>               Specify sensor platform to retrieve, e.g., x86_64, aarch64
    -t, --type <SENSOR_TYPE>                       Specify which sensor to download [falcon-container|falcon-sensor|falcon-kac|falcon-snapshot|falcon-imageanalyzer|kpagent|fcs] (Default: falcon-container)

    --runtime <RUNTIME>                            Use a different container runtime [docker, podman, skopeo] (Default: docker)
    --dump-credentials                             Print registry credentials to stdout to copy/paste into container tools
    --get-image-path                               Get the full image path including the registry, repository, and latest tag for the specified SENSOR_TYPE
    --get-pull-token                               Get the pull token of the selected SENSOR_TYPE for Kubernetes
    --get-cid                                      Get the CID assigned to the API Credentials
    --list-tags                                    List all tags available for the selected sensor type and platform(optional)
    --allow-legacy-curl                            Allow the script to run with an older version of curl

Internal Flags:
    --internal-build-stage <BUILD_STAGE>           (Internal only) Falcon Build Stage [release|stage] (Default: release)

Help Options:
    -h, --help                                     Display this help message
```

### Full list of variables available

> **Note**: **Settings can be passed to the script via CLI flags or environment variables:**

| Flags                                          | Environment Variables   | Default                    | Description                                                                              |
|:-----------------------------------------------|-------------------------|----------------------------|------------------------------------------------------------------------------------------|
| `-f`, `--cid <FALCON_CID>`                     | `$FALCON_CID`           | `None` (Optional)          | CrowdStrike Customer ID (CID). *If not provided, CID will be auto-detected.*                                                            |
| `-u`, `--client-id <FALCON_CLIENT_ID>`         | `$FALCON_CLIENT_ID`     | `None` (Required)          | CrowdStrike API Client ID                                                                |
| `-s`, `--client-secret <FALCON_CLIENT_SECRET>` | `$FALCON_CLIENT_SECRET` | `None` (Required)          | CrowdStrike API Client Secret                                                            |
| `-r`, `--region <FALCON_CLOUD>`                | `$FALCON_CLOUD`         | `us-1` (Optional)          | CrowdStrike Region. \**Auto-discovery is only available for [`us-1, us-2, eu-1`] regions.* |
| `-c`, `--copy <REGISTRY/NAMESPACE>`            | `$COPY`                 | `None` (Optional)          | Registry you want to copy the sensor image to. Example: `myregistry.com/mynamespace`     |
| `-v`, `--version <SENSOR_VERSION>`             | `$SENSOR_VERSION`       | `None` (Optional)          | Specify sensor version to retrieve from the registry                                     |
| `-p`, `--platform <SENSOR_PLATFORM>`           | `$SENSOR_PLATFORM`      | `None` (Optional)          | Specify sensor platform to retrieve from the registry                                    |
| `-t`, `--type <SENSOR_TYPE>`                   | `$SENSOR_TYPE`          | `falcon-container` (Optional) | Specify which sensor to download [`falcon-container`, `falcon-sensor`, `falcon-kac`, `falcon-snapshot`, `falcon-imageanalyzer`, `kpagent`, `fcs`] ([see more details below](#sensor-types)) |
| `--runtime`                                    | `$CONTAINER_TOOL`       | `docker` (Optional)        | Use a different container runtime [docker, podman, skopeo]. **Default is Docker**.       |
| `--dump-credentials`                           | `$CREDS`                | `False` (Optional)         | Print registry credentials to stdout to copy/paste into container tools                  |
| `--get-image-path`                             | N/A                     | `None`                     | Get the full image path including the registry, repository, and latest tag for the specified `SENSOR_TYPE`. |
| `--get-pull-token`                             | N/A                     | `None`                     | Get the pull token of the selected `SENSOR_TYPE` for Kubernetes.                         |
| `--get-cid`                                    | N/A                     | `None`                     | Get the CID assigned to the API Credentials.                                             |
| `--list-tags`                                  | `$LISTTAGS`             | `False` (Optional)         | List all tags available for the selected sensor                                          |
| `--allow-legacy-curl`                          | `$ALLOW_LEGACY_CURL`    | `False` (Optional)         | Allow the script to run with an older version of cURL                                    |
| `-h`, `--help`                                 | N/A                     | `None`                     | Display help message                                                                     |

---
> **Note**: **Internal flags are for CrowdStrike internal use only. Internal flags do not provide any functionality to end customers.**

| Internal Flags                                 | Environment Variables   | Default                    | Description                                                                              |
|:-----------------------------------------------|-------------------------|----------------------------|------------------------------------------------------------------------------------------|
| `--internal-build-stage <BUILD_STAGE>`         | `$BUILD_STAGE`          | `release` (Optional)       | Falcon Build Stage [`release, stage`]                                                    |

---

### Sensor Types

The following sensor types are available to download:

| Sensor Image Name | Description |
|:-------------|:------------|
| `falcon-sensor` | The Falcon sensor for Linux as a DaemonSet deployment |
| `falcon-container` **(default)** | The Falcon Container sensor for Linux |
| `falcon-kac` | The Falcon Kubernetes Admission Controller |
| `falcon-snapshot` | The Falcon Snapshot scanner |
| `falcon-imageanalyzer` | The Falcon Image Assessment at Runtime |
| `kpagent` | The Falcon Kubernetes Protection Agent |
| `fcs` | The Falcon Cloud Security CLI tool |

### Examples

#### Example downloading the Falcon Kubernetes Admission Controller

The following example will attempt to autodiscover the region and download the latest version of the Falcon Kubernetes Admission Controller container image.

```shell
./falcon-container-sensor-pull.sh \
--client-id <FALCON_CLIENT_ID> \
--client-secret <FALCON_CLIENT_SECRET> \
--type falcon-kac
```

#### Example getting the full image path for the Falcon DaemonSet sensor

The following example will print the image repository path with the latest image tag of the Falcon DaemonSet sensor.

```shell
./falcon-container-sensor-pull.sh \
--client-id <FALCON_CLIENT_ID> \
--client-secret <FALCON_CLIENT_SECRET> \
--type falcon-sensor \
--get-image-path
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

#### Example generating a pull token for K8s

The following example will generate a pull token for the Falcon Container sensor for use in Kubernetes.

```shell
./falcon-container-sensor-pull.sh \
--client-id <FALCON_CLIENT_ID> \
--client-secret <FALCON_CLIENT_SECRET> \
--type falcon-container \
--get-pull-token
```

#### Example getting the CID

The following example will get the CID for the Falcon Sensor configuration for kubernetes deployment.

```shell
./falcon-container-sensor-pull.sh \
--client-id <FALCON_CLIENT_ID> \
--client-secret <FALCON_CLIENT_SECRET> \
--type falcon-sensor \
--get-cid
```

#### Example dumping credentials

The following example will dump the credentials to stdout to copy/paste into container tools.

```shell
./falcon-container-sensor-pull.sh \
--client-id <FALCON_CLIENT_ID> \
--client-secret <FALCON_CLIENT_SECRET> \
--dump-credentials
```

#### Example copying multi-arch image to a different registry

The following example will copy the `falcon-sensor` multi-arch image to a different registry using Skopeo.

```shell
./falcon-container-sensor-pull.sh \
--client-id <FALCON_CLIENT_ID> \
--client-secret <FALCON_CLIENT_SECRET> \
--type falcon-sensor \
--copy myregistry.com/mynamespace
--runtime skopeo
```

#### Example copying multi-arch image for a specific platform

The following example will copy the `falcon-sensor` multi-arch image for the `aarch64` platform to a different registry using Skopeo.

```shell
./falcon-container-sensor-pull.sh \
--client-id <FALCON_CLIENT_ID> \
--client-secret <FALCON_CLIENT_SECRET> \
--type falcon-sensor \
--platform aarch64
--copy myregistry.com/mynamespace
--runtime skopeo
```

#### Example pulling the image for a specific platform from a multi-arch image

The following example will pull the `falcon-sensor` image for the `x86_64` platform from the multi-arch image using Docker.

```shell
./falcon-container-sensor-pull.sh \
--client-id <FALCON_CLIENT_ID> \
--client-secret <FALCON_CLIENT_SECRET> \
--type falcon-sensor \
--platform x86_64
```
