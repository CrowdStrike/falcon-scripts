# falcon-k8s-cluster-deploy
Bash script to deploy latest Node Sensor or Sidecar Injector as DaemonSet and Kubernetes Protection agent pulling all images from the CrowdStrike Registry.

## Purpose:
To facilitate quick deployment of recommended CWP resources for testing. 

For other deployment methods including hosting sensor in private registry, Terraform, etc., see CrowdStrike documentation and CrowdStrike GitHub.

## Prerequisite:

- Script requires the following commands to be installed:
  - `curl`
  - `jq`
  - `helm`
  - `docker`, `podman`, or `skopeo`
- CrowdStrike API Client created with `Falcon Images Download (read)`, `Sensor Download (read)`, `Kubernetes Protection Agent (write)`, and `Kubernetes Protection (read/write)`  scope assigned.
- Crowdstrike CID (Customer ID) with two-digit checksum
- Cluster name (For KPA deployment)
- If you are using docker, make sure that docker is running locally.

## Usage:

```
usage: ./falcon-k8s-cluster-deploy.sh

Required Flags:
    -u, --client-id <FALCON_CLIENT_ID>             Falcon API OAUTH Client ID
    -s, --client-secret <FALCON_CLIENT_SECRET>     Falcon API OAUTH Client Secret
    -f, --cid <FALCON_CID_LONG>                    Falcon Customer ID inlcuding 2 digit checksum
    -c, --cluster <K8S_CLUSTER_NAME>               Customer cluster name
Optional Flags:
    -r, --region <FALCON_REGION>     Falcon Cloud
    -v, --version <SENSOR_VERSION>   Specify sensor version to deploy. Default is latest.
    --ebpf                           Deploy Falcon sensor in User - ebpf mode. Default is kernel.
    --sidecar                        Download sidecar-container sensor instead of container sensor
    --skip-kpa                       Skip deployment of KPA 
    --skip-sensor                    Skip deployment of Falcon sensor   
    --runtime                        Use a different container runtime [docker, podman, skopeo]. Default is docker.

Help Options:
    -h, --help display this help message"
```

Execute the script with the required and relevant input arguments. Script will deploy resources into the current kubeconfig context and will create namespaces `falcon-system` and `falcon-kubernetes-protection`.

The node sensor will deploy as a daemonset and automatically protect the host and all containers on the host.

The sidecar sensor will deploy an injector as daemonset. The injector will deploy the sidecar sensor into all newly started pods. Pre-existing workloads must be redeployed to be protected. The pull secret will be deployed into all namespaces at the time of helm chart deployment.

The Kubernetes Protection Agent will be deployed as one pod per cluster.


#### Example to deploy node sensor as daemonset plus KPA:
```
./falcon-k8s-cluster-deploy.sh \
--client-id <ABCDEFG123456> \
--client-secret <ABCDEFG123456> \
--cid <ABCDEFG123456-78> \
--cluster <myclustername>
```

#### Example to deploy sidecar sensor plus KPA:

```
./falcon-k8s-cluster-deploy.sh \
--client-id <ABCDEFG123456> \
--client-secret <ABCDEFG123456> \
--cid <ABCDEFG123456-78> \
--cluster <myclustername> \
--sidecar
```

### Full list of variables available:
Settings can be passed to the script through CLI Flags or environment variables:

| Flags                                          | Environment Variables   | Default                    | Description                                                                              |
|:-----------------------------------------------|-------------------------|----------------------------|------------------------------------------------------------------------------------------|
| `-f`, `--cid <FALCON_CID_LONG>`                     | `$FALCON_CID_LONG`            | `None` (Optional)          | CrowdStrike Customer ID (CID)                                                            |
| `-u`, `--client-id <FALCON_CLIENT_ID>`         | `$FALCON_CLIENT_ID`     | `None` (Required)          | CrowdStrike API Client ID                                                                |
| `-s`, `--client-secret <FALCON_CLIENT_SECRET>` | `$FALCON_CLIENT_SECRET` | `None` (Required)          | CrowdStrike API Client Secret                                                            |
| `-r`, `--region <FALCON_CLOUD>`                | `$FALCON_CLOUD`         | `us-1` (Optional)          | CrowdStrike Region                                                                       |                               |
| `-v`, `--version <SENSOR_VERSION>`             | `$SENSOR_VERSION`       | `None` (Optional)          | Specify sensor version to retrieve from the registry                                     |
| `-p`, `--platform <SENSOR_PLATFORM>`           | `$SENSOR_PLATFORM`      | `None` (Optional)          | Specify sensor platform to retrieve from the registry                                    |
| `--runtime`                                    | `$CONTAINER_TOOL`       | `docker` (Optional)        | Use a different container runtime [docker, podman, skopeo]. Default is docker. Local container runtime is used to list tags.         |                                         |
| `--ebpf`                                 | N/A                     | `None`                     | Deploys node sensor in user / eBPF mode instead of kernel mode. Not compatible with sidecar sensor.  
| `--sidecar`                                 | N/A                     | `None`                     | Deploys sidecar sensor injector as daemonset    
| `--skip-kpa`                                 | N/A                     | `None`                     | Skips deployment of Kubernetes Protection Agent    
| `--skip-sensor`                                 | N/A                     | `None`                     | Skips deployment of Falcon Sensor    
| `-h`, `--help`                                 | N/A                     | `None`                     | Display help message      

### Uninstall Helm Chart
To uninstall, run the following commands:
```

helm uninstall falcon-helm -n falcon-system
helm uninstall kpagent -n falcon-kubernetes-protection
kubectl delete ns falcon-system
kubectl delete ns falcon-kubernetes-protection
```                                                               