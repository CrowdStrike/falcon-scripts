#!/bin/bash
: <<'#DESCRIPTION#'
File: falcon-cluster-deploy.sh
Description: Bash script to deploy Falcon Node Sensor as daemonset and Kubernetes Protection Agent
Requirements: docker or podman or skopeo, jq, helm 
#DESCRIPTION#

set -e

usage()
{
    echo "usage: $0

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
    exit 2
}

die() {
    echo "Fatal error: $*" >&2
    exit 1
}

cs_container() {
    case "${CONTAINER_TOOL}" in
        skopeo)      echo "skopeo";;
        podman)      echo "podman";;
        docker)      echo "docker";;
        *)           die "Unrecognized option: ${CONTAINER_TOOL}";;
    esac
}

cs_cloud() {
    case "${FALCON_CLOUD}" in
        us-1)      echo "api.crowdstrike.com";;
        us-2)      echo "api.us-2.crowdstrike.com";;
        eu-1)      echo "api.eu-1.crowdstrike.com";;
        us-gov-1)  echo "api.laggar.gcw.crowdstrike.com";;
        *)         die "Unrecognized option: ${FALCON_CLOUD}";;
    esac
}

json_value() {
    KEY=$1
    num=$2
    awk -F"[,:}]" '{for(i=1;i<=NF;i++){if($i~/'"$KEY"'\042/){print $(i+1)}}}' | tr -d '"' | sed -n "${num}p"
}


while [ $# != 0 ]; do
case "$1" in
    -u|--client-id)
    if [ -n "${2:-}" ] ; then
        FALCON_CLIENT_ID="${2}"
        shift
    fi
    ;;
    -s|--client-secret)
    if [ -n "${2:-}" ]; then
        FALCON_CLIENT_SECRET="${2}"
        shift
    fi
    ;;
    -r|--region)
    if [ -n "${2:-}" ]; then
        FALCON_CLOUD="${2}"
        shift
    fi
    ;;
    -f|--cid)
    if [ -n "${2:-}" ]; then
        FALCON_CID_LONG="${2}"
        shift
    fi
    ;;
    -c|--cluster)
    if [ -n "${2}" ]; then
        K8S_CLUSTER_NAME="${2}"
        shift
    fi
    ;;
    -v|--version)
    if [ -n "${2:-}" ]; then
        SENSOR_VERSION="${2}"
        shift
    fi
    ;;
    --runtime)
    if [ -n "${2}" ]; then
        CONTAINER_TOOL="${2}"
        shift
    fi
    ;;
    --ebpf)
    if [ -n "${1}" ]; then
        BACKEND="bpf"
    fi
    ;;
    --sidecar)
    if [ -n "${1}" ]; then
        SENSORTYPE="falcon-container"
    fi
    ;;
    --skip-kpa)
    if [ -n "${1}" ]; then
        SKIPKPA=true
    fi
    ;;
    --skip-sensor)
    if [ -n "${1}" ]; then
        SKIPSENSOR=true
    fi
    ;;
    -h|--help)
    if [ -n "${1}" ]; then
        usage
    fi
    ;;
    --) # end argument parsing
    shift
    break
    ;;
    -*) # unsupported flags
    >&2 echo "ERROR: Unsupported flag: '${1}'"
    usage
    ;;
esac
shift
done

# shellcheck disable=SC2086
FALCON_CLOUD=$(echo ${FALCON_CLOUD:-'us-1'} | tr '[:upper:]' '[:lower:]')

# shellcheck disable=SC2086
CONTAINER_TOOL=$(echo ${CONTAINER_TOOL:-docker} | tr '[:upper:]' '[:lower:]')
# shellcheck disable=SC2005,SC2001
cs_registry="registry.crowdstrike.com"
if [ "${FALCON_CLOUD}" = "us-gov-1" ]; then
    cs_registry="registry.laggar.gcw.crowdstrike.com"
fi
FALCON_CID=$(echo "${FALCON_CID_LONG}" | cut -d'-' -f1 | tr '[:upper:]' '[:lower:]')
SENSOR_VERSION=$(echo "$SENSOR_VERSION" | tr '[:upper:]' '[:lower:]')

#Check if user wants to download DaemonSet Node Sensor
if [ -z "$SENSORTYPE" ]; then
    SENSORTYPE="falcon-sensor"
fi

#Check if user wants to deploy sensor in user mode instead of default kernel mode
if [ -z "$BACKEND" ]; then
    BACKEND="kernel"
fi

#Check if user wants to skip sensor deployment
if [ -z "$SKIPSENSOR" ]; then
    SKIPSENSOR=false
fi

#Check if user wants to skip Kubernetes Protection Agent deployment
if [ -z "$SKIPKPA" ]; then
    SKIPKPA=false
fi

#Check for incompatible backend for container sensor
if [[ ${BACKEND} = "bpf" && ${SENSORTYPE} = "falcon-container" ]]; then
    echo "The eBPF user mode is incompatible with Sidecar sensor"
    exit 1
fi

#Check all mandatory variables set
VARIABLES="FALCON_CLIENT_ID FALCON_CLIENT_SECRET FALCON_CID_LONG K8S_CLUSTER_NAME"
{
    for VAR_NAME in $VARIABLES; do
        [ -z "$(eval "echo \"\$$VAR_NAME\"")" ] && echo "$VAR_NAME is not configured!" && VAR_UNSET=true
    done
        [ -n "$VAR_UNSET" ] && usage
}

if ! command -v "$CONTAINER_TOOL" > /dev/null 2>&1; then
    echo "The '$CONTAINER_TOOL' command is missing or invalid. Please install it before continuing. Aborting..."
    exit 2
else
    CONTAINER_TOOL=$(command -v "$CONTAINER_TOOL")
fi

# Functions to authenticate and deploy
function auth_and_tag {
    response_headers=$(mktemp)
    cs_falcon_oauth_token=$(
        if ! command -v curl > /dev/null 2>&1; then
            die "The 'curl' command is missing. Please install it before continuing. Aborting..."
        fi

        token_result=$(echo "client_id=$FALCON_CLIENT_ID&client_secret=$FALCON_CLIENT_SECRET" | \
                    curl -X POST -s -L "https://$(cs_cloud)/oauth2/token" \
                        -H 'Content-Type: application/x-www-form-urlencoded; charset=utf-8' \
                        --dump-header "$response_headers" \
                        --data @-)
        token=$(echo "$token_result" | json_value "access_token" | sed 's/ *$//g' | sed 's/^ *//g')
        if [ -z "$token" ]; then
            die "Unable to obtain CrowdStrike Falcon OAuth Token. Response was $token_result"
        fi
        echo "$token"
    )

    region_hint=$(grep -i ^x-cs-region: "$response_headers" | head -n 1 | tr '[:upper:]' '[:lower:]' | tr -d '\r' | sed 's/^x-cs-region: //g')
    rm "${response_headers}"

    if [ "x${FALCON_CLOUD}" != "x${region_hint}" ] && [ "${region_hint}" != "" ]; then
        if [ -z "${region_hint}" ]; then
            die "Unable to obtain region hint from CrowdStrike Falcon OAuth API, Please provide FALCON_CLOUD environment variable as an override."
        fi
        FALCON_CLOUD="${region_hint}"
    fi

    registry_opts=$(
        # Account for govcloud api mismatch
        if [ "${FALCON_CLOUD}" = "us-gov-1" ]; then
            echo "$SENSORTYPE/govcloud"
        else
            echo "$SENSORTYPE/$FALCON_CLOUD"
        fi
    )

    cs_falcon_cid=$(
        if [ -n "$FALCON_CID" ]; then
            echo "$FALCON_CID" | cut -d'-' -f1 | tr '[:upper:]' '[:lower:]'
        else
            cs_target_cid=$(echo "authorization: Bearer $cs_falcon_oauth_token" | curl -s -L "https://$(cs_cloud)/sensors/queries/installers/ccid/v1" -H @-)
            echo "$cs_target_cid" | tr -d '\n" ' | awk -F'[][]' '{print $2}' | cut -d'-' -f1 | tr '[:upper:]' '[:lower:]'
        fi
    )

# Display info about deployment
echo "Using the following settings:"
echo "Falcon Region:   $(cs_cloud)"
echo "Falcon Registry: ${cs_registry}"
echo "Falcon CID: ${FALCON_CID_LONG}"
echo "Cluster Name: ${K8S_CLUSTER_NAME}"
if [ $SENSORTYPE = "falcon-container" ]; then
    echo "Sensor being deployed as sidecar"
else
    echo "Sensor being deployed as daemonset node sensor"
    echo "Deploying in ${BACKEND} mode"
fi

    #Set Docker token using the BEARER token captured earlier
    ART_PASSWORD=$(echo "authorization: Bearer $cs_falcon_oauth_token" | curl -s -L \
    "https://$(cs_cloud)/container-security/entities/image-registry-credentials/v1" -H @- | json_value "token" | sed 's/ *$//g' | sed 's/^ *//g')

    #Set container login
    (echo "$ART_PASSWORD" | "$CONTAINER_TOOL" login --username "fc-$cs_falcon_cid" "$cs_registry" --password-stdin >/dev/null 2>&1) || ERROR=true
    if [ "${ERROR}" = true ]; then
        die "ERROR: ${CONTAINER_TOOL} login failed"
    fi

    if [ "$LISTTAGS" ] ; then
        case "${CONTAINER_TOOL}" in
            *podman)
            die "Please use docker runtime to list tags" ;;
            *docker)
            REGISTRYBEARER=$(echo "-u fc-$cs_falcon_cid:$ART_PASSWORD" | curl -s -L "https://$cs_registry/v2/token?=fc-$cs_falcon_cid&scope=repository:$registry_opts/release/falcon-sensor:pull&service=registry.crowdstrike.com" -K- | json_value "token" | sed 's/ *$//g' | sed 's/^ *//g')
            echo "authorization: Bearer $REGISTRYBEARER" | curl -s -L "https://$cs_registry/v2/$registry_opts/release/falcon-sensor/tags/list" -H @- | sed "s/, /, \\n/g" ;;
            *skopeo)
            die "Please use docker runtime to list tags" ;;
            *)         die "Unrecognized option: ${CONTAINER_TOOL}";;
        esac    
        exit 0
    fi

    #Get latest sensor version
    case "${CONTAINER_TOOL}" in
            *podman)
            LATESTSENSOR=$($CONTAINER_TOOL image search --list-tags "$cs_registry/$registry_opts/release/falcon-sensor" | grep "$SENSOR_VERSION" | tail -1 | cut -d" " -f3);;
            *docker)
            REGISTRYBEARER=$(echo "-u fc-$cs_falcon_cid:$ART_PASSWORD" | curl -s -L "https://$cs_registry/v2/token?=fc-$cs_falcon_cid&scope=repository:$registry_opts/release/falcon-sensor:pull&service=registry.crowdstrike.com" -K- | json_value "token" | sed 's/ *$//g' | sed 's/^ *//g')
            LATESTSENSOR=$(echo "authorization: Bearer $REGISTRYBEARER" | curl -s -L "https://$cs_registry/v2/$registry_opts/release/falcon-sensor/tags/list" -H @- | awk -v RS=" " '{print}' | grep "$SENSOR_VERSION" | grep -o "[0-9a-zA-Z_\.\-]*" | tail -1);;
            *skopeo)
            LATESTSENSOR=$($CONTAINER_TOOL list-tags "docker://$cs_registry/$registry_opts/release/falcon-sensor" | grep "$SENSOR_VERSION" | grep -o "[0-9a-zA-Z_\.\-]*" | tail -1) ;;
            *)         die "Unrecognized option: ${CONTAINER_TOOL}";;
    esac

    # Create base64 encoded config JSON 
    # -w flag is unnecessary and errors out on macOS on base64 utility. 
    REPOSITORY="$cs_registry/$registry_opts/release/falcon-sensor"
    OS=$(uname -s)
    if [ "${OS}" = "Darwin" ]; then
        ART_USERNAME="fc-$(echo ${FALCON_CID} | awk '{ print tolower($0) }' | cut -d'-' -f1)"
        IMAGE_PULL_TOKEN=$(echo -n $ART_USERNAME:$ART_PASSWORD | base64)
        registryConfigJSON=$(echo {"\"auths\"":{"\"${cs_registry}\"":{"\"auth\"":"\"${IMAGE_PULL_TOKEN}\""}}} | base64)
    else
        ART_USERNAME="fc-$(echo ${FALCON_CID} | awk '{ print tolower($0) }' | cut -d'-' -f1)"
        IMAGE_PULL_TOKEN=$(echo -n $ART_USERNAME:$ART_PASSWORD | base64 -w 0)
        registryConfigJSON=$(echo {"\"auths\"":{"\"${cs_registry}\"":{"\"auth\"":"\"${IMAGE_PULL_TOKEN}\""}}} | base64 -w 0)
    fi
    return
}

function deploy_node_sensor {
    helm repo add crowdstrike https://crowdstrike.github.io/falcon-helm
    helm repo update
    helm upgrade --install falcon-helm crowdstrike/falcon-sensor \
        -n falcon-system --create-namespace \
        --set falcon.cid=${FALCON_CID_LONG} \
        --set node.image.repository=${REPOSITORY} \
        --set node.image.tag=${LATESTSENSOR} \
        --set node.image.registryConfigJSON=${registryConfigJSON} \
        --set node.backend=${BACKEND} 
    return
}
    
function deploy_container_sensor {
    helm repo add crowdstrike https://crowdstrike.github.io/falcon-helm
    helm repo update
    helm upgrade --install falcon-helm crowdstrike/falcon-sensor \
        -n falcon-system --create-namespace \
        --set falcon.cid=${FALCON_CID_LONG} \
        --set container.image.repository=${REPOSITORY} \
        --set container.image.tag=${LATESTSENSOR} \
        --set node.enabled=false \
        --set container.enabled=true \
        --set container.image.pullSecrets.enable=true \
        --set container.image.pullSecrets.allNamespaces=true \
        --set container.image.pullSecrets.registryConfigJSON=${registryConfigJSON} 
    echo ""
    echo "Sidecar injector deployed. You must restart pre-existing pods to inject sensor into those workloads."
    echo ""
    return
}

#Deploy KPA via helm
#Pulls Docker API token programatically for registry pull token
function deploy_kpa {
    FALCON_API_ACCESS_TOKEN=$(curl -sL -X POST "https://$(cs_cloud)/oauth2/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "client_id=${FALCON_CLIENT_ID}" \
        --data-urlencode "client_secret=${FALCON_CLIENT_SECRET}" | jq -cr '.access_token')
    FALCON_KPA_PASSWORD=$(curl -sL -X GET "https://$(cs_cloud)/kubernetes-protection/entities/integration/agent/v1?cluster_name=""&is_self_managed_cluster=true" \
        -H "Accept: application/yaml" \
        -H "Authorization: Bearer ${FALCON_API_ACCESS_TOKEN}" | awk '/dockerAPIToken:/ {print $2}')
    helm repo add kpagent-helm https://registry.crowdstrike.com/kpagent-helm && helm repo update
    helm repo update
    helm upgrade --install --create-namespace -n falcon-kubernetes-protection kpagent kpagent-helm/cs-k8s-protection-agent \
        --set crowdstrikeConfig.clientID=${FALCON_CLIENT_ID} \
        --set crowdstrikeConfig.clientSecret=${FALCON_CLIENT_SECRET} \
        --set crowdstrikeConfig.clusterName=${K8S_CLUSTER_NAME} \
        --set crowdstrikeConfig.env=${FALCON_CLOUD} \
        --set crowdstrikeConfig.cid=${FALCON_CID} \
        --set crowdstrikeConfig.dockerAPIToken=${FALCON_KPA_PASSWORD}
    return
}


#Authenticate and deploy based on selected options
auth_and_tag
if [[ "${SENSORTYPE}" = "falcon-sensor" && $SKIPSENSOR = false ]]; then
    deploy_node_sensor
fi

if [[ "${SENSORTYPE}" = "falcon-container" && $SKIPSENSOR = false ]]; then
    deploy_container_sensor
fi

if [ $SKIPKPA = false ]; then
    deploy_kpa
fi
