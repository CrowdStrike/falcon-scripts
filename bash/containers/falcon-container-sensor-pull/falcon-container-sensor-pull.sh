#!/bin/bash
: <<'#DESCRIPTION#'
File: falcon-container-sensor-pull.sh
Description: Bash script to copy Falcon DaemonSet & Container Sensor images from CrowdStrike Container Registry.
#DESCRIPTION#

set -e

usage()
{
    echo "usage: $0

Required Flags:
    -u, --client-id <FALCON_CLIENT_ID>             Falcon API OAUTH Client ID
    -s, --client-secret <FALCON_CLIENT_SECRET>     Falcon API OAUTH Client Secret

Optional Flags:
    -f, --cid <FALCON_CID>            Falcon Customer ID
    -r, --region <FALCON_REGION>      Falcon Cloud
    -c, --copy <REGISTRY/NAMESPACE>   registry to copy image e.g. myregistry.com/mynamespace
    -v, --version <SENSOR_VERSION>    specify sensor version to retrieve from the registry

    -n, --node                          download node sensor instead of container sensor
    -k, --kubernetes-protection-agent   download kubernetes protection agent instead of falcon sensor
    --runtime                           use a different container runtime [docker, podman, skopeo]. Default is docker.
    --dump-credentials                  print registry credentials to stdout to copy/paste into container tools.
    --list-tags                         list all tags available for the selected sensor

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
        FALCON_CID="${2}"
        shift
    fi
    ;;
    -c|--copy)
    if [ -n "${2}" ]; then
        COPY="${2}"
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
    --dump-credentials)
    if [ -n "${1}" ]; then
        CREDS=true
    fi
    ;;
    --list-tags)
    if [ -n "${1}" ]; then
        LISTTAGS=true
    fi
    ;;
    -n|--node)
    if [ -n "${1}" ]; then
        GET_NODE_SENSOR=true
    fi
    ;;
    -k|--kubernetes-protection-agent)
    if [ -n "${1}" ]; then
        GET_KPA=true
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
FALCON_CID=$(echo "${FALCON_CID}" | cut -d'-' -f1 | tr '[:upper:]' '[:lower:]')
SENSOR_VERSION=$(echo "$SENSOR_VERSION" | tr '[:upper:]' '[:lower:]')
COPY=$(echo "$COPY" | tr '[:upper:]' '[:lower:]')

#Check all mandatory variables set
VARIABLES="FALCON_CLIENT_ID FALCON_CLIENT_SECRET"
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

if grep -qw "skopeo" "$CONTAINER_TOOL" && [ -z "${COPY}" ] ; then
    echo "-c, --copy <REGISTRY/NAMESPACE> must also be set when using skopeo as a runtime"
    exit 1
fi

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

REGISTRY_NAMESPACE_CLOUD=$(
    # Account for govcloud api mismatch
    if [ "${FALCON_CLOUD}" = "us-gov-1" ]; then
        echo govcloud/release
    else
        echo $FALCON_CLOUD/release
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

if [ ! "$LISTTAGS" ] ; then
    echo "Using the following settings:"
    echo "Falcon Region:   $(cs_cloud)"
    echo "Falcon Registry: ${cs_registry}"
fi


if [ "$GET_KPA" ] ; then
    REGISTRY_TOKEN_API_ENDPOINT="https://$(cs_cloud)/kubernetes-protection/entities/integration/agent/v1?cluster_name=clustername&is_self_managed_cluster=true"
    REGISTRY_NAMESPACE=kubernetes_protection
    REGISTRY_IMAGE_NAME=kpagent
    REGISTRY_USERNAME_PREFIX=kp
    REGISTRY_TOKEN_JSON_KEY=dockerAPIToken
elif [ "$GET_NODE_SENSOR" ] ; then
    REGISTRY_TOKEN_API_ENDPOINT="https://$(cs_cloud)/container-security/entities/image-registry-credentials/v1"
    REGISTRY_NAMESPACE=falcon-sensor/$REGISTRY_NAMESPACE_CLOUD
    REGISTRY_IMAGE_NAME=falcon-sensor
    REGISTRY_USERNAME_PREFIX=fc
    REGISTRY_TOKEN_JSON_KEY=token
else
    REGISTRY_TOKEN_API_ENDPOINT="https://$(cs_cloud)/container-security/entities/image-registry-credentials/v1"
    REGISTRY_NAMESPACE=falcon-container/$REGISTRY_NAMESPACE_CLOUD
    REGISTRY_IMAGE_NAME=falcon-sensor
    REGISTRY_USERNAME_PREFIX=fc
    REGISTRY_TOKEN_JSON_KEY=token
fi

REGISTRY_PASSWORD=$(echo "authorization: Bearer $cs_falcon_oauth_token" | curl -s -L "$REGISTRY_TOKEN_API_ENDPOINT" -H @- | if [ "$GET_KPA" ]; then awk '/dockerAPIToken:/ {print $2}' ; else json_value "token" ; fi | sed 's/ *$//g' | sed 's/^ *//g')

#Set container login
(echo "$REGISTRY_PASSWORD" | "$CONTAINER_TOOL" login --username "$REGISTRY_USERNAME_PREFIX-$cs_falcon_cid" "$cs_registry" --password-stdin >/dev/null 2>&1) || ERROR=true

if [ "${ERROR}" = true ]; then
    die "ERROR: ${CONTAINER_TOOL} login failed"
fi

if [ "$LISTTAGS" ] ; then
    case "${CONTAINER_TOOL}" in
        *podman)
        die "Please use docker runtime to list tags" ;;
        *docker)
        REGISTRYBEARER=$(echo "-u $REGISTRY_USERNAME_PREFIX-$cs_falcon_cid:$REGISTRY_PASSWORD" | curl -s -L "https://$cs_registry/v2/token?=$REGISTRY_USERNAME_PREFIX-$cs_falcon_cid&scope=repository:$REGISTRY_NAMESPACE/$REGISTRY_IMAGE_NAME:pull&service=$cs_registry" -K- | json_value "token" | sed 's/ *$//g' | sed 's/^ *//g')
        echo "authorization: Bearer $REGISTRYBEARER" | curl -s -L "https://$cs_registry/v2/$REGISTRY_NAMESPACE/$REGISTRY_IMAGE_NAME/tags/list" -H @- | sed "s/, /, \\n/g" ;;
        *skopeo)
        die "Please use docker runtime to list tags" ;;
        *)         die "Unrecognized option: ${CONTAINER_TOOL}";;
    esac    
    exit 0
fi

#Get latest sensor version
case "${CONTAINER_TOOL}" in
        *podman)
        REGISTRY_IMAGE_TAG=$($CONTAINER_TOOL image search --list-tags "$cs_registry/$REGISTRY_NAMESPACE/$REGISTRY_IMAGE_NAME" | grep "$SENSOR_VERSION" | tail -1 | cut -d" " -f3);;
        *docker)
        REGISTRYBEARER=$(echo "-u $REGISTRY_USERNAME_PREFIX-$cs_falcon_cid:$REGISTRY_PASSWORD" | curl -s -L "https://$cs_registry/v2/token?=$REGISTRY_USERNAME_PREFIX-$cs_falcon_cid&scope=repository:$REGISTRY_NAMESPACE/$REGISTRY_IMAGE_NAME:pull&service=$cs_registry" -K- | json_value "token" | sed 's/ *$//g' | sed 's/^ *//g')
        REGISTRY_IMAGE_TAG=$(echo "authorization: Bearer $REGISTRYBEARER" | curl -s -L "https://$cs_registry/v2/$REGISTRY_NAMESPACE/$REGISTRY_IMAGE_NAME/tags/list" -H @- | awk -v RS=" " '{print}' | grep "$SENSOR_VERSION" | grep -o "[0-9a-zA-Z_\.\-]*" | tail -1);;
        *skopeo)
        REGISTRY_IMAGE_TAG=$($CONTAINER_TOOL list-tags "docker://$cs_registry/$REGISTRY_NAMESPACE/$REGISTRY_IMAGE_NAME" | grep "$SENSOR_VERSION" | grep -o "[0-9a-zA-Z_\.\-]*" | tail -1) ;;
        *)         die "Unrecognized option: ${CONTAINER_TOOL}";;
esac

if [ "$CREDS" ] ; then
    echo "CS Registry Username: $REGISTRY_USERNAME_PREFIX-${cs_falcon_cid}"
    echo "CS Registry Password: ${REGISTRY_PASSWORD}"
    exit 0
fi

#Construct full image path
FULLIMAGEPATH="$cs_registry/$REGISTRY_NAMESPACE/$REGISTRY_IMAGE_NAME:${REGISTRY_IMAGE_TAG}"

if grep -qw "skopeo" "$CONTAINER_TOOL" ; then
    "$CONTAINER_TOOL" copy "docker://$FULLIMAGEPATH" "docker://$COPY/$REGISTRY_IMAGE_NAME:$REGISTRY_IMAGE_TAG"
else
    #Pull the container image locally
    "$CONTAINER_TOOL" pull "$FULLIMAGEPATH"

    # For those that don't want to use skopeo to copy
    if [ -n "$COPY" ]; then
        "$CONTAINER_TOOL" tag "$FULLIMAGEPATH" "$COPY/$REGISTRY_IMAGE_NAME:$REGISTRY_IMAGE_TAG"
        "$CONTAINER_TOOL" push "$COPY/$REGISTRY_IMAGE_NAME:$REGISTRY_IMAGE_TAG"
    fi
fi
