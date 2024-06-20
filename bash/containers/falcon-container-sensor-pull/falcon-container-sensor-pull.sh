#!/bin/bash
: <<'#DESCRIPTION#'
File: falcon-container-sensor-pull.sh
Description: Bash script to copy Falcon DaemonSet Sensor, Container Sensor, Kubernetes Admission Controller or Kubernetes Protection Agent images from CrowdStrike Container Registry.
#DESCRIPTION#

set -e

VERSION="1.4.2"

usage() {
    echo "Usage: $0 [options]
Version: $VERSION

Required Flags:
    -u, --client-id <FALCON_CLIENT_ID>             Falcon API OAUTH Client ID
    -s, --client-secret <FALCON_CLIENT_SECRET>     Falcon API OAUTH Client Secret

Optional Flags:
    -f, --cid <FALCON_CID>                         Falcon Customer ID
    -r, --region <FALCON_CLOUD>                    Falcon Cloud Region [us-1|us-2|eu-1|us-gov-1] (Default: us-1)
    -c, --copy <REGISTRY/NAMESPACE>                Registry to copy the image to, e.g., myregistry.com/mynamespace
    -v, --version <SENSOR_VERSION>                 Specify sensor version to retrieve from the registry
    -p, --platform <SENSOR_PLATFORM>               Specify sensor platform to retrieve, e.g., x86_64, aarch64
    -t, --type <SENSOR_TYPE>                       Specify which sensor to download [falcon-container|falcon-sensor|falcon-kac|falcon-snapshot|falcon-imageanalyzer|kpagent] (Default: falcon-container)

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
    -h, --help                                     Display this help message"
    exit 2
}

die() {
    echo "Fatal error: $*" >&2
    exit 1
}

# todo: Remove in next major release
deprecated() {
    echo "WARNING: $* is deprecated and will be removed in a future release"
}

cs_cloud() {
    case "${FALCON_CLOUD}" in
        us-1) echo "api.crowdstrike.com" ;;
        us-2) echo "api.us-2.crowdstrike.com" ;;
        eu-1) echo "api.eu-1.crowdstrike.com" ;;
        us-gov-1) echo "api.laggar.gcw.crowdstrike.com" ;;
        *) die "Unrecognized region option: ${FALCON_CLOUD}" ;;
    esac
}

json_value() {
    KEY=$1
    num=$2
    awk -F"[,:}]" '{for(i=1;i<=NF;i++){if($i~/'"$KEY"'\042/){print $(i+1)}}}' | tr -d '"' | sed -n "${num}p"
}

while [ $# != 0 ]; do
    case "$1" in
        -u | --client-id)
            if [ -n "${2:-}" ]; then
                FALCON_CLIENT_ID="${2}"
                shift
            fi
            ;;
        -s | --client-secret)
            if [ -n "${2:-}" ]; then
                FALCON_CLIENT_SECRET="${2}"
                shift
            fi
            ;;
        -r | --region)
            if [ -n "${2:-}" ]; then
                FALCON_CLOUD="${2}"
                shift
            fi
            ;;
        -f | --cid)
            if [ -n "${2:-}" ]; then
                FALCON_CID="${2}"
                shift
            fi
            ;;
        -c | --copy)
            if [ -n "${2}" ]; then
                COPY="${2}"
                shift
            fi
            ;;
        -v | --version)
            if [ -n "${2:-}" ]; then
                SENSOR_VERSION="${2}"
                shift
            fi
            ;;
        -p | --platform)
            if [ -n "${2:-}" ]; then
                SENSOR_PLATFORM="${2}"
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
        --get-image-path)
            if [ -n "${1}" ]; then
                GETIMAGEPATH=true
            fi
            ;;
        --get-pull-token)
            if [ -n "${1}" ]; then
                PULLTOKEN=true
            fi
            ;;
        --get-cid)
            if [ -n "${1}" ]; then
                GETCID=true
            fi
            ;;
        --list-tags)
            if [ -n "${1}" ]; then
                LISTTAGS=true
            fi
            ;;
        --allow-legacy-curl)
            if [ -n "${1}" ]; then
                ALLOW_LEGACY_CURL=true
            fi
            ;;
        -n | --node)
            if [ -n "${1}" ]; then
                deprecated "-n|--node"
                SENSOR_TYPE="falcon-sensor"
            fi
            ;;
        --kubernetes-admission-controller)
            if [ -n "${1}" ]; then
                deprecated "--kubernetes-admission-controller"
                SENSOR_TYPE="falcon-kac"
            fi
            ;;
        --kubernetes-protection-agent)
            if [ -n "${1}" ]; then
                deprecated "--kubernetes-protection-agent"
                SENSOR_TYPE="kpagent"
            fi
            ;;
        -t | --type)
            if [ -n "${2}" ]; then
                SENSOR_TYPE="${2}"
                shift
            fi
            ;;
        --internal-build-stage)
            if [ -n "${2:-}" ]; then
                BUILD_STAGE="${2}"
                shift
            fi
            ;;
        -h | --help)
            if [ -n "${1}" ]; then
                usage
            fi
            ;;
        --) # end argument parsing
            shift
            break
            ;;
        -*) # unsupported flags
            echo >&2 "ERROR: Unsupported flag: '${1}'"
            usage
            ;;
    esac
    shift
done

# Check if curl is greater or equal to 7.55
old_curl=$(
    version=$(curl --version | head -n 1 | awk '{ print $2 }')
    minimum="7.55"

    # Check if the version is less than the minimum
    if printf "%s\n" "$version" "$minimum" | sort -V -C; then
        echo 0
    else
        echo 1
    fi
)

# Old curl print warning message
if [ "$old_curl" -eq 0 ]; then
    if [ "${ALLOW_LEGACY_CURL}" != "true" ]; then
        echo """
WARNING: Your version of curl does not support the ability to pass headers via stdin.
For security considerations, we strongly recommend upgrading to curl 7.55.0 or newer.

To bypass this warning, set the optional flag --allow-legacy-curl
"""
        exit 1
    fi
fi

curl_command() {
    # Dash does not support arrays, so we have to pass the args as separate arguments
    local token="$1"
    set -- "$@"
    if [ "$old_curl" -eq 0 ]; then
        curl -s -L -H "Authorization: Bearer ${token}" "$@"
    else
        echo "Authorization: Bearer ${token}" | curl -s -L -H @- "$@"
    fi
}

fetch_tags() {
    # Fetches tags from the CrowdStrike registry
    registry_bearer=$(echo "-u $ART_USERNAME:$ART_PASSWORD" |
        curl -s -L "https://$cs_registry/v2/token?=$ART_USERNAME&scope=repository:$registry_opts/$repository_name:pull&service=registry.crowdstrike.com" -K- |
        json_value "token" |
        sed 's/ *$//g' | sed 's/^ *//g')
    curl_command "$registry_bearer" "https://$cs_registry/v2/$registry_opts/$repository_name/tags/list"
}

format_tags() {
    # Formats tags and handles sorting for KPA
    local all_tags=$1

    case "${SENSOR_TYPE}" in
        "kpagent" | "falcon-snapshot" | "falcon-imageanalyzer")
            echo "$all_tags" |
                sed -n 's/.*"tags" : \[\(.*\)\].*/\1/p' |
                tr -d '"' | tr ',' '\n' |
                awk -F. '{ printf "%05d.%05d.%05d\n", $1, $2, $3 }' |
                sort |
                awk -F. '{ printf "\"%d.%d.%d\"\n", $1+0, $2+0, $3+0 }'
            ;;
        *)
            echo "$all_tags" |
                sed -n 's/.*"tags" : \[\(.*\)\].*/\1/p' |
                awk -F',' -v keyword="$SENSOR_PLATFORM" '{
                    for (i=1; i<=NF; i++) {
                        if (($i ~ keyword || $i !~ /x86_64|aarch64/) && $i !~ /sha256/) {
                            print $i
                        }
                    }
                }'
            ;;
    esac
}

print_formatted_tags() {
    local formatted_tags=$1

    # Print a JSON object with tags properly formatted
    printf "{\n  \"name\": \"%s\",\n  \"repository\": \"%s\",\n  \"tags\": [\n" "${IMAGE_NAME}" "${REPOSITORY}"
    first=true
    echo "$formatted_tags" | while IFS= read -r tag; do
        if [ "$first" = true ]; then
            printf "    %s" "$tag"
            first=false
        else
            printf ",\n    %s" "$tag"
        fi
    done
    printf "\n  ]\n}\n"
}

list_tags() {
    all_tags=$(fetch_tags)
    formatted_tags=$(format_tags "$all_tags")

    print_formatted_tags "$formatted_tags"
}

platform_override() {
    # Allow platform/arch override when dealing with multi-arch images
    case "${SENSOR_PLATFORM}" in
        x86_64) echo "amd64" ;;
        aarch64) echo "arm64" ;;
        *) die "Unrecognized platform option: ${SENSOR_PLATFORM}" ;;
    esac
}

is_multi_arch() {
    local image_path="$1"
    local manifest_output

    case "${CONTAINER_TOOL}" in
        *docker | *podman)
            manifest_output=$($CONTAINER_TOOL manifest inspect "$image_path" 2>/dev/null)
            ;;
        *skopeo)
            manifest_output=$(skopeo inspect "docker://$image_path" --raw 2>/dev/null)
            ;;
        *)
            die "Unsupported container tool: $CONTAINER_TOOL"
            ;;
    esac

    if echo "$manifest_output" | grep -q '"manifests"'; then
        echo true
    else
        echo false
    fi
}

pull_image() {
    local image_path="$1"
    local platform_override="$2"
    if [ -n "$platform_override" ]; then
        "$CONTAINER_TOOL" pull --platform "$platform_override" "$image_path"
    else
        "$CONTAINER_TOOL" pull "$image_path"
    fi
}

copy_image() {
    local source_path="$1"
    local destination_path="$2"
    local multi_arch_copy="$3"
    if [ "$multi_arch_copy" = "true" ]; then
        case "${CONTAINER_TOOL}" in
            *skopeo)
                "$CONTAINER_TOOL" copy --all "docker://$source_path" "docker://$destination_path"
                ;;
            *podman)
                "$CONTAINER_TOOL" manifest create --all "$destination_path" "$source_path" >/dev/null
                "$CONTAINER_TOOL" manifest push --all "$destination_path"
                "$CONTAINER_TOOL" manifest rm "$destination_path" >/dev/null
                ;;
            *docker)
                if ! "$CONTAINER_TOOL" buildx version >/dev/null 2>&1; then
                    die "Docker buildx is not installed/enabled. Please install/enable buildx before continuing."
                else
                    "$CONTAINER_TOOL" buildx imagetools create --tag "$destination_path" "$source_path"
                fi
                ;;
            *)
                die "Unrecognized option: ${CONTAINER_TOOL}"
                ;;
        esac
    else
        # Copy the image to the desired registry
        "$CONTAINER_TOOL" tag "$source_path" "$destination_path"
        "$CONTAINER_TOOL" push "$destination_path"
    fi
}

detect_container_tool() {
    local container_tool
    if command -v docker >/dev/null 2>&1; then
        container_tool="docker"
    elif command -v podman >/dev/null 2>&1; then
        container_tool="podman"
    elif command -v skopeo >/dev/null 2>&1; then
        container_tool="skopeo"
    else
        die "No container runtime tool found. Please install either Docker, Podman, or Skopeo."
    fi
    echo $container_tool
}

display_api_scopes() {
    local sensor_type=$1
    case "${sensor_type}" in
        falcon-sensor | falcon-container | falcon-kac | falcon-imageanalyzer)
            echo "Sensor Download [read], Falcon Images Download [read]"
            ;;
        kpagent)
            echo "Sensor Download [read], Falcon Images Download [read], Kubernetes Protection [read]"
            ;;
        falcon-snapshot)
            echo "Sensor Download [read], Snapshot Scanner Image Download [read]"
            ;;
        *)
            die "Unknown sensor type: ${sensor_type}"
            ;;
    esac
}

# shellcheck disable=SC2086
FALCON_CLOUD=$(echo ${FALCON_CLOUD:-'us-1'} | tr '[:upper:]' '[:lower:]')

# Call the function to auto-detect the container tool if not specified
if [ -z "${CONTAINER_TOOL}" ]; then
    CONTAINER_TOOL=$(detect_container_tool)
else
    CONTAINER_TOOL=$(echo "${CONTAINER_TOOL}" | tr '[:upper:]' '[:lower:]')
fi

# Validate container tool
case "${CONTAINER_TOOL}" in
    skopeo | docker | podman) ;;
    *) die "Unrecognized container runtime: ${CONTAINER_TOOL}" ;;
esac

# shellcheck disable=SC2005,SC2001
cs_registry="registry.crowdstrike.com"
if [ "${FALCON_CLOUD}" = "us-gov-1" ]; then
    cs_registry="registry.laggar.gcw.crowdstrike.com"
fi
SENSOR_VERSION=$(echo "$SENSOR_VERSION" | tr '[:upper:]' '[:lower:]')
SENSOR_PLATFORM=$(echo "$SENSOR_PLATFORM" | tr '[:upper:]' '[:lower:]')
COPY=$(echo "$COPY" | tr '[:upper:]' '[:lower:]')

# Check if SENSORTYPE or SENSOR_TYPE env var is set
# If not, default SENSOR_TYPE to falcon-container
# *SENSORTYPE is deprecated and will be removed in a future release
if [ -z "${SENSOR_TYPE}" ] && [ -z "${SENSORTYPE}" ]; then
    deprecated "The default sensor type of falcon-container"
    SENSOR_TYPE="falcon-container"
elif [ -z "${SENSOR_TYPE}" ] && [ -n "${SENSORTYPE}" ]; then
    deprecated "SENSORTYPE"
    SENSOR_TYPE="${SENSORTYPE}"
fi

# Check if SENSOR_TYPE is set to a valid value
case "${SENSOR_TYPE}" in
    falcon-container | falcon-sensor | falcon-kac | falcon-snapshot | falcon-imageanalyzer | kpagent) ;;
    *) die """
    Unrecognized sensor type: ${SENSOR_TYPE}
    Valid values are [falcon-container|falcon-sensor|falcon-kac|falcon-snapshot|falcon-imageanalyzer|kpagent]""" ;;
esac

#Check all mandatory variables set
VARIABLES="FALCON_CLIENT_ID FALCON_CLIENT_SECRET"
{
    for VAR_NAME in $VARIABLES; do
        [ -z "$(eval "echo \"\$$VAR_NAME\"")" ] && echo "$VAR_NAME is not configured!" && VAR_UNSET=true
    done
    [ -n "$VAR_UNSET" ] && usage
}

if ! command -v "$CONTAINER_TOOL" >/dev/null 2>&1; then
    echo "The '$CONTAINER_TOOL' command is missing or invalid. Please install it before continuing. Aborting..."
    exit 2
else
    CONTAINER_TOOL=$(command -v "$CONTAINER_TOOL")
fi

if grep -qw "skopeo" "$CONTAINER_TOOL" && [ -z "${COPY}" ] && [ -z "${LISTTAGS}" ]; then
    echo "-c, --copy <REGISTRY/NAMESPACE> must also be set when using skopeo as a runtime"
    exit 1
fi

response_headers=$(mktemp)
cs_falcon_oauth_token=$(
    if ! command -v curl >/dev/null 2>&1; then
        die "The 'curl' command is missing. Please install it before continuing. Aborting..."
    fi

    token_result=$(echo "client_id=$FALCON_CLIENT_ID&client_secret=$FALCON_CLIENT_SECRET" |
        curl -X POST -s -L "https://$(cs_cloud)/oauth2/token" \
            -H 'Content-Type: application/x-www-form-urlencoded; charset=utf-8' \
            -H "User-Agent: crowdstrike-falcon-script/$VERSION" \
            --dump-header "$response_headers" \
            --data @-)
    token=$(echo "$token_result" | json_value "access_token" | sed 's/ *$//g' | sed 's/^ *//g')
    if [ -z "$token" ]; then
        die "Unable to obtain CrowdStrike Falcon OAuth Token. Double check your credentials and/or ensure you set the correct cloud region."
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
        echo "$SENSOR_TYPE/gov1"
    else
        echo "$SENSOR_TYPE/$FALCON_CLOUD"
    fi
)

cs_falcon_cid_with_checksum=$(
    if [ -n "$FALCON_CID" ]; then
        echo "$FALCON_CID"
    else
        cs_target_cid=$(curl_command "$cs_falcon_oauth_token" "https://$(cs_cloud)/sensors/queries/installers/ccid/v1")
        if echo "$cs_target_cid" | grep -q "403"; then
            die "Failed to retrieve CID. Ensure the correct API Scopes are assigned: $(display_api_scopes "${SENSOR_TYPE}")"
        fi
        echo "$cs_target_cid" | tr -d '\n" ' | awk -F'[][]' '{print $2}'
    fi
)

cs_falcon_cid=$(echo "$cs_falcon_cid_with_checksum" | cut -d'-' -f1 | tr '[:upper:]' '[:lower:]')

if [ "$GETCID" ]; then
    if [ "${SENSOR_TYPE}" = "kpagent" ]; then
        echo "${cs_falcon_cid}"
    else
        echo "${cs_falcon_cid_with_checksum}"
    fi
    exit 0
fi

if [ -z "$BUILD_STAGE" ]; then
    BUILD_STAGE="release"
fi
# Check if BUILD_STAGE is set to a valid value
case "${BUILD_STAGE}" in
    release | stage) ;;
    *) die """
    Unrecognized sensor build stage: ${BUILD_STAGE}
    Valid values are [release|stage]""" ;;
esac

if [ ! "$LISTTAGS" ] && [ ! "$PULLTOKEN" ] && [ ! "$GETIMAGEPATH" ]; then
    echo "Using the following settings:"
    echo "Falcon Region:   $(cs_cloud)"
    echo "Falcon Registry: ${cs_registry}"
fi

ART_USERNAME="fc-$cs_falcon_cid"
IMAGE_NAME="falcon-sensor"
repository_name="$BUILD_STAGE/falcon-sensor"
registry_type="container-security"

if [ "${SENSOR_TYPE}" = "falcon-kac" ]; then
    # overrides for KAC
    IMAGE_NAME="falcon-kac"
    repository_name="$BUILD_STAGE/falcon-kac"
elif [ "${SENSOR_TYPE}" = "falcon-snapshot" ]; then
    # overrides for Snapshot
    ART_USERNAME="fs-$cs_falcon_cid"
    IMAGE_NAME="cs-snapshotscanner"
    repository_name="$BUILD_STAGE/cs-snapshotscanner"
    registry_type="snapshots"
elif [ "${SENSOR_TYPE}" = "falcon-imageanalyzer" ]; then
    # overrides for Image Analyzer
    IMAGE_NAME="falcon-imageanalyzer"
    repository_name="$BUILD_STAGE/falcon-imageanalyzer"
elif [ "${SENSOR_TYPE}" = "kpagent" ]; then
    # overrides for KPA
    ART_USERNAME="kp-$cs_falcon_cid"
    IMAGE_NAME="kpagent"
    repository_name="kpagent"
    registry_type="kubernetes-protection"
    registry_opts="kubernetes_protection"
fi

#Set Docker token using the BEARER token captured earlier
if [ "${SENSOR_TYPE}" = "kpagent" ]; then
    raw_docker_api_token=$(curl_command "$cs_falcon_oauth_token" "https://$(cs_cloud)/$registry_type/entities/integration/agent/v1?cluster_name=clustername&is_self_managed_cluster=true")
    docker_api_token=$(echo "$raw_docker_api_token" | awk '/dockerAPIToken:/ {print $2}')
else
    raw_docker_api_token=$(curl_command "$cs_falcon_oauth_token" "https://$(cs_cloud)/$registry_type/entities/image-registry-credentials/v1")
    docker_api_token=$(echo "$raw_docker_api_token" | json_value "token")
fi
ART_PASSWORD=$(echo "$docker_api_token" | sed 's/ *$//g' | sed 's/^ *//g')

if [ "$PULLTOKEN" ]; then
    # Determine if base64 supports the -w option
    BASE64_OPT=""
    if base64 --help 2>&1 | grep -q "\-w"; then
        BASE64_OPT="-w 0"
    fi
    # shellcheck disable=SC2086
    PARTIALPULLTOKEN=$(printf "%s:%s" "$ART_USERNAME" "$ART_PASSWORD" | base64 $BASE64_OPT)
    # Generate and display token
    # shellcheck disable=SC2086
    IMAGE_PULL_TOKEN=$(printf '{"auths": { "registry.crowdstrike.com": { "auth": "%s" } } }' "$PARTIALPULLTOKEN" | base64 $BASE64_OPT)
    echo "${IMAGE_PULL_TOKEN}"
    exit 0
fi

if [ -z "$ART_PASSWORD" ]; then
    die "Failed to retrieve the CrowdStrike registry password. Response from API:
$raw_docker_api_token

Ensure the following:
  - Credentials are valid.
  - Correct API Scopes assigned for sensor type: ${SENSOR_TYPE}
        - $(display_api_scopes "${SENSOR_TYPE}")
  - Cloud Security is enabled in your tenant."
fi

if [ "$CREDS" ]; then
    echo "CS Registry Username: ${ART_USERNAME}"
    echo "CS Registry Password: ${ART_PASSWORD}"
    # quitting no need to perform a registry login
    exit 0
fi

#Set container login
error_message=$(echo "$ART_PASSWORD" | "$CONTAINER_TOOL" login --username "$ART_USERNAME" "$cs_registry" --password-stdin 2>&1 >/dev/null) || ERROR=true
if [ "${ERROR}" = "true" ]; then
    # Check to see if unknown flag error is thrown
    if echo "$error_message" | grep -q "unknown flag: --password-stdin" && echo "${CONTAINER_TOOL}" | grep -q "docker"; then
        echo "ERROR: ${CONTAINER_TOOL} login failed. Error message: ${error_message}"
        die "Please upgrade your Docker version to 17.07 or higher"
    fi
    die "ERROR: ${CONTAINER_TOOL} login failed. Error message: ${error_message}"
fi

#Construct repository path
REPOSITORY="$cs_registry/$registry_opts/$repository_name"

if [ "$LISTTAGS" ]; then
    list_tags
    exit 0
fi

#Get latest sensor version
LATESTSENSOR=$(list_tags | awk -v RS=" " '{print}' | grep "$SENSOR_VERSION" | grep -o "[0-9a-zA-Z_\.\-]*" | tail -1)

#Construct full image path
FULLIMAGEPATH="${REPOSITORY}:${LATESTSENSOR}"

if [ "$GETIMAGEPATH" ]; then
    echo "${FULLIMAGEPATH}"
    exit 0
fi

# Construct destination path
COPYPATH="$COPY/$IMAGE_NAME:$LATESTSENSOR"

# Handle multi-arch images first
if [ "$(is_multi_arch "$FULLIMAGEPATH")" = "true" ]; then
    # If a platform has been specified, pull the specific platform for the container tool
    if [ -n "$SENSOR_PLATFORM" ]; then
        # If Skopeo is being used, the platform must be overridden
        if grep -qw "skopeo" "$CONTAINER_TOOL"; then
            "$CONTAINER_TOOL" copy --override-arch "$(platform_override)" "docker://$FULLIMAGEPATH" "docker://$COPYPATH"
        else
            # Podman/Docker can pull the specific platform
            pf_override="linux/$(platform_override)"
            pull_image "$FULLIMAGEPATH" "$pf_override"
            # Copy the image to the desired registry
            if [ -n "$COPY" ]; then
                # At this point, treat the image as a single arch image
                copy_image "$FULLIMAGEPATH" "$COPYPATH" "false"
            fi
        fi
    else
        if [ -n "$COPY" ]; then
            # Copy the multi-arch image to the desired registry
            copy_image "$FULLIMAGEPATH" "$COPYPATH" "true"
        else
            # Pulling the multi-arch image locally is not supported. Either specify a platform or
            # copy the image to a registry.
            die "Pulling multi-arch images locally is not supported.

You can either:
    - Pull a specific platform from the multi-arch image using the -p, --platform flag
    - Copy the multi-arch image to a registry using the -c, --copy flag
            "
        fi
    fi
else
    # Handle non-multi-arch images
    if grep -qw "skopeo" "$CONTAINER_TOOL"; then
        "$CONTAINER_TOOL" copy "docker://$FULLIMAGEPATH" "docker://$COPYPATH"
    else
        pull_image "$FULLIMAGEPATH"

        if [ -n "$COPY" ]; then
            copy_image "$FULLIMAGEPATH" "$COPYPATH" "false"
        fi
    fi
fi
