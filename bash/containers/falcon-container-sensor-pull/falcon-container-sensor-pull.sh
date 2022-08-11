#!/bin/bash
: <<'#DESCRIPTION#'
File: falcon-container-sensor-pull.sh
Description: Bash script to pull Falcon DaemonSet & Container Sensor images from CrowdStrike Container Registry.
#DESCRIPTION#

usage() 
{
    echo "usage: 
$0 \\
    -f | --cid <FALCONCID> \\
    -u | --clientid <FALCONCLIENTID> \\
    -s | --clientsecret <FALCONCLIENTSECRET> \\
    -r | --region <FALCONREGION> \\
    -n | --node (OPTIONAL FLAG) tells script to download node sensor instead of container sensor \\
    -g | --gov (OPTIONAL FLAG) tells the script to use Gov Cloud endpoints
    -h | --help display this help message"
    exit 2
}

while (( "$#" )); do
case "$1" in
    -u|--clientid)
    if [[ -n ${2:-} ]] ; then
        CS_CLIENT_ID="$2"
        shift
    fi
    ;;
    -s|--clientsecret)
    if [[ -n ${2:-} ]]; then
        CS_CLIENT_SECRET="$2"
        shift
    fi
    ;;
    -r|--region)
    if [[ -n ${2:-} ]]; then
        CS_REGION="$2"
        shift
    fi
    ;;
    -f|--cid)
    if [[ -n ${2:-} ]]; then
        CID="$2"
        shift
    fi
    ;;
    -n|--node)
    if [[ -n ${1} ]]; then
        NODE=true
    fi
    ;;
    -g|--gov)
    if [[ -n ${1} ]]; then
        GOV=true
    fi
    ;;
    -h|--help)
    if [[ -n ${1} ]]; then
        usage
    fi
    ;;
    --) # end argument parsing
    shift
    break
    ;;
    -*) # unsupported flags
    >&2 echo "ERROR: Unsupported flag: '$1'"
    usage
    exit 1
    ;;
esac
shift
done

#Check all mandatory variables set
VARIABLES=(CID CS_CLIENT_ID CS_CLIENT_SECRET)
{
    for VAR_NAME in "${VARIABLES[@]}"; do
        [ -z "${!VAR_NAME}" ] && echo "$VAR_NAME is unset refer to help to set" && VAR_UNSET=true
    done
        [ -n "$VAR_UNSET" ] && usage
}

#Check if GOVCLOUD flag setup regions
if [[ $GOV = true ]]; then
    echo "GovCloud flag set, using govcloud endpoints"
    REGION="govcloud"
    API="api.laggar.gcw"
    REGISTRY="registry.laggar.gcw"
    echo "Using Falcon API endpoint of ${API}.crowdstrike.com and Registry endpoint of ${REGISTRY}.crowdstrike.com"
elif [[ -z "${CS_REGION}" ]] || [[ "${CS_REGION}" = "US-1" ]] || [[ "${CS_REGION}" = "us-1" ]]; then
    REGION="us-1"
    API="api"
    REGISTRY="registry"
    echo "Using Falcon API endpoint of ${API}.crowdstrike.com and Registry endpoint of ${REGISTRY}.crowdstrike.com"
else
    REGION=$(echo "${CS_REGION}" | tr '[:upper:]' '[:lower:]') #Convert to lowercase if user entered as UPPERCASE
    API="api.${REGION}"
    REGISTRY="registry"
    echo "Using Falcon API endpoint of ${API}.crowdstrike.com and Registry endpoint of ${REGISTRY}.crowdstrike.com"
fi

#Convert CID to lowercase and remove checksum if present
CIDLOWER=$(echo "${CID}" | cut -d'-' -f1 | tr '[:upper:]' '[:lower:]')

#Get Bearer token to use with registry credentials api endpoint
BEARER=$(curl \
--data "client_id=${CS_CLIENT_ID}&client_secret=${CS_CLIENT_SECRET}" \
--request POST \
--silent \
https://"${API}".crowdstrike.com/oauth2/token | jq -r '.access_token')

#Set Docker token using the BEARER token captured earlier
ART_PASSWORD=$(curl -s -X GET -H "authorization: Bearer ${BEARER}" \
https://"${API}".crowdstrike.com/container-security/entities/image-registry-credentials/v1 | \
jq -r '.resources[].token')

#Set docker login
docker login --username  "fc-${CIDLOWER}" --password "${ART_PASSWORD}" $REGISTRY.crowdstrike.com

#Check if user wants to download DaemonSet Node Sensor
if [[ $NODE = true ]]; then
    SENSORTYPE="falcon-sensor"
else
    SENSORTYPE="falcon-container"
fi

#Get BEARER token for Registry
REGISTRYBEARER=$(curl -X GET -s -u "fc-${CIDLOWER}:${ART_PASSWORD}" "https://$REGISTRY.crowdstrike.com/v2/token?=fc-${CIDLOWER}&scope=repository:$SENSORTYPE/$REGION/release/falcon-sensor:pull&service=registry.crowdstrike.com" | jq -r '.token')
#Get latest sensor version
LATESTSENSOR=$(curl -X GET -s -H "authorization: Bearer ${REGISTRYBEARER}" "https://$REGISTRY.crowdstrike.com/v2/$SENSORTYPE/$REGION/release/falcon-sensor/tags/list" | jq -r '.tags[-1]') 
#Construct full image path
FULLIMAGEPATH="$REGISTRY.crowdstrike.com/$SENSORTYPE/${REGION}/release/falcon-sensor:${LATESTSENSOR}"
#Pull the container image locally
docker pull "${FULLIMAGEPATH}"
