#!/bin/bash

print_usage() {
    cat <<EOF
Uninstalls the CrowdStrike Falcon Sensor from Linux operating systems.

The script recognizes the following environmental variables:

    - FALCON_CLIENT_ID                  (default: unset)
        Your CrowdStrike Falcon API client ID. Required if FALCON_REMOVE_HOST is 'true'.

    - FALCON_CLIENT_SECRET              (default: unset)
        Your CrowdStrike Falcon API client secret. Required if FALCON_REMOVE_HOST is 'true'.

    - FALCON_REMOVE_HOST                (default: unset)
        Determines whether the host should be removed from the Falcon console after uninstalling the sensor.
        Accepted values are ['true', 'false'].

    - FALCON_APH                        (default: unset)
        The proxy host for the sensor to use when communicating with CrowdStrike.

    - FALCON_APP                        (default: unset)
        The proxy port for the sensor to use when communicating with CrowdStrike.
EOF
}

main() {
    if [ -n "$1" ]; then
        print_usage
        exit 1
    fi
    cs_sensor_installed
    echo -n 'Removing Falcon Sensor  ... '
    cs_sensor_remove
    echo '[ Ok ]'
    if [ "${FALCON_REMOVE_HOST}" = "true" ]; then
        echo -n 'Removing host from console ... '
        cs_remove_host_from_console
        echo '[ Ok ] '
    fi
    echo 'Falcon Sensor removed successfully.'
}

cs_sensor_remove() {
    remove_package() {
        pkg="$1"

        if type dnf >/dev/null 2>&1; then
            dnf remove -q -y "$pkg" || rpm -e --nodeps "$pkg"
        elif type yum >/dev/null 2>&1; then
            yum remove -q -y "$pkg" || rpm -e --nodeps "$pkg"
        elif type zypper >/dev/null 2>&1; then
            zypper --quiet remove -y "$pkg" || rpm -e --nodeps "$pkg"
        elif type apt >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt purge -y "$pkg" >/dev/null
        else
            rpm -e --nodeps "$pkg"
        fi
    }

    remove_package "falcon-sensor"
}

cs_remove_host_from_console() {
    if [ -z "$aid" ]; then
        echo 'Unable to find AID. Skipping host removal from console.'
    else
        payload="{\"ids\": [\"$aid\"]}"
        url="https://$(cs_cloud)/devices/entities/devices-actions/v2?action_name=hide_host"

        curl_command -X "POST" -H "Content-Type: application/json" -d "$payload" "$url" >/dev/null

        handle_curl_error $?
    fi
}

cs_cloud() {
    case "${cs_falcon_cloud}" in
        us-1) echo "api.crowdstrike.com" ;;
        us-2) echo "api.us-2.crowdstrike.com" ;;
        eu-1) echo "api.eu-1.crowdstrike.com" ;;
        us-gov-1) echo "api.laggar.gcw.crowdstrike.com" ;;
        *) die "Unrecognized Falcon Cloud: ${cs_falcon_cloud}" ;;
    esac
}

cs_sensor_installed() {
    if ! test -f /opt/CrowdStrike/falconctl; then
        echo "Falcon sensor is not installed."
        exit 1
    fi
}

old_curl=$(
    if ! command -v curl >/dev/null 2>&1; then
        die "The 'curl' command is missing. Please install it before continuing. Aborting..."
    fi

    version=$(curl --version | head -n 1 | awk '{ print $2 }')
    minimum="7.55"

    # Check if the version is less than the minimum
    if printf "%s\n" "$version" "$minimum" | sort -V -C; then
        echo 0
    else
        echo 1
    fi
)

curl_command() {
    # Dash does not support arrays, so we have to pass the args as separate arguments
    set -- "$@"

    if [ "$old_curl" -eq 0 ]; then
        curl -s -x "$proxy" -L -H "Authorization: Bearer ${cs_falcon_oauth_token}" "$@"
    else
        echo "Authorization: Bearer ${cs_falcon_oauth_token}" | curl -s -x "$proxy" -L -H @- "$@"
    fi
}

handle_curl_error() {
    if [ "$1" = "28" ]; then
        err_msg="Operation timed out (exit code 28)."
        if [ -n "$proxy" ]; then
            err_msg="$err_msg A proxy was used to communicate ($proxy). Please check your proxy settings."
        fi
        die "$err_msg"
    fi

    if [ "$1" = "5" ]; then
        err_msg="Couldn't resolve proxy (exit code 5). The address ($proxy) of the given proxy host could not be resolved. Please check your proxy settings."
        die "$err_msg"
    fi

    if [ "$1" = "7" ]; then
        err_msg="Failed to connect to host (exit code 7). Host found, but unable to open connection with host."
        if [ -n "$proxy" ]; then
            err_msg="$err_msg A proxy was used to communicate ($proxy). Please check your proxy settings."
        fi
        die "$err_msg"
    fi
}

json_value() {
    KEY=$1
    num=$2
    awk -F"[,:}]" '{for(i=1;i<=NF;i++){if($i~/'"$KEY"'\042/){print $(i+1)}}}' | tr -d '"' | sed -n "${num}p"
}

die() {
    echo "Fatal error: $*" >&2
    exit 1
}

cs_falcon_cloud=$(
    if [ -n "$FALCON_CLOUD" ]; then
        echo "$FALCON_CLOUD"
    else
        # Auto-discovery is using us-1 initially
        echo "us-1"
    fi
)

response_headers=$(mktemp)

# shellcheck disable=SC2001
proxy=$(
    proxy=""
    if [ -n "$FALCON_APH" ]; then
        proxy="$(echo "$FALCON_APH" | sed "s|http.*://||")"

        if [ -n "$FALCON_APP" ]; then
            proxy="$proxy:$FALCON_APP"
        fi
    fi

    if [ -n "$proxy" ]; then
        # Remove redundant quotes
        proxy="$(echo "$proxy" | sed "s/[\'\"]//g")"
        proxy="http://$proxy"
    fi
    echo "$proxy"
)

if [ "${FALCON_REMOVE_HOST}" = "true" ]; then

    cs_falcon_client_id=$(
        if [ -n "$FALCON_CLIENT_ID" ]; then
            echo "$FALCON_CLIENT_ID"
        elif [ -n "$aws_instance" ]; then
            aws_ssm_parameter "FALCON_CLIENT_ID" | json_value Value 1
        else
            die "Missing FALCON_CLIENT_ID environment variable. Please provide your OAuth2 API Client ID for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys."
        fi
    )

    cs_falcon_client_secret=$(
        if [ -n "$FALCON_CLIENT_SECRET" ]; then
            echo "$FALCON_CLIENT_SECRET"
        elif [ -n "$aws_instance" ]; then
            aws_ssm_parameter "FALCON_CLIENT_SECRET" | json_value Value 1
        else
            die "Missing FALCON_CLIENT_SECRET environment variable. Please provide your OAuth2 API Client Secret for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys."
        fi
    )

    cs_falcon_oauth_token=$(
        token_result=$(echo "client_id=$cs_falcon_client_id&client_secret=$cs_falcon_client_secret" |
            curl -X POST -s -x "$proxy" -L "https://$(cs_cloud)/oauth2/token" \
                -H 'Content-Type: application/x-www-form-urlencoded; charset=utf-8' \
                -H 'User-Agent: crowdstrike-falcon-scripts/1.3.4' \
                --dump-header "${response_headers}" \
                --data @-)

        handle_curl_error $?

        token=$(echo "$token_result" | json_value "access_token" | sed 's/ *$//g' | sed 's/^ *//g')
        if [ -z "$token" ]; then
            die "Unable to obtain CrowdStrike Falcon OAuth Token. Response was $token_result"
        fi

        echo "$token"
    )

    region_hint=$(grep -i ^x-cs-region: "$response_headers" | head -n 1 | tr '[:upper:]' '[:lower:]' | tr -d '\r' | sed 's/^x-cs-region: //g')
    rm "${response_headers}"

    if [ -z "${FALCON_CLOUD}" ]; then
        if [ -z "${region_hint}" ]; then
            die "Unable to obtain region hint from CrowdStrike Falcon OAuth API, Please provide FALCON_CLOUD environment variable as an override."
        fi
        cs_falcon_cloud="${region_hint}"
    else
        if [ -n "$FALCON_ACCESS_TOKEN" ]; then
            :
        elif [ "x${FALCON_CLOUD}" != "x${region_hint}" ]; then
            echo "WARNING: FALCON_CLOUD='${FALCON_CLOUD}' environment variable specified while credentials only exists in '${region_hint}'" >&2
        fi
    fi

    aid="$(/opt/CrowdStrike/falconctl -g --aid | awk -F '"' '{print $2}')"

fi

main "$@"
