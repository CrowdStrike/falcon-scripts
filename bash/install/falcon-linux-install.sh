#!/bin/bash

print_usage() {
    cat <<EOF

Usage: $0 [-h|--help]

Installs and configures the CrowdStrike Falcon Sensor for Linux.
Version: $VERSION

This script recognizes the following environmental variables:

Authentication:
    - FALCON_CLIENT_ID                  (default: unset)
        Your CrowdStrike Falcon API client ID.

    - FALCON_CLIENT_SECRET              (default: unset)
        Your CrowdStrike Falcon API client secret.

    - FALCON_ACCESS_TOKEN               (default: unset)
        Your CrowdStrike Falcon API access token.
        If used, FALCON_CLOUD must also be set.

    - FALCON_CLOUD                      (default: unset)
        The cloud region where your CrowdStrike Falcon instance is hosted.
        Required if using FALCON_ACCESS_TOKEN.
        Accepted values are ['us-1', 'us-2', 'eu-1', 'us-gov-1'].

Other Options
    - FALCON_CID                        (default: auto)
        The customer ID that should be associated with the sensor.
        By default, the CID is automatically determined by your authentication credentials.

    - FALCON_SENSOR_VERSION_DECREMENT   (default: 0 [latest])
        The number of versions prior to the latest release to install.

    - FALCON_PROVISIONING_TOKEN         (default: unset)
        The provisioning token to use for installing the sensor.
        If the provisioning token is unset, the script will attempt to retrieve it from
        the API using your authentication credentials and token requirements.

    - FALCON_SENSOR_UPDATE_POLICY_NAME  (default: unset)
        The name of the sensor update policy to use for installing the sensor.

    - FALCON_TAGS                       (default: unset)
        A comma seperated list of tags for sensor grouping.

    - FALCON_APD                        (default: unset)
        Configures if the proxy should be enabled or disabled.

    - FALCON_APH                        (default: unset)
        The proxy host for the sensor to use when communicating with CrowdStrike.

    - FALCON_APP                        (default: unset)
        The proxy port for the sensor to use when communicating with CrowdStrike.

    - FALCON_BILLING                    (default: default)
        To configure the sensor billing type.
        Accepted values are [default|metered].

    - FALCON_BACKEND                    (default: auto)
        For sensor backend.
        Accepted values are values: [auto|bpf|kernel].

    - FALCON_TRACE                      (default: none)
        To configure the trace level.
        Accepted values are [none|err|warn|info|debug]

    - FALCON_UNINSTALL                  (default: false)
        To uninstall the falcon sensor.
        **LEGACY** Please use the falcon-linux-uninstall.sh script instead.

    - FALCON_INSTALL_ONLY               (default: false)
        To install the falcon sensor without registering it with CrowdStrike.

    - FALCON_DOWNLOAD_ONLY              (default: false)
        To download the falcon sensor without installing it.

    - FALCON_DOWNLOAD_PATH              (default: \$PWD)
        The path to download the falcon sensor to.

    - ALLOW_LEGACY_CURL                 (default: false)
        To use the legacy version of curl; version < 7.55.0.

    - GET_ACCESS_TOKEN                  (default: false)
        Prints an access token and exits.
        Requires FALCON_CLIENT_ID and FALCON_CLIENT_SECRET.
        Accepted values are ['true', 'false'].

    - PREP_GOLDEN_IMAGE                 (default: false)
        To prepare the sensor to be used in a golden image.
        Accepted values are ['true', 'false'].

This script recognizes the following argument:
    -h, --help
        Print this help message and exit.

EOF
}

VERSION="1.7.3"

# If -h or --help is passed, print the usage and exit
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    print_usage
    exit 0
fi

main() {
    if [ "$GET_ACCESS_TOKEN" = "true" ]; then
        get_oauth_token
        echo "$cs_falcon_oauth_token"
        exit 0
    fi

    if [ "${FALCON_DOWNLOAD_ONLY}" = "true" ]; then
        echo -n 'Downloading Falcon Sensor ... '
        local download_destination
        download_destination=$(cs_sensor_download_only)
        echo '[ Ok ]'
        echo "Falcon Sensor downloaded to: $download_destination"
        exit 0
    fi
    echo -n 'Check if Falcon Sensor is running ... '
    cs_sensor_is_running
    echo '[ Not present ]'
    echo -n 'Falcon Sensor Install  ... '
    cs_sensor_install
    echo '[ Ok ]'
    if [ -z "$FALCON_INSTALL_ONLY" ] || [ "${FALCON_INSTALL_ONLY}" = "false" ]; then
        echo -n 'Falcon Sensor Register ... '
        cs_sensor_register
        echo '[ Ok ]'
        echo -n 'Falcon Sensor Restart  ... '
        cs_sensor_restart
        echo '[ Ok ]'
    fi
    if [ "${PREP_GOLDEN_IMAGE}" = "true" ]; then
        echo -n 'Prepping Golden Image  ... '
        cs_golden_image_prep
        echo '[ Ok ]'
        echo 'Falcon Sensor is ready for golden image creation.'
    else
        echo 'Falcon Sensor installed successfully.'
    fi
}

cs_sensor_register() {
    # Get the falcon cid
    cs_falcon_cid="$(get_falcon_cid)"
    # If cs_falcon_token is not set, try getting it from api
    if [ -z "${cs_falcon_token}" ]; then
        cs_falcon_token="$(get_provisioning_token)"
    fi
    # add the cid to the params
    cs_falcon_args=--cid="${cs_falcon_cid}"
    if [ -n "${cs_falcon_token}" ]; then
        cs_token=--provisioning-token="${cs_falcon_token}"
        cs_falcon_args="$cs_falcon_args $cs_token"
    fi
    # add tags to the params
    if [ -n "${FALCON_TAGS}" ]; then
        cs_falconctl_opt_tags=--tags="$FALCON_TAGS"
        cs_falcon_args="$cs_falcon_args $cs_falconctl_opt_tags"
    fi
    # add proxy enable/disable param
    if [ -n "${cs_falcon_apd}" ]; then
        cs_falconctl_opt_apd=--apd=$cs_falcon_apd
        cs_falcon_args="$cs_falcon_args $cs_falconctl_opt_apd"
    fi
    # add proxy host to the params
    if [ -n "${FALCON_APH}" ]; then
        cs_falconctl_opt_aph=--aph="${FALCON_APH}"
        cs_falcon_args="$cs_falcon_args $cs_falconctl_opt_aph"
    fi
    # add proxy port to the params
    if [ -n "${FALCON_APP}" ]; then
        cs_falconctl_opt_app=--app="${FALCON_APP}"
        cs_falcon_args="$cs_falcon_args $cs_falconctl_opt_app"
    fi
    # add the billing type to the params
    if [ -n "${FALCON_BILLING}" ]; then
        cs_falconctl_opt_billing=--billing="${cs_falcon_billing}"
        cs_falcon_args="$cs_falcon_args $cs_falconctl_opt_billing"
    fi
    # add the backend to the params
    if [ -n "${cs_falcon_backend}" ]; then
        cs_falconctl_opt_backend=--backend="${cs_falcon_backend}"
        cs_falcon_args="$cs_falcon_args $cs_falconctl_opt_backend"
    fi
    # add the trace level to the params
    if [ -n "${cs_falcon_trace}" ]; then
        cs_falconctl_opt_trace=--trace="${cs_falcon_trace}"
        cs_falcon_args="$cs_falcon_args $cs_falconctl_opt_trace"
    fi
    # run the configuration command
    # shellcheck disable=SC2086
    /opt/CrowdStrike/falconctl -s -f ${cs_falcon_args} >/dev/null
}

cs_sensor_is_running() {
    if pgrep -u root falcon-sensor >/dev/null 2>&1; then
        echo "sensor is already running... exiting"
        exit 0
    fi
}

cs_sensor_restart() {
    if type systemctl >/dev/null 2>&1; then
        systemctl restart falcon-sensor
    elif type service >/dev/null 2>&1; then
        service falcon-sensor restart
    else
        die "Could not restart falcon sensor"
    fi
}

cs_golden_image_prep() {
    local wait_time=60
    local sleep_interval=5
    local aid

    get_aid() {
        /opt/CrowdStrike/falconctl -g --aid | awk -F '"' '{print $2}'
    }

    aid=$(get_aid)
    while [ -z "$aid" ]; do
        if [ "$wait_time" -le 0 ]; then
            echo '[ Failed ]'
            die "Failed to retrieve existing AID. Please check the sensor status."
        fi
        sleep "$sleep_interval"
        wait_time=$((wait_time - sleep_interval))
        aid=$(get_aid)
    done

    # Remove the aid
    /opt/CrowdStrike/falconctl -d -f --aid >/dev/null

    # Check if a provisioning token was used, if so add it back
    if [ -n "$cs_falcon_token" ]; then
        /opt/CrowdStrike/falconctl -s -f --provisioning-token="$cs_falcon_token" >/dev/null
    fi
}

cs_sensor_install() {
    local tempdir package_name
    tempdir=$(mktemp -d)

    tempdir_cleanup() { rm -rf "$tempdir"; }
    trap tempdir_cleanup EXIT

    get_oauth_token
    package_name=$(cs_sensor_download "$tempdir")
    os_install_package "$package_name"

    tempdir_cleanup
}

cs_sensor_download_only() {
    local destination_dir

    destination_dir="${FALCON_DOWNLOAD_PATH:-$PWD}"
    get_oauth_token
    cs_sensor_download "$destination_dir"
}

cs_sensor_remove() {
    remove_package() {
        local pkg="$1"

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

cs_sensor_policy_version() {
    local cs_policy_name="$1" sensor_update_policy sensor_update_versions

    sensor_update_policy=$(
        curl_command -G "https://$(cs_cloud)/policy/combined/sensor-update/v2" \
            --data-urlencode "filter=platform_name:\"Linux\"+name.raw:\"$cs_policy_name\""
    )

    handle_curl_error $?

    if echo "$sensor_update_policy" | grep "authorization failed"; then
        die "Access denied: Please make sure that your Falcon API credentials allow access to sensor update policies (scope Sensor update policies [read])"
    elif echo "$sensor_update_policy" | grep "invalid bearer token"; then
        die "Invalid Access Token: $cs_falcon_oauth_token"
    fi

    sensor_update_versions=$(echo "$sensor_update_policy" | json_value "sensor_version")
    if [ -z "$sensor_update_versions" ]; then
        die "Could not find a sensor update policy with name: $cs_policy_name"
    fi

    oldIFS=$IFS
    IFS=" "
    # shellcheck disable=SC2086
    set -- $sensor_update_versions
    if [ "$(echo "$sensor_update_versions" | wc -w)" -gt 1 ]; then
        if [ "$cs_os_arch" = "aarch64" ]; then
            echo "$2"
        else
            echo "$1"
        fi
    else
        echo "$1"
    fi
    IFS=$oldIFS
}

cs_sensor_download() {
    local destination_dir="$1" existing_installers sha_list INDEX sha file_type installer

    if [ -n "$cs_sensor_policy_name" ]; then
        cs_sensor_version=$(cs_sensor_policy_version "$cs_sensor_policy_name")
        cs_api_version_filter="+version:\"$cs_sensor_version\""

        if [ "$cs_falcon_sensor_version_dec" -gt 0 ]; then
            echo "WARNING: Disabling FALCON_SENSOR_VERSION_DECREMENT because it conflicts with FALCON_SENSOR_UPDATE_POLICY_NAME"
            cs_falcon_sensor_version_dec=0
        fi
    fi

    existing_installers=$(
        curl_command -G "https://$(cs_cloud)/sensors/combined/installers/v2?sort=version|desc" \
            --data-urlencode "filter=os:\"$cs_os_name\"+os_version:\"*$cs_os_version*\"$cs_api_version_filter$cs_os_arch_filter"
    )

    handle_curl_error $?

    if echo "$existing_installers" | grep "authorization failed"; then
        die "Access denied: Please make sure that your Falcon API credentials allow sensor download (scope Sensor Download [read])"
    elif echo "$existing_installers" | grep "invalid bearer token"; then
        die "Invalid Access Token: $cs_falcon_oauth_token"
    fi

    sha_list=$(echo "$existing_installers" | json_value "sha256")
    if [ -z "$sha_list" ]; then
        die "No sensor found for OS: $cs_os_name, Version: $cs_os_version. Either the OS or the OS version is not yet supported."
    fi

    # Set the index accordingly (the json_value expects and index+1 value)
    INDEX=$((cs_falcon_sensor_version_dec + 1))

    sha=$(echo "$existing_installers" | json_value "sha256" "$INDEX" |
        sed 's/ *$//g' | sed 's/^ *//g')
    if [ -z "$sha" ]; then
        die "Unable to identify a sensor installer matching: $cs_os_name, version: $cs_os_version, index: N-$cs_falcon_sensor_version_dec"
    fi
    file_type=$(echo "$existing_installers" | json_value "file_type" "$INDEX" | sed 's/ *$//g' | sed 's/^ *//g')

    installer="${destination_dir}/falcon-sensor.${file_type}"

    curl_command "https://$(cs_cloud)/sensors/entities/download-installer/v1?id=$sha" -o "${installer}"

    handle_curl_error $?

    echo "$installer"
}

os_install_package() {
    local pkg="$1"

    rpm_install_package() {
        local pkg="$1"

        cs_falcon_gpg_import

        if type dnf >/dev/null 2>&1; then
            dnf install -q -y "$pkg" || rpm -ivh --nodeps "$pkg"
        elif type yum >/dev/null 2>&1; then
            yum install -q -y "$pkg" || rpm -ivh --nodeps "$pkg"
        elif type zypper >/dev/null 2>&1; then
            zypper --quiet install -y "$pkg" || rpm -ivh --nodeps "$pkg"
        else
            rpm -ivh --nodeps "$pkg"
        fi
    }
    # shellcheck disable=SC2221,SC2222
    case "${os_name}" in
        Amazon | CentOS | Oracle | RHEL | Rocky | AlmaLinux | SLES)
            rpm_install_package "$pkg"
            ;;
        Debian)
            DEBIAN_FRONTEND=noninteractive apt-get -qq install -y "$pkg" >/dev/null
            ;;
        Ubuntu)
            # If this is ubuntu 14, we need to use dpkg instead
            if [ "${cs_os_version}" -eq 14 ]; then
                DEBIAN_FRONTEND=noninteractive dpkg -i "$pkg" >/dev/null 2>&1 || true
                DEBIAN_FRONTEND=noninteractive apt-get -qq install -f -y >/dev/null
            else
                DEBIAN_FRONTEND=noninteractive apt-get -qq install -y "$pkg" >/dev/null
            fi
            ;;
        *)
            die "Unrecognized OS: ${os_name}"
            ;;
    esac
}

aws_ssm_parameter() {
    local param_name="$1"

    hmac_sha256() {
        key="$1"
        data="$2"
        echo -n "$data" | openssl dgst -sha256 -mac HMAC -macopt "$key" | sed 's/^.* //'
    }

    token=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
    api_endpoint="AmazonSSM.GetParameters"
    iam_role="$(curl -s -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/iam/security-credentials/)"
    aws_my_region="$(curl -s -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/placement/availability-zone | sed s/.$//)"
    _security_credentials="$(curl -s -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/iam/security-credentials/"$iam_role")"
    access_key_id="$(echo "$_security_credentials" | grep AccessKeyId | sed -e 's/  "AccessKeyId" : "//' -e 's/",$//')"
    access_key_secret="$(echo "$_security_credentials" | grep SecretAccessKey | sed -e 's/  "SecretAccessKey" : "//' -e 's/",$//')"
    security_token="$(echo "$_security_credentials" | grep Token | sed -e 's/  "Token" : "//' -e 's/",$//')"
    datetime=$(date -u +"%Y%m%dT%H%M%SZ")
    date=$(date -u +"%Y%m%d")
    request_data='{"Names":["'"${param_name}"'"],"WithDecryption":"true"}'
    request_data_dgst=$(echo -n "$request_data" | openssl dgst -sha256 | awk -F' ' '{print $2}')
    request_dgst=$(
        cat <<EOF | head -c -1 | openssl dgst -sha256 | awk -F' ' '{print $2}'
POST
/

content-type:application/x-amz-json-1.1
host:ssm.$aws_my_region.amazonaws.com
x-amz-date:$datetime
x-amz-security-token:$security_token
x-amz-target:$api_endpoint

content-type;host;x-amz-date;x-amz-security-token;x-amz-target
$request_data_dgst
EOF
    )
    dateKey=$(hmac_sha256 key:"AWS4$access_key_secret" "$date")
    dateRegionKey=$(hmac_sha256 "hexkey:$dateKey" "$aws_my_region")
    dateRegionServiceKey=$(hmac_sha256 "hexkey:$dateRegionKey" ssm)
    hex_key=$(hmac_sha256 "hexkey:$dateRegionServiceKey" "aws4_request")

    signature=$(
        cat <<EOF | head -c -1 | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$hex_key" | awk -F' ' '{print $2}'
AWS4-HMAC-SHA256
$datetime
$date/$aws_my_region/ssm/aws4_request
$request_dgst
EOF
    )

    response=$(
        curl -s "https://ssm.$aws_my_region.amazonaws.com/" \
            -x "$proxy" \
            -H "Authorization: AWS4-HMAC-SHA256 \
            Credential=$access_key_id/$date/$aws_my_region/ssm/aws4_request, \
            SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, \
            Signature=$signature" \
            -H "x-amz-security-token: $security_token" \
            -H "x-amz-target: $api_endpoint" \
            -H "content-type: application/x-amz-json-1.1" \
            -d "$request_data" \
            -H "x-amz-date: $datetime"
    )
    handle_curl_error $?
    if ! echo "$response" | grep -q '^.*"InvalidParameters":\[\].*$'; then
        die "Unexpected response from AWS SSM Parameter Store: $response"
    elif ! echo "$response" | grep -q '^.*'"${param_name}"'.*$'; then
        die "Unexpected response from AWS SSM Parameter Store: $response"
    fi
    echo "$response"
}

cs_falcon_gpg_import() {
    tempfile=$(mktemp)
    cat >"$tempfile" <<EOF
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
0k88iw==
=X91W
-----END PGP PUBLIC KEY BLOCK-----
EOF
    rpm --import "$tempfile"
    rm "$tempfile"
}

set -e

json_value() {
    KEY=$1
    num=$2
    awk -F"[,:}]" '{for(i=1;i<=NF;i++){if($i~/'"$KEY"'\042/){print $(i+1)}}}' | tr -d '"' | sed -n "${num}p"
}

die() {
    echo "Fatal error: $*" >&2
    exit 1
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

# Check if curl is greater or equal to 7.55
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

# Old curl print warning message
if [ "$old_curl" -eq 0 ]; then
    if [ "${ALLOW_LEGACY_CURL}" != "true" ]; then
        echo """
WARNING: Your version of curl does not support the ability to pass headers via stdin.
For security considerations, we strongly recommend upgrading to curl 7.55.0 or newer.

To bypass this warning, set the environment variable ALLOW_LEGACY_CURL=true
"""
        exit 1
    fi
fi

# Handle error codes returned by curl
handle_curl_error() {
    local err_msg

    # Failed to download the file to destination
    if [ "$1" -eq 23 ]; then
        err_msg="Failed writing received data to disk/destination (exit code 23). Please check the destination path and permissions."
        die "$err_msg"
    fi

    # Proxy related errors
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

curl_command() {
    # Dash does not support arrays, so we have to pass the args as separate arguments
    set -- "$@"

    if [ "$old_curl" -eq 0 ]; then
        curl -s -x "$proxy" -L -H "Authorization: Bearer ${cs_falcon_oauth_token}" "$@"
    else
        echo "Authorization: Bearer ${cs_falcon_oauth_token}" | curl -s -x "$proxy" -L -H @- "$@"
    fi
}

check_aws_instance() {
    local aws_instance

    # Check if running on EC2 hypervisor
    if [ -f /sys/hypervisor/uuid ] && grep -qi ec2 /sys/hypervisor/uuid; then
        aws_instance=true
    # Check if DMI board asset tag matches EC2 instance pattern
    elif [ -f /sys/devices/virtual/dmi/id/board_asset_tag ] && grep -q '^i-[a-z0-9]*$' /sys/devices/virtual/dmi/id/board_asset_tag; then
        aws_instance=true
    # Check if EC2 instance identity document is accessible
    else
        curl_output="$(curl -s --connect-timeout 5 http://169.254.169.254/latest/dynamic/instance-identity/)"
        if [ -n "$curl_output" ] && ! echo "$curl_output" | grep --silent -i 'not.*found'; then
            aws_instance=true
        fi
    fi

    echo "$aws_instance"
}

get_falcon_credentials() {
    if [ -z "$FALCON_ACCESS_TOKEN" ]; then
        aws_instance=$(check_aws_instance)
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
    else
        if [ -z "$FALCON_CLOUD" ]; then
            die "If setting the FALCON_ACCESS_TOKEN manually, you must also specify the FALCON_CLOUD"
        fi
    fi
}

get_oauth_token() {
    # Get credentials first
    get_falcon_credentials

    cs_falcon_oauth_token=$(
        if [ -n "$FALCON_ACCESS_TOKEN" ]; then
            token=$FALCON_ACCESS_TOKEN
        else
            token_result=$(echo "client_id=$cs_falcon_client_id&client_secret=$cs_falcon_client_secret" |
                curl -X POST -s -x "$proxy" -L "https://$(cs_cloud)/oauth2/token" \
                    -H 'Content-Type: application/x-www-form-urlencoded; charset=utf-8' \
                    -H "User-Agent: crowdstrike-falcon-scripts/$VERSION" \
                    --dump-header "${response_headers}" \
                    --data @-)

            handle_curl_error $?

            token=$(echo "$token_result" | json_value "access_token" | sed 's/ *$//g' | sed 's/^ *//g')
            if [ -z "$token" ]; then
                die "Unable to obtain CrowdStrike Falcon OAuth Token. Double check your credentials and/or ensure you set the correct cloud region."
            fi
        fi
        echo "$token"
    )

    if [ -z "$FALCON_ACCESS_TOKEN" ]; then
        region_hint=$(grep -i ^x-cs-region: "$response_headers" | head -n 1 | tr '[:upper:]' '[:lower:]' | tr -d '\r' | sed 's/^x-cs-region: //g')

        if [ -z "${FALCON_CLOUD}" ]; then
            if [ -z "${region_hint}" ]; then
                die "Unable to obtain region hint from CrowdStrike Falcon OAuth API, Please provide FALCON_CLOUD environment variable as an override."
            fi
            cs_falcon_cloud="${region_hint}"
        else
            if [ "x${FALCON_CLOUD}" != "x${region_hint}" ]; then
                echo "WARNING: FALCON_CLOUD='${FALCON_CLOUD}' environment variable specified while credentials only exists in '${region_hint}'" >&2
            fi
        fi
    fi

    rm "${response_headers}"
}

get_provisioning_token() {
    local check_settings is_required token_value
    # First, let's check if installation tokens are required
    check_settings=$(curl_command "https://$(cs_cloud)/installation-tokens/entities/customer-settings/v1")
    handle_curl_error $?

    if echo "$check_settings" | grep "authorization failed" >/dev/null; then
        # For now we just return. We can error out once more people get a chance to update their API keys
        return
    fi

    is_required=$(echo "$check_settings" | json_value "tokens_required" | xargs)
    if [ "$is_required" = "true" ]; then
        local token_query token_id token_result
        # Get the token ID
        token_query=$(curl_command "https://$(cs_cloud)/installation-tokens/queries/tokens/v1")
        token_id=$(echo "$token_query" | tr -d '\n" ' | awk -F'[][]' '{print $2}' | cut -d',' -f1)
        if [ -z "$token_id" ]; then
            die "No installation token found in a required token environment."
        fi

        # Get the token value from ID
        token_result=$(curl_command "https://$(cs_cloud)/installation-tokens/entities/tokens/v1?ids=$token_id")
        token_value=$(echo "$token_result" | json_value "value" | xargs)
        if [ -z "$token_value" ]; then
            die "Could not obtain installation token value."
        fi
    fi

    echo "$token_value"
}

get_falcon_cid() {
    if [ -n "$FALCON_CID" ]; then
        echo "$FALCON_CID"
    else
        cs_target_cid=$(curl_command "https://$(cs_cloud)/sensors/queries/installers/ccid/v1")

        handle_curl_error $?

        if [ -z "$cs_target_cid" ]; then
            die "Unable to obtain CrowdStrike Falcon CID. Response was $cs_target_cid"
        fi
        echo "$cs_target_cid" | tr -d '\n" ' | awk -F'[][]' '{print $2}'
    fi
}

# shellcheck disable=SC2034
cs_uninstall=$(
    if [ "$FALCON_UNINSTALL" ]; then
        echo -n 'Removing Falcon Sensor  ... '
        cs_sensor_remove
        echo '[ Ok ]'
        echo 'Falcon Sensor removed successfully.'
        exit 2
    fi
)

os_name=$(
    # returns either: Amazon, Ubuntu, CentOS, RHEL, or SLES
    # lsb_release is not always present
    name=$(cat /etc/*release | grep ^NAME= | awk -F'=' '{ print $2 }' | sed "s/\"//g;s/Red Hat.*/RHEL/g;s/ Linux$//g;s/ GNU\/Linux$//g;s/Oracle.*/Oracle/g;s/Amazon.*/Amazon/g")
    if [ -z "$name" ]; then
        if lsb_release -s -i | grep -q ^RedHat; then
            name="RHEL"
        elif [ -f /usr/bin/lsb_release ]; then
            name=$(/usr/bin/lsb_release -s -i)
        fi
    fi
    if [ -z "$name" ]; then
        die "Cannot recognise operating system"
    fi

    echo "$name"
)

os_version=$(
    version=$(cat /etc/*release | grep VERSION_ID= | awk '{ print $1 }' | awk -F'=' '{ print $2 }' | sed "s/\"//g")
    if [ -z "$version" ]; then
        if type rpm >/dev/null 2>&1; then
            # older systems may have *release files of different form
            version=$(rpm -qf /etc/redhat-release --queryformat '%{VERSION}' | sed 's/\([[:digit:]]\+\).*/\1/g')
        elif [ -f /etc/debian_version ]; then
            version=$(cat /etc/debian_version)
        elif [ -f /usr/bin/lsb_release ]; then
            version=$(/usr/bin/lsb_release -r | /usr/bin/cut -f 2-)
        fi
    fi
    if [ -z "$version" ]; then
        cat /etc/*release >&2
        die "Could not determine distribution version"
    fi
    echo "$version"
)

cs_os_name=$(
    # returns OS name as recognised by CrowdStrike Falcon API
    # shellcheck disable=SC2221,SC2222
    case "${os_name}" in
        Amazon)
            echo "Amazon Linux"
            ;;
        CentOS | Oracle | RHEL | Rocky | AlmaLinux)
            echo "*RHEL*"
            ;;
        Debian)
            echo "Debian"
            ;;
        SLES)
            echo "SLES"
            ;;
        Ubuntu)
            echo "Ubuntu"
            ;;
        *)
            die "Unrecognized OS: ${os_name}"
            ;;
    esac
)

cs_os_arch=$(
    uname -m
)

cs_os_arch_filter=$(
    case "${cs_os_arch}" in
        x86_64)
            echo "+architectures:\"x86_64\""
            ;;
        aarch64)
            echo "+architectures:\"arm64\""
            ;;
        s390x)
            echo "+architectures:\"s390x\""
            ;;
        *)
            die "Unrecognized OS architecture: ${cs_os_arch}"
            ;;
    esac
)

cs_os_version=$(
    version=$(echo "$os_version" | awk -F'.' '{print $1}')
    # Check if we are using Amazon Linux 1
    if [ "${os_name}" = "Amazon" ]; then
        if [ "$version" != "2" ] && [ "$version" -le 2018 ]; then
            version="1"
        fi
    fi
    echo "$version"
)

cs_falcon_token=$(
    if [ -n "$FALCON_PROVISIONING_TOKEN" ]; then
        echo "$FALCON_PROVISIONING_TOKEN"
    fi
)

cs_falcon_cloud=$(
    if [ -n "$FALCON_CLOUD" ]; then
        echo "$FALCON_CLOUD"
    else
        # Auto-discovery is using us-1 initially
        echo "us-1"
    fi
)

cs_sensor_policy_name=$(
    if [ -n "$FALCON_SENSOR_UPDATE_POLICY_NAME" ]; then
        echo "$FALCON_SENSOR_UPDATE_POLICY_NAME"
    else
        echo ""
    fi
)

cs_falcon_sensor_version_dec=$(
    re='^[0-9]\+$'
    if [ -n "$FALCON_SENSOR_VERSION_DECREMENT" ]; then
        if ! expr "$FALCON_SENSOR_VERSION_DECREMENT" : "$re" >/dev/null 2>&1; then
            die "The FALCON_SENSOR_VERSION_DECREMENT must be an integer greater than or equal to 0 or less than 5. FALCON_SENSOR_VERSION_DECREMENT: \"$FALCON_SENSOR_VERSION_DECREMENT\""
        elif [ "$FALCON_SENSOR_VERSION_DECREMENT" -lt 0 ] || [ "$FALCON_SENSOR_VERSION_DECREMENT" -gt 5 ]; then
            die "The FALCON_SENSOR_VERSION_DECREMENT must be an integer greater than or equal to 0 or less than 5. FALCON_SENSOR_VERSION_DECREMENT: \"$FALCON_SENSOR_VERSION_DECREMENT\""
        else
            echo "$FALCON_SENSOR_VERSION_DECREMENT"
        fi
    else
        echo "0"
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

if [ -n "$FALCON_APD" ]; then
    cs_falcon_apd=$(
        case "${FALCON_APD}" in
            true)
                echo "true"
                ;;
            false)
                echo "false"
                ;;
            *)
                die "Unrecognized APD: ${FALCON_APD} value must be one of : [true|false]"
                ;;
        esac
    )
fi

if [ -n "$FALCON_BILLING" ]; then
    cs_falcon_billing=$(
        case "${FALCON_BILLING}" in
            default)
                echo "default"
                ;;
            metered)
                echo "metered"
                ;;
            *)
                die "Unrecognized BILLING: ${FALCON_BILLING} value must be one of : [default|metered]"
                ;;
        esac
    )
fi

if [ -n "$FALCON_BACKEND" ]; then
    cs_falcon_backend=$(
        case "${FALCON_BACKEND}" in
            auto)
                echo "auto"
                ;;
            bpf)
                echo "bpf"
                ;;
            kernel)
                echo "kernel"
                ;;
            *)
                die "Unrecognized BACKEND: ${FALCON_BACKEND} value must be one of : [auto|bpf|kernel]"
                ;;
        esac
    )
fi

if [ -n "$FALCON_TRACE" ]; then
    cs_falcon_trace=$(
        case "${FALCON_TRACE}" in
            none)
                echo "none"
                ;;
            err)
                echo "err"
                ;;
            warn)
                echo "warn"
                ;;
            info)
                echo "info"
                ;;
            debug)
                echo "debug"
                ;;
            *)
                die "Unrecognized TRACE: ${FALCON_TRACE} value must be one of : [none|err|warn|info|debug]"
                ;;
        esac
    )
fi

main "$@"
