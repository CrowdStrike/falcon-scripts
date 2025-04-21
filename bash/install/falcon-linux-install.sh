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
        For example, 1 would install version N-1.

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

    - USER_AGENT                        (default: unset)
        User agent string to append to the User-Agent header when making
        requests to the CrowdStrike API.

This script recognizes the following argument:
    -h, --help
        Print this help message and exit.

EOF
}

VERSION="1.7.4"

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

check_package_manager_lock() {
    lock_file="/var/lib/rpm/.rpm.lock"
    lock_type="RPM"
    local timeout=300 interval=5 elapsed=0

    if type dpkg >/dev/null 2>&1; then
        lock_file="/var/lib/dpkg/lock"
        lock_type="DPKG"
    fi

    while lsof -w "$lock_file" >/dev/null 2>&1; do
        if [ $elapsed -eq 0 ]; then
            echo ""
            echo "Package manager is locked. Waiting up to ${timeout} seconds for lock to be released..."
        fi

        if [ $elapsed -ge $timeout ]; then
            echo "Timed out waiting for ${lock_type} lock to be released after ${timeout} seconds."
            echo "You may need to manually investigate processes locking ${lock_file}:"
            lsof -w "$lock_file" || true
            die "Installation aborted due to package manager lock timeout."
        fi

        sleep $interval
        elapsed=$((elapsed + interval))
        echo "Retrying again in ${interval} seconds..."
    done
}

os_install_package() {
    local pkg="$1"
    # Check for package manager lock prior to uninstallation
    check_package_manager_lock

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
        Amazon | CentOS* | Oracle | RHEL | Rocky | AlmaLinux | SLES)
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
=ALB8
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

get_user_agent() {
    local user_agent="crowdstrike-falcon-scripts/$VERSION"
    if [ -n "$USER_AGENT" ]; then
        user_agent="${user_agent} ${USER_AGENT}"
    fi
    echo "$user_agent"
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
                    -H "User-Agent: $(get_user_agent)" \
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
        CentOS* | Oracle | RHEL | Rocky | AlmaLinux)
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
