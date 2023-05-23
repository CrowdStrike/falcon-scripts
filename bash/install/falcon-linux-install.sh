#!/bin/bash

print_usage() {
    cat <<EOF
This script installs and configures the CrowdStrike Falcon Sensor for Linux.

CrowdStrike API credentials are needed to download Falcon sensor. The script recognizes the following environmental variables:

    - FALCON_CLIENT_ID
    - FALCON_CLIENT_SECRET

Optional:
    - FALCON_CID                        (default: auto)
    - FALCON_CLOUD                      (default: auto)
    - FALCON_SENSOR_VERSION_DECREMENT   (default: 0 [latest])
    - FALCON_PROVISIONING_TOKEN         (default: unset)
    - FALCON_SENSOR_UPDATE_POLICY_NAME  (default: unset)
    - FALCON_TAGS                       (default: unset)
    - FALCON_APD                        (default: unset)
    - FALCON_APH                        (default: unset)
    - FALCON_APP                        (default: unset)
    - FALCON_BILLING                    (default: default) possible values: [default|metered]
    - FALCON_BACKEND                    (default: auto)    possible values: [auto|bpf|kernel]
    - FALCON_TRACE                      (default: none)    possible values: [none|err|warn|info|debug]
    - FALCON_UNINSTALL                  (default: false)
    - FALCON_INSTALL_ONLY               (default: false)
    - ALLOW_LEGACY_CURL                 (default: false)
EOF
}

main() {
    if [ -n "$1" ]; then
        print_usage
        exit 1
    fi
    echo -n 'Check if Falcon Sensor is running ...'; cs_sensor_is_running; echo '[ Not present ]'
    echo -n 'Falcon Sensor Install  ... '; cs_sensor_install;  echo '[ Ok ]'
    # Run if FALCON_INSTALL_ONLY is not set or is set to false
    if [ -z "$FALCON_INSTALL_ONLY" ] || [ "${FALCON_INSTALL_ONLY}" = "false" ]; then
        echo -n 'Falcon Sensor Register ... '; cs_sensor_register; echo '[ Ok ]'
        echo -n 'Falcon Sensor Restart  ... '; cs_sensor_restart;  echo '[ Ok ]'
    fi
    echo 'Falcon Sensor installed successfully.'
}

cs_sensor_register() {
    if [ -z "$cs_falcon_cid" ]; then
        die "Could not find FALCON CID!"
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
    /opt/CrowdStrike/falconctl -s -f "${cs_falcon_args}"
}

cs_sensor_is_running() {
    if pgrep  -u root falcon-sensor >/dev/null 2>&1 ; then
        echo "sensor is already running... exiting"
        exit 0
    fi
}

cs_sensor_restart() {
    if type service >/dev/null 2>&1; then
        service falcon-sensor restart
    elif type systemctl >/dev/null 2>&1; then
        systemctl restart falcon-sensor
    else
        die "Could not restart falcon sensor"
    fi
}

cs_sensor_install() {
    tempdir=$(mktemp -d)

    tempdir_cleanup() { rm -rf "$tempdir"; }; trap tempdir_cleanup EXIT

    package_name=$(cs_sensor_download "$tempdir")
    os_install_package "$package_name"

    tempdir_cleanup
}

cs_sensor_remove() {
    remove_package() {
        pkg="$1"

        if type dnf > /dev/null 2>&1; then
            dnf remove -q -y "$pkg" || rpm -e --nodeps "$pkg"
        elif type yum > /dev/null 2>&1; then
            yum remove -q -y "$pkg" || rpm -e --nodeps "$pkg"
        elif type zypper > /dev/null 2>&1; then
            zypper --quiet remove -y "$pkg" || rpm -e --nodeps "$pkg"
        elif type apt > /dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt purge -y "$pkg" > /dev/null
        else
            rpm -e --nodeps "$pkg"
        fi
    }

    remove_package "falcon-sensor"
}

cs_sensor_policy_version() {
    cs_policy_name="$1"

    sensor_update_policy=$(
        curl_command -G "https://$(cs_cloud)/policy/combined/sensor-update/v2" \
             --data-urlencode "filter=platform_name:\"Linux\"+name.raw:\"$cs_policy_name\""
    )

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
        if [ "$cs_os_arch" = "aarch64" ] ; then
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
    destination_dir="$1"

    if [ -n "$cs_sensor_policy_name" ]; then
        cs_sensor_version=$(cs_sensor_policy_version "$cs_sensor_policy_name")
        cs_api_version_filter="+version:\"$cs_sensor_version\""

        exit_status=$?
        if [ $exit_status -ne 0 ]; then
            exit $exit_status
        fi
        if [ "$cs_falcon_sensor_version_dec" -gt 0 ]; then
            echo "WARNING: Disabling FALCON_SENSOR_VERSION_DECREMENT because it conflicts with FALCON_SENSOR_UPDATE_POLICY_NAME"
            cs_falcon_sensor_version_dec=0
        fi
    fi

    existing_installers=$(
        curl_command -G "https://$(cs_cloud)/sensors/combined/installers/v1" \
             --data-urlencode "filter=os:\"$cs_os_name\"$cs_api_version_filter$cs_os_arch_filter"
    )

    if echo "$existing_installers" | grep "authorization failed"; then
        die "Access denied: Please make sure that your Falcon API credentials allow sensor download (scope Sensor Download [read])"
    elif echo "$existing_installers" | grep "invalid bearer token"; then
        die "Invalid Access Token: $cs_falcon_oauth_token"
    fi

    sha_list=$(echo "$existing_installers" | json_value "sha256")
    if [ -z "$sha_list" ]; then
        die "No sensor found for with OS Name: $cs_os_name"
    fi

    INDEX=1
    OLDER_VERSION="$cs_falcon_sensor_version_dec"
    if [ -n "$cs_os_version" ]; then
        found=0
        IFS='
'
        for l in $(echo "$existing_installers" | json_value "os_version"); do
            l=$(echo "$l" | sed 's/ *$//g' | sed 's/^ *//g')

            if echo "$l" | grep -q '/'; then
                # Sensor for Ubuntu has l="14/16/18/20"
                for v in $(echo "$l" | tr '/' '\n'); do
                    if [ "$v" = "$cs_os_version" ]; then
                        l="$v"
                        break
                    fi
                done
            fi

            if [ "$l" = "$cs_os_version" ]; then
                found=1
                if [ "$OLDER_VERSION" -eq 0 ] ; then
                    break
                fi
                OLDER_VERSION=$((OLDER_VERSION-1))
            fi
            INDEX=$((INDEX+1))
        done
        if [ $found = 0 ]; then
            die "Unable to locate matching sensor: $cs_os_name, version: $cs_os_version"
        fi
    fi

    sha=$(echo "$existing_installers" | json_value "sha256" "$INDEX" \
              | sed 's/ *$//g' | sed 's/^ *//g')
    if [ -z "$sha" ]; then
        die "Unable to identify a sensor installer matching: $cs_os_name, version: $cs_os_version"
    fi
    file_type=$(echo "$existing_installers" | json_value "file_type" "$INDEX" | sed 's/ *$//g' | sed 's/^ *//g')

    installer="${destination_dir}/falcon-sensor.${file_type}"

    curl_command "https://$(cs_cloud)/sensors/entities/download-installer/v1?id=$sha" -o "${installer}"
    echo "$installer"
}

os_install_package() {
    pkg="$1"

    rpm_install_package() {
        pkg="$1"

        cs_falcon_gpg_import

        if type dnf > /dev/null 2>&1; then
            dnf install -q -y "$pkg" || rpm -ivh --nodeps "$pkg"
        elif type yum > /dev/null 2>&1; then
            yum install -q -y "$pkg" || rpm -ivh --nodeps "$pkg"
        elif type zypper > /dev/null 2>&1; then
            zypper --quiet install -y "$pkg" || rpm -ivh --nodeps "$pkg"
        else
            rpm -ivh --nodeps "$pkg"
        fi
    }
    # shellcheck disable=SC2221,SC2222
    case "${os_name}" in
        Amazon|CentOS|Oracle|RHEL|Rocky|AlmaLinux|SLES)
            rpm_install_package "$pkg"
            ;;
        Debian)
            DEBIAN_FRONTEND=noninteractive apt-get -qq install -y "$pkg" > /dev/null
            ;;
        Ubuntu)
            DEBIAN_FRONTEND=noninteractive apt-get -qq install -y "$pkg" > /dev/null
            ;;
        *)
            die "Unrecognized OS: ${os_name}";;
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
    if ! echo "$response" | grep -q '^.*"InvalidParameters":\[\].*$'; then
        die "Unexpected response from AWS SSM Parameter Store: $response"
    elif ! echo "$response" | grep -q '^.*'"${param_name}"'.*$'; then
        die "Unexpected response from AWS SSM Parameter Store: $response"
    fi
    echo "$response"
}

cs_falcon_gpg_import() {
    tempfile=$(mktemp)
    cat > "$tempfile" <<EOF
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBGDaIBgBEADXSeElUO9NmPLhkSzeN7fGW1MRbNwxgHdo+UYt9R98snUEjXqV
benyCOlLGjxUiVv3S+k6LQ3RyFubDINWyUI2kQhHFIPkniR1wmeMMIqncPVBdpEG
Mi9F6aLg2Xkhz1tEWPkXWqXVo67jgCMFn3SAMYY1EO9HCXxj6OTa6IMbtqq1+3DR
0SgNY25lD51cJ8/FdXn1HxgQ7n5G+cNB7KDaSSOkazJTnOx68x1EI9ZFUNBPNEhx
W9SSuzYFrJNL06byIlTomQULfsfRMm7kSCU0Tp/osT5QKwh1q/+RUm4VwITXY1t2
j+C31QPnysg3lJsop2b5ySpolPeKW8A9dyos3nFNSX3+flZJfyKcd9NlVf2tTqXk
LbOWvrrcCdyslX5BWKLtDR9if79nB8QI+yQPDbcEsOFS9d2c8wj1eIimSK+VH/nG
fit9QR0DS+o9HwwK33dZfXI7KbQy47nPl+ewaady2H8S8pXxTdMycwc7w+QOy/XK
5A+yPR8XOkUieMFJ4PVj48hUIvPWBlxIde4IFi865zv7A3nxwgZ5YzYCbKJg4dJd
9Ptmknd5+1TDjG3e91ZAHUt9bBRzEdXbpRUr3YwecDNcj0Twu4SbT/wZ2pZsbMGi
QxAhkRAKCp+Oyjz8Al6F4opDnkY4krpcr1FkkSof0+XzE01L6YSC2Qca0wARAQAB
tElDcm93ZFN0cmlrZSwgSW5jLiAoZmFsY29uLXNlbnNvciBpbnN0YWxsZXIga2V5
KSA8c3VwcG9ydEBjcm93ZHN0cmlrZS5jb20+iQJSBBMBCgA8FiEEOFpE/46dUSQL
X7TARye71VGbF38FAmDaIBgCGwMFCQPCZwAECwkIBwQVCgkIBRYCAwEAAh4FAheA
AAoJEEcnu9VRmxd/p+cP+gOg6UAOBmG1xRLMxsTH4lmngakWsa6J2d9m3G3K1b7y
MrweLvyhfP/gCyjd11tmJCV0NeVHGJR10wz7q4t7eP8OdSvWi6F9BtxlXaiacXcY
YweGBaUIILy0q+GfsZ0ffLXqB6B5R9JRpP8vYv8csPlodgp8jXeOcTmfI/UstjQP
isTd7cT5yYYTunfZiIUh0ysXeyY6jnkFVTEmZdSlhUJhqnxhvkRgkTrcwGwb08DY
05KcI5LQMlqwiHV2pTZxEtd6hhlfosciFJLcMoII4Xa9TyiYLRSakf1rcoMkNjMC
OEu7RauXXcD43IrvID2303WX4RK6jWAEFHZwaFIUo5bZ2MXgufjsiDcEP3Hg1VuN
UzN69StySNsVCpqQNfMavVpipmMtaFl5tQqMxNDMLiAVLx1m2g9hr4pP3SdKzkPC
626JM+et4lPDtnHAh05XLSkeJEBawL7cnPHRzuQVA12utD9KvYC0D2+WLml1vBuT
R+jOD3QbrYMQQNC89NaDS8P05nED+M2J/FwddMJfrVfd9iYZYW0eK/pppwktY1/f
ktmshju1x3MV8xmduyd3T5YilttfAPQ8mT2wb3nbjLfBm4R5N5xWFrzFAz97J/4a
I0cFWDfTDZSUFsvePYuXaEoWgUynyTQ7pLQcvmsjGpo39SYFXa1CDK6NSQoaeX9+
=ifb7
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
        us-1)      echo "api.crowdstrike.com";;
        us-2)      echo "api.us-2.crowdstrike.com";;
        eu-1)      echo "api.eu-1.crowdstrike.com";;
        us-gov-1)  echo "api.laggar.gcw.crowdstrike.com";;
        *)         die "Unrecognized Falcon Cloud: ${cs_falcon_cloud}";;
    esac
}

# Check for old version of curl that doesn't support -H @-
old_curl=$(
    # we convert curl's version string to a number by removing the dots and test to see if it's less than version 7.55.0
    test "$(curl --version | head -n 1 | awk '{ print $2 }' | tr -d '.')" -lt 7550 && echo 0 || echo 1
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

curl_command() {
    # Dash does not support arrays, so we have to pass the args as separate arguments
    set -- "$@"
    if [ "$old_curl" -eq 0 ]; then
        curl -s -L -H "Authorization: Bearer ${cs_falcon_oauth_token}" "$@"
    else
        echo "Authorization: Bearer ${cs_falcon_oauth_token}" | curl -s -L -H @- "$@"
    fi
}

# shellcheck disable=SC2034
cs_uninstall=$(
    if [ "$FALCON_UNINSTALL" ]; then
        echo -n 'Removing Falcon Sensor  ... '; cs_sensor_remove;  echo '[ Ok ]'
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
        if type rpm > /dev/null 2>&1; then
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
            echo "Amazon Linux";;
        CentOS|Oracle|RHEL|Rocky|AlmaLinux)
            echo "*RHEL*";;
        Debian)
            echo "Debian";;
        SLES)
            echo "SLES";;
        Ubuntu)
            echo "Ubuntu";;
        *)
            die "Unrecognized OS: ${os_name}";;
    esac
)

cs_os_arch=$(
    uname -m
)

cs_os_arch_filter=$(
    case "${cs_os_arch}" in
        x86_64)
            echo "+os_version:!~\"arm64\"+os_version:!~\"zLinux\"";;
        aarch64)
            echo "+os_version:~\"arm64\"";;
        s390x)
            echo "+os_version:~\"zLinux\"";;
        *)
            die "Unrecognized OS architecture: ${cs_os_arch}";;
    esac
)

cs_os_version=$(
    version=$(echo "$os_version" | awk -F'.' '{print $1}')
    if [ "$cs_os_arch" = "aarch64" ] ; then
        echo "$version - arm64"
    elif [ "$os_name" = "Amazon" ] && [ "$version" -ge 2017 ] ; then
        echo "1"
    else
        echo "$version"
    fi
)

aws_instance=$(
    if [ -f /sys/hypervisor/uuid ] && grep -qi ec2 /sys/hypervisor/uuid; then
        echo true
    elif [ -f /sys/devices/virtual/dmi/id/board_asset_tag ] && grep -q '^i-[a-z0-9]*$' /sys/devices/virtual/dmi/id/board_asset_tag; then
        echo true
    else
        curl_output="$(curl -s --connect-timeout 5 http://169.254.169.254/latest/dynamic/instance-identity/)"
        if [ -n "$curl_output" ] && ! echo "$curl_output" | grep --silent -i 'Not Found'; then
            echo true
        fi
    fi
)

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
       if ! expr "$FALCON_SENSOR_VERSION_DECREMENT" : "$re" > /dev/null 2>&1; then
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

cs_falcon_oauth_token=$(
    if ! command -v curl > /dev/null 2>&1; then
        die "The 'curl' command is missing. Please install it before continuing. Aborting..."
    fi

    token_result=$(echo "client_id=$cs_falcon_client_id&client_secret=$cs_falcon_client_secret" | \
                   curl -X POST -s -L "https://$(cs_cloud)/oauth2/token" \
                       -H 'Content-Type: application/x-www-form-urlencoded; charset=utf-8' \
                       -H 'User-Agent: crowdstrike-falcon-scripts/1.1.2' \
                       --dump-header "${response_headers}" \
                       --data @-)
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
    if [ "x${FALCON_CLOUD}" != "x${region_hint}" ]; then
        echo "WARNING: FALCON_CLOUD='${FALCON_CLOUD}' environment variable specified while credentials only exists in '${region_hint}'" >&2
    fi
fi

cs_falcon_cid=$(
    if [ -n "$FALCON_CID" ]; then
        echo "$FALCON_CID"
    else
        cs_target_cid=$(curl_command "https://$(cs_cloud)/sensors/queries/installers/ccid/v1")
        if [ -z "$cs_target_cid" ]; then
            die "Unable to obtain CrowdStrike Falcon CID. Response was $cs_target_cid"
        fi
        echo "$cs_target_cid" | tr -d '\n" ' | awk -F'[][]' '{print $2}'
    fi
)

if [ -n "$FALCON_APD" ]; then
    cs_falcon_apd=$(
        case "${FALCON_APD}" in
            true)
                echo "true";;
            false)
                echo "false";;
            *)
                die "Unrecognized APD: ${FALCON_APD} value must be one of : [true|false]";;
        esac
    )
fi

if [ -n "$FALCON_BILLING" ]; then
    cs_falcon_billing=$(
        case "${FALCON_BILLING}" in
            default)
                echo "default";;
            metered)
                echo "metered";;
            *)
                die "Unrecognized BILLING: ${FALCON_BILLING} value must be one of : [default|metered]";;
        esac
    )
fi

if [ -n "$FALCON_BACKEND" ]; then
    cs_falcon_backend=$(
        case "${FALCON_BACKEND}" in
            auto)
                echo "auto";;
            bpf)
                echo "bpf";;
            kernel)
                echo "kernel";;
            *)
                die "Unrecognized BACKEND: ${FALCON_BACKEND} value must be one of : [auto|bpf|kernel]";;
        esac
    )
fi

if [ -n "$FALCON_TRACE" ]; then
    cs_falcon_trace=$(
        case "${FALCON_TRACE}" in
            none)
                echo "none";;
            err)
                echo "err";;
            warn)
                echo "warn";;
            info)
                echo "info";;
            debug)
                echo "debug";;
            *)
                die "Unrecognized TRACE: ${FALCON_TRACE} value must be one of : [none|err|warn|info|debug]";;
        esac
    )
fi

main "$@"
