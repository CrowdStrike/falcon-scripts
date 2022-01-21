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
EOF
}

main() {
    if [ -n "$1" ]; then
        print_usage
        exit 1
    fi
    echo -n 'Falcon Sensor Install  ... '; cs_sensor_install;  echo '[ Ok ]'
    echo -n 'Falcon Sensor Register ... '; cs_sensor_register; echo '[ Ok ]'
    echo -n 'Falcon Sensor Restart  ... '; cs_sensor_restart;  echo '[ Ok ]'
    echo 'Falcon Sensor deployed successfully.'
}

cs_sensor_register() {
    if [ -z "${cs_falcon_cid}" ]; then
        cs_target_cid=$(curl -s -L "https://$(cs_cloud)/sensors/queries/installers/ccid/v1" \
                             -H "authorization: Bearer $cs_falcon_oauth_token")

        cs_falcon_cid=$(echo "$cs_target_cid" | tr -d '\n" ' | awk -F'[][]' '{print $2}')
    fi

    cs_falcon_args=--cid="${cs_falcon_cid}"
    if [ -n "${cs_falcon_token}" ]; then
        cs_token=--provisioning-token="${cs_falcon_token}"
        cs_falcon_args+=" $cs_token"
    fi
    /opt/CrowdStrike/falconctl -s -f "${cs_falcon_args}"
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

cs_sensor_policy_version() {
    cs_policy_name="$1"

    sensor_update_policy=$(
        curl -s -L -G "https://$(cs_cloud)/policy/combined/sensor-update/v2" \
             --data-urlencode "filter=platform_name:\"Linux\"+name.raw:\"$cs_policy_name\"" \
             --header "authorization: Bearer $cs_falcon_oauth_token"
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

    local sensor_versions
    for i in $sensor_update_versions; do
        sensor_versions+=("$i")
    done

    if [[ "${#sensor_versions[@]}" -gt 1 ]]; then
        if [ "$cs_os_arch" = "aarch64" ] ; then
            echo "${sensor_versions[1]}"
        else
            echo "${sensor_versions[0]}"
        fi
    else
        echo "${sensor_versions[0]}"
    fi
}

cs_sensor_download() {
    destination_dir="$1"

    if [ -n "$cs_sensor_policy_name" ]; then
        cs_sensor_version=$(cs_sensor_policy_version "$cs_sensor_policy_name")
        cs_api_version_filter="+version:\"$cs_sensor_version\""

        exit_status=$?
        if [[ $exit_status -ne 0 ]]; then
            exit $exit_status
        fi
        if [[ $cs_falcon_sensor_version_dec -gt 0 ]]; then
            echo "WARNING: Disabling FALCON_SENSOR_VERSION_DECREMENT because it conflicts with FALCON_SENSOR_UPDATE_POLICY_NAME"
            cs_falcon_sensor_version_dec=0
        fi
    fi

    existing_installers=$(
        curl -s -L -G "https://$(cs_cloud)/sensors/combined/installers/v1" \
             --data-urlencode "filter=os:\"$cs_os_name\"$cs_api_version_filter" \
             -H "Authorization: Bearer $cs_falcon_oauth_token"
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
                    if [ "$v" -eq "$cs_os_version" ]; then
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
    curl -s -L "https://$(cs_cloud)/sensors/entities/download-installer/v1?id=$sha" \
         -H "Authorization: Bearer $cs_falcon_oauth_token" -o "$installer"
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

    case "${os_name}" in
        Amazon)
            rpm_install_package "$pkg"
            ;;
        CentOS)
            rpm_install_package "$pkg"
            ;;
        Debian)
            DEBIAN_FRONTEND=noninteractive apt-get -qq install -y "$pkg" > /dev/null
            ;;
        Oracle)
            rpm_install_package "$pkg"
            ;;
        RHEL)
            rpm_install_package "$pkg"
            ;;
        Rocky)
            rpm_install_package "$pkg"
            ;;
        AlmaLinux)
            rpm_install_package "$pkg"
            ;;
        SLES)
            rpm_install_package "$pkg"
            ;;
        Ubuntu)
            DEBIAN_FRONTEND=noninteractive apt-get -qq install -y "$pkg" > /dev/null
            ;;
        *)
            die "Unrecognized OS: ${os_name}";;
    esac
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

os_name=$(
    # returns either: Amazon, Ubuntu, CentOS, RHEL, or SLES
    # lsb_release is not always present
    name=$(cat /etc/*release | grep ^NAME= | awk -F'=' '{ print $2 }' | sed "s/\"//g;s/Red Hat.*/RHEL/g;s/ Linux$//g;s/ GNU\/Linux$//g;s/Oracle.*/Oracle/g")
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

    echo $name
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
    case "${os_name}" in
        Amazon)  echo "Amazon Linux";;
        CentOS)  echo "RHEL/CentOS/Oracle";;
        Debian)  echo "Debian";;
        Oracle)  echo "RHEL/CentOS/Oracle";;
        RHEL)    echo "RHEL/CentOS/Oracle";;
        Rocky)   echo "RHEL/CentOS/Oracle";;
        AlmaLinux)  echo "RHEL/CentOS/Oracle";;
        SLES)    echo "SLES";;
        Ubuntu)  echo "Ubuntu";;
        *)       die "Unrecognized OS: ${os_name}";;
    esac
)

cs_os_arch=$(
    uname -m
)

cs_os_version=$(
    version=$(echo "$os_version" | awk -F'.' '{print $1}')
    if [ "$cs_os_arch" = "aarch64" ] ; then
        echo "$os_version - arm64"
    else
        echo "$version"
    fi
)

cs_falcon_client_id=$(
    if [ -n "$FALCON_CLIENT_ID" ]; then
        echo "$FALCON_CLIENT_ID"
    else
        die "Missing FALCON_CLIENT_ID environment variable. Please provide your OAuth2 API Client ID for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys."
    fi
)

cs_falcon_client_secret=$(
    if [ -n "$FALCON_CLIENT_SECRET" ]; then
        echo "$FALCON_CLIENT_SECRET"
    else
        die "Missing FALCON_CLIENT_SECRET environment variable. Please provide your OAuth2 API Client Secret for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys."
    fi
)

cs_falcon_cid=$(
    # shellcheck disable=SC2154
    if [ -n "$FALCON_CID" ]; then
        echo "$FALCON_CID"
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
    re='^[0-9]+$'
    if [ -n "$FALCON_SENSOR_VERSION_DECREMENT" ]; then
       if ! [[ $FALCON_SENSOR_VERSION_DECREMENT =~ $re ]]; then
          die "The FALCON_SENSOR_VERSION_DECREMENT must be an integer greater than or equal to 0 or less than 5. FALCON_SENSOR_VERSION_DECREMENT: \"$FALCON_SENSOR_VERSION_DECREMENT\""
       elif ! [[ $FALCON_SENSOR_VERSION_DECREMENT -ge 0 && $FALCON_SENSOR_VERSION_DECREMENT -le 5 ]]; then
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
    if ! command -v curl &> /dev/null; then
        die "The 'curl' command is missing. Please install it before continuing. Aborting..."
    fi

    token_result=$(curl -X POST -s -L "https://$(cs_cloud)/oauth2/token" \
                       -H 'Content-Type: application/x-www-form-urlencoded; charset=utf-8' \
                       --dump-header "${response_headers}" \
                       -d "client_id=$cs_falcon_client_id&client_secret=$cs_falcon_client_secret")
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

main "$@"
