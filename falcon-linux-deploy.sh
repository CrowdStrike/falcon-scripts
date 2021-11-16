#!/bin/bash

print_usage() {
    cat <<EOF
This script installs and configures the CrowdStrike Falcon Sensor for Linux.

CrowdStrike API credentials are needed to download Falcon sensor. The script recognizes the following environmental variables:

    - FALCON_CLIENT_ID
    - FALCON_CLIENT_SECRET

Optional:
    - FALCON_CID                        (default: auto)
    - FALCON_CLOUD                      (default: us-1)
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
        cs_target_cid=$(curl -s -L "https://$cs_cloud/sensors/queries/installers/ccid/v1" \
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
        curl -s -L -G "https://$cs_cloud/policy/combined/sensor-update/v2" \
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

    sensor_versions=( )
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
        curl -s -L -G "https://$cs_cloud/sensors/combined/installers/v1" \
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
    curl -s -L "https://$cs_cloud/sensors/entities/download-installer/v1?id=$sha" \
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
Version: GnuPG v2.0.22 (GNU/Linux)

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
OY0=
=rjt/
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

os_name=$(
    # returns either: Amazon, Ubuntu, CentOS, RHEL, or SLES
    # lsb_release is not always present
    name=$(cat /etc/*release | grep ^NAME= | awk -F'=' '{ print $2 }' | sed "s/\"//g;s/Red Hat.*/RHEL/g;s/ Linux$//g;s/ GNU\/Linux$//g")
    if [ -z "$name" ]; then
        if lsb_release -s -i | grep -q ^RedHat; then
            name="RHEL"
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
        # api.crowdstrike.com is the default
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

cs_cloud=$(
    case "${cs_falcon_cloud}" in
        us-1)      echo "api.crowdstrike.com";;
        us-2)      echo "api.us-2.crowdstrike.com";;
        eu-1)      echo "api.eu-1.crowdstrike.com";;
        us-gov-1)  echo "api.laggar.gcw.crowdstrike.com";;
        *)         die "Unrecognized Falcon Cloud: ${cs_falcon_cloud}";;
    esac
)

cs_falcon_oauth_token=$(
    if ! command -v curl &> /dev/null; then
        die "The 'curl' command is missing. Please install it before continuing. Aborting..."
    fi

    token_result=$(curl -X POST -s -L "https://$cs_cloud/oauth2/token" \
                       -H 'Content-Type: application/x-www-form-urlencoded; charset=utf-8' \
                       -d "client_id=$cs_falcon_client_id&client_secret=$cs_falcon_client_secret")
    token=$(echo "$token_result" | json_value "access_token" | sed 's/ *$//g' | sed 's/^ *//g')
    if [ -z "$token" ]; then
        die "Unable to obtain CrowdStrike Falcon OAuth Token. Response was $token_result"
    fi
    echo "$token"
)

main "$@"
