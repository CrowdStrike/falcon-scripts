#!/bin/bash

case $- in
    *x*)
        set +x
        printf '%s\n' 'WARNING: shell tracing disabled to protect credentials.' >&2
        ;;
esac

falcon_client_secret=$FALCON_CLIENT_SECRET
falcon_access_token=$FALCON_ACCESS_TOKEN
falcon_provisioning_token=$FALCON_PROVISIONING_TOKEN
unset FALCON_CLIENT_SECRET FALCON_ACCESS_TOKEN FALCON_PROVISIONING_TOKEN
FALCON_CLIENT_SECRET=$falcon_client_secret
FALCON_ACCESS_TOKEN=$falcon_access_token
FALCON_PROVISIONING_TOKEN=$falcon_provisioning_token
unset falcon_client_secret falcon_access_token falcon_provisioning_token

# Opt-in redacted debug. Never re-enable set -x around credential paths.
falcon_debug_enabled() {
    case "${FALCON_DEBUG:-}" in
        1 | true) return 0 ;;
        *) return 1 ;;
    esac
}

# Allow-list. Only known-safe keys keep their value; everything else is dropped,
# so a future debug line cannot leak a secret by accident.
falcon_debug_filter() {
    printf '%s\n' "$@" | awk '
        BEGIN {
            split("step source error stage \
                   cloud old_cloud new_cloud region region_hint sensor_cloud \
                   http_status curl_exit exit_code path filter sort \
                   os os_version os_arch os_family kernel pkg_manager distro_id run_as \
                   count index decrement version sensor_version policy_version file_type sha \
                   installer bytes sha_verify billing backend apd aid cid_source \
                   tags_count grouping_tags_count sensor_type param registry repository tag \
                   client_id_set client_secret_set access_token_set member_cid_set \
                   provisioning_token_set maintenance_token_set proxy_set policy_name_set \
                   tags_set grouping_tags_set", safe, " ")
            for (i in safe) { ok[safe[i]] = 1 }
        }
        {
            eq = index($0, "=")
            if (eq < 2) { next }
            key = substr($0, 1, eq - 1)
            printf " %s=%s", key, (key in ok) ? substr($0, eq + 1) : "[DROPPED]"
        }
    '
}

falcon_debug() {
    falcon_debug_enabled || return 0
    local falcon_debug_label
    falcon_debug_label=$1
    shift
    printf 'FALCON_DEBUG: %s%s\n' "$falcon_debug_label" "$(falcon_debug_filter "$@")" >&2
}

# Last HTTP status from a curl --dump-header file. Status only — no header dump.
falcon_debug_http_status() {
    [ -f "$1" ] || return 0
    grep -i '^HTTP/' "$1" 2>/dev/null | tail -n 1 | awk '{print $2}'
}

# Mirrors the selection order in os_install_package / remove_package.
falcon_debug_pkg_manager() {
    if type dnf >/dev/null 2>&1; then
        echo dnf
    elif type yum >/dev/null 2>&1; then
        echo yum
    elif type zypper >/dev/null 2>&1; then
        echo zypper
    elif type apt-get >/dev/null 2>&1; then
        echo apt
    elif type rpm >/dev/null 2>&1; then
        echo rpm
    else
        echo unknown
    fi
}

print_usage() {
    cat <<EOF

Usage: $0 [-h|--help|--debug]

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
        Accepted values are ['us-1', 'us-2', 'us-3', 'eu-1', 'us-gov-1', 'us-gov-2'].

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

    - FALCON_SENSOR_CLOUD               (default: unset)
        To pin the cloud region for unified sensor installations.
        This allows specifying the cloud region for unified sensors at installation time.
        Accepted values are [us-1|us-2|us-3|eu-1|us-gov-1|us-gov-2].

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
        Deprecated. Accepted and ignored; no longer needed.

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

    - FALCON_DEBUG                      (default: unset)
        Print redacted progress markers to stderr: detected OS and package
        manager, the exact sensor query filter, how many installers matched and
        which was chosen, the API route, HTTP status and curl exit code, and the
        installed version and AID. Values are dropped unless the key is on a
        fixed allow-list, so secrets cannot appear. Do not use bash -x for
        support; it prints credentials.
        Accepted values are ['1', 'true'].

This script recognizes the following arguments:
    -h, --help
        Print this help message and exit.
    --debug
        Same as FALCON_DEBUG=1.

EOF
}

VERSION="1.13.0"

# Scan for -h/--help and --debug in any position
for arg in "$@"; do
    case "$arg" in
        -h | --help)
            print_usage
            exit 0
            ;;
        --debug)
            FALCON_DEBUG=1
            ;;
    esac
done

main() {
    falcon_debug start "version=$VERSION" "cloud=${FALCON_CLOUD:-unset}" \
        "client_id_set=$([ -n "${FALCON_CLIENT_ID}" ] && echo yes || echo no)" \
        "access_token_set=$([ -n "${FALCON_ACCESS_TOKEN}" ] && echo yes || echo no)" \
        "member_cid_set=$([ -n "${FALCON_MEMBER_CID}" ] && echo yes || echo no)" \
        "proxy_set=$([ -n "${proxy}" ] && echo yes || echo no)"
    # OS detection drives the sensor query filter, so a mis-detected distro is
    # the usual cause of "no sensor found for OS".
    falcon_debug start "step=environment" \
        "os=$cs_os_name" "os_version=${cs_os_version:-unset}" "os_arch=$cs_os_arch" \
        "kernel=$(uname -r 2>/dev/null)" "run_as=$(id -un 2>/dev/null)" \
        "pkg_manager=$(falcon_debug_pkg_manager)" \
        "policy_name_set=$([ -n "${FALCON_SENSOR_UPDATE_POLICY_NAME}" ] && echo yes || echo no)" \
        "decrement=${cs_falcon_sensor_version_dec:-0}"
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
    # Authoritative version and AID, read back from the installed sensor.
    # aid=none is normal right after install: registration completes
    # asynchronously once the sensor reaches the cloud.
    if [ -x /opt/CrowdStrike/falconctl ]; then
        local installed_version installed_aid
        installed_version=$(/opt/CrowdStrike/falconctl -g --version 2>/dev/null | sed -n 's/.*version *= *\([0-9][0-9.]*\).*/\1/p')
        installed_aid=$(/opt/CrowdStrike/falconctl -g --aid 2>/dev/null | sed -n 's/.*aid="*\([0-9a-fA-F]\{8,\}\)"*.*/\1/p')
        falcon_debug main "step=installed" \
            "version=${installed_version:-unknown}" "aid=${installed_aid:-none}"
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
    # add the cloud region to the params for unified sensors
    if [ -n "${cs_falcon_sensor_cloud}" ]; then
        cs_falconctl_opt_cloud=--cloud="${cs_falcon_sensor_cloud}"
        cs_falcon_args="$cs_falcon_args $cs_falconctl_opt_cloud"
    fi
    # run the configuration command
    # Option names only. cs_falcon_args holds --provisioning-token and --cid,
    # so it must never be printed.
    falcon_debug cs_sensor_register "step=configure" \
        "cid_source=${cs_falcon_cid_source:-api}" \
        "provisioning_token_set=$([ -n "${cs_falcon_token}" ] && echo yes || echo no)" \
        "tags_count=$(printf '%s\n' "${FALCON_TAGS}" | awk -F, '{print ($0=="")?0:NF}')" \
        "apd=${cs_falcon_apd:-unset}" \
        "proxy_set=$([ -n "${FALCON_APH}${FALCON_APP}" ] && echo yes || echo no)" \
        "billing=${cs_falcon_billing:-unset}" \
        "backend=${cs_falcon_backend:-unset}" \
        "sensor_cloud=${cs_falcon_sensor_cloud:-unset}"
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
    ) || handle_curl_error $?

    if echo "$sensor_update_policy" | grep "authorization failed"; then
        die "Access denied: Please make sure that your Falcon API credentials allow access to sensor update policies (scope Sensor update policies [read])"
    elif echo "$sensor_update_policy" | grep "invalid bearer token"; then
        die "Invalid or expired Falcon access token."
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

# Compare the downloaded installer against the SHA-256 that the API supplied.
# That digest is the download id in the request URL, so this check finds
# truncation and alteration in transit. It is not a signature check: the digest
# and the file come from the same response, so it does not prove who built the
# installer.
verify_sha256() {
    local file="$1" expected_sha="$2" local_sha

    if command -v sha256sum >/dev/null 2>&1; then
        local_sha=$(sha256sum "$file" | awk '{ print $1 }')
    elif command -v openssl >/dev/null 2>&1; then
        local_sha=$(openssl dgst -sha256 "$file" | awk '{ print $NF }')
    else
        # Keep the file. The download is not known to be bad, only unverified.
        die "Cannot verify the downloaded sensor installer: neither 'sha256sum' nor 'openssl' is available. Install one of them and try again. The download is kept at $file."
        # die exits, so shellcheck reports the return below as unreachable and
        # it is. Keep it anyway: if die ever stops exiting, control would reach
        # the comparison with an empty digest and delete the file.
        # shellcheck disable=SC2317
        return 1
    fi
    if [ "$local_sha" != "$expected_sha" ]; then
        rm -f "$file"
        die "Downloaded sensor installer failed SHA-256 verification."
    fi
}

cs_sensor_download() {
    local destination_dir="$1" existing_installers sha_list INDEX sha file_type installer sensor_filter

    if [ -n "$cs_sensor_policy_name" ]; then
        cs_sensor_version=$(cs_sensor_policy_version "$cs_sensor_policy_name")
        cs_api_version_filter="+version:\"$cs_sensor_version\""

        if [ "$cs_falcon_sensor_version_dec" -gt 0 ]; then
            echo "WARNING: Disabling FALCON_SENSOR_VERSION_DECREMENT because it conflicts with FALCON_SENSOR_UPDATE_POLICY_NAME"
            cs_falcon_sensor_version_dec=0
        fi
    fi

    sensor_filter="os:\"$cs_os_name\"$cs_os_version_filter$cs_api_version_filter$cs_os_arch_filter"
    # The single most useful line when no sensor is found or the wrong one is.
    falcon_debug cs_sensor_download "step=query" "filter=$sensor_filter" "sort=version|desc" "decrement=$cs_falcon_sensor_version_dec"
    existing_installers=$(
        curl_command -G "https://$(cs_cloud)/sensors/combined/installers/v3?sort=version|desc" \
            --data-urlencode "filter=$sensor_filter"
    ) || handle_curl_error $?

    if echo "$existing_installers" | grep "authorization failed"; then
        die "Access denied: Please make sure that your Falcon API credentials allow sensor download (scope Sensor Download [read])"
    elif echo "$existing_installers" | grep "invalid bearer token"; then
        die "Invalid or expired Falcon access token."
    fi

    sha_list=$(echo "$existing_installers" | json_value "sha256")
    falcon_debug cs_sensor_download "step=matched" "count=$(echo "$sha_list" | grep -c .)"
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

    # json_value matches any key containing the name, so "version" would also
    # match os_version. The sha identifies the build unambiguously instead.
    falcon_debug cs_sensor_download "step=selected" "index=$INDEX" "file_type=$file_type" "sha=$(printf '%.12s' "$sha")"

    curl_command "https://$(cs_cloud)/sensors/entities/download-installer/v3?id=$sha" -o "${installer}" || handle_curl_error $?

    falcon_debug cs_sensor_download "step=downloaded" "installer=$installer" "bytes=$(wc -c <"$installer" 2>/dev/null | tr -d ' ')"

    verify_sha256 "$installer" "$sha"
    falcon_debug cs_sensor_download "step=verified" "sha_verify=ok"

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
            # Refresh package cache to handle stale cache issues
            DEBIAN_FRONTEND=noninteractive apt-get -qq update >/dev/null 2>&1 || true
            DEBIAN_FRONTEND=noninteractive apt-get -qq install -y "$pkg" >/dev/null
            ;;
        Ubuntu)
            # Refresh package cache to handle stale cache issues
            DEBIAN_FRONTEND=noninteractive apt-get -qq update >/dev/null 2>&1 || true

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
    local param_name="$1" imds_err

    falcon_debug aws_ssm_parameter "step=request" "param=$param_name"

    hmac_sha256() {
        key="$1"
        data="$2"
        echo -n "$data" | openssl dgst -sha256 -mac HMAC -macopt "$key" | sed 's/^.* //'
    }

    imds_err="Failed to query the EC2 instance metadata service. Reading an SSM parameter needs IMDSv2 access from this host."
    token=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600") || die "$imds_err (curl exit $?)"
    api_endpoint="AmazonSSM.GetParameters"
    iam_role="$(printf 'header = "X-aws-ec2-metadata-token: %s"\n' "$token" | curl -s -K- http://169.254.169.254/latest/meta-data/iam/security-credentials/)" || die "$imds_err (curl exit $?)"
    aws_my_region="$(printf 'header = "X-aws-ec2-metadata-token: %s"\n' "$token" | curl -s -K- http://169.254.169.254/latest/meta-data/placement/availability-zone | sed s/.$//)"
    _security_credentials="$(printf 'header = "X-aws-ec2-metadata-token: %s"\n' "$token" | curl -s -K- http://169.254.169.254/latest/meta-data/iam/security-credentials/"$iam_role")" || die "$imds_err (curl exit $?)"
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

    falcon_debug aws_ssm_parameter "step=request" "param=$param_name" "region=${aws_my_region:-unset}"
    response=$(
        {
            printf 'header = "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s/%s/ssm/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=%s"\n' \
                "$access_key_id" "$date" "$aws_my_region" "$signature"
            printf 'header = "x-amz-security-token: %s"\n' "$security_token"
            printf 'header = "x-amz-target: %s"\n' "$api_endpoint"
            printf 'header = "content-type: application/x-amz-json-1.1"\n'
            printf 'header = "x-amz-date: %s"\n' "$datetime"
        } | curl -s "https://ssm.$aws_my_region.amazonaws.com/" \
            -x "$proxy" -K- \
            -d "$request_data"
    ) || handle_curl_error $?
    if ! echo "$response" | grep -q '^.*"InvalidParameters":\[\].*$' ||
        ! echo "$response" | grep -q '^.*'"${param_name}"'.*$'; then
        # The response body holds the decrypted parameter value, so report only
        # the error message that AWS returns and never the body itself.
        ssm_error=$(echo "$response" | json_value "message" 1)
        die "Unexpected response from AWS SSM Parameter Store for parameter '$param_name'.${ssm_error:+ AWS reported: $ssm_error}"
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
    # $1 optionally overrides cs_falcon_cloud, used by the OAuth region retry.
    local region="${1:-$cs_falcon_cloud}"
    case "${region}" in
        us-1) echo "api.crowdstrike.com" ;;
        us-2) echo "api.us-2.crowdstrike.com" ;;
        us-3) echo "api.us-3.crowdstrike.com" ;;
        eu-1) echo "api.eu-1.crowdstrike.com" ;;
        us-gov-1) echo "api.laggar.gcw.crowdstrike.com" ;;
        us-gov-2) echo "api.us-gov-2.crowdstrike.mil" ;;
        *) die "Unrecognized Falcon Cloud: ${region}" ;;
    esac
}

if ! command -v curl >/dev/null 2>&1; then
    die "The 'curl' command is missing. Please install it before continuing. Aborting..."
fi

if [ "${ALLOW_LEGACY_CURL:-false}" = "true" ]; then
    echo "NOTICE: ALLOW_LEGACY_CURL is no longer needed and is ignored." >&2
fi

# Handle error codes returned by curl
handle_curl_error() {
    local err_msg

    falcon_debug handle_curl_error "curl_exit=$1"

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
    local escaped_token auth_config headers body status hint old_host new_host arg rc req_path
    # The configuration value must be quoted, because it holds a space and a
    # colon. curl processes backslash escapes inside a quoted value, so a
    # backslash or a double quote in the token has to be escaped first.
    escaped_token=$(printf '%s' "$cs_falcon_oauth_token" | sed 's/\\/\\\\/g; s/"/\\"/g')
    auth_config=$(printf 'header = "Authorization: Bearer %s"' "$escaped_token")

    # API route only, for the debug marker. The query string is dropped: it can
    # carry an installer id, and the route alone identifies the call.
    req_path=""
    for arg in "$@"; do
        case "$arg" in
            https://*)
                req_path=${arg#https://}
                case "$req_path" in
                    */*) req_path=/${req_path#*/} ;;
                    *) req_path=/ ;;
                esac
                req_path=${req_path%%\?*}
                break
                ;;
        esac
    done

    headers=$(mktemp)
    body=$(mktemp)
    # No -L: the bearer token must never cross a redirect hop. The body is held
    # back so that a redirect body is not emitted ahead of the retry's.
    printf '%s\n' "$auth_config" |
        curl -s -x "$proxy" --proto '=https' --dump-header "$headers" -K- "$@" >"$body"
    rc=$?

    # A wrong region answers with a redirect naming the right one in x-cs-region.
    # Re-issue against that region instead of following Location. Take the last
    # status line, because a proxy CONNECT dumps one of its own first.
    status=$(awk '/^HTTP\//{s=$2} END{print s}' "$headers")
    falcon_debug curl_command "path=$req_path" "http_status=$status" "curl_exit=$rc"
    case "$status" in
        301 | 302 | 307 | 308)
            hint=$(grep -i ^x-cs-region: "$headers" | head -n 1 | tr '[:upper:]' '[:lower:]' | tr -d '\r' | sed 's/^x-cs-region: //g')
            if [ -n "$hint" ]; then
                old_host=$(cs_cloud)
                # cs_cloud() validates the hint against its own allowlist. Check
                # for empty rather than trusting its die, which does not stop bash.
                new_host=$(cs_cloud "$hint")
                if [ -n "$new_host" ] && [ "$new_host" != "$old_host" ]; then
                    for arg in "$@"; do
                        shift
                        case "$arg" in
                            "https://$old_host/"*)
                                arg="https://$new_host/${arg#"https://$old_host/"}"
                                ;;
                        esac
                        set -- "$@" "$arg"
                    done
                    printf '%s\n' "$auth_config" |
                        curl -s -x "$proxy" --proto '=https' -K- "$@" >"$body"
                    rc=$?
                    falcon_debug curl_command "step=region_retry" "path=$req_path" "region=$hint" "curl_exit=$rc"
                fi
            fi
            ;;
    esac

    cat "$body"
    rm -f "$headers" "$body"
    return "$rc"
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
        # A probe failure means this is not an EC2 instance, so keep going.
        curl_output="$(curl -s --connect-timeout 5 http://169.254.169.254/latest/dynamic/instance-identity/ || true)"
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

# POSTs the OAuth payload from stdin, never argv. $1 = API host, $2 = header dump path.
oauth_token_request() {
    curl -X POST -s -x "$proxy" --proto '=https' "https://$1/oauth2/token" \
        -H 'Content-Type: application/x-www-form-urlencoded; charset=utf-8' \
        -H "User-Agent: $(get_user_agent)" \
        --dump-header "$2" \
        --data @-
}

get_oauth_token() {
    # Get credentials first
    get_falcon_credentials

    cs_falcon_oauth_token=$(
        if [ -n "$FALCON_ACCESS_TOKEN" ]; then
            falcon_debug oauth2_token "source=access_token" "cloud=${cs_falcon_cloud:-unset}"
            token=$FALCON_ACCESS_TOKEN
        else
            auth_payload="client_id=$cs_falcon_client_id&client_secret=$cs_falcon_client_secret"

            falcon_debug oauth2_token "step=request" "cloud=${cs_falcon_cloud:-unset}"
            token_result=$(echo "$auth_payload" | oauth_token_request "$(cs_cloud)" "${response_headers}") || handle_curl_error $?
            falcon_debug oauth2_token "step=response" "http_status=$(falcon_debug_http_status "${response_headers}")" "cloud=${cs_falcon_cloud:-unset}"

            token=$(echo "$token_result" | json_value "access_token" | sed 's/ *$//g' | sed 's/^ *//g')
            if [ -z "$token" ]; then
                # Wrong region: retry against the x-cs-region hint instead of
                # following the redirect, which would replay the secret to Location.
                hinted=$(grep -i ^x-cs-region: "${response_headers}" | head -n 1 | tr '[:upper:]' '[:lower:]' | tr -d '\r' | sed 's/^x-cs-region: //g')
                if [ -n "$hinted" ] && [ "$hinted" != "$cs_falcon_cloud" ]; then
                    # cs_cloud() validates the hint against its own allowlist. Check
                    # for empty rather than trusting its die, which does not stop bash.
                    retry_host=$(cs_cloud "$hinted")
                    if [ -n "$retry_host" ]; then
                        # Separate file: --dump-header truncates, and region_hint below
                        # still needs the original response.
                        retry_headers=$(mktemp)
                        falcon_debug oauth2_token "step=retry" "region=$hinted"
                        token_result=$(echo "$auth_payload" | oauth_token_request "$retry_host" "$retry_headers") || handle_curl_error $?
                        falcon_debug oauth2_token "step=retry_response" "http_status=$(falcon_debug_http_status "$retry_headers")" "region=$hinted"
                        rm -f "$retry_headers"
                        token=$(echo "$token_result" | json_value "access_token" | sed 's/ *$//g' | sed 's/^ *//g')
                    fi
                fi
            fi
            if [ -z "$token" ]; then
                die "Unable to obtain CrowdStrike Falcon OAuth Token. Double check your credentials and/or ensure you set the correct cloud region."
            fi
        fi
        echo "$token"
    )

    if [ -z "$FALCON_ACCESS_TOKEN" ]; then
        region_hint=$(grep -i ^x-cs-region: "$response_headers" | head -n 1 | tr '[:upper:]' '[:lower:]' | tr -d '\r' | sed 's/^x-cs-region: //g')
        falcon_debug oauth2_token "region_hint=${region_hint:-none}" "cloud=${cs_falcon_cloud:-unset}"

        if [ -z "${FALCON_CLOUD}" ]; then
            if [ -z "${region_hint}" ]; then
                die "Unable to obtain region hint from CrowdStrike Falcon OAuth API, Please provide FALCON_CLOUD environment variable as an override."
            fi
            cs_falcon_cloud="${region_hint}"
        elif [ -n "${region_hint}" ] && [ "${FALCON_CLOUD}" != "${region_hint}" ]; then
            echo "WARNING: FALCON_CLOUD='${FALCON_CLOUD}' environment variable specified while credentials only exists in '${region_hint}'" >&2
            # Use the hint. The API answers the wrong region with a redirect, which
            # curl_command no longer follows.
            cs_falcon_cloud="${region_hint}"
        fi
    fi

    rm "${response_headers}"
}

get_provisioning_token() {
    local check_settings is_required token_value
    # First, let's check if installation tokens are required
    check_settings=$(curl_command "https://$(cs_cloud)/installation-tokens/entities/customer-settings/v1") || handle_curl_error $?

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
        cs_target_cid=$(curl_command "https://$(cs_cloud)/sensors/queries/installers/ccid/v1") || handle_curl_error $?

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

cs_os_version_filter=$(
    # Amazon Linux versions are exact whole numbers (1, 2, 2023). A wildcard match
    # on Amazon Linux 2 ("*2*") also matches "2023", so AL2 hosts could be served an
    # AL2023 installer. Use an exact match for Amazon Linux to avoid this. The API
    # stores the arm64 os_version with a " - arm64" suffix, so match accordingly.
    if [ "${os_name}" = "Amazon" ]; then
        if [ "$cs_os_arch" = "aarch64" ]; then
            echo "+os_version:\"$cs_os_version - arm64\""
        else
            echo "+os_version:\"$cs_os_version\""
        fi
    else
        echo "+os_version:\"*$cs_os_version*\""
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

if [ -n "$FALCON_SENSOR_CLOUD" ]; then
    cs_falcon_sensor_cloud=$(
        case "${FALCON_SENSOR_CLOUD}" in
            us-1)
                echo "us-1"
                ;;
            us-2)
                echo "us-2"
                ;;
            us-3)
                echo "us-3"
                ;;
            eu-1)
                echo "eu-1"
                ;;
            us-gov-1)
                echo "us-gov-1"
                ;;
            us-gov-2)
                echo "us-gov-2"
                ;;
            *)
                die "Unrecognized SENSOR_CLOUD: ${FALCON_SENSOR_CLOUD} value must be one of : [us-1|us-2|us-3|eu-1|us-gov-1|us-gov-2]"
                ;;
        esac
    )
fi

main "$@"
