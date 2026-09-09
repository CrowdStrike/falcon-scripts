#!/bin/bash

case $- in
    *x*)
        set +x
        printf '%s\n' 'WARNING: shell tracing disabled to protect credentials.' >&2
        ;;
esac

falcon_client_secret=$FALCON_CLIENT_SECRET
falcon_access_token=$FALCON_ACCESS_TOKEN
falcon_maintenance_token=$FALCON_MAINTENANCE_TOKEN
unset FALCON_CLIENT_SECRET FALCON_ACCESS_TOKEN FALCON_MAINTENANCE_TOKEN
FALCON_CLIENT_SECRET=$falcon_client_secret
FALCON_ACCESS_TOKEN=$falcon_access_token
FALCON_MAINTENANCE_TOKEN=$falcon_maintenance_token
unset falcon_client_secret falcon_access_token falcon_maintenance_token

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

Uninstalls the CrowdStrike Falcon Sensor from Linux operating systems.
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

Other Options:
    - FALCON_MAINTENANCE_TOKEN          (default: unset)
        Sensor uninstall maintenance token used to unlock sensor uninstallation.
        If not provided but FALCON_CLIENT_ID and FALCON_CLIENT_SECRET are set,
        the script will try to retrieve the token from the API.

    - FALCON_REMOVE_HOST                (default: unset)
        Determines whether the host should be removed from the Falcon console after uninstalling the sensor.
        Requires API Authentication.
        NOTE: It is recommended to use Host Retention Policies in the Falcon console instead.
        Accepted values are ['true', 'false'].

    - GET_ACCESS_TOKEN                  (default: unset)
        Prints an access token and exits.
        Requires FALCON_CLIENT_ID and FALCON_CLIENT_SECRET.
        Accepted values are ['true', 'false'].

    - FALCON_APH                        (default: unset)
        The proxy host for the sensor to use when communicating with CrowdStrike.

    - FALCON_APP                        (default: unset)
        The proxy port for the sensor to use when communicating with CrowdStrike.

    - ALLOW_LEGACY_CURL                 (default: false)
        Deprecated. Accepted and ignored; no longer needed.

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
        "maintenance_token_set=$([ -n "${FALCON_MAINTENANCE_TOKEN}" ] && echo yes || echo no)" \
        "proxy_set=$([ -n "${proxy}" ] && echo yes || echo no)"
    # OS values here are informational only: uninstall never filters an API
    # query by OS, so a mis-detected value cannot break sensor selection.
    falcon_debug start "step=environment" \
        "os=$(awk -F= '/^NAME=/{print $2}' /etc/*release 2>/dev/null | tr -d '"' | head -n 1)" \
        "os_version=$(awk -F= '/^VERSION_ID=/{print $2}' /etc/*release 2>/dev/null | tr -d '"' | head -n 1)" \
        "os_arch=$(uname -m)" "kernel=$(uname -r 2>/dev/null)" "run_as=$(id -un 2>/dev/null)" \
        "pkg_manager=$(falcon_debug_pkg_manager)"
    if [ "$GET_ACCESS_TOKEN" = "true" ]; then
        get_oauth_token
        echo "$cs_falcon_oauth_token"
        exit 0
    fi

    # Check if Falcon sensor is installed
    cs_sensor_installed

    # Handle maintenance token
    cs_maintenance_token=""
    if [ -n "$FALCON_MAINTENANCE_TOKEN" ]; then
        cs_maintenance_token="$FALCON_MAINTENANCE_TOKEN"
        falcon_debug maintenance_token "source=env" "maintenance_token_set=yes"
    elif [ -n "$FALCON_CLIENT_ID" ] && [ -n "$FALCON_CLIENT_SECRET" ] && [ -n "$aid" ]; then
        get_oauth_token
        get_maintenance_token
        echo "Retrieved maintenance token via API"
    fi

    echo -n 'Removing Falcon Sensor  ... '
    cs_sensor_remove
    echo '[ Ok ]'
    if [ "${FALCON_REMOVE_HOST}" = "true" ]; then
        echo -n 'Removing host from console ... '
        get_oauth_token
        cs_remove_host_from_console
        echo '[ Ok ]'
    fi
    echo 'Falcon Sensor removed successfully.'
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
            DEBIAN_FRONTEND=noninteractive apt purge -y "$pkg" >/dev/null 2>&1
        else
            rpm -e --nodeps "$pkg"
        fi
    }

    falcon_debug cs_sensor_remove "step=start" "pkg_manager=$(falcon_debug_pkg_manager)"

    # Handle maintenance protection
    if [ -n "$cs_maintenance_token" ]; then
        # shellcheck disable=SC2086
        if ! /opt/CrowdStrike/falconctl -s -f --maintenance-token=${cs_maintenance_token} >/dev/null 2>&1; then
            falcon_debug cs_sensor_remove "step=maintenance_protection" "error=apply_failed"
            die "Failed to apply maintenance token. Uninstallation may fail."
        fi
        falcon_debug cs_sensor_remove "step=maintenance_protection" "maintenance_token_set=yes"
    fi

    # Check for package manager lock prior to uninstallation
    check_package_manager_lock

    # Temporarily disable exit-on-error to capture package removal exit code
    set +e
    remove_package "falcon-sensor"
    removal_exit_code=$?
    set -e

    falcon_debug cs_sensor_remove "step=removed" "exit_code=$removal_exit_code"
    if [ "$removal_exit_code" -ne 0 ]; then
        die "Failed to remove falcon-sensor package (exit code $removal_exit_code). This may indicate that tamper protection is enabled on the sensor. Please provide FALCON_MAINTENANCE_TOKEN or set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET to retrieve a maintenance token via the API."
    fi
}

cs_remove_host_from_console() {
    if [ -z "$aid" ]; then
        falcon_debug cs_remove_host_from_console "step=skipped" "aid=none"
        echo 'Unable to find AID. Skipping host removal from console.'
    else
        falcon_debug cs_remove_host_from_console "step=request" "aid=$aid"
        payload="{\"ids\": [\"$aid\"]}"
        url="https://$(cs_cloud)/devices/entities/devices-actions/v2?action_name=hide_host"

        curl_command -X "POST" -H "Content-Type: application/json" -d "$payload" "$url" >/dev/null || handle_curl_error $?
        falcon_debug cs_remove_host_from_console "step=done"
    fi
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

cs_sensor_installed() {
    if ! test -f /opt/CrowdStrike/falconctl; then
        falcon_debug cs_sensor_installed "step=already_uninstalled"
        echo "Falcon sensor is already uninstalled." && exit 0
    fi
    # Get AID if FALCON_REMOVE_HOST is set to true or if we need to get a maintenance token
    if [ "${FALCON_REMOVE_HOST}" = "true" ] || [ -n "$FALCON_CLIENT_ID" ] && [ -n "$FALCON_CLIENT_SECRET" ] && [ -z "$FALCON_MAINTENANCE_TOKEN" ]; then
        get_aid
    fi
}

get_maintenance_token() {
    if [ -z "$aid" ]; then
        die "Unable to find AID. Cannot retrieve maintenance token."
    fi

    echo "Retrieving maintenance token from the CrowdStrike Falcon API..."

    payload="{\"device_id\": \"$aid\", \"audit_message\": \"CrowdStrike Falcon Uninstall Bash Script\"}"
    url="https://$(cs_cloud)/policy/combined/reveal-uninstall-token/v1"

    response=$(curl_command -X "POST" -H "Content-Type: application/json" -d "$payload" "$url") || handle_curl_error $?

    if echo "$response" | grep -q "\"uninstall_token\""; then
        cs_maintenance_token=$(echo "$response" | json_value "uninstall_token" 1 | sed 's/ *$//g' | sed 's/^ *//g')
        if [ -z "$cs_maintenance_token" ]; then
            falcon_debug maintenance_token "source=api" "error=empty_token"
            die "Retrieved empty maintenance token from API."
        fi
        falcon_debug maintenance_token "source=api" "maintenance_token_set=yes"
    else
        falcon_debug maintenance_token "source=api" "error=no_token_in_response"
        die "Failed to retrieve a maintenance token from the Falcon API."
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

handle_curl_error() {
    falcon_debug handle_curl_error "curl_exit=$1"
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

if ! command -v curl >/dev/null 2>&1; then
    die "The 'curl' command is missing. Please install it before continuing. Aborting..."
fi

if [ "${ALLOW_LEGACY_CURL:-false}" = "true" ]; then
    echo "NOTICE: ALLOW_LEGACY_CURL is no longer needed and is ignored." >&2
fi

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

get_aid() {
    aid="$(/opt/CrowdStrike/falconctl -g --aid | awk -F '"' '{print $2}')"
    falcon_debug get_aid "aid=${aid:-none}"
}

#------Start of the script------#
set -e

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

main "$@"
