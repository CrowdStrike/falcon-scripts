#!/bin/bash
set -e

# Default values
INSTALL=false
UNINSTALL=false
CID=""
TAGS=""
IMAGE=""

# Help function
show_help() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  --install           Install the application"
    echo "  --uninstall         Uninstall the application"
    echo "  --cid <id>          Specify Falcon Customer ID (CID)"
    echo "  --tags <tags>       Specify tags (comma separated)"
    echo "  --image <image>     Specify image"
    echo ""
    echo "Environment variables can also be used:"
    echo "  INSTALL=true|false"
    echo "  UNINSTALL=true|false"
    echo "  FALCON_CID=<id>"
    echo "  FALCON_TAGS=<tags>"
    echo "  FALCON_IMAGE=<image>"
    exit 1
}

# Override defaults with environment variables if they exist
[ "$INSTALL" = "true" ] && INSTALL=true
[ "$UNINSTALL" = "true" ] && UNINSTALL=true
[ -n "$FALCON_CID" ] && FALCON_CID="$FALCON_CID"
[ -n "$FALCON_TAGS" ] && FALCON_TAGS="$FALCON_TAGS"
[ -n "$FALCON_IMAGE" ] && FALCON_IMAGE="$FALCON_IMAGE"

# Parse command line arguments (these override environment variables)
while [ $# -gt 0 ]; do
    case $1 in
        --install)
            INSTALL=true
            shift
            ;;
        --uninstall)
            UNINSTALL=true
            shift
            ;;
        --cid)
            if [ -n "$2" ] && [ "$(echo "$2" | cut -c1)" != "-" ]; then
                FALCON_CID="$2"
                shift 2
            else
                echo "Error: --cid requires an argument"
                exit 1
            fi
            ;;
        --tags)
            if [ -n "$2" ] && [ "$(echo "$2" | cut -c1)" != "-" ]; then
                FALCON_TAGS="$2"
                shift 2
            else
                echo "Error: --tags requires an argument"
                exit 1
            fi
            ;;
        --image)
            if [ -n "$2" ] && [ "$(echo "$2" | cut -c1)" != "-" ]; then
                FALCON_IMAGE="$2"
                shift 2
            else
                echo "Error: --image requires an argument"
                exit 1
            fi
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            ;;
    esac
done

# Validate parameters
if [ "$INSTALL" = "true" ] && [ "$UNINSTALL" = "true" ]; then
    echo "Error: Cannot specify both --install and --uninstall"
    exit 1
fi

if [ "$INSTALL" = "false" ] && [ "$UNINSTALL" = "false" ]; then
    echo "Error: Must specify either --install or --uninstall"
    exit 1
fi

if [ "$INSTALL" = "true" ] && [ -z "$FALCON_CID" ]; then
    echo "Error: --cid is required for installation"
    exit 1
fi

if [ "$INSTALL" = "true" ] && [ -z "$FALCON_IMAGE" ]; then
    echo "Error: --image is required for installation"
    exit 1
fi

cs_install() {

    echo "Creating falcon.conf file"

cat << EOF > /etc/systemd/system/falcon.conf
# Configure the Falcon daemonset to run as a container.
# e.g. FALCON_CONTAINER_IMAGE=registry.crowdstrike.com/falcon-sensor/us-1/release/falcon-sensor:7.22.0-17507-1.falcon-linux.Release.US-1
FALCON_CONTAINER_IMAGE=$FALCON_IMAGE

# Configures whether the sensor runs in kernel mode or bpf
# NOTE: It is recommended to keep this set to bpf.
FALCON_BACKEND=bpf

# Configure your Falcon CID
FALCON_CID=$FALCON_CID

# Configure sensor grouping tags to be used in the Falcon console.
FALCON_TAGS="$FALCON_TAGS"
EOF

    echo "Creating falcon.service file"

cat << EOF > /etc/systemd/system/falcon.service
[Unit]
Description=Docker falcon.service
After=docker.service
Requires=docker.service

[Service]
EnvironmentFile=/etc/systemd/system/falcon.conf
TimeoutStartSec=0
Restart=always
ExecStartPre=/usr/bin/docker run --rm \\
        --privileged \\
        --pid=host \\
        --net=host \\
        --ipc=host \\
        --entrypoint /opt/CrowdStrike/falcon-daemonset-init \\
        \${FALCON_CONTAINER_IMAGE} -i
ExecStart=/usr/bin/docker run --rm --name falcon \\
        --privileged \\
        --pid=host \\
        --net=host \\
        --ipc=host \\
        --userns=host \\
        -e FALCONCTL_OPT_BACKEND=bpf \\
        -e FALCONCTL_OPT_CID=\${FALCON_CID} \\
        -e FALCONCTL_OPT_TAGS=\${FALCON_TAGS} \\
        -v /opt/CrowdStrike/falconstore:/opt/CrowdStrike/falconstore \\
        \${FALCON_CONTAINER_IMAGE}
ExecStop=/usr/bin/docker stop falcon

[Install]
WantedBy=default.target
EOF

    echo "Enabling the Falcon sensor"
    systemctl enable --now falcon
}

cs_uninstall() {
    echo "Disabling the Falcon sensor"
    systemctl disable --now falcon

    echo "Cleaning up /opt/Crowdstrike/"
    FALCON_CONTAINER_IMAGE=$(grep IMAGE /etc/systemd/system/falcon.conf | cut -d"=" -f2)
    /usr/bin/docker run --rm \
        --privileged \
        --pid=host \
        --net=host \
        --ipc=host \
        --entrypoint /opt/CrowdStrike/falcon-daemonset-init \
        $FALCON_CONTAINER_IMAGE -u
    
    echo "Removing Falcon SystemD files"
    rm -f /etc/systemd/system/falcon.*
}

main() {
    if [[ "$INSTALL" == "true" ]]; then
        cs_install
    elif [[ "$UNINSTALL" == "true" ]]; then
        cs_uninstall
    fi
}

main "@"
