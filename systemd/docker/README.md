# Falcon Linux SystemD Docker Service

This guide explains how to configure the Falcon Sensor to run as a SystemD service using Docker in non-Kubernetes environments.

## Requirements

- Docker installed and running
- Root or sudo privileges
- A valid CrowdStrike Falcon Customer ID (CID)
- Access to the Falcon container image

## Installation Options

### Option 1: Using the Automated Install Script

The `systemd_docker_installer.sh` script simplifies installation and configuration:

1. Load or pull the Falcon Sensor image to your host:
   ```bash
   docker pull myrepo.com/falcon/sensor:1234
   ```

2. Run the installer with your specific parameters:
   ```bash
   systemd_docker_installer.sh --install \
     --image myrepo.com/falcon/sensor:1234 \
     --cid ABCDEFabcdef012345-12 \
     --tags systemd,production
   ```

To uninstall later:
```bash
systemd_docker_installer.sh --uninstall
```

### Option 2: Manual Installation

1. Load or pull the Falcon Sensor image to your host:
   ```bash
   docker pull myrepo.com/falcon/sensor:1234
   ```

2. Update the `falcon.conf` configuration file your settings. e.g.:
   ```
   FALCON_CONTAINER_IMAGE=myrepo.com/falcon/sensor:1234
   FALCON_CID=ABCDEFabcdef012345-12
   FALCON_TAGS=systemd,production
   ```

3. Copy the `falcon.conf` and `falcon.service` files to `/etc/systemd/system`:
   ```bash
   cp falcon.* /etc/systemd/system
   ```

4. Enable and start the Falcon service:
   ```bash
   systemctl enable --now falcon.service
   ```