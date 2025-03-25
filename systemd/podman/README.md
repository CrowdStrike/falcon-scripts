# Falcon Linux SystemD Podman service

This guide explains how to configure the Falcon Sensor to run as a SystemD service using Podman in non-Kubernetes environments.

## Requirements

- Podman installed and running
- Root or sudo privileges
- A valid CrowdStrike Falcon Customer ID (CID)
- Access to the Falcon container image

## Installation Options
1. Load or pull the Falcon Sensor image to your host:
   ```bash
   podman pull myrepo.com/falcon/sensor:1234
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
