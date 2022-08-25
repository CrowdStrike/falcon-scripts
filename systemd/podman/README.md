# Falcon Linux SystemD Podman service

## Configuration

1. Replace the following in the `falcon.service` file:
   - `<CID>` with your CrowdStrike Falcon Customer ID
   - `<falcon-sensor-container-image>` with the repository/name:tag of the sensor e.g. myrepo.com/falcon/sensor:1234 (use `localhost` for the repository if the sensor was loaded locally)

2. Load or pull the sensor to the host

3. Install the `falcon.service` file:
   ```bash
   # cp falcon.service /etc/systemd/system
   ```

4. Enable the Falcon service
   ```bash
   systemctl enable --now falcon.service
   ```
