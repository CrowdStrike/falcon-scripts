#!/bin/bash
 
# Step 1 : Get Sensor Download API credentials
#          create here a sensor download api creds : https://falcon.eu-1.crowdstrike.com/support/api-clients-and-keys
 
# before running the script set the API Creds in env or uncomment and fill below
#export CS_API_CLIENT_ID="XXXXXXX"
#export CS_API_CLIENT_SECRET="YYYYYYYYY"
 
target_cloud_api="api.crowdstrike.com"
# Possible values:
# US-GOV-1: api.laggar.gcw.crowdstrike.com
# EU-1: api.eu-1.crowdstrike.com
# US-2: api.us-2.crowdstrike.com
 
target_os="Ubuntu"
# Possible values:
# "Debian"
# "SLES"
# "RHEL/CentOS/Oracle"
# "Amazon Linux"
# "Debian"
# "Ubuntu"
# "RHEL/CentOS/Oracle"
 
# where to store the sensor file (by default same directory) [don't forget to add a / at the end of the path ]
target_path=""
 
# authenticate
crowdstrike_oauth2_token=$(curl --request POST \
  --silent \
  --url "https://$target_cloud_api/oauth2/token" \
  --header "content-type: application/x-www-form-urlencoded" \
  --data client_id=$CS_API_CLIENT_ID \
  --data client_secret=$CS_API_CLIENT_SECRET | \
    python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")
 
# find the target CID based on download credentials
target_cid=$(curl --request GET \
  --silent \
  --url "https://$target_cloud_api/sensors/queries/installers/ccid/v1" \
  --header "authorization: Bearer $crowdstrike_oauth2_token" \
  --header "Content-Type: application/json" | \
    python3 -c "import sys, json; print(json.load(sys.stdin)['resources'][0])")
 
echo "Target CID: $target_cid"
 
latest_sensor_version_sha256=$(curl --request GET \
  --silent \
  --url "https://$target_cloud_api/sensors/combined/installers/v1?filter=platform%3A%22linux*%22%2Bos%3A%22$target_os%22&=&sort=version.desc&limit=1" \
  --header "authorization: Bearer $crowdstrike_oauth2_token" | \
    python3 -c "import sys, json; print(json.load(sys.stdin)['resources'][0]['sha256'])")
echo "Latest version: $latest_sensor_version_sha256"
 
# Get infos on the latest sensor version
latest_sensor_version_infos=$(curl --request GET \
  --silent \
  --url "https://$target_cloud_api/sensors/combined/installers/v1?filter=platform%3A%22linux*%22%2Bos%3A%22$target_os%22&=&sort=version.desc&limit=1" \
  --header "authorization: Bearer $crowdstrike_oauth2_token")
 
# extract info from the JSON
latest_sha256=$(echo $latest_sensor_version_infos | python3 -c "import sys, json; print(json.load(sys.stdin)['resources'][0]['sha256'])")
latest_name=$(echo $latest_sensor_version_infos | python3 -c "import sys, json; print(json.load(sys.stdin)['resources'][0]['name'])")
 
echo "Download the latest version : $latest_description"
echo "Save it to : $target_path$latest_name"
curl --request GET \
  --url "https://$target_cloud_api/sensors/entities/download-installer/v1?id=$latest_sensor_version_sha256" \
  --header "authorization: Bearer $crowdstrike_oauth2_token" \
  --output "$target_path$latest_name"
 
 
# If you need to run the installer
# 
# Ubuntu: sudo dpkg -i <installer_filename>
# RHEL, CentOS, Amazon Linux: sudo yum install <installer_filename>
# SLES: sudo zypper install <installer_filename>
 
# Configure the CID
# All OSes: sudo /opt/CrowdStrike/falconctl -s --cid=$target_cid
 
# start the sensor
# Hosts with SysVinit: service falcon-sensor start
# Hosts with Systemd: systemctl start falcon-sensor
 
# Confirm the sensor is running.
# All OSes: ps -e | grep falcon-sensor
