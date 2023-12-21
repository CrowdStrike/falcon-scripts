#!/bin/bash

print_usage() {
    cat <<EOF
This script removes the CrowdStrike Falcon Sensor for Linux from the operating system.

EOF
}

main() {
    if [ -n "$1" ]; then
        print_usage
        exit 1
    fi
    echo -n 'Removing Falcon Sensor  ... '
    cs_sensor_remove
    echo '[ Ok ]'
    echo 'Falcon Sensor removed successfully.'
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
            DEBIAN_FRONTEND=noninteractive apt purge -y "$pkg" >/dev/null
        else
            rpm -e --nodeps "$pkg"
        fi
    }

    remove_package "falcon-sensor"
}

main "$@"
