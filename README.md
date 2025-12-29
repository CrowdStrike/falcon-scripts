# Falcon Scripts for Deployments

This repository is dedicated to providing scripts that assist in the installation and uninstallation of the CrowdStrike Falcon Sensor on various platforms. Our primary aim is to offer streamlined and efficient tools for setting up and removing the Falcon Sensor, ensuring a hassle-free experience for our users.

## Script Categories and Descriptions

The scripts in this repository are organized into the following categories:

| Bash | Description |
|:-|:-|
| [Containers](bash/containers) | Shell scripts for working with the CrowdStrike Falcon Container Sensor Images |
| [Install](bash/install) | Shell scripts for installing/uninstalling the CrowdStrike Falcon Sensor for Linux |
| [Migrate](bash/migrate) | Shell script to migrate Falcon sensor from one CID to another for Linux |

| PowerShell | Description |
|:-|:-|
| [Install](powershell/install) | PowerShell scripts for installing/uninstalling the CrowdStrike Falcon Sensor for Windows |
| [Migrate](powershell/migrate) | PowerShell script to migrate Falcon sensor from one CID to another for Windows |

| SystemD | Description |
|:-|:-|
| [Podman](systemd/podman) | SystemD service to start CrowdStrike Falcon Linux Sensor Container on local system using Podman |
| [Docker](systemd/docker) | SystemD service to start CrowdStrike Falcon Linux Sensor Container on local system using Docker |

## Contributing

We welcome contributions that improve the installation, uninstallation, and distribution processes of the Falcon Sensor. Please ensure that your contributions align with our coding standards and pass all CI/CD checks.

## Support

Falcon Scripts is a community-driven, open source project designed to streamline the deployment and use of the CrowdStrike Falcon sensor. While not a formal CrowdStrike product, Falcon Scripts is maintained by CrowdStrike and supported in partnership with the open source developer community.

For additional support, please see the [SUPPORT.md](SUPPORT.md) file.

## License

See [LICENSE](LICENSE)
# Test
