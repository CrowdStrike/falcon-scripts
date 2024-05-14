# Falcon Container Sensor Pull Script Deprecations

The following deprecations will be introduced in version 2.0.0 of the Falcon Container Sensor Pull Script:

1. **Default Sensor Type Change** : The default sensor type will be changed from `falcon-container` to `falcon-sensor`. This change is based off of feedback from our customers and is intended to simplify the usage of this script.

1. **Environment Variable Deprecation** : The `SENSORTYPE` environment variable will be deprecated and replaced by `SENSOR_TYPE`. This update is intended to increase readability and maintain consistency in our environment variable naming convention.

1. **Command Option Deprecation** : The command line options `-n, --node`, `--kubernetes-admission-controller`, and `--kubernetes-protection-agent` will be deprecated and replaced by a single option `-t, --type`. The new `-t, --type` option will allow you to specify the sensor type in a more straightforward and simplified manner.

While these changes will be officially introduced in version 2.0.0, we will continue to support the deprecated environment variable and command options until that release. We strongly encourage you to adapt your usage to include the new `SENSOR_TYPE` environment variable and `-t, --type` command option to ensure a smooth transition when version 2.0.0 is released.

Please refer to the updated usage instructions and examples in the [Usage](README.md#usage) section of this README. Feel free to reach out with any questions or concerns.
