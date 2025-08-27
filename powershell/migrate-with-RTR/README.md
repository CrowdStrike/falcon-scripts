# Migrating CrowdStrike Endpoints With RTR Script

This document outlines a method for migrating CrowdStrike Falcon endpoints from one tenant to another when no Mobile Device Management (MDM) solution is available. This approach leverages Real-Time Response (RTR) to execute a detached process that survives the sensor's uninstallation.

## The Issue

The migration process involves two key steps: uninstalling the old sensor and then installing the new one. Running the `falcon_windows_migrate.ps1` script directly from an RTR session would cause the session to terminate the moment the old sensor was uninstalled. This meant the second half of the script—installing the new sensor—would never run.

## The Solution

The solution is to wrap the migration PowerShell script in a batch file. This batch file uses the `start powershell.exe` command to launch the migration script as a new, detached process. This is crucial because a detached process is independent of its parent process (the RTR session) and will continue to run even after the parent terminates.

> **Note:** The `start` command ensures the PowerShell script runs in the background and is not affected when the original RTR session disconnects.

## Deployment

Here is the step-by-step deployment process using the available RTR tool:

1.  **Update Credentials:** First, ensure the migration script's credentials are correct for the new tenant.
2.  **Push the Batch File:** Use the `put` command in the RTR session to transfer the batch file onto the target endpoint.
    ```bash
    put crowdstrike-migration.bat
    ```
3.  **Run the Script:** Execute the batch file from the RTR session. This will spawn the PowerShell script in the background.
    ```bash
    run C:\crowdstrike-migration.bat
    ```
    At this point, the RTR session will disconnect as the old sensor uninstalls, but the migration process will continue to run in the background, completing the installation of the new sensor.

## Automation via SOAR

For a more scalable and hands-off approach, this process can be automated using Fusion SOAR workflows.

* **Cloud Storage:** Push the `crowdstrike-migration.bat` file to CrowdStrike's cloud storage.
* **Automate with SOAR:** Configure a SOAR workflow to automatically issue the `put` and `run` commands whenever a new host checks in.

This automation eliminates the need for manual intervention, ensuring that the migration happens automatically as new hosts come online.
