# Falcon® Contain
CrowdStrike Falcon® Contain GUI for more powerful and rapid host containment

## Background  
  
  Falcon®'s host contain action is powerful, but very limited within the Falcon® console.  This tool utilizes the CrowdStrike API to issue host containment actions based on hostname wildcards, IP ranges, defined host groups in Falcon®, or user-specified agent IDs (AID).  This tool can be useful for security operations teams needing to quickly contain groups of machines to prevent widespread infection and/or encryption of systems.

## Requirements
  1. CrowdStrike Falcon® API Client ID and Secret with query and contain/uncontain rights
  2. The Falcon® API endpoint URL for your tenant
  3. A GUI (non-Server Core) Windows install that can run PowerShell.  No additional PowerShell modules or libraries are required.
  4. FalconContain.ps1 from this repository  
  5. Familiarity with the Falcon® Query Lancuage (FQL) if you intend to contain/uncontain hosts in this manner

### List of Falcon® API endpoints as of May 2023  
  - **US-1:**	api.crowdstrike.com (default)  
  - **US-2:**	api.us-2.crowdstrike.com  
  - **EU-1:**	api.eu-1.crowdstrike.com  
  - **US Government 1:** api.laggar.gcw.crowdstrike.com  

## Setup
  1. Download the latest release .ZIP file.
  2. Right-click the downloaded file, click Properties, and click "Unblock"
  3. Extract the .ZIP to a single directory.
  4. Run FalconContain.ps1. If a configuration file is not found in the current directory, you will be prompted for these details:  
    - Falcon API Endpoint URL (default is api.crowdstrike.com)  
    - Falcon API ClientID  
    - Falcon API Secret
  5. (Optional) Edit ProtectedAIDs.txt after the first run and add Falcon AIDs (one per line) for hosts like core DHCP, DNS, and perhaps a domain controller.  Comments can be added on the same line as each AID entry.  These are protected endpoints that will not be affected by contain/uncontain actions, even if they are returned in the results of a query.  Note, the entries must be Falcon AIDs, not host names, so should look like this:  
  ```443864e5193bd38ca6fcd81067ab331b```

## Running Falcon® Contain
  1. Execute the FalconContain.ps1 script  
    - Contain / un-contain via AID requires the user to first look up the AIDs of hosts in the Falcon console  
    - Contain / un-contain via FQL allows more flexible queries of hosts, with a selectable maximum affected hosts value  
    - Contain / un-contain via Host Groups allows the user to simply select a Falcon host group (these are configured in the Falcon console)  

## Troubleshooting
  - The configuration file cannot be read.
    - The configuration file includes encrypted API details.  The file is not portable between users/computers.  Simply delete FalconContain-Config.xml and run FalconContain.ps1 to build a new configuration file.
  - A log of all session actions is saved in the working directory as FalconContainerMMddyy-HHmmss.log  
  - More info about the Falcon Query Language can be found here (login required): https://falcon.crowdstrike.com/documentation/45/falcon-query-language-fql  
