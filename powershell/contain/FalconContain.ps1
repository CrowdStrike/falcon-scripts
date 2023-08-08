<#
.NAME
    Falcon® Contain
#>

if ([System.Environment]::OSVersion.Platform -ne 'Win32NT'){
  Write-Output "Sorry, Falcon Contain is only intended for the Windows operating system."
  Exit
}

# API connection ID and secret encrypted with the Windows Data Protection API.
###### NOTE: Encrypted config file is not portable between users/machines. ######
$ConfigFile = 'FalconContain-Config.xml'

# The host AIDs in the Protected AIDs file will never be contained/lifted, even if in a selected Host Group or a result from a host query.
# Contain/lift by AID will STILL be allowed for these hosts though.
$AIDFile = 'ProtectedAIDs.txt'
$DefaultAPIURL = 'api.crowdstrike.com'

#Configure logging
$LaunchDTS = (Get-Date).ToString("MMddyy-HHmmss")
$LogPath = "FalconContain" + $LaunchDTS + ".log"
Start-Transcript -Path $LogPath

# Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# If the ProtectedAID config file does not exist, create an empty file
if (-not(Test-Path -Path $AIDFile -PathType Leaf)){New-Item -Name $AIDFile -ItemType File}

# If the config file does not exist, prompt for details and write the file.
if (-not(Test-Path -Path $ConfigFile -PathType Leaf)){
    $APIURL=Read-Host -Prompt "Enter Falcon API Endpoint URL.  Press enter to accept the default of [$($DefaultAPIURL)]"
    if ($APIURL.Length -eq 0) {$APIURL = $DefaultAPIURL}
    $apiUserSS=Read-Host -Prompt 'Enter Falcon API ClientID' -AsSecureString
    $apiKeySS=Read-Host -Prompt 'Enter Falcon API Secret' -AsSecureString

    # Convert the input values to encrypted text
    $apiUserTxt = ConvertFrom-SecureString -SecureString $apiUserSS
    $apiKeyTxt = ConvertFrom-SecureString -SecureString $apiKeySS

    # Save the encrypted values and signature to an XML file
    $xml = New-Object System.Xml.XmlDocument
    $xml.AppendChild($xml.CreateXmlDeclaration("1.0", "UTF-8", $null))
    $root = $xml.AppendChild($xml.CreateElement("APIDetails"))
    $root.AppendChild($xml.CreateElement("apiURL")).InnerText = $APIURL
    $root.AppendChild($xml.CreateElement("apiUser")).InnerText = $apiUserTxt
    $root.AppendChild($xml.CreateElement("apiKey")).InnerText = $apiKeyTxt
    $xml.Save($ConfigFile)
    }
else { # Config file exists, read API details from config.
    # Load the XML file
    $xml = New-Object System.Xml.XmlDocument
    $xml.Load($ConfigFile)
    $APIConfig = $xml.SelectSingleNode("//APIDetails")

    # Get API details
    $APIURL = $APIConfig.SelectSingleNode("apiURL").InnerText
    $apiUserTxt = $APIConfig.SelectSingleNode("apiUser").InnerText
    $apiKeyTxt = $APIConfig.SelectSingleNode("apiKey").InnerText

    # Convert the API info to secure strings
    $apiUserSS = ConvertTo-SecureString $apiUserTxt
    $apiKeySS = ConvertTo-SecureString $apiKeyTxt
    }

function QueryGroups() # All this does is ask Falcon for the latest Host Group list for GUI dropdown display
{

$TokenRequestHeaders = @{
  'accept' = 'application/json'
  'Content-Type' = 'application/x-www-form-urlencoded'
  }

$FormData = @{
  'client_id' = [pscredential]::new('user',$apiUserSS).GetNetworkCredential().Password
  'client_secret' = [pscredential]::new('user',$apiKeySS).GetNetworkCredential().Password
  }

$PostRequest = 'https://' + $APIURL + '/oauth2/token'
$ValidToken = Invoke-RestMethod -Uri $PostRequest -Method 'Post' -Body $FormData -Headers $TokenRequestHeaders | Select-Object access_token
$FormData = $null
[System.GC]::Collect()

if ($ValidToken)
    {
      $AuthString = 'Bearer ' + $ValidToken.access_token
      $DownloadRequestHeaders = @{
      'Content-Type' = 'application/json'
      'Authorization' = $AuthString
      }
    $GetRequest = 'https://' + $APIURL + '/devices/combined/host-groups/v1'
    $GetResponse = Invoke-RestMethod -Uri $GetRequest -Method 'Get' -ContentType 'application/json;charset=utf-8' -Headers $DownloadRequestHeaders
    return $GetResponse # Return the current list of Host Groups
    }
else # We were not able to establish a connection to the API, so bail out of this session.
    {
    Write-Output "****************************************************************"
    Write-Output "Connection to the CrowdStrike API failed.  Verify your API credentials, permission, and network access to the API endpoint."
    exit
    }
} # End QueryGroups

Write-Output "****************************************************************"
Write-Output "Fetching latest Falcon host groups..."

$GroupList = QueryGroups # Call function to get and return an object with the current list of Falcon Host Groups

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

#Form Window
$Form                            = New-Object system.Windows.Forms.Form
$Form.ClientSize                 = New-Object System.Drawing.Point(725,525)
$Form.text                       = "Falcon Contain 1.1.5 August 7 2023"
$Form.TopMost                    = $false

#AID form entry field
$HostLst                        = New-Object system.Windows.Forms.TextBox
$HostLst.multiline              = $false
$HostLst.text                   = "Format: `"aid1`",`"aid2`",`"aid3`""
$HostLst.width                  = 411
$HostLst.height                 = 20
$HostLst.location               = New-Object System.Drawing.Point(109,41)
$HostLst.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
$HostLst.ForeColor              = [System.Drawing.ColorTranslator]::FromHtml("#9b9b9b")

#AID form entry field label
$AidLabel                       = New-Object system.Windows.Forms.Label
$AidLabel.text                  = "Target AID(s):"
$AidLabel.AutoSize              = $true
$AidLabel.width                 = 25
$AidLabel.height                = 10
$AidLabel.location              = New-Object System.Drawing.Point(17,44)
$AidLabel.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

#AID form entry field contain button
$SpecifyContain                  = New-Object system.Windows.Forms.Button
$SpecifyContain.text             = "Contain"
$SpecifyContain.width            = 60
$SpecifyContain.height           = 30
$SpecifyContain.location         = New-Object System.Drawing.Point(640,38)
$SpecifyContain.Font             = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

#AID form entry field lift contain button
$SpecifyLiftContain              = New-Object system.Windows.Forms.Button
$SpecifyLiftContain.text         = "Lift"
$SpecifyLiftContain.width        = 60
$SpecifyLiftContain.height       = 30
$SpecifyLiftContain.location     = New-Object System.Drawing.Point(560,38)
$SpecifyLiftContain.Font         = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

#Falcon query language (host) form entry field
$HostQuery                        = New-Object system.Windows.Forms.TextBox
$HostQuery.multiline              = $false
$HostQuery.text                   = "Enter Query"
$HostQuery.width                  = 356 #411
$HostQuery.height                 = 20
$HostQuery.location               = New-Object System.Drawing.Point(109,131)
$HostQuery.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
$HostQuery.ForeColor              = [System.Drawing.ColorTranslator]::FromHtml("#9b9b9b")

#Falcon query language max affected records setting
$HostQueryLimit                        = New-Object system.Windows.Forms.TextBox
$HostQueryLimit.multiline              = $false
$HostQueryLimit.text                   = "1"
$HostQueryLimit.width                  = 40
$HostQueryLimit.height                 = 20
$HostQueryLimit.location               = New-Object System.Drawing.Point(500,131)
$HostQueryLimit.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

#Falcon query language (host) form entry field label
$HostLabel                       = New-Object system.Windows.Forms.Label
$HostLabel.text                  = "Target host(s):"
$HostLabel.AutoSize              = $true
$HostLabel.width                 = 25
$HostLabel.height                = 10
$HostLabel.location              = New-Object System.Drawing.Point(17,134)
$HostLabel.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

#Falcon query language (host) max affected records field label
$HostLimitLabel                       = New-Object system.Windows.Forms.Label
$HostLimitLabel.text                  = "MAX:"
$HostLimitLabel.AutoSize              = $true
$HostLimitLabel.width                 = 25
$HostLimitLabel.height                = 10
$HostLimitLabel.location              = New-Object System.Drawing.Point(465,134)
$HostLimitLabel.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

#Falcon query language (host) form entry field example 1
$HostHelp0                       = New-Object system.Windows.Forms.Label
$HostHelp0.text                  = "Search by host name ex: hostname:'CA-ONT-D-2*'"
$HostHelp0.AutoSize              = $true
$HostHelp0.width                 = 411
$HostHelp0.height                = 20
$HostHelp0.location              = New-Object System.Drawing.Point(109,160)
$HostHelp0.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

#Falcon query language (host) form entry field example 2
$HostHelp1                       = New-Object system.Windows.Forms.Label
$HostHelp1.text                  = "Search by host name ex: hostname:'HQ-DC-0*'"
$HostHelp1.AutoSize              = $true
$HostHelp1.width                 = 411
$HostHelp1.height                = 20
$HostHelp1.location              = New-Object System.Drawing.Point(109,180)
$HostHelp1.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

#Falcon query language (host) form entry field example 3
$HostHelp2                       = New-Object system.Windows.Forms.Label
$HostHelp2.text                  = "Search by IP ex: local_ip:'10.20.3.0/24'+external_ip:'4.4.0.0/16'"
$HostHelp2.AutoSize              = $true
$HostHelp2.width                 = 411
$HostHelp2.height                = 20
$HostHelp2.location              = New-Object System.Drawing.Point(109,200)
$HostHelp2.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

#Falcon query language contain button
$SpecifyContain1                  = New-Object system.Windows.Forms.Button
$SpecifyContain1.text             = "Contain"
$SpecifyContain1.width            = 60
$SpecifyContain1.height           = 30
$SpecifyContain1.location         = New-Object System.Drawing.Point(640,128)
$SpecifyContain1.Font             = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

#Falcon query language lift containment button
$SpecifyLiftContain1              = New-Object system.Windows.Forms.Button
$SpecifyLiftContain1.text         = "Lift"
$SpecifyLiftContain1.width        = 60
$SpecifyLiftContain1.height       = 30
$SpecifyLiftContain1.location     = New-Object System.Drawing.Point(560,128)
$SpecifyLiftContain1.Font         = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

#Host Group selection combobox label
$GroupLabel                      = New-Object System.Windows.Forms.Label
$GroupLabel.text                  = "Target group:"
$GroupLabel.AutoSize              = $true
$GroupLabel.width                 = 25
$GroupLabel.height                = 10
$GroupLabel.location              = New-Object System.Drawing.Point(17,234)
$GroupLabel.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

#Host Group selection combobox
$GroupSelect                      = New-Object System.Windows.Forms.ComboBox
$GroupSelect.MaxDropDownItems     = 6
ForEach ($name in $GroupList.resources)
  {
  $GroupSelect.Items.Add($name.name)
  }
$GroupSelect.width                = 411
$GroupSelect.height               = 20
$GroupSelect.location             = New-Object System.Drawing.Point(109,231)
$GroupSelect.Font                 = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

#Host Group selection contain button
$SpecifyContain2                  = New-Object system.Windows.Forms.Button
$SpecifyContain2.text             = "Contain"
$SpecifyContain2.width            = 60
$SpecifyContain2.height           = 30
$SpecifyContain2.location         = New-Object System.Drawing.Point(640,228)
$SpecifyContain2.Font             = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

#Host Group selection lift containment button
$SpecifyLiftContain2              = New-Object system.Windows.Forms.Button
$SpecifyLiftContain2.text         = "Lift"
$SpecifyLiftContain2.width        = 60
$SpecifyLiftContain2.height       = 30
$SpecifyLiftContain2.location     = New-Object System.Drawing.Point(560,228)
$SpecifyLiftContain2.Font         = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

#Hint regarding log file output at bottom of form
$SafetyInfo                         = New-Object system.Windows.Forms.Label
$SafetyInfo.text                  = "NOTE: Protected hosts (in ProtectedAIDs.txt) can only be contained/lifted using the Target AIDs dialog."
$SafetyInfo.AutoSize              = $true
$SafetyInfo.width                 = 650
$SafetyInfo.height                = 20
$SafetyInfo.location              = New-Object System.Drawing.Point(30,10)
$SafetyInfo.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
$SafetyInfo.ForeColor              = [System.Drawing.ColorTranslator]::FromHtml("#ff0000")

#Hint regarding log file output at bottom of form
$LogInfo                         = New-Object system.Windows.Forms.Label
$LogInfo.text                  = "Log of all session actions saved in working directory as FalconContainerMMddyy-HHmmss.log"
$LogInfo.AutoSize              = $true
$LogInfo.width                 = 650
$LogInfo.height                = 20
$LogInfo.location              = New-Object System.Drawing.Point(17,500)
$LogInfo.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

#Add all the controls to the form
$Form.controls.AddRange(@($HostLst,$AidLabel,$SpecifyContain,$SpecifyLiftContain,$HostQuery,$HostQueryLimit,$HostLabel,$HostLimitLabel,$HostHelp0,$HostHelp1,$HostHelp2,$SpecifyContain1,$SpecifyLiftContain1,$GroupLabel,$GroupSelect,$SpecifyContain2,$SpecifyLiftContain2,$SafetyInfo,$LogInfo))

#AID function calls (button actions)
$SpecifyLiftContain.Add_Click({ AIDs $HostLst "lift_containment" })
$SpecifyContain.Add_Click({ AIDs $HostLst "contain" })

#FQL function calls (button actions)
$SpecifyLiftContain1.Add_Click({ Hosts $HostQuery $HostQueryLimit "lift_containment" })
$SpecifyContain1.Add_Click({ Hosts $HostQuery $HostQueryLimit "contain" })

#Group selection function calls (button actions)
$SpecifyLiftContain2.Add_Click({ Groups $GroupSelect "lift_containment" })
$SpecifyContain2.Add_Click({ Groups $GroupSelect "contain" })

#region Logic

function AIDs ($Payload,$HostAction) # This function BLINDLY takes the user's input and passes it to the API for AID contain/lift contain actions
{
if(!$Payload.text -Or ($Payload.text -Eq "Format: `"aid1`",`"aid2`",`"aid3`""))
  {
  Write-Output "+++***=== NO AIDs SPECIFIED.  CANCELLING ACTION ===***+++"
  return #NO AIDs ENTERED!
  }

$CommandDetails = "==>ACTION:" + $HostAction + "  ON AIDs: " + $Payload.text

Write-Output "****************************************************************"
Write-Output $CommandDetails

$TokenRequestHeaders = @{
  'accept' = 'application/json'
  'Content-Type' = 'application/x-www-form-urlencoded'
  }

$FormData = @{
  'client_id' = [pscredential]::new('user',$apiUserSS).GetNetworkCredential().Password
  'client_secret' = [pscredential]::new('user',$apiKeySS).GetNetworkCredential().Password
  }

$PostRequest = 'https://' + $APIURL + '/oauth2/token'
$ValidToken = Invoke-RestMethod -Uri $PostRequest -Method 'Post' -Body $FormData -Headers $TokenRequestHeaders | Select-Object access_token
$FormData = $null
[System.GC]::Collect()

if ($ValidToken)
    {
      $AuthString = 'Bearer ' + $ValidToken.access_token

      $DownloadRequestHeaders = @{
      'Content-Type' = 'application/json'
      'Authorization' = $AuthString
      }
    $RequestBody = '{
    "ids": ['+
    $Payload.text+'
    ]
    }'
    $PostAction = 'https://' + $APIURL + '/devices/entities/devices-actions/v2?action_name=' + $HostAction
    Invoke-RestMethod -Uri $PostAction -Method 'Post' -Headers $DownloadRequestHeaders -Body $RequestBody
    }
} # End function AIDs

function Hosts ($Query,$QueryLimit,$HostAction) # This function verifies the query is not empty, then passes it to the API as a Falcon Query contain/lift contain action.
{
if(!$Query.text -Or ($Query.text -Eq "Enter Query"))
{
Write-Output "+++***=== NO QUERY SPECIFIED.  CANCELLING ACTION ===***+++"
return #NO QUERY ENTERED!
}
$CommandDetails = "==>ACTION:" + $HostAction + "  ON: " + $Query.text + " (MAX RECORDS: " + $QueryLimit.text + ")"

Write-Output "*****************************************************************"
Write-Output $CommandDetails

$TokenRequestHeaders = @{
  'accept' = 'application/json'
  'Content-Type' = 'application/x-www-form-urlencoded'
  }

$FormData = @{
  'client_id' = [pscredential]::new('user',$apiUserSS).GetNetworkCredential().Password
  'client_secret' = [pscredential]::new('user',$apiKeySS).GetNetworkCredential().Password
  }

$PostRequest = 'https://' + $APIURL + '/oauth2/token'
$ValidToken = Invoke-RestMethod -Uri $PostRequest -Method 'Post' -Body $FormData -Headers $TokenRequestHeaders | Select-Object access_token
$FormData = $null
[System.GC]::Collect()

if ($ValidToken)
    {
      $AuthString = 'Bearer ' + $ValidToken.access_token

      $DownloadRequestHeaders = @{
      'Content-Type' = 'application/json'
      'Authorization' = $AuthString
      }
    $GetRequest = 'https://' + $APIURL + '/devices/queries/devices/v1?limit=' + $QueryLimit.text + '&filter=' + $Query.text
    $GetResponse = Invoke-RestMethod -Uri $GetRequest -Method 'Get' -ContentType 'application/json;charset=utf-8' -Headers $DownloadRequestHeaders
    ForEach ($resource in $GetResponse.resources)
      {
        if (-not(Select-String -Pattern $resource -Path $AIDFile -Quiet))
          {
          $HostList += "`"$resource`""
          $HostList += ","
          }
      }
    if(!$HostList)
    {
    Write-Output "+++***=== NO VALID MATCHING RECORDS.  CANCELLING ACTION ===***+++"
    return # No resulting records!
    }
    $HostList = $HostList.Substring(0,$HostList.Length-1)
    $AffectedMachines = "==>AFFECTED HOSTS: " + $HostList
    Write-Output $AffectedMachines
    $RequestBody = '{
    "ids": ['+
    $HostList+'
    ]
    }'
    $PostAction = 'https://' + $APIURL + '/devices/entities/devices-actions/v2?action_name=' + $HostAction
    Invoke-RestMethod -Uri $PostAction -Method 'Post' -Headers $DownloadRequestHeaders -Body $RequestBody
    }
} # End function Hosts

function Groups ($Group,$HostAction) # This function takes the selected Host Group name, performs a group member search, then passes result to the API as an AID contain/lift contain action.
{
if(!$Group.text)
{
Write-Output "+++***=== NO GROUP SELECTED.  CANCELLING ACTION ===***+++"
return #NO GROUP SELECTED!
}

$CommandDetails = "==>ACTION:" + $HostAction + "  ON GROUP: " + $Group.text

Write-Output "****************************************************************"
Write-Output $CommandDetails

$TokenRequestHeaders = @{
  'accept' = 'application/json'
  'Content-Type' = 'application/x-www-form-urlencoded'
  }

$FormData = @{
  'client_id' = [pscredential]::new('user',$apiUserSS).GetNetworkCredential().Password
  'client_secret' = [pscredential]::new('user',$apiKeySS).GetNetworkCredential().Password
  }

$PostRequest = 'https://' + $APIURL + '/oauth2/token'
$ValidToken = Invoke-RestMethod -Uri $PostRequest -Method 'Post' -Body $FormData -Headers $TokenRequestHeaders | Select-Object access_token
$FormData = $null
[System.GC]::Collect()

if ($ValidToken)
    {
      $AuthString = 'Bearer ' + $ValidToken.access_token

      $DownloadRequestHeaders = @{
      'Content-Type' = 'application/json'
      'Authorization' = $AuthString
      }

ForEach ($name in $GroupList.resources)
  {
  if($name.name -Eq $Group.text)
    {
    $GroupID = $name.id
    }
  }
    $GetRequest = 'https://' + $APIURL + '/devices/combined/host-group-members/v1?id=' + $GroupID
    $GetResponse = Invoke-RestMethod -Uri $GetRequest -Method 'Get' -ContentType 'application/json;charset=utf-8' -Headers $DownloadRequestHeaders
    ForEach ($resource in $GetResponse.resources)
      {
      $IDString = $resource.device_id
      if (-not(Select-String -Pattern $IDString -Path $AIDFile -Quiet))
          {
          $HostList1 += "`"$IDString`""
          $HostList1 += ","
          }
      }
    if(!$HostList1)
      {
      Write-Output "+++***=== NO VALID MATCHING RECORDS.  CANCELLING ACTION ===***+++"
      return # No resulting records!
      }
    $HostList1 = $HostList1.Substring(0,$HostList1.Length-1)
    $AffectedMachines = "==>AFFECTED HOSTS: " + $HostList1
    Write-Output $AffectedMachines
    $RequestBody = '{
    "ids": ['+
    $HostList1+'
    ]
    }'
    $PostAction = 'https://' + $APIURL + '/devices/entities/devices-actions/v2?action_name=' + $HostAction
    Invoke-RestMethod -Uri $PostAction -Method 'Post' -Headers $DownloadRequestHeaders -Body $RequestBody
    }
} # End function Groups
#endregion

#Launch form
Write-Output "****************************************************************"
Write-Output "Launching GUI..."
[void]$Form.ShowDialog()

#End logging
Stop-Transcript

# Clear $FormData variable before closing and run garbage collection again, just to be sure
$FormData = $null
[System.GC]::Collect()
