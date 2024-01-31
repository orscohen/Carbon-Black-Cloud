#************************************************	
#| Script Configuration:                        |
#| -------------------------------------------  |
#|                                              |
# Define configuration variables

# To grant these privileges to your API key, you can use the following steps:
# 
# Go to the Carbon Black Cloud console and navigate to Settings > API Access.
# Click the Manage Access Levels tab.
# Select the access level that you want to grant these privileges to.
# Click the Edit button.
# Under the API Privileges section, select the following privileges:
# - Read-only access to the kits endpoint
# - Write-only access to the downloads endpoint
# Click the Save button.
# API Secret for Carbon Black- New tenant 
$api_key = "your-api-Secret-here"

# API ID for Carbon Black- New tenant 
$api_id = "your-api-id-here"

# Organization ID for Carbon Black- New tenant 
$org_id = "your-org-id-here"

# Base URL for downloads (changeable) - New tenant 
$baseUrl = "https://defense-prod05.conferdeploy.net"

#Company Code for installation - New tenant 
$COMPANY_CODE = "COMPANY_CODE=********"

# Uninstall Key - old tenent
$uninstallPassword = '*************'

# Old Tenant ID - Can be checked in file $Env:Programdata\CarbonBlack\DataFiles\cfg.ini 
# in RegistrationId=XXXXX-YYYYY | Please use XXXXX Number  - without the YYYYY
$tenantId = "***********"
#*****************************************************************************************************************************

# Check if Carbon Black is installed
$cbProductName = 'Carbon Black Cloud Sensor 64-bit'
$cbInstalled = (Get-WmiObject -Class Win32_Product -Filter "Name='$cbProductName'") -ne $null

if ($cbInstalled) {
    Write-Host "Carbon Black is installed."

    # Get the contents of the text file
    $cfgIniContents = Get-Content -Path "$Env:Programdata\CarbonBlack\DataFiles\cfg.ini"

    # Define the pattern to match with a variable for the tenant
    $pattern = "RegistrationId=$tenantId-\d+"

    if ($cfgIniContents -match $pattern) {
        # A line matching the pattern was found
        Write-Host "Pattern found: $($matches[0])"
        Write-Host "Uninstalling Carbon Black."

        $cbInstallPath = "$Env:Programfiles\Confer"
        $uninstallExe = ".\Uninstall.exe"
        $bypassArg = "/bypass 1"
        $uninstallArg = "/uninstall"

        Invoke-Expression "$cbInstallPath\$uninstallExe $bypassArg $uninstallPassword"
        Invoke-Expression "$cbInstallPath\$uninstallExe $uninstallArg $uninstallPassword"
    } else {
        # Pattern not found
        Write-Host "Pattern not found"
        Write-Host "CB is installed with another tenant."
    }
} else {
    Write-Host "Carbon Black is not installed. Installing it with the new tenant."

    # Point to file repository where files will be checked/downloaded
    $softwareRepo = "c:\Windows\temp"

    # One-time pull request from site. Future variables will be built off this data
    $rssFeed = Invoke-WebRequest -Uri "https://docs.vmware.com/en/VMware-Carbon-Black-Cloud/rn_rss.xml" -UseBasicParsing

    # Grab first mention of Carbon Black Windows sensor from RSS feed, then extract version number
    $CBVersion = $rssFeed.Content
    $CBVersion = $CBVersion.Substring($CBVersion.IndexOf('VMware Carbon Black Cloud Windows Sensor'))
    $CBVersion = $CBVersion.Substring(0, $CBVersion.IndexOf(' Release Notes'))
  

    # Create filenames with the current tenant ID and version
    $CBFilenamex64 = "installer_vista_win7_win8-64-$tenantId-$CBVersion.msi"

    # Define the full download URL
    $downloadUrl = "$baseUrl/appservices/v5/orgs/$org_id/kits/$CBFilenamex64"

    # Variables needed to download from Carbon Black with API call
    $headers = @{"X-Auth-Token" = "$api_key/$api_id"}

    if (-Not (Test-Path -Path "$softwareRepo\$CBFilenamex64")) {
        Invoke-WebRequest -Uri $downloadUrl -Headers $headers -OutFile "$softwareRepo\$CBFilenamex64"
        msiexec /qn /i "$softwareRepo\$CBFilenamex64" /L*vx "$softwareRepo\CB_log_install.txt" $COMPANY_CODE
        Write-Host "Installed: $softwareRepo\$CBFilenamex64"
    }
}
