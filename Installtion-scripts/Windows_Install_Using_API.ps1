# Point to file repositories where the files will be checked/downloaded
$softwareRepo = "C:\Windows\temp"
# Base URL for Carbon Black deployment
$carbonBlackBaseUrl = "https://defense-prod05.conferdeploy.net"
# Company Code from CB
$COMPANY_CODE = "COMPANY_CODE=********"
# Variables needed to download from Carbon Black with API call
$api_secret = ""
$api_id = ""
$org_id = ""


# One-time pull request from the site. Future variables will be built off this data
$content = Invoke-WebRequest -Uri "https://docs.vmware.com/en/VMware-Carbon-Black-Cloud/rn_rss.xml" -UseBasicParsing

# Grab the first mention of the Carbon Black Windows sensor from the RSS feed, then subtract the string to the version number
$CBVersion = $content.Content
$CBVersion = $CBVersion.Substring($CBVersion.IndexOf('VMware Carbon Black Cloud Windows Sensor'))
$CBVersion = $CBVersion.Substring(0, $CBVersion.IndexOf(' Release Notes'))
$CBVersion = $CBVersion.Replace("VMware Carbon Black Cloud Windows Sensor ", "")

# Create filenames with the current version
$CBFilenamex64 = "installer_vista_win7_win8-64-$CBVersion.msi"
#$CBFilenamex86 = "installer_vista_win7_win8-32-$CBVersion.msi"


$headers = @{
    "X-Auth-Token" = "$api_secret/$api_id"
}


if (!(Test-Path -Path "$softwareRepo\$CBFilenamex64")) {
    $downloadUrl = "$carbonBlackBaseUrl/appservices/v5/orgs/$org_id/kits/$CBFilenamex64"
    Invoke-WebRequest -Uri $downloadUrl -headers $headers -OutFile "$softwareRepo\$CBFilenamex64"
    # Copy-Item -Path "$softwareRepo\x64\$CBFilenamex64" -Destination "$softwareRepo\x64\$CBFilenamex64Latest" # Used for group policy deployment
    # Start-Process -NoNewWindow $PdqInventoryPath -ArgumentList "UpdateCustomVariable $PdqInventoryVariable $CBVersion"
    # Start-Process -NoNewWindow msiexec.exe -ArgumentList "/I $softwareRepo\$CBFilenamex64 /qn $COMPANY_CODE"
    msiexec /qn /i "$softwareRepo\$CBFilenamex64" /L*vx "$softwareRepo\CB_log_install.txt" $COMPANY_CODE
    Write-Output "$softwareRepo\$CBFilenamex64"
}
