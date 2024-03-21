#!/bin/bash

CBDirectory="/Applications/VMware Carbon Black Cloud/"
SENSOR_VERSION="3.8.0.58"
Install_code=""  # Can be retrieved from CB Console
ORG_ID="Yout_ORG_ID" # Replace with your actual ORG ID
API_KEY="Your_API_Key"  # Replace with your actual API Key
SECRET="Your_Secret"    # Replace with your actual Secret

X_AUTH_TOKEN="${API_KEY}/${SECRET}"

dmgPath="/tmp/confer_installer_mac-${SENSOR_VERSION}.dmg"
mountPoint=$(/usr/bin/mktemp -d /tmp/file.XXXX)

if [[ -d $CBDirectory ]]; then
    curl --location --request GET "https://defense-prod05.conferdeploy.net/appservices/v5/orgs/${ORG_ID}/kits/confer_installer_mac-${SENSOR_VERSION}.dmg" -H "X-Auth-Token:${X_AUTH_TOKEN}" --output "$dmgPath"
    /usr/bin/hdiutil attach "$dmgPath" -mountpoint "$mountPoint" -noverify -nobrowse -noautoopen
    ${mountPoint}/docs/cbcloud_install_unattended.sh -i "${mountPoint}/cbcloud Install.pkg" -c $Install_code
    /usr/bin/hdiutil detach "$mountPoint"
    /bin/rm -rf "$mountPoint"
    /bin/rm -rf "$dmgPath"
    ###########Carbon Black Installing Script
else
    echo "Carbon Black Is Already Installed"
    exit 0
fi
