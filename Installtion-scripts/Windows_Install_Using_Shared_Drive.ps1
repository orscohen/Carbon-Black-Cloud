# Location of the Carbon Black executable you want to use to install
$SensorShare = '\\Path-To-Carbon-Black-Installer\installer_vista_win7_win8-64-3.8.0.627.msi'

# The sensor is copied to the following directory
$SensorLocal = 'C:\windows\Temp\Carbon\installer_vista_win7_win8-64-3.8.0.627.msi'

# Check if the CbDefense service is already installed
if (!(Get-Service -Name 'CbDefense' -ErrorAction SilentlyContinue)) {
    # Create a Carbon TEMP directory if one does not already exist
    if (!(Test-Path -Path 'C:\windows\Temp\Carbon' -ErrorAction SilentlyContinue)) {
        New-Item -ItemType Directory -Path 'C:\windows\Temp\Carbon' -Force
    }

    # Now copy the sensor installer if the share is available
    if (Test-Path -Path $SensorShare) {
        Copy-Item -Path $SensorShare -Destination $SensorLocal -Force

        # Now check to see if the service is already present, and if not, run the installer.
        Set-Location -Path 'C:\windows\Temp\Carbon\'
        Start-Process msiexec -ArgumentList '/i installer_vista_win7_win8-64-3.8.0.627.msi /qn /L*vx "C:\windows\Temp\Carbon\CB_log_install.txt" COMPANY_CODE=******'
    }
}

# Check again if CbDefense service is installed and display appropriate message
if (Get-Service -Name 'CbDefense' -ErrorAction SilentlyContinue) {
    Write-Output "Carbon Black Is Installed"
} else {
    Write-Output "Carbon Black is Not Installed"
}
