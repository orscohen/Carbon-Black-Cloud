$cb = 'Carbon Black Cloud Sensor 64-bit'
# Check for Carbon Black Installation using WMI
$installCb = (Get-WmiObject -Class Win32_Product -Filter "Name='$cb'" | Where-Object { $_.Name -eq $cb }) -ne $null

if ($installCb) {
    Write-Host "Uninstalling Carbon Black..."
    Set-Location -Path "C:\Program Files\Confer"
    $CBremove = ".\Uninstall.exe"
    $bypass = "/bypass 1"
    $removalCode = '*************'
    $uninstall = "/uninstall"

    Invoke-Expression "$CBremove $bypass $removalCode"
    Invoke-Expression "$CBremove $uninstall $removalCode"
} else {
    Write-Host "Carbon Black is already Uninstalled"
}
