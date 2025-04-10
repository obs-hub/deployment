# Set OSDCloudGUI Defaults
$Global:OSDCloud_Defaults = [ordered]@{
    BrandName             = "Out of the Box Solutions"
    BrandColor            = "Blue"
    OSActivation          = "Retail"
    OSEdition             = "Pro"
    OSLanguage            = "en-us"
    OSImageIndex          = 9
    OSActivationValues    = @(
        "Retail"
    )
    OSEditionValues       = @(
        "Pro"
    )
    OSLanguageValues      = @(
        "en-us"
    )
    OSVersionValues       = @(
        "Windows 11"
    )
    captureScreenshots    = $false
    ClearDiskConfirm      = $false
    restartComputer       = $false
    updateDiskDrivers     = $false
    updateFirmware        = $true
    updateNetworkDrivers  = $false
    updateSCSIDrivers     = $false
    WindowsUpdateDrivers  = $false
    WindowsDefenderUpdate = $false
    SyncMSUpCatDriverUSB  = $true
    WindowsUpdate         = $true
}

# Defaults to Overwrite in OSDCloud
$Global:MyOSDCloud        = @{
    SetTimeZone           = $true
}

# Create 'Start-OSDCloudGUI.json' - During WinPE SystemDrive will be 'X:'
$OSDCloudGUIjson = New-Item -Path "$($env:SystemDrive)\OSDCloud\Automate\Start-OSDCloudGUI.json" -Force

# Covert data to Json and export to the file created above
$Global:OSDCloud_Defaults | ConvertTo-Json -Depth 10 | Out-File -FilePath $($OSDCloudGUIjson.FullName) -Force

Write-Host “Starting OSDCloud” -ForegroundColor Cyan
Start-OSDCloudGUI

#region SetupComplete
Write-Host "Adding additional lines to SetupComplete..." -ForegroundColor Cyan
$PSFilePath = "C:\Windows\Setup\scripts\SetupComplete.ps1"

$InsertCode = @(
    "Write-Output '=== Pre-Script Setup ==='",
    "Write-Output 'Waiting for WiFi to connect'",
    "Start-Sleep -Seconds 120"
)
$ExistingScript = Get-Content -Path $PSFilePath

# Insert after WiFi setup
$InsertLocation = -1
for ($i = 0; $i -lt $ExistingScript.Count - 2; $i++) {
    if (
        $ExistingScript[$i]   -like '*Set-WiFi*' -and
        $ExistingScript[$i+1] -like '*Remove-Item*' -and
        $ExistingScript[$i+2] -like '*Write-Output ''-------------------------------------------------------------''*'
    ) {
        $InsertLocation = $i + 3
        break
    }
}
if ($InsertLocation -ne -1) {
    $UpdatedContent = $ExistingScript[0..($InsertLocation - 1)] + $InsertCode + $ExistingScript[$InsertLocation..($ExistingScript.Count - 1)]
    $UpdatedContent | Set-Content -Path $PSFilePath
    Write-Host "Code inserted after the WiFi config block" -ForegroundColor Green
} else {
    Write-Host "WiFi block not found. No changes made" -ForegroundColor Yellow
}
#endregion

Write-Host "Restarting in 10 seconds..." -ForegroundColor Yellow
Start-Sleep -Seconds 10
Restart-Computer -Force
