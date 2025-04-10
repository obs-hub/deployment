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
#$Global:MyOSDCloud        = @{
#    SetTimeZone           = $true
#}

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
    '$Connected = $false',
    'for ($i = 0; $i -lt 20; $i++) {',
    '    if (Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet) {',
    '        $Connected = $true',
    '        Write-Output "Internet connection detected."',
    '        break',
    '    } else {',
    '        Write-Output "Waiting for WiFi connection... [$i]"',
    '        Start-Sleep -Seconds 5',
    '    }',
    '}',
    'if (-not $Connected) {',
    '    Write-Output "Warning: No internet after waiting."',
    '}',
    'Write-Output "-------------------------------------------------------------"'
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
