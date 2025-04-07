<#
.SYNOPSIS
    Updates OSDCloud USB drives after initial setup on a technician PC.
.DESCRIPTION
    - Updates OSD module
    - Downloads and extracts Lenovo drivers
    - Removes unnecessary drivers
    - Edits WinPE with updated driver/startnet script
    - Updates OSDCloud USB with optional offline image
.NOTES
    Run as Administrator. Supports updating multiple USB drives.
    The WinPE partition is only 2GB. If an error occurs or the USB does not boot it's likely due to the size of injected drivers.
#>

$WebScript = "https://raw.githubusercontent.com/obs-hub/deployment/refs/heads/main/OSDCloud/StartOSD.ps1"

# Used to reduce space. Matches using -contains
$DriversToRemove = @("Audio", "Bluetooth", "Camera", "Security", "Video")

$ScriptStartTime = Get-Date

#region CheckAdmin
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Script not run as administrator. Relaunching with elevated privileges..."
    Start-Sleep -Seconds 1
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}
#endregion

#region OSDCloud Setup
Write-Host "Updating OSD module..." -ForegroundColor Cyan
Set-ExecutionPolicy Bypass -Force
Update-Module -Name OSD -Force
Import-Module -Name OSD -Force

Write-Host "Refreshing OSDCloud workspace..." -ForegroundColor Cyan
New-OSDCloudWorkspace -WorkspacePath "C:\OSDCloud\Workspace"
Set-OSDCloudWorkspace -WorkspacePath "C:\OSDCloud\Workspace"
#endregion

#region Drivers
Write-Host "Downloading Lenovo drivers..." -ForegroundColor Cyan
# Add -Compatible to match this PCs model
Get-LenovoDriverPack -DownloadPath "C:\Drivers"

Write-Host "Expanding driver packs..." -ForegroundColor Cyan
$DriverPacks = Get-ChildItem -Path "C:\Drivers" -File
foreach ($Item in $DriverPacks) {
    if ($Item.Extension -eq ".exe" -and
        ($Item.VersionInfo.FileDescription -match "Lenovo" -or
         $Item.Name -match "tc_|tp_|ts_|500w|sccm_|m710e|tp10|tp8|yoga")) {
        Write-Host "Expanding: $($Item.Name)" -ForegroundColor Gray
        Start-Process -FilePath $Item.FullName -ArgumentList "/SILENT /SUPPRESSMSGBOXES" -Wait
    } else {
        Write-Host "Skipping non-matching file: $($Item.Name)" -ForegroundColor DarkGray
    }
}

Write-Host "Cleaning unnecessary drivers..." -ForegroundColor Yellow
# Default Lenovo directory
$DriversDir = "C:\Drivers\SCCM"
Get-ChildItem -Path $DriversDir -Recurse -Directory | Where-Object {
    $DriversToRemove -contains $_.Name
} | ForEach-Object {
    Remove-Item -Path $_.FullName -Recurse -Force
    Write-Host "Removed: $($_.FullName)"
}
#endregion

#region StartNet fallback script
$Startnet = @'
ping -n 1 google.com | find "TTL=" >nul
if errorlevel 1 (
    echo No internet, running Start-OSDCloudGUI
    start /wait PowerShell -NoL -W Mi -C Start-OSDCloudGUI
) else (
    echo Host reachable
)
'@
#endregion

#region Build USB
Write-Host "Injecting drivers and fallback script into WinPE..." -ForegroundColor Cyan
Edit-OSDCloudWinPE -StartWebScript $WebScript -DriverPath "C:\Drivers" -CloudDriver "WiFi" -WirelessConnect -Startnet $Startnet

Write-Host "Updating OSDCloud USB..." -ForegroundColor Cyan
$USBDrives = Get-Volume | Where-Object { $_.DriveType -eq 'Removable' -and $_.FileSystemLabel -ne "WINPE" }
if ($USBDrives.Count -eq 0) {
    Write-Host "No OSDCloud USB drives found. Creating new OSDCloud USB..." -ForegroundColor Yellow
    New-OSDCloudUSB

    Write-Host "Adding offline Windows image to USB..." -ForegroundColor Cyan
    Update-OSDCloudUSB -OSLanguage en-us -OSActivation Retail
} else {
    foreach ($Drive in $USBDrives) {
        Write-Host "Updating USB Drive: $($Drive.DriveLetter):\ ($($Drive.FileSystemLabel))"  -ForegroundColor Green
        Update-OSDCloudUSB -OSLanguage en-us -OSActivation Retail
    }
}

Write-Host "Updating OSDCloud USB..." -ForegroundColor Cyan
Update-OSDCloudUSB -OSLanguage en-us -OSActivation Retail
#endregion

$Duration = New-TimeSpan -Start $ScriptStartTime -End (Get-Date)
Write-Host ""
Write-Host "Completed in $($Duration.Minutes) minutes $($Duration.Seconds) seconds." -ForegroundColor Cyan