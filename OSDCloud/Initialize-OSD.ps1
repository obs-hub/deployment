﻿<#
.SYNOPSIS
    Creates a bootable OSDCloud USB with WiFi support, injected drivers, and an offline image fallback.
.DESCRIPTION
    - Checks for and installs ADK + WinPE
    - Initializes OSDCloud
    - Downloads & injects drivers
    - Adds fallback startnet.cmd
    - Creates bootable USB and adds offline image
.NOTES
    Run as Administrator on the technician PC.
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

#region CheckInstallADK
function Install-ComponentIfMissing {
    param (
        [string]$DisplayNamePattern,
        [string]$DownloadUrl,
        [string]$InstallerPath,
        [string]$Args,
        [string]$ComponentName
    )

    if (-not (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
              Where-Object { $_.DisplayName -match $DisplayNamePattern })) {
        Write-Host "$ComponentName not detected, downloading..."
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $InstallerPath -UseBasicParsing
        $process = Start-Process -FilePath $InstallerPath -ArgumentList $Args -Wait -PassThru
        if ($process.ExitCode -eq 0) {
            Write-Host "$ComponentName successfully installed." -ForegroundColor Yellow
        } else {
            Write-Error "$ComponentName installation failed. Aborting..."
            Exit 1
        }
    } else {
        Write-Host "$ComponentName already installed." -ForegroundColor Green
    }
}

Write-Host "Checking for Windows Assessment and Deployment Kit..." -ForegroundColor Cyan
Install-ComponentIfMissing "Windows Assessment and Deployment Kit*" `
    "https://go.microsoft.com/fwlink/?linkid=2289980" `
    "$env:TEMP\adksetup.exe" `
    "/quiet /norestart /features OptionId.DeploymentTools" `
    "Windows ADK"

Install-ComponentIfMissing "Windows Assessment and Deployment Kit Windows Preinstallation Environment*" `
    "https://go.microsoft.com/fwlink/?linkid=2289981" `
    "$env:TEMP\adkwinpesetup.exe" `
    "/quiet /norestart" `
    "WinPE Add-on"
#endregion

#region OSDCloud Setup
Write-Host "Installing and configuring OSD module..." -ForegroundColor Cyan
Set-ExecutionPolicy Bypass -Force
Install-Module -Name OSD -Force
Import-Module -Name OSD -Force

New-OSDCloudTemplate -Name WinRE -WinRE -SetAllIntl en-us
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
Write-Host "Customizing WinPE with drivers and fallback script..." -ForegroundColor Cyan
Edit-OSDCloudWinPE -StartWebScript $WebScript -DriverPath "C:\Drivers" -CloudDriver "WiFi" -WirelessConnect -Startnet $Startnet

Write-Host "Creating OSDCloud USB..." -ForegroundColor Cyan
New-OSDCloudUSB

Write-Host "Adding offline Windows image to USB..." -ForegroundColor Cyan
Update-OSDCloudUSB -OSLanguage en-us -OSActivation Retail
#endregion

$Duration = New-TimeSpan -Start $ScriptStartTime -End (Get-Date)
Write-Host ""
Write-Host "Completed in $($Duration.Minutes) minutes $($Duration.Seconds)seconds" -ForegroundColor Cyan