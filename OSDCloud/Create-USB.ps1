<#
.SYNOPSIS
    Creates a bootable OSDCloud USB with WiFi support, injected drivers, and an offline image fallback.
.DESCRIPTION
    - Checks for and installs ADK + WinPE
    - Initializes OSD
    - Downloads and extracts Lenovo drivers
    - Removes unnecessary drivers to save space
    - Adds fallback startnet.cmd
    - Edits WinPE with updated driver/startnet script
    - Creates OSDCloud USB with optional offline image
.NOTES
    Run as Administrator on a technician PC or a reference PC with the -Compatible flag to download drivers that match this PC. 
    Supports updating multiple USB drives.
    The WinPE partition is only 2GB. If an error occurs or the USB does not boot it's likely due to the size of injected drivers.
#>

$WebScript = "https://raw.githubusercontent.com/obs-hub/deployment/refs/heads/main/OSDCloud/StartOSD.ps1"

# Used to reduce space. Matches using -contains
$DriversToRemove = @("Audio", "Bluetooth", "Camera", "Security", "Video")

$WorkspacePath = "C:\OSDCloud\Workspace"

$ScriptStartTime = Get-Date

#region CheckAdmin
$ScriptUrl = 'https://raw.githubusercontent.com/obs-hub/deployment/refs/heads/main/OSDCloud/Create-USB.ps1'

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Script not run as administrator. Relaunch with elevated privileges..."
    #Start-Sleep -Seconds 3
    #Start-Process powershell.exe -ArgumentList "-NoProfile", "-ExecutionPolicy Bypass", "-Command iex (irm '$ScriptUrl')" -Verb RunAs
    #Exit
}
#endregion

#region CheckInstallADK
function Install-ComponentIfMissing {
    param (
        [string]$DisplayNamePattern,
        [string]$DownloadUrl,
        [string]$InstallerPath,
        [array]$Arguments,
        [string]$ComponentName
    )

    $installed = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Where-Object { $_.DisplayName -match $DisplayNamePattern }

    if (-not $installed) {
        Write-Host "$ComponentName not detected, downloading..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $InstallerPath -UseBasicParsing

        if (-not $Arguments -or $Arguments.Count -eq 0) {
            Write-Error "No arguments provided for $ComponentName installation. Aborting..."
            Exit 1
        }
        try {
            $process = Start-Process -FilePath $InstallerPath -ArgumentList $Arguments -Wait -PassThru

            if ($process.ExitCode -eq 0) {
                Write-Host "$ComponentName successfully installed." -ForegroundColor Green
            } else {
                Write-Error "$ComponentName installation failed. Aborting..."
                Exit 1
            }
        }
        catch {
            Write-Error "An error occurred while installing $ComponentName $_"
            Exit 1
        }
    } else {
        Write-Host "$ComponentName already installed." -ForegroundColor Green
    }
}

Write-Host "Checking for Windows Assessment and Deployment Kit..." -ForegroundColor Cyan
Install-ComponentIfMissing -DisplayNamePattern "Windows Assessment and Deployment Kit*" `
    -DownloadUrl "https://go.microsoft.com/fwlink/?linkid=2289980" `
    -InstallerPath "$env:TEMP\adksetup.exe" `
    -Arguments @("/quiet", "/norestart", "/features OptionId.DeploymentTools") `
    -ComponentName "Windows ADK"

Install-ComponentIfMissing -DisplayNamePattern "Windows Assessment and Deployment Kit Windows Preinstallation Environment*" `
    -DownloadUrl "https://go.microsoft.com/fwlink/?linkid=2289981" `
    -InstallerPath "$env:TEMP\adkwinpesetup.exe" `
    -Arguments @("/quiet", "/norestart") `
    -ComponentName "WinPE Add-on"
#endregion

#region OSDCloud Setup
Write-Host "Updating OSD module..." -ForegroundColor Cyan
Set-ExecutionPolicy Bypass -Force
if (-not (Get-InstalledModule -Name "OSD" -ErrorAction SilentlyContinue)) {
    Write-Host "OSD module not found. Installing..." -ForegroundColor Yellow
    Install-Module -Name OSD -Force
}
else {
    Update-Module -Name OSD -Force
}
Import-Module -Name OSD -Force

$TemplatePath = "C:\ProgramData\OSDCloud\Templates\WinRE"
if (-not (Test-Path $TemplatePath)) {
    Write-Host "WinRE template not found. Creating new OSDCloud template..." -ForegroundColor Yellow
    New-OSDCloudTemplate -Name WinRE -WinRE -SetAllIntl en-us
}
Write-Host "Refreshing OSDCloud workspace..." -ForegroundColor Cyan
New-OSDCloudWorkspace -WorkspacePath $WorkspacePath
Set-OSDCloudWorkspace -WorkspacePath $WorkspacePath
#endregion

#region Drivers
Write-Host "Downloading Lenovo drivers..." -ForegroundColor Cyan
# Add -Compatible to match this PCs model
Get-LenovoDriverPackCatalog -DownloadPath "C:\Drivers"

Write-Host "Expanding driver packs..." -ForegroundColor Cyan
# Default Lenovo directory
$DriversDir = "C:\Drivers\SCCM"
$DriverPacks = Get-ChildItem -Path "C:\Drivers" -File
foreach ($Item in $DriverPacks) {
    if ($Item.Extension -eq ".exe" -and
        ($Item.VersionInfo.FileDescription -match "Lenovo" -or
        $Item.Name -match "tc_|tp_|ts_|500w|sccm_|m710e|tp10|tp8|yoga")) {

        # Determine the target folder that should be created upon expansion
        $TargetFolder = Join-Path $DriversDir $Item.BaseName

        if (Test-Path $TargetFolder) {
            Write-Host "Skipping expansion for $($Item.Name) because folder '$TargetFolder' already exists." -ForegroundColor DarkGray
        }
        else {
            Write-Host "Expanding: $($Item.Name)"
            Start-Process -FilePath $Item.FullName -ArgumentList "/SILENT /SUPPRESSMSGBOXES" -Wait
        }
    }
    else {
        Write-Host "Skipping non-matching file: $($Item.Name)" -ForegroundColor DarkGray
    }
}

Write-Host "Cleaning unnecessary drivers: $($DriversToRemove -join ', ')..." -ForegroundColor Yellow
Get-ChildItem -Path $DriversDir -Recurse -Directory | Where-Object {
    $DriversToRemove -contains $_.Name
} | ForEach-Object {
    Remove-Item -Path $_.FullName -Recurse -Force
    Write-Host "Removed: $($_.FullName)" -ForegroundColor Gray
}
#endregion

#region SetupComplete Script
Write-Host "Creating SetupComplete files..." -ForegroundColor Cyan

$SetupCompleteUrl = 'https://raw.githubusercontent.com/obs-hub/deployment/refs/heads/main/OSDCloud/SetupComplete.ps1'

$BatFilePath = "$WorkspacePath\Config\Scripts\SetupComplete\SetupComplete.cmd"
$PSFilePath = "$WorkspacePath\Config\Scripts\SetupComplete\SetupComplete.ps1"
$SetupCompletePath = "C:\OSDCloud\Scripts\SetupComplete\SetupComplete.ps1"
            
#Create Batch File to Call PowerShell File
            
New-Item -Path $BatFilePath -ItemType File -Force
$CustomActionContent = New-Object system.text.stringbuilder
[void]$CustomActionContent.Append('%windir%\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy ByPass -File')
[void]$CustomActionContent.Append(" $SetupCompletePath")
Add-Content -Path $BatFilePath -Value $CustomActionContent.ToString()

#Create PowerShell File to do actions
            
New-Item -Path $PSFilePath -ItemType File -Force
Add-Content -path $PSFilePath "Set-ExecutionPolicy Bypass -Force -Scope CurrentUser"
Add-Content -path $PSFilePath "Invoke-Expression (Invoke-RestMethod -Uri `"$SetupCompleteUrl`")"
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

do {
    $USBDrives = Get-Volume | Where-Object { $_.DriveType -eq 'Removable' }

    if ($USBDrives.Count -eq 0) {
        Write-Warning "No USB drive detected. Please insert a USB drive to continue or CTRL+C to exit..."
        Start-Sleep -Seconds 5
    }
} while ($USBDrives.Count -eq 0)

$USBDrives = Get-Volume | Where-Object { $_.FileSystemLabel -like "OSDCloud*" }
if ($USBDrives.Count -eq 0) {
    Write-Host "No OSDCloud USB drives found. Creating new OSDCloud USB..." -ForegroundColor Yellow
    New-OSDCloudUSB
}
Write-Host "Updating OSDCloud USB..." -ForegroundColor Cyan
Update-OSDCloudUSB -OSLanguage en-us -OSActivation Retail
#endregion

Start-Sleep -Seconds 3
$Duration = New-TimeSpan -Start $ScriptStartTime -End (Get-Date)
Write-Host ""
Write-Host "Completed in $($Duration.Minutes) minutes $($Duration.Seconds) seconds." -ForegroundColor Cyan
