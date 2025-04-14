#Ninite Installer Script
#Downloads Ninite Installer based on Input
#Currently Supports a few different apps, feel free to add others
#Supports Install & Uninstall

Function Invoke-Ninite {
    Param(
        [Parameter(Mandatory = $true, Position = 1, HelpMessage = "Ninite Application List")]
        [ValidateNotNullOrEmpty()]
        [string]$AppList,

        [Parameter(Position = 2, HelpMessage = "Install or Uninstall")]
        [ValidateSet("Install", "Uninstall")]
        [string]$Invoke = 'Install'
    )

    $DefaultPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
    $LogPath = "$DefaultPath\Ninite.txt"

    # Start logging
    Start-Transcript -Path "$LogPath" -Append
    $dtFormat = 'dd-MMM-yyyy HH:mm:ss'
    Write-Host "$(Get-Date -Format $dtFormat) [INFO] Script started"

    $scriptDir = "C:\ProgramData\Intune"
    Write-Host "$(Get-Date -Format $dtFormat) [INFO] Download location $scriptDir"

    $AppArray = $AppList.Split(",")

    Foreach ($NiniteApp in $AppArray) {
        Write-Host "$(Get-Date -Format $dtFormat) [INFO] Processing application: $NiniteApp"

        # Timeout if things are taking too long
        $AppTimeout = "180"

        # Set information per app to be used later
        $downloadlink = ""
        $uninstallstring = ""

        switch ($NiniteApp) {
            "7Zip" {
                $downloadlink = "https://ninite.com/7Zip/ninite.exe"
                $uninstallstring = '"C:\Program Files\7-Zip\Uninstall.exe" /S'
                $AppTimeout = "300"
            }
            "Chrome" {
                $downloadlink = "https://ninite.com/chrome/ninite.exe"
                $uninstallstring = "wmic product where name='Google Chrome' call uninstall"
            }
            "FileZilla" {
                $downloadlink = "https://ninite.com/FileZilla/ninite.exe"
                $uninstallstring = '"C:\Program Files (x86)\FileZilla FTP Client\uninstall.exe" /S'
            }
            "Firefox" {
                $downloadlink = "https://ninite.com/FireFox/ninite.exe"
                $uninstallstring = '"C:\Program Files\Mozilla Firefox\uninstall\helper.exe" /S'
            }
            "GreenShot" {
                $downloadlink = "https://ninite.com/GreenShot/ninite.exe"
                $uninstallstring = '"c:\windows\system32\taskkill.exe" /IM greenshot* /F & "C:\Program Files\Greenshot\unins000.exe" /SILENT'
            }
            "VLC" {
                $downloadlink = "https://ninite.com/VLC/ninite.exe"
                $uninstallstring = '"C:\Program Files\VideoLAN\VLC\uninstall.exe" /S /NCRC'
            }
            "VSCode" {
                $downloadlink = "https://ninite.com/VSCode/ninite.exe"
                $uninstallstring = '"C:\Program Files\Microsoft VS Code\unins000.exe" /SILENT'
            }
            "WinDirStat" {
                $downloadlink = "https://ninite.com/WinDirStat/ninite.exe"
                $uninstallstring = '"C:\Program Files (x86)\WinDirStat\Uninstall.exe" /S'
                $AppTimeout = "300"
            }
            default {
                Write-Host "$(Get-Date -Format $dtFormat) [ERROR] Unknown application: $NiniteApp"
                continue
            }
        }

        if ($Invoke -eq "Install") {
            # Download the Ninite file
            Write-Host "$(Get-Date -Format $dtFormat) [INFO] Downloading $NiniteApp to $scriptDir"
            try {
                $ProgressPreference = 'SilentlyContinue'
                Invoke-WebRequest -Uri $downloadlink -OutFile "$scriptDir\NiniteInstaller.exe" -UseBasicParsing -Verbose
            } catch {
                Write-Host "$(Get-Date -Format $dtFormat) [ERROR] Failed to download $NiniteApp: $_"
                exit 1
            }

            if (!(Test-Path "$scriptDir\NiniteInstaller.exe")) {
                Write-Host "$(Get-Date -Format $dtFormat) [ERROR] $NiniteApp did not download, exiting script"
                exit 1
            }

            # Launch the Ninite installer
            Write-Host "$(Get-Date -Format $dtFormat) [INFO] Launching Ninite installer for $NiniteApp"
            try {
                Start-Process -FilePath "$scriptDir\NiniteInstaller.exe"
            } catch {
                Write-Host "$(Get-Date -Format $dtFormat) [ERROR] Failed to start Ninite installer for $NiniteApp: $_"
                exit 1
            }

            $Y = 1
            While (!(Get-WmiObject win32_process -Filter { Name = 'Ninite.exe' }) -and $Y -lt 10) {
                Write-Host "$(Get-Date -Format $dtFormat) [INFO] Waiting for Ninite.exe to download and launch"
                Start-Sleep -Seconds 1
                $Y++
            }

            If ($Y -ge 10) {
                Write-Host "$(Get-Date -Format $dtFormat) [ERROR] $NiniteApp did not download, exiting script"
                Get-Process | Where-Object { $_.Name -like "ninite*" } | Stop-Process -Verbose
                exit 1
            }

            # Monitor install process
            $PIDs = (Get-WmiObject win32_process -Filter { Name = 'Ninite.exe' }).ProcessID
            Write-Host "$(Get-Date -Format $dtFormat) [INFO] Ninite Process IDs: $PIDs"

            $MSIRunning = (Get-WmiObject win32_process -Filter { Name = "msiexec.exe" or Name = "Target.exe" } | Where-Object { $PIDs -contains $_.ParentProcessID }).ProcessID 
            $X = 1
            while ($null -eq $MSIRunning -and $X -lt "$AppTimeout") {
                $X++
                Start-Sleep -Seconds 1
                Write-Host "$(Get-Date -Format $dtFormat) [INFO] Waiting for software installer to start"
                $MSIRunning = (Get-WmiObject win32_process -Filter { Name = "msiexec.exe" or Name = "Target.exe" } | Where-Object { $PIDs -contains $_.ParentProcessID }).ProcessID 
            }
            Write-Host "$(Get-Date -Format $dtFormat) [INFO] Installer started"
            Write-Host "$(Get-Date -Format $dtFormat) [INFO] Waiting for software installer to finish"
            $ParentPID = (Get-WmiObject win32_process -Filter { Name = "msiexec.exe" or Name = "Target.exe" } | Where-Object { $PIDs -contains $_.ParentProcessID }).ProcessID
            $ParentProc = Get-Process -Id $ParentPID
            $ParentProc.WaitForExit()
            Write-Host "$(Get-Date -Format $dtFormat) [INFO] Software install finished"

            # Kill Task on the Ninite Installer
            Start-Sleep -Seconds 5
            Write-Host "$(Get-Date -Format $dtFormat) [INFO] Killing Ninite wrapper"
            Get-Process | Where-Object { $_.Name -like "ninite*" } | Stop-Process -Verbose
        }

        # Remove the Ninite Installer
        if (Test-Path "$scriptDir\NiniteInstaller.exe") {
            Start-Sleep -Seconds 2
            Write-Host "$(Get-Date -Format $dtFormat) [INFO] Deleting Ninite installer"
            try {
                Remove-Item "$scriptDir\NiniteInstaller.exe"
            } catch {
                Write-Host "$(Get-Date -Format $dtFormat) [ERROR] Failed to delete Ninite installer: $_"
            }
        }

        # Run the Uninstall if in Uninstall Mode
        if ($Invoke -eq "Uninstall") {
            Write-Host "$(Get-Date -Format $dtFormat) [INFO] Uninstalling $NiniteApp"
            try {
                cmd.exe /c $uninstallstring
            } catch {
                Write-Host "$(Get-Date -Format $dtFormat) [ERROR] Failed to uninstall $NiniteApp: $_"
            }
        }
    }

    Write-Host "$(Get-Date -Format $dtFormat) [INFO] Script finished"
    Stop-Transcript
}
