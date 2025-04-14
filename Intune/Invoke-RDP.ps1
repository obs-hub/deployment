# Include RDP file downloaded from RDWeb, and optional icon file
# If icon is not included, system icon will be used
# Files can be in the root or a subfolder when packaged to IntuneWin
# If RDPName parameter is not specified, "RemoteApp" will be used
# Ability to install or uninstall with Invoke parameter

Function Invoke-RDP {
    Param(
        [Parameter(Position = 1, HelpMessage = "RemoteApp Name")]
        [string]$RDPName = 'RemoteApp',

        [Parameter(Position = 2, HelpMessage = "Install or Uninstall")]
        [ValidateSet("Install", "Uninstall")]
        [string]$Invoke = 'Install')

    $TargetDir = "C:\Program Files (x86)\RemoteApp"
    $ShortcutPath = "C:\Users\Public\Desktop\$RDPName.lnk"
    $TargetPath = "$TargetDir\$RDPName.rdp"
    $StartMenuPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs"

    $DefaultPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
    $LogPath = "$DefaultPath\$RDPName.log"

    #Start logging
    Start-Transcript -Path "$LogPath" -Append
    $dtFormat = 'dd-MMM-yyyy HH:mm:ss'
    Write-Host "$(Get-Date -Format $dtFormat)"

    If ($Invoke -eq "Install") {
        Install-RDP
    }
    Elseif ($Invoke -eq "Uninstall") {
        Write-Host "Uninstalling $RDPName"
        Uninstall-RDP
    }

    Write-Host "$(Get-Date -Format $dtFormat)"
    Stop-Transcript
}


Function Install-RDP {
    $RDPFile = Get-ChildItem -Path ".\" -Recurse -File -Include "*.rdp"
    If ($null -ne $RDPFile) {
        If (!(Test-Path "$TargetDir")) {
            Write-Host "Create directory if it doesn't exist $TargetDir"
            New-Item -ItemType Directory -Path $TargetDir -Force
        }
        Write-Host "Create RemoteApp from included RDP file $TargetDir\$RDPName.rdp"
        Get-Content "$RDPFile" -Raw | Out-File "$TargetDir\$RDPName.rdp"
    }
    Else {
        Write-Host "No RDP file present. Exiting"
        Exit 1
    }

    $IncludedIcon = Get-ChildItem -Path ".\" -Recurse -File -Include "*.ico"
    If ($null -ne $IncludedIcon) {
        $IconFile = "$TargetDir\$RDPName.ico"
        Write-Host "Copy icon $RDPName.ico to $IconFile"
        Copy-Item "$IncludedIcon" "$IconFile"
    }
    Else {
        Write-Host "No icon file present. Using system default"
        $IconFile = "%systemroot%\system32\mstscax.dll, 0"
    }

    Write-Host "Create Desktop shortcut" 
    $Shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath = $TargetPath
    $Shortcut.IconLocation = $IconFile
    $Shortcut.Save()

    Write-Host "Copy shortcut to Start Menu"
    Copy-Item $ShortcutPath $StartMenuPath
}


Function Uninstall-RDP {
    Write-Host "Removing $ShortcutPath and $TargetDir"
    Remove-Item "$ShortcutPath"
    Remove-Item "$TargetDir" -Recurse -Force
}
