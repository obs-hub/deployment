<#
	.SYNOPSIS
		This script attempts to find a matching Datto site ID for the assigned user and installs the agent.
	.DESCRIPTION
		The script checks Intune for the device being provisioned, checks for the assigned user, checks that user's group membership, and installs the agent.
	.EXAMPLE
		Invoke-KonnektInstall 
		This command installs the Konnekt agent.
#>
Function Invoke-KonnektInstall {
    # MsiExec.exe /X{13EBE51F-7EF9-4E30-97F3-C53BF333739D} /qn /norestart

	[CmdletBinding(PositionalBinding=$false)]
	param(
		[String] $LogPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\KonnektInstall-$(Get-Date -Format yyyyMMdd_HHmmss).log"
	)
	
	Import-Module OBS.PS.Tools.Logging

	Write-Log -L $LogPath "Invoke-KonnektInstall begins"
	
	If (Get-Service konnektUpdate -ErrorAction SilentlyContinue) {
		Write-Log -L $LogPath -level error "Konnekt Agent already installed on this device"
		# exit 0
	} 

	$URL="https://trial.konnekt.io/releases/Konnekt-X64-2.12.0.0.Msi"
	$FilePath = "$env:TEMP\Konnekt-x64.msi"
	Write-Log -L $LogPath -level info "Full Konnekt Download URL: $($URL)"
	
	try {
		(New-Object System.Net.WebClient).DownloadFile($URL, $FilePath)
	} 
	catch {
		Write-Log -L $LogPath -level error "Konnekt agent download failed"
		# exit 1
	} 
	
	# Install the Agent
	$InstallStart = Get-Date 
	Write-Log -L $LogPath -level info "Starting Konnekt install"
	Start-Process msiexec -ArgumentList "/i `"$filepath`"","/norestart","/qn" -Wait
	Write-Log -L $LogPath -level info "Konnekt install completed in $((Get-Date).Subtract($InstallStart).Seconds) seconds."
	Remove-Item $FilePath
		
}
