<#
	.SYNOPSIS
	.DESCRIPTION
	.EXAMPLE
		Invoke-KonnektSiteConfig -SiteURL https://tenantname.sharepoint.com/sites/SiteName/ -SiteTitle "Site Name"
#>
Function Invoke-KonnektSiteConfig {
    # MsiExec.exe /X{13EBE51F-7EF9-4E30-97F3-C53BF333739D} /qn /norestart

	[CmdletBinding(PositionalBinding=$false)]
	param(
		[Parameter(Mandatory = $true)]
		[string] $SiteURL,
		[Parameter(Mandatory = $true)]
		[string] $SiteTitle,
		[string] $SiteDriveLetter = $null,
		[switch] $RemoveSite,
		[String] $LogPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\KonnektInstall-$(Get-Date -Format yyyyMMdd_HHmmss).log"
	)
	
	Import-Module OBS.PS.Tools.Logging
	
	# Registry paths in use
	$KonnektSiteListConfig = "HKCU:\SOFTWARE\Policies\GlueckKanja\Konnekt\SharepointSites"
	$KonnektConfig = "HKCU:\SOFTWARE\Policies\GlueckKanja\Konnekt\"
	
	# Build connect site config string
	$KonnektSiteConfigString = "$($SiteURL)|$($SiteTitle)||true" 
	Write-Log -L $LogPath -level debug "Konnekt Site string: $KonnektSiteConfigString"	
	
	if ($RemoveSite.IsPresent) {
		
		Write-Log -L $LogPath "Invoke-KonnektSiteConfig REMOVAL (Site: $($SiteTitle)) begins"
		# Check if the Konnekt registry DWord to map the requested site exists, create it if not.
		if ((Get-ItemProperty -Path $KonnektSiteListConfig -Name $KonnektSiteConfigString -ErrorAction SilentlyContinue)) {
			Write-Log -L $LogPath -level debug "Konnekt site config registry DWORD present, removing"
			Remove-ItemProperty -Path $KonnektSiteListConfig -Name $KonnektSiteConfigString | Out-Null
		}
		exit 0
	}

	Write-Log -L $LogPath "Invoke-KonnektSiteConfig (Site: $($SiteTitle)) begins"
	
	If (Get-Service konnektUpdate -ErrorAction SilentlyContinue) {
		Write-Log -L $LogPath -level warning "Konnekt Agent is not installed on this device. Configuration is continuing, but site will not map without Konnekt Agent."
	} 
	
	# Check if the Konnekt registry key exists, create it if not
	if (-not (Test-Path $KonnektConfig)) {
		Write-Log -L $LogPath -level debug "Konnekt registry key not present, creating"
		New-Item -Path $KonnektConfig -Force | Out-Null
	}
	
	# Check if the Konnekt Site List registry key exists, create it if not
	if (-not (Test-Path $KonnektSiteListConfig)) {
		Write-Log -L $LogPath -level debug "Konnekt sites registry key not present, creating"
		New-Item -Path $KonnektSiteListConfig -Force | Out-Null
	}
	
	# Check if the Konnekt registry DWord to enable managed site mappings exists, create it if not. Note this DWORD shares the same name as the Site List key, this is expected.
	if (-not (Get-ItemProperty -Path $KonnektConfig -Name "SharepointSites" -ErrorAction SilentlyContinue)) {
		Write-Log -L $LogPath -level debug "Konnekt manual mapping enablement registry DWORD not present, creating"
		New-ItemProperty -Path $KonnektConfig -Name "SharepointSites" -Value 1 -PropertyType DWord | Out-Null
	}
	
	# Check if the Konnekt registry string to map the requested site exists, create it if not.
	if (-not (Get-ItemProperty -Path $KonnektSiteListConfig -Name $KonnektSiteConfigString -ErrorAction SilentlyContinue)) {
		# No corresponding registry value exists
		Write-Log -L $LogPath -level debug "Konnekt site config registry String not present, creating"
		New-ItemProperty -Path $KonnektSiteListConfig -Name $KonnektSiteConfigString -Value $KonnektSiteConfigString -PropertyType String | Out-Null
	} elseif ((Get-ItemProperty -Path $KonnektSiteListConfig -Name $KonnektSiteConfigString -ErrorAction SilentlyContinue) -ne $KonnektSiteConfigString) {
		# The registry value exists, but it is incorrect
		Write-Log -L $LogPath -level debug "Konnekt site config registry String is present but incorrect"
		Set-ItemProperty -Path $KonnektSiteListConfig -Name $KonnektSiteConfigString -Value $KonnektSiteConfigString | Out-Null
	} else {
		# The registry value exists, no action needed
		Write-Log -L $LogPath -level warn "Konnekt Site $($SiteTitle) already exists."
	}
	
	Write-Log -L $LogPath -level info "Konnekt Site $($SiteTitle) installation completed."

}
