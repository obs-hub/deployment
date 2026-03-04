<#
	.SYNOPSIS
		This script attempts to find a matching Datto site ID for the assigned user and installs the agent.
	.DESCRIPTION
		The script checks Intune for the device being provisioned, checks for the assigned user, checks that user's group membership, and installs the agent.
	.PARAMETER TenantId
		365 tenant ID
	.PARAMETER ClientId
		App ID for app registration in 365 (needs group read and directory read access).
	.PARAMETER ClientSecret
		Secret credential for app registration.
	.PARAMETER DefaultDattoSiteId
		GUID of default Datto site ID for when a user is unable to be classified, ideally the OnDemand builtin site.
	.EXAMPLE
		Invoke-DattoAgentInstall -TenantId ea1cb72a-3b33-4e53-91e4-7d218e6de36a -ClientId 4198db7a-a383-41b5-b9ff-728e848d8f66 -ClientSecret drtyretwe57yw457uyws453ehdr56yw347ysrtuj -DefaultDattoSiteId 34d6eceb-bc7c-4508-8ea6-a0e3bd9acd3f
		This command looks up the Datto site id and installs the agent.
#>
Function Invoke-DattoAgentInstall {
	[CmdletBinding(PositionalBinding=$false)]
	param(
		[Parameter(Mandatory = $true)]
		[String] $Tenant,
		[Parameter(Mandatory = $true)]
		[String] $AppId,
		[Parameter(Mandatory = $true)]
		[String] $AppSecret,
		[Parameter(Mandatory = $true)]
		[String] $DefaultDattoSiteId,
		[String] $LogPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\DattoAgentInstall-$(Get-Date -Format yyyyMMdd_HHmmss).log"
	)
	
	Import-Module OBS.PS.Tools.Logging

	Write-Log -L $LogPath "Invoke-DattoAgentInstall begins for tenant $($Tenant)"
	
	If (Get-Service CagService -ErrorAction SilentlyContinue) {
		Write-Output "Datto RMM Agent already installed on this device"
		exit 0
	} 

	$Body = @{
		Grant_Type = "client_credentials"
		Scope = "https://graph.microsoft.com/.default"
		Client_Id = $AppId
		Client_Secret = $AppSecret
	}

	Write-Log -L $LogPath "Calling for token at https://login.microsoftonline.com/$($Tenant)/oauth2/v2.0/token"
	
	$Connection = Invoke-RestMethod `
		-Uri "https://login.microsoftonline.com/$($Tenant)/oauth2/v2.0/token" `
		-Method POST `
		-Body $body

	$Token = $Connection.access_token
	
	$Headers = @{ Authorization = "Bearer $Token" }
	$Device = Invoke-RestMethod -Headers $Headers -Method GET -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=deviceName eq '$($env:COMPUTERNAME)'" 


	if (-not $Device.value) {
		Write-Log -L $LogPath -level error "Machine was not found in Intune."
	}
	$DeviceOwner = $Device.value[0].userId
	if (-not $DeviceOwner) {		
		Write-Log -L $LogPath -level warning "Machine does not have a primary user assigned. Falling back to Autopilot owner."


		$Serial = (Get-CimINstance -ClassName Win32_BIOS).SerialNumber
		$AutoPilot = Invoke-RestMethod -Headers $Headers -Method GET -Uri "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber, '$Serial')"
		if ($AutoPilot.value -and $AutoPilot.value[0].userPrincipalName) {
			$AssignedUpn = $AutoPilot.value[0].userPrincipalName
			Write-Log -L $LogPath -level info "Found Autopilot assigned user: $AssignedUpn"

			# Resolve UPN to User ID
			$UserLookup = Invoke-RestMethod -Headers $Headers -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$AssignedUpn"
			$DeviceOwner = $UserLookup.id
		} else {
			Write-Log -L $LogPath -level error "No assigned user in Intune or Autopilot."
		}
	}
		
	$DeviceOwnerGroups = Invoke-RestMethod -Headers $Headers -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$DeviceOwner/memberOf"
	$DeviceOwnerGroup = $DeviceOwnerGroups[0].Value | Where-Object { $_.displayName -like '*Site:*' }
	
	if (-not $DeviceOwnerGroup) {
		Write-Log -L $LogPath -level error "No Intune Site group found for user assigned"
	}

	$DeviceOwnerGroupId = $DeviceOwnerGroup.Id
	Write-Log -L $LogPath -level info "Found group: $($DeviceOwnerGroup.displayName) [$DeviceOwnerGroupId]"
		
	$DattoSiteId = $DeviceOwnerGroup.description
	
	[System.Guid]$Ref = New-Guid
	if (-not ([System.Guid]::TryParse($DattoSiteId, [ref]$Ref))) {	
		Write-Log -L $LogPath -level error "DattoSiteId not found or no location ID set. Setting to default group [$DefaultDattoSiteId]."
		$DattoSiteId = $DefaultDattoSiteId
	}
 
	Write-Log -L $LogPath -level info "Found DattoSiteId: $DattoSiteId"

	$AgentURL="https://vidal.rmm.datto.com/download-agent/windows/$($DattoSiteId)"
	Write-Log -L $LogPath -level info "Full Datto Agent Download URL: $($AgentURL)"
	
	try {
		(New-Object System.Net.WebClient).DownloadFile($AgentURL, "$env:TEMP\DRMMSetup.exe")
	} 
	catch {
		Write-Log -L $LogPath -level error "Datto agent download failed"
		exit 1
	} 
	
	# Install the Agent
	$InstallStart = Get-Date 
	Write-Log -L $LogPath -level info "Starting Agent install"
	& "$env:TEMP\DRMMSetup.exe" | Out-Null 
	Write-Log -L $LogPath -level info "Agent install completed in $((Get-Date).Subtract($InstallStart).Seconds) seconds."
	Remove-Item "$env:TEMP\DRMMSetup.exe" -Force
		
}
