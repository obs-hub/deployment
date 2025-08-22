<#
	.SYNOPSIS
		This script attempts to find a matching location ID for the assigned user.
	.DESCRIPTION
		The script checks Intune for the device being provisioned, checks for the assigned user, checks that user's group membership, and assigns an environment variable if found.
	.PARAMETER TenantId
		365 tenant ID
	.PARAMETER ClientId
		App ID for app registration in 365 (needs group read and directory read access).
	.PARAMETER ClientSecret
		Secret credential for app registration.
	.EXAMPLE
		Invoke-AutomateLocationSelection -TenantId ea1cb72a-3b33-4e53-91e4-7d218e6de36a -ClientId 4198db7a-a383-41b5-b9ff-728e848d8f66 -ClientSecret drtyretwe57yw457uyws453ehdr56yw347ysrtuj
		This command looks up the location id and assigns it if found.
#>
Function Invoke-AutomateLocationSelection {
	[CmdletBinding(PositionalBinding=$false)]
	param(
		[Parameter(Mandatory = $true)]
		[String] $Tenant,
		[Parameter(Mandatory = $true)]
		[String] $AppId,
		[Parameter(Mandatory = $true)]
		[String] $AppSecret,
		[String] $LogPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AutomateLocationSelection-$(Get-Date -Format yyyyMMdd_HHmmss).log"
	)
	Import-Module OBS.PS.Tools.Logging

	Write-Log -L $LogPath "Invoke-AutomateLocationSelection begins for tenant $($Tenant)"
	
	# Checkl if location is set
	If ([int]::TryParse([Environment]::GetEnvironmentVariable('AutomateLocationID', 'Machine'), [ref]0)) {
		Write-Log -L $LogPath -level error "AutomateLocationID already set to $([Environment]::GetEnvironmentVariable('AutomateLocationID', 'Machine')), exiting"
		return
	}
	
	Write-Log -L $logpath "AutomateLocationId not found, proceeding to request from Entra"

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
		throw "Machine was not found in Intune."
	}
	$DeviceOwner = $Device.value[0].userId
	if (-not $DeviceOwner) {		
		Write-Log -L $LogPath -level warning "Machine does not have a primary user assigned. Falling back to Autopilot owner."


		$Serial = (Get-CimINstance -ClassName Win32_BIOS).SerialNumber
		Invoke-RestMethod -Headers $Headers -Method GET -Uri "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber, '$Serial')"
		if ($AutoPilot.value -and $AutoPilot.value[0].userPrincipalName) {
			$AssignedUpn = $AutoPilot.value[0].userPrincipalName
			Write-Log -L $LogPath -level info "Found Autopilot assigned user: $AssignedUpn"

			# Resolve UPN to User ID
			$UserLookup = Invoke-RestMethod -Headers $Headers -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$AssignedUpn"
			$DeviceOwner = $UserLookup.id
		} else {
			Write-Log -L $LogPath -level error "No assigned user in Intune or Autopilot."
			throw "No assigned user in Intune or Autopilot."
		}
	}
		
	$DeviceOwnerGroups = Invoke-RestMethod -Headers $Headers -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$DeviceOwner/memberOf"
	$DeviceOwnerGroup = $DeviceOwnerGroups[0].Value | Where-Object { $_.displayName -like '*Site:*' }
	
	if (-not $DeviceOwnerGroup) {
		Write-Log -L $LogPath -level error "No Intune Site group found for user assigned"
		throw "No Intune Site group found for user assigned"
	}

	$DeviceOwnerGroupId = $DeviceOwnerGroup.Id
	Write-Log -L $LogPath -level info "Found group: $($DeviceOwnerGroup.displayName) [$DeviceOwnerGroupId]"
		
	$LocationId = $DeviceOwnerGroup.description
	
	$Ref = 0
	if (-not ([int]::TryParse($LocationId, [ref]$Ref) -and $LocationId -gt 0)) {	
		Write-Log -L $LogPath -level error "LocationId not found or no location ID set"
		throw "LocationId not found or no location ID set"
	}
 
	Write-Log -L $LogPath -level info "Found LocationId: $LocationId"

	# Set as machine environment variable
	[Environment]::SetEnvironmentVariable("AutomateLocationID", $LocationId, "Machine")
	Write-Log -L $LogPath -level info "Environment variable 'AutomateLocationID' set to '$LocationId'"
}
