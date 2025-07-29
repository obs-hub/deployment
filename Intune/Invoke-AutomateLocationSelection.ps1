Function Invoke-AutomateLocationSelection {
	[CmdletBinding(PositionalBinding=$false)]
    param(
		[Parameter(Mandatory = $true)]
		[String] $TenantId,
		[Parameter(Mandatory = $true)]
		[String] $ClientId,
		[Parameter(Mandatory = $true)]
		[String] $ClientSecret,
		[String] $LogPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AutomateLocationSelection-$(Get-Date -Format yyyyMMdd_HHmmss).log"
	)
	
	Import-Module OBS.PS.Tools.Logging

	# Checkl if location is set
	If ([int]::TryParse([Environment]::GetEnvironmentVariable('AutomateLocationID', 'Machine'), [ref]0)) {
		Write-Log -L $LogPath -level error "AutomateLocationID already set to $([Environment]::GetEnvironmentVariable('AutomateLocationID', 'Machine'), exiting"
		return
	}

	# Connect to Graph API
	$SecureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
	$MgGraphParams = @{
		ClientId     = $ClientId
		TenantId     = $TenantId
		ClientSecret = $SecureSecret
	}
	Connect-MgGraph @MgGraphParams
	$Context = Get-MgContext
	if (-not $Context.Account -or -not $Context.TenantId) {
		Write-Log -L $LogPath -level error "Failed to authenticate with Microsoft Graph"
		throw "Failed to authenticate with Microsoft Graph"
	}

	# Get current device and assigned user ID from Intune
	$DeviceName = $env:COMPUTERNAME
	Write-Log -L $LogPath -level info "Current localhost is $DeviceName"
	$Device = Get-MgDeviceManagementManagedDevice -Filter "deviceName eq '$DeviceName'" -Top 1

	if (-not $Device) {
		Write-Log -L $LogPath -level error "Device '$DeviceName' not found in Intune"
		throw "Device '$DeviceName' not found in Intune"
	}

	$UserId = $Device.UserId
	if (-not $UserId) {
		Write-Log -L $LogPath -level error "Device '$DeviceName' does not have a primary user assigned"
		throw "Device '$DeviceName' does not have a primary user assigned"
	}

	# Get user group memberships and check for Site group membership
	$Groups = Get-MgUserMemberOf -UserId $UserId -All

	$Group = $Groups | Where-Object { $_.AdditionalProperties['displayName'] -like '*Site:*' }

	if (-not $Group) {
		Write-Log -L $LogPath -level error "No Intune Site group found for user assigned to '$DeviceName'"
		throw "No Intune Site group found for user assigned to '$DeviceName'"
	}

	$GroupId = $Group.Id
	Write-Log -L $LogPath -level info "Found group: $($Group.AdditionalProperties['displayName']) [$GroupId]"


	# Match LocationId
	$LocationId = (Get-MgGroup -GroupId $Group.Id).Description

	if (-not $LocationId) {
		Write-Log -L $LogPath -level error "GroupId '$GroupId' not found or no location ID set"
		throw "GroupId '$GroupId' not found or no location ID set"
	}

	$LocationId = $Location.LocationId
	Write-Log -L $LogPath -level info "Found LocationId: $LocationId"

	# Set as machine environment variable
	[Environment]::SetEnvironmentVariable("AutomateLocationID", $LocationId, "Machine")
	Write-Log -L $LogPath -level info "Environment variable 'AutomateLocationID' set to '$LocationId'"
}
