<#
    .SYNOPSIS
    .DESCRIPTION
    .EXAMPLE
        Invoke-KonnektSiteConfig -SiteURL https://tenantname.sharepoint.com/sites/SiteName/ -SiteTitle "Site Name"
#>
Function Invoke-KonnektSiteAutoConfig {

    [CmdletBinding(PositionalBinding=$false)]
    param(
        [Parameter(Mandatory = $true)]
        [String] $Tenant,
        [Parameter(Mandatory = $true)]
        [String] $AppId,
        [Parameter(Mandatory = $true)]
        [String] $AppSecret,
        [string] $IntuneAppId = $null,
		[switch] $RemoveSite,
        [String] $LogPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Konnekt$($SiteTitle)Install-$(Get-Date -Format yyyyMMdd_HHmmss).log"
    )
    
    Import-Module OBS.PS.Tools.Logging
	
	
    # Get AppID from current script directory
    if ($PSScriptRoot -match '\\IMECache\\([0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})_\d+') {
		$IntuneAppId = $Matches[1]
	} elseif ($IntuneAppId -match '([0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})') {
        Write-Log -L $LogPath -level error "Could not detect an AppId from the PSCommandPath variable. Falling back to AppId parameter. Parameter is for debug purposes only."    
    } else {
        Write-Log -L $LogPath -level error "Could not detect an AppId from the PSCommandPath or the -AppId parameter. Exiting."
        throw "Could not detect an AppId from the PSCommandPath or the -AppId parameter. PSScriptRoot: $PSScriptRoot"
    }
    
    # Connect to Graph
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
    
    # Get SharePoint site info:
    #   1. Look up AppId in Intune
    #   2, Get Intune App description 
    #   3. Parse {spsiteurl:} and {sptitle:} variables
    #   4. Build Konnekt connection string
    
    $GraphUri = "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps/$($IntuneAppId)?`$select=id,displayName,description"

    try {
        $App = Invoke-RestMethod -Uri $GraphUri -Headers $Headers -Method Get -ErrorAction Stop
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        if ($StatusCode -eq 404) {
            Write-Log -L $LogPath -level error "Could not find an Intune application that matches ID $($IntuneAppId). Exiting."
            throw "Could not find an Intune application that matches ID $($IntuneAppId)."
        }
        Write-Log -L $LogPath -level error "Graph lookup for app '$IntuneAppId' failed (HTTP $StatusCode): $($_.Exception.Message)"
        throw "Graph lookup for app '$IntuneAppId' failed (HTTP $StatusCode): $($_.Exception.Message)"
    }

    Write-Log -L $LogPath -level info "Processing description for $($App.displayName)"
    
    # The description field contains bracketed strings that make up metadata about the corresponding SharePoint site: 
    #     - {spurl:https://example-tenant.sharepoint.com/sites/SiteName} 
    #     - {sptitle:"Example Site Name"}
    # These two fields are used to build the string that Konnekt expects for each site.
    $Description = $App.description
    if ($Description -match '\{spurl:\s*([^}\s]+)\s*\}') {
        $SpUrl = $Matches[1]
        
        # Confirm the URL is valid and points to a SharePoint site
        $Uri = $null # TryCreate requires a variable to insert the compared value into
        $IsValidUrl = [uri]::TryCreate($Url, 'Absolute', [ref]$Uri) -and
            $Uri.Scheme -eq 'https' -and
            ($Uri.Host -eq 'sharepoint.com' -or $Uri.Host.EndsWith('.sharepoint.com'))
    }

    if ($Description -match '\{sptitle:\s*"([^"]*)"\s*\}') {
        $SpTitle = $Matches[1]
    }
    
    if (-not [string]::IsNullOrWhiteSpace($myVar) -and -not $IsValidUrl) {
        Write-Log -L $LogPath -level warning "IntuneApp $($App.displayName) did not have a valid set of SharePoint metadata. The failing string: $($App.description). This group was skipped."
        throw "IntuneApp $($App.displayName) did not have a valid set of SharePoint metadata. The failing string: $($App.description)."
    }
    
    # Registry paths in use
    $KonnektSiteListPath = "HKCU:\SOFTWARE\Policies\GlueckKanja\Konnekt\SharepointSites"
    $KonnektConfigPath = "HKCU:\SOFTWARE\Policies\GlueckKanja\Konnekt\"
    
    # Build connect site config string
    $KonnektSiteConfigString = "$($SpUrl)|$($SpTitle)||true" 
    Write-Log -L $LogPath -level debug "Konnekt Site string: $KonnektSiteConfigString"
	
	$KonnektSiteName = $KonnektSiteConfigString
	$KonnektSiteValue = $KonnektSiteConfigString
	
    if ($RemoveSite.IsPresent) {
        
        Write-Log -L $LogPath "Invoke-KonnektSiteConfig REMOVAL (Site: $($SpTitle)) begins"
        # Check if the Konnekt registry DWord to map the requested site exists, create it if not.
        if ((Get-ItemPropertyValue -Path $KonnektSiteListPath -Name $KonnektSiteName -ErrorAction SilentlyContinue)) {
            Write-Log -L $LogPath -level debug "Konnekt site config registry DWORD present, removing"
            Remove-ItemProperty -Path $KonnektSiteListPath -Name $KonnektSiteName | Out-Null
        }
        exit 0
    }

    Write-Log -L $LogPath "Invoke-KonnektSiteConfig (Site: $($SpTitle)) begins"
    
    If ((Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Konnekt*" }).Count -eq 0) {
        Write-Log -L $LogPath -level warning "Konnekt Agent is not installed on this device. Configuration is continuing, but site will not map without Konnekt Agent."
    } 
    
    # Check if the Konnekt registry key exists, create it if not
    if (-not (Test-Path $KonnektConfigPath)) {
        Write-Log -L $LogPath -level debug "Konnekt registry key not present, creating"
        New-Item -Path $KonnektConfigPath -Force | Out-Null
    }
	
    # Check if the Konnekt registry DWord to enable managed site mappings exists, create it if not. Note this DWORD shares the same name as the Site List key, this is expected.
    if (-not (Get-ItemProperty -Path $KonnektConfigPath -Name "SharepointSites" -ErrorAction SilentlyContinue)) {
        Write-Log -L $LogPath -level debug "Konnekt manual mapping enablement registry DWORD not present, creating"
        New-ItemProperty -Path $KonnektConfigPath -Name "SharepointSites" -Value 1 -PropertyType DWord | Out-Null
    }
	
    # Check if the Konnekt SharepointSites registry key exists, create it if not
    if (-not (Test-Path $KonnektSiteListPath)) {
        Write-Log -L $LogPath -level debug "Konnekt SharepointSites registry key not present, creating"
		New-Item -Path $KonnektSiteListPath -Force | Out-Null
	}

	$Current = (Get-ItemProperty -Path $KonnektSiteListPath -Name $KonnektSiteName -ErrorAction SilentlyContinue).$KonnektSiteName

	if ($Current -ne $KonnektSiteValue) {
		New-ItemProperty -Path $KonnektSiteListPath -Name $KonnektSiteName -Value $KonnektSiteValue -PropertyType String -Force | Out-Null
	} else {
        Write-Log -L $LogPath -level info "Konnekt site config for $($SpTitle) exists and is valid: $($Current)"
	}
		
	
    Write-Log -L $LogPath -level debug "Registry path:$KonnektSiteListPath Registry name:$KonnektSiteName Registry value:$(Get-ItemPropertyValue -Path $KonnektSiteListPath -Name $KonnektSiteName -ErrorAction SilentlyContinue)"
    Write-Log -L $LogPath -level info "Konnekt Site $($SpTitle) installation completed."

}
