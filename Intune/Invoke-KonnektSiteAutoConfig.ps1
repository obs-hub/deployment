<#
    .SYNOPSIS
        Adds or removes one Konnekt SharePoint site mapping for each active user on the device.
    .DESCRIPTION
        Intended to run as a SYSTEM-context Intune Win32 app. Reads the Intune app's description
        from Graph, parses the {spurl:} and {sptitle:} metadata, and writes one value under
        HKEY_USERS\<SID>\SOFTWARE\Policies\GlueckKanja\Konnekt\SharepointSites for each active
        user. Any failure throws, so Intune records a non-zero exit code instead of a false success.
    .PARAMETER IntuneAppId
        Fallback only. Normally the app ID is read from the IMECache folder the install runs from.
    .PARAMETER RemoveSite
        Removes this app's site value instead of adding it. Use in the uninstall command.
    .EXAMPLE
        Invoke-KonnektSiteAutoConfig -Tenant $TenantId -AppId $ClientId -AppSecret $Secret
    .EXAMPLE
        Invoke-KonnektSiteAutoConfig -Tenant $TenantId -AppId $ClientId -AppSecret $Secret -RemoveSite
#>
function Invoke-KonnektSiteAutoConfig {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory)]
        [string]$Tenant,

        [Parameter(Mandatory)]
        [string]$AppId,

        [Parameter(Mandatory)]
        [string]$AppSecret,

        [string]$IntuneAppId,

        [switch]$RemoveSite,

        [string]$LogPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\KonnektSiteInstall-$(Get-Date -Format yyyyMMdd_HHmmss).log"
    )

    # Make every cmdlet failure terminating, so a failed registry write can't end in exit code 0
    $ErrorActionPreference = 'Stop'
    Import-Module OBS.PS.Tools.Logging

    $GuidPattern = '[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}'
    $KonnektConfigPath = 'SOFTWARE\Policies\GlueckKanja\Konnekt'

    # Resolve the Intune app ID. IME runs the install with C:\Windows\IMECache\<AppId>_<Rev>\ as the
    # working directory. $PSScriptRoot only matches if this function's file lives in that folder,
    # so the current location is checked as well.
    $ResolvedAppId = $null
    foreach ($Path in @($PSScriptRoot, (Get-Location).ProviderPath)) {
        if ($Path -match "\\IMECache\\($GuidPattern)_\d+") {
            $ResolvedAppId = $Matches[1]
            break
        }
    }

    if ($null -eq $ResolvedAppId) {
        if ($IntuneAppId -match "^$GuidPattern$") {
            Write-Log -L $LogPath -Level warning "No IMECache path found (PSScriptRoot: '$PSScriptRoot'). Falling back to -IntuneAppId $IntuneAppId."
            $ResolvedAppId = $IntuneAppId
        }
        else {
            Write-Log -L $LogPath -Level error "Could not determine the Intune app ID from the IMECache path or -IntuneAppId. Exiting."
            throw "Could not determine the Intune app ID. PSScriptRoot: '$PSScriptRoot', Location: '$((Get-Location).ProviderPath)'"
        }
    }
    $IntuneAppId = $ResolvedAppId
    Write-Log -L $LogPath -Level info "Starting Konnekt Site config routine. Intune app ID: $IntuneAppId. Mode: $(if ($RemoveSite) { 'Remove' } else { 'Add' })"

    # Connect to Graph
    $TokenUri = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token"
    $Body = @{
        grant_type    = 'client_credentials'
        scope         = 'https://graph.microsoft.com/.default'
        client_id     = $AppId
        client_secret = $AppSecret
    }

    Write-Log -L $LogPath "Calling for token at $TokenUri"
    try {
        $Connection = Invoke-RestMethod -Uri $TokenUri -Method Post -Body $Body
    }
    catch {
        Write-Log -L $LogPath -Level error "Token request failed (check the app secret has not expired): $($_.Exception.Message)"
        throw "Token request failed: $($_.Exception.Message)"
    }
    $Headers = @{ Authorization = "Bearer $($Connection.access_token)" }

    # Look up the Intune app and read its description
    $GraphUri = "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps/$($IntuneAppId)?`$select=id,displayName,description"
    try {
        $App = Invoke-RestMethod -Uri $GraphUri -Headers $Headers -Method Get
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        if ($StatusCode -eq 404) {
            Write-Log -L $LogPath -Level error "Could not find an Intune application that matches ID $IntuneAppId. Exiting."
            throw "Could not find an Intune application that matches ID $IntuneAppId."
        }
        Write-Log -L $LogPath -Level error "Graph lookup for app '$IntuneAppId' failed (HTTP $StatusCode): $($_.Exception.Message)"
        throw "Graph lookup for app '$IntuneAppId' failed (HTTP $StatusCode): $($_.Exception.Message)"
    }

    Write-Log -L $LogPath -Level info "Processing description for $($App.displayName)"

    # The description holds the site metadata as bracketed strings:
    #     {spurl:https://example-tenant.sharepoint.com/sites/SiteName}
    #     {sptitle:"Example Site Name"}
    # The parsing must stay identical to the detection script so both build the same value name.
    $Description = $App.description
    $SpUrl = $null
    $SpTitle = $null
    $IsValidUrl = $false

    if ($Description -match '\{spurl:\s*([^}\s]+)\s*\}') {
        $SpUrl = $Matches[1]
        $Uri = $null # TryCreate needs a variable to write the parsed URI into
        $IsValidUrl = [uri]::TryCreate($SpUrl, 'Absolute', [ref]$Uri) -and
            $Uri.Scheme -eq 'https' -and
            ($Uri.Host -eq 'sharepoint.com' -or $Uri.Host.EndsWith('.sharepoint.com'))
    }

    if ($Description -match '\{sptitle:\s*"([^"]*)"\s*\}') {
        $SpTitle = $Matches[1]
    }

    if (-not $IsValidUrl -or [string]::IsNullOrWhiteSpace($SpTitle)) {
        Write-Log -L $LogPath -Level error "Intune app $($App.displayName) does not have a valid set of SharePoint metadata. The failing string: $Description"
        throw "Intune app $($App.displayName) does not have a valid set of SharePoint metadata. The failing string: $Description"
    }

    # Konnekt uses the same string as both the value name and the value data
    $SiteValue = "$SpUrl|$SpTitle||true"
    Write-Log -L $LogPath -Level debug "Konnekt site string: $SiteValue"

    # Check for the agent via the uninstall keys.
    if (-not $RemoveSite) {
        $UninstallPaths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        $KonnektAgent = Get-ItemProperty -Path $UninstallPaths -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like '*Konnekt*' }
        if ($null -eq $KonnektAgent) {
            Write-Log -L $LogPath -Level warning "Konnekt Agent is not installed on this device. Configuration is continuing, but the site will not map without the agent."
        }
    }

    # Find the active user(s). WTSEnumerateSessions gives the real session state (Active vs Disconnected).
    $WtsSource = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class WtsSessionHelper {
    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSEnumerateSessions(IntPtr hServer, int Reserved, int Version,
        out IntPtr ppSessionInfo, out int pCount);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr pMemory);

    [StructLayout(LayoutKind.Sequential)]
    private struct WTS_SESSION_INFO {
        public int SessionId;
        public IntPtr pWinStationName;
        public int State;
    }

    private const int WTSActive = 0;

    public static int[] GetActiveSessionIds() {
        IntPtr SessionInfoPtr;
        int Count;
        List<int> Ids = new List<int>();

        if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out SessionInfoPtr, out Count)) {
            return Ids.ToArray();
        }

        try {
            int Size = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
            for (int i = 0; i < Count; i++) {
                IntPtr Current = new IntPtr(SessionInfoPtr.ToInt64() + (i * Size));
                WTS_SESSION_INFO Info = (WTS_SESSION_INFO)Marshal.PtrToStructure(Current, typeof(WTS_SESSION_INFO));
                if (Info.State == WTSActive) {
                    Ids.Add(Info.SessionId);
                }
            }
        }
        finally {
            WTSFreeMemory(SessionInfoPtr);
        }

        return Ids.ToArray();
    }
}
'@

    try {
        # Add-Type fails if the type already exists in this session, e.g. when testing interactively
        if (-not ('WtsSessionHelper' -as [type])) {
            Add-Type -TypeDefinition $WtsSource -Language CSharp
        }
        $ActiveSessionIds = [WtsSessionHelper]::GetActiveSessionIds()
        $ExplorerProcesses = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'explorer.exe'"
    }
    catch {
        Write-Log -L $LogPath -Level error "Could not enumerate user sessions: $($_.Exception.Message)"
        throw "Could not enumerate user sessions: $($_.Exception.Message)"
    }

    # Session 0 is never an interactive user
    $ActiveExplorers = $ExplorerProcesses | Where-Object {
        $_.SessionId -ne 0 -and $ActiveSessionIds -contains $_.SessionId
    }

    $UserSids = @(
        foreach ($Process in $ActiveExplorers) {
            $Owner = Invoke-CimMethod -InputObject $Process -MethodName GetOwnerSid -ErrorAction SilentlyContinue
            if ($null -ne $Owner -and $Owner.ReturnValue -eq 0) {
                $Owner.Sid
            }
        }
    ) | Select-Object -Unique

    # Fail if there is no signed in user
    if (@($UserSids).Count -eq 0) {
        Write-Log -L $LogPath -Level error "No active user session found. Nothing was written."
        throw 'No active user session found; cannot write the user policy value.'
    }

    # Write or remove the site value in each active user's hive. 
    foreach ($Sid in $UserSids) {
		$ConfigPath = "Registry::HKEY_USERS\$Sid\$KonnektConfigPath"
		$SiteListPath = "$ConfigPath\SharepointSites"
		try {
			if ($RemoveSite) {
				if ($null -ne (Get-ItemProperty -Path $SiteListPath -Name $SiteValue -ErrorAction SilentlyContinue)) {
					Remove-ItemProperty -Path $SiteListPath -Name $SiteValue -ErrorAction SilentlyContinue
					Write-Log -L $LogPath -Level info "Removed site $SpTitle for SID $($Sid)"
				}
				else {
					Write-Log -L $LogPath -Level info "Site $SpTitle not present for SID $($Sid); nothing to remove"
				}
				continue
			}
			Write-Log -L $LogPath "Installing site $SpTitle for SID $($Sid)"

			# -Force creates the parent Konnekt key as well if it is missing
			if (-not (Test-Path -Path $SiteListPath)) {
				New-Item -Path $SiteListPath -Force | Out-Null
			} else {
			
				if ($null -ne (Get-ItemProperty -Path $SiteListPath -Name "*Accounting|*" -ErrorAction SilentlyContinue)) {
			        Remove-ItemProperty -Path $SiteListPath -Name "*Accounting|*" -ErrorAction SilentlyContinue
					Write-Log -L $LogPath -Level info "RECONCILITION: Removed old accounting entry for SID $($Sid)"
				}
			}

			# The enablement DWORD SharePoint sites allows multiple site mappings under the SharepointSites path. The DWORD and the path are the same, this is expected
			if ($null -eq (Get-ItemProperty -Path $ConfigPath -Name 'SharepointSites' -ErrorAction SilentlyContinue)) {
				New-ItemProperty -Path $ConfigPath -Name 'SharepointSites' -Value 1 -PropertyType DWord | Out-Null
			}

			# Check for the konnekt site string presence and add it if it is missing
			$Current = (Get-ItemProperty -Path $SiteListPath -Name $SiteValue -ErrorAction SilentlyContinue).$SiteValue
			if ($Current -ne $SiteValue) {
				New-ItemProperty -Path $SiteListPath -Name $SiteValue -Value $SiteValue -PropertyType String -Force | Out-Null
				Write-Log -L $LogPath -Level info "Wrote site $SpTitle for SID $($Sid)"
			}
			else {
				Write-Log -L $LogPath -Level info "Site config for $SpTitle already exists and is valid for SID $($Sid)"
			}
		}
		catch {
			Write-Log -L $LogPath -Level error "Failed to update Konnekt site $SpTitle for SID $($Sid): $($_.Exception.Message)"
			throw "Failed to update Konnekt site $SpTitle for SID $($Sid): $($_.Exception.Message)"
		}
	}

	# Reconcile changes in Nov 26 
	New-Item -Path "HKLM:\SOFTWARE\Policies\GlueckKanja\Konnekt" -Force | Out-Null
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\GlueckKanja\Konnekt" -Name 'EnhancedOAuth' -PropertyType 'DWORD' -Value 1 -Force | Out-Null
	# End Reconcile changes in Nov 26 

    Write-Log -L $LogPath -Level info "Konnekt site $SpTitle $(if ($RemoveSite) { 'removal' } else { 'installation' }) completed."
}
