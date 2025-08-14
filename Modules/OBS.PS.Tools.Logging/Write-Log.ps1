Function Write-Log {
	[CmdletBinding(PositionalBinding=$false)]
    param(
		[Parameter(Mandatory = $true, Position = 0)]
		[Alias ('T')]
		[String] $Text,
		[Parameter(Mandatory = $true)]
		[Alias ('L')]
		[String] $LogFile,
		[String] $DateTimeFormat = 'yyyy-MM-dd HH:mm:ss',
		[Alias ('LogTimeStamp')]
		[Bool] $LogTime = $true,
		[Alias ('Level')]
		[ValidateSet('debug', 'info', 'notice', 'error', 'warning', 'critical')]
		[String]$LogLevel = 'info',
		[Bool] $ShowTime = $true,
		[Bool] $ShowLevel = $true,
        [int] $LogRetry = 2,
        [switch] $LogOnly
	)
	
	
    if (-not $LogOnly) {
		if (-not ($LogLevel.ToLower().Substring(0,1) -eq "d" -and $DebugPreference -ne "Continue")) {
			if ($Text.Length -gt 0) {
				Write-Host $Text
			}
		}
	}
	
	if ($Text.Length -gt 0 -and $LogFile) {
		$LogOutput = ""
		$LogEntrySaved = $False
		$LogEntrySaveRetry = 0
		Do {
			$LogEntrySaveRetry++
			Try {
				switch ($True) {
					(Test-Path variable:LogTime) {
						$Output += "[$([datetime]::Now.ToString($DateTimeFormat))]"
					}
					(Test-Path variable:LogLevel) {
						$Output += "[$($LogLevel.ToUpper().Substring(0,4))]"
					}
					((Test-Path variable:LogTime) -or (Test-Path variable:LogLevel)) {
						$Output += " "
					}
					($True) {
						$Output += $Text
					}
				}
				$LogOutput | Out-File -FilePath $LogFile -Append -ErrorAction Stop -WhatIf:$false
				$LogEntrySaved = $true
			} Catch {
				if ($LogEntrySaved -eq $false -and $LogEntrySaveRetry -eq $LogRetry) {
						Write-Warning "Couldn't write to log file $($_.Exception.Message). Tried ($LogEntrySaveRetry/$LogRetry))"
				} else {
					Write-Warning "Couldn't write to log file $($_.Exception.Message). Retrying... ($LogEntrySaveRetry/$LogRetry)"
				}
			}
		} Until ($LogEntrySaved -eq $true -or $LogEntrySaveRetry -ge $LogRetry)
	}
}

Export-ModuleMember -Function 'Write-Log'
