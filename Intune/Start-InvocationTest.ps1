function Start-InvocationTest {
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(ValueFromRemainingArguments = $true)]
        $Params
    )
    
    Get-Module OBS.PS.Tools.Logging -ListAvailable
    
    Write-Host $Params
    }
