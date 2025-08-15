function Start-InvocationTest {
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(ValueFromRemainingArguments = $true)]
        $Params
    )
    
    Write-Host $Params
    }
