# Copies the extracted drivers back to USB for DISM injection the next time this model is encountered

$ComputerManufacturer = (Get-MyComputerManufacturer -Brief)
$ComputerModel = (Get-MyComputerModel)
$OSDCloudUSB = Get-Volume.usb | Where-Object { ($_.FileSystemLabel -match 'OSDCloud') -or ($_.FileSystemLabel -match 'BHIMAGE') } | Select-Object -First 1

$DriverDestinationPath = "$($OSDCloudUSB.DriveLetter):\OSDCloud\DriverPacks\DISM\$ComputerManufacturer\$ComputerModel"

if (-NOT (Test-Path -Path $DriverDestinationPath)) {
    New-Item -Path $DriverDestinationPath -ItemType Directory -Force -ErrorAction Ignore | Out-Null
}

# Lenovo
$rootPath = "C:\DRIVERS\SCCM"
if (-not (Test-Path -Path $rootPath)) {
    Write-Host "$rootPath does not exist. Exiting script."
    return
}

# Lenovo extracts to a timestamp folder
$timestampFolder = Get-ChildItem -Path $rootPath -Recurse -Directory |
Where-Object { $_.Name -match '^\d{8}\.\d+$' } |
Select-Object -First 1

if ($timestampFolder) {
    Write-Host "Copying Lenovo drivers to USB"
    Get-ChildItem -Path $timestampFolder.FullName -Directory | ForEach-Object {
        $source = $_.FullName
        $destination = Join-Path $DriverDestinationPath $_.Name
        Write-Host "Copying from $source to $destination"
        robocopy $source $destination /E /NFL /NDL /NJH /NJS /NC /NS /NP | Out-Null
    }
}
