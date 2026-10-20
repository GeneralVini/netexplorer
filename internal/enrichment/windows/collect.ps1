# Export read-only Windows evidence. No credentials, probes, exploits or settings changes.
# Run locally: powershell.exe -NoProfile -File .\collect-windows.ps1 -OutputPath .\windows-inventory.json
param([string]$OutputPath, [switch]$ToStdout)
if (-not $ToStdout -and [string]::IsNullOrWhiteSpace($OutputPath)) { throw 'Specify OutputPath or ToStdout.' }
$ErrorActionPreference = 'Stop'
if (-not $ToStdout -and (Test-Path -LiteralPath $OutputPath)) { throw 'Output already exists. Choose a new filename.' }
$notes = New-Object 'System.Collections.Generic.List[string]'
$os = Get-CimInstance Win32_OperatingSystem
$addresses = @()
try {
    $addresses = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' |
        ForEach-Object { $_.IPAddress } | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Sort-Object -Unique)
} catch { $notes.Add('IPv4 collection unavailable.') }
$hotfixes = @()
try { $hotfixes = @(Get-HotFix | ForEach-Object { $_.HotFixID } | Where-Object { $_ -match '^KB\d{6,8}$' } | Sort-Object -Unique) }
catch { $notes.Add('Hotfix collection unavailable; Get-HotFix is not a complete update history.') }
$ubr = $null
try { $ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR).UBR }
catch { $notes.Add('Update build revision unavailable.') }
$spooler = 'unknown'
try {
    $service = Get-CimInstance Win32_Service -Filter "Name='Spooler'"
    if ($null -eq $service) { $spooler = 'absent' }
    elseif ($service.State -eq 'Running') { $spooler = 'running' }
    else { $spooler = 'stopped' }
} catch { $notes.Add('Print Spooler inventory unavailable.') }
$policy = @{}
try {
    $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    if (Test-Path -LiteralPath $path) {
        $values = Get-ItemProperty -LiteralPath $path
        foreach ($key in @('NoWarningNoElevationOnInstall','UpdatePromptSettings','RestrictDriverInstallationToAdministrators')) {
            if ($null -ne $values.$key) { $policy[$key] = [int]$values.$key }
        }
    }
} catch { $notes.Add('Point and Print policy collection unavailable.') }
$components = @{}
try {
    $file = Join-Path $env:SystemRoot 'System32\vbscript.dll'
    if (Test-Path -LiteralPath $file) { $components['vbscript'] = (Get-Item -LiteralPath $file).VersionInfo.FileVersion }
} catch { $notes.Add('VBScript version unavailable.') }
try {
    $defender = Get-MpComputerStatus
    $components['defender_platform'] = [string]$defender.AMProductVersion
    $components['defender_engine'] = [string]$defender.AMEngineVersion
    $components['defender_signatures'] = [string]$defender.AntivirusSignatureVersion
} catch { $notes.Add('Defender inventory unavailable.') }
try {
    $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive
    $components['bitlocker'] = 'Protection=' + [string]$volume.ProtectionStatus + ';Encryption=' + [string]$volume.EncryptionMethod
} catch { $notes.Add('BitLocker inventory unavailable; elevated read permissions may be required.') }
$result = [ordered]@{
    schema_version = 1
    collected_at = [DateTime]::UtcNow.ToString('o')
    computer_name = [string]$os.CSName
    addresses = @($addresses)
    caption = [string]$os.Caption
    version = [string]$os.Version
    build = [string]$os.BuildNumber
    ubr = $ubr
    product_type = [int]$os.ProductType
    service_pack_major = [int]$os.ServicePackMajorVersion
    hotfixes = @($hotfixes)
    spooler = $spooler
    point_and_print = $policy
    components = $components
    errors = @($notes.ToArray())
}
# CreateNew prevents overwriting a file even if it appeared after the initial check.
$json = $result | ConvertTo-Json -Depth 6
if ($ToStdout) { Write-Output $json; return }
$bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json)
$stream = [System.IO.File]::Open($OutputPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
Write-Output ('Exported Windows inventory to ' + $OutputPath)
