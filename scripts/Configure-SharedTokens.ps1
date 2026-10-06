#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory=$true)][string]$InstallDir,
    [Parameter(Mandatory=$true)][string]$SharedSettingsFile,
    [switch]$Apply,
    [switch]$Restart
)
$ErrorActionPreference = 'Stop'
if (-not $Apply) { Write-Output 'No changes. Review shared settings and supply -Apply.'; exit 0 }
$InstallDir = (Resolve-Path -LiteralPath $InstallDir).Path
$SharedSettingsFile = (Resolve-Path -LiteralPath $SharedSettingsFile).Path
$Service = Get-Service 'PSMTencentCloudSTS' -ErrorAction Stop
if ($Service.Status -ne 'Stopped' -and -not $Restart) { throw 'Stop the service or explicitly supply -Restart before configuration.' }
$ConfigPath = Join-Path $InstallDir 'shared-secrets.json'
$XmlPath = Join-Path $InstallDir 'PSMTencentCloudSTS.xml'
$BackupPath = Join-Path $InstallDir 'PSMTencentCloudSTS.xml.before-shared'
if ((Test-Path -LiteralPath $ConfigPath) -or (Test-Path -LiteralPath $BackupPath)) { throw 'Existing shared configuration or backup found. Follow the upgrade procedure.' }
$OldShared = $env:PSM_TC_SHARED_CONFIG
try {
    Push-Location $InstallDir
    $env:PSM_TC_SHARED_CONFIG = $SharedSettingsFile
    # Verify protected input, TLS connection and namespace before changing service configuration.
    & (Join-Path $InstallDir 'venv\Scripts\python.exe') -c 'import os; from security import shared_environment,configured_token_store; configured_token_store(shared_environment(os.environ))' 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Shared configuration validation failed; no details are printed.' }
} finally {
    Pop-Location
    $env:PSM_TC_SHARED_CONFIG = $OldShared
}
Copy-Item -LiteralPath $SharedSettingsFile -Destination $ConfigPath
& icacls.exe $ConfigPath '/inheritance:r' '/grant:r' '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-5-19:R' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Protecting shared configuration failed; service configuration has not been changed.' }
Copy-Item -LiteralPath $XmlPath -Destination $BackupPath
$Xml = New-Object System.Xml.XmlDocument
$Xml.XmlResolver = $null
$Xml.Load($XmlPath)
if ($Xml.service.env | Where-Object { $_.name -eq 'PSM_TC_SHARED_CONFIG' }) { throw 'Shared environment entry already exists.' }
$Entry = $Xml.CreateElement('env')
$Entry.SetAttribute('name','PSM_TC_SHARED_CONFIG')
$Entry.SetAttribute('value',$ConfigPath)
$null = $Xml.service.AppendChild($Entry)
$Xml.Save($XmlPath)
if ($Restart) {
    $Wrapper = Join-Path $InstallDir 'PSMTencentCloudSTS.exe'
    & $Wrapper stop 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0 -and $Service.Status -ne 'Stopped') { throw 'Service stop failed; inspect protected configuration before retry.' }
    & $Wrapper start 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Service start failed; inspect protected configuration before retry.' }
}
Write-Output 'Shared configuration installed. Verify authenticated /healthz and cross-node acceptance.'
