#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory=$true)][string]$InstallDir,
    [Parameter(Mandatory=$true)][string]$SharedSettingsFile,
    [switch]$Apply,
    [switch]$Restart
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Shared-ServiceConfig.ps1')
if (-not $Apply) { Write-Output 'No changes. Review shared settings and supply -Apply.'; exit 0 }
$InstallDir = (Resolve-Path -LiteralPath $InstallDir).Path
$SharedSettingsFile = (Resolve-Path -LiteralPath $SharedSettingsFile).Path
$Service = Get-Service 'PSMTencentCloudSTS' -ErrorAction Stop
if ($Service.Status -ne 'Stopped' -and -not $Restart) { throw 'Stop the service or explicitly supply -Restart before configuration.' }
$ConfigPath = Join-Path $InstallDir 'shared-secrets.json'
$XmlPath = Join-Path $InstallDir 'PSMTencentCloudSTS.xml'
$BackupPath = Join-Path $InstallDir 'PSMTencentCloudSTS.xml.before-shared'
if ((Test-Path -LiteralPath $ConfigPath) -or (Test-Path -LiteralPath $BackupPath)) { throw 'Existing shared configuration or backup found. Follow the upgrade procedure.' }
$Xml = New-SharedServiceConfig -XmlPath $XmlPath -ConfigPath $ConfigPath
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
[System.IO.File]::Copy($SharedSettingsFile, $ConfigPath, $false)
# The service reads this file as its own virtual account. LocalService is deliberately not
# granted access: an unrelated service on the same host using that shared identity must not
# be able to read the shared Redis credential or the session signing key.
& icacls.exe $ConfigPath '/inheritance:r' '/grant:r' '*S-1-5-18:F' '*S-1-5-32-544:F' 'NT SERVICE\PSMTencentCloudSTS:R' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Protecting shared configuration failed; service configuration has not been changed.' }
Save-SharedServiceConfig -Document $Xml -XmlPath $XmlPath -BackupPath $BackupPath
if ($Restart) {
    $Wrapper = Join-Path $InstallDir 'PSMTencentCloudSTS.exe'
    & $Wrapper stop 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0 -and $Service.Status -ne 'Stopped') { throw 'Service stop failed; inspect protected configuration before retry.' }
    & $Wrapper start 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Service start failed; inspect protected configuration before retry.' }
}
Write-Output 'Shared configuration installed. Verify authenticated /healthz and cross-node acceptance.'
