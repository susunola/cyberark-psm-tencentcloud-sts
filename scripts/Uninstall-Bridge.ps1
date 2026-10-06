#Requires -RunAsAdministrator
[CmdletBinding()]
param([string]$InstallDir = 'C:\PSM-TencentCloud')
$ErrorActionPreference = 'Stop'
$Exe = Join-Path $InstallDir 'PSMTencentCloudSTS.exe'
if (Get-Service 'PSMTencentCloudSTS' -ErrorAction SilentlyContinue) {
    Stop-Service 'PSMTencentCloudSTS' -Force
    & $Exe uninstall
    if ($LASTEXITCODE -ne 0) { throw 'Service uninstall failed.' }
}
Write-Output 'Service removed. Files preserved for audit/rollback. Remove the dedicated IIS site and component association separately.'
