# Uninstall stops the service but keeps the files: the service configuration is audit and
# rollback evidence, and losing it during an uninstall would be silent data loss.
$ErrorActionPreference = 'Stop'
$Root = Split-Path $PSScriptRoot -Parent
& (Join-Path $Root 'Uninstall-Bridge.ps1') -InstallDir $env:INSTALL_DIR
if (Get-Service 'PSMTencentCloudSTS' -ErrorAction SilentlyContinue) {
    throw 'The service still exists after uninstall.'
}
foreach ($Kept in @('settings.json', 'PSMTencentCloudSTS.xml', 'app.py')) {
    if (-not (Test-Path (Join-Path $env:INSTALL_DIR $Kept))) {
        throw "$Kept was removed by the uninstall; audit and rollback evidence must survive."
    }
}
