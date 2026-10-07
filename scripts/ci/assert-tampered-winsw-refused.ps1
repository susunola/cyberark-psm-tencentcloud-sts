# The refusal has to happen before the install directory exists: a mismatch found
# afterwards would already have installed something.
$ErrorActionPreference = 'Stop'
$Root = Split-Path $PSScriptRoot -Parent
$Wrong = '0' * 64
$Refused = $false
try {
    & (Join-Path $Root 'Install-Bridge.ps1') -PythonExe (Get-Command python).Source `
        -WinSWExe (Join-Path $env:RUNNER_TEMP 'WinSW.exe') -WinSWSha256 $Wrong `
        -SettingsFile (Join-Path $env:RUNNER_TEMP 'settings.json') -InstallDir $env:INSTALL_DIR
} catch {
    if ($_.Exception.Message -match 'checksum mismatch') { $Refused = $true } else { throw }
}
if (-not $Refused) { throw 'The installer accepted a mismatch between the WinSW hash and the file.' }
if (Test-Path $env:INSTALL_DIR) { throw 'The install directory exists despite the checksum refusal.' }
