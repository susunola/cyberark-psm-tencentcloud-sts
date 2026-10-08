# The real installation: hash-pinned dependencies, the service under its own virtual account
# and the generated IIS configuration. The installer output is kept for triage either way, and
# it must not mention a fallback to version pins, which would mean the hash lock was ignored.
$ErrorActionPreference = 'Stop'
$Root = Split-Path $PSScriptRoot -Parent
# Windows PowerShell 5.1 can turn redirected native stderr (for example pip notices)
# into a terminating NativeCommandError under Stop. Keep stderr separate; the
# installer checks native exit codes, so real installation failures still fail.
$Output = & (Join-Path $Root 'Install-Bridge.ps1') -PythonExe (Get-Command python).Source `
    -WinSWExe (Join-Path $env:RUNNER_TEMP 'WinSW.exe') -WinSWSha256 $env:WINSW_SHA256 `
    -SettingsFile (Join-Path $env:RUNNER_TEMP 'settings.json') -InstallDir $env:INSTALL_DIR
$Output | Tee-Object -FilePath (Join-Path $env:GITHUB_WORKSPACE 'installer.log')
if ($Output -match 'without hash verification') {
    throw 'The installer fell back to version pins instead of the hash-pinned lock.'
}
if (-not (Get-Service 'PSMTencentCloudSTS' -ErrorAction SilentlyContinue)) {
    throw 'The service was not registered.'
}
