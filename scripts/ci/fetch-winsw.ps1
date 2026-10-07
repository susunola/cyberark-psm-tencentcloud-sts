# Fetched rather than vendored, and confirmed against the pin before anything uses it.
$ErrorActionPreference = 'Stop'
$Target = Join-Path $env:RUNNER_TEMP 'WinSW.exe'
Invoke-WebRequest -Uri $env:WINSW_URL -OutFile $Target -UseBasicParsing
$Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Target).Hash.ToLower()
if ($Actual -ne $env:WINSW_SHA256) {
    throw "WinSW artifact changed upstream: expected $env:WINSW_SHA256 but got $Actual. Review before updating the pin."
}
