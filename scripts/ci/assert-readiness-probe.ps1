# The proxy key is read back out of the installed service configuration, so this also
# proves the configuration the installer wrote is the one the running service serves.
$ErrorActionPreference = 'Stop'
$Xml = Get-Content -Raw (Join-Path $env:INSTALL_DIR 'PSMTencentCloudSTS.xml')
$ProxyKey = ([regex]'name="PSM_TC_PROXY_KEY" value="([^"]+)"').Match($Xml).Groups[1].Value
if (-not $ProxyKey) { throw 'The service XML does not carry the proxy key.' }
$Response = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8765/healthz' -TimeoutSec 5 `
    -Headers @{'X-PSM-Bridge-Key' = $ProxyKey; 'X-PSM-Authenticated-User' = 'ci-probe'}
if (($Response.Content | ConvertFrom-Json).status -ne 'ok') { throw 'The readiness probe did not report ok.' }
$Unauthenticated = 0
try { Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8765/healthz' -TimeoutSec 5 | Out-Null }
catch { $Unauthenticated = [int]$_.Exception.Response.StatusCode }
Write-Output "unauthenticated status: $Unauthenticated"
if ($Unauthenticated -ne 403) { throw "Expected 403 without the proxy key, got $Unauthenticated." }
