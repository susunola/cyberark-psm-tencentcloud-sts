# The proxy key is read back out of the installed service configuration, so this also proves
# the configuration the installer wrote is the one the running service serves.
$ErrorActionPreference = 'Stop'
$Headers = @{'X-PSM-Bridge-Key' = ''; 'X-PSM-Authenticated-User' = 'ci-probe'}
$Xml = Get-Content -Raw (Join-Path $env:INSTALL_DIR 'PSMTencentCloudSTS.xml')
$ProxyKey = ([regex]'name="PSM_TC_PROXY_KEY" value="([^"]+)"').Match($Xml).Groups[1].Value
if (-not $ProxyKey) { throw 'The service XML does not carry the proxy key.' }
$Headers['X-PSM-Bridge-Key'] = $ProxyKey

$Response = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8765/healthz' -TimeoutSec 5 -Headers $Headers
if (($Response.Content | ConvertFrom-Json).status -ne 'ok') { throw 'The readiness probe did not report ok.' }

# /healthz keeps its meaning for existing monitoring; /readyz is the name that says what it
# checks, so both must answer the same way with the key.
$Ready = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8765/readyz' -TimeoutSec 5 -Headers $Headers
if (($Ready.Content | ConvertFrom-Json).status -ne 'ok') { throw 'The /readyz probe did not report ok.' }

foreach ($Guarded in @('/healthz', '/readyz')) {
    $Unauthenticated = 0
    try { Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8765$Guarded" -TimeoutSec 5 | Out-Null }
    catch { $Unauthenticated = [int]$_.Exception.Response.StatusCode }
    Write-Output "unauthenticated $Guarded status: $Unauthenticated"
    if ($Unauthenticated -ne 403) { throw "Expected 403 for $Guarded without the proxy key, got $Unauthenticated." }
}

# Liveness is the one route a supervisor without the key may call, and it must answer
# nothing but liveness: the deployed surface is where that has to hold, not just in a test.
$Live = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8765/livez' -TimeoutSec 5
if (($Live.Content | ConvertFrom-Json).status -ne 'ok') { throw 'The liveness probe did not report ok.' }
if ($Live.Content -match 'version') { throw 'The liveness probe discloses more than liveness.' }
Write-Output "anonymous /livez status: $($Live.StatusCode)"
