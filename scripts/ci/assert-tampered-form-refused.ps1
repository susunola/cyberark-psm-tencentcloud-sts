# Submit a form the bridge must refuse before it reaches any cloud call. This is the same path
# PSM takes - loopback HTTP behind the TLS proxy - and the audit line proves the refusal is
# attributable to a reason code rather than only visible as a status code.
$ErrorActionPreference = 'Stop'
$Xml = Get-Content -Raw (Join-Path $env:INSTALL_DIR 'PSMTencentCloudSTS.xml')
$ProxyKey = ([regex]'name="PSM_TC_PROXY_KEY" value="([^"]+)"').Match($Xml).Groups[1].Value
if (-not $ProxyKey) { throw 'The service XML does not carry the proxy key.' }
$Headers = @{'X-PSM-Bridge-Key' = $ProxyKey; 'X-PSM-Authenticated-User' = 'ci-probe'}

# An unexpected field: the shape check runs before the session check, so this must be refused
# even though the caller has no session, and it must not be a redirect to the console. A
# redirect is refused at the point it would be followed, so an accepted form cannot reach
# Tencent from this test.
$Body = @{
    csrf        = 'not-a-session-token'
    profile     = 'tc-readonly'
    secret_id   = 'AKIDacceptanceprobe0001'
    secret_key  = 'not-a-real-key'
    audit_label = 'ci-probe'
    role_arn    = 'qcs::cam::uin/100000000001:roleName/Admin'
}
$Status = 0
try {
    Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8765/connect' -Method Post -Body $Body `
        -Headers $Headers -TimeoutSec 10 -MaximumRedirection 0 | Out-Null
} catch {
    $Status = [int]$_.Exception.Response.StatusCode
}
Write-Output "tampered form status: $Status"
if ($Status -ne 400) { throw "Expected 400 for a form carrying an unexpected field, got $Status." }

# The operator reads the audit trail, so the refusal must name its reason there.
$ErrLog = Join-Path $env:INSTALL_DIR 'logs\PSMTencentCloudSTS.err.log'
$Recorded = $false
foreach ($Attempt in 1..10) {
    if ((Test-Path $ErrLog) -and (Select-String -Path $ErrLog -Pattern 'form-shape-rejected' -Quiet)) {
        $Recorded = $true
        break
    }
    Start-Sleep -Seconds 1
}
if (-not $Recorded) { throw 'The refusal is not attributable: form-shape-rejected is missing from the service log.' }
Write-Output 'audit: form-shape-rejected recorded'
