#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PythonExe,
    [Parameter(Mandatory)][string]$WinSWExe,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$WinSWSha256,
    [Parameter(Mandatory)][string]$SettingsFile,
    [string]$InstallDir = 'C:\PSM-TencentCloud'
)
$ErrorActionPreference = 'Stop'
function Invoke-Checked([string]$Exe, [string[]]$Arguments) {
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Command failed: $Exe (exit $LASTEXITCODE)" }
}
if (Test-Path $InstallDir) { throw 'Install directory already exists. Use the documented upgrade procedure.' }
if (Get-Service 'PSMTencentCloudSTS' -ErrorAction SilentlyContinue) { throw 'Service already exists.' }
$ActualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $WinSWExe).Hash
if ($ActualHash -ne $WinSWSha256) { throw 'WinSW checksum mismatch.' }
$SourceDir = Split-Path $PSScriptRoot -Parent
Invoke-Checked -Exe $PythonExe -Arguments @((Join-Path $PSScriptRoot 'check_config.py'), $SettingsFile)
$Installed = $false
try {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
    # Dedicated installation directory: administrators and SYSTEM only initially.
    Invoke-Checked -Exe 'icacls.exe' -Arguments @($InstallDir, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
    foreach ($Name in @('app.py','federation.py','configuration.py','security.py','runtime.py','version.py','requirements.lock.txt')) {
        Copy-Item -LiteralPath (Join-Path $SourceDir $Name) -Destination $InstallDir
    }
    Copy-Item -LiteralPath $SettingsFile -Destination (Join-Path $InstallDir 'settings.json')
    Invoke-Checked -Exe $PythonExe -Arguments @('-m','venv',(Join-Path $InstallDir 'venv'))
    $ServicePython = Join-Path $InstallDir 'venv\Scripts\python.exe'
    Invoke-Checked -Exe $ServicePython -Arguments @('-m','pip','install','-r',(Join-Path $InstallDir 'requirements.lock.txt'))
    Copy-Item -LiteralPath $WinSWExe -Destination (Join-Path $InstallDir 'PSMTencentCloudSTS.exe')
    function New-Secret {
        $Bytes = New-Object byte[] 48
        $Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $Rng.GetBytes($Bytes); return [Convert]::ToBase64String($Bytes) } finally { $Rng.Dispose() }
    }
    $ProxyKey = New-Secret
    $SessionKey = New-Secret
    $Escape = { param($Value) [System.Security.SecurityElement]::Escape($Value) }
    $SafeDir = & $Escape $InstallDir
    $Xml = @"
<service>
  <id>PSMTencentCloudSTS</id>
  <name>Tencent Cloud STS Bridge for PSM</name>
  <description>Internal console federation bridge. Requires authenticated HTTPS proxy.</description>
  <executable>$SafeDir\venv\Scripts\python.exe</executable>
  <arguments>"$SafeDir\app.py"</arguments>
  <workingdirectory>$SafeDir</workingdirectory>
  <env name="PSM_TC_CONFIG" value="$SafeDir\settings.json" />
  <env name="PSM_TC_PROXY_KEY" value="$ProxyKey" />
  <env name="PSM_TC_SESSION_KEY" value="$SessionKey" />
  <serviceaccount><username>NT AUTHORITY\LocalService</username></serviceaccount>
  <startmode>Automatic</startmode>
  <onfailure action="restart" delay="10 sec" />
  <logpath>$SafeDir\logs</logpath>
  <log mode="roll" />
</service>
"@
    Set-Content -LiteralPath (Join-Path $InstallDir 'PSMTencentCloudSTS.xml') -Value $Xml -Encoding UTF8
    New-Item -ItemType Directory -Path (Join-Path $InstallDir 'logs') | Out-Null
    Invoke-Checked -Exe 'icacls.exe' -Arguments @($InstallDir, '/grant', '*S-1-5-19:(OI)(CI)RX')
    Invoke-Checked -Exe 'icacls.exe' -Arguments @((Join-Path $InstallDir 'logs'), '/grant', '*S-1-5-19:(OI)(CI)M')
    # This generated file contains the proxy secret. Only copy it into an ACL-protected IIS root.
    $WebConfig = Get-Content -Raw -LiteralPath (Join-Path $SourceDir 'deployment\web.config.template')
    $WebConfig = $WebConfig.Replace('REPLACE_WITH_PRIVATE_PROXY_KEY', $ProxyKey)
    Set-Content -LiteralPath (Join-Path $InstallDir 'web.config.generated') -Value $WebConfig -Encoding UTF8
    $Installed = $true
    Invoke-Checked -Exe (Join-Path $InstallDir 'PSMTencentCloudSTS.exe') -Arguments @('install')
    Invoke-Checked -Exe (Join-Path $InstallDir 'PSMTencentCloudSTS.exe') -Arguments @('start')
    $Ready = $false
    for ($Attempt = 0; $Attempt -lt 15; $Attempt++) {
        try {
            $Response = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8765/healthz' -TimeoutSec 2 `
                -Headers @{'X-PSM-Bridge-Key'=$ProxyKey; 'X-PSM-Authenticated-User'='installer-readiness'}
            if ($Response.StatusCode -eq 200 -and ($Response.Content | ConvertFrom-Json).status -eq 'ok') {
                $Ready = $true; break
            }
        } catch { }
        Start-Sleep -Seconds 1
    }
    if (-not $Ready) { throw 'Service readiness timed out.' }
    Write-Output 'Bridge installed. Configure the authenticated HTTPS proxy before connecting PSM.'
} catch {
    if ($Installed) {
        try {
            if (Get-Service 'PSMTencentCloudSTS' -ErrorAction SilentlyContinue) {
                & (Join-Path $InstallDir 'PSMTencentCloudSTS.exe') stop 2>$null
                & (Join-Path $InstallDir 'PSMTencentCloudSTS.exe') uninstall 2>$null
            }
        } catch { }
    }
    # Preserve ACL-protected files for diagnosis; do not automatically delete user configuration.
    throw 'Installation failed. Inspect restricted service logs and installation files; no secrets are printed.'
} finally {
    $ProxyKey = $null; $SessionKey = $null; $Xml = $null; $WebConfig = $null
}
