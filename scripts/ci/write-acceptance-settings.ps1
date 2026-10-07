# A synthetic profile, because the installer validates its input file and CI must never
# carry a real CAM role.
$ErrorActionPreference = 'Stop'
$Settings = @{
    profiles = @{
        'tc-readonly' = @{
            role_arn           = 'qcs::cam::uin/100000000001:roleName/PSMAcceptance'
            allowed_secret_ids = @('AKIDacceptanceprobe0001')
            destination        = 'https://console.tencentcloud.com/'
            duration_seconds   = 300
            region             = 'ap-singapore'
        }
    }
} | ConvertTo-Json -Depth 5
Set-Content -LiteralPath (Join-Path $env:RUNNER_TEMP 'settings.json') -Value $Settings -Encoding utf8
