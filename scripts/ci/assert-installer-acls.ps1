# Read the ACLs the installer is supposed to apply, rather than assume it applied them.
# The proxy key lives in web.config.generated, so the service account that runs the proxy
# must not be able to read it, while the install directory must still let LocalService read
# the configuration and venv it needs to start.
$ErrorActionPreference = 'Stop'
$WebConfig = Join-Path $env:INSTALL_DIR 'web.config.generated'
if (-not (Test-Path $WebConfig)) { throw 'web.config.generated is missing.' }
$WebAcl = (Get-Acl $WebConfig).Access
$WebPrincipals = $WebAcl | ForEach-Object { $_.IdentityReference.Value }
Write-Output "web.config.generated access: $($WebPrincipals -join ', ')"
foreach ($Ace in $WebAcl) {
    $Name = $Ace.IdentityReference.Value
    if ($Name -match 'S-1-5-19' -or $Name -match 'LOCAL SERVICE') {
        throw "web.config.generated grants $Name access; only SYSTEM and administrators may read it."
    }
    if ($Name -match 'S-1-1-0' -or $Name -match 'Everyone' -or $Name -match 'S-1-5-32-545') {
        throw "web.config.generated grants $Name access, which is too broad."
    }
}
$DirAcl = (Get-Acl $env:INSTALL_DIR).Access | ForEach-Object { $_.IdentityReference.Value }
Write-Output "install directory access: $($DirAcl -join ', ')"
if (-not ($DirAcl | Where-Object { $_ -match 'S-1-5-19' -or $_ -match 'LOCAL SERVICE' })) {
    throw 'The install directory does not grant LocalService read access, which the service needs.'
}
