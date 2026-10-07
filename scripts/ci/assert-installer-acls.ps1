# Read the ACLs the installer is supposed to apply, rather than assume it applied them. The
# proxy key is in the service XML, which the service account reads as itself, and in
# web.config.generated, which the service account has no reason to read at all. The shared
# LocalService identity must not appear on either path.
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
    if ($Name -match 'PSMTencentCloudSTS') {
        throw "web.config.generated grants the service account access; the IIS site configuration is not its concern."
    }
    if ($Name -match 'S-1-1-0' -or $Name -match 'Everyone' -or $Name -match 'S-1-5-32-545') {
        throw "web.config.generated grants $Name access, which is too broad."
    }
}
# The service must be able to read its own configuration and code, as its own identity.
$DirAcl = (Get-Acl $env:INSTALL_DIR).Access | ForEach-Object { $_.IdentityReference.Value }
Write-Output "install directory access: $($DirAcl -join ', ')"
if (-not ($DirAcl | Where-Object { $_ -match 'PSMTencentCloudSTS' })) {
    throw 'The install directory does not grant the service account read access, which the service needs.'
}
if ($DirAcl | Where-Object { $_ -match 'S-1-5-19' -or $_ -match 'LOCAL SERVICE' }) {
    throw 'The install directory grants LocalService access; the proxy key belongs to the service account alone.'
}
