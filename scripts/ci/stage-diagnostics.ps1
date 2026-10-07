# upload-artifact refuses any path outside the workspace root, and the install directory is
# outside the checkout, so everything is staged into the workspace first.
$ErrorActionPreference = 'Stop'
$Staging = Join-Path $env:GITHUB_WORKSPACE 'diagnostics'
New-Item -ItemType Directory -Force -Path $Staging | Out-Null
Copy-Item -LiteralPath (Join-Path $env:GITHUB_WORKSPACE 'installer.log') -Destination $Staging `
    -ErrorAction SilentlyContinue
if (Test-Path (Join-Path $env:INSTALL_DIR 'logs')) {
    Copy-Item -Path (Join-Path $env:INSTALL_DIR 'logs\*') -Destination $Staging -Recurse -Force `
        -ErrorAction SilentlyContinue
}
Get-ChildItem $Staging | ForEach-Object { Write-Output "diagnostic: $($_.Name)" }
