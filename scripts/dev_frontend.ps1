param(
    [switch]$InstallDeps
)

$repoRoot = Split-Path -Parent $PSScriptRoot
$frontendRoot = Join-Path $repoRoot "frontend"
Set-Location $frontendRoot

if ($InstallDeps -or -not (Test-Path (Join-Path $frontendRoot "node_modules"))) {
    npm install
}

npm run dev
