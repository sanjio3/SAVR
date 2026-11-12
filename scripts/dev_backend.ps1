$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot
$env:PYTHONPATH = $repoRoot

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Error "uv is required. Install it first: https://docs.astral.sh/uv/"
    exit 1
}

uv run python -m src.cli.service_server
