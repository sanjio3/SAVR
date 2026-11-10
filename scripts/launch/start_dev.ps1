param(
    [switch]$Bootstrap
)

# 本脚本位于 scripts/launch/，dev_all.ps1 在其上一级（scripts/）。
$scriptPath = Join-Path $PSScriptRoot "..\dev_all.ps1"
& $scriptPath @PSBoundParameters
