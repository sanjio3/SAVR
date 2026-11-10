param(
    [switch]$Bootstrap
)

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

function Stop-ListeningProcesses {
    param(
        [int[]]$Ports
    )

    $connections = Get-NetTCPConnection -LocalPort $Ports -State Listen -ErrorAction SilentlyContinue
    if (-not $connections) {
        return
    }

    $processIds = $connections | Select-Object -ExpandProperty OwningProcess -Unique
    foreach ($processId in $processIds) {
        try {
            $process = Get-CimInstance Win32_Process -Filter "ProcessId = $processId" -ErrorAction Stop
            Write-Host ("Stopping existing listener PID {0} on ports {1}: {2}" -f $processId, (($connections | Where-Object { $_.OwningProcess -eq $processId } | Select-Object -ExpandProperty LocalPort -Unique) -join ","), $process.CommandLine)
            Stop-Process -Id $processId -Force -ErrorAction Stop
        } catch {
            Write-Warning ("Failed to stop PID {0}: {1}" -f $processId, $_.Exception.Message)
        }
    }

    Start-Sleep -Seconds 1
}

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Error "uv is required. Install it first: https://docs.astral.sh/uv/"
    exit 1
}

if ($Bootstrap) {
    uv sync --group dev
} else {
    uv sync --frozen --group dev
}

Stop-ListeningProcesses -Ports @(8000, 5200)

$backendArgs = @(
    "-NoExit",
    "-ExecutionPolicy", "Bypass",
    "-File", (Join-Path $repoRoot "scripts\\dev_backend.ps1")
)

$frontendArgs = @(
    "-NoExit",
    "-ExecutionPolicy", "Bypass",
    "-File", (Join-Path $repoRoot "scripts\\dev_frontend.ps1")
)

if ($Bootstrap) {
    $frontendArgs += "-InstallDeps"
}

Start-Process powershell -ArgumentList $backendArgs -WorkingDirectory $repoRoot | Out-Null
Start-Sleep -Seconds 1
Start-Process powershell -ArgumentList $frontendArgs -WorkingDirectory $repoRoot | Out-Null

Write-Host "Backend and frontend started."
Write-Host "Backend: http://127.0.0.1:8000"
Write-Host "Frontend: http://127.0.0.1:5200"
Write-Host "First run: .\scripts\launch\start_dev.ps1 -Bootstrap"
