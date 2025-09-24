Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Run-Step($name, $path, $args=@()){
  if(-not (Test-Path $path)){ Write-Host "✗ $name (missing: $path)" -ForegroundColor Red; return }
  Write-Host "==> $name" -ForegroundColor Cyan
  & $path @args
  Write-Host "✓ $name`n" -ForegroundColor Green
}

Run-Step "ZAP AF (both roles)" ".\run-zap-coffee.ps1" @("-Target","http://host.docker.internal:8080/","-ApiKey","changeme")
Run-Step "Aggressive Active Scan" ".\active-attack.ps1"
Run-Step "Session Fixation" ".\check-session-fixation.ps1"
Run-Step "Brute-force Smoke" ".\bruteforce-smoke.ps1"
Run-Step "API Sanity" ".\api-sanity.ps1"
Run-Step "RBAC/IDOR (seeded)" ".\rbac-idor-probe.ps1"
Run-Step "RBAC/IDOR (discover+mutate)" ".\discover-and-probe.ps1" @("-MaxDepth","5","-MutateCount","25")

Write-Host "Reports:" -ForegroundColor Yellow
Get-ChildItem .\reports\* | Select-Object Name, Length, LastWriteTime | Sort-Object LastWriteTime
