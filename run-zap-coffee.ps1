param(
  [string]$Target = "http://host.docker.internal:8080/",
  [string]$Yaml   = "coffee-af.yaml",
  [string]$ReportsDir = "reports",
  [string]$ZapImage = "ghcr.io/zaproxy/zaproxy:stable",
  [string]$ApiKey = "changeme"
)

if (!(Test-Path $ReportsDir)) { New-Item -ItemType Directory -Path $ReportsDir | Out-Null }

Write-Host "==> Pulling ZAP image if needed..."
docker pull $ZapImage

Write-Host "==> Running ZAP Automation Framework..."
docker run --rm --add-host=host.docker.internal:host-gateway `
  -u root `
  -v "${PWD}:/zap/wrk" `
  -e ZAP_API_KEY="$ApiKey" `
  -t $ZapImage `
  zap.sh -cmd -autorun "/zap/wrk/$Yaml"

$report = Join-Path $ReportsDir "zap-coffee-top10.html"
if (Test-Path $report) {
  Write-Host "==> Done. Open report: $report"
} else {
  Write-Warning "ZAP finished but report not found. Check console output."
}
