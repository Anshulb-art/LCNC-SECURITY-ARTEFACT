param([string]$Out = ".\reports\index.html")

$ErrorActionPreference = "Stop"
if (!(Test-Path .\reports)) { New-Item -ItemType Directory -Path .\reports | Out-Null }

# Collect ZAP reports
$zapHtmls = Get-ChildItem .\reports\zap-*.html -ErrorAction SilentlyContinue
$zapJson  = Get-ChildItem .\reports\zap-*.json -ErrorAction SilentlyContinue | Select-Object -First 1

# ZAP alerts summary table (if we have JSON)
$alertsFrag = "<p>No ZAP JSON found.</p>"
if ($zapJson) {
  try {
    $z = Get-Content $zapJson.FullName | ConvertFrom-Json
    $alerts = $z.site.alerts | Select-Object alert, risk, confidence, count
    $alertsFrag = ($alerts | ConvertTo-Html -Fragment -PreContent "<h2>ZAP Alerts (from $($zapJson.Name))</h2>")
  } catch {
    $alertsFrag = "<p>Failed to parse $($zapJson.Name): $($_.Exception.Message)</p>"
  }
}

# RBAC/IDOR CSV -> HTML fragment
$rbacCsv = ".\reports\rbac-idor.csv"
$rbacFrag = if (Test-Path $rbacCsv) {
  (Import-Csv $rbacCsv | ConvertTo-Html -Fragment -PreContent "<h2>RBAC / IDOR Probe</h2>")
} else { "<p>No RBAC/IDOR CSV found.</p>" }

# Re-run the lightweight scripts to capture their current output (or comment these out if you prefer)
function Run-IfExists($path){ if(Test-Path $path){ & $path 2>&1 | Out-String } else { "Missing: $path" } }
$sf  = Run-IfExists ".\check-session-fixation.ps1"
$bf  = Run-IfExists ".\bruteforce-smoke.ps1"
$api = Run-IfExists ".\api-sanity.ps1"

# Build link list to ZAP HTMLs
$links = if ($zapHtmls){ ($zapHtmls | ForEach-Object { "<li><a href='$($_.Name)'>$($_.Name)</a></li>" }) -join "`n" } else { "<li>No ZAP HTML reports found.</li>" }

$body = @"
<h1>Coffee App – Security Run</h1>

<h2>ZAP HTML Reports</h2>
<ul>
$links
</ul>

$alertsFrag
$rbacFrag

<h2>Session Fixation</h2>
<pre>$([System.Web.HttpUtility]::HtmlEncode($sf))</pre>

<h2>Brute-force Smoke</h2>
<pre>$([System.Web.HttpUtility]::HtmlEncode($bf))</pre>

<h2>API Sanity</h2>
<pre>$([System.Web.HttpUtility]::HtmlEncode($api))</pre>
"@

$head = "<style>body{font-family:Segoe UI,Arial,sans-serif;line-height:1.4} table{border-collapse:collapse;margin:8px 0} td,th{border:1px solid #ccc;padding:6px 8px}</style>"
ConvertTo-Html -Head $head -Body $body -Title "Coffee Security Report" | Set-Content $Out -Encoding UTF8
Write-Host "Wrote $Out"
