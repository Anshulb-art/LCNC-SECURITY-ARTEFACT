param(
  [string]$Base = "http://host.docker.internal:8080/",
  [int]$MaxDepth = 2,
  [int]$MutateCount = 3,       # how many neighbor IDs to try
  [string]$OutCsv = ".\reports\rbac-idor.csv"
)

$ErrorActionPreference = "Stop"
if (!(Test-Path .\reports)) { New-Item -ItemType Directory -Path .\reports | Out-Null }

function New-Session($u,$p){
  $s = New-Object Microsoft.PowerShell.Commands.WebRequestSession
  Invoke-WebRequest -Uri ($Base + "login.html") -WebSession $s -UseBasicParsing -Method GET | Out-Null
  Invoke-WebRequest -Uri ($Base + "login.html") -WebSession $s -UseBasicParsing -Method POST `
    -ContentType "application/x-www-form-urlencoded" `
    -Body ("username={0}&password={1}" -f [uri]::EscapeDataString($u), [uri]::EscapeDataString($p)) | Out-Null
  $s
}

# Credentials (change if needed)
$CustUser = "Jack"; $CustPass = "HvvG5JSD9z"
$EngUser  = "Bill"; $EngPass  = "tGovGHz1r3"

# --- Mini crawler (logged in as Customer to see general app surface)
$cust = New-Session $CustUser $CustPass
$visited = New-Object 'System.Collections.Generic.HashSet[string]'
$queue = New-Object System.Collections.Queue
$start = ($Base.TrimEnd('/') + '/')
$queue.Enqueue(@{ Url=$start; Depth=0 })
$visited.Add($start) | Out-Null

function InScope($url){
  try {
    $u = [uri]$url
    return ($u.Host -eq ([uri]$Base).Host)
  } catch { return $false }
}

while ($queue.Count -gt 0){
  $item = $queue.Dequeue()
  $url = $item.Url; $d = $item.Depth
  try {
    $resp = Invoke-WebRequest -Uri $url -WebSession $cust -UseBasicParsing -Method GET -TimeoutSec 20
    # Collect links
    $links = @($resp.Links | ForEach-Object { $_.href }) + @($resp.ParsedHtml.getElementsByTagName('a') | ForEach-Object { $_.href })
    foreach($l in $links){
      if (-not $l) { continue }
      try {
        $abs = (New-Object System.Uri([uri]$url, $l)).AbsoluteUri
      } catch { continue }
      if (InScope $abs -and -not $visited.Contains($abs)) {
        $visited.Add($abs) | Out-Null
        if ($d -lt $MaxDepth) { $queue.Enqueue(@{ Url=$abs; Depth=$d+1 }) }
      }
    }
  } catch { }
}

# --- Build candidate list with ID mutations
$candidates = New-Object System.Collections.Generic.HashSet[string]
foreach($u in $visited){
  $candidates.Add($u) | Out-Null
  # Path number mutations
  if ($u -match '(.*?)(\d+)(\D*)$'){
    $num = [int]$Matches[2]
    1..$MutateCount | ForEach-Object {
      $candidates.Add(($u -replace '\d+',( $num + $_ ))) | Out-Null
    }
  }
  # Query string number mutations
  if ($u -match '\?'){
    $uri = [uri]$u
    $qs = [System.Web.HttpUtility]::ParseQueryString($uri.Query)
    foreach($k in $qs.Keys){
      if ($qs[$k] -match '^\d+$'){
        $orig = [int]$qs[$k]
        1..$MutateCount | ForEach-Object {
          $qs[$k] = ($orig + $_)
          $builder = New-Object System.UriBuilder $uri
          $builder.Query = ($qs.ToString())
          $candidates.Add($builder.Uri.AbsoluteUri) | Out-Null
        }
        $qs[$k] = $orig
      }
    }
  }
}

Write-Host "Discovered $($visited.Count) URLs; probing $($candidates.Count) candidates..."

# Engineer session too
$eng = New-Session $EngUser $EngPass

# --- Probe both roles
$rows = @()
foreach ($full in $candidates){
  foreach ($role in @(@{Name="Customer"; Session=$cust}, @{Name="Engineer"; Session=$eng})) {
    try {
      $r = Invoke-WebRequest -Uri $full -WebSession $role.Session -UseBasicParsing -MaximumRedirection 5 -Method GET -TimeoutSec 20
      $status = [int]$r.StatusCode; $body = $r.Content
    } catch {
      $status = try { $_.Exception.Response.StatusCode.value__ } catch { 0 }
      $body   = try { (New-Object IO.StreamReader $_.Exception.Response.GetResponseStream()).ReadToEnd() } catch { "" }
    }
    $blocked = ($status -in 401,403) -or ($body -match '(?i)forbidden|unauthori[sz]ed|login|sign\s*in')
    $pii     = ($body -match '(?i)\b(email|@|phone|iban|internal|admin|engineer|user(name|id)?)\b')
    $rows += [pscustomobject]@{
      URL        = $full
      Role       = $role.Name
      Status     = $status
      Blocked    = $blocked
      PIIKeyword = $pii
    }
  }
}

# Pivot
$group = $rows | Group-Object URL
$report = foreach ($g in $group) {
  $c = $g.Group | Where-Object {$_.Role -eq 'Customer'} | Select-Object -First 1
  $e = $g.Group | Where-Object {$_.Role -eq 'Engineer'} | Select-Object -First 1
  [pscustomobject]@{
    URL                  = $g.Name
    Customer_Status      = $c.Status
    Customer_Blocked     = $c.Blocked
    Customer_PIIKeyword  = $c.PIIKeyword
    Engineer_Status      = $e.Status
    Engineer_Blocked     = $e.Blocked
    Engineer_PIIKeyword  = $e.PIIKeyword
    Potential_RBAC_Leak  = ($c.Status -eq 200 -and $e.Status -in 401,403) -or ($e.Status -eq 200 -and $c.Status -in 401,403)
    Potential_IDOR       = ($c.Status -eq 200 -and $e.Status -eq 200 -and ($g.Name -match '(?i)\b(id|user|order|account|invoice|ticket)\b')) -and (($c.PIIKeyword -or $e.PIIKeyword))
  }
}

$report | Export-Csv -NoTypeInformation -Encoding UTF8 $OutCsv
Write-Host "RBAC/IDOR probe saved to $OutCsv"
