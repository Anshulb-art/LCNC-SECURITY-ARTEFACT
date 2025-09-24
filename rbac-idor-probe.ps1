param(
  [string]$Base = "http://host.docker.internal:8080/",
  [string]$UrlList = "urls.txt",
  [string]$OutCsv = ".\reports\rbac-idor.csv"
)

$ErrorActionPreference = "Stop"
if (!(Test-Path .\reports)) { New-Item -ItemType Directory -Path .\reports | Out-Null }

function New-Session($username, $password) {
  $sess = New-Object Microsoft.PowerShell.Commands.WebRequestSession
  Invoke-WebRequest -Uri ($Base + "login.html") -WebSession $sess -UseBasicParsing -Method GET | Out-Null
  Invoke-WebRequest -Uri ($Base + "login.html") -WebSession $sess -UseBasicParsing -Method POST `
    -ContentType "application/x-www-form-urlencoded" `
    -Body ("username={0}&password={1}" -f [uri]::EscapeDataString($username), [uri]::EscapeDataString($password)) | Out-Null
  return $sess
}

# Demo creds — change if needed
$CustUser = "Jack"; $CustPass = "HvvG5JSD9z"
$EngUser  = "Bill"; $EngPass  = "tGovGHz1r3"

$urls = Get-Content $UrlList | Where-Object { $_ -and (-not $_.StartsWith("#")) } | ForEach-Object { $_.Trim() }
if (-not $urls -or $urls.Count -eq 0) { throw "No URLs found in $UrlList" }

Write-Host "Logging in as Customer..."
$cust = New-Session $CustUser $CustPass
Write-Host "Logging in as Engineer..."
$eng  = New-Session $EngUser  $EngPass

$rows = @()
foreach ($u in $urls) {
  $full = ($Base.TrimEnd('/') + '/' + $u.TrimStart('/'))

  foreach ($role in @(
    @{Name="Customer"; Session=$cust},
    @{Name="Engineer"; Session=$eng}
  )) {
    try {
      $r = Invoke-WebRequest -Uri $full -WebSession $role.Session -UseBasicParsing -MaximumRedirection 5 -Method GET -TimeoutSec 30
      $status = [int]$r.StatusCode
      $body   = $r.Content
    } catch {
      $status = try { $_.Exception.Response.StatusCode.value__ } catch { 0 }
      $body   = try { (New-Object IO.StreamReader $_.Exception.Response.GetResponseStream()).ReadToEnd() } catch { "" }
    }

    $blocked = ($status -in 401,403) -or ($body -match '(?i)forbidden|unauthori[sz]ed|login|sign\s*in')
    $pii     = ($body -match '(?i)email|@|phone|iban|internal|admin|engineer')

    $rows += [pscustomobject]@{
      URL        = $full
      Role       = $role.Name
      Status     = $status
      Blocked    = $blocked
      PIIKeyword = $pii
    }
  }
}

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
    Potential_IDOR       = ($c.Status -eq 200 -and $e.Status -eq 200 -and ($g.Name -match '(?i)\b(id|user|order)\b') -and ($c.PIIKeyword -or $e.PIIKeyword))
    Potential_RBAC_Leak  = ($c.Status -eq 200 -and $e.Status -in 401,403) -or ($e.Status -eq 200 -and $c.Status -in 401,403)
  }
}

$report | Export-Csv -NoTypeInformation -Encoding UTF8 $OutCsv
Write-Host "RBAC/IDOR probe saved to $OutCsv"
