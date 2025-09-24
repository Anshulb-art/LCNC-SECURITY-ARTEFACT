param([string]$Base="http://host.docker.internal:8080/")
$targets = @(
  "api/orders",
  "api/orders?id=1",
  "search?q=' OR '1'='1",
  "search?q=<script>alert(1)</script>"
)
foreach($t in $targets){
  $u = ($Base.TrimEnd('/') + '/' + $t)
  try {
    $r = Invoke-WebRequest $u -UseBasicParsing -TimeoutSec 10
    "{0} -> {1}" -f $u, [int]$r.StatusCode
  } catch {
    "{0} -> {1}" -f $u, ($_.Exception.Response.StatusCode.value__)
  }
}
