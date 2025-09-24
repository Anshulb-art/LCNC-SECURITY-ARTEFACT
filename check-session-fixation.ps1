param([string]$Base="http://host.docker.internal:8080/")
function Get-SessionId($sess,$base){
  $c = $sess.Cookies.GetCookies($base) | Where-Object { $_.Name -match '(?i)sess|jsession|auth' } | Select-Object -First 1
  if($c){ return "$($c.Name)=$($c.Value)" } else { return "" }
}
$s = New-Object Microsoft.PowerShell.Commands.WebRequestSession

Invoke-WebRequest "$($Base)login.html" -WebSession $s -UseBasicParsing | Out-Null
$pre = Get-SessionId $s $Base

Invoke-WebRequest "$($Base)login.html" -WebSession $s -UseBasicParsing -Method POST `
  -ContentType "application/x-www-form-urlencoded" `
  -Body "username=Jack&password=HvvG5JSD9z" | Out-Null

$post = Get-SessionId $s $Base

"Pre-Login cookie:  {0}" -f $pre
"Post-Login cookie: {0}" -f $post
if($pre -and $post -and ($pre -eq $post)){
  Write-Host "❌ Session Fixation suspected (cookie did NOT rotate)" -ForegroundColor Red
}else{
  Write-Host "✅ Session rotates after login" -ForegroundColor Green
}
