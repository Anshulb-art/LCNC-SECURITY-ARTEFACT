param(
  [string]$Target  = "http://host.docker.internal:8080/",
  [string]$ApiKey  = "changeme",
  [string]$ZapImage = "ghcr.io/zaproxy/zaproxy:stable"
)

# 1) Write AF plan that defines a policy and uses it
@"
env:
  contexts:
    - name: CoffeeContext
      urls: [ "$Target" ]
      includePaths: [ "${Target}.*" ]
      authentication:
        method: form
        parameters:
          loginUrl: "${Target}login.html"
          loginRequestData: "username={%username%}&password={%password%}"
        verification:
          method: response
          loggedInRegex: "(?i)logout|welcome|order"
          loggedOutRegex: "(?i)login|sign\\s*in"
      sessionManagement:
        method: cookie
      users:
        - name: Customer-Jack
          credentials: { username: "Jack", password: "HvvG5JSD9z" }

  parameters:
    failOnError: true
    progressToStdout: true

jobs:
  # Light crawl as logged-in user
  - type: spider
    parameters:
      context: "CoffeeContext"
      url: "$Target"
      user: "Customer-Jack"
      maxDuration: 8
      maxChildren: 0

  - type: passiveScan-wait
    parameters:
      maxDuration: 3

  # Define a custom policy with stronger settings
  - type: activeScan
    parameters:
      context: "CoffeeContext"
      user: "Customer-Jack"
      policy: "AggressivePolicy"
      # durations keep the run bounded
      maxRuleDurationInMins: 8
      maxScanDurationInMins: 45
    policyDefinition:
      name: "AggressivePolicy"
      defaultStrength: "High"
      defaultThreshold: "Low"
      rules: []  # add per-rule overrides here if you want

  - type: report
    parameters:
      template: "traditional-html"
      reportDir: "reports"
      reportFile: "zap-active-attack.html"
      displayReport: false
  - type: report
    parameters:
      template: "traditional-json"
      reportDir: "reports"
      reportFile: "zap-active-attack.json"
      displayReport: false
"@ | Set-Content -Encoding UTF8 .\active-attack.yaml

# 2) Run docker with host mapping and proxy bypass for local host
docker pull $ZapImage | Out-Null
docker run --rm -u root `
  --add-host=host.docker.internal:host-gateway `
  -v "${PWD}:/zap/wrk" `
  -e ZAP_API_KEY="$ApiKey" `
  -e JAVA_OPTS='-Dhttp.nonProxyHosts=localhost|127.0.0.1|host.docker.internal|*.internal' `
  -t $ZapImage `
  zap.sh -cmd -autorun "/zap/wrk/active-attack.yaml"

Write-Host "Reports written to .\reports\zap-active-attack.html / .json"
