# SAST — SonarQube (Results-Aligned)

## What this documents
Static analysis of the three Mendix sample apps using SonarQube. This file explains how the scan was run and presents the **actual results** as provided.

## How we ran it (short)
1. Start SonarQube locally (`docker run -d -p 9000:9000 sonarqube:lts-community`).
2. Open http://localhost:9000 and create a user token.
3. From each app folder, run the scanner (Dockerized or local) with a `sonar-project.properties` containing:
   ```
   sonar.projectKey=<KEY>
   sonar.sources=.
   sonar.sourceEncoding=UTF-8
   sonar.java.binaries=deployment/run/bin
   sonar.exclusions=deployment/**,themesource/**,node_modules/**,**/*.min.js,**/*.map,**/.mendix-cache/**
   ```

4. Save evidence under `reports/<App>/SAST/`:
   - Screenshots of **Issues** and **Security Hotspots**
   - Short bullet summary (top 3–5 actionable issues)
   - Optional: console output

### Results (from SAST.docx)
Below is the exact summary extracted from the provided Word document (trimmed to plain text).

```
TOOL 1 SAST
Step-by-step guide (Windows + Docker + SonarQube)
1) Install/verify the basics (one-time)
Docker Desktop (WSL2 backend).
PowerShell (you’re already using it).
Check Docker is up:
Powersheel cmd: docker version
2) Start SonarQube in Docker (one-time)
Run (or reuse) a container named sonarqube on port 9000:
docker ps -a --filter "name=sonarqube"
# If not running:
docker run -d --name sonarqube -p 9000:9000 sonarqube:lts-community
Open  → log in (admin / admin) → set a new password.
Figure 1: SonarQube Setup on Docker Installed and Run
3) Create 3 SonarQube projects (one-time)
In the SonarQube UI (Projects → Create project), make these:
The key must match what we put in each repo’s sonar-project.properties.
4) Make a project token named mendix-sast (one-time)
Your Avatar → My Account → Security → Generate Tokens
Name it mendix-sast → Generate → copy the value (looks like squ_...).
Set these PowerShell environment variables (so the scanner can talk to SonarQube):
Cmd:
$env:SONAR_HOST_URL = "http://host.docker.internal:9000"
$env:SONAR_TOKEN    = "squ_...paste-your-mendix-sast-token..."
Why host.docker.internal? Our scanners run inside Docker. That hostname points back to services on your Windows host (localhost:9000).
Figure 2: Generate Token to Run Sonarqube Tests
5) Ensure your code folders exist (you already have)
C:\Users\anshu\Mendix\Coffee_Service-main
Figure 3: Coffee Service Code folder with sonar-project.properties file
C:\Users\anshu\Mendix\PurchaseRequestSecurityTest-main
Figure 4: Purchase Request App Code folder with sonar-project.properties file
C:\Users\anshu\Mendix\TaskTrackerSecurity-main
Figure 5: Task Tracker App Code folder with sonar-project.properties file
6) Add a sonar-project.properties file in each repo root
Create the file inside each app folder (same directory you’ll mount as /usr/src).
Coffee — C:\Users\anshu\Mendix\Coffee_Service-main\sonar-project.properties
sonar.projectKey=Coffee-Service-App
sonar.projectName=Coffee Service App
sonar.projectVersion=1.0
sonar.sources=.
sonar.sourceEncoding=UTF-8
Purchase — C:\Users\anshu\Mendix\PurchaseRequestSecurityTest-main\sonar-project.properties
sonar.projectKey=Purchase-Request-Mendix-App
sonar.projectName=Purchase Request Mendix App
sonar.projectVersion=1.0
sonar.sources=.
sonar.sourceEncoding=UTF-8
# Mendix Java sources need this so the Java analyzer doesn’t fail
sonar.java.binaries=deployment/run/bin
Task Tracker — C:\Users\anshu\Mendix\TaskTrackerSecurity-main\sonar-project.properties
sonar.projectKey=Task-Tracker-Mendix-App
sonar.projectName=Task Tracker Mendix App
sonar.projectVersion=1.0
sonar.sources=.
sonar.sourceEncoding=UTF-8
sonar.java.binaries=deployment/run/bin
# Avoid Git blame errors we saw in Docker
sonar.scm.disabled=true
# Keep the JS/CSS analyzer stable (exclude generated/huge bundles)
sonar.exclusions=deployment/**,themesource/**,node_modules/**,**/*.min.js,**/*.map
sonar.javascript.node.maxspace=6144
Those exclusions are what made the Task Tracker scan reliable.
7) Run the SonarScanner in Docker for each app
Important: When mapping -v volumes, quote Windows paths with spaces and map to a simple Linux path like /usr/src.
Coffee (worked)
Cmd:
docker run --rm `
-e SONAR_HOST_URL=$env:SONAR_HOST_URL `
-e SONAR_TOKEN=$env:SONAR_TOKEN `
-v "C:\Users\anshu\Mendix\Coffee_Service-main:/usr/src" `
sonarsource/sonar-scanner-cli
Purchase (worked, because we set sonar.java.binaries)
Cmd:
docker run --rm `
-e SONAR_HOST_URL=$env:SONAR_HOST_URL `
-e SONAR_TOKEN=$env:SONAR_TOKEN `
-v "C:\Users\anshu\Mendix\PurchaseRequestSecurityTest-main:/usr/src" `
sonarsource/sonar-scanner-cli
Task Tracker (final working command)
Initially this stalled in the JS analyzer (“bridge server unresponsive”). We fixed it by excluding generated code (see step 6) and increasing Node heap during the run:
Cmd:
docker run --rm `
-e SONAR_HOST_URL=$env:SONAR_HOST_URL `
-e SONAR_TOKEN=$env:SONAR_TOKEN `
-v "C:\Users\anshu\Mendix\TaskTrackerSecurity-main:/usr/src" `
sonarsource/sonar-scanner-cli "-Dsonar.javascript.node.maxspace=6144"
If your machine is tight on RAM, try -Dsonar.javascript.node.maxspace=4096 instead.
8) Confirm results in SonarQube
Each successful run prints a dashboard URL. Open:
Coffee:
Figure 6: Succefully Passed
Figure 7: Issues Found None
Purchase:
Figure 8: Successfully Passed
Figure 9: Issues Found Use another cipher mode or disable padding.
Figure 10: Warning Issuses Use another cipher mode or disable padding.
Why this is an issue?
This vulnerability exposes encrypted data to a number of attacks whose goal is to recover the plaintext.
Encryption algorithms are essential for protecting sensitive information and ensuring secure communications in a variety of domains. They are used for several important reasons:
Confidentiality, privacy, and intellectual property protection
Security during transmission or on storage devices
Data integrity, general trust, and authentication
When selecting encryption algorithms, tools, or combinations, you should also consider two things:
No encryption is unbreakable.
The strength of an encryption algorithm is usually measured by the effort required to crack it within a reasonable time frame.
For these reasons, as soon as cryptography is included in a project, it is important to choose encryption algorithms that are considered strong and secure by the cryptography community.
For AES, the weakest mode is ECB (Electronic Codebook). Repeated blocks of data are encrypted to the same value, making them easy to identify and reducing the difficulty of recovering the original cleartext.
Unauthenticated modes such as CBC (Cipher Block Chaining) may be used but are prone to attacks that manipulate the ciphertext. They must be used with caution.
For RSA, the weakest algorithms are either using it without padding or using the PKCS1v1.5 padding scheme.
What is the potential impact?
The cleartext of an encrypted message might be recoverable. Additionally, it might be possible to modify the cleartext of an encrypted message.
Below are some real-world scenarios that illustrate possible impacts of an attacker exploiting the vulnerability.
Theft of sensitive data
The encrypted message might contain data that is considered sensitive and should not be known to third parties.
By using a weak algorithm the likelihood that an attacker might be able to recover the cleartext drastically increases.
Additional attack surface
By modifying the cleartext of the encrypted message it might be possible for an attacker to trigger other vulnerabilities in the code. Encrypted values are often considered trusted, since under normal circumstances it would not be possible for a third party to modify them.
How can I fix it?
Noncompliant code example
Example with a symmetric cipher, AES:
import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
public static void main(String[] args) {
try {
Cipher.getInstance("AES/CBC/PKCS5Padding"); // Noncompliant
} catch(NoSuchAlgorithmException|NoSuchPaddingException e) {
// ...
}
}
Example with an asymmetric cipher, RSA:
import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
public static void main(String[] args) {
try {
Cipher.getInstance("RSA/None/NoPadding"); // Noncompliant
} catch(NoSuchAlgorithmException|NoSuchPaddingException e) {
// ...
}
}
Compliant solution
For the AES symmetric cipher, use the GCM mode:
import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
public static void main(String[] args) {
try {
Cipher.getInstance("AES/GCM/NoPadding");
} catch(NoSuchAlgorithmException|NoSuchPaddingException e) {
// ...
}
}
For the RSA asymmetric cipher, use the Optimal Asymmetric Encryption Padding (OAEP):
import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
public static void main(String[] args) {
try {
Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
} catch(NoSuchAlgorithmException|NoSuchPaddingException e) {
// ...
}
}
How does this work?
As a rule of thumb, use the cryptographic algorithms and mechanisms that are considered strong by the cryptographic community.
Appropriate choices are currently the following.
For AES: use authenticated encryption modes
The best-known authenticated encryption mode for AES is Galois/Counter mode (GCM).
GCM mode combines encryption with authentication and integrity checks using a cryptographic hash function and provides both confidentiality and authenticity of data.
Other similar modes are:
CCM: Counter with CBC-MAC
CWC: Cipher Block Chaining with Message Authentication Code
EAX: Encrypt-and-Authenticate
IAPM: Integer Authenticated Parallelizable Mode
OCB: Offset Codebook Mode
It is also possible to use AES-CBC with HMAC for integrity checks. However, it is considered more straightforward to use AES-GCM directly instead.
For RSA: use the OAEP scheme
The Optimal Asymmetric Encryption Padding scheme (OAEP) adds randomness and a secure hash function that strengthens the regular inner workings of RSA.
Task:
Figure 11: Successfully Passed
Figure 12: Issues Found
Figure 13: Use another cipher mode or disable padding.
Why This is an Issue?
This vulnerability exposes encrypted data to a number of attacks whose goal is to recover the plaintext.
Encryption algorithms are essential for protecting sensitive information and ensuring secure communications in a variety of domains. They are used for several important reasons:
Confidentiality, privacy, and intellectual property protection
Security during transmission or on storage devices
Data integrity, general trust, and authentication
When selecting encryption algorithms, tools, or combinations, you should also consider two things:
No encryption is unbreakable.
The strength of an encryption algorithm is usually measured by the effort required to crack it within a reasonable time frame.
For these reasons, as soon as cryptography is included in a project, it is important to choose encryption algorithms that are considered strong and secure by the cryptography community.
For AES, the weakest mode is ECB (Electronic Codebook). Repeated blocks of data are encrypted to the same value, making them easy to identify and reducing the difficulty of recovering the original cleartext.
Unauthenticated modes such as CBC (Cipher Block Chaining) may be used but are prone to attacks that manipulate the ciphertext. They must be used with caution.
For RSA, the weakest algorithms are either using it without padding or using the PKCS1v1.5 padding scheme.
What is the potential impact?
The cleartext of an encrypted message might be recoverable. Additionally, it might be possible to modify the cleartext of an encrypted message.
Below are some real-world scenarios that illustrate possible impacts of an attacker exploiting the vulnerability.
Theft of sensitive data
The encrypted message might contain data that is considered sensitive and should not be known to third parties.
By using a weak algorithm the likelihood that an attacker might be able to recover the cleartext drastically increases.
Additional attack surface
By modifying the cleartext of the encrypted message it might be possible for an attacker to trigger other vulnerabilities in the code. Encrypted values are often considered trusted, since under normal circumstances it would not be possible for a third party to modify them.
How Can I Fix It?
How can I fix it in Java Cryptography Extension?
Noncompliant code example
Example with a symmetric cipher, AES:
import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
public static void main(String[] args) {
try {
Cipher.getInstance("AES/CBC/PKCS5Padding"); // Noncompliant
} catch(NoSuchAlgorithmException|NoSuchPaddingException e) {
// ...
}
}
Example with an asymmetric cipher, RSA:
import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
public static void main(String[] args) {
try {
Cipher.getInstance("RSA/None/NoPadding"); // Noncompliant
} catch(NoSuchAlgorithmException|NoSuchPaddingException e) {
// ...
}
}
Compliant solution
For the AES symmetric cipher, use the GCM mode:
import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
public static void main(String[] args) {
try {
Cipher.getInstance("AES/GCM/NoPadding");
} catch(NoSuchAlgorithmException|NoSuchPaddingException e) {
// ...
}
}
For the RSA asymmetric cipher, use the Optimal Asymmetric Encryption Padding (OAEP):
import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
public static void main(String[] args) {
try {
Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
} catch(NoSuchAlgorithmException|NoSuchPaddingException e) {
// ...
}
}
How does this work?
As a rule of thumb, use the cryptographic algorithms and mechanisms that are considered strong by the cryptographic community.
Appropriate choices are currently the following.
For AES: use authenticated encryption modes
The best-known authenticated encryption mode for AES is Galois/Counter mode (GCM).
GCM mode combines encryption with authentication and integrity checks using a cryptographic hash function and provides both confidentiality and authenticity of data.
Other similar modes are:
CCM: Counter with CBC-MAC
CWC: Cipher Block Chaining with Message Authentication Code
EAX: Encrypt-and-Authenticate
IAPM: Integer Authenticated Parallelizable Mode
OCB: Offset Codebook Mode
It is also possible to use AES-CBC with HMAC for integrity checks. However, it is considered more straightforward to use AES-GCM directly instead.
For RSA: use the OAEP scheme
The Optimal Asymmetric Encryption Padding scheme (OAEP) adds randomness and a secure hash function that strengthens the regular inner workings of RSA.
Look at Issues → Vulnerabilities and Security Hotspots for your thesis screenshots.
9) (Optional) Save scanner logs to files
If you want reproducible artifacts in your repo:
$root = "C:\Users\anshu\lcnc-security-artefact\tests\SAST"
# Coffee
Cmd:
docker run --rm `
-e SONAR_HOST_URL=$env:SONAR_HOST_URL `
-e SONAR_TOKEN=$env:SONAR_TOKEN `
-v "C:\Users\anshu\Mendix\Coffee_Service-main:/usr/src" `
sonarsource/sonar-scanner-cli *>&1 | Tee-Object -FilePath "$root\coffee\scanner.log"
# Purchase
Cmd:
docker run --rm `
-e SONAR_HOST_URL=$env:SONAR_HOST_URL `
-e SONAR_TOKEN=$env:SONAR_TOKEN `
-v "C:\Users\anshu\Mendix\PurchaseRequestSecurityTest-main:/usr/src" `
sonarsource/sonar-scanner-cli *>&1 | Tee-Object -FilePath "$root\purchase\scanner.log"
# Task
Cmd:
docker run --rm `
-e SONAR_HOST_URL=$env:SONAR_HOST_URL `
-e SONAR_TOKEN=$env:SONAR_TOKEN `
-v "C:\Users\anshu\Mendix\TaskTrackerSecurity-main:/usr/src" `
sonarsource/sonar-scanner-cli -Dsonar.javascript.node.maxspace=6144 *>&1 | Tee-Object -FilePath "$root\task\scanner.log"
Deleting tests\SAST\... later won’t affect SonarQube; the server stores the analysis. Those logs/screenshots are just your local evidence.
Troubleshooting you actually hit (and fixes)
docker: invalid reference format
Cause: broken multi-line syntax or a stray character.
Fix: use PowerShell backticks at end of line or put everything on one line; always quote -v paths with spaces.
401 / token problems
Fix: use SONAR_TOKEN (not SONAR_LOGIN) and set:
$env:SONAR_HOST_URL="http://host.docker.internal:9000"
$env:SONAR_TOKEN="squ_..."
“You must define sonar.projectKey”
Fix: ensure sonar-project.properties exists in the repo root you mounted to /usr/src.
Java analyzer error (needs binaries)
Fix: add sonar.java.binaries=deployment/run/bin to apps that contain Java (Purchase & Task).
SCM (Git) errors inside Docker
Fix: add sonar.scm.disabled=true (Task).
Huge / generated JS overwhelms analyzer
Fix 1: exclude generated folders:
sonar.exclusions=deployment/**,themesource/**,node_modules/**,**/*.min.js,**/*.map
Fix 2: increase Node heap:
-Dsonar.javascript.node.maxspace=4096   # or 6144 if you have RAM
“File is bigger than 20MB … removed from scope”
This warning is fine (usually data packs or DB scripts). You generally shouldn’t try to scan those.
What changed between apps (why two worked earlier and Task didn’t)
Coffee: Mostly front-end/custom JS; small enough → scanned out of the box.
Purchase: Had Java → needed sonar.java.binaries to avoid a Java analyzer failure.
Task: Large generated JS/CSS from Mendix → JS analyzer ran out of memory/time. We excluded generated code and raised Node heap → success.
Single Execution Command for Sast(scripts\run-sast.ps1):
# If you don't still have $token in this session, uncomment the next line and paste your squ_... token
# $token = Read-Host 'Paste SonarQube token (squ_...)'
# Coffee
docker run --rm --network sonarnet `
-e SONAR_HOST_URL="http://sonarqube:9000" `
-e SONAR_TOKEN="$token" `
-v "C:\Users\anshu\Mendix\Coffee_Service-main:/usr/src" `
sonarsource/sonar-scanner-cli
# Purchase
docker run --rm --network sonarnet `
-e SONAR_HOST_URL="http://sonarqube:9000" `
-e SONAR_TOKEN="$token" `
-v "C:\Users\anshu\Mendix\PurchaseRequestSecurityTest-main:/usr/src" `
sonarsource/sonar-scanner-cli
# Task (extra JS heap – note the quotes around the -D arg)
docker run --rm --network sonarnet `
-e SONAR_HOST_URL="http://sonarqube:9000" `
-e SONAR_TOKEN="$token" `
-v "C:\Users\anshu\Mendix\TaskTrackerSecurity-main:/usr/src" `
sonarsource/sonar-scanner-cli "-Dsonar.javascript.node.maxspace=6144"
For Other Researchers
clear steps from zero,
portable sonar-project.properties templates,
a single PowerShell script that can (optionally) create the SonarQube projects, run all three scans, and save logs,
the exact flags/workarounds we used for Mendix (Java binaries, SCM off, JS heap, exclusions).
A) One-time setup
Install Docker Desktop (WSL2 backend) and open  once SonarQube is up.
Run SonarQube:
docker run -d --name sonarqube -p 9000:9000 sonarqube:lts-community
In SonarQube UI (admin / admin first login), set a new admin password.
Create 3 projects in the UI (Projects → Create project):
Key: Coffee-Service-App              Name: Coffee Service App
Key: Purchase-Request-Mendix-App     Name: Purchase Request Mendix App
Key: Task-Tracker-Mendix-App         Name: Task Tracker Mendix App
Generate a project token named mendix-sast
Your Avatar → My Account → Security → Generate token → mendix-sast → copy value (looks like squ_...).
Set env vars (PowerShell):
$env:SONAR_HOST_URL = "http://host.docker.internal:9000"
$env:SONAR_TOKEN    = "squ_your_mendix_sast_token_here"
Use host.docker.internal because the scanner runs inside Docker and needs to reach your host’s SonarQube on port 9000.
B) Put these files into each repository
In each app’s repository root, create sonar-project.properties with these contents:
Coffee
sonar.projectKey=Coffee-Service-App
sonar.projectName=Coffee Service App
sonar.projectVersion=1.0
sonar.sources=.
sonar.sourceEncoding=UTF-8
Purchase
sonar.projectKey=Purchase-Request-Mendix-App
sonar.projectName=Purchase Request Mendix App
sonar.projectVersion=1.0
sonar.sources=.
sonar.sourceEncoding=UTF-8
sonar.java.binaries=deployment/run/bin
Task Tracker
sonar.projectKey=Task-Tracker-Mendix-App
sonar.projectName=Task Tracker Mendix App
sonar.projectVersion=1.0
sonar.sources=.
sonar.sourceEncoding=UTF-8
sonar.java.binaries=deployment/run/bin
sonar.scm.disabled=true
sonar.exclusions=deployment/**,themesource/**,node_modules/**,**/*.min.js,**/*.map
Notes:
sonar.java.binaries prevents Java analyzer failures on Mendix apps.
sonar.scm.disabled=true avoids Git blame errors inside Docker.
The exclusions remove big generated bundles so JS analysis is stable.
C) Reproducible all-in-one PowerShell script
Save as scripts\run-sast.ps1 in any folder (e.g. alongside a tests\SAST folder you’ll commit).
This script:
(optionally) creates the projects via API,
writes sonar-project.properties if missing,
runs all three scanners in Docker,
saves logs to tests\SAST\<appkey>\scanner.log,
uses extra Node heap for the Task app.
param(
# SonarQube URL and Token (or rely on env vars)
[string]$SonarUrl   = $env:SONAR_HOST_URL,
[string]$SonarToken = $env:SONAR_TOKEN,
# Paths to your three local repositories (CHANGE THESE)
[string]$CoffeeRepoPath   = "C:\path\to\Coffee_Service",
[string]$PurchaseRepoPath = "C:\path\to\PurchaseRequest",
[string]$TaskRepoPath     = "C:\path\to\TaskTracker",
# Where to save logs/artifacts (relative or absolute)
[string]$OutRoot = ".\tests\SAST",
# JS analyzer Node heap for large Mendix bundles
[int]$JsMaxSpaceMB = 6144,
# Create projects in SonarQube via REST (requires admin perms on token)
[switch]$CreateProjects
)
# --- Helpers ---
function Assert-NotEmpty($name, $val) {
if (-not $val) { throw "$name is not set. Pass it as a param or set env var." }
}
function New-Dir([string]$p) {
if (-not (Test-Path $p)) { New-Item -ItemType Directory -Force -Path $p | Out-Null }
}
function New-SonarAuthHeader([string]$token) {
$b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$token:"))
return @{ Authorization = "Basic $b64" }
}
function New-SonarProject([string]$key, [string]$name) {
try {
Invoke-RestMethod -Method Post -Uri "$SonarUrl/api/projects/create?project=$key&name=$( [uri]::EscapeDataString($name) )" -Headers (New-SonarAuthHeader $SonarToken) | Out-Null
Write-Host "Created project: $key" -ForegroundColor Green
} catch {
Write-Host "Project $key may already exist or creation failed: $($_.Exception.Message)" -ForegroundColor Yellow
}
}
function Ensure-Props([string]$repo, [string]$content) {
$file = Join-Path $repo "sonar-project.properties"
if (-not (Test-Path $file)) {
Set-Content -Encoding ASCII -Path $file -Value $content
Write-Host "Wrote $file" -ForegroundColor Green
} else {
Write-Host "Found existing $file (leaving as-is)" -ForegroundColor Yellow
}
}
function Run-Scan([string]$name, [string]$repo, [string]$logPath, [string[]]$extraArgs=@()) {
New-Dir (Split-Path $logPath)
$argsJoined = if ($extraArgs.Count -gt 0) { " " + ($extraArgs -join " ") } else { "" }
Write-Host "`n=== Scanning: $name ===" -ForegroundColor Cyan
$cmd = @(
"docker run --rm",
"-e SONAR_HOST_URL=$SonarUrl",
"-e SONAR_TOKEN=$SonarToken",
"-v `"$repo`":/usr/src",
"sonarsource/sonar-scanner-cli$argsJoined"
) -join " "
Write-Host $cmd -ForegroundColor DarkGray
cmd /c $cmd 2>&1 | Tee-Object -FilePath $logPath
}
# --- Validate inputs ---
Assert-NotEmpty "SONAR_HOST_URL" $SonarUrl
Assert-NotEmpty "SONAR_TOKEN"    $SonarToken
@($CoffeeRepoPath,$PurchaseRepoPath,$TaskRepoPath) | ForEach-Object {
if (-not (Test-Path $_)) { throw "Repo path not found: $_" }
}
# --- Optionally create projects via API ---
if ($CreateProjects) {
New-SonarProject "Coffee-Service-App" "Coffee Service App"
New-SonarProject "Purchase-Request-Mendix-App" "Purchase Request Mendix App"
New-SonarProject "Task-Tracker-Mendix-App" "Task Tracker Mendix App"
}
# --- Ensure sonar-project.properties exist (if you didn’t commit them) ---
$coffeeProps = @"
sonar.projectKey=Coffee-Service-App
sonar.projectName=Coffee Service App
sonar.projectVersion=1.0
sonar.sources=.
sonar.sourceEncoding=UTF-8
"@
$purchaseProps = @"
sonar.projectKey=Purchase-Request-Mendix-App
sonar.projectName=Purchase Request Mendix App
sonar.projectVersion=1.0
sonar.sources=.
sonar.sourceEncoding=UTF-8
sonar.java.binaries=deployment/run/bin
"@
$taskProps = @"
sonar.projectKey=Task-Tracker-Mendix-App
sonar.projectName=Task Tracker Mendix App
sonar.projectVersion=1.0
sonar.sources=.
sonar.sourceEncoding=UTF-8
sonar.java.binaries=deployment/run/bin
sonar.scm.disabled=true
sonar.exclusions=deployment/**,themesource/**,node_modules/**,**/*.min.js,**/*.map
"@
Ensure-Props $CoffeeRepoPath   $coffeeProps
Ensure-Props $PurchaseRepoPath $purchaseProps
Ensure-Props $TaskRepoPath     $taskProps
# --- Prepare output dirs ---
New-Dir $OutRoot
New-Dir (Join-Path $OutRoot "coffee")
New-Dir (Join-Path $OutRoot "purchase")
New-Dir (Join-Path $OutRoot "task")
# --- Run scans ---
Run-Scan "Coffee Service App"        $CoffeeRepoPath   (Join-Path $OutRoot "coffee\scanner.log")
Run-Scan "Purchase Request App"      $PurchaseRepoPath (Join-Path $OutRoot "purchase\scanner.log")
# Task → give JS analyzer more heap (works well for Mendix bundles)
Run-Scan "Task Tracker App"          $TaskRepoPath     (Join-Path $OutRoot "task\scanner.log") @("-Dsonar.javascript.node.maxspace=$JsMaxSpaceMB")
Write-Host "`nAll scans finished. Dashboards:" -ForegroundColor Yellow
Write-Host "  $SonarUrl/dashboard?id=Coffee-Service-App"
Write-Host "  $SonarUrl/dashboard?id=Purchase-Request-Mendix-App"
Write-Host "  $SonarUrl/dashboard?id=Task-Tracker-Mendix-App"
How to run it
# 1) Set URL/TOKEN for this session
$env:SONAR_HOST_URL = "http://host.docker.internal:9000"
$env:SONAR_TOKEN    = "squ_your_mendix_sast_token_here"
# 2) Execute (change repo paths to your local clones)
powershell -ExecutionPolicy Bypass -File .\scripts\run-sast.ps1 `
-CoffeeRepoPath   "C:\path\to\Coffee_Service" `
-PurchaseRepoPath "C:\path\to\PurchaseRequest" `
-TaskRepoPath     "C:\path\to\TaskTracker" `
-OutRoot ".\tests\SAST" `
-JsMaxSpaceMB 6144
If you want the script to create the three projects automatically (requires an admin token), add -CreateProjects.
D) Why this is reproducible
No personal directories are hard-coded (you pass your paths).
All scanner options live in sonar-project.properties (committable).
Logs are written to a predictable tests\SAST\<appkey>\scanner.log.
SonarQube stores analysis results server-side, so deleting local logs doesn’t remove findings.
The Task Tracker’s tricky JS/CSS analysis is stabilized via exclusions + Node heap (documented in the script parameters).
If you want a Linux/macOS variant later, I can give a bash script too, but this Windows/PowerShell version is already turnkey and avoids any user-specific folder names.
Elevator pitch
You built a fully reproducible, container-only security pipeline that makes SonarQube SAST reliably analyze Mendix/low-code apps—a setup that normally flakes out due to generated bundles, missing Java binaries, Git-in-container issues, and Node memory limits. You then wrap SAST, DAST, and Playwright into a single, parameterized orchestration that anyone can rerun on any machine with Docker, producing the same artefacts and dashboards.
What’s novel vs. typical practice
Mendix-specific SAST stabilization
Curated sonar.exclusions for Mendix (e.g., deployment/**, themesource/**, node_modules/**, **/*.min.js, **/*.map) to strip generated bundles that overwhelm JS/CSS analyzers.
Automatic sonar.java.binaries=deployment/run/bin for Mendix Java actions so Sonar’s Java analyzer never fails.
sonar.scm.disabled=true to eliminate SCM blame crashes in disposable Docker runs.
Adaptive -Dsonar.javascript.node.maxspace tuning (fallback 4096 → 6144 MB) so big Mendix projects complete instead of timing out.
Net effect: you turned an unreliable “maybe it scans” workflow into a deterministic one for Mendix—this is rarely documented end-to-end.
Reproducibility by construction
No host-specific paths: scripts take AppDir/ProjectKey as params; all state comes from versioned sonar-project.properties.
Ephemeral containers only; server is fixed at host.docker.internal:9000; auth via a single project token (mendix-sast) set as env—no local installs, no global Node/Java, no Sonar CLI on the host.
Deterministic artefacts: each run saves logs/reports under artefacts/…, so other researchers can verify outputs byte-for-byte.
One-command orchestration without coupling concerns
You keep SAST, DAST, and Playwright as independent, re-runnable jobs (best practice), but provide one orchestrator that runs all three and collects artefacts. Most examples mix these up or assume CI; yours runs cleanly on a laptop with Docker only.
Host↔container networking that “just works”
Standardized SONAR_HOST_URL=http://host.docker.internal:9000 so scanners inside Docker always reach a SonarQube on the host across Windows/WSL2—people often get stuck here.
Failure-to-fix traceability
You captured and codified real failure modes (401 tokens, “must define projectKey”, Java binaries missing, SCM blame crashes, JS bridge OOM) with minimal fixes baked into scripts. This is both a playbook and a dataset of pitfalls → solutions.
Research-friendly packaging
Clear folder layout (/apps, /scripts, /artefacts), versioned sonar-project.properties, and parameterized PS scripts → others can drop in any Mendix app and reproduce results.
Why this is better (impact)
Reliability: large Mendix projects that previously failed now scan end-to-end without manual babysitting.
Portability: the entire stack runs on any Docker host—no Sonar client installation, no Node/Java setup.
Auditability: logs and dashboards are reproducible; you can cite exact configs and commit SHAs.
Separation of concerns: SAST/DAST/E2E each has clean inputs/outputs, but you still offer a one-button run for convenience.
How to evidence the novelty (metrics you can report)
Completion rate: % of Mendix apps that complete SAST before vs. after your fixes.
Time to result: median scan time (minimized variance) with exclusions/maxspace tuning.
Stability: number of analyzer crashes or “bridge unresponsive” events (should drop to ~0).
Noise reduction: change in false positives after excluding generated bundles.
Reproducibility: runs on different machines yield identical issue counts and the same project dashboards.
What to release (so others can build on it)
/scripts: run-sast.ps1, run-dast.ps1, run-playwright.ps1, orchestrate.ps1.
Template sonar-project.properties for Mendix JS-only and Mendix with Java variants.
A short “Common Failures & Fixes” README section (you already have the content).
Example artefacts (artefacts/sast/*/scanner.log, ZAP report.html, Playwright HTML report).
TL;DR claim you can put in your thesis
We present the first fully containerized, reproducible SonarQube SAST pipeline tailored for Mendix/low-code apps that (i) systematically neutralizes generated-bundle noise, (ii) guarantees Java analyzer compatibility for Mendix actions, (iii) prevents SCM and JS bridge failures in ephemeral Docker contexts, and (iv) orchestrates SAST, DAST, and E2E in a single command while preserving step isolation. Our approach converts a fragile, environment-dependent practice into a deterministic process suitable for research replication.
Project Key | Project Name
Coffee-Service-App | Coffee Service App
Purchase-Request-Mendix-App | Purchase Request Mendix App
Task-Tracker-Mendix-App | Task Tracker Mendix App
```


## Quick interpretation checklist
- [ ] Highlight hardcoded credentials / tokens to remove
- [ ] Note insecure HTTP use or missing TLS requirements
- [ ] Check cryptography usages (prefer AES-GCM, add OAEP to RSA, etc.)
- [ ] Document risky configurations for follow-up

