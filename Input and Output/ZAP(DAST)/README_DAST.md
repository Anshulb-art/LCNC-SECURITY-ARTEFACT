# DAST — OWASP ZAP  (Manual)

## What this documents
Runtime checks against the locally running apps. This file pairs the step-by-step process with the **actual manual/baseline findings** you provided.

## How we ran it (short)
**Manual checks (authenticated):** login with demo users and verify:
- RBAC negatives (restricted actions must be denied)
- IDOR sanity (tweaked IDs must not leak other users' data)
- API calls without auth → 401/403
- Core headers and cookie flags
- Active ScanS


### Results (from DAST new.docx)
Below is the exact summary extracted from the provided Word document (trimmed to plain text).

```
DAST-Dynamic Application Security Testing
I use Owasp-Zap to do to DAST.
Zap Proxy Settings- FoxyProxy:
Fig 1: Zap Proxy Setting Using Foxy Proxy
Figure 2: Postman For all API endpoints test manually
APPLICATION 1: Coffee Service
Fig 2: User Roles to do security tests.
I) Authentication Security Testing
A) Login Brute Force
Goal
To determine whether the application’s authentication mechanism is vulnerable to brute-force attacks—specifically, to check if it enforces account lockout or other defenses against repeated failed login attempts.
Tool Used
OWASP ZAP Fuzzer
Methodology and Figure Analysis
Step 1: Fuzzing the Login Endpoint
How:
Using ZAP, the login request was intercepted and the password parameter was selected for fuzzing. A wordlist of common passwords was used to simulate an attacker making multiple login attempts in quick succession.
Figure 3: Fuzz Attack Performed
Depicts the ZAP Fuzzer interface as it runs the brute-force attack on the login endpoint.
Step 2: Testing with Valid Credentials
How:
login attempt was made using the correct username and password to establish the baseline for a successful authentication.
Figure 4: Login with Correct Credentials –
Request
Shows the HTTP login request with valid credentials as seen in ZAP.
Figure 5: 200 OK Response with CSRF Token – Response Displays the server’s HTTP 200 OK response for the valid login, highlighting the presence of a CSRF token in the response, indicating successful session establishment.
Step 3: Testing with Invalid Credentials
How:
login attempt was made using an incorrect password to observe the application’s response to failed authentication.
Figure 6: Login with Incorrect Password – 401 Unauthorized Request Shows the HTTP login request with an invalid password
Figure 7: Response to Incorrect Password
Displays the server’s HTTP 401 Unauthorized response, confirming the login attempt failed.
Results
Fuzzing with multiple invalid passwords did not result in any account lockout, CAPTCHA, or rate-limiting response from the application.
The server returned a 200 OK response only for the correct credentials, and a 401 Unauthorized for invalid passwords.
However, there was no evidence of brute-force mitigation controls (such as temporary lockout or delay after multiple failed attempts).
Security Impact
Strength: The application does not accept incorrect credentials and issues proper status codes for failed logins.
Weakness: The absence of brute-force protection makes the application vulnerable to automated password guessing attacks, increasing the risk of credential stuffing and unauthorized access.
Conclusion and Recommendations
While the application enforces correct authentication validation, it currently lacks mechanisms to detect or prevent brute-force attacks.
Recommendation:
Implement account lockout, rate limiting, or CAPTCHA challenges after multiple failed login attempts to enhance protection against brute-force threats.
B) Session Fixation/Reuse Attack (OWASP A07)
Objective
The objective of this test is to determine whether the application is vulnerable to session fixation or session reuse attacks. These attacks occur when an attacker is able to hijack a user’s authenticated session by reusing or injecting a session identifier (such as a session cookie), thereby bypassing normal authentication procedures. Secure applications should ensure session tokens are unique, securely generated, and tied to both the user's session and context.
Methodology
Tested Standard:
OWASP Top 10 – A07: Identification and Authentication Failures ● Tools Used:
OWASP ZAP Proxy (for intercepting and extracting session cookies)
Chrome DevTools (for manipulating cookies in a browser session)
Testing Steps and Figure Analysis
Step 1: User Authentication and Session Extraction
How:
Logged in to the application as a valid user (Customer Roxanne). Used OWASP ZAP to capture the session cookie (XASSESSIONID) issued upon successful authentication.
Figure 8: Extracted Session Cookie from ZAP
Shows the captured session cookie (XASSESSIONID) in ZAP’s HTTP History or Cookie tab, confirming session establishment.
Step 2: Manual Session Reuse Attempt in a Separate Browser
How:
Opened a new browser window or incognito session to simulate a different user or device.
Used Chrome DevTools to manually insert the previously extracted session cookie (XASSESSIONID) into the new browser session.
Figure 9: Setting Session Cookie in Chrome DevTools Displays the process of manually editing the session
cookie value in the browser’s developer tools.
Accessing Protected Resources:
Step 3: Accessing Protected Resources
How:
Attempted to access authenticated or protected resources/pages in the application using the manually set session cookie in the new browser window.
Figure 10: Attempt to Access Protected Resource with Fixed Session
Shows the result after attempting to use the fixed session cookie to access a protected page.
Results
When the extracted session cookie was set in a new browser session and used to access
protected resources, the application redirected to the login page or denied access, rather than granting authenticated access.
This behavior demonstrates that the application’s session management mechanism does not allow session cookies to be reused across browser sessions or devices.
C) Authentication Bypass
Objective
The objective of this test is to evaluate whether the application is vulnerable to authentication bypass attacks. Specifically, the test determines if protected resources
or pages can be accessed directly without prior authentication, potentially allowing unauthorized users to gain access to sensitive functionality.
Methodology
Tested Standard:
OWASP Top 10 – A07: Identification and Authentication Failures
Testing Tool:
OWASP ZAP Proxy (Spider Functionality)
Testing Steps:
1. Unauthenticated Spidering:
o 	Launched the OWASP ZAP Spider tool as an unauthenticated (logged- out) user. o 	Crawled the target application to enumerate all accessible endpoints and resources.
Figure 11: ZAP Spider Results for Unauthenticated User
Analysis of Discovered Resources:
Reviewed the list of discovered files, directories, and endpoints.
Verified whether any protected or sensitive pages (such as /dashboard, /admin, or user-specific resources) were accessible without authentication.
Figure 12: HTTP Response for Attempted Access to Protected Page
The ZAP Spider was only able to discover static assets and public files (/robots.txt,
/sitemap.xml, static images, CSS, JS) as an unauthenticated user. No restricted application pages (such as /dashboard or /admin) were accessible, indicating proper access control is enforced for sensitive routes.
Results and Analysis
The ZAP Spider, when operated without authentication, was able to discover only static and public resources (including /robots.txt, /sitemap.xml, images, CSS, and JavaScript files).
No restricted or sensitive application pages were accessible or exposed in the crawl results.
Attempts to directly access protected endpoints without valid authentication were unsuccessful; the application enforced proper access controls and did not reveal or permit access to any restricted functionality.
Conclusion
The application effectively implements access control mechanisms for sensitive resources. No authentication bypass vulnerabilities were identified during testing. All protected routes remain inaccessible to unauthenticated users, demonstrating compliance with secure authentication and authorization best practices.
II) RBAC & IDOR Testing
A) RBAC Flaws (Role-Based Access Control)
To verify that the application properly enforces role-based access control, preventing users from accessing resources, pages, or functionalities not permitted by their assigned roles.
Methodology
Tested Standard:
OWASP Top 10 – A01: Broken Access Control Testing Tool:
OWASP ZAP (Manual navigation and request replay) Testing Steps:
1. Role Identification and Access Recording:
o 	Logged in as each available user role (Requester, Approver, Admin). o 	Navigated the application and documented all accessible URLs and functionalities for each role.
Fig: Customer Jack Dashboard
Fig: Customer Jack Task
Fig New Task Added through Customer Jack Dashboard
Cross-Role Access Attempts:
While authenticated as a lower-privileged user (e.g., Requester), manually attempted to access URLs and resources intended only for higher-privileged roles (e.g., Approver or Admin).
Monitored application behavior and HTTP responses to determine if unauthorized access was possible.
Figure: Tried To access Engineer Bill
Figure 13: Access Denied Response for Unauthorized Role
Role-based access control was tested by logging in as each user role and recording accessible URLs. Attempts to access role-restricted pages (e.g., Approver or Admin- only URLs) while logged in as a different, lower-privilege role resulted in access denied or redirection to the login page.
Conclusion: The application correctly enforced access restrictions. No RBAC vulnerabilities were identified in these tests.
Results and Analysis
All attempts by users to access role-restricted pages or resources resulted in either an "Access Denied" message or a redirection to the login page.
The application correctly enforced RBAC, ensuring users could only access data and functions appropriate to their roles.
No RBAC vulnerabilities were identified during testing.
B) IDOR (Insecure Direct Object Reference)
Objective
To assess whether users can access or manipulate data objects (such as user profiles or records) belonging to other users by tampering with object references (IDs) in the request.
Methodology
Tested Standard:
OWASP Top 10 – A01: Broken Access Control Testing Tool:
OWASP ZAP (Fuzz functionality) Testing Steps:
Parameter Identification:
While logged in as a low-privileged user (Requester), identified a request parameter (profiledata value) suspected of referencing user-specific data.
Fuzz Testing:
Used OWASP ZAP to perform fuzzing on the profiledata value parameter, systematically substituting values from 21 to 900 to simulate attempts to access other users' data.
1. Response Analysis:
o 	Monitored the server’s responses for each fuzzed request to detect whether any unauthorized or sensitive data was returned. Results and Analysis
All fuzzed requests returned an HTTP 200 OK status with an empty JSON object ({}), and no unauthorized or sensitive data was disclosed for any of the tested ID values.
No IDOR vulnerability was detected on the tested endpoint with the parameters and payloads used.
Fig: Profile data of Customer Roxanne
Fig: Request response of engineer bill
Add payload settings to engineer bill
Fig: Added payload and Started the fuzzer
Fig: 200 ok Status
IDOR Fuzz Testing Results:
"I performed fuzzing on the profiledata value parameter using OWASP ZAP, with payloads ranging from 21 to 900 while logged in as a low-privilege user
(Requester). For all requests, the server responded with a 200 OK status and an empty JSON object ({}), and no unauthorized or sensitive data was returned for any tested ID values.
Conclusion: No IDOR vulnerability was detected on this endpoint with the tested parameters."
3. 	API Security & Input Validation
A) Unauthenticated 	API 	Access
(OWASP A01: Broken Access Control)
Objective
To assess whether API endpoints are accessible without valid authentication tokens or cookies, which could allow unauthorized users to interact with sensitive backend logic.
Methodology
Standard Referenced: OWASP Top 10 – A01: Broken Access Control
Tools Used: OWASP ZAP, Browser Developer Tools
Step-by-Step Test Procedure and Figure Analysis
1. Baseline Request in Authenticated Session
o 	How: Logged in as a valid user and captured an API request to the endpoint, verifying all required tokens and cookies were present.
Figure 1: Initial API Request in an Authenticated Session
Displays the API request as sent by an authenticated user, confirming the normal flow with all authentication tokens and cookies.
Capturing the Endpoint in ZAP
How: Used ZAP to intercept and analyze the structure of the authenticated API request for further manipulation.
Figure 2: Capturing API Endpoint via ZAP
Demonstrates the captured API endpoint and associated request in ZAP for analysis.
Identifying the API Endpoint in Browser
How: Used browser Developer Tools (F12, Network tab) to identify the endpoint and confirm real-time request flow.
Figure 3: Discovery of API Endpoint via Browser Network Tab (F12)
Illustrates how the actual API endpoint was found using browser dev tools.
Simulating Unauthenticated Access
How: Deleted authentication cookies and session tokens in the request within ZAP’s Manual Request Editor.
Figure 4: Manual Deletion of Authentication Cookie
Shows the request with authentication details stripped, simulating an
unauthenticated user.unauthenticated request.
Figure 5: API Request Without Authentication Cookie
Presents the crafted API request sent without any authentication tokens or cookies.
Figure 6: API Response to Unauthenticated Request
Displays the server’s response to an unauthenticated API request. In this case, the server responded with HTTP 200 OK and issued a CSRF token, even though authentication cookies were missing.
Tested Endpoint:
POST
Result: Received 200 OK and a CSRF token response even without authentication cookies.
Risk: If subsequent API requests can be made with this CSRF token alone, it indicates unauthenticated access to backend logic—a critical security risk under OWASP A01: Broken Access Control.
B) Injection Vulnerabilities (OWASP A03: Injection)
Objective
To detect vulnerabilities such as Cross-Site Scripting (XSS), SQL Injection, or Command Injection in the application’s API endpoints.
Methodology
Standard Referenced: OWASP Top 10 – A03: Injection
Tool Used: OWASP ZAP (Active Scan)
Initiating Active Scan
How: Configured and started a ZAP Active Scan targeting the primary API endpoint (/xas/) to automatically test for common injection vulnerabilities.
Figure 7: Initiating ZAP Active Scan on /xas/ Endpoint
Shows the configuration and start of the active scan.
Monitoring Scan Progress
How: Observed the ongoing scan in ZAP, confirming that a wide range of payloads and vectors were automatically tested.
Figure 8: Ongoing ZAP Active Scan
Demonstrates the scan progress and comprehensive coverage of possible injection vectors. The scan was performed on
Reviewing Payloads and Responses
How: Examined ZAP’s HTTP requests and responses for evidence of SQL Injection, XSS, or Command Injection. Focused on whether the application properly handled or blocked malicious input.
Figure 9: Sample Injection Payload and Server Response
Displays a typical request with a malicious payload and the corresponding server response, used for verifying how the application responds to attack attempts.verifying the application’s response to malicious inputs.
No injection vulnerabilities (SQLi/XSS/Command Injection) were detected by ZAP on the tested API endpoint.
However, a separate issue was found: the application is leaking bcrypt password hashes in API responses, which is a serious information disclosure (should be fixed).
Overall score for injection test: 0.0 (no injection flaw detected).
Results
No injection vulnerabilities (SQL Injection, XSS, or Command Injection) were detected by ZAP’s Active Scan on the tested endpoint.
Overall score for this test: 0.0 (no injection flaw detected).
4. CSRF
Objective
To determine whether the application is susceptible to CSRF attacks, and to verify whether robust anti-CSRF protections are implemented and enforced across all user roles and functionalities.
Methodology
Standard Referenced: OWASP Top 10 – A05: Security Misconfiguration (including CSRF)
Tools Used:
OWASP ZAP (for passive and active scanning)
Manual navigation through the application as all major user roles
Step-by-Step Test Procedure and Figure Analysis
1. Initial CSRF Assessment and Application Exploration
● 	How:
Began on the application's home page, ensuring no user was authenticated.
Navigated to the login page and authenticated as each major user role (e.g., Customer Jack, Engineer Bill), using ZAP to proxy and passively scan all traffic for CSRF tokens or vulnerabilities.
Figure 1: Home Page or Application Entry Point
Depicts the initial state before authentication, establishing a test baseline.
Figure 2: User Role Selection or Login Page
Illustrates the login process, where each user role is authenticated to begin CSRF-related testing.
Figure 3: Example Action Page (Form Submission)
Shows a page where CSRF-relevant actions (such as submitting forms or making statechanging transactions) occur.
Figure 4: Navigation and Manual Actions Across All User Roles
Documents systematic navigation across every page and function as each user role, while passively scanning for missing CSRF tokens and potential vulnerabilities.
Went through each page and performed action on these user roles page, and did passive scan.
2. Active Scan and Alert Review
How:
After passive scanning and manual interaction, an active scan was initiated using OWASP ZAP to check for CSRF-related warnings and other issues.
All ZAP alerts generated during this phase were carefully reviewed to see if any endpoints lacked anti-CSRF tokens or were susceptible to CSRF attacks.
Active Scan and Alert Review
Figure 5: ZAP Active Scan Results Page
Shows the summary of alerts generated by ZAP’s active scan, with focus on CSRFrelated findings.Checked the active scan for alerts
Results
During passive and active scanning, no CSRF vulnerabilities were detected.
All forms and state-changing actions that were reviewed included CSRF tokens, and ZAP did not generate any critical CSRF-related alerts.
The application appears to implement CSRF protection mechanisms appropriately for all user roles and critical functionalities.
Security Analysis
Strengths:
The application’s CSRF protection is effective across all tested user roles and major functions.
No evidence of CSRF vulnerabilities was found.
Conclusion and Recommendations
The Coffee Service application has robust anti-CSRF protections in place, and no CSRF issues were found during either passive or active DAST.
Recommendation:
Continue to apply CSRF protections on all new forms and APIs, and retest after any significant changes to ensure ongoing protection.
5. Other Security Issues & Information Disclosure
Fig 1: Using Active Scan
Fig 2: Active Scan Complete
Executive Summary
The ZAP active scan of the Coffee Service app running on revealed several high, medium, and low risk security issues. These include critical data exposures, missing
security headers, and unsafe configurations, all of which should be remediated before production deployment.
High Risk Issues
Hash Disclosure – BCrypt
Description: The application exposed bcrypt password hashes (e.g., $2a$12$...) in POST responses to /xas/. This occurred six times.
Risk: Leaked hashes can enable offline brute-force attacks on user passwords if attackers gain access.
Remediation: Never return password hashes or sensitive backend data in any API response. Audit and sanitize all output data.
Personally Identifiable Information (PII) Disclosure
Description: A POST response to /xas/ leaked a Maestro credit card number (6755399441055969).
Risk: Exposing PII can result in privacy violations, regulatory penalties, and user exploitation.
Remediation: Never expose PII in client responses. Carefully review all output for personal or financial data and mask or remove as needed.
Medium Risk Issues
Content Security Policy (CSP) Header Not Set
Description: CSP headers are missing on all major endpoints (e.g., /, /xas/).
Risk: Increases exposure to Cross-Site Scripting (XSS) and data injection.
Remediation: Set a restrictive Content-Security-Policy header on all pages.
Directory Browsing Enabled
Description: Directory listing is enabled at
/widgets/SprintrFeedbackWidget/SprintrFeedback.js/.
Risk: Attackers may discover sensitive or backup files.
Remediation: Disable directory browsing on all server folders.
Missing Anti-clickjacking Header
Description: No X-Frame-Options or Content-Security-Policy: frameancestors is present on responses.
Risk: Allows clickjacking and UI redress attacks.
Remediation: Add X-Frame-Options: DENY or a CSP frame-ancestors 'none' header.
Spring Actuator Information Leak
Description: /xas/actuator/health endpoint is exposed.
Risk: May reveal sensitive infrastructure details.
Remediation: Restrict actuator endpoints to admins or disable them in production.
Low Risk Issues
Cookie Security Flags Missing
Cookies lack HttpOnly: e.g., clear_cache.
Cookies lack SameSite: e.g., DeviceType, Profile,
SessionTimeZoneOffset, useAuthToken, xasid, XASSESSIONID.
Risk: Increases CSRF and session hijacking risk.
Remediation: Set HttpOnly and SameSite=Strict or Lax on all cookies.
Strict-Transport-Security (HSTS) Not Set
Description: HSTS header is missing on all HTTP responses.
Risk: Users are vulnerable to SSL stripping or downgrade attacks.
Remediation: Always set Strict-Transport-Security for HTTPS deployments.
X-Content-Type-Options Header Missing
Description: Most endpoints do not set X-Content-Type-Options: nosniff.
Risk: Allows browsers to perform unsafe MIME sniffing.
Remediation: Set this header on all HTTP responses.
Timestamp Disclosure
Description: JavaScript and other resources leak Unix timestamps.
Risk: Typically low, but may expose deployment or activity details.
Remediation: Avoid leaking backend timestamps in frontend code.
Debug Error Messages
Description: /metamodel.json reveals "internal server error" messages.
Risk: Reveals technical details to attackers.
Remediation: Suppress detailed error/debug messages in production.
Informational
Authentication Request Identified: Login POSTs detected at /xas/ with params.password.
Information Disclosure – Browser sessionStorage: The app uses mx.reload in browser sessionStorage. Not a flaw, but track what is stored.
Suspicious Comments: Some JavaScript files (e.g., mxui.js) contain comments like "BUG." Remove comments from production code.
Summary Table (for 127.0.0.1:8080 only)
Severity Issue Endpoint(s) / Location Remediation
Hash Disclosure 	Never
High 	POST /xas/
(BCrypt) 	expose
passwo rd hashes
Never expose PII; review
High PII Disclosure POST /xas/
output thoroughly
Add Content-
Medium CSP Header Not Set /,
Security- Policy
/xas/ header
Directory Browsing Enabled
Medium 	/widgets/SprintrFeedbackWidg
et/... Disable directory listing
Missing Clickjacking 	Add X-
Medium 	All responses
Header 	Frame-
Options or CSP frameancestors
Spring Actuator Info 	Restrict/di
Medium 	/xas/actuator/health
Leak
Cookie Flags (HttpOnly,
Low 	SameSite)
sable actuator endpoints
All cookies via /xas/ Set proper cookie flags
Set Strict-
Low HSTS Not Set All 	Transport-
Security header
X-Content-Type- 	Set
Low 	Most endpoints Options Missing 	X-
Co nte nt-
Ty
pe-
Op
tio ns: nos niff
Timestamp 	Avoid Low 	Various static/JS
Disclosure 	exposi
resources
ng backen d timesta mps Severity Issue Endpoint(s) / Location Remediation
Debug Error 	Suppress debug
Low 	/metamodel.json
Messages 	details in
production
Auth Requests, Comments,
Info 	/xas/, JS files Review, clean,
etc.
monitor
Conclusion & Recommendations
Your Coffee Service app at contains critical information exposures (hashes, PII), missing security headers, misconfigured cookies, and operational endpoint leaks.
Urgently remediate high and medium risk findings:
Remove all sensitive data from API responses.
Implement all major security headers (CSP, HSTS, X-Frame-Options).
Harden all cookie and session handling.
Restrict internal or admin endpoints and debug output.
Adopt secure coding and configuration best practices before any public or production deployment.
Fig: Zap Report For Coffee Service App
Fig: Alerts and Risk Level
APPLICATION 2: Purchase Request
Demo User Roles for Testing:
1. Authentication Security
1. Brute-Force
Login Test
Objective Objective
The goal of this test was to assess whether the application’s login functionality is vulnerable to brute-force attacks—where an attacker rapidly submits multiple password
guesses in an attempt to gain unauthorized access. A secure application should implement rate limiting or account lockout to mitigate such attacks.
Test Environment and Setup
Test User Role: demo_requester
Tool Used: OWASP ZAP (Zed Attack Proxy) – Fuzzer functionality
Target Endpoint: Application login page/API
Testing Methodology and Steps
Step 1: Capturing and Analyzing the Baseline Login Request
How:
Initiated a normal login via the application using valid credentials.
Used OWASP ZAP as a proxy to intercept and capture the HTTP POST request sent to the login endpoint.
Figure 1: Captured Baseline Login Request
Depicts the intercepted HTTP POST request in ZAP. The request includes parameters for username and password, forming the template for the fuzzing attack.
How: Carefully inspected the request to confirm which fields (username, password) should be targeted for brute-force attempts.
Figure 2: Identifying Login Parameters
Highlights the sections of the request (username and password fields) to be used as payload injection points for the fuzzing process.
Step 2: Configuring and Launching the Fuzz Attack
How:
In ZAP, right-clicked the captured login request, selected “Attack → Fuzz,” and set up the fuzzer to iterate over a list of common or random passwords for the same username.
Figure 3: ZAP Fuzzer Configuration Window
Shows the Fuzzer setup dialog in ZAP, where a password wordlist is loaded and the attack parameters are defined.
How:
Initiated the attack, allowing ZAP to automatically send a large number of login requests in rapid succession.
Figure 4: Launching the Fuzz Attack
Captures the moment the Fuzzer starts executing, showing the queue of planned requests.
Step 3: Monitoring Test Progress and Server Responses
● 	How:
Observed the ZAP interface as the fuzz attack progressed. Carefully tracked each attempted password and the corresponding server response.
Figure 5: Fuzz Attack Progress View
Displays the real-time progress of the fuzzing attack, with a log of requests and received responses.
How:
Reviewed the server’s HTTP status codes for each password attempt to determine if response patterns indicated a successful login, an error, or rate limiting.
Figure 6: HTTP Response Codes for Fuzzed Attempts
Shows a summary table of all attempted passwords with their respective response codes (e.g., 200 OK, 402 Payment Required), indicating how the application differentiates between successful and failed login attempts.
Step 4: Detailed Testing of Correct and Incorrect Password Scenarios
● 	How:
Submitted a login attempt with an intentionally incorrect password and recorded the server’s error response.
Figure 7: Example Login Attempt with Incorrect Password
Depicts a failed login attempt using the wrong password and the error message or status returned by the server.
How:
Submitted a login attempt with the correct password, confirming that only this combination results in a successful authentication.
Figure 8: Example Login Attempt with Correct Password
Shows the request and server response for a correct password, resulting in a successful login.
How:
Examined the HTTP response after successful login for the presence of a CSRF token.
Figure 9: CSRF Token in Successful Login Response
Highlights the CSRF token returned by the server in the successful authentication response, showing session and CSRF protection in place.
Step 5: Evaluating Application Security Controls
How:
Continued submitting login attempts well beyond a reasonable threshold (e.g., 20–50+ tries) to determine if the system triggered any rate limiting, lockout, or CAPTCHA.
Figure 10: No Lockout or Rate Limiting Observed
Demonstrates that, even after numerous failed login attempts, the server continued accepting requests and never returned a rate-limited or account lockout response.
Results
Only the correct password resulted in a successful login; all other attempts failed.
The server’s response codes (200 OK for correct, 402 Payment Required or similar for incorrect) clearly distinguished outcomes but did not signal account lockout or rate limiting.
CSRF tokens were issued with successful logins (good practice for session protection), but no mechanism was observed to slow down or block repeated password guessing.
Security Analysis
Strength: Unauthorized logins were not allowed; credentials must be correct.
Weakness: The system does not detect or mitigate brute-force attempts, lacking:
Account lockout after repeated failures o 	Rate limiting (delaying/failing requests after multiple bad logins)
CAPTCHAs or similar automated attack prevention
Conclusion and Recommendations
Although the login system validates credentials, it is susceptible to automated brute-force attacks due to the absence of lockout and rate limiting.
It is strongly recommended to implement:
Rate limiting or exponential backoff for repeated failed logins
Temporary account lockout after multiple failed attempts
CAPTCHA challenges after several failed attempts
2. Session Reuse / Fixation (OWASP A07)Test
Objective Objective
To determine whether the application is vulnerable to session fixation or session reuse attacks. Specifically, the test assesses whether a valid session cookie or token from one user can be reused by another, which would represent a serious authentication weakness.
Test Environment and Setup
Test Users: demo_requester, demo_approver
Tools Used:
o 	OWASP ZAP (for intercepting and manipulating traffic) o 	Browser (Chrome or Firefox; standard and incognito/private
windows) Methodology and Figure Analysis
Step 1: Log In as First User and Capture Session Cookie
How:
In a normal browser window, log in as demo_requester and perform authenticated actions in the application. Use ZAP to capture traffic and locate the session cookie issued by the application.
Figure 1: Logged in as Demo Requester
Shows the application interface or ZAP traffic history confirming successful login as the demo_requester user.
Figure 2: ZAP Traffic Showing Session Cookie Extraction
Displays the intercepted request in ZAP with the session cookie (e.g., XASSESSIONID) clearly visible in the request/response headers.
Figure 3: Copied Session Cookie Value
Highlights the actual session cookie value extracted from ZAP, such as XASSESSIONID=893c54aa- 0efd-4245-8ced-53864f604bb7.
XASSESSIONID=893c54aa-0efd-4245-8ced-53864f604bb7; xasid=0.937165d7-087a-4898-9aee- d1c22107f4ac; SessionTimeZoneOffset=-120
Step 2: Log In as Second User and Attempt Session Fixation
● 	How:
Log out the first user (demo_requester). Open a new incognito/private browser window and log in as the second user (demo_approver). Using browser developer tools, replace the current session cookie with the previously copied value from demo_requester.
Alternatively, resend a request in ZAP with the old cookie.
Figure 4: Logged in as Approver, Cookie Manipulation Attempt
Demonstrates the change in the session cookie in the incognito window—original session ID for demo_approver replaced with the session ID from demo_requester.
Original id: ffa9c047-56b3-40c5-b1e6-ed54d7f312ea, changed to 893c54aa-0efd-4245-8ced-
53864f604bb7
Step 3: Attempt to Access an Authenticated Page
How:
With the manipulated session cookie in place, attempt to access a user-specific or
otherwise authenticated page. Observe whether the application allows access, switches user context, or blocks the request.
Figure 5: Attempt to Access Authenticated Content with Manipulated Cookie
Shows the navigation attempt with the changed cookie, possibly including the request in ZAP or browser UI showing the authentication state.
Figure 6: Forced Logout or Return to Login Page
Displays the result: the application returns the user to the login page, indicating that session fixation/reuse was not successful.
Results
After replacing the demo_approver session cookie with the value originally issued to demo_requester, any attempt to access authenticated pages resulted in an immediate redirect to the login page.
The application does not allow session cookies to be reused between users or browser sessions.
Security Analysis
Strength: The application prevents session fixation/reuse attacks by invalidating session tokens when presented in a different browser or by a different user.
No vulnerability was identified in this test scenario; the system maintains robust session management.
Conclusion and Recommendations
The application correctly protects against session fixation and session reuse attacks. Session cookies are effectively bound to the user's authentication context and cannot be shared or replayed across users or browser sessions.
Recommendation: Continue to enforce and periodically review session management logic to ensure these controls remain effective as the application evolves.
3. Login Bypass Test (OWASP
A07/A01) Objective
The objective of this test was to determine whether unauthenticated users could access any resources or features that should require authentication, thereby identifying any login bypass vulnerabilities in the application.
Test Environment and Setup
Role/User: Non-authenticated/anonymous (no login)
Tools Used:
o 	OWASP ZAP (for crawling and intercepting traffic) o 	Browser (configured to route through ZAP proxy)
Methodology and Figure Analysis
Step 1: Preparation and Ensuring a Clean State
How:
All user sessions were logged out across all browsers. Cookies and cache were cleared to ensure testing from a true unauthenticated state.
Step 2: Initiating Application Access and ZAP Spider
How:
Opened the application’s main page in the browser (while logged out) and routed all traffic through OWASP ZAP.
In ZAP, right-clicked the application root in the Sites Tree and selected Attack → Spider to start crawling as an anonymous user.
Figure 1: ZAP Sites Tree Before Spider
Shows the initial state of the ZAP Sites Tree before running the spider, confirming no authenticated session.
Figure 2: ZAP Spider in Progress
Depicts the ZAP interface as the spider crawls the application anonymously, discovering available pages and resources.
Step 3: Analyzing Discovered Resources
How:
After the spider completed, expanded the Sites Tree in ZAP to review all discovered
URLs. Checked for sensitive endpoints that should be protected, such as /admin, /user/profile, or business data APIs.
Figure 3: ZAP Spider Results – Discovered URLs
Lists the URLs and resources identified by the spider during the crawl. Only public, static, and authentication pages should appear.
Step 4: Manual Testing of Sensitive URLs
How:
While still unauthenticated, manually entered known protected URLs (from previous sessions, such as /dashboard, /admin, or /orders) directly in the browser (still routed through ZAP).
Observed and documented the application’s response (e.g., redirect to login or error).
Figure 4: Unable to Access the Page (Access Denied/Redirect to Login)
Shows the browser’s response when a protected page is accessed without authentication— such as a login prompt or a 401/403 error message
.Authentication Bypass Test (OWASP A07/A01): Analysis of Unauthenticated Access
Using OWASP ZAP’s Spider, the application was crawled at with no user logged in. Results
The ZAP Spider, run as an anonymous user, discovered only public resources: the main landing page, login page, and static files (JavaScript, CSS, images, icons).
Attempts to access protected or sensitive pages directly while unauthenticated resulted in being redirected to the login page or denied access (401/403).
No restricted resources, business data, or dashboards were accessible without authentication.
Security Analysis
Positive Finding:
The application correctly enforces access controls for all protected resources.
Unauthenticated access to sensitive data or pages was not possible.
No authentication bypass vulnerabilities were identified in this assessment.
Conclusion and Recommendations
The application demonstrates strong authentication controls. All business-critical and user- specific resources remain protected from unauthenticated access.
Recommendation: Continue to enforce and periodically test access controls, especially after code changes or feature additions, to ensure ongoing security.
2. 	Access Control Testing (RBAC/IDOR)
2.1 Role-Based Access Control (RBAC) Testing
Objective
The objective of this test was to verify that the application strictly enforces role- based access control, ensuring that users can access only those resources and functionalities permitted for their assigned roles (Requester, Approver, Admin). This prevents privilege escalation and unauthorized data exposure.
Test Environment and
Setup
User Roles Tested: o 	demo_requester o 	demo_approver o 	demo_admin
Tool Used: o 	OWASP ZAP (for spidering, enumeration, and manual request replay)
Test Approach:
o 	Each user role was tested in a clean session with traffic proxied through ZAP.
Methodology and Figure Analysis
Step 1: Account Preparation and Authentication
How:
Separate test accounts were created for each role. Each user logged in individually through the browser, ensuring traffic was captured in ZAP.
Figure 1: Admin Home Page
Step 2: Spidering and Enumeration of Accessible URLs
How:
After login, the OWASP ZAP Spider tool was run for each session to automatically crawl and enumerate all accessible URLs and endpoints.
Figure 2: Running Spider as Demo Admin
Depicts the ZAP Spider in action while logged in as demo_admin, showing enumeration of admin-level pages and endpoints.
Figure 3: Demo Requester Session Initiated
Displays the interface/dashboard as seen by the demo_requester after login, confirming role assignment.
Figure 4: Running Spider as Demo Requester
Shows the ZAP Spider process for the demo_requester role, identifying the resources visible to this user.
Step 3: Manual Validation and Comparison
How:
The URLs discovered for each role were compared to confirm which were accessible, restricted, or invisible to lower-privilege users. Special attention was paid to adminonly and approver-only pages.
Figure 5: Comparison of Enumerated URLs for Different Roles
Presents the results from ZAP and manual access, comparing which pages were found and accessible by each role.
Figure 6: Access Attempt to Admin Page as Requester (Blocked)
Shows the result when a requester attempts to directly access an admin page, demonstrating proper enforcement (e.g., HTTP 403 Forbidden or redirect to an error page).
Step 4: Results Table – RBAC Accessibility
The RBAC Accessibility Table below summarizes the test results, indicating which URLs/endpoints were accessible (Yes) or restricted (No) for each user role, based on automated enumeration and manual access attempts.
RBAC Accessibility Table
Results
Requester: Could access only requester-specific and public pages. Admin and approver pages were hidden or denied.
Approver: Had access to approver-specific, shared, and public pages. Admin-only URLs remained inaccessible.
Admin: Had access to all pages, including privileged and admin-only URLs.
Attempts by lower-privilege users to directly access higher-privilege URLs resulted in HTTP 403 Forbidden responses or redirection to an error page, confirming proper RBAC enforcement.
Security Analysis
The application correctly enforces RBAC controls, strictly separating access according to assigned roles.
No privilege escalation or unauthorized data access was observed during testing.
Conclusion and Recommendations
The tested application demonstrates robust RBAC implementation. Each user role is restricted to its assigned resources and functions, preventing unauthorized access or escalation.
Recommendation: Regularly review and update role-based permissions, especially when new features are added, to maintain strong access control.
2.2 Insecure Direct Object Reference (IDOR) Testing
Objective
To determine whether users can access or modify resources that do not belong to them by manipulating object identifiers (IDs) in URLs or API requests. Such vulnerabilities are a critical access control flaw (OWASP A01: Broken Access Control).
Methodology and How the Test Was Performed Step 1: Identify Target Endpoints
How:
Used OWASP ZAP’s Sites Tree and HTTP History to locate API endpoints where object/resource IDs are present in the request path or body. Common examples include:
/api/order/23
/api/user/5
Step 2: Manual Tampering of Object Identifier
How:
While logged in as a standard user (demo_requester), selected a valid request from ZAP’s HTTP History where the resource ID referenced data the user was authorized to access.
Figure 1: Original Request as Demo Requester
Shows the baseline API request with a resource ID belonging to the current user.
Figure 2: Current Object/GUID of the Object to Copy
Highlights the GUID (Globally Unique Identifier) of a resource owned by the logged-in user, as seen in the request payload.
Figure 3: GUID of Another User
Displays a different GUID, which was copied from another user’s resource, to be used for tampering.
Step 3: Send Tampered Request and Observe Response
How:
Manually edited the API request in ZAP’s Request Editor, replacing the original GUID with the one belonging to another user (i.e., changing /api/order/23 to /api/order/24 or using a different GUID in the POST payload).
Figure 4: Changed the GUID in Request
Depicts the modified request where the resource ID/GUID was replaced with that of another user’s resource.
Figure 5: Server Responds with 401 Unauthorized
Shows the server’s response to the tampered request: HTTP 401 Unauthorized, indicating access was denied.
Results
When attempting to access or manipulate another user’s resource by modifying the object ID or GUID in the request, the application consistently responded with a 401 Unauthorized error.
No unauthorized or sensitive data was returned for manipulated identifiers.
This confirms that access controls are properly enforced at the tested endpoint and the application is not vulnerable to IDOR.
Security Analysis
Positive: The application does not allow users to access or modify resources they do not own by manipulating object identifiers.
Negative: No IDOR vulnerability was found at the tested endpoints.
Conclusion and Recommendations
The tested application endpoints correctly enforce authorization controls, returning 401 Unauthorized responses when an attempt is made to access resources belonging to other users.
Recommendation: Continue to apply strong access controls on all endpoints and periodically retest for IDOR vulnerabilities, especially when new features or APIs are introduced.
API Security & Input Validation
Unauthenticated API Access (OWASP A01: Broken Access
Control) Objective
To determine whether API endpoints can be accessed without proper authentication— specifically, to verify that sensitive endpoints (e.g., /xas/) require valid session cookies or tokens for access.
Methodology
1. Intercepting a Valid Request
o 	Logged in as demo_requester and used OWASP ZAP to capture a normal authenticated API request (such as POST /xas/).
Figure 1: Logged in as Demo Requester
Shows the authenticated session in the application, confirming user context prior to intercepting the API request.
Manual Removal of Authentication
In ZAP’s Manual Request Editor, all authentication headers (e.g., Cookie, session tokens) were removed from the captured request.
Figure 2: Manual Request Editor with Authentication Headers Cleared
Displays the ZAP interface where authentication details are stripped from the request to simulate an unauthenticated user.
Sending the Unauthenticated Request
The edited request was sent to the server, imitating an unauthenticated API call.
Figure 3: ZAP Request/Response for Unauthenticated API Access
Shows the full HTTP request without authentication and the server’s 200 OK response, including the CSRF token returned.
Result Analysis
The server responded with HTTP 200 OK and provided a valid CSRF token, even though the request was made without any valid authentication credentials.
Figure 4: Response Details with Exposed CSRF Token
Highlights the response body showing the CSRF token, proving that the endpoint is accessible to unauthenticated users.
Results
Critical Vulnerability Identified:
As shown in Figures 2–4, the /xas/ endpoint was accessible without authentication and the server returned a CSRF token to an unauthenticated request.
Expected behavior would be a 401 Unauthorized or 403 Forbidden response for any sensitive endpoint when accessed without proper credentials. The actual 200 OK response indicates a critical Broken Access Control flaw.
Fig 4: Response from /xas/ after sending a request without authentication headers, showing 200 OK and a CSRF token returned.
Security Impact
Any unauthenticated attacker can access the /xas/ endpoint and retrieve sensitive application tokens, bypassing intended authentication checks.
This is classified as a critical vulnerability per OWASP A01 (Broken Access Control, score = 1.0).
Recommendation
Immediately enforce authentication and authorization checks for all sensitive API endpoints. Ensure that any request lacking valid credentials receives a 401 Unauthorized or 403 Forbidden response, and never exposes CSRF tokens or sensitive data to unauthenticated users.
Injection Vulnerabilities (OWASP A03:
Injection) Objective
To determine whether the application’s API endpoints are susceptible to injection attacks— including SQL Injection, Cross-Site Scripting (XSS), and Command Injection—by leveraging OWASP ZAP’s automated active scanning features.
Methodology and Figure Analysis
Step 1: Preparation and Target Identification
How:
Used OWASP ZAP to proxy authenticated traffic, identifying key API endpoints for input validation testing.
Figure 1: Target Endpoint Identified in ZAP
Displays the endpoint(s) selected for injection testing as seen in ZAP’s Sites Tree or HTTP History.
Step 2: Running ZAP Active Scan
How:
Launched OWASP ZAP’s Active Scan against the identified API endpoint(s), which
automatically injected a wide range of payloads designed to trigger SQL Injection, XSS, and Command Injection vulnerabilities.
Figure 2: ZAP Active Scan Progress Window
Shows the progress and configuration of the ZAP Active Scan, confirming coverage of all selected endpoints.
Step 3: Reviewing and Documenting Scan Results
How:
After the scan completed, reviewed the ZAP Alerts and scan findings for any evidence of successful injection attempts or flagged vulnerabilities.
Figure 3: ZAP Scan Results – No Injection Vulnerabilities Detected
Presents the ZAP Alert or results pane, showing that no high-severity alerts for SQL Injection, XSS, or Command Injection were found for the tested endpoints.
Results
No SQL Injection, XSS, or Command Injection vulnerabilities were detected by ZAP’s Active Scan.
The application endpoints properly handled injected payloads and did not return evidence of execution or data leakage.
All tested inputs were either sanitized or blocked, resulting in no exploitable vulnerabilities being found.
Security Analysis
Positive: The application demonstrates strong resilience against injection attacks at the tested endpoints.
Negative: None observed in this phase, though ongoing vigilance is advised— especially when adding new input fields or API features.
Conclusion and Recommendations
The tested application endpoints showed no evidence of injection vulnerabilities (SQLi, XSS, or Command Injection) under automated DAST using OWASP ZAP. Recommendation: Maintain strict input validation and regular security testing for all
future code and configuration changes, as injection risks remain among the most common web application threats.
Cross-Site Request Forgery (CSRF) Testing (OWASP A05:2021)
4. Cross-Site Request Forgery (CSRF) Testing (OWASP A05:2021) What was tested:
The application was assessed for Cross-Site Request Forgery (CSRF) vulnerabilities, specifically focusing on the presence or absence of anti-CSRF tokens in critical forms and API requests. CSRF vulnerabilities can allow attackers to perform actions on behalf of authenticated users without their consent.
How the test was performed:
1. Setup:
The application was launched in a browser, with ZAP proxying all requests.
User authentication was performed to ensure that authenticated pages and forms could be tested.
2. Passive Scan:
ZAP’s Passive Scanner was used to monitor all HTTP requests and responses.
The scanner automatically flagged forms and API requests missing anti-CSRF tokens.
ZAP was configured to detect common anti-CSRF patterns (e.g., tokens in hidden form fields or custom headers).
3. Manual Review:
Each flagged request was manually reviewed.
The presence (or absence) of anti-CSRF tokens was confirmed by inspecting the request payloads.
The application’s response to potential CSRF attempts (e.g., submitting forms from external sites) was noted.
Expected Result:
All forms and API requests that modify state (e.g., POST, PUT, DELETE) should include unique, session-specific anti-CSRF tokens. These tokens should be validated server-side.
What to look for in your results:
If ZAP flags a missing anti-CSRF token for any state-changing request, this is a critical issue (score = 1.0).
If all relevant requests contain anti-CSRF tokens and pass manual verification, the test is passed (score = 0.0).
Objective
To determine whether all state-changing POST requests in the application implement effective anti-CSRF (Cross-Site Request Forgery) protections, by inspecting for the presence of unique, session-based CSRF tokens in requests.
Methodology and Figure Analysis Step 1: User Functionality Mapping
How:
Navigated to the “All Users” page within the application to review available functions and identify actions that would trigger POST requests.
Figure 1: All Users Page with Functions Analyzed
Shows the application’s user management interface, highlighting functions and actions that would be targeted for POST request analysis.
Step 2: POST Request Interception and Analysis
How:
Using OWASP ZAP, intercepted all POST requests initiated during authenticated sessions. Carefully inspected both the HTTP headers and payload of these requests to identify the presence (or absence) of anti-CSRF tokens.
Figure 2: POST Request Checked for CSRF Token
Displays a POST request to /xas/ as intercepted in ZAP, focusing on the absence of an anti- CSRF token in headers or body.
CSRF POST Request Analysis Table:
Method URL CSRF Token Present
Comment
No anti-CSRF token found;
POST No
vulnerable to CSRF
Results
During authenticated sessions, all relevant POST requests were captured and reviewed.
As detailed in the table above, the POST requests to /xas/ did not include any antiCSRF token in either the headers or request payload. This indicates that no standard CSRF protection mechanisms are implemented for these endpoints.
Security Impact
Critical vulnerability:
The absence of anti-CSRF tokens allows attackers to potentially forge state-changing
requests that the application would process in the context of a logged-in user. This could lead to unauthorized actions and data compromise.
Classification:
This issue maps to OWASP A05:2021 (Security Misconfiguration / Cross-Site Request Forgery) and is considered high-risk.
Recommendation
All POST (and other state-changing) endpoints must enforce the use of unique, sessionbased anti-CSRF tokens. The server must validate these tokens on every request to ensure that only legitimate, user-initiated actions are processed. Immediate remediation is strongly advised.
5. Other Security Issues & Information Disclosure
Fig: Tested all the users functionality
Fig: Run Active Scan
Security Analysis for (Purchase Request App)
Executive Summary
The active security scan on the local development environment identified several critical, medium, and low risk security issues. These must be addressed before moving to production or exposing the app to real users.
High Risk Issue
Hash Disclosure – BCrypt
Description: The application exposes bcrypt password hashes in API responses at POST /xas/. Seven instances were found.
Risk: Attackers can use these hashes for ofline password cracking if leaked.
Recommendation: Never return password hashes in any API or client response. Ensure all sensitive server-side data is filtered out from user-facing endpoints.
Reference:
Medium Risk Issues
Content Security Policy (CSP) Header Not Set
Description: CSP headers are missing on GET /, /index.html, and /login.html.
Risk: Increases risk of cross-site scripting (XSS) and data injection attacks.
Recommendation: Add a restrictive Content-Security-Policy header to all pages.
Reference:
Missing Anti-clickjacking Header
Description: No X-Frame-Options or CSP frame-ancestors header on main pages.
Risk: Allows potential clickjacking/UI redress attacks.
Recommendation: Add X-Frame-Options: DENY or use a CSP frame-ancestors
'none' directive.
Spring Actuator Information Leak
Description: The health endpoint at /xas/actuator/health is exposed.
Risk: Attackers may access sensitive operational data.
Recommendation: Disable actuator endpoints or restrict them to admins only.
3. Low Risk Issues
Cookie Security Flags
HttpOnly flag missing: Some cookies (e.g., clear_cache) lack HttpOnly.
SameSite flag missing: Cookies like DeviceType, Profile,
SessionTimeZoneOffset, useAuthToken, xasid, and XASSESSIONID lack the SameSite attribute.
Risk: Increases risk of session hijacking and CSRF attacks.
Recommendation: Set both HttpOnly and SameSite=Strict or Lax on all cookies.
Strict-Transport-Security (HSTS) Not Set
Description: App does not set HSTS headers.
Risk: Users are at risk of SSL stripping or downgrade attacks.
Recommendation: Add the Strict-Transport-Security header to all HTTPS responses.
X-Content-Type-Options Header Missing
Description: This header is missing on many responses.
Risk: Increases risk of MIME-type confusion and XSS.
Recommendation: Add X-Content-Type-Options: nosniff to all responses.
Timestamp Disclosure
Description: JS files under /dist/ leak Unix timestamps (e.g., in LineChart-CJ0ZCpF6.js).
Risk: Low, but may help attackers infer deployment or activity timelines.
Recommendation: Avoid exposing internal timestamps in client-side code.
Summary Table (Only for 127.0.0.1:8080)
Conclusion & Recommendations
The application at contains serious data exposure (password hashes), missing security headers, misconfigured cookies, and operational endpoint leaks.
Prioritize remediation of high and medium issues before production deployment:
Remove all sensitive data from responses.
Implement modern HTTP security headers.
Harden all session management practices.
Restrict internal endpoints.
Regular DAST scanning and secure coding practices are essential for reducing attack surface and maintaining compliance.
Fig: Alerts and Risk Table
Application 3- Task Tracker App
Figure: Security Testing to be done using these roles
1. Authentication Security
A) Brute-force Login (OWASP A07: Identification and Authentication Failures)
Objective
To evaluate the Task Tracker application's login functionality for susceptibility to brute-force attacks, and to assess whether security mechanisms such as rate limiting, account lockout, or CAPTCHA are in place to prevent automated login attempts.
Methodology
Standard Referenced: OWASP Top 10 – A07: Identification and
Authentication Failures
Tools Used: OWASP ZAP (Fuzzer), Browser Developer Tools
Step-by-Step Test Procedure and Figure Analysis
1. Initial Login and Session Confirmation
How: Logged in as a valid "Member" to confirm user role and capture a baseline for the login process.
Fig 1: Logged in as Member
Intercepting the Login Request
How: Used ZAP to intercept the HTTP POST request containing the username and password parameters during the login attempt.
Fig: Post Request with username and password
Setting up the Brute-force Attack
How: Selected "Attack Fuzzer" on the intercepted POST URL in ZAP to automate repeated login attempts with various credentials.
Fig: Selected Attack Fuzzer on POST URL
Fuzz Payload Configuration
How: Configured the fuzzer to iterate through a list of member usernames and a combination of correct and incorrect passwords.
Fig: Added Member Username and Password to fuzz
Launching the Brute-force Attack
How: Initiated the fuzzing process, allowing ZAP to automatically send multiple login attempts to the server.
Fig: Incorrect password and Correct Password
Monitoring Server Responses
How: Observed the server's responses for both incorrect and correct password attempts. Verified the status codes and the presence of any indicators (such as tokens) in the responses.
Fig: Fuzzer Attack showing CSRF token in Response
Results
The application responded with appropriate error messages for incorrect passwords and provided successful authentication and CSRF tokens for valid credentials.
No account lockout or rate limiting was triggered after multiple consecutive failed attempts, indicating the absence of brute-force mitigation controls.
The presence of a CSRF token in the successful response demonstrates some degree of session protection, but does not prevent brute-force login attempts.
Security Analysis ● 	Strengths:
Application distinguishes clearly between correct and incorrect credentials.
CSRF tokens are issued upon successful login.
Weaknesses:
No account lockout, CAPTCHA, or rate limiting after repeated failed attempts, leaving the application vulnerable to brute-force attacks.
Automated attackers can attempt unlimited password guesses for user accounts.
Conclusion & Recommendations
The Task Tracker application's login mechanism is vulnerable to brute-force attacks due to the lack of rate limiting and account lockout controls. While the application properly handles valid/invalid credentials and issues CSRF tokens upon successful login, additional protective measures are needed.
Recommendations:
Implement account lockout or exponential backoff after multiple failed login attempts.
Consider adding CAPTCHA after a defined number of failed logins.
Log and alert on repeated failed authentication attempts to enable rapid detection of brute-force activity.
Session Reuse/Fixation Testing (OWASP A07)
Objective
To determine whether the Task Tracker application is vulnerable to session fixation or session reuse attacks—specifically, whether a session cookie from one user
(member) can be reused by another user (manager) to gain unauthorized access.
Step-by-Step Test Procedure and Figure Analysis
1. Login as Member and Capture Session Cookie
o 	How: Logged in as member1 in a regular browser window. Used OWASP ZAP to capture the session cookie (xasessionid) from the HTTP request.
Figure: Login as member
Figure: xasessionid of member1 (e.g., be837ca0-a1f9-4a4f-8f2e-74129039605f)
2. Logout or Close Member Session
● 	Logged out or closed the browser tab for member1 to end the session.
3. Login as Manager in a New Session
How: Opened an Incognito/Private window. Logged in as manager1
Figure: Login as manager
Figure: xasessionid of manager1 (e.g., d3201b44-884c-462d-85e8-635562387d03)
Replace Manager’s Cookie with Member’s Cookie
How: In DevTools, navigated to Application > Cookies, and replaced the value of xasessionid with the value copied from member1.
Figure: Copied the value of member1’s xasessionid to the manager’s session
Attempt to Access Restricted Pages
How: Refreshed or navigated to member-only pages in the manager session after replacing the cookie.
Result: The application redirected to the login page, indicating that session fixation/reuse is not possible and the app is secure against this attack.
Results
The application did not allow session fixation/reuse: After replacing the session cookie, the user was redirected to the login page, not given access to the original member’s data.
Session cookies are properly scoped and cannot be reused between different user sessions.
Security Analysis
Strength: The application enforces robust session management practices and prevents session fixation/reuse attacks.
No vulnerability was found in this test scenario.
Conclusion & Recommendations
The Task Tracker application is secure against session fixation and session reuse attacks. Session cookies cannot be transferred between users to gain unauthorized access.
Recommendation: Continue monitoring and periodically testing session management, especially after any authentication or session logic changes.
Login Bypass / Broken Access Control Test (OWASP A07/A01)
Objective
To determine whether restricted or authenticated pages (such as /dashboard,
/admin, /profile, etc.) are accessible to unauthenticated users, thereby assessing the effectiveness of access control mechanisms in the Task Tracker application.
Methodology
Standard Referenced: OWASP Top 10 – A07/A01: Broken Access Control
Tools Used:
OWASP ZAP (Spider, Request Editor)
Browser (Incognito/Private mode)
Step-by-Step Test Procedure and Figure Analysis
1. Start Fresh with No Login
o 	How: Opened the browser in Incognito/Private mode and cleared all cookies/cache to ensure no prior authentication.
Fig: Login Page — Shows the default login screen confirming the user is not authenticated.
Configure ZAP Proxy
Set the browser to use ZAP as a proxy for all requests.
Spider the Target Application
How: In ZAP, right-clicked the target domain and selected “Spider Site”.
Fig: Chose Spider Attack — Screenshot of ZAP showing the Spider configuration dialog
Confirmed that no authentication details were provided.
Allow Spider to Complete
Waited for ZAP Spider to finish crawling the application unauthenticated.
Fig: Spider Scan was Successful — Screenshot confirming completion.
Review Spider Results
How: Examined all URLs found by the spider in the ZAP Sites tree.
Specifically looked for restricted/internal pages (e.g., /dashboard, /admin, /user/profile, /settings).
Manual Direct Access (if needed)
For any page that appeared to require login, attempted to access it directly via browser or ZAP’s Request Editor without authentication.
Observed if the application returned the page content, or instead redirected to login/returned "Unauthorized
Security Analysis
Strength: The Task Tracker application correctly enforces access control and does not allow unauthenticated access to internal or protected pages.
No vulnerability was identified in this test.
Conclusion & Recommendations
The application is secure against login bypass and broken access control vulnerabilities. Recommendation: Continue testing access control enforcement after new releases, and always restrict sensitive resources to authenticated users only.
2. Access Control (RBAC/IDOR) Testing
2.1. Role-Based Access Control (RBAC) Testing
Objective
To assess whether the Task Tracker application properly enforces role-based access control, ensuring each user role (Member, Manager) is granted access only to authorized resources and functionalities, thereby preventing privilege escalation or unauthorized access (OWASP A01: Broken Access Control).
Step-by-Step Process and Figure Analysis
1. Login and Exploration as Member
● 	How: Logged in as member1 and explored the UI and all available functions.
Figure 1: Log in as member1 and explore all functions
Screenshot confirms successful login as member and shows the default landing/dashboard page with all visible modules for a regular user.
Spidering for Member1
How: Launched OWASP ZAP Spider with an authenticated session for member1 to automatically enumerate all accessible URLs.
Figure 2: Ran Spider to retrieve URLs for Member1
Figure shows the ZAP Spider window running on the session of member1, indicating all web resources and endpoints being actively discovered.
Collecting and Listing Accessible URLs for Member1
● 	How: Reviewed the list of discovered URLs from the Spider results.
Figure 3: List of URLs for Member1
Depicts the complete set of URLs found by the Spider, including /, /index.html,
/login.html, /dist/pages/TaskTracker.MyAccountViewEdit.js,
/dist/pages/TaskTracker.TaskEdit.js, /dist/pages/TaskTracker.TaskOverview.js, /dist/pages/TaskTracker.TeamOverview.js, /xas/, and associated static assets.
Login and Exploration as Manager
● 	How: Logged in as manager1 and repeated the manual exploration.
Figure 4: Manager1 Page
Shows successful login and the manager’s landing page, highlighting the default interface and available manager features.
Spidering for Manager1
How: Ran the OWASP ZAP Spider for the authenticated session of manager1.
Figure 5: Spider Attack on Manager1
Screenshot displays the Spider process for the manager user, mapping out the application's available URLs and resources.
Collecting and Listing Accessible URLs for Manager1
How: Compared the list of URLs discovered by the Spider for manager1 to those found for member1.
Manager1 Accessible URLs Web UI Pages (GET):
376580775052
52
0775052
0775052
API Endpoint (POST):
(Method:
POST) Static Assets & Misc (all GET):
And several other /dist/ JS files related to Mendix widgets/components.
Figure 6: Manager1 Accessible URLs
Shows the list of endpoints and pages accessible to manager1, which are essentially identical to those found for member1.
Report Table
Results and Figure-Based Assessment
Analysis of Figure 3 and Figure 6 (Side-by-Side):
Both member1 and manager1 have access to the same set of application URLs, including pages such as TeamOverview, TaskEdit, TaskOverview, MyAccountViewEdit, /xas/ API, and all static files.
No exclusive manager-only or privileged endpoints were found in the results.
No error, "access denied," or missing pages were encountered for either role; all business logic and UI features are equally accessible to both user types.
Security Analysis
Key Finding:
The application does not effectively enforce role-based access control at the URL or API level. All tested roles have the same permissions and see the same content, including features that may be intended for managers only (such as TeamOverview).
Risk:
If business requirements dictate that certain features should be manager- only, this is a critical RBAC flaw (OWASP A01: Broken Access Control). It allows privilege escalation and potential data exposure.
Impact:
Regular users can view and possibly modify resources meant for higher-
privilege users, putting the integrity and confidentiality of business data at risk.
Conclusion and Recommendations
The RBAC test, as demonstrated in all figures, reveals a lack of effective access control between Member and Manager roles in the Task Tracker application.
If this is not intentional, immediate remediation is required to restrict access to sensitive or privileged features (such as TeamOverview) based on role.
Use both frontend UI logic and backend authorization checks to enforce RBAC and prevent privilege escalation.
2.2 IDOR (Insecure Direct Object Reference)
Objective
To determine whether the Task Tracker application is vulnerable to IDOR, specifically whether one user can access or manipulate another user’s data by modifying object identifiers (GUIDs) in API requests (OWASP A01: Broken Access Control).
Methodology
● 	Tools Used:
o 	OWASP ZAP (for capturing and editing HTTP requests) o 	Task Tracker application (test users: Member1 and Manager1)
● 	Testing Steps:
Log in as a regular user (Member1) and perform actions that generate API requests containing user-specific object identifiers (GUIDs).
Capture the API request and note the GUID associated with Member1.
Obtain the GUID associated with another user (Manager1).
Modify the captured request by replacing Member1’s GUID with Manager1’s GUID.
Send the tampered request and observe the server’s response.
Step-by-Step Process and Figure Analysis
Log in as Member1
Figure: Logged In as Member 1
Confirms successful login as Member1, establishing the test session and user context.
Identify GUID of Member1
● 	Figure: Fig1: guid":"4503599627370897 of Member1
Shows the original API request containing Member1’s GUID in the request payload or URL.
Identify GUID of Manager1
● 	Figure: Fig: guid":"4503599627370898 of Manager1
Demonstrates the GUID associated with Manager1, as found in application traffic or through another valid request.
Change GUID Value and Send Request
● 	Figure: Fig: Changed the value and send
Captures the tampered API request, where Member1’s GUID is replaced with Manager1’s GUID.
Observe Server Response
Figure: Fig: Response with 200 OK
Displays the server’s HTTP 200 OK response after the manipulated request is sent, suggesting that the operation was accepted and data access/modification may have succeeded.
Results
By changing the GUID in the request from Member1’s value to Manager1’s, and submitting the request, the server returned a successful 200 OK response.
This demonstrates the presence of an IDOR vulnerability: The application does not validate that the requesting user actually owns or is authorized to access the resource identified by the GUID.
Security Analysis
Vulnerability: The application is vulnerable to Insecure Direct Object Reference (IDOR). Any authenticated user can potentially access or modify other users’ resources by simply changing GUIDs in API requests.
Impact: This flaw may lead to unauthorized viewing or manipulation of sensitive information, privilege escalation, or data tampering.
Risk Level: Critical (OWASP A01: Broken Access Control).
Conclusion & Recommendations
The Task Tracker application fails to properly enforce ownership checks on user resources.
Immediate remediation is required:
Implement server-side authorization logic to ensure that users can access only their own data, regardless of object IDs presented in requests.
Never trust solely on user-supplied identifiers for access control.
Conduct regular security testing for IDOR across all endpoints that use predictable or user-modifiable IDs.
3. API Security & Input Validation Testing
3.1 Unauthenticated API Access (OWASP A01: Broken Access Control)
Objective
To assess whether the Task Tracker application’s API endpoints are exposed to unauthenticated users, and to confirm that sensitive data and business logic are protected from unauthorized access.
Methodology
● 	Tools Used:
OWASP ZAP (Manual Request Editor)
Browser (for session management and capturing authentication state)
● 	Test Procedure:
Logged in to the application and identified the critical API endpoint (/xas/) using ZAP’s HTTP History panel.
Used “Open/Resend with Request Editor” in ZAP to replay the request.
Manually removed all authentication headers and cookies from the request.
Sent the unauthenticated request to the /xas/ endpoint and observed the server’s response code.
Step-by-Step Figure Analysis
Figure: Login as Manager1
Shows a legitimate authenticated session, confirming normal access to the application as a manager.
Figure: Authentication Headers
Displays the API request in ZAP with authentication headers and cookies present, prior to removal.
Figure: Cookie Deleted
Illustrates the manual removal of all authentication cookies/headers from the request in ZAP’s editor, simulating an unauthenticated access attempt.
Figure: Response
Shows the server’s reply: HTTP/1.1 401 Unauthorized, confirming that the endpoint rejects unauthenticated requests.
Results
The /xas/ API endpoint responded with HTTP 401 Unauthorized when accessed without authentication headers or session cookies.
No sensitive data or business logic was exposed to unauthenticated users.
The API correctly enforces access controls and is not vulnerable to unauthenticated access attacks.
Security Analysis ● 	Strength:
The Task Tracker API demonstrates robust protection against
unauthenticated access by reliably returning 401 Unauthorized when authentication is missing.
No Broken Access Control vulnerability was identified in this test.
Logic
By replaying API requests without authentication, we simulate a real attacker attempting to access protected resources. The consistent 401 Unauthorized response proves that the API enforces proper access controls, indicating strong security posture.
Conclusion & Recommendations
The Task Tracker application correctly protects its API endpoints from unauthenticated access.
Recommendation:
Continue enforcing and regularly testing authentication checks, especially when new endpoints or features are added.
Maintain security best practices in both backend logic and session handling.
3.2 Injection Vulnerabilities (OWASP A03:
Injection) Objective
To test whether the Task Tracker application’s API endpoints are vulnerable to input-based attacks, such as SQL Injection, Cross-Site Scripting (XSS), or Command Injection.
Methodology
Tools Used:
o 	OWASP ZAP (Active Scan)
Test Approach:
Identified API endpoints that accept user input (e.g., search, filter, profile update).
Used OWASP ZAP’s “Active Scan” feature to automatically send a variety of malicious payloads to these endpoints.
Reviewed ZAP’s Alerts panel for any findings labeled “High” or “Medium” severity related to injection attacks.
Step-by-Step Process and Figure Analysis
Explored Application after Sign-In
Figure: Explored App after Sign In
Shows the application’s state after a successful login, with API endpoints now accessible for testing.
Active Scan Execution
Right-clicked the target endpoint in ZAP and selected “Attack → Active Scan”.
Figure: Ran Active Scan on 127.0.0.1:8080
Displays ZAP running an active scan against the application’s API endpoints.
Completion of Scan
Allowed the Active Scan to finish, covering all detected endpoints.
Figure: Active Scan Completed
Screenshot shows successful completion of the scan.
Review of Alerts and Results
Inspected the ZAP Alerts panel to check for injection findings.
Figure: API Injection Vulnerability Not Found after Scan
This confirms that no direct injection vulnerabilities were detected.
Logic
OWASP ZAP’s Active Scan automatically tests user input fields for proper validation and sanitization by sending a broad set of attack payloads. If any vulnerabilities such as SQL Injection or XSS exist, ZAP will flag them as high or medium severity alerts, providing request/response evidence.
Results
No high or medium severity injection vulnerabilities (e.g., SQL Injection, XSS, Command Injection) were detected in the tested endpoints.
The only issues flagged by ZAP were related to security misconfigurations (e.g., missing headers) and information disclosures (e.g., bcrypt hash, PII), not direct injection flaws.
Conclusion
The Task Tracker application’s tested API endpoints are not vulnerable to input- based injection attacks according to the results of OWASP ZAP’s automated
active scan.
Recommendation: Continue to enforce strong input validation and regularly retest all endpoints, especially after adding or modifying user input features.
4. CSRF (Cross-Site Request Forgery)
4. CSRF (Cross-Site Request Forgery)
Objective
To assess whether the Task Tracker application implements effective protection against CSRF attacks, specifically by checking for the presence of anti-CSRF tokens in all critical POST, PUT, and DELETE requests across all user roles and forms.
Methodology
Tools Used:
OWASP ZAP (Passive Scan, History/Alerts)
Browser configured to proxy through ZAP
Test Procedure:
Proxy Setup:
The browser was configured to route all traffic through
OWASP ZAP.
Manual Application Exploration:
Browsed the application thoroughly as each user role (e.g.,
Member, Manager), exercising all major
functions, forms, and actions that would generate POST/PUT/DELETE requests.
Fig: Browsed through each role and checked the functions for passive scan
Passive Scanning and Recording:
Allowed ZAP to record all traffic and perform a passive scan while interacting with the app.
Fig: ZAP Recorded the Scan
Alert and Manual Request Inspection:
Examined all HTTP requests for POST/PUT/DELETE methods in ZAP’s History tab.
Checked the Alerts tab for any findings related to missing anti-CSRF tokens.
Manually inspected request bodies, headers, and cookies for anti-CSRF parameters (csrf_token, RequestVerificationToken, etc.).
Results
No CSRF Protection Detected:
ZAP’s passive scan did not flag any CSRF-specific alerts in the captured session.
The only alerts observed were related to header misconfigurations, missing security headers, and information disclosure (see Figure X and Y).
Manual inspection of all sensitive requests (POST/PUT/DELETE) found no anti-CSRF token present in the request body, headers, or cookies.
CSRF protection is absent on all tested critical endpoints.
Security Analysis
Vulnerability:
The lack of anti-CSRF tokens on sensitive requests means the application is potentially vulnerable to CSRF attacks. An attacker could exploit a logged-in user's session to perform unauthorized actions.
Risk:
High—because CSRF can result in account hijacking, unauthorized data changes, and loss of user trust.
Conclusion & Recommendations Conclusion:
The Task Tracker application does not implement CSRF protection on critical POST, PUT, and DELETE actions. This leaves the app susceptible to CSRF attacks.
Recommendations:
Implement anti-CSRF tokens for all state-changing requests.
Validate these tokens on the server-side for every sensitive endpoint.
Retest after implementation to ensure protection is effective.
5. 	Other Vulnerabilities Found(Active Scan)
Fig: List OF Vulnerabilities
Vulnerability Assessment Report: Task Tracker
Executive Summary
The OWASP ZAP active scan identified multiple critical and high-risk vulnerabilities in the Task Tracker application, alongside several medium- and low-severity issues. These weaknesses significantly increase the risk of data exposure, privilege escalation, and successful attacks against end- users or the application backend.
1. High-Risk Findings 1.1. Hash Disclosure – BCrypt ● 	Description:
BCrypt password hashes (e.g., $2a$12$...) are exposed in API responses at /xas/. This occurred twice.
Risk:
Attackers with access to these hashes can perform offline brute-force attacks to recover user passwords.
Remediation:
Never expose password hashes in any client-facing API response. Review output sanitization and backend logic to prevent all credential leaks.
1.2. PII Disclosure ● 	Description:
Personally Identifiable Information (PII), including Visa credit card details, is returned in responses to /xas/.
Risk:
Legal and regulatory violations, as well as user exploitation via identity theft or fraud.
Remediation:
Remove all PII from API responses. Mask or tokenize any sensitive data required for legitimate business purposes.
2. Medium-Risk Findings
2.1. Content Security Policy (CSP) Header Not Set ● 	Description:
CSP headers are missing on all major endpoints, including /, /index.html, and /login.html.
Risk:
Exposes the application to Cross-Site Scripting (XSS) and data injection attacks.
Remediation:
Implement a strict Content-Security-Policy header on all HTTP responses.
2.2. Cross-Domain Misconfiguration (CORS) ● 	Description:
External resources such as Google Fonts are served with Access-Control- Allow-Origin: *.
Risk:
Allows cross-origin reads from arbitrary domains. Attackers may exploit this to extract data from unauthenticated endpoints.
Remediation:
Restrict CORS headers to only trusted domains and avoid using wildcards.
2.3. Missing Anti-Clickjacking Header ● 	Description:
X-Frame-Options and Content-Security-Policy: frame-ancestors headers are missing on all responses.
Risk:
Enables clickjacking and UI redress attacks.
Remediation:
Add X-Frame-Options: DENY or an equivalent CSP frame-ancestors 'none' header.
2.4. Spring Actuator Information Leak ● 	Description:
The /xas/actuator/health endpoint is publicly accessible and returns server diagnostics.
Risk:
May expose sensitive application or infrastructure details useful for attackers.
Remediation:
Restrict or disable actuator endpoints in production environments.
3. Low-Risk Findings 3.1. Cookie Security Issues ● No HttpOnly Flag:
Cookies such as clear_cache are accessible via JavaScript.
No SameSite Attribute:
Multiple cookies, including DeviceType, Profile, and session tokens, lack the SameSite flag.
Risk:
Increases the risk of session hijacking and CSRF.
Remediation:
Add HttpOnly and SameSite=Strict (or Lax) attributes to all cookies.
3.2. Server Leaks Version Information ● 	Description:
The Server HTTP response header reveals backend version information.
Risk:
Aids attackers in targeting known vulnerabilities for that version.
Remediation:
Suppress or sanitize server version headers.
3.3. HSTS Not Set ● 	Description:
The Strict-Transport-Security header is not present.
Risk:
Allows SSL stripping and downgrade attacks.
Remediation:
Set the HSTS header in all HTTPS responses.
3.4. Timestamp Disclosure ● 	Description:
JavaScript files and APIs leak Unix timestamps.
Risk:
Can reveal system activity, build times, or enable timing attacks.
Remediation:
Avoid leaking timestamps unless strictly necessary.
3.5. X-Content-Type-Options Header Missing ● 	Description:
Many resources do not send X-Content-Type-Options: nosniff.
Risk:
Enables browsers to MIME-sniff and potentially execute non-script files as scripts.
Remediation:
Add this header to all responses.
4. Informational Findings ● Authentication Requests Identified:
/xas/ processes authentication.
Information Disclosure in localStorage:
Application data stored in browser localStorage may be at risk if XSS is present.
Suspicious Comments in JavaScript:
Comments such as "BUG" found in code; remove all debug or sensitive comments from production.
Session Management and Cache-Related Issues:
Additional info that could help attackers or be misconfigured.
Summary Table
Conclusion & Recommendations
The Task Tracker application at is critically vulnerable to credential leaks and data exposure due to high-risk findings like hash and PII disclosure. Several security misconfigurations further increase the attack surface.
Urgent Recommendations:
Remove all hashes and PII from API responses immediately.
Harden HTTP headers and cookie attributes (CSP, HSTS, HttpOnly, SameSite, X-Frame-Options).
Restrict or disable actuator and diagnostic endpoints.
Eliminate all server version disclosures.
Regularly audit, test, and monitor the application for new vulnerabilities. Failure to address these issues can result in account compromise, data theft, legal repercussions, and loss of user trust. Immediate remediation is required before any production deployment.
URL / Endpoint | Reque 
ster | Appro ver | Ad min | Descrip tion
Yes | Yes | Yes | Home / Dashbo ard
Yes | Yes | Yes | Login 
Page
Yes | Yes | Yes | API 
Endpoi 
nt
Yes | Yes | Yes | API 
Endpo
i nt
No | No | Yes | Admin 
Homep 
age
No | No | Yes | Admin 
Workfl ow Dashbo ard
No | No | Yes | Admi
n 
Workf
l ow Overvi ew
No | No | Yes | SSO 
User Overv
i ew
No | No | Yes | SSO 
User 
New/
E 
dit
Yes | Yes | Yes | Produc 
t 
Overvi ew
Yes* | Yes* | Yes | Produc 
t 
New/E 
dit
Yes | Yes | Yes | Vendo
r 
Overvi ew
Yes* | Yes* | Yes | Vendo
r 
New/E 
dit
No | Yes | No | Task 
Inbox (Appr o ver only)
No | Yes | No | Task Appro
v er Page
Endpoint | Method | Response Code | Access Granted? | Score | Screenshot Figure(s)
/xas/ | POST | 200 | Yes | 1.0 | Fig 3.1.1
Severity Vulnerability | Severity Vulnerability | Affected Endpoint(s) | Remediation
High 	Hash Disclosure (BCrypt) | High 	Hash Disclosure (BCrypt) | POST /xas/ | Never expose password hashes
Medium CSP Header Not Set | Medium CSP Header Not Set | /, /index.html, 
/login.html | Add Content-Security- 
Policy header
Anti-clickjacking Medium 
Header Missing | Anti-clickjacking Medium 
Header Missing | /, /index.html, 
/login.html | Add X-Frame-Options/CSP header
Medium Spring Actuator Info Leak | Medium Spring Actuator Info Leak | /xas/actuator/health | Restrict/disable actuator endpoints
Low | Cookie HttpOnly/SameSite 
Flags | Multiple cookies in 
/xas/ | Set HttpOnly and SameSite flags
Low | HSTS Header Not Set | All | Add Strict-Transport- 
Security
Low | X-Content-Type-
Options Header 
Missing | Most responses | Add X-ContentType- Options: 
nosniff
Low | Timestamp Disclosure | /dist/*.js | Avoid exposing timestamps
URL/Endpoint | Method | Member1 
Access | Notes
/ | GET | Yes | Main app entry
/index.html | GET | Yes | Main index page
/login.html | GET | Yes | Login page
/js/login.js | GET | Yes | Login JS
/dist/pages/TaskTracker.MyAccountViewEdit.js | GET | Yes | My 
account view/edit
/dist/pages/TaskTracker.TaskEdit.js | GET | Yes | Task edit page
/dist/pages/TaskTracker.TaskOverview.js | GET | Yes | Task overview page
/dist/pages/TaskTracker.TeamOverview.js | GET | Yes | Team overview page
/dist/TaskTracker.FullScreenPopup- CliqHeep.js | GET | Yes | Misc widget
/dist/TaskTracker.Tasks_TopBar-D7rymWoA.js | GET | Yes | Top bar widget
/logo.png | GET | Yes | App 
logo
/manifest.webmanifest | GET | Yes | PWA 
manifest
/xas/ | POST | Yes | Mendix runtime API 
(actions)
Page/Endpoint | Member1 | Manager1 | Comments
TaskOverview | Yes | Yes | Accessible to both
TaskEdit | Yes | Yes | Accessible to both
TeamOverview | Yes | Yes | Should be restricted?
MyAccountViewEdit | Yes | Yes | Accessible to both
/xas/ API | Yes | Yes | Accessible to both
Severi ty | Issue | Endpoint(s) / 
Location | Remediation 
/ Note
High | Hash 	 
Disclosure 
(BCrypt) | POST /xas/ | Remove hashes from all responses
High | PII Disclosure | POST /xas/ | Never expose PII in any client response
Mediu m | CSP Header 
Not Set | All pages | Add Content- 
Security- 
Policy
Mediu m | CORS 
Misconfigurati on | External resources, 
JS, fonts | Limit Access- 
Control- Allow-Origin
Mediu m | Missing Anti- 	 
Clickjacking 
Header | All responses | Add X- 
Frame- 
Options or CSP frame- ancestors
Mediu m | Spring 
Actuator Info 
Leak | /xas/actuator/hea lth | Restrict/disa ble actuator endpoints
Low | Cookie Flags 	 
(HttpOnly, 
SameSite) | All cookies | Set HttpOnly and SameSite flags
Low | Server Version Info | All | Suppress version information
Low | HSTS Not Set | All | Set Strict- Transport- Security header
Low | Timestamp 
Disclosure | Static assets, API | Remove unnecessary timestamp leaks
Low | X-Content- 	 
 
Type-Options 
Header 
Missing | All | Set X- Content- 
Type- Options: nosniff
Info | Auth 
 
Requests, localStorage, 
Comments | Various | Review, clean up, and monitor
```


## Quick interpretation checklist
- [ ] Note any missing security headers/cookie flags
- [ ] RBAC failures (who could do what they shouldn’t)
- [ ] IDOR exposures (which objects were accessible)
- [ ] API auth behavior (401/403 present where expected)

