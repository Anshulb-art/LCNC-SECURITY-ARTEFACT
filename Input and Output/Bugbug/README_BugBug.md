# BugBug — E2E Evidence (Results-Aligned)

## What this documents
Short, focused recordings/screenshots proving role behavior and ownership rules. These directly back up RBAC/IDOR conclusions.

## How we ran it (short)
- Record **Requester** and **Approver/Admin** flows (login, key actions, denied attempts).
- Export screenshots/video and a 4–8 line `NOTES.txt` (goal → steps → expected vs actual).
- Store under `reports/<App>/BugBug/` with the standard naming convention.

### Results (from BugBug Analysis.docx)
Below is the exact summary extracted from the provided Word document (trimmed to plain text).

```
BugBug Analysis
1. 	Coffee Service BugBug Test
1. Authentication Test
A) Valid Login Test
Test Objective:
Verify that users can successfully log in with valid credentials and are granted access to their respective dashboards.
Test Steps:
Navigate to the login page.
Enter valid credentials for Customer (Jack).
Enter valid credentials for Engineer (Bill).
Click the login button.
Verify that the correct dashboard/homepage loads. Results:
Customer (Jack): Login successful, Dashboard displayed as expected.
Engineer (Bill): Login successful, Dashboard displayed as expected.
Figure : Logged in as Customer Javck
Fig 1: Logged in as Customer Jack
Fig 2: Dashboard after successful run
Fig 3: Login test passed for Customer Jack
Fig 4: Starting to test for Engineer Bill
Fig 5: Login Test Passes for Engineer Bill
Status: PASSED
Risk Measurement:
Likelihood: Low (test consistently passes)
Impact: High (if broken, users cannot access the system) Recommendation:
Retest after any authentication module updates to catch regressions early.
B) Logout
Test 	Test
Objective:
Verify that users can log out successfully and are redirected to the login screen. Test Steps:
Log in with valid credentials (Customer and Engineer).
Click the logout button.
Verify redirection to the login screen. Results:
Customer (Roxanne): Successfully logged out and redirected to login screen.
Engineer (Bill): Successfully logged out and redirected to login screen.
Fig 6: Logout Test passed for Customer Roxanne
Fig 7: Logout Test Passed Engineer Bill
Status: PASSED
Risk Measurement:
Likelihood: Low
Impact: Moderate (if logout fails, user sessions could be exposed) Recommendation:
Retest logout after any changes to session handling or navigation.
C) Invalid
Login 	Test
Objective:
Verify that the application provides clear and consistent error messages for invalid login attempts, regardless of user role.
Test Steps:
Attempt to log in with incorrect credentials for both Customer and Engineer accounts.
Observe the error feedback or message. Expected Result:
Both roles receive the same clear error message (e.g., “Invalid credentials”). Actual Results:
Customer Account: Displays expected error message (“Invalid credentials”).
Engineer Account: Displays expected error message (“Invalid credentials”).
Fig 8: Invalid Login Customer Roxanne
Fig 9: Test Pass for Engineer Bill
Status: Passed
Risk Measurement:
Likelihood: Low
Impact: Moderate (confusing for users; minor security risk for user enumeration) Recommendation:
Update authentication logic to ensure all user roles receive the same clear error message on failed login attempts.
2) UI Functional Tests
A) Button
Clicks Test Objective:
Ensure all critical buttons trigger the correct actions and UI responses. Test Steps:
Click each critical button (e.g., Save, Cancel, Next).
Add assertions to verify correct outcomes (modal opens, page changes, etc.). Results:
All button actions verified and functioned correctly.
Fig 10: Button Clicks Test Passed
Status: PASSED
Risk Measurement:
Likelihood: Low
Impact: Moderate (broken UI can affect business process and user satisfaction) Recommendation:
Automate regression button tests and retest after each UI update.
2. Form Submissions
Goal: Ensure forms work for both valid and invalid data.
How:
a) Valid Data:
Test Objective:
Ensure forms submit successfully when all inputs are valid. Test Steps:
Fill out forms with valid data.
Click submit.
Assert that confirmation or correct data display occurs. Results:
Forms submitted successfully and provided correct feedback.
Fig 10: Valid data test passed
Status: PASSED
b) Invalid/Missing Data:
Test Objective:
Ensure forms display proper validation errors when invalid or missing data is submitted. Test Steps:
Leave required fields blank or enter invalid data.
Click submit.
Assert for error messages or field highlights. Results:
Correct error messages and validation hints were displayed.
Fig 11: Invalid data test passed
Status: PASSED
Risk Measurement:
Likelihood: Low
Impact: Moderate (could block users or allow bad data) Recommendation:
Continuously expand tests for new fields or validation scenarios as the app grows.
3) Based Access Control
(RBAC) Test Objective:
Ensure each user role (Customer, Engineer, Admin, Manager) can access only authorized features and data.
Test Steps:
Log in as each role.
Navigate to different pages/features.
Attempt restricted actions (directly or via URL).
Assert correct visibility/access per role. Results:
RBAC is functioning as expected.
Unauthorized URL access attempts redirected users to home page.
Fig: Logged in as customer jack
Fig: Tried To copy url of Engineer bill
Status: PASSED
Risk Measurement:
Likelihood: Low (based on current testing)
Impact: Critical (failure could lead to data breaches or privilege escalation)
Recommendation:
Retest RBAC after any update involving user roles or permissions.
Regularly review test evidence for audit and compliance purposes.
4. General Recommendations
Integrate BugBug into CI/CD:
Automate all tests in your deployment pipeline for continuous quality assurance.
Maintain Test Coverage:
Regularly update BugBug scenarios to cover new features and regression risks.
Store Evidence:
Save screenshots and logs for every test run, especially failed ones, to support audits and troubleshooting.
Periodic Manual Review:
Supplement automation with manual exploratory testing for complex scenarios.
Application 2:
2. Purchase Request App
Figure 1: Purchase Request App Started
1. Authentication Tests
A) Valid Login Test
Test Objective: Confirm users can log in successfully using valid credentials and access their respective dashboards.
Steps:
Log in as Demo Administrator.
Log in as Demo Approver.
Figure 2: Successfully Signed In As Demo Administrator
Figure 3: Assertions Used for the Demo Administrator
Figure 4: Login Successful for Demo Approver
Figure 5: Assertions Used for Demo Approver
Status: PASSED
Risk:
Likelihood: Low
Impact: High (essential for application access)
Countermeasures:
Retest regularly post-authentication updates to ensure continued reliability.
Invalid Login Test
Test Objective: Ensure consistent and clear error messages when invalid credentials are entered.
Steps:
Attempt login with incorrect credentials for Demo Administrator and Demo Approver.
Figure 6: Invalid login tried with incorrect password on demo administrator
Figure 7: Assertions Used for Invalid Tests on Demo Administrator
Figure 8: Invalid login attempted on Demo Approver, Sign in Failed
Status: PASSED
Risk:
Likelihood: Low
Impact: Moderate (clarity impacts user experience) Countermeasures:
Maintain uniform error feedback across all roles.
Logout Test
Figure 9: Sign out was successful for demo administrator
Test Objective: Validate successful logout and ensure session termination with no residual access.
Steps:
Logout after valid login as Demo Administrator and Demo Approver.
Verify redirection to the login screen.
Figure 10: Assertions used for Demo Administrator
Figure 11: Sign out Successfully for Demo Approver
Figure 12: Assertions Performed on Sign out test Status: PASSED
Risk:
Likelihood: Low
Impact: High (critical for preventing unauthorized access)
Countermeasures:
Routine testing post-session management updates.
2. UI Functional Tests
A) Button Clicks Test
Test Objective: Verify all critical buttons trigger correct behaviors. Steps:
● 	Test Cancel, Save, and other major buttons for all user roles (Administrator, Approver, Requester).
Figure 13: Running Buton Click Tests and Checking cancel and Save Button Functionality
Figure 14: Button Tests Successfully Passed for Administrator
Figure 15: Assertion used for Button Clicks on Administrator account
Figure 16: Button Clicks Test Successful on Approver
Figure 17: Assertions used for Approver
Figure 18: Button Clicks Test passed for requester user
Figure 19: Assertions used for Requester user
Status: PASSED
Risk:
Likelihood: Low
Impact: Moderate (functional UI essential for usability) Countermeasures:
Automated regression testing for continuous assurance.
B) Form Submission Test (Valid Data)
Valid Data Submission
Test Objective: Ensure form submission succeeds with valid data. Steps:
Fill forms with valid data and submit.
Figure 20: Form Submission Valid Data Administrator Passed
Figure 21: Assertions Used
Figure 22: Form Submission Valid Data Requester Passed
Figure 23: Assertions used
Status: PASSED
C) Form Submission Test (Invalid/Missing Data)
Figure 24: Shows Error on Admin dashboard for missing data
Test Objective: Ensure appropriate validation and error handling for invalid or missing form data.
Steps:
● 	Attempt submissions with invalid or missing data.
Figure 25: Assertion Used
Figure 26: Shows Error on requester dashboard
Status: Passed
Risk:
Likelihood: High (common user error scenario)
Impact: High (data integrity significantly compromised)
Countermeasures:
Immediately enhance validation to reject incorrect data explicitly.
Implement stringent client and server-side validation checks.
Regularly audit data validation mechanisms.
3. Role-Based Access Control (RBAC) Tests
Test Objective: Validate enforcement of user permissions and restrictions.
Steps:
● 	Attempt access to Admin features from Requester role directly via URL.
Figure 27: Logged in as Requester
Figure 28: Requester Dashboard
Figure 29: Failed to open Admin Dashboard Status: PASSED
Risk:
Likelihood: Low
Impact: Critical (potential unauthorized access to sensitive features) Countermeasures:
Continuous RBAC tests after any permission updates.
Routine monitoring for unauthorized access attempts.
Overall Recommendations:
Implement comprehensive automated tests in CI/CD pipelines for continuous coverage.
Conduct periodic manual reviews and security assessments.
Enhance validation processes to uphold data integrity.
Regularly update test scenarios to reflect new features or system modifications.
Application 3:
2. Task Tracker Security App
Fig 1: Successful App Run From Mendix Platform
1. Authentication Tests
a) Valid 	Login
Test 	Test
Objective:
Ensure that users can log in successfully using valid credentials and access appropriate role-specific dashboards.
Steps:
Log in as Manager1 (Manager role)
Log in as Member1 (Member role)
Confirm correct dashboard and access privileges
Fig 2: Assertions Performed
Fig 3: Tests Passed
Fig 4: Test Assertions for Member
Fig 5: Test Passed for member login
Status: PASSED
Risk:
Likelihood: Low
Impact: High (inability to log in impacts system usability significantly) Countermeasures:
Regular retesting after system updates to ensure stable authentication processes.
b) Invalid 	Login
Test 	Test
Objective:
Verify that the system consistently provides clear error feedback when invalid credentials are entered, and no partial logins occur.
Steps:
Attempt login with incorrect credentials for Manager1 and Member1
Check error feedback
Fig 6: Test Assertions for Manager
Fig 7: Test Passed for Manager
Fig 8: Test Asserted for Member
Fig 9: Test Passed for Member Status: PASSED
Risk:
Likelihood: Low
Impact: Moderate (clear error messages enhance user trust and experience) Countermeasures:
Continuously monitor for consistent feedback implementation across all roles.
c) Logout Test 	Test
Objective:
Verify successful logout and session termination, ensuring no further access post- logout.
Steps:
Log in as Manager1 and Member1
Logout and verify redirection to the login page
Attempt accessing protected pages directly via URL
Fig 10: Logout Test Assertion For Manager
Fig 11: Logout Test Pass For Manager
Fig 12: Logout Test Assertion for Member
Fig 13: Logout Test Pass for Member
Status: PASSED
Risk:
Likelihood: Low
Impact: High (failure could lead to session hijacking and unauthorized access)
Countermeasures:
Periodic checks after updates that involve session management changes.
2. UI Functional
Tests Test
Objective:
Ensure critical buttons function correctly, triggering expected behaviors.
Steps:
● 	Click all major buttons (Save, Cancel, Next, Submit) for both Manager and Member roles
Fig 14: Button Clicks Test Assertion for Manager
Fig 15: Button Clicks Test Passed for Manager Role
Fig 16: Button Clicks Test Asserted for Member
Fig 17: Button Clicks Test Passed for Member
Status: PASSED
Risk:
Likelihood: Low
Impact: Moderate (UI failure could affect user operations and productivity)
Countermeasures:
Implement automated regression testing after UI changes.
b) Form Submission Test
Valid Data:
Valid Data Submission
Test Objective:
Confirm forms submit correctly when valid data is entered.
Steps:
Enter valid data into forms and submit
Fig 18: Assertions for Valid Data
Fig 19: Data is Accepted- Passed
Status: PASSED
Invalid/Missing Data: Test Objective:
Ensure forms handle invalid or missing inputs appropriately.
Steps:
Attempt form submission with invalid or missing data
Fig 20: Shows Error Messager
Status: PASSED
Risk:
Likelihood: Moderate (data input errors common among users)
Impact: Moderate (incorrect data submission can disrupt data integrity and system reliability)
Countermeasures:
Reinforce strict validation on all forms; maintain comprehensive automated tests.
3. RBAC (Role-Based Access Control) Tests
Direct URL Access/Bypass
Test Objective:
Ensure users cannot access unauthorized pages/features by direct URL or manipulation.
Steps:
Logged in as Member1, attempt direct access to Manager-only pages via URL
Logged in as Manager1, attempt direct access to Admin-only pages
Expected Results:
Users should be denied access or redirected appropriately.
Fig 21: Logged In as Manager 1
Fig 22: View Team only access by manager1
Fig 23: Logged In as Member1
Fig 24: Try to access Manager1 link
Fig 25: Role Based Access Control Failed- links can be bypassed
Fig 26: Test Failed
Actual Results:
Manager1: Appropriate access; Manager-specific features correctly accessed. (Fig 21 & Fig 22)
Member1: RBAC failure; Member1 able to bypass restrictions and access Manager-only links. (Fig 23, Fig 24, Fig 25 & Fig 26)
Status: FAILED +
Risk and Impact:
Likelihood: High
Impact: Critical (potential privilege escalation and unauthorized sensitive data access)
Countermeasures:
Immediately strengthen RBAC enforcement across all system components.
Regularly perform code audits and penetration testing.
Employ continuous monitoring and automated alerts for access violations.
1
Overall Recommendations:
Integrate BugBug automated testing into the CI/CD pipeline.
Regularly update tests in line with application changes.
Conduct periodic manual testing and thorough security audits.
Provide training and clear documentation to developers and testers on security best practices.
```


## Quick interpretation checklist
- [ ] Each flow ties to a concrete claim (allowed/denied)
- [ ] Screens show both the attempted action and the system response
- [ ] Notes explain the expected control and the observed behavior
