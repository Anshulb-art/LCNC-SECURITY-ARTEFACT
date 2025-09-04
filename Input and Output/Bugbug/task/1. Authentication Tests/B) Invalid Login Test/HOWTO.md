# BugBug — Task — HOW TO reproduce: 1. Authentication Tests — B) Invalid Login Test

## Prerequisites

- App is running (e.g., http://127.0.0.1:8080).
- Use the same roles shown in this folder’s screenshots.
- Proxy via **ZAP** for DAST tests, or use **BugBug** for UI/E2E tests.

## Steps

1. Open login page.
2. Enter valid credentials for the role shown.
3. Assert dashboard/header and role-specific widgets.

## Verify

- URL contains dashboard/home.
- Expected header/widget visible.

## Notes

Keep screenshots and reports with these docs.


