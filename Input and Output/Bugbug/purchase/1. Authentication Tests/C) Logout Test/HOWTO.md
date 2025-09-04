# BugBug — Purchase — HOW TO reproduce: 1. Authentication Tests — C) Logout Test

## Prerequisites

- App is running (e.g., http://127.0.0.1:8080).
- Use the same roles shown in this folder’s screenshots.
- Proxy via **ZAP** for DAST tests, or use **BugBug** for UI/E2E tests.

## Steps

1. Click logout from an authenticated session.
2. Open a protected URL in same tab.

## Verify

- Redirect to login.
- No protected content after logout.

## Notes

Keep screenshots and reports with these docs.


