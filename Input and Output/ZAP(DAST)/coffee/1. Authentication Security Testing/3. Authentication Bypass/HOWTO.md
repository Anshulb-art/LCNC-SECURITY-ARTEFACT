# DAST — Coffee — HOW TO reproduce: 1. Authentication Security Testing — 3. Authentication Bypass

## Prerequisites

- App is running (e.g., http://127.0.0.1:8080).
- Use the same roles shown in this folder’s screenshots.
- Proxy via **ZAP** for DAST tests, or use **BugBug** for UI/E2E tests.

## Steps

1. Clear cookies; run Spider.
2. Directly load /dashboard, /admin, etc.

## Verify

- Login page or 401/403, never the page content.

## Notes

Keep screenshots and reports with these docs.


