# DAST — Task — HOW TO reproduce: 3. API Security & Input Validation Testing — 1. Unauthenticated API Access

## Prerequisites

- App is running (e.g., http://127.0.0.1:8080).
- Use the same roles shown in this folder’s screenshots.
- Proxy via **ZAP** for DAST tests, or use **BugBug** for UI/E2E tests.

## Steps

1. Capture authenticated API call.
2. Resend with cookies removed.

## Verify

- 401/403 expected. **200 + token** = vulnerability.

## Notes

Keep screenshots and reports with these docs.


