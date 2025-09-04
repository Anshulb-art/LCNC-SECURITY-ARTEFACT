# DAST — Coffee — HOW TO reproduce: 2. RBAC & IDOR Testing — 2. IDOR (Insecure Direct Object Reference)

## Prerequisites

- App is running (e.g., http://127.0.0.1:8080).
- Use the same roles shown in this folder’s screenshots.
- Proxy via **ZAP** for DAST tests, or use **BugBug** for UI/E2E tests.

## Steps

1. Login as low role.
2. Open a manager/admin page directly.

## Verify

- 403/redirect; no privileged view.

## Notes

Keep screenshots and reports with these docs.


