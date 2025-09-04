# DAST — Task — HOW TO reproduce: 1. Authentication Security — 2. Session ReuseFixation Testing

## Prerequisites

- App is running (e.g., http://127.0.0.1:8080).
- Use the same roles shown in this folder’s screenshots.
- Proxy via **ZAP** for DAST tests, or use **BugBug** for UI/E2E tests.

## Steps

1. Login as A; copy cookie.
2. Login as B; replace cookie and refresh protected page.

## Verify

- Access denied; redirected to login.

## Notes

Keep screenshots and reports with these docs.


