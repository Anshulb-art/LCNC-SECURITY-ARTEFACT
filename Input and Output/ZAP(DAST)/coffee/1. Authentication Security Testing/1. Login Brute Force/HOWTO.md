# DAST — Coffee — HOW TO reproduce: 1. Authentication Security Testing — 1. Login Brute Force

## Prerequisites

- App is running (e.g., http://127.0.0.1:8080).
- Use the same roles shown in this folder’s screenshots.
- Proxy via **ZAP** for DAST tests, or use **BugBug** for UI/E2E tests.

## Steps

1. Capture login POST.
2. Fuzz the password field (include one correct value).
3. Observe codes and timing.

## Verify

- Bad attempts throttled/locked after a threshold.

## Notes

Keep screenshots and reports with these docs.


