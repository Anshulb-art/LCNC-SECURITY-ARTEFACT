# DAST — Purchase — 1. Authentication Security — 1. Brute-Force Login Test

**Result:** WEAK CONTROLS

## What this test proves

Repeated bad passwords should trigger rate-limiting/lockout to resist credential stuffing.

## What to look for in the screenshots

- ZAP fuzzer results
- 401 for bad attempts
- No throttling observed

## Evidence & folder layout

This folder’s images are named **Step …** and **Result …** in execution order. Compare your run to the **Result** image/state.

## Risk

Likelihood: High • Impact: High. Current controls are insufficient (no lockout/rate limiting).

## Recommendation

Add **rate-limiting**, **temporary lockout**, and optionally **CAPTCHA**.


