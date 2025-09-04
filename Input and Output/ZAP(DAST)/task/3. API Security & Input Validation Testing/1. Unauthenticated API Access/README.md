# DAST — Task — 3. API Security & Input Validation Testing — 1. Unauthenticated API Access

**Result:** PASSED

## What this test proves

APIs must reject unauthenticated requests and never return CSRF tokens.

## What to look for in the screenshots

- Manual Request Editor without cookies
- 200 OK with token (bad) or 401/403 (good)

## Evidence & folder layout

This folder’s images are named **Step …** and **Result …** in execution order. Compare your run to the **Result** image/state.

## Risk

Likelihood: High • Impact: Critical.

## Recommendation

Require auth on all stateful endpoints; never expose tokens unauthenticated.


