# DAST — Coffee — 1. Authentication Security Testing — 2. Session FixationReuse Attack Test

**Result:** PASSED

## What this test proves

A session cookie from user A must not grant access in user B’s browser.

## What to look for in the screenshots

- Cookie copy
- Attempted reuse
- Redirect to login

## Evidence & folder layout

This folder’s images are named **Step …** and **Result …** in execution order. Compare your run to the **Result** image/state.

## Risk

Likelihood: Low • Impact: High.

## Recommendation

Rotate session IDs on login; set HttpOnly/SameSite.


