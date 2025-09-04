# DAST — Purchase — 2. Access Control Testing (RBAC,IDOR) — 2 Insecure Direct Object Reference (IDOR) Testing

**Result:** PASSED

## What this test proves

Lower roles must not access higher-privilege pages by direct URL or navigation.

## What to look for in the screenshots

- Lower role attempting privileged URL
- Block/redirect evidence

## Evidence & folder layout

This folder’s images are named **Step …** and **Result …** in execution order. Compare your run to the **Result** image/state.

## Risk

Likelihood: Variable • Impact: Critical if bypassable.

## Recommendation

Enforce **server-side** authorization on every page/action.


