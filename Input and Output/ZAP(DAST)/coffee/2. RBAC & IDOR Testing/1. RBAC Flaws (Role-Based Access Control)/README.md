# DAST — Coffee — 2. RBAC & IDOR Testing — 1. RBAC Flaws (Role-Based Access Control)

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


