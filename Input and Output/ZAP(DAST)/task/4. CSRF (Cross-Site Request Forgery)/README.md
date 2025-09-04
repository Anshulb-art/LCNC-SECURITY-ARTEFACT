# DAST — Task — 4. CSRF (Cross-Site Request Forgery)

**Result:** INFO

## What this test proves

State-changing requests must include a validated CSRF token.

## What to look for in the screenshots

- POSTs include token
- ZAP shows no critical CSRF alerts

## Evidence & folder layout

This folder’s images are named **Step …** and **Result …** in execution order. Compare your run to the **Result** image/state.

## Risk

Likelihood: Varies • Impact: High.

## Recommendation

Enforce tokens + SameSite cookies; validate server-side.


