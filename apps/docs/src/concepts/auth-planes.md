---
title: Auth Planes
---

# Auth Planes

Seams keeps login, wallet authority, signing budget, and delegated execution
separate. A route or operation should belong to one primary auth plane.

| Plane | Purpose |
| --- | --- |
| App session | Proves the user is logged into the app or identity provider. |
| Wallet Session | Admits wallet-user operations and signing-budget routes. |
| Threshold session | Proves curve/session-specific signing authority. |
| Signing grant | Carries TTL and remaining-use budget for a signing lane. |
| Delegation grant | Policy and audit object for delegated execution. |
| API credential | Machine credential for scoped project or server routes. |

App sessions alone cannot authorize transaction signing, key export, device
linking, agent lane issuance, or delegated execution.

## Why It Matters

Each plane answers a different question:

1. Who is logged in?
2. Which wallet operation is allowed?
3. Which exact signing lane may participate?
4. Which budget or mandate is being spent?
5. Can the request still execute after revocation and replay checks?

Keeping those questions separate prevents a broad login token from becoming
wallet signing authority.
