---
title: Auth Planes
description: Separate application login, wallet authority, signing budget, and delegated execution into explicit auth planes.
---

# Auth planes

Seams keeps login, wallet authority, signing budget, and delegated execution
separate. A route or operation should belong to one primary auth plane.

| Plane                | Purpose                                                      |
| -------------------- | ------------------------------------------------------------ |
| App session          | Proves the user is logged into the app or identity provider. |
| Wallet Session       | Admits reusable wallet-user operations.                      |
| Threshold session    | Proves curve/session-specific signing authority.             |
| Wallet Session quota | Carries TTL and remaining-use budget for reusable signing.   |
| Capability grant     | Authorizes one exact operation and capability use.           |
| Delegation grant     | Policy and audit object for delegated execution.             |
| API credential       | Machine credential for scoped project or server routes.      |

App sessions alone cannot authorize transaction signing, key export, device
linking, agent lane issuance, or delegated execution.

## Why it matters

Each plane answers a different question:

1. Who is logged in?
2. Which wallet operation is allowed?
3. Which exact signing lane may participate?
4. Which budget or mandate is being spent?
5. Can the request still execute after revocation and replay checks?

Keeping those questions separate prevents a broad login token from becoming
wallet signing authority.
