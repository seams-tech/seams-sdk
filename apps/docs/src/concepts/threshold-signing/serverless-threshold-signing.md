---
title: Serverless threshold signing
description: Deploy self-hostable threshold wallet roles to serverless infrastructure with explicit operational boundaries.
---

# Serverless threshold signing

Seams provides self-hostable threshold embedded wallets that deploy to
Cloudflare. It uses threshold signing and hidden-share derivation. Normal
signing produces signature shares; no single runtime needs to assemble the
canonical private key.

## Signing boundary

The ordinary signing path is share-based:

```text
holder-side signing share + admitted server-side signing share -> signature
```

Holder-side material lives in wallet-origin runtime boundaries. Server-side
material lives behind Router admission, worker auth, policy, replay checks,
quota checks, signing budgets, and lane binding.

The canonical private key is not reconstructed in the wallet iframe, Router, or
SigningWorker during normal signing. Export is a separate operation with fresh
authorization, audit capture, and public-key parity checks.

## Split-role derivation

Ed25519 material is produced by Streaming Yao between Deriver A and Deriver B.
ECDSA material uses strict threshold-PRF derivation and additive scalar shares.
Each role receives only the output it is allowed to use:

- client and browser workers receive holder-side signing material or handles;
- Router receives public routing and policy state;
- Deriver roles receive role-local protocol state;
- SigningWorker receives activated server-side signing material and one-use
  presignature state.

These curve-specific flows derive compatible signing shares without joining the
underlying root material in one process. Deployments that need a stronger
server runtime boundary can place sensitive roles inside TEEs while preserving
the same threshold-signing model.

## Cloudflare-native self-hosting

Seams is self-hostable and serverless-friendly. Teams can run split roles on
Cloudflare Workers and Durable Objects with near-zero initial hosting cost and
no server fleet.

That gives teams a practical path from prototype to production:

- start with a same-account development deployment or a separate-account
  production-parity deployment;
- keep Router, Deriver, and SigningWorker roles separated;
- scale with Workers instead of managing long-running servers;
- preserve the same wallet architecture as operational isolation increases.

Small teams can test the model without standing up bespoke infrastructure.
Larger deployments can add private bindings, isolated workers, dedicated
storage, TEEs, and stricter release controls around the same protocol shape.

Deployable runtime artifacts and development examples are available separately
from the planned production portability product. R122 will add the customer
deployment compiler, wallet import, continuity verification, and explicit
cutover. A development deployment does not establish those migration guarantees
or independent A/B administrative isolation.

R120's managed tenant-root backups also do not constitute a portable wallet
inventory. R121 first adds tenant-controlled recovery of the exact root;
R122 owns wallet/deployment migration. See
[recovery and portability](/deploy-and-operate/recovery-and-portability) for
current availability.

Read next:

- [Threshold Signing](/concepts/threshold-signing/)
- [Streaming Yao A/B](/concepts/threshold-signing/streaming-yao-ab)
- [Route Auth And Deployment](/concepts/advanced/route-auth-and-deployment)
