---
title: Threshold APIs
description: Stable threshold session-policy helpers, PRF salts, and intent digest exports from @seams/wallet/threshold.
---

# Threshold APIs

`@seams/wallet/threshold` is the stable protocol-facing surface for applications
that must reproduce threshold session-policy inputs or registration digests.

It exports:

- `THRESHOLD_SESSION_POLICY_VERSION`;
- `buildEd25519SessionPolicy`;
- `computeEd25519SessionPolicyDigest32`;
- the `Ed25519SessionPolicy` type;
- `PRF_FIRST_SALT_V1` and `PRF_SECOND_SALT_V1`;
- `computeThresholdEcdsaKeygenIntentDigest`.

Keep policy construction at a trusted boundary. The digest commits to the
precise policy; changing an input creates a different authorization object.
Most browser integrations should let `SeamsWeb` own this work.

Read [threshold signing](/concepts/threshold-signing/) before integrating this
entrypoint directly.
