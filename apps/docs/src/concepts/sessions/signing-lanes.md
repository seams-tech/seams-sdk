---
title: Signing lanes
description: Select the exact custody, capability, policy, and nonce lane required for one signing operation.
---

# Signing lanes

A signing lane is the exact signing capability selected for one operation.

It answers:

```text
Who is signing?
Which auth method or delegated lane owns the capability?
Which curve and chain target are being used?
Which reusable Wallet Session authorization or verified step-up evidence authorizes it?
Which threshold session and key material must be used?
```

## Lifecycle

1. Read a side-effect-free snapshot.
2. Select one concrete lane or fail with a typed error.
3. Restore only that exact lane.
4. Plan auth for that lane.
5. Admit the exact authorized operation and consume quota when applicable.
6. Sign and finalize with that same lane.

Snapshot reads should not restore, prompt, consume quota, delete records, or
choose a fallback auth method.

## Sign-ready lane

A lane is sign-ready only after auth and material are both ready for the same
identity:

```text
sign-ready =
  (exact AuthorizationGrantRef + WalletSessionId + quotaId
    | verified step-up evidence)
  + exact AuthorizedOperationId
  + exact thresholdSessionId
  + Router A/B scope
  + valid quota state when reusable
  + runtime-validated worker material
```

Other states are useful for planning, but they must not enter final signing:

```ts [Protocol sketch]
switch (state.kind) {
  case 'runtime_validated':
    // The only sign-ready state: authorization, operation, threshold identity, quota,
    // Router A/B scope, and worker-owned material were validated together.
    return state.value;

  case 'restore_available':
    // Durable material exists, so an explicit restore phase can run first.
    throw new Error(`not sign-ready: ${state.reason}`);

  case 'material_hint_unvalidated':
    // A persisted handle exists, but the current worker has not validated it.
    throw new Error(`not sign-ready: ${state.reason}`);

  case 'invalid':
    // Required signing identity, auth, quota, material, or scope is missing.
    throw new Error(`not sign-ready: ${state.reason}`);

  case 'non_signing':
    // Valid lifecycle state for another purpose, but not Router A/B signing.
    throw new Error(`not sign-ready: ${state.reason}`);
}
```

Final signing consumes `runtime_validated` state. Restore, remint, repair, and
step-up happen in explicit planning phases before final signing.

## Examples

Refactor 90 lanes cover NEAR Ed25519 transactions, ECDSA Tempo signing, ECDSA
EVM signing, passkey accounts, Email OTP accounts, and VoiceID-gated intents.
Linked-device and delegated-agent lanes are follow-on work in Refactors 103 and 104.
