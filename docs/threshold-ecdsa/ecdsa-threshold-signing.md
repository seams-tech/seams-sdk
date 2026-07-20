# Router A/B Router A/B ECDSA derivation Signing

Last updated: 2026-06-17

## Scope

ECDSA signing now uses Router A/B Router A/B ECDSA derivation for product signing flows. Public
SDK callers provide wallet/session context and a concrete chain target; they do
not call public threshold ECDSA authorize, presign, sign-init, or sign-finalize
routes.

The active release requirement is:

- EVM-family digest signing uses Router A/B Router A/B ECDSA derivation normal signing.
- Pool-hit signing consumes one prepared Router A/B Router A/B ECDSA derivation presignature.
- Pool-miss signing refills through Router A/B Router A/B ECDSA derivation pool-fill and then
  signs through the same Router A/B normal-signing boundary.
- Registration, activation, recovery, refresh, export, and keyset publication
  keep using the current Router A/B ECDSA derivation lifecycle surfaces described in
  [router-a-b-SPEC.md](../router-a-b-SPEC.md).

## Public Signing Boundary

The public client boundary is the Router A/B normal-signing route pair:

- `POST /router-ab/ecdsa-derivation/sign/prepare`
- `POST /router-ab/ecdsa-derivation/sign`

The Router A/B Router A/B ECDSA derivation pool-fill boundary is:

- `POST /router-ab/ecdsa-derivation/presignature-pool/fill/init`
- `POST /router-ab/ecdsa-derivation/presignature-pool/fill/step`

The SDK sends a bearer Wallet Session JWT with browser credentials omitted. The
request builders bind the typed Router A/B ECDSA derivation scope, request id, signing digest,
presignature id, expiry, and response digest checks before the signature is
accepted by the SDK.

The old public threshold ECDSA authorize, presign, and signing endpoint family
is deleted from active Express and Cloudflare route definitions.

## Identity Model

Public ECDSA operation inputs stay wallet and chain scoped:

```ts
{
  walletSession: {
    walletId: string;
    walletSessionUserId: string;
  };
  chainTarget:
    | { kind: 'tempo'; chainId: number; networkSlug: string }
    | { kind: 'evm'; namespace: 'eip155'; chainId: number; networkSlug: string };
}
```

`signingRootId` and `signingRootVersion` are server/protocol/persistence
normalization details. They should not reappear as client SDK domain fields.
Client-side active signing state uses Router A/B key-handle state and Wallet
Session credentials instead.

## Presignature Lifecycle

Router A/B Router A/B ECDSA derivation preserves the user-facing latency model:

- Pool hit: pop one local presignature, finalize through Router A/B normal
  signing, and consume the matching server presignature exactly once.
- Pool miss: perform Router A/B Router A/B ECDSA derivation pool-fill, then continue through the
  Router A/B normal-signing boundary.
- Missing `poolFill` is a hard failure in live presign refill. There is no
  fallback to the old public threshold ECDSA presign routes.

One-use presignature semantics are release-critical. A claimed presignature must
be bound to the exact request context and must not return to the available pool
after use, abort, expiry, or drift rejection.

## Current Evidence

Current implementation and cleanup evidence is tracked in:

- [router-a-b-SPEC.md](../router-a-b-SPEC.md)
- [router-a-b-deployment.md](../router-a-b-deployment.md)
- [router-a-b-SPEC.md](../router-a-b-SPEC.md)
- [refactor-68-wallet-session-v2.md](../refactor-68-wallet-session-v2.md)

Local type-checks, focused Router A/B Router A/B ECDSA derivation tests, source guards, local
smoke, bundled smoke, release checks, and staging dry-run are recorded there.
Deployed Cloudflare browser evidence remains the release-tail gate.
