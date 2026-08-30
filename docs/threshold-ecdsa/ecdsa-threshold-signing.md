# Router A/B ECDSA Derivation Signing

Last updated: 2026-08-30

## Scope

ECDSA product signing uses Router A/B ECDSA derivation. Public SDK callers
enter through an exact Wallet Session authorization and a concrete EVM-family
chain target. They do not call threshold ECDSA authorize, presign, sign-init,
or sign-finalize endpoints.

The current lifecycle is:

- EVM-family digest signing uses Router A/B normal signing.
- A pool hit consumes one prepared Router A/B presignature and signs through
  the normal-signing boundary.
- A pool miss refills through Router A/B pool-fill and then signs through the
  same normal-signing boundary.
- Registration, activation, recovery, refresh, export, and keyset publication
  use the Router A/B ECDSA derivation lifecycle surfaces described in
  [router-ab/protocol.md](../router-ab/protocol.md).

## Public Signing Boundary

The public client boundary is the Router A/B normal-signing route pair:

- `POST /router-ab/ecdsa-derivation/sign/prepare`
- `POST /router-ab/ecdsa-derivation/sign`

Presignature pool-fill uses:

- `POST /router-ab/ecdsa-derivation/presignature-pool/fill/init`
- `POST /router-ab/ecdsa-derivation/presignature-pool/fill/step`

The SDK sends the primary `WalletSessionOperationCredentialV1` as the bearer
`Authorization` credential with browser credentials omitted. The server
resolves that credential to one exact Wallet Session authorization before
admitting the ECDSA operation.

Request builders bind the typed Router A/B ECDSA derivation scope, request and
operation ids, operation digests, signing digest, presignature id, expiry, and
response-digest checks before a signature is accepted. The bearer authenticates
the HTTP request; the canonical protocol request carries the resolved ECDSA
material and operation scope.

The former threshold ECDSA authorize, presign, and signing endpoint family is
absent from active Express and Cloudflare route definitions.

## Exact Wallet Session Identity

Every ECDSA normal-signing and pool-fill operation is admitted against one
exact V2 Wallet Session authorization. The resolved identity binds:

- wallet id, authority id, and `walletAuthMethodId`;
- authorization id, Wallet Session id, and quota id;
- authority digest, authority revocation epoch, and expiry; and
- the ECDSA `sign` capability subject naming the exact material activation.

The material activation resolves the key handle, relayer key, participant set,
signing worker, runtime-policy scope, normal-signing state, and EVM-family
public identity. Each resolved value must agree with the exact authority,
method, Wallet Session, quota, and capability subject before admission. No
route infers an authentication method from wallet uniqueness, and sibling
method sessions remain independent.

The concrete EVM-family chain target is a separate typed operation input. It
can partition request, policy, lane, and transaction state; it does not replace
the exact authority, method, session, or quota identity or partition the
EVM-family key identity. Signing-root identifiers remain protocol and
persistence fields rather than client-selected authorization identity.

## Presignature Lifecycle

Router A/B preserves the user-facing latency model:

- Pool hit: pop one local presignature, finalize through Router A/B normal
  signing, and consume the matching server presignature exactly once.
- Pool miss: perform Router A/B pool-fill, then continue through the normal-
  signing boundary.
- A missing pool-fill response is a hard failure. There is no alternate
  threshold presignature route.

Signing and pool-fill admission consume the exact session quota and bind the
operation claim to the request and material scope. A claimed presignature must
not return to the available pool after use, abort, expiry, or drift rejection.

ECDSA export uses the exact `export_keys` capability subject and a fresh
operation-bound step-up. It does not substitute another authority or auth
method for the session that admitted the operation.

## Implementation Anchors

The live route and request boundaries are implemented in:

- `packages/wallet-server/src/router/transport/fetch/routes/thresholdEcdsa.ts`
- `packages/shared-ts/src/utils/routerAbEcdsaDerivation.ts`
- `packages/shared-ts/src/device-linking/contracts.ts`

The shared Router A/B protocol details and canonical encoding rules are in
[router-ab/protocol.md](../router-ab/protocol.md).
