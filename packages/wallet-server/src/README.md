# Server Package

`AuthService` and the Router API implement wallet registration, built-in owner
verification, opaque Wallet Sessions, signing admission, and recovery. Wallet
application authentication is intentionally outside this package.

## Authorization model

- Passkey and Email OTP verifiers create a server-internal
  `VerifiedOwnerProof`.
- Registration and unlock may consume that proof to mint an opaque, D1-backed
  Wallet Session token.
- Signing routes resolve the token into trusted curve-specific admission,
  consume server-authoritative budget, and never decode claims supplied by the
  client.
- Fresh step-up and export proofs authorize one exact operation without
  renewing a reusable Wallet Session.
- Linked-device signing keeps its separate JWT, local-presence, permission,
  quota, and revocation boundary.
- Console authentication uses its independent `console_session_v1` boundary in
  the console server package.

## Primary wallet routes

- `POST /wallets/register/setup`
- `POST /wallets/register/respond`
- `POST /wallets/register/activate`
- `POST /wallets/register/near-provisioning`
- `POST /wallet/unlock/challenge`
- `POST /wallet/unlock/verify`
- `POST /wallet/session/exchange/issue`
- `POST /wallet/session/exchange/redeem`
- `POST /router-ab/ecdsa-derivation/sign/prepare`
- `POST /router-ab/ed25519/sign/prepare`
- `GET /healthz`
- `GET /readyz`
- `GET /.well-known/webauthn`

The hosted-wallet exchange routes deliver one opaque Wallet Session token
through a short-lived, origin-bound, single-use capability. They do not create
an application session, and the outer application never receives the token.

## PRF Session Seal Module

`signingSessionSeal` is optional and preserves sealed signing refresh material.
It does not authorize wallet ownership.

```ts
import { createRouterApiRouter } from '@seams/wallet-server/router/express';
import { createSigningSessionSealOptions } from '@seams/wallet-server';

const signingSessionSeal = createSigningSessionSealOptions({
  rootSecretB64u: process.env.SIGNING_SESSION_SEAL_ROOT_SECRET_B64U!,
  currentKeyVersion: 'signing-session-seal-production-r2',
  acceptedWarmKeyVersions: ['signing-session-seal-production-r2'],
});

app.use('/', createRouterApiRouter(service, {
  threshold,
  signingSessionSeal,
}));
```

Store the random 32-byte root secret in a secrets manager. Retain accepted old
key versions only until their sealed records expire.

## Required runtime configuration

```bash
RELAYER_ACCOUNT_ID=relayer.testnet
RELAYER_PRIVATE_KEY=ed25519:...
ROR_RP_ID=wallet.example.localhost
NEAR_RPC_URL=https://rpc.testnet.near.org
NETWORK_ID=testnet
```
