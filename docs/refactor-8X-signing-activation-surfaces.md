# Signing Activation Surfaces

Date created: July 17, 2026

Status: API design. Implementation starts after wallet-origin WebAuthn behavior
is verified for the supported Chromium and Safari/WebKit matrix.

## Goal

Allow an app to own transaction-review layout without moving wallet passkeys,
credential creation, signing authority, or signing secrets to the app origin.

The app may render transaction details and an intent-review UI. The final user
activation control remains wallet-origin iframe DOM and is represented by a
typed, correlated signing activation surface.

## Trust Boundary

- The app origin supplies display-only transaction review data.
- The wallet iframe derives and verifies the authoritative request, wallet ID,
  chain, transaction digest, expiry, and confirmation policy.
- The app origin never receives an activation proof, passkey PRF output, or
  prepared signing material.
- A signing activation proof is single-use and binds `surfaceId`, `requestId`,
  `walletId`, chain, transaction digest, wallet-origin RP ID, and expiry.
- The wallet iframe rejects proof reuse, mismatched request data, expired
  preparation, replacement, cancellation, and stale connection ownership.

## Proposed API

```ts
type SigningActivationSurface = {
  kind: 'wallet_iframe_signing_activation_surface_v1';
  mount(target: HTMLElement): void;
  dispose(): void;
  state(): SigningActivationSurfaceState;
  onStateChange(listener: (state: SigningActivationSurfaceState) => void): () => void;
};

type SigningActivationSurfaceState =
  | { kind: 'idle' }
  | { kind: 'mounting'; identity: SigningActivationIdentity }
  | { kind: 'ready'; identity: SigningActivationIdentity; expiresAtMs: number }
  | { kind: 'starting'; identity: SigningActivationIdentity }
  | { kind: 'completed'; identity: SigningActivationIdentity }
  | { kind: 'cancelled'; identity: SigningActivationIdentity; reason: SigningActivationCancelReason }
  | { kind: 'failed'; identity: SigningActivationIdentity; error: string };
```

The public input contains a provided wallet session, chain target, transaction
request, and a required presentation payload. It cannot accept confirmation
configuration, callbacks that execute in the wallet iframe, a caller-supplied
activation proof, raw digest, expiry, or prepared signing state.

## User Intent

The app's transaction review is part of the user's intent. The SDK therefore
requires the app to present the same request identity and review model that the
wallet iframe prepared before mounting the final CTA. The app cannot alter the
wallet-authoritative transaction, chain, policy, or expiry after readiness.

The wallet-origin CTA covers only the final activation control. The wallet
modal remains the default confirmation experience; localized activation is an
explicit opt-in for an app that owns its review layout.

## Lifecycle

1. The router creates a request and signing-activation identity.
2. The wallet iframe verifies the signing request, derives the authoritative
   digest, prepares the confirmation, and reserves the WebAuthn coordinator.
3. The wallet iframe reports readiness with identity and expiry only.
4. The shared renderer anchors the wallet-origin confirmation control to the
   app target.
5. The iframe click consumes the reservation and starts WebAuthn inline.
6. Wallet-origin signing verifies the proof binding before any signing action.
7. Matching completion, cancellation, expiry, replacement, and connection close
   release the reservation and hide only that surface.

## Delivery Phases

### Phase A: Contract And Boundary Types

- Define signing activation identities, receipt, proof, cancellation, and
  surface-state unions.
- Add request-bound proof validation at the wallet-origin signing boundary.
- Add type fixtures that reject missing wallet, chain, digest, request, expiry,
  or reservation bindings.

### Phase B: Wallet Preparation

- Prepare and verify the transaction before `READY`.
- Reserve the shared WebAuthn prompt coordinator before rendering the CTA.
- Keep digest, challenge, prepared signing state, and proof wallet-origin only.

### Phase C: App Integration

- Add a narrow mounting API for custom app confirmers.
- Reuse the registration geometry, clipping, focus proxy, mirrored interaction,
  and stale-event policy.
- Keep the wallet-origin modal transaction confirmer as the default path.

### Phase D: Validation And Rollout

- Prove inline wallet-origin credential use in Chromium.
- Verify supported Safari/WebKit behavior or return the typed unsupported error
  without a parent-origin bridge.
- Cover proof replay, mismatch, expiry, concurrent surface arbitration, and
  cleanup after replacement.
