# Refactor 114 — Recover Account with a Code

Status: implemented; final operating-path verification in progress.

## Decision

Add **Recover account** to the hosted login menu. A user enters a `WalletId`
and one saved recovery code, creates a replacement Passkey, then signs in with
that Passkey through the existing login path.

The recovery code is the sole recovery authorization. Recovery is available
only when the wallet has exactly one active owner auth method, that method is a
Passkey, and its binding matches the requested RP. Every refusal uses the same
user-facing message. R109A will define recovery policy for multi-auth wallets.

R114 reuses the existing recovery-code reservation, custody ceremony, complete
key-manifest reconstruction, WebAuthn registration, possession verification,
and local-continuity restoration. It adds no recovery grant, session type, or
public SDK recovery API.

## User Flow

```text
enter code -> prepare -> create new passkey -> finalize -> sign in
```

1. **Recover account** opens editable Wallet ID and recovery-code fields. The
   Wallet ID may be seeded from the selected saved account.
2. Submit validates both fields and prepares recovery. The code leaves the form
   once preparation succeeds.
3. **Create new passkey** invokes `navigator.credentials.create()` directly
   from its click handler.
4. The wallet reconstructs and verifies the complete key manifest, then asks
   the server to atomically install the replacement.
5. **Sign in with new passkey** enters the normal Passkey login path for the
   exact recovered Wallet ID.
6. Successful normal login creates the fresh Wallet Session and emits the
   existing `authenticated/passkey` hosted outcome.

The separate clicks preserve browser user-activation requirements and keep
Wallet Session creation in one established path.

## Prepare Boundary

The client derives `rpId` from trusted wallet configuration and sends:

```ts
type WalletRecoveryPrepareRequest = {
  readonly walletId: WalletId;
  readonly rpId: WebAuthnRpId;
  readonly recoveryCodeB64u: string;
  readonly reservationId: RecoveryCodeReservationId;
};
```

The server validates the exact request, verifies Origin/RP policy, decodes the
code once, and clears the decoded bytes in `finally`. It atomically reserves
the code, selects the single active Passkey method, and persists a short-lived
WebAuthn registration challenge containing all source facts needed by
finalization.

The response contains registration options, reservation expiry, the wrapped
custody material, and the stored key manifest. Source credential and authority
facts remain server-side.

## Create and Finalize

Credential creation occurs synchronously at the beginning of the dedicated
button handler. Secret material stays inside the coordinator and is never
returned to the hosted UI.

Finalization sends:

```ts
type WalletRecoveryFinalizeRequest = {
  readonly walletId: WalletId;
  readonly reservationId: RecoveryCodeReservationId;
  readonly challengeId: string;
  readonly replacementId: string;
  readonly webauthnRegistration: WebAuthnRegistrationCredential;
  readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly ecdsaMaterialPossessionProofs: readonly WalletRecoveryEcdsaMaterialPossessionProofInputV1[];
};
```

The success response is `{ ok: true, storeVersion }`. Client failures have one
of three internal classifications:

```ts
type WalletRecoveryAttemptFailure =
  | { readonly kind: 'refused' }
  | { readonly kind: 'retryable_conflict' }
  | { readonly kind: 'transport_uncertain' };
```

A definite refusal disposes the operation. A retryable conflict or uncertain
finalization retains the redacted operation so the same commit can be replayed.
Cancellation wipes remaining code and factor material.

## Server Commit

Finalization verifies the durable challenge, WebAuthn registration, complete
stored key manifest, recovery envelopes, possession proofs, activation
receipts, reservation state, and source auth-method compare-and-swap facts.

One D1 transaction then:

- installs the replacement authenticator, binding, active auth method, and
  custody envelope;
- consumes the reserved recovery code;
- revokes the source auth method and every Wallet Session it issued;
- retires the source custody envelope; and
- deletes the registration challenge.

Any failed statement leaves the commit unapplied. Replay succeeds only when
readback proves the same replacement is active, the source is revoked, its
envelope is retired, and the reservation is consumed.

## Ed25519 Recovery Admission

The first Ed25519 recovery admission carries the prepared registration
challenge ID in the internal
`x-seams-wallet-recovery-challenge-id` header. The router loads that durable
challenge, verifies its active reservation and wallet, derives the expected
Near key lifecycle, and admits only an exact match. Execute and activate
continue from the existing protocol admission receipt.

Ordinary signing never emits this header. It is an internal bridge to the one
stored recovery authorization rather than a second authorization design.

## Hosted Boundary

Recovery remains inside the wallet iframe. The hosted UI depends on the
host-only `HostedRecoveryPort`, whose operations are:

- `prepare(walletId, recoveryCode, signal)`;
- `createPasskey(prepared)`;
- `finalize(credentialCreated)`; and
- `cancel(activeOperation)`.

The port returns only narrow lifecycle handles and generic failure kinds. The
UI never receives recovery bytes, PRF material, WebAuthn responses, challenges,
relay details, or server diagnostics.

The recovery view uses native forms and buttons, visible labels, paste-friendly
inputs, stable validation descriptions, first-invalid-field focus, a live
region, recovery-specific Back/Escape cancellation, and 320px reflow. All
server refusals map to:

> That recovery code can’t be used. Check the wallet ID and code, then try
> again.

## Security Invariants

- One active code and its `WalletId` authorize one replacement attempt for a
  single-Passkey wallet.
- Origin and RP policy are verified before registration options are issued.
- Concurrent attempts with one code admit at most one successful finalization.
- Raw recovery codes never enter logs, durable challenges, errors, hosted
  outcomes, or parent-window messages.
- Complete key-manifest verification preserves every public wallet identity.
- Replacement installation, code consumption, source-factor retirement, and
  source-session revocation are atomic.
- Precommit cancellation and definite failure leave the code unconsumed.
- A fresh Wallet Session comes only from normal login with the replacement
  Passkey.

## Implementation Checklist

- [x] Exact prepare and finalize wire boundaries.
- [x] Durable WebAuthn recovery-registration challenge.
- [x] Single-active-Passkey and RP gate.
- [x] Atomic replacement promotion and strict replay readback.
- [x] Immutable D1 compare-and-swap guard sentinel.
- [x] Challenge-backed Ed25519 recovery admission.
- [x] Coordinator cancellation, retry retention, and secret zeroization.
- [x] Hosted recovery view and exact-wallet normal login continuation.
- [x] Removal of the superseded recovery APIs and bootstrap path.
- [x] Focused server, client, authorization, hosted-session, Lit, type, and
      source-boundary coverage.
- [ ] Fresh-browser intended-behaviour contract passes from a clean local stack.
- [x] Final repository checks and symbol audit pass, or unrelated failures are
      classified against the testing policy.

## Non-Goals

- Multi-auth sibling preservation or replacement policy; R109A owns it.
- Email, social, contact, or help-desk recovery.
- A recovery grant, general factor kind, independent session mint, React form,
  or new hosted outcome method.
- New key derivation, wallet identities, signing roots, accounts, or addresses.
