# Refactor 114 — Recover Account with a Code

Status: Phase 1 and Phase 2 implemented.

## Phase 1 Decision

Phase 1 records the implemented wallet-scoped recovery path. Phase 2 below
supersedes its user-supplied Wallet ID and prepare-request shape while retaining
the wallet-bound cryptographic checks and finalization path.

Add **Recover account** to the hosted login menu. A user enters a `WalletId`
and one saved recovery code, creates a replacement Passkey, then signs in with
that Passkey through the existing login path.

The recovery code is the sole recovery authorization. Recovery is available
only when the wallet has exactly one active owner auth method, that method is a
Passkey, and its binding matches the requested RP. Every refusal uses the same
user-facing message. R109C will define recovery policy for multi-auth wallets.

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

The success response returns the committed credential material required to
rebuild the local login projection:

```ts
type WalletRecoveryFinalizeSuccess = {
  readonly ok: true;
  readonly storeVersion: string;
  readonly credential: {
    readonly credentialIdB64u: string;
    readonly credentialPublicKeyB64u: string;
    readonly counter: number;
  };
};
```

Client failures have one of three internal classifications:

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

## Phase 2 — Discover the Wallet from the Recovery Code

Status: implemented.

### Outcome

The hosted recovery form asks for one recovery code. A successful prepare
resolves and returns the exact `WalletId`; credential creation, finalization,
and normal Passkey sign-in continue with that resolved identity.

The recovery code remains the sole recovery authorization. A locator identifies
which recovery set to inspect. Authorization still requires the existing
wallet-bound recovery-key derivation, active-code reservation, RP/origin policy,
single-active-Passkey policy, complete custody reconstruction, manifest
verification, and atomic replacement commit.

### Locator Design

Add a domain-separated `RecoveryCodeLocatorV1`:

```text
SHA-256(
  encodeTuple(
    "seams/wallet-recovery/code-locator/v1",
    recoveryCodeBytes
  )
)
```

Recovery codes contain 20 cryptographically random bytes, so a direct SHA-256
locator retains 160 bits of preimage resistance. This phase adds no password
KDF, server pepper, or second recovery credential.

Keep `DerivedWalletRecoveryKeyId` unchanged. It remains derived from the code,
`WalletId`, and recovery-set version, and it remains the identity bound into the
stored manifest-KEK wrap. After locator lookup, prepare must derive that existing
wallet-bound ID and require an exact wrap match before reserving the code. A
locator row alone never authorizes recovery.

### Persistence Shape

Add one D1 table scoped identically to the recovery-set store:

```sql
CREATE TABLE wallet_recovery_code_locators (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  locator_b64u TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  recovery_key_id TEXT NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, locator_b64u),
  UNIQUE (namespace, org_id, project_id, env_id, wallet_id, recovery_key_id)
);

CREATE INDEX idx_wallet_recovery_code_locators_wallet
  ON wallet_recovery_code_locators (
    namespace, org_id, project_id, env_id, wallet_id
  );
```

The table is a narrow secondary index over the authoritative recovery envelope
set. It stores no plaintext code, lifecycle state, ciphertext, or authorization
result.

Registration must insert the recovery set, backup acknowledgement, custody
envelope, and all ten locator rows in the existing all-or-nothing commit.
Rotation must replace the recovery set and all ten locator rows in one
transaction. Finalization must consume the reserved wrap and delete its locator
row in the same recovery-promotion transaction. A revoked code loses its locator
in the transaction that revokes it. Reservation leaves the locator present so
an expired or cancelled attempt can use the code again.

Treat locator collisions as a rejected issuance or rotation. The client creates
a fresh recovery-code set and retries the whole operation; it never selects a
different wallet for an existing locator.

### Issuance and Rotation Boundary

Derive locators in shared TypeScript from the already-issued code bytes. Build a
precise commit input that pairs each locator with the `DerivedWalletRecoveryKeyId`
of the wrap produced for the same code. Validate the ten-entry count, uniqueness,
and one-to-one pairing once before sending the commit request.

The server request parser accepts the locator/key-id pairs as an issuance
boundary shape, validates them once, and passes a typed set into registration or
rotation. Core persistence functions receive the complete valid locator set as
a required field. They do not accept partial locator arrays or raw strings.

### Prepare Boundary

Replace the Phase 1 prepare request with:

```ts
type WalletRecoveryPrepareRequest = {
  readonly rpId: WebAuthnRpId;
  readonly recoveryCodeB64u: string;
  readonly reservationId: RecoveryCodeReservationId;
};
```

Prepare performs these steps in order:

1. Verify the request shape and RP/origin policy.
2. Decode the code once and derive `RecoveryCodeLocatorV1`.
3. Resolve exactly one tenant-scoped locator row.
4. Parse the resolved `WalletId` and `DerivedWalletRecoveryKeyId` at the D1
   boundary.
5. Load the authoritative recovery set by the resolved wallet.
6. Derive the existing wallet-bound recovery-key ID from the code and resolved
   wallet, and require equality with both the locator row and stored wrap.
7. Apply the existing active-code reservation and wallet recovery policy.
8. Persist the durable registration challenge and return the prepared payload
   with the verified `walletId`.

Every missing, consumed, revoked, colliding, corrupt, or mismatched locator and
wrap returns the existing generic recovery refusal. Logs and diagnostics may
record only an opaque operation ID and failure class; they must exclude the raw
code, locator, and resolved wallet for refused attempts.

The success result becomes:

```ts
type WalletRecoveryPrepareSuccess = {
  readonly ok: true;
  readonly walletId: WalletId;
  // Existing wrap, entries, manifest, registration, reservation, and version.
};
```

Finalization keeps `walletId` as a required field. It comes from the prepared
operation and durable challenge, rather than user input. Existing challenge,
replay, Ed25519 admission, compare-and-swap, and normal-login checks continue to
bind to that exact wallet.

### Hosted UI and Domain State

Remove `walletId`, `walletIdError`, and the Wallet ID input from the recovery
entry view model. The entry state requires only a recovery-code value and its
validation error. `HostedRecoveryPort.prepare` accepts the code and abort signal;
its prepared success branch requires the resolved `WalletId` returned by the
server.

Update the form copy to:

> Enter a recovery code to recover your wallet.

Map every server refusal to:

> That recovery code can’t be used. Check the code and try again.

After prepare succeeds, every later recovery state carries the resolved
`WalletId` as required domain data. The sign-in continuation uses only this
server-verified value.

Downloaded and copied backups may continue to include the Wallet ID as useful
context. Recovery correctness must not depend on that metadata.

### Existing Recovery Sets

Existing recovery sets contain only wallet-bound recovery-key IDs. A code-only
locator cannot be reconstructed from those stored values, and the server has no
plaintext codes to backfill it.

Before shipping Phase 2, choose the deployment path from actual persistence
state:

- If no durable user recovery sets exist, apply the new migration and replace
  the Phase 1 request/UI directly.
- If durable sets exist, require authenticated code rotation to issue locator-
  indexed sets before removing the Phase 1 request boundary. Track completion
  explicitly, then delete the Wallet-ID prepare shape and its tests. Do not add
  a permanent dual lookup path.

The final operating path has one prepare request and one hosted form. Fixture,
mock, and source-guard coverage for user-entered Wallet IDs is obsolete and
must be deleted rather than preserved as compatibility behavior.

This implementation selects the direct path for new deployments: apply the
locator migration before issuing any new recovery set. Environments that
already contain Phase 1 sets must rotate those sets through the authenticated
settings flow before enabling the code-only prepare route.

### Implementation Sequence

1. Add `RecoveryCodeLocatorV1`, its parser/deriver, and deterministic tests.
2. Add the D1 locator table and a store with tenant-scoped lookup plus prepared
   insert/delete statements.
3. Extend registration and rotation commit inputs so locator rows change
   atomically with their recovery sets.
4. Extend recovery promotion and revocation commits so locator deletion is
   atomic with code consumption or revocation.
5. Replace the prepare wire parser and service input, resolve the wallet through
   the locator store, and return the verified `WalletId` on success.
6. Narrow coordinator and hosted recovery domain states around the resolved
   wallet identity.
7. Remove the Wallet ID field, handlers, validation copy, and obsolete fixtures
   from the hosted UI.
8. Update `docs/intended-behaviours.md` and its recovery contract in the same
   change set.
9. Delete the Phase 1 prepare shape after the selected persistence transition
   is complete.

### Verification

- Type fixtures reject prepare requests containing `walletId`, prepared states
  without a resolved wallet, and entry states carrying wallet identity.
- Locator vectors prove normalization-equivalent recovery-code strings produce
  one locator and distinct codes produce distinct locators.
- D1 tests prove tenant isolation, collision rejection, and atomic locator
  insertion, rotation, consumption, and revocation.
- Route tests prove code-only success, exact resolved-wallet return, strict
  request fields, uniform refusals, and zeroized decoded code bytes.
- Domain tests corrupt each of locator wallet, locator recovery-key ID, stored
  wrap ID, and recovery-set wallet independently; every corruption is refused
  before reservation.
- Concurrency tests prove one code admits at most one finalization and rotation
  cannot leave old locators or publish new locators without the matching set.
- Hosted tests prove one-input keyboard/focus behavior, generic error copy, Back
  and Escape cancellation, and exact-wallet normal-login continuation.
- The intended-behaviour contract recovers from a fresh browser with only one
  saved code and confirms the replacement Passkey signs into the resolved
  wallet.
- Run the narrow store, route, coordinator, hosted-session, and Lit tests first;
  then run `pnpm test:intended`, `pnpm test:source-guards`, and `pnpm check`
  because this phase changes a public request boundary and durable schema.

### Phase 2 Completion Checklist

- [x] Code-only locator derivation and parser are canonical.
- [x] Registration, rotation, consumption, and revocation own locator rows
      atomically with recovery-set lifecycle.
- [x] Prepare accepts only RP, code, and reservation identity.
- [x] Successful prepare returns the server-resolved `WalletId`.
- [x] Wallet-bound wrap verification remains mandatory after locator lookup.
- [x] Hosted recovery has one input and no Wallet ID state or validation path.
- [x] Existing durable sets follow the selected transition and the temporary
      boundary is deleted.
- [x] Focused locator, persistence, rotation, prepare, coordinator, hosted
      session, and Lit tests pass. The intended-behaviour contract and full
      repository checks remain release-gate work for the target deployment.

## Non-Goals

- Multi-auth sibling preservation or replacement policy; R109C owns it.
- Email, social, contact, or help-desk recovery.
- A recovery grant, general factor kind, independent session mint, React form,
  or new hosted outcome method.
- New key derivation, wallet identities, signing roots, accounts, or addresses.
