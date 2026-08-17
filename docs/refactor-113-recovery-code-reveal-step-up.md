# Refactor 113 — Step-Up-Protected Recovery-Code Reveal

Status: proposed implementation plan.

## Goal

Require a fresh wallet factor before plaintext recovery codes can be decrypted
and rendered after registration or recovery-code rotation.

The step-up protects an unattended authenticated browser session from silently
revealing the wallet's offline recovery factor. Recovery status and active-code
counts remain readable without a prompt. Plaintext recovery codes remain local
to the wallet-owned browser context and are deleted after the owner confirms a
successful backup.

## Threat Model And Security Value

This refactor protects against:

- another person using an unlocked browser session;
- stale UI state that still considers the wallet logged in;
- accidental reveal through a low-friction account-menu action;
- a parent application requesting plaintext without a fresh wallet factor;
- replay of a reveal authorization against another wallet or recovery-code
  issuance.

The current pending-backup record stores an AES-GCM key, IV, and ciphertext in
the same IndexedDB row. The key is non-extractable, which prevents export of
the raw key while still allowing same-origin code to invoke decryption. An
application-level step-up therefore does not provide cryptographic isolation
from arbitrary same-origin script execution. Once codes are rendered, code
running in that origin can also observe the DOM or process memory.

Defending against a fully compromised wallet origin requires a separate
factor-wrapped storage design: the decryption key would be wrapped by passkey
PRF material or an Email OTP factor-release secret and would be unavailable
until that factor is opened. That larger custody change is outside this
refactor. Refactor 113 must describe its protection as fresh-user-presence
gating, never as an XSS boundary.

## Current State

The current backup flow has the security-sensitive operations in this order:

1. `pendingWalletRecoveryCodeBackupRepository.read(walletId)` decrypts the
   local record.
2. `showWalletRecoveryCodeBackupUi(...)` renders the plaintext codes.
3. `buildWalletCustodyPasskeyFactorProof(...)` requests a passkey assertion for
   `recovery_acknowledge`.
4. The server records the acknowledgement.
5. The local pending record is deleted.

The factor currently protects acknowledgement. It does not protect reveal.
The public method name, `acknowledgeWalletRecoveryCodeBackup`, also hides the
fact that the method decrypts and displays codes before it acknowledges them.

The server already has operation-bound factor proof machinery for passkeys and
Email OTP. `computeWalletCustodyAdminChallengeDigest` binds the wallet,
operation, payload, and browser origin. Refactor 113 reuses that machinery and
adds one exact reveal lifecycle.

The existing `/wallets/recovery/read` route returns the opaque recovery
envelope set. No production SDK flow calls it. It must not be reused as a
reveal authorization endpoint because that would return unrelated recovery
material. Phase 1 removes that inactive public path and replaces its ambiguous
`recovery_read` operation with the exact backup-reveal operation.

## Product Decisions

1. Opening the recovery-code modal and reading status does not require
   step-up.
2. Pressing **View recovery codes** starts a fresh factor challenge.
3. Passkey wallets complete one WebAuthn assertion. Email OTP wallets complete
   one Email OTP challenge.
4. Plaintext is decrypted only after the server verifies the operation-bound
   factor proof.
5. The authorization is bound to the exact wallet ID, recovery-set issuance
   time, browser origin, and operation.
6. One successful step-up covers the reveal followed by backup
   acknowledgement. The owner must not receive a second Touch ID or OTP prompt
   in the same uninterrupted flow.
7. Closing or cancelling the reveal leaves the encrypted local record intact
   and leaves backup status outstanding.
8. The acknowledgement endpoint consumes the short-lived reveal grant. It
   records backup only for the same recovery-code issuance.
9. A subsequent reveal after cancellation or grant expiry requires another
   fresh factor.
10. Recovery codes never cross `postMessage`, HTTP, logs, analytics, error
    messages, React state outside the wallet-owned dialog, or server storage.

## Non-Goals

- Wrap the local AES key with passkey PRF or Email OTP factor-release material.
- Make plaintext safe from arbitrary script already executing in the wallet
  origin.
- Change recovery-code generation, wrapping, consumption, or rotation.
- Add a general-purpose step-up framework.
- Add a grace period that permits code reveal without a fresh factor.
- Preserve the inactive `/wallets/recovery/read` public route or the
  `recovery_read` operation name.
- Allow parent applications to receive plaintext recovery codes.

## Domain Model

Model the flow as a closed lifecycle. Do not represent it with optional proof,
grant, codes, or acknowledgement fields.

```ts
type RecoveryCodeBackupFlow =
  | {
      readonly kind: 'status_ready';
      readonly walletId: WalletId;
      readonly issuedAtMs: number;
    }
  | {
      readonly kind: 'authorizing_reveal';
      readonly walletId: WalletId;
      readonly issuedAtMs: number;
      readonly method: 'passkey' | 'email_otp';
    }
  | {
      readonly kind: 'reveal_authorized';
      readonly authorization: RecoveryCodeRevealAuthorization;
    }
  | {
      readonly kind: 'codes_visible';
      readonly authorization: RecoveryCodeRevealAuthorization;
      readonly recoveryCodes: WalletRecoveryCodeSet;
    }
  | {
      readonly kind: 'acknowledging_backup';
      readonly authorization: RecoveryCodeRevealAuthorization;
    }
  | {
      readonly kind: 'completed';
      readonly walletId: WalletId;
      readonly issuedAtMs: number;
    }
  | {
      readonly kind: 'failed';
      readonly stage: 'authorization' | 'local_read' | 'acknowledgement';
      readonly message: string;
    };
```

`RecoveryCodeRevealAuthorization` is created only by the exact response parser
for the reveal-authorization route:

```ts
type RecoveryCodeRevealAuthorization = {
  readonly kind: 'recovery_code_reveal_authorization_v1';
  readonly authorizationId: AuthorizedOperationId;
  readonly walletId: WalletId;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};
```

Passkey and Email OTP proof collection remain separate branch-specific
builders. Core flow functions receive a completed `WalletCustodyFactorProof`;
they do not accept a bag of optional credential, OTP, provider, or challenge
fields.

## Authorization Contract

### Reveal authorization request

Add:

`POST /wallets/recovery/authorize-backup-reveal`

The request contains:

- `walletId`;
- `issuedAtMs` from the pending local record metadata;
- one exact `WalletCustodyFactorProof`.

The proof operation is `recovery_backup_reveal`. Its canonical payload is:

```ts
{
  walletId,
  issuedAtMs,
}
```

The server:

1. validates the route body once;
2. verifies the passkey or Email OTP proof through the existing wallet-custody
   operation authorizer;
3. reads authoritative recovery status;
4. requires the current recovery set to exist;
5. requires its issuance time to equal `issuedAtMs`;
6. returns a short-lived, opaque reveal authorization;
7. leaves that authorization pending until acknowledgement or expiry.

The response contains wallet identity and timing metadata only. It never
contains the opaque server recovery set, wrapped recovery entries, ciphertext,
or plaintext codes.

### Backup acknowledgement request

Change the acknowledgement endpoint to require the reveal authorization ID.
The server atomically:

1. resolves the pending authorization;
2. requires the same wallet and issuance time;
3. requires the authorization to be unexpired and unused;
4. records backup acknowledgement for that issuance;
5. consumes the authorization;
6. returns the acknowledged issuance time.

Retrying the same acknowledgement returns the stored successful result.
Another wallet, issuance, origin, or operation cannot consume the grant.

Use the existing authorized-operation store and replay semantics. Do not add a
second grant table or a client-generated bearer token.

## Client Flow

### 1. Inspect without decrypting

Split pending backup persistence into two reads:

- `readMetadata(walletId)` returns `walletId` and `issuedAtMs` after validating
  the row;
- `reveal(authorization)` decrypts only when the authorization wallet and
  issuance exactly match the row.

Remove the unrestricted `read(walletId)` method. The status path uses
`readMetadata` or `has` and never receives plaintext.

### 2. Collect the active factor

Resolve the wallet's current authentication method into an exhaustive union:

- passkey branch: build one `recovery_backup_reveal` WebAuthn proof;
- Email OTP branch: request one operation-bound challenge, collect the OTP,
  and build one Email OTP proof.

No branch may fall back to another factor after the user cancels. Cancellation
returns the modal to its status state with no codes in memory.

### 3. Authorize, decrypt, and render

Send the factor proof to the reveal-authorization route. Parse the exact
authorization response. Then call the repository reveal operation and render
the codes inside the wallet-owned backup UI.

Keep the authorization in memory. Do not persist it in IndexedDB, local
storage, URL state, React query caches, or parent-window messages.

### 4. Acknowledge and delete

When the user confirms that the codes were saved, send the authorization ID to
the acknowledgement route. Delete the encrypted pending row only after the
server returns acknowledgement for the same issuance.

If acknowledgement fails, retain the encrypted row. Remove plaintext from UI
state when the dialog closes and zero temporary byte buffers where the current
storage and codec APIs expose them.

## Public API And UI

Replace the ambiguous public method:

- remove `acknowledgeWalletRecoveryCodeBackup({ walletId })`;
- add `completeWalletRecoveryCodeBackup({ walletId })`.

The replacement owns the entire wallet-local interaction: authorization,
reveal, acknowledgement, and local deletion. Its result is a discriminated
union for `completed`, `cancelled`, `no_pending_backup`, `unauthorized`, and
`transport_failed`.

The account-menu modal keeps status and counts visible. Its button states are:

- **View recovery codes** — idle;
- **Verify to view** — factor collection is active;
- **Loading recovery codes** — authorization succeeded and local decrypt is in
  progress;
- **Saved recovery codes** — acknowledgement is in progress.

The modal must preserve focus trapping, restoration, keyboard dismissal, and
screen-reader announcements. Sensitive codes appear only in the existing
wallet-owned backup dialog after the state reaches `codes_visible`.

## Failure And Concurrency Rules

- Missing or corrupt local row: return `no_pending_backup` or a local storage
  failure before requesting a factor.
- Stale issuance after rotation: reject authorization, delete no local data,
  and refresh status.
- Wrong wallet or origin: reject before local decrypt.
- Cancelled WebAuthn or OTP: show no error toast unless the existing UI treats
  cancellation as an error; reveal no codes.
- Expired authorization: close plaintext UI state and require a fresh factor.
- Two tabs: the first successful acknowledgement consumes the authorization
  and deletes its local row. The second tab refreshes status and clears any
  stale pending record only after it observes the matching acknowledged
  issuance.
- Transport failure after reveal: retain the encrypted row, clear plaintext
  when the dialog closes, and require a new step-up on the next reveal.
- Rotation during reveal: acknowledgement fails on issuance mismatch. The old
  codes are never marked as the current set's backup.

## Implementation Phases

### Phase 0 — Contract and deletion map

- [ ] Add the intended behavior to `docs/intended-behaviours.md`.
- [ ] Record every caller of `recovery_read`, `/wallets/recovery/read`, and
      `readWalletRecoverySet`.
- [ ] Confirm the current production caller count remains zero.
- [ ] Delete obsolete tests and fixtures that protect the inactive read route.
- [ ] Define the reveal lifecycle and result unions before changing runtime
      behavior.

### Phase 1 — Exact server authorization

- [ ] Replace `recovery_read` with `recovery_backup_reveal` in
      `WalletCustodyAdminOperation` and every exhaustive boundary parser.
- [ ] Delete `/wallets/recovery/read`, its response parser, and its public route
      definition.
- [ ] Add `/wallets/recovery/authorize-backup-reveal` with an exact request and
      response parser.
- [ ] Verify authoritative issuance time before returning authorization.
- [ ] Change backup acknowledgement to consume the reveal authorization.
- [ ] Reuse the authorized-operation store for expiry, replay, and atomic
      completion.
- [ ] Confirm server responses and logs contain no recovery code material.

### Phase 2 — Local reveal boundary

- [ ] Replace repository `read(walletId)` with `readMetadata(walletId)` and
      `reveal(authorization)`.
- [ ] Require exact wallet and issuance equality before AES-GCM decryption.
- [ ] Add a single linear coordinator for authorize, reveal, acknowledge, and
      delete.
- [ ] Keep the authorization memory-only.
- [ ] Remove helpers that permit plaintext reads without authorization.

### Phase 3 — Passkey and Email OTP integration

- [ ] Add a branch-specific passkey reveal proof builder using the existing
      wallet-custody challenge digest.
- [ ] Add a branch-specific Email OTP reveal proof builder using the existing
      custody Email OTP challenge route.
- [ ] Route both branches into the same post-proof coordinator.
- [ ] Ensure one complete reveal-and-acknowledge flow produces one factor
      prompt.
- [ ] Replace the public API and wallet-iframe message with
      `completeWalletRecoveryCodeBackup`.
- [ ] Remove the old acknowledgement-only public and message paths.

### Phase 4 — UI and lifecycle verification

- [ ] Update the modal state machine and accessible progress copy.
- [ ] Verify plaintext never appears before factor success.
- [ ] Verify cancellation, stale issuance, expiry, and acknowledgement failure.
- [ ] Run the focused intended-behavior contracts once after implementation is
      complete.
- [ ] Run the full intended-behavior suite once after focused contracts pass.
- [ ] Remove stale lower-authority tests or fixtures that encode reveal before
      authorization.
- [ ] Run type checks, relevant source boundaries, and `git diff --check`.

## Intended-Behavior Contracts

Add recovery-code coverage to the authoritative lifecycle suite:

### Passkey wallet

1. Register a wallet and leave backup outstanding.
2. Open recovery status without a Touch ID prompt.
3. Press **View recovery codes**.
4. Assert exactly one WebAuthn prompt occurs before plaintext appears.
5. Confirm backup.
6. Assert the server records the matching issuance and the local pending row is
   deleted.
7. Reopen status and assert no codes can be revealed.

### Email OTP wallet

1. Register a wallet and leave backup outstanding.
2. Open recovery status without an OTP challenge.
3. Press **View recovery codes**.
4. Assert one Email OTP challenge and verification occur before plaintext
   appears.
5. Confirm backup and assert matching issuance and local deletion.

### Negative cases

- cancel passkey or OTP and assert plaintext never appears;
- present a grant for another wallet and assert local decrypt is refused;
- rotate between authorization and acknowledgement and assert issuance
  mismatch;
- expire the grant and assert a fresh factor is required;
- fail acknowledgement transport and assert the encrypted row remains;
- inspect network and console records and assert no plaintext recovery code is
  present.

Focused unit tests may cover repository matching and lifecycle reduction.
Delete any inline fixture or source guard that exists solely for the retired
`recovery_read` response.

## Acceptance Criteria

- Plaintext recovery codes cannot be obtained through any supported SDK or UI
  path before a fresh passkey or Email OTP step-up succeeds.
- Status and counts remain available without step-up.
- One reveal-and-acknowledge journey requests one factor.
- Reveal authorization is wallet-, issuance-, origin-, operation-, expiry-,
  and replay-bound.
- Acknowledgement consumes the exact reveal authorization.
- Closing or failing the flow preserves the encrypted pending backup.
- Successful acknowledgement deletes the matching local row.
- No public API, wallet-iframe message, route, log, or analytic payload carries
  plaintext recovery codes.
- The inactive recovery-set read route and its obsolete tests are deleted.
- Passkey and Email OTP intended-behavior contracts pass.
- The complete intended-behavior suite passes once after implementation.
