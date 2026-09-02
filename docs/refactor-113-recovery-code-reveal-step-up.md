# Refactor 113 — Verify Before Recovery-Code Reveal

Status: proposed implementation plan.

## Decision

Require the server to verify a fresh wallet factor before the browser decrypts
pending recovery codes.

Keep the existing `acknowledgeWalletRecoveryCodeBackup({ walletId })` public
operation and recovery-code modal. Reorder the operation behind that API and
reuse the existing wallet-custody factor proofs and authorized-operation store.
Add one narrow authorization response that permits local reveal for the exact
wallet and recovery-code issuance.

This is a local hardening change. It does not introduce a new recovery-code
coordinator, public API lifecycle, persistence table, cryptographic format, or
UI state machine.

## Current Problem

The current direct flow performs its sensitive actions in this order:

1. `pendingWalletRecoveryCodeBackupRepository.read(walletId)` decrypts the
   local recovery codes.
2. The wallet surface renders the plaintext codes.
3. The server records backup acknowledgement from the wallet ID.
4. The SDK deletes the pending local record.

Acknowledgement deliberately has no factor prompt because it only clears the
backup reminder and deletes the local pending record. The sensitive reveal
still happens before any fresh factor verification. The same ordering is
reachable through the wallet iframe.

## Target Flow

The existing public operation performs one linear flow:

1. Read only `walletId` and `issuedAtMs` from the pending local record.
2. Collect a Passkey or Email OTP proof for `recovery_backup_reveal`, using the
   wallet's active authentication authority.
3. Send the proof, `walletId`, and `issuedAtMs` to the server.
4. The server verifies the proof and confirms that `issuedAtMs` is the current
   recovery-set issuance.
5. The server admits a short-lived authorized operation and returns its exact
   public binding.
6. The repository decrypts only after receiving that parsed authorization.
7. The existing wallet-owned backup surface displays the codes.
8. After the owner confirms backup, the acknowledgement route consumes the
   authorized operation and records acknowledgement for the same issuance.
9. The SDK deletes the pending local record after successful acknowledgement.

Cancellation before reveal leaves the encrypted record untouched. Closing the
codes without confirming backup clears the visible plaintext and leaves the
record for a future attempt. The unused authorization expires through the
existing authorized-operation lifecycle.

## Exact Authorization Type

The response parser is the only builder for the value accepted by local reveal:

```ts
type RecoveryCodeRevealAuthorization = {
  readonly kind: 'recovery_code_reveal_authorization_v1';
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly walletId: WalletId;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};
```

The repository exposes:

```ts
readMetadata(walletId: WalletId): Promise<{
  readonly walletId: WalletId;
  readonly issuedAtMs: number;
} | null>;

reveal(
  authorization: RecoveryCodeRevealAuthorization,
): Promise<PendingWalletRecoveryCodeBackup | null>;
```

`reveal` requires exact wallet and issuance equality with the stored row before
decrypting. Remove the unrestricted `read(walletId)` method.

## Server Changes

Add:

`POST /wallets/recovery/authorize-backup-reveal`

The exact request contains:

- `walletId`;
- `issuedAtMs`;
- one `WalletCustodyFactorProof` for `recovery_backup_reveal`.

The route verifies the factor proof through the existing wallet-custody
authorizer, checks the authoritative recovery-set issuance, and admits one
short-lived authorized operation bound to:

- tenant and wallet;
- browser origin;
- `recovery_backup_reveal`;
- `issuedAtMs`;
- expiry and replay state.

Change `/wallets/recovery/acknowledge-backup` to accept the authorized-operation
ID. It resolves the operation, requires the same wallet and issuance, records
the acknowledgement, and completes the operation with the existing idempotent
replay behavior.

Delete the inactive `/wallets/recovery/read` route and its `recovery_read`
operation while changing this boundary. Delete `recovery_acknowledge` after the
acknowledgement route consumes the reveal authorization. No deprecated aliases
or compatibility request shapes remain.

## Client Changes

Keep `acknowledgeWalletRecoveryCodeBackup({ walletId })` as the public entry
point. Update its direct and iframe implementations to execute the target flow
above.

Reuse:

- the existing Passkey and Email OTP wallet-custody proof builders;
- the existing wallet-owned recovery-code display surface;
- the current modal's loading and error handling;
- the current pending-backup IndexedDB row and encryption format.

The React account menu continues to call the same public method. It needs no new
recovery lifecycle union or additional view states.

## Security Invariants

- Supported SDK and UI paths cannot decrypt pending recovery codes until the
  server verifies a fresh factor for the exact wallet and issuance.
- Reveal authorization is wallet-, issuance-, origin-, operation-, expiry-, and
  replay-bound.
- The acknowledgement consumes the reveal authorization for the same issuance.
- The pending encrypted row is deleted only after successful acknowledgement.
- Recovery codes remain inside the wallet-owned surface and never enter HTTP,
  `postMessage`, logs, analytics, or parent application state.
- Closing, cancellation, expiry, and transport failure preserve the encrypted
  pending record and clear visible plaintext.

This change provides fresh-user-presence gating. It does not protect plaintext
from arbitrary script already executing in the wallet origin. A factor-wrapped
local encryption key would be required for that stronger boundary and remains
outside this refactor.

## Implementation Plan

### 1. Server authorization boundary

- Add `recovery_backup_reveal` to the exact wallet-custody operation union and
  exhaustive parsers.
- Add the reveal-authorization route using the existing factor authorizer and
  authorized-operation store.
- Change backup acknowledgement to consume the authorized operation.
- Delete `recovery_read`, `recovery_acknowledge`, and the inactive recovery-read
  route and client.

Exit criterion: the server issues a reveal authorization only for a fresh valid
factor and the current recovery-set issuance.

### 2. Local reveal ordering

- Split pending-backup persistence into `readMetadata` and typed `reveal`.
- Reorder the existing direct operation to authorize, reveal, display,
  acknowledge, and delete.
- Apply the same operation through the existing wallet-iframe handler.
- Clear plaintext state on every exit from the display surface.

Exit criterion: no supported client path decrypts the row before authorization,
and successful backup still deletes the row once.

### 3. Focused verification

- Add one repository test rejecting a wrong-wallet or wrong-issuance reveal
  authorization.
- Add route coverage for valid authorization, issuance mismatch, expiry, and
  acknowledgement replay.
- Add one intended-behaviour flow for each supported factor family proving the
  prompt completes before plaintext appears.
- Verify cancellation before authorization never decrypts and cancellation
  after reveal leaves the encrypted row pending.
- Delete tests and fixtures owned solely by the inactive recovery-read route.
- Run the focused tests, `pnpm test:intended`, `pnpm test:source-guards`,
  `pnpm check`, and `git diff --check`.

## Non-Goals

- Changing recovery-code generation, rotation, wrapping, consumption, or
  account-recovery behavior.
- Adding a general-purpose step-up framework.
- Adding a new database table, grant format, coordinator, modal, or public API.
- Wrapping the IndexedDB encryption key with Passkey PRF or Email OTP factor
  material.
- Protecting plaintext from a compromised wallet origin.

## Completion Criteria

- Fresh Passkey or Email OTP verification completes before local recovery-code
  decryption.
- Authorization and acknowledgement are bound to one wallet and recovery-set
  issuance through the existing authorized-operation store.
- The public recovery API and account-menu interaction remain unchanged.
- Cancellation and failure preserve the pending encrypted backup.
- Successful acknowledgement deletes the matching local row.
- `recovery_read`, `recovery_acknowledge`, and their obsolete route/client/test
  paths are absent.
- Focused coverage and the intended-behaviour suite pass.
