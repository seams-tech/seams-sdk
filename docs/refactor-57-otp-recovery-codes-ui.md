# Email OTP Recovery Codes UI Plan

Status: implementation plan.

This plan adds the product UI for backing up the 10 Email OTP recovery codes
generated during Email OTP enrollment. The cryptographic recovery mechanism
already exists in the worker/server model; this plan makes the backup step
visible, mandatory, and testable.

## Recovery Mechanism

Email OTP enrollment creates device-local enrollment escrow:

```text
enc_s(S)
```

`S` is the Email OTP client secret. `enc_s(S)` is stored in wallet-iframe
IndexedDB for same-device login. If local IndexedDB is lost, the user needs one
recovery code to restore `enc_s(S)`.

During enrollment, the Email OTP worker generates 10 one-time recovery keys:

```text
recovery_key_1 ... recovery_key_10
```

For each recovery key, the worker derives a recovery wrapping key and encrypts
the same device-local escrow:

```text
C_i = ChaCha20-Poly1305_Encrypt(K_recovery_i, enc_s(S))
```

With this UI lifecycle, the server stores 10 recovery-wrapped enrollment escrow
records:

```ts
type EmailOtpRecoveryWrappedEnrollmentEscrowRecord = {
  walletId: string;
  userId: string;
  authSubjectId: string;
  authMethod: 'google_sso_email_otp';
  enrollmentId: string;
  enrollmentVersion: string;
  enrollmentSealKeyVersion: string;
  signingRootId: string;
  signingRootVersion: string;
  recoveryKeyId: string;
  recoveryKeyStatus: 'pending_backup' | 'active' | 'consumed' | 'revoked' | 'abandoned';
  nonceB64u: string;
  wrappedDeviceEnrollmentEscrowB64u: string;
  aadHashB64u: string;
  issuedAtMs: number;
  updatedAtMs: number;
};
```

Implement the lifecycle as a discriminated union in TypeScript. Avoid optional
timestamp bags in core logic. Boundary parsers may accept raw persistence rows,
then must normalize them into one of these valid lifecycle branches:

```ts
type EmailOtpRecoveryWrappedEnrollmentEscrowLifecycle =
  | {
      recoveryKeyStatus: 'pending_backup';
      acknowledgedAtMs?: never;
      consumedAtMs?: never;
      revokedAtMs?: never;
      abandonedAtMs?: never;
      cleanupReason?: never;
    }
  | {
      recoveryKeyStatus: 'active';
      acknowledgedAtMs: number;
      consumedAtMs?: never;
      revokedAtMs?: never;
      abandonedAtMs?: never;
      cleanupReason?: never;
    }
  | {
      recoveryKeyStatus: 'consumed';
      acknowledgedAtMs: number;
      consumedAtMs: number;
      revokedAtMs?: never;
      abandonedAtMs?: never;
      cleanupReason?: never;
    }
  | {
      recoveryKeyStatus: 'revoked';
      acknowledgedAtMs: number;
      consumedAtMs?: never;
      revokedAtMs: number;
      abandonedAtMs?: never;
      cleanupReason?: never;
    }
  | {
      recoveryKeyStatus: 'abandoned';
      acknowledgedAtMs?: never;
      consumedAtMs?: never;
      revokedAtMs?: never;
      abandonedAtMs: number;
      cleanupReason:
        | 'registration_cancelled'
        | 'registration_restarted'
        | 'rotation_restarted'
        | 'pending_backup_expired';
    };
```

The worker currently emits `active` recovery-wrapped escrow records. This plan
changes that behavior. Enrollment must persist `pending_backup` records first,
and only `backup-acknowledge` may activate them.

The server never stores the plaintext recovery keys, plaintext `enc_s(S)`,
plaintext `S`, recovery KEKs, or derived signing material.

Relevant implementation surfaces:

1. SDK enrollment result recovery-code field in
   `client/src/SeamsWeb/interfaces.ts`.
2. recovery key generation and wrapping in
   `client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`.
3. formatting/normalization helpers in
   `shared/src/utils/emailOtpRecoveryKey.ts`.
4. server-side acknowledgement, consume, and failure routes:
   - `POST /wallet/email-otp/recovery-key/backup-acknowledge`
   - `POST /wallet/email-otp/recovery-key/consume`
   - `POST /wallet/email-otp/recovery-key/attempt-failed`
5. recovery unwrap prompt support in `PasskeyAuthMenu` for entering one recovery
   key on a new device or after local storage loss.

## Product Goal

After Email OTP enrollment succeeds, show the user the 10 recovery codes and make
them back up the codes before the setup flow can be treated as complete.

User-facing term:

```text
recovery code
```

Internal term:

```text
recovery key
```

The UI should never call them "secrets" in user-facing copy. "Recovery code" is
clearer and matches account-recovery expectations.

## Non-Goals

1. Do not store plaintext recovery codes in localStorage, sessionStorage,
   analytics, logs, or server state.
2. Store generated plaintext recovery codes in IndexedDB only in the dedicated
   pending-backup store defined in Phase 6. This store exists only to survive a
   reload or crash before the user downloads the generated codes.
3. Do not email recovery codes to the user.
4. Do not allow server-side recovery without one user-held recovery code.
5. Do not use recovery codes for transaction signing or key export.
6. Do not couple recovery-code backup to passkey recovery or NEAR account
   recovery.
7. Do not add a long-lived recovery-code cache. The pending-backup IndexedDB
   store is deleted after download acknowledgement, account lock, explicit
   cancellation, stale pending cleanup, or expiry.

## UX Flow

```mermaid
sequenceDiagram
  participant User
  participant UI as "Registration UI"
  participant SDK as "SeamsWeb SDK"
  participant Worker as "emailOtp Worker"
  participant Server

  User->>UI: "Complete Email OTP verification"
  UI->>SDK: "enrollEmailOtp / enrollAndLoginWithEmailOtpEcdsaCapability"
  SDK->>Worker: "Enroll Email OTP"
  Worker->>Worker: "Create enc_s(S)"
  Worker->>Worker: "Generate 10 recovery codes"
  Worker->>Worker: "Wrap enc_s(S) under each code"
  Worker->>Server: "Persist 10 pending_backup wrapped escrows"
  Server-->>Worker: "Enrollment pending backup"
  Worker-->>SDK: "EmailOtpRecoveryCodeSet + issuedAtMs + enrollment metadata"
  SDK-->>UI: "Direct SDK result or wallet-iframe backup screen"
  UI->>User: "Show 10 recovery codes inside the owning UI boundary"
  User->>UI: "Copy/download/print and confirm backup"
  UI->>SDK: "Acknowledge backup"
  SDK->>Server: "Activate pending_backup escrow set"
  Server-->>SDK: "Backup acknowledged"
```

## Backup Screen Requirements

Create a dedicated recovery-code backup screen shown immediately after Email OTP
enrollment returns `recoveryKeys`.

Screen content:

1. Title: `Save your recovery codes`
2. Explanation: these codes restore Email OTP access if this browser/device is
   lost.
3. Warning: each code can be used once.
4. Warning: losing all codes may prevent restoring Email OTP on a new device.
5. The 10 codes in a scannable numbered list.
6. Primary `Download recovery codes` action.
7. Secondary `Copy all` action.
8. Secondary `Print` action where supported.
9. Checkbox: `I saved these recovery codes somewhere safe.`
10. Primary action: `Continue`.

Suggested copy:

```text
Save your recovery codes

These codes restore Email OTP access if this browser or device is lost.
Each code can be used once. Store them somewhere private, like a password
manager.
```

Recovery code display:

```text
01  008J-4CT4-ANK7-F24S-NAXW-SQFE-ZW83-4N3P
02  ...
...
10  ...
```

Use the existing formatting from `formatEmailOtpRecoveryKey(...)`. Codes are
8 groups of 4 Crockford Base32 characters.

## Confirmation Policy

First implementation:

1. `Download recovery codes` is the most prominent action on the screen.
2. Continue is disabled until the user completes at least one backup action:
   download, copy, or print.
3. Continue is also disabled until the user checks the backup acknowledgement.
4. The checkbox state is UI memory only until the owning UI boundary submits
   backup acknowledgement.
5. Server-side backup acknowledgement records non-secret lifecycle completion
   only. It provides no cryptographic proof of backup.
6. The plaintext recovery codes are cleared from React state after the user
   continues.
7. The pending-backup IndexedDB record is deleted after successful download and
   backup acknowledgement.
8. If the user cancels, closes the modal, navigates away, reloads, or the
   registration UI unmounts before acknowledgement, the pending-backup IndexedDB
   record remains until it is redisplayed, explicitly abandoned, replaced, or
   expired.
9. If the backup step is abandoned before acknowledgement and the local pending
   record is gone, the app must not rely on the generated codes. The generated
   server records remain `pending_backup` and excluded from recovery use. The
   next setup attempt must revoke, delete, or expire that pending set before
   generating a fresh set of 10 codes.

Backup action completion semantics:

1. Download counts after the component builds the file from current in-memory
   props, creates a Blob URL, dispatches the download click without throwing, and
   schedules URL revocation. A thrown browser error leaves the action incomplete.
2. Copy counts after `navigator.clipboard.writeText(...)` resolves. If the
   Clipboard API is unavailable or rejects, show a selectable manual-copy view
   and count completion only after the user activates `I copied these codes`.
3. Print counts after `window.print()` is invoked from a user gesture in a
   browser that supports it. The UI may record only `printDialogOpened`; browsers
   do not expose a reliable printed-page signal.
4. Backup-action completion is persisted only as deletion of the pending backup
   record plus non-secret server acknowledgement.

Optional stronger follow-up:

1. Ask the user to re-enter one randomly selected code before continuing.
2. Validate locally with `normalizeEmailOtpRecoveryKey(...)`.
3. Do not send the typed code to the server.
4. Clear the typed code immediately after local validation.

Do the checkbox-only flow first. Add re-entry only if product requires stronger
friction.

## State Ownership

Plaintext recovery codes may exist only in:

1. worker memory during generation.
2. the direct SDK enrollment result returned to a trusted same-origin
   registration UI.
3. wallet-iframe internal messages and wallet-iframe UI memory while the backup
   screen is displayed.
4. the dedicated pending-backup IndexedDB store before successful download and
   backup acknowledgement.
5. clipboard, downloaded file, printed page, or password manager after explicit
   user action.

Plaintext recovery codes must not exist in:

1. server storage.
2. IndexedDB outside the dedicated pending-backup store.
3. localStorage or sessionStorage.
4. logs.
5. analytics or telemetry events.
6. SDK progress events.
7. crash reports.
8. wallet-iframe host RPC payloads.

Wallet-iframe mode has a stricter presentation boundary than direct SDK mode.
The wallet iframe owns the recovery-code backup screen and returns only
non-secret acknowledgement metadata to the host page. The host page must never
receive generated `recoveryKeys` through iframe RPC, logs, progress events, or
registration result payloads.

IndexedDB may store generated plaintext recovery codes only while the matching
server-side recovery-wrapped escrows remain `pending_backup`. It must never
store recovery wrapping keys, recovery KEKs, `enc_s(S)` for backup display, or a
serialized backup-screen payload after acknowledgement.

Allowed backup metadata and temporary plaintext state:

```ts
type EmailOtpRecoveryCodeSetLifecycle =
  | {
      status: 'pending_backup';
      walletId: string;
      enrollmentId: string;
      recoveryCodeCount: 10;
      issuedAtMs: number;
    }
  | {
      status: 'active';
      walletId: string;
      enrollmentId: string;
      recoveryCodeCount: 10;
      issuedAtMs: number;
      acknowledgedAtMs: number;
      activeRecoveryCodeCountAtAcknowledgement: 10;
    }
  | {
      status: 'abandoned';
      walletId: string;
      enrollmentId: string;
      recoveryCodeCount: 10;
      issuedAtMs: number;
      abandonedAtMs: number;
      cleanupReason:
        | 'registration_cancelled'
        | 'registration_restarted'
        | 'rotation_restarted'
        | 'pending_backup_expired';
    };

type EmailOtpRecoveryCodeBackupStatus = Extract<
  EmailOtpRecoveryCodeSetLifecycle,
  { status: 'active' }
>;

type PendingEmailOtpRecoveryCodeBackupRecord = {
  v: 1;
  secretKind: 'email_otp_recovery_codes_pending_backup';
  storageScope: 'iframe_origin_indexeddb' | 'host_origin_indexeddb';
  walletId: string;
  enrollmentId: string;
  enrollmentSealKeyVersion: string;
  recoveryCodesIssuedAtMs: number;
  recoveryKeys: EmailOtpRecoveryCodeSet;
  createdAtMs: number;
  expiresAtMs: number;
};
```

The active lifecycle record proves only that the UI step was completed. The
pending backup record is a temporary local artifact. It is deleted before or
during the same operation that activates the server-side pending set.

The server may persist the non-secret `pending_backup` lifecycle state for
recovery-wrapped escrow records, and those records are excluded from active
recovery-code counts, active status responses, and recovery consumption until
acknowledgement activates them. A matching pending backup record lets the owning
UI boundary redisplay the generated code set after reload while the server set is
still pending.

## UI Integration Points

### SDK Result

Enrollment results must carry a normalized fixed-size recovery-code set and the
issuance timestamp used for the backup file:

```ts
declare const emailOtpRecoveryCodeBrand: unique symbol;

type EmailOtpRecoveryCode = string & {
  readonly [emailOtpRecoveryCodeBrand]: true;
};

type EmailOtpRecoveryCodeSet = readonly [
  EmailOtpRecoveryCode,
  EmailOtpRecoveryCode,
  EmailOtpRecoveryCode,
  EmailOtpRecoveryCode,
  EmailOtpRecoveryCode,
  EmailOtpRecoveryCode,
  EmailOtpRecoveryCode,
  EmailOtpRecoveryCode,
  EmailOtpRecoveryCode,
  EmailOtpRecoveryCode,
];

type EmailOtpEnrollmentResult = {
  recoveryKeys: EmailOtpRecoveryCodeSet;
  recoveryCodesIssuedAtMs: number;
  challengeId: string;
  otpChannel: WalletEmailOtpChannel;
  enrollmentSealKeyVersion: string;
  clientUnlockPublicKeyB64u: string;
  unlockKeyVersion: string;
  thresholdEcdsaClientVerifyingShareB64u: string;
};
```

Do not make `recoveryKeys` or `recoveryCodesIssuedAtMs` optional. Enrollment
either returns exactly 10 normalized recovery codes with an issuance timestamp or
fails. Validate and normalize raw worker output once at the worker/SDK boundary
with `normalizeEmailOtpRecoveryKey(...)`, then pass `EmailOtpRecoveryCodeSet`
through UI code.

Add a named parser/builder for this boundary. Existing raw `string[]` enrollment
results must be replaced at the public SDK surface. Add static type fixtures that
reject:

1. arbitrary `string[]` recovery-code sets.
2. missing `recoveryCodesIssuedAtMs`.
3. optional `recoveryKeys`.
4. broad object spreads that bypass the builder.
5. direct casts from raw worker output to `EmailOtpRecoveryCodeSet`.

### React Component

Add a component:

```text
client/src/react/components/EmailOtpRecoveryCodesBackup/
```

Suggested files:

```text
EmailOtpRecoveryCodesBackup.tsx
EmailOtpRecoveryCodesBackup.css
index.ts
```

Props:

```ts
type EmailOtpRecoveryCodesBackupBaseProps = {
  walletId: string;
  recoveryCodes: EmailOtpRecoveryCodeSet;
  recoveryCodesIssuedAtMs: number;
  onContinue(): void;
};

type EmailOtpRecoveryCodesBackupProps =
  | (EmailOtpRecoveryCodesBackupBaseProps & { mode: 'blocking' })
  | (EmailOtpRecoveryCodesBackupBaseProps & {
      mode: 'cancelable';
      onCancel(): void;
    });
```

Rules:

1. `recoveryCodes` is already a normalized `EmailOtpRecoveryCodeSet`.
2. The boundary normalizer enforces exactly 10 codes.
3. The component formats with `formatEmailOtpRecoveryKey(...)`.
4. Download is visually primary; copy and print are secondary.
5. The component writes generated codes only through the pending-backup
   repository from Phase 6.
6. The component clears any local copied/downloaded text buffer after action
   completion where the browser API permits it.
7. The component clears React plaintext code state on unmount.
8. The component reloads codes from the pending-backup repository only when the
   server status is still `pending_backup` for the same enrollment identifiers.
9. The component tracks `hasCompletedBackupAction` through successful download
   and pending-record deletion.
10. `Continue` requires successful download and server acknowledgement.

### Registration Flow

Wire the component after successful Email OTP enrollment:

1. `SeamsWeb.auth.enrollEmailOtp(...)`
2. `SeamsWeb.auth.enrollAndLoginWithEmailOtpEcdsaCapability(...)`
3. wallet-iframe registration flows inside the iframe UI boundary.

The UI should pause the registration completion path until backup is
acknowledged.

Direct SDK mode boundary:

```text
worker returns EmailOtpRecoveryCodeSet
  -> SDK validates and returns EmailOtpRecoveryCodeSet to trusted registration UI
  -> trusted registration UI stores PendingEmailOtpRecoveryCodeBackupRecord
  -> trusted registration UI displays and acknowledges
  -> SDK activates pending_backup escrow set
  -> UI deletes PendingEmailOtpRecoveryCodeBackupRecord and drops state
```

Wallet-iframe mode boundary:

```text
worker returns EmailOtpRecoveryCodeSet inside wallet iframe
  -> wallet iframe stores PendingEmailOtpRecoveryCodeBackupRecord
  -> wallet iframe displays and acknowledges
  -> wallet iframe activates pending_backup escrow set
  -> wallet iframe returns non-secret backup acknowledgement metadata to host
  -> wallet iframe deletes PendingEmailOtpRecoveryCodeBackupRecord and drops state
```

Iframe RPC payloads to host code must carry only non-secret lifecycle metadata.
They must never carry generated `recoveryKeys`.

This is a breaking iframe contract change. The iframe-owned routes
`PM_ENROLL_EMAIL_OTP` and `PM_ENROLL_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY` must stop
returning generated recovery-code arrays to the host. In wallet-iframe mode, the
iframe renders the backup screen, calls `backup-acknowledge`, clears plaintext
codes, and returns only `EmailOtpRecoveryCodeBackupStatus` or equivalent
non-secret completion metadata to host code.

Server activation and abandoned-backup cleanup:

1. Enrollment persists the 10 recovery-wrapped escrows with
   `recoveryKeyStatus: 'pending_backup'`.
2. `pending_backup` records are excluded from
   `activeRecoveryWrappedEnrollmentEscrowCount`, recovery status responses, and
   recovery-key consumption.
3. After the user completes a backup action and checks the acknowledgement, the
   owning UI boundary calls
   `POST /wallet/email-otp/recovery-key/backup-acknowledge` with non-secret
   enrollment identifiers. The route atomically switches the matching
   `pending_backup` set to `active`, records `acknowledgedAtMs`, and returns
   `EmailOtpRecoveryCodeBackupStatus`.
4. If the user abandons backup, the owning UI boundary marks setup incomplete
   and drops React plaintext code state. The pending-backup IndexedDB record
   remains available for redisplay until acknowledgement, explicit cleanup, or
   expiry. The next setup attempt must revoke or delete the old
   `pending_backup` set before generating a replacement set.
5. The server may expire stale `pending_backup` sets and mark them `abandoned`
   with `cleanupReason: 'pending_backup_expired'`.

Recover this case through the dedicated pending-backup IndexedDB record only
while the server status is still `pending_backup`.

## Download Format

Downloaded file name:

```text
seams-email-otp-recovery-codes-<walletId>.txt
```

Build `<walletId>` from a filename-safe wallet label by allowing ASCII letters,
digits, `_`, `.`, and `-`, and replacing every other character with `_`.

File body:

```text
Seams Email OTP recovery codes

Wallet: <walletId>
Created: <ISO timestamp>

Store these codes somewhere private. Each code can be used once.

01  <code>
02  <code>
...
10  <code>
```

`Created` is derived from `recoveryCodesIssuedAtMs`, formatted as an ISO
timestamp at render/download time.

The file must not include `enc_s(S)`, `S`, recoveryKeyId values, session ids,
threshold key ids, or signing roots.

Download implementation rules:

1. Build the file contents from current in-memory props.
2. Use a Blob URL and revoke it immediately after triggering the download.
3. Do not store the generated text in component state after the click handler
   returns.
4. Record only the non-secret fact that a download action completed.
5. If download fails, keep the codes visible and show copy/print fallbacks.

## Account Settings Follow-Up

Add an account-settings section reachable from the profile menu:

```text
Email OTP recovery codes
```

Profile-menu entrypoint:

1. Add `PROFILE_MENU_ITEM_IDS.RECOVERY_CODES`.
2. Add a menu item with label `Recovery Codes`.
3. Render the status/rotation UI from `AccountMenuButton` using the same portal
   pattern as linked devices and key export.
4. Disable the item when the user is logged out.
5. Fetch server status on open before reading any local pending backup record.
6. Redisplay plaintext recovery codes only from a matching, unexpired
   pending-backup IndexedDB record while server status is `pending_backup`.

Files:

1. `client/src/react/components/AccountMenuButton/types.ts`
2. `client/src/react/components/AccountMenuButton/index.tsx`
3. recovery-code status/rotation modal or drawer component files

Display:

1. active recovery-code count.
2. consumed recovery-code count.
3. revoked recovery-code count.
4. last rotation time.
5. action to rotate/recreate a full set of 10 codes.

Required server routes for full lifecycle:

1. `POST /wallet/email-otp/recovery-key/backup-acknowledge`
2. `GET or POST /wallet/email-otp/device-escrow/status`
3. `POST /wallet/email-otp/recovery-key/revoke`
4. `POST /wallet/email-otp/recovery-key/rotate`

Rotation behavior:

1. Requires fresh Email OTP or equivalent account auth.
2. Rewraps current `enc_s(S)` under 10 newly generated recovery codes.
3. Atomically replaces the active server-side recovery-wrapped escrow set.
4. Displays the new 10 codes in the same backup UI.
5. Marks old active codes revoked or deletes them according to server policy.

Successful device recovery currently returns
`activeRecoveryWrappedEnrollmentEscrowCount`. If the count drops below 10, prompt
the user to rotate and restore the set to 10 active recovery codes.

## Error Handling

Backup screen errors:

1. Clipboard failure: show manual-copy fallback and keep the codes visible.
2. Download failure: show copy/print alternatives.
3. Print failure: show copy/download alternatives.
4. Backup acknowledgement route failure: keep the codes visible, keep
   `Continue` disabled, and allow retry.
5. User closes the modal: keep registration in a pending backup state or show an
   explicit confirmation that leaving discards the displayed codes and requires
   restarting or rotating recovery-code setup.

Recovery use errors:

1. Invalid format: validate locally before server interaction.
2. Wrong code: report failure through
   `/wallet/email-otp/recovery-key/attempt-failed`.
3. Consumed/revoked code: show a clear recovery-code error.
4. Active count below 10 after successful recovery: show rotation prompt.

## Security Requirements

1. Never log plaintext recovery codes.
2. Never include plaintext recovery codes in SDK events.
3. Never include plaintext recovery codes in server route payloads. A
   user-entered recovery code may travel only in the local worker unwrap request.
4. Never send generated recovery codes back to the server during enrollment.
5. Redact `recoveryKeys` in debug output and error serialization.
6. Add static/architecture tests that fail if `recoveryKeys` appears in
   telemetry, analytics, or progress event payloads.
7. Browser autocomplete should be disabled for recovery-code display and entry
   fields.
8. Recovery-code entry should accept paste and normalize spaces/dashes.
9. Store generated recovery codes in IndexedDB only in the dedicated
   pending-backup store, only before acknowledgement, and only for the matching
   `pending_backup` server state.
10. Wallet-iframe host RPC payloads must never include generated `recoveryKeys`.
11. `backup-acknowledge` route payloads must contain only non-secret enrollment
    identifiers and acknowledgement metadata.

## Regression Warnings

1. Do not keep active-immediately recovery-wrapped escrow behavior. New
   enrollment records start as `pending_backup`; recovery consumption and active
   counts must ignore them until acknowledgement.
2. Do not preserve old iframe result payloads that expose generated
   `recoveryKeys` to host pages. Wallet-iframe backup is iframe-owned.
3. Do not keep public recovery-code types as raw `string[]`. Normalize once at
   the worker/SDK boundary into a fixed-size `EmailOtpRecoveryCodeSet`.
4. Do not make `recoveryKeys`, identity fields, lifecycle timestamps, or
   acknowledgement metadata optional in core types.
5. Do not persist plaintext recovery codes outside the dedicated pending-backup
   store. Abandonment after that record is deleted means those plaintext codes
   are gone.
6. Do not patch tests around obsolete behavior. Delete or rewrite fixtures that
   encode active-immediately records, raw recovery-code arrays, or iframe host
   `recoveryKeys` payloads unless they are intentionally testing request or
   persistence boundary rejection.

## Implementation Steps

### Phase 1: Current Surface Audit

1. Confirm every Email OTP enrollment path returns an `EmailOtpRecoveryCodeSet`
   with exactly 10 normalized `recoveryKeys` and `recoveryCodesIssuedAtMs`.
2. Confirm direct SDK enrollment results expose `recoveryKeys` only to trusted
   same-origin registration UI.
3. Confirm wallet-iframe host RPC payloads never expose generated
   `recoveryKeys`; the iframe owns backup display and returns only non-secret
   acknowledgement metadata.
4. Confirm SDK progress events do not include `recoveryKeys`.
5. Confirm logs redact `recoveryKeys`.
6. Confirm IndexedDB persists `recoveryKeys` only in the dedicated
   pending-backup store, and confirm localStorage/sessionStorage never persist
   `recoveryKeys` or generated recovery-code text.
7. Identify tests, helpers, and fixtures that assume active-immediately
   recovery-wrapped escrows.
8. Identify iframe host message types and handlers that currently return
   `recoveryKeys` to host code.

Files:

1. `client/src/SeamsWeb/interfaces.ts`
2. `client/src/SeamsWeb/emailOtp.ts`
3. `client/src/SeamsWeb/index.ts`
4. `client/src/core/WalletIframe/shared/messages.ts`
5. `client/src/core/WalletIframe/router.ts`
6. `client/src/core/WalletIframe/host/wallet-iframe-handlers.ts`
7. `client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`

### Phase 2: Server Lifecycle Hardening

1. Replace active-immediately worker output with `pending_backup` recovery
   wrapped escrows.
2. Add `pending_backup` and `abandoned` to server persistence boundary parsers.
3. Model recovery-wrapped escrow lifecycle as a discriminated union with
   branch-specific timestamps and `never` fields for invalid timestamps.
4. Add `backup-acknowledge` route and route definition.
5. Make `backup-acknowledge` atomically activate exactly the matching pending
   set and record `acknowledgedAtMs`.
6. Ensure pending and abandoned records are excluded from
   `activeRecoveryWrappedEnrollmentEscrowCount`.
7. Ensure pending and abandoned records cannot be consumed by recovery-key use.
8. Add stale pending cleanup behavior that revokes, deletes, or marks records
   abandoned before replacement.
9. Update Postgres and in-memory stores together.
10. Delete or rewrite active-immediately fixtures that only protected obsolete
    behavior.

Files:

1. `client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`
2. `server/src/core/EmailOtpStores.ts`
3. `server/src/core/EmailOtpPostgresRecords.ts`
4. `server/src/router/routeDefinitions.ts`
5. `server/src/router/express/routes/sessions.ts`
6. `server/src/router/cloudflare/routes/sessions.ts`
7. `server/src/router/emailOtpRouteHandlers.ts`
8. `tests/unit/emailOtpRecoveryWrappedEnrollmentEscrowStore.unit.test.ts`
9. `tests/relayer/email-otp.routes.test.ts`
10. `tests/relayer/helpers.ts`

### Phase 3: SDK And Iframe Boundary Contracts

1. Add an `EmailOtpRecoveryCode` brand and fixed-size
   `EmailOtpRecoveryCodeSet`.
2. Add a boundary parser/builder that validates exactly 10 normalized recovery
   codes and `recoveryCodesIssuedAtMs`.
3. Replace raw `string[]` recovery-code public result types.
4. Add type fixtures rejecting raw arrays, optional recovery-code fields, broad
   spreads, and direct casts from worker output.
5. Change wallet-iframe enrollment routes so generated recovery codes remain
   inside the iframe boundary.
6. Return only non-secret backup completion metadata to host code.
7. Add architecture/static tests that fail if iframe host RPC payloads include
   generated `recoveryKeys`.

Files:

1. `client/src/SeamsWeb/interfaces.ts`
2. `client/src/SeamsWeb/emailOtp.ts`
3. `client/src/core/signingEngine/workerManager/workerTypes.ts`
4. `client/src/core/WalletIframe/shared/messages.ts`
5. `client/src/core/WalletIframe/host/handlers/emailOtp.ts`
6. `client/src/core/WalletIframe/client/router.ts`
7. SDK/public typecheck fixtures

### Phase 4: Backup Component

1. Add `EmailOtpRecoveryCodesBackup`.
2. Accept `EmailOtpRecoveryCodeSet` and `recoveryCodesIssuedAtMs` props.
3. Use existing recovery-key formatting helpers.
4. Add primary download action.
5. Add secondary copy and print actions.
6. Add acknowledgement checkbox.
7. Gate continue on one completed backup action plus acknowledgement.
8. Implement explicit completion semantics for download, copy, manual copy, and
   print.
9. Add redaction-safe component tests.

Files:

1. `client/src/react/components/EmailOtpRecoveryCodesBackup/**`
2. `shared/src/utils/emailOtpRecoveryKey.ts`
3. `tests/unit/emailOtpRecoveryCodesBackup.unit.test.ts`

### Phase 5: Registration UI Integration

1. Show backup UI after `enrollEmailOtp`.
2. Show backup UI after `enrollAndLoginWithEmailOtpEcdsaCapability`.
3. Render wallet-iframe backup UI inside the iframe boundary.
4. Pause completion until acknowledgement.
5. Add and call `POST /wallet/email-otp/recovery-key/backup-acknowledge` after
   local UI acknowledgement and activate the matching `pending_backup` set.
6. Clear codes from state after continuation.
7. Persist non-secret backup acknowledgement metadata if the product needs a
   setup-complete indicator.
8. Treat abandoned backup as unrecoverable plaintext-code loss. Revoke or delete
   the old `pending_backup` set before restart or authenticated recovery-code
   rotation can create a replacement set.

Likely integration points:

1. `client/src/react/components/PasskeyAuthMenu/**`
2. demo registration/login containers that call `seams.auth.enrollEmailOtp`
3. wallet-iframe registration UI surfaces
4. wallet-iframe host handlers that receive non-secret backup acknowledgement
   metadata

### Phase 6: Temporary Pending Backup IndexedDB Store

Goal: prevent loss of generated recovery codes if the browser reloads, the
registration modal unmounts, or the wallet iframe restarts before the user has
downloaded the codes. This is a bounded pending-backup artifact, scoped to the
same origin that owns the backup UI.

State model:

```ts
type PendingEmailOtpRecoveryCodeBackupLifecycle =
  | {
      status: 'pending_backup';
      acknowledgedAtMs?: never;
      abandonedAtMs?: never;
      expiredAtMs?: never;
    }
  | {
      status: 'abandoned';
      acknowledgedAtMs?: never;
      abandonedAtMs: number;
      expiredAtMs?: never;
      cleanupReason:
        | 'registration_cancelled'
        | 'registration_restarted'
        | 'rotation_restarted'
        | 'user_dismissed'
        | 'server_pending_set_missing';
    }
  | {
      status: 'expired';
      acknowledgedAtMs?: never;
      abandonedAtMs?: never;
      expiredAtMs: number;
      cleanupReason: 'pending_backup_expired';
    };

type PendingEmailOtpRecoveryCodeBackupRecord =
  PendingEmailOtpRecoveryCodeBackupLifecycle & {
    v: 1;
    secretKind: 'email_otp_recovery_codes_pending_backup';
    storageScope: 'iframe_origin_indexeddb' | 'host_origin_indexeddb';
    walletId: string;
    enrollmentId: string;
    enrollmentSealKeyVersion: string;
    recoveryCodesIssuedAtMs: number;
    recoveryKeys: EmailOtpRecoveryCodeSet;
    createdAtMs: number;
    expiresAtMs: number;
  };
```

Implementation steps:

1. Add a new `seams_wallet` object store for pending Email OTP recovery-code
   backups.
2. Bump `SEAMS_WALLET_DB_VERSION` and add the store to
   `SEAMS_WALLET_SCHEMA_MANIFEST`.
3. Use a composite key of `[wallet_id, enrollment_id]`.
4. Add indexes for `wallet_id`, `enrollment_id`, `expires_at_ms`, and
   `status`.
5. Add a repository module:

   ```text
   client/src/core/indexedDB/seamsWalletDB/emailOtpPendingRecoveryCodeBackups.ts
   ```

6. Normalize raw rows at the repository boundary into
   `PendingEmailOtpRecoveryCodeBackupRecord`.
7. Require `recoveryKeys` to parse through the fixed-size
   `EmailOtpRecoveryCodeSet` builder. Reject raw `string[]` in core helpers.
8. Reject records with missing wallet identity, enrollment identifiers,
   timestamps, expiry, or invalid lifecycle branch timestamps.
9. Reject records whose `secretKind` is anything other than
   `email_otp_recovery_codes_pending_backup`.
10. Write the pending record immediately after enrollment returns generated
    codes and before showing the backup modal.
11. In wallet-iframe mode, write the pending record inside the wallet iframe
    origin. The host page must never receive the record or `recoveryKeys`.
12. In direct SDK mode, write the pending record in the SDK origin that owns the
    same-origin registration UI.
13. On opening the `Recovery Codes` menu item, fetch server status first.
14. If server status is `pending_backup`, read the matching pending backup
    record by `walletId`, `enrollmentId`, and `enrollmentSealKeyVersion`.
15. If a matching pending record exists and is not expired, show the compact
    recovery-code backup modal with the stored codes and a `Download` button.
16. If no matching pending record exists, show non-secret pending status and a
    message that the generated codes are unavailable on this device.
17. If the server reports `ready`, `not_enrolled`, or `incomplete`, never
    display a pending backup record. Delete stale local pending records for that
    wallet/enrollment.
18. After a successful download, call
    `POST /wallet/email-otp/recovery-key/backup-acknowledge`.
19. Delete the pending record only after acknowledgement succeeds. If deletion
    fails, retry deletion and keep the server acknowledgement result; the next
    status open must delete the stale record because server status is no longer
    `pending_backup`.
20. If acknowledgement fails, keep the pending record and keep the modal open so
    the user can retry.
21. Delete pending records on explicit abandon/cancel only after marking or
    replacing the matching server pending set according to the server cleanup
    policy.
22. Delete expired pending records during repository startup, before writing a
    new record for the same wallet, and when the account menu opens.
23. Use a short expiry window. Start with 24 hours unless product requires a
    shorter window.
24. Never sync this store, export it, include it in diagnostics, or expose it
    through public API payloads.

Files:

1. `client/src/core/indexedDB/schemaNames.ts`
2. `client/src/core/indexedDB/seamsWalletDB/schema.ts`
3. `client/src/core/indexedDB/seamsWalletDB/emailOtpPendingRecoveryCodeBackups.ts`
4. `client/src/web/SeamsWeb/operations/authMethods/emailOtp/recoveryCodeBackup.ts`
5. `client/src/web/SeamsWeb/operations/registration/registration.ts`
6. `client/src/web/SeamsWeb/walletIframe/host/handlers/emailOtp.ts`
7. `client/src/react/components/AccountMenuButton/RecoveryCodesModal.tsx`
8. `tests/unit/emailOtpPendingRecoveryCodeBackups.unit.test.ts`
9. `tests/unit/seamsWeb.emailOtpRecoveryCodeBackup.unit.test.ts`
10. `tests/unit/walletIframeHost.emailOtpRecoveryCodes.unit.test.ts`

Static guard updates:

1. Keep the existing escrow-store guard that rejects `recoveryKeys` in
   `email_otp_escrows`.
2. Add an allowlist guard so `recoveryKeys` may appear only in:
   - worker generation output.
   - enrollment result boundary parsers.
   - pending backup repository.
   - backup UI rendering/download code.
   - boundary rejection tests.
3. Add a guard that fails if `PendingEmailOtpRecoveryCodeBackupRecord` appears
   in server code, iframe host-to-parent message payloads, progress events, logs,
   telemetry, or public non-registration APIs.

Validation:

1. Repository unit tests prove invalid branch combinations are rejected.
2. Repository unit tests prove raw `string[]` recovery-code arrays are rejected.
3. Repository unit tests prove expired records are deleted and never returned for
   display.
4. Backup UI tests prove codes can be restored from pending IndexedDB after a
   reload when server status is still `pending_backup`.
5. Account menu tests prove pending codes are displayed only for the matching
   Email OTP wallet/enrollment.
6. Account menu tests prove ready status deletes stale pending records and does
   not redisplay codes.
7. Iframe tests prove host responses still contain no generated `recoveryKeys`.
8. Static guards prove generated recovery codes are not written to localStorage,
   sessionStorage, logs, telemetry, or server route payloads.

### Phase 7: Settings And Rotation

1. Add recovery-code status route.
2. Add revoke route.
3. Add rotate route.
4. Add `PROFILE_MENU_ITEM_IDS.RECOVERY_CODES`.
5. Add a `Recovery Codes` menu item in `AccountMenuButton`.
6. Add account-settings recovery-code status UI reachable from that menu item.
7. Add rotate flow using the same backup component.
8. Prompt rotation after recovery when active count is below 10.

Server files:

1. `server/src/router/routeDefinitions.ts`
2. `server/src/router/express/routes/sessions.ts`
3. `server/src/router/cloudflare/routes/sessions.ts`
4. `server/src/core/AuthService.ts`
5. `server/src/core/EmailOtpStores.ts`

Client files:

1. `client/src/SeamsWeb/emailOtp.ts`
2. `client/src/core/WalletIframe/shared/messages.ts`
3. `client/src/react/components/AccountMenuButton/types.ts`
4. `client/src/react/components/AccountMenuButton/index.tsx`
5. account settings recovery-code UI modules

### Phase 8: Tests

Add tests for:

1. enrollment result contains an `EmailOtpRecoveryCodeSet` with exactly 10
   formatted recovery codes.
2. backup screen renders all 10 codes.
3. Download recovery codes is the primary action.
4. Continue is disabled until a backup action completes according to explicit
   action semantics.
5. Continue is disabled until acknowledgement.
6. copy/download output contains only wallet id, timestamp, and recovery codes.
7. download timestamp comes from `recoveryCodesIssuedAtMs`.
8. Blob URL is revoked after download.
9. UI clears recovery codes from component state after continue.
10. SDK progress events never include `recoveryKeys`.
11. logs and error objects redact `recoveryKeys`.
12. wallet-iframe host RPC payloads never include generated `recoveryKeys`.
13. pending backup records are excluded from active counts and recovery
    consumption.
14. backup acknowledgement activates exactly the matching pending set.
15. abandoned backup revokes, deletes, or expires the old pending set before
    replacement.
16. recovery-code entry normalizes lowercase, spaces, and dashes.
17. used recovery code consumes exactly one active server record.
18. post-recovery active count below 10 triggers rotation prompt.
19. IndexedDB receives generated recovery codes only through the dedicated
    pending-backup store.
20. localStorage and sessionStorage never receive generated recovery codes.
21. abandoned backup can redisplay old plaintext recovery codes after reload only
    while the matching pending-backup IndexedDB record exists, has not expired,
    and server status is still `pending_backup`.
22. active-immediately recovery-wrapped escrow fixtures are gone or limited to
    boundary rejection coverage.
23. public SDK type fixtures reject raw recovery-code arrays and optional
    recovery-code fields.
24. wallet-iframe enrollment host responses contain no generated `recoveryKeys`.
25. `AccountMenuButton` exposes the `Recovery Codes` menu item only for logged-in
    users.
26. profile-menu recovery-code status fetches server status before reading local
    pending backup records.
27. profile-menu recovery-code status renders plaintext codes only from a
    matching, unexpired pending backup record.

## Acceptance Criteria

1. New Email OTP enrollment cannot complete silently without giving the user the
   10 recovery codes.
2. The user can download the 10 recovery codes with one prominent button.
3. The user can also copy or print the 10 codes.
4. Continue requires a completed backup action and acknowledgement.
5. The UI clearly says each code can be used once.
6. The app does not persist plaintext recovery codes after acknowledgement.
7. The app persists plaintext recovery codes before acknowledgement only in the
   dedicated pending-backup IndexedDB store.
8. The server never receives generated plaintext recovery codes.
9. Wallet-iframe host code never receives generated recovery codes.
10. Pending backup escrows become active only after backup acknowledgement.
11. Abandoning the backup screen revokes, deletes, or expires the old pending set
    before restart or authenticated rotation creates replacement codes.
12. Existing device-recovery prompt still accepts one formatted recovery code.
13. Successful recovery consumes one code and surfaces the remaining active count.
14. Account settings can show recovery-code status and rotate back to 10 active
   codes.
15. Tests prove recovery codes are redacted from events, logs, server state, and
   every persistent store outside the dedicated pending-backup store.

## Related Docs

1. Email OTP architecture:
   [email-otp.md](email-otp.md).
2. Signing-session architecture:
   [../signing-session-architecture/](../signing-session-architecture/).
