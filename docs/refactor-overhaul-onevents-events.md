# onEvent Event Overhaul Refactor Plan

Status: Complete for current implementation scope

This plan replaces the current SDK `onEvent`/SSEvent model with flow-native events for registration, wallet unlock, transaction signing, link-device flows, and email recovery. The current event types were designed around an older step-based system and now obscure threshold signer behavior, especially EVM threshold signing, Email OTP authorization, warm signing sessions, presign/commit work, nonce lifecycle updates, device-linking handoff state, and recovery finalization state.

Breaking changes are acceptable. Do not preserve deprecated event names, legacy numeric step meanings, or duplicate compatibility shims. The goal is to leave one clear event system that describes the product flows we actually run now.

## Current problems

1. `RegistrationSSEEvent`, `LoginSSEvent`, and `ActionSSEEvent` are step-based rather than flow-based.
2. Several EVM/Tempo threshold signing events are emitted with ad hoc phases that are not in `ActionPhase`, so wallet-iframe forwarding can drop them before app callbacks receive them.
3. The wallet-iframe progress bus infers overlay show/hide from string phase names. Every new phase can become a hidden UX bug.
4. Email OTP registration and unlock APIs do not consistently expose `onEvent`, even though they are now first-class auth paths.
5. Link-device events are still framed around QR/device polling implementation steps and include nested registration/login error phases.
6. Email recovery events are split across start/finalize paths and do not clearly distinguish waiting for email, polling chain state, and final local persistence.
7. Event `message` text is scattered through implementation code, making it hard to review the user-facing toast/progress copy.
8. Some current events are too granular because they mirror old implementation steps; other flows are missing important events because they were added after the event model.

## Target model

Replace the current event families with a single versioned envelope:

```ts
type WalletFlowEvent =
  | RegistrationFlowEvent
  | UnlockFlowEvent
  | SigningFlowEvent
  | LinkDeviceFlowEvent
  | EmailRecoveryFlowEvent;

type WalletFlowEventBase = {
  version: 2;
  flow: 'registration' | 'unlock' | 'signing' | 'link_device' | 'email_recovery';
  step: number;
  phase: string;
  status:
    | 'started'
    | 'waiting_for_user'
    | 'running'
    | 'succeeded'
    | 'failed'
    | 'cancelled'
    | 'skipped';
  message: string;
  flowId: string;
  requestId?: string;
  accountId?: string;
  authMethod?: 'passkey' | 'email_otp' | 'warm_session';
  interaction?: {
    kind:
      | 'none'
      | 'passkey_create'
      | 'passkey_assert'
      | 'otp_input'
      | 'transaction_confirmation'
      | 'qr_scan'
      | 'qr_display'
      | 'email_recovery_link';
    overlay: 'show' | 'hide' | 'none';
  };
  data?: Record<string, unknown>;
  error?: {
    code?: string;
    message: string;
    retryable?: boolean;
  };
};
```

Rules:

1. Keep ordered phase constants with numeric names, for example `SigningEventPhase.STEP_07_AUTHENTICATION_COMPLETE`.
2. Keep `step` on emitted events so app toasts and debuggers can show ordered progress.
3. Step numbers are new per-flow ordinals, not compatibility with the current `ActionPhase`, `LoginPhase`, or `RegistrationPhase` meanings.
4. Branching flows can reuse the same step number for mutually exclusive alternatives. For example passkey auth and Email OTP auth can both occupy the authorization step.
5. `phase` names describe user/product flow state, not implementation line numbers. The enum member name carries the visible ordering; the enum value should stay semantic, such as `signing.auth.passkey.prompt.succeeded`.
6. `message` is public UI copy. Keep it short, present tense where possible, and stable enough for toast/progress UI.
7. Extra technical facts go into `data`, not `message`.
8. Iframe overlay behavior is explicit via `interaction.overlay`; the progress bus must not infer visibility from `phase`.
9. Events are emitted only when they help app UX, debugging, or support. Internal microsteps should be skipped or represented in `data`.
10. Every flow has terminal `succeeded`, `failed`, or `cancelled` events.

Example shape:

```ts
export enum SigningEventPhase {
  STEP_01_STARTED = 'signing.started',
  STEP_02_REQUEST_PREPARED = 'signing.request.prepared',
  STEP_04_ACCOUNT_READINESS_STARTED = 'signing.account.readiness.started',
  STEP_05_CONFIRMATION_DISPLAYED = 'signing.confirmation.displayed',
  STEP_07_AUTHENTICATION_COMPLETE = 'signing.authentication.complete',
  STEP_08_SIGNER_PREPARE_STARTED = 'signing.signer.prepare.started',
  STEP_10_COMMIT_STARTED = 'signing.commit.started',
  STEP_11_TRANSACTION_SIGNED = 'signing.transaction.signed',
  STEP_12_BROADCAST_ACCEPTED = 'signing.broadcast.accepted',
  STEP_13_RECEIPT_FINALIZED = 'signing.receipt.finalized',
  STEP_14_APP_STATE_SYNC_STARTED = 'signing.app_state.sync.started',
  STEP_15_COMPLETED = 'signing.completed',
  FAILED = 'signing.failed',
  CANCELLED = 'signing.cancelled',
}
```

The exact step names should be flow-specific. Do not keep old names like `ActionPhase.STEP_4_AUTHENTICATION_COMPLETE`; create the new ordered names in the new event namespace.

## Event copy inventory

These are the initial canonical event phases and messages. Implementation may remove or add phases as flow review reveals a better UX, but additions must update this table first.

The rows below are in canonical step order. During implementation, each row should become a `STEP_N_*` enum member unless it is an unordered terminal event such as `FAILED` or `CANCELLED`. If a flow branch has mutually exclusive auth methods, the branch rows may share a step number.

### Passkey Registration

| Phase | Status | Message |
| --- | --- | --- |
| `registration.started` | `started` | `Starting registration` |
| `registration.account.preflight.started` | `running` | `Checking account details` |
| `registration.account.preflight.succeeded` | `succeeded` | `Account details ready` |
| `registration.auth.passkey.create.started` | `waiting_for_user` | `Create your passkey` |
| `registration.auth.passkey.create.succeeded` | `succeeded` | `Passkey created` |
| `registration.signer.ed25519.prepare.started` | `running` | `Preparing NEAR signer` |
| `registration.signer.ed25519.prepare.succeeded` | `succeeded` | `NEAR signer ready` |
| `registration.relay.bootstrap.started` | `running` | `Creating wallet account` |
| `registration.relay.bootstrap.succeeded` | `succeeded` | `Wallet account created` |
| `registration.account.verify.started` | `running` | `Verifying wallet account` |
| `registration.account.verify.succeeded` | `succeeded` | `Wallet account verified` |
| `registration.storage.persist.started` | `running` | `Saving wallet metadata` |
| `registration.storage.persist.succeeded` | `succeeded` | `Wallet metadata saved` |
| `registration.signer.ecdsa.provision.started` | `running` | `Preparing EVM signer` |
| `registration.signer.ecdsa.provision.succeeded` | `succeeded` | `EVM signer ready` |
| `registration.signer.ecdsa.provision.skipped` | `skipped` | `EVM signer setup skipped` |
| `registration.completed` | `succeeded` | `Registration complete` |
| `registration.failed` | `failed` | `Registration failed` |
| `registration.cancelled` | `cancelled` | `Registration cancelled` |

Overlay rules:

1. `registration.auth.passkey.create.started` uses `interaction: { kind: 'passkey_create', overlay: 'show' }`.
2. `registration.auth.passkey.create.succeeded`, `registration.failed`, and `registration.cancelled` use `overlay: 'hide'`.

### Email OTP Registration

| Phase | Status | Message |
| --- | --- | --- |
| `registration.started` | `started` | `Starting registration` |
| `registration.session.exchange.started` | `running` | `Checking registration session` |
| `registration.session.exchange.succeeded` | `succeeded` | `Registration session ready` |
| `registration.otp.challenge.started` | `running` | `Sending email code` |
| `registration.otp.challenge.sent` | `succeeded` | `Email code sent` |
| `registration.otp.input.required` | `waiting_for_user` | `Enter the email code` |
| `registration.otp.verify.started` | `running` | `Verifying email code` |
| `registration.otp.verify.succeeded` | `succeeded` | `Email verified` |
| `registration.signer.email_otp.enroll.started` | `running` | `Securing Email OTP signer` |
| `registration.signer.email_otp.enroll.succeeded` | `succeeded` | `Email OTP signer secured` |
| `registration.signer.ecdsa.bootstrap.started` | `running` | `Preparing EVM signer` |
| `registration.signer.ecdsa.bootstrap.succeeded` | `succeeded` | `EVM signer ready` |
| `registration.signer.ed25519.provision.started` | `running` | `Preparing NEAR signer` |
| `registration.signer.ed25519.provision.succeeded` | `succeeded` | `NEAR signer ready` |
| `registration.signer.ed25519.provision.skipped` | `skipped` | `NEAR signer setup skipped` |
| `registration.completed` | `succeeded` | `Registration complete` |
| `registration.failed` | `failed` | `Registration failed` |
| `registration.cancelled` | `cancelled` | `Registration cancelled` |

Overlay rules:

1. `registration.otp.input.required` uses `interaction: { kind: 'otp_input', overlay: 'show' }` when the input is rendered in the wallet iframe.
2. `registration.otp.verify.started`, `registration.failed`, and `registration.cancelled` use `overlay: 'hide'` after the user submits or exits.

### Wallet Unlock

Use `unlock`, not `login`, in new event names. The user-facing API may still have an `unlock` method, but event names should not call this flow login.

| Phase | Status | Message |
| --- | --- | --- |
| `unlock.started` | `started` | `Unlocking wallet` |
| `unlock.account.lookup.started` | `running` | `Finding wallet account` |
| `unlock.account.lookup.succeeded` | `succeeded` | `Wallet account found` |
| `unlock.auth.passkey.challenge.started` | `running` | `Preparing passkey check` |
| `unlock.auth.passkey.prompt.started` | `waiting_for_user` | `Confirm with passkey` |
| `unlock.auth.passkey.prompt.succeeded` | `succeeded` | `Passkey confirmed` |
| `unlock.auth.email_otp.challenge.started` | `running` | `Sending email code` |
| `unlock.auth.email_otp.challenge.sent` | `succeeded` | `Email code sent` |
| `unlock.auth.email_otp.input.required` | `waiting_for_user` | `Enter the email code` |
| `unlock.auth.email_otp.verify.started` | `running` | `Verifying email code` |
| `unlock.auth.email_otp.verify.succeeded` | `succeeded` | `Email verified` |
| `unlock.app_session.exchange.started` | `running` | `Creating app session` |
| `unlock.app_session.exchange.succeeded` | `succeeded` | `App session ready` |
| `unlock.app_session.exchange.skipped` | `skipped` | `App session skipped` |
| `unlock.signing_session.warmup.started` | `running` | `Preparing signing session` |
| `unlock.signing_session.ed25519.ready` | `succeeded` | `NEAR signing session ready` |
| `unlock.signing_session.ecdsa.ready` | `succeeded` | `EVM signing session ready` |
| `unlock.session.ready` | `succeeded` | `Wallet session ready` |
| `unlock.completed` | `succeeded` | `Wallet unlocked` |
| `unlock.failed` | `failed` | `Wallet unlock failed` |
| `unlock.cancelled` | `cancelled` | `Wallet unlock cancelled` |

Overlay rules:

1. Passkey prompt events use `kind: 'passkey_assert'`.
2. Email OTP input events use `kind: 'otp_input'`.
3. Warm-session preparation does not show the overlay unless it triggers a passkey or OTP prompt.

### Transaction Signing

The signing flow must cover NEAR, Tempo, and EVM, but the immediate correctness priority is threshold EVM transaction signing.

| Phase | Status | Message |
| --- | --- | --- |
| `signing.started` | `started` | `Preparing transaction` |
| `signing.request.prepared` | `succeeded` | `Transaction ready for review` |
| `signing.nonce.reserve.started` | `running` | `Reserving nonce` |
| `signing.nonce.reserve.succeeded` | `succeeded` | `Nonce reserved` |
| `signing.account.readiness.started` | `running` | `Checking account readiness` |
| `signing.account.readiness.succeeded` | `succeeded` | `Account ready` |
| `signing.account.readiness.skipped` | `skipped` | `Account readiness check skipped` |
| `signing.confirmation.displayed` | `waiting_for_user` | `Review transaction` |
| `signing.confirmation.approved` | `succeeded` | `Transaction approved` |
| `signing.confirmation.cancelled` | `cancelled` | `Transaction rejected` |
| `signing.auth.warm_session.claimed` | `succeeded` | `Signing session authorized` |
| `signing.auth.passkey.prompt.started` | `waiting_for_user` | `Confirm with passkey` |
| `signing.auth.passkey.prompt.succeeded` | `succeeded` | `Passkey confirmed` |
| `signing.auth.email_otp.challenge.started` | `running` | `Sending email code` |
| `signing.auth.email_otp.challenge.sent` | `succeeded` | `Email code sent` |
| `signing.auth.email_otp.input.required` | `waiting_for_user` | `Enter the email code` |
| `signing.auth.email_otp.verify.started` | `running` | `Verifying email code` |
| `signing.auth.email_otp.verify.succeeded` | `succeeded` | `Email verified` |
| `signing.authentication.complete` | `succeeded` | `Authentication complete` |
| `signing.signer.prepare.started` | `running` | `Preparing secure signer` |
| `signing.signer.prepare.succeeded` | `succeeded` | `Secure signer ready` |
| `signing.threshold_session.ensure.started` | `running` | `Checking threshold signer` |
| `signing.threshold_session.reconnect.started` | `running` | `Reconnecting threshold signer` |
| `signing.threshold_session.reconnect.succeeded` | `succeeded` | `Threshold signer ready` |
| `signing.presign.claim.started` | `running` | `Preparing signature share` |
| `signing.presign.claim.succeeded` | `succeeded` | `Signature share ready` |
| `signing.presign.refill.scheduled` | `running` | `Refreshing signature shares` |
| `signing.commit.queued` | `running` | `Waiting for threshold signer` |
| `signing.commit.started` | `running` | `Creating threshold signature` |
| `signing.commit.succeeded` | `succeeded` | `Threshold signature created` |
| `signing.signature.created` | `succeeded` | `Signature created` |
| `signing.transaction.signed` | `succeeded` | `Transaction signed` |
| `signing.broadcast.submitted` | `running` | `Broadcasting transaction` |
| `signing.broadcast.accepted` | `succeeded` | `Transaction broadcast` |
| `signing.broadcast.rejected` | `failed` | `Transaction broadcast failed` |
| `signing.nonce.reconcile.started` | `running` | `Checking nonce state` |
| `signing.nonce.reconcile.succeeded` | `succeeded` | `Nonce state updated` |
| `signing.receipt.finalized` | `succeeded` | `Transaction finalized` |
| `signing.receipt.reverted` | `failed` | `Transaction reverted` |
| `signing.transaction.dropped` | `failed` | `Transaction dropped` |
| `signing.transaction.replaced` | `succeeded` | `Transaction replaced` |
| `signing.app_state.sync.started` | `running` | `Refreshing app state` |
| `signing.app_state.sync.succeeded` | `succeeded` | `App state refreshed` |
| `signing.completed` | `succeeded` | `Transaction complete` |
| `signing.failed` | `failed` | `Signing failed` |
| `signing.cancelled` | `cancelled` | `Signing cancelled` |

Overlay rules:

1. `signing.confirmation.displayed` uses `interaction: { kind: 'transaction_confirmation', overlay: 'show' }`.
2. Passkey and OTP auth events use their auth-specific interaction kinds.
3. `signing.confirmation.approved`, `signing.auth.passkey.prompt.succeeded`, `signing.auth.email_otp.verify.started`, `signing.transaction.signed`, `signing.failed`, and `signing.cancelled` use `overlay: 'hide'` when no later user interaction is pending.
4. Threshold signer work, presign work, commit queues, account-readiness checks, nonce reconciliation, and broadcast tracking never show the overlay by themselves.

### Link Device

The link-device flow spans two devices. The same event family should cover both the QR-display device and the QR-scanning device, with `data.role` set to `display` or `scanner` where useful.

| Phase | Status | Message |
| --- | --- | --- |
| `link_device.started` | `started` | `Starting device link` |
| `link_device.qr.generated` | `waiting_for_user` | `Scan the QR code` |
| `link_device.qr.scanning` | `waiting_for_user` | `Scanning QR code` |
| `link_device.qr.scanned` | `succeeded` | `QR code scanned` |
| `link_device.payload.validated` | `succeeded` | `Link request verified` |
| `link_device.authorization.started` | `waiting_for_user` | `Authorize device link` |
| `link_device.authorization.succeeded` | `succeeded` | `Device link authorized` |
| `link_device.relay_session.registered` | `succeeded` | `Link session ready` |
| `link_device.onchain.add_key.started` | `running` | `Adding device key` |
| `link_device.onchain.add_key.detected` | `succeeded` | `Device key detected` |
| `link_device.new_device.register.started` | `running` | `Registering new device` |
| `link_device.new_device.register.succeeded` | `succeeded` | `New device registered` |
| `link_device.signer.near.persist.started` | `running` | `Saving NEAR signer` |
| `link_device.signer.near.persist.succeeded` | `succeeded` | `NEAR signer saved` |
| `link_device.signer.ecdsa.persist.started` | `running` | `Saving EVM signer` |
| `link_device.signer.ecdsa.persist.succeeded` | `succeeded` | `EVM signer saved` |
| `link_device.signer.ecdsa.persist.skipped` | `skipped` | `EVM signer skipped` |
| `link_device.polling.started` | `running` | `Waiting for linked device` |
| `link_device.completed` | `succeeded` | `Device linked` |
| `link_device.auto_unlock.started` | `running` | `Unlocking linked device` |
| `link_device.auto_unlock.succeeded` | `succeeded` | `Linked device unlocked` |
| `link_device.auto_unlock.skipped` | `skipped` | `Auto unlock skipped` |
| `link_device.failed` | `failed` | `Device link failed` |
| `link_device.cancelled` | `cancelled` | `Device link cancelled` |

Overlay rules:

1. `link_device.qr.generated` uses `interaction: { kind: 'qr_display', overlay: 'hide' }`; the app should remain usable while displaying the QR UI outside the invisible iframe overlay.
2. `link_device.qr.scanning` uses `interaction: { kind: 'qr_scan', overlay: 'none' }` unless the scanner UI is rendered inside the wallet iframe.
3. `link_device.authorization.started` uses `interaction: { kind: 'transaction_confirmation', overlay: 'show' }` or `passkey_assert` when the implementation is pure WebAuthn.
4. `link_device.new_device.register.started` uses `interaction: { kind: 'passkey_create', overlay: 'show' }` when the linked device is creating a passkey.
5. `link_device.authorization.succeeded`, `link_device.new_device.register.succeeded`, `link_device.failed`, and `link_device.cancelled` use `overlay: 'hide'`.

### Email Recovery

Email recovery is a two-part flow: start recovery, then finalize once the email-side recovery action has completed. The event model should make that split explicit without forcing the app to learn separate event families.

| Phase | Status | Message |
| --- | --- | --- |
| `email_recovery.started` | `started` | `Starting email recovery` |
| `email_recovery.resumed.pending` | `running` | `Resuming email recovery` |
| `email_recovery.account.lookup.started` | `running` | `Finding wallet account` |
| `email_recovery.account.lookup.succeeded` | `succeeded` | `Wallet account found` |
| `email_recovery.auth.passkey.create.started` | `waiting_for_user` | `Create recovery passkey` |
| `email_recovery.auth.passkey.create.succeeded` | `succeeded` | `Recovery passkey created` |
| `email_recovery.email.link.sent` | `succeeded` | `Recovery email sent` |
| `email_recovery.email.link.waiting` | `waiting_for_user` | `Waiting for email confirmation` |
| `email_recovery.recovery_key.poll.started` | `running` | `Checking recovery key status` |
| `email_recovery.recovery_key.poll.detected` | `succeeded` | `Recovery key confirmed` |
| `email_recovery.finalize.started` | `running` | `Finalizing recovery` |
| `email_recovery.finalize.succeeded` | `succeeded` | `Recovery finalized` |
| `email_recovery.auto_unlock.skipped` | `skipped` | `Local unlock skipped` |
| `email_recovery.completed` | `succeeded` | `Email recovery complete` |
| `email_recovery.failed` | `failed` | `Email recovery failed` |
| `email_recovery.cancelled` | `cancelled` | `Email recovery cancelled` |

Overlay rules:

1. `email_recovery.auth.passkey.create.started` uses `interaction: { kind: 'passkey_create', overlay: 'show' }`.
2. `email_recovery.email.link.waiting` uses `interaction: { kind: 'email_recovery_link', overlay: 'hide' }`.
3. Polling, finalization, and storage events never show the overlay by themselves.
4. `email_recovery.auth.passkey.create.succeeded`, `email_recovery.failed`, and `email_recovery.cancelled` use `overlay: 'hide'`.

## Files to update first

Update these files in dependency order. The first pass should be narrow: establish the new event envelope and transport behavior, then migrate one flow at a time.

### 1. Event type source of truth

- `client/src/core/types/sdkSentEvents.ts`
  - Defines the v2 event envelope, flow phase enums, hook option callback types, phase-to-step maps, messages, and constructor helpers.
  - This should be the first implementation file changed because every emitter and callback consumer imports from it.
  - Add the new v2 envelope, `RegistrationEventPhase`, `UnlockEventPhase`, `SigningEventPhase`, `LinkDeviceEventPhase`, `EmailRecoveryFlowEventPhase`, phase-to-step mappings, canonical messages, and event constructor helpers here or in a sibling module imported from here.
- `client/src/index.ts` and `client/src/react/index.ts`
  - Re-export the public event types and enums.
  - Update after the type source of truth lands so downstream apps see only the new names.
- `client/src/react/types.ts`
  - Re-exports and aliases SDK event types for React consumers.
  - Update with the public exports to avoid React users compiling against removed legacy names.
- `client/src/core/types/linkDevice.ts` and `client/src/core/types/emailRecovery.ts`
  - Define flow-specific option types for link-device and email-recovery callbacks.

### 2. Wallet iframe transport boundary

- `client/src/core/WalletIframe/shared/messages.ts`
  - Defines `ProgressPayload`, the `PROGRESS` envelope, and serializable request `options`.
  - Change `ProgressPayload` to the v2 event envelope before touching router or host forwarding.
- `client/src/core/WalletIframe/host/wallet-iframe-handlers.ts`
  - Owns `withProgress()` and bridges host-side SDK `onEvent` into `PROGRESS` messages.
  - Add `onEvent` forwarding for Email OTP registration/unlock iframe APIs that currently return results without progress callbacks.
- `client/src/core/WalletIframe/host/index.ts`
  - Owns `postProgress()` and the host-side `PROGRESS` send path.
  - Keep this thin, but update types once `ProgressPayload` changes.
- `client/src/core/WalletIframe/client/router.ts`
  - Owns callback forwarding through `wrapOnEvent()`, request registration, cancellation fallback events, and old runtime phase guards.
  - Replace old enum membership guards with v2 `version`/`flow` guards.
  - Update all public method option types that expose `onEvent`.
- `client/src/core/WalletIframe/client/progress/on-events-progress-bus.ts`
  - Owns overlay visibility decisions.
  - Replace phase-string `SHOW_PHASES`/`HIDE_PHASES` with `event.interaction.overlay`.

### 3. Registration emitters

- `client/src/core/TatchiPasskey/registration.ts`
  - Main passkey registration event emitter.
  - Replace old `RegistrationPhase` emissions with v2 registration events and preserve ordered `step`.
- `client/src/core/TatchiPasskey/faucets/createAccountRelayServer.ts`
  - Emits relay bootstrap registration progress.
  - Convert these after `registration.ts` so account creation messages are consistent.
- `client/src/core/signingEngine/SigningEngine.ts`
  - Owns Email OTP enrollment, Email OTP login/bootstrap, ECDSA capability bootstrap, and some signing entry points.
  - Add Email OTP registration event coverage here after passkey registration semantics are settled.
- `client/src/core/TatchiPasskey/index.ts` and `client/src/core/TatchiPasskey/interfaces.ts`
  - Public auth/registration method surfaces.
  - Add or update `onEvent` options for Email OTP registration/unlock methods and route them through wallet iframe mode.

### 4. Unlock emitters

- `client/src/core/TatchiPasskey/login.ts`
  - Main wallet unlock implementation despite the filename.
  - Rename event semantics from login to unlock, split overloaded `webauthn-assertion` events, and emit warm-session readiness events.
- `client/src/react/context/useTatchiWithSdkFlow.ts`
  - Checks v2 unlock and registration completion phases to update React state.
- `client/src/react/context/useTatchiContextValue.ts`
  - Uses React flow runtime behavior with v2 event phases.

### 5. Transaction signing emitters

- `client/src/core/signingEngine/api/evmSigning.ts`
  - Highest-priority signing file because it emits current ad hoc EVM/Tempo threshold lifecycle events: Email OTP challenge, threshold reconnect, presign refill, commit queue, and nonce lifecycle.
  - Convert first within signing so stale EVM threshold transaction events are fixed early.
- `client/src/core/signingEngine/orchestration/evm/evmSigningFlow.ts`
  - Emits EVM confirmation and signing progress events.
  - Convert after `evmSigning.ts` has the canonical signing event helpers.
- `client/src/core/signingEngine/orchestration/tempo/tempoSigningFlow.ts`
  - Mirrors EVM flow for Tempo; update with the same signing helpers.
- `client/src/core/signingEngine/orchestration/near/transactionsFlow.ts`
  - Main NEAR threshold transaction flow; emits v2 signing events.
- `client/src/core/signingEngine/orchestration/near/delegateFlow.ts`
  - Delegate action flow with old action phases.
  - Convert with the NEAR transaction signing pass.
- `client/src/core/signingEngine/api/nearSigning.ts`
  - NEAR signing API wrapper that emits action-style events.
  - Update after the underlying orchestration flow.
- `client/src/core/TatchiPasskey/near/actions.ts`, `client/src/core/TatchiPasskey/near/delegateAction.ts`, `client/src/core/TatchiPasskey/near/signNEP413.ts`, and `client/src/core/TatchiPasskey/near/index.ts`
  - Public NEAR wrapper layer using shared v2 signing helpers.
- `client/src/core/TatchiPasskey/tempo/executeEvmFamilyTransaction.ts`
  - Public Tempo/EVM transaction execution wrapper and nonce lifecycle callback surface.
  - Update once `evmSigning.ts` event names are final.

### 6. Worker-origin progress bridge

- `client/src/core/signingEngine/touchConfirm/handlers/flows/signing.ts`
  - Emits old WebAuthn/authentication progress from confirmation handling.
  - Convert to auth-specific signing events or feed through event constructor helpers.
- `client/src/core/signingEngine/workerManager/workerTransport.ts`
  - Delivers worker progress payloads to pending operations.
  - Audit after event constructors exist; this may need normalization at the boundary.
- `client/src/core/signingEngine/workerManager/workerTypes.ts`
  - Types worker `onEvent`/progress payloads.
  - Update with the new event envelope or an explicit worker-internal progress type if worker progress stays lower-level.
- `client/src/core/signingEngine/interfaces/near.ts`
  - Exposes v2 `SigningFlowEvent` callbacks for NEAR signing interfaces.

### 7. Tests and docs to update early

- `tests/unit/progressBus.overlayIntentResolver.test.ts`
  - Overlay metadata tests for the progress bus.
- `tests/e2e/worker_events.test.ts`
  - Currently asserts old action progress phases; convert to v2 flow sequence assertions.
- `tests/unit/tatchiPasskey.chainSigners.unit.test.ts`
  - Updated to assert v2 signing completion.
- `tests/unit/tatchiPasskey.loginThresholdWarm.unit.test.ts`
  - Unlock/warm-session event expectations should move to v2 unlock phases.
- `tests/unit/thresholdEcdsa.registrationBootstrapParity.unit.test.ts`
  - Registration and ECDSA bootstrap expectations should be checked while migrating registration events.
- `tests/unit/deviceRecoveryDomain.emailRecovery.unit.test.ts`
  - Updated to assert v2 email-recovery phase order.
- Link-device tests under `tests/unit/linkDevice.*.test.ts` and `tests/e2e/thresholdEcdsa.linkDevice.manualBootstrap.test.ts`
  - Add v2 link-device sequence assertions where the test covers progress callbacks.
- `client/src/core/WalletIframe/client/README-onevent-hooks.md`, `client/src/core/WalletIframe/client/progress/README-progress-bus.md`, and `client/src/core/WalletIframe/README.md`
  - Keep these docs aligned with the v2 `WalletFlowEvent` envelope and explicit `interaction.overlay` behavior.

### 8. Link-device emitters and consumers

- `client/src/core/TatchiPasskey/near/linkDevice.ts`
  - Main device2 QR generation, polling, registration, completion, and auto-unlock flow.
  - Replace `DeviceLinkingPhase` emissions with v2 `link_device` events.
- `client/src/core/TatchiPasskey/scanDevice.ts`
  - Device1 scanned-QR path and authorization/registration handoff.
  - Convert QR scan, authorization, and linked-device persistence events.
- `client/src/core/rpcClients/near/rpcCalls.ts`
  - Emits device-link authorization/add-key completion progress.
  - Convert or route through link-device event helpers.
- `client/src/core/TatchiPasskey/near/linkDevicePreparedEcdsa.ts`, `client/src/core/TatchiPasskey/evm/linkDeviceThresholdEcdsa.ts`, and `client/src/core/TatchiPasskey/near/linkDeviceOwnerManagement.ts`
  - Link-device signer persistence and owner-management helpers.
  - Add events only if they represent user-visible signer readiness; otherwise keep details in parent event `data`.
- `client/src/react/hooks/useDeviceLinking.ts`, `client/src/react/components/ShowQRCode.tsx`, `client/src/react/components/QRCodeScanner.tsx`, `client/src/react/components/AccountMenuButton/types.ts`, and `client/src/react/components/PasskeyAuthMenu/controller/usePasskeyAuthMenuController.ts`
  - React consumers that import `DeviceLinkingPhase`/`DeviceLinkingSSEEvent` or switch on old phases.
  - Update after core link-device emitters migrate.

### 9. Email recovery emitters and consumers

- `client/src/core/TatchiPasskey/near/emailRecovery.ts`
  - Main start/finalize email recovery domain implementation.
  - Replace `EmailRecoveryPhase` emissions with v2 `email_recovery` events and clarify start versus finalize phases.
- `client/src/utils/emailRecovery/emailRecoveryPendingStore.ts`
  - Pending recovery storage is not an event emitter, but its state names should be checked against the v2 recovery phases for consistency.
- `client/src/core/TatchiPasskey/interfaces.ts`, `client/src/core/TatchiPasskey/index.ts`, and `client/src/core/WalletIframe/TatchiPasskeyIframe.ts`
  - Public recovery surfaces and iframe route wrappers.
  - Update callback types and event forwarding for recovery methods.
- `client/src/core/WalletIframe/client/router.ts` and `client/src/core/WalletIframe/host/wallet-iframe-handlers.ts`
  - Already listed as transport files, but recovery-specific `startEmailRecovery` and `finalizeEmailRecovery` methods need v2 flow guards and option types.

## Phased todo list

### Phase 0. Inventory and event sequence decisions

- [x] Inventory every `onEvent?.(...)` call in `client/src/core`, `client/src/react`, wallet iframe host/client code, and tests.
- [x] Classify each current event as keep, rename, merge, split, or delete.
- [x] Identify flows that currently emit too many internal implementation events and collapse them into one user-facing event plus structured `data`.
- [x] Identify flows that currently emit too few events, especially Email OTP registration/unlock, EVM threshold signing, link-device signer persistence, and email recovery finalization.
- [x] Confirm the canonical phase/message table in this document before changing types.
- [x] Decide whether nonce reporting callbacks are part of `signing` events or a separate `transaction_lifecycle` flow. Default: keep them under `signing` for now because app toasts consume them as signing progress.

### Phase 1. Replace public event types

- [x] Replace `BaseSSEEvent`, `RegistrationSSEEvent`, `LoginSSEvent`, `ActionSSEEvent`, and related step interfaces with v2 flow event types.
  - Public SDK events are now v2-only. The Rust NEAR signer worker still has a private `NearWorkerProgressEvent` boundary, but it is no longer exported as an SDK `onEvent` shape.
- [x] Keep numeric `step` on the public event surface, but redefine it as a new per-flow ordinal.
  - V2 constructors now derive `step` from the phase-to-step map and no longer accept manual step overrides.
- [x] Remove `RegistrationPhase`, `LoginPhase`, and `ActionPhase` legacy enums rather than keeping aliases.
  - `RegistrationPhase`, `LoginPhase`, and `ActionPhase` are removed from source and tests. Touch-confirm/worker progress now uses private string phases with v2 status words at the worker boundary and maps to v2 signing events before app callbacks.
- [x] Add flow-specific phase enums with `STEP_N_*` member names:
  - [x] `RegistrationEventPhase`
  - [x] `UnlockEventPhase`
  - [x] `SigningEventPhase`
  - [x] `LinkDeviceEventPhase`
  - [x] `EmailRecoveryFlowEventPhase`
- [x] Add a single phase-to-step mapping per flow so helpers derive `event.step` from `event.phase`.
- [x] Allow mutually exclusive branch phases to share a step number where that improves readability.
- [x] Add helper constructors in one SDK module so all emitters use the same status/message/interaction conventions.
- [x] Update hook option types so registration, unlock, signing, link-device, and email-recovery methods all use `EventCallback<WalletFlowEvent>` or flow-specific narrowed callbacks.
  - Completed for registration, unlock, signing, link-device, email-recovery, account-sync, and Email OTP public API boundaries.

### Phase 2. Wallet iframe message and progress bus refactor

- [x] Replace `ProgressPayload` in `client/src/core/WalletIframe/shared/messages.ts` with the v2 event envelope.
  - Completed after migrating account sync to `AccountSyncFlowEvent`; `ProgressPayload` is now `WalletFlowEvent`.
- [x] Update wallet iframe host `withProgress()` to forward v2 events without old step/phase coercion.
- [x] Replace phase-set overlay heuristics in `client/src/core/WalletIframe/client/progress/on-events-progress-bus.ts` with explicit `event.interaction.overlay`.
- [x] Remove `SHOW_PHASES`, `HIDE_PHASES`, and `defaultPhaseHeuristics` phase-string matching.
  - Completed phase-name cleanup: `SHOW_PHASES`, `HIDE_PHASES`, and terminal phase/status inference are removed. The bus now reads only `event.interaction.overlay`.
- [x] Ensure terminal v2 events default to `interaction: { kind: 'none', overlay: 'hide' }`.
- [x] Update `OnEventsProgressBus` stats to track `flow`, `phase`, `status`, and `lastAt`.
- [x] Update `WalletIframeRouter.wrapOnEvent()` to filter by `version` and `flow`, not old enum membership.
  - Completed for registration, unlock, signing, link-device, and email-recovery routes.
- [x] Ensure unrecognized v2 events are still forwarded to subscribers when their `flow` matches.
- [x] Update link-device and email-recovery router methods to use v2 flow-specific guards.
- [x] Remove dead wallet iframe `ActionSSEEvent`/`ActionPhase` progress guard code after signing routes moved to `SigningFlowEvent`.
- [x] Replace the remaining account-sync legacy guard with `AccountSyncFlowEvent`.
- [x] Update cancellation/error fallback events emitted by the router to use `failed` or `cancelled` v2 terminal events.
  - Router error fallbacks now synthesize v2 terminal flow events for registration, unlock, signing, link-device, email-recovery, and account-sync requests.

Implementation note: the first implementation slice added the v2 event model, numbered flow phase enums, canonical message map, event constructor helper, v2-capable wallet iframe `ProgressPayload`, and explicit overlay handling in the progress bus. The old event exports are still present until each emitter and public callback surface is migrated.

### Phase 3. Registration emitters

- [x] Rewrite passkey registration events in `client/src/core/TatchiPasskey/registration.ts` using the passkey registration table.
- [x] Rewrite relay bootstrap registration events in `client/src/core/TatchiPasskey/faucets/createAccountRelayServer.ts`.
- [x] Add missing ECDSA post-registration provisioning events.
- [x] Delete old registration rollback events that emit `RegistrationPhase.REGISTRATION_ERROR`; replace with one terminal `registration.failed` plus `data.rollback`.
- [x] Thread `flowId` through the whole registration flow.
- [x] Ensure passkey creation show/hide events are emitted even when the flow fails or is cancelled.
- [x] Add Email OTP registration `onEvent` support to public SDK methods and wallet iframe payloads:
  - [x] `requestEmailOtpEnrollmentChallenge`
  - [x] `exchangeGoogleEmailOtpSession` when `accountMode === 'register'`
  - [x] `enrollEmailOtp`
  - [x] `enrollAndLoginWithEmailOtpEcdsaCapability`
- [x] Decide whether Email OTP registration phases need to move into `SigningEngine`.
  - Decision for this pass: keep the public `TatchiPasskey` wrappers as the event boundary. They now emit v2 registration events around Email OTP challenge, session exchange, OTP verify, signer enrollment, ECDSA provisioning, completion, and failure. Move lower-level events into `SigningEngine` later only if product needs granular worker/session progress.

### Phase 4. Unlock emitters

- [x] Rename event semantics from login to unlock in SDK event types and emitted phases.
- [x] Rewrite `client/src/core/TatchiPasskey/login.ts` events using the unlock table.
- [x] Split current overloaded `webauthn-assertion` events into account lookup, passkey challenge, passkey prompt, app-session exchange, and warm-session events.
- [x] Add Email OTP unlock `onEvent` support to:
  - [x] `requestEmailOtpChallenge`
  - [x] `loginWithEmailOtpEcdsaCapability`
- [x] Emit Email OTP challenge, input, verify, and ECDSA capability readiness events.
  - Completed at the public SDK wrapper boundary, including terminal failure events. Add deeper `SigningEngine` emissions only if product wants more granular worker/session progress.
- [x] Emit distinct Ed25519 and ECDSA warm-session readiness events during threshold warm-up.
- [x] Ensure unlock terminal events are emitted for success and failure.
- [x] Add explicit unlock cancellation handling where passkey/OTP cancellation can be distinguished from other failures.
  - Passkey WebAuthn cancellation and Email OTP cancellation-shaped errors now emit `unlock.cancelled` with `status: 'cancelled'` instead of `unlock.failed`.

### Phase 5. Signing emitters

- [x] Rewrite NEAR transaction signing events to use the signing table without old `ActionPhase`.
  - Completed for NEAR transaction signing, delegate signing, NEP-413 signing, public NEAR wrappers, router forwarding, and the device-link add-key signing bridge.
- [x] Rewrite Tempo signing events in `client/src/core/signingEngine/orchestration/tempo/tempoSigningFlow.ts`.
- [x] Rewrite EVM signing events in `client/src/core/signingEngine/orchestration/evm/evmSigningFlow.ts`.
- [x] Rewrite EVM family lifecycle events in `client/src/core/signingEngine/api/evmSigning.ts`:
  - [x] Email OTP challenge events
  - [x] threshold-session reconnect events
  - [x] presign refill scheduled events
  - [x] commit queue and commit start events
  - [x] nonce broadcast/reconcile/finalize/dropped/replaced events
- [x] Rename first-send account-readiness progress events.
- [x] Add dedicated post-finalization app-state sync events instead of reusing receipt-finalized copy.
- [x] Ensure warm-session authorization emits `signing.auth.warm_session.claimed`.
- [x] Ensure passkey and Email OTP authorization emit auth-method-specific events.
- [x] Ensure threshold signing emits presign and commit events only for threshold ECDSA signing; do not emit them for WebAuthn P-256 or non-threshold paths.
- [x] Emit `signing.transaction.signed` as the signing terminal event before broadcast-related events.
- [x] Emit `signing.completed` only after the requested operation is actually complete for that API shape.

### Phase 6. Link-device emitters

- [x] Rewrite device2 QR generation and polling events in `client/src/core/TatchiPasskey/near/linkDevice.ts`.
- [x] Rewrite device1 scanned-QR authorization and registration events in `client/src/core/TatchiPasskey/scanDevice.ts`.
- [x] Rewrite device-link authorization/add-key progress emitted from `client/src/core/rpcClients/near/rpcCalls.ts`.
- [x] Represent signer persistence and ECDSA owner-management work as link-device events only when user-visible; otherwise attach details to parent event `data`.
- [x] Replace nested legacy registration/login error phases with `link_device.failed` and structured `error.code`.
- [x] Ensure both QR-display and QR-scanner roles emit `link_device.completed` or `link_device.failed`.
- [x] Ensure long-running QR polling remains sticky in wallet iframe mode without relying on old phase names.

### Phase 7. Email recovery emitters

- [x] Rewrite start-email-recovery events in `client/src/core/TatchiPasskey/near/emailRecovery.ts`.
- [x] Rewrite finalize-email-recovery events in the same file.
- [x] Split current overloaded polling phases into email approval waiting and recovery-key polling.
  - Current implementation emits explicit `email_recovery.email.link.waiting` while the user confirms from email, then `email_recovery.recovery_key.poll.*` while finalize waits for the recovered key on-chain. A separate relay-backed email approval polling phase should only be added if that path becomes app-visible.
- [x] Emit `email_recovery.resumed.pending` when resuming pending state.
- [x] Ensure pending-store status changes line up with v2 event phase names.
  - Finalize now advances pending records through `awaiting-add-key`, `finalizing`, `complete`, or `error` alongside the v2 resume, poll, finalize, completion, and failure events.
- [x] Ensure start and finalize paths both emit terminal success/failure/cancellation events.
- [x] Ensure wallet iframe overlay hides while the user is expected to leave the app and click the email recovery link.

### Phase 8. React and app-facing callback updates

- [x] Update React context wrappers to accept v2 flow events.
- [x] Update PasskeyAuthMenu event handling so copy comes from canonical event messages where appropriate.
  - `useTatchiWithSdkFlow` now streams v2 `event.message` copy and treats cancelled terminal events as flow completion errors so the menu waiting state clears.
- [x] Update UI assumptions about numeric `step` so they use the new per-flow ordinal, not old global action/login/registration steps.
  - React and demo scans no longer find app-facing `event.step` branching; examples now branch by v2 phases/statuses.
- [x] Update toast examples and app demos to branch by `event.flow`, `event.phase`, and `event.status`.
  - Updated Passkey login/register/sync and NEAR signing demo to use v2 registration, unlock, account-sync, and signing events.
- [x] Update QR/link-device React consumers to branch by `flow === 'link_device'` and `LinkDeviceEventPhase`.
- [x] Update email recovery consumers to branch by `flow === 'email_recovery'` and `EmailRecoveryFlowEventPhase`.
- [x] Update public SDK exports from `client/src/index.ts` and `client/src/react/index.ts`.

### Phase 9. Tests

- [x] Replace tests that assert old public `phase` strings or old numeric `step` values.
  - Updated wallet-iframe progress bus tests to `defaultOverlayIntentResolver` metadata assertions, chain signer completion assertions to v2 signing phases, wallet-iframe harness fixtures to v2 `WalletFlowEvent` payloads, and e2e public callback assertions to v2 registration/unlock/signing phases. Remaining old strings are Rust/WASM worker-internal progress names, not app-facing `onEvent` phases.
- [x] Add tests proving each new phase enum maps to the expected per-flow `step`.
  - Completed in `tests/unit/walletFlowEvent.signing.unit.test.ts`; every v2 phase enum is checked against `WALLET_FLOW_EVENT_STEPS`, and each `STEP_N_*` member must map to `N`.
- [x] Add unit tests for event constructors and message copy.
  - Completed for global step/message map coverage plus signing, account-sync, and terminal cancellation constructors. Existing flow-sequence tests cover additional registration, unlock, link-device, and email-recovery emitted copy.
- [x] Add wallet iframe progress bus tests proving overlay behavior follows `interaction.overlay`.
- [x] Add router tests proving new EVM threshold phases are forwarded to app `onEvent`.
  - Completed in `tests/wallet-iframe/router.signingProgressForwarding.test.ts`, including a wrong-flow progress frame that must be ignored by the signing callback.
- [x] Add passkey registration flow-sequence tests.
  - Completed in `tests/unit/tatchiPasskey.passkeyIframe.flowEvents.unit.test.ts`, covering the wallet-iframe `onEvent` passkey registration sequence and overlay metadata.
- [x] Add Email OTP registration flow-sequence tests.
  - Completed in `tests/unit/tatchiPasskey.emailOtpIframe.unit.test.ts`, including wallet iframe payload checks that `onEvent` is not serialized.
- [x] Add passkey unlock flow-sequence tests.
  - Completed in `tests/unit/tatchiPasskey.passkeyIframe.flowEvents.unit.test.ts`, covering the wallet-iframe `onEvent` passkey unlock sequence and overlay metadata.
- [x] Add Email OTP unlock flow-sequence tests.
  - Completed for challenge, session unlock, per-operation unlock, and enroll-and-login registration event boundaries.
- [x] Add Email OTP registration/unlock failure-path tests.
  - Completed for iframe unlock ERROR responses and app-origin Email OTP enrollment secret rejection.
- [x] Add EVM threshold signing flow-sequence tests covering:
  - [x] warm-session path
  - [x] passkey reauth path
  - [x] Email OTP per-operation path
  - [x] threshold session reconnect
  - [x] commit queue
  - [x] nonce broadcast accepted
  - [x] nonce broadcast rejected and reconcile
  - Covered EVM-family execute success, broadcast rejection, and nonce reconciliation paths in `tests/unit/tatchiPasskey.chainSigners.unit.test.ts`; covered low-level EVM passkey reauth and Email OTP per-operation authorization sequences in `tests/unit/tempo.signingAuthMode.unit.test.ts`; covered real capability readiness reconnect events in `tests/unit/evmSigning.thresholdReconnectEvents.unit.test.ts`.
- [x] Add focused NEAR Ed25519 signer-prep flow-sequence coverage.
  - Completed in `tests/unit/thresholdEd25519.immediateSignFallback.unit.test.ts`, covering confirmation approval, signer preparation, authentication completion, commit start, transaction signed, and completion ordering on the cached warm-session path.
- [x] Add link-device flow-sequence tests for QR-display and QR-scanner roles.
  - Completed in `tests/unit/linkDevice.flowEvents.unit.test.ts` for the device2 QR-display sequence and scanner-role invalid-QR terminal failure sequence.
- [x] Add email recovery flow-sequence tests for start, resume, finalize, and failure.
  - Completed in `tests/unit/deviceRecoveryDomain.emailRecovery.unit.test.ts`, including start, pending resume, finalize success, timeout failure, cancellation, and pending-store status transitions.
- [x] Add cancellation tests for registration, unlock, signing, link-device, and email recovery.
  - Completed with router behavioral cancellation coverage for registration, unlock, and signing in `tests/wallet-iframe/router.cancellationProgress.test.ts`; link-device cancellation in `tests/unit/linkDevice.flowEvents.unit.test.ts`; email-recovery cancellation in `tests/unit/deviceRecoveryDomain.emailRecovery.unit.test.ts`; and terminal constructor coverage for registration, unlock, signing, link-device, and email recovery in `tests/unit/walletFlowEvent.signing.unit.test.ts`.
- [x] Add account-sync v2 constructor coverage.

### Phase 10. Cleanup and deletion

- [x] Delete old phase enums and old step-specific interfaces.
  - Deleted migrated `RegistrationPhase`/`RegistrationSSEEvent`, `LoginPhase`/`LoginSSEvent`, `ActionPhase`/`ActionSSEEvent`, `DeviceLinkingPhase`/`DeviceLinkingSSEEvent`, and `EmailRecoveryPhase`/`EmailRecoverySSEEvent` definitions and public exports.
- [x] Delete old wallet iframe phase heuristics and any fallback mappings.
- [x] Delete stale tests that only verify legacy event names.
  - Removed the old `progressBus.defaultPhaseHeuristics` test and replaced wallet-iframe fixtures that still depended on legacy phase strings.
- [x] Remove code comments that describe the old SSEvent system.
  - Updated wallet-iframe and signing comments that still named old phase strings; remaining old string references are historical notes in this plan or private worker protocol names.
- [x] Search for `SSEvent`, `ActionPhase`, `LoginPhase`, `RegistrationPhase`, `DeviceLinkingPhase`, and `EmailRecoveryPhase`; all should be gone or intentionally renamed to v2 concepts.
  - Completed for `client/src` and unit tests; remaining matches are historical notes in this plan document only.
- [x] Search for `STEP_`; remaining matches should be new v2 phase enum members only.
  - Completed for `client/src` and tests; remaining matches are v2 phase enum members, v2 consumers, v2-focused tests, or docs examples.
- [x] Update docs and examples that mention old event phases.
  - Updated wallet-iframe docs and test guidance to describe v2 `interaction.overlay` instead of phase heuristics.
- [x] Normalize the private `UserConfirmProgressEvent` bridge to v2 status words before it maps into `WalletFlowEvent`.
  - Replaced the private `progress`/`success`/`error` vocabulary with `running`/`succeeded`/`failed` in touch-confirm progress payloads, the host parser, and the EVM/Tempo signing mappers.
- [x] Run the full affected test suite and a wallet iframe EVM threshold signing e2e.
  - `pnpm -C tests exec playwright test ./unit/walletFlowEvent.signing.unit.test.ts ./unit/tatchiPasskey.passkeyIframe.flowEvents.unit.test.ts ./unit/tatchiPasskey.emailOtpIframe.unit.test.ts ./unit/linkDevice.flowEvents.unit.test.ts ./unit/progressBus.overlayIntentResolver.test.ts ./wallet-iframe/router.signingProgressForwarding.test.ts ./e2e/worker_events.test.ts --reporter=line` passes with 16 passed and 1 skipped. The skipped case is the existing managed-registration-transport branch in `worker_events.test.ts`.
  - `pnpm -C tests exec playwright test ./unit/walletFlowEvent.signing.unit.test.ts ./unit/deviceRecoveryDomain.emailRecovery.unit.test.ts --reporter=line` passes with 9 passed after the email recovery polling phase rename.

## Next Implementation Queue

No current implementation tasks remain for the registration, unlock, signing, link-device, email-recovery, wallet-iframe, React, and example event overhaul.

Future-only follow-up: add distinct relay-backed email approval polling phases if that polling path becomes app-visible. The current SDK path already emits `email_recovery.email.link.waiting` for user email approval and `email_recovery.recovery_key.poll.*` for finalize-time recovery-key polling.

## Acceptance criteria

1. Apps receive all registration, unlock, signing, link-device, and email-recovery events through the same v2 event envelope.
2. EVM threshold signing no longer emits stale action phases or hidden ad hoc events.
3. Wallet iframe overlay visibility is driven by explicit event interaction metadata.
4. Email OTP registration and unlock have event coverage comparable to passkey flows.
5. Link-device progress covers both QR-display and QR-scanner roles without nested registration/login error phases.
6. Email recovery progress distinguishes start, pending resume, email approval waiting, recovery-key polling, and finalization.
7. Event messages are centralized enough to review as product copy.
8. Old event enums, legacy step meanings, and duplicate compatibility paths are removed.
9. New events retain clear per-flow numeric ordering through `step` and `STEP_N_*` phase enum members.
10. Tests assert event flow sequences for the main passkey, Email OTP, warm-session, EVM threshold signing, link-device, and email recovery paths.
