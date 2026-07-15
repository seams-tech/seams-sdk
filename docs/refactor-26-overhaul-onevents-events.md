# onEvent Event Overhaul

Status: complete for the current implementation scope.

The SDK public `onEvent` surface now uses one versioned `WalletFlowEvent` model for user-facing wallet progress. Events are flow-native, keep per-flow numeric ordering, and use explicit interaction metadata for wallet-iframe overlay behavior.

The source of truth is `client/src/core/types/sdkSentEvents.ts`.

## Event Envelope

Every public progress callback receives a v2 event:

```ts
type WalletFlowEventBase = {
  version: 2;
  flow:
    | 'registration'
    | 'unlock'
    | 'signing'
    | 'link_device'
    | 'email_recovery'
    | 'account_sync'
    | 'key_export';
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
      | 'email_recovery_link'
      | 'key_export_viewer';
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

1. Public phases are grouped by flow-specific enums with numbered member names, for example `SigningEventPhase.STEP_07_AUTHENTICATION_COMPLETE`.
2. `step` is derived from the phase-to-step map. Emitters do not hand-roll step numbers.
3. Step numbers are per-flow ordinals. Branches can share a step when they are mutually exclusive.
4. `message` is short user-facing copy. Technical details belong in `data`.
5. Overlay behavior is explicit via `interaction.overlay`. The iframe progress bus does not infer visibility from phase strings.
6. Events are coarse enough for app UX, toasts, debugging, and support. Internal worker microsteps stay private unless they represent real user-visible latency.
7. Failures and cancellations are terminal events with `step: 0`.

## Registration

Flow: `registration`

Passkey and Email OTP registration share the same event family. Step 4 branches by auth method.

| Step | Phase | Message |
| ---: | --- | --- |
| 1 | `registration.started` | `Starting registration` |
| 2 | `registration.account.preflight.started` | `Checking account details` |
| 2 | `registration.account.preflight.succeeded` | `Account details ready` |
| 3 | `registration.session.exchange.started` | `Checking registration session` |
| 3 | `registration.session.exchange.succeeded` | `Registration session ready` |
| 4 | `registration.auth.passkey.create.started` | `Create your passkey` |
| 4 | `registration.auth.passkey.create.succeeded` | `Passkey created` |
| 4 | `registration.otp.challenge.started` | `Sending registration email code` |
| 4 | `registration.otp.challenge.sent` | `Registration email code sent` |
| 4 | `registration.otp.input.required` | `Enter the registration code` |
| 4 | `registration.otp.verify.started` | `Verifying registration code` |
| 4 | `registration.otp.verify.succeeded` | `Registration email verified` |
| 5 | `registration.signer.ed25519.prepare.started` | `Preparing NEAR signer` |
| 5 | `registration.signer.ed25519.prepare.succeeded` | `NEAR signer ready` |
| 5 | `registration.signer.ed25519.provision.started` | `Preparing NEAR signer` |
| 5 | `registration.signer.ed25519.provision.succeeded` | `NEAR signer ready` |
| 5 | `registration.signer.ed25519.provision.skipped` | `NEAR signer setup skipped` |
| 6 | `registration.relay.bootstrap.started` | `Creating wallet account` |
| 6 | `registration.relay.bootstrap.succeeded` | `Wallet account created` |
| 7 | `registration.account.verify.started` | `Verifying wallet account` |
| 7 | `registration.account.verify.succeeded` | `Wallet account verified` |
| 8 | `registration.storage.persist.started` | `Saving wallet metadata` |
| 8 | `registration.storage.persist.succeeded` | `Wallet metadata saved` |
| 9 | `registration.signer.email_otp.enroll.started` | `Securing Email OTP registration` |
| 9 | `registration.signer.email_otp.enroll.succeeded` | `Email OTP registration secured` |
| 10 | `registration.signer.ecdsa.provision.started` | `Preparing EVM signing session` |
| 10 | `registration.signer.ecdsa.provision.succeeded` | `EVM signing session ready` |
| 10 | `registration.signer.ecdsa.provision.skipped` | `EVM signer setup skipped` |
| 10 | `registration.signer.ecdsa.bootstrap.started` | `Preparing EVM signer` |
| 10 | `registration.signer.ecdsa.bootstrap.succeeded` | `EVM signer ready` |
| 11 | `registration.completed` | `Registration complete` |
| 0 | `registration.failed` | `Registration failed` |
| 0 | `registration.cancelled` | `Registration cancelled` |

Overlay behavior:

- Passkey creation uses `interaction.kind: 'passkey_create'`.
- Email OTP input uses `interaction.kind: 'otp_input'`.
- Terminal failed/cancelled events hide the overlay by default.

## Unlock

Flow: `unlock`

The user-facing flow is wallet unlock, even when implementation files still have login-oriented names.

| Step | Phase | Message |
| ---: | --- | --- |
| 1 | `unlock.started` | `Unlocking wallet` |
| 2 | `unlock.account.lookup.started` | `Finding wallet account` |
| 2 | `unlock.account.lookup.succeeded` | `Wallet account found` |
| 3 | `unlock.auth.passkey.challenge.started` | `Preparing passkey check` |
| 3 | `unlock.auth.passkey.prompt.started` | `Confirm with passkey` |
| 3 | `unlock.auth.passkey.prompt.succeeded` | `Passkey confirmed` |
| 3 | `unlock.auth.email_otp.challenge.started` | `Sending email code` |
| 3 | `unlock.auth.email_otp.challenge.sent` | `Email code sent` |
| 3 | `unlock.auth.email_otp.input.required` | `Enter the email code` |
| 3 | `unlock.auth.email_otp.verify.started` | `Verifying email code` |
| 3 | `unlock.auth.email_otp.verify.succeeded` | `Email verified` |
| 4 | `unlock.app_session.exchange.started` | `Creating app session` |
| 4 | `unlock.app_session.exchange.succeeded` | `App session ready` |
| 4 | `unlock.app_session.exchange.skipped` | `App session skipped` |
| 5 | `unlock.signing_session.warmup.started` | `Preparing transaction signing` |
| 5 | `unlock.signing_session.ed25519.ready` | `NEAR signing session ready` |
| 5 | `unlock.signing_session.ecdsa.ready` | `EVM signing session ready` |
| 6 | `unlock.session.ready` | `Wallet session ready` |
| 7 | `unlock.completed` | `Wallet unlocked` |
| 0 | `unlock.failed` | `Wallet unlock failed` |
| 0 | `unlock.cancelled` | `Wallet unlock cancelled` |

Email OTP unlock gets real-time progress from the Email OTP worker in both direct SDK and wallet-iframe-owned flows. Worker progress is mapped into these public unlock events before reaching app callbacks.

## Signing

Flow: `signing`

This flow covers NEAR, Tempo, EVM, NEP-413, delegate actions, send-only flows, and broadcast lifecycle. Not every phase appears in every signing path.

| Step | Phase | Message |
| ---: | --- | --- |
| 1 | `signing.started` | `Preparing transaction` |
| 2 | `signing.request.prepared` | `Transaction ready for review` |
| 3 | `signing.nonce.reserve.started` | `Reserving nonce` |
| 3 | `signing.nonce.reserve.succeeded` | `Nonce reserved` |
| 4 | `signing.account.readiness.started` | `Checking account setup` |
| 4 | `signing.account.readiness.succeeded` | `Account setup verified` |
| 4 | `signing.account.readiness.skipped` | `Account setup check skipped` |
| 5 | `signing.confirmation.displayed` | `Review transaction` |
| 5 | `signing.confirmation.approved` | `Transaction approved` |
| 5 | `signing.confirmation.cancelled` | `Transaction rejected` |
| 6 | `signing.auth.warm_session.claimed` | `Signing session authorized` |
| 6 | `signing.auth.passkey.prompt.started` | `Confirm with passkey` |
| 6 | `signing.auth.passkey.prompt.succeeded` | `Passkey confirmed` |
| 6 | `signing.auth.email_otp.challenge.started` | `Sending email code` |
| 6 | `signing.auth.email_otp.challenge.sent` | `Email code sent` |
| 6 | `signing.auth.email_otp.input.required` | `Enter the email code` |
| 6 | `signing.auth.email_otp.verify.started` | `Verifying email code` |
| 6 | `signing.auth.email_otp.verify.succeeded` | `Email verified` |
| 7 | `signing.authentication.complete` | `Authentication complete` |
| 8 | `signing.signer.prepare.started` | `Preparing secure signer` |
| 8 | `signing.signer.prepare.succeeded` | `Secure signer ready` |
| 8 | `signing.presign.refill.scheduled` | `Preparing future signatures` |
| 9 | `signing.threshold_session.reconnect.started` | `Loading secure signer` |
| 9 | `signing.threshold_session.reconnect.succeeded` | `Secure signer loaded` |
| 10 | `signing.commit.queued` | `Waiting to sign` |
| 10 | `signing.commit.started` | `Signing transaction` |
| 10 | `signing.commit.succeeded` | `Transaction signature ready` |
| 11 | `signing.transaction.signed` | `Transaction signed` |
| 12 | `signing.broadcast.started` | `Broadcasting transaction` |
| 12 | `signing.broadcast.accepted` | `Transaction submitted` |
| 12 | `signing.broadcast.rejected` | `Transaction broadcast failed` |
| 13 | `signing.nonce.reconcile.started` | `Checking nonce state` |
| 13 | `signing.nonce.reconcile.succeeded` | `Nonce state updated` |
| 13 | `signing.receipt.finalized` | `Transaction finalized` |
| 13 | `signing.receipt.reverted` | `Transaction reverted` |
| 13 | `signing.transaction.dropped` | `Transaction dropped` |
| 13 | `signing.transaction.replaced` | `Transaction replaced` |
| 13 | `signing.broadcast.skipped` | `Broadcast skipped` |
| 14 | `signing.app_state.sync.started` | `Refreshing app state` |
| 14 | `signing.app_state.sync.succeeded` | `App state refreshed` |
| 15 | `signing.completed` | `Transaction complete` |
| 0 | `signing.failed` | `Transaction signing failed` |
| 0 | `signing.cancelled` | `Transaction signing cancelled` |

Toast guidance:

- Show/update toasts for coarse latency-heavy states: review, auth, signer preparation, threshold reconnect, commit, transaction signed, broadcast, receipt, app-state sync, completed, failed, and cancelled.
- Do not expose raw eth/tempo worker operations such as transaction hash computation or transaction encoding as public toast states.

## Link Device

Flow: `link_device`

The same event family covers the QR-display device and the QR-scanner device. Role-specific details are carried in `data` when needed.
For the QR-display role, `link_device.qr.displayed` emits `interaction.overlay: 'hide'` because the QR screen is rendered by the app. Scanner authorization and new-device passkey phases emit `overlay: 'show'` only when the wallet iframe must capture activation.

| Step | Phase | Message |
| ---: | --- | --- |
| 1 | `link_device.qr.prepare.started` | `Preparing device link` |
| 1 | `link_device.qr.displayed` | `Scan the QR code` |
| 2 | `link_device.qr.scan.started` | `Scanning QR code` |
| 2 | `link_device.qr.scan.succeeded` | `QR code scanned` |
| 3 | `link_device.authorization.started` | `Authorize device link` |
| 3 | `link_device.authorization.succeeded` | `Device link authorized` |
| 4 | `link_device.request.submitted` | `Submitting device link` |
| 5 | `link_device.request.detected` | `Device link detected` |
| 6 | `link_device.new_device.register.started` | `Registering new device` |
| 6 | `link_device.new_device.register.succeeded` | `New device registered` |
| 7 | `link_device.auto_unlock.started` | `Unlocking new device` |
| 7 | `link_device.auto_unlock.succeeded` | `New device unlocked` |
| 8 | `link_device.completed` | `Device linked` |
| 0 | `link_device.failed` | `Device link failed` |
| 0 | `link_device.cancelled` | `Device link cancelled` |

Implementation note: signer persistence and ECDSA owner-management details are only public link-device events when user-visible. Otherwise, they stay in `data` on the parent event.

## Account Sync

Flow: `account_sync`

| Step | Phase | Message |
| ---: | --- | --- |
| 1 | `account_sync.started` | `Starting account sync` |
| 2 | `account_sync.auth.passkey.prompt.started` | `Confirm with passkey` |
| 2 | `account_sync.auth.passkey.prompt.succeeded` | `Passkey confirmed` |
| 3 | `account_sync.relay.verify.started` | `Verifying account access` |
| 3 | `account_sync.relay.verify.succeeded` | `Account access verified` |
| 4 | `account_sync.authenticator.saved` | `Passkey saved locally` |
| 5 | `account_sync.threshold_session.ready` | `Signing session ready` |
| 6 | `account_sync.completed` | `Account synced` |
| 0 | `account_sync.failed` | `Account sync failed` |
| 0 | `account_sync.cancelled` | `Account sync cancelled` |

## Wallet Iframe Progress Bridge

`ProgressPayload` in `client/src/core/WalletIframe/shared/messages.ts` is `WalletFlowEvent`.

Child-to-parent progress messages use:

```ts
{ type: 'PROGRESS', requestId, payload: event }
```

The wallet host wraps SDK calls with `withProgress()`, translating host-side `onEvent(event)` into `PROGRESS`. The router correlates by `requestId`, feeds the event into `OnEventsProgressBus`, then forwards the narrowed event to the app callback.

The progress bus reads only `event.interaction.overlay`:

- `show`: expand the iframe overlay for active user interaction.
- `hide`: hide once no in-flight request still requires the overlay.
- `none`: update stats and leave overlay visibility unchanged.

No functions cross the iframe boundary. App callbacks run only in the parent.

## Worker Progress Boundary

There are two event layers:

1. Public `WalletFlowEvent` progress for app callbacks and toasts.
2. Private worker progress for worker transport and worker-owned latency reporting.

Current private worker progress:

- NEAR signer worker uses `NearWorkerProgressEvent`.
- Email OTP worker sends lightweight progress codes for OTP verification, Email OTP enrollment, and ECDSA bootstrap. Direct SDK and iframe-owned Email OTP paths map those codes into public registration/unlock events before apps see them.
- EVM and Tempo signer workers emit private RPC progress frames shaped as `{ phase, status, message, data }`. These remain internal and are not mapped directly into public signing events.

Recommendation: keep eth/tempo worker frames private unless a worker operation becomes user-visible latency. Public signing toasts should stay coarse: review, auth, signer/session readiness, threshold commit, transaction signed, broadcast, finalization, app-state sync, completion, failure, and cancellation.

## Key Export

Flow: `key_export`

Key export now has its own typed progress family. Export viewer lifecycle is controlled by `key_export.viewer.opened` and `key_export.viewer.closed` progress events rather than broad wallet-origin window messages.

| Step | Phase | Message |
| ---: | --- | --- |
| 1 | `key_export.started` | `Preparing key export` |
| 2 | `key_export.auth.passkey.prompt.started` | `Confirm with passkey` |
| 2 | `key_export.auth.passkey.prompt.succeeded` | `Passkey confirmed` |
| 3 | `key_export.material.prepare.started` | `Preparing key material` |
| 3 | `key_export.material.prepare.succeeded` | `Key material ready` |
| 4 | `key_export.viewer.opened` | `Review private key` |
| 5 | `key_export.viewer.closed` | `Key export closed` |
| 6 | `key_export.completed` | `Key export complete` |
| 0 | `key_export.failed` | `Key export failed` |
| 0 | `key_export.cancelled` | `Key export cancelled` |

Overlay behavior:

- Passkey authentication uses `interaction.kind: 'passkey_assert'` and `interaction.overlay: 'show'`.
- Key material preparation keeps `interaction.overlay: 'none'` unless the iframe must stay interactive for a visible wallet-owned view.
- Viewer opened uses a new interaction kind such as `key_export_viewer` with `interaction.overlay: 'show'`.
- Viewer closed, completed, failed, and cancelled use `interaction.overlay: 'hide'`.
- Generic `WALLET_UI_CLOSED` messages must not directly hide the wallet iframe.

Implementation status:

- [x] Add `key_export` to `WalletFlow` and add `KeyExportEventPhase`, `KeyExportFlowEvent`, step mapping, default messages, and runtime type guard coverage in `client/src/core/types/sdkSentEvents.ts`.
- [x] Add `key_export_viewer` as the explicit key-export interaction kind.
- [x] Add key export hook types for app-facing callbacks without reusing signing/account-sync event families for export-specific UI lifecycle.
- [x] Emit key export progress from `PM_EXPORT_KEYPAIR_UI` and `PM_EXPORT_THRESHOLD_ED25519_SEED_FROM_HSS_REPORT_UI` through `postProgress(requestId, event)`.
- [x] Replace export viewer parent `window.postMessage` overlay-control messages with wallet-iframe-local lifecycle callbacks that the request handler maps into key export progress events.
- [x] Remove router export-specific `WALLET_EXPORT_VIEWER_OPENED`, `EXPORT_KEYPAIR_CANCELLED`, `WALLET_UI_CLOSED`, and `overlayState.exportViewerOpen` handling.
- [x] Separate sticky progress-subscription lifetime from overlay stickiness. Export can keep receiving progress after `PM_RESULT`, while overlay visibility is still controlled by progress demand. `PM_RESULT` clears only preflight demand, not demand created by `key_export.viewer.opened`.
- [x] Keep `WALLET_UI_OPENED`/`WALLET_UI_CLOSED` outside router visibility handling.
- [x] Add regression tests proving a stale generic `WALLET_UI_CLOSED` cannot hide an open key export viewer because router visibility is driven only by `interaction.overlay`.
- [x] Add progress bus/router integration coverage for `key_export.viewer.opened -> show` and `key_export.viewer.closed -> hide`.
- [x] Update `client/src/core/WalletIframe/client/README-onevent-hooks.md` so the docs name key export as a progress-driven wallet iframe flow.

## Completed Implementation Checklist

- [x] Replaced public step-based event families with v2 flow-native events.
- [x] Kept `STEP_N_*` enum member names and per-flow `step` values.
- [x] Centralized phase-to-step and default message mappings in `sdkSentEvents.ts`.
- [x] Migrated registration, unlock, signing, link-device, email-recovery, and account-sync callbacks.
- [x] Added Email OTP registration and unlock progress, including iframe-owned Email OTP worker progress forwarding.
- [x] Reworked wallet iframe progress routing to forward `WalletFlowEvent` payloads.
- [x] Replaced phase-name overlay inference with explicit `interaction.overlay`.
- [x] Kept worker progress private unless mapped intentionally into public flow events.
- [x] Added typed key export progress events and moved export viewer overlay lifecycle onto progress events.
- [x] Added focused tests for flow event ordering, iframe forwarding, progress bus overlay behavior, Email OTP iframe progress, and worker transport progress.

## Future-Only Follow-Up

Add more public phases only when a real user-visible latency gap appears. For now the public event surface is intentionally coarse, and eth/tempo worker micro-progress remains internal.
