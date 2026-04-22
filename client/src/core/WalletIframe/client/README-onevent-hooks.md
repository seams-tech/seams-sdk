# Wallet Iframe onEvent Bridging

This document explains how app-provided `onEvent` callbacks are bridged across the wallet iframe boundary. The iframe protocol uses a serializable `PROGRESS` envelope whose payload is a public v2 `WalletFlowEvent`.

This is the app-facing progress path. Lower-level signer worker progress is private unless it is explicitly mapped into one of these public wallet flow events.

## How It Works

1. Parent -> Child (RPC without functions)

- Parent sends a `PM_*` envelope. Functions in request payloads/options are stripped before crossing the iframe boundary.
- The parent registers the original app callback locally as a request-scoped `onProgress` handler.

```ts
// Parent app code
await walletRouter.registerPasskey({
  nearAccountId,
  options: {
    onEvent: (ev) => {
      // ev is RegistrationFlowEvent
    },
  },
});
```

2. Child emits PROGRESS from its `onEvent`

- The wallet host wraps `TatchiPasskey` calls and translates `onEvent(ev)` into:
  `post({ type: 'PROGRESS', requestId, payload: ev })`.
- Payloads use the v2 wallet flow event envelope:
  `RegistrationFlowEvent | UnlockFlowEvent | SigningFlowEvent | LinkDeviceFlowEvent | EmailRecoveryFlowEvent | AccountSyncFlowEvent`.
- Email OTP registration/unlock/capability calls owned by the iframe are also wrapped with this bridge, so Email OTP worker progress mapped inside the iframe reaches the parent before the final result.

3. Parent bridges PROGRESS -> onEvent

- For each request, the client registers an `onProgress` handler created via `wrapOnEvent(onEvent, isXxxFlowEvent)`.
- When a `PROGRESS` message arrives, the client:
  - correlates by `requestId`
  - routes through a small `OnEventsProgressBus`
  - invokes the stored `onProgress`, which safely narrows by `event.version` and `event.flow`, then forwards to your `onEvent`.

4. Completion

- Child posts `PM_RESULT` (success) or `ERROR` (failure). The pending entry resolves/rejects and, unless `sticky` is set, progress delivery is unregistered.

## Message Shapes (child -> parent)

- PROGRESS: `{ type: 'PROGRESS', requestId: string, payload: WalletFlowEvent }`
- PM_RESULT: `{ type: 'PM_RESULT', requestId: string, payload: { ok: true, result: unknown } }`
- ERROR: `{ type: 'ERROR', requestId: string, payload: { code: string, message: string, details?: unknown } }`

Ordering is FIFO per `requestId`.

## Where The Bridging Lives (code)

- Host posts PROGRESS from `onEvent`:
  - `src/core/WalletIframe/host/wallet-iframe-handlers.ts`
    - `withProgress()` wraps host-side SDK calls and posts `PROGRESS`.
    - Covered flows include registration, unlock, Email OTP registration/unlock/capability calls, signing, link device, email recovery, and account sync.
  - `src/core/WalletIframe/host/index.ts`
    - Owns the host `postProgress()` send path.
- Client receives PROGRESS and invokes app `onEvent` via wrapper:
  - `src/core/WalletIframe/client/router.ts`
    - `post()` registers `{ onProgress }` per request
    - `onPortMessage()` dispatches `PROGRESS` to `OnEventsProgressBus`
    - `wrapOnEvent(onEvent, isXxxFlowEvent)` narrows `ProgressPayload` before calling `onEvent`
- Message types:
  - `src/core/WalletIframe/shared/messages.ts` (`ProgressPayload`, PROGRESS/PM_RESULT/ERROR envelopes, `options.sticky`)
- Overlay behavior:
  - `src/core/WalletIframe/client/progress/on-events-progress-bus.ts`
    - reads `event.interaction.overlay` only; there are no phase-string show/hide rules.

## Event Layers

There are two progress layers:

1. Public app callbacks receive v2 `WalletFlowEvent` payloads.
2. Signer workers may emit private worker progress. Worker progress is mapped into public events only at deliberate flow boundaries.

Current worker behavior:

- NEAR signer worker progress remains private to the signer orchestration.
- Email OTP worker progress is mapped into public registration/unlock events for direct SDK and iframe-owned Email OTP flows.
- EVM and Tempo signer workers emit private RPC progress frames for transport visibility. These are not forwarded directly to app `onEvent` callbacks.

## Notes

- No functions ever cross the boundary; app callbacks run in the parent only.
- Timeouts are refreshed on each `PROGRESS` received.
- Type guards (`isRegistrationFlowEvent`, `isUnlockFlowEvent`, `isSigningFlowEvent`, etc.) ensure your `onEvent` only receives the expected v2 flow shape.
- `event.step` is a per-flow ordinal derived from `event.phase`.
- `event.message` is canonical user-facing copy from `sdkSentEvents.ts` unless a flow deliberately overrides it for context.
- Use `sticky` when a flow should keep receiving status after the main result (e.g., certain device-linking screens).
