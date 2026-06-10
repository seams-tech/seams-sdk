# UiConfirm Runtime

## Owns

`uiConfirm` is the concrete browser confirmation runtime between signer workers and wallet-origin main-thread UI.

- the worker/main-thread handshake for `UserConfirmRequest`
- main-thread routing of prompts to typed confirmation flows
- UserConfirm worker lifecycle plus PRF.first warm-session cache helpers
- confirmation modal/drawer/export viewer rendering
- Lit confirmation components and `TxDisplayModel` rendering

## May Import

`webauthnAuth/*`, `chains/*`, `stepUpConfirmation/*`, `interfaces/*`,
`nonce/*`, `session/*`, `threshold/*`, and `workerManager/*`.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, `flows/*`, retired folders, or broad internal
barrels.

## Entrypoints

- `UiConfirmManager.ts`
- `types.ts`
- `awaitUserConfirmation.ts`
- `warmSessionUiConfirm.ts`

## Current Structure

```text
client/src/core/signingEngine/uiConfirm/
├── README.md
├── types.ts                     # public uiConfirm ports/types
├── UiConfirmManager.ts          # concrete manager implementation
├── awaitUserConfirmation.ts     # worker-side handshake bridge (awaitUserConfirmationV2)
├── handlers/
│   ├── handlePromptFromWorker.ts
│   ├── determineConfirmationConfig.ts
│   ├── flowOrchestrator.ts
│   └── flows/
│       ├── signing.ts
│       ├── registration.ts
│       ├── localOnly.ts
│       ├── requestRegistrationCredentialConfirmation.ts
│       └── adapters/
│           ├── adapters.ts
│           └── request.ts
└── ui/
    ├── confirm-ui.ts
    ├── confirm-ui-types.ts
    ├── registry.ts
    ├── lit-events.ts
    └── lit-components/*
```

Transaction display formatting now lives under `client/src/core/signingEngine/chains/*`.
The shared display model lives in `client/src/core/signingEngine/interfaces/display.ts`.

## Runtime Sequence

1. Worker calls `awaitUserConfirmationV2(...)` from `awaitUserConfirmation.ts`.
2. `awaitUserConfirmationV2` posts `PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD` and waits for `USER_PASSKEY_CONFIRM_RESPONSE`.
3. The uiConfirm bridge/runtime intercepts that prompt and calls `handlers/handlePromptFromWorker.ts`.
4. `handlePromptFromWorker` validates request, resolves effective config, and dispatches to flow handlers (`signing`, `registration`, `localOnly`).
5. Flow sends decision back to worker using `sendConfirmResponse(...)`.
6. Worker resolves `awaitUserConfirmationV2` and returns the decision payload.
7. The bridge/runtime `requestUserConfirmation(...)` path receives that worker response and resolves the original main-thread request.

## Message Contract

- Worker -> main thread: `PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD` with `UserConfirmRequest`
- Main thread -> worker: `USER_PASSKEY_CONFIRM_RESPONSE` with `UserConfirmDecision`
- Progress: `USER_PASSKEY_CONFIRM_PROGRESS`

Main-thread envelopes must never include forbidden secrets (`prfOutput`, `wrapKeySeed`, `wrapKeySalt`).
