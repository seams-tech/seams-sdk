# TouchConfirm Runtime

## Purpose

`touchConfirm` is the confirmation boundary between signer workers and wallet-origin main-thread UI.

It owns:

- the worker/main-thread handshake for `UserConfirmRequest`
- main-thread routing of prompts to typed confirmation flows
- SecureConfirm worker lifecycle plus PRF.first warm-session cache helpers

## Current Structure

```text
client/src/core/signingEngine/touchConfirm/
├── README.md
├── index.ts                     # barrel export
├── types.ts                     # public touchConfirm ports/types
├── TouchConfirmManager.ts       # concrete manager implementation
├── awaitUserConfirmation.ts     # worker-side handshake bridge (awaitUserConfirmationV2)
├── displayFormat/
│   ├── nearTx.ts
│   ├── evmTx.ts
│   └── tempoTx.ts
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
├── shared/
│   ├── confirmTypes.ts
│   ├── confirmCommon.ts
│   ├── displayModel.ts
│   └── forbiddenMainThreadSecrets.typecheck.ts
└── ui/
    ├── confirm-ui.ts
    ├── confirm-ui-types.ts
    ├── registry.ts
    ├── lit-events.ts
    └── lit-components/*
```

## Runtime Sequence

1. Worker calls `awaitUserConfirmationV2(...)` from `awaitUserConfirmation.ts`.
2. `awaitUserConfirmationV2` posts `PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD` and waits for `USER_PASSKEY_CONFIRM_RESPONSE`.
3. `TouchConfirmManager` intercepts that prompt and calls `handlers/handlePromptFromWorker.ts`.
4. `handlePromptFromWorker` validates request, resolves effective config, and dispatches to flow handlers (`signing`, `registration`, `localOnly`).
5. Flow sends decision back to worker using `sendConfirmResponse(...)`.
6. Worker resolves `awaitUserConfirmationV2` and returns the decision payload.
7. `TouchConfirmManager.requestUserConfirmation(...)` receives that worker response and resolves the original main-thread request.

## Message Contract

- Worker -> main thread: `PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD` with `UserConfirmRequest`
- Main thread -> worker: `USER_PASSKEY_CONFIRM_RESPONSE` with `SecureConfirmDecision`
- Progress: `USER_PASSKEY_CONFIRM_PROGRESS`

Main-thread envelopes must never include forbidden secrets (`prfOutput`, `wrapKeySeed`, `wrapKeySalt`).
