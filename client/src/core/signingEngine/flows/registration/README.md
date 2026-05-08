# registration

## Owns

Passkey registration-time account lifecycle persistence, credential confirmation,
and registration-facing WebAuthn credential helpers used by the public facade.

## May Import

`interfaces/*`, shared SDK account/profile types, `walletAuth/*` WebAuthn
primitives, and `workerManager/*` validation contracts.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, `session/*`, `threshold/*`, `nonce/*`, or
unrelated signing operation folders.

## Entrypoints

- `public.ts`: `SigningEngine` registration-facing facade entrypoint
- `accountLifecycle.ts`: persisted account/profile/authenticator lifecycle
- `session.ts`: registration confirmation prompt and WebAuthn challenge helpers

## Stage Order

1. Persist or read account/profile state in `accountLifecycle.ts`.
2. Request registration credential confirmation in `session.ts`.
3. Collect serialized authentication credentials in `session.ts`.
4. Expose the public registration facade in `public.ts`.
