# Refactor 93: Intended Behaviour E2E Contract

Date created: 2026-07-02

Status: planning.

Source of truth: [Intended Behaviours](./intended-behaviours.md)

## Problem

The test suite is large, but the regressions keep landing in lifecycle seams:
registration to signing, unlock to signing, step-up to first signing operation,
and key export. Many current tests validate units, guards, or mocked demo
surfaces. They do not run the real wallet iframe, IndexedDB, D1 Router API,
workers, Durable Objects, and signing/session/budget code as one system.

The missing gate is a small e2e contract suite that exercises the behaviours
users actually depend on.

## Rule

Do not add more broad unit coverage for these behaviours. Add one small e2e
contract suite and keep it mandatory for refactors touching auth, registration,
warm sessions, signing lanes, budget, key export, D1/DO state, or wallet iframe
routing.

## Scope

Run real SDK/runtime code:

- wallet iframe router
- IndexedDB persistence
- D1 Router API local backend
- Durable Object session/budget state
- Ed25519 and ECDSA workers
- registration, unlock, step-up, signing, and export flows

Stub only external services:

- Google identity response
- Email OTP delivery/readback
- NEAR RPC/faucet result
- Tempo/Arc RPC result

Do not mock SDK internals, signing-engine lane selection, budget coordinator,
wallet iframe messages, worker material persistence, or Router API responses.

## Contract Matrix

Each row must verify Ed25519 and ECDSA behaviour.

| Flow | Required checks |
| --- | --- |
| Passkey registration -> tx signing | registration succeeds; NEAR, Tempo, and Arc/EVM sign without another prompt while budget remains; budget decreases correctly |
| Passkey unlock -> tx signing | unlock warms NEAR and configured ECDSA targets; NEAR, Tempo, and Arc/EVM sign without another prompt while budget remains |
| Passkey step-up signing | after budget exhaustion, step-up uses passkey; the first post-step-up NEAR and ECDSA transaction succeeds |
| Passkey key export | Ed25519 and ECDSA export require fresh export authorization and succeed after it |
| Email OTP registration -> tx signing | registration sends one OTP; wallet-name reroll does not send another OTP; NEAR, Tempo, and Arc/EVM sign without another OTP while budget remains |
| Email OTP unlock -> tx signing | unlock sends one wallet-unlock OTP; unlock warms NEAR and configured ECDSA targets; NEAR, Tempo, and Arc/EVM sign without another OTP while budget remains |
| Email OTP step-up signing | after budget exhaustion, step-up uses Email OTP; the first post-step-up NEAR and ECDSA transaction succeeds |
| Email OTP key export | Ed25519 and ECDSA export require fresh export OTP and succeed after it |

Cross-row assertions:

- Passkey flows never call Email OTP verification.
- Email OTP flows never call WebAuthn/passkey PRF or passkey sealed restore.
- Registration and default unlock produce equivalent lane inventory for the same
  wallet, auth method, and configured chains.
- ECDSA checks are chain-target exact for Tempo and Arc/EVM.
- `budget_unknown` must fail the test. It is not an acceptable intermediate
  state in a successful signing path.
- The first transaction after step-up must succeed. A failure followed by a
  successful retry is a test failure.

## Test Layout

Add a dedicated directory:

```text
tests/e2e/intended-behaviours/
  passkey.registration.contract.test.ts
  passkey.unlock.contract.test.ts
  email-otp.registration.contract.test.ts
  email-otp.unlock.contract.test.ts
  harness.ts
```

Add one command:

```json
"test:intended": "pnpm -C tests test:intended"
```

The tests should be optimized for local refactor use:

- assume `pnpm router` and `pnpm site` can already be running during local
  debugging
- provide one CI mode that starts the required local services
- fail fast on the first contract violation
- emit a compact lifecycle trace on failure

## Implementation Order

1. Build the harness around the current manually tested local D1 setup.
2. Add Passkey registration and unlock contract tests.
3. Add Email OTP registration and unlock contract tests.
4. Add key export checks for both auth methods.
5. Add step-up exhaustion checks for both curves and auth methods.
6. Retire or demote overlapping mocked e2e tests that no longer catch unique
   behaviour.

## Exit Criteria

- A refactor that breaks any listed intended behaviour fails `test:intended`.
- Manual testing is used for UX polish, not for discovering lifecycle contract
  regressions.
- The suite contains a few lifecycle tests instead of another large set of unit
  tests.
