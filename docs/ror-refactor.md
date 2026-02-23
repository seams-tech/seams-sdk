# ROR Refactor Plan: Server-Owned Related Origins

Status: Planned  
Severity: High (auth compatibility + platform behavior)  
Last updated: 2026-02-23

## 1. Direct Answer

Yes, we still need `/.well-known/webauthn` when cross-origin apps use a wallet RP ID.

Example:

1. Wallet iframe origin: `wallet.tatchi.xyz` (RP ID domain).
2. Embedding app: `app1.com`.
3. If WebAuthn is performed from `app1.com` with RP ID `wallet.tatchi.xyz`, then `https://app1.com` must be in `https://wallet.tatchi.xyz/.well-known/webauthn`.

Conclusion: keep the endpoint, but move source-of-truth to relay/server (Postgres-backed), not contract.

## 2. Goals

1. Remove contract-coupled ROR lookup from core auth service.
2. Keep `/.well-known/webauthn` behavior correct and explicit.
3. Make ROR origin management server-owned (Postgres + optional static config for local/dev).
4. Preserve strict sanitization/normalization semantics for allowed origins.
5. Ship as a clean breaking change with no legacy alias surface.

## 3. Non-Goals

1. No compatibility aliases (`webAuthnContractId`, `WEBAUTHN_CONTRACT_ID`, or contract fallback paths).
2. No wildcard origin support.
3. No change to WebAuthn cryptographic verification flow in this refactor.

## 4. Current State

1. `/.well-known/webauthn` exists in both express/cloudflare routers.
2. ROR origin lookup currently depends on `AuthService.getRorOrigins(...)`.
3. `AuthService` still carries ROR contract concerns (`rorContractId` + NEAR view call path).
4. ROR config in examples/docs is still presented as contract account ID.

## 5. Target Architecture

## 5.1 Route-Level ROR Provider

Introduce a dedicated provider interface owned by router layer:

```ts
export interface RorOriginsProvider {
  getAllowedOrigins(input: { rpId: string; host?: string }): Promise<string[]>;
}
```

Routers call provider directly for `/.well-known/webauthn`; `AuthService` is no longer in this path.

## 5.2 Provider Implementations

1. `StaticRorOriginsProvider`:
   - For local/dev/testing.
   - Configured by code/env; returns normalized set.
2. `PostgresRorOriginsProvider`:
   - Canonical production path.
   - Reads per-RP-ID allowlist from Postgres.

## 5.3 Data Model (Postgres)

Add table (name suggestion: `webauthn_related_origins`):

1. `id` (uuid pk)
2. `rp_id` (text, indexed)
3. `origin` (text, unique with `rp_id`)
4. `is_active` (boolean default true)
5. `created_at` / `updated_at` (timestamptz)

Indexes:

1. `(rp_id, is_active)`
2. unique `(rp_id, origin)`

## 5.4 Router Behavior

`GET /.well-known/webauthn`:

1. Resolve RP ID for the serving host (explicit config mapping, not inferred from contract).
2. Fetch origins from provider.
3. Sanitize/dedupe/validate absolute origins.
4. Return `{ origins }` with short cache headers.

## 6. Breaking API/Config Changes

1. Remove ROR contract config from `AuthService`:
   - Remove `rorContractId` from `AuthServiceConfig` and `AuthServiceConfigInput`.
   - Remove `getRorContractId()` and `getRorOrigins(...)` from `AuthService`.
2. Add router-level ROR options:
   - `rorProvider` (required for well-known route when enabled).
   - `rpId` or `rpIdByHost` mapping (required to prevent ambiguous host behavior).
3. Replace env docs/examples from contract ID config to provider-backed config.

## 7. Implementation Plan

## Phase 0: Contract Surface Freeze

- [ ] Confirm no remaining `contractId` / `webAuthnContractId` / `WEBAUTHN_CONTRACT_ID` symbols.
- [ ] Add CI grep guard to block reintroduction.

## Phase 1: Provider Abstractions

- [ ] Add `RorOriginsProvider` interface + normalization helper module.
- [ ] Add `StaticRorOriginsProvider`.
- [ ] Add unit tests for normalization and invalid origin rejection.

Suggested files:

- `server/src/router/ror/provider.ts` (new)
- `server/src/router/ror/staticProvider.ts` (new)
- `tests/unit/server.rorProvider.unit.test.ts` (new)

## Phase 2: Router Wiring

- [ ] Extend express/cloudflare router options with `rorProvider` and RP-ID config.
- [ ] Update `/.well-known/webauthn` handlers to use provider only.
- [ ] Keep cache-control behavior unchanged unless explicitly revised.

Suggested files:

- `server/src/router/relay.ts`
- `server/src/router/express/routes/wellKnown.ts`
- `server/src/router/cloudflare/routes/wellKnown.ts`

## Phase 3: Postgres Provider

- [ ] Add Postgres read-only provider implementation.
- [ ] Add query + mapping tests (including inactive row filtering).
- [ ] Wire provider into relay-server example when `POSTGRES_URL` exists.

Suggested files:

- `server/src/router/ror/postgresProvider.ts` (new)
- `server/src/core/storage/postgres/*` (reuse existing DB utilities where possible)
- `examples/relay-server/src/index.ts`

## Phase 4: Remove AuthService ROR Responsibilities

- [ ] Remove `getRorOrigins(...)` and `getRorContractId()` from `AuthService`.
- [ ] Remove `rorContractId` from config types and initialization.
- [ ] Update health payload to no longer expose contract-derived ROR config.

Suggested files:

- `server/src/core/AuthService.ts`
- `server/src/core/types.ts`
- `server/src/core/config.ts`
- `server/src/router/express/routes/health.ts`
- `server/src/router/cloudflare/routes/health.ts`

## Phase 5: Examples, Docs, and Tests

- [ ] Update server/worker examples to configure provider-backed ROR.
- [ ] Rewrite docs that still describe on-chain WebAuthn contract as ROR source-of-truth.
- [ ] Update relayer tests to inject mock providers instead of stubbing `AuthService.getRorOrigins`.

## 8. Testing Plan

1. Unit:
   - Origin normalization and dedupe.
   - RP-ID/host resolution logic.
   - Postgres provider query filtering and ordering.
2. Integration:
   - Express `/.well-known/webauthn` with static provider.
   - Cloudflare `/.well-known/webauthn` with static provider.
   - Postgres-backed happy path.
3. Regression:
   - Existing health/ready routes.
   - ROR endpoint cache header behavior.

## 9. Rollout

1. Land provider abstraction + router wiring first.
2. Switch examples/tests to provider path.
3. Remove `AuthService` ROR contract surface in same PR series.
4. Update migration notes in `sdk/README.md` and `server/src/README.md`.

## 10. Risks and Mitigations

1. Misconfigured RP-ID/host mapping can break passkeys.
   - Mitigation: fail-fast startup validation for required ROR config.
2. Origin list drift across environments.
   - Mitigation: single Postgres source-of-truth + admin workflow.
3. Overly permissive origin entries.
   - Mitigation: strict parser, no wildcard support, explicit allowlist review.

## 11. Acceptance Criteria

1. `/.well-known/webauthn` works without contract dependency.
2. No `AuthService` config or methods reference ROR contract lookup.
3. All tests for relayer well-known and ROR origin behavior pass.
4. Docs/examples describe server-owned ROR management only.
