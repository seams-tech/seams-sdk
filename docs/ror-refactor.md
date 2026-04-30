# ROR Refactor Plan: Remove Contract-Coupled Origins

Status: Ready for implementation  
Severity: High (auth compatibility + breaking config/API)  
Last updated: 2026-02-24

## 1. Direct Answer

Yes, we can remove `ROR_CONTRACT_ID` and contract-based ROR lookup.

Yes, it is a breaking change.

`/.well-known/webauthn` must remain. Only the data source changes.

## 2. What Breaks

Removing legacy ROR contract code breaks these surfaces unless migrated in the same PR series:

1. `AuthService` constructor call sites that still pass `rorContractId`.
2. Router handlers that call `AuthService.getRorOrigins()` / `getRorContractId()`.
3. Cloudflare envs using `ROR_CONTRACT_ID` / `ROR_METHOD`.
4. Tests stubbing `getRorOrigins` on fake `AuthService`.
5. Dev plugin/docs flow that reads chain via `VITE_ROR_CONTRACT_ID`.
6. Examples and READMEs describing contract-based `get_allowed_origins`.

If we delete `rorContractId` without router-provider replacement, `/.well-known/webauthn` behavior will regress.

## 3. Scope and Decisions

1. Keep `GET /.well-known/webauthn`.
2. Move ROR source-of-truth to server-owned providers.
3. Remove all contract-coupled symbols in one cleanup:
   `ROR_CONTRACT_ID`, `VITE_ROR_CONTRACT_ID`, `ROR_METHOD`, `VITE_ROR_METHOD`,
   `rorContractId`, `getRorOrigins`, `getRorContractId`.
4. No compatibility aliases.
5. No wildcard origins.
6. Breaking changes are intentional.

## 4. Target Architecture

### 4.1 Router-owned ROR provider

```ts
export interface RorOriginsProvider {
  getAllowedOrigins(input: { rpId: string; host?: string }): Promise<string[]>;
}
```

### 4.2 Router configuration

Routers must resolve RP ID explicitly and query provider directly:

```ts
type RelayRouterRorOptions = {
  provider: RorOriginsProvider;
  rpId?: string;
  rpIdByHost?: Record<string, string>;
};
```

Rules:

1. Exactly one RP ID strategy must be configured: `rpId` or `rpIdByHost`.
2. Startup/config validation must fail fast on ambiguous or missing ROR config.

### 4.3 Provider implementations

1. `StaticRorOriginsProvider` for local/dev/tests.
2. `PostgresRorOriginsProvider` for production.

### 4.4 Postgres model

Table: `webauthn_related_origins`

1. `id` uuid primary key
2. `rp_id` text not null
3. `origin` text not null
4. `is_active` boolean not null default true
5. `created_at` timestamptz not null default now()
6. `updated_at` timestamptz not null default now()

Indexes:

1. `index (rp_id, is_active)`
2. `unique (rp_id, origin)`

## 5. Breaking API/Config Contract

### 5.1 Removed

1. `AuthServiceConfig.rorContractId`
2. `AuthServiceConfigInput.rorContractId`
3. `AuthService.getRorOrigins(...)`
4. `AuthService.getRorContractId()`
5. Cloudflare router env fields:
   `ROR_CONTRACT_ID`, `ROR_METHOD`

### 5.2 Added

1. Router option block for ROR provider + RP ID mapping.
2. Provider interfaces and implementations under `server/src/router/ror/*`.

### 5.3 Runtime expectations

1. `/.well-known/webauthn` returns sanitized/deduped origins from provider.
2. Cache policy remains `max-age=60, stale-while-revalidate=600` unless explicitly changed.

## 6. Implementation Plan

### Phase 0: Guardrails

- [ ] Add CI grep guard blocking reintroduction of removed symbols.
- [ ] Add CI grep guard blocking docs claims that ROR source-of-truth is on-chain.

### Phase 1: Provider primitives

- [x] Add `RorOriginsProvider` interface.
- [x] Add origin normalization/validation helper shared by providers and routes.
- [x] Add `StaticRorOriginsProvider`.
- [ ] Add unit tests for normalization and invalid origin rejection.

Suggested files:

- `server/src/router/ror/provider.ts` (new)
- `server/src/router/ror/normalize.ts` (new)
- `server/src/router/ror/staticProvider.ts` (new)
- `tests/unit/server.rorProvider.unit.test.ts` (new)

### Phase 2: Router wiring

- [x] Extend `RelayRouterOptions` with ROR options.
- [x] Wire express and cloudflare `/.well-known/webauthn` to provider path only.
- [x] Add RP ID resolution helper (`rpId` vs `rpIdByHost`) with fail-fast validation.
- [x] Keep route response format unchanged: `{ origins }`.

Suggested files:

- `server/src/router/relay.ts`
- `server/src/router/express/createRelayRouter.ts`
- `server/src/router/cloudflare/createCloudflareRouter.ts`
- `server/src/router/express/routes/wellKnown.ts`
- `server/src/router/cloudflare/routes/wellKnown.ts`

### Phase 3: Postgres provider

- [ ] Implement `PostgresRorOriginsProvider`.
- [ ] Add query tests (active-only filtering, ordering, dedupe).
- [ ] Add migration/DDL for `webauthn_related_origins`.

Suggested files:

- `server/src/router/ror/postgresProvider.ts` (new)
- `server/src/core/storage/postgres/*` (reuse existing db utilities)
- `tests/unit/server.rorPostgresProvider.unit.test.ts` (new)

### Phase 4: Remove `AuthService` ROR legacy

- [x] Remove config fields and methods tied to ROR contract lookup.
- [x] Remove constructor logging of `rorContractId`.
- [x] Remove health payload contract references.
- [x] Delete obsolete `tests/relayer/rorOrigins.test.ts`.

Suggested files:

- `server/src/core/types.ts`
- `server/src/core/config.ts`
- `server/src/core/AuthService.ts`
- `server/src/router/express/routes/health.ts`
- `server/src/router/cloudflare/routes/health.ts`

### Phase 5: Examples and runtime env cleanup

- [x] Replace `ROR_CONTRACT_ID` in relay examples with provider-backed config.
- [x] Replace cloudflare worker env contract fields with provider-backed config.
- [x] Update seams-site env/vite config to stop forwarding `VITE_ROR_CONTRACT_ID`.

Suggested files:

- `examples/relay-server/.env.example`
- `examples/relay-server/src/index.ts`
- `examples/relay-cloudflare-worker/src/worker.ts`
- `examples/relay-cloudflare-worker/wrangler.toml`
- `examples/seams-site/env.example`
- `examples/seams-site/vite.config.ts`
- `examples/seams-site/vite-env.d.ts`

### Phase 6: Tests + docs + plugin cleanup

- [x] Update router tests to inject a mock ROR provider instead of stubbing `AuthService.getRorOrigins`.
- [x] Remove legacy ROR contract references from server/docs/examples.
- [x] Remove plugin/docs references to dynamic chain ROR fetch in dev.
- [x] Keep docs aligned with server-owned ROR management only.

Candidate files:

- `tests/relayer/helpers.ts`
- `tests/relayer/health-wellknown.test.ts`
- `tests/e2e/thresholdEd25519.*.test.ts` (constructor arg cleanup)
- `server/src/README.md`
- `client/src/core/signingEngine/signers/webauthn/fallbacks/README.md`
- `examples/seams-docs/src/concepts/passkey-scope.md`
- `examples/seams-docs/src/concepts/passkey-scope.md`
- `examples/seams-docs/src/getting-started/installation.md`
- `examples/seams-docs/src/getting-started/installation.md`

## 7. Migration Notes (Consumers)

Before:

```ts
const service = new AuthService({
  relayerAccount,
  relayerPrivateKey,
  rorContractId: process.env.ROR_CONTRACT_ID,
});
app.use('/', createRelayRouter(service));
```

After:

```ts
const service = new AuthService({
  relayerAccount,
  relayerPrivateKey,
});

app.use(
  '/',
  createRelayRouter(service, {
    ror: {
      provider: new StaticRorOriginsProvider({
        byRpId: { 'wallet.example.com': ['https://app1.com'] },
      }),
      rpIdByHost: { 'wallet.example.com': 'wallet.example.com' },
    },
  }),
);
```

## 8. Test Plan

1. Unit:
   origin parser, normalization, dedupe, invalid inputs.
2. Integration:
   express/cloudflare `/.well-known/webauthn` with static provider.
3. Persistence:
   postgres provider filtering and RP-ID scoping.
4. Regression:
   `healthz`, `readyz`, existing auth/session/threshold routes.
5. Negative:
   missing `ror` config when route is enabled should fail fast.

## 9. Acceptance Criteria

1. `/.well-known/webauthn` works without any contract lookup.
2. No code references removed legacy symbols.
3. No docs/examples instruct contract-based ROR allowlist management.
4. CI guard blocks reintroduction.
5. Router tests pass with provider injection model.

## 10. Rollout

1. Land Phases 0-2 together to keep well-known behavior intact.
2. Land Phase 3 before production migration.
3. Land Phases 4-6 in same release train; no legacy aliases.
4. Publish migration notes in `server/src/README.md` and `sdk/README.md`.
