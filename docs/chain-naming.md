# Chain Naming Cleanup Plan

Last updated: 2026-02-26

## 1. Problem

The codebase currently mixes two different meanings:

1. `evm` as a protocol family (used by signing/orchestration APIs).
2. `arc` as both a concrete network brand and an internal family marker in config.

This creates drift and confusion:

1. Some code treats `arc` as the EVM family (`TatchiChainFamily = 'near' | 'tempo' | 'arc'`).
2. Other code correctly treats `evm` as the family (`chain: 'evm'` in signing types).
3. This blocks clean expansion to additional EVM networks (Ethereum, Sepolia, etc.).

## 2. Decision

Adopt a strict 3-level chain identity model across the codebase.

1. `family`: execution/signing family.
2. `network`: concrete deployment network.
3. `chainId`: numeric on-chain domain.

Canonical rules:

1. Use `evm` for family-level APIs, enums, function names, modules, and orchestration.
2. Use concrete network names for config and runtime scoping (`arc-*`, `ethereum-*`, etc.).
3. Use `chainId` for protocol-level uniqueness where network name is not enough.
4. No legacy alias path where `arc` remains a family name.

## 3. Naming Contract

Use this contract as the source of truth.

```ts
// family-level (generic)
type ChainFamily = 'near' | 'tempo' | 'evm';

// concrete networks (extensible)
type NearNetwork = 'near-mainnet' | 'near-testnet';
type TempoNetwork = 'tempo-mainnet' | 'tempo-testnet';
type EvmNetwork = 'arc-mainnet' | 'arc-testnet' | 'ethereum-mainnet' | 'ethereum-sepolia';

type ChainNetwork = NearNetwork | TempoNetwork | EvmNetwork;
```

Keying rules:

1. Nonce/session/account state must key by concrete `network` and `chainId`, not family alone.
2. Family selectors are only for shared behavior selection (`evm` vs `tempo` vs `near`).

## 4. Breaking-Change Policy

1. Remove `arc` as a family type everywhere.
2. Do not keep compatibility unions like `'arc' | 'evm'` for family concepts.
3. Do not add adapter shims that preserve old naming semantics.
4. Clean up old names in place as each area is migrated.

## 5. Implementation Plan

### Phase 1: Core Type System and Config Canonicalization

Scope:

1. `client/src/core/types/tatchi.ts`
2. `client/src/core/config/chains.ts`
3. `client/src/core/config/defaultConfigs.ts`
4. Any helper types importing `TatchiChainFamily` or `TatchiArcChainNetwork`

Changes:

1. Replace `TatchiChainFamily = 'near' | 'tempo' | 'arc'` with `TatchiChainFamily = 'near' | 'tempo' | 'evm'`.
2. Replace `TatchiArcChainNetwork` with `TatchiEvmChainNetwork` that includes `arc-*` and new EVM networks.
3. Make `chainFamilyFromNetwork('arc-*') === 'evm'`.
4. Add helper predicates to avoid string-prefix duplication:
   1. `isNearChainNetwork`
   2. `isTempoChainNetwork`
   3. `isEvmChainNetwork`
5. Replace `resolvePrimaryExplorerUrl(..., 'arc')` call sites with `resolvePrimaryExplorerUrl(..., 'evm')`.
6. Update config normalization branch in `defaultConfigs.ts` from `family === 'arc'` to `family === 'evm'`.

Definition of done:

1. No type in core config uses `arc` as a family value.
2. All family derivation logic maps concrete EVM networks to `evm`.

### Phase 2: Runtime Surface and Module Naming Consistency

Scope:

1. `client/src/core/signingEngine/*`
2. `client/src/core/TatchiPasskey/*`
3. `client/src/core/WalletIframe/*`

Changes:

1. Keep `evm` naming in runtime APIs (`chain: 'evm'`, `EvmSigner`, `EvmAdapter`, `evmSigningFlow`).
2. Remove any runtime code paths that assume `arc` is the only EVM network.
3. Ensure runtime resolver inputs use concrete network identity when selecting RPC/explorer.
4. Keep brand-specific naming only where explicitly Arc-specific behavior is required.

Definition of done:

1. Runtime chain/family logic is `near|tempo|evm` only.
2. Arc-specific behavior is isolated to concrete network branches, not family branches.

### Phase 3: Nonce Manager and State-Key Scoping

Scope:

1. `client/src/core/rpcClients/evm/nonceManager.ts` (new)
2. Signing bootstrap/orchestration wiring
3. Related tests

Changes:

1. Key nonce state by concrete network and chain id:
   1. `family`
   2. `network`
   3. `chainId`
   4. `sender`
   5. `nonceKey?` (tempo)
2. Prohibit family-only keying for EVM nonce state.
3. Add cross-network collision tests (same sender on Arc vs Ethereum networks).

Definition of done:

1. Same sender cannot collide nonce reservations across distinct EVM networks.
2. No key schema relies on `arc` as family.

### Phase 4: Public Docs, Examples, and Env Naming Hygiene

Scope:

1. `docs/*`
2. `examples/tatchi-site/*`
3. `examples/tatchi-docs/*`

Changes:

1. Use `evm` for generic capability docs and API examples.
2. Use `Arc` only for Arc-specific examples, env vars, and labels.
3. Add at least one non-Arc EVM network example in docs (e.g., Ethereum Sepolia) to prevent regressions.
4. Update wording that currently implies `evm == arc`.

Definition of done:

1. Docs clearly separate family (`evm`) from network (`arc-*`, `ethereum-*`).
2. Examples no longer teach Arc-only assumptions as generic EVM behavior.

### Phase 5: Test and Guardrail Hardening

Scope:

1. `tests/unit/*`
2. `tests/e2e/*`
3. Optional static guard scripts

Changes:

1. Update tests that assert old family semantics (`'arc'` family expectations).
2. Add unit tests for `chainFamilyFromNetwork` covering all EVM networks.
3. Add snapshot/assertion tests for explorer resolution using `family: 'evm'`.
4. Add compile-time guardrails (type-level or test-level) to prevent reintroducing `'arc'` as a family.
5. Add grep-based CI guard for disallowed patterns in family types/switches.

Definition of done:

1. CI fails if `arc` is reintroduced as a family discriminator.
2. CI passes with multi-network EVM fixtures.

## 6. TODO Checklist (Execution Tracker)

### Phase 1: Core Type System and Config Canonicalization

- [x] Replace all family discriminators from `'arc'` to `'evm'`.
      Files: `client/src/core/types/tatchi.ts`, `client/src/core/config/chains.ts`, `client/src/core/config/defaultConfigs.ts`, `client/src/core/rpcClients/evm/nonceManager.ts`, `client/src/core/signingEngine/bootstrap/managerAssembly.ts`.
- [x] Replace `TatchiArc*` type names with `TatchiEvm*` and remove old symbol exports/imports.
      Files: `client/src/core/types/tatchi.ts`, `client/src/core/config/defaultConfigs.ts`.
- [x] Add chain-network predicates (`isNearChainNetwork`, `isTempoChainNetwork`, `isEvmChainNetwork`) and migrate prefix checks.
      Files: `client/src/core/config/chains.ts`, `client/src/core/config/defaultConfigs.ts`, `client/src/core/rpcClients/evm/nonceManager.ts`.
- [x] Extend EVM network union with at least one non-Arc network fixture (e.g., Sepolia).
      Files: `client/src/core/types/tatchi.ts`, `client/src/core/config/chains.ts`, `client/src/core/config/defaultConfigs.ts`.

### Phase 2: Runtime Surface and Module Naming Consistency

- [x] Remove runtime assumptions that EVM explorer/RPC is single-family-only.
      Files: `client/src/core/signingEngine/bootstrap/managerAssembly.ts`, `client/src/core/signingEngine/interfaces/runtime.ts`, `client/src/core/signingEngine/workerManager/index.ts`.
- [x] Thread network-aware explorer resolution through touch-confirm UI props/models.
      Files: `client/src/core/signingEngine/touchConfirm/types.ts`, `client/src/core/signingEngine/touchConfirm/ui/confirm-ui-types.ts`, `client/src/core/signingEngine/touchConfirm/ui/confirm-ui.ts`, `client/src/core/signingEngine/touchConfirm/ui/lit-components/TxTree/index.ts`, `client/src/core/signingEngine/touchConfirm/ui/lit-components/IframeTxConfirmer/tx-confirm-content.ts`, `client/src/core/signingEngine/touchConfirm/ui/lit-components/IframeTxConfirmer/tx-confirmer-wrapper.ts`, `client/src/core/signingEngine/touchConfirm/ui/lit-components/IframeTxConfirmer/viewer-modal.ts`, `client/src/core/signingEngine/touchConfirm/ui/lit-components/IframeTxConfirmer/viewer-drawer.ts`.

### Phase 3: Nonce Manager and State-Key Scoping

- [x] Finalize EVM nonce manager family/network semantics and remove `arc` family dependency.
      Files: `client/src/core/rpcClients/evm/nonceManager.ts`.
- [x] Wire nonce manager into orchestration dependencies and signing flows.
      Files: `client/src/core/signingEngine/bootstrap/managerAssembly.ts`, `client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts`, `client/src/core/signingEngine/orchestration/evm/evmSigningFlow.ts`, `client/src/core/signingEngine/orchestration/tempo/tempoSigningFlow.ts`, `client/src/core/signingEngine/orchestration/executeSigningIntent.ts`.
- [x] Add collision tests for same sender across multiple EVM networks/chainIds.
      Files: `tests/unit/evmNonceManager.unit.test.ts`, `tests/unit/signingPipeline.unified.unit.test.ts`, `tests/e2e/thresholdEcdsa.tempoSigning.test.ts`.

### Phase 4: Public Docs, Examples, and Env Naming Hygiene

- [x] Update architecture/docs to explicitly separate family (`evm`) vs network (`arc-*`, `ethereum-*`).
      Files: `docs/architecture-current.md`, `docs/ecdsa_threshold_signing.md`, `docs/multichain-nonce-manager.md`.
- [x] Add non-Arc EVM example flow and remove Arc-only generic wording.
      Files: `examples/tatchi-site/src/docs/getting-started/next-steps.md`, `examples/tatchi-docs/src/getting-started/next-steps.md`.
- [x] Keep Arc-specific env/config names only where the behavior is Arc-specific.
      Files: `examples/tatchi-site/src/config.ts`, `examples/tatchi-site/vite-env.d.ts`, `examples/tatchi-site/env.example`, `examples/tatchi-site/env.iphone.example`.

### Phase 5: Test and Guardrail Hardening

- [x] Update tests that encode old family assumptions and add `chainFamilyFromNetwork` coverage for all EVM networks.
      Files: `tests/unit/*`, `tests/e2e/docs.thresholdRegisterAndSigning.integration.test.ts`, `tests/e2e/docs.thresholdSigningActions.smoke.test.ts`.
- [x] Add CI guardrails that fail on reintroducing `arc` as a family discriminator.
      Files: `tests/scripts/check-chain-family-naming.mjs` (new), `tests/package.json`, `.github/workflows/ci.yml`.

## 7. Compiled File Update List

Use this list as the fast path so work can run in parallel by phase.

### P0 Must-Touch (Current Known Blockers)

1. `client/src/core/types/tatchi.ts`
2. `client/src/core/config/chains.ts`
3. `client/src/core/config/defaultConfigs.ts`
4. `client/src/core/rpcClients/evm/nonceManager.ts`
5. `client/src/core/signingEngine/bootstrap/managerAssembly.ts`

### P1 Runtime Explorer/Network Threading

1. `client/src/core/signingEngine/interfaces/runtime.ts`
2. `client/src/core/signingEngine/workerManager/index.ts`
3. `client/src/core/signingEngine/touchConfirm/types.ts`
4. `client/src/core/signingEngine/touchConfirm/ui/confirm-ui-types.ts`
5. `client/src/core/signingEngine/touchConfirm/ui/confirm-ui.ts`
6. `client/src/core/signingEngine/touchConfirm/ui/lit-components/TxTree/index.ts`
7. `client/src/core/signingEngine/touchConfirm/ui/lit-components/IframeTxConfirmer/tx-confirm-content.ts`
8. `client/src/core/signingEngine/touchConfirm/ui/lit-components/IframeTxConfirmer/tx-confirmer-wrapper.ts`
9. `client/src/core/signingEngine/touchConfirm/ui/lit-components/IframeTxConfirmer/viewer-modal.ts`
10. `client/src/core/signingEngine/touchConfirm/ui/lit-components/IframeTxConfirmer/viewer-drawer.ts`

### P2 Nonce Orchestration and State Keying

1. `client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts`
2. `client/src/core/signingEngine/orchestration/evm/evmSigningFlow.ts`
3. `client/src/core/signingEngine/orchestration/tempo/tempoSigningFlow.ts`
4. `client/src/core/signingEngine/orchestration/executeSigningIntent.ts`
5. `tests/unit/evmNonceManager.unit.test.ts`
6. `tests/unit/signingPipeline.unified.unit.test.ts`
7. `tests/e2e/thresholdEcdsa.tempoSigning.test.ts`

### P3 Docs and Examples

1. `docs/architecture-current.md`
2. `docs/ecdsa_threshold_signing.md`
3. `docs/multichain-nonce-manager.md`
4. `examples/tatchi-site/src/config.ts`
5. `examples/tatchi-site/src/docs/getting-started/next-steps.md`
6. `examples/tatchi-docs/src/getting-started/next-steps.md`
7. `examples/tatchi-site/vite-env.d.ts`
8. `examples/tatchi-site/env.example`
9. `examples/tatchi-site/env.iphone.example`

### P4 Guardrails and CI

1. `tests/scripts/check-chain-family-naming.mjs` (new)
2. `tests/package.json`
3. `.github/workflows/ci.yml`

## 8. Migration Sequence (PR Plan)

1. PR 1: Type/config family migration (`arc` family removed, `evm` family canonicalized).
2. PR 2: Runtime call-site cleanup (network-aware resolver inputs, family switches).
3. PR 3: Nonce manager key schema and tests (`network + chainId` keyed).
4. PR 4: Docs/examples rewrite for family vs network semantics.
5. PR 5: Regression guards + CI checks.

## 9. Acceptance Criteria

1. No core type defines `'arc'` as a chain family.
2. `chainFamilyFromNetwork` returns `'evm'` for all EVM networks, including `arc-*`.
3. Runtime signing APIs remain `chain: 'evm' | 'tempo' | 'near'` and do not encode network brands.
4. Nonce/session keying for EVM includes concrete `network` and `chainId`.
5. Docs/examples consistently distinguish family from concrete network names.
6. CI guardrails prevent reintroducing family/network conflation.

## 10. Current Status

1. Phases 1-5 checklist items are complete.
2. Follow-up validation completed: chain-family and nonce-manager unit suites are green.
3. Follow-up validation completed: touch-confirm display model suite is green after restoring explicit `Function`/`Selector` fields in EVM/Tempo call details.
4. Follow-up validation completed: mixed EVM explorer link selection by `family + chainId` is covered and green in `tests/lit-components/confirm-ui.handle.test.ts`.
5. Follow-up validation completed: docs frontend signing integration/smoke specs were updated for the current DemoPage runtime contract and now pass in targeted runs.
6. Follow-up validation completed: repo `lint` gate is green after fixing 36 blocking lint errors from the previous `pnpm check` run.
7. Full `pnpm check` currently remains blocked by repository-wide `format:check` debt (Prettier reports ~794 files), which is outside this migration slice.
8. Follow-up validation completed: previously failing lite specs for wallet-iframe local-signer login warm-up and nonce-manager integration are green after aligning test signer mode expectations.
9. Follow-up validation completed: light-theme accessibility contrast regression (`--site-text-button` vs `--site-brand`) is fixed and `theme.colorThemer.validation` is green in targeted runs.

## 11. Next Steps

1. [ ] Run the full CI profile (`pnpm check`, `pnpm -C tests test:lite`, unit/e2e gates) before merge.
       Current blocker: global `format:check` baseline failures.
2. [x] Add an integration test that asserts touch-confirm explorer link selection by `family + chainId` using mixed EVM networks.
3. [ ] Triage and resolve remaining repo-wide `pnpm check` failures that are outside chain-family naming scope.
       Completed sub-step: lint blockers resolved.
       Completed sub-step: targeted lite regressions (threshold warm-up, nonce-manager integration, theme contrast) resolved.
       Remaining sub-step: full-suite rerun plus format-check baseline cleanup strategy.
