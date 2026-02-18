# Refactor Follow-Up Plan (Readability + Modularity)

Last updated: 2026-02-18

This follow-up roadmap continues from the completed phases in
`docs/refactor.md` and focuses on onboarding clarity and modular boundaries
without over-fragmenting files.

## Next Phased TODOs (Readability + Modularity)

### Phase 8: Align Repo Truth Sources

Goal: remove broken/legacy paths so docs, workspace config, and build config describe the same repo layout.

- [x] Remove missing example package entries from `pnpm-workspace.yaml`.
- [x] Update root `README.md` architecture links to existing docs paths.
- [x] Update `sdk/build-paths.ts` frontend example paths to current example apps.
- [x] Add a CI check that fails on missing local doc paths referenced by README/workspace scripts.

Definition of done:

- New contributors can run documented commands/paths without dead links or missing packages.

### Phase 9: Split Stable vs Experimental SDK Surface

Goal: make the root SDK entrypoint easy to understand and safe by default.

- [x] Keep `client/src/index.ts` focused on stable public APIs.
- [x] Move experimental/internal signing exports to explicit subpaths (for example `@tatchi-xyz/sdk/experimental/*`).
- [x] Update `sdk/package.json` exports map to reflect the split.
- [x] Add a guardrail check to prevent deep internal module exports from the root entrypoint.

Definition of done:

- Root imports communicate a clear "safe public surface"; advanced APIs are opt-in via explicit paths.

### Phase 10: Remove Remaining Wrapper Indirection

Goal: one canonical file path per implementation (no re-export hop chains).

- [x] Remove one-line compatibility wrappers in `client/src/core/signing/api/*` that only re-export nested modules.
- [x] Remove one-line wrappers in `client/src/core/signing/secureConfirm/manager.ts` and `.../manager/index.ts`.
- [x] Remove `lit-components/*` wrapper re-exports where canonical modules already exist under `secureConfirm/ui/*`.
- [x] Delete empty directories under `client/src/core/signing/api/` (`registration`, `signing`, `storage`) unless used immediately.

Definition of done:

- Searching for a symbol lands on the implementation file first, not a wrapper.

### Phase 11: Adopt Flow-Pack Modularity (Not File Explosion)

Goal: make signing flows readable while keeping modules cohesive.

- [x] Group signing logic by flow package (for example `near/transactionsFlow`, `near/delegateFlow`, `near/nep413Flow`, `tempo/tempoSigningFlow`).
- [x] Keep shared primitives in `shared.ts`/`types.ts` per flow package instead of creating micro-files.
- [x] Define module granularity rule in this plan:
  - prefer cohesive files over wrappers,
  - avoid files that only rename/re-export,
  - split only when a file has multiple distinct responsibilities.
- [x] Refactor NEAR signing handlers to follow the new flow-pack layout.

Definition of done:

- A new contributor can follow each signing flow from entrypoint to worker with minimal folder hopping.

### Phase 12: Decompose Large Entrypoints by Domain

Goal: reduce cognitive load in large top-level classes without changing behavior.

- [ ] Split `client/src/core/TatchiPasskey/index.ts` into domain modules:
  - auth/session,
  - signing/actions,
  - device/recovery,
  - wallet-iframe coordination.
- [ ] Split `client/src/core/signing/api/WebAuthnManager.ts` into domain modules under `signing/api/modules/*` and keep class as thin orchestrator.
- [ ] Preserve existing public class method signatures.
- [ ] Add module-level call graph docs/comments for each extracted domain module.

Definition of done:

- `TatchiPasskey` and `WebAuthnManager` remain public facades, not implementation monoliths.

### Phase 13: Consolidate Signing Runtime Worker Boundaries

Goal: eliminate conceptual split between worker runtime files and worker transport/orchestration.

- [ ] Move `client/src/core/workers/*.worker.ts` under a single signing runtime root (`client/src/core/signing/runtime/workers/*` or equivalent canonical location).
- [ ] Keep runtime asset path resolution and build output filenames stable during move.
- [ ] Update `sdk/rolldown.config.ts` entries and worker path helpers accordingly.
- [ ] Add a check to prevent reintroducing a second worker root.

Definition of done:

- Worker runtime, worker transport, and worker operation contracts live under one discoverable tree.

### Phase 14: Normalize Cross-Package Imports

Goal: improve readability and reduce brittle deep-relative paths.

- [ ] Convert deep relative imports to configured aliases (`@shared/*`, `@server/*`, `@/*`) across client core modules.
- [ ] Add lint/check rule forbidding deep cross-package relative imports when alias exists.
- [ ] Keep local same-folder relative imports for nearby modules (readability first).

Definition of done:

- Cross-package imports are uniform and easy to scan.

### Phase 15: Add Onboarding Architecture Guides

Goal: make structure and transaction-signing flow obvious to first-time contributors.

- [ ] Add one canonical architecture doc for SDK folder structure and ownership boundaries.
- [ ] Add one canonical "Signing Flow Walkthrough" doc (register/login -> NEAR sign -> Tempo/EVM sign -> worker -> wasm).
- [ ] Link both docs from root `README.md` and `sdk/README.md`.
- [ ] Add "where to edit" tables for common tasks (signing behavior, worker protocols, UI confirmation, relayer routes).

Definition of done:

- A new contributor can identify edit locations and flow boundaries in under 10 minutes.

### Phase 16: Enforce with Checks + Incremental Rollout

Goal: prevent regression after cleanup.

- [ ] Extend `sdk/scripts/check-signing-architecture.sh` with:
  - no wrapper reintroduction checks,
  - no dead paths in docs/workspace config,
  - root export boundary checks.
- [ ] Run phased PR rollout (one phase per PR where practical) with smoke tests per phase.
- [ ] Record migration notes for any moved paths used by tests or scripts.

Definition of done:

- Readability/modularity improvements are locked by automation and do not drift back.
