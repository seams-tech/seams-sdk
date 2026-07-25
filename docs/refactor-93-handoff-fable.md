# Refactor 93 — Handoff (Fable → Codex)

Date: July 25, 2026
Worktree: `/private/tmp/seams-refactor-93-role-lifecycle`
Branch: `codex/refactor-93-role-lifecycle` (PR #18, draft)
Last full-gate-verified commit: `0668682d0` — commits after it are doc-only.
Local commits are **not pushed**. Nothing deployed. No cutover window is
configured in any environment (verified by three independent greps plus the
config renderer), so all three families run on the legacy runtime.

Gate state at `0668682d0`: `pnpm check` 0 errors; 729 Rust tests / 61 binaries,
0 failures; source-guards 36 scripts + 231 source tests, exit 0; 33 focused
Yao unit tests green. Logs retained under the session scratchpad
(`pnpm-check.log`, `cargo-*.log`, `source-guards.log`, `pw-focused.log`).

## What's done (since your pause checkpoint)

1. **Source-guard chain unblocked** (was red): sessionId classifications for
   the Export/Recovery modules, nine test-ledger registrations, and the two
   Email OTP ordering guards retargeted at the atomic batch they now guard.
2. **Registration finalization closed to the boundary you flagged:**
   - Sponsored NEAR creation split into prepare (build+sign+hash, no
     broadcast) and broadcast (replays exact persisted bytes).
   - Side-effect boundary runs `prepare()` before the claim is persisted,
     stores the artifact on the claim, returns it on `in_progress`, and tells
     `execute` whether the attempt is `fresh` or `resumed`.
   - Your audit findings 1–2 fixed: broadcast returns
     `created | rejected | uncertain`; only failures proving the transaction
     cannot have landed are `rejected`; `uncertain` throws so the claim stays
     open; a resumed attempt settles the stored hash via `txStatus` before
     resubmitting.
   - Persisted claims are parsed/validated at the D1 boundary (casts removed).
   - Email OTP enrollment statements ride inside the single wallet commit
     `batch()`; the commit input is a passkey/email_otp discriminated union.
   - Wired into finalize keyed by the activation session id (hex).
3. **Per-family cutover** (your finding 3): `RouterAbEd25519YaoGatewayCutoverStateV1`
   with independent windows per family via
   `ROUTER_AB_YAO_GATEWAY_{REGISTRATION,RECOVERY,EXPORT}_{ADMISSION_CUTOFF_MS,DRAIN_UNTIL_MS}`.
   A family with no window stays legacy indefinitely — the expired-window
   inheritance you identified is structurally impossible now.
4. **All seven Yao operations composed behind the selector.** Recovery and
   export dispatch through `createStagingRecoveryRequestScopedDependencies` /
   `createStagingExportRequestScopedDependencies` — env-only builders reusing
   the existing authorization classes and never touch the tenant runtime.
5. **Finalize/execute store split closed.** Finalize reads the activation via
   `consumeActivated` on a runtime that was a fixed tenant-runtime value;
   enabling the registration window would have failed every finalize. The
   `ed25519YaoProductRegistration` option now accepts a resolver; the staging
   worker resolves it with the `registration_execute` classification so
   finalize follows execute's store for the whole window.
6. **Tests:** 20 registration-bridge (durability-before-effect, ambiguity
   keeps the claim open, resumed reconciliation, no-rebuild, exact replay,
   concurrency: exactly one effect, loser gets `exact_replay`), 8 cutover
   (incl. no-window-stays-legacy and independent family schedules), 5 commit
   store incl. three new Email OTP atomicity/rollback/convergence cases
   against a real temp D1 database.
7. **Worktree hygiene:** registration-bridge merged; recovery-activation and
   export-bridge were already integrated (handoff before mine overstated
   their isolation); canonical-digest, signed-handshake, lifecycle-tests are
   stale duplicates safe to prune.

The handoff snapshot stood at **69 checked / 33 unchecked** — the unchecked count rose twice
when audit findings showed earlier claims were too strong, which is the
intended direction of error.

## What's left

1. **Local parity is implemented.** The local worker routes registration,
   recovery (including warm bootstrap), and export through the request-scoped
   D1 handlers. Its backend still uses the local service bindings and intended
   fault controller, and readiness checks the versioned JSON CAS tables.
2. **Entry-point convergence.** Commit store and side-effect boundary are
   proven in isolation; no test drives the full
   `CloudflareD1WalletRegistrationService` finalize across an interruption.
   Needs the full service constructed against temp D1.
3. **Capability fallback bridge is implemented.** `resolveActiveCapability`
   falls back on a shared-record miss to the D1 wallet signer record and
   installs it through the shared CAS boundary. The lookup is bounded to the
   requested wallet and signer slot.
4. **Canonical fingerprint and discriminated side-effect API are implemented.**
   Finalize replay records bind the idempotency key to the request fingerprint,
   and prepared/non-resumable effect inputs reject invalid combinations at the
   type boundary.
5. **Add-signer review.** `walletAddSigners` shares the runtime resolver I
   changed; only the registration path was reasoned through.
6. **Tenant runtime removal**, in order: audit its authoritative in-memory
   state; non-Yao routes flatten to direct worker composition (no drain
   needed — their stores are D1-backed); after all Yao drains, delete the DO
   class, `ROUTER_API_RUNTIME` binding, instance naming, readyz probe,
   snapshot serializer/parser, SQLite migration. Recommended scope split: the
   Yao half closes acceptance criterion 3 inside refactor-93; full removal is
   the follow-up refactor (`refactor-93-gateway-persistence-follow-up.md`).
7. **Staging:** deploy a frozen commit with windows unset (no behaviour
   change), exercise registration/recovery/export/replay/restart/concurrency,
   then enable windows one family at a time and observe each drain.
8. **Drain-gated deletion** of legacy routes/env keys/parsers/serial-flow
   tests — the deletion audit and drain-evidence gate already enforce this.
9. **Production evidence** — still blocked on Workers Observability access;
   acceptance criteria 15–17 cannot be evaluated. Analyzer and data-gate are
   ready. This is the long pole and is not a code problem.

## Issues encountered (including my own errors — check my work accordingly)

1. **I shipped the ambiguity bug you caught**: the broadcaster collapsed
   exceptions into `{success:false}` and my test simulated ambiguity with a
   thrown exception — a path production never took. Fixed, with tests that
   model the resolved-failure path. Implication: verify my tests exercise
   production behavior, not fixture-shaped behavior.
2. **My global-window design was wrong** for staged rollout, exactly as you
   said; per-family state replaced it.
3. **A tautological test** (comparing a call to itself) was written and
   caught the same turn; spot-check other assertions of mine for the pattern.
4. **An index-based splice duplicated a block** in `d1RouterApiStagingWorker.ts`;
   I reverted to the committed state and redid it with targeted edits — that
   file is worth a residue check.
5. **Merge hazard:** the first registration-bridge merge brought the
   commit-plan switch without its uncommitted supporting store changes
   (3 type errors). Fixed by committing the supporting half and re-merging.
   General rule that bit us: staged file edits travel with commits their
   support hasn't landed for.
6. **Real-D1 tests caught two fixture bugs** an `as`-cast had hidden: the
   enrollment store takes a scoped `prepare`, and the email_otp authority
   requires `emailHashHex`/`registrationAuthorityId`.
7. **Environment:** the unit/source-guard blockage you reported reproduced on
   `dev` (stale base), confirmed before any fix; concurrent sessions moved
   the worktree mid-review once — pin a freeze commit for anything
   deployment-shaped.
8. An independent audit thread may deliver findings against this same branch;
   its findings and this handoff may overlap.

## Takeover verification

The takeover correctness findings were addressed on the implementation branch.
NEAR reconciliation now distinguishes created, rejected, not-found, and
uncertain outcomes, reads back the expected account and FullAccess key, and
rebroadcasts only the exact validated transaction bytes. Persisted prepared
artifacts are parsed structurally and their transaction hash is checked against
the serialized bytes before any network effect. The deployment renderer emits
six per-family cutoff/drain variables, and the public registration-start gate,
existing-wallet capability fallback, and request-scoped local route path are
wired. Warm recovery bootstrap is also request-scoped and participates in the
recovery family selector. Focused typechecks and recovery/cutover suites pass.

The remaining gates are intentionally open: end-to-end finalize crash
convergence through `finalizeWalletRegistration`, staged window enablement and
drain evidence, deletion of the tenant runtime after non-Yao/session state is
migrated, and production cold/warm evidence that requires Workers Observability
access.
