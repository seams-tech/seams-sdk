# Refactor 120 — handoff to Codex

Branch: `codex/refactor-120-phase0`, worktree `~/Dev/rust/seams-sdk-r120`.
Baseline for this handoff: `b3cd2b3e8`. Ancestry note: `f7b36712b` merged `dev`
into this branch with `-s ours` after proving R120 is a tree superset of `dev`.

Two files are intentionally dirty and belong to Codex —
`docs/refactor-120-rotate-tenant-secrets.md` and
`docs/evidence/r120-boundary-inventory-v1.json`. Nothing here touched them.

## Where the goal stands

The agreed goal has ten items. Item 1 is the current front, and it is *not*
finished — see the exact stopping point below.

| # | Item | State |
|---|------|-------|
| 1 | Isolated creation/D1 probe | **In progress** — harness fixed, probe reaches the runtime and fails on a real mismatch |
| 2 | Authorized pending cleanup | Partial — reservation landed, execute/complete/receipt and rejection tests remain |
| 3 | Live creation graph `Router → A → B → DO` | Not started |
| 4 | Initial activation | Not started — blocks the rotation lifecycle probe |
| 5 | Phase 1 deployment work | Partial (workflows + key generation exist, unverified) |
| 6 | Live refresh | Not started |
| 7 | Ed25519 profile activation | Not started |
| 8 | Operational lifecycle | Not started |
| 9 | Production integration and cutover | Not started |
| 10 | Phase 6 cleanup | Not started |

## What landed in this stretch

`ef0ef45bd` — `reserve_authorized_cleanup` on the role store
(`crates/router-ab-cloudflare/src/tenant_root_role_d1.rs:3079`). The raw
`reserve_cleanup_pending` is now reachable only from inside the store; an
external cleanup must present a `VerifiedTenantRootRoleCleanupCommandV1`
naming the exact row, role, epoch and revision. The scope derives from the
cleanup command's own nonce, not the ceremony's, so a replayed creation
command cannot authorize deleting the share it created. Also renamed the
shared role mapper (it was probe-named but sits in a production path) and
dropped two unused imports.

`b3cd2b3e8` — the private-D1 probe can boot a Deriver again. Three distinct
faults, all pre-existing:

1. **Migrations never applied.** D1's `exec()` treats every newline as a
   statement boundary, so a multi-line `CREATE TABLE` arrived truncated and
   setup died on line 1. The script now collapses each statement to one line,
   keeping trigger `BEGIN … END` bodies and string literals intact instead of
   splitting on their interior semicolons.
2. **No tenant-root env existed.** `parse_cloudflare_deriver_a_bindings_v1`
   requires `TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON`, and the
   fixture generator emitted zero tenant-root keys, so the Worker could not
   boot. Both roles now get their operational rotation provider descriptors and
   secrets (`crates/router-ab-dev/examples/cloudflare_private_d1_fixture.rs:378`).
   The published issuer keyset there is a **deployment descriptor only** — the
   creation probe carries its own issuer identity, so it can never be satisfied
   by a real deployment's key.
3. **The rotation lifecycle scenario has been unpassable since `aaa3e0265`.**
   `tenant_root_role_d1_integration_activation`
   (`crates/router-ab-cloudflare/src/tenant_root_role_d1.rs:5208`) is a stub
   that unconditionally errors. The broken migrations had been hiding this. The
   script now asserts that exact failure message, so it breaks loudly the moment
   item 4 lands rather than passing silently or failing opaquely.

## Exact stopping point — resume here

Run: `pnpm run test:private-d1` (this sets `ROUTER_AB_WORKER_BUILD_PROFILE=dev`;
`--build-only` forces release, which compiles the `debug_assertions`-gated probe
out entirely and is never the command you want).

Current failure, and it is a **genuine defect, not harness noise**:

```
deriver_a Rust role-store initial creation:
  tenant-root role creation package was refused:
  MalformedInput: tenant-root online role-share request does not match this provider
```

Cause: `tenant_root_creation_probe_provider_config`
(`crates/router-ab-cloudflare/src/tenant_root_role_d1.rs:4893`) returns
hardcoded descriptors —

```
workerd://tenant-root-creation-probe/epoch-1
r120-creation-probe-backup
r120-creation-probe-backup/epoch-1
```

— while the provider actually loaded at
`crates/router-ab-cloudflare/src/tenant_root_role_d1.rs:4628` comes from Env via
`load_cloudflare_tenant_root_operational_rotation_provider_v1` and carries the
fixture's descriptors. The runtime correctly refuses a seal request whose
declared provider does not match the provider doing the sealing.

Recommended fix: take `env` and `worker_role` in
`tenant_root_creation_probe_provider_config` and build
`TenantRootRoleRuntimeProviderConfigV1` from
`parse_cloudflare_tenant_root_operational_rotation_provider_config_v1`'s
`online_epoch_wrapping_key_ref()` / `backup_provider_id()` /
`backup_key_version()`. Do **not** instead edit the fixture to echo the
hardcoded strings: making the probe describe the provider it genuinely holds is
the property worth testing, and a fixture that agrees with itself proves nothing.

Once green, item 1's exit gate is met: both A and B creation-specific wrappers
proven against real D1, each terminalizing its own distinct receipt.

## Then, in order

- **Item 2.** `execute_cleanup` / `complete_cleanup`, DO-side cleanup receipt
  recording, and the rejection cases. `reserve_authorized_cleanup` currently has
  no test of its own — the core command type's tests (`914e09454`) cover the
  command, not the store path.
- **Item 3.** The live graph. The handoff's `Router → A → B → DO` ordering is
  load-bearing: the initiating share is random and cannot be regenerated on a
  later request, so parking a commitment durably would strand a ceremony whose
  scalar no longer exists.
- **Item 4.** Activation evidence. Landing this must also flip the pinned
  assertion in `test-private-d1.mjs` back to the real
  `runTenantRootRoleLifecycle` body, which is still present and marked with an
  eslint-disable for exactly that purpose.

## Verification state at `b3cd2b3e8`

- `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --lib` — 85 passed, 0 failed
- `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test secret_material_boundaries` — 4 passed, 0 failed
- release and debug builds of `router-ab-cloudflare` both clean of errors
- `pnpm run test:private-d1` — **red**, at the provider mismatch above

Remaining release-profile `dead_code` warnings are the not-yet-wired
tenant-root control-plane functions; they resolve with item 3.

## Standing constraints

- The debug-only probe issuer key stays behind `#[cfg(debug_assertions)]`, is
  never a production fallback, is never sourced from or written into production
  secrets, and emits no secret bytes. `secret_material_boundaries.rs` proves
  release builds cannot reference it — note it reads `env.rs`, `lib.rs` and
  `tenant_root_role_runtime.rs` **directly**, because `read_src_file("lib.rs")`
  aggregates every `.rs` under `src/` and made the test pass vacuously.
- `TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON` has no compatibility
  alias; the Router-prefixed name is gone deliberately.
- Path-scoped commits only. `cargo fmt --manifest-path
  crates/router-ab-dev/Cargo.toml` reformats unrelated files in that crate —
  revert them if it does.
