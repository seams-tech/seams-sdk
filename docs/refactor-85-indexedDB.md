# Refactor 85B: IndexedDB Minimization Plan

Date created: July 1, 2026

Status: planning.

Parent plan: [Refactor 90 Modular Auth And Capability](./refactor-90-modular-auth-capabilities-plan.md)

## Goal

Minimize browser IndexedDB so it becomes a local cache and local secret-material
store, not the durable source of truth for wallet, auth, signer, recovery,
policy, budget, or capability identity.

This supports the Refactor 90 direction where MPC signing is one capability of
Seams Auth rather than the root account model. Cross-platform clients should be
able to use the same server-side auth and capability records without recreating
browser-specific IndexedDB state.

## Core Rule

Server records are authoritative. IndexedDB may store only:

- local MPC client material or sealed material needed by this device;
- short-lived loaded worker handles and binding digests;
- short-lived warm-session and restore leases;
- local UI preferences and recent-selection hints;
- opaque references to server-owned wallet, principal, auth-method, and
  capability records.

IndexedDB must not own durable facts such as wallet identity, auth-method
enrollment, signer capability identity, public chain/account bindings, recovery
state, policy/budget state, or audit history.

## Target Shape

Server-side capability records:

```ts
type CapabilityInstance =
  | {
      kind: 'near_ed25519_mpc_signing';
      capabilityId: CapabilityId;
      walletId: WalletId;
      signer: NearEd25519SignerBinding;
      status: CapabilityStatus;
      policyBinding: CapabilityPolicyBinding;
    }
  | {
      kind: 'evm_ecdsa_mpc_signing';
      capabilityId: CapabilityId;
      walletId: WalletId;
      signer: EvmFamilyEcdsaSignerBinding;
      status: CapabilityStatus;
      policyBinding: CapabilityPolicyBinding;
    };
```

Client-local material records:

```ts
type LocalCapabilityMaterial =
  | {
      kind: 'none';
      capabilityId: CapabilityId;
    }
  | {
      kind: 'sealed_local_material';
      capabilityId: CapabilityId;
      materialIdentity: MaterialIdentity;
      sealedRef: LocalSealedMaterialRef;
      sealedBlobB64u: string;
      formatVersion: string;
      expiresAtMs?: number;
    }
  | {
      kind: 'loaded_worker_material';
      capabilityId: CapabilityId;
      materialIdentity: MaterialIdentity;
      workerHandle: WorkerMaterialHandle;
      expiresAtMs: number;
    };
```

Local rows may duplicate server IDs for indexing, but core logic must immediately
normalize local rows into a discriminated local-material state. It must not read
raw IndexedDB identity fields as authority.

## Current Store Inventory

Current `seams_wallet` stores from
`packages/sdk-web/src/core/indexedDB/schemaNames.ts`:

| Store | Current role | Target disposition |
| --- | --- | --- |
| `app_state` | Last user/profile, UI state, preferences | Keep only UI preference and recent-selection hints. Remove authoritative wallet/session facts. |
| `wallets` | Local wallet profile mirror | Replace with server wallet/principal summary cache keyed by `walletId`, or delete once server session reads are cheap enough. |
| `wallet_auth_methods` | Local auth-method mirror | Move authority server-side. Keep only optional display/cache rows with server `authMethodId` references. |
| `wallet_signers` | Local signer capability mirror | Move authority server-side as capability instances. Keep only capability ID cache and display hints. |
| `near_accounts` | NEAR account projection and lookup | Move authority server-side. Keep optional display cache; NEAR signing requires server capability binding plus local material. |
| `signer_ops_outbox` | Local retry/outbox for signer operations | Re-evaluate. Keep only if offline retry is still a product requirement; otherwise delete and require online capability APIs. |
| `recovery_emails` | Local recovery email mirror | Move authority server-side. Keep display cache only if needed. |
| `nonce_lane_leases` | Local nonce coordination | Prefer server/chain-derived readiness. Keep only ephemeral per-tab/per-device cache if still needed for UX. |
| `nonce_lane_locks` | Local lock coordination | Keep only ephemeral coordination, with TTL and no durable authority. |
| `key_material` | MPC/local key material and signer metadata | Keep only local secret/material records keyed by `capabilityId`; remove duplicated signer authority fields. |
| `signing_session_seals` | Sealed warm-session material | Keep as local sealed material cache keyed by capability/session identity; server owns session/grant authority. |
| `signing_session_restore_leases` | Local restore coordination | Keep as ephemeral local-only lease with TTL. |
| `email_otp_escrows` | Email OTP device enrollment escrow | Move authority server-side where possible. Keep only encrypted local escrow if needed for device-local recovery UX. |
| `email_otp_pending_recovery_code_backups` | Pending recovery-code backup | Move to server workflow. Keep only transient encrypted draft state if needed. |

## Phase 1: Boundary Classification

Goal: classify each IndexedDB field before moving code.

Do:

- For every store, create a field-level inventory with one disposition:
  `server_authoritative`, `local_secret_material`, `ephemeral_cache`,
  `ui_cache`, or `delete`.
- Identify every read path where IndexedDB data currently influences auth,
  capability, signer, budget, recovery, nonce, export, or lane selection.
- Mark every field that duplicates server truth, including wallet/auth-method
  status, signer capability state, NEAR account binding, ECDSA public binding,
  recovery email state, and policy/budget state.
- Add a short deletion note for any field kept only as a temporary request or
  persistence boundary compatibility shape.
- Record the current cross-origin split: app-origin IndexedDB disabled in iframe
  mode, wallet-origin IndexedDB as local material host.

Check:

- Each store has a written disposition.
- No field is classified as both server-authoritative and local-authoritative.
- Every identity-sensitive read has a target replacement API or local-material
  parser.

## Phase 2: Server Authoritative Capability Snapshot API

Goal: replace local wallet/signing mirrors with server-owned capability
snapshots.

Do:

- Add a server route that returns the authenticated principal's wallet summary
  and capability instances:

```ts
type WalletCapabilitySnapshot = {
  walletId: WalletId;
  displayName: string;
  authMethods: readonly AuthMethodSummary[];
  capabilities: readonly CapabilityInstance[];
  updatedAtMs: number;
};
```

- Source snapshot data from D1/DO/server stores, not IndexedDB uploads.
- Include enough public signer facts for UI, exact lane construction, and
  capability selection.
- Keep secret material and sealed local blobs out of the response.
- Add cache validators or version stamps so browser caches can cheaply refresh.

Check:

- Fresh browser with empty IndexedDB can list wallets, auth methods, and signer
  capabilities after login.
- Capability selection uses server snapshot plus local material state.
- IndexedDB wallet/signature mirror rows are not required for login display.

## Phase 3: Local Material Store Redesign

Goal: make local storage model only local material.

Do:

- Replace broad wallet/signing rows consumed by core logic with
  `LocalCapabilityMaterial` records keyed by `capabilityId`.
- Normalize raw IndexedDB rows into:
  `none`, `sealed_local_material`, or `loaded_worker_material`.
- Move duplicated fields such as `nearAccountId`, `nearEd25519SigningKeyId`,
  chain target, public key, signer slot, and ECDSA threshold key ID out of local
  authority. Local material may store these only inside a binding digest or
  immutable `materialIdentity` used to verify against the server capability.
- Require every use of local material to compare its `capabilityId` and
  `materialIdentity` against the server snapshot before signing/export.
- Delete core functions that accept raw key-material rows, raw wallet signer
  rows, or raw near-account projection rows.

Check:

- NEAR signing, EVM signing, export, login warmup, and recovery restore read
  local material through the same local-material union.
- Missing local material triggers restore or reauth, not local identity
  reconstruction.
- Duplicate or mismatched local material fails closed before worker use.

## Phase 4: Remove Local Wallet/Auth/Signer Authority

Goal: stop IndexedDB from deciding which wallets, auth methods, and signers
exist.

Do:

- Replace wallet picker, login menu, account menu, and recent unlock reads with
  server session/snapshot reads plus UI cache fallback for display only.
- Move `wallet_auth_methods` authority to server auth-method records.
- Move `wallet_signers` authority to server capability records.
- Move `near_accounts` authority to server capability binding records.
- Delete local code that creates durable wallet/auth/signer identity without a
  server response.
- Keep app-state recent-selection hints as non-authoritative IDs. Missing server
  records must hide the item instead of trusting the hint.

Check:

- Clearing IndexedDB does not make server-owned wallets disappear.
- Stale IndexedDB cannot resurrect a deleted wallet, auth method, or signer.
- Login/unlock can complete on a fresh browser by restoring only needed local
  material.

## Phase 5: Recovery And Email OTP Local Storage Cut

Goal: keep recovery state server-owned and use local storage only for encrypted
device-local drafts.

Do:

- Move recovery email status and enrollment metadata to server reads.
- Move Email OTP enrollment and recovery-code backup authority to server
  records.
- Keep local encrypted escrows only when the device must hold an unrecoverable
  local secret.
- Rename local escrow stores to make their device-local role explicit if they
  remain.
- Delete broad local recovery mirrors once server routes are the only authority.

Check:

- Email OTP login and recovery work after clearing IndexedDB except where local
  sealed material is intentionally required.
- Recovery status UI reflects server state.
- Local escrow rows cannot create or authorize recovery by themselves.

## Phase 6: Nonce, Budget, And Session Cache Cleanup

Goal: leave only TTL-bound local coordination in IndexedDB.

Do:

- Move budget status and signing grant authority fully server-side.
- Keep nonce lane leases/locks only as local contention avoidance, with strict
  TTL and no source-of-truth semantics.
- Rename wallet-scoped nonce fields currently named `accountId` to `walletId`.
- Ensure signing-session seals are treated as sealed local material caches, not
  proof that a grant/session is still active.
- Delete local session records that duplicate server grant/session truth once
  capability snapshot and seal validation cover the path.

Check:

- Expired local session or nonce rows cannot authorize signing.
- Server budget/session denial wins over local cache.
- Local locks can be cleared without corrupting server state.

## Phase 6A: Active Wallet Session Boundary

Status: implemented July 6, 2026 as an independent correctness slice. This
landed before the broader Refactor 85B capability-snapshot, local-material
redesign, and schema-shrink phases. The slice changed parser/domain-state
behavior and focused callers without a schema bump.

Goal: expired or exhausted persisted wallet-session rows cannot become active
signing domain state. IndexedDB session rows are durable hints until the boundary
parser proves current lifetime, spend, authority binding, and material binding.

Trigger: the July 6 auto-audit found that an expired Router A/B Ed25519
wallet-session row can still parse as signable and classify as
`runtime_validated`, causing NEAR readiness and available-lane policy to treat
stale persisted state as ready until a later caller performs its own expiry
check.

Scope: fix the Ed25519 bug and audit the ECDSA twin in the same slice. If the
ECDSA persisted-record classifier already rejects expired or exhausted session
state, record the exact counterevidence in this phase before closing it.

Do:

- Split the Router A/B Ed25519 signing-session parser into an active-state
  builder that requires `{ record, nowMs }` and returns an active session only
  when wallet-session authority, JWT claims, signing root, Router A/B state,
  material identity, `remainingUses`, and `expiresAtMs > nowMs` all hold.
- Audit the Router A/B ECDSA HSS persisted-record classifier for the same
  lifetime/spend hazard. Apply the same active-state boundary and tests if
  expired or exhausted ECDSA records can classify as runtime-validated,
  restorable-active, or ready.
- Add explicit non-signable persisted-state variants for inactive sessions:
  separate `expired` and `exhausted` branches. These branches must carry
  `value?: never` so active signing-session values cannot exist in inactive
  state.
- Make `classifyRouterAbEd25519PersistedSigningRecord` emit inactive state
  before `runtime_validated`, `restore_available`, or material-hint branches.
  Previously validated worker material may remain restorable local material,
  but it must not carry an active wallet-session value after session expiry.
- Use one operation clock. The caller supplies `nowMs` once per signing/export
  operation and threads it through active-state parsing, readiness, lane
  selection, and restore planning instead of re-sampling time at each branch.
- Update NEAR readiness, persisted available-lane policy, selected-lane
  capability reads, material restore, seal restore, reconnect planning, and
  implicit NEAR funding helpers to consume the inactive branch instead of
  deriving readiness from raw persisted `expiresAtMs`.
- Route sealed-session restore through the same active-state parser after
  material is restored. Restoring local sealed material for an expired grant can
  produce restorable local material state, but it must land in `expired` or
  `exhausted` for signing authority.
- Treat local `remainingUses` as a fail-fast hint only. Server grant/spend
  state is authoritative: local non-exhausted state can still be denied by the
  server, and server denial must never be "repaired" by adjusting local
  `remainingUses`.
- Keep the downstream signing RPC and presign expiry checks as defense in depth;
  the active boundary becomes the primary domain invariant.
- Add type fixtures or source guards that reject constructing an active
  Router A/B signing-wallet session from a generic persisted record without the
  active-state builder.

Check:

- A material-ready Ed25519 record with `expiresAtMs <= nowMs` and a previously
  validated worker-material key classifies as `expired`, never
  `runtime_validated`.
- ECDSA HSS persisted-record classifiers either have equivalent expired and
  exhausted test coverage or a documented counterexample proving the hazard does
  not apply.
- `resolveRouterAbEd25519WalletSessionStateFromRecord` returns `null` for
  expired and exhausted records.
- NEAR transaction readiness maps expired persisted wallet-session rows to
  `expired`, and remaining-spend exhaustion maps to step-up/exhausted handling.
- If a session is active at readiness time and expires before the signing RPC or
  presign request lands, the operation maps to the existing reauth/step-up path
  or a user-facing expired-session result, not an internal invariant error.
- Persisted available lanes never advertise expired records as durable `ready`.
- Seal restore for an expired grant cannot create an active signing session.
- Future, non-exhausted runtime-validated records still sign, export, and
  restore through the existing intended behaviour contracts.

## Phase 7: Schema Shrink

Goal: reduce the physical IndexedDB schema.

Do:

- Bump `SEAMS_WALLET_DB_VERSION`.
- Delete stores whose authority moved server-side and whose cache value no
  longer justifies local complexity.
- Keep a small schema:
  - UI state/preference cache;
  - local capability material;
  - sealed material cache;
  - restore/nonce short TTL leases, if still needed.
- Remove repository methods for deleted stores.
- Delete tests and fixtures that only protect deleted local-authority behavior.

Check:

- New installs create only the reduced store set.
- Existing dev users can clear IndexedDB and continue from server state.
- No production source imports deleted repository methods.

## Phase 8: Guards And Documentation

Goal: prevent IndexedDB authority from growing back.

Do:

- Add a source guard rejecting core auth/capability/signing code that reads raw
  `wallets`, `wallet_auth_methods`, `wallet_signers`, or `near_accounts` rows as
  authority.
- Add a guard that allows IndexedDB authority reads only in named boundary
  modules such as local material parsers and UI cache readers.
- Document which stores are allowed to contain local secret material.
- Update Refactor 85 docs to reference this storage boundary.

Check:

- Source guards pass.
- Docs explain how a fresh browser restores capability state from the server and
  local material from the device.

## Acceptance Criteria

- Fresh browser login with empty IndexedDB can discover wallets and capabilities
  from the server.
- Clearing IndexedDB removes only local material, local cache, and preferences;
  it does not delete server wallet/auth/capability records.
- IndexedDB cannot authorize signing, export, recovery, policy, budget, or
  wallet existence without server state.
- Expired or exhausted IndexedDB wallet-session rows cannot construct active
  signing-session state, readiness, available-lane `ready` advisories, or
  trusted wallet-session auth.
- All core signing/export/unlock paths consume a server capability binding plus
  normalized local material state.
- Local material records are keyed by `capabilityId` and validated against the
  server capability snapshot before use.
- No core code derives `walletId`, `nearAccountId`, signer identity, auth
  method, grant, or capability state from local cache alone.

## Validation Plan

Run focused checks as phases land:

```sh
pnpm -C packages/sdk-web -s type-check
pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/walletCapabilityBindings.sourceGuard.unit.test.ts --reporter=line
pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/runtimePostconditions.unit.test.ts --reporter=line
pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/ed25519TransactionLaneSelection.unit.test.ts unit/nearSigning.sessionSelection.unit.test.ts --reporter=line
pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/availableSigningLanes.ed25519Duplicates.unit.test.ts unit/availableSigningLanes.ecdsaDuplicates.unit.test.ts --reporter=line
pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/routerAbEd25519.walletSessionState.unit.test.ts unit/signingCapabilityStrictRecords.unit.test.ts --reporter=line
```

Manual checks:

- Register a wallet, clear IndexedDB, log in, and confirm wallet/capability
  discovery comes from the server.
- Restore local material and sign NEAR and EVM transactions.
- Delete or disable a server capability, leave stale IndexedDB rows in place,
  and confirm signing/export fails.
- Test wallet iframe mode and app-origin disabled IndexedDB mode.

## Open Questions

- Which local material types must survive browser restart for acceptable UX?
- Do we still need offline signer-operation outbox behavior?
- Should local UI caches be encrypted or left as non-sensitive display hints?
- What is the final `CapabilityId` format for NEAR Ed25519 and EVM ECDSA
  signers?
- Can nonce lane coordination be moved entirely server-side after D1/DO staging?
