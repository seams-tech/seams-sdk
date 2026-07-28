# Refactor 94C: Remove Durable Object Latency From Signing

Date created: July 28, 2026

Status: active

## Objective

Restore registration to a typical 1.5–2 second post-authentication path, with
3 seconds as the hard product ceiling.

The final Cloudflare topology has:

- a stateless MPC Router;
- stateless Deriver A and Deriver B Workers;
- a stateless SigningWorker;
- separate role-private D1 databases;
- zero Durable Object calls during registration and ordinary signing;
- one ephemeral SigningWorker presign-session Durable Object outside both
  blocking paths;
- three blocking registration routes;
- no legacy selector, fallback, dual-read, or compatibility path.

Refactor 94C retains the completed Refactor 93 and 94A work: Worker custody
separation, Service Bindings, pair binding, signed readiness, one-use role
execution, exact terminal redelivery, lazy NEAR provisioning, and the browser
ECDSA proof-verification boundary.

## Confirmed Cause

The cold regression is stateful orchestration around fast cryptography:

| Boundary | Representative cold time | Representative warm time |
| --- | ---: | ---: |
| Router authorization and admission | about 2,360 ms | about 60 ms |
| SigningWorker output DO | about 1,406 ms | about 38 ms |
| Gateway session and budget DOs | about 1,336 ms | about 22 ms |
| Deriver work | 22–49 ms | similar |
| Worker startup | 3–11 ms | similar |

Service Bindings remain. The Durable Object authorities and redundant public
and D1 round trips are removed.

## Design Rules

### Persist Only Real Effects

Durable state exists only for:

- activation and custody commitment;
- consume-once role/Yao execution;
- exact budget or presign consumption;
- an explicit on-chain operation outside registration;
- terminal bytes that must be redelivered exactly.

Deterministic and idempotent work recovers through re-execution and database
constraints. State written solely for the next route to read is replaced with
a signed client-carried payload.

Delete:

- stored managed grants;
- separate wallet reservations and their cleanup job;
- quota `COUNT` queries;
- abuse-check DO calls;
- duplicate start pre-reads and side-effect journals;
- the outer finalize journal and separate replay-cache write;
- Gateway respond replay state after role retry is verified;
- serialized post-registration React refreshes.

### One Authority Per Effect

- Gateway D1 owns canonical product ceremonies and irreversible product
  activation results.
- Deriver A owns its root share as a role-only Worker Secret and uses A private
  D1 for encrypted one-use state.
- Deriver B owns its root share as a role-only Worker Secret and uses B private
  D1 for encrypted one-use state.
- SigningWorker private D1 owns activated material, exact delivery results,
  sessions, budgets, and presign consumption.
- Router owns no mutable storage.

An operation row's terminal update is its replay record. No second journal or
cache records the same effect.

### Signed Setup And Policy

The Gateway signs the setup and admitted-policy payloads carried by the client
and sent to Router. Each payload binds its operation, environment, request
fingerprint, issue time, expiry, and policy/key version. The setup payload also
binds the wallet candidate, authentication challenge, and signer plan.

Workers verify these payloads locally against deployment-pinned keys.
Registration performs no JWKS, policy, or authorization-state fetch.

The frozen internal contract uses these exact rules:

- request fingerprints are `PublicDigest32` values over the existing canonical
  typed domain encoding, never raw JSON serialization;
- signed setup and policy payloads are compact Ed25519 JWS/JWT strings that the
  client carries opaquely;
- activate returns exact terminal response bytes and exposes no Router
  readiness receipt;
- Gateway is the only wallet-session JWT minting authority; Router and role
  Workers only verify with deployment-pinned key material.

Abuse control uses Cloudflare rate limiting. An exact product quota, where the
configured policy requires one, uses one conditional counter update.

### Role-Private D1 Custody

Root shares remain role-only Worker Secrets. The root-share Durable Objects
stored startup metadata rather than root-share bytes, so their replacement is
local metadata derived from the role Secret and deployment-pinned epochs. Root
shares do not move into D1.

Private D1 stores mutable role lifecycle and SigningWorker custody records.
This intentionally changes the operator threat surface: a Cloudflare
account-scoped API token may query D1 ciphertext through `wrangler d1 execute`
or the D1 API. Application encryption makes database access alone insufficient
to recover protected material.

- A, B, and SigningWorker use separate versioned KEKs available only to the
  owning Worker.
- D1, migration, observability, and general CI credentials contain no KEK.
- AEAD associated data binds role, environment, deriver set or SigningWorker
  identity, root epoch where applicable, record purpose, and schema version.
- No Worker, deployment principal, or release job receives both A and B role
  databases or both role KEKs.
- Plaintext root shares exist only in the owning role's request memory.

The three private schemas are intentionally small:

| Database | Public lookup columns | Encrypted record |
| --- | --- | --- |
| Deriver A D1 | session/pair digest, lifecycle, revision, expiry | A input, execution state, completed output |
| Deriver B D1 | session/pair digest, lifecycle, revision, expiry | B input, execution state, completed output |
| SigningWorker D1 | operation/material identity, request digest, lifecycle, revision, expiry | activated material, session/budget/presign state, protected terminal payload |

A and B use the same logical lifecycle schema in different databases. SQL
transactions use `INSERT ON CONFLICT` for first ownership and versioned
compare-and-swap updates for transitions. Public columns support conflict and
expiry checks only; protected JSON crosses the D1 boundary as ciphertext.

### NEAR Registration Is Local Key Provisioning

Registration creates an Ed25519 keypair and derives the NEAR implicit account
identifier from the public key. It creates no named account on chain.

Registration therefore uses no NEAR RPC, relayer, nonce, block hash, gas,
signed transaction, broadcast, `txStatus`, or on-chain backup journal.
Deferred NEAR provisioning persists only encrypted signer material, the
implicit account projection, and the local provisioning result.

## Target Topology

```mermaid
flowchart LR
    C["Client / wallet iframe"] --> G["Gateway Worker"]
    G --> GD["Gateway D1"]
    G --> R["Stateless MPC Router"]
    R --> A["Stateless Deriver A"]
    R --> B["Stateless Deriver B"]
    A --> AD["A private D1"]
    B --> BD["B private D1"]
    A <-->|"authenticated protocol"| B
    R --> S["Stateless SigningWorker"]
    S --> SD["SigningWorker private D1"]
```

All Worker-to-Worker calls use Service Bindings. The D1 databases use an
explicit documented locality compatible with the production Gateway stores.

## Three-Route Registration

### 1. Setup

One Gateway request:

- authenticates the application;
- applies rate limiting and any conditional exact quota;
- chooses the generated wallet name;
- inserts the canonical ceremony with its wallet UNIQUE constraint;
- returns the signed setup and policy payloads;
- starts safe ECDSA and Yao preparation concurrently during the user prompt.

Preparation creates no custody commitment, consumes no factor, and enters no
irreversible state.

### 2. Authenticated Respond

One Gateway request:

- verifies the passkey or Email OTP proof;
- verifies setup and policy signatures locally;
- returns the exact A/B proof bundles for browser verification.

Role-private state owns exact retry and partial-role convergence. Remove the
Gateway claim/terminal pair after one focused test proves that an identical
retry following a lost or partial response returns the exact role results and
a conflicting fingerprint fails before execution.

### 3. Activate And Finalize

After browser proof verification, one Gateway request:

- claims the irreversible activation;
- invokes Router and SigningWorker;
- commits activated material, session, budget, wallet, signer,
  authentication, and credential records;
- stores the exact terminal response in the operation row;
- returns the wallet-ready result.

The standalone finalize route and its journals are deleted. Authentication
enrollment and recovery-critical records remain blocking. Notifications,
analytics, and redundant refreshes may run asynchronously.

## Client Tail

- Initialize ECDSA client WASM during the authentication prompt.
- Hydrate React account state from activate-and-finalize.
- Refresh login and account data concurrently in the background.
- Represent passkey-session sealing as a typed pending state. Immediate signing
  awaits or resumes it.
- Keep lazy NEAR provisioning outside the blocking ECDSA path.

## Durable Object Deletion Map

| Current binding | Replacement |
| --- | --- |
| `ROUTER_REPLAY_DO` | Owning Gateway or role terminal row |
| `ROUTER_LIFECYCLE_DO` | Owning Gateway or role lifecycle row |
| `ROUTER_PROJECT_POLICY_DO` | Signed request-carried policy |
| `ROUTER_QUOTA_DO` | Conditional owner counter when exact quota is required |
| `ROUTER_ABUSE_DO` | Cloudflare rate limiting |
| `ROUTER_WALLET_BUDGET_DO` | SigningWorker private D1 |
| `DERIVER_A_ROOT_SHARE_DO` | Local startup metadata derived from A's role-only Worker Secret |
| `DERIVER_A_YAO_SESSION_DO` | A private D1 lifecycle row |
| `DERIVER_B_ROOT_SHARE_DO` | Local startup metadata derived from B's role-only Worker Secret |
| `DERIVER_B_YAO_SESSION_DO` | B private D1 lifecycle row |
| `SIGNING_WORKER_SERVER_OUTPUT_DO` | SigningWorker private D1 |
| `SIGNING_WORKER_ED25519_YAO_DO` | SigningWorker private D1 |

`SIGNING_WORKER_PRESIGN_SESSION_DO` is the sole exception. It coordinates one
in-memory background ECDSA presign rendezvous and owns no durable custody,
budget, activation, delivery, or replay record.

## Concurrent Implementation Split

Use two dedicated branches and keep file ownership exclusive until the
integration gate:

- **Codex / topology lane:** `codex/refactor-94c-regression-fixes`
- **Claude / product lane:** `claude/refactor-94c-product-path`

Create both branches from the commit containing this split. Codex owns
`crates/router-ab-*`, `packages/sdk-server-ts/migrations`, role and
SigningWorker database migrations, Worker bindings/configuration, generated
Rust-to-TypeScript protocol bindings, Rust tests, custody documentation, and
Durable Object deletion. Claude owns `packages/sdk-server-ts/src`,
`packages/sdk-web`, `apps/seams-site`, and the TypeScript tests for those
product paths. Only Codex edits this checklist. Claude reports completed commit
hashes for Codex to mark.

### Wave 0: Parallel Inventory And Contract Preparation

#### Codex: Internal Topology Contract

- [x] Map the 12 DO bindings and stored records to Gateway D1, Deriver A D1,
      Deriver B D1, SigningWorker D1, or deletion.
- [ ] Define the minimal internal policy, role-lifecycle, activation, and
      terminal-result contracts. Generate the TypeScript bindings once.
- [x] Specify the three role-private D1 schemas, separate KEKs, encrypted
      mutable records, and role-only root-share Secret retention.
- [x] Update the threat/deployment docs for the D1 custody surface.

#### Claude: Product Contract And Deletion Inventory

- [ ] Map the current grant, intent, start, respond, activate, finalize, replay,
      reservation, and refresh paths in the TypeScript product flow.
- [ ] Define the public setup, authenticated-respond, and
      activate-and-finalize request/result unions using the existing auth
      branches.
- [ ] List the TypeScript records, routes, fixtures, and tests deleted by the
      three-route flow.

#### Contract Checkpoint

- [ ] Agree on field names, fingerprints, idempotency keys, signed-policy
      claims, and terminal response bytes. Codex commits the canonical internal
      bindings; Claude rebases before implementation.

No implementation on either lane may redefine the other lane's contract.

### Wave 1: Parallel Implementation

#### Codex: Zero-DO Custody Topology

- [ ] Make Router authorization local with the signed request-carried policy
      and pinned verification key. Remove registration-time network/JWKS reads.
- [ ] Make Router stateless and delete its six DO bindings and adapters.
- [ ] Implement Deriver A and B private-D1 lifecycle, encrypted mutable state,
      role-only root-share Secrets,
      deterministic retry, and exact completed-output replay.
- [ ] Implement SigningWorker private-D1 activation, delivery, session, budget,
      and presign transactions.
- [ ] Migrate long-lived custody records, invalidate ephemeral ceremonies, and
      delete the SigningWorker and Deriver DO implementations.

#### Claude: Three-Route Product Flow

- [ ] Implement setup, authenticated respond, and activate-and-finalize as the
      only blocking registration routes against the frozen internal interfaces.
- [ ] Delete stored grants, wallet reservations and cleanup, quota counts,
      start/finalize journals, duplicate replay writes, and successful-path
      readbacks.
- [ ] Keep Gateway state only at irreversible activation and terminal replay;
      remove Gateway respond bookkeeping after its deterministic retry test.
- [ ] Add ECDSA WASM prompt-time prewarm, response hydration, background
      refresh, typed passkey-seal pending state, and deferred local-only NEAR
      provisioning.
- [ ] Adapt recovery, export, and ordinary signing to the new interfaces while
      preserving their public behavior.

The lanes may use temporary compile-time interface stubs that exactly match the
checkpoint. Delete those stubs during integration.

### Wave 2: Integration

- [ ] Merge the Codex contract, storage, and Worker commits into the 94C
      integration branch first; merge Claude's product commits second.
- [ ] Resolve generated-binding and call-site conflicts without retaining the
      old topology or adding compatibility branches.
- [ ] Prove registration and ordinary signing contain zero DO calls and
      registration contains exactly three blocking server routes.
- [ ] Run the minimum validation below and fix only observed failures in the
      new operating path.

No mixed-topology revision is deployed.

### Wave 3: Cutover And Delete

- [ ] Run one optimized local Email OTP and one passkey registration.
- [ ] Deploy one coherent staging revision and manually exercise registration,
      unlock/sign, recovery, and export.
- [ ] Confirm the existing timing summary reports zero DO intervals and a
      wallet-ready result within 3 seconds.
- [ ] Deploy the same revision to production after staging passes.
- [ ] Delete migration commands, retired bindings/configuration, and fixtures
      whose only purpose was the removed topology.

Exit: local, staging, and production use the same zero-DO implementation.

## Minimum Validation

No new test framework, trace cohort, mutation suite, or source-text guard is
required.

Required evidence:

1. One focused real-D1 test for concurrent activation and exact lost-response
   replay.
2. One focused role test for identical retry, partial completion, and
   conflicting fingerprint.
3. One custody test showing wrong-role or wrong-KEK ciphertext fails closed.
4. Existing focused registration, recovery, export, and signing tests affected
   by the changed adapters.
5. `pnpm check`, `cargo test -p router-ab-cloudflare`, and `git diff --check`
   before staging.
6. One manual Email OTP and one passkey registration in local, staging, and
   production.

Classify existing failing tests under `AGENTS.md`. Delete fixtures that encode
the retired DO topology.

## Performance Acceptance

- setup: at or below 400 ms;
- authenticated respond: at or below 350 ms after preparation is ready;
- browser proof verification: at or below 100 ms;
- activate-and-finalize: at or below 500 ms;
- typical wallet-ready registration: approximately 1.5–2 seconds;
- hard wallet-ready ceiling: 3 seconds;
- cold path within 500 ms of warm after excluding the user prompt;
- zero registration DO calls;
- zero Router mutable-persistence calls;
- zero network calls for token or policy verification;
- no standalone grant, intent, start, or finalize route.

## Completion Criteria

Refactor 94C is complete when:

1. Router, Deriver A, Deriver B, and SigningWorker are stateless.
2. Their production Wrangler configurations contain zero DO bindings.
3. Role-private encrypted D1 storage preserves A/B custody.
4. Registration uses setup, authenticated respond, and activate-and-finalize.
5. Registration and ordinary signing make zero DO calls.
6. Exact activation replay, role one-use behavior, recovery staging, export
   isolation, and budget consumption remain correct.
7. Registration performs no NEAR on-chain account creation.
8. No compatibility or retired persistence path remains.
9. Staging and production registration meet the 3-second hard ceiling.

## Out Of Scope

- prewarming Durable Objects scheduled for deletion;
- a new coordinator or ledger;
- new telemetry infrastructure or production trace cohorts;
- reusable cryptographic preprocessing;
- changing ECDSA or Yao cryptography;
- named NEAR account creation during registration;
- Smart Placement experiments before the zero-DO topology is live.

## Relationship To Other Refactors

- [`refactor-93.md`](./refactor-93.md) records the Router and pair-bound work
  retained here.
- [`refactor-94A-performance-regression.md`](./refactor-94A-performance-regression.md)
  records completed registration-path simplification and local results.
- [`refactor-94B-cold-ecdsa-registration.md`](./refactor-94B-cold-ecdsa-registration.md)
  records the completed cold-boundary diagnosis and timing apparatus.
- Refactor 90 remains authoritative for modular authorization capabilities.
