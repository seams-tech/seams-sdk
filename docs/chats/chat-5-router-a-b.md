# Chat 5: Router A/B Handoff

Date: 2026-06-14

## Objective

Design and implement the lean Router A/B architecture for Ed25519-HSS hardening,
with a local development harness that mimics the Cloudflare deployment shape.

The core goal is operational server blindness: no single server-side process
should be able to reconstruct joined client-sensitive derivation state such as
`d`, `a`, or `x_client_base`.

## Key Security Conclusions

- `ed25519-hss` is useful only if the deployment preserves the protocol
  boundary. Pinning a crate version and deploying on Cloudflare helps supply
  chain stability, but a compromised or modified server deployment could still
  deviate from the protocol and log intermediate state.
- Outlayer-style intermittent attestation is not a strong tamper-detection
  model for this case. A malicious Cloudflare instance could behave correctly
  on sampled requests and deviate on others.
- Moving the hidden computation to the client would protect server blindness,
  but it shifts risk and computation to clients. That is a poor fit for light or
  embedded clients.
- The preferred architecture is split server roles:
  - Router handles public auth, policy, rate limits, replay, and transport.
  - Deriver A and Deriver B handle derivation-only work.
  - SigningWorker owns activated signing material and normal signing.
  - Deriver A/B are off the normal-signing hot path.

## Main Architecture

Current MVP shape:

```text
Client -> Router -> Deriver A
                 -> Deriver B
Deriver A <-> Deriver B
Deriver A/B -> SigningWorker activation bundles
Router -> Client client-output bundles

Normal signing:
Client -> Router -> SigningWorker -> Router -> Client
```

Important invariants:

- Server-side never materializes joined `d`, `a`, or `x_client_base`.
- Client receives only client-output bundles.
- SigningWorker receives only relayer/signing-worker output bundles.
- Deriver A and Deriver B are derivation-only.
- Normal signing uses Router + SigningWorker only.
- v1 is strict all(2), modeled with signer-set concepts to preserve a future
  N-of-N or t-of-N upgrade path.

The first prototype can run Router, Deriver A, Deriver B, and SigningWorker in
one Cloudflare account. Later deployments can separate them across Cloudflare
accounts or move Deriver A/B to TEEs such as AWS Nitro and Google Confidential
Computing.

## Protocol Decisions

- Selected derivation primitive: `mpc_threshold_prf_v1`.
  - It is slower than the smaller split-root derivation prototype, but still
    sub-millisecond in local measurements.
  - It has a clearer formal-verification path because it reuses the
    `threshold-prf` crate.
- Malicious correctness target: Minimum Level C for the lean MVP.
  - Server verifies transcript bindings and output delivery shape.
  - Stronger public verifying-share checks remain future hardening work.
- Relayer placement changed during the chat:
  - Initial thought: Signer A as relayer.
  - Current shape: dedicated SigningWorker. Deriver A/B are derivation-only.
- Role names changed:
  - Old: Signer A / Signer B.
  - Current user-facing role names: Deriver A / Deriver B.
  - Some protocol identifiers and constants still use signer naming where it is
    part of existing wire/protocol vocabulary.

## Documentation Created Or Updated

- `docs/router-A-B-signer.md`
  - Main architecture and implementation plan.
  - Operational roadmap.
  - Future N-of-N and t-of-N notes.
  - Cloudflare-only prototype path and future multi-provider/TEE path.
- `docs/router-A-B-signer-SPEC.md`
  - Protocol gates, threat matrix, state machine, transcript binding, output
    correctness levels, observability/redaction, release gates, vectors, API
    shapes, examples, folder structure, and formal-verification notes.
- `docs/router-a-b-local-dev.md`
  - Local deployment parity plan.
  - Four-worker local topology.
  - Local env templates, local SQLite storage, local HTTP service-binding
    transport, smoke flows, developer commands, and Cloudflare parity checks.
- `docs/rotate-korg-secrets.md`
  - Updated direction to align with Router A/B operational rotation.
- Follow-up refactor doc for extracting shared threshold-PRF/router-ab logic.

## Implemented Crates And Structure

The implementation was consolidated toward:

- `crates/router-ab-core`
  - Platform-neutral protocol types, derivation flow, transcript/evidence,
    role-separated APIs, local in-process simulation, formal-verification
    scaffolding, and anti-drift tests.
- `crates/router-ab-cloudflare`
  - Cloudflare adapter boundary.
  - Durable Object scopes.
  - Role-specific Worker configs.
  - Service Binding route constants.
  - Strict Worker entrypoints.
  - HPKE recipient proof-bundle delivery.
  - SigningWorker activation and normal-signing boundaries.
- `crates/router-ab-dev`
  - Local development and parity helpers.
  - Ed25519-HSS parity fixtures.
  - Local env materialization.
  - SQLite durable/local storage.
  - Four-process local worker harness.
  - Local smoke and timing capture commands.

Earlier split crates such as separate `router-ab-derivation`, `router-ab-protocol`,
`router-ab-cloudflare`, and `router-ab-local-dev` were simplified into the above
shape.

## Local Development Harness

Implemented a four-process local harness in `crates/router-ab-dev`.

Local roles:

- Router: default `http://127.0.0.1:8787`
- Deriver A: default `http://127.0.0.1:8788`
- Deriver B: default `http://127.0.0.1:8789`
- SigningWorker: default `http://127.0.0.1:8790`

Commands added to root `package.json`:

```sh
pnpm router:init
pnpm router:up
pnpm router:check
pnpm router:smoke
pnpm router:smoke:bundled
pnpm router:measure
pnpm router:down
pnpm router
pnpm router:multiplex
pnpm router:bundled
```

Persistent local development setup:

```sh
pnpm router:init -- --force
pnpm router:up
pnpm router:check
pnpm router:down
```

If default ports `8787-8790` are occupied:

```sh
pnpm router:init -- --force --ephemeral-ports
pnpm router:up
pnpm router:check
pnpm router:down
```

Current local smoke behavior:

- Setup request goes through Router public HTTP.
- A/B peer coordination is exercised over local HTTP.
- SigningWorker accepts only encrypted `x_server_base` proof bundles.
- Router returns only client-output bundles.
- Normal signing routes Router -> SigningWorker and returns a dev-only
  deterministic SigningWorker signature over the required smoke payload.
- Deriver A/B receive zero normal-signing hot-path requests.
- The Cloudflare strict SigningWorker entrypoint now uses the production
  role-separated Ed25519-HSS finalizer once exact server round-1 state has been
  persisted.

Single-terminal log mode:

```sh
pnpm router -- --fresh
```

This launches Router, Deriver A, Deriver B, and SigningWorker with
color-labeled interleaved logs. For the 2x2 terminal dashboard, run:

```sh
pnpm router:multiplex -- --fresh
```

Ctrl-C terminates all four worker processes and restores the terminal.

For a no-segregation single-process profile, run:

```sh
pnpm router:bundled
```

This exposes Router, Deriver A, Deriver B, and SigningWorker routes from one
HTTP listener. It is the local TEE-shaped deployment profile, separate from
`pnpm server`, which still starts the main SDK relay server.

Smoke-test the bundled topology with:

```sh
pnpm router:smoke:bundled
```

`router:measure` writes local timing evidence to:

```text
crates/router-ab-dev/reports/local-smoke-timings/
```

Latest persistent four-worker local run:

- Default `8787` was occupied by an existing Node process.
- `router:init -- --force --ephemeral-ports` generated free ports
  `52310-52313`.
- `router:up` started Router, Deriver A, Deriver B, and SigningWorker
  as four detached local processes.
- `router:check -- --out /tmp/router-ab-local-four-worker-smoke.json`
  passed:
  - setup status: `accepted`
  - Deriver B peer status: `accepted`
  - Deriver A peer status: `accepted`
  - SigningWorker activation status: `accepted`
  - normal signing status: `signed`
  - Deriver A/B normal-signing request counts: `0`
- `router:down` terminated all four worker pids.

Latest ephemeral topology smoke checks:

- `router:smoke` passed with `topology: four-worker`.
  - setup status: `accepted`
  - Deriver B peer status: `accepted`
  - Deriver A peer status: `accepted`
  - SigningWorker activation status: `accepted`
  - normal signing status: `signed`
  - Deriver A/B normal-signing request counts: `0`
- `router:smoke:bundled` passed with `topology: bundled`.
  - one bundled process exposed Router, Deriver A, Deriver B, and
    SigningWorker routes through one localhost listener.
  - setup status: `accepted`
  - Deriver B peer status: `accepted`
  - Deriver A peer status: `accepted`
  - SigningWorker activation status: `accepted`
  - normal signing status: `signed`
  - Deriver A/B normal-signing request counts: `0`

## Cloudflare Parity Work

Implemented or updated:

- Local route constants checked against Cloudflare route constants.
- Local HTTP WireMessage JSON request bytes checked against Cloudflare
  Service Binding JSON serialization helper.
- Local env templates checked against Wrangler startup manifests for role names,
  service bindings, Durable Object bindings, and required secret/storage
  counterparts.
- Added `ROUTER_AB_WORKER_ROLE` vars to all four Wrangler manifests.
- Cloudflare strict Worker feature builds passed for:
  - Router
  - Deriver A
  - Deriver B
  - SigningWorker

Cloudflare startup-latency tooling already exists:

```sh
pnpm -C crates/router-ab-cloudflare measure:startup-latencies -- --dry-run
pnpm -C crates/router-ab-cloudflare measure:startup-latencies -- --upload
```

Dry-run validates upload shape and size. Real `startup_time_ms` requires a
deployed upload/version flow.

Upload attempt status:

```sh
rtk pnpm -C crates/router-ab-cloudflare measure:startup-latencies -- --upload --out reports/startup-latencies/startup-latencies-2026-06-14-upload.json
```

Result:

- Wrangler built Router, Deriver A, Deriver B, and SigningWorker release Wasm.
- Every `wrangler versions upload` call stopped before upload because this
  non-interactive session has no `CLOUDFLARE_API_TOKEN`.
- The generated report has `startupTimeMs: null` and `upload: null` for all
  four roles:
  `reports/startup-latencies/startup-latencies-2026-06-14-upload.json`.

## Formal Verification And Spec Compliance

The spec-to-code compliance pass focused on:

- Server/client forbidden joined-state invariants.
- Recipient-output authorization.
- Transcript binding.
- Activation-context binding.
- Role naming and anti-drift checks.
- Formal-verification intent mismatch risks.

Issues addressed during implementation:

- Server-side combined-output package helpers that could expose joined
  `x_client_base` were replaced or avoided for production-shaped local flow.
- Evidence completeness and package delivery shape were tightened.
- Boundary parser gaps and invalid constructibility were improved.
- Prototype split-root surface was quarantined after choosing
  `mpc_threshold_prf_v1`.
- Startup evidence and AES-GCM runtime posture were addressed or documented as
  release gates.

## Current Validation Snapshot

Last focused validation run:

```text
cargo test --manifest-path crates/router-ab-dev/Cargo.toml
50 passed

pnpm router:smoke
passed with normal_signing_status="ed25519_v1" and Deriver A/B normal-signing counts 0

pnpm router:measure -- --out /tmp/router-ab-local-smoke.json
passed and wrote timing evidence

cargo test --manifest-path crates/router-ab-core/Cargo.toml
235 passed

cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml
194 passed
```

Earlier relevant checks:

```text
cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint
passed

cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-a-entrypoint
passed

cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-b-entrypoint
passed

cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint
passed

pnpm -C crates/router-ab-cloudflare measure:startup-latencies -- --dry-run
passed and wrote reports/startup-latencies/startup-latencies-2026-06-14T03-47-45-021Z.json
```

Completed since the first handoff draft:

- [x] Replaced local HTTP normal-signing fail-closed smoke with a successful
      local dev SigningWorker signature smoke.
- [x] Kept Deriver A/B off the normal-signing hot path and asserted zero
      normal-signing requests in smoke/tests.
- [x] Fixed the Cloudflare deterministic HPKE seal vector.
- [x] Refreshed stale generated core contract and payload vector fixtures.
- [x] Re-ran core, dev, Cloudflare adapter, strict Worker feature checks, local
      smoke, local timing capture, and Cloudflare startup dry-run.
- [x] Attempted Cloudflare startup-latency upload capture and recorded the
      missing-token blocker for all four roles.
- [x] Added persistent local init support for free ports and proved the
      four-worker Router/Deriver A/Deriver B/SigningWorker setup locally.
- [x] Added `pnpm router` interleaved logs and `pnpm router:multiplex` 2x2
      dashboard modes with Ctrl-C cleanup.
- [x] Added `pnpm router:bundled` single-server mode and a bundled topology
      smoke command for the no-segregation local profile.
- [x] Added staging and production Wrangler environments for Router, Deriver A,
      Deriver B, and SigningWorker.
- [x] Added `.github/workflows/router-ab.yml` for Router A/B tests, strict
      Worker checks, local four-worker smoke, and Wrangler startup dry-run evidence.
- [x] Added `.github/workflows/deploy-router-ab.yml` for manual validation,
      Cloudflare Worker version upload, and target deploy.
- [x] Added GitHub Environment variable injection for Router JWT values,
      Deriver A/B public keys, SigningWorker public key, and A/B peer verifying
      keys.
- [x] Updated deployment runbooks with Router A/B secrets, vars, workflow
      commands, and deploy order.
- [x] Confirmed local browser passkey wallet unlock with `pnpm build:sdk &&
pnpm router`.
- [x] Confirmed local browser passkey account registration, Ed25519 transaction
      signing, and ECDSA transaction signing with the same local stack.
- [x] Fixed `pnpm router` startup so it waits for
      `https://localhost:9444/.well-known/webauthn` to stay healthy before
      starting Router A/B workers.
- [x] Committed the scoped local-dev launcher/docs slice:
      `bd5610b6d router-ab: harden local dev launcher`.
- [x] Committed the scoped SDK ECDSA exact-session slice:
      `a41f87ce6 sdk-web: require exact passkey ecdsa session records`.
- [x] Re-ran `cargo test --manifest-path crates/router-ab-dev/Cargo.toml`:
      50 tests passed.
- [x] Re-ran `pnpm router:smoke` and `pnpm router:smoke:bundled`; both passed
      setup, A/B peer coordination, SigningWorker activation, and normal
      signing with Deriver A/B normal-signing request counts at `0`.
- [x] Replaced `local_dev_ed25519_v1` normal-signing smoke signatures with the
      production Ed25519-HSS two-step shape. The local Router and
      SigningWorker now expose prepare/finalize routes and both
      `pnpm router:smoke` and `pnpm router:smoke:bundled` report
      `normal_signing_status: "ed25519_v1"`.
- [x] Captured current local four-worker timing evidence with
      `pnpm router:measure -- --out /tmp/router-ab-local-smoke-2026-06-14.json`:
      total `36 ms`, setup `18 ms`, SigningWorker activation `1 ms`, normal
      signing `0 ms`.
- [x] Re-ran `pnpm router:deploy:check`; at that snapshot it failed only on the
      then-open P1 blocker for persisted server round-1 nonce material. This
      was superseded by the later
      `pnpm -C crates/router-ab-cloudflare assert:release-ready` pass below.
- [x] Re-ran `pnpm router:deploy:dry-run`; all four strict Worker roles bundled
      and wrote
      `crates/router-ab-cloudflare/reports/startup-latencies/startup-latencies-2026-06-14T14-11-55-253Z.json`.
      Dry-run gzip upload sizes: Router `573.83 KiB`, Deriver A `598.97 KiB`,
      Deriver B `599.92 KiB`, SigningWorker `567.14 KiB`.
- [x] Added `ed25519_hss::role_signing`, the role-separated Ed25519-HSS
      normal-signing primitive. It derives client/server verifying shares from
      `x_client_base`/`x_server_base`, creates the client signature share,
      verifies the client share, and finalizes a standard Ed25519 signature from
      server-owned `x_server_base` without reconstructing joined `a`.
- [x] Added focused parity/source-guard tests:
      `cargo test --manifest-path crates/ed25519-hss/Cargo.toml role_separated_ed25519 -- --nocapture`
      passed 4 tests.
- [x] Added SigningWorker round-1 Durable Object storage:
      `CloudflareSigningWorkerRound1RecordV1`, exact idempotent put, exact
      non-expired take, conflicting-handle rejection, and tests for all three
      paths.
- [x] Added production round-1 prepare wiring:
      `NormalSigningRound1PrepareRequestV1` /
      `NormalSigningRound1PrepareResponseV1`, public
      `/v1/hss/sign/prepare`, private
      `/router-ab/v1/signing-worker/sign/prepare`, normal-signing JWT and
      policy/quota/abuse admission, persisted server commitments, and exact
      `round1_binding_digest` enforcement on nonce take.
- [x] Wired the strict Cloudflare SigningWorker normal-signing finalizer to
      `CloudflareRoleSeparatedEd25519NormalSigningHandlerV1`. The handler
      consumes active `x_server_base`, persisted server round-1 state,
      client/server commitments, verifying shares, and the client signature
      share, then returns a standard Ed25519 signature.
- [x] Re-ran focused validation:
      `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings -- --nocapture`
      passed 198 tests;
      `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards -- --nocapture`
      passed 12 tests;
      `cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`
      passed.
- [x] Re-ran `pnpm -C crates/router-ab-cloudflare assert:release-ready`; the
      P1/P2 release blockers covered by that gate are clear.
- [x] Exposed the browser-side role-separated Ed25519 normal-signing client
      share primitive through `wasm/hss_client_signer` and the SDK HSS worker.
      The bridge accepts required raw 32-byte base64url shares/commitments plus
      non-empty signing payload bytes, creates fresh client round-1 nonce
      material inside one worker call, and returns only client commitments,
      client verifying share, and client signature share.
- [x] Wired the SDK NEAR transaction normal-signing path through Router A/B
      prepare, the HSS-client bridge, and Router A/B finalize. The SDK now
      opts into the path only when the Ed25519 session carries explicit
      `routerAbNormalSigning.signingWorkerId`, verifies the returned scope and
      signing-payload digest, and locally attaches the returned Ed25519
      signature to the NEAR transaction.
- [x] Added shared `routerAbNormalSigning` session metadata parsing and threaded
      it through SDK persistence, sealed-session restore metadata, server
      Ed25519 session policy/response types, registration session
      normalization, and email-recovery preparation parsing.
- [x] Added a typed SDK/server configuration source for Router A/B normal
      signing:
      `routerAb.normalSigning.mode="enabled"` with a required
      `signingWorkerId` on the SDK side, `VITE_ROUTER_AB_NORMAL_SIGNING_WORKER_ID`
      in the demo frontend, and `ROUTER_AB_NORMAL_SIGNING_WORKER_ID` on the
      relay/server side. Passkey registration/unlock now populate
      `sessionPolicy.routerAbNormalSigning.signingWorkerId` for Router
      A/B-enabled sessions, and the server rejects mismatched SigningWorker ids.

## Remaining Open Tasks

### 1. Finish Remaining SDK Normal-Signing Surfaces

Required:

- Extend the Router A/B normal-signing helper from NEAR transactions to
  signature-only Ed25519 flows such as NEP-413 and delegate actions.
- Add focused unit coverage for the typed route client and session metadata
  parser around missing `signingWorkerId`, mismatched scopes, mismatched
  payload digests, and missing FROST finalize material.
- Keep residual `group_public_key` finalize-material review on the
  production-hardening list. P1 is closed for the audited release gate, but
  hardening should remove the client-supplied public-key field from finalize
  material or add transcript-bound public-key/address parity vectors.

### 2. Deployed Cloudflare Runtime Evidence

Local smoke timing capture is implemented. The remaining release evidence needs
real Cloudflare upload/deployment data.

Required:

- Fill GitHub Environments `staging` and `production` with the Router A/B
  variables and secrets listed in `docs/deployment/infra.md`.
- Run `deploy-router-ab` with `operation=upload-version` to capture
  Cloudflare startup evidence for the target environment.
- Run `deploy-router-ab` with `operation=deploy` when the uploaded Worker
  versions and startup evidence are acceptable.
- Record `startup_time_ms` for Router, Deriver A, Deriver B, and SigningWorker.
- Record uploaded gzip size beside each startup number.
- Exercise cold-ish and warm request paths:
  - normal signing: `Client -> Router -> SigningWorker -> Router -> Client`
  - setup/export/refresh: `Client -> Router -> Deriver A + Deriver B -> SigningWorker`
- Pull Cloudflare metrics/logs for CPU time, wall time, invocation status, and
  startup failure events.
- Compare against startup budget:
  - excellent: `< 100 ms`
  - acceptable: `100-300 ms`
  - risky: `300-700 ms`
  - unacceptable: near `1000 ms`

### 3. Commit Hygiene

The worktree has many unrelated concurrent changes outside Router A/B. For
Router A/B work, keep commits scoped to:

- `crates/router-ab-core`
- `crates/router-ab-cloudflare`
- `crates/router-ab-dev`
- `docs/router-A-B-signer*.md`
- `docs/router-a-b-local-dev.md`
- `packages/shared-ts`
- `packages/sdk-server-ts`
- `packages/sdk-web`
- root `package.json` command wrappers

Avoid mixing VoiceID, threshold-prf t-of-N refactor, or SDK-server changes into
Router A/B commits unless the SDK-server changes are part of the Router A/B
session or normal-signing boundary.

Current scoped inventory to inspect before staging the remaining Router A/B
work:

- Handoff and local-dev docs:
  - `chats/chat-5-router-a-b.md`
  - `docs/router-a-b-local-dev.md`
  - `docs/router-A-B-signer-SPEC.md`
- Local dev harness:
  - `crates/router-ab-dev/Cargo.toml`
  - `crates/router-ab-dev/Cargo.lock`
  - `crates/router-ab-dev/README.md`
  - `crates/router-ab-dev/env/*.local.example`
  - `crates/router-ab-dev/scripts/measure-local-smoke-timings.mjs`
  - `crates/router-ab-dev/src/lib.rs`
  - `crates/router-ab-dev/src/bin/router_ab_local_*.rs`
  - `crates/router-ab-dev/src/bin/local_dev_process/mod.rs`
  - `crates/router-ab-dev/tests/*`
- Core protocol/vector updates:
  - `crates/router-ab-core/fixtures/derivation/contract/contract-vectors-v1.json`
  - `crates/router-ab-core/fixtures/protocol/payload/payload-vectors-v1.json`
  - `crates/router-ab-core/src/protocol/normal_signing.rs`
  - `crates/router-ab-core/tests/protocol_boundaries.rs`
- Cloudflare adapter and evidence:
  - `crates/router-ab-cloudflare/src/lib.rs`
  - `crates/router-ab-cloudflare/wrangler.*.toml`
  - `crates/router-ab-cloudflare/tests/bindings.rs`
  - `crates/router-ab-cloudflare/src/durable_object.rs`
  - `crates/router-ab-cloudflare/benches/router_latency.rs`
  - `crates/router-ab-cloudflare/reports/startup-latencies/*.json`
- Root command wrappers:
  - `package.json`

Some Router A/B files above were already dirty before the latest normal-signing
and vector cleanup pass. Review each diff before staging so the final commit
only contains the intended Router A/B slice.

## Suggested Next Session Start

Run:

```sh
rtk pnpm router:deploy:check
rtk pnpm router:deploy:dry-run
```

Then choose one of:

1. Finish the remaining SDK normal-signing surfaces.
2. Re-run deployed Cloudflare startup/runtime evidence after
   GitHub Environment secrets and vars are available.
3. Prepare scoped Router A/B commits from the remaining dirty core,
   Cloudflare, and docs files.

Deployment-prep commands:

```sh
gh workflow run deploy-router-ab.yml --ref dev -f target=staging -f operation=validate -f role=all
gh workflow run deploy-router-ab.yml --ref dev -f target=staging -f operation=upload-version -f role=all
gh workflow run deploy-router-ab.yml --ref dev -f target=staging -f operation=deploy -f role=all
```
