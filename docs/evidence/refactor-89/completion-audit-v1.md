# Refactor 89 local completion audit v1

Date: July 17, 2026

Status: **27 requirements aligned; B3, B6, and D7 are blocked by the rejected
Cloudflare signing lifecycle review. Deployed ECDSA evidence remains assigned
to the Router A/B deployment plan.**

## Audit scope and decision rules

The authoritative implementation scope is the `Implementation-complete Local
Phases` tracker in `docs/refactor-89-slimmer-near-ecdsa.md`. The plan explicitly assigns
Cloudflare rollout, deployed latency/cost, rollback receipts, and multi-account
operational evidence to the deployment plans. Historical phase checklists below
that tracker are construction records rather than active work.

This audit uses these classifications:

- `aligned`: current implementation plus direct executable or artifact evidence
  establishes the requirement;
- `blocked`: a required implementation or security property is absent;
- `external_gate`: a required independent actor has not supplied approval; and
- `excluded_deployment`: the requirement belongs to a named deployment plan and
  is outside the local refactor completion boundary.

An absence search is evidence only where a current guard enumerates the deleted
owner or dependency. Artifact evidence is accepted only when it names the exact
shipping file and digest. Cryptographic compatibility evidence is bounded to
the pinned oracle corpus; it is never treated as a proof of construction
security.

## Spec IR

| ID | Normative requirement | Preconditions and authority | Required postcondition or failure behavior |
| --- | --- | --- | --- |
| `A1` | Browser presigning uses the fixed Client role. | Authenticated role-local additive share, registered group key, fixed session context. | Only the Client fixed-role state machine is constructible; invalid input or round aborts. |
| `A2` | SigningWorker presigning uses the fixed SigningWorker role. | Private SigningWorker authority and the same authenticated pair context. | Only the SigningWorker fixed-role state machine is constructible; invalid input or round aborts. |
| `A3` | SigningWorker finalization uses the purpose-built online kernel. | Committed one-use server material and exact Client signature share. | Emit a verified low-`s` recoverable signature or terminally reject and burn the pair. |
| `A4` | Production boundaries contain no runtime topology selection or generic state bags. | Compile-time Client/SigningWorker ownership. | Participant vectors, threshold, role selectors, and generic protocol state are unreachable. |
| `A5` | Cutover preserves public key/address, signature, budget, recovery, and export behavior. | Same authenticated key and lifecycle authority. | Product-observable cryptographic and lifecycle outputs remain stable; invalid bindings fail closed. |
| `B1` | A storage-independent persistent pool contract binds the exact identity and has absorbing tombstones. | Valid wallet, account, scope, pair, role, epochs, protocol, and material locator. | Only forward `available -> reserved -> committed-use -> tombstone` transitions are possible. |
| `B2` | Client persistence is encrypted, atomic, destructive on uncertainty, and non-revivable. | Parsed pool identity and durable non-extractable sealing key. | CAS and ciphertext deletion complete before material leaves storage; uncertainty burns material. |
| `B3` | SigningWorker persistence applies the same monotonic lifecycle. | Authenticated scope, expected revision, exact request and pair. | Atomic Durable Object mutation persists the next state or rejects stale/substituted input. |
| `B4` | Outputs cross a process boundary only after committed-use and material deletion persist. | Exact committed record and online request binding. | Persistence failure withholds the signature share/final signature. |
| `B5` | Pair creation is bound to the authenticated registry and exact wallet key. | Verified Router A/B activation and commitment registry. | Unbound or substituted material never becomes available. |
| `B6` | The lifecycle fault matrix covers concurrency and every uncertain terminal path. | Both concrete adapters plus the shared reducer. | Stale, timeout, cancellation, abort, crash, failure, retirement, and duplicate use end safely. |
| `C1` | Protocol ID, numeric registry, encoding, transcript domains, ceilings, and rejects are frozen. | Fixed two-role eleven-round protocol. | Every accepted frame is canonical and bounded; any framing ambiguity rejects. |
| `C2` | Decoders are one-pass and covered by deterministic, mutation, and fuzz evidence. | Untrusted peer bytes. | Truncation, trailing data, header/length mutation, and malformed fields cannot advance state. |
| `C3` | Online pool-hit signing has no presign worker dependency. | Committed Client material already exists. | Only the online worker and online Wasm are created/fetched. |
| `C4` | A real browser waterfall proves zero presign bytes and zero Deriver calls on a pool hit. | Production-emitted artifacts and a seeded encrypted committed record. | Exact asset/request observations satisfy the pool-hit boundary. |
| `C5` | Presign loading occurs only for explicit initial fill or observable refill. | Empty/low pool and configured policy. | Default prewarm and pool hits cannot create the presign worker. |
| `C6` | Public EVM utilities have one owner and one build path selected by measured total size. | Complete artifact comparison. | Duplicate utility leaves and build aliases are deleted. |
| `D1` | Construction, adversary model, checks, assumptions, and oracle manifest are complete. | Pinned NEAR source plus the fixed local construction. | Claims, non-claims, divergence, party views, and evidence are explicit and reviewable. |
| `D2` | New/new and both mixed-role semantic replay modes execute. | Digest-pinned oracle vectors and normalized transcript profile. | All four role-pair cases reach the frozen semantic trace or fail the parity gate. |
| `D3` | Critical malformed, binding, replay, and abort cases are indexed and executable. | Untrusted framing, peer messages, lifecycle commands, and online inputs. | Every indexed invalid case aborts without output or reuse. |
| `D4` | Fixed APIs reject generic topology, cross-role use, invalid order, and reuse at compile time. | Public production API only. | Invalid programs fail to compile; test-only internals stay feature-gated. |
| `D5` | Native/Wasm constant-time analysis records findings and assumptions. | Release artifacts and purpose-built source. | Forbidden variable-time operators are absent from audited secret arithmetic; branch/runtime limits remain non-claims. |
| `D6` | Zeroization, logging, parser, and dependency boundaries have targeted guards. | Production source and resolved graphs. | Secret-bearing values zeroize; logging/generic backend edges and permissive parsing cannot return. |
| `D7` | An independent cryptographer approves the bounded construction before production promotion. | Stable reviewed commit/tree and digest-pinned corpus. | Authenticated approval with no open security-relevant conditions. |
| `E1` | Generic signer-core threshold ECDSA and production NEAR edges are deleted. | Purpose-built cutover complete. | No production caller, feature, manifest, or lockfile restores the generic backend. |
| `E2` | Fixtures, aliases, assets, names, and compatibility readers unique to the old backend are deleted. | Current intended behavior frozen. | Old-only artifacts are absent; current boundary readers reject the obsolete shapes. |
| `E3` | Deleted owners have permanent symbol and dependency guards. | Current source tree and shipping artifacts. | Reintroduction fails the guard suite. |
| `E4` | Clean builds and focused crypto, persistence, bundle, and intended-behavior suites pass. | Current local source and generated artifacts. | All named local gates pass; credential-dependent external store cases are reported separately. |
| `E5` | Final digests, compressed sizes, timings, and zero-old-caller report are recorded. | Reproducible release artifacts. | Evidence identifies exact files, hashes, sizes, timings, and allowed historical/oracle references. |
| `E6` | Local completion is reconciled and deployment work transfers to the deployment plans. | Local gates complete. | ECDSA deployment is owned by `router-ab/deployment.md`; Ed25519 Yao remains separate. |

## Code IR

| ID | Implementation boundary | State, control flow, and access restriction |
| --- | --- | --- |
| `C-DERIVE` | `wasm/router_ab_ecdsa_derivation_client/src/ecdsa_prf_finalizer.rs:17-76`; `crates/router-ab-cloudflare/tests/ecdsa_derivation_activation_boundaries.rs:11-34` | Opens recipient-scoped A/B bundles, pairs them, authenticates the registry, and finalizes role-local output. Activation tests require both bundles before registry-bound combination. |
| `C-PRESIGN` | `crates/router-ab-ecdsa-presign/src/lib.rs:206-415`; `crates/router-ab-ecdsa-presign/src/session.rs:163-557` | Distinct additive-share inputs and consuming Client/SigningWorker session states drive eleven role-fixed rounds. Generic topology parameters are absent. |
| `C-WASM-PS` | `wasm/router_ab_ecdsa_presign_client/src/lib.rs:87-142`; `wasm/router_ab_ecdsa_signing_worker/src/presign.rs:49-104` | Each Wasm package exports one role-specific session wrapper. Its internal fixed session owns ordering and terminal output extraction. |
| `C-ONLINE` | `crates/router-ab-ecdsa-online/src/lib.rs:94-267`; `crates/router-ab-cloudflare/src/signing_worker/mod.rs:943-995` | Available material is consumed into reserved then committed types. Only committed values reach Client share computation or SigningWorker verification/finalization. |
| `C-CLIENT-STORE` | `packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsaPresignMaterialStore.ts:623-1105` | Boundary parsing creates a discriminated persisted state. IndexedDB transactions implement admission, reserve, commit, destructive online take, recovery, and exact-scope retirement. |
| `C-SW-STORE` | `crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs:31-161,340-760` | One serializable command reducer validates scope/revision and couples lifecycle state to matching material variants. Tombstones contain no secret material. |
| `C-POOL` | `crates/router-ab-ecdsa-pool/src/lib.rs:97-700` | Exact identity newtypes, consuming domain states, revisions, mutations, terminal reasons, destructive recovery, and absorbing tombstones define the shared lifecycle. |
| `C-CODEC` | `crates/router-ab-ecdsa-presign/src/codec.rs:39-200,872-1270` | Fixed magic/version/role/round/flags/length parsing precedes field parsing. Deterministic corpus, strict mutations, and seeded mutations exercise every frame decoder. |
| `C-LOADER` | `packages/sdk-web/src/core/signingEngine/workerManager/workerTransport.ts:122-128,555-599`; `packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsa-online-client.worker.ts:1-126` | Default prewarm excludes presign/online. Separate URLs create separate workers. The online worker imports only online Wasm and the encrypted material store. |
| `C-ASSURE` | `crates/router-ab-ecdsa-presign/specs/assurance-ledger-v1.md:46-208`; `docs/evidence/refactor-89/phase-d-bounded-assurance-v1.json` | Normative equations, adversary model, party views, alignment, deliberate divergence, assumption ledger, exact oracle, test counts, and static-analysis results form the bounded security record. |
| `C-DELETE` | `crates/router-ab-ecdsa-near-oracle-tests/tests/production_boundaries.rs:283-321`; `tests/scripts/check-ecdsa-client-worker-split.mjs:24-370` | Current guards assert deleted paths are absent, production manifests exclude generic dependencies, Wasm exports remain role-specific, obsolete stores/operations cannot return, and all 16 review-corpus digests match. |
| `C-DEPLOY` | `docs/router-ab/deployment.md:21-47,67-78,195-199`; `docs/router-ab/ed25519-yao/deployment.md:6-12,248-251` | Strict ECDSA stays off Yao, production uses independently administered A/B accounts, same-account remains development-only, and Yao’s release gate delegates ECDSA deployment. |

Cryptographic function-level alignment is intentionally centralized in
`assurance-ledger-v1.md:119-141`. That ledger maps every fixed layer to concrete
functions and classifies the corrected upstream OT expansion as a deliberate
mismatch rather than concealing it as parity.

## Alignment IR

| Spec ID | Code/test/evidence mapping | Classification | Confidence |
| --- | --- | --- | ---: |
| `A1` | `C-PRESIGN`, `C-WASM-PS`; cross-Wasm handshake at `tests/unit/thresholdEcdsa.presignDistributed.unit.test.ts:349` | `aligned` | 1.00 |
| `A2` | `C-PRESIGN`, `C-WASM-PS`; fixed pool-fill at `tests/unit/thresholdEcdsa.presignDistributed.unit.test.ts:573` | `aligned` | 1.00 |
| `A3` | `C-ONLINE`; finalization call at `crates/router-ab-cloudflare/src/signing_worker/mod.rs:995` | `aligned` | 1.00 |
| `A4` | `C-PRESIGN`, `C-WASM-PS`, `C-DELETE`; 7 presign and 5 online compile-fail fixtures recorded in Phase D evidence | `aligned` | 0.99 |
| `A5` | `assurance-ledger-v1.md:143-158`; 62 focused product tests and 11 intended-behavior contracts in Phase E evidence | `aligned` | 0.99 |
| `B1` | `C-POOL`; `AvailableRecord::reserve` at `src/lib.rs:218`, `ReservedRecord::commit` at line 344, `CommittedRecord::finish` at line 447 | `aligned` | 1.00 |
| `B2` | `C-CLIENT-STORE`; concurrency/burn/failure/recovery/retirement tests at `tests/unit/ecdsaPresignMaterialStore.unit.test.ts:40-779` | `aligned` | 0.99 |
| `B3` | `C-SW-STORE`; normal mutation ordering is covered, while recovery commands have no production caller and revision-2 state retains secret material | `blocked` | 1.00 |
| `B4` | Client destructive take at `ecdsaPresignMaterialStore.ts:940-1015`; SigningWorker commit/finalize path at `router-ab-cloudflare/src/lib.rs:9975-10037` | `aligned` | 0.99 |
| `B5` | `C-DERIVE`; Client identity parsing at `ecdsaPresignMaterialStore.ts:220-232`; SigningWorker scope binding at `ecdsa_pool_lifecycle.rs:21-29` | `aligned` | 0.98 |
| `B6` | Shared reducer and Client adapter tests pass; actual Worker/DO concurrency, terminal-write failure, restart, cancellation, expiry, retirement, and restore evidence is absent | `blocked` | 1.00 |
| `C1` | `C-CODEC`; normative registry at `fixed-driver-v1.md:84-137` | `aligned` | 1.00 |
| `C2` | `C-CODEC`; strict mutation functions at `codec.rs:908-992` and complete corpus at lines 1021-1233 | `aligned` | 1.00 |
| `C3` | `C-LOADER`; worker-isolation guard at `check-ecdsa-client-worker-split.mjs:163-183,274-338` | `aligned` | 1.00 |
| `C4` | Browser waterfall test at `tests/unit/routerAbEcdsaPoolHitWaterfall.unit.test.ts:77-368` | `aligned` | 1.00 |
| `C5` | Prewarm allowlist at `workerTransport.ts:122-128`; refill policy tests at `thresholdEcdsa.presignPoolPolicy.unit.test.ts:96-221` | `aligned` | 0.99 |
| `C6` | Final ownership decision and measured comparison at `refactor-89-slimmer-near-ecdsa.md:313-319`; single-owner guard in `check-ecdsa-client-worker-split.mjs` | `aligned` | 0.99 |
| `D1` | `C-ASSURE`; exact 47-row check inventory and manifest guard recorded in Phase D evidence | `aligned` | 1.00 |
| `D2` | `crates/router-ab-ecdsa-near-oracle-tests/tests/presign_parity.rs`; four cases and trace digest in `assurance-ledger-v1.md:34-44` | `aligned` | 1.00 |
| `D3` | `abort-corpus-v1.md`; executable index `tests/abort_corpus_index.rs`; 44 runtime presign tests in Phase D evidence | `aligned` | 0.99 |
| `D4` | Compile-fail inventory in `assurance-ledger-v1.md:123-140` and counts in Phase D evidence | `aligned` | 1.00 |
| `D5` | `tests/wasm_constant_time.rs`; native/Wasm results and explicit open assumptions in Phase D evidence | `aligned` | 0.96 |
| `D6` | `C-DELETE`; `sourceReview` and dependency/API claims in Phase D evidence | `aligned` | 0.99 |
| `D7` | The original construction review and 16-artifact corpus remain valid. The independent Cloudflare lifecycle review returned `REJECTED` with confidence `0.98`. | `blocked` | 1.00 |
| `E1` | `C-DELETE`; zero production generic backend/dependency counts in Phase E evidence | `aligned` | 1.00 |
| `E2` | `C-DELETE`; strict persisted-record parser and deleted-store guard recorded in Phase E evidence | `aligned` | 0.99 |
| `E3` | `C-DELETE`; both production-boundary and worker-split guards are executable current tests | `aligned` | 1.00 |
| `E4` | `phase-e-local-artifacts-v1.json` records SDK/server builds, focused Rust/Wasm/persistence suites, bundle guard, and all 11 intended-behavior contracts | `aligned` | 0.99 |
| `E5` | `phase-e-local-artifacts-v1.json` and `phase-e-local-timings-v1.json` contain exact artifacts, digests, sizes, medians, and zero-old-caller counts | `aligned` | 1.00 |
| `E6` | `C-DEPLOY`; the active plan states the same ownership at `refactor-89-slimmer-near-ecdsa.md:32-37,409-415` | `aligned` | 1.00 |

## Divergence findings

### `AUD-001` — stale fixed-driver integration status

- Severity: documentation integrity
- Confidence: `1.00`
- Previous state: `fixed-driver-v1.md` still called the canonical codec, Wasm
  adapters, parser mutation corpus, and concrete persistence open.
- Current state: the status and alignment table now describe the integrated
  implementation and direct evidence.
- Resolution: fixed in this audit; the independent-review handoff contains the
  new SHA-256 digest.

### `AUD-002` — stale layer-spec adapter and constant-time blockers

- Severity: documentation integrity
- Confidence: `1.00`
- Previous state: polynomial, base-ROT, random-OT, MTA, online, pool, and
  prototype-security documents retained checkpoint-era “pending adapter” and
  “Wasm analysis open” statements.
- Current state: each layer document distinguishes its layer-local claim from
  the completed composed local path. Static-analysis limits remain explicit
  non-claims rather than obsolete blockers.
- Resolution: fixed in this audit; every normative layer document is now
  individually digest-pinned in the independent-review handoff.

### `AUD-003` — independent construction review

- Severity: resolved production-promotion gate
- Confidence: `1.00`
- Evidence: `docs/security/router-ab-ecdsa-phase4-review.md` records an
  independent `APPROVED` decision. The initial review found `RAR-01`; the
  implementation added a two-role commit/reveal public coin without another
  network round trip, and the same reviewer approved the remediated corpus.
- Resolution: closed for the digest-pinned construction snapshot with a
  16-artifact table and independently verified 122-file manifest. The later
  registration-package split preserves all 16 corpus digests. The current
  lifecycle receipt supersedes the older documents' Cloudflare-adapter
  completeness statements without altering the immutable corpus.

### `AUD-004` — registration package split and rejected lifecycle delta

- Severity: formal-closure blocker
- Confidence: `1.00`
- Evidence:
  `docs/evidence/refactor-89/registration-package-delta-review-v1.md`
  records the sound `ecdsa_registration_client` ownership split, narrowed
  deferred export package, operation-selective loading, asset paths, guards,
  and browser waterfall.
- Blocking result:
  `docs/evidence/refactor-89/cloudflare-signing-lifecycle-security-review-v1.md`
  records the completed lifecycle review and its `REJECTED` decision. Open
  findings cover material-bearing committed persistence, unreachable recovery,
  incomplete failure/expiry/retirement burning, rollback revival, and a
  missing 60-second lease cap. The separately reviewed same-account Ed25519 Yao
  adapter now has a normal durable one-use claim, while crash/expiry/rollback
  terminality and single-copy SigningWorker material remain incomplete.
- Resolution required for Refactor 89: remediate ECDSA findings `CF-LC-001`,
  `CF-LC-002`, `CF-LC-003`, and `CF-LC-005`, execute the concrete adapter fault
  matrix, and obtain independent approval of the exact remediated bytes.
  Ed25519 findings `CF-LC-004` and `CF-LC-006` remain in the Yao deployment
  gate. The
  16-artifact construction corpus remains byte-identical.

## Deployment alignment

The local refactor is topology-neutral and supports both deployment profiles.
Production promotion uses `router_ab_cloudflare_separate_accounts_v1` with
independently administered Deriver A and B accounts. Same-account deployment is
limited to development, staging, and benchmarks by
`docs/router-ab/deployment.md:35-47`. ECDSA uses strict Router A/B threshold-PRF
derivation plus additive secp256k1 shares and has no Yao dependency
(`router-ab/deployment.md:21-33`). The separate Ed25519 Yao release gate
explicitly delegates ECDSA rollout at `docs/router-ab/ed25519-yao/deployment.md:6-12`.

The ECDSA deployment requirements still open in
`docs/router-ab/deployment.md:195-199` are `excluded_deployment` for this local
audit. They remain mandatory before the system is called production-ready.

## Decision

The purpose-built fixed 2-of-2 ECDSA construction is complete at the local
cryptographic boundary. Formal Refactor 89 closure remains blocked on B3, B6,
and D7. The lifecycle review has been performed and rejected, so restoration
of an old manifest is no longer a valid closure route. The registration package
split itself is sound and all 16 cryptographic corpus digests still match. The
current lifecycle receipt controls the newer Cloudflare adapter status.
Deployment promotion remains owned by `docs/router-ab/deployment.md`. No claim
in this audit upgrades oracle parity into a security proof or treats
same-account development as independent-account security.
