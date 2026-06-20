# Router A/B Spec-To-Code Compliance Audit - 2026-06-16

## 1. Executive Summary

Verdict at audit time: the implementation was directionally aligned with the Router A/B architecture for local Ed25519 and ECDSA-HSS normal signing, including one-use nonce/presignature handling and role-separated server material. It was not deploy-ready for strict Cloudflare production.

The original audit found two release-blocking implementation gaps:

1. P1: private SigningWorker and Deriver endpoints are configured with public `workers.dev` exposure, while their strict private dispatchers do not enforce a Router-only service-auth boundary.
2. P1: ECDSA explicit export lacks the export-distinct audit or telemetry event required by the ECDSA-HSS export spec.

Remediation status as of the follow-up implementation recorded in Section 17:
the P1 private-worker boundary issue, P1 ECDSA explicit export audit issue, P2
Ed25519 finalize group-key hardening issue, P3 stale-checklist drift, and P3
Router A/B ECDSA bridge naming issue are fixed locally. The only open item from
this audit is deployed strict Cloudflare browser/runtime evidence, which is
deferred to the deployment phase.

## 2. Scope And Inputs

Audit date: 2026-06-16.

Workspace: `/Users/pta/Dev/rust/seams-sdk`.

Git HEAD at audit start: `a4382e6ed77cb85d0a8d0fb3798201ff493c1383`.

The worktree was dirty during this audit. The review includes the current uncommitted implementation, including Router A/B ECDSA-HSS files, deploy-prep changes, and SDK signing changes.

Primary specs reviewed:

- [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md)
- [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md)
- [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md)
- [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md)
- [crates/ecdsa-hss/specs/protocol.md](/Users/pta/Dev/rust/seams-sdk/crates/ecdsa-hss/specs/protocol.md)
- [crates/ecdsa-hss/specs/export.md](/Users/pta/Dev/rust/seams-sdk/crates/ecdsa-hss/specs/export.md)

Primary implementation areas reviewed:

- [crates/router-ab-cloudflare/src/strict_worker.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/strict_worker.rs)
- [crates/router-ab-cloudflare/src/lib.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs)
- [crates/router-ab-cloudflare/src/durable_object.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/durable_object.rs)
- [crates/router-ab-core/src/protocol/ecdsa_hss.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs)
- [packages/shared-ts/src/utils/routerAbEcdsaHss.ts](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts)
- [packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaHssPresignBridge.ts](/Users/pta/Dev/rust/seams-sdk/packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaHssPresignBridge.ts)
- [packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts)
- [packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts)
- [packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts)

## 3. Spec Corpus

The ECDSA-HSS plan makes the ECDSA work release-blocking for full Router A/B deployment. It states that Cloudflare deploy remains blocked until ECDSA registration, activation, normal signing, export, recovery/refresh, and validation are either implemented or the ECDSA public surface is explicitly removed from the release scope. See [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:15).

The normal ECDSA hot path is specified as `Client -> Router -> SigningWorker -> Router -> Client`; Deriver A and Deriver B are outside the per-signature hot path. See [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:27).

The server-blindness invariant says production server paths must never reconstruct canonical `x`, return `privateKeyHex`, or accept both `y_client` and `y_server` in the same request. See [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:53) and [crates/ecdsa-hss/specs/protocol.md](/Users/pta/Dev/rust/seams-sdk/crates/ecdsa-hss/specs/protocol.md:5).

The ECDSA protocol version and transcripts must bind ECDSA-specific purpose strings, secp256k1 keys, address, context, Deriver roles, SigningWorker identity, export authorization digest, and replay nonce. See [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:73) and [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:160).

The normal-signing prepare/finalize path requires Router admission, replay reserve, SigningWorker presignature pool reservation, request-bound one-use presignature records, finalize take, and response. See [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:136).

The public/private boundary says public Router routes accept typed registration, bootstrap, export, recovery, refresh, prepare, and finalize. The private Deriver boundary accepts only Router-forwarded role-encrypted material. See [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:116).

The explicit ECDSA export spec allows a server-side export share to be released only to an authorized client flow, and requires an export-distinct audit or telemetry event. The server export response may contain `x_relayer_export` plus public transcript/auth metadata, and must never contain canonical `x`, `privateKeyHex`, or client share material. See [crates/ecdsa-hss/specs/export.md](/Users/pta/Dev/rust/seams-sdk/crates/ecdsa-hss/specs/export.md:8), [crates/ecdsa-hss/specs/export.md](/Users/pta/Dev/rust/seams-sdk/crates/ecdsa-hss/specs/export.md:27), and [crates/ecdsa-hss/specs/export.md](/Users/pta/Dev/rust/seams-sdk/crates/ecdsa-hss/specs/export.md:183).

The single-session release plan records that Ed25519 presign-pool UX work is implemented locally, while pool-hit/pool-miss latency, deployed strict browser evidence, CORS preflight behavior, and runtime evidence remain open. See [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:1458), [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:1478), and [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:1487).

## 4. Spec-IR

The normalized requirements are:

1. Router is the only public protocol boundary for client operations.
2. Deriver A, Deriver B, and SigningWorker private routes are reachable only through Router-mediated internal calls.
3. Deriver A and Deriver B derive and forward server-side signing material; they do not participate in each normal signature.
4. SigningWorker owns activated server signing material and one-use signing nonce or presignature state.
5. Ed25519 and ECDSA normal signing require prepare/finalize binding to the exact request context.
6. Nonces and presignatures are single-use and must be consumed atomically on valid take.
7. ECDSA server paths never reconstruct canonical ECDSA private scalar `x`, never return `privateKeyHex`, and never accept both client and server scalar inputs in the same production request.
8. ECDSA export is explicit, authorized, nonce-bound, auditable, and returns only the server export share plus public metadata.
9. Policy, quota, replay, and abuse controls are enforced through Router admission and Durable Object state.
10. Deployed readiness requires actual Cloudflare upload, deployed browser evidence, CORS evidence, cold/hot latency evidence, logs/metrics evidence, and worker startup evidence.
11. Public SDK APIs should stay simple; Router-internal complexity should absorb ceremony/session details.
12. Legacy naming and V1 cleanup are post-functional tasks, with compatibility only at persistence/request boundaries.

## 5. Code-IR

The public strict Router path dispatches allowlisted public routes and loads configured JWT/JWKS verification. See [crates/router-ab-cloudflare/src/strict_worker.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/strict_worker.rs:190), [crates/router-ab-cloudflare/src/strict_worker.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/strict_worker.rs:255), and [crates/router-ab-cloudflare/src/lib.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs:10509).

The strict SigningWorker dispatcher directly handles private activation, Ed25519 prepare/finalize, Ed25519 presign-pool, ECDSA presignature-pool put, ECDSA prepare, and ECDSA finalize routes. The dispatcher constructs runtime state and routes by path. See [crates/router-ab-cloudflare/src/strict_worker.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/strict_worker.rs:1250).

The ECDSA public prepare/finalize path verifies Wallet Session credentials, does Router admission/replay work, and forwards to the SigningWorker. See [crates/router-ab-cloudflare/src/lib.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs:11125) and [crates/router-ab-cloudflare/src/lib.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs:11200).

The SigningWorker ECDSA prepare path loads active state and material, takes a pool presignature, rerandomizes, converts it to a request-bound record, and stores the bound record. See [crates/router-ab-cloudflare/src/lib.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs:14280) and [crates/router-ab-cloudflare/src/lib.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs:1590).

The SigningWorker ECDSA finalize path recomputes prepare and signing digests, takes the bound presignature record, and finalizes the signature. See [crates/router-ab-cloudflare/src/lib.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs:14635).

Durable Object storage validates exact lookup context and deletes records on take for Ed25519 round-1 state, Ed25519 presign pool records, ECDSA bound presignatures, and ECDSA presign pool records. See [crates/router-ab-cloudflare/src/durable_object.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/durable_object.rs:5569), [crates/router-ab-cloudflare/src/durable_object.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/durable_object.rs:5613), [crates/router-ab-cloudflare/src/durable_object.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/durable_object.rs:5660), and [crates/router-ab-cloudflare/src/durable_object.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/durable_object.rs:5710).

Cloudflare server output material validation accepts only `x_server_base` material for the server role. See [crates/router-ab-cloudflare/src/lib.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs:2200) and [crates/router-ab-cloudflare/src/lib.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs:17750).

ECDSA source guards check that Cloudflare Router A/B ECDSA code does not expose canonical export keys, `privateKeyHex`, raw root material, or presignature scalar shares in public or persistence receipts. See [crates/router-ab-cloudflare/tests/source_guards.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/tests/source_guards.rs:1400).

The current AuditSink type has only a gate-decision event, and the Cloudflare preloaded host sink ignores recorded events. See [crates/router-ab-core/src/protocol/engine/host.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/engine/host.rs:13) and [crates/router-ab-cloudflare/src/lib.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs:4802).

## 6. Alignment-IR

Aligned areas:

1. Normal signing topology is implemented through Router admission and SigningWorker prepare/finalize paths.
2. Deriver A/B are outside the hot normal-signing path for ECDSA.
3. ECDSA server-blindness is enforced in the production material shape and guarded by source checks.
4. One-use Ed25519 and ECDSA nonce/presignature semantics are implemented with exact validation and delete-on-take behavior.
5. ECDSA prepare records are request-bound before finalization.
6. Concrete JWKS verification and Durable Object policy/quota/abuse machinery exist, making older unchecked spec items stale.
7. Ed25519 signature-only NEP-413 and delegate paths are implemented through Router A/B before fallback, making the older unchecked spec item stale.
8. The local release gates and dry-run packaging gates are green.

Original gaps:

1. The private worker deploy boundary is not enforced by the current Cloudflare config and strict private dispatcher.
2. ECDSA export lacks required export-distinct audit/telemetry.
3. Deployed Cloudflare evidence remains open.
4. Ed25519 finalize still accepts a client-supplied group public key.
5. Docs and naming have drifted behind the newer implementation.

Follow-up status: items 1, 2, 4, and 5 are fixed locally and validated in
Section 17. Item 3 remains open as deployed-runtime evidence and is tracked in
the deployment phase.

## 7. Divergence Findings

### P1 - Private worker endpoints are configured as publicly reachable

Type: concrete divergence.

Confidence: 0.92.

Requirement: Router is the public boundary; Deriver and SigningWorker private boundaries accept Router-forwarded internal material. See [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:116) and [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:27).

Observed code: the strict SigningWorker entrypoint directly dispatches private routes, including activation, normal signing prepare/finalize, presignature-pool put, ECDSA prepare, and ECDSA finalize. See [crates/router-ab-cloudflare/src/strict_worker.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/strict_worker.rs:1250).

Observed deployment config: the SigningWorker Wrangler config sets `workers_dev = true` for base, staging, and production environments. See [crates/router-ab-cloudflare/wrangler.signing-worker.toml](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/wrangler.signing-worker.toml:1), [crates/router-ab-cloudflare/wrangler.signing-worker.toml](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/wrangler.signing-worker.toml:29), and [crates/router-ab-cloudflare/wrangler.signing-worker.toml](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/wrangler.signing-worker.toml:47). The Deriver worker configs also set public `workers.dev` exposure. See [crates/router-ab-cloudflare/wrangler.signer-a.toml](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/wrangler.signer-a.toml:1) and [crates/router-ab-cloudflare/wrangler.signer-b.toml](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/wrangler.signer-b.toml:1).

Impact: public callers can reach routes that are architecturally private. Cryptographic checks, active-state checks, and request digests reduce key-extraction risk, but the trust boundary is still wrong. The exposed surface includes stateful routes such as presignature-pool put and activation-related private routes, creating a meaningful DoS, state-pollution, and boundary-bypass risk.

Fix:

1. Set non-Router workers to private-by-default in staging and production by disabling public `workers.dev` exposure and removing public routes for Deriver A, Deriver B, and SigningWorker.
2. Add a strict internal service-auth check to every non-Router entrypoint, such as an HMAC/JWT header injected by Router service-binding calls or a Cloudflare Access/service-token equivalent.
3. Add release-gate checks that fail if staging/production non-Router worker configs expose `workers_dev = true` or public routes.
4. Add route tests that direct external requests to private worker handlers fail before route-specific body parsing.

### P1 - ECDSA explicit export lacks required export audit/telemetry

Type: concrete divergence.

Confidence: 0.88.

Requirement: ECDSA export must emit an export-distinct audit or telemetry event with operation, key, auth, decision, and reason fields, excluding raw shares, scalar material, decrypted keys, and signatures. See [crates/ecdsa-hss/specs/export.md](/Users/pta/Dev/rust/seams-sdk/crates/ecdsa-hss/specs/export.md:183).

Observed code: the Router ECDSA export handler validates request/auth, admission, replay, lifecycle, and Deriver calls. See [crates/router-ab-cloudflare/src/lib.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs:10737). The audit event enum currently only models `GateDecision`, and the Cloudflare AuditSink ignores events. See [crates/router-ab-core/src/protocol/engine/host.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/engine/host.rs:13) and [crates/router-ab-cloudflare/src/lib.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs:4802).

Impact: export can succeed without the distinct evidence trail required by the spec. That weakens incident response and removes a required release-control signal for the highest-risk ECDSA operation.

Fix:

1. Add an `EcdsaHssExportDecision` audit event with export operation id, key id/address, project/session scope, authenticated principal/session id, decision, reason code, and replay nonce.
2. Emit success and failure decisions in the public Router export handler. Emit failure before share release where applicable and success after authorized release.
3. Route the event to structured Worker logs or the existing audit sink with redaction.
4. Add source guards that forbid scalar/share material, `privateKeyHex`, decrypted key bytes, and signatures in export audit events.
5. Add unit/route coverage for export allowed, denied, replayed, and malformed cases.

### P2 - Deployed strict Cloudflare evidence is still open

Type: evidence gap.

Confidence: 0.95.

Requirement: release readiness requires actual upload/deploy evidence, deployed browser evidence for `/v2/router-ab/ed25519/sign/prepare` and `/v2/router-ab/ed25519/sign`, configured-origin success, rejected-origin behavior, preflight behavior, cold/hot latency, logs/metrics, Deriver non-invocation on normal signing, and startup evidence. See [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:1478), [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:1487), and [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:3176).

Observed evidence: local release gates and dry-run packaging pass, but the recorded startup-latency report is dry-run mode and has `startupTimeMs` as `null`, which is expected for that evidence type. Startup reports are generated as ignored timestamped JSON under `crates/router-ab-cloudflare/reports/startup-latencies/`.

Impact: the implementation can be described as locally and dry-run validated. It should not be described as deployed or production-ready.

Fix:

1. Complete actual Cloudflare upload with real Router/Deriver/SigningWorker deploy inputs.
2. Capture browser evidence for configured-origin success, rejected-origin failure, and preflight behavior.
3. Record pool-hit and pool-miss latency separately, including CORS preflight behavior.
4. Capture logs/metrics showing Deriver A/B are not invoked for normal signing.
5. Record actual worker startup evidence after deploy.

### P2 - Ed25519 finalize still accepts client-supplied `group_public_key`

Type: hardening gap.

Confidence: 0.80.

Requirement: the spec keeps a hardening item to review and either remove client-supplied `group_public_key` or prove it is harmless through transcript binding and validation. See [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:1581).

Observed code: the SDK finalize protocol still includes a client-provided `group_public_key`, and the Cloudflare finalizer passes the decoded protocol value into role-separated Ed25519 finalization. See [packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts:154) and [crates/router-ab-cloudflare/src/lib.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs:1943).

Mitigating code: the Ed25519 role-signing finalizer validates the server share, verifying shares, group key relationship, and final signature. See [crates/ed25519-hss/src/role_signing.rs](/Users/pta/Dev/rust/seams-sdk/crates/ed25519-hss/src/role_signing.rs:198) and [crates/ed25519-hss/src/role_signing.rs](/Users/pta/Dev/rust/seams-sdk/crates/ed25519-hss/src/role_signing.rs:365).

Impact: this is lower risk than the two P1 issues because the crypto checks reject inconsistent key/share combinations. The remaining concern is protocol clarity and identity binding: active SigningWorker state should own the account/group identity rather than trusting the client to repeat it correctly.

Fix:

1. Derive or load `group_public_key` from active SigningWorker material or Router session scope.
2. Remove the public finalize field after internal derivation exists.
3. Add negative vectors proving mismatched account/group identity is rejected before nonce consumption.

### P3 - Older spec checkboxes are stale

Type: documentation drift.

Confidence: 0.86.

Observed drift: [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:1570) still lists signature-only Ed25519 Router A/B flows as unchecked, but [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:958) and the SDK flow code show NEP-413 and delegate actions are routed through Router A/B before fallback. See [packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts:302) and [packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts:442).

Observed drift: [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:1627) still lists concrete JWKS JWT verifier and DO-backed policy/quota/abuse as unchecked, but implementation and tests exist. See [crates/router-ab-cloudflare/src/lib.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs:10509), [crates/router-ab-cloudflare/src/durable_object.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/durable_object.rs:5990), and [crates/router-ab-cloudflare/tests/bindings.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/tests/bindings.rs:10090).

Impact: stale unchecked items make the release tail harder to read and can cause duplicate implementation work.

Fix: reconcile the older signer/spec docs against the single-session and ECDSA docs. Mark implemented items as complete with code/test evidence, and leave only active release blockers.

### P3 - ECDSA bridge still exposes legacy `relayer` naming

Type: maintainability drift.

Confidence: 0.82.

Requirement: the ECDSA plan says new Router A/B ECDSA protocol names should use `server` terminology and `*_server` variables until the ECDSA version freezes legacy names. See [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:98).

Observed code: the new shared ECDSA bridge still exposes `relayerKeyId` in Router A/B ECDSA presignature share records, and the server bridge wraps legacy `ThresholdEcdsaPresignatureRelayerShareRecord`. See [packages/shared-ts/src/utils/routerAbEcdsaHss.ts](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:54), [packages/shared-ts/src/utils/routerAbEcdsaHss.ts](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:287), and [packages/sdk-server-ts/src/core/ThresholdService/routerAbEcdsaHssPresignBridge.ts](/Users/pta/Dev/rust/seams-sdk/packages/sdk-server-ts/src/core/ThresholdService/routerAbEcdsaHssPresignBridge.ts:1).

Impact: this appears to be naming drift rather than a cryptographic behavior change. It keeps obsolete role language in new Router A/B boundary types.

Fix: rename new Router A/B ECDSA boundary fields to `serverKeyId` or equivalent, isolate unavoidable legacy adapters behind request/persistence boundaries, and update type fixtures to reject new uses of `relayer` in Router A/B ECDSA protocol types.

## 8. Security Boundary Assessment

The logical cryptographic boundary is mostly sound: Derivers produce role-specific server material, SigningWorker owns active server signing material, and the client produces client-side signing material. The ECDSA source guards and material validation meaningfully support the server-blindness invariant.

The deploy boundary is the weak point. A private service-binding architecture must be enforced by deployment configuration and entrypoint checks. Public `workers.dev` exposure on private workers breaks that property even when Router uses service bindings for normal calls.

## 9. Nonce And Presignature Reuse Assessment

The one-use behavior is implemented correctly in the reviewed storage paths. Ed25519 round-1 records, Ed25519 presign pool records, ECDSA bound presignature records, and ECDSA presign pool records are validated against exact lookup context and deleted on successful take. See [crates/router-ab-cloudflare/src/durable_object.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/durable_object.rs:5569), [crates/router-ab-cloudflare/src/durable_object.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/durable_object.rs:5613), [crates/router-ab-cloudflare/src/durable_object.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/durable_object.rs:5660), and [crates/router-ab-cloudflare/src/durable_object.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/durable_object.rs:5710).

The remaining risk is exposure of private worker routes that can write or attempt to write state outside Router admission. The core take semantics still look sound. The exposed private routes weaken the operational protection around the pool.

## 10. Export And Audit Assessment

The ECDSA export data boundary largely follows the spec: export returns server export share material and public metadata rather than canonical private key material. The missing part is the required export-distinct audit/telemetry trail.

The current audit API is too narrow for export compliance. It should be extended with explicit export decision events rather than treating export as an ordinary gate decision.

## 11. Deployment Readiness Assessment

Current status at audit time:

- Local release blocker check: passing.
- Cloudflare source guards: passing.
- ECDSA-HSS core protocol tests: passing.
- Focused TypeScript Router A/B unit tests: passing.
- Dry-run packaging: passing.
- Actual Cloudflare upload: open.
- Deployed strict browser evidence: open.
- Runtime latency/log/metrics evidence: open.
- Worker startup evidence from deployed environment: open.

Follow-up status: the P1 private-worker exposure and P1 export audit gaps are
fixed locally. Deploy readiness remains blocked until actual deployed evidence
is captured.

## 12. Documentation Drift

The docs are mostly useful, but the source of truth is split across the older signer/spec docs, the single-session plan, and the ECDSA plan. The older signer/spec docs still imply some Ed25519-only readiness and contain stale unchecked tasks.

Recommended doc cleanup:

1. Make [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md) the Ed25519 single-session/release-tail tracker.
2. Make [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md) the ECDSA-HSS release blocker tracker.
3. Treat [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md) and [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md) as historical specs plus status summaries, with links to the active trackers.
4. Remove stale unchecked items only after adding code/test evidence links.

## 13. Validation Run

Commands run during this audit:

```sh
rtk pnpm router:deploy:check
```

Result: pass. The release blocker check reported Router A/B release blockers clear.

```sh
rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards
```

Result: pass. `36 passed`.

```sh
rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test ecdsa_hss_protocol
```

Result: pass. `52 passed`.

```sh
rtk pnpm -C tests test:unit -- ./unit/routerAbEcdsaHssPresignBridge.unit.test.ts ./unit/routerAbNormalSigningValidation.unit.test.ts ./unit/routerAbNormalSigningPolicy.unit.test.ts
```

Result: pass. `11 passed`.

One direct Playwright invocation was attempted against unit test files and failed before test execution due repository alias resolution and test-discovery setup. The corrected repository test command above passed.

## 14. Confidence And Ambiguities

High confidence:

- One-use nonce/presignature semantics are implemented in the reviewed storage paths.
- ECDSA server-blindness is protected by material typing and source guards.
- Local release gates and focused protocol tests pass.
- Private worker `workers.dev` exposure is present in the checked Wrangler configs.
- Export-distinct audit/telemetry is missing from the reviewed audit/event path.

Medium confidence:

- The private-worker exposure finding applies to both SigningWorker and Deriver workers. The code and configs support this conclusion, but deployed Cloudflare account-level routing settings were not inspected.
- `group_public_key` is a hardening issue rather than a current exploit. The finalizer validates key/share consistency, but active-state ownership of group identity would be cleaner.

Ambiguities:

- Cloudflare account-level Access policies or manual dashboard route settings could reduce exposure outside the repo. The repo config and code should enforce the boundary independently.
- The audit did not perform a live deployed Worker request because deploy inputs and deployed URLs were not available in this turn.

## 15. Recommended Fix Order

1. Fix private worker exposure and add a release gate for non-Router public routes.
2. Add ECDSA export audit/telemetry events and redaction/source guards.
3. Capture actual Cloudflare deployed evidence and update the release tracker.
4. Remove or internally derive Ed25519 `group_public_key` from active state.
5. Reconcile stale older docs against the active single-session and ECDSA plans.
6. Run the final Router A/B legacy naming cleanup, including `relayer` to `server` in new ECDSA boundary types.

## 16. Appendix: Evidence Index

Spec evidence:

- ECDSA release-blocking scope: [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:15)
- ECDSA normal-signing topology: [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:27)
- ECDSA server-blindness: [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:53)
- ECDSA public/private boundary: [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:116)
- ECDSA one-use normal signing: [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:136)
- ECDSA export audit requirement: [crates/ecdsa-hss/specs/export.md](/Users/pta/Dev/rust/seams-sdk/crates/ecdsa-hss/specs/export.md:183)
- Deployed evidence open: [docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/seams-sdk/docs/router-a-b-SPEC.md:1478)

Code evidence:

- Strict SigningWorker private dispatcher: [crates/router-ab-cloudflare/src/strict_worker.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/strict_worker.rs:1250)
- SigningWorker `workers_dev`: [crates/router-ab-cloudflare/wrangler.signing-worker.toml](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/wrangler.signing-worker.toml:1)
- Router JWT/JWKS verifier loading: [crates/router-ab-cloudflare/src/lib.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs:10509)
- ECDSA public prepare: [crates/router-ab-cloudflare/src/lib.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs:11125)
- ECDSA SigningWorker prepare from pool: [crates/router-ab-cloudflare/src/lib.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs:14280)
- ECDSA SigningWorker finalize: [crates/router-ab-cloudflare/src/lib.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs:14635)
- One-use storage takes: [crates/router-ab-cloudflare/src/durable_object.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/durable_object.rs:5569)
- Current audit event shape: [crates/router-ab-core/src/protocol/engine/host.rs](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/engine/host.rs:13)

## 17. Remediation Status - 2026-06-16

Fixed in follow-up implementation:

- P1 private worker exposure: non-Router strict Wrangler configs now set
  `workers_dev = false`, strict private Deriver/SigningWorker dispatchers
  require internal service-auth before runtime construction or body parsing,
  Router service-binding calls attach `x-router-ab-internal-service-auth`, and
  `rtk pnpm router:deploy:check` now gates those config/source invariants.
- P1 ECDSA explicit export audit: Router export emits
  `EcdsaHssExplicitExportDecision` for forwarded, stopped, and rejected
  outcomes. Source guards keep export audit events free of scalar/share,
  decrypted-key, signature, `privateKeyHex`, and raw root material.
- P2 Ed25519 finalize group key: v2 normal-signing finalize and presign
  pool-hit finalize wire material no longer accepts `group_public_key`. Strict
  SigningWorker finalize loads the account/group public key from active
  SigningWorker state, and core boundary parser tests reject client-supplied
  `group_public_key`.
- P3 stale docs and ECDSA bridge naming: older signer checklists now mark
  implemented Router A/B signature-only Ed25519 flows and JWKS/DO-backed
  admission stores as complete. The new Router A/B ECDSA-HSS presignature bridge
  uses `serverKeyId`, with legacy `relayerKeyId` conversion isolated at the
  existing threshold-ECDSA store adapter.

Still open:

- Deployed strict Cloudflare browser/runtime evidence remains deferred until the
  deployment phase. Local, source, package, and strict-entrypoint checks pass.

No local implementation finding from this historical audit remains open.

Validation:

- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test normal_signing_v2`
  passed with 20 tests.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`
  passed with 38 tests.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings`
  passed with 273 tests.
- `rtk pnpm -C packages/sdk-web type-check` passed.
- `rtk pnpm -C packages/sdk-server-ts type-check` passed.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/routerAbEcdsaHssPresignBridge.unit.test.ts ./unit/thresholdEcdsa.presignDistributed.unit.test.ts --reporter=line`
  passed with 19 tests.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`,
  `strict-worker-signing-worker-entrypoint`, `strict-worker-signer-a-entrypoint`,
  and `strict-worker-signer-b-entrypoint` passed.
- `rtk pnpm router:deploy:check` passed.
