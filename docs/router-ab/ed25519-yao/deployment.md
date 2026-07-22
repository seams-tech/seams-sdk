# Yao A/B Deployment and Production Release Plan

Status: **production lifecycle validation pending**

This file owns only the high-impact path from the completed local Yao A/B
implementation to a production release decision. Local implementation evidence
stays in [router-ab/ed25519-yao/implementation-plan.md](./implementation-plan.md). General Router A/B and ECDSA deployment
work stays in [router-ab/deployment.md](../deployment.md).

The canonical Cloudflare benchmark deployment uses the same-account Service
Binding WebSocket artifact. This plan retains the 16 completed deployment
decisions and implementation tasks plus one production lifecycle release
blocker. Other unfinished follow-up work was removed rather than carried as a
release backlog. Acceptance criteria describe outcomes and are not separate
tasks.

## Completed local and same-account evidence

The local gate already covers complete activation and export circuits, role
separation, realistic OT and wire bytes, bounded streaming, registration,
recovery, refresh, exact export, post-refresh signing, source isolation, and
constant-time code-generation checks. `phase13a:local-preflight` remains the
canonical local evidence check.

Same-account deployment checkpoint (2026-07-16):

- endpoint: `https://yaos-ab-benchmark.seams.sh/benchmark/activation`;
- Deriver A version: `97aa6e79-4ab3-4a23-9c3f-0a68a0ecb134`;
- Deriver B version: `b3940de8-1162-4221-80a6-7639a01ba515`;
- deployment identity: `23e830706f862fe346b8c238bd8a4eb9`;
- two live protocol smoke requests passed. The warm request completed in
  252 ms of Worker protocol time; B's first response byte reached A at 12 ms,
  before A closed its request direction at 241 ms.

Same-account HTTP backpressure experiment (2026-07-17):

- A bounded four-envelope queue increased the application buffer ceiling from
  one 131,180-byte envelope to four envelopes, approximately 525 KiB, while
  preserving the exact 2,222,584-byte wire profile;
- a 30-pair campaign recorded zero failures. The four-envelope Service Binding
  path measured 298 ms p50, 509 ms p95, 606 ms p99, 313.3 ms mean, and 188.9 ms
  mean table-drain time. The unchanged cross-account WebSocket control measured
  207 ms p50, 383 ms p95, 443 ms p99, and 242.5 ms mean;
- widening the Rust channel did not remove the HTTP stream-drain latency. The
  losing four-envelope variant was deleted and the one-envelope bound restored;
- restored versions are Deriver A `59b5a1cb-b754-4784-b8c3-f3cdc7effebc` and
  Deriver B `9455e52b-52b5-4a7e-b53f-878eb230ab53`.

Same-account Service Binding WebSocket experiment (2026-07-17):

- the cross-account WebSocket role loop, envelope encoding, single-envelope
  application ownership, directional EOF, timeout, and wire accounting were
  reused unchanged. Only connection establishment changed to a WebSocket
  upgrade fetched through the `DERIVER_B` Service Binding;
- isolated versions are Deriver A `387cfe41-dfb0-4da7-a7ac-f0e1b191598f` and
  Deriver B `adea6448-6141-4768-b372-378a1a0fd018`;
- 33 consecutive stress ceremonies completed with zero failures and preserved
  the exact 2,222,584-byte A/B transport total;
- a 60-pair interleaved campaign against the unchanged one-envelope HTTP-stream
  control recorded zero failures for both transports. Service Binding
  WebSocket measured 202 ms p50, 230 ms p95, 236 ms p99, and 204.7 ms mean.
  HTTP stream measured 234 ms p50, 258 ms p95, 318 ms p99, and 232.5 ms mean;
- each WebSocket block of ten remained within 194-203 ms p50 and 222-236 ms
  p95. The paired result favors the WebSocket upgrade by 32 ms at p50, 28 ms
  at p95, and 27.8 ms on mean protocol time.

Same-account native Workers RPC stream experiment (2026-07-17):

- Deriver A called a fixed `WorkerEntrypoint` method through its private Service
  Binding and transferred one byte-oriented `ReadableStream` plus one
  byte-oriented `WritableStream`. Both directions use Cloudflare
  `IdentityTransformStream`; every A-to-B write awaits the native writable
  backpressure promise;
- deployment identity: `7a53ae90039de55aa701bc1b77831901`;
- isolated Deriver A version:
  `47f6c933-46ae-4692-909e-a4b703ce166f`;
- isolated Deriver B version:
  `d3de93d1-5102-4d70-8341-86a090e898b7`;
- endpoint:
  `https://ed25519-yao-ab-benchmark-a-rpc.n6378056.workers.dev/benchmark/activation`;
- local and deployed ceremonies completed with the unchanged role machines and
  exact 2,222,584-byte transport ledger. The local completion measured 216 ms;
- a 40-pair alternating deployed campaign recorded zero failures. Every RPC
  and WebSocket sample entered through NRT. RPC measured 231 ms p50, 249 ms
  p95, 264 ms p99, and 227.5 ms mean Worker protocol time. The canonical
  WebSocket control measured 198 ms p50, 222 ms p95, 232 ms p99, and 200.8 ms
  mean;
- client-observed RPC wall time measured 464 ms p50, 522 ms p95, 582 ms p99,
  and 470.6 ms mean. WebSocket measured 412 ms p50, 510 ms p95, 536 ms p99,
  and 420.0 ms mean;
- native RPC therefore lost the paired comparison by 33 ms at p50, 27 ms at
  p95, 32 ms at p99, and 26.7 ms on mean Worker protocol time. It remains an
  isolated benchmark candidate and is not a production fallback.

Transport adapter boundary (2026-07-17):

- Deriver A now has one compile-time generic protocol driver,
  `run_deriver_a<T: YaoDuplexTransport>`. The driver alone owns the Yao role
  machine, directional EOF state, message validation, and completion;
- HTTP streams and WebSocket implement the transport contract directly.
  Workers RPC transfers native streams and normalizes them into the same
  stream adapter before entering the driver;
- the transport contract contains protocol messages, directional closure, and
  byte accounting. Cloudflare placement evidence stays outside it. This keeps
  WebSocket and HTTP adapters portable to other server platforms while the
  Workers RPC binding remains an explicitly Cloudflare-specific adapter;
- each Worker artifact selects one adapter at compile time. There is no runtime
  transport negotiation, fallback, or duplicate Yao role loop;
- a source guard requires one Deriver A role-machine construction site and all
  three feature builds pass the same exact-wire tests and local ceremony smoke;
- the refactor changes no browser/client package. Generated Deriver A JS glue
  is byte-identical for all three artifacts. Relative to the pre-refactor
  server artifacts, HTTP-stream Wasm is 1,443 bytes smaller, WebSocket Wasm is
  3,043 bytes smaller, and experimental RPC Wasm is 7,777 bytes larger. The
  RPC increase is server-only.

Canonical promotion checkpoint (2026-07-17):

- endpoint: `https://yaos-ab-benchmark.seams.sh/benchmark/activation`;
- deployment identity: `8cd5f7b0531caafe8849270a217f34c5`;
- Deriver A version: `a8104a8c-b5dc-4095-b580-6cc8736a5ed9`;
- Deriver B version: `dfb117cf-4760-4808-9f55-b0e321be75aa`;
- the checked-in canonical A/B Wrangler configs and package scripts build the
  Service Binding WebSocket roles. The duplicate candidate configs and scripts
  were deleted;
- 41 post-cutover ceremonies completed with zero failures and exact 2,222,584
  byte accounting. The first immediate 20-sample cohort measured 298 ms p50,
  360 ms p95, and 480 ms p99 while the newly deployed isolates warmed. The
  following 20-sample cohort measured 196 ms p50, 224 ms p95, and 296 ms p99;
- every request in the phase-timing cohort entered Deriver A through NRT. The
  warm cohort reached B's response headers and offer at 10 ms p50, completed
  the extension at 59 ms p50, and completed the ceremony at 196 ms p50.

Final deployed benchmark comparison (2026-07-17):

| Topology | Campaign | p50 | p95 | p99 | Mean | Failures |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Same-account Service Binding HTTP stream | 60-pair interleaved control | 234 ms | 258 ms | 318 ms | 232.5 ms | 0/60 |
| Same-account Service Binding WebSocket | 60-pair interleaved candidate | **202 ms** | **230 ms** | **236 ms** | **204.7 ms** | 0/60 |
| Same-account Service Binding WebSocket | 40-pair RPC control | **198 ms** | **222 ms** | **232 ms** | **200.8 ms** | 0/40 |
| Same-account native Workers RPC streams | 40-pair interleaved candidate | 231 ms | 249 ms | 264 ms | 227.5 ms | 0/40 |
| Cross-account public WebSocket | separate 30-pair checkpoint | 203 ms | 315 ms | 424 ms | 219.4 ms | 0/30 |

All transports retained the exact 2,222,584-byte activation wire profile. The
HTTP/WebSocket 60-pair rows form one campaign; the RPC/WebSocket 40-pair rows
form a later campaign. Each same-account candidate therefore has an interleaved
canonical control under the same observed edge conditions. The cross-account
row comes from the earlier independently administered campaign and is
contextual rather than a paired measurement. A later cross-account A/B
revision synchronization exposed a rapid reconnect/teardown failure and does
not supersede the completed 30-pair checkpoint until that separate defect is
resolved.

WebSocket send milestones measure runtime queue acceptance rather than peer
receipt or socket-buffer drain. The Rust role owns at most one encoded envelope
at a time, while Cloudflare's internal WebSocket queue is opaque. Promotion is
therefore limited to the fixed, size-checked 2,222,584-byte ceremony and its
131,180-byte maximum envelope; larger or negotiated profiles require a new
memory and flow-control decision.

Same-account Service Binding WebSocket is the selected Cloudflare transport. It
met the 250 ms p95 objective in both paired campaigns, had the lowest p99,
completed the stress sequence without failures, and retained private
Worker-to-Worker routing. Native RPC streams also met the objective but added
latency without strengthening the deployment boundary. Promotion carries the
same-account operational segregation claim; it does not carry an
independent-cloud-account corruption boundary. RPC streams and cross-account
WebSocket remain benchmark research rather than runtime negotiation or
fallback.

### Placement and tail-latency interpretation

Cloudflare documents that a Service Binding runs both Workers on the same
thread of the same Cloudflare server by default. Geographic separation between
A and B therefore does not explain same-account variance. The post-promotion
cold and warm cohorts entered through the same NRT location and still differed
materially, which points to isolate startup, JIT warm-up, Worker scheduling, and
compute contention as important tail contributors.

Cross-account WebSocket adds a public hostname upgrade and an independently
routed B invocation. Its p50 shows that the best path remains competitive; its
wider p95/p99 can include public-upgrade setup, independent isolate scheduling,
network routing, and A/B data-center variation. The existing evidence does not
identify one cause because B's colo was not correlated per ceremony.

Cloudflare Placement Hints can place fetch handlers near an explicit cloud
region. A future cross-account experiment may apply the same
`placement.region` to A and B, record each role's `cf.colo` plus the
`cf-placement` response, and compare pinned and unpinned interleaved cohorts.
Placement does not guarantee one exact Cloudflare facility and may increase
client-to-A latency outside the selected region. The selected same-account
Service Binding topology does not require geographic pinning.

This comparison closes the same-account transport question. Separate-account
evidence remains useful for evaluating a stronger administrative boundary, but
it no longer selects the recommended Cloudflare runtime transport.

Cross-account HTTPS gate outcome (2026-07-17):

- Deriver B was deployed from an independently administered repository and
  Cloudflare account, and its fixed public endpoint was reachable from A;
- the global-HTTPS interactive request/response attempt did not complete within
  the 15-second ceremony timeout;
- that HTTPS-duplex transport is closed. The one approved bounded fallback is a
  fixed binary WebSocket between A and B, with the same protocol role machines,
  envelope encoding, wire ledger, deployment identity, and timeout.

Cross-account WebSocket checkpoint (2026-07-17):

- Deriver A version: `6612e212-da79-4f74-b56e-ad8dd3f71401`;
- Deriver B source commit: `ff15094`;
- deployment identity: `413ca90969656de42fb801db85f82812`;
- the complete fixed activation ceremony passed across independently
  administered Cloudflare accounts. B's first envelope reached A at 120 ms,
  before A closed its send direction at 187 ms, and peer close completed at
  481 ms;
- the exact A/B transport total remained 2,222,584 bytes. The protocol role
  machines, envelopes, wire accounting, and lifecycle messages were unchanged;
- a 30-pair alternating campaign recorded zero failures. Cross-account
  WebSocket measured 203 ms p50, 315 ms p95, 424 ms p99, and 219.4 ms mean.
  Same-account Service Binding measured 229 ms p50, 476 ms p95, 483 ms p99,
  and 273.0 ms mean in the paired comparison;
- cross-account WebSocket passed the original transport and p99 criteria. Its
  315 ms p95 exceeded the 250 ms product objective, and the newer reconnect
  defect makes it unsuitable as the current production transport. It remains
  deferred evidence for a future independent-account design.

Cloudflare runtime and pricing checkpoint (2026-07-17):

- ten Deriver A trace events reported zero non-`ok` outcomes, 245 ms CPU p50,
  550 ms CPU p95, and 320.9 ms mean CPU. Deriver A alone therefore exceeds the
  current 150 ms combined-role CPU objective;
- current [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/)
  charges no Worker bandwidth or egress fee, counts the WebSocket upgrade as
  one request, includes 10 million requests and 30 million CPU-ms per paid
  account each month, then charges $0.30 per million requests and $0.02 per
  million CPU-ms;
- at the observed 320.9 ms Deriver A mean, A contributes $6.42 of gross CPU
  usage per million ceremonies before included usage.

## Closed Gate 1: Separate-account viability experiment

Phase aliases: **9D and 13A**

Goal: decide whether the unchanged, locally proven passive ceremony is worth
production investment on the intended topology.

This gate selected the same-account transport and closed the independent-account
candidate for this release.

- [x] Deploy the fixed benchmark artifacts to independently administered
      Cloudflare accounts.
- [x] Run the single fixed cross-account WebSocket experiment. Prove B's first
      protocol envelope reaches A before A closes its send direction, and the
      complete activation ceremony reaches peer close without changing
      protocol messages, wire accounting, timeout, or lifecycle behavior.
- [x] Run one representative warm campaign in the intended client region and
      record complete-ceremony p50/p95/p99, failures, exact transport bytes,
      and a paired same-account comparison.
- [x] Record Deriver A CPU and runtime outcomes from Cloudflare trace events.
- [x] Publish one dated `go` or `stop` decision for the WebSocket experiment.
      **Stop, 2026-07-17:** the independently administered cross-account
      WebSocket completed correctly, but its 315 ms p95 missed the 250 ms
      product objective and the later rapid reconnect/teardown defect remains
      unresolved. It is deferred from this release. Same-account Service
      Binding WebSocket remains the selected production transport.

### Acceptance criteria

- Every sampled ceremony proves the fixed activation wire profile and early
  B-to-A response property.
- Cross-account table-stream p95 is below 75 ms.
- Complete ceremony p95 is at most 250 ms and p99 is at most 500 ms.
- The conservative combined A+B CPU p95 bound is at most 150 ms.
- Both roles remain below the project-owned memory ceiling with zero observed
  `exceededMemory` statuses.
- Independent account administration and measured cost are accepted explicitly.

Missing or malformed evidence yields `evidence-incomplete`. Complete WebSocket
evidence that misses a transport or latency criterion yields `stop`. A `go`
opens Gate 2.

Same-account deployment, first-request observations, placement identifiers,
frame-level timings, and connection-reuse observations remain optional
diagnostics. They do not block this gate.

## Gate 2: Selected production design

Phase alias: **6A**

Goal: choose one coherent security construction and one platform before any
production implementation starts.

- [x] Select P0 Half-Gates with the existing fixed OT suite and the existing
      reviewed circuit manifests. The production claim is passive/honest
      execution with independent role code and secrets. It excludes malicious
      garbling/evaluation, Cloudflare-account administrator compromise, shared
      deployment-authority compromise, and simultaneous compromise of A and B.
- [x] Select Cloudflare Workers with same-account Service Binding WebSocket as
      the one production transport. The fixed 128 KiB activation frame profile,
      exact 2,222,584-byte wire ledger, and existing registration, recovery,
      refresh, export, and normal-signing contracts remain unchanged.
- [x] Freeze the P0 latency objective at 250 ms p95 and 500 ms p99 for the Yao
      ceremony. The selected transport met that objective in both paired
      deployed campaigns.
- [x] Publish `build`: promote the real product lifecycle. Cross-account
      WebSocket, HTTP-stream, and Workers RPC implementations remain benchmark
      research and are absent from production runtime negotiation.

### Acceptance criteria

- The selected composition supports every attack class named in its P0 claim.
- The design preserves separate Deriver Workers, role-local secrets, storage,
  entrypoints, and deployment credentials inside one Cloudflare account.
- One implementation path fits the approved security, performance, and effort
  budgets.
- Runtime profile negotiation and dormant fallback implementations are absent
  from the production design.

## Gate 3: Build and deploy the selected design

Phase aliases: **6B, 7, 8, 10, and 11**

Goal: harden the existing Phase 9C lifecycle around the one selected
construction and deploy it under the real operator model.

Deployment checkpoint (2026-07-17):

- Router: `router-ab-router-staging`, version
  `9235221e-51bc-4168-9316-8f8fb1a2ba7d`;
- Deriver A: `router-ab-deriver-a-staging`, version
  `7457e67f-acbc-4d2c-8aec-c37e0c7f7f98`;
- Deriver B: `router-ab-deriver-b-staging`, version
  `008a5afd-fd04-4589-82e7-4f43d05e19c5`;
- SigningWorker: `router-ab-signing-worker-staging`, version
  `f772f5d2-343b-47da-a078-1f3f0e73178b`;
- product Router API: `seams-sdk-d1-router-api-staging`, version
  `ab2b06f7-ee89-46f2-ac2a-4bc548c0b4d0`;
- production frontend artifact: `https://c56ccf96.seams-site.pages.dev`;
- production wallet artifact: `https://a56f128d.seams-wallet.pages.dev`;
- Cloudflare Pages accepted the `seams.sh` and `wallet.seams.sh` custom-domain
  bindings. The proxied CNAME records now resolve both production origins and
  Cloudflare serves valid TLS certificates;
- the product API and Router expose the same `router_ab_keyset_v2`, and both
  product health and readiness probes return HTTP 200;
- the deployed site root, wallet shell, and Ed25519 Yao WASM asset return HTTP
  200 with the expected HTML and `application/wasm` content types;
- a post-publish 21-request canonical same-account WebSocket campaign completed
  with 21 successes, zero failures, and exact 2,222,584-byte accounting. The
  20 warm samples measured 202 ms p50, 216 ms p95, and 219 ms p99 of Worker
  protocol time;
- Cloudflare Worker Analytics recorded 21 invocations for each role with zero
  errors and zero client disconnects. Mean CPU was 226.3 ms for A and 167.0 ms
  for B, or 393.2 ms combined per ceremony. Sampled p99 isolate memory was
  27.7 MB for A and 33.8 MB for B, with no `exceededMemory` outcome;
- at the current Standard rates, the measured same-account ceremony models to
  approximately $8.16 of gross request plus CPU usage per million ceremonies
  before included monthly usage, with no added Service Binding request or
  Worker bandwidth charge. The benchmark Workers have no storage binding;
- the focused Ed25519 and ECDSA normal-signing boundary suites passed 19/19
  cases and reject normal-signing paths that invoke derivation handlers;
- all five Workers share one rotated internal service credential. A, B, and
  SigningWorker retain distinct role-local cryptographic secrets and Durable
  Object namespaces.

Gate 3 reconciliation (2026-07-17):

- the selected Yao Worker topology, exact wire profile, latency, CPU, memory,
  failure rate, and benchmark cost are measured;
- the focused normal-signing suites prove the source boundary makes zero
  Deriver calls. This plan does not claim a completed production-origin
  lifecycle observation;
- Cloudflare Pages and DNS now serve both custom domains with the production
  WebAuthn RP ID pinned to `seams.sh`. Production-origin lifecycle validation is
  unblocked;
- the A/B Worker, role-local secret, Durable Object namespace, and log
  separation are deployed;
- live version metadata confirms Deriver A can access only its A root-share and
  Yao-session Durable Objects plus A private secret names, while Deriver B can
  access only the corresponding B resources. Both deployed versions were
  authored by the same Cloudflare OAuth principal. The release claim therefore
  excludes distinct deployment principals;
- the checked deployment contract now assigns Router, A, B, and SigningWorker
  separate protected GitHub Environments and deploy-token slots. The runbook
  defines role-local secret escrow, SQLite Durable Object recovery, terminal
  handling for interrupted Yao sessions, credential/key rotation, one-role
  compromise response, and fail-closed rollback.
- the completed Rust-crate formal-verification scaffolding, specification
  checks, adversarial tests, compiled-WASM checks, and bounded security
  assurance pass provide the project-owned cryptographic review basis. This
  plan makes no claim of independent third-party review.

- [x] Implement only the selected cryptographic suite, production circuits,
      manifests, artifact encodings, and entrypoints; delete losing prototypes
      and benchmark-only production paths.
- [x] Add mutually authenticated role-bound transport, pinned identities,
      authenticated transcripts, strict binary framing, size and timeout
      limits, replay controls, fresh per-ceremony labels/OT/randomness/nonces,
      recipient encryption, and selected output binding.
- [x] Implement the minimum durable lifecycle required for one-use execution,
      rollback safety, crash recovery, and exact ciphertext redelivery without
      reevaluation. Preprocessing opens only when the selected construction
      requires it or measured just-in-time execution misses the frozen SLO.
- [x] Deploy A and B as distinct Workers with distinct role-local secrets,
      Durable Object namespaces, and role-specific logs inside the selected
      Cloudflare account. The release claim excludes account-admin and
      shared-CI compromise.
- [x] Promote the existing Phase 9C Router, client, and SigningWorker contracts
      without introducing a parallel lifecycle or runtime security selector.
- [ ] Complete one production-origin lifecycle validation covering fresh
      registration, recovery or refresh after page reload, exact key export,
      post-refresh signing, and observed zero Deriver calls during ordinary
      signing.
- [x] Run the selected claim's correctness and adversarial suite, including
      vectors, differential cases, corrupt-role behavior, malformed inputs,
      replay, crash/redelivery, point validation, secret-log checks, dependency
      review, and native plus compiled-WASM constant-time review.
- [x] Benchmark the selected Yao release candidate in the intended topology and
      verify latency, failures, CPU, memory, and exact wire bytes against the
      frozen SLO.

### Acceptance criteria

- The implementation and public capability claim match the selected
  construction exactly.
- Production contains one security profile and one deployment profile.
- A and B have distinct Worker, secret, and storage boundaries and communicate
  through the frozen authenticated Service Binding WebSocket transport.
- Invalid role, lifecycle, circuit, recipient, and session combinations fail
  at the boundary or compilation.
- Recipient outputs remain private under the selected corruption model, and no
  critical or high cryptographic finding remains.

## Explicitly deferred work

Prepositioned garbled circuits, reusable base OT, ticket pools, distributed
reservation, epoch-floor authorities, burn accounting, multi-level admission
budgets, and preprocessing storage remain absent unless Gate 2 selects a
construction that requires them or Gate 3 measurements prove they are needed.
Any such work receives a new measured, construction-specific plan.

ECDSA independent-account deployment and lifecycle migration remain owned by
[router-ab/deployment.md](../deployment.md). Browser asset-waterfall
work remains part of the general deployment/release runbook and does not block
the Yao viability decision.
