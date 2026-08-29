# Ed25519 Yao Cloudflare benchmark

This isolated crate exercises the fixed activation circuit with the 128 KiB
stream profile over two compile-time Cloudflare topologies. It is benchmark
infrastructure and has no production protocol route.

The canonical `workers-rs` 0.8.5 same-account local-workerd results are recorded
in
[`docs/phase9b-same-account-report-v085.md`](docs/phase9b-same-account-report-v085.md).
The preceding 0.8.4 run remains as explicitly historical evidence in
[`docs/phase9b-same-account-report.md`](docs/phase9b-same-account-report.md).
Local compile-time fault results are recorded in
[`docs/phase9b-worker-fault-report.md`](docs/phase9b-worker-fault-report.md) and
[`docs/phase9b-worker-fault-remaining-report.md`](docs/phase9b-worker-fault-remaining-report.md).
The R120 role-targeted threshold-PRF preface, its compact local measurements,
and the remaining production-selection gates are recorded in
[`docs/r120-phase0-local-smoke.md`](docs/r120-phase0-local-smoke.md).

The canonical `deriver-a` and `deriver-b` artifacts carry fixed
`same-account-service-binding-websocket` metrics. Deriver A opens one binary
WebSocket upgrade through the private `DERIVER_B` Service Binding. The
`deriver-a-cross-account` and
`deriver-b-cross-account` artifacts carry fixed `cross-account-websocket`
metrics. A opens one binary WebSocket to the required
`DERIVER_B_WEBSOCKET_ENDPOINT` binding. This is the single bounded transport
experiment opened after the deployed global-HTTPS request-stream attempt timed
out before completing a ceremony. There is no runtime topology selection or
alternate cross-account transport. Both artifacts use the same fixed protocol
role drivers and exact envelope encoding. Each adapter maps an envelope to one
binary message, retains one Rust-owned encoded envelope at a time, and mints
directional EOF evidence only when its owned direction ends.

The cross-account endpoint is parsed once at the Worker boundary. It must use
WSS, contain no credentials, query, or fragment, use either the default port or
port 443, and end at exactly `/benchmark/activation`. The checked-in domain is
an inert example and must be replaced with Deriver B's fixed custom domain
before a deployed benchmark.

The A response JSON and B completion log report adapter-visible incoming bytes,
the largest incoming fragment delivered by the platform, total and peak
outgoing envelope bytes, and the fixed one-envelope queue maximum. Secret
request and response ingress bypass the generic `workers-rs` body conversion.
Each JavaScript `Uint8Array` is copied directly into one
`Zeroizing<Vec<u8>>`, its delivered JavaScript view is overwritten immediately,
and `Bytes::from_owner` retains the zeroizing owner until the final slice drops.
The outgoing generic `StreamBody` still makes one JavaScript-stream copy.

Outgoing envelopes use a zeroizing `Bytes` owner. The Rust-owned envelope is
wiped when `workers-rs` releases it after copying the bytes into the JavaScript
stream. Every successful A result and B completion log fixes
`production_eligible = false` and the bounded disposal claim
`incoming_secret_buffer_disposal =
"rust-wasm-copy-zeroized-js-view-overwritten-platform-copies-uncontrolled"`.
The claim covers adapter-owned Rust/WASM copies and the delivered JavaScript
view. V8, workerd, network, and other platform copies remain outside application
control. Both benchmark collectors enforce the exact label and byte accounting.

Install the pinned Worker builder once, then build each entrypoint
independently:

```sh
npm run worker-build:install
npm run build:b
npm run build:a
npm run build:a:cross-account
npm run build:b:cross-account
```

The repository-pinned Wrangler 4.111.0 binary drives dry runs, local workerd,
and named-profile deployment preflights:

```sh
npm run dry-run:b
npm run dry-run:a
npm run dry-run:a:cross-account
npm run dry-run:b:cross-account
npm run dev:same-account
```

In another terminal, run the timed smoke:

```sh
curl --fail-with-body --silent --show-error --max-time 120 \
  -X POST http://127.0.0.1:8787/benchmark/activation | \
jq -e '
  .ok == true and
  .benchmark_only == true and
  .topology == "same-account-service-binding-websocket" and
  .family == "activation" and
  .profile == "128KiB" and
  .table_payload_bytes == 2104960
'
```

A successful response proves the local runtime exposed B's response before A
closed its request: A cannot send `BaseChoices` until it receives B's `Offer`,
while request EOF occurs only after `Translation`. The adapter aborts after 15
seconds if the transport or ceremony stalls.

After the smoke passes, collect one first-request observation and sequential
warm samples:

```sh
npm run bench:same-account -- 51
```

For the R120 architecture comparison, collect the current and threshold-PRF
profiles for activation, export, and lane materialization. The default is one
first observation plus 100 warm observations per profile and ceremony. A
loopback diagnostic accepts positional arguments:

```sh
npm run bench:r120 -- 101 http://127.0.0.1:8787/benchmark/activation \
  same-account-service-binding-websocket
```

Deployed evidence accepts no positional endpoint or topology. It derives both
from the complete deployment receipt and rejects every response whose
deployment ID does not match:

```sh
export YAOS_AB_SAMPLE_COUNT=101
export YAOS_AB_R120_CAMPAIGN=paired-latency
npm run bench:r120 > r120-same-latency.json
```

The runner completes the fixed attempt set. Any timeout, transport error, or
invalid response produces a sanitized failed-campaign artifact with explicit
success, failure, and retry counts and rejects selection; it never silently
retries into a passing cohort.

Latency uses interleaved current/candidate observations. Workers analytics do
not expose the request header that selects an R120 profile, so CPU and memory
use two exclusive, non-overlapping windows against the same deployed build:

```sh
export YAOS_AB_R120_CAMPAIGN=resource-current
npm run bench:r120 > r120-same-resource-current-campaign.json
export YAOS_AB_R120_RESOURCE_CAMPAIGN_PATH="$PWD/r120-same-resource-current-campaign.json"
npm run analytics:r120 > r120-same-resource-current.json

export YAOS_AB_R120_CAMPAIGN=resource-candidate
npm run bench:r120 > r120-same-resource-candidate-campaign.json
export YAOS_AB_R120_RESOURCE_CAMPAIGN_PATH="$PWD/r120-same-resource-candidate-campaign.json"
npm run analytics:r120 > r120-same-resource-candidate.json
```

Run the same three campaigns for the independently administered cross-account
deployment. The offline `phase0:r120:evaluate` command recomputes latency from
raw samples, compares per-role CPU p95 and sampled memory P999, verifies request
counts and non-overlapping resource windows, checks 25% CPU/memory/WebSocket
headroom, then emits the exact approval-payload digest. A passing result is
`ready-for-release-signature`; it remains ineligible for selection until the
release authority signs that digest.

```sh
export YAOS_AB_R120_SAME_ACCOUNT_LATENCY_REPORT=/absolute/r120-same-latency.json
export YAOS_AB_R120_SAME_ACCOUNT_CURRENT_RESOURCE_REPORT=/absolute/r120-same-resource-current.json
export YAOS_AB_R120_SAME_ACCOUNT_CANDIDATE_RESOURCE_REPORT=/absolute/r120-same-resource-candidate.json
export YAOS_AB_R120_CROSS_ACCOUNT_LATENCY_REPORT=/absolute/r120-cross-latency.json
export YAOS_AB_R120_CROSS_ACCOUNT_CURRENT_RESOURCE_REPORT=/absolute/r120-cross-resource-current.json
export YAOS_AB_R120_CROSS_ACCOUNT_CANDIDATE_RESOURCE_REPORT=/absolute/r120-cross-resource-candidate.json
npm run phase0:r120:check-inputs
npm run phase0:r120:evaluate > r120-selection-candidate.json
```

The preflight is read-only. It requires six distinct JSON paths, hashes each
artifact, and checks the expected topology/profile identities without applying
the performance gates. Start deployed R120 runs from
`deployment-env/r120-one-account.env.example` and
`deployment-env/r120-two-account.env.example`.

The release authority signs outside this benchmark harness using the frozen
byte layout in `../../docs/refactor-120-rotate-tenant-secrets.md`. Verify the returned
record against the externally pinned policy:

```sh
export YAOS_AB_R120_SELECTION_CANDIDATE=/absolute/r120-selection-candidate.json
export YAOS_AB_R120_RELEASE_AUTHORITY_POLICY=/absolute/r120-release-authority-policy.json
export YAOS_AB_R120_SIGNED_SELECTION=/absolute/r120-signed-selection.json
npm run phase0:r120:verify > r120-architecture-selection.json
```

Only `phase0:r120:verify` can emit `selection_ready = true`. It recomputes the
approval-payload digest, applies the authority sequence floor and key epoch,
verifies the exact Ed25519 signature, and commits the raw SHA-256 hash of all
three input artifacts in the final record.

Validate the complete local compile/build matrix with one command:

```sh
npm run validate:local-readiness
```

This runs formatting, native tests and source guards, strict host and WASM
Clippy for all four normal artifacts and every compile-time fault artifact,
the local/deployed measurement fixtures, and all corresponding Worker builds.
It also runs Wrangler dry-run bundling for the four normal same/cross-account
artifacts. The command also reruns the core passive Rust suite and two-process
tests, all three strict core/WASM Clippy targets, the independently regenerated
Phase 5 stream KAT, 186 independent Python verifier tests, and 128 freshly
generated differential cases. The fail-closed formal parity gate runs 80
production Rust tests, 418 generator Rust tests including 25 circuit tests,
and three artifact-filesystem-policy tests. It builds and executes all six Phase 5 WASM
stream profiles in normal and delayed producer/consumer modes. The live
workerd smoke and 51-ceremony benchmark remain separate because they own a
loopback listener and produce the measured baseline.

The activation/128-KiB report also carries a typed wire ledger. It freezes
2,104,960 table bytes, 82,112 ordinary passive-OT bytes, 33,300 other control
bytes, 400 envelope-header bytes, and 2,222,584 total A/B transport bytes.
Both Worker roles compare their observed directional counters with this ledger
before accepting completion.

Local readiness also rebuilds and runs the native and Node WASM compute
collectors. Each uses one warm-up and twenty measured activation/export
ceremonies at 128 KiB, enforces the provisional local compute and memory
budgets, and preserves the boundary between local lower bounds and deployed
Worker evidence. The canonical results are in
[`../ed25519-yao/docs/phase13a-local-compute-report.md`](../ed25519-yao/docs/phase13a-local-compute-report.md).

The same command runs a fail-closed benchmark-isolation audit and its mutation
fixtures. The audit permits only four exact development/verifier dependencies,
requires zero benchmark-crate dependents and production routes, and scans the
product tree for protocol reachability. Its canonical result is in
[`docs/phase13a-isolation-audit-v1.md`](docs/phase13a-isolation-audit-v1.md).

Compile-time fault artifacts exercise the Worker streaming boundary without
headers, query parameters, environment switches, or runtime profile selection.
Run one pair at a time, then invoke its assertion from another terminal:

```sh
npm run dev:fault:fragmentation
npm run smoke:fault:success

npm run dev:fault:request-disconnect
npm run smoke:fault:request-disconnect

npm run dev:fault:response-disconnect
npm run smoke:fault:response-disconnect

npm run dev:fault:trailing
npm run smoke:fault:trailing

npm run dev:fault:timeout
npm run smoke:fault:timeout

npm run dev:fault:wrong-service
npm run smoke:fault:wrong-service

npm run dev:fault:wrong-role
npm run smoke:fault:wrong-role

npm run dev:fault:session-mismatch
npm run smoke:fault:session-mismatch
```

The fragmentation artifact reports its emitted fragment count and maximum
separately from platform-observed fragments because workerd may coalesce stream
chunks. The public A endpoint also consumes and rejects any non-empty request
body before it creates a session or contacts B. Verify that boundary against
any running A fault pair with `npm run smoke:public-body-rejection`.

The HTTP-stream fault artifacts disable Wrangler's unused-request-body drain
middleware because those isolated tests intentionally retain the old stream
boundary long enough to exercise disconnect, fragmentation, and trailing-byte
failures. They are not deployable transport alternatives.

The deployed cross-account HTTPS attempt reached the independently administered
B Worker but did not complete the interactive request/response ceremony before
the adapter timeout. The fixed WebSocket artifact is the only bounded fallback
experiment. A real two-account WebSocket run must prove complete ceremony EOF,
the unchanged protocol wire ledger, and the latency and resource gates before
any production transport decision.

## Deployed measurement tooling

The [deployed benchmark runbook](docs/phase9b-deployed-measurements.md) provides
strict one-account and two-account environment templates, plan-only deployment
orchestration, an opt-in `--execute` boundary, a sequential HTTP collector,
read-only Workers GraphQL CPU/memory/colo collection, a receipt-bound cost
calculator, and a fail-closed offline Phase 13A deployed-viability evaluator
for the intended cross-account topology. Same-account deployment remains a
diagnostic lower bound. Offline fixtures run with:

```sh
npm run test:deployment-tooling
npm run test:cost-report-integrity
npm run test:rendered-deployment-configs
npm run test:constant-time-codegen
```

No deployment command runs by default. The tooling makes no transport-auth or
production-security claim.

Executed benchmark deployments require an absolute receipt path. The
orchestrator writes a fresh shared deployment identity before deploying B,
captures both Wrangler version receipts and local JS/WASM artifact digests,
and updates the mode-0600 ownership receipt after each role. A and B enforce
that identity on their direct protocol hop. HTTP collection, analytics
collection, Phase 13A evaluation, and cleanup all require the matching receipt.

Run the fail-closed local Phase 13A preflight with:

```sh
npm run phase13a:local-preflight
```

It verifies pinned local reports, stream KATs, exact table-byte arithmetic,
local latency observations, validation-matrix evidence, benchmark isolation,
optimized native/Worker-WASM constant-time codegen for secret label and IKNP
selection, and the benchmark promotion blocker. Its successful status is
`deployment-required`; it cannot emit a Phase 13A `go`.
