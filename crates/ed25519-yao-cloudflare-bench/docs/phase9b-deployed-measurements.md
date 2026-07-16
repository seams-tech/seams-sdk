# Phase 9B deployed benchmark tooling

This tooling prepares and measures the isolated activation/128 KiB benchmark.
It creates no production route, authentication claim, Router integration, or
SDK integration. Deployment planning is the default. External state changes
require both `--execute` and two explicit benchmark acknowledgements.

## Boundary inputs

Start from `deployment-env/one-account.env.example` or
`deployment-env/two-account.env.example`. Load the values into the invoking
shell without committing real account IDs or tokens. The parser requires:

- explicit A and B account IDs and Wrangler auth profiles;
- equal account IDs for one-account mode and distinct IDs/profiles for
  two-account mode;
- the canonical HTTPS A endpoint;
- an exact B hostname and `https://<host>/benchmark/activation` endpoint for
  two-account mode;
- the exact benchmark-only A/B script names for the selected topology, a
  sample count from 2 through 1,000, and a bounded region label.
- an absolute `YAOS_AB_DEPLOYMENT_RECEIPT_PATH` ending in `.json`. Use a
  different path for each topology.

The plan and reports omit account IDs. Analytics tokens are read only from
`CLOUDFLARE_ANALYTICS_TOKEN_A` and `CLOUDFLARE_ANALYTICS_TOKEN_B`, excluded
from child processes, and never included in output.

## Plan and optional deployment

```sh
npm run deployment:plan
```

The plan is JSON and performs no writes or external calls. Review the B-then-A
operation order, profiles, script names, domains, topology, and region.

Deployment uses Wrangler named auth profiles. Current Cloudflare documentation
states that `CLOUDFLARE_API_TOKEN` takes precedence over a profile, so the
wrapper rejects global API-token/key variables. It also verifies that the
selected Wrangler exposes `--profile`; the repository's older pinned Wrangler
may require a separately reviewed update before execution.

```sh
npm run deployment:execute
```

Before writing a temporary config or deploying either role, the wrapper binds
each named profile to an isolated temporary directory, runs read-only
`wrangler whoami --account ... --json` there, removes the binding, and deletes
the directory. It parses the returned account set, requires the expected
account, and rejects a two-account profile that can access the peer benchmark
account. The wrapper then generates mode-0600 temporary configs with account
IDs, custom domains, absolute build/entrypoint paths, and the fixed B endpoint;
deploys B first and A second with
`wrangler deploy --strict`; redacts boundary values from captured output; and
deletes the temporary directory. Do not execute against a production account.
The cross-account benchmark endpoint has no protocol authentication and must
be protected externally against unsolicited use. This measurement does not
establish an authenticated-transport security claim.

Before B is deployed, the wrapper writes a mode-0600 ownership receipt with a
fresh 128-bit deployment identity. Wrangler's structured output supplies each
role's exact Wrangler version, Worker tag, version ID, target, and deployment
timestamp. The wrapper also hashes the built JavaScript, WASM, package
manifest, and shim, updating the receipt after B and after A so a partial
B-only deployment retains an ownership record.

Deployment first revalidates the canonical local-readiness evidence bundle and
hashes its exact JSON bytes. The receipt binds that SHA-256 digest before any
Worker upload. HTTP, analytics, cost, and cold-proxy evidence carry the same
digest, and Phase 13A accepts only evidence bound to the currently validated
bundle.

The bundle also commits a deterministic tree digest covering the Yao source,
vectors, tests, lockfiles, build scripts, Worker configurations, verifier, and
validation tooling. Build outputs and caches are excluded. Any covered input
change invalidates both deployment preflight and final Phase 13A evaluation
until the complete local-readiness matrix passes and the bundle is refreshed.

Both rendered Worker configs receive the same deployment identity. A carries
it to B in `x-ed25519-yao-deployment-id`; B compares it with its environment
before protocol work and echoes it; A rejects a missing or mismatched echo.
Successful A output and B completion evidence include the identity.

If B deploys and A fails, B may remain deployed. Cleanup is plan-only by
default and uses reverse dependency order:

```sh
npm run cleanup:plan
```

After reviewing the A-then-B deletion plan, set the separate
`YAOS_AB_CONFIRM_DELETE_BENCHMARK=YES` acknowledgement and run:

```sh
npm run cleanup:execute
```

Cleanup requires the matching ownership receipt and repeats both
profile/account preflights before writing configs or
deleting anything. It attempts A first, then B even when A is already absent,
so a B-only residue from a failed A deployment can still be removed. Any
deletion failure is reported after both attempts and requires inspection.

## HTTP measurements

```sh
npm run bench:deployed > phase9b-deployed-http.json
```

The collector performs one initialization observation followed by at least 50
sequential warm samples. The initialization observation is not classified as a
cold-isolate sample. Client wall time runs from request initiation through complete
response-body EOF, so it covers the complete ceremony and returned result
rather than stopping at response headers. It records success/failure counts,
client wall and A elapsed
p50/p95/p99, all exposed bytes/copies/frame/queue metrics, Deriver A/B colos,
and the client-facing `cf-ray` colo as a cross-check. Responses are bounded to
64 KiB and must match the fixed benchmark profile plus the deployment identity
from the complete receipt. Reports carry its role version IDs, tags, Wrangler
versions, timestamps, and artifact digests. Fetch does not expose a
connection identifier or handshake timing; initialization/warm deltas and
stable colos are observations rather than proof of connection reuse.

### Fresh-version first-request cohort

Cold-proxy quantiles require at least 20 independently deployed version pairs.
For each pair, deploy B then A with a fresh receipt, run the HTTP collector, and
retain the complete report. Assemble one topology-specific cohort from absolute
report paths:

```sh
npm run cold-cohort:assemble -- \
  /absolute/fresh-version-01.json \
  /absolute/fresh-version-02.json \
  /absolute/fresh-version-03.json \
  /absolute/fresh-version-04.json \
  /absolute/fresh-version-05.json \
  /absolute/fresh-version-06.json \
  /absolute/fresh-version-07.json \
  /absolute/fresh-version-08.json \
  /absolute/fresh-version-09.json \
  /absolute/fresh-version-10.json \
  /absolute/fresh-version-11.json \
  /absolute/fresh-version-12.json \
  /absolute/fresh-version-13.json \
  /absolute/fresh-version-14.json \
  /absolute/fresh-version-15.json \
  /absolute/fresh-version-16.json \
  /absolute/fresh-version-17.json \
  /absolute/fresh-version-18.json \
  /absolute/fresh-version-19.json \
  /absolute/fresh-version-20.json \
  > phase9b-fresh-version-first-request.json
```

The assembler requires unique deployment IDs and unique A/B version IDs,
stable artifact and local-readiness bundle digests, one topology and region,
complete successful reports, and a first raw request after both deployments. It reports p50/p95/p99 as a
fresh-version first-request operational cold proxy. It fixes
`physical_isolate_cold_proven = false`; Cloudflare exposes no evidence that can
upgrade this cohort into a physical-isolate cold-start claim.

## Read-only Cloudflare analytics

Create narrowly scoped Account Analytics Read tokens, set the analytics time
window, wait for the dataset to include the completed run, then execute:

```sh
npm run analytics:deployed > phase9b-deployed-analytics.json
```

The collector queries each account separately through
`workersInvocationsAdaptive`. Its core query reports requests, errors,
disconnects, subrequests, CPU, wall time, request duration, and per-colo
groups. A second query asks only for the documented isolate-memory P50, P90,
P99, and P999 fields. Splitting the requests preserves core timing data when a
plan or schema does not expose memory. Such failures are returned explicitly
as codes and GraphQL paths without echoing server messages, tokens, or account
IDs. Adaptive quantiles are sampled evidence. Memory P999 is the strongest
available gate signal and is not an exact maximum.

The analytics collector loads the same complete receipt. Phase 13A requires
its deployment identity, version IDs, tags, Wrangler versions, and artifact
digests to match the HTTP report exactly.

Each role also receives a sampled memory gate summary. The fixed threshold is
96 MiB (`100663296` bytes), and the comparison is strict:
`memoryUsageBytesP999 < threshold`. Equality or a higher P999 fails. Any core
analytics row with status `exceededMemory` also forces failure. Missing core or
memory evidence yields `unavailable`; sampled P999 evidence cannot prove the
exact per-invocation maximum.
The evaluator recomputes this gate from the raw P999 quantile and per-colo
invocation statuses. It requires the classification
`cloudflare-reservoir-sampled-shared-isolate-operational-proxy`, fixes
`exact_peak_proven = false`, and records platform-copy accounting as
unavailable. A forged derived gate cannot override the raw evidence.

## Cost model

Copy `deployment-env/cost.env.example`, source the matching deployment
environment, enter the receipt-bound HTTP/analytics request, mean CPU, and byte
measurements, and supply the current pricing rates and allowances:

```sh
npm run cost:deployed > phase9b-deployed-cost.json
```

Under the Standard usage model, one-account Service Binding mode models one billed inbound request and combines
A+B CPU in one account. Two-account public HTTPS models one inbound A request
and one inbound B request in their respective accounts; A's outbound
subrequest is not counted as a third request. Rates and included quotas remain
per account. The network rate is also user supplied. Enter zero only after
confirming the current Workers pricing source states there is no added
bandwidth/egress charge.

Current authoritative references:

- [Workers pricing and Service Binding billing](https://developers.cloudflare.com/workers/platform/pricing/)
- [Workers GraphQL metrics query](https://developers.cloudflare.com/analytics/graphql-api/tutorials/querying-workers-metrics/)
- [GraphQL API-token authentication](https://developers.cloudflare.com/analytics/graphql-api/getting-started/authentication/api-token-auth/)
- [Wrangler authentication profiles](https://developers.cloudflare.com/workers/wrangler/commands/general/)
- [Workers memory metrics](https://developers.cloudflare.com/workers/observability/metrics-and-analytics/)

## Offline validation

```sh
npm run test:deployment-tooling
```

Fixtures cover topology and endpoint rejection, report quantiles, exact colo
field names, GraphQL core/memory success, plan/schema memory failure, output
redaction, rendered deployment configs, fresh-version cohort identity, and
receipt-bound cost-domain edge cases.

## Phase 13A deployed viability evaluation

Before deployment resumes, verify the pinned local evidence bundle:

```sh
npm run phase13a:local-preflight
```

The local preflight returns `status = "deployment-required"` and
`phase13a_decision = "unavailable"` after validating evidence digests, stream
KAT table arithmetic, local timing observations, the local artifact matrix,
and the non-promotion invariant. It lists every deployed evidence class still
required and cannot authorize Phase 6A.

Create a project-owned operational acceptance record from
`deployment-env/phase13a-operational-acceptance.json.example`. Its positive
same-account and cross-account cost ceilings must be approved before looking at
the final decision. Set all nine absolute report paths, then run the offline
evaluator:

```sh
export YAOS_AB_PHASE13A_SAME_BENCHMARK_REPORT=/absolute/same-http.json
export YAOS_AB_PHASE13A_SAME_ANALYTICS_REPORT=/absolute/same-analytics.json
export YAOS_AB_PHASE13A_CROSS_BENCHMARK_REPORT=/absolute/cross-http.json
export YAOS_AB_PHASE13A_CROSS_ANALYTICS_REPORT=/absolute/cross-analytics.json
export YAOS_AB_PHASE13A_SAME_COLD_PROXY_REPORT=/absolute/same-cold-proxy.json
export YAOS_AB_PHASE13A_CROSS_COLD_PROXY_REPORT=/absolute/cross-cold-proxy.json
export YAOS_AB_PHASE13A_SAME_COST_REPORT=/absolute/same-cost.json
export YAOS_AB_PHASE13A_CROSS_COST_REPORT=/absolute/cross-cost.json
export YAOS_AB_PHASE13A_OPERATIONAL_ACCEPTANCE=/absolute/operational-acceptance.json
npm run phase13a:evaluate
```

Complete valid evidence produces `go` or `stop` with stable reason codes.
Missing, malformed, or statistically insufficient evidence produces the
separate `evidence-incomplete` state and cannot terminate the Yao investigation
as a substantive `stop`. The evaluator recomputes warm and cold-proxy quantiles and table ranges from every
raw sample, checks each timing sequence, and requires every sample to prove the
first raw B-to-A body byte arrived before request-direction close. Decoded
`Offer` remains a separate protocol-progress milestone. Missing files, fields,
analytics, samples, or memory gates fail closed. It also requires zero
benchmark failures, exact analytics script/request correlation, zero analytics
errors, matching region labels, and analytics windows that cover their HTTP
benchmark windows. Warm cohorts require at least 50 samples after initialization.
Cold proxies require at least 20 fresh-version first requests with distinct A/B
version identities, stable artifacts, and one current local-readiness bundle.

Cost reports must match the same deployment receipts, regions, analytics CPU
means, invocation counts, and HTTP transport bytes. The evaluator recomputes
every request, CPU, network, account, and total cost field from the supplied
rates. A go also requires the explicit operational record to accept independent
two-account administration, confirm review of the dated pricing source, and
set ceilings above both measured per-million costs.

The exact timing contract is:

- complete ceremony through response-body EOF:
  `warm.metrics.client_wall_ms.p95` and `.p99`;
- fresh-version first-request operational cold proxy:
  `metrics.client_wall_ms.p50`, `.p95`, and `.p99`, with the physical-isolate
  cold claim fixed to false;
- cross-account table stream:
  `warm.metrics.table_stream_duration_ms.p95`;
- raw body progress: A-to-B and B-to-A first/final body-byte milestones,
  distinct from decoded Offer/Returned and physical request/response EOF;
- ordinary passive OT: exactly four messages in four sequentially dependent
  one-way rounds;
- combined-role CPU p95 upper bound: the sum of A and B marginal
  `cpuTimeP99` values. By the union bound, both roles are within those
  percentiles for at least 98% of ceremonies, which conservatively covers the
  required joint p95 without pretending that two marginal p95 values form a
  paired percentile;
- table bytes: `fixed_profile_ranges.table_payload_bytes.min` and `.max`;
- memory: each role's gate recomputed from raw reservoir-sampled shared-isolate
  P999 and `exceededMemory` status rows, with exact peak fixed to unproven.

The table limit is 2.10 MiB, represented as the largest allowed integer byte
count (`2202009`); exact observed table bytes remain in the decision evidence.
Cross-account table-stream p95 must be below 75 ms. Cross-account complete
ceremony p95/p99 must be at most 250/500 ms. Combined CPU is the conservative
sum of A and B marginal CPU P99 and must be at most 150 ms. Every A/B memory gate in
both topology reports must show P999 strictly below 96 MiB with zero
`exceededMemory` observations.
