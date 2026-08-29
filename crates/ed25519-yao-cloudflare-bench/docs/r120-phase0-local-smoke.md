# R120 Phase 0 local feasibility record

Date: August 29, 2026

Status: provisionally feasible; production architecture selection remains
open.

## Result

The benchmark-only role-targeted threshold-PRF preface completed activation,
export, and lane-materialization ceremonies under local `workerd` using the
same-account Service Binding and WebSocket topology. It reused the established
A/B session and added one simultaneous bidirectional proof-bundle flight.

Each direction carried one 342-byte HPKE-encrypted bundle, for 684 bytes total.
The candidate added zero connections, HTTP requests, WebSockets, client round
trips, and standalone readiness flights. Current and candidate reports had
identical Yao circuit and schedule digests, wire ledgers, and recipient-package
sizes.

| Repeat | Ceremony | Candidate preface | Client-wall delta | Worker-elapsed delta |
| ---: | --- | ---: | ---: | ---: |
| 1 | Activation | 4 ms | 1.512334 ms | 2 ms |
| 1 | Export | 4 ms | 1.737125 ms | 1 ms |
| 1 | Lane materialization | 5 ms | 5.366749 ms | 6 ms |
| 2 | Activation | 4 ms | 3.753666 ms | 3 ms |
| 2 | Export | 4 ms | 2.196374 ms | 2 ms |
| 2 | Lane materialization | 4 ms | 2.047501 ms | 3 ms |

Each compact repeat contained one first observation and one warm observation
per profile and ceremony. With one warm observation, the reported warm p95
equals that single value. The runs establish local engineering feasibility and
exercise the benchmark assertions. They do not provide a statistical latency
claim or production Worker resource evidence. The updated runner classified
the second repeat as `provisionally-feasible`; its latency, artifact/wire parity,
and preface-resource gates passed, while its sample-count and production
selection gates remained open.

## Interpretation

The largest observed warm client-wall delta was 5.366749 ms and the largest
Worker-elapsed delta was 6 ms, both below the plan's 10 ms rejection ceiling.
The preface itself took 4-5 ms. The result supports continuing with the
role-targeted threshold-PRF design and gives no current reason to pursue the
joined-root Yao circuit.

Production protocol work remains gated on both deployed topologies completing
the default one first plus 100 warm observations per cohort, along with
per-role CPU, sampled memory P999, finite-limit Workers headroom, raw artifact
publication, and a signed architecture-selection record. First-observation
latency remains descriptive; the selected APIs do not expose fresh-isolate
incidence.

For local diagnostics, run the same comparison with:

```sh
pnpm bench:r120 -- 101 http://127.0.0.1:8787/benchmark/activation \
  same-account-service-binding-websocket
```

Deployed mode derives its endpoint and topology from a complete receipt and
accepts no positional values. Run `paired-latency`, `resource-current`, and
`resource-candidate` campaigns for each topology. The resource windows are
exclusive and non-overlapping because Workers analytics aggregate by script
and cannot group on the R120 profile header. The offline evaluator then
recomputes raw latency, resource deltas, and headroom and emits the exact digest
that the release authority must sign.

## Deployment checkpoint

The safe deployment wrapper accepts exact benchmark-owned `workers.dev`
hostnames in addition to custom domains. A read-only preflight on August 29,
2026 found one authenticated account/profile and produced a same-account plan
for 101 observations per profile and ceremony. It schedules Deriver B before
Deriver A and retains the deployment receipt plus reverse-order cleanup path.
No external state changed.

Execution remains gated by the repository's canonical local-readiness chain.
The R120 base first encounters two R103F-owned lane-holder test literals that
predate the required envelope-ownership field. A diagnostic correction then
reaches an R103F-owned device-link source guard. Those changes remain with the
concurrent R103F owner, after which this branch can rebase and regenerate the
readiness receipt. Cross-account execution also needs a second independently
administered account/profile. Phase 0 stays open until both deployed cohorts
and their Workers resource evidence pass.
