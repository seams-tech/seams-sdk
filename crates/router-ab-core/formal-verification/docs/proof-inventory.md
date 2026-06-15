# Proof Inventory

## Planned Verus Proofs

| Claim | Status | Notes |
| --- | --- | --- |
| Context encoding includes candidate id | Planned | Mirrors `DerivationContext::encode_context_v1` |
| Context encoding includes request kind | Planned | Mirrors `DerivationContext::encode_context_v1` |
| Context encoding includes correctness level | Planned | Mirrors `DerivationContext::encode_context_v1` |
| Context encoding includes account scope | Planned | Covers network, account id, and account public key |
| Context encoding includes root epoch | Planned | Required for refresh safety |
| Context encoding includes ceremony id | Planned | Required for replay protection |
| Transcript digest includes role identities | Planned | Router, Deriver A, Deriver B, SigningWorker, client |
| Allowed opened-value kinds are role scoped | Model entry added | Client receives `x_client_base`; SigningWorker receives `x_server_base` |
| Context field order is fixed | Planned | Required for anti-drift |
| Transcript field order is fixed | Planned | Required for anti-drift |
| Empty required fields are rejected | Planned | Boundary validation model |
| Changed bound field changes abstract transcript identity | Planned | Abstract digest injectivity assumption |
| Root epoch separation | Planned | New epoch material cannot verify under old epoch |
| Recipient separation | Planned | Client and SigningWorker outputs use disjoint labels |
| State-machine transition safety | Planned | No delivery before signer inputs are accepted |
| Verified output binds accepted A/B inputs | Planned | Prevents mixed-transcript acceptance |
| Replay cache rejects changed bound fields | Planned | Mirrors `state-machine.md` |
| Minimum Level C binds package commitments | Planned | Mirrors `minimum-level-c.md` |
| Package commitment binds recipient identity | Planned | Mirrors `envelopes-and-delivery.md` |
| Public-share-binding evidence includes Minimum Level C evidence | Planned | Stronger correctness path |
| Secret-classified types exclude public secret returns | Planned | Source/API shape property |
| Candidate A Router excludes plaintext PRF partials | Model entry added | Abstract visibility predicate in Verus model |
| Candidate A client observes only client-targeted partials | Model entry added | Abstract visibility predicate in Verus model |
| Candidate A SigningWorker observes only SigningWorker-targeted partials | Model entry added | Abstract visibility predicate in Verus model |
| Role-view events exclude forbidden joined state | Model entry added | Forbidden joined events are modeled explicitly and are unobservable |
| Production service roles match the FV role set | Anti-drift test added | `formal-verification/verus/tests/anti_drift.rs` |
| Production output authorization matches the FV opened-value model | Anti-drift test added | Client opens `x_client_base`; SigningWorker path uses `x_server_base` |

## Planned Lean Proofs

| Claim | Status | Notes |
| --- | --- | --- |
| One server-side role view excludes forbidden joined state | Model entry added | Event-based privacy predicate |
| Client view excludes joined `d`, `a`, and SigningWorker material | Model entry added | Event-based privacy predicate |
| Router view excludes plaintext A/B share pairs | Planned | Privacy model |
| Client opens only `x_client_base` | Planned | Role/output authorization |
| SigningWorker opens only `x_server_base` | Model entry added | Role/output authorization |
| Deriver A alone excludes forbidden joined state | Planned | Role-view privacy |
| Deriver B alone excludes forbidden joined state | Planned | Role-view privacy |
| Router-mediated transport does not alter visibility claim | Planned | Topology-independent view model |
| Router plus one deriver excludes joined forbidden state | Planned | Threat matrix claim |
| A+B collusion is outside server-blind claim | Planned | Threat matrix boundary |
| Candidate A Router view excludes plaintext PRF partials | Model entry added | Lean privacy predicate |
| Candidate A client observes only `x_client_base` partials | Model entry added | Lean privacy predicate |
| Candidate A SigningWorker observes only `x_server_base` partials | Model entry added | Lean privacy predicate |

## Out Of Scope Until Candidate Selection

- computational PRF security
- elliptic-curve group relation proofs
- real envelope encryption security
- Cloudflare deployment integrity
- split-root production proofs; split-root remains comparison material outside
  the selected v1 production FV surface
