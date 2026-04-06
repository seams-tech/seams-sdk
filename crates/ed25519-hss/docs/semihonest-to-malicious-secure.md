# Semi-Honest To Malicious-Security Plan

This note is the minimum plan required to move `ed25519-hss` from
semi-honest security to a credible malicious-security claim against a cheating
client.

The target claim is:

- a malicious client cannot recover `K_org`
- a malicious client cannot recover full `y_relayer`
- a malicious client cannot obtain more than its allowed branch or output view
- cheating causes abort before useful extra output is released

## Boundary Prerequisite Status

One important prerequisite boundary fix is now landed:

- the old sealed `ServerInputsPacket` production seam is removed from the
  production client boundary
- the production staged flow now advances through real server-owned stage-local
  continuations from add-stage onward instead of being only transcript
  scaffolding
- non-export production flows now use the staged server-assisted path rather
  than the old joined-input packet delivery path

That closes the specific boundary gap where a malicious client could recover
per-account `y_relayer` or `tau_relayer` from the old production seam.

What it does **not** do:

- it does not produce a full malicious-security claim by itself
- it does not make `ExplicitKeyExport` safe against malicious in-page code,
  because that flow intentionally delivers canonical seed material
- it does not replace the need for malicious-secure OT, authenticated Beaver
  protections, replay limits, or broader active-security controls

## Threat Reality

The practical concern is usually not one-shot exfiltration.

The more realistic attack shape is:

- a malicious client sends many crafted requests
- replays or swaps protocol material
- varies inputs adaptively
- studies abort behavior or output differences across runs
- tries to accumulate information about server-held hidden state

So this note should be read as protection against active probing, not as a
claim that the client would otherwise instantly read out `K_org` or full
`y_relayer` from one honest run.

## Practical Attack Vectors

The practical attack model is repeated authenticated abuse, not naive direct
readout of server secrets.

### 1. Repeated probing with crafted requests

Attack shape:

- the attacker compromises an authenticated client session
- the attacker sends many threshold-eval requests with mostly valid payloads
- one field is varied at a time across runs
- the attacker studies success, failure, latency class, and output differences

Typical payloads:

- valid JWT or equivalent authenticated request state
- valid account and credential context
- near-valid OT material with one manipulated branch-related field
- replayed or swapped prepared-session artifacts
- repeated requests with chosen client inputs around one hypothesis

What this can exploit:

- weak transcript binding
- replayable setup material
- detailed failure signaling
- output released before all checks succeed

Why this matters:

- the attacker may not learn `K_org` or full `y_relayer` in one call
- the attacker may still be able to accumulate information across many calls

### 2. Replay and cross-session mix attempts

Attack shape:

- the attacker captures artifacts from one valid run
- the attacker replays them into a later run or mixes artifacts across runs
- the attacker checks whether the protocol accepts or rejects and what stage the
  failure reaches

Typical payloads:

- reused prepared-session identifiers
- swapped packet/bundle pairs from another run under the same account or
  credential
- stale output-delivery artifacts

What this can exploit:

- missing transcript/session binding
- missing one-time-use enforcement
- insufficient replay rejection

### 3. Selective-failure probing

Attack shape:

- the attacker sends malformed or strategically inconsistent payloads
- the attacker uses the resulting abort behavior as an oracle
- the attacker repeats this enough times to test hypotheses about server-held
  hidden state

Typical payloads:

- malformed OT-related material
- malformed Beaver-related material
- late-stage payloads that only fail if deeper checks are reached

What this can exploit:

- useful output revealed too early
- detailed failure reasons
- timing differences between failure classes

## Practical Interpretation

For this codebase, the main concern is usually:

- compromise of an authenticated client runtime
- repeated probing over many requests
- gradual entropy gain, if any, rather than instant one-shot exfiltration

That is why Tier 1 focuses on:

- authenticated session binding
- one-time-use prepared sessions
- replay rejection
- rate limiting
- anomaly detection
- minimal failure detail
- verify-before-reveal

## Product Constraint

The current hidden-eval runtime is already in the roughly `0.5s` to `0.7s`
band, depending on path and environment. That means full active-security work
must be justified against product latency.

If a change makes the product unusably slow, it is not acceptable as a
practical deployment path even if it improves the formal security story.

This plan therefore separates:

- minimum low-overhead abuse resistance for production hardening
- full protocol changes required for a formal malicious-security claim

The intended product stance is:

- defer the expensive malicious-security features if immediate one-shot or
  low-request exfiltration is not credible
- do not ignore them permanently
- revisit them later as part of a v2 design or as an optional higher-security
  mode if the performance hit is acceptable

## Deployment Tiers

### Tier 1: Practical Abuse Resistance

This tier does **not** give a formal malicious-security claim, but it may be
the right product tradeoff if the main concern is repeated probing by an
authenticated malicious client.

Required controls:

- strong authenticated session binding, such as JWTs bound to one request flow
- one-time-use prepared sessions
- replay rejection
- strict per-account, per-credential, and per-IP rate limiting
- anomaly detection for malformed or suspicious threshold-eval requests
- minimal client-visible failure detail
- transcript binding for setup artifacts, online packets, and outputs
- verify-before-reveal output discipline

Why this tier exists:

- it directly raises the cost of repeated probing attacks
- it is much cheaper than a full malicious-secure OT plus authenticated Beaver
  rollout
- it may be sufficient if the server is trusted and the product bar is
  pragmatic rather than formal
- it is the default deployment tier if Tier 2 would make the product too slow

### Tier 2: Formal Malicious-Client Security

This tier is the stronger cryptographic target.

It requires:

- transcript binding
- malicious-secure OT
- authenticated Beaver usage
- verify-before-reveal output discipline
- adversarial tests proving the cheating-client cases fail

Use this tier only if the product or compliance bar really requires the
stronger claim.

This tier may be pursued later as:

- a v2 protocol design
- an optional higher-security deployment mode for users who accept the latency
  cost

The exact slowdown is not known yet, but a substantial increase is plausible.
Malicious-secure OT plus authenticated Beaver checks could be materially more
expensive than the current semi-honest path, so this tier should not be assumed
cheap enough for universal default rollout.

## Minimum Required Protections

These are the minimum protocol-level protections required for a credible formal
malicious-client security claim. This is not an either/or list.

### 1. Transcript Binding

Every important artifact and message must be bound to one committed session
transcript and one committed hidden-eval program digest.

Required scope:

- setup artifacts
- OT payloads
- Beaver material
- online packets
- final outputs

Without this, replay, swap, and cross-session mix attacks remain possible.

### 2. Malicious-Secure OT

The OT path must prevent a cheating client from learning more than one valid
branch or exploiting malformed OT payloads.

Without this, a malicious client can target the branch-selection boundary
directly.

### 3. Authenticated Beaver Usage

The Beaver path must actively verify triple identity, triple consistency, and
one-time use.

Without this, a cheating participant can try to bias or probe hidden
multiplication silently.

### 4. Verify Before Reveal

Useful output must not be released until transcript, OT, Beaver, and packet
checks all succeed.

Without this, selective-failure behavior can still leak information even if the
earlier checks exist.

## Validation Requirement

Adversarial tests are not a separate cryptographic primitive, but they are
required to support the implementation claim.

The malicious-security rollout is not complete without explicit cheating-client
tests.

## Phased Todo List

### Phase 0. Freeze The Current Baseline

- [ ] record the exact semi-honest baseline in
  `crates/ed25519-hss/security.md`
- [ ] inventory every current unchecked seam in:
  - OT
  - Beaver usage
  - packet replay/swap handling
  - output release

Exit criteria:

- the current semi-honest assumptions are enumerated before protocol changes

### Phase 0.5. Land Low-Overhead Production Hardening

- [ ] require authenticated request/session binding for threshold-eval calls
- [ ] make prepared sessions one-time-use
- [ ] reject replayed prepared-session or output-delivery artifacts
- [ ] add strict rate limits and abuse detection for repeated malformed calls
- [ ] minimize client-visible failure detail
- [ ] ensure output reveal still happens only after basic packet/transcript
  checks pass

Exit criteria:

- repeated probing is operationally constrained even before full
  malicious-security protocol work lands

### Phase 1. Implement Transcript Binding

- [ ] define one transcript root that covers:
  - protocol version
  - context binding
  - participant roles
  - hidden-eval program digest
  - setup artifact digests
- [ ] bind OT payloads to that transcript root
- [ ] bind Beaver material to that transcript root
- [ ] bind online packets to that transcript root
- [ ] bind final outputs to that transcript root
- [ ] reject replayed, swapped, or cross-session artifacts

Code targets:

- `crates/ed25519-hss/src/succinct_hss.rs`
- `crates/ed25519-hss/src/ddh_hss.rs`

Exit criteria:

- no important artifact or packet is accepted without transcript binding

### Phase 2. Implement Malicious-Secure OT

- [ ] add branch-level transcript binding and input-index binding
- [ ] add OT consistency checks or replace the OT path with a malicious-secure
  variant
- [ ] reject malformed, replayed, or mismatched OT material
- [ ] verify that the client cannot realize more than one valid branch

Code targets:

- `crates/ed25519-hss/src/ddh_hss.rs`

Exit criteria:

- the OT path no longer relies on a semi-honest client assumption

### Phase 3. Implement Authenticated Beaver Usage

- [ ] bind every triple to transcript and gate identity
- [ ] enforce one-time triple use
- [ ] add triple consistency verification
- [ ] add masked-opening consistency verification for `d` and `e`
- [ ] abort on any malformed Beaver use before useful output release

Code targets:

- `crates/ed25519-hss/src/ddh_hss.rs`
- `crates/ed25519-hss/src/ddh_hidden_eval_executor.rs`

Exit criteria:

- malformed Beaver arithmetic is detected rather than silently consumed

### Phase 4. Implement Verify-Before-Reveal Output Discipline

- [ ] ensure final output release happens only after transcript, OT, and Beaver
  checks succeed
- [ ] remove or delay any useful output reveal that currently happens before the
  active checks complete
- [ ] normalize failure behavior where practical so cheating yields abort rather
  than extra signal

Code targets:

- `crates/ed25519-hss/src/succinct_hss.rs`
- output-delivery paths in
  `crates/ed25519-hss/src/ddh_hidden_eval_executor.rs`

Exit criteria:

- cheating can cause abort, but not extra useful reveal

### Phase 5. Add Adversarial Tests

- [ ] add replayed-packet tests
- [ ] add swapped-packet tests
- [ ] add transcript-mismatch tests
- [ ] add malformed OT tests
- [ ] add malformed Beaver tests
- [ ] add cheating-client tests that attempt to obtain extra branch or output
  views

Exit criteria:

- the malicious-client claim is backed by explicit negative tests

## Recommended Order

If the product needs practical hardening first:

1. Phase 0.5 low-overhead production hardening
2. transcript binding
3. verify-before-reveal output discipline
4. decide whether the remaining risk still justifies malicious-secure OT and
   authenticated Beaver usage

If the product needs the formal malicious-client claim:

1. transcript binding
2. malicious-secure OT
3. authenticated Beaver usage
4. verify-before-reveal output discipline
5. adversarial tests

## Benchmark Rule

The protocol-heavy changes are expected to increase latency, especially:

- malicious-secure OT
- authenticated Beaver usage

Transcript binding and verify-before-reveal should usually be cheaper.

Required sequence:

1. land the security change
2. prove the cheating case fails
3. rerun native and browser benchmarks
4. optimize the malicious-secure path afterward

Do not weaken the checks to preserve semi-honest benchmark numbers.

Practical deployment rule:

- if Tier 2 pushes end-to-end runtime past the product bar, ship Tier 1 first
  and treat Tier 2 as a separately justified security investment
- explicitly document Tier 2 as deferred rather than ignored

## Completion Bar

This plan is complete only when:

- transcript binding is enforced across setup, OT, Beaver, packets, and outputs
- the OT path is malicious-secure against a cheating client
- Beaver usage is actively verified
- useful output is withheld until verification succeeds
- adversarial tests cover the cheating-client cases that motivated the change
