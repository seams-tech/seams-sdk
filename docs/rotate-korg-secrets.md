# Router A/B Signing-Root Rotation Plan

Date updated: June 11, 2026

Status: design plan aligned with
[docs/router-a-b-SPEC.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/router-a-b-SPEC.md).

## Objective

Design the signing-root custody and rotation model for the Router A/B signer
architecture.

The goals are:

- avoid durable plaintext `signing_root_secret` / `k_org` storage
- avoid authoritative per-wallet durable server secret storage
- avoid a deterministic platform `master_secret` that can rederive customer
  roots after self-host migration
- preserve wallet addresses when custody shares are refreshed
- prevent any single server-side production process from seeing enough material
  to reconstruct joined `k_org`, `y_relayer`, `tau_relayer`, `d`, `a`, or
  `x_client_base`
- keep day-to-day signing on the Router plus one relayer path
- use Router + Signer A + Signer B only for registration, key export, recovery,
  and relayer-share refresh
- preserve a path from same-account Cloudflare Workers to separate Cloudflare
  accounts and later TEE-backed multi-cloud signers

Breaking package and API changes are allowed where they cleanly replace the old
single-signer custody model.

## Decision

Use randomly generated signing roots, but never let the normal hosted runtime
combine enough root material in one process.

For each project/environment:

1. Generate a random `signing_root_secret`, also called `k_org` in crypto
   notation.
2. Split it into a recoverable threshold sharing, initially 2-of-3.
3. Assign active custody roles to Signer A and Signer B.
4. Seal each custody share under role-specific wrapping keys.
5. Persist sealed shares with `signing_root_version`, `root_share_epoch`,
   storage locator, wrapping-key locator, and signer-role metadata.
6. Discard plaintext `k_org` after the root ceremony and backup/export ceremony
   complete.
7. Use Router + A + B for derivation-time ceremonies.
8. Use Router + one relayer for day-to-day signing after A/B have produced the
   allowed relayer output.

The active Router A/B invariant is:

```text
Router never has plaintext root shares.
Router never decrypts signer envelopes.
A sees only A custody material.
B sees only B custody material.
No hosted process opens joined y_relayer or tau_relayer during derivation.
No hosted process opens joined d, a, or x_client_base.
Client opens only x_client_base.
Relayer opens only x_relayer_base.
```

The canonical durable recovery material is the set of sealed signing-root
shares plus the customer backup package. There is no platform-only
`master_secret -> k_org` recovery path.

## Relationship To Router A/B

`docs/router-a-b-SPEC.md` owns the online service architecture:

```text
Client -> Router -> Signer A
                 -> Signer B

Signer A <-> Signer B

A/B -> Client: encrypted client-output packages
A/B -> Relayer: relayer-output packages
```

This document owns the root custody and rotation semantics underneath that
architecture:

```text
signing_root_secret / k_org
  -> role-specific sealed signing-root shares
  -> split y_relayer / tau_relayer derivation
  -> A/B HSS derivation
  -> x_client_base and x_relayer_base output delivery
```

The old "one signer decrypts two shares and combines into full `y_relayer`"
shape is no longer the target for hosted production. It remains useful only as
a reference-vector or emergency recovery ceremony, and must not be presented as
the security boundary for Router A/B.

## Naming

Use product-oriented names at API and storage boundaries. Use short crypto
names only in protocol internals.

| Concept | Preferred Name | Crypto/Internal Name |
| --- | --- | --- |
| Random signing root | `signing_root_secret` | `k_org` |
| Signing root version | `signing_root_version` | `k_org_version` |
| Root share epoch | `root_share_epoch` | share epoch |
| A custody share | `signing_root_secret_share_a` | `k_org_share_a` |
| B custody share | `signing_root_secret_share_b` | `k_org_share_b` |
| Backup/recovery share | `signing_root_secret_share_backup` | `k_org_share_backup` |
| Sealed root share | `sealed_signing_root_secret_share` | `enc(k_org_share_i)` |
| Share wrapping key | `share_wrapping_key` | KEK |
| A-side relayer root input | `server_wallet_root_input_a` | `y_A` |
| B-side relayer root input | `server_wallet_root_input_b` | `y_B` |
| Joined relayer root input | `server_wallet_root_input` | `y_relayer` |
| A-side relayer tau input | `server_tau_input_a` | `tau_A` |
| B-side relayer tau input | `server_tau_input_b` | `tau_B` |
| Joined relayer tau input | `server_tau_input` | `tau_relayer` |
| Server signing share | `server_signing_share` | `x_relayer` |
| Client signing share | `client_signing_share` | `x_client` |

The joined values are algebraic definitions:

```text
y_relayer = y_A + y_B
tau_relayer = tau_A + tau_B
```

They should not exist as plaintext transport payloads or persisted server state
in the hosted Router A/B path.

## Threat Model

The signing system uses threshold signing with:

- a server-side contribution derived from `k_org`
- a client-side contribution derived from passkey PRF material

Compromise of `k_org` is serious, but it is not by itself a complete wallet
compromise. An attacker still needs the user's client contribution to sign.

Router A/B primarily protects against:

- durable plaintext root exposure
- a Router compromise reading signer plaintext
- a single signer compromise reconstructing `k_org`
- a single signer compromise opening joined `y_relayer` or `tau_relayer`
- a modified hosted server logging joined `d`, `a`, or `x_client_base`
- self-host migration that preserves wallet addresses without retaining a
  hosted master-secret backdoor

Router A/B does not by itself prove full malicious security. A compromised party
can deny service, abort a protocol, send malformed messages, attempt replay, or
try active transcript confusion. Those failures must be detected through
transcript binding, role-specific envelope encryption, output-kind checks,
commitments, and later verifying-share/proof work where needed.

## Secret Hierarchy

Durable custody hierarchy:

```text
signing_root_secret / k_org
  -> threshold root shares
    -> role-specific sealed signing-root shares
      -> role-specific storage and wrapping-key domains
```

Hosted derivation hierarchy:

```text
A custody share -> A-side derivation material -> y_A, tau_A
B custody share -> B-side derivation material -> y_B, tau_B

y_A + y_B = y_relayer
tau_A + tau_B = tau_relayer

A/B HSS derivation -> x_client_A, x_client_B, x_relayer_A, x_relayer_B
client opens x_client_base
relayer opens x_relayer_base
```

Normal signing hierarchy:

```text
client contribution + relayer x_relayer_base -> threshold signature
```

Normal signing should not unwrap `k_org` shares or invoke Signer A and Signer B.

## Canonical Records

`SigningRootRecord` is the durable root record for one
project/environment/root version.

It should contain:

- `project_id`
- `env_id`
- `signing_root_id`
- `signing_root_version`
- `root_share_epoch`
- `derivation_version`
- wallet origin and RP ID binding
- share threshold and share count
- sealed signing-root shares
- per-share role: A, B, backup, export, or recovery
- per-share storage locator
- per-share wrapping-key locator
- signer identity policy for A and B
- source metadata such as hosted generated, customer imported, customer
  generated, dev, or self-host

Wallet metadata should include:

- `project_id`
- `wallet_id`
- `user_id`
- `rp_id`
- `scheme_id`
- `key_purpose`
- `wallet_key_version`
- `signing_root_version`
- `root_share_epoch` used for the latest derivation ceremony
- `derivation_version`
- threshold public key
- address or chain-specific public identity
- active or retired status

## Root Creation

Project creation uses an audited root ceremony:

1. Generate `signing_root_secret` using a CSPRNG.
2. Assign `signing_root_version = 1`.
3. Assign `root_share_epoch = 1`.
4. Split the root with the selected threshold sharing.
5. Assign role-specific shares to Signer A, Signer B, and backup/recovery.
6. Seal each hosted share under its role-specific wrapping key.
7. Persist `SigningRootRecord` and indexed sealed shares atomically.
8. Export a customer backup package.
9. Require customer backup confirmation before production activation.
10. Zeroize plaintext `signing_root_secret` and plaintext root shares from the
    provisioning boundary.

The root ceremony is the only normal hosted ceremony that may reconstruct
`k_org`. In production, it should run in a narrow provisioning boundary with
approval, audit logging, and no request-driven signing capability.

## Derivation-Time Flow

Registration, recovery, key export, and relayer-share refresh use Router + A +
B:

```text
Client -> Router:
  public metadata
  encrypted A envelope
  encrypted B envelope

Router -> A:
  encrypted A envelope
  public metadata

Router -> B:
  encrypted B envelope
  public metadata

A <-> B:
  transcript-bound protocol messages

A/B -> Client:
  encrypted client-output packages

A/B -> Relayer:
  relayer-output packages
```

Signer A:

- unwraps only A custody material
- receives only A-side client material
- computes A-side derivation material
- emits only A-side client and relayer output packages

Signer B:

- unwraps only B custody material
- receives only B-side client material
- computes B-side derivation material
- emits only B-side client and relayer output packages

The Router stores only public lifecycle state, hashes, transcript digests,
timing, and error codes.

## Derivation Primitive Decision

The previous threshold-PRF plan derived a full `y_relayer` by combining PRF
partials:

```text
partial_i = [k_org_share_i] P
partial_j = [k_org_share_j] P
Z = lambda_i * partial_i + lambda_j * partial_j
y_relayer = HashToBytes("y_relayer:v1", encode(Z), wallet_context)
```

That shape is useful for reference vectors, but a signer/combiner that computes
`HashToBytes(...)` sees joined `y_relayer`. Router A/B needs a split-output
derivation:

```text
A derives y_A and tau_A.
B derives y_B and tau_B.
No party opens y_relayer = y_A + y_B.
No party opens tau_relayer = tau_A + tau_B.
A/B feed split material into the HSS derivation protocol.
```

There are two acceptable implementation paths:

- **MPC threshold-PRF-to-shares.** Keep the threshold-PRF construction, but have
  A and B produce additive shares of `HashToBytes(...)` without opening the
  hash output to one combiner.
- **New split root derivation.** Define a versioned derivation that naturally
  produces `y_A`, `y_B`, `tau_A`, and `tau_B` under the Router A/B security
  invariant.

Do not use a construction that exposes enough derived wallet input to make
root-share compromise analysis unclear. Any new split derivation must have
dedicated vectors, domain separation, and a review of what one derived share
reveals.

## Rotation Semantics

There are three different operations. They must not be conflated.

### Rewrap Root Shares

Rewrap means encrypting the same root shares under new wrapping keys.

Result:

- same `signing_root_secret`
- same root shares unless refresh also happens
- same wallet addresses
- no passkey re-registration
- no relayer-share refresh unless wrapping-key policy requires it

Router A/B handling:

- A rewraps only A custody shares.
- B rewraps only B custody shares.
- backup/export shares are rewrapped by their custody boundary.
- Router coordinates approvals and records public audit state.
- No party opens joined `k_org`, `y_relayer`, or `tau_relayer`.

### Refresh Root Shares

Refresh means replacing hosted root shares while preserving the same underlying
`signing_root_secret`.

Result:

- same `signing_root_secret`
- new root-share values
- incremented `root_share_epoch`
- same wallet addresses
- no passkey re-registration
- relayer shares may need refresh if the active relayer state was derived under
  an old custody epoch policy

This is the address-preserving operational rotation.

Preferred hosted refresh is distributed resharing:

```text
A old share + B old share + optional recovery participant
  -> new A share
  -> new B share
  -> new backup/recovery share
```

No hosted production process should reconstruct `k_org` during refresh. A
controlled provisioning or TEE ceremony may be used as an interim tool, but it
must be labeled as a stronger-trust ceremony and audited separately from normal
Router A/B operation.

Refresh protocol requirements:

1. Authenticate the refresh operation.
2. Pin `signing_root_version` and current `root_share_epoch`.
3. Freeze new derivation ceremonies for the project/environment.
4. Run distributed resharing or approved provisioning ceremony.
5. Seal new A, B, and backup/recovery shares under active wrapping keys.
6. Write all shares under `root_share_epoch + 1` atomically.
7. Run address/public-key parity checks against known wallet inventory.
8. Run a Router A/B relayer-share refresh for active relayer material when
   policy requires it.
9. Mark the new epoch active.
10. Retire old sealed shares after rollback window and evidence export.

### Replace Signing Root

Replacing the signing root means creating `signing_root_secret[v+1]`.

Result:

- new `signing_root_secret`
- new server-side derivation material
- usually new threshold public key
- usually new wallet address
- wallet-key migration required

Use this for root compromise or intentional full rekeying, not normal
operational rotation.

## Relayer-Share Refresh

Relayer-share refresh is the normal way to update the active relayer's allowed
`x_relayer_base` after a custody, derivation, relayer, or deployment change.

Flow:

```text
Router authenticates refresh request
Router sends encrypted A/B envelopes
A/B run split derivation for the target wallet/account context
A/B send client-output packages to the client if needed
A/B send relayer-output packages to the designated relayer
Relayer opens and activates x_relayer_base
Router records public transcript and activation status
```

This path must not require both A and B for normal day-to-day signing after the
refresh is complete.

## Recovery Model

Recovery requires enough root shares to reconstruct or reshare the root, or the
customer backup package.

Recovery paths:

- one hosted signer unavailable: use the remaining hosted/recovery shares
  through an approved recovery ceremony
- one storage location lost: recover from the other shares
- one wrapping key unavailable: recover from other shares if their wrapping keys
  are available
- all hosted storage lost: recover from customer backup
- customer self-host migration: export or reshare root shares to customer
  infrastructure

There is no deterministic platform `master_secret` recovery path. That improves
post-migration trust semantics, but it requires customer backup and recovery
drills.

## Security Boundaries

### Router Compromise

Impact:

- can deny service, replay stale outer requests, route incorrectly, or return
  incomplete responses
- should see only public metadata, ciphertext, hashes, and transcript digests
- should not learn A plaintext, B plaintext, root shares, `y_relayer`,
  `tau_relayer`, `d`, `a`, `x_client_base`, or `x_relayer_base`

Response:

1. rotate Router deploy credentials and signing keys
2. inspect transcript and routing logs
3. invalidate pending ceremonies
4. require signer-side replay protection to reject stale Router traffic

### Signer A Or B Runtime Compromise

Impact:

- exposes that signer's custody share and role-local derived material
- should not expose joined `k_org`, joined `y_relayer`, joined `tau_relayer`,
  joined `d`, joined `a`, or `x_client_base`

Response:

1. disable the affected signer
2. rotate deploy credentials and wrapping-key permissions
3. refresh root shares if share integrity is uncertain
4. refresh relayer shares for affected wallets/accounts
5. inspect signer, storage, and unwrap audit logs

### A And B Runtime Compromise

Impact:

- hosted root custody may be compromised
- relayer derivation material may be compromised
- attacker still needs client contribution for signing, but server-side risk is
  elevated across the project/environment

Response:

1. stop new wallet enrollment under the affected root
2. disable affected relayer material
3. decide whether signing-root replacement and wallet migration are required
4. increase signing monitoring and policy restrictions
5. notify customers according to incident policy

### Relayer Runtime Compromise

Impact:

- exposes `x_relayer_base`
- does not expose `k_org`, `y_relayer`, `tau_relayer`, `d`, `a`, or
  `x_client_base`
- attacker still needs client contribution to sign

Response:

1. disable affected relayer deployment
2. rotate relayer identity and storage credentials
3. run Router A/B relayer-share refresh
4. inspect signing attempts and policy logs

### Customer Backup Loss

Impact:

- no immediate signing impact if hosted shares remain available
- disaster recovery margin is reduced

Response:

1. require customer to regenerate or download a new backup package
2. optionally refresh root shares before issuing the new backup
3. block production-ready recovery status until backup confirmation completes

## Self-Host Migration

Same-wallet self-host migration transfers custody of the same
`signing_root_secret`.

Recommended flow:

1. Freeze new wallet enrollment for the project/environment.
2. Pin `signing_root_version` and `root_share_epoch`.
3. Customer provides import wrapping metadata.
4. Hosted export ceremony loads the active `SigningRootRecord`.
5. Hosted export ceremony rewraps or reshares hosted shares into customer
   custody.
6. Export `SigningRootMigrationExportArtifactV1` with customer-sealed shares,
   wallet inventory, and checksum.
7. Customer imports the artifact.
8. Customer verifies known wallet addresses.
9. Hosted signing is disabled.
10. Hosted shares are deleted or retired.
11. Deletion and disablement evidence is exported.

Result:

- same `signing_root_secret`
- same wallet addresses
- no hosted platform master secret remains able to rederive the customer's root

If the customer wants a fresh root, that is wallet-key migration.

## Local Development

Local development should mirror Router A/B boundaries:

```text
localhost:9090  Router
localhost:9091  Signer A
localhost:9092  Signer B
localhost:9093  Relayer
local Postgres  signing-root metadata and sealed-share records
```

Local requirements:

- local Postgres stores active `SigningRootRecord` and sealed shares
- Router env has no share decrypt keys
- Signer A env has only A keys and A share access
- Signer B env has only B keys and B share access
- Relayer env has only relayer-output activation/storage access
- fixtures are allowed only behind explicit no-DB test flags

Local tests should prove:

- Router cannot decrypt A/B envelopes
- A rejects B-only material
- B rejects A-only material
- no local process materializes joined `d`, `a`, or `x_client_base`
- share refresh preserves known wallet addresses
- relayer-share refresh activates the expected `x_relayer_base`

## Rust/Wasm Implementation Direction

The Router A/B protocol core should be pure Rust and platform-agnostic:

```text
crates/router-ab-core
  split derivation backend
  role-specific protocol types
  transcript state machines
  envelope framing
  output package validation
  host traits and local simulation

crates/router-ab-cloudflare
  workers-rs adapters
  Env parsing
  fetch/service-binding transport
  Response mapping

crates/router-ab-dev
  SQLite seed tooling
  local persistence smoke tests
  development-only database adapters
```

Cloudflare Workers should use `workers-rs` wrappers around the pure Rust core.
Future TypeScript, Axum, Nitro, GCP, or Node deployments should use the same
canonical wire protocol and may call the Rust core through Wasm where useful.

## Implementation Phases

These phases replace the old single-signer-first rollout.

| Phase | Runtime Shape | TEE Required | Launch Requirement |
| --- | --- | --- | --- |
| Phase 1 | Local Router/A/B boundary simulation | no | yes |
| Phase 2 | Cloudflare Router/A/B with deterministic dev derivation | no | yes |
| Phase 3 | Cloudflare Router/A/B with real split derivation | no | yes |
| Phase 4 | Separate Cloudflare accounts for Router, A, B, and optional relayer | no | no |
| Phase 5 | Multi-cloud TEE signers | yes | no |

### Phase 1. Local Router A/B Boundary Simulation

1. Add local Router, Signer A, Signer B, and Relayer processes.
2. Seed local SQLite or Postgres with signing-root metadata and role-specific
   sealed shares.
3. Use deterministic transcript-bound dev outputs.
4. Prove Router opacity, wrong-role rejection, transcript binding, replay
   rejection, and output-kind separation.
5. Prove normal signing uses Router plus one relayer.

### Phase 2. Cloudflare Router A/B Boundary

1. Deploy Router, Signer A, Signer B, and Relayer as Cloudflare Workers.
2. Use same-account Service Bindings for the prototype.
3. Keep A/B payloads encrypted and role-specific.
4. Keep deterministic dev derivation until the split derivation primitive is
   finalized.
5. Record Worker size, `startup_time_ms`, setup/export latency, and normal
   signing latency.

### Phase 3. Real Split Derivation

1. Choose MPC threshold-PRF-to-shares or a new split root derivation.
2. Produce `y_A`, `y_B`, `tau_A`, and `tau_B` without opening joined relayer
   root material.
3. Feed split material into A/B HSS derivation.
4. Produce client-output and relayer-output packages.
5. Add vectors proving wallet identity is stable across root-share refresh.
6. Add source guards proving joined secret state does not cross production
   boundaries.

### Phase 4. Separate Cloudflare Accounts

1. Move Router, A, B, and optional relayer into separate Cloudflare accounts.
2. Replace same-account Service Bindings with authenticated HTTPS.
3. Pin signer identities and key epochs in the Router policy.
4. Split deploy credentials, storage credentials, wrapping keys, and logs.
5. Keep the wire protocol unchanged.

### Phase 5. Multi-Cloud TEE Signers

1. Move Signer A to an AWS Nitro Enclave-backed service.
2. Move Signer B to a Google Cloud Confidential service.
3. Bind signer identity to attestation evidence, measurement, signing key,
   protocol version, and deployment epoch.
4. Encrypt A/B envelopes only to attested signer keys.
5. Bind peer attestation evidence into A/B transcripts.

## Implementation Todo List

### Milestone A. Data Model

- [x] Define `SigningRootRecord`.
- [x] Define `SealedSigningRootSecretShare`.
- [x] Define `root_share_epoch`.
- [x] Define share wrapping-key locator metadata on sealed share records.
- [x] Define migration bundle and export artifact shapes for self-host export.
- [x] Define durable sealed-share storage for Postgres, Cloudflare Durable
      Objects, and in-memory tests.
- [x] Define wallet metadata that includes `signing_root_version` and
      `derivation_version`.
- [x] Remove public docs that present deterministic `master_secret -> k_org` as
      the target model.
- [ ] Add role ownership to hosted sealed-share records: A, B, backup, export,
      or recovery.
- [ ] Add signer identity policy to `SigningRootRecord`.
- [ ] Make hosted `signingRootVersion` and `rootShareEpoch` mandatory at the
      Router A/B boundary.

### Milestone B. Root Ceremony And Backup

- [ ] Implement random root generation.
- [ ] Implement 2-of-3 or selected threshold splitting.
- [ ] Implement role-specific share sealing.
- [ ] Write complete `SigningRootRecord` and indexed sealed shares atomically.
- [ ] Implement customer backup package generation.
- [ ] Implement root zeroization after provisioning.
- [ ] Add recovery drills proving root creation and backup restore do not depend
      on platform master-secret rederivation.

### Milestone C. Router A/B Protocol Core

- [x] Create pure Rust `router-ab-core` crate.
- [x] Define role-specific A/B/root-epoch types.
- [x] Define transcript binding for root version, root epoch, signer identity,
      account, session, request kind, and relayer identity.
- [x] Define encrypted A/B envelopes.
- [x] Define client-output and relayer-output packages.
- [x] Add type fixtures/source guards for wrong-role and wrong-output paths.

### Milestone D. Local Simulation

- [x] Start local Router, Signer A, Signer B, and Relayer processes.
- [x] Seed local SQLite/Postgres plans with role-specific sealed shares.
- [x] Add deterministic transcript-bound dev derivation.
- [x] Add end-to-end local request through Router.
- [ ] Add negative tests for Router plaintext access, wrong-role payloads,
      replay, expiry, transcript mismatch, and output-kind confusion.

### Milestone E. Split Derivation

- [ ] Decide between MPC threshold-PRF-to-shares and new split root derivation.
- [ ] Add canonical vectors for `y_A`, `y_B`, `tau_A`, `tau_B`, and output
      packages.
- [ ] Prove no one-process combiner opens joined `y_relayer` or `tau_relayer`.
- [ ] Wire split derivation into A/B HSS.
- [ ] Add address/public-key parity tests before and after root-share refresh.

### Milestone F. Cloudflare Deployment

- [ ] Add `workers-rs` Router wrapper.
- [ ] Add `workers-rs` Signer A and Signer B wrappers.
- [ ] Add `workers-rs` Relayer wrapper.
- [ ] Configure same-account Service Bindings for prototype deployment.
- [ ] Record compressed/uncompressed Worker size and `startup_time_ms`.
- [ ] Benchmark setup/export/refresh with 1, 2, 3, and 4 A/B round trips.
- [ ] Benchmark normal signing through Router plus one relayer.

### Milestone G. Rotation And Recovery

- [ ] Implement role-local rewrap.
- [ ] Implement distributed or approved-provisioning root-share refresh.
- [ ] Increment `root_share_epoch`.
- [ ] Verify known wallet addresses after refresh.
- [ ] Run relayer-share refresh where policy requires it.
- [ ] Delete or retire old share epochs after rollback window.
- [ ] Add break-glass recovery runbooks.

### Milestone H. Self-Host Migration

- [ ] Implement hosted export authorization and approval flow.
- [ ] Export `SigningRootMigrationExportArtifactV1` with checksum, wallet
      inventory, and customer-sealed shares.
- [ ] Rewrap or reshare hosted shares into customer custody.
- [ ] Verify imported artifact checksum before persisting self-host records.
- [ ] Verify self-host worker derives the same wallet addresses.
- [ ] Disable hosted signing after customer verification.
- [ ] Delete or retire hosted shares.
- [ ] Export audit evidence.

## Non-Goals

- durable plaintext `k_org` storage
- deterministic platform rederivation of customer roots
- authoritative per-wallet durable server secret storage
- presenting one-worker root reconstruction as the hosted production boundary
- a one-process combiner that opens joined `y_relayer` for Router A/B hosted
  production
- two-server online signing for every normal signature
- transparent wallet identity preservation when the signing root is replaced
- full malicious-secure MPC proof system in the first Router A/B implementation

## Open Questions

- Which split derivation primitive should replace the old full-`y_relayer`
  combiner path?
- Should the initial production shares start in one Postgres database with
  role-specific KEKs, or split across storage accounts from day one?
- Which share wrapping keys are acceptable for Signer A and Signer B?
- Should the customer backup contain the hosted sharing or a distinct customer
  backup sharing?
- What backup confirmation UX is required before production activation?
- What exact signer identity registry is used for A, B, Router, and relayer?
- Which values must be committed publicly so clients can detect bad output?
- When does the threat model justify moving A and B to separate Cloudflare
  accounts?
- Which TEE providers and attestation policies should Phase 5 target?
- Do we support both self-host rewrap and self-host resharing?

## Summary

The target model is:

- random `signing_root_secret` / `k_org`
- sealed, role-specific signing-root shares
- no durable plaintext `k_org`
- no deterministic platform `master_secret`
- customer backup required
- Router sees only ciphertext and public metadata
- Signer A sees only A custody material
- Signer B sees only B custody material
- no hosted production process opens joined `y_relayer`, `tau_relayer`, `d`,
  `a`, or `x_client_base`
- Router + A + B handles registration, export, recovery, and relayer-share
  refresh
- Router + one relayer handles day-to-day signing
- share rewrap and share refresh preserve wallet addresses
- signing-root replacement changes wallet identity unless the product layer
  handles migration
- same-account Cloudflare Workers are the prototype target
- separate Cloudflare accounts and multi-cloud TEEs are later hardening stages
