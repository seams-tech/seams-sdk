# Homomorphic Key Export Support Plan (Ed25519, Option B)

Date updated: March 25, 2026

## Objective

Define a simpler alternative Ed25519 architecture for NEAR accounts with:

- one threshold operational key `a`,
- one independent recovery key `d`,
- both attached to the same NEAR account,
- both derived from one shared client/server root design through domain-separated derivation,
- standard NEAR-compatible recovery-key export,
- server-blind recovery export using homomorphic encryption.

This option deliberately does not require one canonical Ed25519 secret to serve both:

- threshold transaction signing, and
- standard seed-based private-key export.

That separation is the point of the design.

## Core Idea

Use two sibling keys for the same NEAR account:

- operational key:
  - threshold-only,
  - used for normal transaction signing,
  - identified by public key `pk_a`,
- recovery key:
  - standard Ed25519 seed-based key,
  - used only for explicit recovery/export/admin flows,
  - identified by public key `pk_d`.

High-level architecture:

```text
           shared client/server root design

        client secret                server secret
      WebAuthn prf.output              K_org
              |                          |
              |                          |
     HKDF("op/client", ctx)    HKDF("op/server", ctx)
              |                          |
              +-------- combine ---------+
                         |
                         v
                  threshold key domain
                         |
                         v
                         a
                         |
                      pk_a = [a]B

        client secret                server secret
      WebAuthn prf.output              K_org
              |                          |
              |                          |
   HKDF("recovery/client", ctx) HKDF("recovery/server", ctx)
              |                          |
              +-------- combine ---------+
                         |
                         v
                  recovery seed domain
                         |
                         v
                         d
                         |
                   pk_d = Ed25519(d)

             attach both pk_a and pk_d to one NEAR account
```

Important clarification:

- this plan does not derive both keys from a hidden combined root `M` and then evaluate `KDF(M, label)` inside a hidden computation,
- instead, each party derives its own labeled contribution locally and the protocol combines the resulting shares,
- this preserves the "shared-root" architecture without turning the KDF step into an MPC requirement.

## Frozen Homomorphic Encryption Scheme

Recovery export in Option B should use a fixed additive homomorphic encryption scheme:

- scheme: Paillier,
- modulus size: at least 2048 bits,
- plaintext space: `Z_n` with `n > 2^256`.

Encoding rule:

- recovery seed shares in `Z_(2^256)` are encoded as non-negative integers inside `Z_n`,
- because `n > 2^256`, this encoding is lossless for the full 256-bit recovery-share domain.

Required server operation:

- `HE_AddConst(C, y_server)` where `C` encrypts `y_client`.

Why this is frozen here:

- it fixes ciphertext size expectations at roughly the 2048-bit Paillier scale,
- it makes worker/runtime cost concrete,
- it prevents the export path from drifting into an unspecified HE abstraction.

## Why This Option Exists

The hardest part of the single-key Ed25519 design is not additive combine itself.
The hard part is forcing one hidden seed to also become threshold Ed25519 signing material:

- `d -> SHA-512(d) -> clamp -> a`

If the system requires:

- standard seed export for NEAR tooling, and
- threshold signing over the same hidden Ed25519 secret,

then the nonlinear seed-expansion step becomes the bottleneck.

Option B avoids that bottleneck by separating roles:

- `a` is the threshold signing secret,
- `d` is the recovery/export secret.

This means:

- homomorphic export is needed only for the recovery seed domain,
- no MPC is needed for recovery export itself,
- the operational threshold signer can use its own share model without pretending it is an exportable NEAR seed.

## NEAR Account Model

One NEAR account holds two keys:

- `pk_a`: threshold operational key,
- `pk_d`: recovery key.

Bootstrap rule:

- new accounts should attach `pk_a` and `pk_d` in the same account-creation flow,
- this should be one bootstrap transaction sequence for account creation,
- after bootstrap, the user should not need to perform a second explicit key-attachment step just to enable recovery.

Design assumption:

- both should be full-access keys if the recovery key must be able to rotate keys, remove the operational key, or otherwise recover the account without cooperation from the threshold signer.

Important consequence:

- NEAR does not natively understand "operational" vs "recovery" semantics,
- on-chain, these are just two attached access keys,
- the distinction is enforced by product policy and UX, not by NEAR protocol semantics alone.

## Strict Architectural Rule

In this option there are exactly two Ed25519 key roles for NEAR:

- one threshold operational key lifecycle,
- one recovery/export key lifecycle.

Implementation consequences:

- the operational key lifecycle must not also be treated as the standard export key lifecycle,
- the recovery key lifecycle must not be used on the hot signing path,
- no hidden `d -> a` conversion path should exist,
- no fallback mode should silently reinterpret a threshold scalar as a NEAR seed export artifact.

## Frozen Decisions

The following decisions are locked for Option B and should be treated as settled design constraints, not open questions:

- `pk_a` is the only hot-path threshold signing key.
- `pk_d` is a standard seed-based recovery key, not a threshold signing key.
- new NEAR accounts attach both `pk_a` and `pk_d` in the same bootstrap account-creation flow.
- recovery export is stateless:
  - `y_client` is re-derived from `prf.output` and `ctx`
  - `y_server` is re-derived from `K_org` and `ctx`
  - no persisted per-account recovery export share record is required
- `relayerExportShareB64u` is not part of the Option B recovery design.
- Paillier is used only for explicit recovery/export flows.
- registration does not require Paillier.
- normal signing does not require Paillier.
- the client provides `recoveryPublicKey` during bootstrap/account registration.
- the server does not attempt to derive `recoveryPublicKey` from its share alone.
- bootstrap is allowed to reconstruct `d` once on the client in order to compute `pk_d` for first account creation.
- bootstrap reconstruction of `d` is a one-time enrollment exception, not the normal recovery/export path.
- after bootstrap computes `pk_d`, the client discards `d`; bootstrap does not persist plaintext recovery seed material.
- `relayerKeyId` remains the operational threshold-key identifier for `pk_a`.
- recovery export verification is always against `pk_d`, never against `pk_a`.
- operational threshold signing state and recovery export state must be modeled as separate domains in code, storage, and API payloads.

Implementation consequence:

- any request type, struct, IndexedDB record, or route payload that still implies one Ed25519 public key serves both threshold signing and standard NEAR seed export is legacy and should be rewritten rather than preserved.

## Mathematical Model

### Context binding

Let `ctx` bind at least:

- `orgId`
- `accountId`
- `keyPurpose`
- `keyVersion`
- participant ids
- derivation version

Let `K_org` be the tenant-specific server master secret.

Let `prf.output` be the client WebAuthn PRF output for the same account context.

## Stateless Recovery Guarantee

Option B should make recovery export stateless at the per-account share layer.

Guarantee:

- `y_client` is deterministically re-derivable from `prf.output` and `ctx`,
- `y_server` is deterministically re-derivable from `K_org` and `ctx`,
- no per-account persisted recovery-share state is required for recovery export to succeed.

Operational consequence:

- accidental loss of a per-account recovery-share database should not destroy recovery export capability,
- recovery export remains available as long as the system still has:
  - the client WebAuthn PRF path,
  - the tenant server root secret,
  - the correct context binding inputs.

Stronger form:

- if the operational threshold-key lifecycle also follows the same deterministic root-derivation model, then the entire Option B account design can be stateless per-account apart from disposable performance caches and metadata bindings.

## Operational key domain

Define domain-separated operational contributions:

- `u_client = HKDF_u256(prf.output, "ed25519/op/client:v1", ctx)`
- `u_server = HKDF_u256(K_org, "ed25519/op/server:v1", ctx)`

Interpret these in the operational-key construction domain.

This plan intentionally does not require a specific operational-key share construction here.
The only required invariant is:

- the operational lifecycle must produce threshold signing material for secret `a`,
- the threshold signer must realize public key `pk_a`,
- the hot signing path uses only the operational-key lifecycle.

This leaves room for:

- persisted per-account relayer shares,
- stateless rebuildable cached shares,
- rerandomized FROST base shares,
- or another threshold share package,

as long as none of those are treated as the recovery/export seed.

## Recovery key domain

Define domain-separated recovery-seed shares:

- `y_client = HKDF_u256(prf.output, "ed25519/recovery/client:v1", ctx)`
- `y_server = HKDF_u256(K_org, "ed25519/recovery/server:v1", ctx)`

Interpret both in `Z_(2^256)`.

Define:

- `m_d = y_client + y_server mod 2^256`
- `d = LE32(m_d)`

From `d` derive standard Ed25519 key material:

- `h_d = SHA-512(d)`
- `a_d = clamp(h_d[0..31])`
- `pk_d = [a_d]B`

The canonical exported recovery private key is:

- `ed25519:` + base58(`d || pk_d`)

Important property:

- `d` is a normal seed-based Ed25519 private key,
- this makes it directly compatible with standard NEAR key expectations,
- recovery export reconstructs `d`, not a scalar-only artifact.

## Why Recovery Export Does Not Require MPC

Recovery export for `d` does not require MPC if the system allows:

- reconstruction of `d` on the client during explicit recovery/export.

In that case the protocol only needs secure additive combine over the seed-share domain:

- client holds `y_client`,
- server holds `y_server`,
- client recovers `m_d = y_client + y_server mod 2^256`,
- client derives `d` and verifies `pk_d`.

Homomorphic encryption is enough because:

- the server only needs to add its share,
- the server does not need to evaluate `SHA-512`,
- the server does not need to clamp,
- the server does not need to produce threshold shares from hidden seed material.

MPC would only be required if the design changed to require:

- hidden transformation from shared seed material into hidden threshold signing material, or
- recovery signing with `d` while keeping `d` hidden from both parties.

That is explicitly out of scope for Option B.

## Homomorphic Recovery Export Flow

### Goal

Allow the client to reconstruct the recovery key `d` during explicit recovery/export while keeping the server blind to plaintext `d`.

### Export cost profile

Expected export round-trip:

- one HE ciphertext upload,
- one HE ciphertext response,
- one local HKDF derivation,
- one local HE decrypt,
- one local Ed25519 public-key verification.

At the 2048-bit Paillier level, this means roughly:

- about 512 bytes up,
- about 512 bytes down,
- no circuit transfer,
- no multi-round MPC,
- no OT setup.

### Protocol

1. Export init

- client requests a one-time recovery export ticket for `(orgId, accountId, keyPurpose, keyVersion)`,
- server validates authorization, step-up auth, policy, rate limit, and TTL,
- server issues a short-lived one-time `exportId`.

2. Client encrypts its recovery share

- client worker derives `y_client`,
- client worker generates ephemeral HE keypair `(pk_HE, sk_HE)`,
- client worker computes ciphertext `C = Enc_pk_HE(y_client)`,
- client sends `{ exportId, pk_HE, C, accountId, keyVersion }`.

3. Server homomorphic combine

- server validates `exportId`, account binding, TTL, and replay rules,
- server derives or loads `y_server` for the same bound context,
- server computes `C' = HE_AddConst(C, y_server)`,
- server returns `{ exportId, keyVersion, C' }`.

4. Client finalize

- client worker decrypts `m_d = Dec_sk_HE(C')`,
- client worker converts `m_d` to `d = LE32(m_d)`,
- client worker derives `pk_d_candidate` from `d`,
- client worker checks `pk_d_candidate == expected pk_d`,
- only on success may the client emit `ed25519:` + base58(`d || pk_d_candidate`),
- client worker zeroizes temporary buffers, `d`, `m_d`, `y_client`, and `sk_HE`.

### Required fail-closed check

Before any recovery artifact is emitted:

- derive `pk_d` from reconstructed `d`,
- compare against the expected recovery public key bound to the account and key version,
- abort on mismatch.

This check is mandatory because:

- the server cannot prove the client encrypted the intended share,
- the client must not export malformed or mismatched private material.

## Enrollment / Rotation Output

For each `(orgId, accountId, keyPurpose, keyVersion)`, enrollment or rotation must bind:

- operational public key `pk_a`,
- recovery public key `pk_d`,
- operational derivation spec version,
- recovery derivation spec version,
- operational server-side material or derivation metadata,
- recovery server-side share or derivation metadata,
- participant ids,
- explicit capability metadata indicating recovery export support.

If this option is adopted, the account lifecycle should treat both keys as one package:

- one account version,
- one operational key,
- one recovery key,
- one coherent policy surface.

## Bootstrap Attachment Flow

For new-account creation, the system should provision both keys together.

Required behavior:

1. derive and bind `pk_a` for the operational threshold lifecycle,
2. derive and bind `pk_d` for the recovery lifecycle,
3. create the NEAR account,
4. attach both `pk_a` and `pk_d` in the same bootstrap account-creation flow,
5. verify on-chain that both access keys are present for the new account version.

Design intent:

- recovery capability exists immediately after account creation,
- no follow-up user ceremony is needed just to attach the recovery key,
- the product story remains one registration flow, not registration plus later recovery-key activation.

### NEAR transaction structure

On NEAR, a single transaction can include multiple `AddKey` actions, so both `pk_a` and `pk_d` get attached atomically.

The flow would be:

1. Client worker derives both key domains in one enrollment session.
2. For bootstrap only, the client worker may reconstruct `d` once, compute `pk_d`, and immediately discard `d`.
3. Client sends the server: `pk_a`, `pk_d`, and whatever relayer-side material the server needs.
4. Server creates the NEAR account with a single transaction containing:
   - `CreateAccount`
   - `AddKey(pk_a, FullAccess)` — operational
   - `AddKey(pk_d, FullAccess)` — recovery
   - `Transfer` (initial funding)

Both keys are live from the first block. No second transaction, no window where only one key exists.

The server cannot compute `pk_d` from its share alone. Bootstrap therefore depends on the client-provided `pk_d`.

### Who provides `pk_d` at enrollment time

The client provides `pk_d` during bootstrap.

Reason:

- the server must know `pk_d` at enrollment time because it is submitting the `AddKey` action,
- the server holds only `y_server`,
- the server cannot compute `pk_d` from its share alone,
- bootstrap therefore allows the client to reconstruct `d` once, compute `pk_d`, send `pk_d`, and then discard `d`.

This is a bootstrap-only exception.

It does not change the normal recovery/export model:

- ordinary recovery export still uses the explicit Paillier flow,
- the server still never sees plaintext `d`,
- plaintext `d` is never persisted.

Operational note:

- the server may help construct, sponsor, and broadcast the bootstrap transaction sequence,
- but the bootstrap flow should still be treated as authorized account creation, not as a server-only administrative key insertion into an already-live account.

## Recovery Flow

A typical recovery flow should be:

1. user completes explicit recovery auth,
2. client reconstructs/export-reveals `d` through the HE combine flow,
3. client derives `pk_d_candidate` from `d` and fails closed unless it matches the persisted `pk_d`,
4. client reveals the standard NEAR recovery artifact `ed25519:` + base58(`d || pk_d`) in the secure export viewer,
5. user stores that recovery key and, if needed, uses normal NEAR tooling or wallet flows to manually recover account control.

Recommended policy:

- treat successful export/recovery as a high-sensitivity reveal event,
- rate limit and audit recovery export,
- do not auto-submit recovery transactions,
- do not auto-rotate `pk_a`,
- leave any follow-up key removal or rotation to explicit user action.

## Security Properties

### What this option improves

- avoids hidden seed-to-threshold Ed25519 conversion,
- keeps standard NEAR-compatible seed export simple,
- keeps the server blind to plaintext recovery key material during export,
- allows product-level recovery without requiring MPC on the recovery path,
- cleanly separates hot signing from recovery/export.

### What this option does not improve

- NEAR still sees two attached keys, not a protocol-native recovery role,
- the recovery key is a live admin key if it is full-access,
- compromise of recovery export flow compromises the account,
- compromise of the shared derivation inputs compromises both sibling key domains.

### Independence caveat

The two keys are independent on-chain but not independent in root custody.

If both are derived from:

- the same client PRF secret source, and
- the same server master secret source,

then compromise or loss of those root inputs affects both domains.

Domain separation prevents accidental key collision and cross-domain misuse.
It does not create true custody independence.

## Recommended Storage Model

### Operational key

- store or derive only the operational-key materials needed for threshold signing,
- allow server-durable cached threshold material if needed for performance,
- never treat operational threshold shares as exportable NEAR seed material.

### Recovery key

- server stores or derives only the server recovery share contribution `y_server`,
- client derives `y_client` from WebAuthn PRF output,
- reconstructed `d` exists only in client worker memory during explicit recovery/export,
- no plaintext `d` persistence in IndexedDB, localStorage, sessionStorage, or server storage.

## Product Policy Requirements

- recovery export must require explicit step-up auth,
- recovery export must be rate limited and audited,
- recovery export must use one-time short-lived tickets,
- recovery export must be disabled by default unless the account version explicitly supports it,
- successful recovery/export should surface explicit user guidance about secure storage and optional manual NEAR-side follow-up.

## Non-Goals

This option does not attempt to provide:

- one canonical Ed25519 secret that simultaneously powers threshold signing and NEAR seed export,
- hidden conversion from seed shares to threshold signing shares,
- threshold use of the recovery key while keeping the recovery seed hidden,
- recovery-key use on the hot transaction-signing path.

## Recommended Decision

Choose Option B if the priority order is:

1. simpler recovery/export architecture,
2. standard NEAR-compatible recovery key export,
3. server-blind export for the recovery key,
4. avoiding Ed25519 hidden seed-expansion MPC on the recovery path.

Do not choose Option B if the hard requirement is:

- one single Ed25519 key identity that must support both threshold signing and standard seed export with no separate recovery key.

## Why Not Option B

Do not choose Option B for chains whose account model is effectively bound to one canonical public key identity.

Examples include:

- Solana,
- Sui,
- Aptos,
- Stellar.

For those chains, the "separate operational key plus separate recovery key attached to the same account" model does not map cleanly to the chain's account semantics.

In those environments, the system generally needs one of:

- the single-seed design from Option A, or
- an MPC-over-`SHA-512` style approach for hidden Ed25519 seed expansion.

## Phased TODO List

### Phase 1: architecture freeze

- [x] Freeze Option B as a NEAR-only dual-key design.
- [x] Freeze the two key roles:
  - `pk_a` = threshold operational key
  - `pk_d` = recovery/export key
- [x] Freeze the bootstrap rule that new accounts attach both keys in the same account-creation flow.
- [x] Freeze the bootstrap assumption that the client may reconstruct `d` once to compute `pk_d`, then discard it.
- [x] Freeze the recovery export artifact as standard NEAR seed export:
  - `ed25519:` + base58(`d || pk_d`)
- [x] Freeze the rule that recovery export reconstructs `d`, never a scalar-form artifact.
- [x] Freeze the rule that Paillier is used only for explicit recovery/export flows, not registration or hot-path signing.
- [x] Remove or mark legacy any Ed25519 plan that still assumes one hidden Ed25519 secret must directly serve both threshold signing and NEAR seed export.

### Phase 2: derivation and binding spec

- [x] Freeze `ctx` contents for both operational and recovery domains.
- [x] Freeze derivation labels:
  - `ed25519/op/client:v1`
  - `ed25519/op/server:v1`
  - `ed25519/recovery/client:v1`
  - `ed25519/recovery/server:v1`
- [x] Freeze `keyVersion` semantics so `pk_a`, `pk_d`, and recovery export eligibility are all bound to the same account version.
- [ ] Freeze participant-id handling and derivation versioning for the operational threshold lifecycle.
- [x] Freeze the server-side source of truth for recovery export as deterministic derivation from `K_org` plus bound context, not persisted per-account recovery shares.
- [x] Freeze the public metadata that must be persisted per account:
  - `pk_a`
  - `pk_d`
  - `accountId`
  - `orgId`
  - `keyPurpose`
  - `keyVersion`
  - derivation versions
  - capability flags

### Phase 3: operational threshold lifecycle

- [ ] Choose the exact operational threshold construction for `pk_a`.
- [ ] Keep the operational lifecycle compatible with existing threshold signing orchestration wherever possible.
- [ ] Ensure the operational lifecycle does not require or emit any NEAR seed-export artifact.
- [ ] If the operational lifecycle can be derived from roots, define the deterministic rebuild flow.
- [ ] If the operational lifecycle still uses durable cached relayer shares, define them as disposable caches rather than canonical long-lived specs state.
- [ ] Bind the resulting operational package to:
  - `pk_a`
  - participant ids
  - `keyVersion`
  - derivation version

### Phase 4: bootstrap registration flow

- [x] Thread `recoveryPublicKey` through the client/server registration payloads, local persistence, and bootstrap response shapes so `pk_d` can be carried end-to-end.
- [x] Add a bootstrap recovery-share preflight so the client can fetch the deterministic server contribution for `pk_d` derivation before account creation.
- [x] Extend enrollment so the client derives both key domains during one registration session.
- [ ] Produce `pk_a` from the operational threshold lifecycle.
- [x] Produce `pk_d` from the recovery derivation domain.
- [x] Define the registration payload so the server receives all metadata needed to bootstrap the account, including `pk_a` and `pk_d`.
- [x] Update bootstrap account creation to submit one NEAR transaction containing:
  - `CreateAccount`
  - `AddKey(pk_a, FullAccess)`
  - `AddKey(pk_d, FullAccess)`
  - `Transfer`
- [x] Add post-commit verification that both `pk_a` and `pk_d` are visible as on-chain access keys for the new account.
- [x] Fail closed if only one key appears on-chain or if either key mismatches the expected public key.
- [x] Ensure no second user ceremony is required to enable recovery after account creation.

### Phase 5: Paillier recovery export runtime

- [x] Add a shared Paillier runtime with:
  - key generation
  - encryption
  - decryption
  - add-constant
  - strict serialization
- [x] Freeze the Paillier modulus size at `>= 2048` bits.
- [x] Implement strict encoding of `y_client`, `y_server`, and `m_d` in the `2^256` recovery-share domain.
- [ ] Add cross-runtime test vectors for:
  - `Enc(y_client)`
  - `AddConst(y_server)`
  - `Dec(y_client + y_server mod 2^256)`
- [x] Keep the recovery export runtime lazy-loaded so it does not affect the baseline client bundle or signing path.

### Phase 6: server recovery export module

- [ ] Add an explicit recovery export module under the threshold export namespace.
- [x] Rebind active `export/init` gating to persisted recovery metadata (`recoveryPublicKey`, `recoveryExportCapable`, `keyVersion`) instead of `relayerExportShareB64u`.
- [x] Implement `export/init` with:
  - authorization
  - step-up auth check
  - audit logging
- [x] Implement `export/init` with:
  - one-time ticket issuance
  - TTL
  - replay protection
- [x] Implement `export/combine` with:
  - ticket validation
  - account/key-version binding validation
  - `y_server` derivation from `K_org` and `ctx`
  - Paillier `HE_AddConst`
  - one-time ticket consumption
- [x] Ensure the server never exposes Paillier decrypt capability.
- [x] Ensure server logs never include plaintext shares, plaintext seeds, or raw ciphertext bodies unless explicitly redacted for debug mode in non-production environments.

### Phase 7: client recovery export flow

- [x] Implement worker-scoped recovery export orchestration.
- [x] Derive `y_client` from `prf.output` and the frozen recovery label set.
- [x] Generate ephemeral Paillier keypair `(pk_HE, sk_HE)` in worker memory only.
- [x] Encrypt `y_client` and call `export/combine`.
- [x] Decrypt `m_d`, convert to `d`, derive `pk_d_candidate`, and compare with expected `pk_d`.
- [x] Emit the recovery artifact only after the public-key match succeeds.
- [x] Zeroize:
  - `y_client`
  - `m_d`
  - `d`
  - `sk_HE`
  - temporary byte buffers
- [x] Fail closed on:
  - ticket expiry
  - replay
  - ciphertext parse failure
  - decrypt failure
  - public-key mismatch

### Phase 8: recovery execution and rotation

- [x] Define the exact client-side recovery flow after `d` is exported.
- [x] Add SDK helper copy for manual NEAR recovery follow-up after export.
- [ ] Decide policy for any recommended user follow-up after export:
  - manual remove/rotate `pk_a`
  - manual revoke `pk_d`
  - no immediate change
- [ ] Add structured audit events for:
  - export init
  - export combine
  - export finalize
  - optional manual-recovery handoff

### Phase 9: client and server cleanup

- [x] Remove `relayerExportShareB64u` from the active client/server/WASM bootstrap, registration, and storage surfaces.
- [x] Rename active Ed25519 export capability fields from `seedExportCapable` to `recoveryExportCapable`.
- [x] Rename active Ed25519 bootstrap/enrollment symbols to Option B terminology across client/server/WASM helpers and worker messages.
- [x] Freeze the active Option B lifecycle identifiers to:
  - `keyVersion = option-b-v1`
  - `artifactKind = near-ed25519-option-b-v1`
- [x] Remove legacy Ed25519 code paths that assume one hidden secret must serve both threshold signing and seed export.
- [x] Remove NEAR-specific scalar-export framing from recovery UX and APIs.
- [x] Remove any alternate or fallback Ed25519 enrollment mode that conflicts with the dual-key Option B story.
- [x] Update SDK, server, and docs terminology so the product story is only:
  - threshold operational signing
  - explicit recovery export
  - manual post-export recovery follow-up if the user chooses it

### Phase 10: verification and rollout

- [x] Add unit tests for derivation correctness and domain separation.
- [x] Add integration tests for registration/bootstrap with both `pk_a` and `pk_d` attached in one flow.
- [x] Add integration tests for recovery export happy path.
- [x] Add export-init unit coverage that asserts the WebAuthn step-up challenge is bound to persisted `(nearAccountId, rpId, relayerKeyId, keyVersion, recoveryPublicKey)` context.
- [x] Add negative coverage for replayed export tickets.
- [x] Add relayer route coverage for `export/init` that fails closed when `webauthn_authentication` is missing.
- [x] Add relayer route coverage for `export/init` that fails closed when step-up verification is denied.
- [x] Add unit coverage that `export/init` fails closed when persisted recovery metadata is incomplete (`recoveryPublicKey` missing or `recoveryExportCapable !== true`).
- [x] Add relayer route coverage that `export/init` fails closed when persisted recovery metadata is incomplete.
- [x] Add negative coverage for wrong `keyVersion`.
- [x] Add negative coverage for expired tickets.
- [x] Add negative coverage for malformed ciphertext / malformed Paillier payloads.
- [x] Add negative coverage for `pk_d` public-key mismatch after decrypt-and-derive.
- [x] Add negative coverage for wrong `accountId`.
- [x] Add service coverage that `export/combine` relies only on the authorized export session context, not current persisted key material.
- [x] Add tests that confirm no plaintext recovery key material is persisted at rest.
- [x] Add performance checks for:
  - registration latency versus current operational threshold enrollment
  - Paillier keygen latency on target browsers/devices
  - export request/response payload sizes
- [x] Re-run the benchmark on target desktop browser runtimes and append those measurements to `docs/benchmarks/threshold-ed25519-dual-key.md`.
- [x] Skip real release-target device benchmark runs for now.
  - Desktop/node/browser benchmark coverage remains recorded in `docs/benchmarks/threshold-ed25519-dual-key.md`.
- [ ] Monitor recovery export success/failure metrics once this becomes the default NEAR recovery model.

## Immediate Next Steps

- [x] Add registration/bootstrap integration coverage that asserts:
  - the recovery-share preflight is required
  - both keys are attached on-chain
  - operational-only bootstrap results are rejected
- [x] Add relayer route coverage for recovery export that asserts:
  - persisted recovery metadata remains the `export/init` gating source
- [x] Add service or route coverage for recovery export that asserts:
  - `export/combine` relies only on the authorized export session context, not caller-supplied account metadata
- [x] Tighten memory cleanup in the worker so Paillier private-key state and recovered seed buffers are actively overwritten after export completes.
- [x] Add tests that confirm no plaintext recovery key material is persisted at rest.
- [x] Add service or relayer integration coverage for the live recovery export happy path.
- [x] Run and record performance checks for registration latency, Paillier keygen latency, and export payload sizes in a dedicated benchmark runner under `benchmarks/threshold-ed25519-dual-key/` and sync the latest report to `docs/benchmarks/threshold-ed25519-dual-key.md`.
- [x] Refresh or replace the stale `crates/signer-core/fixtures/ed25519-option-b-v1/v1.json` vector so the full `near-threshold-ed25519` feature-gated Rust test suite passes again.
- [x] Decide whether the remaining performance checks belong in a dedicated benchmark runner under `benchmarks/` or as targeted browser/runtime specs in `tests/`.
- [x] Define the exact client-side recovery flow after `d` is exported and freeze the recovery reveal UX.
- [x] Add explicit SDK guidance for manual NEAR recovery follow-up after export.
- [x] Keep the post-export recovery screen neutral:
  - show the verified recovery artifact,
  - do not recommend an automatic `pk_a` rotation,
  - leave any follow-up key changes to explicit user action.
- [x] Remove the remaining active Ed25519 single-key and NEAR scalar-export assumptions from client/server/docs so the product story is only operational signing plus explicit recovery export.
- [x] Remove the remaining active alternate NEAR Ed25519 enrollment/export paths that treated recovery metadata as optional:
  - persistence now requires full Option B recovery metadata,
  - export no longer falls back to `clientNearPublicKey`,
  - local NEAR export assumptions are removed from binding/hardening coverage.
- [x] Tighten the remaining NEAR Option B helper/result types so successful bootstrap/keygen paths require:
  - `recoveryPublicKey`,
  - `recoveryExportCapable=true`,
  - full Option B bootstrap metadata.
- [x] Re-run the benchmark on desktop browser runtimes and append those measurements to `docs/benchmarks/threshold-ed25519-dual-key.md`.
- [x] Finish the one-key terminology/data-model sweep across the active NEAR Option B path.
- [x] Tighten the remaining Option B boundary/result types so successful NEAR bootstrap/keygen/export shapes are strict.
- [x] Remove residual alternate or fallback Ed25519 scaffolding from the active NEAR Option B path.
- [ ] Add recovery export success/failure monitoring once Option B becomes the default NEAR recovery model.
- [x] Skip real release-target device benchmark runs for now.

## Likely Repo Touchpoints

This section lists the first-pass file map for a sweeping Option B PR. The goal is to make the implementation reviewable as one coherent change instead of a set of scattered edits.

### New modules likely needed

- `crates/homo-enc-core/`
  - Add the Paillier runtime for keygen, encrypt, decrypt, and add-constant.
- `wasm/homo-enc-runtime/`
  - Add browser/server-facing WASM bindings for the Paillier runtime.
- `server/src/threshold/export/homoEncKeyExport/`
  - Add server-side recovery export module, ticket lifecycle, and observability wiring.

### Shared Rust and WASM touchpoints

- `crates/signer-core/src/near_ed25519_recovery.rs`
  - Add recovery-export helpers for `pk_d` on top of the current Option B bootstrap logic.
  - Keep NEAR `ed25519:` encoding and public-key verification for exported recovery seed `d`.
- `crates/signer-core/src/near_threshold_ed25519.rs`
  - Strip any remaining seed-export coupling from the operational threshold signer.
  - Make it purely about the operational key lifecycle for `pk_a`.
- `crates/signer-core/src/near_threshold_frost.rs`
  - Ensure the FROST path only models operational signing shares and verifying shares.
  - Remove any expectation that threshold shares double as NEAR seed-export material.
- `wasm/near_signer/src/handlers/handle_threshold_ed25519_derive_bootstrap_package.rs`
  - Keep the current Option B bootstrap package output aligned with the frozen identifiers and recovery-share preflight.
  - Add any recovery-export worker entry points needed for Paillier export finalization.
- `wasm/near_signer/src/handlers/mod.rs`
  - Register the new or renamed Option B enrollment/export handlers.
- `wasm/near_signer/src/types/worker_messages.rs`
  - Add new worker message payloads for:
    - dual-key enrollment derivation
    - recovery export combine/finalize
    - public-key verification for `pk_d`
- `wasm/near_signer/src/types/handlers.rs`
  - Update worker-dispatch types to match the new Option B handler surface.
- `wasm/near_signer/src/types/mod.rs`
  - Export the new worker message and result types.
- `wasm/near_signer/src/types/near.rs`
  - Confirm the NEAR action model supports bootstrap with two `AddKey` actions and any recovery rotation path updates.
- `wasm/near_signer/src/threshold/threshold_frost.rs`
  - Keep the operational threshold logic isolated from recovery export logic.

### Client enrollment and bootstrap touchpoints

- `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEd25519Lifecycle.ts`
  - Keep the dual-key enrollment result aligned with the frozen Option B output shape.
  - Return both `pk_a` and `pk_d` plus the operational/recovery derivation metadata required downstream.
- `client/src/core/signingEngine/threshold/workflows/keygenEd25519.ts`
  - Update the worker derivation flow to request the dual-key enrollment package.
  - Stop treating the result as one combined Ed25519 identity.
- `client/src/core/signingEngine/threshold/workflows/enrollEd25519Key.ts`
  - Update registration-time orchestration to carry `pk_a` and `pk_d` through the bootstrap payload.
- `client/src/core/signingEngine/interfaces/nearKeyOps.ts`
  - Change the key-ops interface to expose dual-key Option B derivation calls instead of the old one-key shape.
- `client/src/core/signingEngine/workerManager/nearKeyOps/index.ts`
  - Wire the new worker messages and results into the JS-side key-ops adapter.
- `client/src/core/rpcClients/near/rpcCalls.ts`
  - Update threshold Ed25519 keygen/export request shapes.
  - Add or revise RPC helpers for recovery export init/combine under the Option B contract.
- `client/src/core/TatchiPasskey/faucets/createAccountRelayServer.ts`
  - Extend the bootstrap request so account creation carries both `pk_a` and `pk_d`.
  - Update the request hashing surface accordingly.
- `client/src/core/TatchiPasskey/registration.ts`
  - Update registration flow state to derive both keys during one enrollment session.
  - Verify both keys after bootstrap account creation.
- `client/src/core/TatchiPasskey/thresholdWarmSessionBootstrap.ts`
  - Keep warm-session/bootstrap logic tied only to the operational threshold key `pk_a`.
  - Remove any assumption that the exported seed and threshold session refer to the same public key.
- `shared/src/utils/registrationBootstrapHash.ts`
  - Include the recovery-key bootstrap fields in the registration request hash so bootstrap signatures remain stable and auditable.

### Client storage and recovery-export touchpoints

- `client/src/core/indexedDB/passkeyNearKeysDB.types.ts`
  - Extend the stored NEAR threshold material schema to include recovery-key metadata such as:
    - `recoveryPublicKey`
    - recovery derivation version
    - export capability flags
- `client/src/core/indexedDB/near/keyMaterial.ts`
  - Persist and load the dual-key Option B metadata.
  - Keep operational threshold material separate from recovery export metadata.
- `client/src/core/signingEngine/api/recovery/privateKeyExportRecovery.ts`
  - Replace the current hard-disabled shortcut with the real worker-owned Option B export flow.
  - Require recovery export to verify reconstructed `d` against stored `pk_d`.
- `client/src/core/types/secure-confirm-worker.ts`
  - Add or update worker request/response types for recovery export with Paillier.
- `client/src/core/types/signer-worker.ts`
  - Add or update low-level worker message types for enrollment/export.
- `client/src/core/types/rpc.ts`
  - Update request/response DTOs for bootstrap, keygen, and export routes.
- `client/src/core/types/sdkSentEvents.ts`
  - Add or revise progress phases for:
    - dual-key enrollment
    - recovery export init
    - recovery export finalize
- `client/src/core/TatchiPasskey/near/emailRecovery.ts`
  - Update NEAR recovery flow copy to consume exported `d` without auto-rotation assumptions.
- `client/src/core/TatchiPasskey/near/linkDevice.ts`
  - Ensure device-linking remains bound to `pk_a` unless product policy explicitly wants to link recovery capability too.
- `client/src/core/TatchiPasskey/syncAccount.ts`
  - Update account sync logic to classify and surface both operational and recovery access keys on NEAR accounts.

### Server registration and threshold touchpoints

- `server/src/core/types.ts`
  - Update threshold Ed25519 bootstrap, keygen, and export request/response types for Option B.
  - Add explicit fields for `pk_d` and recovery export metadata.
- `server/src/core/AuthService.ts`
  - Update atomic registration/bootstrap to create the account with both `AddKey(pk_a)` and `AddKey(pk_d)`.
  - Persist or bind the public metadata for both keys under one account version.
  - Verify on-chain presence of both keys after bootstrap.
- `server/src/router/relayRegistrationBootstrap.ts`
  - Pass through the expanded Option B registration payloads and responses.
  - Ensure any JWT/session wrapping reflects the operational key only where appropriate.
- `server/src/core/ThresholdService/ThresholdSigningService.ts`
  - Replace the old one-key keygen assumptions with Option B dual-key enrollment parsing.
  - Implement or delegate the recovery export init/combine flow using deterministic `y_server` derivation.
- `server/src/core/ThresholdService/signingHandlers.ts`
  - Keep sign-init/finalize tied to `pk_a` only.
  - Remove any coupling between operational signing and recovery export semantics.
- `server/src/core/ThresholdService/relayerKeyMaterial.ts`
  - Rework relayer key material loading so operational shares and recovery export state are not conflated.
  - If the operational path becomes derivable from roots, demote persisted relayer shares to cache status.
- `server/src/core/ThresholdService/schemes/types.ts`
  - Expand scheme registration types to model the Option B dual-key result package.
- `server/src/core/ThresholdService/createThresholdSigningService.ts`
  - Wire any new recovery export module/config and adjust keystore assumptions if recovery export becomes stateless.
- `server/src/core/config.ts`
  - Add config normalization for Paillier export runtime and any Option B feature flag or stateless derivation toggles.

### Server route touchpoints

- `server/src/router/routeDefinitions.ts`
  - Update route contracts for Option B keygen and recovery export endpoints.
- `server/src/router/express/routes/thresholdEd25519.ts`
  - Update Express threshold Ed25519 routes to the Option B request/response shape.
- `server/src/router/cloudflare/routes/thresholdEd25519.ts`
  - Mirror the same route changes in the Cloudflare router.
- `server/src/router/cloudflare/types.ts`
  - Update Cloudflare route typings and request-body expectations for Option B.
- `server/src/router/cloudflare/durableObjects/thresholdEd25519Store.ts`
  - Update any session-state schema only if the operational threshold session payload changes.
- `server/src/router/express/routes/emailRecovery.ts`
  - Update recovery routes if they need to invoke or expose the new recovery export flow.
- `server/src/router/cloudflare/routes/emailRecovery.ts`
  - Mirror the same recovery-route changes for Cloudflare.
- `server/src/router/express/routes/syncAccount.ts`
  - Update sync response shape if it now surfaces both operational and recovery keys.
- `server/src/router/cloudflare/routes/syncAccount.ts`
  - Mirror the same sync changes for Cloudflare.

### Tests and fixtures that will likely move

- `tests/e2e/thresholdEd25519.testUtils.ts`
  - Update shared helpers to expect dual-key bootstrap behavior and recovery-key metadata.
- `tests/e2e/thresholdEd25519.*.test.ts`
  - Update registration/on-chain assertions to expect two keys on the account where appropriate.
  - Keep signing-path assertions tied to `pk_a`.
- `tests/relayer/threshold-ed25519.*.test.ts`
  - Update relayer-side keygen and export contract tests to the Option B shape.
- `tests/unit/thresholdEd25519*.test.ts`
  - Update unit coverage around request parsing, key material, and export gating.
- New tests:
  - add recovery export happy-path coverage
  - add `pk_d` mismatch fail-closed coverage
  - add bootstrap verification coverage for both access keys
  - add stateless re-derivation coverage for `y_server`

### Docs that should be kept in sync

- `docs/homomorphic-key-export-ED25519.md`
  - Either mark clearly as Option A / one-key design or replace references that imply it is the only Ed25519 path.
- `docs/stateless-shared-root-ed25519.md`
  - Cross-link the shared-root reasoning that Option B reuses for deterministic derivation.
- `docs/remove-local-ed25519-signer.md`
  - Update any cleanup guidance so it matches the dual-key Option B story rather than the old one-key story.

## Exact Symbols To Update

This is the stricter code-level edit map for the first sweeping PR. It intentionally calls out exact functions, types, and Rust structs so the implementation can be tracked against a concrete checklist.

### Client: enrollment, bootstrap, and persistence

- `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEd25519Lifecycle.ts`
  - `ThresholdEd25519LifecycleDeps`
    - Keep `deriveThresholdEd25519BootstrapPackage` as the single enrollment entry point for Option B.
  - `DeriveThresholdEd25519BootstrapPackageResult`
    - Replace the old one-key fields with explicit dual-key fields:
      - rename `publicKey` to `operationalPublicKey`
      - add `recoveryPublicKey`
      - remove `relayerExportShareB64u`
      - rename `seedExportCapable` to `recoveryExportCapable`
  - `deriveThresholdEd25519BootstrapPackageFromCredential()`
    - Keep the current Option B bootstrap entry point and continue rewriting its result shape away from one-key assumptions.
    - Return a dual-key registration package instead of a one-key package.

- `client/src/core/signingEngine/interfaces/nearKeyOps.ts`
  - `NearSigningKeyOps.deriveThresholdEd25519BootstrapPackage`
    - Keep as the Option B dual-key enrollment method.
    - Change result shape to return both `operationalPublicKey` and `recoveryPublicKey`.
    - Remove `relayerExportShareB64u` from the client/server registration contract.

- `client/src/core/signingEngine/workerManager/nearKeyOps/index.ts`
  - `createNearKeyOps()`
    - Keep the `deriveThresholdEd25519BootstrapPackageWasm()` call aligned with the frozen Option B worker message names.
    - Update success/error mapping for the renamed dual-key fields.

- `client/src/core/signingEngine/threshold/workflows/keygenEd25519.ts`
  - `DUAL_KEY_ED25519_KEY_VERSION_V1`
    - Rename to an Option B lifecycle version constant.
  - `keygenEd25519()`
    - Replace the current one-key enrollment request with a dual-key request.
    - Send both `operationalPublicKey` and `recoveryPublicKey` to the relay.
    - Stop requiring `relayerExportShareB64u`.
    - Stop treating the returned `publicKey` as both signing identity and export identity.

- `client/src/core/signingEngine/threshold/workflows/enrollEd25519Key.ts`
  - `DeriveThresholdBootstrapPackageResult`
    - Replace with an Option B dual-key enrollment result type.
  - `EnrollThresholdEd25519KeyHandlerContext.signingKeyOps.deriveThresholdEd25519BootstrapPackage`
    - Keep as the Option B dual-key method.
  - `enrollEd25519KeyHandler()`
    - Update request body, response mapping, and validation to use:
      - `operationalPublicKey`
      - `recoveryPublicKey`
      - `recoveryExportCapable`
    - Remove `relayerExportShareB64u` handling.

- `client/src/core/TatchiPasskey/faucets/createAccountRelayServer.ts`
  - `CreateAccountAndRegisterUserRequest.threshold_ed25519`
    - Rename `public_key` to `operational_public_key`
    - add `recovery_public_key`
    - remove `relayer_export_share_b64u`
    - rename `seed_export_capable` to `recovery_export_capable`
  - `createAccountAndRegisterWithRelayServer()`
    - Populate the dual-key bootstrap payload.
    - Ensure request hashing includes `recovery_public_key`.

- `client/src/core/TatchiPasskey/registration.ts`
  - `registerPasskeyInternal()`
    - Update registration orchestration so it derives both keys in one session.
    - Persist both public keys into client state/metadata.
  - `verifyAccountAccessKeysPresent()`
    - Change verification from “threshold key exists” to “both `pk_a` and `pk_d` exist”.

- `client/src/core/TatchiPasskey/thresholdWarmSessionBootstrap.ts`
  - `createThresholdWarmSessionPolicyDraft()`
  - `buildThresholdWarmSessionBootstrapPayload()`
  - `hydrateThresholdWarmSessionFromRelay()`
    - Keep these bound strictly to the operational threshold key `pk_a`.
    - Remove any assumption that the warmed threshold session and exported seed share one public key.

- `client/src/core/indexedDB/passkeyNearKeysDB.types.ts`
  - `ThresholdEd25519ArtifactKind`
    - Rename if needed to make clear it is the recovery export artifact kind, not the operational key kind.
  - `ThresholdEd25519_2p_V1Material`
    - Add:
      - `recoveryPublicKey`
      - `recoveryExportCapable`
      - recovery derivation version or label metadata
    - Rename `seedExportCapable` to `recoveryExportCapable`.

- `client/src/core/indexedDB/near/keyMaterial.ts`
  - `StoreNearThresholdKeyMaterialInput`
    - Add `recoveryPublicKey`
    - rename `seedExportCapable` to `recoveryExportCapable`
    - remove `clientExportShareDerivation` if Option B export becomes fully root-derived and stateless
  - `mapThresholdNearKey()`
    - Read dual-key metadata from payload.
  - `getNearThresholdKeyMaterial()`
    - Return a dual-key material record.
  - `storeNearKeyMaterial()`
    - Persist the recovery public key and Option B capability flags.

### Client: export and recovery flow

- `client/src/core/signingEngine/api/recovery/privateKeyExportRecovery.ts`
  - Remove:
    - `EXPORT_WORKER_BOUNDARY_DISABLED_CODE`
    - `createExportHardeningError()`
    - `throwExportWorkerBoundaryBlocked()`
  - `runExportWorkerOperation()`
    - Wire the real Option B export flow instead of hard-failing.
    - Require recovery export to use stored `recoveryPublicKey`, not the operational threshold public key.
  - `exportKeypairWithUIWorkerDriven()`
  - `exportKeypairWithUI()`
    - Return recovery-export results after worker verification of reconstructed `d`.

- `client/src/core/rpcClients/near/rpcCalls.ts`
  - `thresholdEd25519Keygen()`
    - Change payload and response parsing to Option B field names.
  - `thresholdEd25519ExportInit()`
    - Stop keying recovery export by operational `relayerKeyId` alone.
    - Bind export init by `nearAccountId`, `keyVersion`, and recovery-key metadata.
  - `thresholdEd25519ExportCombine()`
    - Add Paillier public-key transport if needed.
    - Keep request/response scoped to recovery export only.

- `client/src/core/types/secure-confirm-worker.ts`
  - `ThresholdEd25519ExportArtifactKind`
    - Rename if needed for recovery specificity.
  - `ExportPrivateKeysWithUiWorkerPayload`
    - Add `recoveryPublicKey`
    - rename `seedExportCapable` to `recoveryExportCapable`
  - `UserConfirmWorkerMessageType`
    - Add any Option B-specific export worker message names if the current generic export message becomes too ambiguous.

- `client/src/core/types/signer-worker.ts`
  - Update worker DTOs for dual-key enrollment and Option B export finalization.

- `client/src/core/types/rpc.ts`
  - Add or rename the Threshold Ed25519 RPC DTOs so they no longer imply one public key serves both threshold signing and recovery export.

- `client/src/core/types/sdkSentEvents.ts`
  - `RegistrationEventStep7ThresholdKeyEnrollment`
  - `RegistrationEventStep7ThresholdKeyEnrollmentProgress`
    - Update status text so enrollment explicitly mentions provisioning both operational and recovery keys.

- `client/src/core/TatchiPasskey/near/emailRecovery.ts`
  - `EmailRecoveryDomain`
    - Update exported-key recovery to use `pk_d` semantics.
    - Ensure post-recovery rotation removes/replaces `pk_a` and optionally rotates `pk_d`.

- `client/src/core/TatchiPasskey/syncAccount.ts`
  - `syncAccount()`
    - Update sync logic to detect, classify, and persist both operational and recovery access keys.

### Server: DTOs, bootstrap, and threshold service

- `server/src/core/types.ts`
  - `CreateAccountAndRegisterRequest.threshold_ed25519`
    - rename `public_key` to `operational_public_key`
    - add `recovery_public_key`
    - remove `relayer_export_share_b64u`
    - rename `seed_export_capable` to `recovery_export_capable`
  - `CreateAccountAndRegisterResult.thresholdEd25519`
    - rename `publicKey` to `operationalPublicKey`
    - add `recoveryPublicKey`
    - rename `seedExportCapable` to `recoveryExportCapable`
  - `ThresholdEd25519KeygenWithWebAuthnRequest`
    - rename `publicKey` to `operationalPublicKey`
    - add `recoveryPublicKey`
    - remove `relayerExportShareB64u`
    - rename `seedExportCapable` to `recoveryExportCapable`
  - `ThresholdEd25519KeygenResponse`
    - rename `publicKey` to `operationalPublicKey`
    - add `recoveryPublicKey`
    - rename `seedExportCapable` to `recoveryExportCapable`
  - `ThresholdEd25519ExportInitRequest`
    - replace `relayerKeyId`-only identity with a recovery-export binding that includes `nearAccountId` and `keyVersion`.
  - `ThresholdEd25519ExportInitResponse`
    - replace `publicKey` with `recoveryPublicKey`.
  - `ThresholdEd25519ExportCombineRequest`
    - remove dependence on operational `relayerKeyId` if possible.
    - add Paillier public-key material if needed by the chosen wire format.
  - `ThresholdEd25519ExportCombineResponse`
    - replace `publicKey` with `recoveryPublicKey`
    - rename `seedExportCapable` to `recoveryExportCapable`

- `server/src/core/AuthService.ts`
  - `parseThresholdEd25519BootstrapInput()`
    - Parse `operational_public_key` and `recovery_public_key`.
    - Remove `relayerExportShareB64u`.
  - `toThresholdEd25519BootstrapSession()`
    - Keep session output operational-only.
  - `createAccountAndRegisterUser()`
    - Create the NEAR account with both `AddKey(pk_a)` and `AddKey(pk_d)`.
    - Persist/bind both public keys under the same account version.
    - Remove bootstrap assumptions that a relayer export share record must be stored for Ed25519 recovery export.

- `server/src/core/ThresholdService/schemes/types.ts`
  - `ThresholdEd25519RegistrationKeygenRequest`
    - rename `publicKey` to `operationalPublicKey`
    - add `recoveryPublicKey`
    - remove `relayerExportShareB64u`
    - rename `seedExportCapable` to `recoveryExportCapable`
  - `ThresholdEd25519RegistrationKeygenResult`
    - rename `publicKey` to `operationalPublicKey`
    - add `recoveryPublicKey`
    - rename `seedExportCapable` to `recoveryExportCapable`
  - `ThresholdEd25519Frost2pSchemeModule.registration.keygenFromSeedBackedPackage`
    - Rename to an Option B registration method.

- `server/src/core/ThresholdService/ThresholdSigningService.ts`
  - `ParsedThresholdEd25519KeygenRequest`
    - Change to dual-key fields and remove `relayerExportShareB64u`.
  - `parseThresholdEd25519KeygenRequest()`
    - Parse Option B keygen/bootstrap payloads.
  - `createThresholdEd25519ExportSessionId()`
    - Keep if export sessions remain, but bind them to recovery export identity instead of operational relayer key identity.
  - `ed25519Keygen()`
    - Stop assuming one bootstrap package produces the signing public key and recovery identity together.
    - Persist operational threshold material plus recovery metadata separately.
  - `ed25519ExportInit()`
    - Rebind export to recovery-key metadata and deterministic `y_server` derivation.
  - `ed25519ExportCombine()`
    - Implement Paillier combine over recovery share `y_server`.
    - Remove dependence on stored `relayerExportShareB64u`.

- `server/src/core/ThresholdService/signingHandlers.ts`
  - `thresholdEd25519SignInit()`
  - `thresholdEd25519SignFinalize()`
  - `thresholdEd25519CosignInit()`
  - `thresholdEd25519CosignFinalize()`
    - Ensure these remain strictly operational-key handlers for `pk_a`.
    - Remove any assumptions that exported seed state and threshold signing state share the same public key identity.

- `server/src/core/ThresholdService/relayerKeyMaterial.ts`
  - `resolveThresholdEd25519RelayerKeyMaterial()`
    - Change lookup assumptions so operational threshold key material and recovery export state are not conflated.
    - Remove any assumption that recovery export depends on persisted one-package recovery share state.

- `server/src/core/ThresholdService/createThresholdSigningService.ts`
  - `createThresholdSigningService()`
    - Wire any new Paillier export module/runtime and adjust threshold Ed25519 service initialization accordingly.

- `server/src/core/config.ts`
  - `normalizeThresholdEd25519KeyStoreConfig()`
    - Update config assumptions if recovery export no longer depends on persisted per-account export shares.

### Server: routers and route contracts

- `server/src/router/routeDefinitions.ts`
  - `createRelayRouteDefinitions()`
    - Update summaries and schemas for Threshold Ed25519 keygen/export routes to the Option B contract.

- `server/src/router/express/routes/thresholdEd25519.ts`
  - `registerThresholdEd25519Routes()`
    - Update request parsing and route handling for the dual-key keygen/export payloads.

- `server/src/router/cloudflare/routes/thresholdEd25519.ts`
  - `handleThresholdEd25519()`
    - Mirror the same Option B request/response changes.

- `server/src/router/relayRegistrationBootstrap.ts`
  - `handleRegistrationBootstrap()`
    - Return the expanded dual-key bootstrap response.
    - Keep threshold session JWT binding tied to `pk_a`, not `pk_d`.

- `server/src/router/express/routes/emailRecovery.ts`
  - `registerEmailRecoveryRoutes()`
    - Update recovery-route wiring if exported `d` becomes the main NEAR recovery path.

- `server/src/router/cloudflare/routes/emailRecovery.ts`
  - `handleEmailRecoveryPrepare()`
    - Mirror the same Option B recovery changes.

- `server/src/router/express/routes/syncAccount.ts`
  - `registerSyncAccountRoutes()`
    - Update sync response shape if both NEAR keys are surfaced.

- `server/src/router/cloudflare/routes/syncAccount.ts`
  - `handleSyncAccount()`
    - Mirror the same sync response changes.

### Rust and WASM: exact structs and functions

- `wasm/near_signer/src/handlers/handle_threshold_ed25519_derive_bootstrap_package.rs`
  - `DeriveThresholdEd25519BootstrapPackageRequest`
    - Keep the current Option B dual-key enrollment request aligned with the frozen recovery-share preflight inputs.
  - `DeriveThresholdEd25519BootstrapPackageResult`
    - Replace `public_key` with:
      - `operational_public_key`
      - `recovery_public_key`
    - remove `relayer_export_share_b64u`
    - rename `seed_export_capable` to `recovery_export_capable`
  - `handle_threshold_ed25519_derive_bootstrap_package()`
    - Keep as the Option B dual-key enrollment handler and add any recovery-export worker hooks here or alongside it.

- `wasm/near_signer/src/types/worker_messages.rs`
  - `WorkerRequestType::DeriveThresholdEd25519BootstrapPackage`
    - Keep as the Option B dual-key enrollment request enum value.
  - `WorkerResponseType::DeriveThresholdEd25519BootstrapPackageSuccess`
  - `WorkerResponseType::DeriveThresholdEd25519BootstrapPackageFailure`
    - Keep the current Option B response names aligned with the worker runtime surface.
  - `worker_request_type_name()`
  - `worker_response_type_name()`
    - Update string names for the renamed Option B messages.

- `crates/signer-core/src/near_ed25519_recovery.rs`
  - `BootstrapThresholdShareBundleV1`
    - Split or replace with separate operational/recovery structs.
  - `DualKeyEd25519BootstrapPackageV1`
    - Replace with an Option B dual-key registration package.
  - `prepare_dual_key_ed25519_bootstrap_package_v1()`
    - Rewrite to prepare:
      - operational threshold registration data
      - recovery public key metadata
  - `validate_seed_backed_ed25519_registration_package_v1()`
    - Rewrite validation around Option B dual-key invariants.
  - `derive_seed_backed_client_export_share_v1()`
  - `derive_seed_backed_relayer_export_share_2p_v1()`
  - `combine_seed_backed_export_shares_2p_v1()`
    - Replace with recovery-domain naming and semantics if these helpers remain.
  - `encode_near_ed25519_private_key_from_seed()`
    - Keep, but scope it clearly to recovery-key export.

- `crates/signer-core/src/near_threshold_frost.rs`
  - `ThresholdEd25519KeygenOutput`
    - Keep operational-only semantics for the threshold key.
  - `threshold_ed25519_keygen_from_client_verifying_share()`
  - `threshold_ed25519_keygen_from_master_secret_and_client_verifying_share()`
    - Ensure these are only used for the operational key lifecycle.
    - Remove any comments or downstream assumptions that tie them to seed export.

- `crates/signer-core/src/near_threshold_ed25519.rs`
  - `derive_client_key_package_from_wrap_key_seed_b64u()`
    - Confirm this remains operational-only or split it if it still conflates export and signing material.
  - `client_round1_commit()`
  - `build_signing_package()`
  - `client_round2_signature_share()`
  - `aggregate_signature()`
    - No recovery-key semantics should leak into these functions.

- `wasm/near_signer/src/threshold/threshold_frost.rs`
  - `threshold_ed25519_keygen_from_seed_backed_package()`
    - Rename or replace with an Option B operational-key keygen entry point.
    - Remove the one-package assumption.

### Tests: exact first wave

- `tests/e2e/thresholdEd25519.testUtils.ts`
  - Update registration/bootstrap helpers to expect both `pk_a` and `pk_d`.
- `tests/e2e/thresholdEd25519.onchainScope.test.ts`
  - Update on-chain key assertions for dual-key bootstrap.
- `tests/e2e/thresholdEd25519.keygenIntegrity.test.ts`
  - Extend integrity assertions to cover both public keys and the removal of `relayerExportShareB64u`.
- `tests/relayer/threshold-ed25519.access-key-scope-retry.test.ts`
  - Update access-key polling expectations to handle two NEAR keys on the account.
- New tests
  - Add one recovery export happy-path test.
  - Add one recovery public-key mismatch fail-closed test.
  - Add one bootstrap “both AddKey actions present” test.
