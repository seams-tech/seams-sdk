# P-256 Agent Keys And AP2 Mandate Signing

Date created: June 25, 2026

Rewritten: July 22, 2026

Status: draft cryptographic and protocol plan. P-256 threshold key generation,
signing, JOSE encoding, AP2 wire adapters, and credential-release integration
are unimplemented.

## Goal

Give an agent an independent P-256/ES256 identity key that can sign AP2 closed
Checkout and Payment Mandates after a user-signed open mandate authorizes that
exact agent public key and scope.

```text
User authorization key
  -> signs open Checkout and Payment Mandates
       -> binds independent Agent P-256 public key and constraints

Agent P-256 key
  -> signs concrete closed Checkout and Payment Mandates
       -> Seams policy participant co-signs only after deterministic checks

Credential Provider
  -> verifies open + closed mandate chain
       -> releases one scoped payment credential
```

The agent key is separate from the user's wallet, passkey, authorization, and
payment keys. The AP2 signature proves agent authorship. It does not itself
become the user's blockchain wallet signature.

## Protocol Basis

AP2 v0.2 defines autonomous operation as:

- a user-signed open mandate containing the agent public key as a `cnf` claim;
- an agent-signed closed mandate for the concrete checkout or payment;
- verification that the closed mandate satisfies every disclosed open-mandate
  constraint;
- credential release only after successful mandate verification.

References:

- AP2 specification: https://ap2-protocol.org/ap2/specification/
- Agent Authorization Framework: https://ap2-protocol.org/ap2/agent_authorization/
- Checkout Mandate: https://ap2-protocol.org/ap2/checkout_mandate/
- Payment Mandate: https://ap2-protocol.org/ap2/payment_mandate/
- AP2 flows: https://ap2-protocol.org/ap2/flows/

The implementation pins an exact AP2 schema and `vct` version. Raw claims from
a future version fail until a new parser and verification branch exist.

## Dependencies And Authority

This plan consumes:

- [refactor-99-agent-id-spending.md](./refactor-99-agent-id-spending.md) for
  agent identity, custody, owner authorization, typed spending policy, budget,
  replay, revocation, and audit;
- [refactor-90-modular-auth-capabilities-plan.md](./refactor-90-modular-auth-capabilities-plan.md)
  for authorization resources, exact operation claims, server participation,
  quotas, effect ordering, and recovery;
- upstream or composed MPC primitives selected during the Phase 0 spike for
  P-256 threshold ECDSA;
- standard RustCrypto and JOSE implementations for independent output
  verification.

This plan owns:

- P-256 agent-key public identity and threshold participant material;
- AP2 ES256 signing sessions for agent-authored closed mandates;
- P-256 JWK, signature, and JOSE encoding;
- AP2 open/closed mandate parsing and signature-chain verification;
- Credential Provider handoff after deterministic verification.

It does not own the user's wallet signing key, direct blockchain payment
execution, merchant checkout signature, or payment-network credential format.

## Required Invariants

1. User and agent keys are independent. No user secret or wallet share is
   delivered to the agent P-256 key ceremony.
2. Every autonomous AP2 flow presents a verified user-signed open mandate that
   binds the exact agent P-256 public key.
3. Every closed Checkout and Payment Mandate is signed under that agent key.
4. A threshold deployment splits the agent key between the agent custody
   runtime and a Seams policy participant. Neither participant signs alone.
5. The Seams participant contributes only after exact open-mandate,
   closed-mandate, checkout, budget, expiry, replay, and revocation admission.
6. AP2 mandate signing and payment execution remain separate operations with
   separate keys, claims, receipts, and failure states.
7. The signature verifies as ordinary JOSE ES256 using the agent public JWK.
8. Hashing occurs exactly once according to the selected JOSE signing input.
9. Raw SD-JWT, disclosure, checkout JWT, and credential-provider payloads are
   parsed once at their boundaries.
10. Revocation rejects signing and credential release before presignature or
    payment work.
11. Existing ambiguous `delegated share` language is deleted. Every share is
    identified as agent-key material or wallet-execution material.

## Key Roles

Keep cryptographic roles explicit:

```ts
type Ap2KeyRole =
  | 'user_open_mandate_authorization'
  | 'agent_closed_mandate_authorship'
  | 'merchant_checkout_issuer'
  | 'credential_provider_issuer'
  | 'wallet_payment_execution';
```

This plan implements only `agent_closed_mandate_authorship`. Other roles enter
as verified external evidence or through their owning adapters.

## Agent P-256 Key

```ts
type AgentP256KeyRecord = {
  kind: 'agent_p256_key_v1';
  agentId: AgentId;
  agentIdentityKeyId: AgentIdentityKeyId;
  algorithm: 'p256_ecdsa_es256';
  publicJwk: P256PublicJwk;
  signingBinding: AgentP256SigningBinding;
  keyEpoch: AgentP256KeyEpoch;
  lifecycle: AgentP256KeyLifecycle;
};

type AgentP256SigningBinding =
  | {
      kind: 'agent_p256_2_of_2_v1';
      agentCustodyBindingId: AgentCustodyBindingId;
      agentParticipantId: AgentP256ParticipantId;
      policyParticipantId: AgentP256ParticipantId;
      bindingDigestB64u: string;
      hsmAttestation?: never;
    }
  | {
      kind: 'agent_p256_hsm_v1';
      agentCustodyBindingId: AgentCustodyBindingId;
      hsmAttestation: AgentP256HsmAttestation;
      bindingDigestB64u: string;
      agentParticipantId?: never;
      policyParticipantId?: never;
    };
```

The initial threshold profile is 2-of-2. The HSM branch is a separate
single-signer deployment profile. A future 2-of-3 profile requires a new
signing-binding branch, availability model, DKG/resharing proof, and failure
policy.

Agent key rotation creates a new key record and invalidates its use for new
authorizations. Existing open mandates remain bound to the prior key and are
revoked or allowed to expire under their explicit lifecycle.

## P-256 And JOSE Encoding

Use these external encodings:

- curve: NIST P-256 / secp256r1;
- signature algorithm: ECDSA with SHA-256 (`ES256`);
- public key: JOSE EC JWK with `kty: "EC"`, `crv: "P-256"`, and exact
  32-byte base64url `x` and `y` coordinates;
- JOSE signature: 64 raw bytes `R || S`, with each scalar left-padded to
  32 bytes;
- compact and SD-JWT signing input: exact ASCII protected-header and payload
  encodings required by the selected JOSE library and AP2 version.

Internal threshold output may use a scalar tuple or DER. One boundary encoder
converts it to raw JOSE bytes. DER never crosses the AP2 wire boundary.

The low-S policy must be frozen before implementation. Verification accepts
only the chosen canonical form so independent libraries and test vectors agree.

## Threshold Scheme Boundary

The implementation should compose with audited upstream MPC components where
their public traits and security model fit. Phase 0 resolves whether P-256 is:

- a new scheme/domain in the selected MPC stack;
- a Seams-owned protocol package using shared curve-independent transport and
  DKG components;
- an HSM-backed agent key profile used before threshold software is ready.

No private upstream fork becomes the implicit source of truth. Any required
upstream changes are isolated, reviewed, and tested against standard P-256
verification.

The protocol boundary exposes only typed operations:

```ts
type AgentP256Operation =
  | AgentP256KeyCreationOperation
  | AgentP256ClosedMandateSigningOperation
  | AgentP256KeyRefreshOperation
  | AgentP256KeyRevocationOperation;
```

It does not accept arbitrary hashes from the agent runtime. Signing accepts a
verified canonical closed-mandate signing input and its Refactor 99 admission.

## Key Creation

1. Register the independent agent identity and custody binding through
   Refactor 99.
2. Create a P-256 key operation with exact agent and policy participants.
3. Run admitted DKG or import an HSM-generated public identity through its
   explicit branch.
4. Verify public point validity and participant commitments.
5. Encode and independently verify the public JWK.
6. Return agent and policy custody receipts bound to key epoch and transcript.
7. Activate the key only after all receipts and attestation requirements pass.
8. Publish no owner authorization automatically. The user separately approves
   an open mandate for this public key.

## User-Signed Open Mandates

The Trusted Surface:

1. receives proposed open Checkout and Payment Mandate content;
2. parses the pinned AP2 schemas and constraint disclosures;
3. displays agent key fingerprint, merchants, items or categories, amount,
   recurrence, expiry, and payment instrument scope;
4. requires fresh user verification;
5. obtains the user signature through the configured authorization-key
   adapter;
6. verifies the completed open mandates independently;
7. records their hashes and normalized constraints in a Refactor 99
   authorization;
8. activates no payment credential during open-mandate creation.

The open mandate must bind the exact `AgentP256KeyRecord.publicJwk` in `cnf`.
Key mismatch, missing key confirmation, unsupported constraint, or incomplete
selective disclosure fails closed.

## Agent-Signed Closed Mandates

After the agent obtains a merchant-signed checkout:

1. Parse and verify the merchant checkout JWT.
2. Construct closed Checkout and Payment Mandate content.
3. Bind the exact checkout hash, amount, merchant, instrument reference,
   transaction identity, issue time, expiry, and request nonce.
4. Create a Refactor 99 agent-signed spend request over the normalized intent
   and mandate signing-input digests.
5. Verify the user-signed open mandates and their constraints.
6. Atomically reserve delegated budget and replay identity.
7. Create an `AgentP256ClosedMandateSigningOperation` for the exact JOSE signing
   input.
8. Agent custody and Seams policy participants produce the ES256 signature.
9. Independently verify the output using RustCrypto and a separate JOSE path.
10. Attach the signature to the closed mandate and persist the complete proof
    chain.

Checkout and Payment Mandates are distinct signed objects and operations. One
signature, nonce, budget claim, or idempotency key cannot satisfy both.

## Credential Provider Verification And Release

Before releasing a payment credential, the Credential Provider verifies:

- pinned AP2 `vct` and schema branches;
- user signatures on open mandates;
- open-mandate `cnf` binding to the exact agent public JWK;
- agent signatures on closed mandates;
- selective-disclosure integrity;
- merchant checkout signature and checkout hash;
- every disclosed constraint against the closed content;
- amount, merchant, recurrence, payment instrument, expiry, and nonce;
- Refactor 99 authorization lifecycle, revocation epoch, replay, and budget;
- absence of a prior successful or unresolved execution for the same claim.

Success releases one scoped, short-lived credential for the exact checkout.
The credential layer records release identity and expiry. It cannot widen the
authorization or release a reusable unrestricted payment credential.

If the payment rail pushes funds from a Seams wallet, Refactor 99 separately
admits and executes the wallet transaction. The AP2 agent signature remains
authorship evidence and never substitutes for the wallet signature.

## Signing Operation State

```ts
type AgentP256SigningLifecycle =
  | {
      state: 'prepared';
      operationId: AgentP256OperationId;
      signingInputDigestB64u: string;
    }
  | {
      state: 'presign_claimed';
      operationId: AgentP256OperationId;
      presignatureId: AgentP256PresignatureId;
    }
  | {
      state: 'signing';
      operationId: AgentP256OperationId;
      transcriptDigestB64u: string;
    }
  | {
      state: 'completed';
      operationId: AgentP256OperationId;
      signatureDigestB64u: string;
      completedAtMs: number;
    }
  | {
      state: 'failed_before_effect';
      operationId: AgentP256OperationId;
      failureCode: AgentP256PreEffectFailureCode;
    }
  | {
      state: 'outcome_unknown';
      operationId: AgentP256OperationId;
      reconciliationReference: string;
    };
```

Presignatures are one-use. A claimed presignature is never returned to the pool
after ambiguous participation. Budget follows Refactor 99 outcome-unknown
semantics.

## Revocation And Recovery

Agent authorization revocation and P-256 key revocation are separate:

- revoking one open authorization blocks only its scope;
- revoking an agent P-256 key blocks every active authorization naming it;
- suspending custody blocks threshold participation without rewriting signed
  mandate bytes;
- key rotation creates a new P-256 key and requires new user-signed open
  mandates;
- active signing sessions are fenced by key and authorization revocation
  epochs;
- ambiguous completed signatures are reconciled before budget release.

No recovery path changes the agent public key silently. Custody recovery that
preserves the key requires a reviewed threshold resharing protocol and a new
key epoch. Otherwise create a new key and obtain fresh authorization.

## API Surface

```text
createAgentP256Key()
getAgentP256Key()
refreshAgentP256Key()
revokeAgentP256Key()
createAp2OpenMandates()
signAp2ClosedCheckoutMandate()
signAp2ClosedPaymentMandate()
verifyAp2MandateChain()
releaseAp2PaymentCredential()
```

Raw scalar shares, presignatures, arbitrary hashes, unsigned owner approvals,
and caller-asserted policy decisions are absent from public APIs.

## Implementation Phases

### Phase 0: Standards And Cryptographic Spike

- [ ] Pin the AP2 version, exact `vct` values, schemas, disclosures, and
      verification algorithms.
- [ ] Inventory candidate P-256 threshold implementations and upstream MPC
      extension points.
- [ ] Freeze 2-of-2 protocol, DKG, presignature, low-S, and recovery choices.
- [ ] Produce ordinary single-key ES256 reference vectors first.
- [ ] Decide whether an HSM-backed agent-key branch ships before threshold
      P-256.

### Phase 1: P-256 Domain And Encoding

- [ ] Add P-256 scalar, point, key, participant, epoch, and operation types.
- [ ] Implement strict JWK and raw `R || S` encoding.
- [ ] Add JOSE signing-input construction with exactly-once hashing.
- [ ] Verify every vector with RustCrypto and an independent JOSE library.

### Phase 2: Agent Key Lifecycle

- [ ] Implement admitted 2-of-2 DKG and activation receipts.
- [ ] Seal agent and policy shares to their exact custody boundaries.
- [ ] Implement key suspension, revocation, and rotation.
- [ ] Add transcript, participant-substitution, and corrupted-share tests.

### Phase 3: AP2 Open Mandates

- [ ] Implement pinned open Checkout and Payment Mandate parsers.
- [ ] Add Trusted Surface approval and user-signature adapters.
- [ ] Verify `cnf` binding to the agent P-256 key.
- [ ] Normalize verified constraints into Refactor 99 authorization claims.

### Phase 4: AP2 Closed Mandates

- [ ] Implement closed Checkout and Payment Mandate builders separately.
- [ ] Bind merchant checkout JWT and checkout hash.
- [ ] Require agent-signed Refactor 99 spend requests.
- [ ] Add policy-gated threshold ES256 signing.

### Phase 5: Credential Release

- [ ] Verify complete open/closed mandate chains.
- [ ] Atomically coordinate budget, replay, signing, and credential release.
- [ ] Issue exact-checkout credentials and durable receipts.
- [ ] Reconcile ambiguous signing and payment outcomes.

### Phase 6: Production Security

- [ ] Audit nonce generation, presignature isolation, scalar handling, and
      constant-time behavior.
- [ ] Add dependency pinning, transcript limits, abuse controls, and HSM/TEE
      deployment profiles.
- [ ] Complete an independent cryptographic and AP2 protocol review.

## Validation

Static fixtures prove:

- user and agent key records cannot share role branches;
- agent P-256 operations cannot carry wallet-execution material;
- open and closed mandates cannot share result types;
- Checkout and Payment signing operations cannot be interchanged;
- raw hashes and unverified mandates cannot construct prepared signing state.

Cryptographic tests prove:

- 2-of-2 key generation and signing;
- standard P-256 JWK verification;
- exact raw ES256 `R || S` encoding;
- wrong hash, double hash, wrong curve, high-S policy, malformed point, and
  corrupted-share rejection;
- one-use presignature and participant-binding enforcement;
- independent vectors reproduce the same signatures or verify the same
  protocol outputs as applicable.

AP2 tests prove:

- open mandates require user signatures and exact agent `cnf` binding;
- closed mandates require the authorized agent signature;
- wrong agent key, checkout hash, merchant, amount, recurrence, instrument,
  nonce, disclosure, expiry, or `vct` fails;
- a valid closed mandate outside open constraints fails;
- revocation blocks signing and credential release;
- mandate and receipt evidence reconstructs a dispute chain.

Concurrency tests prove:

- duplicate closed-mandate requests claim one operation;
- concurrent purchases cannot exceed authorization budget;
- signing timeout after possible participation retains budget and
  presignature claims;
- key or authorization revocation fences queued and in-flight operations.

## Non-Goals

- giving the agent a user wallet share as its identity key;
- using the agent P-256 signature as a blockchain wallet signature;
- transferring funds into an agent account;
- accepting arbitrary SD-JWT or future AP2 schemas without pinned parsers;
- issuing unrestricted reusable payment credentials;
- using one threshold key for user, agent, merchant, and Credential Provider
  roles;
- claiming upstream MPC compatibility before the Phase 0 spike verifies it.

## Decisions Required Before Implementation

- Freeze the AP2 version and supported autonomous constraint subset.
- Select the P-256 threshold implementation and participant deployment.
- Freeze low-S, deterministic encoding, and JOSE library behavior.
- Select user-signature adapters for open mandates.
- Select the initial payment credential and wallet-execution adapter.
- Define retention, selective disclosure, and dispute-evidence privacy policy.
