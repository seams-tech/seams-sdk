# Refactor 90: P-256 Threshold Signatures For AP2

Status: draft plan

Last updated: June 25, 2026

## Goal

Add AP2-compatible P-256 threshold ECDSA signing to the NEAR MPC stack so Seams
agents can create standard ES256 mandates for merchant-controlled SaaS actions.

The target product flow is:

- merchant grants constrained authority to an agent;
- agent can initiate a threshold signing session;
- Seams policy engine contributes the backend MPC share only after policy checks;
- the output is a normal P-256 / ES256 signature that AP2 verifiers can validate;
- Seams credential layer verifies the signed mandate and releases a scoped JWT,
  virtual card authorization, wallet authorization, or payment-token release.

This preserves the dual-control property:

```text
Agent alone cannot complete a purchase.
Seams backend alone cannot complete a purchase.
Credential layer can release spend capability only after mandate verification.
```

## Why P-256 Is Needed

Google AP2 uses Checkout Mandates and Payment Mandates as signed authorization
objects for agentic commerce. The AP2 examples use JOSE `ES256`, which is ECDSA
over NIST P-256 with SHA-256, and AP2 examples bind delegated agent authority
with `cnf.jwk.crv: "P-256"`.

Implication for Seams:

- AP2 verifiers expect a standard P-256 public key and standard ES256 signature;
- the signature must verify with normal JOSE / SD-JWT tooling;
- threshold signing is an internal authority-control mechanism;
- the final signature must look like a normal P-256 ECDSA signature.

Relevant AP2 objects:

- Checkout Mandate: authorizes completion of a specific checkout.
- Payment Mandate: authorizes payment for the checkout.
- Open Mandates: user-approved constraints for autonomous agent use.
- Closed Mandates: exact checkout/payment authorization produced after the agent
  finds the concrete purchase.

References:

- AP2 specification: https://ap2-protocol.org/ap2/specification/
- AP2 checkout mandate: https://ap2-protocol.org/ap2/checkout_mandate/
- AP2 payment mandate: https://ap2-protocol.org/ap2/payment_mandate/
- AP2 flows: https://ap2-protocol.org/ap2/flows/

## What Seams Uses AP2 For

Initial use case:

```text
Merchant agents buying, managing, downgrading, and canceling SaaS services.
```

Examples:

- buy or upgrade a Shopify subscription;
- buy an analytics, helpdesk, ad, translation, returns, or logistics SaaS tool;
- cancel unused SaaS subscriptions;
- downgrade a plan that exceeds policy;
- renew a domain or operational tool;
- authorize one-time setup fees within a merchant-approved budget.

AP2 is valuable here because SaaS purchases are authority-sensitive:

- recurring charges;
- add-ons and plan upgrades;
- employee or agent access to merchant tools;
- cancellation and refund evidence;
- budget controls;
- dispute records.

The AP2 mandate gives Seams a signed, replay-resistant authority record. The
credential layer turns that record into a short-lived spend capability.

## Current NEAR MPC Context

Based on the public `near/mpc` documentation:

- `near/mpc` is the NEAR MPC node for chain signatures.
- It supports multiple threshold-signature schemes organized into domains.
- Domains have their own IDs, schemes, and purposes.
- Schemes share curve-independent DKG.
- Signing workflows are scheme-specific.
- Supported schemes include threshold ECDSA over Secp256k1, threshold EdDSA over
  Ed25519, and confidential key derivation over BLS12-381.
- The older `near/threshold-signatures` repository is archived; development has
  moved into `near/mpc` under `crates/threshold-signatures`.

References:

- NEAR MPC: https://github.com/near/mpc
- Historical threshold signatures repo: https://github.com/near/threshold-signatures

This architecture suggests P-256 should be added as a new scheme or domain if
the relevant traits and crate boundaries are accessible.

## Preferred Architecture

Prefer composition around upstream `near/mpc`.

Target shape:

```text
seams-ap2-p256
  -> depends on upstream near/mpc crates where possible
  -> adds AP2-specific P-256 scheme/domain glue
  -> exposes Seams AP2 signing envelopes
  -> verifies output with standard JOSE P-256 tooling
```

Preferred dependency structure:

```text
near/mpc upstream
  crates/threshold-signatures
  crates/mpc-node
  protocol/runtime/network code

seams-ap2-p256
  P-256 curve suite adapter
  AP2 mandate signing envelope parser
  AP2-specific signing policy checks
  JOSE/SD-JWT output encoding
  Seams credential release integration
```

Reason:

- upstream updates remain easy to consume;
- Seams-specific AP2 policy stays outside upstream cryptography code;
- P-256 support can be proposed upstream as a general threshold ECDSA feature;
- Seams avoids carrying a large permanent fork.

## Fallback Architecture

If `near/mpc` does not expose enough public extension points, create a small fork
with the P-256 changes isolated to the threshold-signature and domain registry
boundary.

Fork rules:

- keep upstream `near/mpc` as `upstream`;
- keep the Seams fork branch small and rebased frequently;
- isolate P-256 code under a new module or crate;
- avoid modifying existing Secp256k1 or Ed25519 behavior;
- upstream general extension points as PRs;
- keep AP2 business policy outside the fork.

Fallback structure:

```text
near-mpc-seams fork
  crates/threshold-signatures/src/ecdsa/p256
  crates/threshold-signatures/src/ecdsa/curve_suite.rs
  crates/mpc-node domain registration for p256_ap2

seams-ap2-p256
  AP2 envelopes
  policy checks
  credential authorization
  tests against the forked domain
```

Decision rule:

```text
Use composition if P-256 can be implemented through public crates or upstreamable
extension points.

Use a fork only when private APIs or binary-level domain registration block a
composed implementation.
```

## Technical Design

### P-256 Domain

Add a new signing domain for AP2:

```text
domain_id: p256_ap2
scheme: threshold_ecdsa_p256
purpose: AP2 mandate signing
curve: NIST P-256
signature: ECDSA
encoding: JOSE ES256 raw R || S
hash: SHA-256 over the JOSE signing input
```

Domain constraints:

- sign only typed AP2 mandate payloads;
- reject arbitrary byte signing at the Seams API boundary;
- require an open mandate reference for autonomous signing;
- require an agent threshold-share participation proof;
- require a Seams policy co-signing decision;
- bind signature to checkout hash, mandate hash, nonce, and expiry.

### Curve Suite Abstraction

Spike whether existing ECDSA code can be generalized behind a curve suite trait.

Candidate interface:

```rust
trait EcdsaCurveSuite {
    type Scalar;
    type ProjectivePoint;
    type AffinePoint;
    type Signature;
    type VerifyingKey;

    const CURVE_ID: &'static str;
    const JOSE_ALG: &'static str;

    fn generator() -> Self::ProjectivePoint;
    fn order_bytes() -> &'static [u8];
    fn scalar_from_bytes(bytes: &[u8]) -> Result<Self::Scalar, CurveError>;
    fn point_from_sec1(bytes: &[u8]) -> Result<Self::AffinePoint, CurveError>;
    fn point_to_sec1(point: &Self::AffinePoint) -> Vec<u8>;
    fn point_to_jwk(point: &Self::AffinePoint) -> P256Jwk;
    fn verify_es256(
        key: &Self::VerifyingKey,
        signing_input: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), VerifyError>;
}
```

Implementation detail:

- use RustCrypto `p256` / `ecdsa` crates for local verification, public key
  encoding, and test vectors;
- keep threshold math in the NEAR threshold-signatures protocol;
- produce signatures that verify in at least two independent JOSE libraries.

### Hashing Boundary

AP2/JOSE `ES256` signs:

```text
ASCII(BASE64URL(protected_header) + "." + BASE64URL(payload))
```

with SHA-256 inside the ECDSA signing operation.

NEAR threshold ECDSA code may expect a prehashed message. The Seams API must
make the hashing boundary explicit:

```text
AP2 signing input
  -> SHA-256 exactly once
  -> threshold ECDSA sign over digest
  -> JOSE raw R || S output
```

Required guardrails:

- reject prehashed raw input at the AP2 API boundary;
- store the exact JOSE signing input in audit evidence;
- store the SHA-256 digest used by the MPC protocol;
- test that double-hashing fails expected verification.

### Signature Encoding

AP2/JWS expects ES256 signatures as raw fixed-width concatenation:

```text
R: 32 bytes
S: 32 bytes
signature = R || S
```

Internal protocol output may be DER or scalar tuple. Add an explicit encoder:

```text
ThresholdEcdsaSignature
  -> P256SignatureParts { r, s }
  -> jose_es256_signature_bytes
  -> base64url(signature)
```

Validation:

- reject non-32-byte `r` or `s`;
- left-pad valid scalars to 32 bytes;
- decide whether to enforce low-S normalization and document the choice;
- verify with RustCrypto and a JOSE library.

## Seams AP2 Signing Flow

```text
1. Merchant/user approves open Checkout Mandate and open Payment Mandate in the
   Seams Trusted Surface.
2. Open mandates bind agent public key, merchant/payee, allowed SaaS actions,
   amount ceiling, recurrence, expiry, and payment instrument.
3. Agent finds the exact SaaS action: buy, upgrade, downgrade, cancel, or renew.
4. Agent constructs closed mandate content and starts threshold signing with its
   delegated share.
5. Seams policy co-signer validates:
   - open mandate reference;
   - closed mandate content;
   - SaaS vendor identity;
   - product or plan;
   - amount and recurrence;
   - cancellation or downgrade semantics;
   - policy version;
   - budget reservation;
   - expiry;
   - nonce and replay state;
   - credential availability.
6. Seams contributes the backend MPC share.
7. The completed P-256 signature becomes the AP2 closed mandate signature.
8. Seams Credential Provider verifies the completed mandate.
9. Credential layer issues a scoped JWT, virtual card authorization, wallet
   authorization, or payment-token release.
10. Checkout/cancellation executor completes the SaaS action.
11. Audit stores mandates, signing transcript references, credential release,
   SaaS receipt, screenshots/API evidence, and final result.
```

## API Surface

Public Seams API should expose typed operations:

```text
createOpenAp2Mandate
startAp2P256ThresholdSession
cosignAp2ClosedMandate
verifyAp2MandateSignature
authorizePaymentCredential
recordSaasPurchaseReceipt
recordSaasCancellationReceipt
revokeOpenAp2Mandate
```

Core request type:

```text
AP2P256SigningRequest
  - orgId
  - userOrMerchantPrincipalId
  - agentPrincipalId
  - agentP256PublicKey
  - openCheckoutMandateId
  - openPaymentMandateId
  - closedMandateKind
  - joseProtectedHeader
  - mandatePayload
  - joseSigningInput
  - checkoutHash
  - merchantPayee
  - amount
  - recurrence
  - paymentInstrumentRef
  - policyVersion
  - nonce
  - expiresAt
```

Core result type:

```text
AP2P256SigningResult
  - signingSessionId
  - completedSignature
  - publicKeyJwk
  - closedMandateJwtOrSdJwt
  - policyDecisionId
  - auditEventId
```

Credential result:

```text
PaymentCredentialAuthorization
  - authorizationId
  - signedMandateRef
  - credentialKind
  - scopedJwtOrTokenRef
  - allowedMerchant
  - maxAmount
  - checkoutHash
  - expiresAt
  - revocationState
```

## Refactor Phases

### Phase 0: Feasibility Spike

Questions:

- Can P-256 be added as an external crate using public `near/mpc` APIs?
- Is DKG truly generic enough for P-256 in the current crate boundaries?
- Are Secp256k1 assumptions embedded in ECDSA protocol code?
- Can a new signing domain be registered without modifying `mpc-node`?
- Can Seams run only the threshold-signatures crate without the whole node?

Tasks:

- clone `near/mpc`;
- map `crates/threshold-signatures` public APIs;
- map domain registration in `mpc-node`;
- identify private modules that block composition;
- build a toy P-256 local ECDSA signing and JOSE verification harness;
- write a 1-page decision note: composition, upstream extension PR, or fork.

Exit criteria:

- decision on composition vs fork;
- list of required upstream extension points;
- first failing test that expresses P-256 signing goal.

### Phase 1: Domain And Type Boundaries

Tasks:

- define `P256Ap2Domain`;
- define typed AP2 signing requests;
- define exact hashing and encoding boundary;
- add public key JWK encoding for P-256;
- add signature encoding for ES256 raw `R || S`;
- add verification helpers with RustCrypto `p256`.

Exit criteria:

- local P-256 signature fixtures verify with standard ES256 verification;
- AP2 signing input is hashed exactly once;
- arbitrary raw signing path is unavailable through Seams AP2 API.

### Phase 2: Threshold P-256 Implementation

Tasks:

- instantiate threshold ECDSA over P-256;
- wire DKG for P-256;
- wire presign/offline material for P-256;
- wire online signing for AP2 digests;
- support 2-of-2 and 2-of-3 dev networks;
- add timeout and abort behavior at the caller boundary.

Exit criteria:

- threshold-produced signatures verify as ES256;
- insufficient threshold fails;
- corrupted share fails;
- wrong message digest fails;
- wrong public key fails;
- replayed signing session fails.

### Phase 3: Seams Policy Co-Signer

Tasks:

- add `AP2MandateSigningEnvelope`;
- bind open mandates to agent public key;
- verify checkout hash and mandate hash;
- verify merchant/payee, SaaS action, amount, recurrence, and expiry;
- reserve budget before co-signing;
- attach policy decision and approval evidence;
- make revocation checks immediate before backend share contribution.

Exit criteria:

- agent share alone cannot produce a valid AP2 mandate signature;
- Seams backend share alone cannot produce a valid AP2 mandate signature;
- valid policy plus agent share plus backend share produces a valid signature;
- policy denial prevents backend share contribution.

### Phase 4: Credential Layer

Tasks:

- verify completed AP2 P-256 mandate signatures;
- verify open/closed mandate linkage;
- issue scoped JWT/payment credential authorization;
- bind credential to merchant, checkout hash, amount, expiry, and nonce;
- record credential release in audit;
- add revocation endpoint.

Exit criteria:

- credential release fails without a completed mandate signature;
- credential release fails after budget exhaustion;
- credential release fails after mandate or policy revocation;
- credential JWT cannot be replayed outside scope.

### Phase 5: SaaS Purchase And Cancellation Pilot

Tasks:

- implement Shopify subscription purchase simulation;
- implement SaaS cancellation simulation;
- capture receipts and screenshots/API evidence;
- model recurring subscription policy;
- model cancellation authority separately from payment authority.

Exit criteria:

- agent can buy an allowed SaaS plan under budget;
- agent cannot buy a disallowed add-on;
- agent can cancel an allowed SaaS subscription;
- user can inspect AP2 mandates, credential release, and execution evidence.

## Testing Plan

Cryptographic tests:

- P-256 public key JWK encoding;
- ES256 raw `R || S` encoding;
- RustCrypto `p256` verification;
- independent JOSE library verification;
- wrong hash rejection;
- double-hash rejection;
- insufficient-threshold rejection;
- corrupted-share rejection;
- replayed signing-session rejection.

Protocol tests:

- 2-of-2 DKG and sign;
- 2-of-3 DKG and sign;
- resharing if needed for production;
- presign material exhaustion;
- timeout behavior;
- participant mismatch;
- malicious or malformed transcript message.

AP2 tests:

- open Checkout Mandate creation;
- open Payment Mandate creation;
- closed Checkout Mandate signing;
- closed Payment Mandate signing;
- agent key binding;
- checkout hash binding;
- merchant/payee mismatch rejection;
- recurrence/budget rejection;
- expired mandate rejection.

Product tests:

- allowed Shopify plan purchase;
- disallowed Shopify add-on;
- allowed SaaS cancellation;
- cancellation without payment credential;
- downgrade with approval;
- audit export for dispute or finance review.

## Security Review Checklist

- The AP2 API accepts typed mandate signing requests only.
- The agent share cannot be reused outside the delegated scope.
- The Seams backend share is unreachable from the LLM runtime.
- The backend share is contributed only after deterministic policy checks.
- Open mandates bind the agent public key and expire quickly.
- Closed mandates bind checkout hash, amount, merchant, nonce, and expiry.
- Credential release verifies the completed threshold signature.
- Budget reservation is atomic with credential release.
- Revocation blocks signing and credential release.
- Signing transcripts are logged without leaking secret shares.
- RNG quality is reviewed for P-256 ECDSA nonce/pre-signature generation.
- Side-channel risks are reviewed for scalar operations and serialization.
- Dependencies are pinned and audited.

## Risks

Implementation risk:

- NEAR ECDSA code may contain Secp256k1-specific assumptions.
- P-256 support may require private `near/mpc` module changes.
- ECDSA threshold signing is harder to audit than EdDSA/FROST paths.

Interop risk:

- AP2 validators expect standard JOSE ES256 output.
- SD-JWT/KB-SD-JWT serialization must match verifier expectations.
- Hashing and signature encoding mistakes can create hard-to-debug failures.

Operational risk:

- presign material management can become a bottleneck;
- timeouts and abort behavior need explicit caller handling;
- fork drift can become expensive if upstream changes rapidly.

Product risk:

- SaaS vendors may lack AP2-native flows for a while;
- early execution may require browser/API automation plus normal payment rails;
- cancellation semantics vary by SaaS provider.

## Decision Gates

Gate 1: Composition feasibility.

- Pass: P-256 can be implemented through public or upstreamable extension points.
- Fail: private APIs require a Seams fork.

Gate 2: Cryptographic correctness.

- Pass: threshold P-256 signatures verify with independent ES256 tooling.
- Fail: protocol output cannot be made AP2-compatible without unsafe changes.

Gate 3: Dual-control guarantee.

- Pass: neither agent nor Seams backend can complete a signature alone.
- Fail: one side can unilaterally create purchase-authorizing mandates.

Gate 4: AP2 product flow.

- Pass: signed mandates can authorize a scoped credential for SaaS purchase or
  cancellation.
- Fail: credential layer requires authority outside the signed mandate model.

## Recommended First Step

Run the feasibility spike against current `near/mpc`.

Preferred outcome:

```text
Add a general P-256 ECDSA domain through upstreamable extension points, keep AP2
policy and credential release in Seams-specific crates, and avoid a permanent
fork.
```

Expected fallback:

```text
Maintain a narrow Seams fork of near/mpc focused on P-256 domain support while
upstreaming the extension points needed to return to normal upstream tracking.
```
