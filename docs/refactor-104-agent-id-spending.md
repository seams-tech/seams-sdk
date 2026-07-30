# Agent Identity And Delegated Spending

Date created: July 22, 2026

Status: active product and security plan. Independent agent identities,
owner-signed delegated-spend authorizations, agent-signed spend requests, and
their admission and revocation stores are unimplemented. Existing dormant
delegated-lane scaffolds encode a superseded lane-owned identity model and will
be replaced directly.

## Goal

Let an agent spend within an owner-approved mandate from the owner's existing
wallet while keeping the owner's and agent's keys separate.

```text
Agent creates an independent identity key.
Owner approves an exact wallet-key set and spending mandate.
Each covered owner wallet key signs the authorization for that agent key.
Agent signs every concrete spend request with its own key.
Seams verifies authorship, authorization, scope, budget, replay, and revocation.
The selected wallet execution path signs from the owner's wallet.
Funds move directly from the owner's wallet to the approved destination.
```

The design preserves three distinct proofs:

```text
agent signature   -> who requested the spend
owner signature   -> who authorized the agent and under which constraints
wallet execution  -> which wallet paid
```

## Dependencies And Authority

This plan consumes:

- [refactor-90-modular-auth-capabilities-plan.md](./refactor-90-modular-auth-capabilities-plan.md)
  and its SPEC for authorization resources, exact operation fingerprints,
  atomic grant-plus-quota claims, Wallet Session boundaries, effect ordering,
  replay handling, and audit;
- [refactor-96-wallet-execution-lanes.md](./refactor-96-wallet-execution-lanes.md)
  for stable wallet-key identities and optional delegated-execution lanes;
- [refactor-97-share-rotation.md](./refactor-97-share-rotation.md) when a direct
  threshold-wallet adapter provisions an authorization-bound agent runtime
  lane;
- `crates/router-ab-ecdsa-derivation` and the Ed25519 Yao implementation for
  wallet execution under exact active capabilities;
- [refactor-10X-p256.md](./refactor-10X-p256.md) for AP2 P-256 agent keys and
  user-signed-open/agent-signed-closed mandate interoperability.

This plan owns:

- agent identities and public signing keys;
- owner-signed delegated-spend authorization records;
- typed spend scopes and budget policy;
- agent request signatures and final-transaction binding;
- delegated authorization lifecycle, suspension, expiry, and revocation;
- atomic delegated-budget and replay claims;
- delegated execution admission and audit evidence.

Refactor 98 owns physical device linking and contains no agent types.

## Required Invariants

1. Every agent has at least one independent identity signing key. No agent
   identity key equals or derives from an owner wallet key.
2. An agent receives no owner private key, complete wallet secret, export
   capability, recovery authority, or account-admin authority.
3. Owner authorization binds one exact agent key, wallet-key manifest, scope,
   budget, validity window, nonce domain, and revocation epoch.
4. Each wallet key covered by a direct-wallet authorization contributes an
   owner proof over the same canonical authorization digest.
5. Every spend request carries an agent signature over the authorization ID,
   typed intent, final unsigned-transaction digest, idempotency key, request
   nonce, issue time, and expiry.
6. Policy validates both the typed intent and the final unsigned transaction.
   A valid intent cannot authorize substituted transaction bytes.
7. Budget reservation is atomic before signing. Concurrent requests cannot
   exceed aggregate or per-operation limits.
8. Revocation and expiry fail before wallet share, presignature, credential, or
   payment-token work.
9. On-chain or payment execution spends from the owner's wallet or payment
   instrument. The agent needs no prefunded account.
10. Agent authorship remains available in durable audit evidence even when the
    chain exposes only the owner's wallet signature.
11. Raw agent, tool, quote, checkout, transaction, oracle, and persistence
    shapes are parsed once at their boundaries.
12. Old lane-owned mandate types and tests are deleted at cutover. No legacy
    `delegated_agent` compatibility branch enters core logic.

## Trust Boundaries

### Owner trusted surface

- authenticates the owner with fresh user verification;
- displays the agent identity fingerprint and custody status;
- displays wallet keys, chains, assets, counterparties, action types, budget,
  fees, recurrence, expiry, and revocation consequences;
- constructs one canonical authorization;
- obtains one owner proof for every direct wallet key in the manifest;
- publishes the authorization only after all proofs verify.

### Agent runtime

- owns its independent identity private key;
- protects the key in its declared custody runtime;
- constructs typed intents from untrusted tool output;
- signs concrete request envelopes;
- may hold an incomplete lane-specific MPC share for the direct threshold
  adapter;
- never receives the owner's complete signing key or an export-capable share.

### Router and policy service

- verify agent and owner signatures;
- resolve current authorization, revocation, wallet-key, and execution state;
- normalize and verify quotes, counterparties, assets, and final transactions;
- atomically reserve budget and replay identity;
- issue one committed execution admission;
- release, commit, or retain reservations according to deterministic execution
  outcomes;
- cannot forge an agent request or bypass the required agent signature.

### Wallet execution participants

- accept only committed prepared admission from the Router;
- verify exact wallet key, lane, participants, epochs, authorization, request,
  and transaction digests;
- sign no broader payload than the admitted final transaction;
- expose no owner share or export path to the agent runtime.

## Agent Identity

An identity is a stable agent record with one or more protocol-specific signing
keys. Each authorization names one exact key.

```ts
type AgentIdentityRecord = {
  kind: 'agent_identity_v1';
  agentId: AgentId;
  displayName: string;
  operator: AgentOperator;
  keys: readonly [AgentIdentityKeyRecord, ...AgentIdentityKeyRecord[]];
  lifecycle: AgentIdentityLifecycle;
  createdAtMs: number;
};

type AgentIdentityKeyRecord =
  | {
      kind: 'agent_identity_key_v1';
      algorithm: 'secp256k1_schnorr_bip340';
      agentIdentityKeyId: AgentIdentityKeyId;
      publicKeyXOnlyB64u: string;
      publicJwk?: never;
      lifecycle: AgentIdentityKeyLifecycle;
    }
  | {
      kind: 'agent_identity_key_v1';
      algorithm: 'p256_ecdsa_es256';
      agentIdentityKeyId: AgentIdentityKeyId;
      publicJwk: P256PublicJwk;
      publicKeyXOnlyB64u?: never;
      lifecycle: AgentIdentityKeyLifecycle;
    };
```

The BIP-340 branch can represent the same agent identity used by Nostr/Buzz.
The P-256 branch supports AP2 closed mandates. A future algorithm requires a
new union branch, canonical verifier, test vectors, and custody policy.

Keys are never silently rotated in place. Rotation creates a new key record and
requires fresh owner authorization. Existing authorizations remain bound to the
old key and follow their own expiry or revocation lifecycle.

### BIP-340 signing boundary

The BIP-340 profile is a distinct agent-key signing protocol. It provisions an
independent agent key and defines x-only public-key normalization, tagged
hashing, nonce handling, participant binding, output encoding, and test vectors
explicitly. Existing threshold ECDSA wallet shares, presignatures, and signing
rounds are unavailable to this profile.

A threshold BIP-340 implementation may reuse reviewed secp256k1 scalar and
point primitives, authenticated transport, lifecycle machinery, and custody
interfaces. Phase 0 must select and review a BIP-340-compatible threshold
protocol before the threshold branch can ship. A single-signer HSM, TEE, or
customer-runtime branch remains explicit and produces the same ordinary
BIP-340 verification result.

## Agent Custody Binding

Identity-key custody and optional wallet-lane custody are separate records:

```ts
type AgentCustodyBindingRecord = {
  kind: 'agent_custody_binding_v1';
  custodyBindingId: AgentCustodyBindingId;
  agentId: AgentId;
  agentIdentityKeyId: AgentIdentityKeyId;
  runtime:
    | 'managed_service'
    | 'tee'
    | 'hsm'
    | 'customer_runtime';
  signingKeyAttestation: AgentSigningKeyAttestation;
  encryptionPublicKeyB64u: string;
  lifecycle: AgentCustodyLifecycle;
};
```

An optional `DelegatedExecutionLaneRecord` references this custody binding for
holder-package delivery. The identity key signs requests; the lane share
participates only in wallet execution.

## Delegated Spend Authorization

The canonical claims are independent from transport and signature encoding:

```ts
type DelegatedSpendAuthorizationV1 = {
  kind: 'delegated_spend_authorization_v1';
  authorizationId: DelegatedSpendAuthorizationId;
  walletId: WalletId;
  ownerKeyManifest: readonly [AuthorizedWalletKey, ...AuthorizedWalletKey[]];
  agentId: AgentId;
  agentIdentityKeyId: AgentIdentityKeyId;
  agentIdentityKeyAlgorithm:
    | 'secp256k1_schnorr_bip340'
    | 'p256_ecdsa_es256';
  agentPublicKeyDigestB64u: string;
  custodyBindingId: AgentCustodyBindingId;
  scope: DelegatedSpendScopeV1;
  budget: SingleAssetDelegatedBudgetV1;
  replayPolicy: DelegatedReplayPolicyV1;
  policyVersion: 'delegated_spend_policy_v1';
  policyDigestB64u: string;
  revocationEpoch: number;
  issuedAtMs: number;
  notBeforeMs: number;
  expiresAtMs: number;
  authorizationNonce: string;
};
```

`ownerKeyManifest` is canonically ordered and duplicate-free. Each entry binds
the wallet key's family, public identity, and permitted execution adapter.

### Owner proof

For direct wallet spending, every wallet key in the manifest signs the same
domain-separated authorization digest:

```text
message = SHA256(
  "seams:delegated-spend-authorization:v1:" ||
  canonical_cbor(authorization)
)
```

```ts
type SignedDelegatedSpendAuthorizationV1 = {
  kind: 'signed_delegated_spend_authorization_v1';
  authorization: DelegatedSpendAuthorizationV1;
  authorizationDigestB64u: string;
  ownerProofs: readonly [WalletKeyOwnerProof, ...WalletKeyOwnerProof[]];
};
```

The proof set must match the wallet-key manifest exactly. Missing, duplicate,
extra, wrong-family, wrong-public-key, or differently digested proofs fail.

An AP2 open mandate is an adapter-specific owner authorization envelope. Its
verified disclosures normalize into the same core claims, while its original
signed bytes remain attached as external evidence. Core policy never accepts
raw SD-JWT claims.

## Spending Scope

The first scope remains intentionally narrow:

```ts
type DelegatedSpendScopeV1 = {
  kind: 'delegated_spend_scope_v1';
  allowedIntentKind: 'specific_purchase_payment_v1';
  allowedChains: readonly [ChainId, ...ChainId[]];
  allowedAsset: AssetDescriptor;
  allowedCounterparties: readonly [CounterpartyDescriptor, ...CounterpartyDescriptor[]];
  allowedDestinations: readonly [AddressDescriptor, ...AddressDescriptor[]];
  allowancePolicy: 'forbidden';
  recurringPaymentPolicy: 'forbidden';
  maxFee: AtomicAmount;
  requiredQuoteBinding: 'merchant_signed_quote_v1';
  requiredFinalTransactionBinding: 'exact_unsigned_transaction_v1';
};
```

The MVP allows one asset per authorization. Use exact stablecoin atomic units,
such as USDC base units, for dollar-denominated product limits. Generic
cross-asset USD accounting remains unavailable until a separate policy branch
defines oracle identity, quote freshness, confidence, rounding, fallback, and
dispute semantics.

Allowance grants, arbitrary contract calls, recurring payments, swaps,
bridging, subscriptions, and account administration require separate typed
intent and policy branches.

## Budget

```ts
type SingleAssetDelegatedBudgetV1 = {
  kind: 'single_asset_delegated_budget_v1';
  asset: AssetDescriptor;
  aggregateLimit: AtomicAmount;
  perOperationLimit: AtomicAmount;
  feeTreatment: 'fees_count_toward_aggregate';
};
```

Budget state is server-canonical:

```ts
type DelegatedBudgetClaimState =
  | {
      state: 'reserved';
      reservationId: DelegatedBudgetReservationId;
      operationId: DelegatedSpendOperationId;
      reservedAmount: AtomicAmount;
      reservedFee: AtomicAmount;
      expiresAtMs: number;
    }
  | {
      state: 'committed';
      reservationId: DelegatedBudgetReservationId;
      executionReceiptDigestB64u: string;
      committedAtMs: number;
    }
  | {
      state: 'released';
      reservationId: DelegatedBudgetReservationId;
      releaseReason: 'pre_execution_failure' | 'definitive_rejection';
      releasedAtMs: number;
    }
  | {
      state: 'outcome_unknown';
      reservationId: DelegatedBudgetReservationId;
      reconciliationReference: string;
      markedAtMs: number;
    };
```

Reservation uses one compare-and-swap against authorization identity,
revocation epoch, operation fingerprint, aggregate committed amount, aggregate
reserved amount, and request idempotency key. `outcome_unknown` retains budget
until authoritative reconciliation. No timeout alone refunds a potentially
executed payment.

## Agent Spend Request

The agent signs a concrete request after quote and transaction construction:

```ts
type AgentSpendRequestV1 = {
  kind: 'agent_spend_request_v1';
  requestId: AgentSpendRequestId;
  authorizationId: DelegatedSpendAuthorizationId;
  authorizationDigestB64u: string;
  authorizationRevocationEpoch: number;
  agentId: AgentId;
  agentIdentityKeyId: AgentIdentityKeyId;
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  intent: SpecificPurchasePaymentIntentV1;
  intentDigestB64u: string;
  quoteDigestB64u: string;
  finalUnsignedTransactionDigestB64u: string;
  idempotencyKey: DelegatedIdempotencyKey;
  requestNonce: string;
  requestedAtMs: number;
  expiresAtMs: number;
};

type SignedAgentSpendRequestV1 = {
  kind: 'signed_agent_spend_request_v1';
  request: AgentSpendRequestV1;
  requestDigestB64u: string;
  agentSignature: AgentIdentitySignature;
};
```

The signature message is domain-separated and commits canonical CBOR bytes.
The verifier uses the exact public key named by the authorization. A valid
signature under another active key for the same agent fails.

## Authorization Lifecycle

```ts
type DelegatedSpendAuthorizationLifecycle =
  | {
      state: 'active';
      revocationEpoch: number;
      activatedAtMs: number;
    }
  | {
      state: 'suspended';
      revocationEpoch: number;
      suspendedAtMs: number;
      reason: 'owner_paused' | 'risk_engine' | 'custody_unavailable';
    }
  | {
      state: 'exhausted';
      revocationEpoch: number;
      exhaustedAtMs: number;
    }
  | {
      state: 'expired';
      revocationEpoch: number;
      expiredAtMs: number;
    }
  | {
      state: 'revoked';
      revocationEpoch: number;
      revokedAtMs: number;
      reason:
        | 'owner_revoked'
        | 'agent_compromise'
        | 'custody_compromise'
        | 'policy_replaced';
    };
```

Only `active` authorizations admit new operations. Budget exhaustion commits an
`exhausted` transition. Budget top-up, scope expansion, expiry extension, agent
key rotation, or wallet-key-set change creates a newly signed authorization;
it never mutates the signed claims in place.

## Admission And Execution

Execute checks in this order:

1. Parse and verify the signed agent request.
2. Load the exact signed owner authorization.
3. Verify authorization digest, owner proof set, agent key, validity window,
   lifecycle, and revocation epoch.
4. Load active wallet key and selected execution adapter.
5. Normalize and validate the quote, counterparty, asset, amount, destination,
   fees, and typed intent.
6. Independently decode or construct the final unsigned transaction.
7. Verify its digest and semantic fields against the request and authorization.
8. Atomically claim replay identity and reserve aggregate budget.
9. Construct one `PreparedDelegatedWalletExecution` with exact immutable
   evidence references.
10. Execute through the selected adapter.
11. Commit the budget and audit receipt on confirmed execution; release only on
    definitive pre-execution failure; retain unknown outcomes for
    reconciliation.

Policy denial performs no share, presignature, credential, or payment-token
work.

## Execution Adapters

### Direct threshold-wallet execution

The transaction is signed under the owner's existing wallet key. Funds leave
that wallet directly. The chain generally exposes the wallet signature while
Seams retains the agent and owner proofs in audit evidence.

An authorization-bound `delegated_execution` lane may give the agent runtime an
incomplete holder share and Seams a matching policy-controlled server share.
Both parties are then required for the wallet signature. The lane is an
execution mechanism and grants no authority without a verified active
authorization and signed request.

### AP2 credential release

The user-signed open mandate binds the agent P-256 key and constraints. The
agent signs the closed Checkout and Payment Mandates. The Credential Provider
verifies both before releasing a scoped credential or payment token. Refactor
10X owns wire compatibility and P-256 signing.

### Chain-native delegated account

A future smart-account adapter may register the agent public key and scope
on-chain. Its contract, revocation transaction, nonce model, and policy proof
are chain-specific. Core authorization still retains the owner and agent proof
chain.

## Revocation

Revocation is one fenced operation:

1. Increment the server-canonical authorization revocation epoch and mark the
   authorization revoked.
2. Reject new requests and budget reservations immediately.
3. Stop queued operations that have not crossed an irreversible execution
   boundary.
4. Revoke optional delegated-execution lanes and disable their server
   participants.
5. Terminate agent sessions and invalidate warm custody handles.
6. Mark in-flight ambiguous operations `outcome_unknown` for reconciliation.
7. Emit an authorization revocation receipt and affected-operation inventory.
8. Submit chain-native revocation when the selected adapter requires it.

Owner lanes, wallet keys, funds, and unrelated authorizations remain active.
Previously completed transactions remain valid.

## Audit Evidence

One delegated execution audit chain retains:

- exact owner-signed authorization bytes and digest;
- exact agent public key and signed request bytes;
- normalized intent, quote, and final transaction digests;
- policy version and decision;
- replay and budget claim IDs and transitions;
- wallet key, optional execution lane, participants, and epochs;
- wallet signature or credential-release receipt;
- chain, merchant, or payment receipt;
- denial, revocation, and reconciliation evidence.

Audit projections may omit private commercial data. The retained evidence must
remain sufficient to prove owner authorization, agent authorship, and execution
binding during dispute review.

## Public SDK Surface

```text
registerAgentIdentity()
rotateAgentIdentityKey()
createDelegatedSpendAuthorization()
listDelegatedSpendAuthorizations()
suspendDelegatedSpendAuthorization()
revokeDelegatedSpendAuthorization()
submitAgentSpendRequest()
getDelegatedSpendOperation()
```

Registration accepts public keys and boundary-validated custody attestations.
It never accepts agent private keys through ordinary SDK, iframe, callback, or
logging surfaces.

Agent methods use separate request and result unions from physical-device
linking. No option bag can construct both operations.

## Current Scaffolds To Replace

Delete or replace these dormant shapes when the new behavior lands:

- `DelegatedAgentSigningLaneRecord`;
- lane-owned `DelegatedMandatePolicy`;
- the old share-holder-oriented `AgentPrincipalId`; replace it with the
  identity-oriented `AgentId`;
- unsigned `DelegatedSigningRequest`;
- lane-derived `DelegatedSigningAuditEvent`;
- `DelegatedBudgetReservationStore` semantics tied to lane policy;
- `agentWallets.ts` projections that infer authority from lane ownership;
- broad rotation jobs shared between device and agent enrollment.

Retain useful typed purchase-intent and canonical digest code only after it is
adapted to the signed authorization and request boundaries.

## Implementation Phases

### Phase 0: Freeze Protocol

- [ ] Freeze identity-key algorithms and canonical CBOR encoding.
- [ ] Select the BIP-340 signing profiles and, if threshold signing is used,
      its protocol, participant topology, nonce rules, and independent vectors.
- [ ] Freeze direct-wallet owner proof encoding for Ed25519 and secp256k1.
- [ ] Freeze the stablecoin-only MVP scope, budget, fee, and quote policy.
- [ ] Freeze request signature, replay, expiry, and revocation semantics.
- [ ] Freeze the first execution adapter and custody topology.

### Phase 1: Identity And Authorization

- [ ] Add branded IDs and exhaustive identity/key/custody lifecycles.
- [ ] Add canonical authorization builder and boundary parser.
- [ ] Verify one exact owner proof per wallet key.
- [ ] Add authorization store and lifecycle transitions.
- [ ] Add negative type fixtures for wallet-key/agent-key substitution.

### Phase 2: Agent Requests And Policy

- [ ] Add algorithm-specific agent request verifiers.
- [ ] Add one specific-purchase intent and merchant-signed quote parser.
- [ ] Verify final unsigned transaction independently.
- [ ] Add authorization scope, expiry, fee, and counterparty admission.

### Phase 3: Budget, Replay, And Audit

- [ ] Implement atomic replay and budget claims through Refactor 90.
- [ ] Implement outcome-unknown reconciliation.
- [ ] Persist the complete three-proof audit chain.
- [ ] Add denial and exhaustion projections.

### Phase 4: Direct Wallet Execution

- [ ] Provision optional authorization-bound execution lanes.
- [ ] Bind prepared admission to exact wallet capability execution.
- [ ] Sign from the owner wallet without transferring funds to the agent.
- [ ] Commit budget and execution receipts exactly once.

### Phase 5: Revocation And Operations

- [ ] Implement immediate authorization and lane revocation.
- [ ] Terminate active agent sessions and warm handles.
- [ ] Add management UI, notifications, and audit export.
- [ ] Add agent-key rotation through fresh authorization.

### Phase 6: Protocol Adapters

- [ ] Integrate AP2 open and closed mandate verification.
- [ ] Add chain-native delegated-account adapters only after their on-chain
      policy and revocation models are separately specified.

## Validation

Static fixtures prove:

- agent keys cannot construct wallet-key records;
- authorizations require nonempty wallet-key manifests and exact agent keys;
- direct-wallet proof sets cannot omit or add wallet keys;
- signed claims cannot be mutated into lifecycle state;
- P-256 and BIP-340 signatures cannot cross algorithm branches;
- prepared execution cannot carry unverified raw requests;
- delegated authorization cannot grant export, recovery, or account admin.

Cryptographic tests prove:

- owner proofs verify only over the canonical authorization digest;
- agent signatures verify only over the canonical request digest;
- BIP-340 keys and signing state are independent from wallet ECDSA shares and
  presignatures;
- wrong agent key, owner key, algorithm, domain separator, or encoding fails;
- modified amount, destination, quote, transaction, expiry, or nonce fails;
- independent implementations reproduce authorization and request vectors.

Policy and concurrency tests prove:

- over-budget, expired, suspended, revoked, replayed, and out-of-scope requests
  fail before execution work;
- concurrent requests cannot exceed aggregate budget;
- fees count toward the configured aggregate cap;
- transaction substitution fails after valid intent admission;
- unknown execution outcomes retain reservations;
- definitive pre-execution failures release reservations exactly once.

Execution tests prove:

- an authorized purchase spends directly from the owner's wallet;
- the agent owns no prefunded wallet and receives no owner export material;
- optional delegated execution requires both agent holder and server
  participation;
- owner authorization or agent signature alone cannot execute;
- revoking one authorization preserves owner and unrelated agent spending;
- audit reconstructs owner authorization, agent authorship, and wallet payment.

## Non-Goals

- transferring a spending balance into an agent-owned wallet;
- treating an agent identity key as a wallet key;
- relying on prompts or tool arguments as policy evidence;
- supporting arbitrary contract calls in the MVP;
- generic fiat valuation without an explicit oracle policy;
- silent scope expansion, budget top-up, or expiry extension;
- granting export, recovery, membership, or account administration;
- using NIP-OA alone as a spending mandate;
- requiring one execution adapter across all chains and payment rails.

## Decisions Required Before Implementation

- Select the MVP agent identity algorithm: BIP-340 for Buzz/Nostr alignment,
  P-256 ES256 for AP2, or two explicit protocol keys under one agent identity.
- Select the owner-proof format for each supported wallet key family.
- Select the direct threshold execution topology and agent custody requirements.
- Freeze the first supported stablecoin, networks, merchant quote format, and
  destination identity rules.
- Define how refunds restore budget, if at all, without weakening dispute and
  replay guarantees.
- Define retention and privacy policy for signed commercial evidence.
