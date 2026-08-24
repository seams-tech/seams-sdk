# Agent Runtime Enrollment And Delegated Spending

Date created: July 22, 2026

Last reconciled: August 22, 2026 (CLI runtime enrollment and direct-wallet product boundary)

Status: active product and security plan. CLI agent-runtime enrollment,
independent agent identities, owner-signed delegated-spend authorizations,
agent-signed spend requests, and their admission and revocation stores are
unimplemented. Existing dormant delegated-lane scaffolds encode a superseded
lane-owned identity model and will be replaced directly. R101/R102 lane shares,
epochs, rotation, fencing, and MPC activation primitives remain reusable
execution machinery.

## Goal

Let an agent spend within an owner-approved mandate from the owner's existing
wallet while keeping the owner's and agent's keys separate.

```text
CLI creates an independent agent identity key and enrollment request.
Owner opens seams.sh and approves that exact runtime, wallet-key set, and
spending mandate.
Each covered owner wallet key signs the authorization for that agent key.
One incomplete delegated-execution holder share is delivered to the CLI for
each covered wallet key; the owner wallet seed never leaves owner custody.
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

The agent-wallet product is a logical projection over an `AgentIdentity`,
`DelegatedSpendAuthorization`, `DelegatedExecutionSigningLaneRecord`, and the
owner's existing `WalletKeyRecord`. It creates no second wallet, public key,
address, prefunded balance, or canonical owner. Owner and delegated lanes use
fresh independent shares that preserve the existing wallet public key. The
agent identity key remains a separate request-authorship key.

## Dependencies And Authority

This plan consumes:

- [refactor-90-modular-auth-capabilities-plan.md](./refactor-90-modular-auth-capabilities-plan.md)
  and its SPEC for authorization resources, exact operation fingerprints,
  `AuthorizedOperationId`, `MpcMaterialActivationRef`, Wallet Session
  boundaries, effect ordering, replay handling, and audit. Refactor 104 owns
  the delegated authorization, budget, and replay stores that supply its own
  authorization source;
- [refactor-101-wallet-execution-lanes.md](./refactor-101-wallet-execution-lanes.md)
  for stable wallet-key identities and the existing
  `DelegatedExecutionSigningLaneRecord` execution primitive;
- [refactor-102-rotatable-signing-lanes.md](./refactor-102-rotatable-signing-lanes.md) when a direct
  threshold-wallet adapter provisions an authorization-bound agent runtime
  lane;
- the existing Ed25519 and secp256k1 signature primitives for agent request
  signing and verification;
- `crates/router-ab-ecdsa-derivation` and the Ed25519 Yao implementation for
  wallet execution under exact active capabilities.

This plan owns:

- CLI agent-runtime enrollment sessions, approval transcripts, encrypted
  holder-package delivery, activation, and local public projections;
- agent identities and public signing keys;
- owner-signed delegated-spend authorization records;
- typed spend scopes and budget policy;
- agent request signatures and final-transaction binding;
- delegated authorization lifecycle, suspension, expiry, and revocation;
- atomic delegated-budget and replay claims;
- delegated execution admission and audit evidence.

Refactor 103 owns physical device linking and contains no agent types.

### Relationship To Physical Devices And Separate Wallets

R104 owns a dedicated agent-runtime enrollment flow. The CLI creates a
short-lived unclaimed enrollment session and an approval URL or QR code. The
owner opens that request on `seams.sh`, authenticates with fresh user
verification, reviews the runtime identity and exact mandate, signs the
authorization, and provisions authorization-bound delegated lanes. The CLI
receives only encrypted incomplete lane-specific holder packages. It never
receives the wallet custody seed.

The enrollment transport may reuse established authenticated SSE, POST,
polling, HPKE delivery, and committed-delivery helpers where their existing
interfaces fit. It must not reuse `LinkedDevice*` records, routes, state
machines, receipts, target factors, Wallet Sessions, owner-equivalent
permissions, or UI. Agent enrollment creates no owner credential and grants no
local-user-presence, export, recovery, or account-administration capability.

R104 reuses `DelegatedExecutionSigningLaneRecord` plus curve-agnostic R101/R102
provisioning, activation, epoch, rotation, and fencing primitives. The lane is
an execution mechanism; agent identity and authority come exclusively from the
independent agent key and the owner-signed delegated authorization.

R104 covers direct spending from an existing owner's wallet under a constrained
mandate. It creates no separately funded agent wallet. An independently owned
wallet remains in the ordinary canonical-owner model and is outside delegated
spending.

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
8. Delegated authorization lifecycle and delegated budget lifecycle are
   independent. Budget exhaustion denies new spends without moving the signed
   authorization to an `exhausted` state.
9. Revocation and expiry fail before wallet share, presignature, or execution
   work.
10. On-chain execution spends from the owner's wallet. The agent needs no
    prefunded account.
11. Agent authorship remains available in durable audit evidence even when the
    chain exposes only the owner's wallet signature.
12. Raw agent, tool, quote, transaction, oracle, and persistence
    shapes are parsed once at their boundaries.
13. Old lane-owned mandate types and tests are deleted at cutover. No legacy
    `delegated_agent` compatibility branch enters core logic.
14. A lane never establishes agent identity, delegated authority, budget, or
    replay rights. Those facts must verify before lane activation or execution.
15. Every direct threshold-wallet execution names one authorization-bound lane,
    its current share epoch, participants, and exact material activation.
16. No R104 path transfers or reconstructs the owner's wallet custody seed.
17. An enrollment URL or QR code contains public bootstrap identity only. It
    carries no wallet, share, root, recovery, authorization, Wallet Session, or
    export material.
18. Owner approval binds the exact enrollment session, agent identity key,
    custody binding, wallet-key manifest, authorization digest, target lanes,
    participants, protocol versions, and expiry.
19. The CLI opens holder packages only inside its wallet worker and persists
    sealed envelopes plus a public runtime projection. Raw identity private
    keys and holder shares never cross CLI output, callback, tool, or log
    boundaries.
20. Enrollment becomes active only after every child lane activation receipt
    verifies and the CLI acknowledges exact committed delivery.
21. A local runtime profile is a projection of server-canonical identity,
    authorization, lane, and lifecycle records. It grants no authority by
    itself and never controls admission.

## Trust Boundaries

### Owner trusted surface

- authenticates the owner with fresh user verification;
- atomically claims one short-lived unclaimed agent enrollment session;
- displays the agent identity fingerprint and custody status;
- displays wallet keys, chains, assets, counterparties, action types, budget,
  fees, recurrence, expiry, and revocation consequences;
- constructs one canonical authorization;
- obtains one owner proof for every direct wallet key in the manifest;
- publishes the authorization only after all proofs verify;
- completes enrollment only after all lane activation and delivery receipts
  verify.

### Agent runtime

- generates its identity signing key and HPKE delivery key inside the CLI
  wallet worker;
- creates the unclaimed enrollment session and displays its approval URL or QR;
- owns its independent identity private key;
- protects the key in its declared custody runtime;
- constructs typed intents from untrusted tool output;
- signs concrete request envelopes;
- holds an incomplete lane-specific MPC share only when an active authorization
  selects the direct threshold adapter;
- seals identity and holder material locally and exposes only public profile,
  request, status, and receipt data to the calling agent framework;
- never receives the owner's complete signing key or an export-capable share.

### Gateway policy service and Router

- Gateway D1 owns delegated authorization records, owner proof sets, scope,
  revocation facts, delegated replay and budget claims, authorized operations,
  enrollment claims, approval transcripts, delivery receipts, activation
  results, and product audit records;
- verify agent and owner signatures at the authenticated Gateway boundary;
- resolve current authorization, revocation, wallet-key, and execution state;
- normalize and verify quotes, counterparties, assets, and final transactions;
- atomically reserve delegated budget and claim replay identity in the R104
  store transaction;
- issue one committed execution admission carrying the exact
  `AuthorizedOperationId` and material activation;
- release, commit, or retain reservations according to deterministic execution
  outcomes;
- Router validates and forwards the internally authenticated Gateway command.
  It owns no mutable authorization, budget, replay, or execution ledger and
  cannot forge an agent request or bypass the required agent signature.

### Wallet execution participants

- accept only committed prepared admission from the Router;
- for direct threshold execution, verify the exact wallet key, lane,
  participants, epochs, authorization, request, and transaction digests;
- sign no broader payload than the admitted final transaction;
- expose no owner share or export path to the agent runtime.

## Agent Runtime Enrollment

Enrollment is a short-lived bootstrap that binds one CLI runtime to an
independent agent identity, owner-signed authorization, and exact delegated
execution lanes. Enrollment never authenticates an ordinary spend and never
becomes a reusable authorization source.

The CLI begins from no wallet identity or authority:

```text
CLI wallet worker
  -> generate agent identity key and HPKE delivery key
  -> register an unclaimed enrollment session
  -> display https://seams.sh/agents/enroll?... or its QR form

Owner trusted surface
  -> claim the session after fresh user verification
  -> review agent fingerprint, wallet keys, scope, budget, fees, and expiry
  -> sign one exact delegated-spend authorization
  -> authorize and provision one delegated lane per covered wallet key

CLI wallet worker
  -> receive encrypted committed holder packages
  -> verify authorization, participant, lane, epoch, and activation bindings
  -> seal identity and holder material locally
  -> acknowledge exact delivery and activate the runtime profile
```

### Enrollment state

```ts
type AgentRuntimeEnrollmentState =
  | {
      state: 'awaiting_owner';
      enrollmentSessionId: AgentRuntimeEnrollmentSessionId;
      runtimeProfileId: AgentRuntimeProfileId;
      agentId: AgentId;
      agentIdentityKeyId: AgentIdentityKeyId;
      custodyBindingId: AgentCustodyBindingId;
      expiresAtMs: number;
      walletId?: never;
      authorizationId?: never;
    }
  | {
      state: 'owner_claimed';
      enrollmentSessionId: AgentRuntimeEnrollmentSessionId;
      runtimeProfileId: AgentRuntimeProfileId;
      agentId: AgentId;
      agentIdentityKeyId: AgentIdentityKeyId;
      custodyBindingId: AgentCustodyBindingId;
      walletId: WalletId;
      claimExpiresAtMs: number;
      authorizationId?: never;
    }
  | {
      state: 'provisioning';
      enrollmentSessionId: AgentRuntimeEnrollmentSessionId;
      runtimeProfileId: AgentRuntimeProfileId;
      agentId: AgentId;
      agentIdentityKeyId: AgentIdentityKeyId;
      custodyBindingId: AgentCustodyBindingId;
      walletId: WalletId;
      authorizationId: DelegatedSpendAuthorizationId;
      walletKeyManifestDigestB64u: string;
    }
  | {
      state: 'committed_delivery_required';
      enrollmentSessionId: AgentRuntimeEnrollmentSessionId;
      runtimeProfileId: AgentRuntimeProfileId;
      agentId: AgentId;
      agentIdentityKeyId: AgentIdentityKeyId;
      custodyBindingId: AgentCustodyBindingId;
      walletId: WalletId;
      authorizationId: DelegatedSpendAuthorizationId;
      authorizationDigestB64u: string;
      transcriptSetDigestB64u: string;
    }
  | {
      state: 'active';
      enrollmentSessionId: AgentRuntimeEnrollmentSessionId;
      runtimeProfileId: AgentRuntimeProfileId;
      agentId: AgentId;
      agentIdentityKeyId: AgentIdentityKeyId;
      custodyBindingId: AgentCustodyBindingId;
      walletId: WalletId;
      authorizationId: DelegatedSpendAuthorizationId;
      activatedAtMs: number;
    }
  | {
      state: 'terminated_unclaimed';
      enrollmentSessionId: AgentRuntimeEnrollmentSessionId;
      runtimeProfileId: AgentRuntimeProfileId;
      agentId: AgentId;
      agentIdentityKeyId: AgentIdentityKeyId;
      custodyBindingId: AgentCustodyBindingId;
      reason: 'expired' | 'cli_cancelled';
      terminatedAtMs: number;
      walletId?: never;
      authorizationId?: never;
    }
  | {
      state: 'terminated_claimed_precommit';
      enrollmentSessionId: AgentRuntimeEnrollmentSessionId;
      runtimeProfileId: AgentRuntimeProfileId;
      agentId: AgentId;
      agentIdentityKeyId: AgentIdentityKeyId;
      custodyBindingId: AgentCustodyBindingId;
      walletId: WalletId;
      reason: 'expired' | 'cli_cancelled' | 'owner_denied';
      terminatedAtMs: number;
      authorizationId?: never;
    }
  | {
      state: 'terminated_authorized_precommit';
      enrollmentSessionId: AgentRuntimeEnrollmentSessionId;
      runtimeProfileId: AgentRuntimeProfileId;
      agentId: AgentId;
      agentIdentityKeyId: AgentIdentityKeyId;
      custodyBindingId: AgentCustodyBindingId;
      walletId: WalletId;
      authorizationId: DelegatedSpendAuthorizationId;
      reason: 'expired' | 'cli_cancelled' | 'definitive_provisioning_failure';
      terminatedAtMs: number;
    };
```

Entering `terminated_authorized_precommit` revokes the signed authorization and
cancels or retires every pending target-lane effect before the terminal receipt
commits. No terminal precommit branch can satisfy delegated admission.

The enrollment-created agent identity, identity key, and custody binding begin
in `pending_enrollment` lifecycle branches. Only the aggregate transition to
`active` activates them. Every terminal precommit transition tombstones those
draft records after the audit-retention boundary.

No cancellation or timeout rolls back a committed holder package. At and after
`committed_delivery_required`, the system redelivers the same ciphertexts and
completes receipt accounting. If owner policy cancels the product after that
boundary, Gateway completes delivery accounting and immediately revokes the
authorization and target lanes before admission can use them.

### Approval URL boundary

The URL and equivalent QR encode one canonical payload:

```ts
type AgentRuntimeEnrollmentBootstrapV1 = {
  version: 'v1';
  purpose: 'agent_runtime_enrollment';
  enrollmentSessionId: AgentRuntimeEnrollmentSessionId;
  issuedAtMs: number;
  expiresAtMs: number;
};
```

The parser accepts this exact shape and rejects unknown fields. The high-entropy
session ID resolves the server-held agent public key, HPKE delivery key,
custody declaration, and expiry. The owner surface displays the resolved agent
key fingerprint before claim. The URL carries no wallet identity or secret,
and possession of it grants only the ability to present an unclaimed request.

### Owner approval transcript

One immutable enrollment approval binds:

- enrollment session, runtime profile, agent, identity key, and custody binding;
- exact agent public-key and HPKE delivery-key digests;
- wallet and canonically ordered wallet-key manifest;
- exact signed delegated authorization and digest;
- target lane IDs, first share epochs, holder and server participants;
- participant and authorization binding digests;
- protocol suites, versions, operation ID, idempotency key, and expiry.

The owner trusted surface commits the approval and signed authorization in one
Gateway operation. Each covered wallet key contributes the required owner proof
over the same delegated authorization. Curve-specific lane provisioning also
consumes the exact approval operation and transcript digest. Substituting a
runtime, key, wallet, authorization, participant, lane, or protocol version
invalidates the approval or activation receipt.

### CLI custody and local profile

The default CLI profile root is `~/.seams/agents/<runtime-profile-id>/`.
`profile.json` contains the public active projection. Identity private-key and
holder-package envelopes remain encrypted at rest, with their wrapping key in
the operating system secure keychain. Directories use owner-only permissions;
files use owner read/write permissions. The CLI provides no plaintext file,
command-line argument, environment-variable, export, or stdout fallback for
secret material.

```ts
type ActiveAgentRuntimeProfileProjectionV1 = {
  kind: 'active_agent_runtime_profile_projection_v1';
  runtimeProfileId: AgentRuntimeProfileId;
  enrollmentSessionId: AgentRuntimeEnrollmentSessionId;
  agentId: AgentId;
  agentIdentityKeyId: AgentIdentityKeyId;
  custodyBindingId: AgentCustodyBindingId;
  walletId: WalletId;
  authorizationId: DelegatedSpendAuthorizationId;
  authorizationDigestB64u: string;
  walletKeys: readonly [AgentRuntimeWalletKeyProjectionV1, ...AgentRuntimeWalletKeyProjectionV1[]];
  activatedAtMs: number;
};

type AgentRuntimeWalletKeyProjectionV1 = {
  kind: 'agent_runtime_wallet_key_projection_v1';
  walletKey: AuthorizedWalletKey;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  laneRevocationEpoch: number;
  participantBindingDigestB64u: string;
  materialActivation: MpcMaterialActivationRef;
};
```

The local profile contains no independent lifecycle or policy decision. CLI
status refresh parses the server response once and replaces the public
projection with the exact canonical active or terminal view. Missing local
material makes the runtime unavailable; it never causes reprovisioning,
authorization replacement, or policy widening without fresh owner approval.

## Agent Identity

An identity is a stable agent record with one or more independent keys using the
signer families already supported by Seams. Each authorization names one exact
key.

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
      algorithm: 'ed25519';
      agentIdentityKeyId: AgentIdentityKeyId;
      publicKeyB64u: string;
      publicKeyCompressedB64u?: never;
      lifecycle: AgentIdentityKeyLifecycle;
    }
  | {
      kind: 'agent_identity_key_v1';
      algorithm: 'secp256k1_ecdsa';
      agentIdentityKeyId: AgentIdentityKeyId;
      publicKeyCompressedB64u: string;
      publicKeyB64u?: never;
      lifecycle: AgentIdentityKeyLifecycle;
    };
```

The Ed25519 branch reuses the existing Ed25519 signing and verification stack.
The secp256k1 branch reuses the existing ECDSA stack. Agent keys use independent
key material and distinct domain-separated request messages; they never reuse or
derive from an owner's wallet key.

A future algorithm requires a new union branch, canonical verifier, test
vectors, and custody policy. Refactor 104 adds no signature algorithm or signing
protocol.

Keys are never silently rotated in place. Rotation creates a new key record and
requires fresh owner authorization. Existing authorizations remain bound to the
old key and follow their own expiry or revocation lifecycle.

### Existing signer boundary

Agent request signing uses the existing Ed25519 or secp256k1 signature and
verification primitives. The CLI generates this independent identity key
locally and proves possession during enrollment. The identity key needs no
threshold protocol because it cannot authorize or execute a wallet operation
by itself. It does not become a wallet lane or derive from owner material.
Verification uses the corresponding existing public-key verifier over the
canonical agent request digest.

This reuse is limited to signer machinery. Agent identity, authorization,
budget, replay, and revocation remain separate domains from Wallet Sessions and
owner wallet keys.

## Agent Custody Binding

Identity-key custody and wallet-lane custody are separate records. The R104 MVP
accepts one exact local CLI custody branch:

```ts
type AgentCustodyBindingRecord = {
  kind: 'agent_custody_binding_v1';
  custodyBindingId: AgentCustodyBindingId;
  agentId: AgentId;
  agentIdentityKeyId: AgentIdentityKeyId;
  runtime: 'local_cli';
  runtimeProfileId: AgentRuntimeProfileId;
  signingKeyPossessionProof: AgentSigningKeyPossessionProof;
  encryptionPublicKeyB64u: string;
  encryptionKeyPossessionProof: AgentEncryptionKeyPossessionProof;
  lifecycle: AgentCustodyLifecycle;
};
```

The possession proofs bind one Gateway enrollment challenge, session ID,
runtime profile, agent identity key, and encryption key. OS-keychain
availability is local operational status. It cannot widen scope, bypass owner
approval, or influence admission.

An agent identity can exist without a wallet lane. When an authorization selects
the direct threshold-wallet adapter, its `DelegatedExecutionSigningLaneRecord`
is required and references this custody binding for holder-package delivery.
The existing lane record binds the authorization ID, exact agent identity key,
custody binding, holder and server participants, share epoch, and authorization
digest. The identity key signs requests; the lane share participates only in
wallet execution.

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
  agentIdentityKeyAlgorithm: 'ed25519' | 'secp256k1_ecdsa';
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

### Delegated Authorization Source

Refactor 90's implemented `AuthorizationGrant` remains
`WalletSessionAuthorization`, with its reusable allowance identified by
`MpcWalletSigningQuotaId`. Refactor 104 adds a disjoint authorization-grant
variant while retaining the shared `AuthorizationGrantRef` and
`OperationAuthorizationSource`:

```ts
type DelegatedSpendAuthorizationGrantRefV1 = {
  kind: 'delegated_spend_authorization_grant_v1';
  authorizationId: DelegatedSpendAuthorizationId;
};

type DelegatedSpendAuthorizationGrantV1 = {
  kind: 'delegated_spend_authorization_grant_v1';
  authorizationGrantRef: DelegatedSpendAuthorizationGrantRefV1;
  authorization: SignedDelegatedSpendAuthorizationV1;
  lifecycle: Extract<DelegatedSpendAuthorizationLifecycle, { state: 'active' }>;
  walletSessionId?: never;
  quotaId?: never;
};
```

The grant is built only from the exact owner-signed delegated authorization,
its proof set, and the R104 authorization store. This plan adds
`DelegatedSpendAuthorizationGrantRefV1` and
`DelegatedSpendAuthorizationGrantV1` as disjoint branches of the shared
`AuthorizationGrantRef` and `AuthorizationGrant` unions. Every agent spend uses
the existing `OperationAuthorizationSource.authorization_grant` branch, whose
shared reference must resolve to this exact delegated variant. Verified
step-up evidence cannot replace the owner-signed authorization or the agent's
request signature. Delegated admission carries no `WalletSessionId` or
`MpcWalletSigningQuotaId` alias and reuses the shared `AuthorizedOperationId`
and stable fingerprint machinery only after the delegated grant verifies. Its
shared `AuthorizedOperation.quota` branch is `quota_neutral` with respect to
Wallet Session quota; the R104 delegated budget reservation remains required
and commits atomically in the same Gateway transaction.

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

R104 owns the delegated authorization, budget-claim, and replay-claim ports and
their Gateway D1 transaction boundary. The transaction verifies the exact
delegated authorization source, checks its revocation epoch, claims the stable
replay fingerprint, reserves budget once, creates the `AuthorizedOperation`,
and writes audit linkage atomically before dispatch. A private SigningWorker
stores only cryptographic effect deduplication, presignature or Yao material
consumption, and terminal response replay. Router receives an internally
authenticated command and response and stores no claim state.

The deleted lane-local reservation surface is replaced by the R104-owned claim
integration described above. No legacy parser or alias enters core logic.

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

The stable operation fingerprint covers the wallet key, adapter, normalized
intent, quote binding, final unsigned transaction, destination, amount, and
idempotency semantics. It excludes rotating authorization, delegated budget
claim, Wallet Session, quota, revocation, agent-session, custody-runtime, and
other runtime identities. Those identities are admission inputs and audit
evidence. They never become alternate operation identities. A replay resolves
the same `AuthorizedOperationId` and recorded result without consuming a second
authorization or budget claim.

For direct threshold-wallet execution, the prepared admission is explicit:

```ts
type PreparedDelegatedWalletExecution = {
  kind: 'prepared_delegated_wallet_execution_v1';
  authorizedOperation: Extract<AuthorizedOperation, { lifecycle: 'claimed' }>;
  budgetClaim: Extract<DelegatedBudgetClaimState, { state: 'reserved' }>;
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  laneRevocationEpoch: number;
  participantBindingDigestB64u: LaneParticipantBindingDigestB64u;
  authorizationBindingDigestB64u: string;
  materialActivation: MpcMaterialActivationRef;
  requestDigestB64u: string;
  finalUnsignedTransactionDigestB64u: string;
};
```

The lane fields identify the exact active delegated execution material,
participant set, authorization binding, and revocation fence. They remain
independent from the delegated authorization, budget claim, Wallet Session,
quota, and operation identities.

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
      state: 'expired';
      revocationEpoch: number;
      expiredAtMs: number;
    }
  | {
      state: 'revoked';
      revocationEpoch: number;
      revokedAtMs: number;
      reason: 'owner_revoked' | 'agent_compromise' | 'custody_compromise' | 'policy_replaced';
    };

type DelegatedBudgetLifecycle =
  | {
      state: 'available';
      aggregateCommitted: AtomicAmount;
      aggregateReserved: AtomicAmount;
    }
  | {
      state: 'exhausted';
      aggregateCommitted: AtomicAmount;
      exhaustedAtMs: number;
    };
```

Only `active` authorizations admit new operations. Budget exhaustion commits an
exhausted transition in the delegated budget projection while the authorization
remains `active`. Budget top-up, scope expansion, expiry extension, agent key
rotation, or wallet-key-set change creates a newly signed authorization; it
never mutates the signed claims in place.

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
8. Resolve the shared authorization-grant source to the exact
   `DelegatedSpendAuthorizationGrantV1`.
9. In the R104 durable-owner transaction, atomically claim the stable replay
   identity, reserve delegated budget, and create or replay one
   `AuthorizedOperationId`.
10. Resolve the exact lane ID, share and revocation epochs, participant and
    authorization binding digests, and `MpcMaterialActivationRef` for the direct
    threshold adapter. Construct one `PreparedDelegatedWalletExecution` with
    immutable evidence references.
11. Execute through the selected adapter.
12. Commit the budget and audit receipt on confirmed execution; release only on
    definitive pre-execution failure; retain unknown outcomes for
    reconciliation.

Policy denial performs no share, presignature, or wallet execution work.

## Execution Adapter

The transaction is signed under the owner's existing wallet key. Funds leave
that wallet directly. The chain generally exposes the wallet signature while
Seams retains the agent and owner proofs in audit evidence.

The direct threshold-wallet adapter requires an authorization-bound
`delegated_execution` lane. It gives the agent runtime an incomplete holder
share and Seams a matching policy-controlled server share. Both parties are
required for the wallet signature. The lane is an
execution mechanism keyed by the exact `MpcMaterialActivationRef`; it grants
no authority without a verified active delegated authorization and signed
request. Wallet Session and delegated authorization identities remain separate,
and revoking the delegated source never replaces unrelated owner material.

Refactor 104 ships this direct threshold-wallet adapter only. Additional payment
protocol or chain-specific delegation adapters require separate plans.

## Revocation

Revocation is one fenced operation:

1. Increment the server-canonical authorization revocation epoch and mark the
   authorization revoked.
2. Reject new requests and budget reservations immediately.
3. Stop queued operations that have not crossed an irreversible execution
   boundary.
4. Revoke every delegated-execution lane bound to the authorization and disable
   its server participants.
5. Terminate agent sessions and invalidate warm custody handles.
6. Publish a terminal runtime-profile projection. An online CLI deletes its
   sealed holder material after verifying that receipt; an offline or
   compromised CLI may retain ciphertext and its incomplete share, so security
   relies on the fenced server participant rather than remote deletion.
7. Mark in-flight ambiguous operations `outcome_unknown` for reconciliation.
8. Emit an authorization revocation receipt and affected-operation inventory.

Owner auth methods, canonical wallet material, wallet keys, funds, and unrelated
authorizations remain active. Previously completed transactions remain valid.

## Audit Evidence

One delegated execution audit chain retains:

- enrollment session, owner claim, approval transcript, possession proofs,
  committed-delivery acknowledgement, and activation receipts;
- exact owner-signed authorization bytes and digest;
- exact agent public key and signed request bytes;
- normalized intent, quote, and final transaction digests;
- policy version and decision;
- replay and budget claim IDs and transitions;
- wallet key, execution lane, participants, and epochs;
- wallet signature and execution receipt;
- chain, merchant, or payment receipt;
- denial, revocation, and reconciliation evidence.

Audit projections may omit private commercial data. The retained evidence must
remain sufficient to prove owner authorization, agent authorship, and execution
binding during dispute review.

## Public SDK Surface

```text
createAgentRuntimeEnrollment()
getAgentRuntimeEnrollment()
claimAgentRuntimeEnrollment()
approveAgentRuntimeEnrollment()
cancelAgentRuntimeEnrollment()
acknowledgeAgentRuntimeDelivery()
rotateAgentIdentityKey()
createDelegatedSpendAuthorization()
listDelegatedSpendAuthorizations()
suspendDelegatedSpendAuthorization()
revokeDelegatedSpendAuthorization()
submitAgentSpendRequest()
getDelegatedSpendOperation()
```

Enrollment registration accepts public keys and boundary-validated possession
proofs. It never accepts agent private keys or plaintext holder shares through
ordinary SDK, iframe, callback, CLI output, or logging surfaces. Enrollment
creates the draft agent identity and custody binding; no separate public
identity-registration path bypasses owner approval. Enrollment functions
require the narrow state branch named by the operation.

Agent methods use separate request and result unions from physical-device
linking. No option bag can construct both operations.

The first CLI surface is:

```text
seams agent init
seams agent status
seams agent spend
seams agent request-policy-change
seams agent revoke
```

`seams agent init` prints the approval URL and waits for activation. A policy
change command creates a fresh owner-approval request; it cannot mutate or
widen the active signed authorization locally. Machine-readable output exposes
public identifiers, lifecycle, policy, request, and receipt data only.

## Current Scaffolds To Retain Or Replace

Retain the current `DelegatedExecutionSigningLaneRecord`, participant records,
lane lifecycle, share epoch, material activation, rotation, and fencing
primitives. They already model a lane as execution material bound to an
authorization, agent key, and custody identity.

Delete or replace these dormant lane-owned authority shapes when the new
behavior lands:

- lane-owned `DelegatedMandatePolicy`;
- the old share-holder-oriented `AgentPrincipalId`; replace it with the
  identity-oriented `AgentId`;
- unsigned `DelegatedSigningRequest`;
- lane-derived `DelegatedSigningAuditEvent`;
- broad rotation jobs shared between device and agent enrollment.

R104 adds Gateway authorization records plus durable-owner delegated budget and
replay claim integration. No lane-owned budget authority remains. Retain useful
typed purchase-intent and canonical digest code only after it is adapted to the
signed authorization and request boundaries. Retain curve-agnostic R101/R102
lane records, epochs, participant bindings, material-activation checks,
rotation, and fencing. Do not retain a `LinkedDevice*` dependency for R104.

## Implementation Phases

### Phase 0: Freeze Encodings And CLI Custody

- [ ] Freeze Ed25519 and secp256k1 ECDSA agent-identity signature profiles and
      canonical CBOR encoding.
- [ ] Freeze the enrollment bootstrap, possession-proof, approval-transcript,
      committed-delivery, and active-profile encodings.
- [ ] Freeze the `local_cli` custody branch, `~/.seams/agents` public projection,
      sealed-envelope layout, OS-keychain wrapping, and file permissions.
- [ ] Reuse existing wallet signer protocols, participant topology, nonce
      rules, capability lifecycle, and vectors without adding another wallet
      signing scheme.
- [ ] Freeze direct-wallet owner proof encoding for Ed25519 and secp256k1.
- [ ] Freeze the stablecoin-only MVP scope, budget, fee, and quote policy.
- [ ] Freeze request signature, replay, expiry, and revocation semantics.
- [ ] Freeze the direct threshold-wallet adapter, including its required
      authorization-bound lane and custody topology.

### Phase 1: Runtime Enrollment, Identity, And Authorization

- [ ] Add branded IDs and exhaustive identity/key/custody lifecycles.
- [ ] Add the exhaustive enrollment state, strict URL/QR parser, durable claim
      store, expiry, cancellation, and forward-only delivery recovery.
- [ ] Generate identity and HPKE keys inside the CLI wallet worker and verify
      exact enrollment possession proofs at Gateway.
- [ ] Add the `seams.sh` claim and approval surface with fresh owner
      verification and exact runtime, wallet, policy, and revocation display.
- [ ] Add canonical authorization builder and boundary parser.
- [ ] Verify one exact owner proof per wallet key.
- [ ] Commit the owner approval transcript, signed authorization, target-lane
      manifest, and activation work as one durable operation.
- [ ] Add authorization and enrollment stores and lifecycle transitions.
- [ ] Add negative type fixtures for wallet-key/agent-key substitution.

### Phase 2: Agent Requests And Policy

- [ ] Add Ed25519 and secp256k1 ECDSA agent request verifiers using existing
      verification primitives.
- [ ] Add one specific-purchase intent and merchant-signed quote parser.
- [ ] Verify final unsigned transaction independently.
- [ ] Add authorization scope, expiry, fee, and counterparty admission.

### Phase 3: Budget, Replay, And Audit

- [ ] Implement the R104-owned delegated authorization, budget-claim, and
      replay-claim transaction in Gateway D1 before private worker dispatch.
      Reuse Refactor 90's stable fingerprint and `AuthorizedOperationId`
      primitives; do not write `WalletSessionAuthorization` or Wallet Session
      quota records for delegated authority.
- [ ] Keep budget exhaustion in its own projection while authorization remains
      `active` until suspension, expiry, or revocation.
- [ ] Implement outcome-unknown reconciliation.
- [ ] Persist the complete three-proof audit chain.
- [ ] Add denial and exhaustion projections.

### Phase 4: Direct Wallet Execution

- [ ] Provision one authorization-bound execution lane for each wallet key
      covered by the direct threshold adapter.
- [ ] Encrypt holder packages directly to the enrolled CLI delivery key, verify
      exact committed delivery, seal them locally, and activate the public
      runtime projection only after every child receipt verifies.
- [ ] Bind prepared admission to exact wallet capability execution and
      lane ID, share and revocation epochs, participant and authorization
      binding digests, and `MpcMaterialActivationRef`.
- [ ] Sign from the owner wallet without transferring funds to the agent.
- [ ] Commit budget and execution receipts exactly once.

### Phase 5: Revocation And Operations

- [ ] Implement immediate authorization and lane revocation.
- [ ] Terminate active agent sessions and warm handles, publish the terminal
      profile receipt, and clear local material when the CLI observes it.
- [ ] Add management UI, notifications, and audit export.
- [ ] Add agent-key rotation and policy replacement through a fresh owner
      approval, authorization, and lane provisioning operation.
- [ ] Ship the CLI init, status, spend, policy-change-request, and revoke
      commands with JSON output that contains no secret material.

## Validation

Static fixtures prove:

- enrollment states reject wallet and authorization identities before their
  corresponding claim or commit transitions;
- draft identity, key, and custody records cannot become active outside the
  aggregate enrollment activation transition;
- the bootstrap payload cannot carry wallet, authorization, session, share,
  root, recovery, export, or private-key fields;
- only the `local_cli` custody branch can construct an R104 custody binding;
- an active local profile requires a nonempty set of exact lane and material
  activation projections;
- local projections and diagnostics cannot construct admission or lifecycle
  transitions;
- agent keys cannot construct wallet-key records;
- authorizations require nonempty wallet-key manifests and exact agent keys;
- delegated admissions cannot construct a `WalletSessionAuthorization` or
  consume `MpcWalletSigningQuota` as their authorization source;
- direct-wallet proof sets cannot omit or add wallet keys;
- signed claims cannot be mutated into lifecycle state;
- Ed25519 and secp256k1 ECDSA signatures cannot cross algorithm branches;
- prepared execution cannot carry unverified raw requests;
- direct wallet preparation requires an independent
  `AuthorizedOperationId`, lane ID, share and revocation epochs, participant
  and authorization binding digests, and `MpcMaterialActivationRef`;
- delegated authorization cannot grant export, recovery, or account admin.

Cryptographic tests prove:

- signing-key and encryption-key possession proofs bind the exact enrollment
  challenge, session, runtime profile, agent key, and delivery key;
- holder packages decrypt only under the enrolled CLI delivery key and bind the
  exact authorization, lane, participant set, share epoch, and activation;
- owner proofs verify only over the canonical authorization digest;
- agent signatures verify only over the canonical request digest;
- agent keys and signing state are independent from owner Wallet keys, shares,
  and presignatures;
- wrong agent key, owner key, algorithm, domain separator, or encoding fails;
- modified amount, destination, quote, transaction, expiry, or nonce fails;
- rotating authorization, quota, session, and runtime identities do not alter
  the stable operation fingerprint;
- independent implementations reproduce authorization and request vectors.

Enrollment tests prove:

- an unclaimed session exposes public bootstrap data only and expires without
  creating wallet authority;
- a session can be claimed once by one freshly verified owner operation;
- approval displays and commits the exact agent fingerprint, wallet-key
  manifest, scope, budget, fees, expiry, and revocation consequences;
- runtime, key, wallet, authorization, participant, lane, protocol, ciphertext,
  and receipt substitution fails;
- precommit cancellation creates no active lane;
- every terminal precommit outcome tombstones draft identity and custody records
  and revokes any authorization created before termination;
- postcommit interruption redelivers the same ciphertexts and either activates
  or immediately revokes the exact committed lanes;
- local status refresh cannot widen policy or activate missing material;
- CLI JSON output, errors, callbacks, and logs contain no secret material.

Policy and concurrency tests prove:

- over-budget, expired, suspended, revoked, replayed, and out-of-scope requests
  fail before execution work;
- budget exhaustion changes only the delegated budget projection; the signed
  authorization remains `active`;
- concurrent requests cannot exceed aggregate budget;
- fees count toward the configured aggregate cap;
- transaction substitution fails after valid intent admission;
- unknown execution outcomes retain reservations;
- definitive pre-execution failures release reservations exactly once.

Execution tests prove:

- an authorized purchase spends directly from the owner's wallet;
- the agent owns no prefunded wallet and receives no owner export material;
- owner and delegated lanes use distinct holder/server material while
  preserving the wallet public key and address byte-for-byte;
- the CLI receives no wallet custody seed, owner share, complete wallet key, or
  independently usable signing capability;
- direct threshold delegated execution requires both agent holder and server
  participation;
- owner authorization or agent signature alone cannot execute;
- revoking one authorization preserves owner and unrelated agent spending;
- audit reconstructs owner authorization, agent authorship, and wallet payment.

## Non-Goals

- transferring a spending balance into an agent-owned wallet;
- treating an agent identity key as a wallet key;
- using R103 `LinkedDevice*` records, routes, state machines, receipts, target
  factors, owner-equivalent permissions, or wallet custody-seed transfer for an
  agent;
- making the local runtime profile a canonical authorization, policy, budget,
  replay, or lifecycle store;
- providing plaintext identity-key or holder-share import, export, command-line,
  environment-variable, or file-storage paths;
- relying on prompts or tool arguments as policy evidence;
- supporting arbitrary contract calls in the MVP;
- generic fiat valuation without an explicit oracle policy;
- silent scope expansion, budget top-up, or expiry extension;
- granting export, recovery, membership, or account administration;
- adding another signature scheme or external payment protocol;
- adding chain-native delegated accounts;
- supporting more than the direct threshold-wallet adapter in this refactor.

## Decisions Required Before Implementation

- Select the owner-proof format for each supported wallet key family.
- Select the exact direct-threshold participant topology for each wallet key
  family; the agent holder remains the enrolled `local_cli` runtime.
- Freeze enrollment, claim, approval, and committed-delivery deadlines and the
  supported OS secure-keychain adapters.
- Freeze the first supported stablecoin, networks, merchant quote format, and
  destination identity rules.
- Define how refunds restore budget, if at all, without weakening dispute and
  replay guarantees.
- Define retention and privacy policy for signed commercial evidence.
