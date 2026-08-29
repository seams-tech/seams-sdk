# Agent Runtime Enrollment And Delegated Spending

Date created: July 22, 2026

Last reconciled: August 29, 2026 (exact owner admission, delegated grant typing,
and R102 delivery/activation boundaries)

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
The owner signing path for each covered `WalletKeyRecord` produces a proof over
the authorization for that agent key.
One incomplete delegated-execution holder share is delivered to the CLI for
each covered wallet key; the wallet custody seed never leaves owner custody.
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
address, prefunded balance, or canonical owner. Each lane uses fresh,
R102-provisioned lane-holder and SigningWorker participant shares that preserve
the existing wallet public key. A delegated lane holder share is not
seed-derived and never enters a recovery set. The agent identity key remains a
separate request-authorship key.

## Dependencies And Authority

This plan consumes:

- [refactor-90-modular-auth-capabilities-plan.md](./refactor-90-modular-auth-capabilities-plan.md)
  and its SPEC for authorization resources, exact operation fingerprints,
  `AuthorizedOperationId`, `MpcMaterialActivationRef`, Wallet Session
  boundaries, effect ordering, replay handling, and audit. Refactor 104 owns
  the delegated authorization, budget, and replay stores that supply its own
  authorization source;
- [refactor-103F-final-cutover.md](./refactor-103F-final-cutover.md) for the
  exact-only owner-operation boundary: `WalletSessionAuthorizationV2`, exact
  `WalletAuthorityId` and `WalletAuthMethodId` selection,
  `WalletSessionOperationCredentialV1`, `ExactV2AdmissionContext`, and the
  final removal of fallback owner admission;
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

[refactor-109D-multi-auth-linking.md](./refactor-109D-multi-auth-linking.md)
owns linked-device authorities and methods.
[refactor-115-recover-multiauth.md](./refactor-115-recover-multiauth.md) owns
additive owner recovery. R104 consumes neither model: agent enrollment creates
no linked authority or auth method, and delegated lane holder shares never
enter owner recovery sets.

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

R103F owns the exact owner-operation admission used to approve and administer
an agent authorization. R109D owns physical linked-device authority, and R115
owns additive owner recovery. None of those plans owns agent identity,
delegated policy, budget, replay, or execution-lane product state.

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
   identity key equals a `WalletKeyRecord` public key or derives from the wallet
   custody seed, an owner signing root, or wallet-lane participant material.
2. An agent receives no wallet custody seed, owner signing root, owner-lane
   holder share, complete wallet signing key, export capability, recovery
   authority, or account-admin authority.
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
22. Claim, approval, policy replacement, suspension, and revocation enter
    through R103F's exact owner-operation boundary. The server records the exact
    active `WalletAuthorityId`, `WalletAuthMethodId`, authority digest and
    revocation epoch, and owner `AuthorizedOperationId` used for the action.
23. Exact owner-operation admission and the wallet-key proof set are distinct
    proofs. Neither substitutes for the other.
24. A delegated authorization grant cannot construct an
    `OwnerOperationAuthorizationSource`, consume Wallet Session quota, or admit
    export, recovery, linking, membership, or account-administration work.
25. Gateway product-state transactions never claim atomicity with private
    SigningWorker D1. Cross-store lane provisioning and activation use durable,
    idempotent effects and exact verified receipts.
26. A committed holder package is redelivered only as the same ciphertext to
    the same enrolled delivery key. Loss of the corresponding private key
    requires authorization and lane revocation followed by fresh owner-approved
    enrollment.

## Trust Boundaries

### Owner trusted surface

- authenticates the owner with fresh user verification through R103F's exact
  owner-operation boundary;
- atomically claims one short-lived unclaimed agent enrollment session;
- resolves and records the exact active authority, auth method, authority
  digest and revocation epoch, and owner authorized-operation identity;
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
- owns its independent agent identity private key;
- protects the key in its declared custody runtime;
- constructs typed intents from untrusted tool output;
- signs concrete request envelopes;
- holds an incomplete lane-specific MPC share only when an active authorization
  selects the direct threshold adapter;
- seals identity and holder material locally and exposes only public profile,
  request, status, and receipt data to the calling agent framework;
- never receives the wallet custody seed, an owner signing root, an owner-lane
  holder share, a complete wallet signing key, or an export-capable share.

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

### Private SigningWorker persistence

- owns private delegated-lane participant material, ciphertext, effect replay,
  and signing-effect receipts;
- accepts only an internally authenticated command that names committed Gateway
  product state and exact material activation;
- cannot create delegated identity, authorization, policy, budget, or replay
  rights; and
- completes Gateway-authored provisioning and revocation intents through
  idempotent effects. Gateway publishes product activation only after verifying
  every required private-worker and holder-delivery receipt.

### Wallet execution participants

- accept only committed prepared admission from the Router;
- for direct threshold execution, verify the exact wallet key, lane,
  participants, epochs, authorization, request, and transaction digests;
- sign no broader payload than the admitted final transaction;
- expose no owner signing root, owner-lane holder share, or export path to the
  agent runtime.

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
  -> claim the session through exact owner admission after fresh user verification
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
    }
  | {
      state: 'terminated_postcommit';
      enrollmentSessionId: AgentRuntimeEnrollmentSessionId;
      runtimeProfileId: AgentRuntimeProfileId;
      agentId: AgentId;
      agentIdentityKeyId: AgentIdentityKeyId;
      custodyBindingId: AgentCustodyBindingId;
      walletId: WalletId;
      authorizationId: DelegatedSpendAuthorizationId;
      authorizationDigestB64u: string;
      transcriptSetDigestB64u: string;
      reason:
        | 'owner_cancelled'
        | 'delivery_deadline_expired'
        | 'recipient_key_lost'
        | 'activation_receipt_rejected';
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

Redelivery retains the original `AgentCustodyBindingId`, HPKE recipient key,
authorization, target-lane manifest, and ciphertext digest. It cannot rewrap or
regenerate a committed package for a replacement recipient. If the CLI loses
the delivery private key, identity private key, or sealed delegated holder
material, the enrollment enters `terminated_postcommit`; Gateway revokes the
authorization and every target lane, and the owner starts a fresh enrollment.
Delegated lane holder shares are per-lane execution material, are not
seed-derived, and never enter R115 recovery.

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

### Exact owner administration operations

R104 adds one narrow owner-administration capability and exact operation kinds
for its state-changing owner actions:

```ts
const DELEGATED_SPEND_ADMIN_OPERATION_KINDS = {
  claimEnrollment: 'delegated_spend.claim_enrollment',
  approveAuthorization: 'delegated_spend.approve_authorization',
  suspendAuthorization: 'delegated_spend.suspend_authorization',
  revokeAuthorization: 'delegated_spend.revoke_authorization',
  replaceAuthorization: 'delegated_spend.replace_authorization',
} as const;

type DelegatedSpendAdminOperationRef = {
  readonly capabilityKind: 'delegated_spend_administration';
  readonly operationKind: DelegatedSpendAdminOperationKind;
};

type DelegatedSpendAdminOperationKind =
  (typeof DELEGATED_SPEND_ADMIN_OPERATION_KINDS)[keyof typeof DELEGATED_SPEND_ADMIN_OPERATION_KINDS];
```

The shared capability-kind, operation-kind, parser, envelope, fingerprint, and
owner-operation unions gain those exact branches. They carry no spend execution
right. The MVP requires fresh verified owner step-up for every state-changing
R104 administration operation. Its boundary resolver emits the exact active
authority and auth method required by R103F; an R104 route cannot accept a
delegated grant as its owner authorization source. Suspension is one-way for
the signed authorization: resuming the product creates a replacement
authorization through fresh owner approval.

### Owner approval transcript

One immutable enrollment approval binds:

- enrollment session, runtime profile, agent, identity key, and custody binding;
- exact owner `WalletAuthorityId`, `WalletAuthMethodId`, authority digest and
  revocation epoch, and claim and approval `AuthorizedOperationId` values;
- exact agent public-key and HPKE delivery-key digests;
- wallet and canonically ordered wallet-key manifest;
- exact signed delegated authorization and digest;
- target lane IDs, first share epochs, holder and server participants;
- participant and authorization binding digests;
- protocol suites, versions, operation ID, idempotency key, and expiry.

The claim, approval, policy replacement, suspension, and revocation are exact
owner operations. The MVP requires fresh verified step-up for approval; R103F
resolves that proof to the exact active authority and auth method before the
Gateway operation can commit. Each covered wallet key then contributes the
required owner proof over the same delegated authorization. Exact owner
admission proves who approved the administrative action; the wallet-key proof
set proves authorization for every wallet key in the manifest.

Gateway atomically commits the approval transcript, signed authorization,
target-lane manifest, and durable provisioning-effect intent in its product
store. Curve-specific SigningWorker provisioning consumes the exact approval
operation and transcript digest through idempotent private effects. Gateway
publishes activation only after verifying the resulting private-worker and
holder-delivery receipts; no transaction spans Gateway D1 and private
SigningWorker D1. Substituting a runtime, key, wallet, authority, auth method,
authorization, participant, lane, protocol version, effect, or receipt
invalidates approval or activation.

The recorded owner authority and auth method serve as immutable approval
provenance. Ongoing delegated admission resolves the signed authorization,
wallet-key state, budget, replay state, and lane activation. Removing an
unrelated owner auth method does not mutate an already active signed delegated
authorization. Owner revocation of the authorization, wallet-key retirement or
compromise, policy replacement, expiry, and lane fencing remain explicit
lifecycle events.

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
authorization replacement, recovery, or policy widening. Key or holder-material
loss requires server-side revocation and fresh owner-approved enrollment.

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
key material and distinct domain-separated request messages. They never reuse or
derive from the wallet custody seed, owner signing roots, or wallet-lane
participant material.

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
by itself. It does not become a wallet lane or derive from the wallet custody
seed, owner signing roots, or wallet-lane participant material.
Verification uses the corresponding existing public-key verifier over the
canonical agent request digest.

This reuse is limited to signer machinery. Agent identity, authorization,
budget, replay, and revocation remain separate domains from Wallet Sessions and
`WalletKeyRecord` identities.

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
digest. The identity key signs requests; the delegated lane holder share
participates only in wallet execution. That holder share is per-lane R102
material, is not derived from the wallet custody seed, and is excluded from
every owner recovery set.

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

The implemented shared seam consists of `AUTHORIZATION_GRANT_KINDS`,
`AuthorizationGrantRef`, `parseAuthorizationGrantRef`,
`OperationAuthorizationSource`, and `AuthorizedOperationInput`. After R103F,
the Wallet Session branch resolves only an exact
`WalletSessionAuthorizationV2`; reusable signing through that branch continues
to require its `MpcWalletSigningQuotaId`.

R104 extends the shared grant-kind constant, reference union, and boundary
parser with one disjoint reference. The resolved delegated grant is a
server-only R104 authorization-store result rather than a client-constructible
general grant record:

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

The grant resolver builds this record only from the exact owner-signed
delegated authorization, its complete wallet-key proof set, and the active R104
authorization-store row. Client input supplies only the parsed reference.
Verified step-up evidence cannot replace the owner-signed authorization or the
agent request signature.

Delegated authority is an authorization source for existing exact wallet
signing capabilities. It adds no generic capability or arbitrary-operation
escape hatch. The MVP admits only the existing NEAR and EVM transaction-signing
operation kinds:

```ts
type DelegatedSpendOperationRef =
  | (Extract<
      CapabilityOperationRef,
      { readonly capabilityKind: 'near_ed25519_mpc_signing' }
    > & { readonly operationKind: 'near.sign_transaction' })
  | (Extract<
      CapabilityOperationRef,
      { readonly capabilityKind: 'evm_ecdsa_mpc_signing' }
    > & { readonly operationKind: 'evm.sign_transaction' });

type DelegatedSpendAuthorizationSourceV1 = {
  readonly kind: 'authorization_grant';
  readonly authorizationGrantRef: DelegatedSpendAuthorizationGrantRefV1;
  readonly evidenceSetDigest?: never;
};

type DelegatedAuthorizedOperationInputV1 = {
  readonly tenantId: TenantId;
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly auditEventId: AuthorizationAuditEventId;
  readonly claimedAtMs: number;
  readonly operation: CapabilityOperationEnvelope<DelegatedSpendOperationRef>;
  readonly authorization: DelegatedSpendAuthorizationSourceV1;
  readonly quota: { readonly kind: 'quota_neutral'; readonly quotaId?: never };
};
```

`AuthorizedOperationInput` gains that exact branch. Its Wallet Session signing
branch remains paired with `consume_reusable_wallet_session`; a delegated grant
cannot enter that branch, and a Wallet Session signing grant cannot enter the
delegated `quota_neutral` branch. `OwnerOperationAuthorizationSource` remains
restricted to an exact Wallet Session grant or verified owner step-up and can
never carry a delegated grant reference. Export, NEP-413 signing, NEAR delegate
actions, vault work, device linking, recovery, membership, and administration
remain unrepresentable through delegated admission.

Delegated admission carries no `WalletSessionId` or
`MpcWalletSigningQuotaId` alias. It reuses `AuthorizedOperationId` and stable
operation-fingerprint machinery only after the delegated grant resolves. Its
shared `AuthorizedOperation.quota` branch is `quota_neutral` with respect to
Wallet Session quota; the separate R104 delegated budget and replay claims
remain mandatory and commit atomically with the authorized-operation claim in
one Gateway D1 transaction.

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
claim, Wallet Session, quota, revocation, enrollment-session, custody-runtime,
and other runtime identities. Those identities are admission inputs and audit
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
8. Require the delegated `AuthorizationGrantRef` branch and resolve it to the
   exact active `DelegatedSpendAuthorizationGrantV1`; reject every Wallet
   Session, verified-step-up, export, and unsupported operation-kind branch.
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
and revoking the delegated source never replaces unrelated owner signing roots
or signing lanes.

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
5. Reject reuse of cached local custody handles for new work and close optional
   transport connections. Neither is an authorization source or security
   fence.
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

The cutover inventory is authoritative:

| Current surface | Action | R104 final ownership |
| --- | --- | --- |
| `packages/shared-ts/src/signing-lanes/records.ts` and `recordParsers.ts` | Retain `DelegatedExecutionSigningLaneRecord`, its exact parser, participant binding, epoch, lifecycle, and fencing branches. Extend only where the final authorization and custody bindings require it. | Execution-material record; no identity, policy, budget, replay, or recovery authority. |
| `packages/shared-ts/src/signing-lanes/records.typecheck.ts` | Retain valid lane-shape fixtures and add invalid authorization, agent-key, custody, participant, and lane-kind combinations. | Static ownership of the final lane union. |
| `packages/shared-ts/src/signing-lanes/execution.ts` and `execution.typecheck.ts` | Keep the shared owner and linked execution branches. Replace the dormant delegated `ReservedDelegatedBudgetClaim` and `PreparedDelegatedWalletExecution` branch with the final R104 Gateway-owned budget claim and exact prepared-admission shape. | Shared execution envelope consumes already claimed authorization and budget evidence; it creates neither. |
| `packages/shared-ts/src/signing-lanes/policies.ts` | Delete `DelegatedMandatePolicy`, the broad old `AgentCustodyBindingRecord`, managed-service/TEE/HSM/customer-runtime branches, allowance policy, and lane-owned budget authority. Retain simple descriptors only if their final parsed R104 types use them directly. | `DelegatedSpendAuthorizationV1`, `DelegatedSpendScopeV1`, `SingleAssetDelegatedBudgetV1`, and `AgentCustodyBindingRecord` live in R104-owned modules. |
| `packages/shared-ts/src/signing-lanes/intents.ts` | Delete unsigned `DelegatedSigningRequest`, lane-derived `DelegatedSigningAuditEvent`, `AllowanceGrantIntent`, and the broad `DelegatedSigningIntent` union. Adapt useful asset, address, counterparty, amount, purchase-intent, and digest primitives to the signed request and exact boundary parser. | R104 signed request, policy, and audit modules own agent intent and authorship. |
| `packages/shared-ts/src/utils/domainIds.ts`, `signing-lanes/ids.ts`, and their type fixtures | Replace share-holder-oriented `AgentPrincipalId` and its parser with identity-oriented `AgentId`; keep existing lane, wallet-key, authorization, and material IDs whose meanings remain exact. | Agent identity owns `AgentId`; lane IDs remain execution identities. |
| `packages/wallet/src/SeamsWeb/operations/delegation/*` and `packages/wallet/src/core/signingEngine/session/lanes/lanePolicy.ts` | Delete dormant mandate re-exports and convert any retained purchase-intent digest helper to the canonical R104 request boundary. | Owner approval UI consumes R104 public types; wallet lane code owns no delegated policy. |
| `packages/wallet/src/core/signingEngine/session/lanes/walletExecutionLaneHydration.ts` | Keep owner and linked behavior. Add a dedicated delegated hydration/admission function that requires the active delegated lane, authorization binding, participant digest, epochs, and exact material activation. Do not widen the linked-device-only rotatable hydrator into a shared product flow. | Curve-agnostic lane hydration; R104 authorization resolves before invocation. |
| `packages/shared-ts/src/signing-lanes/rotation.ts`, `rotationParsers.ts`, `rotationDigests.ts`, and `rotationLifecycle.ts` | Retain curve-agnostic delegated lane rotation, revocation, epoch, receipt, and parser machinery. Split only branches that currently assume linked-device enrollment state or identity. | R102 execution-material rotation; R104 initiates it from authorization or custody lifecycle events. |
| `packages/shared-ts/src/signing-lanes/index.ts` and wallet re-exports | Remove exports for deleted scaffolds and export only the final R104 public types from their owning modules. | One public definition per final concept. |

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
- [ ] Freeze exact owner claim, approval, replacement, suspension, and
      revocation operation bindings, including the authority, auth method,
      authority digest and revocation epoch, and owner `AuthorizedOperationId`.
- [ ] Freeze the `delegated_spend_administration` capability and its exact
      claim, approve, suspend, revoke, and replace operation kinds. Every MVP
      mutation requires fresh verified owner step-up; suspension resumes only
      through replacement.
- [ ] Freeze the direct threshold-wallet adapter, including its required
      authorization-bound lane and custody topology.

### Phase 1: Runtime Enrollment, Identity, And Authorization

- [ ] Add branded IDs and exhaustive identity/key/custody lifecycles.
- [ ] Add the exhaustive enrollment state, strict URL/QR parser, durable claim
      store, expiry, cancellation, and forward-only delivery recovery.
- [ ] Add the `terminated_postcommit` branch and committed-recipient-loss rule.
      Redelivery must retain the original recipient, manifest, and ciphertext;
      private-key or sealed-holder-material loss revokes the authorization and
      lanes and requires fresh enrollment.
- [ ] Generate identity and HPKE keys inside the CLI wallet worker and verify
      exact enrollment possession proofs at Gateway.
- [ ] Add the `seams.sh` claim and approval surface with fresh owner
      verification through R103F exact owner admission and exact runtime,
      wallet, policy, and revocation display.
- [ ] Add the exact delegated-spend administration capability-operation refs,
      parsers, fingerprints, and owner-operation union branches. Keep all of
      them unavailable to delegated spend grants.
- [ ] Record the exact owner authority, auth method, authority digest and
      revocation epoch, and authorized-operation identity in the approval
      transcript and audit chain.
- [ ] Add canonical authorization builder and boundary parser.
- [ ] Verify one exact owner proof per wallet key.
- [ ] Add `delegated_spend_authorization_grant_v1` to
      `AUTHORIZATION_GRANT_KINDS`, `AuthorizationGrantRef`, and the exact
      boundary parser, plus the server-only active-grant resolver.
- [ ] Commit the owner approval transcript, signed authorization, target-lane
      manifest, and durable provisioning-effect intent in one Gateway
      transaction. Execute private SigningWorker provisioning idempotently and
      publish activation only after exact aggregate receipts verify.
- [ ] Add authorization and enrollment stores and lifecycle transitions.
- [ ] Add negative type fixtures for wallet-key/agent-key and exact owner
      authority/auth-method substitution.

### Phase 2: Agent Requests And Policy

- [ ] Add Ed25519 and secp256k1 ECDSA agent request verifiers using existing
      verification primitives.
- [ ] Add one specific-purchase intent and merchant-signed quote parser.
- [ ] Map delegated MVP admission only to existing `near.sign_transaction` and
      `evm.sign_transaction` capability-operation branches. Add no generic
      delegated capability kind.
- [ ] Verify final unsigned transaction independently.
- [ ] Add authorization scope, expiry, fee, and counterparty admission.

### Phase 3: Budget, Replay, And Audit

- [ ] Implement the R104-owned delegated authorization, budget-claim, and
      replay-claim transaction in Gateway D1 before private worker dispatch.
      Reuse Refactor 90's stable fingerprint and `AuthorizedOperationId`
      primitives; do not write `WalletSessionAuthorizationV2` or Wallet Session
      quota records for delegated authority.
- [ ] Restructure `AuthorizedOperationInput` by grant kind: exact Wallet Session
      signing continues to require `consume_reusable_wallet_session`; exact
      delegated transaction signing requires the delegated grant reference and
      `quota_neutral`. Keep `OwnerOperationAuthorizationSource` unable to carry
      the delegated reference.
- [ ] Add type fixtures rejecting delegated-plus-Wallet-Session-quota,
      Wallet-Session-signing-plus-`quota_neutral`, delegated export, delegated
      NEP-413/delegate-action, and delegated owner/admin operation combinations.
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
- [ ] Persist Gateway product state and private SigningWorker material in their
      existing stores. Drive provisioning, activation, and revocation across
      them with durable idempotent effects and verified receipts; add no
      cross-store transaction abstraction.
- [ ] Bind prepared admission to exact wallet capability execution and
      lane ID, share and revocation epochs, participant and authorization
      binding digests, and `MpcMaterialActivationRef`.
- [ ] Sign from the owner wallet without transferring funds to the agent.
- [ ] Commit budget and execution receipts exactly once.

### Phase 5: Revocation And Operations

- [ ] Implement immediate authorization and lane revocation.
- [ ] Reject cached custody-handle reuse, close optional transport connections,
      publish the terminal profile receipt, and clear local material when the
      CLI observes it. Authorization revocation and server-participant fencing
      remain the enforcement controls.
- [ ] Handle active-runtime identity-key, delivery-key, or sealed-holder loss by
      revoking the affected authorization and lanes and requiring fresh exact
      owner approval; add no delegated-share recovery path.
- [ ] Add management UI, notifications, and audit export.
- [ ] Add agent-key rotation and policy replacement through a fresh owner
      approval, authorization, and lane provisioning operation.
- [ ] Ship the CLI init, status, spend, policy-change-request, and revoke
      commands with JSON output that contains no secret material.

### Phase 6: Scaffold Cutover And Closure

- [ ] Replace `AgentPrincipalId` with `AgentId` in domain IDs, signing-lane IDs,
      policies, intents, parsers, and type fixtures; delete the old brand and
      parser.
- [ ] Delete `DelegatedMandatePolicy`, the superseded broad custody record and
      runtime branches, allowance-grant policy, and their wallet re-exports.
- [ ] Replace unsigned `DelegatedSigningRequest`, lane-derived
      `DelegatedSigningAuditEvent`, `AllowanceGrantIntent`, and the dormant
      delegated execution/budget-claim shapes with the final signed request,
      Gateway claim, prepared admission, and audit evidence.
- [ ] Add the dedicated delegated lane hydrator. Preserve owner and linked
      hydration behavior and keep R102 rotation, epoch, participant, receipt,
      and fencing primitives shared only where their inputs are product-neutral.
- [ ] Update retained type fixtures and focused behavioral tests to the final
      types. Delete tests, fixtures, helpers, and source guards that exist only
      for the superseded lane-owned authority model.
- [ ] Remove obsolete exports and run final searches for `AgentPrincipalId`,
      `DelegatedMandatePolicy`, `DelegatedSigningRequest`,
      `DelegatedSigningAuditEvent`, `AllowanceGrantIntent`, broad agent custody
      runtimes, and delegated use of `LinkedDevice*` product state. Every hit
      must be an intentional final type, migration/persistence boundary, or
      historical plan reference.
- [ ] Run the narrow type fixtures and delegated enrollment, policy,
      concurrency, execution, recipient-loss, and revocation tests, then the
      repository typecheck and architecture checks.

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
- delegated admissions cannot construct a `WalletSessionAuthorizationV2` or
  consume `MpcWalletSigningQuota` as their authorization source;
- delegated signing cannot use `consume_reusable_wallet_session`, and Wallet
  Session signing cannot use the delegated `quota_neutral` branch;
- delegated grant references cannot construct an
  `OwnerOperationAuthorizationSource`;
- delegated admission cannot construct export, NEP-413, delegate-action, vault,
  device-linking, recovery, membership, or administration operations;
- R104 owner administration accepts only the exact verified-owner-step-up
  source and rejects Wallet Session and delegated grant references in the MVP;
- direct-wallet proof sets cannot omit or add wallet keys;
- owner authority, auth method, authority digest or revocation epoch, and owner
  authorized-operation substitution fails before approval commits;
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
- agent keys and signing state are independent from the wallet custody seed,
  owner signing roots, wallet-lane participant material, and presignatures;
- wrong agent key, wallet-key proof, algorithm, domain separator, or encoding
  fails;
- modified amount, destination, quote, transaction, expiry, or nonce fails;
- rotating authorization, delegated budget claim, replay claim, enrollment, and
  runtime identities do not alter the stable operation fingerprint;
- independent implementations reproduce authorization and request vectors.

Enrollment tests prove:

- an unclaimed session exposes public bootstrap data only and expires without
  creating wallet authority;
- a session can be claimed once by one freshly verified owner operation;
- claim and approval resolve the exact active owner authority and auth method;
  fallback, revoked, stale-epoch, or mismatched owner contexts fail;
- approval displays and commits the exact agent fingerprint, wallet-key
  manifest, scope, budget, fees, expiry, and revocation consequences;
- runtime, key, wallet, authorization, participant, lane, protocol, ciphertext,
  and receipt substitution fails;
- precommit cancellation creates no active lane;
- every terminal precommit outcome tombstones draft identity and custody records
  and revokes any authorization created before termination;
- postcommit interruption redelivers the same ciphertexts and either activates
  or immediately revokes the exact committed lanes;
- postcommit delivery-recipient substitution and ciphertext regeneration fail;
  loss of the original recipient private key terminates the enrollment, revokes
  its authorization and lanes, and requires fresh owner approval;
- Gateway retry and private SigningWorker retry converge through the same
  provisioning effects and receipts without cross-store transaction claims;
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
- owner and delegated lanes use distinct per-lane holder and SigningWorker
  participant material while preserving the wallet public key and address
  byte-for-byte;
- the CLI receives no wallet custody seed, owner signing root, owner-lane holder
  share, complete wallet signing key, or independently usable signing
  capability;
- direct threshold delegated execution requires both agent holder and server
  participation;
- owner authorization or agent signature alone cannot execute;
- revoking one authorization preserves owner and unrelated agent spending;
- audit reconstructs owner authorization, agent authorship, and wallet payment.

## Non-Goals

- transferring a spending balance into an agent-owned wallet;
- treating an agent identity key as a wallet key;
- using R109D `LinkedDevice*` records, linked authorities or auth methods,
  routes, state machines, receipts, target factors, owner-equivalent
  permissions, or wallet custody seed transfer for an agent;
- placing a delegated lane holder share in R115 recovery or rewrapping a
  committed holder package to a replacement recipient;
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
