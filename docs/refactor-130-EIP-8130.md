# Refactor 130 — Base Vibenet EIP-8130 Smart Accounts

Status: future/inactive. Current product uses normal threshold ECDSA owner
addresses for Tempo and EVM-family signing. Smart-account code has been removed
from the active SDK, server, config, persistence, and test surface. This plan
does not describe current behavior and must not add active code paths, public
API fields, config fields, database tables, or tests until the feature is
explicitly reintroduced.

Date created: August 25, 2026

Status after approval: planned Vibenet-only implementation. EIP-8130 is a draft,
Base Vibenet is an experimental devnet, and the current reference contracts and
client API remain unsuitable for production funds.

## Goal

Give each newly registered Vibenet wallet a deterministic EIP-8130 smart-account
address controlled by its existing Router A/B threshold ECDSA owner. The account
stays counterfactual until its first transaction, deploys through the canonical
Vibenet account configuration, sends a second native EIP-8130 transaction, and
supports an atomic owner-actor rotation that preserves the smart-account address.

The first demonstrated path is:

```text
register wallet
  -> activate threshold ECDSA owner
  -> derive counterfactual Vibenet account
  -> fund counterfactual address from the Vibenet faucet
  -> first native 0x79 send deploys the account
  -> verify code and owner actor onchain
  -> second native 0x79 send uses the deployed account
  -> provision replacement threshold ECDSA owner
  -> authorize replacement and revoke old owner atomically
  -> verify the same account address signs through the replacement owner
  -> prove the retired owner is rejected
```

Effectiveness comes first. Session keys, payers, DKIM recovery, ERC-4337,
EIP-7702 upgrades, and production-chain rollout begin only after this operating
path works once and its onchain postconditions are verified.

## Decision

1. Add Base Vibenet as one explicit native EIP-8130 chain target:
   - network slug: `base-vibenet`;
   - chain ID: `84538453`;
   - RPC: `https://rpc.vibes.base.org`;
   - execution profile: `eip8130_native`.
2. Create a fresh no-EOA smart account for each wallet. Do not upgrade the
   threshold owner EOA through EIP-7702. A no-EOA address lets an onchain actor
   rotation retire the old owner without preserving address-bound EOA authority.
3. Use the canonical immutable Vibenet account implementation with its ERC-1167
   per-wallet instance (`upgradeable: false` in the current builder API). Seams
   does not deploy the shared Keystore, canonical authenticators, or account
   implementation. Upgrade governance adds no value to this first slice.
4. Keep deployment lazy. Registration persists the deterministic address and
   exact create change. The first account transaction performs deployment.
5. Use the existing threshold secp256k1 key as the initial unrestricted admin
   actor. Existing Router A/B derivation, SigningWorker material, presignatures,
   Wallet Sessions, and operation authorization remain the signing authority.
6. Support ordered nonce key `0` only. Parallel nonce keys and nonce-free mode
   remain outside the first implementation.
7. Self-pay from a faucet-funded counterfactual address. ERC-8168 payer support
   remains outside the first implementation.
8. Broadcast native type-`0x79` transactions directly with
   `eth_sendRawTransaction`. No bundler or transaction relayer participates in
   normal Vibenet signing.
9. Pin the EIP-8130 client implementation to one reviewed commit. Do not depend
   on a floating branch or reproduce changing wire formats in several modules.
10. Treat Vibenet as disposable test infrastructure. No production or durable
    availability claim depends on it.

## Scope

### Included

- Vibenet chain configuration and capability resolution;
- counterfactual smart-account derivation from a canonical deployment and
  threshold ECDSA initial actor;
- one durable smart-account record per wallet and chain;
- native EIP-8130 transaction hashing, threshold signing, serialization, direct
  broadcast, receipt parsing, and readback;
- lazy account creation on the first send;
- ordinary calls after deployment;
- config-only actor changes;
- replacement threshold ECDSA key provisioning and atomic owner rotation;
- account sync and recovery synchronization of public smart-account facts;
- secure confirmation for calls, deployment, and authority changes;
- deterministic vectors, type fixtures, focused behavior tests, and one live
  Vibenet smoke path.

### Excluded

- Base Sepolia, Base mainnet, Ethereum, Arc, Tempo, and other chains;
- ERC-4337 EntryPoint, bundlers, paymasters, and portable account deployment;
- EIP-7702 delegated EOAs and migration of existing EOA balances or approvals;
- ERC-8168 payer services and token-denominated gas;
- passkey, P-256, delegate, policy, session-key, and sponsor actors;
- custom account implementations and account-code upgrades;
- DKIM, email, guardian, and social recovery;
- multichain actor-change replay;
- parallel and nonce-free transaction lanes;
- production rollout, production funds, audit claims, or stable public API
  guarantees for the draft protocol.

These exclusions remove complete concepts. They must not leave dormant flags,
placeholder tables, unused request fields, or compatibility branches.

## Existing Architecture

Current EVM-family custody has one canonical key identity:

```text
WalletId
  -> EvmFamilyWalletKeyRecord
  -> threshold secp256k1 public key
  -> threshold owner EOA address
  -> target-specific signing session and nonce lane
```

`EvmFamilyWalletKeyRecord.evmAddress` currently names the threshold owner
address. `EvmAdapter` accepts only `kind: 'eip1559'`, hashes that envelope, asks
the threshold signer for one secp256k1 digest signature, and serializes a signed
EIP-1559 transaction. The public execution lifecycle broadcasts the resulting
bytes directly through `eth_sendRawTransaction`.

Refactor 130 keeps that canonical threshold-key identity. It adds account
indirection above it:

```text
WalletId
  -> EvmSmartAccountRecord
       accountAddress --------------> public wallet address on Vibenet
       activeOwnerWalletKeyId ------> EvmFamilyWalletKeyRecord
                                         thresholdOwnerAddress
                                         threshold key and signing lanes
```

The smart account consumes the threshold owner as an actor. It never becomes
the source of threshold ECDSA readiness, key selection, custody material, or
lane activation.

## Vocabulary

- **threshold owner address** — the address derived from the active threshold
  secp256k1 public key. It authenticates as a k1 actor.
- **smart-account address** — the deterministic CREATE2 account address users
  fund and applications display on Vibenet.
- **account implementation** — canonical shared runtime logic referenced by
  each wallet's small deployed account instance.
- **account configuration** — the canonical Vibenet Keystore state containing
  actor authorization, sequence, and lock facts.
- **create plan** — the immutable user salt, runtime code, initial actors, and
  derived address required to create one counterfactual account.
- **owner rotation** — one admin-authorized change that authorizes a replacement
  threshold owner actor and revokes the previous actor.
- **custody-share refresh** — replacement of incomplete off-chain shares while
  preserving the same threshold public key. It changes no actor.

Do not name the smart-account address `evmAddress`, `ownerAddress`, or
`thresholdAddress`. Do not name the threshold owner address `accountAddress`.

## Domain Model

### Chain execution profile

Resolve raw chain configuration once into a precise internal union:

```ts
type EvmExecutionProfile =
  | {
      readonly kind: 'eip1559_eoa';
      readonly chainTarget: EvmEip155ChainTarget;
    }
  | {
      readonly kind: 'eip8130_native';
      readonly chainTarget: EvmEip155ChainTarget;
      readonly deployment: Eip8130CanonicalDeployment;
    };
```

`base-vibenet` resolves to `eip8130_native`. Existing supported EVM networks
resolve to `eip1559_eoa`. Core signing functions require the relevant branch.
They do not accept optional deployment fields or infer protocol support from a
successful RPC call.

The Vibenet deployment parser validates every required canonical address and
code hash at the configuration boundary. No caller supplies contract addresses
inside a signing request.

### Account identity and lifecycle

Add a standalone record rather than widening `EvmFamilyWalletKeyRecord`:

```ts
type EvmSmartAccountRecord = {
  readonly kind: 'evm_smart_account_record_v1';
  readonly walletId: WalletId;
  readonly chainTarget: EvmEip155ChainTarget;
  readonly accountAddress: Eip8130AccountAddress;
  readonly activeOwnerWalletKeyId: WalletKeyId;
  readonly createPlan: Eip8130CreatePlan;
  readonly lifecycle: Eip8130AccountLifecycle;
};

type Eip8130AccountLifecycle =
  | {
      readonly state: 'counterfactual';
      readonly establishedAtMs?: never;
      readonly deploymentTxHash?: never;
      readonly deploymentBlockNumber?: never;
      readonly submittedAtMs?: never;
    }
  | {
      readonly state: 'deployment_submitted';
      readonly deploymentTxHash: EvmTransactionHash;
      readonly submittedAtMs: number;
      readonly establishedAtMs?: never;
      readonly deploymentBlockNumber?: never;
    }
  | {
      readonly state: 'deployed';
      readonly deploymentTxHash: EvmTransactionHash;
      readonly deploymentBlockNumber: bigint;
      readonly establishedAtMs: number;
      readonly submittedAtMs?: never;
    };
```

Submission uncertainty resolves by reading the transaction and onchain account
state. Do not create a local `failed` branch that can overwrite a deployed
account after a timeout.

`Eip8130CreatePlan` requires:

- canonical deployment version;
- domain-separated user salt;
- exact runtime bytecode or proxy creation code;
- runtime code hash;
- sorted initial actor set containing exactly one unrestricted k1 admin;
- initial actor-set digest;
- derived account address.

Construction occurs through one branch-specific builder. Persistence and wire
records pass through boundary parsers before they enter core logic.

### Signing request

Extend the EVM request union with a fully separate branch:

```ts
type EvmSigningRequest = Eip1559SigningRequest | Eip8130SigningRequest;

type Eip8130SigningRequest = {
  readonly chain: 'evm';
  readonly kind: 'eip8130';
  readonly chainTarget: EvmEip155ChainTarget;
  readonly nonce: Eip8130OrderedNonce;
  readonly gas: Eip8130GasFields;
  readonly validity: Eip8130ValidityWindow;
  readonly payer: { readonly kind: 'self' };
  readonly metadata: Eip8130Metadata;
  readonly senderSignatureAlgorithm: 'secp256k1';
} & Eip8130Operation;

type Eip8130Operation =
  | {
      readonly operation: 'deploy_and_call';
      readonly account: CounterfactualEip8130Account;
      readonly calls: readonly [Eip8130CallPhase, ...Eip8130CallPhase[]];
      readonly accountChanges: readonly [Eip8130CreateChange];
    }
  | {
      readonly operation: 'calls';
      readonly account: DeployedEip8130Account;
      readonly calls: readonly [Eip8130CallPhase, ...Eip8130CallPhase[]];
      readonly accountChanges: readonly [];
    }
  | {
      readonly operation: 'owner_rotation';
      readonly account: DeployedEip8130Account;
      readonly calls: readonly [];
      readonly accountChanges: readonly [SignedEip8130OwnerRotation];
    };
```

The first slice accepts ordered nonce key `0` and self-payment only. Builders
construct those exact branches. Raw library transaction objects never cross the
public SDK, persistence, secure-confirmation, or threshold-signing boundaries.

### Signed result

```ts
type Eip8130SignedResult = {
  readonly chain: 'evm';
  readonly kind: 'eip8130';
  readonly accountAddress: Eip8130AccountAddress;
  readonly actorId: Eip8130ActorId;
  readonly transactionHash: EvmTransactionHash;
  readonly rawTransaction: Eip8130RawTransaction;
  readonly nonce: Eip8130OrderedNonce;
  readonly includedCreate: boolean;
};
```

EIP-1559 and EIP-8130 results remain separate through broadcast, receipt, nonce,
and audit handling. An EIP-8130 result cannot enter the EOA nonce lifecycle.

## Shared And Per-Wallet Deployment

### Shared once on Vibenet

The native chain supplies or canonically deploys:

- Keystore/account configuration;
- k1, P-256, WebAuthn, and delegate authenticators;
- default and supported account implementations;
- nonce and transaction-context protocol facilities;
- optional policy contracts outside this first slice.

Seams reads and validates the canonical Vibenet deployment. It does not deploy,
upgrade, or substitute these contracts.

### One instance per wallet

Each wallet receives one deterministic Vibenet smart-account instance. The
instance stays counterfactual through registration. Its first send includes the
create change, after which the account has code and its actor configuration is
initialized.

Use one versioned salt derivation:

```text
SHA-256(
  encodeTuple(
    "seams/eip8130/account-salt/v1",
    WalletId,
    accountProfileVersion
  )
)
```

The salt is chain-independent so a later portability plan can reproduce the
same address when it uses the exact same canonical deployment, code, actors,
and account profile. Refactor 130 instantiates and operates that address only on
Vibenet. The account address also commits to runtime code and the initial actor
set under the EIP-8130 derivation. Never reuse an address prediction after any
committed input changes.

## Operating Paths

### Registration

1. Complete the existing wallet custody ceremony and strict Router A/B ECDSA
   activation.
2. Resolve the exact active `EvmFamilyWalletKeyRecord` and verified threshold
   owner address.
3. Build the unrestricted k1 initial actor from that address.
4. Resolve and validate the pinned canonical Vibenet deployment.
5. Derive the salt, create plan, actor-set digest, and account address.
6. Compare client and server address derivation before committing registration.
7. Persist the public smart-account record as `counterfactual` in the same
   registration commit that publishes its owning wallet key.
8. Return the smart-account address as the Vibenet account identity. Continue to
   expose the threshold owner address only in advanced signer diagnostics.

A failed smart-account derivation fails the Vibenet registration branch before
registration reports success. Existing NEAR and ordinary EVM registration
branches remain governed by their own selected signer set.

### First transaction and lazy deployment

1. Resolve a `counterfactual` account and active owner key.
2. Check Vibenet chain ID, canonical deployment version, derived address, actor
   digest, runtime code hash, and current empty-account state.
3. Require the counterfactual account to hold enough Vibenet ETH for the
   estimated first transaction. The smoke path obtains this ETH from the faucet.
4. Read ordered nonce key `0` from the EIP-8130 nonce manager.
5. Build one transaction containing the immutable create change plus the user's
   first call phase.
6. Render deployment, initial admin actor, account address, calls, and maximum
   fee in secure confirmation.
7. Reserve the existing wallet signing budget and threshold-sign the exact
   EIP-8130 sender digest.
8. Serialize one type-`0x79` transaction and broadcast it directly.
9. Persist `deployment_submitted` with its transaction hash before waiting.
10. After finalization, require successful phases and read back:
    - runtime code at the account address;
    - expected runtime code hash;
    - initialized account sequence;
    - live unrestricted k1 actor matching the active owner;
    - absence of an unexpected implicit/default EOA actor.
11. Commit `deployed` only after every readback succeeds.

If receipt waiting times out, retain `deployment_submitted`. Reconciliation
checks chain state and reaches `deployed` when the immutable postconditions are
present. It returns to `counterfactual` only after proving the transaction did
not land and the address still has no code or account configuration.

### Subsequent transaction

1. Require the `deployed` lifecycle branch.
2. Read ordered nonce key `0`.
3. Build the call phases with an empty `accountChanges` list.
4. Confirm, threshold-sign, serialize, broadcast, and inspect every receipt
   phase.
5. Attribute the operation to both smart-account address and authenticated
   actor ID in audit evidence.

The second successful send is required evidence that account operation is not
accidentally coupled to the create path.

### Owner rotation

Owner rotation is a privileged, freshly authorized operation:

1. Require fresh operation-scoped owner authorization.
2. Provision a replacement strict Router A/B ECDSA wallet key under a new
   `WalletKeyVersion`. Keep the current key active during provisioning.
3. Verify the replacement public key, address, participants, activation, and
   possession proofs.
4. Read the live account-change sequence and current actor configuration.
5. Build one signed account-change batch that:
   - authorizes the replacement k1 actor as unrestricted admin;
   - revokes the current k1 actor;
   - consumes the exact live local sequence.
6. Display the account address, current actor, replacement actor, unchanged
   account address, chain, and revocation consequence.
7. Sign the config digest with the current threshold owner.
8. Construct the config-only native transaction containing that signed change,
   then sign the distinct outer transaction sender digest with the replacement
   owner. Account changes apply before outer sender authentication, so the
   enclosing transaction must authenticate through the newly authorized actor.
   Reserve one threshold signature use from each owner lane for this logical
   operation and label each signature by its protocol domain and wallet-key
   version.
9. Before submission, retain one harmless, short-validity old-owner probe
   transaction signed against the post-rotation nonce. It exists only to prove
   onchain revocation after rotation and contains no value or authority change.
10. Submit the config-only native transaction and wait for finalization.
11. Read back the replacement actor as live and unrestricted, the previous actor
    as absent, and the account address/code as unchanged.
12. Atomically update `activeOwnerWalletKeyId`, retire the previous wallet key,
    revoke its Wallet Sessions and signing lanes, and record the rotation
    receipt.
13. Submit the pre-signed harmless old-owner probe before consuming its nonce
    through another transaction. Require an actor-authentication rejection and
    verify the nonce remains unchanged. Do not reactivate retired custody
    material to construct a post-rotation test.
14. Sign and send one transaction through the replacement owner using that same
    unchanged nonce.

Failure before onchain actor rotation leaves the current key active. An
uncertain submission freezes local owner selection and reconciles onchain state
before either key signs another account operation. No rollback reauthorizes a
revoked actor silently.

### Account synchronization and wallet recovery

Account sync treats onchain code and actor configuration as authoritative and
the server record as a durable public projection. It verifies the deterministic
address and hydrates only a precise lifecycle branch.

Existing recovery codes reconstruct and verify custody for the active wallet
key. They do not authorize an onchain actor change. If recovery restores the
same active threshold owner, the smart-account address and actor state remain
unchanged. Recovery that cannot reproduce the active owner stops before signing.

DKIM or recovery-driven owner replacement requires a future custom authenticator
design and is outside Refactor 130.

## Client Dependency Boundary

The current workspace Viem version has no EIP-8130 module. During this draft
phase:

1. Pin the reviewed EIP-8130 Viem fork to an immutable commit and lockfile
   integrity.
2. Import it from one internal `eip8130` protocol adapter only.
3. Convert its raw accounts, deployment records, transaction objects, receipts,
   and errors into Seams domain types at that boundary.
4. Verify its transaction hashes, serialized bytes, derived addresses, and
   account-change digests against the canonical contracts repository.
5. Record the pinned EIP commit, contracts commit, deployment version, contract
   addresses, and runtime code hashes in one checked source file.
6. Upgrade by intentional replacement with regenerated vectors. Do not add
   adapters for multiple draft revisions.

If the fork cannot be pinned reproducibly or its canonical deployment drifts,
stop the implementation before public API or persistence changes.

## Signing And Secure Confirmation

The existing threshold signer already signs 32-byte secp256k1 digests. Refactor
130 changes the digest builder and final envelope while preserving custody and
threshold signing.

Add an EIP-8130 adapter that:

- requires `Eip8130SigningRequest`;
- validates the active smart account and owner binding;
- constructs the exact unsigned sender payload;
- exposes structured deployment, actor-change, phase, call, metadata, payer,
  validity, nonce, and gas facts to secure confirmation;
- requests one `secp256k1` digest signature labeled for the EIP-8130 sender
  domain during deploy-and-call and ordinary-call operations;
- accepts only a config change threshold-signed by the current owner on the
  owner-rotation branch, then requests the outer sender-domain signature from
  the replacement owner that the change authorizes;
- produces the canonical k1 `sender_auth` blob;
- serializes and hashes the final type-`0x79` transaction;
- returns `Eip8130SignedResult`.

The confirmer must reject opaque account changes, unknown authenticators,
unknown scope bits, a mismatched account address, a create plan that differs
from the registered plan, and any owner rotation lacking fresh authorization.

## Nonce, Broadcast, And Receipt Rules

- Use ordered nonce key `0` only.
- Read the EIP-8130 nonce manager. Do not call the EOA nonce backend for this
  branch.
- Bind reservations to wallet, smart account, chain ID, nonce key, sequence,
  actor, and exact operation.
- Broadcast raw bytes through the configured Vibenet RPC.
- Parse EIP-8130 receipt fields once at the RPC boundary.
- Check every call phase. A top-level receipt status alone is insufficient.
- Treat earlier committed phases and account changes as persistent when a later
  phase fails.
- Reconcile account creation and owner rotation through direct state readback.
- Classify a halted or unavailable Vibenet as
  `environment_or_infrastructure_failure`; do not mutate transaction logic to
  accommodate a stalled devnet.

## Persistence

Add one current D1 table and one browser projection for public account state.
Do not place key material, shares, auth blobs, raw signatures, or complete
transactions in either.

The durable record contains:

- tenant/project environment;
- wallet ID;
- chain target and chain ID;
- smart-account address;
- active owner wallet-key ID and version;
- canonical deployment version;
- user salt;
- runtime code hash;
- initial actor-set digest;
- lifecycle branch and lifecycle timestamps;
- deployment transaction hash and block when applicable;
- latest verified account-change sequence;
- latest verification timestamp.

Use `(project_environment_id, wallet_id, chain_id)` as the logical identity.
Every D1 row passes through a strict parser. Registration, deployment
finalization, and rotation use compare-and-swap facts. Historical migrations
remain unchanged.

The browser projection caches the same public identity and lifecycle for
offline display and startup. Server and onchain readback override stale local
state. Browser state never grants signing authority.

## Public API

Keep existing EOA transaction methods intact for existing configured networks.
Add an EIP-8130 calls API whose types cannot express an EIP-1559 envelope:

```ts
seams.evm.sendCalls({
  walletSession,
  chainTarget: 'base-vibenet',
  phases,
  metadata,
  options,
});
```

Registration results and wallet profiles return a discriminated Vibenet account
identity with:

- smart-account address;
- `counterfactual` or `deployed` lifecycle;
- active threshold owner address as advanced signer data;
- deployment transaction hash only in the branches where it exists.

Add a separate privileged `rotateOwner` operation. It accepts no raw actor
change, scope, authenticator address, sequence, deployment address, or unsigned
transaction supplied by application code. Those facts come from registered
state and the canonical adapter.

## Server And Infrastructure

### Existing services retained

- Router A/B strict ECDSA derivation;
- SigningWorker online ECDSA participation;
- Wallet Session and operation-scoped authorization;
- signing budgets, audit, and presignature pools;
- configured RPC access.

### New server responsibilities

- validate and commit smart-account registration facts;
- return public account projections during sync;
- authorize deployment and owner rotation operations;
- coordinate replacement threshold-key provisioning;
- compare-and-swap deployment and rotation lifecycle records;
- retain audit receipts and onchain verification facts.

### Services not required

- ERC-4337 bundler;
- EntryPoint integration;
- transaction relayer for ordinary native sends;
- paymaster or ERC-8168 payer;
- custom account factory;
- custom authenticator;
- Vibenet node operation.

The browser can broadcast directly. Existing managed deployments may proxy RPC
for policy or observability, but that proxy must forward exact signed bytes and
must not become signing authority.

## Security Invariants

1. The smart-account address and threshold owner address are distinct domain
   types and are never interchangeable.
2. One counterfactual account binds one exact chain, canonical deployment,
   salt, runtime code, and sorted initial actor set.
3. Registration verifies independent client and server derivations of the same
   smart-account address.
4. Only the active `EvmFamilyWalletKeyRecord` may authenticate account sends or
   account changes.
5. Smart-account persistence contains no custody material and grants no signing
   authority.
6. The first transaction uses the registered create plan byte-for-byte.
7. A deployed account never returns to the counterfactual state.
8. Deployment success requires code, code-hash, sequence, and actor readback.
9. Owner rotation authorizes the replacement and revokes the current actor in
   one batch.
10. Old custody material retires only after verified onchain revocation.
11. An uncertain rotation blocks both candidate owners until reconciliation.
12. The smart-account address remains unchanged across owner rotation.
13. The EIP-8130 branch never consumes an EOA nonce reservation.
14. Secure confirmation displays every call phase and every authority change.
15. Application code cannot supply authenticator, actor scope, config sequence,
    canonical deployment, create bytecode, or recovery authority.
16. Draft protocol shapes are normalized once inside the pinned adapter.
17. Logs and errors contain no signature, auth blob, threshold material, or raw
    recovery data.
18. Vibenet availability never changes persisted authority without onchain
    readback.

## Implementation Phases

### Phase 0 — Freeze the external contract

- [ ] Pin one EIP-8130 specification commit, contracts commit, Viem fork commit,
      and Vibenet canonical deployment.
- [ ] Record chain ID, RPC, deployment addresses, implementation code hashes,
      authenticator addresses, and supported RPC methods.
- [ ] Add canonical address, create-address, sender-digest, serialized-
      transaction, and actor-change vectors generated from the pinned reference.
- [ ] Verify the public RPC accepts type `0x79` and the Vibenet faucet can fund a
      counterfactual address.
- [ ] Stop if any required revision floats or cannot reproduce the vectors.

### Phase 1 — Domain types and chain boundary

- [ ] Add `base-vibenet` and resolve it to `eip8130_native`.
- [ ] Add branded account, actor, nonce, hash, metadata, and raw-transaction
      values with boundary parsers.
- [ ] Add `EvmSmartAccountRecord`, create-plan, and lifecycle unions.
- [ ] Add type fixtures rejecting optional owner identity, mixed lifecycle
      fields, EOA nonce state, raw deployment objects, broad object spreads, and
      invalid signing-request branches.
- [ ] Keep `EvmFamilyWalletKeyRecord` unchanged as the threshold-key source.

### Phase 2 — Counterfactual registration and persistence

- [ ] Build the canonical initial k1 actor after ECDSA activation.
- [ ] Derive the salt, create plan, and smart-account address through the pinned
      adapter.
- [ ] Require client/server derivation parity.
- [ ] Add the D1 smart-account table, strict record parser, registration commit,
      and account-sync reader.
- [ ] Add the browser public projection and startup hydration.
- [ ] Return the counterfactual smart-account identity from Vibenet
      registration.

### Phase 3 — Native deployment and ordinary sends

- [ ] Add the EIP-8130 signing request/result branches and adapter.
- [ ] Add secure-confirmation models for create, calls, actor changes, nonce,
      payer, validity, metadata, and gas.
- [ ] Add nonce-key-0 reads and reservations independently of EOA nonce state.
- [ ] Add direct `0x79` broadcast and phase-aware receipt parsing.
- [ ] Include the create change only for a counterfactual account.
- [ ] Persist submitted state before waiting and reconcile uncertain results.
- [ ] Verify code, code hash, sequence, and actor before committing deployed.
- [ ] Demonstrate a second send without the create change.

### Phase 4 — Threshold owner rotation

- [ ] Add fresh operation authorization for exact Vibenet owner rotation.
- [ ] Provision a replacement strict Router A/B ECDSA wallet-key version.
- [ ] Build and confirm one atomic authorize/revoke account-change batch.
- [ ] Freeze local selection during uncertain submission.
- [ ] Read back actor removal/addition and unchanged account identity.
- [ ] Commit active-owner replacement and retire old sessions, lanes, and key
      material only after readback.
- [ ] Demonstrate a replacement-owner send and retired-owner rejection.

### Phase 5 — Public surface and documentation

- [ ] Add `sendCalls` and privileged `rotateOwner` capabilities.
- [ ] Update wallet profiles, account display, funding instructions, explorer
      links, events, and errors to use the smart-account address.
- [ ] Document the threshold owner as signer diagnostics rather than the public
      receiving address.
- [ ] Update `docs/intended-behaviours.md` and its contract only when the
      Vibenet registration behavior becomes supported product behavior.
- [ ] Document Vibenet's experimental availability and direct-RPC model.

### Phase 6 — Cleanup and review

- [ ] Delete temporary smoke-only entry points after the operating path moves
      through the public capability.
- [ ] Remove duplicate raw EIP-8130 shapes outside the protocol adapter.
- [ ] Confirm no removed smart-account types from Refactor 37 were revived.
- [ ] Confirm no ERC-4337, paymaster, DKIM, EIP-7702, multichain, or production
      placeholders entered active code.
- [ ] Review the complete change in one reading and remove abstractions that do
      not eliminate ambiguity.

## Verification

### Deterministic tests

- type fixtures reject invalid account lifecycle and request combinations;
- vector tests reproduce the pinned reference implementation's address,
  digest, auth blob, transaction bytes, transaction hash, and actor-change
  digest;
- registration derives the same address on client and server;
- a changed salt, code hash, actor, scope, or deployment version changes the
  address or fails validation;
- counterfactual signing includes exactly one registered create change;
- deployed signing cannot include a create change;
- EIP-8130 requests cannot enter the EIP-1559 encoder or EOA nonce backend;
- secure confirmation rejects hidden or mismatched account changes;
- receipt parsing preserves committed earlier phases when a later phase fails;
- timeout reconciliation cannot regress a deployed account;
- owner rotation changes the active owner and preserves the account address;
- invalid broad object literals and unsafe lifecycle spreads fail typecheck.

### Focused behavior tests

- Vibenet registration returns a counterfactual smart-account address owned by
  the activated threshold ECDSA key;
- first-send state moves `counterfactual -> deployment_submitted -> deployed`
  only after exact readback;
- second send succeeds without deployment data;
- normal threshold ECDSA budgets and step-up policy still apply;
- owner rotation requires fresh operation authorization;
- uncertain deployment and uncertain rotation resume by readback;
- account sync restores the exact account, owner, and lifecycle;
- existing EIP-1559 EOA signing remains unchanged on existing chains.

### Live Vibenet smoke

Provide one explicit command that:

1. checks Vibenet health and chain ID;
2. registers or loads a dedicated smoke wallet;
3. derives its counterfactual address;
4. requests faucet funding and polls the balance;
5. deploys through the first native transaction;
6. verifies code and initial actor;
7. sends a second transaction;
8. provisions and rotates to a replacement threshold owner using a current-
   owner config-change signature and replacement-owner outer-transaction
   signature;
9. submits the pre-signed harmless old-owner probe, proves actor-authentication
   rejection, and verifies its nonce was not consumed;
10. sends through the replacement owner using the unchanged nonce;
11. prints only public addresses, transaction hashes, block numbers, actor IDs,
    and verification results.

A halted Vibenet is an `environment_or_infrastructure_failure`. The smoke
command reports that classification and exits without changing production code
or test expectations.

### Narrow commands

Finalize exact command names alongside the implementation. Prefer:

```bash
pnpm -C tests exec playwright test -c playwright.lite.config.ts \
  ./unit/eip8130.domain.typecheck.test.ts \
  ./unit/eip8130.vectors.unit.test.ts \
  ./unit/eip8130.accountLifecycle.unit.test.ts \
  ./unit/eip8130.ownerRotation.unit.test.ts --reporter=line

pnpm run eip8130:vibenet:smoke
git diff --check
```

Run broader registration, wallet recovery, ECDSA signing, account-sync, and
public type checks because this feature changes shared registration results,
public account identity, persistence, and privileged key lifecycle. Run
`pnpm test:intended` after the intended-behavior contract changes.

## Rollout

The explicit `base-vibenet` chain target is the activation boundary. Do not add
a global feature flag or allow another chain to opt into `eip8130_native` by
supplying arbitrary addresses.

Rollout order:

1. internal development wallet;
2. deterministic vectors and local focused tests;
3. live Vibenet create plus second-send smoke;
4. live Vibenet threshold-owner rotation smoke;
5. public experimental Vibenet capability;
6. reassessment after the EIP, contracts, client API, and Base activation plan
   stabilize.

Base Sepolia or mainnet requires a separate plan. That plan must revalidate
canonical deployments, transaction semantics, gas, RPC behavior, audits,
availability, migration, and production incident response. It cannot inherit a
Vibenet deployment record by changing the chain ID.

## Exit Criteria

- One registered wallet has a deterministic Vibenet smart-account address
  distinct from its threshold owner address.
- The account deploys lazily through its first native type-`0x79` transaction.
- Exact code and initial actor state verify onchain before local deployment
  finalization.
- A second native transaction succeeds without deployment data.
- Existing Router A/B threshold ECDSA signs both transactions without a new
  custody or signing protocol.
- Ordered EIP-8130 nonce key `0` is isolated from EOA nonce state.
- One fresh-authorized rotation installs a replacement threshold owner and
  revokes the previous owner atomically.
- The smart-account address remains unchanged through rotation.
- The replacement owner can transact and the retired owner is rejected.
- Account sync reconstructs the same public account lifecycle from durable and
  onchain facts.
- Existing EIP-1559 EOA behavior passes its focused regression coverage.
- No ERC-4337, payer, EIP-7702, DKIM, session-key, multichain, or production
  compatibility path exists in the implementation.
- Documentation labels EIP-8130 and Vibenet experimental and makes no
  production-support claim.

## Future Work Requiring Separate Plans

- Base Sepolia and Base mainnet native activation;
- portable ERC-4337 execution and bundler integration;
- ERC-8168 payer and sponsored first transactions;
- passkey/P-256 owners and scoped session actors;
- cross-chain account deployment and actor-change replay;
- migration of existing EOA-held assets and approvals;
- custom account implementations and upgrade governance;
- DKIM, guardian, or social recovery authenticators;
- production audits, monitoring, incident response, and contract-version
  governance.

## References

- [EIP-8130 specification](https://eips.ethereum.org/EIPS/eip-8130)
- [EIP-8130 builder guide](https://www.eip8130.com/guide)
- [Vibenet getting started](https://www.eip8130.com/guide/getting-started)
- [Creating EIP-8130 accounts](https://www.eip8130.com/guide/creating-accounts)
- [EIP-8130 reference contracts](https://github.com/base/eip-8130)
- [Refactor 37 smart-account deletion and future-plan boundary](./refactor-37.md)
- [EVM ECDSA address invariant](../apps/docs/src/concepts/threshold-signing/evm-ecdsa.md)
- [Key-rotation taxonomy](../apps/docs/src/concepts/delegation/key-rotation.md)
