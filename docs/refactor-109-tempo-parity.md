# Tempo Native Account And Transaction Parity

Date created: August 5, 2026

Status: proposed implementation plan

## Decision Summary

1. Refactor 109 targets parity with Tempo's native account-abstraction and
   transaction features. It does not attempt to clone the complete Tempo
   Wallet product or every action in the Tempo Viem package.
2. The first release completes one safe vertical slice for each essential
   account mode: threshold secp256k1 root accounts, WebAuthn/P-256 root
   accounts, and device-bound P-256 access keys.
3. Access keys become a Tempo chain-native execution adapter for the wallet-key
   and delegated-spending model in Refactors 101 through 104. A Tempo access key
   is never treated as an off-chain Wallet Session or as authority by itself.
4. On-chain access-key constraints are the chain-enforced safety floor. Seams
   policy may narrow that authority and must never widen it.
5. The public and core transaction models use exact discriminated unions.
   `TempoRlpValue`, optional protocol bags, and caller-assembled signature
   envelopes are removed from the supported path.
6. Existing Tempo support is hardened before adding more lifecycle machinery:
   canonical encoding, independent vectors, direct WebAuthn signing, batches,
   fee-token selection, scheduling fields, and nonce modes must agree with the
   selected Tempo network release.
7. Basic access keys and native fee sponsorship ship before advanced access-key
   policy, durable scheduling, and EIP-7702-style authorization lists.
8. Every phase ends with one demonstrated operating path. Broader guardrails
   follow only where that path exposes a concrete failure mode.

## Scope

This plan covers the native features advertised by Tempo Transactions:

- EIP-2718 type `0x76` encoding and signing;
- secp256k1, P-256, WebAuthn, and keychain sender signatures;
- domain-bound passkey accounts;
- configurable TIP-20 fee tokens;
- native fee sponsorship;
- atomic call batches;
- protocol, two-dimensional, and expiring nonce modes;
- scheduled transaction validity windows;
- scoped access-key authorization, use, inspection, update, and revocation;
- the current access-key policy surface selected in Phase 0;
- Tempo AA authorization lists;
- Viem-compatible account and transaction boundaries.

The parity source set is:

- [Account Abstraction on Tempo](https://tempo.xyz/blog/account-abstraction/);
- [Use Tempo Transactions](https://tempo.xyz/developers/docs/guide/tempo-transaction);
- [Tempo Transaction specification](https://docs.tempo.xyz/protocol/transactions/spec-tempo-transaction);
- [Account Keychain precompile](https://docs.tempo.xyz/protocol/transactions/AccountKeychain);
- [Embed Passkey Accounts](https://docs.tempo.xyz/guide/use-accounts/embed-passkeys);
- [Viem Tempo access-key authorization](https://viem.sh/tempo/actions/accessKey.signAuthorization);
- [Viem Tempo access-key witness revocation](https://viem.sh/tempo/actions/accessKey.burnWitness).

Tempo's protocol and SDK surface is evolving. Phase 0 records the exact network
release, hardfork, transaction schema, Account Keychain ABI, and vector source
that this refactor implements. Later Tempo changes require a new reviewed
schema branch or a follow-up refactor; they do not enter core logic through
permissive RLP input.

Out of scope:

- cloning Tempo Wallet's portfolio, activity, swap, on-ramp, or visual design;
- general TIP-20 issuance and administration;
- DEX, AMM, rewards, transfer-policy, receive-policy, and payment-channel action
  libraries;
- a generic replacement for Viem;
- agent identity and delegated-spend authorization outside the Tempo adapter;
- support for multiple historical Tempo transaction schemas.

## Dependencies And Authority

This plan consumes:

- [Refactor 90](./refactor-90-modular-auth-capabilities-plan.md) for exact
  authorization resources, operation fingerprints, atomic claims, replay, and
  audit;
- [Refactor 100](./refactor-100-passkey-account-refactor.md) for passkey
  credential ownership and wallet identity;
- [Refactor 101](./refactor-101-wallet-execution-lanes.md) for stable wallet-key
  identity and chain-specific execution adapters;
- [Refactor 102](./refactor-102-rotatable-signing-lanes.md) for replaceable execution
  material and revocation epochs;
- [Refactor 103](./refactor-103-device-linking.md) for device continuity;
- [Refactor 104](./refactor-104-agent-id-spending.md) for independent agent
  identity, owner authorization, agent request signatures, budget, replay, and
  delegated execution admission;
- [Sponsorship Policy Engine Plan](./sponsorship-policy.md) for sponsorship
  policy, reservations, execution adapters, finalized spend, and billing.

Refactor 109 owns:

- the canonical Tempo transaction domain and wire codec;
- Tempo account-address derivation for each supported root signer;
- Tempo root, access-key, and fee-payer signing domains;
- Tempo access-key custody and on-chain lifecycle;
- projection of Seams delegated policy into Tempo access-key constraints;
- Tempo fee sponsorship execution;
- Tempo nonce and scheduling behavior;
- Tempo-specific public SDK and Viem interoperability surfaces;
- Tempo parity vectors and intended-behaviour contracts.

Refactor 104 remains authoritative for agent authorship and owner mandates. A
Tempo access key can execute an admitted agent request, but possession of that
key does not replace the `DelegatedSpendAuthorization` or signed
`SpendRequest`.

## Current State

The SDK already has a useful Tempo foundation. Support claims must distinguish
wire acceptance from a complete public lifecycle.

| Feature | Current state | Gap to parity |
| --- | --- | --- |
| Type `0x76` secp256k1 sender signing | Working | Revalidate against the pinned current schema and independent vectors. |
| Atomic `calls` batch | Encoded and displayed | Add boundary parsing, whole-batch policy, simulation, and chain integration evidence. |
| Access list | Encoded | Model address and create destinations exactly; add current vectors. |
| `feeToken` | Encoded; Fee Manager helpers exist | Add token validation, resolution, receipt evidence, and a narrow public API. |
| Fee-payer signature | Sender placeholder and signed envelope are encoded | Add the `0x78` payer digest, payer signer, remote relay contract, policy, settlement, and end-to-end evidence. |
| `validAfter` / `validBefore` | Encoded and shown in confirmation | Add strict validity rules and a durable scheduled-submission lifecycle. |
| Two-dimensional nonce | `nonceKey` and managed nonce lanes exist | Prove concurrent submission and add explicit protocol/sequence/expiring nonce branches. |
| Expiring nonce | Raw fields can approximate it | Add the protocol sentinel, bounded validity, automatic nonce resolution, and retry behavior. |
| WebAuthn root signature | Signer, envelope packing, and request path exist | Add account provisioning/address identity, authoritative vectors, and an on-chain intended-behaviour path. |
| Plain P-256 root signature | Envelope is accepted by the codec | Add a typed signer and custody path or reject it at the public boundary until one exists. |
| Keychain sender signature | Prepacked `0x03` bytes are accepted | Add access-key account state, inner signing, root-address binding, and lifecycle. |
| `keyAuthorization` | Explicitly rejected | Implement typed authorization, root signing, first-use attachment, witness handling, and exact RLP. |
| Access-key limits and scopes | Missing | Implement the pinned Account Keychain policy surface and reconciliation. |
| Access-key revocation and updates | Missing | Implement root-only management calls, reads, events, and fail-closed local state. |
| Tempo AA authorization list | Non-empty values are explicitly rejected | Add typed Tempo authorizations, signatures, validation, and EIP-7702 constraints. |
| Contract creation call | Rejected by the address-only call type | Add an exact `create` call branch after AA constraints are implemented. |
| Viem interoperability | Consumers can pass low-level SDK shapes manually | Provide a documented account/sign-transaction adapter and compatibility fixtures. |
| Public Tempo signing boundary | Accepts a multichain request and contains an EIP-1559 branch | Require an exact Tempo request and delete the generic-EVM path from the Tempo capability. |

The current `TempoUnsignedTx` exposes `TempoRlpValue` for unsupported fields.
The Rust signer then rejects those fields and always encodes an empty AA list.
This is a boundary-shaped promise without the behavior. Phase 1 deletes that
shape and replaces it with exact supported branches.

## Ranking Method

Importance:

- **5 — critical:** required for the product promise or for a safe parity claim;
- **4 — high:** a primary Tempo native capability with material user value;
- **3 — medium:** important interoperability or advanced account behavior;
- **2 — low:** completes the protocol surface for narrower use cases;
- **1 — optional:** convenience with no effect on the parity claim.

Difficulty:

- **1 — small:** localized type, codec, or API work with existing primitives;
- **2 — moderate:** one vertical slice across a few established boundaries;
- **3 — substantial:** client, signer, lifecycle, and integration work;
- **4 — hard:** new signing domain or durable distributed lifecycle;
- **5 — very hard:** security-critical policy projected across chain and Seams
  state, including recovery and concurrency.

Priority follows importance and dependency order. Difficulty informs slicing;
it does not push critical security work behind lower-value conveniences.

## Ranked Feature Backlog

| Rank | Feature | Importance | Difficulty | Delivery priority | Reason |
| ---: | --- | :---: | :---: | :---: | --- |
| 1 | Canonical full Tempo transaction domain, codec, hashes, and vectors | 5 | 3 | P0 | Every later signature and policy proof depends on exact bytes. |
| 2 | WebAuthn root account provisioning and signing | 5 | 3 | P0 | Passkey accounts are Tempo's primary account UX and the root for access-key authorization. |
| 3 | Basic access-key authorization, first use, subsequent keychain signing, and revocation | 5 | 4 | P0 | This creates background signing and is the closest Tempo-native counterpart to Seams delegated execution. |
| 4 | Access-key custody, recovery boundary, expiry, token limits, scopes, and lifecycle reconciliation | 5 | 5 | P0 | A usable key without enforceable least authority would be an unsafe parity claim. |
| 5 | Native fee sponsorship from sender intent through payer signature and finalized billing | 5 | 4 | P0 | Gasless use is central to embedded accounts and existing Seams sponsorship infrastructure can support it. |
| 6 | Atomic batch calls with whole-batch display, policy, and simulation | 4 | 2 | P1 | Encoding exists; safety and public ergonomics remain. |
| 7 | Fee-token selection and account preference | 4 | 2 | P1 | Stablecoin-denominated fees are a core Tempo advantage and most wire support exists. |
| 8 | Protocol, 2D sequence, and expiring nonce modes with concurrent submission | 4 | 3 | P1 | Parallel payments require precise nonce state rather than caller-managed bigint fields. |
| 9 | Scheduled transaction signing, persistence, submission, cancellation, and expiry | 4 | 4 | P1 | Wire fields exist; reliable future execution requires a durable service lifecycle. |
| 10 | Viem-compatible Tempo account and transaction adapter | 4 | 3 | P1 | Ecosystem compatibility makes the feature usable without a parallel application integration. |
| 11 | Simulation-backed confirmation and receipt reconciliation | 4 | 3 | P1 | Batches, access-key limits, sponsorship, and schedules need trustworthy preflight and final evidence. |
| 12 | Advanced access-key administration: periodic limits, admin keys, limit updates, and authorization witnesses | 3 | 5 | P2 | These complete the current richer keychain surface after the least-authority baseline works. |
| 13 | Plain P-256 root accounts | 3 | 2 | P2 | The wire scheme matters for protocol parity, while WebAuthn roots and P-256 access keys cover the primary embedded-account paths. |
| 14 | Tempo AA authorization lists | 3 | 4 | P2 | EIP-7702 interoperability is useful and carries a wider execution/security surface. |
| 15 | Contract-creation calls and remaining access-list edge cases | 2 | 2 | P3 | This completes the transaction shape and has limited relevance to the embedded-payment path. |

## Target Domain Model

Raw request data is parsed once into exact internal branches. The examples
below establish shape and ownership; Phase 0 freezes precise field widths and
protocol versioning from the selected source release.

### Account signer

```ts
type TempoAccountSigner =
  | {
      kind: 'tempo_threshold_secp256k1_root';
      walletId: WalletId;
      walletKeyId: WalletKeyId;
      tempoAddress: TempoAddress;
    }
  | {
      kind: 'tempo_webauthn_p256_root';
      walletId: WalletId;
      walletKeyId: WalletKeyId;
      credentialId: PasskeyCredentialId;
      tempoAddress: TempoAddress;
    }
  | {
      kind: 'tempo_p256_access_key';
      walletId: WalletId;
      walletKeyId: WalletKeyId;
      tempoAccessKeyId: TempoAccessKeyId;
      rootAddress: TempoAddress;
      accessKeyAddress: TempoAddress;
    };
```

The root address is derived from the exact root public key. A WebAuthn
credential used only to authenticate access to a threshold secp256k1 wallet
does not become that wallet's Tempo root signer. Direct WebAuthn root accounts
are an explicit wallet-key branch.

### Nonce mode

```ts
type TempoNonceMode =
  | {
      kind: 'protocol_sequence';
      nonce: bigint;
    }
  | {
      kind: 'user_sequence';
      nonceKey: bigint;
      nonce: bigint;
    }
  | {
      kind: 'expiring';
      validBeforeSeconds: bigint;
      validAfterSeconds: bigint | null;
    };
```

Only the boundary resolver converts `expiring` into protocol sentinel fields.
Core signing never guesses a nonce mode from a magic bigint supplied by the
caller.

### Fee authority

```ts
type TempoFeeAuthority =
  | {
      kind: 'sender_pays';
      feeToken: TempoFeeTokenSelection;
    }
  | {
      kind: 'sponsorship_requested';
      sponsorshipPolicyId: SponsorshipPolicyId;
      feeTokenPreference: TempoFeeTokenSelection;
    }
  | {
      kind: 'sponsored';
      sponsorshipPolicyId: SponsorshipPolicyId;
      feePayer: TempoAddress;
      feeToken: TempoAddress;
      feePayerSignature: TempoSecp256k1Signature;
    };
```

The transition from `sponsorship_requested` to `sponsored` occurs inside the
sponsorship executor after policy and reservation succeed. Public callers
cannot label arbitrary bytes as an approved sponsor signature.

### Access-key state

```ts
type TempoAccessKeyRecord =
  | {
      kind: 'tempo_access_key_pending_authorization';
      tempoAccessKeyId: TempoAccessKeyId;
      rootAddress: TempoAddress;
      key: TempoAccessKeyPublicKey;
      requestedPolicy: TempoAccessKeyPolicy;
      authorizationWitness: TempoAuthorizationWitness;
    }
  | {
      kind: 'tempo_access_key_active';
      tempoAccessKeyId: TempoAccessKeyId;
      rootAddress: TempoAddress;
      key: TempoAccessKeyPublicKey;
      onchainPolicy: TempoAccessKeyPolicy;
      authorizationTxHash: TempoTransactionHash;
      observedAtBlock: bigint;
    }
  | {
      kind: 'tempo_access_key_inactive';
      tempoAccessKeyId: TempoAccessKeyId;
      rootAddress: TempoAddress;
      reason: 'expired' | 'revoked' | 'witness_burned' | 'lost_local_key';
      observedAtBlock: bigint;
    };
```

The default interactive access key is a non-extractable WebCrypto P-256 key.
The SDK stores only its handle and public material. Agent runtimes may register
an externally held supported public key through Refactor 104's chain-native
adapter after owner authorization.

## Required Invariants

1. Every hash and envelope is produced by one canonical codec shared through
   generated bindings or common vectors. TypeScript does not maintain a second
   hand-written RLP implementation.
2. Every supported Tempo transaction identifies one exact network schema and
   one exact sender branch.
3. Public requests cannot carry raw RLP, prepacked keychain envelopes, or an
   unverified fee-payer signature.
4. A direct WebAuthn root account address derives from the credential public
   key that signs the transaction.
5. A passkey used as Seams authentication for a threshold wallet remains an
   authentication factor. It signs Tempo transactions directly only for the
   explicit WebAuthn root-account branch.
6. Access-key authorization requires fresh root authority and displays the
   key fingerprint, expiry, token limits, call scopes, recipients, recurrence,
   admin status, and revocation consequences.
7. An access key receives no root key, owner share, export capability,
   recovery authority, or implicit account-administration authority.
8. Background signing proceeds only when on-chain key state and Seams
   authorization state are both active.
9. Seams policy is equal to or narrower than the authorized on-chain policy.
   A mismatch fails before signing.
10. Agent use also requires a valid Refactor 104 authorization, agent-signed
    request, budget reservation, replay claim, and exact transaction binding.
11. Access-key expiry, revocation, witness burn, and lost local custody fail
    before nonce reservation, sponsorship reservation, or signing.
12. Fee sponsorship uses the Tempo fee-payer signing domain and commits to the
    exact sender, transaction, selected fee token, and key authorization fields
    required by the pinned schema.
13. Sponsorship policy and spend are reserved atomically before the payer
    signs. Finalized spend settles exactly once.
14. Batch policy validates every call and the aggregate value. One allowed call
    cannot hide a disallowed sibling.
15. Scheduled work persists exact signed bytes, sender, nonce mode, validity
    window, policy identity, and idempotency identity.
16. Scheduled submission never signs after the original authorization window
    and never retries after `validBefore`.
17. Nonce modes are mutually exclusive. Expiring nonces do not enter the
    durable sequence-lane allocator.
18. Chain reads and receipts are parsed once into precise state. Diagnostics do
    not influence control flow.
19. Revoked access-key IDs are never silently reused. Rotation provisions a
    new key and authorization.
20. Existing raw optional fields, MVP rejection branches, and tests that assert
    obsolete rejections are deleted at cutover.

## Prioritized Implementation Plan

### Phase 0: Freeze The Parity Contract

Objective: select the exact protocol target before changing supported bytes.

Deliverables:

- record the Tempo network release, hardfork, type-`0x76` field order, optional
  trailing-field rules, Account Keychain ABI, access-key policy schema, and
  fee-payer signing domain;
- vendor or generate independent fixtures from the selected Tempo Rust or Viem
  implementation for every signature and optional-field branch;
- add a parity manifest listing each ranked feature as `supported`, `partial`,
  `unsupported`, or `deferred` with an evidence link;
- define the public compatibility target for Viem transaction serialization and
  local accounts;
- decide which advanced access-key features are active on the target network:
  periodic limits, call scopes, recipients, admin keys, and witnesses;
- update `docs/intended-behaviours.md` with the new Tempo account and background
  signing contracts.

Exit gate:

- one reviewed fixture set independently proves current secp256k1 sender hashes,
  WebAuthn envelopes, fee-payer hashes, key authorizations, keychain signatures,
  batches, fee tokens, validity windows, and all nonce modes;
- schema ambiguity is resolved before production types change.

### Phase 1: Replace The MVP Codec With The Canonical Transaction Domain

Objective: make every already-exposed Tempo field exact and honest.

Deliverables:

- replace `TempoRlpValue` with typed transaction, key-authorization, and AA
  authorization records;
- narrow `SignTempoArgs.request` to an exact Tempo request and delete the
  EIP-1559 branch from the Tempo signing capability;
- split call targets into `address` and `create` domain branches while keeping
  `create` unavailable until Phase 8;
- split nonce and fee authority into the unions above;
- implement exact sender, fee-payer, key-authorization, and signed-envelope
  codecs in `signer-core`;
- generate the TypeScript boundary from the Rust-owned shapes or parse into one
  exact generated wire contract;
- preserve working secp256k1, batches, access lists, fee-token, validity-window,
  and managed user-sequence behavior;
- delete the MVP rejection function and the fixtures that assert unsupported
  `keyAuthorization` or AA fields once their replacement branches land;
- reject unsupported domain branches at the public boundary with explicit
  feature status rather than carrying them into the codec.

Exit gate:

- all Phase 0 vectors match byte-for-byte in Rust and browser WASM;
- existing intended Tempo secp256k1 signing remains green;
- invalid transaction branches fail at construction or boundary parsing.

### Phase 2: Ship Direct Passkey Root Accounts

Objective: support Tempo's primary embedded-account model end to end.

Deliverables:

- add an explicit Tempo WebAuthn root wallet-key branch at registration;
- derive and persist its Tempo address from the credential P-256 public key;
- retain the public key in the wallet credential store required for future
  address reconstruction;
- bind RP ID, credential ID, wallet key, Tempo address, and network target;
- sign type-`0x76` sender hashes through the existing wallet-origin WebAuthn
  ceremony and canonical envelope packer;
- add a plain non-extractable WebCrypto P-256 account branch only if a concrete
  product path needs a root key without WebAuthn; otherwise keep plain P-256
  root signing unavailable at the public boundary;
- expose the derived Tempo address and account kind through one public account
  projection.

Exit gate:

- registration creates a direct passkey-root Tempo account;
- a real Tempo transaction succeeds on the selected test network;
- refresh and unlock reconstruct the same address and sign again;
- a threshold secp256k1 wallet cannot accidentally select the WebAuthn root
  branch.

### Phase 3: Ship The Basic Access-Key Vertical Slice

Objective: deliver constrained background signing with one root prompt.

Deliverables:

- generate a non-extractable WebCrypto P-256 access key in the wallet origin;
- build a typed authorization with chain ID, access-key identity, expiry,
  explicit token limits, and the narrowest available call and recipient scopes
  supported by the pinned network;
- obtain fresh root authorization and bind its signature to the exact canonical
  authorization hash;
- support first-use attachment where the access key signs the transaction that
  carries its root authorization;
- support later `0x03` keychain signatures bound to the root Tempo address;
- read Account Keychain state and reconcile pending authorization into active
  state only after receipt confirmation;
- implement root-signed revoke, event parsing, and fail-closed local
  invalidation;
- expose narrow `createTempoAccessKey`, `getTempoAccessKey`,
  `listTempoAccessKeys`, and `revokeTempoAccessKey` operations;
- add a background-signing operation that accepts only an active access-key
  record and an admitted exact transaction;
- keep agent use behind Refactor 104 admission. Human application sessions can
  use the same chain adapter without inventing an agent identity.

Exit gate:

- one root prompt authorizes a key and the first access-key transaction;
- a later transaction signs without a biometric prompt;
- expiry, token-limit exhaustion, revocation, wrong root address, and local-key
  loss each fail safely;
- the chain and SDK identify the same access key and remaining authority.

### Phase 4: Complete Native Fee Sponsorship

Objective: execute gasless Tempo transactions through the existing sponsorship
policy and ledger boundaries.

Deliverables:

- add a Tempo sponsorship policy executor rather than routing type `0x76`
  through the EVM EIP-1559 raw-transaction executor;
- have the sender sign the canonical placeholder form;
- compute the `0x78` fee-payer digest with the exact sender, fee token, and key
  authorization commitment;
- sign with the configured sponsor secp256k1 key or call a typed remote fee-payer
  service;
- assemble and broadcast the final signed transaction;
- extend resolved policy, idempotency, prepaid reservation, spend caps,
  finalized spend, billing attribution, and audit to the Tempo executor;
- support both root and access-key senders;
- make unsponsored fallback an explicit policy branch. The default sponsored
  operation fails closed.

Exit gate:

- a user with no fee balance completes a sponsored root transaction and a
  sponsored access-key transaction;
- sponsor rejection releases or retains reservations according to the existing
  deterministic settlement rules;
- receipt reconciliation records the exact fee token and finalized sponsor
  spend once.

### Phase 5: Finish Payment Ergonomics And Concurrency

Objective: complete the high-value Tempo transaction features whose wire
foundation already exists.

Deliverables:

- add fee-token lookup, validation, explicit per-transaction selection, and
  account preference reads/writes;
- make batch input non-empty at the type level and validate each call plus
  aggregate value, gas, and token movement;
- simulate the final call set before confirmation when the configured Tempo RPC
  supports the selected simulation method;
- display all calls, decoded selectors, recipients, amounts, fee authority,
  fee token, validity, nonce mode, and access-key constraints;
- implement explicit protocol and user-sequence nonce selection;
- implement the expiring-nonce sentinel with the protocol's bounded validity
  rules and no sequence-lane persistence;
- prove concurrent submission across a small fixed user-sequence pool and the
  expiring mode;
- reconcile receipts by exact nonce mode and transaction identity.
- expose a Viem-compatible account and transaction adapter for the root and
  access-key branches supported through this phase;

Exit gate:

- a multi-call payment is simulated, reviewed, signed, and atomically executed;
- fee-token preference and explicit override both work;
- a concurrency test submits at least 20 transactions from one account without
  nonce collisions or a global sequential bottleneck.

### Phase 6: Add Durable Scheduled Transactions

Objective: turn validity-window signing into reliable future execution.

Deliverables:

- define a scheduled-transaction lifecycle with `prepared`, `signed`,
  `scheduled`, `submitting`, `finalized`, `cancelled`, `expired`, and terminal
  failure branches;
- persist exact signed bytes and immutable schedule identity after signing;
- require `validAfter < validBefore` and a configured maximum schedule horizon;
- submit inside the window through an idempotent server scheduler;
- bind sponsorship reservation lifetime to the schedule or acquire sponsorship
  at submission through a separately authorized flow selected in Phase 0;
- implement cancellation before submission and deterministic behavior after a
  broadcast race;
- avoid nonce starvation by using an approved sequence strategy or expiring
  nonce mode;
- emit durable audit and status events.

Exit gate:

- a transaction signed in advance executes inside its window after client
  shutdown;
- cancellation prevents unbroadcast work;
- expired work never broadcasts;
- retries cannot produce two finalized transactions for one schedule.

### Phase 7: Complete Advanced Access-Key Policy And Agent Projection

Objective: align Tempo's current keychain policy with Refactor 104 without
creating two independent authorization systems.

Deliverables:

- add the Phase 0-selected periodic token limits and limit-update operations;
- add admin keys only behind an explicit separate authorization branch with a
  stronger owner confirmation contract;
- bind authorization witnesses and implement witness burn for signed,
  unsubmitted authorizations where supported;
- project a Refactor 104 `DelegatedSpendAuthorization` into the narrowest
  representable Tempo access-key policy;
- preserve server-canonical constraints the chain cannot express, including
  richer aggregate budgets, tool identity, quote binding, and audit;
- compare final transactions against both policy layers before signing;
- reconcile on-chain remaining limits with server budget and suspend on drift;
- define rotation as a fresh key plus fresh root authorization, followed by
  revocation of the old key.

Exit gate:

- every supported delegated-spend scope either projects exactly, projects to a
  stricter on-chain policy, or fails as unrepresentable;
- agent authorship remains independently verifiable in audit evidence;
- admin, witness, periodic-limit, and update flows have independent vectors and
  on-chain tests.

### Phase 8: Add AA Authorization Lists And Ecosystem Interoperability

Objective: complete the remaining advanced account and integration surface.

Deliverables:

- add typed Tempo EIP-7702 authorization records and supported signature
  branches;
- add the typed plain P-256 root account and signer branch required for full
  signature-scheme parity;
- enforce authority recovery, chain binding, nonce rules, and the prohibition
  on create calls when an AA authorization list is present;
- enable the exact contract-create call branch when the transaction has no AA
  authorization list;
- extend the Viem-compatible local-account adapter with plain P-256, AA
  authorization, and contract-creation support;
- add fixtures that round-trip Seams-signed transactions through current Viem
  decoding and Viem-signed fixtures through Seams decoding;
- publish a final support matrix with code, vector, intended-contract, and
  on-chain evidence links;
- delete temporary low-level exports superseded by the typed public surface.

Exit gate:

- non-empty AA authorization lists execute on the selected test network;
- Viem and Seams agree on addresses, hashes, signed bytes, and access-key
  authorization for every supported account branch;
- no public or core API accepts `TempoRlpValue` or caller-packed signature
  envelopes.

## Verification Strategy

### Cryptographic and wire authority

- Rust vectors own field order, optional trailing fields, signature domains,
  address derivation, RLP, and signed bytes.
- Fixtures must originate independently from the pinned Tempo implementation or
  current Viem Tempo release. Production encoders never generate their own
  expected values during the same assertion.
- Browser WASM replays the same fixtures and must match byte-for-byte.
- Negative vectors cover field confusion between sender, payer,
  key-authorization, WebAuthn, P-256, and keychain domains.

### Type authority

Add type fixtures proving rejection of:

- raw RLP in a public transaction;
- a sponsored fee branch without verified payer identity and signature;
- an access-key signer without root address and active key identity;
- an expiring nonce combined with a user-sequence key;
- a scheduled transaction without both window bounds;
- an AA authorization list combined with a create call;
- a delegated agent execution without Refactor 104 prepared admission;
- broad object spreads that mix root and access-key lifecycle branches.

### Intended behavior

Add focused contracts for:

1. direct passkey-root registration, signing, refresh, and unlock;
2. access-key creation, first use, background reuse, expiry, and revocation;
3. sponsored root and access-key transactions;
4. batch review and atomic execution;
5. concurrent nonce execution;
6. scheduled execution after client shutdown.

Live network tests are environment-gated integration evidence. They do not
replace deterministic vectors or local lifecycle contracts.

## Rollout And Cutover

1. Keep the current secp256k1 Tempo path active while Phases 0 and 1 validate
   identical bytes.
2. Cut over to the exact transaction domain in one release. Delete raw RLP
   public fields and MVP rejection fixtures in that change.
3. Gate each new public operation on a server-published Tempo feature manifest
   tied to the pinned network schema. This is deployment capability, not a
   legacy behavior flag.
4. Roll out direct passkey roots, basic access keys, and sponsorship as separate
   observable vertical slices.
5. Treat persisted access-key and scheduled-operation records as versioned
   boundary formats. Parse them once into the current domain.
6. If a network upgrade changes authorization bytes, suspend creation of new
   affected records until a reviewed schema branch lands. Existing active keys
   follow verified on-chain state.

## Completion Criteria

Refactor 109 is complete when:

- the support matrix marks every P0 and P1 row `supported` with evidence;
- direct secp256k1 and WebAuthn root accounts sign canonical Tempo
  transactions;
- a device-bound access key can be authorized once, sign in the background,
  enforce policy, and be revoked;
- a Refactor 104 agent can use the same chain-native adapter only after owner
  authorization and per-request admission;
- native sponsorship, fee-token selection, batching, concurrency, and durable
  scheduling each work end to end;
- current selected access-key limits and scopes are enforced and reconciled;
- Viem and Seams produce compatible addresses, hashes, and signed bytes;
- the codec has no unsupported-field placeholder or raw RLP escape hatch;
- obsolete MVP rejection tests and compatibility-shaped code are deleted;
- `pnpm test:intended`, the targeted Tempo unit/integration tests, Rust vector
  tests, browser WASM replay, type fixtures, and `pnpm check` pass.

P2 and P3 rows may ship as reviewed follow-up phases if the first production
parity claim explicitly says `Tempo native embedded-account parity` and lists
AA authorization lists and contract creation as deferred. A claim of complete
type-`0x76` protocol parity requires all rows.
