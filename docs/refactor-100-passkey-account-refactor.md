# Passkey Custody Refactor For Wrapped Client Roots And Holder Shares

Date created: June 15, 2026

Last reconciled: August 7, 2026 (single-seed revision; scope/locator review applied)

Status: active design plan. Same-device passkey Ed25519 sealing and rehydration,
durable ECDSA material identity, and the current Email OTP wallet lifecycle have
landed as groundwork. Portable server-held wrapped custody, random-root
registration, mixed-wallet recovery envelopes, and recovery-code unwrap remain
pending. Ed25519 lifecycle behavior must preserve the architecture and
production gates in [router-ab/ed25519-yao/implementation-plan.md](./router-ab/ed25519-yao/implementation-plan.md).

## Dependencies And Authority

This plan owns passkey-controlled client custody. It consumes the completed
Refactor 90 authorization, material-activation, hydration, and durable-owner
contracts; it does not redefine or supply a second owner for those contracts.
Its custody handles enter the canonical Refactor 90 activation boundary through
typed material inputs. That boundary returns the exact
`MpcMaterialActivationRef`; the custody handle never supplies or aliases it.

The follow-on plans are:

- [refactor-101-wallet-execution-lanes.md](./refactor-101-wallet-execution-lanes.md)
  for `WalletKey`, share-bearing execution lanes, and lane identity;
- [refactor-102-share-rotation.md](./refactor-102-share-rotation.md) for
  curve-specific lane provisioning and refresh;
- [refactor-103-device-linking.md](./refactor-103-device-linking.md) for
  physical linked-device product flows;
- [refactor-104-agent-id-spending.md](./refactor-104-agent-id-spending.md) for
  agent-key custody and delegated execution.

Refactor 90 is the authority for canonical active ECDSA capability manifests,
browser persistence, activation commits, hydration, and exact operation-lane
selection. Its `R90-INV-009` and `R90-INV-013` rules govern every authorization
and material handoff in this plan.

The cryptographic authorities are:

- [router-ab/ed25519-yao/implementation-plan.md](./router-ab/ed25519-yao/implementation-plan.md) for Ed25519 registration, recovery, refresh,
  recipient provisioning, activation, signing, and export;
- `crates/router-ab-ecdsa-derivation` for secp256k1 role-local derivation,
  additive shares, threshold signing, and export;
- the Wallet Session model for authorization, exact key bindings, budget, and
  expiry.

This plan does not introduce an alternate signing protocol.

## Goal

Make passkeys and Email OTP interchangeable authentication and unwrap factors
for one random, rotatable wallet custody seed.

Target shape:

```text
WebAuthn user verification + PRF output   (or the Email OTP factor secret)
  -> factor KEK inside the secure worker
  -> opens the wallet custody seed envelope (or one lane holder-share envelope)
  -> parallel domain-separated HKDF derives each owner signing root from the seed
  -> creates an opaque live capability per key
  -> capability participates in the existing Ed25519 or ECDSA lifecycle
```

Adopted August 7, 2026: both factor kinds wrap the same wallet custody seed in
factor-specific envelopes, so one wallet can hold passkey and Email OTP unwrap
paths to identical signing material, and enrolling or revoking one factor never
touches the other factor's envelope or the seed itself.

The passkey PRF output is limited to KEK derivation and authentication binding.
It does not define a wallet key, custody seed, Yao Client root, ECDSA client
root share, or lane holder share after this refactor. Every owner signing root
derives from the seed in parallel; no signing root is ever derived from another
signing root.

## Required Invariants

1. Wallet public identities remain stable during credential replacement,
   envelope rewrap, recovery, and lane refresh.
2. A passkey credential can be revoked independently from a linked-device lane.
3. JavaScript, the app origin, Router, and persistence adapters never receive a
   plaintext client root, holder share, PRF output, or KEK.
4. The browser signing worker owns opened material through opaque handles and
   zeroizes it at lock, page lifecycle termination, success, and failure.
5. Recovery of a mixed wallet covers the exact Ed25519 and EVM-family key set in
   one wallet-scoped operation.
6. Recovery-code consumption commits only after every required key capability
   is activated and identity continuity is verified.
7. Core functions accept precise active-custody states. Raw persistence shapes
   and credential responses are parsed once at their boundaries.
8. Development data created by superseded custody designs is deleted. No
   legacy deterministic-share branch, feature flag, or compatibility lifecycle
   enters core logic.
9. Active passkey custody envelopes are available from an authenticated
   server-side ciphertext store. Browser IndexedDB may cache them, but a
   browser-only record is never the cross-device source of truth.
10. A synced passkey cold unlock reuses the same RP ID, credential ID, PRF,
    custody secret, and active envelope. It creates neither a replacement
    credential nor a recovery-code consumption.
11. Refactor 100 owns portable encrypted custody and factor-specific unwrap.
    Refactor 90 owns the active local ECDSA manifest, encrypted role-local
    material, activation journal, and post-effect hydration result. Refactor
    100 hands opened material into those canonical Refactor 90 boundaries and
    never introduces a second owner for their state.
12. ECDSA cold unlock and recovery preserve the registered public key, address,
    material owner, key slot, and participant binding. They may create a fresh
    threshold session and server generation. An old `AuthorizationGrantRef`,
    `WalletSessionId`, `MpcWalletSigningQuotaId`, `AuthorizedOperationId`,
    bearer credential, nonce, or `MpcMaterialActivationRef` is never copied as
    a new durable identity. A `thresholdSessionId` may remain in an ECDSA
    holder-share envelope as a curve-local protocol binding; it is never a
    wallet-key, lane, or material identity and never replaces
    `MpcMaterialActivationRef`.
13. The current passkey-PRF-wrapped Ed25519 local-material record is a
    same-device continuity cache. It is never treated as the portable custody
    envelope, server source of truth, or random Client root defined by this
    plan.

## Current Seams SDK State

The local SDK already has the following lifecycle foundations:

- passkey Ed25519 registration, same-root recovery, refresh, signing, and export
  run through Streaming Yao A/B;
- the live Ed25519 Client is owned by Rust/WASM. IndexedDB now retains its public
  capability projection plus an authenticated encrypted activated-Client record
  for same-device rehydration. Rust/WASM derives that record's wrapping key from
  `PRF.first`, binds it to the exact wallet, key, credential, RP, lifecycle,
  worker, participant set, public key, and state epoch, and re-verifies the
  threshold public-key relation when opening it;
- passkey PRF input currently derives the stable Ed25519 Yao Client root inside
  Rust/WASM;
- Router A/B ECDSA derivation currently derives the client root share from
  passkey PRF input and activates exact threshold sessions for one EVM-family
  key slot. Registration persists the exact role-local durable material
  reference and public identity needed by later unlock and export flows;
- Email OTP registration, cold unlock, recovery, budget refresh, and ECDSA
  export use factor-owned worker material, durable ECDSA identity, and the same
  Wallet Session admission boundary;
- Ed25519 warm-up is authorized by a server-verified signed Wallet Session, and
  registration derives the effective RP ID from the wallet iframe boundary;
- one Wallet Session authorization (`AuthorizationGrantRef`, with its exact
  `WalletSessionId` and `MpcWalletSigningQuotaId`) can bind an Ed25519 key and
  the exact ECDSA sessions for Tempo and Arc/EVM under one shared budget;
- Email OTP recovery-code backup, status, and rotation UX exists for the current
  enrollment-escrow model. Those codes do not yet open the wallet-scoped mixed
  custody envelope set defined here;
- the explicit custody-secret union, envelope record, wallet-scoped recovery
  envelope set, their branch-specific builders, their boundary parsers, and
  their static fixtures have landed in
  `packages/shared-ts/src/passkey-custody/` and
  `packages/shared-ts/src/wallet-recovery/walletRecoveryEnvelopeSet.ts`, and
  replace the previous generic `PasskeyHolderShareEnvelopeRecord` and
  `RecoveryWrappedHolderShareEnvelopeRecord` scaffolds. They are the frozen
  custody boundary and are not yet wired into random-root registration,
  portable cold unlock, or wallet-scoped recovery;
- linked-device operations remain fail closed.

The current local Ed25519 envelope closes routine same-device continuity. It
does not close any portable-custody phase below: it contains the activated
Client scalar share derived from the current deterministic Client root, lives
only in browser storage, and requires the same credential's PRF output.

The refactor changes every owner root source:

```text
current passkey Ed25519: PRF.first -> deterministic Yao Client root
current passkey ECDSA:   PRF.first -> deterministic client root share
current Email OTP:       random secret32 -> Ed25519 Yao Client root
                            (own extract salt + application binding digest)
                         random secret32 -> threshold-root intermediate T
                            (seams/email-otp/root/v1) -> ECDSA client root
                            share and unlock auth seed, both chained from T:
                            a latent key-separation weakness, deleted by
                            Phase 1B. T is a sibling of the Yao Client root,
                            not its parent, and is never derived in
                            production.

target, both factors:
  random wallet custody seed (generated in Rust)
    -> Ed25519 Yao Client root = HKDF(seed, ed25519 label)
    -> ECDSA client root share = HKDF(seed, ecdsa label)
  seed sealed independently under each enrolled factor KEK and under the
  recovery manifest KEK
```

New registrations use a random seed from their first ceremony. Since the project
is in development, test wallets and obsolete persisted records are discarded
when the new registration path lands. Any retained wallet requires an explicit
identity-preserving protocol from Refactor 102; an envelope rewrite can never
silently change its public key or address.

## Custody Secret Taxonomy

The envelope plaintext must identify the protocol capability it restores.
`holder share` is too broad for the new SDK.

```ts
type PasskeyCustodySecretBinding =
  | {
      // One random seed per wallet. Every owner signing root is derived from
      // it in parallel with domain-separated HKDF; no signing root is derived
      // from another signing root. Each enrolled factor wraps this same seed.
      kind: 'wallet_custody_seed_v1';
      derivationScheme: 'wallet_seed_parallel_hkdf_sha256_v1';
      keyManifestDigestB64u: string;
      nearEd25519SigningKeyId: NearEd25519SigningKeyId;
      registeredPublicKeyB64u: string;
      evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
      clientRootPublicKey33B64u: string;
      walletKeyId?: never;
      laneId?: never;
      laneShareEpoch?: never;
      participantBindingDigestB64u?: never;
      thresholdSessionId?: never;
      thresholdPublicKey33B64u?: never;
    }
  | {
      kind: 'ed25519_lane_holder_share_v1';
      walletKeyId: WalletKeyId;
      laneId: SigningLaneId;
      laneShareEpoch: LaneShareEpoch;
      nearEd25519SigningKeyId: NearEd25519SigningKeyId;
      registeredPublicKeyB64u: string;
      participantBindingDigestB64u: string;
      derivationScheme?: never;
      keyManifestDigestB64u?: never;
      evmFamilySigningKeySlotId?: never;
      clientRootPublicKey33B64u?: never;
      thresholdSessionId?: never;
      thresholdPublicKey33B64u?: never;
    }
  | {
      kind: 'ecdsa_lane_holder_share_v1';
      walletKeyId: WalletKeyId;
      laneId: SigningLaneId;
      laneShareEpoch: LaneShareEpoch;
      evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
      // Protocol-session binding only; this is not a durable key or material identity.
      thresholdSessionId: ThresholdEcdsaSessionId;
      thresholdPublicKey33B64u: string;
      derivationScheme?: never;
      keyManifestDigestB64u?: never;
      nearEd25519SigningKeyId?: never;
      registeredPublicKeyB64u?: never;
      participantBindingDigestB64u?: never;
      clientRootPublicKey33B64u?: never;
    };
```

Owner registration and same-root recovery use the seed branch. The Yao
key-creation signer slot and stable-context binding are registration-ceremony
facts owned by the Yao boundary; they are verified there against the derived
root, not stored in custody. A physical
linked-device lane may receive a lane-specific holder-share branch produced by
the protocol in Refactor 102. Refactor 104 owns agent-key custody and any
optional delegated-execution holder package; it cannot reuse passkey custody
implicitly. The `thresholdSessionId` on an ECDSA holder-share branch is a
curve-local protocol binding. It may rotate with the threshold protocol and
never substitutes for wallet key, lane, `MpcMaterialActivationRef`, or any
authorization identity.
Builders must be branch-specific. Core code never constructs this union with a
broad spread or an `as` cast.

Passkey custody records carry no authorization identity. At execution,
`R90-INV-009` admits one exact `AuthorizedOperation` from exactly one source:
the reusable branch names an `AuthorizationGrantRef` and resolves its
`WalletSessionId` and `MpcWalletSigningQuotaId`, while the step-up branch carries
only verified evidence and its `AuthorizedOperationId`. Both branches resolve
the exact `MpcMaterialActivationRef` independently. A recovery code and an
opened custody handle are factors or material inputs; neither is an authorization
grant, Wallet Session, quota, or operation identity.

## Passkey Envelope Records

Replace the generic `PasskeyHolderShareEnvelopeRecord` with a union whose
plaintext kind is explicit.

```ts
type PasskeyCustodyEnvelopeLifecycle =
  | {
      state: 'active';
      activatedAtMs: number;
      retiredAtMs?: never;
      revokedAtMs?: never;
    }
  | {
      state: 'retired';
      activatedAtMs: number;
      retiredAtMs: number;
      revokedAtMs?: never;
    }
  | {
      state: 'revoked';
      activatedAtMs: number;
      revokedAtMs: number;
      retiredAtMs?: never;
    };

// Which enrolled factor sealed this envelope. Factors are interchangeable
// unwrap paths to the same custody seed; each factor has its own envelope,
// KEK derivation, and revocation.
type WalletCustodyEnvelopeFactor =
  | {
      kind: 'passkey';
      rpId: string;
      credentialIdB64u: string;
      kekVersion: 'passkey_prf_kek_hkdf_sha256_v1';
    }
  | {
      kind: 'email_otp';
      enrollmentId: string;
      enrollmentSealKeyVersion: string;
      kekVersion: 'email_otp_factor_kek_hkdf_sha256_v1';
    };

type PasskeyCustodyEnvelopeRecord = {
  kind: 'wallet_custody_envelope_v2';
  envelopeId: PasskeyEnvelopeId;
  walletId: WalletId;
  binding: PasskeyCustodySecretBinding;
  factor: WalletCustodyEnvelopeFactor;
  envelopeRevision: number;
  nonceB64u: string;
  sealedCustodySecretB64u: string;
  ciphertextDigestB64u: string;
  aadHashB64u: string;
  lifecycle: PasskeyCustodyEnvelopeLifecycle;
  createdAtMs: number;
  updatedAtMs: number;
};
```

The record above supersedes the landed passkey-only
`passkey_custody_envelope_v1` shape (Phase 1B task): the factor union makes
passkey and Email OTP interchangeable unwrap paths to the same custody seed.
It stores ciphertext and public binding data. It cannot store a raw secret, PRF output, KEK, recovery code, or
live capability handle. It also carries no `AuthorizationGrantRef`,
`WalletSessionId`, `MpcWalletSigningQuotaId`, `AuthorizedOperationId`, or
bearer-session identity; those values are resolved for an operation by the
Refactor 90 boundary.

The canonical portable envelope is stored server-side so a browser with no
prior IndexedDB state can retrieve it after an exact WebAuthn assertion. The
server store is opaque custody storage: it validates credential, wallet,
envelope lifecycle, revision, and ciphertext/public-binding digests, but cannot
open the envelope or report its plaintext as live. A browser cache is
non-authoritative and must match the exact server envelope revision and digest
before use.

Envelope retrieval requires a server-verified assertion for the exact wallet,
RP ID, credential ID, operation challenge, and active credential binding. The
PRF result is removed before the assertion crosses the worker boundary. Only
the secure worker receives the PRF result, derives the KEK, and opens the
returned ciphertext.

Registration records WebAuthn PRF support plus the credential backup-eligibility
and backup-state observations. Backup flags are advisory credential metadata;
they do not prove that a provider will return the same PRF on another device.
Cross-device custody is enabled only after an actual PRF result has sealed the
server-held envelope. Cold unlock still requires a successful PRF result.

## Recovery Envelope Set

A recovery code protects a wallet-scoped set of custody entries. It is not
modeled as an independent recovery code per curve.

```ts
type WalletRecoveryEnvelopeEntry = {
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  custodySecretKind: PasskeyCustodySecretBinding['kind'];
  nonceB64u: string;
  wrappedCustodySecretB64u: string;
  aadHashB64u: string;
};

// One recovery code's wrap of the set's random manifest KEK. The frozen
// design is two-level: code -> manifest KEK -> per-entry wrap keys. A code
// never wraps a custody entry directly.
type WalletRecoveryManifestKekWrap = {
  recoveryKeyId: DerivedWalletRecoveryKeyId;
  nonceB64u: string;
  wrappedManifestKekB64u: string;
  aadHashB64u: string;
  lifecycle: RecoveryCodeLifecycleState;
};

type WalletRecoveryEnvelopeSetRecord = {
  kind: 'wallet_recovery_envelope_set_v1';
  walletId: WalletId;
  keyManifestDigestB64u: string;
  manifestKekWraps: readonly WalletRecoveryManifestKekWrap[];
  entries: readonly WalletRecoveryEnvelopeEntry[];
  issuedAtMs: number;
  updatedAtMs: number;
};
```

The manifest contains the exact active owner key/lane set. Under the
single-seed model the owner coverage is one `wallet_custody_seed_v1` entry;
per-lane holder-share entries appear only for linked-device lanes. Parsing
rejects an
empty set, duplicate wallet keys, duplicate lanes, omitted required keys, and
entries outside the authenticated wallet.

Use ten single-use codes, matching the existing Email OTP recovery UX. Each
code wraps the same manifest KEK; consuming or revoking one code touches only
its wrap. A code is reserved during recovery and becomes consumed only after
the complete new credential activation commits. Failed pre-commit recovery
releases the reservation. Failed post-commit Yao recovery follows the
forward-only recovery rules in
`router-ab/ed25519-yao/implementation-plan.md`. A consumed-code recovery mints
a fresh manifest KEK and rewraps the set, and a key-manifest change (new
wallet key, lane refresh) requires code rotation because entries cannot be
added without the manifest KEK.

## KEK And AAD Binding

KEK derivation is versioned and bound to the credential and relying party.

```text
passkey_kek = HKDF-SHA256(
  ikm = WebAuthn PRF.first,
  salt = versioned application salt,
  info = hash(rpId, credentialId, walletId, envelopeId, purpose, version)
)
```

Envelope AAD includes:

- wallet ID;
- wallet key ID and curve-specific key-slot identity;
- lane ID and lane share epoch;
- custody-secret kind;
- registered public key or EVM address binding;
- participant or threshold-session binding;
- Yao stable-context and key-creation signer slot where applicable;
- Router A/B signing-root identity and version;
- factor kind, plus credential ID and RP ID (passkey) or enrollment
  identity (Email OTP);
- envelope, KEK, and protocol versions.

`MpcMaterialActivationRef` is bound when opened material enters the canonical
activation boundary. It is deliberately separate from the envelope's stable
custody binding so explicit material reactivation can mint a fresh activation
ID without rewriting the wallet key or address. Authorization identities are
never used as envelope AAD or custody locators.

The worker recomputes AAD from parsed domain records. Callers cannot supply an
arbitrary AAD blob.

## Registration Flow

1. Parse the exact wallet registration intent and signer-set selection.
2. Create the `WalletKey` inventory and owner lane identities.
3. Create the passkey and obtain required PRF output inside the secure-confirm
   worker.
4. Generate one random wallet custody seed inside Rust/WASM and derive every
   owner signing root from it in parallel with domain-separated HKDF:
   - the Ed25519 Yao Client root;
   - the Router A/B ECDSA client root share.
   No signing root derives from another signing root.
5. Execute the existing key-family registration protocols with those imported
   seed-derived roots.
6. Verify the returned Ed25519 public key, ECDSA public key, EVM address,
   participant bindings, threshold sessions, and the Wallet Session
   authorization (`AuthorizationGrantRef`, `WalletSessionId`, and
   `MpcWalletSigningQuotaId`) established by the canonical Refactor 90 path.
7. Seal the wallet custody seed under the registering factor's KEK; each
   later-enrolled factor seals the same seed in its own envelope.
8. Create the recovery envelope sets from the same seed.
9. Submit the registration effects to their canonical durable owners using one
   exact registration correlation. Gateway D1 owns the product ceremony,
   public wallet records, passkey-envelope metadata/ciphertext, recovery-set
   metadata, activation results, Wallet Session authorization, quotas,
   authorized operations, and authorization audit. Deriver A/B private D1 owns
   role custody and one-use cryptographic state; SigningWorker private D1 owns
   activated material, delivery, cryptographic effect deduplication,
   presignature or Yao material consumption, and terminal response replay.
   Router only forwards typed commands and owns no mutable registration state.
   Each server effect is idempotent and queryable by its correlation and exact
   receipt. After every required server receipt and activation read-back is
   present, the browser performs one atomic IndexedDB finalization for local
   envelopes, public projections, and lifecycle facts. Registration reports
   cross-device custody ready only after that convergence.
10. Zeroize seed, derived-root, and PRF inputs on every exit.

The Yao Client-root source becomes a precise union with a seed-derived-root
branch. The PRF-derived-root branch and the Email OTP chained derivations are
deleted when this flow lands.

## Unlock And Ordinary Signing

1. Resolve the exact active server-held passkey envelope set for the requested
   wallet and credential. A matching browser cache may satisfy the ciphertext
   read only after exact revision and digest validation.
2. Run WebAuthn and derive the passkey KEK inside the worker.
3. Open only the custody entries the requested operation needs: the seed
   entry restores every owner signing root in one open; lane holder-share
   entries stay per-lane.
4. Convert opened material into opaque Rust/WASM handles:
   - an Ed25519 Yao Client capability or lane holder capability;
   - an ECDSA role-local client-root or holder-share capability.
5. Resolve authorization and material as separate identities. A reusable
   operation resolves its `AuthorizationGrantRef` to the exact
   `WalletSessionId` and `MpcWalletSigningQuotaId`; a step-up operation carries
   verified evidence and its `AuthorizedOperationId` without a grant, Wallet
   Session, or reusable quota. Independently resolve the lane, key,
   participant, curve-local threshold-session binding, and exact
   `MpcMaterialActivationRef`.
6. Submit the admitted `AuthorizedOperation` and exact material activation
   through the existing Router and SigningWorker path.

Ordinary Ed25519 signing performs zero Yao evaluations and zero Deriver calls.
Ordinary ECDSA signing performs no role-local root derivation after the live
capability is ready. Warm sessions retain opaque handles with bounded TTL and
uses. They never cache PRF output or plaintext roots in JavaScript.

## Synced-Passkey Cold Unlock

Passkey-provider synchronization is a cold-unlock path, not credential
replacement. It applies when the same credential is available on a browser or
device with no prior Seams IndexedDB state.

1. Resolve the active credential and envelope manifest from the server by wallet
   and exact credential identity.
2. Run WebAuthn at the wallet RP ID with the exact credential and versioned PRF
   input. Keep the PRF result in the secure worker while sending only the
   PRF-redacted assertion for server verification.
3. After successful assertion verification, fetch the exact active ciphertext,
   envelope revision, public binding, and digest.
4. Derive the same passkey KEK and open the existing custody entries. Do not run
   deterministic PRF-root derivation and do not create a new passkey envelope.
5. Verify every opened root against the registered Ed25519 public key or ECDSA
   public key, address, material-owner, key-slot, participant, and lifecycle
   binding before publication.
6. Feed each verified capability into its canonical activation boundary. ECDSA
   uses the Refactor 90 activation journal and exact read-back path; Ed25519 uses
   the corresponding Yao publication/durability boundary. Ordinary hydration
   preserves the current exact `MpcMaterialActivationRef`.
7. Resolve operation authorization separately from material. A reusable
   operation admits its `AuthorizationGrantRef`, `WalletSessionId`,
   `MpcWalletSigningQuotaId`, and `AuthorizedOperationId`; a step-up operation
   admits its `AuthorizedOperationId` from verified evidence and carries none of
   those reusable identities. Threshold sessions, Wallet Sessions, quotas, and
   server generations may rotate as protocol or authorization facts, but they
   are never recovered from the portable custody envelope. Explicit material
   reactivation is the exception: it creates a fresh `MpcMaterialActivationId`
   and `MpcMaterialActivationRef` through the Refactor 90 activation journal.
8. Report success only after exact canonical re-resolution is sign-ready for
   every requested capability. A partial mixed-wallet unlock cannot publish a
   shortcut ready record for its successful companion.

This flow requires no recovery code, Email OTP recovery, new credential,
credential tombstone, or linked-device lane. Missing, conflicting, revoked,
unsupported-PRF, digest-mismatched, and unavailable envelope states fail
explicitly; none fall back to fresh share derivation.

Provider synchronization and hybrid "use another device" authentication are
separate compatibility cases. Supporting one does not imply that the other
returns a usable PRF result. Test and report them independently; when PRF
evaluation is unavailable, route to recovery-code recovery or explicit device
linking rather than changing the custody root.

## Credential-Replacement Recovery Flow

1. Authorize the wallet recovery request with Email OTP through the canonical
   Refactor 90 admission boundary, then supply one unused recovery code as the
   custody-envelope unwrap factor. The recovery code is a custody factor, not
   an `AuthorizationGrantRef`, Wallet Session, quota, or operation identity.
2. Reserve the recovery code and resolve its exact key manifest.
3. Open every recovery-wrapped custody entry inside the recovery worker.
4. Create the replacement passkey and its KEK.
5. Run Ed25519 Yao same-root recovery for each Ed25519 root entry.
6. Rebind and explicitly reactivate each ECDSA client-root entry while
   preserving the threshold public key, address, material owner, key slot,
   participants, and registered lifecycle identity. Explicit reactivation
   creates a fresh `MpcMaterialActivationId` and `MpcMaterialActivationRef`
   through the Refactor 90 activation journal. Activate a fresh threshold
   session and server generation when required; do not copy the prior
   threshold-session ID, `AuthorizationGrantRef`, `WalletSessionId`,
   `MpcWalletSigningQuotaId`, `AuthorizedOperationId`, bearer credential, or
   nonce state.
7. Seal every custody entry under the replacement passkey KEK.
8. Verify identity continuity for the complete manifest.
9. Apply the idempotent Gateway/worker server effects and query their exact
   receipts. Gateway D1 consumes the reserved recovery code only after every
   required activation receipt verifies. The browser then atomically finalizes
   the replacement envelope set, prior-credential tombstone, and local
   lifecycle facts in IndexedDB. Router remains a stateless forwarding
   boundary; the server and browser commits converge by exact correlation and
   do not pretend to be one transaction.
10. Zeroize all opened recovery material.

Recovery never creates a new wallet key, key-creation signer slot, registered
Ed25519 public key, EVM address, or EVM-family key slot.

## Additional Credentials And Linked Devices

Adding another passkey envelope to an existing owner lane keeps:

```text
same wallet key
same lane ID
same lane share epoch
same custody secret
new credential and envelope IDs
```

Use this for an additional platform passkey, hardware authenticator, or
credential replacement on the same owner lane. A new credential has a distinct
credential ID and PRF, so an already authorized owner factor, recovery factor,
or linked-device protocol must open the existing custody secret before it can
be resealed under the new credential's KEK.

Do not use this transition for ordinary passkey-provider synchronization.
Synchronization makes the same credential and PRF available on another device;
the synced-passkey cold-unlock flow reuses its existing active envelope.

QR-linked device creation keeps the wallet keys and creates:

```text
one new linked-device enrollment
one new linked-device lane per required wallet key
new holder material per lane
new matching SigningWorker or relayer material per lane
new passkey envelopes on Device 2
```

Refactor 102 owns the key-family provisioning ceremony. Refactor 103 owns the QR
and product behavior.

## Credential And Device Management

- Removing one passkey revokes its envelope set and invalidates its live
  handles.
- Removing a synced passkey leaves the lane active when another active envelope
  protects the same custody secret.
- Suspected plaintext exposure triggers lane refresh through Refactor 102.
- Revoking a linked device revokes its enrollment and all child lanes. Owner
  lane envelopes remain active.
- Credential replacement and device revocation are separate user operations.

## Where This Stands (2026-08-09)

57 of 71 boxes. Phase 2 is complete; Phase 3's NEAR half is complete; Phases 4
and 5 have their load-bearing primitives with every guard mutation-checked.
The refactor's defining property is proven in a circuit test: register a wallet
under one factor, enrol a second by resealing the envelope, unlock with the
second alone.

**Verified by types, unit and circuit tests — never yet against running
services.** The spliced registration path compiles and its parts are tested in
isolation; no wallet has been registered through it end to end. Two of the open
boxes exist for exactly that.

The fourteen open boxes are not more of the same work, and it is worth knowing
which is which before picking one up:

- **One is a decision** — the ECDSA ownership handoff under *Decisions
  Required*. It cannot be implemented around: minting an
  `MpcMaterialActivationRef` locally would be a second owner for state Refactor
  90 owns, which Invariant 11 forbids. The Ed25519 path only avoided it because
  the Router mints that identity in its receipt.
- **Three are blocked behind that decision** — the EVM install, shrinking
  `wasm/ecdsa_registration_client`, and deleting the PRF-derived signing-root
  paths. The last also needs the Email OTP and mixed registration paths spliced,
  which was deliberately not done: splicing NEAR alone for a mixed wallet leaves
  a half-covered recovery set.
- **Three need Refactor 102** to deliver lane holder material first.
- **Two need a live stack** — the dev-wallet wipe, and proving synced cold
  unlock end to end.
- **Five are flows**, each spanning server routes, client wiring and UI. Their
  cores exist as primitives; what remains is the orchestration.

**Cold unlock (2026-08-09).** Every piece now exists, is tested, and is
reachable from JavaScript: the store has a DI site and a service-bag port, the
retrieval route is registered with its assertion bound to a server-issued
challenge, and the client has the RPC, the join-wire projection, the cache
reader, the wasm open path, the metadata assembly and the warm/cold branch.
What is left is the last mile — calling `openOrRejoinWalletCustodyEd25519V1`
from the unlock surface, where the factor secret and the wallet session live,
and driving `rejoinNearEd25519CustodyV1` on its rejoin branch.

**Cold unlock itself is now composed** (`coldUnlock.ts`): fetch, project,
rejoin, persist, with the forced order tested and each retrieval failure
keeping its own code. That path never reads a local cache — a new device has
none by definition — so it did not need the decision below, which turned out
to gate only the *warm* path.

**The warm path does need that decision, and it is not a small one.** The
hydration site (`ed25519YaoLocalMaterial.ts`, the
`rehydrate_material_activation` branch) has the activation facts and the
factor secret, and no custody envelope — because *the client never stores
one*. The envelope is committed to the server at registration and cached
nowhere locally.

That matters more than it first reads, because the seed is never retained:
`open_wallet_custody_ed25519_material_v1` re-derives it by opening the
envelope on **every** unlock. So the continuity cache as it stands saves the
Router ceremony round and not the network round — a warm unlock still cannot
complete offline.

Two ways out, and they differ in cost rather than correctness:

1. **Cache the envelope locally.** It is ciphertext plus public binding and
   carries no client secret, so it is safe at rest under the same argument
   that lets it cross the network. This needs a new IndexedDB store and a
   schema bump (v13 → v14), which touches every existing wallet's local
   state, and the cached copy must be revision-checked against the server's
   `envelopeRevision` before it is trusted — a stale local envelope and a
   rewrapped server one would fail to unlock with a correct credential.
2. **Fetch the envelope per unlock.** No migration, no staleness question, and
   unlock keeps a hard network dependency that the phrase "same-device
   continuity cache" does not suggest to a reader.

This is recorded rather than decided because the migration is user-visible and
the offline property is a product question, not an implementation detail. It
blocks warm-path latency, not correctness: cold unlock works without it, and
a warm unlock that fetches its envelope is correct, just not offline.

**And one finding that resizes those flows (2026-08-09).** The passkey-custody
envelope storage layer is built, tested, and *entirely unwired from the running
server*: `CloudflareD1PasskeyCustodyEnvelopeStore` is referenced by type in the
domain code and constructed **only in tests** — no DI site builds one, and no
route service exposes one.

So cold unlock is not one route away. The order is: construct the store beside
the other custody stores at the auth-service DI site, expose it as a route
service, register the retrieval route, then add the client RPC and the unlock
composition. The wire mapping for that route now exists
(`passkeyCustodyEnvelopeRetrievalRoute.ts`), so the first two steps are what
stands between a tested layer and a reachable one.

This is the same shape as the earlier finding that nothing consumed
`ecdsaReadyStateBlobB64u`: a layer whose tests all pass and whose production
callers do not exist. Worth checking for deliberately — a green suite says
nothing about whether anything calls the thing it covers.

**A third instance, found the same day.** The Ed25519 continuity cache had
`persistWalletCustodyEd25519MaterialV1` and no loader: written at
registration, never read, so every unlock paid for the Router round the cache
exists to avoid. Now readable, with `absent` and `unusable` kept distinct.

**A fourth, which was the real blocker.**
`open_wallet_custody_ed25519_material_v1` existed in Rust, was tested, and had
no `wasm_bindgen` export — so JavaScript could not call it and the cold unlock
composition had nothing to call. Exporting it forced a decision worth
recording: the two wasm modules each define their own `WasmActivatedClientV1`,
warm unlock imports from the yao client's, and a handle from the wrong module
cannot sign. So the export belongs in `router-ab-ed25519-yao-client`, which
required moving `ed25519_local_material_binding_v1` down beside the opener —
the ceremony can reach down to it, unlock could never have reached up.

**And the same shape across all of Phase 4.** `runWalletRecoveryWithCode`,
`admitWalletRecoveryCredentialPromotion` and the recovery-key-id derivation
were exported, tested, and called only by their own tests. Phase 4 was never
"unstarted" — its primitives were complete and unreachable, exactly as cold
unlock's were. What it needs is a route, an RPC and a surface, which is the
same three-piece shape, not more crypto.

**Spending a code is now wired end to end** — domain
(`walletRecoveryAttempt.ts`), route (`/wallets/recovery/spend`) and client RPC
(`walletRecoverySpend.ts`). It needed no new store: each manifest KEK wrap already carries its own lifecycle, so a
spend is a versioned update to the record registration already writes. Three
properties are pinned there because each fails silently — an unknown code and
a spent code answer byte-identically (otherwise the route counts how many of
the user's ten remain), the spend is written before the payload is returned,
and the write is guarded against the version the read observed.

Five instances in one refactor is a pattern, not coincidence. Each was a
half-built seam that typechecked and tested green because *nothing on the
other side existed to disagree with it*. When adding a producer, check for
the consumer; when adding a store, check for the DI site; when adding a
write, check for the read. The test suite will not ask.

**So the honest reading of the five flow boxes is one sentence:** every one of
them has its primitives written and mutation-checked, and none of them is
reachable from a running system. That is a single kind of remaining work —
route, RPC, surface — repeated five times, and it is why the box count has
stopped being a useful measure of what is left.

A note for whoever picks this up: converting a flow box into a primitive closes
the box and leaves the flow. Several boxes above were closed that way
deliberately, because the primitive is the part with the security properties —
but the orchestration is still owed, and the box no longer says so.

## Implementation Phases

### Landed Lifecycle Groundwork

- [x] Seal activated passkey Ed25519 Client material inside Rust/WASM under an
      authenticated, identity-bound same-device envelope.
- [x] Rehydrate that material for routine unlock, signing, and budget refresh;
      reserve explicit Yao recovery for device-linking and export operations.
- [x] Persist durable ECDSA role-local material identity during registration and
      resolve it through current passkey and Email OTP lifecycle paths.
- [x] Restore current Email OTP registration, unlock, recovery, budget refresh,
      and export behavior for the mixed wallet.

These checkpoints preserve today's deterministic root sources. They are inputs
to the replacement work below and do not authorize retaining deterministic
root derivation after random-root registration lands.

### Phase 0: Freeze Custody Boundaries

- [x] Replace the generic holder-share envelope model with the explicit custody
      secret union.
- [x] Add branch-specific builders and boundary parsers.
- [x] Add static fixtures rejecting cross-curve fields and raw-secret records.
- [x] Delete obsolete custody envelope types and fixtures. The generic
      `PasskeyHolderShareEnvelopeRecord`, `RecoveryWrappedHolderShareEnvelopeRecord`,
      their single-purpose KEK contexts, and their fixtures are gone.
- [ ] Delete the deterministic PRF-root lifecycle types themselves. These stay
      until Phase 2 lands a random-root registration path: they are the live
      Ed25519 and ECDSA root sources, not scaffolding.

### Phase 1: Envelope Crypto

- [x] Implement passkey KEK derivation in Rust
      (`crates/signer-core/src/passkey_custody.rs`, feature `passkey-custody`).
      The AAD is recomputed there from the parsed binding, so a caller passes
      records and never an opaque AAD blob.
- [x] Implement authenticated seal/open for every custody-secret branch.
- [x] Implement the wallet recovery envelope-set crypto
      (`crates/signer-core/src/wallet_recovery_custody.rs`): code KEK opens the
      manifest KEK, manifest KEK derives per-entry KEKs.
- [x] Expose the custody seal/open through the browser worker's wasm boundary
      (`wasm/near_signer/src/passkey_custody_wasm.rs`). Opened material returns
      as an opaque handle with no byte accessor, and custody secrets are
      generated inside Rust, so JavaScript can neither read nor supply plaintext
      custody material.
- [x] Implement recovery-code reservation
      (`packages/shared-ts/src/wallet-recovery/recoveryCodeReservation.ts`).
      Reserve -> consume-on-commit, release on pre-commit failure, and
      time-bounded holds so an abandoned recovery cannot strand a code.
- [x] Implement the server-side opaque passkey-envelope store with exact
      credential, wallet, lifecycle, revision, and digest lookup results
      (`packages/sdk-server-ts/src/router/cloudflare/d1/passkeyCustody/`).
      Built on `CloudflareD1VersionedJsonRecordStore`; revoked rows are retained
      as credential tombstones and excluded from active retrieval.
- [x] Implement authenticated envelope retrieval that verifies the WebAuthn
      assertion while keeping PRF output inside the secure worker
      (`packages/sdk-server-ts/src/router/domains/passkeyCustody/`). Retrieval
      rejects an assertion that still carries any WebAuthn extension output
      before verification runs, so a leaked PRF result fails loudly instead of
      being silently sanitized and served.
- [x] Persist PRF support and WebAuthn backup observations without treating
      backup eligibility or backup state as proof of cross-device PRF
      continuity (`packages/shared-ts/src/passkey-custody/credentialObservations.ts`).
      `resolveCrossDeviceCustodyReadiness` takes PRF support and the active
      sealed envelope only; backup flags are not parameters, so a
      "backed up therefore portable" conclusion cannot be written.
- [x] Add AAD substitution and ciphertext tamper tests
      (`crates/signer-core/tests/passkey_custody_envelope.rs` and
      `crates/signer-core/tests/wallet_recovery_custody.rs`).

### Phase 1B: Single-Seed Custody Revision

Adopted August 7, 2026. Passkey and Email OTP become interchangeable unwrap
factors for one wallet custody seed, and every owner signing root derives from
the seed in parallel. This also removes a latent Email OTP key-separation
weakness: the ECDSA client root share and unlock auth seed were both chained
from one intermediate (`seams/email-otp/root/v1`), so any holder of that
intermediate could compute both from public context.

Independent review on August 7, 2026 corrected an earlier overstatement of this
weakness. The chaining parent is NOT the Ed25519 Yao Client root: that root is
derived by `derive_ed25519_yao_client_root_from_email_otp_factor_v1` under its
own extract salt and expand domain, and binds the application binding digest.
The intermediate is a sibling of it, both derived from `secret32`. No
production code derives the intermediate — the Email OTP worker imports only
the two leaf functions — so there was no demonstrated live exposure path, and
holding the Ed25519 Yao Client root never conferred the ECDSA share or unlock
seed. The weakness was structural and latent; the fix is warranted on
key-separation grounds, not incident grounds.

Wiping dev OTP wallets was approved August 7, 2026 on the operator's assertion
that none are in production. That deployment fact is not verifiable from
repository evidence.

- [x] Amend this plan for single-seed custody, parallel derivation, and
      factor-kind envelopes (this revision).
- [x] Replace Email OTP's chained derivations with parallel domain-separated
      derivation from `secret32`; delete the chained paths and their v1
      labels (`wasm/email_otp_runtime`, labels
      `seams/email-otp/ecdsa-client-share/v2` and
      `seams/email-otp/unlock-auth/v2`).
- [x] Delete the retired Email OTP chain parent (the `seams/email-otp/root/v1`
      intermediate, its wasm export, and its test helpers). Nothing derived it
      after parallel derivation landed, and its "threshold root" name collided
      with the MPC threshold protocol — the collision that caused a
      misdiagnosis during this revision. The key-separation tests recompute it
      locally instead.
- [x] Collapse the custody-secret union's two owner root branches into one
      `wallet_custody_seed_v1` branch; lane holder-share branches unchanged.
- [x] Add the factor-kind union (`passkey` | `email_otp`) to the custody
      envelope record, KEK context, server store, and authenticated
      retrieval. The store addresses envelopes by factor rather than by
      credential; assertion-gated retrieval serves passkey envelopes only.
- [x] Mirror the union and factor changes in the signer-core binding, AAD
      encoding, and the near_signer wasm boundary. Wallet and lane scope are
      distinguished by an explicit AAD scope marker, so neither encoding can
      be a prefix of the other.
- [x] Implement seed -> parallel HKDF derivation of the Ed25519 Yao Client
      root and ECDSA client root share
      (`crates/signer-core/src/wallet_seed_derivation.rs`). Frozen labels:
      `seams/wallet-custody/seed/ed25519-yao-client-root/v1` and
      `seams/wallet-custody/seed/ecdsa-client-root-share/v1`. Both take the
      seed directly as IKM; neither root is a function of the other.
- [x] Make manifest verification fail closed. `verify_wallet_key_manifest_v1`
      recomputes the canonical manifest digest from the derived public
      identities and rejects any mismatch. Callers must run it before
      publishing a capability or consuming a recovery code, and must abort
      rather than continue with partial results. This is what a stored
      `keyManifestDigestB64u` is worth: the record parser never verifies it.
- [x] DECIDED (August 7, 2026) — lane coverage: a recovery set carries the
      owner seed and nothing else. A linked device's holder share is sealed
      under that device's own factor, so it never depended on the owner
      credential and survives owner recovery untouched; carrying it in the
      owner's set would instead let an owner recovery code reconstruct that
      device's material, collapsing the device separation Refactor 103
      creates. A lost lane is revoked and reprovisioned through Refactor 102,
      not recovered. Both parsers reject lane kinds in a recovery entry.
- [x] FIX (August 7, 2026) — the key manifest moves **off** the seed and
      becomes a per-key-set record, correcting an over-constraint introduced
      earlier in this refactor.

      The defect: the manifest digest was bound into the seed envelope's AAD
      and into the KEK context of every recovery wrap, so the seed
      self-certified "I control exactly these two keys". Nothing required that.
      The EVM-family and NEAR Ed25519 key sets are independent, and binding
      them to one manifest coupled them for no benefit. The visible symptoms
      were that a key set could not be added later without resealing the
      envelope and rewrapping all ten recovery codes, and that the ceremony
      appeared to need both protocols completed together — which read as a
      conflict with Refactor 94C's deferred-Yao contract. Both symptoms came
      from the coupling, not from 94C and not from the product shape.

      Correct shape:

      - The seed envelope binds to wallet, envelope, factor, and derivation
        scheme. No manifest digest, so it is sealed once and never resealed as
        key sets arrive.
      - Each key set records its own manifest when it registers.
      - The fail-closed gate survives, scoped per key set: to publish
        capability for a key set, the derived identity must reproduce *that*
        key set's recorded manifest. Same property, narrower subject.

      Once decoupled, each key set provisions on its own schedule and 94C's
      ordering is untouched: the EVM wallet commits its custody immediately and
      Ed25519 records its manifest whenever its Yao work settles.

      Consequence to accept: the recovery wrap scopes lose the key manifest
      digest, and with it the property that a wrap cannot be moved onto a set
      whose manifest has since changed. That guard was protecting key rotation;
      with per-key-set manifests a rotation no longer invalidates the seed, so
      the guard moves to the per-key-set gate rather than disappearing. Wallet
      id remains the wrap's binding, and there is one seed per wallet.

      Dependency: provisioning a second key set in a *later session* requires
      opening the existing seed, which is the Phase 3 cold-unlock path. Same
      session needs nothing new.

      ACCEPTANCE CRITERIA — the other half of this fix. Review found that
      moving the manifest off the seed makes *absence* unauthenticated. Under
      the old shape the manifest lived in the seed envelope's AAD, so a
      provisioned key set could not be made to disappear without breaking the
      envelope. A free-standing manifest row can simply be deleted, and both
      readers would treat that as "not provisioned yet": provisioning would
      re-register the key set, and recovery would restore fewer key sets than
      the wallet has and report success. Substitution still fails closed;
      absence would not fail at all.

      The manifest digest therefore gets **no record of its own**. It is a
      field on the operational registration state that signing already depends
      on, so that deleting it breaks signing loudly rather than narrowing the
      wallet silently:

      - EVM family — the registered slot state, whose relayer share every 2PC
        signature needs.
      - NEAR Ed25519 — the registration record, cross-checkable against the
        access keys on the NEAR account itself, which the Gateway does not
        control.

      Required behaviour:

      1. Enumerate key sets from operational registration state, never from
         "which manifest records exist". For NEAR, cross-check on chain.
      2. Verify per enumerated key set, fail closed. Recovery must restore
         exactly the enumerated set — restoring fewer is a failure, not a
         partial success.
      3. A key set whose registration already exists re-runs in continuity
         mode, never Establish, so an induced re-run either reproduces the
         identical key or fails. `prepare_client_recovery_with_root_v1` is that
         seam on the Yao side.
      4. Commit outcomes: no custody → generate seed, seal, issue recovery set,
         CAS-insert. Custody exists, including on a lost race → open the
         existing envelope and add this key set only. Never generate a second
         seed. Test before implementing: concurrent EVM and NEAR ceremonies end
         with one seed envelope, one recovery set, two manifests.

      Residual, stated rather than papered over: a server restoring an old
      snapshot rewinds registrations and digests together. No client-side
      scheme beats wholesale rollback without an external anchor — detectable
      for NEAR via chain state, for EVM once the address has on-chain history,
      and otherwise in the denial-of-service class the server always had.
- [x] Rebuild the ceremony as one key set per run.
      `wasm/wallet_custody_ceremony` now provisions a single key set per run,
      and a run is one of two things:

      - **establish** — the wallet's first key set. The seed is generated here,
        its envelope is sealed, and the ten-code recovery set is issued.
      - **join** — a later key set. The seed comes from opening the existing
        envelope, and the run writes *nothing* but its own key manifest.

      `CustodyOriginV1` carries which, and `finish` refuses the two crossed
      combinations outright: an establishing run that seals nothing, and a
      joining run that tries to seal a seed or issue codes. That second refusal
      is the one that matters — a joining run which sealed would give the
      wallet a second seed and a second recovery set, leaving half its keys
      uncovered by either. `join_existing_custody` is the only constructor for
      the join origin and it requires a successful envelope open, so the
      authorisation is structural rather than a flag.

      Continuity is wired through: a key set whose registration already exists
      passes its registered public key, and the run takes
      `prepare_client_recovery_with_root_v1` instead of the registration seam.
      An induced re-run then reproduces the identical key or fails.

      Deleted with the coupling that required them:
      `derive_wallet_seed_owner_roots_v1` and its equal-digest tripwire. Paired
      derivation only ever existed because one manifest named both key sets.
      The ceremony is smaller for it — one seed, one root, one protocol, one
      manifest per run.

      The commit payload changes shape to match: `establishedCustody` is
      present only on an establishing run, and the manifest digest is returned
      for the caller to write onto that key set's *registration state*, never
      to a record of its own.
- [x] Rework the circuit tests for the new shape, and restore the ceremony's
      own tests. The rebuild had dropped `ceremony::tests` wholesale along with
      the paired states they were written against, so `ceremony.rs` had no
      tests at all; the circuit tests had been detached from `lib.rs` and
      nothing compiled them.

      The circuit tests now prove what the decoupling was for. An EVM-family
      run establishes custody — seed sealed, ten codes issued — with no Router
      execution request in existence, so the Yao circuit has nothing it could
      have been asked to do. A NEAR run reaches that same seed by opening the
      envelope that run sealed, and commits its manifest and nothing else.

      No test starts from a fixed seed any more: `from_seed_for_test` is gone
      with the states it belonged to, and a joining run's seed arrives the way
      production's does, so the seed-continuity assertions cannot pass by
      agreeing with themselves. Checked by mutation — replacing the envelope
      open with a fresh seed fails six of the eight circuit tests.

      Two beyond the happy path: a re-derived EVM key set is checked against
      its recorded digest through the verifying constructor, which is what
      recovery must be able to do; and a NEAR re-run over a recorded key takes
      the recovery seam and lands on the identical key, while one told to
      preserve a key this seed does not produce fails rather than registering a
      replacement.

      24 tests in the crate, ~6s. The `router-ab-dev` harness is unchanged.
- [x] Align the TypeScript layer. The seed binding now carries `kind` and
      `derivationScheme` only, the recovery set no longer names a key manifest,
      and the commit payload splits into `establishedCustody` plus the key set
      this run provisioned. The commit adapter refuses a joining run's payload
      rather than half-building records from absent fields.

      This closed a live defect: `near_signer`'s parser uses
      `deny_unknown_fields` and had already dropped the five manifest fields,
      so every TypeScript-built seed binding would have been rejected at
      runtime. No suite caught it, because the Rust and TypeScript unit suites
      each test only their own side. A cross-boundary wire fixture would.

      Also fixed while here: `clientRootPublicKey33B64u` belongs to no binding
      now, so the unknown-field guard reported it as plaintext custody material
      — it matches the `clientroot` substring. It is a published point, so a
      field naming itself a public key is exempt from that classification while
      still being rejected.
- [ ] Wipe dev OTP wallets and obsolete persisted records with the Phase 2
      test-wallet reset.
- [x] Record a naming glossary in `AGENTS.md` fixing each custody term to one
      referent, plus the suffix convention (bare `root` names a secret
      derivation origin; `RootId`, `RootVersion`, and `RootShareEpoch` name
      metadata about it and are never key material).

### Phase 2: Seed-Root Registration

- [x] Add seed-derived Client-root input to Yao registration
      (`prepare_client_registration_with_root_v1` plus
      `client_application_binding_digest_v1`, so callers derive against the
      exact digest the protocol verifies). The seed root is bound to the same
      application binding digest the PRF root used, so only the secret's
      origin changed.
- [x] Add seed-derived client-root-share input to ECDSA derivation. The
      bootstrap seam already accepted a root share, so no new entry point was
      needed; the seed-derived share flows through
      `prepare_ecdsa_client_bootstrap` unchanged. Both curves' derivations now
      take the application binding digest their own protocol computes, so a
      caller cannot bind to something the protocol will not verify.
- [x] DECIDED (August 7, 2026) — module topology: custody ceremonies get their
      own wasm module, `wallet_custody_ceremony`, statically linking
      `signer-core`, `router-ab-ed25519-yao-client`, and
      `router-ab-ecdsa-derivation`.

      A **custody ceremony** is a flow that derives owner roots *and* verifies
      the key manifest: initial registration and recovery re-establishment.
      Adding a second factor to an existing wallet is not one — it reseals a
      seed whose manifest was verified when it was admitted — so it stays in
      `near_signer` with the other custody primitives.

      Why a module at all: custody lived in `near_signer`, Yao registration in
      `router-ab-ed25519-yao-client`, ECDSA bootstrap in
      `router_ab_ecdsa_derivation_client`, and no module depended on the
      others. A seed-derived root could not reach its protocol without crossing
      JavaScript as bytes, which invariant 3 forbids. One module reaching both
      protocol crates is the only way to close that gap; both already build as
      `rlib` as well as `cdylib`, so this is a new target, not new plumbing.

      Why not `near_signer`: it loads for every NEAR signing operation and
      carries a bundle-size guard. Hosting registration there would pull
      frost/curve25519 *and* k256 registration code onto the recurring signing
      path for a flow that runs once per wallet. Ordinary Ed25519 signing
      already sits in `near_signer` and links no registration crate; that stays
      true.

      Why not the existing `wasm/ecdsa_registration_client`, despite the name:
      it is not registration-only. `open_ecdsa_role_local_signing_share_v1`
      runs at rehydration, and both `ecdsa-derivation-client.worker.ts` and
      `email-otp.worker.ts` load the module, so adding Yao dependencies would
      grow a recurring download. Its API surface is also built on the pattern
      this refactor removes — `prepare_..._from_resolved_email_otp_root_v1`
      takes a raw root share as base64 JSON, `open_...` returns
      `signingShare32B64u`, and its pending state blob carries `x_client32` in
      plaintext across JS — so placing no-secrets-cross-JS exports beside those
      would mislead reviewers. Several of those exports are Phase 2 deletion
      targets anyway. Once registration leaves it, rename it around role-local
      material rehydration or fold that remainder into its natural owner rather
      than leaving a compatibility shell under a misleading name.

      Rules the module is built to:

      - Every ceremony completes inside one module instance. Custody code is
        duplicated by static linking into both modules; secrets are never
        transferred between them.
      - Interactive protocol rounds hold session state as a wasm-memory handle,
        not a state blob through JavaScript. The existing role-local blob
        carries plaintext key material and must not be inherited. Seal any
        state that genuinely has to survive a module reload.
      - Network messages still travel through JavaScript: they carry public
        protocol data only.
      - Typestate transitions: `seed held → protocols prepared → manifest
        verified → envelopes sealed → public commit payload produced`. Every
        failure transition destroys the seed, the roots, and the ceremony
        state.
      - Verify-and-commit is atomic *within* the module: manifest verification
        and envelope sealing happen in one transition. JavaScript performs the
        server write, receiving ciphertext and public records. No verification
        token crosses the wasm boundary — a token that came back would prove
        only that some verification once succeeded.
- [x] Build the `wallet_custody_ceremony` registration typestate.
      `wasm/wallet_custody_ceremony` links `signer-core`, the Yao client, and
      the ECDSA derivation crate, and implements the transitions:
      `CeremonySeedHeldV1 → CeremonyProtocolsPreparedV1 →
      CeremonyProtocolsCompletedV1 → CeremonyManifestEstablishedV1 →
      WalletCustodyCommitPayloadV1`. Each transition consumes `self`, so a
      failure drops the state and zeroizes the seed and session material.

      What the structure buys, beyond what any signature could:

      - The two owner roots are never fields of any state. They exist only
        inside `prepare`, where they pass straight into the two protocol
        preparations, so no caller-reachable value ever holds a root.
      - The Ed25519 binding digest is computed inside `prepare` from the typed
        application facts via `client_application_binding_digest_v1` — the same
        function the protocol verifies against — and is not a parameter.
      - The ECDSA pending state blob stays in wasm memory between rounds. It
        carries `x_client32` in the clear, so the standalone bootstrap module's
        habit of handing it to JavaScript is deliberately not inherited.
      - The manifest proof is a private field of
        `CeremonyManifestEstablishedV1` and never crosses the boundary.
        Verify-and-seal is one transition; there is no verified state a caller
        can hold or replay.
      - Nonces for the envelope, the ten code wraps, and the recovery entry are
        generated inside `seal`, so a caller cannot reuse one across two seals.

      Registration mints its manifest digest through
      `establish_wallet_key_manifest_v1` rather than the verifying constructor:
      no envelope exists yet, so there is nothing to reproduce. Recovery and
      cold unlock must use `verify_registered_wallet_key_manifest_v1`, which
      compares and can fail. Separate functions so a reader can tell which a
      path took.

      Known asymmetry, recorded rather than papered over: the ECDSA binding
      digest arrives in the relayer's bootstrap response and cannot be
      recomputed client-side the way the Ed25519 one can. The ECDSA protocol
      binds it through `contextBinding32`, which the caller cross-checks. That
      is a property of the two protocols, not of this module.
- [x] Drive the whole ceremony through the real Router A/B circuit.
      `src/circuit_tests.rs` runs both Derivers locally over an in-process
      relay — the genuine Yao circuit, not a stub — and finalizes ECDSA against
      a relayer identity composed by the protocol itself. Thirteen tests now
      cover the module: seven own the output contract (the sealed envelope
      opens back to the ceremony seed, all ten recovery codes reach it, nonces
      are unique per ceremony, a partial set or malformed manifest aborts
      before anything is sealed) and six own the protocol half:

      - a ceremony completes both protocols and commits one key manifest, with
        the envelope binding recording exactly the digest it established;
      - the registered public key equals the Router receipt's;
      - the same seed registers the same owner keys across two independent
        sessions with fresh Deriver keysets, while the ciphertext still
        differs — nonces and the manifest KEK are per-ceremony;
      - a different seed registers a different key manifest;
      - a Router result from another session cannot complete the ceremony;
      - a relayer identity whose group key is not the sum of the client and
        relayer keys is refused, so the wallet cannot be bound to a threshold
        key the seed-derived share does not participate in.

      Note on what this does and does not prove. That the Ed25519 binding
      digest is the protocol's own is a *compile-time* property —
      `RegistrationProtocolInputsV1` has no field for it — not something these
      tests establish: a ceremony using a wrong digest would still derive a
      valid root and complete the circuit, just for a different key. The tests
      establish that the ceremony drives both real protocols to completion and
      that its outputs are stable and seed-determined.
- [x] Add the `wasm_bindgen` boundary. `src/wasm.rs` exposes one entry point,
      `wallet_custody_ceremony_begin_registration_v1`, and four state handles.
      Each transition takes `self` by value, and wasm-bindgen nulls the
      JavaScript object's pointer when a method consumes it — so a caller
      physically cannot reuse an advanced state, retry a failed transition, or
      seal twice. The typestate and the JavaScript object graph enforce the
      same rule.

      Yao activation entropy is generated at this boundary rather than
      accepted, so JavaScript cannot supply the recipient key material or the
      Deriver seal seeds. The Rust-side inputs struct still takes entropy
      because the circuit tests must control it to play the Deriver roles.
      `RegistrationProtocolInputsWireV1` has no field for the Ed25519 binding
      digest and uses `deny_unknown_fields`, so a caller supplying one is
      rejected rather than silently ignored.

      Decoders return `String` and convert to `JsValue` only at the edge:
      `JsValue::from_str` aborts on non-wasm32 targets, which would otherwise
      make the hand-written address and base64url parsers untestable on the
      host. Three tests cover them.
- [x] Gate the Ed25519 Yao client's own `#[wasm_bindgen]` surface behind a
      default-on `wasm-bindings` feature. A cdylib inherits every
      `#[wasm_bindgen]` export it can see through its rlib dependencies, so the
      first real `wasm-pack` build of the ceremony module re-exported the
      crate's PRF registration and recovery sessions *and*
      `WasmExportedEd25519SeedV1` — Ed25519 seed export — from a boundary that
      has no business offering them. The ceremony crate now depends with
      `default-features = false`; the standalone Yao build keeps the feature
      and is unchanged. The published surface is one function and four state
      handles, and the binary dropped from 538,910 to 427,005 bytes.
- [x] Commit the server-held envelope and recovery set atomically.
      `CloudflareD1WalletCustodyCommitStore.commitRegistration` writes both rows
      in one D1 transaction through `putMany`.

      Atomicity is why this is a store rather than two sequential writes. The
      two partial outcomes are not equally bad. A recovery set with no envelope
      leaves a wallet no factor can open — loud, and retried. An envelope with
      no recovery set leaves a *working* wallet whose owner believes they hold
      ten recovery codes that were never stored: silent, and discovered only
      when recovery is attempted. Neither state is reachable now.

      Both records share the envelope key prefix, because a D1 batch is scoped
      to one store instance and one instance is one prefix. Their keys cannot
      collide: an envelope key is a JSON array and begins with `[`, a
      recovery-set key begins with `recovery-set:`. The envelope key builder is
      exported from the envelope store and used by both, so there is one
      definition — a second spelling would write rows no lookup could find.

      Both writes are inserts, never updates. A repeated ceremony for a wallet
      that already has custody is refused rather than overwriting a seed whose
      keys are already registered. A pair naming two wallets or two key
      manifests is refused before anything is written, since a recovery set
      whose codes open a seed for a manifest the envelope does not name would
      recover keys the wallet never registered.
- [x] Build the ceremony worker. `wallet-custody-ceremony.worker.ts` owns the
      wasm state handle across the two Router/relayer round-trips, keyed by a
      ceremony id, so the seed, the owner roots, and the ECDSA pending blob
      never exist as JavaScript values. The main thread carries public protocol
      messages between rounds and ciphertext at the end.

      The worker mirrors the Rust typestate at the message layer: a step *takes*
      the handle out of the map before advancing, and only a successful
      transition puts the next one back. A failed step therefore ends the
      ceremony instead of leaving a half-advanced state to retry into. There is
      no `completed` state in the map — completing the protocols and
      establishing the manifest are one message, so a completed-but-
      unestablished handle never waits on a caller.

      In-flight ceremonies are bounded: each holds custody material, so a caller
      that abandons them fails rather than growing the map. `discard` drops a
      handle, which zeroizes the seed and any in-flight protocol state.
- [x] Adapt the ceremony's commit payload into the two stored records.
      `buildWalletCustodyRegistrationRecords` parses the payload through the
      same boundary parsers every other reader uses, and
      `commitWalletCustodyRegistration` builds then commits, so a malformed
      ceremony result is a request outcome rather than a route crash and
      nothing is written in that case.

      The envelope binding is carried through from the ceremony's own JSON, not
      reassembled from loose fields: the binding is what the AAD was computed
      over, so any field this server re-derived instead of carrying would
      produce an envelope that cannot open. Refused: a binding naming another
      wallet or another key manifest than the payload, a set that is not
      exactly ten wraps, duplicate recovery key ids (a code is found by id, so
      duplicates would silently shrink the set), and malformed nonces,
      ciphertext, or digests.
- [x] Wire the ceremony worker into `SignerWorkerManager`.
      `WalletCustodyCeremonyWorkerOperationMap` types one operation per step,
      `walletCustodyCeremony` joins `SignerWorkerOperationMapByKind`, and the
      transport gains a spawn case and a URL resolver. The worker's frames
      already matched the `{id, ok, result}` RPC shape, so the generic
      fall-through handles dispatch — with one explicit narrowing branch,
      because TypeScript cannot correlate `kind` with `request` once the
      fall-through union has more than one member.

      `WalletCustodyCeremonyCommitPayload` moved to `@shared/passkey-custody`
      so the SDK channel and the Gateway commit path describe it once. Two
      spellings would diverge silently, and the first symptom would be a stored
      envelope that never opens.

      Compile-time fixtures in `workerTypes.typecheck.ts` pin what the channel
      may carry: a caller supplying a wallet custody seed fails to compile, and
      the seal result has no seed and no manifest KEK.
- [x] Add the client-side ceremony driver.
      `runWalletCustodyRegistrationCeremony` orders the three worker steps
      around a caller-supplied `runRouterRound`, so the network shape stays with
      the registration flow that owns it and the driver stays testable without
      one.

      Its real job is cleanup. A ceremony holds a seed in the worker until it
      seals, and the worker only drops a handle when a step *it* ran threw — a
      Router round-trip that fails leaves a live ceremony the worker knows
      nothing about. Every exit that is not a completed seal discards, and a
      discard that itself fails does not mask the original error: the caller
      must learn why the ceremony failed, not why cleanup did.
- [x] Split `registration.ts` so the splice below is reviewable. Move-only, in
      two commits, 7,402 → 4,250 lines: `registrationTiming.ts` (55
      declarations), `registrationStrictEcdsa.ts` (32), and
      `registrationEd25519Yao.ts` (34).

      Each extraction ran as a script over exact line ranges and was verified
      byte-identical to the original text once `export` prefixes are normalised
      away — nothing was retyped. Cluster boundaries were chosen by measuring
      references in both directions and absorbing back-references until only
      type-only ones remained, not by grouping on name. The three-route ECDSA
      orchestration deliberately stayed behind: it calls `registerWallet`, the
      warmup, and app-session helpers, so moving it would have created a real
      import cycle rather than a type-only one.
- [x] Realign the ceremony's worker channel to one key set per run. The worker
      and driver were still on the paired wasm API and typechecked only because
      `wasm/wallet_custody_ceremony/pkg` is a gitignored artifact whose local
      copy predated the rebuild. Rebuilt, and moved over: a run declares its
      origin (establish or join) and its key set, the worker dispatches
      completion from the key set it stored, and the driver makes both refused
      combinations unrepresentable rather than merely rejected.
- [x] Splice the ceremony into `registration.ts` and commit its payload.
      **Landed 2026-08-09** for the Ed25519-only passkey path (`52162fc46`).

      **Blocked on a decision, found 2026-08-09: the splice cannot establish
      custody until wallet-scoped recovery codes can be issued, and they
      cannot be today.**

      An establishing run structurally requires exactly ten codes —
      `finish()` refuses `(Establish, None)`, correctly, because an envelope
      with no recovery set is the silent failure the atomic commit above exists
      to prevent. So the splice needs code issuance, which is Phase 4's
      unchecked "Bind ten single-use codes to the wallet-scoped mixed-custody
      envelope set".

      What exists and what does not:

      - Code *formatting* is shared already — `buildWalletRecoveryCodeSet`,
        `formatWalletRecoveryCode`, `normalizeWalletRecoveryCode` are the Email
        OTP primitives re-exported under wallet names
        (`shared-ts/src/wallet-recovery/recoveryCodes.ts`).
      - Code *identity* is not. `deriveEmailOtpRecoveryKeyId` binds the id to
        an Email OTP enrollment — `enrollmentVersion` and
        `enrollmentSealKeyVersion` are fields in its HKDF tuple
        (`utils/emailOtpRecoveryKey.ts:305-335`). A passkey wallet has no
        enrollment, so this derivation cannot mint ids for a wallet-scoped
        custody set at all.
      - Every current caller sidesteps it: the ceremony's own tests and
        fixtures spell ids as `email-otp-rkid-v1-code-{index}` or a bare
        SHA-256, and the ceremony never checks the format. The TypeScript
        parser does (`email-otp-rkid-v1-` plus 43 base64url chars), so the two
        sides already disagree about what an id is.

      **Built so far (2026-08-09), leaving one dependency.** The primitives the
      splice needs now exist and are tested:

      - `issueWalletRecoveryCodes` mints the ten codes from the platform
        CSPRNG, with no `Math.random` fallback.
      - `establishNearEd25519CustodyV1`
        (`sdk-web/.../walletCustody/registrationCeremony.ts`) issues the set,
        runs one NEAR key set, and returns the codes, the wire payload, the
        continuity cache, and the Yao activation reference.
      - The wire payload is a *projection*: the cache and the ECDSA
        ready-state blob come back as their own fields, so "send the payload"
        cannot send client signing material by accident.
      - The activation reference is parsed from the round the run performed —
        the PRF path read it off the active client it kept, and a ceremony
        keeps no client.

      **The persistence counterpart now exists too (2026-08-09).** The blocker
      recorded here was that the Ed25519-only passkey path ends by handing its
      `pending` registration to `persistPasskeyRegistrationEd25519Material`,
      which seals under `PRF.first` — and a ceremony produces a seed-sealed
      record and no `pending`. Both halves of that are built:

      - `walletCustody/ed25519SeedMaterial.ts` stores the wallet-scoped record.
        One row per wallet, replacing the two per-factor rows that existed only
        because two factors wrapped them. Its binding names the key set and no
        credential, and the builder takes ciphertext rather than a live client,
        so it *cannot* seal — the wrapping key derives from the seed, which
        never crosses the ceremony's wasm boundary.
      - The ceremony now reports `ed25519ApplicationBindingDigestB64u`, because
        opening the cache rebuilds the exact seal binding and that digest is
        one of its fields. Reported rather than recomputed: a reader
        reassembling it from loose application facts could differ by one byte
        and hold a record that never opens.
      - `walletCustody/ceremonyStepRunner.ts` adapts the worker transport to
        the driver, and is the single place the ceremony's channel name is
        spelled — a run's seed lives in one worker's state across all three
        steps, so a step dispatched elsewhere finds no run to continue.

      **All that remains of the splice is the call-site edit** in
      `registration.ts`'s Ed25519-only passkey path: run the ceremony instead
      of `registerVerifiedPasskeyEd25519YaoV1`, pass the projected payload as
      `walletCustodyCommit` on route 4 with `established.activationReference`,
      persist through `persistWalletCustodyEd25519MaterialV1`, act on the
      returned `walletCustody` outcome, and surface the recovery codes. The
      downstream calls in that path (`storeWalletEd25519RegistrationData`,
      `upsertEd25519YaoPublicCapabilityLaneReference`,
      `persistRegistrationPasskeyEd25519SealedRuntime`) still read the
      PRF-path's `pending`, so each needs its facts sourced from the
      ceremony's payload instead — that is the bulk of the remaining edit.

      **DECIDED AND FROZEN (2026-08-09).** Issuance moves into Phase 2, because
      establishing custody must atomically issue the recovery set. Phase 4
      keeps recovery *use*: backup acknowledgement, rotation, status, and the
      recovery UX.

      The derivation, frozen verbatim:

      ```text
      digest = SHA-256(length-prefixed tuple(
        "seams/wallet-recovery/recovery-key-id/v1",
        base64url(recoveryCodeBytes),
        walletId,
        "wallet_recovery_envelope_set_v1"
      ))

      recoveryKeyId = "wallet-rkid-v1-" || base64url(digest)
      ```

      - **Factor-neutral id and prefix.** `email-otp-rkid-v1-` is neither
        reused nor reinterpreted.
      - **Not bound to `envelopeId`.** Recovery is wallet-scoped and must
        survive adding, rewrapping, and revoking factor-specific envelopes; the
        establishing envelope is incidental. (This corrects an earlier
        suggestion here that included it.)
      - **SHA-256 is intentional, not a shortcut.** This is an
        identifier/verifier derived from a 160-bit random code, not key
        material. The dedicated domain and canonical tuple provide separation
        without implying the output is a key.
      - **Derived inside Rust/WASM from `walletId + codeBytes`.**
        `RecoveryCodeInputV1` does not accept a caller-supplied id; each sealed
        wrap returns the id that was derived for it, and the same derivation is
        exposed for recovery lookup. This removes the ceremony/parser
        disagreement structurally rather than by convention, and needs
        cross-boundary vectors.
      - **`DerivedWalletRecoveryKeyId` and its parser are wallet-owned types.**
        The canonical code constants and formatting implementation move under
        `wallet-recovery`; Email OTP consumes those wallet primitives. The
        Email-OTP-owned aliases and the old derivation are deleted when the
        enrollment-escrow path is removed.

      **Two boundary defects to fix while here** (both in the recovery-set
      parser, both compatibility paths that hide a real invariant):

      - `parseWalletRecoveryEnvelopeSetRecord` must require *exactly ten*
        wraps. It accepts 1–10 today, though establishment and the durable
        invariant both require ten lifecycle records.
      - Remove stale `keyManifestDigestB64u` acceptance and its comments. The
        manifest moved to per-key-set registration state; silently accepting
        and dropping the retired field is a compatibility path.

      **The earlier note here was wrong and the shape of the work is different
      from what it described.** It said the ceremony needs both protocols
      prepared before either completes, because one seed feeds two. That was
      true of the paired ceremony; with one key set per run it is not, and the
      two key sets can be provisioned in separate runs at separate times.

      **Decision (2026-08-07, refined 2026-08-08): EVM registers a
      seed-derived share on the router-ab registration route — with no wire or
      Router change.** The route keeps its three legs, its `signedSetup`, its
      relayer, and its existing payload kinds. The strict rounds keep running
      (they provision the SigningWorker's relayer half); what changes is
      client-side only: the activation facts are computed from the ceremony's
      seed-derived share instead of the Deriver-delivered `xClientBase`, which
      the server accepts because it never verified the client share's
      provenance (see the flow map below for the proof chain). The custody
      seed becomes the derivation authority for the client half, so no Deriver
      pair can reconstruct the client share of a seed-root wallet.

      Why the rounds cannot be *fed* the seed root: in the strict protocol the
      client is a *recipient* of `xClientBase`, derived from the two derivers'
      root halves — there is no input slot for a client-chosen root. That is
      unlike Yao, where the client was always a contributing party. But no
      input slot is needed: the client simply does not use what the rounds
      deliver for its half, and nothing server-side ever depended on it doing
      so.

      Two earlier notes here are superseded: `thresholdEcdsaDerivationRoleLocalBootstrap`
      is *not* the carrier — it has no server counterpart at all; the
      `ecdsa-derivation-role-local` format is the registration route's own
      activate output, not a separate service. And nothing about this is "the
      route Email OTP already uses": every registration today goes through the
      strict rounds.

      **Server flow map (traced 2026-08-08).** What the payload kind actually
      touches, and the one finding that widens its scope:

      - Respond's ECDSA branch is a *forwarder*: the Gateway handler
        (`walletRegistrationRoutes.ts:1889`, parser `:1921`, kind gate `:1989`)
        calls `respondWalletRegistration`
        (`d1WalletRegistrationService.ts:2343`), which — after signed-setup
        verification, plan cross-check, and authority verification — POSTs to
        the **Rust MPCRouter worker** at `/router-ab/ecdsa-derivation/register`
        (`routerAbEcdsaStrictRegistration.ts:280`, Rust handler
        `router-ab-cloudflare/src/lib.rs:4792`), which runs Deriver A and B as
        role Workers and returns the proof bundles.
      - **The relayer's public identity is not Gateway state.** It arrives only
        in the *activation receipt* from the Rust worker
        (`ecdsa_activation.public_identity`, read at
        `d1WalletRegistrationService.ts:863`); the Gateway shape-validates it
        (`validation.ts:452`) and composes nothing —
        `compose_public_identity_from_public_keys` runs only in client wasm
        today. So the seed-root kind reaches into the Rust worker: it needs a
        mode with **no deriver rounds**, where the SigningWorker derives its
        relayer share against the client's seed-derived public key and returns
        the composed identity in the receipt. The primitive exists:
        `derive_relayer_share_for_client_public`
        (`router-ab-ecdsa-derivation`), already exercised in
        `signer-core/tests/native_readiness_vectors.rs`.
      - Respond-before-activate is enforced by stored branch state, not
        convention: respond is the only writer of
        `evm_family_ecdsa_pending_activation` and of `authorityState:
        verified`; activate's claim requires exactly that branch kind
        (`d1RegistrationCeremonyStore.ts:135`) and one `activationOwner` per
        ceremony. The seed-root kind keeps this machine — what changes is what
        the pending branch holds (no Router bundles, no `pendingActivation`
        blob) and what activate forwards.
      - **SUPERSEDED (2026-08-08): no Router change is needed at all.** An
        earlier note here concluded the seed-root mode was a new Router path.
        Verifying that claim disproved it. The Router never checks the client
        share's provenance: at activation the SigningWorker composes the
        receipt identity from `client_activation.derivation_client_share_public_key33_b64u`
        — the client's claimed facts — against its own opened material
        (`lib.rs:3215`); the request's `validate()` pins only request-side
        digests, and `transcript_digest` is a pure function of the registration
        request (`to_threshold_prf_request()`), computable by the client
        without opening a bundle. The Gateway's `requireActivatedEcdsaIdentity`
        checks the receipt *echoes the claim* — consistency, not provenance.
        The Deriver-derived `xClientBase` was always a derivation service *for
        the client*, whose proofs the client verifies; the server never
        depended on the client using it.

        So the seed-root client share rides the existing protocol unchanged: the
        client runs registration exactly as today, and presents activation
        facts computed from its seed-derived share instead of `xClientBase`.
        The rounds keep running because they still do necessary work — they
        provision the SigningWorker's own output material (`y_relayer`), the
        relayer half of the 2-of-2. "The strict rounds stop producing EVM keys"
        is precise only as: they stop producing the *client* half. The
        delivered-but-unused `xClientBase` is transitional dead weight;
        skipping it is an optional later Router optimization, not a
        prerequisite. No new payload kind is needed either — the wire shape of
        the activation facts is identical, and the wallet's seed-root
        provenance is already recorded by the custody commit itself (the EVM
        key set's manifest digest on registration state).
      - The full inventory of files gating the kind literals (parsers,
        contracts, stored-branch decoders — including
        `d1RegistrationCeremonyRecords.ts:1200`, which hard-codes
        `evm_family_ecdsa_keygen`, and the exhaustiveness guards that will
        fail to compile on a new arm) is in the respond/activate trace; start
        from `parseWalletRegistrationRespondRequest` and
        `RegistrationCeremonyStore.ts:268-371`.

      **The agreement is proved (2026-08-08).**
      `crates/signer-core/tests/seed_root_ecdsa_registration.rs` drives the
      whole substitution in-process against the production functions on both
      sides — seed → HKDF → `prepare_ecdsa_client_bootstrap` on the client,
      `derive_relayer_share_for_client_public` on the SigningWorker,
      `finalize_ecdsa_client_bootstrap` back on the client — and they land on
      one threshold key and one address. So the remaining work on this item is
      wire and state plumbing, not cryptography.

      It also pins two properties the plumbing must not lose: the same seed
      re-registers the same address (recovery), and a different SigningWorker
      answering the same client yields a different wallet (the seed is one half
      of a 2-of-2, never the whole). Mutation-checked — flipping one bit of the
      client public key the server derives against fails five of the seven.

      The ordering worry recorded here earlier was overstated. The ECDSA
      application binding digest is available before any Router leg: the local
      `create` step computes it from the setup response's `strictRegistration`
      facts (`ceremony.registration_binding()`, exposing
      `applicationBindingDigestB64u`), and it is that same digest the current
      flow later hands to `prepareRouterAbEcdsaRoleLocalClientBootstrap`. The
      relayer's bootstrap value echoes `applicationBindingDigestB64u` and
      `contextBinding32B64u` back, so the finalize cross-check stays.

      **Decision (2026-08-07): the digest requirement stays.** Dropping it from
      the seed derivation was considered and rejected: it buys nothing for
      ordering — the role-local bootstrap runs under
      `RouterAbEcdsaDerivationStableKeyContext`, which is built from the same
      digest at the same moment, and `contextBinding32` is how both sides agree
      what is being registered — and it is a real property, not ceremony. The
      binding means a run induced under a wrong or foreign context derives a
      *different* key rather than reusing the wallet's real share there, and it
      keeps the two key sets' derivation models symmetric (the Ed25519 root is
      bound to its Yao application binding digest the same way). Recovery
      already depends on the digest being stable — that is what the *Stable* in
      the context type means.

      The NEAR half has no such obstacle: the Ed25519 binding digest is
      computed inside the ceremony from the typed application facts, so a NEAR
      run can begin as soon as its admission receipt exists. Refactor 94C's
      contract still holds — deferred NEAR work is handed off before activate
      and never awaited.

      Its seam is narrow and known: `RouterAbEd25519YaoClientV1.registerAdmitted`
      builds a `WasmClientRegistrationSessionV1` from `secret32` — the passkey
      PRF result or the Email OTP factor key. The ceremony takes the same
      admission, application binding and participant ids and differs only in
      where the root comes from, so this is a substitution rather than a
      restructure.

      **Blocker found 2026-08-08: the NEAR ceremony run produces no signing
      material, and the splice cannot land until it does.**
      `CeremonyProtocolPreparedV1::complete_near_ed25519`
      (`wasm/wallet_custody_ceremony/src/ceremony.rs:455`) calls
      `complete_client_activation_v1`, keeps only
      `activated.registered_public_key()`, and drops the `ActivatedClientV1` —
      which zeroizes on drop. Its EVM sibling does the opposite: it carries the
      finalized `ready_state_blob` out through
      `ecdsa_ready_state_blob_b64u`.

      This is not a substitution the client can paper over. The ceremony *is*
      the registration for a spliced NEAR key set — it builds the execute
      request through `prepare_client_registration_with_root_v1` — so running
      `registerAdmitted` alongside it for material would derive a second,
      different root. As built, a seed-derived NEAR wallet would register a
      public key it holds nothing to sign with.

      **Where the material has to end up, and the decision that shapes it.**
      Today the same-device continuity cache is sealed *per factor*:
      `WasmActivatedClientV1::seal_local_material` takes `PRF.first`,
      `seal_email_otp_local_material` takes the enrollment secret, each under
      its own salt and info
      (`crates/router-ab-ed25519-yao-client/src/wasm.rs:566-602`). Constraint 13
      already says that record is a same-device continuity cache and never the
      source of truth — but per-factor sealing contradicts what this refactor is
      for: a wallet that registered under a passkey and later added Email OTP
      would miss the cache on every OTP unlock and have to reproduce the
      material through a Router round.

      **Recommendation: seal the continuity cache under the custody seed**, in
      its own domain-separated HKDF alongside the two root derivations, so
      either factor reaches it after opening the envelope it already has to
      open. That keeps the seal inside the ceremony's wasm boundary, which is
      the invariant the crate exists for — the seed never crosses to JS, so
      nothing else *can* seal it. It needs a new Rust-callable seal/import pair
      in `router-ab-ed25519-yao-client` (both the primitive and its salts are
      private to `wasm.rs` today), then `ed25519LocalMaterialB64u` on the commit
      payload as the NEAR analogue of the EVM ready-state blob.

      This is a new seal domain, so it is a decision rather than a mechanical
      step: the alternative is to seal per factor at the ceremony boundary and
      accept a cache miss whenever a wallet unlocks under a factor it did not
      register with.

      **Decision reviewed and confirmed (2026-08-08): seal under the custody
      seed.** The review sharpened three things beyond the original framing:

      - *Per-factor-times-N ("seal under both") is unsound multi-device, not
        merely stateful.* Factor add happens on one device; another device's
        IndexedDB cannot gain the new factor's wrap without a re-seal ceremony
        on that device, so a later-added factor never opens existing caches.
        It degenerates to per-factor with more state. Ruled out. Seed-sealing
        handles the same case by construction: the *server* envelope gains a
        wrap (`reseal_wallet_custody_seed_under_new_factor_v1`), and a stale
        local envelope copy just refetches once.
      - *Seed-sealing has two real costs.* (1) Warm unlock changes shape from
        `factor → open cache` to `factor → KEK → open envelope → seed → HKDF →
        open cache`, so the envelope ciphertext must be cached locally or warm
        unlock gains a server fetch. (2) The seed materializes on every warm
        unlock instead of only during ceremonies — it stays inside wasm and
        zeroizes, and the client scalar share it unwraps is equal-value
        material that materializes anyway, but it is a posture change and is
        recorded as such.
      - *Two things are washes, not differentiators.* User presence: the
        passkey KEK still requires the WebAuthn/PRF ceremony, so the seed sits
        behind the factor gate, not beside it. Revocation: local material
        outliving factor revocation until wiped is true under every option (a
        revoked passkey still computes PRF; a cached wrap still opens); the
        threshold model is the backstop either way — one local share cannot
        sign, and server-side revocation kills the SigningWorker half.

      Implementation requirements the review pinned: the cache key gets its
      own HKDF domain with vectors proving it equals neither signing root; the
      seal binding drops the credential/RP components (the record is
      factor-agnostic by design) and keeps wallet, key, lifecycle, worker,
      participant set, public key, and state epoch.

      **Built 2026-08-08.** `derive_ed25519_local_material_cache_key_from_seed_v1`
      is a third domain beside the two roots;
      `router-ab-ed25519-yao-client/src/local_material.rs` holds the seal and
      import, with the wasm bindings delegating to it byte-for-byte so records
      sealed before the split still open. The ceremony seals at
      `complete_near_ed25519` rather than at `finish`, so the activated Client's
      lifetime is one function rather than three states.

      Two things the implementation settled that the plan had not:

      - **The cache never crosses to the server.** It is the ceremony's output
        to its own client, and the server has no use for a device's signing
        material, so `walletCustodyCeremonyCommitPayloadFromWire` drops the two
        fields — a client that sends them anyway cannot cause them to be
        stored. The Rust payload carries them because that same struct is the
        worker→client return; the wire coercion is where the two roles part.
      - **The binding needed a golden test, not a round-trip.** A test that
        rebuilds the binding through the production builder passes no matter
        what fields are added to it — including a credential id, the exact
        coupling this removes. The mutation survived until the binding's byte
        encoding was pinned field by field.

      **Correction (2026-08-09): the material install below is Phase 3 work,
      not a Phase 2 blocker.** It was recorded here as blocking the splice.
      That reads the sequencing backwards: this plan already owns the handoff
      as Phase 3's "Open custody entries into opaque worker handles" and "Hand
      verified ECDSA custody material to the Refactor 90 activation journal and
      read-back path", and the exact shape of it is a *deliberately unfrozen*
      entry under Decisions Required — "the typed ownership handoff from an
      opened Refactor 100 ECDSA custody handle into the Refactor 90 activation
      input". So nothing consuming the blob today is the plan working as
      written, not an oversight.

      The splice may therefore land first, as sequenced. A ceremony-registered
      wallet is not signable until Phase 3, which is acceptable because the
      PRF-derived path is deleted only later ("Delete PRF-derived signing-root
      paths after replacement") and dev wallets are wiped with the Phase 2
      cutover. What follows stays here as the *findings* that Phase 3 starts
      from, not as a gate on Phase 2.

      **Findings (2026-08-08): nothing installs the ceremony's material into a
      signing worker — for either key set.**
      `ecdsaReadyStateBlobB64u` has existed on the commit payload since the
      ceremony was built, and no production code reads it: it reaches the
      shared wire type, a worker typecheck fixture, and tests, and stops there.
      `ed25519LocalMaterialB64u` now joins it. So a spliced wallet of either
      kind would register correctly, seal its custody, and hold material that
      nothing can turn into a signing handle.

      The destinations exist and are the seams to wire:

      - **EVM.** `ecdsaCapabilityManifestStore.ts` already persists a
        `readyStateBlobB64u` (encrypted), and
        `ecdsa-derivation-client.worker.ts` already consumes one. The ceremony's
        blob has to reach that store rather than a new one.
      - **NEAR.** Today the activated-Client record is per factor and read
        through two parallel paths —
        `session/passkey/ed25519YaoLocalMaterial.ts`
        (`readPasskeyEd25519YaoLocalMaterialLocatorV1`) and
        `session/emailOtp/ed25519YaoLocalMaterial.ts`
        (`readEmailOtpEd25519YaoLocalMaterialV1`). The seed-sealed record
        replaces *both* with one wallet-scoped record, which is the point: two
        readers exist only because there were two wrapping factors.

      **The EVM half's first blocker is the same bug as the NEAR one, and it
      is fixed (2026-08-08).** `complete_evm_family` computed the full public
      identity through `finalize_ecdsa_client_bootstrap` and kept only
      `ready_state_blob`, dropping `public_facts`. Those facts are exactly what
      `finalizeRouterAbEcdsaRegistrationActivation` builds
      `registeredPublicFacts` and `roleLocalPublicFacts` from, so an installer
      would have held material it could not describe. They now ride the payload
      as `ecdsaPublicFacts` — reported rather than re-derived at the install
      site, because re-deriving means trusting a second computation to agree
      with the one that produced the material.

      **What remains for the EVM install is larger than "route the blob".**
      `finalizeRouterAbEcdsaRegistrationActivation`
      (`workers/ecdsa-derivation-client.worker.ts`) reaches
      `sealAndFinalizeActivation` only through a *prepared journal*: it opens
      one by id, decodes its pending payload, finalizes the pending state blob
      locally, and derives the activation binding from it. A ceremony run
      creates none of that. So the seam is that worker's finalize, which must
      accept a ready-state blob and public facts produced elsewhere instead of
      finalizing a pending blob it holds — not the store, which is fine as-is.

      **Decision (2026-08-09, user-confirmed): `ecdsaReadyStateBlobB64u` never
      crosses to the server. This was not a free choice — Invariant 3 already
      required it**, and the Non-Goals repeat it: persistence adapters never
      receive a holder share, and custody material is never stored in the app,
      iframe host, Router, or database. The blob's encoding is what makes it a
      holder share rather than opaque ciphertext:
      `extract_client_signing_share32_from_ready_state_blob` is
      `parse_ready_state(&blob).x_client32`, so the blob yields the client's
      signing share from its bytes with *no key*. It is not self-encrypted;
      the IndexedDB manifest store double-encrypts it before persisting for
      exactly that reason. Letting it cross would hand one share of a 2-of-2
      key to the relayer — the holder of the other share.

      There is no necessity or performance counter-argument: nothing
      server-side reads it, it is same-device material another device could
      not use, recovery reproduces it from the seed rather than from any
      escrow, and — decisively — nothing sends it yet, because the splice is
      unbuilt. This is the last moment the drop costs zero migration.

      Enforced at the wire coercion beside the NEAR cache fields (a client
      that sends it anyway cannot cause it to be stored), and proven by the
      activate route tests, whose fixture payloads carry the blob through the
      real path and commit successfully without it. **Splice requirement:**
      the client must also project the payload before sending — the server
      drop keeps the blob out of stores, but only the client-side projection
      keeps it off the wire entirely.

      The import side is built and tested in Rust
      (`import_activated_client_under_custody_seed_v1`) but is not exposed at
      the wasm boundary, and cannot be exposed the obvious way: the cache key
      derives from the seed, which never leaves the ceremony module. So the
      unlock entry point belongs *in that module* — factor secret plus envelope
      plus cache record in, signing handle out — rather than as another
      `WasmActivatedClientV1` import arm taking a key JavaScript would have to
      hold.

      **Do not splice NEAR alone for mixed wallets.** A mixed wallet whose NEAR
      key set came from the custody seed while its EVM key set is still
      PRF-derived is a wallet the recovery set only half covers — recovery
      would restore NEAR and silently miss EVM, which is the exact failure this
      refactor exists to prevent. Either both key sets move together, or the
      first slice is Ed25519-only wallets, which have no EVM key set to strand.

      **Both halves of the admission decision are built (2026-08-08).**
      `walletCustodyRegistrationAdmission.ts` is the only path a route should
      take to `commitWalletCustodyRegistration` — it enforces the wallet-
      equality check and the joining case. `verifiedCustodyFactor.ts` resolves
      the envelope factor from the verified `WalletAuthAuthority`, so no route
      can read it off the payload; its Email OTP arm needs the enrollment id
      and seal key version from the material the same leg finalizes, and
      refuses rather than guessing.

      `registrationCustodyOutcome.ts` composes the two into the leg's whole
      custody side-effect and maps the store's results to what a client acts
      on. Eighteen tests across the three modules, two mutation-checked
      (disabling the wallet-equality check; sourcing the RP id from anywhere
      but the verifier).

      **Policy decided here, and it is a policy call rather than a mechanical
      one: activation never fails because of custody.** The registration is
      already committed when the custody commit runs, and the seed exists only
      in the client's worker — so the client is the only party that can retry,
      re-enter as a join, or abandon. Failing activation would leave the server
      registered, the response an error, and the client with no instruction it
      can read. Every outcome is reported instead. This is not a claim that a
      wallet without custody is acceptable: a client seeing anything but
      `committed` or `not_requested` must act on it rather than treat
      registration as done.

      **The route wiring landed 2026-08-08, at exactly these seams.** Both
      registration legs now carry a custody payload in and an outcome back out,
      and the client sends and parses both. Three route-level tests pin it, two
      of them mutation-checked: restricting the commit to the ECDSA leg fails
      the Ed25519 test (the exact regression the correction below prevents), and
      dropping the outcome from the responses fails all three.

      Two things the wiring settled that the seam list did not anticipate:

      - **The inbound coercion is total and never throws**
        (`walletCustodyCeremonyCommitPayloadFromWire`, shared beside the payload
        type). Absent means no ceremony ran; *everything else* becomes a payload
        the gate reports on. Rejecting malformed custody at the route would fail
        a call whose wallet is already committed, and conflating it with absent
        would let a wallet with an unrecoverable seed report as fully
        registered.
      - **The policy has to survive infrastructure, not just bad input.**
        `commitRegistrationCustody` now catches store failures too: a D1 outage
        after the registration commit must come back as a reported `rejected`
        the client can retry from, never an exception that fails a leg whose
        wallet exists. A rejection is logged, because it is a wallet whose seed
        is not yet recoverable.

      The seams as built:

      - `WalletRegistrationActivateInput` gains `walletCustodyCommit?`
        (`walletRegistrationInputs.ts:56`), parsed in the activate handler
        (`walletRegistrationRoutes.ts:2077-2108`) — pass it through unvalidated,
        since the admission gate owns validation.
      - Construct `CloudflareD1WalletCustodyCommitStore` beside
        `walletRegistrationCommitStore` in the DI site
        (`d1RouterApiAuthService.ts:1435`) — same `options` shape — and inject
        it into `CloudflareD1WalletRegistrationService`.
      - **Correction (2026-08-08): the commit belongs inside
        `executeWalletRegistrationFinalize` (`d1WalletRegistrationService.ts:3786`),
        not in the activate path.** Two callers reach it — activate's ECDSA
        branch (`:3367`) and `commitDeferredEd25519Signer` (`:2654`) — and one
        seam inside covers both. It is also the only correct place for an
        Ed25519-only wallet: activate returns `near_pending` with no Yao result
        yet, so that wallet's custody can only be sealed on the *deferred* NEAR
        provisioning leg. A commit wired into activate alone would silently
        never fire for the first client slice.

        `executeWalletRegistrationFinalize` already has what the commit needs:
        `ceremonyAuthority` from `verifiedRegistrationCeremonyAuthority`, and
        the ceremony's wallet id.

      - The payload rides `WalletRegistrationFinalizeRequestBase`
        (`registrationContracts.ts:765`) as an optional field, which both
        callers populate. Note this changes
        `walletRegistrationFinalizeRequestFingerprint` — it hashes the whole
        request — which is correct: a different custody payload is a different
        request and must not adopt a prior operation row.

      - **The Email OTP factor is fully threadable.** Its two facts live
        together on the `EmailOtpWalletEnrollmentRecord` the same leg builds
        (`d1EmailOtpRegistrationEnrollmentFinalizer.ts:392-400`):
        `enrollmentId` and `enrollmentSealKeyVersion`. The finalize request
        already carries the seal key version; the id comes from the finalizer's
        result, so surface it rather than re-deriving it.
      - The outcome rides `WalletRegistrationFinalizeResponseBase`, so both the
        activate and NEAR-provisioning responses carry it. The client's exact
        key lists were updated in the same change — `walletCustody` added to
        the finalize parser, the Ed25519-pending activate branch, and the
        provisioning success list — and the outcome parser *throws* on an
        unrecognised status rather than guessing, since that is version skew
        between a client and its own Gateway.

      **A test-fixture correction fell out of this** (2026-08-08). Driving the
      deferred NEAR leg for the first time exposed that
      `createActivatedFinalizeYaoRuntimeFixture` rebuilt its admission request
      with invented `material_activation` ids and its own signing root, so the
      request it returned never equalled the one admitted — finalize's
      comparison against the stored signer branch rejected it. The fixture was
      the inaccurate party (a real runtime returns the bytes it was admitted
      with), so it now carries the incoming ref and derives its scope from the
      incoming signing root. Route 4 is testable end to end as a result.

      **Decision (2026-08-07): the custody commit has no standalone route.**
      `commitWalletCustodyRegistration` and its store are built and tested but
      unexposed; the carrier is the registration flow's own activate/finalize
      leg. What proves a caller may establish custody for a wallet is exactly
      what proves they may create the wallet: the verified `signedSetup` plus
      that leg's own auth proof (the WebAuthn create, or the Email OTP proof).
      Custody must never be establishable under weaker or different conditions
      than the wallet itself. The handler checks the payload names the wallet
      the verified registration names, and supplies the envelope's factor ref
      from the credential it just verified rather than trusting the payload's
      copy — so an envelope cannot be addressed to someone else's credential.
      The insert-only store, `already_exists` on replay, and
      `custody_already_established` on a lost race remain the backstops; a
      joining run commits nothing here at all, its manifest digest riding the
      registration state the leg already writes.

      The PRF-derived path must keep working until this lands.
- [x] Repair the SDK barrel at
      `core/signingEngine/session/passkey/envelopes/index.ts`, which still
      re-exported `PASSKEY_CUSTODY_ENVELOPE_VERSION_V1`,
      `buildEd25519YaoClientRootBinding`, `buildEcdsaClientRootShareBinding`,
      and two recovery builders that the custody-union collapse removed. The
      SDK TypeScript build had been failing on this since that commit. Updated
      to the current surface: seed builders, factor builders, and the v2
      envelope version.
- [ ] Shrink `wasm/ecdsa_registration_client` once registration leaves it:
      rename around role-local material rehydration or fold the remainder into
      its natural owner. Do not leave a compatibility shell under the old name.
- [ ] Delete PRF-derived signing-root paths after replacement.

### Phase 3: Unlock And Signing

- [x] Open custody entries into opaque worker handles.
      **NEAR landed 2026-08-09** (`c0c80f923`):
      `open_wallet_custody_ed25519_material_v1` takes a factor secret and the
      stored ciphertext and returns the activated Client, in one call — the
      seed exists only between opening the envelope and deriving the cache
      key, and splitting that would put it in a JavaScript caller's hands.

      It lives in the Ed25519 client's crate rather than the ceremony module,
      per the glossary: unlocking derives no owner root and establishes no
      manifest, so it is not a ceremony. The import re-verifies that the cached
      share still reproduces the registered key, so nothing trusts the cache.

      A circuit test proves the property this refactor exists for: register
      under one factor, enrol a second by resealing the envelope, unlock with
      the second alone. Under the per-factor records this replaces, the second
      factor would have found no cache at all.

      ECDSA remains: it needs the frozen ownership handoff below.
- [ ] Implement synced-passkey cold unlock from a new browser with empty
      IndexedDB by retrieving and opening the existing server-held envelope.
- [x] Prove synced cold unlock uses the same credential and envelope without
      creating a credential or consuming a recovery code.
      `rejoinNearEd25519CustodyV1` joins existing custody and calls `finish`
      with nothing to establish — a combination the ceremony *refuses*, which
      is what makes "no second envelope, no new codes" structural rather than a
      promise the function makes. It also passes the registered key as
      continuity, so the run reproduces that key set instead of registering a
      second, different one; dropping that fails a test.

      What remains of the box above is the surrounding flow: retrieving the
      server-held envelope on a browser with empty IndexedDB, and driving this
      from the unlock path.
- [ ] Hand verified ECDSA custody material to the Refactor 90 activation journal
      and read-back path as an exact `MpcMaterialActivationRef`; do not write a
      second active ECDSA persistence record.
- [x] Bind opaque material handles only to wallet key, lane, epoch, participant
      set, exact material activation, and TTL. Compose the admitted reusable or
      step-up authorization branch only in prepared operation state; no
      authorization, Wallet Session, quota, or operation identity enters the
      material handle.

      **Pinned at compile time** (`ed25519SeedMaterial.typecheck.ts`), because
      these are *absences*: a runtime test can only check the fields a record
      has, and the property is which ones it can never carry. Two families are
      excluded for different reasons — authorization identity, because a
      material handle is a key rather than a permission and Refactor 90 owns
      those per operation; and factor identity, because the record is sealed
      under the seed so a factor enrolled later opens it too. The sealed half
      also cannot name a plaintext share or the seed itself.
- [ ] Preserve zero-Deriver ordinary Ed25519 signing.
- [ ] Preserve exact ECDSA public and material identity while allowing a fresh
      threshold session and server generation.

### Phase 4: Wallet-Scoped Recovery

- [x] Preserve the existing ten-code backup, status, and rotation UX for Email
      OTP enrollment escrow.
- [ ] Recovery *use* only. Code **issuance** moved to Phase 2 (2026-08-09):
      establishing custody must atomically issue the recovery set, so the
      issuance primitive cannot live downstream of the ceremony that needs it.
      What stays here is backup acknowledgement, rotation, status, and the
      recovery UX.
- [ ] Reuse the Email OTP authorization and Refactor 90 Wallet Session/
      `AuthorizedOperation` admission boundary; recovery-code custody remains
      separate from authorization and quota.
- [x] The recovery read side: `open_wallet_custody_seed_with_recovery_code_v1`
      (`cb84039ae`). The code opens the manifest KEK, the manifest KEK opens
      the seed entry — the two-level design frozen above, which is what lets
      one code be consumed or revoked without touching the other nine.

      The code never selects its own wrap: its id is derived from the wallet
      and the code bytes and matched against the stored set, so a caller cannot
      point a code at a wrap it does not open, and a code for another wallet
      finds nothing rather than being tried against every row. Tested against a
      real ceremony's output; all ten codes reach the same seed.
- [x] Recover every key in the exact manifest before credential promotion.
      `admitWalletRecoveryCredentialPromotion` is the only thing that decides
      it, and it decides on the *set*: a mixed wallet that promoted after only
      some key sets verified would leave the owner believing they had recovered
      while part of the wallet still answers to a credential they no longer
      hold — surfacing the first time that key set is used.

      Silence is not success (a key set nothing reported on is outstanding),
      conflicting reports for one key set are treated as failure, and an empty
      manifest is refused rather than trivially satisfied — it means the caller
      never loaded one.
- [x] Consume a recovery code only with the activation commit.
      `runWalletRecoveryWithCode` makes the ordering structural rather than a
      rule each call site restates: it reserves before the work runs, consumes
      only on a reported commit, and releases on every other path including a
      throw — the case a hand-written call site is likeliest to miss, and the
      one where a burned code leaves the user one poorer with nothing
      recovered.

      A commit whose hold has lapsed is *refused* rather than released: the
      code is owed consumption, and handing it back would let one code be
      spent twice. Nothing here persists; each transition returns the next
      lifecycle for the caller to write.

### Phase 5: Credential Management

- [x] Add the custody half of second-factor enrolment — the capability this
      whole refactor exists for, since per-factor roots cannot be reconciled
      after the fact.

      Designing it exposed a contradiction in the module decision above. That
      decision says adding a factor is not a ceremony and stays in
      `near_signer`, but the only seal available took a
      `VerifiedWalletKeyManifestDigestV1`, whose constructors either establish a
      new manifest or verify one — and verifying means deriving both owner
      roots, which needs protocol crates `near_signer` does not link. As
      written, factor addition was unimplementable where it was assigned.

      The resolution is a second, distinct proof rather than a second ceremony.
      Opening a seed envelope already authenticates the seed against its key
      manifest, because the digest and every identity field are in the AAD. So
      the open path mints `WalletCustodySeedFromSealedEnvelopeV1`, and
      `reseal_wallet_custody_seed_under_new_factor_v1` requires it. A reseal may
      change only the factor and the envelope id: wallet, key manifest, and key
      set must be identical, so it cannot move a seed to another wallet or
      relabel which keys it controls. No root derivation, no protocol crate, and
      no ceremony-module load to add a passkey to an Email OTP wallet.

      The two proofs are deliberately not convertible. Sharing one token would
      let an admitted seed reach the registration seal, or a fresh verification
      reach a reseal that is meant to preserve an existing record.

      Related hole closed while designing this: the registration seal compared
      only the *recorded* `keyManifestDigestB64u` against the proof, leaving the
      binding's signing key id, registered public key, slot id, and client root
      key unchecked — an envelope could carry a valid digest beside identity
      fields that never produced it, and those fields are what a later unlock
      reads. Both seal paths now require the whole binding to reproduce the
      digest.

      Exported from `near_signer` as `passkey_custody_open_wallet_seed_v1` and
      `passkey_custody_reseal_wallet_seed_v1`, with the reseal generating its
      own nonce.
- [x] Add passkey envelope creation, listing, and revocation. Creation,
      rewrap, retire and revoke were already on the store; **listing was the
      missing one, and the credential-management rules could not be written
      without it.** Whether removing a passkey is safe depends on whether
      *another* active envelope still protects the same custody seed, which no
      per-envelope lookup can answer.

      `listWalletEnvelopes` scans by the wallet's own key prefix — the encoded
      key's first element plus its comma, so a wallet whose id prefixes
      another's cannot match it — and `admitEnvelopeRevocation` refuses the
      last *active* envelope, since revoking it leaves a seed no factor can
      open while appearing to succeed. Counting rows rather than active rows
      fails a test.
- [x] Add device labels and credential activity history.
      A *sibling* of the custody envelope, never a field on it: the envelope's
      AAD covers its own fields, so folding a mutable label inside would mean
      renaming a device rewrapped custody, and a failed rename could leave a
      wallet unopenable. It carries no secret and decides nothing — revocation
      reads the envelope's lifecycle, not this.

      Absences are meaningful: no label until the user sets one (inventing one
      from a user agent would present a guess as their choice), and no
      last-use until it has been used since registration. A use count without
      a last-use time, or the reverse, is refused — that history cannot have
      happened, and it is how a partial write shows up. Recording a use is
      monotonic, so an out-of-order report cannot make a credential read as
      unused.
- [ ] Add lane refresh escalation after suspected holder-secret exposure.

### Phase 6: Linked-Lane Integration

- [ ] Accept Ed25519 and ECDSA lane holder material produced by Refactor 102.
- [ ] Seal linked-device holder material under Device 2's passkey KEK.
- [ ] Return exact per-key delivery receipts and an aggregate manifest receipt.

## Validation

Static checks:

- a custody seed envelope with lane or holder-share fields fails;
- a lane holder-share envelope with the other curve's fields fails;
- an ECDSA holder-share envelope without a threshold session fails;
- a linked-device holder-share envelope with a key-creation root field fails;
- an active envelope without credential, lane, key, or AAD identity fails;
- plaintext root, holder share, PRF, KEK, and recovery-code fields cannot appear
  in persisted or app-visible records;
- raw boundary shapes cannot reach core unlock or signing functions.

Focused behavior tests:

- mixed Ed25519/ECDSA registration seals every required root;
- unlock produces valid signatures for NEAR, Tempo, and Arc/EVM;
- a new browser with empty IndexedDB can use the same synced credential to
  retrieve the server-held envelope, restore exact custody material, activate
  canonical local state, and sign without a recovery code;
- synced cold unlock preserves credential and envelope IDs while allowing
  threshold-session and server-generation rotation;
- missing, conflicting, revoked, unsupported-PRF, digest-mismatched, and
  unavailable synced envelopes fail explicitly and never rederive a root;
- provider-synchronized cold unlock and hybrid cross-device authentication have
  separate PRF compatibility coverage and fallback results;
- passkey addition preserves the lane and wallet public identities;
- passkey addition creates a distinct credential and envelope, unlike
  passkey-provider synchronization;
- Email OTP and recovery-code recovery preserve every wallet key;
- partial mixed-wallet recovery never promotes the replacement credential;
- code replay, wrong wallet, wrong key manifest, wrong RP, wrong credential,
  wrong lane epoch, and wrong public key all fail;
- linked-device holder material can be delivered, sealed, reopened, signed, and
  revoked without affecting owner envelopes;
- lock, pagehide, timeout, success, and failure destroy live handles.

Broad gate:

- run the Yao local-product gate because this changes Ed25519 registration and
  recovery inputs;
- run the mixed passkey registration and recovery suites;
- run ECDSA registration, recovery, signing, and export identity-continuity
  tests;
- repeat production-profile gates when the Yao production adapter exists.

## Non-Goals

- changing a wallet public key or address during credential management;
- storing plaintext custody material in the app, iframe host, Router, or
  database;
- letting a linked device reuse an owner lane's holder material;
- using ordinary signing routes for export;
- retaining migration readers, feature flags, or dual custody implementations;
- bypassing Yao production-security gates.

## Decisions Required Before Implementation

- FROZEN (August 6, 2026) — passkey envelope AEAD: ChaCha20Poly1305 (IETF)
  with a 12-byte random nonce, 16-byte tag, and HKDF-SHA256 KEK derivation
  (`chacha20poly1305-hkdf-sha256-v1`, `PASSKEY_CUSTODY_WRAP_ALG_V1`). This is
  the same primitive as `EMAIL_OTP_RECOVERY_WRAP_ALG` and the Rust/WASM
  activated-Client seal; no second AEAD family enters the custody paths.
  Random 12-byte nonces are safe here because each envelope's KEK is unique
  (the envelope ID is HKDF info) and one envelope is sealed only a handful of
  times across rewraps. The envelope parser accepts exactly 12-byte nonces.
- FROZEN (August 7, 2026) — root generation: one random 32-byte wallet
  custody seed generated inside Rust (`getrandom`), with every owner signing
  root derived from it in parallel by domain-separated HKDF-SHA256 (Ed25519
  Yao Client root and Router A/B ECDSA client root share; distinct labels, no
  chained derivation). Passkey and Email OTP wrap the same seed in
  factor-specific envelopes. Email OTP's landed chained derivation (ECDSA
  client share and unlock auth seed derived from the Ed25519 threshold root)
  is a latent key-separation weakness — the chaining parent is an internal
  intermediate that no production path derives, and it is a sibling of, not
  the parent of, the Ed25519 Yao Client root — and is deleted rather than
  versioned. Dev OTP wallets are wiped (approved August 7, 2026 on the
  operator's assertion that none are in production; not verifiable from
  repository evidence).
- FROZEN (August 6, 2026) — recovery-code wrapping uses a manifest KEK: each
  of the ten codes wraps one random 32-byte manifest KEK
  (`WalletRecoveryManifestKekWrap`, purpose `wallet_recovery_manifest_kek`),
  and each custody entry is wrapped once under an entry KEK derived from the
  manifest KEK with per-entry info (wallet key, lane, epoch, custody kind).
  Per-entry AAD is preserved through the entry KEK purpose; all-or-nothing is
  structural because one code opens the manifest KEK or nothing. Code rotation
  rewraps only the manifest KEK and never re-opens plaintext roots; a
  consumed-code recovery mints a fresh manifest KEK while the worker already
  holds plaintext. Consequence: a key-manifest change (new wallet key, lane
  refresh) requires recovery-code rotation, since entries cannot be added
  without the manifest KEK.
- FROZEN (August 6, 2026) — the server-side passkey-envelope store is built on
  the Gateway D1 versioned JSON record store
  (`CloudflareD1VersionedJsonRecordStore`): key
  `passkey-envelope:<walletId>:<credentialIdB64u>:<envelopeId>` under the
  tenant scope, with `parsePasskeyCustodyEnvelopeRecord` as the row parser.
  The store version string is the transport CAS token; the domain
  `envelopeRevision` increments by exactly 1 per rewrap and the server rejects
  non-monotonic puts. Lifecycle transitions use predicate-guarded atomic
  patches: active -> retired (superseded by rewrap), active/retired -> revoked
  (terminal). Revoked rows are retained as credential tombstones but excluded
  from retrieval. Authenticated retrieval (after server-side WebAuthn
  assertion verification for the exact wallet, credential, and challenge)
  returns a typed union: active with envelope and revision, or explicit
  revoked / retired / missing / digest-mismatch failures; no branch falls back
  to derivation.
- Freeze the typed ownership handoff from an opened Refactor 100 ECDSA custody
  handle into the Refactor 90 activation input, exact
  `MpcMaterialActivationRef`, activation journal, manifest read-back, and
  hydration result. Explicit material reactivation must allocate a fresh
  activation ID; ordinary rehydration must preserve the current one.
- Define the per-owner effects for wallet registration and recovery: Gateway D1
  owns product ceremonies, passkey-envelope records, activation results,
  Wallet Session authorization, quotas, authorized operations, and audit;
  Deriver A/B private D1 owns role custody and one-use cryptographic state;
  SigningWorker private D1 owns activated material, delivery, cryptographic
  effect deduplication, presignature or Yao material consumption, and terminal
  response replay; the browser owns atomic IndexedDB finalization; Router only
  forwards typed commands. Every server effect is idempotent and queryable by
  exact correlation and receipt. No distributed Router-owned commit or
  cross-system transaction is required.
