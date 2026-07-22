# Passkey Custody Refactor For Wrapped Client Roots And Holder Shares

Date created: June 15, 2026

Last reconciled: July 22, 2026

Status: active design plan. Same-device passkey Ed25519 sealing and rehydration,
durable ECDSA material identity, and the current Email OTP wallet lifecycle have
landed as groundwork. Portable server-held wrapped custody, random-root
registration, mixed-wallet recovery envelopes, and recovery-code unwrap remain
pending. Ed25519 lifecycle behavior must preserve the architecture and
production gates in [router-ab/ed25519-yao/implementation-plan.md](./router-ab/ed25519-yao/implementation-plan.md).

## Dependencies And Authority

This plan owns passkey-controlled client custody. It supplies custody records
and worker APIs consumed by:

- [refactor-90-modular-auth-capabilities-plan.md](./refactor-90-modular-auth-capabilities-plan.md)
  for canonical active ECDSA capability manifests, browser persistence,
  activation commits, hydration, and exact operation-lane selection;
- [refactor-96-delegate-wallets.md](./refactor-96-delegate-wallets.md) for
  `WalletKey`, `SigningLane`, and enrollment identity;
- [refactor-97-share-rotation.md](./refactor-97-share-rotation.md) for
  curve-specific lane provisioning and refresh;
- [refactor-98-delegated-agent-linked-device-behavior.md](./refactor-98-delegated-agent-linked-device-behavior.md)
  for linked-device and delegated-agent product flows.

The cryptographic authorities are:

- [router-ab/ed25519-yao/implementation-plan.md](./router-ab/ed25519-yao/implementation-plan.md) for Ed25519 registration, recovery, refresh,
  recipient provisioning, activation, signing, and export;
- `crates/router-ab-ecdsa-derivation` for secp256k1 role-local derivation,
  additive shares, threshold signing, and export;
- the Wallet Session model for authorization, exact key bindings, budget, and
  expiry.

This plan does not introduce an alternate signing protocol.

## Goal

Make passkeys authentication and unwrap factors for random, rotatable client
custody material.

Target shape:

```text
WebAuthn user verification + PRF output
  -> passkey KEK inside the secure worker
  -> opens one exact client-root or holder-share envelope
  -> creates an opaque live capability
  -> capability participates in the existing Ed25519 or ECDSA lifecycle
```

The passkey PRF output is limited to KEK derivation and authentication binding.
It does not define a wallet key, Yao Client root, ECDSA client root share, or
lane holder share after this refactor.

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
11. Refactor 95 owns portable encrypted custody and factor-specific unwrap.
    Refactor 90 owns the active local ECDSA manifest, encrypted role-local
    material, activation journal, and post-effect hydration result. Neither
    refactor may introduce a second owner for the other's state.
12. ECDSA cold unlock and recovery preserve the registered public key, address,
    material owner, key slot, and participant binding. They may create a fresh
    threshold session and server generation; an old grant, quota, bearer
    credential, nonce, or threshold-session ID is never copied as durable key
    identity.
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
- one Wallet Session grant can bind an Ed25519 key and the exact ECDSA sessions
  for Tempo and Arc/EVM under one shared budget;
- Email OTP recovery-code backup, status, and rotation UX exists for the current
  enrollment-escrow model. Those codes do not yet open the wallet-scoped mixed
  custody envelope set defined here;
- target custody-envelope record types and type fixtures exist, though they are
  not wired into random-root registration, portable cold unlock, or
  wallet-scoped recovery;
- linked-device operations remain fail closed.

The current local Ed25519 envelope closes routine same-device continuity. It
does not close any portable-custody phase below: it contains the activated
Client scalar share derived from the current deterministic Client root, lives
only in browser storage, and requires the same credential's PRF output.

The refactor changes both passkey root sources:

```text
current Ed25519: PRF.first -> deterministic Yao Client root
target Ed25519:  random Yao Client root -> passkey-sealed root envelope

current ECDSA:   PRF.first -> deterministic client root share
target ECDSA:    random client root share -> passkey-sealed root envelope
```

New registrations use random roots from their first ceremony. Since the project
is in development, test wallets and obsolete persisted records are discarded
when the new registration path lands. Any retained wallet requires an explicit
identity-preserving protocol from Refactor 97; an envelope rewrite can never
silently change its public key or address.

## Custody Secret Taxonomy

The envelope plaintext must identify the protocol capability it restores.
`holder share` is too broad for the new SDK.

```ts
type PasskeyCustodySecretBinding =
  | {
      kind: 'ed25519_yao_client_root_v1';
      walletKeyId: WalletKeyId;
      laneId: SigningLaneId;
      laneShareEpoch: LaneShareEpoch;
      nearEd25519SigningKeyId: NearEd25519SigningKeyId;
      keyCreationSignerSlot: KeyCreationSignerSlot;
      stableContextDigestB64u: string;
      participantBindingDigestB64u: string;
      evmFamilySigningKeySlotId?: never;
      thresholdSessionId?: never;
    }
  | {
      kind: 'ed25519_lane_holder_share_v1';
      walletKeyId: WalletKeyId;
      laneId: SigningLaneId;
      laneShareEpoch: LaneShareEpoch;
      nearEd25519SigningKeyId: NearEd25519SigningKeyId;
      registeredPublicKeyB64u: string;
      participantBindingDigestB64u: string;
      keyCreationSignerSlot?: never;
      stableContextDigestB64u?: never;
      evmFamilySigningKeySlotId?: never;
      thresholdSessionId?: never;
    }
  | {
      kind: 'ecdsa_client_root_share_v1';
      walletKeyId: WalletKeyId;
      laneId: SigningLaneId;
      laneShareEpoch: LaneShareEpoch;
      evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
      applicationBindingDigestB64u: string;
      clientRootPublicKey33B64u: string;
      nearEd25519SigningKeyId?: never;
      keyCreationSignerSlot?: never;
      thresholdSessionId?: never;
    }
  | {
      kind: 'ecdsa_lane_holder_share_v1';
      walletKeyId: WalletKeyId;
      laneId: SigningLaneId;
      laneShareEpoch: LaneShareEpoch;
      evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
      thresholdSessionId: ThresholdEcdsaSessionId;
      thresholdPublicKey33B64u: string;
      nearEd25519SigningKeyId?: never;
      keyCreationSignerSlot?: never;
      clientRootPublicKey33B64u?: never;
    };
```

Owner registration and same-root recovery use the root branches. A linked or
delegated lane may receive a lane-specific holder-share branch produced by the
protocol in Refactor 97. Builders must be branch-specific. Core code never
constructs this union with a broad spread or an `as` cast.

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

type PasskeyCustodyEnvelopeRecord = {
  kind: 'passkey_custody_envelope_v1';
  envelopeId: PasskeyEnvelopeId;
  walletId: WalletId;
  binding: PasskeyCustodySecretBinding;
  rpId: string;
  credentialIdB64u: string;
  passkeyEnvelopeVersion: 'passkey_custody_envelope_v1';
  passkeyKekVersion: 'passkey_prf_kek_hkdf_sha256_v1';
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

The record stores ciphertext and public binding data. It cannot store a raw
secret, PRF output, KEK, recovery code, or live capability handle.

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

type WalletRecoveryEnvelopeSetRecord = {
  kind: 'wallet_recovery_envelope_set_v1';
  walletId: WalletId;
  recoveryKeyId: DerivedWalletRecoveryKeyId;
  keyManifestDigestB64u: string;
  entries: readonly WalletRecoveryEnvelopeEntry[];
  lifecycle: RecoveryCodeLifecycleState;
  issuedAtMs: number;
  updatedAtMs: number;
};
```

The manifest contains the exact active owner key/lane set. Parsing rejects an
empty set, duplicate wallet keys, duplicate lanes, omitted required keys, and
entries outside the authenticated wallet.

Use ten single-use codes, matching the existing Email OTP recovery UX. A code
is reserved during recovery and becomes consumed only after the complete new
credential activation commits. Failed pre-commit recovery releases the
reservation. Failed post-commit Yao recovery follows the forward-only recovery
rules in `router-ab/ed25519-yao/implementation-plan.md`.

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
- credential ID and RP ID;
- envelope, KEK, and protocol versions.

The worker recomputes AAD from parsed domain records. Callers cannot supply an
arbitrary AAD blob.

## Registration Flow

1. Parse the exact wallet registration intent and signer-set selection.
2. Create the `WalletKey` inventory and owner lane identities.
3. Create the passkey and obtain required PRF output inside the secure-confirm
   worker.
4. Generate independent random client custody roots inside Rust/WASM:
   - one Yao Client root for each new Ed25519 wallet key;
   - one Router A/B ECDSA client root share for the EVM-family wallet key.
5. Execute the existing key-family registration protocols with those imported
   random roots.
6. Verify the returned Ed25519 public key, ECDSA public key, EVM address,
   participant bindings, threshold sessions, and wallet-level grant.
7. Seal every client root under the passkey KEK.
8. Create the recovery envelope sets from the same roots.
9. Commit wallet keys, lanes, envelopes, recovery sets, public capability
   projections, and the Wallet Session grant through one journaled registration
   commit. Server-held portable envelopes must be committed before registration
   reports cross-device custody ready.
10. Zeroize root and PRF inputs on every exit.

The Yao Client-root source becomes a precise union with a generated-random-root
branch. The PRF-derived-root branch is deleted when this flow lands.

## Unlock And Ordinary Signing

1. Resolve the exact active server-held passkey envelope set for the requested
   wallet and credential. A matching browser cache may satisfy the ciphertext
   read only after exact revision and digest validation.
2. Run WebAuthn and derive the passkey KEK inside the worker.
3. Open only the custody entries required by the requested lane and key.
4. Convert opened material into opaque Rust/WASM handles:
   - an Ed25519 Yao Client capability or lane holder capability;
   - an ECDSA role-local client-root or holder-share capability.
5. Resolve the exact Wallet Session, lane, key, participant, threshold-session,
   budget, and expiry binding.
6. Sign through the existing Router and SigningWorker path.

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
   the corresponding Yao publication/durability boundary.
7. Mint or activate fresh threshold sessions, grants, quotas, and server
   generations where policy requires them. These rotating facts are never
   recovered from the portable custody envelope.
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

1. Authorize the wallet recovery request with Email OTP, then supply one unused
   recovery code as the custody-envelope unwrap factor.
2. Reserve the recovery code and resolve its exact key manifest.
3. Open every recovery-wrapped custody entry inside the recovery worker.
4. Create the replacement passkey and its KEK.
5. Run Ed25519 Yao same-root recovery for each Ed25519 root entry.
6. Rebind and reactivate each ECDSA client-root entry while preserving the
   threshold public key, address, material owner, key slot, participants, and
   registered lifecycle identity. Activate a fresh threshold session and server
   generation when required; do not copy the prior threshold-session ID, grant,
   quota, bearer credential, or nonce state.
7. Seal every custody entry under the replacement passkey KEK.
8. Verify identity continuity for the complete manifest.
9. Atomically activate the replacement envelope set, tombstone the prior
   credential binding, and consume the recovery code.
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

Refactor 97 owns the key-family provisioning ceremony. Refactor 98 owns the QR
and product behavior.

## Credential And Device Management

- Removing one passkey revokes its envelope set and invalidates its live
  handles.
- Removing a synced passkey leaves the lane active when another active envelope
  protects the same custody secret.
- Suspected plaintext exposure triggers lane refresh through Refactor 97.
- Revoking a linked device revokes its enrollment and all child lanes. Owner
  lane envelopes remain active.
- Credential replacement and device revocation are separate user operations.

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

- [ ] Replace the generic holder-share envelope model with the explicit custody
      secret union.
- [ ] Add branch-specific builders and boundary parsers.
- [ ] Add static fixtures rejecting cross-curve fields and raw-secret records.
- [ ] Delete deterministic PRF-root lifecycle types and obsolete fixtures.

### Phase 1: Envelope Crypto

- [ ] Implement passkey KEK derivation inside Rust/WASM.
- [ ] Implement authenticated seal/open for every custody-secret branch.
- [ ] Implement wallet recovery envelope sets and recovery-code reservation.
- [ ] Implement the server-side opaque passkey-envelope store with exact
      credential, wallet, lifecycle, revision, and digest lookup results.
- [ ] Implement authenticated envelope retrieval that verifies the WebAuthn
      assertion while keeping PRF output inside the secure worker.
- [ ] Persist PRF support and WebAuthn backup observations without treating
      backup eligibility or backup state as proof of cross-device PRF
      continuity.
- [ ] Add AAD substitution and ciphertext tamper tests.

### Phase 2: Random-Root Registration

- [ ] Add generated-random Client-root input to Yao registration.
- [ ] Add generated-random client-root-share input to ECDSA derivation.
- [ ] Commit server-held mixed-wallet passkey envelopes and recovery envelope
      sets with the registration result.
- [ ] Delete PRF-derived signing-root paths after replacement.

### Phase 3: Unlock And Signing

- [ ] Open custody entries into opaque worker handles.
- [ ] Implement synced-passkey cold unlock from a new browser with empty
      IndexedDB by retrieving and opening the existing server-held envelope.
- [ ] Prove synced cold unlock uses the same credential and envelope without
      creating a credential or consuming a recovery code.
- [ ] Hand verified ECDSA custody material to the Refactor 90 activation journal
      and read-back path; do not write a second active ECDSA persistence record.
- [ ] Bind handles to wallet key, lane, epoch, participant set, grant, and TTL.
- [ ] Preserve zero-Deriver ordinary Ed25519 signing.
- [ ] Preserve exact ECDSA public and material identity while allowing a fresh
      threshold session and server generation.

### Phase 4: Wallet-Scoped Recovery

- [x] Preserve the existing ten-code backup, status, and rotation UX for Email
      OTP enrollment escrow.
- [ ] Bind ten single-use codes to the wallet-scoped mixed-custody envelope set.
- [ ] Reuse the Email OTP authorization and Wallet Session admission boundary.
- [ ] Recover every key in the exact manifest before credential promotion.
- [ ] Consume a recovery code only with the activation commit.

### Phase 5: Credential Management

- [ ] Add passkey envelope creation, listing, and revocation.
- [ ] Add device labels and credential activity history.
- [ ] Add lane refresh escalation after suspected holder-secret exposure.

### Phase 6: Linked-Lane Integration

- [ ] Accept Ed25519 and ECDSA lane holder material produced by Refactor 97.
- [ ] Seal linked-device holder material under Device 2's passkey KEK.
- [ ] Return exact per-key delivery receipts and an aggregate manifest receipt.

## Validation

Static checks:

- an Ed25519 root envelope with ECDSA fields fails;
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

- Select the passkey envelope AEAD and nonce format already supported by the
  Rust/WASM boundary.
- Freeze the exact random-root generation API for Yao and ECDSA derivation.
- Freeze whether a recovery code wraps each manifest entry directly or wraps a
  manifest KEK that encrypts the entries. Both designs must preserve per-entry
  AAD and all-or-nothing promotion.
- Freeze the server-side passkey-envelope schema, revision/CAS rules, retention,
  authenticated retrieval result, and revocation behavior.
- Freeze the exact ownership handoff from an opened Refactor 95 ECDSA custody
  handle into the Refactor 90 activation input, commit journal, manifest
  read-back, and hydration result.
- Define the durable transaction boundary for wallet registration and recovery
  across Router records, SigningWorker activation, and browser persistence.
