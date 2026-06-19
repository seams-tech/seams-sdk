# Stealth EVM Addresses

Date created: 2026-05-27
Status: proposed

## Goal

Add ERC-5564-compatible EVM stealth address support to the SDK with two
separate capabilities:

- Sender-side stealth payment derivation using threshold-derived ephemeral
  secp256k1 keys.
- Recipient-side stealth spending from threshold-controlled ECDSA spending
  keys using the existing threshold-signatures tweak mechanic.

The first capability lets a sender derive `ephemeralPubKey`, `viewTag`, and
`stealthAddress` without holding a local single-party ephemeral private key.
The second capability lets a recipient spend from an ERC-5564 stealth address
whose base spending key is a Seams threshold ECDSA key.

## Background

ERC-5564 scheme `1` uses secp256k1 public keys and view tags. A recipient
publishes a stealth meta-address containing:

- `P_spend`: spending public key.
- `P_view`: viewing public key.

For each payment, the sender creates a fresh ephemeral scalar `r` and computes:

```text
R = rG
Z = rP_view
h = hash(Z)
viewTag = h[0]
P_stealth = P_spend + hG
stealthAddress = pubkeyToAddress(P_stealth)
```

The sender announces `R` and `viewTag`. The recipient scans announcements with
their viewing private key:

```text
Z = p_view R
h = hash(Z)
P_stealth = P_spend + hG
```

For spending, the stealth private key is:

```text
p_stealth = p_spend + h mod n
```

That final equation maps directly to threshold ECDSA public-key tweaking. If
`p_spend` is held as additive or threshold shares, the signer should authorize
and sign as the tweaked key `P_spend + hG`.

## Current Code Shape

The existing ECDSA stack already has most of the primitives needed:

- `crates/signer-core/src/secp256k1.rs`
  - validates compressed secp256k1 public keys.
  - adds compressed secp256k1 public keys.
  - converts compressed secp256k1 public keys to Ethereum addresses.
  - converts private scalars to compressed public keys.
- `crates/ecdsa-hss/src/shared/derive.rs`
  - derives role-local client and relayer additive ECDSA shares.
  - composes client and relayer public shares into a threshold public key.
- `crates/signer-core/src/threshold_ecdsa.rs`
  - uses `threshold-signatures` rerandomization with `Tweak`.
  - currently passes `Tweak::new(TsScalar::ZERO)` in both signature-share
    computation and finalization.
- `client/src/core/signingEngine/chains/evm/ethSignerWasm.ts`
  - exposes secp256k1 arithmetic and threshold ECDSA worker calls to TypeScript.
- `client/src/threshold.ts`
  - exposes the current stable threshold/lite ECDSA session APIs.

The missing primitive is secp256k1 scalar multiplication of an arbitrary public
key:

```text
scalar32 * publicKey33 -> publicKey33
```

This is needed for threshold sender-side ECDH, where each party contributes a
share of `rP_view`.

## signer-core Review

Current `signer-core` support is strong enough for the base EVM and threshold
ECDSA pieces, with a few narrow gaps.

### Available Today

- `secp256k1` feature:
  - Derives single-party secp256k1 keys from PRF material.
  - Derives deterministic relayer signing shares.
  - Maps additive 2P shares into the Shamir-style share encoding expected by
    `threshold-signatures`.
  - Validates compressed SEC1 public keys.
  - Adds compressed SEC1 public keys.
  - Derives compressed public keys from 32-byte private scalars.
  - Derives Ethereum addresses from compressed public keys using Keccak-256 of
    the uncompressed point.
  - Produces and verifies low-s recoverable secp256k1 signatures.
- `threshold-ecdsa` feature:
  - Runs the Cait-Sith style presign protocol over the NEAR
    `threshold-signatures` dependency.
  - Rerandomizes presignatures for each message.
  - Already imports and uses `Tweak`, which is the right primitive for
    recipient-side stealth spending.
  - Currently hardcodes `Tweak::new(TsScalar::ZERO)` in
    `threshold_ecdsa_compute_signature_share` and
    `threshold_ecdsa_finalize_signature`.
- Test coverage:
  - Covers additive-share mapping.
  - Covers public-key addition against scalar addition.
  - Covers private-scalar to public-key derivation.
  - Covers low-s single-party secp256k1 signatures and recovery.
  - Covers Ethereum address derivation from an existing public key.
  - Threshold ECDSA core tests currently cover invalid participant input only;
    the full signing path coverage lives mostly in higher-level harnesses.

### Gaps For Stealth Addresses

- There is no `scalar * arbitrary public key` helper for ECDH-style
  derivation.
- There is no public helper for adding two private scalars modulo secp256k1
  order. This is needed for fixtures and explicit export flows, rather than
  normal threshold signing.
- There is no ERC-5564-specific shared-secret hash helper.
- Public-key addition does not expose a domain-specific
  `derive_tweaked_public_key(base, tweak)` helper that rejects zero tweak and
  identity results with stealth-specific errors.
- Threshold ECDSA signing accepts only the base public key because the tweak is
  hardcoded to zero.
- Threshold ECDSA finalization verifies and recovers against the base public
  key. Tweaked signing must verify and recover against `P_base + tweak * G`.
- Core feature boundaries need an explicit choice: either keep ERC-5564 helpers
  under the `secp256k1` feature and keep threshold tweak math local to
  `threshold_ecdsa`, or intentionally make `threshold-ecdsa` depend on the
  `secp256k1` feature.

## Spec Decisions To Lock First

These decisions should be resolved before touching protocol or persistence
code. They define wire compatibility and prevent two incompatible stealth
formats from entering the SDK.

- [ ] **ERC-5564 shared-secret encoding.** Decide the exact byte encoding fed
  into `hash(Z)`: compressed SEC1 point, uncompressed SEC1 point, x-coordinate,
  or the reference implementation's chosen encoding. Lock this with fixtures.
- [ ] **ERC-5564 hash-to-scalar rule.** Decide whether `hash(Z)` is interpreted
  directly as a 32-byte scalar, reduced modulo `n`, or rejected when outside
  scalar range. Lock zero-scalar retry/rejection behavior.
- [ ] **Meta-address format.** Decide the accepted input set:
  `st:eth:0x...`, raw hex bytes, compressed public keys only, or compatibility
  with uncompressed keys at the request boundary. Internal types should store
  canonical compressed 33-byte keys.
- [ ] **Announcement metadata.** Define SDK-supported metadata layouts for
  native ETH, ERC20, ERC721, and arbitrary payloads. The first byte must be the
  view tag.
- [ ] **Announcer addresses.** Decide whether known ERC-5564 announcer
  addresses are SDK defaults, app config, or caller-provided only.
- [ ] **Sender ephemeral relayer derivation.** Decide deterministic derivation
  from server secret and request context versus stateful random generation.
  Deterministic derivation needs replay policy; stateful generation needs
  storage and deletion policy.
- [ ] **Sender ephemeral authorization scope.** Define the exact context bound
  into a relayer ephemeral contribution: wallet, rp id, chain id,
  recipient spend/view keys, request nonce, origin/runtime policy scope, and
  expiry.
- [ ] **Sender endpoint response.** Decide whether the server returns only
  public shares (`R_relayer`, `Z_relayer`) or also a transcript digest for audit
  and replay detection.
- [ ] **Recipient viewing key model.** Decide whether the viewing key can be
  single-party local material, threshold-derived material, or both. Recipient
  scanning needs this before a public API is exposed.
- [ ] **Recipient spending key mode.** Define the signing mode as
  `kind: 'erc5564_stealth_address'` with required base public key, derived public
  key, derived address, tweak scalar, and announcement reference.
- [ ] **Budget and audit identity.** Decide how policy sees a stealth spend:
  base signer identity plus derived stealth address should both be present, with
  the derived address treated as the transaction sender.
- [ ] **Presign pool scope.** Decide whether base-key presignatures can be
  shared across tweaks by default. The `threshold-signatures` rerandomization
  design supports this, so per-tweak pools should require a specific policy
  reason.
- [ ] **Feature boundary.** Decide whether `threshold-ecdsa` may call helpers
  from the `secp256k1` module, or whether duplicate minimal tweak-public-key
  math stays inside `threshold_ecdsa` to preserve feature separation.
- [ ] **Fixture source.** Pick the external reference implementation or checked
  test vectors used to lock ERC-5564 derivation and view-tag behavior.

## Implementation Task List

### signer-core

- [ ] Add `multiply_secp256k1_public_key_33(scalar32, publicKey33)`.
- [ ] Add `add_secp256k1_private_scalars_32(left32, right32)` for fixtures and
  export-only flows.
- [ ] Add `derive_secp256k1_tweak_public_key_33(tweak32)`.
- [ ] Add `derive_tweaked_secp256k1_public_key_33(basePublicKey33, tweak32)`.
- [ ] Add ERC-5564 hash helper after the shared-secret encoding decision is
  locked.
- [ ] Add ERC-5564 stealth public-key/address helper after hash-to-scalar
  behavior is locked.
- [ ] Reject invalid scalars, zero stealth tweaks, invalid public keys, and
  identity public-key sums with stable `SignerCoreErrorCode` values.
- [ ] Add Rust unit tests for scalar multiplication, ECDH share addition,
  stealth public-key derivation, zero/identity rejection, and fixture vectors.
- [ ] Add shared core fixture coverage in
  `crates/signer-core/fixtures/signing-vectors/platform_surface_tests.rs`
  and embedded-Linux replay coverage in `crates/signer-embedded-linux/src/tests.rs`.

### threshold_ecdsa

- [ ] Add a core signing tweak type:

  ```rust
  pub enum ThresholdEcdsaSigningMode {
      Standard,
      ScalarTweak([u8; 32]),
  }
  ```

- [ ] Update `threshold_ecdsa_compute_signature_share` to accept the tweak and
  pass it into `RerandomizationArguments`.
- [ ] Update `threshold_ecdsa_finalize_signature` to accept the same tweak.
- [ ] Compute the effective verifying key from the base key and tweak.
- [ ] Verify the final threshold signature against the effective verifying key.
- [ ] Recover `recId` against the effective verifying key.
- [ ] Add a test that signs with a known non-zero tweak and verifies recovery
  against `P_base + tweak * G`.
- [ ] Add a mismatch test where client and relayer use different tweaks and
  finalization fails.

### WASM And Worker Boundaries

- [ ] Export new signer-core secp256k1 primitives from `wasm/eth_signer`.
- [ ] Update `wasm/eth_signer/src/derive.rs` and `wasm/eth_signer/src/lib.rs`.
- [ ] Extend `wasm/eth_signer/src/threshold.rs` to pass tweak data into
  threshold ECDSA core functions.
- [ ] Update `client/src/core/signingEngine/workerManager/workerTypes.ts` with
  required branch-specific tweak payloads.
- [ ] Update `client/src/core/signingEngine/workerManager/workers/eth-signer.worker.ts`.
- [ ] Update `client/src/core/signingEngine/chains/evm/ethSignerWasm.ts`.
- [ ] Update `server/src/core/ThresholdService/ethSignerWasm.ts`.
- [ ] Add worker unit coverage for each new primitive and tweaked signature
  share computation.

### Router A/B ECDSA-HSS Signing Flow

- [ ] Extend Router A/B ECDSA-HSS prepare request parsing with a discriminated
  signing tweak branch.
- [ ] Store tweak metadata in the Router A/B ECDSA-HSS request or active
  signing context.
- [ ] Include base public key, effective public key, derived address, tweak
  kind, tweak scalar hash/redaction, and announcement reference in records.
- [ ] Bind Router A/B prepare and finalize to the same authorized tweak context.
- [ ] Pass the authorized tweak to WASM finalization through the Router A/B
  SigningWorker boundary.
- [ ] Ensure signature verification and recovery use the effective public key.
- [ ] Add authorization failures for missing, malformed, or mismatched tweak
  metadata.
- [ ] Add audit and budget inputs for base signer identity plus derived stealth
  sender address.

### Client Signing Flow

- [ ] Add `ThresholdEcdsaSigningKeyMode` as a discriminated union.
- [ ] Require `kind: 'standard'` on all existing ECDSA signing paths.
- [ ] Add `kind: 'erc5564_stealth_address'` for stealth spending paths.
- [ ] Thread the tweak branch through the Router A/B ECDSA-HSS signing helper.
- [ ] Pass tweak data into `thresholdEcdsaComputeSignatureShareWasm`.
- [ ] Pass tweak data through Router A/B ECDSA-HSS prepare/finalize request
  builders.
- [ ] Add type fixtures rejecting optional/bag-shaped tweak inputs.
- [ ] Keep base-key presignature pool behavior unless the presign-pool spec
  decision requires per-tweak isolation.

### SDK Stealth Module

- [ ] Create `client/src/stealth.ts`.
- [ ] Add package export `@seams/sdk/stealth`.
- [ ] Add meta-address parser with canonical internal compressed keys.
- [ ] Add local single-party ERC-5564 derivation for fixtures and basic sender
  support.
- [ ] Add threshold sender ephemeral derivation API after server endpoint shape
  is locked.
- [ ] Add announcement metadata builders.
- [ ] Add scanner helpers only after the recipient viewing-key model is locked.

### Threshold Sender Ephemeral Server Flow

- [ ] Add `POST /threshold-ecdsa/stealth/ephemeral`.
- [ ] Parse and normalize the request once at the route boundary.
- [ ] Validate wallet/session authority and runtime policy scope.
- [ ] Derive or allocate one-time relayer ephemeral scalar according to the
  locked spec.
- [ ] Return relayer public contribution values and optional transcript digest.
- [ ] Add replay protection according to the locked derivation model.
- [ ] Ensure no durable signer/key-handle/presignature state is created for
  sender ephemeral keys.

### Test And Fixture Work

- [ ] Add signer-core ERC-5564 vector tests.
- [ ] Add WASM replay tests for new primitives.
- [ ] Add threshold ECDSA tweaked-signature harness tests.
- [ ] Add TypeScript type-level rejection fixtures.
- [ ] Add SDK parser and metadata tests.
- [ ] Add an integration fixture against the selected ERC-5564 reference.
- [ ] Add an end-to-end stealth-spending test after tweak signing and scanner
  semantics are stable.

## Target Model

Expose a separate SDK module:

```ts
export {
  deriveErc5564StealthPayment,
  parseErc5564StealthMetaAddress,
  computeErc5564StealthTweak,
  type Erc5564StealthPaymentResult,
  type Erc5564StealthMetaAddress,
  type ThresholdStealthEphemeralSession,
} from '@seams/sdk/stealth';
```

Keep this separate from `@seams/sdk/threshold` because stealth derivation has
different lifecycle semantics from durable account signing sessions. Ephemeral
sender keys should use one-time contexts and short-lived relayer state.

### Sender-Side State

Use explicit lifecycle states for threshold ephemeral derivation:

```ts
type ThresholdStealthEphemeralSession =
  | {
      kind: 'prepared';
      sessionId: string;
      recipientViewingPublicKey33: Uint8Array;
      clientEphemeralPublicShare33: Uint8Array;
      relayerEphemeralPublicShare33: Uint8Array;
      thresholdEphemeralPublicKey33: Uint8Array;
      ecdhShareStatus?: never;
    }
  | {
      kind: 'ecdh_complete';
      sessionId: string;
      recipientViewingPublicKey33: Uint8Array;
      thresholdEphemeralPublicKey33: Uint8Array;
      sharedPoint33: Uint8Array;
      viewTag: number;
    }
  | {
      kind: 'announced';
      sessionId: string;
      thresholdEphemeralPublicKey33: Uint8Array;
      stealthAddress: `0x${string}`;
      viewTag: number;
      announcementTxHash: `0x${string}`;
    };
```

Core derivation functions should accept only the narrowest valid state. For
example, address construction should accept `kind: 'ecdh_complete'`, and
announcement tracking should accept `kind: 'announced'`.

### Recipient-Side State

Represent stealth spending as a tweaked signing lane:

```ts
type ThresholdEcdsaSigningKeyMode =
  | {
      kind: 'standard';
      tweak32?: never;
      derivedPublicKey33?: never;
      derivedEthereumAddress?: never;
    }
  | {
      kind: 'erc5564_stealth_address';
      tweak32: Uint8Array;
      basePublicKey33: Uint8Array;
      derivedPublicKey33: Uint8Array;
      derivedEthereumAddress: `0x${string}`;
      announcement: Erc5564AnnouncementRef;
    };
```

Signing APIs should require this branch explicitly instead of optional
`tweak32` bags. The default existing path is `kind: 'standard'`.

## Protocol Design

### Sender-Side Threshold Ephemeral Derivation

The sender threshold ephemeral key is additive:

```text
r = r_client + r_relayer mod n
R = rG = r_clientG + r_relayerG
Z = rP_view = r_clientP_view + r_relayerP_view
```

Flow:

1. SDK parses and validates the ERC-5564 meta-address at the boundary.
2. SDK generates a one-time client ephemeral share `r_client`.
3. SDK computes:
   - `R_client = r_clientG`.
   - `Z_client = r_clientP_view`.
4. SDK requests a one-time relayer contribution bound to:
   - wallet/session authority.
   - recipient `P_view`.
   - recipient `P_spend`.
   - chain id.
   - app origin/runtime policy scope.
   - request nonce.
5. Relayer derives or generates `r_relayer` and returns:
   - `R_relayer = r_relayerG`.
   - `Z_relayer = r_relayerP_view`.
6. SDK computes:
   - `R = R_client + R_relayer`.
   - `Z = Z_client + Z_relayer`.
   - `h = erc5564Hash(Z)`.
   - `P_stealth = P_spend + hG`.
   - `stealthAddress = pubkeyToAddress(P_stealth)`.
   - `viewTag = h[0]`.
7. Caller sends the asset to `stealthAddress` and announces `R` plus metadata
   through the ERC-5564 announcer contract.

Relayer state should be short-lived and one-time. It should never create an
ECDSA account signer, key handle, presignature pool entry, or durable wallet
key record for `r`.

### Recipient-Side Threshold Stealth Spending

For a threshold-controlled recipient spending key, the recipient derives the
same ERC-5564 tweak:

```text
h = erc5564Hash(p_view R)
P_stealth = P_spend + hG
p_stealth = p_spend + h
```

The threshold signer should sign with `p_spend + h` by passing `h` as the
threshold-signatures `Tweak`.

Required signer behavior:

1. Authorization binds the signing request to:
   - base ECDSA key handle.
   - base threshold public key `P_spend`.
   - `kind: 'erc5564_stealth_address'`.
   - tweak scalar `h`.
   - derived public key `P_spend + hG`.
   - derived Ethereum address.
   - source announcement reference.
2. Client signature-share computation uses `Tweak::new(h)`.
3. Relayer finalization uses the same `Tweak::new(h)`.
4. Final signature verification and recovery use the derived public key.
5. Budget, UI confirmation, and audit logs display the derived stealth address
   and retain the base signer identity separately.

No private key reconstruction is required for normal signing.

## Implementation Plan

### Phase 1: Core secp256k1 Primitives

Add the missing arithmetic to `crates/signer-core/src/secp256k1.rs`:

- `multiply_secp256k1_public_key_33(scalar32, publicKey33) -> publicKey33`.
- `add_secp256k1_private_scalars_32(left32, right32) -> scalar32` for export
  and fixtures only.
- `hash_erc5564_shared_secret_to_tweak32(sharedPoint33) -> tweak32`.
- `derive_erc5564_stealth_public_key(spendingPublicKey33, tweak32) -> publicKey33`.

Design choices:

- Treat zero tweak as invalid for ERC-5564 stealth derivation.
- Treat identity public-key sums as invalid.
- Return compressed SEC1 public keys internally.
- Convert to uncompressed only at Ethereum address/hash boundaries.

Add Rust unit tests for:

- scalar multiplication matches private scalar multiplication.
- `r_clientP + r_relayerP == (r_client + r_relayer)P`.
- stealth public key equals `(p_spend + h)G` for fixture scalars.
- invalid scalar/public-key inputs fail closed.

### Phase 2: WASM Boundaries

Expose the new primitives through `wasm/eth_signer`:

- `multiply_secp256k1_public_key_33`.
- `add_secp256k1_private_scalars_32`.
- `hash_erc5564_shared_secret_to_tweak_32`.
- `derive_erc5564_stealth_public_key_33`.

Update:

- `wasm/eth_signer/src/derive.rs`.
- `wasm/eth_signer/src/lib.rs`.
- `client/src/core/signingEngine/workerManager/workers/eth-signer.worker.ts`.
- `client/src/core/signingEngine/workerManager/workerTypes.ts`.
- `client/src/core/signingEngine/chains/evm/ethSignerWasm.ts`.

Keep raw `Uint8Array` inputs at the worker boundary and convert to precise
domain types in TypeScript wrappers.

### Phase 3: ERC-5564 SDK Module

Create `client/src/stealth.ts` and export it from the SDK package as
`@seams/sdk/stealth`.

Domain types should use required fields:

```ts
type Erc5564StealthMetaAddress = {
  scheme: 'erc5564';
  chain: 'eth';
  schemeId: 1;
  spendingPublicKey33: Uint8Array;
  viewingPublicKey33: Uint8Array;
};

type Erc5564StealthPaymentResult = {
  schemeId: 1;
  stealthAddress: `0x${string}`;
  ephemeralPublicKey33: Uint8Array;
  viewTag: number;
  metadata: Uint8Array;
  tweak32: Uint8Array;
  stealthPublicKey33: Uint8Array;
};
```

Functions:

- `parseErc5564StealthMetaAddress(raw: string): Result<Erc5564StealthMetaAddress, ParseError>`.
- `deriveErc5564StealthAddress(args): Promise<Erc5564StealthPaymentResult>`.
- `computeErc5564ViewTag(tweak32): number`.
- `buildErc5564AnnouncementMetadata(args): Uint8Array`.

Use `Result`-style unions for recoverable parsing/validation failures. Throw
only for programmer errors or worker failures.

### Phase 4: Threshold Sender Ephemeral Module

Add a threshold sender flow that does one-time ephemeral derivation:

```ts
type ThresholdErc5564SenderEphemeralRequest = {
  kind: 'threshold_erc5564_sender_ephemeral';
  relayerUrl: string;
  walletId: WalletId;
  recipient: Erc5564StealthMetaAddress;
  chainId: number;
  requestNonce32: Uint8Array;
  runtimePolicyScope: RuntimePolicyScope;
};
```

Server endpoint shape:

- `POST /threshold-ecdsa/stealth/ephemeral`
  - validates session authority.
  - derives or allocates one-time relayer scalar.
  - returns `relayerEphemeralPublicShare33B64u` and
    `relayerViewingSharedPoint33B64u`.

Client computes the final public values. The server should never receive the
client ephemeral scalar.

Persistence:

- Prefer stateless deterministic relayer derivation from a server secret,
  request nonce, recipient keys, chain id, and wallet.
- If stateful replay protection is required, store only a request digest and
  expiry. Do not store the relayer scalar.

### Phase 5: Threshold ECDSA Tweak Support

Extend threshold ECDSA signing with an explicit tweak branch.

Rust:

- Change `threshold_ecdsa_compute_signature_share` to accept a required
  `SigningTweak` enum at the WASM/core boundary.
- Change `threshold_ecdsa_finalize_signature` to accept the same tweak.
- Pass `Tweak::new(tweakScalar)` into `RerandomizationArguments`.
- Verify the final signature against the derived public key.

TypeScript:

- Add a discriminated signing-mode union to ECDSA signing material.
- Require `kind: 'standard'` for existing paths.
- Require `kind: 'erc5564_stealth_address'` for stealth spending.
- Avoid optional `tweak32` in core signing functions.

Server:

- Add tweak fields to Router A/B ECDSA-HSS prepare/finalize request and
  active-state records.
- Bind the authorization record to the derived address and announcement ref.
- Persist only public tweak metadata and authorization state.

Client:

- Include tweak metadata in the Router A/B ECDSA-HSS signing helper.
- Include tweak metadata in presign pool keys only if the protocol requires
  separate presign pools. The threshold-signatures rerandomization design should
  allow base-key presignatures to be reused across tweaks, so start with the
  existing base-key pool.

### Phase 6: Recipient Scanning And Spending UX

Add a scanner boundary that consumes announcement events and returns typed
matches:

```ts
type Erc5564AnnouncementMatch =
  | {
      kind: 'matched_threshold_spending_key';
      announcement: Erc5564AnnouncementRef;
      baseSpendingPublicKey33: Uint8Array;
      stealthPublicKey33: Uint8Array;
      stealthAddress: `0x${string}`;
      tweak32: Uint8Array;
      viewTag: number;
    }
  | {
      kind: 'view_tag_mismatch';
      announcement: Erc5564AnnouncementRef;
      expectedViewTag: number;
      actualViewTag: number;
    }
  | {
      kind: 'address_mismatch';
      announcement: Erc5564AnnouncementRef;
      derivedAddress: `0x${string}`;
      announcedAddress: `0x${string}`;
    };
```

The scanner validates and normalizes raw logs once. Core matching logic should
only receive parsed announcements and known key material.

Spending flow:

1. User selects a matched stealth UTXO-like EVM account.
2. SDK builds a signing lane with `kind: 'erc5564_stealth_address'`.
3. Wallet confirmation displays the stealth address as the sending account.
4. Signing uses the base threshold ECDSA key plus the ERC-5564 tweak.

### Phase 7: Contracts And Announcement Helpers

The SDK should avoid owning ERC-5564 contracts. It should provide helpers to:

- encode announcer call data.
- encode native/ERC20/ERC721 metadata with the first byte as `viewTag`.
- optionally target known announcer addresses per chain through config.

Keep contract addresses and chain support configurable at request boundaries.

### Phase 8: Tests And Fixtures

Add tests in increasing cost order:

- Rust core tests for secp256k1 primitives and tweak math.
- WASM worker unit tests for new primitive wrappers.
- TypeScript type fixtures with `@ts-expect-error` for invalid tweak states:
  - `kind: 'standard'` carrying `tweak32`.
  - stealth address mode missing `derivedEthereumAddress`.
  - signing function receiving raw optional tweak data.
- SDK unit tests for ERC-5564 meta-address parsing.
- End-to-end threshold ECDSA signing test that signs with a known tweak and
  verifies recovery against `P_base + hG`.
- Integration fixture comparing local ERC-5564 derivation against a known
  implementation.

Full browser E2E should wait until the core tweak signing path is stable.

## Security Notes

- The sender ephemeral scalar must be one-time. Reusing `r` across recipients
  or payments weakens privacy.
- The relayer contribution must be bound to recipient keys, chain id, wallet
  subject, and request nonce.
- Recipient scanning with view tags leaks one byte of `hash(Z)` by design.
- Funding stealth addresses from a known account can link the recipient.
- Threshold spending signs as the derived stealth address. UI, audit, and
  budget checks must display and authorize that derived address.
- Export flows that reconstruct a private key need separate handling:
  `p_stealth = p_spend + h`. Normal threshold signing should use tweak signing.

## Open Questions

- Which hash encoding should be used for `hash(Z)` in our ERC-5564
  implementation: compressed SEC1, uncompressed SEC1, or x-coordinate-only?
  Resolve this against the reference implementation and lock fixtures.
- Should sender-side threshold ephemeral relayer shares be deterministic or
  stateful random? Deterministic derivation reduces persistence, while stateful
  derivation can give stronger replay controls.
- Should `@seams/sdk/stealth` include log scanning helpers, or should scanning
  live in a higher-level wallet module that already owns RPC providers?
- Should stealth spending consume the existing base-key presign pool across all
  tweaks, or should pool policy support an optional per-tweak isolation mode?

## First Cut

The smallest useful implementation is:

1. Add core/WASM secp256k1 scalar-multiply-public-key and ERC-5564 address
   derivation helpers.
2. Add `@seams/sdk/stealth` for local single-party sender derivation and
   meta-address parsing.
3. Add threshold ECDSA tweak support for recipient-side stealth spending.
4. Add threshold sender-side ephemeral derivation after the tweak signing path
   is tested.

This order gives us ERC-5564 compatibility and recipient-side threshold
spending first, then adds the more privacy-sensitive sender threshold ephemeral
flow once fixtures and signing semantics are stable.
