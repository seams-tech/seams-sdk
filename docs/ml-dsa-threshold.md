# Threshold ML-DSA Feasibility

Status: design note for adding small-party threshold ML-DSA signing to the SDK.

## Summary

Adding Mithril-style threshold ML-DSA is feasible in the current architecture.
For a 2-3 party deployment, the threshold-service layer is a good fit: it
already has scheme modules, short-lived threshold sessions, authorization
routes, client/relayer signing roles, and WASM-backed client signing workers.

End-to-end NEAR transaction signing is a medium-sized integration because the
current NEAR signer stack is Ed25519-shaped. The service can host a Mithril
protocol driver with limited disruption, while the NEAR signer wire model needs
new ML-DSA public key and signature variants once NEAR finalizes its protocol
encoding.

The recommended approach is to add ML-DSA as a new signer family instead of
generalizing the existing Ed25519 implementation in place.

## External Facts

NIST FIPS 204 standardizes ML-DSA and defines key generation, signing, and
verification for three parameter sets: ML-DSA-44, ML-DSA-65, and ML-DSA-87.
The signature sizes are 2420, 3309, and 4627 bytes respectively, and public keys
are 1312, 1952, and 2592 bytes respectively.

Mithril / Efficient Threshold ML-DSA claims full ML-DSA verifier compatibility
and small-party support up to six parties. The NIST MPTS 2026 presentation also
states that Mithril supports DKG and a posteriori sharing of an existing ML-DSA
key while preserving the original public key.

Leo Kao's threshold ML-DSA work is relevant for future variants. The January
2026 paper describes arbitrary-threshold standard ML-DSA signatures, and TALUS
describes one-round online signing with standard verifier compatibility. These
are useful comparison points, but Mithril is the better first target for a 2-3
node deployment because its small-party scope matches the product requirement.

Sources:

- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [Efficient Threshold ML-DSA, USENIX Security 2026](https://www.usenix.org/conference/usenixsecurity26/presentation/celi)
- [Mithril NIST MPTS 2026 presentation](https://csrc.nist.gov/presentations/2026/mpts2026-3b7)
- [Kao: FIPS 204-Compatible Threshold ML-DSA via Shamir Nonce DKG](https://arxiv.org/abs/2601.20917)
- [Kao: TALUS](https://arxiv.org/abs/2603.22109)

## Current Architecture Fit

### Server Threshold Service

The server has a scheme-module boundary under
`server/src/core/ThresholdService/schemes`. Today the registered schemes are:

- `threshold-ed25519-frost-2p-v1`
- `threshold-secp256k1-ecdsa-2p-v1`

Mithril should be added as a new scheme id, for example:

```ts
export const THRESHOLD_ML_DSA_MITHRIL_V1_SCHEME_ID =
  'threshold-ml-dsa-mithril-v1' as const;
```

The scheme module should own:

- ML-DSA parameter set: `ml-dsa-44`, `ml-dsa-65`, or `ml-dsa-87`
- party set and threshold
- keygen or share import
- threshold session minting and authorization
- per-signing-session transcript state
- final standard ML-DSA signature verification before returning a result

The current `ThresholdProtocolDriver` shape is enough for two-round protocols.
Mithril should use a protocol-specific state machine because its transcript is
multi-round and carries scheme-specific commitments, masks, local rejection
state, and aggregation inputs.

Use explicit lifecycle state types:

```ts
type MithrilSigningSession =
  | {
      state: 'initialized';
      sessionId: string;
      keyId: string;
      parameterSet: 'ml-dsa-44' | 'ml-dsa-65' | 'ml-dsa-87';
      participantIds: number[];
      threshold: number;
      messageDigest32: string;
    }
  | {
      state: 'round1_complete';
      sessionId: string;
      round1TranscriptB64u: string;
    }
  | {
      state: 'round2_complete';
      sessionId: string;
      round2TranscriptB64u: string;
    }
  | {
      state: 'finalized';
      sessionId: string;
      signatureB64u: string;
    };
```

Raw request bodies should be normalized once at route boundaries into these
states. Internal protocol code should accept the narrow state type required for
the next step.

### Client Signing Engine

The client signing interfaces already model algorithms and key refs, but the
algorithm set currently contains Ed25519, secp256k1, and WebAuthn P-256. Add an
ML-DSA NEAR lane as a distinct key ref and signing request variant:

```ts
type NearMlDsaParameterSet = 'ml-dsa-44' | 'ml-dsa-65' | 'ml-dsa-87';

type ThresholdMlDsaKeyRef = {
  type: 'threshold-ml-dsa-mithril';
  nearAccountId: string;
  signerSlot: number;
  relayerUrl: string;
  keyId: string;
  parameterSet: NearMlDsaParameterSet;
  participantIds: number[];
  threshold: number;
  publicKeyB64u: string;
  thresholdSessionId: string;
  walletSigningSessionId: string;
  thresholdSessionAuthToken: string;
};
```

The NEAR lane selector should select exactly one concrete ML-DSA lane for an
operation, parallel to the existing Ed25519 lane selection model. The ML-DSA
lane must carry the parameter set and public key identity as required fields.

### WASM NEAR Signer

The main implementation work is here. Current NEAR worker types use fixed
Ed25519 shapes:

- public key: key type plus `[u8; 32]`
- signature: key type plus `[u8; 64]`
- transaction builder accepts `public_key_bytes: &[u8; 32]`
- transaction finalizer accepts `signature_bytes: &[u8; 64]`

ML-DSA requires variable-size public keys and signatures. Replace the internal
NEAR key/signature representation with explicit variants:

```rust
pub enum NearPublicKey {
    Ed25519([u8; 32]),
    MlDsa {
        parameter_set: MlDsaParameterSet,
        bytes: Vec<u8>,
    },
}

pub enum NearSignature {
    Ed25519([u8; 64]),
    MlDsa {
        parameter_set: MlDsaParameterSet,
        bytes: Vec<u8>,
    },
}
```

The Borsh serialization must match NEAR's final protocol encoding exactly. That
encoding is the production blocker. Until NEAR publishes the final enum tags,
public key prefixes, transaction hashing rules, and access-key format, the SDK
can only implement an internal prototype.

### Key Material Storage

Do not reuse `threshold_ed25519_v1` payloads. Add a precise key-material kind:

```ts
type ThresholdMlDsaKeyMaterial = {
  kind: 'threshold_ml_dsa_mithril_v1';
  nearAccountId: string;
  signerSlot: number;
  publicKey: string;
  parameterSet: 'ml-dsa-44' | 'ml-dsa-65' | 'ml-dsa-87';
  threshold: number;
  participantIds: number[];
  keyId: string;
  keyVersion: string;
  timestamp: number;
};
```

The storage boundary should validate public key length against the parameter set
and persist the normalized internal record.

## Implementation Approach

### Phase 1: Protocol Spike

Goal: verify the Mithril crate/API shape and transcript model.

Tasks:

1. Add a private Rust crate or feature-gated module for Mithril ML-DSA.
2. Generate and verify standard ML-DSA signatures for a fixed 2-of-3 local
   setup.
3. Verify output with an unmodified FIPS 204 verifier.
4. Measure signature latency and transcript sizes for ML-DSA-44 first.

Acceptance criteria:

- local 2-of-3 signing produces a standard ML-DSA signature
- verification passes through a standard verifier
- transcript state is serializable without exposing secret shares

### Phase 2: Server Scheme Module

Goal: make Mithril available through the existing threshold service boundary.

Tasks:

1. Add `threshold-ml-dsa-mithril-v1` scheme id.
2. Add typed keygen/import and session records.
3. Add route handlers for Mithril signing rounds.
4. Bind authorization to NEAR account, key id, parameter set, participant set,
   threshold, operation digest, and wallet signing session.
5. Verify the final signature server-side before returning it.

Acceptance criteria:

- no raw JSON protocol transcript flows past route validation
- signing sessions move through monotonic typed states
- repeated or out-of-order round messages fail with typed errors

### Phase 3: Client And Worker Integration

Goal: support ML-DSA signing through the wallet signing flow.

Tasks:

1. Add ML-DSA lane identity and key-material readers/writers.
2. Add signer worker request/response types for ML-DSA threshold signing.
3. Add ML-DSA signer backend beside the current Ed25519 backend.
4. Add NEAR transaction serialization variants once NEAR wire encoding lands.
5. Add flow events and readiness checks specific to ML-DSA threshold lanes.

Acceptance criteria:

- lane selection identifies Ed25519 and ML-DSA capabilities independently
- all ML-DSA lifecycle fields are required after boundary normalization
- worker signing returns a standard ML-DSA signature and typed algorithm metadata

### Phase 4: Compatibility And Safety Gates

Goal: make the path safe enough for testnet.

Tasks:

1. Add FIPS 204 known-answer tests for the chosen parameter set.
2. Add NEAR transaction serialization fixtures for ML-DSA access keys and
   signatures.
3. Add cross-verification against NEAR's reference implementation.
4. Add transcript replay, wrong participant, wrong parameter set, and wrong key
   id tests.
5. Add bundle-size and WASM performance checks.

Acceptance criteria:

- signed transactions match NEAR reference fixtures byte-for-byte
- incompatible parameter-set/key-id combinations fail at validation boundaries
- ML-DSA path has no fallback to Ed25519 signing for the same operation

## Main Risks

### NEAR Wire Format

The SDK should wait for NEAR's final ML-DSA public key and signature enum
encoding before production support. Internal prototypes can use a temporary
encoding behind private tests.

### Library Maturity

Mithril implementations are new. Treat the first integration as experimental
until the chosen implementation has audit coverage, stable APIs, and standard
verifier compatibility tests.

### Transcript Size

Mithril is practical for 2-3 nodes, but transcript messages are larger than the
existing Ed25519 FROST messages. The relayer routes and worker transport should
use explicit size limits per round.

### Bundle And WASM Size

ML-DSA arithmetic and threshold logic will increase worker size. Keep the
implementation behind a feature boundary and load it only for ML-DSA lanes.

## Recommendation

Proceed with a Mithril ML-DSA spike targeting ML-DSA-44 and a fixed 2-of-3
local configuration. After the protocol spike passes standard verification, add
the server scheme module and typed lifecycle records. Wire it into NEAR
transaction signing after NEAR publishes the final ML-DSA transaction encoding.
