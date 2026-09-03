use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use threshold_prf::{
    complete_ed25519_deriver_a_target_v1, complete_ed25519_deriver_b_target_v1,
    Ed25519DeriverAThresholdPrfRootV1, Ed25519DeriverAToBTargetProofBundleV1,
    Ed25519DeriverBThresholdPrfRootV1, Ed25519DeriverBToATargetProofBundleV1,
    PreparedEd25519DeriverATargetV1, PreparedEd25519DeriverBTargetV1, ThresholdPrfError,
};

use crate::derivation::PublicDigest32;
use crate::protocol::ed25519_yao::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedInputV1,
    Ed25519YaoStableKeyContextBindingV1,
};
use crate::protocol::error::{
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};

/// Version identity for the role-targeted Ed25519 outer protocol.
pub const ROUTER_AB_ED25519_YAO_OUTER_PROTOCOL_ID_V2: &str = "router_ab_ed25519_yao_outer_v2";

/// Maximum lifetime of an outer preface binding.
pub const ED25519_YAO_OUTER_MAX_LIFETIME_MS_V2: u64 = 300_000;

/// Maximum clock skew accepted for an outer preface binding.
pub const ED25519_YAO_OUTER_MAX_CLOCK_SKEW_MS_V2: u64 = 60_000;

/// Number of bytes in the directional transport nonce.
pub const ED25519_YAO_OUTER_NONCE_LEN_V2: usize = 16;

/// Maximum ciphertext length for one directional target-proof payload.
pub const ED25519_YAO_OUTER_TARGET_PROOF_MAX_BYTES_V2: usize = 4 * 1024;

const HPKE_ENCAPSULATED_KEY_LEN_V2: usize = 32;
const HPKE_TAG_LEN_V2: usize = 16;
const TARGET_PROOF_WIRE_MAGIC_V2: &[u8; 8] = b"R120PRF2";
const TARGET_PROOF_WIRE_VERSION_V2: u8 = 2;
const TARGET_PROOF_ROLE_A_V2: u8 = 1;
const TARGET_PROOF_ROLE_B_V2: u8 = 2;
const TARGET_PROOF_AAD_LEN_V2: usize = 139;

/// Wire version for the role-targeted Ed25519 outer protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ed25519YaoOuterProtocolVersionV2 {
    /// The fixed role-targeted outer protocol.
    V2,
}

impl Ed25519YaoOuterProtocolVersionV2 {
    /// Returns the stable wire version label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2 => "v2",
        }
    }
}

/// One non-zero pair-session identity for the V2 outer protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Ed25519YaoPairSessionIdV2([u8; 32]);

impl Ed25519YaoPairSessionIdV2 {
    /// Creates a pair-session identity from exact bytes.
    pub fn new(bytes: [u8; 32]) -> RouterAbProtocolResult<Self> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(malformed("Ed25519 Yao V2 pair session must be nonzero"));
        }
        Ok(Self(bytes))
    }

    /// Creates the V2 identity for an existing Yao session transcript.
    pub fn from_yao_session(session: crate::protocol::ed25519_yao::Ed25519YaoSessionIdV1) -> Self {
        Self(session.into_bytes())
    }

    /// Returns the exact session bytes.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Returns the exact session bytes by reference.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Ed25519YaoPairSessionIdV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(<[u8; 32]>::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Epoch-bound metadata shared by both directional target-proof payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoOuterBindingV2 {
    version: Ed25519YaoOuterProtocolVersionV2,
    pair_session: Ed25519YaoPairSessionIdV2,
    stable_context_binding: Ed25519YaoStableKeyContextBindingV1,
    custody_binding_digest: PublicDigest32,
    nonce: [u8; ED25519_YAO_OUTER_NONCE_LEN_V2],
    issued_at_ms: u64,
    expires_at_ms: u64,
}

impl Ed25519YaoOuterBindingV2 {
    /// Creates a validated outer binding. Stable context bytes never cross this boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pair_session: Ed25519YaoPairSessionIdV2,
        stable_context_binding: Ed25519YaoStableKeyContextBindingV1,
        custody_binding_digest: PublicDigest32,
        nonce: [u8; ED25519_YAO_OUTER_NONCE_LEN_V2],
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let binding = Self {
            version: Ed25519YaoOuterProtocolVersionV2::V2,
            pair_session,
            stable_context_binding,
            custody_binding_digest,
            nonce,
            issued_at_ms,
            expires_at_ms,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates nonces, digests, and the fixed lifetime window.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        if self
            .stable_context_binding
            .into_bytes()
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(malformed(
                "Ed25519 Yao V2 stable context binding must be nonzero",
            ));
        }
        validate_digest("custody binding digest", self.custody_binding_digest)?;
        if self.nonce.iter().all(|byte| *byte == 0) {
            return Err(malformed("Ed25519 Yao V2 outer nonce must be nonzero"));
        }
        if self.issued_at_ms == 0
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > ED25519_YAO_OUTER_MAX_LIFETIME_MS_V2
        {
            return Err(malformed(
                "Ed25519 Yao V2 outer binding lifetime is invalid",
            ));
        }
        Ok(())
    }

    /// Validates the binding against a peer wall clock.
    pub fn validate_at(&self, now_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if self.issued_at_ms > now_ms.saturating_add(ED25519_YAO_OUTER_MAX_CLOCK_SKEW_MS_V2)
            || now_ms
                > self
                    .expires_at_ms
                    .saturating_add(ED25519_YAO_OUTER_MAX_CLOCK_SKEW_MS_V2)
        {
            return Err(malformed(
                "Ed25519 Yao V2 outer binding is outside its clock window",
            ));
        }
        Ok(())
    }

    /// Returns the V2 wire version.
    pub const fn version(&self) -> Ed25519YaoOuterProtocolVersionV2 {
        self.version
    }

    /// Returns the exact pair-session identity.
    pub const fn pair_session(&self) -> Ed25519YaoPairSessionIdV2 {
        self.pair_session
    }

    /// Returns the stable context binding digest.
    pub const fn stable_context_binding(&self) -> Ed25519YaoStableKeyContextBindingV1 {
        self.stable_context_binding
    }

    /// Returns the epoch-bound custody binding digest.
    pub const fn custody_binding_digest(&self) -> PublicDigest32 {
        self.custody_binding_digest
    }

    /// Returns the exact directional transport nonce.
    pub const fn nonce(&self) -> &[u8; ED25519_YAO_OUTER_NONCE_LEN_V2] {
        &self.nonce
    }

    /// Returns the issue timestamp.
    pub const fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    /// Returns the expiry timestamp.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEd25519YaoOuterBindingV2 {
    version: Ed25519YaoOuterProtocolVersionV2,
    pair_session: Ed25519YaoPairSessionIdV2,
    stable_context_binding: Ed25519YaoStableKeyContextBindingV1,
    custody_binding_digest: PublicDigest32,
    nonce: [u8; ED25519_YAO_OUTER_NONCE_LEN_V2],
    issued_at_ms: u64,
    expires_at_ms: u64,
}

impl<'de> Deserialize<'de> for Ed25519YaoOuterBindingV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawEd25519YaoOuterBindingV2::deserialize(deserializer)?;
        if raw.version != Ed25519YaoOuterProtocolVersionV2::V2 {
            return Err(D::Error::custom("unsupported Ed25519 Yao V2 outer version"));
        }
        Self::new(
            raw.pair_session,
            raw.stable_context_binding,
            raw.custody_binding_digest,
            raw.nonce,
            raw.issued_at_ms,
            raw.expires_at_ms,
        )
        .map_err(D::Error::custom)
    }
}

/// A-to-B encrypted payload. Its plaintext is always B's fixed target proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoDeriverAToBTargetProofPayloadV2 {
    binding: Ed25519YaoOuterBindingV2,
    encapsulated_key: [u8; HPKE_ENCAPSULATED_KEY_LEN_V2],
    ciphertext: Vec<u8>,
}

impl Ed25519YaoDeriverAToBTargetProofPayloadV2 {
    /// Encodes the exact A-to-B HPKE associated data.
    pub fn aad_for_binding(
        binding: &Ed25519YaoOuterBindingV2,
    ) -> RouterAbProtocolResult<[u8; TARGET_PROOF_AAD_LEN_V2]> {
        encode_target_proof_aad_v2(binding, TARGET_PROOF_ROLE_A_V2, TARGET_PROOF_ROLE_B_V2)
    }

    /// Creates a validated encrypted A-to-B target-proof payload.
    pub fn new(
        binding: Ed25519YaoOuterBindingV2,
        encapsulated_key: [u8; HPKE_ENCAPSULATED_KEY_LEN_V2],
        ciphertext: Vec<u8>,
    ) -> RouterAbProtocolResult<Self> {
        let payload = Self {
            binding,
            encapsulated_key,
            ciphertext,
        };
        payload.validate()?;
        Ok(payload)
    }

    /// Validates the exact fixed plaintext-derived ciphertext shape.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.binding.validate()?;
        if self.encapsulated_key.iter().all(|byte| *byte == 0) {
            return Err(malformed(
                "Ed25519 Yao V2 target payload key must be nonzero",
            ));
        }
        let expected = Ed25519DeriverAToBTargetProofBundleV1::LEN + HPKE_TAG_LEN_V2;
        if self.ciphertext.len() != expected
            || self.ciphertext.len() > ED25519_YAO_OUTER_TARGET_PROOF_MAX_BYTES_V2
        {
            return Err(malformed(
                "Ed25519 Yao V2 A-to-B ciphertext length is invalid",
            ));
        }
        Ok(())
    }

    /// Validates that this payload belongs to one exact outer binding.
    pub fn validate_for_binding(
        &self,
        expected: &Ed25519YaoOuterBindingV2,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if self.binding != *expected {
            return Err(malformed("Ed25519 Yao V2 A-to-B payload binding mismatch"));
        }
        Ok(())
    }

    /// Parses an already-authenticated plaintext into the fixed B-target bundle.
    pub fn decode_plaintext(
        &self,
        plaintext: &[u8],
    ) -> RouterAbProtocolResult<Ed25519DeriverAToBTargetProofBundleV1> {
        self.validate()?;
        Ed25519DeriverAToBTargetProofBundleV1::from_slice(plaintext).map_err(threshold_prf_error)
    }

    /// Returns the outer binding.
    pub const fn binding(&self) -> &Ed25519YaoOuterBindingV2 {
        &self.binding
    }

    /// Returns the fixed HPKE encapsulated key.
    pub const fn encapsulated_key(&self) -> &[u8; HPKE_ENCAPSULATED_KEY_LEN_V2] {
        &self.encapsulated_key
    }

    /// Returns the encrypted target proof.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Encodes the fixed binary A-to-B transport frame.
    pub fn encode_fixed_wire(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        encode_target_proof_wire_v2(
            Self::aad_for_binding(&self.binding)?,
            &self.encapsulated_key,
            &self.ciphertext,
        )
    }

    /// Decodes one exact fixed binary A-to-B transport frame.
    pub fn decode_fixed_wire(bytes: &[u8]) -> RouterAbProtocolResult<Self> {
        let (binding, encapsulated_key, ciphertext) = decode_target_proof_wire_v2(
            bytes,
            TARGET_PROOF_ROLE_A_V2,
            TARGET_PROOF_ROLE_B_V2,
            Ed25519DeriverAToBTargetProofBundleV1::LEN + HPKE_TAG_LEN_V2,
        )?;
        Self::new(binding, encapsulated_key, ciphertext)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEd25519YaoDeriverAToBTargetProofPayloadV2 {
    binding: Ed25519YaoOuterBindingV2,
    encapsulated_key: [u8; HPKE_ENCAPSULATED_KEY_LEN_V2],
    ciphertext: Vec<u8>,
}

impl<'de> Deserialize<'de> for Ed25519YaoDeriverAToBTargetProofPayloadV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawEd25519YaoDeriverAToBTargetProofPayloadV2::deserialize(deserializer)?;
        Self::new(raw.binding, raw.encapsulated_key, raw.ciphertext).map_err(D::Error::custom)
    }
}

/// B-to-A encrypted payload. Its plaintext is always A's fixed target proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoDeriverBToATargetProofPayloadV2 {
    binding: Ed25519YaoOuterBindingV2,
    encapsulated_key: [u8; HPKE_ENCAPSULATED_KEY_LEN_V2],
    ciphertext: Vec<u8>,
}

impl Ed25519YaoDeriverBToATargetProofPayloadV2 {
    /// Encodes the exact B-to-A HPKE associated data.
    pub fn aad_for_binding(
        binding: &Ed25519YaoOuterBindingV2,
    ) -> RouterAbProtocolResult<[u8; TARGET_PROOF_AAD_LEN_V2]> {
        encode_target_proof_aad_v2(binding, TARGET_PROOF_ROLE_B_V2, TARGET_PROOF_ROLE_A_V2)
    }

    /// Creates a validated encrypted B-to-A target-proof payload.
    pub fn new(
        binding: Ed25519YaoOuterBindingV2,
        encapsulated_key: [u8; HPKE_ENCAPSULATED_KEY_LEN_V2],
        ciphertext: Vec<u8>,
    ) -> RouterAbProtocolResult<Self> {
        let payload = Self {
            binding,
            encapsulated_key,
            ciphertext,
        };
        payload.validate()?;
        Ok(payload)
    }

    /// Validates the exact fixed plaintext-derived ciphertext shape.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.binding.validate()?;
        if self.encapsulated_key.iter().all(|byte| *byte == 0) {
            return Err(malformed(
                "Ed25519 Yao V2 target payload key must be nonzero",
            ));
        }
        let expected = Ed25519DeriverBToATargetProofBundleV1::LEN + HPKE_TAG_LEN_V2;
        if self.ciphertext.len() != expected
            || self.ciphertext.len() > ED25519_YAO_OUTER_TARGET_PROOF_MAX_BYTES_V2
        {
            return Err(malformed(
                "Ed25519 Yao V2 B-to-A ciphertext length is invalid",
            ));
        }
        Ok(())
    }

    /// Validates that this payload belongs to one exact outer binding.
    pub fn validate_for_binding(
        &self,
        expected: &Ed25519YaoOuterBindingV2,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if self.binding != *expected {
            return Err(malformed("Ed25519 Yao V2 B-to-A payload binding mismatch"));
        }
        Ok(())
    }

    /// Parses an already-authenticated plaintext into the fixed A-target bundle.
    pub fn decode_plaintext(
        &self,
        plaintext: &[u8],
    ) -> RouterAbProtocolResult<Ed25519DeriverBToATargetProofBundleV1> {
        self.validate()?;
        Ed25519DeriverBToATargetProofBundleV1::from_slice(plaintext).map_err(threshold_prf_error)
    }

    /// Returns the outer binding.
    pub const fn binding(&self) -> &Ed25519YaoOuterBindingV2 {
        &self.binding
    }

    /// Returns the fixed HPKE encapsulated key.
    pub const fn encapsulated_key(&self) -> &[u8; HPKE_ENCAPSULATED_KEY_LEN_V2] {
        &self.encapsulated_key
    }

    /// Returns the encrypted target proof.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Encodes the fixed binary B-to-A transport frame.
    pub fn encode_fixed_wire(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        encode_target_proof_wire_v2(
            Self::aad_for_binding(&self.binding)?,
            &self.encapsulated_key,
            &self.ciphertext,
        )
    }

    /// Decodes one exact fixed binary B-to-A transport frame.
    pub fn decode_fixed_wire(bytes: &[u8]) -> RouterAbProtocolResult<Self> {
        let (binding, encapsulated_key, ciphertext) = decode_target_proof_wire_v2(
            bytes,
            TARGET_PROOF_ROLE_B_V2,
            TARGET_PROOF_ROLE_A_V2,
            Ed25519DeriverBToATargetProofBundleV1::LEN + HPKE_TAG_LEN_V2,
        )?;
        Self::new(binding, encapsulated_key, ciphertext)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEd25519YaoDeriverBToATargetProofPayloadV2 {
    binding: Ed25519YaoOuterBindingV2,
    encapsulated_key: [u8; HPKE_ENCAPSULATED_KEY_LEN_V2],
    ciphertext: Vec<u8>,
}

impl<'de> Deserialize<'de> for Ed25519YaoDeriverBToATargetProofPayloadV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawEd25519YaoDeriverBToATargetProofPayloadV2::deserialize(deserializer)?;
        Self::new(raw.binding, raw.encapsulated_key, raw.ciphertext).map_err(D::Error::custom)
    }
}

/// Complete V2 preface request carrying the two existing Yao inputs and one
/// recipient-encrypted target proof in each direction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519YaoPrefaceRequestV2 {
    ceremony: Ed25519YaoCeremonyBindingV1,
    outer_binding: Ed25519YaoOuterBindingV2,
    deriver_a_input: Ed25519YaoEncryptedInputV1,
    deriver_b_input: Ed25519YaoEncryptedInputV1,
    deriver_a_to_b: Ed25519YaoDeriverAToBTargetProofPayloadV2,
    deriver_b_to_a: Ed25519YaoDeriverBToATargetProofPayloadV2,
}

impl RouterAbEd25519YaoPrefaceRequestV2 {
    /// Creates a validated request after the control plane selected all outer metadata.
    pub fn new(
        ceremony: Ed25519YaoCeremonyBindingV1,
        outer_binding: Ed25519YaoOuterBindingV2,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
        deriver_a_to_b: Ed25519YaoDeriverAToBTargetProofPayloadV2,
        deriver_b_to_a: Ed25519YaoDeriverBToATargetProofPayloadV2,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            ceremony,
            outer_binding,
            deriver_a_input,
            deriver_b_input,
            deriver_a_to_b,
            deriver_b_to_a,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates the exact Yao input pair and both fixed proof directions.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.ceremony.validate()?;
        self.outer_binding.validate()?;
        let expected_session = self.outer_binding.pair_session().into_bytes();
        let expected_stable = self.outer_binding.stable_context_binding().into_bytes();
        if self.ceremony.session_id.into_bytes() != expected_session
            || self.ceremony.stable_key_context_binding.into_bytes() != expected_stable
        {
            return Err(malformed(
                "Ed25519 Yao V2 outer binding does not match ceremony",
            ));
        }
        validate_yao_input(
            &self.ceremony,
            &self.deriver_a_input,
            Ed25519YaoDeriverRoleV1::DeriverA,
        )?;
        validate_yao_input(
            &self.ceremony,
            &self.deriver_b_input,
            Ed25519YaoDeriverRoleV1::DeriverB,
        )?;
        self.deriver_a_to_b
            .validate_for_binding(&self.outer_binding)?;
        self.deriver_b_to_a
            .validate_for_binding(&self.outer_binding)
    }

    /// Returns the ceremony binding used by unchanged Yao artifacts.
    pub const fn ceremony(&self) -> &Ed25519YaoCeremonyBindingV1 {
        &self.ceremony
    }

    /// Returns the V2 epoch-bound outer binding.
    pub const fn outer_binding(&self) -> &Ed25519YaoOuterBindingV2 {
        &self.outer_binding
    }

    /// Returns the existing opaque A/B Yao inputs.
    pub const fn yao_inputs(&self) -> (&Ed25519YaoEncryptedInputV1, &Ed25519YaoEncryptedInputV1) {
        (&self.deriver_a_input, &self.deriver_b_input)
    }

    /// Returns the encrypted A-to-B target proof.
    pub const fn deriver_a_to_b(&self) -> &Ed25519YaoDeriverAToBTargetProofPayloadV2 {
        &self.deriver_a_to_b
    }

    /// Returns the encrypted B-to-A target proof.
    pub const fn deriver_b_to_a(&self) -> &Ed25519YaoDeriverBToATargetProofPayloadV2 {
        &self.deriver_b_to_a
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouterAbEd25519YaoPrefaceRequestV2 {
    ceremony: Ed25519YaoCeremonyBindingV1,
    outer_binding: Ed25519YaoOuterBindingV2,
    deriver_a_input: Ed25519YaoEncryptedInputV1,
    deriver_b_input: Ed25519YaoEncryptedInputV1,
    deriver_a_to_b: Ed25519YaoDeriverAToBTargetProofPayloadV2,
    deriver_b_to_a: Ed25519YaoDeriverBToATargetProofPayloadV2,
}

impl<'de> Deserialize<'de> for RouterAbEd25519YaoPrefaceRequestV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterAbEd25519YaoPrefaceRequestV2::deserialize(deserializer)?;
        Self::new(
            raw.ceremony,
            raw.outer_binding,
            raw.deriver_a_input,
            raw.deriver_b_input,
            raw.deriver_a_to_b,
            raw.deriver_b_to_a,
        )
        .map_err(D::Error::custom)
    }
}

/// Role-local Deriver A preface state before the peer proof is opened.
pub struct Ed25519YaoDeriverAPrefaceInFlightV2 {
    binding: Ed25519YaoOuterBindingV2,
    prepared: PreparedEd25519DeriverATargetV1,
    outbound: Ed25519DeriverAToBTargetProofBundleV1,
}

impl core::fmt::Debug for Ed25519YaoDeriverAPrefaceInFlightV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Ed25519YaoDeriverAPrefaceInFlightV2([redacted])")
    }
}

impl Ed25519YaoDeriverAPrefaceInFlightV2 {
    /// Creates A's local preface state from the fixed threshold-prf preparation result.
    pub fn new(
        binding: Ed25519YaoOuterBindingV2,
        prepared: PreparedEd25519DeriverATargetV1,
        outbound: Ed25519DeriverAToBTargetProofBundleV1,
    ) -> RouterAbProtocolResult<Self> {
        binding.validate()?;
        Ok(Self {
            binding,
            prepared,
            outbound,
        })
    }

    /// Returns the exact plaintext that must be encrypted for Deriver B.
    pub fn outbound_plaintext(&self) -> &[u8; Ed25519DeriverAToBTargetProofBundleV1::LEN] {
        self.outbound.as_bytes()
    }

    /// Verifies B's incoming A-target proof and yields only A's target root.
    pub fn complete(
        self,
        incoming: &Ed25519YaoDeriverBToATargetProofPayloadV2,
        incoming_plaintext: &[u8],
    ) -> RouterAbProtocolResult<Ed25519YaoDeriverAPrefaceReadyV2> {
        incoming.validate_for_binding(&self.binding)?;
        let incoming_bundle = incoming.decode_plaintext(incoming_plaintext)?;
        let root = complete_ed25519_deriver_a_target_v1(self.prepared, &incoming_bundle)
            .map_err(threshold_prf_error)?;
        Ok(Ed25519YaoDeriverAPrefaceReadyV2 {
            binding: self.binding,
            root,
        })
    }
}

/// Role-local Deriver B preface state before the peer proof is opened.
pub struct Ed25519YaoDeriverBPrefaceInFlightV2 {
    binding: Ed25519YaoOuterBindingV2,
    prepared: PreparedEd25519DeriverBTargetV1,
    outbound: Ed25519DeriverBToATargetProofBundleV1,
}

impl core::fmt::Debug for Ed25519YaoDeriverBPrefaceInFlightV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Ed25519YaoDeriverBPrefaceInFlightV2([redacted])")
    }
}

impl Ed25519YaoDeriverBPrefaceInFlightV2 {
    /// Creates B's local preface state from the fixed threshold-prf preparation result.
    pub fn new(
        binding: Ed25519YaoOuterBindingV2,
        prepared: PreparedEd25519DeriverBTargetV1,
        outbound: Ed25519DeriverBToATargetProofBundleV1,
    ) -> RouterAbProtocolResult<Self> {
        binding.validate()?;
        Ok(Self {
            binding,
            prepared,
            outbound,
        })
    }

    /// Returns the exact plaintext that must be encrypted for Deriver A.
    pub fn outbound_plaintext(&self) -> &[u8; Ed25519DeriverBToATargetProofBundleV1::LEN] {
        self.outbound.as_bytes()
    }

    /// Verifies A's incoming B-target proof and yields only B's target root.
    pub fn complete(
        self,
        incoming: &Ed25519YaoDeriverAToBTargetProofPayloadV2,
        incoming_plaintext: &[u8],
    ) -> RouterAbProtocolResult<Ed25519YaoDeriverBPrefaceReadyV2> {
        incoming.validate_for_binding(&self.binding)?;
        let incoming_bundle = incoming.decode_plaintext(incoming_plaintext)?;
        let root = complete_ed25519_deriver_b_target_v1(self.prepared, &incoming_bundle)
            .map_err(threshold_prf_error)?;
        Ok(Ed25519YaoDeriverBPrefaceReadyV2 {
            binding: self.binding,
            root,
        })
    }
}

/// A's typed local `preface_ready` capability.
pub struct Ed25519YaoDeriverAPrefaceReadyV2 {
    binding: Ed25519YaoOuterBindingV2,
    root: Ed25519DeriverAThresholdPrfRootV1,
}

impl core::fmt::Debug for Ed25519YaoDeriverAPrefaceReadyV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Ed25519YaoDeriverAPrefaceReadyV2([redacted])")
    }
}

impl Ed25519YaoDeriverAPrefaceReadyV2 {
    /// Returns the outer binding proven by the completed preface.
    pub const fn binding(&self) -> &Ed25519YaoOuterBindingV2 {
        &self.binding
    }

    /// Consumes the capability for A's local contribution KDF.
    pub fn into_threshold_prf_root(self) -> Ed25519DeriverAThresholdPrfRootV1 {
        self.root
    }

    /// Gates the unchanged A Yao input on the completed preface.
    pub fn into_yao_input(
        self,
        input: Ed25519YaoEncryptedInputV1,
    ) -> RouterAbProtocolResult<(
        Ed25519DeriverAThresholdPrfRootV1,
        Ed25519YaoEncryptedInputV1,
    )> {
        validate_yao_input_for_outer_binding(
            &self.binding,
            &input,
            Ed25519YaoDeriverRoleV1::DeriverA,
        )?;
        Ok((self.root, input))
    }
}

/// B's typed local `preface_ready` capability.
pub struct Ed25519YaoDeriverBPrefaceReadyV2 {
    binding: Ed25519YaoOuterBindingV2,
    root: Ed25519DeriverBThresholdPrfRootV1,
}

impl core::fmt::Debug for Ed25519YaoDeriverBPrefaceReadyV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Ed25519YaoDeriverBPrefaceReadyV2([redacted])")
    }
}

impl Ed25519YaoDeriverBPrefaceReadyV2 {
    /// Returns the outer binding proven by the completed preface.
    pub const fn binding(&self) -> &Ed25519YaoOuterBindingV2 {
        &self.binding
    }

    /// Consumes the capability for B's local contribution KDF.
    pub fn into_threshold_prf_root(self) -> Ed25519DeriverBThresholdPrfRootV1 {
        self.root
    }

    /// Gates the unchanged B Yao input on the completed preface.
    pub fn into_yao_input(
        self,
        input: Ed25519YaoEncryptedInputV1,
    ) -> RouterAbProtocolResult<(
        Ed25519DeriverBThresholdPrfRootV1,
        Ed25519YaoEncryptedInputV1,
    )> {
        validate_yao_input_for_outer_binding(
            &self.binding,
            &input,
            Ed25519YaoDeriverRoleV1::DeriverB,
        )?;
        Ok((self.root, input))
    }
}

/// Why a role-local preface session was permanently burned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ed25519YaoPrefaceBurnReasonV2 {
    /// The peer proof or its authenticated transport failed validation.
    PeerProofRejected,
    /// The outer binding expired before completion.
    Expired,
    /// The transport failed after one-use preface state was allocated.
    TransportFailure,
}

/// Explicit local lifecycle for one role-targeted preface.
pub enum Ed25519YaoPrefaceStateV2 {
    /// A awaits B's encrypted A-target proof.
    DeriverAAwaiting(Ed25519YaoDeriverAPrefaceInFlightV2),
    /// B awaits A's encrypted B-target proof.
    DeriverBAwaiting(Ed25519YaoDeriverBPrefaceInFlightV2),
    /// A has completed its own target and may construct its Yao role.
    DeriverAReady(Ed25519YaoDeriverAPrefaceReadyV2),
    /// B has completed its own target and may construct its Yao role.
    DeriverBReady(Ed25519YaoDeriverBPrefaceReadyV2),
    /// The one-use pair was burned and cannot be retried.
    Burned {
        session: Ed25519YaoPairSessionIdV2,
        reason: Ed25519YaoPrefaceBurnReasonV2,
    },
}

impl core::fmt::Debug for Ed25519YaoPrefaceStateV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DeriverAAwaiting(_) => formatter.write_str("DeriverAAwaiting"),
            Self::DeriverBAwaiting(_) => formatter.write_str("DeriverBAwaiting"),
            Self::DeriverAReady(_) => formatter.write_str("DeriverAReady"),
            Self::DeriverBReady(_) => formatter.write_str("DeriverBReady"),
            Self::Burned { session, reason } => formatter
                .debug_struct("Burned")
                .field("session", session)
                .field("reason", reason)
                .finish(),
        }
    }
}

impl Ed25519YaoPrefaceStateV2 {
    /// Completes A's state transition after opening B's authenticated payload.
    pub fn complete_deriver_a(
        self,
        incoming: &Ed25519YaoDeriverBToATargetProofPayloadV2,
        plaintext: &[u8],
    ) -> RouterAbProtocolResult<Self> {
        match self {
            Self::DeriverAAwaiting(in_flight) => Ok(Self::DeriverAReady(
                in_flight.complete(incoming, plaintext)?,
            )),
            Self::DeriverBAwaiting(_)
            | Self::DeriverAReady(_)
            | Self::DeriverBReady(_)
            | Self::Burned { .. } => {
                Err(malformed("Ed25519 Yao V2 A preface state is not awaiting"))
            }
        }
    }

    /// Completes B's state transition after opening A's authenticated payload.
    pub fn complete_deriver_b(
        self,
        incoming: &Ed25519YaoDeriverAToBTargetProofPayloadV2,
        plaintext: &[u8],
    ) -> RouterAbProtocolResult<Self> {
        match self {
            Self::DeriverBAwaiting(in_flight) => Ok(Self::DeriverBReady(
                in_flight.complete(incoming, plaintext)?,
            )),
            Self::DeriverAAwaiting(_)
            | Self::DeriverAReady(_)
            | Self::DeriverBReady(_)
            | Self::Burned { .. } => {
                Err(malformed("Ed25519 Yao V2 B preface state is not awaiting"))
            }
        }
    }

    /// Burns this one-use pair and drops any role-local secret state.
    pub fn burn(self, reason: Ed25519YaoPrefaceBurnReasonV2) -> Self {
        let session = match &self {
            Self::DeriverAAwaiting(state) => state.binding.pair_session(),
            Self::DeriverBAwaiting(state) => state.binding.pair_session(),
            Self::DeriverAReady(state) => state.binding.pair_session(),
            Self::DeriverBReady(state) => state.binding.pair_session(),
            Self::Burned { session, .. } => *session,
        };
        Self::Burned { session, reason }
    }

    /// Returns the pair-session identity without exposing secret state.
    pub const fn session(&self) -> Ed25519YaoPairSessionIdV2 {
        match self {
            Self::DeriverAAwaiting(state) => state.binding.pair_session(),
            Self::DeriverBAwaiting(state) => state.binding.pair_session(),
            Self::DeriverAReady(state) => state.binding.pair_session(),
            Self::DeriverBReady(state) => state.binding.pair_session(),
            Self::Burned { session, .. } => *session,
        }
    }
}

fn encode_target_proof_aad_v2(
    binding: &Ed25519YaoOuterBindingV2,
    source: u8,
    target: u8,
) -> RouterAbProtocolResult<[u8; TARGET_PROOF_AAD_LEN_V2]> {
    binding.validate()?;
    if source == target
        || !matches!(source, TARGET_PROOF_ROLE_A_V2 | TARGET_PROOF_ROLE_B_V2)
        || !matches!(target, TARGET_PROOF_ROLE_A_V2 | TARGET_PROOF_ROLE_B_V2)
    {
        return Err(malformed(
            "Ed25519 Yao V2 target-proof direction is invalid",
        ));
    }
    let mut aad = [0_u8; TARGET_PROOF_AAD_LEN_V2];
    aad[..8].copy_from_slice(TARGET_PROOF_WIRE_MAGIC_V2);
    aad[8] = TARGET_PROOF_WIRE_VERSION_V2;
    aad[9] = source;
    aad[10] = target;
    aad[11..43].copy_from_slice(binding.pair_session().as_bytes());
    aad[43..75].copy_from_slice(&binding.stable_context_binding().into_bytes());
    aad[75..107].copy_from_slice(binding.custody_binding_digest().as_bytes());
    aad[107..123].copy_from_slice(binding.nonce());
    aad[123..131].copy_from_slice(&binding.issued_at_ms().to_be_bytes());
    aad[131..139].copy_from_slice(&binding.expires_at_ms().to_be_bytes());
    Ok(aad)
}

fn decode_target_proof_aad_v2(
    aad: &[u8],
    expected_source: u8,
    expected_target: u8,
) -> RouterAbProtocolResult<Ed25519YaoOuterBindingV2> {
    if aad.len() != TARGET_PROOF_AAD_LEN_V2
        || &aad[..8] != TARGET_PROOF_WIRE_MAGIC_V2
        || aad[8] != TARGET_PROOF_WIRE_VERSION_V2
        || aad[9] != expected_source
        || aad[10] != expected_target
    {
        return Err(malformed("Ed25519 Yao V2 target-proof header is invalid"));
    }
    let pair_session = Ed25519YaoPairSessionIdV2::new(
        aad[11..43]
            .try_into()
            .map_err(|_| malformed("Ed25519 Yao V2 target-proof session is invalid"))?,
    )?;
    let stable_context_binding = Ed25519YaoStableKeyContextBindingV1::new(
        aad[43..75]
            .try_into()
            .map_err(|_| malformed("Ed25519 Yao V2 target-proof context is invalid"))?,
    );
    let custody_binding_digest = PublicDigest32::new(
        aad[75..107]
            .try_into()
            .map_err(|_| malformed("Ed25519 Yao V2 target-proof custody is invalid"))?,
    );
    let nonce = aad[107..123]
        .try_into()
        .map_err(|_| malformed("Ed25519 Yao V2 target-proof nonce is invalid"))?;
    let issued_at_ms = u64::from_be_bytes(
        aad[123..131]
            .try_into()
            .map_err(|_| malformed("Ed25519 Yao V2 target-proof issue time is invalid"))?,
    );
    let expires_at_ms = u64::from_be_bytes(
        aad[131..139]
            .try_into()
            .map_err(|_| malformed("Ed25519 Yao V2 target-proof expiry is invalid"))?,
    );
    Ed25519YaoOuterBindingV2::new(
        pair_session,
        stable_context_binding,
        custody_binding_digest,
        nonce,
        issued_at_ms,
        expires_at_ms,
    )
}

fn encode_target_proof_wire_v2(
    aad: [u8; TARGET_PROOF_AAD_LEN_V2],
    encapsulated_key: &[u8; HPKE_ENCAPSULATED_KEY_LEN_V2],
    ciphertext: &[u8],
) -> RouterAbProtocolResult<Vec<u8>> {
    if ciphertext.is_empty() || ciphertext.len() > ED25519_YAO_OUTER_TARGET_PROOF_MAX_BYTES_V2 {
        return Err(malformed(
            "Ed25519 Yao V2 target-proof ciphertext length is invalid",
        ));
    }
    let mut wire = Vec::with_capacity(aad.len() + encapsulated_key.len() + ciphertext.len());
    wire.extend_from_slice(&aad);
    wire.extend_from_slice(encapsulated_key);
    wire.extend_from_slice(ciphertext);
    Ok(wire)
}

fn decode_target_proof_wire_v2(
    bytes: &[u8],
    expected_source: u8,
    expected_target: u8,
    expected_ciphertext_len: usize,
) -> RouterAbProtocolResult<(Ed25519YaoOuterBindingV2, [u8; 32], Vec<u8>)> {
    let expected_len = TARGET_PROOF_AAD_LEN_V2
        .checked_add(HPKE_ENCAPSULATED_KEY_LEN_V2)
        .and_then(|length| length.checked_add(expected_ciphertext_len))
        .ok_or_else(|| malformed("Ed25519 Yao V2 target-proof length overflow"))?;
    if bytes.len() != expected_len {
        return Err(malformed(
            "Ed25519 Yao V2 target-proof wire length is invalid",
        ));
    }
    let binding = decode_target_proof_aad_v2(
        &bytes[..TARGET_PROOF_AAD_LEN_V2],
        expected_source,
        expected_target,
    )?;
    let key_start = TARGET_PROOF_AAD_LEN_V2;
    let ciphertext_start = key_start + HPKE_ENCAPSULATED_KEY_LEN_V2;
    let encapsulated_key = bytes[key_start..ciphertext_start]
        .try_into()
        .map_err(|_| malformed("Ed25519 Yao V2 target-proof key is invalid"))?;
    Ok((
        binding,
        encapsulated_key,
        bytes[ciphertext_start..].to_vec(),
    ))
}

fn validate_yao_input(
    ceremony: &Ed25519YaoCeremonyBindingV1,
    input: &Ed25519YaoEncryptedInputV1,
    expected_role: Ed25519YaoDeriverRoleV1,
) -> RouterAbProtocolResult<()> {
    input.validate()?;
    if input.deriver() != expected_role
        || input.operation() != ceremony.operation
        || input.session() != ceremony.session_id.into_bytes()
        || input.stable_context_binding() != ceremony.stable_key_context_binding.into_bytes()
    {
        return Err(malformed("Ed25519 Yao V2 input does not match ceremony"));
    }
    Ok(())
}

fn validate_yao_input_for_outer_binding(
    binding: &Ed25519YaoOuterBindingV2,
    input: &Ed25519YaoEncryptedInputV1,
    expected_role: Ed25519YaoDeriverRoleV1,
) -> RouterAbProtocolResult<()> {
    input.validate()?;
    if input.deriver() != expected_role
        || input.session() != binding.pair_session().into_bytes()
        || input.stable_context_binding() != binding.stable_context_binding().into_bytes()
    {
        return Err(malformed(
            "Ed25519 Yao V2 ready input does not match outer binding",
        ));
    }
    Ok(())
}

fn validate_digest(field: &'static str, digest: PublicDigest32) -> RouterAbProtocolResult<()> {
    if digest.bytes.iter().all(|byte| *byte == 0) {
        return Err(malformed(field));
    }
    Ok(())
}

fn threshold_prf_error(error: ThresholdPrfError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("Ed25519 Yao V2 target proof rejected: {error}"),
    )
}

fn malformed(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::MalformedWirePayload, message)
}
