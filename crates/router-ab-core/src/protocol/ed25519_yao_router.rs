use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::derivation::PublicDigest32;
use crate::protocol::ed25519_yao::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoCircuitFamilyV1, Ed25519YaoDeriverRoleV1,
    Ed25519YaoEncryptedInputV1, Ed25519YaoOperationV1, Ed25519YaoSessionIdV1,
};
use crate::protocol::error::{
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};

/// Stable protocol identity bound into every Refactor 93 ceremony digest.
pub const ED25519_YAO_PROTOCOL_ID_V1: &str = "router_ab_ed25519_yao_v1";
/// Activation circuit identity bound into Refactor 93 ceremony digests.
pub const ED25519_YAO_ACTIVATION_CIRCUIT_ID_V1: &str = "ed25519_yao_activation_v1";
/// Export circuit identity bound into Refactor 93 ceremony digests.
pub const ED25519_YAO_EXPORT_CIRCUIT_ID_V1: &str = "ed25519_yao_export_v1";
/// Lane-materialization circuit identity bound into lane digests.
pub const ED25519_YAO_LANE_MATERIALIZATION_CIRCUIT_ID_V1: &str =
    "ed25519_yao_lane_materialization_v1";

const INPUT_DIGEST_DOMAIN_V1: &[u8] = b"router-ab-ed25519-yao/input/v1";
const PAIR_DIGEST_DOMAIN_V1: &[u8] = b"router-ab-ed25519-yao/input-pair/v1";
const AUTHORIZATION_DIGEST_DOMAIN_V1: &[u8] = b"router-ab-ed25519-yao/authorization/v1";
const READINESS_DIGEST_DOMAIN_V1: &[u8] = b"router-ab-ed25519-yao/readiness/v1";
const START_ACCEPTANCE_DIGEST_DOMAIN_V1: &[u8] = b"router-ab-ed25519-yao/start-acceptance/v1";

/// Protocol artifact identity for one Yao circuit family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript-bindings", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(
    feature = "typescript-bindings",
    ts(rename = "RouterAbEd25519YaoCircuitIdV1", rename_all = "snake_case")
)]
pub enum Ed25519YaoCircuitIdV1 {
    /// Activation circuit used by registration, recovery, and refresh.
    ActivationV1,
    /// Exact-seed export circuit.
    ExportV1,
    /// Recipient-isolated lane-materialization circuit.
    LaneMaterializationV1,
}

impl Ed25519YaoCircuitIdV1 {
    /// Returns the stable wire identity.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActivationV1 => ED25519_YAO_ACTIVATION_CIRCUIT_ID_V1,
            Self::ExportV1 => ED25519_YAO_EXPORT_CIRCUIT_ID_V1,
            Self::LaneMaterializationV1 => ED25519_YAO_LANE_MATERIALIZATION_CIRCUIT_ID_V1,
        }
    }

    fn from_family(family: Ed25519YaoCircuitFamilyV1) -> Self {
        match family {
            Ed25519YaoCircuitFamilyV1::Activation => Self::ActivationV1,
            Ed25519YaoCircuitFamilyV1::Export => Self::ExportV1,
            Ed25519YaoCircuitFamilyV1::LaneMaterialization => Self::LaneMaterializationV1,
        }
    }
}

/// Protocol version identity for the Refactor 93 Yao contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript-bindings", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(
    feature = "typescript-bindings",
    ts(rename = "RouterAbEd25519YaoProtocolIdV1", rename_all = "snake_case")
)]
pub enum Ed25519YaoProtocolIdV1 {
    /// Current protocol contract.
    V1,
}

impl Ed25519YaoProtocolIdV1 {
    /// Returns the stable wire identity.
    pub const fn as_str(self) -> &'static str {
        ED25519_YAO_PROTOCOL_ID_V1
    }
}

/// Canonical ceremony identity used as the root of the input-pair digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "typescript-bindings", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
#[cfg_attr(
    feature = "typescript-bindings",
    ts(rename = "RouterAbEd25519YaoCeremonyIdentityV1")
)]
pub struct Ed25519YaoCeremonyIdentityV1 {
    binding: Ed25519YaoCeremonyBindingV1,
    circuit: Ed25519YaoCircuitIdV1,
    protocol: Ed25519YaoProtocolIdV1,
}

impl Ed25519YaoCeremonyIdentityV1 {
    /// Creates an identity whose circuit agrees with the admitted operation.
    pub fn new(
        binding: Ed25519YaoCeremonyBindingV1,
        circuit: Ed25519YaoCircuitIdV1,
        protocol: Ed25519YaoProtocolIdV1,
    ) -> RouterAbProtocolResult<Self> {
        binding.validate()?;
        if circuit != Ed25519YaoCircuitIdV1::from_family(binding.circuit_family()) {
            return Err(invalid_router_yao(
                "Ed25519 Yao ceremony circuit does not match its operation",
            ));
        }
        Ok(Self {
            binding,
            circuit,
            protocol,
        })
    }

    /// Creates the current protocol identity from an admitted binding.
    pub fn from_binding(binding: Ed25519YaoCeremonyBindingV1) -> RouterAbProtocolResult<Self> {
        let circuit = Ed25519YaoCircuitIdV1::from_family(binding.circuit_family());
        Self::new(binding, circuit, Ed25519YaoProtocolIdV1::V1)
    }

    /// Revalidates a value received at a serialization boundary.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.binding.validate()?;
        if self.circuit != Ed25519YaoCircuitIdV1::from_family(self.binding.circuit_family()) {
            return Err(invalid_router_yao(
                "Ed25519 Yao ceremony circuit does not match its operation",
            ));
        }
        Ok(())
    }

    /// Returns the admitted ceremony binding.
    pub const fn binding(&self) -> &Ed25519YaoCeremonyBindingV1 {
        &self.binding
    }

    /// Returns the circuit identity.
    pub const fn circuit(&self) -> Ed25519YaoCircuitIdV1 {
        self.circuit
    }

    /// Returns the protocol identity.
    pub const fn protocol(&self) -> Ed25519YaoProtocolIdV1 {
        self.protocol
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEd25519YaoCeremonyIdentityV1 {
    binding: Ed25519YaoCeremonyBindingV1,
    circuit: Ed25519YaoCircuitIdV1,
    protocol: Ed25519YaoProtocolIdV1,
}

impl<'de> Deserialize<'de> for Ed25519YaoCeremonyIdentityV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawEd25519YaoCeremonyIdentityV1::deserialize(deserializer)?;
        Self::new(raw.binding, raw.circuit, raw.protocol).map_err(D::Error::custom)
    }
}

/// Canonical A/B ciphertext digest binding for one admitted execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "typescript-bindings", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
#[cfg_attr(
    feature = "typescript-bindings",
    ts(rename = "RouterAbEd25519YaoInputPairBindingV1")
)]
pub struct Ed25519YaoInputPairBindingV1 {
    ceremony: Ed25519YaoCeremonyIdentityV1,
    deriver_a_input_digest: PublicDigest32,
    deriver_b_input_digest: PublicDigest32,
    recipient_set_digest: PublicDigest32,
    authorization_digest: PublicDigest32,
    pair_digest: PublicDigest32,
}

impl Ed25519YaoInputPairBindingV1 {
    /// Creates a pair binding and derives its digest from canonical bytes.
    pub fn new(
        ceremony: Ed25519YaoCeremonyIdentityV1,
        deriver_a_input_digest: PublicDigest32,
        deriver_b_input_digest: PublicDigest32,
        recipient_set_digest: PublicDigest32,
        authorization_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        ceremony.validate()?;
        validate_digest("deriver_a_input_digest", deriver_a_input_digest)?;
        validate_digest("deriver_b_input_digest", deriver_b_input_digest)?;
        validate_digest("recipient_set_digest", recipient_set_digest)?;
        validate_digest("authorization_digest", authorization_digest)?;
        let pair_digest = derive_input_pair_digest_v1(
            &ceremony,
            deriver_a_input_digest,
            deriver_b_input_digest,
            recipient_set_digest,
            authorization_digest,
        );
        Ok(Self {
            ceremony,
            deriver_a_input_digest,
            deriver_b_input_digest,
            recipient_set_digest,
            authorization_digest,
            pair_digest,
        })
    }

    /// Creates a pair binding by hashing the exact opaque role envelopes.
    pub fn from_inputs(
        ceremony: Ed25519YaoCeremonyIdentityV1,
        deriver_a_input: &Ed25519YaoEncryptedInputV1,
        deriver_b_input: &Ed25519YaoEncryptedInputV1,
        recipient_set_digest: PublicDigest32,
        authorization_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        validate_input_for_ceremony(
            ceremony.binding(),
            deriver_a_input,
            Ed25519YaoDeriverRoleV1::DeriverA,
        )?;
        validate_input_for_ceremony(
            ceremony.binding(),
            deriver_b_input,
            Ed25519YaoDeriverRoleV1::DeriverB,
        )?;
        let deriver_a_input_digest = ed25519_yao_encrypted_input_digest_v1(deriver_a_input)?;
        let deriver_b_input_digest = ed25519_yao_encrypted_input_digest_v1(deriver_b_input)?;
        Self::new(
            ceremony,
            deriver_a_input_digest,
            deriver_b_input_digest,
            recipient_set_digest,
            authorization_digest,
        )
    }

    /// Creates a pair binding directly from an admitted ceremony binding.
    pub fn from_ceremony_binding(
        binding: Ed25519YaoCeremonyBindingV1,
        deriver_a_input: &Ed25519YaoEncryptedInputV1,
        deriver_b_input: &Ed25519YaoEncryptedInputV1,
        recipient_set_digest: PublicDigest32,
        authorization_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        Self::from_inputs(
            Ed25519YaoCeremonyIdentityV1::from_binding(binding)?,
            deriver_a_input,
            deriver_b_input,
            recipient_set_digest,
            authorization_digest,
        )
    }

    /// Revalidates the derived digest after deserialization.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.ceremony.validate()?;
        let expected = derive_input_pair_digest_v1(
            &self.ceremony,
            self.deriver_a_input_digest,
            self.deriver_b_input_digest,
            self.recipient_set_digest,
            self.authorization_digest,
        );
        if expected != self.pair_digest {
            return Err(invalid_router_yao(
                "Ed25519 Yao input-pair digest does not match canonical fields",
            ));
        }
        Ok(())
    }

    /// Returns the ceremony identity.
    pub const fn ceremony(&self) -> &Ed25519YaoCeremonyIdentityV1 {
        &self.ceremony
    }

    /// Returns the admitted ceremony binding without the protocol wrapper.
    pub const fn binding(&self) -> &Ed25519YaoCeremonyBindingV1 {
        self.ceremony.binding()
    }

    /// Returns the exact transcript session bytes.
    pub const fn session(&self) -> [u8; 32] {
        self.ceremony.binding().session_id.into_bytes()
    }

    /// Returns the Deriver A envelope digest.
    pub const fn deriver_a_input_digest(&self) -> PublicDigest32 {
        self.deriver_a_input_digest
    }

    /// Returns the Deriver B envelope digest.
    pub const fn deriver_b_input_digest(&self) -> PublicDigest32 {
        self.deriver_b_input_digest
    }

    /// Returns the recipient-set digest.
    pub const fn recipient_set_digest(&self) -> PublicDigest32 {
        self.recipient_set_digest
    }

    /// Returns the admission/authorization digest.
    pub const fn authorization_digest(&self) -> PublicDigest32 {
        self.authorization_digest
    }

    /// Returns the canonical pair digest used by both roles.
    pub const fn pair_digest(&self) -> PublicDigest32 {
        self.pair_digest
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEd25519YaoInputPairBindingV1 {
    ceremony: Ed25519YaoCeremonyIdentityV1,
    deriver_a_input_digest: PublicDigest32,
    deriver_b_input_digest: PublicDigest32,
    recipient_set_digest: PublicDigest32,
    authorization_digest: PublicDigest32,
    pair_digest: PublicDigest32,
}

impl<'de> Deserialize<'de> for Ed25519YaoInputPairBindingV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawEd25519YaoInputPairBindingV1::deserialize(deserializer)?;
        let binding = Self::new(
            raw.ceremony,
            raw.deriver_a_input_digest,
            raw.deriver_b_input_digest,
            raw.recipient_set_digest,
            raw.authorization_digest,
        )
        .map_err(D::Error::custom)?;
        if binding.pair_digest != raw.pair_digest {
            return Err(D::Error::custom(
                "Ed25519 Yao input-pair digest does not match canonical fields",
            ));
        }
        Ok(binding)
    }
}

/// Channel-authenticated authority for one Gateway-admitted Yao execution request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAdmittedExecutionAuthorityV1 {
    authority_digest: PublicDigest32,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

impl RouterAdmittedExecutionAuthorityV1 {
    /// Creates a short-lived, nonzero execution authority.
    pub fn new(
        authority_digest: PublicDigest32,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        validate_digest("authority_digest", authority_digest)?;
        if issued_at_ms == 0 || expires_at_ms <= issued_at_ms {
            return Err(invalid_router_yao(
                "Ed25519 Yao execution authority lifetime is invalid",
            ));
        }
        Ok(Self {
            authority_digest,
            issued_at_ms,
            expires_at_ms,
        })
    }

    /// Revalidates authority expiry against a wall-clock timestamp.
    pub fn validate_at(&self, now_ms: u64) -> RouterAbProtocolResult<()> {
        if now_ms < self.issued_at_ms || now_ms >= self.expires_at_ms {
            return Err(invalid_router_yao(
                "Ed25519 Yao execution authority is expired or issued in the future",
            ));
        }
        Ok(())
    }

    /// Returns the admitted authority digest.
    pub const fn authority_digest(&self) -> PublicDigest32 {
        self.authority_digest
    }

    /// Returns the authority issue timestamp.
    pub const fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    /// Returns the authority expiry timestamp.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouterAdmittedExecutionAuthorityV1 {
    authority_digest: PublicDigest32,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

impl<'de> Deserialize<'de> for RouterAdmittedExecutionAuthorityV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterAdmittedExecutionAuthorityV1::deserialize(deserializer)?;
        Self::new(raw.authority_digest, raw.issued_at_ms, raw.expires_at_ms)
            .map_err(D::Error::custom)
    }
}

/// Operation-specific Router execution request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouterEd25519YaoExecuteRequestV1 {
    /// Initial registration activation.
    Registration {
        /// Gateway-admitted execution authority.
        authority: RouterAdmittedExecutionAuthorityV1,
        /// Admitted activation ceremony binding.
        binding: Ed25519YaoCeremonyBindingV1,
        /// Exact A/B ciphertext pair binding.
        pair_binding: Ed25519YaoInputPairBindingV1,
        /// Opaque Deriver A envelope.
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        /// Opaque Deriver B envelope.
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
    /// Recovery activation into staged recipient shares.
    Recovery {
        /// Gateway-admitted execution authority.
        authority: RouterAdmittedExecutionAuthorityV1,
        /// Admitted activation ceremony binding.
        binding: Ed25519YaoCeremonyBindingV1,
        /// Exact A/B ciphertext pair binding.
        pair_binding: Ed25519YaoInputPairBindingV1,
        /// Opaque Deriver A envelope.
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        /// Opaque Deriver B envelope.
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
    /// Explicit client-recipient export.
    Export {
        /// Gateway-admitted execution authority.
        authority: RouterAdmittedExecutionAuthorityV1,
        /// Admitted export identity binding.
        binding: crate::protocol::ed25519_yao::RouterAbEd25519YaoExportBindingV1,
        /// Exact A/B ciphertext pair binding.
        pair_binding: Ed25519YaoInputPairBindingV1,
        /// Opaque Deriver A envelope.
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        /// Opaque Deriver B envelope.
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
    /// Creates one new recipient-isolated signing lane.
    LaneProvisioning {
        /// Gateway-admitted execution authority.
        authority: RouterAdmittedExecutionAuthorityV1,
        /// Admitted lane ceremony binding.
        binding: Ed25519YaoCeremonyBindingV1,
        /// Exact A/B ciphertext pair binding.
        pair_binding: Ed25519YaoInputPairBindingV1,
        /// Immutable lane job.
        job: crate::protocol::ed25519_yao_lane::Ed25519YaoLaneJobV1,
        /// Opaque Deriver A envelope.
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        /// Opaque Deriver B envelope.
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
    /// Replaces one lane with its next share epoch.
    LaneRefresh {
        /// Gateway-admitted execution authority.
        authority: RouterAdmittedExecutionAuthorityV1,
        /// Admitted lane ceremony binding.
        binding: Ed25519YaoCeremonyBindingV1,
        /// Exact A/B ciphertext pair binding.
        pair_binding: Ed25519YaoInputPairBindingV1,
        /// Immutable lane job.
        job: crate::protocol::ed25519_yao_lane::Ed25519YaoLaneJobV1,
        /// Opaque Deriver A envelope.
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        /// Opaque Deriver B envelope.
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
}

/// Raw Gateway-to-Router request before Router-owned digest construction.
///
/// This boundary deliberately carries only the admitted ceremony binding and
/// opaque role envelopes. The Router derives every digest that commits this
/// request before it creates the internal execution request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouterEd25519YaoGatewayExecuteRequestV1 {
    /// Initial registration activation.
    Registration {
        /// Admitted activation ceremony binding.
        binding: Ed25519YaoCeremonyBindingV1,
        /// Opaque Deriver A envelope.
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        /// Opaque Deriver B envelope.
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
    /// Recovery activation into staged recipient shares.
    Recovery {
        /// Admitted activation ceremony binding.
        binding: Ed25519YaoCeremonyBindingV1,
        /// Opaque Deriver A envelope.
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        /// Opaque Deriver B envelope.
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
    /// Explicit client-recipient export.
    Export {
        /// Admitted export identity binding.
        binding: crate::protocol::ed25519_yao::RouterAbEd25519YaoExportBindingV1,
        /// Opaque Deriver A envelope.
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        /// Opaque Deriver B envelope.
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum RawRouterEd25519YaoGatewayExecuteRequestV1 {
    Registration {
        binding: Ed25519YaoCeremonyBindingV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
    Recovery {
        binding: Ed25519YaoCeremonyBindingV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
    Export {
        binding: crate::protocol::ed25519_yao::RouterAbEd25519YaoExportBindingV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
}

impl<'de> Deserialize<'de> for RouterEd25519YaoGatewayExecuteRequestV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterEd25519YaoGatewayExecuteRequestV1::deserialize(deserializer)?;
        let request = match raw {
            RawRouterEd25519YaoGatewayExecuteRequestV1::Registration {
                binding,
                deriver_a_input,
                deriver_b_input,
            } => Self::registration(binding, deriver_a_input, deriver_b_input),
            RawRouterEd25519YaoGatewayExecuteRequestV1::Recovery {
                binding,
                deriver_a_input,
                deriver_b_input,
            } => Self::recovery(binding, deriver_a_input, deriver_b_input),
            RawRouterEd25519YaoGatewayExecuteRequestV1::Export {
                binding,
                deriver_a_input,
                deriver_b_input,
            } => Self::export(binding, deriver_a_input, deriver_b_input),
        };
        request.map_err(D::Error::custom)
    }
}

impl RouterEd25519YaoGatewayExecuteRequestV1 {
    /// Builds a validated registration request.
    pub fn registration(
        binding: Ed25519YaoCeremonyBindingV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    ) -> RouterAbProtocolResult<Self> {
        validate_gateway_inputs(
            &binding,
            Ed25519YaoOperationV1::Registration,
            &deriver_a_input,
            &deriver_b_input,
        )?;
        Ok(Self::Registration {
            binding,
            deriver_a_input,
            deriver_b_input,
        })
    }

    /// Builds a validated recovery request.
    pub fn recovery(
        binding: Ed25519YaoCeremonyBindingV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    ) -> RouterAbProtocolResult<Self> {
        validate_gateway_inputs(
            &binding,
            Ed25519YaoOperationV1::Recovery,
            &deriver_a_input,
            &deriver_b_input,
        )?;
        Ok(Self::Recovery {
            binding,
            deriver_a_input,
            deriver_b_input,
        })
    }

    /// Builds a validated export request.
    pub fn export(
        binding: crate::protocol::ed25519_yao::RouterAbEd25519YaoExportBindingV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    ) -> RouterAbProtocolResult<Self> {
        validate_gateway_inputs(
            binding.ceremony(),
            Ed25519YaoOperationV1::Export,
            &deriver_a_input,
            &deriver_b_input,
        )?;
        Ok(Self::Export {
            binding,
            deriver_a_input,
            deriver_b_input,
        })
    }

    /// Returns the operation branch.
    pub const fn operation(&self) -> Ed25519YaoOperationV1 {
        match self {
            Self::Registration { .. } => Ed25519YaoOperationV1::Registration,
            Self::Recovery { .. } => Ed25519YaoOperationV1::Recovery,
            Self::Export { .. } => Ed25519YaoOperationV1::Export,
        }
    }

    /// Returns the admitted ceremony binding.
    pub const fn ceremony_binding(&self) -> &Ed25519YaoCeremonyBindingV1 {
        match self {
            Self::Registration { binding, .. } | Self::Recovery { binding, .. } => binding,
            Self::Export { binding, .. } => binding.ceremony(),
        }
    }

    /// Returns the exact role inputs.
    pub const fn inputs(&self) -> (&Ed25519YaoEncryptedInputV1, &Ed25519YaoEncryptedInputV1) {
        match self {
            Self::Registration {
                deriver_a_input,
                deriver_b_input,
                ..
            }
            | Self::Recovery {
                deriver_a_input,
                deriver_b_input,
                ..
            }
            | Self::Export {
                deriver_a_input,
                deriver_b_input,
                ..
            } => (deriver_a_input, deriver_b_input),
        }
    }

    /// Returns the admission digest committed by the raw request.
    pub fn authorization_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        match self {
            Self::Export { binding, .. } => Ok(PublicDigest32::new(binding.authorization_digest())),
            Self::Registration { .. } | Self::Recovery { .. } => {
                let canonical = serde_json::to_vec(self).map_err(|error| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MalformedWirePayload,
                        format!("Router Yao authorization preimage serialization failed: {error}"),
                    )
                })?;
                let mut preimage =
                    Vec::with_capacity(AUTHORIZATION_DIGEST_DOMAIN_V1.len() + canonical.len());
                preimage.extend_from_slice(AUTHORIZATION_DIGEST_DOMAIN_V1);
                preimage.extend_from_slice(&canonical);
                Ok(digest_bytes(&preimage))
            }
        }
    }

    /// Converts the raw request into the validated internal execute request.
    pub fn into_execute_request(
        self,
        recipient_set_digest: PublicDigest32,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<RouterEd25519YaoExecuteRequestV1> {
        let authorization_digest = self.authorization_digest()?;
        let (deriver_a_input, deriver_b_input) = self.inputs();
        let pair_binding = Ed25519YaoInputPairBindingV1::from_ceremony_binding(
            self.ceremony_binding().clone(),
            deriver_a_input,
            deriver_b_input,
            recipient_set_digest,
            authorization_digest,
        )?;
        let authority = RouterAdmittedExecutionAuthorityV1::new(
            authorization_digest,
            issued_at_ms,
            expires_at_ms,
        )?;
        match self {
            Self::Registration {
                binding,
                deriver_a_input,
                deriver_b_input,
            } => RouterEd25519YaoExecuteRequestV1::registration(
                authority,
                binding,
                pair_binding,
                deriver_a_input,
                deriver_b_input,
            ),
            Self::Recovery {
                binding,
                deriver_a_input,
                deriver_b_input,
            } => RouterEd25519YaoExecuteRequestV1::recovery(
                authority,
                binding,
                pair_binding,
                deriver_a_input,
                deriver_b_input,
            ),
            Self::Export {
                binding,
                deriver_a_input,
                deriver_b_input,
            } => RouterEd25519YaoExecuteRequestV1::export(
                authority,
                binding,
                pair_binding,
                deriver_a_input,
                deriver_b_input,
            ),
        }
    }
}

/// Raw Gateway-to-Router execute target carried by the V2 server envelope.
///
/// The target owns only the admitted ceremony binding and opaque role
/// envelopes. The Router derives every digest that commits this target before
/// it creates the internal execution request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouterEd25519YaoGatewayExecuteTargetV2 {
    /// Initial registration activation.
    Registration {
        /// Admitted activation ceremony binding.
        binding: Ed25519YaoCeremonyBindingV1,
        /// Opaque Deriver A envelope.
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        /// Opaque Deriver B envelope.
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
    /// Recovery activation into staged recipient shares.
    Recovery {
        /// Admitted activation ceremony binding.
        binding: Ed25519YaoCeremonyBindingV1,
        /// Opaque Deriver A envelope.
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        /// Opaque Deriver B envelope.
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
    /// Explicit client-recipient export.
    Export {
        /// Admitted export identity binding.
        binding: crate::protocol::ed25519_yao::RouterAbEd25519YaoExportBindingV1,
        /// Opaque Deriver A envelope.
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        /// Opaque Deriver B envelope.
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum RawRouterEd25519YaoGatewayExecuteTargetV2 {
    Registration {
        binding: Ed25519YaoCeremonyBindingV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
    Recovery {
        binding: Ed25519YaoCeremonyBindingV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
    Export {
        binding: crate::protocol::ed25519_yao::RouterAbEd25519YaoExportBindingV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
}

impl<'de> Deserialize<'de> for RouterEd25519YaoGatewayExecuteTargetV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterEd25519YaoGatewayExecuteTargetV2::deserialize(deserializer)?;
        let target = match raw {
            RawRouterEd25519YaoGatewayExecuteTargetV2::Registration {
                binding,
                deriver_a_input,
                deriver_b_input,
            } => Self::registration(binding, deriver_a_input, deriver_b_input),
            RawRouterEd25519YaoGatewayExecuteTargetV2::Recovery {
                binding,
                deriver_a_input,
                deriver_b_input,
            } => Self::recovery(binding, deriver_a_input, deriver_b_input),
            RawRouterEd25519YaoGatewayExecuteTargetV2::Export {
                binding,
                deriver_a_input,
                deriver_b_input,
            } => Self::export(binding, deriver_a_input, deriver_b_input),
        };
        target.map_err(D::Error::custom)
    }
}

impl RouterEd25519YaoGatewayExecuteTargetV2 {
    /// Builds a validated registration target.
    pub fn registration(
        binding: Ed25519YaoCeremonyBindingV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    ) -> RouterAbProtocolResult<Self> {
        validate_gateway_inputs(
            &binding,
            Ed25519YaoOperationV1::Registration,
            &deriver_a_input,
            &deriver_b_input,
        )?;
        Ok(Self::Registration {
            binding,
            deriver_a_input,
            deriver_b_input,
        })
    }

    /// Builds a validated recovery target.
    pub fn recovery(
        binding: Ed25519YaoCeremonyBindingV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    ) -> RouterAbProtocolResult<Self> {
        validate_gateway_inputs(
            &binding,
            Ed25519YaoOperationV1::Recovery,
            &deriver_a_input,
            &deriver_b_input,
        )?;
        Ok(Self::Recovery {
            binding,
            deriver_a_input,
            deriver_b_input,
        })
    }

    /// Builds a validated export target.
    pub fn export(
        binding: crate::protocol::ed25519_yao::RouterAbEd25519YaoExportBindingV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    ) -> RouterAbProtocolResult<Self> {
        validate_gateway_inputs(
            binding.ceremony(),
            Ed25519YaoOperationV1::Export,
            &deriver_a_input,
            &deriver_b_input,
        )?;
        Ok(Self::Export {
            binding,
            deriver_a_input,
            deriver_b_input,
        })
    }

    /// Returns the operation branch.
    pub const fn operation(&self) -> Ed25519YaoOperationV1 {
        match self {
            Self::Registration { .. } => Ed25519YaoOperationV1::Registration,
            Self::Recovery { .. } => Ed25519YaoOperationV1::Recovery,
            Self::Export { .. } => Ed25519YaoOperationV1::Export,
        }
    }

    /// Returns the admitted ceremony binding.
    pub const fn ceremony_binding(&self) -> &Ed25519YaoCeremonyBindingV1 {
        match self {
            Self::Registration { binding, .. } | Self::Recovery { binding, .. } => binding,
            Self::Export { binding, .. } => binding.ceremony(),
        }
    }

    /// Returns the exact role inputs.
    pub const fn inputs(&self) -> (&Ed25519YaoEncryptedInputV1, &Ed25519YaoEncryptedInputV1) {
        match self {
            Self::Registration {
                deriver_a_input,
                deriver_b_input,
                ..
            }
            | Self::Recovery {
                deriver_a_input,
                deriver_b_input,
                ..
            }
            | Self::Export {
                deriver_a_input,
                deriver_b_input,
                ..
            } => (deriver_a_input, deriver_b_input),
        }
    }

    /// Returns the admission digest committed by the target.
    pub fn authorization_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        match self {
            Self::Export { binding, .. } => Ok(PublicDigest32::new(binding.authorization_digest())),
            Self::Registration { .. } | Self::Recovery { .. } => {
                let canonical = serde_json::to_vec(self).map_err(|error| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MalformedWirePayload,
                        format!("Router Yao authorization preimage serialization failed: {error}"),
                    )
                })?;
                let mut preimage =
                    Vec::with_capacity(AUTHORIZATION_DIGEST_DOMAIN_V1.len() + canonical.len());
                preimage.extend_from_slice(AUTHORIZATION_DIGEST_DOMAIN_V1);
                preimage.extend_from_slice(&canonical);
                Ok(digest_bytes(&preimage))
            }
        }
    }

    /// Converts the target into the validated internal execute request.
    pub fn into_execute_request(
        self,
        recipient_set_digest: PublicDigest32,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<RouterEd25519YaoExecuteRequestV1> {
        let authorization_digest = self.authorization_digest()?;
        let (deriver_a_input, deriver_b_input) = self.inputs();
        let pair_binding = Ed25519YaoInputPairBindingV1::from_ceremony_binding(
            self.ceremony_binding().clone(),
            deriver_a_input,
            deriver_b_input,
            recipient_set_digest,
            authorization_digest,
        )?;
        let authority = RouterAdmittedExecutionAuthorityV1::new(
            authorization_digest,
            issued_at_ms,
            expires_at_ms,
        )?;
        match self {
            Self::Registration {
                binding,
                deriver_a_input,
                deriver_b_input,
            } => RouterEd25519YaoExecuteRequestV1::registration(
                authority,
                binding,
                pair_binding,
                deriver_a_input,
                deriver_b_input,
            ),
            Self::Recovery {
                binding,
                deriver_a_input,
                deriver_b_input,
            } => RouterEd25519YaoExecuteRequestV1::recovery(
                authority,
                binding,
                pair_binding,
                deriver_a_input,
                deriver_b_input,
            ),
            Self::Export {
                binding,
                deriver_a_input,
                deriver_b_input,
            } => RouterEd25519YaoExecuteRequestV1::export(
                authority,
                binding,
                pair_binding,
                deriver_a_input,
                deriver_b_input,
            ),
        }
    }
}

fn validate_gateway_inputs(
    binding: &Ed25519YaoCeremonyBindingV1,
    expected_operation: Ed25519YaoOperationV1,
    deriver_a_input: &Ed25519YaoEncryptedInputV1,
    deriver_b_input: &Ed25519YaoEncryptedInputV1,
) -> RouterAbProtocolResult<()> {
    binding.validate()?;
    if binding.operation != expected_operation {
        return Err(invalid_router_yao(
            "Router Yao Gateway request operation does not match its binding",
        ));
    }
    validate_input_for_ceremony(binding, deriver_a_input, Ed25519YaoDeriverRoleV1::DeriverA)?;
    validate_input_for_ceremony(binding, deriver_b_input, Ed25519YaoDeriverRoleV1::DeriverB)
}

impl RouterEd25519YaoExecuteRequestV1 {
    /// Builds a registration request after validating pair and binding identity.
    pub fn registration(
        authority: RouterAdmittedExecutionAuthorityV1,
        binding: Ed25519YaoCeremonyBindingV1,
        pair_binding: Ed25519YaoInputPairBindingV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    ) -> RouterAbProtocolResult<Self> {
        validate_execute_pair(
            &binding,
            Ed25519YaoOperationV1::Registration,
            &pair_binding,
            &deriver_a_input,
            &deriver_b_input,
        )?;
        validate_authority_digest(&authority, &pair_binding)?;
        Ok(Self::Registration {
            authority,
            binding,
            pair_binding,
            deriver_a_input,
            deriver_b_input,
        })
    }

    /// Builds a recovery request after validating pair and binding identity.
    pub fn recovery(
        authority: RouterAdmittedExecutionAuthorityV1,
        binding: Ed25519YaoCeremonyBindingV1,
        pair_binding: Ed25519YaoInputPairBindingV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    ) -> RouterAbProtocolResult<Self> {
        validate_execute_pair(
            &binding,
            Ed25519YaoOperationV1::Recovery,
            &pair_binding,
            &deriver_a_input,
            &deriver_b_input,
        )?;
        validate_authority_digest(&authority, &pair_binding)?;
        Ok(Self::Recovery {
            authority,
            binding,
            pair_binding,
            deriver_a_input,
            deriver_b_input,
        })
    }

    /// Builds an export request after validating pair and binding identity.
    pub fn export(
        authority: RouterAdmittedExecutionAuthorityV1,
        binding: crate::protocol::ed25519_yao::RouterAbEd25519YaoExportBindingV1,
        pair_binding: Ed25519YaoInputPairBindingV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    ) -> RouterAbProtocolResult<Self> {
        validate_execute_pair(
            binding.ceremony(),
            Ed25519YaoOperationV1::Export,
            &pair_binding,
            &deriver_a_input,
            &deriver_b_input,
        )?;
        if pair_binding.ceremony().binding() != binding.ceremony() {
            return Err(invalid_router_yao(
                "Ed25519 Yao export pair binding does not match its export binding",
            ));
        }
        validate_authority_digest(&authority, &pair_binding)?;
        Ok(Self::Export {
            authority,
            binding,
            pair_binding,
            deriver_a_input,
            deriver_b_input,
        })
    }

    /// Builds a lane-provisioning request after exact job and pair validation.
    #[allow(clippy::too_many_arguments)]
    pub fn lane_provisioning(
        authority: RouterAdmittedExecutionAuthorityV1,
        binding: Ed25519YaoCeremonyBindingV1,
        pair_binding: Ed25519YaoInputPairBindingV1,
        job: crate::protocol::ed25519_yao_lane::Ed25519YaoLaneJobV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    ) -> RouterAbProtocolResult<Self> {
        validate_lane_execute_pair(
            &binding,
            Ed25519YaoOperationV1::LaneProvisioning,
            &pair_binding,
            &job,
            &deriver_a_input,
            &deriver_b_input,
        )?;
        validate_authority_digest(&authority, &pair_binding)?;
        Ok(Self::LaneProvisioning {
            authority,
            binding,
            pair_binding,
            job,
            deriver_a_input,
            deriver_b_input,
        })
    }

    /// Builds a lane-refresh request after exact job and pair validation.
    #[allow(clippy::too_many_arguments)]
    pub fn lane_refresh(
        authority: RouterAdmittedExecutionAuthorityV1,
        binding: Ed25519YaoCeremonyBindingV1,
        pair_binding: Ed25519YaoInputPairBindingV1,
        job: crate::protocol::ed25519_yao_lane::Ed25519YaoLaneJobV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    ) -> RouterAbProtocolResult<Self> {
        validate_lane_execute_pair(
            &binding,
            Ed25519YaoOperationV1::LaneRefresh,
            &pair_binding,
            &job,
            &deriver_a_input,
            &deriver_b_input,
        )?;
        validate_authority_digest(&authority, &pair_binding)?;
        Ok(Self::LaneRefresh {
            authority,
            binding,
            pair_binding,
            job,
            deriver_a_input,
            deriver_b_input,
        })
    }

    /// Returns the operation branch.
    pub const fn operation(&self) -> Ed25519YaoOperationV1 {
        match self {
            Self::Registration { .. } => Ed25519YaoOperationV1::Registration,
            Self::Recovery { .. } => Ed25519YaoOperationV1::Recovery,
            Self::Export { .. } => Ed25519YaoOperationV1::Export,
            Self::LaneProvisioning { .. } => Ed25519YaoOperationV1::LaneProvisioning,
            Self::LaneRefresh { .. } => Ed25519YaoOperationV1::LaneRefresh,
        }
    }

    /// Returns the exact pair binding carried by the request.
    pub const fn pair_binding(&self) -> &Ed25519YaoInputPairBindingV1 {
        match self {
            Self::Registration { pair_binding, .. }
            | Self::Recovery { pair_binding, .. }
            | Self::Export { pair_binding, .. }
            | Self::LaneProvisioning { pair_binding, .. }
            | Self::LaneRefresh { pair_binding, .. } => pair_binding,
        }
    }

    /// Returns the Router authority carried by the request.
    pub const fn authority(&self) -> &RouterAdmittedExecutionAuthorityV1 {
        match self {
            Self::Registration { authority, .. }
            | Self::Recovery { authority, .. }
            | Self::Export { authority, .. }
            | Self::LaneProvisioning { authority, .. }
            | Self::LaneRefresh { authority, .. } => authority,
        }
    }
}

fn validate_lane_execute_pair(
    binding: &Ed25519YaoCeremonyBindingV1,
    expected_operation: Ed25519YaoOperationV1,
    pair_binding: &Ed25519YaoInputPairBindingV1,
    job: &crate::protocol::ed25519_yao_lane::Ed25519YaoLaneJobV1,
    deriver_a_input: &Ed25519YaoEncryptedInputV1,
    deriver_b_input: &Ed25519YaoEncryptedInputV1,
) -> RouterAbProtocolResult<()> {
    job.validate()?;
    if job.yao_request_kind.operation() != expected_operation
        || binding.operation != expected_operation
        || binding.session_id.into_bytes() != job.session_v1()?
        || binding.stable_key_context_binding.into_bytes() != job.stable_context_binding_v1()?
        || pair_binding.authorization_digest() != PublicDigest32::new(job.transcript_digest_v1()?)
    {
        return Err(invalid_router_yao(
            "Ed25519 Yao lane execute request does not match its admitted job",
        ));
    }
    validate_execute_pair(
        binding,
        expected_operation,
        pair_binding,
        deriver_a_input,
        deriver_b_input,
    )
}

fn validate_authority_digest(
    authority: &RouterAdmittedExecutionAuthorityV1,
    pair_binding: &Ed25519YaoInputPairBindingV1,
) -> RouterAbProtocolResult<()> {
    if authority.authority_digest() != pair_binding.authorization_digest() {
        return Err(invalid_router_yao(
            "Ed25519 Yao execution authority does not match authorization binding",
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum RawRouterEd25519YaoExecuteRequestV1 {
    Registration {
        authority: RouterAdmittedExecutionAuthorityV1,
        binding: Ed25519YaoCeremonyBindingV1,
        pair_binding: Ed25519YaoInputPairBindingV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
    Recovery {
        authority: RouterAdmittedExecutionAuthorityV1,
        binding: Ed25519YaoCeremonyBindingV1,
        pair_binding: Ed25519YaoInputPairBindingV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
    Export {
        authority: RouterAdmittedExecutionAuthorityV1,
        binding: crate::protocol::ed25519_yao::RouterAbEd25519YaoExportBindingV1,
        pair_binding: Ed25519YaoInputPairBindingV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
    LaneProvisioning {
        authority: RouterAdmittedExecutionAuthorityV1,
        binding: Ed25519YaoCeremonyBindingV1,
        pair_binding: Ed25519YaoInputPairBindingV1,
        job: crate::protocol::ed25519_yao_lane::Ed25519YaoLaneJobV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
    LaneRefresh {
        authority: RouterAdmittedExecutionAuthorityV1,
        binding: Ed25519YaoCeremonyBindingV1,
        pair_binding: Ed25519YaoInputPairBindingV1,
        job: crate::protocol::ed25519_yao_lane::Ed25519YaoLaneJobV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    },
}

impl<'de> Deserialize<'de> for RouterEd25519YaoExecuteRequestV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterEd25519YaoExecuteRequestV1::deserialize(deserializer)?;
        match raw {
            RawRouterEd25519YaoExecuteRequestV1::Registration {
                authority,
                binding,
                pair_binding,
                deriver_a_input,
                deriver_b_input,
            } => Self::registration(
                authority,
                binding,
                pair_binding,
                deriver_a_input,
                deriver_b_input,
            ),
            RawRouterEd25519YaoExecuteRequestV1::Recovery {
                authority,
                binding,
                pair_binding,
                deriver_a_input,
                deriver_b_input,
            } => Self::recovery(
                authority,
                binding,
                pair_binding,
                deriver_a_input,
                deriver_b_input,
            ),
            RawRouterEd25519YaoExecuteRequestV1::Export {
                authority,
                binding,
                pair_binding,
                deriver_a_input,
                deriver_b_input,
            } => Self::export(
                authority,
                binding,
                pair_binding,
                deriver_a_input,
                deriver_b_input,
            ),
            RawRouterEd25519YaoExecuteRequestV1::LaneProvisioning {
                authority,
                binding,
                pair_binding,
                job,
                deriver_a_input,
                deriver_b_input,
            } => Self::lane_provisioning(
                authority,
                binding,
                pair_binding,
                job,
                deriver_a_input,
                deriver_b_input,
            ),
            RawRouterEd25519YaoExecuteRequestV1::LaneRefresh {
                authority,
                binding,
                pair_binding,
                job,
                deriver_a_input,
                deriver_b_input,
            } => Self::lane_refresh(
                authority,
                binding,
                pair_binding,
                job,
                deriver_a_input,
                deriver_b_input,
            ),
        }
        .map_err(D::Error::custom)
    }
}

fn validate_execute_pair(
    binding: &Ed25519YaoCeremonyBindingV1,
    expected_operation: Ed25519YaoOperationV1,
    pair_binding: &Ed25519YaoInputPairBindingV1,
    deriver_a_input: &Ed25519YaoEncryptedInputV1,
    deriver_b_input: &Ed25519YaoEncryptedInputV1,
) -> RouterAbProtocolResult<()> {
    binding.validate()?;
    if binding.operation != expected_operation || pair_binding.ceremony().binding() != binding {
        return Err(invalid_router_yao(
            "Ed25519 Yao execute pair does not match its operation binding",
        ));
    }
    let expected = Ed25519YaoInputPairBindingV1::from_inputs(
        pair_binding.ceremony().clone(),
        deriver_a_input,
        deriver_b_input,
        pair_binding.recipient_set_digest(),
        pair_binding.authorization_digest(),
    )?;
    if expected.pair_digest() != pair_binding.pair_digest() {
        return Err(invalid_router_yao(
            "Ed25519 Yao execute pair digest does not match its envelopes",
        ));
    }
    pair_binding.validate()
}

/// Operation-specific successful Router result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouterEd25519YaoExecuteSuccessV1 {
    /// Registration activation result.
    Registration {
        result: crate::protocol::ed25519_yao::RouterAbEd25519YaoActivationResultV1,
    },
    /// Recovery staged activation result.
    Recovery {
        result: crate::protocol::ed25519_yao::RouterAbEd25519YaoActivationResultV1,
    },
    /// Client-recipient export result.
    Export {
        result: crate::protocol::ed25519_yao::RouterAbEd25519YaoExportResultV1,
    },
    /// New lane output commitment.
    LaneProvisioning {
        result: crate::protocol::ed25519_yao_lane::RouterAbEd25519YaoLaneResultV1,
    },
    /// Replacement lane-epoch output commitment.
    LaneRefresh {
        result: crate::protocol::ed25519_yao_lane::RouterAbEd25519YaoLaneResultV1,
    },
}

impl RouterEd25519YaoExecuteSuccessV1 {
    /// Wraps a registration result after checking its operation binding.
    pub fn registration(
        result: crate::protocol::ed25519_yao::RouterAbEd25519YaoActivationResultV1,
    ) -> RouterAbProtocolResult<Self> {
        if result.binding().operation != Ed25519YaoOperationV1::Registration {
            return Err(invalid_router_yao(
                "Ed25519 Yao registration result has the wrong operation",
            ));
        }
        Ok(Self::Registration { result })
    }

    /// Wraps a recovery result after checking its operation binding.
    pub fn recovery(
        result: crate::protocol::ed25519_yao::RouterAbEd25519YaoActivationResultV1,
    ) -> RouterAbProtocolResult<Self> {
        if result.binding().operation != Ed25519YaoOperationV1::Recovery {
            return Err(invalid_router_yao(
                "Ed25519 Yao recovery result has the wrong operation",
            ));
        }
        Ok(Self::Recovery { result })
    }

    /// Wraps an export result after checking its operation binding.
    pub fn export(
        result: crate::protocol::ed25519_yao::RouterAbEd25519YaoExportResultV1,
    ) -> RouterAbProtocolResult<Self> {
        if result.binding().ceremony().operation != Ed25519YaoOperationV1::Export {
            return Err(invalid_router_yao(
                "Ed25519 Yao export result has the wrong operation",
            ));
        }
        Ok(Self::Export { result })
    }

    /// Wraps a lane-provisioning result after checking its job branch.
    pub fn lane_provisioning(
        result: crate::protocol::ed25519_yao_lane::RouterAbEd25519YaoLaneResultV1,
    ) -> RouterAbProtocolResult<Self> {
        result.validate()?;
        if result.job.yao_request_kind
            != crate::protocol::ed25519_yao_lane::Ed25519YaoLaneRequestKindV1::LaneProvisioning
        {
            return Err(invalid_router_yao(
                "Ed25519 Yao lane-provisioning result has the wrong operation",
            ));
        }
        Ok(Self::LaneProvisioning { result })
    }

    /// Wraps a lane-refresh result after checking its job branch.
    pub fn lane_refresh(
        result: crate::protocol::ed25519_yao_lane::RouterAbEd25519YaoLaneResultV1,
    ) -> RouterAbProtocolResult<Self> {
        result.validate()?;
        if result.job.yao_request_kind
            != crate::protocol::ed25519_yao_lane::Ed25519YaoLaneRequestKindV1::LaneRefresh
        {
            return Err(invalid_router_yao(
                "Ed25519 Yao lane-refresh result has the wrong operation",
            ));
        }
        Ok(Self::LaneRefresh { result })
    }

    /// Returns the operation branch.
    pub const fn operation(&self) -> Ed25519YaoOperationV1 {
        match self {
            Self::Registration { .. } => Ed25519YaoOperationV1::Registration,
            Self::Recovery { .. } => Ed25519YaoOperationV1::Recovery,
            Self::Export { .. } => Ed25519YaoOperationV1::Export,
            Self::LaneProvisioning { .. } => Ed25519YaoOperationV1::LaneProvisioning,
            Self::LaneRefresh { .. } => Ed25519YaoOperationV1::LaneRefresh,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum RawRouterEd25519YaoExecuteSuccessV1 {
    Registration {
        result: crate::protocol::ed25519_yao::RouterAbEd25519YaoActivationResultV1,
    },
    Recovery {
        result: crate::protocol::ed25519_yao::RouterAbEd25519YaoActivationResultV1,
    },
    Export {
        result: crate::protocol::ed25519_yao::RouterAbEd25519YaoExportResultV1,
    },
    LaneProvisioning {
        result: crate::protocol::ed25519_yao_lane::RouterAbEd25519YaoLaneResultV1,
    },
    LaneRefresh {
        result: crate::protocol::ed25519_yao_lane::RouterAbEd25519YaoLaneResultV1,
    },
}

impl<'de> Deserialize<'de> for RouterEd25519YaoExecuteSuccessV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterEd25519YaoExecuteSuccessV1::deserialize(deserializer)?;
        match raw {
            RawRouterEd25519YaoExecuteSuccessV1::Registration { result } => {
                Self::registration(result)
            }
            RawRouterEd25519YaoExecuteSuccessV1::Recovery { result } => Self::recovery(result),
            RawRouterEd25519YaoExecuteSuccessV1::Export { result } => Self::export(result),
            RawRouterEd25519YaoExecuteSuccessV1::LaneProvisioning { result } => {
                Self::lane_provisioning(result)
            }
            RawRouterEd25519YaoExecuteSuccessV1::LaneRefresh { result } => {
                Self::lane_refresh(result)
            }
        }
        .map_err(D::Error::custom)
    }
}

/// Recoverable or terminal failure class for one Router execution attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterEd25519YaoExecuteFailureCodeV1 {
    /// Internal service transport was unavailable before activation.
    ServiceUnavailable,
    /// The exact pair is already owned by another live execution.
    ConflictingPair,
    /// A prepared record or receipt was missing or mismatched.
    MissingPreparation,
    /// The nonterminal ceremony lifetime elapsed.
    CeremonyExpired,
    /// SigningWorker delivery remains uncertain and may be retried exactly.
    SigningWorkerUncertain,
    /// The role recorded a sanitized terminal failure.
    TerminalRoleFailure,
    /// The admitted authority was rejected at the Router boundary.
    AuthorizationRejected,
}

/// Reason an activated execution identity is permanently burned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterEd25519YaoBurnReasonV1 {
    /// Caller disconnected after activation began.
    CallerDisconnected,
    /// Peer acceptance or transcript state became ambiguous.
    PeerUncertain,
    /// Protocol execution failed after one-use activation.
    ProtocolFailure,
}

/// Result-style Router execution response with explicit retry semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouterEd25519YaoExecuteResultV1 {
    /// Operation-specific successful result.
    Succeeded {
        result: Box<RouterEd25519YaoExecuteSuccessV1>,
    },
    /// Failure safe for an exact request retry.
    RecoverableFailure {
        code: RouterEd25519YaoExecuteFailureCodeV1,
        retry_after_ms: u64,
    },
    /// Request rejected before one-use activation.
    Rejected {
        code: RouterEd25519YaoExecuteFailureCodeV1,
    },
    /// Execution identity burned after activation uncertainty.
    Burned {
        execution_id: Ed25519YaoExecutionIdV1,
        reason: RouterEd25519YaoBurnReasonV1,
    },
}

impl RouterEd25519YaoExecuteResultV1 {
    /// Creates a successful operation-specific result.
    pub fn succeeded(result: RouterEd25519YaoExecuteSuccessV1) -> Self {
        Self::Succeeded {
            result: Box::new(result),
        }
    }

    /// Creates a retryable failure with a positive retry hint.
    pub fn recoverable(
        code: RouterEd25519YaoExecuteFailureCodeV1,
        retry_after_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        if retry_after_ms == 0 {
            return Err(invalid_router_yao(
                "Ed25519 Yao recoverable failure retry hint must be positive",
            ));
        }
        Ok(Self::RecoverableFailure {
            code,
            retry_after_ms,
        })
    }

    /// Creates a pre-activation rejection.
    pub const fn rejected(code: RouterEd25519YaoExecuteFailureCodeV1) -> Self {
        Self::Rejected { code }
    }

    /// Creates an irreversible burned execution result.
    pub fn burned(
        execution_id: Ed25519YaoExecutionIdV1,
        reason: RouterEd25519YaoBurnReasonV1,
    ) -> Self {
        Self::Burned {
            execution_id,
            reason,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum RawRouterEd25519YaoExecuteResultV1 {
    Succeeded {
        result: Box<RouterEd25519YaoExecuteSuccessV1>,
    },
    RecoverableFailure {
        code: RouterEd25519YaoExecuteFailureCodeV1,
        retry_after_ms: u64,
    },
    Rejected {
        code: RouterEd25519YaoExecuteFailureCodeV1,
    },
    Burned {
        execution_id: Ed25519YaoExecutionIdV1,
        reason: RouterEd25519YaoBurnReasonV1,
    },
}

impl<'de> Deserialize<'de> for RouterEd25519YaoExecuteResultV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterEd25519YaoExecuteResultV1::deserialize(deserializer)?;
        match raw {
            RawRouterEd25519YaoExecuteResultV1::Succeeded { result } => {
                Ok(Self::succeeded(*result))
            }
            RawRouterEd25519YaoExecuteResultV1::RecoverableFailure {
                code,
                retry_after_ms,
            } => Self::recoverable(code, retry_after_ms).map_err(D::Error::custom),
            RawRouterEd25519YaoExecuteResultV1::Rejected { code } => Ok(Self::rejected(code)),
            RawRouterEd25519YaoExecuteResultV1::Burned {
                execution_id,
                reason,
            } => Ok(Self::burned(execution_id, reason)),
        }
    }
}

/// Execution identity allocated once for a request and never reused after ambiguity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Ed25519YaoExecutionIdV1([u8; 32]);

impl Ed25519YaoExecutionIdV1 {
    /// Creates a nonzero execution identity.
    pub fn new(bytes: [u8; 32]) -> RouterAbProtocolResult<Self> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(invalid_router_yao(
                "Ed25519 Yao execution id must be nonzero",
            ));
        }
        Ok(Self(bytes))
    }

    /// Returns the fixed execution bytes.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl<'de> Deserialize<'de> for Ed25519YaoExecutionIdV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(<[u8; 32]>::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Signature scheme for role readiness receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ed25519YaoRoleSignatureSchemeV1 {
    /// Ed25519 signature over the canonical readiness message.
    Ed25519V1,
}

/// Role signature carried by a readiness receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoRoleSignatureV1 {
    /// Signature algorithm.
    pub scheme: Ed25519YaoRoleSignatureSchemeV1,
    /// Fixed Ed25519 signature bytes.
    bytes: Vec<u8>,
}

impl Ed25519YaoRoleSignatureV1 {
    /// Creates a nonzero Ed25519 role signature.
    pub fn new(
        scheme: Ed25519YaoRoleSignatureSchemeV1,
        bytes: [u8; 64],
    ) -> RouterAbProtocolResult<Self> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(invalid_router_yao(
                "Ed25519 Yao readiness signature must be nonzero",
            ));
        }
        Ok(Self {
            scheme,
            bytes: bytes.to_vec(),
        })
    }

    /// Returns the fixed Ed25519 signature bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEd25519YaoRoleSignatureV1 {
    scheme: Ed25519YaoRoleSignatureSchemeV1,
    bytes: Vec<u8>,
}

impl<'de> Deserialize<'de> for Ed25519YaoRoleSignatureV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawEd25519YaoRoleSignatureV1::deserialize(deserializer)?;
        if raw.bytes.len() != 64 {
            return Err(D::Error::custom(
                "Ed25519 Yao readiness signature must be 64 bytes",
            ));
        }
        let mut signature_bytes = [0_u8; 64];
        signature_bytes.copy_from_slice(&raw.bytes);
        Self::new(raw.scheme, signature_bytes).map_err(D::Error::custom)
    }
}

/// Signed proof that one role durably persisted exact prepared state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoRoleReadinessReceiptV1 {
    role: Ed25519YaoDeriverRoleV1,
    session: Ed25519YaoSessionIdV1,
    pair_digest: PublicDigest32,
    local_input_digest: PublicDigest32,
    root_metadata_digest: PublicDigest32,
    prepared_at_ms: u64,
    expires_at_ms: u64,
    signature: Ed25519YaoRoleSignatureV1,
}

impl Ed25519YaoRoleReadinessReceiptV1 {
    /// Creates a receipt after the role's prepared record is durable.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: Ed25519YaoDeriverRoleV1,
        session: Ed25519YaoSessionIdV1,
        pair_digest: PublicDigest32,
        local_input_digest: PublicDigest32,
        root_metadata_digest: PublicDigest32,
        prepared_at_ms: u64,
        expires_at_ms: u64,
        signature: Ed25519YaoRoleSignatureV1,
    ) -> RouterAbProtocolResult<Self> {
        if prepared_at_ms == 0 || expires_at_ms <= prepared_at_ms {
            return Err(invalid_router_yao(
                "Ed25519 Yao readiness receipt lifetime is invalid",
            ));
        }
        validate_digest("pair_digest", pair_digest)?;
        validate_digest("local_input_digest", local_input_digest)?;
        validate_digest("root_metadata_digest", root_metadata_digest)?;
        Ok(Self {
            role,
            session,
            pair_digest,
            local_input_digest,
            root_metadata_digest,
            prepared_at_ms,
            expires_at_ms,
            signature,
        })
    }

    /// Validates that this receipt belongs to the exact pair and role input.
    pub fn validate_for_pair(
        &self,
        pair: &Ed25519YaoInputPairBindingV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate_at(self.prepared_at_ms)?;
        if self.session != pair.ceremony.binding().session_id
            || self.pair_digest != pair.pair_digest()
        {
            return Err(invalid_router_yao(
                "Ed25519 Yao readiness receipt does not match the input pair",
            ));
        }
        let expected_local_digest = match self.role {
            Ed25519YaoDeriverRoleV1::DeriverA => pair.deriver_a_input_digest(),
            Ed25519YaoDeriverRoleV1::DeriverB => pair.deriver_b_input_digest(),
        };
        if self.local_input_digest != expected_local_digest {
            return Err(invalid_router_yao(
                "Ed25519 Yao readiness receipt has the wrong role input digest",
            ));
        }
        Ok(())
    }

    /// Validates the lifetime at a supplied wall-clock time.
    pub fn validate_at(&self, now_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate_at_with_max_future_skew(now_ms, 0)
    }

    /// Validates the lifetime while allowing bounded verifier clock skew.
    pub fn validate_at_with_max_future_skew(
        &self,
        now_ms: u64,
        max_future_skew_ms: u64,
    ) -> RouterAbProtocolResult<()> {
        if self.prepared_at_ms > now_ms.saturating_add(max_future_skew_ms)
            || now_ms >= self.expires_at_ms
        {
            return Err(invalid_router_yao(
                "Ed25519 Yao readiness receipt is expired or issued in the future",
            ));
        }
        Ok(())
    }

    /// Returns the canonical digest of the unsigned receipt fields.
    pub fn signed_message_digest(&self) -> PublicDigest32 {
        derive_readiness_message_digest_v1(
            self.role,
            self.session,
            self.pair_digest,
            self.local_input_digest,
            self.root_metadata_digest,
            self.prepared_at_ms,
            self.expires_at_ms,
        )
    }

    /// Returns the role that prepared the record.
    pub const fn role(&self) -> Ed25519YaoDeriverRoleV1 {
        self.role
    }

    /// Returns the session identity.
    pub const fn session(&self) -> Ed25519YaoSessionIdV1 {
        self.session
    }

    /// Returns the exact transcript session bytes.
    pub const fn session_bytes(&self) -> [u8; 32] {
        self.session.into_bytes()
    }

    /// Returns the exact pair digest.
    pub const fn pair_digest(&self) -> PublicDigest32 {
        self.pair_digest
    }

    /// Returns the role-local input digest.
    pub const fn local_input_digest(&self) -> PublicDigest32 {
        self.local_input_digest
    }

    /// Returns the role-local root metadata digest.
    pub const fn root_metadata_digest(&self) -> PublicDigest32 {
        self.root_metadata_digest
    }

    /// Returns the preparation timestamp.
    pub const fn prepared_at_ms(&self) -> u64 {
        self.prepared_at_ms
    }

    /// Returns the expiry timestamp.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Returns the signed role proof.
    pub const fn signature(&self) -> &Ed25519YaoRoleSignatureV1 {
        &self.signature
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEd25519YaoRoleReadinessReceiptV1 {
    role: Ed25519YaoDeriverRoleV1,
    session: Ed25519YaoSessionIdV1,
    pair_digest: PublicDigest32,
    local_input_digest: PublicDigest32,
    root_metadata_digest: PublicDigest32,
    prepared_at_ms: u64,
    expires_at_ms: u64,
    signature: Ed25519YaoRoleSignatureV1,
}

impl<'de> Deserialize<'de> for Ed25519YaoRoleReadinessReceiptV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawEd25519YaoRoleReadinessReceiptV1::deserialize(deserializer)?;
        Self::new(
            raw.role,
            raw.session,
            raw.pair_digest,
            raw.local_input_digest,
            raw.root_metadata_digest,
            raw.prepared_at_ms,
            raw.expires_at_ms,
            raw.signature,
        )
        .map_err(D::Error::custom)
    }
}

/// Signed proof that one role durably entered the one-use running state for an
/// exact pair and execution identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoRoleStartAcceptanceV1 {
    role: Ed25519YaoDeriverRoleV1,
    session: Ed25519YaoSessionIdV1,
    pair_digest: PublicDigest32,
    execution_id: Ed25519YaoExecutionIdV1,
    root_metadata_digest: PublicDigest32,
    accepted_at_ms: u64,
    expires_at_ms: u64,
    signature: Ed25519YaoRoleSignatureV1,
}

impl Ed25519YaoRoleStartAcceptanceV1 {
    /// Creates an acceptance after the role's running record is durable.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: Ed25519YaoDeriverRoleV1,
        session: Ed25519YaoSessionIdV1,
        pair_digest: PublicDigest32,
        execution_id: Ed25519YaoExecutionIdV1,
        root_metadata_digest: PublicDigest32,
        accepted_at_ms: u64,
        expires_at_ms: u64,
        signature: Ed25519YaoRoleSignatureV1,
    ) -> RouterAbProtocolResult<Self> {
        if accepted_at_ms == 0 || expires_at_ms <= accepted_at_ms {
            return Err(invalid_router_yao(
                "Ed25519 Yao start acceptance lifetime is invalid",
            ));
        }
        validate_digest("pair_digest", pair_digest)?;
        validate_digest("root_metadata_digest", root_metadata_digest)?;
        Ok(Self {
            role,
            session,
            pair_digest,
            execution_id,
            root_metadata_digest,
            accepted_at_ms,
            expires_at_ms,
            signature,
        })
    }

    /// Validates that this acceptance belongs to the exact pair.
    pub fn validate_for_pair(
        &self,
        pair: &Ed25519YaoInputPairBindingV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate_at(self.accepted_at_ms)?;
        if self.session != pair.ceremony.binding().session_id
            || self.pair_digest != pair.pair_digest()
        {
            return Err(invalid_router_yao(
                "Ed25519 Yao start acceptance does not match the input pair",
            ));
        }
        Ok(())
    }

    /// Validates the lifetime at a supplied wall-clock time.
    pub fn validate_at(&self, now_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate_at_with_max_future_skew(now_ms, 0)
    }

    /// Validates the lifetime while allowing bounded verifier clock skew.
    pub fn validate_at_with_max_future_skew(
        &self,
        now_ms: u64,
        max_future_skew_ms: u64,
    ) -> RouterAbProtocolResult<()> {
        if self.accepted_at_ms > now_ms.saturating_add(max_future_skew_ms)
            || now_ms >= self.expires_at_ms
        {
            return Err(invalid_router_yao(
                "Ed25519 Yao start acceptance is expired or issued in the future",
            ));
        }
        Ok(())
    }

    /// Returns the canonical digest of the unsigned acceptance fields.
    pub fn signed_message_digest(&self) -> PublicDigest32 {
        derive_start_acceptance_message_digest_v1(
            self.role,
            self.session,
            self.pair_digest,
            self.execution_id,
            self.root_metadata_digest,
            self.accepted_at_ms,
            self.expires_at_ms,
        )
    }

    /// Returns the accepting role.
    pub const fn role(&self) -> Ed25519YaoDeriverRoleV1 {
        self.role
    }

    /// Returns the session identity.
    pub const fn session(&self) -> Ed25519YaoSessionIdV1 {
        self.session
    }

    /// Returns the exact session bytes.
    pub const fn session_bytes(&self) -> [u8; 32] {
        self.session.into_bytes()
    }

    /// Returns the exact pair digest.
    pub const fn pair_digest(&self) -> PublicDigest32 {
        self.pair_digest
    }

    /// Returns the allocated execution identity.
    pub const fn execution_id(&self) -> Ed25519YaoExecutionIdV1 {
        self.execution_id
    }

    /// Returns the role-local root metadata digest.
    pub const fn root_metadata_digest(&self) -> PublicDigest32 {
        self.root_metadata_digest
    }

    /// Returns the acceptance timestamp.
    pub const fn accepted_at_ms(&self) -> u64 {
        self.accepted_at_ms
    }

    /// Returns the expiry timestamp.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Returns the signed role proof.
    pub const fn signature(&self) -> &Ed25519YaoRoleSignatureV1 {
        &self.signature
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEd25519YaoRoleStartAcceptanceV1 {
    role: Ed25519YaoDeriverRoleV1,
    session: Ed25519YaoSessionIdV1,
    pair_digest: PublicDigest32,
    execution_id: Ed25519YaoExecutionIdV1,
    root_metadata_digest: PublicDigest32,
    accepted_at_ms: u64,
    expires_at_ms: u64,
    signature: Ed25519YaoRoleSignatureV1,
}

impl<'de> Deserialize<'de> for Ed25519YaoRoleStartAcceptanceV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawEd25519YaoRoleStartAcceptanceV1::deserialize(deserializer)?;
        Self::new(
            raw.role,
            raw.session,
            raw.pair_digest,
            raw.execution_id,
            raw.root_metadata_digest,
            raw.accepted_at_ms,
            raw.expires_at_ms,
            raw.signature,
        )
        .map_err(D::Error::custom)
    }
}

/// Computes the digest of one exact opaque role envelope.
pub fn ed25519_yao_encrypted_input_digest_v1(
    input: &Ed25519YaoEncryptedInputV1,
) -> RouterAbProtocolResult<PublicDigest32> {
    input.validate()?;
    let mut bytes =
        Vec::with_capacity(INPUT_DIGEST_DOMAIN_V1.len() + input.ciphertext().len() + 128);
    bytes.extend_from_slice(INPUT_DIGEST_DOMAIN_V1);
    bytes.push(input.kind().wire_tag());
    bytes.push(input.deriver().wire_tag());
    bytes.push(operation_tag(input.operation()));
    bytes.extend_from_slice(&input.session());
    bytes.extend_from_slice(&input.stable_context_binding());
    bytes.extend_from_slice(input.encapsulated_key());
    push_u32(&mut bytes, input.ciphertext().len());
    bytes.extend_from_slice(input.ciphertext());
    Ok(digest_bytes(&bytes))
}

/// Computes the canonical digest of the three public HPKE recipient keys.
pub fn ed25519_yao_recipient_set_digest_v1(
    deriver_a_input_public_key: [u8; 32],
    deriver_b_input_public_key: [u8; 32],
    signing_worker_recipient_public_key: [u8; 32],
) -> RouterAbProtocolResult<PublicDigest32> {
    let keys = [
        deriver_a_input_public_key,
        deriver_b_input_public_key,
        signing_worker_recipient_public_key,
    ];
    if keys.iter().any(|key| key.iter().all(|byte| *byte == 0)) {
        return Err(invalid_router_yao(
            "Ed25519 Yao recipient set contains a zero public key",
        ));
    }
    if keys[0] == keys[1] || keys[0] == keys[2] || keys[1] == keys[2] {
        return Err(invalid_router_yao(
            "Ed25519 Yao recipient set public keys must be distinct",
        ));
    }
    let mut bytes = Vec::with_capacity(96);
    for key in keys {
        bytes.extend_from_slice(&key);
    }
    Ok(digest_bytes(&bytes))
}

/// Computes the canonical digest from an already validated pair of inputs.
pub fn ed25519_yao_input_pair_digest_v1(
    ceremony: &Ed25519YaoCeremonyIdentityV1,
    deriver_a_input: &Ed25519YaoEncryptedInputV1,
    deriver_b_input: &Ed25519YaoEncryptedInputV1,
    recipient_set_digest: PublicDigest32,
    authorization_digest: PublicDigest32,
) -> RouterAbProtocolResult<PublicDigest32> {
    let binding = Ed25519YaoInputPairBindingV1::from_inputs(
        ceremony.clone(),
        deriver_a_input,
        deriver_b_input,
        recipient_set_digest,
        authorization_digest,
    )?;
    Ok(binding.pair_digest())
}

fn validate_input_for_ceremony(
    ceremony: &Ed25519YaoCeremonyBindingV1,
    input: &Ed25519YaoEncryptedInputV1,
    expected_role: Ed25519YaoDeriverRoleV1,
) -> RouterAbProtocolResult<()> {
    input.validate()?;
    let expected_kind = match ceremony.circuit_family() {
        Ed25519YaoCircuitFamilyV1::Activation => {
            crate::protocol::ed25519_yao::Ed25519YaoInputKindV1::Activation
        }
        Ed25519YaoCircuitFamilyV1::Export => {
            crate::protocol::ed25519_yao::Ed25519YaoInputKindV1::Export
        }
        Ed25519YaoCircuitFamilyV1::LaneMaterialization => {
            crate::protocol::ed25519_yao::Ed25519YaoInputKindV1::LaneMaterialization
        }
    };
    if input.kind() != expected_kind
        || input.deriver() != expected_role
        || input.operation() != ceremony.operation
        || input.session() != ceremony.session_id.into_bytes()
        || input.stable_context_binding() != ceremony.stable_key_context_binding.into_bytes()
    {
        return Err(invalid_router_yao(
            "Ed25519 Yao input does not match the ceremony identity",
        ));
    }
    Ok(())
}

fn derive_input_pair_digest_v1(
    ceremony: &Ed25519YaoCeremonyIdentityV1,
    deriver_a_input_digest: PublicDigest32,
    deriver_b_input_digest: PublicDigest32,
    recipient_set_digest: PublicDigest32,
    authorization_digest: PublicDigest32,
) -> PublicDigest32 {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(PAIR_DIGEST_DOMAIN_V1);
    push_identity(&mut bytes, ceremony);
    push_digest(&mut bytes, deriver_a_input_digest);
    push_digest(&mut bytes, deriver_b_input_digest);
    push_digest(&mut bytes, recipient_set_digest);
    push_digest(&mut bytes, authorization_digest);
    digest_bytes(&bytes)
}

fn derive_readiness_message_digest_v1(
    role: Ed25519YaoDeriverRoleV1,
    session: Ed25519YaoSessionIdV1,
    pair_digest: PublicDigest32,
    local_input_digest: PublicDigest32,
    root_metadata_digest: PublicDigest32,
    prepared_at_ms: u64,
    expires_at_ms: u64,
) -> PublicDigest32 {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(READINESS_DIGEST_DOMAIN_V1);
    bytes.push(role.wire_tag());
    bytes.extend_from_slice(&session.into_bytes());
    push_digest(&mut bytes, pair_digest);
    push_digest(&mut bytes, local_input_digest);
    push_digest(&mut bytes, root_metadata_digest);
    bytes.extend_from_slice(&prepared_at_ms.to_be_bytes());
    bytes.extend_from_slice(&expires_at_ms.to_be_bytes());
    digest_bytes(&bytes)
}

fn derive_start_acceptance_message_digest_v1(
    role: Ed25519YaoDeriverRoleV1,
    session: Ed25519YaoSessionIdV1,
    pair_digest: PublicDigest32,
    execution_id: Ed25519YaoExecutionIdV1,
    root_metadata_digest: PublicDigest32,
    accepted_at_ms: u64,
    expires_at_ms: u64,
) -> PublicDigest32 {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(START_ACCEPTANCE_DIGEST_DOMAIN_V1);
    bytes.push(role.wire_tag());
    bytes.extend_from_slice(&session.into_bytes());
    push_digest(&mut bytes, pair_digest);
    bytes.extend_from_slice(&execution_id.into_bytes());
    push_digest(&mut bytes, root_metadata_digest);
    bytes.extend_from_slice(&accepted_at_ms.to_be_bytes());
    bytes.extend_from_slice(&expires_at_ms.to_be_bytes());
    digest_bytes(&bytes)
}

fn push_identity(bytes: &mut Vec<u8>, identity: &Ed25519YaoCeremonyIdentityV1) {
    bytes.extend_from_slice(identity.protocol().as_str().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(identity.circuit().as_str().as_bytes());
    bytes.push(0);
    let binding = identity.binding();
    push_string(bytes, &binding.lifecycle.lifecycle_id);
    push_string(bytes, binding.lifecycle.work_kind.as_str());
    push_string(bytes, binding.lifecycle.primitive_request_kind.as_str());
    push_string(bytes, binding.lifecycle.root_share_epoch.as_str());
    push_string(bytes, &binding.lifecycle.account_id);
    push_string(bytes, &binding.lifecycle.session_id);
    push_string(bytes, &binding.lifecycle.signer_set_id);
    push_string(bytes, &binding.lifecycle.selected_server_id);
    bytes.push(operation_tag(binding.operation));
    bytes.extend_from_slice(&binding.session_id.into_bytes());
    bytes.extend_from_slice(&binding.stable_key_context_binding.into_bytes());
}

fn operation_tag(operation: Ed25519YaoOperationV1) -> u8 {
    match operation {
        Ed25519YaoOperationV1::Registration => 1,
        Ed25519YaoOperationV1::Recovery => 2,
        Ed25519YaoOperationV1::Refresh => 3,
        Ed25519YaoOperationV1::Export => 4,
        Ed25519YaoOperationV1::LaneProvisioning => 5,
        Ed25519YaoOperationV1::LaneRefresh => 6,
    }
}

fn push_string(bytes: &mut Vec<u8>, value: &str) {
    push_u32(bytes, value.len());
    bytes.extend_from_slice(value.as_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: usize) {
    bytes.extend_from_slice(&(value as u32).to_be_bytes());
}

fn push_digest(bytes: &mut Vec<u8>, digest: PublicDigest32) {
    bytes.extend_from_slice(digest.as_bytes());
}

fn digest_bytes(bytes: &[u8]) -> PublicDigest32 {
    PublicDigest32::new(Sha256::digest(bytes).into())
}

fn validate_digest(field: &'static str, digest: PublicDigest32) -> RouterAbProtocolResult<()> {
    if digest.bytes.iter().all(|byte| *byte == 0) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("Ed25519 Yao {field} must be nonzero"),
        ));
    }
    Ok(())
}

fn invalid_router_yao(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::MalformedWirePayload, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derivation::{PublicDigest32, RootShareEpoch};
    use crate::protocol::gate::ExpensiveWorkKindV1;
    use crate::protocol::lifecycle::LifecycleScopeV1;

    fn binding() -> Ed25519YaoCeremonyBindingV1 {
        Ed25519YaoCeremonyBindingV1::new(
            LifecycleScopeV1::new(
                "lifecycle-1",
                ExpensiveWorkKindV1::RegistrationPrepare,
                RootShareEpoch::new("epoch-1").expect("epoch"),
                "account-1",
                "session-1",
                "signer-set-1",
                "server-1",
            )
            .expect("lifecycle"),
            Ed25519YaoOperationV1::Registration,
            Ed25519YaoSessionIdV1::new([1; 32]).expect("session"),
            crate::protocol::ed25519_yao::Ed25519YaoStableKeyContextBindingV1::new([2; 32]),
            crate::protocol::lifecycle::MpcMaterialActivationRefV1::new(
                "activation-1",
                "capability-1",
                "account-1",
                "key-1",
                "lifecycle-1",
                "server-1",
            )
            .expect("material activation"),
        )
        .expect("binding")
    }

    fn input(role: Ed25519YaoDeriverRoleV1, fill: u8) -> Ed25519YaoEncryptedInputV1 {
        Ed25519YaoEncryptedInputV1::new(
            crate::protocol::ed25519_yao::Ed25519YaoInputKindV1::Activation,
            role,
            Ed25519YaoOperationV1::Registration,
            [1; 32],
            [2; 32],
            [3; 32],
            vec![fill; 32],
        )
        .expect("input")
    }

    #[test]
    fn pair_digest_is_canonical_and_changes_with_either_input() {
        let ceremony = Ed25519YaoCeremonyIdentityV1::from_binding(binding()).expect("identity");
        let a = input(Ed25519YaoDeriverRoleV1::DeriverA, 4);
        let b = input(Ed25519YaoDeriverRoleV1::DeriverB, 5);
        let pair = Ed25519YaoInputPairBindingV1::from_inputs(
            ceremony.clone(),
            &a,
            &b,
            PublicDigest32::new([6; 32]),
            PublicDigest32::new([7; 32]),
        )
        .expect("pair");
        assert_eq!(
            hex::encode(pair.deriver_a_input_digest().bytes),
            "a109a8e00efbc6858e5096416348ccaae58c036cb475f5d93cb407611d0a62eb"
        );
        assert_eq!(
            hex::encode(pair.deriver_b_input_digest().bytes),
            "7fba9a0afac0469b5743d70c35f4049f5b1d2723fe3993c686e835f3b7632a4b"
        );
        assert!(pair.validate().is_ok());
        assert_eq!(
            hex::encode(pair.pair_digest().bytes),
            "663ad944ce14e451f6d87eb8415ef1aa665d75e18c92913bcc5e4e11c49f2cfc"
        );
        let changed = Ed25519YaoInputPairBindingV1::from_inputs(
            ceremony,
            &a,
            &input(Ed25519YaoDeriverRoleV1::DeriverB, 8),
            PublicDigest32::new([6; 32]),
            PublicDigest32::new([7; 32]),
        )
        .expect("changed pair");
        assert_ne!(pair.pair_digest(), changed.pair_digest());
    }

    #[test]
    fn gateway_request_constructs_pair_only_in_rust() {
        let request = RouterEd25519YaoGatewayExecuteRequestV1::registration(
            binding(),
            input(Ed25519YaoDeriverRoleV1::DeriverA, 4),
            input(Ed25519YaoDeriverRoleV1::DeriverB, 5),
        )
        .expect("gateway request");
        let authorization_digest = request
            .authorization_digest()
            .expect("authorization digest");
        assert_ne!(authorization_digest, PublicDigest32::new([0; 32]));
        let wire = serde_json::to_vec(&request).expect("gateway request JSON");
        let decoded = serde_json::from_slice::<RouterEd25519YaoGatewayExecuteRequestV1>(&wire)
            .expect("gateway request round trip");
        let execute = decoded
            .into_execute_request(
                ed25519_yao_recipient_set_digest_v1([1; 32], [2; 32], [3; 32])
                    .expect("recipient digest"),
                1,
                2,
            )
            .expect("internal execute request");
        assert_eq!(execute.authority().authority_digest(), authorization_digest);
        assert_eq!(
            execute.pair_binding().recipient_set_digest(),
            ed25519_yao_recipient_set_digest_v1([1; 32], [2; 32], [3; 32])
                .expect("recipient digest")
        );
    }

    #[test]
    fn gateway_target_v2_constructs_pair_only_in_rust() {
        let target = RouterEd25519YaoGatewayExecuteTargetV2::registration(
            binding(),
            input(Ed25519YaoDeriverRoleV1::DeriverA, 4),
            input(Ed25519YaoDeriverRoleV1::DeriverB, 5),
        )
        .expect("gateway target");
        let authorization_digest = target.authorization_digest().expect("authorization digest");
        let wire = serde_json::to_vec(&target).expect("gateway target JSON");
        let decoded = serde_json::from_slice::<RouterEd25519YaoGatewayExecuteTargetV2>(&wire)
            .expect("gateway target round trip");
        let execute = decoded
            .into_execute_request(
                ed25519_yao_recipient_set_digest_v1([1; 32], [2; 32], [3; 32])
                    .expect("recipient digest"),
                1,
                2,
            )
            .expect("internal execute request");
        assert_eq!(execute.authority().authority_digest(), authorization_digest);
        assert_eq!(execute.operation(), Ed25519YaoOperationV1::Registration);
    }

    #[test]
    fn recipient_set_digest_is_ordered_and_rejects_duplicate_keys() {
        let digest = ed25519_yao_recipient_set_digest_v1([1; 32], [2; 32], [3; 32])
            .expect("recipient digest");
        assert_eq!(
            hex::encode(digest.bytes),
            "8a2e491356cfdb05a1d13785e0794d7cd163f91af79a146c976b1d2ac643b679"
        );
        assert_ne!(
            digest,
            ed25519_yao_recipient_set_digest_v1([2; 32], [1; 32], [3; 32])
                .expect("ordered recipient digest")
        );
        assert!(ed25519_yao_recipient_set_digest_v1([1; 32], [1; 32], [3; 32]).is_err());
        assert!(ed25519_yao_recipient_set_digest_v1([0; 32], [2; 32], [3; 32]).is_err());
    }

    #[test]
    fn pair_digest_wire_value_cannot_be_replaced() {
        let ceremony = Ed25519YaoCeremonyIdentityV1::from_binding(binding()).expect("identity");
        let pair = Ed25519YaoInputPairBindingV1::new(
            ceremony,
            PublicDigest32::new([3; 32]),
            PublicDigest32::new([4; 32]),
            PublicDigest32::new([5; 32]),
            PublicDigest32::new([6; 32]),
        )
        .expect("pair");
        let mut value = serde_json::to_value(&pair).expect("json");
        value["pair_digest"]["bytes"][0] = serde_json::json!(0);
        assert!(serde_json::from_value::<Ed25519YaoInputPairBindingV1>(value).is_err());
    }

    #[test]
    fn readiness_receipt_binds_role_local_input_and_pair() {
        let ceremony = Ed25519YaoCeremonyIdentityV1::from_binding(binding()).expect("identity");
        let a = input(Ed25519YaoDeriverRoleV1::DeriverA, 4);
        let b = input(Ed25519YaoDeriverRoleV1::DeriverB, 5);
        let pair = Ed25519YaoInputPairBindingV1::from_inputs(
            ceremony,
            &a,
            &b,
            PublicDigest32::new([6; 32]),
            PublicDigest32::new([7; 32]),
        )
        .expect("pair");
        let receipt = Ed25519YaoRoleReadinessReceiptV1::new(
            Ed25519YaoDeriverRoleV1::DeriverA,
            pair.ceremony().binding().session_id,
            pair.pair_digest(),
            pair.deriver_a_input_digest(),
            PublicDigest32::new([8; 32]),
            10,
            100,
            Ed25519YaoRoleSignatureV1::new(Ed25519YaoRoleSignatureSchemeV1::Ed25519V1, [9; 64])
                .expect("signature"),
        )
        .expect("receipt");
        assert!(receipt.validate_for_pair(&pair).is_ok());
        assert!(receipt.validate_at(9).is_err());
        assert!(receipt.validate_at_with_max_future_skew(9, 1).is_ok());
        assert!(receipt.validate_at_with_max_future_skew(8, 1).is_err());
        assert!(receipt.validate_at(100).is_err());
        assert!(receipt.validate_at_with_max_future_skew(100, 1).is_err());
        let wire = serde_json::to_value(&receipt).expect("receipt JSON");
        let decoded = serde_json::from_value::<Ed25519YaoRoleReadinessReceiptV1>(wire)
            .expect("receipt roundtrip");
        assert_eq!(
            decoded.signed_message_digest(),
            receipt.signed_message_digest()
        );
    }

    #[test]
    fn start_acceptance_binds_execution_identity_and_pair() {
        let ceremony = Ed25519YaoCeremonyIdentityV1::from_binding(binding()).expect("identity");
        let a = input(Ed25519YaoDeriverRoleV1::DeriverA, 4);
        let b = input(Ed25519YaoDeriverRoleV1::DeriverB, 5);
        let pair = Ed25519YaoInputPairBindingV1::from_inputs(
            ceremony,
            &a,
            &b,
            PublicDigest32::new([6; 32]),
            PublicDigest32::new([7; 32]),
        )
        .expect("pair");
        let acceptance = Ed25519YaoRoleStartAcceptanceV1::new(
            Ed25519YaoDeriverRoleV1::DeriverB,
            pair.ceremony().binding().session_id,
            pair.pair_digest(),
            Ed25519YaoExecutionIdV1::new([8; 32]).expect("execution"),
            PublicDigest32::new([9; 32]),
            10,
            100,
            Ed25519YaoRoleSignatureV1::new(Ed25519YaoRoleSignatureSchemeV1::Ed25519V1, [10; 64])
                .expect("signature"),
        )
        .expect("acceptance");
        assert!(acceptance.validate_for_pair(&pair).is_ok());
        assert!(acceptance.validate_at(9).is_err());
        assert!(acceptance.validate_at_with_max_future_skew(9, 1).is_ok());
        assert!(acceptance.validate_at_with_max_future_skew(8, 1).is_err());
        assert!(acceptance.validate_at(100).is_err());
        let wire = serde_json::to_value(&acceptance).expect("acceptance JSON");
        let decoded = serde_json::from_value::<Ed25519YaoRoleStartAcceptanceV1>(wire)
            .expect("acceptance roundtrip");
        assert_eq!(
            decoded.signed_message_digest(),
            acceptance.signed_message_digest()
        );
        assert_ne!(
            acceptance.signed_message_digest(),
            Ed25519YaoRoleStartAcceptanceV1::new(
                Ed25519YaoDeriverRoleV1::DeriverB,
                acceptance.session(),
                acceptance.pair_digest(),
                Ed25519YaoExecutionIdV1::new([11; 32]).expect("execution"),
                acceptance.root_metadata_digest(),
                acceptance.accepted_at_ms(),
                acceptance.expires_at_ms(),
                acceptance.signature().clone(),
            )
            .expect("changed acceptance")
            .signed_message_digest()
        );
    }

    #[test]
    fn execute_request_union_rejects_cross_operation_fields() {
        let ceremony = Ed25519YaoCeremonyIdentityV1::from_binding(binding()).expect("identity");
        let a = input(Ed25519YaoDeriverRoleV1::DeriverA, 4);
        let b = input(Ed25519YaoDeriverRoleV1::DeriverB, 5);
        let pair = Ed25519YaoInputPairBindingV1::from_inputs(
            ceremony,
            &a,
            &b,
            PublicDigest32::new([6; 32]),
            PublicDigest32::new([7; 32]),
        )
        .expect("pair");
        let authority =
            RouterAdmittedExecutionAuthorityV1::new(PublicDigest32::new([7; 32]), 10, 100)
                .expect("authority");
        let mismatched_authority =
            RouterAdmittedExecutionAuthorityV1::new(PublicDigest32::new([8; 32]), 10, 100)
                .expect("mismatched authority");
        assert!(RouterEd25519YaoExecuteRequestV1::registration(
            mismatched_authority,
            binding(),
            pair.clone(),
            a.clone(),
            b.clone(),
        )
        .is_err());
        let request =
            RouterEd25519YaoExecuteRequestV1::registration(authority, binding(), pair, a, b)
                .expect("registration request");
        let wire = serde_json::to_value(&request).expect("request JSON");
        let decoded = serde_json::from_value::<RouterEd25519YaoExecuteRequestV1>(wire)
            .expect("request roundtrip");
        assert_eq!(decoded.operation(), Ed25519YaoOperationV1::Registration);
        assert!(RouterEd25519YaoExecuteRequestV1::recovery(
            authority,
            binding(),
            decoded.pair_binding().clone(),
            input(Ed25519YaoDeriverRoleV1::DeriverA, 4),
            input(Ed25519YaoDeriverRoleV1::DeriverB, 5),
        )
        .is_err());
    }
}
