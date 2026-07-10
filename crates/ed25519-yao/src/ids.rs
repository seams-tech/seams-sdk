/// Frozen Router A/B Ed25519 Yao protocol identifier string.
pub const PROTOCOL_ID_STR: &str = "router_ab_ed25519_yao_v1";
/// Frozen activation circuit identifier string.
pub const ACTIVATION_CIRCUIT_ID_STR: &str = "ed25519_yao_activation_v1";
/// Frozen export circuit identifier string.
pub const EXPORT_CIRCUIT_ID_STR: &str = "ed25519_yao_export_v1";
/// Frozen activation output-schema identifier string.
pub const ACTIVATION_OUTPUT_SCHEMA_ID_STR: &str = "ed25519_yao_activation_output_schema_v1";
/// Frozen export output-schema identifier string.
pub const EXPORT_OUTPUT_SCHEMA_ID_STR: &str = "ed25519_yao_export_output_schema_v1";

/// The only protocol identifier accepted by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtocolId(());

impl ProtocolId {
    /// Returns the frozen wire identifier.
    pub const fn as_str(self) -> &'static str {
        PROTOCOL_ID_STR
    }
}

/// Frozen protocol identifier value.
pub const PROTOCOL_ID: ProtocolId = ProtocolId(());

/// A fixed circuit identifier accepted by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CircuitId(&'static str);

impl CircuitId {
    /// Returns the frozen circuit identifier string.
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// Frozen activation circuit identifier value.
pub const ACTIVATION_CIRCUIT_ID: CircuitId = CircuitId(ACTIVATION_CIRCUIT_ID_STR);
/// Frozen export circuit identifier value.
pub const EXPORT_CIRCUIT_ID: CircuitId = CircuitId(EXPORT_CIRCUIT_ID_STR);

/// Disjoint fixed circuit families in protocol v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CircuitFamily {
    /// Registration, activation, recovery, and refresh derivation without seed output.
    Activation,
    /// Explicitly authorized seed export.
    Export,
}

impl CircuitFamily {
    /// Returns the fixed identifier for this family.
    pub const fn circuit_id(self) -> CircuitId {
        match self {
            Self::Activation => ACTIVATION_CIRCUIT_ID,
            Self::Export => EXPORT_CIRCUIT_ID,
        }
    }
}
