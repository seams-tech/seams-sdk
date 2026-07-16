use crate::error::{RouterAbEcdsaDerivationError, RouterAbEcdsaDerivationResult};

pub const ROUTER_AB_ECDSA_DERIVATION_CONTEXT_VERSION: &str = "v1";
pub const ROUTER_AB_ECDSA_DERIVATION_CONTEXT_DOMAIN_TAG: &[u8] =
    b"router-ab-ecdsa-derivation/context/v1";
pub const ROUTER_AB_ECDSA_DERIVATION_SCHEME_ID: &str = "router-ab-ecdsa-derivation-v1";
pub const ROUTER_AB_ECDSA_DERIVATION_CURVE: &str = "secp256k1";
pub const ROUTER_AB_ECDSA_DERIVATION_PARTICIPANT_IDS: [u16; 2] = [1, 2];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAbEcdsaDerivationStableKeyContext {
    pub application_binding_digest: [u8; 32],
}

impl RouterAbEcdsaDerivationStableKeyContext {
    pub fn new(application_binding_digest: [u8; 32]) -> Self {
        Self {
            application_binding_digest,
        }
    }

    pub fn validate(&self) -> RouterAbEcdsaDerivationResult<()> {
        Ok(())
    }
}

pub fn encode_context(
    context: &RouterAbEcdsaDerivationStableKeyContext,
) -> RouterAbEcdsaDerivationResult<Vec<u8>> {
    context.validate()?;

    let mut out = Vec::with_capacity(
        ROUTER_AB_ECDSA_DERIVATION_CONTEXT_DOMAIN_TAG.len()
            + encoded_string_len(ROUTER_AB_ECDSA_DERIVATION_SCHEME_ID)?
            + encoded_string_len(ROUTER_AB_ECDSA_DERIVATION_CURVE)?
            + context.application_binding_digest.len()
            + 1
            + (ROUTER_AB_ECDSA_DERIVATION_PARTICIPANT_IDS.len() * 2),
    );

    out.extend_from_slice(ROUTER_AB_ECDSA_DERIVATION_CONTEXT_DOMAIN_TAG);
    push_ascii_string(&mut out, ROUTER_AB_ECDSA_DERIVATION_SCHEME_ID)?;
    push_ascii_string(&mut out, ROUTER_AB_ECDSA_DERIVATION_CURVE)?;
    out.extend_from_slice(&context.application_binding_digest);

    out.push(
        u8::try_from(ROUTER_AB_ECDSA_DERIVATION_PARTICIPANT_IDS.len()).map_err(|_| {
            RouterAbEcdsaDerivationError::invalid_length("participant_ids length exceeds u8 range")
        })?,
    );
    for participant_id in ROUTER_AB_ECDSA_DERIVATION_PARTICIPANT_IDS {
        out.extend_from_slice(&participant_id.to_be_bytes());
    }

    Ok(out)
}

fn validate_ascii_field<'a>(
    field_name: &str,
    value: &'a str,
) -> RouterAbEcdsaDerivationResult<&'a str> {
    if value.is_empty() {
        return Err(RouterAbEcdsaDerivationError::invalid_input(format!(
            "{field_name} must be non-empty"
        )));
    }
    if !value.is_ascii() {
        return Err(RouterAbEcdsaDerivationError::invalid_input(format!(
            "{field_name} must be ASCII-only"
        )));
    }
    if value.len() > usize::from(u16::MAX) {
        return Err(RouterAbEcdsaDerivationError::invalid_length(format!(
            "{field_name} exceeds u16 length encoding"
        )));
    }
    Ok(value)
}

fn encoded_string_len(value: &str) -> RouterAbEcdsaDerivationResult<usize> {
    Ok(validate_ascii_field("encoded string", value)?.len() + 2)
}

fn push_ascii_string(out: &mut Vec<u8>, value: &str) -> RouterAbEcdsaDerivationResult<()> {
    let value = validate_ascii_field("string field", value)?;
    let len = u16::try_from(value.len()).map_err(|_| {
        RouterAbEcdsaDerivationError::invalid_length("string field exceeds u16 length")
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
