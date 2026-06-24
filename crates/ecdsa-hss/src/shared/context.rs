use crate::error::{EcdsaHssError, EcdsaHssResult};

pub const ECDSA_HSS_CONTEXT_VERSION: &str = "v4";
pub const ECDSA_HSS_CONTEXT_DOMAIN_TAG: &[u8] = b"ecdsa-hss:context:v4";
pub const ECDSA_HSS_SCHEME_ID: &str = "ecdsa-hss-v4";
pub const ECDSA_HSS_CURVE: &str = "secp256k1";
pub const ECDSA_HSS_PARTICIPANT_IDS: [u16; 2] = [1, 2];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaHssStableKeyContext {
    pub application_binding_digest: [u8; 32],
}

impl EcdsaHssStableKeyContext {
    pub fn new(application_binding_digest: [u8; 32]) -> Self {
        Self {
            application_binding_digest,
        }
    }

    pub fn validate(&self) -> EcdsaHssResult<()> {
        Ok(())
    }
}

pub fn encode_context(context: &EcdsaHssStableKeyContext) -> EcdsaHssResult<Vec<u8>> {
    context.validate()?;

    let mut out = Vec::with_capacity(
        ECDSA_HSS_CONTEXT_DOMAIN_TAG.len()
            + encoded_string_len(ECDSA_HSS_SCHEME_ID)?
            + encoded_string_len(ECDSA_HSS_CURVE)?
            + context.application_binding_digest.len()
            + 1
            + (ECDSA_HSS_PARTICIPANT_IDS.len() * 2),
    );

    out.extend_from_slice(ECDSA_HSS_CONTEXT_DOMAIN_TAG);
    push_ascii_string(&mut out, ECDSA_HSS_SCHEME_ID)?;
    push_ascii_string(&mut out, ECDSA_HSS_CURVE)?;
    out.extend_from_slice(&context.application_binding_digest);

    out.push(
        u8::try_from(ECDSA_HSS_PARTICIPANT_IDS.len()).map_err(|_| {
            EcdsaHssError::invalid_length("participant_ids length exceeds u8 range")
        })?,
    );
    for participant_id in ECDSA_HSS_PARTICIPANT_IDS {
        out.extend_from_slice(&participant_id.to_be_bytes());
    }

    Ok(out)
}

fn validate_ascii_field<'a>(field_name: &str, value: &'a str) -> EcdsaHssResult<&'a str> {
    if value.is_empty() {
        return Err(EcdsaHssError::invalid_input(format!(
            "{field_name} must be non-empty"
        )));
    }
    if !value.is_ascii() {
        return Err(EcdsaHssError::invalid_input(format!(
            "{field_name} must be ASCII-only"
        )));
    }
    if value.len() > usize::from(u16::MAX) {
        return Err(EcdsaHssError::invalid_length(format!(
            "{field_name} exceeds u16 length encoding"
        )));
    }
    Ok(value)
}

fn encoded_string_len(value: &str) -> EcdsaHssResult<usize> {
    Ok(validate_ascii_field("encoded string", value)?.len() + 2)
}

fn push_ascii_string(out: &mut Vec<u8>, value: &str) -> EcdsaHssResult<()> {
    let value = validate_ascii_field("string field", value)?;
    let len = u16::try_from(value.len())
        .map_err(|_| EcdsaHssError::invalid_length("string field exceeds u16 length"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
