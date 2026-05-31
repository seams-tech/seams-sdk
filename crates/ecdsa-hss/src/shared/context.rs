use crate::error::{EcdsaHssError, EcdsaHssResult};

pub const ECDSA_HSS_CONTEXT_DOMAIN_TAG: &[u8] = b"ecdsa-hss:context:v2";
pub const ECDSA_HSS_SCHEME_ID: &str = "ecdsa-hss-v2";
pub const ECDSA_HSS_CURVE: &str = "secp256k1";
pub const ECDSA_HSS_KEY_SCOPE: &str = "evm-family";
pub const ECDSA_HSS_PARTICIPANT_IDS: [u16; 2] = [1, 2];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaHssStableKeyContext {
    pub wallet_id: String,
    pub rp_id: String,
    pub ecdsa_threshold_key_id: String,
    pub signing_root_id: String,
    pub signing_root_version: String,
    pub key_purpose: String,
    pub key_version: String,
}

impl EcdsaHssStableKeyContext {
    pub fn new(
        wallet_id: impl Into<String>,
        rp_id: impl Into<String>,
        ecdsa_threshold_key_id: impl Into<String>,
        signing_root_id: impl Into<String>,
        signing_root_version: impl Into<String>,
        key_purpose: impl Into<String>,
        key_version: impl Into<String>,
    ) -> Self {
        Self {
            wallet_id: wallet_id.into(),
            rp_id: rp_id.into(),
            ecdsa_threshold_key_id: ecdsa_threshold_key_id.into(),
            signing_root_id: signing_root_id.into(),
            signing_root_version: signing_root_version.into(),
            key_purpose: key_purpose.into(),
            key_version: key_version.into(),
        }
    }

    pub fn validate(&self) -> EcdsaHssResult<()> {
        validate_ascii_field("wallet_id", &self.wallet_id)?;
        validate_ascii_field("rp_id", &self.rp_id)?;
        validate_ascii_field("ecdsa_threshold_key_id", &self.ecdsa_threshold_key_id)?;
        validate_ascii_field("signing_root_id", &self.signing_root_id)?;
        validate_ascii_field("signing_root_version", &self.signing_root_version)?;
        validate_ascii_field("key_purpose", &self.key_purpose)?;
        validate_ascii_field("key_version", &self.key_version)?;
        Ok(())
    }
}

pub fn encode_context(context: &EcdsaHssStableKeyContext) -> EcdsaHssResult<Vec<u8>> {
    context.validate()?;

    let mut out = Vec::with_capacity(
        ECDSA_HSS_CONTEXT_DOMAIN_TAG.len()
            + encoded_string_len(ECDSA_HSS_SCHEME_ID)?
            + encoded_string_len(ECDSA_HSS_CURVE)?
            + encoded_string_len(&context.wallet_id)?
            + encoded_string_len(&context.rp_id)?
            + encoded_string_len(ECDSA_HSS_KEY_SCOPE)?
            + encoded_string_len(&context.ecdsa_threshold_key_id)?
            + encoded_string_len(&context.signing_root_id)?
            + encoded_string_len(&context.signing_root_version)?
            + encoded_string_len(&context.key_purpose)?
            + encoded_string_len(&context.key_version)?
            + 1
            + (ECDSA_HSS_PARTICIPANT_IDS.len() * 2),
    );

    out.extend_from_slice(ECDSA_HSS_CONTEXT_DOMAIN_TAG);
    push_ascii_string(&mut out, ECDSA_HSS_SCHEME_ID)?;
    push_ascii_string(&mut out, ECDSA_HSS_CURVE)?;
    push_ascii_string(&mut out, &context.wallet_id)?;
    push_ascii_string(&mut out, &context.rp_id)?;
    push_ascii_string(&mut out, ECDSA_HSS_KEY_SCOPE)?;
    push_ascii_string(&mut out, &context.ecdsa_threshold_key_id)?;
    push_ascii_string(&mut out, &context.signing_root_id)?;
    push_ascii_string(&mut out, &context.signing_root_version)?;
    push_ascii_string(&mut out, &context.key_purpose)?;
    push_ascii_string(&mut out, &context.key_version)?;

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
