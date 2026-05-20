use signer_core::error::{CoreResult, SignerCoreError};

pub const ECDSA_HSS_V1_CONTEXT_DOMAIN_TAG: &[u8] = b"ecdsa-hss:context:v1";
pub const ECDSA_HSS_V1_SCHEME_ID: &str = "ecdsa-hss-v1";
pub const ECDSA_HSS_V1_CURVE: &str = "secp256k1";
pub const ECDSA_HSS_V1_KEY_SCOPE: &str = "evm-family";
pub const ECDSA_HSS_V1_PARTICIPANT_IDS: [u16; 2] = [1, 2];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaHssStableKeyContextV1 {
    pub wallet_session_user_id: String,
    pub subject_id: String,
    pub ecdsa_threshold_key_id: String,
    pub signing_root_id: String,
    pub signing_root_version: String,
    pub key_purpose: String,
    pub key_version: String,
}

impl EcdsaHssStableKeyContextV1 {
    pub fn new(
        wallet_session_user_id: impl Into<String>,
        subject_id: impl Into<String>,
        ecdsa_threshold_key_id: impl Into<String>,
        signing_root_id: impl Into<String>,
        signing_root_version: impl Into<String>,
        key_purpose: impl Into<String>,
        key_version: impl Into<String>,
    ) -> Self {
        Self {
            wallet_session_user_id: wallet_session_user_id.into(),
            subject_id: subject_id.into(),
            ecdsa_threshold_key_id: ecdsa_threshold_key_id.into(),
            signing_root_id: signing_root_id.into(),
            signing_root_version: signing_root_version.into(),
            key_purpose: key_purpose.into(),
            key_version: key_version.into(),
        }
    }

    pub fn validate(&self) -> CoreResult<()> {
        validate_ascii_field("wallet_session_user_id", &self.wallet_session_user_id)?;
        validate_ascii_field("subject_id", &self.subject_id)?;
        validate_ascii_field("ecdsa_threshold_key_id", &self.ecdsa_threshold_key_id)?;
        validate_ascii_field("signing_root_id", &self.signing_root_id)?;
        validate_ascii_field("signing_root_version", &self.signing_root_version)?;
        validate_ascii_field("key_purpose", &self.key_purpose)?;
        validate_ascii_field("key_version", &self.key_version)?;
        Ok(())
    }
}

pub fn encode_context_v1(context: &EcdsaHssStableKeyContextV1) -> CoreResult<Vec<u8>> {
    context.validate()?;

    let mut out = Vec::with_capacity(
        ECDSA_HSS_V1_CONTEXT_DOMAIN_TAG.len()
            + encoded_string_len(ECDSA_HSS_V1_SCHEME_ID)?
            + encoded_string_len(ECDSA_HSS_V1_CURVE)?
            + encoded_string_len(&context.wallet_session_user_id)?
            + encoded_string_len(&context.subject_id)?
            + encoded_string_len(ECDSA_HSS_V1_KEY_SCOPE)?
            + encoded_string_len(&context.ecdsa_threshold_key_id)?
            + encoded_string_len(&context.signing_root_id)?
            + encoded_string_len(&context.signing_root_version)?
            + encoded_string_len(&context.key_purpose)?
            + encoded_string_len(&context.key_version)?
            + 1
            + (ECDSA_HSS_V1_PARTICIPANT_IDS.len() * 2),
    );

    out.extend_from_slice(ECDSA_HSS_V1_CONTEXT_DOMAIN_TAG);
    push_ascii_string(&mut out, ECDSA_HSS_V1_SCHEME_ID)?;
    push_ascii_string(&mut out, ECDSA_HSS_V1_CURVE)?;
    push_ascii_string(&mut out, &context.wallet_session_user_id)?;
    push_ascii_string(&mut out, &context.subject_id)?;
    push_ascii_string(&mut out, ECDSA_HSS_V1_KEY_SCOPE)?;
    push_ascii_string(&mut out, &context.ecdsa_threshold_key_id)?;
    push_ascii_string(&mut out, &context.signing_root_id)?;
    push_ascii_string(&mut out, &context.signing_root_version)?;
    push_ascii_string(&mut out, &context.key_purpose)?;
    push_ascii_string(&mut out, &context.key_version)?;

    out.push(
        u8::try_from(ECDSA_HSS_V1_PARTICIPANT_IDS.len()).map_err(|_| {
            SignerCoreError::invalid_length("participant_ids length exceeds u8 range")
        })?,
    );
    for participant_id in ECDSA_HSS_V1_PARTICIPANT_IDS {
        out.extend_from_slice(&participant_id.to_be_bytes());
    }

    Ok(out)
}

fn validate_ascii_field<'a>(field_name: &str, value: &'a str) -> CoreResult<&'a str> {
    if value.is_empty() {
        return Err(SignerCoreError::invalid_input(format!(
            "{field_name} must be non-empty"
        )));
    }
    if !value.is_ascii() {
        return Err(SignerCoreError::invalid_input(format!(
            "{field_name} must be ASCII-only for v1"
        )));
    }
    if value.len() > usize::from(u16::MAX) {
        return Err(SignerCoreError::invalid_length(format!(
            "{field_name} exceeds u16 length encoding"
        )));
    }
    Ok(value)
}

fn encoded_string_len(value: &str) -> CoreResult<usize> {
    Ok(validate_ascii_field("encoded string", value)?.len() + 2)
}

fn push_ascii_string(out: &mut Vec<u8>, value: &str) -> CoreResult<()> {
    let value = validate_ascii_field("string field", value)?;
    let len = u16::try_from(value.len())
        .map_err(|_| SignerCoreError::invalid_length("string field exceeds u16 length"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
