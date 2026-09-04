use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use threshold_prf::PrfPurpose;

use crate::derivation::{
    StableTenantDerivationContextV2, TenantRootCustodyBindingV1, TenantRootDerivationNonceV1,
    TenantRootProtocolDigestV1, TENANT_ROOT_MAX_CLOCK_SKEW_MS_V1, TENANT_ROOT_MAX_LIFETIME_MS_V1,
};
use crate::protocol::envelope::{EncryptedPayloadV1, RoleEncryptedEnvelopeV1};
use crate::protocol::error::{
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};

const ECDSA_THRESHOLD_PRF_PRIVATE_REQUEST_VERSION_V2: &[u8] =
    b"router-ab-protocol/ecdsa-threshold-prf-private-request/v2";
const ECDSA_THRESHOLD_PRF_OUTER_REQUEST_VERSION_V2: &[u8] =
    b"router-ab-protocol/ecdsa-threshold-prf-outer-request/v2";

/// Fixed version for the stable tenant-root ECDSA request boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EcdsaThresholdPrfRequestVersionV2 {
    /// The stable tenant-root request shape.
    V2,
}

impl EcdsaThresholdPrfRequestVersionV2 {
    /// Returns the canonical version label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2 => "v2",
        }
    }
}

/// Fixed ECDSA threshold-PRF purpose accepted by the V2 request boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EcdsaThresholdPrfPurposeV2 {
    /// Client-owned base output.
    XClientBase,
    /// Server-owned base output.
    XServerBase,
    /// Server-owned ECDSA derivation input.
    YServer,
}

impl EcdsaThresholdPrfPurposeV2 {
    /// Returns the exact threshold-PRF purpose selected by this request.
    pub const fn threshold_prf_purpose(self) -> PrfPurpose {
        match self {
            Self::XClientBase => PrfPurpose::RouterAbXClientBaseV1,
            Self::XServerBase => PrfPurpose::RouterAbXServerBaseV1,
            Self::YServer => PrfPurpose::RouterAbEcdsaDerivationYServer,
        }
    }

    /// Returns the canonical threshold-PRF purpose label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::XClientBase => "router-ab/x_client_base/v1",
            Self::XServerBase => "router-ab/x_server_base/v1",
            Self::YServer => "router-ab-ecdsa-derivation/y-server/v1",
        }
    }
}

/// Validated request data consumed after the role-encrypted boundary.
///
/// The stable context is the only threshold-PRF input. Custody is represented
/// by its authenticated digest and is supplied again by the server-side
/// custody lookup; no caller-selected role, identity, lineage, or epoch is
/// carried by this shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EcdsaThresholdPrfPrivateRequestV2 {
    version: EcdsaThresholdPrfRequestVersionV2,
    stable_context: StableTenantDerivationContextV2,
    custody_binding_digest: TenantRootProtocolDigestV1,
    purpose: EcdsaThresholdPrfPurposeV2,
}

impl EcdsaThresholdPrfPrivateRequestV2 {
    /// Creates one exact validated private request.
    pub fn new(
        stable_context: StableTenantDerivationContextV2,
        custody_binding_digest: TenantRootProtocolDigestV1,
        purpose: EcdsaThresholdPrfPurposeV2,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            version: EcdsaThresholdPrfRequestVersionV2::V2,
            stable_context,
            custody_binding_digest,
            purpose,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates the exact stable request fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        if self.version != EcdsaThresholdPrfRequestVersionV2::V2 {
            return Err(malformed("unsupported ECDSA threshold-PRF V2 version"));
        }
        let stable_digest = self.stable_context.digest().map_err(map_derivation_error)?;
        if stable_digest.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(malformed(
                "ECDSA threshold-PRF stable context digest must be non-zero",
            ));
        }
        if self
            .custody_binding_digest
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(malformed(
                "ECDSA threshold-PRF custody binding digest must be non-zero",
            ));
        }
        let _ = self.purpose.threshold_prf_purpose();
        Ok(())
    }

    /// Validates this request against the independently authenticated custody record.
    pub fn validate_for_custody(
        &self,
        custody_binding: &TenantRootCustodyBindingV1,
        now_ms: u64,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        custody_binding
            .validate_at(now_ms)
            .map_err(map_derivation_error)?;
        if self.custody_binding_digest != custody_binding.digest().map_err(map_derivation_error)? {
            return Err(malformed(
                "ECDSA threshold-PRF private request custody binding digest does not match",
            ));
        }
        if self.stable_context.digest().map_err(map_derivation_error)?
            != custody_binding.stable_context_digest()
        {
            return Err(malformed(
                "ECDSA threshold-PRF private request stable context does not match custody",
            ));
        }
        Ok(())
    }

    /// Returns the fixed request version.
    pub const fn version(&self) -> EcdsaThresholdPrfRequestVersionV2 {
        self.version
    }

    /// Returns the stable context consumed by threshold-PRF.
    pub const fn stable_context(&self) -> &StableTenantDerivationContextV2 {
        &self.stable_context
    }

    /// Returns the authenticated custody binding digest.
    pub const fn custody_binding_digest(&self) -> TenantRootProtocolDigestV1 {
        self.custody_binding_digest
    }

    /// Returns the fixed threshold-PRF purpose.
    pub const fn purpose(&self) -> EcdsaThresholdPrfPurposeV2 {
        self.purpose
    }

    /// Returns strict canonical request bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_field(&mut out, ECDSA_THRESHOLD_PRF_PRIVATE_REQUEST_VERSION_V2);
        push_field(&mut out, self.version.as_str().as_bytes());
        push_field(
            &mut out,
            self.stable_context
                .application_binding_digest_b64u()
                .as_bytes(),
        );
        push_field(&mut out, self.custody_binding_digest.as_bytes());
        push_field(&mut out, self.purpose.as_str().as_bytes());
        out
    }

    /// Returns the digest of strict canonical private-request bytes.
    pub fn digest(&self) -> RouterAbProtocolResult<TenantRootProtocolDigestV1> {
        self.validate()?;
        TenantRootProtocolDigestV1::from_bytes(Sha256::digest(self.canonical_bytes()).into())
            .map_err(map_derivation_error)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawEcdsaThresholdPrfPrivateRequestV2 {
    version: EcdsaThresholdPrfRequestVersionV2,
    stable_context: StableTenantDerivationContextV2,
    custody_binding_digest: TenantRootProtocolDigestV1,
    purpose: EcdsaThresholdPrfPurposeV2,
}

impl<'de> Deserialize<'de> for EcdsaThresholdPrfPrivateRequestV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawEcdsaThresholdPrfPrivateRequestV2::deserialize(deserializer)?;
        if raw.version != EcdsaThresholdPrfRequestVersionV2::V2 {
            return Err(D::Error::custom(
                "unsupported ECDSA threshold-PRF private request version",
            ));
        }
        Self::new(raw.stable_context, raw.custody_binding_digest, raw.purpose)
            .map_err(D::Error::custom)
    }
}

/// Validated public transport wrapper for one stable ECDSA request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EcdsaThresholdPrfOuterRequestV2 {
    version: EcdsaThresholdPrfRequestVersionV2,
    request_nonce: TenantRootDerivationNonceV1,
    issued_at_ms: u64,
    expires_at_ms: u64,
    private_request: EcdsaThresholdPrfPrivateRequestV2,
    signer_a_envelope: RoleEncryptedEnvelopeV1,
    signer_b_envelope: RoleEncryptedEnvelopeV1,
}

impl EcdsaThresholdPrfOuterRequestV2 {
    /// Creates one exact validated outer request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_nonce: TenantRootDerivationNonceV1,
        issued_at_ms: u64,
        expires_at_ms: u64,
        private_request: EcdsaThresholdPrfPrivateRequestV2,
        signer_a_envelope: RoleEncryptedEnvelopeV1,
        signer_b_envelope: RoleEncryptedEnvelopeV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            version: EcdsaThresholdPrfRequestVersionV2::V2,
            request_nonce,
            issued_at_ms,
            expires_at_ms,
            private_request,
            signer_a_envelope,
            signer_b_envelope,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates version, custody-independent metadata, and fixed role envelopes.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        if self.version != EcdsaThresholdPrfRequestVersionV2::V2 {
            return Err(malformed(
                "unsupported ECDSA threshold-PRF outer request version",
            ));
        }
        self.private_request.validate()?;
        if self.issued_at_ms == 0
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > TENANT_ROOT_MAX_LIFETIME_MS_V1
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "ECDSA threshold-PRF V2 outer request lifetime is invalid",
            ));
        }
        self.signer_a_envelope.validate()?;
        self.signer_b_envelope.validate()?;
        if self.signer_a_envelope.recipient_role != crate::derivation::Role::SignerA {
            return Err(malformed(
                "ECDSA threshold-PRF V2 first envelope must target Signer A",
            ));
        }
        if self.signer_b_envelope.recipient_role != crate::derivation::Role::SignerB {
            return Err(malformed(
                "ECDSA threshold-PRF V2 second envelope must target Signer B",
            ));
        }
        Ok(())
    }

    /// Validates the request lifetime against one wall clock.
    pub fn validate_at(&self, now_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if self.issued_at_ms > now_ms.saturating_add(TENANT_ROOT_MAX_CLOCK_SKEW_MS_V1)
            || now_ms
                > self
                    .expires_at_ms
                    .saturating_add(TENANT_ROOT_MAX_CLOCK_SKEW_MS_V1)
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "ECDSA threshold-PRF V2 outer request is outside its clock window",
            ));
        }
        Ok(())
    }

    /// Validates the outer request against the server-authenticated custody record.
    pub fn validate_for_custody(
        &self,
        custody_binding: &TenantRootCustodyBindingV1,
        now_ms: u64,
    ) -> RouterAbProtocolResult<()> {
        self.validate_at(now_ms)?;
        self.private_request
            .validate_for_custody(custody_binding, now_ms)
    }

    /// Returns the private request after the outer boundary has been validated.
    pub const fn private_request(&self) -> &EcdsaThresholdPrfPrivateRequestV2 {
        &self.private_request
    }

    /// Returns the request nonce used for replay admission.
    pub const fn request_nonce(&self) -> TenantRootDerivationNonceV1 {
        self.request_nonce
    }

    /// Returns the issue timestamp.
    pub const fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    /// Returns the expiry timestamp.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Returns the role-A encrypted envelope.
    pub const fn signer_a_envelope(&self) -> &RoleEncryptedEnvelopeV1 {
        &self.signer_a_envelope
    }

    /// Returns the role-B encrypted envelope.
    pub const fn signer_b_envelope(&self) -> &RoleEncryptedEnvelopeV1 {
        &self.signer_b_envelope
    }

    /// Returns strict canonical outer-request bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_field(&mut out, ECDSA_THRESHOLD_PRF_OUTER_REQUEST_VERSION_V2);
        push_field(&mut out, self.version.as_str().as_bytes());
        push_field(&mut out, self.request_nonce.as_bytes());
        push_u64(&mut out, self.issued_at_ms);
        push_u64(&mut out, self.expires_at_ms);
        push_field(&mut out, &self.private_request.canonical_bytes());
        push_role_envelope(&mut out, &self.signer_a_envelope);
        push_role_envelope(&mut out, &self.signer_b_envelope);
        out
    }

    /// Returns the digest of strict canonical outer-request bytes.
    pub fn digest(&self) -> RouterAbProtocolResult<TenantRootProtocolDigestV1> {
        self.validate()?;
        TenantRootProtocolDigestV1::from_bytes(Sha256::digest(self.canonical_bytes()).into())
            .map_err(map_derivation_error)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawEcdsaThresholdPrfOuterRequestV2 {
    version: EcdsaThresholdPrfRequestVersionV2,
    request_nonce: TenantRootDerivationNonceV1,
    issued_at_ms: u64,
    expires_at_ms: u64,
    private_request: EcdsaThresholdPrfPrivateRequestV2,
    signer_a_envelope: RoleEncryptedEnvelopeV1,
    signer_b_envelope: RoleEncryptedEnvelopeV1,
}

impl<'de> Deserialize<'de> for EcdsaThresholdPrfOuterRequestV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawEcdsaThresholdPrfOuterRequestV2::deserialize(deserializer)?;
        if raw.version != EcdsaThresholdPrfRequestVersionV2::V2 {
            return Err(D::Error::custom(
                "unsupported ECDSA threshold-PRF outer request version",
            ));
        }
        Self::new(
            raw.request_nonce,
            raw.issued_at_ms,
            raw.expires_at_ms,
            raw.private_request,
            raw.signer_a_envelope,
            raw.signer_b_envelope,
        )
        .map_err(D::Error::custom)
    }
}

/// Encodes strict canonical bytes for one V2 private request.
pub fn encode_ecdsa_threshold_prf_private_request_v2(
    request: &EcdsaThresholdPrfPrivateRequestV2,
) -> Vec<u8> {
    request.canonical_bytes()
}

/// Decodes strict canonical bytes for one V2 private request.
pub fn decode_ecdsa_threshold_prf_private_request_v2(
    bytes: &[u8],
) -> RouterAbProtocolResult<EcdsaThresholdPrfPrivateRequestV2> {
    let mut decoder = RequestDecoder::new(bytes);
    decoder.expect_field(
        ECDSA_THRESHOLD_PRF_PRIVATE_REQUEST_VERSION_V2,
        "private request version",
    )?;
    decoder.expect_field(b"v2", "private request protocol version")?;
    let application_binding_digest = decoder.read_string("stable context application digest")?;
    let stable_context = StableTenantDerivationContextV2::from_application_binding_digest_b64u(
        &application_binding_digest,
    )
    .map_err(map_derivation_error)?;
    let custody_binding_digest = decoder.read_protocol_digest("custody binding digest")?;
    let purpose = parse_purpose(&decoder.read_string("threshold-PRF purpose")?)?;
    decoder.finish()?;
    let request =
        EcdsaThresholdPrfPrivateRequestV2::new(stable_context, custody_binding_digest, purpose)?;
    if request.canonical_bytes() != bytes {
        return Err(malformed(
            "ECDSA threshold-PRF V2 private request is not canonical",
        ));
    }
    Ok(request)
}

/// Encodes strict canonical bytes for one V2 outer request.
pub fn encode_ecdsa_threshold_prf_outer_request_v2(
    request: &EcdsaThresholdPrfOuterRequestV2,
) -> Vec<u8> {
    request.canonical_bytes()
}

/// Decodes strict canonical bytes for one V2 outer request.
pub fn decode_ecdsa_threshold_prf_outer_request_v2(
    bytes: &[u8],
) -> RouterAbProtocolResult<EcdsaThresholdPrfOuterRequestV2> {
    let mut decoder = RequestDecoder::new(bytes);
    decoder.expect_field(
        ECDSA_THRESHOLD_PRF_OUTER_REQUEST_VERSION_V2,
        "outer request version",
    )?;
    decoder.expect_field(b"v2", "outer request protocol version")?;
    let request_nonce =
        TenantRootDerivationNonceV1::from_bytes(decoder.read_fixed_32("outer request nonce")?)
            .map_err(map_derivation_error)?;
    let issued_at_ms = decoder.read_u64("outer request issue time")?;
    let expires_at_ms = decoder.read_u64("outer request expiry")?;
    let private_request =
        decode_ecdsa_threshold_prf_private_request_v2(decoder.read_field("private request")?)?;
    let signer_a_envelope = decoder.read_role_envelope("Signer A envelope")?;
    let signer_b_envelope = decoder.read_role_envelope("Signer B envelope")?;
    decoder.finish()?;
    let request = EcdsaThresholdPrfOuterRequestV2::new(
        request_nonce,
        issued_at_ms,
        expires_at_ms,
        private_request,
        signer_a_envelope,
        signer_b_envelope,
    )?;
    if request.canonical_bytes() != bytes {
        return Err(malformed(
            "ECDSA threshold-PRF V2 outer request is not canonical",
        ));
    }
    Ok(request)
}

fn parse_purpose(value: &str) -> RouterAbProtocolResult<EcdsaThresholdPrfPurposeV2> {
    match value {
        "router-ab/x_client_base/v1" => Ok(EcdsaThresholdPrfPurposeV2::XClientBase),
        "router-ab/x_server_base/v1" => Ok(EcdsaThresholdPrfPurposeV2::XServerBase),
        "router-ab-ecdsa-derivation/y-server/v1" => Ok(EcdsaThresholdPrfPurposeV2::YServer),
        _ => Err(malformed("unknown ECDSA threshold-PRF V2 purpose")),
    }
}

fn push_role_envelope(out: &mut Vec<u8>, envelope: &RoleEncryptedEnvelopeV1) {
    push_field(out, envelope.recipient_role.as_str().as_bytes());
    push_field(out, envelope.header_digest.as_bytes());
    push_field(out, envelope.aad_digest.as_bytes());
    push_field(out, envelope.ciphertext.as_bytes());
}

fn map_derivation_error(
    error: crate::derivation::RouterAbDerivationError,
) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("ECDSA threshold-PRF V2 request rejected derivation field: {error}"),
    )
}

fn malformed(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::MalformedWirePayload, message)
}

fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

struct RequestDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RequestDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn expect_field(&mut self, expected: &[u8], field: &'static str) -> RouterAbProtocolResult<()> {
        let actual = self.read_field(field)?;
        if actual != expected {
            return Err(malformed("ECDSA threshold-PRF V2 request version mismatch"));
        }
        Ok(())
    }

    fn read_field(&mut self, field: &'static str) -> RouterAbProtocolResult<&'a [u8]> {
        let length = self.read_u32(field)? as usize;
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| malformed("ECDSA threshold-PRF V2 request length overflow"))?;
        if end > self.bytes.len() {
            return Err(malformed(
                "ECDSA threshold-PRF V2 request field is truncated",
            ));
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn read_string(&mut self, field: &'static str) -> RouterAbProtocolResult<String> {
        String::from_utf8(self.read_field(field)?.to_vec())
            .map_err(|_| malformed("ECDSA threshold-PRF V2 request field is not UTF-8"))
    }

    fn read_fixed_32(&mut self, field: &'static str) -> RouterAbProtocolResult<[u8; 32]> {
        self.read_field(field)?
            .try_into()
            .map_err(|_| malformed("ECDSA threshold-PRF V2 request fixed field has invalid length"))
    }

    fn read_protocol_digest(
        &mut self,
        field: &'static str,
    ) -> RouterAbProtocolResult<TenantRootProtocolDigestV1> {
        TenantRootProtocolDigestV1::from_bytes(self.read_fixed_32(field)?)
            .map_err(map_derivation_error)
    }

    fn read_u32(&mut self, _field: &'static str) -> RouterAbProtocolResult<u32> {
        let bytes = self
            .bytes
            .get(self.offset..self.offset.saturating_add(4))
            .ok_or_else(|| malformed("ECDSA threshold-PRF V2 request integer is truncated"))?;
        if bytes.len() != 4 {
            return Err(malformed(
                "ECDSA threshold-PRF V2 request integer is truncated",
            ));
        }
        self.offset += 4;
        Ok(u32::from_be_bytes(
            bytes.try_into().expect("four-byte slice"),
        ))
    }

    fn read_u64(&mut self, _field: &'static str) -> RouterAbProtocolResult<u64> {
        let bytes = self
            .bytes
            .get(self.offset..self.offset.saturating_add(8))
            .ok_or_else(|| malformed("ECDSA threshold-PRF V2 request timestamp is truncated"))?;
        if bytes.len() != 8 {
            return Err(malformed(
                "ECDSA threshold-PRF V2 request timestamp is truncated",
            ));
        }
        self.offset += 8;
        Ok(u64::from_be_bytes(
            bytes.try_into().expect("eight-byte slice"),
        ))
    }

    fn read_role_envelope(
        &mut self,
        field: &'static str,
    ) -> RouterAbProtocolResult<RoleEncryptedEnvelopeV1> {
        let recipient_role = match self.read_string(field)?.as_str() {
            "signer_a" => crate::derivation::Role::SignerA,
            "signer_b" => crate::derivation::Role::SignerB,
            _ => return Err(malformed("ECDSA threshold-PRF V2 envelope role is invalid")),
        };
        let header_digest = crate::derivation::PublicDigest32::new(self.read_fixed_32(field)?);
        let aad_digest = crate::derivation::PublicDigest32::new(self.read_fixed_32(field)?);
        let ciphertext = EncryptedPayloadV1::new(self.read_field(field)?.to_vec())?;
        RoleEncryptedEnvelopeV1::new(recipient_role, header_digest, aad_digest, ciphertext)
    }

    fn finish(&self) -> RouterAbProtocolResult<()> {
        if self.offset != self.bytes.len() {
            return Err(malformed(
                "ECDSA threshold-PRF V2 request has trailing bytes",
            ));
        }
        Ok(())
    }
}
