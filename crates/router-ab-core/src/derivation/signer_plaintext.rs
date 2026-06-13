use serde::{Deserialize, Serialize};

use crate::derivation::candidate_mpc_prf::{MpcPrfOutputRequestV1, MpcPrfSuiteId};
use crate::derivation::context::{CandidateId, RequestKind, RootShareEpoch};
use crate::derivation::error::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
};
use crate::derivation::material::{OpenedShareKind, PublicDigest32, Role};

const SIGNER_INPUT_PLAINTEXT_VERSION_V1: &[u8] = b"router-ab-derivation/signer-input-plaintext/v1";

/// V1 quorum policy carried by decrypted signer-input plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerInputQuorumPolicyV1 {
    /// Router A/B v1 requires both configured signers.
    All2,
}

impl SignerInputQuorumPolicyV1 {
    /// Returns the canonical quorum-policy label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All2 => "all_2",
        }
    }
}

/// Strict post-decryption plaintext accepted from Router-to-signer envelopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerInputPlaintextV1 {
    /// Selected derivation candidate.
    pub candidate_id: CandidateId,
    /// Selected Candidate A suite.
    pub mpc_prf_suite_id: MpcPrfSuiteId,
    /// Primitive request kind.
    pub request_kind: RequestKind,
    /// Router lifecycle id.
    pub lifecycle_id: String,
    /// Signer-set id.
    pub signer_set_id: String,
    /// V1 quorum policy.
    pub quorum_policy: SignerInputQuorumPolicyV1,
    /// Recipient signer role.
    pub recipient_role: Role,
    /// Recipient signer identity.
    pub recipient_signer_id: String,
    /// Recipient signer key epoch.
    pub recipient_key_epoch: String,
    /// Signer-local root-share epoch.
    pub root_share_epoch: RootShareEpoch,
    /// Selected relayer identity.
    pub selected_relayer_id: String,
    /// Selected relayer key epoch.
    pub selected_relayer_key_epoch: String,
    /// Public transcript digest.
    pub transcript_digest: PublicDigest32,
    /// Router public request digest.
    pub router_request_digest: PublicDigest32,
    /// Role-envelope associated-data digest.
    pub aad_digest: PublicDigest32,
    /// Output requests this signer may evaluate.
    pub output_requests: Vec<MpcPrfOutputRequestV1>,
}

impl SignerInputPlaintextV1 {
    /// Creates validated signer-input plaintext.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        candidate_id: CandidateId,
        mpc_prf_suite_id: MpcPrfSuiteId,
        request_kind: RequestKind,
        lifecycle_id: impl Into<String>,
        signer_set_id: impl Into<String>,
        quorum_policy: SignerInputQuorumPolicyV1,
        recipient_role: Role,
        recipient_signer_id: impl Into<String>,
        recipient_key_epoch: impl Into<String>,
        root_share_epoch: RootShareEpoch,
        selected_relayer_id: impl Into<String>,
        selected_relayer_key_epoch: impl Into<String>,
        transcript_digest: PublicDigest32,
        router_request_digest: PublicDigest32,
        aad_digest: PublicDigest32,
        output_requests: Vec<MpcPrfOutputRequestV1>,
    ) -> RouterAbDerivationResult<Self> {
        let plaintext = Self {
            candidate_id,
            mpc_prf_suite_id,
            request_kind,
            lifecycle_id: lifecycle_id.into(),
            signer_set_id: signer_set_id.into(),
            quorum_policy,
            recipient_role,
            recipient_signer_id: recipient_signer_id.into(),
            recipient_key_epoch: recipient_key_epoch.into(),
            root_share_epoch,
            selected_relayer_id: selected_relayer_id.into(),
            selected_relayer_key_epoch: selected_relayer_key_epoch.into(),
            transcript_digest,
            router_request_digest,
            aad_digest,
            output_requests,
        };
        plaintext.validate()?;
        Ok(plaintext)
    }

    /// Validates the strict public metadata and output-request allowlist.
    pub fn validate(&self) -> RouterAbDerivationResult<()> {
        if self.candidate_id != CandidateId::MpcThresholdPrfV1 {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::UnsupportedCandidate,
                "signer input plaintext requires mpc_threshold_prf_v1",
            ));
        }
        require_signer_role(self.recipient_role)?;
        require_non_empty("lifecycle_id", &self.lifecycle_id)?;
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        require_non_empty("recipient_signer_id", &self.recipient_signer_id)?;
        require_non_empty("recipient_key_epoch", &self.recipient_key_epoch)?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        require_non_empty("selected_relayer_id", &self.selected_relayer_id)?;
        require_non_empty(
            "selected_relayer_key_epoch",
            &self.selected_relayer_key_epoch,
        )?;
        if self.output_requests.is_empty() {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                "signer input plaintext requires at least one output request",
            ));
        }
        for (index, request) in self.output_requests.iter().enumerate() {
            request.validate()?;
            if request.opened_share_kind == OpenedShareKind::XRelayerBase
                && (request.recipient_role != Role::Relayer
                    || request.recipient_identity != self.selected_relayer_id)
            {
                return Err(RouterAbDerivationError::new(
                    RouterAbDerivationErrorCode::RecipientMismatch,
                    "signer input plaintext relayer output recipient mismatch",
                ));
            }
            for prior in &self.output_requests[..index] {
                if prior.opened_share_kind == request.opened_share_kind
                    && prior.recipient_role == request.recipient_role
                    && prior.recipient_identity == request.recipient_identity
                {
                    return Err(RouterAbDerivationError::new(
                        RouterAbDerivationErrorCode::MalformedInput,
                        "signer input plaintext contains duplicate output request",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Returns canonical signer-input plaintext bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        encode_signer_input_plaintext_v1(self)
    }
}

/// Encodes signer-input plaintext with fixed field order.
pub fn encode_signer_input_plaintext_v1(
    plaintext: &SignerInputPlaintextV1,
) -> RouterAbDerivationResult<Vec<u8>> {
    plaintext.validate()?;
    let mut out = Vec::new();
    push_len32(&mut out, SIGNER_INPUT_PLAINTEXT_VERSION_V1);
    push_len32(&mut out, plaintext.candidate_id.as_str().as_bytes());
    push_len32(&mut out, plaintext.mpc_prf_suite_id.as_str().as_bytes());
    push_len32(&mut out, plaintext.request_kind.as_str().as_bytes());
    push_string(&mut out, &plaintext.lifecycle_id);
    push_string(&mut out, &plaintext.signer_set_id);
    push_len32(&mut out, plaintext.quorum_policy.as_str().as_bytes());
    push_len32(&mut out, plaintext.recipient_role.as_str().as_bytes());
    push_string(&mut out, &plaintext.recipient_signer_id);
    push_string(&mut out, &plaintext.recipient_key_epoch);
    push_string(&mut out, plaintext.root_share_epoch.as_str());
    push_string(&mut out, &plaintext.selected_relayer_id);
    push_string(&mut out, &plaintext.selected_relayer_key_epoch);
    push_digest(&mut out, plaintext.transcript_digest);
    push_digest(&mut out, plaintext.router_request_digest);
    push_digest(&mut out, plaintext.aad_digest);
    push_u32(&mut out, plaintext.output_requests.len() as u32);
    for request in &plaintext.output_requests {
        push_len32(&mut out, request.opened_share_kind.as_str().as_bytes());
        push_len32(&mut out, request.recipient_role.as_str().as_bytes());
        push_string(&mut out, &request.recipient_identity);
    }
    Ok(out)
}

/// Decodes strict canonical signer-input plaintext bytes.
pub fn decode_signer_input_plaintext_v1(
    bytes: &[u8],
) -> RouterAbDerivationResult<SignerInputPlaintextV1> {
    let mut decoder = SignerPlaintextDecoder { bytes, offset: 0 };
    decoder.require_label(
        SIGNER_INPUT_PLAINTEXT_VERSION_V1,
        "signer input plaintext version",
    )?;
    let candidate_id = parse_candidate_id(decoder.read_str("candidate id")?)?;
    let mpc_prf_suite_id = parse_mpc_prf_suite_id(decoder.read_str("mpc prf suite id")?)?;
    let request_kind = parse_request_kind(decoder.read_str("request kind")?)?;
    let lifecycle_id = decoder.read_string("lifecycle id")?;
    let signer_set_id = decoder.read_string("signer set id")?;
    let quorum_policy = parse_quorum_policy(decoder.read_str("quorum policy")?)?;
    let recipient_role = parse_role(decoder.read_str("recipient role")?)?;
    let recipient_signer_id = decoder.read_string("recipient signer id")?;
    let recipient_key_epoch = decoder.read_string("recipient key epoch")?;
    let root_share_epoch = RootShareEpoch::new(decoder.read_string("root share epoch")?)?;
    let selected_relayer_id = decoder.read_string("selected relayer id")?;
    let selected_relayer_key_epoch = decoder.read_string("selected relayer key epoch")?;
    let transcript_digest = decoder.read_digest("transcript digest")?;
    let router_request_digest = decoder.read_digest("router request digest")?;
    let aad_digest = decoder.read_digest("aad digest")?;
    let output_count = decoder.read_u32("output request count")?;
    let mut output_requests = Vec::with_capacity(output_count as usize);
    for _ in 0..output_count {
        let opened_share_kind = parse_opened_share_kind(decoder.read_str("opened share kind")?)?;
        let recipient_role = parse_role(decoder.read_str("output recipient role")?)?;
        let recipient_identity = decoder.read_string("output recipient identity")?;
        output_requests.push(MpcPrfOutputRequestV1::new(
            opened_share_kind,
            recipient_role,
            recipient_identity,
        )?);
    }
    decoder.require_finished()?;
    SignerInputPlaintextV1::new(
        candidate_id,
        mpc_prf_suite_id,
        request_kind,
        lifecycle_id,
        signer_set_id,
        quorum_policy,
        recipient_role,
        recipient_signer_id,
        recipient_key_epoch,
        root_share_epoch,
        selected_relayer_id,
        selected_relayer_key_epoch,
        transcript_digest,
        router_request_digest,
        aad_digest,
        output_requests,
    )
}

struct SignerPlaintextDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SignerPlaintextDecoder<'a> {
    fn require_label(
        &mut self,
        expected: &[u8],
        field: &'static str,
    ) -> RouterAbDerivationResult<()> {
        let actual = self.read_bytes(field)?;
        if actual != expected {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::UnsupportedVersion,
                format!("{field} mismatch"),
            ));
        }
        Ok(())
    }

    fn read_string(&mut self, field: &'static str) -> RouterAbDerivationResult<String> {
        let bytes = self.read_bytes(field)?;
        let value = core::str::from_utf8(bytes).map_err(|_| {
            RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                format!("{field} must be UTF-8"),
            )
        })?;
        Ok(value.to_owned())
    }

    fn read_str(&mut self, field: &'static str) -> RouterAbDerivationResult<&'a str> {
        let bytes = self.read_bytes(field)?;
        core::str::from_utf8(bytes).map_err(|_| {
            RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                format!("{field} must be UTF-8"),
            )
        })
    }

    fn read_digest(&mut self, field: &'static str) -> RouterAbDerivationResult<PublicDigest32> {
        let bytes = self.read_bytes(field)?;
        if bytes.len() != 32 {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                format!("{field} must be 32 bytes"),
            ));
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(bytes);
        Ok(PublicDigest32::new(digest))
    }

    fn read_u32(&mut self, field: &'static str) -> RouterAbDerivationResult<u32> {
        let end = self.offset.checked_add(4).ok_or_else(|| {
            RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                format!("{field} length prefix overflow"),
            )
        })?;
        if end > self.bytes.len() {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                format!("{field} is truncated"),
            ));
        }
        let mut raw = [0u8; 4];
        raw.copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
        Ok(u32::from_be_bytes(raw))
    }

    fn read_bytes(&mut self, field: &'static str) -> RouterAbDerivationResult<&'a [u8]> {
        let len = self.read_u32(field)? as usize;
        let end = self.offset.checked_add(len).ok_or_else(|| {
            RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                format!("{field} length overflow"),
            )
        })?;
        if end > self.bytes.len() {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                format!("{field} is truncated"),
            ));
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn require_finished(&self) -> RouterAbDerivationResult<()> {
        if self.offset == self.bytes.len() {
            return Ok(());
        }
        Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            "signer input plaintext has trailing bytes",
        ))
    }
}

fn parse_candidate_id(value: &str) -> RouterAbDerivationResult<CandidateId> {
    match value {
        "mpc_threshold_prf_v1" => Ok(CandidateId::MpcThresholdPrfV1),
        "split_root_derivation_v1" => Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::UnsupportedCandidate,
            "signer input plaintext requires mpc_threshold_prf_v1",
        )),
        _ => Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::UnsupportedCandidate,
            "unknown signer input plaintext candidate id",
        )),
    }
}

fn parse_mpc_prf_suite_id(value: &str) -> RouterAbDerivationResult<MpcPrfSuiteId> {
    match value {
        "threshold_prf_ristretto255_sha512" => Ok(MpcPrfSuiteId::ThresholdPrfRistretto255Sha512),
        _ => Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::UnsupportedCandidate,
            "unknown signer input plaintext MPC PRF suite id",
        )),
    }
}

fn parse_request_kind(value: &str) -> RouterAbDerivationResult<RequestKind> {
    match value {
        "registration" => Ok(RequestKind::Registration),
        "export" => Ok(RequestKind::Export),
        "refresh" => Ok(RequestKind::Refresh),
        _ => Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            "unknown signer input plaintext request kind",
        )),
    }
}

fn parse_quorum_policy(value: &str) -> RouterAbDerivationResult<SignerInputQuorumPolicyV1> {
    match value {
        "all_2" => Ok(SignerInputQuorumPolicyV1::All2),
        _ => Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            "unknown signer input plaintext quorum policy",
        )),
    }
}

fn parse_opened_share_kind(value: &str) -> RouterAbDerivationResult<OpenedShareKind> {
    match value {
        "x_client_base" => Ok(OpenedShareKind::XClientBase),
        "x_relayer_base" => Ok(OpenedShareKind::XRelayerBase),
        _ => Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            "unknown signer input plaintext opened share kind",
        )),
    }
}

fn parse_role(value: &str) -> RouterAbDerivationResult<Role> {
    match value {
        "router" => Ok(Role::Router),
        "signer_a" => Ok(Role::SignerA),
        "signer_b" => Ok(Role::SignerB),
        "relayer" => Ok(Role::Relayer),
        "client" => Ok(Role::Client),
        _ => Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            "unknown signer input plaintext role",
        )),
    }
}

fn require_signer_role(role: Role) -> RouterAbDerivationResult<()> {
    match role {
        Role::SignerA | Role::SignerB => Ok(()),
        _ => Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            "signer input plaintext recipient role must be a signer",
        )),
    }
}

fn require_non_empty(field: &'static str, value: &str) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            format!("{field} is required"),
        ));
    }
    Ok(())
}

fn push_string(out: &mut Vec<u8>, value: &str) {
    push_len32(out, value.as_bytes());
}

fn push_digest(out: &mut Vec<u8>, digest: PublicDigest32) {
    push_len32(out, digest.as_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_len32(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}
