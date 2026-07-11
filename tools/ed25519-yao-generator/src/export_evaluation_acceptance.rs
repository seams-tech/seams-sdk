//! Construction-independent authenticated A/B export authorization acceptance.
//!
//! The host model requires two role-pinned Ed25519 signatures over the same
//! export request, provenance pair, authenticated store resolution, and one-use
//! execution before evaluation. Trusted authority distribution, durable replay,
//! transport, and selected-profile protocol security remain later-phase work.

use core::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::authenticated_store::{
    AuthenticatedRegisteredStoreResolutionV1, AuthenticatedStoreErrorV1,
};
use crate::ceremony_context::{
    CeremonyContextErrorV1, CeremonyDeriverAKeyEpochV1, CeremonyDeriverBKeyEpochV1,
    CeremonyRequestKindV1,
};
use crate::lifecycle_domain::ExportRequestV1;
use crate::provenance::{ProvenanceEncodingErrorV1, RoleInputProvenancePairV1};
use crate::semantic_artifacts::{
    OneUseExecutionId32V1, OpaqueHostReferenceEvaluationEvidenceDigest32V1, SemanticArtifactErrorV1,
};

/// Canonical role-acceptance statement encoding domain.
pub const EXPORT_AUTHORIZATION_ACCEPTANCE_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/export-authorization-acceptance/v1";
/// Domain for one signed role-acceptance artifact digest.
pub const EXPORT_AUTHORIZATION_ACCEPTANCE_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/export-authorization-acceptance-digest/v1";
/// Domain for a pinned role authority-key digest.
pub const EXPORT_AUTHORIZATION_ACCEPTANCE_AUTHORITY_KEY_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/export-authorization-authority-key-digest/v1";
/// Canonical ordered A-then-B acceptance-pair encoding domain.
pub const EXPORT_AUTHORIZATION_ACCEPTANCE_PAIR_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/export-authorization-acceptance-pair/v1";
/// Domain for the ordered A/B acceptance-pair digest.
pub const EXPORT_AUTHORIZATION_ACCEPTANCE_PAIR_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/export-authorization-acceptance-pair-digest/v1";

const DERIVER_A_ROLE_TAG_V1: u8 = 0x01;
const DERIVER_B_ROLE_TAG_V1: u8 = 0x02;
const ACCEPTED_DECISION_TAG_V1: u8 = 0x01;

#[derive(Clone, Copy)]
struct ExportAuthorizationAcceptanceAuthorityCoreV1 {
    role_tag: u8,
    key_epoch: u64,
    verifying_key: VerifyingKey,
    key_digest: [u8; 32],
}

impl ExportAuthorizationAcceptanceAuthorityCoreV1 {
    fn parse(
        role_tag: u8,
        key_epoch: u64,
        verifying_key_bytes: [u8; 32],
    ) -> Result<Self, ExportAuthorizationAcceptanceErrorV1> {
        let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
            .map_err(|_| ExportAuthorizationAcceptanceErrorV1::InvalidAuthorityVerifyingKey)?;
        if verifying_key.is_weak() {
            return Err(ExportAuthorizationAcceptanceErrorV1::WeakAuthorityVerifyingKey);
        }
        let mut digest_input = Vec::new();
        push_lp32(
            &mut digest_input,
            EXPORT_AUTHORIZATION_ACCEPTANCE_AUTHORITY_KEY_DIGEST_DOMAIN_V1,
        )?;
        push_lp32(&mut digest_input, &[role_tag])?;
        push_lp32(&mut digest_input, &key_epoch.to_be_bytes())?;
        push_lp32(&mut digest_input, &verifying_key_bytes)?;
        Ok(Self {
            role_tag,
            key_epoch,
            verifying_key,
            key_digest: Sha256::digest(digest_input).into(),
        })
    }

    fn verify(self, message: &[u8], signature: &[u8; 64]) -> bool {
        self.verifying_key
            .verify_strict(message, &Signature::from_bytes(signature))
            .is_ok()
    }
}

impl fmt::Debug for ExportAuthorizationAcceptanceAuthorityCoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExportAuthorizationAcceptanceAuthorityCoreV1")
            .field("role_tag", &self.role_tag)
            .field("key_epoch", &self.key_epoch)
            .field("key_digest", &"[computed SHA-256]")
            .finish()
    }
}

/// Trusted Deriver A authorization-acceptance verifying authority.
#[derive(Clone, Copy)]
pub struct DeriverAExportAuthorizationAcceptanceAuthorityV1(
    ExportAuthorizationAcceptanceAuthorityCoreV1,
);

impl DeriverAExportAuthorizationAcceptanceAuthorityV1 {
    /// Parses a non-weak Deriver A authority at the given request key epoch.
    pub fn parse(
        key_epoch: CeremonyDeriverAKeyEpochV1,
        verifying_key_bytes: [u8; 32],
    ) -> Result<Self, ExportAuthorizationAcceptanceErrorV1> {
        ExportAuthorizationAcceptanceAuthorityCoreV1::parse(
            DERIVER_A_ROLE_TAG_V1,
            key_epoch.value(),
            verifying_key_bytes,
        )
        .map(Self)
    }

    /// Returns the authority key epoch.
    pub const fn key_epoch(self) -> u64 {
        self.0.key_epoch
    }

    /// Returns the role-separated authority key digest.
    pub const fn key_digest(self) -> [u8; 32] {
        self.0.key_digest
    }

    /// Returns the exact verifying-key bytes.
    pub fn verifying_key_bytes(self) -> [u8; 32] {
        self.0.verifying_key.to_bytes()
    }
}

impl fmt::Debug for DeriverAExportAuthorizationAcceptanceAuthorityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Trusted Deriver B authorization-acceptance verifying authority.
#[derive(Clone, Copy)]
pub struct DeriverBExportAuthorizationAcceptanceAuthorityV1(
    ExportAuthorizationAcceptanceAuthorityCoreV1,
);

impl DeriverBExportAuthorizationAcceptanceAuthorityV1 {
    /// Parses a non-weak Deriver B authority at the given request key epoch.
    pub fn parse(
        key_epoch: CeremonyDeriverBKeyEpochV1,
        verifying_key_bytes: [u8; 32],
    ) -> Result<Self, ExportAuthorizationAcceptanceErrorV1> {
        ExportAuthorizationAcceptanceAuthorityCoreV1::parse(
            DERIVER_B_ROLE_TAG_V1,
            key_epoch.value(),
            verifying_key_bytes,
        )
        .map(Self)
    }

    /// Returns the authority key epoch.
    pub const fn key_epoch(self) -> u64 {
        self.0.key_epoch
    }

    /// Returns the role-separated authority key digest.
    pub const fn key_digest(self) -> [u8; 32] {
        self.0.key_digest
    }

    /// Returns the exact verifying-key bytes.
    pub fn verifying_key_bytes(self) -> [u8; 32] {
        self.0.verifying_key.to_bytes()
    }
}

impl fmt::Debug for DeriverBExportAuthorizationAcceptanceAuthorityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Trusted, role-distinct A/B authority pair supplied by the host boundary.
#[derive(Debug, Clone, Copy)]
pub struct ExportAuthorizationAcceptanceAuthoritiesV1 {
    deriver_a: DeriverAExportAuthorizationAcceptanceAuthorityV1,
    deriver_b: DeriverBExportAuthorizationAcceptanceAuthorityV1,
}

impl ExportAuthorizationAcceptanceAuthoritiesV1 {
    /// Rejects reuse of one verifying key across both operational roles.
    pub fn new(
        deriver_a: DeriverAExportAuthorizationAcceptanceAuthorityV1,
        deriver_b: DeriverBExportAuthorizationAcceptanceAuthorityV1,
    ) -> Result<Self, ExportAuthorizationAcceptanceErrorV1> {
        if deriver_a.0.verifying_key.to_bytes() == deriver_b.0.verifying_key.to_bytes() {
            return Err(ExportAuthorizationAcceptanceErrorV1::SharedRoleAuthorityKey);
        }
        Ok(Self {
            deriver_a,
            deriver_b,
        })
    }

    /// Returns the pinned Deriver A authority.
    pub const fn deriver_a(self) -> DeriverAExportAuthorizationAcceptanceAuthorityV1 {
        self.deriver_a
    }

    /// Returns the pinned Deriver B authority.
    pub const fn deriver_b(self) -> DeriverBExportAuthorizationAcceptanceAuthorityV1 {
        self.deriver_b
    }
}

/// Admission time used to reject an expired export authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportAuthorizationCheckedAtUnixMsV1(u64);

impl ExportAuthorizationCheckedAtUnixMsV1 {
    /// Validates a nonzero public admission timestamp.
    pub const fn new(value: u64) -> Result<Self, ExportAuthorizationAcceptanceErrorV1> {
        if value == 0 {
            return Err(ExportAuthorizationAcceptanceErrorV1::ZeroCheckedAtTime);
        }
        Ok(Self(value))
    }

    /// Returns the Unix timestamp in milliseconds.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Raw Deriver A acceptance signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DeriverAExportAuthorizationAcceptanceSignature64V1([u8; 64]);

impl DeriverAExportAuthorizationAcceptanceSignature64V1 {
    /// Wraps exact signature bytes.
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Returns exact signature bytes.
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for DeriverAExportAuthorizationAcceptanceSignature64V1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeriverAExportAuthorizationAcceptanceSignature64V1([signature])")
    }
}

/// Raw Deriver B acceptance signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DeriverBExportAuthorizationAcceptanceSignature64V1([u8; 64]);

impl DeriverBExportAuthorizationAcceptanceSignature64V1 {
    /// Wraps exact signature bytes.
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Returns exact signature bytes.
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for DeriverBExportAuthorizationAcceptanceSignature64V1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeriverBExportAuthorizationAcceptanceSignature64V1([signature])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExportAuthorizationAcceptanceCommonV1 {
    request_id: String,
    replay_nonce: [u8; 32],
    request_expiry: u64,
    client_recipient_key: [u8; 32],
    request_context_digest: [u8; 32],
    authorization_digest: [u8; 32],
    transcript_digest: [u8; 32],
    provenance_pair_digest: [u8; 32],
    signed_store_resolution_digest: [u8; 32],
    store_authority_key_epoch: u64,
    store_authority_key_digest: [u8; 32],
    active_state_version: u64,
    registered_public_key: [u8; 32],
    one_use_execution_id: [u8; 32],
}

impl ExportAuthorizationAcceptanceCommonV1 {
    fn validate(
        request: &ExportRequestV1,
        state: &AuthenticatedRegisteredStoreResolutionV1,
        provenance: &RoleInputProvenancePairV1,
        one_use_execution_id: OneUseExecutionId32V1,
    ) -> Result<Self, ExportAuthorizationAcceptanceErrorV1> {
        let dag = request.validated_dag();
        if dag.request_kind() != CeremonyRequestKindV1::Export {
            return Err(ExportAuthorizationAcceptanceErrorV1::RequestKindMismatch);
        }
        state.validate_for(request.request_context(), dag, provenance)?;
        if request.authorization().registered_public_key() != state.state().registered_public_key()
        {
            return Err(ExportAuthorizationAcceptanceErrorV1::RegisteredPublicKeyMismatch);
        }
        let authority = state.trusted_transition_authority();
        Ok(Self {
            request_id: request.request_context().request_id().as_str().to_owned(),
            replay_nonce: *request.request_context().replay_nonce().as_bytes(),
            request_expiry: request.request_context().request_expiry().value(),
            client_recipient_key: *request
                .request_context()
                .client_ephemeral_public_key()
                .as_bytes(),
            request_context_digest: *dag.request_context_digest().as_bytes(),
            authorization_digest: *dag.authorization_digest().as_bytes(),
            transcript_digest: *dag.transcript_digest().as_bytes(),
            provenance_pair_digest: *provenance.digest()?.as_bytes(),
            signed_store_resolution_digest: state.signed_resolution_digest()?,
            store_authority_key_epoch: authority.key_epoch().value(),
            store_authority_key_digest: authority.key_digest(),
            active_state_version: state.active_state_version().value(),
            registered_public_key: *state.state().registered_public_key().as_bytes(),
            one_use_execution_id: *one_use_execution_id.as_bytes(),
        })
    }

    fn encode_into(
        &self,
        output: &mut Vec<u8>,
    ) -> Result<(), ExportAuthorizationAcceptanceErrorV1> {
        push_lp32(output, self.request_id.as_bytes())?;
        push_lp32(output, &self.replay_nonce)?;
        push_lp32(output, &self.request_expiry.to_be_bytes())?;
        push_lp32(output, &self.client_recipient_key)?;
        push_lp32(output, &self.request_context_digest)?;
        push_lp32(output, &self.authorization_digest)?;
        push_lp32(output, &self.transcript_digest)?;
        push_lp32(output, &self.provenance_pair_digest)?;
        push_lp32(output, &self.signed_store_resolution_digest)?;
        push_lp32(output, &self.store_authority_key_epoch.to_be_bytes())?;
        push_lp32(output, &self.store_authority_key_digest)?;
        push_lp32(output, &self.active_state_version.to_be_bytes())?;
        push_lp32(output, &self.registered_public_key)?;
        push_lp32(output, &self.one_use_execution_id)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExportAuthorizationAcceptanceRecordV1 {
    role_tag: u8,
    deriver_id: String,
    deriver_key_epoch: u64,
    authority_key_digest: [u8; 32],
    checked_at: u64,
    common: ExportAuthorizationAcceptanceCommonV1,
    role_provenance_statement_digest: [u8; 32],
}

impl ExportAuthorizationAcceptanceRecordV1 {
    fn encode(&self) -> Result<Vec<u8>, ExportAuthorizationAcceptanceErrorV1> {
        let mut output = Vec::new();
        push_lp32(
            &mut output,
            EXPORT_AUTHORIZATION_ACCEPTANCE_ENCODING_DOMAIN_V1,
        )?;
        push_lp32(&mut output, ed25519_yao::PROTOCOL_ID_STR.as_bytes())?;
        push_lp32(&mut output, &[CeremonyRequestKindV1::Export.tag()])?;
        push_lp32(&mut output, &[self.role_tag])?;
        push_lp32(&mut output, self.deriver_id.as_bytes())?;
        push_lp32(&mut output, &self.deriver_key_epoch.to_be_bytes())?;
        push_lp32(&mut output, &self.authority_key_digest)?;
        push_lp32(&mut output, &self.checked_at.to_be_bytes())?;
        self.common.encode_into(&mut output)?;
        push_lp32(&mut output, &self.role_provenance_statement_digest)?;
        push_lp32(&mut output, &[ACCEPTED_DECISION_TAG_V1])?;
        Ok(output)
    }
}

/// Prepared Deriver A acceptance statement bound to its pinned authority.
pub struct PreparedDeriverAExportAuthorizationAcceptanceV1 {
    record: ExportAuthorizationAcceptanceRecordV1,
    authority: DeriverAExportAuthorizationAcceptanceAuthorityV1,
}

impl PreparedDeriverAExportAuthorizationAcceptanceV1 {
    /// Returns the exact statement bytes Deriver A must sign.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ExportAuthorizationAcceptanceErrorV1> {
        self.record.encode()
    }

    /// Strictly verifies Deriver A's signature and produces a move-only capability.
    pub fn verify(
        self,
        signature: DeriverAExportAuthorizationAcceptanceSignature64V1,
    ) -> Result<VerifiedDeriverAExportAuthorizationAcceptanceV1, ExportAuthorizationAcceptanceErrorV1>
    {
        let signing_bytes = self.record.encode()?;
        if !self
            .authority
            .0
            .verify(&signing_bytes, signature.as_bytes())
        {
            return Err(ExportAuthorizationAcceptanceErrorV1::InvalidDeriverASignature);
        }
        Ok(VerifiedDeriverAExportAuthorizationAcceptanceV1 {
            record: self.record,
            signature,
            authority_verifying_key_bytes: self.authority.verifying_key_bytes(),
        })
    }
}

/// Prepared Deriver B acceptance statement bound to its pinned authority.
pub struct PreparedDeriverBExportAuthorizationAcceptanceV1 {
    record: ExportAuthorizationAcceptanceRecordV1,
    authority: DeriverBExportAuthorizationAcceptanceAuthorityV1,
}

impl PreparedDeriverBExportAuthorizationAcceptanceV1 {
    /// Returns the exact statement bytes Deriver B must sign.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ExportAuthorizationAcceptanceErrorV1> {
        self.record.encode()
    }

    /// Strictly verifies Deriver B's signature and produces a move-only capability.
    pub fn verify(
        self,
        signature: DeriverBExportAuthorizationAcceptanceSignature64V1,
    ) -> Result<VerifiedDeriverBExportAuthorizationAcceptanceV1, ExportAuthorizationAcceptanceErrorV1>
    {
        let signing_bytes = self.record.encode()?;
        if !self
            .authority
            .0
            .verify(&signing_bytes, signature.as_bytes())
        {
            return Err(ExportAuthorizationAcceptanceErrorV1::InvalidDeriverBSignature);
        }
        Ok(VerifiedDeriverBExportAuthorizationAcceptanceV1 {
            record: self.record,
            signature,
            authority_verifying_key_bytes: self.authority.verifying_key_bytes(),
        })
    }
}

/// Strictly verified Deriver A acceptance capability.
pub struct VerifiedDeriverAExportAuthorizationAcceptanceV1 {
    record: ExportAuthorizationAcceptanceRecordV1,
    signature: DeriverAExportAuthorizationAcceptanceSignature64V1,
    authority_verifying_key_bytes: [u8; 32],
}

impl VerifiedDeriverAExportAuthorizationAcceptanceV1 {
    /// Returns the exact signed statement bytes.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ExportAuthorizationAcceptanceErrorV1> {
        self.record.encode()
    }

    /// Returns the canonical signed-artifact digest.
    pub fn digest(&self) -> Result<[u8; 32], ExportAuthorizationAcceptanceErrorV1> {
        signed_acceptance_digest(&self.record, self.signature.as_bytes())
    }

    /// Returns the exact verified signature bytes.
    pub const fn signature_bytes(&self) -> &[u8; 64] {
        self.signature.as_bytes()
    }

    /// Returns the pinned authority-key digest.
    pub const fn authority_key_digest(&self) -> &[u8; 32] {
        &self.record.authority_key_digest
    }

    /// Returns the role-specific provenance-statement digest.
    pub const fn provenance_statement_digest(&self) -> &[u8; 32] {
        &self.record.role_provenance_statement_digest
    }

    /// Returns the admission timestamp.
    pub const fn checked_at(&self) -> u64 {
        self.record.checked_at
    }
}

/// Strictly verified Deriver B acceptance capability.
pub struct VerifiedDeriverBExportAuthorizationAcceptanceV1 {
    record: ExportAuthorizationAcceptanceRecordV1,
    signature: DeriverBExportAuthorizationAcceptanceSignature64V1,
    authority_verifying_key_bytes: [u8; 32],
}

impl VerifiedDeriverBExportAuthorizationAcceptanceV1 {
    /// Returns the exact signed statement bytes.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ExportAuthorizationAcceptanceErrorV1> {
        self.record.encode()
    }

    /// Returns the canonical signed-artifact digest.
    pub fn digest(&self) -> Result<[u8; 32], ExportAuthorizationAcceptanceErrorV1> {
        signed_acceptance_digest(&self.record, self.signature.as_bytes())
    }

    /// Returns the exact verified signature bytes.
    pub const fn signature_bytes(&self) -> &[u8; 64] {
        self.signature.as_bytes()
    }

    /// Returns the pinned authority-key digest.
    pub const fn authority_key_digest(&self) -> &[u8; 32] {
        &self.record.authority_key_digest
    }

    /// Returns the role-specific provenance-statement digest.
    pub const fn provenance_statement_digest(&self) -> &[u8; 32] {
        &self.record.role_provenance_statement_digest
    }

    /// Returns the admission timestamp.
    pub const fn checked_at(&self) -> u64 {
        self.record.checked_at
    }
}

/// Ordered, coherent verified A/B pair required by the export evaluator.
///
/// The pair is move-only and is consumed when an export session is admitted.
///
/// ```compile_fail
/// use ed25519_yao_generator::VerifiedExportAuthorizationAcceptancePairV1;
///
/// fn cannot_consume_twice(pair: VerifiedExportAuthorizationAcceptancePairV1) {
///     drop(pair);
///     drop(pair);
/// }
/// ```
pub struct VerifiedExportAuthorizationAcceptancePairV1 {
    deriver_a: VerifiedDeriverAExportAuthorizationAcceptanceV1,
    deriver_b: VerifiedDeriverBExportAuthorizationAcceptanceV1,
    encoding: Vec<u8>,
    digest: [u8; 32],
    evaluation_evidence_digest: OpaqueHostReferenceEvaluationEvidenceDigest32V1,
}

impl VerifiedExportAuthorizationAcceptancePairV1 {
    /// Pairs exactly one verified A capability with one verified B capability.
    pub fn new(
        deriver_a: VerifiedDeriverAExportAuthorizationAcceptanceV1,
        deriver_b: VerifiedDeriverBExportAuthorizationAcceptanceV1,
    ) -> Result<Self, ExportAuthorizationAcceptanceErrorV1> {
        if deriver_a.record.common != deriver_b.record.common {
            return Err(ExportAuthorizationAcceptanceErrorV1::AcceptanceBindingMismatch);
        }
        if deriver_a.authority_verifying_key_bytes == deriver_b.authority_verifying_key_bytes {
            return Err(ExportAuthorizationAcceptanceErrorV1::SharedRoleAuthorityKey);
        }
        let mut encoding = Vec::new();
        push_lp32(
            &mut encoding,
            EXPORT_AUTHORIZATION_ACCEPTANCE_PAIR_ENCODING_DOMAIN_V1,
        )?;
        push_lp32(&mut encoding, &deriver_a.digest()?)?;
        push_lp32(&mut encoding, &deriver_b.digest()?)?;
        let mut digest_input = Vec::new();
        push_lp32(
            &mut digest_input,
            EXPORT_AUTHORIZATION_ACCEPTANCE_PAIR_DIGEST_DOMAIN_V1,
        )?;
        push_lp32(&mut digest_input, &encoding)?;
        let digest = Sha256::digest(digest_input).into();
        let evaluation_evidence_digest =
            OpaqueHostReferenceEvaluationEvidenceDigest32V1::new(digest)?;
        Ok(Self {
            deriver_a,
            deriver_b,
            encoding,
            digest,
            evaluation_evidence_digest,
        })
    }

    /// Returns Deriver A's verified acceptance.
    pub const fn deriver_a(&self) -> &VerifiedDeriverAExportAuthorizationAcceptanceV1 {
        &self.deriver_a
    }

    /// Returns Deriver B's verified acceptance.
    pub const fn deriver_b(&self) -> &VerifiedDeriverBExportAuthorizationAcceptanceV1 {
        &self.deriver_b
    }

    /// Returns the canonical ordered A-then-B pair bytes.
    pub fn encode(&self) -> &[u8] {
        &self.encoding
    }

    /// Returns the digest of the canonical pair bytes.
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(crate) fn validate_for(
        &self,
        request: &ExportRequestV1,
        state: &AuthenticatedRegisteredStoreResolutionV1,
        provenance: &RoleInputProvenancePairV1,
        one_use_execution_id: OneUseExecutionId32V1,
        authorities: ExportAuthorizationAcceptanceAuthoritiesV1,
    ) -> Result<(), ExportAuthorizationAcceptanceErrorV1> {
        let expected = ExportAuthorizationAcceptanceCommonV1::validate(
            request,
            state,
            provenance,
            one_use_execution_id,
        )?;
        if self.deriver_a.record.common != expected || self.deriver_b.record.common != expected {
            return Err(ExportAuthorizationAcceptanceErrorV1::AcceptanceBindingMismatch);
        }
        if self.deriver_a.record.authority_key_digest != authorities.deriver_a.key_digest()
            || self.deriver_b.record.authority_key_digest != authorities.deriver_b.key_digest()
        {
            return Err(ExportAuthorizationAcceptanceErrorV1::AuthoritySubstitution);
        }
        Ok(())
    }

    pub(crate) const fn evaluation_evidence_digest(
        &self,
    ) -> OpaqueHostReferenceEvaluationEvidenceDigest32V1 {
        self.evaluation_evidence_digest
    }
}

/// Prepares Deriver A's statement from sealed request/state/provenance owners.
pub fn prepare_deriver_a_export_authorization_acceptance_v1(
    request: &ExportRequestV1,
    state: &AuthenticatedRegisteredStoreResolutionV1,
    provenance: &RoleInputProvenancePairV1,
    one_use_execution_id: OneUseExecutionId32V1,
    checked_at: ExportAuthorizationCheckedAtUnixMsV1,
    authority: DeriverAExportAuthorizationAcceptanceAuthorityV1,
) -> Result<PreparedDeriverAExportAuthorizationAcceptanceV1, ExportAuthorizationAcceptanceErrorV1> {
    let binding = request.request_context().deriver_a_binding();
    if authority.key_epoch() != binding.key_epoch().value() {
        return Err(ExportAuthorizationAcceptanceErrorV1::AuthorityKeyEpochMismatch);
    }
    validate_checked_at(request, checked_at)?;
    let common = ExportAuthorizationAcceptanceCommonV1::validate(
        request,
        state,
        provenance,
        one_use_execution_id,
    )?;
    Ok(PreparedDeriverAExportAuthorizationAcceptanceV1 {
        record: ExportAuthorizationAcceptanceRecordV1 {
            role_tag: DERIVER_A_ROLE_TAG_V1,
            deriver_id: binding.id().as_str().to_owned(),
            deriver_key_epoch: binding.key_epoch().value(),
            authority_key_digest: authority.key_digest(),
            checked_at: checked_at.value(),
            common,
            role_provenance_statement_digest: *provenance.deriver_a().digest()?.as_bytes(),
        },
        authority,
    })
}

/// Prepares Deriver B's statement from sealed request/state/provenance owners.
pub fn prepare_deriver_b_export_authorization_acceptance_v1(
    request: &ExportRequestV1,
    state: &AuthenticatedRegisteredStoreResolutionV1,
    provenance: &RoleInputProvenancePairV1,
    one_use_execution_id: OneUseExecutionId32V1,
    checked_at: ExportAuthorizationCheckedAtUnixMsV1,
    authority: DeriverBExportAuthorizationAcceptanceAuthorityV1,
) -> Result<PreparedDeriverBExportAuthorizationAcceptanceV1, ExportAuthorizationAcceptanceErrorV1> {
    let binding = request.request_context().deriver_b_binding();
    if authority.key_epoch() != binding.key_epoch().value() {
        return Err(ExportAuthorizationAcceptanceErrorV1::AuthorityKeyEpochMismatch);
    }
    validate_checked_at(request, checked_at)?;
    let common = ExportAuthorizationAcceptanceCommonV1::validate(
        request,
        state,
        provenance,
        one_use_execution_id,
    )?;
    Ok(PreparedDeriverBExportAuthorizationAcceptanceV1 {
        record: ExportAuthorizationAcceptanceRecordV1 {
            role_tag: DERIVER_B_ROLE_TAG_V1,
            deriver_id: binding.id().as_str().to_owned(),
            deriver_key_epoch: binding.key_epoch().value(),
            authority_key_digest: authority.key_digest(),
            checked_at: checked_at.value(),
            common,
            role_provenance_statement_digest: *provenance.deriver_b().digest()?.as_bytes(),
        },
        authority,
    })
}

/// Failure while constructing, authenticating, or consuming export acceptance.
#[derive(Debug)]
pub enum ExportAuthorizationAcceptanceErrorV1 {
    /// An authority verifying key was not a valid compressed Edwards point.
    InvalidAuthorityVerifyingKey,
    /// Authority verifying keys must not be weak Edwards points.
    WeakAuthorityVerifyingKey,
    /// A and B must use distinct authority keys.
    SharedRoleAuthorityKey,
    /// Admission timestamps must be nonzero.
    ZeroCheckedAtTime,
    /// The request was not an export request.
    RequestKindMismatch,
    /// Admission occurred after request expiry.
    AuthorizationExpired,
    /// A role authority epoch differed from the request binding.
    AuthorityKeyEpochMismatch,
    /// The authorization and authenticated state named different registered keys.
    RegisteredPublicKeyMismatch,
    /// Deriver A's acceptance signature was invalid.
    InvalidDeriverASignature,
    /// Deriver B's acceptance signature was invalid.
    InvalidDeriverBSignature,
    /// The two role acceptances or consuming evaluator named different bindings.
    AcceptanceBindingMismatch,
    /// Verified acceptances did not use the evaluator's trusted authority pair.
    AuthoritySubstitution,
    /// Canonical ceremony encoding failed.
    Ceremony(CeremonyContextErrorV1),
    /// Canonical provenance encoding failed.
    Provenance(ProvenanceEncodingErrorV1),
    /// Authenticated store validation failed.
    Store(AuthenticatedStoreErrorV1),
    /// Semantic evidence construction failed.
    Semantic(SemanticArtifactErrorV1),
    /// A canonical field exceeded the LP32 length range.
    ValueTooLong,
}

impl fmt::Display for ExportAuthorizationAcceptanceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidAuthorityVerifyingKey => "export authority verifying key is invalid",
            Self::WeakAuthorityVerifyingKey => "export authority verifying key must not be weak",
            Self::SharedRoleAuthorityKey => "A and B export authorities must be distinct",
            Self::ZeroCheckedAtTime => "export authorization admission time must be nonzero",
            Self::RequestKindMismatch => "export acceptance requires an export request",
            Self::AuthorizationExpired => "export authorization expired before acceptance",
            Self::AuthorityKeyEpochMismatch => {
                "export acceptance authority epoch differs from the request"
            }
            Self::RegisteredPublicKeyMismatch => {
                "export authorization and authenticated state must name the same key"
            }
            Self::InvalidDeriverASignature => "Deriver A export acceptance signature is invalid",
            Self::InvalidDeriverBSignature => "Deriver B export acceptance signature is invalid",
            Self::AcceptanceBindingMismatch => {
                "A/B export acceptances must bind the same exact evaluation"
            }
            Self::AuthoritySubstitution => {
                "export acceptances do not match the evaluator's trusted authorities"
            }
            Self::Ceremony(_) => "canonical ceremony encoding failed",
            Self::Provenance(_) => "canonical provenance encoding failed",
            Self::Store(_) => "authenticated store validation failed",
            Self::Semantic(_) => "semantic evaluation evidence construction failed",
            Self::ValueTooLong => "export acceptance LP32 value exceeds U32 length",
        })
    }
}

impl std::error::Error for ExportAuthorizationAcceptanceErrorV1 {}

impl From<CeremonyContextErrorV1> for ExportAuthorizationAcceptanceErrorV1 {
    fn from(error: CeremonyContextErrorV1) -> Self {
        Self::Ceremony(error)
    }
}

impl From<ProvenanceEncodingErrorV1> for ExportAuthorizationAcceptanceErrorV1 {
    fn from(error: ProvenanceEncodingErrorV1) -> Self {
        Self::Provenance(error)
    }
}

impl From<AuthenticatedStoreErrorV1> for ExportAuthorizationAcceptanceErrorV1 {
    fn from(error: AuthenticatedStoreErrorV1) -> Self {
        Self::Store(error)
    }
}

impl From<SemanticArtifactErrorV1> for ExportAuthorizationAcceptanceErrorV1 {
    fn from(error: SemanticArtifactErrorV1) -> Self {
        Self::Semantic(error)
    }
}

fn validate_checked_at(
    request: &ExportRequestV1,
    checked_at: ExportAuthorizationCheckedAtUnixMsV1,
) -> Result<(), ExportAuthorizationAcceptanceErrorV1> {
    if checked_at.value() > request.request_context().request_expiry().value() {
        return Err(ExportAuthorizationAcceptanceErrorV1::AuthorizationExpired);
    }
    Ok(())
}

fn signed_acceptance_digest(
    record: &ExportAuthorizationAcceptanceRecordV1,
    signature: &[u8; 64],
) -> Result<[u8; 32], ExportAuthorizationAcceptanceErrorV1> {
    let mut digest_input = Vec::new();
    push_lp32(
        &mut digest_input,
        EXPORT_AUTHORIZATION_ACCEPTANCE_DIGEST_DOMAIN_V1,
    )?;
    push_lp32(&mut digest_input, &record.encode()?)?;
    push_lp32(&mut digest_input, signature)?;
    Ok(Sha256::digest(digest_input).into())
}

fn push_lp32(
    output: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), ExportAuthorizationAcceptanceErrorV1> {
    let length = u32::try_from(value.len())
        .map_err(|_| ExportAuthorizationAcceptanceErrorV1::ValueTooLong)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::ceremony_fixtures::canonical_export_ceremony_fixture_for_registered_key_v1;
    use crate::export_delivery::HostOnlyExportClientReleaseEvidenceV1;
    use crate::lifecycle_domain::{
        ArtifactSessionErrorV1, ExportArtifactIssuanceV1, ExportOutputCommitmentEvidenceV1,
    };
    use crate::provenance_fixtures::canonical_provenance_fixture_pair_for_registered_key_v1;
    use crate::semantic_artifacts::{
        OpaqueHostReferenceClientDeliveryEvidenceDigest32V1,
        OpaqueHostReferenceConsumedExportAuthorizationDigest32V1,
        OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
        OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
    };
    use crate::semantic_fixture_material::{
        export_bindings, export_ideal_coin, export_inputs, reference_fixture,
    };
    use crate::semantic_lifecycle_fixtures::authenticated_state_from_provenance;

    const A_SEED: [u8; 32] = [0x31; 32];
    const B_SEED: [u8; 32] = [0x32; 32];

    struct Fixture {
        request: ExportRequestV1,
        provenance: RoleInputProvenancePairV1,
        state: AuthenticatedRegisteredStoreResolutionV1,
        execution_id: OneUseExecutionId32V1,
        authorities: ExportAuthorizationAcceptanceAuthoritiesV1,
    }

    fn fixture() -> Fixture {
        let material = reference_fixture();
        let (context, authorization, transcript) =
            canonical_export_ceremony_fixture_for_registered_key_v1(material.registered_public_key);
        let request = ExportRequestV1::new(context, authorization, transcript)
            .expect("canonical export request");
        let provenance = canonical_provenance_fixture_pair_for_registered_key_v1(
            CeremonyRequestKindV1::Export,
            material.registered_public_key,
        );
        let state = authenticated_state_from_provenance(
            request.request_context(),
            request.validated_dag(),
            &provenance,
            provenance
                .export_registered_state_binding()
                .expect("export state binding"),
            11,
            11,
        );
        let a = SigningKey::from_bytes(&A_SEED);
        let b = SigningKey::from_bytes(&B_SEED);
        let authorities = ExportAuthorizationAcceptanceAuthoritiesV1::new(
            DeriverAExportAuthorizationAcceptanceAuthorityV1::parse(
                request.request_context().deriver_a_binding().key_epoch(),
                a.verifying_key().to_bytes(),
            )
            .expect("A authority"),
            DeriverBExportAuthorizationAcceptanceAuthorityV1::parse(
                request.request_context().deriver_b_binding().key_epoch(),
                b.verifying_key().to_bytes(),
            )
            .expect("B authority"),
        )
        .expect("distinct authorities");
        Fixture {
            request,
            provenance,
            state,
            execution_id: OneUseExecutionId32V1::new([0x44; 32]).expect("execution id"),
            authorities,
        }
    }

    fn verified_pair(fixture: &Fixture) -> VerifiedExportAuthorizationAcceptancePairV1 {
        verified_pair_with(
            fixture,
            fixture.authorities,
            SigningKey::from_bytes(&A_SEED),
            SigningKey::from_bytes(&B_SEED),
            fixture.execution_id,
        )
    }

    fn verified_pair_with(
        fixture: &Fixture,
        authorities: ExportAuthorizationAcceptanceAuthoritiesV1,
        signing_key_a: SigningKey,
        signing_key_b: SigningKey,
        execution_id: OneUseExecutionId32V1,
    ) -> VerifiedExportAuthorizationAcceptancePairV1 {
        let checked_at = ExportAuthorizationCheckedAtUnixMsV1::new(1).expect("checked at");
        let prepared_a = prepare_deriver_a_export_authorization_acceptance_v1(
            &fixture.request,
            &fixture.state,
            &fixture.provenance,
            execution_id,
            checked_at,
            authorities.deriver_a(),
        )
        .expect("prepare A");
        let prepared_b = prepare_deriver_b_export_authorization_acceptance_v1(
            &fixture.request,
            &fixture.state,
            &fixture.provenance,
            execution_id,
            checked_at,
            authorities.deriver_b(),
        )
        .expect("prepare B");
        let signature_a = DeriverAExportAuthorizationAcceptanceSignature64V1::from_bytes(
            signing_key_a
                .sign(&prepared_a.signing_bytes().expect("A bytes"))
                .to_bytes(),
        );
        let signature_b = DeriverBExportAuthorizationAcceptanceSignature64V1::from_bytes(
            signing_key_b
                .sign(&prepared_b.signing_bytes().expect("B bytes"))
                .to_bytes(),
        );
        VerifiedExportAuthorizationAcceptancePairV1::new(
            prepared_a.verify(signature_a).expect("verify A"),
            prepared_b.verify(signature_b).expect("verify B"),
        )
        .expect("acceptance pair")
    }

    #[test]
    fn verified_pair_is_required_and_retained_through_release() {
        let fixture = fixture();
        let acceptance_pair = verified_pair(&fixture);
        let expected_pair_digest = *acceptance_pair.digest();
        let material = reference_fixture();
        let session = fixture
            .request
            .begin_host_reference_artifact_session(
                ExportArtifactIssuanceV1::new(
                    fixture.state,
                    fixture.execution_id,
                    fixture.authorities,
                ),
                &fixture.provenance,
                acceptance_pair,
            )
            .expect("accepted export session");
        let committed = session
            .evaluate_and_commit_host_reference(
                export_inputs(&material),
                export_ideal_coin(),
                export_bindings(),
                ExportOutputCommitmentEvidenceV1::new(
                    OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1::new([0xa1; 32])
                        .expect("A receipt"),
                    OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1::new([0xb1; 32])
                        .expect("B receipt"),
                ),
            )
            .expect("export commitment");
        assert_eq!(
            committed
                .artifacts()
                .receipt()
                .evaluation_evidence_digest()
                .as_bytes(),
            &expected_pair_digest
        );
        let release = HostOnlyExportClientReleaseEvidenceV1::for_output_committed(
            &committed,
            OpaqueHostReferenceClientDeliveryEvidenceDigest32V1::new([0xc1; 32])
                .expect("delivery evidence"),
            OpaqueHostReferenceConsumedExportAuthorizationDigest32V1::new([0xd1; 32])
                .expect("consumed authorization"),
        );
        let released = committed.release_v1(release).expect("released export");
        assert_eq!(
            released
                .artifacts()
                .receipt()
                .evaluation_evidence_digest()
                .as_bytes(),
            &expected_pair_digest
        );
    }

    #[test]
    fn expired_authorization_is_rejected_before_signing() {
        let fixture = fixture();
        let expired = ExportAuthorizationCheckedAtUnixMsV1::new(
            fixture.request.request_context().request_expiry().value() + 1,
        )
        .expect("nonzero timestamp");
        assert!(matches!(
            prepare_deriver_a_export_authorization_acceptance_v1(
                &fixture.request,
                &fixture.state,
                &fixture.provenance,
                fixture.execution_id,
                expired,
                fixture.authorities.deriver_a(),
            ),
            Err(ExportAuthorizationAcceptanceErrorV1::AuthorizationExpired)
        ));
    }

    #[test]
    fn wrong_a_signature_is_rejected_by_pinned_authority() {
        let fixture = fixture();
        let checked_at = ExportAuthorizationCheckedAtUnixMsV1::new(1).expect("checked at");
        let prepared = prepare_deriver_a_export_authorization_acceptance_v1(
            &fixture.request,
            &fixture.state,
            &fixture.provenance,
            fixture.execution_id,
            checked_at,
            fixture.authorities.deriver_a(),
        )
        .expect("prepared A");
        let attacker = SigningKey::from_bytes(&[0x99; 32]);
        let signature = DeriverAExportAuthorizationAcceptanceSignature64V1::from_bytes(
            attacker
                .sign(&prepared.signing_bytes().expect("signing bytes"))
                .to_bytes(),
        );
        assert!(matches!(
            prepared.verify(signature),
            Err(ExportAuthorizationAcceptanceErrorV1::InvalidDeriverASignature)
        ));
    }

    #[test]
    fn same_authority_key_cannot_serve_both_roles() {
        let fixture = fixture();
        let signing_key = SigningKey::from_bytes(&A_SEED);
        let a = DeriverAExportAuthorizationAcceptanceAuthorityV1::parse(
            fixture
                .request
                .request_context()
                .deriver_a_binding()
                .key_epoch(),
            signing_key.verifying_key().to_bytes(),
        )
        .expect("A authority");
        let b = DeriverBExportAuthorizationAcceptanceAuthorityV1::parse(
            fixture
                .request
                .request_context()
                .deriver_b_binding()
                .key_epoch(),
            signing_key.verifying_key().to_bytes(),
        )
        .expect("B authority");
        assert!(matches!(
            ExportAuthorizationAcceptanceAuthoritiesV1::new(a, b),
            Err(ExportAuthorizationAcceptanceErrorV1::SharedRoleAuthorityKey)
        ));
        let checked_at = ExportAuthorizationCheckedAtUnixMsV1::new(1).expect("checked at");
        let prepared_a = prepare_deriver_a_export_authorization_acceptance_v1(
            &fixture.request,
            &fixture.state,
            &fixture.provenance,
            fixture.execution_id,
            checked_at,
            a,
        )
        .expect("prepared A");
        let prepared_b = prepare_deriver_b_export_authorization_acceptance_v1(
            &fixture.request,
            &fixture.state,
            &fixture.provenance,
            fixture.execution_id,
            checked_at,
            b,
        )
        .expect("prepared B");
        let signature_a = DeriverAExportAuthorizationAcceptanceSignature64V1::from_bytes(
            signing_key
                .sign(&prepared_a.signing_bytes().expect("A bytes"))
                .to_bytes(),
        );
        let signature_b = DeriverBExportAuthorizationAcceptanceSignature64V1::from_bytes(
            signing_key
                .sign(&prepared_b.signing_bytes().expect("B bytes"))
                .to_bytes(),
        );
        assert!(matches!(
            VerifiedExportAuthorizationAcceptancePairV1::new(
                prepared_a.verify(signature_a).expect("verified A"),
                prepared_b.verify(signature_b).expect("verified B"),
            ),
            Err(ExportAuthorizationAcceptanceErrorV1::SharedRoleAuthorityKey)
        ));
    }

    #[test]
    fn coherent_attacker_authority_substitution_is_rejected_by_issuance() {
        let fixture = fixture();
        let attacker_a = SigningKey::from_bytes(&[0x71; 32]);
        let attacker_b = SigningKey::from_bytes(&[0x72; 32]);
        let attacker_authorities = ExportAuthorizationAcceptanceAuthoritiesV1::new(
            DeriverAExportAuthorizationAcceptanceAuthorityV1::parse(
                fixture
                    .request
                    .request_context()
                    .deriver_a_binding()
                    .key_epoch(),
                attacker_a.verifying_key().to_bytes(),
            )
            .expect("attacker A authority"),
            DeriverBExportAuthorizationAcceptanceAuthorityV1::parse(
                fixture
                    .request
                    .request_context()
                    .deriver_b_binding()
                    .key_epoch(),
                attacker_b.verifying_key().to_bytes(),
            )
            .expect("attacker B authority"),
        )
        .expect("distinct attacker authorities");
        let attacker_pair = verified_pair_with(
            &fixture,
            attacker_authorities,
            attacker_a,
            attacker_b,
            fixture.execution_id,
        );
        let rejection = match fixture.request.begin_host_reference_artifact_session(
            ExportArtifactIssuanceV1::new(fixture.state, fixture.execution_id, fixture.authorities),
            &fixture.provenance,
            attacker_pair,
        ) {
            Ok(_) => panic!("substituted authorities were accepted"),
            Err(rejection) => rejection,
        };
        assert_eq!(
            rejection.reason(),
            ArtifactSessionErrorV1::ExportAuthorizationAcceptanceRejected
        );
    }

    #[test]
    fn acceptance_from_another_execution_is_rejected() {
        let fixture = fixture();
        let alternate_execution = OneUseExecutionId32V1::new([0x45; 32]).expect("execution id");
        let pair = verified_pair_with(
            &fixture,
            fixture.authorities,
            SigningKey::from_bytes(&A_SEED),
            SigningKey::from_bytes(&B_SEED),
            alternate_execution,
        );
        let rejection = match fixture.request.begin_host_reference_artifact_session(
            ExportArtifactIssuanceV1::new(fixture.state, fixture.execution_id, fixture.authorities),
            &fixture.provenance,
            pair,
        ) {
            Ok(_) => panic!("execution splice was accepted"),
            Err(rejection) => rejection,
        };
        assert_eq!(
            rejection.reason(),
            ArtifactSessionErrorV1::ExportAuthorizationAcceptanceRejected
        );
    }

    #[test]
    fn zero_admission_time_is_rejected() {
        assert!(matches!(
            ExportAuthorizationCheckedAtUnixMsV1::new(0),
            Err(ExportAuthorizationAcceptanceErrorV1::ZeroCheckedAtTime)
        ));
    }
}
