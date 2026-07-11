//! Authenticated, request-bound registered-state resolution for host semantics.

use core::fmt;
use core::num::NonZeroU64;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::ceremony_context::{
    CeremonyContextErrorV1, CeremonyDurableStoreIdentityScopeV1, CeremonyPublicRequestContextV1,
    CeremonyRequestKindV1, CeremonyValidatedDagV1,
};
use crate::lifecycle_domain::{
    validate_registered_state_fields, RegisteredLifecyclePreStateV1, RegisteredStateBindingFieldV1,
};
use crate::provenance::{
    ProvenanceEncodingErrorV1, RegisteredStateProvenanceBindingV1,
    RegisteredStateProvenanceErrorV1, RoleInputProvenancePairDigest32V1, RoleInputProvenancePairV1,
};

/// Domain for one signed registered-state resolution.
pub const AUTHENTICATED_STORE_RESOLUTION_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/authenticated-store-resolution/v1";
/// Domain for the authority verifying-key digest.
pub const STORE_AUTHORITY_KEY_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/store-authority-key-digest/v1";

/// Nonzero active registered-state version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ActiveStoreStateVersionV1(NonZeroU64);

impl ActiveStoreStateVersionV1 {
    /// Validates a nonzero active state version.
    pub const fn new(value: u64) -> Result<Self, AuthenticatedStoreErrorV1> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(AuthenticatedStoreErrorV1::ZeroActiveStateVersion),
        }
    }

    /// Returns the numeric state version.
    pub const fn value(self) -> u64 {
        self.0.get()
    }
}

/// Nonzero store-authority signing-key epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StoreAuthorityKeyEpochV1(NonZeroU64);

impl StoreAuthorityKeyEpochV1 {
    /// Validates a nonzero authority key epoch.
    pub const fn new(value: u64) -> Result<Self, AuthenticatedStoreErrorV1> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(AuthenticatedStoreErrorV1::ZeroAuthorityKeyEpoch),
        }
    }

    /// Returns the numeric authority key epoch.
    pub const fn value(self) -> u64 {
        self.0.get()
    }
}

/// Validated non-weak store-authority Ed25519 verifying key.
#[derive(Clone, Copy)]
pub struct StoreAuthorityVerifyingKeyV1 {
    key_epoch: StoreAuthorityKeyEpochV1,
    verifying_key: VerifyingKey,
    key_digest: [u8; 32],
}

impl StoreAuthorityVerifyingKeyV1 {
    /// Parses one authority key and rejects weak Edwards points.
    pub fn parse(
        key_epoch: StoreAuthorityKeyEpochV1,
        bytes: [u8; 32],
    ) -> Result<Self, AuthenticatedStoreErrorV1> {
        let verifying_key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| AuthenticatedStoreErrorV1::InvalidAuthorityVerifyingKey)?;
        if verifying_key.is_weak() {
            return Err(AuthenticatedStoreErrorV1::WeakAuthorityVerifyingKey);
        }
        let mut digest_input = Vec::new();
        push_lp32(&mut digest_input, STORE_AUTHORITY_KEY_DIGEST_DOMAIN_V1)?;
        push_lp32(&mut digest_input, &bytes)?;
        Ok(Self {
            key_epoch,
            verifying_key,
            key_digest: Sha256::digest(digest_input).into(),
        })
    }

    /// Returns the pinned authority key epoch.
    pub const fn key_epoch(self) -> StoreAuthorityKeyEpochV1 {
        self.key_epoch
    }

    /// Returns the domain-separated authority key digest.
    pub const fn key_digest(self) -> [u8; 32] {
        self.key_digest
    }

    /// Returns the exact pinned authority verifying-key bytes.
    pub(crate) fn verifying_key_bytes(self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Strictly verifies a store-authority signature for another sealed store transition.
    pub(crate) fn verify_transition_signature(
        self,
        message: &[u8],
        signature: StoreAuthoritySignature64V1,
    ) -> bool {
        let signature = Signature::from_bytes(signature.as_bytes());
        self.verifying_key
            .verify_strict(message, &signature)
            .is_ok()
    }
}

impl fmt::Debug for StoreAuthorityVerifyingKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoreAuthorityVerifyingKeyV1")
            .field("key_epoch", &self.key_epoch)
            .field("key_digest", &"[computed SHA-256]")
            .finish()
    }
}

/// Raw 64-byte store-authority signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StoreAuthoritySignature64V1([u8; 64]);

impl StoreAuthoritySignature64V1 {
    /// Wraps signature bytes for strict verification.
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Returns the exact signature bytes.
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for StoreAuthoritySignature64V1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StoreAuthoritySignature64V1([signature])")
    }
}

/// Unsigned request-bound store resolution prepared for an external authority signer.
pub struct UnverifiedRegisteredStoreResolutionV1 {
    authority_key_epoch: StoreAuthorityKeyEpochV1,
    authority_key_digest: [u8; 32],
    request_kind: CeremonyRequestKindV1,
    request_context_digest: [u8; 32],
    authorization_digest: [u8; 32],
    transcript_digest: [u8; 32],
    provenance_pair_digest: RoleInputProvenancePairDigest32V1,
    active_state_version: ActiveStoreStateVersionV1,
    durable_identity: CeremonyDurableStoreIdentityScopeV1,
    state: RegisteredLifecyclePreStateV1,
}

impl UnverifiedRegisteredStoreResolutionV1 {
    /// Builds a coherent registered-state resolution for one exact request and provenance pair.
    pub fn new(
        request: &CeremonyPublicRequestContextV1,
        dag: CeremonyValidatedDagV1,
        provenance: &RoleInputProvenancePairV1,
        active_state_version: ActiveStoreStateVersionV1,
        state: RegisteredLifecyclePreStateV1,
        authority: StoreAuthorityVerifyingKeyV1,
    ) -> Result<Self, AuthenticatedStoreErrorV1> {
        validate_request_and_provenance(request, dag, provenance)?;
        let binding = registered_state_binding(dag.request_kind(), provenance)?;
        validate_store_state(&state, binding)?;
        Ok(Self {
            authority_key_epoch: authority.key_epoch(),
            authority_key_digest: authority.key_digest(),
            request_kind: dag.request_kind(),
            request_context_digest: *dag.request_context_digest().as_bytes(),
            authorization_digest: *dag.authorization_digest().as_bytes(),
            transcript_digest: *dag.transcript_digest().as_bytes(),
            provenance_pair_digest: provenance.digest()?,
            active_state_version,
            durable_identity: request.durable_store_identity_scope(),
            state,
        })
    }

    /// Returns the exact bytes the store authority must sign.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, AuthenticatedStoreErrorV1> {
        encode_resolution(self)
    }

    /// Strictly verifies the authority signature and seals the resolution.
    pub fn verify(
        self,
        signature: StoreAuthoritySignature64V1,
        authority: StoreAuthorityVerifyingKeyV1,
    ) -> Result<AuthenticatedRegisteredStoreResolutionV1, AuthenticatedStoreErrorV1> {
        if self.authority_key_epoch != authority.key_epoch() {
            return Err(AuthenticatedStoreErrorV1::AuthorityKeyEpochMismatch);
        }
        if self.authority_key_digest != authority.key_digest() {
            return Err(AuthenticatedStoreErrorV1::AuthorityKeyDigestMismatch);
        }
        let message = self.signing_bytes()?;
        let parsed_signature = Signature::from_bytes(signature.as_bytes());
        authority
            .verifying_key
            .verify_strict(&message, &parsed_signature)
            .map_err(|_| AuthenticatedStoreErrorV1::InvalidAuthoritySignature)?;
        Ok(AuthenticatedRegisteredStoreResolutionV1 {
            inner: self,
            authority,
            signature,
        })
    }
}

/// Move-only authenticated registered state bound to one request and provenance pair.
pub struct AuthenticatedRegisteredStoreResolutionV1 {
    inner: UnverifiedRegisteredStoreResolutionV1,
    authority: StoreAuthorityVerifyingKeyV1,
    signature: StoreAuthoritySignature64V1,
}

impl AuthenticatedRegisteredStoreResolutionV1 {
    /// Revalidates this sealed resolution against the consuming request and provenance pair.
    pub(crate) fn validate_for(
        &self,
        request: &CeremonyPublicRequestContextV1,
        dag: CeremonyValidatedDagV1,
        provenance: &RoleInputProvenancePairV1,
    ) -> Result<(), AuthenticatedStoreErrorV1> {
        validate_request_and_provenance(request, dag, provenance)?;
        if self.inner.request_kind != dag.request_kind() {
            return Err(AuthenticatedStoreErrorV1::RequestKindMismatch);
        }
        if self.inner.request_context_digest != *dag.request_context_digest().as_bytes() {
            return Err(AuthenticatedStoreErrorV1::RequestContextDigestMismatch);
        }
        if self.inner.authorization_digest != *dag.authorization_digest().as_bytes() {
            return Err(AuthenticatedStoreErrorV1::AuthorizationDigestMismatch);
        }
        if self.inner.transcript_digest != *dag.transcript_digest().as_bytes() {
            return Err(AuthenticatedStoreErrorV1::TranscriptDigestMismatch);
        }
        if self.inner.provenance_pair_digest != provenance.digest()? {
            return Err(AuthenticatedStoreErrorV1::ProvenancePairDigestMismatch);
        }
        if self.inner.durable_identity != request.durable_store_identity_scope() {
            return Err(AuthenticatedStoreErrorV1::DurableIdentityMismatch);
        }
        let binding = registered_state_binding(dag.request_kind(), provenance)?;
        validate_store_state(&self.inner.state, binding)
    }

    /// Returns the authenticated active state version.
    pub const fn active_state_version(&self) -> ActiveStoreStateVersionV1 {
        self.inner.active_state_version
    }

    /// Returns the authenticated registered-state projection.
    pub const fn state(&self) -> &RegisteredLifecyclePreStateV1 {
        &self.inner.state
    }

    /// Returns the immutable durable identity covered by the store signature.
    pub(crate) const fn durable_identity(&self) -> &CeremonyDurableStoreIdentityScopeV1 {
        &self.inner.durable_identity
    }

    /// Returns the exact authority that authenticated this store resolution.
    pub(crate) const fn trusted_transition_authority(&self) -> StoreAuthorityVerifyingKeyV1 {
        self.authority
    }

    /// Returns the strict signature that authenticated this exact resolution.
    pub(crate) const fn authority_signature(&self) -> StoreAuthoritySignature64V1 {
        self.signature
    }

    /// Returns SHA-256 over the exact store-authority-signed resolution bytes.
    pub(crate) fn signed_resolution_digest(&self) -> Result<[u8; 32], AuthenticatedStoreErrorV1> {
        Ok(Sha256::digest(self.inner.signing_bytes()?).into())
    }

    pub(crate) fn signed_resolution_bytes(&self) -> Result<Vec<u8>, AuthenticatedStoreErrorV1> {
        self.inner.signing_bytes()
    }
}

impl fmt::Debug for AuthenticatedRegisteredStoreResolutionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedRegisteredStoreResolutionV1")
            .field("request_kind", &self.inner.request_kind)
            .field("active_state_version", &self.inner.active_state_version)
            .field("authority_key_epoch", &self.inner.authority_key_epoch)
            .finish()
    }
}

/// Failure while constructing, authenticating, or consuming store authority.
#[derive(Debug)]
pub enum AuthenticatedStoreErrorV1 {
    /// Active state versions are nonzero.
    ZeroActiveStateVersion,
    /// Authority key epochs are nonzero.
    ZeroAuthorityKeyEpoch,
    /// Authority verifying-key bytes were invalid.
    InvalidAuthorityVerifyingKey,
    /// Authority verifying keys must not be weak Edwards points.
    WeakAuthorityVerifyingKey,
    /// The supplied authority key epoch differed from the signed record.
    AuthorityKeyEpochMismatch,
    /// The supplied authority key digest differed from the signed record.
    AuthorityKeyDigestMismatch,
    /// Strict Ed25519 signature verification failed.
    InvalidAuthoritySignature,
    /// The request branch differed from the signed resolution.
    RequestKindMismatch,
    /// The request-context digest differed from the signed resolution.
    RequestContextDigestMismatch,
    /// The authorization digest differed from the signed resolution.
    AuthorizationDigestMismatch,
    /// The transcript digest differed from the signed resolution.
    TranscriptDigestMismatch,
    /// The provenance pair digest differed from the signed resolution.
    ProvenancePairDigestMismatch,
    /// The immutable ceremony identity differed from the signed resolution.
    DurableIdentityMismatch,
    /// The lifecycle branch had no registered state.
    UnregisteredRequestKind,
    /// The canonical ceremony boundary failed.
    Ceremony(CeremonyContextErrorV1),
    /// Canonical provenance encoding failed.
    Provenance(ProvenanceEncodingErrorV1),
    /// The provenance branch could not supply registered state.
    RegisteredStateProvenance(RegisteredStateProvenanceErrorV1),
    /// Store state differed from provenance.
    RegisteredStateMismatch(RegisteredStateBindingFieldV1),
    /// One canonical value exceeded the LP32 length range.
    ValueTooLong,
}

impl fmt::Display for AuthenticatedStoreErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroActiveStateVersion => {
                formatter.write_str("active state version must be nonzero")
            }
            Self::ZeroAuthorityKeyEpoch => {
                formatter.write_str("store authority key epoch must be nonzero")
            }
            Self::InvalidAuthorityVerifyingKey => {
                formatter.write_str("store authority verifying key is invalid")
            }
            Self::WeakAuthorityVerifyingKey => {
                formatter.write_str("store authority verifying key must not be weak")
            }
            Self::AuthorityKeyEpochMismatch => {
                formatter.write_str("store authority key epoch mismatch")
            }
            Self::AuthorityKeyDigestMismatch => {
                formatter.write_str("store authority key digest mismatch")
            }
            Self::InvalidAuthoritySignature => {
                formatter.write_str("store authority signature is invalid")
            }
            Self::RequestKindMismatch => {
                formatter.write_str("store resolution request kind mismatch")
            }
            Self::RequestContextDigestMismatch => {
                formatter.write_str("store resolution request-context digest mismatch")
            }
            Self::AuthorizationDigestMismatch => {
                formatter.write_str("store resolution authorization digest mismatch")
            }
            Self::TranscriptDigestMismatch => {
                formatter.write_str("store resolution transcript digest mismatch")
            }
            Self::ProvenancePairDigestMismatch => {
                formatter.write_str("store resolution provenance pair digest mismatch")
            }
            Self::DurableIdentityMismatch => {
                formatter.write_str("store resolution durable identity mismatch")
            }
            Self::UnregisteredRequestKind => {
                formatter.write_str("request kind has no registered-state authority")
            }
            Self::Ceremony(error) => error.fmt(formatter),
            Self::Provenance(error) => error.fmt(formatter),
            Self::RegisteredStateProvenance(error) => error.fmt(formatter),
            Self::RegisteredStateMismatch(field) => {
                write!(formatter, "registered store state mismatch at {field:?}")
            }
            Self::ValueTooLong => {
                formatter.write_str("authenticated store LP32 value exceeds U32 length")
            }
        }
    }
}

impl std::error::Error for AuthenticatedStoreErrorV1 {}

impl From<CeremonyContextErrorV1> for AuthenticatedStoreErrorV1 {
    fn from(error: CeremonyContextErrorV1) -> Self {
        Self::Ceremony(error)
    }
}

impl From<ProvenanceEncodingErrorV1> for AuthenticatedStoreErrorV1 {
    fn from(error: ProvenanceEncodingErrorV1) -> Self {
        Self::Provenance(error)
    }
}

fn validate_request_and_provenance(
    request: &CeremonyPublicRequestContextV1,
    dag: CeremonyValidatedDagV1,
    provenance: &RoleInputProvenancePairV1,
) -> Result<(), AuthenticatedStoreErrorV1> {
    if request.request_kind() != dag.request_kind() {
        return Err(AuthenticatedStoreErrorV1::RequestKindMismatch);
    }
    if request.digest()? != dag.request_context_digest() {
        return Err(AuthenticatedStoreErrorV1::RequestContextDigestMismatch);
    }
    if provenance.ceremony_request_context_digest().as_bytes()
        != dag.request_context_digest().as_bytes()
    {
        return Err(AuthenticatedStoreErrorV1::RequestContextDigestMismatch);
    }
    if provenance.ceremony_authorization_digest().as_bytes()
        != dag.authorization_digest().as_bytes()
    {
        return Err(AuthenticatedStoreErrorV1::AuthorizationDigestMismatch);
    }
    if provenance.ceremony_transcript_digest().as_bytes() != dag.transcript_digest().as_bytes() {
        return Err(AuthenticatedStoreErrorV1::TranscriptDigestMismatch);
    }
    Ok(())
}

fn registered_state_binding(
    request_kind: CeremonyRequestKindV1,
    provenance: &RoleInputProvenancePairV1,
) -> Result<RegisteredStateProvenanceBindingV1, AuthenticatedStoreErrorV1> {
    match request_kind {
        CeremonyRequestKindV1::Recovery => provenance
            .recovery_registered_state_binding()
            .map_err(AuthenticatedStoreErrorV1::RegisteredStateProvenance),
        CeremonyRequestKindV1::Refresh => provenance
            .refresh_registered_state_binding()
            .map(|binding| binding.current())
            .map_err(AuthenticatedStoreErrorV1::RegisteredStateProvenance),
        CeremonyRequestKindV1::Export => provenance
            .export_registered_state_binding()
            .map_err(AuthenticatedStoreErrorV1::RegisteredStateProvenance),
        CeremonyRequestKindV1::Registration | CeremonyRequestKindV1::Activation => {
            Err(AuthenticatedStoreErrorV1::UnregisteredRequestKind)
        }
    }
}

fn validate_store_state(
    state: &RegisteredLifecyclePreStateV1,
    binding: RegisteredStateProvenanceBindingV1,
) -> Result<(), AuthenticatedStoreErrorV1> {
    validate_registered_state_fields(state, binding)
        .map_err(AuthenticatedStoreErrorV1::RegisteredStateMismatch)
}

fn encode_resolution(
    resolution: &UnverifiedRegisteredStoreResolutionV1,
) -> Result<Vec<u8>, AuthenticatedStoreErrorV1> {
    let mut output = Vec::new();
    push_lp32(
        &mut output,
        AUTHENTICATED_STORE_RESOLUTION_ENCODING_DOMAIN_V1,
    )?;
    push_lp32(
        &mut output,
        &resolution.authority_key_epoch.value().to_be_bytes(),
    )?;
    push_lp32(&mut output, &resolution.authority_key_digest)?;
    push_lp32(&mut output, &[resolution.request_kind.tag()])?;
    push_lp32(&mut output, &resolution.request_context_digest)?;
    push_lp32(&mut output, &resolution.authorization_digest)?;
    push_lp32(&mut output, &resolution.transcript_digest)?;
    push_lp32(&mut output, resolution.provenance_pair_digest.as_bytes())?;
    push_lp32(
        &mut output,
        &resolution.active_state_version.value().to_be_bytes(),
    )?;
    push_lp32(&mut output, &resolution.durable_identity.encode()?)?;
    push_lp32(&mut output, &encode_registered_state(&resolution.state)?)?;
    Ok(output)
}

fn encode_registered_state(
    state: &RegisteredLifecyclePreStateV1,
) -> Result<Vec<u8>, AuthenticatedStoreErrorV1> {
    let mut output = Vec::new();
    push_lp32(&mut output, state.registered_public_key.as_bytes())?;
    push_lp32(
        &mut output,
        state.active_credential_binding_digest.as_bytes(),
    )?;
    push_lp32(&mut output, &state.stable_scope.encode()?)?;
    push_lp32(
        &mut output,
        &state.active_activation_epoch.value().to_be_bytes(),
    )?;
    push_lp32(&mut output, state.deriver_a_root_record.as_bytes())?;
    push_lp32(&mut output, state.deriver_a_root_binding.as_bytes())?;
    push_lp32(
        &mut output,
        &state.deriver_a_root_epoch.value().to_be_bytes(),
    )?;
    push_lp32(&mut output, state.deriver_a_state_record.as_bytes())?;
    push_lp32(
        &mut output,
        &state.deriver_a_input_state_epoch.value().to_be_bytes(),
    )?;
    push_lp32(&mut output, state.deriver_b_root_record.as_bytes())?;
    push_lp32(&mut output, state.deriver_b_root_binding.as_bytes())?;
    push_lp32(
        &mut output,
        &state.deriver_b_root_epoch.value().to_be_bytes(),
    )?;
    push_lp32(&mut output, state.deriver_b_state_record.as_bytes())?;
    push_lp32(
        &mut output,
        &state.deriver_b_input_state_epoch.value().to_be_bytes(),
    )?;
    Ok(output)
}

fn push_lp32(output: &mut Vec<u8>, value: &[u8]) -> Result<(), AuthenticatedStoreErrorV1> {
    let length = u32::try_from(value.len()).map_err(|_| AuthenticatedStoreErrorV1::ValueTooLong)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::ceremony_context::CeremonyActivationEpochV1;
    use crate::lifecycle_domain::{
        ActiveCredentialBindingDigest32V1, RegisteredStateBindingFieldV1,
    };
    use crate::provenance::RegisteredStateProvenanceBindingV1;
    use crate::semantic_artifacts_tests::{export_ceremony, provenance_pair, recovery_ceremony};
    use crate::semantic_fixture_material::reference_fixture;
    use crate::RegisteredEd25519PublicKey32V1;

    fn test_authority(seed: u8, epoch: u64) -> (SigningKey, StoreAuthorityVerifyingKeyV1) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let authority = StoreAuthorityVerifyingKeyV1::parse(
            StoreAuthorityKeyEpochV1::new(epoch).expect("authority epoch"),
            signing_key.verifying_key().to_bytes(),
        )
        .expect("authority key");
        (signing_key, authority)
    }

    fn state_from_binding(
        binding: RegisteredStateProvenanceBindingV1,
    ) -> RegisteredLifecyclePreStateV1 {
        let a = binding.deriver_a();
        let b = binding.deriver_b();
        RegisteredLifecyclePreStateV1::from_host_reference_store_projection(
            binding.registered_public_key(),
            ActiveCredentialBindingDigest32V1::new([0x41; 32]).expect("active credential binding"),
            binding.stable_scope(),
            CeremonyActivationEpochV1::new(7).expect("activation epoch"),
            a.role_root_record_digest(),
            a.root_binding_artifact_digest(),
            a.role_root_epoch(),
            a.record_digest(),
            a.epoch(),
            b.role_root_record_digest(),
            b.root_binding_artifact_digest(),
            b.role_root_epoch(),
            b.record_digest(),
            b.epoch(),
        )
    }

    fn verified_recovery_resolution() -> (
        crate::lifecycle_domain::RecoveryRequestV1,
        RoleInputProvenancePairV1,
        AuthenticatedRegisteredStoreResolutionV1,
    ) {
        let fixture = reference_fixture();
        let (context, authorization, transcript) = recovery_ceremony();
        let request =
            crate::lifecycle_domain::RecoveryRequestV1::new(context, authorization, transcript)
                .expect("recovery request");
        let pair = provenance_pair(request.validated_dag(), Some(fixture.registered_public_key));
        let state = state_from_binding(
            pair.recovery_registered_state_binding()
                .expect("recovery state"),
        );
        let (signing_key, authority) = test_authority(0x51, 4);
        let unverified = UnverifiedRegisteredStoreResolutionV1::new(
            request.request_context(),
            request.validated_dag(),
            &pair,
            ActiveStoreStateVersionV1::new(11).expect("state version"),
            state,
            authority,
        )
        .expect("store resolution");
        let signature = signing_key.sign(&unverified.signing_bytes().expect("signing bytes"));
        let verified = unverified
            .verify(
                StoreAuthoritySignature64V1::from_bytes(signature.to_bytes()),
                authority,
            )
            .expect("verified store resolution");
        (request, pair, verified)
    }

    #[test]
    fn valid_resolution_binds_state_version_epoch_and_request_graph() {
        let (request, pair, resolution) = verified_recovery_resolution();
        assert_eq!(resolution.active_state_version().value(), 11);
        assert_eq!(resolution.state().active_activation_epoch().value(), 7);
        resolution
            .validate_for(request.request_context(), request.validated_dag(), &pair)
            .expect("request-bound resolution");
    }

    #[test]
    fn strict_signature_verification_rejects_mutation() {
        let fixture = reference_fixture();
        let (context, authorization, transcript) = recovery_ceremony();
        let request =
            crate::lifecycle_domain::RecoveryRequestV1::new(context, authorization, transcript)
                .expect("request");
        let pair = provenance_pair(request.validated_dag(), Some(fixture.registered_public_key));
        let state = state_from_binding(pair.recovery_registered_state_binding().expect("state"));
        let (signing_key, authority) = test_authority(0x52, 5);
        let resolution = UnverifiedRegisteredStoreResolutionV1::new(
            request.request_context(),
            request.validated_dag(),
            &pair,
            ActiveStoreStateVersionV1::new(12).expect("state version"),
            state,
            authority,
        )
        .expect("resolution");
        let mut signature = signing_key
            .sign(&resolution.signing_bytes().expect("signing bytes"))
            .to_bytes();
        signature[0] ^= 1;
        assert!(matches!(
            resolution.verify(
                StoreAuthoritySignature64V1::from_bytes(signature),
                authority
            ),
            Err(AuthenticatedStoreErrorV1::InvalidAuthoritySignature)
        ));
    }

    #[test]
    fn authority_key_epoch_and_key_digest_cannot_be_substituted() {
        let fixture = reference_fixture();
        let (context, authorization, transcript) = recovery_ceremony();
        let request =
            crate::lifecycle_domain::RecoveryRequestV1::new(context, authorization, transcript)
                .expect("request");
        let pair = provenance_pair(request.validated_dag(), Some(fixture.registered_public_key));
        let state = state_from_binding(pair.recovery_registered_state_binding().expect("state"));
        let (signing_key, authority) = test_authority(0x53, 6);
        let resolution = UnverifiedRegisteredStoreResolutionV1::new(
            request.request_context(),
            request.validated_dag(),
            &pair,
            ActiveStoreStateVersionV1::new(13).expect("state version"),
            state,
            authority,
        )
        .expect("resolution");
        let signature = StoreAuthoritySignature64V1::from_bytes(
            signing_key
                .sign(&resolution.signing_bytes().expect("signing bytes"))
                .to_bytes(),
        );
        let (_, wrong_epoch) = test_authority(0x53, 7);
        assert!(matches!(
            resolution.verify(signature, wrong_epoch),
            Err(AuthenticatedStoreErrorV1::AuthorityKeyEpochMismatch)
        ));
    }

    #[test]
    fn authority_key_digest_cannot_be_substituted_at_the_same_epoch() {
        let fixture = reference_fixture();
        let (context, authorization, transcript) = recovery_ceremony();
        let request =
            crate::lifecycle_domain::RecoveryRequestV1::new(context, authorization, transcript)
                .expect("request");
        let pair = provenance_pair(request.validated_dag(), Some(fixture.registered_public_key));
        let state = state_from_binding(pair.recovery_registered_state_binding().expect("state"));
        let (signing_key, authority) = test_authority(0x55, 9);
        let resolution = UnverifiedRegisteredStoreResolutionV1::new(
            request.request_context(),
            request.validated_dag(),
            &pair,
            ActiveStoreStateVersionV1::new(15).expect("state version"),
            state,
            authority,
        )
        .expect("resolution");
        let signature = StoreAuthoritySignature64V1::from_bytes(
            signing_key
                .sign(&resolution.signing_bytes().expect("signing bytes"))
                .to_bytes(),
        );
        let (_, wrong_key) = test_authority(0x56, 9);
        assert!(matches!(
            resolution.verify(signature, wrong_key),
            Err(AuthenticatedStoreErrorV1::AuthorityKeyDigestMismatch)
        ));
    }

    #[test]
    fn incoherent_registered_key_is_rejected_before_signing() {
        let fixture = reference_fixture();
        let (context, authorization, transcript) = recovery_ceremony();
        let request =
            crate::lifecycle_domain::RecoveryRequestV1::new(context, authorization, transcript)
                .expect("request");
        let pair = provenance_pair(request.validated_dag(), Some(fixture.registered_public_key));
        let mut state =
            state_from_binding(pair.recovery_registered_state_binding().expect("state"));
        state.registered_public_key = RegisteredEd25519PublicKey32V1::parse(
            (ED25519_BASEPOINT_POINT + ED25519_BASEPOINT_POINT)
                .compress()
                .to_bytes(),
        )
        .expect("alternate key");
        let (_, authority) = test_authority(0x54, 8);
        assert!(matches!(
            UnverifiedRegisteredStoreResolutionV1::new(
                request.request_context(),
                request.validated_dag(),
                &pair,
                ActiveStoreStateVersionV1::new(14).expect("state version"),
                state,
                authority,
            ),
            Err(AuthenticatedStoreErrorV1::RegisteredStateMismatch(
                RegisteredStateBindingFieldV1::RegisteredPublicKey
            ))
        ));
    }

    #[test]
    fn active_credential_binding_is_covered_by_the_store_signature() {
        let fixture = reference_fixture();
        let (context, authorization, transcript) = recovery_ceremony();
        let request =
            crate::lifecycle_domain::RecoveryRequestV1::new(context, authorization, transcript)
                .expect("request");
        let pair = provenance_pair(request.validated_dag(), Some(fixture.registered_public_key));
        let binding = pair.recovery_registered_state_binding().expect("state");
        let state = state_from_binding(binding);
        let mut substituted_state = state_from_binding(binding);
        substituted_state.active_credential_binding_digest =
            ActiveCredentialBindingDigest32V1::new([0x42; 32]).expect("alternate credential");
        let (signing_key, authority) = test_authority(0x57, 10);
        let original = UnverifiedRegisteredStoreResolutionV1::new(
            request.request_context(),
            request.validated_dag(),
            &pair,
            ActiveStoreStateVersionV1::new(16).expect("state version"),
            state,
            authority,
        )
        .expect("original resolution");
        let substituted = UnverifiedRegisteredStoreResolutionV1::new(
            request.request_context(),
            request.validated_dag(),
            &pair,
            ActiveStoreStateVersionV1::new(16).expect("state version"),
            substituted_state,
            authority,
        )
        .expect("substituted resolution");
        let original_bytes = original.signing_bytes().expect("original signing bytes");
        let signature =
            StoreAuthoritySignature64V1::from_bytes(signing_key.sign(&original_bytes).to_bytes());
        assert_ne!(
            original_bytes,
            substituted
                .signing_bytes()
                .expect("substituted signing bytes")
        );
        assert!(matches!(
            substituted.verify(signature, authority),
            Err(AuthenticatedStoreErrorV1::InvalidAuthoritySignature)
        ));
    }

    #[test]
    fn verified_resolution_cannot_cross_request_family() {
        let fixture = reference_fixture();
        let (_recovery_request, _recovery_pair, resolution) = verified_recovery_resolution();
        let (context, authorization, transcript) = export_ceremony(fixture.registered_public_key);
        let export_request =
            crate::lifecycle_domain::ExportRequestV1::new(context, authorization, transcript)
                .expect("export request");
        let export_pair = provenance_pair(
            export_request.validated_dag(),
            Some(fixture.registered_public_key),
        );
        assert!(matches!(
            resolution.validate_for(
                export_request.request_context(),
                export_request.validated_dag(),
                &export_pair,
            ),
            Err(AuthenticatedStoreErrorV1::RequestKindMismatch)
        ));
    }
}
