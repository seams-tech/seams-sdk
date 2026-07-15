use core::fmt;
use std::collections::BTreeMap;

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use signer_core::{
    near_threshold_ed25519::{
        build_signing_package, client_round1_commit, client_round2_signature_share,
        commitments_from_wire, key_package_from_signing_share_bytes, signature_share_to_b64u,
        verifying_share_bytes_from_signing_share_bytes, CommitmentsWire,
    },
    near_threshold_frost::compute_threshold_ed25519_group_public_key_2p_from_verifying_shares,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Client-side FROST signing failure after Yao activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientSigningError {
    /// The Client scalar share was not a canonical nonzero scalar.
    InvalidClientShare,
    /// Participant identifiers were invalid or did not define the registered key.
    InvalidPublicRelation,
    /// SigningWorker commitments could not be decoded.
    InvalidSigningWorkerCommitments,
    /// FROST signing failed.
    SigningFailed,
}

impl fmt::Display for ClientSigningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidClientShare => "Ed25519 Yao Client signing share is invalid",
            Self::InvalidPublicRelation => {
                "Ed25519 Yao FROST shares do not define the registered public key"
            }
            Self::InvalidSigningWorkerCommitments => {
                "Ed25519 Yao SigningWorker commitments are invalid"
            }
            Self::SigningFailed => "Ed25519 Yao Client FROST signing failed",
        })
    }
}

impl std::error::Error for ClientSigningError {}

/// Exact public and Client-secret inputs for one FROST signature share.
pub struct ClientSigningRequestV1<'a> {
    /// Canonical Client scalar share returned by Yao activation.
    pub client_scalar_share: &'a [u8; 32],
    /// Registered Ed25519 group public key.
    pub registered_public_key: &'a [u8; 32],
    /// Fixed Client and SigningWorker FROST participant identifiers.
    pub participant_ids: [u16; 2],
    /// Router-admitted 32-byte digest to sign.
    pub admitted_digest: &'a [u8; 32],
    /// SigningWorker round-one commitments.
    pub signing_worker_commitments: &'a CommitmentsWire,
    /// Public SigningWorker verifying share bound during activation.
    pub signing_worker_verifying_share: &'a [u8; 32],
}

/// Public Client material sent in one normal-signing finalize request.
#[derive(Debug, Clone)]
pub struct ClientSigningShareV1 {
    client_commitments: CommitmentsWire,
    client_verifying_share: [u8; 32],
    client_signature_share_b64u: String,
}

impl ClientSigningShareV1 {
    /// Returns the Client round-one commitments.
    pub const fn client_commitments(&self) -> &CommitmentsWire {
        &self.client_commitments
    }

    /// Returns the Client verifying share.
    pub const fn client_verifying_share(&self) -> [u8; 32] {
        self.client_verifying_share
    }

    /// Returns the canonical FROST signature-share encoding.
    pub fn client_signature_share_b64u(&self) -> &str {
        &self.client_signature_share_b64u
    }
}

/// Creates one Client FROST share from an activated Yao scalar and admitted digest.
pub fn create_client_signing_share_v1(
    request: ClientSigningRequestV1<'_>,
) -> Result<ClientSigningShareV1, ClientSigningError> {
    let scalar_option = Scalar::from_canonical_bytes(*request.client_scalar_share);
    let scalar = scalar_option.unwrap_or(Scalar::ZERO);
    let client_verifying_share = (ED25519_BASEPOINT_POINT * scalar).compress().to_bytes();
    let mut valid = scalar_option.is_some();
    valid &= !scalar.ct_eq(&Scalar::ZERO);
    if !bool::from(valid) {
        return Err(ClientSigningError::InvalidClientShare);
    }

    let computed_public_key = compute_threshold_ed25519_group_public_key_2p_from_verifying_shares(
        &client_verifying_share,
        request.signing_worker_verifying_share,
        request.participant_ids[0],
        request.participant_ids[1],
    )
    .map_err(|_| ClientSigningError::InvalidPublicRelation)?;
    if !bool::from(computed_public_key.ct_eq(request.registered_public_key)) {
        return Err(ClientSigningError::InvalidPublicRelation);
    }

    let client_identifier = frost_ed25519::Identifier::try_from(request.participant_ids[0])
        .map_err(|_| ClientSigningError::InvalidPublicRelation)?;
    let signing_worker_identifier = frost_ed25519::Identifier::try_from(request.participant_ids[1])
        .map_err(|_| ClientSigningError::InvalidPublicRelation)?;
    let signing_worker_commitments = commitments_from_wire(request.signing_worker_commitments)
        .map_err(|_| ClientSigningError::InvalidSigningWorkerCommitments)?;
    let mut key_package = key_package_from_signing_share_bytes(
        request.client_scalar_share,
        request.registered_public_key,
        client_identifier,
    )
    .map_err(|_| ClientSigningError::InvalidClientShare)?;
    let mut round1 =
        client_round1_commit(&key_package).map_err(|_| ClientSigningError::SigningFailed)?;
    let signing_package = build_signing_package(
        request.admitted_digest,
        BTreeMap::from([
            (client_identifier, round1.commitments),
            (signing_worker_identifier, signing_worker_commitments),
        ]),
    );
    let signature_share =
        client_round2_signature_share(&signing_package, &round1.nonces, &key_package)
            .map_err(|_| ClientSigningError::SigningFailed)?;
    round1.nonces.zeroize();
    key_package.zeroize();
    Ok(ClientSigningShareV1 {
        client_commitments: round1.commitments_wire,
        client_verifying_share: verifying_share_bytes_from_signing_share_bytes(
            request.client_scalar_share,
        ),
        client_signature_share_b64u: signature_share_to_b64u(&signature_share)
            .map_err(|_| ClientSigningError::SigningFailed)?,
    })
}
