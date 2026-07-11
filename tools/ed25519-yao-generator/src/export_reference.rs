//! Host-only export arithmetic over public synthetic reference inputs.
//!
//! Variable-time arithmetic is permitted because this module belongs only to
//! the clear fixture generator. Production protocol code and secret material
//! cannot depend on this crate.

use core::fmt;

use crate::output_sharing::share_host_only_export_seed_from_seed_v1;
use crate::{
    wrapping_add_le_256, DeriverAClientY, DeriverAServerY, DeriverBClientY, DeriverBServerY,
    HostOnlyExportIdealCoinV1, HostOnlySeedExportSharesV1, RegisteredEd25519PublicKey32V1,
    SeedBytes,
};
use ed25519_dalek::SigningKey;

/// Exact validation failure for the narrow host-only export reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyExportReferenceErrorV1 {
    /// The export projection derives a different public key than the expected key.
    RegisteredPublicKeyMismatch,
}

impl fmt::Display for HostOnlyExportReferenceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegisteredPublicKeyMismatch => formatter
                .write_str("export projection must derive the expected registered public key"),
        }
    }
}

impl std::error::Error for HostOnlyExportReferenceErrorV1 {}

/// Borrowed y-only role inputs for one host-only export projection.
pub struct HostOnlyExportReferenceInputsV1<'a> {
    deriver_a_y_client: &'a DeriverAClientY,
    deriver_a_y_server: &'a DeriverAServerY,
    deriver_b_y_client: &'a DeriverBClientY,
    deriver_b_y_server: &'a DeriverBServerY,
}

impl<'a> HostOnlyExportReferenceInputsV1<'a> {
    /// Binds exactly four public synthetic y inputs; no scalar input is accepted.
    pub const fn new(
        deriver_a_y_client: &'a DeriverAClientY,
        deriver_a_y_server: &'a DeriverAServerY,
        deriver_b_y_client: &'a DeriverBClientY,
        deriver_b_y_server: &'a DeriverBServerY,
    ) -> Self {
        Self {
            deriver_a_y_client,
            deriver_a_y_server,
            deriver_b_y_client,
            deriver_b_y_server,
        }
    }
}

/// Marker produced after exact export/public-key equality succeeds.
pub struct HostOnlyExportPublicKeyEqualityWitnessV1 {
    _private: (),
}

/// Validated export projection ready for deterministic host-only seed sharing.
pub struct HostOnlyPreparedExportReferenceV1 {
    seed: SeedBytes,
    deriver_a_y_client: [u8; 32],
    deriver_a_y_server: [u8; 32],
    deriver_b_y_client: [u8; 32],
    deriver_b_y_server: [u8; 32],
    expected_registered_public_key: RegisteredEd25519PublicKey32V1,
    public_key_equality_witness: HostOnlyExportPublicKeyEqualityWitnessV1,
}

impl HostOnlyPreparedExportReferenceV1 {
    pub(crate) const fn deriver_a_y_client_fixture_bytes(&self) -> [u8; 32] {
        self.deriver_a_y_client
    }

    pub(crate) const fn deriver_a_y_server_fixture_bytes(&self) -> [u8; 32] {
        self.deriver_a_y_server
    }

    pub(crate) const fn deriver_b_y_client_fixture_bytes(&self) -> [u8; 32] {
        self.deriver_b_y_client
    }

    pub(crate) const fn deriver_b_y_server_fixture_bytes(&self) -> [u8; 32] {
        self.deriver_b_y_server
    }

    /// Returns the caller-supplied expected registered public key.
    pub const fn expected_registered_public_key(&self) -> &RegisteredEd25519PublicKey32V1 {
        &self.expected_registered_public_key
    }

    /// Returns evidence of exact public-key equality for this host-only projection.
    pub const fn public_key_equality_witness(&self) -> &HostOnlyExportPublicKeyEqualityWitnessV1 {
        &self.public_key_equality_witness
    }
}

/// Host-only export result containing only the expected key, witness, and shares.
pub struct HostOnlyExportReferenceSuccessV1 {
    expected_registered_public_key: RegisteredEd25519PublicKey32V1,
    public_key_equality_witness: HostOnlyExportPublicKeyEqualityWitnessV1,
    output_shares: HostOnlySeedExportSharesV1,
}

impl HostOnlyExportReferenceSuccessV1 {
    /// Returns the caller-supplied expected registered public key.
    pub const fn expected_registered_public_key(&self) -> &RegisteredEd25519PublicKey32V1 {
        &self.expected_registered_public_key
    }

    /// Returns evidence of exact public-key equality for this host-only projection.
    pub const fn public_key_equality_witness(&self) -> &HostOnlyExportPublicKeyEqualityWitnessV1 {
        &self.public_key_equality_witness
    }

    /// Returns the typed Deriver A and Deriver B export seed shares.
    pub const fn output_shares(&self) -> &HostOnlySeedExportSharesV1 {
        &self.output_shares
    }

    pub(crate) fn into_output_shares(self) -> HostOnlySeedExportSharesV1 {
        self.output_shares
    }
}

/// Evaluates export arithmetic and checks the authoritative public key before output sharing.
pub fn prepare_host_only_export_reference_v1(
    inputs: HostOnlyExportReferenceInputsV1<'_>,
    expected_registered_public_key: &RegisteredEd25519PublicKey32V1,
) -> Result<HostOnlyPreparedExportReferenceV1, HostOnlyExportReferenceErrorV1> {
    let deriver_a_y_client = inputs.deriver_a_y_client.expose_bytes();
    let deriver_a_y_server = inputs.deriver_a_y_server.expose_bytes();
    let deriver_b_y_client = inputs.deriver_b_y_client.expose_bytes();
    let deriver_b_y_server = inputs.deriver_b_y_server.expose_bytes();
    let deriver_a_y = wrapping_add_le_256(deriver_a_y_client, deriver_a_y_server);
    let deriver_b_y = wrapping_add_le_256(deriver_b_y_client, deriver_b_y_server);
    let seed_bytes = wrapping_add_le_256(deriver_a_y, deriver_b_y);
    if SigningKey::from_bytes(&seed_bytes)
        .verifying_key()
        .to_bytes()
        != *expected_registered_public_key.as_bytes()
    {
        return Err(HostOnlyExportReferenceErrorV1::RegisteredPublicKeyMismatch);
    }

    Ok(HostOnlyPreparedExportReferenceV1 {
        seed: SeedBytes(seed_bytes),
        deriver_a_y_client,
        deriver_a_y_server,
        deriver_b_y_client,
        deriver_b_y_server,
        expected_registered_public_key: *expected_registered_public_key,
        public_key_equality_witness: HostOnlyExportPublicKeyEqualityWitnessV1 { _private: () },
    })
}

/// Consumes a validated projection and applies one explicit fixture seed coin.
pub fn evaluate_host_only_export_output_sharing_v1(
    prepared: HostOnlyPreparedExportReferenceV1,
    coin: HostOnlyExportIdealCoinV1,
) -> HostOnlyExportReferenceSuccessV1 {
    let HostOnlyPreparedExportReferenceV1 {
        seed,
        deriver_a_y_client: _,
        deriver_a_y_server: _,
        deriver_b_y_client: _,
        deriver_b_y_server: _,
        expected_registered_public_key,
        public_key_equality_witness,
    } = prepared;
    let output_shares =
        share_host_only_export_seed_from_seed_v1(&seed, coin.into_seed_output_coin());

    HostOnlyExportReferenceSuccessV1 {
        expected_registered_public_key,
        public_key_equality_witness,
        output_shares,
    }
}
