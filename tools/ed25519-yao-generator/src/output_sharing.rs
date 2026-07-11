//! Deterministic output-sharing arithmetic over public synthetic fixtures.
//!
//! This host-only module may use variable-time library arithmetic. Production
//! protocol code and secret material cannot depend on this crate.

use core::fmt;

use curve25519_dalek::scalar::Scalar;

use crate::{
    wrapping_add_le_256, ActivationOracleOutput, CanonicalScalarBytes, ExportOracleOutput,
    SeedBytes,
};

/// Boundary failures for host-only output-sharing fixture coins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyOutputSharingErrorV1 {
    /// The client scalar coin is not a canonical scalar encoding.
    NonCanonicalClientScalarOutputCoin,
    /// The SigningWorker scalar coin is not a canonical scalar encoding.
    NonCanonicalSigningWorkerScalarOutputCoin,
}

impl fmt::Display for HostOnlyOutputSharingErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCanonicalClientScalarOutputCoin => {
                formatter.write_str("client scalar output coin must be canonical")
            }
            Self::NonCanonicalSigningWorkerScalarOutputCoin => {
                formatter.write_str("SigningWorker scalar output coin must be canonical")
            }
        }
    }
}

impl std::error::Error for HostOnlyOutputSharingErrorV1 {}

/// Validated host-only fixture coin for the client scalar output.
pub struct HostOnlyClientScalarOutputCoinV1(Scalar);

impl HostOnlyClientScalarOutputCoinV1 {
    /// Parses a canonical little-endian scalar fixture coin.
    pub fn from_canonical_fixture_bytes(
        bytes: [u8; 32],
    ) -> Result<Self, HostOnlyOutputSharingErrorV1> {
        Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
            .map(Self)
            .ok_or(HostOnlyOutputSharingErrorV1::NonCanonicalClientScalarOutputCoin)
    }

    /// Explicitly exposes the canonical fixture bytes.
    pub fn expose_fixture_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Validated host-only fixture coin for the SigningWorker scalar output.
pub struct HostOnlySigningWorkerScalarOutputCoinV1(Scalar);

impl HostOnlySigningWorkerScalarOutputCoinV1 {
    /// Parses a canonical little-endian scalar fixture coin.
    pub fn from_canonical_fixture_bytes(
        bytes: [u8; 32],
    ) -> Result<Self, HostOnlyOutputSharingErrorV1> {
        Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
            .map(Self)
            .ok_or(HostOnlyOutputSharingErrorV1::NonCanonicalSigningWorkerScalarOutputCoin)
    }

    /// Explicitly exposes the canonical fixture bytes.
    pub fn expose_fixture_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Host-only fixture coin for the export seed output.
pub struct HostOnlySeedOutputCoinV1([u8; 32]);

impl HostOnlySeedOutputCoinV1 {
    /// Creates a seed fixture coin from any 32-byte little-endian value.
    pub const fn from_fixture_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Explicitly exposes the fixture bytes.
    pub const fn expose_fixture_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// Typed host-only fixture coins for activation-family scalar outputs.
pub struct HostOnlyActivationOutputCoinsV1 {
    client: HostOnlyClientScalarOutputCoinV1,
    signing_worker: HostOnlySigningWorkerScalarOutputCoinV1,
}

impl HostOnlyActivationOutputCoinsV1 {
    /// Joins the independently typed client and SigningWorker fixture coins.
    pub const fn new(
        client: HostOnlyClientScalarOutputCoinV1,
        signing_worker: HostOnlySigningWorkerScalarOutputCoinV1,
    ) -> Self {
        Self {
            client,
            signing_worker,
        }
    }

    /// Returns the client scalar fixture coin.
    pub const fn client(&self) -> &HostOnlyClientScalarOutputCoinV1 {
        &self.client
    }

    /// Returns the SigningWorker scalar fixture coin.
    pub const fn signing_worker(&self) -> &HostOnlySigningWorkerScalarOutputCoinV1 {
        &self.signing_worker
    }
}

/// Deriver A's host-only client scalar output share.
pub struct HostOnlyDeriverAClientScalarShareV1(Scalar);

impl HostOnlyDeriverAClientScalarShareV1 {
    /// Explicitly exposes the canonical fixture bytes.
    pub fn expose_fixture_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Deriver B's host-only client scalar output share.
pub struct HostOnlyDeriverBClientScalarShareV1(Scalar);

impl HostOnlyDeriverBClientScalarShareV1 {
    /// Explicitly exposes the canonical fixture bytes.
    pub fn expose_fixture_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Deriver A's host-only SigningWorker scalar output share.
pub struct HostOnlyDeriverASigningWorkerScalarShareV1(Scalar);

impl HostOnlyDeriverASigningWorkerScalarShareV1 {
    /// Explicitly exposes the canonical fixture bytes.
    pub fn expose_fixture_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Deriver B's host-only SigningWorker scalar output share.
pub struct HostOnlyDeriverBSigningWorkerScalarShareV1(Scalar);

impl HostOnlyDeriverBSigningWorkerScalarShareV1 {
    /// Explicitly exposes the canonical fixture bytes.
    pub fn expose_fixture_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Deriver A's host-only export seed share.
pub struct HostOnlyDeriverASeedExportShareV1([u8; 32]);

impl HostOnlyDeriverASeedExportShareV1 {
    /// Explicitly exposes the fixture bytes.
    pub const fn expose_fixture_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// Deriver B's host-only export seed share.
pub struct HostOnlyDeriverBSeedExportShareV1([u8; 32]);

impl HostOnlyDeriverBSeedExportShareV1 {
    /// Explicitly exposes the fixture bytes.
    pub const fn expose_fixture_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// Deriver A's typed activation-family output-share view.
pub struct HostOnlyDeriverAActivationOutputSharesV1 {
    client: HostOnlyDeriverAClientScalarShareV1,
    signing_worker: HostOnlyDeriverASigningWorkerScalarShareV1,
}

impl HostOnlyDeriverAActivationOutputSharesV1 {
    /// Returns Deriver A's client scalar share.
    pub const fn client(&self) -> &HostOnlyDeriverAClientScalarShareV1 {
        &self.client
    }

    /// Returns Deriver A's SigningWorker scalar share.
    pub const fn signing_worker(&self) -> &HostOnlyDeriverASigningWorkerScalarShareV1 {
        &self.signing_worker
    }
}

/// Deriver B's typed activation-family output-share view.
pub struct HostOnlyDeriverBActivationOutputSharesV1 {
    client: HostOnlyDeriverBClientScalarShareV1,
    signing_worker: HostOnlyDeriverBSigningWorkerScalarShareV1,
}

impl HostOnlyDeriverBActivationOutputSharesV1 {
    /// Returns Deriver B's client scalar share.
    pub const fn client(&self) -> &HostOnlyDeriverBClientScalarShareV1 {
        &self.client
    }

    /// Returns Deriver B's SigningWorker scalar share.
    pub const fn signing_worker(&self) -> &HostOnlyDeriverBSigningWorkerScalarShareV1 {
        &self.signing_worker
    }
}

/// Typed host-only activation-family shares grouped by Deriver role.
pub struct HostOnlyActivationOutputSharesV1 {
    deriver_a: HostOnlyDeriverAActivationOutputSharesV1,
    deriver_b: HostOnlyDeriverBActivationOutputSharesV1,
}

impl HostOnlyActivationOutputSharesV1 {
    /// Returns Deriver A's activation-family output shares.
    pub const fn deriver_a(&self) -> &HostOnlyDeriverAActivationOutputSharesV1 {
        &self.deriver_a
    }

    /// Returns Deriver B's activation-family output shares.
    pub const fn deriver_b(&self) -> &HostOnlyDeriverBActivationOutputSharesV1 {
        &self.deriver_b
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn into_role_shares(
        self,
    ) -> (
        HostOnlyDeriverAActivationOutputSharesV1,
        HostOnlyDeriverBActivationOutputSharesV1,
    ) {
        (self.deriver_a, self.deriver_b)
    }
}

/// Typed host-only export seed shares grouped by Deriver role.
pub struct HostOnlySeedExportSharesV1 {
    deriver_a: HostOnlyDeriverASeedExportShareV1,
    deriver_b: HostOnlyDeriverBSeedExportShareV1,
}

impl HostOnlySeedExportSharesV1 {
    /// Returns Deriver A's seed export share.
    pub const fn deriver_a(&self) -> &HostOnlyDeriverASeedExportShareV1 {
        &self.deriver_a
    }

    /// Returns Deriver B's seed export share.
    pub const fn deriver_b(&self) -> &HostOnlyDeriverBSeedExportShareV1 {
        &self.deriver_b
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn into_role_shares(
        self,
    ) -> (
        HostOnlyDeriverASeedExportShareV1,
        HostOnlyDeriverBSeedExportShareV1,
    ) {
        (self.deriver_a, self.deriver_b)
    }
}

/// Shares activation-family scalar outputs with explicit host-only fixture coins.
pub fn share_host_only_activation_outputs_v1(
    output: &ActivationOracleOutput,
    coins: HostOnlyActivationOutputCoinsV1,
) -> HostOnlyActivationOutputSharesV1 {
    let x_client_base = parse_oracle_scalar(output.material().x_client_base());
    let x_server_base = parse_oracle_scalar(output.material().x_server_base());
    let HostOnlyActivationOutputCoinsV1 {
        client,
        signing_worker,
    } = coins;
    let HostOnlyClientScalarOutputCoinV1(client_coin) = client;
    let HostOnlySigningWorkerScalarOutputCoinV1(signing_worker_coin) = signing_worker;

    HostOnlyActivationOutputSharesV1 {
        deriver_a: HostOnlyDeriverAActivationOutputSharesV1 {
            client: HostOnlyDeriverAClientScalarShareV1(client_coin),
            signing_worker: HostOnlyDeriverASigningWorkerScalarShareV1(signing_worker_coin),
        },
        deriver_b: HostOnlyDeriverBActivationOutputSharesV1 {
            client: HostOnlyDeriverBClientScalarShareV1(x_client_base - client_coin),
            signing_worker: HostOnlyDeriverBSigningWorkerScalarShareV1(
                x_server_base - signing_worker_coin,
            ),
        },
    }
}

/// Shares an authorized export seed with an explicit host-only fixture coin.
pub fn share_host_only_export_seed_v1(
    output: &ExportOracleOutput,
    coin: HostOnlySeedOutputCoinV1,
) -> HostOnlySeedExportSharesV1 {
    share_host_only_export_seed_from_seed_v1(output.seed(), coin)
}

pub(crate) fn share_host_only_export_seed_from_seed_v1(
    seed: &SeedBytes,
    coin: HostOnlySeedOutputCoinV1,
) -> HostOnlySeedExportSharesV1 {
    let HostOnlySeedOutputCoinV1(deriver_a) = coin;
    let deriver_b = wrapping_sub_le_256(seed.expose_bytes(), deriver_a);

    HostOnlySeedExportSharesV1 {
        deriver_a: HostOnlyDeriverASeedExportShareV1(deriver_a),
        deriver_b: HostOnlyDeriverBSeedExportShareV1(deriver_b),
    }
}

/// Reconstructs the client scalar output from its exact A/B share pair.
pub fn reconstruct_host_only_client_scalar_output_v1(
    deriver_a: &HostOnlyDeriverAClientScalarShareV1,
    deriver_b: &HostOnlyDeriverBClientScalarShareV1,
) -> CanonicalScalarBytes {
    CanonicalScalarBytes((deriver_a.0 + deriver_b.0).to_bytes())
}

/// Reconstructs the SigningWorker scalar output from its exact A/B share pair.
pub fn reconstruct_host_only_signing_worker_scalar_output_v1(
    deriver_a: &HostOnlyDeriverASigningWorkerScalarShareV1,
    deriver_b: &HostOnlyDeriverBSigningWorkerScalarShareV1,
) -> CanonicalScalarBytes {
    CanonicalScalarBytes((deriver_a.0 + deriver_b.0).to_bytes())
}

/// Reconstructs the export seed from its exact A/B share pair.
pub fn reconstruct_host_only_seed_export_v1(
    deriver_a: &HostOnlyDeriverASeedExportShareV1,
    deriver_b: &HostOnlyDeriverBSeedExportShareV1,
) -> SeedBytes {
    SeedBytes(wrapping_add_le_256(deriver_a.0, deriver_b.0))
}

fn parse_oracle_scalar(bytes: &CanonicalScalarBytes) -> Scalar {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes.expose_bytes()))
        .expect("validated oracle output scalar must remain canonical")
}

fn wrapping_sub_le_256(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut borrow = 0u16;

    for index in 0..32 {
        let subtrahend = u16::from(right[index]) + borrow;
        let difference = u16::from(left[index]).wrapping_sub(subtrahend);
        output[index] = difference as u8;
        borrow = difference >> 15;
    }

    output
}
