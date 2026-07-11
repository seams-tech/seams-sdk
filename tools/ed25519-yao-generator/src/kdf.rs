//! Synthetic contribution derivation for reference vectors.
//!
//! Every root accepted here is synthetic fixture material. Production wallet,
//! credential, or Deriver roots are forbidden by this host-only crate boundary.

use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::context::StableKeyDerivationContext;

/// HKDF-SHA256 extract salt for synthetic contribution derivation.
pub const CONTRIBUTION_KDF_EXTRACT_SALT_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/contribution-kdf/hkdf-sha256/extract/v1";

/// Domain prefix for every synthetic contribution HKDF expand-info value.
pub const CONTRIBUTION_KDF_EXPAND_INFO_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/contribution-kdf/hkdf-sha256/expand/v1";

/// Public tag selecting Deriver A.
pub const CONTRIBUTION_KDF_ROLE_A_TAG_V1: u8 = 0x01;

/// Public tag selecting Deriver B.
pub const CONTRIBUTION_KDF_ROLE_B_TAG_V1: u8 = 0x02;

/// Public tag selecting client-originated contribution material.
pub const CONTRIBUTION_KDF_CLIENT_SOURCE_TAG_V1: u8 = 0x01;

/// Public tag selecting server-originated contribution material.
pub const CONTRIBUTION_KDF_SERVER_SOURCE_TAG_V1: u8 = 0x02;

/// Public tag selecting a seed-domain `y` contribution.
pub const CONTRIBUTION_KDF_Y_OUTPUT_TAG_V1: u8 = 0x01;

/// Public tag selecting a scalar-domain `tau` contribution.
pub const CONTRIBUTION_KDF_TAU_OUTPUT_TAG_V1: u8 = 0x02;

/// Exact byte length of one version-one contribution expand-info value.
pub const CONTRIBUTION_KDF_EXPAND_INFO_LEN_V1: usize =
    CONTRIBUTION_KDF_EXPAND_INFO_DOMAIN_V1.len() + 1 + 1 + 1 + 1 + 32;

/// Synthetic client derivation root used only by reference vectors.
#[derive(PartialEq, Eq)]
pub struct SyntheticClientDerivationRootV1([u8; 32]);

impl SyntheticClientDerivationRootV1 {
    /// Constructs a synthetic root from fixture bytes.
    pub const fn from_fixture_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Synthetic Deriver A root used only by reference vectors.
pub struct SyntheticDeriverADerivationRootV1([u8; 32]);

impl SyntheticDeriverADerivationRootV1 {
    /// Constructs a synthetic root from fixture bytes.
    pub const fn from_fixture_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Synthetic Deriver B root used only by reference vectors.
pub struct SyntheticDeriverBDerivationRootV1([u8; 32]);

impl SyntheticDeriverBDerivationRootV1 {
    /// Constructs a synthetic root from fixture bytes.
    pub const fn from_fixture_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Synthetic 256-bit little-endian contribution in `Z_(2^256)`.
pub struct SyntheticYContributionV1([u8; 32]);

impl SyntheticYContributionV1 {
    /// Exposes the synthetic fixture bytes.
    pub const fn expose_fixture_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// Synthetic canonical little-endian scalar contribution in `Z_l`.
pub struct SyntheticTauContributionV1([u8; 32]);

impl SyntheticTauContributionV1 {
    /// Exposes the synthetic fixture bytes.
    pub const fn expose_fixture_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// Synthetic client contribution addressed to Deriver A.
pub struct SyntheticDeriverAClientContributionV1 {
    y: SyntheticYContributionV1,
    tau: SyntheticTauContributionV1,
}

impl SyntheticDeriverAClientContributionV1 {
    /// Returns the synthetic seed-domain contribution.
    pub const fn y(&self) -> &SyntheticYContributionV1 {
        &self.y
    }

    /// Returns the synthetic scalar-domain contribution.
    pub const fn tau(&self) -> &SyntheticTauContributionV1 {
        &self.tau
    }
}

/// Synthetic client contribution addressed to Deriver B.
pub struct SyntheticDeriverBClientContributionV1 {
    y: SyntheticYContributionV1,
    tau: SyntheticTauContributionV1,
}

impl SyntheticDeriverBClientContributionV1 {
    /// Returns the synthetic seed-domain contribution.
    pub const fn y(&self) -> &SyntheticYContributionV1 {
        &self.y
    }

    /// Returns the synthetic scalar-domain contribution.
    pub const fn tau(&self) -> &SyntheticTauContributionV1 {
        &self.tau
    }
}

/// Synthetic server contribution owned by Deriver A.
pub struct SyntheticDeriverAServerContributionV1 {
    y: SyntheticYContributionV1,
    tau: SyntheticTauContributionV1,
}

impl SyntheticDeriverAServerContributionV1 {
    /// Returns the synthetic seed-domain contribution.
    pub const fn y(&self) -> &SyntheticYContributionV1 {
        &self.y
    }

    /// Returns the synthetic scalar-domain contribution.
    pub const fn tau(&self) -> &SyntheticTauContributionV1 {
        &self.tau
    }
}

/// Synthetic server contribution owned by Deriver B.
pub struct SyntheticDeriverBServerContributionV1 {
    y: SyntheticYContributionV1,
    tau: SyntheticTauContributionV1,
}

impl SyntheticDeriverBServerContributionV1 {
    /// Returns the synthetic seed-domain contribution.
    pub const fn y(&self) -> &SyntheticYContributionV1 {
        &self.y
    }

    /// Returns the synthetic scalar-domain contribution.
    pub const fn tau(&self) -> &SyntheticTauContributionV1 {
        &self.tau
    }
}

/// Synthetic client contributions split across the two fixed Deriver roles.
pub struct SyntheticClientContributionsV1 {
    deriver_a: SyntheticDeriverAClientContributionV1,
    deriver_b: SyntheticDeriverBClientContributionV1,
}

impl SyntheticClientContributionsV1 {
    /// Returns the client contribution addressed to Deriver A.
    pub const fn deriver_a(&self) -> &SyntheticDeriverAClientContributionV1 {
        &self.deriver_a
    }

    /// Returns the client contribution addressed to Deriver B.
    pub const fn deriver_b(&self) -> &SyntheticDeriverBClientContributionV1 {
        &self.deriver_b
    }
}

/// Derives both role-separated synthetic client contributions.
pub fn derive_synthetic_client_contributions_v1(
    root: &SyntheticClientDerivationRootV1,
    context: &StableKeyDerivationContext,
) -> SyntheticClientContributionsV1 {
    let deriver_a = derive_synthetic_contribution_v1(
        &root.0,
        context,
        CONTRIBUTION_KDF_ROLE_A_TAG_V1,
        CONTRIBUTION_KDF_CLIENT_SOURCE_TAG_V1,
    );
    let deriver_b = derive_synthetic_contribution_v1(
        &root.0,
        context,
        CONTRIBUTION_KDF_ROLE_B_TAG_V1,
        CONTRIBUTION_KDF_CLIENT_SOURCE_TAG_V1,
    );

    SyntheticClientContributionsV1 {
        deriver_a: SyntheticDeriverAClientContributionV1 {
            y: deriver_a.y,
            tau: deriver_a.tau,
        },
        deriver_b: SyntheticDeriverBClientContributionV1 {
            y: deriver_b.y,
            tau: deriver_b.tau,
        },
    }
}

/// Derives Deriver A's synthetic server contribution.
///
/// ```compile_fail
/// use ed25519_yao_generator::{
///     derive_synthetic_deriver_a_server_contribution_v1,
///     StableKeyDerivationContext, SyntheticDeriverBDerivationRootV1,
/// };
///
/// let context = StableKeyDerivationContext::new([0x42; 32], 1, 2).unwrap();
/// let wrong_root = SyntheticDeriverBDerivationRootV1::from_fixture_bytes([7; 32]);
/// let _ = derive_synthetic_deriver_a_server_contribution_v1(&wrong_root, &context);
/// ```
pub fn derive_synthetic_deriver_a_server_contribution_v1(
    root: &SyntheticDeriverADerivationRootV1,
    context: &StableKeyDerivationContext,
) -> SyntheticDeriverAServerContributionV1 {
    let contribution = derive_synthetic_contribution_v1(
        &root.0,
        context,
        CONTRIBUTION_KDF_ROLE_A_TAG_V1,
        CONTRIBUTION_KDF_SERVER_SOURCE_TAG_V1,
    );
    SyntheticDeriverAServerContributionV1 {
        y: contribution.y,
        tau: contribution.tau,
    }
}

/// Derives Deriver B's synthetic server contribution.
pub fn derive_synthetic_deriver_b_server_contribution_v1(
    root: &SyntheticDeriverBDerivationRootV1,
    context: &StableKeyDerivationContext,
) -> SyntheticDeriverBServerContributionV1 {
    let contribution = derive_synthetic_contribution_v1(
        &root.0,
        context,
        CONTRIBUTION_KDF_ROLE_B_TAG_V1,
        CONTRIBUTION_KDF_SERVER_SOURCE_TAG_V1,
    );
    SyntheticDeriverBServerContributionV1 {
        y: contribution.y,
        tau: contribution.tau,
    }
}

struct SyntheticContributionV1 {
    y: SyntheticYContributionV1,
    tau: SyntheticTauContributionV1,
}

fn derive_synthetic_contribution_v1(
    root: &[u8; 32],
    context: &StableKeyDerivationContext,
    role_tag: u8,
    source_tag: u8,
) -> SyntheticContributionV1 {
    let hkdf = Hkdf::<Sha256>::new(Some(CONTRIBUTION_KDF_EXTRACT_SALT_V1), root);
    let context_binding = context.binding_digest();

    let y_info = contribution_expand_info_v1(
        role_tag,
        source_tag,
        CONTRIBUTION_KDF_Y_OUTPUT_TAG_V1,
        context_binding.as_bytes(),
    );
    let mut y = [0u8; 32];
    hkdf.expand(&y_info, &mut y)
        .expect("32-byte output is valid for HKDF-SHA256");

    let tau_info = contribution_expand_info_v1(
        role_tag,
        source_tag,
        CONTRIBUTION_KDF_TAU_OUTPUT_TAG_V1,
        context_binding.as_bytes(),
    );
    let mut tau_wide = [0u8; 64];
    hkdf.expand(&tau_info, &mut tau_wide)
        .expect("64-byte output is valid for HKDF-SHA256");
    let tau = Scalar::from_bytes_mod_order_wide(&tau_wide).to_bytes();

    SyntheticContributionV1 {
        y: SyntheticYContributionV1(y),
        tau: SyntheticTauContributionV1(tau),
    }
}

pub(crate) fn contribution_expand_info_v1(
    role_tag: u8,
    source_tag: u8,
    output_tag: u8,
    context_binding: &[u8; 32],
) -> [u8; CONTRIBUTION_KDF_EXPAND_INFO_LEN_V1] {
    let mut info = [0u8; CONTRIBUTION_KDF_EXPAND_INFO_LEN_V1];
    let domain_end = CONTRIBUTION_KDF_EXPAND_INFO_DOMAIN_V1.len();
    info[..domain_end].copy_from_slice(CONTRIBUTION_KDF_EXPAND_INFO_DOMAIN_V1);
    info[domain_end] = 0x00;
    info[domain_end + 1] = role_tag;
    info[domain_end + 2] = source_tag;
    info[domain_end + 3] = output_tag;
    info[domain_end + 4..].copy_from_slice(context_binding);
    info
}
