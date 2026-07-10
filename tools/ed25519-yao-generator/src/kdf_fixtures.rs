//! Portable synthetic contribution-KDF continuity vectors.
//!
//! Roots, contributions, and joined traces in this module are public synthetic
//! fixtures. Production wallet or Deriver material is forbidden.

use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

use crate::{
    derive_synthetic_client_contributions_v1, derive_synthetic_deriver_a_server_contribution_v1,
    derive_synthetic_deriver_b_server_contribution_v1, evaluate_activation, wrapping_add_le_256,
    DeriverAContribution, DeriverBContribution, OracleMaterial, RawDeriverAContribution,
    RawDeriverBContribution, StableKeyDerivationContext, SyntheticClientDerivationRootV1,
    SyntheticDeriverADerivationRootV1, SyntheticDeriverBDerivationRootV1,
};

/// Schema identifier for the version-one contribution-KDF corpus.
pub const KDF_VECTOR_CORPUS_SCHEMA_V1: &str =
    "seams:router-ab:ed25519-yao:kdf-continuity-vectors:v1";

const SYNTHETIC_CLIENT_ROOT_V1: [u8; 32] = [0x11; 32];
const SYNTHETIC_DERIVER_A_ROOT_V1: [u8; 32] = [0x22; 32];
const SYNTHETIC_DERIVER_B_ROOT_V1: [u8; 32] = [0x33; 32];
const SYNTHETIC_APPLICATION_BINDING_V1: [u8; 32] = [0x42; 32];

/// Strict portable corpus for contribution-KDF continuity evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfVectorCorpusV1 {
    /// Fixed schema identifier.
    pub schema: String,
    /// Fixed protocol identifier.
    pub protocol_id: String,
    /// Canonical synthetic continuity cases.
    pub cases: Vec<KdfContinuityVectorCaseV1>,
}

/// One complete synthetic KDF-to-public-identity trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfContinuityVectorCaseV1 {
    /// Stable case identifier.
    pub case_id: String,
    /// Public synthetic roots used to reproduce the KDF outputs.
    pub synthetic_roots: KdfSyntheticRootsV1,
    /// Frozen stable-context record and binding.
    pub context: KdfStableContextVectorV1,
    /// All eight role/source-separated KDF outputs.
    pub contributions: KdfContributionVectorV1,
    /// Joined host-only clear trace through the Ed25519 public identity.
    pub synthetic_clear_reference_trace: KdfClearReferenceTraceV1,
}

/// Public synthetic roots for one KDF vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfSyntheticRootsV1 {
    /// Synthetic client derivation root.
    pub client_root_hex: String,
    /// Synthetic Deriver A derivation root.
    pub deriver_a_root_hex: String,
    /// Synthetic Deriver B derivation root.
    pub deriver_b_root_hex: String,
}

/// Frozen stable-context evidence for one KDF vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfStableContextVectorV1 {
    /// SDK-owned immutable application binding digest.
    pub application_binding_digest_hex: String,
    /// Exactly two canonical participant identifiers.
    pub participant_ids: [u16; 2],
    /// Exact stable-context encoding.
    pub encoded_hex: String,
    /// SHA-256 binding of the stable-context encoding.
    pub binding_sha256_hex: String,
}

/// All role/source-separated KDF output encodings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfContributionVectorV1 {
    /// Client seed-domain contribution addressed to Deriver A.
    pub y_client_a_hex: String,
    /// Client scalar-domain contribution addressed to Deriver A.
    pub tau_client_a_hex: String,
    /// Client seed-domain contribution addressed to Deriver B.
    pub y_client_b_hex: String,
    /// Client scalar-domain contribution addressed to Deriver B.
    pub tau_client_b_hex: String,
    /// Server seed-domain contribution owned by Deriver A.
    pub y_server_a_hex: String,
    /// Server scalar-domain contribution owned by Deriver A.
    pub tau_server_a_hex: String,
    /// Server seed-domain contribution owned by Deriver B.
    pub y_server_b_hex: String,
    /// Server scalar-domain contribution owned by Deriver B.
    pub tau_server_b_hex: String,
}

/// Complete joined synthetic trace for independent verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfClearReferenceTraceV1 {
    /// Deriver A's joined `y` input modulo `2^256`.
    pub y_a_hex: String,
    /// Deriver B's joined `y` input modulo `2^256`.
    pub y_b_hex: String,
    /// Joined RFC 8032 seed `d` modulo `2^256`.
    pub joined_seed_hex: String,
    /// Full SHA-512 digest of the joined seed.
    pub sha512_digest_hex: String,
    /// Clamped lower SHA-512 half before scalar reduction.
    pub clamped_scalar_bytes_hex: String,
    /// Canonical reduced Ed25519 scalar `a`.
    pub signing_scalar_hex: String,
    /// Deriver A's joined `tau` input modulo `l`.
    pub tau_a_hex: String,
    /// Deriver B's joined `tau` input modulo `l`.
    pub tau_b_hex: String,
    /// Joined `tau` modulo `l`.
    pub tau_hex: String,
    /// Canonical `a + tau mod l` scalar.
    pub x_client_base_hex: String,
    /// Canonical `a + 2*tau mod l` scalar.
    pub x_server_base_hex: String,
    /// Compressed `[x_client_base]B` point.
    pub x_client_point_hex: String,
    /// Compressed `[x_server_base]B` point.
    pub x_server_point_hex: String,
    /// Standard Ed25519 public key derived from the joined seed.
    pub public_key_hex: String,
}

/// Builds the canonical version-one synthetic KDF continuity corpus.
pub fn canonical_kdf_vector_corpus_v1() -> KdfVectorCorpusV1 {
    let context = StableKeyDerivationContext::new(SYNTHETIC_APPLICATION_BINDING_V1, 2, 1)
        .expect("fixed synthetic context is valid");
    let client_root = SyntheticClientDerivationRootV1::from_fixture_bytes(SYNTHETIC_CLIENT_ROOT_V1);
    let deriver_a_root =
        SyntheticDeriverADerivationRootV1::from_fixture_bytes(SYNTHETIC_DERIVER_A_ROOT_V1);
    let deriver_b_root =
        SyntheticDeriverBDerivationRootV1::from_fixture_bytes(SYNTHETIC_DERIVER_B_ROOT_V1);
    let client = derive_synthetic_client_contributions_v1(&client_root, &context);
    let server_a = derive_synthetic_deriver_a_server_contribution_v1(&deriver_a_root, &context);
    let server_b = derive_synthetic_deriver_b_server_contribution_v1(&deriver_b_root, &context);

    let y_client_a = client.deriver_a().y().expose_fixture_bytes();
    let tau_client_a = client.deriver_a().tau().expose_fixture_bytes();
    let y_client_b = client.deriver_b().y().expose_fixture_bytes();
    let tau_client_b = client.deriver_b().tau().expose_fixture_bytes();
    let y_server_a = server_a.y().expose_fixture_bytes();
    let tau_server_a = server_a.tau().expose_fixture_bytes();
    let y_server_b = server_b.y().expose_fixture_bytes();
    let tau_server_b = server_b.tau().expose_fixture_bytes();

    let deriver_a = DeriverAContribution::try_from(RawDeriverAContribution {
        y_client: y_client_a,
        y_server: y_server_a,
        tau_client: tau_client_a,
        tau_server: tau_server_a,
    })
    .expect("KDF-derived A tau values are canonical");
    let deriver_b = DeriverBContribution::try_from(RawDeriverBContribution {
        y_client: y_client_b,
        y_server: y_server_b,
        tau_client: tau_client_b,
        tau_server: tau_server_b,
    })
    .expect("KDF-derived B tau values are canonical");
    let activation = evaluate_activation(&deriver_a, &deriver_b);

    KdfVectorCorpusV1 {
        schema: KDF_VECTOR_CORPUS_SCHEMA_V1.to_owned(),
        protocol_id: ed25519_yao::PROTOCOL_ID_STR.to_owned(),
        cases: vec![KdfContinuityVectorCaseV1 {
            case_id: "synthetic_kdf_continuity_baseline_v1".to_owned(),
            synthetic_roots: KdfSyntheticRootsV1 {
                client_root_hex: encode_hex(&SYNTHETIC_CLIENT_ROOT_V1),
                deriver_a_root_hex: encode_hex(&SYNTHETIC_DERIVER_A_ROOT_V1),
                deriver_b_root_hex: encode_hex(&SYNTHETIC_DERIVER_B_ROOT_V1),
            },
            context: KdfStableContextVectorV1 {
                application_binding_digest_hex: encode_hex(
                    context.application_binding_digest().as_bytes(),
                ),
                participant_ids: context.participant_ids().as_array(),
                encoded_hex: encode_hex(context.encode().as_bytes()),
                binding_sha256_hex: encode_hex(context.binding_digest().as_bytes()),
            },
            contributions: KdfContributionVectorV1 {
                y_client_a_hex: encode_hex(&y_client_a),
                tau_client_a_hex: encode_hex(&tau_client_a),
                y_client_b_hex: encode_hex(&y_client_b),
                tau_client_b_hex: encode_hex(&tau_client_b),
                y_server_a_hex: encode_hex(&y_server_a),
                tau_server_a_hex: encode_hex(&tau_server_a),
                y_server_b_hex: encode_hex(&y_server_b),
                tau_server_b_hex: encode_hex(&tau_server_b),
            },
            synthetic_clear_reference_trace: clear_reference_trace(
                y_client_a,
                y_server_a,
                y_client_b,
                y_server_b,
                tau_client_a,
                tau_server_a,
                tau_client_b,
                tau_server_b,
                activation.material(),
            ),
        }],
    }
}

#[allow(clippy::too_many_arguments)]
fn clear_reference_trace(
    y_client_a: [u8; 32],
    y_server_a: [u8; 32],
    y_client_b: [u8; 32],
    y_server_b: [u8; 32],
    tau_client_a: [u8; 32],
    tau_server_a: [u8; 32],
    tau_client_b: [u8; 32],
    tau_server_b: [u8; 32],
    material: &OracleMaterial,
) -> KdfClearReferenceTraceV1 {
    let y_a = wrapping_add_le_256(y_client_a, y_server_a);
    let y_b = wrapping_add_le_256(y_client_b, y_server_b);
    let joined_seed = wrapping_add_le_256(y_a, y_b);
    let tau_client_a = canonical_scalar(tau_client_a);
    let tau_server_a = canonical_scalar(tau_server_a);
    let tau_client_b = canonical_scalar(tau_client_b);
    let tau_server_b = canonical_scalar(tau_server_b);
    let tau_a = tau_client_a + tau_server_a;
    let tau_b = tau_client_b + tau_server_b;

    KdfClearReferenceTraceV1 {
        y_a_hex: encode_hex(&y_a),
        y_b_hex: encode_hex(&y_b),
        joined_seed_hex: encode_hex(&joined_seed),
        sha512_digest_hex: encode_hex(&material.sha512_digest().expose_bytes()),
        clamped_scalar_bytes_hex: encode_hex(&material.clamped_scalar_bytes().expose_bytes()),
        signing_scalar_hex: encode_hex(&material.signing_scalar().expose_bytes()),
        tau_a_hex: encode_hex(&tau_a.to_bytes()),
        tau_b_hex: encode_hex(&tau_b.to_bytes()),
        tau_hex: encode_hex(&material.tau().expose_bytes()),
        x_client_base_hex: encode_hex(&material.x_client_base().expose_bytes()),
        x_server_base_hex: encode_hex(&material.x_server_base().expose_bytes()),
        x_client_point_hex: encode_hex(&material.x_client().expose_bytes()),
        x_server_point_hex: encode_hex(&material.x_server().expose_bytes()),
        public_key_hex: encode_hex(&material.public_key().expose_bytes()),
    }
}

fn canonical_scalar(bytes: [u8; 32]) -> Scalar {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .expect("KDF-derived tau is canonical")
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
