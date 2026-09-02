use core::fmt;

use hpke_ng::{Aes256Gcm, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};
use rand_chacha::ChaCha20Rng as ProofRng;
use rand_chacha_09::ChaCha20Rng as HpkeRng;
use rand_core::SeedableRng as SeedableRng06;
use rand_core_09::SeedableRng as SeedableRng09;
use signer_core::ed25519_yao_derivation::{
    derive_ed25519_yao_deriver_a_server_contribution_v1,
    derive_ed25519_yao_deriver_b_server_contribution_v1, Ed25519YaoDeriverADerivationRootV1,
    Ed25519YaoDeriverAServerContributionV1, Ed25519YaoDeriverBDerivationRootV1,
    Ed25519YaoDeriverBServerContributionV1, Ed25519YaoStableKeyDerivationContextV1,
};
use threshold_prf::{
    complete_ed25519_deriver_a_target_v1, complete_ed25519_deriver_b_target_v1,
    prepare_ed25519_deriver_a_target_v1, prepare_ed25519_deriver_b_target_v1,
    Ed25519DeriverAToBTargetProofBundleV1, Ed25519DeriverBToATargetProofBundleV1,
    PreparedEd25519DeriverATargetV1, PreparedEd25519DeriverBTargetV1, SigningRootShare,
    SigningRootShareCommitment, ThresholdShareId,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

type PrefaceHpke = Hpke<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>;

const WIRE_MAGIC: &[u8; 8] = b"R120PRF1";
const HPKE_INFO: &[u8] = b"seams/r120/ed25519-role-target-preface/v1";
const PROOF_PLAINTEXT_LEN: usize = Ed25519DeriverAToBTargetProofBundleV1::LEN;
const HPKE_TAG_LEN: usize = 16;
const CIPHERTEXT_LEN: usize = PROOF_PLAINTEXT_LEN + HPKE_TAG_LEN;
const AAD_LEN: usize = 130;
const ENCAPSULATED_KEY_LEN: usize = 32;
const WIRE_LEN: usize = AAD_LEN + ENCAPSULATED_KEY_LEN + CIPHERTEXT_LEN;
const A_SHARE_ID: u16 = 1;
const B_SHARE_ID: u16 = 2;
const BENCHMARK_EXPIRY_MS: u64 = u64::MAX;
const ROLE_A: u8 = 1;
const ROLE_B: u8 = 2;
const RECIPIENT_A_IKM: [u8; 32] = [0xA2; 32];
const RECIPIENT_B_IKM: [u8; 32] = [0xB2; 32];
const FIXTURE_A_COMMITMENT: [u8; SigningRootShareCommitment::LEN] = [
    0x00, 0x01, 0xe4, 0x54, 0x9e, 0xe1, 0x6b, 0x9a, 0xa0, 0x30, 0x99, 0xca, 0x20, 0x8c, 0x67, 0xad,
    0xaf, 0xca, 0xfa, 0x4c, 0x3f, 0x3e, 0x4e, 0x53, 0x03, 0xde, 0x60, 0x26, 0xe3, 0xca, 0x8f, 0xf8,
    0x44, 0x60,
];
const FIXTURE_B_COMMITMENT: [u8; SigningRootShareCommitment::LEN] = [
    0x00, 0x02, 0x4c, 0xf1, 0xb9, 0xde, 0xda, 0x93, 0xeb, 0x9f, 0xd5, 0x15, 0xfc, 0xc9, 0x92, 0x62,
    0xae, 0xd1, 0x36, 0x8b, 0x48, 0xf2, 0x4a, 0x27, 0xaf, 0xd2, 0x98, 0x4d, 0xa8, 0xfe, 0x7b, 0xb2,
    0x34, 0x1f,
];
const DIRECT_DERIVER_A_Y: [u8; 32] = [
    0x26, 0x35, 0x4f, 0x82, 0xb3, 0x86, 0x0a, 0x84, 0xb4, 0x4e, 0xdd, 0x57, 0xc9, 0x78, 0x07, 0x84,
    0x8c, 0xda, 0xad, 0x26, 0x37, 0xd3, 0x95, 0x25, 0x06, 0x5f, 0xc3, 0x99, 0x49, 0x2f, 0x9e, 0xb2,
];
const DIRECT_DERIVER_A_TAU: [u8; 32] = [
    0xc3, 0x83, 0x57, 0xa5, 0x1a, 0x1f, 0x70, 0x43, 0xe0, 0x85, 0x5f, 0x81, 0xaf, 0x94, 0xf8, 0x00,
    0x94, 0xa3, 0x30, 0xff, 0x86, 0x9f, 0x2c, 0x19, 0x80, 0x3a, 0x9a, 0xd2, 0xc9, 0xe0, 0x69, 0x01,
];
const DIRECT_DERIVER_B_Y: [u8; 32] = [
    0x75, 0x6c, 0xa8, 0x5a, 0x15, 0xcc, 0xd7, 0x98, 0x63, 0x20, 0x65, 0xa9, 0xb2, 0x72, 0x57, 0x6e,
    0x37, 0xfd, 0x1a, 0x98, 0xcd, 0x62, 0xb9, 0xe3, 0x4c, 0x9d, 0xc7, 0x6b, 0x42, 0x5e, 0x93, 0x02,
];
const DIRECT_DERIVER_B_TAU: [u8; 32] = [
    0xc3, 0x4e, 0xad, 0xf3, 0x19, 0x65, 0x2e, 0xcd, 0xde, 0x3c, 0x87, 0x25, 0xeb, 0x6f, 0xa5, 0x4f,
    0x54, 0x64, 0x50, 0xa3, 0x33, 0xd2, 0xaa, 0x8a, 0xc6, 0x28, 0x31, 0xd5, 0x70, 0xbb, 0xda, 0x02,
];

/// Fixed outer binding for one benchmark-only PRF preface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PrefaceBinding {
    session: [u8; 32],
    stable_context_digest: [u8; 32],
    custody_binding_digest: [u8; 32],
}

impl PrefaceBinding {
    /// Creates a benchmark binding from the Yao session and stable context.
    pub(crate) fn new(
        session: [u8; 32],
        stable_context: &Ed25519YaoStableKeyDerivationContextV1,
        custody_binding_digest: [u8; 32],
    ) -> Result<Self, PrefaceError> {
        if session.iter().all(|byte| *byte == 0)
            || custody_binding_digest.iter().all(|byte| *byte == 0)
        {
            return Err(PrefaceError::InvalidBinding);
        }
        Ok(Self {
            session,
            stable_context_digest: stable_context.binding_digest(),
            custody_binding_digest,
        })
    }
}

/// One exact encrypted A-to-B proof bundle.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct DeriverAToBProofBundle(#[zeroize] [u8; WIRE_LEN]);

/// One exact encrypted B-to-A proof bundle.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct DeriverBToAProofBundle(#[zeroize] [u8; WIRE_LEN]);

impl DeriverAToBProofBundle {
    /// Returns the exact encrypted wire bytes.
    pub(crate) fn as_bytes(&self) -> &[u8; WIRE_LEN] {
        &self.0
    }

    /// Parses one exact encrypted wire bundle.
    #[cfg(any(
        feature = "deriver-b-cross-account",
        feature = "deriver-b-same-account-websocket"
    ))]
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, PrefaceError> {
        let bytes = bytes.try_into().map_err(|_| PrefaceError::InvalidWire)?;
        Ok(Self(bytes))
    }
}

impl DeriverBToAProofBundle {
    /// Returns the exact encrypted wire bytes.
    pub(crate) fn as_bytes(&self) -> &[u8; WIRE_LEN] {
        &self.0
    }

    /// Parses one exact encrypted wire bundle.
    #[cfg(any(
        feature = "deriver-a-cross-account",
        feature = "deriver-a-same-account-websocket",
        test
    ))]
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, PrefaceError> {
        let bytes = bytes.try_into().map_err(|_| PrefaceError::InvalidWire)?;
        Ok(Self(bytes))
    }
}

/// Deriver A state after producing its single outbound proof bundle.
pub(crate) struct PreparedDeriverA {
    binding: PrefaceBinding,
    target: PreparedEd25519DeriverATargetV1,
}

/// Deriver B state after producing its single outbound proof bundle.
pub(crate) struct PreparedDeriverB {
    binding: PrefaceBinding,
    target: PreparedEd25519DeriverBTargetV1,
}

/// Benchmark-only role-target preface failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrefaceError {
    /// The stable or custody binding is invalid.
    InvalidBinding,
    /// The role share or expected commitment is invalid.
    InvalidShare,
    /// The fixed wire envelope is malformed or role-swapped.
    InvalidWire,
    /// Platform randomness was unavailable.
    Randomness,
    /// Recipient encryption or opening failed.
    Encryption,
    /// Threshold-PRF proof verification or combine failed.
    Proof,
    /// The existing Ed25519 contribution KDF failed.
    ContributionKdf,
}

impl fmt::Display for PrefaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidBinding => "invalid R120 benchmark preface binding",
            Self::InvalidShare => "invalid R120 benchmark root share",
            Self::InvalidWire => "invalid R120 benchmark preface wire bundle",
            Self::Randomness => "R120 benchmark preface randomness unavailable",
            Self::Encryption => "R120 benchmark preface encryption failed",
            Self::Proof => "R120 benchmark threshold PRF proof failed",
            Self::ContributionKdf => "R120 benchmark contribution KDF failed",
        })
    }
}

impl std::error::Error for PrefaceError {}

/// Exact serialized byte length of one encrypted proof bundle.
pub(crate) const fn proof_bundle_wire_len() -> usize {
    WIRE_LEN
}

/// Returns the fixed benchmark stable derivation context.
pub(crate) fn benchmark_stable_context(
) -> Result<Ed25519YaoStableKeyDerivationContextV1, PrefaceError> {
    Ed25519YaoStableKeyDerivationContextV1::new([0x42; 32], A_SHARE_ID, B_SHARE_ID)
        .map_err(|_| PrefaceError::InvalidBinding)
}

/// Returns Deriver A's fixed benchmark-only 2-of-2 root share.
pub(crate) fn benchmark_share_a() -> Result<SigningRootShare, PrefaceError> {
    benchmark_share(A_SHARE_ID, 12)
}

/// Returns Deriver B's fixed benchmark-only 2-of-2 root share.
pub(crate) fn benchmark_share_b() -> Result<SigningRootShare, PrefaceError> {
    benchmark_share(B_SHARE_ID, 19)
}

/// Prepares Deriver A's local A-target partial and encrypted B-target bundle.
pub(crate) fn prepare_deriver_a(
    share: &SigningRootShare,
    expected_peer_commitment: [u8; SigningRootShareCommitment::LEN],
    stable_context: &Ed25519YaoStableKeyDerivationContextV1,
    binding: PrefaceBinding,
) -> Result<(PreparedDeriverA, DeriverAToBProofBundle), PrefaceError> {
    require_stable_context(stable_context, binding)?;
    let commitment = SigningRootShareCommitment::from_bytes(expected_peer_commitment)
        .map_err(|_| PrefaceError::InvalidShare)?;
    let mut rng = proof_rng()?;
    let (target, outgoing) =
        prepare_ed25519_deriver_a_target_v1(share, commitment, &stable_context.encode(), &mut rng)
            .map_err(|_| PrefaceError::Proof)?;
    let wire = seal_bundle(
        ROLE_A,
        ROLE_B,
        binding,
        outgoing.as_bytes(),
        &RECIPIENT_B_IKM,
    )?;
    Ok((
        PreparedDeriverA { binding, target },
        DeriverAToBProofBundle(wire),
    ))
}

/// Prepares Deriver B's local B-target partial and encrypted A-target bundle.
pub(crate) fn prepare_deriver_b(
    share: &SigningRootShare,
    expected_peer_commitment: [u8; SigningRootShareCommitment::LEN],
    stable_context: &Ed25519YaoStableKeyDerivationContextV1,
    binding: PrefaceBinding,
) -> Result<(PreparedDeriverB, DeriverBToAProofBundle), PrefaceError> {
    require_stable_context(stable_context, binding)?;
    let commitment = SigningRootShareCommitment::from_bytes(expected_peer_commitment)
        .map_err(|_| PrefaceError::InvalidShare)?;
    let mut rng = proof_rng()?;
    let (target, outgoing) =
        prepare_ed25519_deriver_b_target_v1(share, commitment, &stable_context.encode(), &mut rng)
            .map_err(|_| PrefaceError::Proof)?;
    let wire = seal_bundle(
        ROLE_B,
        ROLE_A,
        binding,
        outgoing.as_bytes(),
        &RECIPIENT_A_IKM,
    )?;
    Ok((
        PreparedDeriverB { binding, target },
        DeriverBToAProofBundle(wire),
    ))
}

/// Completes Deriver A's target and runs the existing role-local contribution KDF.
pub(crate) fn complete_deriver_a(
    prepared: PreparedDeriverA,
    incoming: &DeriverBToAProofBundle,
    stable_context: &Ed25519YaoStableKeyDerivationContextV1,
) -> Result<Ed25519YaoDeriverAServerContributionV1, PrefaceError> {
    require_stable_context(stable_context, prepared.binding)?;
    let plaintext = open_bundle(
        incoming.as_bytes(),
        ROLE_B,
        ROLE_A,
        prepared.binding,
        &RECIPIENT_A_IKM,
    )?;
    let incoming = Ed25519DeriverBToATargetProofBundleV1::from_slice(&plaintext)
        .map_err(|_| PrefaceError::Proof)?;
    let output = complete_ed25519_deriver_a_target_v1(prepared.target, &incoming)
        .map_err(|_| PrefaceError::Proof)?
        .into_secret_bytes();
    derive_ed25519_yao_deriver_a_server_contribution_v1(
        &Ed25519YaoDeriverADerivationRootV1::from_secret_bytes(*output),
        stable_context,
    )
    .map_err(|_| PrefaceError::ContributionKdf)
}

/// Completes Deriver B's target and runs the existing role-local contribution KDF.
pub(crate) fn complete_deriver_b(
    prepared: PreparedDeriverB,
    incoming: &DeriverAToBProofBundle,
    stable_context: &Ed25519YaoStableKeyDerivationContextV1,
) -> Result<Ed25519YaoDeriverBServerContributionV1, PrefaceError> {
    require_stable_context(stable_context, prepared.binding)?;
    let plaintext = open_bundle(
        incoming.as_bytes(),
        ROLE_A,
        ROLE_B,
        prepared.binding,
        &RECIPIENT_B_IKM,
    )?;
    let incoming = Ed25519DeriverAToBTargetProofBundleV1::from_slice(&plaintext)
        .map_err(|_| PrefaceError::Proof)?;
    let output = complete_ed25519_deriver_b_target_v1(prepared.target, &incoming)
        .map_err(|_| PrefaceError::Proof)?
        .into_secret_bytes();
    derive_ed25519_yao_deriver_b_server_contribution_v1(
        &Ed25519YaoDeriverBDerivationRootV1::from_secret_bytes(*output),
        stable_context,
    )
    .map_err(|_| PrefaceError::ContributionKdf)
}

/// Returns the fixed public commitment expected by Deriver A.
pub(crate) const fn benchmark_peer_commitment_for_a() -> [u8; SigningRootShareCommitment::LEN] {
    FIXTURE_B_COMMITMENT
}

/// Returns the fixed public commitment expected by Deriver B.
pub(crate) const fn benchmark_peer_commitment_for_b() -> [u8; SigningRootShareCommitment::LEN] {
    FIXTURE_A_COMMITMENT
}

/// Returns the direct-reference Deriver A contribution used by the baseline cohort.
pub(crate) const fn benchmark_direct_deriver_a_contribution() -> ([u8; 32], [u8; 32]) {
    (DIRECT_DERIVER_A_Y, DIRECT_DERIVER_A_TAU)
}

/// Returns the direct-reference Deriver B contribution used by the baseline cohort.
pub(crate) const fn benchmark_direct_deriver_b_contribution() -> ([u8; 32], [u8; 32]) {
    (DIRECT_DERIVER_B_Y, DIRECT_DERIVER_B_TAU)
}

fn benchmark_share(id: u16, scalar: u8) -> Result<SigningRootShare, PrefaceError> {
    let mut bytes = [0_u8; 32];
    bytes[0] = scalar;
    SigningRootShare::from_canonical_bytes(
        ThresholdShareId::from_u16(id).map_err(|_| PrefaceError::InvalidShare)?,
        bytes,
    )
    .map_err(|_| PrefaceError::InvalidShare)
}

fn require_stable_context(
    stable_context: &Ed25519YaoStableKeyDerivationContextV1,
    binding: PrefaceBinding,
) -> Result<(), PrefaceError> {
    if stable_context.binding_digest() == binding.stable_context_digest {
        Ok(())
    } else {
        Err(PrefaceError::InvalidBinding)
    }
}

fn proof_rng() -> Result<ProofRng, PrefaceError> {
    let mut seed = [0_u8; 32];
    getrandom::getrandom(&mut seed).map_err(|_| PrefaceError::Randomness)?;
    Ok(ProofRng::from_seed(seed))
}

fn hpke_rng() -> Result<HpkeRng, PrefaceError> {
    let mut seed = [0_u8; 32];
    getrandom::getrandom(&mut seed).map_err(|_| PrefaceError::Randomness)?;
    Ok(HpkeRng::from_seed(seed))
}

fn random_nonce() -> Result<[u8; 16], PrefaceError> {
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| PrefaceError::Randomness)?;
    if nonce.iter().all(|byte| *byte == 0) {
        return Err(PrefaceError::Randomness);
    }
    Ok(nonce)
}

fn seal_bundle(
    source: u8,
    target: u8,
    binding: PrefaceBinding,
    plaintext: &[u8; PROOF_PLAINTEXT_LEN],
    recipient_ikm: &[u8; 32],
) -> Result<[u8; WIRE_LEN], PrefaceError> {
    let mut wire = [0_u8; WIRE_LEN];
    write_aad(
        &mut wire[..AAD_LEN],
        source,
        target,
        binding,
        random_nonce()?,
    )?;
    let (_, public_key) = DhKemX25519HkdfSha256::derive_key_pair(recipient_ikm)
        .map_err(|_| PrefaceError::Encryption)?;
    let mut rng = hpke_rng()?;
    let (encapsulated_key, ciphertext) = PrefaceHpke::seal_base(
        &mut rng,
        &public_key,
        HPKE_INFO,
        &wire[..AAD_LEN],
        plaintext,
    )
    .map_err(|_| PrefaceError::Encryption)?;
    if encapsulated_key.as_ref().len() != ENCAPSULATED_KEY_LEN || ciphertext.len() != CIPHERTEXT_LEN
    {
        return Err(PrefaceError::Encryption);
    }
    wire[AAD_LEN..AAD_LEN + ENCAPSULATED_KEY_LEN].copy_from_slice(encapsulated_key.as_ref());
    wire[AAD_LEN + ENCAPSULATED_KEY_LEN..].copy_from_slice(&ciphertext);
    Ok(wire)
}

fn write_aad(
    aad: &mut [u8],
    source: u8,
    target: u8,
    binding: PrefaceBinding,
    nonce: [u8; 16],
) -> Result<(), PrefaceError> {
    if aad.len() != AAD_LEN || source == target || !matches!(source, ROLE_A | ROLE_B) {
        return Err(PrefaceError::InvalidWire);
    }
    aad[..8].copy_from_slice(WIRE_MAGIC);
    aad[8] = source;
    aad[9] = target;
    aad[10..42].copy_from_slice(&binding.session);
    aad[42..74].copy_from_slice(&binding.stable_context_digest);
    aad[74..106].copy_from_slice(&binding.custody_binding_digest);
    aad[106..122].copy_from_slice(&nonce);
    aad[122..130].copy_from_slice(&BENCHMARK_EXPIRY_MS.to_be_bytes());
    Ok(())
}

fn open_bundle(
    wire: &[u8; WIRE_LEN],
    expected_source: u8,
    expected_target: u8,
    binding: PrefaceBinding,
    recipient_ikm: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, PrefaceError> {
    validate_aad(&wire[..AAD_LEN], expected_source, expected_target, binding)?;
    let encapsulated_key =
        DhKemX25519HkdfSha256::enc_from_bytes(&wire[AAD_LEN..AAD_LEN + ENCAPSULATED_KEY_LEN])
            .map_err(|_| PrefaceError::Encryption)?;
    let (private_key, _) = DhKemX25519HkdfSha256::derive_key_pair(recipient_ikm)
        .map_err(|_| PrefaceError::Encryption)?;
    PrefaceHpke::open_base(
        &encapsulated_key,
        &private_key,
        HPKE_INFO,
        &wire[..AAD_LEN],
        &wire[AAD_LEN + ENCAPSULATED_KEY_LEN..],
    )
    .map(Zeroizing::new)
    .map_err(|_| PrefaceError::Encryption)
}

fn validate_aad(
    aad: &[u8],
    expected_source: u8,
    expected_target: u8,
    binding: PrefaceBinding,
) -> Result<(), PrefaceError> {
    if aad.len() != AAD_LEN
        || &aad[..8] != WIRE_MAGIC
        || aad[8] != expected_source
        || aad[9] != expected_target
        || aad[10..42] != binding.session
        || aad[42..74] != binding.stable_context_digest
        || aad[74..106] != binding.custody_binding_digest
        || aad[106..122].iter().all(|byte| *byte == 0)
        || aad[122..130] != BENCHMARK_EXPIRY_MS.to_be_bytes()
    {
        return Err(PrefaceError::InvalidWire);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use signer_core::ed25519_yao_derivation::{
        derive_ed25519_yao_deriver_a_server_contribution_v1,
        derive_ed25519_yao_deriver_b_server_contribution_v1,
    };
    use threshold_prf::reference::evaluate_direct_reference;
    use threshold_prf::{PrfContext, PrfPurpose, SigningRootScalar, SuiteId};

    fn binding(stable_context: &Ed25519YaoStableKeyDerivationContextV1) -> PrefaceBinding {
        PrefaceBinding::new([0x51; 32], stable_context, [0x61; 32]).expect("binding")
    }

    fn alternate_shares() -> (SigningRootShare, SigningRootShare) {
        (
            benchmark_share(A_SHARE_ID, 16).expect("alternate A"),
            benchmark_share(B_SHARE_ID, 27).expect("alternate B"),
        )
    }

    fn commitment(share: &SigningRootShare) -> [u8; SigningRootShareCommitment::LEN] {
        SigningRootShareCommitment::from_share(share).to_bytes()
    }

    fn target_context(
        purpose: PrfPurpose,
        stable_context: &Ed25519YaoStableKeyDerivationContextV1,
    ) -> PrfContext {
        PrfContext::new(
            SuiteId::Ristretto255Sha512,
            purpose,
            stable_context.encode(),
        )
    }

    #[test]
    fn one_flight_matches_direct_role_targets_and_wire_budget() {
        let stable_context = benchmark_stable_context().expect("stable context");
        let binding = binding(&stable_context);
        let share_a = benchmark_share_a().expect("share A");
        let share_b = benchmark_share_b().expect("share B");
        let (prepared_a, a_to_b) =
            prepare_deriver_a(&share_a, commitment(&share_b), &stable_context, binding)
                .expect("prepare A");
        let (prepared_b, b_to_a) =
            prepare_deriver_b(&share_b, commitment(&share_a), &stable_context, binding)
                .expect("prepare B");
        let contribution_a =
            complete_deriver_a(prepared_a, &b_to_a, &stable_context).expect("complete A");
        let contribution_b =
            complete_deriver_b(prepared_b, &a_to_b, &stable_context).expect("complete B");

        let mut root_bytes = [0_u8; 32];
        root_bytes[0] = 5;
        let root = SigningRootScalar::from_canonical_bytes(root_bytes).expect("root");
        let context_a =
            target_context(PrfPurpose::Ed25519DeriverAContributionRoot, &stable_context);
        let context_b =
            target_context(PrfPurpose::Ed25519DeriverBContributionRoot, &stable_context);
        let direct_a = evaluate_direct_reference(&root, &context_a).expect("direct A");
        let direct_b = evaluate_direct_reference(&root, &context_b).expect("direct B");
        let expected_a = derive_ed25519_yao_deriver_a_server_contribution_v1(
            &Ed25519YaoDeriverADerivationRootV1::from_secret_bytes(direct_a.into_bytes()),
            &stable_context,
        )
        .expect("expected A");
        let expected_b = derive_ed25519_yao_deriver_b_server_contribution_v1(
            &Ed25519YaoDeriverBDerivationRootV1::from_secret_bytes(direct_b.into_bytes()),
            &stable_context,
        )
        .expect("expected B");

        let (actual_a_y, actual_a_tau) = contribution_a.into_parts();
        let (expected_a_y, expected_a_tau) = expected_a.into_parts();
        let actual_a_y = actual_a_y.into_bytes();
        let actual_a_tau = actual_a_tau.into_bytes();
        assert_eq!(actual_a_y, expected_a_y.into_bytes());
        assert_eq!(actual_a_tau, expected_a_tau.into_bytes());
        assert_eq!(
            (actual_a_y, actual_a_tau),
            benchmark_direct_deriver_a_contribution()
        );
        let (actual_b_y, actual_b_tau) = contribution_b.into_parts();
        let (expected_b_y, expected_b_tau) = expected_b.into_parts();
        let actual_b_y = actual_b_y.into_bytes();
        let actual_b_tau = actual_b_tau.into_bytes();
        assert_eq!(actual_b_y, expected_b_y.into_bytes());
        assert_eq!(actual_b_tau, expected_b_tau.into_bytes());
        assert_eq!(
            (actual_b_y, actual_b_tau),
            benchmark_direct_deriver_b_contribution()
        );
        assert_eq!(proof_bundle_wire_len(), WIRE_LEN);
        assert!(2 * proof_bundle_wire_len() < 4096);
    }

    #[test]
    fn resharing_preserves_both_role_contributions() {
        let stable_context = benchmark_stable_context().expect("stable context");
        let binding = binding(&stable_context);
        let (share_a, share_b) = alternate_shares();
        let (prepared_a, a_to_b) =
            prepare_deriver_a(&share_a, commitment(&share_b), &stable_context, binding)
                .expect("prepare A");
        let (prepared_b, b_to_a) =
            prepare_deriver_b(&share_b, commitment(&share_a), &stable_context, binding)
                .expect("prepare B");
        let refreshed_a =
            complete_deriver_a(prepared_a, &b_to_a, &stable_context).expect("complete A");
        let refreshed_b =
            complete_deriver_b(prepared_b, &a_to_b, &stable_context).expect("complete B");

        let original_a = {
            let share_a = benchmark_share_a().expect("share A");
            let share_b = benchmark_share_b().expect("share B");
            let (prepared_a, _) =
                prepare_deriver_a(&share_a, commitment(&share_b), &stable_context, binding)
                    .expect("prepare original A");
            let (_, b_to_a) =
                prepare_deriver_b(&share_b, commitment(&share_a), &stable_context, binding)
                    .expect("prepare original B");
            complete_deriver_a(prepared_a, &b_to_a, &stable_context).expect("original A")
        };
        let original_b = {
            let share_a = benchmark_share_a().expect("share A");
            let share_b = benchmark_share_b().expect("share B");
            let (_, a_to_b) =
                prepare_deriver_a(&share_a, commitment(&share_b), &stable_context, binding)
                    .expect("prepare original A");
            let (prepared_b, _) =
                prepare_deriver_b(&share_b, commitment(&share_a), &stable_context, binding)
                    .expect("prepare original B");
            complete_deriver_b(prepared_b, &a_to_b, &stable_context).expect("original B")
        };

        let (refreshed_a_y, refreshed_a_tau) = refreshed_a.into_parts();
        let (original_a_y, original_a_tau) = original_a.into_parts();
        assert_eq!(refreshed_a_y.into_bytes(), original_a_y.into_bytes());
        assert_eq!(refreshed_a_tau.into_bytes(), original_a_tau.into_bytes());
        let (refreshed_b_y, refreshed_b_tau) = refreshed_b.into_parts();
        let (original_b_y, original_b_tau) = original_b.into_parts();
        assert_eq!(refreshed_b_y.into_bytes(), original_b_y.into_bytes());
        assert_eq!(refreshed_b_tau.into_bytes(), original_b_tau.into_bytes());
    }

    #[test]
    fn direction_binding_and_ciphertext_mutation_fail_closed() {
        let stable_context = benchmark_stable_context().expect("stable context");
        let binding = binding(&stable_context);
        let share_a = benchmark_share_a().expect("share A");
        let share_b = benchmark_share_b().expect("share B");
        let (prepared_a, a_to_b) =
            prepare_deriver_a(&share_a, commitment(&share_b), &stable_context, binding)
                .expect("prepare A");
        assert!(matches!(
            DeriverBToAProofBundle::decode(a_to_b.as_bytes())
                .and_then(|bundle| complete_deriver_a(prepared_a, &bundle, &stable_context)),
            Err(PrefaceError::InvalidWire)
        ));

        let (prepared_a, _) =
            prepare_deriver_a(&share_a, commitment(&share_b), &stable_context, binding)
                .expect("prepare A again");
        let (_, b_to_a) =
            prepare_deriver_b(&share_b, commitment(&share_a), &stable_context, binding)
                .expect("prepare B");
        let mut mutated = *b_to_a.as_bytes();
        mutated[WIRE_LEN - 1] ^= 1;
        let mutated = DeriverBToAProofBundle::decode(&mutated).expect("fixed wire");
        assert!(matches!(
            complete_deriver_a(prepared_a, &mutated, &stable_context),
            Err(PrefaceError::Encryption)
        ));
    }

    #[test]
    fn fixed_fixture_commitments_match_role_shares() {
        assert_eq!(
            commitment(&benchmark_share_a().expect("share A")),
            benchmark_peer_commitment_for_b()
        );
        assert_eq!(
            commitment(&benchmark_share_b().expect("share B")),
            benchmark_peer_commitment_for_a()
        );
    }
}
