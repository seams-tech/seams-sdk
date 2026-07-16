use k256::{
    elliptic_curve::{ff::PrimeField, sec1::ToEncodedPoint},
    AffinePoint, ProjectivePoint, Scalar,
};
use router_ab_ecdsa_presign::proofs::{
    prove_client_dlog_with_nonce, prove_signing_worker_dlog_eq_with_nonce, ClientDLogContext,
    DLogEqStatement, DLogProofKind, DLogStatement, ProofNonce, ProofWitness,
    SigningWorkerDLogEqContext, TripleIndex,
};
use router_ab_ecdsa_wire::{
    CompressedPointBytes, PairContextDigest, PresignPairContext, ScalarBytes, SigningScopeDigest,
};

const EXPECTED_DLOG_COMMITMENT: [u8; 33] = [
    3, 119, 74, 231, 248, 88, 169, 65, 30, 94, 244, 36, 107, 112, 198, 90, 172, 86, 73, 152, 11,
    229, 193, 120, 145, 187, 236, 23, 137, 93, 160, 8, 203,
];
const EXPECTED_DLOG_RESPONSE: [u8; 32] = [
    126, 46, 14, 2, 209, 174, 218, 237, 129, 235, 62, 127, 144, 180, 107, 100, 30, 5, 38, 161, 135,
    174, 28, 74, 86, 147, 209, 81, 247, 147, 49, 242,
];
const EXPECTED_DLOG_EQ_COMMITMENT0: [u8; 33] = [
    3, 222, 253, 234, 76, 219, 103, 119, 80, 164, 32, 254, 232, 7, 234, 207, 33, 235, 152, 152,
    174, 121, 185, 118, 135, 102, 228, 250, 160, 74, 45, 74, 52,
];
const EXPECTED_DLOG_EQ_COMMITMENT1: [u8; 33] = [
    2, 108, 112, 152, 128, 185, 89, 235, 124, 81, 121, 178, 156, 197, 87, 143, 220, 108, 178, 174,
    19, 221, 206, 222, 41, 213, 248, 29, 149, 222, 10, 180, 170,
];
const EXPECTED_DLOG_EQ_RESPONSE: [u8; 32] = [
    88, 174, 242, 88, 50, 219, 131, 208, 61, 228, 125, 44, 78, 178, 94, 17, 72, 12, 192, 158, 128,
    53, 198, 113, 223, 37, 18, 200, 196, 18, 243, 111,
];

fn binding() -> PresignPairContext {
    PresignPairContext::new(
        SigningScopeDigest::new([0x24; 32]),
        PairContextDigest::new([0x42; 32]),
    )
}

fn scalar_bytes(scalar: Scalar) -> ScalarBytes {
    ScalarBytes::new(scalar.to_bytes().into())
}

fn point_bytes(point: AffinePoint) -> CompressedPointBytes {
    let encoded = point.to_encoded_point(true);
    let bytes: [u8; 33] = encoded
        .as_bytes()
        .try_into()
        .expect("compressed secp256k1 points have fixed width");
    CompressedPointBytes::new(bytes)
}

fn generator_multiple(scalar: Scalar) -> CompressedPointBytes {
    point_bytes((ProjectivePoint::GENERATOR * scalar).to_affine())
}

fn witness(scalar: Scalar) -> ProofWitness {
    ProofWitness::from_bytes(scalar_bytes(scalar)).expect("valid witness")
}

fn nonce(scalar: Scalar) -> ProofNonce {
    ProofNonce::from_bytes(scalar_bytes(scalar)).expect("valid nonce")
}

fn scalar_from_hex(value: &str) -> Scalar {
    let bytes: [u8; 32] = hex::decode(value)
        .expect("valid hex")
        .try_into()
        .expect("32-byte scalar");
    Option::<Scalar>::from(Scalar::from_repr(bytes.into())).expect("canonical scalar")
}

#[test]
fn fixed_proof_vectors_are_stable() {
    let dlog_secret = Scalar::from(7u64);
    let dlog_context = ClientDLogContext::new(binding(), TripleIndex::Zero, DLogProofKind::TripleA);
    let dlog_statement =
        DLogStatement::from_bytes(generator_multiple(dlog_secret)).expect("valid statement");
    let dlog = prove_client_dlog_with_nonce(
        dlog_context,
        dlog_statement,
        witness(dlog_secret),
        nonce(Scalar::from(11u64)),
    )
    .expect("valid dlog proof");
    let (dlog_commitment, dlog_response) = dlog.into_parts();

    let eq_secret = Scalar::from(13u64);
    let alternate_generator = ProjectivePoint::GENERATOR * Scalar::from(19u64);
    let dlog_eq_context = SigningWorkerDLogEqContext::new(binding(), TripleIndex::One);
    let dlog_eq_statement = DLogEqStatement::from_bytes(
        generator_multiple(eq_secret),
        point_bytes(alternate_generator.to_affine()),
        point_bytes((alternate_generator * eq_secret).to_affine()),
    )
    .expect("valid equality statement");
    let dlog_eq = prove_signing_worker_dlog_eq_with_nonce(
        dlog_eq_context,
        dlog_eq_statement,
        witness(eq_secret),
        nonce(Scalar::from(17u64)),
    )
    .expect("valid dlog equality proof");
    let (dlog_eq_commitment0, dlog_eq_commitment1, dlog_eq_response) = dlog_eq.into_parts();

    assert_eq!(dlog_commitment.as_bytes(), &EXPECTED_DLOG_COMMITMENT);
    assert_eq!(dlog_response.into_bytes(), EXPECTED_DLOG_RESPONSE);
    assert_eq!(
        dlog_eq_commitment0.as_bytes(),
        &EXPECTED_DLOG_EQ_COMMITMENT0
    );
    assert_eq!(
        dlog_eq_commitment1.as_bytes(),
        &EXPECTED_DLOG_EQ_COMMITMENT1
    );
    assert_eq!(dlog_eq_response.into_bytes(), EXPECTED_DLOG_EQ_RESPONSE);
}

#[test]
fn pinned_near_vectors_use_the_same_schnorr_and_chaum_pedersen_equations() {
    let x = scalar_from_hex("FC9A011DF3753BD79D841C11F6521F25AD2AB1DECEB96B7E8C28D87EA3303A06");
    let dlog_challenge =
        scalar_from_hex("BA7718DDF60BC62FC6081B658322E908CD4FF161AB754748EC170CBC66898CDB");
    let dlog_response =
        scalar_from_hex("5086B275DC32C8CD1AAD377918E0B622BAF92844BDC46808BD5568D6E304DB33");
    let public = ProjectivePoint::GENERATOR * x;
    let commitment = ProjectivePoint::GENERATOR * dlog_response - public * dlog_challenge;
    assert_eq!(
        ProjectivePoint::GENERATOR * dlog_response,
        commitment + public * dlog_challenge
    );

    let alternate_generator = ProjectivePoint::GENERATOR * x;
    let public1 = alternate_generator * x;
    let dlog_eq_challenge =
        scalar_from_hex("95B6C33214488D2F0429129E9AF2CB2943F9F064421BB270918CFA412CB680E2");
    let dlog_eq_response =
        scalar_from_hex("067B14308E1E96A782791C10179F1801B6764037141CBA0462A4D495EB78B2D0");
    let commitment0 = ProjectivePoint::GENERATOR * dlog_eq_response - public * dlog_eq_challenge;
    let commitment1 = alternate_generator * dlog_eq_response - public1 * dlog_eq_challenge;
    assert_eq!(
        ProjectivePoint::GENERATOR * dlog_eq_response,
        commitment0 + public * dlog_eq_challenge
    );
    assert_eq!(
        alternate_generator * dlog_eq_response,
        commitment1 + public1 * dlog_eq_challenge
    );
}
