use k256::{
    elliptic_curve::{ff::PrimeField, sec1::FromEncodedPoint},
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar,
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use router_ab_ecdsa_presign::{proofs::TripleIndex, triples::commit_client_polynomials};
use router_ab_ecdsa_wire::{
    CompressedPointBytes, PairContextDigest, PresignPairContext, ScalarBytes, SigningScopeDigest,
};

const EXPECTED_DIGEST: &str = "1df6c8a25ed6fe95410f6a048331abdfc3b5cf1566019dc42a432e48bc75d9a9";
const EXPECTED_E0: &str = "033720e3e731b97ae4e13e140440e4e9a41f17f5165e3cf133fb80b38ff52332c2";
const EXPECTED_E1: &str = "02c038f5b19c6db2ab31ca06c886ff25c94c293d73421fc0aa419dfd640981d73e";
const EXPECTED_F0: &str = "028e7a34b3bc38f091673df2f6a6dd01a7dea30405c1d72320d8961eea2fa82ce6";
const EXPECTED_F1: &str = "03e51431be807213e0f29c434b38a2997e801a6b057d80091c65c208ef66ae365b";
const EXPECTED_L0: &str = "02b64db7a26fb86cf8045c087d9ba7a2b44d4e063e573cd7227fb4cbe2b3dc5512";
const EXPECTED_RANDOMIZER: &str =
    "4bd7a20c846153459c2eb5b35bf52d259f8eb107fe35ea9084e2157585ce60fe";
const EXPECTED_E_SHARE: &str = "2e622d1420863f2b079583b5d4c8cd485395bb579c6661ee92ff3a853f1015ec";
const EXPECTED_F_SHARE: &str = "4c8922f01daf14d234606cb536777feda80c76f3966dcb299714a1fe2153094e";

fn binding() -> PresignPairContext {
    PresignPairContext::new(
        SigningScopeDigest::new([0x24; 32]),
        PairContextDigest::new([0x42; 32]),
    )
}

fn point(bytes: CompressedPointBytes) -> ProjectivePoint {
    let encoded = EncodedPoint::from_bytes(bytes.as_bytes()).expect("encoded point");
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .expect("curve point");
    ProjectivePoint::from(affine)
}

fn scalar(bytes: ScalarBytes) -> Scalar {
    Option::<Scalar>::from(Scalar::from_repr(bytes.into_bytes().into())).expect("canonical scalar")
}

#[test]
fn fixed_polynomial_opening_vector_is_stable_and_uses_near_share_equations() {
    let mut rng = ChaCha20Rng::from_seed([0x31; 32]);
    let (state, commitment) =
        commit_client_polynomials(binding(), TripleIndex::Zero, &mut rng).expect("commitment");
    let (opened, opening) = state.open();
    let share = opened.private_share_for_signing_worker();
    let (_, _, digest) = commitment.into_parts();
    let (_, _, e0, e1, f0, f1, l0, randomizer) = opening.into_parts();
    let (_, _, e_share, f_share) = share.into_parts();
    let e_share = e_share.into_bytes();
    let f_share = f_share.into_bytes();

    assert_eq!(hex::encode(digest), EXPECTED_DIGEST);
    assert_eq!(hex::encode(e0.as_bytes()), EXPECTED_E0);
    assert_eq!(hex::encode(e1.as_bytes()), EXPECTED_E1);
    assert_eq!(hex::encode(f0.as_bytes()), EXPECTED_F0);
    assert_eq!(hex::encode(f1.as_bytes()), EXPECTED_F1);
    assert_eq!(hex::encode(l0.as_bytes()), EXPECTED_L0);
    assert_eq!(hex::encode(randomizer), EXPECTED_RANDOMIZER);
    assert_eq!(hex::encode(e_share), EXPECTED_E_SHARE);
    assert_eq!(hex::encode(f_share), EXPECTED_F_SHARE);

    let worker_coordinate = Scalar::from(3u64);
    assert_eq!(
        point(e0) + point(e1) * worker_coordinate,
        ProjectivePoint::GENERATOR * scalar(ScalarBytes::new(e_share))
    );
    assert_eq!(
        point(f0) + point(f1) * worker_coordinate,
        ProjectivePoint::GENERATOR * scalar(ScalarBytes::new(f_share))
    );
}
