use base64ct::{Base64UrlUnpadded, Encoding};
use curve25519_dalek::scalar::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use router_ab_core::{RouterAbEcdsaDerivationStableKeyContextV1, StableTenantDerivationContextV2};
use threshold_prf::{
    apply_two_party_root_share_refresh, combine_verified_partials,
    evaluate_partial_with_dleq_proof, generate_two_party_root_share, PrfContext, PrfPurpose,
    RootShareRefreshCoefficient, SigningRootShare, SuiteId, ThresholdPolicy, TwoPartyDeriverRole,
    ValidatedThresholdSet,
};

const STABLE_CONTEXT_HEX: &str = "726f757465722d61622d65636473612d64657269766174696f6e2f636f6e746578742f7631001d726f757465722d61622d65636473612d64657269766174696f6e2d76310009736563703235366b3142424242424242424242424242424242424242424242424242424242424242420200010002";

fn seeded_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn refresh_role_share(
    current: &SigningRootShare,
    recipient: TwoPartyDeriverRole,
    coefficient_a: &RootShareRefreshCoefficient,
    coefficient_b: &RootShareRefreshCoefficient,
) -> SigningRootShare {
    let contribution_a = coefficient_a
        .commitment()
        .verify_contribution(coefficient_a.contribution_for(recipient))
        .expect("Deriver A contribution verifies");
    let contribution_b = coefficient_b
        .commitment()
        .verify_contribution(coefficient_b.contribution_for(recipient))
        .expect("Deriver B contribution verifies");
    apply_two_party_root_share_refresh(current, contribution_a, contribution_b)
        .expect("share refresh succeeds")
}

fn evaluate_pair(
    shares: &[SigningRootShare],
    policy: ThresholdPolicy,
    context: &PrfContext,
    proof_seed: u8,
) -> [u8; 32] {
    let mut proof_rng = seeded_rng(proof_seed);
    let bundles = ValidatedThresholdSet::from_proof_bundles(
        policy,
        shares
            .iter()
            .map(|share| {
                evaluate_partial_with_dleq_proof(share, context, &mut proof_rng)
                    .expect("partial proof evaluates")
            })
            .collect(),
    )
    .expect("fixed 2-of-2 proof set");
    combine_verified_partials(&bundles, context)
        .expect("verified combine")
        .into_bytes()
}

#[test]
fn stable_context_is_byte_exact_with_the_existing_ecdsa_protocol_context() {
    let digest = [0x42; 32];
    let stable = StableTenantDerivationContextV2::new(digest);
    let existing =
        RouterAbEcdsaDerivationStableKeyContextV1::new(Base64UrlUnpadded::encode_string(&digest))
            .expect("existing context");

    assert_eq!(
        hex::encode(stable.canonical_context_bytes()),
        STABLE_CONTEXT_HEX
    );
    assert_eq!(
        stable.canonical_context_bytes(),
        existing.canonical_context_bytes().expect("existing bytes")
    );
}

#[test]
fn stable_context_wire_is_strict_and_canonical() {
    let stable = StableTenantDerivationContextV2::new([0x42; 32]);
    let json = serde_json::to_value(&stable).expect("serialize stable context");
    assert_eq!(
        json,
        serde_json::json!({
            "applicationBindingDigestB64u": Base64UrlUnpadded::encode_string(&[0x42; 32])
        })
    );
    assert_eq!(
        serde_json::from_value::<StableTenantDerivationContextV2>(json)
            .expect("parse canonical context"),
        stable
    );

    for invalid in [
        serde_json::json!({}),
        serde_json::json!({
            "applicationBindingDigestB64u": Base64UrlUnpadded::encode_string(&[0x42; 31])
        }),
        serde_json::json!({
            "applicationBindingDigestB64u": format!("{}=", Base64UrlUnpadded::encode_string(&[0x42; 32]))
        }),
        serde_json::json!({
            "applicationBindingDigestB64u": Base64UrlUnpadded::encode_string(&[0x42; 32]),
            "rootShareEpoch": "epoch-2"
        }),
    ] {
        assert!(serde_json::from_value::<StableTenantDerivationContextV2>(invalid).is_err());
    }
}

#[test]
fn refreshed_ab_shares_reproduce_every_ecdsa_threshold_prf_output() {
    let policy = ThresholdPolicy::from_u16s(2, 2).expect("fixed 2-of-2 policy");
    let current = vec![
        generate_two_party_root_share(TwoPartyDeriverRole::DeriverA, &mut seeded_rng(1)),
        generate_two_party_root_share(TwoPartyDeriverRole::DeriverB, &mut seeded_rng(2)),
    ];
    let coefficient_a = RootShareRefreshCoefficient::from_canonical_bytes(
        TwoPartyDeriverRole::DeriverA,
        Scalar::from(17_u64).to_bytes(),
    )
    .expect("Deriver A coefficient");
    let coefficient_b = RootShareRefreshCoefficient::from_canonical_bytes(
        TwoPartyDeriverRole::DeriverB,
        Scalar::from(29_u64).to_bytes(),
    )
    .expect("Deriver B coefficient");
    let refreshed = vec![
        refresh_role_share(
            &current[0],
            TwoPartyDeriverRole::DeriverA,
            &coefficient_a,
            &coefficient_b,
        ),
        refresh_role_share(
            &current[1],
            TwoPartyDeriverRole::DeriverB,
            &coefficient_a,
            &coefficient_b,
        ),
    ];
    let stable_context = StableTenantDerivationContextV2::new([0x42; 32]);

    for (index, purpose) in [
        PrfPurpose::RouterAbXClientBaseV1,
        PrfPurpose::RouterAbXServerBaseV1,
        PrfPurpose::RouterAbEcdsaDerivationYServer,
    ]
    .into_iter()
    .enumerate()
    {
        let context = PrfContext::new(
            SuiteId::Ristretto255Sha512,
            purpose,
            stable_context.canonical_context_bytes(),
        );
        assert_eq!(
            evaluate_pair(&current, policy, &context, 10 + index as u8),
            evaluate_pair(&refreshed, policy, &context, 20 + index as u8),
        );
    }
}
