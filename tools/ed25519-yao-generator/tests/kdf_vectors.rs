use ed25519_yao_generator::{
    canonical_kdf_vector_corpus_v1, derive_synthetic_client_contributions_v1,
    derive_synthetic_deriver_a_server_contribution_v1,
    derive_synthetic_deriver_b_server_contribution_v1, evaluate_activation, DeriverAContribution,
    DeriverBContribution, Ed25519YaoApplicationBindingFactsV1,
    Ed25519YaoApplicationBindingKeyCreationSignerSlotV1,
    Ed25519YaoApplicationBindingSigningKeyIdV1, Ed25519YaoApplicationBindingSigningRootIdV1,
    Ed25519YaoApplicationBindingWalletIdV1, KdfVectorCorpusV1, RawDeriverAContribution,
    RawDeriverBContribution, StableKeyDerivationContext, SyntheticClientDerivationRootV1,
    SyntheticDeriverADerivationRootV1, SyntheticDeriverBDerivationRootV1,
};

const COMMITTED_CORPUS: &str = include_str!("../vectors/ed25519-yao-kdf-v1.json");

#[derive(Clone, Copy)]
struct SyntheticRoots {
    client: [u8; 32],
    deriver_a: [u8; 32],
    deriver_b: [u8; 32],
}

fn public_key(
    roots: SyntheticRoots,
    application_binding: [u8; 32],
    participant_ids: [u16; 2],
) -> [u8; 32] {
    let context = StableKeyDerivationContext::new(
        application_binding,
        participant_ids[0],
        participant_ids[1],
    )
    .expect("synthetic context is valid");
    let client = derive_synthetic_client_contributions_v1(
        &SyntheticClientDerivationRootV1::from_fixture_bytes(roots.client),
        &context,
    );
    let server_a = derive_synthetic_deriver_a_server_contribution_v1(
        &SyntheticDeriverADerivationRootV1::from_fixture_bytes(roots.deriver_a),
        &context,
    );
    let server_b = derive_synthetic_deriver_b_server_contribution_v1(
        &SyntheticDeriverBDerivationRootV1::from_fixture_bytes(roots.deriver_b),
        &context,
    );
    let deriver_a = DeriverAContribution::try_from(RawDeriverAContribution {
        y_client: client.deriver_a().y().expose_fixture_bytes(),
        y_server: server_a.y().expose_fixture_bytes(),
        tau_client: client.deriver_a().tau().expose_fixture_bytes(),
        tau_server: server_a.tau().expose_fixture_bytes(),
    })
    .expect("derived A contribution is canonical");
    let deriver_b = DeriverBContribution::try_from(RawDeriverBContribution {
        y_client: client.deriver_b().y().expose_fixture_bytes(),
        y_server: server_b.y().expose_fixture_bytes(),
        tau_client: client.deriver_b().tau().expose_fixture_bytes(),
        tau_server: server_b.tau().expose_fixture_bytes(),
    })
    .expect("derived B contribution is canonical");

    evaluate_activation(&deriver_a, &deriver_b)
        .material()
        .public_key()
        .expose_bytes()
}

fn application_binding_digest(
    wallet_id: &str,
    signing_key_id: &str,
    signing_root_id: &str,
    key_creation_signer_slot: u32,
) -> [u8; 32] {
    *Ed25519YaoApplicationBindingFactsV1::new(
        Ed25519YaoApplicationBindingWalletIdV1::parse(wallet_id).expect("valid wallet id"),
        Ed25519YaoApplicationBindingSigningKeyIdV1::parse(signing_key_id)
            .expect("valid signing key id"),
        Ed25519YaoApplicationBindingSigningRootIdV1::parse(signing_root_id)
            .expect("valid signing root id"),
        Ed25519YaoApplicationBindingKeyCreationSignerSlotV1::new(key_creation_signer_slot)
            .expect("valid key-creation signer slot"),
    )
    .digest()
    .as_bytes()
}

#[test]
fn committed_kdf_corpus_matches_the_canonical_builder_byte_for_byte() {
    let expected = canonical_kdf_vector_corpus_v1();
    let parsed: KdfVectorCorpusV1 =
        serde_json::from_str(COMMITTED_CORPUS).expect("committed KDF corpus is valid JSON");
    let canonical = format!(
        "{}\n",
        serde_json::to_string_pretty(&expected).expect("KDF corpus serializes")
    );

    assert_eq!(parsed, expected);
    assert_eq!(COMMITTED_CORPUS, canonical);
}

#[test]
fn kdf_corpus_rejects_unknown_fields() {
    let mut value = serde_json::to_value(canonical_kdf_vector_corpus_v1())
        .expect("KDF corpus converts to JSON");
    value
        .as_object_mut()
        .expect("corpus is an object")
        .insert("unexpected".to_owned(), serde_json::Value::Bool(true));

    assert!(serde_json::from_value::<KdfVectorCorpusV1>(value).is_err());

    let mut nested = serde_json::to_value(canonical_kdf_vector_corpus_v1())
        .expect("KDF corpus converts to JSON");
    nested["cases"][0]["application_binding"]
        .as_object_mut()
        .expect("application binding is an object")
        .insert("signing_root_version".to_owned(), "v2".into());

    assert!(serde_json::from_value::<KdfVectorCorpusV1>(nested).is_err());
}

#[test]
fn changing_any_synthetic_root_or_participant_set_changes_identity() {
    let roots = SyntheticRoots {
        client: [0x11; 32],
        deriver_a: [0x22; 32],
        deriver_b: [0x33; 32],
    };
    let application_binding = application_binding_digest(
        "wallet-fixture",
        "ed25519ks_fixture",
        "project-fixture:env-fixture",
        1,
    );
    let baseline = public_key(roots, application_binding, [1, 2]);

    assert_ne!(
        baseline,
        public_key(
            SyntheticRoots {
                client: [0x12; 32],
                ..roots
            },
            application_binding,
            [1, 2]
        )
    );
    assert_ne!(
        baseline,
        public_key(
            SyntheticRoots {
                deriver_a: [0x23; 32],
                ..roots
            },
            application_binding,
            [1, 2]
        )
    );
    assert_ne!(
        baseline,
        public_key(
            SyntheticRoots {
                deriver_b: [0x34; 32],
                ..roots
            },
            application_binding,
            [1, 2]
        )
    );
    assert_ne!(baseline, public_key(roots, application_binding, [1, 3]));
}

#[test]
fn changing_each_application_binding_fact_changes_final_identity() {
    let roots = SyntheticRoots {
        client: [0x11; 32],
        deriver_a: [0x22; 32],
        deriver_b: [0x33; 32],
    };
    let baseline_binding = application_binding_digest(
        "wallet-fixture",
        "ed25519ks_fixture",
        "project-fixture:env-fixture",
        1,
    );
    let baseline = public_key(roots, baseline_binding, [1, 2]);

    for changed_binding in [
        application_binding_digest(
            "wallet-fixture-2",
            "ed25519ks_fixture",
            "project-fixture:env-fixture",
            1,
        ),
        application_binding_digest(
            "wallet-fixture",
            "ed25519ks_fixture_2",
            "project-fixture:env-fixture",
            1,
        ),
        application_binding_digest(
            "wallet-fixture",
            "ed25519ks_fixture",
            "project-fixture:env-fixture-2",
            1,
        ),
        application_binding_digest(
            "wallet-fixture",
            "ed25519ks_fixture",
            "project-fixture:env-fixture",
            2,
        ),
    ] {
        assert_ne!(baseline_binding, changed_binding);
        assert_ne!(baseline, public_key(roots, changed_binding, [1, 2]));
    }
}

#[test]
fn application_binding_record_is_the_stable_context_input() {
    let corpus = canonical_kdf_vector_corpus_v1();
    let case = corpus.cases.first().expect("canonical case exists");

    assert_eq!(
        case.application_binding.digest_sha256_hex,
        case.context.application_binding_digest_hex
    );
    assert_eq!(
        case.application_binding.digest_sha256_hex,
        "b1dbafce5fd696ae4bd5611e3684a778febfdf7f716e2dfe3211ce0cff708121"
    );
    assert_eq!(case.application_binding.key_creation_signer_slot, 1);
    assert_eq!(
        case.context.binding_sha256_hex,
        "b5601ad156882b545a2e4a4a694e87c7982842d37a4c666645302604b2720655"
    );
}

#[test]
fn participant_reordering_preserves_the_derived_identity() {
    let roots = SyntheticRoots {
        client: [0x11; 32],
        deriver_a: [0x22; 32],
        deriver_b: [0x33; 32],
    };
    let application_binding = application_binding_digest(
        "wallet-fixture",
        "ed25519ks_fixture",
        "project-fixture:env-fixture",
        1,
    );

    assert_eq!(
        public_key(roots, application_binding, [1, 2]),
        public_key(roots, application_binding, [2, 1])
    );
}
