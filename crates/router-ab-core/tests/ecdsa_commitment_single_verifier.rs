const REGISTRY_SOURCE: &str = include_str!("../src/derivation/ecdsa_commitment_registry.rs");
const DERIVATION_EXPORTS_SOURCE: &str = include_str!("../src/derivation/mod.rs");

fn production_registry_source() -> &'static str {
    REGISTRY_SOURCE
        .split("#[cfg(test)]\nmod client_authenticated_adapter_tests")
        .next()
        .expect("production commitment registry source")
}

#[test]
fn core_commitment_registry_accepts_only_the_opaque_client_capability() {
    let source = production_registry_source();
    assert!(source.contains("EcdsaAuthenticatedCommitmentRegistryV1"));
    assert!(source.contains("authenticates_exact_record"));

    for forbidden in [
        "RootShareCommitmentAuthorityKeyV1",
        "RootShareCommitmentTrustPolicyV1",
        "RootShareCommitmentStatementV1",
        "SignedRootShareCommitmentRecordV1",
        "RootShareCommitmentRegistryV1::authenticate",
        "ed25519_dalek",
        "VerifyingKey",
        "verify_strict",
    ] {
        assert!(
            !source.contains(forbidden),
            "core must not own commitment policy or signature verification through `{forbidden}`"
        );
        assert!(
            !DERIVATION_EXPORTS_SOURCE.contains(forbidden),
            "core must not export obsolete commitment verifier symbol `{forbidden}`"
        );
    }
}
