const HPKE_SOURCE: &str = include_str!("../src/hpke.rs");

fn production_hpke_source() -> &'static str {
    HPKE_SOURCE
        .split("#[cfg(test)]\nmod commitment_boundary_tests")
        .next()
        .expect("hpke production source")
}

#[test]
fn cloudflare_delegates_commitment_authentication_to_the_client_protocol() {
    let source = production_hpke_source();
    assert!(source.contains("authenticate_ecdsa_commitment_registry_v1"));
    assert!(source.contains("RootShareCommitmentRegistryV1::from_client_authenticated"));

    for forbidden in [
        "verify_cloudflare_commitment_policy_v1",
        "cloudflare_commitment_policy_signing_bytes",
        "COMMITMENT_POLICY_MANIFEST_DOMAIN",
        "ed25519_dalek",
        "VerifyingKey",
        "verify_strict",
    ] {
        assert!(
            !source.contains(forbidden),
            "Cloudflare commitment loading must not own policy or signature verification through `{forbidden}`"
        );
    }
}

#[test]
fn cloudflare_commitment_trust_is_pinned_at_build_time() {
    let source = production_hpke_source();
    for required in [
        "ROUTER_AB_ECDSA_COMMITMENT_POLICY_RELEASE_AUTHORITY_PUBLIC_KEY_HEX",
        "ROUTER_AB_ECDSA_COMMITMENT_POLICY_DIGEST_HEX",
        "ROUTER_AB_ECDSA_COMMITMENT_POLICY_MINIMUM_RELEASE_EPOCH",
        "option_env!",
    ] {
        assert!(
            source.contains(required),
            "Cloudflare commitment loading must retain build-time trust pin `{required}`"
        );
    }
}
