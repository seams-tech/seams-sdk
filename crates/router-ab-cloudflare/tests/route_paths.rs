use router_ab_cloudflare::{
    CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ADD_SIGNER_PUBLIC_REQUEST_PATH,
    CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PUBLIC_REQUEST_PATH,
    CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PUBLIC_REQUEST_PATH,
    CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PUBLIC_REQUEST_PATH,
    CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PUBLIC_REQUEST_PATH,
    CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PUBLIC_REQUEST_PATH,
    CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PUBLIC_REQUEST_PATH,
    CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH,
    CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH,
    CLOUDFLARE_ROUTER_PUBLIC_KEYSET_PATH, CLOUDFLARE_ROUTER_PUBLIC_KEYSET_WELL_KNOWN_PATH,
    CLOUDFLARE_ROUTER_WALLET_BUDGET_STATUS_PUBLIC_REQUEST_PATH,
};

#[test]
fn router_public_route_constants_use_current_unversioned_paths() {
    let routes = [
        (
            CLOUDFLARE_ROUTER_PUBLIC_KEYSET_WELL_KNOWN_PATH,
            "/.well-known/router-ab/keyset",
        ),
        (CLOUDFLARE_ROUTER_PUBLIC_KEYSET_PATH, "/router-ab/keyset"),
        (
            CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH,
            "/router-ab/ed25519/sign/prepare",
        ),
        (
            CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH,
            "/router-ab/ed25519/sign",
        ),
        (
            CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PUBLIC_REQUEST_PATH,
            "/router-ab/ecdsa-derivation/register",
        ),
        (
            CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ADD_SIGNER_PUBLIC_REQUEST_PATH,
            "/router-ab/ecdsa-derivation/add-signer",
        ),
        (
            CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PUBLIC_REQUEST_PATH,
            "/router-ab/ecdsa-derivation/export",
        ),
        (
            CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PUBLIC_REQUEST_PATH,
            "/router-ab/ecdsa-derivation/recover",
        ),
        (
            CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PUBLIC_REQUEST_PATH,
            "/router-ab/ecdsa-derivation/refresh",
        ),
        (
            CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PUBLIC_REQUEST_PATH,
            "/router-ab/ecdsa-derivation/sign/prepare",
        ),
        (
            CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PUBLIC_REQUEST_PATH,
            "/router-ab/ecdsa-derivation/sign",
        ),
        (
            CLOUDFLARE_ROUTER_WALLET_BUDGET_STATUS_PUBLIC_REQUEST_PATH,
            "/router-ab/wallet-budget/status",
        ),
    ];

    for (actual, expected) in routes {
        assert_eq!(actual, expected);
        assert!(
            !actual.starts_with("/v1/") && !actual.starts_with("/v2/"),
            "{actual} must stay on the current public route namespace"
        );
    }
}
