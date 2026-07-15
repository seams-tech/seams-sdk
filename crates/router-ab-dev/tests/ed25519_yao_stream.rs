use std::net::TcpListener;
use std::thread;

use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoOperationV1, Ed25519YaoSessionIdV1,
    Ed25519YaoStableKeyContextBindingV1, ExpensiveWorkKindV1, LifecycleScopeV1, RootShareEpoch,
};
use router_ab_dev::{
    run_local_activation_deriver_a_http_v1, run_local_activation_deriver_b_http_v1,
    run_local_export_deriver_a_http_v1, run_local_export_deriver_b_http_v1,
};
use router_ab_ed25519_yao::recipient::client::combine_export_packages;
use router_ab_ed25519_yao::relay::{derive_registration_receipt, ActivationPublicCommitments};
use router_ab_ed25519_yao::{
    build_activation_deriver_a, build_activation_deriver_b, build_export_deriver_a,
    build_export_deriver_b, ActivationDeriverAContribution, ActivationDeriverBContribution,
    ExportDeriverAContribution, ExportDeriverBContribution,
};
use signer_core::ed25519_yao_derivation::{
    derive_ed25519_yao_client_contributions_v1,
    derive_ed25519_yao_deriver_a_server_contribution_v1,
    derive_ed25519_yao_deriver_b_server_contribution_v1, Ed25519YaoApplicationBindingFactsV1,
    Ed25519YaoApplicationBindingKeyCreationSignerSlotV1,
    Ed25519YaoApplicationBindingSigningKeyIdV1, Ed25519YaoApplicationBindingSigningRootIdV1,
    Ed25519YaoApplicationBindingWalletIdV1, Ed25519YaoClientDerivationRootV1,
    Ed25519YaoDeriverAClientContributionV1, Ed25519YaoDeriverADerivationRootV1,
    Ed25519YaoDeriverAServerContributionV1, Ed25519YaoDeriverBClientContributionV1,
    Ed25519YaoDeriverBDerivationRootV1, Ed25519YaoDeriverBServerContributionV1,
    Ed25519YaoStableKeyDerivationContextV1,
};
use zeroize::{Zeroize, Zeroizing};

const SESSION: [u8; 32] = [0x51; 32];
const INTERNAL_AUTH: &str = "local-ed25519-yao-stream-test-auth";
const EXPECTED_PUBLIC_KEY: [u8; 32] = [
    0xcc, 0xd2, 0x55, 0xd0, 0xb8, 0x87, 0x21, 0x77, 0x19, 0x47, 0x03, 0x8f, 0x1a, 0x7c, 0x29, 0xb4,
    0x9e, 0xee, 0x39, 0x02, 0xd6, 0xaa, 0x73, 0x2e, 0x5e, 0x44, 0x82, 0x51, 0x53, 0x7b, 0xf0, 0x77,
];
const EXPECTED_SEED: [u8; 32] = [
    0xc6, 0xdb, 0x61, 0x24, 0xf7, 0xfe, 0xa8, 0xe2, 0x0e, 0xc7, 0xce, 0x74, 0x72, 0xd7, 0x52, 0x10,
    0xd6, 0x47, 0x06, 0x2c, 0x04, 0xd5, 0x3d, 0x93, 0x11, 0xb3, 0xda, 0xb6, 0xd3, 0x4b, 0xdf, 0xdc,
];

fn activation_binding() -> Ed25519YaoCeremonyBindingV1 {
    let lifecycle = LifecycleScopeV1::new(
        "local-lifecycle-1",
        ExpensiveWorkKindV1::RegistrationPrepare,
        RootShareEpoch::new("epoch-1").expect("root epoch"),
        "account-1",
        "wallet-session-1",
        "signer-set-1",
        "signing-worker-1",
    )
    .expect("lifecycle");
    Ed25519YaoCeremonyBindingV1::new(
        lifecycle,
        Ed25519YaoOperationV1::Registration,
        Ed25519YaoSessionIdV1::new(SESSION).expect("session"),
        Ed25519YaoStableKeyContextBindingV1::new([
            0xb5, 0x60, 0x1a, 0xd1, 0x56, 0x88, 0x2b, 0x54, 0x5a, 0x2e, 0x4a, 0x4a, 0x69, 0x4e,
            0x87, 0xc7, 0x98, 0x28, 0x42, 0xd3, 0x7a, 0x4c, 0x66, 0x66, 0x45, 0x30, 0x26, 0x04,
            0xb2, 0x72, 0x06, 0x55,
        ]),
    )
    .expect("activation binding")
}

fn derived_contributions() -> (
    Ed25519YaoStableKeyDerivationContextV1,
    Ed25519YaoDeriverAClientContributionV1,
    Ed25519YaoDeriverBClientContributionV1,
    Ed25519YaoDeriverAServerContributionV1,
    Ed25519YaoDeriverBServerContributionV1,
) {
    let application = Ed25519YaoApplicationBindingFactsV1::new(
        Ed25519YaoApplicationBindingWalletIdV1::parse("wallet-fixture").expect("wallet"),
        Ed25519YaoApplicationBindingSigningKeyIdV1::parse("ed25519ks_fixture")
            .expect("signing key"),
        Ed25519YaoApplicationBindingSigningRootIdV1::parse("project-fixture:env-fixture")
            .expect("signing root"),
        Ed25519YaoApplicationBindingKeyCreationSignerSlotV1::new(1).expect("slot"),
    );
    let context = Ed25519YaoStableKeyDerivationContextV1::new(application.digest(), 1, 2)
        .expect("stable context");
    let client_root = Ed25519YaoClientDerivationRootV1::from_secret_bytes([0x11; 32]);
    let deriver_a_root = Ed25519YaoDeriverADerivationRootV1::from_secret_bytes([0x22; 32]);
    let deriver_b_root = Ed25519YaoDeriverBDerivationRootV1::from_secret_bytes([0x33; 32]);
    let (client_a, client_b) = derive_ed25519_yao_client_contributions_v1(&client_root, &context)
        .expect("client KDF")
        .into_parts();
    let server_a = derive_ed25519_yao_deriver_a_server_contribution_v1(&deriver_a_root, &context)
        .expect("A KDF");
    let server_b = derive_ed25519_yao_deriver_b_server_contribution_v1(&deriver_b_root, &context)
        .expect("B KDF");
    (context, client_a, client_b, server_a, server_b)
}

fn activation_roles() -> (
    router_ab_ed25519_yao::ActivationDeriverA,
    router_ab_ed25519_yao::ActivationDeriverB,
) {
    let (context, client_a, client_b, server_a, server_b) = derived_contributions();
    let binding = activation_binding();
    let a = build_activation_deriver_a(
        &binding,
        ActivationDeriverAContribution::base(&context, client_a, server_a),
    )
    .expect("A role");
    let b = build_activation_deriver_b(
        &binding,
        ActivationDeriverBContribution::base(&context, client_b, server_b),
    )
    .expect("B role");
    (a, b)
}

fn export_roles() -> (
    router_ab_ed25519_yao::ExportDeriverA,
    router_ab_ed25519_yao::ExportDeriverB,
) {
    let (context, client_a, client_b, server_a, server_b) = derived_contributions();
    let lifecycle = LifecycleScopeV1::new(
        "local-export-lifecycle-1",
        ExpensiveWorkKindV1::KeyExport,
        RootShareEpoch::new("epoch-1").expect("root epoch"),
        "account-1",
        "wallet-session-1",
        "signer-set-1",
        "signing-worker-1",
    )
    .expect("export lifecycle");
    let binding = Ed25519YaoCeremonyBindingV1::new(
        lifecycle,
        Ed25519YaoOperationV1::Export,
        Ed25519YaoSessionIdV1::new(SESSION).expect("session"),
        Ed25519YaoStableKeyContextBindingV1::new([
            0xb5, 0x60, 0x1a, 0xd1, 0x56, 0x88, 0x2b, 0x54, 0x5a, 0x2e, 0x4a, 0x4a, 0x69, 0x4e,
            0x87, 0xc7, 0x98, 0x28, 0x42, 0xd3, 0x7a, 0x4c, 0x66, 0x66, 0x45, 0x30, 0x26, 0x04,
            0xb2, 0x72, 0x06, 0x55,
        ]),
    )
    .expect("export binding");
    let a = build_export_deriver_a(
        &binding,
        ExportDeriverAContribution::from_derived(&context, client_a, server_a),
    )
    .expect("export A role");
    let b = build_export_deriver_b(
        &binding,
        ExportDeriverBContribution::from_derived(&context, client_b, server_b),
    )
    .expect("export B role");
    (a, b)
}

#[test]
fn activation_completes_over_one_full_duplex_chunked_http_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let address = listener.local_addr().expect("loopback address");
    let (a, b) = activation_roles();

    let b_thread = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept A connection");
        run_local_activation_deriver_b_http_v1(stream, SESSION, INTERNAL_AUTH, b)
            .expect("B stream completion")
    });
    let a_completion = run_local_activation_deriver_a_http_v1(address, SESSION, INTERNAL_AUTH, a)
        .expect("A stream completion");
    let b_completion = b_thread.join().expect("B thread completion");

    assert_eq!(
        a_completion.final_transcript(),
        b_completion.final_transcript()
    );
    assert_eq!(a_completion.stream_metrics().frame_count(), 17);
    assert_eq!(b_completion.stream_metrics().frame_count(), 17);
    let activation_wire = a_completion.wire_byte_ledger();
    assert_eq!(activation_wire, b_completion.wire_byte_ledger());
    assert_eq!(activation_wire.deriver_a_to_b_transport_bytes(), 2_185_420);
    assert_eq!(activation_wire.deriver_b_to_a_transport_bytes(), 37_164);
    assert_eq!(activation_wire.total_ab_transport_bytes(), 2_222_584);

    let commitments = ActivationPublicCommitments::new(
        a_completion.client_commitment(),
        b_completion.client_commitment(),
        a_completion.signing_worker_commitment(),
        b_completion.signing_worker_commitment(),
    );
    let receipt = derive_registration_receipt(commitments).expect("registration receipt");
    assert_eq!(receipt.registered_public_key(), &EXPECTED_PUBLIC_KEY);
}

#[test]
fn export_completes_over_the_same_duplex_transport_and_recovers_the_exact_seed() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let address = listener.local_addr().expect("loopback address");
    let (a, b) = export_roles();

    let b_thread = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept A connection");
        run_local_export_deriver_b_http_v1(stream, SESSION, INTERNAL_AUTH, b)
            .expect("B export stream completion")
    });
    let a_completion = run_local_export_deriver_a_http_v1(address, SESSION, INTERNAL_AUTH, a)
        .expect("A export stream completion");
    let b_completion = b_thread.join().expect("B thread completion");

    assert_eq!(
        a_completion.final_transcript(),
        b_completion.final_transcript()
    );
    assert_eq!(a_completion.stream_metrics().frame_count(), 1);
    assert_eq!(b_completion.stream_metrics().frame_count(), 1);
    let export_wire = a_completion.wire_byte_ledger();
    assert_eq!(export_wire, b_completion.wire_byte_ledger());
    assert_eq!(export_wire.deriver_a_to_b_transport_bytes(), 82_636);
    assert_eq!(export_wire.deriver_b_to_a_transport_bytes(), 20_780);
    assert_eq!(export_wire.total_ab_transport_bytes(), 103_416);
    let mut exported_seed = Zeroizing::new(
        combine_export_packages(
            SESSION,
            a_completion.final_transcript(),
            a_completion.export_package(),
            b_completion.export_package(),
        )
        .expect("combine export packages")
        .into_bytes(),
    );
    assert_eq!(*exported_seed, EXPECTED_SEED);
    exported_seed.zeroize();
}
