use std::fs;
use std::path::PathBuf;

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn adapter_has_no_hss_backend_or_transport_policy() {
    let root = crate_root();
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("manifest");
    let source = fs::read_to_string(root.join("src/lib.rs")).expect("source");
    for forbidden in [
        "ed25519-hss",
        "ed25519_hss",
        "ecdsa-hss",
        "ecdsa_hss",
        "cloudflare",
        "worker::",
        "reqwest",
        "hyper::",
    ] {
        assert!(
            !manifest.contains(forbidden) && !source.contains(forbidden),
            "composition adapter contains forbidden dependency or policy: {forbidden}"
        );
    }
}

#[test]
fn only_recipient_modules_export_package_combination() {
    let source = fs::read_to_string(crate_root().join("src/lib.rs")).expect("source");
    let relay_start = source.find("pub mod relay").expect("relay module");
    let recipient_start = source.find("pub mod recipient").expect("recipient module");
    let relay_source = &source[relay_start..recipient_start];
    assert!(!relay_source.contains("combine_client_activation_packages"));
    assert!(!relay_source.contains("combine_signing_worker_activation_packages"));
    assert!(!relay_source.contains("combine_export_packages"));
}
