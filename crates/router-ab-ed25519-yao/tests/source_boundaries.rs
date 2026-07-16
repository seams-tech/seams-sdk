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

#[test]
fn local_product_surface_exposes_only_the_fixed_128_kib_profile() {
    let source = fs::read_to_string(crate_root().join("../ed25519-yao/src/lib.rs"))
        .expect("ed25519-yao public surface");
    let local_surface = source
        .split("pub mod local_protocol {")
        .nth(1)
        .and_then(|tail| tail.split("\n}\n").next())
        .expect("fixed local protocol module");
    for forbidden in ["64KiB", "256KiB", "benchmark::*"] {
        assert!(
            !local_surface.contains(forbidden),
            "local product surface must not expose {forbidden}"
        );
    }
    for required in ["Activation128KiBDeriverA", "Export128KiBDeriverB"] {
        assert!(
            local_surface.contains(required),
            "local product surface must expose {required}"
        );
    }
}
