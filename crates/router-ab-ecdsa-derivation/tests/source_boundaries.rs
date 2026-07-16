use std::fs;
use std::path::{Path, PathBuf};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate must live under <repository>/crates")
        .to_path_buf()
}

fn read_repository_file(relative_path: &str) -> String {
    let path = repository_root().join(relative_path);
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("failed to read {}: {error}", path.display());
    })
}

fn cargo_feature_block<'a>(cargo_toml: &'a str, feature_name: &str) -> &'a str {
    let start_marker = format!("{feature_name} = [");
    let start = cargo_toml
        .find(&start_marker)
        .unwrap_or_else(|| panic!("missing Cargo feature `{feature_name}`"));
    let remaining = &cargo_toml[start..];
    let end = remaining
        .find("\n]")
        .map(|offset| offset + 2)
        .expect("Cargo feature block must close");
    &remaining[..end]
}

#[test]
fn crate_replacement_is_exact_and_old_crate_is_absent() {
    let root = repository_root();
    assert!(!root.join("crates/ecdsa-hss").exists());
    assert!(root.join("crates/router-ab-ecdsa-derivation").is_dir());

    let cargo_toml = read_repository_file("crates/router-ab-ecdsa-derivation/Cargo.toml");
    assert!(cargo_toml.contains("name = \"router-ab-ecdsa-derivation\""));
    assert!(cargo_toml.contains("name = \"router_ab_ecdsa_derivation\""));
}

#[test]
fn signer_role_local_feature_stays_independent_of_threshold_signing_backend() {
    let cargo_toml = read_repository_file("crates/signer-core/Cargo.toml");
    let feature = cargo_feature_block(&cargo_toml, "ecdsa-role-local-client");

    for required in [
        "dep:hkdf",
        "dep:sha2",
        "dep:base64ct",
        "dep:router-ab-ecdsa-derivation",
    ] {
        assert!(feature.contains(required), "missing `{required}`");
    }
    for forbidden in ["threshold-ecdsa", "threshold-signatures"] {
        assert!(!feature.contains(forbidden), "forbidden `{forbidden}`");
    }
}

#[test]
fn active_rust_manifests_use_router_ab_ecdsa_derivation_name() {
    for relative_path in [
        "crates/router-ab-cloudflare/Cargo.toml",
        "crates/router-ab-core/Cargo.toml",
        "crates/router-ab-dev/Cargo.toml",
        "crates/router-ab-ecdsa-derivation/Cargo.toml",
        "crates/signer-core/Cargo.toml",
    ] {
        let cargo_toml = read_repository_file(relative_path);
        assert!(!cargo_toml.contains("ecdsa-hss"), "{relative_path}");
        assert!(!cargo_toml.contains("ecdsa_hss"), "{relative_path}");
    }
}
