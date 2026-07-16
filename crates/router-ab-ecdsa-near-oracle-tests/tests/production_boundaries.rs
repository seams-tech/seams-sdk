use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const FORBIDDEN_PACKAGES: [&str; 11] = [
    "threshold-signatures",
    "signer-core",
    "cait-sith",
    "round-based",
    "curve25519-dalek",
    "ed25519-dalek",
    "p256",
    "p384",
    "bls12_381",
    "ark-ec",
    "rmp-serde",
];

const FORBIDDEN_SOURCE_TOKENS: [&str; 9] = [
    "threshold_signatures",
    "signer_core",
    "cait_sith",
    "round_based",
    "futures::",
    "tokio::",
    "async_trait",
    "Box<dyn",
    "rmp_serde",
];

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates directory")
        .parent()
        .expect("repository root")
        .to_path_buf()
}

fn production_manifests(root: &Path) -> [(PathBuf, bool); 5] {
    [
        (root.join("crates/router-ab-ecdsa-wire/Cargo.toml"), false),
        (root.join("crates/router-ab-ecdsa-pool/Cargo.toml"), false),
        (
            root.join("crates/router-ab-ecdsa-presign/Cargo.toml"),
            false,
        ),
        (root.join("crates/router-ab-ecdsa-online/Cargo.toml"), false),
        (
            root.join("wasm/router_ab_ecdsa_online_client/Cargo.toml"),
            true,
        ),
    ]
}

fn production_source_roots(root: &Path) -> [PathBuf; 5] {
    [
        root.join("crates/router-ab-ecdsa-wire/src"),
        root.join("crates/router-ab-ecdsa-pool/src"),
        root.join("crates/router-ab-ecdsa-presign/src"),
        root.join("crates/router-ab-ecdsa-online/src"),
        root.join("wasm/router_ab_ecdsa_online_client/src"),
    ]
}

fn rust_sources(directory: &Path, output: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()))
    {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            rust_sources(&path, output);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            output.push(path);
        }
    }
}

fn resolved_normal_packages(manifest: &Path, wasm_target: bool) -> Vec<String> {
    let mut command = Command::new("cargo");
    command.args([
        "tree",
        "--manifest-path",
        manifest.to_str().expect("UTF-8 manifest path"),
        "--locked",
        "--offline",
        "--edges",
        "normal",
        "--prefix",
        "none",
        "--format",
        "{p}",
    ]);
    if wasm_target {
        command.args(["--target", "wasm32-unknown-unknown"]);
    }
    let output = command.output().expect("cargo tree must be available");
    assert!(
        output.status.success(),
        "cargo tree failed for {}: {}",
        manifest.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("cargo tree output must be UTF-8")
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

fn is_forbidden_package(package: &str) -> bool {
    package.starts_with("futures")
        || package.starts_with("ark-")
        || FORBIDDEN_PACKAGES
            .iter()
            .any(|forbidden| package == *forbidden)
}

#[test]
fn purpose_built_production_graphs_exclude_generic_threshold_and_unrelated_crypto() {
    let root = repository_root();
    for (manifest, wasm_target) in production_manifests(&root) {
        for package in resolved_normal_packages(&manifest, wasm_target) {
            assert!(
                !is_forbidden_package(&package),
                "{} resolves forbidden production package {package}",
                manifest.display()
            );
        }
    }
}

#[test]
fn purpose_built_sources_exclude_generic_runtime_imports() {
    let root = repository_root();
    let mut sources = Vec::new();
    for directory in production_source_roots(&root) {
        rust_sources(&directory, &mut sources);
    }
    for path in sources {
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        for forbidden in FORBIDDEN_SOURCE_TOKENS {
            assert!(
                !source.contains(forbidden),
                "{} contains forbidden production token {forbidden}",
                path.display()
            );
        }
    }
}

fn assert_leaf_graph_excludes(root: &Path, relative_manifest: &str, forbidden: &[&str]) {
    let manifest = root.join(relative_manifest);
    for package in resolved_normal_packages(&manifest, true) {
        assert!(
            !forbidden.iter().any(|name| package == *name),
            "{} resolves forbidden leaf package {package}",
            manifest.display()
        );
    }
}

fn assert_exact_wasm_exports(root: &Path, relative_source: &str, expected: &[&str]) {
    let source_path = root.join(relative_source);
    let source = fs::read_to_string(&source_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", source_path.display()));
    assert_eq!(
        source.matches("#[wasm_bindgen]").count(),
        expected.len(),
        "{} has an unexpected Wasm export count",
        source_path.display()
    );
    for export in expected {
        assert!(
            source.contains(&format!("pub fn {export}")),
            "{} is missing Wasm export {export}",
            source_path.display()
        );
    }
}

#[test]
fn experimental_public_codec_leaves_have_exact_disjoint_surfaces() {
    let root = repository_root();
    assert_leaf_graph_excludes(
        &root,
        "wasm/evm_transaction_codec/Cargo.toml",
        &[
            "threshold-signatures",
            "k256",
            "p256",
            "ciborium",
            "futures",
            "hkdf",
            "rand_core",
        ],
    );
    assert_leaf_graph_excludes(
        &root,
        "wasm/webauthn_p256/Cargo.toml",
        &["threshold-signatures", "k256", "sha3", "futures", "hkdf"],
    );
    assert_exact_wasm_exports(
        &root,
        "wasm/evm_transaction_codec/src/lib.rs",
        &[
            "compute_eip1559_tx_hash",
            "encode_eip1559_signed_tx_from_signature65",
        ],
    );
    assert_exact_wasm_exports(
        &root,
        "wasm/webauthn_p256/src/lib.rs",
        &[
            "build_webauthn_p256_signature",
            "decode_cose_p256_public_key",
        ],
    );
}

#[test]
fn cloudflare_signing_worker_finalization_excludes_near_ecdsa_backend() {
    let root = repository_root();
    assert_leaf_graph_excludes(
        &root,
        "crates/router-ab-cloudflare/Cargo.toml",
        &["threshold-signatures", "cait-sith", "rmp-serde"],
    );
    let source_path = root.join("crates/router-ab-cloudflare/src/signing_worker/mod.rs");
    let source = fs::read_to_string(&source_path).expect("read Cloudflare SigningWorker source");
    assert!(source.contains("finalize_signing_worker_signature"));
    assert!(!source.contains("threshold_ecdsa_finalize_signature"));
}
