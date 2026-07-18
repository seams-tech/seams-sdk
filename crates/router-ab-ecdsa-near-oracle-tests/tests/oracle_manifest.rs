use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const ORACLE_REPOSITORY: &str = "https://github.com/near/threshold-signatures";
const ORACLE_COMMIT: &str = "db609be5021eb9d794f577601f422818fbdfe246";
const ORACLE_GIT_TREE: &str = "05f60d54971e2f1e417dab7191f0f5d02f82468c";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorpusManifest {
    schema_version: u32,
    oracle: OracleSource,
    vectors: Vec<OracleVector>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OracleSource {
    repository: String,
    commit: String,
    git_tree: String,
    entry_point: String,
    source_files: Vec<OracleSourceFile>,
}

#[derive(Deserialize)]
struct OracleSourceFile {
    path: String,
    sha256: String,
}

#[derive(Deserialize)]
struct OracleVector {
    id: String,
}

#[derive(Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    source: Option<String>,
    manifest_path: PathBuf,
}

fn manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/v1/manifest.json")
}

fn cargo_metadata() -> CargoMetadata {
    let cargo_manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let output = Command::new("cargo")
        .args([
            "metadata",
            "--locked",
            "--offline",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(cargo_manifest)
        .output()
        .expect("cargo metadata must be available");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse cargo metadata")
}

fn threshold_signatures_source_root(metadata: &CargoMetadata) -> PathBuf {
    let package = metadata
        .packages
        .iter()
        .find(|package| package.name == "threshold-signatures")
        .expect("locked oracle package");
    let source = package.source.as_deref().expect("oracle git source");
    assert!(source.contains(ORACLE_REPOSITORY));
    assert!(source.contains(ORACLE_COMMIT));
    package
        .manifest_path
        .parent()
        .expect("oracle manifest parent")
        .to_path_buf()
}

fn git_value(root: &Path, revision: &str) -> String {
    let output = Command::new("git")
        .args([
            "-C",
            root.to_str().expect("UTF-8 oracle root"),
            "rev-parse",
            revision,
        ])
        .output()
        .expect("git must be available");
    assert!(
        output.status.success(),
        "git rev-parse {revision} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git output must be UTF-8")
        .trim()
        .to_owned()
}

fn file_sha256(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn oracle_manifest_pins_the_exact_source_tree_and_corpus() {
    let encoded = fs::read(manifest_path()).expect("read oracle manifest");
    let manifest: CorpusManifest = serde_json::from_slice(&encoded).expect("parse oracle manifest");
    assert_eq!(manifest.schema_version, 1);
    assert_eq!(manifest.oracle.repository, ORACLE_REPOSITORY);
    assert_eq!(manifest.oracle.commit, ORACLE_COMMIT);
    assert_eq!(manifest.oracle.git_tree, ORACLE_GIT_TREE);

    let metadata = cargo_metadata();
    let source_root = threshold_signatures_source_root(&metadata);
    assert_eq!(git_value(&source_root, "HEAD"), ORACLE_COMMIT);
    assert_eq!(git_value(&source_root, "HEAD^{tree}"), ORACLE_GIT_TREE);

    assert_eq!(manifest.oracle.source_files.len(), 23);
    assert!(manifest
        .oracle
        .source_files
        .iter()
        .any(|source| source.path == manifest.oracle.entry_point));
    for source in &manifest.oracle.source_files {
        let path = source_root.join(&source.path);
        assert!(
            path.is_file(),
            "missing pinned oracle source {}",
            path.display()
        );
        assert_eq!(
            file_sha256(&path),
            source.sha256,
            "oracle source drift: {}",
            source.path
        );
    }

    let vector_ids: BTreeSet<&str> = manifest
        .vectors
        .iter()
        .map(|vector| vector.id.as_str())
        .collect();
    assert_eq!(vector_ids.len(), manifest.vectors.len());
    assert_eq!(
        vector_ids,
        BTreeSet::from([
            "fixed-2p-presign-happy-001",
            "fixed-base-rot-001",
            "fixed-corrected-mta-001",
            "fixed-corrected-random-ot-extension-001",
            "fixed-polynomial-opening-001",
            "fixed-presign-semantic-replay-001",
            "fixed-proof-kernels-001",
        ])
    );
}
