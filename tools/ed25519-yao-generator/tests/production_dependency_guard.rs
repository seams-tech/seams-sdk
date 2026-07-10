use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN_PACKAGE_NAME: &str = "ed25519-yao-generator";
const PRODUCTION_RUST_ROOTS: [&str; 2] = ["crates", "wasm"];
const ALLOWED_DEV_MANIFEST: &str = "crates/ed25519-yao/formal-verification/verus/Cargo.toml";

fn collect_cargo_manifests(
    directory: &Path,
    excluded_external_tools: &Path,
    manifests: &mut Vec<PathBuf>,
) {
    if directory == excluded_external_tools {
        return;
    }
    let entries = fs::read_dir(directory).expect("production Rust root must be readable");
    for entry in entries {
        let path = entry.expect("directory entry must be readable").path();
        if path.is_dir() {
            if path
                .file_name()
                .is_some_and(|name| name == "target" || name == ".git" || name == ".lake")
            {
                continue;
            }
            collect_cargo_manifests(&path, excluded_external_tools, manifests);
        } else if path.file_name().is_some_and(|name| name == "Cargo.toml") {
            manifests.push(path);
        }
    }
}

#[test]
fn production_rust_manifests_cannot_depend_on_the_clear_oracle() {
    let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("generator must remain under repository tools/");
    let mut manifests = Vec::new();
    let excluded_external_tools =
        repository_root.join("crates/ed25519-yao/formal-verification/lean-boundary/tools");
    for relative_root in PRODUCTION_RUST_ROOTS {
        collect_cargo_manifests(
            &repository_root.join(relative_root),
            &excluded_external_tools,
            &mut manifests,
        );
    }

    for manifest in manifests {
        let contents = fs::read_to_string(&manifest).expect("Cargo manifest must be readable");
        if !contents.contains(FORBIDDEN_PACKAGE_NAME) {
            continue;
        }
        let relative_manifest = manifest
            .strip_prefix(repository_root)
            .expect("scanned manifest is under the repository root");
        assert_eq!(
            relative_manifest,
            Path::new(ALLOWED_DEV_MANIFEST),
            "manifest {} depends on the joined clear oracle outside the one formal dev boundary",
            manifest.display()
        );
        let dev_dependencies = contents
            .split_once("[dev-dependencies]")
            .map(|(_, dependencies)| dependencies)
            .and_then(|dependencies| dependencies.split("\n[").next())
            .expect("formal mirror dependency must remain dev-only");
        assert!(
            dev_dependencies.contains(FORBIDDEN_PACKAGE_NAME),
            "formal mirror clear-oracle dependency must remain under [dev-dependencies]"
        );
    }
}
