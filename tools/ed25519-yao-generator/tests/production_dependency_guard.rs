use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN_PACKAGE_NAME: &str = "ed25519-yao-generator";
const PRODUCTION_RUST_ROOTS: [&str; 2] = ["crates", "wasm"];

fn collect_cargo_manifests(directory: &Path, manifests: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(directory).expect("production Rust root must be readable");
    for entry in entries {
        let path = entry.expect("directory entry must be readable").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            collect_cargo_manifests(&path, manifests);
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
    for relative_root in PRODUCTION_RUST_ROOTS {
        collect_cargo_manifests(&repository_root.join(relative_root), &mut manifests);
    }

    for manifest in manifests {
        let contents = fs::read_to_string(&manifest).expect("Cargo manifest must be readable");
        assert!(
            !contents.contains(FORBIDDEN_PACKAGE_NAME),
            "production manifest {} depends on the joined clear oracle",
            manifest.display()
        );
    }
}
