use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const FORBIDDEN_HOST_PACKAGE_NAMES: [&str; 2] =
    ["ed25519-yao-generator", "ed25519-yao-artifact-fs-policy"];
const PRODUCTION_RUST_ROOTS: [&str; 2] = ["crates", "wasm"];

fn collect_production_entry_manifests(repository_root: &Path) -> Vec<PathBuf> {
    let mut manifests = Vec::new();
    for relative_root in PRODUCTION_RUST_ROOTS {
        let root = repository_root.join(relative_root);
        for entry in fs::read_dir(&root).expect("production Rust root must be readable") {
            let path = entry.expect("production entry must be readable").path();
            let manifest = path.join("Cargo.toml");
            if path.is_dir() && manifest.is_file() {
                manifests.push(manifest);
            }
        }
    }
    manifests.sort();
    manifests
}

fn forbidden_runtime_dependency(
    manifest: &Path,
) -> Result<Option<(String, PathBuf)>, Box<dyn std::error::Error>> {
    let mut visited = HashSet::new();
    find_forbidden_runtime_dependency(manifest, &mut visited)
}

fn find_forbidden_runtime_dependency(
    manifest: &Path,
    visited: &mut HashSet<PathBuf>,
) -> Result<Option<(String, PathBuf)>, Box<dyn std::error::Error>> {
    let manifest = manifest.canonicalize()?;
    if !visited.insert(manifest.clone()) {
        return Ok(None);
    }
    let source = fs::read_to_string(&manifest)?;
    let document = source.parse::<toml::Value>()?;
    let package_name = document
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| format!("{} has no package.name", manifest.display()))?;
    if FORBIDDEN_HOST_PACKAGE_NAMES.contains(&package_name) {
        return Ok(Some((package_name.to_owned(), manifest)));
    }
    let manifest_directory = manifest
        .parent()
        .expect("canonical Cargo manifest has a parent");
    if let Some(forbidden) = forbidden_locked_package(manifest_directory)? {
        return Ok(Some(forbidden));
    }
    let mut dependencies = Vec::new();
    collect_local_runtime_dependencies(&document, manifest_directory, &mut dependencies)?;
    dependencies.sort();
    dependencies.dedup();
    for dependency in dependencies {
        if let Some(forbidden) = find_forbidden_runtime_dependency(&dependency, visited)? {
            return Ok(Some(forbidden));
        }
    }
    Ok(None)
}

fn forbidden_locked_package(
    manifest_directory: &Path,
) -> Result<Option<(String, PathBuf)>, Box<dyn std::error::Error>> {
    let lockfile = manifest_directory.join("Cargo.lock");
    if !lockfile.is_file() {
        return Ok(None);
    }
    let document = fs::read_to_string(&lockfile)?.parse::<toml::Value>()?;
    let packages = document
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| format!("{} has no package array", lockfile.display()))?;
    for package in packages {
        let Some(name) = package
            .as_table()
            .and_then(|table| table.get("name"))
            .and_then(toml::Value::as_str)
        else {
            return Err(format!("{} has a package without a name", lockfile.display()).into());
        };
        if FORBIDDEN_HOST_PACKAGE_NAMES.contains(&name) {
            return Ok(Some((name.to_owned(), lockfile)));
        }
    }
    Ok(None)
}

fn collect_local_runtime_dependencies(
    value: &toml::Value,
    manifest_directory: &Path,
    dependencies: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(table) = value.as_table() else {
        return Ok(());
    };
    for (key, child) in table {
        match key.as_str() {
            "dependencies" | "build-dependencies" => {
                collect_dependency_table(child, manifest_directory, dependencies)?;
            }
            "dev-dependencies" => {}
            _ => collect_local_runtime_dependencies(child, manifest_directory, dependencies)?,
        }
    }
    Ok(())
}

fn collect_dependency_table(
    value: &toml::Value,
    manifest_directory: &Path,
    dependencies: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let table = value
        .as_table()
        .ok_or("dependency section must be a TOML table")?;
    for specification in table.values() {
        let Some(path) = specification
            .as_table()
            .and_then(|dependency| dependency.get("path"))
            .and_then(toml::Value::as_str)
        else {
            continue;
        };
        let manifest = manifest_directory.join(path).join("Cargo.toml");
        if !manifest.is_file() {
            return Err(format!(
                "local dependency manifest is missing: {}",
                manifest.display()
            )
            .into());
        }
        dependencies.push(manifest);
    }
    Ok(())
}

#[test]
fn production_runtime_dependency_closures_exclude_host_only_yao_packages() {
    let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("generator must remain under repository tools/");
    let manifests = collect_production_entry_manifests(repository_root);
    assert!(!manifests.is_empty());
    for manifest in manifests {
        let forbidden = forbidden_runtime_dependency(&manifest)
            .unwrap_or_else(|error| panic!("failed to inspect {}: {error}", manifest.display()));
        assert!(
            forbidden.is_none(),
            "production manifest {} reaches forbidden host package {forbidden:?}",
            manifest.display()
        );
    }
}

#[test]
fn transitive_facade_dependency_is_rejected_while_dev_only_edges_are_ignored() {
    let fixture = TemporaryManifestGraph::create();
    fixture.write_package("generator", "ed25519-yao-generator", "");
    fixture.write_package(
        "facade",
        "innocent-facade",
        "[dependencies]\nhidden = { path = \"../generator\" }\n",
    );
    fixture.write_package(
        "production",
        "production-entry",
        "[dependencies]\nfacade = { path = \"../facade\" }\n",
    );
    let forbidden = forbidden_runtime_dependency(&fixture.manifest("production"))
        .expect("synthetic dependency graph parses")
        .expect("transitive host package is rejected");
    assert_eq!(forbidden.0, "ed25519-yao-generator");

    fixture.write_package(
        "dev-only",
        "dev-only-entry",
        "[dev-dependencies]\ngenerator = { path = \"../generator\" }\n",
    );
    assert!(forbidden_runtime_dependency(&fixture.manifest("dev-only"))
        .expect("dev-only graph parses")
        .is_none());

    fixture.write_package(
        "locked-facade",
        "locked-facade-entry",
        "[dependencies]\nremote-facade = \"1\"\n",
    );
    fixture.write_lockfile_with_forbidden_package("locked-facade", "ed25519-yao-generator");
    let forbidden = forbidden_runtime_dependency(&fixture.manifest("locked-facade"))
        .expect("synthetic locked graph parses")
        .expect("host package hidden behind a registry or Git facade is rejected");
    assert_eq!(forbidden.0, "ed25519-yao-generator");
}

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TemporaryManifestGraph {
    root: PathBuf,
}

impl TemporaryManifestGraph {
    fn create() -> Self {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!(
                "production-dependency-guard-{}-{id}",
                std::process::id()
            ));
        fs::create_dir_all(&root).expect("temporary manifest graph is created");
        Self { root }
    }

    fn write_package(&self, directory: &str, name: &str, dependencies: &str) {
        let path = self.root.join(directory);
        fs::create_dir_all(&path).expect("synthetic package directory is created");
        let manifest = format!(
            "[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[lib]\npath = \"lib.rs\"\n\n{dependencies}"
        );
        fs::write(path.join("Cargo.toml"), manifest).expect("synthetic manifest is written");
        fs::write(path.join("lib.rs"), "").expect("synthetic library is written");
    }

    fn manifest(&self, directory: &str) -> PathBuf {
        self.root.join(directory).join("Cargo.toml")
    }

    fn write_lockfile_with_forbidden_package(&self, directory: &str, package_name: &str) {
        let lockfile = format!(
            "# This file is automatically @generated by Cargo.\nversion = 3\n\n[[package]]\nname = \"{package_name}\"\nversion = \"0.0.0\"\n"
        );
        fs::write(self.root.join(directory).join("Cargo.lock"), lockfile)
            .expect("synthetic lockfile is written");
    }
}

impl Drop for TemporaryManifestGraph {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
