use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use wasmparser::{KnownCustom, Name, Operator, Parser, Payload, TypeRef};

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates directory")
        .parent()
        .expect("repository root")
        .to_path_buf()
}

struct ReleaseWasmTarget {
    manifest: PathBuf,
    artifact: PathBuf,
}

fn release_wasm_targets(root: &Path) -> [ReleaseWasmTarget; 3] {
    [
        ReleaseWasmTarget {
            manifest: root.join("wasm/router_ab_ecdsa_presign_client/Cargo.toml"),
            artifact: root.join(
                "wasm/router_ab_ecdsa_presign_client/target/wasm32-unknown-unknown/release/router_ab_ecdsa_presign_client.wasm",
            ),
        },
        ReleaseWasmTarget {
            manifest: root.join("wasm/router_ab_ecdsa_signing_worker/Cargo.toml"),
            artifact: root.join(
                "wasm/router_ab_ecdsa_signing_worker/target/wasm32-unknown-unknown/release/router_ab_ecdsa_signing_worker.wasm",
            ),
        },
        ReleaseWasmTarget {
            manifest: root.join("wasm/router_ab_ecdsa_online_client/Cargo.toml"),
            artifact: root.join(
                "wasm/router_ab_ecdsa_online_client/target/wasm32-unknown-unknown/release/router_ab_ecdsa_online_client.wasm",
            ),
        },
    ]
}

fn ensure_release_wasm(target: &ReleaseWasmTarget) {
    if target.artifact.is_file() {
        return;
    }
    let output = Command::new("cargo")
        .args([
            "build",
            "--locked",
            "--offline",
            "--release",
            "--target",
            "wasm32-unknown-unknown",
            "--manifest-path",
            target
                .manifest
                .to_str()
                .expect("Wasm manifest path must be UTF-8"),
        ])
        .output()
        .expect("cargo build must be available");
    assert!(
        output.status.success(),
        "failed to build {}: {}",
        target.manifest.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn function_names_and_import_count(
    bytes: &[u8],
) -> Result<(BTreeMap<u32, String>, u32), wasmparser::BinaryReaderError> {
    let mut names = BTreeMap::new();
    let mut imported_functions = 0u32;
    for payload in Parser::new(0).parse_all(bytes) {
        match payload? {
            Payload::ImportSection(imports) => {
                for import in imports {
                    if matches!(import?.ty, TypeRef::Func(_)) {
                        imported_functions += 1;
                    }
                }
            }
            Payload::CustomSection(section) => {
                if let KnownCustom::Name(reader) = section.as_known() {
                    for subsection in reader {
                        if let Name::Function(functions) = subsection? {
                            for function in functions {
                                let function = function?;
                                names.insert(function.index, function.name.to_owned());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok((names, imported_functions))
}

fn variable_time_arithmetic_operators(
    bytes: &[u8],
) -> Result<Vec<String>, wasmparser::BinaryReaderError> {
    let (function_names, imported_functions) = function_names_and_import_count(bytes)?;
    let mut findings = Vec::new();
    let mut body_index = 0u32;
    for payload in Parser::new(0).parse_all(bytes) {
        if let Payload::CodeSectionEntry(body) = payload? {
            let mut operators = body.get_operators_reader()?;
            while !operators.eof() {
                let offset = operators.original_position();
                let operator = operators.read()?;
                if matches!(
                    operator,
                    Operator::I32DivS
                        | Operator::I32DivU
                        | Operator::I32RemS
                        | Operator::I32RemU
                        | Operator::I64DivS
                        | Operator::I64DivU
                        | Operator::I64RemS
                        | Operator::I64RemU
                        | Operator::F32Div
                        | Operator::F32Sqrt
                        | Operator::F64Div
                        | Operator::F64Sqrt
                ) {
                    let function_index = imported_functions + body_index;
                    let function_name = function_names
                        .get(&function_index)
                        .map(String::as_str)
                        .unwrap_or("<unnamed>");
                    findings.push(format!("body={body_index} function={function_name} offset={offset} operator={operator:?}"));
                }
            }
            body_index += 1;
        }
    }
    Ok(findings)
}

fn is_approved_public_arithmetic(finding: &str) -> bool {
    [
        "core..iter",
        "core..array..drain",
        "4core4iter",
        "alloc..vec",
        "hashbrown",
        "const_oid",
        "core3fmt",
        "signingworkerpresignsession_poll",
        "digest..core_api..wrapper", // Fixed/public input-length block partitioning.
        "hmac11get_der_key",         // Fixed 32-byte HKDF input-key length.
    ]
    .iter()
    .any(|fragment| finding.contains(fragment))
}

#[test]
fn release_wasm_kernels_exclude_variable_time_division_and_sqrt() {
    let root = repository_root();
    for target in release_wasm_targets(&root) {
        ensure_release_wasm(&target);
        assert!(
            target.artifact.is_file(),
            "missing release Wasm artifact {} after a successful build",
            target.artifact.display()
        );
        let bytes = fs::read(&target.artifact).unwrap_or_else(|error| {
            panic!("failed to read {}: {error}", target.artifact.display())
        });
        let findings = variable_time_arithmetic_operators(&bytes).unwrap_or_else(|error| {
            panic!("failed to parse {}: {error}", target.artifact.display())
        });
        let unapproved: Vec<&str> = findings
            .iter()
            .map(String::as_str)
            .filter(|finding| !is_approved_public_arithmetic(finding))
            .collect();
        assert!(
            unapproved.is_empty(),
            "{} contains variable-time arithmetic outside approved public length, collection, OID, and formatting code:\n{}",
            target.artifact.display(),
            unapproved.join("\n")
        );
    }
}
