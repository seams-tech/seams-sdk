use std::fs;
use std::path::Path;
use std::process::Command;

use ed25519_yao_generator::{
    canonical_fixed_reference_generated_block_v1, render_fixed_reference_specification_v1,
    FixedReferenceSpecificationErrorV1, FIXED_REFERENCE_GENERATED_BEGIN_V1,
    FIXED_REFERENCE_GENERATED_END_V1, FIXED_REFERENCE_GENERATED_SCHEMA_V1,
};
use sha2::{Digest, Sha256};

const COMMITTED_SPECIFICATION: &str = include_str!("../docs/fixed-reference-v1.md");

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn marker_template(body: &str) -> String {
    format!(
        "prefix\n{FIXED_REFERENCE_GENERATED_BEGIN_V1}\n{body}\n{FIXED_REFERENCE_GENERATED_END_V1}\n"
    )
}

#[test]
fn committed_specification_is_canonical_and_self_regenerating() {
    assert!(COMMITTED_SPECIFICATION.ends_with('\n'));
    assert!(!COMMITTED_SPECIFICATION.ends_with("\n\n"));
    assert_eq!(
        COMMITTED_SPECIFICATION
            .matches(FIXED_REFERENCE_GENERATED_BEGIN_V1)
            .count(),
        1
    );
    assert_eq!(
        COMMITTED_SPECIFICATION
            .matches(FIXED_REFERENCE_GENERATED_END_V1)
            .count(),
        1
    );
    assert_eq!(
        render_fixed_reference_specification_v1(COMMITTED_SPECIFICATION)
            .expect("committed specification renders"),
        COMMITTED_SPECIFICATION
    );
}

#[test]
fn generated_block_commits_the_exact_repository_corpora() {
    let block = canonical_fixed_reference_generated_block_v1().expect("goldens render");
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for relative_path in [
        "vectors/ed25519-yao-v1.json",
        "vectors/ed25519-yao-kdf-v1.json",
        "vectors/ed25519-yao-ceremony-context-v1.json",
        "vectors/ed25519-yao-lifecycle-continuity-v1.json",
        "vectors/ed25519-yao-provenance-v1.json",
        "vectors/ed25519-yao-output-sharing-v1.json",
        "vectors/ed25519-yao-semantic-lifecycle-v1.json",
        "vectors/ed25519-yao-output-party-views-v1.json",
        "vectors/ed25519-yao-evaluation-input-party-views-v1.json",
        "vectors/ed25519-yao-uniform-abort-envelope-v1.json",
        "vectors/ed25519-yao-evaluator-abort-state-party-views-v1.json",
        "vectors/ed25519-yao-export-delivery-v1.json",
        "vectors/ed25519-yao-activation-delivery-v1.json",
        "vectors/ed25519-yao-activation-recipient-party-views-v1.json",
        "vectors/ed25519-yao-recovery-credential-transition-v1.json",
        "vectors/ed25519-yao-export-evaluator-authorization-v1.json",
        "vectors/ed25519-yao-registration-evaluator-admission-v1.json",
        "vectors/ed25519-yao-recovery-evaluator-admission-v1.json",
        "vectors/ed25519-yao-refresh-evaluator-admission-v1.json",
        "vectors/ed25519-yao-semantic-frame-party-views-v1.json",
        "vectors/ed25519-yao-phase2b-core-reconciliation-v1.json",
    ] {
        let bytes =
            fs::read(manifest_dir.join(relative_path)).expect("committed corpus is readable");
        let digest = encode_hex(&Sha256::digest(&bytes));
        let row = block
            .lines()
            .find(|line| line.contains(&format!("`{relative_path}`")))
            .expect("generated block contains corpus row");
        assert!(row.contains(&format!("| {} |", bytes.len())));
        assert!(row.contains(&format!("`{digest}`")));
    }

    for relative_path in [
        "docs/output-sharing-v1.md",
        "docs/circuit-ir-v1.md",
        "docs/ceremony-context-v1.md",
        "docs/input-provenance-v1.md",
        "docs/semantic-artifact-lifecycle-v1.md",
        "docs/output-party-views-v1.md",
        "docs/evaluation-input-party-views-v1.md",
        "docs/uniform-abort-envelope-v1.md",
        "docs/evaluator-abort-state-party-views-v1.md",
        "docs/export-delivery-lifecycle-v1.md",
        "docs/activation-delivery-lifecycle-v1.md",
        "docs/activation-recipient-party-views-v1.md",
        "docs/recovery-credential-transition-v1.md",
        "docs/export-evaluator-authorization-v1.md",
        "docs/registration-evaluator-admission-v1.md",
        "docs/recovery-evaluator-admission-v1.md",
        "docs/refresh-evaluator-admission-v1.md",
        "docs/semantic-frame-party-views-v1.md",
        "docs/phase2b-core-reconciliation-v1.md",
    ] {
        let bytes = fs::read(manifest_dir.join(relative_path))
            .expect("companion specification is readable");
        let digest = encode_hex(&Sha256::digest(&bytes));
        let row = block
            .lines()
            .find(|line| line.contains(&format!("`{relative_path}`")))
            .expect("generated block contains companion specification row");
        assert!(row.contains(&format!("| {} |", bytes.len())));
        assert!(row.contains(&format!("`{digest}`")));
    }
}

#[test]
fn input_provenance_document_commitment_is_drift_sensitive() {
    let block = canonical_fixed_reference_generated_block_v1().expect("goldens render");
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/input-provenance-v1.md");
    let bytes = fs::read(path).expect("input-provenance specification is readable");
    let row = block
        .lines()
        .find(|line| line.contains("`docs/input-provenance-v1.md`"))
        .expect("generated block contains input-provenance specification row");
    let digest = encode_hex(&Sha256::digest(&bytes));
    assert!(row.contains(&format!("| {} |", bytes.len())));
    assert!(row.contains(&format!("`{digest}`")));

    let mut drifted = bytes;
    drifted[0] ^= 1;
    let drifted_digest = encode_hex(&Sha256::digest(&drifted));
    assert_ne!(drifted_digest, digest);
    assert!(!row.contains(&format!("`{drifted_digest}`")));
}

#[test]
fn generated_block_has_eight_kdf_rows_and_no_unfrozen_fields() {
    let block = canonical_fixed_reference_generated_block_v1().expect("goldens render");
    let kdf_rows = block
        .lines()
        .filter(|line| line.starts_with("| A |") || line.starts_with("| B |"))
        .count();

    assert_eq!(kdf_rows, 8);
    assert!(block.contains(FIXED_REFERENCE_GENERATED_SCHEMA_V1));
    for excluded in ["transcript", "package", "receipt", "wire"] {
        assert!(!block.contains(excluded));
    }
}

#[test]
fn renderer_rejects_missing_duplicate_and_reversed_markers() {
    assert_eq!(
        render_fixed_reference_specification_v1("plain text\n"),
        Err(FixedReferenceSpecificationErrorV1::MissingBeginMarker)
    );
    assert_eq!(
        render_fixed_reference_specification_v1(&format!(
            "{FIXED_REFERENCE_GENERATED_BEGIN_V1}\n{FIXED_REFERENCE_GENERATED_BEGIN_V1}\n{FIXED_REFERENCE_GENERATED_END_V1}\n"
        )),
        Err(FixedReferenceSpecificationErrorV1::DuplicateBeginMarker)
    );
    assert_eq!(
        render_fixed_reference_specification_v1(&format!("{FIXED_REFERENCE_GENERATED_BEGIN_V1}\n")),
        Err(FixedReferenceSpecificationErrorV1::MissingEndMarker)
    );
    assert_eq!(
        render_fixed_reference_specification_v1(&format!(
            "{FIXED_REFERENCE_GENERATED_BEGIN_V1}\n{FIXED_REFERENCE_GENERATED_END_V1}\n{FIXED_REFERENCE_GENERATED_END_V1}\n"
        )),
        Err(FixedReferenceSpecificationErrorV1::DuplicateEndMarker)
    );
    assert_eq!(
        render_fixed_reference_specification_v1(&format!(
            "{FIXED_REFERENCE_GENERATED_END_V1}\n{FIXED_REFERENCE_GENERATED_BEGIN_V1}\n"
        )),
        Err(FixedReferenceSpecificationErrorV1::InvalidMarkerOrder)
    );
}

#[test]
fn renderer_rejects_noncanonical_marker_lines_and_document_endings() {
    let inline = format!(
        "prefix {FIXED_REFERENCE_GENERATED_BEGIN_V1}\n{FIXED_REFERENCE_GENERATED_END_V1}\n"
    );
    assert_eq!(
        render_fixed_reference_specification_v1(&inline),
        Err(FixedReferenceSpecificationErrorV1::NonCanonicalMarkerLine)
    );

    let begin_crlf = format!(
        "{FIXED_REFERENCE_GENERATED_BEGIN_V1}\r\nstale\n{FIXED_REFERENCE_GENERATED_END_V1}\n"
    );
    assert_eq!(
        render_fixed_reference_specification_v1(&begin_crlf),
        Err(FixedReferenceSpecificationErrorV1::NonCanonicalMarkerLine)
    );

    let end_crlf = format!(
        "{FIXED_REFERENCE_GENERATED_BEGIN_V1}\nstale\n{FIXED_REFERENCE_GENERATED_END_V1}\r\ntail\n"
    );
    assert_eq!(
        render_fixed_reference_specification_v1(&end_crlf),
        Err(FixedReferenceSpecificationErrorV1::NonCanonicalMarkerLine)
    );

    let no_final_lf = marker_template("stale")
        .strip_suffix('\n')
        .expect("template ends in LF")
        .to_owned();
    assert_eq!(
        render_fixed_reference_specification_v1(&no_final_lf),
        Err(FixedReferenceSpecificationErrorV1::NonCanonicalDocumentEnding)
    );
    assert_eq!(
        render_fixed_reference_specification_v1(&(marker_template("stale") + "\n")),
        Err(FixedReferenceSpecificationErrorV1::NonCanonicalDocumentEnding)
    );
}

#[test]
fn renderer_repairs_generated_drift_and_preserves_human_prose() {
    let tampered = COMMITTED_SPECIFICATION.replace(
        "13934b86ed57e6634c2a3d8ff1361923e9caf28c2aad160251d0b2af779a7e36",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert_ne!(tampered, COMMITTED_SPECIFICATION);
    assert_eq!(
        render_fixed_reference_specification_v1(&tampered).expect("tampered block renders"),
        COMMITTED_SPECIFICATION
    );

    let changed_prose = COMMITTED_SPECIFICATION.replacen(
        "This specification owns",
        "This specification normatively owns",
        1,
    );
    let rendered =
        render_fixed_reference_specification_v1(&changed_prose).expect("changed prose renders");
    assert!(rendered.contains("This specification normatively owns"));
}

#[test]
fn dedicated_cli_checks_the_committed_specification() {
    let input = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/fixed-reference-v1.md");
    let output = Command::new(env!("CARGO_BIN_EXE_ed25519-yao-spec-goldens"))
        .args(["check", "--input"])
        .arg(&input)
        .output()
        .expect("specification checker starts");

    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)
        .expect("checker stdout is UTF-8")
        .contains("checked fixed-reference-v1 specification"));
}
