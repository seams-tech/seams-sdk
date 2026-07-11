use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signer, SigningKey, Verifier};
use ed25519_yao_generator::{
    evaluate_host_only_export_output_sharing_v1, prepare_host_only_export_reference_v1,
    reconstruct_host_only_seed_export_v1, DeriverAContribution, DeriverBContribution,
    HostOnlyExportIdealCoinV1, HostOnlyExportPublicKeyEqualityWitnessV1,
    HostOnlyExportReferenceErrorV1, HostOnlyExportReferenceInputsV1,
    HostOnlyPreparedExportReferenceV1, HostOnlySeedOutputCoinV1, RawDeriverAContribution,
    RawDeriverBContribution, RegisteredEd25519PublicKey32V1,
};

const RFC8032_SEED_ONE: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const RFC8032_PUBLIC_KEY_ONE: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const RFC8032_PUBLIC_KEY_TWO: [u8; 32] = [
    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
];

struct ExportFixture {
    deriver_a: DeriverAContribution,
    deriver_b: DeriverBContribution,
    expected_registered_public_key: RegisteredEd25519PublicKey32V1,
}

fn scalar_zero_bytes() -> [u8; 32] {
    Scalar::ZERO.to_bytes()
}

fn one_le_256() -> [u8; 32] {
    let mut value = [0u8; 32];
    value[0] = 1;
    value
}

fn expected_registered_public_key(bytes: [u8; 32]) -> RegisteredEd25519PublicKey32V1 {
    RegisteredEd25519PublicKey32V1::parse(bytes)
        .expect("hardcoded RFC 8032 public key is canonical and prime-order")
}

fn export_fixture() -> ExportFixture {
    export_fixture_from_y_fields(RFC8032_SEED_ONE, [0u8; 32], [0u8; 32], [0u8; 32])
}

fn wrapped_export_fixture() -> ExportFixture {
    export_fixture_from_y_fields([0xff; 32], one_le_256(), RFC8032_SEED_ONE, [0u8; 32])
}

fn export_fixture_from_y_fields(
    y_client_a: [u8; 32],
    y_server_a: [u8; 32],
    y_client_b: [u8; 32],
    y_server_b: [u8; 32],
) -> ExportFixture {
    let zero = scalar_zero_bytes();
    ExportFixture {
        deriver_a: DeriverAContribution::try_from(RawDeriverAContribution {
            y_client: y_client_a,
            y_server: y_server_a,
            tau_client: zero,
            tau_server: zero,
        })
        .expect("synthetic Deriver A export contribution is valid"),
        deriver_b: DeriverBContribution::try_from(RawDeriverBContribution {
            y_client: y_client_b,
            y_server: y_server_b,
            tau_client: zero,
            tau_server: zero,
        })
        .expect("synthetic Deriver B export contribution is valid"),
        expected_registered_public_key: expected_registered_public_key(RFC8032_PUBLIC_KEY_ONE),
    }
}

fn prepare(
    fixture: &ExportFixture,
) -> Result<HostOnlyPreparedExportReferenceV1, HostOnlyExportReferenceErrorV1> {
    prepare_with_expected_key(fixture, &fixture.expected_registered_public_key)
}

fn prepare_with_expected_key(
    fixture: &ExportFixture,
    expected_key: &RegisteredEd25519PublicKey32V1,
) -> Result<HostOnlyPreparedExportReferenceV1, HostOnlyExportReferenceErrorV1> {
    prepare_host_only_export_reference_v1(
        HostOnlyExportReferenceInputsV1::new(
            fixture.deriver_a.y_client(),
            fixture.deriver_a.y_server(),
            fixture.deriver_b.y_client(),
            fixture.deriver_b.y_server(),
        ),
        expected_key,
    )
}

fn accept_public_key_witness(_: &HostOnlyExportPublicKeyEqualityWitnessV1) {}

fn independent_wrapping_sub_le_256(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut borrow = false;
    for index in 0..32 {
        let (without_right, right_borrow) = left[index].overflowing_sub(right[index]);
        let (difference, prior_borrow) = without_right.overflowing_sub(u8::from(borrow));
        output[index] = difference;
        borrow = right_borrow || prior_borrow;
    }
    output
}

fn reconstruct_success_seed(
    success: &ed25519_yao_generator::HostOnlyExportReferenceSuccessV1,
) -> [u8; 32] {
    reconstruct_host_only_seed_export_v1(
        success.output_shares().deriver_a(),
        success.output_shares().deriver_b(),
    )
    .expose_bytes()
}

#[test]
fn matching_registered_key_prepares_public_key_equality_witness() {
    let fixture = export_fixture();
    let prepared = prepare(&fixture).expect("RFC 8032 registered key must match");

    assert_eq!(
        prepared.expected_registered_public_key().as_bytes(),
        &RFC8032_PUBLIC_KEY_ONE
    );
    accept_public_key_witness(prepared.public_key_equality_witness());
}

#[test]
fn different_valid_registered_key_is_rejected_and_borrowed_inputs_retry() {
    let fixture = export_fixture();
    let different_valid_key = expected_registered_public_key(RFC8032_PUBLIC_KEY_TWO);
    assert!(matches!(
        prepare_with_expected_key(&fixture, &different_valid_key),
        Err(HostOnlyExportReferenceErrorV1::RegisteredPublicKeyMismatch)
    ));

    let retry = prepare(&fixture).expect("borrowed synthetic inputs remain available for retry");
    accept_public_key_witness(retry.public_key_equality_witness());
}

#[test]
fn split_y_carry_and_wrap_reconstruct_exact_export_seed() {
    let fixture = wrapped_export_fixture();
    let prepared = prepare(&fixture).expect("wrapped split inputs derive the RFC seed key");
    let success = evaluate_host_only_export_output_sharing_v1(
        prepared,
        HostOnlyExportIdealCoinV1::from_host_only_fixture(
            HostOnlySeedOutputCoinV1::from_fixture_bytes([0u8; 32]),
        ),
    );

    assert_eq!(
        success.output_shares().deriver_a().expose_fixture_bytes(),
        [0u8; 32]
    );
    assert_eq!(
        success.output_shares().deriver_b().expose_fixture_bytes(),
        RFC8032_SEED_ONE
    );
    assert_eq!(reconstruct_success_seed(&success), RFC8032_SEED_ONE);
}

#[test]
fn seed_shares_match_independent_zero_one_and_max_arithmetic() {
    let fixture = export_fixture();
    for coin in [[0u8; 32], one_le_256(), [0xff; 32]] {
        let success = evaluate_host_only_export_output_sharing_v1(
            prepare(&fixture).expect("registered key must match for every fixture coin"),
            HostOnlyExportIdealCoinV1::from_host_only_fixture(
                HostOnlySeedOutputCoinV1::from_fixture_bytes(coin),
            ),
        );

        assert_eq!(
            success.output_shares().deriver_a().expose_fixture_bytes(),
            coin
        );
        assert_eq!(
            success.output_shares().deriver_b().expose_fixture_bytes(),
            independent_wrapping_sub_le_256(RFC8032_SEED_ONE, coin)
        );
        assert_eq!(reconstruct_success_seed(&success), RFC8032_SEED_ONE);
    }
}

#[test]
fn reconstructed_rfc8032_seed_signs_and_verifies_with_registered_key() {
    let fixture = export_fixture();
    let success = evaluate_host_only_export_output_sharing_v1(
        prepare(&fixture).expect("hardcoded RFC 8032 key must match"),
        HostOnlyExportIdealCoinV1::from_host_only_fixture(
            HostOnlySeedOutputCoinV1::from_fixture_bytes([0xa5; 32]),
        ),
    );
    let reconstructed_seed = reconstruct_success_seed(&success);
    let signing_key = SigningKey::from_bytes(&reconstructed_seed);
    let verifying_key = signing_key.verifying_key();
    let message = b"seams host-only export reference v1";
    let signature = signing_key.sign(message);

    assert_eq!(reconstructed_seed, RFC8032_SEED_ONE);
    assert_eq!(verifying_key.to_bytes(), RFC8032_PUBLIC_KEY_ONE);
    assert_eq!(
        success.expected_registered_public_key().as_bytes(),
        &verifying_key.to_bytes()
    );
    verifying_key
        .verify(message, &signature)
        .expect("signature from reconstructed RFC 8032 seed must verify");
    accept_public_key_witness(success.public_key_equality_witness());
}

struct UiHarness {
    directory: PathBuf,
}

impl UiHarness {
    fn create() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must follow Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "ed25519-yao-export-reference-ui-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(directory.join("src")).expect("create UI harness source directory");
        let manifest_directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .expect("canonical generator path");
        let dependency_path = manifest_directory.to_string_lossy().replace('\\', "\\\\");
        fs::write(
            directory.join("Cargo.toml"),
            format!(
                "[package]\nname = \"export-reference-ui\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
                 [dependencies]\ned25519-yao-generator = {{ path = \"{dependency_path}\" }}\n"
            ),
        )
        .expect("write UI harness manifest");
        Self { directory }
    }

    fn check(&self, body: &str) -> std::process::Output {
        fs::write(self.directory.join("src/main.rs"), body).expect("write UI harness source");
        Command::new(cargo_command())
            .args(["check", "--quiet", "--offline"])
            .current_dir(&self.directory)
            .env("CARGO_TARGET_DIR", self.directory.join("target"))
            .output()
            .expect("execute UI cargo check")
    }
}

impl Drop for UiHarness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn cargo_command() -> OsString {
    match std::env::var_os("CARGO") {
        Some(command) => command,
        None => OsString::from("cargo"),
    }
}

fn assert_compile_failure(harness: &UiHarness, body: &str, code: &str) {
    let output = harness.check(body);
    assert!(!output.status.success(), "UI case unexpectedly compiled");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(code),
        "UI case failed without {code}:\n{stderr}"
    );
}

#[test]
fn source_and_ui_guards_keep_export_synthetic_seed_scoped_and_nonproduction() {
    let harness = UiHarness::create();
    let control = harness.check(
        "use ed25519_yao_generator::{HostOnlyExportReferenceSuccessV1, HostOnlyPreparedExportReferenceV1};\n\
         fn accept(prepared: &HostOnlyPreparedExportReferenceV1, success: &HostOnlyExportReferenceSuccessV1) {\n\
             let _ = prepared.expected_registered_public_key();\n\
             let _ = prepared.public_key_equality_witness();\n\
             let _ = success.expected_registered_public_key();\n\
             let _ = success.public_key_equality_witness();\n\
             let _ = success.output_shares();\n\
         }\nfn main() {}",
    );
    assert!(
        control.status.success(),
        "UI control failed:\n{}",
        String::from_utf8_lossy(&control.stderr)
    );

    for (body, code) in [
        (
            "use ed25519_yao_generator::HostOnlyPreparedExportReferenceV1;\n\
             fn invalid(value: &HostOnlyPreparedExportReferenceV1) { let _ = value.seed(); }\nfn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::HostOnlyPreparedExportReferenceV1;\n\
             fn invalid(value: &HostOnlyPreparedExportReferenceV1) { let _ = value.material(); }\nfn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::HostOnlyExportReferenceSuccessV1;\n\
             fn invalid(value: &HostOnlyExportReferenceSuccessV1) { let _ = value.seed(); }\nfn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::HostOnlyExportReferenceSuccessV1;\n\
             fn invalid(value: &HostOnlyExportReferenceSuccessV1) { let _ = value.prepared(); }\nfn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::HostOnlyPreparedExportReferenceV1;\n\
             fn invalid(value: HostOnlyPreparedExportReferenceV1) { let _ = value.clone(); }\nfn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::HostOnlyExportPublicKeyEqualityWitnessV1;\n\
             fn main() { let _ = HostOnlyExportPublicKeyEqualityWitnessV1 { _private: () }; }",
            "E0451",
        ),
    ] {
        assert_compile_failure(&harness, body, code);
    }

    let source = include_str!("../src/export_reference.rs");
    for forbidden in [
        "serde",
        "Serialize",
        "Deserialize",
        "rand::",
        "rand_core",
        "getrandom",
        "OsRng",
        "Authorization",
        "ApprovedExportAuthorizationV1",
        "ConsumedExportAuthorizationV1",
        "ExportRequestV1",
        "RegisteredPreStateV1",
        "RoleInputProvenance",
        "Ciphertext",
        "Package",
        "Receipt",
        "Persistence",
        "lifecycle_domain",
        "worker::",
        "wasm_bindgen",
        "cloudflare",
        "evaluate_export_v1(",
        "ExportOracleOutput",
        "OracleMaterial",
        "pub const fn seed",
        "pub fn seed",
        "pub const fn material",
        "pub fn material",
        "pub const fn export_output",
        "pub fn export_output",
    ] {
        assert!(
            !source.contains(forbidden),
            "blocked dependency or overstated surface `{forbidden}` entered export reference"
        );
    }
    assert!(source.contains("seed: SeedBytes"));
    assert!(source.contains("share_host_only_export_seed_from_seed_v1(&seed"));

    for line in source.lines() {
        let declaration = line.trim();
        if !declaration.starts_with("pub struct ") && !declaration.starts_with("pub enum ") {
            continue;
        }
        let type_name = declaration
            .split_ascii_whitespace()
            .nth(2)
            .expect("public type declaration name")
            .trim_end_matches("<'a>");
        assert!(
            type_name.starts_with("HostOnly"),
            "public export type lacks HostOnly prefix: {type_name}"
        );
    }
}
