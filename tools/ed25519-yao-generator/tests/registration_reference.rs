use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use ed25519_yao_generator::{
    evaluate_host_only_registration_output_sharing_v1, prepare_host_only_registration_reference_v1,
    reconstruct_host_only_client_scalar_output_v1,
    reconstruct_host_only_signing_worker_scalar_output_v1, HostOnlyActivationOutputCoinsV1,
    HostOnlyClientScalarOutputCoinV1, HostOnlyPreparedRegistrationReferenceV1,
    HostOnlyRegistrationIdealCoinsV1, HostOnlyRegistrationReferenceInputsV1,
    HostOnlySigningWorkerScalarOutputCoinV1, StableKeyDerivationContext,
    SyntheticClientDerivationRootV1, SyntheticDeriverADerivationRootV1,
    SyntheticDeriverBDerivationRootV1, CONTRIBUTION_KDF_CLIENT_SOURCE_TAG_V1,
    CONTRIBUTION_KDF_EXPAND_INFO_DOMAIN_V1, CONTRIBUTION_KDF_EXTRACT_SALT_V1,
    CONTRIBUTION_KDF_ROLE_A_TAG_V1, CONTRIBUTION_KDF_ROLE_B_TAG_V1,
    CONTRIBUTION_KDF_SERVER_SOURCE_TAG_V1, CONTRIBUTION_KDF_TAU_OUTPUT_TAG_V1,
    CONTRIBUTION_KDF_Y_OUTPUT_TAG_V1,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha512};

const CLIENT_ROOT_BYTES: [u8; 32] = [0x11; 32];
const DERIVER_A_ROOT_BYTES: [u8; 32] = [0x22; 32];
const DERIVER_B_ROOT_BYTES: [u8; 32] = [0x33; 32];

struct RegistrationFixture {
    client_root: SyntheticClientDerivationRootV1,
    deriver_a_root: SyntheticDeriverADerivationRootV1,
    deriver_b_root: SyntheticDeriverBDerivationRootV1,
    context: StableKeyDerivationContext,
}

struct IndependentContribution {
    y: [u8; 32],
    tau: [u8; 32],
}

fn registration_fixture() -> RegistrationFixture {
    RegistrationFixture {
        client_root: SyntheticClientDerivationRootV1::from_fixture_bytes(CLIENT_ROOT_BYTES),
        deriver_a_root: SyntheticDeriverADerivationRootV1::from_fixture_bytes(DERIVER_A_ROOT_BYTES),
        deriver_b_root: SyntheticDeriverBDerivationRootV1::from_fixture_bytes(DERIVER_B_ROOT_BYTES),
        context: StableKeyDerivationContext::new([0x42; 32], 1, 2)
            .expect("synthetic stable context is valid"),
    }
}

fn prepare(fixture: &RegistrationFixture) -> HostOnlyPreparedRegistrationReferenceV1 {
    prepare_with(
        &fixture.client_root,
        &fixture.deriver_a_root,
        &fixture.deriver_b_root,
        &fixture.context,
    )
}

fn prepare_with(
    client_root: &SyntheticClientDerivationRootV1,
    deriver_a_root: &SyntheticDeriverADerivationRootV1,
    deriver_b_root: &SyntheticDeriverBDerivationRootV1,
    context: &StableKeyDerivationContext,
) -> HostOnlyPreparedRegistrationReferenceV1 {
    prepare_host_only_registration_reference_v1(HostOnlyRegistrationReferenceInputsV1::new(
        client_root,
        deriver_a_root,
        deriver_b_root,
        context,
    ))
}

fn independent_contribution(
    root: [u8; 32],
    context: &StableKeyDerivationContext,
    role_tag: u8,
    source_tag: u8,
) -> IndependentContribution {
    let hkdf = Hkdf::<Sha256>::new(Some(CONTRIBUTION_KDF_EXTRACT_SALT_V1), &root);
    let binding = context.binding_digest();
    let y_info = independent_expand_info(
        role_tag,
        source_tag,
        CONTRIBUTION_KDF_Y_OUTPUT_TAG_V1,
        binding.as_bytes(),
    );
    let tau_info = independent_expand_info(
        role_tag,
        source_tag,
        CONTRIBUTION_KDF_TAU_OUTPUT_TAG_V1,
        binding.as_bytes(),
    );
    let mut y = [0u8; 32];
    hkdf.expand(&y_info, &mut y)
        .expect("32-byte HKDF output is valid");
    let mut tau_wide = [0u8; 64];
    hkdf.expand(&tau_info, &mut tau_wide)
        .expect("64-byte HKDF output is valid");
    IndependentContribution {
        y,
        tau: Scalar::from_bytes_mod_order_wide(&tau_wide).to_bytes(),
    }
}

fn independent_expand_info(
    role_tag: u8,
    source_tag: u8,
    output_tag: u8,
    context_binding: &[u8; 32],
) -> Vec<u8> {
    let mut info = Vec::with_capacity(CONTRIBUTION_KDF_EXPAND_INFO_DOMAIN_V1.len() + 36);
    info.extend_from_slice(CONTRIBUTION_KDF_EXPAND_INFO_DOMAIN_V1);
    info.push(0);
    info.push(role_tag);
    info.push(source_tag);
    info.push(output_tag);
    info.extend_from_slice(context_binding);
    info
}

fn parse_scalar(bytes: [u8; 32]) -> Scalar {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .expect("prepared scalar remains canonical")
}

fn independent_add_le_256(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut carry = 0u16;
    for index in 0..32 {
        let sum = u16::from(left[index]) + u16::from(right[index]) + carry;
        output[index] = sum as u8;
        carry = sum >> 8;
    }
    output
}

fn independent_clamp(mut digest_prefix: [u8; 32]) -> [u8; 32] {
    digest_prefix[0] &= 248;
    digest_prefix[31] &= 63;
    digest_prefix[31] |= 64;
    digest_prefix
}

fn assert_deriver_a_equal(
    left: &HostOnlyPreparedRegistrationReferenceV1,
    right: &HostOnlyPreparedRegistrationReferenceV1,
) {
    assert_eq!(
        left.deriver_a().y_client().expose_bytes(),
        right.deriver_a().y_client().expose_bytes()
    );
    assert_eq!(
        left.deriver_a().y_server().expose_bytes(),
        right.deriver_a().y_server().expose_bytes()
    );
    assert_eq!(
        left.deriver_a().tau_client().expose_bytes(),
        right.deriver_a().tau_client().expose_bytes()
    );
    assert_eq!(
        left.deriver_a().tau_server().expose_bytes(),
        right.deriver_a().tau_server().expose_bytes()
    );
}

fn assert_deriver_b_equal(
    left: &HostOnlyPreparedRegistrationReferenceV1,
    right: &HostOnlyPreparedRegistrationReferenceV1,
) {
    assert_eq!(
        left.deriver_b().y_client().expose_bytes(),
        right.deriver_b().y_client().expose_bytes()
    );
    assert_eq!(
        left.deriver_b().y_server().expose_bytes(),
        right.deriver_b().y_server().expose_bytes()
    );
    assert_eq!(
        left.deriver_b().tau_client().expose_bytes(),
        right.deriver_b().tau_client().expose_bytes()
    );
    assert_eq!(
        left.deriver_b().tau_server().expose_bytes(),
        right.deriver_b().tau_server().expose_bytes()
    );
}

fn assert_activation_equal(
    left: &HostOnlyPreparedRegistrationReferenceV1,
    right: &HostOnlyPreparedRegistrationReferenceV1,
) {
    let left = left.activation().material();
    let right = right.activation().material();
    assert_eq!(
        left.sha512_digest().expose_bytes(),
        right.sha512_digest().expose_bytes()
    );
    assert_eq!(
        left.clamped_scalar_bytes().expose_bytes(),
        right.clamped_scalar_bytes().expose_bytes()
    );
    assert_eq!(
        left.signing_scalar().expose_bytes(),
        right.signing_scalar().expose_bytes()
    );
    assert_eq!(left.tau().expose_bytes(), right.tau().expose_bytes());
    assert_eq!(
        left.x_client_base().expose_bytes(),
        right.x_client_base().expose_bytes()
    );
    assert_eq!(
        left.x_server_base().expose_bytes(),
        right.x_server_base().expose_bytes()
    );
    assert_eq!(
        left.x_client().expose_bytes(),
        right.x_client().expose_bytes()
    );
    assert_eq!(
        left.x_server().expose_bytes(),
        right.x_server().expose_bytes()
    );
    assert_eq!(
        left.public_key().expose_bytes(),
        right.public_key().expose_bytes()
    );
}

#[test]
fn preparation_derives_exact_role_and_source_separated_inputs() {
    let fixture = registration_fixture();
    let prepared = prepare(&fixture);
    let client_a = independent_contribution(
        CLIENT_ROOT_BYTES,
        &fixture.context,
        CONTRIBUTION_KDF_ROLE_A_TAG_V1,
        CONTRIBUTION_KDF_CLIENT_SOURCE_TAG_V1,
    );
    let client_b = independent_contribution(
        CLIENT_ROOT_BYTES,
        &fixture.context,
        CONTRIBUTION_KDF_ROLE_B_TAG_V1,
        CONTRIBUTION_KDF_CLIENT_SOURCE_TAG_V1,
    );
    let server_a = independent_contribution(
        DERIVER_A_ROOT_BYTES,
        &fixture.context,
        CONTRIBUTION_KDF_ROLE_A_TAG_V1,
        CONTRIBUTION_KDF_SERVER_SOURCE_TAG_V1,
    );
    let server_b = independent_contribution(
        DERIVER_B_ROOT_BYTES,
        &fixture.context,
        CONTRIBUTION_KDF_ROLE_B_TAG_V1,
        CONTRIBUTION_KDF_SERVER_SOURCE_TAG_V1,
    );

    assert_eq!(prepared.deriver_a().y_client().expose_bytes(), client_a.y);
    assert_eq!(
        prepared.deriver_a().tau_client().expose_bytes(),
        client_a.tau
    );
    assert_eq!(prepared.deriver_a().y_server().expose_bytes(), server_a.y);
    assert_eq!(
        prepared.deriver_a().tau_server().expose_bytes(),
        server_a.tau
    );
    assert_eq!(prepared.deriver_b().y_client().expose_bytes(), client_b.y);
    assert_eq!(
        prepared.deriver_b().tau_client().expose_bytes(),
        client_b.tau
    );
    assert_eq!(prepared.deriver_b().y_server().expose_bytes(), server_b.y);
    assert_eq!(
        prepared.deriver_b().tau_server().expose_bytes(),
        server_b.tau
    );
}

#[test]
fn root_and_context_mutations_stay_within_their_kdf_domains() {
    let fixture = registration_fixture();
    let baseline = prepare(&fixture);
    let changed_client = SyntheticClientDerivationRootV1::from_fixture_bytes([0x12; 32]);
    let changed_client_prepared = prepare_with(
        &changed_client,
        &fixture.deriver_a_root,
        &fixture.deriver_b_root,
        &fixture.context,
    );
    assert_ne!(
        baseline.deriver_a().y_client().expose_bytes(),
        changed_client_prepared
            .deriver_a()
            .y_client()
            .expose_bytes()
    );
    assert_ne!(
        baseline.deriver_b().tau_client().expose_bytes(),
        changed_client_prepared
            .deriver_b()
            .tau_client()
            .expose_bytes()
    );
    assert_eq!(
        baseline.deriver_a().y_server().expose_bytes(),
        changed_client_prepared
            .deriver_a()
            .y_server()
            .expose_bytes()
    );
    assert_eq!(
        baseline.deriver_b().tau_server().expose_bytes(),
        changed_client_prepared
            .deriver_b()
            .tau_server()
            .expose_bytes()
    );

    let changed_a = SyntheticDeriverADerivationRootV1::from_fixture_bytes([0x23; 32]);
    let changed_a_prepared = prepare_with(
        &fixture.client_root,
        &changed_a,
        &fixture.deriver_b_root,
        &fixture.context,
    );
    assert_ne!(
        baseline.deriver_a().y_server().expose_bytes(),
        changed_a_prepared.deriver_a().y_server().expose_bytes()
    );
    assert_eq!(
        baseline.deriver_a().y_client().expose_bytes(),
        changed_a_prepared.deriver_a().y_client().expose_bytes()
    );
    assert_deriver_b_equal(&baseline, &changed_a_prepared);

    let changed_b = SyntheticDeriverBDerivationRootV1::from_fixture_bytes([0x34; 32]);
    let changed_b_prepared = prepare_with(
        &fixture.client_root,
        &fixture.deriver_a_root,
        &changed_b,
        &fixture.context,
    );
    assert_ne!(
        baseline.deriver_b().tau_server().expose_bytes(),
        changed_b_prepared.deriver_b().tau_server().expose_bytes()
    );
    assert_deriver_a_equal(&baseline, &changed_b_prepared);

    let changed_context = StableKeyDerivationContext::new([0x43; 32], 1, 2)
        .expect("changed synthetic context is valid");
    let changed_context_prepared = prepare_with(
        &fixture.client_root,
        &fixture.deriver_a_root,
        &fixture.deriver_b_root,
        &changed_context,
    );
    assert_ne!(
        baseline.deriver_a().y_client().expose_bytes(),
        changed_context_prepared
            .deriver_a()
            .y_client()
            .expose_bytes()
    );
    assert_ne!(
        baseline.deriver_b().y_server().expose_bytes(),
        changed_context_prepared
            .deriver_b()
            .y_server()
            .expose_bytes()
    );
}

#[test]
fn borrowed_synthetic_inputs_repeat_deterministically() {
    let fixture = registration_fixture();
    let first = prepare(&fixture);
    let second = prepare(&fixture);

    assert_deriver_a_equal(&first, &second);
    assert_deriver_b_equal(&first, &second);
    assert_activation_equal(&first, &second);
}

#[test]
fn activation_matches_independent_ed25519_arithmetic_and_public_relation() {
    let fixture = registration_fixture();
    let prepared = prepare(&fixture);
    let a = prepared.deriver_a();
    let b = prepared.deriver_b();
    let joined_seed = independent_add_le_256(
        independent_add_le_256(a.y_client().expose_bytes(), a.y_server().expose_bytes()),
        independent_add_le_256(b.y_client().expose_bytes(), b.y_server().expose_bytes()),
    );
    let sha512_digest: [u8; 64] = Sha512::digest(joined_seed).into();
    let mut digest_prefix = [0u8; 32];
    digest_prefix.copy_from_slice(&sha512_digest[..32]);
    let clamped = independent_clamp(digest_prefix);
    let signing_scalar = Scalar::from_bytes_mod_order(clamped);
    let tau = parse_scalar(a.tau_client().expose_bytes())
        + parse_scalar(a.tau_server().expose_bytes())
        + parse_scalar(b.tau_client().expose_bytes())
        + parse_scalar(b.tau_server().expose_bytes());
    let x_client_base = signing_scalar + tau;
    let x_server_base = signing_scalar + tau + tau;
    let x_client = x_client_base * ED25519_BASEPOINT_POINT;
    let x_server = x_server_base * ED25519_BASEPOINT_POINT;
    let public_key = SigningKey::from_bytes(&joined_seed)
        .verifying_key()
        .to_bytes();
    let material = prepared.activation().material();

    assert_eq!(material.sha512_digest().expose_bytes(), sha512_digest);
    assert_eq!(material.clamped_scalar_bytes().expose_bytes(), clamped);
    assert_eq!(
        material.signing_scalar().expose_bytes(),
        signing_scalar.to_bytes()
    );
    assert_eq!(material.tau().expose_bytes(), tau.to_bytes());
    assert_eq!(
        material.x_client_base().expose_bytes(),
        x_client_base.to_bytes()
    );
    assert_eq!(
        material.x_server_base().expose_bytes(),
        x_server_base.to_bytes()
    );
    assert_eq!(
        material.x_client().expose_bytes(),
        x_client.compress().to_bytes()
    );
    assert_eq!(
        material.x_server().expose_bytes(),
        x_server.compress().to_bytes()
    );
    assert_eq!(material.public_key().expose_bytes(), public_key);
    assert_eq!(
        x_client + x_client - x_server,
        signing_scalar * ED25519_BASEPOINT_POINT
    );
}

fn activation_coins(client: Scalar, signing_worker: Scalar) -> HostOnlyActivationOutputCoinsV1 {
    HostOnlyActivationOutputCoinsV1::new(
        HostOnlyClientScalarOutputCoinV1::from_canonical_fixture_bytes(client.to_bytes())
            .expect("canonical client fixture coin"),
        HostOnlySigningWorkerScalarOutputCoinV1::from_canonical_fixture_bytes(
            signing_worker.to_bytes(),
        )
        .expect("canonical SigningWorker fixture coin"),
    )
}

#[test]
fn output_shares_reconstruct_zero_small_and_boundary_coins() {
    let fixture = registration_fixture();
    let expected = prepare(&fixture);
    let expected_client = expected
        .activation()
        .material()
        .x_client_base()
        .expose_bytes();
    let expected_signing_worker = expected
        .activation()
        .material()
        .x_server_base()
        .expose_bytes();

    for (client_coin, signing_worker_coin) in [
        (Scalar::ZERO, Scalar::ZERO),
        (Scalar::ONE, Scalar::from(2u64)),
        (
            Scalar::ZERO - Scalar::ONE,
            Scalar::ZERO - Scalar::from(2u64),
        ),
    ] {
        let success = evaluate_host_only_registration_output_sharing_v1(
            prepare(&fixture),
            HostOnlyRegistrationIdealCoinsV1::from_host_only_fixture(activation_coins(
                client_coin,
                signing_worker_coin,
            )),
        );
        assert_eq!(
            reconstruct_host_only_client_scalar_output_v1(
                success.output_shares().deriver_a().client(),
                success.output_shares().deriver_b().client(),
            )
            .expose_bytes(),
            expected_client
        );
        assert_eq!(
            reconstruct_host_only_signing_worker_scalar_output_v1(
                success.output_shares().deriver_a().signing_worker(),
                success.output_shares().deriver_b().signing_worker(),
            )
            .expose_bytes(),
            expected_signing_worker
        );
        assert_activation_equal(success.prepared(), &expected);
    }
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
            "ed25519-yao-registration-ui-{}-{nonce}",
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
                "[package]\nname = \"registration-reference-ui\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
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
fn source_and_compile_guards_keep_registration_synthetic_seed_free_and_nonproduction() {
    let harness = UiHarness::create();
    let control = harness.check(
        "use ed25519_yao_generator::HostOnlyPreparedRegistrationReferenceV1;\n\
         fn accept(_: &HostOnlyPreparedRegistrationReferenceV1) {}\nfn main() {}",
    );
    assert!(
        control.status.success(),
        "UI control failed:\n{}",
        String::from_utf8_lossy(&control.stderr)
    );
    assert_compile_failure(
        &harness,
        "use ed25519_yao_generator::{HostOnlyRegistrationReferenceInputsV1, StableKeyDerivationContext, SyntheticClientDerivationRootV1, SyntheticDeriverADerivationRootV1, SyntheticDeriverBDerivationRootV1};\n\
         fn invalid<'a>(client: &'a SyntheticClientDerivationRootV1, a: &'a SyntheticDeriverADerivationRootV1, b: &'a SyntheticDeriverBDerivationRootV1, context: &'a StableKeyDerivationContext) {\n\
             let _ = HostOnlyRegistrationReferenceInputsV1::new(client, b, a, context);\n}\nfn main() {}",
        "E0308",
    );
    assert_compile_failure(
        &harness,
        "use ed25519_yao_generator::HostOnlyPreparedRegistrationReferenceV1;\n\
         fn invalid(value: HostOnlyPreparedRegistrationReferenceV1) { let _ = value.activation().seed(); }\nfn main() {}",
        "E0599",
    );

    let source = include_str!("../src/registration_reference.rs");
    for forbidden in [
        "serde",
        "Serialize",
        "Deserialize",
        "rand::",
        "rand_core",
        "getrandom",
        "OsRng",
        "Authorization",
        "Provenance",
        "provenance::",
        "AntiBias",
        "anti_bias",
        "anti-bias",
        "UnregisteredPreStateV1",
        "RegisteredPreStateV1",
        "RegistrationRequestV1",
        "ReferenceLifecycle",
        "Credential",
        "Ciphertext",
        "Package",
        "Receipt",
        "Persistence",
        "lifecycle_domain",
        "worker::",
        "wasm_bindgen",
        "cloudflare",
        "evaluate_registration_v1(",
        "evaluate_export",
        "ExportOracleOutput",
        "HostOnlySeed",
        "SeedBytes",
        "pub const fn seed",
        "pub fn seed",
    ] {
        assert!(
            !source.contains(forbidden),
            "blocked dependency or overstated surface `{forbidden}` entered registration reference"
        );
    }

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
            "public registration type lacks HostOnly prefix: {type_name}"
        );
    }
}
