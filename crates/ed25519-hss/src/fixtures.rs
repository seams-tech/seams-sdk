use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::shared::{
    eval_f_expand, CanonicalContext, FExpandInput, FExpandOutput, ProtoError, ProtoResult,
};

pub const FIXTURE_FORMAT_VERSION: &str = "f_expand_v1";
pub const COMMITTED_FIXTURE_CORPUS_JSON: &str = include_str!("../fixtures/f_expand_v1.json");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FExpandFixture {
    pub name: String,
    pub input: FExpandInput,
    pub output: FExpandOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureCorpusFile {
    pub format_version: String,
    pub fixtures: Vec<FixtureRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureRecord {
    pub name: String,
    pub context: ContextRecord,
    pub inputs: FixtureInputsRecord,
    pub outputs: FixtureOutputsRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextRecord {
    pub application_binding_digest_hex: String,
    pub participant_ids: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureInputsRecord {
    pub y_client_hex: String,
    pub y_server_hex: String,
    pub tau_client_hex: String,
    pub tau_server_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureOutputsRecord {
    pub context_binding_sha256_hex: String,
    pub m_hex: String,
    pub d_hex: String,
    pub h_hex: String,
    pub a_bytes_hex: String,
    pub a_hex: String,
    pub tau_hex: String,
    pub x_client_base_hex: String,
    pub x_server_base_hex: String,
    pub public_key_hex: String,
}

pub fn deterministic_fixture_corpus() -> ProtoResult<Vec<FExpandFixture>> {
    let cases = vec![
        (
            "wraparound-seed",
            CanonicalContext {
                application_binding_digest: derive_bytes32("wraparound-seed/application-binding"),
                participant_ids: vec![2, 1, 2],
            },
            [0xff; 32],
            one_le_u256(),
            derive_scalar_bytes("wraparound-seed/tau-client"),
            derive_scalar_bytes("wraparound-seed/tau-server"),
        ),
        (
            "patterned-le-seed",
            CanonicalContext {
                application_binding_digest: derive_bytes32("patterned-le-seed/application-binding"),
                participant_ids: vec![1, 2],
            },
            ascending_bytes(),
            descending_bytes(),
            derive_scalar_bytes("patterned-le-seed/tau-client"),
            derive_scalar_bytes("patterned-le-seed/tau-server"),
        ),
        (
            "derived-alpha",
            CanonicalContext {
                application_binding_digest: derive_bytes32("derived-alpha/application-binding"),
                participant_ids: vec![1, 2],
            },
            derive_bytes32("derived-alpha/y-client"),
            derive_bytes32("derived-alpha/y-server"),
            derive_scalar_bytes("derived-alpha/tau-client"),
            derive_scalar_bytes("derived-alpha/tau-server"),
        ),
        (
            "derived-beta",
            CanonicalContext {
                application_binding_digest: derive_bytes32("derived-beta/application-binding"),
                participant_ids: vec![9, 4, 9, 4],
            },
            derive_bytes32("derived-beta/y-client"),
            derive_bytes32("derived-beta/y-server"),
            derive_scalar_bytes("derived-beta/tau-client"),
            derive_scalar_bytes("derived-beta/tau-server"),
        ),
        (
            "derived-gamma",
            CanonicalContext {
                application_binding_digest: derive_bytes32("derived-gamma/application-binding"),
                participant_ids: vec![11, 7],
            },
            derive_bytes32("derived-gamma/y-client"),
            derive_bytes32("derived-gamma/y-server"),
            derive_scalar_bytes("derived-gamma/tau-client"),
            derive_scalar_bytes("derived-gamma/tau-server"),
        ),
    ];

    cases
        .into_iter()
        .map(
            |(name, context, y_client, y_server, tau_client, tau_server)| {
                let input = FExpandInput {
                    context,
                    y_client,
                    y_server,
                    tau_client,
                    tau_server,
                };
                let output = eval_f_expand(&input)?;
                Ok(FExpandFixture {
                    name: name.to_string(),
                    input,
                    output,
                })
            },
        )
        .collect()
}

pub fn serialized_fixture_corpus() -> ProtoResult<FixtureCorpusFile> {
    Ok(FixtureCorpusFile {
        format_version: FIXTURE_FORMAT_VERSION.to_string(),
        fixtures: deterministic_fixture_corpus()?
            .iter()
            .map(FixtureRecord::from_fixture)
            .collect(),
    })
}

pub fn committed_fixture_corpus_file() -> ProtoResult<FixtureCorpusFile> {
    serde_json::from_str(COMMITTED_FIXTURE_CORPUS_JSON).map_err(|err| {
        ProtoError::Decode(format!("failed to parse committed fixture corpus: {err}"))
    })
}

pub fn committed_fixture_corpus() -> ProtoResult<Vec<FExpandFixture>> {
    committed_fixture_corpus_file()?.to_internal()
}

impl FixtureCorpusFile {
    pub fn to_internal(&self) -> ProtoResult<Vec<FExpandFixture>> {
        if self.format_version != FIXTURE_FORMAT_VERSION {
            return Err(ProtoError::Decode(format!(
                "unexpected fixture format version: {}",
                self.format_version
            )));
        }
        self.fixtures
            .iter()
            .map(FixtureRecord::to_fixture)
            .collect::<ProtoResult<Vec<_>>>()
    }
}

impl FixtureRecord {
    fn from_fixture(fixture: &FExpandFixture) -> Self {
        Self {
            name: fixture.name.clone(),
            context: ContextRecord {
                application_binding_digest_hex: hex::encode(
                    fixture.input.context.application_binding_digest,
                ),
                participant_ids: fixture.input.context.participant_ids.clone(),
            },
            inputs: FixtureInputsRecord {
                y_client_hex: hex::encode(fixture.input.y_client),
                y_server_hex: hex::encode(fixture.input.y_server),
                tau_client_hex: hex::encode(fixture.input.tau_client),
                tau_server_hex: hex::encode(fixture.input.tau_server),
            },
            outputs: FixtureOutputsRecord {
                context_binding_sha256_hex: hex::encode(fixture.output.context_binding),
                m_hex: hex::encode(fixture.output.m),
                d_hex: hex::encode(fixture.output.d),
                h_hex: hex::encode(fixture.output.h),
                a_bytes_hex: hex::encode(fixture.output.a_bytes),
                a_hex: hex::encode(fixture.output.a),
                tau_hex: hex::encode(fixture.output.tau),
                x_client_base_hex: hex::encode(fixture.output.x_client_base),
                x_server_base_hex: hex::encode(fixture.output.x_server_base),
                public_key_hex: hex::encode(fixture.output.public_key),
            },
        }
    }

    fn to_fixture(&self) -> ProtoResult<FExpandFixture> {
        Ok(FExpandFixture {
            name: self.name.clone(),
            input: FExpandInput {
                context: CanonicalContext {
                    application_binding_digest: decode_hex_32(
                        "application_binding_digest_hex",
                        &self.context.application_binding_digest_hex,
                    )?,
                    participant_ids: self.context.participant_ids.clone(),
                },
                y_client: decode_hex_32("y_client_hex", &self.inputs.y_client_hex)?,
                y_server: decode_hex_32("y_server_hex", &self.inputs.y_server_hex)?,
                tau_client: decode_hex_32("tau_client_hex", &self.inputs.tau_client_hex)?,
                tau_server: decode_hex_32("tau_server_hex", &self.inputs.tau_server_hex)?,
            },
            output: FExpandOutput {
                context_binding: decode_hex_32(
                    "context_binding_sha256_hex",
                    &self.outputs.context_binding_sha256_hex,
                )?,
                m: decode_hex_32("m_hex", &self.outputs.m_hex)?,
                d: decode_hex_32("d_hex", &self.outputs.d_hex)?,
                h: decode_hex_64("h_hex", &self.outputs.h_hex)?,
                a_bytes: decode_hex_32("a_bytes_hex", &self.outputs.a_bytes_hex)?,
                a: decode_hex_32("a_hex", &self.outputs.a_hex)?,
                tau: decode_hex_32("tau_hex", &self.outputs.tau_hex)?,
                x_client_base: decode_hex_32("x_client_base_hex", &self.outputs.x_client_base_hex)?,
                x_server_base: decode_hex_32("x_server_base_hex", &self.outputs.x_server_base_hex)?,
                public_key: decode_hex_32("public_key_hex", &self.outputs.public_key_hex)?,
            },
        })
    }
}

fn decode_hex_32(label: &str, value: &str) -> ProtoResult<[u8; 32]> {
    let bytes =
        hex::decode(value).map_err(|err| ProtoError::Decode(format!("invalid {label}: {err}")))?;
    bytes
        .try_into()
        .map_err(|_| ProtoError::Decode(format!("{label} must decode to 32 bytes")))
}

fn decode_hex_64(label: &str, value: &str) -> ProtoResult<[u8; 64]> {
    let bytes =
        hex::decode(value).map_err(|err| ProtoError::Decode(format!("invalid {label}: {err}")))?;
    bytes
        .try_into()
        .map_err(|_| ProtoError::Decode(format!("{label} must decode to 64 bytes")))
}

fn derive_bytes32(label: &str) -> [u8; 32] {
    let digest = Sha512::digest(format!("succinct-garbling-proto/{label}/bytes32"));
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

fn derive_scalar_bytes(label: &str) -> [u8; 32] {
    let digest = Sha512::digest(format!("succinct-garbling-proto/{label}/scalar"));
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    let scalar = Scalar::from_bytes_mod_order_wide(&wide);
    if scalar == Scalar::ZERO {
        return Scalar::ONE.to_bytes();
    }
    scalar.to_bytes()
}

fn one_le_u256() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = 1;
    out
}

fn ascending_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (idx, byte) in out.iter_mut().enumerate() {
        *byte = idx as u8;
    }
    out
}

fn descending_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (idx, byte) in out.iter_mut().enumerate() {
        *byte = (31 - idx) as u8;
    }
    out
}
