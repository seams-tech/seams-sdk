use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use signer_core::error::CoreResult;
use signer_core::secp256k1::{
    THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID, THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID,
};

use crate::client::ClientOutputV1;
use crate::server::{FinalizedServerSessionV1, ServerPrepareInputsV1, StagedServerSessionV1};
use crate::shared::context::EcdsaHssContextV1;
use crate::shared::derive::{
    derive_additive_shares_v1, derive_canonical_secret_v1, AdditiveShareMaterialV1,
    CanonicalSecretMaterialV1,
};
use crate::wire::{PrepareEnvelopeV1, RespondRequestV1, RootShareInputsV1, ServerEvalOperationV1};

pub const FIXTURE_FORMAT_VERSION: &str = "phase1_v1";
pub const COMMITTED_FIXTURE_CORPUS_JSON: &str = include_str!("../fixtures/phase1_v1.json");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phase1FixtureV1 {
    pub name: String,
    pub context: EcdsaHssContextV1,
    pub y_client32_le: [u8; 32],
    pub y_relayer32_le: [u8; 32],
    pub canonical: CanonicalSecretMaterialV1,
    pub additive_shares: AdditiveShareMaterialV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenDerivationFixtureV1 {
    pub name: String,
    pub operation: ServerEvalOperationV1,
    pub client_request: RespondRequestV1,
    pub client_output: ClientOutputV1,
    pub finalized_server_session: FinalizedServerSessionV1,
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
    pub near_account_id: String,
    pub key_purpose: String,
    pub key_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureInputsRecord {
    pub y_client32_le_hex: String,
    pub y_relayer32_le_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureOutputsRecord {
    pub context_bytes_hex: String,
    pub d32_hex: String,
    pub x32_hex: String,
    pub public_key33_hex: String,
    pub ethereum_address20_hex: String,
    pub retry_counter: u32,
    pub x_client32_hex: String,
    pub x_relayer32_hex: String,
    pub client_public_key33_hex: String,
    pub relayer_public_key33_hex: String,
    pub mapped_client_share32_hex: String,
    pub mapped_relayer_share32_hex: String,
    pub threshold_public_key33_hex: String,
    pub threshold_ethereum_address20_hex: String,
    pub client_participant_id: u32,
    pub relayer_participant_id: u32,
}

pub fn deterministic_fixture_corpus() -> CoreResult<Vec<Phase1FixtureV1>> {
    [
        (
            "wraparound-zero-d",
            EcdsaHssContextV1::new("wraparound.test.near", "evm-signing", "v1-wrap"),
            [0xff; 32],
            one_le_u256(),
        ),
        (
            "patterned-seed",
            EcdsaHssContextV1::new("patterned.test.near", "evm-signing", "v1-pattern"),
            ascending_bytes(),
            descending_bytes(),
        ),
        (
            "derived-alpha",
            EcdsaHssContextV1::new("alpha.test.near", "evm-export", "v1-alpha"),
            derive_bytes32("ecdsa-hss/fixture/alpha/y-client"),
            derive_bytes32("ecdsa-hss/fixture/alpha/y-relayer"),
        ),
        (
            "derived-beta",
            EcdsaHssContextV1::new("beta.test.near", "evm-signing", "v2-beta"),
            derive_bytes32("ecdsa-hss/fixture/beta/y-client"),
            derive_bytes32("ecdsa-hss/fixture/beta/y-relayer"),
        ),
    ]
    .into_iter()
    .map(|(name, context, y_client32_le, y_relayer32_le)| {
        let canonical = derive_canonical_secret_v1(
            &RootShareInputsV1::new(y_client32_le, y_relayer32_le),
            &context,
        )?;
        let additive_shares = derive_additive_shares_v1(&canonical.x32, &context)?;
        Ok(Phase1FixtureV1 {
            name: name.to_string(),
            context,
            y_client32_le,
            y_relayer32_le,
            canonical,
            additive_shares,
        })
    })
    .collect()
}

pub fn deterministic_hidden_derivation_fixture_corpus() -> CoreResult<Vec<HiddenDerivationFixtureV1>>
{
    let phase1 = deterministic_fixture_corpus()?;
    let mut fixtures = Vec::with_capacity(phase1.len() * 2);

    for fixture in phase1 {
        let request = RespondRequestV1 {
            y_client32_le: fixture.y_client32_le,
        };

        let staged_non_export = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
            prepare: PrepareEnvelopeV1 {
                operation: ServerEvalOperationV1::NonExportSign,
                context: fixture.context.clone(),
            },
            y_relayer32_le: fixture.y_relayer32_le,
        })?;
        let non_export_response = staged_non_export.respond(&request)?;
        fixtures.push(HiddenDerivationFixtureV1 {
            name: format!("{}:non-export", fixture.name),
            operation: ServerEvalOperationV1::NonExportSign,
            client_request: request.clone(),
            client_output: non_export_response.client_output.clone(),
            finalized_server_session: non_export_response.finalized_server_session.clone(),
        });

        let staged_export = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
            prepare: PrepareEnvelopeV1 {
                operation: ServerEvalOperationV1::ExplicitKeyExport,
                context: fixture.context.clone(),
            },
            y_relayer32_le: fixture.y_relayer32_le,
        })?;
        let export_response = staged_export.respond(&request)?;
        fixtures.push(HiddenDerivationFixtureV1 {
            name: format!("{}:explicit-export", fixture.name),
            operation: ServerEvalOperationV1::ExplicitKeyExport,
            client_request: request.clone(),
            client_output: export_response.client_output.clone(),
            finalized_server_session: export_response.finalized_server_session.clone(),
        });
    }

    Ok(fixtures)
}

pub fn serialized_fixture_corpus() -> CoreResult<FixtureCorpusFile> {
    Ok(FixtureCorpusFile {
        format_version: FIXTURE_FORMAT_VERSION.to_string(),
        fixtures: deterministic_fixture_corpus()?
            .iter()
            .map(FixtureRecord::from_fixture)
            .collect(),
    })
}

pub fn committed_fixture_corpus_file() -> CoreResult<FixtureCorpusFile> {
    serde_json::from_str(COMMITTED_FIXTURE_CORPUS_JSON).map_err(|err| {
        signer_core::error::SignerCoreError::decode_error(format!(
            "failed to parse committed fixture corpus: {err}"
        ))
    })
}

pub fn committed_fixture_corpus() -> CoreResult<Vec<Phase1FixtureV1>> {
    committed_fixture_corpus_file()?.to_internal()
}

impl FixtureCorpusFile {
    pub fn to_internal(&self) -> CoreResult<Vec<Phase1FixtureV1>> {
        if self.format_version != FIXTURE_FORMAT_VERSION {
            return Err(signer_core::error::SignerCoreError::decode_error(format!(
                "unexpected fixture format version: {}",
                self.format_version
            )));
        }
        self.fixtures
            .iter()
            .map(FixtureRecord::to_fixture)
            .collect()
    }
}

impl FixtureRecord {
    fn from_fixture(fixture: &Phase1FixtureV1) -> Self {
        Self {
            name: fixture.name.clone(),
            context: ContextRecord {
                near_account_id: fixture.context.near_account_id.clone(),
                key_purpose: fixture.context.key_purpose.clone(),
                key_version: fixture.context.key_version.clone(),
            },
            inputs: FixtureInputsRecord {
                y_client32_le_hex: hex::encode(fixture.y_client32_le),
                y_relayer32_le_hex: hex::encode(fixture.y_relayer32_le),
            },
            outputs: FixtureOutputsRecord {
                context_bytes_hex: hex::encode(&fixture.canonical.context_bytes),
                d32_hex: hex::encode(fixture.canonical.d32),
                x32_hex: hex::encode(fixture.canonical.x32),
                public_key33_hex: hex::encode(fixture.canonical.public_key33),
                ethereum_address20_hex: hex::encode(fixture.canonical.ethereum_address20),
                retry_counter: fixture.additive_shares.retry_counter,
                x_client32_hex: hex::encode(fixture.additive_shares.x_client32),
                x_relayer32_hex: hex::encode(fixture.additive_shares.x_relayer32),
                client_public_key33_hex: hex::encode(fixture.additive_shares.client_public_key33),
                relayer_public_key33_hex: hex::encode(fixture.additive_shares.relayer_public_key33),
                mapped_client_share32_hex: hex::encode(
                    fixture.additive_shares.mapped_client_share32,
                ),
                mapped_relayer_share32_hex: hex::encode(
                    fixture.additive_shares.mapped_relayer_share32,
                ),
                threshold_public_key33_hex: hex::encode(
                    fixture.additive_shares.threshold_public_key33,
                ),
                threshold_ethereum_address20_hex: hex::encode(
                    fixture.additive_shares.threshold_ethereum_address20,
                ),
                client_participant_id: THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID,
                relayer_participant_id: THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID,
            },
        }
    }

    fn to_fixture(&self) -> CoreResult<Phase1FixtureV1> {
        let context = EcdsaHssContextV1::new(
            self.context.near_account_id.clone(),
            self.context.key_purpose.clone(),
            self.context.key_version.clone(),
        );
        let fixture = Phase1FixtureV1 {
            name: self.name.clone(),
            context: context.clone(),
            y_client32_le: decode_hex_32("y_client32_le_hex", &self.inputs.y_client32_le_hex)?,
            y_relayer32_le: decode_hex_32("y_relayer32_le_hex", &self.inputs.y_relayer32_le_hex)?,
            canonical: CanonicalSecretMaterialV1 {
                context_bytes: decode_hex_vec(
                    "context_bytes_hex",
                    &self.outputs.context_bytes_hex,
                )?,
                d32: decode_hex_32("d32_hex", &self.outputs.d32_hex)?,
                x32: decode_hex_32("x32_hex", &self.outputs.x32_hex)?,
                public_key33: decode_hex_33("public_key33_hex", &self.outputs.public_key33_hex)?,
                ethereum_address20: decode_hex_20(
                    "ethereum_address20_hex",
                    &self.outputs.ethereum_address20_hex,
                )?,
            },
            additive_shares: AdditiveShareMaterialV1 {
                retry_counter: self.outputs.retry_counter,
                x_client32: decode_hex_32("x_client32_hex", &self.outputs.x_client32_hex)?,
                x_relayer32: decode_hex_32("x_relayer32_hex", &self.outputs.x_relayer32_hex)?,
                client_public_key33: decode_hex_33(
                    "client_public_key33_hex",
                    &self.outputs.client_public_key33_hex,
                )?,
                relayer_public_key33: decode_hex_33(
                    "relayer_public_key33_hex",
                    &self.outputs.relayer_public_key33_hex,
                )?,
                mapped_client_share32: decode_hex_32(
                    "mapped_client_share32_hex",
                    &self.outputs.mapped_client_share32_hex,
                )?,
                mapped_relayer_share32: decode_hex_32(
                    "mapped_relayer_share32_hex",
                    &self.outputs.mapped_relayer_share32_hex,
                )?,
                threshold_public_key33: decode_hex_33(
                    "threshold_public_key33_hex",
                    &self.outputs.threshold_public_key33_hex,
                )?,
                threshold_ethereum_address20: decode_hex_20(
                    "threshold_ethereum_address20_hex",
                    &self.outputs.threshold_ethereum_address20_hex,
                )?,
            },
        };

        if self.outputs.client_participant_id != THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID {
            return Err(signer_core::error::SignerCoreError::decode_error(
                "unexpected client_participant_id in committed fixture corpus",
            ));
        }
        if self.outputs.relayer_participant_id != THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID {
            return Err(signer_core::error::SignerCoreError::decode_error(
                "unexpected relayer_participant_id in committed fixture corpus",
            ));
        }

        let regenerated = derive_canonical_secret_v1(
            &RootShareInputsV1::new(fixture.y_client32_le, fixture.y_relayer32_le),
            &context,
        )?;
        let regenerated_shares = derive_additive_shares_v1(&regenerated.x32, &context)?;

        if fixture.canonical != regenerated {
            return Err(signer_core::error::SignerCoreError::decode_error(format!(
                "committed canonical outputs drift for fixture {}",
                self.name
            )));
        }
        if fixture.additive_shares != regenerated_shares {
            return Err(signer_core::error::SignerCoreError::decode_error(format!(
                "committed additive-share outputs drift for fixture {}",
                self.name
            )));
        }

        Ok(fixture)
    }
}

fn derive_bytes32(label: &str) -> [u8; 32] {
    let digest = Sha512::digest(label.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

fn one_le_u256() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = 1;
    out
}

fn ascending_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::try_from(index).expect("index fits in u8");
    }
    out
}

fn descending_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::try_from(31usize.saturating_sub(index)).expect("index fits in u8");
    }
    out
}

fn decode_hex_vec(field_name: &str, hex_value: &str) -> CoreResult<Vec<u8>> {
    hex::decode(hex_value).map_err(|err| {
        signer_core::error::SignerCoreError::decode_error(format!(
            "failed to decode {field_name}: {err}"
        ))
    })
}

fn decode_hex_20(field_name: &str, hex_value: &str) -> CoreResult<[u8; 20]> {
    let bytes = decode_hex_vec(field_name, hex_value)?;
    if bytes.len() != 20 {
        return Err(signer_core::error::SignerCoreError::decode_error(format!(
            "{field_name} must decode to 20 bytes (got {})",
            bytes.len()
        )));
    }
    bytes.try_into().map_err(|_| {
        signer_core::error::SignerCoreError::decode_error(format!(
            "{field_name} must decode to exactly 20 bytes"
        ))
    })
}

fn decode_hex_32(field_name: &str, hex_value: &str) -> CoreResult<[u8; 32]> {
    let bytes = decode_hex_vec(field_name, hex_value)?;
    if bytes.len() != 32 {
        return Err(signer_core::error::SignerCoreError::decode_error(format!(
            "{field_name} must decode to 32 bytes (got {})",
            bytes.len()
        )));
    }
    bytes.try_into().map_err(|_| {
        signer_core::error::SignerCoreError::decode_error(format!(
            "{field_name} must decode to exactly 32 bytes"
        ))
    })
}

fn decode_hex_33(field_name: &str, hex_value: &str) -> CoreResult<[u8; 33]> {
    let bytes = decode_hex_vec(field_name, hex_value)?;
    if bytes.len() != 33 {
        return Err(signer_core::error::SignerCoreError::decode_error(format!(
            "{field_name} must decode to 33 bytes (got {})",
            bytes.len()
        )));
    }
    bytes.try_into().map_err(|_| {
        signer_core::error::SignerCoreError::decode_error(format!(
            "{field_name} must decode to exactly 33 bytes"
        ))
    })
}
