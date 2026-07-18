use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use router_ab_ecdsa_client_protocol::{
    EcdsaClientProtocolError, EcdsaCommitmentAuthorityDeliveryV1, EcdsaCommitmentAuthorityV1,
    EcdsaCommitmentPolicyManifestDeliveryV1, EcdsaCommitmentPolicyManifestV1,
    EcdsaCommitmentRecordDeliveryV1, EcdsaCommitmentRecordsDeliveryV1,
    EcdsaCommitmentRegistryDeliveryV1, EcdsaCommitmentStatementV1, EcdsaDeriverRoleV1,
    EcdsaSignedCommitmentPolicyDeliveryV1, EcdsaSignedCommitmentPolicyV1,
    EcdsaSignedCommitmentRecordV1,
};
use serde::{Deserialize, Serialize};
use std::{env, io};
use threshold_prf::{SigningRootShareCommitment, SigningRootShareWire};
use zeroize::Zeroize;

const ROLE_ROOT_SHARE_ENV: &str = "ROUTER_AB_ECDSA_ROLE_ROOT_SHARE_WIRE_HEX";
const RELEASE_KEY_ENV: &str = "ROUTER_AB_ECDSA_RELEASE_AUTHORITY_PRIVATE_KEY_HEX";
const ROLE_AUTHORITY_KEY_ENV: &str = "ROUTER_AB_ECDSA_ROLE_COMMITMENT_AUTHORITY_PRIVATE_KEY_HEX";

fn client_protocol_error(error: EcdsaClientProtocolError) -> io::Error {
    io::Error::other(format!("{error:?}"))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match env::args().nth(1).as_deref() {
        Some("signed-role-record") => emit_signed_role_record(env::args().nth(2).as_deref())?,
        Some("registry") => emit_registry()?,
        _ => return Err(usage().into()),
    }
    Ok(())
}

fn emit_signed_role_record(role: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let role = ProvisionRole::parse(role.ok_or_else(usage)?)?;
    let input: UnsignedCommitmentRecordMetadata = serde_json::from_reader(io::stdin())?;
    input.validate()?;
    let mut share_wire_bytes = required_secret_hex::<34>(ROLE_ROOT_SHARE_ENV)?;
    let mut authority_key_bytes = required_secret_hex::<32>(ROLE_AUTHORITY_KEY_ENV)?;
    let share_wire = SigningRootShareWire::decode(share_wire_bytes)?;
    share_wire_bytes.zeroize();
    let share = share_wire.to_share()?;
    let commitment = SigningRootShareCommitment::from_share(&share).to_bytes();
    let authority_key = SigningKey::from_bytes(&authority_key_bytes);
    authority_key_bytes.zeroize();
    let authority = commitment_authority(role.protocol_role(), &input, &authority_key);
    let record = signed_record(role.protocol_role(), input, commitment, &authority_key)?;
    let output = SignedRoleRecordOutput {
        role,
        authority: authority_delivery(&authority),
        record: record_delivery(&record),
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn emit_registry() -> Result<(), Box<dyn std::error::Error>> {
    let input: RegistryProvisionInput = serde_json::from_reader(io::stdin())?;
    input.validate()?;
    let RegistryProvisionInput {
        release_epoch,
        minimum_root_version,
        minimum_authority_key_epoch,
        revoked_authority_key_epochs,
        revoked_record_digests_hex,
        deriver_a,
        deriver_b,
    } = input;
    let mut release_key_bytes = required_secret_hex::<32>(RELEASE_KEY_ENV)?;
    let release_key = SigningKey::from_bytes(&release_key_bytes);
    release_key_bytes.zeroize();
    let deriver_a = deriver_a.into_verified(ProvisionRole::DeriverA)?;
    let deriver_b = deriver_b.into_verified(ProvisionRole::DeriverB)?;
    let revoked_record_digests = decode_digest_list(revoked_record_digests_hex)?;
    if deriver_a.record.statement.root_id != deriver_b.record.statement.root_id
        || deriver_a.record.statement.root_version != deriver_b.record.statement.root_version
        || deriver_a.record.statement.root_share_epoch
            != deriver_b.record.statement.root_share_epoch
        || deriver_a.record.statement.root_version < minimum_root_version
        || deriver_a.authority.authority_key_epoch < minimum_authority_key_epoch
        || deriver_b.authority.authority_key_epoch < minimum_authority_key_epoch
        || revoked_authority_key_epochs.contains(&deriver_a.authority.authority_key_epoch)
        || revoked_authority_key_epochs.contains(&deriver_b.authority.authority_key_epoch)
        || revoked_record_digests.contains(&deriver_a.record.signed_digest)
        || revoked_record_digests.contains(&deriver_b.record.signed_digest)
    {
        return Err("signed Deriver records do not satisfy the requested registry policy".into());
    }

    let manifest = EcdsaCommitmentPolicyManifestV1 {
        release_epoch,
        minimum_root_version,
        minimum_authority_key_epoch,
        revoked_authority_key_epochs,
        revoked_record_digests,
        signer_a_authority: deriver_a.authority,
        signer_b_authority: deriver_b.authority,
    };
    let manifest_digest = manifest.digest().map_err(client_protocol_error)?;
    let policy = EcdsaSignedCommitmentPolicyV1 {
        release_authority_signature: release_key
            .sign(&manifest.signing_bytes().map_err(client_protocol_error)?)
            .to_bytes(),
        manifest,
        manifest_digest,
    };
    let registry = registry_delivery(&policy, &deriver_a.record, &deriver_b.record);
    let output = RegistryProvisionOutput {
        router_signing_worker_registry_json: serde_json::to_string(&registry)?,
        commitment_registry: registry,
        build_pins: CommitmentPolicyBuildPins {
            release_authority_public_key_hex: hex::encode(release_key.verifying_key().to_bytes()),
            policy_digest_hex: hex::encode(manifest_digest),
            minimum_release_epoch: policy.manifest.release_epoch,
        },
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProvisionRole {
    DeriverA,
    DeriverB,
}

impl ProvisionRole {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "deriver-a" => Ok(Self::DeriverA),
            "deriver-b" => Ok(Self::DeriverB),
            _ => Err("role must be deriver-a or deriver-b".to_owned()),
        }
    }

    fn protocol_role(self) -> EcdsaDeriverRoleV1 {
        match self {
            Self::DeriverA => EcdsaDeriverRoleV1::A,
            Self::DeriverB => EcdsaDeriverRoleV1::B,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedRoleRecordOutput {
    role: ProvisionRole,
    authority: EcdsaCommitmentAuthorityDeliveryV1,
    record: EcdsaCommitmentRecordDeliveryV1,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryProvisionInput {
    release_epoch: u64,
    minimum_root_version: u64,
    minimum_authority_key_epoch: u64,
    revoked_authority_key_epochs: Vec<u64>,
    revoked_record_digests_hex: Vec<String>,
    deriver_a: SignedRoleRecordInput,
    deriver_b: SignedRoleRecordInput,
}

impl RegistryProvisionInput {
    fn validate(&self) -> Result<(), String> {
        if self.release_epoch == 0
            || self.minimum_root_version == 0
            || self.minimum_authority_key_epoch == 0
        {
            return Err("policy epochs and versions must be positive".to_owned());
        }
        self.deriver_a.validate(ProvisionRole::DeriverA)?;
        self.deriver_b.validate(ProvisionRole::DeriverB)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UnsignedCommitmentRecordMetadata {
    root_id: String,
    root_version: u64,
    root_share_epoch: String,
    operator_identity: String,
    authority_key_epoch: u64,
    authority_valid_from_ms: u64,
    authority_valid_until_ms: u64,
    record_valid_from_ms: u64,
    record_valid_until_ms: u64,
}

impl UnsignedCommitmentRecordMetadata {
    fn validate(&self) -> Result<(), String> {
        if self.root_id.is_empty()
            || self.root_version == 0
            || self.root_share_epoch.is_empty()
            || self.operator_identity.is_empty()
            || self.authority_key_epoch == 0
            || self.authority_valid_from_ms >= self.authority_valid_until_ms
            || self.record_valid_from_ms >= self.record_valid_until_ms
        {
            return Err("commitment record metadata is invalid".to_owned());
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedRoleRecordInput {
    role: ProvisionRole,
    authority: EcdsaCommitmentAuthorityDeliveryV1,
    record: EcdsaCommitmentRecordDeliveryV1,
}

impl SignedRoleRecordInput {
    fn validate(&self, expected_role: ProvisionRole) -> Result<(), String> {
        if self.role.protocol_role() != expected_role.protocol_role() {
            return Err("signed role record is assigned to the wrong Deriver".to_owned());
        }
        Ok(())
    }

    fn into_verified(
        self,
        expected_role: ProvisionRole,
    ) -> Result<VerifiedRoleRecord, Box<dyn std::error::Error>> {
        self.validate(expected_role)?;
        let authority = internal_authority(expected_role.protocol_role(), self.authority)?;
        let record = internal_record(expected_role.protocol_role(), self.record)?;
        if record.statement.operator_identity != authority.operator_identity
            || record.statement.authority_key_epoch != authority.authority_key_epoch
            || record.signed_digest != record.statement.digest().map_err(client_protocol_error)?
        {
            return Err("signed role record does not match its authority metadata".into());
        }
        let verifying_key = VerifyingKey::from_bytes(&authority.verifying_key)?;
        verifying_key.verify(
            &record
                .statement
                .signing_bytes()
                .map_err(client_protocol_error)?,
            &Signature::from_bytes(&record.signature),
        )?;
        Ok(VerifiedRoleRecord { authority, record })
    }
}

struct VerifiedRoleRecord {
    authority: EcdsaCommitmentAuthorityV1,
    record: EcdsaSignedCommitmentRecordV1,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistryProvisionOutput {
    router_signing_worker_registry_json: String,
    commitment_registry: EcdsaCommitmentRegistryDeliveryV1,
    build_pins: CommitmentPolicyBuildPins,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CommitmentPolicyBuildPins {
    release_authority_public_key_hex: String,
    policy_digest_hex: String,
    minimum_release_epoch: u64,
}

fn commitment_authority(
    role: EcdsaDeriverRoleV1,
    input: &UnsignedCommitmentRecordMetadata,
    key: &SigningKey,
) -> EcdsaCommitmentAuthorityV1 {
    EcdsaCommitmentAuthorityV1 {
        role,
        operator_identity: input.operator_identity.clone(),
        authority_key_epoch: input.authority_key_epoch,
        valid_from_ms: input.authority_valid_from_ms,
        valid_until_ms: input.authority_valid_until_ms,
        verifying_key: key.verifying_key().to_bytes(),
    }
}

fn signed_record(
    role: EcdsaDeriverRoleV1,
    input: UnsignedCommitmentRecordMetadata,
    commitment_wire: [u8; 34],
    key: &SigningKey,
) -> Result<EcdsaSignedCommitmentRecordV1, Box<dyn std::error::Error>> {
    let statement = EcdsaCommitmentStatementV1 {
        role,
        share_id: match role {
            EcdsaDeriverRoleV1::A => 1,
            EcdsaDeriverRoleV1::B => 2,
        },
        root_id: input.root_id,
        root_version: input.root_version,
        root_share_epoch: input.root_share_epoch,
        commitment_wire,
        operator_identity: input.operator_identity,
        authority_key_epoch: input.authority_key_epoch,
        valid_from_ms: input.record_valid_from_ms,
        valid_until_ms: input.record_valid_until_ms,
    };
    Ok(EcdsaSignedCommitmentRecordV1 {
        signed_digest: statement.digest().map_err(client_protocol_error)?,
        signature: key
            .sign(&statement.signing_bytes().map_err(client_protocol_error)?)
            .to_bytes(),
        statement,
    })
}

fn internal_authority(
    role: EcdsaDeriverRoleV1,
    delivery: EcdsaCommitmentAuthorityDeliveryV1,
) -> Result<EcdsaCommitmentAuthorityV1, String> {
    let authority = EcdsaCommitmentAuthorityV1 {
        role,
        operator_identity: delivery.operator_identity,
        authority_key_epoch: delivery.authority_key_epoch,
        valid_from_ms: delivery.valid_from_ms,
        valid_until_ms: delivery.valid_until_ms,
        verifying_key: decode_hex::<32>(&delivery.verifying_key_hex)?,
    };
    if authority.operator_identity.is_empty()
        || authority.authority_key_epoch == 0
        || authority.valid_from_ms >= authority.valid_until_ms
    {
        return Err("commitment authority metadata is invalid".to_owned());
    }
    Ok(authority)
}

fn internal_record(
    role: EcdsaDeriverRoleV1,
    delivery: EcdsaCommitmentRecordDeliveryV1,
) -> Result<EcdsaSignedCommitmentRecordV1, String> {
    let commitment_wire = decode_hex::<34>(&delivery.commitment_hex)?;
    SigningRootShareCommitment::from_bytes(commitment_wire)
        .map_err(|error| format!("commitment is invalid: {error:?}"))?;
    let share_id = match role {
        EcdsaDeriverRoleV1::A => 1,
        EcdsaDeriverRoleV1::B => 2,
    };
    if u16::from_be_bytes([commitment_wire[0], commitment_wire[1]]) != share_id {
        return Err("commitment share id does not match Deriver role".to_owned());
    }
    Ok(EcdsaSignedCommitmentRecordV1 {
        statement: EcdsaCommitmentStatementV1 {
            role,
            share_id,
            root_id: delivery.root_id,
            root_version: delivery.root_version,
            root_share_epoch: delivery.root_share_epoch,
            commitment_wire,
            operator_identity: delivery.operator_identity,
            authority_key_epoch: delivery.authority_key_epoch,
            valid_from_ms: delivery.record_valid_from_ms,
            valid_until_ms: delivery.record_valid_until_ms,
        },
        signed_digest: decode_hex::<32>(&delivery.signed_digest_hex)?,
        signature: decode_hex::<64>(&delivery.signature_hex)?,
    })
}

fn registry_delivery(
    policy: &EcdsaSignedCommitmentPolicyV1,
    signer_a: &EcdsaSignedCommitmentRecordV1,
    signer_b: &EcdsaSignedCommitmentRecordV1,
) -> EcdsaCommitmentRegistryDeliveryV1 {
    EcdsaCommitmentRegistryDeliveryV1 {
        policy: EcdsaSignedCommitmentPolicyDeliveryV1 {
            manifest: EcdsaCommitmentPolicyManifestDeliveryV1 {
                release_epoch: policy.manifest.release_epoch,
                minimum_root_version: policy.manifest.minimum_root_version,
                minimum_authority_key_epoch: policy.manifest.minimum_authority_key_epoch,
                revoked_authority_key_epochs: policy.manifest.revoked_authority_key_epochs.clone(),
                revoked_record_digests_hex: policy
                    .manifest
                    .revoked_record_digests
                    .iter()
                    .map(hex::encode)
                    .collect(),
                signer_a_authority: authority_delivery(&policy.manifest.signer_a_authority),
                signer_b_authority: authority_delivery(&policy.manifest.signer_b_authority),
            },
            manifest_digest_hex: hex::encode(policy.manifest_digest),
            release_authority_signature_hex: hex::encode(policy.release_authority_signature),
        },
        records: EcdsaCommitmentRecordsDeliveryV1 {
            signer_a: record_delivery(signer_a),
            signer_b: record_delivery(signer_b),
        },
    }
}

fn authority_delivery(
    authority: &EcdsaCommitmentAuthorityV1,
) -> EcdsaCommitmentAuthorityDeliveryV1 {
    EcdsaCommitmentAuthorityDeliveryV1 {
        operator_identity: authority.operator_identity.clone(),
        authority_key_epoch: authority.authority_key_epoch,
        valid_from_ms: authority.valid_from_ms,
        valid_until_ms: authority.valid_until_ms,
        verifying_key_hex: hex::encode(authority.verifying_key),
    }
}

fn record_delivery(record: &EcdsaSignedCommitmentRecordV1) -> EcdsaCommitmentRecordDeliveryV1 {
    EcdsaCommitmentRecordDeliveryV1 {
        root_id: record.statement.root_id.clone(),
        root_version: record.statement.root_version,
        root_share_epoch: record.statement.root_share_epoch.clone(),
        commitment_hex: hex::encode(record.statement.commitment_wire),
        operator_identity: record.statement.operator_identity.clone(),
        authority_key_epoch: record.statement.authority_key_epoch,
        record_valid_from_ms: record.statement.valid_from_ms,
        record_valid_until_ms: record.statement.valid_until_ms,
        signed_digest_hex: hex::encode(record.signed_digest),
        signature_hex: hex::encode(record.signature),
    }
}

fn decode_digest_list(values: Vec<String>) -> Result<Vec<[u8; 32]>, String> {
    values
        .into_iter()
        .map(|value| decode_hex::<32>(&value))
        .collect()
}

fn required_secret_hex<const N: usize>(name: &str) -> Result<[u8; N], String> {
    let mut value = env::var(name).map_err(|_| format!("{name} is required"))?;
    let decoded = decode_hex(&value);
    value.zeroize();
    decoded
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(value).map_err(|_| format!("expected {N} bytes of lowercase hex"))?;
    if hex::encode(&bytes) != value {
        return Err(format!("expected {N} bytes of lowercase hex"));
    }
    bytes
        .try_into()
        .map_err(|_| format!("expected {N} bytes of lowercase hex"))
}

fn usage() -> String {
    format!(
        "usage:\n  {ROLE_ROOT_SHARE_ENV}=<34-byte-hex> {ROLE_AUTHORITY_KEY_ENV}=<32-byte-hex> cargo run -p router-ab-dev --bin router_ab_ecdsa_commitment_provision -- signed-role-record <deriver-a|deriver-b> < role-metadata.json\n  {RELEASE_KEY_ENV}=<32-byte-hex> cargo run -p router-ab-dev --bin router_ab_ecdsa_commitment_provision -- registry < signed-role-records.json"
    )
}
