use ed25519_dalek::{Signer, SigningKey};
use rand_core::{CryptoRng, Error as RandError, RngCore};
use router_ab_core::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};
use router_ab_ecdsa_client_protocol::{
    authenticate_ecdsa_commitment_registry_v1, EcdsaCommitmentAuthorityV1,
    EcdsaCommitmentPolicyManifestV1, EcdsaCommitmentPolicyPinsV1, EcdsaCommitmentRegistryBindingV1,
    EcdsaCommitmentStatementV1, EcdsaDeriverRoleV1, EcdsaSignedCommitmentPolicyV1,
    EcdsaSignedCommitmentRecordV1,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use threshold_prf::{
    generate_signing_root, split_signing_root, SigningRootShareCommitment, SigningRootShareWire,
    ThresholdPolicy,
};

use crate::local_generated_secret_bytes_v1;

pub const LOCAL_SIGNING_WORKER_ECDSA_COMMITMENT_REGISTRY_ENV_V1: &str =
    "SIGNING_WORKER_ECDSA_COMMITMENT_REGISTRY_JSON";
pub const LOCAL_ECDSA_COMMITMENT_POLICY_RELEASE_AUTHORITY_PUBLIC_KEY_BUILD_ENV_V1: &str =
    "ROUTER_AB_ECDSA_COMMITMENT_POLICY_RELEASE_AUTHORITY_PUBLIC_KEY_HEX";
pub const LOCAL_ECDSA_COMMITMENT_POLICY_DIGEST_BUILD_ENV_V1: &str =
    "ROUTER_AB_ECDSA_COMMITMENT_POLICY_DIGEST_HEX";
pub const LOCAL_ECDSA_COMMITMENT_POLICY_MINIMUM_RELEASE_EPOCH_BUILD_ENV_V1: &str =
    "ROUTER_AB_ECDSA_COMMITMENT_POLICY_MINIMUM_RELEASE_EPOCH";
pub const LOCAL_ECDSA_COMMITMENT_POLICY_BUILD_ENV_FILE_V1: &str =
    ".env.router-ab.ecdsa-commitment-policy.build.local";

const ROOT_ID: &str = "signing-root-v1";
const ROOT_EPOCH: &str = "epoch-1";
const SIGNER_A: &str = "signer-a";
const SIGNER_B: &str = "signer-b";
const RELEASE_EPOCH: u64 = 1;
const ROOT_VERSION: u64 = 1;
const AUTHORITY_EPOCH: u64 = 1;
const VALID_FROM_MS: u64 = 1;
const VALID_UNTIL_MS: u64 = u64::MAX;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEcdsaCommitmentPolicyPackageV1 {
    pub registry_json: String,
    pub build_env: String,
    pub deriver_a_root_share_wire_secret: String,
    pub deriver_b_root_share_wire_secret: String,
    pub policy_digest_hex: String,
    pub release_authority_public_key_hex: String,
}

#[derive(Serialize)]
struct RegistryJson {
    policy: PolicyJson,
    records: RecordsJson,
}

#[derive(Serialize)]
struct PolicyJson {
    manifest: ManifestJson,
    manifest_digest_hex: String,
    release_authority_signature_hex: String,
}

#[derive(Serialize)]
struct ManifestJson {
    release_epoch: u64,
    minimum_root_version: u64,
    minimum_authority_key_epoch: u64,
    revoked_authority_key_epochs: Vec<u64>,
    revoked_record_digests_hex: Vec<String>,
    signer_a_authority: AuthorityJson,
    signer_b_authority: AuthorityJson,
}

#[derive(Serialize)]
struct AuthorityJson {
    operator_identity: String,
    authority_key_epoch: u64,
    valid_from_ms: u64,
    valid_until_ms: u64,
    verifying_key_hex: String,
}

#[derive(Serialize)]
struct RecordsJson {
    signer_a: RecordJson,
    signer_b: RecordJson,
}

#[derive(Serialize)]
struct RecordJson {
    root_id: String,
    root_version: u64,
    root_share_epoch: String,
    commitment_hex: String,
    operator_identity: String,
    authority_key_epoch: u64,
    record_valid_from_ms: u64,
    record_valid_until_ms: u64,
    signed_digest_hex: String,
    signature_hex: String,
}

pub fn local_ecdsa_commitment_policy_package_v1(
    seed: &[u8],
) -> RouterAbProtocolResult<LocalEcdsaCommitmentPolicyPackageV1> {
    let mut rng = DeterministicPackageRng::new(seed, "threshold-prf-root")?;
    let root = generate_signing_root(&mut rng);
    let threshold = ThresholdPolicy::from_u16s(2, 2).map_err(package_error)?;
    let shares = split_signing_root(&root, threshold, &mut rng).map_err(package_error)?;
    let share_a = SigningRootShareWire::from_share(&shares[0]).to_bytes();
    let share_b = SigningRootShareWire::from_share(&shares[1]).to_bytes();
    let commitment_a = SigningRootShareCommitment::from_share(&shares[0]).to_bytes();
    let commitment_b = SigningRootShareCommitment::from_share(&shares[1]).to_bytes();

    let release_key = signing_key(seed, "commitment-policy-release-authority")?;
    let authority_a_key = signing_key(seed, "commitment-authority-a")?;
    let authority_b_key = signing_key(seed, "commitment-authority-b")?;
    let manifest = EcdsaCommitmentPolicyManifestV1 {
        release_epoch: RELEASE_EPOCH,
        minimum_root_version: ROOT_VERSION,
        minimum_authority_key_epoch: AUTHORITY_EPOCH,
        revoked_authority_key_epochs: Vec::new(),
        revoked_record_digests: Vec::new(),
        signer_a_authority: authority(EcdsaDeriverRoleV1::A, SIGNER_A, &authority_a_key),
        signer_b_authority: authority(EcdsaDeriverRoleV1::B, SIGNER_B, &authority_b_key),
    };
    let manifest_digest = manifest.digest().map_err(package_error)?;
    let policy = EcdsaSignedCommitmentPolicyV1 {
        release_authority_signature: release_key
            .sign(&manifest.signing_bytes().map_err(package_error)?)
            .to_bytes(),
        manifest,
        manifest_digest,
    };
    let record_a = signed_record(
        EcdsaDeriverRoleV1::A,
        commitment_a,
        SIGNER_A,
        &authority_a_key,
    )?;
    let record_b = signed_record(
        EcdsaDeriverRoleV1::B,
        commitment_b,
        SIGNER_B,
        &authority_b_key,
    )?;
    let release_public_key = release_key.verifying_key().to_bytes();
    authenticate_ecdsa_commitment_registry_v1(
        &EcdsaCommitmentPolicyPinsV1 {
            release_authority_public_key: release_public_key,
            exact_policy_digest: manifest_digest,
            minimum_release_epoch: RELEASE_EPOCH,
        },
        &policy,
        &EcdsaCommitmentRegistryBindingV1 {
            now_ms: VALID_FROM_MS,
            root_share_epoch: ROOT_EPOCH.to_owned(),
            signer_a_identity: SIGNER_A.to_owned(),
            signer_b_identity: SIGNER_B.to_owned(),
        },
        &record_a,
        &record_b,
    )
    .map_err(package_error)?;

    let policy_digest_hex = hex::encode(manifest_digest);
    let release_authority_public_key_hex = hex::encode(release_public_key);
    let build_env = format!(
        "{}={}\n{}={}\n{}={}\n",
        LOCAL_ECDSA_COMMITMENT_POLICY_RELEASE_AUTHORITY_PUBLIC_KEY_BUILD_ENV_V1,
        release_authority_public_key_hex,
        LOCAL_ECDSA_COMMITMENT_POLICY_DIGEST_BUILD_ENV_V1,
        policy_digest_hex,
        LOCAL_ECDSA_COMMITMENT_POLICY_MINIMUM_RELEASE_EPOCH_BUILD_ENV_V1,
        RELEASE_EPOCH,
    );
    let registry_json = serde_json::to_string(&registry_json(&policy, &record_a, &record_b))
        .map_err(package_error)?;
    Ok(LocalEcdsaCommitmentPolicyPackageV1 {
        registry_json,
        build_env,
        deriver_a_root_share_wire_secret: wire_secret(&share_a),
        deriver_b_root_share_wire_secret: wire_secret(&share_b),
        policy_digest_hex,
        release_authority_public_key_hex,
    })
}

fn signing_key(seed: &[u8], label: &str) -> RouterAbProtocolResult<SigningKey> {
    Ok(SigningKey::from_bytes(&local_generated_secret_bytes_v1(
        label, seed,
    )?))
}

fn authority(
    role: EcdsaDeriverRoleV1,
    operator_identity: &str,
    key: &SigningKey,
) -> EcdsaCommitmentAuthorityV1 {
    EcdsaCommitmentAuthorityV1 {
        role,
        operator_identity: operator_identity.to_owned(),
        authority_key_epoch: AUTHORITY_EPOCH,
        valid_from_ms: VALID_FROM_MS,
        valid_until_ms: VALID_UNTIL_MS,
        verifying_key: key.verifying_key().to_bytes(),
    }
}

fn signed_record(
    role: EcdsaDeriverRoleV1,
    commitment_wire: [u8; 34],
    operator_identity: &str,
    key: &SigningKey,
) -> RouterAbProtocolResult<EcdsaSignedCommitmentRecordV1> {
    let statement = EcdsaCommitmentStatementV1 {
        role,
        share_id: match role {
            EcdsaDeriverRoleV1::A => 1,
            EcdsaDeriverRoleV1::B => 2,
        },
        root_id: ROOT_ID.to_owned(),
        root_version: ROOT_VERSION,
        root_share_epoch: ROOT_EPOCH.to_owned(),
        commitment_wire,
        operator_identity: operator_identity.to_owned(),
        authority_key_epoch: AUTHORITY_EPOCH,
        valid_from_ms: VALID_FROM_MS,
        valid_until_ms: VALID_UNTIL_MS,
    };
    Ok(EcdsaSignedCommitmentRecordV1 {
        signed_digest: statement.digest().map_err(package_error)?,
        signature: key
            .sign(&statement.signing_bytes().map_err(package_error)?)
            .to_bytes(),
        statement,
    })
}

fn registry_json(
    policy: &EcdsaSignedCommitmentPolicyV1,
    signer_a: &EcdsaSignedCommitmentRecordV1,
    signer_b: &EcdsaSignedCommitmentRecordV1,
) -> RegistryJson {
    RegistryJson {
        policy: PolicyJson {
            manifest: ManifestJson {
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
                signer_a_authority: authority_json(&policy.manifest.signer_a_authority),
                signer_b_authority: authority_json(&policy.manifest.signer_b_authority),
            },
            manifest_digest_hex: hex::encode(policy.manifest_digest),
            release_authority_signature_hex: hex::encode(policy.release_authority_signature),
        },
        records: RecordsJson {
            signer_a: record_json(signer_a),
            signer_b: record_json(signer_b),
        },
    }
}

fn authority_json(value: &EcdsaCommitmentAuthorityV1) -> AuthorityJson {
    AuthorityJson {
        operator_identity: value.operator_identity.clone(),
        authority_key_epoch: value.authority_key_epoch,
        valid_from_ms: value.valid_from_ms,
        valid_until_ms: value.valid_until_ms,
        verifying_key_hex: hex::encode(value.verifying_key),
    }
}

fn record_json(value: &EcdsaSignedCommitmentRecordV1) -> RecordJson {
    RecordJson {
        root_id: value.statement.root_id.clone(),
        root_version: value.statement.root_version,
        root_share_epoch: value.statement.root_share_epoch.clone(),
        commitment_hex: hex::encode(value.statement.commitment_wire),
        operator_identity: value.statement.operator_identity.clone(),
        authority_key_epoch: value.statement.authority_key_epoch,
        record_valid_from_ms: value.statement.valid_from_ms,
        record_valid_until_ms: value.statement.valid_until_ms,
        signed_digest_hex: hex::encode(value.signed_digest),
        signature_hex: hex::encode(value.signature),
    }
}

fn wire_secret(bytes: &[u8; 34]) -> String {
    format!("mpc-prf-root-share-wire-v1:{}", hex::encode(bytes))
}

fn package_error(error: impl core::fmt::Debug) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!("local ECDSA commitment policy package failed: {error:?}"),
    )
}

struct DeterministicPackageRng {
    seed: [u8; 32],
    counter: u64,
    buffer: [u8; 32],
    offset: usize,
}

impl DeterministicPackageRng {
    fn new(seed: &[u8], label: &str) -> RouterAbProtocolResult<Self> {
        Ok(Self {
            seed: local_generated_secret_bytes_v1(label, seed)?,
            counter: 0,
            buffer: [0u8; 32],
            offset: 32,
        })
    }

    fn refill(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(b"router-ab-dev/ecdsa-commitment-policy-rng/v1");
        hasher.update(self.seed);
        hasher.update(self.counter.to_be_bytes());
        self.buffer = hasher.finalize().into();
        self.counter = self.counter.wrapping_add(1);
        self.offset = 0;
    }
}

impl RngCore for DeterministicPackageRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_be_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_be_bytes(bytes)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        for byte in destination {
            if self.offset == self.buffer.len() {
                self.refill();
            }
            *byte = self.buffer[self.offset];
            self.offset += 1;
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for DeterministicPackageRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_policy_package_is_deterministic_and_seed_bound() {
        let first = local_ecdsa_commitment_policy_package_v1(b"fixture-seed").expect("package");
        let second = local_ecdsa_commitment_policy_package_v1(b"fixture-seed").expect("package");
        let rotated = local_ecdsa_commitment_policy_package_v1(b"rotated-seed").expect("package");
        assert_eq!(first, second);
        assert_ne!(first, rotated);
        assert!(first
            .deriver_a_root_share_wire_secret
            .starts_with("mpc-prf-root-share-wire-v1:0001"));
        assert!(first
            .deriver_b_root_share_wire_secret
            .starts_with("mpc-prf-root-share-wire-v1:0002"));
    }

    #[test]
    fn client_verifier_fails_closed_on_pin_and_record_drift() {
        let seed = b"drift-test-seed";
        let release_key = signing_key(seed, "commitment-policy-release-authority").expect("key");
        let authority_a_key = signing_key(seed, "commitment-authority-a").expect("key");
        let authority_b_key = signing_key(seed, "commitment-authority-b").expect("key");
        let manifest = EcdsaCommitmentPolicyManifestV1 {
            release_epoch: RELEASE_EPOCH,
            minimum_root_version: ROOT_VERSION,
            minimum_authority_key_epoch: AUTHORITY_EPOCH,
            revoked_authority_key_epochs: Vec::new(),
            revoked_record_digests: Vec::new(),
            signer_a_authority: authority(EcdsaDeriverRoleV1::A, SIGNER_A, &authority_a_key),
            signer_b_authority: authority(EcdsaDeriverRoleV1::B, SIGNER_B, &authority_b_key),
        };
        let digest = manifest.digest().expect("manifest digest");
        let policy = EcdsaSignedCommitmentPolicyV1 {
            release_authority_signature: release_key
                .sign(&manifest.signing_bytes().expect("manifest bytes"))
                .to_bytes(),
            manifest,
            manifest_digest: digest,
        };
        let mut commitment_a = [0x11; 34];
        commitment_a[..2].copy_from_slice(&1u16.to_be_bytes());
        let mut commitment_b = [0x22; 34];
        commitment_b[..2].copy_from_slice(&2u16.to_be_bytes());
        let record_a = signed_record(
            EcdsaDeriverRoleV1::A,
            commitment_a,
            SIGNER_A,
            &authority_a_key,
        )
        .expect("record A");
        let record_b = signed_record(
            EcdsaDeriverRoleV1::B,
            commitment_b,
            SIGNER_B,
            &authority_b_key,
        )
        .expect("record B");
        let binding = EcdsaCommitmentRegistryBindingV1 {
            now_ms: VALID_FROM_MS,
            root_share_epoch: ROOT_EPOCH.to_owned(),
            signer_a_identity: SIGNER_A.to_owned(),
            signer_b_identity: SIGNER_B.to_owned(),
        };
        let pins = EcdsaCommitmentPolicyPinsV1 {
            release_authority_public_key: release_key.verifying_key().to_bytes(),
            exact_policy_digest: digest,
            minimum_release_epoch: RELEASE_EPOCH,
        };
        authenticate_ecdsa_commitment_registry_v1(&pins, &policy, &binding, &record_a, &record_b)
            .expect("fixture authenticates");

        let mut drifted_pins = pins;
        drifted_pins.exact_policy_digest[0] ^= 1;
        assert!(authenticate_ecdsa_commitment_registry_v1(
            &drifted_pins,
            &policy,
            &binding,
            &record_a,
            &record_b,
        )
        .is_err());

        let mut drifted_record = record_a.clone();
        drifted_record.statement.commitment_wire[2] ^= 1;
        assert!(authenticate_ecdsa_commitment_registry_v1(
            &pins,
            &policy,
            &binding,
            &drifted_record,
            &record_b,
        )
        .is_err());
    }
}
