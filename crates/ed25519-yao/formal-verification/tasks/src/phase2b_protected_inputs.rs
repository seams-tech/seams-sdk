//! Protected authority-policy and project-challenge boundary for Phase 2B.

use core::fmt;
use std::env;

use ed25519_dalek::VerifyingKey;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const POLICY_JSON_ENV: &str = "ED25519_YAO_PHASE2B_REVIEW_POLICY_JSON";
pub(crate) const POLICY_DIGEST_ENV: &str = "ED25519_YAO_PHASE2B_REVIEW_POLICY_SHA256";
pub(crate) const CHALLENGE_ENV: &str = "ED25519_YAO_PHASE2B_REPRODUCTION_CHALLENGE_HEX";

pub(crate) const POLICY_SCHEMA: &str = "seams:router-ab:ed25519-yao:phase2b-review-authorities:v1";
pub(crate) const POLICY_SCOPE: &str = "phase2b_external_reproduction_and_review_authorities_v1";
pub(crate) const PROTOCOL_ID: &str = "router_ab_ed25519_yao_v1";
pub(crate) const REPRODUCER_ROLE: &str = "independent_reproducer";
pub(crate) const REVIEWER_ROLE: &str = "cryptographic_reviewer";

const AUTHORITY_DIGEST_DOMAIN: &[u8] =
    b"seams/router-ab/ed25519-yao/phase2b-review-authority-key-digest/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProtectedInputsErrorV1 {
    MissingEnvironment(&'static str),
    InvalidEnvironment(&'static str),
    Json,
    NonCanonicalJson,
    InvalidField(&'static str),
    InvalidHex(&'static str),
    InvalidAuthorityKey,
    WeakAuthorityKey,
    AuthorityDigestMismatch,
    AuthoritiesNotDistinct,
    ProtectedPolicyDigestMismatch,
}

impl fmt::Display for ProtectedInputsErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEnvironment(name) => {
                write!(formatter, "missing protected Phase 2B environment `{name}`")
            }
            Self::InvalidEnvironment(name) => {
                write!(formatter, "invalid protected Phase 2B environment `{name}`")
            }
            Self::Json => formatter.write_str("protected Phase 2B policy is invalid JSON"),
            Self::NonCanonicalJson => {
                formatter.write_str("protected Phase 2B policy is not canonical JSON")
            }
            Self::InvalidField(field) => {
                write!(formatter, "invalid protected policy field `{field}`")
            }
            Self::InvalidHex(field) => write!(formatter, "invalid lowercase hex field `{field}`"),
            Self::InvalidAuthorityKey => formatter.write_str("invalid Ed25519 authority key"),
            Self::WeakAuthorityKey => formatter.write_str("weak Ed25519 authority key"),
            Self::AuthorityDigestMismatch => formatter.write_str("authority-key digest mismatch"),
            Self::AuthoritiesNotDistinct => {
                formatter.write_str("reproducer and reviewer authorities are not distinct")
            }
            Self::ProtectedPolicyDigestMismatch => {
                formatter.write_str("protected authority-policy digest mismatch")
            }
        }
    }
}

impl std::error::Error for ProtectedInputsErrorV1 {}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReviewAuthorityPolicyV1 {
    pub(crate) schema: String,
    pub(crate) protocol_id: String,
    pub(crate) policy_scope: String,
    pub(crate) policy_version: u64,
    pub(crate) minimum_approval_sequence: u64,
    pub(crate) independent_reproducer: ReviewAuthorityV1,
    pub(crate) cryptographic_reviewer: ReviewAuthorityV1,
    pub(crate) required_distinct_authorities: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReviewAuthorityV1 {
    pub(crate) role: String,
    pub(crate) authority_id: String,
    pub(crate) key_epoch: u64,
    pub(crate) verifying_key_hex: String,
    pub(crate) authority_key_digest_hex: String,
}

pub(crate) struct ValidatedAuthorityPolicyV1 {
    pub(crate) policy: ReviewAuthorityPolicyV1,
    pub(crate) canonical_sha256: [u8; 32],
    pub(crate) reproducer_key: VerifyingKey,
    pub(crate) reviewer_key: VerifyingKey,
}

pub(crate) struct ProjectChallengeV1([u8; 32]);

impl ProjectChallengeV1 {
    pub(crate) const fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) const fn synthetic(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

pub(crate) struct ProtectedPhase2bInputsV1 {
    pub(crate) policy: ValidatedAuthorityPolicyV1,
    pub(crate) challenge: ProjectChallengeV1,
}

pub(crate) fn load_protected_inputs() -> Result<ProtectedPhase2bInputsV1, ProtectedInputsErrorV1> {
    let policy_json = required_utf8_environment(POLICY_JSON_ENV)?;
    let policy_digest_hex = required_utf8_environment(POLICY_DIGEST_ENV)?;
    let challenge_hex = required_utf8_environment(CHALLENGE_ENV)?;
    let policy_digest = decode_hex::<32>(&policy_digest_hex, "protected_policy_digest")?;
    let challenge = decode_nonzero_challenge(&challenge_hex)?;
    Ok(ProtectedPhase2bInputsV1 {
        policy: validate_policy(policy_json.as_bytes(), policy_digest)?,
        challenge,
    })
}

pub(crate) fn run_protected_inputs_check() -> Result<String, ProtectedInputsErrorV1> {
    let inputs = load_protected_inputs()?;
    Ok(format!(
        "phase2b-protected-inputs-check ok: policy_digest={} policy_version={} minimum_approval_sequence={} reproducer={}@{} reproducer_key_sha256={} reviewer={}@{} reviewer_key_sha256={} challenge_digest={}",
        encode_hex(&inputs.policy.canonical_sha256),
        inputs.policy.policy.policy_version,
        inputs.policy.policy.minimum_approval_sequence,
        inputs.policy.policy.independent_reproducer.authority_id,
        inputs.policy.policy.independent_reproducer.key_epoch,
        encode_hex(&Sha256::digest(inputs.policy.reproducer_key.as_bytes())),
        inputs.policy.policy.cryptographic_reviewer.authority_id,
        inputs.policy.policy.cryptographic_reviewer.key_epoch,
        encode_hex(&Sha256::digest(inputs.policy.reviewer_key.as_bytes())),
        encode_hex(&Sha256::digest(inputs.challenge.bytes())),
    ))
}

pub(crate) fn validate_policy(
    bytes: &[u8],
    protected_digest: [u8; 32],
) -> Result<ValidatedAuthorityPolicyV1, ProtectedInputsErrorV1> {
    let canonical_sha256: [u8; 32] = Sha256::digest(bytes).into();
    if canonical_sha256 != protected_digest {
        return Err(ProtectedInputsErrorV1::ProtectedPolicyDigestMismatch);
    }
    let policy: ReviewAuthorityPolicyV1 = parse_canonical(bytes)?;
    require_equal(&policy.schema, POLICY_SCHEMA, "policy.schema")?;
    require_equal(&policy.protocol_id, PROTOCOL_ID, "policy.protocol_id")?;
    require_equal(&policy.policy_scope, POLICY_SCOPE, "policy.policy_scope")?;
    require_nonzero(policy.policy_version, "policy.policy_version")?;
    require_nonzero(
        policy.minimum_approval_sequence,
        "policy.minimum_approval_sequence",
    )?;
    if !policy.required_distinct_authorities {
        return Err(ProtectedInputsErrorV1::InvalidField(
            "policy.required_distinct_authorities",
        ));
    }
    let reproducer_key = validate_authority(&policy.independent_reproducer, REPRODUCER_ROLE)?;
    let reviewer_key = validate_authority(&policy.cryptographic_reviewer, REVIEWER_ROLE)?;
    if policy.independent_reproducer.authority_id == policy.cryptographic_reviewer.authority_id
        || reproducer_key == reviewer_key
        || policy.independent_reproducer.authority_key_digest_hex
            == policy.cryptographic_reviewer.authority_key_digest_hex
    {
        return Err(ProtectedInputsErrorV1::AuthoritiesNotDistinct);
    }
    Ok(ValidatedAuthorityPolicyV1 {
        policy,
        canonical_sha256,
        reproducer_key,
        reviewer_key,
    })
}

pub(crate) fn authority_digest(role: &str, id: &str, epoch: u64, key: &[u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::new();
    push_lp32(&mut preimage, AUTHORITY_DIGEST_DOMAIN);
    push_lp32(&mut preimage, role.as_bytes());
    push_lp32(&mut preimage, id.as_bytes());
    push_lp32(&mut preimage, &epoch.to_be_bytes());
    push_lp32(&mut preimage, key);
    Sha256::digest(preimage).into()
}

fn validate_authority(
    authority: &ReviewAuthorityV1,
    expected_role: &'static str,
) -> Result<VerifyingKey, ProtectedInputsErrorV1> {
    require_equal(&authority.role, expected_role, "authority.role")?;
    require_visible_ascii(&authority.authority_id, "authority.authority_id")?;
    require_nonzero(authority.key_epoch, "authority.key_epoch")?;
    let key_bytes = decode_hex::<32>(&authority.verifying_key_hex, "authority.verifying_key")?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| ProtectedInputsErrorV1::InvalidAuthorityKey)?;
    if key.is_weak() {
        return Err(ProtectedInputsErrorV1::WeakAuthorityKey);
    }
    if encode_hex(&authority_digest(
        expected_role,
        &authority.authority_id,
        authority.key_epoch,
        &key_bytes,
    )) != authority.authority_key_digest_hex
    {
        return Err(ProtectedInputsErrorV1::AuthorityDigestMismatch);
    }
    Ok(key)
}

fn decode_nonzero_challenge(value: &str) -> Result<ProjectChallengeV1, ProtectedInputsErrorV1> {
    let bytes = decode_hex::<32>(value, "reproduction_challenge")?;
    if bytes == [0; 32] {
        return Err(ProtectedInputsErrorV1::InvalidField(
            "reproduction_challenge",
        ));
    }
    Ok(ProjectChallengeV1(bytes))
}

fn required_utf8_environment(name: &'static str) -> Result<String, ProtectedInputsErrorV1> {
    match env::var(name) {
        Ok(value) if !value.is_empty() => Ok(value),
        Ok(_) => Err(ProtectedInputsErrorV1::InvalidEnvironment(name)),
        Err(env::VarError::NotPresent) => Err(ProtectedInputsErrorV1::MissingEnvironment(name)),
        Err(env::VarError::NotUnicode(_)) => Err(ProtectedInputsErrorV1::InvalidEnvironment(name)),
    }
}

fn parse_canonical<T>(bytes: &[u8]) -> Result<T, ProtectedInputsErrorV1>
where
    T: DeserializeOwned + Serialize,
{
    let value: T = serde_json::from_slice(bytes).map_err(|_| ProtectedInputsErrorV1::Json)?;
    if canonical_json(&value) != bytes {
        return Err(ProtectedInputsErrorV1::NonCanonicalJson);
    }
    Ok(value)
}

fn canonical_json<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).expect("fixed protected input serializes");
    bytes.push(b'\n');
    bytes
}

fn decode_hex<const N: usize>(
    value: &str,
    field: &'static str,
) -> Result<[u8; N], ProtectedInputsErrorV1> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProtectedInputsErrorV1::InvalidHex(field));
    }
    let mut output = [0u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| ProtectedInputsErrorV1::InvalidHex(field))?;
    }
    Ok(output)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn push_lp32(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("fixed protected input field fits LP32");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

fn require_equal(
    actual: &str,
    expected: &str,
    field: &'static str,
) -> Result<(), ProtectedInputsErrorV1> {
    if actual == expected {
        Ok(())
    } else {
        Err(ProtectedInputsErrorV1::InvalidField(field))
    }
}

fn require_nonzero(value: u64, field: &'static str) -> Result<(), ProtectedInputsErrorV1> {
    if value == 0 {
        Err(ProtectedInputsErrorV1::InvalidField(field))
    } else {
        Ok(())
    }
}

fn require_visible_ascii(value: &str, field: &'static str) -> Result<(), ProtectedInputsErrorV1> {
    if value.is_empty()
        || value.trim() != value
        || !value
            .bytes()
            .all(|byte| byte.is_ascii() && !byte.is_ascii_control())
    {
        Err(ProtectedInputsErrorV1::InvalidField(field))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn policy() -> ReviewAuthorityPolicyV1 {
        let reproducer = SigningKey::from_bytes(&[0x11; 32]);
        let reviewer = SigningKey::from_bytes(&[0x22; 32]);
        ReviewAuthorityPolicyV1 {
            schema: POLICY_SCHEMA.to_owned(),
            protocol_id: PROTOCOL_ID.to_owned(),
            policy_scope: POLICY_SCOPE.to_owned(),
            policy_version: 1,
            minimum_approval_sequence: 9,
            independent_reproducer: authority(REPRODUCER_ROLE, "operator-a", 3, &reproducer),
            cryptographic_reviewer: authority(REVIEWER_ROLE, "reviewer-b", 7, &reviewer),
            required_distinct_authorities: true,
        }
    }

    fn authority(role: &str, id: &str, epoch: u64, key: &SigningKey) -> ReviewAuthorityV1 {
        let verifying = key.verifying_key().to_bytes();
        ReviewAuthorityV1 {
            role: role.to_owned(),
            authority_id: id.to_owned(),
            key_epoch: epoch,
            verifying_key_hex: encode_hex(&verifying),
            authority_key_digest_hex: encode_hex(&authority_digest(role, id, epoch, &verifying)),
        }
    }

    #[test]
    fn canonical_policy_produces_private_validated_authorities() {
        let bytes = canonical_json(&policy());
        let validated = validate_policy(&bytes, Sha256::digest(&bytes).into()).expect("policy");
        assert_eq!(validated.policy.policy_version, 1);
        assert_eq!(validated.policy.minimum_approval_sequence, 9);
    }

    #[test]
    fn protected_digest_mismatch_fails_before_policy_acceptance() {
        let bytes = canonical_json(&policy());
        assert!(matches!(
            validate_policy(&bytes, [0; 32]),
            Err(ProtectedInputsErrorV1::ProtectedPolicyDigestMismatch)
        ));
    }

    #[test]
    fn unknown_reordered_crlf_and_trailing_policy_bytes_fail() {
        let bytes = canonical_json(&policy());
        let source = String::from_utf8(bytes.clone()).expect("UTF-8");
        let unknown = source.replacen("{\n", "{\n  \"unknown\": true,\n", 1);
        assert!(parse_canonical::<ReviewAuthorityPolicyV1>(unknown.as_bytes()).is_err());
        assert!(parse_canonical::<ReviewAuthorityPolicyV1>(
            source.replace('\n', "\r\n").as_bytes()
        )
        .is_err());
        let mut trailing = bytes;
        trailing.extend_from_slice(b" \n");
        assert!(parse_canonical::<ReviewAuthorityPolicyV1>(&trailing).is_err());
    }

    #[test]
    fn weak_invalid_and_shared_authorities_fail_closed() {
        let mut value = policy();
        value.independent_reproducer.verifying_key_hex = "00".repeat(32);
        let bytes = canonical_json(&value);
        assert!(validate_policy(&bytes, Sha256::digest(&bytes).into()).is_err());

        let mut value = policy();
        value.cryptographic_reviewer = value.independent_reproducer.clone();
        value.cryptographic_reviewer.role = REVIEWER_ROLE.to_owned();
        let bytes = canonical_json(&value);
        assert!(validate_policy(&bytes, Sha256::digest(&bytes).into()).is_err());
    }

    #[test]
    fn wrong_roles_zero_versions_and_optional_distinctness_fail() {
        let mut value = policy();
        value.independent_reproducer.role = REVIEWER_ROLE.to_owned();
        let bytes = canonical_json(&value);
        assert!(validate_policy(&bytes, Sha256::digest(&bytes).into()).is_err());

        let mut value = policy();
        value.policy_version = 0;
        let bytes = canonical_json(&value);
        assert!(validate_policy(&bytes, Sha256::digest(&bytes).into()).is_err());

        let mut value = policy();
        value.required_distinct_authorities = false;
        let bytes = canonical_json(&value);
        assert!(validate_policy(&bytes, Sha256::digest(&bytes).into()).is_err());
    }

    #[test]
    fn project_challenge_is_exact_lowercase_nonzero_hex() {
        assert!(decode_nonzero_challenge(&"55".repeat(32)).is_ok());
        assert_eq!(
            ProjectChallengeV1::synthetic([0x55; 32]).bytes(),
            &[0x55; 32]
        );
        assert!(decode_nonzero_challenge(&"00".repeat(32)).is_err());
        assert!(decode_nonzero_challenge(&"AA".repeat(32)).is_err());
        assert!(decode_nonzero_challenge(&"55".repeat(31)).is_err());
    }

    #[test]
    fn protected_environment_names_are_fixed_and_disjoint() {
        assert_eq!(POLICY_JSON_ENV, "ED25519_YAO_PHASE2B_REVIEW_POLICY_JSON");
        assert_eq!(
            POLICY_DIGEST_ENV,
            "ED25519_YAO_PHASE2B_REVIEW_POLICY_SHA256"
        );
        assert_eq!(
            CHALLENGE_ENV,
            "ED25519_YAO_PHASE2B_REPRODUCTION_CHALLENGE_HEX"
        );
        assert_ne!(POLICY_JSON_ENV, POLICY_DIGEST_ENV);
        assert_ne!(POLICY_DIGEST_ENV, CHALLENGE_ENV);
    }

    #[test]
    fn protected_capabilities_have_no_clone_or_serialization_surface() {
        let source = include_str!("phase2b_protected_inputs.rs");
        for declaration in [
            "struct ValidatedAuthorityPolicyV1",
            "struct ProjectChallengeV1",
            "struct ProtectedPhase2bInputsV1",
        ] {
            let offset = source.find(declaration).expect("capability declaration");
            let prefix = &source[offset.saturating_sub(80)..offset];
            assert!(!prefix.contains("Clone"));
            assert!(!prefix.contains("Serialize"));
        }
        assert!(!source.contains("SigningKey") || source.contains("#[cfg(test)]"));
    }
}
