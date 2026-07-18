use crate::encoders::{base64_url_decode, base64_url_encode};
use router_ab_ecdsa_client_protocol::{
    authenticate_ecdsa_commitment_registry_v1, decode_ecdsa_client_proof_bundle_envelope_v1,
    finalize_ecdsa_prf_two_party_output_v1, open_ecdsa_client_proof_bundle_v1,
    pair_ecdsa_opened_client_proof_bundles_v1, EcdsaClientProofBundleDeliveryKindV1,
    EcdsaClientProofBundleDeliveryV1, EcdsaClientProofBundlePairDeliveryV1,
    EcdsaCommitmentAuthorityDeliveryV1, EcdsaCommitmentAuthorityV1,
    EcdsaCommitmentPolicyManifestV1, EcdsaCommitmentPolicyPinsV1,
    EcdsaCommitmentRecordDeliveryV1, EcdsaCommitmentRegistryDeliveryV1,
    EcdsaCommitmentStatementV1, EcdsaDeriverRoleV1, EcdsaSignedCommitmentPolicyDeliveryV1,
    EcdsaSignedCommitmentPolicyV1, EcdsaSignedCommitmentRecordV1,
};
use serde::{Deserialize, Serialize};

const RELEASE_AUTHORITY_PUBLIC_KEY_BUILD_ENV: &str =
    "ROUTER_AB_ECDSA_COMMITMENT_POLICY_RELEASE_AUTHORITY_PUBLIC_KEY_HEX";
const POLICY_DIGEST_BUILD_ENV: &str = "ROUTER_AB_ECDSA_COMMITMENT_POLICY_DIGEST_HEX";
const MINIMUM_RELEASE_EPOCH_BUILD_ENV: &str =
    "ROUTER_AB_ECDSA_COMMITMENT_POLICY_MINIMUM_RELEASE_EPOCH";

pub(crate) fn finalize_encrypted_client_proof_bundles_v1(
    input_json: &str,
    private_key: &[u8; 32],
) -> Result<String, String> {
    serialize_final_output(finalize_encrypted_client_proof_output_v1(
        input_json,
        private_key,
    )?)
}

pub(crate) fn finalize_encrypted_client_proof_output_v1(
    input_json: &str,
    private_key: &[u8; 32],
) -> Result<[u8; 32], String> {
    let input: FinalizeEncryptedClientProofBundlesInputV1 =
        serde_json::from_str(input_json).map_err(|error| error.to_string())?;
    finalize_encrypted_client_proof_input_v1(input, private_key)
}

pub(crate) fn finalize_encrypted_client_proof_input_v1(
    input: FinalizeEncryptedClientProofBundlesInputV1,
    private_key: &[u8; 32],
) -> Result<[u8; 32], String> {
    match input.kind {
        FinalizeEncryptedClientProofBundlesKindV1::FinalizeEncryptedClientProofBundlesV1 => {}
    }
    let signer_a = open_client_wire_bundle(input.bundles.signer_a, private_key)?;
    let signer_b = open_client_wire_bundle(input.bundles.signer_b, private_key)?;
    let pair =
        pair_ecdsa_opened_client_proof_bundles_v1(signer_a, signer_b).map_err(protocol_error)?;
    let pins = build_pinned_commitment_policy_v1()?;
    let policy = parse_signed_policy(input.commitment_registry.policy)?;
    let signer_a_record = parse_signed_record(
        input.commitment_registry.records.signer_a,
        EcdsaDeriverRoleV1::A,
        1,
    )?;
    let signer_b_record = parse_signed_record(
        input.commitment_registry.records.signer_b,
        EcdsaDeriverRoleV1::B,
        2,
    )?;
    let binding = pair.commitment_registry_binding(input.verification_time_ms);
    let registry = authenticate_ecdsa_commitment_registry_v1(
        &pins,
        &policy,
        &binding,
        &signer_a_record,
        &signer_b_record,
    )
    .map_err(protocol_error)?;
    let context = pair.prf_context().map_err(protocol_error)?;
    finalize_ecdsa_prf_two_party_output_v1(
        &context,
        &registry,
        &pair.signer_a().role_bound_proof,
        &pair.signer_b().role_bound_proof,
    )
    .map_err(protocol_error)
}

fn open_client_wire_bundle(
    input: EcdsaClientProofBundleDeliveryV1,
    private_key: &[u8; 32],
) -> Result<router_ab_ecdsa_client_protocol::EcdsaOpenedClientProofBundleV1, String> {
    match input.kind {
        EcdsaClientProofBundleDeliveryKindV1::RecipientProofBundle => {}
    }
    let wire_transcript_digest =
        decode_fixed_base64::<32>(&input.transcript_digest_b64u, "bundle.transcriptDigestB64u")?;
    let payload = decode_nonempty_base64(&input.payload_b64u, "bundle.payloadB64u")?;
    let envelope =
        decode_ecdsa_client_proof_bundle_envelope_v1(&payload).map_err(protocol_error)?;
    if envelope.transcript_digest != wire_transcript_digest {
        return Err("recipient proof-bundle WireMessage transcript digest mismatch".to_owned());
    }
    open_ecdsa_client_proof_bundle_v1(&envelope, private_key).map_err(protocol_error)
}

fn serialize_final_output(output: [u8; 32]) -> Result<String, String> {
    serde_json::to_string(&FinalizeEcdsaPrfOutputResultV1 {
        kind: FinalizeEcdsaPrfOutputResultKindV1::RouterAbEcdsaPrfOutputV1,
        output32_b64u: base64_url_encode(&output),
    })
    .map_err(|error| error.to_string())
}

fn build_pinned_commitment_policy_v1() -> Result<EcdsaCommitmentPolicyPinsV1, String> {
    let release_authority_public_key = parse_build_hex::<32>(
        option_env!("ROUTER_AB_ECDSA_COMMITMENT_POLICY_RELEASE_AUTHORITY_PUBLIC_KEY_HEX"),
        RELEASE_AUTHORITY_PUBLIC_KEY_BUILD_ENV,
    )?;
    let exact_policy_digest = parse_build_hex::<32>(
        option_env!("ROUTER_AB_ECDSA_COMMITMENT_POLICY_DIGEST_HEX"),
        POLICY_DIGEST_BUILD_ENV,
    )?;
    let minimum_release_epoch = parse_build_positive_u64(
        option_env!("ROUTER_AB_ECDSA_COMMITMENT_POLICY_MINIMUM_RELEASE_EPOCH"),
        MINIMUM_RELEASE_EPOCH_BUILD_ENV,
    )?;
    Ok(EcdsaCommitmentPolicyPinsV1 {
        release_authority_public_key,
        exact_policy_digest,
        minimum_release_epoch,
    })
}

fn parse_signed_policy(
    policy: EcdsaSignedCommitmentPolicyDeliveryV1,
) -> Result<EcdsaSignedCommitmentPolicyV1, String> {
    let manifest = policy.manifest;
    Ok(EcdsaSignedCommitmentPolicyV1 {
        manifest: EcdsaCommitmentPolicyManifestV1 {
            release_epoch: manifest.release_epoch,
            minimum_root_version: manifest.minimum_root_version,
            minimum_authority_key_epoch: manifest.minimum_authority_key_epoch,
            revoked_authority_key_epochs: manifest.revoked_authority_key_epochs,
            revoked_record_digests: parse_digest_list(manifest.revoked_record_digests_hex)?,
            signer_a_authority: parse_authority(
                manifest.signer_a_authority,
                EcdsaDeriverRoleV1::A,
            )?,
            signer_b_authority: parse_authority(
                manifest.signer_b_authority,
                EcdsaDeriverRoleV1::B,
            )?,
        },
        manifest_digest: decode_lower_hex::<32>(
            &policy.manifest_digest_hex,
            "policy.manifestDigestHex",
        )?,
        release_authority_signature: decode_lower_hex::<64>(
            &policy.release_authority_signature_hex,
            "policy.releaseAuthoritySignatureHex",
        )?,
    })
}

fn parse_authority(
    authority: EcdsaCommitmentAuthorityDeliveryV1,
    role: EcdsaDeriverRoleV1,
) -> Result<EcdsaCommitmentAuthorityV1, String> {
    Ok(EcdsaCommitmentAuthorityV1 {
        role,
        operator_identity: authority.operator_identity,
        authority_key_epoch: authority.authority_key_epoch,
        valid_from_ms: authority.valid_from_ms,
        valid_until_ms: authority.valid_until_ms,
        verifying_key: decode_lower_hex::<32>(
            &authority.verifying_key_hex,
            "authority.verifyingKeyHex",
        )?,
    })
}

fn parse_signed_record(
    record: EcdsaCommitmentRecordDeliveryV1,
    role: EcdsaDeriverRoleV1,
    share_id: u16,
) -> Result<EcdsaSignedCommitmentRecordV1, String> {
    Ok(EcdsaSignedCommitmentRecordV1 {
        statement: EcdsaCommitmentStatementV1 {
            role,
            share_id,
            root_id: record.root_id,
            root_version: record.root_version,
            root_share_epoch: record.root_share_epoch,
            commitment_wire: decode_lower_hex::<34>(
                &record.commitment_hex,
                "record.commitmentHex",
            )?,
            operator_identity: record.operator_identity,
            authority_key_epoch: record.authority_key_epoch,
            valid_from_ms: record.record_valid_from_ms,
            valid_until_ms: record.record_valid_until_ms,
        },
        signed_digest: decode_lower_hex::<32>(&record.signed_digest_hex, "record.signedDigestHex")?,
        signature: decode_lower_hex::<64>(&record.signature_hex, "record.signatureHex")?,
    })
}

fn parse_digest_list(values: Vec<String>) -> Result<Vec<[u8; 32]>, String> {
    values
        .into_iter()
        .map(|value| decode_lower_hex::<32>(&value, "policy.revokedRecordDigestsHex"))
        .collect()
}

fn parse_build_hex<const N: usize>(value: Option<&str>, field: &str) -> Result<[u8; N], String> {
    let value = value.ok_or_else(|| format!("{field} build pin is missing"))?;
    decode_lower_hex(value, field)
}

fn parse_build_positive_u64(value: Option<&str>, field: &str) -> Result<u64, String> {
    let value = value.ok_or_else(|| format!("{field} build pin is missing"))?;
    if value.is_empty()
        || value == "0"
        || value.starts_with('0')
        || !value.as_bytes().iter().all(u8::is_ascii_digit)
    {
        return Err(format!("{field} must be a canonical positive u64"));
    }
    value
        .parse::<u64>()
        .map_err(|_| format!("{field} must be a canonical positive u64"))
}

fn decode_lower_hex<const N: usize>(value: &str, field: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 {
        return Err(format!("{field} must be {} lowercase hex bytes", N));
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (decode_lower_hex_nibble(pair[0], field)? << 4)
            | decode_lower_hex_nibble(pair[1], field)?;
    }
    Ok(output)
}

fn decode_lower_hex_nibble(value: u8, field: &str) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(format!("{field} must use lowercase hexadecimal")),
    }
}

fn decode_fixed_base64<const N: usize>(value: &str, field: &str) -> Result<[u8; N], String> {
    let decoded = base64_url_decode(value).map_err(|error| format!("{field}: {error}"))?;
    decoded
        .try_into()
        .map_err(|_| format!("{field} must decode to {N} bytes"))
}

fn decode_nonempty_base64(value: &str, field: &str) -> Result<Vec<u8>, String> {
    let decoded = base64_url_decode(value).map_err(|error| format!("{field}: {error}"))?;
    if decoded.is_empty() {
        return Err(format!("{field} must be non-empty"));
    }
    Ok(decoded)
}

fn protocol_error(error: router_ab_ecdsa_client_protocol::EcdsaClientProtocolError) -> String {
    format!("Router A/B ECDSA PRF finalization failed: {error:?}")
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FinalizeEncryptedClientProofBundlesInputV1 {
    kind: FinalizeEncryptedClientProofBundlesKindV1,
    verification_time_ms: u64,
    commitment_registry: EcdsaCommitmentRegistryDeliveryV1,
    bundles: EcdsaClientProofBundlePairDeliveryV1,
}

impl FinalizeEncryptedClientProofBundlesInputV1 {
    pub(crate) fn proof_transcript_digest_b64u(&self) -> Result<String, String> {
        let signer_a = &self.bundles.signer_a.transcript_digest_b64u;
        let signer_b = &self.bundles.signer_b.transcript_digest_b64u;
        if signer_a != signer_b {
            return Err("client proof bundles bind different transcripts".to_owned());
        }
        Ok(signer_a.clone())
    }
}

#[derive(Debug, Deserialize)]
enum FinalizeEncryptedClientProofBundlesKindV1 {
    #[serde(rename = "finalize_encrypted_client_proof_bundles_v1")]
    FinalizeEncryptedClientProofBundlesV1,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FinalizeEcdsaPrfOutputResultV1 {
    kind: FinalizeEcdsaPrfOutputResultKindV1,
    output32_b64u: String,
}

#[derive(Debug, Serialize)]
enum FinalizeEcdsaPrfOutputResultKindV1 {
    #[serde(rename = "router_ab_ecdsa_prf_output_v1")]
    RouterAbEcdsaPrfOutputV1,
}
