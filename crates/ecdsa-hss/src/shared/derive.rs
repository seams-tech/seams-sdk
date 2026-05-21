use core::fmt;
use k256::elliptic_curve::bigint::U512;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::Group;
use k256::{FieldBytes, NonZeroScalar, ProjectivePoint, PublicKey, SecretKey, WideBytes};
use sha2::{Digest, Sha256, Sha512};
use signer_core::error::{CoreResult, SignerCoreError};
use signer_core::secp256k1::{
    add_secp256k1_public_keys_33, map_additive_share_to_threshold_signatures_share_2p,
    secp256k1_private_key_32_to_public_key_33, secp256k1_public_key_33_to_ethereum_address_20,
    validate_secp256k1_public_key_33, THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID,
    THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::shared::context::{encode_context_v1, EcdsaHssStableKeyContextV1};
use crate::wire::{ExplicitExportAuthorizationV1, ServerEvalOperationV1};

const CONTEXT_BINDING_DOMAIN: &[u8] = b"ecdsa-hss:role-local:v1:context-binding";
const CLIENT_SHARE_DOMAIN: &[u8] = b"ecdsa-hss:role-local:v1:client-share";
const RELAYER_SHARE_DOMAIN: &[u8] = b"ecdsa-hss:role-local:v1:relayer-share";
const PUBLIC_TRANSCRIPT_DOMAIN: &[u8] = b"ecdsa-hss:role-local:v1:public-transcript";
const EXPORT_AUTHORIZATION_DOMAIN: &[u8] = b"ecdsa-hss:role-local:v1:export-authorization";

const FIELD_CONTEXT_BYTES: u8 = 0x01;
const FIELD_CONTEXT_BINDING: u8 = 0x01;
const FIELD_ROLE_CONTEXT_BYTES: u8 = 0x02;
const FIELD_ROLE_ROOT: u8 = 0x03;
const FIELD_ROLE_RETRY_COUNTER: u8 = 0x04;
const FIELD_TRANSCRIPT_OPERATION: u8 = 0x02;
const FIELD_CLIENT_PUBLIC_KEY: u8 = 0x03;
const FIELD_RELAYER_PUBLIC_KEY: u8 = 0x04;
const FIELD_THRESHOLD_PUBLIC_KEY: u8 = 0x05;
const FIELD_THRESHOLD_ETHEREUM_ADDRESS: u8 = 0x06;
const FIELD_CLIENT_SHARE_RETRY_COUNTER: u8 = 0x07;
const FIELD_RELAYER_SHARE_RETRY_COUNTER: u8 = 0x08;
const FIELD_EXPORT_PUBLIC_TRANSCRIPT_DIGEST: u8 = 0x01;
const FIELD_EXPORT_WALLET_SESSION_USER_ID: u8 = 0x07;
const FIELD_EXPORT_ECDSA_THRESHOLD_KEY_ID: u8 = 0x08;
const FIELD_EXPORT_CLIENT_DEVICE_ID: u8 = 0x09;
const FIELD_EXPORT_CLIENT_SESSION_ID: u8 = 0x0a;
const FIELD_EXPORT_RELAYER_KEY_ID: u8 = 0x0b;
const FIELD_EXPORT_REQUEST_NONCE: u8 = 0x0c;
const FIELD_EXPORT_CONFIRMATION_DIGEST: u8 = 0x0d;
const FIELD_EXPORT_ISSUED_AT_UNIX_MS: u8 = 0x0e;
const FIELD_EXPORT_EXPIRES_AT_UNIX_MS: u8 = 0x0f;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicIdentityV1 {
    pub context_bytes: Vec<u8>,
    pub context_binding32: [u8; 32],
    pub client_public_key33: [u8; 33],
    pub relayer_public_key33: [u8; 33],
    pub threshold_public_key33: [u8; 33],
    pub threshold_ethereum_address20: [u8; 20],
    pub client_share_retry_counter: u32,
    pub relayer_share_retry_counter: u32,
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ClientRoleShareV1 {
    #[zeroize(skip)]
    pub context_bytes: Vec<u8>,
    pub context_binding32: [u8; 32],
    pub retry_counter: u32,
    pub x_client32: [u8; 32],
    pub client_public_key33: [u8; 33],
    pub mapped_client_share32: [u8; 32],
}

impl fmt::Debug for ClientRoleShareV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientRoleShareV1")
            .field("context_bytes_len", &self.context_bytes.len())
            .field("context_binding32", &self.context_binding32)
            .field("retry_counter", &self.retry_counter)
            .field("x_client32", &"<redacted>")
            .field("client_public_key33", &self.client_public_key33)
            .field("mapped_client_share32", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RelayerRoleShareV1 {
    #[zeroize(skip)]
    pub context_bytes: Vec<u8>,
    pub context_binding32: [u8; 32],
    pub retry_counter: u32,
    pub x_relayer32: [u8; 32],
    pub relayer_public_key33: [u8; 33],
    pub mapped_relayer_share32: [u8; 32],
}

impl fmt::Debug for RelayerRoleShareV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayerRoleShareV1")
            .field("context_bytes_len", &self.context_bytes.len())
            .field("context_binding32", &self.context_binding32)
            .field("retry_counter", &self.retry_counter)
            .field("x_relayer32", &"<redacted>")
            .field("relayer_public_key33", &self.relayer_public_key33)
            .field("mapped_relayer_share32", &"<redacted>")
            .finish()
    }
}

pub fn context_binding_v1(context: &EcdsaHssStableKeyContextV1) -> CoreResult<[u8; 32]> {
    let context_bytes = encode_context_v1(context)?;
    context_binding_from_bytes_v1(&context_bytes)
}

pub fn derive_client_share_v1(
    context: &EcdsaHssStableKeyContextV1,
    y_client32_le: [u8; 32],
) -> CoreResult<ClientRoleShareV1> {
    let context_bytes = encode_context_v1(context)?;
    let context_binding32 = context_binding_from_bytes_v1(&context_bytes)?;
    let (x_client32, retry_counter) = derive_role_share32(
        CLIENT_SHARE_DOMAIN,
        &context_bytes,
        &context_binding32,
        y_client32_le,
        0,
    )?;
    let client_public_key33 = private_key_to_public_key33(&x_client32, "client role public key")?;
    let mapped_client_share32 = vec_to_fixed_32(
        map_additive_share_to_threshold_signatures_share_2p(
            &x_client32,
            THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID,
        )?,
        "mapped client share",
    )?;

    Ok(ClientRoleShareV1 {
        context_bytes,
        context_binding32,
        retry_counter,
        x_client32,
        client_public_key33,
        mapped_client_share32,
    })
}

pub fn derive_relayer_share_v1(
    context: &EcdsaHssStableKeyContextV1,
    y_relayer32_le: [u8; 32],
) -> CoreResult<RelayerRoleShareV1> {
    derive_relayer_share_with_retry_v1(context, y_relayer32_le, 0)
}

pub fn derive_relayer_share_for_client_public_v1(
    context: &EcdsaHssStableKeyContextV1,
    y_relayer32_le: [u8; 32],
    client_public_key33: &[u8; 33],
    client_share_retry_counter: u32,
) -> CoreResult<(RelayerRoleShareV1, PublicIdentityV1)> {
    let client_public_key33 = validate_public_key33(client_public_key33, "client public key")?;
    let mut relayer_share_retry_counter = 0u32;

    loop {
        let relayer_share = derive_relayer_share_with_retry_v1(
            context,
            y_relayer32_le,
            relayer_share_retry_counter,
        )?;
        let identity = match compose_public_identity_v1(
            context,
            &client_public_key33,
            client_share_retry_counter,
            &relayer_share,
        ) {
            Ok(identity) => identity,
            Err(err) if is_identity_public_key_sum_error(&err) => {
                relayer_share_retry_counter = relayer_share_retry_counter
                    .checked_add(1)
                    .ok_or_else(|| SignerCoreError::internal("relayer retry counter overflow"))?;
                continue;
            }
            Err(err) => return Err(err),
        };
        return Ok((relayer_share, identity));
    }
}

pub fn compose_public_identity_v1(
    context: &EcdsaHssStableKeyContextV1,
    client_public_key33: &[u8; 33],
    client_share_retry_counter: u32,
    relayer_share: &RelayerRoleShareV1,
) -> CoreResult<PublicIdentityV1> {
    let context_bytes = encode_context_v1(context)?;
    let context_binding32 = context_binding_from_bytes_v1(&context_bytes)?;
    if context_binding32 != relayer_share.context_binding32 {
        return Err(SignerCoreError::invalid_input(
            "relayer share context binding does not match context",
        ));
    }

    let client_public_key33 = validate_public_key33(client_public_key33, "client public key")?;
    let relayer_public_key33 =
        validate_public_key33(&relayer_share.relayer_public_key33, "relayer public key")?;
    let threshold_public_key33 = add_public_keys_non_identity_33(
        &client_public_key33,
        &relayer_public_key33,
        "threshold public key",
    )?;
    let threshold_ethereum_address20 = vec_to_fixed_20(
        secp256k1_public_key_33_to_ethereum_address_20(&threshold_public_key33)?,
        "threshold ethereum address",
    )?;

    Ok(PublicIdentityV1 {
        context_bytes,
        context_binding32,
        client_public_key33,
        relayer_public_key33,
        threshold_public_key33,
        threshold_ethereum_address20,
        client_share_retry_counter,
        relayer_share_retry_counter: relayer_share.retry_counter,
    })
}

pub fn reconstruct_export_key_v1(
    client_share: &ClientRoleShareV1,
    relayer_export_share32: &[u8; 32],
    identity: &PublicIdentityV1,
) -> CoreResult<[u8; 32]> {
    if client_share.context_binding32 != identity.context_binding32 {
        return Err(SignerCoreError::invalid_input(
            "client share context binding does not match public identity",
        ));
    }
    if client_share.retry_counter != identity.client_share_retry_counter {
        return Err(SignerCoreError::invalid_input(
            "client share retry counter does not match public identity",
        ));
    }
    if client_share.client_public_key33 != identity.client_public_key33 {
        return Err(SignerCoreError::invalid_input(
            "client public key does not match public identity",
        ));
    }

    let x_client = parse_nonzero_scalar_32_be(&client_share.x_client32, "x_client32")?;
    let x_relayer = parse_nonzero_scalar_32_be(relayer_export_share32, "relayer_export_share32")?;
    let x_export =
        Option::<NonZeroScalar>::from(NonZeroScalar::new(*x_client.as_ref() + *x_relayer.as_ref()))
            .ok_or_else(|| SignerCoreError::invalid_input("export key reconstructed to zero"))?;
    let x_export32 = nonzero_scalar_to_32_be(&x_export);

    let public_key33 = private_key_to_public_key33(&x_export32, "export public key")?;
    if public_key33 != identity.threshold_public_key33 {
        return Err(SignerCoreError::invalid_input(
            "export public key does not match threshold public key",
        ));
    }
    let address20 = vec_to_fixed_20(
        secp256k1_public_key_33_to_ethereum_address_20(&public_key33)?,
        "export ethereum address",
    )?;
    if address20 != identity.threshold_ethereum_address20 {
        return Err(SignerCoreError::invalid_input(
            "export ethereum address does not match threshold address",
        ));
    }

    Ok(x_export32)
}

pub fn public_transcript_digest_v1(
    operation: ServerEvalOperationV1,
    identity: &PublicIdentityV1,
) -> CoreResult<[u8; 32]> {
    let operation_kind = [operation_kind_byte_v1(operation)];
    let client_share_retry_counter = identity.client_share_retry_counter.to_be_bytes();
    let relayer_share_retry_counter = identity.relayer_share_retry_counter.to_be_bytes();
    let frame = frame_digest_input(
        PUBLIC_TRANSCRIPT_DOMAIN,
        &[
            (FIELD_CONTEXT_BINDING, identity.context_binding32.as_slice()),
            (FIELD_TRANSCRIPT_OPERATION, operation_kind.as_slice()),
            (
                FIELD_CLIENT_PUBLIC_KEY,
                identity.client_public_key33.as_slice(),
            ),
            (
                FIELD_RELAYER_PUBLIC_KEY,
                identity.relayer_public_key33.as_slice(),
            ),
            (
                FIELD_THRESHOLD_PUBLIC_KEY,
                identity.threshold_public_key33.as_slice(),
            ),
            (
                FIELD_THRESHOLD_ETHEREUM_ADDRESS,
                identity.threshold_ethereum_address20.as_slice(),
            ),
            (
                FIELD_CLIENT_SHARE_RETRY_COUNTER,
                client_share_retry_counter.as_slice(),
            ),
            (
                FIELD_RELAYER_SHARE_RETRY_COUNTER,
                relayer_share_retry_counter.as_slice(),
            ),
        ],
    )?;
    let mut hasher = Sha256::new();
    hasher.update(frame);
    Ok(hasher.finalize().into())
}

pub fn export_authorization_digest_v1(
    operation: ServerEvalOperationV1,
    identity: &PublicIdentityV1,
    authorization: &ExplicitExportAuthorizationV1,
) -> CoreResult<[u8; 32]> {
    let public_transcript_digest32 = public_transcript_digest_v1(operation, identity)?;
    let issued_at_unix_ms = authorization.issued_at_unix_ms.to_be_bytes();
    let expires_at_unix_ms = authorization.expires_at_unix_ms.to_be_bytes();
    let frame = frame_digest_input(
        EXPORT_AUTHORIZATION_DOMAIN,
        &[
            (
                FIELD_EXPORT_PUBLIC_TRANSCRIPT_DIGEST,
                public_transcript_digest32.as_slice(),
            ),
            (FIELD_CONTEXT_BINDING, identity.context_binding32.as_slice()),
            (
                FIELD_CLIENT_PUBLIC_KEY,
                identity.client_public_key33.as_slice(),
            ),
            (
                FIELD_RELAYER_PUBLIC_KEY,
                identity.relayer_public_key33.as_slice(),
            ),
            (
                FIELD_THRESHOLD_PUBLIC_KEY,
                identity.threshold_public_key33.as_slice(),
            ),
            (
                FIELD_THRESHOLD_ETHEREUM_ADDRESS,
                identity.threshold_ethereum_address20.as_slice(),
            ),
            (
                FIELD_EXPORT_WALLET_SESSION_USER_ID,
                authorization.wallet_session_user_id.as_bytes(),
            ),
            (
                FIELD_EXPORT_ECDSA_THRESHOLD_KEY_ID,
                authorization.ecdsa_threshold_key_id.as_bytes(),
            ),
            (
                FIELD_EXPORT_CLIENT_DEVICE_ID,
                authorization.client_device_id.as_bytes(),
            ),
            (
                FIELD_EXPORT_CLIENT_SESSION_ID,
                authorization.client_session_id.as_bytes(),
            ),
            (
                FIELD_EXPORT_RELAYER_KEY_ID,
                authorization.relayer_key_id.as_bytes(),
            ),
            (
                FIELD_EXPORT_REQUEST_NONCE,
                authorization.export_request_nonce32.as_slice(),
            ),
            (
                FIELD_EXPORT_CONFIRMATION_DIGEST,
                authorization.confirmation_digest32.as_slice(),
            ),
            (FIELD_EXPORT_ISSUED_AT_UNIX_MS, issued_at_unix_ms.as_slice()),
            (
                FIELD_EXPORT_EXPIRES_AT_UNIX_MS,
                expires_at_unix_ms.as_slice(),
            ),
        ],
    )?;
    let mut hasher = Sha256::new();
    hasher.update(frame);
    Ok(hasher.finalize().into())
}

fn derive_relayer_share_with_retry_v1(
    context: &EcdsaHssStableKeyContextV1,
    y_relayer32_le: [u8; 32],
    retry_counter: u32,
) -> CoreResult<RelayerRoleShareV1> {
    let context_bytes = encode_context_v1(context)?;
    let context_binding32 = context_binding_from_bytes_v1(&context_bytes)?;
    let (x_relayer32, retry_counter) = derive_role_share32(
        RELAYER_SHARE_DOMAIN,
        &context_bytes,
        &context_binding32,
        y_relayer32_le,
        retry_counter,
    )?;
    let relayer_public_key33 =
        private_key_to_public_key33(&x_relayer32, "relayer role public key")?;
    let mapped_relayer_share32 = vec_to_fixed_32(
        map_additive_share_to_threshold_signatures_share_2p(
            &x_relayer32,
            THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID,
        )?,
        "mapped relayer share",
    )?;

    Ok(RelayerRoleShareV1 {
        context_bytes,
        context_binding32,
        retry_counter,
        x_relayer32,
        relayer_public_key33,
        mapped_relayer_share32,
    })
}

fn derive_role_share32(
    role_domain: &[u8],
    context_bytes: &[u8],
    context_binding32: &[u8; 32],
    y_role32_le: [u8; 32],
    retry_counter: u32,
) -> CoreResult<([u8; 32], u32)> {
    let retry_counter_bytes = retry_counter.to_be_bytes();
    let frame = frame_digest_input(
        role_domain,
        &[
            (FIELD_CONTEXT_BINDING, context_binding32.as_slice()),
            (FIELD_ROLE_CONTEXT_BYTES, context_bytes),
            (FIELD_ROLE_ROOT, y_role32_le.as_slice()),
            (FIELD_ROLE_RETRY_COUNTER, retry_counter_bytes.as_slice()),
        ],
    )?;

    let mut hasher = Sha512::new();
    hasher.update(frame);
    let mut digest64: [u8; 64] = hasher.finalize().into();
    let scalar = reduce_sha512_digest_to_nonzero_scalar(&digest64);
    digest64.zeroize();
    Ok((nonzero_scalar_to_32_be(&scalar), retry_counter))
}

fn context_binding_from_bytes_v1(context_bytes: &[u8]) -> CoreResult<[u8; 32]> {
    let frame = frame_digest_input(
        CONTEXT_BINDING_DOMAIN,
        &[(FIELD_CONTEXT_BYTES, context_bytes)],
    )?;
    let mut hasher = Sha256::new();
    hasher.update(frame);
    Ok(hasher.finalize().into())
}

fn operation_kind_byte_v1(operation: ServerEvalOperationV1) -> u8 {
    match operation {
        ServerEvalOperationV1::RegistrationBootstrap => 0x01,
        ServerEvalOperationV1::SessionBootstrap => 0x02,
        ServerEvalOperationV1::NonExportSign => 0x03,
        ServerEvalOperationV1::ExplicitKeyExport => 0x04,
    }
}

fn frame_digest_input(domain: &[u8], fields: &[(u8, &[u8])]) -> CoreResult<Vec<u8>> {
    if fields.len() > usize::from(u8::MAX) {
        return Err(SignerCoreError::invalid_length(
            "digest frame field count exceeds u8 range",
        ));
    }

    let mut out = Vec::new();
    out.extend_from_slice(domain);
    out.push(fields.len() as u8);
    for (tag, value) in fields {
        let len = u16::try_from(value.len()).map_err(|_| {
            SignerCoreError::invalid_length("digest frame field exceeds u16 length")
        })?;
        out.push(*tag);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(value);
    }
    Ok(out)
}

fn parse_nonzero_scalar_32_be(bytes: &[u8], field_name: &str) -> CoreResult<NonZeroScalar> {
    if bytes.len() != 32 {
        return Err(SignerCoreError::invalid_length(format!(
            "{field_name} must be 32 bytes (got {})",
            bytes.len()
        )));
    }
    SecretKey::from_slice(bytes)
        .map(|secret_key| secret_key.to_nonzero_scalar())
        .map_err(|_| SignerCoreError::invalid_input(format!("{field_name} must be in (0, n)")))
}

fn reduce_sha512_digest_to_nonzero_scalar(digest64: &[u8; 64]) -> NonZeroScalar {
    let mut wide = WideBytes::default();
    wide.copy_from_slice(digest64);
    <NonZeroScalar as Reduce<U512>>::reduce_bytes(&wide)
}

fn nonzero_scalar_to_32_be(scalar: &NonZeroScalar) -> [u8; 32] {
    field_bytes_to_array32(&FieldBytes::from(scalar))
}

fn field_bytes_to_array32(bytes: &FieldBytes) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes.as_ref());
    out
}

fn private_key_to_public_key33(private_key32: &[u8; 32], field_name: &str) -> CoreResult<[u8; 33]> {
    vec_to_fixed_33(
        secp256k1_private_key_32_to_public_key_33(private_key32)?,
        field_name,
    )
}

fn validate_public_key33(public_key33: &[u8; 33], field_name: &str) -> CoreResult<[u8; 33]> {
    vec_to_fixed_33(validate_secp256k1_public_key_33(public_key33)?, field_name)
}

fn add_public_keys_non_identity_33(
    left33: &[u8; 33],
    right33: &[u8; 33],
    field_name: &str,
) -> CoreResult<[u8; 33]> {
    if public_key_sum_is_identity(left33, right33)? {
        return Err(SignerCoreError::invalid_input(format!(
            "{field_name} must not be the identity point"
        )));
    }
    vec_to_fixed_33(add_secp256k1_public_keys_33(left33, right33)?, field_name)
}

fn public_key_sum_is_identity(left33: &[u8; 33], right33: &[u8; 33]) -> CoreResult<bool> {
    let left = PublicKey::from_sec1_bytes(left33)
        .map_err(|_| SignerCoreError::decode_error("left public key is invalid"))?;
    let right = PublicKey::from_sec1_bytes(right33)
        .map_err(|_| SignerCoreError::decode_error("right public key is invalid"))?;
    let sum = ProjectivePoint::from(*left.as_affine()) + ProjectivePoint::from(*right.as_affine());
    Ok(bool::from(sum.is_identity()))
}

fn is_identity_public_key_sum_error(err: &SignerCoreError) -> bool {
    err.message.contains("identity point")
}

fn vec_to_fixed_20(bytes: Vec<u8>, field_name: &str) -> CoreResult<[u8; 20]> {
    if bytes.len() != 20 {
        return Err(SignerCoreError::invalid_length(format!(
            "{field_name} must be 20 bytes (got {})",
            bytes.len()
        )));
    }
    bytes.try_into().map_err(|_| {
        SignerCoreError::invalid_length(format!("{field_name} must be exactly 20 bytes"))
    })
}

fn vec_to_fixed_32(bytes: Vec<u8>, field_name: &str) -> CoreResult<[u8; 32]> {
    if bytes.len() != 32 {
        return Err(SignerCoreError::invalid_length(format!(
            "{field_name} must be 32 bytes (got {})",
            bytes.len()
        )));
    }
    bytes.try_into().map_err(|_| {
        SignerCoreError::invalid_length(format!("{field_name} must be exactly 32 bytes"))
    })
}

fn vec_to_fixed_33(bytes: Vec<u8>, field_name: &str) -> CoreResult<[u8; 33]> {
    if bytes.len() != 33 {
        return Err(SignerCoreError::invalid_length(format!(
            "{field_name} must be 33 bytes (got {})",
            bytes.len()
        )));
    }
    bytes.try_into().map_err(|_| {
        SignerCoreError::invalid_length(format!("{field_name} must be exactly 33 bytes"))
    })
}
