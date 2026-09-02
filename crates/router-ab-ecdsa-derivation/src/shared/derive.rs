use crate::error::{RouterAbEcdsaDerivationError, RouterAbEcdsaDerivationResult};
use crate::shared::secp256k1::{
    add_secp256k1_public_keys_33, secp256k1_private_key_32_to_public_key_33,
    secp256k1_public_key_33_to_ethereum_address_20, validate_secp256k1_public_key_33,
};
use core::fmt;
use k256::elliptic_curve::bigint::U512;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::Group;
use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, NonZeroScalar, ProjectivePoint, PublicKey, Scalar, WideBytes};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::context::{encode_context, RouterAbEcdsaDerivationStableKeyContext};
use crate::wire::ServerEvalOperation;

const CONTEXT_BINDING_DOMAIN: &[u8] = b"router-ab-ecdsa-derivation/role-local/context-binding/v1";
const CLIENT_SHARE_DOMAIN: &[u8] = b"router-ab-ecdsa-derivation/role-local/client-share/v1";
const RELAYER_SHARE_DOMAIN: &[u8] = b"router-ab-ecdsa-derivation/role-local/relayer-share/v1";
const PUBLIC_TRANSCRIPT_DOMAIN: &[u8] =
    b"router-ab-ecdsa-derivation/role-local/public-transcript/v1";

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicIdentity {
    pub context_bytes: Vec<u8>,
    pub context_binding32: [u8; 32],
    pub derivation_client_share_public_key33: [u8; 33],
    pub relayer_public_key33: [u8; 33],
    pub threshold_public_key33: [u8; 33],
    pub threshold_ethereum_address20: [u8; 20],
    pub client_share_retry_counter: u32,
    pub relayer_share_retry_counter: u32,
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ClientRoleShare {
    #[zeroize(skip)]
    pub context_bytes: Vec<u8>,
    pub context_binding32: [u8; 32],
    pub retry_counter: u32,
    pub x_client32: [u8; 32],
    pub derivation_client_share_public_key33: [u8; 33],
}

impl fmt::Debug for ClientRoleShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientRoleShare")
            .field("context_bytes_len", &self.context_bytes.len())
            .field("context_binding32", &self.context_binding32)
            .field("retry_counter", &self.retry_counter)
            .field("x_client32", &"<redacted>")
            .field(
                "derivation_client_share_public_key33",
                &self.derivation_client_share_public_key33,
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RelayerRoleShare {
    #[zeroize(skip)]
    pub context_bytes: Vec<u8>,
    pub context_binding32: [u8; 32],
    pub retry_counter: u32,
    pub x_relayer32: [u8; 32],
    pub relayer_public_key33: [u8; 33],
}

/// A freshly sampled target client share for an additive ECDSA lane.
///
/// The scalar is held only by the caller's isolated client boundary. It is
/// intentionally separate from [`ClientRoleShare`], whose retry metadata is
/// tied to deterministic role derivation.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EcdsaLaneClientShare {
    x_client32: [u8; 32],
    #[zeroize(skip)]
    public_key33: [u8; 33],
}

impl fmt::Debug for EcdsaLaneClientShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaLaneClientShare")
            .field("x_client32", &"<redacted>")
            .field("public_key33", &self.public_key33)
            .finish()
    }
}

impl EcdsaLaneClientShare {
    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.x_client32
    }

    pub fn public_key33(&self) -> &[u8; 33] {
        &self.public_key33
    }
}

/// The transient additive delta sent from the holder to the SigningWorker.
///
/// Zero is valid: a random target share can equal the source share. The
/// server still rejects a zero resulting relayer share, preserving the
/// non-zero role-share invariant.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EcdsaLaneDelta {
    delta32: [u8; 32],
}

impl fmt::Debug for EcdsaLaneDelta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaLaneDelta")
            .field("delta32", &"<redacted>")
            .finish()
    }
}

impl EcdsaLaneDelta {
    pub fn from_bytes(delta32: [u8; 32]) -> RouterAbEcdsaDerivationResult<Self> {
        let delta32 = Zeroizing::new(delta32);
        parse_scalar_32_be(delta32.as_slice(), "delta32")?;
        Ok(Self { delta32: *delta32 })
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.delta32
    }
}

impl fmt::Debug for RelayerRoleShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayerRoleShare")
            .field("context_bytes_len", &self.context_bytes.len())
            .field("context_binding32", &self.context_binding32)
            .field("retry_counter", &self.retry_counter)
            .field("x_relayer32", &"<redacted>")
            .field("relayer_public_key33", &self.relayer_public_key33)
            .finish()
    }
}

pub fn context_binding(
    context: &RouterAbEcdsaDerivationStableKeyContext,
) -> RouterAbEcdsaDerivationResult<[u8; 32]> {
    let context_bytes = encode_context(context)?;
    context_binding_from_bytes(&context_bytes)
}

pub fn derive_client_share(
    context: &RouterAbEcdsaDerivationStableKeyContext,
    y_client32_le: [u8; 32],
) -> RouterAbEcdsaDerivationResult<ClientRoleShare> {
    let context_bytes = encode_context(context)?;
    let context_binding32 = context_binding_from_bytes(&context_bytes)?;
    derive_client_share_from_context_bytes(
        CLIENT_SHARE_DOMAIN,
        context_bytes,
        context_binding32,
        y_client32_le,
    )
}

/// Parse one CSPRNG block as a uniformly sampled target client share.
///
/// Callers must retry with a fresh block when this returns an error. Rejection
/// of non-canonical and zero values avoids modulo bias and keeps every target
/// role share in the non-zero scalar domain.
pub fn sample_ecdsa_lane_client_share_v1(
    randomness32: [u8; 32],
) -> RouterAbEcdsaDerivationResult<EcdsaLaneClientShare> {
    let randomness32 = Zeroizing::new(randomness32);
    let scalar = parse_scalar_32_be(randomness32.as_slice(), "target client share")?;
    if bool::from(scalar.is_zero()) {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "target client share must be non-zero",
        ));
    }

    let x_client32 = field_bytes_to_array32(&scalar.to_repr());
    let public_key33 = private_key_to_public_key33(&x_client32, "target client public key")?;
    Ok(EcdsaLaneClientShare {
        x_client32,
        public_key33,
    })
}

/// Derives the compressed public commitment for one role-local client share.
///
/// The scalar is consumed and zeroized so callers can bind an opened ready
/// state to an immutable lane job without exporting the scalar further.
pub fn ecdsa_lane_client_public_key_from_share32_v1(
    client_share32: [u8; 32],
) -> RouterAbEcdsaDerivationResult<[u8; 33]> {
    let client_share32 = Zeroizing::new(client_share32);
    parse_nonzero_scalar_32_be(client_share32.as_ref(), "client share")?;
    private_key_to_public_key33(&client_share32, "client public key")
}

/// Compute the transient holder-to-relayer delta for a target client share.
pub fn derive_ecdsa_lane_delta_v1(
    source_client_share: &ClientRoleShare,
    target_client_share: &EcdsaLaneClientShare,
) -> RouterAbEcdsaDerivationResult<EcdsaLaneDelta> {
    let x_client_source =
        parse_nonzero_scalar_32_be(&source_client_share.x_client32, "source client share")?;
    let x_client_target =
        parse_nonzero_scalar_32_be(target_client_share.secret_bytes(), "target client share")?;
    let delta = *x_client_source.as_ref() - *x_client_target.as_ref();
    EcdsaLaneDelta::from_bytes(field_bytes_to_array32(&delta.to_repr()))
}

/// Computes the transient additive delta from an already-opened client share.
///
/// This boundary is used by the browser lane ceremony after the signer-core
/// ready-state parser has opened the holder material. The source scalar is
/// consumed by the call and never appears in a protocol record.
pub fn derive_ecdsa_lane_delta_from_source_share32_v1(
    source_client_share32: [u8; 32],
    target_client_share: &EcdsaLaneClientShare,
) -> RouterAbEcdsaDerivationResult<EcdsaLaneDelta> {
    let source_client_share32 = Zeroizing::new(source_client_share32);
    let source_client =
        parse_nonzero_scalar_32_be(source_client_share32.as_ref(), "source client share")?;
    let target_client =
        parse_nonzero_scalar_32_be(target_client_share.secret_bytes(), "target client share")?;
    let delta = *source_client.as_ref() - *target_client.as_ref();
    EcdsaLaneDelta::from_bytes(field_bytes_to_array32(&delta.to_repr()))
}

/// Public facts required to rebind one relayer share without loading a
/// mutable lane record. Every point is checked before a target scalar is
/// returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaLanePublicIdentityBindingV1 {
    /// Source client verifying share.
    pub source_client_public_key33: [u8; 33],
    /// Source relayer verifying share.
    pub source_relayer_public_key33: [u8; 33],
    /// Source threshold public key.
    pub threshold_public_key33: [u8; 33],
    /// Source EVM address.
    pub threshold_ethereum_address20: [u8; 20],
}

/// Target relayer material produced by an additive lane rebind.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EcdsaLaneRelayerRebindV1 {
    /// Target relayer scalar. It is never serialized by the protocol layer.
    target_relayer_share32: [u8; 32],
    /// Target relayer verifying share.
    #[zeroize(skip)]
    pub target_relayer_public_key33: [u8; 33],
    /// Public target client verifying share used by the relation check.
    #[zeroize(skip)]
    pub target_client_public_key33: [u8; 33],
    /// Public target threshold key.
    #[zeroize(skip)]
    pub target_threshold_public_key33: [u8; 33],
    /// Target EVM address.
    #[zeroize(skip)]
    pub target_ethereum_address20: [u8; 20],
}

impl EcdsaLaneRelayerRebindV1 {
    /// Consumes the rebind result at the SigningWorker sealing boundary.
    ///
    /// The scalar has no public-record representation and is unavailable once
    /// this one-shot extraction has been handed to the sealing primitive.
    pub fn into_target_relayer_share32(self) -> [u8; 32] {
        let Self {
            target_relayer_share32,
            target_relayer_public_key33: _,
            target_client_public_key33: _,
            target_threshold_public_key33: _,
            target_ethereum_address20: _,
        } = self;
        target_relayer_share32
    }
}

impl fmt::Debug for EcdsaLaneRelayerRebindV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaLaneRelayerRebindV1")
            .field("target_relayer_share32", &"<redacted>")
            .field(
                "target_relayer_public_key33",
                &self.target_relayer_public_key33,
            )
            .field(
                "target_client_public_key33",
                &self.target_client_public_key33,
            )
            .field(
                "target_threshold_public_key33",
                &self.target_threshold_public_key33,
            )
            .field("target_ethereum_address20", &self.target_ethereum_address20)
            .finish()
    }
}

/// Rebinds a relayer scalar from public source facts and a transient delta.
///
/// This is the SigningWorker-side primitive. It does not accept or return a
/// holder scalar and fails closed when either source or target relation is
/// inconsistent with the threshold key or EVM address.
pub fn rebind_ecdsa_lane_relayer_share_bytes_v1(
    source_relayer_share32: [u8; 32],
    source_identity: &EcdsaLanePublicIdentityBindingV1,
    delta: &EcdsaLaneDelta,
    target_client_public_key33: [u8; 33],
) -> RouterAbEcdsaDerivationResult<EcdsaLaneRelayerRebindV1> {
    let source_relayer_share32 = Zeroizing::new(source_relayer_share32);
    let source_client_public_key33 = validate_public_key33(
        &source_identity.source_client_public_key33,
        "source client public key",
    )?;
    let source_relayer_public_key33 = validate_public_key33(
        &source_identity.source_relayer_public_key33,
        "source relayer public key",
    )?;
    let source_threshold_public_key33 = validate_public_key33(
        &source_identity.threshold_public_key33,
        "source threshold public key",
    )?;
    let expected_source_threshold = add_public_keys_non_identity_33(
        &source_client_public_key33,
        &source_relayer_public_key33,
        "source threshold public key",
    )?;
    if expected_source_threshold != source_threshold_public_key33 {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "source threshold public key is inconsistent",
        ));
    }
    let source_address = vec_to_fixed_20(
        secp256k1_public_key_33_to_ethereum_address_20(&source_threshold_public_key33)?,
        "source threshold ethereum address",
    )?;
    if source_address != source_identity.threshold_ethereum_address20 {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "source threshold ethereum address is inconsistent",
        ));
    }

    let source_relayer_scalar =
        parse_nonzero_scalar_32_be(source_relayer_share32.as_ref(), "source relayer share")?;
    let source_relayer_public_from_scalar =
        private_key_to_public_key33(&source_relayer_share32, "source relayer public key")?;
    if source_relayer_public_from_scalar != source_relayer_public_key33 {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "source relayer share public key is inconsistent",
        ));
    }

    let target_client_public_key33 =
        validate_public_key33(&target_client_public_key33, "target client public key")?;
    let delta_scalar = parse_scalar_32_be(delta.as_bytes(), "delta32")?;
    let source_client_point =
        PublicKey::from_sec1_bytes(&source_client_public_key33).map_err(|_| {
            RouterAbEcdsaDerivationError::decode_error("source client public key is invalid")
        })?;
    let expected_target_client =
        target_client_public_key_from_delta(&source_client_point, &delta_scalar)?;
    if expected_target_client != target_client_public_key33 {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "target client public key does not match source client public key and delta",
        ));
    }

    let target_relayer_scalar = *source_relayer_scalar.as_ref() + delta_scalar;
    let target_relayer_scalar = Option::<NonZeroScalar>::from(NonZeroScalar::new(
        target_relayer_scalar,
    ))
    .ok_or_else(|| {
        RouterAbEcdsaDerivationError::invalid_input(
            "target relayer share must remain a non-zero scalar",
        )
    })?;
    let target_relayer_share32 = nonzero_scalar_to_32_be(&target_relayer_scalar);
    let target_relayer_public_key33 =
        private_key_to_public_key33(&target_relayer_share32, "target relayer public key")?;
    let target_threshold_public_key33 = add_public_keys_non_identity_33(
        &target_client_public_key33,
        &target_relayer_public_key33,
        "target threshold public key",
    )?;
    if target_threshold_public_key33 != source_threshold_public_key33 {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "target threshold public key does not preserve source identity",
        ));
    }
    let target_ethereum_address20 = vec_to_fixed_20(
        secp256k1_public_key_33_to_ethereum_address_20(&target_threshold_public_key33)?,
        "target threshold ethereum address",
    )?;
    if target_ethereum_address20 != source_identity.threshold_ethereum_address20 {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "target threshold ethereum address does not preserve source identity",
        ));
    }

    Ok(EcdsaLaneRelayerRebindV1 {
        target_relayer_share32,
        target_relayer_public_key33,
        target_client_public_key33,
        target_threshold_public_key33,
        target_ethereum_address20,
    })
}

pub fn derive_relayer_share(
    context: &RouterAbEcdsaDerivationStableKeyContext,
    y_relayer32_le: [u8; 32],
) -> RouterAbEcdsaDerivationResult<RelayerRoleShare> {
    derive_relayer_share_with_retry(context, y_relayer32_le, 0)
}

pub fn derive_relayer_share_for_client_public(
    context: &RouterAbEcdsaDerivationStableKeyContext,
    y_relayer32_le: [u8; 32],
    derivation_client_share_public_key33: &[u8; 33],
    client_share_retry_counter: u32,
) -> RouterAbEcdsaDerivationResult<(RelayerRoleShare, PublicIdentity)> {
    let derivation_client_share_public_key33 =
        validate_public_key33(derivation_client_share_public_key33, "client public key")?;
    let mut relayer_share_retry_counter = 0u32;

    loop {
        let relayer_share =
            derive_relayer_share_with_retry(context, y_relayer32_le, relayer_share_retry_counter)?;
        let identity = match compose_public_identity(
            context,
            &derivation_client_share_public_key33,
            client_share_retry_counter,
            &relayer_share,
        ) {
            Ok(identity) => identity,
            Err(err) if is_identity_public_key_sum_error(&err) => {
                relayer_share_retry_counter =
                    relayer_share_retry_counter.checked_add(1).ok_or_else(|| {
                        RouterAbEcdsaDerivationError::internal("relayer retry counter overflow")
                    })?;
                continue;
            }
            Err(err) => return Err(err),
        };
        return Ok((relayer_share, identity));
    }
}

/// Rebind the relayer share for an additive target lane.
///
/// The source identity and target client public commitment are checked before
/// the target relayer material is returned. The resulting public identity is
/// guaranteed to retain the source threshold public key and EVM address.
pub fn rebind_ecdsa_lane_relayer_share_v1(
    source_relayer_share: &RelayerRoleShare,
    source_identity: &PublicIdentity,
    delta: &EcdsaLaneDelta,
    target_client_public_key33: &[u8; 33],
    target_client_share_retry_counter: u32,
    target_relayer_share_retry_counter: u32,
) -> RouterAbEcdsaDerivationResult<(RelayerRoleShare, PublicIdentity)> {
    validate_source_identity(source_relayer_share, source_identity)?;
    let target_client_public_key33 =
        validate_public_key33(target_client_public_key33, "target client public key")?;

    let delta_scalar = parse_scalar_32_be(delta.as_bytes(), "delta32")?;
    let source_client_public_key =
        PublicKey::from_sec1_bytes(&source_identity.derivation_client_share_public_key33).map_err(
            |_| RouterAbEcdsaDerivationError::decode_error("source client public key is invalid"),
        )?;
    let target_client_public_key =
        target_client_public_key_from_delta(&source_client_public_key, &delta_scalar)?;
    if target_client_public_key != target_client_public_key33 {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "target client public key does not match source client public key and delta",
        ));
    }

    let source_relayer_scalar =
        parse_nonzero_scalar_32_be(&source_relayer_share.x_relayer32, "source relayer share")?;
    let target_relayer_scalar = *source_relayer_scalar.as_ref() + delta_scalar;
    let target_relayer_scalar = Option::<NonZeroScalar>::from(NonZeroScalar::new(
        target_relayer_scalar,
    ))
    .ok_or_else(|| {
        RouterAbEcdsaDerivationError::invalid_input(
            "target relayer share must remain a non-zero scalar",
        )
    })?;
    let target_relayer32 = nonzero_scalar_to_32_be(&target_relayer_scalar);
    let target_relayer_public_key33 =
        private_key_to_public_key33(&target_relayer32, "target relayer public key")?;
    let target_relayer_share = RelayerRoleShare {
        context_bytes: source_relayer_share.context_bytes.clone(),
        context_binding32: source_relayer_share.context_binding32,
        retry_counter: target_relayer_share_retry_counter,
        x_relayer32: target_relayer32,
        relayer_public_key33: target_relayer_public_key33,
    };

    let target_identity = compose_public_identity_from_parts(
        source_identity.context_bytes.clone(),
        source_identity.context_binding32,
        &target_client_public_key33,
        target_client_share_retry_counter,
        &target_relayer_share,
    )?;
    if target_identity.threshold_public_key33 != source_identity.threshold_public_key33 {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "target threshold public key does not preserve source identity",
        ));
    }
    if target_identity.threshold_ethereum_address20 != source_identity.threshold_ethereum_address20
    {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "target threshold ethereum address does not preserve source identity",
        ));
    }

    Ok((target_relayer_share, target_identity))
}

pub fn compose_public_identity(
    context: &RouterAbEcdsaDerivationStableKeyContext,
    derivation_client_share_public_key33: &[u8; 33],
    client_share_retry_counter: u32,
    relayer_share: &RelayerRoleShare,
) -> RouterAbEcdsaDerivationResult<PublicIdentity> {
    let context_bytes = encode_context(context)?;
    let context_binding32 = context_binding_from_bytes(&context_bytes)?;
    compose_public_identity_from_parts(
        context_bytes,
        context_binding32,
        derivation_client_share_public_key33,
        client_share_retry_counter,
        relayer_share,
    )
}

pub fn compose_public_identity_from_public_keys(
    context: &RouterAbEcdsaDerivationStableKeyContext,
    derivation_client_share_public_key33: &[u8; 33],
    client_share_retry_counter: u32,
    relayer_public_key33: &[u8; 33],
    relayer_share_retry_counter: u32,
) -> RouterAbEcdsaDerivationResult<PublicIdentity> {
    let context_bytes = encode_context(context)?;
    let context_binding32 = context_binding_from_bytes(&context_bytes)?;
    let derivation_client_share_public_key33 =
        validate_public_key33(derivation_client_share_public_key33, "client public key")?;
    let relayer_public_key33 = validate_public_key33(relayer_public_key33, "relayer public key")?;
    let threshold_public_key33 = add_public_keys_non_identity_33(
        &derivation_client_share_public_key33,
        &relayer_public_key33,
        "threshold public key",
    )?;
    let threshold_ethereum_address20 = vec_to_fixed_20(
        secp256k1_public_key_33_to_ethereum_address_20(&threshold_public_key33)?,
        "threshold ethereum address",
    )?;

    Ok(PublicIdentity {
        context_bytes,
        context_binding32,
        derivation_client_share_public_key33,
        relayer_public_key33,
        threshold_public_key33,
        threshold_ethereum_address20,
        client_share_retry_counter,
        relayer_share_retry_counter,
    })
}

pub fn reconstruct_export_key(
    client_share: &ClientRoleShare,
    relayer_export_share32: &[u8; 32],
    identity: &PublicIdentity,
) -> RouterAbEcdsaDerivationResult<[u8; 32]> {
    if client_share.context_binding32 != identity.context_binding32 {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "client share context binding does not match public identity",
        ));
    }
    if client_share.retry_counter != identity.client_share_retry_counter {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "client share retry counter does not match public identity",
        ));
    }
    if client_share.derivation_client_share_public_key33
        != identity.derivation_client_share_public_key33
    {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "client public key does not match public identity",
        ));
    }

    let x_client = parse_nonzero_scalar_32_be(&client_share.x_client32, "x_client32")?;
    let x_relayer = parse_nonzero_scalar_32_be(relayer_export_share32, "relayer_export_share32")?;
    let x_export =
        Option::<NonZeroScalar>::from(NonZeroScalar::new(*x_client.as_ref() + *x_relayer.as_ref()))
            .ok_or_else(|| {
                RouterAbEcdsaDerivationError::invalid_input("export key reconstructed to zero")
            })?;
    let x_export32 = nonzero_scalar_to_32_be(&x_export);

    let public_key33 = private_key_to_public_key33(&x_export32, "export public key")?;
    if public_key33 != identity.threshold_public_key33 {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "export public key does not match threshold public key",
        ));
    }
    let address20 = vec_to_fixed_20(
        secp256k1_public_key_33_to_ethereum_address_20(&public_key33)?,
        "export ethereum address",
    )?;
    if address20 != identity.threshold_ethereum_address20 {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "export ethereum address does not match threshold address",
        ));
    }

    Ok(x_export32)
}

/// Reconstructs one additive-lane export key from the holder and
/// SigningWorker scalar shares.
///
/// The caller supplies the exact receipt-bound threshold public key and EVM
/// address. Both are checked after scalar addition so a valid share pair
/// cannot be redirected to another lane identity.
pub fn reconstruct_ecdsa_additive_export_key_v1(
    holder_share32: [u8; 32],
    signing_worker_share32: [u8; 32],
    expected_threshold_public_key33: [u8; 33],
    expected_ethereum_address20: [u8; 20],
) -> RouterAbEcdsaDerivationResult<[u8; 32]> {
    let holder_share32 = Zeroizing::new(holder_share32);
    let signing_worker_share32 = Zeroizing::new(signing_worker_share32);
    let holder = parse_nonzero_scalar_32_be(holder_share32.as_ref(), "holder_share32")?;
    let signing_worker =
        parse_nonzero_scalar_32_be(signing_worker_share32.as_ref(), "signing_worker_share32")?;
    let export = Option::<NonZeroScalar>::from(NonZeroScalar::new(
        *holder.as_ref() + *signing_worker.as_ref(),
    ))
    .ok_or_else(|| {
        RouterAbEcdsaDerivationError::invalid_input("additive export key reconstructed to zero")
    })?;
    let export32 = nonzero_scalar_to_32_be(&export);
    let public_key33 = private_key_to_public_key33(&export32, "additive export public key")?;
    if public_key33 != expected_threshold_public_key33 {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "additive export public key does not match threshold public key",
        ));
    }
    let ethereum_address20 = vec_to_fixed_20(
        secp256k1_public_key_33_to_ethereum_address_20(&public_key33)?,
        "additive export ethereum address",
    )?;
    if ethereum_address20 != expected_ethereum_address20 {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "additive export ethereum address does not match threshold address",
        ));
    }
    Ok(export32)
}

pub fn public_transcript_digest(
    operation: ServerEvalOperation,
    identity: &PublicIdentity,
) -> RouterAbEcdsaDerivationResult<[u8; 32]> {
    let operation_kind = [operation_kind_byte(operation)];
    let client_share_retry_counter = identity.client_share_retry_counter.to_be_bytes();
    let relayer_share_retry_counter = identity.relayer_share_retry_counter.to_be_bytes();
    let frame = frame_digest_input(
        PUBLIC_TRANSCRIPT_DOMAIN,
        &[
            (FIELD_CONTEXT_BINDING, identity.context_binding32.as_slice()),
            (FIELD_TRANSCRIPT_OPERATION, operation_kind.as_slice()),
            (
                FIELD_CLIENT_PUBLIC_KEY,
                identity.derivation_client_share_public_key33.as_slice(),
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

fn derive_relayer_share_with_retry(
    context: &RouterAbEcdsaDerivationStableKeyContext,
    y_relayer32_le: [u8; 32],
    retry_counter: u32,
) -> RouterAbEcdsaDerivationResult<RelayerRoleShare> {
    let context_bytes = encode_context(context)?;
    let context_binding32 = context_binding_from_bytes(&context_bytes)?;
    derive_relayer_share_from_context_bytes(
        RELAYER_SHARE_DOMAIN,
        context_bytes,
        context_binding32,
        y_relayer32_le,
        retry_counter,
    )
}

fn derive_client_share_from_context_bytes(
    role_domain: &[u8],
    context_bytes: Vec<u8>,
    context_binding32: [u8; 32],
    y_client32_le: [u8; 32],
) -> RouterAbEcdsaDerivationResult<ClientRoleShare> {
    let (x_client32, retry_counter) = derive_role_share32(
        role_domain,
        &context_bytes,
        &context_binding32,
        y_client32_le,
        0,
    )?;
    let derivation_client_share_public_key33 =
        private_key_to_public_key33(&x_client32, "client role public key")?;
    Ok(ClientRoleShare {
        context_bytes,
        context_binding32,
        retry_counter,
        x_client32,
        derivation_client_share_public_key33,
    })
}

fn derive_relayer_share_from_context_bytes(
    role_domain: &[u8],
    context_bytes: Vec<u8>,
    context_binding32: [u8; 32],
    y_relayer32_le: [u8; 32],
    retry_counter: u32,
) -> RouterAbEcdsaDerivationResult<RelayerRoleShare> {
    let (x_relayer32, retry_counter) = derive_role_share32(
        role_domain,
        &context_bytes,
        &context_binding32,
        y_relayer32_le,
        retry_counter,
    )?;
    let relayer_public_key33 =
        private_key_to_public_key33(&x_relayer32, "relayer role public key")?;
    Ok(RelayerRoleShare {
        context_bytes,
        context_binding32,
        retry_counter,
        x_relayer32,
        relayer_public_key33,
    })
}

fn compose_public_identity_from_parts(
    context_bytes: Vec<u8>,
    context_binding32: [u8; 32],
    derivation_client_share_public_key33: &[u8; 33],
    client_share_retry_counter: u32,
    relayer_share: &RelayerRoleShare,
) -> RouterAbEcdsaDerivationResult<PublicIdentity> {
    if context_binding32 != relayer_share.context_binding32 {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "relayer share context binding does not match context",
        ));
    }

    let derivation_client_share_public_key33 =
        validate_public_key33(derivation_client_share_public_key33, "client public key")?;
    let relayer_public_key33 =
        validate_public_key33(&relayer_share.relayer_public_key33, "relayer public key")?;
    let threshold_public_key33 = add_public_keys_non_identity_33(
        &derivation_client_share_public_key33,
        &relayer_public_key33,
        "threshold public key",
    )?;
    let threshold_ethereum_address20 = vec_to_fixed_20(
        secp256k1_public_key_33_to_ethereum_address_20(&threshold_public_key33)?,
        "threshold ethereum address",
    )?;

    Ok(PublicIdentity {
        context_bytes,
        context_binding32,
        derivation_client_share_public_key33,
        relayer_public_key33,
        threshold_public_key33,
        threshold_ethereum_address20,
        client_share_retry_counter,
        relayer_share_retry_counter: relayer_share.retry_counter,
    })
}

fn derive_role_share32(
    role_domain: &[u8],
    context_bytes: &[u8],
    context_binding32: &[u8; 32],
    y_role32_le: [u8; 32],
    retry_counter: u32,
) -> RouterAbEcdsaDerivationResult<([u8; 32], u32)> {
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

fn context_binding_from_bytes(context_bytes: &[u8]) -> RouterAbEcdsaDerivationResult<[u8; 32]> {
    let frame = frame_digest_input(
        CONTEXT_BINDING_DOMAIN,
        &[(FIELD_CONTEXT_BYTES, context_bytes)],
    )?;
    let mut hasher = Sha256::new();
    hasher.update(frame);
    Ok(hasher.finalize().into())
}

fn operation_kind_byte(operation: ServerEvalOperation) -> u8 {
    match operation {
        ServerEvalOperation::RegistrationBootstrap => 0x01,
        ServerEvalOperation::SessionBootstrap => 0x02,
        ServerEvalOperation::NonExportSign => 0x03,
        ServerEvalOperation::ExplicitKeyExport => 0x04,
    }
}

fn frame_digest_input(
    domain: &[u8],
    fields: &[(u8, &[u8])],
) -> RouterAbEcdsaDerivationResult<Vec<u8>> {
    if fields.len() > usize::from(u8::MAX) {
        return Err(RouterAbEcdsaDerivationError::invalid_length(
            "digest frame field count exceeds u8 range",
        ));
    }

    let mut out = Vec::new();
    out.extend_from_slice(domain);
    out.push(fields.len() as u8);
    for (tag, value) in fields {
        let len = u16::try_from(value.len()).map_err(|_| {
            RouterAbEcdsaDerivationError::invalid_length("digest frame field exceeds u16 length")
        })?;
        out.push(*tag);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(value);
    }
    Ok(out)
}

fn parse_nonzero_scalar_32_be(
    bytes: &[u8],
    field_name: &str,
) -> RouterAbEcdsaDerivationResult<NonZeroScalar> {
    let scalar = parse_scalar_32_be(bytes, field_name)?;
    Option::<NonZeroScalar>::from(NonZeroScalar::new(scalar)).ok_or_else(|| {
        RouterAbEcdsaDerivationError::invalid_input(format!("{field_name} must be in (0, n)"))
    })
}

fn parse_scalar_32_be(bytes: &[u8], field_name: &str) -> RouterAbEcdsaDerivationResult<Scalar> {
    if bytes.len() != 32 {
        return Err(RouterAbEcdsaDerivationError::invalid_length(format!(
            "{field_name} must be 32 bytes (got {})",
            bytes.len()
        )));
    }
    let mut repr = Zeroizing::new(FieldBytes::default());
    repr.copy_from_slice(bytes);
    Option::<Scalar>::from(Scalar::from_repr(*repr)).ok_or_else(|| {
        RouterAbEcdsaDerivationError::invalid_input(format!(
            "{field_name} must be a canonical secp256k1 scalar"
        ))
    })
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

fn private_key_to_public_key33(
    private_key32: &[u8; 32],
    field_name: &str,
) -> RouterAbEcdsaDerivationResult<[u8; 33]> {
    vec_to_fixed_33(
        secp256k1_private_key_32_to_public_key_33(private_key32)?,
        field_name,
    )
}

fn target_client_public_key_from_delta(
    source_client_public_key: &PublicKey,
    delta: &Scalar,
) -> RouterAbEcdsaDerivationResult<[u8; 33]> {
    let source_point = ProjectivePoint::from(*source_client_public_key.as_affine());
    let target_point = source_point - (ProjectivePoint::GENERATOR * *delta);
    if bool::from(target_point.is_identity()) {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "target client public key must not be the identity point",
        ));
    }
    vec_to_fixed_33(
        target_point
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        "target client public key",
    )
}

fn validate_source_identity(
    source_relayer_share: &RelayerRoleShare,
    source_identity: &PublicIdentity,
) -> RouterAbEcdsaDerivationResult<()> {
    if source_relayer_share.context_binding32 != source_identity.context_binding32 {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "source relayer share context binding does not match public identity",
        ));
    }
    if source_relayer_share.context_bytes != source_identity.context_bytes {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "source relayer share context does not match public identity",
        ));
    }
    if source_relayer_share.relayer_public_key33 != source_identity.relayer_public_key33 {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "source relayer public key does not match public identity",
        ));
    }
    if source_relayer_share.retry_counter != source_identity.relayer_share_retry_counter {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "source relayer retry counter does not match public identity",
        ));
    }
    let source_relayer_public_key33 = private_key_to_public_key33(
        &source_relayer_share.x_relayer32,
        "source relayer public key",
    )?;
    if source_relayer_public_key33 != source_relayer_share.relayer_public_key33 {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "source relayer share public key is inconsistent",
        ));
    }
    let context_binding32 = context_binding_from_bytes(&source_identity.context_bytes)?;
    if context_binding32 != source_identity.context_binding32 {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "public identity context binding is invalid",
        ));
    }
    let source_client_public_key33 = validate_public_key33(
        &source_identity.derivation_client_share_public_key33,
        "source client public key",
    )?;
    let source_relayer_public_key33 = validate_public_key33(
        &source_identity.relayer_public_key33,
        "source relayer public key",
    )?;
    let threshold_public_key33 = add_public_keys_non_identity_33(
        &source_client_public_key33,
        &source_relayer_public_key33,
        "source threshold public key",
    )?;
    if threshold_public_key33 != source_identity.threshold_public_key33 {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "source threshold public key is inconsistent",
        ));
    }
    let threshold_ethereum_address20 = vec_to_fixed_20(
        secp256k1_public_key_33_to_ethereum_address_20(&threshold_public_key33)?,
        "source threshold ethereum address",
    )?;
    if threshold_ethereum_address20 != source_identity.threshold_ethereum_address20 {
        return Err(RouterAbEcdsaDerivationError::invalid_input(
            "source threshold ethereum address is inconsistent",
        ));
    }
    Ok(())
}

fn validate_public_key33(
    public_key33: &[u8; 33],
    field_name: &str,
) -> RouterAbEcdsaDerivationResult<[u8; 33]> {
    vec_to_fixed_33(validate_secp256k1_public_key_33(public_key33)?, field_name)
}

fn add_public_keys_non_identity_33(
    left33: &[u8; 33],
    right33: &[u8; 33],
    field_name: &str,
) -> RouterAbEcdsaDerivationResult<[u8; 33]> {
    if public_key_sum_is_identity(left33, right33)? {
        return Err(RouterAbEcdsaDerivationError::invalid_input(format!(
            "{field_name} must not be the identity point"
        )));
    }
    vec_to_fixed_33(add_secp256k1_public_keys_33(left33, right33)?, field_name)
}

fn public_key_sum_is_identity(
    left33: &[u8; 33],
    right33: &[u8; 33],
) -> RouterAbEcdsaDerivationResult<bool> {
    let left = PublicKey::from_sec1_bytes(left33)
        .map_err(|_| RouterAbEcdsaDerivationError::decode_error("left public key is invalid"))?;
    let right = PublicKey::from_sec1_bytes(right33)
        .map_err(|_| RouterAbEcdsaDerivationError::decode_error("right public key is invalid"))?;
    let sum = ProjectivePoint::from(*left.as_affine()) + ProjectivePoint::from(*right.as_affine());
    Ok(bool::from(sum.is_identity()))
}

fn is_identity_public_key_sum_error(err: &RouterAbEcdsaDerivationError) -> bool {
    err.message.contains("identity point")
}

fn vec_to_fixed_20(bytes: Vec<u8>, field_name: &str) -> RouterAbEcdsaDerivationResult<[u8; 20]> {
    if bytes.len() != 20 {
        return Err(RouterAbEcdsaDerivationError::invalid_length(format!(
            "{field_name} must be 20 bytes (got {})",
            bytes.len()
        )));
    }
    bytes.try_into().map_err(|_| {
        RouterAbEcdsaDerivationError::invalid_length(format!(
            "{field_name} must be exactly 20 bytes"
        ))
    })
}

fn vec_to_fixed_33(bytes: Vec<u8>, field_name: &str) -> RouterAbEcdsaDerivationResult<[u8; 33]> {
    if bytes.len() != 33 {
        return Err(RouterAbEcdsaDerivationError::invalid_length(format!(
            "{field_name} must be 33 bytes (got {})",
            bytes.len()
        )));
    }
    bytes.try_into().map_err(|_| {
        RouterAbEcdsaDerivationError::invalid_length(format!(
            "{field_name} must be exactly 33 bytes"
        ))
    })
}
