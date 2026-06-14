use core::fmt;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::shared::{ProtoError, ProtoResult};

const BINDING_FACTOR_DOMAIN_V1: &[u8] = b"ed25519-hss/role-separated/binding-factor/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ed25519SigningRoleV1 {
    Client,
    Server,
}

impl Ed25519SigningRoleV1 {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Client => b"client",
            Self::Server => b"server",
        }
    }
}

/// Public FROST-style hiding and binding commitments for one Ed25519 signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct RoleSeparatedEd25519CommitmentsV1 {
    pub hiding: [u8; 32],
    pub binding: [u8; 32],
}

impl RoleSeparatedEd25519CommitmentsV1 {
    /// Creates validated public commitments.
    pub fn new(hiding: [u8; 32], binding: [u8; 32]) -> ProtoResult<Self> {
        let commitments = Self { hiding, binding };
        commitments.validate()?;
        Ok(commitments)
    }

    /// Validates both commitments are usable prime-order Edwards points.
    pub fn validate(&self) -> ProtoResult<()> {
        decode_prime_order_point("hiding commitment", self.hiding)?;
        decode_prime_order_point("binding commitment", self.binding)?;
        Ok(())
    }
}

/// Server- or client-local nonce material for one normal-signing round.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RoleSeparatedEd25519Round1SecretV1 {
    hiding_nonce: [u8; 32],
    binding_nonce: [u8; 32],
}

impl RoleSeparatedEd25519Round1SecretV1 {
    /// Creates validated nonce material from canonical scalar bytes.
    pub fn new(hiding_nonce: [u8; 32], binding_nonce: [u8; 32]) -> ProtoResult<Self> {
        let secret = Self {
            hiding_nonce,
            binding_nonce,
        };
        secret.commitments()?;
        Ok(secret)
    }

    /// Returns the public commitments for this local nonce material.
    pub fn commitments(&self) -> ProtoResult<RoleSeparatedEd25519CommitmentsV1> {
        let hiding =
            scalar_basepoint_bytes(parse_canonical_scalar("hiding nonce", self.hiding_nonce)?);
        let binding =
            scalar_basepoint_bytes(parse_canonical_scalar("binding nonce", self.binding_nonce)?);
        RoleSeparatedEd25519CommitmentsV1::new(hiding, binding)
    }

    fn nonce_scalar(&self, binding_factor: Scalar) -> ProtoResult<Scalar> {
        let hiding = parse_canonical_scalar("hiding nonce", self.hiding_nonce)?;
        let binding = parse_canonical_scalar("binding nonce", self.binding_nonce)?;
        Ok(hiding + binding_factor * binding)
    }
}

impl fmt::Debug for RoleSeparatedEd25519Round1SecretV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoleSeparatedEd25519Round1SecretV1")
            .field("hiding_nonce", &"[redacted]")
            .field("binding_nonce", &"[redacted]")
            .finish()
    }
}

/// Round-1 output that can be persisted by the role owner until finalization.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RoleSeparatedEd25519Round1StateV1 {
    pub commitments: RoleSeparatedEd25519CommitmentsV1,
    pub secret: RoleSeparatedEd25519Round1SecretV1,
}

impl RoleSeparatedEd25519Round1StateV1 {
    /// Creates a validated round-1 state from local nonce material.
    pub fn new(secret: RoleSeparatedEd25519Round1SecretV1) -> ProtoResult<Self> {
        let state = Self {
            commitments: secret.commitments()?,
            secret,
        };
        state.validate()?;
        Ok(state)
    }

    /// Validates persisted public commitments still match the stored nonce material.
    pub fn validate(&self) -> ProtoResult<()> {
        self.commitments.validate()?;
        let expected = self.secret.commitments()?;
        if self.commitments == expected {
            return Ok(());
        }
        Err(ProtoError::InvalidInput(
            "Ed25519 round-1 commitments do not match nonce material".to_string(),
        ))
    }
}

impl fmt::Debug for RoleSeparatedEd25519Round1StateV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoleSeparatedEd25519Round1StateV1")
            .field("commitments", &self.commitments)
            .field("secret", &"[redacted]")
            .finish()
    }
}

/// Client-side request for the Ed25519 role-separated signature share.
pub struct RoleSeparatedEd25519ClientShareRequestV1<'a> {
    pub x_client_base: [u8; 32],
    pub client_round1: &'a RoleSeparatedEd25519Round1StateV1,
    pub group_public_key: [u8; 32],
    pub client_verifying_share: [u8; 32],
    pub server_verifying_share: [u8; 32],
    pub server_commitments: RoleSeparatedEd25519CommitmentsV1,
    pub signing_payload: &'a [u8],
}

/// SigningWorker-side finalization request for a role-separated Ed25519 signature.
pub struct RoleSeparatedEd25519ServerFinalizeRequestV1<'a> {
    pub x_server_base: [u8; 32],
    pub server_round1: &'a RoleSeparatedEd25519Round1StateV1,
    pub group_public_key: [u8; 32],
    pub client_commitments: RoleSeparatedEd25519CommitmentsV1,
    pub server_commitments: RoleSeparatedEd25519CommitmentsV1,
    pub client_verifying_share: [u8; 32],
    pub server_verifying_share: [u8; 32],
    pub client_signature_share: [u8; 32],
    pub signing_payload: &'a [u8],
}

/// SigningWorker finalization output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleSeparatedEd25519ServerFinalizeOutputV1 {
    pub server_signature_share: [u8; 32],
    pub signature: [u8; 64],
}

/// Creates fresh round-1 nonce material and commitments.
pub fn prepare_role_separated_ed25519_round1_v1<Rng>(
    rng: &mut Rng,
) -> ProtoResult<RoleSeparatedEd25519Round1StateV1>
where
    Rng: RngCore + CryptoRng,
{
    let secret = RoleSeparatedEd25519Round1SecretV1::new(
        random_scalar_bytes(rng),
        random_scalar_bytes(rng),
    )?;
    RoleSeparatedEd25519Round1StateV1::new(secret)
}

/// Computes the public client verifying share for the HSS share relation.
pub fn role_separated_ed25519_client_verifying_share_v1(
    x_client_base: [u8; 32],
) -> ProtoResult<[u8; 32]> {
    let x_client = parse_canonical_scalar("x_client_base", x_client_base)?;
    Ok(scalar_basepoint_bytes(x_client + x_client))
}

/// Computes the public server verifying share for the HSS share relation.
pub fn role_separated_ed25519_server_verifying_share_v1(
    x_server_base: [u8; 32],
) -> ProtoResult<[u8; 32]> {
    let x_server = parse_canonical_scalar("x_server_base", x_server_base)?;
    Ok(scalar_basepoint_bytes(-x_server))
}

/// Produces the client signature share without exposing joined Ed25519 key state.
pub fn create_role_separated_ed25519_client_signature_share_v1(
    request: RoleSeparatedEd25519ClientShareRequestV1<'_>,
) -> ProtoResult<[u8; 32]> {
    request.client_round1.validate()?;
    request.server_commitments.validate()?;
    validate_group_key_and_shares(
        request.group_public_key,
        request.client_verifying_share,
        request.server_verifying_share,
    )?;
    let expected_client_share =
        role_separated_ed25519_client_verifying_share_v1(request.x_client_base)?;
    if expected_client_share != request.client_verifying_share {
        return Err(ProtoError::InvalidInput(
            "client verifying share does not match x_client_base".to_string(),
        ));
    }
    let context = SigningContextV1::new(
        request.group_public_key,
        request.client_round1.commitments,
        request.server_commitments,
        request.client_verifying_share,
        request.server_verifying_share,
        request.signing_payload,
    )?;
    let binding_factor = context.binding_factor(Ed25519SigningRoleV1::Client);
    let challenge = context.challenge()?;
    let x_client = parse_canonical_scalar("x_client_base", request.x_client_base)?;
    let effective_client_share = x_client + x_client;
    let share = request.client_round1.secret.nonce_scalar(binding_factor)?
        + challenge * effective_client_share;
    Ok(share.to_bytes())
}

/// Finalizes a role-separated Ed25519 signature from server-owned HSS material.
pub fn finalize_role_separated_ed25519_server_signature_v1(
    request: RoleSeparatedEd25519ServerFinalizeRequestV1<'_>,
) -> ProtoResult<RoleSeparatedEd25519ServerFinalizeOutputV1> {
    request.server_round1.validate()?;
    request.client_commitments.validate()?;
    request.server_commitments.validate()?;
    if request.server_round1.commitments != request.server_commitments {
        return Err(ProtoError::InvalidInput(
            "server round-1 commitments do not match persisted nonce material".to_string(),
        ));
    }
    validate_group_key_and_shares(
        request.group_public_key,
        request.client_verifying_share,
        request.server_verifying_share,
    )?;
    let expected_server_share =
        role_separated_ed25519_server_verifying_share_v1(request.x_server_base)?;
    if expected_server_share != request.server_verifying_share {
        return Err(ProtoError::InvalidInput(
            "server verifying share does not match x_server_base".to_string(),
        ));
    }
    let context = SigningContextV1::new(
        request.group_public_key,
        request.client_commitments,
        request.server_commitments,
        request.client_verifying_share,
        request.server_verifying_share,
        request.signing_payload,
    )?;
    let challenge = context.challenge()?;
    let client_signature_share =
        parse_canonical_scalar("client signature share", request.client_signature_share)?;
    verify_signature_share(
        "client signature share",
        client_signature_share,
        request.client_commitments,
        context.binding_factor(Ed25519SigningRoleV1::Client),
        challenge,
        request.client_verifying_share,
    )?;
    let x_server = parse_canonical_scalar("x_server_base", request.x_server_base)?;
    let effective_server_share = -x_server;
    let server_signature_share = request
        .server_round1
        .secret
        .nonce_scalar(context.binding_factor(Ed25519SigningRoleV1::Server))?
        + challenge * effective_server_share;
    let signature_scalar = client_signature_share + server_signature_share;
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&context.group_commitment()?.compress().to_bytes());
    signature[32..].copy_from_slice(&signature_scalar.to_bytes());
    verify_ed25519_signature(request.group_public_key, request.signing_payload, signature)?;
    Ok(RoleSeparatedEd25519ServerFinalizeOutputV1 {
        server_signature_share: server_signature_share.to_bytes(),
        signature,
    })
}

struct SigningContextV1<'a> {
    group_public_key: [u8; 32],
    client_commitments: RoleSeparatedEd25519CommitmentsV1,
    server_commitments: RoleSeparatedEd25519CommitmentsV1,
    client_verifying_share: [u8; 32],
    server_verifying_share: [u8; 32],
    signing_payload: &'a [u8],
}

impl<'a> SigningContextV1<'a> {
    fn new(
        group_public_key: [u8; 32],
        client_commitments: RoleSeparatedEd25519CommitmentsV1,
        server_commitments: RoleSeparatedEd25519CommitmentsV1,
        client_verifying_share: [u8; 32],
        server_verifying_share: [u8; 32],
        signing_payload: &'a [u8],
    ) -> ProtoResult<Self> {
        validate_group_key_and_shares(
            group_public_key,
            client_verifying_share,
            server_verifying_share,
        )?;
        client_commitments.validate()?;
        server_commitments.validate()?;
        Ok(Self {
            group_public_key,
            client_commitments,
            server_commitments,
            client_verifying_share,
            server_verifying_share,
            signing_payload,
        })
    }

    fn group_commitment(&self) -> ProtoResult<EdwardsPoint> {
        let client = role_commitment(
            self.client_commitments,
            self.binding_factor(Ed25519SigningRoleV1::Client),
        )?;
        let server = role_commitment(
            self.server_commitments,
            self.binding_factor(Ed25519SigningRoleV1::Server),
        )?;
        Ok(client + server)
    }

    fn challenge(&self) -> ProtoResult<Scalar> {
        let group_commitment = self.group_commitment()?.compress().to_bytes();
        let mut hasher = Sha512::new();
        hasher.update(group_commitment);
        hasher.update(self.group_public_key);
        hasher.update(self.signing_payload);
        Ok(Scalar::from_bytes_mod_order_wide(&hasher.finalize().into()))
    }

    fn binding_factor(&self, role: Ed25519SigningRoleV1) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(BINDING_FACTOR_DOMAIN_V1);
        hasher.update(self.group_public_key);
        push_len64(&mut hasher, self.signing_payload);
        push_commitments(&mut hasher, &self.client_commitments);
        push_commitments(&mut hasher, &self.server_commitments);
        hasher.update(self.client_verifying_share);
        hasher.update(self.server_verifying_share);
        hasher.update(role.label());
        Scalar::from_bytes_mod_order_wide(&hasher.finalize().into())
    }
}

fn validate_group_key_and_shares(
    group_public_key: [u8; 32],
    client_verifying_share: [u8; 32],
    server_verifying_share: [u8; 32],
) -> ProtoResult<()> {
    let group = decode_prime_order_point("group public key", group_public_key)?;
    let client = decode_prime_order_point("client verifying share", client_verifying_share)?;
    let server = decode_prime_order_point("server verifying share", server_verifying_share)?;
    if client + server == group {
        return Ok(());
    }
    Err(ProtoError::InvalidInput(
        "Ed25519 verifying shares do not sum to group public key".to_string(),
    ))
}

fn verify_signature_share(
    label: &str,
    signature_share: Scalar,
    commitments: RoleSeparatedEd25519CommitmentsV1,
    binding_factor: Scalar,
    challenge: Scalar,
    verifying_share: [u8; 32],
) -> ProtoResult<()> {
    let left = ED25519_BASEPOINT_POINT * signature_share;
    let right = role_commitment(commitments, binding_factor)?
        + challenge * decode_prime_order_point("verifying share", verifying_share)?;
    if left == right {
        return Ok(());
    }
    Err(ProtoError::InvalidInput(format!(
        "{label} failed verification"
    )))
}

fn verify_ed25519_signature(
    group_public_key: [u8; 32],
    signing_payload: &[u8],
    signature: [u8; 64],
) -> ProtoResult<()> {
    let verifying_key = VerifyingKey::from_bytes(&group_public_key).map_err(|_| {
        ProtoError::InvalidInput("group public key is not a valid Ed25519 key".to_string())
    })?;
    let signature = Ed25519Signature::from_bytes(&signature);
    verifying_key
        .verify_strict(signing_payload, &signature)
        .map_err(|_| {
            ProtoError::InvalidInput("final Ed25519 signature failed verification".to_string())
        })
}

fn role_commitment(
    commitments: RoleSeparatedEd25519CommitmentsV1,
    binding_factor: Scalar,
) -> ProtoResult<EdwardsPoint> {
    Ok(
        decode_prime_order_point("hiding commitment", commitments.hiding)?
            + binding_factor * decode_prime_order_point("binding commitment", commitments.binding)?,
    )
}

fn scalar_basepoint_bytes(scalar: Scalar) -> [u8; 32] {
    (ED25519_BASEPOINT_POINT * scalar).compress().to_bytes()
}

fn parse_canonical_scalar(label: &str, bytes: [u8; 32]) -> ProtoResult<Scalar> {
    Scalar::from_canonical_bytes(bytes)
        .into_option()
        .ok_or_else(|| ProtoError::Decode(format!("{label} must be canonical scalar bytes")))
}

fn decode_prime_order_point(label: &str, bytes: [u8; 32]) -> ProtoResult<EdwardsPoint> {
    let point = CompressedEdwardsY(bytes)
        .decompress()
        .ok_or_else(|| ProtoError::Decode(format!("{label} is not a valid Edwards point")))?;
    if !point.is_small_order() {
        return Ok(point);
    }
    Err(ProtoError::InvalidInput(format!(
        "{label} must be a prime-order Edwards point"
    )))
}

fn random_scalar_bytes<Rng>(rng: &mut Rng) -> [u8; 32]
where
    Rng: RngCore + CryptoRng,
{
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    let scalar = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();
    scalar.to_bytes()
}

fn push_len64(hasher: &mut Sha512, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn push_commitments(hasher: &mut Sha512, commitments: &RoleSeparatedEd25519CommitmentsV1) {
    hasher.update(commitments.hiding);
    hasher.update(commitments.binding);
}
