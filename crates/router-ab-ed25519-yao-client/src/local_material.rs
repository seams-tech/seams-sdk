//! Same-device continuity cache for activated Ed25519 Yao Client material.
//!
//! This record is a cache and nothing else. It re-opens material the protocol
//! already activated, so it is never the source of truth for a wallet's keys,
//! never a portable custody envelope, and never a Client root. Losing it costs
//! a Router round; it does not cost the wallet.
//!
//! The crypto lives here rather than in the wasm bindings because the wallet
//! custody ceremony has to seal one of these from inside its own wasm module,
//! where the custody seed lives and never leaves — and `mod wasm` is compiled
//! only for `wasm32`, so a ceremony test on the host could not reach it. The
//! bindings now delegate here, byte-for-byte: same salts, same info, same
//! plaintext layout, so records sealed before this split still open.
//!
//! Three wrapping domains, listed in [`LocalMaterialSealDomainV1`]. The seed
//! domain is the one this refactor adds, and the reason it exists is that the
//! other two are per factor: a wallet that registered under a passkey and later
//! enrolled Email OTP would miss its cache on every OTP unlock.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use core::fmt;
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use hkdf::Hkdf;
use sha2::Sha256;
use signer_core::near_threshold_frost::compute_threshold_ed25519_group_public_key_2p_from_verifying_shares;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use signer_core::passkey_custody::{
    open_wallet_custody_seed_envelope_v1, PasskeyCustodyEnvelopeBindingV1,
};
use signer_core::wallet_seed_derivation::derive_ed25519_local_material_cache_key_from_seed_v1;

use crate::ActivatedClientV1;

/// Plaintext layout version. Bumping it invalidates every stored record,
/// which is the intended effect of ever changing the layout.
pub const ACTIVATED_CLIENT_SEAL_VERSION_V1: u8 = 1;
/// Version byte, scalar share, registered public key, big-endian state epoch.
pub const ACTIVATED_CLIENT_PLAINTEXT_LEN_V1: usize = 1 + 32 + 32 + 8;
/// ChaCha20-Poly1305 nonce width.
pub const ACTIVATED_CLIENT_NONCE_LEN_V1: usize = 12;
/// Upper bound on the binding, so a caller cannot force unbounded HKDF input.
pub const MAX_ACTIVATED_CLIENT_BINDING_LEN_V1: usize = 4096;

const PASSKEY_SEAL_INFO_V1: &[u8] = b"seams/router-ab/ed25519-yao/activated-client-seal/v1";
const PASSKEY_SEAL_SALT_V1: &[u8] = b"seams/router-ab/ed25519-yao/activated-client-seal/salt/v1";
/// The wallet-scoped domain. Its wrapping secret is the seed-derived cache key
/// from `signer_core::wallet_seed_derivation`, never a factor secret and never
/// a signing root.
const WALLET_CUSTODY_SEED_SEAL_INFO_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/activated-client-seal/wallet-custody-seed/v1";
const WALLET_CUSTODY_SEED_SEAL_SALT_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/activated-client-seal/wallet-custody-seed/salt/v1";

/// Which secret wraps a cache record.
///
/// Separate salt and info per domain, so a record sealed under one never opens
/// under another even if the same 32 bytes were somehow supplied twice. The
/// enum exists rather than loose salt arguments because a caller passing the
/// wrong pair would produce a record that fails to open much later, at unlock,
/// with nothing pointing back to the mistake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalMaterialSealDomainV1 {
    /// Wrapped by `PRF.first`. Opens only for the credential that registered.
    PasskeyPrfFirst,
    /// Wrapped by the seed-derived cache key, so every factor that opens the
    /// wallet's custody envelope reaches the same record.
    WalletCustodySeed,
}

impl LocalMaterialSealDomainV1 {
    const fn salt(self) -> &'static [u8] {
        match self {
            Self::PasskeyPrfFirst => PASSKEY_SEAL_SALT_V1,
            Self::WalletCustodySeed => WALLET_CUSTODY_SEED_SEAL_SALT_V1,
        }
    }

    const fn info(self) -> &'static [u8] {
        match self {
            Self::PasskeyPrfFirst => PASSKEY_SEAL_INFO_V1,
            Self::WalletCustodySeed => WALLET_CUSTODY_SEED_SEAL_INFO_V1,
        }
    }
}

/// Why a cache record could not be sealed or opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalMaterialError {
    /// The binding was empty or longer than the accepted maximum.
    InvalidBinding,
    /// The nonce was not exactly 12 bytes.
    InvalidNonce,
    /// A fixed-width input was the wrong length.
    InvalidLength,
    /// Key derivation, sealing, or opening failed.
    SealFailed,
    /// The envelope opened but its version or layout was not this one's.
    InvalidEnvelope,
    /// The opened record named a different key or state epoch than expected.
    IdentityMismatch,
    /// The opened share does not reproduce the registered threshold key.
    PublicRelationMismatch,
}

impl fmt::Display for LocalMaterialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidBinding => "Ed25519 Yao activated Client binding length is invalid",
            Self::InvalidNonce => "Ed25519 Yao activated Client seal nonce is invalid",
            Self::InvalidLength => "Ed25519 Yao activated Client input length is invalid",
            Self::SealFailed => "Ed25519 Yao activated Client seal failed",
            Self::InvalidEnvelope => "Ed25519 Yao activated Client envelope version is invalid",
            Self::IdentityMismatch => "Ed25519 Yao activated Client envelope identity mismatch",
            Self::PublicRelationMismatch => {
                "sealed Client material does not match the registered Ed25519 public key"
            }
        };
        formatter.write_str(message)
    }
}

impl core::error::Error for LocalMaterialError {}

/// Result alias for the seal and import surface.
pub type LocalMaterialResult<T> = Result<T, LocalMaterialError>;

fn require_32(value: &[u8]) -> LocalMaterialResult<[u8; 32]> {
    value
        .try_into()
        .map_err(|_| LocalMaterialError::InvalidLength)
}

fn require_nonce(value: &[u8]) -> LocalMaterialResult<[u8; ACTIVATED_CLIENT_NONCE_LEN_V1]> {
    value
        .try_into()
        .map_err(|_| LocalMaterialError::InvalidNonce)
}

fn require_binding(binding: &[u8]) -> LocalMaterialResult<()> {
    if binding.is_empty() || binding.len() > MAX_ACTIVATED_CLIENT_BINDING_LEN_V1 {
        return Err(LocalMaterialError::InvalidBinding);
    }
    Ok(())
}

/// Derives the record's AEAD key.
///
/// The binding is mixed into the derivation *and* used as AEAD associated data.
/// That is deliberate belt-and-braces: the first makes a record for one wallet
/// undecryptable under another's binding, the second makes tampering with the
/// binding detectable rather than merely useless.
fn derive_seal_key(
    wrapping_secret: &[u8; 32],
    binding: &[u8],
    domain: LocalMaterialSealDomainV1,
) -> LocalMaterialResult<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(domain.salt()), wrapping_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand_multi_info(&[domain.info(), binding], &mut key[..])
        .map_err(|_| LocalMaterialError::SealFailed)?;
    Ok(key)
}

/// Seals one activated Client's material under any wrapping domain.
pub fn seal_activated_client_material_v1(
    client_scalar_share: &[u8; 32],
    registered_public_key: &[u8; 32],
    state_epoch: u64,
    wrapping_secret: &[u8; 32],
    binding: &[u8],
    nonce: &[u8],
    domain: LocalMaterialSealDomainV1,
) -> LocalMaterialResult<Vec<u8>> {
    let nonce = require_nonce(nonce)?;
    require_binding(binding)?;
    let key = derive_seal_key(wrapping_secret, binding, domain)?;
    let mut plaintext = Zeroizing::new([0u8; ACTIVATED_CLIENT_PLAINTEXT_LEN_V1]);
    plaintext[0] = ACTIVATED_CLIENT_SEAL_VERSION_V1;
    plaintext[1..33].copy_from_slice(client_scalar_share);
    plaintext[33..65].copy_from_slice(registered_public_key);
    plaintext[65..73].copy_from_slice(&state_epoch.to_be_bytes());
    ChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| LocalMaterialError::SealFailed)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: binding,
            },
        )
        .map_err(|_| LocalMaterialError::SealFailed)
}

/// The material an opened record yields, before it becomes an activated Client.
pub struct OpenedLocalMaterialV1 {
    /// The Client's scalar share, zeroized on drop.
    pub client_scalar_share: Zeroizing<[u8; 32]>,
    /// The registered threshold public key this share reproduces.
    pub registered_public_key: [u8; 32],
    /// The SigningWorker state epoch the record was sealed at.
    pub state_epoch: u64,
}

/// Opens a record and re-verifies that its share reproduces the registered key.
///
/// The public-relation check is what makes this safe to cache at all: a record
/// that decrypts but whose share does not recombine to the registered public
/// key is rejected, so a tampered or stale cache cannot install material that
/// signs under a key the wallet does not own.
#[allow(clippy::too_many_arguments)]
pub fn import_activated_client_material_v1(
    wrapping_secret: &[u8; 32],
    binding: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    expected_registered_public_key: &[u8; 32],
    expected_state_epoch: u64,
    participant_ids: [u16; 2],
    signing_worker_verifying_share: &[u8; 32],
    domain: LocalMaterialSealDomainV1,
) -> LocalMaterialResult<OpenedLocalMaterialV1> {
    let nonce = require_nonce(nonce)?;
    require_binding(binding)?;
    let key = derive_seal_key(wrapping_secret, binding, domain)?;
    let plaintext = ChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| LocalMaterialError::SealFailed)?
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: binding,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| LocalMaterialError::SealFailed)?;
    if plaintext.len() != ACTIVATED_CLIENT_PLAINTEXT_LEN_V1
        || plaintext[0] != ACTIVATED_CLIENT_SEAL_VERSION_V1
    {
        return Err(LocalMaterialError::InvalidEnvelope);
    }
    let client_scalar_share = Zeroizing::new(require_32(&plaintext[1..33])?);
    let registered_public_key = require_32(&plaintext[33..65])?;
    let state_epoch = u64::from_be_bytes(
        plaintext[65..73]
            .try_into()
            .map_err(|_| LocalMaterialError::InvalidEnvelope)?,
    );
    if !bool::from(registered_public_key.ct_eq(expected_registered_public_key))
        || state_epoch != expected_state_epoch
    {
        return Err(LocalMaterialError::IdentityMismatch);
    }
    verify_public_relation(
        &client_scalar_share,
        participant_ids,
        signing_worker_verifying_share,
        &registered_public_key,
    )?;
    Ok(OpenedLocalMaterialV1 {
        client_scalar_share,
        registered_public_key,
        state_epoch,
    })
}

fn verify_public_relation(
    client_scalar_share: &[u8; 32],
    participant_ids: [u16; 2],
    signing_worker_verifying_share: &[u8; 32],
    registered_public_key: &[u8; 32],
) -> LocalMaterialResult<()> {
    let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(*client_scalar_share))
        .ok_or(LocalMaterialError::InvalidEnvelope)?;
    let client_verifying_share = (ED25519_BASEPOINT_POINT * scalar).compress().to_bytes();
    let threshold_public_key = compute_threshold_ed25519_group_public_key_2p_from_verifying_shares(
        &client_verifying_share,
        signing_worker_verifying_share,
        participant_ids[0],
        participant_ids[1],
    )
    .map_err(|_| LocalMaterialError::PublicRelationMismatch)?;
    if !bool::from(threshold_public_key.ct_eq(registered_public_key)) {
        return Err(LocalMaterialError::PublicRelationMismatch);
    }
    Ok(())
}

/// Seals an activated Client under the wallet custody seed's cache key.
///
/// Takes the derived cache key rather than the seed, so the seed itself never
/// reaches this crate: the ceremony derives it inside its own module and passes
/// only the wrapping key. The binding must not carry credential or RP identity
/// — this record is factor-agnostic by construction, and binding it to the
/// credential that happened to register would defeat the reason it exists.
pub fn seal_activated_client_under_custody_seed_v1(
    activated: &ActivatedClientV1,
    cache_key: &[u8; 32],
    binding: &[u8],
    nonce: &[u8],
) -> LocalMaterialResult<Vec<u8>> {
    seal_activated_client_material_v1(
        activated.client_scalar_share(),
        &activated.registered_public_key(),
        activated.state_epoch(),
        cache_key,
        binding,
        nonce,
        LocalMaterialSealDomainV1::WalletCustodySeed,
    )
}

/// Opens a seed-sealed record back into an activated Client.
#[allow(clippy::too_many_arguments)]
pub fn import_activated_client_under_custody_seed_v1(
    cache_key: &[u8; 32],
    binding: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    expected_registered_public_key: &[u8; 32],
    expected_state_epoch: u64,
    participant_ids: [u16; 2],
    signing_worker_verifying_share: &[u8; 32],
) -> LocalMaterialResult<ActivatedClientV1> {
    let opened = import_activated_client_material_v1(
        cache_key,
        binding,
        nonce,
        ciphertext,
        expected_registered_public_key,
        expected_state_epoch,
        participant_ids,
        signing_worker_verifying_share,
        LocalMaterialSealDomainV1::WalletCustodySeed,
    )?;
    Ok(ActivatedClientV1::from_local_material_v1(
        *opened.client_scalar_share,
        opened.registered_public_key,
        opened.state_epoch,
    ))
}

/// Canonical binding for the Ed25519 continuity cache record.
///
/// Length-delimited fields under a fixed context, so no two bindings encode
/// alike and no field can be shifted into another. Carries nothing that names
/// a factor.
///
/// Lives here rather than in the ceremony because both sides need it and the
/// dependency only runs one way: the ceremony seals and can reach down to this
/// crate, while unlock opens from this crate and could never reach up. Two
/// copies would be worse than either — it is both HKDF input and AEAD
/// associated data, so a reader that assembled it even slightly differently
/// holds a record that never opens, and the failure looks like a bad factor.
pub fn ed25519_local_material_binding_v1(
    application_binding_digest: &[u8; 32],
    registered_public_key: &[u8; 32],
    participant_ids: [u16; 2],
    state_epoch: u64,
) -> Vec<u8> {
    fn field(out: &mut Vec<u8>, label: &[u8], value: &[u8]) {
        out.extend_from_slice(&(label.len() as u32).to_be_bytes());
        out.extend_from_slice(label);
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
    let mut out = Vec::new();
    field(
        &mut out,
        b"context",
        b"seams/wallet-custody/ed25519-local-material-cache/v1",
    );
    field(
        &mut out,
        b"applicationBindingDigest",
        application_binding_digest,
    );
    field(&mut out, b"registeredPublicKey", registered_public_key);
    field(
        &mut out,
        b"participantIds",
        &[
            participant_ids[0].to_be_bytes(),
            participant_ids[1].to_be_bytes(),
        ]
        .concat(),
    );
    field(&mut out, b"stateEpoch", &state_epoch.to_be_bytes());
    out
}

/// Opens the wallet's continuity cache with a factor, end to end.
///
/// **This is the unlock read side, and it is deliberately one call.** The seed
/// exists only between opening the custody envelope and deriving the cache
/// key; splitting it would put the seed in a caller's hands, and every caller
/// is JavaScript. Factor secret and ciphertext in, activated Client out.
///
/// Unlocking is not a ceremony — it derives no owner root and establishes no
/// manifest. Opening the envelope authenticates the seed to the wallet, and
/// the import below re-verifies that the cached share still reproduces the
/// registered key, so nothing here has to trust the cache.
///
/// Any factor works, which is the whole point: the record was sealed under the
/// seed, so a factor enrolled long after registration opens the same cache as
/// the one that created it.
#[allow(clippy::too_many_arguments)]
pub fn open_wallet_custody_ed25519_material_v1(
    input: OpenWalletCustodyEd25519MaterialV1<'_>,
) -> LocalMaterialResult<ActivatedClientV1> {
    let seed = open_wallet_custody_seed_envelope_v1(
        input.factor_secret,
        input.envelope_binding,
        input.envelope_nonce,
        input.envelope_ciphertext,
        input.envelope_aad_hash,
        input.envelope_ciphertext_digest,
    )
    .map_err(|_| LocalMaterialError::SealFailed)
    .map(|(seed, _admitted)| seed)?;

    let cache_key = derive_ed25519_local_material_cache_key_from_seed_v1(
        &seed,
        input.application_binding_digest,
    )
    .map_err(|_| LocalMaterialError::SealFailed)?;

    import_activated_client_under_custody_seed_v1(
        &cache_key,
        input.binding,
        input.nonce,
        input.ciphertext,
        input.expected_registered_public_key,
        input.expected_state_epoch,
        input.participant_ids,
        input.signing_worker_verifying_share,
    )
}

/// Everything one unlock needs. A struct because eight positional arguments of
/// mostly-byte-slices is a place transpositions hide.
pub struct OpenWalletCustodyEd25519MaterialV1<'a> {
    /// The unwrap factor: `PRF.first`, or the Email OTP factor key.
    pub factor_secret: &'a [u8],
    /// The custody envelope's binding, as stored.
    pub envelope_binding: &'a PasskeyCustodyEnvelopeBindingV1,
    /// The envelope's nonce.
    pub envelope_nonce: &'a [u8],
    /// The sealed custody seed.
    pub envelope_ciphertext: &'a [u8],
    /// The envelope's recorded AAD digest.
    pub envelope_aad_hash: &'a [u8],
    /// The envelope's recorded ciphertext digest.
    pub envelope_ciphertext_digest: &'a [u8],
    /// This key set's application binding digest, from the cache record.
    pub application_binding_digest: &'a [u8; 32],
    /// The cache record's seal binding, rebuilt by the caller.
    pub binding: &'a [u8],
    /// The cache record's nonce.
    pub nonce: &'a [u8],
    /// The cache record's ciphertext.
    pub ciphertext: &'a [u8],
    /// The registered key the opened share must reproduce.
    pub expected_registered_public_key: &'a [u8; 32],
    /// The state epoch the record was sealed at.
    pub expected_state_epoch: u64,
    /// Client and SigningWorker participant ids, in that order.
    pub participant_ids: [u16; 2],
    /// The SigningWorker's verifying share, for the public-relation check.
    pub signing_worker_verifying_share: &'a [u8; 32],
}
