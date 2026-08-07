//! Wallet-scoped recovery envelope sets for Refactor 100.
//!
//! A recovery code protects the whole mixed-wallet custody set through two
//! levels:
//!
//! ```text
//! recovery code --HKDF--> code KEK --opens--> manifest KEK
//! manifest KEK  --HKDF--> entry KEK --opens--> one custody secret
//! ```
//!
//! A code never wraps a custody entry directly. Rotating codes therefore
//! rewraps only the 32-byte manifest KEK and never re-opens a plaintext root,
//! and one code opens the whole set or nothing — the all-or-nothing promotion
//! the recovery flow requires is structural, not a caller convention.
//!
//! Per-entry AAD survives the manifest KEK because each entry KEK is derived
//! with its own wallet key, lane, epoch, and custody-secret kind.
//!
//! Sealing takes a [`VerifiedWalletKeyManifestDigestV1`] rather than a digest,
//! and builds its own scope from it: a set of ten codes may only be issued for
//! a key manifest the ceremony proved the seed reproduces. Opening takes a
//! stored scope directly, because recovery must open the seed *before* it can
//! derive anything to verify against. The gate there is on promoting the
//! recovered seed to a capability, not on the decrypt itself.

use base64ct::{Base64UrlUnpadded, Encoding};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CoreResult, SignerCoreError};
use crate::passkey_custody::{
    sha256_digest, PasskeyCustodySecretKind, PASSKEY_CUSTODY_KEY_LEN, PASSKEY_CUSTODY_NONCE_LEN,
    PASSKEY_CUSTODY_TAG_LEN, PASSKEY_CUSTODY_WRAP_ALG_V1,
};
use crate::wallet_seed_derivation::VerifiedWalletKeyManifestDigestV1;

pub const WALLET_RECOVERY_ENVELOPE_SET_VERSION_V1: &str = "wallet_recovery_envelope_set_v1";
pub const WALLET_RECOVERY_CODE_COUNT: usize = 10;

const RECOVERY_CODE_KEK_SALT_V1: &[u8] = b"seams/wallet-recovery/code-kek/salt/v1";
const RECOVERY_CODE_KEK_INFO_V1: &[u8] = b"seams/wallet-recovery/code-kek/info/v1";
const RECOVERY_ENTRY_KEK_SALT_V1: &[u8] = b"seams/wallet-recovery/entry-kek/salt/v1";
const RECOVERY_ENTRY_KEK_INFO_V1: &[u8] = b"seams/wallet-recovery/entry-kek/info/v1";
const RECOVERY_MANIFEST_AAD_CONTEXT_V1: &[u8] = b"seams/wallet-recovery/manifest-kek/aad/v1";
const RECOVERY_ENTRY_AAD_CONTEXT_V1: &[u8] = b"seams/wallet-recovery/entry/aad/v1";

const MANIFEST_KEK_PURPOSE_V1: &str = "wallet_recovery_manifest_kek";
const MAX_RECOVERY_FIELD_LEN: usize = 512;
const MAX_CUSTODY_SECRET_LEN: usize = 1024;

/// Identifies one recovery code's wrap of the manifest KEK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletRecoveryCodeScopeV1 {
    pub wallet_id: String,
    pub recovery_key_id: String,
    /// Binds a wrap to the exact active owner key/lane manifest, so a wrap
    /// cannot be moved onto a set whose key manifest has since changed.
    pub key_manifest_digest: [u8; 32],
}

/// Identifies the single custody entry inside a recovery envelope set.
///
/// A recovery set covers owner custody only: exactly one wallet-scoped seed.
/// Lane holder shares are deliberately absent. A linked device's share is
/// sealed under that device's own factor, so it never depended on the owner
/// credential and survives owner recovery untouched; including it here would
/// instead let an owner recovery code reconstruct that device's material. A
/// lost lane is revoked and reprovisioned through Refactor 102, not recovered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletRecoveryEntryScopeV1 {
    pub wallet_id: String,
    pub key_manifest_digest: [u8; 32],
}

/// A sealed recovery wrap plus the AAD digest its record stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedRecoveryWrapV1 {
    pub ciphertext: Vec<u8>,
    pub aad_hash: [u8; 32],
}

impl SealedRecoveryWrapV1 {
    pub fn ciphertext_b64u(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.ciphertext)
    }

    pub fn aad_hash_b64u(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.aad_hash)
    }
}

fn require_field(label: &str, value: &str) -> CoreResult<()> {
    if value.is_empty() {
        return Err(SignerCoreError::invalid_input(format!(
            "{label} must not be empty"
        )));
    }
    if value.len() > MAX_RECOVERY_FIELD_LEN {
        return Err(SignerCoreError::invalid_input(format!(
            "{label} exceeds the maximum recovery binding field length"
        )));
    }
    Ok(())
}

fn labeled_field(out: &mut Vec<u8>, label: &[u8], value: &[u8]) {
    out.extend_from_slice(&(label.len() as u32).to_be_bytes());
    out.extend_from_slice(label);
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn labeled_str(out: &mut Vec<u8>, label: &[u8], value: &str) {
    labeled_field(out, label, value.as_bytes());
}

fn require_nonce(nonce: &[u8]) -> CoreResult<[u8; PASSKEY_CUSTODY_NONCE_LEN]> {
    nonce.try_into().map_err(|_| {
        SignerCoreError::invalid_length(format!(
            "wallet recovery nonce must be {PASSKEY_CUSTODY_NONCE_LEN} bytes"
        ))
    })
}

/// AAD for one recovery code's wrap of the manifest KEK.
pub fn encode_recovery_manifest_aad_v1(scope: &WalletRecoveryCodeScopeV1) -> CoreResult<Vec<u8>> {
    require_field("walletId", &scope.wallet_id)?;
    require_field("recoveryKeyId", &scope.recovery_key_id)?;

    let mut out = Vec::new();
    labeled_field(&mut out, b"context", RECOVERY_MANIFEST_AAD_CONTEXT_V1);
    labeled_str(
        &mut out,
        b"setVersion",
        WALLET_RECOVERY_ENVELOPE_SET_VERSION_V1,
    );
    labeled_str(&mut out, b"wrapAlg", PASSKEY_CUSTODY_WRAP_ALG_V1);
    labeled_str(&mut out, b"walletId", &scope.wallet_id);
    labeled_str(&mut out, b"recoveryKeyId", &scope.recovery_key_id);
    labeled_str(&mut out, b"purpose", MANIFEST_KEK_PURPOSE_V1);
    labeled_field(&mut out, b"keyManifestDigest", &scope.key_manifest_digest);
    Ok(out)
}

/// AAD for one custody entry's wrap under the manifest KEK.
pub fn encode_recovery_entry_aad_v1(scope: &WalletRecoveryEntryScopeV1) -> CoreResult<Vec<u8>> {
    require_field("walletId", &scope.wallet_id)?;

    let mut out = Vec::new();
    labeled_field(&mut out, b"context", RECOVERY_ENTRY_AAD_CONTEXT_V1);
    labeled_str(
        &mut out,
        b"setVersion",
        WALLET_RECOVERY_ENVELOPE_SET_VERSION_V1,
    );
    labeled_str(&mut out, b"wrapAlg", PASSKEY_CUSTODY_WRAP_ALG_V1);
    labeled_str(&mut out, b"walletId", &scope.wallet_id);
    // Bound explicitly even though only one kind and scope exist today, so a
    // future lane-bearing entry could never collide with a seed entry's AAD.
    labeled_str(
        &mut out,
        b"custodySecretKind",
        PasskeyCustodySecretKind::WalletCustodySeed.as_str(),
    );
    labeled_str(&mut out, b"scope", "wallet");

    labeled_field(&mut out, b"keyManifestDigest", &scope.key_manifest_digest);
    Ok(out)
}

/// Derives the KEK one recovery code uses to open the manifest KEK.
pub fn derive_wallet_recovery_code_kek_v1(
    recovery_code_bytes: &[u8],
    scope: &WalletRecoveryCodeScopeV1,
) -> CoreResult<Zeroizing<[u8; PASSKEY_CUSTODY_KEY_LEN]>> {
    if recovery_code_bytes.is_empty() {
        return Err(SignerCoreError::invalid_input(
            "recovery code bytes must not be empty",
        ));
    }
    let context_digest = sha256_digest(&encode_recovery_manifest_aad_v1(scope)?);
    let hkdf = Hkdf::<Sha256>::new(Some(RECOVERY_CODE_KEK_SALT_V1), recovery_code_bytes);
    let mut kek = Zeroizing::new([0u8; PASSKEY_CUSTODY_KEY_LEN]);
    hkdf.expand_multi_info(&[RECOVERY_CODE_KEK_INFO_V1, &context_digest], &mut kek[..])
        .map_err(|_| SignerCoreError::hkdf_error("wallet recovery code KEK derivation failed"))?;
    Ok(kek)
}

/// Derives the per-entry KEK from the opened manifest KEK.
pub fn derive_wallet_recovery_entry_kek_v1(
    manifest_kek: &[u8],
    scope: &WalletRecoveryEntryScopeV1,
) -> CoreResult<Zeroizing<[u8; PASSKEY_CUSTODY_KEY_LEN]>> {
    if manifest_kek.len() != PASSKEY_CUSTODY_KEY_LEN {
        return Err(SignerCoreError::invalid_length(format!(
            "wallet recovery manifest KEK must be {PASSKEY_CUSTODY_KEY_LEN} bytes"
        )));
    }
    let context_digest = sha256_digest(&encode_recovery_entry_aad_v1(scope)?);
    let hkdf = Hkdf::<Sha256>::new(Some(RECOVERY_ENTRY_KEK_SALT_V1), manifest_kek);
    let mut kek = Zeroizing::new([0u8; PASSKEY_CUSTODY_KEY_LEN]);
    hkdf.expand_multi_info(&[RECOVERY_ENTRY_KEK_INFO_V1, &context_digest], &mut kek[..])
        .map_err(|_| SignerCoreError::hkdf_error("wallet recovery entry KEK derivation failed"))?;
    Ok(kek)
}

fn seal(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> CoreResult<Vec<u8>> {
    let nonce: Nonce = require_nonce(nonce)?.into();
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| SignerCoreError::crypto_error("invalid wallet recovery KEK"))?;
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SignerCoreError::crypto_error("wallet recovery seal failed"))
}

fn open(key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> CoreResult<Zeroizing<Vec<u8>>> {
    if ciphertext.len() <= PASSKEY_CUSTODY_TAG_LEN {
        return Err(SignerCoreError::invalid_length(
            "wallet recovery ciphertext is shorter than its authentication tag",
        ));
    }
    let nonce: Nonce = require_nonce(nonce)?.into();
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| SignerCoreError::crypto_error("invalid wallet recovery KEK"))?;
    let opened = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| SignerCoreError::crypto_error("wallet recovery open failed"))?;
    Ok(Zeroizing::new(opened))
}

/// Wraps the manifest KEK under one recovery code.
///
/// Takes the verified manifest rather than a scope, and builds the scope from
/// it. Issuing a recovery set is only meaningful for a key manifest this
/// ceremony reproduced: a wrap bound to an unverified digest would hand out ten
/// codes for a key set the seed may not control.
pub fn seal_wallet_recovery_manifest_kek_v1(
    recovery_code_bytes: &[u8],
    wallet_id: &str,
    recovery_key_id: &str,
    verified_key_manifest: &VerifiedWalletKeyManifestDigestV1,
    nonce: &[u8],
    manifest_kek: &[u8],
) -> CoreResult<SealedRecoveryWrapV1> {
    if manifest_kek.len() != PASSKEY_CUSTODY_KEY_LEN {
        return Err(SignerCoreError::invalid_length(format!(
            "wallet recovery manifest KEK must be {PASSKEY_CUSTODY_KEY_LEN} bytes"
        )));
    }
    let scope = &WalletRecoveryCodeScopeV1 {
        wallet_id: wallet_id.to_string(),
        recovery_key_id: recovery_key_id.to_string(),
        key_manifest_digest: *verified_key_manifest.digest(),
    };
    let aad = encode_recovery_manifest_aad_v1(scope)?;
    let code_kek = derive_wallet_recovery_code_kek_v1(recovery_code_bytes, scope)?;
    let ciphertext = seal(&code_kek[..], nonce, &aad, manifest_kek)?;
    Ok(SealedRecoveryWrapV1 {
        ciphertext,
        aad_hash: sha256_digest(&aad),
    })
}

/// Opens the manifest KEK with one recovery code.
pub fn open_wallet_recovery_manifest_kek_v1(
    recovery_code_bytes: &[u8],
    scope: &WalletRecoveryCodeScopeV1,
    nonce: &[u8],
    ciphertext: &[u8],
) -> CoreResult<Zeroizing<[u8; PASSKEY_CUSTODY_KEY_LEN]>> {
    let aad = encode_recovery_manifest_aad_v1(scope)?;
    let code_kek = derive_wallet_recovery_code_kek_v1(recovery_code_bytes, scope)?;
    let opened = open(&code_kek[..], nonce, &aad, ciphertext)?;
    let manifest_kek: [u8; PASSKEY_CUSTODY_KEY_LEN] =
        opened.as_slice().try_into().map_err(|_| {
            SignerCoreError::invalid_length(format!(
                "wallet recovery manifest KEK must be {PASSKEY_CUSTODY_KEY_LEN} bytes"
            ))
        })?;
    Ok(Zeroizing::new(manifest_kek))
}

/// Wraps the wallet custody seed under the manifest KEK.
///
/// Like the code wrap above, the scope is built from the verified manifest, so
/// the entry a recovery code will later open is bound to the key set this
/// ceremony proved the seed reproduces.
pub fn seal_wallet_recovery_entry_v1(
    manifest_kek: &[u8],
    wallet_id: &str,
    verified_key_manifest: &VerifiedWalletKeyManifestDigestV1,
    nonce: &[u8],
    custody_secret: &[u8],
) -> CoreResult<SealedRecoveryWrapV1> {
    if custody_secret.is_empty() || custody_secret.len() > MAX_CUSTODY_SECRET_LEN {
        return Err(SignerCoreError::invalid_input(
            "custody secret length is invalid",
        ));
    }
    let scope = &WalletRecoveryEntryScopeV1 {
        wallet_id: wallet_id.to_string(),
        key_manifest_digest: *verified_key_manifest.digest(),
    };
    let aad = encode_recovery_entry_aad_v1(scope)?;
    let entry_kek = derive_wallet_recovery_entry_kek_v1(manifest_kek, scope)?;
    let ciphertext = seal(&entry_kek[..], nonce, &aad, custody_secret)?;
    Ok(SealedRecoveryWrapV1 {
        ciphertext,
        aad_hash: sha256_digest(&aad),
    })
}

/// Opens one custody secret under the manifest KEK.
pub fn open_wallet_recovery_entry_v1(
    manifest_kek: &[u8],
    scope: &WalletRecoveryEntryScopeV1,
    nonce: &[u8],
    ciphertext: &[u8],
) -> CoreResult<Zeroizing<Vec<u8>>> {
    let aad = encode_recovery_entry_aad_v1(scope)?;
    let entry_kek = derive_wallet_recovery_entry_kek_v1(manifest_kek, scope)?;
    open(&entry_kek[..], nonce, &aad, ciphertext)
}
