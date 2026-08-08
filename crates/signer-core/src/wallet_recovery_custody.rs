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
//! under its own AAD — the wallet, the custody-secret kind, and the scope — so
//! a future lane-bearing entry could never open under a seed entry's key.
//!
//! Wraps bind to the wallet, not to a key manifest. Key sets are provisioned
//! independently and each records its own manifest, so there is no wallet-level
//! manifest for a wrap to name — and a key rotation no longer invalidates the
//! seed the set wraps. What a recovered seed may publish capability for is
//! checked per key set at that key set's own gate.

use base64ct::{Base64UrlUnpadded, Encoding};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{CoreResult, SignerCoreError};
use crate::passkey_custody::{
    sha256_digest, PasskeyCustodySecretKind, PASSKEY_CUSTODY_KEY_LEN, PASSKEY_CUSTODY_NONCE_LEN,
    PASSKEY_CUSTODY_TAG_LEN, PASSKEY_CUSTODY_WRAP_ALG_V1,
};

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

const RECOVERY_KEY_ID_CONTEXT_V1: &str = "seams/wallet-recovery/recovery-key-id/v1";
const RECOVERY_KEY_ID_PREFIX_V1: &str = "wallet-rkid-v1-";

/// Derives one recovery code's identity within a wallet's set.
///
/// **Derived here, never accepted from a caller.** The id is what a stored wrap
/// is found by, so a caller that supplied its own could point two codes at one
/// wrap, or name a wrap that no code opens. Deriving it beside the seal removes
/// that as a representable state and keeps one definition across the boundary —
/// the ceremony and the reader cannot disagree about what an id is.
///
/// SHA-256 rather than an HKDF stage, deliberately: this is an identifier
/// derived from a 160-bit random code, not key material. The dedicated context
/// and the canonical length-delimited tuple give the separation; a KDF here
/// would imply the output were a key.
///
/// Bound to the wallet and the set version, never to an envelope. Recovery is
/// wallet-scoped and has to survive adding, rewrapping, and revoking
/// factor-specific envelopes — the envelope that happened to establish custody
/// is incidental to the code that recovers it.
pub fn derive_wallet_recovery_key_id_v1(wallet_id: &str, code_bytes: &[u8]) -> CoreResult<String> {
    let wallet_id = wallet_id.trim();
    require_field("walletId", wallet_id)?;
    if code_bytes.is_empty() || code_bytes.len() > MAX_RECOVERY_FIELD_LEN {
        return Err(SignerCoreError::invalid_length(
            "recovery code bytes are out of range",
        ));
    }

    /* Four length-prefixed values, no field labels. The AAD encoders above are
    labeled because they bind records with many optional fields; this tuple
    is fixed and frozen, and it must hash byte-identically to the TypeScript
    encoder that derives the same id for recovery lookup. A label here would
    be invisible on this side and impossible to match on the other. */
    let mut out = Vec::new();
    for field in [
        RECOVERY_KEY_ID_CONTEXT_V1,
        &Base64UrlUnpadded::encode_string(code_bytes),
        wallet_id,
        WALLET_RECOVERY_ENVELOPE_SET_VERSION_V1,
    ] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }

    let mut hasher = Sha256::new();
    hasher.update(&out);
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(format!(
        "{RECOVERY_KEY_ID_PREFIX_V1}{}",
        Base64UrlUnpadded::encode_string(&digest)
    ))
}

/// Identifies one recovery code's wrap of the manifest KEK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletRecoveryCodeScopeV1 {
    pub wallet_id: String,
    pub recovery_key_id: String,
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
/// The wrap binds the wallet and the code's own id, not a key manifest. Key
/// sets are provisioned independently and each records its own manifest, so
/// there is no wallet-level manifest for a wrap to name; what a recovered seed
/// may publish is checked per key set at that key set's own gate.
pub fn seal_wallet_recovery_manifest_kek_v1(
    recovery_code_bytes: &[u8],
    wallet_id: &str,
    recovery_key_id: &str,
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
/// Like the code wrap above, the scope is the wallet. One seed covers every key
/// set the wallet has now or provisions later, so binding the entry to a key
/// manifest would leave every key set minted afterwards outside the recovery
/// set the codes open.
pub fn seal_wallet_recovery_entry_v1(
    manifest_kek: &[u8],
    wallet_id: &str,
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

/// One stored recovery wrap, as the caller read it back.
pub struct WalletRecoveryManifestKekWrapV1<'a> {
    /// The id the wrap was stored under.
    pub recovery_key_id: &'a str,
    /// The wrap's nonce.
    pub nonce: &'a [u8],
    /// The wrapped manifest KEK.
    pub ciphertext: &'a [u8],
}

/// Opens a wallet's custody seed with one recovery code.
///
/// **The code never selects its own wrap.** Its id is derived here from the
/// wallet and the code bytes, then matched against the stored set — so a
/// caller cannot point a code at a wrap it does not open, and a code for
/// another wallet finds nothing rather than being tried against every row.
///
/// Two levels, as frozen: the code opens the manifest KEK, and the manifest
/// KEK opens the seed entry. A code never wraps the seed directly, which is
/// what lets one code be consumed or revoked without touching the other nine.
///
/// Returns `None` when no wrap bears this code's id — the "wrong code" answer,
/// kept distinct from a decryption failure so a caller can tell a mistyped
/// code from a corrupt record.
pub fn open_wallet_custody_seed_with_recovery_code_v1(
    wallet_id: &str,
    recovery_code_bytes: &[u8],
    wraps: &[WalletRecoveryManifestKekWrapV1<'_>],
    entry_nonce: &[u8],
    entry_ciphertext: &[u8],
) -> CoreResult<Option<Zeroizing<Vec<u8>>>> {
    let wallet_id = wallet_id.trim();
    require_field("walletId", wallet_id)?;
    let recovery_key_id = derive_wallet_recovery_key_id_v1(wallet_id, recovery_code_bytes)?;

    let Some(wrap) = wraps
        .iter()
        .find(|candidate| candidate.recovery_key_id == recovery_key_id)
    else {
        return Ok(None);
    };

    let manifest_kek = open_wallet_recovery_manifest_kek_v1(
        recovery_code_bytes,
        &WalletRecoveryCodeScopeV1 {
            wallet_id: wallet_id.to_string(),
            recovery_key_id,
        },
        wrap.nonce,
        wrap.ciphertext,
    )?;

    let seed = open_wallet_recovery_entry_v1(
        &manifest_kek[..],
        &WalletRecoveryEntryScopeV1 {
            wallet_id: wallet_id.to_string(),
        },
        entry_nonce,
        entry_ciphertext,
    )?;
    Ok(Some(seed))
}
