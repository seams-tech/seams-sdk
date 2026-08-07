//! Owner signing-root derivation from the wallet custody seed.
//!
//! ```text
//! seed --HKDF(ed25519 label)--> Ed25519 Yao Client root
//! seed --HKDF(ecdsa   label)--> Router A/B ECDSA client root share
//! ```
//!
//! Both roots take the seed directly as IKM under distinct salts. Neither is a
//! function of the other: chaining one signing root off another is exactly the
//! key-separation defect removed from the Email OTP runtime, where holding the
//! Ed25519 root also yielded the ECDSA share.
//!
//! Derivation alone is not sufficient to publish a capability. The seed's
//! envelope records a `keyManifestDigest` naming the exact owner key set the
//! seed must reproduce; [`verify_wallet_key_manifest_v1`] recomputes that
//! digest from the derived public identities and fails closed on mismatch.

use base64ct::{Base64UrlUnpadded, Encoding};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{CoreResult, SignerCoreError};

pub const WALLET_CUSTODY_SEED_LEN: usize = 32;
pub const WALLET_SIGNING_ROOT_LEN: usize = 32;

const ED25519_CLIENT_ROOT_SALT_V1: &[u8] = b"seams/wallet-custody/seed/ed25519-yao-client-root/v1";
const ECDSA_CLIENT_ROOT_SHARE_SALT_V1: &[u8] =
    b"seams/wallet-custody/seed/ecdsa-client-root-share/v1";
const WALLET_KEY_MANIFEST_CONTEXT_V1: &[u8] = b"seams/wallet-custody/key-manifest/v1";

const MAX_FIELD_LEN: usize = 512;

fn require_field(label: &str, value: &str) -> CoreResult<()> {
    if value.is_empty() {
        return Err(SignerCoreError::invalid_input(format!(
            "{label} must not be empty"
        )));
    }
    if value.len() > MAX_FIELD_LEN {
        return Err(SignerCoreError::invalid_input(format!(
            "{label} exceeds the maximum field length"
        )));
    }
    Ok(())
}

fn require_seed(seed: &[u8]) -> CoreResult<()> {
    if seed.len() != WALLET_CUSTODY_SEED_LEN {
        return Err(SignerCoreError::invalid_length(format!(
            "wallet custody seed must be {WALLET_CUSTODY_SEED_LEN} bytes"
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

fn expand(seed: &[u8], salt: &[u8], info: &[u8]) -> CoreResult<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), seed);
    let mut out = Zeroizing::new([0u8; WALLET_SIGNING_ROOT_LEN]);
    hkdf.expand(info, &mut out[..])
        .map_err(|_| SignerCoreError::hkdf_error("wallet seed derivation failed"))?;
    Ok(out)
}

/// Derives the Ed25519 Yao Client root directly from the seed.
///
/// Bound to the Yao application binding digest, exactly as the PRF-derived root
/// it replaces was. That digest already covers the wallet, NEAR signing key,
/// signing root, and key-creation signer slot, so swapping the seed in for
/// `PRF.first` changes the secret input and nothing about what the root is
/// bound to.
pub fn derive_ed25519_yao_client_root_from_seed_v1(
    seed: &[u8],
    application_binding_digest: &[u8; 32],
) -> CoreResult<Zeroizing<[u8; WALLET_SIGNING_ROOT_LEN]>> {
    require_seed(seed)?;
    let mut info = Vec::new();
    labeled_field(
        &mut info,
        b"applicationBindingDigest",
        application_binding_digest,
    );
    let root = expand(seed, ED25519_CLIENT_ROOT_SALT_V1, &info);
    info.clear();
    root
}

/// Derives the Router A/B ECDSA client root share directly from the seed.
///
/// Takes the ECDSA stable-key application binding digest, mirroring the Ed25519
/// derivation above. Both curves therefore bind to the digest their own
/// protocol computes and verifies, so a caller cannot derive against a binding
/// the protocol does not share. The digest already carries the wallet and
/// EVM-family slot identity, which embeds the Router A/B signing root id and
/// version.
///
/// This is strictly more binding than the PRF-derived share it replaces, which
/// used a fixed salt and info and was bound to nothing but the PRF itself.
pub fn derive_ecdsa_client_root_share_from_seed_v1(
    seed: &[u8],
    application_binding_digest: &[u8; 32],
) -> CoreResult<Zeroizing<[u8; WALLET_SIGNING_ROOT_LEN]>> {
    require_seed(seed)?;
    let mut info = Vec::new();
    labeled_field(
        &mut info,
        b"applicationBindingDigest",
        application_binding_digest,
    );
    let share = expand(seed, ECDSA_CLIENT_ROOT_SHARE_SALT_V1, &info);
    info.clear();
    share
}

/// The exact owner key set one custody seed must reproduce.
///
/// Public identities only: this is what a recovered seed is checked against, so
/// it can be recomputed from derivation output plus registered public facts
/// without holding any secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletKeyManifestV1 {
    pub wallet_id: String,
    pub near_ed25519_signing_key_id: String,
    pub registered_public_key: [u8; 32],
    pub evm_family_signing_key_slot_id: String,
    pub client_root_public_key33: [u8; 33],
}

/// Canonical manifest digest. Length-delimited labeled fields, so no two
/// distinct manifests encode alike.
pub fn compute_wallet_key_manifest_digest_v1(
    manifest: &WalletKeyManifestV1,
) -> CoreResult<[u8; 32]> {
    let wallet_id = manifest.wallet_id.trim();
    let signing_key_id = manifest.near_ed25519_signing_key_id.trim();
    let slot_id = manifest.evm_family_signing_key_slot_id.trim();
    require_field("walletId", wallet_id)?;
    require_field("nearEd25519SigningKeyId", signing_key_id)?;
    require_field("evmFamilySigningKeySlotId", slot_id)?;
    if manifest.client_root_public_key33[0] != 0x02 && manifest.client_root_public_key33[0] != 0x03
    {
        return Err(SignerCoreError::invalid_input(
            "clientRootPublicKey33 must be a compressed secp256k1 point",
        ));
    }

    let mut out = Vec::new();
    labeled_field(&mut out, b"context", WALLET_KEY_MANIFEST_CONTEXT_V1);
    labeled_str(&mut out, b"walletId", wallet_id);
    labeled_str(&mut out, b"nearEd25519SigningKeyId", signing_key_id);
    labeled_field(
        &mut out,
        b"registeredPublicKey",
        &manifest.registered_public_key,
    );
    labeled_str(&mut out, b"evmFamilySigningKeySlotId", slot_id);
    labeled_field(
        &mut out,
        b"clientRootPublicKey33",
        &manifest.client_root_public_key33,
    );

    let mut hasher = Sha256::new();
    hasher.update(&out);
    Ok(hasher.finalize().into())
}

pub fn wallet_key_manifest_digest_b64u(digest: &[u8; 32]) -> String {
    Base64UrlUnpadded::encode_string(digest)
}

/// Fail-closed manifest check.
///
/// A recovered or cold-unlocked seed must reproduce the exact owner key set its
/// envelope claims. Exactly-one-seed plus a stored digest proves nothing on its
/// own — the digest is recorded at seal time and never verified by the record
/// parser — so this comparison is what stands between an opened seed and a
/// published capability. Callers must run it before publishing any capability
/// or consuming a recovery code, and must abort on error rather than
/// continuing with partial results.
pub fn verify_wallet_key_manifest_v1(
    manifest: &WalletKeyManifestV1,
    expected_digest: &[u8],
) -> CoreResult<()> {
    let actual = compute_wallet_key_manifest_digest_v1(manifest)?;
    if actual.as_slice() != expected_digest {
        return Err(SignerCoreError::invalid_input(
            "derived wallet key manifest does not match the sealed key manifest digest",
        ));
    }
    Ok(())
}

/// Both owner signing roots, derived together from one seed.
///
/// Registration derives them as a pair so the two cannot be produced from
/// different seeds or in different orders by separate call sites. The struct
/// zeroizes on drop; neither field is exposed by value.
pub struct WalletSeedOwnerRootsV1 {
    ed25519_yao_client_root: Zeroizing<[u8; WALLET_SIGNING_ROOT_LEN]>,
    ecdsa_client_root_share: Zeroizing<[u8; WALLET_SIGNING_ROOT_LEN]>,
}

impl WalletSeedOwnerRootsV1 {
    pub fn ed25519_yao_client_root(&self) -> &[u8; WALLET_SIGNING_ROOT_LEN] {
        &self.ed25519_yao_client_root
    }

    pub fn ecdsa_client_root_share(&self) -> &[u8; WALLET_SIGNING_ROOT_LEN] {
        &self.ecdsa_client_root_share
    }
}

impl core::fmt::Debug for WalletSeedOwnerRootsV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("WalletSeedOwnerRootsV1([REDACTED])")
    }
}

/// Derives every owner signing root for one registration.
///
/// Each curve is bound to the application binding digest its own protocol
/// computes, so a caller passes digests it obtained from those protocols rather
/// than assembling bindings itself.
pub fn derive_wallet_seed_owner_roots_v1(
    seed: &[u8],
    ed25519_application_binding_digest: &[u8; 32],
    ecdsa_application_binding_digest: &[u8; 32],
) -> CoreResult<WalletSeedOwnerRootsV1> {
    // Two protocols, two digests. Equal digests would mean one of them was not
    // the protocol's own, and the roots would then differ only by salt.
    if ed25519_application_binding_digest == ecdsa_application_binding_digest {
        return Err(SignerCoreError::invalid_input(
            "Ed25519 and ECDSA application binding digests must differ",
        ));
    }
    Ok(WalletSeedOwnerRootsV1 {
        ed25519_yao_client_root: derive_ed25519_yao_client_root_from_seed_v1(
            seed,
            ed25519_application_binding_digest,
        )?,
        ecdsa_client_root_share: derive_ecdsa_client_root_share_from_seed_v1(
            seed,
            ecdsa_application_binding_digest,
        )?,
    })
}

/// The registration gate: a seed may publish capability only for the exact key
/// set it reproduces.
///
/// Callers pass the public identities the two protocols actually returned. This
/// rebuilds the canonical manifest, compares its digest with the one the seed
/// envelope was sealed against, and returns the digest only on success — so a
/// caller that ignores the `Result` still has no digest to record.
pub fn verify_registered_wallet_key_manifest_v1(
    manifest: &WalletKeyManifestV1,
    sealed_key_manifest_digest: &[u8],
) -> CoreResult<[u8; 32]> {
    verify_wallet_key_manifest_v1(manifest, sealed_key_manifest_digest)?;
    compute_wallet_key_manifest_digest_v1(manifest)
}
