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
//! Derivation alone is not sufficient to publish a capability. Each owner key
//! set records its own manifest naming the exact identities the seed must
//! reproduce for it; [`verify_wallet_key_set_manifest_v1`] recomputes that
//! digest from the derived public identities and fails closed on mismatch.
//!
//! The manifest is per key set, not per seed. Key sets are provisioned
//! independently — an EVM wallet today, NEAR later — so a seed that named its
//! key sets would have to be resealed every time one arrived.

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
const ED25519_LOCAL_MATERIAL_CACHE_SALT_V1: &[u8] =
    b"seams/wallet-custody/seed/ed25519-local-material-cache/v1";
const NEAR_ED25519_KEY_SET_MANIFEST_CONTEXT_V1: &[u8] =
    b"seams/wallet-custody/key-set-manifest/near-ed25519/v1";
const EVM_FAMILY_KEY_SET_MANIFEST_CONTEXT_V1: &[u8] =
    b"seams/wallet-custody/key-set-manifest/evm-family-ecdsa/v1";

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

/// Derives the wrapping key for the Ed25519 same-device continuity cache.
///
/// **This is not a signing root, and the distinction is the point.** The two
/// derivations above produce key material a protocol signs with. This one
/// produces a wrapping key for a local record that only ever *re-opens*
/// material the protocol already activated — Constraint 13's continuity cache,
/// never a source of truth. Its own salt keeps it from colliding with either
/// root, so holding the cache key yields no signing capability at all.
///
/// Keyed off the seed rather than a factor because that is what makes the cache
/// factor-agnostic. A wallet that registered under a passkey and later enrolled
/// Email OTP reaches the same cache under either, because both factors already
/// open the envelope this seed comes out of. A per-factor wrapping key would
/// give the second factor a guaranteed cache miss on every unlock and force a
/// Router round to reproduce material the device is already holding.
///
/// Bound to the same application binding digest as the Ed25519 root, so the
/// cache for one key set cannot open another's record.
pub fn derive_ed25519_local_material_cache_key_from_seed_v1(
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
    let key = expand(seed, ED25519_LOCAL_MATERIAL_CACHE_SALT_V1, &info);
    info.clear();
    key
}

/// Which owner key set a manifest describes.
///
/// Key sets are provisioned independently, so each records its own manifest and
/// each is verified on its own. A missing record is not an error — it means
/// that key set has not been provisioned yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletKeySetKindV1 {
    NearEd25519,
    EvmFamilyEcdsa,
}

impl WalletKeySetKindV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NearEd25519 => "near_ed25519_v1",
            Self::EvmFamilyEcdsa => "evm_family_ecdsa_v1",
        }
    }

    /// An unknown kind is rejected rather than defaulted, so a future key set
    /// cannot silently inherit another's manifest scope.
    pub fn parse(value: &str) -> CoreResult<Self> {
        match value {
            "near_ed25519_v1" => Ok(Self::NearEd25519),
            "evm_family_ecdsa_v1" => Ok(Self::EvmFamilyEcdsa),
            _ => Err(SignerCoreError::invalid_input(
                "unknown wallet key set kind",
            )),
        }
    }
}

/// The exact key identities one key set must reproduce.
///
/// Public identities only: this is what a recovered seed is checked against, so
/// it can be recomputed from derivation output plus registered public facts
/// without holding any secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletKeySetManifestV1 {
    NearEd25519 {
        wallet_id: String,
        near_ed25519_signing_key_id: String,
        registered_public_key: [u8; 32],
    },
    EvmFamilyEcdsa {
        wallet_id: String,
        /// Embeds the Router A/B signing-root id and version, so binding it
        /// covers the signing-root identity.
        evm_family_signing_key_slot_id: String,
        client_root_public_key33: [u8; 33],
    },
}

impl WalletKeySetManifestV1 {
    pub fn key_set(&self) -> WalletKeySetKindV1 {
        match self {
            Self::NearEd25519 { .. } => WalletKeySetKindV1::NearEd25519,
            Self::EvmFamilyEcdsa { .. } => WalletKeySetKindV1::EvmFamilyEcdsa,
        }
    }

    pub fn wallet_id(&self) -> &str {
        match self {
            Self::NearEd25519 { wallet_id, .. } | Self::EvmFamilyEcdsa { wallet_id, .. } => {
                wallet_id
            }
        }
    }
}

/// Canonical manifest digest. Length-delimited labeled fields under a
/// per-key-set context, so no two manifests encode alike — not across fields,
/// and not across key sets.
pub fn compute_wallet_key_set_manifest_digest_v1(
    manifest: &WalletKeySetManifestV1,
) -> CoreResult<[u8; 32]> {
    let wallet_id = manifest.wallet_id().trim();
    require_field("walletId", wallet_id)?;

    let mut out = Vec::new();
    match manifest {
        WalletKeySetManifestV1::NearEd25519 {
            near_ed25519_signing_key_id,
            registered_public_key,
            ..
        } => {
            let signing_key_id = near_ed25519_signing_key_id.trim();
            require_field("nearEd25519SigningKeyId", signing_key_id)?;
            labeled_field(
                &mut out,
                b"context",
                NEAR_ED25519_KEY_SET_MANIFEST_CONTEXT_V1,
            );
            labeled_str(&mut out, b"walletId", wallet_id);
            labeled_str(&mut out, b"nearEd25519SigningKeyId", signing_key_id);
            labeled_field(&mut out, b"registeredPublicKey", registered_public_key);
        }
        WalletKeySetManifestV1::EvmFamilyEcdsa {
            evm_family_signing_key_slot_id,
            client_root_public_key33,
            ..
        } => {
            let slot_id = evm_family_signing_key_slot_id.trim();
            require_field("evmFamilySigningKeySlotId", slot_id)?;
            if client_root_public_key33[0] != 0x02 && client_root_public_key33[0] != 0x03 {
                return Err(SignerCoreError::invalid_input(
                    "clientRootPublicKey33 must be a compressed secp256k1 point",
                ));
            }
            labeled_field(&mut out, b"context", EVM_FAMILY_KEY_SET_MANIFEST_CONTEXT_V1);
            labeled_str(&mut out, b"walletId", wallet_id);
            labeled_str(&mut out, b"evmFamilySigningKeySlotId", slot_id);
            labeled_field(&mut out, b"clientRootPublicKey33", client_root_public_key33);
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(&out);
    Ok(hasher.finalize().into())
}

pub fn wallet_key_manifest_digest_b64u(digest: &[u8; 32]) -> String {
    Base64UrlUnpadded::encode_string(digest)
}

/// Fail-closed manifest check for one key set.
///
/// A recovered or cold-unlocked seed may publish capability for a key set only
/// if it reproduces that key set's exact identities. The record parser never
/// verifies a stored digest, so this comparison is what stands between an
/// opened seed and a published capability. Callers must run it before
/// publishing capability or consuming a recovery code, and must abort on error
/// rather than continuing with partial results.
pub fn verify_wallet_key_set_manifest_v1(
    manifest: &WalletKeySetManifestV1,
    expected_digest: &[u8],
) -> CoreResult<()> {
    let actual = compute_wallet_key_set_manifest_digest_v1(manifest)?;
    if actual.as_slice() != expected_digest {
        return Err(SignerCoreError::invalid_input(
            "derived wallet key set does not match its recorded key manifest digest",
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
/// computes. This function cannot check that the digests it receives came from
/// those protocols — a caller can always fabricate two distinct byte arrays.
/// Protocol provenance is a property of *where this is called from*, not of
/// this signature: the ceremony module computes both digests from typed
/// protocol outputs and passes them straight in, with no boundary in between at
/// which a caller could substitute its own. The equality rejection below is a
/// tripwire for the obvious mistake, not a provenance proof.
pub fn derive_wallet_seed_owner_roots_v1(
    seed: &[u8],
    ed25519_application_binding_digest: &[u8; 32],
    ecdsa_application_binding_digest: &[u8; 32],
) -> CoreResult<WalletSeedOwnerRootsV1> {
    // Two protocols, two digests. Equal digests mean one of them is not the
    // protocol's own, and the roots would then differ only by salt.
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

/// Proof that one key set's manifest was established or verified.
///
/// The fields are private and the only constructors are
/// [`establish_wallet_key_set_manifest_v1`] and
/// [`verify_registered_wallet_key_set_manifest_v1`], so a caller cannot
/// fabricate one from bytes it computed itself. Record writers take this by
/// reference instead of a `[u8; 32]`.
///
/// It carries the key set it was minted for, so a proof for one key set cannot
/// be used to write another's record.
///
/// Deliberately not `Clone`, `Copy`, `Serialize`, or `Deserialize`: a
/// within-ceremony capability, not a token to store, replay, or hand across a
/// module boundary.
#[derive(Debug)]
pub struct VerifiedWalletKeySetManifestDigestV1 {
    key_set: WalletKeySetKindV1,
    digest: [u8; 32],
}

impl VerifiedWalletKeySetManifestDigestV1 {
    pub fn key_set(&self) -> WalletKeySetKindV1 {
        self.key_set
    }

    /// The verified digest, for recording on the key set's manifest record.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn digest_b64u(&self) -> String {
        wallet_key_manifest_digest_b64u(&self.digest)
    }
}

/// Mints the proof for a key set being provisioned for the first time.
///
/// There is no prior record to reproduce, so there is nothing to compare
/// against. What makes the resulting digest trustworthy is that the manifest
/// was built from what the protocol actually returned — a property of the
/// ceremony that calls this, which no signature can enforce. It is a separate
/// function from the verifying constructor precisely so a reader can tell which
/// of the two a path took.
pub fn establish_wallet_key_set_manifest_v1(
    manifest: &WalletKeySetManifestV1,
) -> CoreResult<VerifiedWalletKeySetManifestDigestV1> {
    Ok(VerifiedWalletKeySetManifestDigestV1 {
        key_set: manifest.key_set(),
        digest: compute_wallet_key_set_manifest_digest_v1(manifest)?,
    })
}

/// The gate for a key set that already has a manifest record: recovery,
/// cold unlock, and any later republish.
///
/// Rebuilds the canonical manifest from the identities the protocol returned,
/// compares its digest with the recorded one, and returns a proof only on
/// success — so a caller that ignores the `Result` has nothing to record and
/// nothing the record writers will accept.
pub fn verify_registered_wallet_key_set_manifest_v1(
    manifest: &WalletKeySetManifestV1,
    recorded_key_manifest_digest: &[u8],
) -> CoreResult<VerifiedWalletKeySetManifestDigestV1> {
    let digest = compute_wallet_key_set_manifest_digest_v1(manifest)?;
    if digest.as_slice() != recorded_key_manifest_digest {
        return Err(SignerCoreError::invalid_input(
            "derived wallet key set does not match its recorded key manifest digest",
        ));
    }
    Ok(VerifiedWalletKeySetManifestDigestV1 {
        key_set: manifest.key_set(),
        digest,
    })
}
