use core::fmt;

use sha2::{Digest, Sha256};

use crate::ApplicationBindingDigest;

/// Domain separating the Yao application binding from prior HSS bindings.
pub const ED25519_YAO_APPLICATION_BINDING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/application-binding/v1";

/// Canonical wallet-identity field label.
pub const ED25519_YAO_APPLICATION_BINDING_WALLET_ID_LABEL_V1: &[u8] = b"walletId";

/// Canonical Ed25519 signing-key-identity field label.
pub const ED25519_YAO_APPLICATION_BINDING_SIGNING_KEY_ID_LABEL_V1: &[u8] =
    b"nearEd25519SigningKeyId";

/// Canonical logical signing-root-identity field label.
pub const ED25519_YAO_APPLICATION_BINDING_SIGNING_ROOT_ID_LABEL_V1: &[u8] = b"signingRootId";

/// Canonical immutable key-creation signer-slot field label.
pub const ED25519_YAO_APPLICATION_BINDING_KEY_CREATION_SIGNER_SLOT_LABEL_V1: &[u8] =
    b"keyCreationSignerSlot";

/// Identity field rejected at the application-binding boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed25519YaoApplicationBindingFieldV1 {
    /// Durable wallet identity.
    WalletId,
    /// Stable NEAR Ed25519 signing-key identity.
    NearEd25519SigningKeyId,
    /// Stable logical signing-root identity.
    SigningRootId,
    /// Signer slot fixed when this wallet key is created.
    KeyCreationSignerSlot,
}

impl fmt::Display for Ed25519YaoApplicationBindingFieldV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WalletId => formatter.write_str("walletId"),
            Self::NearEd25519SigningKeyId => formatter.write_str("nearEd25519SigningKeyId"),
            Self::SigningRootId => formatter.write_str("signingRootId"),
            Self::KeyCreationSignerSlot => formatter.write_str("keyCreationSignerSlot"),
        }
    }
}

/// Validation failure for one immutable application-binding identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed25519YaoApplicationBindingErrorV1 {
    /// The identifier was empty.
    Empty {
        /// Field containing the empty identifier.
        field: Ed25519YaoApplicationBindingFieldV1,
    },
    /// The identifier contained a byte outside visible ASCII.
    InvalidIdentifierGrammar {
        /// Field containing the invalid identifier.
        field: Ed25519YaoApplicationBindingFieldV1,
    },
    /// The identifier cannot be represented by the frozen U32 length prefix.
    ValueTooLong {
        /// Field containing the oversized identifier.
        field: Ed25519YaoApplicationBindingFieldV1,
    },
    /// The immutable key-creation signer slot was zero.
    ZeroKeyCreationSignerSlot,
}

impl fmt::Display for Ed25519YaoApplicationBindingErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { field } => write!(formatter, "{field} must be non-empty"),
            Self::InvalidIdentifierGrammar { field } => {
                write!(
                    formatter,
                    "{field} must contain only visible ASCII bytes 0x21 through 0x7e"
                )
            }
            Self::ValueTooLong { field } => {
                write!(
                    formatter,
                    "{field} exceeds the U32 length-delimited encoding"
                )
            }
            Self::ZeroKeyCreationSignerSlot => {
                formatter.write_str("keyCreationSignerSlot must be a positive U32")
            }
        }
    }
}

impl std::error::Error for Ed25519YaoApplicationBindingErrorV1 {}

fn validate_identifier(
    value: &str,
    field: Ed25519YaoApplicationBindingFieldV1,
) -> Result<(), Ed25519YaoApplicationBindingErrorV1> {
    if value.is_empty() {
        return Err(Ed25519YaoApplicationBindingErrorV1::Empty { field });
    }
    if u32::try_from(value.len()).is_err() {
        return Err(Ed25519YaoApplicationBindingErrorV1::ValueTooLong { field });
    }
    if !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(Ed25519YaoApplicationBindingErrorV1::InvalidIdentifierGrammar { field });
    }
    Ok(())
}

/// Validated durable wallet identity used by the Yao application binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519YaoApplicationBindingWalletIdV1(String);

impl Ed25519YaoApplicationBindingWalletIdV1 {
    /// Validates an exact visible-ASCII wallet identifier.
    pub fn parse(value: &str) -> Result<Self, Ed25519YaoApplicationBindingErrorV1> {
        validate_identifier(value, Ed25519YaoApplicationBindingFieldV1::WalletId)?;
        Ok(Self(value.to_owned()))
    }

    /// Returns the exact identifier committed by the binding.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated stable Ed25519 signing-key identity used by the Yao binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519YaoApplicationBindingSigningKeyIdV1(String);

impl Ed25519YaoApplicationBindingSigningKeyIdV1 {
    /// Validates an exact visible-ASCII Ed25519 signing-key identifier.
    pub fn parse(value: &str) -> Result<Self, Ed25519YaoApplicationBindingErrorV1> {
        validate_identifier(
            value,
            Ed25519YaoApplicationBindingFieldV1::NearEd25519SigningKeyId,
        )?;
        Ok(Self(value.to_owned()))
    }

    /// Returns the exact identifier committed by the binding.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated stable logical signing-root identity used by the Yao binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519YaoApplicationBindingSigningRootIdV1(String);

impl Ed25519YaoApplicationBindingSigningRootIdV1 {
    /// Validates an exact visible-ASCII logical signing-root identifier.
    pub fn parse(value: &str) -> Result<Self, Ed25519YaoApplicationBindingErrorV1> {
        validate_identifier(value, Ed25519YaoApplicationBindingFieldV1::SigningRootId)?;
        Ok(Self(value.to_owned()))
    }

    /// Returns the exact identifier committed by the binding.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Positive signer slot fixed at wallet-key creation time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519YaoApplicationBindingKeyCreationSignerSlotV1(u32);

impl Ed25519YaoApplicationBindingKeyCreationSignerSlotV1 {
    /// Validates a key-creation signer slot as a positive U32.
    pub const fn new(value: u32) -> Result<Self, Ed25519YaoApplicationBindingErrorV1> {
        if value == 0 {
            return Err(Ed25519YaoApplicationBindingErrorV1::ZeroKeyCreationSignerSlot);
        }
        Ok(Self(value))
    }

    /// Returns the immutable key-creation signer slot.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Frozen SDK-owned immutable identifiers for the Yao application binding.
///
/// Mutable versions, epochs, active or recipient slots, and ceremony metadata
/// cannot be represented by this type.
///
/// ```compile_fail
/// use ed25519_yao_generator::{
///     Ed25519YaoApplicationBindingFactsV1, Ed25519YaoApplicationBindingSigningKeyIdV1,
///     Ed25519YaoApplicationBindingSigningRootIdV1, Ed25519YaoApplicationBindingWalletIdV1,
///     Ed25519YaoApplicationBindingKeyCreationSignerSlotV1,
/// };
///
/// let wallet = Ed25519YaoApplicationBindingWalletIdV1::parse("wallet").unwrap();
/// let key = Ed25519YaoApplicationBindingSigningKeyIdV1::parse("ed25519ks_key").unwrap();
/// let root = Ed25519YaoApplicationBindingSigningRootIdV1::parse("project:env").unwrap();
/// let slot = Ed25519YaoApplicationBindingKeyCreationSignerSlotV1::new(1).unwrap();
/// let signing_root_version = "v2";
/// let _ = Ed25519YaoApplicationBindingFactsV1::new(
///     wallet, key, root, slot, signing_root_version,
/// );
/// ```
///
/// ```compile_fail
/// use ed25519_yao_generator::{
///     Ed25519YaoApplicationBindingFactsV1, Ed25519YaoApplicationBindingSigningKeyIdV1,
///     Ed25519YaoApplicationBindingSigningRootIdV1, Ed25519YaoApplicationBindingWalletIdV1,
///     Ed25519YaoApplicationBindingKeyCreationSignerSlotV1,
/// };
///
/// let wallet = Ed25519YaoApplicationBindingWalletIdV1::parse("wallet").unwrap();
/// let key = Ed25519YaoApplicationBindingSigningKeyIdV1::parse("ed25519ks_key").unwrap();
/// let root = Ed25519YaoApplicationBindingSigningRootIdV1::parse("project:env").unwrap();
/// let slot = Ed25519YaoApplicationBindingKeyCreationSignerSlotV1::new(1).unwrap();
/// let _ = Ed25519YaoApplicationBindingFactsV1::new(key, wallet, root, slot);
/// ```
pub struct Ed25519YaoApplicationBindingFactsV1 {
    wallet_id: Ed25519YaoApplicationBindingWalletIdV1,
    signing_key_id: Ed25519YaoApplicationBindingSigningKeyIdV1,
    signing_root_id: Ed25519YaoApplicationBindingSigningRootIdV1,
    key_creation_signer_slot: Ed25519YaoApplicationBindingKeyCreationSignerSlotV1,
}

impl Ed25519YaoApplicationBindingFactsV1 {
    /// Constructs the only supported immutable identifier set.
    pub fn new(
        wallet_id: Ed25519YaoApplicationBindingWalletIdV1,
        signing_key_id: Ed25519YaoApplicationBindingSigningKeyIdV1,
        signing_root_id: Ed25519YaoApplicationBindingSigningRootIdV1,
        key_creation_signer_slot: Ed25519YaoApplicationBindingKeyCreationSignerSlotV1,
    ) -> Self {
        Self {
            wallet_id,
            signing_key_id,
            signing_root_id,
            key_creation_signer_slot,
        }
    }

    /// Encodes the frozen domain and ordered labeled visible-ASCII fields.
    pub fn encode(&self) -> Ed25519YaoApplicationBindingBytesV1 {
        let mut bytes = Vec::new();
        push_length_delimited(&mut bytes, ED25519_YAO_APPLICATION_BINDING_DOMAIN_V1);
        push_labeled_field(
            &mut bytes,
            ED25519_YAO_APPLICATION_BINDING_WALLET_ID_LABEL_V1,
            self.wallet_id.as_str().as_bytes(),
        );
        push_labeled_field(
            &mut bytes,
            ED25519_YAO_APPLICATION_BINDING_SIGNING_KEY_ID_LABEL_V1,
            self.signing_key_id.as_str().as_bytes(),
        );
        push_labeled_field(
            &mut bytes,
            ED25519_YAO_APPLICATION_BINDING_SIGNING_ROOT_ID_LABEL_V1,
            self.signing_root_id.as_str().as_bytes(),
        );
        push_labeled_field(
            &mut bytes,
            ED25519_YAO_APPLICATION_BINDING_KEY_CREATION_SIGNER_SLOT_LABEL_V1,
            &self.key_creation_signer_slot.get().to_be_bytes(),
        );
        Ed25519YaoApplicationBindingBytesV1(bytes)
    }

    /// Computes SHA-256 over the frozen canonical encoding.
    pub fn digest(&self) -> ApplicationBindingDigest {
        let encoded = self.encode();
        let digest: [u8; 32] = Sha256::digest(encoded.as_bytes()).into();
        ApplicationBindingDigest::new(digest)
    }
}

fn push_labeled_field(out: &mut Vec<u8>, label: &[u8], value: &[u8]) {
    push_length_delimited(out, label);
    push_length_delimited(out, value);
}

fn push_length_delimited(out: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("validated binding field length fits in U32");
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
}

/// Frozen canonical byte encoding of the Yao application binding.
#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519YaoApplicationBindingBytesV1(Vec<u8>);

impl Ed25519YaoApplicationBindingBytesV1 {
    /// Returns the complete domain-separated encoding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
