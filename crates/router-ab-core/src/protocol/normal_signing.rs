use crate::derivation::PublicDigest32;
use crate::protocol::error::{
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use crate::protocol::identity::ServerIdentityV1;
use crate::protocol::lifecycle::NormalSigningScopeV1;
use crate::protocol::wire::CanonicalWireBytesV1;
use base64ct::{Base64UrlUnpadded, Encoding};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Number as JsonNumber, Value as JsonValue};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const ROUTER_AB_ED25519_NORMAL_SIGNING_INTENT_VERSION_V2: &[u8] =
    b"router-ab-protocol/ed25519-normal-signing/intent/v2";
const ROUTER_AB_ED25519_SIGNING_PAYLOAD_VERSION_V2: &[u8] =
    b"router-ab-protocol/ed25519-normal-signing/payload/v2";
const ROUTER_AB_ED25519_ROUND1_BINDING_VERSION_V2: &[u8] =
    b"router-ab-protocol/ed25519-normal-signing/round1-binding/v2";
const ROUTER_AB_ED25519_PRESIGN_POOL_ENTRY_BINDING_VERSION_V2: &[u8] =
    b"router-ab-protocol/ed25519-normal-signing/presign-pool-entry-binding/v2";
const MAX_ROUTER_AB_ED25519_PRESIGN_POOL_OFFERS_V2: usize = 64;
const NEP413_PREFIX: u32 = 2_147_484_061;
const NEP461_DELEGATE_ACTION_PREFIX: u32 = 1_073_742_190;

/// NEAR network accepted by Router A/B Ed25519 normal signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterAbNearNetworkIdV2 {
    /// NEAR testnet.
    Testnet,
    /// NEAR mainnet.
    Mainnet,
}

impl RouterAbNearNetworkIdV2 {
    /// Returns the canonical network label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet",
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct RouterAbNearAccountIdBorsh(pub(crate) String);

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct RouterAbNearPublicKeyBorsh {
    pub(crate) key_type: u8,
    pub(crate) key_data: [u8; 32],
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct RouterAbNearSignatureBorsh {
    pub(crate) key_type: u8,
    pub(crate) signature_data: [u8; 64],
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct RouterAbNearCryptoHashBorsh(pub(crate) [u8; 32]);

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct RouterAbNearFunctionCallActionBorsh {
    pub(crate) method_name: String,
    pub(crate) args: Vec<u8>,
    pub(crate) gas: u64,
    pub(crate) deposit: u128,
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct RouterAbNearAccessKeyBorsh {
    pub(crate) nonce: u64,
    pub(crate) permission: RouterAbNearAccessKeyPermissionBorsh,
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub(crate) enum RouterAbNearAccessKeyPermissionBorsh {
    FunctionCall(RouterAbNearFunctionCallPermissionBorsh),
    FullAccess,
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct RouterAbNearFunctionCallPermissionBorsh {
    pub(crate) allowance: Option<u128>,
    pub(crate) receiver_id: String,
    pub(crate) method_names: Vec<String>,
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub(crate) enum RouterAbNearGlobalContractDeployModeBorsh {
    CodeHash,
    AccountId,
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub(crate) enum RouterAbNearGlobalContractIdentifierBorsh {
    CodeHash(RouterAbNearCryptoHashBorsh),
    AccountId(RouterAbNearAccountIdBorsh),
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub(crate) enum RouterAbNearActionBorsh {
    CreateAccount,
    DeployContract {
        code: Vec<u8>,
    },
    FunctionCall(Box<RouterAbNearFunctionCallActionBorsh>),
    Transfer {
        deposit: u128,
    },
    Stake {
        stake: u128,
        public_key: RouterAbNearPublicKeyBorsh,
    },
    AddKey {
        public_key: RouterAbNearPublicKeyBorsh,
        access_key: RouterAbNearAccessKeyBorsh,
    },
    DeleteKey {
        public_key: RouterAbNearPublicKeyBorsh,
    },
    DeleteAccount {
        beneficiary_id: RouterAbNearAccountIdBorsh,
    },
    SignedDelegate(Box<RouterAbNearSignedDelegateBorsh>),
    DeployGlobalContract {
        code: Vec<u8>,
        deploy_mode: RouterAbNearGlobalContractDeployModeBorsh,
    },
    UseGlobalContract {
        contract_identifier: RouterAbNearGlobalContractIdentifierBorsh,
    },
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct RouterAbNearTransactionBorsh {
    pub(crate) signer_id: RouterAbNearAccountIdBorsh,
    pub(crate) public_key: RouterAbNearPublicKeyBorsh,
    pub(crate) nonce: u64,
    pub(crate) receiver_id: RouterAbNearAccountIdBorsh,
    pub(crate) block_hash: RouterAbNearCryptoHashBorsh,
    pub(crate) actions: Vec<RouterAbNearActionBorsh>,
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct RouterAbNearDelegateActionBorsh {
    pub(crate) sender_id: RouterAbNearAccountIdBorsh,
    pub(crate) receiver_id: RouterAbNearAccountIdBorsh,
    pub(crate) actions: Vec<RouterAbNearActionBorsh>,
    pub(crate) nonce: u64,
    pub(crate) max_block_height: u64,
    pub(crate) public_key: RouterAbNearPublicKeyBorsh,
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct RouterAbNearSignedDelegateBorsh {
    pub(crate) delegate_action: RouterAbNearDelegateActionBorsh,
    pub(crate) signature: RouterAbNearSignatureBorsh,
}

pub fn router_ab_near_transaction_action_fingerprint_from_unsigned_borsh_b64u_v2(
    unsigned_transaction_borsh_b64u: &str,
) -> RouterAbProtocolResult<String> {
    let transaction = decode_near_transaction_from_b64u(
        "unsigned_transaction_borsh_b64u",
        unsigned_transaction_borsh_b64u,
    )?;
    router_ab_normal_signing_action_fingerprint_v2(&transaction.actions)
}

pub fn router_ab_delegate_action_fingerprint_from_canonical_borsh_b64u_v2(
    canonical_delegate_borsh_b64u: &str,
) -> RouterAbProtocolResult<String> {
    let delegate = decode_delegate_action_from_b64u(
        "canonical_delegate_borsh_b64u",
        canonical_delegate_borsh_b64u,
    )?;
    router_ab_normal_signing_action_fingerprint_v2(&delegate.actions)
}

/// Display and policy metadata for one NEAR transaction in a normal-signing request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbNearTransactionIntentV1 {
    /// Transaction receiver account.
    pub receiver_id: String,
    /// Canonical fingerprint of the action set displayed to the user.
    pub action_fingerprint: String,
}

impl RouterAbNearTransactionIntentV1 {
    /// Creates validated NEAR transaction intent metadata.
    pub fn new(
        receiver_id: impl Into<String>,
        action_fingerprint: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let intent = Self {
            receiver_id: receiver_id.into(),
            action_fingerprint: action_fingerprint.into(),
        };
        intent.validate()?;
        Ok(intent)
    }

    /// Validates required transaction display fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("transaction.receiver_id", &self.receiver_id)?;
        require_non_empty("transaction.action_fingerprint", &self.action_fingerprint)
    }

    fn push_canonical_bytes(&self, out: &mut Vec<u8>) {
        push_len32(out, self.receiver_id.as_bytes());
        push_len32(out, self.action_fingerprint.as_bytes());
    }
}

/// Policy metadata for one NEP-461 delegate action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbNearDelegateActionIntentV1 {
    /// Account authorizing the delegate action.
    pub sender_id: String,
    /// Account receiving the delegated action.
    pub receiver_id: String,
    /// Delegate public key in NEAR public-key string form.
    pub public_key: String,
    /// Delegate action nonce as a decimal string.
    pub nonce: String,
    /// Maximum block height as a decimal string.
    pub max_block_height: String,
    /// Canonical fingerprint of delegated actions displayed to the user.
    pub action_fingerprint: String,
    /// Canonical NEP-461 delegate-action preimage encoded as unpadded base64url.
    pub canonical_delegate_borsh_b64u: String,
}

impl RouterAbNearDelegateActionIntentV1 {
    /// Creates validated delegate-action intent metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sender_id: impl Into<String>,
        receiver_id: impl Into<String>,
        public_key: impl Into<String>,
        nonce: impl Into<String>,
        max_block_height: impl Into<String>,
        action_fingerprint: impl Into<String>,
        canonical_delegate_borsh_b64u: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let intent = Self {
            sender_id: sender_id.into(),
            receiver_id: receiver_id.into(),
            public_key: public_key.into(),
            nonce: nonce.into(),
            max_block_height: max_block_height.into(),
            action_fingerprint: action_fingerprint.into(),
            canonical_delegate_borsh_b64u: canonical_delegate_borsh_b64u.into(),
        };
        intent.validate()?;
        Ok(intent)
    }

    /// Validates required delegate-action fields and canonical preimage encoding.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("delegate.sender_id", &self.sender_id)?;
        require_non_empty("delegate.receiver_id", &self.receiver_id)?;
        require_non_empty("delegate.public_key", &self.public_key)?;
        require_non_empty("delegate.nonce", &self.nonce)?;
        require_non_empty("delegate.max_block_height", &self.max_block_height)?;
        require_non_empty("delegate.action_fingerprint", &self.action_fingerprint)?;
        require_non_empty(
            "delegate.canonical_delegate_borsh_b64u",
            &self.canonical_delegate_borsh_b64u,
        )?;
        decode_base64url_nonempty(
            "delegate.canonical_delegate_borsh_b64u",
            &self.canonical_delegate_borsh_b64u,
        )?;
        Ok(())
    }

    fn push_canonical_bytes(&self, out: &mut Vec<u8>) {
        push_len32(out, self.sender_id.as_bytes());
        push_len32(out, self.receiver_id.as_bytes());
        push_len32(out, self.public_key.as_bytes());
        push_len32(out, self.nonce.as_bytes());
        push_len32(out, self.max_block_height.as_bytes());
        push_len32(out, self.action_fingerprint.as_bytes());
        push_len32(out, self.canonical_delegate_borsh_b64u.as_bytes());
    }
}

/// Branch-specific typed intent for Router A/B Ed25519 normal signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum RouterAbEd25519NormalSigningIntentV2 {
    /// NEAR transaction signing intent.
    NearTransactionV1 {
        /// Operation id assigned by the SDK.
        operation_id: String,
        /// Stable operation fingerprint displayed and confirmed by the user.
        operation_fingerprint: String,
        /// Account that owns the signing session.
        near_account_id: String,
        /// NEAR network.
        near_network_id: RouterAbNearNetworkIdV2,
        /// Typed transaction display metadata.
        transactions: Vec<RouterAbNearTransactionIntentV1>,
        /// Unsigned transaction Borsh preimage encoded as unpadded base64url.
        unsigned_transaction_borsh_b64u: String,
    },
    /// NEP-413 message signing intent.
    Nep413V1 {
        /// Operation id assigned by the SDK.
        operation_id: String,
        /// Stable operation fingerprint displayed and confirmed by the user.
        operation_fingerprint: String,
        /// Account that owns the signing session.
        near_account_id: String,
        /// NEAR network.
        near_network_id: RouterAbNearNetworkIdV2,
        /// NEP-413 recipient.
        recipient: String,
        /// NEP-413 message.
        message: String,
        /// NEP-413 nonce encoded as unpadded base64url.
        nonce_b64u: String,
        /// Optional NEP-413 callback/state URL.
        callback_url: Option<String>,
    },
    /// NEP-461 delegate-action signing intent.
    NearDelegateActionV1 {
        /// Operation id assigned by the SDK.
        operation_id: String,
        /// Stable operation fingerprint displayed and confirmed by the user.
        operation_fingerprint: String,
        /// Account that owns the signing session.
        near_account_id: String,
        /// NEAR network.
        near_network_id: RouterAbNearNetworkIdV2,
        /// Delegate-action policy metadata.
        delegate: RouterAbNearDelegateActionIntentV1,
    },
}

impl RouterAbEd25519NormalSigningIntentV2 {
    /// Validates required fields and branch-specific preimage references.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::NearTransactionV1 {
                operation_id,
                operation_fingerprint,
                near_account_id,
                transactions,
                unsigned_transaction_borsh_b64u,
                ..
            } => {
                validate_operation_fields(operation_id, operation_fingerprint, near_account_id)?;
                if transactions.is_empty() {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MalformedWirePayload,
                        "near transaction intent requires at least one transaction",
                    ));
                }
                for transaction in transactions {
                    transaction.validate()?;
                }
                decode_base64url_nonempty(
                    "unsigned_transaction_borsh_b64u",
                    unsigned_transaction_borsh_b64u,
                )?;
                Ok(())
            }
            Self::Nep413V1 {
                operation_id,
                operation_fingerprint,
                near_account_id,
                recipient,
                message,
                nonce_b64u,
                callback_url,
                ..
            } => {
                validate_operation_fields(operation_id, operation_fingerprint, near_account_id)?;
                require_non_empty("nep413.recipient", recipient)?;
                require_non_empty("nep413.message", message)?;
                decode_base64url_fixed_32("nep413.nonce_b64u", nonce_b64u)?;
                if let Some(callback_url) = callback_url {
                    require_non_empty("nep413.callback_url", callback_url)?;
                }
                Ok(())
            }
            Self::NearDelegateActionV1 {
                operation_id,
                operation_fingerprint,
                near_account_id,
                delegate,
                ..
            } => {
                validate_operation_fields(operation_id, operation_fingerprint, near_account_id)?;
                if delegate.sender_id != *near_account_id {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLifecycleState,
                        "delegate sender_id must match near_account_id",
                    ));
                }
                delegate.validate()
            }
        }
    }

    /// Returns canonical intent bytes for Router admission.
    pub fn canonical_intent_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        push_len32(&mut out, ROUTER_AB_ED25519_NORMAL_SIGNING_INTENT_VERSION_V2);
        match self {
            Self::NearTransactionV1 {
                operation_id,
                operation_fingerprint,
                near_account_id,
                near_network_id,
                transactions,
                unsigned_transaction_borsh_b64u,
            } => {
                push_len32(&mut out, b"near_transaction_v1");
                push_normal_intent_common(
                    &mut out,
                    operation_id,
                    operation_fingerprint,
                    near_account_id,
                    *near_network_id,
                );
                push_u32(&mut out, transactions.len() as u32);
                for transaction in transactions {
                    transaction.push_canonical_bytes(&mut out);
                }
                push_len32(&mut out, unsigned_transaction_borsh_b64u.as_bytes());
            }
            Self::Nep413V1 {
                operation_id,
                operation_fingerprint,
                near_account_id,
                near_network_id,
                recipient,
                message,
                nonce_b64u,
                callback_url,
            } => {
                push_len32(&mut out, b"nep413_v1");
                push_normal_intent_common(
                    &mut out,
                    operation_id,
                    operation_fingerprint,
                    near_account_id,
                    *near_network_id,
                );
                push_len32(&mut out, recipient.as_bytes());
                push_len32(&mut out, message.as_bytes());
                push_len32(&mut out, nonce_b64u.as_bytes());
                push_optional_string(&mut out, callback_url.as_deref());
            }
            Self::NearDelegateActionV1 {
                operation_id,
                operation_fingerprint,
                near_account_id,
                near_network_id,
                delegate,
            } => {
                push_len32(&mut out, b"near_delegate_action_v1");
                push_normal_intent_common(
                    &mut out,
                    operation_id,
                    operation_fingerprint,
                    near_account_id,
                    *near_network_id,
                );
                delegate.push_canonical_bytes(&mut out);
            }
        }
        Ok(out)
    }

    /// Returns the SHA-256 digest of canonical intent bytes.
    pub fn intent_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        Ok(public_digest(&self.canonical_intent_bytes()?))
    }
}

/// Branch-specific signing payload for Router A/B Ed25519 normal signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum RouterAbEd25519SigningPayloadV2 {
    /// Unsigned NEAR transaction Borsh preimage.
    NearUnsignedTransactionBorshV1 {
        /// Unsigned transaction Borsh encoded as unpadded base64url.
        unsigned_transaction_borsh_b64u: String,
        /// Expected SHA-256 signing digest encoded as unpadded base64url.
        expected_signing_digest_b64u: String,
    },
    /// Canonical NEP-413 signing preimage.
    Nep413MessageV1 {
        /// Canonical NEP-413 prefixed Borsh payload encoded as unpadded base64url.
        canonical_message_b64u: String,
        /// Expected SHA-256 signing digest encoded as unpadded base64url.
        expected_signing_digest_b64u: String,
    },
    /// Canonical NEP-461 delegate-action signing preimage.
    NearDelegateActionV1 {
        /// Canonical delegate-action Borsh encoded as unpadded base64url.
        canonical_delegate_borsh_b64u: String,
        /// Expected SHA-256 signing digest encoded as unpadded base64url.
        expected_signing_digest_b64u: String,
    },
}

impl RouterAbEd25519SigningPayloadV2 {
    /// Validates the payload preimage and expected digest cross-check.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.admitted_signing_digest().map(|_| ())
    }

    /// Returns canonical signing-payload bytes for Router admission.
    pub fn canonical_signing_payload_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        push_len32(&mut out, ROUTER_AB_ED25519_SIGNING_PAYLOAD_VERSION_V2);
        match self {
            Self::NearUnsignedTransactionBorshV1 {
                unsigned_transaction_borsh_b64u,
                expected_signing_digest_b64u,
            } => {
                push_len32(&mut out, b"near_unsigned_transaction_borsh_v1");
                push_len32(&mut out, unsigned_transaction_borsh_b64u.as_bytes());
                push_len32(&mut out, expected_signing_digest_b64u.as_bytes());
            }
            Self::Nep413MessageV1 {
                canonical_message_b64u,
                expected_signing_digest_b64u,
            } => {
                push_len32(&mut out, b"nep413_message_v1");
                push_len32(&mut out, canonical_message_b64u.as_bytes());
                push_len32(&mut out, expected_signing_digest_b64u.as_bytes());
            }
            Self::NearDelegateActionV1 {
                canonical_delegate_borsh_b64u,
                expected_signing_digest_b64u,
            } => {
                push_len32(&mut out, b"near_delegate_action_v1");
                push_len32(&mut out, canonical_delegate_borsh_b64u.as_bytes());
                push_len32(&mut out, expected_signing_digest_b64u.as_bytes());
            }
        }
        Ok(out)
    }

    /// Returns the SHA-256 digest of canonical signing-payload bytes.
    pub fn signing_payload_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        Ok(public_digest(&self.canonical_signing_payload_bytes()?))
    }

    /// Returns the 32-byte message digest admitted for Ed25519 signing.
    pub fn admitted_signing_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        let (field, preimage_b64u, expected_b64u) = match self {
            Self::NearUnsignedTransactionBorshV1 {
                unsigned_transaction_borsh_b64u,
                expected_signing_digest_b64u,
            } => (
                "unsigned_transaction_borsh_b64u",
                unsigned_transaction_borsh_b64u,
                expected_signing_digest_b64u,
            ),
            Self::Nep413MessageV1 {
                canonical_message_b64u,
                expected_signing_digest_b64u,
            } => (
                "canonical_message_b64u",
                canonical_message_b64u,
                expected_signing_digest_b64u,
            ),
            Self::NearDelegateActionV1 {
                canonical_delegate_borsh_b64u,
                expected_signing_digest_b64u,
            } => (
                "canonical_delegate_borsh_b64u",
                canonical_delegate_borsh_b64u,
                expected_signing_digest_b64u,
            ),
        };
        let preimage = decode_base64url_nonempty(field, preimage_b64u)?;
        let expected = PublicDigest32::new(decode_base64url_fixed_32(
            "expected_signing_digest_b64u",
            expected_b64u,
        )?);
        let admitted = public_digest(&preimage);
        if admitted == expected {
            return Ok(admitted);
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "expected signing digest does not match signing payload preimage",
        ))
    }

    fn preimage_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        match self {
            Self::NearUnsignedTransactionBorshV1 {
                unsigned_transaction_borsh_b64u,
                ..
            } => decode_base64url_nonempty(
                "unsigned_transaction_borsh_b64u",
                unsigned_transaction_borsh_b64u,
            ),
            Self::Nep413MessageV1 {
                canonical_message_b64u,
                ..
            } => decode_base64url_nonempty("canonical_message_b64u", canonical_message_b64u),
            Self::NearDelegateActionV1 {
                canonical_delegate_borsh_b64u,
                ..
            } => decode_base64url_nonempty(
                "canonical_delegate_borsh_b64u",
                canonical_delegate_borsh_b64u,
            ),
        }
    }
}

/// Router-derived admission material for one typed normal-signing request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterAbEd25519NormalSigningAdmissionMaterialV2 {
    /// Digest of the canonical typed intent.
    pub intent_digest: PublicDigest32,
    /// Digest of the canonical typed signing payload.
    pub signing_payload_digest: PublicDigest32,
    /// Exact 32-byte digest admitted for the SigningWorker finalizer.
    pub admitted_signing_digest: PublicDigest32,
}

impl RouterAbEd25519NormalSigningAdmissionMaterialV2 {
    /// Returns the round-1 binding digest for a prepared SigningWorker nonce.
    pub fn round1_binding_digest(
        &self,
        scope: &NormalSigningScopeV1,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<PublicDigest32> {
        Ok(public_digest(
            &router_ab_ed25519_normal_signing_round1_binding_bytes_v2(scope, expires_at_ms, self)?,
        ))
    }
}

/// Client-facing typed prepare request after Router boundary parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519NormalSigningPrepareRequestV2 {
    /// Normal signing identity and active SigningWorker scope.
    pub scope: NormalSigningScopeV1,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Typed normal-signing intent.
    pub intent: RouterAbEd25519NormalSigningIntentV2,
    /// Typed signing payload.
    pub signing_payload: RouterAbEd25519SigningPayloadV2,
}

impl RouterAbEd25519NormalSigningPrepareRequestV2 {
    /// Creates a validated typed prepare request.
    pub fn new(
        scope: NormalSigningScopeV1,
        expires_at_ms: u64,
        intent: RouterAbEd25519NormalSigningIntentV2,
        signing_payload: RouterAbEd25519SigningPayloadV2,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            scope,
            expires_at_ms,
            intent,
            signing_payload,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates the typed prepare request without consulting clock state.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        require_positive_ms(
            "normal signing v2 prepare expires_at_ms",
            self.expires_at_ms,
        )?;
        derive_router_ab_ed25519_normal_signing_admission_material_v2(
            &self.intent,
            &self.signing_payload,
        )?;
        Ok(())
    }

    /// Validates the typed prepare request against Router time.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "normal signing v2 prepare request expired",
            ));
        }
        Ok(())
    }

    /// Returns Router-derived admission material for this prepare request.
    pub fn admission_material(
        &self,
    ) -> RouterAbProtocolResult<RouterAbEd25519NormalSigningAdmissionMaterialV2> {
        derive_router_ab_ed25519_normal_signing_admission_material_v2(
            &self.intent,
            &self.signing_payload,
        )
    }

    /// Returns the round-1 binding digest for the typed prepare request.
    pub fn round1_binding_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        self.admission_material()?
            .round1_binding_digest(&self.scope, self.expires_at_ms)
    }
}

/// Parses and validates a raw JSON v2 prepare request at the public Router boundary.
pub fn parse_router_ab_ed25519_normal_signing_prepare_request_v2_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEd25519NormalSigningPrepareRequestV2> {
    let request = parse_normal_signing_boundary_json_v2::<
        RouterAbEd25519NormalSigningPrepareRequestV2,
    >("normal signing v2 prepare request", bytes)?;
    request.validate()?;
    Ok(request)
}

/// Client-offered Ed25519/FROST round-1 material for Router A/B presign-pool refill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519PresignPoolClientOfferV2 {
    /// Client-selected presign id tracked by the SDK pool.
    pub client_presign_id: String,
    /// Client-local nonce handle needed to produce the final signature share.
    pub client_nonce_handle: String,
    /// Client public round-1 commitments.
    pub client_commitments: NormalSigningEd25519TwoPartyFrostCommitmentsV1,
    /// Client verifying share used later to verify the client signature share.
    pub client_verifying_share_b64u: String,
}

impl RouterAbEd25519PresignPoolClientOfferV2 {
    /// Creates a validated client presign-pool offer.
    pub fn new(
        client_presign_id: impl Into<String>,
        client_nonce_handle: impl Into<String>,
        client_commitments: NormalSigningEd25519TwoPartyFrostCommitmentsV1,
        client_verifying_share_b64u: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let offer = Self {
            client_presign_id: client_presign_id.into(),
            client_nonce_handle: client_nonce_handle.into(),
            client_commitments,
            client_verifying_share_b64u: client_verifying_share_b64u.into(),
        };
        offer.validate()?;
        Ok(offer)
    }

    /// Validates required offer fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("client_presign_id", &self.client_presign_id)?;
        require_non_empty("client_nonce_handle", &self.client_nonce_handle)?;
        require_non_empty(
            "client_verifying_share_b64u",
            &self.client_verifying_share_b64u,
        )?;
        self.client_commitments.validate()
    }
}

/// Wallet Session authenticated Router A/B Ed25519 presign-pool refill request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519PresignPoolPrepareRequestV2 {
    /// Normal signing identity and active SigningWorker scope.
    pub scope: NormalSigningScopeV1,
    /// Expiry for accepted unbound pool records.
    pub expires_at_ms: u64,
    /// SDK pool generation used to reject stale refill results.
    pub generation: u64,
    /// Client-generated message-agnostic commitment offers.
    pub client_offers: Vec<RouterAbEd25519PresignPoolClientOfferV2>,
}

impl RouterAbEd25519PresignPoolPrepareRequestV2 {
    /// Creates a validated Router A/B Ed25519 presign-pool refill request.
    pub fn new(
        scope: NormalSigningScopeV1,
        expires_at_ms: u64,
        generation: u64,
        client_offers: Vec<RouterAbEd25519PresignPoolClientOfferV2>,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            scope,
            expires_at_ms,
            generation,
            client_offers,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates the pool refill request without consulting clock state.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        require_positive_ms("presign pool expires_at_ms", self.expires_at_ms)?;
        require_positive_ms("presign pool generation", self.generation)?;
        if self.client_offers.is_empty() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "presign pool refill requires at least one client offer",
            ));
        }
        if self.client_offers.len() > MAX_ROUTER_AB_ED25519_PRESIGN_POOL_OFFERS_V2 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                "presign pool refill carries too many client offers",
            ));
        }
        let mut client_presign_ids = BTreeSet::new();
        let mut client_nonce_handles = BTreeSet::new();
        for offer in &self.client_offers {
            offer.validate()?;
            if !client_presign_ids.insert(offer.client_presign_id.as_str()) {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                    "presign pool refill client_presign_id is duplicated",
                ));
            }
            if !client_nonce_handles.insert(offer.client_nonce_handle.as_str()) {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                    "presign pool refill client_nonce_handle is duplicated",
                ));
            }
        }
        Ok(())
    }

    /// Validates the pool refill request against Router time.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "presign pool refill request expired",
            ));
        }
        Ok(())
    }

    /// Returns a message-agnostic digest binding one client offer to this pool refill scope.
    pub fn pool_entry_binding_digest(
        &self,
        offer: &RouterAbEd25519PresignPoolClientOfferV2,
    ) -> RouterAbProtocolResult<PublicDigest32> {
        router_ab_ed25519_presign_pool_entry_binding_digest_v2(
            &self.scope,
            self.expires_at_ms,
            self.generation,
            offer,
        )
    }
}

/// Parses and validates a raw JSON v2 presign-pool refill request.
pub fn parse_router_ab_ed25519_presign_pool_prepare_request_v2_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEd25519PresignPoolPrepareRequestV2> {
    let request = parse_normal_signing_boundary_json_v2::<
        RouterAbEd25519PresignPoolPrepareRequestV2,
    >("normal signing v2 presign-pool prepare request", bytes)?;
    request.validate()?;
    Ok(request)
}

/// SigningWorker-accepted server side of one Router A/B Ed25519 presign-pool offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519PresignPoolAcceptedEntryV2 {
    /// Client-selected presign id accepted by the SigningWorker.
    pub client_presign_id: String,
    /// SDK pool generation accepted by the SigningWorker.
    pub generation: u64,
    /// Message-agnostic binding digest for the accepted client offer.
    pub pool_entry_binding_digest: PublicDigest32,
    /// Active SigningWorker identity that prepared the server nonces.
    pub signing_worker: ServerIdentityV1,
    /// SigningWorker-local handle for the stored unbound round-1 server nonces.
    pub server_round1_handle: String,
    /// Server public round-1 commitments.
    pub server_commitments: NormalSigningEd25519TwoPartyFrostCommitmentsV1,
    /// Server verifying share used by the client to construct its signature share.
    pub server_verifying_share_b64u: String,
    /// Signature scheme this prepared state supports.
    pub signature_scheme: NormalSigningSignatureSchemeV1,
    /// Prepare timestamp in Unix milliseconds.
    pub prepared_at_ms: u64,
    /// Expiry timestamp in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl RouterAbEd25519PresignPoolAcceptedEntryV2 {
    /// Creates a validated accepted presign-pool entry.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_presign_id: impl Into<String>,
        generation: u64,
        pool_entry_binding_digest: PublicDigest32,
        signing_worker: ServerIdentityV1,
        server_round1_handle: impl Into<String>,
        server_commitments: NormalSigningEd25519TwoPartyFrostCommitmentsV1,
        server_verifying_share_b64u: impl Into<String>,
        signature_scheme: NormalSigningSignatureSchemeV1,
        prepared_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let entry = Self {
            client_presign_id: client_presign_id.into(),
            generation,
            pool_entry_binding_digest,
            signing_worker,
            server_round1_handle: server_round1_handle.into(),
            server_commitments,
            server_verifying_share_b64u: server_verifying_share_b64u.into(),
            signature_scheme,
            prepared_at_ms,
            expires_at_ms,
        };
        entry.validate()?;
        Ok(entry)
    }

    /// Validates accepted entry identity and timing fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("accepted.client_presign_id", &self.client_presign_id)?;
        require_positive_ms("accepted.generation", self.generation)?;
        self.signing_worker.validate()?;
        require_non_empty("server_round1_handle", &self.server_round1_handle)?;
        self.server_commitments.validate()?;
        require_non_empty(
            "server_verifying_share_b64u",
            &self.server_verifying_share_b64u,
        )?;
        require_positive_ms("accepted.prepared_at_ms", self.prepared_at_ms)?;
        require_positive_ms("accepted.expires_at_ms", self.expires_at_ms)?;
        if self.expires_at_ms <= self.prepared_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "accepted presign pool entry expiry must be after prepare time",
            ));
        }
        Ok(())
    }

    /// Validates this accepted entry against its originating refill request and offer.
    pub fn validate_for_offer(
        &self,
        request: &RouterAbEd25519PresignPoolPrepareRequestV2,
        offer: &RouterAbEd25519PresignPoolClientOfferV2,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        offer.validate()?;
        if self.client_presign_id == offer.client_presign_id
            && self.generation == request.generation
            && self.pool_entry_binding_digest == request.pool_entry_binding_digest(offer)?
            && self.signing_worker.server_id == request.scope.signing_worker_id
            && self.expires_at_ms == request.expires_at_ms
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "accepted presign pool entry does not match refill request",
        ))
    }
}

/// Router A/B Ed25519 presign-pool refill response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519PresignPoolPrepareResponseV2 {
    /// Normal signing identity and active SigningWorker scope.
    pub scope: NormalSigningScopeV1,
    /// SDK pool generation accepted by the SigningWorker.
    pub generation: u64,
    /// Accepted server-backed presign entries.
    pub accepted: Vec<RouterAbEd25519PresignPoolAcceptedEntryV2>,
    /// Client presign ids rejected by the SigningWorker.
    pub rejected_client_presign_ids: Vec<String>,
}

impl RouterAbEd25519PresignPoolPrepareResponseV2 {
    /// Creates a validated Router A/B Ed25519 presign-pool refill response.
    pub fn new(
        scope: NormalSigningScopeV1,
        generation: u64,
        accepted: Vec<RouterAbEd25519PresignPoolAcceptedEntryV2>,
        rejected_client_presign_ids: Vec<String>,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self {
            scope,
            generation,
            accepted,
            rejected_client_presign_ids,
        };
        response.validate()?;
        Ok(response)
    }

    /// Validates accepted/rejected identity and duplicate handling.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        require_positive_ms("presign pool response generation", self.generation)?;
        let mut accepted_ids = BTreeSet::new();
        let mut server_handles = BTreeSet::new();
        for entry in &self.accepted {
            entry.validate()?;
            if entry.generation != self.generation {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLifecycleState,
                    "accepted presign pool entry generation does not match response",
                ));
            }
            if entry.signing_worker.server_id != self.scope.signing_worker_id {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLifecycleState,
                    "accepted presign pool entry SigningWorker does not match response scope",
                ));
            }
            if !accepted_ids.insert(entry.client_presign_id.as_str()) {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                    "accepted presign pool client_presign_id is duplicated",
                ));
            }
            if !server_handles.insert(entry.server_round1_handle.as_str()) {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                    "accepted presign pool server_round1_handle is duplicated",
                ));
            }
        }
        let mut rejected_ids = BTreeSet::new();
        for rejected in &self.rejected_client_presign_ids {
            require_non_empty("rejected_client_presign_id", rejected)?;
            if !rejected_ids.insert(rejected.as_str()) {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                    "rejected presign pool client_presign_id is duplicated",
                ));
            }
            if accepted_ids.contains(rejected.as_str()) {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                    "presign pool client_presign_id cannot be both accepted and rejected",
                ));
            }
        }
        Ok(())
    }

    /// Validates this response against the originating pool refill request.
    pub fn validate_for_request(
        &self,
        request: &RouterAbEd25519PresignPoolPrepareRequestV2,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.scope != request.scope || self.generation != request.generation {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "presign pool response scope or generation does not match request",
            ));
        }
        for entry in &self.accepted {
            let offer = request
                .client_offers
                .iter()
                .find(|offer| offer.client_presign_id == entry.client_presign_id)
                .ok_or_else(|| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                        "accepted presign pool entry has no matching client offer",
                    )
                })?;
            entry.validate_for_offer(request, offer)?;
        }
        for rejected in &self.rejected_client_presign_ids {
            if !request
                .client_offers
                .iter()
                .any(|offer| offer.client_presign_id == *rejected)
            {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                    "rejected presign pool id has no matching client offer",
                ));
            }
        }
        Ok(())
    }
}

/// Parses and validates a raw JSON v2 presign-pool refill response.
pub fn parse_router_ab_ed25519_presign_pool_prepare_response_v2_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEd25519PresignPoolPrepareResponseV2> {
    let response = parse_normal_signing_boundary_json_v2::<
        RouterAbEd25519PresignPoolPrepareResponseV2,
    >("normal signing v2 presign-pool prepare response", bytes)?;
    response.validate()?;
    Ok(response)
}

/// Prepare output binding carried by a typed v2 finalize request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519NormalSigningPrepareBindingV2 {
    /// SigningWorker-local handle for the stored round-1 server nonces.
    pub server_round1_handle: String,
    /// Round-1 binding digest returned by prepare.
    pub round1_binding_digest: PublicDigest32,
    /// Intent digest admitted during prepare.
    pub intent_digest: PublicDigest32,
    /// Signing-payload digest admitted during prepare.
    pub signing_payload_digest: PublicDigest32,
}

impl RouterAbEd25519NormalSigningPrepareBindingV2 {
    /// Creates a validated v2 prepare binding.
    pub fn new(
        server_round1_handle: impl Into<String>,
        round1_binding_digest: PublicDigest32,
        intent_digest: PublicDigest32,
        signing_payload_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        let binding = Self {
            server_round1_handle: server_round1_handle.into(),
            round1_binding_digest,
            intent_digest,
            signing_payload_digest,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates required prepare binding fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty(
            "prepare_binding.server_round1_handle",
            &self.server_round1_handle,
        )
    }
}

/// Final Ed25519/FROST material for a typed v2 finalize request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519TwoPartyFrostFinalizeProtocolV2 {
    /// Client round-1 commitments.
    pub client_commitments: NormalSigningEd25519TwoPartyFrostCommitmentsV1,
    /// Server round-1 commitments returned for this server nonce handle.
    pub server_commitments: NormalSigningEd25519TwoPartyFrostCommitmentsV1,
    /// Client verifying share used to verify the client signature share.
    pub client_verifying_share_b64u: String,
    /// Server verifying share used to verify the server signature share.
    pub server_verifying_share_b64u: String,
    /// Client signature share over the Router-admitted signing digest.
    pub client_signature_share_b64u: String,
}

impl RouterAbEd25519TwoPartyFrostFinalizeProtocolV2 {
    /// Creates validated Ed25519/FROST v2 finalization material.
    pub fn new(
        client_commitments: NormalSigningEd25519TwoPartyFrostCommitmentsV1,
        server_commitments: NormalSigningEd25519TwoPartyFrostCommitmentsV1,
        client_verifying_share_b64u: impl Into<String>,
        server_verifying_share_b64u: impl Into<String>,
        client_signature_share_b64u: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let protocol = Self {
            client_commitments,
            server_commitments,
            client_verifying_share_b64u: client_verifying_share_b64u.into(),
            server_verifying_share_b64u: server_verifying_share_b64u.into(),
            client_signature_share_b64u: client_signature_share_b64u.into(),
        };
        protocol.validate()?;
        Ok(protocol)
    }

    /// Validates required Ed25519/FROST finalization fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty(
            "client_verifying_share_b64u",
            &self.client_verifying_share_b64u,
        )?;
        require_non_empty(
            "server_verifying_share_b64u",
            &self.server_verifying_share_b64u,
        )?;
        require_non_empty(
            "client_signature_share_b64u",
            &self.client_signature_share_b64u,
        )?;
        self.client_commitments.validate()?;
        self.server_commitments.validate()
    }
}

/// Role-separated finalize protocol material supplied by a v2 client request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum RouterAbEd25519NormalSigningFinalizeProtocolV2 {
    /// Final Ed25519/FROST step after the SigningWorker has created round-1 nonces.
    Ed25519TwoPartyFrostFinalizeV1(RouterAbEd25519TwoPartyFrostFinalizeProtocolV2),
}

impl RouterAbEd25519NormalSigningFinalizeProtocolV2 {
    /// Validates branch-specific protocol material.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Ed25519TwoPartyFrostFinalizeV1(protocol) => protocol.validate(),
        }
    }

    /// Returns the expected final signature scheme for this protocol.
    pub fn signature_scheme(&self) -> NormalSigningSignatureSchemeV1 {
        match self {
            Self::Ed25519TwoPartyFrostFinalizeV1(_) => NormalSigningSignatureSchemeV1::Ed25519V1,
        }
    }
}

/// Client-facing typed finalize request after Router boundary parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519NormalSigningFinalizeRequestV2 {
    /// Normal signing identity and active SigningWorker scope.
    pub scope: NormalSigningScopeV1,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Prepare output this finalize request must consume.
    pub prepare_binding: RouterAbEd25519NormalSigningPrepareBindingV2,
    /// Role-separated finalization material.
    pub protocol: RouterAbEd25519NormalSigningFinalizeProtocolV2,
}

/// Parses and validates a raw JSON v2 finalize request at the public Router boundary.
pub fn parse_router_ab_ed25519_normal_signing_finalize_request_v2_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEd25519NormalSigningFinalizeRequestV2> {
    let request = parse_normal_signing_boundary_json_v2::<
        RouterAbEd25519NormalSigningFinalizeRequestV2,
    >("normal signing v2 finalize request", bytes)?;
    request.validate()?;
    Ok(request)
}

impl RouterAbEd25519NormalSigningFinalizeRequestV2 {
    /// Creates a validated typed finalize request.
    pub fn new(
        scope: NormalSigningScopeV1,
        expires_at_ms: u64,
        prepare_binding: RouterAbEd25519NormalSigningPrepareBindingV2,
        protocol: RouterAbEd25519NormalSigningFinalizeProtocolV2,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            scope,
            expires_at_ms,
            prepare_binding,
            protocol,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates the typed finalize request without consulting clock state.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        require_positive_ms(
            "normal signing v2 finalize expires_at_ms",
            self.expires_at_ms,
        )?;
        self.prepare_binding.validate()?;
        self.protocol.validate()
    }

    /// Validates the typed finalize request against Router time.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "normal signing v2 finalize request expired",
            ));
        }
        Ok(())
    }

    /// Returns the prepare-time intent digest carried by finalize.
    pub fn intent_digest(&self) -> PublicDigest32 {
        self.prepare_binding.intent_digest
    }

    /// Returns the prepare-time signing-payload digest carried by finalize.
    pub fn signing_payload_digest(&self) -> PublicDigest32 {
        self.prepare_binding.signing_payload_digest
    }

    /// Returns the prepare-time round-1 binding digest carried by finalize.
    pub fn round1_binding_digest(&self) -> PublicDigest32 {
        self.prepare_binding.round1_binding_digest
    }

    /// Returns the SigningWorker-local server round-1 handle.
    pub fn server_round1_handle(&self) -> &str {
        &self.prepare_binding.server_round1_handle
    }
}

/// Pool entry selected for a one-request Router A/B Ed25519 pool-hit finalize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519PresignPoolHitBindingV2 {
    /// Client-selected presign id accepted during pool refill.
    pub client_presign_id: String,
    /// Client-local nonce handle needed to produce the final signature share.
    pub client_nonce_handle: String,
    /// SDK pool generation used when this entry was accepted.
    pub generation: u64,
    /// SigningWorker-local handle for the stored unbound round-1 server nonces.
    pub server_round1_handle: String,
    /// Message-agnostic binding digest returned by pool refill.
    pub pool_entry_binding_digest: PublicDigest32,
}

impl RouterAbEd25519PresignPoolHitBindingV2 {
    /// Creates a validated pool-hit binding.
    pub fn new(
        client_presign_id: impl Into<String>,
        client_nonce_handle: impl Into<String>,
        generation: u64,
        server_round1_handle: impl Into<String>,
        pool_entry_binding_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        let binding = Self {
            client_presign_id: client_presign_id.into(),
            client_nonce_handle: client_nonce_handle.into(),
            generation,
            server_round1_handle: server_round1_handle.into(),
            pool_entry_binding_digest,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates required pool-hit binding fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("pool_hit.client_presign_id", &self.client_presign_id)?;
        require_non_empty("pool_hit.client_nonce_handle", &self.client_nonce_handle)?;
        require_positive_ms("pool_hit.generation", self.generation)?;
        require_non_empty("pool_hit.server_round1_handle", &self.server_round1_handle)
    }
}

/// One-request Router A/B Ed25519 finalize request for a client-side presign-pool hit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519PresignPoolHitFinalizeRequestV2 {
    /// Normal signing identity and active SigningWorker scope.
    pub scope: NormalSigningScopeV1,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Selected pool entry and handles.
    pub pool_binding: RouterAbEd25519PresignPoolHitBindingV2,
    /// Typed normal-signing intent for Router admission.
    pub intent: RouterAbEd25519NormalSigningIntentV2,
    /// Typed signing payload for Router admission.
    pub signing_payload: RouterAbEd25519SigningPayloadV2,
    /// Role-separated finalization material.
    pub protocol: RouterAbEd25519NormalSigningFinalizeProtocolV2,
}

impl RouterAbEd25519PresignPoolHitFinalizeRequestV2 {
    /// Creates a validated pool-hit finalize request.
    pub fn new(
        scope: NormalSigningScopeV1,
        expires_at_ms: u64,
        pool_binding: RouterAbEd25519PresignPoolHitBindingV2,
        intent: RouterAbEd25519NormalSigningIntentV2,
        signing_payload: RouterAbEd25519SigningPayloadV2,
        protocol: RouterAbEd25519NormalSigningFinalizeProtocolV2,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            scope,
            expires_at_ms,
            pool_binding,
            intent,
            signing_payload,
            protocol,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates this pool-hit finalize request without consulting clock state.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        require_positive_ms("pool-hit finalize expires_at_ms", self.expires_at_ms)?;
        self.pool_binding.validate()?;
        derive_router_ab_ed25519_normal_signing_admission_material_v2(
            &self.intent,
            &self.signing_payload,
        )?;
        self.protocol.validate()
    }

    /// Validates the pool-hit finalize request against Router time.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "pool-hit finalize request expired",
            ));
        }
        Ok(())
    }

    /// Returns Router-derived admission material for this pool-hit finalize.
    pub fn admission_material(
        &self,
    ) -> RouterAbProtocolResult<RouterAbEd25519NormalSigningAdmissionMaterialV2> {
        derive_router_ab_ed25519_normal_signing_admission_material_v2(
            &self.intent,
            &self.signing_payload,
        )
    }

    /// Returns the round-1 binding digest after this pool entry is claimed.
    pub fn round1_binding_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        self.admission_material()?
            .round1_binding_digest(&self.scope, self.expires_at_ms)
    }

    /// Returns the selected SigningWorker-local server round-1 handle.
    pub fn server_round1_handle(&self) -> &str {
        &self.pool_binding.server_round1_handle
    }

    /// Lowers a pool-hit finalize into the existing v2 finalize shape after pool admission.
    pub fn to_normal_finalize_request_v2(
        &self,
    ) -> RouterAbProtocolResult<RouterAbEd25519NormalSigningFinalizeRequestV2> {
        self.validate()?;
        let material = self.admission_material()?;
        let prepare_binding = RouterAbEd25519NormalSigningPrepareBindingV2::new(
            self.pool_binding.server_round1_handle.clone(),
            self.round1_binding_digest()?,
            material.intent_digest,
            material.signing_payload_digest,
        )?;
        RouterAbEd25519NormalSigningFinalizeRequestV2::new(
            self.scope.clone(),
            self.expires_at_ms,
            prepare_binding,
            self.protocol.clone(),
        )
    }
}

/// Parses and validates a raw JSON v2 pool-hit finalize request.
pub fn parse_router_ab_ed25519_presign_pool_hit_finalize_request_v2_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEd25519PresignPoolHitFinalizeRequestV2> {
    let request = parse_normal_signing_boundary_json_v2::<
        RouterAbEd25519PresignPoolHitFinalizeRequestV2,
    >("normal signing v2 presign-pool hit finalize request", bytes)?;
    request.validate()?;
    Ok(request)
}

/// Derives all Router admission digests from typed normal-signing request data.
pub fn derive_router_ab_ed25519_normal_signing_admission_material_v2(
    intent: &RouterAbEd25519NormalSigningIntentV2,
    signing_payload: &RouterAbEd25519SigningPayloadV2,
) -> RouterAbProtocolResult<RouterAbEd25519NormalSigningAdmissionMaterialV2> {
    intent.validate()?;
    signing_payload.validate()?;
    validate_router_ab_ed25519_intent_payload_consistency_v2(intent, signing_payload)?;
    Ok(RouterAbEd25519NormalSigningAdmissionMaterialV2 {
        intent_digest: intent.intent_digest()?,
        signing_payload_digest: signing_payload.signing_payload_digest()?,
        admitted_signing_digest: signing_payload.admitted_signing_digest()?,
    })
}

/// Builds the canonical NEP-413 signing preimage from typed intent fields.
pub fn router_ab_ed25519_nep413_canonical_message_b64u_v2(
    message: &str,
    recipient: &str,
    nonce_b64u: &str,
    callback_url: Option<&str>,
) -> RouterAbProtocolResult<String> {
    require_non_empty("nep413.message", message)?;
    require_non_empty("nep413.recipient", recipient)?;
    if let Some(callback_url) = callback_url {
        require_non_empty("nep413.callback_url", callback_url)?;
    }
    let nonce = decode_base64url_fixed_32("nep413.nonce_b64u", nonce_b64u)?;
    let mut payload = Vec::new();
    payload.extend_from_slice(&NEP413_PREFIX.to_le_bytes());
    push_borsh_string(&mut payload, message);
    push_borsh_string(&mut payload, recipient);
    payload.extend_from_slice(&nonce);
    match callback_url {
        Some(callback_url) => {
            payload.push(1);
            push_borsh_string(&mut payload, callback_url);
        }
        None => payload.push(0),
    }
    Ok(Base64UrlUnpadded::encode_string(&payload))
}

/// Signature algorithm returned by the active SigningWorker normal-signing path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalSigningSignatureSchemeV1 {
    /// Ed25519 account signature.
    Ed25519V1,
}

impl NormalSigningSignatureSchemeV1 {
    /// Returns the canonical signature-scheme label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519V1 => "ed25519_v1",
        }
    }
}

/// Role-separated signing protocol material supplied by the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum NormalSigningProtocolV1 {
    /// Final Ed25519/FROST step after the SigningWorker has created round-1 nonces.
    Ed25519TwoPartyFrostFinalizeV1(NormalSigningEd25519TwoPartyFrostFinalizeV1),
}

impl NormalSigningProtocolV1 {
    /// Validates branch-specific protocol material.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Ed25519TwoPartyFrostFinalizeV1(protocol) => protocol.validate(),
        }
    }

    /// Returns the expected final signature scheme for this protocol.
    pub fn signature_scheme(&self) -> NormalSigningSignatureSchemeV1 {
        match self {
            Self::Ed25519TwoPartyFrostFinalizeV1(_) => NormalSigningSignatureSchemeV1::Ed25519V1,
        }
    }
}

/// Public FROST round-1 commitments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalSigningEd25519TwoPartyFrostCommitmentsV1 {
    /// Hiding commitment encoded as unpadded base64url.
    pub hiding: String,
    /// Binding commitment encoded as unpadded base64url.
    pub binding: String,
}

impl NormalSigningEd25519TwoPartyFrostCommitmentsV1 {
    /// Creates validated public FROST commitments.
    pub fn new(
        hiding: impl Into<String>,
        binding: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let commitments = Self {
            hiding: hiding.into(),
            binding: binding.into(),
        };
        commitments.validate()?;
        Ok(commitments)
    }

    /// Validates required commitment fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("commitments.hiding", &self.hiding)?;
        require_non_empty("commitments.binding", &self.binding)
    }
}

/// SigningWorker-produced response for prepared Ed25519/FROST round-1 state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalSigningRound1PrepareResponseV1 {
    /// Normal signing scope used for prepare.
    pub scope: NormalSigningScopeV1,
    /// Digest of the canonical payload bytes to sign.
    pub signing_payload_digest: PublicDigest32,
    /// Digest binding this round-1 handle to the exact signing context.
    pub round1_binding_digest: PublicDigest32,
    /// Active SigningWorker identity that prepared the nonce material.
    pub signing_worker: ServerIdentityV1,
    /// SigningWorker-local handle for the stored round-1 server nonces.
    pub server_round1_handle: String,
    /// Server public round-1 commitments.
    pub server_commitments: NormalSigningEd25519TwoPartyFrostCommitmentsV1,
    /// Server verifying share used by the client to construct its signature share.
    pub server_verifying_share_b64u: String,
    /// Signature scheme this prepared state supports.
    pub signature_scheme: NormalSigningSignatureSchemeV1,
    /// Prepare timestamp in Unix milliseconds.
    pub prepared_at_ms: u64,
    /// Expiry timestamp in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl NormalSigningRound1PrepareResponseV1 {
    /// Creates a validated round-1 prepare response.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: NormalSigningScopeV1,
        signing_payload_digest: PublicDigest32,
        round1_binding_digest: PublicDigest32,
        signing_worker: ServerIdentityV1,
        server_round1_handle: impl Into<String>,
        server_commitments: NormalSigningEd25519TwoPartyFrostCommitmentsV1,
        server_verifying_share_b64u: impl Into<String>,
        signature_scheme: NormalSigningSignatureSchemeV1,
        prepared_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self {
            scope,
            signing_payload_digest,
            round1_binding_digest,
            signing_worker,
            server_round1_handle: server_round1_handle.into(),
            server_commitments,
            server_verifying_share_b64u: server_verifying_share_b64u.into(),
            signature_scheme,
            prepared_at_ms,
            expires_at_ms,
        };
        response.validate()?;
        Ok(response)
    }

    /// Validates response identity and timing fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        self.signing_worker.validate()?;
        if self.signing_worker.server_id != self.scope.signing_worker_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "normal signing round-1 response SigningWorker does not match scope",
            ));
        }
        require_non_empty("server_round1_handle", &self.server_round1_handle)?;
        self.server_commitments.validate()?;
        require_non_empty(
            "server_verifying_share_b64u",
            &self.server_verifying_share_b64u,
        )?;
        if self.prepared_at_ms == 0 || self.expires_at_ms == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "normal signing round-1 response timestamps must be greater than zero",
            ));
        }
        if self.expires_at_ms > self.prepared_at_ms {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            "normal signing round-1 response expiry must be after prepare time",
        ))
    }

    /// Validates the response binds to a typed v2 prepare request.
    pub fn validate_for_v2_prepare_request(
        &self,
        request: &RouterAbEd25519NormalSigningPrepareRequestV2,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        let admission = request.admission_material()?;
        if self.scope == request.scope
            && self.signing_payload_digest == admission.signing_payload_digest
            && self.round1_binding_digest == request.round1_binding_digest()?
            && self.expires_at_ms == request.expires_at_ms
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "normal signing round-1 response does not match v2 prepare request",
        ))
    }
}

/// Finalization material for a two-party Ed25519/FROST normal-signing request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalSigningEd25519TwoPartyFrostFinalizeV1 {
    /// SigningWorker-local handle for the stored round-1 server nonces.
    pub server_round1_handle: String,
    /// Group public key bound to the threshold Ed25519 account.
    pub group_public_key: String,
    /// Client round-1 commitments.
    pub client_commitments: NormalSigningEd25519TwoPartyFrostCommitmentsV1,
    /// Server round-1 commitments returned for this server nonce handle.
    pub server_commitments: NormalSigningEd25519TwoPartyFrostCommitmentsV1,
    /// Client verifying share used to verify the client signature share.
    pub client_verifying_share_b64u: String,
    /// Server verifying share used to verify the server signature share.
    pub server_verifying_share_b64u: String,
    /// Client signature share over the canonical signing digest.
    pub client_signature_share_b64u: String,
}

impl NormalSigningEd25519TwoPartyFrostFinalizeV1 {
    /// Creates validated Ed25519/FROST finalization material.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server_round1_handle: impl Into<String>,
        group_public_key: impl Into<String>,
        client_commitments: NormalSigningEd25519TwoPartyFrostCommitmentsV1,
        server_commitments: NormalSigningEd25519TwoPartyFrostCommitmentsV1,
        client_verifying_share_b64u: impl Into<String>,
        server_verifying_share_b64u: impl Into<String>,
        client_signature_share_b64u: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let protocol = Self {
            server_round1_handle: server_round1_handle.into(),
            group_public_key: group_public_key.into(),
            client_commitments,
            server_commitments,
            client_verifying_share_b64u: client_verifying_share_b64u.into(),
            server_verifying_share_b64u: server_verifying_share_b64u.into(),
            client_signature_share_b64u: client_signature_share_b64u.into(),
        };
        protocol.validate()?;
        Ok(protocol)
    }

    /// Validates required Ed25519/FROST finalization fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("server_round1_handle", &self.server_round1_handle)?;
        require_non_empty("group_public_key", &self.group_public_key)?;
        require_non_empty(
            "client_verifying_share_b64u",
            &self.client_verifying_share_b64u,
        )?;
        require_non_empty(
            "server_verifying_share_b64u",
            &self.server_verifying_share_b64u,
        )?;
        require_non_empty(
            "client_signature_share_b64u",
            &self.client_signature_share_b64u,
        )?;
        self.client_commitments.validate()?;
        self.server_commitments.validate()
    }
}

/// SigningWorker activation state required before normal signing can be forwarded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveSigningWorkerStateV1 {
    /// Canonical account or wallet id.
    pub account_id: String,
    /// Canonical session id.
    pub session_id: String,
    /// Account public key bound into the activation transcript.
    pub account_public_key: String,
    /// Active SigningWorker identity.
    pub signing_worker: ServerIdentityV1,
    /// Transcript that activated the SigningWorker output.
    pub activation_transcript_digest: PublicDigest32,
    /// Digest of stored SigningWorker activation material.
    pub activation_digest: PublicDigest32,
    /// SigningWorker-local storage handle for opened signing material.
    pub signing_worker_material_handle: String,
    /// Activation timestamp in Unix milliseconds.
    pub activated_at_ms: u64,
}

impl ActiveSigningWorkerStateV1 {
    /// Creates a validated active SigningWorker state descriptor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: impl Into<String>,
        session_id: impl Into<String>,
        account_public_key: impl Into<String>,
        signing_worker: ServerIdentityV1,
        activation_transcript_digest: PublicDigest32,
        activation_digest: PublicDigest32,
        signing_worker_material_handle: impl Into<String>,
        activated_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let state = Self {
            account_id: account_id.into(),
            session_id: session_id.into(),
            account_public_key: account_public_key.into(),
            signing_worker,
            activation_transcript_digest,
            activation_digest,
            signing_worker_material_handle: signing_worker_material_handle.into(),
            activated_at_ms,
        };
        state.validate()?;
        Ok(state)
    }

    /// Validates active SigningWorker identity fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("active signing worker account_id", &self.account_id)?;
        require_non_empty("active signing worker session_id", &self.session_id)?;
        require_non_empty(
            "active signing worker account_public_key",
            &self.account_public_key,
        )?;
        require_non_empty(
            "active signing worker material handle",
            &self.signing_worker_material_handle,
        )?;
        self.signing_worker.validate()?;
        if self.activated_at_ms == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "active signing worker activated_at_ms must be greater than zero",
            ));
        }
        Ok(())
    }

    /// Validates the active SigningWorker state matches a normal-signing scope.
    pub fn validate_for_scope(&self, scope: &NormalSigningScopeV1) -> RouterAbProtocolResult<()> {
        self.validate()?;
        scope.validate()?;
        if self.account_id != scope.account_id
            || self.session_id != scope.session_id
            || self.signing_worker.server_id != scope.signing_worker_id
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "active signing worker state does not match normal signing scope",
            ));
        }
        Ok(())
    }
}

/// SigningWorker-produced normal-signing response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalSigningResponseV1 {
    /// Normal signing scope that produced the signature.
    pub scope: NormalSigningScopeV1,
    /// Digest of the canonical payload bytes that were signed.
    pub signing_payload_digest: PublicDigest32,
    /// Active SigningWorker identity used for signing.
    pub signing_worker: ServerIdentityV1,
    /// Signature scheme.
    pub signature_scheme: NormalSigningSignatureSchemeV1,
    /// Signature bytes.
    pub signature: CanonicalWireBytesV1,
    /// Signing timestamp in Unix milliseconds.
    pub signed_at_ms: u64,
}

impl NormalSigningResponseV1 {
    /// Creates a validated normal-signing response.
    pub fn new(
        scope: NormalSigningScopeV1,
        signing_payload_digest: PublicDigest32,
        signing_worker: ServerIdentityV1,
        signature_scheme: NormalSigningSignatureSchemeV1,
        signature: CanonicalWireBytesV1,
        signed_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self {
            scope,
            signing_payload_digest,
            signing_worker,
            signature_scheme,
            signature,
            signed_at_ms,
        };
        response.validate()?;
        Ok(response)
    }

    /// Validates response identity and signature metadata.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        self.signing_worker.validate()?;
        if self.signing_worker.server_id != self.scope.signing_worker_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "normal signing response SigningWorker does not match scope",
            ));
        }
        if self.signed_at_ms == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "normal signing response signed_at_ms must be greater than zero",
            ));
        }
        Ok(())
    }

    /// Validates the response binds to a typed v2 finalize request.
    pub fn validate_for_v2_finalize_request(
        &self,
        request: &RouterAbEd25519NormalSigningFinalizeRequestV2,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.scope != request.scope
            || self.signing_payload_digest != request.signing_payload_digest()
            || self.signature_scheme != request.protocol.signature_scheme()
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "normal signing response does not match v2 finalize request",
            ));
        }
        Ok(())
    }
}

fn public_digest(bytes: &[u8]) -> PublicDigest32 {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    PublicDigest32::new(out)
}

fn push_normal_signing_scope(out: &mut Vec<u8>, scope: &NormalSigningScopeV1) {
    push_len32(out, scope.request_id.as_bytes());
    push_len32(out, scope.account_id.as_bytes());
    push_len32(out, scope.session_id.as_bytes());
    push_len32(out, scope.signing_worker_id.as_bytes());
}

fn router_ab_ed25519_normal_signing_round1_binding_bytes_v2(
    scope: &NormalSigningScopeV1,
    expires_at_ms: u64,
    material: &RouterAbEd25519NormalSigningAdmissionMaterialV2,
) -> RouterAbProtocolResult<Vec<u8>> {
    scope.validate()?;
    require_positive_ms(
        "normal signing v2 round1 binding expires_at_ms",
        expires_at_ms,
    )?;
    let mut out = Vec::new();
    push_len32(&mut out, ROUTER_AB_ED25519_ROUND1_BINDING_VERSION_V2);
    push_normal_signing_scope(&mut out, scope);
    push_u64(&mut out, expires_at_ms);
    out.extend_from_slice(material.intent_digest.as_bytes());
    out.extend_from_slice(material.signing_payload_digest.as_bytes());
    out.extend_from_slice(material.admitted_signing_digest.as_bytes());
    Ok(out)
}

fn router_ab_ed25519_presign_pool_entry_binding_digest_v2(
    scope: &NormalSigningScopeV1,
    expires_at_ms: u64,
    generation: u64,
    offer: &RouterAbEd25519PresignPoolClientOfferV2,
) -> RouterAbProtocolResult<PublicDigest32> {
    scope.validate()?;
    require_positive_ms("presign pool entry binding expires_at_ms", expires_at_ms)?;
    require_positive_ms("presign pool entry binding generation", generation)?;
    offer.validate()?;
    let mut out = Vec::new();
    push_len32(
        &mut out,
        ROUTER_AB_ED25519_PRESIGN_POOL_ENTRY_BINDING_VERSION_V2,
    );
    push_normal_signing_scope(&mut out, scope);
    push_u64(&mut out, expires_at_ms);
    push_u64(&mut out, generation);
    push_len32(&mut out, offer.client_presign_id.as_bytes());
    push_len32(&mut out, offer.client_nonce_handle.as_bytes());
    push_len32(&mut out, offer.client_commitments.hiding.as_bytes());
    push_len32(&mut out, offer.client_commitments.binding.as_bytes());
    push_len32(&mut out, offer.client_verifying_share_b64u.as_bytes());
    Ok(public_digest(&out))
}

fn decode_near_transaction_from_b64u(
    field: &str,
    value: &str,
) -> RouterAbProtocolResult<RouterAbNearTransactionBorsh> {
    let bytes = decode_base64url_nonempty(field, value)?;
    borsh::from_slice(bytes.as_slice()).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must be valid unsigned NEAR transaction Borsh: {err}"),
        )
    })
}

fn decode_delegate_action_from_b64u(
    field: &str,
    value: &str,
) -> RouterAbProtocolResult<RouterAbNearDelegateActionBorsh> {
    let bytes = decode_base64url_nonempty(field, value)?;
    decode_delegate_action_from_prefixed_bytes(field, bytes.as_slice())
}

fn decode_delegate_action_from_prefixed_bytes(
    field: &str,
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbNearDelegateActionBorsh> {
    let Some(prefix_bytes) = bytes.get(..4) else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must include the NEP-461 delegate-action prefix"),
        ));
    };
    let prefix = u32::from_le_bytes(prefix_bytes.try_into().expect("prefix length checked"));
    if prefix != NEP461_DELEGATE_ACTION_PREFIX {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} has an invalid NEP-461 delegate-action prefix"),
        ));
    }
    borsh::from_slice(&bytes[4..]).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must contain a valid NEP-461 delegate action: {err}"),
        )
    })
}

fn router_ab_normal_signing_action_fingerprint_v2(
    actions: &[RouterAbNearActionBorsh],
) -> RouterAbProtocolResult<String> {
    let action_values = actions
        .iter()
        .map(near_action_fingerprint_value)
        .collect::<RouterAbProtocolResult<Vec<_>>>()?;
    let canonical_json = canonical_json_string(&JsonValue::Array(action_values))?;
    Ok(Base64UrlUnpadded::encode_string(
        public_digest(canonical_json.as_bytes()).as_bytes(),
    ))
}

fn near_action_fingerprint_value(
    action: &RouterAbNearActionBorsh,
) -> RouterAbProtocolResult<JsonValue> {
    match action {
        RouterAbNearActionBorsh::CreateAccount => Ok(json_object([(
            "action_type",
            JsonValue::String("CreateAccount".to_owned()),
        )])),
        RouterAbNearActionBorsh::DeployContract { code } => Ok(json_object([
            (
                "action_type",
                JsonValue::String("DeployContract".to_owned()),
            ),
            ("code", bytes_json_array(code)),
        ])),
        RouterAbNearActionBorsh::FunctionCall(action) => Ok(json_object([
            ("action_type", JsonValue::String("FunctionCall".to_owned())),
            (
                "args",
                JsonValue::String(utf8_action_bytes("FunctionCall.args", &action.args)?),
            ),
            ("deposit", JsonValue::String(action.deposit.to_string())),
            ("gas", JsonValue::String(action.gas.to_string())),
            ("method_name", JsonValue::String(action.method_name.clone())),
        ])),
        RouterAbNearActionBorsh::Transfer { deposit } => Ok(json_object([
            ("action_type", JsonValue::String("Transfer".to_owned())),
            ("deposit", JsonValue::String(deposit.to_string())),
        ])),
        RouterAbNearActionBorsh::Stake { stake, public_key } => Ok(json_object([
            ("action_type", JsonValue::String("Stake".to_owned())),
            (
                "public_key",
                JsonValue::String(public_key_string(public_key)?),
            ),
            ("stake", JsonValue::String(stake.to_string())),
        ])),
        RouterAbNearActionBorsh::AddKey {
            public_key,
            access_key,
        } => Ok(json_object([
            ("action_type", JsonValue::String("AddKey".to_owned())),
            (
                "access_key",
                JsonValue::String(access_key_json_string(access_key)?),
            ),
            (
                "public_key",
                JsonValue::String(public_key_string(public_key)?),
            ),
        ])),
        RouterAbNearActionBorsh::DeleteKey { public_key } => Ok(json_object([
            ("action_type", JsonValue::String("DeleteKey".to_owned())),
            (
                "public_key",
                JsonValue::String(public_key_string(public_key)?),
            ),
        ])),
        RouterAbNearActionBorsh::DeleteAccount { beneficiary_id } => Ok(json_object([
            ("action_type", JsonValue::String("DeleteAccount".to_owned())),
            (
                "beneficiary_id",
                JsonValue::String(beneficiary_id.0.clone()),
            ),
        ])),
        RouterAbNearActionBorsh::SignedDelegate(signed_delegate) => Ok(json_object([
            (
                "action_type",
                JsonValue::String("SignedDelegate".to_owned()),
            ),
            (
                "delegate_action",
                delegate_action_fingerprint_value(&signed_delegate.delegate_action)?,
            ),
            (
                "signature",
                signature_fingerprint_value(&signed_delegate.signature),
            ),
        ])),
        RouterAbNearActionBorsh::DeployGlobalContract { code, deploy_mode } => Ok(json_object([
            (
                "action_type",
                JsonValue::String("DeployGlobalContract".to_owned()),
            ),
            ("code", bytes_json_array(code)),
            (
                "deploy_mode",
                JsonValue::String(
                    match deploy_mode {
                        RouterAbNearGlobalContractDeployModeBorsh::CodeHash => "CodeHash",
                        RouterAbNearGlobalContractDeployModeBorsh::AccountId => "AccountId",
                    }
                    .to_owned(),
                ),
            ),
        ])),
        RouterAbNearActionBorsh::UseGlobalContract {
            contract_identifier,
        } => match contract_identifier {
            RouterAbNearGlobalContractIdentifierBorsh::AccountId(account_id) => Ok(json_object([
                (
                    "action_type",
                    JsonValue::String("UseGlobalContract".to_owned()),
                ),
                ("account_id", JsonValue::String(account_id.0.clone())),
            ])),
            RouterAbNearGlobalContractIdentifierBorsh::CodeHash(code_hash) => Ok(json_object([
                (
                    "action_type",
                    JsonValue::String("UseGlobalContract".to_owned()),
                ),
                (
                    "code_hash",
                    JsonValue::String(bs58::encode(code_hash.0).into_string()),
                ),
            ])),
        },
    }
}

fn delegate_action_fingerprint_value(
    delegate: &RouterAbNearDelegateActionBorsh,
) -> RouterAbProtocolResult<JsonValue> {
    let actions = delegate
        .actions
        .iter()
        .map(near_action_fingerprint_value)
        .collect::<RouterAbProtocolResult<Vec<_>>>()?;
    Ok(json_object([
        ("actions", JsonValue::Array(actions)),
        (
            "maxBlockHeight",
            JsonValue::String(delegate.max_block_height.to_string()),
        ),
        ("nonce", JsonValue::String(delegate.nonce.to_string())),
        (
            "publicKey",
            public_key_fingerprint_value(&delegate.public_key),
        ),
        (
            "receiverId",
            JsonValue::String(delegate.receiver_id.0.clone()),
        ),
        ("senderId", JsonValue::String(delegate.sender_id.0.clone())),
    ]))
}

fn public_key_fingerprint_value(public_key: &RouterAbNearPublicKeyBorsh) -> JsonValue {
    json_object([
        ("keyData", bytes_json_array(&public_key.key_data)),
        (
            "keyType",
            JsonValue::Number(JsonNumber::from(public_key.key_type)),
        ),
    ])
}

fn signature_fingerprint_value(signature: &RouterAbNearSignatureBorsh) -> JsonValue {
    json_object([
        (
            "keyType",
            JsonValue::Number(JsonNumber::from(signature.key_type)),
        ),
        ("signatureData", bytes_json_array(&signature.signature_data)),
    ])
}

fn access_key_json_string(
    access_key: &RouterAbNearAccessKeyBorsh,
) -> RouterAbProtocolResult<String> {
    let permission = match &access_key.permission {
        RouterAbNearAccessKeyPermissionBorsh::FullAccess => {
            json_object([("FullAccess", json_object([]))])
        }
        RouterAbNearAccessKeyPermissionBorsh::FunctionCall(permission) => json_object([(
            "FunctionCall",
            json_object([
                (
                    "allowance",
                    permission
                        .allowance
                        .map(|allowance| JsonValue::String(allowance.to_string()))
                        .unwrap_or(JsonValue::Null),
                ),
                (
                    "methodNames",
                    JsonValue::Array(
                        permission
                            .method_names
                            .iter()
                            .map(|method| JsonValue::String(method.clone()))
                            .collect(),
                    ),
                ),
                (
                    "receiverId",
                    JsonValue::String(permission.receiver_id.clone()),
                ),
            ]),
        )]),
    };
    canonical_json_string(&json_object([
        (
            "nonce",
            JsonValue::Number(JsonNumber::from(access_key.nonce)),
        ),
        ("permission", permission),
    ]))
}

fn public_key_string(public_key: &RouterAbNearPublicKeyBorsh) -> RouterAbProtocolResult<String> {
    if public_key.key_type != 0 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "NEAR action public key must be Ed25519",
        ));
    }
    Ok(format!(
        "ed25519:{}",
        bs58::encode(public_key.key_data).into_string()
    ))
}

fn utf8_action_bytes(field: &str, bytes: &[u8]) -> RouterAbProtocolResult<String> {
    String::from_utf8(bytes.to_vec()).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must be valid UTF-8: {err}"),
        )
    })
}

fn bytes_json_array(bytes: &[u8]) -> JsonValue {
    JsonValue::Array(
        bytes
            .iter()
            .map(|byte| JsonValue::Number(JsonNumber::from(*byte)))
            .collect(),
    )
}

fn json_object<const N: usize>(entries: [(&str, JsonValue); N]) -> JsonValue {
    let mut map = JsonMap::new();
    for (key, value) in entries {
        map.insert(key.to_owned(), value);
    }
    JsonValue::Object(map)
}

fn canonical_json_string(value: &JsonValue) -> RouterAbProtocolResult<String> {
    match value {
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::String(_) => {
            serde_json::to_string(value).map_err(json_canonicalization_error)
        }
        JsonValue::Array(values) => {
            let mut out = String::from("[");
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&canonical_json_string(value)?);
            }
            out.push(']');
            Ok(out)
        }
        JsonValue::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort();
            let mut out = String::from("{");
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(
                    &serde_json::to_string(key.as_str()).map_err(json_canonicalization_error)?,
                );
                out.push(':');
                out.push_str(&canonical_json_string(&map[*key])?);
            }
            out.push('}');
            Ok(out)
        }
    }
}

fn json_canonicalization_error(err: serde_json::Error) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("failed to canonicalize action fingerprint JSON: {err}"),
    )
}

fn ensure_equal_string(field: &str, expected: &str, actual: &str) -> RouterAbProtocolResult<()> {
    if expected == actual {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("{field} does not match parsed signing preimage"),
    ))
}

fn validate_router_ab_ed25519_intent_payload_consistency_v2(
    intent: &RouterAbEd25519NormalSigningIntentV2,
    signing_payload: &RouterAbEd25519SigningPayloadV2,
) -> RouterAbProtocolResult<()> {
    match (intent, signing_payload) {
        (
            RouterAbEd25519NormalSigningIntentV2::NearTransactionV1 {
                near_account_id,
                transactions,
                unsigned_transaction_borsh_b64u,
                ..
            },
            RouterAbEd25519SigningPayloadV2::NearUnsignedTransactionBorshV1 { .. },
        ) => {
            let intent_preimage = decode_base64url_nonempty(
                "intent.unsigned_transaction_borsh_b64u",
                unsigned_transaction_borsh_b64u,
            )?;
            if intent_preimage != signing_payload.preimage_bytes()? {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    "NEAR transaction intent preimage does not match signing payload",
                ));
            }
            if transactions.len() != 1 {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    "NEAR transaction intent must describe exactly one unsigned transaction",
                ));
            }
            let parsed = borsh::from_slice::<RouterAbNearTransactionBorsh>(&intent_preimage)
                .map_err(|err| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MalformedWirePayload,
                        format!(
                            "unsigned_transaction_borsh_b64u must be valid unsigned NEAR transaction Borsh: {err}"
                        ),
                    )
                })?;
            let transaction = &transactions[0];
            ensure_equal_string(
                "near transaction signer_id",
                near_account_id,
                &parsed.signer_id.0,
            )?;
            ensure_equal_string(
                "near transaction receiver_id",
                &transaction.receiver_id,
                &parsed.receiver_id.0,
            )?;
            let action_fingerprint =
                router_ab_normal_signing_action_fingerprint_v2(&parsed.actions)?;
            ensure_equal_string(
                "near transaction action_fingerprint",
                &transaction.action_fingerprint,
                &action_fingerprint,
            )
        }
        (
            RouterAbEd25519NormalSigningIntentV2::Nep413V1 {
                recipient,
                message,
                nonce_b64u,
                callback_url,
                ..
            },
            RouterAbEd25519SigningPayloadV2::Nep413MessageV1 { .. },
        ) => {
            let expected = router_ab_ed25519_nep413_canonical_message_b64u_v2(
                message,
                recipient,
                nonce_b64u,
                callback_url.as_deref(),
            )?;
            let expected_preimage =
                decode_base64url_nonempty("computed nep413 canonical message", &expected)?;
            if expected_preimage == signing_payload.preimage_bytes()? {
                return Ok(());
            }
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "NEP-413 intent preimage does not match signing payload",
            ))
        }
        (
            RouterAbEd25519NormalSigningIntentV2::NearDelegateActionV1 {
                near_account_id,
                delegate,
                ..
            },
            RouterAbEd25519SigningPayloadV2::NearDelegateActionV1 { .. },
        ) => {
            let intent_preimage = decode_base64url_nonempty(
                "delegate.canonical_delegate_borsh_b64u",
                &delegate.canonical_delegate_borsh_b64u,
            )?;
            if intent_preimage != signing_payload.preimage_bytes()? {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    "delegate-action intent preimage does not match signing payload",
                ));
            }
            let parsed = decode_delegate_action_from_prefixed_bytes(
                "delegate.canonical_delegate_borsh_b64u",
                &intent_preimage,
            )?;
            ensure_equal_string("delegate sender_id", near_account_id, &parsed.sender_id.0)?;
            ensure_equal_string(
                "delegate sender_id",
                &delegate.sender_id,
                &parsed.sender_id.0,
            )?;
            ensure_equal_string(
                "delegate receiver_id",
                &delegate.receiver_id,
                &parsed.receiver_id.0,
            )?;
            ensure_equal_string(
                "delegate public_key",
                &delegate.public_key,
                &public_key_string(&parsed.public_key)?,
            )?;
            ensure_equal_string("delegate nonce", &delegate.nonce, &parsed.nonce.to_string())?;
            ensure_equal_string(
                "delegate max_block_height",
                &delegate.max_block_height,
                &parsed.max_block_height.to_string(),
            )?;
            let action_fingerprint =
                router_ab_normal_signing_action_fingerprint_v2(&parsed.actions)?;
            ensure_equal_string(
                "delegate action_fingerprint",
                &delegate.action_fingerprint,
                &action_fingerprint,
            )
        }
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "normal-signing intent branch does not match signing payload branch",
        )),
    }
}

fn validate_operation_fields(
    operation_id: &str,
    operation_fingerprint: &str,
    near_account_id: &str,
) -> RouterAbProtocolResult<()> {
    require_non_empty("operation_id", operation_id)?;
    require_non_empty("operation_fingerprint", operation_fingerprint)?;
    require_non_empty("near_account_id", near_account_id)
}

fn parse_normal_signing_boundary_json_v2<T>(label: &str, bytes: &[u8]) -> RouterAbProtocolResult<T>
where
    T: DeserializeOwned,
{
    serde_json::from_slice(bytes).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{label} JSON parse failed: {err}"),
        )
    })
}

fn push_normal_intent_common(
    out: &mut Vec<u8>,
    operation_id: &str,
    operation_fingerprint: &str,
    near_account_id: &str,
    near_network_id: RouterAbNearNetworkIdV2,
) {
    push_len32(out, operation_id.as_bytes());
    push_len32(out, operation_fingerprint.as_bytes());
    push_len32(out, near_account_id.as_bytes());
    push_len32(out, near_network_id.as_str().as_bytes());
}

fn push_optional_string(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            out.push(1);
            push_len32(out, value.as_bytes());
        }
        None => out.push(0),
    }
}

fn push_borsh_string(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn push_len32(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn decode_base64url_nonempty(field: &str, value: &str) -> RouterAbProtocolResult<Vec<u8>> {
    require_non_empty(field, value)?;
    let bytes = Base64UrlUnpadded::decode_vec(value).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must be unpadded base64url: {err}"),
        )
    })?;
    if bytes.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must decode to non-empty bytes"),
        ));
    }
    Ok(bytes)
}

fn decode_base64url_fixed_32(field: &str, value: &str) -> RouterAbProtocolResult<[u8; 32]> {
    let bytes = Base64UrlUnpadded::decode_vec(value).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must be unpadded base64url: {err}"),
        )
    })?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must decode to 32 bytes, got {}", bytes.len()),
        )
    })
}

fn require_positive_ms(field: &str, value: u64) -> RouterAbProtocolResult<()> {
    if value > 0 {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidTimeRange,
        format!("{field} must be greater than zero"),
    ))
}

fn require_non_empty(field: &str, value: &str) -> RouterAbProtocolResult<()> {
    if !value.is_empty() {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::EmptyField,
        format!("{field} must be non-empty"),
    ))
}
