use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CoreResult, SignerCoreError};
use ecdsa_hss::{
    compose_public_identity_from_public_keys, derive_client_share, ClientRoleShare, EcdsaHssError,
    EcdsaHssErrorCode, EcdsaHssStableKeyContext,
};

const PENDING_BLOB_MAGIC: &[u8; 8] = b"EHSSP1\0\0";
const READY_BLOB_MAGIC: &[u8; 8] = b"EHSSR1\0\0";
const ECDSA_HSS_CLIENT_PARTICIPANT_ID: u32 = 1;

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EcdsaRoleLocalPendingStateBlob {
    pub state_blob: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EcdsaRoleLocalReadyStateBlob {
    pub state_blob: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrepareEcdsaClientBootstrapCommand {
    pub context: EcdsaHssStableKeyContext,
    pub client_root_share32: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaClientBootstrapFacts {
    pub context_binding32: [u8; 32],
    pub hss_client_share_public_key33: [u8; 33],
    pub client_share_retry_counter: u32,
    pub participant_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaRoleLocalPublicFacts {
    pub context_binding32: [u8; 32],
    pub hss_client_share_public_key33: [u8; 33],
    pub client_verifying_share33: [u8; 33],
    pub relayer_public_key33: [u8; 33],
    pub group_public_key33: [u8; 33],
    pub ethereum_address20: [u8; 20],
    pub client_share_retry_counter: u32,
    pub relayer_share_retry_counter: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaRoleLocalPreparePublicFacts {
    pub context_binding32: [u8; 32],
    pub hss_client_share_public_key33: [u8; 33],
    pub client_verifying_share33: [u8; 33],
    pub client_share_retry_counter: u32,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrepareEcdsaClientBootstrapOutput {
    pub pending_state_blob: EcdsaRoleLocalPendingStateBlob,
    pub client_bootstrap: EcdsaClientBootstrapFacts,
    pub public_facts: EcdsaRoleLocalPreparePublicFacts,
}

#[derive(Clone, PartialEq, Eq)]
pub struct RelayerPublicIdentityInput {
    pub relayer_key_id: String,
    pub relayer_public_key33: [u8; 33],
    pub group_public_key33: [u8; 33],
    pub ethereum_address20: [u8; 20],
    pub relayer_share_retry_counter: u32,
}

#[derive(Clone, PartialEq, Eq)]
pub struct FinalizeEcdsaClientBootstrapCommand {
    pub pending_state_blob: EcdsaRoleLocalPendingStateBlob,
    pub relayer_public_identity: RelayerPublicIdentityInput,
}

#[derive(Clone, PartialEq, Eq)]
pub struct FinalizeEcdsaClientBootstrapOutput {
    pub ready_state_blob: EcdsaRoleLocalReadyStateBlob,
    pub public_facts: EcdsaRoleLocalPublicFacts,
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
struct PendingState {
    #[zeroize(skip)]
    context: EcdsaHssStableKeyContext,
    context_binding32: [u8; 32],
    client_share_retry_counter: u32,
    x_client32: [u8; 32],
    hss_client_share_public_key33: [u8; 33],
    mapped_client_share32: [u8; 32],
}

pub fn prepare_ecdsa_client_bootstrap(
    input: PrepareEcdsaClientBootstrapCommand,
) -> CoreResult<PrepareEcdsaClientBootstrapOutput> {
    input.context.validate().map_err(map_ecdsa_hss_error)?;
    let client_share = derive_client_share(&input.context, input.client_root_share32)
        .map_err(map_ecdsa_hss_error)?;
    let pending_state = pending_state_from_client_share(input.context, &client_share);
    let pending_state_blob = EcdsaRoleLocalPendingStateBlob {
        state_blob: serialize_pending_state(&pending_state)?,
    };
    let client_bootstrap = EcdsaClientBootstrapFacts {
        context_binding32: pending_state.context_binding32,
        hss_client_share_public_key33: pending_state.hss_client_share_public_key33,
        client_share_retry_counter: pending_state.client_share_retry_counter,
        participant_id: ECDSA_HSS_CLIENT_PARTICIPANT_ID,
    };
    let public_facts = EcdsaRoleLocalPreparePublicFacts {
        context_binding32: pending_state.context_binding32,
        hss_client_share_public_key33: pending_state.hss_client_share_public_key33,
        client_verifying_share33: pending_state.hss_client_share_public_key33,
        client_share_retry_counter: pending_state.client_share_retry_counter,
    };

    Ok(PrepareEcdsaClientBootstrapOutput {
        pending_state_blob,
        client_bootstrap,
        public_facts,
    })
}

pub fn finalize_ecdsa_client_bootstrap(
    input: FinalizeEcdsaClientBootstrapCommand,
) -> CoreResult<FinalizeEcdsaClientBootstrapOutput> {
    let relayer_key_id = input.relayer_public_identity.relayer_key_id.trim();
    if relayer_key_id.is_empty() {
        return Err(SignerCoreError::invalid_input(
            "relayer_key_id must be non-empty",
        ));
    }

    let pending_state = parse_pending_state(&input.pending_state_blob.state_blob)?;
    let identity = compose_public_identity_from_public_keys(
        &pending_state.context,
        &pending_state.hss_client_share_public_key33,
        pending_state.client_share_retry_counter,
        &input.relayer_public_identity.relayer_public_key33,
        input.relayer_public_identity.relayer_share_retry_counter,
    )
    .map_err(map_ecdsa_hss_error)?;
    if identity.context_binding32 != pending_state.context_binding32 {
        return Err(SignerCoreError::invalid_input(
            "pending context binding does not match encoded context",
        ));
    }

    if identity.threshold_public_key33 != input.relayer_public_identity.group_public_key33 {
        return Err(SignerCoreError::invalid_input(
            "relayer group public key does not match client and relayer HSS keys",
        ));
    }
    if identity.threshold_ethereum_address20 != input.relayer_public_identity.ethereum_address20 {
        return Err(SignerCoreError::invalid_input(
            "relayer ethereum address does not match group public key",
        ));
    }

    let public_facts = EcdsaRoleLocalPublicFacts {
        context_binding32: identity.context_binding32,
        hss_client_share_public_key33: identity.client_public_key33,
        client_verifying_share33: identity.client_public_key33,
        relayer_public_key33: identity.relayer_public_key33,
        group_public_key33: identity.threshold_public_key33,
        ethereum_address20: identity.threshold_ethereum_address20,
        client_share_retry_counter: identity.client_share_retry_counter,
        relayer_share_retry_counter: identity.relayer_share_retry_counter,
    };
    let ready_state_blob = EcdsaRoleLocalReadyStateBlob {
        state_blob: serialize_ready_state(&pending_state, relayer_key_id, &public_facts)?,
    };

    Ok(FinalizeEcdsaClientBootstrapOutput {
        ready_state_blob,
        public_facts,
    })
}

fn pending_state_from_client_share(
    context: EcdsaHssStableKeyContext,
    client_share: &ClientRoleShare,
) -> PendingState {
    PendingState {
        context,
        context_binding32: client_share.context_binding32,
        client_share_retry_counter: client_share.retry_counter,
        x_client32: client_share.x_client32,
        hss_client_share_public_key33: client_share.client_public_key33,
        mapped_client_share32: client_share.mapped_client_share32,
    }
}

fn serialize_pending_state(state: &PendingState) -> CoreResult<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(PENDING_BLOB_MAGIC);
    write_context(&mut out, &state.context)?;
    out.extend_from_slice(&state.context_binding32);
    out.extend_from_slice(&state.client_share_retry_counter.to_be_bytes());
    out.extend_from_slice(&state.x_client32);
    out.extend_from_slice(&state.hss_client_share_public_key33);
    out.extend_from_slice(&state.mapped_client_share32);
    Ok(out)
}

fn serialize_ready_state(
    pending_state: &PendingState,
    relayer_key_id: &str,
    public_facts: &EcdsaRoleLocalPublicFacts,
) -> CoreResult<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(READY_BLOB_MAGIC);
    write_context(&mut out, &pending_state.context)?;
    write_string(&mut out, relayer_key_id)?;
    out.extend_from_slice(&pending_state.context_binding32);
    out.extend_from_slice(&pending_state.client_share_retry_counter.to_be_bytes());
    out.extend_from_slice(&pending_state.x_client32);
    out.extend_from_slice(&pending_state.hss_client_share_public_key33);
    out.extend_from_slice(&pending_state.mapped_client_share32);
    out.extend_from_slice(&public_facts.relayer_share_retry_counter.to_be_bytes());
    out.extend_from_slice(&public_facts.relayer_public_key33);
    out.extend_from_slice(&public_facts.group_public_key33);
    out.extend_from_slice(&public_facts.ethereum_address20);
    Ok(out)
}

fn parse_pending_state(bytes: &[u8]) -> CoreResult<PendingState> {
    let mut cursor = BlobCursor::new(bytes);
    cursor.expect_magic(PENDING_BLOB_MAGIC)?;
    let context = cursor.read_context()?;
    let context_binding32 = cursor.read_array::<32>("context_binding32")?;
    let client_share_retry_counter = cursor.read_u32("client_share_retry_counter")?;
    let x_client32 = cursor.read_array::<32>("x_client32")?;
    let hss_client_share_public_key33 = cursor.read_array::<33>("hss_client_share_public_key33")?;
    let mapped_client_share32 = cursor.read_array::<32>("mapped_client_share32")?;
    cursor.expect_end()?;

    Ok(PendingState {
        context,
        context_binding32,
        client_share_retry_counter,
        x_client32,
        hss_client_share_public_key33,
        mapped_client_share32,
    })
}

fn write_context(out: &mut Vec<u8>, context: &EcdsaHssStableKeyContext) -> CoreResult<()> {
    write_string(out, &context.wallet_id)?;
    write_string(out, &context.rp_id)?;
    write_string(out, &context.ecdsa_threshold_key_id)?;
    write_string(out, &context.signing_root_id)?;
    write_string(out, &context.signing_root_version)?;
    write_string(out, &context.key_purpose)?;
    write_string(out, &context.key_version)
}

fn map_ecdsa_hss_error(error: EcdsaHssError) -> SignerCoreError {
    match error.code {
        EcdsaHssErrorCode::InvalidInput => SignerCoreError::invalid_input(error.message),
        EcdsaHssErrorCode::InvalidLength => SignerCoreError::invalid_length(error.message),
        EcdsaHssErrorCode::DecodeError => SignerCoreError::decode_error(error.message),
        EcdsaHssErrorCode::CryptoError => SignerCoreError::crypto_error(error.message),
        EcdsaHssErrorCode::Utf8Error => SignerCoreError::utf8_error(error.message),
        EcdsaHssErrorCode::Internal => SignerCoreError::internal(error.message),
    }
}

fn write_string(out: &mut Vec<u8>, value: &str) -> CoreResult<()> {
    if value.is_empty() {
        return Err(SignerCoreError::invalid_input(
            "blob string field must be non-empty",
        ));
    }
    if !value.is_ascii() {
        return Err(SignerCoreError::invalid_input(
            "blob string field must be ASCII-only",
        ));
    }
    let len = u16::try_from(value.len())
        .map_err(|_| SignerCoreError::invalid_length("blob string field exceeds u16 length"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

struct BlobCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BlobCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn expect_magic(&mut self, expected: &[u8; 8]) -> CoreResult<()> {
        let magic = self.read_slice(expected.len(), "blob magic")?;
        if magic != expected {
            return Err(SignerCoreError::decode_error(
                "unexpected ECDSA HSS state blob magic",
            ));
        }
        Ok(())
    }

    fn read_context(&mut self) -> CoreResult<EcdsaHssStableKeyContext> {
        Ok(EcdsaHssStableKeyContext::new(
            self.read_string("wallet_id")?,
            self.read_string("rp_id")?,
            self.read_string("ecdsa_threshold_key_id")?,
            self.read_string("signing_root_id")?,
            self.read_string("signing_root_version")?,
            self.read_string("key_purpose")?,
            self.read_string("key_version")?,
        ))
        .and_then(|context| {
            context.validate().map_err(map_ecdsa_hss_error)?;
            Ok(context)
        })
    }

    fn read_string(&mut self, field_name: &str) -> CoreResult<String> {
        let len = u16::from_be_bytes(self.read_array::<2>(field_name)?) as usize;
        let bytes = self.read_slice(len, field_name)?;
        if bytes.is_empty() {
            return Err(SignerCoreError::decode_error(format!(
                "{field_name} must be non-empty"
            )));
        }
        if !bytes.is_ascii() {
            return Err(SignerCoreError::decode_error(format!(
                "{field_name} must be ASCII-only"
            )));
        }
        String::from_utf8(bytes.to_vec())
            .map_err(|_| SignerCoreError::utf8_error(format!("{field_name} is not UTF-8")))
    }

    fn read_u32(&mut self, field_name: &str) -> CoreResult<u32> {
        Ok(u32::from_be_bytes(self.read_array::<4>(field_name)?))
    }

    fn read_array<const N: usize>(&mut self, field_name: &str) -> CoreResult<[u8; N]> {
        let slice = self.read_slice(N, field_name)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    fn read_slice(&mut self, len: usize, field_name: &str) -> CoreResult<&'a [u8]> {
        let end = self.offset.checked_add(len).ok_or_else(|| {
            SignerCoreError::invalid_length(format!("{field_name} length overflow"))
        })?;
        if end > self.bytes.len() {
            return Err(SignerCoreError::invalid_length(format!(
                "{field_name} exceeds ECDSA HSS state blob length"
            )));
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn expect_end(&self) -> CoreResult<()> {
        if self.offset != self.bytes.len() {
            return Err(SignerCoreError::decode_error(
                "trailing bytes in ECDSA HSS state blob",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecdsa_hss::derive_relayer_share_for_client_public;

    fn context() -> EcdsaHssStableKeyContext {
        EcdsaHssStableKeyContext::new(
            "wallet.testnet",
            "localhost",
            "ehss-key",
            "root-id",
            "root-v1",
            "evm-signing",
            "v1",
        )
    }

    #[test]
    fn prepare_and_finalize_round_trip_ready_blob() {
        let prepared = prepare_ecdsa_client_bootstrap(PrepareEcdsaClientBootstrapCommand {
            context: context(),
            client_root_share32: [0x11u8; 32],
        })
        .expect("prepare");
        let (_relayer_share, identity) = derive_relayer_share_for_client_public(
            &context(),
            [0x22u8; 32],
            &prepared.client_bootstrap.hss_client_share_public_key33,
            prepared.client_bootstrap.client_share_retry_counter,
        )
        .expect("relayer identity");

        let finalized = finalize_ecdsa_client_bootstrap(FinalizeEcdsaClientBootstrapCommand {
            pending_state_blob: prepared.pending_state_blob,
            relayer_public_identity: RelayerPublicIdentityInput {
                relayer_key_id: "relayer-key".to_owned(),
                relayer_public_key33: identity.relayer_public_key33,
                group_public_key33: identity.threshold_public_key33,
                ethereum_address20: identity.threshold_ethereum_address20,
                relayer_share_retry_counter: identity.relayer_share_retry_counter,
            },
        })
        .expect("finalize");

        assert!(!finalized.ready_state_blob.state_blob.is_empty());
        assert_eq!(
            finalized.public_facts.group_public_key33,
            identity.threshold_public_key33
        );
        assert_eq!(
            finalized.public_facts.ethereum_address20,
            identity.threshold_ethereum_address20
        );
    }

    #[test]
    fn finalize_rejects_mismatched_relayer_public_identity() {
        let prepared = prepare_ecdsa_client_bootstrap(PrepareEcdsaClientBootstrapCommand {
            context: context(),
            client_root_share32: [0x11u8; 32],
        })
        .expect("prepare");
        let (_relayer_share, identity) = derive_relayer_share_for_client_public(
            &context(),
            [0x22u8; 32],
            &prepared.client_bootstrap.hss_client_share_public_key33,
            prepared.client_bootstrap.client_share_retry_counter,
        )
        .expect("relayer identity");

        let mut wrong_group_public_key33 = identity.threshold_public_key33;
        wrong_group_public_key33[1] ^= 0x01;
        let result = finalize_ecdsa_client_bootstrap(FinalizeEcdsaClientBootstrapCommand {
            pending_state_blob: prepared.pending_state_blob,
            relayer_public_identity: RelayerPublicIdentityInput {
                relayer_key_id: "relayer-key".to_owned(),
                relayer_public_key33: identity.relayer_public_key33,
                group_public_key33: wrong_group_public_key33,
                ethereum_address20: identity.threshold_ethereum_address20,
                relayer_share_retry_counter: identity.relayer_share_retry_counter,
            },
        });

        let err = match result {
            Ok(_) => panic!("mismatch should reject"),
            Err(err) => err,
        };
        assert!(err.message.contains("group public key"));
    }
}
