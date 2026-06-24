use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::shared::{ProtoError, ProtoResult};

pub const ED25519_HSS_CONTEXT_VERSION: &str = "v2";
pub const ED25519_HSS_SCHEME_ID: &str = "ed25519-hss-v2";
pub const ED25519_HSS_CURVE: &str = "ed25519";
pub const ED25519_HSS_CONTEXT_BINDING_DOMAIN_V2: &[u8] =
    b"succinct-garbling-proto/ed25519-hss/context-binding/v2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519HssStableKeyContext {
    pub application_binding_digest: [u8; 32],
    pub participant_ids: Vec<u16>,
}

impl Ed25519HssStableKeyContext {
    pub fn normalized(&self) -> ProtoResult<Self> {
        let mut participant_ids: Vec<u16> = self
            .participant_ids
            .iter()
            .copied()
            .filter(|value| *value > 0)
            .collect();
        participant_ids.sort_unstable();
        participant_ids.dedup();

        if participant_ids.len() < 2 {
            return Err(ProtoError::InvalidInput(
                "participant_ids must contain at least two non-zero identifiers".to_string(),
            ));
        }

        Ok(Self {
            application_binding_digest: self.application_binding_digest,
            participant_ids,
        })
    }

    pub fn binding_digest(&self) -> ProtoResult<[u8; 32]> {
        let normalized = self.normalized()?;
        let mut hasher = Sha256::new();

        hasher.update(ED25519_HSS_CONTEXT_BINDING_DOMAIN_V2);
        update_len_prefixed(&mut hasher, ED25519_HSS_CONTEXT_VERSION);
        update_len_prefixed(&mut hasher, ED25519_HSS_SCHEME_ID);
        update_len_prefixed(&mut hasher, ED25519_HSS_CURVE);
        hasher.update(normalized.application_binding_digest);
        hasher.update((normalized.participant_ids.len() as u32).to_be_bytes());
        for participant_id in normalized.participant_ids {
            hasher.update(participant_id.to_be_bytes());
        }

        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok(out)
    }
}

pub type CanonicalContext = Ed25519HssStableKeyContext;

fn update_len_prefixed(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u32).to_be_bytes());
    hasher.update(value.as_bytes());
}
