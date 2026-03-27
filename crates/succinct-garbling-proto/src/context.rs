use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{ProtoError, ProtoResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalContext {
    pub org_id: String,
    pub account_id: String,
    pub key_purpose: String,
    pub key_version: String,
    pub participant_ids: Vec<u16>,
    pub derivation_version: u32,
}

impl CanonicalContext {
    pub fn normalized(&self) -> ProtoResult<Self> {
        validate_field("org_id", &self.org_id)?;
        validate_field("account_id", &self.account_id)?;
        validate_field("key_purpose", &self.key_purpose)?;
        validate_field("key_version", &self.key_version)?;

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
            org_id: self.org_id.clone(),
            account_id: self.account_id.clone(),
            key_purpose: self.key_purpose.clone(),
            key_version: self.key_version.clone(),
            participant_ids,
            derivation_version: self.derivation_version,
        })
    }

    pub fn binding_digest(&self) -> ProtoResult<[u8; 32]> {
        let normalized = self.normalized()?;
        let mut hasher = Sha256::new();

        hasher.update(b"succinct-garbling-proto/context-binding/v1");
        update_len_prefixed(&mut hasher, &normalized.org_id);
        update_len_prefixed(&mut hasher, &normalized.account_id);
        update_len_prefixed(&mut hasher, &normalized.key_purpose);
        update_len_prefixed(&mut hasher, &normalized.key_version);
        hasher.update((normalized.participant_ids.len() as u32).to_be_bytes());
        for participant_id in normalized.participant_ids {
            hasher.update(participant_id.to_be_bytes());
        }
        hasher.update(normalized.derivation_version.to_be_bytes());

        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok(out)
    }
}

fn validate_field(label: &str, value: &str) -> ProtoResult<()> {
    if value.is_empty() {
        return Err(ProtoError::InvalidInput(format!(
            "{label} must be non-empty"
        )));
    }
    if value.trim() != value {
        return Err(ProtoError::InvalidInput(format!(
            "{label} must not contain leading or trailing whitespace"
        )));
    }
    Ok(())
}

fn update_len_prefixed(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u32).to_be_bytes());
    hasher.update(value.as_bytes());
}
