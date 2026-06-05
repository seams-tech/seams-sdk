use crate::error::KdfError;

/// Ephemeral wrap key material derived in the SecureConfirm worker and delivered to the signer.
/// Holds the base64url-encoded WrapKeySeed and its salt, and exposes a helper to derive KEK.
#[derive(Clone)]
pub struct WrapKey {
    pub(crate) wrap_key_seed: String,
    pub(crate) wrap_key_salt: String,
}

impl WrapKey {
    /// Derive KEK from the stored WrapKeySeed + wrap_key_salt using the shared HKDF helper.
    pub fn derive_kek(&self) -> Result<Vec<u8>, String> {
        derive_kek_from_wrap_key_seed(&self.wrap_key_seed, &self.wrap_key_salt)
            .map_err(|e| format!("WrapKeySeed → KEK derivation failed: {}", e))
    }

    /// Return the base64url-encoded wrap_key_salt associated with this wrap key.
    pub fn salt_b64u(&self) -> &str {
        &self.wrap_key_salt
    }
}

impl std::fmt::Debug for WrapKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrapKey")
            .field("wrap_key_seed", &"***")
            .field("wrap_key_salt", &self.wrap_key_salt)
            .finish()
    }
}

/// Derive KEK from WrapKeySeed + wrap_key_salt (HKDF)
pub(crate) fn derive_kek_from_wrap_key_seed(
    wrap_key_seed_b64u: &str,
    wrap_key_salt_b64u: &str,
) -> Result<Vec<u8>, KdfError> {
    signer_core::near_crypto::derive_kek_from_wrap_key_seed_b64u(
        wrap_key_seed_b64u,
        wrap_key_salt_b64u,
    )
    .map_err(|e| {
        let message = e.to_string();
        if message.starts_with("Base64 decode error:") {
            return KdfError::Base64DecodeError(message);
        }
        if message == "HKDF operation failed" {
            return KdfError::HkdfError;
        }
        KdfError::InvalidInput(message)
    })
}
